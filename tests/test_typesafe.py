"""TypeSafe Jev engine: local candidate extraction + Jev decisions + policy controls AI-05/AI-06."""
import json
import os
import tempfile

os.environ.setdefault("PAYWARDEN_DB", os.path.join(tempfile.mkdtemp(), "jev.db"))

import httpx2  # noqa: E402
import pytest  # noqa: E402
import typesafe_sdk  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import agent, main  # noqa: E402
from app.main import app  # noqa: E402

c = TestClient(app)
H = {"Authorization": "Bearer demo-maker-token"}
DOC = ("INVOICE #JV-1\nFrom: Jev Designs\nEmail: jev.designs@example.com\nCC: office@example.com\n"
       "Logo work: $300.00\nTotal due: $850.00 USD")


@pytest.fixture(autouse=True)
def jev_engine(monkeypatch):
    monkeypatch.setattr(main.settings, "typesafe_api_key", "ts-test-key")
    monkeypatch.setattr(main.settings, "typesafe_model", "jev-1.14.0")


def fake_jev(monkeypatch, payee="E1", amount="A2", action="payout", purpose="freelance_work", manipulation=0.02,
             conf=0.97, seen=None):
    async def ask(state, questions):
        if seen is not None:
            seen.update(state=state, questions=questions)
        return {"model": "jev-1.14.0", "nouls": {"manipulation": manipulation},
                "choices": {"payee": (payee, conf), "amount": (amount, conf), "action": (action, 0.99),
                            "purpose": (purpose, 0.95)}}
    monkeypatch.setattr(agent, "_jev_ask", ask)


def analyse(doc=DOC):
    r = c.post("/api/agent/analyse", json={"document": doc}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()


def test_real_sdk_request_and_response(monkeypatch):
    """Drives typesafe_sdk itself against a mocked HTTP layer: endpoint, auth, questions, parsing."""
    captured = {}

    def handler(request):
        captured.update(path=request.url.path, auth=request.headers.get("authorization"),
                        body=json.loads(request.content))
        return httpx2.Response(200, json={
            "model": "jev-1.14.0", "usage": {"input_tokens": 120, "output_tokens": 5},
            "answers": {
                "payee": {"type": "choice", "choice": "E1", "confidence": 0.96, "probabilities": {"E1": 0.96, "E2": 0.04}},
                "amount": {"type": "choice", "choice": "A2", "confidence": 0.93, "probabilities": {"A1": 0.07, "A2": 0.93}},
                "action": {"type": "choice", "choice": "payout", "confidence": 0.99, "probabilities": {"payout": 0.99, "invoice": 0.01}},
                "purpose": {"type": "choice", "choice": "freelance_work", "confidence": 0.9,
                            "probabilities": {"freelance_work": 0.9, "contractor_services": 0.1}},
                "manipulation": {"type": "noul", "noul": 0.03}}})
    real = typesafe_sdk.AsyncTypeSafeClient
    monkeypatch.setattr(typesafe_sdk, "AsyncTypeSafeClient",
                        lambda **kw: real(transport=httpx2.MockTransport(handler), **kw))
    p = analyse(DOC.replace("jev.designs", "jev.sdk"))["proposals"][0]
    assert captured["path"].endswith("/v1/systemone") and captured["auth"] == "Bearer ts-test-key"
    assert captured["body"]["model"] == "jev-1.14.0"
    assert set(captured["body"]["questions"]) == {"payee", "amount", "action", "purpose", "manipulation"}
    assert "jev.sdk@example.com" not in json.dumps(captured["body"])  # redacted before egress
    assert p["amount"] == "850.00" and p["action"] == "payout" and p["verdict"] == "STEP_UP"


def test_jev_picks_among_document_values(monkeypatch):
    seen = {}
    fake_jev(monkeypatch, seen=seen)
    r = analyse()
    p = r["proposals"][0]
    assert r["engine"] == "typesafe:jev-1.14.0"
    assert p["amount"] == "850.00" and p["payee_masked"].startswith("j") and p["verdict"] == "STEP_UP"
    assert not {"AI-03", "AI-04", "AI-05", "AI-06"} & set(p["decision"]["controls"])
    # candidates offered to Jev are exactly the values found in the document, emails pseudonymised
    assert seen["questions"]["amount"].criteria == {"A1": "300.00 USD", "A2": "850.00 USD"}
    assert set(seen["questions"]["payee"].criteria.values()) == {"[EMAIL_1]", "[EMAIL_2]"}
    assert "@" not in seen["state"]


def test_high_manipulation_risk_denied(monkeypatch):
    fake_jev(monkeypatch, manipulation=0.91)
    p = analyse()["proposals"][0]
    assert p["verdict"] == "DENY" and "AI-05" in p["decision"]["controls"]


def test_moderate_manipulation_risk_needs_review(monkeypatch):
    fake_jev(monkeypatch, manipulation=0.6)
    d = analyse(DOC.replace("JV-1", "JV-2").replace("850.00", "851.00"))["proposals"][0]["decision"]
    assert "AI-05" in d["controls"] and d["verdict"] in ("STEP_UP", "DUAL_CONTROL")


def test_low_model_confidence_needs_human(monkeypatch):
    fake_jev(monkeypatch, conf=0.42)
    d = analyse(DOC.replace("JV-1", "JV-3").replace("850.00", "852.00"))["proposals"][0]["decision"]
    assert "AI-06" in d["controls"] and any("unsure" in r for r in d["reasons"])


def test_engine_failure_fails_closed(monkeypatch):
    async def down(state, questions):
        raise typesafe_sdk.TypeSafeAPIConnectionError("unreachable")
    monkeypatch.setattr(agent, "_jev_ask", down)
    r = c.post("/api/agent/analyse", json={"document": DOC}, headers=H)
    assert r.status_code == 502 and "no payment was proposed" in r.json()["detail"]
    assert any(e["action"] == "AGENT_FAILED" for e in c.get("/api/audit", headers=H).json())


def test_nothing_payable_skips_the_model(monkeypatch):
    async def never(state, questions):
        raise AssertionError("Jev should not be called")
    monkeypatch.setattr(agent, "_jev_ask", never)
    r = analyse("Hello team, lunch is at noon on Friday. No invoice here.")
    assert r["proposals"] == [] and r["engine"] == "typesafe:jev-1.14.0"


def test_health_reports_engine():
    assert c.get("/healthz").json()["ai_engine"] == "typesafe:jev-1.14.0"
