"""End-to-end flow in mock mode (no PayPal / Anthropic keys required)."""
import os
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["PAYWARDEN_DB"] = os.path.join(tempfile.mkdtemp(), "api.db")
os.environ.pop("PAYPAL_CLIENT_ID", None)
os.environ.pop("ANTHROPIC_API_KEY", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.main import app  # noqa: E402
from app.samples import SAMPLES  # noqa: E402
from app.security import auth  # noqa: E402

c = TestClient(app)
MAKER = {"Authorization": "Bearer demo-maker-token"}
CHECKER = {"Authorization": "Bearer demo-checker-token"}
H = MAKER
S = {s["id"]: s["document"] for s in SAMPLES}


@pytest.fixture(autouse=True)
def _fresh_mfa_state():
    # Each TOTP time-step is single-use; tests run faster than 30s, so reset between tests.
    auth.reset_mfa_state()
    yield


def analyse(key=None, doc=None):
    r = c.post("/api/agent/analyse", json={"document": doc or S[key]}, headers=H)
    assert r.status_code == 200, r.text
    return r.json()["proposals"][0]


def codes():
    return c.get("/api/demo/totp", headers=H).json()


def approve(p, headers, totp):
    return c.post(f"/api/proposals/{p['id']}/approve", json={"totp": totp, "binding": p["binding"]},
                  headers=headers)


def test_requires_operator_auth():
    assert c.get("/api/proposals").status_code == 401
    assert c.get("/api/proposals", headers={"Authorization": "Bearer wrong"}).status_code == 401
    # the retired shared token is no longer accepted
    assert c.get("/api/proposals", headers={"Authorization": "Bearer demo-operator-token"}).status_code == 401


def test_security_headers_present():
    r = c.get("/healthz")
    for h in ("strict-transport-security", "content-security-policy", "x-frame-options",
              "x-content-type-options", "x-request-id", "cross-origin-resource-policy"):
        assert h in r.headers


def test_request_id_is_sanitised():
    r = c.get("/healthz", headers={"X-Request-ID": "evil\tinjected value"})
    assert r.headers["x-request-id"] != "evil\tinjected value"
    assert c.get("/healthz", headers={"X-Request-ID": "abc-12345"}).headers["x-request-id"] == "abc-12345"


def test_full_flow_step_up_then_auto_allow():
    p = analyse("legit-first")
    assert p["verdict"] == "STEP_UP" and p["status"] == "PENDING"
    assert "payee_enc" not in p and "@example.com" in p["payee_masked"]
    assert len(p["binding"]) == 64
    assert approve(p, MAKER, "000000").status_code == 401
    tampered = c.post(f"/api/proposals/{p['id']}/approve",
                      json={"totp": codes()["maker"], "binding": "0" * 64}, headers=MAKER)
    assert tampered.status_code == 409
    ok = approve(p, MAKER, codes()["maker"])
    assert ok.status_code == 200 and ok.json()["status"] == "EXECUTED"
    assert ok.json()["paypal_ref"].startswith("MOCK-")

    repeat = analyse("legit-repeat")
    assert repeat["verdict"] == "ALLOW" and repeat["status"] == "EXECUTED"


def test_operator_identity_comes_from_token_not_body():
    p = analyse(doc="SOW M3\nContractor: Identity Test LLC\nEmail: id@example.com\nAmount due: USD 6,100.00")
    assert p["verdict"] == "DUAL_CONTROL"
    # A maker cannot claim to be the checker: body field is ignored, token decides.
    r = c.post(f"/api/proposals/{p['id']}/approve",
               json={"operator": "checker", "totp": codes()["maker"], "binding": p["binding"]}, headers=MAKER)
    assert r.json()["status"] == "AWAITING_SECOND_APPROVER"
    again = approve(p, MAKER, codes()["maker"])
    assert again.status_code == 409  # still the maker -> four-eyes rule


def test_dual_control_needs_two_different_operators():
    p = analyse("high-value")
    assert p["verdict"] == "DUAL_CONTROL" and p["decision"]["travel_rule"]
    first = approve(p, MAKER, codes()["maker"])
    assert first.json()["status"] == "AWAITING_SECOND_APPROVER"
    assert approve(p, MAKER, codes()["maker"]).status_code == 409
    second = approve(p, CHECKER, codes()["checker"])
    assert second.status_code == 200 and second.json()["status"] == "EXECUTED"


def test_totp_code_cannot_be_replayed():
    a = analyse(doc="INVOICE A\nFrom: Replay Test\nEmail: replay.a@example.com\nTotal due: $111.00 USD")
    b = analyse(doc="INVOICE B\nFrom: Replay Test\nEmail: replay.b@example.com\nTotal due: $222.00 USD")
    code = codes()["maker"]
    assert approve(a, MAKER, code).status_code == 200
    r = approve(b, MAKER, code)
    assert r.status_code == 401 and "already-used" in r.json()["detail"]


def test_mfa_lockout_after_repeated_failures():
    p = analyse(doc="INVOICE L\nFrom: Lock Test\nEmail: lock@example.com\nTotal due: $333.00 USD")
    for _ in range(5):
        assert approve(p, MAKER, "000000").status_code == 401
    locked = approve(p, MAKER, codes()["maker"])
    assert locked.status_code == 423
    # lockout is per operator: the checker is unaffected
    assert approve(p, CHECKER, codes()["checker"]).status_code == 200


def test_attacks_are_denied():
    for key in ("prompt-injection", "sanctioned", "high-risk-geo"):
        p = analyse(key)
        assert p["verdict"] == "DENY" and p["status"] == "DENIED", (key, p["decision"]["reasons"])


def test_card_number_in_document_is_denied_and_redacted():
    doc = ("INVOICE C-9\nFrom: Card Test\nEmail: card@example.com\nTotal due: $410.00 USD\n"
           "Or charge my card 4111 1111 1111 1111 exp 12/29")
    r = c.post("/api/agent/analyse", json={"document": doc}, headers=H).json()
    p = r["proposals"][0]
    assert p["verdict"] == "DENY" and "PCI-01" in p["decision"]["controls"]
    assert "4111" not in str(p) and "4111" not in r["summary"]


def test_denied_cannot_be_approved():
    p = analyse("prompt-injection")
    assert approve(p, MAKER, codes()["maker"]).status_code == 409


def test_reject_uses_token_identity_and_redacts_reason():
    p = analyse(doc="INVOICE R\nFrom: Reject Test\nEmail: reject@example.com\nTotal due: $444.00 USD")
    r = c.post(f"/api/proposals/{p['id']}/reject", json={"reason": "payee says acct 123456789 is wrong"},
               headers=CHECKER)
    assert r.json()["status"] == "REJECTED"
    entry = next(e for e in c.get("/api/audit", headers=H).json() if e["action"] == "REJECTED")
    assert entry["actor"] == "checker" and "123456789" not in entry["details"]["reason"]


def test_oversized_body_rejected():
    r = c.post("/api/agent/analyse", content=b"{" + b" " * 200_000 + b"}",
               headers={**H, "Content-Type": "application/json"})
    assert r.status_code == 413


def _hook_headers(tid="T-1", age=0):
    t = (datetime.now(timezone.utc) - timedelta(seconds=age)).isoformat()
    return {"paypal-transmission-id": tid, "paypal-transmission-time": t}


def test_unverified_webhook_rejected():
    r = c.post("/api/webhooks/paypal", json={"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "id": "WH-1"},
               headers=_hook_headers())
    assert r.status_code == 400 and r.json()["reason"] == "signature not verified"


def test_stale_webhook_rejected():
    r = c.post("/api/webhooks/paypal", json={"event_type": "X"}, headers=_hook_headers(age=3600))
    assert r.status_code == 400 and "stale" in r.json()["reason"]


def test_replayed_webhook_rejected(monkeypatch):
    async def ok(*_):
        return True
    monkeypatch.setattr(main.paypal, "verify_webhook", ok)
    ev = {"event_type": "PAYMENT.PAYOUTSBATCH.SUCCESS", "id": "WH-2"}
    assert c.post("/api/webhooks/paypal", json=ev, headers=_hook_headers("T-REPLAY")).status_code == 200
    again = c.post("/api/webhooks/paypal", json=ev, headers=_hook_headers("T-REPLAY"))
    assert again.status_code == 400 and again.json()["reason"] == "replayed transmission"


def test_audit_chain_valid_after_flow():
    v = c.get("/api/audit/verify", headers=H).json()
    assert v["valid"] and v["checked"] > 5
