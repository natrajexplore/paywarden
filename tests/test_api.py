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


# ---------------- full-review fixes
def test_paypal_timeout_is_uncertain_not_stuck(monkeypatch):
    """#1: an unknown outcome is recorded (UNCERTAIN), never left in EXECUTING, and still blocks a re-pay."""
    import httpx
    p = analyse(doc="INVOICE TO-1\nFrom: Timeout Test\nEmail: timeout@example.com\nTotal due: $211.00 USD")

    async def boom(*a, **k):
        raise httpx.ReadTimeout("timed out")
    monkeypatch.setattr(main.paypal, "create_payout", boom)
    r = approve(p, MAKER, codes()["maker"])
    assert r.status_code == 504
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "UNCERTAIN"
    again = analyse(doc="INVOICE TO-2\nFrom: Timeout Test\nEmail: timeout@example.com\nTotal due: $211.00 USD")
    assert again["verdict"] == "DENY" and "DUP-01" in again["decision"]["controls"]


def test_paypal_non_json_error_is_a_paypal_error(monkeypatch):
    """#1: a 4xx with an HTML body raises PayPalError, not a JSON decode crash."""
    import asyncio
    import httpx
    from app import paypal_client

    def handler(request):
        if request.url.path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        return httpx.Response(400, text="<html>Bad Request</html>")
    real = httpx.AsyncClient
    monkeypatch.setattr(paypal_client.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), **kw))
    with pytest.raises(paypal_client.PayPalError) as e:
        asyncio.run(paypal_client.PayPalClient()._call("POST", "/v1/payments/payouts", {}))
    assert e.value.status == 400 and "Bad Request" in e.value.body


def test_one_failed_auto_payment_does_not_abort_the_rest(monkeypatch):
    """#6: every proposal in a document is evaluated even if an earlier auto-execution fails."""
    from app.security.policy import Decision

    async def two(document):
        base = dict(action="payout", payee_name="Multi", currency="USD", purpose="supplies", country="US")
        return {"engine": "test", "summary": "", "proposals": [
            {**base, "payee_email": "multi.a@example.com", "amount": "11.00"},
            {**base, "payee_email": "multi.b@example.com", "amount": "12.00"}]}

    async def rejected(*a, **k):
        raise main.PayPalError(422, {})
    monkeypatch.setattr(main.agent, "analyse", two)
    monkeypatch.setattr(main.pdp, "evaluate", lambda p, h: Decision())  # both ALLOW
    monkeypatch.setattr(main.paypal, "create_payout", rejected)
    r = c.post("/api/agent/analyse", json={"document": "multi.a@example.com 11.00 multi.b@example.com 12.00"},
               headers=H)
    assert r.status_code == 200
    assert [p["status"] for p in r.json()["proposals"]] == ["FAILED", "FAILED"]


def _verified(monkeypatch):
    async def ok(*_):
        return True
    monkeypatch.setattr(main.paypal, "verify_webhook", ok)


def _hook(event, tid):
    return c.post("/api/webhooks/paypal", json=event, headers=_hook_headers(tid))


def test_webhook_settles_payout_outcome(monkeypatch):
    """#7: a verified PAYMENT.PAYOUTS-ITEM.FAILED overrides the optimistic EXECUTED."""
    _verified(monkeypatch)
    p = analyse(doc="INVOICE WH-1\nFrom: Webhook Test\nEmail: wh.fail@example.com\nTotal due: $66.00 USD")
    assert approve(p, MAKER, codes()["maker"]).json()["status"] == "EXECUTED"
    event = {"event_type": "PAYMENT.PAYOUTS-ITEM.FAILED", "resource": {"payout_item": {"sender_item_id": p["id"]}}}
    assert _hook(event, "T-WH-1").status_code == 200
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "FAILED"


def test_webhook_unclaimed_payout_stays_executed(monkeypatch):
    """UNCLAIMED is not final: the payee has 30 days to claim; only RETURNED fails it."""
    _verified(monkeypatch)
    p = analyse(doc="INVOICE WH-U\nFrom: Webhook Test\nEmail: wh.unclaimed@example.com\nTotal due: $68.00 USD")
    assert approve(p, MAKER, codes()["maker"]).json()["status"] == "EXECUTED"
    item = {"payout_item": {"sender_item_id": p["id"]}}
    assert _hook({"event_type": "PAYMENT.PAYOUTS-ITEM.UNCLAIMED", "resource": item}, "T-WH-U1").status_code == 200
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "EXECUTED"
    assert any(e["action"] == "PAYOUT_UNCLAIMED" for e in c.get("/api/audit", headers=H).json())
    assert _hook({"event_type": "PAYMENT.PAYOUTS-ITEM.RETURNED", "resource": item}, "T-WH-U2").status_code == 200
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "FAILED"


def test_webhook_resolves_uncertain_and_pending_capture(monkeypatch):
    _verified(monkeypatch)
    p = analyse(doc="INVOICE WH-2\nFrom: Webhook Test\nEmail: wh.ok@example.com\nTotal due: $67.00 USD")
    main.store.update(p["id"], status="UNCERTAIN")
    _hook({"event_type": "PAYMENT.PAYOUTS-ITEM.SUCCEEDED", "resource": {"payout_item": {"sender_item_id": p["id"]}}},
          "T-WH-2")
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "EXECUTED"

    q = c.post("/api/demo/a2a/quote", json={"seller_name": "Hook Seller", "seller_email": "hook@seller.example.com",
                                             "amount": "68.00"}, headers=H).json()
    o = c.post("/api/agent/pay-order", json={"order_id": q["order_id"], "payee_name": "Hook Seller",
                                             "source_document": q["quote"]}, headers=H).json()
    main.store.update(o["id"], status="CAPTURE_PENDING")
    _hook({"event_type": "PAYMENT.CAPTURE.COMPLETED",
           "resource": {"supplementary_data": {"related_ids": {"order_id": q["order_id"]}}}}, "T-WH-3")
    assert c.get(f"/api/proposals/{o['id']}", headers=H).json()["status"] == "EXECUTED"


def test_webhook_cannot_resurrect_a_rejected_proposal(monkeypatch):
    _verified(monkeypatch)
    p = analyse(doc="INVOICE WH-4\nFrom: Webhook Test\nEmail: wh.rej@example.com\nTotal due: $69.00 USD")
    c.post(f"/api/proposals/{p['id']}/reject", json={"reason": "no"}, headers=H)
    _hook({"event_type": "PAYMENT.PAYOUTS-ITEM.SUCCEEDED", "resource": {"payout_item": {"sender_item_id": p["id"]}}},
          "T-WH-4")
    assert c.get(f"/api/proposals/{p['id']}", headers=H).json()["status"] == "REJECTED"


def test_rate_limit_ignores_client_supplied_forwarded_for():
    """#5: only the entry our own proxy appended identifies the client."""
    from starlette.requests import Request
    from app.security.middleware import RateLimit

    def req(xff):
        return Request({"type": "http", "headers": [(b"x-forwarded-for", xff.encode())], "client": ("10.0.0.9", 1)})
    rl = RateLimit(app=None, trusted_hops=1)
    assert rl.client_ip(req("6.6.6.6, 203.0.113.7")) == "203.0.113.7"
    assert rl.client_ip(req("7.7.7.7, 8.8.8.8, 203.0.113.7")) == "203.0.113.7"  # rotating fakes: same bucket
    assert RateLimit(app=None).client_ip(req("6.6.6.6")) == "10.0.0.9"         # no proxy: peer address
