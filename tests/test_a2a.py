"""Agent-to-agent settlement through PayPal Orders (mock mode)."""
import os
import tempfile

os.environ.setdefault("PAYWARDEN_DB", os.path.join(tempfile.mkdtemp(), "a2a.db"))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import main  # noqa: E402
from app.main import app  # noqa: E402
from app.security import auth  # noqa: E402

c = TestClient(app)
AGENT = {"Authorization": "Bearer demo-agent-token"}
MAKER = {"Authorization": "Bearer demo-maker-token"}
CHECKER = {"Authorization": "Bearer demo-checker-token"}


@pytest.fixture(autouse=True)
def _fresh_mfa_state():
    auth.reset_mfa_state()
    yield


def quote(name, email, amount, **kw):
    r = c.post("/api/demo/a2a/quote", json={"seller_name": name, "seller_email": email, "amount": amount, **kw},
               headers=AGENT)
    assert r.status_code == 200, r.text
    return r.json()


def pay(q, name, headers=AGENT, **kw):
    return c.post("/api/agent/pay-order", json={"order_id": q["order_id"], "payee_name": name,
                                                 "source_document": q["quote"], **kw}, headers=headers)


def approve(pid, headers, who):
    row = c.get(f"/api/proposals/{pid}", headers=MAKER).json()
    code = c.get("/api/demo/totp", headers=MAKER).json()[who]
    return c.post(f"/api/proposals/{pid}/approve", json={"totp": code, "binding": row["binding"]}, headers=headers)


def test_seller_quote_names_the_order():
    q = quote("Widget Works", "sales@widgets.example.com", "220.00", description="200 widgets")
    assert q["order_id"].startswith("MOCK-ORDER-")
    for part in (q["order_id"], "Widget Works", "sales@widgets.example.com", "220.00 USD"):
        assert part in q["quote"]


def test_buyer_agent_pays_order_after_human_approval():
    q = quote("Gear Hub", "orders@gearhub.example.com", "315.50")
    p = pay(q, "Gear Hub")
    assert p.status_code == 200, p.text
    p = p.json()
    assert p["action"] == "order" and p["verdict"] == "STEP_UP" and p["status"] == "PENDING"
    assert p["paypal_ref"] == q["order_id"] and p["amount"] == "315.50"
    done = approve(p["id"], CHECKER, "checker")
    assert done.status_code == 200 and done.json()["status"] == "EXECUTED"
    # an order can only be paid once
    assert pay(q, "Gear Hub").status_code == 409


def test_amount_and_payee_come_from_paypal_not_the_agent():
    q = quote("Byte Supply", "billing@bytesupply.example.com", "80.00")
    doc = q["quote"].replace("billing@bytesupply.example.com", "attacker@evil.example")
    p = c.post("/api/agent/pay-order", json={"order_id": q["order_id"], "payee_name": "Byte Supply",
                                             "source_document": doc}, headers=AGENT).json()
    # the real payee (from PayPal) is not in the doctored quote -> provenance fails
    assert p["verdict"] == "DENY" and "AI-04" in p["controls"]


def test_quote_must_reference_the_order():
    q = quote("Paper Co", "ap@paperco.example.com", "45.00")
    other = quote("Paper Co", "ap@paperco.example.com", "46.00")
    r = c.post("/api/agent/pay-order", json={"order_id": other["order_id"], "payee_name": "Paper Co",
                                             "source_document": q["quote"]}, headers=AGENT)
    assert r.status_code == 422
    assert pay(q, "Someone Else").status_code == 422


def test_unknown_order_404():
    r = c.post("/api/agent/pay-order", json={"order_id": "MOCK-ORDER-NOPE", "payee_name": "X",
                                             "source_document": "QUOTE MOCK-ORDER-NOPE from X"}, headers=AGENT)
    assert r.status_code == 404


def test_sanctioned_seller_denied():
    q = quote("Darkwave Holdings", "sales@darkwave-holdings.example", "300.00")
    p = pay(q, "Darkwave Holdings").json()
    assert p["verdict"] == "DENY" and {"AML-01", "AML-03"} <= set(p["controls"])


def test_waits_for_payer_then_operator_captures(monkeypatch):
    q = quote("Slow Pay Ltd", "pay@slowpay.example.com", "150.00")
    order = main.paypal._mock_orders[q["order_id"]]
    order["status"] = "PAYER_ACTION_REQUIRED"
    order["links"] = [{"rel": "payer-action", "href": "https://www.sandbox.paypal.com/checkoutnow?token=X"}]
    p = pay(q, "Slow Pay Ltd").json()
    r = approve(p["id"], MAKER, "maker").json()
    assert r["status"] == "AWAITING_PAYER" and r["payer_action_url"].startswith("https://www.sandbox.paypal.com/")
    assert c.post(f"/api/proposals/{p['id']}/capture", headers=AGENT).status_code == 401   # agents can't
    assert c.post(f"/api/proposals/{p['id']}/capture", headers=MAKER).json()["status"] == "AWAITING_PAYER"
    order["status"] = "APPROVED"                                                         # payer approves
    assert c.post(f"/api/proposals/{p['id']}/capture", headers=MAKER).json()["status"] == "EXECUTED"


def test_order_changed_after_approval_is_refused():
    q = quote("Shifty Parts", "sales@shifty.example.com", "99.00")
    p = pay(q, "Shifty Parts").json()
    main.paypal._mock_orders[q["order_id"]]["purchase_units"][0]["amount"]["value"] = "990.00"
    r = approve(p["id"], MAKER, "maker")
    assert r.status_code == 409 and "no longer matches" in r.json()["detail"]
    assert c.get(f"/api/proposals/{p['id']}", headers=MAKER).json()["status"] == "FAILED"
