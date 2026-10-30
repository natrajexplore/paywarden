"""PayWarden API — the Policy Enforcement Point between AI agents and PayPal."""
from __future__ import annotations

import hmac
import json
import os
import re
import time
import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import agent
from .config import BASE_DIR, settings
from .paypal_client import PayPalError, paypal
from .samples import SAMPLES
from .security import auth, redact
from .security.middleware import BodySizeLimit, RateLimit, SecurityHeaders
from .security.policy import ORDER, PolicyEngine, Proposal
from .store import store

DEMO_MODE = settings.demo_mode
_docs = {} if DEMO_MODE else {"docs_url": None, "redoc_url": None, "openapi_url": None}  # shrink attack surface

app = FastAPI(title="PayWarden", version="0.2.0",
              description="Zero-trust payment firewall for AI agents on PayPal (sandbox)", **_docs)
# Starlette runs the last-added middleware first: headers wrap everything, incl. 413/429 responses.
app.add_middleware(RateLimit, per_minute=int(os.getenv("RATE_LIMIT_PER_MIN", "120")))
app.add_middleware(BodySizeLimit, max_bytes=settings.max_body_bytes)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_methods=["GET", "POST"],
                   allow_headers=["Authorization", "Content-Type"], allow_credentials=False)
app.add_middleware(SecurityHeaders)

pdp = PolicyEngine()
STATIC = BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ---------------------------------------------------------------- models
class AnalyseIn(BaseModel):
    document: str = Field(min_length=10, max_length=20000)


class ApproveIn(BaseModel):
    # The operator's identity comes from their credential, never from the request body.
    totp: str = Field(pattern=r"^\d{6,8}$")
    binding: str = Field(pattern=r"^[0-9a-f]{64}$")


class RejectIn(BaseModel):
    reason: str = Field(default="rejected by operator", max_length=300)


# ---------------------------------------------------------------- helpers
def order_facts(order: dict) -> dict:
    """What PayPal itself says the order is for — the source of truth for agent-to-agent payments."""
    unit = (order.get("purchase_units") or [{}])[0]
    amt = unit.get("amount") or {}
    link = next((lk.get("href") for lk in order.get("links", []) if lk.get("rel") in ("payer-action", "approve")),
                None)
    return {"amount": str(amt.get("value", "")), "currency": str(amt.get("currency_code", "")).upper(),
            "payee_email": str((unit.get("payee") or {}).get("email_address", "")), "payer_action_url": link}


WAITING_FOR_PAYER = ("CREATED", "SAVED", "PAYER_ACTION_REQUIRED")


def single_unit(order: dict) -> bool:
    """Capturing pays *every* purchase unit, so only one-unit orders can be checked and approved."""
    return len(order.get("purchase_units") or []) == 1


def same_order(facts: dict, row: dict) -> bool:
    try:
        same_amount = Decimal(facts["amount"]) == Decimal(row["amount"])
    except InvalidOperation:
        return False
    return (same_amount and facts["currency"] == row["currency"]
            and facts["payee_email"].lower() == row["payee_email"].lower())


async def settle_order(pid: str, row: dict, actor: str) -> dict:
    """Capture a seller's PayPal Order — only if it still matches exactly what was approved."""
    oid = row["paypal_ref"]
    order = await paypal.get_order(oid)
    facts = order_facts(order)
    if not (single_unit(order) and same_order(facts, row)):
        store.update(pid, status="FAILED")
        store.audit.append(actor, "ORDER_CHANGED", {"proposal": pid, "order": oid})
        raise HTTPException(409, "PayPal order no longer matches what was approved")
    status = order.get("status")
    if status in WAITING_FOR_PAYER:
        store.update(pid, status="AWAITING_PAYER")
        store.audit.append(actor, "ORDER_AWAITING_PAYER", {"proposal": pid, "order": oid, "order_status": status})
        return {**store.get(pid), "payer_action_url": facts["payer_action_url"]}
    if status != "APPROVED":  # VOIDED, COMPLETED elsewhere, …: never payable again
        store.update(pid, status="FAILED")
        store.audit.append(actor, "ORDER_NOT_PAYABLE", {"proposal": pid, "order": oid, "order_status": status})
        raise HTTPException(409, f"PayPal order is {status}")
    res = await paypal.capture_order(oid, pid)
    captures = ((res.get("purchase_units") or [{}])[0].get("payments") or {}).get("captures") or [{}]
    cap_id, cap_status = captures[0].get("id"), captures[0].get("status")
    details = {"proposal": pid, "action": "order", "paypal_ref": oid, "capture": cap_id,
               "capture_status": cap_status, "amount": row["amount"], "currency": row["currency"],
               "mode": paypal.mode}
    if cap_status == "COMPLETED":
        store.update(pid, status="EXECUTED")
        store.audit.append(actor, "PAYPAL_EXECUTED", details)
    elif cap_status == "PENDING":  # funds not settled yet (e.g. under PayPal review)
        store.update(pid, status="CAPTURE_PENDING")
        store.audit.append(actor, "PAYPAL_CAPTURE_PENDING", details)
    else:
        store.update(pid, status="FAILED")
        store.audit.append(actor, "PAYPAL_CAPTURE_FAILED", details)
        raise HTTPException(502, f"PayPal did not complete the capture ({cap_status or 'no capture'})")
    return store.get(pid)


EXECUTABLE = ("APPROVED", "PENDING", "AWAITING_PAYER")


async def execute(pid: str, actor: str) -> dict:
    # Atomic claim: a concurrent reject, capture or approval can never run a second execution.
    if not store.transition(pid, EXECUTABLE, "EXECUTING"):
        raise HTTPException(409, "proposal is already being executed or is no longer executable")
    row = store.get(pid, reveal=True)
    try:
        if row["action"] == "order":
            return await settle_order(pid, row, actor)
        if row["action"] == "payout":
            res = await paypal.create_payout(pid, row["payee_email"], row["amount"], row["currency"],
                                             row["note"] or "Payment")
            ref = res["batch_header"]["payout_batch_id"]
        else:
            res = await paypal.create_and_send_invoice(pid, row["payee_email"], row["payee_name"],
                                                       row["amount"], row["currency"], row["note"])
            ref = res["id"]
        store.update(pid, status="EXECUTED", paypal_ref=ref)
        store.audit.append(actor, "PAYPAL_EXECUTED",
                           {"proposal": pid, "action": row["action"], "paypal_ref": ref,
                            "amount": row["amount"], "currency": row["currency"], "mode": paypal.mode})
    except PayPalError as e:
        store.update(pid, status="FAILED")
        store.audit.append(actor, "PAYPAL_FAILED", {"proposal": pid, "status": e.status})  # body withheld: may hold PII
        raise HTTPException(502, f"PayPal rejected the request ({e.status})")
    return store.get(pid)


# ---------------------------------------------------------------- routes
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/healthz")
def health():
    return {"ok": True, "paypal_mode": paypal.mode,
            "ai_engine": settings.anthropic_model if settings.ai_live else "offline-extractor",
            "demo_mode": DEMO_MODE, "redaction": settings.redaction_level}


@app.get("/api/samples")
def samples():
    return SAMPLES


@app.get("/api/demo/totp", dependencies=[Depends(auth.require_operator)])
def demo_totp():
    """DEMO ONLY: shows current codes so judges can test without an authenticator app."""
    if not DEMO_MODE:
        raise HTTPException(404)
    return {op: pyotp.TOTP(s).now() for op, s in settings.operator_totp.items()}


@app.get("/api/policy", dependencies=[Depends(auth.require_agent_or_operator)])
def policy():
    m = pdp.mandate
    return {"agent_id": m.agent_id, "per_txn_auto_limit": str(m.per_txn_auto_limit),
            "dual_control_limit": str(m.dual_control_limit), "hard_txn_limit": str(m.hard_txn_limit),
            "daily_limit": str(m.daily_limit), "max_txn_per_hour": m.max_txn_per_hour,
            "currencies": m.currencies, "purposes": m.purposes}


AGENT_VIEW = ("id", "ts", "action", "payee_masked", "amount", "currency", "verdict", "risk", "status",
              "paypal_ref")


def agent_view(row: dict) -> dict:
    """Least privilege for AI agents: no approval binding, approver list or AI summary."""
    out = {k: row[k] for k in AGENT_VIEW}
    out["reasons"], out["controls"] = row["decision"]["reasons"], row["decision"]["controls"]
    out["approvals_required"] = auth.required_approvers(row["verdict"])
    if row.get("payer_action_url"):
        out["payer_action_url"] = row["payer_action_url"]
    return out


async def decide(raw: dict, source_text: str, summary: str, channel: str, submitted_by: str,
                 paypal_ref: str | None = None) -> dict | None:
    """Every proposal, from any channel, takes this single path through the PDP."""
    try:
        p = Proposal(
            action=str(raw.get("action", "")), payee_email=str(raw.get("payee_email", "")).strip(),
            payee_name=str(raw.get("payee_name", ""))[:140], amount=str(raw.get("amount", "")),
            currency=str(raw.get("currency", "")).upper(), purpose=str(raw.get("purpose", "")),
            country=str(raw.get("country", "US")).upper()[:2], note=str(raw.get("note", ""))[:300],
            source_text=source_text, agent_id=pdp.mandate.agent_id,
        )
    except Exception:  # malformed tool call -> drop, but log
        store.audit.append("pep", "PROPOSAL_MALFORMED", {"raw_keys": sorted(raw.keys()), "channel": channel})
        return None
    p.payee_key = store.payee_key(p.payee_email) if p.payee_email else ""
    decision = pdp.evaluate(p, store.history(p.agent_id)).to_dict()
    row = store.create(p, decision, auth.binding_digest, summary, paypal_ref)
    store.audit.append("pep", "POLICY_DECISION",
                       {"proposal": row["id"], "verdict": decision["verdict"],
                        "risk": decision["risk_score"], "controls": decision["controls"],
                        "amount": p.amount, "currency": p.currency, "payee": row["payee_masked"],
                        "channel": channel, "submitted_by": submitted_by})
    if decision["verdict"] == "ALLOW":
        row = await execute(row["id"], "pep:auto")
    return row


@app.post("/api/agent/analyse")
async def analyse(body: AnalyseIn, principal: str = Depends(auth.require_agent_or_operator)):
    result = await agent.analyse(body.document)
    channel = "mcp" if principal == "agent" else "dashboard"
    store.audit.append("ai-agent", "AGENT_ANALYSED",
                       {"engine": result["engine"], "proposals": len(result["proposals"]),
                        "submitted_by": principal, "channel": channel,
                        "llm_egress": result.get("llm_egress", False),
                        "redaction": settings.redaction_level, "redacted": result.get("redactions", {})})
    out = []
    for raw in result["proposals"]:
        row = await decide(raw, body.document, result["summary"], channel, principal)
        if row:
            out.append(agent_view(row) if principal == "agent" else row)
    return {"engine": result["engine"], "summary": redact.redact_text(result["summary"], settings.redaction_level),
            "proposals": out}


class ProposeIn(BaseModel):
    """A structured proposal from an external AI agent (e.g. over MCP). The source document is
    mandatory: amount and payee must be provable from it (provenance, AI-03/04)."""
    action: str = Field(pattern="^(payout|invoice)$")
    payee_email: str = Field(max_length=254)
    payee_name: str = Field(max_length=140)
    amount: str = Field(pattern=r"^\d{1,9}(\.\d{1,2})?$")
    currency: str = Field(pattern="^[A-Za-z]{3}$")
    purpose: str = Field(max_length=40)
    country: str = Field(default="US", pattern="^[A-Za-z]{2}$")
    note: str = Field(default="", max_length=300)
    source_document: str = Field(min_length=10, max_length=20000)


@app.post("/api/agent/propose")
async def propose(body: ProposeIn, principal: str = Depends(auth.require_agent_or_operator)):
    raw = body.model_dump(exclude={"source_document"})
    store.audit.append("ai-agent", "AGENT_PROPOSED", {"submitted_by": principal, "channel": "mcp-propose"})
    row = await decide(raw, body.source_document, "", "mcp-propose", principal)
    if not row:
        raise HTTPException(422, "malformed proposal")
    return agent_view(row) if principal == "agent" else row


class PayOrderIn(BaseModel):
    """Agent-to-agent: pay a seller agent's PayPal Order. Amount, currency and payee are taken from
    PayPal, not from the agent; the seller's quote must name this order, the amount and the payee."""
    order_id: str = Field(pattern=r"^[A-Z0-9-]{5,40}$")
    payee_name: str = Field(min_length=1, max_length=140)
    purpose: str = Field(default="supplies", max_length=40)
    country: str = Field(default="US", pattern="^[A-Za-z]{2}$")
    source_document: str = Field(min_length=10, max_length=20000)


@app.post("/api/agent/pay-order")
async def pay_order(body: PayOrderIn, principal: str = Depends(auth.require_agent_or_operator)):
    doc = body.source_document
    # Whole-token match: a prefix of a longer order id in the quote does not count.
    id_in_quote = re.search(rf"(?<![A-Za-z0-9-]){re.escape(body.order_id)}(?![A-Za-z0-9-])", doc)
    if not id_in_quote or body.payee_name.strip().lower() not in doc.lower():
        store.audit.append("pep", "ORDER_NOT_GROUNDED", {"order": body.order_id, "submitted_by": principal})
        raise HTTPException(422, "the seller's quote must contain this order id and payee name")
    try:
        order = await paypal.get_order(body.order_id)
    except PayPalError as e:
        raise HTTPException(404 if e.status == 404 else 502, f"PayPal order lookup failed ({e.status})")
    status = order.get("status")
    if status not in WAITING_FOR_PAYER + ("APPROVED",):
        store.audit.append("pep", "ORDER_NOT_PAYABLE", {"order": body.order_id, "order_status": status})
        raise HTTPException(409, f"PayPal order is {status}")
    if not single_unit(order):
        store.audit.append("pep", "ORDER_MULTI_UNIT", {"order": body.order_id, "submitted_by": principal})
        raise HTTPException(422, "only orders with exactly one purchase unit can be paid")
    facts = order_facts(order)
    raw = {"action": "order", "payee_email": facts["payee_email"], "payee_name": body.payee_name,
           "amount": facts["amount"], "currency": facts["currency"], "purpose": body.purpose,
           "country": body.country, "note": f"PayPal order {body.order_id}"}
    store.audit.append("ai-agent", "AGENT_PAY_ORDER", {"order": body.order_id, "submitted_by": principal})
    row = await decide(raw, doc, "", "a2a-order", principal, paypal_ref=body.order_id)
    if not row:
        raise HTTPException(422, "malformed order")
    return agent_view(row) if principal == "agent" else row


class QuoteIn(BaseModel):
    seller_name: str = Field(min_length=1, max_length=140)
    seller_email: str = Field(max_length=254)
    amount: str = Field(pattern=r"^\d{1,9}(\.\d{1,2})?$")
    currency: str = Field(default="USD", pattern="^[A-Z]{3}$")
    description: str = Field(default="Goods", max_length=120)


@app.post("/api/demo/a2a/quote", dependencies=[Depends(auth.require_agent_or_operator)])
async def seller_quote(body: QuoteIn):
    """DEMO ONLY: plays the *seller* agent — creates a PayPal Order payable to the seller and
    returns the quote message a buyer agent would receive."""
    if not DEMO_MODE:
        raise HTTPException(404)
    ref = uuid.uuid4().hex[:12]
    try:
        order = await paypal.create_order(ref, body.amount, body.currency, body.description, body.seller_email)
    except PayPalError as e:
        raise HTTPException(502, f"PayPal rejected the order ({e.status})")
    quote = (f"QUOTE {ref}\nSeller: {body.seller_name}\nEmail: {body.seller_email}\nItem: {body.description}\n"
             f"Total: {body.amount} {body.currency}\nPayPal order: {order['id']}")
    store.audit.append("seller-agent", "SELLER_QUOTE_CREATED", {"order": order["id"], "mode": paypal.mode})
    return {"order_id": order["id"], "quote": quote, "payer_action_url": order_facts(order)["payer_action_url"]}


@app.get("/api/proposals", dependencies=[Depends(auth.require_operator)])
def list_proposals():
    return store.list()


@app.get("/api/proposals/{pid}")
def get_proposal(pid: str, principal: str = Depends(auth.require_agent_or_operator)):
    row = store.get(pid)
    if not row:
        raise HTTPException(404)
    return agent_view(row) if principal == "agent" else row


@app.post("/api/proposals/{pid}/approve")
async def approve(pid: str, body: ApproveIn, operator: str = Depends(auth.require_operator)):
    row = store.get(pid, reveal=True)
    if not row:
        raise HTTPException(404)
    if row["status"] != "PENDING":
        raise HTTPException(409, f"proposal is {row['status']}")
    if auth.locked(operator):
        store.audit.append(operator, "MFA_LOCKED_ATTEMPT", {"proposal": pid})
        raise HTTPException(423, "operator locked after repeated MFA failures - contact a security admin")
    # Cheap, non-secret checks first so a doomed request never consumes a one-time code.
    expected = auth.binding_digest(pid, row["amount"], row["currency"], row["payee_email"])
    if not (hmac.compare_digest(body.binding, expected) and hmac.compare_digest(row["binding"], expected)):
        store.audit.append(operator, "BINDING_MISMATCH", {"proposal": pid})
        raise HTTPException(409, "approval not bound to this exact amount/payee")
    if any(a["operator"] == operator for a in row["approvals"]):
        raise HTTPException(409, "four-eyes rule: a second, different operator must approve")
    if not auth.verify_totp(operator, body.totp):
        store.audit.append(operator, "MFA_FAILED", {"proposal": pid, "locked": auth.locked(operator)})
        raise HTTPException(401, "invalid or already-used one-time code")

    approvals = row["approvals"] + [{"operator": operator, "ts": time.time()}]
    store.update(pid, approvals=approvals)
    store.audit.append(operator, "APPROVED_MFA", {"proposal": pid, "n": len(approvals)})

    verdict = max(row["verdict"], reevaluate(pid, row).verdict, key=lambda v: ORDER[v])
    need = auth.required_approvers(verdict)
    if len(approvals) < need:
        return {"status": "AWAITING_SECOND_APPROVER", "approvals": len(approvals), "required": need}
    return await execute(pid, ",".join(a["operator"] for a in approvals))


def reevaluate(pid: str, row: dict):
    """Zero trust: re-evaluate at execution time (prevents time-of-check/time-of-use gaps)."""
    p = Proposal(action=row["action"], payee_email=row["payee_email"], payee_name=row["payee_name"],
                 amount=row["amount"], currency=row["currency"], purpose=row["purpose"],
                 country=row["country"], note=row["note"], agent_id=row["agent_id"],
                 payee_key=store.payee_key(row["payee_email"]))
    fresh = pdp.evaluate(p, store.history(row["agent_id"], exclude=pid))
    if fresh.verdict == "DENY":
        store.update(pid, status="DENIED")
        store.audit.append("pep", "DENIED_ON_REEVALUATION", {"proposal": pid, "reasons": fresh.reasons})
        raise HTTPException(409, "re-evaluation denied: " + "; ".join(fresh.reasons))
    return fresh


@app.post("/api/proposals/{pid}/capture")
async def capture(pid: str, operator: str = Depends(auth.require_operator)):
    """Finish an approved agent-to-agent payment once the payer has approved the order in PayPal."""
    row = store.get(pid, reveal=True)
    if not row:
        raise HTTPException(404)
    if row["status"] != "AWAITING_PAYER":
        raise HTTPException(409, f"proposal is {row['status']}")
    # The fresh verdict can be stronger (e.g. structuring since approval): demand the missing approvals.
    verdict = max(row["verdict"], reevaluate(pid, row).verdict, key=lambda v: ORDER[v])
    need = auth.required_approvers(verdict)
    if len(row["approvals"]) < need:
        if store.transition(pid, ("AWAITING_PAYER",), "PENDING"):
            store.audit.append("pep", "ESCALATED_ON_REEVALUATION", {"proposal": pid, "verdict": verdict})
        return {**store.get(pid), "approvals_required": need}
    return await execute(pid, operator)


@app.post("/api/proposals/{pid}/reject")
def reject(pid: str, body: RejectIn, operator: str = Depends(auth.require_operator)):
    row = store.get(pid)
    if not row:
        raise HTTPException(404)
    if not store.transition(pid, ("PENDING", "AWAITING_PAYER"), "REJECTED"):
        raise HTTPException(409, f"proposal is {store.get(pid)['status']}")
    store.audit.append(operator, "REJECTED",
                       {"proposal": pid, "reason": redact.redact_text(body.reason, settings.redaction_level)})
    return store.get(pid)


@app.get("/api/audit", dependencies=[Depends(auth.require_operator)])
def audit_log():
    return store.audit.entries()


@app.get("/api/audit/verify", dependencies=[Depends(auth.require_operator)])
def audit_verify():
    return store.audit.verify()


def _fresh(ts: str | None) -> bool:
    try:
        t = datetime.fromisoformat((ts or "").replace("Z", "+00:00")).timestamp()
    except ValueError:
        return False
    return abs(time.time() - t) <= settings.webhook_tolerance_seconds


@app.post("/api/webhooks/paypal")
async def paypal_webhook(request: Request):
    def reject_hook(reason: str, event_type=None):
        store.audit.append("paypal-webhook", "WEBHOOK_REJECTED", {"reason": reason, "event_type": event_type})
        return JSONResponse({"accepted": False, "reason": reason}, status_code=400)

    try:
        event = json.loads(await request.body())
        if not isinstance(event, dict):
            raise ValueError
    except ValueError:
        return reject_hook("malformed body")
    etype = str(event.get("event_type", ""))[:80]
    # Replay window first: cheap, and stops re-sent captures of genuine events.
    if not _fresh(request.headers.get("paypal-transmission-time")):
        return reject_hook("stale or missing transmission time", etype)
    tid = request.headers.get("paypal-transmission-id", "")[:128]
    if not tid:
        return reject_hook("missing transmission id", etype)
    # Never act on unauthenticated callbacks (spoofed "payment completed" is a classic fraud).
    if not await paypal.verify_webhook(dict(request.headers), event):
        return reject_hook("signature not verified", etype)
    if store.webhook_replayed(tid):
        return reject_hook("replayed transmission", etype)
    store.audit.append("paypal-webhook", "WEBHOOK_RECEIVED",
                       {"event_type": etype, "id": str(event.get("id", ""))[:80], "verified": True})
    return {"accepted": True}
