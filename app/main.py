"""PayWarden API — the Policy Enforcement Point between AI agents and PayPal."""
from __future__ import annotations

import hmac
import json
import os
import time
from datetime import datetime

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
async def execute(pid: str, actor: str) -> dict:
    row = store.get(pid, reveal=True)
    try:
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


@app.get("/api/policy", dependencies=[Depends(auth.require_operator)])
def policy():
    m = pdp.mandate
    return {"agent_id": m.agent_id, "per_txn_auto_limit": str(m.per_txn_auto_limit),
            "dual_control_limit": str(m.dual_control_limit), "hard_txn_limit": str(m.hard_txn_limit),
            "daily_limit": str(m.daily_limit), "max_txn_per_hour": m.max_txn_per_hour,
            "currencies": m.currencies, "purposes": m.purposes}


@app.post("/api/agent/analyse")
async def analyse(body: AnalyseIn, operator: str = Depends(auth.require_operator)):
    result = await agent.analyse(body.document)
    store.audit.append("ai-agent", "AGENT_ANALYSED",
                       {"engine": result["engine"], "proposals": len(result["proposals"]),
                        "submitted_by": operator, "llm_egress": result.get("llm_egress", False),
                        "redaction": settings.redaction_level, "redacted": result.get("redactions", {})})
    out = []
    for raw in result["proposals"]:
        try:
            p = Proposal(
                action=str(raw.get("action", "")), payee_email=str(raw.get("payee_email", "")).strip(),
                payee_name=str(raw.get("payee_name", ""))[:140], amount=str(raw.get("amount", "")),
                currency=str(raw.get("currency", "")).upper(), purpose=str(raw.get("purpose", "")),
                country=str(raw.get("country", "US")).upper()[:2], note=str(raw.get("note", ""))[:300],
                source_text=body.document, agent_id=pdp.mandate.agent_id,
            )
        except Exception:  # malformed tool call -> drop, but log
            store.audit.append("pep", "PROPOSAL_MALFORMED", {"raw_keys": sorted(raw.keys())})
            continue
        p.payee_key = store.payee_key(p.payee_email) if p.payee_email else ""
        decision = pdp.evaluate(p, store.history(p.agent_id)).to_dict()
        row = store.create(p, decision, auth.binding_digest, result["summary"])
        store.audit.append("pep", "POLICY_DECISION",
                           {"proposal": row["id"], "verdict": decision["verdict"],
                            "risk": decision["risk_score"], "controls": decision["controls"],
                            "amount": p.amount, "currency": p.currency, "payee": row["payee_masked"]})
        if decision["verdict"] == "ALLOW":
            row = await execute(row["id"], "pep:auto")
        out.append(row)
    return {"engine": result["engine"], "summary": redact.redact_text(result["summary"], settings.redaction_level),
            "proposals": out}


@app.get("/api/proposals", dependencies=[Depends(auth.require_operator)])
def list_proposals():
    return store.list()


@app.get("/api/proposals/{pid}", dependencies=[Depends(auth.require_operator)])
def get_proposal(pid: str):
    row = store.get(pid)
    if not row:
        raise HTTPException(404)
    return row


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

    # Zero trust: re-evaluate at execution time (prevents time-of-check/time-of-use gaps)
    p = Proposal(action=row["action"], payee_email=row["payee_email"], payee_name=row["payee_name"],
                 amount=row["amount"], currency=row["currency"], purpose=row["purpose"],
                 country=row["country"], note=row["note"], agent_id=row["agent_id"],
                 payee_key=store.payee_key(row["payee_email"]))
    fresh = pdp.evaluate(p, store.history(row["agent_id"], exclude=pid))
    if fresh.verdict == "DENY":
        store.update(pid, status="DENIED")
        store.audit.append("pep", "DENIED_ON_REEVALUATION", {"proposal": pid, "reasons": fresh.reasons})
        raise HTTPException(409, "re-evaluation denied: " + "; ".join(fresh.reasons))
    verdict = max(row["verdict"], fresh.verdict, key=lambda v: ORDER[v])
    need = auth.required_approvers(verdict)
    if len(approvals) < need:
        return {"status": "AWAITING_SECOND_APPROVER", "approvals": len(approvals), "required": need}
    return await execute(pid, ",".join(a["operator"] for a in approvals))


@app.post("/api/proposals/{pid}/reject")
def reject(pid: str, body: RejectIn, operator: str = Depends(auth.require_operator)):
    row = store.get(pid)
    if not row:
        raise HTTPException(404)
    if row["status"] != "PENDING":
        raise HTTPException(409, f"proposal is {row['status']}")
    store.update(pid, status="REJECTED")
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
