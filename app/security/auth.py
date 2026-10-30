"""Operator authentication, step-up MFA and dual control.

* API access: one bearer token *per operator*; identity comes from the credential, never from the
  request body (demo-grade; swap for OIDC/mTLS + FIDO2 in prod). Constant-time comparison.
* Step-up: RFC 6238 TOTP — something-you-have factor (NIST SP 800-63B AAL2 when combined with the
  operator credential; FFIEC 2021 guidance: layered, risk-based authentication).
  - Replay protection: each time-step is accepted at most once per operator (RFC 6238 §5.2,
    SP 800-63B §5.1.4.2).
  - Throttling: lockout after N consecutive failures (SP 800-63B §5.2.2, PCI DSS 8.3.4).
* Dynamic linking (EU PSD2 RTS Art. 5): the approval is bound by HMAC-SHA256 (dedicated key) to
  the exact amount, currency and payee the human saw. If anything changes after approval, it is void.
* Dual control / four-eyes: high-risk payments need two *different* operators (maker + checker).
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time

import pyotp
from fastapi import Header, HTTPException

from ..config import settings

_lock = threading.Lock()
_failures: dict[str, int] = {}
_locked_until: dict[str, float] = {}
_last_step: dict[str, int] = {}


def require_operator(authorization: str = Header(default="")) -> str:
    """Returns the authenticated operator's name. Checks every token so timing leaks nothing."""
    token = authorization.removeprefix("Bearer ").strip().encode()
    who = None
    for op, expected in settings.operator_tokens.items():
        if hmac.compare_digest(token, expected.encode()):
            who = op
    if not who:
        raise HTTPException(status_code=401, detail="operator authentication required")
    return who


def locked(operator: str) -> bool:
    with _lock:
        return _locked_until.get(operator, 0) > time.time()


def verify_totp(operator: str, code: str) -> bool:
    """True once per valid code. Failures count toward lockout; replays count as failures."""
    secret = settings.operator_totp.get(operator)
    ok = False
    with _lock:
        if secret and code and code.isdigit() and _locked_until.get(operator, 0) <= time.time():
            totp = pyotp.TOTP(secret)
            now_step = int(time.time()) // totp.interval
            for step in (now_step - 1, now_step, now_step + 1):
                if step > _last_step.get(operator, -1) and hmac.compare_digest(totp.generate_otp(step), code):
                    _last_step[operator] = step
                    ok = True
                    break
        if ok:
            _failures.pop(operator, None)
        else:
            _failures[operator] = _failures.get(operator, 0) + 1
            if _failures[operator] >= settings.mfa_max_failures:
                _locked_until[operator] = time.time() + settings.mfa_lockout_seconds
                _failures.pop(operator, None)
    return ok


def reset_mfa_state() -> None:
    """Test helper / break-glass: clears replay and lockout state."""
    with _lock:
        _failures.clear()
        _locked_until.clear()
        _last_step.clear()


def binding_digest(proposal_id: str, amount: str, currency: str, payee: str) -> str:
    """What-you-see-is-what-you-sign. Shown to the approver; must be echoed back."""
    msg = f"{proposal_id}|{amount}|{currency}|{payee.strip().lower()}".encode()
    return hmac.new(settings.binding_key, msg, hashlib.sha256).hexdigest()


def required_approvers(verdict: str) -> int:
    return {"STEP_UP": 1, "DUAL_CONTROL": 2}.get(verdict, 0)
