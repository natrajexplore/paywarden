"""Policy Decision Point (PDP) — zero trust, default deny.

Every money movement an AI agent proposes is evaluated here before any PayPal API is called.
The agent is an untrusted principal: it is authenticated, least-privileged (a spend *mandate*),
and each request is re-evaluated in context (velocity, history, payee, geography).

Verdicts (strongest wins): DENY > DUAL_CONTROL > STEP_UP > ALLOW
  ALLOW         -> executed automatically within mandate
  STEP_UP       -> one human operator approves with TOTP (NIST SP 800-63B AAL2-style MFA)
  DUAL_CONTROL  -> maker + checker, two different humans, both with TOTP (four-eyes principle)
  DENY          -> blocked, quarantined, logged

Regulatory anchors (see docs/COMPLIANCE_MATRIX.md for the full mapping):
  * OFAC sanctions screening (31 CFR Ch. V), EU/UN consolidated lists
  * BSA/AML red flags & structuring awareness (31 USC 5324), SAR review (31 CFR 1020.320)
  * FinCEN Travel Rule record-keeping at >= USD 3,000 (31 CFR 1010.410(f))
  * FATF Recommendations 10/16 (CDD, wire transparency) and high-risk jurisdiction lists
  * FFIEC authentication guidance (2021) — layered security, step-up for high-risk actions
  * EU PSD2 RTS on SCA — dynamic linking of amount + payee to the authentication
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from difflib import SequenceMatcher
from pathlib import Path

from . import injection, redact

DATA = Path(__file__).resolve().parent.parent.parent / "data"

ORDER = {"ALLOW": 0, "STEP_UP": 1, "DUAL_CONTROL": 2, "DENY": 3}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Labelled parties in the source document are screened too, so a payee name supplied by the agent
# ("Goods") cannot hide the real counterparty ("Seller: Darkwave Holdings").
PARTY_LINE = re.compile(rf"(?im)^\s*(?:{redact.PARTY_LABELS})\s*[:\-]\s*(.+?)\s*$")
PAID_ACTIONS = ("payout", "order")  # money that left us; invoices bill someone else


@dataclass
class Mandate:
    """Least-privilege spend authority granted to one agent. Mirrors a bank's delegated limits."""
    agent_id: str = "ap-agent-01"
    per_txn_auto_limit: Decimal = Decimal("1000.00")    # above -> STEP_UP
    dual_control_limit: Decimal = Decimal("5000.00")    # above -> DUAL_CONTROL
    hard_txn_limit: Decimal = Decimal("20000.00")       # above -> DENY
    daily_limit: Decimal = Decimal("25000.00")          # rolling 24h -> DENY beyond
    max_txn_per_hour: int = 5
    currencies: tuple = ("USD", "EUR", "GBP", "CAD", "AUD", "INR")
    actions: tuple = ("payout", "invoice", "order")
    purposes: tuple = ("contractor_services", "freelance_work", "supplies", "consulting", "refund")
    # Calibrated signals from a decision model (TypeSafe Jev): manipulation probability, choice confidence
    manipulation_deny: float = 0.80        # >= -> DENY
    manipulation_review: float = 0.50      # >= -> STEP_UP
    min_model_confidence: float = 0.70     # payee/amount pick below -> STEP_UP


@dataclass
class Proposal:
    action: str
    payee_email: str
    payee_name: str
    amount: str
    currency: str
    purpose: str
    country: str = "US"
    note: str = ""
    source_text: str = ""
    agent_id: str = "ap-agent-01"
    payee_key: str = ""   # blind index of the payee (set by the store); falls back to the email
    ai_signals: dict = field(default_factory=dict)  # {"manipulation": p, "confidence": {...}} from the model


@dataclass
class Decision:
    verdict: str = "ALLOW"
    risk_score: int = 0
    reasons: list = field(default_factory=list)
    controls: list = field(default_factory=list)   # control IDs that fired
    travel_rule: bool = False
    sar_review: bool = False

    def escalate(self, verdict: str, reason: str, control: str, risk: int) -> None:
        if ORDER[verdict] > ORDER[self.verdict]:
            self.verdict = verdict
        self.reasons.append(reason)
        if control not in self.controls:
            self.controls.append(control)
        self.risk_score = min(100, self.risk_score + risk)

    def to_dict(self) -> dict:
        return asdict(self)


def _load(name: str) -> dict:
    with open(DATA / name, encoding="utf-8") as f:
        return json.load(f)


def _norm(s: str) -> str:
    s = re.sub(r"[^a-z0-9 ]", " ", s.lower())
    s = re.sub(r"\b(llc|ltd|inc|co|corp|company|limited|gmbh|sa|the)\b", " ", s)
    return " ".join(s.split())


class PolicyEngine:
    def __init__(self, mandate: Mandate | None = None):
        self.mandate = mandate or Mandate()
        self.watchlist = _load("watchlist.json")
        self.geo = _load("geo_risk.json")
        self.fx = {c: Decimal(str(r)) for c, r in _load("fx_rates.json")["usd_per_unit"].items()}

    def usd(self, amount, currency: str) -> Decimal:
        """USD equivalent for limit checks. Unknown currencies never reach here (LIM-00 denies)."""
        return (Decimal(amount) * self.fx.get(currency, Decimal("1E9"))).quantize(Decimal("0.01"))

    # ---- screening -------------------------------------------------------
    def screen_name(self, name: str) -> tuple[float, str | None]:
        target = _norm(name)
        best, hit = 0.0, None
        if not target:
            return best, hit
        for entry in self.watchlist["entries"]:
            for candidate in [entry["name"], *entry.get("aliases", [])]:
                score = SequenceMatcher(None, target, _norm(candidate)).ratio()
                # token-set boost: all candidate tokens present in target
                ctoks, ttoks = set(_norm(candidate).split()), set(target.split())
                if ctoks and ctoks <= ttoks:
                    score = max(score, 0.95)
                if score > best:
                    best, hit = score, f'{entry["name"]} [{entry["list"]}]'
        return best, hit

    # ---- main evaluation -------------------------------------------------
    def evaluate(self, p: Proposal, history: list[dict]) -> Decision:
        d = Decision()
        m = self.mandate

        # 1. Authentication / authorisation of the agent (zero trust: who is asking?)
        if p.agent_id != m.agent_id:
            d.escalate("DENY", f"Unknown agent '{p.agent_id}' has no mandate", "ZT-01", 100)
            return d
        if p.action not in m.actions:
            d.escalate("DENY", f"Action '{p.action}' outside agent mandate", "ZT-02", 100)
            return d

        # 2. Strict input validation of model output (OWASP LLM05)
        try:
            amt = Decimal(p.amount)
        except InvalidOperation:
            d.escalate("DENY", "Amount is not a valid decimal", "VAL-01", 100)
            return d
        if amt <= 0 or amt.as_tuple().exponent < -2:
            d.escalate("DENY", "Amount must be positive with at most 2 decimals", "VAL-01", 100)
            return d
        if p.currency not in m.currencies:
            d.escalate("DENY", f"Currency {p.currency} not permitted", "VAL-02", 100)
        if not EMAIL_RE.match(p.payee_email or ""):
            d.escalate("DENY", "Payee email invalid", "VAL-03", 100)
        if p.purpose not in m.purposes:
            d.escalate("STEP_UP", f"Purpose '{p.purpose}' not in approved list", "VAL-04", 20)

        # 3. Prompt-injection / BEC indicators in the untrusted source document (OWASP LLM01)
        findings = injection.scan(p.source_text + " " + p.note)
        severe = {"fund sweep", "beneficiary change", "control bypass", "instruction override", "role hijack"}
        for f in findings:
            if f in severe:
                d.escalate("DENY", f"Untrusted document contains '{f}' — quarantined", "AI-01", 60)
            else:
                d.escalate("STEP_UP", f"Suspicious content in document: {f}", "AI-02", 25)

        # 3a. Model-based signals (decision model, e.g. TypeSafe Jev): a second, calibrated
        #     manipulation detector beside the regex scan, and "the model was unsure" -> human.
        risk = (p.ai_signals or {}).get("manipulation")
        if isinstance(risk, (int, float)):
            if risk >= m.manipulation_deny:
                d.escalate("DENY", f"AI model rates manipulation risk {risk:.2f} — quarantined", "AI-05", 60)
            elif risk >= m.manipulation_review:
                d.escalate("STEP_UP", f"AI model rates manipulation risk {risk:.2f} — human review", "AI-05", 25)
        conf = {k: c for k, c in ((p.ai_signals or {}).get("confidence") or {}).items() if isinstance(c, (int, float))}
        unsure = {k: c for k, c in conf.items() if c < m.min_model_confidence}
        if unsure:
            detail = ", ".join(f"{k} {c:.2f}" for k, c in sorted(unsure.items()))
            d.escalate("STEP_UP", f"AI model unsure of the extraction ({detail}) — confirm", "AI-06", 15)

        # 3b. Card data never enters PayWarden (keeps it out of PCI DSS cardholder-data scope)
        if redact.find_pans(p.source_text + " " + p.note):
            d.escalate("DENY", "Card number (PAN) found in document — card data is never processed; "
                               "request payment via PayPal instead", "PCI-01", 100)

        # 4. Provenance — the model may not invent numbers or beneficiaries
        if p.source_text:
            if not injection.amount_grounded(p.amount, p.source_text):
                d.escalate("DENY", f"Amount {p.amount} does not appear in source document", "AI-03", 70)
            if not injection.payee_grounded(p.payee_email, p.source_text):
                d.escalate("DENY", "Payee email does not appear in source document", "AI-04", 70)

        # 5. Sanctions screening (OFAC / UN / EU style, fuzzy)
        names = [p.payee_name, *(m.group(1) for m in PARTY_LINE.finditer(p.source_text))]
        score, hit = max((self.screen_name(n) for n in names), key=lambda r: r[0])
        if score >= 0.88:
            d.escalate("DENY", f"Sanctions match {score:.2f} vs {hit} — block & report", "AML-01", 100)
        elif score >= 0.75:
            d.escalate("DUAL_CONTROL", f"Potential sanctions match {score:.2f} vs {hit} — manual review",
                       "AML-02", 50)
        domain = p.payee_email.split("@")[-1].lower() if "@" in p.payee_email else ""
        if domain in self.watchlist.get("blocked_domains", []):
            d.escalate("DENY", f"Payee domain {domain} is on the block list", "AML-03", 100)

        # 6. Geography
        cc = (p.country or "").upper()
        if cc in self.geo["comprehensively_sanctioned"]:
            d.escalate("DENY", f"Country {cc} is comprehensively sanctioned", "GEO-01", 100)
        elif cc in self.geo["fatf_call_for_action"]:
            d.escalate("DENY", f"Country {cc} is on FATF call-for-action list", "GEO-02", 100)
        elif cc in self.geo["fatf_increased_monitoring"]:
            d.escalate("DUAL_CONTROL", f"Country {cc} under FATF increased monitoring — EDD", "GEO-03", 35)

        # 7. Limits and mandate — all in USD equivalent, so 6 currencies cannot mean 6x the mandate
        if p.currency not in self.fx:
            d.escalate("DENY", f"No exchange rate for {p.currency}: cannot apply limits", "LIM-00", 100)
            return d
        amt_usd = self.usd(p.amount, p.currency)
        if amt_usd > m.hard_txn_limit:
            d.escalate("DENY", f"Amount exceeds hard limit USD {m.hard_txn_limit} equivalent", "LIM-01", 100)
        elif amt_usd > m.dual_control_limit:
            d.escalate("DUAL_CONTROL", f"Amount > USD {m.dual_control_limit} equivalent requires maker-checker",
                       "LIM-02", 30)
        elif amt_usd > m.per_txn_auto_limit:
            d.escalate("STEP_UP", f"Amount > USD {m.per_txn_auto_limit} equivalent requires MFA approval",
                       "LIM-03", 15)

        now = time.time()
        committed = ("EXECUTED", "PENDING", "APPROVED", "AWAITING_PAYER", "EXECUTING", "CAPTURE_PENDING",
                     "UNCERTAIN")
        day = [h for h in history if now - h["ts"] < 86400 and h["status"] in committed]
        hour = [h for h in day if now - h["ts"] < 3600]
        day_total = sum((self.usd(h["amount"], h["currency"]) for h in day), Decimal("0"))
        if day_total + amt_usd > m.daily_limit:
            d.escalate("DENY", f"Rolling 24h limit USD {m.daily_limit} equivalent (all currencies) would be exceeded",
                       "LIM-04", 80)
        if len(hour) >= m.max_txn_per_hour:
            d.escalate("STEP_UP", f"Velocity: {len(hour)} payments in the last hour", "LIM-05", 25)

        # 8. Duplicate / replay
        payee_key = p.payee_key or p.payee_email.strip().lower()
        dup = [h for h in day if h["payee"] == payee_key and Decimal(h["amount"]) == amt]
        if dup:
            d.escalate("DENY", "Duplicate: same payee and amount within 24h", "DUP-01", 60)

        # 9. New beneficiary (banks apply cooling-off / confirmation of payee)
        # Only money we actually *paid* proves a payee: an invoice we sent them proves nothing.
        known = {h["payee"] for h in history if h["status"] == "EXECUTED" and h.get("action") in PAID_ACTIONS}
        if payee_key not in known:
            d.escalate("STEP_UP", "First payment to this beneficiary — confirm payee", "BEN-01", 15)

        # 10. Structuring red flag (splitting to stay under reporting/approval thresholds)
        same_payee_day = [h for h in day if h["payee"] == payee_key]
        payee_total = sum((self.usd(h["amount"], h["currency"]) for h in same_payee_day), Decimal("0")) + amt_usd
        near = [h for h in same_payee_day
                if m.per_txn_auto_limit * Decimal("0.85") <= self.usd(h["amount"], h["currency"])
                <= m.per_txn_auto_limit]
        if (len(same_payee_day) >= 2 and payee_total > m.dual_control_limit) or len(near) >= 2:
            d.escalate("DUAL_CONTROL", "Possible structuring: split payments to one payee near limits",
                       "AML-04", 45)
            d.sar_review = True

        # 11. Travel Rule record-keeping (>= USD 3,000 equivalent)
        if amt_usd >= Decimal("3000"):
            d.travel_rule = True
            d.controls.append("TR-01")
            d.reasons.append("Travel Rule: originator & beneficiary info recorded (>= USD 3,000)")

        if not d.reasons:
            d.reasons.append("Within mandate; all checks passed")
        return d
