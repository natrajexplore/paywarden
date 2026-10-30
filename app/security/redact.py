"""PII / financial-identifier redaction.

Two jobs:
  1. Data minimisation before third-party egress: the document sent to the LLM has financial
     identifiers masked and emails (and, in strict mode, labelled party names) swapped for
     placeholders that are mapped back locally after the model answers. The model never needs
     the real values to *propose* a payment; the PEP checks provenance against the original.
  2. Redaction of free text that PayWarden stores, logs or returns (notes, AI summaries,
     operator-entered reasons).

Card numbers (PANs) are never processed: PayWarden is out of PCI cardholder-data scope by design,
so a Luhn-valid PAN is always masked and also fails policy (PCI-01 in policy.py).

Levels:  off      -> nothing (demo only; refused when PAYWARDEN_DEMO_MODE=false)
         standard -> PAN, IBAN, SWIFT/BIC, account & routing numbers, SSN, phone masked;
                     emails pseudonymised for the LLM and masked in output
         strict   -> standard + labelled party names (From:/Payee:/Vendor:…) pseudonymised for the LLM

Controls mapped: PCI DSS v4.0.1 3.3–3.5 (don't retain / render PAN unreadable), GLBA Safeguards
314.4(c), GDPR Art. 5(1)(c) data minimisation + Art. 25/32 pseudonymisation, NYDFS 500.13,
EU AI Act Art. 10 data governance, OWASP LLM02 (sensitive information disclosure).
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .crypto import mask_email

LEVELS = ("off", "standard", "strict")

_PAN = re.compile(r"(?<![\w.,])(?:\d[ -]?){12,18}\d(?![\w.,])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
_SWIFT = re.compile(r"(?i)\b(swift|bic)(\s*(?:code)?\s*[:#]?\s*)([A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b")
_ROUTING = re.compile(r"(?i)\b(routing|aba|sort code|ifsc)(\s*(?:no\.?|number|#)?\s*[:#]?\s*)([A-Z0-9][A-Z0-9 -]{4,14}[A-Z0-9])")
_ACCOUNT = re.compile(r"(?i)\b(account|acct|a/c)(\s*(?:no\.?|number|#)?\s*[:#]?\s*)(\d[\d -]{4,22}\d)")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_PHONE = re.compile(r"(?<![\w.])\+?\(?\d[\d ().-]{8,18}\d(?![\w])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# One list of counterparty labels, shared by redaction, sanctions screening and the offline extractor.
PARTY_LABELS = r"from|payee|bill from|contractor|vendor|supplier|seller"
_PARTY = re.compile(rf"(?im)^(\s*(?:{PARTY_LABELS})\s*[:\-]\s*)(.+?)\s*$")


def luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def find_pans(text: str) -> list[str]:
    out = []
    for m in _PAN.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            out.append(m.group(0))
    return out


def _is_phone(s: str) -> bool:
    digits = re.sub(r"\D", "", s)
    # 10–15 digits (E.164) and not a decimal amount like 1234567890.00
    return 10 <= len(digits) <= 15 and not re.search(r"\.\d{2}$", s)


def _mask_identifiers(text: str, counts: Counter) -> str:
    """Mask financial identifiers and government IDs (keeps last 4 where useful for humans)."""
    def pan(m):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and luhn_ok(digits):
            counts["pan"] += 1
            return "[REDACTED:PAN]"
        return m.group(0)

    def labelled(kind):
        def f(m):
            counts[kind] += 1
            v = re.sub(r"[\s-]", "", m.group(3))
            return f"{m.group(1)}{m.group(2)}[REDACTED:{kind.upper()}…{v[-4:]}]"
        return f

    def iban(m):
        counts["iban"] += 1
        return f"[REDACTED:IBAN…{m.group(0).replace(' ', '')[-4:]}]"

    def ssn(_m):
        counts["ssn"] += 1
        return "[REDACTED:SSN]"

    def phone(m):
        if not _is_phone(m.group(0)):
            return m.group(0)
        counts["phone"] += 1
        return "[REDACTED:PHONE]"

    text = _PAN.sub(pan, text)
    text = _IBAN.sub(iban, text)
    text = _SWIFT.sub(labelled("swift"), text)
    text = _ROUTING.sub(labelled("routing"), text)
    text = _ACCOUNT.sub(labelled("account"), text)
    text = _SSN.sub(ssn, text)
    return _PHONE.sub(phone, text)


def redact_text(text: str, level: str) -> str:
    """For anything PayWarden stores, logs or returns. Emails are masked, never pseudonymised."""
    if level == "off" or not text:
        return text
    text = _mask_identifiers(text, Counter())
    return _EMAIL.sub(lambda m: mask_email(m.group(0)), text)


@dataclass
class Pseudonymised:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)   # placeholder -> original
    counts: dict[str, int] = field(default_factory=dict)

    def restore(self, value: str) -> str:
        """Map placeholders in model output back to the original values (locally, never sent)."""
        out = str(value)
        for ph, original in self.mapping.items():
            out = out.replace(ph, original)
        return out


def pseudonymise(text: str, level: str) -> Pseudonymised:
    """Prepare an untrusted document for the LLM (third-party egress)."""
    if level == "off":
        return Pseudonymised(text)
    counts: Counter = Counter()
    mapping: dict[str, str] = {}
    reverse: dict[str, str] = {}

    def token(kind: str, original: str) -> str:
        key = original.strip().lower() if kind == "EMAIL" else original.strip()
        if key not in reverse:
            ph = f"[{kind}_{sum(1 for p in mapping if p.startswith('[' + kind)) + 1}]"
            reverse[key] = ph
            mapping[ph] = original.strip()
            counts[kind.lower()] += 1
        return reverse[key]

    if level == "strict":
        text = _PARTY.sub(lambda m: m.group(1) + token("PARTY", m.group(2)), text)
    text = _mask_identifiers(text, counts)
    text = _EMAIL.sub(lambda m: token("EMAIL", m.group(0)), text)
    return Pseudonymised(text, mapping, dict(counts))
