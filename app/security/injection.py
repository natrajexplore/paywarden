"""Defences for the AI layer (OWASP Top 10 for LLM Applications 2025).

LLM01 Prompt Injection  -> scan untrusted documents for instruction-like content, quarantine them.
LLM05 Improper Output   -> never trust model output; validate every tool argument (see policy.py).
LLM06 Excessive Agency  -> the agent only *proposes*; it holds no PayPal credentials.

"Amount provenance": the amount and payee the model proposes MUST literally appear in the source
document. A model talked into inventing a number or an email address is caught here.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation

_PATTERNS = [
    (r"ignore (all |any )?(previous|prior|above) (instructions|rules)", "instruction override"),
    (r"disregard (the )?(system|previous|above)", "instruction override"),
    (r"you are now|act as (an?|the) ", "role hijack"),
    (r"system prompt|developer mode|jailbreak", "prompt probing"),
    (r"(send|pay|transfer|wire) (all|the remaining|everything|the balance)", "fund sweep"),
    (r"(change|update|replace) (the )?(payee|recipient|beneficiary|bank|paypal) (email|account|details)",
     "beneficiary change"),
    (r"(urgent|immediately|right now).{0,40}(pay|transfer|wire)", "urgency pressure (BEC pattern)"),
    (r"do not (tell|notify|inform|alert)|keep this (secret|confidential)", "secrecy request (BEC pattern)"),
    (r"approve (this|it) automatically|skip (the )?(approval|review|verification)", "control bypass"),
    (r"<\s*(script|iframe)|\{\{.*\}\}|\[\[.*\]\]", "markup / template injection"),
]

_ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")


def scan(text: str) -> list[str]:
    findings: list[str] = []
    if _ZERO_WIDTH.search(text):
        findings.append("hidden zero-width characters")
    low = _ZERO_WIDTH.sub("", text).lower()
    for pat, label in _PATTERNS:
        if re.search(pat, low, flags=re.DOTALL) and label not in findings:
            findings.append(label)
    return findings


def _amounts_in(text: str) -> set[Decimal]:
    found: set[Decimal] = set()
    for m in re.finditer(r"(?<![\w.])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?(?![\w])", text):
        whole = m.group(1).replace(",", "")
        frac = m.group(2) or "0"
        try:
            found.add(Decimal(f"{whole}.{frac}").quantize(Decimal("0.01")))
        except InvalidOperation:
            continue
    return found


def amount_grounded(amount: str, source: str) -> bool:
    try:
        target = Decimal(amount).quantize(Decimal("0.01"))
    except InvalidOperation:
        return False
    return target in _amounts_in(source)


_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def payee_grounded(email: str, source: str) -> bool:
    """The exact address must appear as a whole email in the source: 'ya.designs@example.co' is
    not grounded by 'maya.designs@example.com'."""
    return email.strip().lower() in {m.lower() for m in _EMAIL.findall(source)}
