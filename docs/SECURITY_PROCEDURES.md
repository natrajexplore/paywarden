# PayWarden — Security Operating Procedures

> **Scope.** These are the operating procedures a bank or regulated payment business would expect
> around PayWarden. The hackathon build runs on the **PayPal sandbox**. The technical controls
> referenced here are implemented in this repo; the *organisational* steps (people, schedules,
> sign-offs) are templates for an adopting organisation and are **not** certified or audited.

Each procedure lists its trigger, owner, steps, the evidence it leaves behind, and the
frameworks it supports. "Audit" means the hash-chained, HMAC-signed log (`/api/audit`,
`/api/audit/verify`).

---

## 1. Deployment hardening checklist (before any non-demo deployment)

**Owner:** platform engineer · **Second person:** security officer signs off (four-eyes)

1. Set `PAYWARDEN_DEMO_MODE=false`. The app refuses to start unless every item below is satisfied:
   - `PAYWARDEN_DATA_KEY` and `PAYWARDEN_AUDIT_KEY` are present (32 random bytes each, base64).
   - `OPERATOR_MAKER_TOKEN` / `OPERATOR_CHECKER_TOKEN` are distinct, non-demo, at least 32 characters long.
   - `OPERATOR_MAKER_TOTP` / `OPERATOR_CHECKER_TOTP` are distinct, non-demo base32 seeds of ≥ 160 bits.
   - `PAYWARDEN_REDACTION` is `standard` or `strict`.
   - `ALLOWED_ORIGINS` lists explicit origins (no `*`).
2. Confirm `PAYPAL_BASE_URL` is a PayPal sandbox host over HTTPS. Any other value is refused.
3. Terminate TLS 1.2+ at the platform. Set `FORWARDED_ALLOW_IPS` to the proxy's address only.
4. Confirm `/docs`, `/redoc` and `/openapi.json` return 404 (they are disabled outside demo mode).
5. Confirm `/api/demo/totp` returns 404.
6. Store secrets only in the platform secret store (Render `sync: false` variables, a cloud KMS or
   a vault). Never put them in `.env` files on shared hosts, and never in git.
   `.dockerignore` keeps `.env` out of images.
7. Run `GET /api/audit/verify` and record the `head` hash as the deployment baseline.

**Evidence:** signed checklist, startup log, baseline chain head.
**Frameworks:** PCI DSS 2.2, 6.4, 8.3.6 · NYDFS 500.7 · CIS Controls 4 · DORA Art. 9.

## 2. Operator onboarding and access (joiner / mover / leaver)

**Owner:** security officer · **Approver:** business owner of the payments function

| Event | Steps |
|---|---|
| **Joiner** | Verify identity. Assign exactly one role (maker *or* checker). The same person must never hold both. Generate a token (`secrets.token_urlsafe(32)`) and a TOTP seed (`pyotp.random_base32(32)`). Deliver the seed by QR in person or over an out-of-band channel, never by email. Record the assignment. |
| **Mover** | Re-issue credentials for the new role and revoke the old ones in the same change. |
| **Leaver** | Rotate that operator's token and TOTP seed **the same day** (redeploy with new secrets). Review the audit log for that operator's actions in the last 30 days. |

**Evidence:** access request ticket, approver sign-off, deploy record of the rotation.
**Frameworks:** PCI DSS 7.2, 8.2.6, 8.3 · GLBA 314.4(c)(1) · NYDFS 500.7 · SOX ITGC · ISO 27001 A.5.15–5.18.

## 3. Quarterly access review

**Owner:** security officer · **Reviewer:** someone independent of the payments team

1. List the configured operators and the people who hold each credential.
2. From `/api/audit`, extract every `APPROVED_MFA`, `REJECTED`, `MFA_FAILED` and `MFA_LOCKED_ATTEMPT` event.
3. Confirm that each active credential belongs to a current employee in the right role, and that
   no single person has acted as both maker and checker.
4. Revoke anything that is not justified, then record the review.

**Frameworks:** PCI DSS 7.2.4 · NYDFS 500.7(a)(4) · SOX ITGC user access review.

## 4. Key management and rotation

**Owner:** security officer (key custodian) plus one more custodian (split knowledge / dual control)

| Key | Purpose (HKDF-derived) | Rotation |
|---|---|---|
| `PAYWARDEN_DATA_KEY` | `enc` AES-256-GCM PII encryption · `blind-index` payee lookup | Yearly, on suspected compromise, or when a custodian leaves |
| `PAYWARDEN_AUDIT_KEY` | `audit` HMAC per record · `binding` approval dynamic-linking | Yearly or on suspected compromise |
| Operator tokens / TOTP seeds | Operator authentication | Leaver event, suspected compromise, or 90 days |

Rotation steps:

1. Generate the new key on a trusted host. Two custodians each hold part of the process.
2. **Audit key:** export and archive the current chain (`/api/audit`) with its `verify` result and
   head hash **before** rotating. Records signed under the old key are verified against the archived
   key. Start the new chain segment and record both head hashes.
3. **Data key:** the hackathon build does not re-encrypt in place, so drain pending proposals first.
   In production, use envelope encryption (KMS-held KEK, per-record DEK) so rotation re-wraps DEKs only.
4. Destroy the old key material once retention requirements are met, and record the destruction.

**Frameworks:** PCI DSS 3.6–3.7 · NIST SP 800-57 · NYDFS 500.15 · ISO 27001 A.8.24.

## 5. Payment approval procedure (maker–checker)

1. The AI agent only *proposes*. The policy engine assigns a verdict: ALLOW, STEP_UP, DUAL_CONTROL or DENY.
2. **STEP_UP:** one operator checks the payee, amount and source document, then approves with their
   own token plus a fresh TOTP. The approval is bound by HMAC to the exact amount, currency and payee.
3. **DUAL_CONTROL:** the maker approves first. A *different* person (the checker) independently checks
   the document and approves with their own credentials.
4. **Never** approve because of urgency or secrecy in the document. These are BEC indicators (AI-02).
5. If the payee's details changed relative to previous payments, confirm them by **call-back to a
   number already on file**, never one in the document, before approving.
6. A TOTP code works once. If it is rejected as already used, wait for the next code.
7. Five consecutive MFA failures lock that operator for 15 minutes (`MFA_LOCKOUT_SECONDS`). A lockout
   is treated as a possible security event (see §7).

**Frameworks:** FFIEC authentication guidance · PSD2 RTS Art. 5 · PCI DSS 8.4 · SOX segregation of duties.

## 6. Sanctions hit and SAR-review escalation

| Trigger | Action |
|---|---|
| `AML-01` sanctions match ≥ 0.88 → DENY | Do **not** contact the payee about the block (tipping-off risk). Escalate to the compliance officer the same business day. The compliance officer decides on blocking and reporting with the licensed entity (PayPal or the bank); OFAC blocked-property reports are due within 10 business days. |
| `AML-02` possible match → DUAL_CONTROL | The checker documents why it is a false or true positive before approving. If in doubt, reject and escalate. |
| `AML-04` structuring flag (`sar_review=true`) | Hold the payment. Compliance reviews the payee's 30-day history. Any SAR is filed by the licensed entity (31 CFR 1020.320: within 30 days of detection). |
| `GEO-01/02` sanctioned or FATF call-for-action country | DENY. No override path exists in the product. |

PayWarden flags and records; it does **not** file regulatory reports itself.
**Frameworks:** OFAC compliance framework (2019) · BSA/AML · FATF R.6/R.20 · EU AMLR.

## 7. Security incident response

**Severity guide:** SEV-1 is a suspected unauthorised payout, key compromise or broken audit chain.
SEV-2 is credential compromise with no payment. SEV-3 is a blocked attack (injection, sanctions,
webhook replay) with no impact.

1. **Detect:** sources are `/api/audit/verify` returning `valid:false`; bursts of `MFA_FAILED` or
   `MFA_LOCKED_ATTEMPT`; `WEBHOOK_REJECTED` with `replayed transmission` or `signature not verified`;
   `DENIED_ON_REEVALUATION`; unexpected `PAYPAL_EXECUTED` events.
2. **Contain (within 1 hour for SEV-1):** rotate the affected operator tokens and TOTP seeds. Remove
   `PAYPAL_CLIENT_SECRET`, or rotate it in the PayPal dashboard, to freeze all execution. Keep the
   service up in read-only mode for evidence.
3. **Preserve evidence:** export `/api/audit` and the SQLite DB. Record hashes of both. Do not edit
   records; the chain makes edits detectable anyway.
4. **Eradicate and recover:** fix the root cause. Rotate keys per §4. Redeploy with the §1 checklist.
5. **Notify:** the compliance and legal owner decides on regulatory notice. Examples: NYDFS 500.17
   (72 hours, plus extortion payments within 24 hours), DORA major ICT incident reporting, GDPR
   Art. 33 (72 hours), GLBA Safeguards notification to the FTC (≥ 500 consumers, within 30 days),
   and PCI card-brand rules if card data were ever involved. PayWarden does not store card data.
6. **Post-incident review** within 10 business days, with a threat-model update (`docs/THREAT_MODEL.md`).

## 8. Change management and secure SDLC

1. Every change goes through a pull request reviewed by someone other than its author.
2. CI must pass. That means the test suite (including security tests for each control), **bandit**
   SAST at medium severity or above, and **pip-audit**. A known CVE fails the build.
3. Changes to `app/security/*`, `policy.py` mandate limits, `data/watchlist.json` or `data/geo_risk.json`
   need security-officer approval and a matching update to `docs/COMPLIANCE_MATRIX.md`.
4. Dependencies are pinned with exact versions. Upgrades go through the same PR process.
5. Deployments are recorded with the git SHA and the audit chain head at deploy time.

**Frameworks:** PCI DSS 6.2–6.3, 6.5 · SOX ITGC change management · DORA Art. 9 · NIST SSDF (SP 800-218).

## 9. Logging, monitoring and retention

- The audit log is append-only, hash-chained and HMAC-signed. Free-text fields are redacted before
  writing, and PayPal error bodies are never logged.
- Run `/api/audit/verify` daily, or on every deploy, and alert on `valid:false`.
- Anchor the chain head to external WORM storage hourly (roadmap; until then, record it manually per §1.7).
- Retention: keep audit records for at least 5 years (BSA recordkeeping, 31 CFR 1010.430). Keep at
  least 12 months readily available (PCI DSS 10.5.1).

## 10. Data protection and redaction policy

| Data | Treatment |
|---|---|
| Card numbers (PAN) | Never processed. A Luhn-valid PAN fails policy (PCI-01) and is masked everywhere. |
| Bank identifiers (IBAN, account, routing, SWIFT/BIC), SSN, phone | Masked before LLM egress and in anything stored or returned. The last 4 digits are kept where a human needs them. |
| Payee email / name | Encrypted at rest (AES-256-GCM, row-bound AAD). Masked in API output. Email is pseudonymised before LLM egress. Names are pseudonymised too when `PAYWARDEN_REDACTION=strict`. |
| Source document | Never stored. Only its SHA-256 hash is kept. |
| AI summary, notes, rejection reasons | Redacted before storage and audit. |

Data-subject requests (GDPR Art. 15/17) are handled by the controller. The blind index allows
lookup without decryption. Audit records hold only masked payees, so erasure does not break the chain.
