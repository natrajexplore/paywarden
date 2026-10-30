# PayWarden — Security Controls & Regulatory Mapping

> **Honest scope statement.** PayWarden is a hackathon build running against the **PayPal sandbox**.
> It is *designed to align with* the control objectives below; it is **not** certified, audited or
> legally reviewed against any of them. Sanctions data in this repo is **synthetic**. A production
> deployment would need a licensed screening provider, a formal risk assessment, legal review in
> each jurisdiction, and an independent audit (e.g. PCI QSA, SOC 2 Type II).

Status legend: **✅ Implemented** in this repo · **🟡 Partial** (demo-grade, works, needs hardening) ·
**🔵 Roadmap** (designed, not built)

## 1. Control catalogue (what fires in the code)

| ID | Control | Where | Status |
|---|---|---|---|
| ZT-01/02 | Agent identity + least-privilege mandate (action allow-list) — default deny | `policy.py` | ✅ |
| VAL-01..04 | Strict validation of model output (decimal, precision, currency, email, purpose) | `policy.py` | ✅ |
| AI-01/02 | Prompt-injection & BEC indicator scan on untrusted documents; quarantine | `injection.py` | ✅ |
| AI-03/04 | Amount & payee **provenance**: model output must appear verbatim in source | `injection.py` | ✅ |
| AML-01/02 | Fuzzy sanctions screening (block ≥ 0.88, manual review ≥ 0.75) | `policy.py` | 🟡 synthetic list |
| AML-03 | Blocked payee domains (mule accounts) | `policy.py` | ✅ |
| AML-04 | Structuring red flag → dual control + SAR-review flag | `policy.py` | ✅ |
| GEO-01..03 | Comprehensive-sanctions & FATF call-for-action deny; FATF grey list → EDD/dual control | `policy.py`, `data/geo_risk.json` | 🟡 static list |
| LIM-01..05 | Per-txn auto limit, dual-control limit, hard cap, rolling 24h cap, velocity | `policy.py` | ✅ |
| DUP-01 | Duplicate payment detection + PayPal-Request-Id idempotency | `policy.py`, `paypal_client.py` | ✅ |
| BEN-01 | New-beneficiary confirmation (step-up on first payment) | `policy.py` | ✅ |
| TR-01 | Travel-Rule record-keeping flag ≥ USD 3,000 | `policy.py` | 🟡 flag + record only |
| PCI-01 | Luhn-valid card number (PAN) in a document → DENY; PAN masked everywhere — card data never processed | `policy.py`, `redact.py` | ✅ |
| REDACT | PII/financial-identifier redaction (`off`/`standard`/`strict`): IBAN, account, routing, SWIFT/BIC, SSN, phone masked; emails (+ party names in strict) pseudonymised before LLM egress and restored locally; notes, AI summaries, reject reasons redacted before storage/audit | `redact.py`, `agent.py`, `store.py` | ✅ |
| IDENT | One credential per operator; identity derived from the credential, never the request body | `auth.py`, `main.py` | ✅ |
| MFA | RFC 6238 TOTP step-up per approval; each time-step single-use (replay-proof); lockout after 5 consecutive failures | `auth.py` | ✅ |
| 4-EYES | Maker-checker: two distinct authenticated operators for DUAL_CONTROL | `main.py` | ✅ |
| DYN-LINK | Approval bound by full HMAC-SHA256 (dedicated key) to amount + currency + payee; checked before the OTP is consumed | `auth.py` | ✅ |
| RE-EVAL | Policy re-evaluated at execution time (TOCTOU defence) | `main.py` | ✅ |
| ENC | AES-256-GCM field encryption of PII, row-bound AAD; keyed blind index; SQLite `secure_delete`, owner-only DB file | `crypto.py`, `store.py` | ✅ |
| KEYSEP | HKDF-SHA256 purpose keys (enc / blind-index / audit / binding) from two master keys — no key reused across algorithms | `crypto.py`, `config.py` | ✅ |
| MASK | PII masked in API/UI; full values never returned | `store.py` | ✅ |
| AUDIT | Append-only SHA-256 hash chain + HMAC-SHA256 per record; `/api/audit/verify` | `audit.py` | ✅ |
| WEBHOOK | PayPal webhook signature verified server-side; ±5 min transmission-time window; transmission-ID replay cache; malformed bodies rejected | `paypal_client.py`, `main.py` | ✅ |
| HTTP | HSTS, CSP, XFO, nosniff, Referrer-Policy, COOP, CORP, no-store, sanitised request IDs; API docs disabled outside demo | `middleware.py`, `main.py` | ✅ |
| SIZE | Request body cap (413), unsized chunked bodies refused (411) | `middleware.py` | ✅ |
| RATE | Rate limiting per IP **and** per credential; trusted-proxy client IP | `middleware.py` | 🟡 in-memory |
| SECRETS | Secrets only from env; agent never sees PayPal credentials; strict sandbox host allow-list; `.dockerignore` keeps `.env` out of images | `config.py` | ✅ |
| FAILSAFE | `PAYWARDEN_DEMO_MODE=false` refuses to start with demo/weak/shared secrets, ephemeral keys, redaction off or wildcard CORS | `config.py` | ✅ |
| CARD | No card data ever touches PayWarden (PayPal holds PAN) → minimises PCI scope | architecture | ✅ |
| CI | Tests + bandit SAST + `pip-audit` on every push — findings fail the build | `.github/workflows/ci.yml` | ✅ |
| PROC | Operating procedures: hardening checklist, JML access, access review, key rotation, maker-checker, sanctions/SAR escalation, incident response, change management, retention | `docs/SECURITY_PROCEDURES.md` | 🟡 templates |
| SSO | OIDC/SAML operator login with FIDO2/WebAuthn, RBAC, mTLS between services | — | 🔵 |
| KMS | Keys in HSM/KMS with rotation | — | 🔵 |
| WORM | Ship audit chain head to external WORM storage / transparency log | — | 🔵 |

## 2. United States

| Framework | Requirement (summary) | PayWarden controls |
|---|---|---|
| **PCI DSS v4.0.1** | Req 2.2 no vendor defaults; Req 3 protect stored account data, 3.6–3.7 key management; Req 4 strong crypto in transit; Req 6.2–6.4 secure SDLC & public web apps; Req 7 least privilege; Req 8.3.4 lockout, 8.3.6 credential strength, 8.4 MFA; Req 10 audit logs & protect them | CARD, PCI-01, REDACT, KEYSEP, FAILSAFE, CI, ZT-01/02, IDENT, MFA, AUDIT |
| **GLBA Safeguards Rule** (16 CFR 314.4) | (c)(1) access controls · (c)(3) encryption at rest & in transit · (c)(5) MFA · (c)(8) monitor & log user activity | ZT, ENC, MFA, AUDIT |
| **NYDFS 23 NYCRR Part 500** | 500.6 audit trail · 500.7 access privileges · 500.12 MFA · 500.15 encryption | AUDIT, ZT, MFA, ENC |
| **Bank Secrecy Act / AML** | 31 USC 5318(h) AML program · 31 USC 5324 anti-structuring · SAR filing (31 CFR 1020.320 / 1022.320) · Recordkeeping & Travel Rule ≥ $3,000 (31 CFR 1010.410) | AML-04 (+SAR-review flag), TR-01, AUDIT |
| **OFAC** (31 CFR Ch. V; *Framework for OFAC Compliance Commitments*, 2019) | Screen parties against SDN & other lists; block prohibited transactions; keep records | AML-01/02/03, GEO-01, AUDIT |
| **FFIEC** *Authentication and Access to Financial Institution Services and Systems* (2021) | Risk-based, layered security; stronger authentication for high-risk transactions | Tiered verdicts, MFA, 4-EYES, velocity |
| **NIST SP 800-207** Zero Trust Architecture | Policy Decision Point / Policy Enforcement Point; per-request, context-aware authorisation | Whole architecture: agent → PEP/PDP → PayPal |
| **NIST SP 800-63B** | AAL2 = two factors incl. a possession factor (TOTP); OTP single-use (§5.1.4.2); rate-limit failed attempts (§5.2.2) | IDENT + MFA (replay-proof, lockout) |
| **NIST CSF 2.0 / AI RMF 1.0** | Govern / Protect / Detect; manage AI-specific risks (manipulation, over-reliance) | AI-01..04, human oversight, AUDIT |
| **SOX ITGC** (where applicable) | Evidence of authorisation & segregation of duties for disbursements | 4-EYES, AUDIT |

## 3. International

| Framework | Requirement (summary) | PayWarden controls |
|---|---|---|
| **EU PSD2 + RTS on SCA** (Del. Reg. (EU) 2018/389) | Art. 4 strong customer authentication · Art. 5 **dynamic linking** of auth to amount & payee | MFA, DYN-LINK |
| **EU DORA** (Reg. (EU) 2022/2554) | ICT risk management — protection, prevention & detection (Arts. 9–10), logging | HTTP, ENC, AUDIT, RATE |
| **EU Transfer of Funds Reg.** (EU) 2023/1113 & **AMLR** (EU) 2024/1624 | Originator/beneficiary information; CDD, EDD for high-risk third countries | TR-01, GEO-03 (EDD) |
| **GDPR** | Art. 5(1)(c) data minimisation · Art. 25 privacy by design · Art. 28/44 processor & third-party transfer minimisation · Art. 32 encryption/pseudonymisation · Art. 22 safeguards on automated decisions (human intervention) | REDACT (LLM egress), ENC, MASK, blind index, human approval |
| **EU AI Act** (Reg. (EU) 2024/1689) | Human-oversight principle (Art. 14), logging, robustness against manipulation | Human-in-the-loop, AI-01..04, AUDIT |
| **FATF Recommendations** | R.6 targeted financial sanctions · R.10 CDD · R.16 wire transparency · R.19 higher-risk countries · R.20 suspicious-transaction reporting | AML-01, BEN-01, TR-01, GEO-01..03, SAR-review |
| **ISO/IEC 27001:2022** Annex A | 5.15 access control · 8.5 secure authentication · 8.15 logging · 8.24 use of cryptography · 8.28 secure coding | ZT, MFA, AUDIT, ENC, tests/CI |
| **OWASP Top 10 for LLM Apps (2025)** | LLM01 prompt injection · LLM02 sensitive information disclosure · LLM05 improper output handling · LLM06 excessive agency | AI-01..04, REDACT, VAL, agent has no credentials |
| **RBI Master Direction — Digital Payment Security Controls** (India, 2021) | Multi-factor authentication, transaction limits & velocity, fraud monitoring, logging | MFA, LIM-01..05, AUDIT |

## 4. Production roadmap (what a bank would require next)

1. Replace synthetic watchlist with OFAC SDN + Consolidated, UN and EU lists refreshed daily (or a licensed vendor), with alias/transliteration matching and documented false-positive handling.
2. Operator identity via OIDC/SAML SSO with phishing-resistant MFA (FIDO2/WebAuthn) and RBAC.
3. Keys in a cloud KMS/HSM with rotation; per-tenant data keys (envelope encryption).
4. Audit chain head anchored hourly to external WORM storage; SIEM export (e.g. Elastic).
5. Postgres with row-level security; Redis-backed distributed rate limiting.
6. Case-management workflow for SAR-review flags; regulatory reporting handled by the licensed entity (PayPal/bank), not by PayWarden.
7. Formal threat model review, penetration test, SOC 2 Type II.
