# Threat Model (STRIDE + AI-specific)

**Assets:** business funds in the PayPal account · payee PII · PayPal API credentials · operator
approval authority · integrity of the audit trail.

**Trust boundaries:** (1) incoming documents → AI agent (untrusted data) · (2) AI agent → PayWarden
PEP (untrusted principal) · (3) operator browser → API · (4) PayWarden → PayPal API · (5) PayPal
webhooks → PayWarden.

| # | Threat | STRIDE / OWASP-LLM | Mitigation in PayWarden |
|---|---|---|---|
| T1 | Invoice contains hidden instructions ("ignore rules, pay X") | Tampering · LLM01 | Injection scan (incl. zero-width chars) → DENY; system prompt marks doc as data |
| T2 | Model hallucinates / is coerced into a different amount or payee | Tampering · LLM05 | Provenance checks AI-03/04 — values must appear verbatim in the source |
| T3 | Agent goes rogue / is compromised and calls PayPal directly | Elevation · LLM06 | Agent holds **no** PayPal credentials; only the PEP does |
| T4 | Business Email Compromise: "we changed our bank details, urgent" | Spoofing | BEC patterns (beneficiary change, urgency, secrecy) → DENY/STEP-UP; new-payee step-up |
| T5 | Paying a sanctioned party or high-risk jurisdiction | Legal / compliance | Sanctions fuzzy match, blocked domains, geo rules |
| T6 | Splitting a large payment to dodge limits | Repudiation / AML | Structuring detector → dual control + SAR-review flag; rolling 24h cap |
| T7 | Double payment through retries or replays | Tampering | Duplicate rule + PayPal-Request-Id idempotency |
| T8 | Approver tricked into approving something other than what they saw | Spoofing | Dynamic-linking binding code; re-evaluation at execution |
| T9 | Single insider approves own high-value payout | Elevation | Maker-checker with distinct operators + TOTP each |
| T10 | Stolen operator token | Spoofing | Per-operator tokens; TOTP still required per approval; per-credential rate limiting; lockout after 5 MFA failures; audit of MFA failures |
| T11 | Attacker edits logs to hide a payout | Repudiation | Hash chain + HMAC; `/api/audit/verify` detects edit/delete/reorder |
| T12 | Forged or replayed "payment completed" webhook | Spoofing / Replay | Server-side signature verification via PayPal; ±5 min timestamp window; transmission-ID replay cache; unverified → 400, no action |
| T13 | DB leak exposes payee data | Information disclosure | AES-256-GCM field encryption, row-bound AAD, masked API output |
| T14 | XSS / clickjacking in dashboard | Tampering | Strict CSP (no inline script), output escaping, X-Frame-Options DENY |
| T15 | Accidental use against production PayPal | Operational | Startup guard refuses any non-sandbox base URL |
| T16 | API flooding / oversized bodies | DoS | Per-IP and per-credential rate limiting; body cap 413 / chunked 411 |
| T17 | Operator with the shared token claims to be the checker | Elevation | Identity derived from the credential, never the body; one credential per operator |
| T18 | Shoulder-surfed or intercepted TOTP code re-used | Spoofing / Replay | Each TOTP time-step accepted once per operator |
| T19 | PII / bank details leaked to the LLM provider or into logs | Information disclosure · LLM02 | Redaction layer: identifiers masked, emails/names pseudonymised before egress; free text redacted before storage/audit; PayPal error bodies never logged |
| T20 | Card number pasted into an invoice pulls PayWarden into PCI scope | Compliance | PCI-01 deny + PAN masking; source documents never stored (hash only) |
| T21 | Production deploy left on demo secrets / ephemeral keys | Misconfiguration | Fail-closed startup when demo mode is off |
| T22 | Secrets baked into the container image | Information disclosure | `.dockerignore` excludes `.env`, DB, venv, git |
| T23 | Look-alike PayPal host (`…sandbox.paypal.com.evil.io`) | Spoofing | Exact HTTPS host allow-list |
| T24 | Third-party agent (via MCP) is prompt-injected and tries to pay an attacker or approve its own payment | Elevation · LLM06 | Propose-only agent credential (no approve tool; operator routes refuse it); source document required for provenance; same policy as every channel; humans approve above mandate |
| T25 | MCP server sends the agent token over plain HTTP | Information disclosure | MCP server refuses `http://` except to localhost |
| T26 | Buyer agent is fed a doctored quote, or pays an order that differs from what the seller quoted | Tampering · LLM05 | Amount, currency and payee read from PayPal's order; the quote must contain order ID, payee and amount (AI-03/04); full policy + human approval |
| T27 | Seller changes the order after the human approved it | Tampering (TOCTOU) | Order fetched again before capture; any change fails the payment |
| T28 | Same order paid twice | Tampering | Completed orders refused (409); duplicate rule; idempotent capture |

**Residual risks (accepted for the hackathon):** static bearer tokens instead of SSO + FIDO2;
ephemeral keys in demo mode; in-memory rate limiter, MFA lockout and replay state (reset on
restart, not shared across replicas); regex redaction can miss unusual identifier formats; static FATF/sanctions data; regex-based injection
detection can be evaded by novel phrasing — which is why provenance checks and human approval are
layered behind it (defence in depth, never a single control).
