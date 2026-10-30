# Devpost submission draft — PayWarden

**Tagline:** The zero-trust payment firewall that lets AI agents pay people through PayPal — safely.

## Inspiration
PayPal's own brief asks for agents that *actually transact* — like an assistant that pays
contractors when a job is done. I'm a network security engineer; in my world nobody gives a
system unlimited access just because it asked nicely. Zero trust, least privilege, separation of
duties and audit logs are how banks and enterprise networks stay safe. AI agents moving money
deserve the same discipline.

## What it does
- Claude reads unstructured invoices / statements of work and proposes PayPal Payouts or Invoices via tool use.
- The agent has **no PayPal credentials**. PayWarden's policy engine evaluates every proposal: prompt-injection & BEC detection, amount/payee provenance, spend mandate and velocity, sanctions and FATF screening, structuring detection, duplicates, new-beneficiary checks.
- Verdicts: **ALLOW** (auto-execute on PayPal), **STEP-UP** (one human, TOTP), **DUAL CONTROL** (maker + checker), **DENY** (quarantine).
- Approvals are cryptographically bound to the exact amount and payee (PSD2-style dynamic linking) and the policy is re-checked at execution time.
- Every event goes into a SHA-256 hash-chained, HMAC-signed audit log with one-click verification.
- PII is AES-256-GCM encrypted at rest; PayWarden never touches card data.

## How we built it
FastAPI (Python) · PayPal REST APIs on sandbox — OAuth2, Payouts, Invoicing v2, Orders v2, Webhook signature verification, PayPal-Request-Id idempotency · Anthropic Claude with tool use · AG Grid Community for the operator console · SQLite · cryptography · PyOTP · Docker + Render.

## Tools used (required section)
- **Claude (Anthropic API, model `claude-opus-5-5`)** — document understanding and structured payment proposals through tool use; plain-English summaries for approvers.
- **PayPal Developer Platform (sandbox)** — Payouts, Invoicing, Orders, Webhooks.
- **AG Grid Community** — proposal queue and audit trail grids.
- **Render** — hosting (render.yaml blueprint).

## Challenges
Making the AI genuinely useful while assuming it can be manipulated. The answer was defence in
depth: no single control (not even the injection scanner) is trusted alone — provenance checks,
policy and humans sit behind it.

## Accomplishments
A working end-to-end flow with 50 automated tests, including tamper detection on the audit chain
and a live prompt-injection attack being blocked. Banking-grade hardening on top: PII redaction
before any data reaches the LLM, card numbers refused outright, per-operator credentials with
single-use MFA codes and lockout, and fail-closed production configuration. CI fails the build on
SAST (bandit) or known-CVE (pip-audit) findings.

## What we learned
Agentic commerce needs the same primitives as network security: identity for agents, scoped
mandates, a policy decision point, and immutable logs.

## What's next
MCP server so any agent (Claude Desktop, Cursor) gets the firewall; agent-to-agent settlement via
Orders; official OFAC/UN/EU list ingestion; SSO + FIDO2 for operators; SIEM export.

## Links
- Repo: https://github.com/natrajexplore/paywarden (MIT)
- Demo video: <YouTube link>
- Hosted demo: <Render URL> · tokens `demo-maker-token` / `demo-checker-token`, demo TOTP button enabled

## "Significantly updated" note
New project, started 30 Oct 2026 within the Submission Period.
