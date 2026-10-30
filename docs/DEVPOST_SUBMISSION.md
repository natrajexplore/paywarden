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
- **Any AI agent can use the firewall:** an MCP server lets Claude Desktop, Cursor or any MCP client propose payments with a *propose-only* credential. There is no approve tool, so an agent can never approve its own payment.
- **Agent-to-agent commerce on PayPal Orders:** a seller agent issues a PayPal Order; the buyer agent pays it through PayWarden. The amount and payee come from PayPal itself, not from the agent. The order is checked again before capture, and capture waits for the payer's approval in PayPal.
- Limits apply in USD equivalent across all currencies, and verified PayPal webhooks settle each payment's final outcome. A timeout is recorded as "uncertain", never assumed failed, so nothing is paid twice.
- Every event goes into a SHA-256 hash-chained, HMAC-signed audit log with one-click verification.
- Personal and bank data is redacted before it reaches the LLM. PII is AES-256-GCM encrypted at rest, and PayWarden never touches card data.

## How we built it
FastAPI (Python) · PayPal REST APIs on sandbox — OAuth2, Payouts, Invoicing v2, Orders v2, Webhook signature verification, PayPal-Request-Id idempotency · Anthropic Claude with tool use · Model Context Protocol (Python SDK) · AG Grid Community for the operator console · SQLite · cryptography · PyOTP · Postman/Newman · Docker + Render.

## Tools used (required section)
- **Claude (Anthropic API, model `claude-opus-5-5`)** — document understanding and structured payment proposals through tool use; plain-English summaries for approvers.
- **PayPal Developer Platform (sandbox)** — Payouts, Invoicing, Orders (agent-to-agent settlement: get + capture), Webhooks (signature-verified outcome reconciliation).
- **Model Context Protocol** — the `paywarden_mcp` server puts the firewall in front of any MCP agent (Claude Desktop, Cursor) with a propose-only credential.
- **AG Grid Community** — proposal queue and audit trail grids.
- **Render** — hosting (render.yaml blueprint).
- **Postman / Newman** — a self-checking API collection (34 requests, 78 assertions) that also runs in CI.

## Challenges
Making the AI genuinely useful while assuming it can be manipulated. The answer was defence in
depth: no single control (not even the injection scanner) is trusted alone — provenance checks,
policy and humans sit behind it.

Agent-to-agent payments were the hardest part. A seller's quote is untrusted text, so PayWarden
reads the amount and payee from PayPal's own copy of the order. PayPal also requires the payer to
approve an order before capture, so that step stays human by design. Two rounds of code review
(19 findings) caught subtle money-movement bugs, such as a hidden second purchase unit and
look-alike payee emails. Each one now has a regression test.

## Accomplishments
A working end-to-end flow with **98 automated tests** plus a **Postman collection (34 requests,
78 assertions)** that runs in CI, including tamper detection on the audit chain and a live
prompt-injection attack being blocked. Any MCP agent can use the firewall, and agents can settle
with each other through PayPal Orders without either one holding the other's keys. Banking-grade hardening on top: PII redaction
before any data reaches the LLM, card numbers refused outright, per-operator credentials with
single-use MFA codes and lockout, and fail-closed production configuration. CI fails the build on
SAST (bandit) or known-CVE (pip-audit) findings.

## What we learned
Agentic commerce needs the same primitives as network security: identity for agents, scoped
mandates, a policy decision point, and immutable logs. And when agents trade with each other,
the payment rail (PayPal), not either agent, has to be the source of truth.

## What's next
Per-agent mandates for MCP clients; PayPal partner onboarding so sellers can create orders from their own PayPal apps (today orders are created through PayWarden's app, the marketplace-platform pattern); official OFAC/UN/EU list ingestion; SSO + FIDO2 for operators; SIEM export.

## Links
- Repo: https://github.com/natrajexplore/paywarden (MIT)
- Demo video: <YouTube link>
- Hosted demo: <Render URL> · tokens `demo-maker-token` / `demo-checker-token` (operators), `demo-agent-token` (MCP agent), demo TOTP button enabled
- Postman collection: `postman/` in the repo (import the collection + environment, then Run)

## "Significantly updated" note
New project, started 30 Oct 2026 within the Submission Period.
