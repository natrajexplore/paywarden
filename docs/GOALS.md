# PayWarden — Hackathon Goal & Plan

**Hackathon:** PayPal AI Hackathon (Devpost) — "Build what's next with PayPal and AI"
**Submission deadline:** Thu 12 Nov 2026, 12:00 PM PT (= Fri 13 Nov 2026, 00:30 AM IST)
**Judging:** 1–15 Dec 2026 · **Winners:** ~21 Dec 2026

---

## 1. The one-line goal

> Ship a working, open-source **zero-trust payment firewall for AI agents** that lets an AI
> accounts-payable agent pay real people through PayPal (sandbox) — while every single money
> movement is policy-checked, sanctions-screened, human-approved when risky, and written to a
> tamper-evident audit trail aligned with US and international banking controls.

## 2. The problem (Potential Impact)

AI agents are starting to *move money*, not just recommend. That is exactly what PayPal's own
inspiration list asks for ("an assistant that pays contractors automatically when a job is marked
complete"). But today an LLM with a payments tool is one prompt-injection away from paying the
wrong person, paying twice, or paying a sanctioned party. Banks would never give a junior clerk
unlimited payout authority with no limits, no second signer and no audit log — yet that is what a
raw "LLM + PayPal API key" setup does.

**Audience:** small businesses, agencies and marketplaces that pay many freelancers/contractors
(the people PayPal Payouts and Invoicing already serve) and want AI automation *without* losing
financial control or failing an audit.

## 3. The solution in one picture

```
 Invoice / "job done" message (UNTRUSTED)
            │
            ▼
   ┌─────────────────┐   proposes only — has NO PayPal credentials
   │  Claude AP Agent │──────────────────────────────┐
   └─────────────────┘                               ▼
                                     ┌──────────────────────────────┐
                                     │  PayWarden Policy Enforcement │
                                     │  Point (zero trust, default   │
                                     │  deny)                        │
                                     │  • prompt-injection scan      │
                                     │  • amount provenance check    │
                                     │  • spend mandate & velocity   │
                                     │  • sanctions / high-risk geo  │
                                     │  • structuring (AML) detect   │
                                     │  • duplicate / idempotency    │
                                     └──────┬───────────┬───────────┘
                                   ALLOW    │           │ STEP-UP / DENY
                                            ▼           ▼
                              PayPal Sandbox      Human approval (TOTP MFA,
                              Payouts / Invoicing  maker-checker dual control)
                              / Orders / Webhooks          │
                                            ▲──────────────┘
                                            │
                          Hash-chained, HMAC-signed audit log (tamper-evident)
```

## 4. Success criteria (definition of done by 12 Nov)

| # | Must-have (Stage-1 pass + core score) | Status |
|---|---|---|
| G1 | Real PayPal **sandbox** integration: OAuth2, Payouts, Invoicing (create + send), Orders, Webhook signature verification | done in code (Orders: get + capture for agent-to-agent); **live sandbox run pending** |
| G2 | AI is central: Claude reads unstructured invoices, extracts payee/amount, proposes PayPal actions via tool use | done in code (with PII redaction); **live Claude run pending** |
| G3 | Agent never holds PayPal credentials — all actions pass the Policy Enforcement Point | done in code |
| G4 | Controls: spend mandates, velocity, sanctions screening, structuring detection, injection defence, duplicates | done + hardened (PCI-01, redaction, fail-closed config) |
| G5 | Human-in-the-loop: TOTP step-up + maker-checker for high-value | done (per-operator credentials, single-use codes, lockout) |
| G6 | Tamper-evident audit log with `/api/audit/verify` | done in code |
| G7 | Polished dashboard (AG Grid) — complete product experience | done in code; browser click-through pending |
| G8 | Public GitHub repo with MIT LICENSE visible in About, full run instructions, `.env.example` | done — public, MIT detected, CI green |
| G9 | Runs for judges with **zero keys** (mock mode) *and* with sandbox keys (live mode) | mock mode verified; live mode pending; Render deploy pending |
| G10 | < 3 min YouTube demo, public, no copyrighted music | to record |

| Stretch (prize multipliers) | Prize targeted |
|---|---|
| S1 Deploy on Render (render.yaml included) → hosted demo URL | Best Use of Render |
| S2 AG Grid risk dashboard with row grouping/conditional styling | Best Use of AG Grid |
| S3 Agent-to-agent payment flow (buyer agent ⇄ seller agent settle via Orders) — **done** (`pay_order`; mock-verified, live payer approval pending) | Best Use of Agentic Commerce |
| S4 Expose PayWarden as an MCP server so *any* agent (Claude Desktop, Cursor) gets the firewall — **done** (`paywarden_mcp/`, propose-only) | Most Creative / Best PayPal + AI |
| S5 Postman collection for the API — **done** (`postman/`, 34 requests / 78 assertions, runs in CI via Newman) | Postman ecosystem |

## 5. Judging criteria → how we score (all equally weighted)

| Criterion | What we show |
|---|---|
| Technological Implementation | 4 PayPal products (Payouts, Invoicing, Orders, Webhooks) + Claude tool use + a real security engine with tests — non-trivial |
| Design | One coherent flow: drop invoice → AI proposal → risk verdict → approve with MFA → PayPal sandbox result → audit chain |
| Potential Impact | Specific audience (SMBs paying contractors), specific risk (agent fraud/injection), measurable control |
| Innovation | "Firewall for agent money movement" — applies network zero-trust (PEP/PDP, default-deny, least privilege) to agentic commerce |
| Presentation | 3-min scripted demo including a live **attack**: a prompt-injected invoice gets blocked |

## 6. Milestones (IST)

| Date | Milestone |
|---|---|
| Fri 30 Oct | Rules analysed, idea locked, project scaffold + security engine + tests (this commit) |
| Sat 31 Oct – Sun 1 Nov | Create PayPal sandbox app, add keys, run live mode; test Payouts + Invoicing end-to-end |
| Mon 2 – Wed 4 Nov | Claude agent prompt tuning on 10 realistic invoices (incl. 3 malicious); webhook endpoint public via Render |
| Thu 5 – Sat 7 Nov | Stretch: MCP server wrapper + agent-to-agent flow; dashboard polish |
| Sun 8 Nov | Deploy to Render; full judge dry-run from a clean machine using README only |
| Mon 9 – Tue 10 Nov | Record & edit demo video (<3 min); write Devpost text |
| Wed 11 Nov | Freeze. Submit draft on Devpost, verify links (repo public, license visible, video public) |
| Thu 12 Nov | **Final submit before 23:00 IST** (keep 1.5 h buffer before the 00:30 IST cut-off) |

## 7. Rule-compliance checklist (from the Official Rules)

- [ ] Uses the PayPal developer platform **sandbox** + an AI model (Claude) — PayPal integration is central
- [ ] Project newly created during the Submission Period (started 30 Oct 2026)
- [ ] Text description of features & functionality
- [x] Functional demo: README setup/run instructions **and/or** hosted URL (no mockups) — README verified; hosted URL pending
- [x] Public repo on GitHub with an **open source license detectable in the About section**
- [ ] Demo video < 3 min, on YouTube, public, shows it working, **no third-party trademarks or copyrighted music** without permission
- [ ] Tools section: name the AI model/services and how they are used
- [ ] All materials in English
- [x] Sandbox credentials / test instructions for judges in README (never commit real secrets)
- [ ] Third-party APIs used within their terms (PayPal, Anthropic, AG Grid Community, Render)
- [ ] Original work, solely owned; open-source deps used under their licenses
- [ ] Eligibility: individual of age of majority, resident of India (not an excluded jurisdiction); not a PayPal/Devpost employee or judge-affiliated
