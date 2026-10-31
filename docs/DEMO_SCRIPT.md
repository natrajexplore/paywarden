# Demo video script — target 2:48 (hard limit < 3:00)

Rules reminder: upload to YouTube as **Public**, show the app actually working, **no copyrighted
music or third-party logos** without permission (use silence or a royalty-free track you have
rights to; screen recording of your own app is fine).

| Time | Screen | Voice-over (approx.) |
|---|---|---|
| 0:00–0:12 | Title card → dashboard | "AI agents can now pay people. One poisoned invoice can make them pay the wrong person. PayWarden is a zero-trust payment firewall between AI agents and PayPal." |
| 0:12–0:24 | Header badges: PayPal **sandbox**, AI **typesafe:jev** | "An AI agent on TypeSafe Jev reads invoices and proposes PayPal payouts, but it holds no PayPal keys. Jev can only pick values that are really in the invoice, and every proposal must pass our policy engine first." |
| 0:24–0:46 | Scenario 1 → Run → STEP-UP → reasons → demo code → Approve → PayPal ref | "First payment to a new freelancer: a human approves with a one-time code bound to this exact amount and payee, and the payout hits the PayPal sandbox." |
| 0:46–0:54 | Scenario 2 → ALLOW → EXECUTED instantly | "Next job from the same trusted payee, under the limit: fully autonomous." |
| 0:54–1:14 | Scenario 3 → DUAL CONTROL → maker approves → "awaiting second" → checker approves | "$5,600 needs two different people, maker and checker, plus a Travel Rule record. Same person twice? Refused." |
| 1:14–1:40 | **Scenario 4 attack** → show document text → DENY → reasons | "Now the attack: hidden instructions telling the AI to ignore its rules and pay a mule account. Quarantined. Even if the model were fooled, the amount and payee must appear in the real invoice." |
| 1:40–1:50 | Scenarios 5 & 6 quickly → DENY | "Sanctioned vendor, FATF call-for-action country: blocked." |
| 1:50–2:22 | **Agent-to-agent:** Claude Desktop → paste the seller's quote → "Pay this quote" → Claude calls `pay_order` → switch to dashboard → new `order` proposal (STEP-UP) → approve as checker → EXECUTED with the PayPal order ID | "Any agent can use the firewall too. Here Claude Desktop, connected over MCP, pays a seller agent's PayPal order. It can only propose: PayWarden reads the amount and payee from PayPal itself, and a human approves before the order is captured." |
| 2:22–2:35 | Audit grid → click **Audit chain: VALID** | "Every decision is in a hash-chained, signed audit log. Change one record and verification breaks." |
| 2:35–2:48 | Compliance matrix scroll → repo URL | "Aligned with PCI DSS, GLBA, OFAC, FATF and PSD2 controls. Open source, MIT. PayWarden: let agents pay, safely." |

## Before recording the agent-to-agent scene

1. Connect an MCP client (Claude Desktop's free plan or Cursor both work) to PayWarden using the MCP
   config in the README ([Use it from any AI agent](../README.md#use-it-from-any-ai-agent-mcp)), then restart it.
   No Anthropic API key is needed for this: the MCP client is just the agent's chat app.
2. Create the seller's quote (demo mode) and copy the `quote` text from the response:

   ```bash
   curl -s -X POST localhost:8000/api/demo/a2a/quote -H "Authorization: Bearer demo-agent-token" \
     -H "Content-Type: application/json" \
     -d '{"seller_name":"Lumen Parts","seller_email":"sales@lumen.example.com","amount":"260.00","description":"Sensor kit"}'
   ```

3. In the video, paste the quote into Claude Desktop with: *"Pay this quote from our supplier through PayWarden."*

**Live sandbox only:** PayPal needs the payer to approve an order before capture. After you approve
in PayWarden, the proposal shows **Waiting for the payer** with an *Open the PayPal approval page*
link. Approve there as your sandbox buyer, then click **Capture now**. Mock mode skips this step.
In live mode, set `seller_email` to a sandbox business account, and budget about 10 extra seconds
or cut the PayPal approval page.

## Single-use codes

Each TOTP code works once per operator. Scenario 1 and scenario 3 are both maker approvals, so
wait for the maker's code to change (up to 30 s) before approving scenario 3, or show scenarios 2,
4 and 5 in between. The agent-to-agent approval uses the checker, whose code will have moved on by
then.

Recording tips: 1080p, browser zoom 110%, hide bookmarks bar, pre-run nothing (reset `data/paywarden.db`), rehearse twice, keep cursor movements slow.
