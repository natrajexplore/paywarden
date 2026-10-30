# Demo video script — target 2:45 (hard limit < 3:00)

Rules reminder: upload to YouTube as **Public**, show the app actually working, **no copyrighted
music or third-party logos** without permission (use silence or a royalty-free track you have
rights to; screen recording of your own app is fine).

| Time | Screen | Voice-over (approx.) |
|---|---|---|
| 0:00–0:15 | Title card → dashboard | "AI agents can now pay people. One poisoned invoice can make them pay the wrong person. PayWarden is a zero-trust payment firewall between AI agents and PayPal." |
| 0:15–0:30 | Header badges: PayPal **sandbox**, AI **Claude** | "Claude reads invoices and proposes PayPal payouts — but it holds no PayPal keys. Every proposal must pass our policy engine first." |
| 0:30–0:55 | Scenario 1 → Run → STEP-UP → reasons → demo code → Approve → PayPal ref | "First payment to a new freelancer: the firewall asks a human. I approve with a one-time code bound to this exact amount and payee — and the payout hits the PayPal sandbox." |
| 0:55–1:05 | Scenario 2 → ALLOW → EXECUTED instantly | "Next job from the same trusted payee, under the limit: fully autonomous." |
| 1:05–1:30 | Scenario 3 → DUAL CONTROL → maker approves → "awaiting second" → checker approves | "$7,200 needs two different people — maker and checker — and a Travel Rule record. Same person twice? Refused." |
| 1:30–2:05 | **Scenario 4 attack** → show document text → DENY → reasons | "Now the attack: hidden instructions telling the AI to ignore its rules and wire $9,800 to a mule account. Instruction override, beneficiary change, secrecy request — quarantined. Even if the model were fooled, the amount and payee must appear in the real invoice." |
| 2:05–2:20 | Scenarios 5 & 6 quickly → DENY | "Sanctioned vendor, FATF call-for-action country — blocked." |
| 2:20–2:35 | Audit grid → click **Audit chain: VALID** | "Every decision is in a hash-chained, signed audit log. Change one record and verification breaks." |
| 2:35–2:45 | Compliance matrix scroll → repo URL | "Aligned with PCI DSS, GLBA, OFAC, FATF and PSD2 controls. Open source, MIT. PayWarden — let agents pay, safely." |

Recording tips: 1080p, browser zoom 110%, hide bookmarks bar, pre-run nothing (reset `data/paywarden.db`), rehearse twice, keep cursor movements slow.
