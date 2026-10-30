# Security Policy

## Scope

PayWarden is a hackathon project that talks only to the **PayPal sandbox**. Do not point it at
production PayPal credentials — the app refuses non-sandbox base URLs by design.

## Reporting a vulnerability

Please open a private security advisory on this GitHub repository (Security → Report a
vulnerability) rather than a public issue. Include steps to reproduce and impact. You will get a
response within 5 business days.

## Secrets

* Never commit `.env`. Only `.env.example` (no secrets) is tracked; `.dockerignore` keeps `.env`
  out of container images.
* The demo operator tokens and TOTP seeds are **public demo values**, accepted only while
  `PAYWARDEN_DEMO_MODE=true`.
* With `PAYWARDEN_DEMO_MODE=false` the app **refuses to start** unless both master keys are set,
  each operator has a distinct strong token and TOTP seed, redaction is on and CORS origins are
  explicit. Demo mode off also disables `/api/demo/totp` and the interactive API docs.

## Operating procedures

Deployment hardening, operator joiner/mover/leaver, access reviews, key rotation, the maker-checker
procedure, sanctions/SAR escalation, incident response and change management are in
[docs/SECURITY_PROCEDURES.md](docs/SECURITY_PROCEDURES.md).

## Design references

See [docs/COMPLIANCE_MATRIX.md](docs/COMPLIANCE_MATRIX.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
