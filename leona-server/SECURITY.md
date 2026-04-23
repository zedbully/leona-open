# Security policy — Leona Server

## Reporting a vulnerability

Email **security@leonasec.io**. Do not open public issues for
unpatched server vulnerabilities.

We respond within 72 hours and follow the timelines in the threat model's
"Guiding principles" section. See
[docs/threat-model.md](docs/threat-model.md).

## Scope

**In scope:**
- Authentication bypass (AppKey, SecretKey, OAuth admin)
- Signature forgery, replay, or downgrade
- BoxId enumeration, replay, or cross-tenant leak
- Server-side code execution
- PII / tenant data exfiltration
- DoS attacks that degrade service beyond rate-limiter expectations

**Out of scope:**
- Issues in upstream dependencies (report to the project)
- Theoretical attacks already in the published threat model
- Social engineering against Leona staff
- Physical attacks

## Responsible disclosure

We appreciate embargoes until:

- Fix is deployed to every production region
- Customer disclosure email has been sent
- 30 days have elapsed since those (whichever is later)

## Researcher-friendly defaults

You may not attack production servers without explicit scope agreement.
For authorized pentests email us first; we can provision staging.

For local research against `docker compose`-hosted Leona on your own
hardware, anything goes.
