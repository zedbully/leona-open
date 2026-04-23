# Security policy — Leona Android SDK

## Reporting a vulnerability

Please email **security@leonasec.io** with:

1. A description of the issue
2. Steps to reproduce (ideally a minimal POC APK)
3. Your proposed remediation if you have one

**Do not open a public issue** for vulnerabilities in the SDK itself.

We aim to respond within 72 hours. Disclosure timelines for acknowledged
vulnerabilities:

| Severity | Target |
|---|---|
| Critical (allows bypassing detection in production with minimal effort) | Patch within 7 days, embargo until fix shipped |
| High | Patch within 30 days |
| Medium | Patch in the next scheduled release |
| Low | Public issue, fix on the roadmap |

## Scope

**In scope:**
- Bypasses of any detection claimed in the README
- Ways to read or forge a BoxId client-side
- Ways to extract the session key from memory without a debugger hook Leona detects
- Crashes / data corruption in the SDK itself

**Out of scope:**
- Bypasses that require rooted / debugged devices if the detection is
  claimed to *identify* rooted / debugged devices (that's the point)
- Issues in customer apps that don't integrate Leona correctly
- Theoretical attacks below our published threat model tier (nation-state)

## Recognition

If you want credit, we publish a `HALL_OF_FAME.md` with researcher
acknowledgments. Anonymous reports are welcome too.

## Researcher-friendly defaults

You may:

- Reverse engineer the SDK code in our published AARs for research.
- Run static + dynamic analysis (Frida, Xposed, Unidbg, IDA, Ghidra, etc.)
  against our sample app.
- Publish writeups **after** embargo.

You may not:

- Attack production Leona servers without explicit written authorization
  (contact security@leonasec.io for a scope agreement).
- Attack customer apps in ways that harm their end users.
- Test against live integrations without customer consent.
