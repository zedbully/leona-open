<div align="center">

# 🛡️ Leona

**Mobile application security toolkit for the deception era.**

Static analysis today. Signature-level runtime detection tomorrow. Adaptive defense beyond.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)](https://go.dev)
[![Status](https://img.shields.io/badge/status-alpha-orange)]()

</div>

---

## Why another mobile security tool?

Most mobile security SDKs check surface patterns — process names, file paths, API hashes.
Attackers rename, repack, and bypass them in an afternoon.

**Leona goes deeper.**

We detect attack tools by their *irreducible signatures* — the machine-code patterns that survive any amount of obfuscation and rebranding. And when we detect an attacker, we don't just bail out. **We lie to them.**

## The three pillars

### 1. Static scanner — *available now*

Analyze APKs for hardcoded secrets, insecure configs, exposed components, and CVE-vulnerable dependencies. Built to integrate into CI/CD from day one.

### 2. Runtime SDK with deep detection — *v0.2*

Detect Frida, Xposed, Substrate, and Magisk by their trampoline assembly signatures and memory layout — not by process-name strings. A rebranded Frida looks the same at the instruction level as the real thing. Leona catches it.

### 3. Adaptive defense framework — *v1.0*

When an attack is detected, your app returns honeypot data instead of aborting. Reverse engineering becomes a time sink, not a victory. Attackers waste weeks on decoy code paths before realizing they've been had.

## Quick start (v0.1 scanner)

> ⚠️ v0.1 is under active development. The commands below show the intended interface; current build stubs are placeholders.

```bash
# Install (once published)
go install github.com/leonasec/leona/cmd/leona@latest

# Scan an APK
leona scan myapp.apk

# Output to different report formats
leona scan myapp.apk --format html --output report.html
leona scan myapp.apk --format sarif --output report.sarif  # GitHub Code Scanning
leona scan myapp.apk --format json --output report.json    # CI-friendly
```

## Current status

The CLI repository is currently the **lightest-weight** part of the project:

- command surface exists
- version output works
- scan / rules management are still scaffolds

Today, the engineering center of gravity is the Android runtime SDK and the
server-side BoxId pipeline. See
[`/Users/a/back/Game/cq/docs/current-status.md`](/Users/a/back/Game/cq/docs/current-status.md)
for the repo-wide status snapshot.

## What v0.1 will detect

- 🔑 Hardcoded secrets (API keys, JWT, AWS tokens, private keys, database credentials)
- 🎭 Exposed components (Activity, Service, Provider, Receiver misconfigurations)
- 🔓 Insecure cryptography (DES, MD5, ECB mode, hardcoded keys, weak IVs)
- 🌐 Network weaknesses (cleartext traffic allowed, missing certificate pinning)
- 💾 Insecure storage (world-readable files, plaintext sensitive data)
- 🐛 Debug residuals (`debuggable=true`, `allowBackup=true`, verbose logs in release)
- 📦 CVE-vulnerable dependencies (matched against OSV.dev)
- ...and 30+ more checks covering OWASP MASVS categories

## Roadmap

- [ ] **v0.1.0** — Android APK static scanner
- [ ] **v0.2.0** — Runtime SDK: Frida/Xposed/Substrate/Magisk detection via assembly signatures
- [ ] **v0.3.0** — Honeypot framework: deceive attackers instead of denying service
- [ ] **v0.4.0** — Persistent device fingerprinting (survives factory reset)
- [ ] **v0.5.0** — iOS scanner + SDK
- [ ] **v1.0.0** — Web console, adaptive policy server, threat intelligence feed

## Philosophy: deception over denial

When your app detects tampering today, what does it do?
Crashes? Shows an error? Refuses to start?

You've just told the attacker exactly what tripped your detection.
They'll retry in 10 minutes with their evasion adjusted.

**Leona's approach is different.** We don't deny. We deceive.

- Attacker hooks your crypto function? They get a convincingly valid *fake* result.
- Attacker intercepts your API response? They get honeypot data.
- Attacker reverses your binary? They find decoy code paths that waste their time.
- Attacker tries the same trick tomorrow? The server has updated the deception.

Security isn't a wall. **Security is a maze with no exit.**

## Why not just use MobSF / Mobexler / existing tools?

We respect them. MobSF in particular has shaped mobile security for a decade.

Leona takes a different bet:

| | Existing tools | Leona |
|---|---|---|
| **Static scan** | ✅ Mature | ✅ Cleaner CLI + SARIF + AI-enhanced analysis |
| **Runtime detection** | Process-name / file-path checks | **Assembly-signature checks** |
| **Defense strategy** | Abort on detection | **Adaptive deception (honeypot, fake data)** |
| **Device identity** | Android ID / ADID (resettable) | **Persistent fingerprint (resists factory reset)** |
| **Integration** | Web UI, ops-heavy | **CLI-first, CI/CD-native, single static binary** |
| **Target user** | Security teams | **Developers** |

## Who's behind this

I'm an independent security researcher. 20 years writing Java, 10 years in reverse engineering, 5 years in offensive security. Born in China, building for a global developer community.

I started Leona because every indie and mid-sized team deserves the same quality of protection that enterprise customers get from Guardsquare, Appdome, or Verimatrix — without the $100k/year price tag.

**Code is transparent. Data stays where you put it. Security shouldn't require trust — it should require proof.**

## Contributing

Leona is in alpha. We welcome:

- ⭐ Stars (they genuinely matter in early days)
- 🐛 Issues — bug reports, feature ideas, questions
- 💬 Discussions — architecture debates, attack technique sharing
- 🔧 PRs — especially detection rules and documentation

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR. *(coming soon)*

## Security disclosure

Found a vulnerability *in Leona itself*? Please don't open a public issue.
Email `security@leonasec.io` *(mailbox to be provisioned)* with details. We'll respond within 72 hours.

## License

[Apache License 2.0](LICENSE) — free for commercial use, patent grant included.

---

<div align="center">

*If Leona helps you, a ⭐ on GitHub is the best thanks you can give.*

</div>
