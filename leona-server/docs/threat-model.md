# Leona Server — Threat Model

> "We ship production on a Tuesday; the first attack comes on Wednesday."
>
> Assume every mitigation below is already being probed by an adversary
> the week you deploy. Design accordingly.

---

## 1. Assets

In priority order — protect top first.

1. **Tenant SecretKeys.** Leak implies impersonation of the tenant's
   entire fleet. Stored hashed, shown once, rotatable, rate-limited.
2. **Session keys (ECDHE).** 24h / 100k-upload TTL, per-install. Leak
   implies decryption of that install's upload stream until rotation.
3. **Raw detection events.** Contains user-device fingerprints. PII-
   adjacent; GDPR Art. 4(1) applies. Encrypted at rest, region-pinned.
4. **Verdict responses.** Business decisions ride on these; forgery
   means bypassing every integrated customer's fraud rules.
5. **Service uptime.** Outage blocks customer app flows (or forces
   them to fail-open).

## 2. Threat actors

| Actor | Motivation | Capability |
|---|---|---|
| **Script-kiddie crackers** | Remove SDK from an APK to cheat in one game | Low — tooling only |
| **Organized fraud rings** | Credential stuffing, account takeover at scale | Medium — automated botnets, device farms |
| **Black-market API key resellers** | Sell "working" Leona keys that actually bypass detection | Medium — persistent, well-funded |
| **Competitor** | Reverse-engineer detection techniques to copy or sell counter-measures | High skill, Low volume |
| **Nation-state** | Surveillance, attack on specific tenants | Very high. Out of scope for v1; we harden against lower tiers assuming it makes life harder for this tier too |

## 3. Attack surface

Enumerated by entry point. Each row: attack → primary mitigation →
residual risk → monitoring.

### 3.1 Edge (Cloudflare)

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Volumetric DDoS | Cloudflare Magic Transit + Spectrum + origin IP hidden | Cost spike during attack | CF dashboards + monthly bandwidth alert |
| HTTP flood | CF rate limiting + WAF managed rules + turnstile challenge for anomalies | Short burst reaches origin | CF firewall events → SIEM |
| TLS stripping | HSTS preload + HTTPS-only origins | n/a | n/a |
| Bot scraping of verdict endpoint | WAF + challenge + per-tenant anomaly detection | n/a | Unusual tenant request ratio alarm |

### 3.2 `/v1/handshake` (SDK → server)

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Registry flood (attacker spams handshakes to exhaust Redis) | Per-IP rate limit at gateway + per-app-key rate limit | Slow attacker still works | Handshake/IP/min histogram |
| MITM during first handshake | TLS 1.3 with pinned CA + X25519 ECDHE (no RSA static) | Attacker needs to MITM TLS — out of reach | TLS cert transparency monitoring |
| Session key replay | Keys are per-install + ephemeral; replay across installs fails MAC | n/a | Invalid MAC rate alarm |

### 3.3 `/v1/sense` (SDK → server)

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Replay a captured payload | Timestamp + nonce + HMAC signature; nonces stored in Redis for 1h | Replay inside 1h window impossible; outside, timestamp rejects | Replay reject count |
| Forge payload (no session) | HMAC requires session-derived key | Not feasible | Invalid-HMAC alarm |
| Flood from compromised AppKey | Per-app-key rate limit + anomaly detection | App owner notified + auto-throttle | Spike alert → ops page |
| Giant payload DoS | 128 KiB hard cap at gateway | n/a | Large-payload reject count |
| Submit deliberately malformed / confusing payloads to crash decoder | Input validation, fuzz-tested parser | Bug possible; fail-closed rollback | Parser error rate alarm |
| Sybil submission (fake many devices) | Install ID + device attestation (Play Integrity) + behavioural anomaly detection | Undetected Sybil possible at small scale | Install-ID heuristics + BoxId cluster detection |

### 3.4 `/v1/verdict` (customer backend → server)

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Stolen SecretKey | SecretKey rotation + short window + rate limit + geo lock | Attacker gets window until detection | Anomaly: new IP for secret key |
| BoxId enumeration | BoxId is ULID (128-bit), cannot be brute-forced | Negligible | Invalid-BoxId rate alarm |
| BoxId replay (another backend) | Single-use: `usedAt` timestamp + Redis-backed atomic flip | n/a | LEONA_BOX_ALREADY_USED count |
| Downgrade via conflicting verdicts | Server-issued verdict is signed by Leona; customer backends verify signature | Verdict cache poisoning if signature weak | Signature verification failure alarm |
| Side-channel via error messages | Uniform error responses; no info leakage in 4xx | n/a | Error content diffing in CI |

### 3.5 Admin endpoints

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Admin OAuth token theft | MFA on admin SSO; session TTL 4h; IP allowlist optional | Compromise of admin account | Admin action audit log |
| Privilege escalation | Separate `admin:read` / `admin:write` scopes; RBAC | n/a | All admin writes page SRE |
| Internal malicious admin | 4-eyes for KeyPair creation; audit log with tamper-evident hash chain | Collusion possible | Out-of-band hash chain witness |

### 3.6 Internal services

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| Gateway bypass (direct service hit) | Services only listen on cluster network; NetworkPolicy whitelist gateway | Pod compromise could talk direct | Falco / tetragon runtime detection |
| Database SQL injection | JdbcClient / JPA parameterized; no string-concat query paths; linter gate | n/a | Static scan in CI |
| Supply-chain (dependency compromise) | Renovate auto-bump + signed artifacts + SBOM + dep scanning | Zero-day dep CVE before detection | SBOM dashboard + Snyk |
| Container escape | minimal base (distroless), seccomp, AppArmor, rootless | Kernel CVE only | `kubescape` scan in CI |

### 3.7 Data store attacks

| Attack | Mitigation | Residual | Monitoring |
|---|---|---|---|
| PostgreSQL credential theft | Credentials from Vault / SecretsManager, rotated; connection via private subnet only | Vault compromise worst case | Vault audit log |
| Redis eviction attack (fill cache to force eviction of nonces) | Separate keyspace for replay nonces; memory limits enforce per-keyspace | Forced eviction → replay window opens | Replay-nonce-evicted counter |
| ClickHouse exfil via MV | Read-only accounts per dashboard; no internet egress from data namespace | n/a | Egress NetworkPolicy enforcement |

## 4. Specific 黑产 (gray-market) patterns seen on similar products

Patterns lifted from publicly-known attacks on mobile fraud / attestation
products (SafetyNet, Play Integrity, DeviceCheck). Design assumes these.

### 4.1 "Pass-through" services

Attackers run a service that: takes a request from their bot, forwards
it to a real device farm, captures the BoxId, returns to bot. Bot
submits BoxId to victim business. Mitigation:

- Device attestation cryptographically bind the session key to the
  actual device (Play Integrity HW-backed).
- BoxIds single-use; the botnet would need one real device per request.
- Behavioural fingerprint: real device operator doesn't usually resubmit
  identical payloads at high rate.

### 4.2 Key grinding

Attacker extracts the AppKey from a popular APK (they always can; it's
public by design) and spams `/v1/sense` to poison our ML pipeline or
exhaust the tenant's rate limit. Mitigation:

- Per-AppKey-per-IP rate limit at gateway.
- Install-id diversity check (one AppKey with 10 install-ids in an hour
  behaves differently than 10,000 from different IPs).
- Anomaly detector raises a suppression signal; bogus uploads marked
  `shadow=true` and not returned to dashboard.

### 4.3 Device farm verdicts

Attacker runs a real device farm (real Androids, real Play Integrity),
uses them to mint BoxIds then submits those BoxIds to victim business
at scale. Mitigation:

- Detection events carry timing signatures of device actions; a farm
  that mass-produces BoxIds has suspicious timing distribution.
- Risk score includes "device reputation" (cross-tenant): a device that
  has produced BoxIds for 50 different tenants in a day is flagged.
- Customer backend can opt into behavioural binding (BoxId + user id +
  behavioural check on backend).

### 4.4 Coordinated downgrade request

Attacker targets multiple tenants in the same hour with borderline-
suspicious traffic, trying to calibrate what severity triggers auto-
escalation so they can stay below threshold. Mitigation:

- Thresholds are per-tenant-learned, not global; calibration from one
  tenant doesn't transfer.
- Adaptive: if a tenant sees a cluster of borderline risks in <30min,
  threshold tightens automatically.

## 5. Guiding principles

1. **Fail closed on auth and replay; fail open on latency.** If
   PostgreSQL is down, the verdict service returns "unknown" not "clean"
   — the customer backend chooses its own fail policy.
2. **Every mitigation has a counter; deploy in layers.** No single
   control is load-bearing.
3. **Visibility over prevention.** Detecting a new attack late beats
   blocking an unknown attack poorly. Invest in analytics.
4. **Budget for pager fatigue.** Every alarm above has a runbook. Every
   runbook has an auto-remediation path where safe.

## 6. Pending gaps (known)

These are gaps we accept for alpha and must close before GA:

- [ ] Signed verdicts (server signs with a published key so customer
      backends can offline-verify the response hasn't been tampered).
- [ ] Device reputation cross-tenant index (currently per-tenant only).
- [ ] ML-backed payload anomaly detection (currently rule-based only).
- [ ] Automated runbooks for every alarm (currently ~40% covered).
- [ ] Chaos testing (we have unit + integration; need periodic game-days).
