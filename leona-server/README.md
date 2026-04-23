<div align="center">

# 🛡️ Leona Server

**The backend behind Leona's BoxId protocol.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21+-orange)]()
[![Spring Cloud](https://img.shields.io/badge/Spring_Cloud-2025.x-brightgreen)]()

</div>

---

## What this is

Leona Server receives opaque detection payloads from the
[Leona Android SDK](../leona-sdk-android/README.md), mints BoxId tokens,
and answers verdict queries from customer backends.

It is the piece that makes the SDK's zero-client-decision architecture
(principle #A) actually work: the verdict lives *here*, where attackers
don't have code patches.

## Design principles

1. **Attack-resistant from day one.** We expect to be attacked the week we
   launch — every endpoint is designed for hostile traffic. See
   [docs/threat-model.md](docs/threat-model.md).
2. **Multi-region, data-local.** EU traffic terminates in EU, APAC in
   APAC. GDPR / data residency respected. See [docs/architecture.md](docs/architecture.md).
3. **Horizontally scalable.** Every service is stateless; Kubernetes HPA
   handles scale. State lives in PostgreSQL, Redis, Kafka, ClickHouse.
4. **API contract first.** The [OpenAPI 3.1 spec](openapi/leona-v1.yaml)
   is the source of truth; server code is generated from it where
   possible.
5. **Observable by default.** Every request carries a `X-Request-Id`;
   metrics via Micrometer + OpenTelemetry; logs structured JSON.

## Technology

| Layer | Technology |
|---|---|
| Language | **Java 21+** |
| Framework | **Spring Boot 3.5** + **Spring Cloud 2025.x** |
| API Gateway | Spring Cloud Gateway (reactive, WebFlux) |
| Service discovery | Kubernetes DNS + headless services |
| Config | Spring Cloud Config + K8s ConfigMaps |
| Resilience | Resilience4j (circuit breakers, bulkheads, rate limiters) |
| Messaging | Apache Kafka |
| Database (OLTP) | PostgreSQL 16 |
| Cache | Redis 7 (Cluster mode) |
| Event storage | ClickHouse 24.x |
| Observability | Micrometer + OpenTelemetry + Prometheus + Grafana |
| Tracing | Jaeger / Tempo |
| Edge | Cloudflare (WAF + DDoS + rate limit) |
| Deployment | Docker + Kubernetes (EKS / GKE multi-region) |

## Module layout

```
leona-server/
├── openapi/           # OpenAPI 3.1 spec — source of truth
├── docs/              # Architecture, threat model, ops runbooks
├── common/            # Shared DTOs, crypto, auth helpers
├── gateway/           # Spring Cloud Gateway (public entry)
├── ingestion-service/ # POST /v1/sense (high volume, stateless)
├── query-service/     # POST /v1/verdict (low volume, auth-heavy)
├── admin-service/     # Dashboard + tenant + key management
├── deploy/
│   ├── docker-compose/   # Local dev stack
│   ├── k8s/              # Raw Kubernetes manifests
│   └── helm/             # Helm chart for multi-region deployment
└── build.gradle.kts
```

Optional private module path:

```text
leona-server/private/api-backend
```

If that directory exists, Gradle will also include `:private-api-backend`.
Use it to keep production-only backend code, internal APIs, private rules,
and deployment-specific logic out of the public repo boundary.

## Current status

This repository is already beyond "architecture only":

- the multi-module Gradle layout exists
- the handshake / sense / verdict paths all have code
- gateway auth / signing / replay checks are implemented
- ingestion hot-path now writes an immediate Redis verdict snapshot
- worker scoring and Redis/Postgres persistence paths exist

What is **not** finished yet is product-grade end-to-end validation of the
full Android SDK ↔ server loop.

The repo now also supports a **private backend module boundary** so the
public contracts / docs can stay open while sensitive backend code lives in a
separate ignored module.

That boundary now covers at least:

- optional private API crypto bootstrap:
  `io.leonasec.server.privatebackend.PrivateApiCryptoBootstrap`
- optional private backend module path: `private/api-backend`
- optional private risk scoring engine:
  `io.leonasec.server.privatebackend.PrivateRiskScoringEngine`
- optional private risk score policy:
  `io.leonasec.server.privatebackend.PrivateRiskScorePolicy`

The current private backend scaffold is no longer just a marker:

- private risk policy can apply stricter weights / thresholds
- private risk scoring engine can add event-pattern escalation that is not
  exposed in the public repo
- private backend scorer is now context-aware:
  - tenant-aware overrides
  - ingestion / worker stage-aware strictness
  - deployment-profile driven tuning via private-only env / JVM config
- private admin-service can now import private-only internal ops endpoints from
  the private backend module when present

Private backend risk tuning can be supplied without changing public code:

- `LEONA_PRIVATE_RISK_CONFIG_PATH` / `leona.private.risk.config-path`
  - points to a private JSON config file for tenant overrides / feature gates
- `LEONA_PRIVATE_RISK_PROFILE` / `leona.private.risk.profile`
  - `development` / `staging` / `production`
- `LEONA_PRIVATE_RISK_DEFAULT_STRICTNESS` / `leona.private.risk.default-strictness`
  - `baseline` / `elevated` / `strict`
- `LEONA_PRIVATE_RISK_STRICT_TENANTS` / `leona.private.risk.strict-tenants`
  - comma-separated tenant UUIDs
- `LEONA_PRIVATE_RISK_RELAXED_TENANTS` / `leona.private.risk.relaxed-tenants`
  - comma-separated tenant UUIDs
- `LEONA_PRIVATE_RISK_FEATURE_TENANTS` / `leona.private.risk.feature-tenants`
  - optional tenant allowlist for private-only escalation paths
- `LEONA_PRIVATE_INTERNAL_OPS_ENABLED` / `leona.private.internal-ops.enabled`
  - enables private-only admin internal ops endpoints

Example private JSON file shape:

```json
{
  "profile": "staging",
  "defaultStrictness": "elevated",
  "featureTenants": [
    "33333333-3333-3333-3333-333333333333"
  ],
  "tenantOverrides": {
    "33333333-3333-3333-3333-333333333333": {
      "ingestionStrictness": "baseline",
      "workerStrictness": "strict",
      "privateSignalsEnabled": true
    }
  }
}
```

When `:private-api-backend` is present on the admin-service classpath and
`LEONA_PRIVATE_INTERNAL_OPS_ENABLED=true`, the service now also exposes
private-only internal ops endpoints:

- `GET /v1/internal/private/backend/status`
- `GET /v1/internal/private/backend/readiness`
- `GET /v1/internal/private/backend/crypto`
- `GET /v1/internal/private/risk/config`
- `GET /v1/internal/private/risk/config/capabilities`
- `GET /v1/internal/private/risk/config/sources`
- `GET /v1/internal/private/risk/config/overrides`
- `GET /v1/internal/private/risk/simulate/scenarios`
- `GET /v1/internal/private/risk/simulate/{scenarioId}`
- `GET /v1/internal/private/risk/config/tenants/{tenantId}`
- `GET /v1/internal/private/risk/explain/tenants/{tenantId}`
- `GET /v1/internal/private/risk/rollout`
- `GET /v1/internal/private/risk/rollout/inventory`
- `GET /v1/internal/private/risk/rollout/tenants/{tenantId}`

These endpoints are intended for internal operations only and are implemented
inside the private backend module rather than the public repo.

## Quick start (local dev)

```bash
# Build / test (helper script auto-picks a Java 21 launcher)
./scripts/gradlew-java21.sh test

# Bring up the stack: Postgres, Redis, Kafka, all services
cd deploy/docker-compose
docker compose up -d

# Check the gateway / service health endpoints
curl http://localhost:8080/actuator/health
```

Notes:

- on this repo, the default system Java 25 launcher still breaks Gradle 8.10.2 Kotlin DSL;
  use `./scripts/gradlew-java21.sh ...` for build / test commands
- `admin-service` in `local` profile seeds a dev tenant and logs the generated
  credentials once at startup.
- if you need extra local-only Spring overrides, copy
  `admin-service/src/main/resources/application-local.example.yml` to
  `admin-service/src/main/resources/application-local.yml` first.
- `/v1/sense` is **not** a plain curl-friendly endpoint: it expects a valid
  handshake-derived session, signed headers, and an AES-GCM encrypted payload.
- The recommended local validation path is: `sample-app` / integration tests /
  dedicated demo backend, not a raw manual POST.

See [docs/architecture.md](docs/architecture.md) for the full flow.

Current execution / acceptance docs:

- [`/Users/a/back/Game/cq/docs/README.md`](/Users/a/back/Game/cq/docs/README.md)
- [`/Users/a/back/Game/cq/docs/phase-execution-checklist.md`](/Users/a/back/Game/cq/docs/phase-execution-checklist.md)
- [`/Users/a/back/Game/cq/docs/local-runbook.md`](/Users/a/back/Game/cq/docs/local-runbook.md)

## Status

- [x] OpenAPI 3.1 spec committed — [openapi/leona-v1.yaml](openapi/leona-v1.yaml)
- [x] Architecture + threat model documented
- [x] Gradle multi-module scaffold
- [x] `ingestion-service` implementation skeleton
- [x] `query-service` implementation skeleton
- [x] `admin-service` tenant/key bootstrap
- [x] `worker-event-persister` risk scoring + cache warming path
- [ ] SDK ↔ Server end-to-end test
- [ ] Multi-region deployment runbook

For a repo-wide snapshot of what is implemented today, see
[`/Users/a/back/Game/cq/docs/current-status.md`](/Users/a/back/Game/cq/docs/current-status.md).

## License

[Apache License 2.0](LICENSE) — free for commercial use.
