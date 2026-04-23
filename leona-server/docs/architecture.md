# Leona Server — Architecture

> Audience: anyone building, operating, or integrating with Leona Server.
> If you are writing new endpoints, read this first.

---

## 1. System diagram

```
                                   ┌────────────────────────────────┐
                                   │         Cloudflare             │
                                   │  WAF · DDoS · Edge rate limit  │
                                   └──────────────┬─────────────────┘
                                                  │ TLS 1.3
                          ┌───────────────────────┼────────────────────────┐
                          │                       │                        │
            ┌─────────────┴────────────┐ ┌────────┴───────────┐ ┌──────────┴────────────┐
            │   Region: EU             │ │   Region: US       │ │   Region: APAC        │
            │   (Frankfurt)            │ │   (Virginia)       │ │   (Singapore)         │
            │                          │ │                    │ │                       │
            │  ┌─────────────────────┐ │ │  (same layout)     │ │  (same layout)        │
            │  │  Spring Cloud       │ │ │                    │ │                       │
            │  │  Gateway (reactive) │ │ │                    │ │                       │
            │  └─────────┬───────────┘ │ │                    │ │                       │
            │            │ Resilience4j│ │                    │ │                       │
            │    ┌───────┴──────────┐  │ │                    │ │                       │
            │    │                  │  │ │                    │ │                       │
            │ ┌──┴──────┐    ┌──────┴─┐│ │                    │ │                       │
            │ │ingestion│    │ query  ││ │                    │ │                       │
            │ │-service │    │-service││ │                    │ │                       │
            │ │ (HPA)   │    │ (HPA)  ││ │                    │ │                       │
            │ └──┬──────┘    └──────┬─┘│ │                    │ │                       │
            │    │ Kafka           │   │ │                    │ │                       │
            │    ▼                 ▼   │ │                    │ │                       │
            │  Kafka topic      PostgreSQL  Redis  ClickHouse │ │                       │
            │  (events.raw)     (RW primary, async replicas)  │ │                       │
            └──────────────────────┬───────────────────────────┘ └────────────┬──────────┘
                                   │                                          │
                                   └──────── cross-region replication ────────┘
                                             (async, best-effort, per-tenant)
```

## 2. Why this shape

### 2.1 Gateway-first

All external traffic passes through Spring Cloud Gateway. This is where:

- TLS termination (past Cloudflare)
- JWT / bearer validation
- Rate limiting per-tenant and per-IP (Resilience4j rate limiter)
- Circuit breaking (upstream service protection)
- Request signing verification
- Nonce replay cache lookup (Redis)

The gateway is intentionally "thick" so the downstream services can focus
on business logic without reimplementing auth N times. Services **trust
the gateway** for authentication but not for authorization — every
service still asserts the tenant identity from the propagated context.

### 2.2 Ingestion / Query split

We run two service classes because they have opposite scaling shapes:

| | `ingestion-service` | `query-service` |
|---|---|---|
| Request volume | High (every user, every sensitive op) | Low (only customer backends) |
| Request shape | Large binary, write-heavy | Small JSON, read-heavy |
| Latency budget | 200ms (async upload is OK) | 50ms (on business hot path) |
| Authorization | Minimal (AppKey + session) | Strong (SecretKey + signed + tenant check) |
| Failure impact | Degrades but doesn't block user | Blocks business decisions |
| Scaling signal | Kafka lag + CPU | p99 latency |

Splitting lets us scale them independently and bulkhead their failure
modes.

### 2.3 Why Kafka

The ingestion path is bursty — when a popular app pushes an update we
may see 10× normal traffic for a few hours. Rather than over-provision
PostgreSQL, we:

1. Accept the request at `ingestion-service`, do the decrypt + validate
   pass synchronously.
2. Emit to Kafka topic `events.raw`.
3. A separate consumer group persists to PostgreSQL + ClickHouse.

This turns a spike into a queue, not a cascade failure.

### 2.4 Why three storage engines

Each optimizes for a different access pattern:

- **PostgreSQL 16** — OLTP. Source of truth for tenants, keys, BoxIds,
  aggregated verdicts. Handles verdict `usedAt` marking with row-level
  locks.
- **Redis 7 Cluster** — Hot state. Replay nonces (short TTL), session
  keys, rate limit counters, cached verdicts for 15-minute BoxId TTL.
- **ClickHouse 24.x** — Analytics. Every detection event lands here for
  long-term retention, dashboard time-series, and ML pipelines.

Losing one Redis node is fine (we fall back to DB). Losing one
ClickHouse node is fine (data is replicated). Losing one PostgreSQL
primary triggers PgBouncer failover to a replica (promoted within 30s).

## 3. Multi-region strategy

### 3.1 Traffic routing

Cloudflare geo-DNS resolves `api.leonasec.io` to the nearest region:

- EU users → `api-eu.leonasec.io` → Frankfurt cluster
- US users → `api-us.leonasec.io` → Virginia cluster
- APAC users → `api-apac.leonasec.io` → Singapore cluster

Cross-region failover: if a region's gateway is unreachable, Cloudflare
falls back to the next-closest region within 30 seconds.

### 3.2 Data locality

Each region owns its own PostgreSQL primary and Kafka cluster. A user's
events are written in the region they hit; they are **not** cross-region
replicated by default for GDPR / data residency reasons.

Exceptions:
- Tenant metadata (AppKey / SecretKey / owner) is globally replicated
  because every region needs to authenticate every request.
- A tenant can opt into cross-region event replication if their fraud
  team wants global visibility — requires explicit configuration.

### 3.3 BoxId uniqueness

BoxIds are ULID-based (128 bits, 48-bit timestamp + 80-bit randomness).
Collision probability across regions is negligible. The BoxId's first
two characters encode the origin region so a query to the wrong region
is redirected at the gateway.

## 4. Scaling

### 4.1 Horizontal (stateless services)

`ingestion-service` and `query-service` are stateless. Every instance
can handle any request. Scaling is driven by Kubernetes HPA:

| Service | Scaling signal | Min | Max |
|---|---|---|---|
| gateway | CPU > 60% | 3 | 50 |
| ingestion-service | Kafka consumer lag + CPU | 3 | 100 |
| query-service | p99 latency > 100ms | 3 | 20 |
| admin-service | CPU (low traffic) | 2 | 5 |

Min replicas stay pinned across AZs so one zone failure cannot take us
below min. Max is enforced to keep cost predictable.

### 4.2 Vertical (databases)

PostgreSQL is vertically scaled (primary only) with read replicas
carrying most reads. We do **not** shard PostgreSQL — if we need more
write throughput we move to Citus or CockroachDB.

ClickHouse shards by `tenant_id` modulo N, replicated 2-way via
ClickHouse Keeper.

Kafka scales by topic partition count; `events.raw` starts at 48
partitions per region.

### 4.3 Cold start

We run minimum replicas hot 24/7, so cold start only matters during
full-region failover. Spring Boot 3 with GraalVM Native Image gets us
sub-second startup if needed; default JIT path is ~20 seconds.

## 5. Observability

### 5.1 Three pillars

- **Metrics**: Micrometer → Prometheus. Dashboards in Grafana.
- **Traces**: OpenTelemetry → Tempo. Every inbound request gets a
  `traceId` stamped into the response `X-Request-Id` header.
- **Logs**: Structured JSON → Loki. Every log line carries `traceId` +
  `tenantId` for correlation.

### 5.2 Standard dashboards

Every service owns a Grafana dashboard with these panels:

1. Request rate, error rate, duration (RED method)
2. Saturation: CPU, memory, GC pauses, heap
3. Downstream latency (Postgres, Redis, Kafka)
4. Business metrics (BoxIds minted, verdicts served, tenants active)

### 5.3 SLOs

- `/v1/sense` — 99.9% monthly, p99 < 500ms
- `/v1/verdict` — 99.95% monthly, p99 < 100ms
- `/v1/handshake` — 99.9% monthly, p99 < 200ms

Error budget burn triggers SRE review.

## 6. Deployment topology

### 6.1 Kubernetes

Each region runs one cluster:
- 1 manager control plane (managed: EKS / GKE / AKS)
- 3 worker node groups: general, gateway, data-adjacent
- Dedicated node pools for PostgreSQL (StatefulSet, local NVMe SSDs)

### 6.2 Namespaces

- `leona-prod` — production services
- `leona-data` — databases and message queues
- `leona-monitoring` — Prometheus, Grafana, Loki, Tempo
- `leona-tools` — bastion, secret operator, cert-manager

### 6.3 Release

Every service ships as:
- Docker image tagged with commit SHA + semantic version
- Helm chart pinning that image
- Rolled out canary (10% → 50% → 100%) with automatic rollback on SLO breach

## 7. Module layout (Gradle multi-module)

```
leona-server/
├── build.gradle.kts             ← convention plugins, shared settings
├── settings.gradle.kts
├── gradle/libs.versions.toml    ← dependency catalog
├── common/                      ← DTOs, crypto primitives, auth helpers
├── gateway/                     ← Spring Cloud Gateway (reactive)
├── ingestion-service/           ← WebFlux, Kafka producer
├── query-service/               ← WebFlux, read-through Redis cache
├── admin-service/               ← MVC (back-office, low traffic)
├── worker-event-persister/      ← Kafka consumer → Postgres + ClickHouse
├── deploy/
│   ├── docker-compose/          ← Local dev stack
│   └── helm/                    ← Production deployment chart
└── openapi/                     ← Source-of-truth API spec
```
