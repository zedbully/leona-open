# Contributing to Leona Server

See also: the [Android SDK's CONTRIBUTING.md](../leona-sdk-android/CONTRIBUTING.md)
for shared conventions.

## Development setup

```bash
git clone https://github.com/leonasec/leona-server
cd leona-server
./scripts/gradlew-java21.sh build

cd deploy/docker-compose
docker compose up -d --build
```

Requirements: JDK 21+, Gradle 8.10+, Docker + Docker Compose.

## PR checklist

- [ ] All services compile: `./scripts/gradlew-java21.sh build`
- [ ] Unit + integration tests pass: `./scripts/gradlew-java21.sh test`
- [ ] Docker Compose brings up clean: `docker compose up -d --build`
- [ ] OpenAPI spec updated if API shape changed
- [ ] Threat model updated if attack surface changed
- [ ] Architecture doc updated if topology changed

## Non-negotiables

1. **OpenAPI first.** Any change that alters a request or response body
   MUST update [openapi/leona-v1.yaml](openapi/leona-v1.yaml) in the same PR.
2. **No plaintext secrets in config files.** Use env vars, K8s secrets,
   or Vault. Anything that smells like `password: "..."` fails review.
3. **Every write endpoint is signed + replay-guarded.** If you add a
   `POST` / `PUT` / `DELETE`, the gateway signature filter must cover it.
4. **Virtual threads by default.** `spring.threads.virtual.enabled=true`
   in every service.
5. **SLO-aware scaling.** HPAs go in the Helm chart, not hand-configured.
6. **Don't log PII.** No device fingerprints, no BoxIds, no tenant names
   in application logs above `DEBUG`. Use span attributes instead.

## Style

- Java — Google Java Style (`./scripts/gradlew-java21.sh spotlessApply`).
- Commits — conventional commits.
- Tests — JUnit 5, Testcontainers for integration. No `@MockBean` if a
  real container is cheap.

## License

Apache 2.0 — contributions ship under the same license. No CLA required.
