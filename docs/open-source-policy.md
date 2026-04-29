# Leona Open-Source Policy

> Updated: 2026-04-29

## 1. Public Scope

The public GitHub repository only contains the Android public integration SDK.

Public content includes:

- Android SDK public API
- Android sample app
- Gradle build and public SDK tests
- public-safe integration documentation
- public Android SDK CI

The public repository is enough for customers to integrate Leona into an APK, generate a `BoxId`, and send that `BoxId` through their own backend to the Leona hosted verdict API.

## 2. Closed-Source Scope

The following code and operational assets are intentionally not open source:

- Leona hosted API/backend implementation
- private native runtime and detector catalog
- private JNI bridge
- private risk scoring, weights, tenant policy, and rollout logic
- internal ops endpoints and dashboards
- production infrastructure, deployment, KMS/Vault wiring, keys, and secrets
- internal CLI, release, sync, and incident tooling

These areas are closed for security reasons. Publishing them would make the bypass surface easier to study and would weaken the core value of the SDK.

## 3. Directory Placeholder Rule

The repository keeps the high-level directory structure so readers understand where closed-source implementation lives in the full product.

Closed-source directories must contain only README placeholders in public GitHub. The placeholder should explain:

- the code is intentionally absent,
- the absence is a security decision,
- public SDK users should connect to Leona hosted API/backend,
- private implementation is available only in the internal/private distribution.

## 4. Runtime Decision Rule

The APK does not make authoritative risk decisions.

The client SDK:

- collects runtime evidence,
- reports evidence to Leona,
- returns an opaque `BoxId`,
- exposes diagnostics only for integration/debugging.

The server side:

- owns verdicts,
- owns customer policy,
- owns risk weights,
- owns environment-specific decisions.

## 5. Customer Integration Rule

Customers can fully use Leona in their APK with the public SDK, but the public SDK must be configured to use the Leona API/backend.

The open-source repository does not provide a self-hosted production backend. Self-hosted or private backend code is not part of the public release.
