-- Leona v0.1.0-alpha.1 — initial schema.
--
-- liquibase formatted sql

-- changeset leona:0001-tenants
CREATE TABLE tenants (
    tenant_id   UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    suspended   BOOLEAN NOT NULL DEFAULT false
);

-- changeset leona:0002-api-keys
CREATE TABLE api_keys (
    app_key     TEXT PRIMARY KEY,
    tenant_id   UUID NOT NULL REFERENCES tenants(tenant_id) ON DELETE CASCADE,
    secret_hash TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_tenant ON api_keys (tenant_id) WHERE revoked_at IS NULL;

-- changeset leona:0003-boxes
-- Boxes are the long-term persistent record, replicated from Redis by the
-- worker-event-persister. Redis holds the hot short-TTL copy; Postgres
-- owns the source of truth for audits.
CREATE TABLE boxes (
    box_id              CHAR(26) PRIMARY KEY,
    tenant_id           UUID NOT NULL REFERENCES tenants(tenant_id),
    device_fingerprint  TEXT,
    risk_level          TEXT NOT NULL,
    risk_score          INT NOT NULL,
    risk_reasons        JSONB NOT NULL DEFAULT '[]'::jsonb,
    events              JSONB NOT NULL DEFAULT '[]'::jsonb,
    observed_at         TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ
);

CREATE INDEX idx_boxes_tenant_observed ON boxes (tenant_id, observed_at DESC);
CREATE INDEX idx_boxes_expires ON boxes (expires_at) WHERE used_at IS NULL;
