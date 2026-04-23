/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "api_keys")
public class ApiKeyEntity {

    @Id
    @Column(name = "app_key", nullable = false, updatable = false)
    private String appKey;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    /** SHA-256 of the plaintext secret. Plaintext is returned to the caller exactly once. */
    @Column(name = "secret_hash", nullable = false)
    private String secretHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    protected ApiKeyEntity() {}

    public ApiKeyEntity(String appKey, UUID tenantId, String secretHash, Instant createdAt) {
        this.appKey = appKey;
        this.tenantId = tenantId;
        this.secretHash = secretHash;
        this.createdAt = createdAt;
    }

    public String getAppKey() { return appKey; }
    public UUID getTenantId() { return tenantId; }
    public String getSecretHash() { return secretHash; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void revoke(Instant at) { this.revokedAt = at; }
}
