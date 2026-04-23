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
@Table(name = "tenants")
public class TenantEntity {

    @Id
    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "suspended", nullable = false)
    private boolean suspended;

    protected TenantEntity() {}

    public TenantEntity(UUID tenantId, String name, Instant createdAt, boolean suspended) {
        this.tenantId = tenantId;
        this.name = name;
        this.createdAt = createdAt;
        this.suspended = suspended;
    }

    public UUID getTenantId() { return tenantId; }
    public String getName() { return name; }
    public Instant getCreatedAt() { return createdAt; }
    public boolean isSuspended() { return suspended; }
    public void setSuspended(boolean suspended) { this.suspended = suspended; }
}
