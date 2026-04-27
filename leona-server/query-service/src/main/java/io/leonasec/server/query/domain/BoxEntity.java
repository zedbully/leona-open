/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.Type;

import java.time.Instant;
import java.util.UUID;

/** Read-side JPA mapping. Mirrors the Liquibase-managed boxes table. */
@Entity
@Table(name = "boxes")
public class BoxEntity {

    @Id
    @Column(name = "box_id", length = 26, nullable = false, updatable = false)
    private String boxId;

    @Column(name = "tenant_id", nullable = false, updatable = false)
    private UUID tenantId;

    @Column(name = "device_fingerprint")
    private String deviceFingerprint;

    @Column(name = "canonical_device_id")
    private String canonicalDeviceId;

    @Column(name = "risk_level", nullable = false)
    private String riskLevel;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Type(JsonBinaryType.class)
    @Column(name = "risk_reasons", columnDefinition = "jsonb", nullable = false)
    private String riskReasonsJson;

    @Type(JsonBinaryType.class)
    @Column(name = "events", columnDefinition = "jsonb", nullable = false)
    private String eventsJson;

    @Column(name = "observed_at", nullable = false)
    private Instant observedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    protected BoxEntity() {}

    public String getBoxId() { return boxId; }
    public UUID getTenantId() { return tenantId; }
    public String getDeviceFingerprint() { return deviceFingerprint; }
    public String getCanonicalDeviceId() { return canonicalDeviceId; }
    public String getRiskLevel() { return riskLevel; }
    public int getRiskScore() { return riskScore; }
    public String getRiskReasonsJson() { return riskReasonsJson; }
    public String getEventsJson() { return eventsJson; }
    public Instant getObservedAt() { return observedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getUsedAt() { return usedAt; }
}
