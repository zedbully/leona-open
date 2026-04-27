/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.worker.domain;

import io.hypersistence.utils.hibernate.type.json.JsonBinaryType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.Type;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA mapping for the {@code boxes} table. Mirrors the Liquibase schema in
 * {@code query-service/src/main/resources/db/changelog/changes/001-initial-schema.sql}.
 */
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

    public BoxEntity(
        String boxId, UUID tenantId, String deviceFingerprint, String canonicalDeviceId,
        String riskLevel, int riskScore, String riskReasonsJson,
        String eventsJson, Instant observedAt, Instant expiresAt
    ) {
        this.boxId = boxId;
        this.tenantId = tenantId;
        this.deviceFingerprint = deviceFingerprint;
        this.canonicalDeviceId = canonicalDeviceId;
        this.riskLevel = riskLevel;
        this.riskScore = riskScore;
        this.riskReasonsJson = riskReasonsJson;
        this.eventsJson = eventsJson;
        this.observedAt = observedAt;
        this.expiresAt = expiresAt;
    }

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
    public void setUsedAt(Instant usedAt) { this.usedAt = usedAt; }
}
