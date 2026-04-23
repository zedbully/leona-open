/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.api;

import io.leonasec.server.admin.domain.TenantService;
import io.leonasec.server.common.util.RequestIds;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/v1/admin/tenants")
public class TenantController {

    private final TenantService service;

    public TenantController(TenantService service) {
        this.service = service;
    }

    /** Create a new tenant + initial AppKey/SecretKey pair. */
    @PostMapping
    public ResponseEntity<TenantService.CreatedTenant> create(
        @Valid @RequestBody CreateTenantRequest request
    ) {
        var created = service.createTenant(request.name());
        return ResponseEntity.status(HttpStatus.CREATED)
            .header(RequestIds.HEADER, RequestIds.newId())
            .body(created);
    }

    /** Rotate — create a new AppKey/SecretKey pair for an existing tenant. */
    @PostMapping("/{tenantId}/keys")
    public ResponseEntity<TenantService.CreatedKeyPair> createKeys(
        @PathVariable UUID tenantId
    ) {
        var pair = service.createKeyPair(tenantId);
        return ResponseEntity.status(HttpStatus.CREATED)
            .header(RequestIds.HEADER, RequestIds.newId())
            .body(pair);
    }

    /** Revoke an existing AppKey/SecretKey pair for a tenant. */
    @DeleteMapping("/{tenantId}/keys/{appKey}")
    public ResponseEntity<TenantService.RevokedKeyPair> revokeKey(
        @PathVariable UUID tenantId,
        @PathVariable String appKey
    ) {
        var revoked = service.revokeKeyPair(tenantId, appKey);
        return ResponseEntity.ok()
            .header(RequestIds.HEADER, RequestIds.newId())
            .body(revoked);
    }

    /** Rotate an existing AppKey/SecretKey pair for a tenant. */
    @PostMapping("/{tenantId}/keys/{appKey}/rotate")
    public ResponseEntity<TenantService.RotatedKeyPair> rotateKey(
        @PathVariable UUID tenantId,
        @PathVariable String appKey
    ) {
        var rotated = service.rotateKeyPair(tenantId, appKey);
        return ResponseEntity.ok()
            .header(RequestIds.HEADER, RequestIds.newId())
            .body(rotated);
    }

    public record CreateTenantRequest(@NotBlank String name) {}
}
