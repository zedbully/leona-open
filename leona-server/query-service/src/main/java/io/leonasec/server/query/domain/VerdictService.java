/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * Verdict workflow:
 *
 * <ol>
 *   <li>Atomically mark the BoxId consumed via
 *       {@link BoxIdClaim#claim(BoxId, UUID)}. Only one caller wins.</li>
 *   <li>Load the stored verdict from the persistent store.</li>
 *   <li>Return it with the {@code usedAt} timestamp from step 1.</li>
 * </ol>
 *
 * <p>Steps 1 and 3 are critical for architectural principle #A — the
 * one-time-use enforcement prevents business-logic replays.
 */
@Service
public class VerdictService {

    private final BoxIdClaim claim;
    private final VerdictRepository repository;

    public VerdictService(BoxIdClaim claim, VerdictRepository repository) {
        this.claim = claim;
        this.repository = repository;
    }

    public VerdictResponse consume(UUID tenantId, BoxId boxId) {
        BoxIdClaim.Outcome outcome = claim.claim(boxId, tenantId);
        return switch (outcome.status()) {
            case CLAIMED -> repository.load(boxId, outcome.usedAt())
                .orElseThrow(() -> new LeonaException(ErrorCode.LEONA_BOX_NOT_FOUND));
            case ALREADY_USED -> throw new LeonaException(ErrorCode.LEONA_BOX_ALREADY_USED);
            case EXPIRED -> throw new LeonaException(ErrorCode.LEONA_BOX_EXPIRED);
            case NOT_FOUND -> throw new LeonaException(ErrorCode.LEONA_BOX_NOT_FOUND);
            case WRONG_TENANT -> throw new LeonaException(
                ErrorCode.LEONA_BOX_NOT_FOUND, "BoxId does not belong to this tenant");
        };
    }

    /** Package-visible for tests. */
    static Instant safeUsedAt(BoxIdClaim.Outcome outcome) {
        return outcome.usedAt() == null ? Instant.now() : outcome.usedAt();
    }
}
