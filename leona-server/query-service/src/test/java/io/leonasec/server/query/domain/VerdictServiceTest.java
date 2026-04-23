/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import io.leonasec.server.common.api.BoxId;
import io.leonasec.server.common.api.RiskAssessment;
import io.leonasec.server.common.api.VerdictResponse;
import io.leonasec.server.common.error.ErrorCode;
import io.leonasec.server.common.error.LeonaException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VerdictServiceTest {

    @Test
    void returnsVerdictWhenBoxIdIsClaimed() {
        BoxIdClaim claim = mock(BoxIdClaim.class);
        VerdictRepository repository = mock(VerdictRepository.class);
        VerdictService service = new VerdictService(claim, repository);

        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");
        VerdictResponse response = new VerdictResponse(
            boxId,
            null,
            new RiskAssessment(RiskAssessment.Level.LOW, 12, List.of("test.reason")),
            List.of(),
            Instant.parse("2026-04-21T11:59:00Z"),
            usedAt
        );

        when(claim.claim(boxId, tenantId)).thenReturn(BoxIdClaim.Outcome.claimed(usedAt));
        when(repository.load(boxId, usedAt)).thenReturn(Optional.of(response));

        VerdictResponse actual = service.consume(tenantId, boxId);

        assertEquals(response, actual);
    }

    @Test
    void throwsWhenBoxIdAlreadyUsed() {
        BoxIdClaim claim = mock(BoxIdClaim.class);
        VerdictRepository repository = mock(VerdictRepository.class);
        VerdictService service = new VerdictService(claim, repository);

        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();

        when(claim.claim(boxId, tenantId)).thenReturn(BoxIdClaim.Outcome.alreadyUsed());

        assertThrows(LeonaException.class, () -> service.consume(tenantId, boxId));
    }

    @Test
    void throwsWhenBoxIdExpired() {
        BoxIdClaim claim = mock(BoxIdClaim.class);
        VerdictRepository repository = mock(VerdictRepository.class);
        VerdictService service = new VerdictService(claim, repository);

        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();

        when(claim.claim(boxId, tenantId)).thenReturn(BoxIdClaim.Outcome.expired());

        assertThrows(LeonaException.class, () -> service.consume(tenantId, boxId));
    }

    @Test
    void throwsWhenClaimedBoxIdHasNoStoredVerdict() {
        BoxIdClaim claim = mock(BoxIdClaim.class);
        VerdictRepository repository = mock(VerdictRepository.class);
        VerdictService service = new VerdictService(claim, repository);

        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();
        Instant usedAt = Instant.parse("2026-04-21T12:00:00Z");

        when(claim.claim(boxId, tenantId)).thenReturn(BoxIdClaim.Outcome.claimed(usedAt));
        when(repository.load(boxId, usedAt)).thenReturn(Optional.empty());

        LeonaException error = assertThrows(LeonaException.class, () -> service.consume(tenantId, boxId));

        assertEquals(ErrorCode.LEONA_BOX_NOT_FOUND, error.code());
    }

    @Test
    void throwsWhenBoxIdBelongsToAnotherTenant() {
        BoxIdClaim claim = mock(BoxIdClaim.class);
        VerdictRepository repository = mock(VerdictRepository.class);
        VerdictService service = new VerdictService(claim, repository);

        UUID tenantId = UUID.randomUUID();
        BoxId boxId = BoxId.generate();

        when(claim.claim(boxId, tenantId)).thenReturn(BoxIdClaim.Outcome.wrongTenant());

        LeonaException error = assertThrows(LeonaException.class, () -> service.consume(tenantId, boxId));

        assertEquals(ErrorCode.LEONA_BOX_NOT_FOUND, error.code());
    }

}
