/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.ingestion.domain;

import io.leonasec.server.common.config.TamperBaselineSchema;
import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.stereotype.Component;

@Component
public class TamperBaselineInfoContributor implements InfoContributor {

    private final TamperBaselineProvider provider;

    public TamperBaselineInfoContributor(TamperBaselineProvider provider) {
        this.provider = provider;
    }

    @Override
    public void contribute(Info.Builder builder) {
        TamperBaselineSchema.Summary summary = TamperBaselineSchema.summarize(provider.current());
        TamperBaselineProvider.SourceInfo sourceInfo = provider.sourceInfo();
        java.util.Map<String, Object> detail = new java.util.LinkedHashMap<>();
        detail.put("sourceMode", sourceInfo.mode());
        detail.put("sourcePath", sourceInfo.path());
        detail.put("configured", summary.configured());
        detail.put("totalFieldCount", summary.totalFieldCount());
        detail.put("stringFieldCount", summary.stringFieldCount());
        detail.put("stringArrayFieldCount", summary.stringArrayFieldCount());
        detail.put("stringMapFieldCount", summary.stringMapFieldCount());
        detail.put("configuredFields", summary.configuredFields());
        builder.withDetail("handshakeTamperBaseline", detail);
    }
}
