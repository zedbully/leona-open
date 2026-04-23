/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.config;

import io.leonasec.server.admin.domain.TenantRepository;
import io.leonasec.server.admin.domain.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * Seeds a default tenant + AppKey/SecretKey pair at startup for the
 * {@code local} profile so Docker Compose users can do
 * {@code curl ... -H "X-Leona-App-Key: lk_dev_sample"} immediately.
 *
 * <p>The seeder logs the generated credentials once at INFO so they can
 * be pasted into the sample app's LeonaConfig. Running twice re-uses the
 * first tenant and creates an additional key pair.
 */
@Component
@Profile("local")
public class DevTenantSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DevTenantSeeder.class);

    private final TenantService service;
    private final TenantRepository tenants;

    public DevTenantSeeder(TenantService service, TenantRepository tenants) {
        this.service = service;
        this.tenants = tenants;
    }

    @Override
    public void run(String... args) {
        if (!tenants.findAll().isEmpty()) {
            log.info("DevTenantSeeder: tenants already exist; no new seed.");
            return;
        }
        var created = service.createTenant("Leona Dev Tenant");
        log.info("""

            =====================================================================
              DEV SEED — save these credentials somewhere, they are shown once.
              tenantId : {}
              appKey   : {}
              secretKey: {}
            =====================================================================""",
            created.tenantId(),
            created.keyPair().appKey(),
            created.keyPair().secretKey());
    }
}
