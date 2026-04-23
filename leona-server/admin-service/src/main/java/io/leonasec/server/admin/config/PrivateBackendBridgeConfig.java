/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.admin.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;

/**
 * Optionally imports private admin/backend configuration when the private
 * module is present on the runtime classpath.
 */
@Configuration(proxyBeanMethods = false)
@Import(PrivateBackendBridgeConfig.PrivateBackendImportSelector.class)
public class PrivateBackendBridgeConfig {

    static final class PrivateBackendImportSelector implements ImportSelector {
        private static final String PRIVATE_CONFIG =
            "io.leonasec.server.privatebackend.PrivateAdminOpsConfiguration";

        @Override
        public String[] selectImports(AnnotationMetadata importingClassMetadata) {
            return isPresent(PRIVATE_CONFIG) ? new String[]{PRIVATE_CONFIG} : new String[0];
        }

        private boolean isPresent(String className) {
            try {
                Class.forName(className);
                return true;
            } catch (Throwable ignored) {
                return false;
            }
        }
    }
}
