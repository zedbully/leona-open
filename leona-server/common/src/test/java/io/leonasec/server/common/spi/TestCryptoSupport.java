/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.spi;

public final class TestCryptoSupport {
    private TestCryptoSupport() {}

    public static void install() {
        ApiCryptoProviders.install(new TestApiCryptoProvider());
    }
}
