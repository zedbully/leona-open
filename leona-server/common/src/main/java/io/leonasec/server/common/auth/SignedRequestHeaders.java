/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.common.auth;

/**
 * The four headers every authenticated write request must carry:
 *
 * <ul>
 *   <li>{@code X-Leona-Timestamp} — Unix ms, server rejects if skew > 5 min.</li>
 *   <li>{@code X-Leona-Nonce} — 16 random bytes (base64url, 22 chars). Kept in
 *       Redis for 1h to defeat replay.</li>
 *   <li>{@code X-Leona-Signature} — base64url HMAC-SHA256 of
 *       {@code timestamp || "\n" || nonce || "\n" || body_sha256}.</li>
 *   <li>{@code X-Leona-App-Key} (SDK) or {@code Authorization: Bearer ...}
 *       (customer backend). Identifies the signing principal.</li>
 * </ul>
 */
public record SignedRequestHeaders(
    long timestamp,
    String nonce,
    String signature,
    String principal
) {}
