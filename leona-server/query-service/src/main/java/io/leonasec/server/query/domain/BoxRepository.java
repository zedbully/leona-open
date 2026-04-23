/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
package io.leonasec.server.query.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface BoxRepository extends JpaRepository<BoxEntity, String> {
}
