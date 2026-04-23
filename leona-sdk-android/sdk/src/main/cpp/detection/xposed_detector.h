/*
 * Copyright 2026 Leona Contributors.
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include "../leona.h"

namespace leona::detection {

// Xposed / LSPosed / EdXposed framework detection. Covers the major forks
// of the Xposed family still in active use in 2026.
EventList scan_xposed();

}  // namespace leona::detection
