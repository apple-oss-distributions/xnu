// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <darwintest.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "exported_headers.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.scheduler"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("scheduler"));

T_DECL(headers_compat_c, "Verify that scheduler headers are properly guarded",
    T_META_ENABLED(false)    // Test is at build time.
    ) {
	// If we're here, it compiled!
	T_PASS("Great news: it compiles.");

	T_END;
}
