/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef TEST_ERM_SYSCTL__H
#define TEST_ERM_SYSCTL__H

#include "test_erm_sysctl_common.h"

// This file contains only test related macros

// As we are stateful for our tests (we first write something and expect to read it back later)
// we can't run concurrently.
#define ERM_GLOBAL_META T_GLOBAL_META(         \
	T_META_NAMESPACE("xnu.erm"),               \
	T_META_RADAR_COMPONENT_NAME("xnu"),        \
	T_META_RADAR_COMPONENT_VERSION("security"),\
	T_META_OWNER("fmarmond"),                  \
	T_META_RUN_CONCURRENTLY(false),            \
    T_META_CHECK_LEAKS(false)                  \
	);


#if PLATFORM_SUPPORTS_ERM
#define ERM_ENABLED_META T_META_BOOTARGS_SET("txm_research_extended_config=1"), \
	                                     XNU_T_META_REQUIRES_DEVELOPMENT_KERNEL,\
	                                         T_META_TAG_VM_NOT_ELIGIBLE
#else
#define ERM_ENABLED_META T_META_ENABLED(false)
#endif

#endif
