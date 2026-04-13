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

#ifndef TEST_ERM_SYSCTL_COMMON__H
#define TEST_ERM_SYSCTL_COMMON__H

#include <sys/code_signing.h>
#include <stdlib.h>
#include <stdbool.h>
#include <System/machine/cpu_capabilities.h>


#define ERM_SYSCTL_NAME "user.extended_research_mode_config"

// only true iOS platform supports ERM
#define PLATFORM_SUPPORTS_ERM (TARGET_OS_IOS && !TARGET_OS_VISION)

// simple raw data containing zeroes (to check it is not considered as string)
static const size_t sample_config_len = 8;
static const char sample_config[sample_config_len] = {0, 1, 2, 3, 0, 4, 5, 6};

bool
is_txm_active()
{
	code_signing_monitor_type_t cs_monitor = CS_MONITOR_TYPE_NONE;
	code_signing_config_t cs_config = 0;
	size_t cs_monitor_size = sizeof(cs_monitor);
	size_t cs_config_size = sizeof(cs_config);

	sysctlbyname("security.codesigning.monitor", &cs_monitor, &cs_monitor_size, NULL, 0);
	sysctlbyname("security.codesigning.config", &cs_config, &cs_config_size, NULL, 0);

	return (cs_monitor == CS_MONITOR_TYPE_TXM) && (cs_config & CS_CONFIG_CSM_ENABLED);
}

bool
is_ERM_active()
{
	#if defined(_COMM_PAGE_SECURITY_RESEARCH_DEVICE_ERM_ACTIVE) && !__has_feature(address_sanitizer)
	return (is_txm_active()) && ((*(uint8_t *)(void *)_COMM_PAGE_SECURITY_RESEARCH_DEVICE_ERM_ACTIVE) != 0);
    #else
	return false;
    #endif
}

#endif
