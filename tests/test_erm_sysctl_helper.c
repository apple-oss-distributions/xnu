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

// This program is built with special entitlement that allows it to write the sysctl.
// It is called by tests in `test_erm_sysctl_reader` to write a config before the tests read it back.

#include <sys/types.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "test_erm_sysctl_common.h"

int
main(int argc, char** argv)
{
	if (argc > 1) {
		char* config_buffer = argv[1];

		size_t config_len   = strlen(config_buffer);
		if (is_ERM_active()) {
			printf("Config to store: `%s`\n", config_buffer);
			fflush(stdout);
			int ret = sysctlbyname(ERM_SYSCTL_NAME, NULL, NULL, config_buffer, config_len);
			printf("Returned code for config `%s`: %d\n", config_buffer, ret);
			fflush(stdout);
		} else {
			printf("Couldn't store config `%s` because ERM is NOT active here.\n", config_buffer);
		}
	}
	return 0;
}
