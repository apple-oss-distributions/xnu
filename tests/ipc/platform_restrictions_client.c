/*
 * Copyright (c) 2026 Apple Computer, Inc. All rights reserved.
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
#include <mach/mach.h>
#include <stdio.h>
#include "../task_security_config.h"

int
main(int argc, char **argv)
{
	/*
	 * This binary gets signed under different configurations.
	 * We check our own platform restrictions version and write it to stdout,
	 * then wait to be killed by the harness.
	 */
	struct task_security_config_info config;
	mach_msg_type_number_t count = TASK_SECURITY_CONFIG_INFO_COUNT;
	kern_return_t kr;

	kr = task_info(mach_task_self(), TASK_SECURITY_CONFIG_INFO,
	    (task_info_t)&config, &count);
	if (kr != KERN_SUCCESS) {
		fprintf(stderr, "task_info failed: %d\n", kr);
		return 1;
	}

	struct task_security_config *conf = (struct task_security_config *)&config;

	/* Write our platform restrictions version to stdout so the harness can read it */
	printf("%d\n", conf->platform_restrictions_version);
	fflush(stdout);

	/* Wait around for the harness to kill us */
	while (1) {
	}

	return 0;
}
