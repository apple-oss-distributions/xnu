/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#if (DEVELOPMENT || DEBUG) && !KASAN

#include <sys/sysctl.h>
#include <libkern/stack_protector.h>

__attribute__((noinline))
static int
check_for_cookie(size_t len)
{
	long buf[4];
	long *search = (long *)(void *)&buf[0];
	size_t n;

	assert(len < sizeof(buf));
	assert(__stack_chk_guard != 0);
	assert(((uintptr_t)search & (sizeof(long) - 1)) == 0);

	/* force compiler to insert stack cookie check: */
	memset_s(buf, len, 0, len);

	/* 32 x sizeof(long) should be plenty to find the cookie: */
	for (n = 0; n < 32; ++n) {
		if (*(search++) == __stack_chk_guard) {
			return 0;
		}
	}

	return ESRCH;
}

static int
sysctl_run_stack_chk_tests SYSCTL_HANDLER_ARGS
{
	#pragma unused(arg1, arg2, oidp)

	unsigned int dummy = 0;
	int error, changed = 0, kr;
	error = sysctl_io_number(req, 0, sizeof(dummy), &dummy, &changed);
	if (error || !changed) {
		return error;
	}

	kr = check_for_cookie(3);
	return kr;
}

SYSCTL_PROC(_kern, OID_AUTO, run_stack_chk_tests,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED | CTLFLAG_MASKED,
    0, 0, sysctl_run_stack_chk_tests, "I", "");

#endif /* (DEVELOPMENT || DEBUG) && !KASAN */
