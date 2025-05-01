/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#if DEVELOPMENT || DEBUG

#include <kern/bits.h>

static int
sysctl_test_memmove(__unused int64_t in, __unused int64_t *out)
{
	// Ensure our platform-specific memmove implements correct semantics
	extern void *__xnu_memmove(
		void *dst __sized_by(n),
		const void *src __sized_by(n),
		size_t n) __asm("_memmove");

	// Given two buffers
	int dest = 0;
	int source = 42;
	// When I call our platform-specific memmove implementation
	void* memmove_ret = __xnu_memmove(&dest, &source, sizeof(int));
	// Then the value of `src` has been copied to `dst`
	if (dest != 42) {
		return KERN_FAILURE;
	}
	// And `src` is unmodified
	if (source != 42) {
		return KERN_FAILURE;
	}
	// And the return value is the `dest` pointer we passed in
	if (memmove_ret != &dest) {
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}

SYSCTL_TEST_REGISTER(test_memmove, sysctl_test_memmove);

#endif /* DEBUG || DEVELOPMENT */
