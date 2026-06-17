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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <os/crashlog_private.h>

#if defined(__arm64__) && defined(__LP64__)

#include "_commpage_pfz.h"

#include <arm64/machine_machdep.h>

void (*update_tpidr)(uint64_t) = NULL;

void
os_set_custom_x18_abi_enabled(bool const want_custom_x18_abi)
{
	uint64_t tpidr_upper = __builtin_arm_rsr64("TPIDR_EL0");

	bool const custom_x18_abi_enabled = (bool)(tpidr_upper & MACHDEP_TPIDR_FLAG_PRESERVE_X18);

	// Make sure we strictly toggle the flag here.
	if (!(custom_x18_abi_enabled ^ want_custom_x18_abi)) {
		__builtin_trap();
	}

	tpidr_upper &= ~(MACHDEP_TPIDR_FLAG_PRESERVE_X18 | MACHDEP_TPIDR_CPU_DATA_MASK);
	tpidr_upper |= want_custom_x18_abi ? MACHDEP_TPIDR_FLAG_PRESERVE_X18 : 0;

	update_tpidr(tpidr_upper);
}

bool
os_custom_x18_abi_enabled(void)
{
	return (bool)(__builtin_arm_rsr64("TPIDR_EL0") & MACHDEP_TPIDR_FLAG_PRESERVE_X18);
}


#endif // defined(__arm64__) && defined(__LP64__)
