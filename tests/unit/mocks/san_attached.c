/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#include "mocks/dt_proxy.h"
#include <mach/mach_types.h>

#define NOT_MOCKED(name) PT_FAIL(#name ": this function should never be called since it is mocked by the mocks dylib")

void
data_race_checker_atomic_begin(void)
{
}

void
data_race_checker_atomic_end(void)
{
}

__mockable void
__sanitizer_cov_trace_pc_guard(uint32_t *guard)
{
	// do nothing
}

// Called before a load of appropriate size. Addr is the address of the load.
__mockable void
__sanitizer_cov_load1(uint8_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_load1);
}
__mockable void
__sanitizer_cov_load2(uint16_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_load2);
}
__mockable void
__sanitizer_cov_load4(uint32_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_load4);
}
__mockable void
__sanitizer_cov_load8(uint64_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_load8);
}
__mockable void
__sanitizer_cov_load16(__int128 *addr)
{
	NOT_MOCKED(__sanitizer_cov_load16);
}
// Called before a store of appropriate size. Addr is the address of the store.
void
__sanitizer_cov_store1(uint8_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_store1);
}
void
__sanitizer_cov_store2(uint16_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_store2);
}
void
__sanitizer_cov_store4(uint32_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_store4);
}
void
__sanitizer_cov_store8(uint64_t *addr)
{
	NOT_MOCKED(__sanitizer_cov_store8);
}
void
__sanitizer_cov_store16(__int128 *addr)
{
	NOT_MOCKED(__sanitizer_cov_store16);
}
