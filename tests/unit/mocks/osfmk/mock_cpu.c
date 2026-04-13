/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#include "mocks/osfmk/unit_test_utils.h"
#include "mock_cpu.h"
#include "mock_thread.h"
#include "fibers/fibers.h"

int ut_cpu_count __attribute__((weak)) = 1;

T_MOCK(kern_return_t, cpu_signal,
(cpu_data_t * target, cpu_signal_t signal,
void *p0, void *p1),
(target, signal, p0, p1));

T_MOCK_F(int,
cpu_number, (void), ())
{
	if (ut_mocks_use_fibers && fibers_current) {
		return fibers_current->assigned_cpu;
	}
	return 0;
}

T_MOCK_F(unsigned,
ml_get_cpu_count, (void), ())
{
	return ut_cpu_count;
}

T_MOCK_F(int,
ml_get_max_cpu_number, (void), ())
{
	return ut_cpu_count;
}
