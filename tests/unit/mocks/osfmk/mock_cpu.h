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

#pragma once

#include <arm/cpu_internal.h>
#include "mocks/mock_dynamic.h"

/*
 * Unit tests that want to use multi-CPU simulation must redefine this global with the number of CPUs.
 * This MUST be set before any initialization code runs (i.e., at global scope in test file).
 * Default is 1 CPU if not set.
 *
 * Usage in test file:
 *   UT_CPU_COUNT(4);  // number of simulated CPUs
 */
#define UT_CPU_COUNT(val) int ut_cpu_count = (val)

extern int ut_cpu_count __attribute__((weak));

T_MOCK_DECLARE(
	kern_return_t,
	cpu_signal,
	(cpu_data_t * target, cpu_signal_t signal,
	void *p0, void *p1));


T_MOCK_DECLARE(int, ml_get_max_cpu_number, (void));
