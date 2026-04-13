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

#pragma once

#include "fibers.h"

/*
 * The fibers data racer checker is a watchpoint-based checker inspired by DataCollider: https://www.usenix.org/legacy/event/osdi10/tech/full_papers/Erickson.pdf
 * Unlike the original paper, here everything is implemented in software and called from the load/store instrumentation in mock_thread.c
 * Check to SANCOV_LOAD_STORE_DATA_CHECKER macro to see how the checker API is used.
 */

enum access_type {
	ACCESS_TYPE_LOAD = 0,
	ACCESS_TYPE_STORE = 1
};

// check for concurrent accesses on the same region and, if no data race is detected, install a watchpoint so that other fibers can perform the same check
extern bool check_and_set_watchpoint(void *pc, uintptr_t address, size_t size, enum access_type access_type);
// remove the watchpoint after the memory access is completed
extern void post_check_and_remove_watchpoint(uintptr_t address, size_t size, enum access_type access_type);
// report a data race
extern void report_value_race(uintptr_t current_addr, size_t current_size, enum access_type current_type);
