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

#define __APPLE_API_PRIVATE 1
#define __APPLE_API_UNSTABLE 1

#include <kern/debug.h>
#include <kern/iotrace.h>
#include <kern/zalloc.h>

#include <pexpert/pexpert.h>

#define DEFAULT_IOTRACE_ENTRIES_PER_CPU (64)
#define IOTRACE_MAX_ENTRIES_PER_CPU (1024)

volatile int mmiotrace_enabled = 1;
uint32_t iotrace_entries_per_cpu;

uint32_t PERCPU_DATA(iotrace_next);
iotrace_entry_t *PERCPU_DATA(iotrace_ring);

static void
init_iotrace_bufs(int entries_per_cpu)
{
	const size_t size = entries_per_cpu * sizeof(iotrace_entry_t);

	percpu_foreach(ring, iotrace_ring) {
		*ring = zalloc_permanent_tag(size, ZALIGN(iotrace_entry_t),
		    VM_KERN_MEMORY_DIAG);
	};

	iotrace_entries_per_cpu = entries_per_cpu;
}

__startup_func
static void
iotrace_init(void)
{
	int entries_per_cpu = DEFAULT_IOTRACE_ENTRIES_PER_CPU;
	int enable = mmiotrace_enabled;

	if (kern_feature_override(KF_IOTRACE_OVRD)) {
		enable = 0;
	}

	(void) PE_parse_boot_argn("iotrace", &enable, sizeof(enable));
	if (enable != 0 &&
	    PE_parse_boot_argn("iotrace_epc", &entries_per_cpu, sizeof(entries_per_cpu)) &&
	    (entries_per_cpu < 1 || entries_per_cpu > IOTRACE_MAX_ENTRIES_PER_CPU)) {
		entries_per_cpu = DEFAULT_IOTRACE_ENTRIES_PER_CPU;
	}

	mmiotrace_enabled = enable;

	if (mmiotrace_enabled) {
		init_iotrace_bufs(entries_per_cpu);
	}
}

STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, iotrace_init);
