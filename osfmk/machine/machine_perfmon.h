// Copyright (c) 2020 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#if KERNEL
#include <kern/perfmon.h>
#endif // KERNEL
#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>

struct perfmon_counter {
	uint64_t pc_number;
};

struct perfmon_config {
	struct perfmon_source *pc_source;
	struct perfmon_spec pc_spec;
	unsigned short pc_attr_ids[PERFMON_SPEC_MAX_ATTR_COUNT];

	struct perfmon_counter *pc_counters;
	uint64_t pc_counters_used;
	uint64_t pc_attrs_used;

	bool pc_configured:1;
};
static_assert(PERFMON_SPEC_MAX_ATTR_COUNT < sizeof(uint64_t) * CHAR_BIT,
    "attr IDs must fit in 64-bit integer");

#if KERNEL
/// Fill in an array of register values for all units.
void perfmon_machine_sample_regs(enum perfmon_kind kind, uint64_t *regs,
    size_t regs_len);
#endif // KERNEL

// Set up the counters as specified by the configuration.
int perfmon_machine_configure(enum perfmon_kind kind,
    const perfmon_config_t config);

// Reset the counters to an inactive state.
void perfmon_machine_reset(enum perfmon_kind kind);
