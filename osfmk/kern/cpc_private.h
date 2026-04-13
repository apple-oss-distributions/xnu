// Copyright (c) 2023 Apple Inc. All rights reserved.
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

#pragma once

// Internal definitions and declarations for the CPU Performance Counter
// subsystem.
//
// These should not be used by the kernel at large.

#include <machine/machine_cpc.h>

/// A set of events for applying to the hardware, along with any cyclics that
/// need to be maintained with them.
struct cpc_set {
	cpc_hw_t cst_hw;
	bool cst_applied;
	unsigned int cst_event_count;
	cpc_event_select_t cst_events;
	unsigned int cst_cyclic_count;
	cpc_cyclic_t *cst_cyclics;
	union cpc_machine_regs cst_regs;
};

/// The state of a cyclic.
__enum_closed_decl(cpc_cyclic_state_t, unsigned int, {
	CPC_CYS_INIT = 0,
	CPC_CYS_ENTERED = 1,
});

/// Like a call, but calls the function across all CPU counter hardware units.
struct cpc_cyclic {
	struct cpc_cyclic_info ccyi_info;
	cpc_cyclic_state_t ccyi_state;
	cpc_hw_t ccyi_hw;
	unsigned int ccyi_call_count;
	struct cpc_call ccyi_calls[];
};

/// Update the given counter with a new value, from the platform layer.
void cpc_counter_update(cpc_counter_t counter, uint64_t value);

/// Invoke a call on a given counter.
void cpc_counter_call(
	cpc_counter_t counter,
	cpc_deadlines_t deadlines,
	cpc_slot_t slot,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags);

/// Re-synchronize any deadlines for the given counter with the hardware.
void cpc_deadlines_sync(cpc_deadlines_t deadlines,
    cpc_counter_t counter,
    cpc_slot_t slot);

/// Re-synchronize counters with the hardware.
void cpc_counters_resync(cpc_hw_t hw,
    unsigned int unit_id,
    cpc_counter_t counters);

/// Get the currently-active set of registers for the hardware.
const union cpc_machine_regs *cpc_active_regs(cpc_hw_t hw);
