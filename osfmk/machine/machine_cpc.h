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

#if CONFIG_CPU_COUNTERS

/// This header contains machine-dependent interfaces for generic code in CPC.
/// These functions are not meant to be used in the kernel at large.

#if __arm64__
#include <arm64/cpc_arm64.h>
#elif __x86_64__
#include <x86_64/cpc_x86_64.h>
#else // __arm64__ || __x86_64__
#erorr "unsupported architecture"
#endif // !(__arm64__ || __x86_64__)

/// Update the current CPU's CPMU counter with a value read from the hardware.
///
/// - Parameters:
///     - counter: The counter data structure to update.
///     - slot: The slot of the counter to read from hardware.
/// - Returns: The current count of the counter.
uint64_t cpc_cpmu_counter_update(cpc_counter_t counter, cpc_slot_t slot);

/// Update all counters for the given hardware.
///
/// - Parameter hw: The hardware to update.
/// Note that only the CPMU hardware is currently supported.
void cpc_hw_update(cpc_hw_t hw);

/// Get the list of CPMU counters.
///
/// - Returns: An array of counters indexed by slot of length CPMU_PMC_COUNT.
cpc_counter_t cpc_cpmu_counters(void);

/// Get the list of CPMU deadlines for counters.
///
/// - Returns: An array of deadlines indexed by slot of length CPMU_PMC_COUNT.
cpc_deadlines_t cpc_cpmu_deadlines(void);

/// Return a counter for a specific unit, which may not be the current one.
///
/// - Parameters:
///     - hw: The hardware to get a counter of.
///     - unit_index: Which unit to get the counter from.
///     - slot: The slot of the counter to get.
///     - deadlines: The deadlines corresponding to the returned counter.
/// - Returns: A counter data structure that fits the parameters.
cpc_counter_t cpc_hw_counter(
	cpc_hw_t hw,
	unsigned int unit_index,
	cpc_slot_t slot,
	cpc_deadlines_t *deadlines_out);

/// Return the number of units for a particular hardware.
///
/// - Parameter hw: The hardware to get the unit count of.
/// - Returns: The number of units available in the hardware.
unsigned int cpc_hw_unit_count(cpc_hw_t hw);

/// Call a block in the execution context of each unit.
///
/// - Parameters:
///     - hw: The hardware to target.
///     - block: The block to call.
void cpc_hw_broadcast(cpc_hw_t hw,
    OS_NOESCAPE void (^block)(unsigned int unit_id));

/// Disable PMIs for a particular hardware unit to prevent races.
///
/// - Parameters:
///     - hw: The hardware to disable PMIs on.
///     - regs: The currently active regs.
void cpc_hw_disable_pmis(cpc_hw_t hw, const union cpc_machine_regs *regs);

/// Re-enable PMIs for a particular hardware unit.
///
/// - Parameters:
///     - hw: The hardware to re-enable PMIs on.
///     - regs: The currently active regs.
void cpc_hw_reenable_pmis(cpc_hw_t hw, const union cpc_machine_regs *regs);

/// Disable counting for a slot.
///
/// - Parameters:
///     - hw: The hardware to disable the slot of.
///     - regs: The currently active regs.
///     - slot: The slot to disable.
void cpc_hw_slot_disable(cpc_hw_t hw,
    const union cpc_machine_regs *regs,
    cpc_slot_t slot);

/// Reenable counting for a slot.
///
/// - Parameters:
///     - hw: The hardware to disable the slot of.
///     - regs: The currently active regs.
///     - slot: The slot to re-enable.
void cpc_hw_slot_reenable(cpc_hw_t hw,
    const union cpc_machine_regs *regs,
    cpc_slot_t slot);

/// Program a PMC with a specific counter value.
///
/// - Parameters:
///     - counter: The counter data structure to use for setting the deadline.
///     - slot: The slot of the counter to program with the deadline.
///     - value: The value to program in the hardware PMC.
void cpc_counter_set_value(
	cpc_counter_t counter,
	cpc_slot_t slot,
	uint64_t value);

/// Called by machine-dependent code when bringing each unit online,
/// in the context of that unit.
void cpc_cpu_online(unsigned int cpu_id,
    cpc_counter_t counters,
    cpc_deadlines_t deadlines,
    bool retained_regs);

// CPU state transitions that CPC may need to be notified about.
__enum_closed_decl(cpc_cpu_event_t, uint32_t, {
	// Initialized, once per boot, too early to allocate.
	CPC_CPU_EARLY_INIT,
	// Initialized, once per boot, can allocate.
	CPC_CPU_INIT,
	// Brought online from reset.
	CPC_CPU_ONLINE,
	// Going offline.
	CPC_CPU_OFFLINE,
	// Going idle.
	CPC_CPU_IDLE,
	// Becoming active after returning from idle through reset.
	CPC_CPU_ACTIVE_COLD,
	// Becoming active after returning from idle without reset.
	CPC_CPU_ACTIVE_WARM,
});

// Called by machine-dependent code when CPU transitions occur.
void cpc_cpu_transition(cpc_cpu_event_t event, void *cpu_data);

// Configure the hardware.
void cpc_hw_configure(cpc_hw_t hw,
    unsigned int unit_id,
    cpc_counter_t counters,
    cpc_deadlines_t deadlines,
    bool check_for_cyclics);

/// The initial, default state of the registers.
extern
// Intel discovers the counter capabilities at boot.
#if !__X86_64__
const
#endif // !__X86_64__
union cpc_machine_regs cpc_machine_regs_init;

extern
#if !__X86_64__
const
#endif // !__X86_64__
union cpc_machine_regs cpc_machine_regs_base;

/// Add an event to a machine register structure.
///
/// - Parameters:
///     - regs: The registers to modify.
///     - hw: Which hardware the event belongs to.
///     - options: Any options to use when adding the event.
///     - event: The event selection details.
__result_use_check bool cpc_machine_regs_event_select(
	union cpc_machine_regs *regs,
	cpc_hw_t hw,
	cpc_set_options_t options,
	const struct cpc_event_select *event);

/// Apply the registers to the current unit.
///
/// - Parameters:
///     - regs: The registers to apply.
///     - hw: Which hardware to program.
void cpc_machine_regs_apply(const union cpc_machine_regs *regs, cpc_hw_t hw);

/// Reset the register state to the defaults.
///
/// - Parameters:
///     - regs: The previous registers that were applied.
///     - hw: The hardware to program.
void cpc_machine_regs_reset(const union cpc_machine_regs *regs, cpc_hw_t hw);

#if DEVELOPMENT || DEBUG

/// Read hardware register values.
///
/// - Parameters:
///     - hw: The HW to read the registers of.
///     Must be `CPC_HW_CPMU` currently.
///     - regs: A structure to fill in with the current CPU's register values.
///     - counter_values: An array to fill with the current CPU's counter values.
void cpc_hw_read_regs(cpc_hw_t hw,
    union cpc_machine_regs *regs,
    uint64_t *counter_values);

/// Format registers for diagnostic reports.
///
/// - Parameters:
///     - hw: The HW to format the registers of.
///     Must be `CPC_HW_CPMU` currently.
///     - indent: A string of indentation to prefix each new line.
///     - regs: A structure of register state to source register values from.
///     - output: A string to write the formatted state to.
///     - available: How much space is left in the string.
/// - Returns: The number of characters written to `output`.
size_t cpc_hw_print_regs(
	cpc_hw_t hw,
	const char *indent,
	const union cpc_machine_regs *regs,
	char *output,
	size_t available);

#endif // DEVELOPMENT || DEBUG

#endif // CONFIG_CPU_COUNTERS
