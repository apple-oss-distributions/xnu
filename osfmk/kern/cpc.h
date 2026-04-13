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

#include <os/base.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/_types/_errno_t.h>
#include <kern/debug.h>
#include <kern/locks.h>

__BEGIN_DECLS

// Define whether CPC is operating in a secure environment,
// negated to fail closed/safe (on missing `#include`).
#if DEVELOPMENT || DEBUG
#define CPC_INSECURE 1
extern bool cpc_logging;
char *cpc_state_create(bool local, size_t *size_out);
void cpc_state_destroy(char * state, size_t size);
#else // DEVELOPMENT || DEBUG
#define CPC_INSECURE 0
#endif // DEVELOPMENT || DEBUG

#define CPC_MAX_CALLS (8)
#define CPC_MAX_CYCLICS (32)

extern lck_grp_t cpc_lock_grp;

extern bool cpc_cpmu_supported;

/// The kinds of counting hardware potentially supported by CPC.
__enum_decl(cpc_hw_t, unsigned int, {
	CPC_HW_CPMU,
	CPC_HW_UPMU,
	CPC_HW_COUNT,
});

#pragma mark - Slots and Counters

/// How to refer to specific CPU counters.

/// A counter's "slot" (i.e. index) in a unit's list of counters.
typedef int cpc_slot_t;

/// Some events are "fixed" and always-enabled in the system.
__enum_closed_decl(cpc_fixed_event_t, unsigned int, {
	CPC_FEVT_CYCLES,
	CPC_FEVT_INSTRUCTIONS,
});

/// Convert a fixed event to its slot for use with other interfaces.
///
/// - Parameters:
///     - hw: The HW this event is set up for.
///     - event: The event to get the slot of.
/// - Returns: The slot corresponding to the provided event.
static inline cpc_slot_t
cpc_fixed_event_slot(cpc_hw_t hw, cpc_fixed_event_t event)
{
	if (hw != CPC_HW_CPMU) {
		panic("%s: HW %d has no fixed slot for any events", __func__, hw);
	}
	switch (event) {
	case CPC_FEVT_CYCLES:
	#if __arm64__
		return 0;
	#else // __arm64__
		return 1;
	#endif // !__arm64__
	case CPC_FEVT_INSTRUCTIONS:
	#if __arm64__
		return 1;
	#else // __arm64__
		return 0;
	#endif // !__arm64__
	default:
		panic("%s: HW %d has no fixed slot for event %d", __func__, hw, event);
	}
}

/// A counter's data representation for software,
/// to support counting and sampling.
typedef struct cpc_counter *cpc_counter_t;

#pragma mark - Counting

/// Counting refers to reading the value of the counters.
/// Typically, two counts are taken: at the start and end of a region of interest.

/// Read the counts for a subset of counters in a counting HW's current unit.
///
/// - Parameters:
///     - hw: The HW to read the counter values of.
///     - counter_mask: A bitset of counters to read from the HW.
///     A set bit indicates the counter at that bit position should be read.
///     - counts: An array of counts to fill in.
///     - counts_len: The number of counter values to read and the length of the `counts` array.
///     Should be the minimum of either the number of counters in the HW and the number of bits set in `counter_mask`.
void cpc_hw_counts(
	cpc_hw_t hw,
	uint64_t counter_mask,
	uint64_t *counts,
	size_t counts_len);

/// Return the cycles elapsed on the current CPU.
uint64_t cpc_cycles(void);

/// Return the instructions retired on the current CPU.
uint64_t cpc_instrs(void);

/// A structure for tracking cycles and instructions counted at the same time.
struct cpc_cycles_instrs {
	uint64_t cycles;
	uint64_t instrs;
};

/// Return both the cycles elapsed and instructions retired on the current CPU.
/// This is preferable to calling `cpc_cycles` and `cpc_instrs` independently,
/// as the hardware counters are queried back-to-back.
struct cpc_cycles_instrs cpc_cycles_instrs(void);

/// Same as `cpc_cycles_instrs` but lacks a barrier instruction,
/// which allows other instructions to be re-ordered around this function.
/// The lack of a barrier makes this faster but less precise.
struct cpc_cycles_instrs cpc_cycles_instrs_spec(void);

/// Update the counters for the provided HW's current unit.
///
/// - Parameter hw: The HW to update the counters of.
void cpc_hw_update(cpc_hw_t hw);

#pragma mark - Sampling

/// Sampling uses the counters to trigger interrupts,
/// which can sample the code that caused them to increment.

/// Return the maximum sampling period allowed by the hardware.
uint64_t cpc_hw_max_period(cpc_hw_t hw);

/// Details of how a call occurred,
/// passed to a specified function.
__options_decl(cpc_call_flags_t, uint32_t, {
	CPC_CF_NONE = 0x00,
	/// The PC is the most precise value supported by the hardware.
	CPC_CF_PC_PRECISE = 0x01,
});

/// What execution context the call interrupted.
__enum_decl(cpc_call_source_t, uint32_t, {
	CPC_CS_KERNEL = 0,
	CPC_CS_USER = 1,
	CPC_CS_GUARDED = 2,
});

/// A cyclic is a repeating call that triggers on all CPUs,
/// for the purposes of profiling software.

typedef struct cpc_cyclic *cpc_cyclic_t;

struct cpc_cyclic_info;

/// The information available to a function called by a cyclic.
typedef void (*cpc_cyclic_func_t)(
	struct cpc_cyclic_info *info,
	uint64_t count,
	uint64_t extra_count,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags);

/// How to configure the cyclic.
struct cpc_cyclic_info {
	/// Which counters to use for the cyclic.
	cpc_slot_t cci_slot;
	/// The number of events to occur between the function calls.
	uint64_t cci_period;
	/// The function to call when the cyclic triggers.
	cpc_cyclic_func_t cci_func;
	/// A client-controlled value to remember context.
	void *cci_context;
};

/// Allocate a new cyclic,
/// a way to call a function periodically based on CPU counters across the system.
///
/// - Parameter hw: The HW to target with the cyclic.
/// - Parameter info: How to configure the cyclic.
/// - Returns: A cyclic data structure that must be `cpc_cyclic_destroy`ed to clean up its resources,
/// or NULL on failure.
__result_use_check cpc_cyclic_t cpc_cyclic_alloc(
	cpc_hw_t hw,
	const struct cpc_cyclic_info *info);

/// Start a cyclic's periodic calls.
/// The cyclic must be cancelled with `cpc_cyclic_cancel` before calling `cpc_cyclic_destroy`.
///
/// This is an expensive operation because it involves a CPU broadcast cross-call to set up per-unit state.
///
/// - Parameter cyclic: The cyclic to activate.
void cpc_cyclic_activate(cpc_cyclic_t cyclic);

/// Cancel a cyclic's periodic calls.
/// The cyclic must already have been activated with `cpc_cyclic_activate`.
///
/// This is an expensive operation because it involves a CPU broadcast cross-call to tear down per-unit state.
///
/// - Parameter cyclic: The cyclic to cancel.
void cpc_cyclic_cancel(cpc_cyclic_t cyclic);

/// Destroy an inactive cyclic.
///
/// - Parameter cyclic: The cyclic to destroy.
void cpc_cyclic_destroy(cpc_cyclic_t cyclic);

/// A call is a low-level interface for configuring a one-shot function call on a specific counter.
/// Unlike a cyclic,
/// it only triggers once and on the same CPU counter unit that it was entered on,
/// similar to a `timer_call_t`.

typedef struct cpc_call *cpc_call_t;

/// The information available to a function called by a call.
typedef void (*cpc_call_func_t)(
	cpc_call_t call,
	cpc_slot_t slot,
	uint64_t deadline,
	uint64_t count,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags,
	void *context);

/// Internal state of the call.
__enum_decl(_cpc_call_state_t, uint32_t, {
	CPC_CST_INIT = 0,
	CPC_CST_ENTERED = 1,
});

/// How deadlines are tracked in a counter.
typedef struct cpc_deadlines *cpc_deadlines_t;

/// Expose the data structure internals here so it can be used without allocating.
struct cpc_call {
	cpc_hw_t cca_hw;
	cpc_call_func_t cca_func;
	void *cca_context;
	cpc_slot_t cca_slot;
	cpc_deadlines_t cca_deadlines;
	cpc_counter_t cca_counter;
	_cpc_call_state_t cca_state;
};

/// Initialize the fields of a call.
///
/// - Parameter call: The call to initialize.
/// - Parameter hw: The HW to target.
/// - Parameter counter: The counter to monitor and call based on.
/// - Parameter slot: The corresponding slot of the counter.
/// - Parameter deadlines: The deadlines corresponding to the counter.
/// - Parameter func: The function to call once.
/// - A client-controlled value to remember context.
void cpc_call_init(
	cpc_call_t call,
	cpc_hw_t hw,
	cpc_counter_t counter,
	cpc_slot_t slot,
	cpc_deadlines_t deadlines,
	cpc_call_func_t func,
	void *context);

/// Enter the period to call the function based on the counter incrementing.
/// A call can only be entered once at a time.
/// A call must be cancelled if it is entered to be destroyed.
///
/// - Parameter call: The call to enter.
/// - Parameter period: How many counter increments until the function is called.
void cpc_call_enter(cpc_call_t call, uint64_t period);

/// Cancel an outstanding enter on a call.
/// A call must have been entered before it can be cancelled.
///
/// - Parameter call: The call to cancel.
void cpc_call_cancel(cpc_call_t call);

/// Clean up resources associated with a call.
/// The call cannot be entered.
///
/// - Parameter call: The call to destroy.
void cpc_call_destroy(cpc_call_t call);

#pragma mark - Event Sets

/// Some CPU counters can be configured to count different events.
/// Configuring multiple events at once are recorded in a set.

/// How the counter should count the event.
__options_decl(cpc_event_flags_t, unsigned int, {
	CPC_EF_NONE = 0x0000,
	/// Do not count execution in the kernel EL1 and EL2 contexts.
	CPC_EF_NO_KERNEL = 0x0001,
	/// Do not count execution in the user EL0 context.
	CPC_EF_NO_USER = 0x0002,
});

/// Details of an event selection.
struct cpc_event_select {
	/// Which slot to count this event on.
	cpc_slot_t ces_slot;
	/// The hardware-specific selector encoding for the event.
	uint64_t ces_selector;
	/// Any flags that affect the event's counting behavior.
	cpc_event_flags_t ces_flags;
};
typedef struct cpc_event_select *cpc_event_select_t;

/// A list of `cpc_event_select` and `cpc_cyclic_info` structures for configurable counting.

typedef struct cpc_set *cpc_set_t;

__options_decl(cpc_set_options_t, uint32_t, {
	CPC_SET_BASE = 0x0,

	// Ignore the event allow list for this set.
	CPC_SET_ALLOW_ANY_EVENT = 0x1,
});

/// Create and allocate a new set.
///
/// - Parameter hw: The HW to target for this set.
/// - Parameter events: An array of events to configure at the same time.
/// Slots must be mutually exclusive and configurable.
/// - Parameter events_count: The number of events in the `events` array.
/// - Parameter cyclics: Any cyclics that correspond to event selections that will be activated when the set is applied.
/// - Parameter cyclics_count: The number of cyclics in the `cyclics` array.
/// - Returns: A set that must be destroyed with `cpc_set_destroy` or NULL on failure.
/// The failure reason will be printed to serial.
cpc_set_t cpc_set_alloc(cpc_hw_t hw,
    cpc_set_options_t options,
    const struct cpc_event_select *events,
    unsigned int events_count,
    const struct cpc_cyclic_info *cyclics,
    unsigned int cyclics_count);

/// Apply a set's event selections and cyclics system-wide.
/// A set must be removed with `cpc_set_remove` before it can be destroyed.
///
/// This is an expensive operation because it involves a CPU broadcast cross-call to set up per-unit state.
///
/// - Parameter set: The set to apply.
void cpc_set_apply(cpc_set_t set);

/// Remove the set's event selections and cyclics system-wide.
/// A set must have been applied with `cpc_set_apply` before it can be removed.
///
/// This is an expensive operation because it involves a CPU broadcast cross-call to set up per-unit state.
///
/// - Parameter set: The set to remove.
void cpc_set_remove(cpc_set_t set);

/// Clean up the resources associated with a set.
/// The set cannot be applied when this function is called.
///
/// - Parameter set: The set to destroy.
void cpc_set_destroy(cpc_set_t setting);

#pragma mark - Security

#if CPC_INSECURE

/// Return whether CPC is operating securely.
__result_use_check bool cpc_is_secure(void);

/// Change the security enforcement of CPC.
///
/// - Parameters:
///     - enforce_security: Whether to enforce secure usage of CPC.
void cpc_change_security(bool enforce_security);

#else // CPC_INSECURE

#define cpc_is_secure() true

#endif // !CPC_INSECURE

#pragma mark - Kernel Integration

/// The per-task structure for CPC management.
struct cpc_task {
	bool ctk_owner;
};

/// Take or release ownership of CPC from a task.
///
/// - Parameter task: The task that's changing its ownership.
/// - Parameter own: True if becoming owned or false otherwise.
/// - Returns: 0 on success or an errno value otherwise.
__result_use_check errno_t cpc_task_set_owner(struct cpc_task *task, bool own);

/// Check if the provided task owns CPC.
///
/// - Parameter task: The task to check for ownership.
/// - Returns: True if the task owns CPC or false otherwise.
__result_use_check bool cpc_task_is_owner(struct cpc_task *task);

/// Indicate to CPC the task is terminating.
///
/// - Parameter task: The task that's terminating.
void cpc_task_terminate(struct cpc_task *task);

/// Start sharing CPC.
///
/// - Parameter notify: A function to call whenever exclusive ownership changes.
void cpc_sharing_start(void (*notify)(boolean_t));

/// Check if sharing is currently available for CPC.
///
/// - Returns: True if CPC is capable of being shared or false otherwise.
__result_use_check bool cpc_sharing_available(void);

/// Disable sharing in CPC.
void cpc_sharing_stop(void);

/// Take or release exclusive ownership of CPC.
/// This call must be made in the context of another sharing function that holds its lock.
///
/// - Parameter exc: True to take exclusive ownership or false to release it.
void cpc_sharing_set_exclusive_locked(bool exc);

/// Check if CPC is owned exclusively.
///
/// - Returns: True if CPC is owned exclusively or false if it's shared or unowned.
__result_use_check bool cpc_sharing_is_exclusive(void);

/// Return the last read value of the cycles and instructions counters,
/// which may be part of a reset state.
/// This is probably not the correct interface to use.
struct cpc_cycles_instrs cpc_cycles_instrs_raw_approx(void);

/// Get the number of PMIs seen by hardware.
///
/// - Parameter hw: The HW to count the PMIs of.
/// - Returns: The number of PMIs that have occurred on all units of the HW.
uint64_t cpc_hw_pmi_count(cpc_hw_t hw);

/// The representation of an event selected for counting.
typedef uint32_t cpc_event_t;

/// An invalid event.
extern const cpc_event_t CPC_EVENT_INVALID;

/// Check whether an event is allowed to be counted according to the system's security policy.
///
/// Parameters:
///   - hw: The allow list to check differs by the hardware.
///   - event_selector: The event encoding to be sent to the hardware.
/// Returns: The event found or `CPC_EVENT_INVALID` if the event cannot be selected.
cpc_event_t cpc_find_event(cpc_hw_t hw, uint16_t event_selector);

#pragma mark - Implementation Details

/// Internal state for a counter tracked by CPC.
struct cpc_counter {
	uint64_t cctr_sum;
	uint64_t cctr_prev_value;
#if MACH_ASSERT
	uint64_t cctr_wrap_count;
#endif // MACH_ASSERT
};

/// Internal state for deadlines on a counter.
struct cpc_deadlines {
	uint64_t cd_deadlines[CPC_MAX_CALLS];
	cpc_call_t cd_calls[CPC_MAX_CALLS];
	lck_spin_t cd_lock;
};

typedef struct cpc_deadlines *cpc_deadlines_t;

__END_DECLS
