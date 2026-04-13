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

#include <kern/cpc.h>
#include <stdbool.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <os/atomic.h>
#include <os/atomic_private.h>
#include <kern/percpu.h>
#include <kern/locks.h>
#include <kern/debug.h>
#include <sys/errno.h>
#include <kern/cpc_private.h>
#include <kern/cpu_data.h>
#include <machine/machine_cpc.h>

#if __arm64__
#include <arm/machine_routines.h>
#endif // __arm64__

LCK_GRP_DECLARE(cpc_lock_grp, "cpc");

const cpc_event_t CPC_EVENT_INVALID = UINT32_MAX;

#pragma mark - Counters

/// Set a deadline for a physical counter.
///
/// - Parameter counter: The counter to set the deadline against.
/// - Parameter slot: The slot of the counter being set.
/// - Parameter deadline: The counter value deadline to use; this must be
/// larger than the sum.
static void
_cpc_counter_set_deadline(cpc_counter_t counter, cpc_slot_t slot,
    uint64_t deadline)
{
	assert3u(deadline, >, counter->cctr_sum);
	uint64_t gap = deadline - counter->cctr_sum;
	uint64_t value = 0;
	if (os_sub_overflow(CPC_CPMU_MAX_COUNT, gap, &value)) {
		panic(
			"CPC: cannot set deadline for PMC %d to %llu "
			"(from current sum %llu), %llu > max PMC count %llu",
			slot, deadline, counter->cctr_sum, gap, CPC_CPMU_MAX_COUNT);
	}
	cpc_counter_set_value(counter, slot, value);
}

void
cpc_hw_counts(
	cpc_hw_t __assert_only hw,
	uint64_t counter_mask,
	uint64_t *counts,
	size_t counts_len)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	cpc_counter_t counters = cpc_cpmu_counters();
	int intrs_en = ml_set_interrupts_enabled(FALSE);

	unsigned int ctr_store = 0;
	for (unsigned int i = __builtin_ctzll(counter_mask);
	    i < CPMU_PMC_COUNT && ctr_store < counts_len; i++) {
		if ((1ULL << i) & counter_mask) {
			counts[ctr_store] = cpc_cpmu_counter_update(&counters[i], i);
			ctr_store += 1;
		}
	}
	ml_set_interrupts_enabled(intrs_en);
}

#pragma mark - Calls

uint64_t
cpc_hw_max_period(cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	return CPC_CPMU_MAX_COUNT - 1;
}

void
cpc_deadlines_sync(
	cpc_deadlines_t deadlines,
	cpc_counter_t counter,
	cpc_slot_t slot)
{
	assert(ml_get_interrupts_enabled() == FALSE);
	uint64_t earliest_deadline = UINT64_MAX;
	for (unsigned int i = 0; i < CPC_MAX_CALLS; i++) {
		uint64_t deadline = deadlines->cd_deadlines[i];
		if (deadline != 0 && deadline < earliest_deadline) {
			earliest_deadline = deadline;
		}
	}
	if (earliest_deadline == UINT64_MAX) {
		cpc_counter_set_value(counter, slot, 0);
	} else {
		_cpc_counter_set_deadline(counter, slot, earliest_deadline);
	}
}

void
cpc_call_init(
	cpc_call_t call,
	cpc_hw_t hw,
	cpc_counter_t counter,
	cpc_slot_t slot,
	cpc_deadlines_t deadlines,
	cpc_call_func_t func,
	void *context)
{
	call->cca_hw = hw;
	call->cca_state = CPC_CST_INIT;
	call->cca_counter = counter;
	call->cca_slot = slot;
	call->cca_deadlines = deadlines;
	call->cca_func = func;
	call->cca_context = context;
}

static void
_cpc_call_enter_defer_locked(cpc_call_t call, uint64_t period)
{
	if (call->cca_state == CPC_CST_ENTERED) {
		panic("%s: call to %p is already entered", __func__, call->cca_func);
	}

	cpc_counter_t counter = call->cca_counter;
	cpc_deadlines_t deadlines = call->cca_deadlines;
	cpc_slot_t slot = call->cca_slot;
	unsigned int first_free = CPC_MAX_CALLS;

	for (unsigned int i = 0; i < CPC_MAX_CALLS; i++) {
		if (deadlines->cd_deadlines[i] == 0) {
			first_free = i;
			break;
		}
	}
	if (first_free == CPC_MAX_CALLS) {
		panic("CPC: too many calls on counter %p", counter);
	}
	deadlines->cd_calls[first_free] = call;
	uint64_t current = cpc_cpmu_counter_update(call->cca_counter, slot);
	uint64_t deadline = current + period;
	deadlines->cd_deadlines[first_free] = deadline;
	call->cca_state = CPC_CST_ENTERED;
}

// Enter a call without resynchronizing the hardware counters,
// in order to batch up multiple deadline updates (e.g. for cyclic re-enters).
static void
_cpc_call_enter_defer(cpc_call_t call, uint64_t period)
{
	cpc_deadlines_t deadlines = call->cca_deadlines;
	lck_spin_lock(&deadlines->cd_lock);
	_cpc_call_enter_defer_locked(call, period);
	lck_spin_unlock(&deadlines->cd_lock);
}

void
cpc_call_enter(cpc_call_t call, uint64_t period)
{
	int intrs_en = ml_set_interrupts_enabled(FALSE);
	const union cpc_machine_regs *regs = cpc_active_regs(call->cca_hw);
	cpc_hw_slot_disable(call->cca_hw, regs, call->cca_slot);
	_cpc_call_enter_defer(call, period);
	cpc_deadlines_sync(call->cca_deadlines, call->cca_counter,
	    call->cca_slot);
	cpc_hw_slot_reenable(call->cca_hw, regs, call->cca_slot);
	ml_set_interrupts_enabled(intrs_en);
}

static void
_cpc_deadlines_remove(
	cpc_deadlines_t deadlines,
	unsigned int deadline_index)
{
	deadlines->cd_calls[deadline_index] = NULL;
	deadlines->cd_deadlines[deadline_index] = 0;
}

void
cpc_counter_update(cpc_counter_t counter, uint64_t value)
{
	if (value < counter->cctr_prev_value) {
#if CPC_COUNTERS_WRAP
		uint64_t up_to_max = CPC_CPMU_MAX_COUNT - counter->cctr_prev_value;
		counter->cctr_sum += up_to_max;
		counter->cctr_prev_value = 0;
#else // CPC_COUNTERS_WRAP
		counter->cctr_prev_value = value;
#endif // CPC_COUNTERS_WRAP
#if MACH_ASSERT
		counter->cctr_wrap_count += 1;
#endif // MACH_ASSERT
	}
	counter->cctr_sum += value - counter->cctr_prev_value;
	counter->cctr_prev_value = value;
}

void
cpc_counter_call(
	cpc_counter_t counter,
	cpc_deadlines_t deadlines,
	cpc_slot_t slot,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags)
{
	uint64_t count = cpc_cpmu_counter_update(counter, slot);
	cpc_call_t calls_pending[CPC_MAX_CALLS] = {};
	uint64_t deadlines_pending[CPC_MAX_CALLS] = {};
	unsigned int calls_pending_count = 0;

	lck_spin_lock_nopreempt(&deadlines->cd_lock);
	for (unsigned int i = 0; i < CPC_MAX_CALLS; i++) {
		uint64_t deadline = deadlines->cd_deadlines[i];
		if (deadline != 0 && count >= deadline) {
			cpc_call_t call = deadlines->cd_calls[i];
			call->cca_state = CPC_CST_INIT;
			_cpc_deadlines_remove(deadlines, i);
			calls_pending[calls_pending_count] = call;
			deadlines_pending[calls_pending_count] = deadline;
			calls_pending_count += 1;
		}
	}
	lck_spin_unlock_nopreempt(&deadlines->cd_lock);

	for (unsigned int i = 0; i < calls_pending_count; i++) {
		cpc_call_t call = calls_pending[i];
		call->cca_func(call, slot, deadlines_pending[i], count, pc, source,
		    flags, call->cca_context);
	}
}

void
cpc_call_cancel(cpc_call_t call)
{
	if (call->cca_state != CPC_CST_ENTERED) {
		panic("%s: call to %p is not entered during cancel", __func__,
		    call->cca_func);
	}

	cpc_deadlines_t deadlines = call->cca_deadlines;

#if SCHED_HYGIENE_DEBUG
	int intrs_en = ml_set_interrupts_enabled_with_debug(FALSE, FALSE);
#else // SCHED_HYGIENE_DEBUG
	int intrs_en = ml_set_interrupts_enabled(FALSE);
#endif // !SCHED_HYGIENE_DEBUG
	disable_preemption_without_measurements();
	lck_spin_lock_nopreempt(&deadlines->cd_lock);

	for (unsigned int i = 0; i < CPC_MAX_CALLS; i++) {
		if (deadlines->cd_calls[i] == call) {
			cpc_counter_t counter = call->cca_counter;
			cpc_slot_t slot = call->cca_slot;
			_cpc_deadlines_remove(deadlines, i);
			cpc_deadlines_sync(deadlines, counter, slot);
			call->cca_state = CPC_CST_INIT;
			lck_spin_unlock_nopreempt(&deadlines->cd_lock);
			enable_preemption();
#if SCHED_HYGIENE_DEBUG
			ml_set_interrupts_enabled_with_debug(intrs_en, FALSE);
#else // SCHED_HYGIENE_DEBUG
			ml_set_interrupts_enabled(intrs_en);
#endif // !SCHED_HYGIENE_DEBUG
			return;
		}
	}

	panic("%s: cannot find call %p to cancel", __func__, call);
}

void
cpc_call_destroy(cpc_call_t __assert_only call)
{
	assert3u(call->cca_state, !=, CPC_CST_ENTERED);
}

#pragma mark - Cyclic

LCK_SPIN_DECLARE(_cpc_cyclics_lock, &cpc_lock_grp);
static unsigned int _cpc_active_cyclics_count = 0;
static struct cpc_cyclic *_cpc_active_cyclics[CPC_MAX_CYCLICS] = { NULL };

static void
_cpc_cyclic_trampoline(
	cpc_call_t call,
	cpc_slot_t __unused slot,
	uint64_t deadline,
	uint64_t count,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags,
	void *context)
{
	struct cpc_cyclic *cyc = context;
	cyc->ccyi_info.cci_func(&cyc->ccyi_info, count, count - deadline, pc,
	    source, flags);
	(void)_cpc_call_enter_defer(call, cyc->ccyi_info.cci_period);
	// The hardware will be synchronized at the end of the PMI handler.
}

cpc_cyclic_t
cpc_cyclic_alloc(
	cpc_hw_t hw,
	const struct cpc_cyclic_info *info)
{
	if (info->cci_period > cpc_hw_max_period(hw)) {
		return NULL;
	}
	unsigned int unit_count = cpc_hw_unit_count(hw);
	struct cpc_cyclic *cyc = kalloc_type(struct cpc_cyclic, struct cpc_call,
	    unit_count, Z_ZERO | Z_WAITOK);
	cyc->ccyi_state = CPC_CYS_INIT;
	cyc->ccyi_info = *info;
	cyc->ccyi_hw = hw;
	cyc->ccyi_call_count = unit_count;
	for (unsigned int i = 0; i < unit_count; i++) {
		cpc_deadlines_t deadlines = NULL;
		cpc_counter_t counter = cpc_hw_counter(hw, i, info->cci_slot,
		    &deadlines);
		cpc_call_init(&cyc->ccyi_calls[i], hw,
		    counter, info->cci_slot, deadlines,
		    _cpc_cyclic_trampoline, cyc);
	}
	return cyc;
}

void
cpc_cyclic_destroy(cpc_cyclic_t cyclic)
{
	for (unsigned int i = 0; i < cyclic->ccyi_call_count; i++) {
		cpc_call_destroy(&cyclic->ccyi_calls[i]);
	}
	kfree_type(struct cpc_cyclic, struct cpc_call,
	    cyclic->ccyi_call_count, cyclic);
}

static void
_cpc_cyclic_activate_batch(
	cpc_hw_t hw,
	cpc_cyclic_t *cyclics,
	unsigned int count,
	void (^unit_setup)(unsigned int unit_id))
{
	if (count > 0) {
		// Update the active list for any units that are currently offline.
		bool added = false;
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		lck_spin_lock(&_cpc_cyclics_lock);
		for (unsigned int i = 0; i < count; i++) {
			cpc_cyclic_t cyclic = cyclics[i];
			assert3u(cyclic->ccyi_state, ==, CPC_CYS_INIT);
			if (_cpc_active_cyclics_count < CPC_MAX_CYCLICS) {
				_cpc_active_cyclics[_cpc_active_cyclics_count] = cyclic;
				_cpc_active_cyclics_count += 1;
				added = true;
			} else {
				added = false;
				break;
			}
		}
		lck_spin_unlock(&_cpc_cyclics_lock);
		ml_set_interrupts_enabled(intrs_en);
		if (!added) {
			panic("CPC: too many cyclics active at once");
		}
	}

	// Notify any online units to enter a new period for the cyclic's call.
	cpc_hw_broadcast(hw, ^(unsigned int unit_id) {
		for (unsigned int i = 0; i < count; i++) {
		        cpc_cyclic_t cyclic = cyclics[i];
		        cpc_call_t call = &cyclic->ccyi_calls[unit_id];
		        // Ignore any already-entered calls.
		        // Between adding the cyclic and this IPI being acknowledged,
		        // CPUs being initialized enter calls in _cpc_cyclic_sync_calls.
		        if (call->cca_state == CPC_CST_INIT) {
		                cpc_call_enter(call, cyclic->ccyi_info.cci_period);
			}
		}
		if (unit_setup) {
		        unit_setup(unit_id);
		}
	});

	for (unsigned int i = 0; i < count; i++) {
		cpc_cyclic_t cyclic = cyclics[i];
		cyclic->ccyi_state = CPC_CYS_ENTERED;
	}
}

void
cpc_cyclic_activate(cpc_cyclic_t cyclic)
{
	cpc_cyclic_t cyclics[1] = { cyclic };
	_cpc_cyclic_activate_batch(cyclic->ccyi_hw, cyclics, 1, NULL);
}

static void
_cpc_cyclic_cancel_batch(
	cpc_hw_t hw,
	cpc_cyclic_t *cyclics,
	unsigned int count,
	void (^unit_teardown)(unsigned int unit_id))
{
	if (count > 0) {
		// Remove from the active list so they won't be initialized as units come online.
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		lck_spin_lock(&_cpc_cyclics_lock);
		for (unsigned int i = 0; i < count; i++) {
			cpc_cyclic_t cyclic = cyclics[i];
			assert3u(cyclic->ccyi_state, ==, CPC_CYS_ENTERED);
			bool removed = false;
			for (unsigned int j = 0; j < _cpc_active_cyclics_count; j++) {
				if (_cpc_active_cyclics[j] == cyclic) {
					if (_cpc_active_cyclics_count > 0) {
						_cpc_active_cyclics[j] =
						    _cpc_active_cyclics[_cpc_active_cyclics_count - 1];
					}
					_cpc_active_cyclics_count -= 1;
					_cpc_active_cyclics[_cpc_active_cyclics_count] = NULL;
					removed = true;
					break;
				}
			}
			if (!removed) {
				panic("CPC: cyclic %p cancelled that was not activated", cyclic);
			}
		}
		lck_spin_unlock(&_cpc_cyclics_lock);
		ml_set_interrupts_enabled(intrs_en);
	}

	// Notify any online units to cancel their unit-local calls.
	cpc_hw_broadcast(hw, ^(unsigned int unit_id) {
		if (unit_teardown) {
		        unit_teardown(unit_id);
		}
		for (unsigned int i = 0; i < count; i++) {
		        cpc_cyclic_t cyclic = cyclics[i];
		        cpc_call_t call = &cyclic->ccyi_calls[unit_id];
		        // Allow a call to not have been entered.
		        // Consider CPUs offline at activation and onlining after the cyclic was removed from the active list.
		        // These will not have entered the call.
		        if (call->cca_state == CPC_CST_ENTERED) {
		                cpc_call_cancel(call);
			}
		}
	});

	if (count > 0) {
		// Check for any units that didn't respond to the broadcast and unlink the
		// cyclic's calls from their per-unit deadlines.
		unsigned int unit_count = cpc_hw_unit_count(cyclics[0]->ccyi_hw);
		int intrs_en = ml_set_interrupts_enabled(FALSE);
		for (unsigned int i = 0; i < count; i++) {
			cpc_cyclic_t cyclic = cyclics[i];
			for (unsigned int j = 0; j < unit_count; j++) {
				cpc_call_t call = &cyclic->ccyi_calls[j];
				if (call->cca_state == CPC_CST_ENTERED) {
					cpc_deadlines_t deadlines = call->cca_deadlines;
					lck_spin_lock(&deadlines->cd_lock);
					for (unsigned int k = 0; k < CPC_MAX_CALLS; k++) {
						if (deadlines->cd_calls[k] == call) {
							_cpc_deadlines_remove(deadlines, k);
							call->cca_state = CPC_CST_INIT;
						}
					}
					lck_spin_unlock(&deadlines->cd_lock);
				}
			}
			cyclic->ccyi_state = CPC_CYS_INIT;
		}
		ml_set_interrupts_enabled(intrs_en);
	}
}

void
cpc_cyclic_cancel(cpc_cyclic_t cyclic)
{
	cpc_cyclic_t cyclics[1] = { cyclic };
	_cpc_cyclic_cancel_batch(cyclic->ccyi_hw, cyclics, 1, NULL);
}

/// Synchronize a cyclic's calls with a unit.
/// Must be called in the context of a unit,
/// typically when that unit's CPU or cluster is brought back online.
/// Without this function, any cyclic activations while offline would be missed.
static void
_cpc_cyclic_sync_calls(cpc_hw_t __assert_only hw,
    unsigned int unit_id,
    cpc_deadlines_t deadlines)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	// Scheduler hygiene and preemption measurements include sampling the CPU counters,
	// but this function is called before counters are set up.
#if SCHED_HYGIENE_DEBUG
	int intrs_en = ml_set_interrupts_enabled_with_debug(FALSE, FALSE);
#else // SCHED_HYGIENE_DEBUG
	int intrs_en = ml_set_interrupts_enabled(FALSE);
#endif // !SCHED_HYGIENE_DEBUG
	disable_preemption_without_measurements();
	lck_spin_lock_nopreempt(&_cpc_cyclics_lock);
	lck_spin_lock_nopreempt(&deadlines->cd_lock);

	// Find cyclics with calls that are not present on this unit.
	for (unsigned int i = 0; i < _cpc_active_cyclics_count; i++) {
		struct cpc_cyclic *cyclic = _cpc_active_cyclics[i];
		cpc_call_t cyclic_call = &cyclic->ccyi_calls[unit_id];
		bool found = false;
		if (cyclic != NULL) {
			cpc_slot_t slot = cyclic->ccyi_info.cci_slot;
			for (unsigned int j = 0; j < CPC_MAX_CALLS; j++) {
				cpc_call_t call = deadlines[slot].cd_calls[j];
				if (call == &cyclic->ccyi_calls[unit_id]) {
					found = true;
					break;
				}
			}
			if (!found) {
				// Enter as deferred because the PMC values will be configured after this call.
				_cpc_call_enter_defer_locked(cyclic_call,
				    cyclic->ccyi_info.cci_period);
			}
		}
	}
	lck_spin_unlock_nopreempt(&deadlines->cd_lock);
	lck_spin_unlock_nopreempt(&_cpc_cyclics_lock);
	enable_preemption();
#if SCHED_HYGIENE_DEBUG
	ml_set_interrupts_enabled_with_debug(intrs_en, FALSE);
#else // SCHED_HYGIENE_DEBUG
	ml_set_interrupts_enabled(intrs_en);
#endif // !SCHED_HYGIENE_DEBUG
}

#pragma mark - Sets

cpc_set_t
cpc_set_alloc(cpc_hw_t hw,
    cpc_set_options_t options,
    const struct cpc_event_select *events,
    unsigned int events_count,
    const struct cpc_cyclic_info *cyclics,
    unsigned int cyclics_count)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	union cpc_machine_regs regs = cpc_machine_regs_base;

	for (unsigned int i = 0; i < events_count; i++) {
		if (events[i].ces_selector == 0) {
			continue;
		}
		cpc_slot_t slot = events[i].ces_slot;
		if (slot >= CPMU_PMC_COUNT) {
			printf("CPC: event %d specifies slot %u, out of range\n", i, slot);
			return NULL;
		}
		cpc_event_flags_t flags = events[i].ces_flags;
		if ((flags & (CPC_EF_NO_KERNEL | CPC_EF_NO_USER)) ==
		    (CPC_EF_NO_KERNEL | CPC_EF_NO_USER)) {
			printf("CPC: event %d cannot disable both kernel and user counting\n",
			    i);
			return NULL;
		}

		bool ok = cpc_machine_regs_event_select(&regs, hw, options, &events[i]);
		if (!ok) {
			return NULL;
		}
	}

	uint64_t max_period = cpc_hw_max_period(hw);
	for (unsigned int i = 0; i < cyclics_count; i++) {
		if (cyclics[i].cci_period >= max_period) {
			printf("CPC: cyclic %d period is too large, %llu >= %llu\n", i,
			    cyclics[i].cci_period, max_period);
			return NULL;
		}
	}

	cpc_set_t set = kalloc_type(struct cpc_set, Z_ZERO | Z_WAITOK);
	set->cst_hw = hw;
	set->cst_events = kalloc_type(struct cpc_event_select, events_count,
	    Z_ZERO | Z_WAITOK);
	memcpy(set->cst_events, events, events_count * sizeof(events[0]));
	set->cst_event_count = events_count;
	if (cyclics_count > 0) {
		set->cst_cyclics = kalloc_type(cpc_cyclic_t, cyclics_count,
		    Z_ZERO | Z_WAITOK);
		for (unsigned int i = 0; i < cyclics_count; i++) {
			set->cst_cyclics[i] = cpc_cyclic_alloc(hw, &cyclics[i]);
			if (!set->cst_cyclics[i]) {
				panic("CPC: failed to allocate cyclic");
			}
		}
		set->cst_cyclic_count = cyclics_count;
	}
	set->cst_regs = regs;

	return set;
}

static cpc_set_t _cpc_active_sets[CPC_HW_COUNT] = { 0 };

const union cpc_machine_regs *
cpc_active_regs(cpc_hw_t hw)
{
	struct cpc_set *set = os_atomic_load(_cpc_active_sets + hw, acquire);
	return set ? &set->cst_regs : &cpc_machine_regs_init;
}

void
cpc_set_apply(const cpc_set_t set)
{
	cpc_set_t orig = NULL;
	if (!os_atomic_cmpxchgv(_cpc_active_sets + set->cst_hw, NULL, set, &orig, acq_rel)) {
		panic("cpc: applying settings %p with existing settings %p", set, orig);
	}
	_cpc_cyclic_activate_batch(set->cst_hw, set->cst_cyclics, set->cst_cyclic_count,
	    ^(unsigned int __unused unit_id) {
		cpc_machine_regs_apply(&set->cst_regs, set->cst_hw);
	});
	set->cst_applied = true;
}

void
cpc_set_remove(const cpc_set_t set)
{
	assert(set->cst_applied);
	os_atomic_store(_cpc_active_sets + set->cst_hw, NULL, release);
	_cpc_cyclic_cancel_batch(set->cst_hw, set->cst_cyclics, set->cst_cyclic_count,
	    ^(unsigned int __unused unit_id) {
		cpc_machine_regs_reset(&set->cst_regs, CPC_HW_CPMU);
	});
	set->cst_applied = false;
}

void
cpc_set_destroy(cpc_set_t set)
{
	assert(!set->cst_applied);
	kfree_type(struct cpc_event_select, set->cst_event_count,
	    set->cst_events);
	for (unsigned int i = 0; i < set->cst_cyclic_count; i++) {
		cpc_cyclic_destroy(set->cst_cyclics[i]);
	}
	kfree_type(cpc_cyclic_t, set->cst_cyclic_count, set->cst_cyclics);
	kfree_type(struct cpc_set, set);
}

#pragma mark - CPU Callbacks

void
cpc_hw_configure(cpc_hw_t hw,
    unsigned int unit_id,
    cpc_counter_t counters,
    cpc_deadlines_t deadlines,
    bool check_for_cyclics)
{
	if (hw == CPC_HW_CPMU) {
		assert(ml_get_interrupts_enabled() == FALSE);
		cpc_set_t set = os_atomic_load(_cpc_active_sets + hw, acquire);
		const union cpc_machine_regs *regs = set ? &set->cst_regs :
		    &cpc_machine_regs_init;
		if (check_for_cyclics) {
			_cpc_cyclic_sync_calls(hw, unit_id, deadlines);
		}
		// Resynchronize the counters and ensure any cyclic deadlines are applied.
		cpc_counters_resync(hw, unit_id, counters);

		if (set) {
			cpc_machine_regs_apply(regs, hw);
		} else {
			cpc_machine_regs_reset(regs, hw);
		}
	}
}

#pragma mark - Sharing

/// How CPC is being shared by power management and other clients.
__enum_decl(cpc_sharing_t, unsigned int, {
	CPC_SH_NONE,
	CPC_SH_SHARED,
	CPC_SH_EXCLUSIVE,
});

static void (*_cpc_pm_notify)(boolean_t) = NULL;
static cpc_sharing_t _cpc_sharing_reset = CPC_SH_NONE;
static cpc_sharing_t _cpc_sharing = CPC_SH_NONE;

static LCK_MTX_DECLARE(_cpc_sharing_lock, &cpc_lock_grp);

void
cpc_sharing_start(void (*notify)(boolean_t))
{
	lck_mtx_lock(&_cpc_sharing_lock);
	_cpc_pm_notify = notify;
	_cpc_sharing_reset = CPC_SH_SHARED;
	_cpc_sharing = CPC_SH_SHARED;
	lck_mtx_unlock(&_cpc_sharing_lock);
}

__result_use_check bool
cpc_sharing_available(void)
{
	return _cpc_pm_notify != NULL;
}

void
cpc_sharing_stop(void)
{
	lck_mtx_lock(&_cpc_sharing_lock);
	_cpc_pm_notify = NULL;
	_cpc_sharing_reset = CPC_SH_NONE;
	if (_cpc_sharing == CPC_SH_SHARED) {
		_cpc_sharing = CPC_SH_NONE;
	}
	lck_mtx_unlock(&_cpc_sharing_lock);
}

int
cpc_task_set_owner(struct cpc_task *task, bool owner)
{
	int ret = 0;
	lck_mtx_lock(&_cpc_sharing_lock);
	bool const exc = _cpc_sharing == CPC_SH_EXCLUSIVE;

	if (exc && !task->ctk_owner) {
		// Prevent changes if a different task already has exclusive access.
		ret = EACCES;
		goto out;
	} else if (exc == owner) {
		// No changes needed.
		goto out;
	} else {
		bool const available_to_pm = !owner;
#if HAS_UPMU
		// Until there's native support for the uncore counters in CPC, make
		// sure Monotonic clears out the uncore settings here.
		if (available_to_pm) {
			extern void uncore_reset(void);
			uncore_reset();
		}
#endif // HAS_UPMU
		if (_cpc_pm_notify) {
			_cpc_pm_notify(available_to_pm);
		}

		// kpc_pm_acknowledge was not called in the handler,
		// but finish the operation regardless.
		if ((_cpc_sharing == CPC_SH_EXCLUSIVE) != owner) {
			_cpc_sharing = owner ? CPC_SH_EXCLUSIVE : _cpc_sharing_reset;
		}
	}

	task->ctk_owner = owner;

out:
	lck_mtx_unlock(&_cpc_sharing_lock);
	return 0;
}

void
cpc_task_terminate(struct cpc_task *task)
{
	if (task->ctk_owner) {
		(void)cpc_task_set_owner(task, false);
	}
}

void
cpc_sharing_set_exclusive_locked(bool exc)
{
	LCK_MTX_ASSERT(&_cpc_sharing_lock, LCK_MTX_ASSERT_OWNED);
	_cpc_sharing = exc ? CPC_SH_EXCLUSIVE : _cpc_sharing_reset;
}

__result_use_check bool
cpc_sharing_is_exclusive(void)
{
	return _cpc_sharing != CPC_SH_SHARED;
}

#pragma mark - Security

#if CPC_INSECURE

bool
cpc_is_secure(void)
{
#if CONFIG_CPU_COUNTERS
#if __arm64__
	cpc_event_policy_t policy = cpc_get_event_policy();
	return policy == CPC_EVPOL_RESTRICT_TO_KNOWN || policy == CPC_EVPOL_DENY_ALL;
#else // __arm64__
	return false;
#endif // !__arm64__
#else // CONFIG_CPU_COUNTERS
	return true;
#endif // !CONFIG_CPU_COUNTERS
}

void
cpc_change_security(bool enforce_security)
{
#if CONFIG_CPU_COUNTERS
#if __arm64__
	cpc_set_event_policy(enforce_security ? CPC_EVPOL_RESTRICT_TO_KNOWN : CPC_EVPOL_DEFAULT);
#else // __arm64__
#pragma unused(enforce_security)
	// Intel has no event policy or other security features.
#endif // !__arm64__
#else // CONFIG_CPU_COUNTERS
#pragma unused(enforce_security)
#endif // !CONFIG_CPU_COUNTERS
}

#endif // CPC_INSECURE

#pragma mark - Debugging

#if DEVELOPMENT || DEBUG

#define OUTPUT_BUFFER_SIZE (4096)

char *
cpc_state_create(bool local, size_t *size_out)
{
	unsigned int cpmu_count = local ? 1 : cpc_hw_unit_count(CPC_HW_CPMU);
	struct cpc_set *cpmu_set = os_atomic_load(_cpc_active_sets + CPC_HW_CPMU, acquire);

	struct cpc_pmu_state {
		// Machine-independent, per-PMU state.
		uint64_t cps_counter_sums[CPMU_PMC_COUNT];
		uint64_t cps_counter_prevs[CPMU_PMC_COUNT];
		uint64_t cps_deadlines[CPMU_PMC_COUNT][CPC_MAX_CALLS];

		// Filled in by the machine-dependent layers.
		union cpc_machine_regs cps_regs;
		uint64_t cps_counter_values[CPMU_PMC_COUNT];
	};

	size_t available = cpmu_count * OUTPUT_BUFFER_SIZE;
	if (cpmu_set) {
		available += 4096;
		available += cpmu_set->cst_event_count * 128;
		available += cpmu_set->cst_cyclic_count * 128;
	}

	struct cpc_pmu_state *states = kalloc_type(struct cpc_pmu_state, cpmu_count,
	    Z_WAITOK | Z_ZERO);
	if (!states) {
		printf("CPC: failed to allocate space for PMU states\n");
		return NULL;
	}
	char *output = kalloc_data(available, Z_ZERO | Z_WAITOK);
	if (!output) {
		printf("CPC: failed to allocate %lu bytes for state description\n",
		    available);
		kfree_type(struct cpc_pmu_state, cpmu_count, states);
		return NULL;
	}
	size_t written = 0;

	written += scnprintf(output + written, available - written, "CPC %s\n",
	    cpc_is_secure() ? "secure" : "insecure");
	written += scnprintf(output + written, available - written, "CPMU %s\n",
	    cpmu_set ? "active" : "inactive");
	if (cpmu_set) {
		for (unsigned int i = 0; i < cpmu_set->cst_event_count; i++) {
			struct cpc_event_select *event = &cpmu_set->cst_events[i];
			written += scnprintf(output + written, available - written,
			    "CPMU event %d: 0x%hx on %d (0x%x)\n", i,
			    (uint16_t)event->ces_selector, event->ces_slot,
			    event->ces_flags);
		}
		for (unsigned int i = 0; i < cpmu_set->cst_cyclic_count; i++) {
			struct cpc_cyclic *cyclic = cpmu_set->cst_cyclics[i];
			written += scnprintf(output + written, available - written,
			    "CPMU cyclic %d: %llu on %d\n", i,
			    cyclic->ccyi_info.cci_period,
			    cyclic->ccyi_info.cci_slot);
		}
	}
	written += scnprintf(output + written, available - written,
	    "CPMU %s registers:\n", cpmu_set ? "set" : "initial");
	written += cpc_hw_print_regs(CPC_HW_CPMU, "  ",
	    cpmu_set ? &cpmu_set->cst_regs : &cpc_machine_regs_init,
	    output + written, available - written);

	void (^block)(unsigned int) = ^(unsigned int unit_id){
		struct cpc_pmu_state *pmu_state = &states[unit_id];
		cpc_counter_t counters = cpc_cpmu_counters();
		cpc_deadlines_t deadlines = cpc_cpmu_deadlines();
		for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
			cpc_counter_t counter = &counters[i];
			pmu_state->cps_counter_prevs[i] = counter->cctr_prev_value;
			pmu_state->cps_counter_sums[i] = counter->cctr_sum;
			for (unsigned int j = 0; j < CPC_MAX_CALLS; j++) {
				pmu_state->cps_deadlines[i][j] = deadlines[i].cd_deadlines[j];
			}
		}
		cpc_hw_read_regs(CPC_HW_CPMU, &pmu_state->cps_regs,
		    pmu_state->cps_counter_values);
	};
	if (local) {
		block(cpu_number());
	} else {
		cpc_hw_broadcast(CPC_HW_CPMU, block);
	}

	for (unsigned int i = 0; i < cpmu_count; i++) {
		struct cpc_pmu_state *pmu_state = &states[i];

		written += scnprintf(output + written, available - written,
		    "CPMU %u state:\n", local ? cpu_number() : i);

		for (unsigned int j = 0; j < CPMU_PMC_COUNT; j++) {
			written += scnprintf(output + written,
			    available - written,
			    "  counter %d: sum = %llu, prev = %llu, cur = %llu\n", j,
			    pmu_state->cps_counter_sums[j], pmu_state->cps_counter_prevs[j],
			    pmu_state->cps_counter_values[j]);
			for (unsigned int k = 0; k < CPC_MAX_CALLS; k++) {
				uint64_t deadline = pmu_state->cps_deadlines[j][k];
				if (deadline != 0) {
					written += scnprintf(output + written, available - written,
					    "    deadline %d: %llu\n", k, deadline);
				}
			}
		}

		written += cpc_hw_print_regs(CPC_HW_CPMU, "  ", &pmu_state->cps_regs,
		    output + written, available - written);
	}

	kfree_type(struct cpc_pmu_state, cpmu_count, states);
	*size_out = available;
	return output;
}

void
cpc_state_destroy(char *state, size_t size)
{
	kfree_data(state, size);
}

#endif // DEVELOPMENT || DEBUG
