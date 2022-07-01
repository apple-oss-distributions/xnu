/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/task.h>

#include <kern/ast.h>
#include <kern/kalloc.h>
#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/machine.h>
#include <kern/misc_protos.h>
#include <kern/processor.h>
#include <kern/queue.h>
#include <kern/restartable.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/waitq.h>

#include <os/atomic_private.h>
#include <os/hash.h>
#include <os/refcnt.h>

/**
 * @file osfmk/kern/restartable.c
 *
 * @brief
 * This module implements restartable userspace functions.
 *
 * @discussion
 * task_restartable_ranges_register() allows task to configure
 * the restartable ranges, only once per task,
 * before it has made its second thread.
 *
 * task_restartable_ranges_synchronize() can later be used to trigger
 * restarts for threads with a PC in a restartable region.
 *
 * It is implemented with an AST (AST_RESET_PCS) that will cause threads
 * as they return to userspace to reset PCs in a restartable region
 * to the recovery offset of this region.
 *
 * Because signal delivery would mask the proper saved PC for threads,
 * sigreturn also forcefully sets the AST and will go through the logic
 * every single time.
 */

typedef int (*cmpfunc_t)(const void *a, const void *b);
extern void qsort(void *a, size_t n, size_t es, cmpfunc_t cmp);

#define RR_RANGES_MAX   64
struct restartable_ranges {
	queue_chain_t            rr_link;
	os_refcnt_t              rr_ref;
	uint32_t                 rr_count;
	uint32_t                 rr_hash;
	task_restartable_range_t rr_ranges[RR_RANGES_MAX];
};

#if DEBUG || DEVELOPMENT
#define RR_HASH_SIZE   256
#else
// Release kernel userspace should have shared caches and a single registration
#define RR_HASH_SIZE    16
#endif

static queue_head_t rr_hash[RR_HASH_SIZE];
LCK_GRP_DECLARE(rr_lock_grp, "restartable ranges");
LCK_SPIN_DECLARE(rr_spinlock, &rr_lock_grp);

#define rr_lock()   lck_spin_lock_grp(&rr_spinlock, &rr_lock_grp)
#define rr_unlock() lck_spin_unlock(&rr_spinlock);

#pragma mark internals

/**
 * @function _ranges_cmp
 *
 * @brief
 * Compares two ranges together.
 */
static int
_ranges_cmp(const void *_r1, const void *_r2)
{
	const task_restartable_range_t *r1 = _r1;
	const task_restartable_range_t *r2 = _r2;

	if (r1->location != r2->location) {
		return r1->location < r2->location ? -1 : 1;
	}
	if (r1->length == r2->length) {
		return 0;
	}
	return r1->length < r2->length ? -1 : 1;
}

/**
 * @function _ranges_validate
 *
 * @brief
 * Validates an array of PC ranges for wraps and intersections.
 *
 * @discussion
 * This sorts and modifies the input.
 *
 * The ranges must:
 * - not wrap around,
 * - have a length/recovery offset within a page of the range start
 *
 * @returns
 * - KERN_SUCCESS:          ranges are valid
 * - KERN_INVALID_ARGUMENT: ranges are invalid
 */
static kern_return_t
_ranges_validate(task_t task, task_restartable_range_t *ranges, uint32_t count)
{
	qsort(ranges, count, sizeof(task_restartable_range_t), _ranges_cmp);
	uint64_t limit = task_has_64Bit_data(task) ? UINT64_MAX : UINT32_MAX;
	uint64_t end, recovery;

	if (count == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	for (size_t i = 0; i < count; i++) {
		if (ranges[i].length > TASK_RESTARTABLE_OFFSET_MAX ||
		    ranges[i].recovery_offs > TASK_RESTARTABLE_OFFSET_MAX) {
			return KERN_INVALID_ARGUMENT;
		}
		if (ranges[i].flags) {
			return KERN_INVALID_ARGUMENT;
		}
		if (os_add_overflow(ranges[i].location, ranges[i].length, &end)) {
			return KERN_INVALID_ARGUMENT;
		}
		if (os_add_overflow(ranges[i].location, ranges[i].recovery_offs, &recovery)) {
			return KERN_INVALID_ARGUMENT;
		}
		if (ranges[i].location > limit || end > limit || recovery > limit) {
			return KERN_INVALID_ARGUMENT;
		}
		if (i + 1 < count && end > ranges[i + 1].location) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	return KERN_SUCCESS;
}

/**
 * @function _ranges_lookup
 *
 * @brief
 * Lookup the left side of a range for a given PC within a set of ranges.
 *
 * @returns
 * - 0: no PC range found
 * - the left-side of the range.
 */
__attribute__((always_inline))
static mach_vm_address_t
_ranges_lookup(struct restartable_ranges *rr, mach_vm_address_t pc)
{
	task_restartable_range_t *ranges = rr->rr_ranges;
	uint32_t l = 0, r = rr->rr_count;

	if (pc <= ranges[0].location) {
		return 0;
	}
	if (pc >= ranges[r - 1].location + ranges[r - 1].length) {
		return 0;
	}

	while (l < r) {
		uint32_t i = (r + l) / 2;
		mach_vm_address_t location = ranges[i].location;

		if (pc <= location) {
			/* if the PC is exactly at pc_start, no reset is needed */
			r = i;
		} else if (location + ranges[i].length <= pc) {
			/* if the PC is exactly at the end, it's out of the function */
			l = i + 1;
		} else {
			/* else it's strictly in the range, return the recovery pc */
			return location + ranges[i].recovery_offs;
		}
	}

	return 0;
}

/**
 * @function _restartable_ranges_dispose
 *
 * @brief
 * Helper to dispose of a range that has reached a 0 refcount.
 */
__attribute__((noinline))
static void
_restartable_ranges_dispose(struct restartable_ranges *rr, bool hash_remove)
{
	if (hash_remove) {
		rr_lock();
		remqueue(&rr->rr_link);
		rr_unlock();
	}
	kfree_type(struct restartable_ranges, rr);
}

/**
 * @function _restartable_ranges_equals
 *
 * @brief
 * Helper to compare two restartable ranges.
 */
static bool
_restartable_ranges_equals(
	const struct restartable_ranges *rr1,
	const struct restartable_ranges *rr2)
{
	size_t rr1_size = rr1->rr_count * sizeof(task_restartable_range_t);
	return rr1->rr_hash == rr2->rr_hash &&
	       rr1->rr_count == rr2->rr_count &&
	       memcmp(rr1->rr_ranges, rr2->rr_ranges, rr1_size) == 0;
}

/**
 * @function _restartable_ranges_create
 *
 * @brief
 * Helper to create a uniqued restartable range.
 *
 * @returns
 * - KERN_SUCCESS
 * - KERN_INVALID_ARGUMENT: the validation of the new ranges failed.
 * - KERN_RESOURCE_SHORTAGE: too many ranges, out of memory
 */
static kern_return_t
_restartable_ranges_create(task_t task, task_restartable_range_t *ranges,
    uint32_t count, struct restartable_ranges **rr_storage)
{
	struct restartable_ranges *rr, *rr_found, *rr_base;
	queue_head_t *head;
	uint32_t base_count, total_count;
	size_t base_size, size;
	kern_return_t kr;

	rr_base = *rr_storage;
	base_count = rr_base ? rr_base->rr_count : 0;
	base_size = sizeof(task_restartable_range_t) * base_count;
	size = sizeof(task_restartable_range_t) * count;

	if (os_add_overflow(base_count, count, &total_count)) {
		return KERN_INVALID_ARGUMENT;
	}
	if (total_count > RR_RANGES_MAX) {
		return KERN_RESOURCE_SHORTAGE;
	}

	rr = kalloc_type(struct restartable_ranges,
	    (zalloc_flags_t) (Z_WAITOK | Z_ZERO | Z_NOFAIL));

	queue_chain_init(rr->rr_link);
	os_ref_init(&rr->rr_ref, NULL);
	rr->rr_count = total_count;
	if (base_size) {
		memcpy(rr->rr_ranges, rr_base->rr_ranges, base_size);
	}
	memcpy(rr->rr_ranges + base_count, ranges, size);
	kr = _ranges_validate(task, rr->rr_ranges, total_count);
	if (kr) {
		_restartable_ranges_dispose(rr, false);
		return kr;
	}
	rr->rr_hash = os_hash_jenkins(rr->rr_ranges,
	    rr->rr_count * sizeof(task_restartable_range_t));

	head = &rr_hash[rr->rr_hash % RR_HASH_SIZE];

	rr_lock();
	queue_iterate(head, rr_found, struct restartable_ranges *, rr_link) {
		if (_restartable_ranges_equals(rr, rr_found) &&
		os_ref_retain_try(&rr_found->rr_ref)) {
			goto found;
		}
	}

	enqueue_tail(head, &rr->rr_link);
	rr_found = rr;

found:
	if (rr_base && os_ref_release_relaxed(&rr_base->rr_ref) == 0) {
		remqueue(&rr_base->rr_link);
	} else {
		rr_base = NULL;
	}
	rr_unlock();

	*rr_storage = rr_found;

	if (rr_found != rr) {
		_restartable_ranges_dispose(rr, false);
	}
	if (rr_base) {
		_restartable_ranges_dispose(rr_base, false);
	}
	return KERN_SUCCESS;
}

#pragma mark extern interfaces

__attribute__((always_inline))
void
restartable_ranges_release(struct restartable_ranges *rr)
{
	if (os_ref_release_relaxed(&rr->rr_ref) == 0) {
		_restartable_ranges_dispose(rr, true);
	}
}

__attribute__((always_inline))
void
thread_reset_pcs_will_fault(thread_t thread)
{
	/*
	 * Called in the exception handling code while interrupts
	 * are still disabled.
	 */
	os_atomic_store(&thread->t_rr_state.trr_fault_state,
	    (uint8_t)TRR_FAULT_PENDING, relaxed);
}

__attribute__((always_inline))
void
thread_reset_pcs_done_faulting(struct thread *thread)
{
	thread_rr_state_t state = {
		.trr_ipi_ack_pending = ~0,
	};

	/*
	 * Called by the exception handling code on the way back,
	 * or when the thread is terminated.
	 */
	state.trr_value = os_atomic_and_orig(&thread->t_rr_state.trr_value,
	    state.trr_value, relaxed);

	if (__improbable(state.trr_sync_waiting)) {
		task_t task = get_threadtask(thread);

		task_lock(task);
		wakeup_all_with_inheritor(&thread->t_rr_state, THREAD_AWAKENED);
		task_unlock(task);
	}
}

void
thread_reset_pcs_ack_IPI(struct thread *thread)
{
	thread_rr_state_t trrs;

	/*
	 * Called under the thread lock from IPI or CSwitch context.
	 */
	trrs.trr_value = os_atomic_load(&thread->t_rr_state.trr_value, relaxed);
	if (__improbable(trrs.trr_ipi_ack_pending)) {
		trrs.trr_ipi_ack_pending = false;
		if (trrs.trr_fault_state) {
			assert3u(trrs.trr_fault_state, ==, TRR_FAULT_PENDING);
			trrs.trr_fault_state = TRR_FAULT_OBSERVED;
		}
		os_atomic_store(&thread->t_rr_state.trr_value,
		    trrs.trr_value, relaxed);
	}
}

static bool
thread_rr_wait_if_needed(task_t task, thread_t thread)
{
	thread_rr_state_t state;
	bool did_unlock = false;

	state.trr_value = os_atomic_load(&thread->t_rr_state.trr_value, relaxed);
	if (state.trr_value == 0) {
		return did_unlock;
	}

	assert(state.trr_sync_waiting == 0);

	thread_reference(thread);

	/*
	 * The thread_rr_state state machine is:
	 *
	 *                        ,------------ IPI ack --------------.
	 *                        v                                   |
	 *        .-----> {f:N, w:0, ipi:0} --- IPI sent ---> {f:N, w:0, ipi:1}
	 *        |           |        ^                              |
	 *        |           |        |                              |
	 *      fault       will     fault                          will
	 *      done        fault    done                           fault
	 *        |           |        |                              |
	 *        |           v        |                              v
	 *        |       {f:P, w:0, ipi:0} --- IPI sent ---> {f:P, w:0, ipi:1}
	 *        |               |                                   |
	 *        |               |                                   |
	 *        |     act_set_ast_reset_pcs()                       |
	 *        |               |                                   |
	 *        |               v                                   |
	 *        +------ {f:O, w:0, ipi:0} <--- IPI Ack -------------'
	 *        |               |
	 *        |               |
	 *        |        wait_if_needed()
	 *        |               |
	 *        |               v
	 *        `------ {f:O, w:1, ipi:0}
	 */

	while (state.trr_ipi_ack_pending) {
		disable_preemption();
		task_unlock(task);

		state.trr_value =
		    hw_wait_while_equals32(&thread->t_rr_state.trr_value,
		    state.trr_value);

		enable_preemption();
		task_lock(task);

		did_unlock = true;
	}

	/*
	 * If a VM fault is in flight we must wait for it to resolve
	 * before we can return from task_restartable_ranges_synchronize(),
	 * as the memory we're faulting against might be freed by the caller
	 * as soon as it returns, leading a crash.
	 */
	if (state.trr_fault_state == TRR_FAULT_OBSERVED) {
		thread_rr_state_t nstate = {
			.trr_fault_state  = TRR_FAULT_OBSERVED,
			.trr_sync_waiting = 1,
		};

		if (os_atomic_cmpxchg(&thread->t_rr_state, state,
		    nstate, relaxed)) {
			lck_mtx_sleep_with_inheritor(&task->lock,
			    LCK_SLEEP_DEFAULT, &thread->t_rr_state,
			    thread, THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
			did_unlock = true;
		}
	}

#if MACH_ASSERT
	state.trr_value = os_atomic_load(&thread->t_rr_state.trr_value, relaxed);
	assert3u(state.trr_fault_state, !=, TRR_FAULT_OBSERVED);
	assert3u(state.trr_ipi_ack_pending, ==, 0);
	assert3u(state.trr_sync_waiting, ==, 0);
#endif

	thread_deallocate_safe(thread);
	return did_unlock;
}

bool
thread_reset_pcs_in_range(task_t task, thread_t thread)
{
	return _ranges_lookup(task->t_rr_ranges, machine_thread_pc(thread)) != 0;
}

void
thread_reset_pcs_ast(task_t task, thread_t thread)
{
	struct restartable_ranges *rr;
	mach_vm_address_t pc;

	/*
	 * Because restartable_ranges are set while the task only has on thread
	 * and can't be mutated outside of this, no lock is required to read this.
	 */
	rr = task->t_rr_ranges;
	if (thread->active && rr) {
		pc = _ranges_lookup(rr, machine_thread_pc(thread));

		if (pc) {
			machine_thread_reset_pc(thread, pc);
		}
	}

#if MACH_ASSERT
	thread_rr_state_t state;

	state.trr_value = os_atomic_load(&thread->t_rr_state.trr_value, relaxed);
	assert3u(state.trr_fault_state, ==, TRR_FAULT_NONE);
	assert3u(state.trr_sync_waiting, ==, 0);
#endif
}

void
restartable_init(void)
{
	for (size_t i = 0; i < RR_HASH_SIZE; i++) {
		queue_head_init(rr_hash[i]);
	}
}

#pragma mark MiG interfaces

kern_return_t
task_restartable_ranges_register(
	task_t                    task,
	task_restartable_range_t *ranges,
	mach_msg_type_number_t    count)
{
	kern_return_t kr;

	if (task != current_task()) {
		return KERN_FAILURE;
	}


	kr = _ranges_validate(task, ranges, count);

	if (kr == KERN_SUCCESS) {
		task_lock(task);

		if (task->thread_count > 1) {
			kr = KERN_NOT_SUPPORTED;
#if !DEBUG && !DEVELOPMENT
		} else if (task->t_rr_ranges) {
			/*
			 * For security reasons, on release kernels,
			 * only allow for this to be configured once.
			 *
			 * But to be able to test the feature we need
			 * to relax this for dev kernels.
			 */
			kr = KERN_NOT_SUPPORTED;
#endif
		} else {
			kr = _restartable_ranges_create(task, ranges, count,
			    &task->t_rr_ranges);
		}

		task_unlock(task);
	}

	return kr;
}

kern_return_t
task_restartable_ranges_synchronize(task_t task)
{
	thread_pri_floor_t token;
	thread_t thread;
	bool needs_wait = false;
	kern_return_t kr = KERN_SUCCESS;

	if (task != current_task()) {
		return KERN_FAILURE;
	}

	/*
	 * t_rr_ranges can only be set if the process is single threaded.
	 * As a result, `t_rr_ranges` can _always_ be looked at
	 * from current_thread() without holding a lock:
	 * - either because it's the only thread in the task
	 * - or because the existence of another thread precludes
	 *   modification
	 */
	if (!task->t_rr_ranges) {
		return KERN_SUCCESS;
	}

	/*
	 * When initiating a GC, artificially raise the priority for the
	 * duration of sending ASTs, we want to be preemptible, but this
	 * sequence has to terminate in a timely fashion.
	 */
	token = thread_priority_floor_start();

	task_lock(task);

	/*
	 * In order to avoid trivial deadlocks of 2 threads trying
	 * to wait on each other while in kernel, disallow
	 * concurrent usage of task_restartable_ranges_synchronize().
	 *
	 * At the time this code was written, the one client (Objective-C)
	 * does this under lock which guarantees ordering. If we ever need
	 * more clients, the library around restartable ranges will have
	 * to synchronize in userspace.
	 */
	if (task->task_rr_in_flight) {
		kr = KERN_ALREADY_WAITING;
		goto out;
	}

	task->task_rr_in_flight = true;

	/*
	 * Pair with the acquire barriers handling RR_TSTATE_ONCORE.
	 *
	 * For threads that weren't on core, we rely on the fact
	 * that we are taking their lock in act_set_ast_reset_pcs()
	 * and that the context switch path will also take it before
	 * resuming them which rovides the required ordering.
	 *
	 * For new threads not existing yet, because the task_lock()
	 * is taken to add them to the task thread list,
	 * which also synchronizes with this code.
	 */
	os_atomic_thread_fence(release);

	/*
	 * Set all the AST_RESET_PCS, and see if any thread needs
	 * actual acknowledgement.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread != current_thread()) {
			needs_wait |= act_set_ast_reset_pcs(task, thread);
		}
	}

	/*
	 * Now wait for acknowledgement if we need any
	 */
	while (needs_wait) {
		needs_wait = false;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread == current_thread()) {
				continue;
			}

			needs_wait = thread_rr_wait_if_needed(task, thread);
			if (needs_wait) {
				/*
				 * We drop the task lock,
				 * we need to restart enumerating threads.
				 */
				break;
			}
		}
	}

	task->task_rr_in_flight = false;

out:
	task_unlock(task);

	thread_priority_floor_end(&token);

	return kr;
}
