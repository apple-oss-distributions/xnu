/*
 * Copyright (c) 2003-2019 Apple Inc. All rights reserved.
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

#ifndef _KERN_LOCKS_H_
#define _KERN_LOCKS_H_

#include <sys/cdefs.h>

#ifdef  XNU_KERNEL_PRIVATE
#include <kern/startup.h>
#include <kern/percpu.h>
#endif /* XNU_KERNEL_PRIVATE */

__BEGIN_DECLS

#include <sys/appleapiopts.h>
#include <mach/boolean.h>
#include <kern/kern_types.h>
#include <kern/lock_group.h>
#include <machine/locks.h>
#ifdef KERNEL_PRIVATE
#include <kern/ticket_lock.h>
#endif
#include <kern/lock_types.h>
#include <kern/lock_attr.h>
#include <kern/lock_rw.h>

#define decl_lck_spin_data(class, name)     class lck_spin_t name

extern lck_spin_t      *lck_spin_alloc_init(
	lck_grp_t               *grp,
	lck_attr_t              *attr);

extern void             lck_spin_init(
	lck_spin_t              *lck,
	lck_grp_t               *grp,
	lck_attr_t              *attr);

extern void             lck_spin_lock(
	lck_spin_t              *lck);

extern void             lck_spin_lock_grp(
	lck_spin_t              *lck,
	lck_grp_t               *grp);

extern void             lck_spin_unlock(
	lck_spin_t              *lck);

extern void             lck_spin_destroy(
	lck_spin_t              *lck,
	lck_grp_t               *grp);

extern void             lck_spin_free(
	lck_spin_t              *lck,
	lck_grp_t               *grp);

extern wait_result_t    lck_spin_sleep(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible);

extern wait_result_t    lck_spin_sleep_grp(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	lck_grp_t               *grp);

extern wait_result_t    lck_spin_sleep_deadline(
	lck_spin_t              *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

#ifdef  KERNEL_PRIVATE

extern void             lck_spin_lock_nopreempt(
	lck_spin_t              *lck);

extern void             lck_spin_lock_nopreempt_grp(
	lck_spin_t              *lck, lck_grp_t *grp);

extern void             lck_spin_unlock_nopreempt(
	lck_spin_t              *lck);

extern boolean_t        lck_spin_try_lock_grp(
	lck_spin_t              *lck,
	lck_grp_t               *grp);

extern boolean_t        lck_spin_try_lock(
	lck_spin_t              *lck);

extern boolean_t        lck_spin_try_lock_nopreempt(
	lck_spin_t              *lck);

extern boolean_t        lck_spin_try_lock_nopreempt_grp(
	lck_spin_t              *lck,
	lck_grp_t               *grp);

/* NOT SAFE: To be used only by kernel debugger to avoid deadlock. */
extern boolean_t        kdp_lck_spin_is_acquired(
	lck_spin_t              *lck);

struct _lck_mtx_ext_;
extern void lck_mtx_init_ext(
	lck_mtx_t               *lck,
	struct _lck_mtx_ext_    *lck_ext,
	lck_grp_t               *grp,
	lck_attr_t              *attr);

#endif

#define decl_lck_mtx_data(class, name)     class lck_mtx_t name

extern lck_mtx_t        *lck_mtx_alloc_init(
	lck_grp_t               *grp,
	lck_attr_t              *attr);

extern void             lck_mtx_init(
	lck_mtx_t               *lck,
	lck_grp_t               *grp,
	lck_attr_t              *attr);
extern void             lck_mtx_lock(
	lck_mtx_t               *lck);

extern void             lck_mtx_unlock(
	lck_mtx_t               *lck);

extern void             lck_mtx_destroy(
	lck_mtx_t               *lck,
	lck_grp_t               *grp);

extern void             lck_mtx_free(
	lck_mtx_t               *lck,
	lck_grp_t               *grp);

extern wait_result_t    lck_mtx_sleep(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible);

extern wait_result_t    lck_mtx_sleep_deadline(
	lck_mtx_t               *lck,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

#ifdef KERNEL_PRIVATE
/*
 * Name: lck_spin_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_spin_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
extern wait_result_t lck_spin_sleep_with_inheritor(
	lck_spin_t              *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

/*
 * Name: lck_ticket_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_ticket_t lock used to protect the sleep.  The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: lck_grp_t associated with the lock.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK.
 *   Arg3: event to wait on.
 *   Arg5: thread to propagate the event push to.
 *   Arg6: interruptible flag for wait.
 *   Arg7: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
extern wait_result_t lck_ticket_sleep_with_inheritor(
	lck_ticket_t            *lock,
	lck_grp_t               *grp,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

/*
 * Name: lck_mtx_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK, LCK_SLEEP_SPIN, LCK_SLEEP_SPIN_ALWAYS.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
extern wait_result_t lck_mtx_sleep_with_inheritor(
	lck_mtx_t               *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

/*
 * Name: lck_mtx_sleep_with_inheritor
 *
 * Description: deschedule the current thread and wait on the waitq associated with event to be woken up.
 *              While waiting, the sched priority of the waiting thread will contribute to the push of the event that will
 *              be directed to the inheritor specified.
 *              An interruptible mode and deadline can be specified to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the sleep. The lock will be dropped while sleeping and reaquired before returning according to the sleep action specified.
 *   Arg2: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_SHARED, LCK_SLEEP_EXCLUSIVE.
 *   Arg3: event to wait on.
 *   Arg4: thread to propagate the event push to.
 *   Arg5: interruptible flag for wait.
 *   Arg6: deadline for wait.
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The inheritor specified cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *
 * Returns: result of the wait.
 */
extern wait_result_t lck_rw_sleep_with_inheritor(
	lck_rw_t                *lock,
	lck_sleep_action_t      lck_sleep_action,
	event_t                 event,
	thread_t                inheritor,
	wait_interrupt_t        interruptible,
	uint64_t                deadline);

/*
 * Name: wakeup_one_with_inheritor
 *
 * Description: wake up one waiter for event if any. The thread woken up will be the one with the higher sched priority waiting on event.
 *              The push for the event will be transferred from the last inheritor to the woken up thread.
 *
 * Args:
 *   Arg1: event to wake from.
 *   Arg2: wait result to pass to the woken up thread.
 *   Arg3: pointer for storing the thread wokenup.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: The new inheritor wokenup cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *             A reference for the wokenup thread is acquired.
 *             NOTE: this cannot be called from interrupt context.
 */
extern kern_return_t wakeup_one_with_inheritor(
	event_t                 event,
	wait_result_t           result,
	lck_wake_action_t       action,
	thread_t                *thread_wokenup);

/*
 * Name: wakeup_all_with_inheritor
 *
 * Description: wake up all waiters waiting for event. The old inheritor will lose the push.
 *
 * Args:
 *   Arg1: event to wake from.
 *   Arg2: wait result to pass to the woken up threads.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: NOTE: this cannot be called from interrupt context.
 */
extern kern_return_t wakeup_all_with_inheritor(
	event_t                 event,
	wait_result_t           result);

/*
 * Name: change_sleep_inheritor
 *
 * Description: Redirect the push of the waiting threads of event to the new inheritor specified.
 *
 * Args:
 *   Arg1: event to redirect the push.
 *   Arg2: new inheritor for event.
 *
 * Returns: KERN_NOT_WAITING if no threads were waiting, KERN_SUCCESS otherwise.
 *
 * Conditions: In case of success, the new inheritor cannot run in user space until another inheritor is specified for the event or a
 *             wakeup for the event is called.
 *             NOTE: this cannot be called from interrupt context.
 */
extern kern_return_t change_sleep_inheritor(
	event_t                 event,
	thread_t                inheritor);

/*
 * gate structure
 */
#if XNU_KERNEL_PRIVATE
typedef struct gate {
	uintptr_t         gt_data;                // thread holder, interlock bit and waiter bit
	struct turnstile *gt_turnstile;           // turnstile, protected by the interlock bit
	union {
		struct {
			uint32_t  gt_refs:16,             // refs using the gate, protected by interlock bit
			    gt_alloc:1,                   // gate was allocated with gate_alloc_init
			    gt_type:2,                    // type bits for validity
			    gt_flags_pad:13;              // unused
		};
		uint32_t  gt_flags;
	};
} gate_t;
#else
typedef struct gate {
	uintptr_t         opaque1;
	uintptr_t         opaque2;
	uint32_t          opaque3;
} gate_t;
#endif /* XNU_KERNEL_PRIVATE */

/*
 * Possible gate_wait_result_t values.
 */
__options_decl(gate_wait_result_t, unsigned int, {
	GATE_HANDOFF      = 0x00,         /* gate was handedoff to current thread */
	GATE_OPENED       = 0x01,         /* gate was opened */
	GATE_TIMED_OUT    = 0x02,         /* wait timedout */
	GATE_INTERRUPTED  = 0x03,         /* wait was interrupted */
});

/*
 * Gate flags used by gate_assert
 */
__options_decl(gate_assert_flags_t, unsigned int, {
	GATE_ASSERT_CLOSED = 0x00,         /* asserts the gate is currently closed */
	GATE_ASSERT_OPEN   = 0x01,         /* asserts the gate is currently open */
	GATE_ASSERT_HELD   = 0x02,         /* asserts the gate is closed and held by current_thread() */
});

/*
 * Gate flags used by gate_handoff
 */
__options_decl(gate_handoff_flags_t, unsigned int, {
	GATE_HANDOFF_DEFAULT            = 0x00,         /* a waiter must exist to handoff the gate */
	GATE_HANDOFF_OPEN_IF_NO_WAITERS = 0x1,         /* behave like a gate_open() if there are no waiters */
});

/*
 * Name: decl_lck_rw_gate_data
 *
 * Description: declares a gate variable with specified storage class.
 *              The gate itself will be stored in this variable and it is the caller's responsibility
 *              to ensure that this variable's memory is going to be accessible by all threads that will use
 *              the gate.
 *              Every gate function will require a pointer to this variable as parameter. The same pointer should
 *              be used in every thread.
 *
 *              The variable needs to be initialized once with lck_rw_gate_init() and destroyed once with
 *              lck_rw_gate_destroy() when not needed anymore.
 *
 *              The gate will be used in conjunction with a lck_rw_t.
 *
 * Args:
 *   Arg1: storage class.
 *   Arg2: variable name.
 */
#define decl_lck_rw_gate_data(class, name)                              class gate_t name

/*
 * Name: lck_rw_gate_init
 *
 * Description: initializes a variable declared with decl_lck_rw_gate_data.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
extern void lck_rw_gate_init(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_rw_gate_init().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 */
extern void lck_rw_gate_destroy(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
extern gate_t* lck_rw_gate_alloc_init(lck_rw_t *lock);

/*
 * Name: lck_rw_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *              with lck_rw_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_rw_gate_alloc_init().
 */
extern void lck_rw_gate_free(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_rw_gate_try_close() and lck_rw_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_rw_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_rw_gate_try_close() and lck_rw_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
extern kern_return_t lck_rw_gate_try_close(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
extern void lck_rw_gate_close(lck_rw_t *lock, gate_t *gate);


/*
 * Name: lck_rw_gate_open
 *
 * Description: Opens the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
extern void lck_rw_gate_open(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
extern kern_return_t lck_rw_gate_handoff(lck_rw_t *lock, gate_t *gate, gate_handoff_flags_t flags);

/*
 * Name: lck_rw_gate_steal
 *
 * Description: Set the current ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_rw_gate_open() or lck_rw_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
extern void lck_rw_gate_steal(lck_rw_t *lock, gate_t *gate);

/*
 * Name: lck_rw_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_SHARED, LCK_SLEEP_EXCLUSIVE, LCK_SLEEP_UNLOCK.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_rw_gate_open() or lck_rw_gate_handoff() needs to be called later on.
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
extern gate_wait_result_t lck_rw_gate_wait(lck_rw_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline);

/*
 * Name: lck_rw_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_rw_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_rw_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
extern void lck_rw_gate_assert(lck_rw_t *lock, gate_t *gate, gate_assert_flags_t flags);

/*
 * Name: decl_lck_mtx_gate_data
 *
 * Description: declares a gate variable with specified storage class.
 *              The gate itself will be stored in this variable and it is the caller's responsibility
 *              to ensure that this variable's memory is going to be accessible by all threads that will use
 *              the gate.
 *              Every gate function will require a pointer to this variable as parameter. The same pointer should
 *              be used in every thread.
 *
 *              The variable needs to be initialized once with lck_mtx_gate_init() and destroyed once with
 *              lck_mtx_gate_destroy() when not needed anymore.
 *
 *              The gate will be used in conjunction with a lck_mtx_t.
 *
 * Args:
 *   Arg1: storage class.
 *   Arg2: variable name.
 */
#define decl_lck_mtx_gate_data(class, name)                             class gate_t name

/*
 * Name: lck_mtx_gate_init
 *
 * Description: initializes a variable declared with decl_lck_mtx_gate_data.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
extern void lck_mtx_gate_init(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_destroy
 *
 * Description: destroys a variable previously initialized
 *              with lck_mtx_gate_init().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 */
extern void lck_mtx_gate_destroy(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_alloc_init
 *
 * Description: allocates and initializes a gate_t.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *
 * Returns:
 *         gate_t allocated.
 */
extern gate_t* lck_mtx_gate_alloc_init(lck_mtx_t *lock);

/*
 * Name: lck_mtx_gate_free
 *
 * Description: destroys and tries to free a gate previously allocated
 *	        with lck_mtx_gate_alloc_init().
 *              The gate free might be delegated to the last thread returning
 *              from the gate_wait().
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate obtained with lck_mtx_gate_alloc_init().
 */
extern void lck_mtx_gate_free(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_try_close
 *
 * Description: Tries to close the gate.
 *              In case of success the current thread will be set as
 *              the holder of the gate.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *
 * Returns:
 *          KERN_SUCCESS in case the gate was successfully closed. The current thread is the new holder
 *          of the gate.
 *          A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *          to wake up possible waiters on the gate before returning to userspace.
 *          If the intent is to conditionally probe the gate before waiting, the lock must not be dropped
 *          between the calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait().
 *
 *          KERN_FAILURE in case the gate was already closed. Will panic if the current thread was already the holder of the gate.
 *          lck_mtx_gate_wait() should be called instead if the intent is to unconditionally wait on this gate.
 *          The calls to lck_mtx_gate_try_close() and lck_mtx_gate_wait() should
 *          be done without dropping the lock that is protecting the gate in between.
 */
extern kern_return_t lck_mtx_gate_try_close(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_close
 *
 * Description: Closes the gate. The current thread will be set as
 *              the holder of the gate. Will panic if the gate is already closed.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be open.
 *
 */
extern void lck_mtx_gate_close(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_open
 *
 * Description: Opens of the gate and wakes up possible waiters.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 */
extern void lck_mtx_gate_open(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_handoff
 *
 * Description: Tries to transfer the ownership of the gate. The waiter with highest sched
 *              priority will be selected as the new holder of the gate, and woken up,
 *              with the gate remaining in the closed state throughout.
 *              If no waiters are present, the gate will be kept closed and KERN_NOT_WAITING
 *              will be returned.
 *              GATE_HANDOFF_OPEN_IF_NO_WAITERS flag can be used to specify if the gate should be opened in
 *              case no waiters were found.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags - GATE_HANDOFF_DEFAULT or GATE_HANDOFF_OPEN_IF_NO_WAITERS
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The current thread must be the holder of the gate.
 *
 * Returns:
 *          KERN_SUCCESS in case one of the waiters became the new holder.
 *          KERN_NOT_WAITING in case there were no waiters.
 *
 */
extern kern_return_t lck_mtx_gate_handoff(lck_mtx_t *lock, gate_t *gate, gate_handoff_flags_t flags);

/*
 * Name: lck_mtx_gate_steal
 *
 * Description: Steals the ownership of the gate. It sets the current thread as the
 *              new holder of the gate.
 *              A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *              to wake up possible waiters on the gate before returning to userspace.
 *              NOTE: the previous holder should not call lck_mtx_gate_open() or lck_mtx_gate_handoff()
 *              anymore.
 *
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *
 * Conditions: Lock must be held. Returns with the lock held.
 *             The gate must be closed and the current thread must not already be the holder.
 *
 */
extern void lck_mtx_gate_steal(lck_mtx_t *lock, gate_t *gate);

/*
 * Name: lck_mtx_gate_wait
 *
 * Description: Waits for the current thread to become the holder of the gate or for the
 *              gate to become open. An interruptible mode and deadline can be specified
 *              to return earlier from the wait.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: sleep action. LCK_SLEEP_DEFAULT, LCK_SLEEP_UNLOCK, LCK_SLEEP_SPIN, LCK_SLEEP_SPIN_ALWAYS.
 *   Arg3: interruptible flag for wait.
 *   Arg4: deadline
 *
 * Conditions: Lock must be held. Returns with the lock held according to the sleep action specified.
 *             Lock will be dropped while waiting.
 *             The gate must be closed.
 *
 * Returns: Reason why the thread was woken up.
 *          GATE_HANDOFF - the current thread was handed off the ownership of the gate.
 *                         A matching lck_mtx_gate_open() or lck_mtx_gate_handoff() needs to be called later on
 *                         to wake up possible waiters on the gate before returning to userspace.
 *          GATE_OPENED - the gate was opened by the holder.
 *          GATE_TIMED_OUT - the thread was woken up by a timeout.
 *          GATE_INTERRUPTED - the thread was interrupted while sleeping.
 */
extern gate_wait_result_t lck_mtx_gate_wait(lck_mtx_t *lock, gate_t *gate, lck_sleep_action_t lck_sleep_action, wait_interrupt_t interruptible, uint64_t deadline);

/*
 * Name: lck_mtx_gate_assert
 *
 * Description: asserts that the gate is in the specified state.
 *
 * Args:
 *   Arg1: lck_mtx_t lock used to protect the gate.
 *   Arg2: pointer to the gate data declared with decl_lck_mtx_gate_data.
 *   Arg3: flags to specified assert type.
 *         GATE_ASSERT_CLOSED - the gate is currently closed
 *         GATE_ASSERT_OPEN - the gate is currently opened
 *         GATE_ASSERT_HELD - the gate is currently closed and the current thread is the holder
 */
extern void lck_mtx_gate_assert(lck_mtx_t *lock, gate_t *gate, gate_assert_flags_t flags);


#endif //KERNEL_PRIVATE

#if DEVELOPMENT || DEBUG
#define FULL_CONTENDED 0
#define HALF_CONTENDED 1
#define MAX_CONDENDED  2

extern void             erase_all_test_mtx_stats(void);
extern int              get_test_mtx_stats_string(char* buffer, int buffer_size);
extern void             lck_mtx_test_init(void);
extern void             lck_mtx_test_lock(void);
extern void             lck_mtx_test_unlock(void);
extern int              lck_mtx_test_mtx_uncontended(int iter, char* buffer, int buffer_size);
extern int              lck_mtx_test_mtx_contended(int iter, char* buffer, int buffer_size, int type);
extern int              lck_mtx_test_mtx_uncontended_loop_time(int iter, char* buffer, int buffer_size);
extern int              lck_mtx_test_mtx_contended_loop_time(int iter, char* buffer, int buffer_size, int type);
#endif
#ifdef  KERNEL_PRIVATE

extern boolean_t        lck_mtx_try_lock(
	lck_mtx_t               *lck);

extern void             mutex_pause(uint32_t);

extern void             lck_mtx_yield(
	lck_mtx_t               *lck);

extern boolean_t        lck_mtx_try_lock_spin(
	lck_mtx_t               *lck);

extern void             lck_mtx_lock_spin(
	lck_mtx_t               *lck);

extern boolean_t        kdp_lck_mtx_lock_spin_is_acquired(
	lck_mtx_t               *lck);

extern void             lck_mtx_convert_spin(
	lck_mtx_t               *lck);

extern void             lck_mtx_lock_spin_always(
	lck_mtx_t               *lck);

extern boolean_t        lck_mtx_try_lock_spin_always(
	lck_mtx_t               *lck);

#define lck_mtx_unlock_always(l)        lck_mtx_unlock(l)

extern void             lck_spin_assert(
	lck_spin_t              *lck,
	unsigned                int    type);

#endif  /* KERNEL_PRIVATE */

extern void             lck_mtx_assert(
	lck_mtx_t               *lck,
	unsigned                int    type);

#if MACH_ASSERT
#define LCK_MTX_ASSERT(lck, type) lck_mtx_assert((lck),(type))
#define LCK_SPIN_ASSERT(lck, type) lck_spin_assert((lck),(type))
#else /* MACH_ASSERT */
#define LCK_MTX_ASSERT(lck, type)
#define LCK_SPIN_ASSERT(lck, type)
#endif /* MACH_ASSERT */

#if DEBUG
#define LCK_MTX_ASSERT_DEBUG(lck, type) lck_mtx_assert((lck),(type))
#define LCK_SPIN_ASSERT_DEBUG(lck, type) lck_spin_assert((lck),(type))
#else /* DEBUG */
#define LCK_MTX_ASSERT_DEBUG(lck, type)
#define LCK_SPIN_ASSERT_DEBUG(lck, type)
#endif /* DEBUG */

#define LCK_ASSERT_OWNED                1
#define LCK_ASSERT_NOTOWNED             2

#define LCK_MTX_ASSERT_OWNED    LCK_ASSERT_OWNED
#define LCK_MTX_ASSERT_NOTOWNED LCK_ASSERT_NOTOWNED

#ifdef  MACH_KERNEL_PRIVATE

typedef struct lck_spinlock_to_info {
	void     *lock;
#if DEBUG || DEVELOPMENT
	uintptr_t owner_thread_orig;
#endif /* DEBUG || DEVELOPMENT */
	uintptr_t owner_thread_cur;
	int       owner_cpu;
	uint32_t  extra;
} *lck_spinlock_to_info_t;

extern volatile lck_spinlock_to_info_t lck_spinlock_timeout_in_progress;
PERCPU_DECL(struct lck_spinlock_to_info, lck_spinlock_to_info);

extern void             lck_spinlock_timeout_set_orig_owner(
	uintptr_t owner);

extern lck_spinlock_to_info_t lck_spinlock_timeout_hit(
	void     *lck,
	uintptr_t owner);

struct turnstile;
extern void             lck_mtx_lock_wait(
	lck_mtx_t               *lck,
	thread_t                holder,
	struct turnstile        **ts);

extern int              lck_mtx_lock_acquire(
	lck_mtx_t               *lck,
	struct turnstile        *ts);

extern  boolean_t       lck_mtx_unlock_wakeup(
	lck_mtx_t               *lck,
	thread_t                holder);

extern boolean_t        lck_mtx_ilk_unlock(
	lck_mtx_t               *lck);

extern boolean_t        lck_mtx_ilk_try_lock(
	lck_mtx_t               *lck);

extern void lck_mtx_wakeup_adjust_pri(thread_t thread, integer_t priority);

#endif /* MACH_KERNEL_PRIVATE */
#if  XNU_KERNEL_PRIVATE

uintptr_t unslide_for_kdebug(void* object);

struct lck_attr_startup_spec {
	lck_attr_t              *lck_attr;
	uint32_t                lck_attr_set_flags;
	uint32_t                lck_attr_clear_flags;
};

struct lck_spin_startup_spec {
	lck_spin_t              *lck;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

struct lck_mtx_startup_spec {
	lck_mtx_t               *lck;
	struct _lck_mtx_ext_    *lck_ext;
	lck_grp_t               *lck_grp;
	lck_attr_t              *lck_attr;
};

extern void             lck_attr_startup_init(
	struct lck_attr_startup_spec *spec);

extern void             lck_spin_startup_init(
	struct lck_spin_startup_spec *spec);

extern void             lck_mtx_startup_init(
	struct lck_mtx_startup_spec *spec);

/*
 * Auto-initializing locks declarations
 * ------------------------------------
 *
 * Unless you need to configure your locks in very specific ways,
 * there is no point creating explicit lock attributes. For most
 * static locks, these declaration macros can be used:
 *
 * - LCK_SPIN_DECLARE for spinlocks,
 * - LCK_MTX_EARLY_DECLARE for mutexes initialized before memory
 *   allocations are possible,
 * - LCK_MTX_DECLARE for mutexes,
 *
 * For cases when some particular attributes need to be used,
 * these come in *_ATTR variants that take a variable declared with
 * LCK_ATTR_DECLARE as an argument.
 */
#define LCK_ATTR_DECLARE(var, set_flags, clear_flags) \
	SECURITY_READ_ONLY_LATE(lck_attr_t) var; \
	static __startup_data struct lck_attr_startup_spec \
	__startup_lck_attr_spec_ ## var = { &var, set_flags, clear_flags }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_SECOND, lck_attr_startup_init, \
	    &__startup_lck_attr_spec_ ## var)

#define LCK_SPIN_DECLARE_ATTR(var, grp, attr) \
	lck_spin_t var; \
	static __startup_data struct lck_spin_startup_spec \
	__startup_lck_spin_spec_ ## var = { &var, grp, attr }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_FOURTH, lck_spin_startup_init, \
	    &__startup_lck_spin_spec_ ## var)

#define LCK_SPIN_DECLARE(var, grp) \
	LCK_SPIN_DECLARE_ATTR(var, grp, LCK_ATTR_NULL)

#define LCK_MTX_DECLARE_ATTR(var, grp, attr) \
	lck_mtx_t var; \
	static __startup_data struct lck_mtx_startup_spec \
	__startup_lck_mtx_spec_ ## var = { &var, NULL, grp, attr }; \
	STARTUP_ARG(LOCKS, STARTUP_RANK_FIRST, lck_mtx_startup_init, \
	    &__startup_lck_mtx_spec_ ## var)

#define LCK_MTX_DECLARE(var, grp) \
	LCK_MTX_DECLARE_ATTR(var, grp, LCK_ATTR_NULL)

#define LCK_MTX_EARLY_DECLARE_ATTR(var, grp, attr) \
	lck_mtx_ext_t var ## _ext; \
	lck_mtx_t var; \
	static __startup_data struct lck_mtx_startup_spec \
	__startup_lck_mtx_spec_ ## var = { &var, &var ## _ext, grp, attr }; \
	STARTUP_ARG(LOCKS_EARLY, STARTUP_RANK_FOURTH, lck_mtx_startup_init, \
	    &__startup_lck_mtx_spec_ ## var)

#define LCK_MTX_EARLY_DECLARE(var, grp) \
	LCK_MTX_EARLY_DECLARE_ATTR(var, grp, LCK_ATTR_NULL)

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_LOCKS_H_ */
