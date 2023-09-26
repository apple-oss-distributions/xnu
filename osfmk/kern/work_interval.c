/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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


#include <sys/work_interval.h>

#include <kern/work_interval.h>

#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/machine.h>
#include <kern/thread_group.h>
#include <kern/ipc_kobject.h>
#include <kern/task.h>
#include <kern/coalition.h>
#include <kern/policy_internal.h>
#include <kern/mpsc_queue.h>
#include <kern/workload_config.h>
#include <kern/assert.h>

#include <mach/kern_return.h>
#include <mach/notify.h>
#include <os/refcnt.h>

#include <stdatomic.h>

/*
 * With the introduction of auto-join work intervals, it is possible
 * to change the work interval (and related thread group) of a thread in a
 * variety of contexts (thread termination, context switch, thread mode
 * change etc.). In order to clearly specify the policy expectation and
 * the locking behavior, all calls to thread_set_work_interval() pass
 * in a set of flags.
 */

__options_decl(thread_work_interval_options_t, uint32_t, {
	/* Change the work interval using the explicit join rules */
	THREAD_WI_EXPLICIT_JOIN_POLICY = 0x1,
	/* Change the work interval using the auto-join rules */
	THREAD_WI_AUTO_JOIN_POLICY     = 0x2,
	/* Caller already holds the thread lock */
	THREAD_WI_THREAD_LOCK_HELD     = 0x4,
	/* Caller does not hold the thread lock */
	THREAD_WI_THREAD_LOCK_NEEDED   = 0x8,
	/* Change the work interval from the context switch path (thread may not be running or on a runq) */
	THREAD_WI_THREAD_CTX_SWITCH    = 0x10,
});

static kern_return_t thread_set_work_interval(thread_t, struct work_interval *, thread_work_interval_options_t);
static void work_interval_port_no_senders(ipc_port_t, mach_port_mscount_t);

IPC_KOBJECT_DEFINE(IKOT_WORK_INTERVAL,
    .iko_op_stable     = true,
    .iko_op_no_senders = work_interval_port_no_senders);

#if CONFIG_SCHED_AUTO_JOIN
/* MPSC queue used to defer deallocate work intervals */
static struct mpsc_daemon_queue work_interval_deallocate_queue;

static void work_interval_deferred_release(struct work_interval *);

/*
 * Work Interval Auto-Join Status
 *
 * work_interval_auto_join_status_t represents the state of auto-join for a given work interval.
 * It packs the following information:
 * - A bit representing if a "finish" is deferred on the work interval
 * - Count of number of threads auto-joined to the work interval
 */
#define WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK    ((uint32_t)(1 << 31))
#define WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK    ((uint32_t)(WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK - 1))
#define WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MAX     WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK
typedef uint32_t work_interval_auto_join_status_t;

static inline bool __unused
work_interval_status_deferred_finish(work_interval_auto_join_status_t status)
{
	return (status & WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK) ? true : false;
}

static inline uint32_t __unused
work_interval_status_auto_join_count(work_interval_auto_join_status_t status)
{
	return (uint32_t)(status & WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MASK);
}

/*
 * struct work_interval_deferred_finish_state
 *
 * Contains the parameters of the finish operation which is being deferred.
 */
struct work_interval_deferred_finish_state {
	uint64_t instance_id;
	uint64_t start;
	uint64_t deadline;
	uint64_t complexity;
};

struct work_interval_auto_join_info {
	struct work_interval_deferred_finish_state deferred_finish_state;
	work_interval_auto_join_status_t _Atomic status;
};
#endif /* CONFIG_SCHED_AUTO_JOIN */

#if CONFIG_THREAD_GROUPS
/* Flags atomically set in wi_group_flags wi_group_flags */
#define WORK_INTERVAL_GROUP_FLAGS_THREAD_JOINED 0x1
#endif

/*
 * Work Interval struct
 *
 * This struct represents a thread group and/or work interval context
 * in a mechanism that is represented with a kobject.
 *
 * Every thread that has joined a WI has a +1 ref, and the port
 * has a +1 ref as well.
 *
 * TODO: groups need to have a 'is for WI' flag
 *      and they need a flag to create that says 'for WI'
 *      This would allow CLPC to avoid allocating WI support
 *      data unless it is needed
 *
 * TODO: Enforce not having more than one non-group joinable work
 *      interval per thread group.
 *      CLPC only wants to see one WI-notify callout per group.
 */
struct work_interval {
	uint64_t wi_id;
	struct os_refcnt wi_ref_count;
	uint32_t wi_create_flags;

	/* for debugging purposes only, does not hold a ref on port */
	ipc_port_t wi_port;

	/*
	 * holds uniqueid and version of creating process,
	 * used to permission-gate notify
	 * TODO: you'd think there would be a better way to do this
	 */
	uint64_t wi_creator_uniqueid;
	uint32_t wi_creator_pid;
	int wi_creator_pidversion;

	/* flags set by work_interval_set_workload_id and reflected onto
	 *  thread->th_work_interval_flags upon join */
	uint32_t wi_wlid_flags;

#if CONFIG_THREAD_GROUPS
	uint32_t wi_group_flags;
	struct thread_group *wi_group;  /* holds +1 ref on group */
#endif /* CONFIG_THREAD_GROUPS */

#if CONFIG_SCHED_AUTO_JOIN
	/* Information related to auto-join and deferred finish for work interval */
	struct work_interval_auto_join_info wi_auto_join_info;

	/*
	 * Since the deallocation of auto-join work intervals
	 * can happen in the scheduler when the last thread in
	 * the WI blocks and the thread lock is held, the deallocation
	 * might have to be done on a separate thread.
	 */
	struct mpsc_queue_chain   wi_deallocate_link;
#endif /* CONFIG_SCHED_AUTO_JOIN */

	/*
	 * Work interval class info - determines thread priority for threads
	 * with a work interval driven policy.
	 */
	wi_class_t wi_class;
	uint8_t wi_class_offset;

	struct recount_work_interval wi_recount;
};

/*
 * work_interval_telemetry_data_enabled()
 *
 * Helper routine to check if work interval has the collection of telemetry data enabled.
 */
static inline bool
work_interval_telemetry_data_enabled(struct work_interval *work_interval)
{
	return (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_ENABLE_TELEMETRY_DATA) != 0;
}

/*
 * work_interval_should_collect_telemetry_from_thread()
 *
 * Helper routine to determine whether any work interval telemetry should be collected
 * for a thread.
 */
static inline bool
work_interval_should_collect_telemetry_from_thread(thread_t thread)
{
	if (thread->th_work_interval == NULL) {
		return false;
	}
	return work_interval_telemetry_data_enabled(thread->th_work_interval);
}

/*
 * work_interval_get_recount_tracks()
 *
 * Returns the recount tracks associated with a work interval, or NULL
 * if the work interval is NULL or has telemetry disabled.
 */
inline struct recount_track *
work_interval_get_recount_tracks(struct work_interval *work_interval)
{
	if (work_interval != NULL && work_interval_telemetry_data_enabled(work_interval)) {
		return work_interval->wi_recount.rwi_current_instance;
	}
	return NULL;
}

#if CONFIG_SCHED_AUTO_JOIN

/*
 * work_interval_perform_deferred_finish()
 *
 * Perform a deferred finish for a work interval. The routine accepts the deferred_finish_state as an
 * argument rather than looking at the work_interval since the deferred finish can race with another
 * start-finish cycle. To address that, the caller ensures that it gets a consistent snapshot of the
 * deferred state before calling this routine. This allows the racing start-finish cycle to overwrite
 * the deferred state without issues.
 */
static inline void
work_interval_perform_deferred_finish(__unused struct work_interval_deferred_finish_state *deferred_finish_state,
    __unused struct work_interval *work_interval, __unused thread_t thread)
{

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_WI_DEFERRED_FINISH),
	    thread_tid(thread), thread_group_get_id(work_interval->wi_group));
}

/*
 * work_interval_auto_join_increment()
 *
 * Routine to increment auto-join counter when a new thread is auto-joined to
 * the work interval.
 */
static void
work_interval_auto_join_increment(struct work_interval *work_interval)
{
	struct work_interval_auto_join_info *join_info = &work_interval->wi_auto_join_info;
	__assert_only work_interval_auto_join_status_t old_status = os_atomic_add_orig(&join_info->status, 1, relaxed);
	assert(work_interval_status_auto_join_count(old_status) < WORK_INTERVAL_STATUS_AUTO_JOIN_COUNT_MAX);
}

/*
 * work_interval_auto_join_decrement()
 *
 * Routine to decrement the auto-join counter when a thread unjoins the work interval (due to
 * blocking or termination). If this was the last auto-joined thread in the work interval and
 * there was a deferred finish, performs the finish operation for the work interval.
 */
static void
work_interval_auto_join_decrement(struct work_interval *work_interval, thread_t thread)
{
	struct work_interval_auto_join_info *join_info = &work_interval->wi_auto_join_info;
	work_interval_auto_join_status_t old_status, new_status;
	struct work_interval_deferred_finish_state deferred_finish_state;
	bool perform_finish;

	/* Update the auto-join count for the work interval atomically */
	os_atomic_rmw_loop(&join_info->status, old_status, new_status, acquire, {
		perform_finish = false;
		new_status = old_status;
		assert(work_interval_status_auto_join_count(old_status) > 0);
		new_status -= 1;
		if (new_status == WORK_INTERVAL_STATUS_DEFERRED_FINISH_MASK) {
		        /* No auto-joined threads remaining and finish is deferred */
		        new_status = 0;
		        perform_finish = true;
		        /*
		         * Its important to copy the deferred finish state here so that this works
		         * when racing with another start-finish cycle.
		         */
		        deferred_finish_state = join_info->deferred_finish_state;
		}
	});

	if (perform_finish == true) {
		/*
		 * Since work_interval_perform_deferred_finish() calls down to
		 * the machine layer callout for finish which gets the thread
		 * group from the thread passed in here, it is important to
		 * make sure that the thread still has the work interval thread
		 * group here.
		 */
		assert(thread->thread_group == work_interval->wi_group);
		work_interval_perform_deferred_finish(&deferred_finish_state, work_interval, thread);
	}
}

/*
 * work_interval_auto_join_enabled()
 *
 * Helper routine to check if work interval has auto-join enabled.
 */
static inline bool
work_interval_auto_join_enabled(struct work_interval *work_interval)
{
	return (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) != 0;
}

/*
 * work_interval_deferred_finish_enabled()
 *
 * Helper routine to check if work interval has deferred finish enabled.
 */
static inline bool __unused
work_interval_deferred_finish_enabled(struct work_interval *work_interval)
{
	return (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH) != 0;
}

#endif /* CONFIG_SCHED_AUTO_JOIN */

static inline void
work_interval_retain(struct work_interval *work_interval)
{
	/*
	 * Even though wi_retain is called under a port lock, we have
	 * to use os_ref_retain instead of os_ref_retain_locked
	 * because wi_release is not synchronized. wi_release calls
	 * os_ref_release which is unsafe to pair with os_ref_retain_locked.
	 */
	os_ref_retain(&work_interval->wi_ref_count);
}

static inline void
work_interval_deallocate(struct work_interval *work_interval)
{
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_DESTROY),
	    work_interval->wi_id);
	if (work_interval_telemetry_data_enabled(work_interval)) {
		recount_work_interval_deinit(&work_interval->wi_recount);
	}
	kfree_type(struct work_interval, work_interval);
}

/*
 * work_interval_release()
 *
 * Routine to release a ref count on the work interval. If the refcount goes down
 * to zero, the work interval needs to be de-allocated.
 *
 * For non auto-join work intervals, they are de-allocated in this context.
 *
 * For auto-join work intervals, the de-allocation cannot be done from this context
 * since that might need the kernel memory allocator lock. In that case, the
 * deallocation is done via a thread-call based mpsc queue.
 */
static void
work_interval_release(struct work_interval *work_interval, __unused thread_work_interval_options_t options)
{
	if (os_ref_release(&work_interval->wi_ref_count) == 0) {
#if CONFIG_SCHED_AUTO_JOIN
		if (options & THREAD_WI_THREAD_LOCK_HELD) {
			work_interval_deferred_release(work_interval);
		} else {
			work_interval_deallocate(work_interval);
		}
#else /* CONFIG_SCHED_AUTO_JOIN */
		work_interval_deallocate(work_interval);
#endif /* CONFIG_SCHED_AUTO_JOIN */
	}
}

#if CONFIG_SCHED_AUTO_JOIN

/*
 * work_interval_deferred_release()
 *
 * Routine to enqueue the work interval on the deallocation mpsc queue.
 */
static void
work_interval_deferred_release(struct work_interval *work_interval)
{
	mpsc_daemon_enqueue(&work_interval_deallocate_queue,
	    &work_interval->wi_deallocate_link, MPSC_QUEUE_NONE);
}

/*
 * work_interval_should_propagate()
 *
 * Main policy routine to decide if a thread should be auto-joined to
 * another thread's work interval. The conditions are arranged such that
 * the most common bailout condition are checked the earliest. This routine
 * is called from the scheduler context; so it needs to be efficient and
 * be careful when taking locks or performing wakeups.
 */
inline bool
work_interval_should_propagate(thread_t cthread, thread_t thread)
{
	/* Only allow propagation if the current thread has a work interval and the woken up thread does not */
	if ((cthread->th_work_interval == NULL) || (thread->th_work_interval != NULL)) {
		return false;
	}

	/* Only propagate work intervals which have auto-join enabled */
	if (work_interval_auto_join_enabled(cthread->th_work_interval) == false) {
		return false;
	}

	/* Work interval propagation is enabled for realtime threads only */
	if ((cthread->sched_mode != TH_MODE_REALTIME) || (thread->sched_mode != TH_MODE_REALTIME)) {
		return false;
	}


	/* Work interval propagation only works for threads with the same home thread group */
	struct thread_group *thread_home_tg = thread_group_get_home_group(thread);
	if (thread_group_get_home_group(cthread) != thread_home_tg) {
		return false;
	}

	/* If woken up thread has adopted vouchers and other thread groups, it does not get propagation */
	if (thread->thread_group != thread_home_tg) {
		return false;
	}

	/* If either thread is inactive (in the termination path), do not propagate auto-join */
	if ((!cthread->active) || (!thread->active)) {
		return false;
	}

	return true;
}

/*
 * work_interval_auto_join_propagate()
 *
 * Routine to auto-join a thread into another thread's work interval
 *
 * Should only be invoked if work_interval_should_propagate() returns
 * true. Also expects "from" thread to be current thread and "to" thread
 * to be locked.
 */
void
work_interval_auto_join_propagate(thread_t from, thread_t to)
{
	assert(from == current_thread());
	work_interval_retain(from->th_work_interval);
	work_interval_auto_join_increment(from->th_work_interval);
	__assert_only kern_return_t kr = thread_set_work_interval(to, from->th_work_interval,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD | THREAD_WI_THREAD_CTX_SWITCH);
	assert(kr == KERN_SUCCESS);
}

/*
 * work_interval_auto_join_unwind()
 *
 * Routine to un-join an auto-joined work interval for a thread that is blocking.
 *
 * Expects thread to be locked.
 */
void
work_interval_auto_join_unwind(thread_t thread)
{
	__assert_only kern_return_t kr = thread_set_work_interval(thread, NULL,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD | THREAD_WI_THREAD_CTX_SWITCH);
	assert(kr == KERN_SUCCESS);
}

/*
 * work_interval_auto_join_demote()
 *
 * Routine to un-join an auto-joined work interval when a thread is changing from
 * realtime to non-realtime scheduling mode. This could happen due to multiple
 * reasons such as RT failsafe, thread backgrounding or thread termination. Also,
 * the thread being demoted may not be the current thread.
 *
 * Expects thread to be locked.
 */
void
work_interval_auto_join_demote(thread_t thread)
{
	__assert_only kern_return_t kr = thread_set_work_interval(thread, NULL,
	    THREAD_WI_AUTO_JOIN_POLICY | THREAD_WI_THREAD_LOCK_HELD);
	assert(kr == KERN_SUCCESS);
}

static void
work_interval_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq)
{
	struct work_interval *work_interval = NULL;
	work_interval = mpsc_queue_element(e, struct work_interval, wi_deallocate_link);
	assert(dq == &work_interval_deallocate_queue);
	assert(os_ref_get_count(&work_interval->wi_ref_count) == 0);
	work_interval_deallocate(work_interval);
}

#endif /* CONFIG_SCHED_AUTO_JOIN */

#if CONFIG_SCHED_AUTO_JOIN
__startup_func
static void
work_interval_subsystem_init(void)
{
	/*
	 * The work interval deallocation queue must be a thread call based queue
	 * because it is woken up from contexts where the thread lock is held. The
	 * only way to perform wakeups safely in those contexts is to wakeup a
	 * thread call which is guaranteed to be on a different waitq and would
	 * not hash onto the same global waitq which might be currently locked.
	 */
	mpsc_daemon_queue_init_with_thread_call(&work_interval_deallocate_queue,
	    work_interval_deallocate_queue_invoke, THREAD_CALL_PRIORITY_KERNEL,
	    MPSC_DAEMON_INIT_NONE);
}
STARTUP(THREAD_CALL, STARTUP_RANK_MIDDLE, work_interval_subsystem_init);
#endif /* CONFIG_SCHED_AUTO_JOIN */

/*
 * work_interval_port_convert
 *
 * Called with port locked, returns reference to work interval
 * if indeed the port is a work interval kobject port
 */
static struct work_interval *
work_interval_port_convert_locked(ipc_port_t port)
{
	struct work_interval *work_interval = NULL;

	if (IP_VALID(port)) {
		work_interval = ipc_kobject_get_stable(port, IKOT_WORK_INTERVAL);
		if (work_interval) {
			work_interval_retain(work_interval);
		}
	}

	return work_interval;
}

/*
 * port_name_to_work_interval
 *
 * Description: Obtain a reference to the work_interval associated with a given port.
 *
 * Parameters:  name    A Mach port name to translate.
 *
 * Returns:     NULL    The given Mach port did not reference a work_interval.
 *              !NULL   The work_interval that is associated with the Mach port.
 */
static kern_return_t
port_name_to_work_interval(mach_port_name_t     name,
    struct work_interval **work_interval)
{
	if (!MACH_PORT_VALID(name)) {
		return KERN_INVALID_NAME;
	}

	ipc_port_t port = IP_NULL;
	kern_return_t kr = KERN_SUCCESS;

	kr = ipc_port_translate_send(current_space(), name, &port);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* port is locked */

	assert(IP_VALID(port));

	struct work_interval *converted_work_interval;

	converted_work_interval = work_interval_port_convert_locked(port);

	/* the port is valid, but doesn't denote a work_interval */
	if (converted_work_interval == NULL) {
		kr = KERN_INVALID_CAPABILITY;
	}

	ip_mq_unlock(port);

	if (kr == KERN_SUCCESS) {
		*work_interval = converted_work_interval;
	}

	return kr;
}


/*
 * work_interval_port_no_senders
 *
 * Description: Handle a no-senders notification for a work interval port.
 *              Destroys the port and releases its reference on the work interval.
 *
 * Parameters:  msg     A Mach no-senders notification message.
 *
 * Note: This assumes that there is only one create-right-from-work-interval point,
 *       if the ability to extract another send right after creation is added,
 *       this will have to change to handle make-send counts correctly.
 */
static void
work_interval_port_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	struct work_interval *work_interval = NULL;

	work_interval = ipc_kobject_dealloc_port(port, mscount,
	    IKOT_WORK_INTERVAL);

	work_interval->wi_port = MACH_PORT_NULL;

	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
}

/*
 * work_interval_port_type()
 *
 * Converts a port name into the work interval object and returns its type.
 *
 * For invalid ports, it returns WORK_INTERVAL_TYPE_LAST (which is not a
 * valid type for work intervals).
 */
static uint32_t
work_interval_port_type(mach_port_name_t port_name)
{
	struct work_interval *work_interval = NULL;
	kern_return_t kr;
	uint32_t work_interval_type;

	if (port_name == MACH_PORT_NULL) {
		return WORK_INTERVAL_TYPE_LAST;
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return WORK_INTERVAL_TYPE_LAST;
	}
	/* work_interval has a +1 ref */

	assert(work_interval != NULL);
	work_interval_type = work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK;
	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
	return work_interval_type;
}

/*
 * Sparse - not all work interval classes imply a scheduling policy change.
 * The REALTIME_CRITICAL class *also* requires the thread to have explicitly
 * adopted the REALTIME sched mode to take effect.
 */
static const struct {
	int          priority;
	sched_mode_t sched_mode;
} work_interval_class_data[WI_CLASS_COUNT] = {
	[WI_CLASS_BEST_EFFORT] = {
		BASEPRI_DEFAULT,        // 31
		TH_MODE_TIMESHARE,
	},

	[WI_CLASS_APP_SUPPORT] = {
		BASEPRI_DEFAULT,        // 31
		TH_MODE_TIMESHARE,
	},

	[WI_CLASS_SYSTEM] = {
		BASEPRI_FOREGROUND + 1, // 48
		TH_MODE_FIXED,
	},

	[WI_CLASS_SYSTEM_CRITICAL] = {
		MAXPRI_USER + 1,        // 64
		TH_MODE_FIXED,
	},

	[WI_CLASS_REALTIME_CRITICAL] = {
		BASEPRI_RTQUEUES + 1,   // 98
		TH_MODE_REALTIME,
	},
};

/*
 * Called when a thread gets its scheduling priority from its associated work
 * interval.
 */
int
work_interval_get_priority(thread_t thread)
{
	const struct work_interval *work_interval = thread->th_work_interval;
	assert(work_interval != NULL);

	assert3u(work_interval->wi_class, !=, WI_CLASS_NONE);
	assert3u(work_interval->wi_class, <, WI_CLASS_COUNT);
	int priority = work_interval_class_data[work_interval->wi_class].priority;
	assert(priority != 0);

	priority += work_interval->wi_class_offset;
	assert3u(priority, <=, MAXPRI);

	return priority;
}

/*
 * Switch to a policy driven by the work interval (if applicable).
 */
static void
work_interval_set_policy(thread_t thread)
{
	assert3p(thread, ==, current_thread());

	/*
	 * Ignore policy changes if the workload context shouldn't affect the
	 * scheduling policy.
	 */
	workload_config_flags_t flags = WLC_F_NONE;

	/* There may be no config at all. That's ok. */
	if (workload_config_get_flags(&flags) != KERN_SUCCESS ||
	    (flags & WLC_F_THREAD_POLICY) == 0) {
		return;
	}

	const struct work_interval *work_interval = thread->th_work_interval;
	assert(work_interval != NULL);

	assert3u(work_interval->wi_class, <, WI_CLASS_COUNT);
	const sched_mode_t mode = work_interval_class_data[work_interval->wi_class].sched_mode;

	/*
	 * A mode of TH_MODE_NONE implies that this work interval has no
	 * associated scheduler effects.
	 */
	if (mode == TH_MODE_NONE) {
		return;
	}

	proc_set_thread_policy_ext(thread, TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_WI_DRIVEN, true, mode);
	assert(thread->requested_policy.thrp_wi_driven);

	return;
}

/*
 * Clear a work interval driven policy.
 */
static void
work_interval_clear_policy(thread_t thread)
{
	assert3p(thread, ==, current_thread());

	if (!thread->requested_policy.thrp_wi_driven) {
		return;
	}

	const sched_mode_t mode = sched_get_thread_mode_user(thread);

	proc_set_thread_policy_ext(thread, TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_WI_DRIVEN, false,
	    mode == TH_MODE_REALTIME ? mode : TH_MODE_TIMESHARE);

	assert(!thread->requested_policy.thrp_wi_driven);

	return;
}

/*
 * thread_set_work_interval()
 *
 * Change thread's bound work interval to the passed-in work interval
 * Consumes +1 ref on work_interval upon success.
 *
 * May also pass NULL to un-set work_interval on the thread
 * Will deallocate any old work interval on the thread
 * Return error if thread does not satisfy requirements to join work interval
 *
 * For non auto-join work intervals, deallocate any old work interval on the thread
 * For auto-join work intervals, the routine may wakeup the work interval deferred
 * deallocation queue since thread locks might be currently held.
 */
static kern_return_t
thread_set_work_interval(thread_t thread,
    struct work_interval *work_interval, thread_work_interval_options_t options)
{
	/* All explicit work interval operations should always be from the current thread */
	if (options & THREAD_WI_EXPLICIT_JOIN_POLICY) {
		assert(thread == current_thread());
	}

	/* All cases of needing the thread lock should be from explicit join scenarios */
	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		assert((options & THREAD_WI_EXPLICIT_JOIN_POLICY) != 0);
	}

	/* For all cases of auto join must come in with the thread lock held */
	if (options & THREAD_WI_AUTO_JOIN_POLICY) {
		assert((options & THREAD_WI_THREAD_LOCK_HELD) != 0);
	}

#if CONFIG_THREAD_GROUPS
	if (work_interval && !work_interval->wi_group) {
		/* Reject join on work intervals with deferred thread group creation */
		return KERN_INVALID_ARGUMENT;
	}
#endif /* CONFIG_THREAD_GROUPS */

	if (work_interval) {
		uint32_t work_interval_type = work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK;

		if (options & THREAD_WI_EXPLICIT_JOIN_POLICY) {
			/* Ensure no kern_work_interval_set_workload_id can happen after this point */
			uint32_t wlid_flags;
			(void)os_atomic_cmpxchgv(&work_interval->wi_wlid_flags, 0,
			    WORK_INTERVAL_WORKLOAD_ID_ALREADY_JOINED, &wlid_flags, relaxed);
			if (wlid_flags & WORK_INTERVAL_WORKLOAD_ID_RT_ALLOWED) {
				/* For workload IDs with rt-allowed, neuter the check below to
				 * enable joining before the thread has become realtime for all
				 * work interval types */
				work_interval_type = WORK_INTERVAL_TYPE_DEFAULT;
			}
		}

		if ((work_interval_type == WORK_INTERVAL_TYPE_COREAUDIO) &&
		    (thread->sched_mode != TH_MODE_REALTIME) && (thread->saved_mode != TH_MODE_REALTIME)) {
			return KERN_INVALID_ARGUMENT;
		}
	}

	/*
	 * Ensure a work interval scheduling policy is not used if the thread is
	 * leaving the work interval.
	 */
	if (work_interval == NULL &&
	    (options & THREAD_WI_EXPLICIT_JOIN_POLICY) != 0) {
		work_interval_clear_policy(thread);
	}

	struct work_interval *old_th_wi = thread->th_work_interval;
#if CONFIG_SCHED_AUTO_JOIN
	spl_t s;
	/* Take the thread lock if needed */
	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		s = splsched();
		thread_lock(thread);
	}

	/*
	 * Work interval auto-join leak to non-RT threads.
	 *
	 * If thread might be running on a remote core and it's not in the context switch path (where
	 * thread is neither running, blocked or in the runq), its not possible to update the
	 * work interval & thread group remotely since its not possible to update CLPC for a remote
	 * core. This situation might happen when a thread is transitioning from realtime to
	 * non-realtime due to backgrounding etc., which would mean that non-RT threads would now
	 * be part of the work interval.
	 *
	 * Since there is no immediate mitigation to this issue, the policy is to set a new
	 * flag on the thread which indicates that such a "leak" has happened. This flag will
	 * be cleared when the remote thread eventually blocks and unjoins from the work interval.
	 */
	bool thread_on_remote_core = ((thread != current_thread()) && (thread->state & TH_RUN) && (thread->runq == PROCESSOR_NULL));

	if (thread_on_remote_core && ((options & THREAD_WI_THREAD_CTX_SWITCH) == 0)) {
		assert((options & THREAD_WI_THREAD_LOCK_NEEDED) == 0);
		os_atomic_or(&thread->th_work_interval_flags, TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK, relaxed);
		return KERN_SUCCESS;
	}

	const bool old_wi_auto_joined = ((thread->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN) != 0);

	if ((options & THREAD_WI_AUTO_JOIN_POLICY) || old_wi_auto_joined) {
		__kdebug_only uint64_t old_tg_id = (old_th_wi && old_th_wi->wi_group) ? thread_group_get_id(old_th_wi->wi_group) : ~0;
		__kdebug_only uint64_t new_tg_id = (work_interval && work_interval->wi_group) ? thread_group_get_id(work_interval->wi_group) : ~0;
		KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SCHED_WI_AUTO_JOIN),
		    thread_tid(thread), old_tg_id, new_tg_id, options);
	}

	if (old_wi_auto_joined) {
		/*
		 * If thread was auto-joined to a work interval and is not realtime, make sure it
		 * happened due to the "leak" described above.
		 */
		if (thread->sched_mode != TH_MODE_REALTIME) {
			assert((thread->th_work_interval_flags & TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK) != 0);
		}

		os_atomic_andnot(&thread->th_work_interval_flags, TH_WORK_INTERVAL_FLAGS_AUTO_JOIN_LEAK, relaxed);
		work_interval_auto_join_decrement(old_th_wi, thread);
		thread->sched_flags &= ~TH_SFLAG_THREAD_GROUP_AUTO_JOIN;
	}

#endif /* CONFIG_SCHED_AUTO_JOIN */

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_CHANGE),
	    thread_tid(thread), (old_th_wi ? old_th_wi->wi_id : 0), (work_interval ? work_interval->wi_id : 0), !!(options & THREAD_WI_AUTO_JOIN_POLICY));

	/* transfer +1 ref to thread */
	thread->th_work_interval = work_interval;

#if CONFIG_SCHED_AUTO_JOIN

	if ((options & THREAD_WI_AUTO_JOIN_POLICY) && work_interval) {
		assert(work_interval_auto_join_enabled(work_interval) == true);
		thread->sched_flags |= TH_SFLAG_THREAD_GROUP_AUTO_JOIN;
	}

	if (options & THREAD_WI_THREAD_LOCK_NEEDED) {
		thread_unlock(thread);
		splx(s);
	}
#endif /* CONFIG_SCHED_AUTO_JOIN */

	/*
	 * The thread got a new work interval. It may come with a work interval
	 * scheduling policy that needs to be applied.
	 */
	if (work_interval != NULL &&
	    (options & THREAD_WI_EXPLICIT_JOIN_POLICY) != 0) {
		work_interval_set_policy(thread);
	}

#if CONFIG_THREAD_GROUPS
	if (work_interval) {
		/* Prevent thread_group_set_name after CLPC may have already heard
		 * about the thread group */
		(void)os_atomic_cmpxchg(&work_interval->wi_group_flags, 0,
		    WORK_INTERVAL_GROUP_FLAGS_THREAD_JOINED, relaxed);
	}
	struct thread_group *new_tg = (work_interval) ? (work_interval->wi_group) : NULL;

	if (options & THREAD_WI_AUTO_JOIN_POLICY) {
#if CONFIG_SCHED_AUTO_JOIN
		thread_set_autojoin_thread_group_locked(thread, new_tg);
#endif
	} else {
		thread_set_work_interval_thread_group(thread, new_tg);
	}
#endif /* CONFIG_THREAD_GROUPS */

	if (options & THREAD_WI_EXPLICIT_JOIN_POLICY) {
		/* Construct mask to XOR with th_work_interval_flags to clear the
		* currently present flags and set the new flags in wlid_flags. */
		uint32_t wlid_flags = 0;
		if (work_interval) {
			wlid_flags = os_atomic_load(&work_interval->wi_wlid_flags, relaxed);
		}
		thread_work_interval_flags_t th_wi_xor_mask = os_atomic_load(
			&thread->th_work_interval_flags, relaxed);
		th_wi_xor_mask &= (TH_WORK_INTERVAL_FLAGS_HAS_WORKLOAD_ID |
		    TH_WORK_INTERVAL_FLAGS_RT_ALLOWED);
		if (wlid_flags & WORK_INTERVAL_WORKLOAD_ID_HAS_ID) {
			th_wi_xor_mask ^= TH_WORK_INTERVAL_FLAGS_HAS_WORKLOAD_ID;
			if (wlid_flags & WORK_INTERVAL_WORKLOAD_ID_RT_ALLOWED) {
				th_wi_xor_mask ^= TH_WORK_INTERVAL_FLAGS_RT_ALLOWED;
			}
		}
		if (th_wi_xor_mask) {
			os_atomic_xor(&thread->th_work_interval_flags, th_wi_xor_mask, relaxed);
		}

		/*
		 * Now that the interval flags have been set, re-evaluate
		 * whether the thread needs to be undemoted - the new work
		 * interval may have the RT_ALLOWED flag. and the thread may
		 * have have a realtime policy but be demoted.
		 */
		thread_rt_evaluate(thread);
	}

	if (old_th_wi != NULL) {
		work_interval_release(old_th_wi, options);
	}

	return KERN_SUCCESS;
}

static kern_return_t
thread_set_work_interval_explicit_join(thread_t thread, struct work_interval *work_interval)
{
	assert(thread == current_thread());
	return thread_set_work_interval(thread, work_interval, THREAD_WI_EXPLICIT_JOIN_POLICY | THREAD_WI_THREAD_LOCK_NEEDED);
}

kern_return_t
work_interval_thread_terminate(thread_t thread)
{
	assert(thread == current_thread());
	if (thread->th_work_interval != NULL) {
		return thread_set_work_interval(thread, NULL, THREAD_WI_EXPLICIT_JOIN_POLICY | THREAD_WI_THREAD_LOCK_NEEDED);
	}
	return KERN_SUCCESS;
}

kern_return_t
kern_work_interval_notify(thread_t thread, struct kern_work_interval_args* kwi_args)
{
	assert(thread == current_thread());
	assert(kwi_args->work_interval_id != 0);

	struct work_interval *work_interval = thread->th_work_interval;

	if (work_interval == NULL ||
	    work_interval->wi_id != kwi_args->work_interval_id) {
		/* This thread must have adopted the work interval to be able to notify */
		return KERN_INVALID_ARGUMENT;
	}

	task_t notifying_task = current_task();

	if (work_interval->wi_creator_uniqueid != get_task_uniqueid(notifying_task) ||
	    work_interval->wi_creator_pidversion != get_task_version(notifying_task)) {
		/* Only the creating task can do a notify */
		return KERN_INVALID_ARGUMENT;
	}

	spl_t s = splsched();

#if CONFIG_THREAD_GROUPS
	assert(work_interval->wi_group == thread->thread_group);
#endif /* CONFIG_THREAD_GROUPS */

	uint64_t urgency_param1, urgency_param2;
	kwi_args->urgency = (uint16_t)thread_get_urgency(thread, &urgency_param1, &urgency_param2);

	splx(s);

	/* called without interrupts disabled */
	machine_work_interval_notify(thread, kwi_args);

	return KERN_SUCCESS;
}

/* Start at 1, 0 is not a valid work interval ID */
static _Atomic uint64_t unique_work_interval_id = 1;

kern_return_t
kern_work_interval_create(thread_t thread,
    struct kern_work_interval_create_args *create_params)
{
	assert(thread == current_thread());

	uint32_t create_flags = create_params->wica_create_flags;

	if (((create_flags & WORK_INTERVAL_FLAG_JOINABLE) == 0) &&
	    thread->th_work_interval != NULL) {
		/*
		 * If the thread is doing a legacy combined create and join,
		 * it shouldn't already be part of a work interval.
		 *
		 * (Creating a joinable WI is allowed anytime.)
		 */
		return KERN_FAILURE;
	}

	/*
	 * Check the validity of the create flags before allocating the work
	 * interval.
	 */
	task_t creating_task = current_task();
	if ((create_flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_CA_CLIENT) {
		/*
		 * CA_CLIENT work intervals do not create new thread groups.
		 * There can only be one CA_CLIENT work interval (created by UIKit or AppKit)
		 * per each application task
		 */
		if (create_flags & WORK_INTERVAL_FLAG_GROUP) {
			return KERN_FAILURE;
		}
		if (!task_is_app(creating_task)) {
#if XNU_TARGET_OS_OSX
			/*
			 * Soft-fail the case of a non-app pretending to be an
			 * app, by allowing it to press the buttons, but they're
			 * not actually connected to anything.
			 */
			create_flags |= WORK_INTERVAL_FLAG_IGNORED;
#else
			/*
			 * On iOS, it's a hard failure to get your apptype
			 * wrong and then try to render something.
			 */
			return KERN_NOT_SUPPORTED;
#endif /* XNU_TARGET_OS_OSX */
		}
		if (task_set_ca_client_wi(creating_task, true) == false) {
			return KERN_FAILURE;
		}
	}

#if CONFIG_SCHED_AUTO_JOIN
	if (create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) {
		uint32_t type = (create_flags & WORK_INTERVAL_TYPE_MASK);
		if (type != WORK_INTERVAL_TYPE_COREAUDIO) {
			return KERN_NOT_SUPPORTED;
		}
		if ((create_flags & WORK_INTERVAL_FLAG_GROUP) == 0) {
			return KERN_NOT_SUPPORTED;
		}
	}

	if (create_flags & WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH) {
		if ((create_flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN) == 0) {
			return KERN_NOT_SUPPORTED;
		}
	}
#endif /* CONFIG_SCHED_AUTO_JOIN */

	struct work_interval *work_interval = kalloc_type(struct work_interval,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	uint64_t work_interval_id = os_atomic_inc(&unique_work_interval_id, relaxed);

	*work_interval = (struct work_interval) {
		.wi_id                  = work_interval_id,
		.wi_ref_count           = {},
		.wi_create_flags        = create_flags,
		.wi_creator_pid         = pid_from_task(creating_task),
		.wi_creator_uniqueid    = get_task_uniqueid(creating_task),
		.wi_creator_pidversion  = get_task_version(creating_task),
	};
	os_ref_init(&work_interval->wi_ref_count, NULL);

	if (work_interval_telemetry_data_enabled(work_interval)) {
		recount_work_interval_init(&work_interval->wi_recount);
	}

	__kdebug_only uint64_t tg_id = 0;
#if CONFIG_THREAD_GROUPS
	struct thread_group *tg;
	if ((create_flags &
	    (WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID)) ==
	    (WORK_INTERVAL_FLAG_GROUP | WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID)) {
		/* defer creation of the thread group until the
		 * kern_work_interval_set_workload_id() call */
		work_interval->wi_group = NULL;
	} else if (create_flags & WORK_INTERVAL_FLAG_GROUP) {
		/* create a new group for the interval to represent */
		char name[THREAD_GROUP_MAXNAME] = "";

		snprintf(name, sizeof(name), "WI%lld (pid %d)", work_interval_id,
		    work_interval->wi_creator_pid);

		tg = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);

		thread_group_set_name(tg, name);

		work_interval->wi_group = tg;
	} else {
		/* the interval represents the thread's home group */
		tg = thread_group_get_home_group(thread);

		thread_group_retain(tg);

		work_interval->wi_group = tg;
	}

	/* Capture the tg_id for tracing purposes */
	tg_id = work_interval->wi_group ? thread_group_get_id(work_interval->wi_group) : ~0;

#endif /* CONFIG_THREAD_GROUPS */

	if (create_flags & WORK_INTERVAL_FLAG_JOINABLE) {
		mach_port_name_t name = MACH_PORT_NULL;

		/* work_interval has a +1 ref, moves to the port */
		work_interval->wi_port = ipc_kobject_alloc_port(
			(ipc_kobject_t)work_interval, IKOT_WORK_INTERVAL,
			IPC_KOBJECT_ALLOC_MAKE_SEND | IPC_KOBJECT_ALLOC_NSREQUEST);


		name = ipc_port_copyout_send(work_interval->wi_port, current_space());

		if (!MACH_PORT_VALID(name)) {
			/*
			 * copyout failed (port is already deallocated)
			 * Because of the port-destroyed magic,
			 * the work interval is already deallocated too.
			 */
			return KERN_RESOURCE_SHORTAGE;
		}

		create_params->wica_port = name;
	} else {
		/* work_interval has a +1 ref, moves to the thread */
		kern_return_t kr = thread_set_work_interval_explicit_join(thread, work_interval);
		if (kr != KERN_SUCCESS) {
			/* No other thread can join this work interval since it isn't
			 * JOINABLE so release the reference on work interval */
			work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
			return kr;
		}

		create_params->wica_port = MACH_PORT_NULL;
	}

	create_params->wica_id = work_interval_id;

	if (tg_id != ~0) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_CREATE),
		    work_interval_id, create_flags, pid_from_task(creating_task), tg_id);
	}
	return KERN_SUCCESS;
}

kern_return_t
kern_work_interval_get_flags_from_port(mach_port_name_t port_name, uint32_t *flags)
{
	assert(flags != NULL);

	kern_return_t kr;
	struct work_interval *work_interval;

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	assert(work_interval != NULL);
	*flags = work_interval->wi_create_flags;

	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);

	return KERN_SUCCESS;
}

#if CONFIG_THREAD_GROUPS
_Static_assert(WORK_INTERVAL_NAME_MAX == THREAD_GROUP_MAXNAME,
    "WORK_INTERVAL_NAME_MAX does not match THREAD_GROUP_MAXNAME");
#endif /* CONFIG_THREAD_GROUPS */

kern_return_t
kern_work_interval_set_name(mach_port_name_t port_name, __unused char *name,
    size_t len)
{
	kern_return_t kr;
	struct work_interval *work_interval;

	if (len > WORK_INTERVAL_NAME_MAX) {
		return KERN_INVALID_ARGUMENT;
	}
	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	assert(work_interval != NULL);

#if CONFIG_THREAD_GROUPS
	uint32_t wi_group_flags = os_atomic_load(
		&work_interval->wi_group_flags, relaxed);
	if (wi_group_flags & WORK_INTERVAL_GROUP_FLAGS_THREAD_JOINED) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}
	if (!work_interval->wi_group) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	if (name[0] && (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_GROUP)) {
		char tgname[THREAD_GROUP_MAXNAME];
		snprintf(tgname, sizeof(tgname), "WI%lld %s", work_interval->wi_id,
		    name);
		thread_group_set_name(work_interval->wi_group, tgname);
	}

out:
#endif /* CONFIG_THREAD_GROUPS */
	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);

	return kr;
}

kern_return_t
kern_work_interval_set_workload_id(mach_port_name_t port_name,
    struct kern_work_interval_workload_id_args *workload_id_args)
{
	kern_return_t kr;
	struct work_interval *work_interval;
	uint32_t wlida_flags = 0;
	uint32_t wlid_flags = 0;
#if CONFIG_THREAD_GROUPS
	uint32_t tg_flags = 0;
#endif
	bool from_workload_config = false;

	/* Ensure workload ID name is non-empty. */
	if (!workload_id_args->wlida_name[0]) {
		return KERN_INVALID_ARGUMENT;
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	assert(work_interval != NULL);
	if (!(work_interval->wi_create_flags & WORK_INTERVAL_FLAG_JOINABLE)) {
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	if (!(work_interval->wi_create_flags & WORK_INTERVAL_FLAG_HAS_WORKLOAD_ID)) {
		/* Reject work intervals that didn't indicate they will have a workload ID
		 * at creation. In particular if the work interval has its own thread group,
		 * its creation must have been deferred in kern_work_interval_create */
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	workload_config_t wl_config = {};
	kr = workload_config_lookup_default(workload_id_args->wlida_name, &wl_config);
	if (kr == KERN_SUCCESS) {
		if ((wl_config.wc_create_flags & WORK_INTERVAL_TYPE_MASK) !=
		    (work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK)) {
			if ((wl_config.wc_create_flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_CA_RENDER_SERVER &&
			    (work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_FRAME_COMPOSITOR) {
				/* WORK_INTERVAL_TYPE_FRAME_COMPOSITOR is a valid related type of WORK_INTERVAL_TYPE_CA_RENDER_SERVER */
			} else {
				kr = KERN_INVALID_ARGUMENT;
				goto out;
			}
		}

		wlida_flags = wl_config.wc_flags;

		wlida_flags &= ~WORK_INTERVAL_WORKLOAD_ID_RT_CRITICAL;

#if CONFIG_THREAD_GROUPS
		tg_flags = wl_config.wc_thread_group_flags;
		if (tg_flags != THREAD_GROUP_FLAGS_ABSENT &&
		    (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_GROUP) == 0) {
			kr = KERN_INVALID_ARGUMENT;
			goto out;
		}
#endif /* CONFIG_THREAD_GROUPS */

		from_workload_config = true;
	} else {
		/* If the workload is not present in the table, perform basic validation
		 * that the create flags passed in match the ones used at work interval
		 * create time */
		if ((workload_id_args->wlida_wicreate_flags & WORK_INTERVAL_TYPE_MASK) !=
		    (work_interval->wi_create_flags & WORK_INTERVAL_TYPE_MASK)) {
			kr = KERN_INVALID_ARGUMENT;
			goto out;
		}

		const bool wc_avail = workload_config_available();
		if (!wc_avail) {
			wlida_flags = WORK_INTERVAL_WORKLOAD_ID_RT_ALLOWED;
		}

		/*
		 * If the workload config wasn't even loaded then fallback to
		 * older behaviour where the new thread group gets the default
		 * thread group flags (when WORK_INTERVAL_FLAG_GROUP is set).
		 */
#if CONFIG_THREAD_GROUPS
		if (!wc_avail) {
			tg_flags = THREAD_GROUP_FLAGS_DEFAULT;
		} else {
			struct thread_group *home_group =
			    thread_group_get_home_group(current_thread());
			if (home_group != NULL) {
				tg_flags = thread_group_get_flags(home_group);
			}
		}
#endif /* CONFIG_THREAD_GROUPS */
	}

	workload_id_args->wlida_wicreate_flags = work_interval->wi_create_flags;

	/* cmpxchg a non-zero workload ID flags value (indicating that workload ID
	 * has been set). */
	wlida_flags |= WORK_INTERVAL_WORKLOAD_ID_HAS_ID;
	if (os_atomic_cmpxchgv(&work_interval->wi_wlid_flags, 0, wlida_flags,
	    &wlid_flags, relaxed)) {
		if (from_workload_config) {
			work_interval->wi_class = wl_config.wc_class;
			work_interval->wi_class_offset = wl_config.wc_class_offset;
		}
#if CONFIG_THREAD_GROUPS
		if (work_interval->wi_create_flags & WORK_INTERVAL_FLAG_GROUP) {
			/* Perform deferred thread group creation, now that tgflags are known */
			struct thread_group *tg;
			tg = thread_group_create_and_retain(tg_flags == THREAD_GROUP_FLAGS_ABSENT ?
			    THREAD_GROUP_FLAGS_DEFAULT : tg_flags);

			char tgname[THREAD_GROUP_MAXNAME] = "";
			snprintf(tgname, sizeof(tgname), "WI%lld %s", work_interval->wi_id,
			    workload_id_args->wlida_name);
			thread_group_set_name(tg, tgname);

			assert(work_interval->wi_group == NULL);
			work_interval->wi_group = tg;
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_CREATE),
			    work_interval->wi_id, work_interval->wi_create_flags,
			    work_interval->wi_creator_pid, thread_group_get_id(tg));
		}
#endif /* CONFIG_THREAD_GROUPS */
	} else {
		/* Workload ID has previously been set (or a thread has already joined). */
		if (wlid_flags & WORK_INTERVAL_WORKLOAD_ID_ALREADY_JOINED) {
			kr = KERN_INVALID_ARGUMENT;
			goto out;
		}
		/* Treat this request as a query for the out parameters of the ID */
		workload_id_args->wlida_flags = wlid_flags;
	}

	/*
	 * Emit tracepoints for successfully setting the workload ID.
	 *
	 * After rdar://89342390 has been fixed and a new work interval ktrace
	 * provider has been added, it will be possible to associate a numeric
	 * ID with an ID name. Thus, for those cases where the ID name has been
	 * looked up successfully (`from_workload_config` is true) it will no
	 * longer be necessary to emit a tracepoint with the full ID name.
	 */
	KDBG(MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_SET_WORKLOAD_ID),
	    work_interval->wi_id, from_workload_config);
	kernel_debug_string_simple(
		MACHDBG_CODE(DBG_MACH_WORKGROUP, WORKGROUP_INTERVAL_SET_WORKLOAD_ID_NAME),
		workload_id_args->wlida_name);

	kr = KERN_SUCCESS;

out:
	work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);

	return kr;
}


kern_return_t
kern_work_interval_destroy(thread_t thread, uint64_t work_interval_id)
{
	if (work_interval_id == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if (thread->th_work_interval == NULL ||
	    thread->th_work_interval->wi_id != work_interval_id) {
		/* work ID isn't valid or doesn't match joined work interval ID */
		return KERN_INVALID_ARGUMENT;
	}

	return thread_set_work_interval_explicit_join(thread, NULL);
}

kern_return_t
kern_work_interval_join(thread_t            thread,
    mach_port_name_t    port_name)
{
	struct work_interval *work_interval = NULL;
	kern_return_t kr;

	if (port_name == MACH_PORT_NULL) {
		/* 'Un-join' the current work interval */
		return thread_set_work_interval_explicit_join(thread, NULL);
	}

	kr = port_name_to_work_interval(port_name, &work_interval);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	/* work_interval has a +1 ref */

	assert(work_interval != NULL);

	kr = thread_set_work_interval_explicit_join(thread, work_interval);
	/* ref was consumed by passing it to the thread in the successful case */
	if (kr != KERN_SUCCESS) {
		work_interval_release(work_interval, THREAD_WI_THREAD_LOCK_NEEDED);
	}
	return kr;
}

/*
 * work_interval_port_type_render_server()
 *
 * Helper routine to determine if the port points to a
 * WORK_INTERVAL_TYPE_CA_RENDER_SERVER work interval.
 */
bool
work_interval_port_type_render_server(mach_port_name_t port_name)
{
	return work_interval_port_type(port_name) == WORK_INTERVAL_TYPE_CA_RENDER_SERVER;
}
