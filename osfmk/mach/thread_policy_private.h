/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _MACH_THREAD_POLICY_PRIVATE_H_
#define _MACH_THREAD_POLICY_PRIVATE_H_

#include <mach/mach_types.h>
#include <mach/thread_policy.h>

/*
 * THREAD_POLICY_STATE:
 */
#define THREAD_POLICY_STATE             6

#define THREAD_POLICY_STATE_FLAG_STATIC_PARAM   0x1

struct thread_policy_state {
	integer_t requested;
	integer_t effective;
	integer_t pending;
	integer_t flags;
	uint64_t thps_requested_policy;
	uint64_t thps_effective_policy;
	uint32_t thps_user_promotions;
	uint32_t thps_user_promotion_basepri;
	uint32_t thps_ipc_overrides;
	uint32_t reserved32;
	uint64_t reserved[2];
};

typedef struct thread_policy_state              thread_policy_state_data_t;
typedef struct thread_policy_state              *thread_policy_state_t;

#define THREAD_POLICY_STATE_COUNT       ((mach_msg_type_number_t) \
	(sizeof (thread_policy_state_data_t) / sizeof (integer_t)))

/*
 * THREAD_QOS_POLICY:
 */
#define THREAD_QOS_POLICY               9

typedef uint8_t thread_qos_t;
#define THREAD_QOS_UNSPECIFIED          0
#define THREAD_QOS_DEFAULT              THREAD_QOS_UNSPECIFIED  /* Temporary rename */
#define THREAD_QOS_MAINTENANCE          1
#define THREAD_QOS_BACKGROUND           2
#define THREAD_QOS_UTILITY              3
#define THREAD_QOS_LEGACY               4       /* i.e. default workq threads */
#define THREAD_QOS_USER_INITIATED       5
#define THREAD_QOS_USER_INTERACTIVE     6

#define THREAD_QOS_LAST                 7

#define THREAD_QOS_MIN_TIER_IMPORTANCE  (-15)

/*
 * Overrides are inputs to the task/thread policy engine that
 * temporarily elevate the effective QoS of a thread without changing
 * its steady-state (and round-trip-able) requested QoS. The
 * interfaces into the kernel allow the caller to associate a resource
 * and type that describe the reason/lifecycle of the override. For
 * instance, a contended pthread_mutex_t held by a UTILITY thread
 * might get an override to USER_INTERACTIVE, with the resource
 * being the userspace address of the pthread_mutex_t. When the
 * owning thread releases that resource, it can call into the
 * task policy subsystem to drop the override because of that resource,
 * although if more contended locks are held by the thread, the
 * effective QoS may remain overridden for longer.
 *
 * THREAD_QOS_OVERRIDE_TYPE_PTHREAD_MUTEX is used for contended
 * pthread_mutex_t's via the pthread kext. The holder gets an override
 * with resource=&mutex and a count of 1 by the initial contender.
 * Subsequent contenders raise the QoS value, until the holder
 * decrements the count to 0 and the override is released.
 *
 * THREAD_QOS_OVERRIDE_TYPE_PTHREAD_RWLOCK is unimplemented and has no
 * specified semantics.
 *
 * THREAD_QOS_OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE are explicitly
 * paired start/end overrides on a target thread. The resource can
 * either be a memory allocation in userspace, or the pthread_t of the
 * overrider if no allocation was used.
 *
 * THREAD_QOS_OVERRIDE_TYPE_WILDCARD is a catch-all which will reset every
 * resource matching the resource value.  Passing
 * THREAD_QOS_OVERRIDE_RESOURCE_WILDCARD as well will reset everything.
 */

#define THREAD_QOS_OVERRIDE_TYPE_UNKNOWN                        (0)
#define THREAD_QOS_OVERRIDE_TYPE_PTHREAD_MUTEX                  (1)
#define THREAD_QOS_OVERRIDE_TYPE_PTHREAD_RWLOCK                 (2)
#define THREAD_QOS_OVERRIDE_TYPE_PTHREAD_EXPLICIT_OVERRIDE      (3)
#define THREAD_QOS_OVERRIDE_TYPE_WILDCARD                       (5)

/* A special resource value to indicate a resource wildcard */
#define THREAD_QOS_OVERRIDE_RESOURCE_WILDCARD (~((user_addr_t)0))

struct thread_qos_policy {
	integer_t qos_tier;
	integer_t tier_importance;
};

typedef struct thread_qos_policy       thread_qos_policy_data_t;
typedef struct thread_qos_policy      *thread_qos_policy_t;

#define THREAD_QOS_POLICY_COUNT    ((mach_msg_type_number_t) \
	(sizeof (thread_qos_policy_data_t) / sizeof (integer_t)))

/*
 * THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY:
 *
 * This scheduling mode is for threads which have real time
 * constraints on their execution with support for multiple
 * real time priorities.
 *
 * Threads are ordered by highest priority first then, for
 * threads of the same priority, by earliest deadline first.
 * But if sched_rt_runq_strict_priority is false, a lower priority
 * thread with an earlier deadline will be preferred over a higher
 * priority thread with a later deadline, as long as both threads'
 * computations will fit before the later deadline.
 *
 * Parameters:
 *
 * period: This is the nominal amount of time between separate
 * processing arrivals, specified in absolute time units.  A
 * value of 0 indicates that there is no inherent periodicity in
 * the computation.
 *
 * computation: This is the nominal amount of computation
 * time needed during a separate processing arrival, specified
 * in absolute time units.  The thread may be preempted after
 * the computation time has elapsed.
 * If (computation < constraint/2) it will be forced to
 * constraint/2 to avoid unintended preemption and associated
 * timer interrupts.
 *
 * constraint: This is the maximum amount of real time that
 * may elapse from the start of a separate processing arrival
 * to the end of computation for logically correct functioning,
 * specified in absolute time units.  Must be (>= computation).
 * Note that latency = (constraint - computation).
 *
 * preemptible: IGNORED (This indicates that the computation may be
 * interrupted, subject to the constraint specified above.)
 *
 * priority: This is the scheduling priority of the thread.
 * User processes may only set the default priority of
 * TIME_CONSTRAINT_POLICY_DEFAULT_PRIORITY.  Higher priorities
 * up to TIME_CONSTRAINT_POLICY_MAXIMUM_PRIORITY are reserved
 * for system use and attempts to set them will fail.
 */

#define THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY     10

struct thread_time_constraint_with_priority_policy {
	uint32_t                period;
	uint32_t                computation;
	uint32_t                constraint;
	boolean_t               preemptible;
	uint32_t                priority;
};

typedef struct thread_time_constraint_with_priority_policy    \
        thread_time_constraint_with_priority_policy_data_t;
typedef struct thread_time_constraint_with_priority_policy    \
        *thread_time_constraint_with_priority_policy_t;

#define THREAD_TIME_CONSTRAINT_WITH_PRIORITY_POLICY_COUNT     ((mach_msg_type_number_t) \
	(sizeof (thread_time_constraint_with_priority_policy_data_t) / sizeof (integer_t)))

#define TIME_CONSTRAINT_POLICY_DEFAULT_PRIORITY          97
#define TIME_CONSTRAINT_POLICY_MAXIMUM_PRIORITY         127

/*
 * THREAD_REQUESTED_STATE_POLICY: Retrieves just the thread's requested qos policy
 */
#define THREAD_REQUESTED_STATE_POLICY 11

struct thread_requested_qos_policy {
	integer_t  thrq_base_qos;
	integer_t  thrq_qos_relprio;
	integer_t  thrq_qos_override;
	integer_t  thrq_qos_promote;
	integer_t  thrq_qos_kevent_override;
	integer_t  thrq_qos_workq_override;
	integer_t  thrq_qos_wlsvc_override;
};

typedef struct thread_requested_qos_policy thread_requested_qos_policy_data_t;
typedef struct thread_requested_qos_policy *thread_requested_qos_policy_t;

#define THREAD_REQUESTED_STATE_POLICY_COUNT ((mach_msg_type_number_t) \
	(sizeof(thread_requested_qos_policy_data_t) / sizeof (integer_t)))

/*
 * Internal bitfields are privately exported for revlocked tracing tools like
 * msa to decode tracepoints.
 *
 * These struct definitions *will* change in the future.
 * When they do, we will update THREAD_POLICY_INTERNAL_STRUCT_VERSION.
 */

#define THREAD_POLICY_INTERNAL_STRUCT_VERSION 7

struct thread_requested_policy {
	uint64_t        thrp_int_darwinbg       :1,     /* marked as darwinbg via setpriority */
	    thrp_ext_darwinbg       :1,
	    thrp_int_iotier         :2,                 /* IO throttle tier */
	    thrp_ext_iotier         :2,
	    thrp_int_iopassive      :1,                 /* should IOs cause lower tiers to be throttled */
	    thrp_ext_iopassive      :1,
	    thrp_latency_qos        :3,                 /* Timer latency QoS */
	    thrp_through_qos        :3,                 /* Computation throughput QoS */

	    thrp_pidbind_bg         :1,                 /* task i'm bound to is marked 'watchbg' */
	    thrp_qos                :3,                 /* thread qos class */
	    thrp_qos_relprio        :4,                 /* thread qos relative priority (store as inverse, -10 -> 0xA) */
	    thrp_qos_override       :3,                 /* thread qos class override */
	    thrp_qos_promote        :3,                 /* thread qos class from promotion */
	    thrp_qos_kevent_override:3,                 /* thread qos class from kevent override */
	    thrp_terminated         :1,                 /* heading for termination */
	    thrp_qos_workq_override :3,                 /* thread qos class override (workq) */
	    thrp_qos_wlsvc_override :3,                 /* workloop servicer qos class override */
	    thrp_iotier_kevent_override :2,             /* thread iotier from kevent override */
	    thrp_wi_driven          :1,                 /* thread priority from work interval */

	    thrp_reserved           :23;
};

struct thread_effective_policy {
	uint64_t        thep_darwinbg           :1,     /* marked as 'background', and sockets are marked bg when created */
	    thep_io_tier            :2,                 /* effective throttle tier */
	    thep_io_passive         :1,                 /* should IOs cause lower tiers to be throttled */
	    thep_all_sockets_bg     :1,                 /* All existing sockets in process are marked as bg (thread: all created by thread) */
	    thep_new_sockets_bg     :1,                 /* Newly created sockets should be marked as bg */
	    thep_terminated         :1,                 /* all throttles have been removed for quick exit or SIGTERM handling */
	    thep_qos_ui_is_urgent   :1,                 /* bump UI-Interactive QoS up to the urgent preemption band */
	    thep_latency_qos        :3,                 /* Timer latency QoS level */
	    thep_through_qos        :3,                 /* Computation throughput QoS level */

	    thep_qos                :3,                 /* thread qos class */
	    thep_qos_relprio        :4,                 /* thread qos relative priority (store as inverse, -10 -> 0xA) */
	    thep_qos_promote        :3,                 /* thread qos class used for promotion */
	    thep_promote_above_task :1,                 /* thread is promoted above task-level clamp */
	    thep_wi_driven          :1,                 /* thread priority is driven by work interval */

	    thep_reserved           :38;
};

#endif
