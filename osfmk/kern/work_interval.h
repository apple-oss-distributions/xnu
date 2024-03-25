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

#ifndef _KERN_WORK_INTERVAL_H_
#define _KERN_WORK_INTERVAL_H_

#include <sys/cdefs.h>

#include <stdint.h>
#include <kern/kern_types.h>

#include <kern/thread_group.h>
#include <kern/recount.h>

__BEGIN_DECLS

struct work_interval;

struct kern_work_interval_args {
	uint64_t work_interval_id;
	uint64_t start;
	uint64_t finish;
	uint64_t deadline;
	uint64_t next_start;
	uint32_t notify_flags;
	uint32_t create_flags;
	uint16_t urgency;
};

struct kern_work_interval_create_args {
	uint64_t        wica_id;          /* out param */
	mach_port_name_t wica_port;        /* out param */
	uint32_t        wica_create_flags;
};

struct kern_work_interval_workload_id_args {
	uint32_t        wlida_flags;            /* in/out param */
	uint32_t        wlida_wicreate_flags;   /* in/out param */
	char *          wlida_name;             /* in param */
	uint64_t        wlida_syscall_mask[2];  /* out param */
};

/*
 * Allocate/assign a single work interval ID for a thread,
 * and support deallocating it.
 */
extern kern_return_t
kern_work_interval_create(thread_t thread, struct kern_work_interval_create_args *create_params);

extern kern_return_t
kern_work_interval_get_flags_from_port(mach_port_name_t port_name, uint32_t*flags);

#if CONFIG_THREAD_GROUPS
/*
 * A private interface for kevent subsystem.
 * Returns following scheduling policies associated with a work interval, if available.
 * : Priority
 * : Scheduling policy/mode
 * : +1 ref on the backing thread group
 */
extern kern_return_t
kern_work_interval_get_policy_from_port(mach_port_name_t port_name,
    integer_t *policy, integer_t *priority, struct thread_group **tg);
#endif /* CONFIG_THREAD_GROUPS */


extern kern_return_t
kern_work_interval_destroy(thread_t thread, uint64_t work_interval_id);
extern kern_return_t
kern_work_interval_join(thread_t thread, mach_port_name_t port_name);

extern kern_return_t
kern_work_interval_notify(thread_t thread, struct kern_work_interval_args* kwi_args);
extern kern_return_t
kern_work_interval_set_name(mach_port_name_t port_name, char *name, size_t len);
extern kern_return_t
kern_work_interval_set_workload_id(mach_port_name_t port_name,
    struct kern_work_interval_workload_id_args *workload_id_args);

#ifdef MACH_KERNEL_PRIVATE

bool work_interval_port_type_render_server(mach_port_name_t port_name);

#if CONFIG_SCHED_AUTO_JOIN
bool work_interval_should_propagate(thread_t cthread, thread_t thread);
void work_interval_auto_join_propagate(thread_t from, thread_t to);
void work_interval_auto_join_unwind(thread_t thread);
void work_interval_auto_join_demote(thread_t thread);
#endif /* CONFIG_SCHED_AUTO_JOIN */


struct recount_track *work_interval_get_recount_tracks(struct work_interval *work_interval);

extern kern_return_t work_interval_thread_terminate(thread_t thread);
extern int work_interval_get_priority(thread_t thread);

#endif /* MACH_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE

__enum_closed_decl(wi_class_t, uint8_t, {
	WI_CLASS_NONE              = 0,
	WI_CLASS_DISCRETIONARY     = 1,
	WI_CLASS_BEST_EFFORT       = 2,
	WI_CLASS_APPLICATION       = 3,
	WI_CLASS_SYSTEM            = 4,
	WI_CLASS_SYSTEM_CRITICAL   = 5,
	WI_CLASS_REALTIME          = 6,
	WI_CLASS_REALTIME_CRITICAL = 7,
	WI_CLASS_APP_SUPPORT       = 8,

	WI_CLASS_COUNT
});

#endif

__END_DECLS

#endif /* !defined(_KERN_WORK_INTERVAL_H_) */
