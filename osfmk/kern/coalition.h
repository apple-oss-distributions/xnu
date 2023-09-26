/*
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_COALITION_H_
#define _KERN_COALITION_H_

/* only kernel-private interfaces */
#ifdef XNU_KERNEL_PRIVATE
#include <mach/coalition.h>
#include <kern/thread_group.h>

__BEGIN_DECLS

#if CONFIG_COALITIONS

void coalitions_init(void);

/* These may return:
 * KERN_ALREADY_IN_SET	task is already in a coalition (maybe this one, maybe a different one)
 * KERN_TERMINATED	coalition is already terminated (so it may not adopt any more tasks)
 */
kern_return_t coalitions_adopt_task(coalition_t *coaltions, task_t task);
kern_return_t coalitions_adopt_init_task(task_t task);
kern_return_t coalitions_adopt_corpse_task(task_t task);

/* Currently, no error conditions. If task is not already in a coalition,
 * KERN_SUCCESS is returned because removing it did not fail.
 */
kern_return_t coalitions_remove_task(task_t task);
void          task_release_coalitions(task_t task);

/*
 *
 */
kern_return_t coalitions_set_roles(coalition_t coalitions[COALITION_NUM_TYPES],
    task_t task, int roles[COALITION_NUM_TYPES]);

uint64_t coalition_id(coalition_t coal);
void     task_coalition_ids(task_t task, uint64_t ids[COALITION_NUM_TYPES]);
void     task_coalition_roles(task_t task, int roles[COALITION_NUM_TYPES]);
int      task_coalition_role_for_type(task_t task, int coalition_type);
int      coalition_type(coalition_t coal);

void     task_coalition_update_gpu_stats(task_t task, uint64_t gpu_ns_delta);
boolean_t task_coalition_adjust_focal_count(task_t task, int count, uint32_t *new_count);
uint32_t task_coalition_focal_count(task_t task);
uint32_t task_coalition_game_mode_count(task_t task);
bool task_coalition_adjust_game_mode_count(task_t task, int count, uint32_t *new_count);
boolean_t task_coalition_adjust_nonfocal_count(task_t task, int count, uint32_t *new_count);
uint32_t task_coalition_nonfocal_count(task_t task);

#if CONFIG_THREAD_GROUPS

/* Thread group lives as long as the task is holding the coalition reference */
struct thread_group *task_coalition_get_thread_group(task_t task);

/* Donates the thread group reference to the coalition */
void     coalition_set_thread_group(coalition_t coal, struct thread_group *tg);
struct thread_group *kdp_coalition_get_thread_group(coalition_t coal);

/* Thread group lives as long as the coalition reference is held */
struct thread_group *coalition_get_thread_group(coalition_t coal);

void task_coalition_thread_group_focal_update(task_t task);
void task_coalition_thread_group_game_mode_update(task_t task);
void task_coalition_thread_group_application_set(task_t task);
#endif /* CONFIG_THREAD_GROUPS */

void coalition_for_each_task(coalition_t coal, void *ctx,
    void (*callback)(coalition_t, void *, task_t));

/*  Coalition ledger  */
struct coalition_ledger_indices {
	int logical_writes;
};
void init_coalition_ledgers(void);
int coalition_ledger_set_logical_writes_limit(coalition_t coal, int64_t limit);
void coalition_io_monitor_ctl(struct coalition *coalition, uint32_t flags, int64_t limit);
ledger_t coalition_ledger_get_from_task(task_t task);
void coalition_io_rate_exceeded(int warning, const void *param0, __unused const void *param1);
void coalition_io_ledger_update(task_t task, int32_t flavor, boolean_t is_credit, uint32_t io_size);
/*
 * Mark this coalition as eligible for swap.
 * All tasks currently in this coalition will become swap enabled
 * and new tasks launched into this coalition will be swap enabled.
 *
 * Note:
 * This function can only be called on jetsam coalitions.
 */
void coalition_mark_swappable(coalition_t coal);
/*
 * Returns true iff the coalition has been marked as swappable.
 *
 * Note:
 * This function can only be called on jetsam coalitions.
 */
bool coalition_is_swappable(coalition_t coal);

/* Max limit for coalition logical_writes ledger in MB. Setting to 16 TB */
#define COALITION_MAX_LOGICAL_WRITES_LIMIT ((ledger_amount_t)(1ULL << 24))
/* logical_writes ledger's refill time interval */
#define COALITION_LEDGER_MONITOR_INTERVAL_SECS (24 * 60 * 60)


typedef void (*coalition_iterate_fn_t)(void*, int, coalition_t);
kern_return_t coalition_iterate_stackshot(coalition_iterate_fn_t callout, void *arg, uint32_t coalition_type);

/* Returns with a reference, or COALITION_NULL.
 * There is no coalition with id 0.
 */
coalition_t coalition_find_by_id(uint64_t coal_id);

/* Returns with a reference and an activation, or COALITION_NULL.
 * There is no coalition with id 0.
 */
coalition_t coalition_find_and_activate_by_id(uint64_t coal_id);

void coalition_remove_active(coalition_t coal);

void coalition_release(coalition_t coal);

/*
 * The following functions are to be used by the syscall wrapper
 * in bsd/kern/kern_proc.c, after it has verified the caller's privilege.
 */

/* This may return:
 * KERN_DEFAULT_SET	The default coalition, which contains the kernel, may
 *			not be terminated.
 * KERN_TERMINATED	The coalition was already reaped.
 * KERN_FAILURE		The coalition was not empty or has never been terminated.
 */
kern_return_t coalition_reap_internal(coalition_t coal);

/* This may return:
 * KERN_DEFAULT_SET	The default coalition, which contains the kernel, may
 *			not be terminated.
 * KERN_TERMINATED	The coalition was already terminated (or even reaped)
 * KERN_INVALID_NAME	The coalition was already reaped.
 */
kern_return_t coalition_request_terminate_internal(coalition_t coal);

/* This may return:
 * KERN_RESOURCE_SHORTAGE	Unable to allocate kernel resources for a
 *				new coalition.
 */
kern_return_t coalition_create_internal(int type, int role, boolean_t privileged, boolean_t efficient, coalition_t *out, uint64_t *cid);

boolean_t coalition_term_requested(coalition_t coal);
boolean_t coalition_is_terminated(coalition_t coal);
boolean_t coalition_is_reaped(coalition_t coal);
boolean_t coalition_is_privileged(coalition_t coal);
boolean_t task_is_in_privileged_coalition(task_t task, int type);

kern_return_t coalition_resource_usage_internal(coalition_t coal, struct coalition_resource_usage *cru_out);

kern_return_t coalition_debug_info_internal(coalition_t coal,
    struct coalinfo_debuginfo *c_debuginfo);

task_t kdp_coalition_get_leader(coalition_t coal);

/*
 * development/debug interfaces
 */
#if DEVELOPMENT || DEBUG
int coalition_should_notify(coalition_t coal);
void coalition_set_notify(coalition_t coal, int notify);
#endif

#else /* !CONFIG_COALITIONS */

static inline void
task_coalition_update_gpu_stats(__unused task_t task,
    __unused uint64_t gpu_ns_delta)
{
	return;
}

static inline boolean_t
task_coalition_adjust_focal_count(__unused task_t task,
    __unused int count,
    __unused uint32_t *new_count)
{
	return FALSE;
}

static inline boolean_t
task_coalition_adjust_nonfocal_count(__unused task_t task,
    __unused int count,
    __unused uint32_t *new_count)
{
	return FALSE;
}

static inline uint32_t
task_coalition_focal_count(__unused task_t task)
{
	return 0;
}

static inline void
coalition_for_each_task(__unused coalition_t coal,
    __unused void *ctx,
    __unused void (*callback)(coalition_t, void *, task_t))
{
	return;
}

static inline void
coalition_mark_swappable(__unused coalition_t coal)
{
	return;
}

static inline bool
coalition_is_swappable(__unused coalition_t coal)
{
	return false;
}

#endif /* CONFIG_COALITIONS */

__END_DECLS

#endif /* XNU_KERNEL_PRIVATE */
#endif /* _KERN_COALITION_H */
