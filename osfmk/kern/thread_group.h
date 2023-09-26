/*
 * Copyright (c) 2016 Apple Inc. All rights reserved.
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

/*
 * Thread group support routines.
 */
#ifndef _KERN_THREAD_GROUP_H_
#define _KERN_THREAD_GROUP_H_

struct thread_group;

#include <mach/thread_status.h> /* for proc_reg.h / CONFIG_THREAD_GROUPS */

#ifndef CONFIG_THREAD_GROUPS
#error "The platform must define CONFIG_THREAD_GROUPS to 0 or 1"
#endif

#if CONFIG_THREAD_GROUPS
#include <kern/assert.h>
#include <kern/queue.h>
#include <machine/machine_routines.h>

#define THREAD_GROUP_MAX                (CONFIG_TASK_MAX + 10)
#define THREAD_GROUP_MAXNAME            (32)

#define THREAD_GROUP_SYSTEM          0       // kernel (-VM) + launchd
#define THREAD_GROUP_BACKGROUND      1       // background daemons
#define THREAD_GROUP_VM              3       // kernel VM threads
#define THREAD_GROUP_IO_STORAGE      4       // kernel io storage threads
#define THREAD_GROUP_PERF_CONTROLLER 5       // kernel CLPC threads

#define THREAD_GROUP_INVALID    UINT64_MAX

/* Thread group flags */

/* Flags in the bottom 8 bits are exclusive. */
#define THREAD_GROUP_EXCLUSIVE_FLAGS_MASK 0xff

/* Exclusive flags */
#define THREAD_GROUP_FLAGS_DEFAULT      0x0
#define THREAD_GROUP_FLAGS_EFFICIENT    0x1
#define THREAD_GROUP_FLAGS_APPLICATION  0x2
#define THREAD_GROUP_FLAGS_CRITICAL     0x4
#define THREAD_GROUP_FLAGS_BEST_EFFORT  0x8

/* Shared flags */
#define THREAD_GROUP_FLAGS_UI_APP               0x100
#define THREAD_GROUP_FLAGS_MANAGED              0x200
#define THREAD_GROUP_FLAGS_STRICT_TIMERS        0x400
#define THREAD_GROUP_FLAGS_GAME_MODE            0x800


#define THREAD_GROUP_FLAGS_EXCLUSIVE ( \
    THREAD_GROUP_FLAGS_EFFICIENT |     \
    THREAD_GROUP_FLAGS_APPLICATION |   \
    THREAD_GROUP_FLAGS_CRITICAL |      \
    THREAD_GROUP_FLAGS_BEST_EFFORT)

#define THREAD_GROUP_FLAGS_ABSENT 0xffffffff

static_assert(
	(THREAD_GROUP_FLAGS_EXCLUSIVE & ~THREAD_GROUP_EXCLUSIVE_FLAGS_MASK) == 0,
	"valid exclusive flags");

/* Shared flags */
#define THREAD_GROUP_FLAGS_SHARED ( \
    THREAD_GROUP_FLAGS_UI_APP |     \
    THREAD_GROUP_FLAGS_MANAGED |    \
    THREAD_GROUP_FLAGS_STRICT_TIMERS | \
    THREAD_GROUP_FLAGS_GAME_MODE )

static_assert(
	(THREAD_GROUP_FLAGS_SHARED & THREAD_GROUP_EXCLUSIVE_FLAGS_MASK) == 0,
	"valid shared flags");

__BEGIN_DECLS

void            thread_group_init(void);
void            thread_group_resync(boolean_t create);
struct thread_group *thread_group_create_and_retain(uint32_t flags);
void            thread_group_init_thread(thread_t t, task_t task);
void            thread_group_set_name(struct thread_group *tg, const char *name);
void            thread_group_flags_update_lock(void);
void            thread_group_flags_update_unlock(void);
void            thread_group_set_flags(struct thread_group *tg, uint32_t flags);
uint32_t        thread_group_get_flags(struct thread_group *);
void            thread_group_clear_flags(struct thread_group *tg, uint32_t flags);
void            thread_group_set_flags_locked(struct thread_group *tg, uint32_t flags);
void            thread_group_clear_flags_locked(struct thread_group *tg, uint32_t flags);
boolean_t       thread_group_valid_flags(uint32_t flags);
struct thread_group *thread_group_find_by_name_and_retain(char *name);
struct thread_group *thread_group_find_by_id_and_retain(uint64_t id);
struct thread_group *thread_group_retain(struct thread_group *tg);
void            thread_group_release(struct thread_group *tg);
void            thread_group_release_live(struct thread_group *tg);
void            thread_group_deallocate_safe(struct thread_group *tg);
struct thread_group *thread_group_get(thread_t t);
struct thread_group *thread_group_get_home_group(thread_t t);
void            thread_group_set_bank(thread_t t, struct thread_group *tg);
uint64_t        thread_group_get_id(struct thread_group *tg);
uint32_t        thread_group_count(void);
const char *    thread_group_get_name(struct thread_group *tg);
void *          thread_group_get_machine_data(struct thread_group *tg);
uint32_t        thread_group_machine_data_size(void);
boolean_t       thread_group_uses_immediate_ipi(struct thread_group *tg);
cluster_type_t  thread_group_recommendation(struct thread_group *tg);

typedef         void (*thread_group_iterate_fn_t)(void*, int, struct thread_group *);
kern_return_t   thread_group_iterate_stackshot(thread_group_iterate_fn_t callout, void *arg);
void            thread_group_update_recommendation(struct thread_group *tg, cluster_type_t new_recommendation);
uint64_t        thread_group_id(struct thread_group *tg);

void            thread_set_work_interval_thread_group(thread_t t, struct thread_group *tg);
#if CONFIG_SCHED_AUTO_JOIN
void            thread_set_autojoin_thread_group_locked(thread_t t, struct thread_group *tg);
#endif
#if CONFIG_PREADOPT_TG
void thread_set_preadopt_thread_group(thread_t t, struct thread_group *tg);
#endif

void             thread_resolve_and_enforce_thread_group_hierarchy_if_needed(thread_t t);

#if XNU_KERNEL_PRIVATE
void            thread_group_vm_add(void);
#endif

__END_DECLS

#endif /* CONFIG_THREAD_GROUPS */

#endif // _KERN_THREAD_GROUP_H_
