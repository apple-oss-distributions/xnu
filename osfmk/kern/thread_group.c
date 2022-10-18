/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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
#include <kern/kern_types.h>
#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/task.h>
#include <kern/machine.h>
#include <kern/coalition.h>
#include <sys/errno.h>
#include <kern/queue.h>
#include <kern/locks.h>
#include <kern/thread_group.h>
#include <kern/sched_clutch.h>

#if CONFIG_THREAD_GROUPS

#define TG_MACHINE_DATA_ALIGN_SIZE (16)

struct thread_group {
	uint64_t                tg_id;
	char                    tg_name[THREAD_GROUP_MAXNAME];
	struct os_refcnt        tg_refcount;
	struct {
		uint32_t                tg_flags;
		cluster_type_t          tg_recommendation;
	};
	/* We make the mpsc destroy chain link a separate field here because while
	 * refs = 0 and the thread group is enqueued on the daemon queue, CLPC
	 * (which does not hold an explicit ref) is still under the assumption that
	 * this thread group is alive and may provide recommendation changes/updates
	 * to it. As such, we need to make sure that all parts of the thread group
	 * structure are valid.
	 */
	struct mpsc_queue_chain tg_destroy_link;
	queue_chain_t           tg_queue_chain;
#if CONFIG_SCHED_CLUTCH
	struct sched_clutch     tg_sched_clutch;
#endif /* CONFIG_SCHED_CLUTCH */
	uint8_t                 tg_machine_data[] __attribute__((aligned(TG_MACHINE_DATA_ALIGN_SIZE)));
} __attribute__((aligned(8)));

static SECURITY_READ_ONLY_LATE(zone_t) tg_zone;
static uint32_t tg_count;
static queue_head_t tg_queue;
static LCK_GRP_DECLARE(tg_lck_grp, "thread_group");
static LCK_MTX_DECLARE(tg_lock, &tg_lck_grp);
static LCK_MTX_DECLARE(tg_flags_update_lock, &tg_lck_grp);

static uint64_t tg_next_id = 0;
static uint32_t tg_size;
static uint32_t tg_machine_data_size;
static uint32_t perf_controller_thread_group_immediate_ipi;
static struct thread_group *tg_system;
static struct thread_group *tg_background;
static struct thread_group *tg_vm;
static struct thread_group *tg_io_storage;
static struct thread_group *tg_perf_controller;
int tg_set_by_bankvoucher;

static bool thread_group_retain_try(struct thread_group *tg);

static struct mpsc_daemon_queue thread_group_deallocate_queue;
static void thread_group_deallocate_queue_invoke(mpsc_queue_chain_t e,
    __assert_only mpsc_daemon_queue_t dq);

/*
 * Initialize thread groups at boot
 */
void
thread_group_init(void)
{
	// Get thread group structure extension from EDT or boot-args (which can override EDT)
	if (!PE_parse_boot_argn("kern.thread_group_extra_bytes", &tg_machine_data_size, sizeof(tg_machine_data_size))) {
		if (!PE_get_default("kern.thread_group_extra_bytes", &tg_machine_data_size, sizeof(tg_machine_data_size))) {
			tg_machine_data_size = 8;
		}
	}

	if (!PE_parse_boot_argn("kern.perf_tg_no_dipi", &perf_controller_thread_group_immediate_ipi, sizeof(perf_controller_thread_group_immediate_ipi))) {
		if (!PE_get_default("kern.perf_tg_no_dipi", &perf_controller_thread_group_immediate_ipi, sizeof(perf_controller_thread_group_immediate_ipi))) {
			perf_controller_thread_group_immediate_ipi = 0;
		}
	}

	// Check if thread group can be set by voucher adoption from EDT or boot-args (which can override EDT)
	if (!PE_parse_boot_argn("kern.thread_group_set_by_bankvoucher", &tg_set_by_bankvoucher, sizeof(tg_set_by_bankvoucher))) {
		if (!PE_get_default("kern.thread_group_set_by_bankvoucher", &tg_set_by_bankvoucher, sizeof(tg_set_by_bankvoucher))) {
			tg_set_by_bankvoucher = 1;
		}
	}

	tg_size = sizeof(struct thread_group) + tg_machine_data_size;
	if (tg_size % TG_MACHINE_DATA_ALIGN_SIZE) {
		tg_size += TG_MACHINE_DATA_ALIGN_SIZE - (tg_size % TG_MACHINE_DATA_ALIGN_SIZE);
	}
	tg_machine_data_size = tg_size - sizeof(struct thread_group);
	// printf("tg_size=%d(%lu+%d)\n", tg_size, sizeof(struct thread_group), tg_machine_data_size);
	assert(offsetof(struct thread_group, tg_machine_data) % TG_MACHINE_DATA_ALIGN_SIZE == 0);
	tg_zone = zone_create("thread_groups", tg_size, ZC_ALIGNMENT_REQUIRED);

	queue_head_init(tg_queue);
	tg_system = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);
	thread_group_set_name(tg_system, "system");
	tg_background = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);
	thread_group_set_name(tg_background, "background");
	lck_mtx_lock(&tg_lock);
	tg_next_id++;  // Skip ID 2, which used to be the "adaptive" group. (It was never used.)
	lck_mtx_unlock(&tg_lock);
	tg_vm = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);
	thread_group_set_name(tg_vm, "VM");
	tg_io_storage = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);
	thread_group_set_name(tg_io_storage, "io storage");
	tg_perf_controller = thread_group_create_and_retain(THREAD_GROUP_FLAGS_DEFAULT);
	thread_group_set_name(tg_perf_controller, "perf_controller");

	/*
	 * The thread group deallocation queue must be a thread call based queue
	 * because it is woken up from contexts where the thread lock is held. The
	 * only way to perform wakeups safely in those contexts is to wakeup a
	 * thread call which is guaranteed to be on a different waitq and would
	 * not hash onto the same global waitq which might be currently locked.
	 */
	mpsc_daemon_queue_init_with_thread_call(&thread_group_deallocate_queue,
	    thread_group_deallocate_queue_invoke, THREAD_CALL_PRIORITY_KERNEL,
	    MPSC_DAEMON_INIT_NONE);
}

#if CONFIG_SCHED_CLUTCH
/*
 * sched_clutch_for_thread
 *
 * The routine provides a back linkage from the thread to the
 * sched_clutch it belongs to. This relationship is based on the
 * thread group membership of the thread. Since that membership is
 * changed from the thread context with the thread lock held, this
 * linkage should be looked at only with the thread lock held or
 * when the thread cannot be running (for eg. the thread is in the
 * runq and being removed as part of thread_select().
 */
sched_clutch_t
sched_clutch_for_thread(thread_t thread)
{
	assert(thread->thread_group != NULL);
	return &(thread->thread_group->tg_sched_clutch);
}

sched_clutch_t
sched_clutch_for_thread_group(struct thread_group *thread_group)
{
	return &(thread_group->tg_sched_clutch);
}

/*
 * Translate the TG flags to a priority boost for the sched_clutch.
 * This priority boost will apply to the entire clutch represented
 * by the thread group.
 */
static void
sched_clutch_update_tg_flags(__unused sched_clutch_t clutch, __unused uint32_t flags)
{
	sched_clutch_tg_priority_t sc_tg_pri = 0;
	if (flags & THREAD_GROUP_FLAGS_UI_APP) {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_HIGH;
	} else if (flags & THREAD_GROUP_FLAGS_EFFICIENT) {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_LOW;
	} else {
		sc_tg_pri = SCHED_CLUTCH_TG_PRI_MED;
	}
	os_atomic_store(&clutch->sc_tg_priority, sc_tg_pri, relaxed);
}

#endif /* CONFIG_SCHED_CLUTCH */

uint64_t
thread_group_id(struct thread_group *tg)
{
	return (tg == NULL) ? 0 : tg->tg_id;
}

#if CONFIG_PREADOPT_TG
static inline bool
thread_get_reevaluate_tg_hierarchy_locked(thread_t t)
{
	return t->sched_flags & TH_SFLAG_REEVALUTE_TG_HIERARCHY_LATER;
}

static inline void
thread_set_reevaluate_tg_hierarchy_locked(thread_t t)
{
	t->sched_flags |= TH_SFLAG_REEVALUTE_TG_HIERARCHY_LATER;
}

static inline void
thread_clear_reevaluate_tg_hierarchy_locked(thread_t t)
{
	t->sched_flags &= ~TH_SFLAG_REEVALUTE_TG_HIERARCHY_LATER;
}
#endif

/*
 * Use a spinlock to protect all thread group flag updates.
 * The lock should not have heavy contention since these flag updates should
 * be infrequent. If this lock has contention issues, it should be changed to
 * a per thread-group lock.
 *
 * The lock protects the flags field in the thread_group structure. It is also
 * held while doing callouts to CLPC to reflect these flag changes.
 */

void
thread_group_flags_update_lock(void)
{
	lck_mtx_lock(&tg_flags_update_lock);
}

void
thread_group_flags_update_unlock(void)
{
	lck_mtx_unlock(&tg_flags_update_lock);
}

/*
 * Inform platform code about already existing thread groups
 * or ask it to free state for all thread groups
 */
void
thread_group_resync(boolean_t create)
{
	struct thread_group *tg;

	thread_group_flags_update_lock();
	lck_mtx_lock(&tg_lock);
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (create) {
			machine_thread_group_init(tg);
		} else {
			machine_thread_group_deinit(tg);
		}
	}
	lck_mtx_unlock(&tg_lock);
	thread_group_flags_update_unlock();
}

/*
 * Create new thread group and add new reference to it.
 */
struct thread_group *
thread_group_create_and_retain(uint32_t flags)
{
	struct thread_group *tg;

	tg = zalloc_flags(tg_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	assert((uintptr_t)tg % TG_MACHINE_DATA_ALIGN_SIZE == 0);

	tg->tg_flags = flags;

#if CONFIG_SCHED_CLUTCH
	/*
	 * The clutch scheduler maintains a bunch of runqs per thread group. For
	 * each thread group it maintains a sched_clutch structure. The lifetime
	 * of that structure is tied directly to the lifetime of the thread group.
	 */
	sched_clutch_init_with_thread_group(&(tg->tg_sched_clutch), tg);

	/*
	 * Since the thread group flags are used to determine any priority promotions
	 * for the threads in the thread group, initialize them now.
	 */
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), tg->tg_flags);

#endif /* CONFIG_SCHED_CLUTCH */

	lck_mtx_lock(&tg_lock);
	tg->tg_id = tg_next_id++;
	tg->tg_recommendation = CLUSTER_TYPE_SMP; // no recommendation yet
	os_ref_init(&tg->tg_refcount, NULL);
	tg_count++;
	enqueue_tail(&tg_queue, &tg->tg_queue_chain);

	// call machine layer init before this thread group becomes visible
	machine_thread_group_init(tg);
	lck_mtx_unlock(&tg_lock);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NEW), thread_group_id(tg), thread_group_get_flags(tg));
	if (flags) {
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS), thread_group_id(tg), thread_group_get_flags(tg), 0);
	}

	return tg;
}

/*
 * Point newly created thread to its home thread group
 */
void
thread_group_init_thread(thread_t t, task_t task)
{
	struct thread_group *tg = task_coalition_get_thread_group(task);
	t->thread_group = tg;
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
	    THREAD_GROUP_INVALID, thread_group_id(tg), (uintptr_t)thread_tid(t));
}

/*
 * Set thread group name
 */
void
thread_group_set_name(__unused struct thread_group *tg, __unused const char *name)
{
	if (name == NULL) {
		return;
	}
	if (!thread_group_retain_try(tg)) {
		return;
	}
	if (name[0] != '\0') {
		strncpy(&tg->tg_name[0], name, THREAD_GROUP_MAXNAME);
#if defined(__LP64__)
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME),
		    tg->tg_id,
		    *(uint64_t*)(void*)&tg->tg_name[0],
		    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t)],
		    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t) * 2]
		    );
#else /* defined(__LP64__) */
		KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME),
		    tg->tg_id,
		    *(uint32_t*)(void*)&tg->tg_name[0],
		    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t)],
		    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t) * 2]
		    );
#endif /* defined(__LP64__) */
	}
	thread_group_release(tg);
}

void
thread_group_set_flags(struct thread_group *tg, uint32_t flags)
{
	thread_group_flags_update_lock();
	thread_group_set_flags_locked(tg, flags);
	thread_group_flags_update_unlock();
}

/*
 * Return true if flags are valid, false otherwise.
 * Some flags are mutually exclusive.
 */
boolean_t
thread_group_valid_flags(uint32_t flags)
{
	const uint32_t sflags = flags & ~THREAD_GROUP_EXCLUSIVE_FLAGS_MASK;
	const uint32_t eflags = flags & THREAD_GROUP_EXCLUSIVE_FLAGS_MASK;

	if ((sflags & THREAD_GROUP_FLAGS_SHARED) != sflags) {
		return false;
	}

	if ((eflags & THREAD_GROUP_FLAGS_EXCLUSIVE) != eflags) {
		return false;
	}

	/* Only one of the exclusive flags may be set. */
	if (((eflags - 1) & eflags) != 0) {
		return false;
	}

	return true;
}

void
thread_group_clear_flags(struct thread_group *tg, uint32_t flags)
{
	thread_group_flags_update_lock();
	thread_group_clear_flags_locked(tg, flags);
	thread_group_flags_update_unlock();
}

/*
 * Set thread group flags and perform related actions.
 * The tg_flags_update_lock should be held.
 * Currently supported flags are:
 * Exclusive Flags:
 * - THREAD_GROUP_FLAGS_EFFICIENT
 * - THREAD_GROUP_FLAGS_APPLICATION
 * - THREAD_GROUP_FLAGS_CRITICAL
 * Shared Flags:
 * - THREAD_GROUP_FLAGS_UI_APP
 */

void
thread_group_set_flags_locked(struct thread_group *tg, uint32_t flags)
{
	if (!thread_group_valid_flags(flags)) {
		panic("thread_group_set_flags: Invalid flags %u", flags);
	}

	/* Disallow any exclusive flags from being set after creation, with the
	 * exception of moving from default to application */
	if ((flags & THREAD_GROUP_EXCLUSIVE_FLAGS_MASK) &&
	    !((flags & THREAD_GROUP_FLAGS_APPLICATION) &&
	    (tg->tg_flags & THREAD_GROUP_EXCLUSIVE_FLAGS_MASK) ==
	    THREAD_GROUP_FLAGS_DEFAULT)) {
		flags &= ~THREAD_GROUP_EXCLUSIVE_FLAGS_MASK;
	}
	if ((tg->tg_flags & flags) == flags) {
		return;
	}

	if (tg == tg_system) {
		/*
		 * The system TG is used for kernel and launchd. It is also used
		 * for processes which are getting spawned and do not have a home
		 * TG yet (see task_coalition_get_thread_group()). Make sure the
		 * policies for those processes do not update the flags for the
		 * system TG. The flags for this thread group should only be set
		 * at creation via thread_group_create_and_retain().
		 */
		return;
	}

	__kdebug_only uint64_t old_flags = tg->tg_flags;
	tg->tg_flags |= flags;

	machine_thread_group_flags_update(tg, tg->tg_flags);
#if CONFIG_SCHED_CLUTCH
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), tg->tg_flags);
#endif /* CONFIG_SCHED_CLUTCH */
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS),
	    tg->tg_id, tg->tg_flags, old_flags);
}

/*
 * Clear thread group flags and perform related actions
 * The tg_flags_update_lock should be held.
 * Currently supported flags are:
 * Exclusive Flags:
 * - THREAD_GROUP_FLAGS_EFFICIENT
 * - THREAD_GROUP_FLAGS_APPLICATION
 * - THREAD_GROUP_FLAGS_CRITICAL
 * Shared Flags:
 * - THREAD_GROUP_FLAGS_UI_APP
 */

void
thread_group_clear_flags_locked(struct thread_group *tg, uint32_t flags)
{
	if (!thread_group_valid_flags(flags)) {
		panic("thread_group_clear_flags: Invalid flags %u", flags);
	}

	/* Disallow any exclusive flags from being cleared */
	if (flags & THREAD_GROUP_EXCLUSIVE_FLAGS_MASK) {
		flags &= ~THREAD_GROUP_EXCLUSIVE_FLAGS_MASK;
	}
	if ((tg->tg_flags & flags) == 0) {
		return;
	}

	__kdebug_only uint64_t old_flags = tg->tg_flags;
	tg->tg_flags &= ~flags;
#if CONFIG_SCHED_CLUTCH
	sched_clutch_update_tg_flags(&(tg->tg_sched_clutch), tg->tg_flags);
#endif /* CONFIG_SCHED_CLUTCH */
	machine_thread_group_flags_update(tg, tg->tg_flags);
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FLAGS),
	    tg->tg_id, tg->tg_flags, old_flags);
}



/*
 * Find thread group with specified name and put new reference to it.
 */
struct thread_group *
thread_group_find_by_name_and_retain(char *name)
{
	struct thread_group *result = NULL;

	if (name == NULL) {
		return NULL;
	}

	if (strncmp("system", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_system);
	} else if (strncmp("background", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_background);
	} else if (strncmp("perf_controller", name, THREAD_GROUP_MAXNAME) == 0) {
		return thread_group_retain(tg_perf_controller);
	}

	struct thread_group *tg;
	lck_mtx_lock(&tg_lock);
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (strncmp(tg->tg_name, name, THREAD_GROUP_MAXNAME) == 0 &&
		    thread_group_retain_try(tg)) {
			result = tg;
			break;
		}
	}
	lck_mtx_unlock(&tg_lock);
	return result;
}

/*
 * Find thread group with specified ID and add new reference to it.
 */
struct thread_group *
thread_group_find_by_id_and_retain(uint64_t id)
{
	struct thread_group *tg = NULL;
	struct thread_group *result = NULL;

	switch (id) {
	case THREAD_GROUP_SYSTEM:
		result = tg_system;
		thread_group_retain(tg_system);
		break;
	case THREAD_GROUP_BACKGROUND:
		result = tg_background;
		thread_group_retain(tg_background);
		break;
	case THREAD_GROUP_VM:
		result = tg_vm;
		thread_group_retain(tg_vm);
		break;
	case THREAD_GROUP_IO_STORAGE:
		result = tg_io_storage;
		thread_group_retain(tg_io_storage);
		break;
	case THREAD_GROUP_PERF_CONTROLLER:
		result = tg_perf_controller;
		thread_group_retain(tg_perf_controller);
		break;
	default:
		lck_mtx_lock(&tg_lock);
		qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
			if (tg->tg_id == id && thread_group_retain_try(tg)) {
				result = tg;
				break;
			}
		}
		lck_mtx_unlock(&tg_lock);
	}
	return result;
}

/*
 * Add new reference to specified thread group
 */
struct thread_group *
thread_group_retain(struct thread_group *tg)
{
	os_ref_retain(&tg->tg_refcount);
	return tg;
}

/*
 * Similar to thread_group_retain, but fails for thread groups with a
 * zero reference count. Returns true if retained successfully.
 */
static bool
thread_group_retain_try(struct thread_group *tg)
{
	return os_ref_retain_try(&tg->tg_refcount);
}

static void
thread_group_deallocate_complete(struct thread_group *tg)
{
	lck_mtx_lock(&tg_lock);
	tg_count--;
	remqueue(&tg->tg_queue_chain);
	lck_mtx_unlock(&tg_lock);
	static_assert(THREAD_GROUP_MAXNAME >= (sizeof(uint64_t) * 3), "thread group name is too short");
	static_assert(__alignof(struct thread_group) >= __alignof(uint64_t), "thread group name is not 8 bytes aligned");
#if defined(__LP64__)
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME_FREE),
	    tg->tg_id,
	    *(uint64_t*)(void*)&tg->tg_name[0],
	    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t)],
	    *(uint64_t*)(void*)&tg->tg_name[sizeof(uint64_t) * 2]
	    );
#else /* defined(__LP64__) */
	KDBG(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_NAME_FREE),
	    tg->tg_id,
	    *(uint32_t*)(void*)&tg->tg_name[0],
	    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t)],
	    *(uint32_t*)(void*)&tg->tg_name[sizeof(uint32_t) * 2]
	    );
#endif /* defined(__LP64__) */
	machine_thread_group_deinit(tg);
#if CONFIG_SCHED_CLUTCH
	sched_clutch_destroy(&(tg->tg_sched_clutch));
#endif /* CONFIG_SCHED_CLUTCH */
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_FREE), tg->tg_id);
	zfree(tg_zone, tg);
}

/*
 * Drop a reference to specified thread group
 */
void
thread_group_release(struct thread_group *tg)
{
	if (os_ref_release(&tg->tg_refcount) == 0) {
		thread_group_deallocate_complete(tg);
	}
}

void
thread_group_release_live(struct thread_group *tg)
{
	os_ref_release_live(&tg->tg_refcount);
}

static void
thread_group_deallocate_queue_invoke(mpsc_queue_chain_t e, __assert_only mpsc_daemon_queue_t dq)
{
	assert(dq == &thread_group_deallocate_queue);
	struct thread_group *tg = mpsc_queue_element(e, struct thread_group, tg_destroy_link);

	thread_group_deallocate_complete(tg);
}

void
thread_group_deallocate_safe(struct thread_group *tg)
{
	if (os_ref_release(&tg->tg_refcount) == 0) {
		mpsc_daemon_enqueue(&thread_group_deallocate_queue, &tg->tg_destroy_link,
		    MPSC_QUEUE_NONE);
	}
}

/*
 * Get thread's current thread group
 */
inline struct thread_group *
thread_group_get(thread_t t)
{
	return t->thread_group;
}

struct thread_group *
thread_group_get_home_group(thread_t t)
{
	return task_coalition_get_thread_group(get_threadtask(t));
}

/*
 * The thread group is resolved according to a hierarchy:
 *
 * 1) work interval specified group (explicit API)
 * 2) Auto-join thread group (wakeup tracking for special work intervals)
 * 3) bank voucher carried group (implicitly set)
 * 4) Preadopt thread group (if any)
 * 5) coalition default thread group (ambient)
 *
 * Returns true if the thread's thread group needs to be changed and resolving
 * TG is passed through in-out param. See also
 * thread_mark_thread_group_hierarchy_resolved and
 * thread_set_resolved_thread_group
 *
 * Caller should have thread lock. Interrupts are disabled. Thread doesn't have
 * to be self
 */
static bool
thread_compute_resolved_thread_group(thread_t t, struct thread_group **resolved_tg)
{
	struct thread_group *cur_tg, *tg;
	cur_tg = t->thread_group;

	tg = thread_group_get_home_group(t);

#if CONFIG_PREADOPT_TG
	if (t->preadopt_thread_group) {
		tg = t->preadopt_thread_group;
	}
#endif
	if (t->bank_thread_group) {
		tg = t->bank_thread_group;
	}

	if (t->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN) {
		if (t->auto_join_thread_group) {
			tg = t->auto_join_thread_group;
		}
	} else {
		if (t->work_interval_thread_group) {
			tg = t->work_interval_thread_group;
		}
	}

	*resolved_tg = tg;
	return tg != cur_tg;
}

#if CONFIG_PREADOPT_TG

/*
 * This function is always called after the hierarchy has been resolved. The
 * caller holds the thread lock
 */
static inline void
thread_assert_has_valid_thread_group(thread_t t)
{
	__assert_only struct thread_group *home_tg = thread_group_get_home_group(t);

	assert(thread_get_reevaluate_tg_hierarchy_locked(t) == false);

	__assert_only struct thread_group *resolved_tg;
	assert(thread_compute_resolved_thread_group(t, &resolved_tg) == false);

	assert((t->thread_group == home_tg) ||
	    (t->thread_group == t->preadopt_thread_group) ||
	    (t->thread_group == t->bank_thread_group) ||
	    (t->thread_group == t->auto_join_thread_group) ||
	    (t->thread_group == t->work_interval_thread_group));
}
#endif

/*
 * This function is called when the thread group hierarchy on the thread_t is
 * resolved and t->thread_group is the result of the hierarchy resolution. Once
 * this has happened, there is state that needs to be cleared up which is
 * handled by this function.
 *
 * Prior to this call, we should have either
 * a) Resolved the hierarchy and discovered no change needed
 * b) Resolved the hierarchy and modified the t->thread_group
 */
static void
thread_mark_thread_group_hierarchy_resolved(thread_t __unused t)
{
#if CONFIG_PREADOPT_TG
	/*
	 * We have just reevaluated the thread's hierarchy so we don't need to do it
	 * again later.
	 */
	thread_clear_reevaluate_tg_hierarchy_locked(t);

	/*
	 * Clear the old_preadopt_thread_group field whose sole purpose was to make
	 * sure that t->thread_group didn't have a dangling pointer.
	 */
	thread_assert_has_valid_thread_group(t);

	if (t->old_preadopt_thread_group) {
		thread_group_deallocate_safe(t->old_preadopt_thread_group);
		t->old_preadopt_thread_group = NULL;
	}
#endif
}

/*
 * Called with thread lock held, always called on self.  This function simply
 * moves the thread to the right clutch scheduler bucket and informs CLPC of the
 * change
 */
static void
thread_notify_thread_group_change_self(thread_t t, struct thread_group * __unused old_tg,
    struct thread_group * __unused new_tg)
{
	assert(current_thread() == t);
	assert(old_tg != new_tg);
	assert(t->thread_group == new_tg);

	uint64_t ctime = mach_approximate_time();
	uint64_t arg1, arg2;
	machine_thread_going_on_core(t, thread_get_urgency(t, &arg1, &arg2), 0, 0, ctime);
	machine_switch_perfcontrol_state_update(THREAD_GROUP_UPDATE, ctime, 0, t);
}

/*
 * Called on any thread with thread lock. Updates the thread_group field on the
 * thread with the resolved thread group and always make necessary clutch
 * scheduler callouts. If the thread group is being modified on self,
 * then also make necessary CLPC callouts.
 */
static void
thread_set_resolved_thread_group(thread_t t, struct thread_group *old_tg,
    struct thread_group *resolved_tg, bool on_self)
{
	t->thread_group = resolved_tg;

	/* Thread is either running already or is runnable but not on a runqueue */
	assert((t->state & (TH_RUN | TH_IDLE)) == TH_RUN);
	assert(t->runq == PROCESSOR_NULL);

	struct thread_group *home_tg = thread_group_get_home_group(t);
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
	    thread_group_id(old_tg), thread_group_id(resolved_tg),
	    (uintptr_t)thread_tid(t), thread_group_id(home_tg));

#if CONFIG_PREADOPT_TG
	if (resolved_tg == t->preadopt_thread_group) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT),
		    thread_group_id(old_tg), thread_group_id(resolved_tg),
		    thread_tid(t), thread_group_id(home_tg));
	}
#endif

#if CONFIG_SCHED_CLUTCH
	sched_clutch_t old_clutch = (old_tg) ? &(old_tg->tg_sched_clutch) : NULL;
	sched_clutch_t new_clutch = (resolved_tg) ? &(resolved_tg->tg_sched_clutch) : NULL;
	if (SCHED_CLUTCH_THREAD_ELIGIBLE(t)) {
		sched_clutch_thread_clutch_update(t, old_clutch, new_clutch);
	}
#endif

	if (on_self) {
		assert(t == current_thread());
		thread_notify_thread_group_change_self(t, old_tg, resolved_tg);
	}

	thread_mark_thread_group_hierarchy_resolved(t);
}

/* Caller has thread lock. Always called on self */
static void
thread_resolve_thread_group_hierarchy_self_locked(thread_t t, __unused bool clear_preadopt)
{
	assert(current_thread() == t);

#if CONFIG_PREADOPT_TG
	struct thread_group *preadopt_tg = NULL;
	if (clear_preadopt) {
		if (t->preadopt_thread_group) {
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT_CLEAR),
			    (uintptr_t)thread_tid(t), thread_group_id(t->preadopt_thread_group), 0, 0);

			preadopt_tg = t->preadopt_thread_group;
			t->preadopt_thread_group = NULL;
		}
	}
#endif

	struct thread_group *resolved_tg = NULL;
	bool needs_change = thread_compute_resolved_thread_group(t, &resolved_tg);

	if (needs_change) {
		struct thread_group *old_tg = t->thread_group;
		thread_set_resolved_thread_group(t, old_tg, resolved_tg, true);
	}

	/*
	 * Regardless of whether we modified the t->thread_group above or not, the
	 * hierarchy is now resolved
	 */
	thread_mark_thread_group_hierarchy_resolved(t);

#if CONFIG_PREADOPT_TG
	if (preadopt_tg) {
		thread_group_deallocate_safe(preadopt_tg);
	}
#endif
}

/*
 * Caller has thread lock, never called on self, always called on a thread not
 * on a runqueue. This is called from sched_prim.c. Counter part for calling on
 * self is thread_resolve_thread_group_hierarchy_self
 */
#if CONFIG_PREADOPT_TG
void
thread_resolve_and_enforce_thread_group_hierarchy_if_needed(thread_t t)
{
	assert(t != current_thread());
	assert(t->runq == NULL);

	if (thread_get_reevaluate_tg_hierarchy_locked(t)) {
		struct thread_group *resolved_tg = NULL;

		bool needs_change = thread_compute_resolved_thread_group(t, &resolved_tg);
		if (needs_change) {
			struct thread_group *old_tg = t->thread_group;
			thread_set_resolved_thread_group(t, old_tg, resolved_tg, false);
		}

		/*
		 * Regardless of whether we modified the t->thread_group above or not,
		 * the hierarchy is now resolved
		 */
		thread_mark_thread_group_hierarchy_resolved(t);
	}
}
#endif

#if CONFIG_PREADOPT_TG
/*
 * The thread being passed can be the current thread and it can also be another
 * thread which is running on another core. This function is called with spin
 * locks held (kq and wq lock) but the thread lock is not held by caller.
 *
 * The thread always takes a +1 on the thread group and will release the
 * previous preadoption thread group's reference or stash it.
 */
void
thread_set_preadopt_thread_group(thread_t t, struct thread_group *tg)
{
	spl_t s = splsched();
	thread_lock(t);

	/*
	 * Assert that this is never called on WindowServer when it has already
	 * issued a block callout to CLPC.
	 *
	 * This should never happen because we don't ever call
	 * thread_set_preadopt_thread_group on a servicer after going out to
	 * userspace unless we are doing so to/after an unbind
	 */
	assert((t->options & TH_OPT_IPC_TG_BLOCKED) == 0);

	struct thread_group *old_tg = t->thread_group;
	struct thread_group *home_tg = thread_group_get_home_group(t);

	/*
	 * Since the preadoption thread group can disappear from under you, we need
	 * to make sure that the thread_group pointer is always pointing to valid
	 * memory.
	 *
	 * We run the risk of the thread group pointer pointing to dangling memory
	 * when the following happens:
	 *
	 * a) We update the preadopt_thread_group
	 * b) We resolve hierarchy and need to change the resolved_thread_group
	 * c) For some reason, we are not able to do so and we need to set the
	 * resolved thread group later.
	 */

	/* take the ref from the thread */
	struct thread_group *old_preadopt_tg = t->preadopt_thread_group;

	if (tg == NULL) {
		t->preadopt_thread_group = NULL;
		if (old_preadopt_tg != NULL) {
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT_CLEAR),
			    thread_tid(t), thread_group_id(old_preadopt_tg), 0, 0);
		}
	} else {
		t->preadopt_thread_group = thread_group_retain(tg);
	}

	struct thread_group *resolved_tg = NULL;
	bool needs_change = thread_compute_resolved_thread_group(t, &resolved_tg);
	if (!needs_change) {
		/*
		 * Setting preadoption thread group didn't change anything, simply mark
		 * the hierarchy as resolved and exit.
		 */
		thread_mark_thread_group_hierarchy_resolved(t);
		goto out;
	}

	if (t != current_thread()) {
		/*
		 * We're modifying the thread group of another thread, we need to take
		 * action according to the state of the other thread.
		 *
		 * If the thread is runnable and not yet running, try removing it from
		 * the runq, modify it's TG and then reinsert it for reevaluation. If it
		 * isn't runnable (already running or started running concurrently, or
		 * if it is waiting), then mark a bit having the thread reevaluate its
		 * own hierarchy the next time it is being inserted into a runq
		 */
		if ((t->state & TH_RUN) && (t->runq != PROCESSOR_NULL)) {
			/* Thread is runnable but not running */

			bool removed_from_runq = thread_run_queue_remove(t);
			if (removed_from_runq) {
				thread_set_resolved_thread_group(t, old_tg, resolved_tg, false);

				KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT),
				    thread_group_id(old_tg), thread_group_id(tg),
				    (uintptr_t)thread_tid(t), thread_group_id(home_tg));

				thread_run_queue_reinsert(t, SCHED_TAILQ);
			} else {
				/*
				 * We failed to remove it from the runq - it probably started
				 * running, let the thread reevaluate the next time it gets
				 * enqueued on a runq
				 */
				thread_set_reevaluate_tg_hierarchy_locked(t);

				KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT_NEXTTIME),
				    thread_group_id(old_tg), thread_group_id(tg),
				    (uintptr_t)thread_tid(t), thread_group_id(home_tg));
			}
		} else {
			/*
			 * The thread is not runnable or it is running already - let the
			 * thread reevaluate the next time it gets enqueued on a runq
			 */
			thread_set_reevaluate_tg_hierarchy_locked(t);

			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT_NEXTTIME),
			    thread_group_id(old_tg), thread_group_id(tg),
			    (uintptr_t)thread_tid(t), thread_group_id(home_tg));
		}
	} else {
		/* We're modifying thread group on ourselves */
		thread_set_resolved_thread_group(t, old_tg, resolved_tg, true);

		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_PREADOPT),
		    thread_group_id(old_tg), thread_group_id(tg),
		    thread_tid(t), thread_group_id(home_tg));
	}

out:
	if (thread_get_reevaluate_tg_hierarchy_locked(t)) {
		assert(t->thread_group == old_tg);
		/*
		 * We need to reevaluate TG hierarchy later as a result of this
		 * `thread_set_preadopt_thread_group` operation. This means that the
		 * thread group on the thread was pointing to either the home thread
		 * group, the preadoption thread group we just replaced, or the old
		 * preadoption thread group stashed on the thread.
		 */
		assert(t->thread_group == home_tg ||
		    t->thread_group == old_preadopt_tg ||
		    t->old_preadopt_thread_group);

		if (t->thread_group == old_preadopt_tg) {
			/*
			 * t->thread_group is pointing to the preadopt thread group we just
			 * replaced. This means the hierarchy was resolved before this call.
			 * Assert that there was no old_preadopt_thread_group on the thread.
			 */
			assert(t->old_preadopt_thread_group == NULL);
			/*
			 * Since t->thread_group is still pointing to the old preadopt thread
			 * group - we need to keep it alive until we reevaluate the hierarchy
			 * next
			 */
			t->old_preadopt_thread_group = old_tg; // transfer ref back to thread
		} else if (old_preadopt_tg != NULL) {
			thread_group_deallocate_safe(old_preadopt_tg);
		}
	} else {
		/* We resolved the hierarchy just now */
		thread_assert_has_valid_thread_group(t);

		/*
		 * We don't need the old preadopt thread group that we stashed in our
		 * local variable, drop it.
		 */
		if (old_preadopt_tg) {
			thread_group_deallocate_safe(old_preadopt_tg);
		}
	}
	thread_unlock(t);
	splx(s);
	return;
}

#endif

/*
 * thread_set_thread_group()
 *
 * Caller must guarantee lifetime of the thread group for the life of the call -
 * this overrides the thread group without going through the hierarchy
 * resolution. This is for special thread groups like the VM and IO thread
 * groups only.
 */
static void
thread_set_thread_group(thread_t t, struct thread_group *tg)
{
	struct thread_group *home_tg = thread_group_get_home_group(t);
	struct thread_group *old_tg = NULL;

	spl_t s = splsched();
	old_tg = t->thread_group;

	if (old_tg != tg) {
		thread_lock(t);

		assert((t->options & TH_OPT_IPC_TG_BLOCKED) == 0);
		t->thread_group = tg;

		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
		    thread_group_id(old_tg), thread_group_id(tg),
		    (uintptr_t)thread_tid(t), thread_group_id(home_tg));

		thread_notify_thread_group_change_self(t, old_tg, tg);

		thread_unlock(t);
	}

	splx(s);
}

/* Called without the thread lock held, called on current thread */
void
thread_group_set_bank(thread_t t, struct thread_group *tg)
{
	assert(current_thread() == t);
	/* boot arg disables groups in bank */
	if (tg_set_by_bankvoucher == FALSE) {
		return;
	}

	spl_t s = splsched();
	thread_lock(t);

	/* This is a borrowed reference from the current bank voucher */
	t->bank_thread_group = tg;

	assert((t->options & TH_OPT_IPC_TG_BLOCKED) == 0);
	thread_resolve_thread_group_hierarchy_self_locked(t, tg != NULL);

	thread_unlock(t);
	splx(s);
}

#if CONFIG_SCHED_AUTO_JOIN
/*
 * thread_group_set_autojoin_thread_group_locked()
 *
 * Sets the thread group of a thread based on auto-join rules and reevaluates
 * the hierarchy.
 *
 * Preconditions:
 * - Thread must not be part of a runq (freshly made runnable threads or terminating only)
 * - Thread must be locked by the caller already
 */
void
thread_set_autojoin_thread_group_locked(thread_t t, struct thread_group *tg)
{
	assert(t->runq == PROCESSOR_NULL);

	assert((t->options & TH_OPT_IPC_TG_BLOCKED) == 0);
	t->auto_join_thread_group = tg;

	struct thread_group *resolved_tg = NULL;
	bool needs_change = thread_compute_resolved_thread_group(t, &resolved_tg);

	if (needs_change) {
		struct thread_group *old_tg = t->thread_group;
		struct thread_group *home_tg = thread_group_get_home_group(t);

		t->thread_group = resolved_tg;

		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET),
		    thread_group_id(old_tg), thread_group_id(resolved_tg),
		    thread_tid(t), thread_group_id(home_tg));
		/*
		 * If the thread group is being changed for the current thread, callout
		 * to CLPC to update the thread's information at that layer. This makes
		 * sure CLPC has consistent state when the current thread is going
		 * off-core.
		 *
		 * Note that we are passing in the PERFCONTROL_CALLOUT_WAKE_UNSAFE flag
		 * to CLPC here (as opposed to 0 in thread_notify_thread_group_change_self)
		 */
		if (t == current_thread()) {
			uint64_t ctime = mach_approximate_time();
			uint64_t arg1, arg2;
			machine_thread_going_on_core(t, thread_get_urgency(t, &arg1, &arg2), 0, 0, ctime);
			machine_switch_perfcontrol_state_update(THREAD_GROUP_UPDATE, ctime, PERFCONTROL_CALLOUT_WAKE_UNSAFE, t);
		}
	}

	thread_mark_thread_group_hierarchy_resolved(t);
}
#endif

/* Thread is not locked. Thread is self */
void
thread_set_work_interval_thread_group(thread_t t, struct thread_group *tg)
{
	assert(current_thread() == t);
	assert(!(t->sched_flags & TH_SFLAG_THREAD_GROUP_AUTO_JOIN));

	/*
	 * We have a work interval, we don't need the preadoption thread group
	 * anymore (ie, it shouldn't be available for us to jump back to it after
	 * the thread leaves the work interval)
	 */
	spl_t s = splsched();
	thread_lock(t);

	t->work_interval_thread_group = tg;
	assert((t->options & TH_OPT_IPC_TG_BLOCKED) == 0);

	thread_resolve_thread_group_hierarchy_self_locked(t, tg != NULL);

	thread_unlock(t);
	splx(s);
}

inline cluster_type_t
thread_group_recommendation(struct thread_group *tg)
{
	if (tg == NULL) {
		return CLUSTER_TYPE_SMP;
	} else {
		return tg->tg_recommendation;
	}
}

inline uint64_t
thread_group_get_id(struct thread_group *tg)
{
	return tg->tg_id;
}

uint32_t
thread_group_count(void)
{
	return tg_count;
}

/*
 * Can only be called while tg cannot be destroyed
 */
inline const char*
thread_group_get_name(struct thread_group *tg)
{
	return tg->tg_name;
}

inline void *
thread_group_get_machine_data(struct thread_group *tg)
{
	return &tg->tg_machine_data;
}

inline uint32_t
thread_group_machine_data_size(void)
{
	return tg_machine_data_size;
}

inline boolean_t
thread_group_uses_immediate_ipi(struct thread_group *tg)
{
	return thread_group_get_id(tg) == THREAD_GROUP_PERF_CONTROLLER && perf_controller_thread_group_immediate_ipi != 0;
}

kern_return_t
thread_group_iterate_stackshot(thread_group_iterate_fn_t callout, void *arg)
{
	struct thread_group *tg;
	int i = 0;
	qe_foreach_element(tg, &tg_queue, tg_queue_chain) {
		if (tg == NULL || !ml_validate_nofault((vm_offset_t)tg, sizeof(struct thread_group))) {
			return KERN_FAILURE;
		}
		callout(arg, i, tg);
		i++;
	}
	return KERN_SUCCESS;
}

void
thread_group_join_io_storage(void)
{
	struct thread_group *tg = thread_group_find_by_id_and_retain(THREAD_GROUP_IO_STORAGE);
	assert(tg != NULL);
	thread_set_thread_group(current_thread(), tg);
}

void
thread_group_join_perf_controller(void)
{
	struct thread_group *tg = thread_group_find_by_id_and_retain(THREAD_GROUP_PERF_CONTROLLER);
	assert(tg != NULL);
	thread_set_thread_group(current_thread(), tg);
}

void
thread_group_vm_add(void)
{
	assert(tg_vm != NULL);
	thread_set_thread_group(current_thread(), thread_group_find_by_id_and_retain(THREAD_GROUP_VM));
}

uint32_t
thread_group_get_flags(struct thread_group *tg)
{
	return tg->tg_flags;
}

void
thread_group_update_recommendation(struct thread_group *tg, cluster_type_t new_recommendation)
{
	/*
	 * Since the tg->tg_recommendation field is read by CPUs trying to determine
	 * where a thread/thread group needs to be placed, it is important to use
	 * atomic operations to update the recommendation.
	 */
	os_atomic_store(&tg->tg_recommendation, new_recommendation, relaxed);
}

#if CONFIG_SCHED_EDGE

int sched_edge_restrict_ut = 1;
int sched_edge_restrict_bg = 1;

void
sched_perfcontrol_thread_group_recommend(__unused void *machine_data, __unused cluster_type_t new_recommendation)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	/*
	 * CLUSTER_TYPE_SMP was used for some debugging support when CLPC dynamic control was turned off.
	 * In more recent implementations, CLPC simply recommends "P-spill" when dynamic control is turned off. So it should
	 * never be recommending CLUSTER_TYPE_SMP for thread groups.
	 */
	assert(new_recommendation != CLUSTER_TYPE_SMP);
	/*
	 * The Edge scheduler expects preferred cluster recommendations for each QoS level within a TG. Until the new CLPC
	 * routine is being called, fake out the call from the old CLPC interface.
	 */
	uint32_t tg_bucket_preferred_cluster[TH_BUCKET_SCHED_MAX] = {0};
	/*
	 * For all buckets higher than UT, apply the recommendation to the thread group bucket
	 */
	for (sched_bucket_t bucket = TH_BUCKET_FIXPRI; bucket < TH_BUCKET_SHARE_UT; bucket++) {
		tg_bucket_preferred_cluster[bucket] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	/* For UT & BG QoS, set the recommendation only if they havent been restricted via sysctls */
	if (!sched_edge_restrict_ut) {
		tg_bucket_preferred_cluster[TH_BUCKET_SHARE_UT] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	if (!sched_edge_restrict_bg) {
		tg_bucket_preferred_cluster[TH_BUCKET_SHARE_BG] = (new_recommendation == pset_type_for_id(0)) ? 0 : 1;
	}
	sched_perfcontrol_preferred_cluster_options_t options = 0;
	if (new_recommendation == CLUSTER_TYPE_P) {
		options |= SCHED_PERFCONTROL_PREFERRED_CLUSTER_MIGRATE_RUNNING;
	}
	sched_edge_tg_preferred_cluster_change(tg, tg_bucket_preferred_cluster, options);
}

void
sched_perfcontrol_edge_matrix_get(sched_clutch_edge *edge_matrix, bool *edge_request_bitmap, uint64_t flags, uint64_t matrix_order)
{
	sched_edge_matrix_get(edge_matrix, edge_request_bitmap, flags, matrix_order);
}

void
sched_perfcontrol_edge_matrix_set(sched_clutch_edge *edge_matrix, bool *edge_changes_bitmap, uint64_t flags, uint64_t matrix_order)
{
	sched_edge_matrix_set(edge_matrix, edge_changes_bitmap, flags, matrix_order);
}

void
sched_perfcontrol_thread_group_preferred_clusters_set(void *machine_data, uint32_t tg_preferred_cluster,
    uint32_t overrides[PERFCONTROL_CLASS_MAX], sched_perfcontrol_preferred_cluster_options_t options)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	uint32_t tg_bucket_preferred_cluster[TH_BUCKET_SCHED_MAX] = {
		[TH_BUCKET_FIXPRI]   = (overrides[PERFCONTROL_CLASS_ABOVEUI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_ABOVEUI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_FG] = (overrides[PERFCONTROL_CLASS_UI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_IN] = (overrides[PERFCONTROL_CLASS_UI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_DF] = (overrides[PERFCONTROL_CLASS_NONUI] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_NONUI] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_UT] = (overrides[PERFCONTROL_CLASS_UTILITY] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_UTILITY] : tg_preferred_cluster,
		[TH_BUCKET_SHARE_BG] = (overrides[PERFCONTROL_CLASS_BACKGROUND] != SCHED_PERFCONTROL_PREFERRED_CLUSTER_OVERRIDE_NONE) ? overrides[PERFCONTROL_CLASS_BACKGROUND] : tg_preferred_cluster,
	};
	sched_edge_tg_preferred_cluster_change(tg, tg_bucket_preferred_cluster, options);
}

#else /* CONFIG_SCHED_EDGE */

void
sched_perfcontrol_thread_group_recommend(__unused void *machine_data, __unused cluster_type_t new_recommendation)
{
	struct thread_group *tg = (struct thread_group *)((uintptr_t)machine_data - offsetof(struct thread_group, tg_machine_data));
	SCHED(thread_group_recommendation_change)(tg, new_recommendation);
}

void
sched_perfcontrol_edge_matrix_get(__unused sched_clutch_edge *edge_matrix, __unused bool *edge_request_bitmap, __unused uint64_t flags, __unused uint64_t matrix_order)
{
}

void
sched_perfcontrol_edge_matrix_set(__unused sched_clutch_edge *edge_matrix, __unused bool *edge_changes_bitmap, __unused uint64_t flags, __unused uint64_t matrix_order)
{
}

void
sched_perfcontrol_thread_group_preferred_clusters_set(__unused void *machine_data, __unused uint32_t tg_preferred_cluster,
    __unused uint32_t overrides[PERFCONTROL_CLASS_MAX], __unused sched_perfcontrol_preferred_cluster_options_t options)
{
}

#endif /* CONFIG_SCHED_EDGE */

/*
 * Can only be called while tg cannot be destroyed.
 * Names can be up to THREAD_GROUP_MAXNAME long and are not necessarily null-terminated.
 */
const char*
sched_perfcontrol_thread_group_get_name(void *machine_data)
{
	struct thread_group *tg = __container_of(machine_data, struct thread_group, tg_machine_data);
	return thread_group_get_name(tg);
}

#endif /* CONFIG_THREAD_GROUPS */
