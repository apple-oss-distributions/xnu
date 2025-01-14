/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <kern/exc_guard.h>
#include <kern/locks.h>
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <kern/sched.h>
#include <libkern/OSAtomic.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/vm_reclaim.h>
#include <os/log.h>
#include <pexpert/pexpert.h>
#include <vm/vm_fault_xnu.h>
#include <vm/vm_map.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_reclaim_internal.h>
#include <vm/vm_sanitize_internal.h>
#include <sys/errno.h>
#include <sys/kdebug.h>
#include <vm/vm_kern_xnu.h>
#include <sys/queue.h>
#include <sys/reason.h>
#include <os/atomic_private.h>
#include <os/refcnt.h>
#include <os/refcnt_internal.h>

#pragma mark Tunables

#define VM_RECLAIM_THRESHOLD_DISABLED 0ULL

TUNABLE(uint32_t, kReclaimChunkSize, "vm_reclaim_chunk_size", 16);
static integer_t kReclaimThreadPriority = BASEPRI_VM;
// Reclaim down to vm_reclaim_max_threshold / vm_reclaim_trim_divisor when doing a trim reclaim operation
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_trim_divisor, "vm_reclaim_trim_divisor", 2);
TUNABLE_DT_DEV_WRITEABLE(uint64_t, vm_reclaim_max_threshold, "/defaults", "kern.vm_reclaim_max_threshold", "vm_reclaim_max_threshold", 0, TUNABLE_DT_NONE);
// Used to debug vm_reclaim kills
TUNABLE(bool, panic_on_kill, "vm_reclaim_panic_on_kill", false);

#pragma mark Declarations
typedef struct proc *proc_t;
extern const char *proc_best_name(struct proc *);
extern kern_return_t kern_return_for_errno(int);
extern int exit_with_guard_exception(void *p, mach_exception_data_type_t code, mach_exception_data_type_t subcode);
struct proc *proc_ref(struct proc *p, int locked);
int proc_rele(proc_t p);
static kern_return_t reclaim_copyin_head(vm_deferred_reclamation_metadata_t metadata, uint64_t *head);
static kern_return_t reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail);
static kern_return_t reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy);

os_refgrp_decl(static, vdrm_refgrp, "vm_reclaim_metadata_refgrp", NULL);

struct vm_deferred_reclamation_metadata_s {
	/*
	 * Global list containing every reclamation buffer. Protected by the
	 * reclamation_buffers_lock.
	 */
	TAILQ_ENTRY(vm_deferred_reclamation_metadata_s) vdrm_list;
	/*
	 * A list containing buffers that are ripe for reclamation. Protected by
	 * the async_reclamation_buffers_lock.
	 */
	TAILQ_ENTRY(vm_deferred_reclamation_metadata_s) vdrm_async_list;
	/* Protects all struct fields (except denoted otherwise) */
	decl_lck_mtx_data(, vdrm_lock);
	decl_lck_mtx_gate_data(, vdrm_gate);
	/*
	 * The task owns this structure but we maintain a backpointer here
	 * so that we can send an exception if we hit an error.
	 * Since this is a backpointer we don't hold a reference (it's a weak pointer).
	 */
	task_t vdrm_task;
	pid_t vdrm_pid;
	vm_map_t vdrm_map;
	/*
	 * The owning task holds a ref on this object. When the task dies, it
	 * will set vdrm_task := NULL and drop its ref. Threads operating on the buffer
	 * should hold a +1 on the metadata structure to ensure it's validity.
	 */
	os_refcnt_t vdrm_refcnt;
	user_addr_t vdrm_reclaim_buffer;
	mach_vm_size_t vdrm_buffer_size;
	user_addr_t vdrm_reclaim_indices;
	uint64_t vdrm_reclaimed_at;
	/*
	 * These two values represent running sums of bytes placed in the buffer and bytes reclaimed out of the buffer
	 * cumulatively. Both values are in terms of virtual memory, so they give an upper bound
	 * on the amount of physical memory that can be reclaimed.
	 * To get an estimate of the current amount of VA in the buffer do vdrm_num_bytes_reclaimed - vdrm_num_bytes_put_in_buffer.
	 * Note that neither value is protected by the vdrm_lock.
	 */
	_Atomic size_t vdrm_num_bytes_put_in_buffer;
	_Atomic size_t vdrm_num_bytes_reclaimed;
	/*
	 * The number of threads waiting for a pending reclamation
	 * on this buffer to complete. Protected by the
	 * async_reclamation_buffers_lock.
	 */
	uint32_t vdrm_waiters;
};
static void vmdr_process_async_reclamation_list(void);

extern void *proc_find(int pid);
extern task_t proc_task(proc_t);

#pragma mark Globals
static KALLOC_TYPE_DEFINE(vm_reclaim_metadata_zone, struct vm_deferred_reclamation_metadata_s, KT_DEFAULT);
static LCK_GRP_DECLARE(vm_reclaim_lock_grp, "vm_reclaim");
static os_log_t vm_reclaim_log_handle;

/*
 * We maintain two lists of reclamation buffers.
 * The reclamation_buffers list contains every buffer in the system.
 * The async_reclamation_buffers_list contains buffers that are ripe for reclamation.
 * Each list has its own lock.
 */
static TAILQ_HEAD(, vm_deferred_reclamation_metadata_s) reclamation_buffers = TAILQ_HEAD_INITIALIZER(reclamation_buffers);

static TAILQ_HEAD(, vm_deferred_reclamation_metadata_s) async_reclamation_buffers = TAILQ_HEAD_INITIALIZER(async_reclamation_buffers);
/*
 * The reclamation_buffers_lock protects the reclamation_buffers list.
 * It must be held when iterating over the list or manipulating the list.
 * It should be dropped when acting on a specific metadata entry after acquiring the vdrm_lock.
 */
LCK_MTX_DECLARE(reclamation_buffers_lock, &vm_reclaim_lock_grp);
LCK_MTX_DECLARE(async_reclamation_buffers_lock, &vm_reclaim_lock_grp);
static uint64_t reclamation_counter; // generation count for global reclaims


static void vmdr_list_append_locked(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_list_remove_locked(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_async_list_append_locked(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_async_list_remove_locked(vm_deferred_reclamation_metadata_t metadata);

static SECURITY_READ_ONLY_LATE(thread_t) vm_reclaim_thread;
static void reclaim_thread(void *param __unused, wait_result_t wr __unused);
static void vmdr_metadata_release(vm_deferred_reclamation_metadata_t metadata);

#pragma mark Implementation

static vm_deferred_reclamation_metadata_t
vmdr_metadata_alloc(
	task_t                  task,
	user_addr_t             buffer,
	mach_vm_size_t          size,
	user_addr_t             indices)
{
	vm_deferred_reclamation_metadata_t metadata;
	vm_map_t map = task->map;

	assert(!map->is_nested_map);

	metadata = zalloc_flags(vm_reclaim_metadata_zone, Z_WAITOK | Z_ZERO);
	lck_mtx_init(&metadata->vdrm_lock, &vm_reclaim_lock_grp, LCK_ATTR_NULL);
	lck_mtx_gate_init(&metadata->vdrm_lock, &metadata->vdrm_gate);
	os_ref_init(&metadata->vdrm_refcnt, &vdrm_refgrp);

	metadata->vdrm_task = task;
	/*
	 * Forked children will not yet have a pid. Lazily set the pid once the
	 * task has been started.
	 *
	 * TODO: do not support buffer initialization during fork and have libmalloc
	 * initialize the buffer after fork. (rdar://124295804)
	 */
	metadata->vdrm_pid = 0;
	metadata->vdrm_map = map;
	metadata->vdrm_reclaim_buffer = buffer;
	metadata->vdrm_buffer_size = size;
	metadata->vdrm_reclaim_indices = indices;

	/*
	 * we do not need to hold a lock on `task` because this is called
	 * either at fork() time or from the context of current_task().
	 */
	vm_map_reference(map);
	return metadata;
}

static void
vmdr_metadata_free(vm_deferred_reclamation_metadata_t metadata)
{
	assert3u(os_ref_get_count(&metadata->vdrm_refcnt), ==, 0);
	vm_map_deallocate(metadata->vdrm_map);
	lck_mtx_destroy(&metadata->vdrm_lock, &vm_reclaim_lock_grp);
	lck_mtx_gate_destroy(&metadata->vdrm_lock, &metadata->vdrm_gate);
	zfree(vm_reclaim_metadata_zone, metadata);
}

static inline __result_use_check
kern_return_t
vm_deferred_reclamation_buffer_init_internal_sanitize(
	vm_map_t           map,
	mach_vm_address_ut address_u,
	mach_vm_size_ut    size_u,
	mach_vm_address_t  *address,
	mach_vm_size_t     *size)
{
	/* Sanitize addr/size separately since addr is only a hint. */
	*address = vm_sanitize_addr(map, address_u);

	static_assert(
		sizeof(struct mach_vm_reclaim_buffer_v1_s) < FOURK_PAGE_SIZE,
		"If growing struct mach_vm_reclaim_buffer_v1_s beyond 4K, "
		"add a runtime check on size to prevent subtraction "
		"underflow.");
	return vm_sanitize_size(
		0,
		size_u,
		VM_SANITIZE_CALLER_MACH_VM_DEFERRED_RECLAMATION_BUFFER_INIT,
		map,
		VM_SANITIZE_FLAGS_SIZE_ZERO_FAILS,
		size);
}

kern_return_t
vm_deferred_reclamation_buffer_init_internal(
	task_t             task,
	mach_vm_address_ut *address_u,
	mach_vm_size_ut    size_u)
{
	kern_return_t kr = KERN_FAILURE;
	mach_vm_address_t address;
	mach_vm_size_t size;
	vm_deferred_reclamation_metadata_t metadata = NULL;
	vm_map_t map;
	uint64_t head = 0, tail = 0, busy = 0;
	static bool reclaim_disabled_logged = false;

	if (task == TASK_NULL || address_u == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	map = task->map;

	kr = vm_deferred_reclamation_buffer_init_internal_sanitize(
		map,
		*address_u,
		size_u,
		&address,
		&size);
	if (__improbable(kr != KERN_SUCCESS)) {
		return vm_sanitize_get_kr(kr);
	}

	if (!vm_reclaim_max_threshold) {
		if (!reclaim_disabled_logged) {
			/* Avoid logging failure for every new process */
			reclaim_disabled_logged = true;
			os_log_error(vm_reclaim_log_handle,
			    "vm_reclaim: failed to initialize vmdr buffer - reclaim is disabled (%llu)\n",
			    vm_reclaim_max_threshold);
		}
		return KERN_NOT_SUPPORTED;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_START,
	    task_pid(task), size);
	/*
	 * TODO: If clients other than libmalloc adopt deferred reclaim, a
	 * different tag should be given
	 */
	/*
	 * `address` was sanitized under the assumption that we'll only use
	 * it as a hint (overflow checks were used) so we must pass the
	 * anywhere flag.
	 */
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE_PERMANENT(
		.vm_tag = VM_MEMORY_MALLOC);
	kr = mach_vm_allocate_kernel(
		map,
		vm_sanitize_wrap_addr_ref(&address),
		vm_sanitize_wrap_size(size),
		vmk_flags);
	if (kr != KERN_SUCCESS) {
		os_log_error(vm_reclaim_log_handle, "vm_reclaim: failed to allocate VA for reclaim "
		    "buffer (%d) - %s [%d]\n", kr, task_best_name(task), task_pid(task));
		return kr;
	}
	assert3u(address, !=, 0);

	user_addr_t buffer = address + \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries);
	/*
	 * vm_sanitize_size above guarantees that size is at least one map
	 * page. This guarantees that subtraction below doesn't underflow.
	 */
	mach_vm_size_t buffer_size = size - \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries);
	user_addr_t indices = address + \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, indices);

	metadata = vmdr_metadata_alloc(task, buffer, buffer_size, indices);

	/*
	 * Validate the starting indices.
	 */
	kr = reclaim_copyin_busy(metadata, &busy);
	if (kr != KERN_SUCCESS) {
		goto out;
	}
	kr = reclaim_copyin_head(metadata, &head);
	if (kr != KERN_SUCCESS) {
		goto out;
	}
	kr = reclaim_copyin_tail(metadata, &tail);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	if (head != 0 || tail != 0 || busy != 0) {
		os_log_error(vm_reclaim_log_handle, "vm_reclaim: indices were not "
		    "zero-initialized\n");
		kr = KERN_INVALID_ARGUMENT;
		goto out;
	}

	/*
	 * Publish the metadata to the task & global buffer list. This must be
	 * done under the task lock to synchronize with task termination - i.e.
	 * task_terminate_internal is guaranteed to see the published metadata and
	 * tear it down.
	 */
	lck_mtx_lock(&reclamation_buffers_lock);
	task_lock(task);

	if (!task_is_active(task) || task_is_halting(task)) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: failed to initialize buffer on dying task %s [%d]", task_best_name(task), task_pid(task));
		kr = KERN_ABORTED;
		goto fail_task;
	}
	if (task->deferred_reclamation_metadata != NULL) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: tried to overwrite existing reclaim buffer for %s [%d]", task_best_name(task), task_pid(task));
		kr = KERN_INVALID_ARGUMENT;
		goto fail_task;
	}

	vmdr_list_append_locked(metadata);

	task->deferred_reclamation_metadata = metadata;

	task_unlock(task);
	lck_mtx_unlock(&reclamation_buffers_lock);

	*address_u = vm_sanitize_wrap_addr(address);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    task_pid(task), KERN_SUCCESS, address);
	return KERN_SUCCESS;

fail_task:
	task_unlock(task);
	lck_mtx_unlock(&reclamation_buffers_lock);

out:
	vmdr_metadata_release(metadata);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    task_pid(task), kr);
	return kr;
}

#pragma mark Synchronization

static inline void
vmdr_metadata_lock(vm_deferred_reclamation_metadata_t metadata)
{
	lck_mtx_lock(&metadata->vdrm_lock);
}

static inline void
vmdr_metadata_unlock(vm_deferred_reclamation_metadata_t metadata)
{
	lck_mtx_unlock(&metadata->vdrm_lock);
}

static inline void
vmdr_metadata_assert_owned_locked(vm_deferred_reclamation_metadata_t metadata)
{
	lck_mtx_gate_assert(&metadata->vdrm_lock, &metadata->vdrm_gate,
	    GATE_ASSERT_HELD);
}

static inline void
vmdr_metadata_assert_owned(vm_deferred_reclamation_metadata_t metadata)
{
#if MACH_ASSERT
	vmdr_metadata_lock(metadata);
	vmdr_metadata_assert_owned_locked(metadata);
	vmdr_metadata_unlock(metadata);
#else /* MACH_ASSERT */
	(void)metadata;
#endif /* MACH_ASSERT */
}


/*
 * Try to take ownership of the buffer. Returns true if successful.
 */
static bool
vmdr_metadata_try_own_locked(vm_deferred_reclamation_metadata_t metadata)
{
	kern_return_t kr = lck_mtx_gate_try_close(&metadata->vdrm_lock,
	    &metadata->vdrm_gate);
	return kr == KERN_SUCCESS;
}

static void
vmdr_metadata_own_locked(vm_deferred_reclamation_metadata_t metadata)
{
	__assert_only gate_wait_result_t wait_result;
	if (!vmdr_metadata_try_own_locked(metadata)) {
		wait_result = lck_mtx_gate_wait(
			&metadata->vdrm_lock, &metadata->vdrm_gate, LCK_SLEEP_DEFAULT,
			THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		assert(wait_result == GATE_HANDOFF);
	}
}

/*
 * Set the current thread as the owner of a reclaim buffer. May block. Will
 * propagate priority.
 */
static void
vmdr_metadata_own(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_lock(metadata);
	vmdr_metadata_own_locked(metadata);
	vmdr_metadata_unlock(metadata);
}

static void
vmdr_metadata_disown_locked(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_assert_owned_locked(metadata);
	lck_mtx_gate_handoff(&metadata->vdrm_lock, &metadata->vdrm_gate,
	    GATE_HANDOFF_OPEN_IF_NO_WAITERS);
}

/*
 * Release ownership of a reclaim buffer and wakeup any threads waiting for
 * ownership. Must be called from the thread that acquired ownership.
 */
static void
vmdr_metadata_disown(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_lock(metadata);
	vmdr_metadata_disown_locked(metadata);
	vmdr_metadata_unlock(metadata);
}

static void
vmdr_metadata_retain(vm_deferred_reclamation_metadata_t metadata)
{
	os_ref_retain(&metadata->vdrm_refcnt);
}

static void
vmdr_metadata_release(vm_deferred_reclamation_metadata_t metadata)
{
	if (os_ref_release(&metadata->vdrm_refcnt) == 0) {
		vmdr_metadata_free(metadata);
	}
}

void
vm_deferred_reclamation_buffer_own(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_own(metadata);
}

void
vm_deferred_reclamation_buffer_disown(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_disown(metadata);
}

#pragma mark Global Queue Management

static void
vmdr_list_remove_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert(metadata->vdrm_list.tqe_prev != NULL);
	TAILQ_REMOVE(&reclamation_buffers, metadata, vdrm_list);
	metadata->vdrm_list.tqe_prev = NULL;
	metadata->vdrm_list.tqe_next = NULL;
}

static void
vmdr_list_append_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert(metadata->vdrm_list.tqe_prev == NULL);
	TAILQ_INSERT_TAIL(&reclamation_buffers, metadata, vdrm_list);
}

static void
vmdr_async_list_remove_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&async_reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert(metadata->vdrm_async_list.tqe_prev != NULL);
	TAILQ_REMOVE(&async_reclamation_buffers, metadata, vdrm_async_list);
	metadata->vdrm_async_list.tqe_prev = NULL;
	metadata->vdrm_async_list.tqe_next = NULL;
}

static void
vmdr_async_list_append_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&async_reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert(metadata->vdrm_async_list.tqe_prev == NULL);
	TAILQ_INSERT_TAIL(&async_reclamation_buffers, metadata, vdrm_async_list);
}

static bool
vmdr_metadata_has_pending_reclamation(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&async_reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	return metadata->vdrm_async_list.tqe_prev != NULL;
}

#pragma mark Lifecycle

void
vm_deferred_reclamation_buffer_uninstall(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	/*
	 * First remove the buffer from the global list so no one else can get access to it.
	 */
	lck_mtx_lock(&reclamation_buffers_lock);
	vmdr_list_remove_locked(metadata);
	lck_mtx_unlock(&reclamation_buffers_lock);

	/*
	 * Now remove it from the async list (if present)
	 */
	lck_mtx_lock(&async_reclamation_buffers_lock);
	if (vmdr_metadata_has_pending_reclamation(metadata)) {
		vmdr_async_list_remove_locked(metadata);
	}
	lck_mtx_unlock(&async_reclamation_buffers_lock);
}

void
vm_deferred_reclamation_buffer_deallocate(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	/* Buffer must be uninstalled before being deallocated */
	assert(metadata->vdrm_async_list.tqe_prev == NULL);
	assert(metadata->vdrm_async_list.tqe_next == NULL);
	assert(metadata->vdrm_list.tqe_prev == NULL);
	assert(metadata->vdrm_list.tqe_next == NULL);
	/*
	 * The task is dropping its ref on this buffer. First remove the buffer's
	 * back-reference to the task so that any threads currently operating on
	 * this buffer do not try to operate on the dead/dying task
	 */
	vmdr_metadata_lock(metadata);
	metadata->vdrm_task = TASK_NULL;
	vmdr_metadata_unlock(metadata);

	vmdr_metadata_release(metadata);
}

#pragma mark Exception Delivery

static void
reclaim_kill_with_reason(
	vm_deferred_reclamation_metadata_t metadata,
	unsigned reason,
	mach_exception_data_type_t subcode)
{
	unsigned int guard_type = GUARD_TYPE_VIRT_MEMORY;
	mach_exception_code_t code = 0;
	task_t task;
	proc_t p = NULL;
	boolean_t fatal = TRUE;
	bool killing_self;
	pid_t pid;
	int err;

	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_NOTOWNED);

	EXC_GUARD_ENCODE_TYPE(code, guard_type);
	EXC_GUARD_ENCODE_FLAVOR(code, reason);
	EXC_GUARD_ENCODE_TARGET(code, 0);

	vmdr_metadata_lock(metadata);
	task = metadata->vdrm_task;
	if (task == TASK_NULL || !task_is_active(task) || task_is_halting(task)) {
		/* Task is no longer alive */
		vmdr_metadata_unlock(metadata);
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to deliver guard exception because task "
		    "[%d] is already dead.\n",
		    task ? task_pid(task) : -1);
		return;
	}

	if (panic_on_kill) {
		panic("vm_reclaim: About to kill %p due to %d with subcode %lld\n", task, reason, subcode);
	}

	killing_self = (task == current_task());
	if (!killing_self) {
		task_reference(task);
	}
	assert(task != kernel_task);
	vmdr_metadata_unlock(metadata);

	if (reason == kGUARD_EXC_DEALLOC_GAP) {
		task_lock(task);
		fatal = (task->task_exc_guard & TASK_EXC_GUARD_VM_FATAL);
		task_unlock(task);
	}

	if (!fatal) {
		os_log_info(vm_reclaim_log_handle,
		    "vm_reclaim: Skipping non fatal guard exception.\n");
		goto out;
	}

	pid = task_pid(task);
	if (killing_self) {
		p = get_bsdtask_info(task);
	} else {
		p = proc_find(pid);
		if (p && proc_task(p) != task) {
			os_log_error(vm_reclaim_log_handle,
			    "vm_reclaim: Unable to deliver guard exception because proc is gone & pid rolled over.\n");
			goto out;
		}
	}

	if (!p) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to deliver guard exception because task does not have a proc.\n");
		goto out;
	}

	int flags = PX_DEBUG_NO_HONOR;
	exception_info_t info = {
		.os_reason = OS_REASON_GUARD,
		.exception_type = EXC_GUARD,
		.mx_code = code,
		.mx_subcode = subcode
	};

	err = exit_with_mach_exception(p, info, flags);
	if (err != 0) {
		os_log_error(vm_reclaim_log_handle, "vm_reclaim: Unable to deliver guard exception to %p: %d\n", p, err);
		goto out;
	}


out:
	if (!killing_self) {
		if (p) {
			proc_rele(p);
			p = NULL;
		}
		if (task) {
			task_deallocate(task);
			task = NULL;
		}
	}
}

#pragma mark CopyI/O

static user_addr_t
get_head_ptr(user_addr_t indices)
{
	return indices + offsetof(mach_vm_reclaim_indices_v1_t, head);
}

static user_addr_t
get_tail_ptr(user_addr_t indices)
{
	return indices + offsetof(mach_vm_reclaim_indices_v1_t, tail);
}

static user_addr_t
get_busy_ptr(user_addr_t indices)
{
	return indices + offsetof(mach_vm_reclaim_indices_v1_t, busy);
}

static kern_return_t
reclaim_handle_copyio_error(vm_deferred_reclamation_metadata_t metadata, int result)
{
	if (result != 0 && (result != EFAULT || !vm_fault_get_disabled())) {
		reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_COPYIO_FAILURE,
		    result);
	}
	return kern_return_for_errno(result);
}

/*
 * Helper functions to do copyio on the head, tail, and busy pointers.
 * Note that the kernel will only write to the busy and head pointers.
 * Userspace is not supposed to write to the head or busy pointers, but the kernel
 * must be resilient to that kind of bug in userspace.
 */

static kern_return_t
reclaim_copyin_head(vm_deferred_reclamation_metadata_t metadata, uint64_t *head)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyin_atomic64(head_ptr, head);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy head ptr from 0x%llx: err=%d\n", head_ptr, result);
	}
	return kr;
}

static kern_return_t
reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t tail_ptr = get_tail_ptr(indices);

	result = copyin_atomic64(tail_ptr, tail);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy tail ptr from 0x%llx: err=%d\n", tail_ptr, result);
	}
	return kr;
}

static kern_return_t
reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyin_atomic64(busy_ptr, busy);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy busy ptr from 0x%llx: err=%d\n", busy_ptr, result);
	}
	return kr;
}

static bool
reclaim_copyout_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyout_atomic64(value, busy_ptr);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy %llu to busy ptr at 0x%llx: err=%d\n", value, busy_ptr, result);
	}
	return kr;
}

static bool
reclaim_copyout_head(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyout_atomic64(value, head_ptr);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy %llu to head ptr at 0x%llx: err=%d\n", value, head_ptr, result);
	}
	return kr;
}

#pragma mark Reclamation

/*
 * Reclaim a chunk (kReclaimChunkSize entries) from the buffer.
 *
 * Writes the number of entries reclaimed to `num_reclaimed_out`. Note that
 * there may be zero reclaimable entries in the chunk (they have all been
 * re-used by userspace).
 *
 * Returns:
 *  - KERN_NOT_FOUND if the buffer has been exhausted (head == tail)
 *  - KERN_FAILURE on failure to reclaim -- metadata lock will be dropped
 *    before returning
 */
static kern_return_t
reclaim_chunk(vm_deferred_reclamation_metadata_t metadata,
    size_t *num_reclaimed_out, vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	int result = 0;
	size_t num_reclaimed = 0;
	uint64_t head = 0, tail = 0, busy = 0, num_to_reclaim = 0, new_tail = 0,
	    num_copied = 0, buffer_len = 0;
	user_addr_t indices;
	vm_map_t map = metadata->vdrm_map, old_map;
	mach_vm_reclaim_entry_v1_t reclaim_entries[kReclaimChunkSize];

	assert(metadata != NULL);
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_NOTOWNED);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_START,
	    metadata->vdrm_pid, kReclaimChunkSize);

	buffer_len = metadata->vdrm_buffer_size /
	    sizeof(mach_vm_reclaim_entry_v1_t);

	memset(reclaim_entries, 0, sizeof(reclaim_entries));

	indices = (user_addr_t) metadata->vdrm_reclaim_indices;
	old_map = vm_map_switch(map);

	if (options & RECLAIM_NO_FAULT) {
		vm_fault_disable();
	}

	kr = reclaim_copyin_busy(metadata, &busy);
	if (kr != KERN_SUCCESS) {
		goto fail;
	}
	kr = reclaim_copyin_head(metadata, &head);
	if (kr != KERN_SUCCESS) {
		goto fail;
	}
	kr = reclaim_copyin_tail(metadata, &tail);
	if (kr != KERN_SUCCESS) {
		goto fail;
	}

	if (busy != head) {
		// Userspace overwrote one of the pointers
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Userspace modified head or busy pointer! head: %llu "
		    "(0x%llx) != busy: %llu (0x%llx) | tail = %llu (0x%llx)\n",
		    head, get_head_ptr(indices), busy, get_busy_ptr(indices), tail,
		    get_tail_ptr(indices));
		reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_INDEX_FAILURE,
		    busy);
		kr = KERN_FAILURE;
		goto fail;
	}

	if (tail < head) {
		/*
		 * Userspace is likely in the middle of trying to re-use an entry,
		 * bail on this reclamation.
		 */
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Userspace modified head or tail pointer! head: %llu "
		    "(0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
		    head, get_head_ptr(indices), tail, get_tail_ptr(indices), busy,
		    get_busy_ptr(indices));
		kr = KERN_FAILURE;
		goto fail;
	}

	/*
	 * NB: If any of the copyouts below fail due to faults being disabled,
	 * the buffer may be left in a state where several entries are unusable
	 * until the next reclamation (i.e. busy > head)
	 */
	num_to_reclaim = tail - head;
	while (true) {
		num_to_reclaim = MIN(num_to_reclaim, kReclaimChunkSize);
		if (num_to_reclaim == 0) {
			break;
		}
		busy = head + num_to_reclaim;
		kr = reclaim_copyout_busy(metadata, busy);
		if (kr != KERN_SUCCESS) {
			goto fail;
		}
		os_atomic_thread_fence(seq_cst);
		kr = reclaim_copyin_tail(metadata, &new_tail);
		if (kr != KERN_SUCCESS) {
			goto fail;
		}

		if (new_tail >= busy) {
			/* Got num_to_reclaim entries */
			break;
		}
		tail = new_tail;
		if (tail < head) {
			/*
			 * Userspace is likely in the middle of trying to re-use an entry,
			 * bail on this reclamation
			 */
			os_log_error(vm_reclaim_log_handle,
			    "vm_reclaim: Userspace modified head or tail pointer! head: "
			    "%llu (0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
			    head, get_head_ptr(indices), tail, get_tail_ptr(indices),
			    busy, get_busy_ptr(indices));
			/* Reset busy back to head */
			reclaim_copyout_busy(metadata, head);
			kr = KERN_FAILURE;
			goto fail;
		}
		/* Can't reclaim these entries. Try again */
		num_to_reclaim = tail - head;
		if (num_to_reclaim == 0) {
			/* Nothing left to reclaim. Reset busy to head. */
			kr = reclaim_copyout_busy(metadata, head);
			if (kr != KERN_SUCCESS) {
				goto fail;
			}
			break;
		}
		/*
		 * Note that num_to_reclaim must have gotten smaller since tail got smaller,
		 * so this is gauranteed to converge.
		 */
	}

	while (num_copied < num_to_reclaim) {
		uint64_t memcpy_start_idx = (head % buffer_len);
		uint64_t memcpy_end_idx = memcpy_start_idx + num_to_reclaim - num_copied;
		// Clamp the end idx to the buffer. We'll handle wrap-around in our next go around the loop.
		memcpy_end_idx = MIN(memcpy_end_idx, buffer_len);
		uint64_t num_to_copy = memcpy_end_idx - memcpy_start_idx;

		assert(num_to_copy + num_copied <= kReclaimChunkSize);
		user_addr_t src_ptr = metadata->vdrm_reclaim_buffer +
		    (memcpy_start_idx * sizeof(mach_vm_reclaim_entry_v1_t));
		mach_vm_reclaim_entry_v1_t *dst_ptr = reclaim_entries + num_copied;

		result = copyin(src_ptr, dst_ptr,
		    (num_to_copy * sizeof(mach_vm_reclaim_entry_v1_t)));
		kr = reclaim_handle_copyio_error(metadata, result);
		if (kr != KERN_SUCCESS) {
			if (kr != KERN_MEMORY_ERROR) {
				os_log_error(vm_reclaim_log_handle,
				    "vm_reclaim: Unable to copyin %llu entries in reclaim "
				    "buffer at 0x%llx to 0x%llx: err=%d\n",
				    num_to_copy, src_ptr, (uint64_t) dst_ptr, result);
			}
			goto fail;
		}

		num_copied += num_to_copy;
		head += num_to_copy;
	}

	for (size_t i = 0; i < num_to_reclaim; i++) {
		mach_vm_reclaim_entry_v1_t *entry = &reclaim_entries[i];
		KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_START,
		    metadata->vdrm_pid, entry->address, entry->size,
		    entry->behavior);
		DTRACE_VM4(vm_reclaim_chunk,
		    int, metadata->vdrm_pid,
		    mach_vm_address_t, entry->address,
		    size_t, entry->size,
		    mach_vm_reclaim_behavior_v1_t, entry->behavior);
		if (entry->address != 0 && entry->size != 0) {
			switch (entry->behavior) {
			case MACH_VM_RECLAIM_DEALLOCATE:
				kr = vm_map_remove_guard(map,
				    vm_map_trunc_page(entry->address,
				    VM_MAP_PAGE_MASK(map)),
				    vm_map_round_page(entry->address + entry->size,
				    VM_MAP_PAGE_MASK(map)),
				    VM_MAP_REMOVE_GAPS_FAIL,
				    KMEM_GUARD_NONE).kmr_return;
				if (kr == KERN_INVALID_VALUE) {
					reclaim_kill_with_reason(metadata, kGUARD_EXC_DEALLOC_GAP, entry->address);
					goto fail;
				} else if (kr != KERN_SUCCESS) {
					os_log_error(vm_reclaim_log_handle,
					    "vm_reclaim: Unable to deallocate 0x%llx (%u) from 0x%llx err=%d\n",
					    entry->address, entry->size, (uint64_t) map, kr);
					reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE, kr);
					goto fail;
				}
				break;
			case MACH_VM_RECLAIM_REUSABLE:
				kr = vm_map_behavior_set(map,
				    vm_map_trunc_page(entry->address, VM_MAP_PAGE_MASK(map)),
				    vm_map_round_page(entry->address + entry->size, VM_MAP_PAGE_MASK(map)),
				    VM_BEHAVIOR_REUSABLE);
				if (kr != KERN_SUCCESS) {
					os_log_error(vm_reclaim_log_handle,
					    "vm_reclaim: unable to free(reusable) 0x%llx (%u) for pid %d err=%d\n",
					    entry->address, entry->size, metadata->vdrm_pid, kr);
				}
				break;
			default:
				os_log_error(vm_reclaim_log_handle,
				    "vm_reclaim: attempted to reclaim entry with unsupported behavior %uh",
				    entry->behavior);
				reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE, kr);
				kr = KERN_INVALID_VALUE;
				goto fail;
			}
			num_reclaimed++;
			os_atomic_add(&metadata->vdrm_num_bytes_reclaimed, entry->size, relaxed);
			KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_END,
			    metadata->vdrm_pid, entry->address);
		}
	}

	kr = reclaim_copyout_head(metadata, head);
	if (kr != KERN_SUCCESS) {
		goto fail;
	}

	if (options & RECLAIM_NO_FAULT) {
		vm_fault_enable();
	}
	vm_map_switch(old_map);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_END,
	    metadata->vdrm_pid, num_to_reclaim, num_reclaimed, true);
	*num_reclaimed_out = num_reclaimed;
	if (num_to_reclaim == 0) {
		// We have exhausted the reclaimable portion of the buffer
		return KERN_NOT_FOUND;
	}
	return KERN_SUCCESS;

fail:
	if (options & RECLAIM_NO_FAULT) {
		vm_fault_enable();
	}
	vm_map_switch(old_map);
	*num_reclaimed_out = num_reclaimed;
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_END,
	    metadata->vdrm_pid, num_to_reclaim, num_reclaimed, false);
	return kr;
}

/*
 * Attempts to reclaim until the buffer's estimated number of available bytes
 * is <= num_bytes_reclaimable_threshold. The metadata buffer lock should be
 * held by the caller.
 *
 * Writes the number of entries reclaimed to `num_reclaimed_out`.
 */
static kern_return_t
reclaim_entries_from_buffer(vm_deferred_reclamation_metadata_t metadata,
    size_t num_bytes_reclaimable_threshold, size_t *num_reclaimed_out)
{
	assert(metadata != NULL);
	assert(num_reclaimed_out != NULL);
	vmdr_metadata_assert_owned(metadata);
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_NOTOWNED);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_START, metadata->vdrm_pid);

	size_t num_entries_reclaimed = 0, num_bytes_reclaimed, estimated_reclaimable_bytes, reclaimable_bytes;
	while (true) {
		kern_return_t kr;
		size_t curr_entries_reclaimed = 0;
		num_bytes_reclaimed = os_atomic_load(&metadata->vdrm_num_bytes_reclaimed, relaxed);
		reclaimable_bytes = os_atomic_load(&metadata->vdrm_num_bytes_put_in_buffer, relaxed);
		if (num_bytes_reclaimed > reclaimable_bytes) {
			estimated_reclaimable_bytes = 0;
		} else {
			estimated_reclaimable_bytes = reclaimable_bytes - num_bytes_reclaimed;
		}
		if (reclaimable_bytes <= num_bytes_reclaimable_threshold) {
			break;
		}
		kr = reclaim_chunk(metadata, &curr_entries_reclaimed,
		    RECLAIM_OPTIONS_NONE);
		if (kr == KERN_NOT_FOUND) {
			// Nothing left to reclaim
			break;
		} else if (kr != KERN_SUCCESS) {
			KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_END,
			    metadata->vdrm_pid, num_entries_reclaimed,
			    estimated_reclaimable_bytes, kr);
			*num_reclaimed_out = num_entries_reclaimed;
			return kr;
		}
		num_entries_reclaimed += curr_entries_reclaimed;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_END,
	    metadata->vdrm_pid, num_entries_reclaimed,
	    estimated_reclaimable_bytes, KERN_SUCCESS);
	*num_reclaimed_out = num_entries_reclaimed;
	return KERN_SUCCESS;
}

/*
 * Get the reclamation metadata buffer for the given map.
 */
static vm_deferred_reclamation_metadata_t
get_task_reclaim_metadata(task_t task)
{
	assert(task != NULL);
	vm_deferred_reclamation_metadata_t metadata = NULL;
	task_lock(task);
	metadata = task->deferred_reclamation_metadata;
	task_unlock(task);
	return metadata;
}

kern_return_t
vm_deferred_reclamation_buffer_synchronize_internal(task_t task, size_t num_entries_to_reclaim)
{
	kern_return_t kr;
	vm_deferred_reclamation_metadata_t metadata = NULL;
	size_t total_reclaimed = 0;

	if (!task_is_active(task)) {
		return KERN_FAILURE;
	}

	metadata = get_task_reclaim_metadata(task);
	if (metadata == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vmdr_metadata_own(metadata);

	while (total_reclaimed < num_entries_to_reclaim) {
		size_t num_reclaimed;
		kr = reclaim_chunk(metadata, &num_reclaimed, RECLAIM_OPTIONS_NONE);
		if (kr == KERN_NOT_FOUND) {
			/* buffer has been fully reclaimed from */
			break;
		} else if (kr != KERN_SUCCESS) {
			vmdr_metadata_disown(metadata);
			return kr;
		}

		total_reclaimed += num_reclaimed;
	}

	vmdr_metadata_disown(metadata);
	return KERN_SUCCESS;
}

kern_return_t
vm_deferred_reclamation_buffer_update_reclaimable_bytes_internal(task_t task, size_t reclaimable_bytes)
{
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;
	size_t num_bytes_reclaimed, estimated_reclaimable_bytes, num_bytes_in_buffer, num_reclaimed = 0;
	bool success;
	kern_return_t kr = KERN_SUCCESS;
	if (metadata == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!metadata->vdrm_pid) {
		metadata->vdrm_pid = task_pid(task);
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_START,
	    metadata->vdrm_pid, reclaimable_bytes);

	/*
	 * The client is allowed to make this call in parallel from multiple threads.
	 * Ensure we only ever increase the value of vdrm_num_bytes_put_in_buffer.
	 * If the client's value is smaller than what we've stored, another thread
	 * raced ahead of them and we've already acted on that accounting so this
	 * call should be a no-op.
	 */
	success = os_atomic_rmw_loop(&metadata->vdrm_num_bytes_put_in_buffer, num_bytes_in_buffer,
	    reclaimable_bytes, acquire,
	{
		if (num_bytes_in_buffer > reclaimable_bytes) {
		        os_atomic_rmw_loop_give_up(break);
		}
	});
	if (!success) {
		/* Stale value. Nothing new to reclaim */
		goto done;
	}
	num_bytes_reclaimed = os_atomic_load(&metadata->vdrm_num_bytes_reclaimed, relaxed);

	if (reclaimable_bytes > num_bytes_reclaimed) {
		estimated_reclaimable_bytes = reclaimable_bytes - num_bytes_reclaimed;
		if (estimated_reclaimable_bytes > vm_reclaim_max_threshold) {
			vmdr_metadata_own(metadata);
			kr = reclaim_entries_from_buffer(metadata,
			    vm_reclaim_max_threshold, &num_reclaimed);
			vmdr_metadata_disown(metadata);
		}
	}

done:
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_END,
	    metadata->vdrm_pid, reclaimable_bytes, num_bytes_reclaimed,
	    num_reclaimed);

	return kr;
}

static inline size_t
pick_reclaim_threshold(vm_deferred_reclamation_action_t action)
{
	switch (action) {
	case RECLAIM_FULL:
		return 0;
	case RECLAIM_TRIM:
		return vm_reclaim_max_threshold / vm_reclaim_trim_divisor;
	case RECLAIM_ASYNC:
		return 0;
	}
}

void
vm_deferred_reclamation_reclaim_memory(vm_deferred_reclamation_action_t action, vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	size_t num_reclaimed;
	size_t reclaim_threshold;

	switch (action) {
	case RECLAIM_ASYNC:
		lck_mtx_lock(&async_reclamation_buffers_lock);
		vmdr_process_async_reclamation_list();
		lck_mtx_unlock(&async_reclamation_buffers_lock);
		break;
	case RECLAIM_TRIM:
	case RECLAIM_FULL:
		reclaim_threshold = pick_reclaim_threshold(action);
		KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ALL_MEMORY) | DBG_FUNC_START,
		    action, reclaim_threshold);
		lck_mtx_lock(&reclamation_buffers_lock);
		reclamation_counter++;
		vm_deferred_reclamation_metadata_t metadata = TAILQ_FIRST(&reclamation_buffers);
		while (metadata != NULL) {
			vmdr_list_remove_locked(metadata);
			vmdr_list_append_locked(metadata);
			vmdr_metadata_retain(metadata);
			lck_mtx_unlock(&reclamation_buffers_lock);

			vmdr_metadata_lock(metadata);

			if (metadata->vdrm_reclaimed_at >= reclamation_counter) {
				// We've already seen this one. We're done
				vmdr_metadata_unlock(metadata);
				lck_mtx_lock(&reclamation_buffers_lock);
				break;
			}
			metadata->vdrm_reclaimed_at = reclamation_counter;

			if (options & RECLAIM_NO_WAIT) {
				bool acquired = vmdr_metadata_try_own_locked(metadata);
				if (!acquired) {
					vmdr_metadata_unlock(metadata);
					goto next;
				}
			} else {
				vmdr_metadata_own_locked(metadata);
			}
			vmdr_metadata_unlock(metadata);

			kr = reclaim_entries_from_buffer(metadata,
			    reclaim_threshold, &num_reclaimed);

			vmdr_metadata_disown(metadata);
next:
			vmdr_metadata_release(metadata);
			lck_mtx_lock(&reclamation_buffers_lock);
			metadata = TAILQ_FIRST(&reclamation_buffers);
		}
		lck_mtx_unlock(&reclamation_buffers_lock);
		KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ALL_MEMORY) | DBG_FUNC_END,
		    reclamation_counter);
		break;
	default:
		panic("Unexpected reclaim action %d", action);
	}
}

void
vm_deferred_reclamation_reclaim_all_memory(
	vm_deferred_reclamation_options_t options)
{
	vm_deferred_reclamation_reclaim_memory(RECLAIM_FULL, options);
}

bool
vm_deferred_reclamation_reclaim_from_task_async(task_t task)
{
	bool queued = false;
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;

	if (metadata != NULL) {
		os_log_debug(vm_reclaim_log_handle, "vm_reclaim: enquequeing %d for "
		    "asynchronous reclamation.\n", task_pid(task));
		lck_mtx_lock(&async_reclamation_buffers_lock);
		// move this buffer to the tail if still on the async list
		if (vmdr_metadata_has_pending_reclamation(metadata)) {
			vmdr_async_list_remove_locked(metadata);
		}
		vmdr_async_list_append_locked(metadata);
		lck_mtx_unlock(&async_reclamation_buffers_lock);
		queued = true;
		thread_wakeup_thread(&vm_reclaim_thread, vm_reclaim_thread);
	}

	return queued;
}

kern_return_t
vm_deferred_reclamation_reclaim_from_task_sync(task_t task, size_t max_entries_to_reclaim)
{
	kern_return_t kr;
	size_t num_reclaimed = 0;
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;

	if (!task_is_active(task) || task_is_halting(task)) {
		return KERN_ABORTED;
	}

	if (metadata != NULL) {
		vmdr_metadata_own(metadata);
		while (num_reclaimed < max_entries_to_reclaim) {
			size_t num_reclaimed_now;
			kr = reclaim_chunk(metadata, &num_reclaimed_now, RECLAIM_OPTIONS_NONE);
			if (kr == KERN_NOT_FOUND) {
				// Nothing left to reclaim
				break;
			} else if (kr != KERN_SUCCESS) {
				/* Lock has already been released and task is being killed. */
				vmdr_metadata_disown(metadata);
				return kr;
			}
			num_reclaimed += num_reclaimed_now;
		}
		vmdr_metadata_disown(metadata);
	}

	return KERN_SUCCESS;
}

vm_deferred_reclamation_metadata_t
vm_deferred_reclamation_buffer_fork(task_t task, vm_deferred_reclamation_metadata_t parent)
{
	vm_deferred_reclamation_metadata_t metadata = NULL;
	vmdr_metadata_assert_owned(parent);

	assert(task->deferred_reclamation_metadata == NULL);
	metadata = vmdr_metadata_alloc(task, parent->vdrm_reclaim_buffer,
	    parent->vdrm_buffer_size, parent->vdrm_reclaim_indices);
	vmdr_metadata_disown(parent);

	lck_mtx_lock(&reclamation_buffers_lock);
	vmdr_list_append_locked(metadata);
	lck_mtx_unlock(&reclamation_buffers_lock);

	return metadata;
}

static void
reclaim_thread_init(void)
{
#if CONFIG_THREAD_GROUPS
	thread_group_vm_add();
#endif
	thread_set_thread_name(current_thread(), "VM_reclaim");
}


static void
vmdr_process_async_reclamation_list(void)
{
	kern_return_t kr;
	size_t total_entries_reclaimed = 0;
	size_t num_tasks_reclaimed = 0;
	LCK_MTX_ASSERT(&async_reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ASYNC_MEMORY) | DBG_FUNC_START);

	vm_deferred_reclamation_metadata_t metadata = TAILQ_FIRST(&async_reclamation_buffers);
	while (metadata != NULL) {
		size_t num_reclaimed;
		vmdr_metadata_retain(metadata);
		/*
		 * NB: It is safe to drop the async list lock without removing the
		 * buffer because only one thread (the reclamation thread) may consume
		 * from the async list. The buffer is guaranteed to still be in the
		 * list when the lock is re-taken.
		 */
		lck_mtx_unlock(&async_reclamation_buffers_lock);

		vmdr_metadata_own(metadata);

		/* NB: Currently the async reclaim thread fully reclaims the buffer */
		kr = reclaim_entries_from_buffer(metadata, 0, &num_reclaimed);
		total_entries_reclaimed += num_reclaimed;
		num_tasks_reclaimed++;

		assert(current_thread()->map == kernel_map);
		vmdr_metadata_disown(metadata);

		lck_mtx_lock(&async_reclamation_buffers_lock);
		/* Wakeup anyone waiting on this buffer getting processed */
		if (metadata->vdrm_waiters) {
			wakeup_all_with_inheritor(&metadata->vdrm_async_list,
			    THREAD_AWAKENED);
		}
		/*
		 * Check that the buffer has not been removed from the async list
		 * while being reclaimed from. This can happen if the task terminates
		 * while the reclamation is in flight.
		 */
		if (vmdr_metadata_has_pending_reclamation(metadata)) {
			vmdr_async_list_remove_locked(metadata);
		}
		vmdr_metadata_release(metadata);
		metadata = TAILQ_FIRST(&async_reclamation_buffers);
	}
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ASYNC_MEMORY) | DBG_FUNC_END,
	    num_tasks_reclaimed, total_entries_reclaimed);
}

__enum_decl(reclaim_thread_state, uint32_t, {
	RECLAIM_THREAD_INIT = 0,
	RECLAIM_THREAD_CONT = 1,
});

static void
reclaim_thread_continue(void)
{
	lck_mtx_lock(&async_reclamation_buffers_lock);

	vmdr_process_async_reclamation_list();
	assert_wait(&vm_reclaim_thread, THREAD_UNINT);

	lck_mtx_unlock(&async_reclamation_buffers_lock);
}

void
reclaim_thread(void *param, wait_result_t wr __unused)
{
	if (param == (void *) RECLAIM_THREAD_INIT) {
		reclaim_thread_init();
	} else {
		assert(param == (void *) RECLAIM_THREAD_CONT);
	}

	reclaim_thread_continue();

	(void) thread_block_parameter(reclaim_thread, (void*) RECLAIM_THREAD_CONT);
}

__startup_func
static void
vm_deferred_reclamation_init(void)
{
	// Note: no-op pending rdar://27006343 (Custom kernel log handles)
	vm_reclaim_log_handle = os_log_create("com.apple.xnu", "vm_reclaim");

	(void)kernel_thread_start_priority(reclaim_thread,
	    (void *)RECLAIM_THREAD_INIT, kReclaimThreadPriority,
	    &vm_reclaim_thread);
}

STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, vm_deferred_reclamation_init);

#if DEVELOPMENT || DEBUG

bool
vm_deferred_reclamation_block_until_pid_has_been_reclaimed(int pid)
{
	vm_deferred_reclamation_metadata_t metadata = NULL;
	proc_t p = proc_find(pid);
	if (p == NULL) {
		return false;
	}
	task_t t = proc_task(p);
	if (t == NULL) {
		proc_rele(p);
		return false;
	}

	task_lock(t);
	if (!task_is_halting(t) && task_is_active(t)) {
		metadata = t->deferred_reclamation_metadata;
		if (metadata != NULL) {
			vmdr_metadata_retain(metadata);
		}
	}
	task_unlock(t);
	proc_rele(p);
	if (metadata == NULL) {
		return false;
	}

	lck_mtx_lock(&async_reclamation_buffers_lock);
	while (vmdr_metadata_has_pending_reclamation(metadata)) {
		metadata->vdrm_waiters++;
		lck_mtx_sleep_with_inheritor(&async_reclamation_buffers_lock,
		    LCK_SLEEP_DEFAULT, &metadata->vdrm_async_list, vm_reclaim_thread,
		    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		metadata->vdrm_waiters--;
	}
	lck_mtx_unlock(&async_reclamation_buffers_lock);

	vmdr_metadata_release(metadata);
	return true;
}

#endif /* DEVELOPMENT || DEBUG */
