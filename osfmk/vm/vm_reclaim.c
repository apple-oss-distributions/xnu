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
#include <mach/mach_vm.h>
#include <mach/vm_reclaim.h>
#include <os/log.h>
#include <pexpert/pexpert.h>
#include <vm/vm_map.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_reclaim_internal.h>
#include <sys/kdebug.h>
#include <sys/queue.h>
#include <os/atomic_private.h>

#pragma mark Tunables
TUNABLE(uint32_t, kReclaimChunkSize, "vm_reclaim_chunk_size", 16);
static integer_t kReclaimThreadPriority = BASEPRI_VM;
// Reclaim down to vm_reclaim_max_threshold / vm_reclaim_trim_divisor when doing a trim reclaim operation
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_trim_divisor, "vm_reclaim_trim_divisor", 2);
TUNABLE_DT_DEV_WRITEABLE(uint64_t, vm_reclaim_max_threshold, "/defaults", "kern.vm_reclaim_max_threshold", "vm_reclaim_max_threshold", 0, TUNABLE_DT_NONE);
// Used to debug vm_reclaim kills
TUNABLE(bool, panic_on_kill, "vm_reclaim_panic_on_kill", false);

#pragma mark Declarations
typedef struct proc *proc_t;
extern char *proc_best_name(proc_t proc);
extern int exit_with_guard_exception(void *p, mach_exception_data_type_t code, mach_exception_data_type_t subcode);
struct proc *proc_ref(struct proc *p, int locked);
int proc_rele(proc_t p);
static bool reclaim_copyin_head(vm_deferred_reclamation_metadata_t metadata, uint64_t *head);
static bool reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail);
static bool reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy);

struct vm_deferred_reclamation_metadata_s {
	TAILQ_ENTRY(vm_deferred_reclamation_metadata_s) vdrm_list; // Global list containing every reclamation buffer
	TAILQ_ENTRY(vm_deferred_reclamation_metadata_s) vdrm_async_list; // A list containing buffers that are ripe for reclamation
	decl_lck_mtx_data(, vdrm_lock); /* Held when reclaiming from the buffer */
	/*
	 * The task owns this structure but we maintain a backpointer here
	 * so that we can send an exception if we hit an error.
	 * Since this is a backpointer we don't hold a reference (it's a weak pointer).
	 */
	task_t vdrm_task;
	vm_map_t vdrm_map;
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
};
static void process_async_reclamation_list(void);

extern void *proc_find(int pid);
extern task_t proc_task(proc_t);

#pragma mark Globals
static KALLOC_TYPE_DEFINE(vm_reclaim_metadata_zone, struct vm_deferred_reclamation_metadata_s, KT_DEFAULT);
static LCK_GRP_DECLARE(vm_reclaim_lock_grp, "vm_reclaim");
static os_log_t vm_reclaim_log_handle;

/*
 * The ringbuffer must contain at least 2 entries to distinguish between empty
 * (head == tail) and full (head == tail + 1).
 */
#define BUFFER_MIN_ENTRY_COUNT 2

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
static size_t reclamation_buffers_length;
static uint64_t reclamation_counter; // generation count for global reclaims

static SECURITY_READ_ONLY_LATE(thread_t) vm_reclaim_thread;
static void reclaim_thread(void *param __unused, wait_result_t wr __unused);

#pragma mark Implementation

/*
 * The current design is not tolerant to faulting on the buffer under the
 * metadata lock. Wire the buffer as a stop-gap solution for now; in the
 * future, the synchronization scheme should be revised to allow the buffer
 * to be pageable (rdar://112039103).
 */

static kern_return_t
vmdr_metadata_wire(vm_deferred_reclamation_metadata_t metadata)
{
	kern_return_t kr;
	vm_map_offset_t buffer_start = (metadata->vdrm_reclaim_buffer -
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries));
	vm_map_offset_t buffer_end = (metadata->vdrm_reclaim_buffer +
	    metadata->vdrm_buffer_size);
	kr = vm_map_wire_kernel(metadata->vdrm_map, buffer_start, buffer_end,
	    VM_PROT_NONE, VM_KERN_MEMORY_OSFMK, TRUE);
	if (kr != KERN_SUCCESS) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: failed to wire userspace reclaim buffer for pid %d (%d)",
		    task_pid(metadata->vdrm_task), kr);
	}
	return kr;
}

static kern_return_t
vmdr_metadata_unwire(vm_deferred_reclamation_metadata_t metadata)
{
	kern_return_t kr;
	vm_map_offset_t buffer_start = (metadata->vdrm_reclaim_buffer -
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries));
	vm_map_offset_t buffer_end = (metadata->vdrm_reclaim_buffer +
	    metadata->vdrm_buffer_size);
	kr = vm_map_unwire(metadata->vdrm_map, buffer_start, buffer_end, TRUE);
	if (kr != KERN_SUCCESS) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: unable to un-wire buffer %p (%llu) for pid %d (%d)",
		    (void *)buffer_start, (buffer_end - buffer_start),
		    task_pid(metadata->vdrm_task), kr);
	}
	return kr;
}

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
	metadata->vdrm_task = task;
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
	vm_map_deallocate(metadata->vdrm_map);
	lck_mtx_destroy(&metadata->vdrm_lock, &vm_reclaim_lock_grp);
	zfree(vm_reclaim_metadata_zone, metadata);
}

kern_return_t
vm_deferred_reclamation_buffer_init_internal(
	task_t                  task,
	mach_vm_offset_t        address,
	mach_vm_size_t          size)
{
	kern_return_t kr = KERN_FAILURE, tmp_kr;
	vm_deferred_reclamation_metadata_t metadata = NULL;
	bool success;
	uint64_t head = 0, tail = 0, busy = 0;

	if (address == 0 ||
	    size < (sizeof(struct mach_vm_reclaim_buffer_v1_s) +
	    BUFFER_MIN_ENTRY_COUNT * sizeof(mach_vm_reclaim_entry_v1_t)) ||
	    !VM_MAP_PAGE_ALIGNED(address, VM_MAP_PAGE_MASK(task->map)) ||
	    !VM_MAP_PAGE_ALIGNED((address + size), VM_MAP_PAGE_MASK(task->map))) {
		return KERN_INVALID_ARGUMENT;
	}

	/* vm_reclaim is disabled */
	if (vm_reclaim_max_threshold == 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: failed to initialize vmdr buffer - reclaim is disabled (%llu)",
		    vm_reclaim_max_threshold);
		return KERN_NOT_SUPPORTED;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_START,
	    task_pid(task), address, size);

	user_addr_t buffer = address + \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries);
	mach_vm_size_t buffer_size = size - \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, entries);
	user_addr_t indices = address + \
	    offsetof(struct mach_vm_reclaim_buffer_v1_s, indices);

	metadata = vmdr_metadata_alloc(task, buffer, buffer_size, indices);

	kr = vmdr_metadata_wire(metadata);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	/*
	 * Validate the starting indices.
	 *
	 * NB: At this point it is impossible for another thread to hold a
	 * reference to this metadata. However, reclaim_copyin may call reclaim_kill
	 * on failure, which assumes the metadata lock is held.
	 */
	lck_mtx_lock(&metadata->vdrm_lock);

	success = reclaim_copyin_busy(metadata, &busy);
	if (!success) {
		/* metadata lock has been dropped and exception delivered to task */
		kr = KERN_INVALID_ARGUMENT;
		goto fail_wired;
	}
	success = reclaim_copyin_head(metadata, &head);
	if (!success) {
		/* metadata lock has been dropped and exception delivered to task */
		kr = KERN_INVALID_ARGUMENT;
		goto fail_wired;
	}
	success = reclaim_copyin_tail(metadata, &tail);
	if (!success) {
		/* metadata lock has been dropped and exception delivered to task */
		kr = KERN_INVALID_ARGUMENT;
		goto fail_wired;
	}

	lck_mtx_unlock(&metadata->vdrm_lock);

	if (head != 0 || tail != 0 || busy != 0) {
		kr = KERN_INVALID_ARGUMENT;
		goto fail_wired;
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
		    "vm_reclaim: failed to initialize buffer on dying task (pid %d)", task_pid(task));
		kr = KERN_TERMINATED;
		goto fail_task;
	} else if (task->deferred_reclamation_metadata != NULL) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: tried to overwrite existing reclaim buffer for pid %d", task_pid(task));
		kr = KERN_INVALID_ARGUMENT;
		goto fail_task;
	}

	TAILQ_INSERT_TAIL(&reclamation_buffers, metadata, vdrm_list);
	reclamation_buffers_length++;

	task->deferred_reclamation_metadata = metadata;

	task_unlock(task);
	lck_mtx_unlock(&reclamation_buffers_lock);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    task_pid(task), KERN_SUCCESS);
	return KERN_SUCCESS;

fail_task:
	task_unlock(task);
	lck_mtx_unlock(&reclamation_buffers_lock);

fail_wired:
	tmp_kr = vmdr_metadata_unwire(metadata);
	assert3u(tmp_kr, ==, KERN_SUCCESS);

out:
	vmdr_metadata_free(metadata);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    task_pid(task), kr);
	return kr;
}

void
vm_deferred_reclamation_buffer_uninstall(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	/*
	 * First remove the buffer from the global list so no one else can get access to it.
	 */
	lck_mtx_lock(&reclamation_buffers_lock);
	TAILQ_REMOVE(&reclamation_buffers, metadata, vdrm_list);
	reclamation_buffers_length--;
	lck_mtx_unlock(&reclamation_buffers_lock);

	/*
	 * Now remove it from the async list (if present)
	 */
	lck_mtx_lock(&async_reclamation_buffers_lock);
	if (metadata->vdrm_async_list.tqe_next != NULL || metadata->vdrm_async_list.tqe_prev != NULL) {
		TAILQ_REMOVE(&async_reclamation_buffers, metadata, vdrm_async_list);
		metadata->vdrm_async_list.tqe_next = NULL;
		metadata->vdrm_async_list.tqe_prev = NULL;
	}
	lck_mtx_unlock(&async_reclamation_buffers_lock);

	// A kernel thread may have grabbed the lock for this buffer before we had
	// a chance to remove it from the queues. Take the metadata lock to ensure
	// any such workers are finished operating on the buffer.
	lck_mtx_lock(&metadata->vdrm_lock);
	lck_mtx_unlock(&metadata->vdrm_lock);

	vmdr_metadata_unwire(metadata);
}

void
vm_deferred_reclamation_buffer_deallocate(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	vmdr_metadata_free(metadata);
}

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

static void
reclaim_kill_with_reason(
	vm_deferred_reclamation_metadata_t metadata,
	unsigned reason,
	mach_exception_data_type_t subcode)
{
	unsigned int guard_type = GUARD_TYPE_VIRT_MEMORY;
	mach_exception_code_t code = 0;
	task_t task = metadata->vdrm_task;
	proc_t p = NULL;
	boolean_t fatal = TRUE;
	bool killing_self = false;
	pid_t pid;
	int err;

	if (panic_on_kill) {
		panic("vm_reclaim: About to kill %p due to %d with subcode %lld\n", task, reason, subcode);
	}

	EXC_GUARD_ENCODE_TYPE(code, guard_type);
	EXC_GUARD_ENCODE_FLAVOR(code, reason);
	EXC_GUARD_ENCODE_TARGET(code, 0);

	assert(metadata->vdrm_task != kernel_task);
	killing_self = task == current_task();
	if (!killing_self) {
		/*
		 * Grab a reference on the task to make sure it doesn't go away
		 * after we drop the metadata lock
		 */
		task_reference(task);
	}
	/*
	 * We need to issue a wakeup in case this kill is coming from the async path.
	 * Once we drop the lock the caller can no longer do this wakeup, but
	 * if there's someone blocked on this reclaim they hold a map reference
	 * and thus need to be woken up so the map can be freed.
	 */
	thread_wakeup(&metadata->vdrm_async_list);
	lck_mtx_unlock(&metadata->vdrm_lock);

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

		task_deallocate(task);
		task = NULL;
	}

	if (!p) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to deliver guard exception because task does not have a proc.\n");
		goto out;
	}

	err = exit_with_guard_exception(p, code, subcode);
	if (err != 0) {
		os_log_error(vm_reclaim_log_handle, "vm_reclaim: Unable to deliver guard exception to %p: %d\n", p, err);
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

static void
reclaim_handle_copyio_error(vm_deferred_reclamation_metadata_t metadata, int result)
{
	reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_COPYIO_FAILURE, result);
}

/*
 * Helper functions to do copyio on the head, tail, and busy pointers.
 * Note that the kernel will only write to the busy and head pointers.
 * Userspace is not supposed to write to the head or busy pointers, but the kernel
 * must be resilient to that kind of bug in userspace.
 */


static bool
reclaim_copyin_head(vm_deferred_reclamation_metadata_t metadata, uint64_t *head)
{
	int result;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyin_atomic64(head_ptr, head);

	if (result != 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy head ptr from 0x%llx: err=%d\n", head_ptr, result);
		reclaim_handle_copyio_error(metadata, result);
		return false;
	}
	return true;
}

static bool
reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail)
{
	int result;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t tail_ptr = get_tail_ptr(indices);

	result = copyin_atomic64(tail_ptr, tail);

	if (result != 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy tail ptr from 0x%llx: err=%d\n", tail_ptr, result);
		reclaim_handle_copyio_error(metadata, result);
		return false;
	}
	return true;
}

static bool
reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy)
{
	int result;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyin_atomic64(busy_ptr, busy);

	if (result != 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy busy ptr from 0x%llx: err=%d\n", busy_ptr, result);
		reclaim_handle_copyio_error(metadata, result);
		return false;
	}
	return true;
}

static bool
reclaim_copyout_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyout_atomic64(value, busy_ptr);

	if (result != 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy %llu to busy ptr at 0x%llx: err=%d\n", value, busy_ptr, result);
		reclaim_handle_copyio_error(metadata, result);
		return false;
	}
	return true;
}

static bool
reclaim_copyout_head(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	user_addr_t indices = metadata->vdrm_reclaim_indices;
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyout_atomic64(value, head_ptr);

	if (result != 0) {
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Unable to copy %llu to head ptr at 0x%llx: err=%d\n", value, head_ptr, result);
		reclaim_handle_copyio_error(metadata, result);
		return false;
	}
	return true;
}

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
reclaim_chunk(vm_deferred_reclamation_metadata_t metadata, size_t *num_reclaimed_out)
{
	assert(metadata != NULL);
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_OWNED);
	int result = 0;
	size_t num_reclaimed = 0;
	uint64_t head = 0, tail = 0, busy = 0, num_to_reclaim = 0, new_tail = 0, num_copied = 0, buffer_len = 0;
	user_addr_t indices;
	vm_map_t map = metadata->vdrm_map, old_map;
	mach_vm_reclaim_entry_v1_t reclaim_entries[kReclaimChunkSize];
	bool success;

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_START,
	    task_pid(metadata->vdrm_task), kReclaimChunkSize);

	buffer_len = metadata->vdrm_buffer_size / sizeof(mach_vm_reclaim_entry_v1_t);

	memset(reclaim_entries, 0, sizeof(reclaim_entries));

	indices = (user_addr_t) metadata->vdrm_reclaim_indices;
	old_map = vm_map_switch(map);

	success = reclaim_copyin_busy(metadata, &busy);
	if (!success) {
		goto fail;
	}
	success = reclaim_copyin_head(metadata, &head);
	if (!success) {
		goto fail;
	}
	success = reclaim_copyin_tail(metadata, &tail);
	if (!success) {
		goto fail;
	}

	if (busy != head) {
		// Userspace overwrote one of the pointers
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Userspace modified head or busy pointer! head: %llu (0x%llx) != busy: %llu (0x%llx) | tail = %llu (0x%llx)\n",
		    head, get_head_ptr(indices), busy, get_busy_ptr(indices), tail, get_tail_ptr(indices));
		reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_INDEX_FAILURE, busy);
		goto fail;
	}

	if (tail < head) {
		// Userspace is likely in the middle of trying to re-use an entry, bail on this reclamation
		os_log_error(vm_reclaim_log_handle,
		    "vm_reclaim: Userspace modified head or tail pointer! head: %llu (0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
		    head, get_head_ptr(indices), tail, get_tail_ptr(indices), busy, get_busy_ptr(indices));
		lck_mtx_unlock(&metadata->vdrm_lock);
		goto fail;
	}

	num_to_reclaim = tail - head;
	while (true) {
		num_to_reclaim = MIN(num_to_reclaim, kReclaimChunkSize);
		if (num_to_reclaim == 0) {
			break;
		}
		busy = head + num_to_reclaim;
		success = reclaim_copyout_busy(metadata, busy);
		if (!success) {
			goto fail;
		}
		os_atomic_thread_fence(seq_cst);
		success = reclaim_copyin_tail(metadata, &new_tail);
		if (!success) {
			goto fail;
		}

		if (new_tail >= busy) {
			/* Got num_to_reclaim entries */
			break;
		}
		tail = new_tail;
		if (tail < head) {
			// Userspace is likely in the middle of trying to re-use an entry, bail on this reclamation
			os_log_error(vm_reclaim_log_handle,
			    "vm_reclaim: Userspace modified head or tail pointer! head: %llu (0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
			    head, get_head_ptr(indices), tail, get_tail_ptr(indices), busy, get_busy_ptr(indices));
			lck_mtx_unlock(&metadata->vdrm_lock);
			goto fail;
		}
		/* Can't reclaim these entries. Try again */
		num_to_reclaim = tail - head;
		if (num_to_reclaim == 0) {
			/* Nothing left to reclaim. Reset busy to head. */
			success = reclaim_copyout_busy(metadata, head);
			if (!success) {
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
		user_addr_t src_ptr = metadata->vdrm_reclaim_buffer + memcpy_start_idx * sizeof(mach_vm_reclaim_entry_v1_t);
		mach_vm_reclaim_entry_v1_t *dst_ptr = reclaim_entries + num_copied;

		result = copyin(src_ptr, dst_ptr, num_to_copy * sizeof(mach_vm_reclaim_entry_v1_t));

		if (result != 0) {
			os_log_error(vm_reclaim_log_handle,
			    "vm_reclaim: Unable to copyin %llu entries in reclaim buffer at 0x%llx to 0x%llx: err=%d\n",
			    num_to_copy, src_ptr, (uint64_t) dst_ptr, result);
			reclaim_handle_copyio_error(metadata, result);
			goto fail;
		}

		num_copied += num_to_copy;
		head += num_to_copy;
	}

	for (size_t i = 0; i < num_to_reclaim; i++) {
		mach_vm_reclaim_entry_v1_t *entry = &reclaim_entries[i];
		KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_START,
		    task_pid(metadata->vdrm_task), entry->address, entry->size,
		    entry->behavior);
		DTRACE_VM4(vm_reclaim_chunk,
		    int, task_pid(metadata->vdrm_task),
		    mach_vm_address_t, entry->address,
		    size_t, entry->size,
		    mach_vm_reclaim_behavior_v1_t, entry->behavior);
		if (entry->address != 0 && entry->size != 0) {
			kern_return_t kr;
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
					    entry->address, entry->size, task_pid(metadata->vdrm_task), kr);
				}
				break;
			default:
				os_log_error(vm_reclaim_log_handle,
				    "vm_reclaim: attempted to reclaim entry with unsupported behavior %uh",
				    entry->behavior);
				reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE, kr);
				goto fail;
			}
			num_reclaimed++;
			os_atomic_add(&metadata->vdrm_num_bytes_reclaimed, entry->size, relaxed);
			KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_END,
			    task_pid(metadata->vdrm_task), entry->address);
		}
	}

	success = reclaim_copyout_head(metadata, head);
	if (!success) {
		goto fail;
	}

	vm_map_switch(old_map);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_END,
	    task_pid(metadata->vdrm_task), num_to_reclaim, num_reclaimed, true);
	*num_reclaimed_out = num_reclaimed;
	if (num_to_reclaim == 0) {
		// We have exhausted the reclaimable portion of the buffer
		return KERN_NOT_FOUND;
	}
	return KERN_SUCCESS;
fail:
	vm_map_switch(old_map);
	*num_reclaimed_out = num_reclaimed;
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_END,
	    task_pid(metadata->vdrm_task), num_to_reclaim, num_reclaimed, false);
	return KERN_FAILURE;
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
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_OWNED);
	if (!task_is_active(metadata->vdrm_task)) {
		/*
		 * If the task is exiting, the reclaim below will likely fail and fall through
		 * to the (slower) error path.
		 * So as an optimization, we bail out early here.
		 */
		return 0;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_START, task_pid(metadata->vdrm_task));

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
		kr = reclaim_chunk(metadata, &curr_entries_reclaimed);
		if (kr == KERN_NOT_FOUND) {
			break;
		} else if (kr != KERN_SUCCESS) {
			KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_END,
			    task_pid(metadata->vdrm_task), num_entries_reclaimed,
			    estimated_reclaimable_bytes, kr);
			*num_reclaimed_out = num_entries_reclaimed;
			return kr;
		}
		num_entries_reclaimed += curr_entries_reclaimed;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ENTRIES) | DBG_FUNC_END,
	    task_pid(metadata->vdrm_task), num_entries_reclaimed,
	    estimated_reclaimable_bytes, KERN_SUCCESS);
	*num_reclaimed_out = num_entries_reclaimed;
	return KERN_SUCCESS;
}

/*
 * Get the reclamation metadata buffer for the given map.
 * If the buffer exists it is returned locked.
 */
static vm_deferred_reclamation_metadata_t
get_task_reclaim_metadata(task_t task)
{
	assert(task != NULL);
	vm_deferred_reclamation_metadata_t metadata = NULL;
	task_lock(task);
	metadata = task->deferred_reclamation_metadata;
	if (metadata != NULL) {
		lck_mtx_lock(&metadata->vdrm_lock);
	}
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

	while (total_reclaimed < num_entries_to_reclaim) {
		size_t num_reclaimed;
		kr = reclaim_chunk(metadata, &num_reclaimed);
		if (kr == KERN_NOT_FOUND) {
			/* buffer has been fully reclaimed from */
			break;
		} else if (kr != KERN_SUCCESS) {
			/* Lock has already been released and task is being killed. */
			return kr;
		}

		total_reclaimed += num_reclaimed;
	}
	lck_mtx_unlock(&metadata->vdrm_lock);

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

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_START,
	    task_pid(task), reclaimable_bytes);

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
			lck_mtx_lock(&metadata->vdrm_lock);
			kr = reclaim_entries_from_buffer(metadata,
			    vm_reclaim_max_threshold, &num_reclaimed);
			if (kr != KERN_SUCCESS) {
				/* Lock has already been released & task is in the process of getting killed. */
				goto done;
			}
			lck_mtx_unlock(&metadata->vdrm_lock);
		}
	}

done:
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_END,
	    task_pid(task), reclaimable_bytes, num_bytes_reclaimed, num_reclaimed);

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
vm_deferred_reclamation_reclaim_memory(vm_deferred_reclamation_action_t action)
{
	kern_return_t kr;
	size_t num_reclaimed;

	if (action == RECLAIM_ASYNC) {
		lck_mtx_lock(&async_reclamation_buffers_lock);

		process_async_reclamation_list();
		lck_mtx_unlock(&async_reclamation_buffers_lock);
	} else {
		size_t reclaim_threshold = pick_reclaim_threshold(action);
		KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ALL_MEMORY) | DBG_FUNC_START,
		    action, reclaim_threshold);
		lck_mtx_lock(&reclamation_buffers_lock);
		reclamation_counter++;
		while (true) {
			vm_deferred_reclamation_metadata_t metadata = TAILQ_FIRST(&reclamation_buffers);
			if (metadata == NULL) {
				break;
			}
			lck_mtx_lock(&metadata->vdrm_lock);
			if (metadata->vdrm_reclaimed_at >= reclamation_counter) {
				// We've already seen this one. We're done
				lck_mtx_unlock(&metadata->vdrm_lock);
				break;
			}
			metadata->vdrm_reclaimed_at = reclamation_counter;

			TAILQ_REMOVE(&reclamation_buffers, metadata, vdrm_list);
			TAILQ_INSERT_TAIL(&reclamation_buffers, metadata, vdrm_list);
			lck_mtx_unlock(&reclamation_buffers_lock);

			kr = reclaim_entries_from_buffer(metadata,
			    reclaim_threshold, &num_reclaimed);
			if (kr == KERN_SUCCESS) {
				lck_mtx_unlock(&metadata->vdrm_lock);
			}

			lck_mtx_lock(&reclamation_buffers_lock);
		}
		lck_mtx_unlock(&reclamation_buffers_lock);
		KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ALL_MEMORY) | DBG_FUNC_END,
		    reclamation_counter);
	}
}

void
vm_deferred_reclamation_reclaim_all_memory(void)
{
	vm_deferred_reclamation_reclaim_memory(RECLAIM_FULL);
}

bool
vm_deferred_reclamation_reclaim_from_task_async(task_t task)
{
	bool queued = false;
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;

	if (metadata != NULL) {
		lck_mtx_lock(&async_reclamation_buffers_lock);
		if (metadata->vdrm_async_list.tqe_next != NULL ||
		    metadata->vdrm_async_list.tqe_prev != NULL) {
			// move this buffer to the tail if still on the async list
			TAILQ_REMOVE(&async_reclamation_buffers, metadata, vdrm_async_list);
		}
		TAILQ_INSERT_TAIL(&async_reclamation_buffers, metadata, vdrm_async_list);
		lck_mtx_unlock(&async_reclamation_buffers_lock);
		queued = true;
		thread_wakeup(&vm_reclaim_thread);
	}

	return queued;
}

bool
vm_deferred_reclamation_reclaim_from_task_sync(task_t task, size_t max_entries_to_reclaim)
{
	kern_return_t kr;
	size_t num_reclaimed = 0;
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;

	if (!task_is_active(task)) {
		return false;
	}

	if (metadata != NULL) {
		lck_mtx_lock(&metadata->vdrm_lock);
		while (num_reclaimed < max_entries_to_reclaim) {
			size_t num_reclaimed_now;
			kr = reclaim_chunk(metadata, &num_reclaimed_now);
			if (kr == KERN_NOT_FOUND) {
				// Nothing left to reclaim
				break;
			} else if (kr != KERN_SUCCESS) {
				/* Lock has already been released and task is being killed. */
				return false;
			}
			num_reclaimed += num_reclaimed_now;
		}
		lck_mtx_unlock(&metadata->vdrm_lock);
	}

	return num_reclaimed > 0;
}

vm_deferred_reclamation_metadata_t
vm_deferred_reclamation_buffer_fork(task_t task, vm_deferred_reclamation_metadata_t parent)
{
	kern_return_t kr;
	vm_deferred_reclamation_metadata_t metadata = NULL;

	LCK_MTX_ASSERT(&parent->vdrm_lock, LCK_MTX_ASSERT_OWNED);

	assert(task->deferred_reclamation_metadata == NULL);
	metadata = vmdr_metadata_alloc(task, parent->vdrm_reclaim_buffer,
	    parent->vdrm_buffer_size, parent->vdrm_reclaim_indices);
	lck_mtx_unlock(&parent->vdrm_lock);

	kr = vmdr_metadata_wire(metadata);
	if (kr != KERN_SUCCESS) {
		vmdr_metadata_free(metadata);
		return NULL;
	}

	lck_mtx_lock(&reclamation_buffers_lock);
	TAILQ_INSERT_TAIL(&reclamation_buffers, metadata, vdrm_list);
	reclamation_buffers_length++;
	lck_mtx_unlock(&reclamation_buffers_lock);

	return metadata;
}

void
vm_deferred_reclamation_buffer_lock(vm_deferred_reclamation_metadata_t metadata)
{
	lck_mtx_lock(&metadata->vdrm_lock);
}

void
vm_deferred_reclamation_buffer_unlock(vm_deferred_reclamation_metadata_t metadata)
{
	lck_mtx_unlock(&metadata->vdrm_lock);
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
process_async_reclamation_list(void)
{
	kern_return_t kr;
	size_t total_entries_reclaimed = 0;
	size_t num_tasks_reclaimed = 0;
	LCK_MTX_ASSERT(&async_reclamation_buffers_lock, LCK_MTX_ASSERT_OWNED);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_ASYNC_MEMORY) | DBG_FUNC_START);

	vm_deferred_reclamation_metadata_t metadata = TAILQ_FIRST(&async_reclamation_buffers);
	while (metadata != NULL) {
		size_t num_reclaimed;
		TAILQ_REMOVE(&async_reclamation_buffers, metadata, vdrm_async_list);
		metadata->vdrm_async_list.tqe_next = NULL;
		metadata->vdrm_async_list.tqe_prev = NULL;
		lck_mtx_lock(&metadata->vdrm_lock);
		lck_mtx_unlock(&async_reclamation_buffers_lock);

		// NB: Currently the async reclaim thread fully reclaims the buffer.
		kr = reclaim_entries_from_buffer(metadata, 0, &num_reclaimed);
		total_entries_reclaimed += num_reclaimed;
		if (kr != KERN_SUCCESS) {
			/* Lock has already been released & task is in the process of getting killed. */
			goto next;
		}
		num_tasks_reclaimed++;
		/* Wakeup anyone waiting on this buffer getting processed */
		thread_wakeup(&metadata->vdrm_async_list);
		assert(current_thread()->map == kernel_map);
		lck_mtx_unlock(&metadata->vdrm_lock);

next:
		lck_mtx_lock(&async_reclamation_buffers_lock);
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

	process_async_reclamation_list();
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
	vm_reclaim_log_handle = os_log_create("com.apple.mach.vm", "reclaim");

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
	vm_map_t map = NULL;
	if (p == NULL) {
		return false;
	}
	task_t t = proc_task(p);
	if (t == NULL) {
		proc_rele(p);
		return false;
	}

	task_lock(t);
	if (t->map) {
		metadata = t->deferred_reclamation_metadata;
		if (metadata != NULL) {
			map = t->map;
			vm_map_reference(t->map);
		}
	}
	task_unlock(t);
	proc_rele(p);
	if (metadata == NULL) {
		return false;
	}

	lck_mtx_lock(&async_reclamation_buffers_lock);
	while (metadata->vdrm_async_list.tqe_next != NULL || metadata->vdrm_async_list.tqe_prev != NULL) {
		assert_wait(&metadata->vdrm_async_list, THREAD_UNINT);
		lck_mtx_unlock(&async_reclamation_buffers_lock);
		thread_block(THREAD_CONTINUE_NULL);
		lck_mtx_lock(&async_reclamation_buffers_lock);
	}

	/*
	 * The async reclaim thread first removes the buffer from the list
	 * and then reclaims it (while holding its lock).
	 * So grab the metadata buffer's lock here to ensure the
	 * reclaim is done.
	 */
	lck_mtx_lock(&metadata->vdrm_lock);
	lck_mtx_unlock(&metadata->vdrm_lock);
	lck_mtx_unlock(&async_reclamation_buffers_lock);

	vm_map_deallocate(map);
	return true;
}

#endif /* DEVELOPMENT || DEBUG */
