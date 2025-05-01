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
#include <kern/sched_prim.h>
#include <kern/startup.h>
#include <kern/thread_group.h>
#include <libkern/OSAtomic.h>
#include <mach/kern_return.h>
#include <mach/mach_types.h>
#include <mach/vm_reclaim_private.h>
#include <os/atomic_private.h>
#include <os/base_private.h>
#include <os/log.h>
#include <os/refcnt.h>
#include <os/refcnt_internal.h>
#include <pexpert/pexpert.h>
#include <sys/errno.h>
#include <sys/kdebug.h>
#include <sys/queue.h>
#include <sys/reason.h>
#include <vm/vm_fault_xnu.h>
#include <vm/vm_map.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_pageout_internal.h>
#include <vm/vm_reclaim_internal.h>
#include <vm/vm_sanitize_internal.h>
#include <vm/vm_kern_xnu.h>

#pragma mark Tunables

#if XNU_TARGET_OS_IOS && !XNU_TARGET_OS_XR
/* Temporarily opt iOS into the legacy behavior as a stop-gap */
#define CONFIG_WORKING_SET_ESTIMATION 0
/*
 * Deferred reclaim may be enabled via EDT for select iOS devices, but
 * defaults to disabled
 */
#define VM_RECLAIM_ENABLED_DEFAULT false
#else
#define CONFIG_WORKING_SET_ESTIMATION 1
#define VM_RECLAIM_ENABLED_DEFAULT true
#endif

#if DEVELOPMENT || DEBUG
TUNABLE(uint32_t, kReclaimChunkSize, "vm_reclaim_chunk_size", 16);
#else /* RELEASE */
const uint32_t kReclaimChunkSize = 16;
#endif /* DEVELOPMENT || DEBUG */
#if CONFIG_WORKING_SET_ESTIMATION
TUNABLE_DT_DEV_WRITEABLE(bool, vm_reclaim_enabled, "/defaults",
    "kern.vm_reclaim_enabled", "vm_reclaim_enabled", VM_RECLAIM_ENABLED_DEFAULT, TUNABLE_DT_NONE);
/* TODO: Consider varying the sampling rate based on rusage, ringbuffer-velocity, memory pressure */
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_sampling_period_ns, "vm_reclaim_sampling_period_ns", 1ULL * NSEC_PER_SEC);
TUNABLE_DEV_WRITEABLE(uint32_t, vm_reclaim_autotrim_pct_normal, "vm_reclaim_autotrim_pct_normal", 10);
TUNABLE_DEV_WRITEABLE(uint32_t, vm_reclaim_autotrim_pct_pressure, "vm_reclaim_autotrim_pct_pressure", 5);
TUNABLE_DEV_WRITEABLE(uint32_t, vm_reclaim_autotrim_pct_critical, "vm_reclaim_autotrim_pct_critical", 1);
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_wma_weight_base, "vm_reclaim_wma_weight_base", 3);
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_wma_weight_cur, "vm_reclaim_wma_weight_cur", 1);
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_wma_denom, "vm_reclaim_wma_denom", 4);
TUNABLE_DEV_WRITEABLE(uint64_t, vm_reclaim_abandonment_threshold, "vm_reclaim_abandonment_threshold", 512);
#else /* CONFIG_WORKING_SET_ESTIMATION */
TUNABLE_DT_DEV_WRITEABLE(uint64_t, vm_reclaim_max_threshold, "/defaults",
    "kern.vm_reclaim_max_threshold", "vm_reclaim_max_threshold", 0, TUNABLE_DT_NONE);
#endif /* CONFIG_WORKING_SET_ESTIMATION */
TUNABLE(bool, panic_on_kill, "vm_reclaim_panic_on_kill", false);
#if DEVELOPMENT || DEBUG
TUNABLE_WRITEABLE(bool, vm_reclaim_debug, "vm_reclaim_debug", false);
#endif

#pragma mark Declarations
typedef struct proc *proc_t;
extern const char *proc_best_name(struct proc *);
extern void *proc_find(int pid);
extern task_t proc_task(proc_t);
extern kern_return_t kern_return_for_errno(int);
extern int mach_to_bsd_errno(kern_return_t kr);
extern int exit_with_guard_exception(void *p, mach_exception_data_type_t code, mach_exception_data_type_t subcode);
struct proc *proc_ref(struct proc *p, int locked);
int proc_rele(proc_t p);

#define _vmdr_log_type(type, fmt, ...) os_log_with_type(vm_reclaim_log_handle, type, "vm_reclaim: " fmt, ##__VA_ARGS__)
#define vmdr_log(fmt, ...) _vmdr_log_type(OS_LOG_TYPE_DEFAULT, fmt, ##__VA_ARGS__)
#define vmdr_log_info(fmt, ...) _vmdr_log_type(OS_LOG_TYPE_INFO, fmt, ##__VA_ARGS__)
#define vmdr_log_error(fmt, ...) _vmdr_log_type(OS_LOG_TYPE_ERROR, fmt, ##__VA_ARGS__)
#if DEVELOPMENT || DEBUG
#define vmdr_log_debug(fmt, ...) \
MACRO_BEGIN \
if (os_unlikely(vm_reclaim_debug)) { \
	_vmdr_log_type(OS_LOG_TYPE_DEBUG, fmt, ##__VA_ARGS__); \
} \
MACRO_END
#else /* !(DEVELOPMENT || DEBUG)*/
#define vmdr_log_debug(...)
#endif /* DEVELOPMENT || DEBUG */

static kern_return_t reclaim_copyin_head(vm_deferred_reclamation_metadata_t metadata, uint64_t *head);
static kern_return_t reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail);
static kern_return_t reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy);
static kern_return_t reclaim_handle_copyio_error(vm_deferred_reclamation_metadata_t metadata, int result);
#if CONFIG_WORKING_SET_ESTIMATION
static bool vmdr_sample_working_set(vm_deferred_reclamation_metadata_t metadata, size_t *trim_threshold_out);
#endif
static void vmdr_metadata_release(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_list_append_locked(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_list_remove_locked(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_metadata_own(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_metadata_disown(vm_deferred_reclamation_metadata_t metadata);
static void vmdr_garbage_collect(vm_deferred_reclamation_gc_action_t action, vm_deferred_reclamation_options_t options);
static kern_return_t reclaim_chunk(vm_deferred_reclamation_metadata_t metadata,
    uint64_t bytes_to_reclaim, uint64_t *bytes_reclaimed_out,
    mach_vm_reclaim_count_t chunk_size, mach_vm_reclaim_count_t *num_reclaimed_out);

struct vm_deferred_reclamation_metadata_s {
	/*
	 * Global list containing every reclamation buffer. Protected by the
	 * reclamation_buffers_lock.
	 */
	TAILQ_ENTRY(vm_deferred_reclamation_metadata_s) vdrm_list;
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
	/* The virtual address of the ringbuffer in the user map (immutable) */
	user_addr_t vdrm_buffer_addr;
	/* The size of the VM allocation containing the ringbuffer (immutable) */
	mach_vm_size_t vdrm_buffer_size;
	/* The length of the ringbuffer. This may be changed on buffer re-size */
	mach_vm_reclaim_count_t vdrm_buffer_len;
	/* Which GC epoch this buffer was last considered in */
	uint64_t vdrm_reclaimed_at;
	/*
	 * The number of threads waiting for a pending reclamation
	 * on this buffer to complete.
	 */
	uint32_t vdrm_waiters;
#if CONFIG_WORKING_SET_ESTIMATION
	/* timestamp (MAS) of the last working set sample for this ringbuffer */
	uint64_t vdrm_last_sample_abs;
	/*
	 * Exponential moving average of the minimum reclaimable buffer size (in VMDR_WMA_UNIT's)
	 */
	uint64_t vdrm_reclaimable_bytes_wma;
	/*
	 * The minimum amount of reclaimable memory in this buffer for the current
	 * sampling interval.
	 */
	size_t vdrm_reclaimable_bytes_min;
#endif /* CONFIG_WORKING_SET_ESTIMATION */
	/*
	 * These two values represent running sums of uncancelled bytes
	 * entered into the ring by userspace and bytes reclaimed out of the
	 * buffer by the kernel.
	 *
	 * The uncancelled byte-count may fluctuate as the client enters and
	 * cancels new reclamation requests. Reclamation requests which have
	 * been completed by the kernel will not deduct from the uncancelled
	 * count but will be added to the reclaimed byte count.
	 *
	 *  - `vdrm_cumulative_reclaimed_bytes` is monotonically increasing.
	 *  - `vdrm_cumulative_uncancelled_bytes` may fluctuate but
	 *    should trend upward.
	 *  - `vdrm_cumulative_uncancelled_bytes` must be kept >=
	 *    `vdrm_cumulative_reclaimed_bytes`
	 *
	 * Both values are in terms of virtual memory,
	 * so they give an upper bound on the amount of physical memory that
	 * can be reclaimed. To get an estimate of the current amount of VA in
	 * the buffer do vdrm_cumulative_uncancelled_bytes -
	 * vdrm_cumulative_reclaimed_bytes.
	 */
	size_t vdrm_cumulative_uncancelled_bytes;
	size_t vdrm_cumulative_reclaimed_bytes;

	/*
	 * Tracks whether or not this reclamation metadata has been added
	 * to the global list yet. Normally, this happens when it is allocated,
	 * except in the case of fork(). In this case, we have to duplicate the
	 * parent's metadata before it returns from fork(), but this occurs
	 * before the child's address space is set up.
	 */
	uint8_t vdrm_is_registered : 1,
	    __unused1 : 7;
};

#pragma mark Globals
static KALLOC_TYPE_DEFINE(vm_reclaim_metadata_zone, struct vm_deferred_reclamation_metadata_s, KT_DEFAULT);
static LCK_GRP_DECLARE(vm_reclaim_lock_grp, "vm_reclaim");
os_refgrp_decl(static, vm_reclaim_metadata_refgrp, "vm_reclaim_metadata_refgrp", NULL);
/*
 * The reclamation_buffers list contains every buffer in the system.
 * The reclamation_buffers_lock protects the reclamation_buffers list.
 * It must be held when iterating over the list or manipulating the list.
 * It should be dropped when acting on a specific metadata entry after acquiring the vdrm_lock.
 */
static TAILQ_HEAD(, vm_deferred_reclamation_metadata_s) reclaim_buffers = TAILQ_HEAD_INITIALIZER(reclaim_buffers);
LCK_MTX_DECLARE(reclaim_buffers_lock, &vm_reclaim_lock_grp);
/* Number of times Reclaim GC has run */
uint64_t vm_reclaim_gc_epoch = 0;
/* The number of reclamation actions (drains/trims) done during GC */
uint64_t vm_reclaim_gc_reclaim_count;
/* Gate for GC */
static decl_lck_mtx_gate_data(, vm_reclaim_gc_gate);
os_log_t vm_reclaim_log_handle;
/* Number of initialized reclaim buffers */
_Atomic uint32_t vm_reclaim_buffer_count;
uint64_t vm_reclaim_sampling_period_abs = 0;
static SECURITY_READ_ONLY_LATE(thread_t) vm_reclaim_scavenger_thread = THREAD_NULL;
static sched_cond_atomic_t vm_reclaim_scavenger_cond = SCHED_COND_INIT;

#pragma mark Buffer Initialization/Destruction

static vm_deferred_reclamation_metadata_t
vmdr_metadata_alloc(
	task_t                  task,
	user_addr_t             buffer,
	mach_vm_size_t          size,
	mach_vm_reclaim_count_t len)
{
	vm_deferred_reclamation_metadata_t metadata;
	vm_map_t map = task->map;

	assert(!map->is_nested_map);

	metadata = zalloc_flags(vm_reclaim_metadata_zone, Z_WAITOK | Z_ZERO);
	lck_mtx_init(&metadata->vdrm_lock, &vm_reclaim_lock_grp, LCK_ATTR_NULL);
	lck_mtx_gate_init(&metadata->vdrm_lock, &metadata->vdrm_gate);
	os_ref_init(&metadata->vdrm_refcnt, &vm_reclaim_metadata_refgrp);

	metadata->vdrm_task = task;
	metadata->vdrm_map = map;
	metadata->vdrm_buffer_addr = buffer;
	metadata->vdrm_buffer_size = size;
	metadata->vdrm_buffer_len = len;

	if (os_atomic_inc(&vm_reclaim_buffer_count, relaxed) == UINT32_MAX) {
		panic("Overflowed vm_reclaim_buffer_count");
	}

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
	lck_mtx_gate_destroy(&metadata->vdrm_lock, &metadata->vdrm_gate);
	lck_mtx_destroy(&metadata->vdrm_lock, &vm_reclaim_lock_grp);
	zfree(vm_reclaim_metadata_zone, metadata);
	if (os_atomic_dec_orig(&vm_reclaim_buffer_count, relaxed) == 0) {
		panic("Underflowed vm_reclaim_buffer_count");
	}
}

static mach_vm_size_t
vmdr_round_len_to_size(vm_map_t map, mach_vm_reclaim_count_t count)
{
	mach_vm_size_t metadata_size = offsetof(struct mach_vm_reclaim_ring_s, entries);
	mach_vm_size_t entries_size = count * sizeof(struct mach_vm_reclaim_entry_s);
	return vm_map_round_page(metadata_size + entries_size, vm_map_page_mask(map));
}

mach_error_t
vm_deferred_reclamation_buffer_allocate_internal(
	task_t                   task,
	mach_vm_address_ut       *address_u,
	mach_vm_reclaim_count_t  len,
	mach_vm_reclaim_count_t  max_len)
{
	kern_return_t kr;
	kern_return_t tmp_kr;
	vm_deferred_reclamation_metadata_t metadata = NULL;
	vm_map_t map;
	uint64_t head = 0, tail = 0, busy = 0;
	static bool reclaim_disabled_logged = false;

	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	if (address_u == NULL) {
		return KERN_INVALID_ADDRESS;
	}
	if (len == 0 || max_len == 0 || max_len < len) {
		return KERN_INVALID_ARGUMENT;
	}
	map = task->map;
#if CONFIG_WORKING_SET_ESTIMATION
	if (!vm_reclaim_enabled) {
#else /* !CONFIG_WORKING_SET_ESTIMATION */
	if (!vm_reclaim_max_threshold) {
#endif /* CONFIG_WORKING_SET_ESTIMATION */
		if (!reclaim_disabled_logged) {
			/* Avoid logging failure for every new process */
			reclaim_disabled_logged = true;
			vmdr_log_error("failed to initialize deferred "
			    "reclamation buffer - vm_reclaim is disabled\n");
		}
		return VM_RECLAIM_NOT_SUPPORTED;
	}

	map = task->map;
	mach_vm_size_t rounded_vm_size = vmdr_round_len_to_size(map, max_len);
	if (rounded_vm_size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	if (rounded_vm_size > VM_RECLAIM_MAX_BUFFER_SIZE) {
		vmdr_log_error("denying request to allocate ringbuffer of size "
		    "%llu KiB (max %llu KiB)\n",
		    rounded_vm_size,
		    VM_RECLAIM_MAX_BUFFER_SIZE);
		return KERN_NO_SPACE;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_START,
	    task_pid(task), len);

	/*
	 * Allocate a VM region that can contain the maximum buffer size. The
	 * allocation starts as VM_PROT_NONE and may be unprotected on buffer
	 * resize.
	 *
	 * TODO: If clients other than libmalloc adopt deferred reclaim, a
	 * different tag should be given
	 *
	 * `address` was sanitized under the assumption that we'll only use
	 * it as a hint (overflow checks were used) so we must pass the
	 * anywhere flag.
	 */
	vm_map_kernel_flags_t vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE_PERMANENT(
		.vm_tag = VM_MEMORY_MALLOC);
	mach_vm_size_ut size_u = vm_sanitize_wrap_size(rounded_vm_size);
	kr = mach_vm_map_kernel(map, address_u, size_u, VM_MAP_PAGE_MASK(map),
	    vmk_flags, IPC_PORT_NULL, 0, FALSE,
	    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_COPY);
	if (kr != KERN_SUCCESS) {
		vmdr_log_error("%s [%d] failed to allocate VA for reclaim "
		    "buffer (%d)\n", task_best_name(task), task_pid(task), kr);
		return kr;
	}
	mach_vm_address_t address = VM_SANITIZE_UNSAFE_UNWRAP(*address_u);
	assert3u(address, !=, 0);

	metadata = vmdr_metadata_alloc(task, address, rounded_vm_size, len);
	metadata->vdrm_pid = task_pid(task);

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
		vmdr_log_error("indices were not "
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
	lck_mtx_lock(&reclaim_buffers_lock);
	task_lock(task);

	if (!task_is_active(task) || task_is_halting(task)) {
		vmdr_log_error(
			"failed to initialize buffer on dying task %s [%d]",
			task_best_name(task), task_pid(task));
		kr = KERN_ABORTED;
		goto fail_task;
	}
	if (task->deferred_reclamation_metadata != NULL) {
		vmdr_log_error(
			"tried to overwrite existing reclaim buffer for %s [%d]", task_best_name(task), task_pid(task));
		kr = VM_RECLAIM_RESOURCE_SHORTAGE;
		goto fail_task;
	}

	metadata->vdrm_is_registered = true;
	vmdr_list_append_locked(metadata);
	task->deferred_reclamation_metadata = metadata;

	task_unlock(task);
	lck_mtx_unlock(&reclaim_buffers_lock);

	vmdr_log_debug("%s [%d] allocated ring with capacity %u/%u\n",
	    task_best_name(task), task_pid(task),
	    len, max_len);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    task_pid(task), KERN_SUCCESS, address);
	DTRACE_VM3(reclaim_ring_allocate,
	    mach_vm_address_t, address,
	    mach_vm_reclaim_count_t, len,
	    mach_vm_reclaim_count_t, max_len);
	return KERN_SUCCESS;

fail_task:
	task_unlock(task);
	lck_mtx_unlock(&reclaim_buffers_lock);

	tmp_kr = mach_vm_deallocate(map,
	    *address_u, size_u);
	assert(tmp_kr == KERN_SUCCESS);

out:
	*address_u = vm_sanitize_wrap_addr(0ull);
	vmdr_metadata_release(metadata);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_INIT) | DBG_FUNC_END,
	    kr, NULL);
	return kr;
}

#pragma mark Synchronization & Lifecycle

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

static bool
vmdr_metadata_try_own_locked(vm_deferred_reclamation_metadata_t metadata)
{
	kern_return_t kr = lck_mtx_gate_try_close(&metadata->vdrm_lock,
	    &metadata->vdrm_gate);
	return kr == KERN_SUCCESS;
}

/*
 * Try to take ownership of the buffer. Returns true if successful.
 */
static bool
vmdr_metadata_own_locked(vm_deferred_reclamation_metadata_t metadata,
    vm_deferred_reclamation_options_t options)
{
	__assert_only gate_wait_result_t wait_result;
	if (!vmdr_metadata_try_own_locked(metadata)) {
		if (options & RECLAIM_NO_WAIT) {
			return false;
		}
		wait_result = lck_mtx_gate_wait(
			&metadata->vdrm_lock, &metadata->vdrm_gate, LCK_SLEEP_DEFAULT,
			THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		assert(wait_result == GATE_HANDOFF);
	}
	return true;
}

/*
 * Set the current thread as the owner of a reclaim buffer. May block. Will
 * propagate priority.
 */
static void
vmdr_metadata_own(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_lock(metadata);
	vmdr_metadata_own_locked(metadata, RECLAIM_OPTIONS_NONE);
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

static void
vmdr_list_remove_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&reclaim_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert3p(metadata->vdrm_list.tqe_prev, !=, NULL);
	TAILQ_REMOVE(&reclaim_buffers, metadata, vdrm_list);
	metadata->vdrm_list.tqe_prev = NULL;
	metadata->vdrm_list.tqe_next = NULL;
}

static void
vmdr_list_append_locked(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&reclaim_buffers_lock, LCK_MTX_ASSERT_OWNED);
	assert3p(metadata->vdrm_list.tqe_prev, ==, NULL);
	TAILQ_INSERT_TAIL(&reclaim_buffers, metadata, vdrm_list);
}

void
vm_deferred_reclamation_buffer_deallocate(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	/*
	 * First remove the buffer from the global list so no one else can get access to it.
	 */
	lck_mtx_lock(&reclaim_buffers_lock);
	if (metadata->vdrm_is_registered) {
		vmdr_list_remove_locked(metadata);
	}
	lck_mtx_unlock(&reclaim_buffers_lock);

	/*
	 * The task is dropping its ref on this buffer. First remove the buffer's
	 * back-reference to the task so that any threads currently operating on
	 * this buffer do not try to operate on the dead/dying task
	 */
	vmdr_metadata_lock(metadata);
	assert3p(metadata->vdrm_task, !=, TASK_NULL);
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
		vmdr_log_error(
			"Unable to deliver guard exception because task "
			"[%d] is already dead.\n",
			metadata->vdrm_pid);
		return;
	}

	if (panic_on_kill) {
		panic("About to kill %p due to %d with subcode %lld\n", task, reason, subcode);
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
		vmdr_log_info(
			"Skipping non fatal guard exception for %s [%d]\n",
			task_best_name(task), task_pid(task));
		goto out;
	}

	pid = task_pid(task);
	if (killing_self) {
		p = get_bsdtask_info(task);
	} else {
		p = proc_find(pid);
		if (p && proc_task(p) != task) {
			vmdr_log_error(
				"Unable to deliver guard exception because proc is gone & pid rolled over.\n");
			goto out;
		}
	}

	if (!p) {
		vmdr_log_error(
			"Unable to deliver guard exception because task does not have a proc.\n");
		goto out;
	}

	int flags = PX_DEBUG_NO_HONOR;
	exception_info_t info = {
		.os_reason = OS_REASON_GUARD,
		.exception_type = EXC_GUARD,
		.mx_code = code,
		.mx_subcode = subcode
	};

	vmdr_log("Force-exiting %s [%d]\n", task_best_name(task), task_pid(task));

	err = exit_with_mach_exception(p, info, flags);
	if (err != 0) {
		vmdr_log_error("Unable to deliver guard exception to %p: %d\n", p, err);
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

#pragma mark Copy I/O

static user_addr_t
get_entries_ptr(vm_deferred_reclamation_metadata_t metadata)
{
	return metadata->vdrm_buffer_addr +
	       offsetof(struct mach_vm_reclaim_ring_s, entries);
}

static user_addr_t
get_indices_ptr(user_addr_t buffer_addr)
{
	return buffer_addr +
	       offsetof(struct mach_vm_reclaim_ring_s, indices);
}

static user_addr_t
get_head_ptr(user_addr_t indices)
{
	return indices + offsetof(struct mach_vm_reclaim_indices_s, head);
}

static user_addr_t
get_tail_ptr(user_addr_t indices)
{
	return indices + offsetof(struct mach_vm_reclaim_indices_s, tail);
}

static user_addr_t
get_busy_ptr(user_addr_t indices)
{
	return indices + offsetof(struct mach_vm_reclaim_indices_s, busy);
}

static kern_return_t
reclaim_handle_copyio_error(vm_deferred_reclamation_metadata_t metadata, int result)
{
	if (result != 0 && (result != EFAULT || !vm_fault_get_disabled())) {
		vmdr_log_error("Killing [%d] due to copy I/O error\n", metadata->vdrm_pid);
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
	user_addr_t indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyin_atomic64(head_ptr, head);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		vmdr_log_error(
			"Unable to copy head ptr from 0x%llx: err=%d\n", head_ptr, result);
	}
	return kr;
}

static kern_return_t
reclaim_copyin_tail(vm_deferred_reclamation_metadata_t metadata, uint64_t *tail)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	user_addr_t tail_ptr = get_tail_ptr(indices);

	result = copyin_atomic64(tail_ptr, tail);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		vmdr_log_error(
			"Unable to copy tail ptr from 0x%llx: err=%d\n", tail_ptr, result);
	}
	return kr;
}

static kern_return_t
reclaim_copyin_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t *busy)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyin_atomic64(busy_ptr, busy);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		vmdr_log_error(
			"Unable to copy busy ptr from 0x%llx: err=%d\n", busy_ptr, result);
	}
	return kr;
}

static bool
reclaim_copyout_busy(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	user_addr_t busy_ptr = get_busy_ptr(indices);

	result = copyout_atomic64(value, busy_ptr);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		vmdr_log_error(
			"Unable to copy %llu to busy ptr at 0x%llx: err=%d\n", value, busy_ptr, result);
	}
	return kr;
}

static bool
reclaim_copyout_head(vm_deferred_reclamation_metadata_t metadata, uint64_t value)
{
	int result;
	kern_return_t kr;
	user_addr_t indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	user_addr_t head_ptr = get_head_ptr(indices);

	result = copyout_atomic64(value, head_ptr);
	kr = reclaim_handle_copyio_error(metadata, result);
	if (kr != KERN_SUCCESS && kr != KERN_MEMORY_ERROR) {
		vmdr_log_error(
			"Unable to copy %llu to head ptr at 0x%llx: err=%d\n", value, head_ptr, result);
	}
	return kr;
}

#pragma mark Reclamation

/*
 * @func reclaim_chunk
 *
 * @brief
 * Reclaim a batch of entries from the buffer.
 *
 * @param bytes_to_reclaim
 * Number of bytes caller wishes to reclaim from the buffer
 *
 * @param bytes_reclaimed_out
 * The number of bytes reclaimed from the buffer written out
 *
 * @param chunk_size
 * The maximum number of entries to hold busy and reclaim from (must
 * be <= kReclaimChunkSize)
 *
 * @param num_reclaimed_out
 * The number of entries reclaimed written out
 *
 * @discussion
 * If the buffer has been exhausted of entries (tail == head),
 * num_reclaimed_out will be zero. It is important that the caller abort any
 * loops if such a condition is met.
 */
static kern_return_t
reclaim_chunk(vm_deferred_reclamation_metadata_t metadata,
    uint64_t bytes_to_reclaim, uint64_t *bytes_reclaimed_out,
    mach_vm_reclaim_count_t chunk_size, mach_vm_reclaim_count_t *num_reclaimed_out)
{
	kern_return_t kr = KERN_SUCCESS;
	int result = 0;
	mach_vm_reclaim_count_t num_reclaimed = 0, num_copied = 0;
	uint64_t bytes_reclaimed = 0;
	uint64_t head = 0, tail = 0, busy = 0, num_to_reclaim = 0, new_tail = 0;
	user_addr_t indices;
	vm_map_t map = metadata->vdrm_map;
	vm_map_switch_context_t switch_ctx;
	struct mach_vm_reclaim_entry_s copied_entries[kReclaimChunkSize];

	assert(metadata != NULL);
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_NOTOWNED);
	vmdr_metadata_assert_owned(metadata);

	assert(chunk_size <= kReclaimChunkSize);

	KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_START,
	    metadata->vdrm_pid, bytes_to_reclaim);

	memset(copied_entries, 0, sizeof(copied_entries));

	indices = get_indices_ptr(metadata->vdrm_buffer_addr);
	switch_ctx = vm_map_switch_to(map);

	kr = reclaim_copyin_busy(metadata, &busy);
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	kr = reclaim_copyin_head(metadata, &head);
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	kr = reclaim_copyin_tail(metadata, &tail);
	if (kr != KERN_SUCCESS) {
		goto done;
	}

	/*
	 * NB: busy may not be exactly equal to head if the jetsam
	 * thread fails to fault on the indices after having marked
	 * entries busy
	 */
	if (busy < head || (busy - head) > kReclaimChunkSize) {
		vmdr_log_error(
			"Userspace modified head or busy pointer! head: %llu "
			"(0x%llx) | busy: %llu (0x%llx) | tail = %llu (0x%llx)\n",
			head, get_head_ptr(indices), busy, get_busy_ptr(indices), tail,
			get_tail_ptr(indices));
		reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_INDEX_FAILURE,
		    busy);
		kr = KERN_FAILURE;
		goto done;
	}

	if (tail < head) {
		/*
		 * Userspace is likely in the middle of trying to re-use an entry,
		 * bail on this reclamation.
		 */
		vmdr_log_error(
			"Tail < head! Userspace is likely attempting a "
			"cancellation; aborting reclamation | head: %llu "
			"(0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
			head, get_head_ptr(indices), tail, get_tail_ptr(indices), busy,
			get_busy_ptr(indices));
		kr = KERN_ABORTED;
		goto done;
	}

	/*
	 * NB: If any of the copyouts below fail due to faults being disabled,
	 * the buffer may be left in a state where several entries are unusable
	 * until the next reclamation (i.e. busy > head)
	 */
	num_to_reclaim = tail - head;
	while (true) {
		num_to_reclaim = MIN(num_to_reclaim, chunk_size);
		if (num_to_reclaim == 0) {
			break;
		}
		busy = head + num_to_reclaim;
		kr = reclaim_copyout_busy(metadata, busy);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
		os_atomic_thread_fence(seq_cst);
		kr = reclaim_copyin_tail(metadata, &new_tail);
		if (kr != KERN_SUCCESS) {
			goto done;
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
			vmdr_log_error(
				"Tail < head! Userspace is likely attempting a "
				"cancellation; aborting reclamation | head: %llu "
				"(0x%llx) > tail: %llu (0x%llx) | busy = %llu (0x%llx)\n",
				head, get_head_ptr(indices), tail, get_tail_ptr(indices), busy,
				get_busy_ptr(indices));
			/* Reset busy back to head */
			reclaim_copyout_busy(metadata, head);
			kr = KERN_ABORTED;
			goto done;
		}
		/* Can't reclaim these entries. Try again */
		num_to_reclaim = tail - head;
		if (num_to_reclaim == 0) {
			/* Nothing left to reclaim. Reset busy to head. */
			kr = reclaim_copyout_busy(metadata, head);
			if (kr != KERN_SUCCESS) {
				goto done;
			}
			break;
		}
		/*
		 * Note that num_to_reclaim must have gotten smaller since tail got smaller,
		 * so this is gauranteed to converge.
		 */
	}
	vmdr_log_debug("[%d] reclaiming up to %llu entries (%llu KiB) head=%llu "
	    "busy=%llu tail=%llu len=%u", metadata->vdrm_pid, num_to_reclaim,
	    bytes_reclaimed, head, busy, tail, metadata->vdrm_buffer_len);

	uint64_t memcpy_start_idx = head % metadata->vdrm_buffer_len;
	while (num_copied < num_to_reclaim) {
		uint64_t memcpy_end_idx = memcpy_start_idx + num_to_reclaim - num_copied;
		// Clamp the end idx to the buffer. We'll handle wrap-around in our next go around the loop.
		memcpy_end_idx = MIN(memcpy_end_idx, metadata->vdrm_buffer_len);
		uint64_t num_to_copy = memcpy_end_idx - memcpy_start_idx;

		assert(num_to_copy + num_copied <= kReclaimChunkSize);
		user_addr_t src_ptr = get_entries_ptr(metadata) +
		    (memcpy_start_idx * sizeof(struct mach_vm_reclaim_entry_s));
		struct mach_vm_reclaim_entry_s *dst_ptr = copied_entries + num_copied;
		result = copyin(src_ptr, dst_ptr,
		    (num_to_copy * sizeof(struct mach_vm_reclaim_entry_s)));
		kr = reclaim_handle_copyio_error(metadata, result);
		if (kr != KERN_SUCCESS) {
			if (kr != KERN_MEMORY_ERROR || !vm_fault_get_disabled()) {
				vmdr_log_error(
					"Unable to copyin %llu entries in reclaim "
					"buffer at 0x%llx to 0x%llx: err=%d\n",
					num_to_copy, src_ptr, (uint64_t) dst_ptr, result);
			}
			goto done;
		}

		num_copied += num_to_copy;
		memcpy_start_idx = (memcpy_start_idx + num_to_copy) % metadata->vdrm_buffer_len;
	}

	for (num_reclaimed = 0; num_reclaimed < num_to_reclaim && bytes_reclaimed < bytes_to_reclaim; num_reclaimed++) {
		mach_vm_reclaim_entry_t entry = &copied_entries[num_reclaimed];
		KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_START,
		    metadata->vdrm_pid, entry->address, entry->size,
		    entry->behavior);
		if (entry->address != 0 && entry->size != 0) {
			vm_map_address_t start = vm_map_trunc_page(entry->address,
			    VM_MAP_PAGE_MASK(map));
			vm_map_address_t end = vm_map_round_page(entry->address + entry->size,
			    VM_MAP_PAGE_MASK(map));
			DTRACE_VM4(vm_reclaim_entry,
			    pid_t, metadata->vdrm_pid,
			    mach_vm_address_t, entry->address,
			    mach_vm_address_t, end,
			    mach_vm_reclaim_action_t, entry->behavior);
			KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_START,
			    metadata->vdrm_pid, start, end,
			    entry->behavior);
			vmdr_log_debug("[%d] Reclaiming entry %llu (0x%llx, 0x%llx)\n", metadata->vdrm_pid, head + num_reclaimed, start, end);
			switch (entry->behavior) {
			case VM_RECLAIM_DEALLOCATE:
				kr = vm_map_remove_guard(map,
				    start, end, VM_MAP_REMOVE_GAPS_FAIL,
				    KMEM_GUARD_NONE).kmr_return;
				if (kr == KERN_INVALID_VALUE) {
					vmdr_log_error(
						"[%d] Killing due to virtual-memory guard at (0x%llx, 0x%llx)\n",
						metadata->vdrm_pid, start, end);
					reclaim_kill_with_reason(metadata, kGUARD_EXC_DEALLOC_GAP, entry->address);
					goto done;
				} else if (kr != KERN_SUCCESS) {
					vmdr_log_error(
						"[%d] Killing due to deallocation failure at (0x%llx, 0x%llx) err=%d\n",
						metadata->vdrm_pid, start, end, kr);
					reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE, kr);
					goto done;
				}
				break;
			case VM_RECLAIM_FREE:
				/*
				 * TODO: This should free the backing pages directly instead of using
				 * VM_BEHAVIOR_REUSABLE, which will mark the pages as clean and let them
				 * age in the LRU.
				 */
				kr = vm_map_behavior_set(map, start,
				    end, VM_BEHAVIOR_REUSABLE);
				if (kr != KERN_SUCCESS) {
					vmdr_log_error(
						"[%d] Failed to free(reusable) (0x%llx, 0x%llx) err=%d\n",
						metadata->vdrm_pid, start, end, kr);
				}
				break;
			default:
				vmdr_log_error(
					"attempted to reclaim entry with unsupported behavior %uh",
					entry->behavior);
				reclaim_kill_with_reason(metadata, kGUARD_EXC_RECLAIM_DEALLOCATE_FAILURE, kr);
				kr = KERN_INVALID_VALUE;
				goto done;
			}
			bytes_reclaimed += entry->size;
			KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_ENTRY) | DBG_FUNC_END,
			    kr);
		}
	}

	assert(head + num_reclaimed <= busy);
	head += num_reclaimed;
	kr = reclaim_copyout_head(metadata, head);
	if (kr != KERN_SUCCESS) {
		goto done;
	}
	if (busy > head) {
		busy = head;
		kr = reclaim_copyout_busy(metadata, busy);
		if (kr != KERN_SUCCESS) {
			goto done;
		}
	}

done:
	vmdr_log_debug("[%d] reclaimed %u entries (%llu KiB) head=%llu "
	    "busy=%llu tail=%llu len=%u", metadata->vdrm_pid, num_reclaimed,
	    bytes_reclaimed, head, busy, tail, metadata->vdrm_buffer_len);
	vm_map_switch_back(switch_ctx);
	KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_CHUNK) | DBG_FUNC_END,
	    bytes_reclaimed, num_reclaimed, kr);
	if (bytes_reclaimed_out) {
		*bytes_reclaimed_out = bytes_reclaimed;
	}
	if (num_reclaimed_out) {
		*num_reclaimed_out = num_reclaimed;
	}
	return kr;
}

/*
 * @func vmdr_reclaim_from_buffer
 *
 * @brief
 * Reclaim entries until the buffer's estimated number of available bytes
 * is <= @c bytes_to_reclaim.
 *
 * @param bytes_to_reclaim
 * The minimum number of bytes to reclaim
 *
 * @param num_bytes_reclaimed_out
 * The number of bytes reclaimed written out
 *
 * @param options
 * If RECLAIM_NO_FAULT is set, do not fault on the buffer if it has been paged
 * out.
 *
 * @discussion
 * The buffer should be owned by the caller.
 */
static kern_return_t
vmdr_reclaim_from_buffer(vm_deferred_reclamation_metadata_t metadata,
    size_t bytes_to_reclaim, size_t *num_bytes_reclaimed_out,
    vm_deferred_reclamation_options_t options)
{
	kern_return_t kr = KERN_SUCCESS;

	if (options & RECLAIM_NO_FAULT) {
		vm_fault_disable();
	}

	size_t total_bytes_reclaimed = 0;
	while (total_bytes_reclaimed < bytes_to_reclaim) {
		uint64_t cur_bytes_reclaimed;
		mach_vm_reclaim_count_t entries_reclaimed;
		kr = reclaim_chunk(metadata, bytes_to_reclaim - total_bytes_reclaimed,
		    &cur_bytes_reclaimed, kReclaimChunkSize, &entries_reclaimed);
		total_bytes_reclaimed += cur_bytes_reclaimed;
		if (entries_reclaimed == 0 || kr != KERN_SUCCESS) {
			break;
		}
	}

	if (options & RECLAIM_NO_FAULT) {
		vm_fault_enable();
	}
	vmdr_log_debug("reclaimed %lu B / %lu B from %d\n", total_bytes_reclaimed, bytes_to_reclaim, metadata->vdrm_pid);
	if (num_bytes_reclaimed_out) {
		*num_bytes_reclaimed_out = total_bytes_reclaimed;
	}
	return kr;
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

#pragma mark Buffer Resize/Synchronization

kern_return_t
vm_deferred_reclamation_buffer_flush_internal(task_t task,
    mach_vm_reclaim_count_t num_entries_to_reclaim)
{
	kern_return_t kr;
	vm_deferred_reclamation_metadata_t metadata = NULL;
	mach_vm_reclaim_count_t total_reclaimed = 0;
	uint64_t bytes_reclaimed = 0;

	if (!task_is_active(task)) {
		return KERN_INVALID_TASK;
	}

	metadata = get_task_reclaim_metadata(task);
	if (metadata == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	vmdr_metadata_own(metadata);

	vmdr_log_debug("[%d] flushing %u entries\n", task_pid(task), num_entries_to_reclaim);
	KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_FLUSH) | DBG_FUNC_START, metadata->vdrm_pid, num_entries_to_reclaim);

	while (total_reclaimed < num_entries_to_reclaim) {
		mach_vm_reclaim_count_t cur_reclaimed;
		uint64_t cur_bytes_reclaimed;
		mach_vm_reclaim_count_t chunk_size = MIN(num_entries_to_reclaim - total_reclaimed, kReclaimChunkSize);
		kr = reclaim_chunk(metadata, UINT64_MAX, &cur_bytes_reclaimed, chunk_size,
		    &cur_reclaimed);
		total_reclaimed += cur_reclaimed;
		bytes_reclaimed += cur_bytes_reclaimed;
		if (cur_reclaimed == 0) {
			break;
		} else if (kr == KERN_ABORTED) {
			/*
			 * Unable to reclaim due to a lost race with
			 * userspace, yield the gate and try again
			 */
			vmdr_metadata_disown(metadata);
			vmdr_metadata_own(metadata);
			continue;
		} else if (kr != KERN_SUCCESS) {
			break;
		}
	}

	vmdr_metadata_lock(metadata);
	metadata->vdrm_cumulative_reclaimed_bytes += bytes_reclaimed;
	vmdr_metadata_disown_locked(metadata);
	vmdr_metadata_unlock(metadata);

	KDBG_FILTERED(VM_RECLAIM_CODE(VM_RECLAIM_FLUSH) | DBG_FUNC_END, kr, total_reclaimed, bytes_reclaimed);
	DTRACE_VM2(reclaim_flush,
	    mach_vm_reclaim_count_t, num_entries_to_reclaim,
	    size_t, bytes_reclaimed);
	return kr;
}

kern_return_t
vm_deferred_reclamation_buffer_resize_internal(
	task_t                   task,
	mach_vm_reclaim_count_t len)
{
	kern_return_t kr;
	mach_vm_reclaim_count_t num_entries_reclaimed = 0;
	mach_vm_reclaim_count_t old_len;

	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	if (len == 0) {
		return KERN_INVALID_ARGUMENT;
	}
	vm_deferred_reclamation_metadata_t metadata = get_task_reclaim_metadata(task);
	if (metadata == NULL) {
		return KERN_INVALID_TASK;
	}

	/* Size must be multiple of page size */
	vm_map_t map = task->map;
	mach_vm_size_t new_size = vmdr_round_len_to_size(map, len);
	if (new_size == 0) {
		return KERN_INVALID_ARGUMENT;
	}
	if (new_size > metadata->vdrm_buffer_size) {
		return KERN_NO_SPACE;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_RESIZE) | DBG_FUNC_START,
	    task_pid(task), new_size);

	/*
	 * Prevent other threads from operating on this buffer while it is
	 * resized. It is the caller's responsibility to ensure mutual
	 * exclusion with other user threads
	 */
	vmdr_metadata_own(metadata);

	old_len = metadata->vdrm_buffer_len;

	vmdr_log_debug("%s [%d] resizing buffer %u -> %u entries\n",
	    task_best_name(task), task_pid(task), old_len, len);

	/*
	 * Reclaim all the entries currently in the buffer to prevent re-use
	 * of old reclaim ids that will alias differently into the newly sized
	 * buffer.
	 *
	 * TODO: Consider encoding the ringbuffer-capacity in the
	 * mach_vm_reclaim_id_t, so reuses can still find objects after a resize.
	 */
	do {
		kr = reclaim_chunk(metadata, UINT64_MAX, NULL, kReclaimChunkSize,
		    &num_entries_reclaimed);
		if (kr != KERN_SUCCESS) {
			goto fail;
		}
	} while (num_entries_reclaimed > 0);

	/* Publish new user addresses in kernel metadata */
	vmdr_metadata_lock(metadata);
	metadata->vdrm_buffer_len = len;
	vmdr_metadata_disown_locked(metadata);
	vmdr_metadata_unlock(metadata);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_RESIZE) | DBG_FUNC_END, KERN_SUCCESS, num_entries_reclaimed);
	DTRACE_VM2(reclaim_ring_resize,
	    mach_vm_reclaim_count_t, old_len,
	    mach_vm_reclaim_count_t, len);
	return KERN_SUCCESS;

fail:
	vmdr_metadata_disown(metadata);
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_RESIZE) | DBG_FUNC_END, kr, num_entries_reclaimed);
	return kr;
}

#pragma mark Accounting

#if CONFIG_WORKING_SET_ESTIMATION
extern vm_pressure_level_t memorystatus_vm_pressure_level;

static uint64_t
vmdr_metadata_autotrim_threshold(vm_deferred_reclamation_metadata_t metadata)
{
	kern_return_t kr;
	uint32_t autotrim_pct;

	/*
	 * Determine the autotrim threshold based on the current pressure level
	 */
	vm_pressure_level_t pressure_level = os_atomic_load(&memorystatus_vm_pressure_level, relaxed);
	switch (pressure_level) {
	case kVMPressureNormal:
		autotrim_pct = vm_reclaim_autotrim_pct_normal;
		break;
	case kVMPressureWarning:
	case kVMPressureUrgent:
		autotrim_pct = vm_reclaim_autotrim_pct_pressure;
		break;
	case kVMPressureCritical:
		autotrim_pct = vm_reclaim_autotrim_pct_critical;
		break;
	default:
		panic("vm_reclaim: unexpected vm_pressure_level %d", pressure_level);
	}

	/*
	 * Estimate the task's maximum working set size
	 */
	ledger_amount_t phys_footprint_max = 0;
	kr = ledger_get_lifetime_max(metadata->vdrm_task->ledger,
	    task_ledgers.phys_footprint, &phys_footprint_max);
	assert3u(kr, ==, KERN_SUCCESS);

	return phys_footprint_max * autotrim_pct / 100;
}

#define VMDR_WMA_UNIT (1 << 8)
#define VMDR_WMA_MIX(base, e)  ((vm_reclaim_wma_weight_base * (base) + (e) * VMDR_WMA_UNIT * vm_reclaim_wma_weight_cur) / vm_reclaim_wma_denom)

static size_t
vmdr_metadata_reset_min_bytes(vm_deferred_reclamation_metadata_t metadata)
{
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_OWNED);
	metadata->vdrm_reclaimable_bytes_min =
	    metadata->vdrm_cumulative_uncancelled_bytes -
	    metadata->vdrm_cumulative_reclaimed_bytes;
	return metadata->vdrm_reclaimable_bytes_min;
}

/*
 * @func vmdr_ws_sample
 *
 * @brief sample the working set size of the given buffer
 *
 * @param metadata
 * The reclaim buffer to sample
 *
 * @param trim_threshold_out
 * If the buffer should be trimmed, the amount to trim (in bytes) will be
 * written out
 *
 * @returns true iff the buffer should be trimmed
 *
 * @discussion
 * The caller must hold the buffer locked.
 */
static bool
vmdr_sample_working_set(vm_deferred_reclamation_metadata_t metadata,
    size_t *trim_threshold_out)
{
	LCK_MTX_ASSERT(&metadata->vdrm_lock, LCK_MTX_ASSERT_OWNED);

	uint64_t now = mach_absolute_time();
	if (now - metadata->vdrm_last_sample_abs < vm_reclaim_sampling_period_abs) {
		/* A sampling period has not elapsed */
		return false;
	}

	size_t estimated_reclaimable_bytes;
	uint64_t samples_elapsed = (now - metadata->vdrm_last_sample_abs) /
	    vm_reclaim_sampling_period_abs;

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_SAMPLE) | DBG_FUNC_START,
	    metadata->vdrm_pid,
	    now,
	    metadata->vdrm_last_sample_abs,
	    metadata->vdrm_reclaimable_bytes_min);

	if (samples_elapsed > vm_reclaim_abandonment_threshold) {
		/*
		 * Many sampling periods have elapsed since the ring was
		 * last sampled. Don't bother computing the WMA and assume
		 * the buffer's current contents are unneeded.
		 */
		estimated_reclaimable_bytes =
		    metadata->vdrm_cumulative_uncancelled_bytes -
		    metadata->vdrm_cumulative_reclaimed_bytes;
		metadata->vdrm_reclaimable_bytes_min = estimated_reclaimable_bytes;
		metadata->vdrm_reclaimable_bytes_wma = estimated_reclaimable_bytes;
	} else {
		/*
		 * Compute an exponential moving average of the minimum amount of reclaimable
		 * memory in this buffer. Multiple sampling periods may have elapsed
		 * since the last sample. By definition, the minimum must be the same for
		 * all elapsed periods (otherwise libmalloc would have called down to
		 * update accounting)
		 */
		for (unsigned int i = 0; i < samples_elapsed; i++) {
			metadata->vdrm_reclaimable_bytes_wma = VMDR_WMA_MIX(
				metadata->vdrm_reclaimable_bytes_wma,
				metadata->vdrm_reclaimable_bytes_min);
		}

		/* Reset the minimum to start a new sampling interval */
		estimated_reclaimable_bytes = vmdr_metadata_reset_min_bytes(metadata);
	}

	metadata->vdrm_last_sample_abs = now;

	size_t trim_threshold_bytes = MIN(metadata->vdrm_reclaimable_bytes_min,
	    metadata->vdrm_reclaimable_bytes_wma / VMDR_WMA_UNIT);
	size_t autotrim_threshold = vmdr_metadata_autotrim_threshold(metadata);

	bool trim_needed = trim_threshold_bytes >= vm_map_page_size(metadata->vdrm_map) &&
	    trim_threshold_bytes >= autotrim_threshold;

	*trim_threshold_out = vm_map_round_page(trim_threshold_bytes,
	    vm_map_page_mask(metadata->vdrm_map));

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_SAMPLE) | DBG_FUNC_END,
	    *trim_threshold_out,
	    trim_needed,
	    estimated_reclaimable_bytes);
	DTRACE_VM5(reclaim_sample,
	    pid_t, metadata->vdrm_pid,
	    uint64_t, metadata->vdrm_reclaimable_bytes_wma,
	    size_t, metadata->vdrm_reclaimable_bytes_min,
	    size_t, estimated_reclaimable_bytes,
	    size_t, *trim_threshold_out);
	vmdr_log_debug("sampled buffer with min %lu est %lu trim %lu wma %llu\n",
	    metadata->vdrm_reclaimable_bytes_min,
	    estimated_reclaimable_bytes,
	    trim_threshold_bytes,
	    metadata->vdrm_reclaimable_bytes_wma / VMDR_WMA_UNIT);

	return trim_needed;
}
#endif /* CONFIG_WORKING_SET_ESTIMATION */

/*
 * Caller must have buffer owned and unlocked
 */
static kern_return_t
vmdr_trim(vm_deferred_reclamation_metadata_t metadata, size_t bytes_to_reclaim,
    size_t *bytes_reclaimed, vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_TRIM) | DBG_FUNC_START,
	    metadata->vdrm_pid, bytes_to_reclaim);

	kr = vmdr_reclaim_from_buffer(metadata, bytes_to_reclaim,
	    bytes_reclaimed, options);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_TRIM) | DBG_FUNC_END, kr, bytes_reclaimed);
	DTRACE_VM3(reclaim_trim,
	    pid_t, metadata->vdrm_pid,
	    size_t, bytes_to_reclaim,
	    size_t, *bytes_reclaimed);
	return kr;
}

/*
 * Caller must have buffer owned and unlocked
 */
static kern_return_t
vmdr_drain(vm_deferred_reclamation_metadata_t metadata, size_t *bytes_reclaimed,
    vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_DRAIN) | DBG_FUNC_START,
	    metadata->vdrm_pid);

	kr = vmdr_reclaim_from_buffer(metadata, UINT64_MAX,
	    bytes_reclaimed, options);

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_DRAIN) | DBG_FUNC_END, kr, bytes_reclaimed);
	DTRACE_VM2(reclaim_drain,
	    pid_t, metadata->vdrm_pid,
	    size_t, *bytes_reclaimed);
	return kr;
}

kern_return_t
vm_deferred_reclamation_buffer_update_reclaimable_bytes_internal(task_t task, uint64_t bytes_placed_in_buffer)
{
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;
	size_t estimated_reclaimable_bytes, bytes_to_reclaim, bytes_reclaimed = 0;
	kern_return_t kr = KERN_SUCCESS;
	if (metadata == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_START,
	    metadata->vdrm_pid, bytes_placed_in_buffer);

	vmdr_metadata_lock(metadata);

	if (!metadata->vdrm_pid) {
		/* If this is a forked child, we may not yet have a pid */
		metadata->vdrm_pid = task_pid(task);
	}

	/*
	 * The client is allowed to make this call in parallel from multiple threads.
	 * It's possible that, while we were waiting for the lock, another
	 * thread updated accounting with a larger/newer uncancelled_bytes
	 * value that resulted in a reclaim. We can't provide strict ordering
	 * with the current implementation, but we can at least detect very
	 * erroneous stale values that would result in the uncancelled-byte
	 * count being less than the reclaimed-byte-count (which cannot be
	 * accurate).
	 *
	 * TODO: Consider making this a try_copyin of the userspace value
	 * under the mutex to ensure ordering/consistency (rdar://137607771)
	 */
	if (bytes_placed_in_buffer < metadata->vdrm_cumulative_reclaimed_bytes) {
		goto done;
	}

	metadata->vdrm_cumulative_uncancelled_bytes = bytes_placed_in_buffer;
	estimated_reclaimable_bytes = bytes_placed_in_buffer - metadata->vdrm_cumulative_reclaimed_bytes;
#if CONFIG_WORKING_SET_ESTIMATION
	bool should_reclaim = vmdr_sample_working_set(metadata, &bytes_to_reclaim);
	if (should_reclaim) {
		vmdr_metadata_own_locked(metadata, RECLAIM_OPTIONS_NONE);
		lck_mtx_unlock(&metadata->vdrm_lock);
		vmdr_log_debug("trimming pid %d\n", metadata->vdrm_pid);

		kr = vmdr_trim(metadata, bytes_to_reclaim, &bytes_reclaimed, RECLAIM_OPTIONS_NONE);

		vmdr_metadata_lock(metadata);
		metadata->vdrm_cumulative_reclaimed_bytes += bytes_reclaimed;
		/* Reset the current minimum now that the buffer has been trimmed down */
		vmdr_metadata_reset_min_bytes(metadata);
		vmdr_metadata_disown_locked(metadata);
		if (kr == KERN_ABORTED) {
			/*
			 * We were unable to complete the trim due to a lost
			 * race with userspace. This need not be fatal b/c the
			 * accounting was successfully updated.
			 */
			kr = KERN_SUCCESS;
		}
	} else {
		/* Update the minimum for the current sampling period */
		metadata->vdrm_reclaimable_bytes_min = MIN(metadata->vdrm_reclaimable_bytes_min, estimated_reclaimable_bytes);
	}
#else /* !CONFIG_WORKING_SET_ESTIMATION */
	if (estimated_reclaimable_bytes > vm_reclaim_max_threshold) {
		bytes_to_reclaim = vm_reclaim_max_threshold - estimated_reclaimable_bytes;
		vmdr_metadata_own_locked(metadata, RECLAIM_OPTIONS_NONE);
		vmdr_metadata_unlock(metadata);
		kr = vmdr_trim(metadata, bytes_to_reclaim, &bytes_reclaimed, RECLAIM_OPTIONS_NONE);
		vmdr_metadata_lock(metadata);
		metadata->vdrm_cumulative_reclaimed_bytes += bytes_reclaimed;
		vmdr_metadata_disown_locked(metadata);
		if (kr == KERN_ABORTED) {
			/*
			 * We were unable to complete the trim due to a lost
			 * race with userspace. This need not be fatal b/c the
			 * accounting was successfully updated.
			 */
			kr = KERN_SUCCESS;
		}
	}
#endif /* CONFIG_WORKING_SET_ESTIMATION */

done:
	KDBG(VM_RECLAIM_CODE(VM_RECLAIM_UPDATE_ACCOUNTING) | DBG_FUNC_END,
	    metadata->vdrm_cumulative_uncancelled_bytes,
	    metadata->vdrm_cumulative_reclaimed_bytes,
	    bytes_reclaimed);
	vmdr_metadata_unlock(metadata);
	return kr;
}

kern_return_t
vm_deferred_reclamation_task_drain(task_t task,
    vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	size_t bytes_reclaimed;

	task_lock(task);
	if (!task_is_active(task) || task_is_halting(task)) {
		task_unlock(task);
		return KERN_ABORTED;
	}
	vm_deferred_reclamation_metadata_t metadata = task->deferred_reclamation_metadata;
	if (metadata == NULL) {
		task_unlock(task);
		return KERN_SUCCESS;
	}
	vmdr_metadata_retain(metadata);
	task_unlock(task);

	vmdr_metadata_own(metadata);

	kr = vmdr_drain(metadata, &bytes_reclaimed, options);

	vmdr_metadata_lock(metadata);
	metadata->vdrm_cumulative_reclaimed_bytes += bytes_reclaimed;
	vmdr_metadata_disown_locked(metadata);
	vmdr_metadata_unlock(metadata);

	vmdr_metadata_release(metadata);
	return kr;
}

void
vm_deferred_reclamation_task_suspend(task_t task)
{
	if (task->deferred_reclamation_metadata) {
		sched_cond_signal(&vm_reclaim_scavenger_cond, vm_reclaim_scavenger_thread);
	}
}

#pragma mark KPIs

vm_deferred_reclamation_metadata_t
vm_deferred_reclamation_task_fork(task_t task, vm_deferred_reclamation_metadata_t parent)
{
	vm_deferred_reclamation_metadata_t metadata = NULL;
	vmdr_metadata_assert_owned(parent);

	assert(task->deferred_reclamation_metadata == NULL);
	metadata = vmdr_metadata_alloc(task, parent->vdrm_buffer_addr,
	    parent->vdrm_buffer_size, parent->vdrm_buffer_len);

	metadata->vdrm_cumulative_reclaimed_bytes = parent->vdrm_cumulative_reclaimed_bytes;
	metadata->vdrm_cumulative_uncancelled_bytes = parent->vdrm_cumulative_uncancelled_bytes;
#if CONFIG_WORKING_SET_ESTIMATION
	metadata->vdrm_reclaimable_bytes_min = parent->vdrm_reclaimable_bytes_min;
	metadata->vdrm_reclaimable_bytes_wma = parent->vdrm_reclaimable_bytes_wma;
	metadata->vdrm_last_sample_abs = parent->vdrm_last_sample_abs;
#endif /* CONFIG_WORKING_SET_ESTIMATION */

	return metadata;
}

void
vm_deferred_reclamation_task_fork_register(vm_deferred_reclamation_metadata_t metadata)
{
	assert(metadata != NULL);
	assert(!metadata->vdrm_is_registered);

	lck_mtx_lock(&reclaim_buffers_lock);
	metadata->vdrm_is_registered = true;
	vmdr_list_append_locked(metadata);
	lck_mtx_unlock(&reclaim_buffers_lock);
}

bool
vm_deferred_reclamation_task_has_ring(task_t task)
{
	return task->deferred_reclamation_metadata != NULL;
}

void
vm_deferred_reclamation_ring_own(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_own(metadata);
}

void
vm_deferred_reclamation_ring_disown(vm_deferred_reclamation_metadata_t metadata)
{
	vmdr_metadata_disown(metadata);
}

void
vm_deferred_reclamation_gc(vm_deferred_reclamation_gc_action_t action, vm_deferred_reclamation_options_t options)
{
	vmdr_garbage_collect(action, options);
}

#pragma mark Global Reclamation GC

static void
vmdr_garbage_collect(vm_deferred_reclamation_gc_action_t action, vm_deferred_reclamation_options_t options)
{
	kern_return_t kr;
	size_t bytes_reclaimed, bytes_to_reclaim;
	bool should_reclaim;
	gate_wait_result_t wr;

#if !CONFIG_WORKING_SET_ESTIMATION
	if (action == RECLAIM_GC_TRIM) {
		/* GC_TRIM is a no-op without working set estimation */
		return;
	}
#endif /* !CONFIG_WORKING_SET_ESTIMATION */

	lck_mtx_lock(&reclaim_buffers_lock);
	kr = lck_mtx_gate_try_close(&reclaim_buffers_lock, &vm_reclaim_gc_gate);
	if (kr != KERN_SUCCESS) {
		if (options & RECLAIM_NO_WAIT) {
			lck_mtx_unlock(&reclaim_buffers_lock);
			return;
		}
		wr = lck_mtx_gate_wait(&reclaim_buffers_lock, &vm_reclaim_gc_gate, LCK_SLEEP_DEFAULT, THREAD_UNINT, TIMEOUT_WAIT_FOREVER);
		assert3u(wr, ==, GATE_HANDOFF);
	}

	vm_reclaim_gc_epoch++;
	vmdr_log_debug("running global GC\n");
	while (true) {
		vm_deferred_reclamation_metadata_t metadata = TAILQ_FIRST(&reclaim_buffers);
		if (metadata == NULL) {
			break;
		}
		vmdr_list_remove_locked(metadata);
		vmdr_list_append_locked(metadata);
		vmdr_metadata_retain(metadata);
		lck_mtx_unlock(&reclaim_buffers_lock);

		vmdr_metadata_lock(metadata);

		if (metadata->vdrm_reclaimed_at >= vm_reclaim_gc_epoch) {
			/* We've already seen this one. We're done */
			vmdr_metadata_unlock(metadata);
			vmdr_metadata_release(metadata);
			lck_mtx_lock(&reclaim_buffers_lock);
			break;
		}
		metadata->vdrm_reclaimed_at = vm_reclaim_gc_epoch;

		task_t task = metadata->vdrm_task;
		if (task == TASK_NULL ||
		    !task_is_active(task) ||
		    task_is_halting(task)) {
			goto next;
		}
		bool buffer_is_suspended = task_is_app_suspended(task);
		task = TASK_NULL;

		switch (action) {
		case RECLAIM_GC_DRAIN:
			if (!vmdr_metadata_own_locked(metadata, options)) {
				goto next;
			}
			vmdr_metadata_unlock(metadata);
			vmdr_drain(metadata, &bytes_reclaimed, options);
			vmdr_metadata_lock(metadata);
			vmdr_metadata_disown_locked(metadata);
			break;
		case RECLAIM_GC_SCAVENGE:
			if (buffer_is_suspended) {
				vmdr_metadata_own_locked(metadata, options);
				vmdr_metadata_unlock(metadata);
				/* This buffer is no longer in use, fully reclaim it. */
				vmdr_log_debug("found suspended buffer (%d), draining\n", metadata->vdrm_pid);
				kr = vmdr_drain(metadata, &bytes_reclaimed, options);
				vmdr_metadata_lock(metadata);
				vmdr_metadata_disown_locked(metadata);
			}
			break;
		case RECLAIM_GC_TRIM:
#if CONFIG_WORKING_SET_ESTIMATION
			should_reclaim = vmdr_sample_working_set(metadata, &bytes_to_reclaim);
			if (should_reclaim) {
				vmdr_log_debug("GC found stale buffer (%d), trimming\n", metadata->vdrm_pid);
				vmdr_metadata_own_locked(metadata, options);
				vmdr_metadata_unlock(metadata);
				kr = vmdr_trim(metadata, bytes_to_reclaim, &bytes_reclaimed, options);
				vmdr_metadata_lock(metadata);
				vmdr_metadata_disown_locked(metadata);
			}
#else /* !CONFIG_WORKING_SET_ESTIMATION */
			(void)bytes_to_reclaim;
			(void)should_reclaim;
#endif /* CONFIG_WORKING_SET_ESTIMATION */
			break;
		}
		if (bytes_reclaimed) {
			vm_reclaim_gc_reclaim_count++;
			metadata->vdrm_cumulative_reclaimed_bytes += bytes_reclaimed;
		}
		if (metadata->vdrm_waiters && action != RECLAIM_GC_TRIM) {
			thread_wakeup((event_t)&metadata->vdrm_waiters);
		}
next:
		vmdr_metadata_unlock(metadata);
		vmdr_metadata_release(metadata);
		lck_mtx_lock(&reclaim_buffers_lock);
	}
	lck_mtx_gate_handoff(&reclaim_buffers_lock, &vm_reclaim_gc_gate, GATE_HANDOFF_OPEN_IF_NO_WAITERS);
	lck_mtx_unlock(&reclaim_buffers_lock);
}

OS_NORETURN
static void
vm_reclaim_scavenger_thread_continue(__unused void *param, __unused wait_result_t wr)
{
	sched_cond_ack(&vm_reclaim_scavenger_cond);

	while (true) {
		vmdr_garbage_collect(RECLAIM_GC_SCAVENGE, RECLAIM_OPTIONS_NONE);
		sched_cond_wait(&vm_reclaim_scavenger_cond, THREAD_UNINT, vm_reclaim_scavenger_thread_continue);
	}
}

OS_NORETURN
static void
vm_reclaim_scavenger_thread_init(__unused void *param, __unused wait_result_t wr)
{
	thread_set_thread_name(current_thread(), "VM_reclaim_scavenger");
#if CONFIG_THREAD_GROUPS
	thread_group_vm_add();
#endif /* CONFIG_THREAD_GROUPS */
	sched_cond_wait(&vm_reclaim_scavenger_cond, THREAD_UNINT, vm_reclaim_scavenger_thread_continue);
	__builtin_unreachable();
}

__startup_func
static void
vm_deferred_reclamation_init(void)
{
	vm_reclaim_log_handle = os_log_create("com.apple.xnu", "vm_reclaim");
#if CONFIG_WORKING_SET_ESTIMATION
	nanoseconds_to_absolutetime((uint64_t)vm_reclaim_sampling_period_ns,
	    &vm_reclaim_sampling_period_abs);
#endif /* CONFIG_WORKING_SET_ESTIMATION */

	sched_cond_init(&vm_reclaim_scavenger_cond);
	lck_mtx_gate_init(&reclaim_buffers_lock, &vm_reclaim_gc_gate);
	kern_return_t kr = kernel_thread_start_priority(vm_reclaim_scavenger_thread_init,
	    NULL, BASEPRI_KERNEL, &vm_reclaim_scavenger_thread);
	if (kr != KERN_SUCCESS) {
		panic("Unable to create VM reclaim thread, %d", kr);
	}
}

STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, vm_deferred_reclamation_init);

#pragma mark Debug Interfaces

#if DEVELOPMENT || DEBUG

bool
vm_deferred_reclamation_block_until_task_has_been_reclaimed(task_t task)
{
	bool reclaimed;
	vm_deferred_reclamation_metadata_t metadata = NULL;

	task_lock(task);
	if (!task_is_halting(task) && task_is_active(task)) {
		metadata = task->deferred_reclamation_metadata;
	}
	if (metadata != NULL) {
		vmdr_metadata_retain(metadata);
	}
	task_unlock(task);
	if (metadata == NULL) {
		return false;
	}

	vmdr_metadata_lock(metadata);

	metadata->vdrm_waiters++;
	/* Wake up the scavenger thread */
	sched_cond_signal(&vm_reclaim_scavenger_cond, vm_reclaim_scavenger_thread);
	wait_result_t wr = lck_mtx_sleep(&metadata->vdrm_lock,
	    LCK_SLEEP_DEFAULT, (event_t)&metadata->vdrm_waiters,
	    THREAD_ABORTSAFE);
	metadata->vdrm_waiters--;
	reclaimed = (wr == THREAD_AWAKENED);

	vmdr_metadata_unlock(metadata);
	vmdr_metadata_release(metadata);
	return reclaimed;
}

#endif /* DEVELOPMENT || DEBUG */
