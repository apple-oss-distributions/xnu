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

#ifndef _VM_RECLAIM_H_
#define _VM_RECLAIM_H_

#ifdef PRIVATE
#if defined(__LP64__)

#include <mach/mach_types.h>
#include <mach/kern_return.h>
#include <stdbool.h>

__BEGIN_DECLS

typedef struct mach_vm_reclaim_indices_v1_s {
	_Atomic uint64_t head;
	_Atomic uint64_t tail;
	_Atomic uint64_t busy;
} mach_vm_reclaim_indices_v1_t;

// The action to be performed by the kernel on reclamation of an entry
__enum_decl(mach_vm_reclaim_behavior_v1_t, uint16_t, {
	// Deallocate (unmap) the entry
	MACH_VM_RECLAIM_DEALLOCATE = 0,
	// Mark the entry as clean and leave mapped (VM_BEHAVIOR_REUSABLE)
	MACH_VM_RECLAIM_REUSABLE = 1,
});

typedef struct mach_vm_reclaim_entry_v1_s {
	mach_vm_address_t address;
	uint32_t size;
	mach_vm_reclaim_behavior_v1_t behavior;
	uint16_t flags;
} mach_vm_reclaim_entry_v1_t;

/*
 * Contains the data used for synchronization with the kernel. This structure
 * should be page-aligned.
 */
typedef struct mach_vm_reclaim_buffer_v1_s {
	mach_vm_reclaim_indices_v1_t indices;
	/* align to multiple of entry size */
	uint64_t _unused;
	/*
	 * The ringbuffer entries themselves populate the remainder of this
	 * buffer's vm allocation.
	 */
	mach_vm_reclaim_entry_v1_t entries[0];
} *mach_vm_reclaim_buffer_v1_t;

#if !KERNEL
#define VM_RECLAIM_INDEX_NULL UINT64_MAX

/*
 * Userspace interface for placing items in the reclamation buffer and trying to take them back out.
 * Note that these interfaces are NOT thread safe. It is the caller's responsibility to synchronize concurrent
 * operations on the same buffer.
 *
 * These operations are implemented in libsyscall.
 */

typedef struct mach_vm_reclaim_ringbuffer_v1_s {
	mach_vm_reclaim_buffer_v1_t buffer;
	mach_vm_size_t buffer_len;
	uint64_t va_in_buffer;
	uint64_t last_accounting_given_to_kernel;
} *mach_vm_reclaim_ringbuffer_v1_t;

kern_return_t mach_vm_reclaim_ringbuffer_init(mach_vm_reclaim_ringbuffer_v1_t ringbuffer);

/*
 * Mark the given range as free.
 * Returns a unique identifier for the range that can be used by reclaim_mark_used
 * This will update the userspace reclaim buffer accounting, but will not
 * inform the kernel about the new bytes in the buffer. If the kernel should be informed,
 * should_update_kernel_accounting will be set to true and the caller should call
 * mach_vm_reclaim_update_kernel_accounting. That syscall might reclaim the buffer, so
 * this gives the caller an opportunity to first drop any locks.
 */
uint64_t mach_vm_reclaim_mark_free(
	mach_vm_reclaim_ringbuffer_v1_t buffer,
	mach_vm_address_t start_addr,
	uint32_t size,
	mach_vm_reclaim_behavior_v1_t behavior,
	bool *should_update_kernel_accounting);

/*
 * Attempt to take back the range determined by id.
 * Returns true iff range can now be used.
 * Subsequent calls to reclaim_mark_used with the same id are not supported & may return true or false.
 */
bool mach_vm_reclaim_mark_used(
	mach_vm_reclaim_ringbuffer_v1_t buffer,
	uint64_t id,
	mach_vm_address_t start_addr,
	uint32_t size);

/*
 * Check if the range is available for re-use.
 * Returns true if the range is still available. Note that this doesn't claim the range, so it may be reclaimed in parallel.
 * Note that a return value of false does not guarantee that the kernel has reclaimed the range already (it may just be considering it).
 */
bool mach_vm_reclaim_is_available(
	const mach_vm_reclaim_ringbuffer_v1_t buffer,
	uint64_t id);

/*
 * Check if the range has been reclaimed.
 * Returns true if the range is no longer available for re-use.
 */
bool mach_vm_reclaim_is_reclaimed(
	const mach_vm_reclaim_ringbuffer_v1_t buffer,
	uint64_t id);

/*
 * Force the kernel to reclaim at least num_entries_to_reclaim entries from the ringbuffer (if present).
 * Note that mach_vm_reclaim_mark_free automatically handles the full ringbuffer case.
 */
kern_return_t mach_vm_reclaim_synchronize(
	mach_vm_reclaim_ringbuffer_v1_t ringbuffer,
	mach_vm_size_t num_entries_to_reclaim);

/*
 * Let the kernel know how much VA is in the ringbuffer.
 * The kernel may choose to reclaim from the ringbuffer on this thread.
 * This should be called whenever mach_vm_reclaim_mark_free returns true in
 * should_update_kernel_accounting. It may be called at any other time
 * if the caller wants to update the kernel's accounting & is
 * thread safe w.r.t. all other mach_vm_reclaim calls.
 */
kern_return_t mach_vm_reclaim_update_kernel_accounting(
	const mach_vm_reclaim_ringbuffer_v1_t ring_buffer);

#endif /* !KENREL */

__END_DECLS

#endif /* PRIVATE */

#endif /* __LP64__ */

#endif /* _VM_RECLAIM_H_ */
