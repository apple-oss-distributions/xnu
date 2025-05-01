/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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
#pragma once
#if defined(__LP64__)
#include <mach/mach_types.h>
#include <mach/vm_reclaim.h>
#include <ptrcheck.h>

/*
 * This header exists for the internal implementation in libsyscall/xnu
 * and for observability with debugging tools. It should _NOT_ be used by
 * clients.
 */

#define VM_RECLAIM_MAX_BUFFER_SIZE (128ull << 20)
#define VM_RECLAIM_MAX_CAPACITY ((VM_RECLAIM_MAX_BUFFER_SIZE - \
	offsetof(struct mach_vm_reclaim_ring_s, entries)) / \
	sizeof(struct mach_vm_reclaim_entry_s))

__BEGIN_DECLS

typedef struct mach_vm_reclaim_indices_s {
	_Atomic mach_vm_reclaim_id_t head;
	_Atomic mach_vm_reclaim_id_t tail;
	_Atomic mach_vm_reclaim_id_t busy;
} *mach_vm_reclaim_indices_t;

typedef struct mach_vm_reclaim_entry_s {
	mach_vm_address_t address;
	uint32_t size;
	mach_vm_reclaim_action_t behavior;
	uint8_t _unused[3];
} *mach_vm_reclaim_entry_t;

/*
 * Contains the data used for synchronization with the kernel. This structure
 * should be page-aligned.
 */
struct mach_vm_reclaim_ring_s {
	mach_vm_size_t va_in_buffer;
	mach_vm_size_t last_accounting_given_to_kernel;
	mach_vm_reclaim_count_t len;
	mach_vm_reclaim_count_t max_len;
	struct mach_vm_reclaim_indices_s indices;
	/*
	 * The ringbuffer entries themselves populate the remainder of this
	 * buffer's vm allocation.
	 * NB: the fields preceding `entries` must be aligned to a multiple of
	 * the entry size.
	 */
	struct mach_vm_reclaim_entry_s entries[] __counted_by(len);
};

__END_DECLS
#endif /* __LP64__ */
