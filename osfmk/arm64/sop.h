/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
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

#ifndef _ARM64_SOP_H_
#define _ARM64_SOP_H_

#include <stdbool.h>
#include <stdint.h>

__BEGIN_DECLS

#if CONFIG_SPTM
/*
 * Try to map the first stack redzone page with a temporary stack page so that we
 * can survive a stack overflow.
 */
bool sop_try_map_redzone_page(uintptr_t va);

/*
 * Unmap the first thread stack redzone page and free the temporary stack page.
 */
void sop_unmap_redzone_page(thread_t thread);

#if DEVELOPMENT || DEBUG
/*
 * Boot-arg to artificially reduce kernel stack size for testing.
 * Extern declaration for use in thread stack setup.
 */
extern uint32_t sop_kstack_reduce;
#endif

#endif /* CONFIG_SPTM */

/*
 * Number of entries in the SOP exception ring buffer. Must be a power of 2
 * because the assembly indexes into the ring using a bitmask.
 */
#define SOP_EXCEPTION_RING_SIZE 16

typedef struct {
	uint64_t esr;
	uint64_t far;
	uint64_t elr;
	uint64_t spsr;
	uint64_t sp;
	uint64_t tpidr;
	uint64_t timestamp;
	uint64_t flags;     /* exception source identifier */
} sop_exception_snapshot_t;

__END_DECLS

#endif /* _ARM64_SOP_H_ */
