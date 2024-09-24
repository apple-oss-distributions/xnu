/*
 * Copyright (c) 2000-2023 Apple Inc. All rights reserved.
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

#ifndef _KERN_STACKSHOT_H_
#define _KERN_STACKSHOT_H_

#include <stdint.h>
#include <kern/kern_types.h>
#include <kern/kern_cdata.h>

__BEGIN_DECLS

#ifdef XNU_KERNEL_PRIVATE

extern void                   kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size,
    uint64_t flags, kcdata_descriptor_t data_p, uint64_t since_timestamp, uint32_t pagetable_mask);
extern uint32_t               kdp_stack_snapshot_bytes_traced(void);
extern uint32_t               kdp_stack_snapshot_bytes_uncompressed(void);
extern boolean_t              stackshot_thread_is_idle_worker_unsafe(thread_t thread);
extern void                   stackshot_cpu_preflight(void);
extern void                   stackshot_aux_cpu_entry(void);
extern void                   stackshot_cpu_signal_panic(void);
extern kern_return_t          kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config,
    size_t stackshot_config_size, boolean_t stackshot_from_user);
extern kern_return_t          do_stackshot(void* context);
extern boolean_t              stackshot_active(void);
extern boolean_t              panic_stackshot_active(void);
extern kern_return_t do_panic_stackshot(void *context);
extern void *                 stackshot_alloc_with_size(size_t size, kern_return_t *err);

/* Allocates an array of elements of a type from the stackshot buffer. Works in regular & panic stackshots. */
#define stackshot_alloc_arr(type, count, err) stackshot_alloc_with_size(sizeof(type) * (count), err)

/* Allocates an element with a type from the stackshot buffer. Works in regular & panic stackshot. */
#define stackshot_alloc(type, err) stackshot_alloc_with_size(sizeof(type), err)

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERN_STACKSHOT_H_ */
