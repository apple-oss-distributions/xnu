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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#ifndef _KCOV_STKSZ_H_
#define _KCOV_STKSZ_H_

#include <stdbool.h>

#include <kern/thread.h>
#include <mach/vm_types.h>

#include <san/kcov_stksz_data.h>

#if KERNEL_PRIVATE

#if CONFIG_STKSZ

__BEGIN_DECLS

void kcov_stksz_init_thread(kcov_stksz_thread_t *);
void kcov_stksz_update_stack_size(thread_t, kcov_thread_data_t *, void *, uintptr_t);

/* Sets ksancov stack for given thread. */
void kcov_stksz_set_thread_stack(thread_t, vm_offset_t);

/* Returns stack info for given thread. */
vm_offset_t kcov_stksz_get_thread_stkbase(thread_t);
vm_offset_t kcov_stksz_get_thread_stksize(thread_t);

__END_DECLS

#else

#define kcov_stksz_init_thread(thread)
#define kcov_stksz_update_stack_size(thread, data, caller, sp)

#endif /* CONFIG_STKSZ */

#endif /* KERNEL_PRIVATE */

#endif /* _KCOV_STKSZ_H_ */
