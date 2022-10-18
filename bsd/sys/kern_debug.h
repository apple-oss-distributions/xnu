/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

#ifndef _SYS_KERN_DEBUG_H_
#define _SYS_KERN_DEBUG_H_

#include <mach/mach_types.h>

#include <sys/types.h>

__BEGIN_DECLS

/*
 * A selector is just made of an index into syscall_rejection_masks,
 * with the exception of the highest bit, which indicates whether the
 * mask is to be added as an "allow" mask or a "deny" mask.
 */
typedef uint8_t syscall_rejection_selector_t;

__END_DECLS

#define SYSCALL_REJECTION_IS_ALLOW_MASK (1 << 6)
#define SYSCALL_REJECTION_NON_MASK_BITS 1

#define SYSCALL_REJECTION_SELECTOR_BITS 7
#define SYSCALL_REJECTION_SELECTOR_MASK ((1 << SYSCALL_REJECTION_SELECTOR_BITS) - 1)
#define SYSCALL_REJECTION_SELECTOR_MASK_COUNT (1 << (SYSCALL_REJECTION_SELECTOR_BITS-SYSCALL_REJECTION_NON_MASK_BITS))

#define SYSCALL_REJECTION_INDEX_MASK       (SYSCALL_REJECTION_SELECTOR_MASK & ~(syscall_rejection_selector_t)(SYSCALL_REJECTION_IS_ALLOW_MASK))

#define SYSCALL_REJECTION_ALLOW(sc)     ((sc) | SYSCALL_REJECTION_IS_ALLOW_MASK)
#define SYSCALL_REJECTION_DENY(sc)      (sc)

#define SYSCALL_REJECTION_NULL          0
#define SYSCALL_REJECTION_ALL           1

//// Flags for debug_syscall_reject_config

/*
 * default (no special behavior)
 */
#define SYSCALL_REJECTION_FLAGS_DEFAULT 0

/*
 * force fatal: Hitting a denied syscall in this thread will always go
 * the fatal path, no matter what the global mode is set to.
 */
#define SYSCALL_REJECTION_FLAGS_FORCE_FATAL 1

/*
 * once: Hitting a denied syscall or mach trap will be remembered for
 * the rest of the lifetime of this thread, and iff the once flag is
 * currently set, such a remembered system call/mach trap will never hit
 * again. (Note: This means that by removing the ONCE flag, all system
 * calls/mach traps will hit again).
 */
#define SYSCALL_REJECTION_FLAGS_ONCE           2

#ifndef KERNEL

__BEGIN_DECLS

/* Request that the syscall rejection mask of the current thread be changed to the
 * one specified by the list of selectors provided, e.g.
 * syscall_rejection_selector_t selectors[] =
 *     [ SYSCALL_REJECTION_DENY(SYSCALL_REJECTION_ALL),
 *       SYSCALL_REJECTION_ALLOW(MY_SELECTOR) ];
 * ret = debug_syscall_reject_config(selectors, countof(selectors), SYSCALL_REJECTION_FLAGS_DEFAULT);
 */

int debug_syscall_reject_config(const syscall_rejection_selector_t *selectors, size_t len, uint64_t flags);

/* Compatibility with old interface. */
int debug_syscall_reject(const syscall_rejection_selector_t *selectors, size_t len);

__END_DECLS

#else /* KERNEL */

#include <stdbool.h>

#include <kern/bits.h>

#include <sys/sysproto.h>

__BEGIN_DECLS

typedef bitmap_t *syscall_rejection_mask_t;

int sys_debug_syscall_reject_config(struct proc *p, struct debug_syscall_reject_config_args *args, int *ret);

int debug_syscall_reject(struct proc *p, struct debug_syscall_reject_args *args, int *ret);

bool debug_syscall_rejection_handle(int syscall_mach_trap_number);

void reset_debug_syscall_rejection_mode(void);

void rejected_syscall_guard_ast(thread_t thread, mach_exception_data_type_t code, mach_exception_data_type_t subcode);

extern int debug_syscall_rejection_mode;

__END_DECLS

#endif /* KERNEL */

#endif  /* _SYS_KERN_DEBUG_H_ */
