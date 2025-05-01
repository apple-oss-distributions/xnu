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
#include <sys/cdefs.h>
#include <stdint.h>

__BEGIN_DECLS

#ifdef KERNEL
__abortlike __printflike(1, 2)
extern void panic(const char *string, ...);
#endif /* KERNEL */

#if KERNEL_PRIVATE
struct task;
struct thread;
struct proc;

#if XNU_KERNEL_PRIVATE
#define panic(ex, ...)  ({ \
	__asm__("" ::: "memory"); \
	(panic)(ex " @%s:%d", ## __VA_ARGS__, __FILE_NAME__, __LINE__); \
})
#else /* else XNU_KERNEL_PRIVATE */
#define panic(ex, ...)  ({ \
	__asm__("" ::: "memory"); \
	(panic)(#ex " @%s:%d", ## __VA_ARGS__, __FILE_NAME__, __LINE__); \
})
#endif /* else XNU_KERNEL_PRIVATE*/
#define panic_plain(ex, ...)  (panic)(ex, ## __VA_ARGS__)

__abortlike __printflike(4, 5)
void panic_with_options(unsigned int reason, void *ctx,
    uint64_t debugger_options_mask, const char *str, ...);
__abortlike __printflike(5, 6)
void panic_with_options_and_initiator(const char* initiator, unsigned int reason, void *ctx,
    uint64_t debugger_options_mask, const char *str, ...);

#if XNU_KERNEL_PRIVATE && defined (__x86_64__)
__abortlike __printflike(5, 6)
void panic_with_thread_context(unsigned int reason, void *ctx,
    uint64_t debugger_options_mask, struct thread* th, const char *str, ...);
#endif /* XNU_KERNEL_PRIVATE && defined (__x86_64__) */

#endif /* KERNEL_PRIVATE */

__END_DECLS
