// Copyright (c) 2016-2021 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#ifndef KERN_BACKTRACE_H
#define KERN_BACKTRACE_H

// Kernel and user space backtracing (call stack walking) functions.
//
// For the current kernel stack, call backtrace from any context:
//
// ```c
// #define MAX_STK_LEN (8)
//
// void *ret_addrs[MAX_STK_LEN] = { 0 };
// backtrace_info_t info = BTI_NONE;
// unsigned int stk_len = backtrace(ret_addrs, MAX_STK_LEN, NULL, &info);
// for (unsigned int i = 0; i < stk_len; i++) {
//     printf("%p -> ", ret_addrs[i]);
// }
// printf("%s\n", (info & BTI_TRUNCATED) ? "TRUNC" : "NULL");
// ```
//
// For user stacks, call backtrace_user from a faultable context:
//
// ```c
// uintptr_t ret_addrs[MAX_STK_LEN] = { 0 };
// struct backtrace_user_info info = BTUINFO_INIT;
// unsigned int stk_len = backtrace_user(ret_addrs, MAX_STK_LEN, NULL, &info);
// if (info.btui_error != 0) {
//     printf("user space%s stack is %u frames deep\n",
//         (info->btui_info & BTI_TRUNCATED) ? " truncated" : "", stk_len);
// }
// ```
//
// Refer to documentation in backtrace(9) for more information.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/cdefs.h>
// XXX Surgically include just the errno_t definition, so this can still be used
//     by Mach.
#include <sys/_types/_errno_t.h>

__BEGIN_DECLS

// backtrace_flags_t change how the backtraces are recorded.
__options_decl(backtrace_flags_t, uint32_t, {
	BTF_NONE = 0x0,
	// BTF_KERN_INTERRUPTED backtraces the interrupted kernel stack.
	BTF_KERN_INTERRUPTED = 0x1,
});

// The copy function is used to copy call stack frame and other information from
// the target call stack.  If an error is returned, the backtrace is aborted.
typedef errno_t (*backtrace_user_copy_fn)(void *ctx, void *dst, user_addr_t src,
    size_t size);

// This copy function returns an error when a copy attempt is made, effectively
// limiting the user backtrace to the PC.
errno_t backtrace_user_copy_error(void *ctx, void *dst, user_addr_t src,
    size_t size);

// Parameters that control how the backtrace is taken.
struct backtrace_control {
	backtrace_flags_t btc_flags;
	// The frame address to start backtracing from; set to 0 to start from the
	// calling frame.
	uintptr_t btc_frame_addr;
	// A thread to backtrace user stacks of; must be either the current thread
	// or one which has been suspended.
	void *btc_user_thread;
	// A functions to call instead of the default copyin routine for
	// user space backtracing.
	backtrace_user_copy_fn btc_user_copy;
	// A context to pass to the user copy routine.
	void *btc_user_copy_context;
	// Apply an offset to each address stored by the backtracer.
	int64_t btc_addr_offset;
};

// Use this offset when walking an async stack, so symbolicators that subtract 1
// from each address to find the call site see valid symbols, instead of
// whatever function is at a lower address than the function pointer.
#define BTCTL_ASYNC_ADDR_OFFSET ((int64_t)1)

#define BTCTL_INIT \
		((struct backtrace_control){ \
			.btc_flags = BTF_NONE, \
			.btc_frame_addr = 0, \
			.btc_user_thread = NULL, \
			.btc_user_copy = NULL, \
			.btc_user_copy_context = NULL, \
			.btc_addr_offset = 0, \
		})

// backtrace_info_t provides information about the backtrace.
__options_decl(backtrace_info_t, uint32_t, {
	BTI_NONE = 0x0,
	// BTI_64_BIT is set when the backtrace is made up of 64-bit addresses.
	BTI_64_BIT = 0x1,
	// BTI_TRUNCATED is set when the backtrace has been truncated, either due
	// to an error copying data, an invalid frame pointer, or running out of
	// buffer space.
	BTI_TRUNCATED = 0x2,
});

// Backtrace the current thread's kernel stack.
unsigned int backtrace(uintptr_t *bt, unsigned int btlen,
    struct backtrace_control *ctl, backtrace_info_t *info_out)
__attribute__((noinline));

// backtrace_user_info describes a user backtrace.
struct backtrace_user_info {
	backtrace_info_t btui_info;
	errno_t btui_error;
	// The index where the start of the async call stack was found.
	unsigned int btui_async_start_index;
	// The frame address that can be backtraced to follow the async call stack.
	uintptr_t btui_async_frame_addr;
	// The frame address to use to resume the backtrace when the call stack is
	// truncated by the size of the passed-in buffer.
	uintptr_t btui_next_frame_addr;
};

#define BTUINFO_INIT \
		((struct backtrace_user_info){ \
			.btui_error = 0, \
			.btui_info = BTI_NONE, \
			.btui_async_start_index = 0, \
			.btui_async_frame_addr = 0, \
			.btui_next_frame_addr = 0, \
		})

// Backtrace a thread's user stack.
unsigned int backtrace_user(uintptr_t *bt, unsigned int btlen,
    const struct backtrace_control *ctl, struct backtrace_user_info *info_out);

__END_DECLS

#endif // !defined(KERN_BACKTRACE_H)
