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

/* socd_client_kern.h: machine-independent API for interfacing with soc diagnostics data pipeline, kernel mode specific logic */

#ifndef _KERN_SOCD_CLIENT_KERN_H_
#define _KERN_SOCD_CLIENT_KERN_H_

#include <kern/socd_client.h>
#include <kern/kern_types.h>
#include <mach/vm_param.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

/*
 * SOCD_TRACE
 * Trace an event to debug kernel and hardware hangs. Traced on all build variants of kernel.
 * x - kdebug debugid
 * a, b, c, d - 64 bit data arguments
 *
 * Usage:
 *    SOCD_TRACE is an expensive operation and must not be used on performance critical paths.
 *    Each data argument must be wrapped with SOCD_ADDR or SOCD_VAL macro. To enforce this rule,
 *    SOCD_ is prepended to all data arguments passed to SOCD_TRACE.
 *    1. Use ADDR when passing a kernel address. The macro verifies kernel address is slid, then it removes the slide.
 *       When kernel address is not slid, the macro returns 0.
 *    2. Use VALUE when passing an argument that's not expected to be a kernel address. When the argument
 *       is a kernel address, the macro returns 0.
 *    3. Use PACK_2X32 to pack two 32 bit values into one 64 bit argument. PACK_2X32 arguments must be wrapped with ADDR or VALUE macro as well.
 *    4. Use PACK_LSB to overwrite the least significant bit of a 64 bit value. PACK_LSB arguments must be wrapped with ADDR or VALUE macro as well.
 *
 *
 * Example:
 *      SOCD_TRACE(KDBG_EVENTID(DBG_DRIVERS, DBG_SOCDIAGS, SOCD_TRACE_EVENTID(SOCD_TRACE_CLASS_KERNEL, SOCD_TRACE_CODE_KERNEL_PANIC)),
 *                 ADDR(caller_function_ptr), VALUE(panic_options))
 */
#define SOCD_TRACE(x, ...) SOCD_TRACE_(x, ## __VA_ARGS__, 4, 3, 2, 1, 0)
#define SOCD_TRACE_(x, a, b, c, d, n, ...) SOCD_TRACE##n(x, a, b, c, d)
#define SOCD_TRACE0(x, a, b, c, d)         SOCD_TRACE_IMPL(x,        0,        0,        0,        0)
#define SOCD_TRACE1(x, a, b, c, d)         SOCD_TRACE_IMPL(x, SOCD_##a,        0,        0,        0)
#define SOCD_TRACE2(x, a, b, c, d)         SOCD_TRACE_IMPL(x, SOCD_##a, SOCD_##b,        0,        0)
#define SOCD_TRACE3(x, a, b, c, d)         SOCD_TRACE_IMPL(x, SOCD_##a, SOCD_##b, SOCD_##c,        0)
#define SOCD_TRACE4(x, a, b, c, d)         SOCD_TRACE_IMPL(x, SOCD_##a, SOCD_##b, SOCD_##c, SOCD_##d)

#if defined(__arm64__)
#define SOCD_TRACE_IMPL(x, a, b, c, d) \
do { \
	socd_client_trace((x), (socd_client_trace_arg_t)(a), (socd_client_trace_arg_t)(b), \
	                        (socd_client_trace_arg_t)(c), (socd_client_trace_arg_t)(d)); \
} while (0)
#else // defined(__arm64__)
#define SOCD_TRACE_IMPL(x, a, b, c, d)
#endif // !defined(__arm64__)

#define SOCD_ADDR(_a) (VM_KERNEL_UNSLIDE((vm_offset_t)(_a)))
#define SOCD_VALUE(_v) (VM_KERNEL_ADDRESS((vm_offset_t)(_v)) ? (socd_client_trace_arg_t)0 : (socd_client_trace_arg_t)(_v))
#define SOCD_PACK_2X32(h, l) ((((uint64_t)(SOCD_##h) & 0xffffffff) << 32) | ((uint64_t)(SOCD_##l) & 0xffffffff))
#define SOCD_PACK_LSB(h, lsb) ((((uint64_t)(SOCD_##h)) & 0xfffffffffffffffe) | ((uint64_t)(SOCD_##lsb) & 0x1))

/* Test macros for proper functionality locally before nominating. */
#if !defined(__arm64__)
static_assert(SOCD_PACK_2X32(VALUE(0xffff1000), VALUE(0xffff1200)) == 0xffff1000ffff1200, "PACK_2X32 failed to return expected output.");
static_assert(SOCD_PACK_LSB(VALUE(0xffff), VALUE(0x0)) == 0xfffe, "PACK_LSB failed to return expected output.");
#endif // !defined(__arm64__)

#define _SOCD_TRACE_XNU(c, x, ...) \
   SOCD_TRACE(KDBG_EVENTID(DBG_DRIVERS, DBG_SOCDIAGS, SOCD_TRACE_EVENTID(SOCD_TRACE_CLASS_XNU, SOCD_TRACE_CODE_XNU_##c)) | (x), ## __VA_ARGS__)
#define SOCD_TRACE_XNU(c, ...) _SOCD_TRACE_XNU(c, DBG_FUNC_NONE, ## __VA_ARGS__)
#define SOCD_TRACE_XNU_START(c, ...) _SOCD_TRACE_XNU(c, DBG_FUNC_START, ## __VA_ARGS__)
#define SOCD_TRACE_XNU_END(c, ...) _SOCD_TRACE_XNU(c, DBG_FUNC_END, ## __VA_ARGS__)

extern void socd_client_trace(uint32_t debugid, socd_client_trace_arg_t arg1,
    socd_client_trace_arg_t arg2, socd_client_trace_arg_t arg3, socd_client_trace_arg_t arg4);

__END_DECLS

#endif /* !defined(_KERN_SOCD_CLIENT_KERN_H_) */
