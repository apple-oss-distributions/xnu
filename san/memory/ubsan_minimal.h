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

#ifndef _UBSAN_MINIMAL_H_
#define _UBSAN_MINIMAL_H_

#if CONFIG_UBSAN_MINIMAL
/*
 * This minimal runtime contains the handlers for checks that are suitable
 * at runtime. To minimize codegen impact, the handlers simply act as a shim
 * to a brk instruction, which gets then inlined by the compiler+LTO.
 * This is similar to UBSAN trapping mode, but guarantees that we can fix
 * and continue by simply stepping to the next instruction during the exception
 * handler.
 *
 * UBSAN Minimal runtime is currently available only for iOS and only for
 * signed overflow checks. It is only used on RELEASE and DEVELOPMENT kernels.
 */

#pragma GCC visibility push(hidden)
enum ubsan_minimal_trap_idx {
	UBSAN_MINIMAL_SIGNED_OVERFLOW = 0x1206,
	UBSAN_MINIMAL_TRAPS_END
};
#define UBSAN_MINIMAL_TRAPS_START       UBSAN_MINIMAL_SIGNED_OVERFLOW
#define UBSAN_MINIMAL_TRAPS_TOTAL       (UBSAN_MINIMAL_TRAPS_END - UBSAN_MINIMAL_TRAPS_START)

/* Trap handler for telemetry */
void ubsan_handle_brk_trap(uint16_t, uintptr_t, uintptr_t);

/* Setup ubsan minimal runtime */
void ubsan_minimal_init(void);

/*
 * signed-integer-overflow ABI
 */
void __ubsan_handle_divrem_overflow_minimal(void);
void __ubsan_handle_negate_overflow_minimal(void);
void __ubsan_handle_mul_overflow_minimal(void);
void __ubsan_handle_sub_overflow_minimal(void);
void __ubsan_handle_add_overflow_minimal(void);

#pragma GCC visibility pop

#endif /* CONFIG_UBSAN_MINIMAL */
#endif /* _UBSAN_MINIMAL_H_ */
