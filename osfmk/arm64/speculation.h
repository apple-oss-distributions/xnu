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

#ifndef _SPECULATION_H_
#define _SPECULATION_H_
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>


/*
 * SPECULATION_GUARD_ZEROING_???_CC
 *
 * These macros perform a speculation safe version of the following pseudo-code:
 * cc = cmp(cmp_1, cmp_2)
 * if (cc)
 *     out = value
 * else
 *     out = 0
 *
 * where "cc" is an ARM64 condition code (EQ, HS, etc.).
 *
 * Additionally, we provide four variants (for the ??? in the name):
 * 1. XXX (value is 64-bits, cmp_1 and cmp_2 are 64-bits)
 * 2. XWW (value is 64-bits, cmp_1 and cmp_2 are 32-bits)
 * 3. WXX (value is 32-bits, cmp_1 and cmp_2 are 64-bits)
 * 4. WWW (value is 32-bits, cmp_1 and cmp_2 are 32-bits)
 */

/**
 * Generate the zeroing speculation guard expression
 *
 * out: The output location for the guarded value
 * out_valid: The condition evaluated true non-speculatively
 * value: The input value to guard
 * cmp_1, cmp_2: The two operands to compare
 * cmp_prefix: The ASM prefix for the registers in the compare instruction. For
 * 64-bit operands, pass an empty string. For 32-bit operands, pass "w"
 * cs_prefix: The ASM prefix for the registers in the select instruction.
 */
#define SPECULATION_GUARD_ZEROING_GEN(out, out_valid, value, cmp_1, cmp_2, cc, cmp_prefix, cs_prefix) \
    { \
	__asm__ ( \
	    "cmp       %" cmp_prefix "[_cmp_1], %" cmp_prefix "[_cmp_2]\n" \
	    "csel      %" cs_prefix "[_out], %" cs_prefix "[_value], %" cs_prefix "[_zero], " cc "\n" \
	    "cset      %w[_out_valid], " cc "\n" \
	    "csdb\n" \
	    : [_out] "=r" (out), [_out_valid] "=r" (out_valid) \
	    : [_cmp_1] "r" (cmp_1), [_cmp_2] "r" (cmp_2), [_value] "r" (value), [_zero] "rz" (0ULL) \
	    : "cc" \
	); \
    }

#define SPECULATION_GUARD_ZEROING_XXX(out, out_valid, value, cmp_1, cmp_2, cc) \
    SPECULATION_GUARD_ZEROING_GEN(out, out_valid, value, cmp_1, cmp_2, cc, "", "")

#define SPECULATION_GUARD_ZEROING_XWW(out, out_valid, value, cmp_1, cmp_2, cc) \
    SPECULATION_GUARD_ZEROING_GEN(out, out_valid, value, cmp_1, cmp_2, cc, "w", "")

#define SPECULATION_GUARD_ZEROING_WXX(out, out_valid, value, cmp_1, cmp_2, cc) \
    SPECULATION_GUARD_ZEROING_GEN(out, out_valid, value, cmp_1, cmp_2, cc, "", "w")

#define SPECULATION_GUARD_ZEROING_WWW(out, out_valid, value, cmp_1, cmp_2, cc) \
    SPECULATION_GUARD_ZEROING_GEN(out, out_valid, value, cmp_1, cmp_2, cc, "w", "w")

/*
 * SPECULATION_GUARD_SELECT_???_CC
 *
 * These macros perform a speculation safe version of the following pseudo-code:
 * cc = cmp(cmp_1, cmp_2)
 * if (cc)
 *     value = sel_1
 * else
 *     value = sel_2
 *
 * where "cc" is an ARM64 condition code (EQ, HS, etc.).
 *
 * Due to the limitations of macros/ASM, callers must provide both CC and !CC
 * (the compliment, e.g. EQ and NE, HS and LO, etc.). Passing an incorrect
 * compliment may result in incorrect or otherwise surprising behavior.
 *
 * Additionally, we provide four variants (for the ??? in the name):
 * 1. XXX (value is 64-bits, cmp_1 and cmp_2 are 64-bits)
 * 2. XWW (value is 64-bits, cmp_1 and cmp_2 are 32-bits)
 * 3. WXX (value is 32-bits, cmp_1 and cmp_2 are 64-bits)
 * 4. WWW (value is 32-bits, cmp_1 and cmp_2 are 32-bits)
 *
 * This guard has no requirements on non-speculative resolution.
 */

/**
 * Generate the selection speculation guard expression
 *
 * output: The output value
 * cmp_1, cmp_2: The two operands to compare
 * sel_1, sel_2: The values to pick if cc or n_cc (respectively)
 * cc, n_cc: The ARM64 condition code CC and its compliment !CC
 * cmp_prefix: The ASM prefix for the registers in the compare instruction. For
 * 64-bit operands, pass an empty string. For 32-bit operands, pass "w"
 * cs_prefix: The ASM prefix for the registers in the select instruction.
 */
#define SPECULATION_GUARD_SELECT_GEN(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2, cmp_prefix, cs_prefix) \
    __asm__ ( \
	"cmp       %" cmp_prefix "[_cmp_1], %" cmp_prefix "[_cmp_2]\n" \
	"csel      %" cs_prefix "[_out], %" cs_prefix "[_sel_1], %" cs_prefix "[_sel_2], " cc "\n" \
	"csdb\n" \
	: [_out] "=r" (out) \
	: [_cmp_1] "r" (cmp_1), [_cmp_2] "r" (cmp_2), [_sel_1] "r" (sel_1), [_sel_2] "r" (sel_2), [_zero] "rz" (0ULL) \
	: "cc" \
    );

#define SPECULATION_GUARD_SELECT_XXX(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2) \
    SPECULATION_GUARD_SELECT_GEN(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2, "", "")

#define SPECULATION_GUARD_SELECT_XWW(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2) \
    SPECULATION_GUARD_SELECT_GEN(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2, "w", "")

#define SPECULATION_GUARD_SELECT_WXX(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2) \
    SPECULATION_GUARD_SELECT_GEN(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2, "", "w")

#define SPECULATION_GUARD_SELECT_WWW(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2) \
    SPECULATION_GUARD_SELECT_GEN(out, cmp_1, cmp_2, cc, sel_1, n_cc, sel_2, "w", "w")

#endif /* _SPECULATION_H_ */
