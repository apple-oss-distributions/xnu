/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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

#include <arm64/asm.h>
#include <pexpert/arm64/board_config.h>


#if CONFIG_SPTM
	.text
	.align 2
	.globl EXT(arm64_panic_lockdown_test_load)
LEXT(arm64_panic_lockdown_test_load)
	ldr		x0, [x0]
	ret

	.globl EXT(arm64_panic_lockdown_test_gdbtrap)
LEXT(arm64_panic_lockdown_test_gdbtrap)
	.long 0xe7ffdefe
	ret

#if __has_feature(ptrauth_calls)
	.globl EXT(arm64_panic_lockdown_test_pac_brk_c470)
LEXT(arm64_panic_lockdown_test_pac_brk_c470)
	brk		0xC470
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c471)
LEXT(arm64_panic_lockdown_test_pac_brk_c471)
	brk		0xC471
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c472)
LEXT(arm64_panic_lockdown_test_pac_brk_c472)
	brk		0xC472
	ret

	.globl EXT(arm64_panic_lockdown_test_pac_brk_c473)
LEXT(arm64_panic_lockdown_test_pac_brk_c473)
	brk		0xC473
	ret

	.globl EXT(arm64_panic_lockdown_test_telemetry_brk_ff00)
LEXT(arm64_panic_lockdown_test_telemetry_brk_ff00)
	brk		0xFF00
	ret

	.globl EXT(arm64_panic_lockdown_test_br_auth_fail)
LEXT(arm64_panic_lockdown_test_br_auth_fail)
	braaz	x0
	ret

	.globl EXT(arm64_panic_lockdown_test_ldr_auth_fail)
LEXT(arm64_panic_lockdown_test_ldr_auth_fail)
	ldraa	x0, [x0]
	ret
#endif /* ptrauth_calls  */

#if __ARM_ARCH_8_6__
	.globl EXT(arm64_panic_lockdown_test_fpac)
LEXT(arm64_panic_lockdown_test_fpac)
	autiza	x0
	ret
#endif /* __ARM_ARCH_8_6__ */
#endif /* CONFIG_SPTM */
