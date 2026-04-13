/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef _ARM64_STATIC_IF_ASM_H_
#define _ARM64_STATIC_IF_ASM_H_

/*
 * Implementation note: STATIC_BRANCH_IF_{DISABLED,ENABLED} must be C-style
 * preprocessor macros since they need to expand tokens in assym.s, and those
 * are implemented as C-style #defines.  But they defer to assembly macros to
 * actually emit code, since C-style macros can't generate multiline
 * asm code.
 */

#include "assym.s"

#if KASAN
#define STATIC_IF_SEGSECT __DATA_CONST,__static_if
#else
#define STATIC_IF_SEGSECT __BOOTDATA,__static_if
#endif

#define __static_if_key_init_value(_key) _key ## _jump_key_INIT_VALUE

/**
 * Takes a branch when a static_if key is disabled.
 *
 * @param _key static_if key
 * @param _branch_target target of the branch, if taken
 */
#define STATIC_BRANCH_IF_DISABLED(_key, _branch_target) \
	_EMIT_STATIC_BRANCH _key, _branch_target, __static_if_key_init_value(_key), 0

/**
 * Takes a branch when a static_if key is enabled.
 *
 * @param _key static_if key
 * @param _branch_target target of the branch, if taken
 */
#define STATIC_BRANCH_IF_ENABLED(_key, _branch_target) \
	_EMIT_STATIC_BRANCH _key, _branch_target, __static_if_key_init_value(_key), 1

/* BEGIN IGNORE CODESTYLE */
.macro _EMIT_STATIC_BRANCH key:req, branch_target:req, init_value:req, branch_value:req
	.ifnc \init_value,0
		.ifnc \init_value,1
			.error "unknown static_if key '\key' (check genassym.c)"
		.endif
	.endif

	Lstatic_if_asm_base_\@:
	.if \init_value == \branch_value
		b \branch_target
	.else
		nop
	.endif

	.pushsection STATIC_IF_SEGSECT, regular, live_support
	.align 3
		.long Lstatic_if_asm_base_\@ - .						/* sie_base */
		.long \branch_target - Lstatic_if_asm_base_\@			/* sie_target */
	.if \init_value == \branch_value							/* sie_link */
		.quad _\()\key\()_jump_key + 1
	.else
		.quad _\()\key\()_jump_key
	.endif
	.popsection
	.align 2
.endmacro
/* END IGNORE CODESTYLE */

#endif /* _ARM64_STATIC_IF_ASM_H_ */

/* vim: set ts=4 ft=asm: */
