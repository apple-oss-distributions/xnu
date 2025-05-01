/* * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <mach/vm_types.h>
#include <machine/static_if.h>
#include <arm64/amcc_rorgn.h>
#include <arm64/proc_reg.h>
#include <kern/startup.h>

extern char __text_exec_start[] __SEGMENT_START_SYM("__TEXT_EXEC");
extern char __text_exec_end[]   __SEGMENT_END_SYM("__TEXT_EXEC");

__attribute__((always_inline))
static uint32_t
arm64_insn_nop(void)
{
	return 0xd503201f;
}

__attribute__((always_inline))
static uint32_t
arm64_insn_b(int32_t delta)
{
	return 0x14000000u | ((delta >> 2) & 0x03ffffff);
}

MARK_AS_FIXUP_TEXT void
ml_static_if_entry_patch(static_if_entry_t sie, int branch)
{
	vm_offset_t patch_point = __static_if_entry_patch_point(sie);
	uint32_t insn;

	if (branch) {
		insn = arm64_insn_b(sie->sie_target);
	} else {
		insn = arm64_insn_nop();
	}

	if ((vm_offset_t)__text_exec_start <= patch_point &&
	    patch_point < (vm_offset_t)__text_exec_end) {
		asm volatile (""
		     /* patch the instruction */
                     "str     %w1, [%0]"     "\n\t"
#if !__ARM_IC_NOALIAS_ICACHE__
		     /* invalidate icache cacheline */
                     "ic      ivau, %0"      "\n\t"
                     "dsb     sy"            "\n\t"
                     "isb     sy"
#endif /* !__ARM_IC_NOALIAS_ICACHE__ */
                     : : "r"(patch_point), "r"(insn) : "memory");
	}
}

MARK_AS_FIXUP_TEXT void
ml_static_if_flush_icache(void)
{
	asm volatile (""
             "ic      ialluis"       "\n\t"
             "dsb     sy"            "\n\t"
             "isb     sy" : : : "memory");
}
