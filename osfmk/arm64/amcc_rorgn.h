/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#ifndef _ARM64_AMCC_RORGN_H_
#define _ARM64_AMCC_RORGN_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
#include <stdbool.h>

#include <libkern/section_keywords.h>

void rorgn_stash_range(void);
void rorgn_lockdown(void);
bool rorgn_contains(vm_offset_t addr, vm_size_t size, bool defval);
void rorgn_validate_core(void);

extern vm_offset_t ctrr_begin, ctrr_end;
#if CONFIG_CSR_FROM_DT
extern bool csr_unsafe_kernel_text;
#endif /* CONFIG_CSR_FROM_DT */

#if KERNEL_CTRR_VERSION >= 3
#define CTXR_XN_DISALLOW_ALL \
	/* Execute Masks for EL2&0 */ \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL2_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL0TGE1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL2_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL0TGE1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_MMUOFF_shift) | \
	/* Execute Masks for EL1&0 when Stage2 Translation is disabled */ \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL0TGE0_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL0TGE0_shift)

#define CTXR_XN_KERNEL \
	/* Execute Masks for EL2&0 */ \
    (CTXR3_XN_disallow_outside << CTXR3_x_CTL_EL2_XN_EL2_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL0TGE1_shift) | \
    (CTXR3_XN_disallow_outside << CTXR3_x_CTL_EL2_XN_GL2_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL0TGE1_shift) | \
    (CTXR3_XN_disallow_outside << CTXR3_x_CTL_EL2_XN_MMUOFF_shift) | \
	/* Execute Masks for EL1&0 when Stage2 Translation is disabled */ \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_EL0TGE0_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL1_shift) | \
    (CTXR3_XN_disallow_inside << CTXR3_x_CTL_EL2_XN_GL0TGE0_shift)
#endif /* KERNEL_CTRR_VERSION >= 3 */

#endif /* defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR) */

__END_DECLS

#endif /* _ARM64_AMCC_RORGN_H_ */
