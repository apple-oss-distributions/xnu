/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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


#include <machine/asm.h>
#include <mach/kern_return.h>
#include <arm64/proc_reg.h>
#include <arm64/exception_asm.h>
#include <pexpert/arm64/board_config.h>

#include "assym.s"

#if HAS_GUARDED_IO_FILTER && !CONFIG_SPTM

    .section __PPLTEXT,__text,regular,pure_instructions
    .align 2
    .globl EXT(io_filter_vtop)
LEXT(io_filter_vtop)
    ARM64_STACK_PROLOG
    /* x9 - temp reg for the physical addr of the ioreg, x10 - draft reg. */
    at      s1e1w, x0                 // Get PA of the addr passed in for comparison.
                                      // Use s1e1w flavor of at so permission is checked for writing from EL1.
    isb     sy
    mrs     x9, PAR_EL1
    and     x10, x9, #0x7ffffffffc000 // Extract the page-aligned address from PAR_EL1.PA[51:48] | PAR_EL1.PA[47:14].
    bfxil   x10, x0, #0, #14          // Copy the page offset from the VA to assemble the PA.
    tst     x9, #0x1                  // Check PAR_EL1.F to see if translation was successful.
    csel    x0, x10, xzr, eq          // If translation was successful return PA, else 0.

    ARM64_STACK_EPILOG
#endif /* HAS_GUARDED_IO_FILTER && !CONFIG_SPTM */
