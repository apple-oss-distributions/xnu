/* Copyright (c) (2012,2014-2019,2021,2022) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

//debug configuration header file
#ifndef _CORECRYPTO_CCN_DEBUG_H_
#define _CORECRYPTO_CCN_DEBUG_H_

#include <corecrypto/cc_config.h>

// DO NOT INCLUDE this HEADER file in CoreCrypto files added for XNU project or headers
// included by external clients.

// ========================
// Printf for corecrypto
// ========================
#if CC_KERNEL
    #include <pexpert/pexpert.h>
    #define cc_printf(x...) kprintf(x)
    #if !CONFIG_EMBEDDED
extern int printf(const char *format, ...) __cc_printflike(1, 2);
    #endif
#elif CC_IBOOT || CC_RTKIT || CC_RTKITROM
    #include <stdio.h>
    #define cc_printf(x...) printf(x)
#elif CC_SGX || CC_EFI
    #define cc_printf(x...)
#elif CC_TXM
    #define cc_printf(x...)
#elif CC_SPTM
    #define cc_printf(x...)
#else
    #include <stdio.h>
    #define cc_printf(x...) fprintf(stderr, x)
#endif

// ========================
// Integer types
// ========================

#if CC_KERNEL
/* Those are not defined in libkern */
#define PRIx64 "llx"
#define PRIx32 "x"
#define PRIx16 "hx"
#define PRIx8  "hhx"
#else
#include <inttypes.h>
#endif

#if  CCN_UNIT_SIZE == 8
#define CCPRIx_UNIT ".016" PRIx64
#elif  CCN_UNIT_SIZE == 4
#define CCPRIx_UNIT ".08" PRIx32
#else
#error invalid CCN_UNIT_SIZE
#endif

// ========================
// Print utilities for corecrypto
// ========================

#include <corecrypto/cc.h>

/* Print a byte array of arbitrary size */
void cc_print(const char *label, size_t count, const uint8_t *s);

#endif /* _CORECRYPTO_CCN_DEBUG_H_ */
