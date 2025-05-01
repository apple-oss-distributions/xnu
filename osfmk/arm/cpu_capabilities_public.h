/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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

#ifndef _ARM_CPU_CAPABILITIES_PUBLIC_H
#define _ARM_CPU_CAPABILITIES_PUBLIC_H



/*
 * In order to reduce the number of sysctls require for a process to get
 * the full list of supported processor capabilities extensions, the
 * hw.optional.arm.caps sysctl generates a bit buffer with each bit representing
 * the presence (1) or absence (0) of a given FEAT extension.
 */

#define HW_OPTIONAL_ARM_CAPS

/*
 * Clang needs those bits to remain constant.
 * Existing entries should never be updated as they are ABI.
 * Adding new entries to the end and bumping CAP_BIT_NB is okay.
 */

#define CAP_BIT_FEAT_FlagM          0
#define CAP_BIT_FEAT_FlagM2         1
#define CAP_BIT_FEAT_FHM            2
#define CAP_BIT_FEAT_DotProd        3
#define CAP_BIT_FEAT_SHA3           4
#define CAP_BIT_FEAT_RDM            5
#define CAP_BIT_FEAT_LSE            6
#define CAP_BIT_FEAT_SHA256         7
#define CAP_BIT_FEAT_SHA512         8
#define CAP_BIT_FEAT_SHA1           9
#define CAP_BIT_FEAT_AES            10
#define CAP_BIT_FEAT_PMULL          11
#define CAP_BIT_FEAT_SPECRES        12
#define CAP_BIT_FEAT_SB             13
#define CAP_BIT_FEAT_FRINTTS        14
#define CAP_BIT_FEAT_LRCPC          15
#define CAP_BIT_FEAT_LRCPC2         16
#define CAP_BIT_FEAT_FCMA           17
#define CAP_BIT_FEAT_JSCVT          18
#define CAP_BIT_FEAT_PAuth          19
#define CAP_BIT_FEAT_PAuth2         20
#define CAP_BIT_FEAT_FPAC           21
#define CAP_BIT_FEAT_DPB            22
#define CAP_BIT_FEAT_DPB2           23
#define CAP_BIT_FEAT_BF16           24
#define CAP_BIT_FEAT_I8MM           25
#define CAP_BIT_FEAT_WFxT           26
#define CAP_BIT_FEAT_RPRES          27
#define CAP_BIT_FEAT_ECV            28
#define CAP_BIT_FEAT_AFP            29
#define CAP_BIT_FEAT_LSE2           30
#define CAP_BIT_FEAT_CSV2           31
#define CAP_BIT_FEAT_CSV3           32
#define CAP_BIT_FEAT_DIT            33
#define CAP_BIT_FEAT_FP16           34
#define CAP_BIT_FEAT_SSBS           35
#define CAP_BIT_FEAT_BTI            36


/* SME */
#define CAP_BIT_FEAT_SME            40
#define CAP_BIT_FEAT_SME2           41
#define CAP_BIT_FEAT_SME_F64F64     42
#define CAP_BIT_FEAT_SME_I16I64     43

#define CAP_BIT_AdvSIMD             49
#define CAP_BIT_AdvSIMD_HPFPCvt     50
#define CAP_BIT_FEAT_CRC32          51

#define CAP_BIT_SME_F32F32          52
#define CAP_BIT_SME_BI32I32         53
#define CAP_BIT_SME_B16F32          54
#define CAP_BIT_SME_F16F32          55
#define CAP_BIT_SME_I8I32           56
#define CAP_BIT_SME_I16I32          57

#define CAP_BIT_FEAT_PACIMP         58


#define CAP_BIT_FEAT_HBC            64
#define CAP_BIT_FEAT_EBF16          65
#define CAP_BIT_FEAT_SPECRES2       66
#define CAP_BIT_FEAT_CSSC           67
#define CAP_BIT_FEAT_FPACCOMBINE    68


#define CAP_BIT_FP_SyncExceptions   73

/* Legacy definitions for backwards compatibility */
#define CAP_BIT_CRC32               CAP_BIT_FEAT_CRC32

/* Total number of FEAT bits. */
#define CAP_BIT_NB 74

#endif /* _ARM_CPU_CAPABILITIES_PUBLIC_H */
