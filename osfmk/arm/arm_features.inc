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

/**
 * Enumerated ARM optional features to be exported to userspace. These are to be
 * enumerated using the official feature name from the ARM ARM. They are grouped
 * below based on the MSR that will be used to populate the data.
 */

/* Features from: ID_AA64ISAR0_EL1 */
ARM_FEATURE_FLAG(FEAT_CRC32);
ARM_FEATURE_FLAG(FEAT_FlagM);
ARM_FEATURE_FLAG(FEAT_FlagM2);
ARM_FEATURE_FLAG(FEAT_FHM);
ARM_FEATURE_FLAG(FEAT_DotProd);
ARM_FEATURE_FLAG(FEAT_SHA3);
ARM_FEATURE_FLAG(FEAT_RDM);
ARM_FEATURE_FLAG(FEAT_LSE);
ARM_FEATURE_FLAG(FEAT_SHA256);
ARM_FEATURE_FLAG(FEAT_SHA512);
ARM_FEATURE_FLAG(FEAT_SHA1);
ARM_FEATURE_FLAG(FEAT_AES);
ARM_FEATURE_FLAG(FEAT_PMULL);

/* Features from: ID_AA64ISAR1_EL1 */
ARM_FEATURE_FLAG(FEAT_SPECRES);
ARM_FEATURE_FLAG(FEAT_SPECRES2);
ARM_FEATURE_FLAG(FEAT_SB);
ARM_FEATURE_FLAG(FEAT_FRINTTS);
ARM_FEATURE_FLAG(FEAT_PACIMP);
ARM_FEATURE_FLAG(FEAT_LRCPC);
ARM_FEATURE_FLAG(FEAT_LRCPC2);
ARM_FEATURE_FLAG(FEAT_FCMA);
ARM_FEATURE_FLAG(FEAT_JSCVT);
ARM_FEATURE_FLAG(FEAT_PAuth);
ARM_FEATURE_FLAG(FEAT_PAuth2);
ARM_FEATURE_FLAG(FEAT_FPAC);
ARM_FEATURE_FLAG(FEAT_FPACCOMBINE);
ARM_FEATURE_FLAG(FEAT_DPB);
ARM_FEATURE_FLAG(FEAT_DPB2);
ARM_FEATURE_FLAG(FEAT_BF16);
ARM_FEATURE_FLAG(FEAT_EBF16);
ARM_FEATURE_FLAG(FEAT_I8MM);

/* Features from: ID_AA64ISAR2_EL1 */
ARM_FEATURE_FLAG(FEAT_WFxT);
ARM_FEATURE_FLAG(FEAT_RPRES);
ARM_FEATURE_FLAG(FEAT_CSSC);
ARM_FEATURE_FLAG(FEAT_HBC);

/* Features from: ID_AA64MMFR0_EL1 */
ARM_FEATURE_FLAG(FEAT_ECV);

/* Features from: ID_AA64MMFR1_EL1 */
ARM_FEATURE_FLAG(FEAT_AFP);

/* Features from: ID_AA64MMFR2_EL1 */
ARM_FEATURE_FLAG(FEAT_LSE2);

/* Features from: ID_AA64PFR0_EL1 */
ARM_FEATURE_FLAG(FEAT_CSV2);
ARM_FEATURE_FLAG(FEAT_CSV3);
ARM_FEATURE_FLAG(FEAT_DIT);
ARM_FEATURE_FLAG(AdvSIMD);
ARM_FEATURE_FLAG(AdvSIMD_HPFPCvt);
ARM_FEATURE_FLAG(FEAT_FP16);

/* Features from: ID_AA64PFR1_EL1 */
ARM_FEATURE_FLAG(FEAT_SSBS);
ARM_FEATURE_FLAG(FEAT_BTI);
ARM_FEATURE_FLAG(FEAT_SME);
ARM_FEATURE_FLAG(FEAT_SME2);

/* Features from: ID_AA64PFR2_EL1 */

/* Features from: ID_AA64SMFR0_EL1 */
ARM_FEATURE_FLAG(SME_F32F32);
ARM_FEATURE_FLAG(SME_BI32I32);
ARM_FEATURE_FLAG(SME_B16F32);
ARM_FEATURE_FLAG(SME_F16F32);
ARM_FEATURE_FLAG(SME_I8I32);
ARM_FEATURE_FLAG(SME_I16I32);
ARM_FEATURE_FLAG(FEAT_SME_F64F64);
ARM_FEATURE_FLAG(FEAT_SME_I16I64);

/* Features from: FPCR */
ARM_FEATURE_FLAG(FP_SyncExceptions);

/* Features derived from other feature flags */
