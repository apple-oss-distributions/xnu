/*
 * Copyright (c) 2012-2015 Apple Inc. All rights reserved.
 */

#ifndef _PEXPERT_ARM64_COMMON_H
#define _PEXPERT_ARM64_COMMON_H

/* This block of definitions is misplaced to shelter it from lines that will be
 * removed in rdar://56937184. These definitions must be moved back after that
 * change has been merged. */
#ifdef APPLE_ARM64_ARCH_FAMILY
#endif

#ifdef ASSEMBLER
#define __MSR_STR(x) x
#else
#define __MSR_STR1(x) #x
#define __MSR_STR(x) __MSR_STR1(x)
#endif

#ifdef APPLE_ARM64_ARCH_FAMILY



#if defined(APPLETYPHOON) || defined(APPLETWISTER)
#define ARM64_REG_CYC_CFG_skipInit     (1ULL<<30)
#define ARM64_REG_CYC_CFG_deepSleep    (1ULL<<24)
#else /* defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER) */
#define ARM64_REG_ACC_OVRD_enDeepSleep                 (1ULL << 34)
#define ARM64_REG_ACC_OVRD_disPioOnWfiCpu              (1ULL << 32)
#define ARM64_REG_ACC_OVRD_dsblClkDtr                  (1ULL << 29)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_mask              (3ULL << 27)
#define ARM64_REG_ACC_OVRD_cpmWakeUp_force             (3ULL << 27)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask            (3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deny            (2ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep       (3ULL << 25)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask             (3ULL << 17)
#define ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep        (3ULL << 17)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask      (3ULL << 15)
#define ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep (2ULL << 15)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask            (3ULL << 13)
#define ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep       (3ULL << 13)
#endif /* defined(APPLECYCLONE) || defined(APPLETYPHOON) || defined(APPLETWISTER) */

#define ARM64_REG_CYC_OVRD_irq_mask            (3<<22)
#define ARM64_REG_CYC_OVRD_irq_disable         (2<<22)
#define ARM64_REG_CYC_OVRD_fiq_mask            (3<<20)
#define ARM64_REG_CYC_OVRD_fiq_disable         (2<<20)
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_up   (2<<24)
#define ARM64_REG_CYC_OVRD_ok2pwrdn_force_down (3<<24)
#define ARM64_REG_CYC_OVRD_disWfiRetn          (1<<0)

#if defined(APPLEMONSOON)
#define ARM64_REG_CYC_OVRD_dsblSnoopTime_mask  (3ULL << 30)
#define ARM64_REG_CYC_OVRD_dsblSnoopPTime      (1ULL << 31)  /// Don't fetch the timebase from the P-block
#endif /* APPLEMONSOON */

#define ARM64_REG_LSU_ERR_STS_L1DTlbMultiHitEN (1ULL<<54)
#define ARM64_REG_LSU_ERR_CTL_L1DTlbMultiHitEN (1ULL<<3)



#if defined(HAS_IPI)
#define ARM64_REG_IPI_RR_TYPE_IMMEDIATE (0 << 28)
#define ARM64_REG_IPI_RR_TYPE_RETRACT   (1 << 28)
#define ARM64_REG_IPI_RR_TYPE_DEFERRED  (2 << 28)
#define ARM64_REG_IPI_RR_TYPE_NOWAKE    (3 << 28)

#define ARM64_IPISR_IPI_PENDING         (1ull << 0)
#endif /* defined(HAS_IPI) */

#if defined(HAS_OBJC_BP_HELPER)
#define ARM64_REG_BP_OBJC_ADR_EL1_mask                 (0x00ffffffffffffffull)
#define ARM64_REG_BP_OBJC_ADR_EL1_shift                (0)

#define ARM64_REG_BP_OBJC_CTL_EL1_Mask_mask            (0x001ffffff8000000ull)
#define ARM64_REG_BP_OBJC_CTL_EL1_Mask_shift           (27)

#define ARM64_REG_BP_OBJC_CTL_EL1_AR_ClassPtr_mask     (0x00000000003e0000ull)
#define ARM64_REG_BP_OBJC_CTL_EL1_AR_ClassPtr_shift    (17)

#define ARM64_REG_BP_OBJC_CTL_EL1_AR_Selector_mask     (0x000000000001f000ull)
#define ARM64_REG_BP_OBJC_CTL_EL1_AR_Selector_shift    (12)

#define ARM64_REG_BP_OBJC_CTL_EL1_Br_Offset_mask       (0x000000000000007full)
#define ARM64_REG_BP_OBJC_CTL_EL1_Br_Offset_shift      (0)
#endif /* defined(HAS_OBJC_BP_HELPER) */


#endif /* APPLE_ARM64_ARCH_FAMILY */


#if defined(HAS_BP_RET)
#define ARM64_REG_ACC_CFG_bdpSlpEn    (1ULL << 2)
#define ARM64_REG_ACC_CFG_btpSlpEn    (1ULL << 3)
#define ARM64_REG_ACC_CFG_bpSlp_mask  3
#define ARM64_REG_ACC_CFG_bpSlp_shift 2
#endif /* defined(HAS_BP_RET) */



#define MPIDR_CORETYPE_SHIFT  (16)
#define MPIDR_CORETYPE_WIDTH  (3)
#define MPIDR_CORETYPE_MASK   ((1ULL << MPIDR_CORETYPE_WIDTH) - 1)
#define MPIDR_CORETYPE_ACC_E  (0ULL)
#define MPIDR_CORETYPE_ACC_P  (1ULL)



#define CPU_PIO_CPU_STS_OFFSET               (0x100ULL)
#define CPU_PIO_CPU_STS_cpuRunSt_mask        (0xff)

/*
 * CORE_THRTL_CFG2 non-sysreg tunable
 */
#define CORE_THRTL_CFG2_OFFSET               (0x218)

#define CORE_THRTL_CFG2_c1pptThrtlRate_shift (56)
#define CORE_THRTL_CFG2_c1pptThrtlRate_mask  (0xFFULL << CORE_THRTL_CFG2_c1pptThrtlRate_shift)




#if defined(APPLEH16)
/*
 * EACC/PACC cpmX_IMPL register offset
 */
#define LLC_ERR_INF_OFFSET (0x18ULL)
#define LLC_ERR_INF_NREC   (1ULL << 36)
#endif /* defined(APPLEH16) */

#ifdef ASSEMBLER

/*
 * Determines whether the executing core is a P-core.
 *
 * @param arg0 result register; will be non-zero if executed on a P-core, else
 *             zero if executed on an E-core / non-PE core / non-AMP architectures.
 */
.macro ARM64_IS_PCORE
#if defined(APPLEMONSOON) || HAS_CLUSTER
	mrs   $0, MPIDR_EL1
	ubfx  $0, $0, #MPIDR_CORETYPE_SHIFT, #MPIDR_CORETYPE_WIDTH
	and   $0, $0, #MPIDR_CORETYPE_ACC_P
#else
	mov   $0, xzr
#endif
.endmacro


/*
 * Determines whether the executing core is an E-core.
 *
 * @note Clobbers condition flags.
 *
 * @param arg0 result register; will be non-zero if executed on an E-core, else
 *             zero if executed on a P-core / non-PE core / non-AMP architectures.
 */
.macro ARM64_IS_ECORE
#if defined(APPLEMONSOON) || HAS_CLUSTER
	mrs    $0, MPIDR_EL1
	ands   $0, $0, #(MPIDR_CORETYPE_MASK << MPIDR_CORETYPE_SHIFT)
	csinc  $0, xzr, xzr, ne
#else
	mov    $0, xzr
#endif
.endmacro

/*
 * Reads a system register using the appropriate name for E-cores, P-cores and
 * non-PE cores.
 *
 * @note See also: ARM64_IS_ECORE
 *
 * @param arg0 GPR indicating the core type; non-zero if this is an E-core, else zero
 * @param arg1 destination GPR
 * @param arg2 system register name to use for E-cores
 * @param arg3 system register name to use for P-cores, non-PE cores or
 *             non-AMP architectures.
 */
.macro ARM64_READ_CORE_SYSREG
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbz  $0, 1f
// E-core
	mrs  $1, $2
	b    2f
// non-PE core / P-core / non-AMP architecture
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	mrs  $1, $3
2:
.endmacro

/*
 * Writes a system register using the appropriate name for E-cores, P-cores and
 * non-PE cores.
 *
 * @note See also: ARM64_IS_ECORE
 *
 * @param arg0 GPR indicating the core type; non-zero if this is an E-core, else zero
 * @param arg1 source GPR
 * @param arg2 system register name to use for E-cores
 * @param arg3 system register name to use for P-cores, non-PE cores or
 *             non-AMP architectures.
 */
.macro ARM64_WRITE_CORE_SYSREG
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbz  $0, 1f
// E-core
	msr  $2, $1
	b    2f
// non-PE core / P-core / non-AMP architecture
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	msr  $3, $1
2:
.endmacro

#endif /* ASSEMBLER */

#endif /* ! _PEXPERT_ARM_ARM64_H */
