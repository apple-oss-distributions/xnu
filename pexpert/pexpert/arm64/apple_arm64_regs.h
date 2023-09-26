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



#endif /* APPLE_ARM64_ARCH_FAMILY */


#if defined(HAS_BP_RET)
#define ARM64_REG_ACC_CFG_bdpSlpEn    (1ULL << 2)
#define ARM64_REG_ACC_CFG_btpSlpEn    (1ULL << 3)
#define ARM64_REG_ACC_CFG_bpSlp_mask  3
#define ARM64_REG_ACC_CFG_bpSlp_shift 2
#endif /* defined(HAS_BP_RET) */



#define MPIDR_PNE_SHIFT 16 // pcore not ecore
#define MPIDR_PNE       (1 << MPIDR_PNE_SHIFT)


#define CPU_PIO_CPU_STS_OFFSET               (0x100ULL)
#define CPU_PIO_CPU_STS_cpuRunSt_mask        (0xff)

/*
 * CORE_THRTL_CFG2 non-sysreg tunable
 */
#define CORE_THRTL_CFG2_OFFSET               (0x218)




#ifdef ASSEMBLER

/*
 * arg0: register in which to store result
 *   0=>not a p-core, non-zero=>p-core
 */
.macro ARM64_IS_PCORE
#if defined(APPLEMONSOON) || HAS_CLUSTER
	mrs $0, MPIDR_EL1
	and $0, $0, #(MPIDR_PNE)
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
.endmacro

/*
 * reads a special purpose register, using a different msr for e- vs. p-cores
 *   arg0: register indicating the current core type, see ARM64_IS_PCORE
 *   arg1: register in which to store the result of the read
 *   arg2: SPR to use for e-core
 *   arg3: SPR to use for p-core or non-AMP architecture
 */
.macro ARM64_READ_EP_SPR
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbnz $0, 1f
// e-core
	mrs  $1, $2
	b    2f
// p-core
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	mrs  $1, $3
2:
.endmacro

/*
 * writes a special purpose register, using a different msr for e- vs. p-cores
 * arg0: register indicating the current core type, see ARM64_IS_PCORE
 * arg1: register containing the value to write
 * arg2: SPR to use for e-core
 * arg3: SPR to use for p-core or non-AMP architecture
 */
.macro ARM64_WRITE_EP_SPR
#if defined(APPLEMONSOON) || HAS_CLUSTER
	cbnz $0, 1f
// e-core
	msr  $2, $1
	b    2f
// p-core
1:
#endif /* defined(APPLEMONSOON) || HAS_CLUSTER */
	msr  $3, $1
2:
.endmacro

#endif /* ASSEMBLER */

#endif /* ! _PEXPERT_ARM_ARM64_H */
