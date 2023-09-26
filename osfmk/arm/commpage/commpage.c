/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 *	File:		arm/commpage/commpage.c
 *	Purpose:	Set up and export a RO/RW page
 */
#include <libkern/section_keywords.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/vm_map.h>
#include <machine/cpu_capabilities.h>
#include <machine/commpage.h>
#include <machine/config.h>
#include <machine/pmap.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <ipc/ipc_port.h>
#include <arm/cpuid.h>          /* for cpuid_info() & cache_info() */
#include <arm/misc_protos.h>
#include <arm/rtclock.h>
#include <libkern/OSAtomic.h>
#include <stdatomic.h>
#include <kern/remote_time.h>
#include <kern/smr.h>
#include <machine/atomic.h>
#include <machine/machine_remote_time.h>
#include <machine/machine_routines.h>

#include <sys/kdebug.h>

#if CONFIG_ATM
#include <atm/atm_internal.h>
#endif

static int commpage_cpus( void );


static void commpage_init_cpu_capabilities( void );

SECURITY_READ_ONLY_LATE(vm_address_t)   commPagePtr = 0;
SECURITY_READ_ONLY_LATE(vm_address_t)   commpage_rw_addr = 0;
SECURITY_READ_ONLY_LATE(vm_address_t)   commpage_kernel_ro_addr = 0;
SECURITY_READ_ONLY_LATE(uint64_t)       _cpu_capabilities = 0;
SECURITY_READ_ONLY_LATE(vm_address_t)   commpage_rw_text_addr = 0;

extern user64_addr_t commpage_text64_location;
extern user32_addr_t commpage_text32_location;

/* For sysctl access from BSD side */
extern int gARMv8Crc32;
extern int gARMv8Gpi;
extern int gARM_FEAT_FlagM;
extern int gARM_FEAT_FlagM2;
extern int gARM_FEAT_FHM;
extern int gARM_FEAT_DotProd;
extern int gARM_FEAT_SHA3;
extern int gARM_FEAT_RDM;
extern int gARM_FEAT_LSE;
extern int gARM_FEAT_SHA256;
extern int gARM_FEAT_SHA512;
extern int gARM_FEAT_SHA1;
extern int gARM_FEAT_AES;
extern int gARM_FEAT_PMULL;
extern int gARM_FEAT_SPECRES;
extern int gARM_FEAT_SB;
extern int gARM_FEAT_FRINTTS;
extern int gARM_FEAT_LRCPC;
extern int gARM_FEAT_LRCPC2;
extern int gARM_FEAT_FCMA;
extern int gARM_FEAT_JSCVT;
extern int gARM_FEAT_PAuth;
extern int gARM_FEAT_PAuth2;
extern int gARM_FEAT_FPAC;
extern int gARM_FEAT_DPB;
extern int gARM_FEAT_DPB2;
extern int gARM_FEAT_BF16;
extern int gARM_FEAT_I8MM;
extern int gARM_FEAT_ECV;
extern int gARM_FEAT_LSE2;
extern int gARM_FEAT_CSV2;
extern int gARM_FEAT_CSV3;
extern int gARM_FEAT_DIT;
extern int gARM_AdvSIMD;
extern int gARM_AdvSIMD_HPFPCvt;
extern int gARM_FEAT_FP16;
extern int gARM_FEAT_SSBS;
extern int gARM_FEAT_BTI;
extern int gARM_FP_SyncExceptions;

extern int      gUCNormalMem;

void
commpage_populate(void)
{
	uint16_t        c2;
	int cpufamily;

	// Create the data and the text commpage
	vm_map_address_t kernel_data_addr, kernel_text_addr, kernel_ro_data_addr, user_text_addr;
	pmap_create_commpages(&kernel_data_addr, &kernel_text_addr, &kernel_ro_data_addr, &user_text_addr);

	commpage_rw_addr = kernel_data_addr;
	commpage_rw_text_addr = kernel_text_addr;
	commpage_kernel_ro_addr = kernel_ro_data_addr;
	commPagePtr = (vm_address_t) _COMM_PAGE_BASE_ADDRESS;

#if __arm64__
	commpage_text64_location = user_text_addr;
	bcopy(_COMM_PAGE64_SIGNATURE_STRING, (void *)(_COMM_PAGE_SIGNATURE + _COMM_PAGE_RW_OFFSET),
	    MIN(_COMM_PAGE_SIGNATURELEN, strlen(_COMM_PAGE64_SIGNATURE_STRING)));
#endif

	*((uint16_t*)(_COMM_PAGE_VERSION + _COMM_PAGE_RW_OFFSET)) = (uint16_t) _COMM_PAGE_THIS_VERSION;

	commpage_init_cpu_capabilities();
	commpage_set_timestamp(0, 0, 0, 0, 0);

	if (_cpu_capabilities & kCache32) {
		c2 = 32;
	} else if (_cpu_capabilities & kCache64) {
		c2 = 64;
	} else if (_cpu_capabilities & kCache128) {
		c2 = 128;
	} else {
		c2 = 0;
	}

	*((uint16_t*)(_COMM_PAGE_CACHE_LINESIZE + _COMM_PAGE_RW_OFFSET)) = c2;

	commpage_update_active_cpus();
	cpufamily = cpuid_get_cpufamily();
	*((uint8_t*)(_COMM_PAGE_CPU_CLUSTERS + _COMM_PAGE_RW_OFFSET)) = (uint8_t) ml_get_cluster_count();
	*((uint8_t*)(_COMM_PAGE_PHYSICAL_CPUS + _COMM_PAGE_RW_OFFSET)) = (uint8_t) machine_info.physical_cpu_max;
	*((uint8_t*)(_COMM_PAGE_LOGICAL_CPUS + _COMM_PAGE_RW_OFFSET)) = (uint8_t) machine_info.logical_cpu_max;
	*((uint64_t*)(_COMM_PAGE_MEMORY_SIZE + _COMM_PAGE_RW_OFFSET)) = machine_info.max_mem;
	*((uint32_t*)(_COMM_PAGE_CPUFAMILY + _COMM_PAGE_RW_OFFSET)) = (uint32_t)cpufamily;
	*((uint32_t*)(_COMM_PAGE_DEV_FIRM_LEGACY + _COMM_PAGE_RW_OFFSET)) = (uint32_t)PE_i_can_has_debugger(NULL);
	*((uint32_t*)(_COMM_PAGE_DEV_FIRM + _COMM_PAGE_RO_OFFSET)) = (uint32_t)PE_i_can_has_debugger(NULL);
	*((uint8_t*)(_COMM_PAGE_USER_TIMEBASE + _COMM_PAGE_RW_OFFSET)) = user_timebase_type();

	// Populate logical CPU -> logical cluster table
	ml_map_cpus_to_clusters((uint8_t*)(_COMM_PAGE_CPU_TO_CLUSTER + _COMM_PAGE_RW_OFFSET));

	*((uint8_t*)(_COMM_PAGE_CONT_HWCLOCK + _COMM_PAGE_RW_OFFSET)) = (uint8_t)user_cont_hwclock_allowed();
	*((uint8_t*)(_COMM_PAGE_KERNEL_PAGE_SHIFT_LEGACY + _COMM_PAGE_RW_OFFSET)) = (uint8_t) page_shift;
	*((uint8_t*)(_COMM_PAGE_KERNEL_PAGE_SHIFT + _COMM_PAGE_RO_OFFSET)) = (uint8_t) page_shift;

#if __arm64__
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_32_LEGACY + _COMM_PAGE_RW_OFFSET)) = (uint8_t) page_shift_user32;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_32 + _COMM_PAGE_RO_OFFSET)) = (uint8_t) page_shift_user32;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_64_LEGACY + _COMM_PAGE_RW_OFFSET)) = (uint8_t) SIXTEENK_PAGE_SHIFT;
	*((uint8_t*)(_COMM_PAGE_USER_PAGE_SHIFT_64 + _COMM_PAGE_RO_OFFSET)) = (uint8_t) SIXTEENK_PAGE_SHIFT;
#endif /* __arm64__ */

	commpage_update_timebase();
	commpage_update_mach_continuous_time(0);

	clock_sec_t secs;
	clock_usec_t microsecs;
	clock_get_boottime_microtime(&secs, &microsecs);
	commpage_update_boottime(secs * USEC_PER_SEC + microsecs);

	/*
	 * set commpage approximate time to zero for initialization.
	 * scheduler shall populate correct value before running user thread
	 */
	*((uint64_t *)(_COMM_PAGE_APPROX_TIME + _COMM_PAGE_RW_OFFSET)) = 0;
#ifdef CONFIG_MACH_APPROXIMATE_TIME
	*((uint8_t *)(_COMM_PAGE_APPROX_TIME_SUPPORTED + _COMM_PAGE_RW_OFFSET)) = 1;
#else
	*((uint8_t *)(_COMM_PAGE_APPROX_TIME_SUPPORTED + _COMM_PAGE_RW_OFFSET)) = 0;
#endif

	commpage_update_kdebug_state();

#if CONFIG_ATM
	commpage_update_atm_diagnostic_config(atm_get_diagnostic_config());
#endif


	*((uint64_t*)(_COMM_PAGE_REMOTETIME_PARAMS + _COMM_PAGE_RW_OFFSET)) = BT_RESET_SENTINEL_TS;

#if CONFIG_QUIESCE_COUNTER
	cpu_quiescent_set_storage((_Atomic uint64_t *)(_COMM_PAGE_CPU_QUIESCENT_COUNTER +
	    _COMM_PAGE_RW_OFFSET));
#endif /* CONFIG_QUIESCE_COUNTER */
}

#define COMMPAGE_TEXT_SEGMENT "__TEXT_EXEC"
#define COMMPAGE_TEXT_SECTION "__commpage_text"

/* Get a pointer to the start of the ARM PFZ code section. This macro tell the
 * linker that the storage for the variable here is at the start of the section */
extern char commpage_text_start[]
__SECTION_START_SYM(COMMPAGE_TEXT_SEGMENT, COMMPAGE_TEXT_SECTION);

/* Get a pointer to the end of the ARM PFZ code section. This macro tell the
 * linker that the storage for the variable here is at the end of the section */
extern char commpage_text_end[]
__SECTION_END_SYM(COMMPAGE_TEXT_SEGMENT, COMMPAGE_TEXT_SECTION);

/* This is defined in the commpage text section as a symbol at the start of the preemptible
 * functions */
extern char commpage_text_preemptible_functions;

#if CONFIG_ARM_PFZ
static size_t size_of_pfz = 0;
#endif

/* This is the opcode for brk #666 */
#define BRK_666_OPCODE 0xD4205340

void
commpage_text_populate(void)
{
#if CONFIG_ARM_PFZ
	size_t size_of_commpage_text = commpage_text_end - commpage_text_start;
	if (size_of_commpage_text == 0) {
		panic("ARM comm page text section %s,%s missing", COMMPAGE_TEXT_SEGMENT, COMMPAGE_TEXT_SECTION);
	}
	assert(size_of_commpage_text <= PAGE_SIZE);
	assert(size_of_commpage_text > 0);

	/* Get the size of the PFZ half of the comm page text section. */
	size_of_pfz = &commpage_text_preemptible_functions - commpage_text_start;

	// Copy the code segment of comm page text section into the PFZ
	memcpy((void *) _COMM_PAGE64_TEXT_START_ADDRESS, (void *) commpage_text_start, size_of_commpage_text);

	// Make sure to populate the rest of it with brk 666 so that undefined code
	// doesn't get  run
	memset((char *) _COMM_PAGE64_TEXT_START_ADDRESS + size_of_commpage_text, BRK_666_OPCODE,
	    PAGE_SIZE - size_of_commpage_text);
#endif
}

uint32_t
commpage_is_in_pfz64(addr64_t addr64)
{
#if CONFIG_ARM_PFZ
	if ((addr64 >= commpage_text64_location) &&
	    (addr64 < (commpage_text64_location + size_of_pfz))) {
		return 1;
	} else {
		return 0;
	}
#else
#pragma unused (addr64)
	return 0;
#endif
}


void
commpage_set_timestamp(
	uint64_t        tbr,
	uint64_t        secs,
	uint64_t        frac,
	uint64_t        scale,
	uint64_t        tick_per_sec)
{
	new_commpage_timeofday_data_t *commpage_timeofday_datap;

	if (commPagePtr == 0) {
		return;
	}

	commpage_timeofday_datap =  (new_commpage_timeofday_data_t *)(_COMM_PAGE_NEWTIMEOFDAY_DATA + _COMM_PAGE_RW_OFFSET);

	commpage_timeofday_datap->TimeStamp_tick = 0x0ULL;

	__builtin_arm_dmb(DMB_ISH);

	commpage_timeofday_datap->TimeStamp_sec = secs;
	commpage_timeofday_datap->TimeStamp_frac = frac;
	commpage_timeofday_datap->Ticks_scale = scale;
	commpage_timeofday_datap->Ticks_per_sec = tick_per_sec;

	__builtin_arm_dmb(DMB_ISH);

	commpage_timeofday_datap->TimeStamp_tick = tbr;

}

/*
 * Update _COMM_PAGE_MEMORY_PRESSURE.  Called periodically from vm's compute_memory_pressure()
 */

void
commpage_set_memory_pressure(
	unsigned int    pressure )
{
	if (commPagePtr == 0) {
		return;
	}
	*((uint32_t *)(_COMM_PAGE_MEMORY_PRESSURE + _COMM_PAGE_RW_OFFSET)) = pressure;
}

/*
 * Determine number of CPUs on this system.
 */
static int
commpage_cpus( void )
{
	int cpus;

	cpus = machine_info.max_cpus;

	if (cpus == 0) {
		panic("commpage cpus==0");
	}
	if (cpus > 0xFF) {
		cpus = 0xFF;
	}

	return cpus;
}

uint64_t
_get_cpu_capabilities(void)
{
	return _cpu_capabilities;
}

vm_address_t
_get_commpage_priv_address(void)
{
	return commpage_rw_addr;
}

vm_address_t
_get_commpage_ro_address(void)
{
	return commpage_kernel_ro_addr;
}

vm_address_t
_get_commpage_text_priv_address(void)
{
	return commpage_rw_text_addr;
}

#if defined(__arm64__)
/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64ISAR0_EL1
 */
static void
commpage_init_arm_optional_features_isar0(uint64_t *commpage_bits)
{
	uint64_t bits = 0;
	uint64_t isar0 = __builtin_arm_rsr64("ID_AA64ISAR0_EL1");

	if ((isar0 & ID_AA64ISAR0_EL1_TS_MASK) >= ID_AA64ISAR0_EL1_TS_FLAGM_EN) {
		gARM_FEAT_FlagM = 1;
		bits |= kHasFEATFlagM;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_TS_MASK) >= ID_AA64ISAR0_EL1_TS_FLAGM2_EN) {
		gARM_FEAT_FlagM2 = 1;
		bits |= kHasFEATFlagM2;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_FHM_MASK) >= ID_AA64ISAR0_EL1_FHM_8_2) {
		gARM_FEAT_FHM = 1;
		bits |= kHasFeatFHM;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_DP_MASK) >= ID_AA64ISAR0_EL1_DP_EN) {
		gARM_FEAT_DotProd = 1;
		bits |= kHasFeatDotProd;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_SHA3_MASK) >= ID_AA64ISAR0_EL1_SHA3_EN) {
		gARM_FEAT_SHA3 = 1;
		bits |= kHasFeatSHA3;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_RDM_MASK) >= ID_AA64ISAR0_EL1_RDM_EN) {
		gARM_FEAT_RDM = 1;
		bits |= kHasFeatRDM;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_ATOMIC_MASK) >= ID_AA64ISAR0_EL1_ATOMIC_8_1) {
		gARM_FEAT_LSE = 1;
		bits |= kHasFeatLSE;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_SHA2_MASK) >= ID_AA64ISAR0_EL1_SHA2_512_EN) {
		gARM_FEAT_SHA512 = 1;
		bits |= kHasFeatSHA512;
	}
	if ((isar0 & ID_AA64ISAR0_EL1_CRC32_MASK) == ID_AA64ISAR0_EL1_CRC32_EN) {
		gARMv8Crc32 = 1;
		bits |= kHasARMv8Crc32;
	}

#if __ARM_V8_CRYPTO_EXTENSIONS__
	/**
	 * T7000 has a bug in the ISAR0 register that reports that PMULL is not
	 * supported when it actually is. To work around this, for all of the crypto
	 * extensions, just check if they're supported using the board_config.h
	 * values.
	 */
	gARM_FEAT_PMULL = 1;
	gARM_FEAT_SHA1 = 1;
	gARM_FEAT_AES = 1;
	gARM_FEAT_SHA256 = 1;
	bits |= kHasARMv8Crypto;
#endif /* __ARM_V8_CRYPTO_EXTENSIONS__ */

	*commpage_bits |= bits;
}

/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64ISAR1_EL1
 */
static void
commpage_init_arm_optional_features_isar1(uint64_t *commpage_bits)
{
	uint64_t bits = 0;
	uint64_t isar1 = __builtin_arm_rsr64("ID_AA64ISAR1_EL1");
	uint64_t sctlr = __builtin_arm_rsr64("SCTLR_EL1");

	if ((isar1 & ID_AA64ISAR1_EL1_SPECRES_MASK) >= ID_AA64ISAR1_EL1_SPECRES_EN &&
	    sctlr & SCTLR_EnRCTX) {
		gARM_FEAT_SPECRES = 1;
		bits |= kHasFeatSPECRES;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_SB_MASK) >= ID_AA64ISAR1_EL1_SB_EN) {
		gARM_FEAT_SB = 1;
		bits |= kHasFeatSB;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_FRINTTS_MASK) >= ID_AA64ISAR1_EL1_FRINTTS_EN) {
		gARM_FEAT_FRINTTS = 1;
		bits |= kHasFeatFRINTTS;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_GPI_MASK) >= ID_AA64ISAR1_EL1_GPI_EN) {
		gARMv8Gpi = 1;
		bits |= kHasArmv8GPI;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_LRCPC_MASK) >= ID_AA64ISAR1_EL1_LRCPC_EN) {
		gARM_FEAT_LRCPC = 1;
		bits |= kHasFeatLRCPC;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_LRCPC_MASK) >= ID_AA64ISAR1_EL1_LRCP2C_EN) {
		gARM_FEAT_LRCPC2 = 1;
		bits |= kHasFeatLRCPC2;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_FCMA_MASK) >= ID_AA64ISAR1_EL1_FCMA_EN) {
		gARM_FEAT_FCMA = 1;
		bits |= kHasFeatFCMA;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_JSCVT_MASK) >= ID_AA64ISAR1_EL1_JSCVT_EN) {
		gARM_FEAT_JSCVT = 1;
		bits |= kHasFeatJSCVT;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_API_MASK) >= ID_AA64ISAR1_EL1_API_PAuth_EN) {
		gARM_FEAT_PAuth = 1;
		bits |= kHasFeatPAuth;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_API_MASK) >= ID_AA64ISAR1_EL1_API_PAuth2_EN) {
		gARM_FEAT_PAuth2 = 1;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_API_MASK) >= ID_AA64ISAR1_EL1_API_FPAC_EN) {
		gARM_FEAT_FPAC = 1;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_DPB_MASK) >= ID_AA64ISAR1_EL1_DPB_EN) {
		gARM_FEAT_DPB = 1;
		bits |= kHasFeatDPB;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_DPB_MASK) >= ID_AA64ISAR1_EL1_DPB2_EN) {
		gARM_FEAT_DPB2 = 1;
		bits |= kHasFeatDPB2;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_BF16_MASK) >= ID_AA64ISAR1_EL1_BF16_EN) {
		gARM_FEAT_BF16 = 1;
	}
	if ((isar1 & ID_AA64ISAR1_EL1_I8MM_MASK) >= ID_AA64ISAR1_EL1_I8MM_EN) {
		gARM_FEAT_I8MM = 1;
	}

	*commpage_bits |= bits;
}

/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64MMFR0_EL1
 */
static void
commpage_init_arm_optional_features_mmfr0(uint64_t *commpage_bits)
{
	uint64_t bits = 0;
	uint64_t mmfr0 = __builtin_arm_rsr64("ID_AA64MMFR0_EL1");

	if ((mmfr0 & ID_AA64MMFR0_EL1_ECV_MASK) >= ID_AA64MMFR0_EL1_ECV_EN) {
		gARM_FEAT_ECV = 1;
	}

	*commpage_bits |= bits;
}

/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64MMFR2_EL1
 */
static void
commpage_init_arm_optional_features_mmfr2(uint64_t *commpage_bits)
{
	uint64_t bits = 0;
	uint64_t mmfr2 = __builtin_arm_rsr64("ID_AA64MMFR2_EL1");

	if ((mmfr2 & ID_AA64MMFR2_EL1_AT_MASK) >= ID_AA64MMFR2_EL1_AT_LSE2_EN) {
		gARM_FEAT_LSE2 = 1;
		bits |= kHasFeatLSE2;
	}

	*commpage_bits |= bits;
}

/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64PFR0_EL1
 */
static void
commpage_init_arm_optional_features_pfr0(uint64_t *commpage_bits)
{
	uint64_t bits = 0;
	uint64_t pfr0 = __builtin_arm_rsr64("ID_AA64PFR0_EL1");

	if ((pfr0 & ID_AA64PFR0_EL1_CSV3_MASK) >= ID_AA64PFR0_EL1_CSV3_EN) {
		gARM_FEAT_CSV3 = 1;
		bits |= kHasFeatCSV3;
	}
	if ((pfr0 & ID_AA64PFR0_EL1_CSV2_MASK) >= ID_AA64PFR0_EL1_CSV2_EN) {
		gARM_FEAT_CSV2 = 1;
		bits |= kHasFeatCSV2;
	}
	if ((pfr0 & ID_AA64PFR0_EL1_DIT_MASK) >= ID_AA64PFR0_EL1_DIT_EN) {
		gARM_FEAT_DIT = 1;
		bits |= kHasFeatDIT;
	}
	if ((pfr0 & ID_AA64PFR0_EL1_AdvSIMD_MASK) != ID_AA64PFR0_EL1_AdvSIMD_DIS) {
		gARM_AdvSIMD = 1;
		bits |= kHasAdvSIMD;
		if ((pfr0 & ID_AA64PFR0_EL1_AdvSIMD_MASK) >= ID_AA64PFR0_EL1_AdvSIMD_HPFPCVT) {
			gARM_AdvSIMD_HPFPCvt = 1;
			bits |= kHasAdvSIMD_HPFPCvt;
		}
		if ((pfr0 & ID_AA64PFR0_EL1_AdvSIMD_MASK) >= ID_AA64PFR0_EL1_AdvSIMD_FP16) {
			gARM_FEAT_FP16 = 1;
			bits |= kHasFeatFP16;
		}
	}

	*commpage_bits |= bits;
}

/**
 * Initializes all commpage entries and sysctls for EL0 visible features in ID_AA64PFR1_EL1
 */
static void
commpage_init_arm_optional_features_pfr1(uint64_t *commpage_bits)
{
	uint64_t pfr1 = __builtin_arm_rsr64("ID_AA64PFR1_EL1");

	if ((pfr1 & ID_AA64PFR1_EL1_SSBS_MASK) >= ID_AA64PFR1_EL1_SSBS_EN) {
		gARM_FEAT_SSBS = 1;
	}

	if ((pfr1 & ID_AA64PFR1_EL1_BT_MASK) >= ID_AA64PFR1_EL1_BT_EN) {
		gARM_FEAT_BTI = 1;
	}

#pragma unused(commpage_bits)
}


/**
 * Read the system register @name, attempt to set set bits of @mask if not
 * already, test if bits were actually set, reset the register to its
 * previous value if required, and 'return' @mask with only bits that
 * were successfully set (or already set) in the system register. */
#define _test_sys_bits(name, mask) ({ \
	const uint64_t src = __builtin_arm_rsr64(#name); \
    uint64_t test = src | mask; \
    if (test != src) { \
	__builtin_arm_wsr64(#name, test); \
	test = __builtin_arm_rsr64(#name); \
	if (test != src) { \
	    __builtin_arm_wsr64(#name, src); \
	}\
    } \
    mask & test; \
})

/**
 * Reports whether FPU exceptions are supported.
 * Possible FPU exceptions are :
 * - input denormal;
 * - inexact;
 * - underflow;
 * - overflow;
 * - divide by 0;
 * - invalid operation.
 *
 * Any of those can be supported or not but for now, we consider that
 * it all or nothing : FPU exceptions support flag set <=> all 6 exceptions
 * a supported.
 */
static void
commpage_init_arm_optional_features_fpcr(uint64_t *commpage_bits)
{
	uint64_t support_mask = FPCR_IDE | FPCR_IXE | FPCR_UFE | FPCR_OFE |
	    FPCR_DZE | FPCR_IOE;
	uint64_t FPCR_bits = _test_sys_bits(FPCR, support_mask);
	if (FPCR_bits == support_mask) {
		gARM_FP_SyncExceptions = 1;
		*commpage_bits |= kHasFP_SyncExceptions;
	}
}

/**
 * Initializes all commpage entries and sysctls for ARM64 optional features accessible from EL0.
 */
static void
commpage_init_arm_optional_features(uint64_t *commpage_bits)
{
	commpage_init_arm_optional_features_isar0(commpage_bits);
	commpage_init_arm_optional_features_isar1(commpage_bits);
	commpage_init_arm_optional_features_mmfr0(commpage_bits);
	commpage_init_arm_optional_features_mmfr2(commpage_bits);
	commpage_init_arm_optional_features_pfr0(commpage_bits);
	commpage_init_arm_optional_features_pfr1(commpage_bits);
	commpage_init_arm_optional_features_fpcr(commpage_bits);
}
#endif /* __arm64__ */

/*
 * Initialize _cpu_capabilities vector
 */
static void
commpage_init_cpu_capabilities( void )
{
	uint64_t bits;
	int cpus;
	ml_cpu_info_t cpu_info;

	bits = 0;
	ml_cpu_get_info(&cpu_info);

	switch (cpu_info.cache_line_size) {
	case 128:
		bits |= kCache128;
		break;
	case 64:
		bits |= kCache64;
		break;
	case 32:
		bits |= kCache32;
		break;
	default:
		break;
	}
	cpus = commpage_cpus();

	if (cpus == 1) {
		bits |= kUP;
	}

	bits |= (cpus << kNumCPUsShift);

	bits |= kFastThreadLocalStorage;        // TPIDRURO for TLS

	bits |= kHasVfp;

#if defined(__arm64__)
	bits |= kHasFMA;
#endif
	bits |= kHasEvent;
#ifdef __arm64__
	commpage_init_arm_optional_features(&bits);
#endif



#if HAS_UCNORMAL_MEM
	gUCNormalMem = 1;
	bits |= kHasUCNormalMemory;
#endif

	_cpu_capabilities = bits;

	*((uint32_t *)(_COMM_PAGE_CPU_CAPABILITIES + _COMM_PAGE_RW_OFFSET)) = (uint32_t)_cpu_capabilities;
	*((uint64_t *)(_COMM_PAGE_CPU_CAPABILITIES64 + _COMM_PAGE_RW_OFFSET)) = _cpu_capabilities;

}

/*
 * Updated every time a logical CPU goes offline/online
 */
void
commpage_update_active_cpus(void)
{
	if (!commPagePtr) {
		return;
	}
	*((uint8_t *)(_COMM_PAGE_ACTIVE_CPUS + _COMM_PAGE_RW_OFFSET)) = (uint8_t)processor_avail_count;

}

/*
 * Update the commpage bits for mach_absolute_time and mach_continuous_time (for userspace)
 */
void
commpage_update_timebase(void)
{
	if (commPagePtr) {
		*((uint64_t*)(_COMM_PAGE_TIMEBASE_OFFSET + _COMM_PAGE_RW_OFFSET)) = rtclock_base_abstime;
	}
}

/*
 * Update the commpage with current kdebug state: whether tracing is enabled, a
 * typefilter is present, and continuous time should be used for timestamps.
 *
 * Disregards configuration and set to 0 if tracing is disabled.
 */
void
commpage_update_kdebug_state(void)
{
	if (commPagePtr) {
		uint32_t state = kdebug_commpage_state();
		*((volatile uint32_t *)(_COMM_PAGE_KDEBUG_ENABLE + _COMM_PAGE_RW_OFFSET)) = state;
	}
}

/* Ditto for atm_diagnostic_config */
void
commpage_update_atm_diagnostic_config(uint32_t diagnostic_config)
{
	if (commPagePtr) {
		*((volatile uint32_t*)(_COMM_PAGE_ATM_DIAGNOSTIC_CONFIG + _COMM_PAGE_RW_OFFSET)) = diagnostic_config;
	}
}

/*
 * Update the commpage data with the state of multiuser mode for
 * this device. Allowing various services in userspace to avoid
 * IPC in the (more common) non-multiuser environment.
 */
void
commpage_update_multiuser_config(uint32_t multiuser_config)
{
	if (commPagePtr) {
		*((volatile uint32_t *)(_COMM_PAGE_MULTIUSER_CONFIG + _COMM_PAGE_RW_OFFSET)) = multiuser_config;
	}
}

/*
 * update the commpage data for
 * last known value of mach_absolute_time()
 */

void
commpage_update_mach_approximate_time(uint64_t abstime)
{
#ifdef CONFIG_MACH_APPROXIMATE_TIME
	if (!commPagePtr) {
		return;
	}

	uint64_t *approx_time_base = (uint64_t *)(uintptr_t)(_COMM_PAGE_APPROX_TIME + _COMM_PAGE_RW_OFFSET);

	uint64_t saved_data = os_atomic_load_wide(approx_time_base, relaxed);
	if (saved_data < abstime) {
		/*
		 * ignore the success/fail return value assuming that
		 * if the value has been updated since we last read it,
		 * someone else has written a timestamp that is new enough.
		 */
		__unused bool ret = os_atomic_cmpxchg(approx_time_base,
		    saved_data, abstime, relaxed);
	}


#else /* CONFIG_MACH_APPROXIMATE_TIME */
#pragma unused (abstime)
#endif
}

/*
 * update the commpage data's total system sleep time for
 * userspace call to mach_continuous_time()
 */
void
commpage_update_mach_continuous_time(uint64_t sleeptime)
{
	if (!commPagePtr) {
		return;
	}

	uint64_t *cont_time_base = (uint64_t *)(uintptr_t)(_COMM_PAGE_CONT_TIMEBASE + _COMM_PAGE_RW_OFFSET);

	os_atomic_store_wide(cont_time_base, sleeptime, relaxed);

}

void
commpage_update_mach_continuous_time_hw_offset(uint64_t offset)
{
	*((uint64_t *)(_COMM_PAGE_CONT_HW_TIMEBASE + _COMM_PAGE_RW_OFFSET)) = offset;
}

/*
 * update the commpage's value for the boot time
 */
void
commpage_update_boottime(uint64_t value)
{
	if (!commPagePtr) {
		return;
	}

	uint64_t *boottime_usec = (uint64_t *)(uintptr_t)(_COMM_PAGE_BOOTTIME_USEC + _COMM_PAGE_RW_OFFSET);

	os_atomic_store_wide(boottime_usec, value, relaxed);

}

/*
 * set the commpage's remote time params for
 * userspace call to mach_bridge_remote_time()
 */
void
commpage_set_remotetime_params(double rate, uint64_t base_local_ts, uint64_t base_remote_ts)
{
	if (commPagePtr) {
#ifdef __arm64__
		struct bt_params *paramsp = (struct bt_params *)(_COMM_PAGE_REMOTETIME_PARAMS + _COMM_PAGE_RW_OFFSET);
		paramsp->base_local_ts = 0;
		__builtin_arm_dmb(DMB_ISH);
		paramsp->rate = rate;
		paramsp->base_remote_ts = base_remote_ts;
		__builtin_arm_dmb(DMB_ISH);
		paramsp->base_local_ts = base_local_ts;  //This will act as a generation count
#endif /* __arm64__ */
	}
}


/*
 * update the commpage with if dtrace user land probes are enabled
 */
void
commpage_update_dof(boolean_t enabled)
{
#if CONFIG_DTRACE
	*((uint8_t*)(_COMM_PAGE_DTRACE_DOF_ENABLED + _COMM_PAGE_RW_OFFSET)) = (enabled ? 1 : 0);
#else
	(void)enabled;
#endif
}

/*
 * update the dyld global config flags
 */
void
commpage_update_dyld_flags(uint64_t value)
{
	*((uint64_t*)(_COMM_PAGE_DYLD_FLAGS + _COMM_PAGE_RW_OFFSET)) = value;

}
