/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include <pexpert/pexpert.h>
#if __arm64__
#include <pexpert/arm64/board_config.h>
#include <arm64/hv_hvc.h>
#endif /* __arm64__ */

#include <arm/cpuid_internal.h>
#include <arm/cpu_capabilities_public.h>
#include <arm/pmap.h>
#include <arm64/proc_reg.h>
#include <machine/machine_cpuid.h>
#include <machine/machine_routines.h>
#include <vm/vm_protos.h>


#if defined(APPLEAVALANCHE) && defined(ARM64_BOARD_CONFIG_T6020)
#define CHECK_RDAR_145882231 1
#endif

#if defined(CHECK_RDAR_145882231)
SECURITY_READ_ONLY_LATE(bool) needs_rdar_145882231 = FALSE;
extern char gTargetTypeBuffer[16];
#endif /* CHECK_RDAR_145882231 */

#if __arm64__

void configure_misc_apple_boot_args(void);
void configure_misc_apple_regs(bool is_boot_cpu);
void configure_timer_apple_regs(void);
void configure_late_apple_regs(bool cold_boot);

void
configure_misc_apple_boot_args(void)
{
}


void
configure_misc_apple_regs(bool is_boot_cpu)
{
#pragma unused(is_boot_cpu)

}

// machine_routines_apple.c gets built on non-Apple platforms but it won't
// #include apple_arm64_regs.h so some of the constants referenced below
// won't exist in those builds
#if APPLE_ARM64_ARCH_FAMILY

static bool
cpu_needs_throttle_tunable(uint32_t midr_pnum)
{
	switch (midr_pnum) {
#if defined(APPLEAVALANCHE)
	/* ACCP only */
	case MIDR_RHODES_DIE_AVALANCHE:
		return true;
#endif /* APPLEAVALANCHE */

#if defined(APPLEEVEREST)
	case MIDR_IBIZA_ACCE:
	case MIDR_IBIZA_ACCP:
		return true;
	case MIDR_LOBOS_ACCE:
	case MIDR_LOBOS_ACCP:
		return true;
	case MIDR_PALMA_ACCE:
	case MIDR_PALMA_ACCP:
		return true;
	case MIDR_COLL_ACCE:
	case MIDR_COLL_ACCP:
		return true;
#endif /* APPLEEVEREST */
	default:
		return false;
	}
}

/*
 * configure_late_apple_regs()
 *
 * Normal tunables (HID bits) are applied early on, in the APPLY_TUNABLES
 * asm macro.  This C function is intended to handle special cases where that
 * isn't possible, e.g.
 *  - Tunables that require PIO mappings
 *  - Tunables that need access to the parsed CPU topology info
 *
 * Unlike configure_misc_apple_regs(), it is guaranteed to execute after
 * ml_parse_cpu_topology() / ml_map_cpu_pio() are done,
 * and after cpu_number() is valid.
 */
void
configure_late_apple_regs(bool cold_boot)
{
#if defined(CHECK_RDAR_145882231)
	if (cold_boot) {
		/* We only want the rdar://145882231 tunable to apply to J236c */
		if (0 == strncmp(gTargetTypeBuffer, "J236c", sizeof(gTargetTypeBuffer))) {
			needs_rdar_145882231 = true;
		}
	}

	/* rdar://145882231 */
	if (needs_rdar_145882231 && arm64_is_p_core()) {
		uint64_t hid16  = __builtin_arm_rsr64("HID16");
		hid16 |= ARM64_REG_HID16_leqThrottleAggr;
		__builtin_arm_wsr64("HID16", hid16);
		hid16 = __builtin_arm_rsr64("HID16");
		const uint64_t expect = hid16 | ARM64_REG_HID16_leqThrottleAggr;
		if (expect != hid16) {
			panic("HID16 not as expected, Got: 0x%llx, Expected: 0x%llx", hid16, expect);
		}
	}
#endif /* CHECK_RDAR_145882231 */

	const ml_topology_info_t *tinfo = ml_get_topology_info();
	uint32_t midr_pnum = machine_read_midr() & MIDR_EL1_PNUM_MASK;
	uint64_t reg_val;

	bool apply_late_pio_regs = cold_boot;
#ifdef APPLEEVEREST
	/*
	 * On H15 CPUs PIO locks are applied early in the non-cold boot
	 * path.
	 */
	apply_late_pio_regs = 0;
#endif
	if (apply_late_pio_regs) {
		if (cpu_needs_throttle_tunable(midr_pnum)) {
			vm_offset_t cpu_impl = tinfo->cpus[cpu_number()].cpu_IMPL_regs;
			const uint64_t c1pptThrtlRate = 0xb2;
			reg_val = ml_io_read64(cpu_impl + CORE_THRTL_CFG2_OFFSET);
			reg_val &= ~CORE_THRTL_CFG2_c1pptThrtlRate_mask;
			reg_val |= c1pptThrtlRate << CORE_THRTL_CFG2_c1pptThrtlRate_shift;
			ml_io_write64(cpu_impl + CORE_THRTL_CFG2_OFFSET, reg_val);
		}
	}

#if defined(APPLEAVALANCHE)
	if (tinfo->max_die_id > 0) {
		if (midr_pnum == MIDR_RHODES_DIE_AVALANCHE || midr_pnum == MIDR_RHODES_DIE_BLIZZARD) {
			// rdar://93675127 (Rhodes address match granularity for BIU)
			reg_val = __builtin_arm_rsr64("HID5");
			reg_val &= ~ARM64_REG_HID5_BiuBchMatchGran_mask;
			reg_val |= ARM64_REG_HID5_BiuBchMatchGran_VALUE(0);
			__builtin_arm_wsr64("HID5", reg_val);
		}
	}
#endif /* APPLEAVALANCHE */

#if defined(APPLEEVEREST)
#endif /* APPLEEVEREST */
}
#endif /* APPLE_ARM64_ARCH_FAMILY */

void
configure_timer_apple_regs(void)
{
}

#endif /* __arm64__ */

#if HAS_APPLE_PAC

#if HAS_PARAVIRTUALIZED_PAC
static uint64_t vmapple_default_rop_pid;
static uint64_t vmapple_default_jop_pid;

static inline void
vmapple_pac_get_default_keys()
{
	static bool initialized = false;
	if (os_atomic_xchg(&initialized, true, relaxed)) {
		return;
	}

	const uint64_t fn = VMAPPLE_PAC_GET_DEFAULT_KEYS;
	asm volatile (
                "mov	x0, %[fn]"      "\n"
                "hvc	#0"             "\n"
                "cbnz	x0, ."          "\n"
                "str	x2, %[b_key]"   "\n"
                "str	x3, %[el0_key]" "\n"
                : [b_key] "=m"(vmapple_default_rop_pid),
                  [el0_key] "=m"(vmapple_default_jop_pid)
                : [fn] "r"(fn)
                : "x0", "x1", "x2", "x3", "x4"
        );
}

#endif /* HAS_PARAVIRTUALIZED_PAC */

/**
 * Returns the default ROP key.
 */
uint64_t
ml_default_rop_pid(void)
{
#if HAS_PARAVIRTUALIZED_PAC
	vmapple_pac_get_default_keys();
	return vmapple_default_rop_pid;
#else
	return 0;
#endif /* HAS_PARAVIRTUALIZED_PAC */
}

/**
 * Returns the default JOP key.
 */
uint64_t
ml_default_jop_pid(void)
{
#if HAS_PARAVIRTUALIZED_PAC
	vmapple_pac_get_default_keys();
	return vmapple_default_jop_pid;
#else
	return 0;
#endif /* HAS_PARAVIRTUALIZED_PAC */
}

/**
 * Returns an appropriate JOP key for non-arm64e userspace processes.  The
 * return value may vary from call to call.
 */
uint64_t
ml_non_arm64e_user_jop_pid(void)
{
#if HAS_PARAVIRTUALIZED_PAC
	return generate_jop_key();
#else
	return 0;
#endif /* HAS_PARAVIRTUALIZED_PAC */
}
#endif /* HAS_APPLE_PAC */

