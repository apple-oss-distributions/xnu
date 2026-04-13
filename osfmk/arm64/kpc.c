/*
 * Copyright (c) 2012-2023 Apple Inc. All rights reserved.
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

#include <arm/cpu_data_internal.h>
#include <arm/cpu_internal.h>
#include <kern/cpu_number.h>
#include <kern/kpc.h>
#include <kern/thread.h>
#include <kern/processor.h>
#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <kern/cpc.h>
#include <stdint.h>
#include <sys/errno.h>

// KPC's implementation is maintained for backwards-compatibility,
// but on ARM, its internals have been replaced by CPC.

#if HAS_CPMU_PC_CAPTURE
int kpc_pc_capture = 1;
#else /* HAS_CPMU_PC_CAPTURE */
int kpc_pc_capture = 0;
#endif /* !HAS_CPMU_PC_CAPTURE */

static uint64_t _kpc_read_pmesr(uint32_t counter);

#define KPC_ARM64_FIXED_COUNT        (2)
#define KPC_ARM64_CONFIGURABLE_COUNT (CPMU_PMC_COUNT - KPC_ARM64_FIXED_COUNT)

#if CPMU_64BIT_PMCS
#define KPC_ARM64_COUNTER_WIDTH    (63)
#define KPC_ARM64_COUNTER_OVF_BIT  (63)
#else // CPMU_64BIT_PMCS
#define KPC_ARM64_COUNTER_WIDTH    (47)
#define KPC_ARM64_COUNTER_OVF_BIT  (47)
#endif // !CPMU_64BIT_PMCS

/*
 * Configuration registers that can be controlled by RAWPMU:
 *
 * All: PMCR2-4, OPMAT0-1, OPMSK0-1.
 * Later: PM_MEMFLT_CTL23, PM_MEMFLT_CTL45, PMEFR2-9.
 */
#if CPMU_EVENT_FILTERING
#define RAWPMU_CONFIG_COUNT 17
#else /* CPMU_EVENT_FILTERING */
#define RAWPMU_CONFIG_COUNT 7
#endif /* !CPMU_EVENT_FILTERING */

#if CPMU_16BIT_EVENTS
#define PMESR_PMC_WIDTH UINT64_C(16)
#define PMESR_PMC_MASK  ((uint64_t)UINT16_MAX)
#else // CPMU_16BIT_EVENTS
#define PMESR_PMC_WIDTH UINT64_C(8)
#define PMESR_PMC_MASK  ((uint64_t)UINT8_MAX)
#endif // !CPMU_16BIT_EVENTS

#define CFGWORD_EL0A32EN_MASK (0x10000)
#define CFGWORD_EL0A64EN_MASK (0x20000)
#define CFGWORD_EL1EN_MASK    (0x40000)
#define CFGWORD_EL3EN_MASK    (0x80000)

kpc_config_t
kpc_config_arch_process(kpc_config_t config)
{
	if (cpc_is_secure()) {
		config &= ~CFGWORD_EL1EN_MASK;
	}
	return config;
}

cpc_event_flags_t
kpc_config_arch_flags(kpc_config_t config)
{
	// The low 16 bits of a configuration word selects the event.
	// Bits 16-19 are mapped to exception level filters.

	cpc_event_flags_t flags = CPC_EF_NONE;
	// Assume no masks means all masks on.
	kpc_config_t all_on = CFGWORD_EL0A64EN_MASK | CFGWORD_EL0A32EN_MASK;
	if (!cpc_is_secure()) {
		all_on |= CFGWORD_EL1EN_MASK;
	}
	if ((config & (CFGWORD_EL0A64EN_MASK | CFGWORD_EL0A32EN_MASK |
	    CFGWORD_EL1EN_MASK)) == 0) {
		config |= all_on;
	}
	if (!(config & (CFGWORD_EL0A64EN_MASK | CFGWORD_EL0A32EN_MASK))) {
		flags |= CPC_EF_NO_USER;
	}
	if (!(config & CFGWORD_EL1EN_MASK)) {
		flags |= CPC_EF_NO_KERNEL;
	}
	return flags;
}

#pragma mark - Non-CPC

static uint32_t kpc_xread_sync;
static void
kpc_get_curcpu_counters_xcall(void *args)
{
	struct kpc_get_counters_remote *handler = args;

	assert(handler != NULL);
	assert(handler->buf != NULL);

	int offset = cpu_number() * handler->buf_stride;
	int r = kpc_get_curcpu_counters(handler->classes, NULL, &handler->buf[offset]);

	/* number of counters added by this CPU, needs to be atomic  */
	os_atomic_add(&(handler->nb_counters), r, relaxed);

	if (os_atomic_dec(&kpc_xread_sync, relaxed) == 0) {
		thread_wakeup((event_t) &kpc_xread_sync);
	}
}

int
kpc_get_all_cpus_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	assert(buf != NULL);

	int enabled = ml_set_interrupts_enabled(FALSE);

	if (curcpu) {
		*curcpu = cpu_number();
	}
	struct kpc_get_counters_remote hdl = {
		.classes = classes,
		.nb_counters = 0,
		.buf = buf,
		.buf_stride = kpc_get_counter_count(classes)
	};
	cpu_broadcast_xcall(&kpc_xread_sync, TRUE, kpc_get_curcpu_counters_xcall, &hdl);
	int offset = hdl.nb_counters;

	(void)ml_set_interrupts_enabled(enabled);

	return offset;
}

uint32_t
kpc_fixed_count(void)
{
	return KPC_ARM64_FIXED_COUNT;
}

uint32_t
kpc_configurable_count(void)
{
	return KPC_ARM64_CONFIGURABLE_COUNT;
}

uint32_t
kpc_fixed_config_count(void)
{
	return 0;
}

uint32_t
kpc_configurable_config_count(uint64_t pmc_mask)
{
	assert3u(kpc_popcount(pmc_mask), <=, kpc_configurable_count());
	return kpc_popcount(pmc_mask);
}

int
kpc_get_fixed_config(kpc_config_t *configv __unused)
{
	return 0;
}

uint64_t
kpc_fixed_max(void)
{
	return (1ULL << KPC_ARM64_COUNTER_WIDTH) - 1;
}

uint64_t
kpc_configurable_max(void)
{
	return (1ULL << KPC_ARM64_COUNTER_WIDTH) - 1;
}

int
kpc_get_configurable_config(kpc_config_t *configv, uint64_t pmc_mask)
{
	const uint32_t cfg_count = kpc_configurable_count();
	const uint32_t offset = kpc_fixed_count();

	assert(configv != NULL);

	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			*configv++ = _kpc_read_pmesr(i + offset);
		}
	}
	return 0;
}

uint32_t
kpc_get_classes(void)
{
	return KPC_CLASS_FIXED_MASK | KPC_CLASS_CONFIGURABLE_MASK |
	       KPC_CLASS_RAWPMU_MASK;
}

int
kpc_get_pmu_version(void)
{
	return KPC_PMU_ARM_APPLE;
}

#pragma mark - Direct CPMU Access

#define PMCR_PMC_8_9_OFFSET     (32)
#define PMCR_PMC_8_9_SHIFT(PMC) (((PMC) - 8) + PMCR_PMC_8_9_OFFSET)
#define PMCR_PMC_SHIFT(PMC)     (((PMC) <= 7) ? (PMC) : \
	                        PMCR_PMC_8_9_SHIFT(PMC))

#define PMESR_SHIFT(PMC, OFF)     ((PMESR_PMC_WIDTH) * ((PMC) - (OFF)))
#define PMESR_EVT_MASK(PMC, OFF)  (PMESR_PMC_MASK << PMESR_SHIFT(PMC, OFF))
#define PMESR_EVT_CLEAR(PMC, OFF) (~PMESR_EVT_MASK(PMC, OFF))

#define PMESR_EVT_DECODE(PMESR, PMC, OFF) \
	(((PMESR) >> PMESR_SHIFT(PMC, OFF)) & PMESR_PMC_MASK)
#define PMESR_EVT_ENCODE(EVT, PMC, OFF) \
	(((EVT) & PMESR_PMC_MASK) << PMESR_SHIFT(PMC, OFF))

#define PMCR1_EL0_A32_OFFSET (0)
#define PMCR1_EL0_A64_OFFSET (8)
#define S3_1_C15_C1_0_A64_OFFSET (16)
#define PMCR1_EL3_A64_OFFSET (24)

#define PMCR1_EL0_A32_SHIFT(PMC) (PMCR1_EL0_A32_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR1_EL0_A64_SHIFT(PMC) (PMCR1_EL0_A64_OFFSET + PMCR_PMC_SHIFT(PMC))
#define S3_1_C15_C1_0_A64_SHIFT(PMC) (S3_1_C15_C1_0_A64_OFFSET + PMCR_PMC_SHIFT(PMC))
#define PMCR1_EL3_A64_SHIFT(PMC) (PMCR1_EL0_A64_OFFSET + PMCR_PMC_SHIFT(PMC))

#define PMCR1_EL0_A32_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL0_A32_SHIFT(PMC))
#define PMCR1_EL0_A64_ENABLE_MASK(PMC) (UINT64_C(1) << PMCR1_EL0_A64_SHIFT(PMC))
#define S3_1_C15_C1_0_A64_ENABLE_MASK(PMC) (UINT64_C(1) << S3_1_C15_C1_0_A64_SHIFT(PMC))

#define SREG_READ(SR)     ({ uint64_t VAL; \
	                     __asm__ volatile("mrs %0, " SR : "=r"(VAL)); \
	                     VAL; })

/*
 * Configuration registers that can be controlled by RAWPMU:
 *
 * All: PMCR2-4, OPMAT0-1, OPMSK0-1.
 * Later: PM_MEMFLT_CTL23, PM_MEMFLT_CTL45, PMEFR2-9.
 */
#if CPMU_EVENT_FILTERING
#define RAWPMU_CONFIG_COUNT 17
#else /* CPMU_EVENT_FILTERING */
#define RAWPMU_CONFIG_COUNT 7
#endif /* !CPMU_EVENT_FILTERING */

uint32_t
kpc_rawpmu_config_count(void)
{
	return RAWPMU_CONFIG_COUNT;
}

int
kpc_get_rawpmu_config(kpc_config_t *configv)
{
	configv[0] = SREG_READ("S3_1_C15_C2_0");
	configv[1] = SREG_READ("S3_1_C15_C3_0");
	configv[2] = SREG_READ("S3_1_C15_C4_0");
	configv[3] = SREG_READ("S3_1_C15_C7_0");
	configv[4] = SREG_READ("S3_1_C15_C8_0");
	configv[5] = SREG_READ("S3_1_C15_C9_0");
	configv[6] = SREG_READ("S3_1_C15_C10_0");
#if CPMU_EVENT_FILTERING
	configv[7] = SREG_READ("PM_MEMFLT_CTL23_EL1");
	configv[8] = SREG_READ("PM_MEMFLT_CTL45_EL1");
	/*
	 * Use coproc addresses for PMEFR{2,9} instead of register names due to rdar://152681387
	 */
	configv[9] = SREG_READ("S3_2_C15_C2_1");
	configv[10] = SREG_READ("S3_2_C15_C3_1");
	configv[11] = SREG_READ("S3_2_C15_C4_1");
	configv[12] = SREG_READ("S3_2_C15_C5_1");
	configv[13] = SREG_READ("S3_2_C15_C6_1");
	configv[14] = SREG_READ("S3_2_C15_C7_1");
	configv[15] = SREG_READ("S3_2_C15_C8_1");
	configv[16] = SREG_READ("S3_2_C15_C9_1");
#endif /* CPMU_EVENT_FILTERING */
	return 0;
}

static uint64_t
_kpc_read_pmesr(uint32_t counter)
{
	uint64_t pmesr;

	switch (counter) {
	case 2:
	case 3:
	case 4:
	case 5:
		pmesr = PMESR_EVT_DECODE(SREG_READ("S3_1_C15_C5_0"), counter, 2);
		break;
	case 6:
	case 7:
#if KPC_ARM64_CONFIGURABLE_COUNT > 6
	case 8:
	case 9:
#endif // KPC_ARM64_CONFIGURABLE_COUNT > 6
		pmesr = PMESR_EVT_DECODE(SREG_READ("S3_1_C15_C6_0"), counter, 6);
		break;
	default:
		pmesr = 0;
		break;
	}

	kpc_config_t config = pmesr;

	uint64_t pmcr1 = SREG_READ("S3_1_C15_C1_0");

	if (pmcr1 & PMCR1_EL0_A32_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL0A32EN_MASK;
	}
	if (pmcr1 & PMCR1_EL0_A64_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL0A64EN_MASK;
	}
	if (pmcr1 & S3_1_C15_C1_0_A64_ENABLE_MASK(counter)) {
		config |= CFGWORD_EL1EN_MASK | CFGWORD_EL3EN_MASK;
	}

	return config;
}
