/*
 * Copyright (c) 2017-2020 Apple Inc. All rights reserved.
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
#include <arm/machine_routines.h>
#include <arm64/monotonic.h>
#include <kern/assert.h>
#include <kern/cpc.h>
#include <kern/debug.h> /* panic */
#include <kern/kpc.h>
#include <kern/monotonic.h>
#include <machine/atomic.h>
#include <machine/limits.h> /* CHAR_BIT */
#include <os/overflow.h>
#include <pexpert/arm64/board_config.h>
#include <pexpert/device_tree.h> /* SecureDTFindEntry */
#include <pexpert/pexpert.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/monotonic.h>

void uncore_reset(void);

/*
 * Ensure that control registers read back what was written under MACH_ASSERT
 * kernels.
 *
 * A static inline function cannot be used due to passing the register through
 * the builtin -- it requires a constant string as its first argument, since
 * MSRs registers are encoded as an immediate in the instruction.
 */
#if MACH_ASSERT
#define CTRL_REG_SET(reg, val) do { \
	__builtin_arm_wsr64((reg), (val)); \
	uint64_t __check_reg = __builtin_arm_rsr64((reg)); \
	if (__check_reg != (val)) { \
	        panic("value written to %s was not read back (wrote 0x%llx, read 0x%llx)", \
	            #reg, (val), __check_reg); \
	} \
} while (0)
#else /* MACH_ASSERT */
#define CTRL_REG_SET(reg, val) __builtin_arm_wsr64((reg), (val))
#endif /* MACH_ASSERT */

#pragma mark uncore performance monitor

#if HAS_UPMU

static bool mt_uncore_initted = false;

static bool mt_uncore_suspended_cpd = false;

/*
 * Uncore Performance Monitor
 *
 * Uncore performance monitors provide event-counting for the last-level caches
 * (LLCs), SME engine, and other shared or non-CPU-complex systems.  Each
 * cluster has its own uncore performance monitor.
 */

#define MAX_NMONITORS MAX_CPU_CLUSTERS
static uintptr_t cpm_impl[MAX_NMONITORS] = {};
static unsigned int max_upmcs[MAX_NMONITORS] = {};

#define UPMSR_OVF_POS 2
#define UPMSR_OVF(R, CTR) ((R) >> ((CTR) + UPMSR_OVF_POS) & 0x1)
#define UPMSR_OVF_MASK    (((UINT64_C(1) << UPMU_PMC_COUNT) - 1) << UPMSR_OVF_POS)

#if UPMU_12BIT_EVENTS
#define UPMU_ESR_BITS 12
#define UPMU_ESR_WIDTH 16
#else /* UPMU_12BIT_EVENTS */
#define UPMU_ESR_BITS 8
#define UPMU_ESR_WIDTH 8
#endif /* !UPMU_12BIT_EVENTS */

#define UPMU_ESR_EVENT_MASK ((1ULL << UPMU_ESR_BITS) - 1)

#define UPMPCM_CORE(ID) (UINT64_C(1) << (ID))

#if UPMU_64BIT_PMCS
#define UPMC_WIDTH (63)
#else // UPMU_64BIT_PMCS
#define UPMC_WIDTH (47)
#endif // !UPMU_64BIT_PMCS

/*
 * The uncore_pmi_mask is a bitmask of CPUs that receive uncore PMIs.  It's
 * initialized by uncore_init and controllable by the uncore_pmi_mask boot-arg.
 */
static int32_t uncore_pmi_mask = 0;

/*
 * The uncore_active_ctrs is a bitmask of uncore counters that are currently
 * requested.
 */
static uint32_t uncore_active_ctrs = 0;
static_assert(sizeof(uncore_active_ctrs) * CHAR_BIT >= UPMU_PMC_COUNT,
    "counter mask should fit the full range of counters");

#if UPMU_9BIT_SELECTORS
static uint16_t uncore_selectors_bit9 = 0;
#endif /* UPMU_9BIT_SELECTORS */

static uint64_t
_upmcr0_value(void)
{
#if UPMU_9BIT_SELECTORS
	return (uint64_t)uncore_selectors_bit9 << 36 | (uint64_t)uncore_active_ctrs;
#else /* UPMU_9BIT_SELECTORS */
	return uncore_active_ctrs;
#endif /* !UPMU_9BIT_SELECTORS */
}

/*
 * mt_uncore_enabled is true when any uncore counters are active.
 */
bool mt_uncore_enabled = false;

/*
 * The uncore_events are the event configurations for each uncore counter -- as
 * a union to make it easy to program the hardware registers.
 */
static struct uncore_config {
	uint64_t uc_event_regs[(UPMU_PMC_COUNT * (UPMU_ESR_BITS + 4)) / 64];
	union {
		uint16_t uccm_masks[UPMU_PMC_COUNT];
		uint64_t uccm_regs[UPMU_PMC_COUNT / 4];
	} uc_cpu_masks[MAX_NMONITORS];
} uncore_config;

static struct uncore_monitor {
	/*
	 * The last snapshot of each of the hardware counter values.
	 */
	uint64_t um_snaps[UPMU_PMC_COUNT];

	/*
	 * The accumulated counts for each counter.
	 */
	uint64_t um_counts[UPMU_PMC_COUNT];

	/*
	 * Protects accessing the hardware registers and fields in this structure.
	 */
	lck_spin_t um_lock;

	/*
	 * Whether this monitor needs its registers restored after wake.
	 */
	bool um_sleeping;

#if MACH_ASSERT
	/*
	 * Save whether this monitor has been read since sleeping.
	 */
	bool um_read_since_sleep;
#endif /* MACH_ASSERT */
} uncore_monitors[MAX_NMONITORS];

/*
 * Each uncore unit has its own monitor, corresponding to the memory hierarchy
 * of the LLCs.
 */
static unsigned int
uncore_nmonitors(void)
{
	return ml_get_topology_info()->num_clusters;
}

static unsigned int
uncmon_get_curid(void)
{
	return cpu_cluster_id();
}

/*
 * Per-monitor locks are required to prevent races with the PMI handlers, not
 * from other CPUs that are configuring (those are serialized with monotonic's
 * per-device lock).
 */

static int
uncmon_lock(struct uncore_monitor *mon)
{
	int intrs_en = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(&mon->um_lock);
	return intrs_en;
}

static void
uncmon_unlock(struct uncore_monitor *mon, int intrs_en)
{
	lck_spin_unlock(&mon->um_lock);
	(void)ml_set_interrupts_enabled(intrs_en);
}

/*
 * Helper functions for accessing the hardware -- these require the monitor be
 * locked to prevent other CPUs' PMI handlers from making local modifications
 * or updating the counts.
 */

#define UPMCR0_INTEN_POS 20
#define UPMCR0_INTGEN_POS 16
enum {
	UPMCR0_INTGEN_OFF = 0,
	/* fast PMIs are only supported on core CPMU */
	UPMCR0_INTGEN_AIC = 2,
	UPMCR0_INTGEN_HALT = 3,
	UPMCR0_INTGEN_FIQ = 4,
};
/* always enable interrupts for all counters */
#define UPMCR0_INTEN (((1ULL << UPMU_PMC_COUNT) - 1) << UPMCR0_INTEN_POS)
/* route uncore PMIs through the FIQ path */
#define UPMCR0_INIT (UPMCR0_INTEN | (UPMCR0_INTGEN_FIQ << UPMCR0_INTGEN_POS))

/*
 * Turn counting on for counters set in the `enctrmask` and off, otherwise.
 */
static inline void
uncmon_set_counting_locked(uint64_t enctrmask)
{
	/*
	 * UPMCR0 controls which counters are enabled and how interrupts are generated
	 * for overflows.
	 */
	__builtin_arm_wsr64("S3_7_C15_C0_4", UPMCR0_INIT | enctrmask);
}

/*
 * The uncore performance monitoring counters (UPMCs) are 48/64-bits wide.  The
 * high bit is an overflow bit, triggering a PMI, providing 47/63 usable bits.
 */

#define UPMC_MAX ((UINT64_C(1) << UPMC_WIDTH) - 1)

/*
 * The `__builtin_arm_{r,w}sr` functions require constant strings, since the
 * MSR/MRS instructions encode the registers as immediates.  Otherwise, this
 * would be indexing into an array of strings.
 */

#define UPMC_0_7(X, A) X(0, A); X(1, A); X(2, A); X(3, A); X(4, A); X(5, A); \
	        X(6, A); X(7, A)
#if UPMU_PMC_COUNT <= 8
#define UPMC_ALL(X, A) UPMC_0_7(X, A)
#else /* UPMU_PMC_COUNT <= 8 */
#define UPMC_8_15(X, A) X(8, A); X(9, A); X(10, A); X(11, A); X(12, A); \
	        X(13, A); X(14, A); X(15, A)
#define UPMC_ALL(X, A) UPMC_0_7(X, A); UPMC_8_15(X, A)
#endif /* UPMU_PMC_COUNT > 8 */

static void
_broadcast_block_trampoline(void *blk)
{
	void (^cb)(unsigned int) = blk;
	const ml_topology_info_t *topo = ml_get_topology_info();
	unsigned int cpu = cpu_number();
	unsigned int cluster = topo->cpus[cpu].cluster_id;
	if (topo->clusters[cluster].first_cpu_id == cpu) {
		cb(topo->cpus[cpu].cluster_id);
	}
}

static void
_broadcast_each_cluster(void (^cb)(unsigned int cluster_id))
{
	cpu_broadcast_xcall_simple(TRUE, _broadcast_block_trampoline, cb);
}

static inline uint64_t
uncmon_read_counter_locked(unsigned int ctr)
{
	assert(ctr < UPMU_PMC_COUNT);
	switch (ctr) {
	case 0:
		return __builtin_arm_rsr64("S3_7_C15_C7_4");
	case 1:
		return __builtin_arm_rsr64("S3_7_C15_C8_4");
	case 2:
		return __builtin_arm_rsr64("S3_7_C15_C9_4");
	case 3:
		return __builtin_arm_rsr64("S3_7_C15_C10_4");
	case 4:
		return __builtin_arm_rsr64("S3_7_C15_C11_4");
	case 5:
		return __builtin_arm_rsr64("S3_7_C15_C12_4");
	case 6:
		return __builtin_arm_rsr64("S3_7_C15_C13_4");
	case 7:
		return __builtin_arm_rsr64("S3_7_C15_C14_4");
#if UPMU_PMC_COUNT > 8
	case 8:
		return __builtin_arm_rsr64("S3_7_C15_C0_5");
	case 9:
		return __builtin_arm_rsr64("S3_7_C15_C1_5");
	case 10:
		return __builtin_arm_rsr64("S3_7_C15_C2_5");
	case 11:
		return __builtin_arm_rsr64("S3_7_C15_C3_5");
	case 12:
		return __builtin_arm_rsr64("S3_7_C15_C4_5");
	case 13:
		return __builtin_arm_rsr64("S3_7_C15_C5_5");
	case 14:
		return __builtin_arm_rsr64("S3_7_C15_C6_5");
	case 15:
		return __builtin_arm_rsr64("S3_7_C15_C7_5");
#if UPMU_PMC_COUNT > 16
	/*
	 * Use coproc addresses instead of register names due to rdar://152681387
	 */
	case 16:
		return __builtin_arm_rsr64("S3_7_C15_C12_7");
	case 17:
		return __builtin_arm_rsr64("S3_7_C15_C13_0");
	case 18:
		return __builtin_arm_rsr64("S3_7_C15_C13_1");
	case 19:
		return __builtin_arm_rsr64("S3_7_C15_C13_7");
	case 20:
		return __builtin_arm_rsr64("S3_7_C15_C14_7");
	case 21:
		return __builtin_arm_rsr64("S3_7_C15_C15_7");
	case 22:
		return __builtin_arm_rsr64("S3_7_C15_C10_7");
	case 23:
		return __builtin_arm_rsr64("S3_7_C15_C10_1");
#endif /* UPMU_PMC_COUNT > 16 */
#endif /* UPMU_PMC_COUNT > 8 */
	default:
		panic("monotonic: invalid counter read %u", ctr);
		__builtin_unreachable();
	}
}

static inline void
uncmon_write_counter_locked(unsigned int ctr, uint64_t count)
{
	assert(count < UPMC_MAX);
	assert(ctr < UPMU_PMC_COUNT);
	switch (ctr) {
	case 0:
		return __builtin_arm_wsr64("S3_7_C15_C7_4", count);
	case 1:
		return __builtin_arm_wsr64("S3_7_C15_C8_4", count);
	case 2:
		return __builtin_arm_wsr64("S3_7_C15_C9_4", count);
	case 3:
		return __builtin_arm_wsr64("S3_7_C15_C10_4", count);
	case 4:
		return __builtin_arm_wsr64("S3_7_C15_C11_4", count);
	case 5:
		return __builtin_arm_wsr64("S3_7_C15_C12_4", count);
	case 6:
		return __builtin_arm_wsr64("S3_7_C15_C13_4", count);
	case 7:
		return __builtin_arm_wsr64("S3_7_C15_C14_4", count);
#if UPMU_PMC_COUNT > 8
	case 8:
		return __builtin_arm_wsr64("S3_7_C15_C0_5", count);
	case 9:
		return __builtin_arm_wsr64("S3_7_C15_C1_5", count);
	case 10:
		return __builtin_arm_wsr64("S3_7_C15_C2_5", count);
	case 11:
		return __builtin_arm_wsr64("S3_7_C15_C3_5", count);
	case 12:
		return __builtin_arm_wsr64("S3_7_C15_C4_5", count);
	case 13:
		return __builtin_arm_wsr64("S3_7_C15_C5_5", count);
	case 14:
		return __builtin_arm_wsr64("S3_7_C15_C6_5", count);
	case 15:
		return __builtin_arm_wsr64("S3_7_C15_C7_5", count);
#if UPMU_PMC_COUNT > 16
	/*
	 * Use coproc addresses instead of register names due to rdar://152681387
	 */
	case 16:
		return __builtin_arm_wsr64("S3_7_C15_C12_7", count);
	case 17:
		return __builtin_arm_wsr64("S3_7_C15_C13_0", count);
	case 18:
		return __builtin_arm_wsr64("S3_7_C15_C13_1", count);
	case 19:
		return __builtin_arm_wsr64("S3_7_C15_C13_7", count);
	case 20:
		return __builtin_arm_wsr64("S3_7_C15_C14_7", count);
	case 21:
		return __builtin_arm_wsr64("S3_7_C15_C15_7", count);
	case 22:
		return __builtin_arm_wsr64("S3_7_C15_C10_7", count);
	case 23:
		return __builtin_arm_wsr64("S3_7_C15_C10_1", count);
#endif /* UPMU_PMC_COUNT > 16 */
#endif /* UPMU_PMC_COUNT > 8 */
	default:
		panic("monotonic: invalid counter write %u", ctr);
	}
}

static inline void
uncmon_update_locked(unsigned int monid, unsigned int ctr)
{
	struct uncore_monitor *mon = &uncore_monitors[monid];
	if (!mon->um_sleeping) {
		uint64_t snap = 0;
		snap = uncmon_read_counter_locked(ctr);
		if (snap < mon->um_snaps[ctr]) {
#if MACH_ASSERT
			panic("monotonic: UPMC%d on UPMU %d went backwards from "
			    "%llx to %llx%s"
			    , ctr,
			    monid, mon->um_snaps[ctr], snap,
			    mon->um_read_since_sleep ? "" : ", first read since sleep"
			    );
#else /* MACH_ASSERT */
			snap = mon->um_snaps[ctr];
#endif /* !MACH_ASSERT */
		}
		mon->um_counts[ctr] += snap - mon->um_snaps[ctr];
		mon->um_snaps[ctr] = snap;
	}
}

static inline void
uncmon_program_events_locked(unsigned int monid)
{
	/*
	 * UPMESR[0123] is the event selection register that determines which event
	 * a counter will count.
	 */
	CTRL_REG_SET("S3_7_C15_C1_4", uncore_config.uc_event_regs[0]);

#if UPMU_PMC_COUNT > 8
	CTRL_REG_SET("S3_7_C15_C11_5", uncore_config.uc_event_regs[1]);
#if UPMU_PMC_COUNT > 16
	/*
	 * Use coproc addresses instead of register names due to rdar://152681387
	 *
	 * Avoid `CTRL_REG_SET` as some of these are write-ignored on SoCs which
	 * feature less than 6 CPUs per cluster.
	 */
	__builtin_arm_wsr64("S3_7_C15_C11_7", uncore_config.uc_event_regs[2]);
	__builtin_arm_wsr64("S3_7_C15_C12_0", uncore_config.uc_event_regs[3]);
	__builtin_arm_wsr64("S3_7_C15_C12_1", uncore_config.uc_event_regs[4]);
	__builtin_arm_wsr64("S3_7_C15_C12_5", uncore_config.uc_event_regs[5]);
#endif /* UPMU_PMC_COUNT > 16 */
#endif /* UPMU_PMC_COUNT > 8 */

	/*
	 * UPMECM[012345] are the event core masks for each counter -- whether or
	 * not that counter counts events generated by an agent.  These are set to
	 * all ones so the uncore counters count events from all cores.
	 *
	 * The bits are based off the start of the cluster -- e.g. even if a core
	 * has a CPU ID of 4, it might be the first CPU in a cluster.
	 */
	CTRL_REG_SET("S3_7_C15_C3_4",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[0]);
	CTRL_REG_SET("S3_7_C15_C4_4",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[1]);

#if UPMU_PMC_COUNT > 8
	CTRL_REG_SET("S3_7_C15_C8_5",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[2]);
	CTRL_REG_SET("S3_7_C15_C9_5",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[3]);
#if UPMU_PMC_COUNT > 16
	/*
	 * Use coproc addresses instead of register names due to rdar://152681387
	 *
	 * Avoid `CTRL_REG_SET` as some of these are write-ignored on SoCs which
	 * feature less than 6 CPUs per cluster.
	 */
	__builtin_arm_wsr64("S3_6_C11_C12_6",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[4]);
	__builtin_arm_wsr64("S3_6_C11_C12_7",
	    uncore_config.uc_cpu_masks[monid].uccm_regs[5]);
#endif /* UPMU_PMC_COUNT > 16 */
#endif /* UPMU_PMC_COUNT > 8 */
}

static void
uncmon_clear_int_locked(void)
{
	__builtin_arm_wsr64("S3_7_C15_C6_4", 0);
}

/*
 * Get the PMI mask for the provided `monid` -- that is, the bitmap of CPUs
 * that should be sent PMIs for a particular monitor.
 */
static uint64_t
uncmon_get_pmi_mask(unsigned int monid)
{
	uint64_t pmi_mask = uncore_pmi_mask;

	const ml_topology_info_t *topology = ml_get_topology_info();
	pmi_mask &= topology->clusters[monid].cpu_mask;

	return pmi_mask;
}

/*
 * Initialization routines for the uncore counters.
 */

static void
uncmon_init_locked(unsigned int monid)
{
	/*
	 * UPMPCM defines the PMI core mask for the UPMCs -- which cores should
	 * receive interrupts on overflow.
	 */
	CTRL_REG_SET("S3_7_C15_C5_4", uncmon_get_pmi_mask(monid));
	uncmon_set_counting_locked(mt_uncore_enabled ? _upmcr0_value() : 0);
}

static uintptr_t acc_impl[MAX_NMONITORS] = {};

/*
 * Initialize the uncore device for monotonic.
 */
static int
uncore_init(__unused mt_device_t dev)
{
#if HAS_UPMU
	assert(MT_NDEVS > 0);
	mt_devices[MT_NDEVS - 1].mtd_nmonitors = (uint8_t)uncore_nmonitors();
#endif

#if DEVELOPMENT || DEBUG
	/*
	 * Development and debug kernels observe the `uncore_pmi_mask` boot-arg,
	 * allowing PMIs to be routed to the CPUs present in the supplied bitmap.
	 * Do some sanity checks on the value provided.
	 */
	bool parsed_arg = PE_parse_boot_argn("uncore_pmi_mask", &uncore_pmi_mask,
	    sizeof(uncore_pmi_mask));
	if (parsed_arg) {
		if (__builtin_popcount(uncore_pmi_mask) != (int)uncore_nmonitors()) {
			panic("monotonic: invalid uncore PMI mask 0x%x", uncore_pmi_mask);
		}
		for (unsigned int i = 0; i < uncore_nmonitors(); i++) {
			if (__builtin_popcountll(uncmon_get_pmi_mask(i)) != 1) {
				panic("monotonic: invalid uncore PMI CPU for cluster %d in mask 0x%x",
				    i, uncore_pmi_mask);
			}
		}
	} else
#endif /* DEVELOPMENT || DEBUG */
	{
		/* arbitrarily route to core 0 in each cluster */
		uncore_pmi_mask |= 1;
	}
	assert(uncore_pmi_mask != 0);

	const ml_topology_info_t *topology = ml_get_topology_info();
	for (unsigned int monid = 0; monid < uncore_nmonitors(); monid++) {
		ml_topology_cluster_t *cluster = &topology->clusters[monid];
		cpm_impl[monid] = (uintptr_t)cluster->cpm_IMPL_regs;
		acc_impl[monid] = (uintptr_t)cluster->acc_IMPL_regs;
#if UPMU_PMC_COUNT > 16
		/*
		 * Even on systems with 24 possible UPMCs, the E clusters are still limited
		 * to 16 UPMCs.
		 *
		 * Only allow programming up to that amount, as further UPMESRs are invalid
		 * and generate aborts on PIO access.
		 */
		max_upmcs[monid] = cluster->cluster_type & CLUSTER_TYPE_E ? 16 : UPMU_PMC_COUNT;
#else /* UPMU_PMC_COUNT */
		max_upmcs[monid] = UPMU_PMC_COUNT;
#endif /* UPMU_PMC_COUNT */
		assert(cpm_impl[monid] != 0 && acc_impl[monid] != 0);

		struct uncore_monitor *mon = &uncore_monitors[monid];
		lck_spin_init(&mon->um_lock, &mt_lock_grp, LCK_ATTR_NULL);
	}

	mt_uncore_initted = true;

	return 0;
}

/*
 * Support for monotonic's mtd_read function.
 */

static void
uncmon_read_all_counters(unsigned int monid, uint64_t ctr_mask, uint64_t *counts)
{
	struct uncore_monitor *mon = &uncore_monitors[monid];

	int intrs_en = uncmon_lock(mon);

	for (unsigned int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
		if (ctr_mask & (1ULL << ctr)) {
			uncmon_update_locked(monid, ctr);
			counts[ctr] = mon->um_counts[ctr];
		}
	}
#if MACH_ASSERT
	mon->um_read_since_sleep = true;
#endif /* MACH_ASSERT */

	uncmon_unlock(mon, intrs_en);
}

/*
 * Read all monitor's counters.
 */
static int
uncore_read(uint64_t ctr_mask, uint64_t *counts_out)
{
	assert(ctr_mask != 0);
	assert(counts_out != NULL);

	if (!uncore_active_ctrs) {
		return EPWROFF;
	}
	if (ctr_mask & ~uncore_active_ctrs) {
		return EINVAL;
	}

	_broadcast_each_cluster(^(unsigned int cluster_id) {
		/*
		 * Find this monitor's starting offset into the `counts_out` array.
		 */
		uint64_t *counts = counts_out + (UPMU_PMC_COUNT * cluster_id);
		uncmon_read_all_counters(cluster_id, ctr_mask, counts);
	});

	return 0;
}

/*
 * Support for monotonic's mtd_add function.
 */

/*
 * Add an event to the current uncore configuration.  This doesn't take effect
 * until the counters are enabled again, so there's no need to involve the
 * monitors.
 */
static int
uncore_add(struct monotonic_config *config, uint32_t *ctr_out)
{
	if (mt_uncore_enabled) {
		return EBUSY;
	}

	uint16_t selector = (uint16_t)config->event;
	uint32_t available = ~uncore_active_ctrs & config->allowed_ctr_mask;

	if (available == 0) {
		return ENOSPC;
	}

	cpc_event_t found_event = cpc_find_event(CPC_HW_UPMU, selector);
	if (found_event == CPC_EVENT_INVALID) {
		return EPERM;
	}

	uint32_t valid_ctrs = (UINT32_C(1) << UPMU_PMC_COUNT) - 1;
	if ((available & valid_ctrs) == 0) {
		return E2BIG;
	}
	/*
	 * Clear the UPMCs the first time an event is added.
	 */
	if (uncore_active_ctrs == 0) {
		/*
		 * Suspend powerdown until the next reset.
		 */
		assert(!mt_uncore_suspended_cpd);
		suspend_cluster_powerdown();
		mt_uncore_suspended_cpd = true;

		_broadcast_each_cluster(^(unsigned int cluster_id) {
			struct uncore_monitor *mon = &uncore_monitors[cluster_id];
			int intrs_en = uncmon_lock(mon);
			if (!mon->um_sleeping) {
			        for (unsigned int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
			                uncmon_write_counter_locked(ctr, 0);
				}
			}
			memset(&mon->um_snaps, 0, sizeof(mon->um_snaps));
			memset(&mon->um_counts, 0, sizeof(mon->um_counts));
			uncmon_unlock(mon, intrs_en);
		});
	}

	uint32_t ctr = __builtin_ffsll(available) - 1;
	assert3u(ctr, <, UPMU_PMC_COUNT);

	uncore_active_ctrs |= UINT64_C(1) << ctr;
	uint32_t i = (ctr * UPMU_ESR_WIDTH) / (sizeof(uncore_config.uc_event_regs[0]) * CHAR_BIT);
	uint32_t bits_pos = (ctr * UPMU_ESR_WIDTH) % (sizeof(uncore_config.uc_event_regs[0]) * CHAR_BIT);
	uint64_t bits = (selector & UPMU_ESR_EVENT_MASK) << bits_pos;
	uncore_config.uc_event_regs[i] &= ~(UPMU_ESR_EVENT_MASK << bits_pos);
	uncore_config.uc_event_regs[i] |= bits;
#if UPMU_9BIT_SELECTORS
	uncore_selectors_bit9 &= ~(1 << ctr);
	uncore_selectors_bit9 |= ((selector >> 8) & 1) << ctr;
#endif /* UPMU_9BIT_SELECTORS */
	uint64_t cpu_mask = UINT64_MAX;
	if (config->cpu_mask != 0) {
		cpu_mask = config->cpu_mask;
	}
	const ml_topology_info_t *topology = ml_get_topology_info();
	for (i = 0; i < uncore_nmonitors(); i++) {
		const unsigned int shift = topology->clusters[i].first_cpu_id;
		uncore_config.uc_cpu_masks[i].uccm_masks[ctr] = (uint16_t)(cpu_mask >> shift);
	}

	*ctr_out = ctr;
	return 0;
}

/*
 * Support for monotonic's mtd_reset function.
 */

/*
 * Reset all configuration and disable the counters if they're currently
 * counting.
 */
void
uncore_reset(void)
{
	mt_uncore_enabled = false;

	if (!mt_uncore_suspended_cpd) {
		/* If we haven't already suspended CPD, we need to do so now to ensure we can issue remote reads
		 * to every cluster. */
		suspend_cluster_powerdown();
		mt_uncore_suspended_cpd = true;
	}

	if (cpc_sharing_is_exclusive()) {
		_broadcast_each_cluster(^(unsigned int cluster_id) {
			struct uncore_monitor *mon = &uncore_monitors[cluster_id];

			int intrs_en = uncmon_lock(mon);
			uncmon_set_counting_locked(0);

			for (int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
			        if (uncore_active_ctrs & (1U << ctr)) {
			                uncmon_write_counter_locked(ctr, 0);
				}
			}

			memset(&mon->um_snaps, 0, sizeof(mon->um_snaps));
			memset(&mon->um_counts, 0, sizeof(mon->um_counts));
			uncmon_clear_int_locked();

			uncmon_unlock(mon, intrs_en);
		});
	}

	uncore_active_ctrs = 0;
#if UPMU_9BIT_SELECTORS
	uncore_selectors_bit9 = 0;
#endif /* UPMU_9BIT_SELECTORS */
	memset(&uncore_config, 0, sizeof(uncore_config));

	if (cpc_sharing_is_exclusive()) {
		_broadcast_each_cluster(^(unsigned int cluster_id) {
			struct uncore_monitor *mon = &uncore_monitors[cluster_id];
			int intrs_en = uncmon_lock(mon);
			uncmon_program_events_locked(cluster_id);
			uncmon_unlock(mon, intrs_en);
		});
	}

	/*
	 * Catch any sleeping monitors and ensure their counts are zeroed out
	 * when they wake.
	 */
	for (unsigned int i = 0; i < uncore_nmonitors(); i++) {
		struct uncore_monitor *mon = &uncore_monitors[i];
		int intrs_en = uncmon_lock(mon);
		if (mon->um_sleeping) {
			memset(&mon->um_snaps, 0, sizeof(mon->um_snaps));
			memset(&mon->um_counts, 0, sizeof(mon->um_counts));
		}
		uncmon_unlock(mon, intrs_en);
	}

	/* After reset, no counters should be active, so we can allow powerdown again */
	if (mt_uncore_suspended_cpd) {
		resume_cluster_powerdown();
		mt_uncore_suspended_cpd = false;
	}
}

/*
 * Support for monotonic's mtd_enable function.
 */

static void
uncore_set_enabled(bool enable)
{
	mt_uncore_enabled = enable;

	_broadcast_each_cluster(^(unsigned int cluster_id) {
		struct uncore_monitor *mon = &uncore_monitors[cluster_id];
		int intrs_en = uncmon_lock(mon);
		if (enable) {
		        uncmon_init_locked(cluster_id);
		        uncmon_program_events_locked(cluster_id);
		        uncmon_set_counting_locked(_upmcr0_value());
		} else {
		        uncmon_set_counting_locked(0);
		}
		uncmon_unlock(mon, intrs_en);
	});
}

/*
 * Hooks in the machine layer.
 */

void
mt_uncore_pmi(uint64_t upmsr)
{
	/*
	 * Determine which counters overflowed.
	 */
	uint64_t disable_ctr_mask = (upmsr & UPMSR_OVF_MASK) >> UPMSR_OVF_POS;
	/* should not receive interrupts from inactive counters */
	assert(!(disable_ctr_mask & ~uncore_active_ctrs));

	if (uncore_active_ctrs == 0) {
		return;
	}

	unsigned int monid = uncmon_get_curid();
	struct uncore_monitor *mon = &uncore_monitors[monid];

	int intrs_en = uncmon_lock(mon);

	/*
	 * Disable any counters that overflowed.
	 */
	uncmon_set_counting_locked(uncore_active_ctrs & ~disable_ctr_mask);

	/*
	 * With the overflowing counters disabled, capture their counts and reset
	 * the UPMCs and their snapshots to 0.
	 */
	for (unsigned int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
		if (UPMSR_OVF(upmsr, ctr)) {
			uncmon_update_locked(monid, ctr);
			mon->um_snaps[ctr] = 0;
			uncmon_write_counter_locked(ctr, 0);
		}
	}

	/*
	 * Acknowledge the interrupt, now that any overflowed PMCs have been reset.
	 */
	uncmon_clear_int_locked();

	/*
	 * Re-enable all active counters.
	 */
	uncmon_set_counting_locked(uncore_active_ctrs);

	uncmon_unlock(mon, intrs_en);
}

static void
uncore_save(void)
{
	if (!uncore_active_ctrs) {
		return;
	}

	_broadcast_each_cluster(^(unsigned int cluster_id) {
		struct uncore_monitor *mon = &uncore_monitors[cluster_id];
		int intrs_en = uncmon_lock(mon);

		if (mt_uncore_enabled) {
		        uncmon_set_counting_locked(0);
		}

		for (unsigned int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
		        if (uncore_active_ctrs & (1U << ctr)) {
		                uncmon_update_locked(cluster_id, ctr);
		                mon->um_snaps[ctr] = 0;
		                uncmon_write_counter_locked(ctr, 0);
			}
		}

		mon->um_sleeping = true;
		uncmon_unlock(mon, intrs_en);
	});
}

static void
uncore_restore(void)
{
	if (!uncore_active_ctrs) {
		return;
	}
	/* Ensure interrupts disabled before reading uncmon_get_curid */
	bool intr = ml_set_interrupts_enabled(false);
	unsigned int curmonid = uncmon_get_curid();

	struct uncore_monitor *mon = &uncore_monitors[curmonid];
	int intrs_en = uncmon_lock(mon);
	if (!mon->um_sleeping) {
		goto out;
	}

	for (unsigned int ctr = 0; ctr < UPMU_PMC_COUNT; ctr++) {
		if (uncore_active_ctrs & (1U << ctr)) {
			uncmon_write_counter_locked(ctr, mon->um_snaps[ctr]);
		}
	}
	uncmon_program_events_locked(curmonid);
	uncmon_init_locked(curmonid);
	mon->um_sleeping = false;
#if MACH_ASSERT
	mon->um_read_since_sleep = false;
#endif /* MACH_ASSERT */

out:
	uncmon_unlock(mon, intrs_en);
	ml_set_interrupts_enabled(intr);
}

#endif /* HAS_UPMU */

#pragma mark common hooks

void
mt_sleep(void)
{
#if HAS_UPMU
	uncore_save();
#endif /* HAS_UPMU */
}

void
mt_wake_per_core(void)
{
#if HAS_UPMU
	if (mt_uncore_initted) {
		uncore_restore();
	}
#endif /* HAS_UPMU */
}

#pragma mark dev nodes

struct mt_device mt_devices[] = {
#if HAS_UPMU
	[0] = {
		.mtd_name = "uncore",
		.mtd_init = uncore_init,
		.mtd_add = uncore_add,
		.mtd_reset = uncore_reset,
		.mtd_enable = uncore_set_enabled,
		.mtd_read = uncore_read,

		.mtd_ncounters = UPMU_PMC_COUNT,
	}
#endif /* HAS_UPMU */
};

static_assert(
	(sizeof(mt_devices) / sizeof(mt_devices[0])) == MT_NDEVS,
	"MT_NDEVS macro should be same as the length of mt_devices");
