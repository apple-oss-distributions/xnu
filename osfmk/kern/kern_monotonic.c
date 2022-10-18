/*
 * Copyright (c) 2017 Apple Inc. All rights reserved.
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

#include <kern/assert.h>
#include <kern/kpc.h>
#include <kern/monotonic.h>
#include <kern/thread.h>
#include <machine/atomic.h>
#include <machine/monotonic.h>
#include <mach/mach_traps.h>
#include <stdatomic.h>
#include <sys/errno.h>

bool mt_debug = false;
_Atomic uint64_t mt_pmis = 0;
_Atomic uint64_t mt_retrograde = 0;

#define MT_KDBG_INSTRS_CYCLES(CODE) \
	KDBG_EVENTID(DBG_MONOTONIC, DBG_MT_INSTRS_CYCLES, CODE)

static void mt_fixed_counts_internal(uint64_t *counts, uint64_t *counts_since);

uint64_t
mt_mtc_update_count(struct mt_cpu *mtc, unsigned int ctr)
{
	uint64_t snap = mt_core_snap(ctr);
	if (snap < mtc->mtc_snaps[ctr]) {
		if (mt_debug) {
			kprintf("monotonic: cpu %d: thread %#llx: "
			    "retrograde counter %u value: %llu, last read = %llu\n",
			    cpu_number(), thread_tid(current_thread()), ctr, snap,
			    mtc->mtc_snaps[ctr]);
		}
		(void)atomic_fetch_add_explicit(&mt_retrograde, 1,
		    memory_order_relaxed);
		mtc->mtc_snaps[ctr] = snap;
		return 0;
	}

	uint64_t count = snap - mtc->mtc_snaps[ctr];
	mtc->mtc_snaps[ctr] = snap;

	return count;
}

uint64_t
mt_cpu_update_count(cpu_data_t *cpu, unsigned int ctr)
{
	return mt_mtc_update_count(&cpu->cpu_monotonic, ctr);
}

static void
mt_fixed_counts_internal(uint64_t *counts, uint64_t *counts_since)
{
	assert(ml_get_interrupts_enabled() == FALSE);

	struct mt_cpu *mtc = mt_cur_cpu();
	assert(mtc != NULL);

	mt_mtc_update_fixed_counts(mtc, counts, counts_since);
}

void
mt_mtc_update_fixed_counts(struct mt_cpu *mtc, uint64_t *counts,
    uint64_t *counts_since)
{
	if (!mt_core_supported) {
		return;
	}

	for (int i = 0; i < (int) kpc_fixed_count(); i++) {
		uint64_t last_delta;
		uint64_t count;

		last_delta = mt_mtc_update_count(mtc, i);
		count = mtc->mtc_counts[i] + last_delta;

		if (counts) {
			counts[i] = count;
		}
		if (counts_since) {
			assert(counts != NULL);
			counts_since[i] = count - mtc->mtc_counts_last[i];
			mtc->mtc_counts_last[i] = count;
		}

		mtc->mtc_counts[i] = count;
	}
}

void
mt_update_fixed_counts(void)
{
	assert(ml_get_interrupts_enabled() == FALSE);

#if defined(__x86_64__)
	__builtin_ia32_lfence();
#elif defined(__arm64__)
	__builtin_arm_isb(ISB_SY);
#endif /* !defined(__x86_64__) && defined(__arm64__) */

	mt_fixed_counts_internal(NULL, NULL);
}

void
mt_fixed_counts(uint64_t *counts)
{
#if defined(__x86_64__)
	__builtin_ia32_lfence();
#elif defined(__arm64__)
	__builtin_arm_isb(ISB_SY);
#endif /* !defined(__x86_64__) && defined(__arm64__) */

	int intrs_en = ml_set_interrupts_enabled(FALSE);
	mt_fixed_counts_internal(counts, NULL);
	ml_set_interrupts_enabled(intrs_en);
}

uint64_t
mt_cur_cpu_instrs(void)
{
	uint64_t counts[MT_CORE_NFIXED];

	if (!mt_core_supported) {
		return 0;
	}

	mt_fixed_counts(counts);
	return counts[MT_CORE_INSTRS];
}

uint64_t
mt_cur_cpu_cycles(void)
{
	uint64_t counts[MT_CORE_NFIXED];

	if (!mt_core_supported) {
		return 0;
	}

	mt_fixed_counts(counts);
	return counts[MT_CORE_CYCLES];
}

void
mt_cur_cpu_cycles_instrs_speculative(uint64_t *cycles, __unused uint64_t *instrs)
{
	uint64_t counts[MT_CORE_NFIXED] = {0};
	struct mt_cpu *mtc = mt_cur_cpu();

	assert(ml_get_interrupts_enabled() == FALSE);
	assert(mtc != NULL);

	mt_mtc_update_fixed_counts(mtc, counts, NULL);

	*cycles = counts[MT_CORE_CYCLES];
	*instrs = counts[MT_CORE_INSTRS];
}

void
mt_perfcontrol(uint64_t *instrs, uint64_t *cycles)
{
	if (!mt_core_supported) {
		*instrs = 0;
		*cycles = 0;
		return;
	}

	struct mt_cpu *mtc = mt_cur_cpu();

	/*
	 * The performance controller queries the hardware directly, so provide the
	 * last snapshot we took for the core.  This is the value from when we
	 * updated the thread counts.
	 */

	*instrs = mtc->mtc_snaps[MT_CORE_INSTRS];
	*cycles = mtc->mtc_snaps[MT_CORE_CYCLES];
}

bool
mt_acquire_counters(void)
{
	if (kpc_get_force_all_ctrs()) {
		extern bool kpc_task_get_forced_all_ctrs(task_t);
		if (kpc_task_get_forced_all_ctrs(current_task())) {
			return true;
		}
		return false;
	}
	kpc_force_all_ctrs(current_task(), 1);
	return true;
}

bool
mt_owns_counters(void)
{
	return kpc_get_force_all_ctrs();
}

void
mt_release_counters(void)
{
	if (kpc_get_force_all_ctrs()) {
		kpc_force_all_ctrs(current_task(), 0);
	}
}

/*
 * Maintain reset values for the fixed instruction and cycle counters so
 * clients can be notified after a given number of those events occur.  This is
 * only used by microstackshot.
 */

bool mt_microstackshots = false;
unsigned int mt_microstackshot_ctr = 0;
uint64_t mt_microstackshot_period = 0;
mt_pmi_fn mt_microstackshot_pmi_handler = NULL;
void *mt_microstackshot_ctx = NULL;
uint64_t mt_core_reset_values[MT_CORE_NFIXED] = { 0 };

#define MT_MIN_FIXED_PERIOD (10 * 1000 * 1000)

int
mt_microstackshot_start(unsigned int ctr, uint64_t period, mt_pmi_fn handler,
    void *ctx)
{
	assert(ctr < MT_CORE_NFIXED);

	if (period < MT_MIN_FIXED_PERIOD) {
		return EINVAL;
	}
	if (mt_microstackshots) {
		return EBUSY;
	}

	mt_microstackshot_ctr = ctr;
	mt_microstackshot_pmi_handler = handler;
	mt_microstackshot_ctx = ctx;

	int error = mt_microstackshot_start_arch(period);
	if (error) {
		mt_microstackshot_ctr = 0;
		mt_microstackshot_pmi_handler = NULL;
		mt_microstackshot_ctx = NULL;
		return error;
	}

	mt_microstackshot_period = period;
	mt_microstackshots = true;

	return 0;
}

int
mt_microstackshot_stop(void)
{
	mt_microstackshots = false;
	mt_microstackshot_period = 0;
	memset(mt_core_reset_values, 0, sizeof(mt_core_reset_values));

	return 0;
}
