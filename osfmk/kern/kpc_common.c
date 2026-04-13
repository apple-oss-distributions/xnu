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

#include <mach/mach_types.h>
#include <machine/machine_routines.h>
#include <machine/machine_cpc.h>
#include <kern/processor.h>
#include <kern/kalloc.h>
#include <sys/errno.h>
#include <sys/vm.h>
#include <kperf/buffer.h>
#include <kern/monotonic.h>
#include <kern/thread.h>

#include <kern/kpc.h>

#include <kperf/kperf.h>
#include <kperf/sample.h>
#include <kperf/context.h>
#include <kperf/action.h>

#if CONFIG_CPU_COUNTERS

#define COUNTERBUF_SIZE_PER_CPU (KPC_MAX_COUNTERS * sizeof(uint64_t))
#define COUNTERBUF_SIZE (machine_info.logical_cpu_max * \
	                 COUNTERBUF_SIZE_PER_CPU)

/* The maximum number of RAWPMU configuration values. */
#define RAWPMU_CONFIG_COUNT (17)

/*
 * The configuration lock is held whenever KPC's configuration is being updated
 * by user space.
 */
static LCK_GRP_DECLARE(kpc_config_lckgrp, "kpc");
static LCK_MTX_DECLARE(kpc_config_lock, &kpc_config_lckgrp);

struct kpc_globals {
	/*
	 * Requested KPC state for user space getters.
	 */
	kpc_config_t configs[KPC_MAX_COUNTERS + RAWPMU_CONFIG_COUNT];
	uint32_t actionids[KPC_MAX_COUNTERS];
	uint64_t periods[KPC_MAX_COUNTERS];

	/*
	 * The actively running classes and PMCs.
	 */
	uint32_t running_class_mask;
	uint64_t running_pmc_mask;

	/*
	 * Power management sharing.
	 */
	bool pwr_mgmt_custom_config;
	uint64_t pwr_mgmt_pmc_mask;

	/*
	 * CPC management structures and state.
	 */

	/*
	 * Events requested by KPC, for use with `set`.
	 */
	struct cpc_event_select event_selects[KPC_MAX_COUNTERS + RAWPMU_CONFIG_COUNT];
	unsigned int event_count;
	/*
	 * Cyclics requested by KPC, for use with `set`.
	 */
	struct cpc_cyclic_info cyclics[KPC_MAX_COUNTERS];
	unsigned int cyclic_count;

	/*
	 * The CPC counter set in use when KPC starts running.
	 */
	cpc_set_t set;
	/*
	 * The current set is out of date and will be re-created when counters
	 * start running.
	 */
	bool set_out_of_date;
	/*
	 * The set has been applied to the system and must be torn down by KPC.
	 */
	bool set_applied;
};

/*
 * Access protected by `kpc_config_lock`.
 */
static struct kpc_globals g_kpc = { 0 };

/*
 * Update the kpc state with inputs to the `cpc_set_t`, marking it out of date.
 */
static void
_update_kpc_set_inputs(void (^update_blk)(void))
{
	lck_mtx_lock(&kpc_config_lock);
	update_blk();
	g_kpc.set_out_of_date = true;
	lck_mtx_unlock(&kpc_config_lock);
}

int
kpc_force_all_ctrs(task_t task, int val)
{
	return cpc_task_set_owner(&task->t_cpc, val != 0);
}

void
kpc_pm_acknowledge(boolean_t available_to_pm)
{
	cpc_sharing_set_exclusive_locked(!available_to_pm);
}

int
kpc_get_force_all_ctrs(void)
{
	return cpc_sharing_is_exclusive();
}

boolean_t
kpc_register_pm_handler(kpc_pm_handler_t handler)
{
	return kpc_reserve_pm_counters(0x38, handler, TRUE);
}

boolean_t
kpc_reserve_pm_counters(
	uint64_t pmc_mask,
	kpc_pm_handler_t handler,
	boolean_t custom_config)
{
	uint64_t const all_mask = (1ULL << kpc_configurable_count()) - 1;
	uint64_t const req_mask = pmc_mask & all_mask;

	assert(handler != NULL);

	/*
	 * Power management provides thread-safety for writing these values.
	 */
	g_kpc.pwr_mgmt_custom_config = custom_config;
	g_kpc.pwr_mgmt_pmc_mask = req_mask;
	cpc_sharing_start(handler);

	printf("kpc: pm registered pmc_mask=0x%llx custom_config=%d\n",
	    req_mask, custom_config);

	/*
	 * The requested power management mask should match the mask expected
	 * by KPC.
	 */
	uint32_t __assert_only cfg_count = kpc_get_counter_count(KPC_CLASS_CONFIGURABLE_MASK);
	uint32_t __assert_only pwr_count = kpc_popcount(req_mask);
	assert3u((cfg_count + pwr_count), ==, kpc_configurable_count());

	return !cpc_sharing_is_exclusive();
}

void
kpc_release_pm_counters(void)
{
	g_kpc.pwr_mgmt_custom_config = false;
	g_kpc.pwr_mgmt_pmc_mask = 0;
	cpc_sharing_stop();
}

static bool
kpc_multiple_clients(void)
{
	return cpc_sharing_available();
}

boolean_t
kpc_controls_fixed_counters(void)
{
	return !cpc_sharing_available() || kpc_get_force_all_ctrs() || !g_kpc.pwr_mgmt_custom_config;
}

uint32_t
kpc_get_running(void)
{
	uint64_t pmc_mask = 0;
	uint32_t cur_state = 0;

	if (kpc_is_running_fixed()) {
		cur_state |= KPC_CLASS_FIXED_MASK;
	}

	pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
	if (kpc_is_running_configurable(pmc_mask)) {
		cur_state |= KPC_CLASS_CONFIGURABLE_MASK;
	}

	pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
	if ((pmc_mask != 0) && kpc_is_running_configurable(pmc_mask)) {
		cur_state |= KPC_CLASS_POWER_MASK;
	}

	return cur_state;
}

/* may be called from an IPI */
int
kpc_get_curcpu_counters(uint32_t classes, int *curcpu, uint64_t *buf)
{
	int enabled = 0, offset = 0;
	uint64_t pmc_mask = 0ULL;

	assert(buf);

	enabled = ml_set_interrupts_enabled(FALSE);

	if (curcpu) {
		*curcpu = cpu_number();
	}

	if (classes & KPC_CLASS_FIXED_MASK) {
		kpc_get_fixed_counters(&buf[offset]);
		offset += kpc_get_counter_count(KPC_CLASS_FIXED_MASK);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
		kpc_get_configurable_counters(&buf[offset], pmc_mask);
		offset += kpc_popcount(pmc_mask);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
		kpc_get_configurable_counters(&buf[offset], pmc_mask);
		offset += kpc_popcount(pmc_mask);
	}

	ml_set_interrupts_enabled(enabled);

	return offset;
}

/* generic counter reading function */
int
kpc_get_cpu_counters(boolean_t all_cpus, uint32_t classes,
    int *curcpu, uint64_t *buf)
{
	assert(buf);

	/*
	 * Unlike reading the current CPU counters, reading counters from all
	 * CPUs is architecture dependent. This allows kpc to make the most of
	 * the platform if memory mapped registers is supported.
	 */
	if (all_cpus) {
		return kpc_get_all_cpus_counters(classes, curcpu, buf);
	} else {
		return kpc_get_curcpu_counters(classes, curcpu, buf);
	}
}

uint32_t
kpc_get_counter_count(uint32_t classes)
{
	uint32_t count = 0;

	if (classes & KPC_CLASS_FIXED_MASK) {
		count += kpc_fixed_count();
	}

	if (classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) {
		uint64_t pmc_msk = kpc_get_configurable_pmc_mask(classes);
		uint32_t pmc_cnt = kpc_popcount(pmc_msk);
		count += pmc_cnt;
	}

	return count;
}

#pragma mark - Configuration State Getters and Setters

uint32_t
kpc_get_config_count(uint32_t classes)
{
	uint32_t count = 0;

	if (classes & KPC_CLASS_FIXED_MASK) {
		count += kpc_fixed_config_count();
	}

	if (classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(classes);
		count += kpc_configurable_config_count(pmc_mask);
	}

	if ((classes & KPC_CLASS_RAWPMU_MASK) &&
	    (!kpc_multiple_clients() || kpc_get_force_all_ctrs())) {
		count += kpc_rawpmu_config_count();
	}

	return count;
}

int
kpc_get_config(uint32_t classes, kpc_config_t *current_config)
{
	uint32_t count = 0;

	if (classes & KPC_CLASS_FIXED_MASK) {
		kpc_get_fixed_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_FIXED_MASK);
	}

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
		kpc_get_configurable_config(&current_config[count], pmc_mask);
		count += kpc_get_config_count(KPC_CLASS_CONFIGURABLE_MASK);
	}

	if (classes & KPC_CLASS_POWER_MASK) {
		uint64_t pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
		kpc_get_configurable_config(&current_config[count], pmc_mask);
		count += kpc_get_config_count(KPC_CLASS_POWER_MASK);
	}

	if (classes & KPC_CLASS_RAWPMU_MASK) {
		/*
		 * Clients shouldn't ask for config words that aren't available.
		 * Most likely, they'd misinterpret the returned buffer if we
		 * allowed this.
		 */
		if (kpc_multiple_clients() && !kpc_get_force_all_ctrs()) {
			return EPERM;
		}
		kpc_get_rawpmu_config(&current_config[count]);
		count += kpc_get_config_count(KPC_CLASS_RAWPMU_MASK);
	}

	return 0;
}

static int
_validate_kpc_config(uint32_t classes, kpc_config_t *configs)
{
	uint64_t const cfg_pmc_mask = kpc_get_configurable_pmc_mask(classes);
	unsigned int const cfg_count = kpc_configurable_count();

	/*
	 * RAWPMU registers can't be shared; they alter behavior to arbitrary PMCs.
	 */
	if ((classes & KPC_CLASS_RAWPMU_MASK) && kpc_multiple_clients() &&
	    !kpc_get_force_all_ctrs()) {
		printf("kpc: kpc_set_config: cannot set RAWPMU when counters are shared\n");
		return EXDEV;
	}

	if ((classes & KPC_CLASS_CONFIGURABLE_MASK) &&
	    (classes & KPC_CLASS_POWER_MASK)) {
		printf("kpc: kpc_set_config: cannot configure power with configurable\n");
		return EINVAL;
	}

#if __x86_64__
	if ((classes & KPC_CLASS_RAWPMU_MASK)) {
		printf("kpc: kpc_set_config: power is unsupported\n");
		return ENOTSUP;
	}
#endif /* __x86_64__ */

	/*
	 * Find any disallowed events to return an error here instead of set-running
	 * where the CPC set is created.
	 */
	unsigned int i_configs = 0;
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if (((1ULL << i) & cfg_pmc_mask) == 0) {
			continue;
		}
		uint16_t selector = configs[i_configs] & 0xffff;
		cpc_event_t event = cpc_find_event(CPC_HW_CPMU, selector);
		if (event == CPC_EVENT_INVALID) {
			printf("kpc: kpc_set_config: not allowed to count event 0x%04x\n",
			    selector);
			return EPERM;
		}
		i_configs += 1;
	}
	return 0;
}

static int
_kpc_set_config_internal(uint32_t classes, kpc_config_t *configs)
{
	unsigned int fix_count = kpc_fixed_count();
	unsigned int cfg_count = kpc_configurable_count();
	uint64_t const cfg_pmc_mask = kpc_get_configurable_pmc_mask(classes);

	int error = _validate_kpc_config(classes, configs);
	if (error != 0) {
		return error;
	}

	/* BEGIN IGNORE CODESTYLE */
	_update_kpc_set_inputs(^{
		unsigned int event_index = 0;
		for (unsigned int i = 0; i < cfg_count; i++) {
			if (((1ULL << i) & cfg_pmc_mask) == 0) {
				continue;
			}

			struct cpc_event_select *select = &g_kpc.event_selects[event_index];
			kpc_config_t config = kpc_config_arch_process(configs[event_index]);
			select->ces_selector = config & 0xffff;
			select->ces_flags = kpc_config_arch_flags(config);
			select->ces_slot = fix_count + i;
			g_kpc.configs[fix_count + i] = config;
			event_index += 1;
		}

#if __arm64__
		if (classes & KPC_CLASS_RAWPMU_MASK) {
			for (unsigned int i = 0; i < RAWPMU_CONFIG_COUNT; i++) {
				struct cpc_event_select *select = &g_kpc.event_selects[event_index];
				kpc_config_t config = configs[event_index];
				cpc_legacy_rawpmu_t rawpmu = (cpc_legacy_rawpmu_t)(-1 - i);
				select->ces_slot = (cpc_slot_t)rawpmu;
				select->ces_selector = config;
				event_index += 1;
			}
		}
#endif /* __arm64__ */

		g_kpc.event_count = event_index;
	});
	/* END IGNORE CODESTYLE */

	return 0;
}

int
kpc_set_config_kernel(uint32_t classes, kpc_config_t * configv)
{
	// User space always forces all counters when shimmed to CPC.
	(void)kpc_force_all_ctrs(current_task(), 1);
	return _kpc_set_config_internal(classes, configv);
}

int kpc_set_config_external(uint32_t classes, kpc_config_t *configv);
int
kpc_set_config_external(uint32_t classes, kpc_config_t *configv)
{
	return _kpc_set_config_internal(classes, configv);
}

#pragma mark - Buffer Management

uint32_t
kpc_get_counterbuf_size(void)
{
	return COUNTERBUF_SIZE;
}

/* allocate a buffer large enough for all possible counters */
uint64_t *
kpc_counterbuf_alloc(void)
{
	return kalloc_data_tag(COUNTERBUF_SIZE, Z_WAITOK | Z_ZERO, VM_KERN_MEMORY_DIAG);
}

void
kpc_counterbuf_free(uint64_t *buf)
{
	kfree_data(buf, COUNTERBUF_SIZE);
}

#pragma mark kperf and CPC Interfaces

void
kpc_sample_kperf(uint32_t actionid, uint32_t counter, uint64_t config,
    uint64_t count, uintptr_t pc, kperf_kpc_flags_t flags)
{
	struct kperf_sample sbuf;

	uint64_t desc = config | (uint64_t)counter << 32 | (uint64_t)flags << 48;

	BUF_DATA(PERF_KPC_HNDLR | DBG_FUNC_START, desc, count, pc);

	thread_t thread = current_thread();
	task_t task = get_threadtask(thread);

	struct kperf_context ctx = {
		.cur_thread = thread,
		.cur_task = task,
		.cur_pid = task_pid(task),
		.trigger_type = TRIGGER_TYPE_PMI,
		.trigger_id = 0,
	};

	int r = kperf_sample(&sbuf, &ctx, actionid, SAMPLE_FLAG_PEND_USER);

	BUF_INFO(PERF_KPC_HNDLR | DBG_FUNC_END, r);
}

static void
_kpc_cyclic_handler(
	struct cpc_cyclic_info *info,
	uint64_t count,
	uint64_t __unused extra_count,
	uintptr_t pc,
	cpc_call_source_t source,
	cpc_call_flags_t flags)
{
	kpc_config_t config = g_kpc.configs[info->cci_slot];
	kperf_kpc_flags_t kpc_flags = (source == CPC_CS_KERNEL) ? KPC_KERNEL_PC : 0;
	kpc_flags |= (flags & CPC_CF_PC_PRECISE) ? KPC_CAPTURED_PC : 0;
	kpc_flags |= KPC_USER_COUNTING | KPC_KERNEL_COUNTING;
	if ((flags & CPC_EF_NO_USER)) {
		kpc_flags &= ~KPC_USER_COUNTING;
	}
	if ((flags & CPC_EF_NO_KERNEL)) {
		kpc_flags &= ~KPC_KERNEL_COUNTING;
	}
	kpc_sample_kperf(g_kpc.actionids[info->cci_slot], info->cci_slot,
	    config & 0xffff, count, pc, kpc_flags);
}

#pragma mark Other State Getters and Setters

static int
_validate_set_periods(uint32_t classes, uint64_t *periods_in, uint64_t periods_out[KPC_MAX_COUNTERS])
{
	uint64_t const cfg_pmc_mask = kpc_get_configurable_pmc_mask(classes);
	bool const fixed = (classes & KPC_CLASS_FIXED_MASK) != 0;
	unsigned int const fix_count = kpc_fixed_count();
	unsigned int const cfg_count = kpc_configurable_count();

	/*
	 * No clients have the right to modify both classes.
	 */
	if ((classes & (KPC_CLASS_CONFIGURABLE_MASK)) &&
	    (classes & (KPC_CLASS_POWER_MASK))) {
		return EPERM;
	}

	/*
	 * Translate the periods requested for the classes into their respective
	 * counters.
	 */
	uint64_t max_period = cpc_hw_max_period(CPC_HW_CPMU);
	unsigned int val_index = 0;
	if (fixed) {
		for (unsigned int i = 0; i < fix_count; i++) {
			if (periods_in[i] > max_period) {
				printf("kpc: period %d is too large, %llu > %llu\n", i,
				    periods_in[i], max_period);
				return EINVAL;
			}
		}
		memcpy(periods_out, periods_in, fix_count * sizeof(periods_out[0]));
		val_index += fix_count;
	}
	for (unsigned int i = 0; i < cfg_count; i++) {
		if (cfg_pmc_mask & (1ULL << i)) {
			if (periods_in[val_index] > max_period) {
				printf("kpc: period %d is too large, %llu > %llu\n", val_index,
				    periods_in[val_index], max_period);
				return EINVAL;
			}
			periods_out[fix_count + i] = periods_in[val_index];
			val_index += 1;
		}
	}

	return 0;
}

int
kpc_set_period(uint32_t classes, uint64_t *periods)
{
	uint64_t valid_periods[KPC_MAX_COUNTERS] = { 0 };
	static_assert(sizeof(valid_periods) == sizeof(g_kpc.periods));
	int error = _validate_set_periods(classes, periods, valid_periods);
	if (error != 0) {
		return error;
	}
	uint64_t *valid_periods_arr = valid_periods;

	/* BEGIN IGNORE CODESTYLE */
	_update_kpc_set_inputs(^{
		unsigned int const all_count = kpc_fixed_count() + kpc_configurable_count();

		memcpy(g_kpc.periods, valid_periods_arr, sizeof(valid_periods));

		/*
		 * Start configuring CPC cyclics for the periods.
		 */
		assert3u(all_count, <=, sizeof(g_kpc.cyclics) / sizeof(g_kpc.cyclics[0]));
		memset(g_kpc.cyclics, 0, sizeof(g_kpc.cyclics));
		g_kpc.cyclic_count = 0;

		for (unsigned int i = 0; i < all_count; i++) {
			uint64_t period = g_kpc.periods[i];
			if (period != 0) {
				struct cpc_cyclic_info *cyclic = &g_kpc.cyclics[g_kpc.cyclic_count];
				cyclic->cci_period = period;
				cyclic->cci_func = _kpc_cyclic_handler;
				cyclic->cci_slot = i;
				g_kpc.cyclic_count += 1;
			}
		}
	});
	/* END IGNORE CODESTYLE */

	return 0;
}

int
kpc_get_period(uint32_t classes, uint64_t *periods_out)
{
	uint32_t fix_count = kpc_fixed_count();
	uint32_t cfg_count = kpc_configurable_count();
	uint64_t pmc_mask = 0ULL;
	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
	} else if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
	}

	lck_mtx_lock(&kpc_config_lock);

	uint32_t i_periods = 0;
	if (classes & KPC_CLASS_FIXED_MASK) {
		memcpy(periods_out, g_kpc.periods, fix_count * sizeof(periods_out[0]));
		i_periods += fix_count;
	}

	/*
	 * Only return one or the other, preferring the configurable class.
	 */
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			periods_out[i_periods] = g_kpc.periods[fix_count + i];
			i_periods += 1;
		}
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int
kpc_set_actionid(uint32_t classes, uint32_t *actionids)
{
	unsigned int const fix_count = kpc_fixed_count();
	uint64_t pmc_mask = 0ULL;
	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
	} else if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
	}

	/* NOTE: what happens if a pmi occurs while actionids are being
	 * set is undefined. */
	lck_mtx_lock(&kpc_config_lock);

	uint32_t i_actionids = 0;
	if (classes & KPC_CLASS_FIXED_MASK) {
		memcpy(&g_kpc.actionids, actionids, fix_count * sizeof(actionids[0]));
		i_actionids += fix_count;
	}

	uint32_t cfg_count = kpc_configurable_count();
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			g_kpc.actionids[fix_count + i] = actionids[i_actionids];
			i_actionids += 1;
		}
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int
kpc_get_actionid(uint32_t classes, uint32_t *actionids_out)
{
	unsigned int fix_count = kpc_fixed_count();
	unsigned int cfg_count = kpc_configurable_count();
	uint64_t pmc_mask = 0ULL;
	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_CONFIGURABLE_MASK);
	} else if (classes & KPC_CLASS_POWER_MASK) {
		pmc_mask = kpc_get_configurable_pmc_mask(KPC_CLASS_POWER_MASK);
	}

	lck_mtx_lock(&kpc_config_lock);

	unsigned int i_actionids = 0;
	if (classes & KPC_CLASS_FIXED_MASK) {
		memcpy(actionids_out, &g_kpc.actionids, fix_count * sizeof(actionids_out[0]));
		i_actionids += fix_count;
	}
	for (uint32_t i = 0; i < cfg_count; ++i) {
		if ((1ULL << i) & pmc_mask) {
			actionids_out[i_actionids] = g_kpc.actionids[fix_count + i];
			i_actionids += 1;
		}
	}

	lck_mtx_unlock(&kpc_config_lock);

	return 0;
}

int
kpc_get_fixed_counters(uint64_t *counterv)
{
#if __arm64__
	struct cpc_cycles_instrs counts = cpc_cycles_instrs();
	counterv[0] = counts.cycles;
	counterv[1] = counts.instrs;
#elif __X86_64__
	uint32_t count = kpc_fixed_count();
	cpc_hw_counts(CPC_HW_CPMU, (1ULL << count) - 1, counterv, count);
#endif // !__X86_64__ && !__arm64__
	return 0;
}

int
kpc_get_configurable_counters(uint64_t *counterv, uint64_t pmc_mask)
{
	assert(counterv != NULL);
	uint32_t offset = kpc_fixed_count();
	uint32_t config_count = kpc_configurable_count();
	cpc_hw_counts(CPC_HW_CPMU, pmc_mask << offset, counterv, config_count);
	return 0;
}

static int
_kpc_set_running_internal(uint32_t classes)
{
	int error = 0;
	uint32_t cfg_classes = classes;

	/*
	 * The power mask implies configurable counters for CPC.
	 */
	if (classes & KPC_CLASS_POWER_MASK) {
		cfg_classes |= KPC_CLASS_CONFIGURABLE_MASK;
	}

	lck_mtx_lock(&kpc_config_lock);
	bool const enabling_configurable = cfg_classes & KPC_CLASS_CONFIGURABLE_MASK;
	if (enabling_configurable) {
		/*
		 * Configurable counters are starting up; synchronize the KPC state
		 * with CPC.
		 */
		if (g_kpc.set == NULL || g_kpc.set_out_of_date) {
			if (g_kpc.set) {
				if (g_kpc.set_applied) {
					cpc_set_remove(g_kpc.set);
					g_kpc.set_applied = false;
				} else {
					/*
					 * Set was allocated but not applied, indicating counting
					 * had been previously disabled.
					 *
					 * This set is still out of date, so destroy it.
					 */
				}
				cpc_set_destroy(g_kpc.set);
				g_kpc.set = NULL;
			} else {
				/*
				 * Need to allocate a new set, as this is the first time KPC
				 * has been configured.
				 */
			}
			g_kpc.set = cpc_set_alloc(CPC_HW_CPMU, CPC_SET_BASE, g_kpc.event_selects,
			    g_kpc.event_count, g_kpc.cyclics, g_kpc.cyclic_count);
			if (g_kpc.set) {
				g_kpc.set_out_of_date = false;
			} else {
				/*
				 * Set failed to allocate, will return an error below.
				 */
			}
		} else {
			/*
			 * Set already exists and is not out of date.
			 */
		}
		if (!g_kpc.set) {
			error = EINVAL;
			goto out;
		}

		if (!g_kpc.set_applied) {
			cpc_set_apply(g_kpc.set);
			g_kpc.set_applied = true;
		} else {
			/*
			 * Transitioning from running to running, with no intervening
			 * changes to the configuration.
			 */
		}
	} else {
		bool const configurable_running = g_kpc.running_class_mask & KPC_CLASS_CONFIGURABLE_MASK;
		if (configurable_running && g_kpc.set && g_kpc.set_applied) {
			cpc_set_remove(g_kpc.set);
			g_kpc.set_applied = false;
		} else {
			/*
			 * Nothing was running or applied, so don't try to remove it.
			 */
		}
	}

	g_kpc.running_pmc_mask = kpc_get_configurable_pmc_mask(classes);
	g_kpc.running_class_mask = cfg_classes;

out:
	lck_mtx_unlock(&kpc_config_lock);
	if (error != 0) {
		printf("kpc: failed to set running: %d\n", error);
	}
	return error;
}

int
kpc_set_running_kernel(uint32_t classes)
{
	return _kpc_set_running_internal(classes);
}

int kpc_set_running_external(uint32_t classes);
int
kpc_set_running_external(uint32_t classes)
{
	return _kpc_set_running_internal(classes);
}

uint8_t
kpc_popcount(uint64_t value)
{
	return (uint8_t)__builtin_popcountll(value);
}

uint64_t
kpc_get_configurable_pmc_mask(uint32_t classes)
{
	uint32_t configurable_count = kpc_configurable_count();
	uint64_t cfg_mask = 0ULL, pwr_mask = 0ULL, all_cfg_pmcs_mask = 0ULL;

	/* not configurable classes or no configurable counters */
	if (((classes & (KPC_CLASS_CONFIGURABLE_MASK | KPC_CLASS_POWER_MASK)) == 0) ||
	    (configurable_count == 0)) {
		goto exit;
	}

	assert3u(configurable_count, <, 64);
	all_cfg_pmcs_mask = (1ULL << configurable_count) - 1;

	if (classes & KPC_CLASS_CONFIGURABLE_MASK) {
		if (kpc_get_force_all_ctrs()) {
			cfg_mask |= all_cfg_pmcs_mask;
		} else {
			cfg_mask |= (~g_kpc.pwr_mgmt_pmc_mask) & all_cfg_pmcs_mask;
		}
	}

	/*
	 * The power class exists iff:
	 *      - No tasks acquired all PMCs
	 *      - PM registered and uses kpc to interact with PMCs
	 */
	if (!kpc_get_force_all_ctrs() &&
	    kpc_multiple_clients() &&
	    !g_kpc.pwr_mgmt_custom_config &&
	    (classes & KPC_CLASS_POWER_MASK)) {
		pwr_mask |= g_kpc.pwr_mgmt_pmc_mask & all_cfg_pmcs_mask;
	}

exit:
	assert3u(((cfg_mask | pwr_mask) & (~all_cfg_pmcs_mask)), ==, 0);
	assert3u(kpc_popcount(cfg_mask | pwr_mask), <=, kpc_configurable_count());
	assert3u(cfg_mask & pwr_mask, ==, 0ULL);

	return cfg_mask | pwr_mask;
}

boolean_t
kpc_is_running_fixed(void)
{
	return (g_kpc.running_class_mask & KPC_CLASS_FIXED_MASK) == KPC_CLASS_FIXED_MASK;
}

boolean_t
kpc_is_running_configurable(uint64_t pmc_mask)
{
	assert3u(kpc_popcount(pmc_mask), <=, kpc_configurable_count());
	return ((g_kpc.running_class_mask & KPC_CLASS_CONFIGURABLE_MASK) == KPC_CLASS_CONFIGURABLE_MASK) &&
	       ((g_kpc.running_pmc_mask & pmc_mask) == pmc_mask);
}

#else // CONFIG_CPU_COUNTERS

/*
 * Ensure there are stubs available for kexts, even if xnu isn't built to
 * support CPU counters.
 */

void
kpc_pm_acknowledge(boolean_t __unused available_to_pm)
{
}

boolean_t
kpc_register_pm_handler(kpc_pm_handler_t __unused handler)
{
	return FALSE;
}

boolean_t
kpc_reserve_pm_counters(
	uint64_t __unused pmc_mask,
	kpc_pm_handler_t __unused handler,
	boolean_t __unused custom_config)
{
	return TRUE;
}

void
kpc_release_pm_counters(void)
{
}

int
kpc_get_force_all_ctrs(void)
{
	return 0;
}

int
kpc_get_cpu_counters(
	boolean_t __unused all_cpus,
	uint32_t __unused classes,
	int * __unused curcpu,
	uint64_t * __unused buf)
{
	return ENOTSUP;
}

uint32_t
kpc_get_running(void)
{
	return 0;
}

int
kpc_set_running_kernel(uint32_t __unused classes)
{
	return ENOTSUP;
}

int
kpc_get_config(
	uint32_t __unused classes,
	kpc_config_t * __unused current_config)
{
	return ENOTSUP;
}

int
kpc_set_config_kernel(
	uint32_t __unused classes,
	kpc_config_t * __unused configv)
{
	return ENOTSUP;
}

int kpc_set_config_external(uint32_t classes, kpc_config_t *configv);
int
kpc_set_config_external(
	uint32_t __unused classes,
	kpc_config_t * __unused configv)
{
	return ENOTSUP;
}

int kpc_set_running_external(uint32_t classes);
int
kpc_set_running_external(uint32_t __unused classes)
{
	return ENOTSUP;
}

#endif // !CONFIG_CPU_COUNTERS
