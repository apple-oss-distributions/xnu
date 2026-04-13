// Copyright (c) 2023 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#include <stdint.h>
#include <kern/kalloc.h>
#include <i386/cpuid.h>
#include <i386/cpu_data.h>
#include <i386/lapic.h>
#include <i386/proc_reg.h>
#include <kern/clock.h>
#include <kern/cpc.h>
#include <kern/cpc_private.h>
#include <machine/machine_cpc.h>

static int _cpc_lapic_pmi(x86_saved_state_t * __unused state);

bool cpc_cpmu_supported = false;
unsigned int _cpc_x86_64_cpmu_counter_count = 0;
unsigned int _cpc_x86_64_cpmu_fixed_count = 0;

// The static assignment of Intel's fixed-function counters.

__enum_decl(_cpc_x86_64_fixed_pmc_t, uint32_t, {
	CPC_X86_64_PMC_INSTRS = 0,
	CPC_X86_64_PMC_CYCLES = 1,
	CPC_X86_64_PMC_CYCLES_REF = 2,
});

#define CPC_X86_64_FIXED_RDPMC_TYPE (1ULL << 30)
#define CPC_X86_64_RDPMC_INSTRS \
    (CPC_X86_64_FIXED_RDPMC_TYPE | CPC_X86_64_PMC_INSTRS)
#define CPC_X86_64_RDPMC_CYCLES \
    (CPC_X86_64_FIXED_RDPMC_TYPE | CPC_X86_64_PMC_CYCLES)
#define CPC_X86_64_RDPMC_CYCLES_REF \
    (CPC_X86_64_FIXED_RDPMC_TYPE | CPC_X86_64_PMC_CYCLES_REF)

// [0]: Enable counter in user mode.
// [1]: Enable counter in supervisor mode.
// [2]: Count across all SMT hardware threads (avoid).
// [3]: Enable PMIs for this counter.
#define _CPC_X86_64_PMI_EN (0x8)
#define _CPC_X86_64_FIXCTRL_EN(ctr) (0xbULL << (4 * (ctr)))
// Offset by 32 for the fixed counters.
#define _CPC_X86_64_GLOBCTRL_FIX_EN(ctr) (UINT64_C(1) << (ctr + 32))

#define _CPC_X86_64_REGS_INIT { \
	        .cmr_cpmu = { \
	                .cxcr_global_ctrl = _CPC_X86_64_GLOBCTRL_FIX_EN(0) | \
	    _CPC_X86_64_GLOBCTRL_FIX_EN(1) | _CPC_X86_64_GLOBCTRL_FIX_EN(2), \
	                .cxcr_fixed_ctrl = _CPC_X86_64_FIXCTRL_EN(0) | \
	    _CPC_X86_64_FIXCTRL_EN(1) | _CPC_X86_64_FIXCTRL_EN(2), \
	                .cxcr_evtsel = { 0 }, \
	        }, \
	}

union cpc_machine_regs cpc_machine_regs_init = _CPC_X86_64_REGS_INIT;
union cpc_machine_regs cpc_machine_regs_base = _CPC_X86_64_REGS_INIT;

static void __unused
_cpc_core_disable(void)
{
	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, 0);
}

void
cpc_hw_disable_pmis(cpc_hw_t __assert_only hw,
    const union cpc_machine_regs * __unused regs)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	// Intel requires individual writes to each event selection register to
	// only disable PMIs.
	// This is pretty expensive, so just disable the counters instead.
	_cpc_core_disable();
}

void
cpc_counter_set_value(cpc_counter_t counter, cpc_slot_t slot, uint64_t value)
{
	assert3u(slot, <, _cpc_x86_64_cpmu_counter_count);
	if (slot < _cpc_x86_64_cpmu_fixed_count) {
		wrmsr64(MSR_IA32_PERF_FIXED_CTR0 + slot, value);
	} else {
		wrmsr64(MSR_IA32_PERFCTR0 + (slot - _cpc_x86_64_cpmu_fixed_count),
		    value);
	}
	counter->cctr_prev_value = value;
}

cpc_counter_t
cpc_cpmu_counters(void)
{
	struct cpc_cpu *cpu = &current_cpu_datap()->cpu_cpc;
	return cpu->ccp_cpmu_counters;
}

cpc_deadlines_t
cpc_cpmu_deadlines(void)
{
	struct cpc_cpu *cpu = &current_cpu_datap()->cpu_cpc;
	return cpu->ccp_cpmu_deadlines;
}

uint64_t
cpc_cycles(void)
{
	if (cpc_cpmu_supported) {
		uint64_t cur_cycles = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_CYCLES);
		cpc_counter_t counters = cpc_cpmu_counters();
		cpc_counter_t cycles_counter = &counters[CPC_X86_64_PMC_CYCLES];
		cpc_counter_update(cycles_counter, cur_cycles);
		return cycles_counter->cctr_sum;
	} else {
		return 0;
	}
}

uint64_t
cpc_instrs(void)
{
	if (cpc_cpmu_supported) {
		uint64_t cur_instrs = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_INSTRS);
		cpc_counter_t counters = cpc_cpmu_counters();
		cpc_counter_t instrs_counter = &counters[CPC_X86_64_PMC_INSTRS];
		cpc_counter_update(instrs_counter, cur_instrs);
		return instrs_counter->cctr_sum;
	} else {
		return 0;
	}
}

struct cpc_cycles_instrs
cpc_cycles_instrs(void)
{
	__builtin_ia32_mfence();
	return cpc_cycles_instrs_spec();
}

struct cpc_cycles_instrs
cpc_cycles_instrs_spec(void)
{
	if (cpc_cpmu_supported) {
		uint64_t cur_instrs = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_INSTRS);
		uint64_t cur_cycles = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_CYCLES);
		cpc_counter_t counters = cpc_cpmu_counters();
		cpc_counter_t instrs_counter = &counters[CPC_X86_64_PMC_INSTRS];
		cpc_counter_t cycles_counter = &counters[CPC_X86_64_PMC_CYCLES];
		cpc_counter_update(instrs_counter, cur_instrs);
		cpc_counter_update(cycles_counter, cur_cycles);
		return (struct cpc_cycles_instrs){
			       .instrs = instrs_counter->cctr_sum,
			       .cycles = cycles_counter->cctr_sum,
		};
	} else {
		return (struct cpc_cycles_instrs){ 0 };
	}
}

struct cpc_cycles_instrs
cpc_cycles_instrs_raw_approx(void)
{
	cpc_counter_t counters = cpc_cpmu_counters();
	cpc_counter_t instrs_counter = &counters[CPC_X86_64_PMC_INSTRS];
	cpc_counter_t cycles_counter = &counters[CPC_X86_64_PMC_CYCLES];
	return (struct cpc_cycles_instrs){
		       .instrs = instrs_counter->cctr_prev_value,
		       .cycles = cycles_counter->cctr_prev_value,
	};
}

struct cpc_cycles_instrs
cpc_cycles_instrs_raw_approx_x86_64(
	uint64_t *unhalted_ref_cycles_out)
{
	cpc_counter_t counters = cpc_cpmu_counters();
	cpc_counter_t instrs_counter = &counters[CPC_X86_64_PMC_INSTRS];
	cpc_counter_t cycles_counter = &counters[CPC_X86_64_PMC_CYCLES];
	*unhalted_ref_cycles_out =
	    counters[CPC_X86_64_PMC_CYCLES_REF].cctr_prev_value;
	return (struct cpc_cycles_instrs){
		       .cycles = cycles_counter->cctr_prev_value,
		       .instrs = instrs_counter->cctr_prev_value,
	};
}

uint64_t
cpc_hw_pmi_count(cpc_hw_t hw)
{
	uint64_t pmi_count = 0;
	if (hw == CPC_HW_CPMU) {
		for (unsigned int i = 0; i < machine_info.max_cpus; i++) {
			if (cpu_data_ptr[i] != NULL) {
				pmi_count += cpu_data_ptr[i]->cpu_cpc.ccp_core_pmi_count;
			}
		}
	}
	return pmi_count;
}

void
cpc_counters_resync(cpc_hw_t __assert_only hw,
    unsigned int __unused unit_id,
    cpc_counter_t counters)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	for (unsigned int i = 0; i < _cpc_x86_64_cpmu_counter_count; i++) {
		cpc_counter_set_value(&counters[i], i, counters[i].cctr_prev_value);
	}
}

static void
_cpc_x86_64_cpmu_registers_reenable(const struct _cpc_x86_64_cpmu_regs *regs)
{
	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, regs->cxcr_global_ctrl);
}

void
cpc_hw_reenable_pmis(
	cpc_hw_t __assert_only hw,
	const union cpc_machine_regs *regs)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	_cpc_x86_64_cpmu_registers_reenable(&regs->cmr_cpmu);
}

void
cpc_hw_slot_disable(cpc_hw_t __assert_only hw,
    const union cpc_machine_regs * __unused regs,
    cpc_slot_t __unused slot)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	// Disabling all counters is "close enough" for Intel.
	_cpc_core_disable();
}

void
cpc_hw_slot_reenable(cpc_hw_t __assert_only hw,
    const union cpc_machine_regs *regs,
    cpc_slot_t __unused slot)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	_cpc_x86_64_cpmu_registers_reenable(&regs->cmr_cpmu);
}

static uint64_t
_cpc_hw_read_pmc(cpc_hw_t __assert_only hw, unsigned int pmc)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	if (pmc < _cpc_x86_64_cpmu_fixed_count) {
		pmc |= CPC_X86_64_FIXED_RDPMC_TYPE;
	} else {
		pmc -= _cpc_x86_64_cpmu_fixed_count;
	}
	return __builtin_ia32_rdpmc(pmc);
}

static int
_cpc_lapic_pmi(x86_saved_state_t *state)
{
	struct cpc_cpu *cpu = &current_cpu_datap()->cpu_cpc;
	cpu->ccp_core_pmi_count += 1;

	if (cpu->ccp_core_active) {
		_cpc_core_disable();
	}

	uint64_t status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);
	bool state_64 = is_saved_state64(state);
	uint64_t cs = state_64 ? saved_state64(state)->isf.cs :
	    saved_state32(state)->cs;
	bool kernel = (cs & SEL_PL) != SEL_PL_U;

	uintptr_t pc = state_64 ? saved_state64(state)->isf.rip :
	    saved_state32(state)->eip;
	if (kernel) {
		pc = VM_KERNEL_UNSLIDE(pc);
	}

	cpc_call_source_t source = kernel ? CPC_CS_KERNEL : CPC_CS_USER;

	uint64_t clear_overflows = 0;
	for (unsigned int i = 0; i < _cpc_x86_64_cpmu_counter_count; i++) {
		bool const is_fixed = i < _cpc_x86_64_cpmu_fixed_count;
		int const fixed_offset = is_fixed ? 32 : -_cpc_x86_64_cpmu_fixed_count;
		uint64_t const i_overflow = 1ULL << (i + fixed_offset);
		if ((status & i_overflow)) {
			uint64_t value = _cpc_hw_read_pmc(CPC_HW_CPMU, i);
			cpc_counter_t ctr = &cpu->ccp_cpmu_counters[i];
			cpc_counter_update(ctr, value);
			cpc_deadlines_t deadlines = &cpu->ccp_cpmu_deadlines[i];
			cpc_counter_call(ctr, deadlines, i, pc, source, 0);
			cpc_deadlines_sync(deadlines, ctr, i);
			clear_overflows |= i_overflow;
		}
	}
	wrmsr64(MSR_IA32_PERF_GLOBAL_OVF_CTRL, clear_overflows);

#if MACH_ASSERT
	uint64_t after_status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS);
	if (after_status != 0) {
		unsigned int counter_index = __builtin_ctzll(after_status);
		if (counter_index >= 32) {
			counter_index -= 32;
		} else {
			counter_index += _cpc_x86_64_cpmu_fixed_count;
		}
		uint64_t value = _cpc_hw_read_pmc(CPC_HW_CPMU, counter_index);
		panic("CPC: overflow status non-zero after handling PMI: "
		    "0x%016llx, PMC%d: 0x%016llx, initial status: 0x%016llx, "
		    "acknowledged: 0x%016llx",
		    after_status, counter_index, value, status, clear_overflows);
	}
	for (unsigned int i = 0; i < _cpc_x86_64_cpmu_counter_count; i++) {
		uint64_t value = _cpc_hw_read_pmc(CPC_HW_CPMU, i);
		if (value & (1ULL << 48)) {
			panic("CPC: PMC%d is still overflowed after handling PMI: "
			    "0x%016llx, PMC%d: 0x%016llx", i, status, i, value);
		}
	}
#endif // MACH_ASSERT

	if (cpu->ccp_core_active) {
		const union cpc_machine_regs *regs = cpc_active_regs(CPC_HW_CPMU);
		_cpc_x86_64_cpmu_registers_reenable(&regs->cmr_cpmu);
	}
	return 0;
}

void
cpc_early_init(void)
{
	if (PE_parse_boot_argn("-nomt_core", NULL, 0)) {
		return;
	}
	i386_cpu_info_t *info = cpuid_info();
	if (info->cpuid_arch_perf_leaf.version >= 2) {
		lapic_set_pmi_func(_cpc_lapic_pmi);
		cpc_cpmu_supported = true;
		_cpc_x86_64_cpmu_fixed_count = info->cpuid_arch_perf_leaf.fixed_number;
		// Halve the number of configurable counters due to hyperthread
		// isolation.
		_cpc_x86_64_cpmu_counter_count = _cpc_x86_64_cpmu_fixed_count +
		    info->cpuid_arch_perf_leaf.number / 2;

		if (_cpc_x86_64_cpmu_fixed_count == 4) {
			cpc_machine_regs_init.cmr_cpmu.cxcr_global_ctrl |=
			    _CPC_X86_64_GLOBCTRL_FIX_EN(3);
			cpc_machine_regs_init.cmr_cpmu.cxcr_fixed_ctrl |=
			    _CPC_X86_64_FIXCTRL_EN(3);
		}
		cpc_machine_regs_base = cpc_machine_regs_init;
	}
}

void
cpc_cpu_transition(cpc_cpu_event_t event, void *vcpu_data)
{
	struct cpu_data *cpu_data = vcpu_data;
	struct cpc_cpu *cpu = &cpu_data->cpu_cpc;

	if (!cpc_cpmu_supported) {
		return;
	}

	switch (event) {
	case CPC_CPU_EARLY_INIT:
		for (unsigned int i = 0; i < _cpc_x86_64_cpmu_counter_count; i++) {
			lck_spin_init(&cpu->ccp_cpmu_deadlines[i].cd_lock, &cpc_lock_grp, LCK_ATTR_NULL);
		}
		break;

	case CPC_CPU_INIT:
		// Keep these around for kpc's thread counters.
		assert(cpu_data->cpu_kpc_buf[0] == NULL);
		cpu_data->cpu_kpc_buf[0] = kalloc_data(
			sizeof(uint64_t) * _cpc_x86_64_cpmu_counter_count,
			Z_ZERO | Z_WAITOK);
		assert(cpu_data->cpu_kpc_buf[1] == NULL);
		cpu_data->cpu_kpc_buf[1] = kalloc_data(
			sizeof(uint64_t) * _cpc_x86_64_cpmu_counter_count,
			Z_ZERO | Z_WAITOK);
		break;

	case CPC_CPU_ONLINE:
		cpc_hw_configure(CPC_HW_CPMU, cpu_data->cpu_number,
		    cpu->ccp_cpmu_counters, cpu->ccp_cpmu_deadlines, true);
		cpu->ccp_core_active = true;
		break;

	case CPC_CPU_OFFLINE:
		cpu->ccp_core_active = false;
		_cpc_core_disable();
		[[fallthrough]];
	case CPC_CPU_IDLE:
		// Just save the PMCs when a CPU is going down.
		cpc_hw_update(CPC_HW_CPMU);
		break;

	// No need to re-initialize anything after idle.
	case CPC_CPU_ACTIVE_COLD:
	case CPC_CPU_ACTIVE_WARM:
		break;
	}
}

cpc_event_t
cpc_find_event(cpc_hw_t __unused hw, uint16_t event_selector)
{
	return event_selector;
}

cpc_counter_t
cpc_hw_counter(
	cpc_hw_t hw,
	unsigned int unit_index,
	cpc_slot_t slot,
	cpc_deadlines_t *deadlines_out)
{
	switch (hw) {
	case CPC_HW_CPMU:;
		struct cpc_cpu *cpu = &cpu_datap(unit_index)->cpu_cpc;
		*deadlines_out = &cpu->ccp_cpmu_deadlines[slot];
		return &cpu->ccp_cpmu_counters[slot];
	case CPC_HW_UPMU:
		return NULL;
	default:
		panic("%s: unknown HW %d", __func__, hw);
	}
}

unsigned int
cpc_hw_unit_count(cpc_hw_t hw)
{
	switch (hw) {
	case CPC_HW_CPMU:
		return machine_info.max_cpus;
	case CPC_HW_UPMU:
		return 0; // None supported by CPC, at least.
	default:
		panic("%s: unknown HW %d", __func__, hw);
	}
}

void
cpc_hw_update(cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	__builtin_ia32_mfence();
	uint64_t raw_counts[CPMU_PMC_COUNT] = {
		[CPC_X86_64_PMC_INSTRS] = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_INSTRS),
		[CPC_X86_64_PMC_CYCLES] = __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_CYCLES),
		[CPC_X86_64_PMC_CYCLES_REF] =
	    __builtin_ia32_rdpmc(CPC_X86_64_RDPMC_CYCLES_REF),
	};
	if (_cpc_x86_64_cpmu_fixed_count == 4) {
		raw_counts[3] = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | 3);
	}
	raw_counts[_cpc_x86_64_cpmu_fixed_count + 0] = __builtin_ia32_rdpmc(0);
	raw_counts[_cpc_x86_64_cpmu_fixed_count + 1] = __builtin_ia32_rdpmc(1);
	raw_counts[_cpc_x86_64_cpmu_fixed_count + 2] = __builtin_ia32_rdpmc(2);
	raw_counts[_cpc_x86_64_cpmu_fixed_count + 3] = __builtin_ia32_rdpmc(3);

	cpc_counter_t counters = cpc_cpmu_counters();
	for (unsigned int i = 0; i < _cpc_x86_64_cpmu_counter_count; i++) {
		cpc_counter_update(&counters[i], raw_counts[i]);
	}
}

uint64_t
cpc_cpmu_counter_update(cpc_counter_t counter, cpc_slot_t slot)
{
	uint64_t value = 0;
	assert3u(slot, <, _cpc_x86_64_cpmu_counter_count);
	if (slot < _cpc_x86_64_cpmu_fixed_count) {
		value = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | slot);
	} else {
		value = __builtin_ia32_rdpmc(slot - _cpc_x86_64_cpmu_fixed_count);
	}

	cpc_counter_update(counter, value);
	return counter->cctr_sum;
}

static uint64_t
_cpc_event_flags_evntsel(cpc_event_flags_t flags)
{
	uint64_t const user_only = 1ULL << 16;
	uint64_t const kernel_only = 1ULL << 17;

	if ((flags & CPC_EF_NO_KERNEL)) {
		return user_only;
	} else if ((flags & CPC_EF_NO_USER)) {
		return kernel_only;
	} else {
		return user_only | kernel_only;
	}
}

__result_use_check bool
cpc_machine_regs_event_select(
	union cpc_machine_regs *regs,
	cpc_hw_t __assert_only hw,
	cpc_set_options_t __unused options,
	const struct cpc_event_select *event)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	if (event->ces_slot >= _cpc_x86_64_cpmu_counter_count) {
		printf("CPC: rejecting event for slot %d, max is %d\n", event->ces_slot,
		    _cpc_x86_64_cpmu_counter_count);
		return false;
	}
	uint64_t const mode_bits = _cpc_event_flags_evntsel(event->ces_flags);
	// Ignored after Sandy Bridge.
	uint64_t const pin_control_bit = 1ULL << 19;
	// This bit causes the counter to count events occurring in both
	// hardware threads.
	uint64_t const any_thread_bit = 1ULL << 21;
	uint64_t const disallowed_bits = pin_control_bit | any_thread_bit;
	uint64_t const allowed_bits = 0xFFFFFFFFULL & ~disallowed_bits;
	uint64_t const pmi_en_bits = (1ULL << 20) | (1ULL << 22);
	unsigned int const evtsel_index = event->ces_slot - _cpc_x86_64_cpmu_fixed_count;
	assert3u(evtsel_index, <,
	    _cpc_x86_64_cpmu_counter_count - _cpc_x86_64_cpmu_fixed_count);
	regs->cmr_cpmu.cxcr_evtsel[evtsel_index] =
	    (event->ces_selector & allowed_bits) | mode_bits | pmi_en_bits;
	regs->cmr_cpmu.cxcr_global_ctrl |= 1ULL << evtsel_index;
	return true;
}

#if DEVELOPMENT || DEBUG

void
cpc_hw_read_regs(cpc_hw_t __assert_only hw,
    union cpc_machine_regs *regs,
    uint64_t *counter_values)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	regs->cmr_cpmu = (struct _cpc_x86_64_cpmu_regs){
		.cxcr_fixed_ctrl = rdmsr64(MSR_IA32_PERF_FIXED_CTR_CTRL),
		.cxcr_global_ctrl = rdmsr64(MSR_IA32_PERF_GLOBAL_CTRL),
		.cxcr_global_ovf_ctrl = rdmsr64(MSR_IA32_PERF_GLOBAL_OVF_CTRL),
		.cxcr_global_status = rdmsr64(MSR_IA32_PERF_GLOBAL_STATUS),
		.cxcr_evtsel = {
			[0] = rdmsr64(MSR_IA32_EVNTSEL0),
			[1] = rdmsr64(MSR_IA32_EVNTSEL1),
			[2] = rdmsr64(MSR_IA32_EVNTSEL2),
			[3] = rdmsr64(MSR_IA32_EVNTSEL3),
		},
	};

	counter_values[0] = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | 0);
	counter_values[1] = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | 1);
	counter_values[2] = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | 2);
	if (_cpc_x86_64_cpmu_fixed_count == 4) {
		counter_values[3] = __builtin_ia32_rdpmc(CPC_X86_64_FIXED_RDPMC_TYPE | 3);
	}
	counter_values[_cpc_x86_64_cpmu_fixed_count] = __builtin_ia32_rdpmc(0);
	counter_values[_cpc_x86_64_cpmu_fixed_count + 1] = __builtin_ia32_rdpmc(1);
	counter_values[_cpc_x86_64_cpmu_fixed_count + 2] = __builtin_ia32_rdpmc(2);
	counter_values[_cpc_x86_64_cpmu_fixed_count + 3] = __builtin_ia32_rdpmc(3);
}

size_t
cpc_hw_print_regs(
	cpc_hw_t __assert_only hw,
	const char *indent,
	const union cpc_machine_regs *regs,
	char *output,
	size_t available)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	return scnprintf(output, available,
	           "%sGLOBAL_CTRL: 0x%016llx, FIXED_CTR_CTRL: 0x%016llx\n"
	           "%sEVNTSEL0: 0x%016llx, EVNTSEL1: 0x%016llx,\n"
	           "%sEVNTSEL2: 0x%016llx, EVNTSEL3: 0x%016llx\n", indent,
	           regs->cmr_cpmu.cxcr_global_ctrl,
	           regs->cmr_cpmu.cxcr_fixed_ctrl,
	           indent, regs->cmr_cpmu.cxcr_evtsel[0], regs->cmr_cpmu.cxcr_evtsel[1],
	           indent, regs->cmr_cpmu.cxcr_evtsel[2], regs->cmr_cpmu.cxcr_evtsel[3]);
}

#endif // DEVELOPMENT || DEBUG

static void
_cpc_cpmu_regs_zero_pmcs(void)
{
	wrmsr64(MSR_IA32_PERFCTR0 + 0, 0);
	wrmsr64(MSR_IA32_PERFCTR0 + 1, 0);
	wrmsr64(MSR_IA32_PERFCTR0 + 2, 0);
	wrmsr64(MSR_IA32_PERFCTR0 + 3, 0);
}

void
cpc_machine_regs_reset(
	const union cpc_machine_regs * __unused regs,
	cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	cpc_machine_regs_apply(&cpc_machine_regs_init, hw);
	_cpc_cpmu_regs_zero_pmcs();
	cpc_counter_t counters = cpc_cpmu_counters();
	for (unsigned int i = _cpc_x86_64_cpmu_fixed_count;
	    i < _cpc_x86_64_cpmu_counter_count; i++) {
		counters[i].cctr_prev_value = 0;
	}
}

void
cpc_machine_regs_apply(
	const union cpc_machine_regs *regs,
	cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	wrmsr64(MSR_IA32_PERF_FIXED_CTR_CTRL, regs->cmr_cpmu.cxcr_fixed_ctrl);
	wrmsr64(MSR_IA32_PERF_GLOBAL_CTRL, regs->cmr_cpmu.cxcr_global_ctrl);
	wrmsr64(MSR_IA32_EVNTSEL0, regs->cmr_cpmu.cxcr_evtsel[0]);
	wrmsr64(MSR_IA32_EVNTSEL1, regs->cmr_cpmu.cxcr_evtsel[1]);
	wrmsr64(MSR_IA32_EVNTSEL2, regs->cmr_cpmu.cxcr_evtsel[2]);
	wrmsr64(MSR_IA32_EVNTSEL3, regs->cmr_cpmu.cxcr_evtsel[3]);
}

static void
_cpc_cpmu_broadcast_trampoline(void *arg)
{
	unsigned int cpu = cpu_number();
	void (^block)(unsigned int cpu_id) = arg;
	block(cpu);
}

void
cpc_hw_broadcast(
	cpc_hw_t __assert_only hw,
	void (^block)(unsigned int unit_id))
{
	assert3u(hw, ==, CPC_HW_CPMU);
	mp_cpus_call(CPUMASK_ALL, ASYNC, _cpc_cpmu_broadcast_trampoline, block);
}
