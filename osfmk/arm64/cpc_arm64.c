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

#include <kern/assert.h>
#include <kern/debug.h>
#include <kern/cpc.h>
#include <kern/percpu.h>
#include <kern/startup.h>
#include <kern/thread.h>
#include <kern/kalloc.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/machine_routines.h>
#include <kern/cpc_private.h>
#include <machine/machine_cpc.h>

#if defined(__BUILDING_XNU_LIB_UNITTEST__)
// CPC cannot program the CPMU's privileged MSRs from user space.
bool cpc_cpmu_supported = false;
#else
bool cpc_cpmu_supported = true;
#endif

static void _cpc_cpmu_control_disable(void);
static void _cpc_cpmu_control_reenable(void);

#if CPMU_AIC_PMI
#define PMCR0_INTGEN (0x200)
#else // CPMU_AIC_PMI
#define PMCR0_INTGEN (0x400)
#endif // !CPMU_AIC_PMI
#define PMCR0_INIT   (0x3 | 0x3000 | PMCR0_INTGEN)
#define PMCR1_INIT   (0x30300)

#if DEVELOPMENT || DEBUG

struct cpc_percpu_diags {
	uint64_t cpcd_prev_pmcr0;
	const char *cpcd_last_pmcr0_func;
};

PERCPU_DECL(struct cpc_percpu_diags, _cpc_percpu_diags);
struct cpc_percpu_diags PERCPU_DATA(_cpc_percpu_diags);

#define PMCR0_LOG() do { \
	struct cpc_percpu_diags *diags = PERCPU_GET(_cpc_percpu_diags); \
	diags->cpcd_prev_pmcr0 = __builtin_arm_rsr64("S3_1_C15_C0_0"); \
	diags->cpcd_last_pmcr0_func = __func__; \
} while (false)

#else // DEVELOPMENT || DEBUG

#define PMCR0_LOG() do { } while (false)

#endif // !(DEVELOPMENT || DEBUG)

#pragma mark - Counters

cpc_counter_t
cpc_cpmu_counters(void)
{
	struct cpc_cpu *cpu = &getCpuDatap()->cpu_cpc;
	return cpu->ccp_cpmu_counters;
}

cpc_deadlines_t
cpc_cpmu_deadlines(void)
{
	struct cpc_cpu *cpu = &getCpuDatap()->cpu_cpc;
	return cpu->ccp_cpmu_deadlines;
}

cpc_counter_t
cpc_hw_counter(
	cpc_hw_t hw,
	unsigned int id,
	cpc_slot_t slot,
	cpc_deadlines_t *deadlines_out)
{
	switch (hw) {
	case CPC_HW_CPMU:;
		struct cpc_cpu *cpu = &cpu_datap(id)->cpu_cpc;
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
		return ml_get_cpu_count();
	case CPC_HW_UPMU:
		return 0; // None supported by CPC, at least.
	default:
		panic("%s: unknown HW %d", __func__, hw);
	}
}

#if MACH_ASSERT
static void
_cpc_slot_assert_disabled(cpc_slot_t slot)
{
	unsigned int const enable_offset = slot > 7 ? 32 - 8 : 0;
	uint64_t pmc_enable = 1ULL << (enable_offset + slot);
	uint64_t pmi_enable = 1ULL << (enable_offset + 12 + slot);
	uint64_t pmcr0 = __builtin_arm_rsr64("S3_1_C15_C0_0");
	if (ml_get_interrupts_enabled() && (pmcr0 & pmc_enable) &&
	    (pmcr0 & pmi_enable) && (pmcr0 & PMCR0_INTGEN)) {
		panic("CPC: found PMC%d enabled when it shouldn't be from 0x%llx", slot,
		    pmcr0);
	}
}
#else // MACH_ASSERT
static void
_cpc_slot_assert_disabled(cpc_slot_t __unused slot)
{
}
#endif // !MACH_ASSERT

void
cpc_counter_set_value(cpc_counter_t counter, cpc_slot_t slot, uint64_t value)
{
	_cpc_slot_assert_disabled(slot);
	counter->cctr_prev_value = value;
	switch (slot) {
	case 0: __builtin_arm_wsr64("S3_2_C15_C0_0", value); break;
	case 1: __builtin_arm_wsr64("S3_2_C15_C1_0", value); break;
	case 2: __builtin_arm_wsr64("S3_2_C15_C2_0", value); break;
	case 3: __builtin_arm_wsr64("S3_2_C15_C3_0", value); break;
	case 4: __builtin_arm_wsr64("S3_2_C15_C4_0", value); break;
	case 5: __builtin_arm_wsr64("S3_2_C15_C5_0", value); break;
	case 6: __builtin_arm_wsr64("S3_2_C15_C6_0", value); break;
	case 7: __builtin_arm_wsr64("S3_2_C15_C7_0", value); break;
#if CPMU_PMC_COUNT > 8
#if CPMU_S3_2_C15_C9_09_ADDRESS
	case 8: __builtin_arm_wsr64("S3_2_C15_C8_0", value); break;
	case 9: __builtin_arm_wsr64("S3_2_C15_C9_0", value); break;
#else // CPMU_S3_2_C15_C9_09_ADDRESS
	case 8: __builtin_arm_wsr64("S3_2_C15_C9_0", value); break;
	case 9: __builtin_arm_wsr64("S3_2_C15_C10_0", value); break;
#endif // !CPMU_S3_2_C15_C9_09_ADDRESS
#endif // CPMU_PMC_COUNT > 8
	default:
#if MACH_ASSERT
		panic("%s: unexpected counter write: %d", __func__, slot);
#else // MACH_ASSERT
		return;
#endif // !MACH_ASSERT
	}
}

void
cpc_counters_resync(cpc_hw_t __assert_only hw,
    unsigned int __unused unit_id,
    cpc_counter_t counters)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
		cpc_counter_set_value(&counters[i], i, counters[i].cctr_prev_value);
	}
}

uint64_t
cpc_cpmu_counter_update(cpc_counter_t counter, cpc_slot_t slot)
{
	_cpc_slot_assert_disabled(slot);
	uint64_t value = 0;
	switch (slot) {
	case 0: value = __builtin_arm_rsr64("S3_2_C15_C0_0"); break;
	case 1: value = __builtin_arm_rsr64("S3_2_C15_C1_0"); break;
	case 2: value = __builtin_arm_rsr64("S3_2_C15_C2_0"); break;
	case 3: value = __builtin_arm_rsr64("S3_2_C15_C3_0"); break;
	case 4: value = __builtin_arm_rsr64("S3_2_C15_C4_0"); break;
	case 5: value = __builtin_arm_rsr64("S3_2_C15_C5_0"); break;
	case 6: value = __builtin_arm_rsr64("S3_2_C15_C6_0"); break;
	case 7: value = __builtin_arm_rsr64("S3_2_C15_C7_0"); break;
#if CPMU_PMC_COUNT > 8
#if CPMU_S3_2_C15_C9_09_ADDRESS
	case 8: value = __builtin_arm_rsr64("S3_2_C15_C8_0"); break;
	case 9: value = __builtin_arm_rsr64("S3_2_C15_C9_0"); break;
#else // CPMU_S3_2_C15_C9_09_ADDRESS
	case 8: value = __builtin_arm_rsr64("S3_2_C15_C9_0"); break;
	case 9: value = __builtin_arm_rsr64("S3_2_C15_C10_0"); break;
#endif // !CPMU_S3_2_C15_C9_09_ADDRESS
#endif // CPMU_PMC_COUNT > 8
	default:
#if MACH_ASSERT
		panic("%s: unexpected counter read: %d", __func__, slot);
#else // MACH_ASSERT
		return 0;
#endif // !MACH_ASSERT
	}
	cpc_counter_update(counter, value);
	return counter->cctr_sum;
}

void
cpc_hw_update(cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	// XXX This barrier is not strictly necessary.
	// Might be worth adding a speculative version of this function.
	__builtin_arm_isb(ISB_SY);
	uint64_t raw_counts[CPMU_PMC_COUNT] = {
		[0] = __builtin_arm_rsr64("S3_2_C15_C0_0"),
		[1] = __builtin_arm_rsr64("S3_2_C15_C1_0"),
		[2] = __builtin_arm_rsr64("S3_2_C15_C2_0"),
		[3] = __builtin_arm_rsr64("S3_2_C15_C3_0"),
		[4] = __builtin_arm_rsr64("S3_2_C15_C4_0"),
		[5] = __builtin_arm_rsr64("S3_2_C15_C5_0"),
		[6] = __builtin_arm_rsr64("S3_2_C15_C6_0"),
		[7] = __builtin_arm_rsr64("S3_2_C15_C7_0"),
#if CPMU_PMC_COUNT > 8
#if CPMU_S3_2_C15_C9_09_ADDRESS
		[8] = __builtin_arm_rsr64("S3_2_C15_C8_0"),
		[9] = __builtin_arm_rsr64("S3_2_C15_C9_0"),
#else // CPMU_S3_2_C15_C9_09_ADDRESS
		[8] = __builtin_arm_rsr64("S3_2_C15_C9_0"),
		[9] = __builtin_arm_rsr64("S3_2_C15_C10_0"),
#endif // !CPMU_S3_2_C15_C9_09_ADDRESS
#endif // CPMU_PMC_COUNT > 8
	};
	cpc_counter_t counters = cpc_cpmu_counters();
	for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
		cpc_counter_update(&counters[i], raw_counts[i]);
	}
}

uint64_t
cpc_cycles(void)
{
#ifndef __BUILDING_XNU_LIB_UNITTEST__
	uint64_t cur_cycles = __builtin_arm_rsr64("S3_2_C15_C0_0");
#else // !defined(__BUILDING_XNU_LIB_UNITTEST__)
	uint64_t cur_cycles = 0;
#endif // defined(__BUILDING_XNU_LIB_UNITTEST__)
	cpc_counter_t counters = cpc_cpmu_counters();
	cpc_counter_update(&counters[0], cur_cycles);
	return counters[0].cctr_sum;
}

uint64_t
cpc_instrs(void)
{
#ifndef __BUILDING_XNU_LIB_UNITTEST__
	uint64_t cur_instrs = __builtin_arm_rsr64("S3_2_C15_C1_0");
#else // !defined(__BUILDING_XNU_LIB_UNITTEST__)
	uint64_t cur_instrs = 0;
#endif // defined(__BUILDING_XNU_LIB_UNITTEST__)
	cpc_counter_t counters = cpc_cpmu_counters();
	cpc_counter_update(&counters[1], cur_instrs);
	return counters[1].cctr_sum;
}

struct cpc_cycles_instrs
cpc_cycles_instrs(void)
{
	__builtin_arm_isb(ISB_SY);
	return cpc_cycles_instrs_spec();
}

struct cpc_cycles_instrs
cpc_cycles_instrs_spec(void)
{
	uint64_t cur_cycles = __builtin_arm_rsr64("S3_2_C15_C0_0");
	uint64_t cur_instrs = __builtin_arm_rsr64("S3_2_C15_C1_0");
	cpc_counter_t counters = cpc_cpmu_counters();
	cpc_counter_update(&counters[0], cur_cycles);
	cpc_counter_update(&counters[1], cur_instrs);
	return (struct cpc_cycles_instrs){
		       .cycles = counters[0].cctr_sum,
		       .instrs = counters[1].cctr_sum,
	};
}

struct cpc_cycles_instrs
cpc_cycles_instrs_raw_approx(void)
{
	cpc_counter_t counters = cpc_cpmu_counters();
	return (struct cpc_cycles_instrs){
		       .cycles = counters[0].cctr_prev_value,
		       .instrs = counters[1].cctr_prev_value,
	};
}

uint64_t
cpc_hw_pmi_count(cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	const ml_topology_info_t *topology_info = ml_get_topology_info();
	uint64_t npmis = 0;
	for (unsigned int i = 0; i < topology_info->num_cpus; i++) {
		cpu_data_t *cpu = (cpu_data_t *)CpuDataEntries[topology_info->cpus[i].cpu_id].cpu_data_vaddr;
		npmis += cpu->cpu_cpc.ccp_cpmu_pmi_count;
	}
	return npmis;
}

#pragma mark - Calls

/// Handle A Performance Monitor Interrupt (PMI) from the CPMU, typically when
/// a PMC overflows.
///
/// ! This function is called from primary interrupt context.
///
/// - Parameters
///     - cpu_data: The per-CPU data for the CPU that is handling the PMI.
///     - pmcr0: The value of the CPMU's PMCR0 that contains the condition.
static void
_cpc_cpmu_pmi(cpu_data_t *cpu_data, uint64_t pmcr0)
{
	assert(cpu_data != NULL);
	assert(ml_get_interrupts_enabled() == FALSE);

	PMCR0_LOG();
	_cpc_cpmu_control_disable();
	// Use an instruction barrier to ensure the CPMU has flushed any counter
	// updates and PMSR is accurate.
	__builtin_arm_isb(ISB_SY);

#if CPC_DEBUG
	if (!PMCR0_PMI(pmcr0)) {
		panic("%s: CPMU PMI handler called but no PMI (PMCR0 = %#llx)",
		    __func__, pmcr0);
	}
#else // CPC_DEBUG
#pragma unused(pmcr0)
#endif // !CPC_DEBUG

	uint64_t pmsr = __builtin_arm_rsr64("S3_1_C15_C13_0");
	cpu_data->cpu_stat.pmi_cnt_wake += 1;
	struct cpc_cpu *cpu = &cpu_data->cpu_cpc;
	cpu->ccp_cpmu_pmi_count += 1;

	uint64_t __assert_only handled = 0;
	for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
		uint64_t i_bit = 1ULL << i;
		if ((pmsr & i_bit) == 0) {
			continue;
		}

#if MACH_ASSERT
		handled |= i_bit;
#endif // MACH_ASSERT

		cpc_counter_t ctr = &cpu->ccp_cpmu_counters[i];
		cpc_deadlines_t deadline = &cpu->ccp_cpmu_deadlines[i];

		bool captured = false;
		uintptr_t pc = 0;
#if HAS_CPMU_PC_CAPTURE
#define PMC_SUPPORTS_PC_CAPTURE(CTR) (((CTR) >= 5) && ((CTR) <= 7))
#define PC_CAPTURE_PMC(PCC_VAL)      (((PCC_VAL) >> 56) & 0x7)
#define PC_CAPTURE_PC(PCC_VAL)       ((PCC_VAL) & ((UINT64_C(1) << 48) - 1))

		if (PMC_SUPPORTS_PC_CAPTURE(i)) {
			uintptr_t pc_capture = __builtin_arm_rsr64("S3_1_C15_C14_1");
			captured = PC_CAPTURE_PMC(pc_capture) == i;
			if (captured) {
				pc = PC_CAPTURE_PC(pc_capture);
			}
		}
#endif // HAS_CPMU_PC_CAPTURE

		cpc_call_source_t source = CPC_CS_KERNEL;
		struct arm_saved_state *state;
		state = cpu_data->cpu_int_state;
		if (state) {
			if (PSR64_IS_USER(get_saved_state_cpsr(state))) {
				source = CPC_CS_USER;
			}
			if (!captured) {
				pc = get_saved_state_pc(state);
			}
			if (source == CPC_CS_KERNEL) {
				pc = VM_KERNEL_UNSLIDE(pc);
			}
		} else {
			// Don't know where the PC came from and may be a kernel address,
			// so clear it to prevent leaking the slide.
			pc = 0;
			captured = false;
		}

		cpc_call_flags_t flags = CPC_CF_NONE;
		if (captured) {
			flags |= CPC_CF_PC_PRECISE;
		}
		cpc_counter_call(ctr, deadline, i, pc, source, flags);
	}

	for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
		if (pmsr & (1ULL << i)) {
			cpc_counter_t ctr = &cpu->ccp_cpmu_counters[i];
			cpc_deadlines_t deadlines = &cpu->ccp_cpmu_deadlines[i];
			cpc_deadlines_sync(deadlines, ctr, i);
		}
	}

#if MACH_ASSERT
	uint64_t pmsr_after_handling = __builtin_arm_rsr64("S3_1_C15_C13_0");
	if (pmsr_after_handling != 0) {
		unsigned int first_ctr_ovf = __builtin_ffsll(pmsr_after_handling) - 1;
		uint64_t count = 0;
		const char *extra = "";
		if (first_ctr_ovf >= CPMU_PMC_COUNT) {
			extra = " (invalid counter)";
		} else {
			count = cpu->ccp_cpmu_counters[first_ctr_ovf].cctr_prev_value;
		}

		panic("CPC: PMI status not cleared on exit from handler, "
		    "PMSR = 0x%llx HANDLE -> 0x%llx, handled 0x%llx, "
		    "PMCR0 = 0x%llx, PMC%d = 0x%llx%s", pmsr, pmsr_after_handling,
		    handled, __builtin_arm_rsr64("S3_1_C15_C0_0"), first_ctr_ovf, count, extra);
	}
#endif // MACH_ASSERT

	_cpc_cpmu_control_reenable();
}

#pragma mark - Settings

#define PMCR0_ALLOWED_MASK ~(\
	(0x1ULL << 30) /* Useren */ | \
	(0x1ULL << 8) /* intGen Fast PMI/Debug Halt */ \
	)
#define PMCR1_ALLOWED_MASK (\
	(0xffULL << 8) /* EL0 Enable for PMC[01234567] */ | \
	(0x3ULL << 16) /* EL2 Enable for PMC[01] */ | \
	(0x3ULL << 40) /* EL0 Enable for PMC[89] */ \
    )

static inline void
_cpc_cpmu_pmcr0_write(uint64_t value)
{

	/* BEGIN IGNORE CODESTYLE */
	asm volatile(
		// Construct the mask in assembly, as the ARM immediate encoding cannot represent PMCR0_ALLOWED_MASK.
		"mov     x16, #-0x101\n\t"
		"movk    x16, #0xbfff, lsl #16\n\t"

		// Mask the input value and set PMCR0 with it.
		"and     x16, %[value], x16\n\t"
		"msr     S3_1_C15_C0_0, x16\n\t"
		:: [value] "r" (value)
		: "x16"
	);
	/* END IGNORE CODESTYLE */
}

static inline void
_cpc_cpmu_pmcr01_write(uint64_t pmcr0, uint64_t pmcr1)
{

	const uint64_t pmcr1_mask = cpc_is_secure() ? PMCR1_ALLOWED_MASK : UINT64_MAX;

	/* BEGIN IGNORE CODESTYLE */
	asm volatile(
		// Construct the masks in assembly, as ARM immediate encoding cannot represent them.
		"mov     x16, #-0x101\n\t"
		"movk    x16, #0xbfff, lsl #16\n\t"
#if CPC_INSECURE
		// Insecure kernels should be allowed to use a dynamic mask for testing.
		"mov     x17, %[pmcr1_mask]\n\t"
#else // CPC_INSECURE
		"mov     x17, #0xff00\n\t"         // EL0: enable PMC[01234567]
		"movk    x17, #0x3, lsl #16\n\t"   // EL2: enable PMC[01]
		"movk    x17, #0x300, lsl #32\n\t" // EL0: enable PMC[89]
#endif // !CPC_INSECURE

		"and     x16, %[pmcr0], x16\n\t"
		"and     x17, %[pmcr1], x17\n\t"
		"msr     S3_1_C15_C1_0, x17\n\t"
#if CONFIG_EXCLAVES || HYPERVISOR
		"msr     S3_1_C15_C7_2, x17\n\t"
#endif // CONFIG_EXCLAVES || HYPERVISOR
		"msr     S3_1_C15_C0_0, x16\n\t"
		::
		[pmcr0] "r" (pmcr0),
		[pmcr0_mask] "i" (PMCR0_ALLOWED_MASK),
		[pmcr1] "r" (pmcr1),
		[pmcr1_mask] "r" (pmcr1_mask)
		: "x16", "x17"
	);
	/* END IGNORE CODESTYLE */
}

struct _cpc_cpmu_pmesr_bits {
	uint64_t ccpb_bits;
	unsigned int ccpb_index;
};

#if CPMU_16BIT_EVENTS
#define CPMU_SELECTOR_WIDTH (16)
#define CPMU_SELECTOR_MASK  (0xffff)
#else // CPMU_16BIT_EVENTS
#define CPMU_SELECTOR_WIDTH (8)
#define CPMU_SELECTOR_MASK  (0xff)
#endif // !CPMU_16BIT_EVENTS

static struct _cpc_cpmu_pmesr_bits
_cpc_cpmu_pmesr_bits(unsigned int slot, uint64_t selector)
{
	unsigned int const pmesr_index = slot >= 6 ? 1 : 0;
	unsigned int const selector_shift = (slot - 2 - pmesr_index * 4) * CPMU_SELECTOR_WIDTH;
	return (struct _cpc_cpmu_pmesr_bits){
		       .ccpb_bits = (selector & CPMU_SELECTOR_MASK) << selector_shift,
		               .ccpb_index = pmesr_index,
	};
}

__SECURITY_STACK_DISALLOWED_PUSH
// Inlining subverts the no-frame-larger warning.
OS_NOINLINE
static void
_cpc_cpmu_pmesr_write_events_internal(const uint32_t *events)
{
	uint64_t pmesr0 = 0, pmesr1 = 0;

	for (int i = 0; i < CPMU_PMC_COUNT - 2; i++) {
		uint32_t event = events[i];
		if (event > cpc_known_cpmu_events.cel_event_count) {
			continue;
		}
		uint64_t selector = cpc_known_cpmu_events.cel_events[event].cev_selector;
		struct _cpc_cpmu_pmesr_bits bits = _cpc_cpmu_pmesr_bits(i + 2, selector);
		if (bits.ccpb_index == 1) {
			pmesr1 |= bits.ccpb_bits;
		} else {
			pmesr0 |= bits.ccpb_bits;
		}
	}

	__builtin_arm_wsr64("S3_1_C15_C5_0", pmesr0);
	__builtin_arm_wsr64("S3_1_C15_C6_0", pmesr1);
}
__SECURITY_STACK_DISALLOWED_POP

static inline void
_cpc_cpmu_pmesr_write_events(const uint32_t events[CPMU_PMC_COUNT - 2])
{
	release_assert(!ml_get_interrupts_enabled());
#if __has_feature(ptrauth_calls)
	uint64_t intrs_en = ml_pac_safe_interrupts_disable();
#endif // __has_feature(ptrauth_calls)
	_cpc_cpmu_pmesr_write_events_internal(events);
#if __has_feature(ptrauth_calls)
	ml_pac_safe_interrupts_restore(intrs_en);
#endif // __has_feature(ptrauth_calls)
}

static void
_cpc_cpmu_control_disable(void)
{
	_cpc_cpmu_pmcr0_write(0);
}

const union cpc_machine_regs cpc_machine_regs_init = {
	.cmr_cpmu = {
		.cacr_pmcr = {[0] = PMCR0_INIT, [1] = PMCR1_INIT, },
		// Cause PMESR to be written as zeroes.
		.cacr_has_events = true,
	},
};
const union cpc_machine_regs cpc_machine_regs_base = {
	.cmr_cpmu = {
		.cacr_pmcr = {[0] = PMCR0_INIT, [1] = PMCR1_INIT, },
	},
};

// Use a separate function to avoid a branch between writes to MSRs.
static void __unused
_cpc_cpmu_regs_apply_no_pmesr(const struct _cpc_arm64_cpmu_regs *regs)
{
	_cpc_cpmu_pmcr01_write(regs->cacr_pmcr[0], regs->cacr_pmcr[1]);
}

static void
_cpc_cpmu_regs_zero_pmcs(void)
{
	__builtin_arm_wsr64("S3_2_C15_C2_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C3_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C4_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C5_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C6_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C7_0", 0);
#if CPMU_PMC_COUNT > 8
#if CPMU_S3_2_C15_C9_09_ADDRESS
	__builtin_arm_wsr64("S3_2_C15_C8_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C9_0", 0);
#else // CPMU_S3_2_C15_C9_09_ADDRESS
	__builtin_arm_wsr64("S3_2_C15_C9_0", 0);
	__builtin_arm_wsr64("S3_2_C15_C10_0", 0);
#endif // !CPMU_S3_2_C15_C9_09_ADDRESS
#endif // CPMU_PMC_COUNT > 8
}

void
cpc_machine_regs_reset(const union cpc_machine_regs * __unused regs,
    cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	PMCR0_LOG();
	cpc_machine_regs_apply(&cpc_machine_regs_base, hw);
	_cpc_cpmu_regs_zero_pmcs();
	cpc_counter_t counters = cpc_cpmu_counters();
	for (unsigned int i = 2; i < CPMU_PMC_COUNT; i++) {
		counters[i].cctr_prev_value = 0;
		counters[i].cctr_sum = 0;
	}
}

void
cpc_machine_regs_apply(const union cpc_machine_regs *regs,
    cpc_hw_t __assert_only hw)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	assert(ml_get_interrupts_enabled() == FALSE);

	_cpc_cpmu_pmcr01_write(regs->cmr_cpmu.cacr_pmcr[0],
	    regs->cmr_cpmu.cacr_pmcr[1]);
	if (regs->cmr_cpmu.cacr_has_events) {
#if CPC_INSECURE
		if (cpc_is_secure()) {
			_cpc_cpmu_pmesr_write_events(regs->cmr_cpmu.cacr_events);
		} else {
			__builtin_arm_wsr64("S3_1_C15_C5_0", regs->cmr_cpmu.cacr_pmesr[0]);
			__builtin_arm_wsr64("S3_1_C15_C6_0", regs->cmr_cpmu.cacr_pmesr[1]);
		}
#else // CPC_INSECURE
		_cpc_cpmu_pmesr_write_events(regs->cmr_cpmu.cacr_events);
#endif // !CPC_INSECURE
	}

	if (regs->cmr_cpmu.cacr_ext) {
		__builtin_arm_wsr64("S3_1_C15_C2_0", regs->cmr_cpmu.cacr_pmcr2);
		__builtin_arm_wsr64("S3_1_C15_C3_0", regs->cmr_cpmu.cacr_pmcr3);
		__builtin_arm_wsr64("S3_1_C15_C4_0", regs->cmr_cpmu.cacr_pmcr4);
		__builtin_arm_wsr64("S3_1_C15_C7_0", regs->cmr_cpmu.cacr_opmat0);
		__builtin_arm_wsr64("S3_1_C15_C8_0", regs->cmr_cpmu.cacr_opmat1);
		__builtin_arm_wsr64("S3_1_C15_C9_0", regs->cmr_cpmu.cacr_opmsk0);
		__builtin_arm_wsr64("S3_1_C15_C10_0", regs->cmr_cpmu.cacr_opmsk1);

#if CPMU_EVENT_FILTERING
		__builtin_arm_wsr64("PM_MEMFLT_CTL23_EL1", regs->cmr_cpmu.cacr_pm_memflt_ctl23);
		__builtin_arm_wsr64("PM_MEMFLT_CTL45_EL1", regs->cmr_cpmu.cacr_pm_memflt_ctl45);
		__builtin_arm_wsr64("S3_2_C15_C2_1", regs->cmr_cpmu.cacr_pmefr[0]);
		__builtin_arm_wsr64("S3_2_C15_C3_1", regs->cmr_cpmu.cacr_pmefr[1]);
		__builtin_arm_wsr64("S3_2_C15_C4_1", regs->cmr_cpmu.cacr_pmefr[2]);
		__builtin_arm_wsr64("S3_2_C15_C5_1", regs->cmr_cpmu.cacr_pmefr[3]);
		__builtin_arm_wsr64("S3_2_C15_C6_1", regs->cmr_cpmu.cacr_pmefr[4]);
		__builtin_arm_wsr64("S3_2_C15_C7_1", regs->cmr_cpmu.cacr_pmefr[5]);
		__builtin_arm_wsr64("S3_2_C15_C8_1", regs->cmr_cpmu.cacr_pmefr[6]);
		__builtin_arm_wsr64("S3_2_C15_C9_1", regs->cmr_cpmu.cacr_pmefr[7]);
#endif // CPMU_EVENT_FILTERING
	}
}

void
cpc_hw_disable_pmis(cpc_hw_t __assert_only hw, const union cpc_machine_regs *regs)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	PMCR0_LOG();
	_cpc_cpmu_pmcr0_write(regs->cmr_cpmu.cacr_pmcr[0] & ~PMCR0_INTGEN);
}

void
cpc_hw_reenable_pmis(cpc_hw_t __assert_only hw, const union cpc_machine_regs *regs)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	PMCR0_LOG();
	_cpc_cpmu_pmcr0_write(regs->cmr_cpmu.cacr_pmcr[0]);
}

void
cpc_hw_slot_disable(cpc_hw_t __assert_only hw,
    const union cpc_machine_regs *regs,
    cpc_slot_t slot)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	unsigned int const enable_offset = slot > 7 ? 32 - 8 : 0;
	uint64_t pmcr0_enable = 1ULL << (enable_offset + slot);
	PMCR0_LOG();
	_cpc_cpmu_pmcr0_write(regs->cmr_cpmu.cacr_pmcr[0] & ~pmcr0_enable);
}

void
cpc_hw_slot_reenable(cpc_hw_t __assert_only hw,
    const union cpc_machine_regs *regs,
    cpc_slot_t __unused slot)
{
	assert3u(hw, ==, CPC_HW_CPMU);
	PMCR0_LOG();
	_cpc_cpmu_pmcr0_write(regs->cmr_cpmu.cacr_pmcr[0]);
}

static uint64_t
_cpc_event_flags_pmcr1(cpc_event_flags_t flags, cpc_slot_t slot)
{
	uint64_t const offset = slot > 7 ? 32 : 8;
	uint64_t const user_only = 1ULL << (offset + slot);
	uint64_t const kernel_only = 1ULL << (offset + slot + 8);

	if ((flags & CPC_EF_NO_KERNEL)) {
		return user_only;
	} else if ((flags & CPC_EF_NO_USER)) {
		return kernel_only;
	} else {
		return user_only | kernel_only;
	}
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
	boolean_t const include_self = TRUE;
	cpu_broadcast_xcall_simple(include_self,
	    _cpc_cpmu_broadcast_trampoline, block);
}

__result_use_check bool
cpc_machine_regs_event_select(
	union cpc_machine_regs *regs,
	cpc_hw_t __assert_only hw,
	cpc_set_options_t __unused options,
	const struct cpc_event_select *select)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	cpc_slot_t slot = select->ces_slot;
	uint64_t selector = select->ces_selector;
	if (slot < 0) {
		regs->cmr_cpmu.cacr_ext = true;
		switch (slot) {
		case CPC_LRP_CPMU_PMCR2:
			regs->cmr_cpmu.cacr_pmcr2 = selector;
			break;
		case CPC_LRP_CPMU_PMCR3:
			regs->cmr_cpmu.cacr_pmcr3 = selector;
			break;
		case CPC_LRP_CPMU_PMCR4:
			regs->cmr_cpmu.cacr_pmcr4 = selector;
			break;
		case CPC_LRP_CPMU_OPMAT0:
			regs->cmr_cpmu.cacr_opmat0 = selector;
			break;
		case CPC_LRP_CPMU_OPMAT1:
			regs->cmr_cpmu.cacr_opmat1 = selector;
			break;
		case CPC_LRP_CPMU_OPMSK0:
			regs->cmr_cpmu.cacr_opmsk0 = selector;
			break;
		case CPC_LRP_CPMU_OPMSK1:
			regs->cmr_cpmu.cacr_opmsk1 = selector;
			break;
#if CPMU_EVENT_FILTERING
		case CPC_LRP_CPMU_PM_MEMFLT_CTL23:
			regs->cmr_cpmu.cacr_pm_memflt_ctl23 = selector;
			break;
		case CPC_LRP_CPMU_PM_MEMFLT_CTL45:
			regs->cmr_cpmu.cacr_pm_memflt_ctl45 = selector;
			break;
		case CPC_LRP_CPMU_PMEFR2:
			regs->cmr_cpmu.cacr_pmefr[0] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR3:
			regs->cmr_cpmu.cacr_pmefr[1] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR4:
			regs->cmr_cpmu.cacr_pmefr[2] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR5:
			regs->cmr_cpmu.cacr_pmefr[3] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR6:
			regs->cmr_cpmu.cacr_pmefr[4] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR7:
			regs->cmr_cpmu.cacr_pmefr[5] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR8:
			regs->cmr_cpmu.cacr_pmefr[6] = selector;
			break;
		case CPC_LRP_CPMU_PMEFR9:
			regs->cmr_cpmu.cacr_pmefr[7] = selector;
			break;
#endif // CPMU_EVENT_FILTERING
		default:
			panic("CPC: unexpected slot provided: %d", slot);
		}
		return true;
	}
	if (slot < 2) {
		printf("CPC: event cannot select fixed counter %u\n", slot);
		return false;
	}

	cpc_event_t const event = cpc_find_event(CPC_HW_CPMU, (uint16_t)selector);
	if (event == CPC_EVENT_INVALID) {
		return false;
	}
	cpc_event_flags_t flags = select->ces_flags;
	if ((flags & (CPC_EF_NO_KERNEL | CPC_EF_NO_USER)) ==
	    (CPC_EF_NO_KERNEL | CPC_EF_NO_USER)) {
		printf("CPC: event on %d cannot disable both kernel and user\n",
		    slot);
		return false;
	}

	unsigned int const enable_offset = slot > 7 ? 32 - 8 : 0;
	uint64_t pmcr0_enable = 1ULL << (enable_offset + slot);

	if ((regs->cmr_cpmu.cacr_pmcr[0] & pmcr0_enable)) {
		printf("CPC: event would conflict on %d\n", slot);
		return false;
	}

	regs->cmr_cpmu.cacr_pmcr[0] |= pmcr0_enable;

	unsigned int const pmi_offset = slot > 7 ? 44 - 8 : 12;
	regs->cmr_cpmu.cacr_pmcr[0] |= 1ULL << (pmi_offset + slot);

#if HAS_CPMU_PC_CAPTURE
	if (PMC_SUPPORTS_PC_CAPTURE(slot)) {
		unsigned int const pc_capture_offset = 24 - 5;
		regs->cmr_cpmu.cacr_pmcr[0] |= 1ULL << (pc_capture_offset + slot);
	}
#endif // HAS_CPMU_PC_CAPTURE

	struct _cpc_cpmu_pmesr_bits pmesr = _cpc_cpmu_pmesr_bits(slot, selector);
	regs->cmr_cpmu.cacr_pmesr[pmesr.ccpb_index] |= pmesr.ccpb_bits;
	regs->cmr_cpmu.cacr_pmcr[1] |= _cpc_event_flags_pmcr1(flags, slot);
	regs->cmr_cpmu.cacr_events[slot - 2] = event;
	regs->cmr_cpmu.cacr_has_events = true;
	return true;
}

static void
_cpc_cpmu_control_reenable(void)
{
	const union cpc_machine_regs *regs = cpc_active_regs(CPC_HW_CPMU);
	_cpc_cpmu_pmcr0_write(regs->cmr_cpmu.cacr_pmcr[0]);
}

#pragma mark - External Calls

void
cpc_cpu_transition(cpc_cpu_event_t event, void *vcpu_data)
{
	struct cpu_data *cpu_data = vcpu_data;
	struct cpc_cpu *cpu = &cpu_data->cpu_cpc;

	switch (event) {
	case CPC_CPU_EARLY_INIT:
		for (unsigned int i = 0; i < CPMU_PMC_COUNT; i++) {
			lck_spin_init(&cpu->ccp_cpmu_deadlines[i].cd_lock, &cpc_lock_grp, LCK_ATTR_NULL);
		}
		break;

	case CPC_CPU_INIT:
		// Keep these around for kpc's thread counters.
		assert(cpu_data->cpu_kpc_buf[0] == NULL);
		cpu_data->cpu_kpc_buf[0] = kalloc_data(sizeof(uint64_t) * CPMU_PMC_COUNT,
		    Z_ZERO | Z_WAITOK);
		assert(cpu_data->cpu_kpc_buf[1] == NULL);
		cpu_data->cpu_kpc_buf[1] = kalloc_data(sizeof(uint64_t) * CPMU_PMC_COUNT,
		    Z_ZERO | Z_WAITOK);
		break;

	case CPC_CPU_ONLINE:
		cpc_hw_configure(CPC_HW_CPMU, cpu_data->cpu_number,
		    cpu->ccp_cpmu_counters, cpu->ccp_cpmu_deadlines, true);
		break;

	case CPC_CPU_OFFLINE:
		// Disable the counters so a pending PMI doesn't prevent power-gating.
		PMCR0_LOG();
		_cpc_cpmu_control_disable();
		[[fallthrough]];
	case CPC_CPU_IDLE:
		// Just save the PMCs when a CPU is going idle.
		cpc_hw_update(CPC_HW_CPMU);
		break;

	case CPC_CPU_ACTIVE_WARM:
#if HAS_RETENTION_STATE
		break;
#else // HAS_RETENTION_STATE
		// Systems without WFI retention need to reconfigure the counters.
		[[fallthrough]];
#endif // !HAS_RETENTION_STATE

	case CPC_CPU_ACTIVE_COLD:
		cpc_hw_configure(CPC_HW_CPMU, cpu_data->cpu_number,
		    cpu->ccp_cpmu_counters, cpu->ccp_cpmu_deadlines, false);
		break;

	default:
		break;
	}
}

#if CPMU_AIC_PMI
extern void cpc_cpmu_aic_pmi(cpu_id_t source);
void
cpc_cpmu_aic_pmi(cpu_id_t source)
{
	struct cpu_data *curcpu = getCpuDatap();
	if (source != curcpu->interrupt_nub) {
		panic("CPC: PMI from IOCPU %p delivered to wrong IOCPU %p", source,
		    curcpu->interrupt_nub);
	}
	_cpc_cpmu_pmi(curcpu, __builtin_arm_rsr64("S3_1_C15_C0_0"));
}
#endif // CPMU_AIC_PMI

void
cpc_fiq(
	void *cpu,
	uint64_t pmcr0,
	uint64_t upmsr)
{
#if CPMU_AIC_PMI
#pragma unused(cpu, pmcr0)
#else // CPMU_AIC_PMI
	_cpc_cpmu_pmi(cpu, pmcr0);
#endif // !CPMU_AIC_PMI

#if HAS_UPMU
	if (upmsr != 0) {
		// Monotonic handles the UPMU counters.
		mt_uncore_pmi(upmsr);
	}
#else // HAS_UPMU
#pragma unused(upmsr)
#endif // !HAS_UPMU
}

#pragma mark - Diagnostics

#if DEVELOPMENT || DEBUG

size_t
cpc_hw_print_regs(
	cpc_hw_t __assert_only hw,
	const char *indent,
	const union cpc_machine_regs *regs,
	char *output,
	size_t available)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	size_t written = 0;
	written += scnprintf(output + written, available - written,
	    "%s PMCR0: 0x%016llx    PMCR1: 0x%016llx\n"
	    "%sPMESR0: 0x%016llx   PMESR1: 0x%016llx\n",
	    indent,
	    regs->cmr_cpmu.cacr_pmcr[0],
	    regs->cmr_cpmu.cacr_pmcr[1],
	    indent,
	    regs->cmr_cpmu.cacr_pmesr[0],
	    regs->cmr_cpmu.cacr_pmesr[1]);
	for (unsigned int i = 0; i < CPMU_PMC_COUNT - 2; i++) {
		unsigned int event_index = regs->cmr_cpmu.cacr_events[i];
		if (event_index != 0 && event_index < cpc_known_cpmu_events.cel_event_count) {
			const struct cpc_event_info *info = &cpc_known_cpmu_events.cel_events[event_index];
			written += scnprintf(output + written, available - written,
			    "%s  PMC%d event: 0x%04hx (%d, %s)\n",
			    indent,
			    i + 2,
			    info->cev_selector,
			    event_index,
			    info->cev_name);
		}
	}
	if (regs->cmr_cpmu.cacr_ext) {
		written += scnprintf(output + written, available - written,
		    "%s PMCR2: 0x%016llx    PMCR3: 0x%016llx    PMCR4: 0x%016llx\n"
		    "%sOPMAT0: 0x%016llx   OPMAT1: 0x%016llx   OPMSK0: 0x%016llx   OPMSK1: 0x%016llx\n"
#if CPMU_EVENT_FILTERING
		    "%sPM_MEMFLT_CTL23: 0x%016llx PM_MEMFLT_CTL45: 0x%016llx\n"
		    "%sPMEFR2: 0x%016llx PMEFR3: 0x%016llx PMEFR4: 0x%016llx PMEFR5: 0x%016llx\n"
		    "%sPMEFR6: 0x%016llx PMEFR7: 0x%016llx PMEFR8: 0x%016llx PMEFR9: 0x%016llx\n"
#endif // CPMU_EVENT_FILTERING
		    , indent,
		    regs->cmr_cpmu.cacr_pmcr2,
		    regs->cmr_cpmu.cacr_pmcr3,
		    regs->cmr_cpmu.cacr_pmcr4,
		    indent,
		    regs->cmr_cpmu.cacr_opmat0,
		    regs->cmr_cpmu.cacr_opmat1,
		    regs->cmr_cpmu.cacr_opmsk0,
		    regs->cmr_cpmu.cacr_opmsk1
#if CPMU_EVENT_FILTERING
		    , indent,
		    regs->cmr_cpmu.cacr_pm_memflt_ctl23,
		    regs->cmr_cpmu.cacr_pm_memflt_ctl45,
		    indent,
		    regs->cmr_cpmu.cacr_pmefr[0],
		    regs->cmr_cpmu.cacr_pmefr[1],
		    regs->cmr_cpmu.cacr_pmefr[2],
		    regs->cmr_cpmu.cacr_pmefr[3],
		    indent,
		    regs->cmr_cpmu.cacr_pmefr[4],
		    regs->cmr_cpmu.cacr_pmefr[5],
		    regs->cmr_cpmu.cacr_pmefr[6],
		    regs->cmr_cpmu.cacr_pmefr[7]
#endif // CPMU_EVENT_FILTERING
		    );
	}
	return written;
}

void
cpc_hw_read_regs(cpc_hw_t __assert_only hw,
    union cpc_machine_regs *regs,
    uint64_t *counter_values)
{
	assert3u(hw, ==, CPC_HW_CPMU);

	regs->cmr_cpmu = (struct _cpc_arm64_cpmu_regs){
		.cacr_pmcr[0] = __builtin_arm_rsr64("S3_1_C15_C0_0"),
		.cacr_pmcr[1] = __builtin_arm_rsr64("S3_1_C15_C1_0"),
		.cacr_pmesr[0] = __builtin_arm_rsr64("S3_1_C15_C5_0"),
		.cacr_pmesr[1] = __builtin_arm_rsr64("S3_1_C15_C6_0"),
		.cacr_pmcr2 = __builtin_arm_rsr64("S3_1_C15_C2_0"),
		.cacr_pmcr3 = __builtin_arm_rsr64("S3_1_C15_C3_0"),
		.cacr_pmcr4 = __builtin_arm_rsr64("S3_1_C15_C4_0"),
		.cacr_opmat0 = __builtin_arm_rsr64("S3_1_C15_C7_0"),
		.cacr_opmat1 = __builtin_arm_rsr64("S3_1_C15_C8_0"),
		.cacr_opmsk0 = __builtin_arm_rsr64("S3_1_C15_C9_0"),
		.cacr_opmsk1 = __builtin_arm_rsr64("S3_1_C15_C10_0"),
#if CPMU_EVENT_FILTERING
		.cacr_pm_memflt_ctl23 = __builtin_arm_rsr64("PM_MEMFLT_CTL23_EL1"),
		.cacr_pm_memflt_ctl45 = __builtin_arm_rsr64("PM_MEMFLT_CTL45_EL1"),
		// Use coproc addresses for PMEFR{2,9} instead of register names due to rdar://152681387
		.cacr_pmefr = {
			__builtin_arm_rsr64("S3_2_C15_C2_1"),
			__builtin_arm_rsr64("S3_2_C15_C3_1"),
			__builtin_arm_rsr64("S3_2_C15_C4_1"),
			__builtin_arm_rsr64("S3_2_C15_C5_1"),
			__builtin_arm_rsr64("S3_2_C15_C6_1"),
			__builtin_arm_rsr64("S3_2_C15_C7_1"),
			__builtin_arm_rsr64("S3_2_C15_C8_1"),
			__builtin_arm_rsr64("S3_2_C15_C9_1"),
		},
#endif // CPMU_EVENT_FILTERING
		.cacr_ext = true,
	};

	counter_values[0] = __builtin_arm_rsr64("S3_2_C15_C0_0");
	counter_values[1] = __builtin_arm_rsr64("S3_2_C15_C1_0");
	counter_values[2] = __builtin_arm_rsr64("S3_2_C15_C2_0");
	counter_values[3] = __builtin_arm_rsr64("S3_2_C15_C3_0");
	counter_values[4] = __builtin_arm_rsr64("S3_2_C15_C4_0");
	counter_values[5] = __builtin_arm_rsr64("S3_2_C15_C5_0");
	counter_values[6] = __builtin_arm_rsr64("S3_2_C15_C6_0");
	counter_values[7] = __builtin_arm_rsr64("S3_2_C15_C7_0");
#if CPMU_PMC_COUNT > 8
#if CPMU_S3_2_C15_C9_09_ADDRESS
	counter_values[8] = __builtin_arm_rsr64("S3_2_C15_C8_0");
	counter_values[9] = __builtin_arm_rsr64("S3_2_C15_C9_0");
#else // CPMU_S3_2_C15_C9_09_ADDRESS
	counter_values[8] = __builtin_arm_rsr64("S3_2_C15_C9_0");
	counter_values[9] = __builtin_arm_rsr64("S3_2_C15_C10_0");
#endif // !CPMU_S3_2_C15_C9_09_ADDRESS
#endif // CPMU_PMC_COUNT > 8
}

#endif // DEVELOPMENT || DEBUG
