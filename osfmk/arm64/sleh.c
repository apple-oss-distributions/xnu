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

#include <arm/caches_internal.h>
#include <arm/cpu_data.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <arm/thread.h>
#include <arm/rtclock.h>
#include <arm/trap.h> /* for IS_ARM_GDB_TRAP() et al */
#include <arm64/proc_reg.h>
#include <arm64/machine_machdep.h>
#include <arm64/monotonic.h>
#include <arm64/instructions.h>

#include <kern/debug.h>
#include <kern/restartable.h>
#include <kern/socd_client.h>
#include <kern/thread.h>
#include <kern/zalloc_internal.h>
#include <mach/exception.h>
#include <mach/arm/traps.h>
#include <mach/vm_types.h>
#include <mach/machine/thread_status.h>

#include <machine/atomic.h>
#include <machine/limits.h>

#include <pexpert/arm/protos.h>
#include <pexpert/arm64/apple_arm64_regs.h>
#include <pexpert/arm64/board_config.h>

#include <vm/vm_page.h>
#include <vm/pmap.h>
#include <vm/vm_fault.h>
#include <vm/vm_kern.h>

#include <sys/errno.h>
#include <sys/kdebug.h>
#include <kperf/kperf.h>

#include <kern/policy_internal.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#include <prng/entropy.h>




#include <arm64/platform_error_handler.h>

#if KASAN_TBI
#include <san/kasan.h>
#endif /* KASAN_TBI */

#if CONFIG_UBSAN_MINIMAL
#include <san/ubsan_minimal.h>
#endif


#ifndef __arm64__
#error Should only be compiling for arm64.
#endif

#if DEBUG || DEVELOPMENT
#define HAS_TELEMETRY_KERNEL_BRK 1
#endif


#define TEST_CONTEXT32_SANITY(context) \
	(context->ss.ash.flavor == ARM_SAVED_STATE32 && context->ss.ash.count == ARM_SAVED_STATE32_COUNT && \
	 context->ns.nsh.flavor == ARM_NEON_SAVED_STATE32 && context->ns.nsh.count == ARM_NEON_SAVED_STATE32_COUNT)

#define TEST_CONTEXT64_SANITY(context) \
	(context->ss.ash.flavor == ARM_SAVED_STATE64 && context->ss.ash.count == ARM_SAVED_STATE64_COUNT && \
	 context->ns.nsh.flavor == ARM_NEON_SAVED_STATE64 && context->ns.nsh.count == ARM_NEON_SAVED_STATE64_COUNT)

#define ASSERT_CONTEXT_SANITY(context) \
	assert(TEST_CONTEXT32_SANITY(context) || TEST_CONTEXT64_SANITY(context))


#define COPYIN(src, dst, size)                           \
	(PSR64_IS_KERNEL(get_saved_state_cpsr(state))) ? \
	copyin_kern(src, dst, size) :                    \
	copyin(src, dst, size)

#define COPYOUT(src, dst, size)                          \
	(PSR64_IS_KERNEL(get_saved_state_cpsr(state))) ? \
	copyout_kern(src, dst, size)                   : \
	copyout(src, dst, size)

// Below is for concatenating a string param to a string literal
#define STR1(x) #x
#define STR(x) STR1(x)

#define ARM64_KDBG_CODE_KERNEL (0 << 8)
#define ARM64_KDBG_CODE_USER   (1 << 8)
#define ARM64_KDBG_CODE_GUEST  (2 << 8)

_Static_assert(ARM64_KDBG_CODE_GUEST <= KDBG_CODE_MAX, "arm64 KDBG trace codes out of range");
_Static_assert(ARM64_KDBG_CODE_GUEST <= UINT16_MAX, "arm64 KDBG trace codes out of range");

void panic_with_thread_kernel_state(const char *msg, arm_saved_state_t *ss) __abortlike;

void sleh_synchronous_sp1(arm_context_t *, uint32_t, vm_offset_t) __abortlike;
void sleh_synchronous(arm_context_t *, uint32_t, vm_offset_t, bool);



void sleh_irq(arm_saved_state_t *);
void sleh_fiq(arm_saved_state_t *);
void sleh_serror(arm_context_t *context, uint32_t esr, vm_offset_t far);
void sleh_invalid_stack(arm_context_t *context, uint32_t esr, vm_offset_t far) __dead2;

static void sleh_interrupt_handler_prologue(arm_saved_state_t *, unsigned int type);
static void sleh_interrupt_handler_epilogue(void);

static void handle_svc(arm_saved_state_t *);
static void handle_mach_absolute_time_trap(arm_saved_state_t *);
static void handle_mach_continuous_time_trap(arm_saved_state_t *);

static void handle_msr_trap(arm_saved_state_t *state, uint32_t esr);
#if __has_feature(ptrauth_calls)
static void handle_pac_fail(arm_saved_state_t *state, uint32_t esr) __dead2;
#endif

extern kern_return_t arm_fast_fault(pmap_t, vm_map_address_t, vm_prot_t, bool, bool);

static void handle_uncategorized(arm_saved_state_t *);

static void handle_kernel_breakpoint(arm_saved_state_t *, uint32_t);

static void handle_breakpoint(arm_saved_state_t *, uint32_t) __dead2;

typedef void (*abort_inspector_t)(uint32_t, fault_status_t *, vm_prot_t *);
static void inspect_instruction_abort(uint32_t, fault_status_t *, vm_prot_t *);
static void inspect_data_abort(uint32_t, fault_status_t *, vm_prot_t *);

static int is_vm_fault(fault_status_t);
static int is_translation_fault(fault_status_t);
static int is_alignment_fault(fault_status_t);

typedef void (*abort_handler_t)(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, expected_fault_handler_t);
static void handle_user_abort(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, expected_fault_handler_t);
static void handle_kernel_abort(arm_saved_state_t *, uint32_t, vm_offset_t, fault_status_t, vm_prot_t, expected_fault_handler_t);

static void handle_pc_align(arm_saved_state_t *ss) __dead2;
static void handle_sp_align(arm_saved_state_t *ss) __dead2;
static void handle_sw_step_debug(arm_saved_state_t *ss) __dead2;
static void handle_wf_trap(arm_saved_state_t *ss) __dead2;
static void handle_fp_trap(arm_saved_state_t *ss, uint32_t esr) __dead2;

static void handle_watchpoint(vm_offset_t fault_addr) __dead2;

static void handle_abort(arm_saved_state_t *, uint32_t, vm_offset_t, abort_inspector_t, abort_handler_t, expected_fault_handler_t);

static void handle_user_trapped_instruction32(arm_saved_state_t *, uint32_t esr) __dead2;

static void handle_simd_trap(arm_saved_state_t *, uint32_t esr) __dead2;

extern void mach_kauth_cred_thread_update(void);
void   mach_syscall_trace_exit(unsigned int retval, unsigned int call_number);

struct proc;

typedef uint32_t arm64_instr_t;

extern void
unix_syscall(struct arm_saved_state * regs, thread_t thread_act, struct proc * proc);

extern void
mach_syscall(struct arm_saved_state*);

#if CONFIG_DTRACE
extern kern_return_t dtrace_user_probe(arm_saved_state_t* regs);
extern boolean_t dtrace_tally_fault(user_addr_t);

/*
 * Traps for userland processing. Can't include bsd/sys/fasttrap_isa.h, so copy
 * and paste the trap instructions
 * over from that file. Need to keep these in sync!
 */
#define FASTTRAP_ARM32_INSTR 0xe7ffdefc
#define FASTTRAP_THUMB32_INSTR 0xdefc
#define FASTTRAP_ARM64_INSTR 0xe7eeee7e

#define FASTTRAP_ARM32_RET_INSTR 0xe7ffdefb
#define FASTTRAP_THUMB32_RET_INSTR 0xdefb
#define FASTTRAP_ARM64_RET_INSTR 0xe7eeee7d

/* See <rdar://problem/4613924> */
perfCallback tempDTraceTrapHook = NULL; /* Pointer to DTrace fbt trap hook routine */
#endif



extern void arm64_thread_exception_return(void) __dead2;

#if defined(APPLETYPHOON)
#define CPU_NAME "Typhoon"
#elif defined(APPLETWISTER)
#define CPU_NAME "Twister"
#elif defined(APPLEHURRICANE)
#define CPU_NAME "Hurricane"
#elif defined(APPLELIGHTNING)
#define CPU_NAME "Lightning"
#else
#define CPU_NAME "Unknown"
#endif

#if (CONFIG_KERNEL_INTEGRITY && defined(KERNEL_INTEGRITY_WT))
#define ESR_WT_SERROR(esr) (((esr) & 0xffffff00) == 0xbf575400)
#define ESR_WT_REASON(esr) ((esr) & 0xff)

#define WT_REASON_NONE           0
#define WT_REASON_INTEGRITY_FAIL 1
#define WT_REASON_BAD_SYSCALL    2
#define WT_REASON_NOT_LOCKED     3
#define WT_REASON_ALREADY_LOCKED 4
#define WT_REASON_SW_REQ         5
#define WT_REASON_PT_INVALID     6
#define WT_REASON_PT_VIOLATION   7
#define WT_REASON_REG_VIOLATION  8
#endif

#if defined(HAS_IPI)
void cpu_signal_handler(void);
extern unsigned int gFastIPI;
#endif /* defined(HAS_IPI) */

static arm_saved_state64_t *original_faulting_state = NULL;


TUNABLE(bool, fp_exceptions_enabled, "-fp_exceptions", false);

extern vm_offset_t static_memory_end;

/*
 * Fault copyio_recovery_entry in copyin/copyout routines.
 *
 * Offets are expressed in bytes from &copy_recovery_table
 */
struct copyio_recovery_entry {
	ptrdiff_t cre_start;
	ptrdiff_t cre_end;
	ptrdiff_t cre_recovery;
};

extern struct copyio_recovery_entry copyio_recover_table[];
extern struct copyio_recovery_entry copyio_recover_table_end[];

static inline ptrdiff_t
copyio_recovery_offset(uintptr_t addr)
{
	return (ptrdiff_t)(addr - (uintptr_t)copyio_recover_table);
}

#if !HAS_APPLE_PAC
static inline uintptr_t
copyio_recovery_addr(ptrdiff_t offset)
{
	return (uintptr_t)copyio_recover_table + (uintptr_t)offset;
}
#endif

static inline struct copyio_recovery_entry *
find_copyio_recovery_entry(arm_saved_state_t *state)
{
	ptrdiff_t offset = copyio_recovery_offset(get_saved_state_pc(state));
	struct copyio_recovery_entry *e;

	for (e = copyio_recover_table; e < copyio_recover_table_end; e++) {
		if (offset >= e->cre_start && offset < e->cre_end) {
			return e;
		}
	}

	return NULL;
}

static inline int
is_vm_fault(fault_status_t status)
{
	switch (status) {
	case FSC_TRANSLATION_FAULT_L0:
	case FSC_TRANSLATION_FAULT_L1:
	case FSC_TRANSLATION_FAULT_L2:
	case FSC_TRANSLATION_FAULT_L3:
	case FSC_ACCESS_FLAG_FAULT_L1:
	case FSC_ACCESS_FLAG_FAULT_L2:
	case FSC_ACCESS_FLAG_FAULT_L3:
	case FSC_PERMISSION_FAULT_L1:
	case FSC_PERMISSION_FAULT_L2:
	case FSC_PERMISSION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_translation_fault(fault_status_t status)
{
	switch (status) {
	case FSC_TRANSLATION_FAULT_L0:
	case FSC_TRANSLATION_FAULT_L1:
	case FSC_TRANSLATION_FAULT_L2:
	case FSC_TRANSLATION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_permission_fault(fault_status_t status)
{
	switch (status) {
	case FSC_PERMISSION_FAULT_L1:
	case FSC_PERMISSION_FAULT_L2:
	case FSC_PERMISSION_FAULT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}

static inline int
is_alignment_fault(fault_status_t status)
{
	return status == FSC_ALIGNMENT_FAULT;
}

static inline int
is_parity_error(fault_status_t status)
{
	switch (status) {
	/*
	 * TODO: According to ARM ARM, Async Parity (0b011001) is a DFSC that is
	 * only applicable to AArch32 HSR register. Can this be removed?
	 */
	case FSC_ASYNC_PARITY:
	case FSC_SYNC_PARITY:
	case FSC_SYNC_PARITY_TT_L1:
	case FSC_SYNC_PARITY_TT_L2:
	case FSC_SYNC_PARITY_TT_L3:
		return TRUE;
	default:
		return FALSE;
	}
}



__dead2 __unused
static void
arm64_implementation_specific_error(arm_saved_state_t *state, uint32_t esr, vm_offset_t far)
{
#pragma unused (state, esr, far)
	panic_plain("Unhandled implementation specific error\n");
}

#if CONFIG_KERNEL_INTEGRITY
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-parameter"
static void
kernel_integrity_error_handler(uint32_t esr, vm_offset_t far)
{
#if defined(KERNEL_INTEGRITY_WT)
#if (DEVELOPMENT || DEBUG)
	if (ESR_WT_SERROR(esr)) {
		switch (ESR_WT_REASON(esr)) {
		case WT_REASON_INTEGRITY_FAIL:
			panic_plain("Kernel integrity, violation in frame 0x%016lx.", far);
		case WT_REASON_BAD_SYSCALL:
			panic_plain("Kernel integrity, bad syscall.");
		case WT_REASON_NOT_LOCKED:
			panic_plain("Kernel integrity, not locked.");
		case WT_REASON_ALREADY_LOCKED:
			panic_plain("Kernel integrity, already locked.");
		case WT_REASON_SW_REQ:
			panic_plain("Kernel integrity, software request.");
		case WT_REASON_PT_INVALID:
			panic_plain("Kernel integrity, encountered invalid TTE/PTE while "
			    "walking 0x%016lx.", far);
		case WT_REASON_PT_VIOLATION:
			panic_plain("Kernel integrity, violation in mapping 0x%016lx.",
			    far);
		case WT_REASON_REG_VIOLATION:
			panic_plain("Kernel integrity, violation in system register %d.",
			    (unsigned) far);
		default:
			panic_plain("Kernel integrity, unknown (esr=0x%08x).", esr);
		}
	}
#else
	if (ESR_WT_SERROR(esr)) {
		panic_plain("SError esr: 0x%08x far: 0x%016lx.", esr, far);
	}
#endif
#endif
}
#pragma clang diagnostic pop
#endif

static void
arm64_platform_error(arm_saved_state_t *state, uint32_t esr, vm_offset_t far, platform_error_source_t source)
{
#if CONFIG_KERNEL_INTEGRITY
	kernel_integrity_error_handler(esr, far);
#endif

	(void)source;
	cpu_data_t *cdp = getCpuDatap();

	if (PE_handle_platform_error(far)) {
		return;
	} else if (cdp->platform_error_handler != NULL) {
		cdp->platform_error_handler(cdp->cpu_id, far);
	} else {
		arm64_implementation_specific_error(state, esr, far);
	}
}

void
panic_with_thread_kernel_state(const char *msg, arm_saved_state_t *ss)
{
	boolean_t ss_valid;

	ss_valid = is_saved_state64(ss);
	arm_saved_state64_t *state = saved_state64(ss);

	os_atomic_cmpxchg(&original_faulting_state, NULL, state, seq_cst);

	// rdar://80659177
	// Read SoCD tracepoints up to twice — once the first time we call panic and
	// another time if we encounter a nested panic after that.
	static int twice = 2;
	if (twice > 0) {
		twice--;
		SOCD_TRACE_XNU(KERNEL_STATE_PANIC, ADDR(state->pc),
		    PACK_LSB(VALUE(state->lr), VALUE(ss_valid)),
		    PACK_2X32(VALUE(state->esr), VALUE(state->cpsr)),
		    VALUE(state->far));
	}


	panic_plain("%s at pc 0x%016llx, lr 0x%016llx (saved state: %p%s)\n"
	    "\t  x0:  0x%016llx x1:  0x%016llx  x2:  0x%016llx  x3:  0x%016llx\n"
	    "\t  x4:  0x%016llx x5:  0x%016llx  x6:  0x%016llx  x7:  0x%016llx\n"
	    "\t  x8:  0x%016llx x9:  0x%016llx  x10: 0x%016llx  x11: 0x%016llx\n"
	    "\t  x12: 0x%016llx x13: 0x%016llx  x14: 0x%016llx  x15: 0x%016llx\n"
	    "\t  x16: 0x%016llx x17: 0x%016llx  x18: 0x%016llx  x19: 0x%016llx\n"
	    "\t  x20: 0x%016llx x21: 0x%016llx  x22: 0x%016llx  x23: 0x%016llx\n"
	    "\t  x24: 0x%016llx x25: 0x%016llx  x26: 0x%016llx  x27: 0x%016llx\n"
	    "\t  x28: 0x%016llx fp:  0x%016llx  lr:  0x%016llx  sp:  0x%016llx\n"
	    "\t  pc:  0x%016llx cpsr: 0x%08x         esr: 0x%08x          far: 0x%016llx\n",
	    msg, state->pc, state->lr, ss, (ss_valid ? "" : " INVALID"),
	    state->x[0], state->x[1], state->x[2], state->x[3],
	    state->x[4], state->x[5], state->x[6], state->x[7],
	    state->x[8], state->x[9], state->x[10], state->x[11],
	    state->x[12], state->x[13], state->x[14], state->x[15],
	    state->x[16], state->x[17], state->x[18], state->x[19],
	    state->x[20], state->x[21], state->x[22], state->x[23],
	    state->x[24], state->x[25], state->x[26], state->x[27],
	    state->x[28], state->fp, state->lr, state->sp,
	    state->pc, state->cpsr, state->esr, state->far);
}

void
sleh_synchronous_sp1(arm_context_t *context, uint32_t esr, vm_offset_t far __unused)
{
	esr_exception_class_t  class = ESR_EC(esr);
	arm_saved_state_t    * state = &context->ss;

	switch (class) {
	case ESR_EC_UNCATEGORIZED:
	{
#if (DEVELOPMENT || DEBUG)
		uint32_t instr = *((uint32_t*)get_saved_state_pc(state));
		if (IS_ARM_GDB_TRAP(instr)) {
			DebuggerCall(EXC_BREAKPOINT, state);
		}
		OS_FALLTHROUGH; // panic if we return from the debugger
#else
		panic_with_thread_kernel_state("Unexpected debugger trap while SP1 selected", state);
#endif /* (DEVELOPMENT || DEBUG) */
	}
	default:
		panic_with_thread_kernel_state("Synchronous exception taken while SP1 selected", state);
	}
}


__attribute__((noreturn))
void
thread_exception_return()
{
	thread_t thread = current_thread();
	if (thread->machine.exception_trace_code != 0) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_END, 0, 0, 0, 0, 0);
		thread->machine.exception_trace_code = 0;
	}

#if KASAN_TBI
	kasan_unpoison_curstack(true);
#endif /* KASAN_TBI */
	arm64_thread_exception_return();
	__builtin_unreachable();
}

/*
 * check whether task vtimers are running and set thread and CPU BSD AST
 *
 * must be called with interrupts masked so updates of fields are atomic
 * must be emitted inline to avoid generating an FBT probe on the exception path
 *
 */
__attribute__((__always_inline__))
static inline void
task_vtimer_check(thread_t thread)
{
	task_t task = get_threadtask_early(thread);

	if (__improbable(task != NULL && task->vtimers)) {
		thread_ast_set(thread, AST_BSD);
		thread->machine.CpuDatap->cpu_pending_ast |= AST_BSD;
	}
}

#if MACH_ASSERT
/**
 * A version of get_preemption_level() that works in early boot.
 *
 * If an exception is raised in early boot before the initial thread has been
 * set up, then calling get_preemption_level() in the SLEH will trigger an
 * infinitely-recursing exception. This function handles this edge case.
 */
static inline int
sleh_get_preemption_level(void)
{
	if (__improbable(current_thread() == NULL)) {
		return 0;
	}
	return get_preemption_level();
}
#endif // MACH_ASSERT

static inline bool
is_platform_error(uint32_t esr)
{
	esr_exception_class_t class = ESR_EC(esr);
	uint32_t iss = ESR_ISS(esr);
	fault_status_t fault_code;

	if (class == ESR_EC_DABORT_EL0 || class == ESR_EC_DABORT_EL1) {
		fault_code = ISS_DA_FSC(iss);
	} else if (class == ESR_EC_IABORT_EL0 || class == ESR_EC_IABORT_EL1) {
		fault_code = ISS_IA_FSC(iss);
	} else {
		return false;
	}

	return fault_code == FSC_SYNC_PARITY;
}

void
sleh_synchronous(arm_context_t *context, uint32_t esr, vm_offset_t far, __unused bool did_initiate_panic_lockdown)
{
	esr_exception_class_t  class   = ESR_EC(esr);
	arm_saved_state_t    * state   = &context->ss;
	thread_t               thread  = current_thread();
#if MACH_ASSERT
	int                    preemption_level = sleh_get_preemption_level();
#endif
	expected_fault_handler_t expected_fault_handler = NULL;
#ifdef CONFIG_XNUPOST
	expected_fault_handler_t saved_expected_fault_handler = NULL;
	uintptr_t saved_expected_fault_addr = 0;
	uintptr_t saved_expected_fault_pc = 0;
#endif /* CONFIG_XNUPOST */

	ASSERT_CONTEXT_SANITY(context);

	task_vtimer_check(thread);

#if CONFIG_DTRACE
	/*
	 * Handle kernel DTrace probes as early as possible to minimize the likelihood
	 * that this path will itself trigger a DTrace probe, which would lead to infinite
	 * probe recursion.
	 */
	if (__improbable((class == ESR_EC_UNCATEGORIZED) && tempDTraceTrapHook &&
	    (tempDTraceTrapHook(EXC_BAD_INSTRUCTION, state, 0, 0) == KERN_SUCCESS))) {
		return;
	}
#endif
	bool is_user = PSR64_IS_USER(get_saved_state_cpsr(state));


	/*
	 * Use KERNEL_DEBUG_CONSTANT_IST here to avoid producing tracepoints
	 * that would disclose the behavior of PT_DENY_ATTACH processes.
	 */
	if (is_user) {
		/* Sanitize FAR (but only if the exception was taken from userspace) */
		switch (class) {
		case ESR_EC_IABORT_EL1:
		case ESR_EC_IABORT_EL0:
			/* If this is a SEA, since we can't trust FnV, just clear FAR from the save area. */
			if (ISS_IA_FSC(ESR_ISS(esr)) == FSC_SYNC_EXT_ABORT) {
				saved_state64(state)->far = 0;
			}
			break;
		case ESR_EC_DABORT_EL1:
		case ESR_EC_DABORT_EL0:
			/* If this is a SEA, since we can't trust FnV, just clear FAR from the save area. */
			if (ISS_DA_FSC(ESR_ISS(esr)) == FSC_SYNC_EXT_ABORT) {
				saved_state64(state)->far = 0;
			}
			break;
		case ESR_EC_WATCHPT_MATCH_EL1:
		case ESR_EC_WATCHPT_MATCH_EL0:
		case ESR_EC_PC_ALIGN:
			break;  /* FAR_ELx is valid */
		default:
			saved_state64(state)->far = 0;
			break;
		}

		thread->machine.exception_trace_code = (uint16_t)(ARM64_KDBG_CODE_USER | class);
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_START,
		    esr, far, get_saved_state_pc(state), 0, 0);
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, ARM64_KDBG_CODE_KERNEL | class) | DBG_FUNC_START,
		    esr, VM_KERNEL_ADDRHIDE(far), VM_KERNEL_UNSLIDE(get_saved_state_pc(state)), 0, 0);
	}

	if (__improbable(ESR_INSTR_IS_2BYTES(esr))) {
		/*
		 * We no longer support 32-bit, which means no 2-byte
		 * instructions.
		 */
		if (is_user) {
			panic("Exception on 2-byte instruction, "
			    "context=%p, esr=%#x, far=%p",
			    context, esr, (void *)far);
		} else {
			panic_with_thread_kernel_state("Exception on 2-byte instruction", state);
		}
	}

#ifdef CONFIG_XNUPOST
	if (thread->machine.expected_fault_handler != NULL) {
		saved_expected_fault_handler = thread->machine.expected_fault_handler;
		saved_expected_fault_addr = thread->machine.expected_fault_addr;
		saved_expected_fault_pc = thread->machine.expected_fault_pc;

		thread->machine.expected_fault_handler = NULL;
		thread->machine.expected_fault_addr = 0;
		thread->machine.expected_fault_pc = 0;

		if (saved_expected_fault_addr == far ||
		    saved_expected_fault_pc == get_saved_state_pc(state)) {
			expected_fault_handler = saved_expected_fault_handler;
		}
	}
#endif /* CONFIG_XNUPOST */

	if (__improbable(is_platform_error(esr))) {
		/*
		 * Must gather error info in platform error handler before
		 * thread is preempted to another core/cluster to guarantee
		 * accurate error details
		 */

		arm64_platform_error(state, esr, far, PLAT_ERR_SRC_SYNC);
		return;
	}

	if (is_user && class == ESR_EC_DABORT_EL0) {
		thread_reset_pcs_will_fault(thread);
	}

	/* Inherit the interrupt masks from previous context */
	if (SPSR_INTERRUPTS_ENABLED(get_saved_state_cpsr(state))) {
		ml_set_interrupts_enabled(TRUE);
	}

	switch (class) {
	case ESR_EC_SVC_64:
		if (!is_saved_state64(state) || !is_user) {
			panic("Invalid SVC_64 context");
		}

		handle_svc(state);
		break;

	case ESR_EC_DABORT_EL0:
		handle_abort(state, esr, far, inspect_data_abort, handle_user_abort, expected_fault_handler);
		break;

	case ESR_EC_MSR_TRAP:
		handle_msr_trap(state, esr);
		break;
/**
 * Some APPLEVIRTUALPLATFORM targets do not specify armv8.6, but it's still possible for
 * them to be hosted by a host that implements ARM_FPAC. There's no way for such a host
 * to disable it or trap it without substantial performance penalty. Therefore, the FPAC
 * handler here needs to be built into the guest kernels to prevent the exception to fall
 * through.
 */
#if __has_feature(ptrauth_calls)
	case ESR_EC_PAC_FAIL:
#ifdef CONFIG_XNUPOST
		if (expected_fault_handler != NULL && expected_fault_handler(state)) {
			break;
		}
#endif /* CONFIG_XNUPOST */
		handle_pac_fail(state, esr);
		__builtin_unreachable();

#endif /* __has_feature(ptrauth_calls) */


	case ESR_EC_IABORT_EL0:
		handle_abort(state, esr, far, inspect_instruction_abort, handle_user_abort, expected_fault_handler);
		break;

	case ESR_EC_IABORT_EL1:
#ifdef CONFIG_XNUPOST
		if ((expected_fault_handler != NULL) && expected_fault_handler(state)) {
			break;
		}
#endif /* CONFIG_XNUPOST */

		panic_with_thread_kernel_state("Kernel instruction fetch abort", state);

	case ESR_EC_PC_ALIGN:
		handle_pc_align(state);
		__builtin_unreachable();

	case ESR_EC_DABORT_EL1:
		handle_abort(state, esr, far, inspect_data_abort, handle_kernel_abort, expected_fault_handler);
		break;

	case ESR_EC_UNCATEGORIZED:
		assert(!ESR_ISS(esr));

#if CONFIG_XNUPOST
		if (!is_user && (expected_fault_handler != NULL) && expected_fault_handler(state)) {
			/*
			 * The fault handler accepted the exception and handled it on its
			 * own. Don't trap to the debugger/panic.
			 */
			break;
		}
#endif /* CONFIG_XNUPOST */
		handle_uncategorized(&context->ss);
		break;

	case ESR_EC_SP_ALIGN:
		handle_sp_align(state);
		__builtin_unreachable();

	case ESR_EC_BKPT_AARCH32:
		handle_breakpoint(state, esr);
		__builtin_unreachable();

	case ESR_EC_BRK_AARCH64:
#ifdef CONFIG_XNUPOST
		if ((expected_fault_handler != NULL) && expected_fault_handler(state)) {
			break;
		}
#endif /* CONFIG_XNUPOST */
		if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
			handle_kernel_breakpoint(state, esr);
			break;
		} else {
			handle_breakpoint(state, esr);
			__builtin_unreachable();
		}

	case ESR_EC_BKPT_REG_MATCH_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_breakpoint(state, esr);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_BKPT_REG_MATCH_EL1:
		panic_with_thread_kernel_state("Hardware Breakpoint Debug exception from kernel. Panic (by design)", state);
		__builtin_unreachable();

	case ESR_EC_SW_STEP_DEBUG_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_sw_step_debug(state);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_SW_STEP_DEBUG_EL1:
		panic_with_thread_kernel_state("Software Step Debug exception from kernel. Panic (by design)", state);
		__builtin_unreachable();

	case ESR_EC_WATCHPT_MATCH_EL0:
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			handle_watchpoint(far);
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_WATCHPT_MATCH_EL1:
		/*
		 * If we hit a watchpoint in kernel mode, probably in a copyin/copyout which we don't want to
		 * abort.  Turn off watchpoints and keep going; we'll turn them back on in return_from_exception..
		 */
		if (FSC_DEBUG_FAULT == ISS_SSDE_FSC(esr)) {
			arm_debug_set(NULL);
			break; /* return to first level handler */
		}
		panic("Unsupported Class %u event code. state=%p class=%u esr=%u far=%p",
		    class, state, class, esr, (void *)far);
		__builtin_unreachable();

	case ESR_EC_TRAP_SIMD_FP:
		handle_simd_trap(state, esr);
		__builtin_unreachable();

	case ESR_EC_ILLEGAL_INSTR_SET:
		panic("Illegal instruction set exception. state=%p class=%u esr=%u far=%p spsr=0x%x",
		    state, class, esr, (void *)far, get_saved_state_cpsr(state));
		__builtin_unreachable();

	case ESR_EC_MCR_MRC_CP15_TRAP:
	case ESR_EC_MCRR_MRRC_CP15_TRAP:
	case ESR_EC_MCR_MRC_CP14_TRAP:
	case ESR_EC_LDC_STC_CP14_TRAP:
	case ESR_EC_MCRR_MRRC_CP14_TRAP:
		handle_user_trapped_instruction32(state, esr);
		__builtin_unreachable();

	case ESR_EC_WFI_WFE:
		// Use of WFI or WFE instruction when they have been disabled for EL0
		handle_wf_trap(state);
		__builtin_unreachable();

	case ESR_EC_FLOATING_POINT_64:
		handle_fp_trap(state, esr);
		__builtin_unreachable();

	default:
		handle_uncategorized(state);
	}

#ifdef CONFIG_XNUPOST
	if (saved_expected_fault_handler != NULL) {
		thread->machine.expected_fault_handler = saved_expected_fault_handler;
		thread->machine.expected_fault_addr = saved_expected_fault_addr;
		thread->machine.expected_fault_pc = saved_expected_fault_pc;
	}
#endif /* CONFIG_XNUPOST */

	if (is_user) {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, thread->machine.exception_trace_code) | DBG_FUNC_END,
		    esr, far, get_saved_state_pc(state), 0, 0);
		thread->machine.exception_trace_code = 0;
	} else {
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
		    MACHDBG_CODE(DBG_MACH_EXCP_SYNC_ARM, ARM64_KDBG_CODE_KERNEL | class) | DBG_FUNC_END,
		    esr, VM_KERNEL_ADDRHIDE(far), VM_KERNEL_UNSLIDE(get_saved_state_pc(state)), 0, 0);
	}
#if MACH_ASSERT
	if (preemption_level != sleh_get_preemption_level()) {
		panic("synchronous exception changed preemption level from %d to %d", preemption_level, sleh_get_preemption_level());
	}
#endif

}

/*
 * Uncategorized exceptions are a catch-all for general execution errors.
 * ARM64_TODO: For now, we assume this is for undefined instruction exceptions.
 */
static void
handle_uncategorized(arm_saved_state_t *state)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

#if CONFIG_DTRACE

	if (PSR64_IS_USER64(get_saved_state_cpsr(state))) {
		/*
		 * For a 64bit user process, we care about all 4 bytes of the
		 * instr.
		 */
		if (instr == FASTTRAP_ARM64_INSTR || instr == FASTTRAP_ARM64_RET_INSTR) {
			if (dtrace_user_probe(state) == KERN_SUCCESS) {
				return;
			}
		}
	} else if (PSR64_IS_USER32(get_saved_state_cpsr(state))) {
		/*
		 * For a 32bit user process, we check for thumb mode, in
		 * which case we only care about a 2 byte instruction length.
		 * For non-thumb mode, we care about all 4 bytes of the instructin.
		 */
		if (get_saved_state_cpsr(state) & PSR64_MODE_USER32_THUMB) {
			if (((uint16_t)instr == FASTTRAP_THUMB32_INSTR) ||
			    ((uint16_t)instr == FASTTRAP_THUMB32_RET_INSTR)) {
				if (dtrace_user_probe(state) == KERN_SUCCESS) {
					return;
				}
			}
		} else {
			if ((instr == FASTTRAP_ARM32_INSTR) ||
			    (instr == FASTTRAP_ARM32_RET_INSTR)) {
				if (dtrace_user_probe(state) == KERN_SUCCESS) {
					return;
				}
			}
		}
	}

#endif /* CONFIG_DTRACE */

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		if (IS_ARM_GDB_TRAP(instr)) {
			boolean_t interrupt_state;
			exception = EXC_BREAKPOINT;

			interrupt_state = ml_set_interrupts_enabled(FALSE);

			/* Save off the context here (so that the debug logic
			 * can see the original state of this thread).
			 */
			current_thread()->machine.kpcb = state;

			/* Hop into the debugger (typically either due to a
			 * fatal exception, an explicit panic, or a stackshot
			 * request.
			 */
			DebuggerCall(exception, state);

			current_thread()->machine.kpcb = NULL;
			(void) ml_set_interrupts_enabled(interrupt_state);
			return;
		} else {
			panic("Undefined kernel instruction: pc=%p instr=%x", (void*)get_saved_state_pc(state), instr);
		}
	}

	/*
	 * Check for GDB breakpoint via illegal opcode.
	 */
	if (IS_ARM_GDB_TRAP(instr)) {
		exception = EXC_BREAKPOINT;
		codes[0] = EXC_ARM_BREAKPOINT;
		codes[1] = instr;
	} else {
		codes[1] = instr;
	}

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

#if __has_feature(ptrauth_calls)
static const uint16_t PTRAUTH_TRAPS_START = 0xC470;
static inline bool
brk_comment_is_ptrauth(uint16_t comment)
{
	return comment >= PTRAUTH_TRAPS_START &&
	       comment <= PTRAUTH_TRAPS_START + ptrauth_key_asdb;
}

static inline const char *
ptrauth_key_to_string(ptrauth_key key)
{
	switch (key) {
	case ptrauth_key_asia:
		return "IA";
	case ptrauth_key_asib:
		return "IB";
	case ptrauth_key_asda:
		return "DA";
	case ptrauth_key_asdb:
		return "DB";
	default:
		__builtin_unreachable();
	}
}

static void __attribute__((noreturn))
ptrauth_handle_brk_trap(void *tstate, uint16_t comment)
{
	arm_saved_state_t *state = (arm_saved_state_t *)tstate;
#define MSG_FMT "Break 0x%04X instruction exception from kernel. Ptrauth failure with %s key resulted in 0x%016llx"
	char msg[strlen(MSG_FMT)
	- strlen("0x%04X") + strlen("0xFFFF")
	- strlen("%s") + strlen("IA")
	- strlen("0x%016llx") + strlen("0xFFFFFFFFFFFFFFFF")
	+ 1];
	ptrauth_key key = (ptrauth_key)(comment - PTRAUTH_TRAPS_START);
	const char *key_str = ptrauth_key_to_string(key);
	snprintf(msg, sizeof(msg), MSG_FMT, comment, key_str, saved_state64(state)->x[16]);
#undef MSG_FMT

	panic_with_thread_kernel_state(msg, state);
	__builtin_unreachable();
}
#endif /* __has_feature(ptrauth_calls) */

#if HAS_TELEMETRY_KERNEL_BRK
static uint32_t bound_chk_violations_event;

static void
telemetry_handle_brk_trap(
	void              *tstate,
	uint16_t          comment)
{
#if CONFIG_UBSAN_MINIMAL
	if (comment == UBSAN_SIGNED_OVERFLOW_TRAP) {
		ubsan_handle_brk_trap(tstate, comment);
	}
#else
	(void)tstate;
#endif

	if (comment == CLANG_BOUND_CHK_SOFT_TRAP) {
		os_atomic_inc(&bound_chk_violations_event, relaxed);
	}
}
#endif /* HAS_TELEMETRY_KERNEL_BRK */

#if __has_feature(ptrauth_calls)
KERNEL_BRK_DESCRIPTOR_DEFINE(ptrauth_desc,
    .type                = KERNEL_BRK_TYPE_PTRAUTH,
    .base                = PTRAUTH_TRAPS_START,
    .max                 = PTRAUTH_TRAPS_START + ptrauth_key_asdb,
    .options             = KERNEL_BRK_UNRECOVERABLE,
    .handle_breakpoint   = ptrauth_handle_brk_trap);
#endif

KERNEL_BRK_DESCRIPTOR_DEFINE(clang_desc,
    .type                = KERNEL_BRK_TYPE_CLANG,
    .base                = CLANG_TRAPS_ARM_START,
    .max                 = CLANG_TRAPS_ARM_END,
    .options             = KERNEL_BRK_UNRECOVERABLE,
    .handle_breakpoint   = NULL);

KERNEL_BRK_DESCRIPTOR_DEFINE(libcxx_desc,
    .type                = KERNEL_BRK_TYPE_LIBCXX,
    .base                = LIBCXX_TRAPS_START,
    .max                 = LIBCXX_TRAPS_END,
    .options             = KERNEL_BRK_UNRECOVERABLE,
    .handle_breakpoint   = NULL);

#if HAS_TELEMETRY_KERNEL_BRK
KERNEL_BRK_DESCRIPTOR_DEFINE(telemetry_desc,
    .type                = KERNEL_BRK_TYPE_TELEMETRY,
    .base                = TELEMETRY_TRAPS_START,
    .max                 = TELEMETRY_TRAPS_END,
    .options             = KERNEL_BRK_RECOVERABLE | KERNEL_BRK_CORE_ANALYTICS,
    .handle_breakpoint   = telemetry_handle_brk_trap);
#endif /* HAS_TELEMETRY_KERNEL_BRK */

static void
#if !HAS_TELEMETRY_KERNEL_BRK
__attribute__((noreturn))
#endif
handle_kernel_breakpoint(arm_saved_state_t *state, uint32_t esr)
{
	uint16_t comment = ISS_BRK_COMMENT(esr);
	const struct kernel_brk_descriptor *desc;

#define MSG_FMT "Break 0x%04X instruction exception from kernel. Panic (by design)"
	char msg[strlen(MSG_FMT) - strlen("0x%04X") + strlen("0xFFFF") + 1];

	desc = find_brk_descriptor_by_comment(comment);

	if (!desc) {
		goto brk_out;
	}

#if HAS_TELEMETRY_KERNEL_BRK
	if (desc->options & KERNEL_BRK_TELEMETRY_OPTIONS) {
		telemetry_kernel_brk(desc->type, desc->options, (void *)state, comment);
	}
#endif

	if (desc->handle_breakpoint) {
		desc->handle_breakpoint(state, comment); /* May trigger panic */
	}

#if HAS_TELEMETRY_KERNEL_BRK
	/* Still alive? Check if we should recover. */
	if (desc->options & KERNEL_BRK_RECOVERABLE) {
		add_saved_state_pc(state, 4);
		return;
	}
#endif

brk_out:
	snprintf(msg, sizeof(msg), MSG_FMT, comment);

	panic_with_thread_kernel_state(msg, state);
	__builtin_unreachable();
#undef MSG_FMT
}

static void
handle_breakpoint(arm_saved_state_t *state, uint32_t esr __unused)
{
	exception_type_t           exception = EXC_BREAKPOINT;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_BREAKPOINT};
	mach_msg_type_number_t     numcodes  = 2;

#if __has_feature(ptrauth_calls)
	if (ESR_EC(esr) == ESR_EC_BRK_AARCH64 &&
	    brk_comment_is_ptrauth(ISS_BRK_COMMENT(esr))) {
		exception |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */

	codes[1] = get_saved_state_pc(state);
	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_watchpoint(vm_offset_t fault_addr)
{
	exception_type_t           exception = EXC_BREAKPOINT;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_DA_DEBUG};
	mach_msg_type_number_t     numcodes  = 2;

	codes[1] = fault_addr;
	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    abort_inspector_t inspect_abort, abort_handler_t handler, expected_fault_handler_t expected_fault_handler)
{
	fault_status_t fault_code;
	vm_prot_t      fault_type;

	inspect_abort(ESR_ISS(esr), &fault_code, &fault_type);
	handler(state, esr, fault_addr, fault_code, fault_type, expected_fault_handler);
}

static void
inspect_instruction_abort(uint32_t iss, fault_status_t *fault_code, vm_prot_t *fault_type)
{
	getCpuDatap()->cpu_stat.instr_ex_cnt++;
	*fault_code = ISS_IA_FSC(iss);
	*fault_type = (VM_PROT_READ | VM_PROT_EXECUTE);
}

static void
inspect_data_abort(uint32_t iss, fault_status_t *fault_code, vm_prot_t *fault_type)
{
	getCpuDatap()->cpu_stat.data_ex_cnt++;
	*fault_code = ISS_DA_FSC(iss);

	/*
	 * Cache maintenance operations always report faults as write access.
	 * Change these to read access, unless they report a permission fault.
	 * Only certain cache maintenance operations (e.g. 'dc ivac') require write
	 * access to the mapping, but if a cache maintenance operation that only requires
	 * read access generates a permission fault, then we will not be able to handle
	 * the fault regardless of whether we treat it as a read or write fault.
	 */
	if ((iss & ISS_DA_WNR) && (!(iss & ISS_DA_CM) || is_permission_fault(*fault_code))) {
		*fault_type = (VM_PROT_READ | VM_PROT_WRITE);
	} else {
		*fault_type = (VM_PROT_READ);
	}
}

#if __has_feature(ptrauth_calls)
static inline uint64_t
fault_addr_bitmask(unsigned int bit_from, unsigned int bit_to)
{
	return ((1ULL << (bit_to - bit_from + 1)) - 1) << bit_from;
}

static inline bool
fault_addr_bit(vm_offset_t fault_addr, unsigned int bit)
{
	return (bool)((fault_addr >> bit) & 1);
}

extern int gARM_FEAT_PAuth2;

/**
 * Determines whether a fault address taken at EL0 contains a PAC error code
 * corresponding to the specified kind of ptrauth key.
 */
static bool
user_fault_addr_matches_pac_error_code(vm_offset_t fault_addr, bool data_key)
{
	bool instruction_tbi = !(get_tcr() & TCR_TBID0_TBI_DATA_ONLY);
	bool tbi = data_key || __improbable(instruction_tbi);

	if (gARM_FEAT_PAuth2) {
		/*
		 * EnhancedPAC2 CPUs don't encode error codes at fixed positions, so
		 * treat all non-canonical address bits like potential poison bits.
		 */
		uint64_t mask = fault_addr_bitmask(T0SZ_BOOT, 54);
		if (!tbi) {
			mask |= fault_addr_bitmask(56, 63);
		}
		return (fault_addr & mask) != 0;
	} else {
		unsigned int poison_shift;
		if (tbi) {
			poison_shift = 53;
		} else {
			poison_shift = 61;
		}

		/* PAC error codes are always in the form key_number:NOT(key_number) */
		bool poison_bit_1 = fault_addr_bit(fault_addr, poison_shift);
		bool poison_bit_2 = fault_addr_bit(fault_addr, poison_shift + 1);
		return poison_bit_1 != poison_bit_2;
	}
}
#endif /* __has_feature(ptrauth_calls) */

static void
handle_pc_align(arm_saved_state_t *ss)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(ss))) {
		panic_with_thread_kernel_state("PC alignment exception from kernel.", ss);
	}

	exc = EXC_BAD_ACCESS;
#if __has_feature(ptrauth_calls)
	if (user_fault_addr_matches_pac_error_code(get_saved_state_pc(ss), false)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */

	codes[0] = EXC_ARM_DA_ALIGN;
	codes[1] = get_saved_state_pc(ss);

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_sp_align(arm_saved_state_t *ss)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(ss))) {
		panic_with_thread_kernel_state("SP alignment exception from kernel.", ss);
	}

	exc = EXC_BAD_ACCESS;
#if __has_feature(ptrauth_calls)
	if (user_fault_addr_matches_pac_error_code(get_saved_state_sp(ss), true)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */

	codes[0] = EXC_ARM_SP_ALIGN;
	codes[1] = get_saved_state_sp(ss);

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_wf_trap(arm_saved_state_t *state)
{
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;
	uint32_t instr = 0;

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

	exc = EXC_BAD_INSTRUCTION;
	codes[0] = EXC_ARM_UNDEFINED;
	codes[1] = instr;

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_fp_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t exc = EXC_ARITHMETIC;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;
	uint32_t instr = 0;

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic_with_thread_kernel_state("Floating point exception from kernel", state);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	/* The floating point trap flags are only valid if TFV is set. */
	if (!fp_exceptions_enabled) {
		exc = EXC_BAD_INSTRUCTION;
		codes[0] = EXC_ARM_UNDEFINED;
	} else if (!(esr & ISS_FP_TFV)) {
		codes[0] = EXC_ARM_FP_UNDEFINED;
	} else if (esr & ISS_FP_UFF) {
		codes[0] = EXC_ARM_FP_UF;
	} else if (esr & ISS_FP_OFF) {
		codes[0] = EXC_ARM_FP_OF;
	} else if (esr & ISS_FP_IOF) {
		codes[0] = EXC_ARM_FP_IO;
	} else if (esr & ISS_FP_DZF) {
		codes[0] = EXC_ARM_FP_DZ;
	} else if (esr & ISS_FP_IDF) {
		codes[0] = EXC_ARM_FP_ID;
	} else if (esr & ISS_FP_IXF) {
		codes[0] = EXC_ARM_FP_IX;
	} else {
		panic("Unrecognized floating point exception, state=%p, esr=%#x", state, esr);
	}

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}



/*
 * handle_alignment_fault_from_user:
 *   state: Saved state
 *
 * Attempts to deal with an alignment fault from userspace (possibly by
 * emulating the faulting instruction).  If emulation failed due to an
 * unservicable fault, the ESR for that fault will be stored in the
 * recovery_esr field of the thread by the exception code.
 *
 * Returns:
 *   -1:     Emulation failed (emulation of state/instr not supported)
 *   0:      Successfully emulated the instruction
 *   EFAULT: Emulation failed (probably due to permissions)
 *   EINVAL: Emulation failed (probably due to a bad address)
 */


static int
handle_alignment_fault_from_user(arm_saved_state_t *state, kern_return_t *vmfr)
{
	int ret = -1;

#pragma unused (state)
#pragma unused (vmfr)

	return ret;
}




static void
handle_sw_step_debug(arm_saved_state_t *state)
{
	thread_t thread = current_thread();
	exception_type_t exc;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t numcodes = 2;

	if (!PSR64_IS_USER(get_saved_state_cpsr(state))) {
		panic_with_thread_kernel_state("SW_STEP_DEBUG exception from kernel.", state);
	}

	// Disable single step and unmask interrupts (in the saved state, anticipating next exception return)
	if (thread->machine.DebugData != NULL) {
		thread->machine.DebugData->uds.ds64.mdscr_el1 &= ~0x1;
	} else {
		panic_with_thread_kernel_state("SW_STEP_DEBUG exception thread DebugData is NULL.", state);
	}

	mask_user_saved_state_cpsr(thread->machine.upcb, 0, PSR64_SS | DAIF_ALL);

	// Special encoding for gdb single step event on ARM
	exc = EXC_BREAKPOINT;
	codes[0] = 1;
	codes[1] = 0;

	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_user_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, expected_fault_handler_t expected_fault_handler)
{
	exception_type_t           exc      = EXC_BAD_ACCESS;
	mach_exception_data_type_t codes[2];
	mach_msg_type_number_t     numcodes = 2;
	thread_t                   thread   = current_thread();

	(void)esr;
	(void)expected_fault_handler;

	if (ml_at_interrupt_context()) {
		panic_with_thread_kernel_state("Apparently on interrupt stack when taking user abort!\n", state);
	}

	thread->iotier_override = THROTTLE_LEVEL_NONE; /* Reset IO tier override before handling abort from userspace */

	if (!is_vm_fault(fault_code) &&
	    thread->t_rr_state.trr_fault_state != TRR_FAULT_NONE) {
		thread_reset_pcs_done_faulting(thread);
	}

	if (is_vm_fault(fault_code)) {
		vm_map_t        map = thread->map;
		vm_offset_t     vm_fault_addr = fault_addr;
		kern_return_t   result = KERN_FAILURE;

		assert(map != kernel_map);

		if (!(fault_type & VM_PROT_EXECUTE)) {
			vm_fault_addr = VM_USER_STRIP_TBI(fault_addr);
		}

		/* check to see if it is just a pmap ref/modify fault */
		if (!is_translation_fault(fault_code)) {
			result = arm_fast_fault(map->pmap,
			    vm_fault_addr,
			    fault_type, (fault_code == FSC_ACCESS_FLAG_FAULT_L3), TRUE);
		}
		if (result != KERN_SUCCESS) {

			{
				/* We have to fault the page in */
				result = vm_fault(map, vm_fault_addr, fault_type,
				    /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, THREAD_ABORTSAFE,
				    /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
			}
		}
		if (thread->t_rr_state.trr_fault_state != TRR_FAULT_NONE) {
			thread_reset_pcs_done_faulting(thread);
		}
		if (result == KERN_SUCCESS || result == KERN_ABORTED) {
			return;
		}

		/*
		 * vm_fault() should never return KERN_FAILURE for page faults from user space.
		 * If it does, we're leaking preemption disables somewhere in the kernel.
		 */
		if (__improbable(result == KERN_FAILURE)) {
			panic("vm_fault() KERN_FAILURE from user fault on thread %p", thread);
		}

		codes[0] = result;
	} else if (is_alignment_fault(fault_code)) {
		kern_return_t vmfkr = KERN_SUCCESS;
		thread->machine.recover_esr = 0;
		thread->machine.recover_far = 0;
		int result = handle_alignment_fault_from_user(state, &vmfkr);
		if (result == 0) {
			/* Successfully emulated, or instruction
			 * copyin() for decode/emulation failed.
			 * Continue, or redrive instruction.
			 */
			thread_exception_return();
		} else if (((result == EFAULT) || (result == EINVAL)) &&
		    (thread->machine.recover_esr == 0)) {
			/*
			 * If we didn't actually take a fault, but got one of
			 * these errors, then we failed basic sanity checks of
			 * the fault address.  Treat this as an invalid
			 * address.
			 */
			codes[0] = KERN_INVALID_ADDRESS;
		} else if ((result == EFAULT) &&
		    (thread->machine.recover_esr)) {
			/*
			 * Since alignment aborts are prioritized
			 * ahead of translation aborts, the misaligned
			 * atomic emulation flow may have triggered a
			 * VM pagefault, which the VM could not resolve.
			 * Report the VM fault error in codes[]
			 */

			codes[0] = vmfkr;
			assertf(vmfkr != KERN_SUCCESS, "Unexpected vmfkr 0x%x", vmfkr);
			/* Cause ESR_EC to reflect an EL0 abort */
			thread->machine.recover_esr &= ~ESR_EC_MASK;
			thread->machine.recover_esr |= (ESR_EC_DABORT_EL0 << ESR_EC_SHIFT);
			set_saved_state_esr(thread->machine.upcb, thread->machine.recover_esr);
			set_saved_state_far(thread->machine.upcb, thread->machine.recover_far);
			fault_addr = thread->machine.recover_far;
		} else {
			/* This was just an unsupported alignment
			 * exception. Misaligned atomic emulation
			 * timeouts fall in this category.
			 */
			codes[0] = EXC_ARM_DA_ALIGN;
		}
	} else if (is_parity_error(fault_code)) {
#if defined(APPLE_ARM64_ARCH_FAMILY)
		/*
		 * Platform errors are handled in sleh_sync before interrupts are enabled.
		 */
#else
		panic("User parity error.");
#endif
	} else {
		codes[0] = KERN_FAILURE;
	}

	codes[1] = fault_addr;
#if __has_feature(ptrauth_calls)
	bool is_data_abort = (ESR_EC(esr) == ESR_EC_DABORT_EL0);
	if (user_fault_addr_matches_pac_error_code(fault_addr, is_data_abort)) {
		exc |= EXC_PTRAUTH_BIT;
	}
#endif /* __has_feature(ptrauth_calls) */
	exception_triage(exc, codes, numcodes);
	__builtin_unreachable();
}

/**
 * Panic because the kernel abort handler tried to apply a recovery handler that
 * isn't inside copyio_recover_table[].
 *
 * @param state original saved-state
 * @param recover invalid recovery handler
 */
__attribute__((noreturn, used))
static void
panic_on_invalid_recovery_handler(arm_saved_state_t *state, struct copyio_recovery_entry *recover)
{
	panic("attempt to set invalid recovery handler %p on kernel saved-state %p", recover, state);
}

static void
handle_kernel_abort_recover(
	arm_saved_state_t              *state,
	uint32_t                        esr,
	vm_offset_t                     fault_addr,
	thread_t                        thread,
	struct copyio_recovery_entry   *_Nonnull recover)
{
	thread->machine.recover_esr = esr;
	thread->machine.recover_far = fault_addr;
#if defined(HAS_APPLE_PAC)
	MANIPULATE_SIGNED_THREAD_STATE(state,
	    "adrp	x6, _copyio_recover_table_end@page		\n"
	    "add	x6, x6, _copyio_recover_table_end@pageoff	\n"
	    "cmp	%[recover], x6					\n"
	    "b.lt	1f						\n"
	    "bl		_panic_on_invalid_recovery_handler		\n"
	    "brk	#0						\n"
	    "1:								\n"
	    "adrp	x6, _copyio_recover_table@page			\n"
	    "add	x6, x6, _copyio_recover_table@pageoff		\n"
	    "cmp	%[recover], x6					\n"
	    "b.ge	1f						\n"
	    "bl		_panic_on_invalid_recovery_handler		\n"
	    "brk	#0						\n"
	    "1:								\n"
	    "ldr	x1, [%[recover], %[CRE_RECOVERY]]		\n"
	    "add	x1, x1, x6					\n"
	    "str	x1, [x0, %[SS64_PC]]				\n",
	    [recover] "r"(recover),
	    [CRE_RECOVERY] "i"(offsetof(struct copyio_recovery_entry, cre_recovery))
	    );
#else
	if ((uintptr_t)recover < (uintptr_t)copyio_recover_table ||
	    (uintptr_t)recover >= (uintptr_t)copyio_recover_table_end) {
		panic_on_invalid_recovery_handler(state, recover);
	}
	saved_state64(state)->pc = copyio_recovery_addr(recover->cre_recovery);
#endif
}

static void
handle_kernel_abort(arm_saved_state_t *state, uint32_t esr, vm_offset_t fault_addr,
    fault_status_t fault_code, vm_prot_t fault_type, expected_fault_handler_t expected_fault_handler)
{
	thread_t thread = current_thread();
	struct copyio_recovery_entry *recover = find_copyio_recovery_entry(state);

#ifdef CONFIG_KERNEL_TAGGING
	/*
	 * If a read/write  access to a tagged address faults over pageable kernel memory
	 * vm_fault() will need to find the right vm entry and offset. Canonicalize the
	 * address here so that the correct comparisons can happen later in the VM code.
	 */
	if (!(fault_type & VM_PROT_EXECUTE) && VM_KERNEL_ADDRESS(fault_addr)) {
		fault_addr = vm_memtag_canonicalize_address(fault_addr);
	}
#endif /* CONFIG_KERNEL_TAGGING */

#ifndef CONFIG_XNUPOST
	(void)expected_fault_handler;
#endif /* CONFIG_XNUPOST */

#if CONFIG_DTRACE
	if (is_vm_fault(fault_code) && thread->t_dtrace_inprobe) { /* Executing under dtrace_probe? */
		if (dtrace_tally_fault(fault_addr)) { /* Should a fault under dtrace be ignored? */
			/*
			 * Point to next instruction, or recovery handler if set.
			 */
			if (recover) {
				handle_kernel_abort_recover(state, esr, fault_addr, thread, recover);
			} else {
				add_saved_state_pc(state, 4);
			}
			return;
		} else {
			panic_with_thread_kernel_state("Unexpected page fault under dtrace_probe", state);
		}
	}
#endif

	if (ml_at_interrupt_context()) {
		panic_with_thread_kernel_state("Unexpected abort while on interrupt stack.", state);
	}

	if (is_vm_fault(fault_code)) {
		kern_return_t result = KERN_FAILURE;
		vm_map_t      map;
		int           interruptible;

		/*
		 * Ensure no faults in the physical aperture. This could happen if
		 * a page table is incorrectly allocated from the read only region
		 * when running with KTRR.
		 */

#ifdef CONFIG_XNUPOST
		if (expected_fault_handler && expected_fault_handler(state)) {
			return;
		}
#endif /* CONFIG_XNUPOST */

		if (fault_addr >= gVirtBase && fault_addr < static_memory_end) {
			panic_with_thread_kernel_state("Unexpected fault in kernel static region\n", state);
		}

		if (VM_KERNEL_ADDRESS(fault_addr) || thread == THREAD_NULL || recover == 0) {
			/*
			 * If no recovery handler is supplied, always drive the fault against
			 * the kernel map.  If the fault was taken against a userspace VA, indicating
			 * an unprotected access to user address space, vm_fault() should fail and
			 * ultimately lead to a panic here.
			 */
			map = kernel_map;
			interruptible = THREAD_UNINT;
		} else {
			map = thread->map;

			/**
			 * In the case that the recovery handler is set (e.g., during copyio
			 * and dtrace probes), we don't want the vm_fault() operation to be
			 * aborted early. Those code paths can't handle restarting the
			 * vm_fault() operation so don't allow it to return early without
			 * creating the wanted mapping.
			 */
			interruptible = (recover) ? THREAD_UNINT : THREAD_ABORTSAFE;
		}

		/* check to see if it is just a pmap ref/modify fault */
		if (!is_translation_fault(fault_code)) {
			result = arm_fast_fault(map->pmap,
			    fault_addr,
			    fault_type, (fault_code == FSC_ACCESS_FLAG_FAULT_L3), FALSE);
			if (result == KERN_SUCCESS) {
				return;
			}
		}

		if (result != KERN_PROTECTION_FAILURE) {
			/*
			 *  We have to "fault" the page in.
			 */
			result = vm_fault(map, fault_addr, fault_type,
			    /* change_wiring */ FALSE, VM_KERN_MEMORY_NONE, interruptible,
			    /* caller_pmap */ NULL, /* caller_pmap_addr */ 0);
		}

		if (result == KERN_SUCCESS) {
			return;
		}

		/*
		 *  If we have a recover handler, invoke it now.
		 */
		if (recover) {
			handle_kernel_abort_recover(state, esr, fault_addr, thread, recover);
			return;
		}

		panic_fault_address = fault_addr;
	} else if (is_alignment_fault(fault_code)) {
		if (recover) {
			handle_kernel_abort_recover(state, esr, fault_addr, thread, recover);
			return;
		}
		panic_with_thread_kernel_state("Unaligned kernel data abort.", state);
	} else if (is_parity_error(fault_code)) {
#if defined(APPLE_ARM64_ARCH_FAMILY)
		/*
		 * Platform errors are handled in sleh_sync before interrupts are enabled.
		 */
#else
		panic_with_thread_kernel_state("Kernel parity error.", state);
#endif
	} else {
		kprintf("Unclassified kernel abort (fault_code=0x%x)\n", fault_code);
	}

	panic_with_thread_kernel_state("Kernel data abort.", state);
}

extern void syscall_trace(struct arm_saved_state * regs);

static void
handle_svc(arm_saved_state_t *state)
{
	int      trap_no = get_saved_state_svc_number(state);
	thread_t thread  = current_thread();
	struct   proc *p;

#define handle_svc_kprintf(x...) /* kprintf("handle_svc: " x) */

#define TRACE_SYSCALL 1
#if TRACE_SYSCALL
	syscall_trace(state);
#endif

	thread->iotier_override = THROTTLE_LEVEL_NONE; /* Reset IO tier override before handling SVC from userspace */

	if (trap_no == (int)PLATFORM_SYSCALL_TRAP_NO) {
		platform_syscall(state);
		panic("Returned from platform_syscall()?");
	}

	mach_kauth_cred_thread_update();

	if (trap_no < 0) {
		switch (trap_no) {
		case MACH_ARM_TRAP_ABSTIME:
			handle_mach_absolute_time_trap(state);
			return;
		case MACH_ARM_TRAP_CONTTIME:
			handle_mach_continuous_time_trap(state);
			return;
		}

		/* Counting perhaps better in the handler, but this is how it's been done */
		thread->syscalls_mach++;
		mach_syscall(state);
	} else {
		/* Counting perhaps better in the handler, but this is how it's been done */
		thread->syscalls_unix++;
		p = get_bsdthreadtask_info(thread);

		assert(p);

		unix_syscall(state, thread, p);
	}
}

static void
handle_mach_absolute_time_trap(arm_saved_state_t *state)
{
	uint64_t now = mach_absolute_time();
	saved_state64(state)->x[0] = now;
}

static void
handle_mach_continuous_time_trap(arm_saved_state_t *state)
{
	uint64_t now = mach_continuous_time();
	saved_state64(state)->x[0] = now;
}


__attribute__((noreturn))
static void
handle_msr_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	if (!is_saved_state64(state)) {
		panic("MSR/MRS trap (ESR 0x%x) from 32-bit state", esr);
	}

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("MSR/MRS trap (ESR 0x%x) from kernel", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

#if __has_feature(ptrauth_calls)
static void
stringify_gpr(unsigned int r, char reg[4])
{
	switch (r) {
	case 29:
		strncpy(reg, "fp", 4);
		return;

	case 30:
		strncpy(reg, "lr", 4);
		return;

	case 31:
		strncpy(reg, "xzr", 4);
		return;

	default:
		snprintf(reg, 4, "x%u", r);
		return;
	}
}

static void
autxx_instruction_extract_reg(uint32_t instr, char reg[4])
{
	unsigned int rd = ARM64_INSTR_AUTxx_RD_GET(instr);
	stringify_gpr(rd, reg);
}

static const char *
autix_system_instruction_extract_reg(uint32_t instr)
{
	unsigned int crm_op2 = ARM64_INSTR_AUTIx_SYSTEM_CRM_OP2_GET(instr);
	if (crm_op2 == ARM64_INSTR_AUTIx_SYSTEM_CRM_OP2_AUTIA1716 ||
	    crm_op2 == ARM64_INSTR_AUTIx_SYSTEM_CRM_OP2_AUTIB1716) {
		return "x17";
	} else {
		return "lr";
	}
}


static void
handle_pac_fail(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_ACCESS | EXC_PTRAUTH_BIT;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_PAC_FAIL};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	if (!is_saved_state64(state)) {
		panic("PAC failure (ESR 0x%x) from 32-bit state", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
#define GENERIC_PAC_FAILURE_MSG_FMT "PAC failure from kernel with %s key"
#define AUTXX_MSG_FMT GENERIC_PAC_FAILURE_MSG_FMT " while authing %s"
#define GENERIC_MSG_FMT GENERIC_PAC_FAILURE_MSG_FMT
#define MAX_PAC_MSG_FMT AUTXX_MSG_FMT

		char msg[strlen(MAX_PAC_MSG_FMT)
		- strlen("%s") + strlen("IA")
		- strlen("%s") + strlen("xzr")
		+ 1];
		ptrauth_key key = (ptrauth_key)(esr & 0x3);
		const char *key_str = ptrauth_key_to_string(key);

		if (ARM64_INSTR_IS_AUTxx(instr)) {
			char reg[4];
			autxx_instruction_extract_reg(instr, reg);
			snprintf(msg, sizeof(msg), AUTXX_MSG_FMT, key_str, reg);
		} else if (ARM64_INSTR_IS_AUTIx_SYSTEM(instr)) {
			const char *reg = autix_system_instruction_extract_reg(instr);
			snprintf(msg, sizeof(msg), AUTXX_MSG_FMT, key_str, reg);
		} else {
			snprintf(msg, sizeof(msg), GENERIC_MSG_FMT, key_str);
		}
		panic_with_thread_kernel_state(msg, state);
	}

	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}
#endif /* __has_feature(ptrauth_calls) */

static void
handle_user_trapped_instruction32(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr;

	if (is_saved_state64(state)) {
		panic("ESR (0x%x) for instruction trapped from U32, but saved state is 64-bit.", esr);
	}

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("ESR (0x%x) for instruction trapped from U32, actually came from kernel?", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

static void
handle_simd_trap(arm_saved_state_t *state, uint32_t esr)
{
	exception_type_t           exception = EXC_BAD_INSTRUCTION;
	mach_exception_data_type_t codes[2]  = {EXC_ARM_UNDEFINED};
	mach_msg_type_number_t     numcodes  = 2;
	uint32_t                   instr     = 0;

	if (PSR64_IS_KERNEL(get_saved_state_cpsr(state))) {
		panic("ESR (0x%x) for SIMD trap from userland, actually came from kernel?", esr);
	}

	COPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));
	codes[1] = instr;

	exception_triage(exception, codes, numcodes);
	__builtin_unreachable();
}

void
sleh_irq(arm_saved_state_t *state)
{
	cpu_data_t * cdp __unused             = getCpuDatap();
#if MACH_ASSERT
	int preemption_level = sleh_get_preemption_level();
#endif


	sleh_interrupt_handler_prologue(state, DBG_INTR_TYPE_OTHER);

#if USE_APPLEARMSMP
	PE_handle_ext_interrupt();
#else
	/* Run the registered interrupt handler. */
	cdp->interrupt_handler(cdp->interrupt_target,
	    cdp->interrupt_refCon,
	    cdp->interrupt_nub,
	    cdp->interrupt_source);
#endif

	entropy_collect();


	sleh_interrupt_handler_epilogue();
#if MACH_ASSERT
	if (preemption_level != sleh_get_preemption_level()) {
		panic("irq handler %p changed preemption level from %d to %d", cdp->interrupt_handler, preemption_level, sleh_get_preemption_level());
	}
#endif
}

void
sleh_fiq(arm_saved_state_t *state)
{
	unsigned int type   = DBG_INTR_TYPE_UNKNOWN;
#if MACH_ASSERT
	int preemption_level = sleh_get_preemption_level();
#endif

#if MONOTONIC_FIQ
	uint64_t pmcr0 = 0, upmsr = 0;
#endif /* MONOTONIC_FIQ */

#if defined(HAS_IPI)
	boolean_t    is_ipi = FALSE;
	uint64_t     ipi_sr = 0;

	if (gFastIPI) {
		MRS(ipi_sr, "S3_5_C15_C1_1");

		if (ipi_sr & ARM64_IPISR_IPI_PENDING) {
			is_ipi = TRUE;
		}
	}

	if (is_ipi) {
		type = DBG_INTR_TYPE_IPI;
	} else
#endif /* defined(HAS_IPI) */
	if (ml_get_timer_pending()) {
		type = DBG_INTR_TYPE_TIMER;
	}
#if MONOTONIC_FIQ
	/* Consult the PMI sysregs last, after IPI/timer
	 * classification.
	 */
	else if (mt_pmi_pending(&pmcr0, &upmsr)) {
		type = DBG_INTR_TYPE_PMI;
	}
#endif /* MONOTONIC_FIQ */

	sleh_interrupt_handler_prologue(state, type);

#if APPLEVIRTUALPLATFORM
	uint64_t iar = __builtin_arm_rsr64("ICC_IAR0_EL1");
#endif

#if defined(HAS_IPI)
	if (type == DBG_INTR_TYPE_IPI) {
		/*
		 * Order is important here: we must ack the IPI by writing IPI_SR
		 * before we call cpu_signal_handler().  Otherwise, there will be
		 * a window between the completion of pending-signal processing in
		 * cpu_signal_handler() and the ack during which a newly-issued
		 * IPI to this CPU may be lost.  ISB is required to ensure the msr
		 * is retired before execution of cpu_signal_handler().
		 */
		MSR("S3_5_C15_C1_1", ARM64_IPISR_IPI_PENDING);
		__builtin_arm_isb(ISB_SY);
		cpu_signal_handler();
	} else
#endif /* defined(HAS_IPI) */
#if MONOTONIC_FIQ
	if (type == DBG_INTR_TYPE_PMI) {
		INTERRUPT_MASKED_DEBUG_START(mt_fiq, DBG_INTR_TYPE_PMI);
		mt_fiq(getCpuDatap(), pmcr0, upmsr);
		INTERRUPT_MASKED_DEBUG_END();
	} else
#endif /* MONOTONIC_FIQ */
	{
		/*
		 * We don't know that this is a timer, but we don't have insight into
		 * the other interrupts that go down this path.
		 */

		cpu_data_t *cdp = getCpuDatap();

		cdp->cpu_decrementer = -1; /* Large */

		/*
		 * ARM64_TODO: whether we're coming from userland is ignored right now.
		 * We can easily thread it through, but not bothering for the
		 * moment (AArch32 doesn't either).
		 */
		INTERRUPT_MASKED_DEBUG_START(rtclock_intr, DBG_INTR_TYPE_TIMER);
		rtclock_intr(TRUE);
		INTERRUPT_MASKED_DEBUG_END();
	}

#if APPLEVIRTUALPLATFORM
	if (iar != GIC_SPURIOUS_IRQ) {
		__builtin_arm_wsr64("ICC_EOIR0_EL1", iar);
		__builtin_arm_isb(ISB_SY);
	}
#endif

	sleh_interrupt_handler_epilogue();
#if MACH_ASSERT
	if (preemption_level != sleh_get_preemption_level()) {
		panic("fiq type %u changed preemption level from %d to %d", type, preemption_level, sleh_get_preemption_level());
	}
#endif
}

void
sleh_serror(arm_context_t *context, uint32_t esr, vm_offset_t far)
{
	task_vtimer_check(current_thread());

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_SERR_ARM, 0) | DBG_FUNC_START,
	    esr, VM_KERNEL_ADDRHIDE(far));
	arm_saved_state_t *state = &context->ss;
#if MACH_ASSERT
	int preemption_level = sleh_get_preemption_level();
#endif

	if (PSR64_IS_USER(get_saved_state_cpsr(state))) {
		/* Sanitize FAR (only if we came from userspace) */
		saved_state64(state)->far = 0;
	}

	ASSERT_CONTEXT_SANITY(context);
	arm64_platform_error(state, esr, far, PLAT_ERR_SRC_ASYNC);
#if MACH_ASSERT
	if (preemption_level != sleh_get_preemption_level()) {
		panic("serror changed preemption level from %d to %d", preemption_level, sleh_get_preemption_level());
	}
#endif
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_SERR_ARM, 0) | DBG_FUNC_END,
	    esr, VM_KERNEL_ADDRHIDE(far));
}

void
mach_syscall_trace_exit(unsigned int retval,
    unsigned int call_number)
{
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    MACHDBG_CODE(DBG_MACH_EXCP_SC, (call_number)) |
	    DBG_FUNC_END, retval, 0, 0, 0, 0);
}

__attribute__((noreturn))
void
thread_syscall_return(kern_return_t error)
{
	thread_t thread;
	struct arm_saved_state *state;

	thread = current_thread();
	state = get_user_regs(thread);

	assert(is_saved_state64(state));
	saved_state64(state)->x[0] = error;

#if MACH_ASSERT
	kern_allocation_name_t
	prior __assert_only = thread_get_kernel_state(thread)->allocation_name;
	assertf(prior == NULL, "thread_set_allocation_name(\"%s\") not cleared", kern_allocation_get_name(prior));
#endif /* MACH_ASSERT */

	if (kdebug_enable) {
		/* Invert syscall number (negative for a mach syscall) */
		mach_syscall_trace_exit(error, (-1) * get_saved_state_svc_number(state));
	}

	thread_exception_return();
}

void
syscall_trace(
	struct arm_saved_state * regs __unused)
{
	/* kprintf("syscall: %d\n", saved_state64(regs)->x[16]);  */
}

static void
sleh_interrupt_handler_prologue(arm_saved_state_t *state, unsigned int type)
{
	const bool is_user = PSR64_IS_USER(get_saved_state_cpsr(state));

	if (is_user == true) {
		/* Sanitize FAR (only if the interrupt occurred while the CPU was in usermode) */
		saved_state64(state)->far = 0;
	}

	recount_enter_interrupt();

	task_vtimer_check(current_thread());

	uint64_t pc = is_user ? get_saved_state_pc(state) :
	    VM_KERNEL_UNSLIDE(get_saved_state_pc(state));

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_START,
	    0, pc, is_user, type);

#if CONFIG_TELEMETRY
	if (telemetry_needs_record) {
		telemetry_mark_curthread(is_user, FALSE);
	}
#endif /* CONFIG_TELEMETRY */
}

static void
sleh_interrupt_handler_epilogue(void)
{
#if KPERF
	kperf_interrupt();
#endif /* KPERF */
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCP_INTR, 0) | DBG_FUNC_END);
	recount_leave_interrupt();
}

void
sleh_invalid_stack(arm_context_t *context, uint32_t esr __unused, vm_offset_t far __unused)
{
	thread_t thread = current_thread();
	vm_offset_t kernel_stack_bottom, sp;

	sp = get_saved_state_sp(&context->ss);
	vm_offset_t kstackptr = (vm_offset_t)thread->machine.kstackptr;
	kernel_stack_bottom = round_page(kstackptr) - KERNEL_STACK_SIZE;

	if ((sp < kernel_stack_bottom) && (sp >= (kernel_stack_bottom - PAGE_SIZE))) {
		panic_with_thread_kernel_state("Invalid kernel stack pointer (probable overflow).", &context->ss);
	}

	panic_with_thread_kernel_state("Invalid kernel stack pointer (probable corruption).", &context->ss);
}


#if DEVELOPMENT || DEBUG
static int trap_handled;
static void
handle_recoverable_kernel_trap(
	__unused void     *tstate,
	uint16_t          comment)
{
	assert(comment == TEST_RECOVERABLE_SOFT_TRAP);

	printf("Recoverable trap handled.\n");
	trap_handled = 1;
}

KERNEL_BRK_DESCRIPTOR_DEFINE(test_desc,
    .type                = KERNEL_BRK_TYPE_TEST,
    .base                = TEST_RECOVERABLE_SOFT_TRAP,
    .max                 = TEST_RECOVERABLE_SOFT_TRAP,
    .options             = KERNEL_BRK_RECOVERABLE,
    .handle_breakpoint   = handle_recoverable_kernel_trap);

static int
recoverable_kernel_trap_test(__unused int64_t in, int64_t *out)
{
	ml_recoverable_trap(TEST_RECOVERABLE_SOFT_TRAP);

	*out = trap_handled;
	return 0;
}

SYSCTL_TEST_REGISTER(recoverable_kernel_trap, recoverable_kernel_trap_test);

#endif
