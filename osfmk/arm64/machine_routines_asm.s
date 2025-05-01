/*
 * Copyright (c) 2007-2015 Apple Inc. All rights reserved.
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

#include <machine/asm.h>
#include <arm64/exception_asm.h>
#include <arm64/machine_machdep.h>
#include <arm64/proc_reg.h>
#include <arm/pmap.h>
#include <kern/ticket_lock.h>
#include <pexpert/arm64/board_config.h>
#include <sys/errno.h>
#include "assym.s"

/*
 * Fault recovery.
 *
 * COPYIO_RECOVER_TABLE_SYM is used to delimit an array with those symbols:
 *     struct copyio_recovery_entry copyio_recover_table[];
 *     struct copyio_recovery_entry copyio_recover_table_end[];
 *
 * COPYIO_RECOVER_RANGE <end_addr>, <recovery_addr>
 *    defines a range from the COPYIO_RECOVER_RANGE point to the <end_addr>
 *    which has a recovery point of recovery_addr (defaulting to copyio_error)
 *
 *    This defines a struct of this type:
 *        struct copyio_recovery_entry {
 *            ptrdiff_t cre_start;
 *            ptrdiff_t cre_end;
 *            ptrdiff_t cre_recovery;
 *        };
 *    where the offset are relative to copyio_recover_table.
 */

.macro COPYIO_RECOVER_TABLE_SYM 	sym_name
	.align 3
	.pushsection __TEXT, __copyio_vectors, regular
	.private_extern EXT(\sym_name)
	.globl EXT(\sym_name)
LEXT(\sym_name)
	.popsection
.endmacro

.macro COPYIO_RECOVER_RANGE end_addr, recovery_addr = copyio_error
	.align	3
	.pushsection __TEXT, __copyio_vectors, regular
	.quad	Lcre_start_\@  - _copyio_recover_table
	.quad	\end_addr      - _copyio_recover_table
	.quad	\recovery_addr - _copyio_recover_table
	.popsection
Lcre_start_\@:
.endmacro

	COPYIO_RECOVER_TABLE_SYM	copyio_recover_table


#if defined(HAS_APPLE_PAC)


.macro LOAD_CPU_JOP_KEY	dst, tmp
	mrs		\tmp, TPIDR_EL1
	ldr		\tmp, [\tmp, ACT_CPUDATAP]
	ldr		\dst, [\tmp, CPU_JOP_KEY]
.endmacro

/*
 * uint64_t ml_enable_user_jop_key(uint64_t user_jop_key)
 */
	.align 2
	.globl EXT(ml_enable_user_jop_key)
LEXT(ml_enable_user_jop_key)
	ARM64_PROLOG
#if HAS_PARAVIRTUALIZED_PAC
	mov 	x2, x0
	MOV64	x0, VMAPPLE_PAC_SET_EL0_DIVERSIFIER_AT_EL1
	mov		x1, #1
	hvc		#0
	cbnz		x0, .
	LOAD_CPU_JOP_KEY x0, x1
	ret
#endif /* HAS_PARAVIRTUALIZED_PAC */

/*
 * void ml_disable_user_jop_key(uint64_t user_jop_key, uint64_t saved_jop_state)
 */
	.align 2
	.globl EXT(ml_disable_user_jop_key)
LEXT(ml_disable_user_jop_key)
	ARM64_PROLOG
#if HAS_PARAVIRTUALIZED_PAC
	mov 	x2, x1
	MOV64	x0, VMAPPLE_PAC_SET_EL0_DIVERSIFIER_AT_EL1
	mov		x1, #0
	hvc		#0
	cbnz		x0, .
	ret
#endif /* HAS_PARAVIRTUALIZED_PAC */

#endif /* defined(HAS_APPLE_PAC) */

#if HAS_BP_RET

/*
 * void set_bp_ret(void)
 * Helper function to enable branch predictor state retention
 * across ACC sleep
 */

	.align 2
	.globl EXT(set_bp_ret)
LEXT(set_bp_ret)
	ARM64_PROLOG
	// Load bpret boot-arg
	adrp		x14, EXT(bp_ret)@page
	add		x14, x14, EXT(bp_ret)@pageoff
	ldr		w14, [x14]

	mrs		x13, CPU_CFG
	and		x13, x13, (~(ARM64_REG_ACC_CFG_bpSlp_mask << ARM64_REG_ACC_CFG_bpSlp_shift))
	and		x14, x14, #(ARM64_REG_ACC_CFG_bpSlp_mask)
	orr		x13, x13, x14, lsl #(ARM64_REG_ACC_CFG_bpSlp_shift)
	msr		CPU_CFG, x13

	ret
#endif // HAS_BP_RET

#if HAS_NEX_PG
	.align 2
	.globl EXT(set_nex_pg)
LEXT(set_nex_pg)
	ARM64_PROLOG
	// Skip if this isn't a p-core; NEX powergating isn't available for e-cores
	ARM64_IS_PCORE  x14
	cbz		x14, Lnex_pg_done


Lnex_pg_done:
	ret

#endif // HAS_NEX_PG

/*	uint32_t get_fpscr(void):
 *		Returns (FPSR | FPCR).
 */
	.align	2
	.globl	EXT(get_fpscr)
LEXT(get_fpscr)
	ARM64_PROLOG
#if	__ARM_VFP__
	mrs	x1, FPSR			// Grab FPSR
	mov	x4, #(FPSR_MASK & 0xFFFF)
	mov	x5, #(FPSR_MASK & 0xFFFF0000)
	orr	x0, x4, x5
	and	x1, x1, x0			// Be paranoid, and clear bits we expect to
						// be clear
	mrs	x2, FPCR			// Grab FPCR
	mov	x4, #(FPCR_MASK & 0xFFFF)
	mov	x5, #(FPCR_MASK & 0xFFFF0000)
	orr	x0, x4, x5
	and	x2, x2, x0			// Be paranoid, and clear bits we expect to
						// be clear
	orr	x0, x1, x2			// OR them to get FPSCR equivalent state
#else
	mov	x0, #0
#endif
	ret
	.align	2
	.globl	EXT(set_fpscr)
/*	void set_fpscr(uint32_t value):
 *		Set the FPCR and FPSR registers, based on the given value; a
 *		noteworthy point is that unlike 32-bit mode, 64-bit mode FPSR
 *		and FPCR are not responsible for condition codes.
 */
LEXT(set_fpscr)
	ARM64_PROLOG
#if	__ARM_VFP__
	mov	x4, #(FPSR_MASK & 0xFFFF)
	mov	x5, #(FPSR_MASK & 0xFFFF0000)
	orr	x1, x4, x5
	and	x1, x1, x0			// Clear the bits that don't apply to FPSR
	mov	x4, #(FPCR_MASK & 0xFFFF)
	mov	x5, #(FPCR_MASK & 0xFFFF0000)
	orr	x2, x4, x5
	and	x2, x2, x0			// Clear the bits that don't apply to FPCR
	msr	FPSR, x1			// Write FPCR
	msr	FPCR, x2			// Write FPSR
	dsb	ish				// FPCR requires synchronization
#endif
	ret

/*
 * void update_mdscr(unsigned long clear, unsigned long set)
 *   Clears and sets the specified bits in MDSCR_EL1.
 *
 * Setting breakpoints in EL1 is effectively a KTRR bypass. The ability to do so is
 * controlled by MDSCR.KDE. The MSR to set MDSCR must be present to allow
 * self-hosted user mode debug. Any checks before the MRS can be skipped with ROP,
 * so we need to put the checks after the MRS where they can't be skipped. That
 * still leaves a small window if a breakpoint is set on the instruction
 * immediately after the MRS. To handle that, we also do a check and then set of
 * the breakpoint control registers. This allows us to guarantee that a given
 * core will never have both KDE set and a breakpoint targeting EL1.
 *
 * If KDE gets set, unset it and then panic
 */
	.align 2
	.globl EXT(update_mdscr)
LEXT(update_mdscr)
	ARM64_PROLOG
	mov	x17, #0
	mrs	x16, MDSCR_EL1
	bic	x16, x16, x0
	orr	x16, x16, x1
1:
	bic	x16, x16, #0x2000
	msr	MDSCR_EL1, x16
#if defined(CONFIG_KERNEL_INTEGRITY)
	/*
	 * verify KDE didn't get set (including via ROP)
	 * If set, clear it and then panic
	 */
	tst	x16, #0x2000
	beq	2f
	mov	x17, #1
	b	1b
2:
	cbnz	x17, Lupdate_mdscr_panic
#endif
	ret

Lupdate_mdscr_panic:
	adrp	x0, Lupdate_mdscr_panic_str@page
	add	x0, x0, Lupdate_mdscr_panic_str@pageoff
	b	EXT(panic)
	b	.

Lupdate_mdscr_panic_str:
	.asciz "MDSCR.KDE was set"


/*
 * 	Set MMU Translation Table Base Alternate
 */
	.text
	.align 2
	.globl EXT(set_mmu_ttb_alternate)
LEXT(set_mmu_ttb_alternate)
	ARM64_PROLOG
	dsb		sy
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		EXT(pinst_set_ttbr1)
	mov		lr, x1
#else
	msr		TTBR1_EL1, x0
#endif /* defined(KERNEL_INTEGRITY_KTRR) */
	isb		sy
	ret

#if XNU_MONITOR
	.section __PPLTEXT,__text,regular,pure_instructions
#else
	.text
#endif
	.align 2
	.globl EXT(set_mmu_ttb)
LEXT(set_mmu_ttb)
	ARM64_PROLOG
#if __ARM_KERNEL_PROTECT__
	/* All EL1-mode ASIDs are odd. */
	orr		x0, x0, #(1 << TTBR_ASID_SHIFT)
#endif /* __ARM_KERNEL_PROTECT__ */
	dsb		ish
	msr		TTBR0_EL1, x0
	isb		sy
	ret


#if XNU_MONITOR
	.text
	.align 2
	.globl EXT(ml_get_ppl_cpu_data)
LEXT(ml_get_ppl_cpu_data)
	ARM64_PROLOG
	LOAD_PMAP_CPU_DATA x0, x1, x2
	ret
#endif

/*
 * 	set AUX control register
 */
	.text
	.align 2
	.globl EXT(set_aux_control)
LEXT(set_aux_control)
	ARM64_PROLOG
	msr		ACTLR_EL1, x0
	// Synchronize system
	isb		sy
	ret

#if __ARM_KERNEL_PROTECT__
	.text
	.align 2
	.globl EXT(set_vbar_el1)
LEXT(set_vbar_el1)
	ARM64_PROLOG
#if defined(KERNEL_INTEGRITY_KTRR)
	b		EXT(pinst_set_vbar)
#else
	msr		VBAR_EL1, x0
	ret
#endif
#endif /* __ARM_KERNEL_PROTECT__ */


/*
 *	set translation control register
 */
	.text
	.align 2
	.globl EXT(set_tcr)
LEXT(set_tcr)
	ARM64_PROLOG
#if defined(APPLE_ARM64_ARCH_FAMILY)
#if DEBUG || DEVELOPMENT
	// Assert that T0Z is always equal to T1Z
	eor		x1, x0, x0, lsr #(TCR_T1SZ_SHIFT - TCR_T0SZ_SHIFT)
	and		x1, x1, #(TCR_TSZ_MASK << TCR_T0SZ_SHIFT)
	cbnz	x1, L_set_tcr_panic
#endif /* DEBUG || DEVELOPMENT */
#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */
#if defined(KERNEL_INTEGRITY_KTRR)
	mov		x1, lr
	bl		EXT(pinst_set_tcr)
	mov		lr, x1
#else
	msr		TCR_EL1, x0
#endif /* defined(KERNEL_INTRITY_KTRR) */
	isb		sy
	ret

#if DEBUG || DEVELOPMENT
L_set_tcr_panic:
	PUSH_FRAME
	sub		sp, sp, #16
	str		x0, [sp]
	adr		x0, L_set_tcr_panic_str
	BRANCH_EXTERN panic

L_set_locked_reg_panic:
	PUSH_FRAME
	sub		sp, sp, #16
	str		x0, [sp]
	adr		x0, L_set_locked_reg_panic_str
	BRANCH_EXTERN panic
	b .

L_set_tcr_panic_str:
	.asciz	"set_tcr: t0sz, t1sz not equal (%llx)\n"


L_set_locked_reg_panic_str:
	.asciz	"attempt to set locked register: (%llx)\n"
#endif /* DEBUG || DEVELOPMENT */

/*
 *	MMU kernel virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop)
LEXT(mmu_kvtop)
	ARM64_PROLOG
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)		// Disable all asynchronous exceptions
	at		s1e1r, x0									// Translation Stage 1 EL1
	isb		sy
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_kvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_kvtop_invalid:
	mov		x0, #0										// Return invalid
	ret

/*
 *	MMU user virtual to physical address translation
 */
	.text
	.align 2
	.globl EXT(mmu_uvtop)
LEXT(mmu_uvtop)
	ARM64_PROLOG
	lsr		x8, x0, #56									// Extract top byte
	cbnz	x8, L_mmu_uvtop_invalid						// Tagged pointers are invalid
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)		// Disable all asynchronous exceptions
	at		s1e0r, x0									// Translation Stage 1 EL0
	isb		sy
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_uvtop_invalid					// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits 
	ret
L_mmu_uvtop_invalid:
	mov		x0, #0										// Return invalid
	ret

/*
 *	MMU kernel virtual to physical address preflight write access
 */
	.text
	.align 2
	.globl EXT(mmu_kvtop_wpreflight)
LEXT(mmu_kvtop_wpreflight)
	ARM64_PROLOG
	mrs		x2, DAIF									// Load current DAIF
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)		// Disable all asynchronous exceptions
	at		s1e1w, x0									// Translation Stage 1 EL1
	mrs		x1, PAR_EL1									// Read result
	msr		DAIF, x2									// Restore interrupt state
	tbnz	x1, #0, L_mmu_kvtop_wpreflight_invalid		// Test Translation not valid
	bfm		x1, x0, #0, #11								// Add page offset
	and		x0, x1, #0x0000ffffffffffff					// Clear non-address bits
	ret
L_mmu_kvtop_wpreflight_invalid:
	mov		x0, #0										// Return invalid
	ret

	.text
	.align 2
copyio_error:
	POP_FRAME							// Return the error populated in x0
	ARM64_STACK_EPILOG					// by the exception handler

#if CONFIG_XNUPOST
/*
 * Test function for panic lockdown which can cause a data abort at a well known
 * PC with a copyio recovery handler.
 */
	.text
	.align 2
	.globl EXT(arm64_panic_lockdown_test_copyio)
LEXT(arm64_panic_lockdown_test_copyio)
	ARM64_PROLOG
	COPYIO_RECOVER_RANGE 1f, 2f
	/* RECOVER_RANGE can change code layout, breaking implicit fault PC */
	.globl EXT(arm64_panic_lockdown_test_copyio_fault_pc)
LEXT(arm64_panic_lockdown_test_copyio_fault_pc)
	ldr		x0, [x0]
1:
	ret
2:
	mov		x0, 0xAA
	ret

#endif /* CONFIG_XNUPOST */

/*
 * int _bcopyin(const user_addr_t src, char *dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyin)
LEXT(_bcopyin)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 5f
	/* If len is less than 256 bytes, do 16 bytewise copy */
	cmp		x2, #256
	b.lt	2f
	sub		x2, x2, #256
	/* 256 bytes at a time */
1:
	/* 0-64 bytes */
	ldp		x3, x4, [x0]
	stp		x3, x4, [x1]
	ldp		x5, x6, [x0, #16]
	stp		x5, x6, [x1, #16]
	ldp		x3, x4, [x0, #32]
	stp		x3, x4, [x1, #32]
	ldp		x5, x6, [x0, #48]
	stp		x5, x6, [x1, #48]

	/* 64-128 bytes */
	ldp		x3, x4, [x0, #64]
	stp		x3, x4, [x1, #64]
	ldp		x5, x6, [x0, #80]
	stp		x5, x6, [x1, #80]
	ldp		x3, x4, [x0, #96]
	stp		x3, x4, [x1, #96]
	ldp		x5, x6, [x0, #112]
	stp		x5, x6, [x1, #112]

	/* 128-192 bytes */
	ldp		x3, x4, [x0, #128]
	stp		x3, x4, [x1, #128]
	ldp		x5, x6, [x0, #144]
	stp		x5, x6, [x1, #144]
	ldp		x3, x4, [x0, #160]
	stp		x3, x4, [x1, #160]
	ldp		x5, x6, [x0, #176]
	stp		x5, x6, [x1, #176]

	/* 192-256 bytes */
	ldp		x3, x4, [x0, #192]
	stp		x3, x4, [x1, #192]
	ldp		x5, x6, [x0, #208]
	stp		x5, x6, [x1, #208]
	ldp		x3, x4, [x0, #224]
	stp		x3, x4, [x1, #224]
	ldp		x5, x6, [x0, #240]
	stp		x5, x6, [x1, #240]

	add		x0, x0, #256
	add		x1, x1, #256

	subs	x2, x2, #256
	b.ge	1b
	/* Fixup the len and test for completion */
	adds	x2, x2, #256
	b.eq	5f
2:
	/* If len is less than 16 bytes, just do a bytewise copy */
	cmp		x2, #16
	b.lt	4f
	sub		x2, x2, #16
3:
	/* 16 bytes at a time */
	ldp		x3, x4, [x0], #16
	stp		x3, x4, [x1], #16
	subs	x2, x2, #16
	b.ge	3b
	/* Fixup the len and test for completion */
	adds	x2, x2, #16
	b.eq	5f
4:	/* Bytewise */
	subs	x2, x2, #1
	ldrb	w3, [x0], #1
	strb	w3, [x1], #1
	b.hi	4b
5:
	mov		x0, xzr
	/*
	 * x3, x4, x5 and x6 now contain user-controlled values which may be used to form
	 * addresses under speculative execution past the _bcopyin(); prevent any
	 * attempts by userspace to influence kernel execution by zeroing them out
	 * before we return.
	 */
	mov		x3, xzr
	mov		x4, xzr
	mov		x5, xzr
	mov		x6, xzr
	POP_FRAME
	ARM64_STACK_EPILOG

#if CONFIG_DTRACE
/*
 * int dtrace_nofault_copy8(const char *src, uint32_t *dst)
 */
	.text
	.align 2
	.globl EXT(dtrace_nofault_copy8)
LEXT(dtrace_nofault_copy8)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 1f
	ldrb		w8, [x0]
1:
	strb		w8, [x1]
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int dtrace_nofault_copy16(const char *src, uint32_t *dst)
 */
	.text
	.align 2
	.globl EXT(dtrace_nofault_copy16)
LEXT(dtrace_nofault_copy16)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 1f
	ldrh		w8, [x0]
1:
	strh		w8, [x1]
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG


#endif /* CONFIG_DTRACE */

/*
 * int dtrace_nofault_copy32(const char *src, uint32_t *dst)
 * int _copyin_atomic32(const user_addr_t src, uint32_t *dst)
 */
	.text
	.align 2
#if CONFIG_DTRACE
	.globl EXT(dtrace_nofault_copy32)
LEXT(dtrace_nofault_copy32)
#endif
	.globl EXT(_copyin_atomic32)
LEXT(_copyin_atomic32)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 1f
	ldr		w8, [x0]
1:
	str		w8, [x1]
	mov		x0, #0
	/*
	 * While x8 does contain a user-controlled value at this point, we will
	 * be overwriting it immediately after returning to this asm function's
	 * C wrapper. So, no need to zero it out here.
	 */
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyin_atomic32_wait_if_equals(const user_addr_t src, uint32_t value)
 */
	.text
	.align 2
	.globl EXT(_copyin_atomic32_wait_if_equals)
LEXT(_copyin_atomic32_wait_if_equals)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 2f
	ldxr		w8, [x0]
2:
	cmp		w8, w1
	mov		x0, ESTALE
	b.ne		1f
	mov		x0, #0
	wfe
1:
	clrex
	/*
	 * While x8 does contain a user-controlled value at this point, we will
	 * be overwriting it immediately after returning to this asm function's
	 * C wrapper. So, no need to zero it out here.
	 */
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * int dtrace_nofault_copy64(const char *src, uint32_t *dst)
 * int _copyin_atomic64(const char *src, uint32_t *dst)
 */
	.text
	.align 2
#if CONFIG_DTRACE
	.globl EXT(dtrace_nofault_copy64)
LEXT(dtrace_nofault_copy64)
#endif
	.globl EXT(_copyin_atomic64)
LEXT(_copyin_atomic64)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE Lcopyin_atomic64_common
	ldr		x8, [x0]
Lcopyin_atomic64_common:
	str		x8, [x1]
	mov		x0, #0
	/*
	 * While x8 does contain a user-controlled value at this point, we will
	 * be overwriting it immediately after returning to this asm function's
	 * C wrapper. So, no need to zero it out here.
	 */
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * int _copyout_atomic32(uint32_t u32, user_addr_t dst)
 */
	.text
	.align 2
	.globl EXT(_copyout_atomic32)
LEXT(_copyout_atomic32)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 1f
	str		w0, [x1]
1:
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _copyout_atomic64(uint64_t u64, user_addr_t dst)
 */
	.text
	.align 2
	.globl EXT(_copyout_atomic64)
LEXT(_copyout_atomic64)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 1f
	str		x0, [x1]
1:
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * int _bcopyout(const char *src, user_addr_t dst, vm_size_t len)
 */
	.text
	.align 2
	.globl EXT(_bcopyout)
LEXT(_bcopyout)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 5f
	/* If len is less than 256 bytes, do 16 bytewise copy */
	cmp		x2, #256
	b.lt	2f
	sub		x2, x2, #256
	/* 256 bytes at a time */
1:
	/* 0-64 bytes */
	ldp		x3, x4, [x0]
	stp		x3, x4, [x1]
	ldp		x5, x6, [x0, #16]
	stp		x5, x6, [x1, #16]
	ldp		x3, x4, [x0, #32]
	stp		x3, x4, [x1, #32]
	ldp		x5, x6, [x0, #48]
	stp		x5, x6, [x1, #48]

	/* 64-128 bytes */
	ldp		x3, x4, [x0, #64]
	stp		x3, x4, [x1, #64]
	ldp		x5, x6, [x0, #80]
	stp		x5, x6, [x1, #80]
	ldp		x3, x4, [x0, #96]
	stp		x3, x4, [x1, #96]
	ldp		x5, x6, [x0, #112]
	stp		x5, x6, [x1, #112]

	/* 128-192 bytes */
	ldp		x3, x4, [x0, #128]
	stp		x3, x4, [x1, #128]
	ldp		x5, x6, [x0, #144]
	stp		x5, x6, [x1, #144]
	ldp		x3, x4, [x0, #160]
	stp		x3, x4, [x1, #160]
	ldp		x5, x6, [x0, #176]
	stp		x5, x6, [x1, #176]

	/* 192-256 bytes */
	ldp		x3, x4, [x0, #192]
	stp		x3, x4, [x1, #192]
	ldp		x5, x6, [x0, #208]
	stp		x5, x6, [x1, #208]
	ldp		x3, x4, [x0, #224]
	stp		x3, x4, [x1, #224]
	ldp		x5, x6, [x0, #240]
	stp		x5, x6, [x1, #240]

	add		x0, x0, #256
	add		x1, x1, #256
	subs	x2, x2, #256
	b.ge	1b
	/* Fixup the len and test for completion */
	adds	x2, x2, #256
	b.eq	5f
2:
	/* If len is less than 16 bytes, just do a bytewise copy */
	cmp		x2, #16
	b.lt	4f
	sub		x2, x2, #16
3:
	/* 16 bytes at a time */
	ldp		x3, x4, [x0], #16
	stp		x3, x4, [x1], #16
	subs	x2, x2, #16
	b.ge	3b
	/* Fixup the len and test for completion */
	adds	x2, x2, #16
	b.eq	5f
4:  /* Bytewise */
	subs	x2, x2, #1
	ldrb	w3, [x0], #1
	strb	w3, [x1], #1
	b.hi	4b
5:
	mov		x0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int _bcopyinstr(
 *	  const user_addr_t user_addr,
 *	  char *dst,
 *	  vm_size_t max,
 *	  vm_size_t *actual)
 */
	.text
	.align 2
	.globl EXT(_bcopyinstr)
LEXT(_bcopyinstr)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE Lcopyinstr_done
	mov		x4, #0						// x4 - total bytes copied
Lcopyinstr_loop:
	ldrb	w5, [x0], #1					// Load a byte from the user source
	strb	w5, [x1], #1				// Store a byte to the kernel dest
	add		x4, x4, #1					// Increment bytes copied
	cbz	x5, Lcopyinstr_done	  		// If this byte is null, we're done
	cmp		x4, x2						// If we're out of space, return an error
	b.ne	Lcopyinstr_loop
Lcopyinstr_too_long:
	mov		x5, #ENAMETOOLONG			// Set current byte to error code for later return
Lcopyinstr_done:
	str		x4, [x3]					// Return number of bytes copied
	mov		x0, x5						// Set error code (0 on success, ENAMETOOLONG on failure)
	/*
	 * A malicious userspace has weak control over the range of values held in
	 * x2 based on which path through the kernel was taken to the copyinstr(),
	 * for example:
	 *  - (PSHMNAMLEN + 1) = 32
	 *  - (MAXPATHLEN - 1) = 1023
	 *  - (PAGE_SIZE * 2) = {8192, 32768}
	 *  - etc
	 *
	 * This indirectly determines how much control a malicious userspace has
	 * over the value held in x4 as they choose the length of the string in
	 * the range of [0..x2] inclusive based on the index of the null terminator
	 * (or lack thereof). This in turn controls the value held in x5, though
	 * this is tightly constrained to either 0 or ENAMETOOLONG (i.e. 63) so
	 * is less of a concern.
	 *
	 * The values held in these three registers (x2, x4, and x5) may be used
	 * to form addresses under speculative execution past the _bcopyinstr();
	 * prevent any attempts by userspace to influence kernel execution by
	 * zeroing them out before we return.
	 */
	mov x2, xzr
	mov x4, xzr
	mov x5, xzr
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * int copyinframe(const vm_address_t frame_addr, char *kernel_addr, bool is64bit)
 *
 *	Safely copy sixteen bytes (the fixed top of an ARM64 frame) from
 *	either user or kernel memory, or 8 bytes (AArch32) from user only.
 * 
 *	x0 : address of frame to copy.
 *	x1 : kernel address at which to store data.
 *	w2 : whether to copy an AArch32 or AArch64 frame.
 *	x3 : temp
 *	x5 : temp (kernel virtual base)
 *	x9 : temp
 *	x10 : old recovery function (set by SET_RECOVERY_HANDLER)
 *	x12, x13 : backtrace data
 *	x16 : thread pointer (set by SET_RECOVERY_HANDLER)
 *
 */
	.text
	.align 2
	.globl EXT(copyinframe)
LEXT(copyinframe)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE Lcopyinframe_done
	cbnz	w2, Lcopyinframe64 		// Check frame size
	adrp	x5, EXT(gVirtBase)@page // For 32-bit frame, make sure we're not trying to copy from kernel
	add		x5, x5, EXT(gVirtBase)@pageoff
	ldr		x5, [x5]
	cmp     x5, x0				// See if address is in kernel virtual range
	b.hi	Lcopyinframe32			// If below kernel virtual range, proceed.
	mov		w0, #EFAULT		// Should never have a 32-bit frame in kernel virtual range
	b		Lcopyinframe_done		

Lcopyinframe32:
	ldr		x12, [x0]			// Copy 8 bytes
	str		x12, [x1]
	mov 	w0, #0					// Success
	b		Lcopyinframe_done

Lcopyinframe64:
	ldr		x3, =VM_MIN_KERNEL_ADDRESS		// Check if kernel address
	orr		x9, x0, ARM_TBI_USER_MASK		// Hide tags in address comparison
	cmp		x9, x3					// If in kernel address range, skip tag test
	b.hs	Lcopyinframe_valid
	tst		x0, ARM_TBI_USER_MASK			// Detect tagged pointers
	b.eq	Lcopyinframe_valid
	mov		w0, #EFAULT				// Tagged address, fail
	b		Lcopyinframe_done
Lcopyinframe_valid:
	ldp		x12, x13, [x0]			// Copy 16 bytes
	stp		x12, x13, [x1]
	mov 	w0, #0					// Success

Lcopyinframe_done:
	POP_FRAME
	ARM64_STACK_EPILOG


/*
 * hw_lck_ticket_t
 * hw_lck_ticket_reserve_orig_allow_invalid(hw_lck_ticket_t *lck
 * #if KASAN_TBI
 *     , const uint8_t *tag_addr
 * #endif
 * )
 */
	.text
	.align 2
	.private_extern EXT(hw_lck_ticket_reserve_orig_allow_invalid)
	.globl EXT(hw_lck_ticket_reserve_orig_allow_invalid)
LEXT(hw_lck_ticket_reserve_orig_allow_invalid)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	COPYIO_RECOVER_RANGE 7f, 9f

	mov		x8, x0
	mov		w9, #HW_LCK_TICKET_LOCK_INC_WORD
1:
#if defined(__ARM_ARCH_8_2__) && !KASAN_TBI
	ldr 		w0, [x8]
#else
	ldaxr		w0, [x8]
#endif
2:
	tbz		w0, #HW_LCK_TICKET_LOCK_VALID_BIT, 9f /* lock valid ? */

	add		w11, w0, w9
#if defined(__ARM_ARCH_8_2__) && !KASAN_TBI
	mov		w12, w0
	casa		w0, w11, [x8]
	cmp		w12, w0
	b.ne		2b
#else /* __ARM_ARCH_8_2__ && !KASAN_TBI */
#if KASAN_TBI
	/*
	 * Memory tagging introduces a further scenario that can lead to an invalid
	 * acquire, which is the case in which the try address doesn't match the
	 * allocated tag (because it has cycled to another allocation). With hardware
	 * memory tagging, this would lead to a fault and get caught by the recovery handler.
	 *
	 * With KASAN_TBI software emulation of memory tagging, we need to explicitly
	 * emulate a tag check. This is no longer an atomic operation, but we are
	 * in the middle of a ldaxr / stxr pair, so we'd catch a transition underneath to
	 * invalid because the store tag would mismatch.
	 */
	ldrb		w13, [x1]
	ubfx		x14, x8, #56, #8
	cmp		w13, w14
	b.ne		9f
#endif /* KASAN_TBI */
	stxr		w12, w11, [x8]
	cbnz		w12, 1b
#endif /* __ARM_ARCH_8_2__ && !KASAN_TBI */

7:
	POP_FRAME
	ARM64_STACK_EPILOG

9: /* invalid */
#if !defined(__ARM_ARCH_8_2__)
	clrex
#endif
	mov		w0, #0
	POP_FRAME
	ARM64_STACK_EPILOG

/*
 * uint32_t arm_debug_read_dscr(void)
 */
	.text
	.align 2
	.globl EXT(arm_debug_read_dscr)
LEXT(arm_debug_read_dscr)
	ARM64_PROLOG
	PANIC_UNIMPLEMENTED

/*
 * void arm_debug_set_cp14(arm_debug_state_t *debug_state)
 *
 *     Set debug registers to match the current thread state
 *      (NULL to disable).  Assume 6 breakpoints and 2
 *      watchpoints, since that has been the case in all cores
 *      thus far.
 */
       .text
       .align 2
       .globl EXT(arm_debug_set_cp14)
LEXT(arm_debug_set_cp14)
	ARM64_PROLOG
	PANIC_UNIMPLEMENTED

#if defined(APPLE_ARM64_ARCH_FAMILY)
/*
 * Note: still have to ISB before executing wfi!
 *
 * x0 = boolean deep_sleep
 * x1 = unsigned int cpu
 * x2 = uint64_t entry_pa
 */
	.text
	.align 2
	.globl EXT(arm64_prepare_for_sleep)
LEXT(arm64_prepare_for_sleep)
	ARM64_PROLOG
	PUSH_FRAME

#if APPLEVIRTUALPLATFORM

#define PSCI_FN_ID_CPU_OFF			0x84000002
#define PSCI_FN_ID_SYSTEM_SUSPEND	0xC400000E

	/*
	 * For a VM, it always powers off CPUs individually, including the boot cpu.
	 * If the boot cpu is going into deep sleep, power off the system instead.
	 */
	cbz		x0, vm_sleep_individual_cpu  // skip if not deep_sleep
	cbnz	x1, vm_sleep_individual_cpu  // skip if not boot cpu
vm_sleep_system:
	MOV64	x0, PSCI_FN_ID_SYSTEM_SUSPEND
	mov		x1, x2
	hvc		0
	b		.

vm_sleep_individual_cpu:
	MOV64	x0, PSCI_FN_ID_CPU_OFF
	hvc		0
	b		.

#endif /* APPLEVIRTUALPLATFORM */


#if HAS_CLUSTER
	cbnz		x0, is_deep_sleep                           // Skip if deep_sleep == true


#if !NO_CPU_OVRD
	// Mask FIQ and IRQ to avoid spurious wakeups
	mrs		x9, CPU_OVRD
	and		x9, x9, #(~(ARM64_REG_CYC_OVRD_irq_mask | ARM64_REG_CYC_OVRD_fiq_mask))
	mov		x10, #(ARM64_REG_CYC_OVRD_irq_disable | ARM64_REG_CYC_OVRD_fiq_disable)
	orr		x9, x9, x10
	msr		CPU_OVRD, x9
	isb
#endif
is_deep_sleep:
#endif

	cbz		x0, not_deep_sleep                              // Skip if deep_sleep == false
#if   __ARM_GLOBAL_SLEEP_BIT__
	// Enable deep sleep
	mrs		x1, ACC_OVRD
	orr		x1, x1, #(ARM64_REG_ACC_OVRD_enDeepSleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep)
#if HAS_RETENTION_STATE
	orr		x1, x1, #(ARM64_REG_ACC_OVRD_disPioOnWfiCpu)
#endif
	msr		ACC_OVRD, x1

#if defined(APPLEMONSOON)
	// Skye has an ACC_OVRD register for EBLK and PBLK. Same bitfield layout for these bits
	mrs		x1, EBLK_OVRD
	orr		x1, x1, #(ARM64_REG_ACC_OVRD_enDeepSleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_disL2Flush4AccSlp_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnSRM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnSRM_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2TrDnLnk_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2TrDnLnk_deepsleep)
	and		x1, x1, #(~(ARM64_REG_ACC_OVRD_ok2PwrDnCPM_mask))
	orr		x1, x1, #(  ARM64_REG_ACC_OVRD_ok2PwrDnCPM_deepsleep)
	msr		EBLK_OVRD, x1

#endif

#else
#if defined(APPLETYPHOON) || defined(APPLETWISTER)
	// Enable deep sleep
	mov		x1, ARM64_REG_CYC_CFG_deepSleep
	msr		CPU_CFG, x1
#endif
#endif

not_deep_sleep:
#if !NO_CPU_OVRD
	// Set "OK to power down" (<rdar://problem/12390433>)
	mrs		x9, CPU_OVRD
	orr		x9, x9, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_down)
#if HAS_RETENTION_STATE
	orr		x9, x9, #(ARM64_REG_CYC_OVRD_disWfiRetn)
#endif
	msr		CPU_OVRD, x9
#endif

	EXEC_END

Lwfi_inst:
	dsb		sy
	isb		sy
	wfi
	b		Lwfi_inst

/*
 * Force WFI to use clock gating only
 *
 */	
	.text
	.align 2
	.globl EXT(arm64_force_wfi_clock_gate)
LEXT(arm64_force_wfi_clock_gate)
	ARM64_STACK_PROLOG
	PUSH_FRAME

#if !NO_CPU_OVRD
	mrs		x0, CPU_OVRD
	orr		x0, x0, #(ARM64_REG_CYC_OVRD_ok2pwrdn_force_up)
	msr		CPU_OVRD, x0
#endif
	
	POP_FRAME
	ARM64_STACK_EPILOG


#if HAS_RETENTION_STATE
	.text
	.align 2
	.globl EXT(arm64_retention_wfi)
LEXT(arm64_retention_wfi)
	ARM64_PROLOG
	wfi
	cbz		lr, Lwfi_retention	// If lr is 0, we entered retention state and lost all GPRs except sp and pc
	ret					// Otherwise just return to cpu_idle()
Lwfi_retention:
	mov		x0, #1
	bl		EXT(ClearIdlePop)
	mov		x0, #0 
	bl		EXT(cpu_idle_exit)	// cpu_idle_exit(from_reset = FALSE)
	b		.			// cpu_idle_exit() should never return
#endif



#else /* !defined(APPLE_ARM64_ARCH_FAMILY) */
	.text
	.align 2
	.globl EXT(arm64_prepare_for_sleep)
LEXT(arm64_prepare_for_sleep)
	ARM64_PROLOG
	PUSH_FRAME
Lwfi_inst:
	dsb		sy
	isb		sy
	wfi
	b		Lwfi_inst

/*
 * Force WFI to use clock gating only
 * Note: for non-Apple device, do nothing.
 */	
	.text
	.align 2
	.globl EXT(arm64_force_wfi_clock_gate)
LEXT(arm64_force_wfi_clock_gate)
	ARM64_PROLOG
	PUSH_FRAME
	nop
	POP_FRAME

#endif /* defined(APPLE_ARM64_ARCH_FAMILY) */

/*
 * void arm64_replace_bootstack(cpu_data_t *cpu_data)
 *
 * This must be called from a kernel thread context running on the boot CPU,
 * after setting up new exception stacks in per-CPU data. That will guarantee
 * that the stack(s) we're trying to replace aren't currently in use.  For
 * KTRR-protected devices, this must also be called prior to VM prot finalization
 * and lockdown, as updating SP1 requires a sensitive instruction.
 */
	.text
	.align 2
	.globl EXT(arm64_replace_bootstack)
LEXT(arm64_replace_bootstack)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	// Set the exception stack pointer
	ldr		x0, [x0, CPU_EXCEPSTACK_TOP]
	mrs		x4, DAIF					// Load current DAIF; use x4 as pinst may trash x1-x3
	msr		DAIFSet, #(DAIFSC_STANDARD_DISABLE)		// Disable all asynchronous exceptions
	// Set SP_EL1 to exception stack
#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	mov		x1, lr
	bl		EXT(pinst_spsel_1)
	mov		lr, x1
#else
	msr		SPSel, #1
#endif
	mov		sp, x0
	msr		SPSel, #0
	msr		DAIF, x4					// Restore interrupt state
	POP_FRAME
	ARM64_STACK_EPILOG

#ifdef MONITOR
/*
 * unsigned long monitor_call(uintptr_t callnum, uintptr_t arg1,
 							  uintptr_t arg2, uintptr_t arg3)
 *
 * Call the EL3 monitor with 4 arguments in registers
 * The monitor interface maintains the same ABI as the C function call standard.  Callee-saved
 * registers are preserved, temporary registers are not.  Parameters and results are passed in
 * the usual manner.
 */
	.text
	.align 2
	.globl EXT(monitor_call)
LEXT(monitor_call)
	ARM64_PROLOG
	smc 	0x11
	ret
#endif

#ifdef HAS_APPLE_PAC
/*
 * COMPUTE_THREAD_STATE_HASH
 *
 * Computes the thread state hash by hashing critical state with gkey.  The hash is
 * diversified by &arm_saved_state_t.
 *
 * To fix rdar://118357645 we bind every step of the sequence to both the PC it
 * belongs to and to the EL level it came from.
 *
 * Special ABI: preserves all registers, except x1, x2 and x17
 * x1 is used to return the result.
 */
.macro COMPUTE_THREAD_STATE_HASH
	/*
	 * Mask off the carry flag for EL0 states so we don't need to re-sign when
	 * that flag is touched by the system call return path.
	 */
	tst		x2, PSR64_MODE_EL_MASK
	b.ne	1f
	bic		x2, x2, PSR_CF
1:

	/*
	 * first pacga, bind with context << 4 || PACGA_TAG
	 */
	lsl		x17, x0, #4
	orr		x17, x17, PACGA_TAG_THREAD
	pacga	x17, x17, x1				/* pc hash = hash(context, pc) */

	/*
	 * pacga puts the result in the upper half of x1. We use the lower half
	 * to add the data to bind the hash to PC, EL and PACGA_TAG
	 *
	 * binding state will be 27 bits of PC, 2 bits of EL, 3 bits of PACGA_TAG
	 * we have reserved both 0b0001 and 0b1001 for thread state tagging.
	 * So we can use the top bit of the tag to store part of EL, and use
	 * more bits of PC.
	 */

	lsl		x1, x1, #2
	bfxil	x1, x2, PSR64_MODE_EL_SHIFT, #2
	lsl		x1, x1, #3
	orr		x1, x1, PACGA_TAG_THREAD


	bfxil	x17, x1, #0, #32
	pacga	x17, x17, x2				/* SPSR(x2) hash (gkey + pc hash) */

	bfxil   x17, x1, #0, #32			/* add binding state */
	pacga	x17, x17, x3				/* LR(x3) Hash (gkey + spsr hash) */

	bfxil   x17, x1, #0, #32			/* add binding state */
	pacga	x17, x17, x4				/* X16(x4) hash (gkey + lr hash) */

	bfxil   x17, x1, #0, #32			/* add binding state */
	pacga	x1, x17, x5					/* X17(x5) hash (gkey + x16 hash) */
.endm

/*
 * CHECK_THREAD_STATE_INTERRUPTS
 *
 * Branches to Lintr_enabled_panic if interrupts are in an unexpected state.
 */
.macro CHECK_THREAD_STATE_INTERRUPTS tmp
	mrs		\tmp, DAIF
	tbz		\tmp, #DAIF_IRQF_SHIFT, Lintr_enabled_panic
	mrs		\tmp, SPSel
	tbz		\tmp, #0, Lintr_enabled_panic
.endm

/**
 * void ml_sign_thread_state(arm_saved_state_t *ss, uint64_t pc,
 *							 uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							 uint64_t x17)
 *
 * ml_sign_thread_state uses a custom calling convention that
 * preserves all registers except x1, x2 and x17.
 */
	.text
	.align 2
	.globl EXT(ml_sign_thread_state)
LEXT(ml_sign_thread_state)
	ARM64_PROLOG
	COMPUTE_THREAD_STATE_HASH
	str		x1, [x0, SS64_JOPHASH]
#if DEBUG || DEVELOPMENT
	CHECK_THREAD_STATE_INTERRUPTS tmp=x1
#endif
	ret

/**
 * void ml_check_signed_state(arm_saved_state_t *ss, uint64_t pc,
 *							  uint32_t cpsr, uint64_t lr, uint64_t x16,
 *							  uint64_t x17)
 *
 * ml_check_signed_state uses a custom calling convention that
 * preserves all registers except x1, x2, x16 and x17.
 */
	.text
	.align 2
	.globl EXT(ml_check_signed_state)
LEXT(ml_check_signed_state)
	ARM64_PROLOG
	CHECK_THREAD_STATE_INTERRUPTS tmp=x16
	ldr		x16, [x0, SS64_JOPHASH]
	COMPUTE_THREAD_STATE_HASH
	cmp		x1, x16
	b.ne	Lcheck_hash_panic
	ret
Lcheck_hash_panic:
	/*
	 * ml_check_signed_state normally doesn't set up a stack frame, since it
	 * needs to work in the face of attackers that can modify the stack.
	 * However we lazily create one in the panic path: at this point we're
	 * *only* using the stack frame for unwinding purposes, and without one
	 * we'd be missing information about the caller.
	 */
	mov		x1, x0
	adr		x0, Lcheck_hash_str
	PUSH_FRAME
	CALL_EXTERN panic_with_thread_kernel_state
	brk		#0

Lcheck_hash_str:
	.asciz "JOP Hash Mismatch Detected (PC, CPSR, or LR corruption)"

	.align 2
Lintr_enabled_panic:
	PUSH_FRAME
	adr		x0, Lintr_enabled_str
	CALL_EXTERN panic
	brk		#0
Lintr_enabled_str:
	/*
	 * Please see the "Signing spilled register state" section of doc/pac.md
	 * for an explanation of why this is bad and how it should be fixed.
	 */
	.asciz "Signed thread state manipulated with interrupts enabled"

/**
 * void ml_auth_thread_state_invalid_cpsr(arm_saved_state_t *ss)
 *
 * Panics due to an invalid CPSR value in ss.
 */
	.text
	.align 2
	.globl EXT(ml_auth_thread_state_invalid_cpsr)
LEXT(ml_auth_thread_state_invalid_cpsr)
	ARM64_STACK_PROLOG
	PUSH_FRAME
	mov		x1, x0
	adr		x0, Linvalid_cpsr_str
	CALL_EXTERN panic_with_thread_kernel_state
	brk		#0

Linvalid_cpsr_str:
	.asciz "Thread state corruption detected (PE mode == 0)"

/**
 * uint64_t ml_pac_safe_interrupts_disable(void)
 *
 * Disable interrupts using only PAC-safe registers.
 *
 * ml_pac_safe_interrupts_disable's return value should be passed to a
 * complementary ml_pac_safe_interrupts_restore call.
 *
 * ml_pac_safe_interrupts_{disable,restore} are intended specifically for
 * PAC-related callers that need to disable interrupts before manipulating
 * signed thread state.  Other callers should use ml_set_interrupts_enabled
 * instead.
 *
 * @return the previous interrupt state
 */
	.text
	.align 2
	.globl EXT(ml_pac_safe_interrupts_disable)
LEXT(ml_pac_safe_interrupts_disable)
	ARM64_PROLOG
	mrs		x16, DAIF
	and		x17, x16, DAIF_STANDARD_DISABLE
	cmp		x17, DAIF_STANDARD_DISABLE
	b.eq	Lalready_disabled
	msr		DAIFSet, DAIFSC_STANDARD_DISABLE
Lalready_disabled:
	mov		x0, x16
	ret

/**
 * void ml_pac_safe_interrupts_restore(uint64_t intr)
 *
 * Restores the interrupt state returned by ml_pac_safe_interrupts_disable().
 *
 * @param intr the previous interrupt state
 */
	.text
	.align 2
	.globl EXT(ml_pac_safe_interrupts_restore)
LEXT(ml_pac_safe_interrupts_restore)
	ARM64_PROLOG
	msr		DAIF, x0
	ret

#endif /* HAS_APPLE_PAC */

	.text
	.align 2
	.globl EXT(fill32_dczva)
LEXT(fill32_dczva)
	ARM64_PROLOG
0:
	dc	zva, x0
	add	x0, x0, #64
	subs	x1, x1, #64
	b.hi	0b
	ret

	.text
	.align 2
	.globl EXT(fill32_nt)
LEXT(fill32_nt)
	ARM64_PROLOG
	dup.4s	v0, w2
0:
	stnp	q0, q0, [x0]
	stnp	q0, q0, [x0, #0x20]
	stnp	q0, q0, [x0, #0x40]
	stnp	q0, q0, [x0, #0x60]
	add	x0, x0, #128
	subs	x1, x1, #128
	b.hi	0b
	ret

#if defined(HAS_APPLE_PAC)


/*
 * ptrauth_utils_sign_blob_generic(const void * ptr, size_t len_bytes, uint64_t data, int flags)
 *
 * See "Signing arbitrary data blobs" of doc/pac.md
 */
	.text
	.align 2
	.globl EXT(ptrauth_utils_sign_blob_generic)
LEXT(ptrauth_utils_sign_blob_generic)
	ARM64_STACK_PROLOG
	PUSH_FRAME

	cbz		x0, Lsign_ret
	lsr		x10, x1, #0x3		// x10 = rounds - number of full words
	and		x9, x1, #0x7		// x9 = ntrailing - number trailing bytes
	tst		w3, #0x1			// Check if PTRAUTH_ADDR_DIVERSIFY is set in flags
	csel	x17, xzr, x0, eq	// If yes, mix the diversifier with the address
	eor		x17, x17, x2
	mov		w16, #0xde43		// Prologue cookie: ptrauth_string_discriminator("ptrauth_utils_sign_blob_generic-prologue") | 0x01

	// x16 is used to accumulate the signature because it is interrupt-safe
	lsl		x16, x16, 4
	orr		x16, x16, PACGA_TAG_BLOB
	pacga	x16, x16, x1		// Mix in the data length. This helps distinguish e.g. a signature of 2 zeros from a signature of 3 zeros.
	orr		x16, x16, PACGA_TAG_BLOB
	pacga	x16, x16, x17		// Mix in the diversifier
	cbz		x10, Lsmall_size	// Handle the case of < 8 bytes

	// Handle as many full 64-bit words as possible first.
Lloop_rounds:
	ldr		x17, [x0], #0x8		// Load the next full 64-bit value
	orr		x16, x16, PACGA_TAG_BLOB
	pacga	x16, x16, x17		// Mix in the next 8 bytes of data
	subs	x10, x10, #0x1
	b.ne	Lloop_rounds
	cbz		x9, Lepilogue_cookie	// If there are no trailing bytes, skip to the epilogue

	/*
	 * Handle the case of between 1 and 7 trailing bytes. x9 contains the
	 * number of trailing bytes, but we convert it to bits so we can use it
	 * as a bitshift to accumulate the trailing bytes into x17. We use x10
	 * as the bit index since it is guaranteed to be zero at this point.
	 * Bytes are accumulated with the first byte read in the LSB position
	 * (just as would be the case if we performed a little-endian 64-bit
	 * read).
	 */
Lsmall_size:
	lsl		x9, x9, #0x3		// x9 = ntrailing_bits, x10 = current bit index (0 at entry)
	mov		x17, #0				// x17 = trailing bytes accumulator
Lloop_ntrailing:
	ldrb	w12, [x0], #0x1		// Load the next trailing byte
	lsl		x12, x12, x10		// Shift it by how many bits we've read so far to align it with its proper slot in x17
	orr		x17, x17, x12		// Or the byte into x17
	add		x10, x10, #0x8		// Advance x10 by 8 bits
	cmp		x9, x10				// Check if we're done with all bytes
	b.ne	Lloop_ntrailing
	orr		x16, x16, PACGA_TAG_BLOB
	pacga	x16, x16, x17		// Mix in the accumulated trailing bytes

Lepilogue_cookie:
	mov		w17, #0x9a2d		// Epilogue cookie: ptrauth_string_discriminator("ptrauth_utils_sign_blob_generic-epilogue") | 0x01
	orr		x16, x16, PACGA_TAG_BLOB
	pacga	x0, x16, x17		// Mix in the epilogue cookie

Lsign_ret:
	POP_FRAME
	ARM64_STACK_EPILOG

#endif // defined(HAS_APPLE_PAC)

    /* THIS MUST STAY LAST IN THIS FILE */
	COPYIO_RECOVER_TABLE_SYM	copyio_recover_table_end

/* vim: set sw=4 ts=4: */
