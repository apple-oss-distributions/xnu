/*
 * Copyright (c) 2012-2013 Apple Inc. All rights reserved.
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

#ifndef _KERNEL_TELEMETRY_H_
#define _KERNEL_TELEMETRY_H_

#include <stdint.h>
#include <sys/cdefs.h>
#include <mach/mach_types.h>
#include <kern/thread.h>

__BEGIN_DECLS

#define TELEMETRY_CMD_TIMER_EVENT 1
#define TELEMETRY_CMD_VOUCHER_NAME 2
#define TELEMETRY_CMD_VOUCHER_STAIN TELEMETRY_CMD_VOUCHER_NAME

enum telemetry_pmi {
	TELEMETRY_PMI_NONE,
	TELEMETRY_PMI_INSTRS,
	TELEMETRY_PMI_CYCLES,
};
#define TELEMETRY_CMD_PMI_SETUP 3

#if XNU_KERNEL_PRIVATE

__options_decl(kernel_brk_options_t, uint32_t, {
	/* Recoverability */
	KERNEL_BRK_UNRECOVERABLE       = 0x00,
	KERNEL_BRK_RECOVERABLE         = 0x01,

	/* Telemetry collection mode */
	KERNEL_BRK_CORE_ANALYTICS      = 0x10,
	KERNEL_BRK_SIMULATED_PANIC     = 0x20, /* Future */
});

#define KERNEL_BRK_TELEMETRY_OPTIONS 0xf0

__enum_decl(kernel_brk_type_t, uint32_t, {
	KERNEL_BRK_TYPE_KASAN,             /* <Unrecoverable> KASan violation traps */
	KERNEL_BRK_TYPE_PTRAUTH,           /* <Unrecoverable> Pointer Auth failure traps */
	KERNEL_BRK_TYPE_CLANG,             /* <Unrecoverable> Clang sanitizer traps */
	KERNEL_BRK_TYPE_LIBCXX,            /* <Unrecoverable> Libc++ abort trap*/
	KERNEL_BRK_TYPE_TELEMETRY,         /* <Rerecoverable> Soft telemetry collection traps */

	KERNEL_BRK_TYPE_TEST,              /* Development only */
});

enum kernel_brk_trap_comment {
	/* CLANG (reserved)       : [0x0000 ~ 0x00FF] <Intel only> */
	CLANG_TRAPS_X86_START          = 0x0000,
	CLANG_BOUND_CHK_TRAP_X86       = 0x0019, /* bound check fatal trap */
	CLANG_TRAPS_X86_END            = 0x00FF,

	/* LIBCXX                 : [0x0800 ~ 0x0800] */
	LIBCXX_TRAPS_START             = 0x0800,
	LIBCXX_ABORT_TRAP              = 0x0800, /* libcxx abort() in libcxx_support/stdlib.h */
	LIBCXX_TRAPS_END               = 0x0800,

	/* KASAN (kasan-tbi.h)    : [0x0900 ~ 0x093F] <ARM only> */

	/* CLANG (reserved)       : [0x5500 ~ 0x56FF] <ARM only> */
	CLANG_TRAPS_ARM_START          = 0x5500,
	CLANG_BOUND_CHK_TRAP_ARM       = 0x5519, /* bound check fatal trap */
	CLANG_TRAPS_ARM_END            = 0X55FF,

	/* PTRAUTH (sleh.c)       : [0xC470 ~ 0xC473] <ARM only> */

	/* TELEMETRY              : [0xFF00 ~ 0xFFFE] */
	TELEMETRY_TRAPS_START          = 0xFF00,
	UBSAN_SIGNED_OVERFLOW_TRAP     = 0xFF00, /* ubsan minimal signed overflow*/
	CLANG_BOUND_CHK_SOFT_TRAP      = 0xFF19, /* ml_bound_chk_soft_trap */
	TELEMETRY_TRAPS_END            = 0xFFFE,

	/* TEST */
	TEST_RECOVERABLE_SOFT_TRAP     = 0xFFFF, /* development only */
};

typedef struct kernel_brk_descriptor {
	kernel_brk_type_t     type;
	uint16_t              base;
	uint16_t              max;
	kernel_brk_options_t  options;

	void (*handle_breakpoint)(void *states, uint16_t comment);
} *kernel_brk_descriptor_t;

extern struct kernel_brk_descriptor brk_descriptors[]
__SECTION_START_SYM("__DATA_CONST", "__brk_desc");

extern struct kernel_brk_descriptor brk_descriptors_end[]
__SECTION_END_SYM("__DATA_CONST", "__brk_desc");

#define KERNEL_BRK_DESCRIPTOR_DEFINE(name, ...) \
__PLACE_IN_SECTION("__DATA_CONST,__brk_desc") \
static const struct kernel_brk_descriptor name = { __VA_ARGS__ };

const static inline struct kernel_brk_descriptor *
find_brk_descriptor_by_comment(uint16_t comment)
{
	for (kernel_brk_descriptor_t des = brk_descriptors; des < brk_descriptors_end; des++) {
		if (comment >= des->base && comment <= des->max) {
			return des;
		}
	}

	return NULL;
}

extern void telemetry_kernel_brk(
	kernel_brk_type_t     type,
	kernel_brk_options_t  options,
	void                  *state,
	uint16_t              comment);

/* boolean_t must be used since variable is loaded from assembly. */
extern volatile boolean_t telemetry_needs_record;

extern void telemetry_init(void);

extern void compute_telemetry(void *);

extern void telemetry_ast(thread_t thread, uint32_t reasons);

extern int telemetry_gather(user_addr_t buffer, uint32_t *length, bool mark);

/* boolean_t must be used since this function is called from assembly. */
extern void telemetry_mark_curthread(boolean_t interrupted_userspace,
    boolean_t pmi);

extern void telemetry_task_ctl(task_t task, uint32_t reason, int enable_disable);
extern void telemetry_task_ctl_locked(task_t task, uint32_t reason, int enable_disable);
extern void telemetry_global_ctl(int enable_disable);

extern int telemetry_timer_event(uint64_t deadline, uint64_t interval, uint64_t leeway);
extern int telemetry_pmi_setup(enum telemetry_pmi pmi_type, uint64_t interval);

#if CONFIG_MACF
extern int telemetry_macf_mark_curthread(void);
#endif

extern void bootprofile_init(void);
extern void bootprofile_wake_from_sleep(void);
extern void bootprofile_get(void **buffer, uint32_t *length);
extern int bootprofile_gather(user_addr_t buffer, uint32_t *length);

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _KERNEL_TELEMETRY_H_ */
