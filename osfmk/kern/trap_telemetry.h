/*
 * Copyright (c) 2012-2024 Apple Inc. All rights reserved.
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

#ifndef _TRAP_TELEMETRY_H_
#define _TRAP_TELEMETRY_H_

#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>
#include <mach/mach_types.h>
#include <kern/thread.h>

__BEGIN_DECLS
#if XNU_KERNEL_PRIVATE
__enum_decl(trap_telemetry_ca_event_t, uint8_t, {
	/** Do not report this event to CoreAnalytics. */
	TRAP_TELEMETRY_CA_EVENT_NONE = 0,

	TRAP_TELEMETRY_CA_EVENT_KERNEL_BRK = 1,

	TRAP_TELEMETRY_CA_EVENT_INTERNAL = 2,

	/** Used for validation, keep this value last. */
	TRAP_TELEMETRY_CA_EVENT_COUNT,
});

typedef struct {
	uint8_t
	/**
	 * The event to use when reporting to CoreAnalytics.
	 * Encodings specified by trap_telemetry_ca_event_t.
	 */
	    telemetry_ca_event:2,

	/**
	 * Should the trap only be reported once per fault PC, per boot?
	 *
	 * This should be set for traps which may fire very often in order to avoid
	 * overwhelming Core Analytics.
	 *
	 * Note, however, that unsetting this option does not guarantee all traps
	 * will be reported. Repeated traps at the same location within quick
	 * succession will, for example, only be reported once for performance
	 * reasons. Additionally, trap telemetry events may be dropped/fail at any
	 * time due to internal conditions.
	 */
	    report_once_per_site:1;
} trap_telemetry_options_s;

__enum_decl(trap_telemetry_type_t, uint32_t, {
	/* These show up in telemetry, do not renumber */
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_KASAN     = 0,     /* <unrecoverable> KASan violation traps */
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_PTRAUTH   = 1,     /* <unrecoverable> Pointer Auth failure traps */
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_CLANG     = 2,     /* <unrecoverable> Clang sanitizer traps */
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_LIBCXX    = 3,     /* <unrecoverable> Libc++ abort trap*/
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_TELEMETRY = 4,     /* <  recoverable> Soft telemetry collection traps */
	TRAP_TELEMETRY_TYPE_KERNEL_BRK_XNU       = 5,     /* <??recoverable> XNU defined traps */

	/* Failure conditions which may eventually turn into hard errors */
	TRAP_TELEMETRY_TYPE_KERNEL_SOFT_ERROR    = 6,
	TRAP_TELEMETRY_TYPE_SPTM_SOFT_ERROR      = 7,

	TRAP_TELEMETRY_TYPE_KERNEL_BRK_TEST      = ~0u,   /* Development only */
});

/**
 * Report a trap with a given type and code originating from the fault location
 * in SAVED_STATE.
 *
 * Returns true if the event was submitted (or duped) and false on error.
 */
extern bool
trap_telemetry_report_exception(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options,
	void *saved_state);

/**
 * Perform a simulated trap of a given type and code.
 * Fault PC and backtrace will begin at the call site of this function.
 *
 * Returns true if the event was submitted (or duped) and false on error.
 */
extern bool
trap_telemetry_report_simulated_trap(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options);

/**
 * Perform a simulated trap of a given type and code, with given fault PC and
 * backtrace.
 *
 * Only up to TRAP_TELEMETRY_BT_FRAMES frames of backtrace will be used.
 *
 * Returns true if the event was submitted (or duped) and false on error.
 */
extern bool
trap_telemetry_report_simulated_trap_with_backtrace(
	trap_telemetry_type_t trap_type,
	uint64_t trap_code,
	trap_telemetry_options_s options,
	uintptr_t fault_pc,
	uintptr_t *frames,
	size_t frames_valid_count);

/** Initialize the trap telemetry module */
extern void
trap_telemetry_init(void);

/* ~* Breakpoint Telemetry Helpers *~ */

enum kernel_brk_trap_comment {
	/* CLANG (reserved)       : [0x0000 ~ 0x00FF] <Intel only> */
	CLANG_X86_TRAP_START           = 0x0000,
	CLANG_X86_TRAP_BOUND_CHK       = 0x0019, /* bound check fatal trap */
	CLANG_X86_TRAP_END             = 0x00FF,

	/* LIBCXX                 : [0x0800 ~ 0x0800] */
	LIBCXX_TRAP_START              = 0x0800,
	LIBCXX_TRAP_ABORT              = 0x0800, /* libcxx abort() in libcxx_support/stdlib.h */
	LIBCXX_TRAP_END                = 0x0800,

	/* KASAN (kasan-tbi.h)    : [0x0900 ~ 0x093F] <ARM only> */

	/* CLANG (reserved)       : [0x5500 ~ 0x55FF] <ARM only> */
	CLANG_ARM_TRAP_START           = 0x5500,
	CLANG_ARM_TRAP_BOUND_CHK       = 0x5519, /* bound check fatal trap */
	CLANG_ARM_TRAP_END             = 0x55FF,

	/* Software defined       : [0xB000 ~ 0xBFFF] */
	XNU_HARD_TRAP_START            = 0xB000,
	XNU_HARD_TRAP_ASSERT_FAILURE   = 0xBFFC, /* backend for assert() */
	XNU_HARD_TRAP_SAFE_UNLINK      = 0xBFFD, /* queue safe unlinking traps */
	XNU_HARD_TRAP_STRING_CHK       = 0xBFFE, /* read traps in string.h */
	XNU_HARD_TRAP_END              = 0xBFFF,

	/* PTRAUTH (sleh.c)       : [0xC470 ~ 0xC473] <ARM only> */

	/* TELEMETRY              : [0xFF00 ~ 0xFFFE] */
	XNU_SOFT_TRAP_START            = 0xFF00,
	UBSAN_SOFT_TRAP_SIGNED_OF      = 0xFF00, /* ubsan minimal signed overflow*/
	CLANG_SOFT_TRAP_BOUND_CHK      = 0xFF19, /* ml_bound_chk_soft_trap */
	XNU_SOFT_TRAP_STRING_CHK       = 0xFFFE, /* read traps in string.h */
	XNU_SOFT_TRAP_END              = 0xFFFE,

	/* TEST */
	TEST_RECOVERABLE_SOFT_TRAP     = 0xFFFF, /* development only */
};

typedef struct {
	uint8_t
	/** Can this breakpoint be recovered from? */
	    recoverable : 1,
	/** Should this breakpoint be reported to trap telemetry? */
	    enable_trap_telemetry : 1;
	/** If recoverable, the telemetry options  */
	trap_telemetry_options_s telemetry_options;
} brk_telemetry_options_s;

/** Default configuration for fatal breakpoints */
#define BRK_TELEMETRY_OPTIONS_FATAL_DEFAULT \
	(brk_telemetry_options_s) { \
	    .recoverable = false, \
	    .enable_trap_telemetry = false, \
	/* ignored when trap telemetry disabled, but zero init anyways */ \
	    .telemetry_options = {0}, \
	}

/** Default configuration for recoverable breakpoints */
#define BRK_TELEMETRY_OPTIONS_RECOVERABLE_DEFAULT(enable_telemetry) \
	(brk_telemetry_options_s) { \
	    .recoverable = true, \
	    .enable_trap_telemetry = (enable_telemetry), \
	    .telemetry_options = { \
	        .telemetry_ca_event = TRAP_TELEMETRY_CA_EVENT_KERNEL_BRK, \
	/* Different backtraces may be useful, so report all */ \
	        .report_once_per_site = false, \
	    }, \
	}

typedef struct kernel_brk_descriptor {
	trap_telemetry_type_t    type;
	uint16_t                 base;
	uint16_t                 max;
	brk_telemetry_options_s  options;

	const char *(*handle_breakpoint)(void *states, uint16_t comment);
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

/* ~* Kernel Soft Error Telemetry Helpers *~ */

__enum_decl(trap_telemetry_kernel_soft_error_code_t, uint64_t, {
	/* Do not renumber entries -- IDs are used in telemetry */
	TRAP_TELEMETRY_KERNEL_SOFT_ERROR_VM_KERNEL_MAX_ALLOC_SIZE = 0,
});

/**
 * Report a kernel soft error CODE with a backtrace originating at this
 * function's call site.
 *
 * If REPORT_ONCE_PER_SITE is true, events will be deduplicated by call site
 * address and only the first instance at a given site will be reported. For the
 * call site address to be meaningful, this function must be inlined (hence the
 * always_inline attribute).
 */
__unused
__attribute__((always_inline))
static void
trap_telemetry_report_kernel_soft_error(
	trap_telemetry_kernel_soft_error_code_t code,
	bool report_once_per_site)
{
	trap_telemetry_report_simulated_trap(
		TRAP_TELEMETRY_TYPE_KERNEL_SOFT_ERROR,
		(uint64_t)code,
		(trap_telemetry_options_s) {
		.telemetry_ca_event = TRAP_TELEMETRY_CA_EVENT_INTERNAL,
		.report_once_per_site = report_once_per_site
	});
}

#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* _TRAP_TELEMETRY_H_  */
