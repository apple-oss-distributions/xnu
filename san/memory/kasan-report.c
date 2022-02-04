/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <string.h>
#include <kern/thread.h>
#include <mach/mach_vm.h>
#include <mach/mach_types.h>
#include <vm/vm_map.h>
#include <libkern/libkern.h>
#include <kern/backtrace.h>

#include "kasan_internal.h"

bool report_suppressed_checks = false;
/*
 * KASAN violation reporting. Decode the access violation and pretty print
 * the violation reason in the panic message.
 */
#define CRASH_CONTEXT_BEFORE 5
#define CRASH_CONTEXT_AFTER  5
#define CONTEXT_BLOCK_SIZE       16
#define CONTEXT_BLOCK_MASK       (CONTEXT_BLOCK_SIZE - 1)

/* Pretty print the shadow table describing memory around the faulting access */
static size_t
kasan_dump_shadow(uptr p, char *buf, size_t len)
{
	int i, j;
	size_t n = 0;
	int before = CRASH_CONTEXT_BEFORE;
	int after = CRASH_CONTEXT_AFTER;

	uptr shadow = (uptr)SHADOW_FOR_ADDRESS(p);
	uptr shadow_p = shadow;
	uptr shadow_page = vm_map_round_page(shadow_p, PAGE_MASK);

	/* rewind to start of context block */
	shadow &= ~((uptr)CONTEXT_BLOCK_MASK);
	shadow -= CONTEXT_BLOCK_SIZE * before;

	n += scnprintf(buf + n, len - n,
	    " Shadow             0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f\n");

	for (i = 0; i < 1 + before + after; i++, shadow += CONTEXT_BLOCK_SIZE) {
		if ((vm_map_round_page(shadow, PAGE_MASK) != shadow_page) && !kasan_is_shadow_mapped(shadow)) {
			/* avoid unmapped shadow when crossing page boundaries */
			continue;
		}

		n += scnprintf(buf + n, len - n, " %16lx:", shadow);

		char *left = " ";
		char *right;

		for (j = 0; j < CONTEXT_BLOCK_SIZE; j++) {
			uint8_t *x = (uint8_t *)(shadow + j);

			right = " ";
			if ((uptr)x == shadow_p) {
				left = "[";
				right = "]";
			} else if ((uptr)(x + 1) == shadow_p) {
				right = "";
			}

			n += scnprintf(buf + n, len - n, "%s%02x%s", left, (unsigned)*x, right);
			left = "";
		}
		n += scnprintf(buf + n, len - n, "\n");
	}

	n += scnprintf(buf + n, len - n, "\n");
	return n;
}

#define KASAN_REPORT_BUFSIZE    4096
static void
kasan_report_internal(uptr p, uptr width, access_t access, violation_t reason, bool dopanic)
{
	const size_t len = KASAN_REPORT_BUFSIZE;
	static char buf[KASAN_REPORT_BUFSIZE];
	size_t n = 0;

	buf[0] = '\0';

	n += kasan_impl_decode_issue(buf, len, p, width, access, reason);
	n += kasan_dump_shadow(p, buf + n, len - n);

	dopanic ? panic("%s", buf) : printf("%s", buf);
}

static void
kasan_panic_report_internal(uptr p, uptr width, access_t access, violation_t reason)
{
	kasan_report_internal(p, width, access, reason, true);
}

static void
kasan_log_report_internal(uptr p, uptr width, access_t access, violation_t reason)
{
	kasan_report_internal(p, width, access, reason, false);
}


/* Pretty print a crash report. */
void NOINLINE OS_NORETURN
kasan_crash_report(uptr p, uptr width, access_t access, violation_t reason)
{
	kasan_handle_test();
	kasan_panic_report_internal(p, width, access, reason);
	__builtin_unreachable(); /* we cant handle this returning anyway */
}

/* Like kasan_crash_report(), but just log a failure. */
static void
kasan_log_report(uptr p, uptr width, access_t access, violation_t reason)
{
	const size_t len = 256;
	char buf[len];
	size_t l = 0;
	uint32_t nframes = 14;
	uintptr_t frames[nframes];
	uintptr_t *bt = frames;

	kasan_log_report_internal(p, width, access, reason);

	struct backtrace_control ctl = {
		/* ignore current frame */
		.btc_frame_addr = (uintptr_t)__builtin_frame_address(0),
	};
	nframes = backtrace(bt, nframes, &ctl, NULL);

	buf[0] = '\0';
	l += scnprintf(buf + l, len - l, "Backtrace: ");
	for (uint32_t i = 0; i < nframes; i++) {
		l += scnprintf(buf + l, len - l, "%lx,", VM_KERNEL_UNSLIDE(bt[i]));
	}
	l += scnprintf(buf + l, len - l, "\n");

	printf("%s", buf);
}

/*
 * Report a violation that may be disabled and/or blacklisted. This can only be
 * called for dynamic checks (i.e. where the fault is recoverable). Use
 * kasan_crash_report() for static (unrecoverable) violations.
 *
 * access: what we were trying to do when the violation occured
 * reason: what failed about the access
 */
void
kasan_violation(uintptr_t addr, size_t size, access_t access, violation_t reason)
{
	assert(__builtin_popcount(access) == 1);
	if (!kasan_check_enabled(access)) {
		/*
		 * A violation happened but the annexed check is disabled. Simply
		 * report the issue.
		 */
		if (report_suppressed_checks) {
			kasan_log_report(addr, size, access, reason);
		}
		return;
	}
	/* Panic as usual */
	kasan_crash_report(addr, size, access, reason);
}
