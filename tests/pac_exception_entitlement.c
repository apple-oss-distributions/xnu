/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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

#include <darwintest.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/exception_types.h>
#include <sys/wait.h>

#include "exc_helpers.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("ghackmann"),
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.ptrauth", 1),
	T_META_IGNORECRASHES(".*pac_exception_entitlement.*"),
	XNU_T_META_SOC_SPECIFIC
	);

#if __arm64e__
static size_t
exception_handler(mach_port_t task __unused, mach_port_t thread __unused,
    exception_type_t type __unused, mach_exception_data_t codes __unused)
{
	T_ASSERT_FAIL("kernel ran exception handler instead of terminating process");
}

/*
 * Real-world software should use ptrauth.h when it needs to manually sign or
 * auth pointers.  But for testing purposes we need clang to emit specific
 * ptrauth instructions, so we use inline asm here instead.
 *
 * Likewise clang would normally combine the "naked" auth and brk testcases as
 * part of a sequence like:
 *
 *     output = auth(...);
 *     if (output is poisoned) {
 *         brk(PTRAUTH_FAILURE_COMMENT);
 *     }
 *
 * On auth failure, CPUs that implement FEAT_FPAC will trap immediately at the
 * auth instruction, and CPUs without FEAT_FPAC will trap at the later brk
 * instruction.  But again, for testing purposes we want these to be two
 * discrete cases.  (On FPAC-enabled CPUs, the kernel should treat *both* traps
 * as ptrauth failure, even if we don't expect the latter to be reachable in
 * real-world software.)
 */

static void
naked_auth(void)
{
	asm volatile (
                "mov	x0, #0"                 "\n"
                "paciza	x0"                     "\n"
                "eor	x0, x0, (1 << 63)"      "\n"
                "autiza	x0"
                :
                :
                : "x0"
        );
}

static void
ptrauth_brk(void)
{
	asm volatile ("brk 0xc470");
}

static void
combined_branch_auth(void)
{
	asm volatile (
                "adr	x0, 1f"                 "\n"
                "paciza	x0"                     "\n"
                "eor	x0, x0, (1 << 63)"      "\n"
                "braaz	x0"                     "\n"
        "1:"
                :
                :
                : "x0"
        );
}

static void
combined_load_auth(void)
{
	asm volatile (
                "mov	x0, sp"                 "\n"
                "pacdza	x0"                     "\n"
                "eor	x0, x0, (1 << 63)"      "\n"
                "ldraa	x0, [x0]"               "\n"
                :
                :
                : "x0"
        );
}

static void
run_pac_exception_test(void (*ptrauth_failure_fn)(void))
{
	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS | EXC_MASK_BREAKPOINT);
		run_exception_handler(exc_port, exception_handler);

		ptrauth_failure_fn();
		/* ptrauth_failure_fn() should have raised an uncatchable exception */
		T_FAIL("child ran to completion");
	} else {
		int status;
		int err = waitpid(pid, &status, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "waitpid");

		T_EXPECT_TRUE(WIFSIGNALED(status), "child terminated due to signal");
		T_EXPECT_EQ(SIGKILL, WTERMSIG(status), "child terminated due to SIGKILL");
	}
}
#endif

T_DECL(pac_exception_naked_auth,
    "Test the com.apple.private.pac.exception entitlement (naked auth failure)",
    T_META_REQUIRES_SYSCTL_EQ("hw.optional.arm.FEAT_FPAC", 1))
{
#if __arm64e__
	run_pac_exception_test(naked_auth);
#else
	T_SKIP("Running on non-arm64e target, skipping...");
#endif
}


T_DECL(pac_exception_ptrauth_brk,
    "Test the com.apple.private.pac.exception entitlement (brk with comment indicating ptrauth failure)")
{
#if __arm64e__
	run_pac_exception_test(ptrauth_brk);
#else
	T_SKIP("Running on non-arm64e target, skipping...");
#endif
}

T_DECL(pac_exception_combined_branch_auth,
    "Test the com.apple.private.pac.exception entitlement (combined branch + auth failure)")
{
#if __arm64e__
	run_pac_exception_test(combined_branch_auth);
#else
	T_SKIP("Running on non-arm64e target, skipping...");
#endif
}

T_DECL(pac_exception_combined_load_auth,
    "Test the com.apple.private.pac.exception entitlement (combined branch + auth failure)")
{
#if __arm64e__
	run_pac_exception_test(combined_load_auth);
#else
	T_SKIP("Running on non-arm64e target, skipping...");
#endif
}
