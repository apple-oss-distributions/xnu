/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include "context_helpers.h"
#include <darwintest.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

#include <os/arch/arm64.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("joster"),
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.arm_kernel_protect", 0), // entitlement will crash on arm_kernel_protect devices
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

T_DECL(x18_toggle,
    "Test that x18 is preserved on hardware that supports it, if entitled and toggled via the API.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	bool did_csw = false;
	uint64_t x18_val;

	uint64_t tpidr = __builtin_arm_rsr64("TPIDR_EL0");
	printf("tpidr: %016llx\n", tpidr);

	T_ASSERT_FALSE(os_custom_x18_abi_enabled(), "custom x18 ABI should be initially disabled");

	for (uint64_t i = 0xFEEDB0B000000000ULL; i < 0xFEEDB0B000000000ULL + 10000; ++i) {
		asm volatile ("mov x18, %0" : : "r"(i));
		int32_t const nr_csw = get_csw_count();
		int const rc = usleep(10);
		int32_t const nr_csw_after = get_csw_count();

		// There isn't any guarantee usleep() will actually context switch so this is a best effort way
		// to see if we've switched at least once in all these iterations.
		did_csw = did_csw || (nr_csw_after > nr_csw);
		T_QUIET; T_ASSERT_EQ(0, rc, "usleep");
		asm volatile ("mov %0, x18" : "=r"(x18_val));
		T_QUIET; T_ASSERT_EQ(x18_val, 0ULL, "check that x18 is cleared after yield");
	}

	os_set_custom_x18_abi_enabled(true);

	T_ASSERT_TRUE(os_custom_x18_abi_enabled(), "custom x18 ABI should be enabled after os_set_custom_x18_abi_enabled(true)");

	tpidr = __builtin_arm_rsr64("TPIDR_EL0");
	printf("tpidr: %016llx\n", tpidr);

	did_csw = false;

	for (uint64_t i = 0xFEEDB0B000000000ULL; i < 0xFEEDB0B000000000ULL + 10000; i++) {
		asm volatile ("mov x18, %0" : : "r"(i));
		int32_t const nr_csw = get_csw_count();
		int const rc = usleep(10);
		int32_t const nr_csw_after = get_csw_count();

		// There isn't any guarantee usleep() will actually context switch so this is a best effort way
		// to see if we've switched at least once in all these iterations.
		did_csw = did_csw || (nr_csw_after > nr_csw);
		T_QUIET; T_ASSERT_EQ(0, rc, "usleep");

		asm volatile ("mov %0, x18" : "=r"(x18_val));
		T_QUIET; T_ASSERT_EQ(x18_val, i, "check that x18 reads back correctly after yield");
	}

	os_set_custom_x18_abi_enabled(false);

	T_ASSERT_FALSE(os_custom_x18_abi_enabled(), "custom x18 ABI should be disabled after os_set_custom_x18_abi_enabled(false)");

	tpidr = __builtin_arm_rsr64("TPIDR_EL0");
	printf("tpidr: %016llx\n", tpidr);

	did_csw = false;

	for (uint64_t i = 0xFEEDB0B000000000ULL; i < 0xFEEDB0B000000000ULL + 10000; ++i) {
		asm volatile ("mov x18, %0" : : "r"(i));
		int32_t const nr_csw = get_csw_count();
		int const rc = usleep(10);
		int32_t const nr_csw_after = get_csw_count();

		// There isn't any guarantee usleep() will actually context switch so this is a best effort way
		// to see if we've switched at least once in all these iterations.
		did_csw = did_csw || (nr_csw_after > nr_csw);
		T_QUIET; T_ASSERT_EQ(0, rc, "usleep");
		asm volatile ("mov %0, x18" : "=r"(x18_val));
		T_QUIET; T_ASSERT_EQ(x18_val, 0ULL, "check that x18 is cleared after yield");
	}


	T_QUIET; T_ASSERT_TRUE(did_csw, "did not context switch, but should have.");
#endif
}

#ifdef __arm64__
// Global variables for signal handling test communication
static volatile bool signal_received = false;
static volatile bool x18_was_enabled_in_signal = false;
static volatile bool signal_handler_completed = false;

static void
sigvtalrm_handler(int sig)
{
	// Step 1: Capture current x18 ABI state
	bool was_enabled = os_custom_x18_abi_enabled();
	x18_was_enabled_in_signal = was_enabled;

	// Step 2: Transition out of custom ABI mode if enabled
	if (was_enabled) {
		os_set_custom_x18_abi_enabled(false);
	}

	// Step 3: Signal completion to main thread
	signal_received = true;
	signal_handler_completed = true;
}
#endif

T_DECL(x18_signal_handling,
    "Test signal handling with custom x18 ABI mode enabled using SIGVTALRM.")
{
#ifndef __arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else
	// Reset global communication variables
	signal_received = false;
	x18_was_enabled_in_signal = false;
	signal_handler_completed = false;

	// Setup SIGVTALRM handler
	struct sigaction sa;
	sa.sa_handler = sigvtalrm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	T_ASSERT_POSIX_ZERO(sigaction(SIGVTALRM, &sa, NULL), "install SIGVTALRM handler");

	// Configure virtual timer
	struct itimerval timer;
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 50000;    // 50ms
	timer.it_interval.tv_sec = 0;
	timer.it_interval.tv_usec = 0;     // No repeat

	T_ASSERT_POSIX_ZERO(setitimer(ITIMER_VIRTUAL, &timer, NULL), "set virtual timer");

	// Enable custom x18 ABI mode
	os_set_custom_x18_abi_enabled(true);
	T_ASSERT_TRUE(os_custom_x18_abi_enabled(), "custom x18 ABI should be enabled before signal");

	// Busy spin to consume CPU time (triggers virtual timer)
	// No OS calls allowed in custom ABI mode - only spinning and x18 API
	// Use generous timeout: 10 billion iterations should handle very fast CPUs
	// while still timing out eventually (~10+ seconds) if signal fails
	volatile uint64_t spin_counter = 0;
	const uint64_t MAX_SPIN_COUNT = 10000000000ULL;

	while (!signal_received && spin_counter < MAX_SPIN_COUNT) {
		spin_counter++;
	}

	T_ASSERT_TRUE(signal_received, "SIGVTALRM should have been received");
	T_ASSERT_TRUE(signal_handler_completed, "signal handler should have completed");
	T_ASSERT_TRUE(x18_was_enabled_in_signal,
	    "custom x18 ABI should have been enabled when signal handler executed");
	T_ASSERT_FALSE(os_custom_x18_abi_enabled(),
	    "custom x18 ABI should be disabled after signal handler");
	T_ASSERT_LT(spin_counter, MAX_SPIN_COUNT, "should not have hit timeout");

	// Cleanup: Cancel any remaining timer
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 0;
	setitimer(ITIMER_VIRTUAL, &timer, NULL);

	// Restore default SIGVTALRM handler
	signal(SIGVTALRM, SIG_DFL);
#endif
}
