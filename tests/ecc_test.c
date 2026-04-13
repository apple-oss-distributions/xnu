/*
 * Copyright (c) 2021-2025 Apple Inc. All rights reserved.
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

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "test_utils.h"

#define SIGBUS_RETCODE (10)

/*
 * We're going to inject ECC errors into shared library text, so don't run with
 * other tests.
 */
T_GLOBAL_META(T_META_RUN_CONCURRENTLY(false),
    T_META_OWNER("m_nitenko"),
    T_META_NAMESPACE("xnu.vm.ecc"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("VM"));


/*
 * No system(3c) on watchOS, so provide our own.
 * returns -1 if fails to run
 * returns 0 if process exits normally.
 * returns +n if process exits due to signal N
 */
static int
my_system(const char *command, const char *arg)
{
	pid_t pid;
	int status = 0;
	int signal = 0;
	int ret;
	const char *argv[] = {
		command,
		"-v",
		arg,
		NULL
	};

	if (dt_launch_tool(&pid, (char **)(void *)argv, FALSE, NULL, NULL)) {
		return -1;
	}

	ret = dt_waitpid(pid, &status, &signal, 100);
	if (signal != 0) {
		return signal;
	} else if (status != 0) {
		return status;
	}
	return 0;
}

T_DECL(amcc_injection_capable,
    "Test that AMCC error injected is implemented when it should be",
    T_META_RUN_CONCURRENTLY(true),
    T_META_ASROOT(true),
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	int capable;
	size_t capable_size = sizeof(capable);

	int ret = sysctlbyname("vm.ecc.amcc_error_injection_capable", &capable,
	    &capable_size, NULL, 0);

	T_ASSERT_EQ(ret, 0, "Sysctl succeeded");
	T_ASSERT_EQ(capable, 1, "Injection function registered");
}

T_DECL(dcs_injection_capable,
    "Test that DCS error injected is implemented when it should be",
    T_META_RUN_CONCURRENTLY(true),
    T_META_ASROOT(true),
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	int capable;
	size_t capable_size = sizeof(capable);

	int ret = sysctlbyname("vm.ecc.dcs_error_injection_capable", &capable,
	    &capable_size, NULL, 0);

	T_ASSERT_EQ(ret, 0, "Sysctl succeeded");
	T_ASSERT_EQ(capable, 1, "Injection function registered");
}

static int
run_helper(const char *const arg)
{
	T_LOG("Now running \"%s\" test in the helper:", arg);
	return my_system("./ecc_test_helper", arg);
}

static void
test_setup(bool use_dcs)
{
	int err;
	uint value = 0;
	size_t size = sizeof value;

	/* Set injection mode to uncorrectable. */
	value = 0;
	err = sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &value, size);
	if (err) {
		T_FAIL("Failed to set the uncorrectable injection mode.");
	}

	/* Disable side effects for the duration of the test. */
	value = 0;
	err = sysctlbyname("vm.persist_retired_pages", NULL, NULL, &value,
	    size);
	if (err) {
		T_FAIL("Failed to disable side effects.");
	}

	value = (uint)use_dcs;
	err = sysctlbyname("vm.test_ecc_dcs", NULL, NULL, &value, size);
	if (err) {
		T_FAIL("Failed to set injection mode");
	}

	T_LOG("Running test in %s mode", use_dcs ? "DCS" : "AMCC");
}

static void
test_cleanup(void)
{
	uint value = 0;
	size_t size = sizeof value;

	/* Set injection mode to uncorrectable. */
	value = 0;
	sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &value, size);

	/* Restore side-effecting to default (enabled). */
	value = 1;
	sysctlbyname("vm.persist_retired_pages", NULL, NULL, &value, size);

	/* Set testing mode back to default (AMCC). */
	value = 0;
	sysctlbyname("vm.test_ecc_dcs", NULL, NULL, &value, size);
}

static void
run_ecc_test(void (*test_func)(void))
{
	T_ATEND(test_cleanup);

	/* Run test with AMCC injection. */
	test_setup(false);
	test_func();

	/* Run test with DCS injection. */
	test_setup(true);
	test_func();
}

/**
 * Trigger an ECC error on a process' TEXT page.
 *
 * The page is not writeable (therefore clean), so we expect it to recover.
 */
static void
private_text_test(void)
{
	int ret = run_helper("Yfoo");
	T_ASSERT_EQ(ret, 0, "First clean call of foo.");

	ret = run_helper("Xfoo");
	T_ASSERT_EQ(ret, 0,
	    "Recovered from an UE on a clean private TEXT page.");

	ret = run_helper("Yfoo");
	T_ASSERT_EQ(ret, 0, "Fixed call of foo.");

	T_PASS("%s passed.", __func__);
}

T_DECL(private_text_ue,
    "Test non-fatal ECC uncorrectable errors on private TEXT pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 */), // Fails on some targets: rdar://167048708
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(private_text_test);
}

/**
 * Trigger an ECC error on a shared library's TEXT page.
 *
 * Since the page is not writeable (therefore clean), we expect to recover.
 */
static void
shared_text_test(void)
{
	int ret = run_helper("Yatan");
	T_ASSERT_EQ(ret, 0, "First clean call of atan.");

	ret = run_helper("Xatan");
	T_ASSERT_EQ(ret, 0,
	    "Recovered from an UE on a clean shared region page.");

	ret = run_helper("Yatan");
	T_ASSERT_EQ(ret, 0, "Fixed call of atan.");

	T_PASS("%s passed.", __func__);
}

T_DECL(shared_text_ue,
    "Test non-fatal ECC uncorrectable errors on shared TEXT pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 */), // Fails on some targets: rdar://167048708
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(shared_text_test);
}

/**
 * Trigger an ECC error on a clean static page.
 *
 * Since the page is clean, we expect to recover.
 */
static void
clean_data_test(void)
{
	int ret = run_helper("Xclean");
	T_ASSERT_EQ(ret, 0, "Recovered from an UE on a clean page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(clean_data_ue,
    "Test non-fatal ECC uncorrectable errors on clean DATA pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 */), // Fails on some targets: rdar://167048708
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(clean_data_test);
}

/**
 * Trigger an ECC error on a dirty static page.
 *
 * Since the page is dirty, we expect the process to get a SIGBUS.
 */
static void
dirty_data_test(void)
{
	int ret = run_helper("Xdirty");
	T_ASSERT_EQ(ret, SIGBUS_RETCODE,
	    "SIGBUSed from an UE on a dirty static page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(dirty_data_ue,
    "Test non-fatal ECC uncorrectable errors on dirty DATA pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false), // Test disabled: rdar://166538431
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(dirty_data_test);
}

/**
 * Trigger an ECC error on a clean allocated page.
 *
 * Since the page is clean, we expect to recover.
 */
static void
clean_mmap_test(void)
{
	int ret = run_helper("Xmmap_clean");
	T_ASSERT_EQ(ret, 0,
	    "Recovered from an ECC on a clean dynamically allocated page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(clean_mmap_ue,
    "Test non-fatal ECC uncorrectable errors on clean mmap'd pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false), // Test disabled: rdar://124132874
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(clean_mmap_test);
}

/**
 * Trigger an ECC error on a dirty allocated page.
 *
 * Since the page is dirty, we expect the process to get a SIGBUS.
 */
static void
dirty_mmap_test(void)
{
	int ret = run_helper("Xmmap_dirty");
	T_ASSERT_EQ(ret, SIGBUS_RETCODE,
	    "SIGBUSed from an UE on a dirty dynamically allocated page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(dirty_mmap_ue,
    "Test non-fatal ECC uncorrectable errors on dirty mmap'd pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false), // Test disabled: rdar://166538590
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(dirty_mmap_test);
}

/**
 * Trigger an ECC error during copyout.
 *
 * Although the page is dirty, the page fault error is handled by failing
 * the copyout syscall.
 */
static void
dirty_copyout_test(void)
{
	int ret = run_helper("Xcopyout");
	T_ASSERT_EQ(ret, EFAULT,
	    "Copyout returns EFAULT from an UE during copyout.");

	T_PASS("%s passed.", __func__);
}

T_DECL(dirty_copyout_ue,
    "Test non-fatal ECC uncorrectable errors during copyout",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false), // Test disabled: rdar://166538740
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(dirty_copyout_test);
}

/**
 * Trigger an ECC error with a write on a clean static page.
 *
 * Since the page is clean, we expect to recover.
 */
static void
clean_data_write_test(void)
{
	int ret = run_helper("Xclean_write");
	T_ASSERT_EQ(ret, 0, "Recovered from a write UE on a clean page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(clean_data_write_ue,
    "Test non-fatal write ECC errors on clean DATA pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 */), // Fails on some targets: rdar://167048708
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(clean_data_write_test);
}

/**
 * Trigger an ECC error with a write on a dirty static page.
 *
 * Since the page is dirty, we expect the process to get a SIGBUS.
 */
static void
dirty_data_write_test(void)
{
	int ret = run_helper("Xdirty_write");
	T_ASSERT_EQ(ret, SIGBUS_RETCODE,
	    "SIGBUSed from a UE write to a dirty static page.");

	T_PASS("%s passed.", __func__);
}

T_DECL(dirty_data_write_ue,
    "Test non-fatal write ECC errors on dirty DATA pages",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false /* TARGET_CPU_ARM64 */), // Fails on some targets: rdar://167048708
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_ecc_test(dirty_data_write_test);
}

/**
 * Ensure that memory faults are not reported when disabled.
 * This test tests both xnu and the platform kext that initiates the fault reporting.
 */
T_DECL(ecc_report_disable_test, "test that disabling memory fault reporting works",
    T_META_IGNORECRASHES(".*ecc_test_helper.*"),
    T_META_ASROOT(true),
    T_META_ENABLED(false), // Test disabled: rdar://157041507
    T_META_REQUIRES_SYSCTL_EQ("vm.dram_ecc_error_injection_capable", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	int ret;

	/* Set testing mode to uncorrectable. */
	uint32_t corrected = 0;
	size_t corrected_size = sizeof(corrected);
	ret = sysctlbyname("vm.test_corrected_ecc", NULL, NULL, &corrected, corrected_size);
	T_ASSERT_FALSE(ret, "Inject uncorrectable errors");

	uint32_t old_mode;
	size_t old_mode_size = sizeof(old_mode);
	ret = sysctlbyname("machdep.mem_fault_report_get", &old_mode, &old_mode_size, NULL, 0);
	T_ASSERT_FALSE(ret, "Get the old mode");

	uint32_t new_mode = false;
	size_t new_mode_size = sizeof(new_mode);
	ret = sysctlbyname("machdep.mem_fault_report_enable", NULL, NULL, &new_mode, new_mode_size);
	T_ASSERT_FALSE(ret, "Disable memory fault reporting");

	/* Inject a uncorrectable ECC to a wired page. */
	ret = run_helper("Xwired");
	T_ASSERT_EQ(ret, 0, "Runner successful");

	/**
	 * Restore the old mode.
	 * If reporting was enabled before, we might get a delayed ECC error after we reenable
	 * reporting.
	 */
	sysctlbyname("machdep.mem_fault_report_enable", NULL, NULL, &old_mode, old_mode_size);

	T_PASS("If you didn't panic, the test passed");
}
