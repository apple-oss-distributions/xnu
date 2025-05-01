/*
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
#include <pthread.h>
#include <ptrauth.h>
#include <mach/machine/thread_state.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/code_signing.h>
#include <stdlib.h>
#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("ghackmann"),
	T_META_RUN_CONCURRENTLY(true)
	);

#if __arm64e__
#ifndef EXC_ARM_PAC_FAIL
#define EXC_ARM_PAC_FAIL        0x105   /* PAC authentication failure */
#endif

static volatile bool mach_exc_caught = false;

static size_t
pac_exception_handler(
	__unused mach_port_t task,
	__unused mach_port_t thread,
	exception_type_t type,
	mach_exception_data_t codes)
{
	T_ASSERT_EQ(type, EXC_BAD_ACCESS, "Caught an EXC_BAD_ACCESS exception");
	T_ASSERT_EQ(codes[0], (uint64_t)EXC_ARM_PAC_FAIL, "The subcode is EXC_ARM_PAC_FAIL");
	mach_exc_caught = true;
	return 4;
}

#define ID_AA64ISAR1_EL1_APA(x)         ((x >> 4) & 0xf)
#define ID_AA64ISAR1_EL1_API(x)         ((x >> 8) & 0xf)

static bool
have_fpac(void)
{
	uint64_t id_aa64isar1_el1;
	size_t id_aa64isar1_el1_size = sizeof(id_aa64isar1_el1);

	int err = sysctlbyname("machdep.cpu.sysreg_ID_AA64ISAR1_EL1", &id_aa64isar1_el1, &id_aa64isar1_el1_size, NULL, 0);
	if (err) {
		return false;
	}

	const uint8_t APA_API_HAVE_FPAC = 0x4;
	return ID_AA64ISAR1_EL1_APA(id_aa64isar1_el1) >= APA_API_HAVE_FPAC ||
	       ID_AA64ISAR1_EL1_API(id_aa64isar1_el1) >= APA_API_HAVE_FPAC;
}

static int
virtual_address_size(void)
{
	int ret;
	size_t ret_size = sizeof(ret);

	int err = sysctlbyname("machdep.virtual_address_size", &ret, &ret_size, NULL, 0);
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname()");
	return ret;
}

static void *
canonical_address(void *ptr)
{
	uint64_t mask = (1ULL << virtual_address_size()) - 1;
	return (void *)((uintptr_t)ptr & mask);
}
#endif // __arm64e__

T_DECL(thread_set_state_corrupted_pc,
    "Test that ptrauth failures in thread_set_state() poison the respective register.", T_META_TAG_VM_NOT_PREFERRED)
{
#if !__arm64e__
	T_SKIP("Running on non-arm64e target, skipping...");
#else
	mach_port_t thread;
	kern_return_t err = thread_create(mach_task_self(), &thread);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Created thread");

	arm_thread_state64_t state;
	mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
	err = thread_get_state(mach_thread_self(), ARM_THREAD_STATE64, (thread_state_t)&state, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got own thread state");

	void *corrupted_pc = (void *)((uintptr_t)state.__opaque_pc ^ 0x4);
	state.__opaque_pc = corrupted_pc;
	err = thread_set_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Set child thread's PC to a corrupted pointer");

	err = thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&state, &count);
	T_QUIET; T_ASSERT_EQ(err, KERN_SUCCESS, "Got child's thread state");
	T_EXPECT_NE(state.__opaque_pc, corrupted_pc, "thread_set_state() with a corrupted PC should poison the PC value");
	T_EXPECT_EQ(canonical_address(state.__opaque_pc), canonical_address(corrupted_pc),
	    "thread_set_state() with a corrupted PC should preserve the canonical address bits");

	err = thread_terminate(thread);
	T_QUIET; T_EXPECT_EQ(err, KERN_SUCCESS, "Terminated thread");
#endif // __arm64e__
}

T_DECL(ptrauth_exception,
    "Test naked ptrauth failures.",
    T_META_IGNORECRASHES("ptrauth_failure.*"), T_META_TAG_VM_NOT_PREFERRED)
{
#if !__arm64e__
	T_SKIP("Running on non-arm64e target, skipping...");
#else
	if (!have_fpac()) {
		T_SKIP("Running on non-FPAC target, skipping...");
		return;
	}

	int pid, stat;
	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS);

	extern int main(int, char *[]);
	void *func_ptr = (void *)main;
	void *func_ptr_stripped = ptrauth_strip(func_ptr, ptrauth_key_function_pointer);
	void *func_ptr_corrupted = (void *)((uintptr_t)func_ptr ^ 1);

	void *func_ptr_authed = func_ptr;
	mach_exc_caught = false;
	run_exception_handler(exc_port, pac_exception_handler);
	asm volatile ("autiza %0" : "+r"(func_ptr_authed));

	T_EXPECT_FALSE(mach_exc_caught, "Authing valid pointer should not cause an exception");
	T_EXPECT_EQ(func_ptr_authed, func_ptr_stripped, "Valid pointer should auth to stripped value");

	pid = fork();
	if (pid == 0) {
		func_ptr_authed = func_ptr_corrupted;
		asm volatile ("autiza %0" : "+r"(func_ptr_authed));
		T_FAIL("Expected PAC EXCEPTION");
		__builtin_unreachable();
	}
	T_ASSERT_TRUE(pid != -1, "Checking fork success in parent");

	T_ASSERT_POSIX_SUCCESS(waitpid(pid, &stat, 0), "waitpid");
	T_ASSERT_TRUE(stat == SIGKILL, "Expect a PAC EXCEPTION to SIGKILL the process");
#endif // __arm64e__
}
