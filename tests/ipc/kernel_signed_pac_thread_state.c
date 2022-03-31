/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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
#include <ptrauth.h>
#include <stdbool.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/exception.h>
#include <mach/thread_status.h>
#include <sys/types.h>
#include <TargetConditionals.h>

#if __arm64__
#define EXCEPTION_THREAD_STATE          ARM_THREAD_STATE64
#define EXCEPTION_THREAD_STATE_COUNT    ARM_THREAD_STATE64_COUNT
#elif __arm__
#define EXCEPTION_THREAD_STATE          ARM_THREAD_STATE
#define EXCEPTION_THREAD_STATE_COUNT    ARM_THREAD_STATE_COUNT
#elif __x86_64__
#define EXCEPTION_THREAD_STATE          x86_THREAD_STATE
#define EXCEPTION_THREAD_STATE_COUNT    x86_THREAD_STATE_COUNT
#else
#error Unsupported architecture
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true));

/**
 * mach_exc_server() is a MIG-generated function that verifies the message
 * that was received is indeed a mach exception and then calls
 * catch_mach_exception_raise_state() to handle the exception.
 */
extern boolean_t mach_exc_server(mach_msg_header_t *, mach_msg_header_t *);

extern kern_return_t
catch_mach_exception_raise(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count);

extern kern_return_t
catch_mach_exception_raise_state(
	mach_port_t exception_port,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count);

extern kern_return_t
catch_mach_exception_raise_state_identity(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count);

extern kern_return_t
catch_mach_exception_raise_identity_protected(
	__unused mach_port_t      exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt);

/**
 * This has to be defined for linking purposes, but it's unused.
 */
kern_return_t
catch_mach_exception_raise(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, thread, task, type, codes, code_count)
	T_FAIL("Triggered catch_mach_exception_raise() which shouldn't happen...");
	__builtin_unreachable();
}

kern_return_t
catch_mach_exception_raise_identity_protected(
	__unused mach_port_t      exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt)
{
#pragma unused(exception_port, thread_id, task_id_token, exception, codes, codeCnt)
	T_FAIL("Triggered catch_mach_exception_raise_identity_protected() which shouldn't happen...");
	__builtin_unreachable();
}

/**
 * This has to be defined for linking purposes, but it's unused.
 */
kern_return_t
catch_mach_exception_raise_state(
	mach_port_t exception_port,
	exception_type_t type,
	exception_data_t codes,
	mach_msg_type_number_t code_count,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
#pragma unused(exception_port, type, codes, code_count, flavor, in_state, in_state_count, out_state, out_state_count)
	T_FAIL("Triggered catch_mach_exception_raise_state() which shouldn't happen...");
	__builtin_unreachable();
}

static int exception_count = 0;

/*
 * Since the test needs to change the opaque field in
 * thread struct, the test redefines the thread struct
 * here. This is just for test purposes, this should not
 * be done anywhere else.
 */
struct test_user_thread_state_64 {
	__uint64_t __x[29];     /* General purpose registers x0-x28 */
	void*      __opaque_fp; /* Frame pointer x29 */
	void*      __opaque_lr; /* Link register x30 */
	void*      __opaque_sp; /* Stack pointer x31 */
	void*      __opaque_pc; /* Program counter */
	__uint32_t __cpsr;      /* Current program status register */
	__uint32_t __opaque_flags; /* Flags describing structure format */
};
#define __TEST_USER_THREAD_STATE64_FLAGS_KERNEL_SIGNED 0x4

/**
 * Called by mach_exc_server() to handle the exception.
 * The first time this is called, it will modify the pc
 * but keep the kernel signed bit. Next time this is called
 * it will modify the pc and remove the kernel signed bit.
 */
kern_return_t
catch_mach_exception_raise_state_identity(
	mach_port_t exception_port __unused,
	mach_port_t thread __unused,
	mach_port_t task __unused,
	exception_type_t type __unused,
	exception_data_t codes __unused,
	mach_msg_type_number_t code_count __unused,
	int *flavor,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
	T_LOG("Caught a mach exception!\n");
	exception_count++;

	/* There should only be two code values. */
	T_QUIET; T_ASSERT_EQ(code_count, 2, "Two code values were provided with the mach exception");

	/**
	 * The code values should be 64-bit since MACH_EXCEPTION_CODES was specified
	 * when setting the exception port.
	 */
	mach_exception_data_t codes_64 = (mach_exception_data_t)(void *)codes;
	T_LOG("Mach exception codes[0]: %#llx, codes[1]: %#llx\n", codes_64[0], codes_64[1]);

	/* Verify that we're receiving the expected thread state flavor. */
	T_QUIET; T_ASSERT_EQ(*flavor, EXCEPTION_THREAD_STATE, "The thread state flavor is EXCEPTION_THREAD_STATE");
	T_QUIET; T_ASSERT_EQ(in_state_count, EXCEPTION_THREAD_STATE_COUNT, "The thread state count is EXCEPTION_THREAD_STATE_COUNT");

	/**
	 * Increment the PC by the 4 so the thread doesn't cause
	 * another exception when it resumes.
	 */
	*out_state_count = in_state_count; /* size of state object in 32-bit words */
	memcpy((void*)out_state, (void*)in_state, in_state_count * 4);

#if __arm64__
	arm_thread_state64_t *state = (arm_thread_state64_t*)(void *)out_state;

	void *pc = (void*)(arm_thread_state64_get_pc(*state) + 4);
	/* Have to sign the new PC value when pointer authentication is enabled. */
	pc = ptrauth_sign_unauthenticated(pc, ptrauth_key_function_pointer, 0);
	arm_thread_state64_set_pc_fptr(*state, pc);
#endif

	if (exception_count == 1) {
#if __arm64__
		/* Set the kernel signed bit, so kernel ignores the new PC */
		struct test_user_thread_state_64 *test_state = (struct test_user_thread_state_64 *)(void *)out_state;
		test_state->__opaque_flags |= __TEST_USER_THREAD_STATE64_FLAGS_KERNEL_SIGNED;
		T_LOG("Set the kernel signed flag on the thread state");
#else
		T_LOG("Not on arm64, Not doing anything");
#endif
	} else if (exception_count == 2) {
		T_LOG("Not clearing the kernel signed bit, this should be the last exception");
	} else {
		T_FAIL("Received more than 2 exceptions, failing the test");
	}

	/* Return KERN_SUCCESS to tell the kernel to keep running the victim thread. */
	return KERN_SUCCESS;
}

static mach_port_t
create_exception_port_behavior64(exception_mask_t exception_mask, exception_behavior_t behavior)
{
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();
	mach_port_t thread = mach_thread_self();
	kern_return_t kr = KERN_SUCCESS;

	if (behavior != EXCEPTION_STATE_IDENTITY && behavior != EXCEPTION_IDENTITY_PROTECTED) {
		T_FAIL("Currently only EXCEPTION_STATE_IDENTITY and EXCEPTION_IDENTITY_PROTECTED are implemented");
	}

	/* Create the mach port the exception messages will be sent to. */
	kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Allocated mach exception port");

	/**
	 * Insert a send right into the exception port that the kernel will use to
	 * send the exception thread the exception messages.
	 */
	kr = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Inserted a SEND right into the exception port");

	/* Tell the kernel what port to send exceptions to. */
	kr = thread_set_exception_ports(
		thread,
		exception_mask,
		exc_port,
		(exception_behavior_t)(behavior | (exception_behavior_t)MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Set the exception port to my custom handler");

	return exc_port;
}

static mach_port_t __unused
create_exception_port(exception_mask_t exception_mask)
{
	return create_exception_port_behavior64(exception_mask, EXCEPTION_STATE_IDENTITY);
}

/**
 * Thread to handle the mach exception.
 *
 * @param arg The exception port to wait for a message on.
 */
static void *
exc_server_thread(void *arg)
{
	mach_port_t exc_port = (mach_port_t)arg;
	kern_return_t kr;

	/**
	 * mach_msg_server_once is a helper function provided by libsyscall that
	 * handles creating mach messages, blocks waiting for a message on the
	 * exception port, calls mach_exc_server() to handle the exception, and
	 * sends a reply based on the return value of mach_exc_server().
	 */
#define MACH_MSG_REPLY_SIZE 4096
	kr = mach_msg_server(mach_exc_server, MACH_MSG_REPLY_SIZE, exc_port, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Received mach exception message");

	pthread_exit((void*)0);
	__builtin_unreachable();
}

static void __unused
run_exception_handler(mach_port_t exc_port)
{
	pthread_t exc_thread;

	/* Spawn the exception server's thread. */
	int err = pthread_create(&exc_thread, (pthread_attr_t*)0, exc_server_thread, (void *)(unsigned long long)exc_port);
	T_QUIET; T_ASSERT_POSIX_ZERO(err, "Spawned exception server thread");

	/* No need to wait for the exception server to be joined when it exits. */
	pthread_detach(exc_thread);
}

T_DECL(kernel_signed_pac_thread_state, "Test that kernel signed thread state given to exception ignores the pc")
{
#if !__arm64e__
	T_SKIP("Running on non-arm64e target, skipping...");
#else
	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS);

	//Change the expected exception to 2 when user ptr enforcement is turned on.
	//int expected_exception = 2;
	int expected_exception = 1;

	run_exception_handler(exc_port);
	*(void *volatile*)0 = 0;

	if (exception_count != expected_exception) {
		T_FAIL("Expected %d exceptions, received %d", expected_exception, exception_count);
	} else {
		T_LOG("TEST PASSED");
	}
	T_END;
#endif
}
