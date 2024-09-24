#include "exc_helpers.h"
#include <darwintest.h>

#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <pthread/private.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include <mach/thread_status.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/exception.h>
#include <mach/thread_status.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/code_signing.h>
#include <TargetConditionals.h>
#include <mach/semaphore.h>

#if __arm64__
#define EXCEPTION_THREAD_STATE          ARM_THREAD_STATE64
#define EXCEPTION_THREAD_STATE_COUNT    ARM_THREAD_STATE64_COUNT
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

struct mach_exception_options {
	mach_port_t exc_port;
	exception_mask_t exceptions_allowed;
	exception_behavior_t behaviors_allowed;
	thread_state_flavor_t flavors_allowed;
};

#if __arm64__
static void
bad_access_func(void)
{
	T_QUIET; T_LOG("Crashing");
	*(void *volatile *)5 = 0;
	T_QUIET; T_LOG("Recoverd!");
	return;
}
#endif /* __arm64__ */

static int num_exceptions = 0;

static uint32_t signing_key = (uint32_t)(0xa8000000 & 0xff000000);
static size_t
exc_handler_state_identity_protected(
	task_id_token_t token,
	uint64_t thread_id,
	exception_type_t type,
	__unused exception_data_t codes,
	thread_state_t in_state,
	mach_msg_type_number_t in_state_count,
	thread_state_t out_state,
	mach_msg_type_number_t *out_state_count)
{
	mach_port_t port1, port2;
	#pragma unused(port1)
	#pragma unused(port2)
	#pragma unused(token)
	#pragma unused(thread_id)
	#pragma unused(type)
	#pragma unused(in_state)
	#pragma unused(in_state_count)
	#pragma unused(out_state)
	#pragma unused(out_state_count)
	*out_state_count = in_state_count;
	T_LOG("Got protected exception!");
	num_exceptions++;
#if __arm64__
	arm_thread_state64_t *state = (arm_thread_state64_t*)(void *)out_state;
	void *func_pc = (void *)arm_thread_state64_get_pc(*state);

	/* Sign a PC which skips over the faulting instruction */
	func_pc = ptrauth_strip(func_pc, ptrauth_key_function_pointer);
	func_pc += 4;
	uint64_t pc_discriminator = ptrauth_blend_discriminator((void *)(unsigned long)signing_key, ptrauth_string_discriminator("pc"));
	func_pc = ptrauth_sign_unauthenticated(func_pc, ptrauth_key_function_pointer, pc_discriminator);

	// Set/Sign the PC of the excepting thread
	T_LOG("userspace discriminator=%llu\n", pc_discriminator);
	arm_thread_state64_set_pc_presigned_fptr(*state, func_pc);

	/* Corrupting the thread state should not crash as only the PC is accepted in hardened exceptions */
	arm_thread_state64_set_lr_presigned_fptr(*state, func_pc);
	arm_thread_state64_set_sp(*state, 0);
	arm_thread_state64_set_fp(*state, 0);

#endif /* __arm64__ */

	return KERN_SUCCESS;
}

static void
thread_register_handler(mach_port_t exc_port,
    const struct mach_exception_options meo)
{
	kern_return_t kr = thread_adopt_exception_handler(
		mach_thread_self(), exc_port, meo.exceptions_allowed,
		meo.behaviors_allowed, meo.flavors_allowed);

	T_ASSERT_MACH_SUCCESS(kr, "thread register handler");
}

static mach_port_t
create_hardened_exception_port(const struct mach_exception_options meo,
    uint32_t signing_key_local)
{
#if !__arm64__
	T_SKIP("Hardened exceptions not supported on !arm64");
	return MACH_PORT_NULL;
#else /* !__arm64__ */
	kern_return_t kr;
	mach_port_t exc_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT | MPO_EXCEPTION_PORT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &exc_port);
	T_ASSERT_MACH_SUCCESS(kr, "constructing mach port");

	T_LOG("register with pc_signing_key=0x%x\n", signing_key_local);
	kr = task_register_hardened_exception_handler(current_task(),
	    signing_key_local, meo.exceptions_allowed,
	    meo.behaviors_allowed, meo.flavors_allowed, exc_port);
	T_ASSERT_MACH_SUCCESS(kr, "registering an exception handler port");
	T_ASSERT_NE_UINT(exc_port, 0, "new exception port not null");

	return exc_port;
#endif /* !__arm64__ */
}

T_DECL(hardened_exceptions_default,
    "Test creating and using hardened exception ports") {
#if !__arm64__
	T_SKIP("Hardened exceptions not supported on !arm64");
#else /* !__arm64__ */
	struct mach_exception_options meo;
	meo.exceptions_allowed = EXC_MASK_BAD_ACCESS;
	meo.behaviors_allowed = EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES;
	meo.flavors_allowed = ARM_THREAD_STATE64;

	mach_port_t exc_port = create_hardened_exception_port(meo, signing_key);

	thread_register_handler(exc_port, meo);

	run_exception_handler_behavior64(exc_port, NULL,
	    (void*)exc_handler_state_identity_protected,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES, true);
	bad_access_func();

	printf("Successfully recovered from the exception!\n");
#endif /* !__arm64__ */
}

extern char *__progname;

T_DECL(entitled_process_exceptions_disallowed,
    "Test that when you have the special entitlement you may not use the hardened exception flow, unless you have debugger entitlements",
    T_META_IGNORECRASHES("*hardened_exceptions_entitled")) {
#if !__arm64__
	T_SKIP("Hardened exceptions not supported on !arm64");
#else /* !__arm64__ */

	bool entitled = strstr(__progname, "entitled") != NULL;
	bool debugger = strstr(__progname, "debugger") != NULL;
	/* thread_set_exception_ports as a hardened binary should fail */
	kern_return_t kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		MACH_PORT_NULL,
		(exception_behavior_t)((unsigned int)EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);

	if (!entitled && !debugger) {
		T_ASSERT_MACH_SUCCESS(kr, "unentitled works normally");
	} else if (entitled && !debugger) {
		T_FAIL("We should have already crashed due to hardening entitlement");
	} else if (entitled && debugger) {
		T_ASSERT_MACH_SUCCESS(kr, "debugger entitlement works normally");
	} else {
		T_FAIL("invalid configuration");
	}
#endif /* !__arm64__ */
}
