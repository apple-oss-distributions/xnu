#include "exc_helpers.h"
#include "ipc_utils.h"
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
	T_META_RUN_CONCURRENTLY(true),
	T_META_ENABLED(TARGET_CPU_ARM64),
	T_META_TAG_VM_PREFERRED);

struct mach_exception_options {
	mach_port_t exc_port;
	exception_mask_t exceptions_allowed;
	exception_behavior_t behaviors_allowed;
	thread_state_flavor_t flavors_allowed;
};

static void
bad_access_func(void)
{
	T_QUIET; T_LOG("Crashing");
	*(void *volatile *)5 = 0;
	T_QUIET; T_LOG("Recoverd!");
	return;
}

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
}

/*
 * ENTITLED: binary carries com.apple.security.only-one-exception-port, a
 * restriction entitlement that forbids thread_set_exception_ports(2) and
 * limits the process to one exception port registered via
 * task_register_hardened_exception_handler.
 * ENTITLED_DEBUGGER: same restriction, with additional debugger entitlement.
 */
#if defined(ENTITLED)
#define HARDENED_EXCEPTIONS_DEFAULT_DECL hardened_exceptions_entitled
#elif defined(ENTITLED_DEBUGGER)
#define HARDENED_EXCEPTIONS_DEFAULT_DECL hardened_exceptions_entitled_debugger
#else
#define HARDENED_EXCEPTIONS_DEFAULT_DECL hardened_exceptions
#endif

#define HARDENED_EXCEPTIONS_CONCAT(a, b) a##b
#define HARDENED_EXCEPTIONS_EXPAND(a, b) HARDENED_EXCEPTIONS_CONCAT(a, b)
#define HARDENED_EXCEPTIONS_DECL(suffix) HARDENED_EXCEPTIONS_EXPAND(HARDENED_EXCEPTIONS_DEFAULT_DECL, suffix)

T_DECL(HARDENED_EXCEPTIONS_DECL(_new_flow),
    "Test creating and using hardened exception ports") {
	struct mach_exception_options meo;
	meo.exceptions_allowed = EXC_MASK_BAD_ACCESS;
	meo.behaviors_allowed = EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES;
	meo.flavors_allowed = EXCEPTION_THREAD_STATE;

	mach_port_t exc_port = create_hardened_exception_port(meo, signing_key);

	thread_register_handler(exc_port, meo);

	run_exception_handler_behavior64(exc_port, NULL,
	    (void*)exc_handler_state_identity_protected,
	    EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES, true);
	bad_access_func();

	T_PASS("Successfully recovered from the exception!\n");
}

#if !defined(ENTITLED)

T_DECL(HARDENED_EXCEPTIONS_DECL(_tse_not_regressed),
    "Test that a process without only-one-exception-port restriction or with debugger "
    "entitlement may use thread_set_exception_ports normally") {
	kern_return_t kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		MACH_PORT_NULL,
		(exception_behavior_t)((unsigned int)EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_ASSERT_MACH_SUCCESS(kr, "works normally without only-one-exception-port restriction");
}

#else /* !defined(ENTITLED) */

T_DECL(HARDENED_EXCEPTIONS_DECL(_tse_disallowed),
    "Test that a process restricted by only-one-exception-port may not use thread_set_exception_ports") {
	if (ipc_hardening_disabled()) {
		T_SKIP("IPC hardening disabled via boot-args");
	}
	/* thread_set_exception_ports on a process with only-one-exception-port restriction should be killed with SIGKILL */
	expect_sigkill(^{
		(void)thread_set_exception_ports(
			mach_thread_self(),
			EXC_MASK_ALL,
			MACH_PORT_NULL,
			(exception_behavior_t)((unsigned int)EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
			EXCEPTION_THREAD_STATE);
	}, "thread_set_exception_ports disallowed for process with only-one-exception-port restriction");
}

#endif /* !defined(ENTITLED) */
