#include <darwintest.h>
#include <pthread/private.h>
#include <sys/sysctl.h>
#include <mach/task.h>
#include "exc_helpers.h"

#define EXCEPTION_IDENTITY_PROTECTED 4

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true));

static size_t
exc_handler_identity_protected(
	task_id_token_t token,
	uint64_t thread_id,
	exception_type_t type,
	__unused exception_data_t codes)
{
	mach_port_t port1, port2;
	kern_return_t kr;

	T_LOG("Got protected exception!");

	port1 = mach_task_self();
	kr = task_identity_token_get_task_port(token, TASK_FLAVOR_CONTROL, &port2); /* Immovable control port for self */
	T_ASSERT_MACH_SUCCESS(kr, "task_identity_token_get_task_port() - CONTROL");
	T_EXPECT_EQ(port1, port2, "Control port matches!");

	T_END;
}

T_DECL(exc_raise_identity_protected, "Test identity-protected exception delivery behavior",
    T_META_TAG_VM_NOT_PREFERRED)
{
	mach_port_t exc_port = create_exception_port_behavior64(EXC_MASK_BAD_ACCESS, EXCEPTION_IDENTITY_PROTECTED);

	run_exception_handler_behavior64(exc_port, NULL, exc_handler_identity_protected, EXCEPTION_IDENTITY_PROTECTED, true);
	*(void *volatile*)0 = 0;
}
