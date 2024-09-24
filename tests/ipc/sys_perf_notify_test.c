#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <unistd.h>
#include <sys/wait.h>
#include <mach/exception_types.h>
#include <mach/mach_port.h>
#include <mach/mach.h>
#include <mach/mach_interface.h>
#include <unistd.h>
#include "excserver_protect_state.h"
#include <TargetConditionals.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_TAG_VM_PREFERRED);

T_HELPER_DECL(child_exit, "Call exit() which will call sys_perf_notify()")
{
	T_LOG("Child exiting...");
	exit(0);
}

static mach_port_t exc_port;
static bool caught_exceptiion = false;

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity_protected(
	mach_port_t exception_port,
	uint64_t thread_id,
	mach_port_t task_id_token,
	exception_type_t exception,
	mach_exception_data_t codes,
	mach_msg_type_number_t codeCnt,
	int * flavor,
	thread_state_t old_state,
	mach_msg_type_number_t old_state_count,
	thread_state_t new_state,
	mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread_id, tatask_id_tokensk, exception, codes, codeCnt, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_identity_protected(
	mach_port_t               exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt)
{
#pragma unused(thread_id, task_id_token)
	caught_exceptiion = true;
	T_QUIET; T_ASSERT_EQ(exception_port, exc_port, "correct exception port");
	T_QUIET; T_ASSERT_EQ(exception, EXC_RPC_ALERT, "exception type is EXC_RPC_ALERT");
	T_QUIET; T_ASSERT_EQ(codeCnt, 2, "codeCnt is 2");
	T_QUIET; T_ASSERT_EQ(codes[0], 0xFF000001, "codes[0] is 0xFF000001");
	return KERN_SUCCESS;
}

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

static void
run_test(void)
{
	int ret, child_pid;
	task_t task;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};
	char path[1024];
	uint32_t size = sizeof(path);
	exception_mask_t masks[EXC_TYPES_COUNT];
	mach_msg_type_number_t nmasks = 0;
	exception_port_t old_ports[EXC_TYPES_COUNT];
	exception_behavior_t old_behaviors[EXC_TYPES_COUNT];
	thread_state_flavor_t old_flavors[EXC_TYPES_COUNT];

	/* Save the current host exception port for EXC_MASK_RPC_ALERT */
	ret = host_get_exception_ports(mach_host_self(), EXC_MASK_RPC_ALERT,
	    masks, &nmasks, old_ports, old_behaviors, old_flavors);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "host_get_exception_ports");

	/* Allocate a new port to catch exception */
	task = mach_task_self();
	T_QUIET; T_ASSERT_NE(task, MACH_PORT_NULL, "mach_task_self");

	ret = mach_port_construct(task, &opts, 0ull, &exc_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_port_construct");

	/* Set the new port as the host exception port */
	ret = host_set_exception_ports(mach_host_self(), EXC_MASK_RPC_ALERT, exc_port, EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES, old_flavors[0]);
	T_ASSERT_MACH_SUCCESS(ret, "Set up host exception port for EXC_MASK_RPC_ALERT");

	/* Spawn child to call exit() which calls into sys_perf_notify() */
	T_QUIET; T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", "child_exit", NULL };
	T_ASSERT_POSIX_ZERO(posix_spawn(&child_pid, args[0], NULL, NULL, args, NULL), "Spawn child to call exit()");

	/* We should receive an exception */
	ret = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
	T_ASSERT_MACH_SUCCESS(ret, "Host exception port should receive an exception after child exited");
	T_ASSERT_EQ(caught_exceptiion, true, "catch_mach_exception_raise_identity_protected() triggered");

	/* Reset host exception port */
	ret = host_set_exception_ports(mach_host_self(), EXC_MASK_RPC_ALERT, old_ports[0], old_behaviors[0], old_flavors[0]);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "resetting host exception port");

	/* Deallocate exception port */
	ret = mach_port_deallocate(task, exc_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_port_deallocate");
}

T_DECL(sys_perf_notify_test, "test sys_perf_notify delivery exception successfully when process exits", T_META_ASROOT(true))
{
	run_test();
}
