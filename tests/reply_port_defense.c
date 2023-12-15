#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>
#include <spawn.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <signal.h>
#include "excserver_protect.h"
#include "../osfmk/ipc/ipc_init.h"
#include "../osfmk/mach/port.h"
#include "../osfmk/kern/exc_guard.h"
#include "exc_helpers.h"

#define MAX_TEST_NUM 5
#define MAX_ARGV 3

extern char **environ;
static mach_exception_data_type_t received_exception_code = 0;
static mach_exception_data_type_t expected_exception_code = 0;
static exception_type_t exception_taken = 0;

/*
 * This test infrastructure is inspired from imm_pinned_control_port.c.
 * It verifies no reply port security semantics are violated.
 *
 * 1. The rcv right of the port would be marked immovable.
 */
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(TRUE));

static mach_port_t
alloc_exception_port(void)
{
	kern_return_t kret;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	kret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate exc_port");

	kret = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right exc_port");

	return exc_port;
}

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
catch_mach_exception_raise_identity_protected(
	__unused mach_port_t      exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt)
{
#pragma unused(exception_port, thread_id, task_id_token)

	T_ASSERT_GT_UINT(codeCnt, 0, "CodeCnt");

	T_LOG("Caught exception type: %d code: 0x%llx", exception, codes[0]);
	exception_taken = exception;
	if (exception == EXC_GUARD) {
		received_exception_code = EXC_GUARD_DECODE_GUARD_FLAVOR((uint64_t)codes[0]);
	} else if (exception == EXC_CORPSE_NOTIFY) {
		received_exception_code = codes[0];
	} else {
		T_FAIL("Unexpected exception");
	}
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

static void *
exception_server_thread(void *arg)
{
	kern_return_t kr;
	mach_port_t exc_port = *(mach_port_t *)arg;

	/* Handle exceptions on exc_port */
	kr = mach_msg_server_once(mach_exc_server, 4096, exc_port, 0);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "mach_msg_server_once");

	return NULL;
}
#define kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE 6
T_DECL(reply_port_defense, "Test reply port semantics violations", T_META_IGNORECRASHES(".*reply_port_defense_client.*"), T_META_CHECK_LEAKS(false))
{
	int ret = 0;

	uint32_t task_exc_guard = 0;
	size_t te_size = sizeof(&task_exc_guard);

	char *test_prog_name = "./reply_port_defense_client";
	char *child_args[MAX_ARGV];
	pid_t client_pid = 0;
	posix_spawnattr_t attrs;
	bool triggers_exception;

	pthread_t s_exc_thread;
	mach_port_t exc_port;

	T_LOG("Check if task_exc_guard exception has been enabled\n");
	ret = sysctlbyname("kern.task_exc_guard_default", &task_exc_guard, &te_size, NULL, 0);
	T_ASSERT_EQ(ret, 0, "sysctlbyname");

	if (!(task_exc_guard & TASK_EXC_GUARD_MP_DELIVER)) {
		T_SKIP("task_exc_guard exception is not enabled");
	}

	for (int i = 0; i < MAX_TEST_NUM; i++) {
		received_exception_code = 0;
		triggers_exception = true;
		exc_port = alloc_exception_port();
		T_QUIET; T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Create a new exception port");

		if (i == 4) {
			triggers_exception = false;
		}

#if defined(TARGET_OS_OSX)
		/* thread_set_exception_ports is allowed on macos due to third party plugins & drivers */
		if (i == 5) {
			triggers_exception = false;
		}
#endif

		/* Create exception serving thread */
		ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

		/* Initialize posix_spawn attributes */
		posix_spawnattr_init(&attrs);

		int err = posix_spawnattr_setexceptionports_np(&attrs, EXC_MASK_GUARD | EXC_MASK_CORPSE_NOTIFY, exc_port,
		    (exception_behavior_t) (EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES), 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "posix_spawnattr_setflags");

		child_args[0] = test_prog_name;
		char test_num[10];
		sprintf(test_num, "%d", i);
		child_args[1] = test_num;
		child_args[2] = NULL;

		T_LOG("========== Spawning new child ==========");
		err = posix_spawn(&client_pid, child_args[0], NULL, &attrs, &child_args[0], environ);
		T_ASSERT_POSIX_SUCCESS(err, "posix_spawn reply_port_defense_client = %d", client_pid);

		int child_status;
		/* Wait for child and check for exception */
		if (-1 == waitpid(-1, &child_status, 0)) {
			T_FAIL("%s waitpid: child", strerror(errno));
		}
		if (WIFEXITED(child_status) && WEXITSTATUS(child_status)) {
			T_FAIL("Child exited with status = 0x%x", child_status);
			T_END;
		}
		sleep(1);
		kill(1, SIGKILL);
		if (triggers_exception) {
			ret = pthread_join(s_exc_thread, NULL);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");
		}

		mach_port_deallocate(mach_task_self(), exc_port);

		if (i == 0) { /* The first test is setup as moving immovable receive right of a reply port. */
			expected_exception_code = (mach_exception_data_type_t)kGUARD_EXC_IMMOVABLE;
		} else if (!triggers_exception) {
			expected_exception_code = 0;
		} else if (i == 5) {
			/* 5th test is for thread_set_exception_ports with no entitlement */
			expected_exception_code = (mach_exception_data_type_t)kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE;
		} else {
			expected_exception_code = (mach_exception_data_type_t)kGUARD_EXC_INVALID_RIGHT;
		}

		T_LOG("Exception code: Received code = 0x%llx Expected code = 0x%llx", received_exception_code, expected_exception_code);
		T_EXPECT_EQ(received_exception_code, expected_exception_code, "Exception code: Received == Expected");
	}

	T_END;
}
