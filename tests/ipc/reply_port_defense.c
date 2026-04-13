#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <darwintest.h>
#include <spawn.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <signal.h>
#include "excserver_protect_state.h"
#include "../osfmk/mach/port.h"
#include "../osfmk/kern/exc_guard.h"
#include "exc_helpers.h"
#include <sys/code_signing.h>
#include "cs_helpers.h"
#include <TargetConditionals.h>
#include "ipc/ipc_utils.h"

#define MAX_ARGV 3

extern char **environ;
static mach_exception_data_type_t received_exception_code = 0;
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
	T_META_TIMEOUT(10),
	T_META_RUN_CONCURRENTLY(TRUE));

static bool
check_current_cs_flags(code_signing_config_t expected_cs_config)
{
	code_signing_config_t cur_cs_config = 0;
	size_t cs_config_size = sizeof(cur_cs_config);
	sysctlbyname("security.codesigning.config", &cur_cs_config, &cs_config_size, NULL, 0);
	return cur_cs_config & expected_cs_config;
}

static bool
is_debugging_unrestricted()
{
	/* AMFI often disables security features if debugging is unrestricted */
	bool unrestricted_debugging = check_current_cs_flags(CS_CONFIG_UNRESTRICTED_DEBUGGING);
	if (unrestricted_debugging) {
		T_LOG("UNRESTRICTED DEBUGGING");
	}
	return unrestricted_debugging;
}

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
catch_mach_exception_raise_state_identity_protected(
	__unused mach_port_t      exception_port,
	uint64_t                  thread_id,
	mach_port_t               task_id_token,
	exception_type_t          exception,
	mach_exception_data_t     codes,
	mach_msg_type_number_t    codeCnt,
	__unused int * flavor,
	__unused thread_state_t old_state,
	__unused mach_msg_type_number_t old_state_count,
	__unused thread_state_t new_state,
	__unused mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread_id, task_id_token, exception, codes, codeCnt)

	T_FAIL("Unsupported catch_mach_exception_raise_state_identity_protected");
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

	T_ASSERT_GT_UINT(codeCnt, 1, "CodeCnt");

	T_LOG("Caught %d codes", codeCnt);
	T_LOG("Caught exception type: %d code[0]: 0x%llx code[1]:0x%llx", exception, codes[0], codes[1]);
	exception_taken = exception;
	if (exception == EXC_GUARD) {
		received_exception_code = EXC_GUARD_DECODE_GUARD_FLAVOR((uint64_t)codes[0]);
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

static void
reply_port_defense(const bool thirdparty_hardened, int test_index, mach_exception_data_type_t expected_exception_code, bool triggers_exception)
{
	/* reset exception code before running this test */
	received_exception_code = 0;
	int ret = 0;

	uint32_t task_exc_guard = 0;
	size_t te_size = sizeof(&task_exc_guard);

	/* Test that the behavior is the same between these two */
	char *test_prog_name = thirdparty_hardened ?
	    "./reply_port_defense_client_3P_hardened" : "./reply_port_defense_client";
	char *child_args[MAX_ARGV];
	pid_t client_pid = 0;
	posix_spawnattr_t attrs;

	pthread_t s_exc_thread;
	mach_port_t exc_port;

	T_LOG("Check if task_exc_guard exception has been enabled\n");
	ret = sysctlbyname("kern.task_exc_guard_default", &task_exc_guard, &te_size, NULL, 0);
	T_ASSERT_EQ(ret, 0, "sysctlbyname");

	if (!(task_exc_guard & TASK_EXC_GUARD_MP_DELIVER)) {
		T_SKIP("task_exc_guard exception is not enabled");
	}

	exc_port = alloc_exception_port();
	T_QUIET; T_ASSERT_NE(exc_port, MACH_PORT_NULL, "Create a new exception port");

	/* Create exception serving thread */
	ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	/*
	 * It is allowed for us to set an exception port because we are entitled test process.
	 * If you are using this code as an example for platform binaries,
	 * use `EXCEPTION_IDENTITY_PROTECTED` instead of `EXCEPTION_DEFAULT`
	 */
	int err = posix_spawnattr_setexceptionports_np(&attrs, EXC_MASK_GUARD, exc_port,
	    (exception_behavior_t) (EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES), 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "posix_spawnattr_setflags");

	child_args[0] = test_prog_name;
	char test_num[10];
	sprintf(test_num, "%d", test_index);
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
	}
	sleep(1);
	kill(1, SIGKILL);
	if (triggers_exception) {
		ret = pthread_join(s_exc_thread, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "pthread_join");
	}

	mach_port_deallocate(mach_task_self(), exc_port);

	T_LOG("Exception code: Received code = 0x%llx Expected code = 0x%llx", received_exception_code, expected_exception_code);
	T_EXPECT_EQ(received_exception_code, expected_exception_code, "Exception code: Received == Expected");
}

T_DECL(reply_port_defense,
    "Test reply port semantics violations",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false),
    T_META_TAG_VM_PREFERRED,
    T_META_ENABLED(!TARGET_OS_OSX && !TARGET_OS_BRIDGE)) {
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}
	bool triggers_exception = true;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_IMMOVABLE;
	int test_num = 0;
	int rp_defense_max_test_idx = 3;
	/* Run the reply_port_defense tests 0, 1, 2 */
	for (int i = test_num; i < rp_defense_max_test_idx; i++) {
		reply_port_defense(true, i, expected_exception_code, triggers_exception);
		reply_port_defense(false, i, expected_exception_code, triggers_exception);
	}
	reply_port_defense(true, 3, kGUARD_EXC_INVALID_RIGHT, triggers_exception);
	reply_port_defense(false, 3, kGUARD_EXC_INVALID_RIGHT, triggers_exception);
}

T_DECL(test_unentitled_thread_set_exception_ports,
    "thread_set_exception_ports should fail without an entitlement",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	int test_num = 5;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_EXCEPTION_BEHAVIOR_ENFORCE;
	bool triggers_exception = true;

	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	// reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_unentitled_thread_set_state,
    "thread_set_state should fail without an entitlement",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false),
    T_META_ENABLED(false /* rdar://133955889 */))
{
	int test_num = 6;
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_THREAD_SET_STATE;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(unentitled_set_exception_ports_pass,
    "set_exception_ports should succeed",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	int test_num = 7;
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_NONE;
	bool triggers_exception = false;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}


T_DECL(kobject_reply_port_defense,
    "sending messages to kobjects without a proper reply port should crash",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_TAG_VM_PREFERRED,
    T_META_CHECK_LEAKS(false),
    T_META_ENABLED(!TARGET_OS_OSX && !TARGET_OS_BRIDGE)) {         /* disable on macOS due to BATS boot-args */
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}
	int test_num = 9;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_KOBJECT_REPLY_PORT_SEMANTICS;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_alloc_weak_reply_port,
    "1p is not allowed to create weak reply ports",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	if (ipc_hardening_disabled() || ipc_sip_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	int test_num = 10;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_INVALID_MPO_ENTITLEMENT;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_move_service_port,
    "service ports are immovable",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	int test_num = 11;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_SERVICE_PORT_VIOLATION_FATAL;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}


T_DECL(test_notification_policy,
    "registering notifications on an mktimer crashes",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false),
    T_META_TAG_VM_PREFERRED,
    T_META_ENABLED(!TARGET_OS_OSX && !TARGET_OS_BRIDGE)) {         /* disable on macOS due to BATS boot-args */
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_INVALID_NOTIFICATION_REQ;
	bool triggers_exception = true;

	int test_num = 12;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);

	test_num = 13;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);

	test_num = 14;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}


T_DECL(test_reply_port_extract_right_disallowed,
    "mach_port_extract_right disallowed on reply port",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	int test_num = 15;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_INVALID_RIGHT;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_mach_task_self_send_movability,
    "mach_task_self is immovable unless you have called ",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	if (ipc_hardening_disabled()) {
		T_SKIP("hardening disabled due to boot-args");
	}

	int test_num = 16;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_IMMOVABLE;
	bool triggers_exception = true;

	if (ipc_sip_disabled() || is_debugging_unrestricted()) {
		/*
		 * see `proc_check_get_movable_control_port`:
		 * enforcement is always controlled by entitlements and
		 * unrestricted debugging boot-arg
		 * or if SIP is disabled
		 */
		expected_exception_code = 0;
		triggers_exception = false;
	}

	/*
	 * it should fail on reply_port_defense_client_3P_hardened because it doesn't
	 * have com.apple.security.get-movable-control-port
	 */
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	test_num = 17; /* These tests crash the same way */
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);

	/*
	 * it should succeed on reply_port_defense_client because it
	 * has com.apple.security.get-movable-control-port
	 */
	test_num = 16;
	expected_exception_code = 0;
	triggers_exception = false;
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
	test_num = 17;
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}


T_DECL(test_send_immovability,
    "ensure that send immovability is set on ports, even if they are not copied out",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	/* attempt to move ports created by mach port construct */


	/* test_move_newly_constructed_port_immovable_send */
	int test_num = 18;
	/*
	 * connection port move_send is allowed when receive
	 * right is in space until rdar://164492988 is fixed
	 */
	/*
	 * mach_exception_data_type_t expected_exception_code = kGUARD_EXC_IMMOVABLE;
	 * bool triggers_exception = true;
	 */
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_NONE;
	bool triggers_exception = false;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);

	/* test_move_special_reply_port */
	test_num = 19;
	expected_exception_code = kGUARD_EXC_IMMOVABLE;
	triggers_exception = true;
	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_reply_port_header_disposition,
    "Ensure only make_send_once is allowed for reply port",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false),
    T_META_ENABLED(!TARGET_OS_OSX && !TARGET_OS_BRIDGE)) {
#if TARGET_OS_OSX || TARGET_OS_BRIDGE
	T_SKIP("disabled on macos");
#endif
	int test_num = 20;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_SEND_INVALID_REPLY;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_service_port_as_exception_port,
    "Ensure both service and weak service port can be used as exception port",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	int test_num = 21;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_NONE;
	bool triggers_exception = false;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}

T_DECL(test_mpo_enforce_reply_port_semantics,
    "Ensure MPO_ENFORCE_REPLY_PORT_SEMANTICS is respected and enforced",
    T_META_IGNORECRASHES(".*reply_port_defense_client.*"),
    T_META_CHECK_LEAKS(false)) {
	int test_num = 22;
	mach_exception_data_type_t expected_exception_code = kGUARD_EXC_REQUIRE_REPLY_PORT_SEMANTICS;
	bool triggers_exception = true;

	reply_port_defense(true, test_num, expected_exception_code, triggers_exception);
	reply_port_defense(false, test_num, expected_exception_code, triggers_exception);
}
