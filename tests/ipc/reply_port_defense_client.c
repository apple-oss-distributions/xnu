#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <pthread/private.h>
#include <unistd.h>
#include <mach/kern_return.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/thread_status.h>
#include <os/tsd.h>
#include <assert.h>
#include <sys/codesign.h>
#include <stdbool.h>
#include <darwintest.h>
#include <mach/mk_timer.h>
#include "cs_helpers.h"

#define MAX_TEST_NUM 23

#if __arm64__
#define machine_thread_state_t          arm_thread_state64_t
#define EXCEPTION_THREAD_STATE          ARM_THREAD_STATE64
#define EXCEPTION_THREAD_STATE_COUNT    ARM_THREAD_STATE64_COUNT
#elif __x86_64__
#define machine_thread_state_t          x86_thread_state_t
#define EXCEPTION_THREAD_STATE          x86_THREAD_STATE
#define EXCEPTION_THREAD_STATE_COUNT    x86_THREAD_STATE_COUNT
#else
#error Unsupported architecture
#endif

/* in xpc/launch_private.h */
#define XPC_DOMAIN_SYSTEM 1
#define XPC_DOMAIN_PORT 7

static mach_port_t
alloc_server_port(void)
{
	mach_port_t server_port = MACH_PORT_NULL;
	kern_return_t kr;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_server_port");

	kr = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_server_port mach_port_insert_right");

	return server_port;
}

static mach_port_t
alloc_reply_port()
{
	kern_return_t kr;
	mach_port_t reply_port = MACH_PORT_NULL;

	mach_port_options_t opts = {
		.flags = MPO_REPLY_PORT | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &reply_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_reply_port");
	T_QUIET; T_ASSERT_NE(reply_port, (mach_port_t)MACH_PORT_NULL, "reply_port_create: %s", mach_error_string(kr));

	return reply_port;
}

static mach_port_t
alloc_weak_reply_port()
{
	kern_return_t kr;
	mach_port_t reply_port = MACH_PORT_NULL;

	mach_port_options_t opts = {
		.flags = MPO_WEAK_REPLY_PORT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &reply_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_reply_port");
	T_QUIET; T_ASSERT_NE(reply_port, (mach_port_t)MACH_PORT_NULL, "weak_reply_port_create: %s", mach_error_string(kr));

	return reply_port;
}

static mach_port_t
alloc_service_port(void)
{
	kern_return_t kr;
	mach_port_t service_port = MACH_PORT_NULL;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &service_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_service_port");

	return service_port;
}

static mach_port_t
alloc_bootstrap_port(void)
{
	kern_return_t kr;
	mach_port_t bootstrap_port = MACH_PORT_NULL;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_PORT,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &bootstrap_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_bootstrap_port");

	return bootstrap_port;
}

static mach_port_t
alloc_weak_service_port(void)
{
	kern_return_t kr;
	mach_port_t weak_service_port = MACH_PORT_NULL;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &weak_service_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "alloc_weak_service_port");

	return weak_service_port;
}

/* The rcv right of the port would be marked immovable. */
static void
test_immovable_receive_right(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL, reply_port = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	server_port = alloc_server_port();
	reply_port = alloc_reply_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = reply_port;
	msg.desc.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;
	kr = mach_msg_send(&msg.header);

	printf("[reply_port_defense_client test_immovable_receive_right]: mach_msg2() returned %d\n", kr);
}

/* The only way you could create a send once right is when you send the port in local port of a mach msg with MAKE_SEND_ONCE disposition. */
static void
test_make_send_once_right(void)
{
	kern_return_t kr;
	mach_port_t reply_port = alloc_reply_port();
	kr = mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	printf("[reply_port_defense_client test_make_send_once_right]: mach_port_insert_right() returned %d\n", kr);
}

static void
test_alloc_weak_reply_port(void)
{
	mach_port_t reply_port = alloc_weak_reply_port();
	printf("[reply_port_defense_client test_alloc_weak_reply_port]: did not crash with port=%d\n", reply_port);
}

/* The send right of the port would only used for guarding a name in ipc space, it would not allow to send a message. */
static void
test_using_send_right(void)
{
	kern_return_t kr;
	mach_port_t reply_port = alloc_reply_port();
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
	} msg;

	msg.header.msgh_remote_port = reply_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
	msg.header.msgh_size = sizeof msg;

	kr = mach_msg_send(&msg.header);
	printf("[reply_port_defense_client test_using_send_right]: mach_msg2() returned %d\n", kr);
}

/* The send right of the port would only used for guarding a name in ipc space, it would not allowed to get moved. */
static void
test_move_send_right(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL, reply_port = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	server_port = alloc_server_port();
	reply_port = alloc_reply_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = reply_port;
	msg.desc.disposition = MACH_MSG_TYPE_MOVE_SEND;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;

	kr = mach_msg_send(&msg.header);
	printf("[reply_port_defense_client test_move_send_right]: mach_msg2() returned %d\n", kr);
}

static void
test_unentitled_thread_set_state(void)
{
	machine_thread_state_t ts;
	mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;

	/* thread_set_state as a platform restrictions binary should fail */
	kern_return_t kr = thread_get_state(mach_thread_self(), MACHINE_THREAD_STATE, (thread_state_t)&ts, &count);

	kr = thread_set_state(mach_thread_self(), MACHINE_THREAD_STATE, (thread_state_t)&ts, count);
	assert(kr != KERN_SUCCESS);
	exit(-1); /* Should have crashed before here! */
}

static void
test_unentitled_thread_set_exception_ports(void)
{
	mach_port_t exc_port = alloc_server_port();

	/* thread_set_exception_ports as a platform restrictions binary should fail without identity protected options */
	kern_return_t kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		exc_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);

	/* thread_set_exception_ports is supposed to crash, unless the policy is turned off.
	 * Things that disable the policy: AMFI boot-args in use, SIP disabled,
	 * third party plugins in a process. The caller of this client will check
	 * whether the test crashed and correctly adhered to these policies.
	 */
	printf("thread_set_exception_ports did not crash kr=%d\n", kr);
}

static void
unentitled_set_exception_ports_pass(void)
{
	mach_port_t exc_port = alloc_server_port();

	/* thread_set_exception_ports with state *IDENTITY_PROTECTED should not fail */
	kern_return_t kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		exc_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_set_exception_ports EXCEPTION_STATE_IDENTITY_PROTECTED");

	kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		exc_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_set_exception_ports EXCEPTION_IDENTITY_PROTECTED");

	return;
}

static void
exception_ports_crash(void)
{
	kern_return_t kr;
	mach_port_t exc_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT | MPO_EXCEPTION_PORT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &exc_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "exception_ports_crash mach_port_construct");

	kr = task_register_hardened_exception_handler(current_task(),
	    0, EXC_MASK_BAD_ACCESS,
	    EXCEPTION_STATE_IDENTITY_PROTECTED, EXCEPTION_THREAD_STATE, exc_port);

	kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_BAD_ACCESS,
		exc_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);

	printf("thread_set_exception_ports did not crash: %d\n", kr);
}

static void
kobject_reply_port_defense(void)
{
	machine_thread_state_t ts;
	mach_msg_type_number_t count = MACHINE_THREAD_STATE_COUNT;
	mach_port_t port = MACH_PORT_NULL;

	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "kobject_reply_port_defense mach_port_allocate");

	// make a kobject call
	kr = thread_get_state(mach_thread_self(), MACHINE_THREAD_STATE, (thread_state_t)&ts, &count);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "kobject_reply_port_defense thread_get_state");

	// set the MIG reply port to a "normal" port
	_os_tsd_set_direct(__TSD_MIG_REPLY, (void *)(uintptr_t)port);

	kr = thread_get_state(mach_thread_self(), MACHINE_THREAD_STATE, (thread_state_t)&ts, &count);

	T_FAIL("kobject call did not crash: %d\n", kr);
}

static void
test_move_service_port(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL, service_port = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	server_port = alloc_server_port();
	service_port = alloc_service_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = service_port;
	msg.desc.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;

	kr = mach_msg_send(&msg.header);
	T_FAIL("move service port did not crash: %d\n", kr);
}

static void
test_mktimer_notification_policy(void)
{
	mach_port_t timer_port = MACH_PORT_NULL;
	mach_port_t notify_port = MACH_PORT_NULL;
	mach_port_t previous = MACH_PORT_NULL;

	kern_return_t kr = KERN_SUCCESS;

	timer_port = mk_timer_create();
	T_ASSERT_NE(timer_port, (mach_port_t)MACH_PORT_NULL, "mk_timer_create: %s", mach_error_string(kr));

	/* notification port for the mk_timer port to come back on */
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate(notify_port): %s", mach_error_string(kr));

	T_LOG("timer: 0x%x, notify: 0x%x", timer_port, notify_port);

	/* request a port-destroyed notification on the timer port, which should crash */
	kr = mach_port_request_notification(mach_task_self(), timer_port, MACH_NOTIFY_PORT_DESTROYED,
	    0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	T_FAIL("mktimer did not crash with exc_guard kr=%d", kr);
}

static void
test_reply_port_port_destroyed_notification_policy(void)
{
	mach_port_t reply_port = MACH_PORT_NULL;
	mach_port_t previous = MACH_PORT_NULL;
	mach_port_t notify_port = MACH_PORT_NULL;

	kern_return_t kr = KERN_SUCCESS;
	mach_port_options_t opts = {};

	reply_port = alloc_reply_port();

	kr = mach_port_construct(mach_task_self(), &opts, 0, &notify_port);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate(notify_port): %s", mach_error_string(kr));

	/* request a port-destroyed notification on the reply port */
	kr = mach_port_request_notification(mach_task_self(), reply_port, MACH_NOTIFY_PORT_DESTROYED,
	    0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	printf("reply port did not crash kr=%d\n", kr);
}

static void
test_reply_port_no_senders_notification_policy(void)
{
	mach_port_t reply_port = MACH_PORT_NULL;
	mach_port_t previous = MACH_PORT_NULL;
	mach_port_t notify_port = MACH_PORT_NULL;

	kern_return_t kr = KERN_SUCCESS;

	reply_port = alloc_reply_port();
	mach_port_options_t opts = {};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &notify_port);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_allocate(notify_port): %s", mach_error_string(kr));

	/* request a no-senders notification on the reply port */
	kr = mach_port_request_notification(mach_task_self(), reply_port, MACH_NOTIFY_NO_SENDERS,
	    0, notify_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);

	T_FAIL("reply port did not crash kr=%d", kr);
}

static void
test_reply_port_insert_right_disallowed(void)
{
	mach_port_t reply_port = MACH_PORT_NULL;
	mach_port_t send_reply_port = MACH_PORT_NULL;
	mach_msg_type_name_t right = 0;

	kern_return_t kr = KERN_SUCCESS;
	reply_port = alloc_reply_port();
	kr = mach_port_extract_right(mach_task_self(), reply_port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &send_reply_port, &right);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "mach_port_extract_right(reply_port, make_send_once): %s", mach_error_string(kr));

	T_FAIL("reply port make send once outside of kmsg did not crash kr=%d", kr);
}

static kern_return_t
move_port(mach_port_t immovable_port)
{
	mach_port_t server_port = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	server_port = alloc_server_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = immovable_port;
	msg.desc.disposition = MACH_MSG_TYPE_MOVE_SEND;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;
	return mach_msg_send(&msg.header);
}

/* attempt to move mach_task_self */
static void
test_mach_task_self_send_movability(void)
{
	kern_return_t kr = move_port(mach_task_self());
	printf("[reply_port_defense_client test_task_self_immovable]: mach_msg2() returned %d\n", kr);
}

/* mach_task_self() is movable before and after calling task_get_special_port, when entitled */
static void
test_task_self_movable_send(void)
{
	kern_return_t kr;
	mach_port_t task_self = MACH_PORT_NULL;

	kr = move_port(mach_task_self());
	T_EXPECT_MACH_SUCCESS(kr, "move mach_task_self");

	kr = task_get_special_port(mach_task_self(), TASK_KERNEL_PORT, &task_self);
	T_EXPECT_MACH_SUCCESS(kr, "task_get_special_port");

	kr = move_port(mach_task_self());
	T_EXPECT_MACH_SUCCESS(kr, "move mach_task_self again");

	mach_port_t thread_port = pthread_mach_thread_np(pthread_main_thread_np());
	kr = move_port(thread_port);
	T_EXPECT_MACH_SUCCESS(kr, "move main_thread_port");
}

static void
test_move_newly_constructed_port_immovable_send(void)
{
	kern_return_t kr;
	mach_port_t port = MACH_PORT_NULL;

	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT | MPO_CONNECTION_PORT,
		.service_port_name = MPO_ANONYMOUS_SERVICE,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &port);

	kr = move_port(port);
	printf("kr=%d\n", kr);
	T_EXPECT_MACH_ERROR(kr, KERN_DENIED, "move port with immovable send rights");
}

static void
test_move_special_reply_port(void)
{
	kern_return_t kr;
	mach_port_t special_reply_port = thread_get_special_reply_port();

	kr = move_port(special_reply_port);
	T_EXPECT_MACH_ERROR(kr, KERN_DENIED, "move special reply port");
}

static void
test_reply_port_header_disposition(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL;
	mach_port_t reply_port1 = MACH_PORT_NULL, reply_port2 = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
	} msg;

	server_port = alloc_server_port();
	reply_port1 = alloc_reply_port();
	reply_port2 = alloc_reply_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_size = sizeof msg;

	/* sending with make_send_once should succeed */
	msg.header.msgh_local_port = reply_port1;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE);
	kr = mach_msg_send(&msg.header);
	T_EXPECT_MACH_SUCCESS(kr, "reply_port_disposition make_send_once");

	/* sending with make_send should fail */
	msg.header.msgh_local_port = reply_port2;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND);
	kr = mach_msg_send(&msg.header);
	T_ASSERT_MACH_ERROR(kr, MACH_SEND_INVALID_REPLY, "reply_port_disposition make_send");
}

static void
test_service_port_as_exception_port(void)
{
	kern_return_t kr;
	mach_port_t service_port = alloc_service_port();
	mach_port_t bootstrap_port = alloc_bootstrap_port();
	mach_port_t weak_service_port = alloc_weak_service_port();

	/* Should succeed */
	kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		service_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "test_service_port_as_exception_port IOT_SERVICE_PORT");

	/* Should succeed */
	kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		weak_service_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "test_service_port_as_exception_port IOT_WEAK_SERVICE_PORT");

	/* Should fail, but no guard exception */
	kr = thread_set_exception_ports(
		mach_thread_self(),
		EXC_MASK_ALL,
		bootstrap_port,
		(exception_behavior_t)((unsigned int)EXCEPTION_STATE_IDENTITY_PROTECTED | MACH_EXCEPTION_CODES),
		EXCEPTION_THREAD_STATE);
	T_QUIET; T_ASSERT_MACH_ERROR(kr, KERN_INVALID_RIGHT, "test_service_port_as_exception_port IOT_BOOTSTRAP_PORT");
}

static void
test_reply_port_semantics(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL;
	mach_port_t non_reply_port = MACH_PORT_NULL;
	mach_port_t port_with_semantics = MACH_PORT_NULL;

	struct {
		mach_msg_header_t header;
	} msg;

	server_port = alloc_server_port();
	non_reply_port = alloc_server_port();

	msg.header.msgh_remote_port = server_port;
	msg.header.msgh_size = sizeof msg;

	/*
	 * Sending to a port without enforcing
	 * reply port semantics should succeed.
	 */
	msg.header.msgh_local_port = non_reply_port;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE);
	kr = mach_msg_send(&msg.header);
	T_EXPECT_MACH_SUCCESS(kr,
	    "talking to RR without reply port semantics, that's fine");

	/*
	 * Sending to a port with enforcing
	 * reply port semantics should fail.
	 */
	mach_port_options_t opts = {
		.flags = MPO_ENFORCE_REPLY_PORT_SEMANTICS | MPO_INSERT_SEND_RIGHT,
	};
	kr = mach_port_construct(mach_task_self(), &opts, 0, &port_with_semantics);
	T_EXPECT_MACH_SUCCESS(kr, "constructing a port with enforce reply port semantics");
	msg.header.msgh_remote_port = port_with_semantics;
	msg.header.msgh_local_port = non_reply_port;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE);
	kr = mach_msg_send(&msg.header);

	T_FAIL("reply port semantics did not crash: %d\n", kr);
}

int
main(int argc, char *argv[])
{
	uint32_t my_csflags = 0;
	bool thirdparty_hardened = !strcmp(argv[0], "./reply_port_defense_client_3P_hardened");
	T_ASSERT_POSIX_ZERO(csops(getpid(), CS_OPS_STATUS, &my_csflags, sizeof(my_csflags)), NULL);

	/* TODO add some sysctl which disabled platform binary bit here */
	if ((my_csflags & CS_PLATFORM_BINARY) == thirdparty_hardened) {
		printf("platform binary does not match expected\n");
		return -1;
	}


	void (*tests[MAX_TEST_NUM])(void) = {
		test_immovable_receive_right, /* 0 */
		test_using_send_right,        /* 1 */
		test_move_send_right,         /* 2 */
		test_make_send_once_right,    /* 3 */
		NULL, /* 4 */
		test_unentitled_thread_set_exception_ports, /* 5 */
		test_unentitled_thread_set_state, /* 6 */
		unentitled_set_exception_ports_pass,
		exception_ports_crash, /* 8 */
		kobject_reply_port_defense, /* 9 */
		test_alloc_weak_reply_port, /* 10 */
		test_move_service_port, /* 11 */
		test_mktimer_notification_policy, /* 12 */
		test_reply_port_port_destroyed_notification_policy, /* 13 */
		test_reply_port_no_senders_notification_policy, /* 14 */
		test_reply_port_insert_right_disallowed, /* 15 */
		test_mach_task_self_send_movability, /* 16 */
		test_task_self_movable_send, /* 17 */
		test_move_newly_constructed_port_immovable_send, /* 18 */
		test_move_special_reply_port, /* 19 */
		test_reply_port_header_disposition, /* 20 */
		test_service_port_as_exception_port, /* 21 */
		test_reply_port_semantics /* 22 */
	};

	if (argc < 2) {
		printf("[reply_port_defense_client]: Specify a test to run.");
		exit(-1);
	}

	int test_num = atoi(argv[1]);
	printf("[reply_port_defense_client]: My Pid: %d Test num: %d third_party_hardened: %s\n",
	    getpid(), test_num, thirdparty_hardened ? "yes" : "no");
	fflush(stdout);
	if (test_num >= 0 && test_num < MAX_TEST_NUM) {
		(*tests[test_num])();
	} else {
		printf("[reply_port_defense_client]: Invalid test num. Exiting...\n");
		exit(-1);
	}
	printf("Child exiting cleanly!!\n");
	fflush(stdout);
	// return 0;
	exit(0);
}
