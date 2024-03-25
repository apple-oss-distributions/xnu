#include <mach/mach.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <mach/task.h>
#include <stdbool.h>
#include <mach/mk_timer.h>
#include "cs_helpers.h"

/*
 * DO NOT run this test file by itself.
 * This test is meant to be invoked by control_port_options darwintest.
 *
 * If hard enforcement for pinned control port is on, pinned tests are
 * expected to generate fatal EXC_GUARD.
 *
 * If hard enforcement for immovable control port is on, immovable tests are
 * expected to generate fatal EXC_GUARD.
 *
 * The type of exception raised (if any) is checked on control_port_options side.
 */
#define MAX_TEST_NUM 21

#ifndef MACH64_SEND_ANY
#define MACH64_SEND_ANY 0x0000000800000000ull
#define MACH64_SEND_MQ_CALL 0x0000000400000000ull
#endif

static int
attempt_send_immovable_port(mach_port_name_t port, mach_msg_type_name_t disp)
{
	mach_port_t server;
	kern_return_t kr;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server);
	assert(kr == 0);

	kr = mach_port_insert_right(mach_task_self(), server, server, MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == 0);

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	msg.header.msgh_remote_port = server;
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
	msg.header.msgh_size = sizeof msg;

	msg.body.msgh_descriptor_count = 1;

	msg.desc.name = port;
	msg.desc.disposition = disp;
	msg.desc.type = MACH_MSG_PORT_DESCRIPTOR;

	return mach_msg_send(&msg.header);
}

static void
pinned_test_main_thread_mod_ref(void)
{
	printf("[Crasher]: Mod refs main thread's self port to 0\n");
	mach_port_t thread_self = mach_thread_self();
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), thread_self, MACH_PORT_RIGHT_SEND, -2);

	printf("[Crasher pinned_test_main_thread_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void* _Nullable
pthread_run(void *_Nullable)
{
	printf("[Crasher]: Deallocate pthread_self\n");
	mach_port_t th_self = pthread_mach_thread_np(pthread_self());
	kern_return_t kr = mach_port_deallocate(mach_task_self(), th_self);

	printf("[Crasher pinned_test_pthread_dealloc] mach_port_deallocate returned %s \n.", mach_error_string(kr));
	return NULL;
}

static void
pinned_test_pthread_dealloc(void)
{
	printf("[Crasher]: Create a pthread and deallocate its self port\n");
	pthread_t thread;
	int ret = pthread_create(&thread, NULL, pthread_run, NULL);
	assert(ret == 0);
	ret = pthread_join(thread, NULL);
	assert(ret == 0);
}

static void
pinned_test_task_self_dealloc(void)
{
	printf("[Crasher]: Deallocate mach_task_self twice\n");
	mach_port_t task_self = mach_task_self();
	kern_return_t kr = mach_port_deallocate(task_self, task_self);
	assert(kr == 0);
	kr = mach_port_deallocate(task_self, task_self);

	printf("[Crasher pinned_test_task_self_dealloc] mach_port_deallocate returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_task_self_mod_ref(void)
{
	printf("[Crasher]: Mod refs mach_task_self() to 0\n");
	kern_return_t kr = mach_port_mod_refs(mach_task_self(), mach_task_self(), MACH_PORT_RIGHT_SEND, -2);

	printf("[Crasher pinned_test_task_self_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_task_threads_mod_ref(void)
{
	printf("[Crasher]: task_threads should return pinned thread ports. Mod refs them to 0\n");
	thread_array_t th_list;
	mach_msg_type_number_t th_cnt;
	kern_return_t kr;
	mach_port_t th_kp = mach_thread_self();
	mach_port_deallocate(mach_task_self(), th_kp);

	kr = task_threads(mach_task_self(), &th_list, &th_cnt);
	mach_port_deallocate(mach_task_self(), th_list[0]);

	kr = mach_port_mod_refs(mach_task_self(), th_list[0], MACH_PORT_RIGHT_SEND, -1);

	printf("[Crasher pinned_test_task_threads_mod_ref] mach_port_mod_refs returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_mach_port_destroy(void)
{
	kern_return_t kr = mach_port_destroy(mach_task_self(), mach_task_self());
	printf("[Crasher pinned_test_mach_port_destroy] mach_port_destroy returned %s \n.", mach_error_string(kr));
}

static void
pinned_test_move_send_as_remote_port(void)
{
	struct {
		mach_msg_header_t header;
	} msg;

	kern_return_t kr = mach_port_deallocate(mach_task_self(), mach_task_self());
	assert(kr == 0);

	/*
	 * We allow move send on remote kobject port but this should trip on pinning on last ref.
	 * See: IPC_OBJECT_COPYIN_FLAGS_ALLOW_IMMOVABLE_SEND.
	 */
	msg.header.msgh_remote_port = mach_task_self();
	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND, 0);
	msg.header.msgh_id = 2000;
	msg.header.msgh_size = sizeof msg;

	kr = mach_msg_send(&msg.header);

	printf("[Crasher pinned_test_move_send_as_remote_port] mach_msg_send returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_as_remote_port(void)
{
	struct {
		mach_msg_header_t header;
	} msg;

	/* Local port cannot be immovable. See: ipc_right_copyin_check_reply() */
	msg.header.msgh_remote_port = mach_task_self();
	msg.header.msgh_local_port = mach_task_self();
	msg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MOVE_SEND);
	msg.header.msgh_id = 2000;
	msg.header.msgh_size = sizeof msg;

	kern_return_t kr = mach_msg_send(&msg.header);

	printf("[Crasher immovable_test_move_send_as_remote_port] mach_msg_send returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_task_self(void)
{
	kern_return_t kr;
	printf("[Crasher]: Move send mach_task_self_\n");
	kr = attempt_send_immovable_port(mach_task_self(), MACH_MSG_TYPE_MOVE_SEND);

	printf("[Crasher immovable_test_move_send_task_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_copy_send_task_self(void)
{
	kern_return_t kr;
	printf("[Crasher]: Copy send mach_task_self_\n");
	kr = attempt_send_immovable_port(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);

	printf("[Crasher immovable_test_copy_send_task_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_thread_self(void)
{
	kern_return_t kr;
	printf("[Crasher]: Move send main thread's self port\n");
	kr = attempt_send_immovable_port(mach_thread_self(), MACH_MSG_TYPE_MOVE_SEND);

	printf("[Crasher immovable_test_move_send_thread_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_copy_send_thread_self(void)
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Copy send main thread's self port\n");
	port = mach_thread_self();
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_thread_self] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
}

static void
immovable_test_copy_send_task_read(void)
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Copy send task read port\n");
	kr = task_get_special_port(mach_task_self(), TASK_READ_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_task_read] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
}

static void
immovable_test_copy_send_task_inspect(void)
{
	kern_return_t kr;
	mach_port_t port;
	printf("[Crasher]: Move send task inspect port\n");
	kr = task_get_special_port(mach_task_self(), TASK_INSPECT_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_MOVE_SEND);
	printf("[Crasher immovable_test_copy_send_task_inspect] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));
}

static void
immovable_test_move_send_thread_inspect(void)
{
	kern_return_t kr;
	mach_port_t port;
	mach_port_t th_port = mach_thread_self();

	printf("[Crasher]: Move send thread inspect port\n");
	kr = thread_get_special_port(th_port, THREAD_INSPECT_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_MOVE_SEND);
	printf("[Crasher immovable_test_move_send_thread_inspect] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), th_port);
}

static void
immovable_test_move_send_raw_thread(void)
{
	kern_return_t kr;
	mach_port_t port;

	kr = thread_create(mach_task_self(), &port);
	assert(kr == 0);
	kr = mach_port_deallocate(mach_task_self(), port); /* not pinned, should not crash */

	kr = thread_create(mach_task_self(), &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_MOVE_SEND); /* immovable, should crash here */
	printf("[Crasher immovable_test_move_send_raw_thread] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	kr = thread_terminate(port);
	assert(kr == 0);
}

static void
immovable_test_copy_send_thread_read(void)
{
	kern_return_t kr;
	mach_port_t port;
	mach_port_t th_port = mach_thread_self();

	printf("[Crasher]: Copy send thread read port\n");
	kr = thread_get_special_port(th_port, THREAD_READ_PORT, &port);
	assert(kr == 0);
	kr = attempt_send_immovable_port(port, MACH_MSG_TYPE_COPY_SEND);
	printf("[Crasher immovable_test_copy_send_thread_read] attempt_send_immovable_port returned %s \n.", mach_error_string(kr));

	mach_port_deallocate(mach_task_self(), port);
	mach_port_deallocate(mach_task_self(), th_port);
}

static void
cfi_test_no_bit_set(void)
{
	printf("[Crasher]: Try sending mach_msg2() without setting CFI bits\n");

	mach_msg_header_t header;
	kern_return_t kr;

	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_remote_port = mach_task_self();
	header.msgh_id = 3409;
	header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	header.msgh_size = sizeof(header);

	kr = mach_msg2(&header, MACH64_SEND_MSG, header, header.msgh_size, 0, MACH_PORT_NULL,
	    0, MACH_MSG_PRIORITY_UNSPECIFIED);
	/* crash */
	printf("[Crasher cfi_test_no_bit_set]: mach_msg2() returned %d\n", kr);
}

static void
cfi_test_two_bits_set(void)
{
	printf("[Crasher]: Try sending mach_msg2() but setting 2 CFI bits\n");

	mach_msg_header_t header;
	kern_return_t kr;

	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_remote_port = mach_task_self();
	header.msgh_id = 3409;
	header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	header.msgh_size = sizeof(header);

	kr = mach_msg2(&header, MACH64_SEND_MSG | MACH64_SEND_ANY | MACH64_SEND_KOBJECT_CALL,
	    header, header.msgh_size, 0, MACH_PORT_NULL,
	    0, MACH_MSG_PRIORITY_UNSPECIFIED);
	/* crash */
	printf("[Crasher cfi_test_two_bits_set]: mach_msg2() returned %d\n", kr);
}

static void
cfi_test_msg_to_timer_port(void)
{
	printf("[Crasher]: Try sending mach_msg2() to timer port\n");

	mach_port_t timer = MACH_PORT_NULL;
	struct oversize_msg {
		mach_msg_header_t header;
		char data[2048];
	} msg;

	kern_return_t kr;
	natural_t kotype;
	mach_vm_address_t addr;

#define IKOT_TIMER 8
	timer = mk_timer_create();
	assert(timer != MACH_PORT_NULL);

	/* Make sure it's a kobject port */
	kr = mach_port_kobject(mach_task_self(), timer, &kotype, &addr);
	assert(kr == KERN_SUCCESS);
	assert(kotype == IKOT_TIMER);

	msg.header.msgh_local_port = MACH_PORT_NULL;
	msg.header.msgh_remote_port = timer;
	msg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0);
	msg.header.msgh_size = sizeof(msg);

	/* Timer port must use MACH64_SEND_MQ_CALL */
	kr = mach_msg2(&msg, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL,
	    msg.header, msg.header.msgh_size, 0, MACH_PORT_NULL,
	    0, MACH_MSG_PRIORITY_UNSPECIFIED);
	assert(kr == KERN_SUCCESS);
	printf("Message sent to timer port successfully\n");

	/* Using MACH64_SEND_KOBJECT_CALL should crash */
	kr = mach_msg2(&msg, MACH64_SEND_MSG | MACH64_SEND_KOBJECT_CALL,
	    msg.header, msg.header.msgh_size, 0, MACH_PORT_NULL,
	    0, MACH_MSG_PRIORITY_UNSPECIFIED);
	/* crash */
	printf("[Crasher cfi_test_timer_port]: mach_msg2() returned %d\n", kr);
}

static void
cfi_test_wrong_bit_set(void)
{
	printf("[Crasher]: Try sending mach_msg2() but setting wrong CFI bits\n");

	mach_msg_header_t header;
	kern_return_t kr;

	header.msgh_local_port = MACH_PORT_NULL;
	header.msgh_remote_port = mach_task_self();
	header.msgh_id = 3409;
	header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	header.msgh_size = sizeof(header);

	/* Using MACH64_SEND_MQ_CALL but destination is a kobject port */
	kr = mach_msg2(&header, MACH64_SEND_MSG | MACH64_SEND_MQ_CALL,
	    header, header.msgh_size, 0, MACH_PORT_NULL,
	    0, MACH_MSG_PRIORITY_UNSPECIFIED);
	/* crash */
	printf("[Crasher cfi_test_wrong_bit_set]: mach_msg2() returned %d\n", kr);
}

int
main(int argc, char *argv[])
{
	void (*tests[MAX_TEST_NUM])(void) = {
		pinned_test_main_thread_mod_ref,
		pinned_test_pthread_dealloc,
		pinned_test_task_self_dealloc,
		pinned_test_task_self_mod_ref,
		pinned_test_task_threads_mod_ref,
		pinned_test_mach_port_destroy,
		pinned_test_move_send_as_remote_port,

		immovable_test_move_send_task_self,
		immovable_test_copy_send_task_self,
		immovable_test_move_send_thread_self,
		immovable_test_copy_send_thread_self,
		immovable_test_copy_send_task_read,
		immovable_test_copy_send_task_inspect,
		immovable_test_move_send_thread_inspect,
		immovable_test_copy_send_thread_read,
		immovable_test_move_send_as_remote_port,
		immovable_test_move_send_raw_thread,

		cfi_test_no_bit_set,
		cfi_test_two_bits_set,
		cfi_test_wrong_bit_set,
		cfi_test_msg_to_timer_port,
	};
	printf("[Crasher]: My Pid: %d\n", getpid());

	if (argc < 2) {
		printf("[Crasher]: Specify a test to run.");
		exit(-1);
	}

	bool third_party_hardened = !strcmp(argv[0], "imm_pinned_control_port_crasher_3P_hardened");
	if (third_party_hardened) {
		// Ensure that we can set this crasher as a non-platform binary
		if (remove_platform_binary() != 0) {
			printf("Failed to remove platform binary, exiting\n");
			exit(1);
		}
	}

	int test_num = atoi(argv[1]);


	if (test_num >= 0 && test_num < MAX_TEST_NUM) {
		printf("[Crasher]: Running test num %d\n", test_num);
		(*tests[test_num])();
	} else {
		printf("[Crasher]: Invalid test num: %d. Exiting...\n", test_num);
		exit(-1);
	}

	exit(0);
}
