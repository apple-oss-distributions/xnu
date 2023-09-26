#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <assert.h>

#define MAX_TEST_NUM 5

static mach_port_t
alloc_server_port(void)
{
	mach_port_t server_port = MACH_PORT_NULL;
	kern_return_t kr;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &server_port);
	assert(kr == 0);

	kr = mach_port_insert_right(mach_task_self(), server_port, server_port, MACH_MSG_TYPE_MAKE_SEND);
	assert(kr == 0);

	return server_port;
}

static mach_port_t
alloc_provisional_reply_port()
{
	kern_return_t kr;
	mach_port_t reply_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	mach_port_options_t opts = {
		.flags = MPO_PROVISIONAL_REPLY_PORT | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &reply_port);
	assert(kr == 0);

	return reply_port;
}

static mach_port_t
alloc_reply_port()
{
	kern_return_t kr;
	mach_port_t reply_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	mach_port_options_t opts = {
		.flags = MPO_REPLY_PORT | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &reply_port);
	assert(kr == 0);

	return reply_port;
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
test_move_provisional_reply_port(void)
{
	kern_return_t kr;
	mach_port_t server_port = MACH_PORT_NULL, reply_port = MACH_PORT_NULL;
	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t desc;
	} msg;

	server_port = alloc_server_port();
	reply_port = alloc_provisional_reply_port();

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

int
main(int argc, char *argv[])
{
	printf("[reply_port_defense_client]: My Pid: %d\n", getpid());

	void (*tests[MAX_TEST_NUM])(void) = {
		test_immovable_receive_right,
		test_make_send_once_right,
		test_using_send_right,
		test_move_send_right,
		test_move_provisional_reply_port
	};

	if (argc < 2) {
		printf("[reply_port_defense_client]: Specify a test to run.");
		exit(-1);
	}

	int test_num = atoi(argv[1]);
	if (test_num >= 0 && test_num < MAX_TEST_NUM) {
		(*tests[test_num])();
	} else {
		printf("[reply_port_defense_client]: Invalid test num. Exiting...\n");
		exit(-1);
	}
	exit(0);
}
