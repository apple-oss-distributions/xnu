#include <stdio.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <bootstrap.h>

static int
connect_to_server(void);

typedef struct {
	mach_msg_header_t   header;
	mach_msg_body_t     body;
	mach_msg_port_descriptor_t port_descriptor;
	mach_msg_trailer_t  trailer;            // subtract this when sending
} ipc_complex_message;

static ipc_complex_message icm_request = {};

struct args {
	const char *progname;
	int verbose;
	int voucher;
	int num_msgs;
	const char *server_port_name;
	mach_port_t server_port;
	mach_port_t reply_port;
	int request_msg_size;
	void *request_msg;
	int reply_msg_size;
	void *reply_msg;
	uint32_t persona_id;
	long client_pid;
};

static void
parse_args(struct args *args)
{
	args->verbose = 0;
	args->voucher = 0;
	args->server_port_name = "TEST_PORT_TABLE_LIMITS";
	args->server_port = MACH_PORT_NULL;
	args->reply_port = MACH_PORT_NULL;
	args->num_msgs = 1;
	args->request_msg_size = sizeof(ipc_complex_message) - sizeof(mach_msg_trailer_t);
	args->reply_msg_size = sizeof(ipc_complex_message) - sizeof(mach_msg_trailer_t);
	args->request_msg = &icm_request;
	args->reply_msg = NULL;
	args->client_pid = getpid();
}

static int
connect_to_server(void)
{
	struct args client_args = {};
	parse_args(&client_args);
	mach_port_t reply_port, dummy_port;

	/* Find the bootstrap port */
	mach_port_t bsport;
	kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (ret) {
		mach_error("client: task_get_bootstrap_port()", ret);
		exit(1);
	}

	printf("client: Look up bootstrap service port\n");
	ret = bootstrap_look_up(bsport, client_args.server_port_name,
	    &client_args.server_port);
	if (ret) {
		mach_error("client: bootstrap_look_up()", ret);
		exit(1);
	}

	printf("client: Allocate reply port\n");
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &reply_port);
	if (ret) {
		mach_error("client: allocate reply port", ret);
		exit(1);
	}
	ret = mach_port_insert_right(mach_task_self(), reply_port, reply_port, MACH_MSG_TYPE_MAKE_SEND );
	if (ret) {
		mach_error("client: allocate reply port", ret);
		exit(1);
	}

	printf("client: Allocate dummy port\n");
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &dummy_port);
	if (ret) {
		mach_error("client: allocate dummy port", ret);
		exit(1);
	}

	/* Construct the message */
	mach_msg_header_t *request = (mach_msg_header_t *)client_args.request_msg;
	request->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND,
	    0, 0) | MACH_MSGH_BITS_COMPLEX;
	request->msgh_size = (mach_msg_size_t)client_args.request_msg_size;
	request->msgh_remote_port = client_args.server_port;
	request->msgh_local_port = reply_port;
	request->msgh_id = 1;

	ipc_complex_message *complexmsg = (ipc_complex_message *)request;
	complexmsg->body.msgh_descriptor_count = 1;
	complexmsg->port_descriptor.name = dummy_port;
	complexmsg->port_descriptor.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	complexmsg->port_descriptor.type = MACH_MSG_PORT_DESCRIPTOR;

	mach_msg_option_t option = MACH_SEND_MSG | MACH_RCV_MSG;

	printf("client: Sending request\n");
	mach_msg_return_t mret = mach_msg(request,
	    option,
	    (mach_msg_size_t)client_args.request_msg_size,
	    sizeof(ipc_complex_message),
	    reply_port,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);

	printf("client: Received reply\n");
	if (mret) {
		mach_error("client: mach_msg", mret);
		exit(1);
	}

	return 0;
}

static inline mach_port_type_t
get_port_type(mach_port_t mp)
{
	mach_port_type_t type = 0;
	mach_port_type(mach_task_self(), mp, &type);
	return type;
}

int
main(int argc, char *argv[])
{
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t retval = KERN_SUCCESS;
	int soft_limit = 0;
	int hard_limit = 0;
	int test_num = 0;
	if (argc == 4) {
		soft_limit = atoi(argv[1]);
		hard_limit = atoi(argv[2]);
		test_num = atoi(argv[3]);
	} else {
		printf("Usage: ./port_table_limits_client <soft limit> <hard limit> <test_num>\n");
		goto fail_and_exit;
	}

	mach_port_t task = mach_task_self();

	if (test_num == 2) {
		printf("client: Wait for a reply message from server before continuing port allocation\n");
		int ret = connect_to_server();
		if (ret) {
			goto fail_and_exit;
		}
	}

	printf("client: Starting the receive right allocation loop\n");
	int i = 0;
	while (!retval) {
		retval = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &port);
		assert(retval == 0);
		assert(get_port_type(port) == MACH_PORT_TYPE_RECEIVE);
		if ((i % 1000) == 0) {
			/* Print every port in the multiple of 1000 */
			printf("client: Port #%d\n", i);
			sleep(1);
		}
		if (i == hard_limit) {
			printf("client: Hitting the hard limit\n");
		}
		if (i > hard_limit) {
			printf("client: Putting child to sleep\n");
			/* Add a sleep so that there is time for server to collect data */
			sleep(5);
		}
		i++;
	}

fail_and_exit:
	exit(1);
}
