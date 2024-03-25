#include <stdio.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <bootstrap.h>
#include <fcntl.h>
#include <sys/errno.h>
#include <sys/resource.h>
#include <dispatch/dispatch.h>

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
	args->server_port_name = "TEST_KQWORKLOOP_LIMITS";
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

	printf("client: Set service port as the resource notify port\n");
	ret = task_set_special_port(mach_task_self(), TASK_RESOURCE_NOTIFY_PORT, client_args.server_port);
	if (ret) {
		mach_error("client: task_set_special_port()", ret);
		exit(1);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int fd = 0;
	int soft_limit = 0;
	int hard_limit = 0;
	int test_num = 0;
	int ret = 0;
	if (argc == 4) {
		soft_limit = atoi(argv[1]);
		hard_limit = atoi(argv[2]);
		test_num = atoi(argv[3]);
	} else {
		printf("Usage: ./kqworkloop_limits_client <soft limit> <hard limit> <test_num>\n");
		goto fail_and_exit;
	}

	printf("client: soft limit = %d, hard limit = %d, test_num = %d\n", soft_limit, hard_limit, test_num);

	// Connect to the server first before then spawning kqworkloops to hit the
	// limits
	if (test_num == 2) {
		ret = connect_to_server();
		if (ret) {
			goto fail_and_exit;
		}
	}


	printf("client: Starting the kqworkloop allocation loop\n");
	int i = 0;
	while (ret == 0) {
		/* Only hang 10 kqworkloops off of a single port */
		mach_port_t port;
		kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
		assert(kr == KERN_SUCCESS);

		for (int j = 0; j < 10; j++) {
			/* Allocate a kqworkloop */
			dispatch_queue_t dq = dispatch_queue_create("leaked queue", DISPATCH_QUEUE_SERIAL);
			dispatch_source_t ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, port, 0, dq);
			dispatch_source_set_event_handler(ds, ^{
				printf("Received a message on port");
			});
			dispatch_activate(ds);
			dispatch_release(dq);

			if ((i % 20) == 0) {
				/* Print the sources in the multiple of 20 */
				printf("client: Allocating source #%d\n", i);
				sleep(1);
			}

			if (i == soft_limit) {
				printf("client: Hit the soft limit \n");
				if (!hard_limit) {
					exit(0);
				}
			}

			if (hard_limit && i == hard_limit) {
				printf("client: Hit the hard limit\n");
				pause();
			}

			i++;
		}
	}

fail_and_exit:
	exit(91);
}
