#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/event.h>
#include <errno.h>
#include <string.h>
#include <libproc.h>

#include <darwintest.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.kevent"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("kevent"));

extern int __proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg, user_addr_t buffer, int32_t buffersize);

T_DECL(avoid_leaking_KASLR, "rdar://101248992") {
	int kq = kqueue();
	T_ASSERT_GE(kq, 0, "Valid kqueue");

	mach_port_t sync_port = MACH_PORT_NULL, mq_port = MACH_PORT_NULL;
	kern_return_t kr = KERN_SUCCESS;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sync_port);
	T_ASSERT_MACH_SUCCESS(kr, "allocated sync port");
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &mq_port);
	T_ASSERT_MACH_SUCCESS(kr, "allocated mq port");


	/* Create a kmsg which has the receive right of mq port in it for later copy
	 * out */
	typedef struct msg_request_s {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
	}* msg_request_t;

	typedef struct msg_reply_s {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port;
		mach_msg_trailer_t trailer;
	}* msg_reply_t;

	union {
		struct msg_request_s request;
		struct msg_reply_s reply;
	} message;
	memset(&message, 0, sizeof(message));

	msg_request_t requestp = &message.request;
	msg_reply_t replyp = &message.reply;

	*requestp = (struct msg_request_s) {
		.header = {
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0, MACH_MSGH_BITS_COMPLEX),
			.msgh_remote_port = sync_port,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_voucher_port = MACH_PORT_NULL,
			.msgh_size = sizeof(*requestp),
			.msgh_id = 0x88888888,
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port = {
			.name = mq_port,
			.type = MACH_MSG_PORT_DESCRIPTOR,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
		},
	};

	/*
	 *	Send the receive right of mq_port to sync_port for later copyout.
	 */
	kr = mach_msg(&requestp->header, MACH_SEND_MSG, sizeof(*requestp), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "sending message to sync port");

	/*
	 * The EV_DISPATCH is required that can pass filt_machport_kqueue_has_turnstile().
	 * The received message will be copied out to replyp.
	 * In filt_machport_stash_port(), the value in ext[3] will be set to the mq_port object.
	 */
	struct kevent_qos_s req_event = {
		.ident = sync_port,
		.filter = EVFILT_MACHPORT,
		.flags = EV_ADD | EV_DISPATCH,
		.fflags = MACH_RCV_MSG,
		.ext = {
			[0] = (uint64_t)replyp,
			[1] = sizeof(*replyp),
		},
	};
	struct kevent_qos_s reply_event = {};

	int nevents = kevent_qos(kq, &req_event, 1, &reply_event, 1, NULL, NULL, 0);
	T_ASSERT_EQ(nevents, 1, NULL);
	T_ASSERT_EQ(replyp->body.msgh_descriptor_count, 1, NULL);
	assert(MACH_PORT_VALID(replyp->port.name) && replyp->port.disposition == MACH_MSG_TYPE_MOVE_RECEIVE);

	struct kevent_extinfo extinfo;
	int knotes = __proc_info(PROC_INFO_CALL_PIDFDINFO, getpid(), PROC_PIDFDKQUEUE_EXTINFO, kq, (user_addr_t)&extinfo, sizeof(extinfo));
	T_ASSERT_EQ(knotes, 1, NULL);
	T_ASSERT_EQ(extinfo.kqext_kev.ident, sync_port, NULL);

	uint64_t leaked_addr = extinfo.kqext_kev.ext[3];
	T_ASSERT_EQ(leaked_addr, NULL, "Leaked kernel address");
}
