#include <darwintest.h>
#include <errno.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipc"),
	T_META_CHECK_LEAKS(false));

mach_port_t thread_get_special_reply_port();

T_DECL(port_stash_turnstile, "stashing knote turnstile on port should take a +1")
{
	int kq = kqueue();
	T_ASSERT_GE(kq, 0, "have a valid kqueue");

#define KNOTE_PORT_COUNT 2

	kern_return_t kr = KERN_SUCCESS;

	mach_port_t sync_port = MACH_PORT_NULL, knote_port[KNOTE_PORT_COUNT] = {MACH_PORT_NULL};
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sync_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");
	for (size_t i = 0; i < KNOTE_PORT_COUNT; i++) {
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &knote_port[i]);
		T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");
	}

	typedef struct sync_knote_msg_local_s sync_knote_msg_local_t;
	typedef struct sync_knote_msg_remote_s sync_knote_msg_remote_t;

#pragma pack(4)
	struct sync_knote_msg_local_s {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port[KNOTE_PORT_COUNT];
		uint64_t sequence;
	};
#pragma pack(0)

#pragma pack(4)
	struct sync_knote_msg_remote_s {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port[KNOTE_PORT_COUNT];
		uint64_t sequence;
		mach_msg_trailer_t trailer;
	};
#pragma pack(0)

	union {
		sync_knote_msg_local_t local;
		sync_knote_msg_remote_t remote;
	} message;

	sync_knote_msg_local_t *local = &message.local;
	sync_knote_msg_remote_t *remote = &message.remote;

	local->header = (mach_msg_header_t){
		.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX),
		.msgh_remote_port = sync_port,
		.msgh_local_port = MACH_PORT_NULL,
		.msgh_voucher_port = MACH_PORT_NULL,
		.msgh_size = sizeof(sync_knote_msg_local_t),
		.msgh_id = 0x88888888,
	};
	local->body.msgh_descriptor_count = KNOTE_PORT_COUNT;
	for (size_t i = 0; i < KNOTE_PORT_COUNT; i++) {
		local->port[i] = (mach_msg_port_descriptor_t){
			.name = knote_port[i],
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		};
	}
	local->sequence = 0x6666666666666666;

	kr = mach_msg(&local->header, MACH_SEND_MSG, sizeof(sync_knote_msg_local_t), 0, MACH_PORT_NULL,
	    0, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg");

	struct kevent_qos_s event = {
		.ident = sync_port,
		.filter = EVFILT_MACHPORT,
		.flags = EV_ADD | EV_ENABLE | EV_DISPATCH,
		.qos = 0xA00,
		.udata = 42424242,
		.fflags = MACH_RCV_MSG,
		.xflags = 0x00,
		.data = 0x00,
		.ext = {(uint64_t)remote, sizeof(*remote), 0, 0},
	};

	struct kevent_qos_s out_events[1];

	int nevents = kevent_qos(kq, &event, 1, out_events, 1, NULL, NULL, 0);
	T_ASSERT_EQ(nevents, 1, "kevent_qos succeeded");
	T_ASSERT_EQ(remote->sequence, 0x6666666666666666, NULL);

	int ret = 0;
	struct kevent_qos_s del_event = {
		.ident = sync_port,
		.filter = EVFILT_MACHPORT,
		.flags = EV_DELETE,
		.qos = 0xA00,
		.udata = 0x00,
		.fflags = MACH_RCV_MSG,
		.xflags = 0x00,
		.data = 0x00,
		.ext = {0, 0, 0, 0},
	};

	ret = kevent_qos(kq, &del_event, 1, NULL, 0, NULL, NULL, 0);
	T_ASSERT_EQ(ret, 0, NULL);

	mach_port_t sr_port = thread_get_special_reply_port();
	struct {
		mach_msg_header_t header;
		uint64_t sequence;
	} sync_link_msg = {
		.header =
		{
			.msgh_bits =
	    MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0),
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port = sr_port,
			.msgh_voucher_port = MACH_PORT_NULL,
			.msgh_size = sizeof(sync_link_msg),
			.msgh_id = 0x86868686,
		},
		.sequence = 0x4242424242424242,
	};

	sync_link_msg.header.msgh_remote_port = remote->port[0].name;
	kr = mach_msg(&(sync_link_msg.header), MACH_SEND_MSG | MACH_SEND_SYNC_OVERRIDE,
	    sizeof(sync_link_msg), 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg");
}
