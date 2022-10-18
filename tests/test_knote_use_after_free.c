/*
 * Test based on POC attached to rdar://96567281 (Knote Use-after-Free in XNU)
 *
 */
#include <darwintest.h>
#include <mach/mach.h>
#include <pthread.h>
#include <sys/event.h>
#include <stdlib.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(TRUE));

typedef struct knote_context_s knote_context_t;
struct knote_context_s {
	int initialized;
	int start;
};

static void *
th_allocate_knotes(void *arg)
{
	knote_context_t *context = (knote_context_t *)arg;
	kern_return_t kr = KERN_SUCCESS;
	T_QUIET; T_ASSERT_EQ(context->initialized, (int)0, "th_allocate_knotes context is initialized.");

	mach_port_t sync_port = MACH_PORT_NULL;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &sync_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate sync_port");

	mach_port_t kq_port = MACH_PORT_NULL;
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &kq_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate kq_port");

	int kq = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kq, "kqueue");

#define PORTS_COUNT 0x1000

	mach_port_t *ports = calloc(PORTS_COUNT, sizeof(mach_port_t));
	T_QUIET; T_ASSERT_NOTNULL(ports, "calloc");

	for (size_t i = 0; i < PORTS_COUNT; i++) {
		mach_port_t port = MACH_PORT_NULL;
		kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

		typedef struct move_receive_request_s move_receive_request_t;
		typedef struct move_receive_reply_s move_receive_reply_t;

		struct move_receive_request_s {
			mach_msg_header_t header;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t port;
			mach_msg_port_descriptor_t kq_port;
		};

		struct move_receive_reply_s {
			mach_msg_header_t header;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t port;
			mach_msg_port_descriptor_t kq_port;
			mach_msg_trailer_t trailer;
		};

		union {
			move_receive_request_t request;
			move_receive_reply_t reply;
		} message;

		move_receive_request_t *request = &message.request;
		move_receive_reply_t *reply = &message.reply;

		request->header = (mach_msg_header_t){
			.msgh_remote_port = sync_port,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_voucher_port = MACH_PORT_NULL,
			.msgh_id = (mach_msg_id_t)0x88888888,
			.msgh_size = sizeof(*request),
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND, 0, 0, MACH_MSGH_BITS_COMPLEX),
		};

		request->body = (mach_msg_body_t){
			.msgh_descriptor_count = 2,
		};

		request->port = (mach_msg_port_descriptor_t){
			.name = port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		};
		request->kq_port = (mach_msg_port_descriptor_t){
			.name = kq_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type = MACH_MSG_PORT_DESCRIPTOR,
		};

		kr = mach_msg(&request->header, MACH_SEND_MSG, sizeof(*request), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		T_QUIET; T_ASSERT_EQ(kr, MACH_MSG_SUCCESS, "mach_msg");

		struct kevent_qos_s event = {
			.ident = sync_port,
			.filter = EVFILT_MACHPORT,
			.flags = EV_ADD | EV_ENABLE | EV_DISPATCH,
			.qos = 0xA00,
			.udata = 0x42424242,
			.fflags = MACH_RCV_MSG,
			.xflags = 0x00,
			.data = 0x00,
			.ext = {(uint64_t)reply, sizeof(*reply), 0, 0},
		};

		struct kevent_qos_s out_events[1];

		int nevents = kevent_qos(kq, &event, 1, out_events, 1, NULL, NULL, 0);
		T_QUIET; T_ASSERT_EQ(nevents, (int)1, "kevent_qos");
		T_QUIET; T_ASSERT_EQ(out_events[0].udata, (uint64_t)0x42424242, "kevent_qos");
		T_QUIET; T_ASSERT_BITS_SET(reply->header.msgh_bits, MACH_MSGH_BITS_COMPLEX, "message is complex");
		T_QUIET; T_ASSERT_EQ(reply->body.msgh_descriptor_count, (mach_msg_size_t)2, "mach_msg");

		ports[i] = reply->port.name;
		kq_port = reply->kq_port.name;
	}

	context->initialized = 1;
	while (!context->start) {
	}

	for (size_t i = 0; i < PORTS_COUNT; i++) {
		uint32_t wl_id = (uint32_t)0x99999999;

		struct kevent_qos_s event = {
			.ident = ports[i],
			.filter = EVFILT_WORKLOOP,
			.flags = EV_ADD | EV_DISABLE,
			.qos = 0x00,
			.udata = 0x88888888,
			.fflags = NOTE_WL_SYNC_IPC,
			.xflags = 0x00,
			.data = 0x66666666,
			.ext = {0x00, 0x00, 0x00, 0x00},
		};
		struct kevent_qos_s output = { };
		int ret = kevent_id(wl_id, &event, 1, &output, 1, NULL, NULL,
		    KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "kevent_id");
	}
	return NULL;
}

T_DECL(test_knote_use_after_free,
    "Verify knote use-after-free issue does not reproduce - rdar://96567281 (Knote Use-after-Free in XNU)",
    T_META_CHECK_LEAKS(false))
{
	mach_port_t task = mach_task_self();

	knote_context_t context = {
		.initialized = 0,
		.start = 0,
	};

	pthread_t thknote;
	T_ASSERT_POSIX_ZERO(pthread_create(&thknote, NULL, th_allocate_knotes, &context), "pthread_create");

	int kq = kqueue();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kq, "kqueue");

#define KNOTE_PORT_COUNT 2

	kern_return_t kr = KERN_SUCCESS;
	mach_port_t sync_port = MACH_PORT_NULL, knote_port[KNOTE_PORT_COUNT];
	kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &sync_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate sync_port");

	for (size_t i = 0; i < KNOTE_PORT_COUNT; i++) {
		knote_port[i] = MACH_PORT_NULL;
		kr = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &knote_port[i]);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate knote_port");
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
		.msgh_id =  (mach_msg_id_t)0x88888888,
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
	T_QUIET; T_ASSERT_EQ(kr, MACH_MSG_SUCCESS, "mach_msg");

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
	T_QUIET; T_ASSERT_EQ(nevents, (int)1, "kevent_qos nevents");
	T_QUIET; T_ASSERT_EQ(remote->sequence, (uint64_t)0x6666666666666666, "kevent_qos remote->sequence");

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
	T_QUIET; T_ASSERT_EQ(ret, (int)0, "kevent_qos return");

	while (!context.initialized) {
	}

	context.start = 1;
	T_ASSERT_POSIX_ZERO(pthread_join(thknote, NULL), "pthread_join");

	kr = _kernelrpc_mach_port_insert_right_trap(task, sync_port, sync_port, MACH_MSG_TYPE_MOVE_RECEIVE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "_kernelrpc_mach_port_insert_right_trap");
}
