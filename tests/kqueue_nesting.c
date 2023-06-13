#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/event.h>
#include <mach/mach.h>
#include <mach/mach_port.h>

#include <Block.h>
#include <darwintest.h>

T_DECL(kqueue_nesting_level, "rdar://100277117 (Reduce kqueue nesting level so that we don't overflow kernel stack)")
{
	// Create a port and register a knote for it on a kqueue
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_ASSERT_MACH_SUCCESS(kr, "allocating a port with a receive right");

	int port_kq = kqueue();
	struct kevent_qos_s event = {
		.ident = port,
		.filter = EVFILT_MACHPORT,
		.flags = EV_ADD | EV_ENABLE,
		.qos = 0x00,
		.udata = 0x66666666,
		.fflags = MACH_RCV_MSG,
		.xflags = 0,
		.data = 0,
		.ext = {},
	};
	int nevents = kevent_qos(port_kq, &event, 1, NULL, 0, NULL, NULL, 0);
	T_EXPECT_EQ(nevents, 0, NULL);

	// Register the other kqueues
	int child_kq = port_kq;

	for (size_t i = 0; i < 1000; i++) {
		int kq = kqueue();
		struct kevent_qos_s kq_read_event = {
			.ident = child_kq,
			.filter = EVFILT_READ,
			.flags = EV_ADD | EV_ENABLE,
			.qos = 0x00,
			.udata = 0x66666666,
			.fflags = 0x00,
			.xflags = 0x00,
			.data = 0,
			.ext = {},
		};

		nevents = kevent_qos(kq, &kq_read_event, 1, NULL, 0, NULL, NULL, 0);
		// This kevent may sometimes fail after we exceed the limit enforced by the
		// kernel in which case, we'd just have created kqueues but not set up any
		// knotes on them.
		//
		// On old-OSes prior to rdar://100277117, this would always succeed and then
		// we'd panic when we send a message
		child_kq = kq;
	}

	// Send a message to the port and activate the first kqueue
	struct {
		mach_msg_header_t header;
		uint64_t data;
	} message = {
		.header = {
			.msgh_remote_port = port,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_voucher_port = MACH_PORT_NULL,
			.msgh_size = sizeof(message),
			.msgh_id = 0x88888888,
			.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0, 0),
		},
		.data = 0x8888888888888,
	};

	kr = mach_msg(&message.header, MACH_SEND_MSG, sizeof(message), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg(SEND)");
}
