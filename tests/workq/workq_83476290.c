#include <mach/port.h>
#include <mach/mach.h>
#include <sys/event.h>
#include <dispatch/dispatch.h>
#include <pthread/workqueue_private.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.workq"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("workq"),
	T_META_RUN_CONCURRENTLY(true));

T_DECL(thread_request_83476290,
    "test that mach_msg_trap causes a thread request")
{
	mach_port_t mp, rp;
	kern_return_t kr;
	dispatch_source_t ds;
	dispatch_queue_t dq;
	int kq;

	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &mp);
	T_ASSERT_MACH_SUCCESS(kr, "create receive right %x", mp);

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &rp);
	T_ASSERT_MACH_SUCCESS(kr, "create reply port right %x", rp);

	dq = dispatch_queue_create_with_target("tr.q", DISPATCH_QUEUE_SERIAL, NULL);
	ds = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, mp, 0, dq);
	dispatch_source_set_event_handler(ds, ^{
		T_PASS("received the event");
		T_END;
	});
	dispatch_activate(ds);

	T_LOG("wait 1ms for the existing dispatch thread to park again");
	usleep(1000);

	kq = kqueue();
	T_ASSERT_POSIX_SUCCESS(kq, "kqueue()");

	/*
	 * Now use the threads that were on the pool to make sure the process
	 * is starved
	 */
	dispatch_async(dispatch_get_global_queue(0, 0), ^{
		usleep(1000);
		struct kevent_qos_s ke = {
		        .ident  = 1,
		        .filter = EVFILT_USER,
		        .fflags = NOTE_TRIGGER,
		};
		int rc = kevent_qos(kq, &ke, 1, NULL, 0, NULL, NULL, 0);
		T_ASSERT_POSIX_SUCCESS(rc, "NOTE_TRIGGER");
		pause();
	});

	struct kevent_qos_s ke = {
		.ident  = 1,
		.filter = EVFILT_USER,
		.flags  = EV_ADD | EV_CLEAR,
	};

	T_LOG("block in kevent, call mach_msg with 5s timeout");
	(void)kevent_qos(kq, &ke, 1, &ke, 1, NULL, NULL, 0);

	mach_msg_header_t hdr = {
		.msgh_remote_port = mp,
		.msgh_local_port  = rp,
		.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0),
		.msgh_id          = 1,
		.msgh_size        = sizeof(hdr),
	};

	kr = mach_msg(&hdr, MACH_SEND_MSG | MACH_RCV_MSG | MACH_RCV_TIMEOUT,
	    sizeof(hdr), sizeof(hdr), rp, 5000, 0);
	T_FAIL("mach_msg returned: %#x", kr);
}
