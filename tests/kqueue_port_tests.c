#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <sys/event.h>
#include <mach/mach.h>
#include <mach/mach_port.h>

#include <Block.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.kevent"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("kevent"),
	T_META_RUN_CONCURRENTLY(true)
	);

static void
send(mach_port_t send_port)
{
	kern_return_t kr = 0;
	mach_msg_base_t msg = {
		.header = {
			.msgh_remote_port = send_port,
			.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    0, MACH_MSG_TYPE_MOVE_SEND, 0),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(msg),
		},
	};

	kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
	    msg.header.msgh_size, 0, MACH_PORT_NULL, 10000, 0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client mach_msg");
}

static kern_return_t
receive(mach_port_t rcv_port)
{
	mach_msg_base_t msg = {
		.header = {
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = rcv_port,
			.msgh_size        = sizeof(msg),
		},
	};

	return mach_msg(&msg.header, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
	           0, msg.header.msgh_size, rcv_port, 5000, 0);
}

static void
fill_kevent(struct kevent *ke, uint16_t action, mach_port_t mp)
{
	*ke = (struct kevent){
		.filter = EVFILT_MACHPORT,
		.flags  = action,
		.ident  = mp,
	};
}

#define TS(s) (struct timespec){ .tv_sec = s }

static void *
pthread_async_do(void *arg)
{
	void (^block)(void) = arg;
	block();
	Block_release(block);
	pthread_detach(pthread_self());
	return NULL;
}

static void
pthread_async(void (^block)(void))
{
	pthread_t th;
	int rc;

	rc = pthread_create(&th, NULL, pthread_async_do, Block_copy(block));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(rc, "pthread_create");
}

T_DECL(kqueue_machport, "basic EVFILT_MACHPORT tests")
{
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};
	mach_port_t mp, pset;
	kern_return_t kr;
	struct kevent ke[2];
	int kq, rc;

	kr = mach_port_construct(mach_task_self(), &opts, 0, &mp);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_construct()");

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_PORT_SET, &pset);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_allocate(PSET)");

	kr = mach_port_move_member(mach_task_self(), mp, pset);
	T_EXPECT_MACH_SUCCESS(kr, "mach_port_move_member(PORT, PSET)");

	kq = kqueue();
	T_EXPECT_POSIX_SUCCESS(kq, "kqueue()");

	/*
	 * Fired when attached
	 */
	send(mp);

	fill_kevent(&ke[0], EV_ADD, mp);
	fill_kevent(&ke[1], EV_ADD, pset);
	rc = kevent(kq, ke, 2, NULL, 0, &TS(5));
	T_EXPECT_POSIX_SUCCESS(rc, "kevent(registration)");

	rc = kevent(kq, NULL, 0, ke, 2, &TS(5));
	T_EXPECT_EQ(rc, 2, "kevent(fired at attach time)");

	receive(mp);
	rc = kevent(kq, NULL, 0, ke, 2, &TS(1));
	T_EXPECT_EQ(rc, 0, "no event");

	/*
	 * Fired after being attached, before wait
	 */
	send(mp);
	rc = kevent(kq, NULL, 0, ke, 2, &TS(5));
	T_EXPECT_EQ(rc, 2, "kevent(fired after attach time, before wait)");

	receive(mp);
	rc = kevent(kq, NULL, 0, ke, 2, &TS(1));
	T_EXPECT_EQ(rc, 0, "no event");

	/*
	 * Fired after being attached, after wait
	 */
	pthread_async(^{
		sleep(1);
		send(mp);
	});
	rc = kevent(kq, NULL, 0, ke, 2, &TS(5));
	T_EXPECT_EQ(rc, 2, "kevent(fired after attach time, after wait)");

	receive(mp);
	rc = kevent(kq, NULL, 0, ke, 2, &TS(1));
	T_EXPECT_EQ(rc, 0, "no event");

	/* Make sure destroying ports wakes you up */
	pthread_async(^{
		sleep(1);
		T_EXPECT_MACH_SUCCESS(mach_port_destruct(mach_task_self(), mp, -1, 0),
		"mach_port_destruct");
	});
	rc = kevent(kq, NULL, 0, ke, 2, &TS(5));
	T_EXPECT_EQ(rc, 1, "kevent(port-destroyed)");
	T_EXPECT_EQ(ke[0].ident, (uintptr_t)mp, "event was for the port");

	pthread_async(^{
		sleep(1);
		T_EXPECT_MACH_SUCCESS(mach_port_mod_refs(mach_task_self(), pset,
		MACH_PORT_RIGHT_PORT_SET, -1), "destroy pset");
	});
	rc = kevent(kq, NULL, 0, ke, 2, &TS(5));
	T_EXPECT_EQ(rc, 1, "kevent(port-destroyed)");
	T_EXPECT_EQ(ke[0].ident, (uintptr_t)pset, "event was for the pset");
}
