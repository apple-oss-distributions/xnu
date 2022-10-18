#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <darwintest.h>
/*
 * Tests that a full UNIX domain socket buffer
 * always reports the right poll() event.
 */

static const int MSG1_LEN = 16384;

static void
do_recv(int sk, char *buf, size_t size)
{
	do{
		struct iovec iov[1];
		struct msghdr msg;

		struct pollfd pfd[1] = { { sk, POLLIN, 0 } };
		T_QUIET; T_ASSERT_POSIX_SUCCESS(poll(pfd, 1, -1), "poll");
		memset(&msg, 0, sizeof(msg));
		iov->iov_base = buf;
		iov->iov_len = size;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		ssize_t res = recvmsg(sk, &msg, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(res, "recvmsg");
		buf += res;
		size -= (size_t)res;
	} while (size);
}


static void *
receiver(void *arg)
{
	int sk = (int)arg;
	char *buf = malloc(MSG1_LEN);
	for (;;) {
		do_recv(sk, buf, MSG1_LEN);
	}
}

static void
do_send(int sk, char *buf, size_t size)
{
	do{
		struct iovec iov[1];
		struct msghdr msg;

		struct pollfd pfd[1] = { { sk, POLLOUT, 0 } };
		int res = poll(pfd, 1, -1);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(res, "poll");
		if (res == 0) {
			continue;
		}
		if (!(pfd[0].revents & POLLOUT)) {
			T_FAIL("POLLOUT not set");
		}
		memset(&msg, 0, sizeof(msg));
		iov->iov_base = buf;
		iov->iov_len = size;
		msg.msg_iov = iov;
		msg.msg_iovlen = 1;
		ssize_t res_sendmsg = sendmsg(sk, &msg, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(res_sendmsg, "sendmsg");
		buf += res_sendmsg;
		size -= (size_t)res_sendmsg;
	} while (size);
}


static void
cfg_sk(int sk)
{
	int newSndBufSz = MSG1_LEN * 2;
	socklen_t optLen = sizeof(newSndBufSz);
	T_ASSERT_POSIX_SUCCESS(setsockopt(sk, SOL_SOCKET, SO_SNDBUF,
	    &newSndBufSz, optLen),
	    "setsockopt");
	newSndBufSz = MSG1_LEN * 2;
	optLen = sizeof(newSndBufSz);
	T_ASSERT_POSIX_SUCCESS(setsockopt(sk, SOL_SOCKET, SO_RCVBUF,
	    &newSndBufSz, optLen),
	    "setsockopt");
	int flags = fcntl(sk, F_GETFL, 0);
	T_ASSERT_POSIX_SUCCESS(flags, "fcntl");
	T_ASSERT_POSIX_SUCCESS(fcntl(sk, F_SETFL, flags | O_NONBLOCK),
	    "fcntl");
}

T_DECL(uipc_sosendcheck, "Tests the UNIX Domain poll filter", T_META_CHECK_LEAKS(false))
{
	int s[2];
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, s),
	    "socketpair");
	cfg_sk(s[0]);
	cfg_sk(s[1]);
	char *buf = malloc(MSG1_LEN);

	pthread_t receiver_th;
	if (pthread_create(&receiver_th, 0, receiver, (void *)(uintptr_t)s[1])) {
		T_FAIL("pthread_create failed");
	}

	for (unsigned int i = 0; i < 90000; i++) {
		do_send(s[0], buf, 5);
		do_send(s[0], buf, MSG1_LEN);
	}
}
