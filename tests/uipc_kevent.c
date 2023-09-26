/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 */
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if_var.h>
#include <netinet/ip6.h>
#include <sys/sysctl.h>
#include <darwintest.h>

/*
 * Tests that filling up the socket buffer doesn't cause
 * kevent to return "writeable".
 */
static void __unused
test_kevent(int type)
{
	int sockets[2] = { -1 };
	int kq = -1;
	struct kevent evlist = { 0 };
	struct kevent chlist = { 0 };

	T_ASSERT_POSIX_SUCCESS((kq = kqueue()), "kqueue");
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, type, 0, sockets), "socketpair");
	int flags = fcntl(sockets[0], F_GETFL);
	T_ASSERT_POSIX_SUCCESS(fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK), "fcntl");

	EV_SET(&chlist, sockets[0], EVFILT_WRITE, EV_ADD | EV_ERROR, 0, 0, 0);
	ssize_t result = kevent(kq, &chlist, 1, &evlist, 1, NULL);
	T_ASSERT_EQ(result, 1, "should be able to write");

	// Fill the socket buffer
	char buf[1] = { 0x55 };
	while (write(sockets[0], buf, sizeof(buf)) > 0) {
		;
	}

	result = write(sockets[0], buf, sizeof(buf));
	if (type == SOCK_STREAM) {
		T_ASSERT_POSIX_FAILURE(result, EWOULDBLOCK, "should block");
	} else {
		T_ASSERT_POSIX_FAILURE(result, ENOBUFS, "should block");
	}

	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	result = kevent(kq, &chlist, 1, &evlist, 1, &ts);
	T_ASSERT_EQ(result, 0, "should timeout");
	close(sockets[0]);
	close(sockets[1]);
	close(kq);
}

static void __unused
test_kevent_lowat(int type)
{
	int sockets[2] = { -1 };
	int kq = -1;
	struct kevent evlist = { 0 };
	struct kevent chlist = { 0 };

	T_ASSERT_POSIX_SUCCESS((kq = kqueue()), "kqueue");
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, type, 0, sockets), "socketpair");
	int flags = fcntl(sockets[0], F_GETFL);
	T_ASSERT_POSIX_SUCCESS(fcntl(sockets[0], F_SETFL, flags | O_NONBLOCK), "fcntl");

	EV_SET(&chlist, sockets[0], EVFILT_WRITE, EV_ADD | EV_ERROR, 0, 0, 0);
	ssize_t result = kevent(kq, &chlist, 1, &evlist, 1, NULL);
	T_ASSERT_EQ(result, 1, "should be able to write");

	// Almost fill the socket buffer but leave 2K available.
	char buf[1] = { 0x55 };
	int max_writes = type == SOCK_STREAM ? 6000 : 30;
	for (int i = 0; i < max_writes; i++) {
		write(sockets[0], buf, sizeof(buf));
	}

	result = kevent(kq, &chlist, 1, &evlist, 1, NULL);
	T_ASSERT_EQ(result, 1, "should be able to write again");

	char large_buf[4096] = { };

	if (type == SOCK_STREAM) {
		// Write 2KB.
		result = write(sockets[0], large_buf, 2 * 1024);
		T_ASSERT_POSIX_SUCCESS(result, "write 2KB");
		// Write 4KB, should fail.
		result = write(sockets[0], large_buf, sizeof(large_buf));
		T_ASSERT_POSIX_FAILURE(result, EWOULDBLOCK, "should block (EWOULDBLOCK)");
	} else {
		// Write 512B.
		result = write(sockets[0], large_buf, 512);
		T_ASSERT_POSIX_SUCCESS(result, "write 512B");
		// Write 2KB, should fail.
		result = write(sockets[0], large_buf, 2048);
		T_ASSERT_POSIX_FAILURE(result, ENOBUFS, "should block (ENOBUFS)");
	}

	// Ask kqueue to wake us up when we can write 100 bytes.
	EV_SET(&chlist, sockets[0], EVFILT_WRITE, EV_ADD | EV_ERROR, NOTE_LOWAT, 100, 0);

	struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
	result = kevent(kq, &chlist, 1, &evlist, 1, &ts);
	T_ASSERT_EQ(result, 0, "should timeout (note_lowat)");

	// Set the send buffer low water mark.
	int lowat = type == SOCK_STREAM ? 100 : 10;
	result = setsockopt(sockets[0], SOL_SOCKET, SO_SNDLOWAT, &lowat, sizeof(lowat));
	T_ASSERT_POSIX_SUCCESS(result, "setsockopt");

	if (type == SOCK_STREAM) {
		// Write 100 bytes.
		result = write(sockets[0], large_buf, 100);
		T_ASSERT_POSIX_SUCCESS(result, "write 100B");
	}

	// Reset the event and kqueue should respect SO_SNDLOWAT.
	EV_SET(&chlist, sockets[0], EVFILT_WRITE, EV_ADD | EV_ERROR, 0, 0, 0);
	result = kevent(kq, &chlist, 1, &evlist, 1, &ts);
	T_ASSERT_EQ(result, 0, "should timeout (sndlowat)");

	close(sockets[0]);
	close(sockets[1]);
	close(kq);
}

T_DECL(uipc_kevent, "Tests the UNIX Domain kevent filter", T_META_CHECK_LEAKS(false))
{
#if 0
	test_kevent(SOCK_STREAM);
	test_kevent(SOCK_DGRAM);
	test_kevent_lowat(SOCK_STREAM);
	test_kevent_lowat(SOCK_DGRAM);
#else
	T_SKIP("Test is unstable");
#endif
}
