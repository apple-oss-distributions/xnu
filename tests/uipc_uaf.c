/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 */
#include <stdio.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_var.h>
#include <netinet/ip6.h>
#include <sys/sysctl.h>
#include <darwintest.h>
#include <TargetConditionals.h>

#define MAX_FDS ((MCLBYTES - sizeof(struct cmsghdr)) / sizeof(void *))

static bool running = false;

static void *
trigger_unp_gc(void *arg __unused)
{
	int fd;
	while (running) {
		fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (fd != -1) {
			close(fd);
		}
	}
	return NULL;
}

static void *
send_scm_rights(void *arg __unused)
{
	struct iovec iov = {};
	struct msghdr msg = {};
	struct msg {
		struct cmsghdr cmsg;
		int fds[MAX_FDS];
	};
	struct msg ctrl_msg = {};

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &ctrl_msg;
	msg.msg_controllen = sizeof(ctrl_msg) - ((MAX_FDS / 2) * sizeof(ctrl_msg.fds[0]));
	ctrl_msg.cmsg.cmsg_type = SCM_RIGHTS;
	ctrl_msg.cmsg.cmsg_level = SOL_SOCKET;
	ctrl_msg.cmsg.cmsg_len = msg.msg_controllen;

	struct msghdr overwrite_msg = {};
	struct msg overwrite_ctrl_msg = {};

	overwrite_msg.msg_iov = &iov;
	overwrite_msg.msg_iovlen = 1;
	overwrite_msg.msg_control = &overwrite_ctrl_msg;
	overwrite_msg.msg_controllen = sizeof(overwrite_ctrl_msg);
	overwrite_ctrl_msg.cmsg.cmsg_type = SCM_RIGHTS;
	overwrite_ctrl_msg.cmsg.cmsg_level = SOL_SOCKET;
	overwrite_ctrl_msg.cmsg.cmsg_len = msg.msg_controllen;

	const uintptr_t invalid_ptr = 0x4141414141414141;
	const uintptr_t *ptr = &invalid_ptr;
	uintptr_t *overwrite_ctrl_msg_ptrs =
	    (uintptr_t*)(void *)(&overwrite_ctrl_msg.fds[0]);
	const int overwrite_ctrl_msg_ptrs_count =
	    MAX_FDS / (sizeof(overwrite_ctrl_msg_ptrs[0]) / sizeof(overwrite_ctrl_msg.fds[0]));

	for (int i = 0; i < overwrite_ctrl_msg_ptrs_count - 2; i++) {
		overwrite_ctrl_msg_ptrs[i] = ptr[0];
	}
	memcpy(&(overwrite_ctrl_msg_ptrs[overwrite_ctrl_msg_ptrs_count - 2]),
	    ptr,
	    sizeof(ptr[0]));
	while (running) {
		int pair[2];

		T_QUIET; T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), "socketpair");
		for (unsigned i = 0; i < MAX_FDS / 2; i++) {
			ctrl_msg.fds[i] = pair[1];
		}
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sendmsg(pair[1], &msg, 0), "sendmsg");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(sendmsg(pair[0], &msg, 0), "sendmsg");
		usleep(100);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(shutdown(pair[1], SHUT_RD), "shutdown");
		T_QUIET; T_ASSERT_POSIX_FAILURE(sendmsg(pair[0], &overwrite_msg, 0), EINVAL, "sendmsg");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(close(pair[0]), "close");
		T_QUIET; T_ASSERT_POSIX_SUCCESS(close(pair[1]), "close");
	}

	return NULL;
}


T_DECL(uipc_uaf, "Tests that the UNIX Domain Socket GC doesn't panic", T_META_CHECK_LEAKS(false))
{
#if TARGET_OS_WATCH
	T_SKIP("test doesn't work on watchOS");
#endif
	running = true;
	pthread_t t1, t2;
	T_ASSERT_POSIX_SUCCESS(pthread_create(&t1, NULL, send_scm_rights, NULL), "pthread_create");
	T_ASSERT_POSIX_SUCCESS(pthread_create(&t2, NULL, send_scm_rights, NULL), "pthread_create");
	pthread_t gc;
	T_ASSERT_POSIX_SUCCESS(pthread_create(&gc, NULL, trigger_unp_gc, NULL), "pthread_create");
	sleep(59);
	running = false;
	sleep(1);
}
