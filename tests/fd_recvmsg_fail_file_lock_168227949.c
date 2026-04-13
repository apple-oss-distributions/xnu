/*
 * Copyright (c) 2026 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <errno.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.file_descriptors"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("file_descriptors"),
	T_META_RUN_CONCURRENTLY(false));


static int
send_fd(int sock, int fd)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsg_buf;

	char data = '*';
	struct iovec iov = {
		.iov_base = &data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg_buf.buf,
		.msg_controllen = sizeof(cmsg_buf.buf),
	};

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;

	ssize_t ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		return -1;
	}

	return 0;
}

static int
recv_fd(int sock)
{
	union {
		struct cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} cmsg_buf;

	char data;
	struct iovec iov = {
		.iov_base = &data,
		.iov_len = sizeof(data),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg_buf.buf,
		.msg_controllen = sizeof(cmsg_buf.buf),
	};

	ssize_t ret = recvmsg(sock, &msg, 0);
	if (ret <= 0) {
		return -1;
	}

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
		errno = EINVAL;
		return -1;
	}

	return *(int *)CMSG_DATA(cmsg);
}

static int
is_lock_held(int fd, off_t start, off_t len, short lock_type)
{
	/* Lock status must be checked from outside our process - POSIX locks are per-process */
	pid_t pid = fork();
	if (pid < 0) {
		return -1;
	}

	if (pid == 0) {
		struct flock fl = {
			.l_start = start,
			.l_len = len,
			.l_type = lock_type,
			.l_whence = SEEK_SET,
		};

		if (fcntl(fd, F_GETLK, &fl) != 0) {
			_exit(2);
		}

		_exit(fl.l_type == F_UNLCK ? 0 : 1);
	}

	int status;
	if (waitpid(pid, &status, 0) < 0) {
		return -1;
	}

	if (!WIFEXITED(status)) {
		return -1;
	}

	int exit_code = WEXITSTATUS(status);
	if (exit_code == 2) {
		return -1;
	}

	return exit_code;
}

T_DECL(recvmsg_fail_file_lock_preserved,
    "Ensure a failed recvmsg containing an fd that we've already locked doesn't release our lock")
{
	char file_path[PATH_MAX];

	/* Given a temporary file */
	const char* tmpdir = dt_tmpdir();
	snprintf(file_path, sizeof(file_path), "%s/test.file", tmpdir);

	int test_fd = open(file_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	T_ASSERT_POSIX_SUCCESS(test_fd, "create test file");

	/* When we take a write lock on the file */
	struct flock fl = {
		.l_start = 0,
		.l_len = 0,
		.l_type = F_WRLCK,
		.l_whence = SEEK_SET,
	};
	T_ASSERT_POSIX_SUCCESS(fcntl(test_fd, F_SETLK, &fl), "acquire write lock");

	/* And create a socketpair for sending the fd to ourselves */
	int sockets[2];
	T_ASSERT_POSIX_SUCCESS(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets),
	    "socketpair");

	/* And we set our fd limit to the current highest fd + 1, leaving no room */
	struct rlimit rl;
	T_ASSERT_POSIX_SUCCESS(getrlimit(RLIMIT_NOFILE, &rl), "getrlimit");
	rl.rlim_cur = sockets[1] + 1;
	T_ASSERT_POSIX_SUCCESS(setrlimit(RLIMIT_NOFILE, &rl), "setrlimit");

	/* And we send the locked fd to ourselves */
	T_ASSERT_POSIX_SUCCESS(send_fd(sockets[0], test_fd), "send_fd");

	/* Then attempting to receive it should fail due to no available fds */
	int received_fd = recv_fd(sockets[1]);
	T_ASSERT_EQ(received_fd, -1, "recv_fd should fail");
	T_ASSERT_TRUE(errno == EMFILE || errno == ENFILE || errno == EMSGSIZE,
	    "recv_fd should fail with EMFILE/ENFILE/EMSGSIZE, got errno=%d", errno);

	/* And our lock should still be held despite the failed recv */
	int lock_still_held = is_lock_held(test_fd, 0, 0, F_WRLCK);
	T_ASSERT_EQ(lock_still_held, 1, "lock should still be held");

	/* (Cleanup) */
	close(sockets[0]);
	close(sockets[1]);
	close(test_fd);
	unlink(file_path);

	T_PASS("File lock preserved despite recvmsg failure");
}
