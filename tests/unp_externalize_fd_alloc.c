/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <errno.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define SCM_RIGHTS                      0x01

T_DECL(scm_rights_control_msg, "Test the fd alloc failure behavior with SCM_RIGHTS control msg")
{
	T_SETUPBEGIN;
	int res, sock[2];

	int fd = open("/dev/null", O_RDWR);
	T_ASSERT_POSIX_SUCCESS(fd, "open(/dev/null)");

	struct rlimit rlim = { 6, 6 };
	setrlimit(RLIMIT_NOFILE, &rlim);

	res = socketpair(AF_UNIX, SOCK_STREAM, 0, sock);
	T_QUIET; T_ASSERT_TRUE(sock[0] >= 0, "failed to create socket");

	struct iovec iovec[1];
	struct msghdr msg = {0};
	struct cmsghdr *cmsghdr;
	char buf[CMSG_SPACE(sizeof(int))];

	iovec[0].iov_base = "";
	iovec[0].iov_len = 1;

	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	cmsghdr = CMSG_FIRSTHDR(&msg);
	cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
	cmsghdr->cmsg_level = SOL_SOCKET;
	cmsghdr->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(cmsghdr), &fd, sizeof(fd));

	T_SETUPEND;

	sendmsg(sock[1], &msg, 0);

	u_char c;
	struct iovec riovec[1];
	struct msghdr rmsg = { 0, };
	char rbuf[CMSG_SPACE(sizeof(int))];

	riovec[0].iov_base = &c;
	riovec[0].iov_len = 1;

	rmsg.msg_iov = riovec;
	rmsg.msg_iovlen = 1;
	rmsg.msg_control = rbuf;
	rmsg.msg_controllen = CMSG_SPACE(sizeof(int));

	ssize_t ret = recvmsg(sock[0], &rmsg, 0);
	T_ASSERT_TRUE(ret == -1, "recvmsg should fail");
	T_ASSERT_TRUE(errno == 24, "the fail code is EMFILE");

	close(fd);
	close(sock[0]);
	close(sock[1]);
}
