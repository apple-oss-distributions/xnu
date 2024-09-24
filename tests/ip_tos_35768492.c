//
//  ip_tos_35768492.c
//  tests
//
//  Test that setting the TOS byte via IP_TOS/IPV6_TCLASS works equally
//  between setsockopt and cmsghdr.
//
//  Copyright (c) 2019-2024 Apple Inc. All rights reserved.
//

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <darwintest.h>

#define IPV6_USE_MIN_MTU        42 /* bool; send packets at the minimum MTU */

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"));

typedef enum _tos_method_t {
	use_none,
	use_header_socket,
	use_setsockopt,
	use_header
} tos_method_t;

static void
my_sendmsg(int sock, int level, int type, char *data, uint8_t tos_byte,
    tos_method_t method, const char *description)
{
	struct msghdr msgvec = {0};
	struct iovec msg = {0};
	uint8_t ctrl[CMSG_SPACE(sizeof(int))] = {0};
	msg.iov_base = (void *)data;
	msg.iov_len = strlen(data);
	msgvec.msg_name = 0;
	msgvec.msg_namelen = 0;
	msgvec.msg_iov = &msg;
	msgvec.msg_iovlen = 1;

	switch (method) {
	case use_header_socket: {
		int off = 0;
		msgvec.msg_control = &ctrl;
		msgvec.msg_controllen = sizeof(ctrl);
		struct cmsghdr * const cmsg = CMSG_FIRSTHDR(&msgvec);
		cmsg->cmsg_level = level;
		cmsg->cmsg_type = IPV6_USE_MIN_MTU;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *)CMSG_DATA(cmsg) = off;
		// fallthrough to also set socket opt
	}
	case use_setsockopt: {
		int val = tos_byte;
		int err = setsockopt(sock, level, type, &val, sizeof(val));
		T_ASSERT_TRUE(err == 0, "Set TOS field using setsockopt()");
		break;
	}

	case use_header: {
		msgvec.msg_control = &ctrl;
		msgvec.msg_controllen = sizeof(ctrl);
		struct cmsghdr * const cmsg = CMSG_FIRSTHDR(&msgvec);
		cmsg->cmsg_level = level;
		cmsg->cmsg_type = type;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));
		*(int *)CMSG_DATA(cmsg) = tos_byte;
		break;
	}

	default:
		break;
	}

	ssize_t num = sendmsg(sock, &msgvec, 0);
	T_ASSERT_TRUE(num > 0, description);
}

static void
my_recvmsg(int sock, int level, int type, const char *expected_data,
    uint8_t expected_tos_byte, const char *description)
{
#define BUF_SIZE 1024
	struct msghdr msgvec = {0};
	struct sockaddr_in peer = {0};
	struct iovec msg = {0};
	uint32_t ctrl_buf[256 / sizeof(uint32_t)] = {0};
	uint8_t buf[BUF_SIZE] = {0};
	msg.iov_base = buf;
	msg.iov_len = BUF_SIZE;
	msgvec.msg_name = &peer;
	msgvec.msg_namelen = sizeof(peer);
	msgvec.msg_iov = &msg;
	msgvec.msg_iovlen = 1;
	msgvec.msg_control = (struct cmsghdr *)ctrl_buf;
	msgvec.msg_controllen = sizeof(ctrl_buf);

	ssize_t num = recvmsg(sock, &msgvec, 0);
	T_ASSERT_GT_INT(num, 0, NULL);
	int cmp = memcmp(buf, expected_data, strlen(expected_data));
	T_ASSERT_EQ_INT(cmp, 0, NULL);

	uint8_t tos_byte = 0;
	for (struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msgvec); cmsg; cmsg = CMSG_NXTHDR(&msgvec, cmsg)) {
		if (cmsg->cmsg_level == level &&
		    cmsg->cmsg_len &&
		    cmsg->cmsg_type == type) {
			tos_byte = (uint8_t)*(int *)CMSG_DATA(cmsg);
			break;
		}
	}

	T_ASSERT_EQ_INT(tos_byte, expected_tos_byte, description);
}

T_DECL(ip_tos, "IPv4 TOS")
{
	int server4 = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_TRUE(server4 >= 0, "Create server socket");

	int val = 1;
	int err = setsockopt(server4, IPPROTO_IP, IP_RECVTOS, &val, sizeof(val));
	T_ASSERT_TRUE(err == 0, "setsockopt(IPPROTO_IP, IP_RECVTOS)");

	int client4 = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_TRUE(client4 >= 0, "Create client socket");

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_len = sizeof(addr);
	addr.sin_port = htons(8008);
	err = inet_pton(AF_INET, "127.0.0.1", &(addr.sin_addr));
	T_ASSERT_TRUE(err == 1, NULL);
	err = bind(server4, (struct sockaddr *)&addr, sizeof(addr));
	T_ASSERT_TRUE(err == 0, NULL);
	err = connect(client4, (struct sockaddr *)&addr, sizeof(addr));
	T_ASSERT_TRUE(err == 0, "connect client socket");

	my_sendmsg(client4, IPPROTO_IP, IP_TOS, "hello", 0xff, use_setsockopt, "IPv4 setsockopt 0xff");
	my_recvmsg(server4, IPPROTO_IP, IP_RECVTOS, "hello", 0xff, "IPv4 setsockopt 0xff");
	my_sendmsg(client4, IPPROTO_IP, IP_TOS, "hello", 0xd0, use_setsockopt, "IPv4 setsocktop 0xd0");
	my_recvmsg(server4, IPPROTO_IP, IP_RECVTOS, "hello", 0xd0, "IPv4 setsockopt 0xd0");
	my_sendmsg(client4, IPPROTO_IP, IP_TOS, "hello", 0xff, use_header, "IPv4 header 0xff");
	my_recvmsg(server4, IPPROTO_IP, IP_RECVTOS, "hello", 0xff, "IPv4 header 0xff");
	my_sendmsg(client4, IPPROTO_IP, IP_TOS, "hello", 0xd0, use_header, "IPv4 header 0xd0");
	my_recvmsg(server4, IPPROTO_IP, IP_RECVTOS, "hello", 0xd0, "IPv4 header 0xd0");
}

T_DECL(ip6_tclass, "IPv6 TCLASS")
{
	int err;
	int val = 1;
	int server6;

	server6 = socket(AF_INET6, SOCK_DGRAM, 0);
	T_ASSERT_TRUE(server6 >= 0, "create server socket");

	err = setsockopt(server6, IPPROTO_IPV6, IPV6_RECVTCLASS, &val, sizeof(val));
	T_ASSERT_TRUE(err == 0, "setsockopt(IPPROTO_IPV6, IPV6_RECVTCLASS) failed");

	int client6 = socket(AF_INET6, SOCK_DGRAM, 0);
	T_ASSERT_TRUE(client6 >= 0, "create client socket");

	struct sockaddr_in6 addr6;
	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_len = sizeof(addr6);
	addr6.sin6_port = htons(8009);

	err = inet_pton(AF_INET6, "::1", &(addr6.sin6_addr));
	T_ASSERT_TRUE(err == 1, "convert address");
	err = bind(server6, (struct sockaddr *)&addr6, sizeof(addr6));
	T_ASSERT_TRUE(err == 0, "bind server socket");
	err = connect(client6, (struct sockaddr *)&addr6, sizeof(addr6));
	T_ASSERT_TRUE(err == 0, "connect client socket");

	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xff, use_setsockopt, "IPv6 setsockopt 0xff");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xff, "IPv6 setsockopt 0xff");
	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xd0, use_setsockopt, "IPv6 setsockopt 0xd0");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xd0, "IPv6 setsockopt 0xd0");
	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xfe, use_header, "IPv6 header 0xff");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xfe, "IPv6 header 0xff");
	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xa0, use_header, "IPv6 header 0xd0");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xa0, "IPv6 header 0xd0");

	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0x60, use_header_socket, "IPv6 header & socket 0x60");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0x60, "IPv6 header 0x60");

	int dscp = 0x59;
	setsockopt(client6, IPPROTO_IPV6, IPV6_TCLASS, &dscp, sizeof(dscp));

	my_sendmsg(client6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xa0, use_header, "IPv6 header 0xd0");
	my_recvmsg(server6, IPPROTO_IPV6, IPV6_TCLASS, "hello", 0xa0, "IPv6 header 0xd0");
}
