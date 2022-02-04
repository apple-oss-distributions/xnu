/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#define __APPLE_USE_RFC_3542 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <semaphore.h>
#include <darwintest.h>

#define LOGSOCKOPT(x) {                                                         \
    int __retv = (x);                                                           \
    if (__retv == -1) {                                                         \
	T_LOG("[:(] SETSOCKOPT FAILED: %s = -1, errno = %d\n", #x, errno);      \
    }                                                                           \
}

#define LISTENER_PORT 9999

void do_kqueue(int kq, int sockfd);
void handle_recv(struct msghdr *recvmsghdr, int packet_len);

sem_t mutex;

static void *
listener_thread(void *unused)
{
	int sockfd;
	int clientlen;
	struct sockaddr_in serveraddr;
	struct sockaddr_in clientaddr;
	struct hostent *hostp;
	char *buf;
	char *hostaddrp;
	int optval;
	int n;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		T_SKIP("cannot open listener sock");
	}

	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)LISTENER_PORT);
	serveraddr.sin_len = sizeof(struct sockaddr_in);

	if (bind(sockfd, (struct sockaddr *)&serveraddr,
	    sizeof(serveraddr)) < 0) {
		T_SKIP("ERROR on binding");
	}

	clientlen = sizeof(clientaddr);
	buf = malloc(5);
	T_LOG("listener started \n");
	sem_post(&mutex);

	while (1) {
		n = recvfrom(sockfd, buf, 5, 0,
		    (struct sockaddr *)&clientaddr, &clientlen);
		if (n < 0) {
			T_SKIP("ERROR in recvfrom");
		}

		hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
		    sizeof(clientaddr.sin_addr.s_addr),
		    AF_INET);
		if (hostp == NULL) {
			T_SKIP("ERROR on gethostbyaddr");
		}
		hostaddrp = inet_ntoa(clientaddr.sin_addr);
		if (hostaddrp == NULL) {
			T_SKIP("ERROR on inet_ntoa\n");
		}

		n = sendto(sockfd, buf, n, 0,
		    (struct sockaddr *)&clientaddr, clientlen);
		if (n < 0) {
			T_SKIP("ERROR in sendto");
		}
	}
}

T_DECL(v4mappedv6_recvpktinfo, "Test setting and using IPV6_RECVPKTINFO on a v4-mapped-v6 address socket")
{
	pthread_t t;
	sem_init(&mutex, 0, 1);
	int error = pthread_create(&t, NULL, &listener_thread, NULL);
	if (error != 0) {
		T_SKIP("cannot start listener thread");
	}

	sem_wait(&mutex);

	struct sockaddr_in6 local_addr = { .sin6_family = AF_INET6, .sin6_len = sizeof(struct sockaddr_in6) };
	struct sockaddr_in6 remote_addr = { };

	int sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		T_SKIP("Couldn't create socket. errno = %d\n", errno);
	}

	int Option = 0;
	LOGSOCKOPT(setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &Option, sizeof(Option)));

	Option = 1;
	LOGSOCKOPT(setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &Option, sizeof(Option)));

	int ret = bind(sockfd, (const struct sockaddr *)&local_addr, sizeof(local_addr));
	if (ret == -1) {
		T_SKIP("Couldn't bind. errno = %d\n", ret);
	}

	struct in_addr v4addr = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};

	// map v4 to v6
	remote_addr.sin6_family = AF_INET6;
	remote_addr.sin6_port = htons(LISTENER_PORT);
	remote_addr.sin6_len = sizeof(struct sockaddr_in6);
	memset(&(remote_addr.sin6_addr.s6_addr[10]), 0xff, 2);
	memcpy(&(remote_addr.sin6_addr.s6_addr[12]), &v4addr.s_addr, 4);

	// now remote_addr is a v4-mapped v6 address
	ret = connect(sockfd, (const struct sockaddr *)&remote_addr, sizeof(remote_addr));

	if (ret == -1) {
		T_SKIP("Couldn't connect. ret = %d, errno = %d\n", ret, errno);
	}

	T_LOG("Socket established. Binded & connected.\n");

	int kq = kqueue();

	if (kq == -1) {
		T_SKIP("Failed to kqueue. errno = %d\n", errno);
	}

	// add fd to kqueue
	struct kevent evSet = { };
	EV_SET(&evSet, sockfd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, (void *)NULL);
	if (kevent(kq, &evSet, 1, NULL, 0, NULL) < 0) {
		T_SKIP("kevent failed??\n");
	}

	// send pkt to notify remote
	sendto(sockfd, "ping", 4, 0, NULL, 0);
	do_kqueue(kq, sockfd);
}

void
do_kqueue(int kq, int sockfd)
{
	int ret = 0;

	char control_space[CMSG_SPACE(8192)] = {};
	struct msghdr recvmsghdr = {};
	char packet_space[1500] = {};

	struct iovec recv_iov;
	recv_iov.iov_len = 1200; // just a safe buffer from the 1500 mut
	recv_iov.iov_base = &packet_space;

	recvmsghdr.msg_iov = &recv_iov;
	recvmsghdr.msg_iovlen = 1;
	recvmsghdr.msg_control = &control_space;
	recvmsghdr.msg_controllen = sizeof(control_space);
	recvmsghdr.msg_flags = 0;

	struct kevent evSet;
	struct kevent evList[32];

	struct timespec timeout;
	timeout.tv_sec = 10;
	timeout.tv_nsec = 0;

	int nev = kevent(kq, NULL, 0, evList, 32, &timeout);

	for (int i = 0; i < nev; i++) {
		T_LOG("[kevent] ident = %zd, filter = %hu, flags = %hd, fflags = %d, data = %zd, udata = %p\n",
		    evList[i].ident, evList[i].filter, evList[i].flags, evList[i].fflags, evList[i].data, evList[i].udata);

		if (evList[i].filter == EVFILT_READ) {
			ret = recvmsg(sockfd, &recvmsghdr, 0);
			if (ret != -1) {
				handle_recv(&recvmsghdr, ret);
			} else {
				T_SKIP("sender recv failed");
			}
			return;
		}
	}

	T_FAIL("timeout after 10s");
}

void
handle_recv(struct msghdr *recvmsghdr, int packet_len)
{
	T_LOG("[!!] Received %d bytes...", packet_len);

	for (int i = 0; i < MIN(packet_len, 5); i++) {
		T_LOG("%02x ", ((char *)recvmsghdr->msg_iov->iov_base)[i]);
	}

	T_LOG("\n");

	struct cmsghdr *cmsg;
	int received_cmsg_header = 0;
	for (cmsg = CMSG_FIRSTHDR(recvmsghdr); cmsg != NULL; cmsg = CMSG_NXTHDR(recvmsghdr, cmsg)) {
		// this never gets hit
		T_LOG("cmsg_level: %d, cmsg_type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
		received_cmsg_header = 1;
	}

	T_EXPECT_TRUE(received_cmsg_header == 1, "recved cmsg hdr");
	T_PASS("Recvd cmsg hdr");
}
