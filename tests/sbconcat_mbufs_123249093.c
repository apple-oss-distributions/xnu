/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <sys/socket.h>
#include <sys/un.h>

#include <unistd.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#define MAX_SUN_PATH (SOCK_MAXADDRLEN - offsetof(struct sockaddr_un, sun_path))

struct u_m_hdr {
	uintptr_t       mh_next;       /* next buffer in chain */
	uintptr_t       mh_nextpkt;    /* next chain in queue/record */
	uintptr_t       mh_data;        /* location of data */
	int32_t         mh_len;         /* amount of data in this mbuf */
	u_int16_t       mh_type;        /* type of data in this mbuf */
	u_int16_t       mh_flags;       /* flags; see below */
};

#define MLEN_OVERFLOW_OFSSET (256 - sizeof(struct u_m_hdr))

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking")
	);

T_DECL(sbconcat_mbufs_123249093, "test sbconcat_mbufs() overflow radar://123249093")
{
	int pair[2] = { -1, -1 };
	union {
		uint8_t _buffer[SOCK_MAXADDRLEN];
		struct sockaddr_un _sun;
	} sun_;
	struct sockaddr_un *sun = &sun_._sun;
	struct u_m_hdr *mhdr;
	ssize_t retval;
	socklen_t address_len = SOCK_MAXADDRLEN;

	snprintf(sun->sun_path, MAX_SUN_PATH, "/tmp/%s.%d", getprogname(), getpid());

	mhdr = (struct u_m_hdr *)(void *)&sun_._buffer[MLEN_OVERFLOW_OFSSET];
	mhdr->mh_next = (uintptr_t)0x4040404040404040ULL;
	mhdr->mh_nextpkt = (uintptr_t)0x4141414141414141ULL;
	mhdr->mh_data = (uintptr_t)0x4242424242424242ULL;
	mhdr->mh_len = 0x43434343;
	mhdr->mh_type = 0x4444;
	mhdr->mh_flags = 0x4545;

	T_LOG("sizeof(struct u_m_hdr): %lu ", sizeof(struct u_m_hdr));
	T_LOG("MLEN_OVERFLOW_OFSSET: %lu ", MLEN_OVERFLOW_OFSSET);
	T_LOG("sun_path: %s ", sun->sun_path);

	/* add 1 for the end of string */
	sun->sun_len =  SOCK_MAXADDRLEN;
	sun->sun_family = AF_LOCAL;

	T_LOG("sun_len: %u sun_path: %s ", sun->sun_len, sun->sun_path);

	(void)unlink(sun->sun_path);

	T_ASSERT_POSIX_SUCCESS(socketpair(PF_LOCAL, SOCK_DGRAM, 0, pair), "socketpair");
	T_LOG("pair[0]: %d pair[1]: %d", pair[0], pair[1]);

	T_ASSERT_POSIX_SUCCESS(bind(pair[0], (struct sockaddr *)sun, sun->sun_len), "bind()");

	if (getsockname(pair[0], (struct sockaddr *)sun, &address_len) == 0) {
		T_LOG("getsockname(%d) OK, sun_len: %u sun_path: %s",
		    pair[0], sun->sun_len, sun->sun_path);
	} else {
		T_LOG("getsockname(%d) error %s (%d)",
		    pair[0], strerror(errno), errno);
	}

	/* The call may succeed or fail with ENOBUFS for CONFIG_MBUF_MCACHE */
	retval = write(pair[0], NULL, 0);
	T_ASSERT_TRUE((retval == 0 || errno == ENOBUFS), "write()");

	close(pair[0]);
	close(pair[1]);

	(void)unlink(sun->sun_path);
}
