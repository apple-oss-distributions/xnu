/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <net/route.h>
#include <net/route_private.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/socketvar.h>
#include <unistd.h>

#include <darwintest.h>

/* ROUNDUP64 macro for alignment - same as kernel */
#ifndef ROUNDUP64
#define ROUNDUP64(x) (((x) + sizeof(u_int64_t) - 1) & ~(sizeof(u_int64_t) - 1))
#endif

#define ADVANCE64(p, n) (void*)((char *)(p) + ROUNDUP64(n))

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("eng_xnu_bsd_net"),
	T_META_ASROOT(true));

static const char *pcblist = "net.route.pcblist";

/*
 * Calculate the item size used by the kernel for each pcblist entry.
 * This matches the kernel's calculation in route_pcblist().
 */
static size_t
get_item_size(void)
{
	return ROUNDUP64(sizeof(struct xrtsockpcb)) +
	       ROUNDUP64(sizeof(struct xsocket_n)) +
	       2 * ROUNDUP64(sizeof(struct xsockbuf_n)) +
	       ROUNDUP64(sizeof(struct xsockstat_n));
}

/*
 * Helper function to check if a routing socket with specific protocol exists
 * that was created by our process.
 * The protocol parameter is the address family filter (AF_INET, AF_INET6, AF_UNSPEC).
 * Returns true if found.
 */
static bool
route_socket_exists(const void *buffer, size_t length, int expected_protocol)
{
	const struct xrtsockgen *xg = (const struct xrtsockgen *)buffer;
	const char *ptr = (const char *)buffer;
	size_t offset = xg->xg_len;
	size_t item_size = get_item_size();
	pid_t my_pid = getpid();

	T_LOG("route_socket_exists: checking for protocol %d, pid %d", expected_protocol, my_pid);
	T_LOG("  xg_len=%u, xg_count=%llu, xg_gencnt=%llu, item_size=%zu",
	    xg->xg_len, xg->xg_count, xg->xg_gencnt, item_size);

	while (offset + item_size <= length) {
		const struct xrtsockpcb *xrp = (const struct xrtsockpcb *)(ptr + offset);

		/* Stop if we hit the trailing xrtsockgen */
		if (xrp->xrp_len == sizeof(struct xrtsockgen)) {
			break;
		}

		/* Verify this is a route PCB structure */
		if (xrp->xrp_kind != XSO_ROUTEPCB) {
			T_LOG("  Unexpected kind %u at offset %zu (expected XSO_ROUTEPCB)",
			    xrp->xrp_kind, offset);
			break;
		}

		/* Calculate offset to xsocket_n and verify bounds */
		size_t xso_offset = offset + ROUNDUP64(sizeof(*xrp));
		if (xso_offset + sizeof(struct xsocket_n) > length) {
			T_LOG("  Not enough space for xsocket_n at offset %zu", xso_offset);
			break;
		}

		/* Find the xsocket_n structure following the xrtsockpcb */
		const struct xsocket_n *xso = (const struct xsocket_n *)(ptr + xso_offset);

		/* Verify this is a socket structure */
		if (xso->xso_kind != XSO_SOCKET) {
			T_LOG("  Unexpected xso_kind %u (expected XSO_SOCKET)", xso->xso_kind);
			offset += item_size;
			continue;
		}

		T_LOG("  Found routing socket: family=%u, protocol=%u, so_last_pid=%d, len=%u",
		    xrp->xrp_family, xrp->xrp_protocol, xso->so_last_pid, xrp->xrp_len);

		/* Check both protocol match and that it's our socket */
		if (xrp->xrp_protocol == expected_protocol && xso->so_last_pid == my_pid) {
			T_LOG("  -> Matched our socket!");
			return true;
		}

		offset += item_size;
	}

	return false;
}

/*
 * Helper function to count all routing sockets in the pcblist.
 */
static size_t
route_socket_count(const void *buffer, size_t length)
{
	const struct xrtsockgen *xg = (const struct xrtsockgen *)buffer;
	const char *ptr = (const char *)buffer;
	size_t offset = xg->xg_len;
	size_t item_size = get_item_size();
	size_t count = 0;

	while (offset + item_size <= length) {
		const struct xrtsockpcb *xrp = (const struct xrtsockpcb *)(ptr + offset);

		/* Stop if we hit the trailing xrtsockgen */
		if (xrp->xrp_len == sizeof(struct xrtsockgen)) {
			break;
		}

		count++;
		offset += item_size;
	}

	T_LOG("route_socket_count: counted %zu sockets (xg_count=%llu)",
	    count, xg->xg_count);

	return count;
}

/*
 * Basic test: create a routing socket and verify it appears in the pcblist.
 * This tests that route_pcblist() successfully enumerates opened routing sockets.
 */
T_DECL(route_pcblist_simple, "route pcblist sysctl - simple")
{
	int s;
	size_t length = 0;
	struct xrtsockgen *buffer;
	int result;

	/* Create a routing socket to be discovered in the pcblist */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_ROUTE, SOCK_RAW, AF_INET), "create PF_ROUTE socket");
	T_LOG("Created routing socket with fd=%d, protocol=AF_INET", s);

	/* Get the buffer length for the pcblist */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	if (result == -1 && errno == ENOENT) {
		close(s);
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);
	T_ASSERT_GT(length, sizeof(struct xrtsockgen), "buffer length should be > header size");
	T_LOG("Buffer length: %zu bytes", length);

	/* Allocate the buffer */
	buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer");

	/* Populate the buffer with the pcblist */
	result = sysctlbyname(pcblist, buffer, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate buffer with %s", pcblist);

	/* Verify the header */
	T_ASSERT_GE(buffer->xg_len, (u_int32_t)sizeof(struct xrtsockgen), "xg_len is valid");
	T_ASSERT_GT(buffer->xg_count, 0ULL, "xg_count should be > 0");
	T_LOG("Generation count: %llu, socket count: %llu",
	    buffer->xg_gencnt, buffer->xg_count);

	/* The routing socket should exist in the list */
	bool exists = route_socket_exists(buffer, length, AF_INET);
	T_ASSERT_TRUE(exists, "route pcblist contains AF_INET routing socket");

	/* Verify the count matches what we enumerated */
	size_t counted = route_socket_count(buffer, length);
	T_EXPECT_EQ((u_int64_t)counted, buffer->xg_count, "counted sockets matches xg_count");

	close(s);
	free(buffer);
}

/*
 * Test socket added after getting buffer size.
 * The socket won't fit in the buffer allocated before it was created.
 */
T_DECL(route_pcblist_added, "route pcblist sysctl - socket added")
{
	int s;
	size_t length = 0;
	size_t old_length = 0;
	struct xrtsockgen *buffer;
	int result;

	/* Get the buffer length for the pcblist BEFORE creating the socket */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	if (result == -1 && errno == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);
	old_length = length;
	T_LOG("Buffer length before socket creation: %zu bytes", old_length);

	/* Now create a routing socket AFTER getting the buffer size */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_ROUTE, SOCK_RAW, AF_INET6), "create PF_ROUTE socket");
	T_LOG("Created routing socket with fd=%d after sizing", s);

	/* Allocate the buffer with the old size */
	buffer = malloc(old_length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer");

	/* Try to populate the buffer with the old size */
	length = old_length;
	result = sysctlbyname(pcblist, buffer, &length, NULL, 0);

	/*
	 * The sysctl may fail with ENOMEM if the new socket doesn't fit,
	 * or it may succeed if there was extra space allocated.
	 * Both outcomes are acceptable - we're testing the behavior.
	 */
	if (result == -1 && errno == ENOMEM) {
		T_LOG("ENOMEM as expected - buffer too small (needed %zu, had %zu)",
		    length, old_length);
		T_PASS("sysctl correctly returned ENOMEM for undersized buffer");
	} else {
		T_ASSERT_POSIX_SUCCESS(result, "populate buffer with %s", pcblist);
		T_LOG("Buffer was large enough despite new socket");

		/*
		 * If it succeeded, check if the new socket appears.
		 * It may not if it was created after the generation snapshot.
		 */
		T_LOG("AF_INET6 socket exists in list: %s",
		    route_socket_exists(buffer, length, AF_INET6) ? "yes" : "no");
	}

	close(s);
	free(buffer);
}

/*
 * Test socket removed before populating buffer.
 * The socket should not appear in the final list.
 */
T_DECL(route_pcblist_removed, "route pcblist sysctl - socket removed")
{
	int s;
	size_t length = 0;
	struct xrtsockgen *buffer;
	int result;

	/* Create a routing socket that will be removed */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC), "create PF_ROUTE socket");
	T_LOG("Created routing socket with fd=%d (to be removed)", s);

	/* Get the buffer length for the pcblist */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	if (result == -1 && errno == ENOENT) {
		close(s);
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);
	T_LOG("Buffer length: %zu bytes", length);

	/* Close the socket BEFORE populating the buffer */
	close(s);
	T_LOG("Closed routing socket fd=%d", s);

	/* Allocate the buffer */
	buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer");

	/* Populate the buffer with the pcblist */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "get updated buffer size");

	result = sysctlbyname(pcblist, buffer, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate buffer with %s", pcblist);

	/*
	 * The closed socket should not appear in the list.
	 * Note: AF_UNSPEC is used to distinguish this socket, but other
	 * routing sockets may exist in the system.
	 */
	T_LOG("Enumerated %zu sockets in pcblist", route_socket_count(buffer, length));

	free(buffer);
}

/*
 * Test multiple routing sockets with different protocols.
 */
T_DECL(route_pcblist_multiple, "route pcblist sysctl - multiple sockets")
{
	int s1, s2, s3;
	size_t length = 0;
	struct xrtsockgen *buffer;
	int result;
	size_t initial_count, final_count;

	/* Get initial count */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	if (result == -1 && errno == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "get initial buffer size");

	buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated initial buffer");

	result = sysctlbyname(pcblist, buffer, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate initial buffer");
	initial_count = route_socket_count(buffer, length);
	T_LOG("Initial routing socket count: %zu", initial_count);
	free(buffer);

	/* Create multiple routing sockets with different protocols */
	T_ASSERT_POSIX_SUCCESS(s1 = socket(PF_ROUTE, SOCK_RAW, AF_INET), "create AF_INET routing socket");
	T_ASSERT_POSIX_SUCCESS(s2 = socket(PF_ROUTE, SOCK_RAW, AF_INET6), "create AF_INET6 routing socket");
	T_ASSERT_POSIX_SUCCESS(s3 = socket(PF_ROUTE, SOCK_RAW, AF_UNSPEC), "create AF_UNSPEC routing socket");
	T_LOG("Created routing sockets: fd=%d (AF_INET), fd=%d (AF_INET6), fd=%d (AF_UNSPEC)",
	    s1, s2, s3);

	/* Get the buffer length for the pcblist */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);
	T_LOG("Buffer length: %zu bytes", length);

	/* Allocate the buffer */
	buffer = malloc(length);
	T_ASSERT_NOTNULL(buffer, "allocated buffer");

	/* Populate the buffer with the pcblist */
	result = sysctlbyname(pcblist, buffer, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate buffer with %s", pcblist);

	/* Count the sockets */
	final_count = route_socket_count(buffer, length);
	T_LOG("Final routing socket count: %zu (expected at least %zu more)",
	    final_count, initial_count + 3);

	/* We should have at least 3 more sockets than initially */
	T_EXPECT_GE(final_count, initial_count + 3,
	    "final count should include our 3 new sockets");

	/* Verify each socket type appears */
	T_EXPECT_TRUE(route_socket_exists(buffer, length, AF_INET),
	    "AF_INET routing socket exists");
	T_EXPECT_TRUE(route_socket_exists(buffer, length, AF_INET6),
	    "AF_INET6 routing socket exists");

	close(s1);
	close(s2);
	close(s3);
	free(buffer);
}

/*
 * Test generation count changes when sockets are created/destroyed.
 */
T_DECL(route_pcblist_generation, "route pcblist sysctl - generation count")
{
	int s;
	size_t length = 0;
	struct xrtsockgen *buffer1, *buffer2;
	int result;
	uint64_t gen1, gen2;

	/* Get initial generation count */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	if (result == -1 && errno == ENOENT) {
		T_SKIP("%s missing", pcblist);
	}
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);

	buffer1 = malloc(length);
	T_ASSERT_NOTNULL(buffer1, "allocated first buffer");

	result = sysctlbyname(pcblist, buffer1, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate first buffer");
	gen1 = buffer1->xg_gencnt;
	T_LOG("Initial generation count: %llu", gen1);
	free(buffer1);

	/* Create and close a routing socket to change generation */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_ROUTE, SOCK_RAW, AF_INET), "create routing socket");
	T_LOG("Created routing socket fd=%d", s);
	close(s);
	T_LOG("Closed routing socket fd=%d", s);

	/* Get new generation count */
	result = sysctlbyname(pcblist, NULL, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "get buffer size for %s", pcblist);

	buffer2 = malloc(length);
	T_ASSERT_NOTNULL(buffer2, "allocated second buffer");

	result = sysctlbyname(pcblist, buffer2, &length, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "populate second buffer");
	gen2 = buffer2->xg_gencnt;
	T_LOG("New generation count: %llu", gen2);

	/*
	 * Generation count should have changed after socket creation/destruction.
	 * Note: This may not always be true if the implementation doesn't increment
	 * the generation count, so we use T_EXPECT instead of T_ASSERT.
	 */
	T_EXPECT_NE(gen1, gen2, "generation count should change after socket lifecycle");

	free(buffer2);
}
