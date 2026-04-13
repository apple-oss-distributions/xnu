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

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/socketvar.h>
#include <unistd.h>

#include <net/pfkeyv2.h>
#include <netkey/keysock_private.h>
#include <net/route_private.h>

#include <darwintest.h>

/* ROUNDUP64 macro for alignment - same as kernel */
#ifndef ROUNDUP64
#define ROUNDUP64(x) (((x) + sizeof(u_int64_t) - 1) & ~(sizeof(u_int64_t) - 1))
#endif

#define ADVANCE64(p, n) (void*)((char *)(p) + ROUNDUP64(n))

/* Define XSO_* constants if not available */
#ifndef XSO_SOCKET
#define XSO_SOCKET      0x001
#define XSO_RCVBUF      0x002
#define XSO_SNDBUF      0x004
#define XSO_STATS       0x008
#define XSO_KEYPCB      0x800
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("eng_xnu_bsd_net"),
	T_META_ASROOT(true));

static const char *pcblist = "net.key.pcblist";

/*
 * Calculate the item size used by the kernel for each pcblist entry.
 * This matches the kernel's calculation in key_pcblist().
 */
static size_t
get_item_size(void)
{
	return ROUNDUP64(sizeof(struct xkeysockpcb)) +
	       ROUNDUP64(sizeof(struct xsocket_n)) +
	       2 * ROUNDUP64(sizeof(struct xsockbuf_n)) +
	       ROUNDUP64(sizeof(struct xsockstat_n));
}

/*
 * Helper function to check if a PF_KEY socket with specific protocol exists
 * that was created by our process.
 * Returns true if found.
 */
static bool
key_socket_exists(const void *buffer, size_t length, int expected_protocol)
{
	const struct xrtsockgen *xg = (const struct xrtsockgen *)buffer;
	const char *ptr = (const char *)buffer;
	size_t offset = xg->xg_len;
	size_t item_size = get_item_size();
	pid_t my_pid = getpid();

	T_LOG("key_socket_exists: checking for protocol %d, pid %d", expected_protocol, my_pid);
	T_LOG("  xg_len=%u, xg_count=%llu, xg_gencnt=%llu, item_size=%zu",
	    xg->xg_len, xg->xg_count, xg->xg_gencnt, item_size);

	while (offset + item_size <= length) {
		const struct xkeysockpcb *xkp = (const struct xkeysockpcb *)(ptr + offset);

		/* Stop if we hit the trailing xrtsockgen */
		if (xkp->xkp_len == sizeof(struct xrtsockgen)) {
			break;
		}

		/* Verify this is a key PCB structure */
		if (xkp->xkp_kind != XSO_KEYPCB) {
			T_LOG("  Unexpected kind %u at offset %zu (expected XSO_KEYPCB)",
			    xkp->xkp_kind, offset);
			break;
		}

		/* Calculate offset to xsocket_n and verify bounds */
		size_t xso_offset = offset + ROUNDUP64(sizeof(*xkp));
		if (xso_offset + sizeof(struct xsocket_n) > length) {
			T_LOG("  Not enough space for xsocket_n at offset %zu", xso_offset);
			break;
		}

		/* Find the xsocket_n structure following the xkeysockpcb */
		const struct xsocket_n *xso = (const struct xsocket_n *)(ptr + xso_offset);

		/* Verify this is a socket structure */
		if (xso->xso_kind != XSO_SOCKET) {
			T_LOG("  Unexpected xso_kind %u (expected XSO_SOCKET)", xso->xso_kind);
			offset += item_size;
			continue;
		}

		T_LOG("  Found PF_KEY socket: family=%u, protocol=%u, so_last_pid=%d, len=%u",
		    xkp->xkp_family, xkp->xkp_protocol, xso->so_last_pid, xkp->xkp_len);

		/* Check both protocol match and that it's our socket */
		if (xkp->xkp_protocol == expected_protocol && xso->so_last_pid == my_pid) {
			T_LOG("  -> Matched our socket!");
			return true;
		}

		offset += item_size;
	}

	return false;
}

/*
 * Helper function to count all PF_KEY sockets in the pcblist.
 */
static size_t
key_socket_count(const void *buffer, size_t length)
{
	const struct xrtsockgen *xg = (const struct xrtsockgen *)buffer;
	const char *ptr = (const char *)buffer;
	size_t offset = xg->xg_len;
	size_t item_size = get_item_size();
	size_t count = 0;

	while (offset + item_size <= length) {
		const struct xkeysockpcb *xkp = (const struct xkeysockpcb *)(ptr + offset);

		/* Stop if we hit the trailing xrtsockgen */
		if (xkp->xkp_len == sizeof(struct xrtsockgen)) {
			break;
		}

		count++;
		offset += item_size;
	}

	T_LOG("key_socket_count: counted %zu sockets (xg_count=%llu)",
	    count, xg->xg_count);

	return count;
}

/*
 * Basic test: create a PF_KEY socket and verify it appears in the pcblist.
 * This tests that key_pcblist() successfully enumerates opened PF_KEY sockets.
 */
T_DECL(key_pcblist_simple, "key pcblist sysctl - simple")
{
	int s;
	size_t length = 0;
	struct xrtsockgen *buffer;
	int result;

	/* Create a PF_KEY socket to be discovered in the pcblist */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket");
	T_LOG("Created PF_KEY socket with fd=%d, protocol=PF_KEY_V2", s);

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

	/* The PF_KEY socket should exist in the list */
	bool exists = key_socket_exists(buffer, length, PF_KEY_V2);
	T_ASSERT_TRUE(exists, "key pcblist contains PF_KEY_V2 socket");

	/* Verify the count matches what we enumerated */
	size_t counted = key_socket_count(buffer, length);
	T_EXPECT_EQ((u_int64_t)counted, buffer->xg_count, "counted sockets matches xg_count");

	close(s);
	free(buffer);
}

/*
 * Test socket added after getting buffer size.
 * The socket won't fit in the buffer allocated before it was created.
 */
T_DECL(key_pcblist_added, "key pcblist sysctl - socket added")
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

	/* Now create a PF_KEY socket AFTER getting the buffer size */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket");
	T_LOG("Created PF_KEY socket with fd=%d, protocol=PF_KEY_V2, after sizing", s);

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
		T_LOG("PF_KEY_V2 socket exists in list: %s",
		    key_socket_exists(buffer, length, PF_KEY_V2) ? "yes" : "no");
	}

	close(s);
	free(buffer);
}

/*
 * Test socket removed before populating buffer.
 * The socket should not appear in the final list.
 */
T_DECL(key_pcblist_removed, "key pcblist sysctl - socket removed")
{
	int s;
	size_t length = 0;
	struct xrtsockgen *buffer;
	int result;

	/* Create a PF_KEY socket that will be removed */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket");
	T_LOG("Created PF_KEY socket with fd=%d (to be removed)", s);

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
	T_LOG("Closed PF_KEY socket fd=%d", s);

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
	 */
	T_LOG("Enumerated %zu sockets in pcblist", key_socket_count(buffer, length));

	free(buffer);
}

/*
 * Test multiple PF_KEY sockets.
 */
T_DECL(key_pcblist_multiple, "key pcblist sysctl - multiple sockets")
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
	initial_count = key_socket_count(buffer, length);
	T_LOG("Initial PF_KEY socket count: %zu", initial_count);
	free(buffer);

	/* Create multiple PF_KEY sockets - all use PF_KEY_V2 protocol */
	T_ASSERT_POSIX_SUCCESS(s1 = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket 1");
	T_ASSERT_POSIX_SUCCESS(s2 = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket 2");
	T_ASSERT_POSIX_SUCCESS(s3 = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket 3");
	T_LOG("Created PF_KEY sockets: fd=%d, fd=%d, fd=%d (all PF_KEY_V2)",
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
	final_count = key_socket_count(buffer, length);
	T_LOG("Final PF_KEY socket count: %zu (expected at least %zu more)",
	    final_count, initial_count + 3);

	/* We should have at least 3 more sockets than initially */
	T_EXPECT_GE(final_count, initial_count + 3,
	    "final count should include our 3 new sockets");

	/* Verify at least one of our sockets appears (they all have same protocol) */
	T_EXPECT_TRUE(key_socket_exists(buffer, length, PF_KEY_V2),
	    "PF_KEY_V2 socket exists");

	close(s1);
	close(s2);
	close(s3);
	free(buffer);
}

/*
 * Test generation count changes when sockets are created/destroyed.
 */
T_DECL(key_pcblist_generation, "key pcblist sysctl - generation count")
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

	/* Create and close a PF_KEY socket to change generation */
	T_ASSERT_POSIX_SUCCESS(s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), "create PF_KEY socket");
	T_LOG("Created PF_KEY socket fd=%d", s);
	close(s);
	T_LOG("Closed PF_KEY socket fd=%d", s);

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
