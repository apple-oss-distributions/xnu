/*
 * Copyright (c) 2018, 2025 Apple Inc. All rights reserved.
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

/*
 * Test for rdar://44899171
 * This test validates that getting the sysctl variables net.local.xxx.pcblist
 * and net.local.xxx.pcblist64 do not cause a __memmove_chk-assertion() panic
 * for long path names
 */

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/un.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_OWNER("vlubet")
	);

/*
 * Check-out long path names
 */
#define STREAM_LONG_PATH_252 \
"/tmp/test-stream-long-path-name-for-testing-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion"
#define STREAM_LONG_PATH_253 \
"/tmp/test-stream-long-path-name-for-testing-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion1"
#define STREAM_LONG_PATH_254 \
"/tmp/test-stream-long-path-name-for-testing-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion23"
#define DGRAM_LONG_PATH_252 \
"/tmp/a-dgram-long-path-name-is-used-to-test-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion"
#define DGRAM_LONG_PATH_253 \
"/tmp/a-dgram-long-path-name-is-used-to-test-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion1"
#define DGRAM_LONG_PATH_254 \
"/tmp/a-dgram-long-path-name-is-used-to-test-the-fix-for-radar-44899171-and-verify-the-net-local-stream-pcblist-net-local-stream-pcblist64-net-local-stream-pcblist64-net-local-stream-pcblist64-sysctl-are-not-triggering-the-strict-__memmove_chk-assertion23"

struct sock_entry {
	int fd;
	int type;
	const char *path;
	struct sockaddr_un *sun;
	uint8_t sun_buffer[SOCK_MAXADDRLEN];
};

static struct sock_entry sock_entries[] = {
	{ .fd = -1, .type = SOCK_STREAM, .path = STREAM_LONG_PATH_252 },
	{ .fd = -1, .type = SOCK_STREAM, .path = STREAM_LONG_PATH_253 },
	{ .fd = -1, .type = SOCK_STREAM, .path = STREAM_LONG_PATH_254 },
	{ .fd = -1, .type = SOCK_DGRAM, .path = DGRAM_LONG_PATH_252 },
	{ .fd = -1, .type = SOCK_DGRAM, .path = DGRAM_LONG_PATH_253 },
	{ .fd = -1, .type = SOCK_DGRAM, .path = DGRAM_LONG_PATH_254 },
	{ .fd = -1, .type = 0, .path = NULL }
};

static const char *const socktypestrs[] =
{ "#0", "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW" };

static void
do_sysctl(const char *mibvar)
{
	char *buf = NULL;
	size_t len = 0;

	/* The pcblist64 sysctl variables are not available on all platforms */
	int ret = sysctlbyname(mibvar, 0, &len, 0, 0);
	if (ret < 0) {
		if (errno == ENOENT) {
			T_LOG("sysctl %s not available (ENOENT)", mibvar);
			return;
		}
		T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname(%s) get size", mibvar);
	}

	buf = malloc(len);
	T_QUIET;
	T_ASSERT_NOTNULL(buf, "malloc %zu bytes", len);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname(mibvar, buf, &len, 0, 0),
	    "sysctlbyname(%s)", mibvar);
	T_LOG("length of %s: %zu", mibvar, len);

	free(buf);
}

static void
do_connect(struct sock_entry *sock_entry)
{
	int s = socket(AF_LOCAL, sock_entry->type, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(%s)", socktypestrs[sock_entry->type]);

	char buf[UINT8_MAX];
	strlcpy(buf, sock_entry->sun->sun_path, sizeof(buf));
	buf[sock_entry->sun->sun_len - offsetof(struct sockaddr_un, sun_path)] = 0;
	T_LOG("connecting to: '%s' with sun_len: %u", buf, sock_entry->sun->sun_len);

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(connect(s, (const struct sockaddr *)sock_entry->sun,
	    sock_entry->sun->sun_len), "connect(%s)", sock_entry->path);

	close(s);
}

T_DECL(test_44899171,
    "test pcblist sysctl with long UNIX domain socket path names",
    T_META_CHECK_LEAKS(false))
{
	const size_t max_sun_path_size = SOCK_MAXADDRLEN - offsetof(struct sockaddr_un, sun_path);
	T_LOG("max_sun_path_size: %zu", max_sun_path_size);

	struct sock_entry *sock_entry;

	/* Create and bind UNIX domain sockets with long path names */
	for (sock_entry = sock_entries; sock_entry->path != NULL; sock_entry++) {
		T_LOG("length of %s path: %zu", socktypestrs[sock_entry->type],
		    strlen(sock_entry->path));

		size_t path_size = MIN(max_sun_path_size, strlen(sock_entry->path));

		sock_entry->sun = (struct sockaddr_un *)sock_entry->sun_buffer;
		sock_entry->sun->sun_family = AF_LOCAL;
		sock_entry->sun->sun_len = offsetof(struct sockaddr_un, sun_path) + path_size;
		(void)memcpy(sock_entry->sun->sun_path, sock_entry->path, path_size);
		T_LOG("sun_len: %u path_size: %zu", sock_entry->sun->sun_len, path_size);

		(void)unlink(sock_entry->sun->sun_path);

		sock_entry->fd = socket(AF_LOCAL, sock_entry->type, 0);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(sock_entry->fd, "socket(%s)",
		    socktypestrs[sock_entry->type]);

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(bind(sock_entry->fd,
		    (const struct sockaddr *)sock_entry->sun, sock_entry->sun->sun_len),
		    "bind(%s)", sock_entry->path);

		if (sock_entry->type == SOCK_STREAM) {
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(listen(sock_entry->fd, 128),
			    "listen(%s)", sock_entry->path);
		}

		do_connect(sock_entry);
	}

	/* Test that sysctl pcblist variables don't panic with long path names */
	do_sysctl("net.local.stream.pcblist");
	do_sysctl("net.local.stream.pcblist64");
	do_sysctl("net.local.dgram.pcblist");
	do_sysctl("net.local.dgram.pcblist64");

	/* Cleanup */
	for (sock_entry = sock_entries; sock_entry->path != NULL; sock_entry++) {
		if (sock_entry->fd >= 0) {
			close(sock_entry->fd);
		}
		(void)unlink(sock_entry->sun->sun_path);
	}

	T_PASS("test_44899171 completed without panic");
}
