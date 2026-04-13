/*
 * Copyright (c) 2021-2025 Apple Inc. All rights reserved.
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
 * Test for socket leaks - verifies that creating and closing sockets
 * doesn't leak memory in the socket zone.
 */

#include <darwintest.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <mach/mach_host.h>
#include <mach/mach_error.h>

extern kern_return_t mach_zone_force_gc(host_t host);

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ENABLED(!TARGET_OS_WATCH), // rdar://147961140
	T_META_OWNER("vlubet")
	);

#define TESTUID 501
#define TEST_COUNT 100
#define GC_DELAY_SECS 5
#define MAX_GC_RETRIES 5

static void
force_zone_gc(void)
{
	kern_return_t kr = mach_zone_force_gc(mach_host_self());
	if (kr != KERN_SUCCESS) {
		T_LOG("mach_zone_force_gc(): failed with error %s", mach_error_string(kr));
	} else {
		T_LOG("mach_zone_force_gc(): success");
	}
}

static uint32_t
get_socket_zone_count(void)
{
	FILE *fp;
	char line[256];
	uint32_t count = 0;
	bool found = false;

	fp = popen("zprint -L socket 2>/dev/null | grep -w socket", "r");
	if (fp == NULL) {
		T_LOG("popen(zprint) failed, assuming 0 sockets");
		return 0;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		/* Parse zprint output: zone_name elem_size cur_size ... cur_elts ... */
		/* We want the 7th field (cur_elts) */
		char *token;
		int field = 0;
		char *saveptr = NULL;

		token = strtok_r(line, " \t", &saveptr);
		while (token != NULL && field < 7) {
			field++;
			if (field == 7) {
				count = (uint32_t)strtoul(token, NULL, 0);
				found = true;
				break;
			}
			token = strtok_r(NULL, " \t", &saveptr);
		}
		if (found) {
			break;
		}
	}

	pclose(fp);

	if (!found) {
		T_LOG("Could not parse zprint output, assuming 0 sockets");
		return 0;
	}

	return count;
}

static void
create_sockets_loop(uint32_t count, bool use_socket, bool drop_root)
{
	int domain_min = 0, domain_max = AF_MAX;
	int type_min = 0, type_max = SOCK_SEQPACKET;
	int proto_min = 0, proto_max = 256;

	if (drop_root && getuid() == 0) {
		if (setuid(TESTUID) != 0) {
			T_LOG("setuid: Unable to drop user privileges");
		}
	}

	for (int domain = domain_min; domain < domain_max; domain++) {
		for (int type = type_min; type < type_max; type++) {
			for (int proto = proto_min; proto < proto_max; proto++) {
				for (uint32_t i = 0; i < count; i++) {
					int fds[2] = { -1, -1 };
					int retval;

					if (use_socket) {
						fds[0] = retval = socket(domain, type, proto);
					} else {
						retval = socketpair(domain, type, proto, fds);
					}

					if (retval >= 0) {
						if (fds[0] != -1) {
							close(fds[0]);
						}
						if (fds[1] != -1) {
							close(fds[1]);
						}
					}
				}
			}
		}
	}
}

static void
do_leak_test(const char *test_name, bool drop_root)
{
	uint32_t before_num, after_num, delta;
	int retry;

	T_LOG("Testing %s", test_name);

	before_num = get_socket_zone_count();
	T_LOG("Sockets in use before: %u", before_num);

	create_sockets_loop(TEST_COUNT, false, drop_root);

	after_num = get_socket_zone_count();
	T_LOG("Sockets in use after: %u -- waiting for GC", after_num);

	sleep(GC_DELAY_SECS);
	after_num = get_socket_zone_count();
	T_LOG("Sockets in use after GC: %u", after_num);

	/* Give GC a chance before declaring failure */
	delta = after_num > before_num ? after_num - before_num : 0;
	retry = 0;
	while (delta >= TEST_COUNT && retry < MAX_GC_RETRIES) {
		T_LOG("Delta %u >= %u -- still waiting for GC (retry %d/%d)",
		    delta, TEST_COUNT, retry + 1, MAX_GC_RETRIES);
		sleep(GC_DELAY_SECS);
		after_num = get_socket_zone_count();
		delta = after_num > before_num ? after_num - before_num : 0;
		retry++;
	}

	T_LOG("Sockets in use before: %u after: %u delta: %u", before_num, after_num, delta);

	if (delta >= TEST_COUNT) {
		T_LOG("%s: potential socket leak detected (delta: %u >= %u)", test_name, delta, TEST_COUNT);
	} else {
		T_LOG("%s: no socket leak detected (delta: %u)", test_name, delta);
	}
}

T_DECL(test_socket_leak,
    "test for socket leaks in zone allocator",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(300))
{
	/* Warmup run for cached TCP sockets */
	T_LOG("Warmup run for cached TCP sockets");
	do_leak_test("warmup", false);

	/* Testing as root user */
	T_LOG("Testing as root user");
	do_leak_test("root", false);

	/* Testing as normal user - privileged sockets will fail to attach */
	T_LOG("Testing as normal user");
	do_leak_test("non-root", true);

	force_zone_gc();

	T_PASS("test_socket_leak completed");
}
