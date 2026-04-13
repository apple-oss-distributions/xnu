/*
 * Copyright (c) 2019, 2025 Apple Inc. All rights reserved.
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
 * Test for connect() race condition (rdar://54833076)
 *
 * Racing connect() calls while SS_ISCONNECTING flag is set can lead to
 * multiple successful connections on the same socket, which can cause
 * use-after-free conditions.
 */

#include <darwintest.h>
#include <pthread.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <string.h>
#include <unistd.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true)
	);

#define CONTROL_NAME "com.apple.net.ipsec_control"

static int saved_panicdebug = -1;

static void
restore_panicdebug(void)
{
	if (saved_panicdebug != -1) {
		int ret = sysctlbyname("net.systm.kctl.panicdebug", NULL, NULL,
		    &saved_panicdebug, sizeof(saved_panicdebug));
		if (ret != 0) {
			T_LOG("Failed to restore net.systm.kctl.panicdebug to %d", saved_panicdebug);
		}
	}
}

struct shared_context {
	int sock;
	struct sockaddr_ctl sa;
	pthread_mutex_t success_mtx;
	pthread_mutex_t control_mtx;
	int success;
	bool finished;
};

static int
try_connect(struct shared_context *pctx)
{
	int result = connect(pctx->sock, (const struct sockaddr *)&pctx->sa, sizeof(struct sockaddr_ctl));
	if (0 == result) {
		pthread_mutex_lock(&pctx->success_mtx);
		pctx->success++;
		if (pctx->success > 1) {
			T_LOG("Multiple successful connect()s for the same socket! (count = %d)", pctx->success);
			pctx->finished = true;
		}
		pthread_mutex_unlock(&pctx->success_mtx);
	}
	return result;
}

static void *
racer(void *data)
{
	struct shared_context *pctx = data;

	while (!pctx->finished) {
		pthread_mutex_lock(&pctx->control_mtx);
		try_connect(pctx);
		pthread_mutex_unlock(&pctx->control_mtx);
	}

	return NULL;
}

T_DECL(test_connect_race,
    "test connect() racing with SS_ISCONNECTING flag (rdar://54833076)",
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(60))
{
	struct shared_context ctx = {
		.sa = {
			.sc_family = AF_SYSTEM,
			.sc_len = sizeof(struct sockaddr_ctl),
			.sc_id = 0,
			.sc_unit = 0
		},
		.success = 0,
		.finished = false
	};
	struct ctl_info ctl_info;
	pthread_t t;
	int count = 0;
	size_t oldlen = sizeof(saved_panicdebug);
	int newval = 1;

	/* Save and set net.systm.kctl.panicdebug sysctl */
	if (sysctlbyname("net.systm.kctl.panicdebug", &saved_panicdebug, &oldlen, NULL, 0) != 0) {
		T_LOG("Could not get net.systm.kctl.panicdebug, skipping sysctl setup");
		saved_panicdebug = -1;
	} else {
		T_LOG("Saved net.systm.kctl.panicdebug = %d", saved_panicdebug);
		if (sysctlbyname("net.systm.kctl.panicdebug", NULL, NULL, &newval, sizeof(newval)) != 0) {
			T_LOG("Could not set net.systm.kctl.panicdebug to 1");
		} else {
			T_LOG("Set net.systm.kctl.panicdebug to 1");
		}
	}
	T_ATEND(restore_panicdebug);

	T_ASSERT_POSIX_ZERO(pthread_mutex_init(&ctx.success_mtx, NULL), "pthread_mutex_init success_mtx");
	T_ASSERT_POSIX_ZERO(pthread_mutex_init(&ctx.control_mtx, NULL), "pthread_mutex_init control_mtx");

	T_LOG("Creating socket");
	ctx.sock = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	T_ASSERT_POSIX_SUCCESS(ctx.sock, "socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)");

	T_LOG("Getting control ID");
	memset(&ctl_info, 0, sizeof(ctl_info));
	strncpy(ctl_info.ctl_name, CONTROL_NAME, sizeof(ctl_info.ctl_name));

	if (ioctl(ctx.sock, CTLIOCGINFO, &ctl_info) != 0) {
		T_SKIP("Could not get id for kernel control %s", CONTROL_NAME);
	}

	ctx.sa.sc_id = ctl_info.ctl_id;
	T_LOG("Control ID: %d", ctl_info.ctl_id);

	T_ASSERT_POSIX_ZERO(pthread_create(&t, NULL, racer, &ctx), "pthread_create");

	T_LOG("Starting race test (1500 iterations)...");
	while (!ctx.finished && count <= 1500) {
		int result = try_connect(&ctx);

		usleep(1000);

		pthread_mutex_lock(&ctx.control_mtx);
		pthread_mutex_lock(&ctx.success_mtx);

		if (!ctx.finished) {
			ctx.success = 0;
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(close(ctx.sock), "close socket");
			ctx.sock = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
			T_QUIET;
			T_ASSERT_POSIX_SUCCESS(ctx.sock, "recreate socket");
		} else {
			T_LOG("Main thread final result: %d", result);
		}

		pthread_mutex_unlock(&ctx.success_mtx);
		pthread_mutex_unlock(&ctx.control_mtx);

		count++;
		if (count % 100 == 0) {
			T_LOG("Progress: %d iterations", count);
		}
	}

	T_LOG("Completed %d iterations", count);

	/* Signal racer thread to exit */
	ctx.finished = true;

	T_ASSERT_POSIX_ZERO(pthread_join(t, NULL), "pthread_join");

	pthread_mutex_destroy(&ctx.success_mtx);
	pthread_mutex_destroy(&ctx.control_mtx);

	close(ctx.sock);
	force_zone_gc();

	if (ctx.success > 1 && ctx.finished) {
		T_FAIL("Multiple successful connect()s detected (count = %d)", ctx.success);
	} else {
		T_PASS("test_connect_race completed without detecting race condition");
	}
}
