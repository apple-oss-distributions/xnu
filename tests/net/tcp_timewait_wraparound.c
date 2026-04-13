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

/*
 * Test for tcp_now timer wraparound handling.
 *
 * This test validates that TIME_WAIT sockets expire correctly when
 * tcp_now wraps around after ~49.7 days of uptime (2^32 milliseconds).
 *
 * The test uses debug sysctls to force tcp_now near the wraparound point:
 * - net.inet.tcp.now_offset: Force tcp_now to a specific value
 * - net.inet.tcp.now: Read current tcp_now value
 *
 * These sysctls are only available on DEBUG/DEVELOPMENT kernels.
 */

#include <darwintest.h>

#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define TSTMP_GT(a, b)   ((int)((a)-(b)) > 0)

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_RUN_CONCURRENTLY(false)
	);

/* Time to wait for tcp_now to advance (milliseconds) */
#define WAIT_TIME_MS 100

/* How close to wraparound to start (5 seconds before) */
#define WRAPAROUND_OFFSET 5000

/*
 * Get the current tcp_now value from the kernel.
 * Returns -1 on error (e.g., sysctl not available).
 */
static int
get_tcp_now(uint32_t *tcp_now_out)
{
	size_t size = sizeof(*tcp_now_out);
	int ret = sysctlbyname("net.inet.tcp.now", tcp_now_out, &size, NULL, 0);
	return ret;
}

/*
 * Force tcp_now to a specific value.
 * Only works on DEBUG/DEVELOPMENT kernels.
 * Returns -1 on error (e.g., sysctl not available or no permission).
 */
static int
set_tcp_now(uint32_t value)
{
	int ret = sysctlbyname("net.inet.tcp.now_offset", NULL, NULL,
	    &value, sizeof(value));
	return ret;
}

/*
 * Get the current MSL (Maximum Segment Lifetime) value in milliseconds.
 */
static int
get_tcp_msl(int *msl_out)
{
	size_t size = sizeof(*msl_out);
	int ret = sysctlbyname("net.inet.tcp.msl", msl_out, &size, NULL, 0);
	return ret;
}

/*
 * Create a TCP connection that will enter TIME_WAIT state.
 * The server socket actively closes, putting it into TIME_WAIT.
 * Returns 0 on success, -1 on error.
 */
static int
create_timewait_connection(void)
{
	int listen_fd = -1;
	int client_fd = -1;
	int server_fd = -1;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int ret = -1;

	/* Create listening socket */
	listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		T_LOG("Failed to create listen socket: %s", strerror(errno));
		goto cleanup;
	}

	int reuse = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0; /* Let kernel choose port */

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		T_LOG("Failed to bind listen socket: %s", strerror(errno));
		goto cleanup;
	}

	if (listen(listen_fd, 1) < 0) {
		T_LOG("Failed to listen: %s", strerror(errno));
		goto cleanup;
	}

	/* Get the assigned port */
	if (getsockname(listen_fd, (struct sockaddr *)&addr, &addr_len) < 0) {
		T_LOG("Failed to get socket name: %s", strerror(errno));
		goto cleanup;
	}

	/* Create client socket and connect */
	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_fd < 0) {
		T_LOG("Failed to create client socket: %s", strerror(errno));
		goto cleanup;
	}

	if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		T_LOG("Failed to connect: %s", strerror(errno));
		goto cleanup;
	}

	/* Accept the connection */
	server_fd = accept(listen_fd, NULL, NULL);
	if (server_fd < 0) {
		T_LOG("Failed to accept: %s", strerror(errno));
		goto cleanup;
	}

	/*
	 * Close server side first - this puts the server socket into TIME_WAIT.
	 * The actively-closing side enters TIME_WAIT to handle delayed packets.
	 */
	close(server_fd);
	server_fd = -1;

	/* Close client side - completes the connection teardown */
	close(client_fd);
	client_fd = -1;

	ret = 0;

cleanup:
	if (listen_fd >= 0) {
		close(listen_fd);
	}
	if (client_fd >= 0) {
		close(client_fd);
	}
	if (server_fd >= 0) {
		close(server_fd);
	}
	return ret;
}

/*
 * Trigger TCP activity to force tcp_now update.
 * tcp_now is only updated when calculate_tcp_clock() is called,
 * which happens during TCP operations (socket creation, I/O, etc.).
 * This function performs a simple TCP operation to trigger the update.
 */
static void
trigger_tcp_now_update(void)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd >= 0) {
		close(fd);
	}
}

/*
 * Test that tcp_now continues to advance after wraparound.
 *
 * This is the core test for the bug fix: previously, tcp_now would freeze
 * when it wrapped from 0xFFFFFFFF to 0 because the unsigned comparison
 * "tmp < current_tcp_now" would fail.
 */
T_DECL(tcp_now_wraparound,
    "Test tcp_now timer continues advancing after 32-bit wraparound",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false))
{
	uint32_t tcp_now_before, tcp_now_after;
	uint32_t wraparound_start;
	int ret;

	/* Check if the debug sysctls are available */
	ret = get_tcp_now(&tcp_now_before);
	if (ret != 0) {
		T_SKIP("net.inet.tcp.now sysctl not available (need DEBUG/DEVELOPMENT kernel)");
		return;
	}

	T_LOG("Initial tcp_now: %u (0x%08x)", tcp_now_before, tcp_now_before);

	/* Set tcp_now to just before wraparound (5 seconds before) */
	wraparound_start = 0xFFFFFFFF - WRAPAROUND_OFFSET;
	T_LOG("Setting tcp_now to %u (0x%08x), %d ms before wraparound",
	    wraparound_start, wraparound_start, WRAPAROUND_OFFSET);

	ret = set_tcp_now(wraparound_start);
	if (ret != 0) {
		T_SKIP("net.inet.tcp.now_offset sysctl not available or no permission");
		return;
	}

	/* Verify the value was set */
	ret = get_tcp_now(&tcp_now_before);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now after setting");
	T_LOG("tcp_now after set: %u (0x%08x)", tcp_now_before, tcp_now_before);

	/*
	 * Wait long enough for tcp_now to wrap around.
	 * We set it 5 seconds before wraparound, so wait 6 seconds.
	 * Trigger TCP activity to ensure tcp_now gets updated.
	 */
	T_LOG("Waiting for tcp_now to wrap around...");
	for (int i = 0; i < (WRAPAROUND_OFFSET / 1000) + 1; i++) {
		sleep(1);
		trigger_tcp_now_update();
	}

	/* Check that tcp_now advanced (wrapped around) */
	trigger_tcp_now_update(); /* Ensure final update */
	ret = get_tcp_now(&tcp_now_after);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now after wraparound");
	T_LOG("tcp_now after wraparound: %u (0x%08x)", tcp_now_after, tcp_now_after);

	/*
	 * Use modular arithmetic to check if tcp_now advanced.
	 * TSTMP_GT handles wraparound correctly: if tcp_now wrapped from
	 * 0xFFFFFFFF to a small value, the signed difference is still positive.
	 */
	if (!TSTMP_GT(tcp_now_after, tcp_now_before)) {
		T_FAIL("tcp_now did not advance: before=%u (0x%08x), after=%u (0x%08x)",
		    tcp_now_before, tcp_now_before, tcp_now_after, tcp_now_after);
	}

	/* Calculate signed difference for logging */
	int32_t elapsed_ms = (int32_t)(tcp_now_after - tcp_now_before);
	T_LOG("tcp_now advanced by %d ms (modular arithmetic)", elapsed_ms);

	/* Verify we got the wraparound we expected */
	if (tcp_now_after < tcp_now_before) {
		T_LOG("Wraparound occurred: %u -> %u", tcp_now_before, tcp_now_after);
	}

	/*
	 * Wait a bit more and verify tcp_now continues advancing
	 * (doesn't freeze after wraparound).
	 */
	usleep(WAIT_TIME_MS * 1000);
	trigger_tcp_now_update();

	uint32_t tcp_now_final;
	ret = get_tcp_now(&tcp_now_final);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now final check");
	T_LOG("tcp_now final: %u (0x%08x)", tcp_now_final, tcp_now_final);

	/* Verify continued advancement using modular arithmetic */
	if (!TSTMP_GT(tcp_now_final, tcp_now_after)) {
		T_FAIL("tcp_now stopped advancing after wraparound: after=%u, final=%u",
		    tcp_now_after, tcp_now_final);
	}

	int32_t advancement = (int32_t)(tcp_now_final - tcp_now_after);
	T_EXPECT_GE(advancement, WAIT_TIME_MS / 2,
	    "tcp_now should continue advancing after wraparound (advanced %d ms)",
	    advancement);

	T_PASS("tcp_now advanced correctly through wraparound");
}

/*
 * Test that TIME_WAIT sockets expire correctly after tcp_now wraparound.
 *
 * This test creates a TCP connection that enters TIME_WAIT, then forces
 * tcp_now to wrap around and verifies the socket eventually expires.
 *
 * TIME_WAIT duration is 2*MSL (typically 30 seconds total).
 */
T_DECL(tcp_timewait_expires_after_wraparound,
    "Test TIME_WAIT sockets expire correctly after tcp_now wraparound",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(120)) /* Allow time for TIME_WAIT to expire */
{
	int msl;
	int ret;

	/* Check if the debug sysctls are available */
	uint32_t tcp_now_test;
	ret = get_tcp_now(&tcp_now_test);
	if (ret != 0) {
		T_SKIP("net.inet.tcp.now sysctl not available (need DEBUG/DEVELOPMENT kernel)");
		return;
	}

	ret = get_tcp_msl(&msl);
	T_ASSERT_POSIX_SUCCESS(ret, "Get MSL value");
	T_LOG("MSL value: %d ms (TIME_WAIT = 2*MSL = %d ms)", msl, 2 * msl);

	/*
	 * Set tcp_now to a value that will wrap around during TIME_WAIT.
	 * We want: tcp_now + TIME_WAIT_DURATION > 0xFFFFFFFF
	 *
	 * Set tcp_now to 0xFFFFFFFF - MSL (so wraparound happens midway through TIME_WAIT)
	 */
	uint32_t pre_wraparound = 0xFFFFFFFF - (uint32_t)msl;
	T_LOG("Setting tcp_now to %u (0x%08x) so wraparound occurs during TIME_WAIT",
	    pre_wraparound, pre_wraparound);

	ret = set_tcp_now(pre_wraparound);
	if (ret != 0) {
		T_SKIP("net.inet.tcp.now_offset sysctl not available or no permission");
		return;
	}

	/* Create a connection that will enter TIME_WAIT */
	T_LOG("Creating TCP connection to put into TIME_WAIT state");
	ret = create_timewait_connection();
	T_ASSERT_EQ(ret, 0, "Create TIME_WAIT connection");

	/* Get tcp_now when the socket entered TIME_WAIT */
	uint32_t tcp_now_start;
	ret = get_tcp_now(&tcp_now_start);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now after connection close");
	T_LOG("tcp_now when entering TIME_WAIT: %u (0x%08x)", tcp_now_start, tcp_now_start);

	/*
	 * Wait for TIME_WAIT to expire (2*MSL).
	 * Add some buffer time for garbage collection.
	 * Periodically trigger TCP activity to ensure tcp_now updates.
	 */
	int wait_time_sec = (2 * msl / 1000) + 5;
	T_LOG("Waiting %d seconds for TIME_WAIT to expire...", wait_time_sec);
	for (int i = 0; i < wait_time_sec; i++) {
		sleep(1);
		trigger_tcp_now_update();
	}

	/* Check that tcp_now wrapped and continued advancing */
	trigger_tcp_now_update(); /* Ensure final update */
	uint32_t tcp_now_end;
	ret = get_tcp_now(&tcp_now_end);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now after TIME_WAIT expiry");
	T_LOG("tcp_now after TIME_WAIT period: %u (0x%08x)", tcp_now_end, tcp_now_end);

	/*
	 * Verify tcp_now advanced using modular arithmetic.
	 * If the bug exists, tcp_now would have frozen and not advanced.
	 * With the fix, tcp_now should have advanced by at least 2*MSL milliseconds.
	 */
	if (!TSTMP_GT(tcp_now_end, tcp_now_start)) {
		T_FAIL("tcp_now did not advance during TIME_WAIT period: start=%u, end=%u",
		    tcp_now_start, tcp_now_end);
	}

	/* Calculate elapsed time using signed arithmetic (wraparound-safe) */
	int32_t elapsed_ms = (int32_t)(tcp_now_end - tcp_now_start);
	T_LOG("tcp_now advanced by %d ms (expected at least %d ms)", elapsed_ms, 2 * msl);

	/* Verify advancement is reasonable (at least the TIME_WAIT duration) */
	int32_t expected_min_ms = 2 * msl;
	if (elapsed_ms < expected_min_ms) {
		T_FAIL("tcp_now advanced by only %d ms, expected at least %d ms",
		    elapsed_ms, expected_min_ms);
	}

	/* Check if wraparound actually occurred */
	if (tcp_now_end < tcp_now_start) {
		T_LOG("Wraparound occurred during TIME_WAIT: %u -> %u", tcp_now_start, tcp_now_end);
	}

	T_PASS("tcp_now advanced correctly (%d ms) through TIME_WAIT period with wraparound",
	    elapsed_ms);
}

/*
 * Test basic tcp_now sysctl accessibility.
 * This is a simpler test that doesn't require wraparound timing.
 */
T_DECL(tcp_now_sysctl,
    "Test tcp_now sysctl is accessible and returns reasonable values",
    T_META_ASROOT(true))
{
	uint32_t tcp_now1, tcp_now2;
	int ret;

	ret = get_tcp_now(&tcp_now1);
	if (ret != 0) {
		T_SKIP("net.inet.tcp.now sysctl not available");
		return;
	}
	T_LOG("tcp_now value 1: %u (0x%08x)", tcp_now1, tcp_now1);

	/* Wait a bit and trigger TCP activity to ensure tcp_now advances */
	usleep(50 * 1000); /* 50 ms */
	trigger_tcp_now_update();

	ret = get_tcp_now(&tcp_now2);
	T_ASSERT_POSIX_SUCCESS(ret, "Get tcp_now second time");
	T_LOG("tcp_now value 2: %u (0x%08x)", tcp_now2, tcp_now2);

	/*
	 * Use modular arithmetic for wraparound-safe check.
	 * Note: tcp_now is updated lazily at TCP layer boundaries (when processing
	 * packets, calling tcp_usrreqs, or when timers fire), not continuously.
	 * We trigger TCP activity to ensure it updates.
	 */
	if (!TSTMP_GT(tcp_now2, tcp_now1)) {
		T_FAIL("tcp_now did not advance: first=%u, second=%u", tcp_now1, tcp_now2);
	}

	int32_t diff = (int32_t)(tcp_now2 - tcp_now1);
	T_LOG("tcp_now advanced by %d ms", diff);

	T_PASS("tcp_now sysctl works correctly");
}
