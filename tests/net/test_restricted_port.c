/*
 * Copyright (c) 2019-2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <stdbool.h>
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
	T_META_OWNER("vlubet")
	);

struct test_case {
	int s_family;
	int s_type;
	int s_protocol;
	int s_fd;
};

struct test_case all_test_cases[] = {
	{
		.s_family = AF_INET,
		.s_type = SOCK_STREAM,
		.s_protocol = 0,
		.s_fd = -1,
	},
	{
		.s_family = AF_INET6,
		.s_type = SOCK_STREAM,
		.s_protocol = 0,
		.s_fd = -1,
	},
	{
		.s_family = AF_INET,
		.s_type = SOCK_DGRAM,
		.s_protocol = 0,
		.s_fd = -1,
	},
	{
		.s_family = AF_INET6,
		.s_type = SOCK_DGRAM,
		.s_protocol = 0,
		.s_fd = -1,
	},
	// Sentinel
	{
		.s_family = AF_UNSPEC,
		.s_type = 0,
		.s_protocol = 0,
		.s_fd = -1,
	}
};

enum {
	SYSTEM_PORT_RANGE,
	USER_PORT_RANGE,
	DYNAMIC_PORT_RANGE
};

static int saved_net_restricted_in_port_verbose = -1;
static bool has_entitlement = false;
static bool is_superuser = false;
static int ipport_firstauto = 49152;
static int ipport_lastauto = 65535;
static uint16_t test_ephemeral_portrange = 1024;

static const char *
get_port_range_str(int port_range)
{
	switch (port_range) {
	case SYSTEM_PORT_RANGE: return "System";
	case USER_PORT_RANGE: return "User";
	case DYNAMIC_PORT_RANGE: return "Dynamic";
	default: T_ASSERT_FAIL("unexpected port range %u", port_range);
	}
	return NULL;
}

static const char *
get_af_family_str(sa_family_t family)
{
	switch (family) {
	case AF_INET: return "AF_INET";
	case AF_INET6: return "AF_INET6";
	default: T_ASSERT_FAIL("unexpected family %u", family);
	}
	return NULL;
}

static const char *
get_sock_type_str(sa_family_t sock_type)
{
	switch (sock_type) {
	case SOCK_STREAM: return "SOCK_STREAM";
	case SOCK_DGRAM: return "SOCK_DGRAM";
	default: T_ASSERT_FAIL("unexpected sock type %u", sock_type);
	}
	return NULL;
}

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

static void
cleanup_sysctls(void)
{
	int val;

	val = 0;
	(void)sysctlbyname("net.restricted_port.test_entitlement", NULL, NULL, &val, sizeof(val));
	(void)sysctlbyname("net.restricted_port.test_superuser", NULL, NULL, &val, sizeof(val));

	val = 49152;
	if (sysctlbyname("net.inet.ip.portrange.first", NULL, NULL, &val, sizeof(val)) != 0) {
		T_LOG("sysctlbyname(net.inet.ip.portrange.first) failed");
	}
	val = 65535;
	if (sysctlbyname("net.inet.ip.portrange.last", NULL, NULL, &val, sizeof(val)) != 0) {
		T_LOG("sysctlbyname(net.inet.ip.portrange.last) failed");
	}
}

static void
cleanup_at_exit(void)
{
	int val = 0;

	if (saved_net_restricted_in_port_verbose != -1 &&
	    saved_net_restricted_in_port_verbose == 0) {
		(void)sysctlbyname("net.restricted_port.verbose", NULL, NULL, &val, sizeof(val));
	}
	(void)sysctlbyname("net.restricted_port.enforced", NULL, NULL, &val, sizeof(val));

	cleanup_sysctls();
}

static void
close_all_test_cases_fd(void)
{
	struct test_case *test_case;

	for (test_case = all_test_cases; test_case->s_family != AF_UNSPEC; test_case++) {
		if (test_case->s_fd != -1) {
			(void)close(test_case->s_fd);
			test_case->s_fd = -1;
		}
	}
}

static void
clean_up_test_cases(void)
{
	close_all_test_cases_fd();
	cleanup_sysctls();
}

static uint16_t
first_in_port_range(int port_range)
{
	switch (port_range) {
	case SYSTEM_PORT_RANGE:
		return 1;
	case USER_PORT_RANGE:
		return 1024;
	case DYNAMIC_PORT_RANGE:
		return ipport_firstauto != 0 ? ipport_firstauto : 49152;
	}
	T_ASSERT_FAIL("bad port range %d", port_range);
}

static uint16_t
last_in_port_range(int port_range)
{
	switch (port_range) {
	case SYSTEM_PORT_RANGE:
		return 1023;
	case USER_PORT_RANGE:
		return 49151;
	case DYNAMIC_PORT_RANGE:
		return ipport_lastauto != 0 ? ipport_lastauto : 65535;
	}
	T_ASSERT_FAIL("bad port range %d", port_range);
}

static uint16_t
find_available_port(int port_range, bool superuser_restricted_port, bool shrink_port_range)
{
	uint16_t test_port = 0;
	uint16_t first_port = first_in_port_range(port_range);
	uint16_t last_port = last_in_port_range(port_range);
	int first_port_offset = 0;

	T_LOG("port_range: %s first_port: %u last_port: %u",
	    get_port_range_str(port_range), first_port, last_port);

	first_port_offset = test_ephemeral_portrange *
	    (superuser_restricted_port + 2 * has_entitlement + 4 * is_superuser);
	if (first_port_offset + test_ephemeral_portrange >= UINT16_MAX) {
		first_port_offset = 0;
	}
	first_port += first_port_offset;
	last_port = first_port + test_ephemeral_portrange;

	T_QUIET; T_ASSERT_LT(first_port, last_port,
	    "first_port: %u >= last_port: %u for portrange: %s and first_port_offset: %u",
	    first_port, last_port, get_port_range_str(port_range), first_port_offset);

	T_LOG("first_port: %u last_port: %u for portrange: %s and first_port_offset: %u",
	    first_port, last_port, get_port_range_str(port_range), first_port_offset);

	if (port_range == DYNAMIC_PORT_RANGE && shrink_port_range) {
		size_t len;
		int port;

		len = sizeof(int);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			sysctlbyname("net.inet.ip.portrange.first", NULL, &len, NULL, 0),
			"get net.inet.ip.portrange.first");

		port = first_port;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			sysctlbyname("net.inet.ip.portrange.first", NULL, NULL, &port, sizeof(port)),
			"set net.inet.ip.portrange.first");

		len = sizeof(int);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			sysctlbyname("net.inet.ip.portrange.last", NULL, &len, NULL, 0),
			"get net.inet.ip.portrange.last");

		port = last_port;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			sysctlbyname("net.inet.ip.portrange.last", NULL, NULL, &port, sizeof(port)),
			"set net.inet.ip.portrange.last");

		ipport_firstauto = first_port;
		ipport_lastauto = last_port;
	}

	for (test_port = first_port + 1; test_port < last_port; test_port++) {
		int retval = -1;
		struct test_case *test_case;

		close_all_test_cases_fd();

		for (test_case = all_test_cases; test_case->s_family != AF_UNSPEC; test_case++) {
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_len = sizeof(struct sockaddr_in),
				.sin_port = 0,
				.sin_addr.s_addr = INADDR_ANY,
			};
			struct sockaddr_in6 sin6 = {
				.sin6_family = AF_INET6,
				.sin6_len = sizeof(struct sockaddr_in6),
				.sin6_port = 0,
				.sin6_addr = IN6ADDR_ANY_INIT,
			};

			struct sockaddr *sa;
			if (test_case->s_family == AF_INET) {
				sin.sin_port = htons(test_port);
				sa = (struct sockaddr *)&sin;
			} else if (test_case->s_family == AF_INET6) {
				sin6.sin6_port = htons(test_port);
				sa = (struct sockaddr *)&sin6;
			} else {
				T_ASSERT_FAIL("test case has unexpected family %u", test_case->s_family);
			}

			test_case->s_fd = socket(test_case->s_family, test_case->s_type, 0);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(test_case->s_fd, "socket() failed");

			retval = bind(test_case->s_fd, sa, sa->sa_len);
			if (retval != 0) {
				T_LOG("cannot bind port %u for socket(%s, %s, %d)",
				    test_port,
				    get_af_family_str(test_case->s_family),
				    get_sock_type_str(test_case->s_type),
				    test_case->s_protocol);
				break;
			}
			T_LOG("could bind port %u for socket(%s, %s, %d)",
			    test_port,
			    get_af_family_str(test_case->s_family),
			    get_sock_type_str(test_case->s_type),
			    test_case->s_protocol);
		}
		if (retval == 0) {
			T_LOG("found port %u is available for all test cases", test_port);
			break;
		}
	}
	if (test_port >= last_port) {
		T_LOG("could not find an available port for all socket types and address families");
		return 0;
	}
	return test_port;
}

static uint16_t
setup_test_cases(int port_range, bool superuser_restricted_port, bool shrink_port_range)
{
	uint16_t test_port;
	size_t len;

	test_port = find_available_port(port_range, superuser_restricted_port, shrink_port_range);
	if (test_port == 0) {
		return 0;
	}

	len = sizeof(saved_net_restricted_in_port_verbose);
	if (sysctlbyname("net.restricted_port.verbose",
	    &saved_net_restricted_in_port_verbose, &len, NULL, 0) != 0) {
		if (errno == ENOENT) {
			T_LOG("sysctlbyname(net.restricted_port.verbose) not available");
			return 0;
		}
		T_ASSERT_POSIX_SUCCESS(-1, "sysctlbyname(net.restricted_port.verbose)");
	}

	int verbose = 1;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(
		sysctlbyname("net.restricted_port.verbose", NULL, NULL, &verbose, sizeof(verbose)),
		"set net.restricted_port.verbose");

	int enforced = 1;
	if (sysctlbyname("net.restricted_port.enforced", NULL, NULL, &enforced, sizeof(enforced)) != 0) {
		if (errno == ENOENT) {
			T_LOG("sysctlbyname(net.restricted_port.enforced) not available");
			return 0;
		}
		T_ASSERT_POSIX_SUCCESS(-1, "sysctlbyname(net.restricted_port.enforced)");
	}

	const char *name = superuser_restricted_port ? "net.restricted_port.test_superuser" :
	    "net.restricted_port.test_entitlement";
	int val = test_port;
	if (sysctlbyname(name, NULL, NULL, &val, sizeof(val)) != 0) {
		if (errno == ENOENT) {
			T_LOG("sysctlbyname(%s) not available", name);
			return 0;
		}
		T_ASSERT_POSIX_SUCCESS(-1, "sysctlbyname(%s)", name);
	}

	close_all_test_cases_fd();

	T_LOG("registered test port %u as %s restricted in %s range", test_port,
	    superuser_restricted_port ? "superuser" : "entitlement",
	    get_port_range_str(port_range));

	return test_port;
}

static void
test_bind_static_port(bool superuser_restricted_port)
{
	uint16_t test_port;
	struct test_case *test_case;
	int test_pass_count = 0;
	int test_fail_count = 0;

	T_LOG("TEST BIND KNOWN PORT: process that %s superuser and that %s have the required entitlement",
	    is_superuser ? "is" : "is not",
	    has_entitlement ? "does" : "does not");

	test_port = setup_test_cases(USER_PORT_RANGE, superuser_restricted_port, false);

	if (test_port == 0) {
		T_SKIP("could not find an available port");
	}

	for (test_case = all_test_cases; test_case->s_family != AF_UNSPEC; test_case++) {
		T_LOG("TEST CASE: port %u is %s restricted, process has entitlement: %s, is superuser: %s, socket(%s, %s, %d)",
		    test_port,
		    superuser_restricted_port ? "superuser" : "entitlement",
		    has_entitlement ? "true" : "false",
		    is_superuser ? "true" : "false",
		    get_af_family_str(test_case->s_family),
		    get_sock_type_str(test_case->s_type),
		    test_case->s_protocol);

		struct sockaddr_in sin = {
			.sin_family = AF_INET,
			.sin_len = sizeof(struct sockaddr_in),
			.sin_port = 0,
			.sin_addr.s_addr = INADDR_ANY,
		};
		struct sockaddr_in6 sin6 = {
			.sin6_family = AF_INET6,
			.sin6_len = sizeof(struct sockaddr_in6),
			.sin6_port = 0,
			.sin6_addr = IN6ADDR_ANY_INIT,
		};
		struct sockaddr *sa;
		if (test_case->s_family == AF_INET) {
			sin.sin_port = htons(test_port);
			sa = (struct sockaddr *)&sin;
		} else if (test_case->s_family == AF_INET6) {
			sin6.sin6_port = htons(test_port);
			sa = (struct sockaddr *)&sin6;
		} else {
			T_ASSERT_FAIL("test case has unexpected family %u", test_case->s_family);
		}

		test_case->s_fd = socket(test_case->s_family, test_case->s_type, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(test_case->s_fd, "socket() failed");

		int retval;
		retval = bind(test_case->s_fd, sa, sa->sa_len);
		if (superuser_restricted_port) {
			if (retval == 0) {
				if (is_superuser) {
					T_LOG("TEST CASE PASSED: expected bind() success");
					test_pass_count++;
				} else {
					T_LOG("TEST CASE FAILED: unexpected bind() success");
					test_fail_count++;
				}
			} else {
				if (is_superuser || errno != EADDRINUSE) {
					T_LOG("TEST CASE FAILED: unexpected bind() failure: %s", strerror(errno));
					test_fail_count++;
				} else {
					T_LOG("TEST CASE PASSED: expected bind() failure");
					test_pass_count++;
				}
			}
		} else {
			if (retval == 0) {
				if (has_entitlement) {
					T_LOG("TEST CASE PASSED: expected bind() success");
					test_pass_count++;
				} else {
					T_LOG("TEST CASE FAILED: unexpected bind() success");
					test_fail_count++;
				}
			} else {
				if (has_entitlement || errno != EADDRINUSE) {
					T_LOG("TEST CASE FAILED: unexpected bind() failure: %s", strerror(errno));
					test_fail_count++;
				} else {
					T_LOG("TEST CASE PASSED: expected bind() failure");
					test_pass_count++;
				}
			}
		}

		close(test_case->s_fd);
		test_case->s_fd = -1;
	}
	clean_up_test_cases();

	T_ASSERT_EQ(test_fail_count, 0, "all static port tests should pass");
}

static void
bind_ephemeral_port_loop(bool superuser_restricted_port, uint16_t test_port)
{
	struct test_case *test_case;

	for (test_case = all_test_cases; test_case->s_family != AF_UNSPEC; test_case++) {
		uint32_t numports = 0;
		uint32_t port_range = last_in_port_range(DYNAMIC_PORT_RANGE) - first_in_port_range(DYNAMIC_PORT_RANGE) + 1;
		bool bound_to_restricted_port = false;

		T_LOG("TEST CASE: ephemeral bind(), port %u is %s restricted, process has entitlement: %s, is superuser: %s, socket(%s, %s, %d), port range: %u",
		    test_port,
		    superuser_restricted_port ? "superuser" : "entitlement",
		    has_entitlement ? "true" : "false",
		    is_superuser ? "true" : "false",
		    get_af_family_str(test_case->s_family),
		    get_sock_type_str(test_case->s_type),
		    test_case->s_protocol,
		    port_range);

		for (numports = 0; numports <= port_range; numports++) {
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_len = sizeof(struct sockaddr_in),
				.sin_port = 0,
				.sin_addr.s_addr = INADDR_ANY,
			};
			struct sockaddr_in6 sin6 = {
				.sin6_family = AF_INET6,
				.sin6_len = sizeof(struct sockaddr_in6),
				.sin6_port = 0,
				.sin6_addr = IN6ADDR_ANY_INIT,
			};

			struct sockaddr *sa;
			if (test_case->s_family == AF_INET) {
				sa = (struct sockaddr *)&sin;
			} else if (test_case->s_family == AF_INET6) {
				sa = (struct sockaddr *)&sin6;
			} else {
				T_ASSERT_FAIL("test case has unexpected family %u", test_case->s_family);
			}

			int fd = socket(test_case->s_family, test_case->s_type, 0);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(fd, "socket() failed");

			int retval = bind(fd, sa, sa->sa_len);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(retval, "bind() failed");

			socklen_t socklen = sa->sa_len;
			retval = getsockname(fd, sa, &socklen);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(retval, "getsockname() failed");

			close(fd);

			uint16_t port;
			if (sa->sa_family == AF_INET) {
				port = ntohs(sin.sin_port);
			} else if (sa->sa_family == AF_INET6) {
				port = ntohs(sin6.sin6_port);
			} else {
				T_ASSERT_FAIL("bound to unexpected family %u", sa->sa_family);
			}

			if (port == test_port) {
				T_LOG("TEST CASE FAILED: could bind to restricted ephemeral port %u", test_port);
				bound_to_restricted_port = true;
				break;
			}
		}

		if (bound_to_restricted_port) {
			T_ASSERT_FAIL("bound to restricted ephemeral port %u", test_port);
		} else {
			T_PASS("could not bind to restricted ephemeral port %u after %u attempts", test_port, numports);
		}
	}
}

static void
test_bind_dynamic_port(bool superuser_restricted_port)
{
	uint16_t test_port;

	T_LOG("TEST BIND EPHEMERAL: process that %s superuser and that %s have the required entitlement",
	    is_superuser ? "is" : "is not",
	    has_entitlement ? "does" : "does not");

	test_port = setup_test_cases(DYNAMIC_PORT_RANGE, superuser_restricted_port, true);
	if (test_port == 0) {
		T_SKIP("could not find an available port");
	}

	bind_ephemeral_port_loop(superuser_restricted_port, test_port);

	clean_up_test_cases();
}

static bool
has_sysctl_restricted_port_test(void)
{
	int val;
	size_t len = sizeof(val);

	if (sysctlbyname("net.restricted_port.test_superuser", &val, &len, NULL, 0) != 0) {
		T_LOG("sysctlbyname(net.restricted_port.test_superuser) not available");
		return false;
	}
	if (sysctlbyname("net.restricted_port.test_entitlement", &val, &len, NULL, 0) != 0) {
		T_LOG("sysctlbyname(net.restricted_port.test_entitlement) not available");
		return false;
	}
	return true;
}

static void
run_tests(void)
{
	const char *progname = getprogname();
	if (progname == NULL) {
		T_ASSERT_FAIL("getprogname() returned NULL");
	}

	T_ATEND(cleanup_at_exit);

	if (!has_sysctl_restricted_port_test()) {
		T_SKIP("restricted port test sysctls not available (requires DEBUG or DEVELOPMENT kernel)");
	}

	if (strstr(progname, "entitled") != NULL) {
		has_entitlement = true;
	} else {
		has_entitlement = false;
	}
	if (getuid() == 0) {
		is_superuser = true;
	}

	T_LOG("Running as: %s %s",
	    is_superuser ? "superuser" : "non-superuser",
	    has_entitlement ? "entitled" : "non-entitled");

	test_bind_dynamic_port(false);
	test_bind_dynamic_port(true);

	test_bind_static_port(false);
	test_bind_static_port(true);

	force_zone_gc();
}

T_DECL(test_restricted_port_root,
    "test restricted port from a process running as root without entitlement",
    T_META_ASROOT(true),
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(600))
{
	run_tests();
}

T_DECL(test_restricted_port_nonroot,
    "test restricted port from a process not running as root without entitlement",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false),
    T_META_TIMEOUT(600))
{
	run_tests();
}
