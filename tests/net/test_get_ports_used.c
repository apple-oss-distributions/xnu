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

#include <darwintest.h>

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(false)
	);

#define SYSCTL_GET_PORTS_USED "net.link.generic.system.get_ports_used"

/* Port range size in bytes (65536 ports / 8 bits per byte) */
#define IP_PORTRANGE_SIZE 65536
#define IP_PORTRANGE_BITFIELD_LEN ((IP_PORTRANGE_SIZE + 7) / 8)

/* Protocol families from sys/socket.h */
#define TEST_PF_UNSPEC  0
#define TEST_PF_INET    2
#define TEST_PF_INET6   30

/* Flags from net/kpi_interface.h */
#define IFNET_GET_LOCAL_PORTS_WILDCARDOK        0x01
#define IFNET_GET_LOCAL_PORTS_NOWAKEUPOK        0x02
#define IFNET_GET_LOCAL_PORTS_TCPONLY           0x04
#define IFNET_GET_LOCAL_PORTS_UDPONLY           0x08
#define IFNET_GET_LOCAL_PORTS_RECVANYIFONLY     0x10
#define IFNET_GET_LOCAL_PORTS_EXTBGIDLEONLY     0x20
#define IFNET_GET_LOCAL_PORTS_ACTIVEONLY        0x40
#define IFNET_GET_LOCAL_PORTS_ANYTCPSTATEOK     0x80

static const int test_protocols[] = {
	TEST_PF_UNSPEC,
	TEST_PF_INET,
	TEST_PF_INET6
};

static const uint32_t test_flags[] = {
	0,      /* no flags */
	IFNET_GET_LOCAL_PORTS_WILDCARDOK,
	IFNET_GET_LOCAL_PORTS_NOWAKEUPOK,
	IFNET_GET_LOCAL_PORTS_TCPONLY,
	IFNET_GET_LOCAL_PORTS_UDPONLY,
	IFNET_GET_LOCAL_PORTS_RECVANYIFONLY,
	IFNET_GET_LOCAL_PORTS_EXTBGIDLEONLY,
	IFNET_GET_LOCAL_PORTS_ACTIVEONLY,
	IFNET_GET_LOCAL_PORTS_ANYTCPSTATEOK,
	/* Test combinations */
	IFNET_GET_LOCAL_PORTS_WILDCARDOK | IFNET_GET_LOCAL_PORTS_TCPONLY,
	IFNET_GET_LOCAL_PORTS_WILDCARDOK | IFNET_GET_LOCAL_PORTS_UDPONLY,
	IFNET_GET_LOCAL_PORTS_NOWAKEUPOK | IFNET_GET_LOCAL_PORTS_ACTIVEONLY,
	IFNET_GET_LOCAL_PORTS_TCPONLY | IFNET_GET_LOCAL_PORTS_ANYTCPSTATEOK,
};

static const char *
protocol_to_string(int protocol)
{
	switch (protocol) {
	case TEST_PF_UNSPEC:
		return "PF_UNSPEC";
	case TEST_PF_INET:
		return "PF_INET";
	case TEST_PF_INET6:
		return "PF_INET6";
	default:
		return "UNKNOWN";
	}
}

static void
flags_to_string(uint32_t flags, char *buf, size_t buflen)
{
	int offset = 0;
	int ret;

	/* Array of flag-name pairs for data-driven flag checking */
	static const struct {
		uint32_t flag;
		const char *name;
	} flag_names[] = {
		{ IFNET_GET_LOCAL_PORTS_WILDCARDOK, "WILDCARDOK" },
		{ IFNET_GET_LOCAL_PORTS_NOWAKEUPOK, "NOWAKEUPOK" },
		{ IFNET_GET_LOCAL_PORTS_TCPONLY, "TCPONLY" },
		{ IFNET_GET_LOCAL_PORTS_UDPONLY, "UDPONLY" },
		{ IFNET_GET_LOCAL_PORTS_RECVANYIFONLY, "RECVANYIFONLY" },
		{ IFNET_GET_LOCAL_PORTS_EXTBGIDLEONLY, "EXTBGIDLEONLY" },
		{ IFNET_GET_LOCAL_PORTS_ACTIVEONLY, "ACTIVEONLY" },
		{ IFNET_GET_LOCAL_PORTS_ANYTCPSTATEOK, "ANYTCPSTATEOK" },
	};

	buf[0] = '\0';

	if (flags == 0) {
		snprintf(buf, buflen, "0");
		return;
	}

	/* Build flags string using data-driven loop */
	for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
		if (flags & flag_names[i].flag) {
			ret = snprintf(buf + offset, buflen - offset, "%s|", flag_names[i].name);
			if (ret > 0 && offset + ret < (int)buflen) {
				offset += ret;
			}
		}
	}

	/* Remove trailing '|' */
	if (offset > 0 && buf[offset - 1] == '|') {
		buf[offset - 1] = '\0';
	}
}

static void
print_set_ports(const uint8_t *bitfield, size_t bitfield_len)
{
	unsigned int count = 0;
	unsigned int first_port = 0;
	bool found_first = false;
	char ports_buf[512];
	int offset = 0;
	bool first_line = true;

	ports_buf[0] = '\0';

	/* Iterate through all bits (port numbers 0-65535) */
	for (unsigned int port = 0; port < IP_PORTRANGE_SIZE; port++) {
		unsigned int byte_index = port / 8;
		unsigned int bit_index = port % 8;

		if (byte_index >= bitfield_len) {
			break;
		}

		/* Check if this bit is set */
		if (bitfield[byte_index] & (1 << bit_index)) {
			count++;
			if (!found_first) {
				first_port = port;
				found_first = true;
			}

			/* Check if adding this port would overflow the buffer */
			int needed_space = snprintf(NULL, 0, "%s%u", (offset == 0) ? "" : ", ", port);

			if (offset + needed_space >= (int)sizeof(ports_buf) - 1) {
				/* Buffer is about to overflow - print current contents and reset */
				if (first_line) {
					T_LOG("    Ports: [%s,", ports_buf);
					first_line = false;
				} else {
					T_LOG("            %s,", ports_buf);
				}
				offset = 0;
				ports_buf[0] = '\0';
			}

			/* Add port to buffer */
			if (offset == 0) {
				offset += snprintf(ports_buf + offset, sizeof(ports_buf) - offset, "%u", port);
			} else {
				offset += snprintf(ports_buf + offset, sizeof(ports_buf) - offset, ", %u", port);
			}
		}
	}

	/* Print final results */
	if (count == 0) {
		T_LOG("    No ports in use");
	} else if (first_line) {
		/* All ports fit in one line */
		T_LOG("    %u port%s in use: [%s]", count, count == 1 ? "" : "s", ports_buf);
	} else {
		/* Multiple lines were printed, close the bracket */
		T_LOG("            %s]", ports_buf);
		T_LOG("    Total: %u ports in use (first=%u)", count, first_port);
	}
}

static int
call_get_ports_used_sysctl(unsigned int ifindex, int protocol, uint32_t flags, uint8_t *bitfield)
{
	int mib[6];
	size_t len = sizeof(mib) / sizeof(mib[0]);
	size_t bitfield_len = IP_PORTRANGE_BITFIELD_LEN;
	int ret;

	/* Get the MIB for the sysctl */
	ret = sysctlnametomib(SYSCTL_GET_PORTS_USED, mib, &len);
	if (ret != 0) {
		return ret;
	}

	/* Append the three parameters: ifindex, protocol, flags */
	mib[len++] = (int)ifindex;
	mib[len++] = protocol;
	mib[len++] = (int)flags;

	/* Call the sysctl */
	ret = sysctl(mib, (u_int)len, bitfield, &bitfield_len, NULL, 0);
	return ret;
}

T_DECL(get_ports_used_all_interfaces,
    "Test sysctl net.link.generic.system.get_ports_used on all interfaces with various protocols and flags")
{
	struct if_nameindex *if_list, *if_ptr;
	uint8_t *bitfield;
	int ret;
	unsigned int total_calls = 0;
	unsigned int successful_calls = 0;

	/* Enable verbose logging to exercise the logging code */
	int verbose = 1;
	size_t verbose_size = sizeof(verbose);
	ret = sysctlbyname("net.link.generic.system.port_used.verbose", NULL, NULL, &verbose, verbose_size);
	if (ret != 0) {
		T_LOG("Warning: Could not enable verbose logging (error %d: %s), continuing anyway",
		    errno, strerror(errno));
	} else {
		T_LOG("Enabled verbose logging for port_used");
	}

	/* Allocate buffer for bitfield */
	bitfield = malloc(IP_PORTRANGE_BITFIELD_LEN);
	T_QUIET; T_ASSERT_NOTNULL(bitfield, "malloc bitfield");

	/* Get list of network interfaces */
	if_list = if_nameindex();
	T_QUIET; T_ASSERT_NOTNULL(if_list, "if_nameindex");

	T_LOG("Testing sysctl on all network interfaces");

	/* Iterate through all interfaces */
	for (if_ptr = if_list; if_ptr->if_index != 0 && if_ptr->if_name != NULL; if_ptr++) {
		T_LOG("Interface: %s (index %u)", if_ptr->if_name, if_ptr->if_index);

		/* Test each protocol */
		for (size_t p = 0; p < sizeof(test_protocols) / sizeof(test_protocols[0]); p++) {
			int protocol = test_protocols[p];

			/* Test each flag combination */
			for (size_t f = 0; f < sizeof(test_flags) / sizeof(test_flags[0]); f++) {
				uint32_t flags = test_flags[f];
				char flags_str[256];

				flags_to_string(flags, flags_str, sizeof(flags_str));

				total_calls++;

				/* Call the sysctl */
				memset(bitfield, 0, IP_PORTRANGE_BITFIELD_LEN);
				ret = call_get_ports_used_sysctl(if_ptr->if_index, protocol, flags, bitfield);

				if (ret == 0) {
					successful_calls++;
					T_LOG("  %s with flags=%s: SUCCESS",
					    protocol_to_string(protocol), flags_str);
					print_set_ports(bitfield, IP_PORTRANGE_BITFIELD_LEN);
				} else {
					/* Some combinations may legitimately fail (e.g., ENOENT for down interfaces) */
					T_LOG("  %s with flags=%s: FAILED (error %d: %s)",
					    protocol_to_string(protocol), flags_str, errno, strerror(errno));
				}
			}
		}
	}

	if_freenameindex(if_list);
	free(bitfield);

	T_LOG("Total sysctl calls: %u, Successful: %u", total_calls, successful_calls);
	T_EXPECT_GT(successful_calls, 0U, "At least one sysctl call should succeed");

	/* Restore verbose setting to 0 */
	verbose = 0;
	sysctlbyname("net.link.generic.system.port_used.verbose", NULL, NULL, &verbose, verbose_size);
}
