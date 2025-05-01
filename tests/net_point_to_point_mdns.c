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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <net/if_utun.h>
#include <net/if_ipsec.h>

#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("dlil"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_ASROOT(true));

T_DECL(point_to_point_mdn_utun,
    "Point-to-point mDNS on utun interface", T_META_TAG_VM_PREFERRED)
{
	int udp_fd;
	int tun_fd;
	struct ctl_info kernctl_info = { 0 };
	struct sockaddr_ctl kernctl_addr = { 0 };
	char ifname[IFXNAMSIZ];
	socklen_t optlen;
	struct ifreq ifr = { 0 };

	T_QUIET; T_EXPECT_POSIX_SUCCESS(udp_fd = socket(AF_INET, SOCK_DGRAM, 0), NULL);

	T_ASSERT_POSIX_SUCCESS(tun_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	strlcpy(kernctl_info.ctl_name, UTUN_CONTROL_NAME, sizeof(kernctl_info.ctl_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(tun_fd, CTLIOCGINFO, &kernctl_info), NULL);

	kernctl_addr.sc_len = sizeof(kernctl_addr);
	kernctl_addr.sc_family = AF_SYSTEM;
	kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
	kernctl_addr.sc_id = kernctl_info.ctl_id;
	kernctl_addr.sc_unit = 0;

	T_ASSERT_POSIX_SUCCESS(bind(tun_fd, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_ASSERT_POSIX_SUCCESS(connect(tun_fd, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	optlen = sizeof(ifname);
	T_ASSERT_POSIX_SUCCESS(getsockopt(tun_fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &optlen), NULL);
	T_LOG("utun interface: %s", ifname);

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCGPOINTOPOINTMDNS, &ifr), NULL);
	T_ASSERT_EQ_INT(ifr.ifr_point_to_point_mdns, 0, "point_to_point_mdns off by default");

	ifr.ifr_point_to_point_mdns = 1;
	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCSPOINTOPOINTMDNS, &ifr), NULL);
	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCGPOINTOPOINTMDNS, &ifr), NULL);
	T_ASSERT_EQ_INT(ifr.ifr_point_to_point_mdns, 1, "point_to_point_mdns turned on");

	ifr.ifr_point_to_point_mdns = 0;
	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCSPOINTOPOINTMDNS, &ifr), NULL);
	T_ASSERT_POSIX_SUCCESS(ioctl(udp_fd, SIOCGPOINTOPOINTMDNS, &ifr), NULL);
	T_ASSERT_EQ_INT(ifr.ifr_point_to_point_mdns, 0, "point_to_point_mdns turned off");

	T_ASSERT_POSIX_SUCCESS(close(tun_fd), NULL);
	T_ASSERT_POSIX_SUCCESS(close(udp_fd), NULL);
}
