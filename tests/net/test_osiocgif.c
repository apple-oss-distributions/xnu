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
 * - verify that the deprecated OSIOCGIFADDR, OSIOCGIFDSTADDR,
 *   OSIOCGIFBRDADDR, and OSIOCGIFNETMASK ioctls work correctly using
 *   a pair of feth interfaces
 */

#include <stdio.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <TargetConditionals.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#include "net_test_lib.h"

/*
 * OSIOCGIF* ioctls are defined in <sys/sockio_private.h> under KERNEL_PRIVATE.
 * Define them here for userspace testing.
 */
#define OSIOCGIFADDR    _IOWR('i', 13, struct ifreq)
#define OSIOCGIFDSTADDR _IOWR('i', 15, struct ifreq)
#define OSIOCGIFBRDADDR _IOWR('i', 18, struct ifreq)
#define OSIOCGIFNETMASK _IOWR('i', 21, struct ifreq)

struct old_sockaddr {
	uint16_t        sa_family;
	char            sa_data[14];
};

T_GLOBAL_META(T_META_NAMESPACE("xnu.net"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("networking"),
    T_META_ASROOT(true));

static char S_feth1[IF_NAMESIZE];
static char S_feth2[IF_NAMESIZE];

static struct in_addr  addr1;
static struct in_addr  addr2;
static struct in_addr  mask;

static void
test_cleanup(void)
{
	if (S_feth1[0] != '\0') {
		(void)ifnet_destroy(S_feth1, false);
		T_LOG("ifnet_destroy %s", S_feth1);
	}
	if (S_feth2[0] != '\0') {
		(void)ifnet_destroy(S_feth2, false);
		T_LOG("ifnet_destroy %s", S_feth2);
	}
}

static void
sigint_cleanup(__unused int sig)
{
	signal(SIGINT, SIG_DFL);
	test_cleanup();
}

static void
test_setup_common(void)
{
	int             error;

	signal(SIGINT, sigint_cleanup);
	T_ATEND(test_cleanup);

	T_ASSERT_EQ(offsetof(struct old_sockaddr, sa_data),
	    offsetof(struct sockaddr, sa_data), "sa_data offset matches");

	/* create a pair of feth interfaces */
	strlcpy(S_feth1, FETH_NAME, sizeof(S_feth1));
	error = ifnet_create_2(S_feth1, sizeof(S_feth1));
	if (error != 0) {
		S_feth1[0] = '\0';
		T_ASSERT_POSIX_SUCCESS(error, "ifnet_create_2 %s", FETH_NAME);
	}
	T_LOG("created %s", S_feth1);

	strlcpy(S_feth2, FETH_NAME, sizeof(S_feth2));
	error = ifnet_create_2(S_feth2, sizeof(S_feth2));
	if (error != 0) {
		S_feth2[0] = '\0';
		T_ASSERT_POSIX_SUCCESS(error, "ifnet_create_2 %s", FETH_NAME);
	}
	T_LOG("created %s", S_feth2);

	/* peer them together */
	fake_set_peer(S_feth1, S_feth2);

	/* assign IPv4 addresses */
	addr1.s_addr = htonl(IN_LINKLOCALNETNUM + 1);   /* 169.254.0.1 */
	addr2.s_addr = htonl(IN_LINKLOCALNETNUM + 2);   /* 169.254.0.2 */
	mask.s_addr = htonl(IN_CLASSB_NET);

	ifnet_add_ip_address(S_feth1, addr1, mask);
	T_LOG("assigned %s to %s", inet_ntoa(addr1), S_feth1);

	ifnet_add_ip_address(S_feth2, addr2, mask);
	T_LOG("assigned %s to %s", inet_ntoa(addr2), S_feth2);
}

static void
test_osiocgifaddr(void)
{
	struct ifreq    ifr = { 0 };
	struct ifreq    ifr2 = { 0 };
	int             s;
	struct old_sockaddr *osa;
	struct sockaddr_in *sin1;
	struct sockaddr_in *sin2;

	test_setup_common();

	s = inet_dgram_socket_get();

	/* verify OSIOCGIFADDR on S_feth1 */
	strlcpy(ifr.ifr_name, S_feth1, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, OSIOCGIFADDR, &ifr),
	    "OSIOCGIFADDR %s", S_feth1);

	/* old socket address does not have a length */
	osa = (struct old_sockaddr *)(void *)&ifr.ifr_addr;
	T_ASSERT_EQ(osa->sa_family, AF_INET,
	    "%s OSIOCGIFADDR address family", S_feth1);
	sin1 = (struct sockaddr_in *)(void *)&ifr.ifr_addr;
	T_ASSERT_EQ(sin1->sin_addr.s_addr, addr1.s_addr,
	    "%s OSIOCGIFADDR address %s", S_feth1, inet_ntoa(sin1->sin_addr));

	/* verify SIOCGIFADDR returns the same value */
	strlcpy(ifr2.ifr_name, S_feth1, sizeof(ifr2.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFADDR, &ifr2),
	    "SIOCGIFADDR %s", S_feth1);
	sin2 = (struct sockaddr_in *)(void *)&ifr2.ifr_addr;
	T_ASSERT_EQ_ULONG((unsigned long)sin2->sin_len, sizeof(struct sockaddr_in),
	    "%s SIOCGIFADDR address family", S_feth1);
	T_ASSERT_EQ(sin2->sin_family, AF_INET,
	    "%s SIOCGIFADDR address family", S_feth1);
	T_ASSERT_EQ(
		sin1->sin_addr.s_addr, sin2->sin_addr.s_addr,
		"%s OSIOCGIFADDR == SIOCGIFADDR", S_feth1);

	T_PASS("OSIOCGIFADDR returned correct addresses matching SIOCGIFADDR");
}

T_DECL(osiocgifaddr,
    "Verify deprecated OSIOCGIFADDR ioctl returns correct interface address",
    T_META_ASROOT(true), T_META_TAG_VM_PREFERRED)
{
	test_osiocgifaddr();
}

static void
test_osiocgifdstaddr(void)
{
	struct ifreq    ifr = { 0 };
	struct ifreq    ifr2 = { 0 };
	int             s;

	test_setup_common();

	s = inet_dgram_socket_get();

	/*
	 * OSIOCGIFDSTADDR requires IFF_POINTOPOINT (checked in
	 * inctl_ifdstaddr).  feth interfaces are not point-to-point,
	 * so the ioctl must return EINVAL.
	 */
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, S_feth1, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_FAILURE(ioctl(s, OSIOCGIFDSTADDR, &ifr), EINVAL,
	    "OSIOCGIFDSTADDR %s returns EINVAL (not point-to-point)", S_feth1);

	/* verify SIOCGIFDSTADDR returns the same error */
	bzero(&ifr2, sizeof(ifr2));
	strlcpy(ifr2.ifr_name, S_feth1, sizeof(ifr2.ifr_name));
	T_ASSERT_POSIX_FAILURE(ioctl(s, SIOCGIFDSTADDR, &ifr2), EINVAL,
	    "SIOCGIFDSTADDR %s returns EINVAL (not point-to-point)", S_feth1);

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, S_feth2, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_FAILURE(ioctl(s, OSIOCGIFDSTADDR, &ifr), EINVAL,
	    "OSIOCGIFDSTADDR %s returns EINVAL (not point-to-point)", S_feth2);

	/* verify SIOCGIFDSTADDR returns the same error */
	bzero(&ifr2, sizeof(ifr2));
	strlcpy(ifr2.ifr_name, S_feth2, sizeof(ifr2.ifr_name));
	T_ASSERT_POSIX_FAILURE(ioctl(s, SIOCGIFDSTADDR, &ifr2), EINVAL,
	    "SIOCGIFDSTADDR %s returns EINVAL (not point-to-point)", S_feth2);

	T_PASS("OSIOCGIFDSTADDR and SIOCGIFDSTADDR both returned EINVAL");
}

T_DECL(osiocgifdstaddr,
    "Verify deprecated OSIOCGIFDSTADDR ioctl on non-point-to-point feth",
    T_META_ASROOT(true), T_META_TAG_VM_PREFERRED)
{
	test_osiocgifdstaddr();
}

static void
test_osiocgifbrdaddr(void)
{
	struct in_addr  brd1;
	struct in_addr  brd2;
	struct ifreq    ifr = { 0 };
	struct ifreq    ifr2 = { 0 };
	int             s;
	struct old_sockaddr *osa;
	struct sockaddr_in *sin1;
	struct sockaddr_in *sin2;

	test_setup_common();

	s = inet_dgram_socket_get();

	/* expected broadcast: addr | ~mask */
	brd1.s_addr = addr1.s_addr | ~mask.s_addr;
	brd2.s_addr = addr2.s_addr | ~mask.s_addr;


	/* verify OSIOCGIFBRDADDR on S_feth1 */
	strlcpy(ifr.ifr_name, S_feth1, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, OSIOCGIFBRDADDR, &ifr),
	    "OSIOCGIFBRDADDR %s", S_feth1);

	/* old socket address does not have a length */
	osa = (struct old_sockaddr *)(void *)&ifr.ifr_addr;
	T_ASSERT_EQ(osa->sa_family, AF_INET,
	    "%s OSIOCGIFBRDADDR broadcast family", S_feth1);
	sin1 = (struct sockaddr_in *)(void *)&ifr.ifr_addr;
	T_ASSERT_EQ(sin1->sin_addr.s_addr, brd1.s_addr,
	    "%s OSIOCGIFBRDADDR broadcast %s", S_feth1, inet_ntoa(sin1->sin_addr));

	/* verify SIOCGIFBRDADDR returns the same value */
	strlcpy(ifr2.ifr_name, S_feth1, sizeof(ifr2.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFBRDADDR, &ifr2),
	    "SIOCGIFBRDADDR %s", S_feth1);
	sin2 = (struct sockaddr_in *)(void *)&ifr2.ifr_addr;
	T_ASSERT_EQ_ULONG((unsigned long)sin2->sin_len, sizeof(struct sockaddr_in),
	    "%s SIOCGIFBRDADDR broadcast length", S_feth1);
	T_ASSERT_EQ(sin2->sin_family, AF_INET,
	    "%s SIOCGIFBRDADDR broadcast family", S_feth1);
	T_ASSERT_EQ(
		sin1->sin_addr.s_addr, sin2->sin_addr.s_addr,
		"%s OSIOCGIFBRDADDR == SIOCGIFBRDADDR", S_feth1);

	T_PASS("OSIOCGIFBRDADDR returned correct broadcast addresses "
	    "matching SIOCGIFBRDADDR");
}

T_DECL(osiocgifbrdaddr,
    "Verify deprecated OSIOCGIFBRDADDR ioctl returns correct broadcast address",
    T_META_ASROOT(true), T_META_TAG_VM_PREFERRED)
{
	test_osiocgifbrdaddr();
}

static void
test_osiocgifnetmask(void)
{
	struct ifreq    ifr = { 0 };
	struct ifreq    ifr2 = { 0 };
	int             s;
	struct sockaddr_in *sin1;
	struct sockaddr_in *sin2;

	test_setup_common();

	s = inet_dgram_socket_get();

	/* verify OSIOCGIFNETMASK on S_feth1 */
	strlcpy(ifr.ifr_name, S_feth1, sizeof(ifr.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, OSIOCGIFNETMASK, &ifr),
	    "OSIOCGIFNETMASK %s", S_feth1);

	sin1 = (struct sockaddr_in *)(void *)&ifr.ifr_addr;
	T_ASSERT_EQ(sin1->sin_addr.s_addr, mask.s_addr,
	    "%s netmask %s", S_feth1, inet_ntoa(sin1->sin_addr));

	/* verify SIOCGIFNETMASK returns the same value */
	strlcpy(ifr2.ifr_name, S_feth1, sizeof(ifr2.ifr_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCGIFNETMASK, &ifr2),
	    "SIOCGIFNETMASK %s", S_feth1);
	sin2 = (struct sockaddr_in *)(void *)&ifr2.ifr_addr;
	T_ASSERT_EQ(
		sin1->sin_addr.s_addr, sin2->sin_addr.s_addr,
		"%s OSIOCGIFNETMASK == SIOCGIFNETMASK", S_feth1);

	T_PASS("OSIOCGIFNETMASK returned correct netmasks "
	    "matching SIOCGIFNETMASK");
}

T_DECL(osiocgifnetmask,
    "Verify deprecated OSIOCGIFNETMASK ioctl returns correct subnet mask",
    T_META_ASROOT(true), T_META_TAG_VM_PREFERRED)
{
	test_osiocgifnetmask();
}
