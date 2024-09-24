/*
 * Copyright (c) 2023-2024 Apple Inc. All rights reserved.
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

#include <sys/ioctl.h>

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "net_test_lib.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_CHECK_LEAKS(false));

static char ifname1[IF_NAMESIZE];

/**
**  stolen from bootp/bootplib/util.c
**
**/

#define ROUNDUP(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(u_int32_t) - 1))) : sizeof(u_int32_t))

static int
rt_xaddrs(char * cp, const char * cplim, struct rt_addrinfo * rtinfo)
{
	int         i;
	struct sockaddr *   sa;

	bzero(rtinfo->rti_info, sizeof(rtinfo->rti_info));
	for (i = 0; (i < RTAX_MAX) && (cp < cplim); i++) {
		if ((rtinfo->rti_addrs & (1 << i)) == 0) {
			continue;
		}
		sa = (struct sockaddr *)cp;
		if ((cp + sa->sa_len) > cplim) {
			return EINVAL;
		}
		rtinfo->rti_info[i] = sa;
		cp += ROUNDUP(sa->sa_len);
	}
	return 0;
}

/**
**  stolen from bootp/IPConfiguration.bproj/iputil.c
**
** inet6_addrlist_*
**/

#define s6_addr16 __u6_addr.__u6_addr16

static char *
copy_if_info(unsigned int if_index, int af, int *ret_len_p)
{
	char *          buf = NULL;
	size_t          buf_len = 0;
	int             mib[6];

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = af;
	mib[4] = NET_RT_IFLIST;
	mib[5] = (int)if_index;

	*ret_len_p = 0;
	if (sysctl(mib, 6, NULL, &buf_len, NULL, 0) < 0) {
		fprintf(stderr, "sysctl() size failed: %s", strerror(errno));
		goto failed;
	}
	buf_len *= 2; /* just in case something changes */
	buf = malloc(buf_len);
	if (sysctl(mib, 6, buf, &buf_len, NULL, 0) < 0) {
		free(buf);
		buf = NULL;
		fprintf(stderr, "sysctl() failed: %s", strerror(errno));
		goto failed;
	}
	*ret_len_p = (int)buf_len;

failed:
	return buf;
}

static bool
inet6_get_linklocal_address(unsigned int if_index, struct in6_addr *ret_addr)
{
	char *          buf = NULL;
	char *          buf_end;
	int             buf_len;
	bool            found = FALSE;
	char *scan;
	struct rt_msghdr *rtm;

	bzero(ret_addr, sizeof(*ret_addr));
	buf = copy_if_info(if_index, AF_INET6, &buf_len);
	if (buf == NULL) {
		goto done;
	}
	buf_end = buf + buf_len;
	for (scan = buf; scan < buf_end; scan += rtm->rtm_msglen) {
		struct ifa_msghdr * ifam;
		struct rt_addrinfo  info;

		/* ALIGN: buf aligned (from calling copy_if_info), scan aligned,
		 * cast ok. */
		rtm = (struct rt_msghdr *)(void *)scan;
		if (rtm->rtm_version != RTM_VERSION) {
			continue;
		}
		if (rtm->rtm_type == RTM_NEWADDR) {
			errno_t         error;
			struct sockaddr_in6 *sin6_p;

			ifam = (struct ifa_msghdr *)rtm;
			info.rti_addrs = ifam->ifam_addrs;
			error = rt_xaddrs((char *)(ifam + 1),
			    ((char *)ifam) + ifam->ifam_msglen,
			    &info);
			if (error) {
				fprintf(stderr, "couldn't extract rt_addrinfo %s (%d)\n",
				    strerror(error), error);
				goto done;
			}
			/* ALIGN: info.rti_info aligned (sockaddr), cast ok. */
			sin6_p = (struct sockaddr_in6 *)(void *)info.rti_info[RTAX_IFA];
			if (sin6_p == NULL
			    || sin6_p->sin6_len < sizeof(struct sockaddr_in6)) {
				continue;
			}
			if (IN6_IS_ADDR_LINKLOCAL(&sin6_p->sin6_addr)) {
				*ret_addr = sin6_p->sin6_addr;
				ret_addr->s6_addr16[1] = 0; /* mask scope id */
				found = TRUE;
				break;
			}
		}
	}

done:
	if (buf != NULL) {
		free(buf);
	}
	return found;
}

static void
cleanup(void)
{
	if (ifname1[0] != '\0') {
		T_LOG("ifnet_destroy %s", ifname1);
		(void)ifnet_destroy(ifname1, false);
	}
}

static void
set_sockaddr_in6(struct sockaddr_in6 *sin6_p, const struct in6_addr *addr)
{
	sin6_p->sin6_family = AF_INET6;
	sin6_p->sin6_len = sizeof(struct sockaddr_in6);
	sin6_p->sin6_addr = *addr;
	return;
}

static int
inet6_difaddr(const char *name, const struct in6_addr *addr)
{
	struct in6_ifreq    ifr;
	int             s6 = inet6_dgram_socket_get();

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	if (addr != NULL) {
		set_sockaddr_in6(&ifr.ifr_ifru.ifru_addr, addr);
	}
	return ioctl(s6, SIOCDIFADDR_IN6, &ifr);
}

static void
in6_len2mask(struct in6_addr *mask, int len)
{
	int i;

	bzero(mask, sizeof(*mask));
	for (i = 0; i < len / 8; i++) {
		mask->s6_addr[i] = 0xff;
	}
	if (len % 8) {
		mask->s6_addr[i] = (0xff00 >> (len % 8)) & 0xff;
	}
}

static int
inet6_aifaddr(const char *name, const struct in6_addr *addr,
    const struct in6_addr *dstaddr, int prefix_length,
    int flags,
    u_int32_t valid_lifetime,
    u_int32_t preferred_lifetime)
{
	struct in6_aliasreq ifra_in6;
	int             s6 = inet6_dgram_socket_get();

	bzero(&ifra_in6, sizeof(ifra_in6));
	strncpy(ifra_in6.ifra_name, name, sizeof(ifra_in6.ifra_name));
	ifra_in6.ifra_lifetime.ia6t_vltime = valid_lifetime;
	ifra_in6.ifra_lifetime.ia6t_pltime = preferred_lifetime;
	ifra_in6.ifra_flags = flags;
	if (addr != NULL) {
		set_sockaddr_in6(&ifra_in6.ifra_addr, addr);
	}

	if (dstaddr != NULL) {
		set_sockaddr_in6(&ifra_in6.ifra_dstaddr, dstaddr);
	}

	if (prefix_length != 0) {
		struct in6_addr     prefixmask;

		in6_len2mask(&prefixmask, prefix_length);
		set_sockaddr_in6(&ifra_in6.ifra_prefixmask, &prefixmask);
	}

	return ioctl(s6, SIOCAIFADDR_IN6, &ifra_in6);
}

static void
create_fake_interface(void)
{
	int     error;

	strlcpy(ifname1, FETH_NAME, sizeof(ifname1));
	error = ifnet_create_2(ifname1, sizeof(ifname1));
	if (error != 0) {
		ifname1[0] = '\0';
		T_ASSERT_POSIX_SUCCESS(error, "ifnet_create_2");
	}
	T_LOG("created %s", ifname1);
}

T_DECL(inet6_addr_mode_auto_to_manual, "inet6 address mode-switching (auto -> manual)")
{
	struct in6_addr lladdr;
	struct in6_addr newaddr;
	unsigned int    if_index;

	T_ATEND(cleanup);

	create_fake_interface();
	ifnet_start_ipv6(ifname1);

	if_index = if_nametoindex(ifname1);
	T_EXPECT_GT(if_index, 0, NULL);
	T_ASSERT_EQ(inet6_get_linklocal_address(if_index, &lladdr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &lladdr, NULL, 64, 123, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Create address as an autoconfed address */
	T_ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::3", &newaddr), 1, NULL);
	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &newaddr, NULL, 64, (IN6_IFF_AUTOCONF | IN6_IFF_TEMPORARY), ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Now mark it as manual */
	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &newaddr, NULL, 64, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Deleting address should NOT result in panic */
	T_ASSERT_POSIX_SUCCESS(inet6_difaddr(ifname1, &newaddr), NULL);
}

T_DECL(inet6_addr_mode_manual_to_auto, "inet6 address mode-switching (manual -> auto)")
{
	struct in6_addr lladdr;
	struct in6_addr newaddr;
	unsigned int    if_index;

	T_ATEND(cleanup);
	create_fake_interface();

	T_LOG("created %s", ifname1);

	ifnet_start_ipv6(ifname1);

	if_index = if_nametoindex(ifname1);
	T_EXPECT_GT(if_index, 0, NULL);
	T_ASSERT_EQ(inet6_get_linklocal_address(if_index, &lladdr), 1, NULL);

	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &lladdr, NULL, 64, 123, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Create address as a manual address */
	T_ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::1", &newaddr), 1, NULL);
	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &newaddr, NULL, 64, 0, ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Now make it autoconfed */
	T_ASSERT_POSIX_SUCCESS(inet6_aifaddr(ifname1, &newaddr, NULL, 64, (IN6_IFF_AUTOCONF | IN6_IFF_TEMPORARY), ND6_INFINITE_LIFETIME, ND6_INFINITE_LIFETIME), NULL);

	/* Deleting address should NOT result in panic */
	T_ASSERT_POSIX_SUCCESS(inet6_difaddr(ifname1, &newaddr), NULL);
}
