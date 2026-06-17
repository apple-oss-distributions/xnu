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
 * icmp6_redirect_raw_socket.c
 *
 * Regression test for recursive inet6_domain_mutex panic:
 *
 * ip6_input holds inet6_domain_mutex while calling icmp6_input (ICMPv6
 * lacks PR_PROTOLOCK). icmp6_redirect_input calls pfctlinput() which
 * iterates protocols and calls in6_pcbnotify(), which calls socket_lock()
 * on raw IPv6 sockets. Those sockets lack pr_lock, so socket_lock()
 * acquires so->so_proto->pr_domain->dom_mtx -- the same mutex -- causing
 * a recursive lock panic.
 *
 * The fix drops inet6_domain_mutex before calling pfctlinput and reacquires
 * it after. This test injects an ICMPv6 Redirect while a raw IPv6 socket
 * exists. Without the fix the kernel panics; with the fix the test passes.
 */

#include <darwintest.h>

#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_fake_var.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/route.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "net_test_lib.h"
#include "bpflib.h"
#include "in_cksum.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_ASROOT(true),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ipv6"),
	T_META_RUN_CONCURRENTLY(false),
	T_META_CHECK_LEAKS(false));

static char ifname1[IF_NAMESIZE];
static char ifname2[IF_NAMESIZE];
static int raw_sock = -1;
static int old_rediraccept = -1;

static void
cleanup(void)
{
	if (raw_sock >= 0) {
		close(raw_sock);
		raw_sock = -1;
	}
	if (old_rediraccept >= 0) {
		(void)sysctlbyname("net.inet6.icmp6.rediraccept",
		    NULL, NULL, &old_rediraccept, sizeof(old_rediraccept));
	}
	if (ifname1[0] != '\0') {
		(void)ifnet_destroy(ifname1, false);
		T_LOG("destroyed %s", ifname1);
	}
	if (ifname2[0] != '\0') {
		(void)ifnet_destroy(ifname2, false);
		T_LOG("destroyed %s", ifname2);
	}
}

/*
 * ICMPv6 checksum: computed over a pseudo-header + ICMPv6 payload.
 * The pseudo-header contains src, dst, upper-layer length, and next-header.
 */
static uint16_t
icmp6_checksum(struct in6_addr *src, struct in6_addr *dst,
    void *icmp6_msg, uint16_t icmp6_len)
{
	struct {
		struct in6_addr src;
		struct in6_addr dst;
		uint32_t        len;
		uint8_t         zero[3];
		uint8_t         nxt;
	} __attribute__((__packed__)) pseudo;
	size_t total_len;
	char *buf;
	uint16_t cksum;

	bzero(&pseudo, sizeof(pseudo));
	bcopy(src, &pseudo.src, sizeof(pseudo.src));
	bcopy(dst, &pseudo.dst, sizeof(pseudo.dst));
	pseudo.len = htonl((uint32_t)icmp6_len);
	pseudo.nxt = IPPROTO_ICMPV6;

	total_len = sizeof(pseudo) + icmp6_len;
	buf = calloc(1, total_len);
	T_QUIET;
	T_ASSERT_NOTNULL(buf, "alloc checksum buffer");
	bcopy(&pseudo, buf, sizeof(pseudo));
	bcopy(icmp6_msg, buf + sizeof(pseudo), icmp6_len);

	cksum = in_cksum(buf, (int)total_len);
	free(buf);
	return cksum;
}

/*
 * Target Link-Layer Address option for ND Redirect.
 * Type=2, Len=1 (8 bytes), followed by 6-byte MAC.
 */
struct nd_opt_tlla {
	uint8_t         type;
	uint8_t         len;            /* in units of 8 bytes */
	uint8_t         lladdr[6];
} __attribute__((__packed__));

T_DECL(icmp6_redirect_raw_socket,
    "ICMPv6 Redirect must not panic with raw IPv6 socket")
{
	int error;
	unsigned int if_index1, if_index2;
	ether_addr_t eaddr1, eaddr2;
	struct in6_addr ll_addr1, ll_addr2;
	int bpf_fd = -1;

	T_ATEND(cleanup);

	/*
	 * Step 1: Create feth pair and enable IPv6.
	 */
	strlcpy(ifname1, FETH_NAME, sizeof(ifname1));
	error = ifnet_create_2(ifname1, sizeof(ifname1));
	T_ASSERT_POSIX_ZERO(error, "create %s", ifname1);
	T_LOG("created %s", ifname1);

	strlcpy(ifname2, FETH_NAME, sizeof(ifname2));
	error = ifnet_create_2(ifname2, sizeof(ifname2));
	T_ASSERT_POSIX_ZERO(error, "create %s", ifname2);
	T_LOG("created %s", ifname2);

	/* Attach IP and peer them */
	ifnet_attach_ip(ifname1);
	ifnet_attach_ip(ifname2);
	fake_set_peer(ifname1, ifname2);

	/* Start IPv6 on both (assigns link-local, disables DAD) */
	ifnet_start_ipv6(ifname1);
	ifnet_start_ipv6(ifname2);

	/* Get interface indices */
	if_index1 = if_nametoindex(ifname1);
	T_ASSERT_GT(if_index1, 0U, "if_index for %s", ifname1);
	if_index2 = if_nametoindex(ifname2);
	T_ASSERT_GT(if_index2, 0U, "if_index for %s", ifname2);

	/* Get MAC addresses */
	ifnet_get_lladdr(ifname1, &eaddr1);
	ifnet_get_lladdr(ifname2, &eaddr2);
	T_LOG("%s MAC: %02x:%02x:%02x:%02x:%02x:%02x",
	    ifname1,
	    eaddr1.octet[0], eaddr1.octet[1], eaddr1.octet[2],
	    eaddr1.octet[3], eaddr1.octet[4], eaddr1.octet[5]);
	T_LOG("%s MAC: %02x:%02x:%02x:%02x:%02x:%02x",
	    ifname2,
	    eaddr2.octet[0], eaddr2.octet[1], eaddr2.octet[2],
	    eaddr2.octet[3], eaddr2.octet[4], eaddr2.octet[5]);

	/* Get link-local addresses */
	T_ASSERT_TRUE(inet6_get_linklocal_address(if_index1, &ll_addr1),
	    "get link-local for %s", ifname1);
	T_ASSERT_TRUE(inet6_get_linklocal_address(if_index2, &ll_addr2),
	    "get link-local for %s", ifname2);

	{
		char buf1[INET6_ADDRSTRLEN], buf2[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &ll_addr1, buf1, sizeof(buf1));
		inet_ntop(AF_INET6, &ll_addr2, buf2, sizeof(buf2));
		T_LOG("%s link-local: %s", ifname1, buf1);
		T_LOG("%s link-local: %s", ifname2, buf2);
	}

	/*
	 * Step 2: Enable redirect acceptance via sysctl.
	 */
	{
		size_t oldlen = sizeof(old_rediraccept);
		int enable = 1;
		T_ASSERT_POSIX_SUCCESS(
			sysctlbyname("net.inet6.icmp6.rediraccept",
			&old_rediraccept, &oldlen, &enable, sizeof(enable)),
			"set net.inet6.icmp6.rediraccept = 1");
		T_LOG("rediraccept: %d -> 1", old_rediraccept);
	}

	/*
	 * Step 3: Install a host route for 2001:db8::1 via feth2's
	 * link-local as gateway, scoped to feth1. This satisfies the
	 * kernel's redirect validation at icmp6.c:2604-2629 which checks
	 * that a route exists for the redirect destination and that
	 * the route's gateway matches the redirect source.
	 */
	{
		struct {
			struct rt_msghdr hdr;
			struct sockaddr_in6 dst;
			struct sockaddr_in6 gw;
		} rtmsg;
		int rs;
		ssize_t len;

		rs = socket(PF_ROUTE, SOCK_RAW, 0);
		T_ASSERT_POSIX_SUCCESS(rs, "routing socket");

		memset(&rtmsg, 0, sizeof(rtmsg));
		rtmsg.hdr.rtm_type = RTM_ADD;
		rtmsg.hdr.rtm_version = RTM_VERSION;
		rtmsg.hdr.rtm_seq = 1;
		rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY;
		rtmsg.hdr.rtm_flags = RTF_UP | RTF_HOST | RTF_STATIC |
		    RTF_GATEWAY | RTF_IFSCOPE;
		rtmsg.hdr.rtm_index = (u_short)if_index1;
		rtmsg.hdr.rtm_msglen = sizeof(rtmsg);

		/* destination: 2001:db8::1 */
		rtmsg.dst.sin6_len = sizeof(rtmsg.dst);
		rtmsg.dst.sin6_family = AF_INET6;
		inet_pton(AF_INET6, "2001:db8::1", &rtmsg.dst.sin6_addr);

		/* gateway: feth2 link-local, scoped to feth1 */
		rtmsg.gw.sin6_len = sizeof(rtmsg.gw);
		rtmsg.gw.sin6_family = AF_INET6;
		rtmsg.gw.sin6_addr = ll_addr2;
		rtmsg.gw.sin6_scope_id = if_index1;

		len = write(rs, &rtmsg, sizeof(rtmsg));
		T_ASSERT_EQ(len, (ssize_t)sizeof(rtmsg),
		    "add host route for 2001:db8::1");
		close(rs);
		T_LOG("added host route 2001:db8::1 via %s link-local",
		    ifname2);
	}

	/*
	 * Step 4: Open a raw IPv6 socket and connect it to 2001:db8::1.
	 * This populates in6p_faddr on the PCB so in6_pcbnotify matches
	 * the socket when processing the redirect via pfctlinput.
	 *
	 * We bind the socket to feth1's interface first so that
	 * in6_selectsrc can find a valid source address (feth1's
	 * link-local) for the global destination.
	 */
	raw_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	T_ASSERT_POSIX_SUCCESS(raw_sock, "create raw IPv6 socket");

	/* Bind to feth1 so source address selection succeeds */
	T_ASSERT_POSIX_ZERO(setsockopt(raw_sock, IPPROTO_IPV6,
	    IPV6_BOUND_IF, &if_index1, sizeof(if_index1)),
	    "bind raw socket to %s", ifname1);

	{
		struct sockaddr_in6 dst = {
			.sin6_len = sizeof(dst),
			.sin6_family = AF_INET6,
		};
		T_ASSERT_EQ(inet_pton(AF_INET6, "2001:db8::1",
		    &dst.sin6_addr), 1, "parse 2001:db8::1");
		T_ASSERT_POSIX_ZERO(connect(raw_sock,
		    (struct sockaddr *)&dst, sizeof(dst)),
		    "connect raw socket to 2001:db8::1");
	}
	T_LOG("raw IPv6 socket connected to 2001:db8::1");

	/*
	 * Step 5: Open BPF on feth2 for packet injection.
	 * header_complete=1 means we supply the full Ethernet header.
	 * filter_receive_none so we don't read back our own packet.
	 */
	bpf_fd = bpf_new();
	T_ASSERT_POSIX_SUCCESS(bpf_fd, "bpf_new");
	T_ASSERT_POSIX_SUCCESS(bpf_setif(bpf_fd, ifname2),
	    "bpf attach to %s", ifname2);
	T_ASSERT_POSIX_SUCCESS(bpf_set_header_complete(bpf_fd, 1),
	    "bpf header_complete=1");
	T_ASSERT_POSIX_SUCCESS(bpf_filter_receive_none(bpf_fd),
	    "bpf filter_receive_none");

	/*
	 * Step 6: Build and inject the ICMPv6 Redirect packet.
	 *
	 * Frame layout:
	 *   [Ethernet header]
	 *   [IPv6 header]
	 *   [ICMPv6 ND_REDIRECT]
	 *   [ND option: Target Link-Layer Address]
	 */
	{
		struct nd_redirect rd;
		struct nd_opt_tlla tlla_opt;
		uint16_t icmp6_len;
		uint16_t ip6_packetlen;

		ether_header_t *eh;
		struct ip6_hdr *ip6;
		char *icmp6_start;
		size_t frame_len;
		char *frame;
		ssize_t nwritten;

		icmp6_len = sizeof(rd) + sizeof(tlla_opt);
		ip6_packetlen = icmp6_len;
		frame_len = sizeof(ether_header_t) + sizeof(struct ip6_hdr) +
		    icmp6_len;

		frame = calloc(1, frame_len);
		T_ASSERT_NOTNULL(frame, "alloc redirect frame");

		/* Ethernet header: src=feth2 MAC, dst=feth1 MAC */
		eh = (ether_header_t *)frame;
		bcopy(eaddr2.octet, eh->ether_shost, ETHER_ADDR_LEN);
		bcopy(eaddr1.octet, eh->ether_dhost, ETHER_ADDR_LEN);
		eh->ether_type = htons(ETHERTYPE_IPV6);

		/* IPv6 header */
		ip6 = (struct ip6_hdr *)(eh + 1);
		bzero(ip6, sizeof(*ip6));
		ip6->ip6_vfc = IPV6_VERSION;
		ip6->ip6_plen = htons(ip6_packetlen);
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_hlim = 255;    /* required by RFC 4861 */
		bcopy(&ll_addr2, &ip6->ip6_src, sizeof(ll_addr2));
		bcopy(&ll_addr1, &ip6->ip6_dst, sizeof(ll_addr1));

		/* ICMPv6 ND Redirect */
		icmp6_start = (char *)(ip6 + 1);
		bzero(&rd, sizeof(rd));
		rd.nd_rd_type = ND_REDIRECT;
		rd.nd_rd_code = 0;
		rd.nd_rd_cksum = 0;
		rd.nd_rd_reserved = 0;
		/* target = feth2 link-local (router case: is_router=1) */
		bcopy(&ll_addr2, &rd.nd_rd_target, sizeof(ll_addr2));
		/* destination = 2001:db8::1 */
		inet_pton(AF_INET6, "2001:db8::1", &rd.nd_rd_dst);

		/* ND option: Target Link-Layer Address */
		bzero(&tlla_opt, sizeof(tlla_opt));
		tlla_opt.type = ND_OPT_TARGET_LINKADDR;
		tlla_opt.len = 1;       /* 1 unit = 8 bytes */
		bcopy(eaddr2.octet, tlla_opt.lladdr, ETHER_ADDR_LEN);

		/* Assemble ICMPv6 payload for checksum computation */
		bcopy(&rd, icmp6_start, sizeof(rd));
		bcopy(&tlla_opt, icmp6_start + sizeof(rd), sizeof(tlla_opt));

		/* Compute ICMPv6 checksum */
		((struct nd_redirect *)icmp6_start)->nd_rd_cksum =
		    icmp6_checksum(&ll_addr2, &ll_addr1,
		    icmp6_start, icmp6_len);

		T_LOG("injecting ICMPv6 Redirect (%zu bytes) on %s",
		    frame_len, ifname2);

		/* Write the frame via BPF on feth2.
		 * feth peering delivers it as input on feth1.
		 * If the bug is present, kernel panics here.
		 */
		nwritten = write(bpf_fd, frame, frame_len);
		T_ASSERT_EQ((size_t)nwritten, frame_len,
		    "bpf write redirect frame");

		free(frame);
	}

	T_PASS("ICMPv6 Redirect processed without panic");

	if (bpf_fd >= 0) {
		close(bpf_fd);
	}
}
