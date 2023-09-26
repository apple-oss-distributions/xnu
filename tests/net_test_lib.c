/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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

#include "net_test_lib.h"
#include "inet_transfer.h"
#include "bpflib.h"
#include "in_cksum.h"

bool S_debug;

int
inet_dgram_socket(void)
{
	int     s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET, SOCK_DGRAM, 0)");
	return s;
}

int
inet6_dgram_socket(void)
{
	int     s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_DGRAM, 0)");
	return s;
}

int
routing_socket(void)
{
	int     s;

	s = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(PF_ROUTE, SOCK_RAW, PF_ROUTE)");
	return s;
}

u_int
ethernet_udp4_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in_addr src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in_addr dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len)
{
	ether_header_t *        eh_p;
	u_int                   frame_length;
	static int              ip_id;
	ip_udp_header_t *       ip_udp;
	char *                  payload;
	udp_pseudo_hdr_t *      udp_pseudo;

	frame_length = (u_int)(sizeof(*eh_p) + sizeof(*ip_udp)) + data_len;
	if (buf_len < frame_length) {
		return 0;
	}

	/* determine frame offsets */
	eh_p = (ether_header_t *)buf;
	ip_udp = (ip_udp_header_t *)(void *)(eh_p + 1);
	udp_pseudo = (udp_pseudo_hdr_t *)(void *)
	    (((char *)&ip_udp->udp) - sizeof(*udp_pseudo));
	payload = (char *)(eh_p + 1) + sizeof(*ip_udp);

	/* ethernet_header */
	bcopy(src, eh_p->ether_shost, ETHER_ADDR_LEN);
	bcopy(dst, eh_p->ether_dhost, ETHER_ADDR_LEN);
	eh_p->ether_type = htons(ETHERTYPE_IP);

	/* copy the data */
	bcopy(data, payload, data_len);

	/* fill in UDP pseudo header (gets overwritten by IP header below) */
	bcopy(&src_ip, &udp_pseudo->src_ip, sizeof(src_ip));
	bcopy(&dst_ip, &udp_pseudo->dst_ip, sizeof(dst_ip));
	udp_pseudo->zero = 0;
	udp_pseudo->proto = IPPROTO_UDP;
	udp_pseudo->length = htons(sizeof(ip_udp->udp) + data_len);

	/* fill in UDP header */
	ip_udp->udp.uh_sport = htons(src_port);
	ip_udp->udp.uh_dport = htons(dst_port);
	ip_udp->udp.uh_ulen = htons(sizeof(ip_udp->udp) + data_len);
	ip_udp->udp.uh_sum = 0;
	ip_udp->udp.uh_sum = in_cksum(udp_pseudo, (int)(sizeof(*udp_pseudo)
	    + sizeof(ip_udp->udp) + data_len));

	/* fill in IP header */
	bzero(ip_udp, sizeof(ip_udp->ip));
	ip_udp->ip.ip_v = IPVERSION;
	ip_udp->ip.ip_hl = sizeof(struct ip) >> 2;
	ip_udp->ip.ip_ttl = MAXTTL;
	ip_udp->ip.ip_p = IPPROTO_UDP;
	bcopy(&src_ip, &ip_udp->ip.ip_src, sizeof(src_ip));
	bcopy(&dst_ip, &ip_udp->ip.ip_dst, sizeof(dst_ip));
	ip_udp->ip.ip_len = htons(sizeof(*ip_udp) + data_len);
	ip_udp->ip.ip_id = htons(ip_id++);

	/* compute the IP checksum */
	ip_udp->ip.ip_sum = 0; /* needs to be zero for checksum */
	ip_udp->ip.ip_sum = in_cksum(&ip_udp->ip, sizeof(ip_udp->ip));

	return frame_length;
}

u_int
ethernet_udp6_frame_populate(void * buf, size_t buf_len,
    const ether_addr_t * src,
    struct in6_addr *src_ip,
    uint16_t src_port,
    const ether_addr_t * dst,
    struct in6_addr * dst_ip,
    uint16_t dst_port,
    const void * data, u_int data_len)
{
	ether_header_t *        eh_p;
	u_int                   frame_length;
	ip6_udp_header_t *      ip6_udp;
	char *                  payload;
	udp6_pseudo_hdr_t *     udp6_pseudo;

	frame_length = (u_int)(sizeof(*eh_p) + sizeof(*ip6_udp)) + data_len;
	if (buf_len < frame_length) {
		return 0;
	}

	/* determine frame offsets */
	eh_p = (ether_header_t *)buf;
	ip6_udp = (ip6_udp_header_t *)(void *)(eh_p + 1);
	udp6_pseudo = (udp6_pseudo_hdr_t *)(void *)
	    (((char *)&ip6_udp->udp) - sizeof(*udp6_pseudo));
	payload = (char *)(eh_p + 1) + sizeof(*ip6_udp);

	/* ethernet_header */
	bcopy(src, eh_p->ether_shost, ETHER_ADDR_LEN);
	bcopy(dst, eh_p->ether_dhost, ETHER_ADDR_LEN);
	eh_p->ether_type = htons(ETHERTYPE_IPV6);

	/* copy the data */
	bcopy(data, payload, data_len);

	/* fill in UDP pseudo header (gets overwritten by IP header below) */
	bcopy(src_ip, &udp6_pseudo->src_ip, sizeof(*src_ip));
	bcopy(dst_ip, &udp6_pseudo->dst_ip, sizeof(*dst_ip));
	udp6_pseudo->zero = 0;
	udp6_pseudo->proto = IPPROTO_UDP;
	udp6_pseudo->length = htons(sizeof(ip6_udp->udp) + data_len);

	/* fill in UDP header */
	ip6_udp->udp.uh_sport = htons(src_port);
	ip6_udp->udp.uh_dport = htons(dst_port);
	ip6_udp->udp.uh_ulen = htons(sizeof(ip6_udp->udp) + data_len);
	ip6_udp->udp.uh_sum = 0;
	ip6_udp->udp.uh_sum = in_cksum(udp6_pseudo, (int)(sizeof(*udp6_pseudo)
	    + sizeof(ip6_udp->udp) + data_len));

	/* fill in IP header */
	bzero(&ip6_udp->ip6, sizeof(ip6_udp->ip6));
	ip6_udp->ip6.ip6_vfc = IPV6_VERSION;
	ip6_udp->ip6.ip6_nxt = IPPROTO_UDP;
	bcopy(src_ip, &ip6_udp->ip6.ip6_src, sizeof(*src_ip));
	bcopy(dst_ip, &ip6_udp->ip6.ip6_dst, sizeof(*dst_ip));
	ip6_udp->ip6.ip6_plen = htons(sizeof(struct udphdr) + data_len);
	/* ip6_udp->ip6.ip6_flow = ? */
	return frame_length;
}

/**
** interface management
**/

void
ifnet_get_lladdr(int s, const char * ifname, ether_addr_t * eaddr)
{
	int err;
	struct ifreq ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	err = ioctl(s, SIOCGIFLLADDR, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCGIFLLADDR %s", ifname);
	bcopy(ifr.ifr_addr.sa_data, eaddr->octet, ETHER_ADDR_LEN);
	return;
}


int
ifnet_attach_ip(int s, char * name)
{
	int                     err;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCPROTOATTACH, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCPROTOATTACH %s", ifr.ifr_name);
	return err;
}

int
ifnet_destroy(int s, const char * ifname, bool fail_on_error)
{
	int             err;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCIFDESTROY, &ifr);
	if (fail_on_error) {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(err, "SIOCSIFDESTROY %s", ifr.ifr_name);
	}
	if (err < 0) {
		T_LOG("SIOCSIFDESTROY %s", ifr.ifr_name);
	}
	return err;
}

int
ifnet_set_flags(int s, const char * ifname,
    uint16_t flags_set, uint16_t flags_clear)
{
	uint16_t        flags_after;
	uint16_t        flags_before;
	struct ifreq    ifr;
	int             ret;

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ret = ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr);
	if (ret != 0) {
		T_LOG("SIOCGIFFLAGS %s", ifr.ifr_name);
		return ret;
	}
	flags_before = (uint16_t)ifr.ifr_flags;
	ifr.ifr_flags |= flags_set;
	ifr.ifr_flags &= ~(flags_clear);
	flags_after = (uint16_t)ifr.ifr_flags;
	if (flags_before == flags_after) {
		/* nothing to do */
		ret = 0;
	} else {
		/* issue the ioctl */
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCSIFFLAGS, &ifr),
		    "SIOCSIFFLAGS %s 0x%x",
		    ifr.ifr_name, (uint16_t)ifr.ifr_flags);
		if (S_debug) {
			T_LOG("setflags(%s set 0x%x clear 0x%x) 0x%x => 0x%x",
			    ifr.ifr_name, flags_set, flags_clear,
			    flags_before, flags_after);
		}
	}
	return ret;
}

#define FETH_NAME       "feth"

/* On some platforms with DEBUG kernel, we need to wait a while */
#define SIFCREATE_RETRY 600

static int
ifnet_create_common(int s, const char * ifname, char *ifname_out, size_t ifname_out_len)
{
	int             error = 0;
	struct ifreq    ifr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	for (int i = 0; i < SIFCREATE_RETRY; i++) {
		if (ioctl(s, SIOCIFCREATE, &ifr) < 0) {
			error = errno;
			T_LOG("SIOCSIFCREATE %s: %s", ifname,
			    strerror(error));
			if (error == EBUSY) {
				/* interface is tearing down, try again */
				usleep(10000);
			} else if (error == EEXIST) {
				/* interface exists, try destroying it */
				(void)ifnet_destroy(s, ifname, false);
			} else {
				/* unexpected failure */
				break;
			}
		} else {
			if (ifname_out != NULL) {
				strlcpy(ifname_out, ifr.ifr_name, ifname_out_len);
			}
			error = 0;
			break;
		}
	}
	if (error == 0) {
		error = ifnet_set_flags(s, ifname, IFF_UP, 0);
	}
	return error;
}

int
ifnet_create(int s, const char * ifname)
{
	return ifnet_create_common(s, ifname, NULL, 0);
}

int
ifnet_create_2(int s, char * ifname, size_t len)
{
	return ifnet_create_common(s, ifname, ifname, len);
}

int
siocdrvspec(int s, const char * ifname,
    u_long op, void *arg, size_t argsize, bool set)
{
	struct ifdrv    ifd;

	memset(&ifd, 0, sizeof(ifd));
	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;
	return ioctl(s, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd);
}

int
fake_set_peer(int s, const char * feth, const char * feth_peer)
{
	struct if_fake_request  iffr;
	int                     ret;

	bzero((char *)&iffr, sizeof(iffr));
	if (feth_peer != NULL) {
		strlcpy(iffr.iffr_peer_name, feth_peer,
		    sizeof(iffr.iffr_peer_name));
	}
	ret = siocdrvspec(s, feth, IF_FAKE_S_CMD_SET_PEER,
	    &iffr, sizeof(iffr), true);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret,
	    "SIOCDRVSPEC(%s, IF_FAKE_S_CMD_SET_PEER, %s)",
	    feth, (feth_peer != NULL) ? feth_peer : "<none>");
	return ret;
}

u_int
make_dhcp_payload(dhcp_min_payload_t payload, ether_addr_t *eaddr)
{
	struct bootp *  dhcp;
	u_int           payload_length;

	/* create a minimal BOOTP packet */
	payload_length = sizeof(*payload);
	dhcp = (struct bootp *)payload;
	bzero(dhcp, payload_length);
	dhcp->bp_op = BOOTREQUEST;
	dhcp->bp_htype = ARPHRD_ETHER;
	dhcp->bp_hlen = sizeof(*eaddr);
	bcopy(eaddr->octet, dhcp->bp_chaddr, sizeof(eaddr->octet));
	return payload_length;
}
