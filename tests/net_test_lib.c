/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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
#include <net/if_fake_var.h>
#include <net/if_vlan_var.h>
#include <net/if_bridgevar.h>

#define RTM_BUFLEN (sizeof(struct rt_msghdr) + 6 * SOCK_MAXADDRLEN)

#define ROUNDUP(a) \
((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))

bool G_debug;

struct in_addr inet_class_c_subnet_mask = {
	.s_addr = htonl(IN_CLASSC_NET)
};

ether_addr_t ether_broadcast = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

/*
 * local utility functions
 */
static void
siocll_start(int s, const char * ifname)
{
	struct in6_aliasreq     ifra_in6;
	int                     result;

	bzero(&ifra_in6, sizeof(ifra_in6));
	strncpy(ifra_in6.ifra_name, ifname, sizeof(ifra_in6.ifra_name));
	result = ioctl(s, SIOCLL_START, &ifra_in6);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(result, "SIOCLL_START %s", ifname);
	return;
}

static void
nd_flags_set(int s, const char * if_name,
    uint32_t set_flags, uint32_t clear_flags)
{
	uint32_t                new_flags;
	struct in6_ndireq       nd;
	int                     result;

	bzero(&nd, sizeof(nd));
	strncpy(nd.ifname, if_name, sizeof(nd.ifname));
	result = ioctl(s, SIOCGIFINFO_IN6, &nd);
	T_ASSERT_POSIX_SUCCESS(result, "SIOCGIFINFO_IN6(%s)", if_name);
	new_flags = nd.ndi.flags;
	if (set_flags) {
		new_flags |= set_flags;
	}
	if (clear_flags) {
		new_flags &= ~clear_flags;
	}
	if (new_flags != nd.ndi.flags) {
		nd.ndi.flags = new_flags;
		result = ioctl(s, SIOCSIFINFO_FLAGS, (caddr_t)&nd);
		T_ASSERT_POSIX_SUCCESS(result,
		    "SIOCSIFINFO_FLAGS(%s) 0x%x",
		    if_name, nd.ndi.flags);
	}
	return;
}


static void
siocprotoattach_in6(int s, const char * name)
{
	struct in6_aliasreq ifra;
	int                 result;

	bzero(&ifra, sizeof(ifra));
	strncpy(ifra.ifra_name, name, sizeof(ifra.ifra_name));
	result = ioctl(s, SIOCPROTOATTACH_IN6, &ifra);
	T_ASSERT_POSIX_SUCCESS(result, "SIOCPROTOATTACH_IN6(%s)", name);
	return;
}

static void
siocaifaddr(int s, char *ifname, struct in_addr addr, struct in_addr mask)
{
	struct ifaliasreq       ifra;
	char                    ntopbuf_ip[INET_ADDRSTRLEN];
	char                    ntopbuf_mask[INET_ADDRSTRLEN];
	int                     ret;
	struct sockaddr_in *    sin;

	bzero(&ifra, sizeof(ifra));
	strncpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

	sin = (struct sockaddr_in *)(void *)&ifra.ifra_addr;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr = addr;

	sin = (struct sockaddr_in *)(void *)&ifra.ifra_mask;
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	sin->sin_addr = mask;

	ret = ioctl(s, SIOCAIFADDR, &ifra);
	inet_ntop(AF_INET, &addr, ntopbuf_ip, sizeof(ntopbuf_ip));
	inet_ntop(AF_INET, &sin->sin_addr, ntopbuf_mask, sizeof(ntopbuf_mask));
	T_ASSERT_POSIX_SUCCESS(ret, "SIOCAIFADDR %s %s %s",
	    ifname, ntopbuf_ip, ntopbuf_mask);
	return;
}


/*
 * utility functions
 */

#define NO_SOCKET       (-1)

static int
_dgram_socket_get(int * sock_p, int af)
{
	int     sock = *sock_p;

	if (sock != NO_SOCKET) {
		goto done;
	}
	sock = *sock_p = socket(af, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(sock,
	    "socket(SOCK_DGRAM, %s, 0)",
	    af == AF_INET ? "AF_INET" : "AF_INET6");
done:
	return sock;
}

static void
_socket_close(int * sock_p)
{
	int sock = *sock_p;

	if (sock != NO_SOCKET) {
		close(sock);
		*sock_p = NO_SOCKET;
	}
}

static int inet_dgram_socket = NO_SOCKET;

int
inet_dgram_socket_get(void)
{
	return _dgram_socket_get(&inet_dgram_socket, AF_INET);
}

void
inet_dgram_socket_close(void)
{
	_socket_close(&inet_dgram_socket);
}


static int inet6_dgram_socket = NO_SOCKET;

int
inet6_dgram_socket_get(void)
{
	return _dgram_socket_get(&inet6_dgram_socket, AF_INET6);
}

void
inet6_dgram_socket_close(void)
{
	_socket_close(&inet6_dgram_socket);
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
ifnet_get_lladdr(const char * ifname, ether_addr_t * eaddr)
{
	int err;
	struct ifreq ifr;
	int s = inet_dgram_socket_get();

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
ifnet_set_lladdr(const char * ifname, ether_addr_t * eaddr)
{
	int err;
	int this_errno = 0;
	struct ifreq ifr;
	int s = inet_dgram_socket_get();

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_addr.sa_family = AF_LINK;
	ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	bcopy(eaddr->octet, ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	err = ioctl(s, SIOCSIFLLADDR, &ifr);
	if (err != 0) {
		this_errno = errno;
		T_LOG("SIOCSIFLLADDR %s %s (%d)", ifname,
		    strerror(this_errno), this_errno);
	} else {
		T_LOG("SIOCSIFLLADDR %s success", ifname);
	}
	return err;
}


void
ifnet_attach_ip(char * name)
{
	int             err;
	struct ifreq    ifr;
	int             s = inet_dgram_socket_get();

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
	err = ioctl(s, SIOCPROTOATTACH, &ifr);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "SIOCPROTOATTACH %s", ifr.ifr_name);
	return;
}

void
ifnet_start_ipv6(const char * ifname)
{
	int             s6 = inet6_dgram_socket_get();

	/* attach IPv6 */
	siocprotoattach_in6(s6, ifname);

	/* disable DAD to avoid 1 second delay (rdar://problem/73270401) */
	nd_flags_set(s6, ifname, 0, ND6_IFF_DAD);

	/* start IPv6LL */
	siocll_start(s6, ifname);

	return;
}

int
ifnet_destroy(const char * ifname, bool fail_on_error)
{
	int             err;
	struct ifreq    ifr;
	int             s = inet_dgram_socket_get();

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
ifnet_set_flags(const char * ifname, uint16_t flags_set, uint16_t flags_clear)
{
	uint16_t        flags_after;
	uint16_t        flags_before;
	struct ifreq    ifr;
	int             ret;
	int             s = inet_dgram_socket_get();

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
		if (G_debug) {
			T_LOG("setflags(%s set 0x%x clear 0x%x) 0x%x => 0x%x",
			    ifr.ifr_name, flags_set, flags_clear,
			    flags_before, flags_after);
		}
	}
	return ret;
}

/* On some platforms with DEBUG kernel, we need to wait a while */
#define SIFCREATE_RETRY 600

static int
ifnet_create_common(const char * ifname, char *ifname_out, size_t ifname_out_len)
{
	int             error = 0;
	struct ifreq    ifr;
	int             s = inet_dgram_socket_get();

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
				(void)ifnet_destroy(ifname, false);
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
		error = ifnet_set_flags(ifname, IFF_UP, 0);
	}
	return error;
}

int
ifnet_create(const char * ifname)
{
	return ifnet_create_common(ifname, NULL, 0);
}

int
ifnet_create_2(char * ifname, size_t len)
{
	return ifnet_create_common(ifname, ifname, len);
}

void
ifnet_add_ip_address(char *ifname, struct in_addr addr, struct in_addr mask)
{
	int             s = inet_dgram_socket_get();

	siocaifaddr(s, ifname, addr, mask);
}

int
ifnet_set_mtu(const char *ifname, int mtu)
{
	int error = 0;
	struct ifreq ifr = { 0 };
	int s = inet_dgram_socket_get();

	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_mtu = mtu;

	T_ASSERT_POSIX_SUCCESS(ioctl(s, SIOCSIFMTU, (caddr_t)&ifr), "set MTU");

	return error;
}

int
siocdrvspec(const char * ifname, u_long op, void *arg, size_t argsize, bool set)
{
	struct ifdrv    ifd;
	int             s = inet_dgram_socket_get();

	memset(&ifd, 0, sizeof(ifd));
	strlcpy(ifd.ifd_name, ifname, sizeof(ifd.ifd_name));
	ifd.ifd_cmd = op;
	ifd.ifd_len = argsize;
	ifd.ifd_data = arg;
	return ioctl(s, set ? SIOCSDRVSPEC : SIOCGDRVSPEC, &ifd);
}

void
fake_set_peer(const char * feth, const char * feth_peer)
{
	struct if_fake_request  iffr;
	int                     ret;

	bzero((char *)&iffr, sizeof(iffr));
	if (feth_peer != NULL) {
		strlcpy(iffr.iffr_peer_name, feth_peer,
		    sizeof(iffr.iffr_peer_name));
	}
	ret = siocdrvspec(feth, IF_FAKE_S_CMD_SET_PEER,
	    &iffr, sizeof(iffr), true);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret,
	    "SIOCDRVSPEC(%s, IF_FAKE_S_CMD_SET_PEER, %s)",
	    feth, (feth_peer != NULL) ? feth_peer : "<none>");
	T_LOG("%s peer %s\n", feth, feth_peer);
	return;
}

void
siocsifvlan(const char * vlan, const char * phys, uint16_t tag)
{
	int             result;
	struct ifreq    ifr;
	int             s = inet_dgram_socket_get();
	struct vlanreq  vlr;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, vlan, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&vlr;
	strlcpy(vlr.vlr_parent, phys, sizeof(vlr.vlr_parent));
	vlr.vlr_tag = tag;
	result = ioctl(s, SIOCSIFVLAN, &ifr);
	T_ASSERT_POSIX_SUCCESS(result, "SIOCSIFVLAN(%s) %s %d",
	    vlan, phys, tag);
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



/*
 * routing table
 */

/*
 * Stolen/modified from IPMonitor/ip_plugin.c
 */
/*
 * Define: ROUTE_MSG_ADDRS_SPACE
 * Purpose:
 *   Since sizeof(sockaddr_dl) > sizeof(sockaddr_in), we need space for
 *   3 sockaddr_in's and 2 sockaddr_dl's, but pad it just in case
 *   someone changes the code and doesn't think to modify this.
 */
#define ROUTE_MSG_ADDRS_SPACE   (3 * sizeof(struct sockaddr_in) \
	                         + 2 * sizeof(struct sockaddr_dl) \
	                         + 128)
typedef struct {
	struct rt_msghdr    hdr;
	char                addrs[ROUTE_MSG_ADDRS_SPACE];
} route_msg;

typedef unsigned short  IFIndex;

typedef enum {
	kRouteFlagsIsScoped         = 0x0001,
	kRouteFlagsHasGateway       = 0x0002,
	kRouteFlagsIsHost           = 0x0004,
} RouteFlags;

typedef struct {
	IFIndex         ifindex;
	RouteFlags      flags;
	struct in_addr  dest;
	struct in_addr  mask;
	struct in_addr  gateway;
	struct in_addr  ifa;
} IPv4Route, * IPv4RouteRef;

/*
 * Function: IPv4RouteApply
 * Purpose:
 *   Add or remove the specified route to/from the kernel routing table.
 */
static int
IPv4RouteApply(IPv4RouteRef route, uint8_t cmd, int s)
{
	size_t          len;
	int             ret = 0;
	route_msg       rtmsg;
	union {
		struct sockaddr_in *    in_p;
		struct sockaddr_dl *    dl_p;
		char *                  ptr;
	} rtaddr;
	static int      rtm_seq;
	static bool     rtm_seq_inited;

	if (!rtm_seq_inited) {
		rtm_seq_inited = true;
		rtm_seq = (int)arc4random();
	}
	if (route->ifindex == 0) {
		T_LOG("no interface specified, ignoring %s",
		    inet_ntoa(route->dest));
		return ENXIO;
	}
	if (s < 0) {
		T_LOG("invalid routing socket");
		return EBADF;
	}
	memset(&rtmsg, 0, sizeof(rtmsg));
	rtmsg.hdr.rtm_type = cmd;
	rtmsg.hdr.rtm_version = RTM_VERSION;
	rtmsg.hdr.rtm_seq = rtm_seq++;
	rtmsg.hdr.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_IFP;
	if (route->ifa.s_addr != 0) {
		rtmsg.hdr.rtm_addrs |= RTA_IFA;
	}
	rtmsg.hdr.rtm_flags = RTF_UP | RTF_STATIC;
	if ((route->flags & kRouteFlagsIsHost) != 0) {
		rtmsg.hdr.rtm_flags |= RTF_HOST;
	} else {
		rtmsg.hdr.rtm_addrs |= RTA_NETMASK;
		if ((route->flags & kRouteFlagsHasGateway) == 0) {
			rtmsg.hdr.rtm_flags |= RTF_CLONING;
		}
	}
	if ((route->flags & kRouteFlagsHasGateway) != 0) {
		rtmsg.hdr.rtm_flags |= RTF_GATEWAY;
	}
	if ((route->flags & kRouteFlagsIsScoped) != 0) {
		rtmsg.hdr.rtm_index = route->ifindex;
		rtmsg.hdr.rtm_flags |= RTF_IFSCOPE;
	}

	rtaddr.ptr = rtmsg.addrs;

	/* dest */
	rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
	rtaddr.in_p->sin_family = AF_INET;
	rtaddr.in_p->sin_addr = route->dest;
	rtaddr.ptr += sizeof(*rtaddr.in_p);

	/* gateway */
	if ((rtmsg.hdr.rtm_flags & RTF_GATEWAY) != 0) {
		/* gateway is an IP address */
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->gateway;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	} else {
		/* gateway is the interface itself */
		rtaddr.dl_p->sdl_len = sizeof(*rtaddr.dl_p);
		rtaddr.dl_p->sdl_family = AF_LINK;
		rtaddr.dl_p->sdl_index = route->ifindex;
		rtaddr.ptr += sizeof(*rtaddr.dl_p);
	}

	/* mask */
	if ((rtmsg.hdr.rtm_addrs & RTA_NETMASK) != 0) {
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->mask;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	}

	/* interface */
	if ((rtmsg.hdr.rtm_addrs & RTA_IFP) != 0) {
		rtaddr.dl_p->sdl_len = sizeof(*rtaddr.dl_p);
		rtaddr.dl_p->sdl_family = AF_LINK;
		rtaddr.dl_p->sdl_index = route->ifindex;
		rtaddr.ptr += sizeof(*rtaddr.dl_p);
	}
	/* interface address */
	if ((rtmsg.hdr.rtm_addrs & RTA_IFA) != 0) {
		rtaddr.in_p->sin_len = sizeof(*rtaddr.in_p);
		rtaddr.in_p->sin_family = AF_INET;
		rtaddr.in_p->sin_addr = route->ifa;
		rtaddr.ptr += sizeof(*rtaddr.in_p);
	}

	/* apply the route */
	len = (sizeof(rtmsg.hdr)
	    + (unsigned long)(rtaddr.ptr - (char *)rtmsg.addrs));
	rtmsg.hdr.rtm_msglen = (u_short)len;
	if (write(s, &rtmsg, len) == -1) {
		ret = errno;
		T_LOG("write routing socket failed, (%d) %s",
		    errno, strerror(errno));
	}
	return ret;
}

static int routing_socket = -1;

static int
routing_socket_get(void)
{
	if (routing_socket != NO_SOCKET) {
		goto done;
	}
	routing_socket = socket(PF_ROUTE, SOCK_RAW, PF_ROUTE);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(routing_socket,
	    "socket(PF_ROUTE, SOCK_RAW, PF_ROUTE)");
done:
	return routing_socket;
}

void
route_add_inet_scoped_subnet(char * ifname, u_short if_index,
    struct in_addr ifa, struct in_addr mask)
{
	int             error;
	IPv4Route       route;
	int             rs = routing_socket_get();

	bzero(&route, sizeof(route));
	route.flags |= kRouteFlagsIsScoped;
	route.ifa = ifa;
	route.ifindex = if_index;
	route.mask = mask;
	route.dest.s_addr = route.ifa.s_addr & route.mask.s_addr;
	T_QUIET;
	T_ASSERT_NE((int)route.ifindex, 0, "if_nametoindex(%s)", ifname);
	error = IPv4RouteApply(&route, RTM_ADD, rs);
	T_ASSERT_EQ(error, 0, "add scoped subnet route %s %s/24", ifname,
	    inet_ntoa(route.dest));
	return;
}

/**
** network_interface
**/

void
network_interface_create(network_interface_t if_p, const if_name_t name)
{
	int             error;
	size_t          len = sizeof(if_p->if_name);

	strlcpy(if_p->if_name, name, len);
	error = ifnet_create_2(if_p->if_name, len);
	T_ASSERT_POSIX_SUCCESS(error, "ifnet_create_2 %s", if_p->if_name);

	if_p->if_index = (u_short)if_nametoindex(if_p->if_name);
	T_QUIET;
	T_ASSERT_TRUE(if_p->if_index != 0, NULL);
	T_LOG("%s: created %s index %d\n",
	    __func__, if_p->if_name, if_p->if_index);
}

void
network_interface_destroy(network_interface_t if_p)
{
	if (if_p->if_index != 0) {
		ifnet_destroy(if_p->if_name, false);
		T_LOG("%s: destroyed %s\n", __func__, if_p->if_name);
	}
}

static inline size_t
network_interface_pair_list_size(size_t count)
{
	return offsetof(network_interface_pair_list, list[count]);
}

network_interface_pair_list_t
network_interface_pair_list_alloc(u_int n)
{
	network_interface_pair_list_t   list;

	list = (network_interface_pair_list_t)
	    calloc(1, network_interface_pair_list_size(n));
	list->count = n;
	return list;
}

void
network_interface_pair_list_destroy(network_interface_pair_list_t list)
{
	network_interface_pair_t        scan;

	if (list == NULL) {
		return;
	}
	scan = list->list;
	for (size_t i = 0; i < list->count; i++, scan++) {
		network_interface_destroy(&scan->one);
		network_interface_destroy(&scan->two);
	}
}

bool
has_ipv4_default_route(void)
{
	bool result = false;
	struct rt_msghdr *rtm = NULL;
	struct sockaddr_in sin = { 0 };

	sin.sin_len = sizeof(struct sockaddr_in);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;

	T_QUIET; T_ASSERT_NOTNULL(rtm = (struct rt_msghdr *)calloc(1, RTM_BUFLEN), NULL);

	rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 1;

	uint8_t *cp = (unsigned char *)(rtm + 1);

	bcopy(&sin, cp, sin.sin_len);
	cp += ROUNDUP(sin.sin_len);

	u_short len = (u_short)(cp - (uint8_t *)rtm);

	rtm->rtm_msglen = len;

	int fd;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd = socket(PF_ROUTE, SOCK_RAW, 0), NULL);

	ssize_t sent = send(fd, rtm, len, 0);
	if (sent == len) {
		result = true;
	} else {
		result = false;
	}

	(void) close(fd);
	free(rtm);

	return result;
}

bool
has_ipv6_default_route(void)
{
	bool result = false;
	struct rt_msghdr *rtm = NULL;
	struct sockaddr_in6 sin6 = { 0 };

	sin6.sin6_len = sizeof(struct sockaddr_in6);
	sin6.sin6_family = AF_INET6;

	T_QUIET; T_ASSERT_NOTNULL(rtm = (struct rt_msghdr *)calloc(1, RTM_BUFLEN), NULL);

	rtm->rtm_msglen = sizeof(struct rt_msghdr) + sizeof(struct sockaddr_in6);
	rtm->rtm_version = RTM_VERSION;
	rtm->rtm_type = RTM_GET;
	rtm->rtm_flags = RTF_UP | RTF_STATIC | RTF_GATEWAY | RTF_HOST;
	rtm->rtm_addrs = RTA_DST;
	rtm->rtm_pid = getpid();
	rtm->rtm_seq = 1;

	uint8_t *cp = (unsigned char *)(rtm + 1);

	bcopy(&sin6, cp, sin6.sin6_len);
	cp += ROUNDUP(sin6.sin6_len);

	u_short len = (u_short)(cp - (uint8_t *)rtm);

	rtm->rtm_msglen = len;

	int fd;
	T_QUIET; T_ASSERT_POSIX_SUCCESS(fd = socket(PF_ROUTE, SOCK_RAW, 0), NULL);

	ssize_t sent = send(fd, rtm, len, 0);
	if (sent == len) {
		result = true;
	} else {
		result = false;
	}

	(void) close(fd);
	free(rtm);

	return result;
}

/*
 * Bridge management
 */
int
bridge_add_member(const char * bridge, const char * member)
{
	struct ifbreq           req;
	int                     ret;

	memset(&req, 0, sizeof(req));
	strlcpy(req.ifbr_ifsname, member, sizeof(req.ifbr_ifsname));
	ret = siocdrvspec(bridge, BRDGADD, &req, sizeof(req), true);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "%s %s %s", __func__, bridge, member);
	return ret;
}
