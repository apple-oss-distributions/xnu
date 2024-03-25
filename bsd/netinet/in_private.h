/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)in.h	8.3 (Berkeley) 1/3/94
 * $FreeBSD: src/sys/netinet/in.h,v 1.48.2.2 2001/04/21 14:53:06 ume Exp $
 */

#ifndef _NETINET_IN_PRIVATE_H_
#define _NETINET_IN_PRIVATE_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
/* 253-254: Experimentation and testing; 255: Reserved (RFC3692) */
/* BSD Private, local use, namespace incursion */
#define IPPROTO_QUIC            253             /* QUIC protocol (Over UDP) */

#ifdef __APPLE__
#define IN_SHARED_ADDRESS_SPACE(i) ((((u_int32_t)(i)) & (u_int32_t)0xffc00000) \
	                        == (u_int32_t)0x64400000)

#define IN_DS_LITE(i) ((((u_int32_t)(i)) & (u_int32_t)0xfffffff8) == (u_int32_t)0xc0000000)

#define IN_6TO4_RELAY_ANYCAST(i) ((((u_int32_t)(i)) & (u_int32_t)IN_CLASSC_NET) == (u_int32_t)0xc0586300)
#endif /* __APPLE__ */
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

/*
 * sockaddr_in with scope ID field; this is used internally to keep
 * track of scoped route entries in the routing table.  The fact that
 * such a value is embedded in the structure is an artifact of the
 * current implementation which could change in future.
 */
struct sockaddr_inifscope {
	__uint8_t       sin_len;
	sa_family_t     sin_family;
	in_port_t       sin_port;
	struct  in_addr sin_addr;
	/*
	 * To avoid possible conflict with an overlaid sockaddr_inarp
	 * having sin_other set to SIN_PROXY, we use the first 4-bytes
	 * of sin_zero since sin_srcaddr is one of the unused fields
	 * in sockaddr_inarp.
	 */
	union {
		char    sin_zero[8];
		struct {
			__uint32_t      ifscope;
		} _in_index;
	} un;
#define sin_scope_id    un._in_index.ifscope
};

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)

/*
 * Options for use with [gs]etsockopt at the IP level.
 * First word of comment is data type; bool is stored in int.
 */
#define IP_NO_IFT_CELLULAR      6969 /* for internal use only */
#define IP_NO_IFT_PDP           IP_NO_IFT_CELLULAR /* deprecated */
#define IP_OUT_IF               9696 /* for internal use only */

#ifdef BSD_KERNEL_PRIVATE
#define CTL_IPPROTO_NAMES { \
    { "ip", CTLTYPE_NODE }, \
    { "icmp", CTLTYPE_NODE }, \
    { "igmp", CTLTYPE_NODE }, \
    { "ggp", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "tcp", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { "egp", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "pup", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "udp", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "idp", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "ipsec", CTLTYPE_NODE }, \
}

#define IPCTL_NAMES { \
    { 0, 0 }, \
    { "forwarding", CTLTYPE_INT }, \
    { "redirect", CTLTYPE_INT }, \
    { "ttl", CTLTYPE_INT }, \
    { "mtu", CTLTYPE_INT }, \
    { "rtexpire", CTLTYPE_INT }, \
    { "rtminexpire", CTLTYPE_INT }, \
    { "rtmaxcache", CTLTYPE_INT }, \
    { "sourceroute", CTLTYPE_INT }, \
    { "directed-broadcast", CTLTYPE_INT }, \
    { "intr-queue-maxlen", CTLTYPE_INT }, \
    { "intr-queue-drops", CTLTYPE_INT }, \
    { "stats", CTLTYPE_STRUCT }, \
    { "accept_sourceroute", CTLTYPE_INT }, \
    { "fastforwarding", CTLTYPE_INT }, \
    { "keepfaith", CTLTYPE_INT }, \
    { "gifttl", CTLTYPE_INT }, \
}
#endif /* BSD_KERNEL_PRIVATE */

#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

/* INET6 stuff */
#define __KAME_NETINET_IN_PRIVATE_H_INCLUDED_
#include <netinet6/in6_private.h>
#undef __KAME_NETINET_IN_PRIVATE_H_INCLUDED_

/*
 * Minimal sized structure to hold an IPv4 or IPv6 socket address
 * as sockaddr_storage can waste memory
 */

union sockaddr_in_4_6 {
	struct sockaddr             sa;
	struct __sockaddr_header    sah;
	struct sockaddr_in          sin;
	struct sockaddr_in6         sin6;
};
#define CLAT46_HDR_EXPANSION_OVERHD     (sizeof(struct ip6_hdr) - sizeof(struct ip))

/*
 * Recommended DiffServ Code Point values
 */

#define _DSCP_DF        0       /* RFC 2474 */

#define _DSCP_CS0       0       /* RFC 2474 */
#define _DSCP_CS1       8       /* RFC 2474 */
#define _DSCP_CS2       16      /* RFC 2474 */
#define _DSCP_CS3       24      /* RFC 2474 */
#define _DSCP_CS4       32      /* RFC 2474 */
#define _DSCP_CS5       40      /* RFC 2474 */
#define _DSCP_CS6       48      /* RFC 2474 */
#define _DSCP_CS7       56      /* RFC 2474 */

#define _DSCP_EF        46      /* RFC 2474 */
#define _DSCP_VA        44      /* RFC 5865 */

#define _DSCP_AF11      10      /* RFC 2597 */
#define _DSCP_AF12      12      /* RFC 2597 */
#define _DSCP_AF13      14      /* RFC 2597 */
#define _DSCP_AF21      18      /* RFC 2597 */
#define _DSCP_AF22      20      /* RFC 2597 */
#define _DSCP_AF23      22      /* RFC 2597 */
#define _DSCP_AF31      26      /* RFC 2597 */
#define _DSCP_AF32      28      /* RFC 2597 */
#define _DSCP_AF33      30      /* RFC 2597 */
#define _DSCP_AF41      34      /* RFC 2597 */
#define _DSCP_AF42      36      /* RFC 2597 */
#define _DSCP_AF43      38      /* RFC 2597 */

#define _DSCP_52        52      /* Wi-Fi WMM Certification: Sigma */

#define _MAX_DSCP       63      /* coded on 6 bits */

#ifndef XNU_PLATFORM_DriverKit
#ifdef KERNEL
#ifdef BSD_KERNEL_PRIVATE
#include <mach/boolean.h>

struct ip;
struct ifnet;
struct mbuf;

extern boolean_t in_broadcast(struct in_addr, struct ifnet *);
extern boolean_t in_canforward(struct in_addr);
extern u_int32_t in_netof(struct in_addr);

extern uint32_t os_cpu_in_cksum_mbuf(struct mbuf *m, int len, int off,
    uint32_t initial_sum);

extern uint16_t inet_cksum(struct mbuf *, uint32_t, uint32_t, uint32_t);
extern uint16_t inet_cksum_buffer(const void *__sized_by(__len), uint32_t, uint32_t, uint32_t __len);
extern uint16_t in_addword(uint16_t, uint16_t);
extern uint16_t in_pseudo(uint32_t, uint32_t, uint32_t);
extern uint16_t in_pseudo64(uint64_t, uint64_t, uint64_t);
extern uint16_t in_cksum_hdr_opt(const struct ip *);
extern uint16_t ip_cksum_hdr_dir(struct mbuf *, uint32_t, int);
extern uint16_t ip_cksum_hdr_dir_buffer(const void *__sized_by(__len), uint32_t, uint32_t __len, int);
extern uint32_t in_finalize_cksum(struct mbuf *, uint32_t, uint32_t);
extern uint16_t b_sum16(const void *__sized_by(len)buf, int len);
#if DEBUG || DEVELOPMENT
extern uint32_t in_cksum_mbuf_ref(struct mbuf *, int, int, uint32_t);
#endif /* DEBUG || DEVELOPMENT */

extern int in_getconninfo(struct socket *, sae_connid_t, uint32_t *,
    uint32_t *, int32_t *, user_addr_t, socklen_t *, user_addr_t, socklen_t *,
    uint32_t *, user_addr_t, uint32_t *);
extern struct in_ifaddr * inifa_ifpwithflag(struct ifnet *, uint32_t);
extern struct in_ifaddr * inifa_ifpclatv4(struct ifnet *);

#define in_cksum(_m, _l)                        \
    inet_cksum(_m, 0, 0, _l)
#define in_cksum_buffer(_b, _l)                 \
    inet_cksum_buffer(_b, 0, 0, _l)
#define ip_cksum_hdr_in(_m, _l)                 \
    ip_cksum_hdr_dir(_m, _l, 0)
#define ip_cksum_hdr_out(_m, _l)                \
    ip_cksum_hdr_dir(_m, _l, 1)

#define in_cksum_hdr(_ip)                       \
    (~b_sum16(_ip, sizeof (struct ip)) & 0xffff)

#define in_cksum_offset(_m, _o)         \
    ((void) in_finalize_cksum(_m, _o, CSUM_DELAY_IP))
#define in_delayed_cksum(_m)            \
    ((void) in_finalize_cksum(_m, 0, CSUM_DELAY_DATA))
#define in_delayed_cksum_offset(_m, _o) \
    ((void) in_finalize_cksum(_m, _o, CSUM_DELAY_DATA))

#define in_hosteq(s, t) ((s).s_addr == (t).s_addr)
#define in_nullhost(x)  ((x).s_addr == INADDR_ANY)
#define in_allhosts(x)  ((x).s_addr == htonl(INADDR_ALLHOSTS_GROUP))

#define SIN(s)          ((struct sockaddr_in *)(void *)s)
#define satosin(sa)     SIN(sa)
#define sintosa(sin)    ((struct sockaddr *)(void *)(sin))
#define SINIFSCOPE(s)   ((struct sockaddr_inifscope *)(void *)(s))

#define IPTOS_UNSPEC                    (-1)    /* TOS byte not set */
#define IPTOS_MASK                      0xFF    /* TOS byte mask */
#endif /* BSD_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
/* exported for ApplicationFirewall */
extern int in_localaddr(struct in_addr);
extern int inaddr_local(struct in_addr);

extern char     *inet_ntoa(struct in_addr);
extern char     *inet_ntoa_r(struct in_addr ina, char *buf,
    size_t buflen);
extern int      inet_pton(int af, const char *, void *);
#endif /* KERNEL_PRIVATE */

#endif /* KERNEL */
#endif /* XNU_PLATFORM_DriverKit */

#endif /* _NETINET_IN_PRIVATE_H_ */
