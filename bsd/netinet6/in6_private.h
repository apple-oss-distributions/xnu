/*
 * Copyright (c) 2008-2020 Apple Inc. All rights reserved.
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
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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
 */

#ifndef DRIVERKIT
#ifndef __KAME_NETINET_IN_PRIVATE_H_INCLUDED_
#error "do not include netinet6/in6_private.h directly, include netinet/in_private.h. " \
        " see RFC2553"
#endif
#endif /* DRIVERKIT */

#ifndef _NETINET6_IN6_PRIVATE_H_
#define _NETINET6_IN6_PRIVATE_H_

#include <netinet/in.h>
#include <stdint.h>
#ifdef BSD_KERNEL_PRIVATE
#include <sys/eventhandler.h>
#endif
#include <sys/types.h>
#include <uuid/uuid.h>

#ifndef XNU_PLATFORM_DriverKit

#ifdef KERNEL_PRIVATE
extern const struct sockaddr_in6 sa6_any;

extern const struct in6_addr in6mask0;
extern const struct in6_addr in6mask7;
extern const struct in6_addr in6mask16;
extern const struct in6_addr in6mask32;
extern const struct in6_addr in6mask64;
extern const struct in6_addr in6mask96;
extern const struct in6_addr in6mask128;

#define SIN6(s)         ((struct sockaddr_in6 *)(void *)s)
#define satosin6(sa)    SIN6(sa)
#define sin6tosa(sin6)  ((struct sockaddr *)(void *)(sin6))
#define SIN6IFSCOPE(s)  SIN6(s)
#endif /* KERNEL_PRIVATE */

struct route_in6_old {
	void            *ro_rt;
	uint32_t        ro_flags;
	struct sockaddr_in6 ro_dst;
};

#ifdef BSD_KERNEL_PRIVATE
#include <net/if_llatbl.h>
#include <sys/eventhandler.h>

/*
 * IP6 route structure
 *
 * A route consists of a destination address and a reference
 * to a routing entry.  These are often held by protocols
 * in their control blocks, e.g. inpcb.
 */
struct route_in6 {
	/*
	 * N.B: struct route_in6 must begin with ro_{rt,srcia,flags}
	 * because the code does some casts of a 'struct route_in6 *'
	 * to a 'struct route *'.
	 */
	struct rtentry  *ro_rt;
	struct  llentry *ro_lle;

	struct ifaddr   *ro_srcia;
	uint32_t        ro_flags;       /* route flags */
	struct sockaddr_in6 ro_dst;
};
#endif /* BSD_KERNEL_PRIVATE */

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)

/*
 * Options for use with [gs]etsockopt at the IPV6 level.
 * First word of comment is data type; bool is stored in int.
 */
#define IPV6_NO_IFT_CELLULAR    6969 /* for internal use only */
#define IPV6_OUT_IF             9696 /* for internal use only */

#ifdef BSD_KERNEL_PRIVATE
#define CTL_IPV6PROTO_NAMES { \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, \
    { "tcp6", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "udp6", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, \
    { "ip6", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, \
    { "ipsec6", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { "icmp6", CTLTYPE_NODE }, \
    { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
    { 0, 0 }, \
}
/*
 * Redefinition of mbuf flags
 */
#define M_AUTHIPHDR     M_PROTO2
#define M_DECRYPTED     M_PROTO3
#define M_AUTHIPDGM     M_PROTO5

struct cmsghdr;
struct mbuf;
struct ifnet;
struct in6_aliasreq;
struct lltable;

extern struct lltable * in6_lltattach(struct ifnet *ifp);
extern uint16_t in6_pseudo(const struct in6_addr *, const struct in6_addr *,
    uint32_t);
extern u_int16_t inet6_cksum(struct mbuf *, uint32_t, uint32_t, uint32_t);
extern u_int16_t inet6_cksum_buffer(const uint8_t *, uint32_t, uint32_t,
    uint32_t);

#define in6_cksum(_m, _n, _o, _l)                       \
    inet6_cksum(_m, _n, _o, _l)
#define in6_cksum_buffer(_b, _n, _o, _l)                \
    inet6_cksum_buffer(_b, _n, _o, _l)

extern int in6_addrscope(struct in6_addr *);
extern struct in6_ifaddr *in6_ifawithscope(struct ifnet *, struct in6_addr *);
extern struct in6_ifaddr *in6_ifawithifp(struct ifnet *, struct in6_addr *);

struct sockaddr;

extern void in6_sin6_2_sin(struct sockaddr_in *sin, struct sockaddr_in6 *sin6);
extern void in6_sin_2_v4mapsin6(struct sockaddr_in *sin,
    struct sockaddr_in6 *sin6);
extern void in6_sin6_2_sin_in_sock(struct sockaddr *nam);
extern int in6_sin_2_v4mapsin6_in_sock(struct sockaddr **nam);

extern uint32_t in6_finalize_cksum(struct mbuf *, uint32_t, int32_t,
    int32_t, uint32_t);

#define in6_delayed_cksum(_m)                   \
    ((void) in6_finalize_cksum(_m, 0, 0, -1, CSUM_DELAY_IPV6_DATA))
#define in6_delayed_cksum_offset(_m, _o, _s, _p)        \
    ((void) in6_finalize_cksum(_m, _o, _s, _p, CSUM_DELAY_IPV6_DATA))

/* IPv6 protocol events */
extern struct eventhandler_lists_ctxt in6_evhdlr_ctxt;
/*
 * XXX Avoid reordering the enum values below.
 * If the order is changed, please make sure
 * in6_event2kev_array is also changed to reflect the
 * change in order of the enums
 */
typedef enum {
	/* Address events */
	/*
	 * XXX To avoid duplicacy and also for correctness
	 * only report these for link local and stable addresses
	 * NOTE: Link local address can never be marked detached
	 * or duplicated.
	 */
	IN6_ADDR_MARKED_DUPLICATED,
	IN6_ADDR_MARKED_DETACHED,
	IN6_ADDR_MARKED_DEPRECATED,

	/* Expiry events */
	IN6_NDP_RTR_EXPIRY,
	IN6_NDP_PFX_EXPIRY,
	IN6_NDP_ADDR_EXPIRY,

	/* XXX DNS expiry needs to be handled by user-space */
	/* MAX */
	IN6_EVENT_MAX,
} in6_evhdlr_code_t;

struct in6_event2kev {
	in6_evhdlr_code_t       in6_event_code;
	uint32_t                in6_event_kev_subclass;
	uint32_t                in6_event_kev_code;
	const char              *in6_event_str;
};
extern struct in6_event2kev in6_event2kev_array[];
extern void in6_eventhdlr_callback(struct eventhandler_entry_arg, in6_evhdlr_code_t,
    struct ifnet *, struct in6_addr *, uint32_t);
extern void in6_event_enqueue_nwk_wq_entry(in6_evhdlr_code_t,
    struct ifnet *, struct in6_addr *, uint32_t);

typedef void (*in6_event_fn) (struct eventhandler_entry_arg, in6_evhdlr_code_t,
    struct ifnet *, struct in6_addr *, uint32_t);
EVENTHANDLER_DECLARE(in6_event, in6_event_fn);
#endif /* BSD_KERNEL_PRIVATE */

/* CLAT46 events */
typedef enum in6_clat46_evhdlr_code_t {
	IN6_CLAT46_EVENT_V4_FLOW,
	IN6_CLAT46_EVENT_V6_ADDR_CONFFAIL,
} in6_clat46_evhdlr_code_t;

struct kev_netevent_clat46_data {
	in6_clat46_evhdlr_code_t clat46_event_code;
	pid_t epid;
	uuid_t euuid;
};

#ifdef BSD_KERNEL_PRIVATE
/* CLAT46 events */
extern struct eventhandler_lists_ctxt in6_clat46_evhdlr_ctxt;
extern void in6_clat46_eventhdlr_callback(struct eventhandler_entry_arg,
    in6_clat46_evhdlr_code_t, pid_t, uuid_t);
extern void in6_clat46_event_enqueue_nwk_wq_entry(in6_clat46_evhdlr_code_t,
    pid_t, uuid_t);

typedef void (*in6_clat46_event_fn) (struct eventhandler_entry_arg, in6_clat46_evhdlr_code_t,
    pid_t, uuid_t);
EVENTHANDLER_DECLARE(in6_clat46_event, in6_clat46_event_fn);
#endif /* BSD_KERNEL_PRIVATE */

#ifdef KERNEL_PRIVATE
/* exporte for ApplicationFirewall */
extern int in6_localaddr(struct in6_addr *);
extern int in6addr_local(struct in6_addr *);
#endif /* KERNEL_PRIVATE */

#endif /* (_POSIX_C_SOURCE && !_DARWIN_C_SOURCE) */
#endif /* XNU_PLATFORM_DriverKit */

#endif /* !_NETINET6_IN6_PRIVATE_H_ */
