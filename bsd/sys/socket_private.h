/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1985, 1986, 1988, 1993, 1994
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
 *	@(#)socket.h	8.4 (Berkeley) 2/21/94
 * $FreeBSD: src/sys/sys/socket.h,v 1.39.2.7 2001/07/03 11:02:01 ume Exp $
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef _SYS_SOCKET_PRIVATE_H_
#define _SYS_SOCKET_PRIVATE_H_

#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/constrained_ctypes.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <uuid/uuid.h>

#ifdef XNU_KERNEL_PRIVATE
#include <kern/assert.h>
#include <kern/kalloc.h>
#endif /* XNU_KERNEL_PRIVATE */

/*
 * Option flags per-socket.
 */
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#ifdef __APPLE__
#define SO_NOWAKEFROMSLEEP      0x10000 /* Don't wake for traffic to this socket */
#define SO_NOAPNFALLBK          0x20000 /* Don't attempt APN fallback for the socket */
#define SO_TIMESTAMP_CONTINUOUS 0x40000 /* Continuous monotonic timestamp on rcvd dgram */

/*
 * Additional options, not kept in so_options.
 */
#define SO_RESTRICTIONS 0x1081          /* APPLE: deny flag set */
#define  SO_RESTRICT_DENY_IN    0x1     /* deny inbound (trapdoor) */
#define  SO_RESTRICT_DENY_OUT   0x2     /* deny outbound (trapdoor) */
#define  SO_RESTRICT_DENY_CELLULAR 0x4  /* deny use of cellular (trapdoor) */
#define  SO_RESTRICT_DENY_EXPENSIVE 0x8 /* deny use of expensive if (trapdoor) */
#define  SO_RESTRICT_DENY_CONSTRAINED 0x10 /* deny use of expensive if (trapdoor) */
#endif

#define SO_EXECPATH     0x1085          /* Application Firewall Socket option */

/*
 * Traffic service class definitions (lowest to highest):
 *
 * SO_TC_BK_SYS
 *	"Background System-Initiated", high delay tolerant, high loss
 *	tolerant, elastic flow, variable size & long-lived.  E.g: system-
 *	initiated iCloud synching or Time Capsule backup, for which there
 *	is no progress feedbacks.
 *
 * SO_TC_BK
 *	"Background", user-initiated, high delay tolerant, high loss tolerant,
 *	elastic flow, variable size.  E.g. user-initiated iCloud synching or
 *	Time Capsule backup; or traffics of background applications, for which
 *	there is some progress feedbacks.
 *
 * SO_TC_BE
 *	"Best Effort", unclassified/standard.  This is the default service
 *	class; pretty much a mix of everything.
 *
 * SO_TC_RD
 *	"Responsive Data", a notch higher than "Best Effort", medium delay
 *	tolerant, elastic & inelastic flow, bursty, long-lived.  E.g. email,
 *	instant messaging, for which there is a sense of interactivity and
 *	urgency (user waiting for output).
 *
 * SO_TC_OAM
 *	"Operations, Administration, and Management", medium delay tolerant,
 *	low-medium loss tolerant, elastic & inelastic flows, variable size.
 *	E.g. VPN tunnels.
 *
 * SO_TC_AV
 *	"Multimedia Audio/Video Streaming", medium delay tolerant, low-medium
 *	loss tolerant, elastic flow, constant packet interval, variable rate &
 *	size.  E.g. AirPlay playback (both video and audio).
 *
 * SO_TC_RV
 *	"Responsive Multimedia Audio/Video", low delay tolerant, low-medium
 *	loss tolerant, elastic flow, variable packet interval, rate and size.
 *	E.g. AirPlay mirroring, screen sharing.
 *
 * SO_TC_VI
 *	"Interactive Video", low delay tolerant, low-medium loss tolerant,
 *	elastic flow, constant packet interval, variable rate & size.  E.g.
 *	FaceTime video.
 *
 * SO_TC_VO
 *	"Interactive Voice", low delay tolerant, low loss tolerant, inelastic
 *	flow, constant packet rate, somewhat fixed size.  E.g. VoIP including
 *	FaceTime audio.
 *
 * SO_TC_CTL
 *	"Network Control", low delay tolerant, low loss tolerant, inelastic
 *	flow, rate is bursty but short, variable size.  E.g. DNS queries;
 *	certain types of locally-originated ICMP, ICMPv6; IGMP/MLD join/leave,
 *	ARP.
 */
#define SO_TRAFFIC_CLASS        0x1086  /* Traffic service class (int) */
#define SO_TC_BK_SYS    100             /* lowest class */
#define SO_TC_BK        200
#define SO_TC_BE        0
#define SO_TC_RD        300
#define SO_TC_OAM       400
#define SO_TC_AV        500
#define SO_TC_RV        600
#define SO_TC_VI        700
#define SO_TC_VO        800
#define SO_TC_CTL       900             /* highest class */
#define SO_TC_MAX       10              /* Total # of traffic classes */
#ifdef XNU_KERNEL_PRIVATE
#define _SO_TC_BK       1               /* deprecated */
#define _SO_TC_VI       2               /* deprecated */
#define _SO_TC_VO       3               /* deprecated */
#define _SO_TC_MAX      4               /* deprecated */

#define SO_VALID_TC(c)                                                  \
	(c == SO_TC_BK_SYS || c == SO_TC_BK || c == SO_TC_BE ||         \
	c == SO_TC_RD || c == SO_TC_OAM || c == SO_TC_AV ||             \
	c == SO_TC_RV || c == SO_TC_VI || c == SO_TC_VO ||              \
	c == SO_TC_CTL || c == SO_TC_NETSVC_SIG)

#define SO_TC_UNSPEC    ((int)-1)               /* Traffic class not specified */

#define SO_TC_SIG       SO_TC_VI                /* to be removed XXX */

#define SOTCIX_BK_SYS   0
#define SOTCIX_BK       1
#define SOTCIX_BE       2
#define SOTCIX_RD       3
#define SOTCIX_OAM      4
#define SOTCIX_AV       5
#define SOTCIX_RV       6
#define SOTCIX_VI       7
#define SOTCIX_VO       8
#define SOTCIX_CTL      9
#endif /* XNU_KERNEL_PRIVATE */

/* Background socket configuration flags  */
#define TRAFFIC_MGT_SO_BACKGROUND       0x0001  /* background socket */
#define TRAFFIC_MGT_TCP_RECVBG          0x0002  /* Only TCP sockets, receiver throttling */

#define SO_RECV_TRAFFIC_CLASS   0x1087          /* Receive traffic class (bool) */
#define SO_TRAFFIC_CLASS_DBG    0x1088          /* Debug traffic class (struct so_tcdbg) */
#define SO_OPTION_UNUSED_0      0x1089          /* Traffic class statistics */
#define SO_PRIVILEGED_TRAFFIC_CLASS 0x1090      /* Privileged traffic class (bool) */
#define SO_DEFUNCTIT    0x1091          /* Defunct a socket (only in internal builds) */
#define SO_DEFUNCTOK    0x1100          /* can be defunct'd */
#define SO_ISDEFUNCT    0x1101          /* get defunct status */

#define SO_OPPORTUNISTIC        0x1102  /* deprecated; use SO_TRAFFIC_CLASS */

/*
 * SO_FLUSH flushes any unsent data generated by a given socket.  It takes
 * an integer parameter, which can be any of the SO_TC traffic class values,
 * or the special SO_TC_ALL value.
 */
#define SO_FLUSH        0x1103          /* flush unsent data (int) */
#define  SO_TC_ALL      (-1)

#define SO_RECV_ANYIF   0x1104          /* unrestricted inbound processing */
#define SO_TRAFFIC_MGT_BACKGROUND       0x1105  /* Background traffic management */

#define SO_FLOW_DIVERT_TOKEN    0x1106  /* flow divert token */

#define SO_DELEGATED            0x1107  /* set socket as delegate (pid_t) */
#define SO_DELEGATED_UUID       0x1108  /* set socket as delegate (uuid_t) */
#define SO_NECP_ATTRIBUTES      0x1109  /* NECP socket attributes (domain, account, etc.) */
#define SO_CFIL_SOCK_ID         0x1110  /* get content filter socket ID (cfil_sock_id_t) */
#define SO_NECP_CLIENTUUID      0x1111  /* NECP Client uuid */

#define SO_AWDL_UNRESTRICTED    0x1113  /* try to use AWDL in restricted mode */
#define SO_EXTENDED_BK_IDLE     0x1114  /* extended time to keep socket idle after app is suspended (int) */
#define SO_MARK_CELLFALLBACK    0x1115  /* Mark as initiated by cell fallback */

#define SO_QOSMARKING_POLICY_OVERRIDE   0x1117  /* int */
#define SO_INTCOPROC_ALLOW              0x1118  /* Try to use internal co-processor interfaces. */

#define SO_NECP_LISTENUUID         0x1120  /* NECP client UUID for listener */
#define SO_MPKL_SEND_INFO          0x1122  /* (struct so_mpkl_send_info) */
#define SO_STATISTICS_EVENT        0x1123  /* int64 argument, an event in statistics collection */
#define SO_WANT_KEV_SOCKET_CLOSED  0x1124  /* want delivery of KEV_SOCKET_CLOSED (int) */
#define SO_MARK_KNOWN_TRACKER      0x1125  /* Mark as a connection to a known tracker */
#define SO_MARK_KNOWN_TRACKER_NON_APP_INITIATED 0x1126  /* Mark tracker connection to be non-app initiated */
#define SO_MARK_WAKE_PKT           0x1127  /* Mark next packet as a wake packet, one shot (int) */
#define SO_RECV_WAKE_PKT           0x1128  /* Receive wake packet indication as ancillary data (int) */
#define SO_MARK_APPROVED_APP_DOMAIN 0x1129 /* Mark connection as being for an approved associated app domain */
#define SO_FALLBACK_MODE           0x1130  /* Indicates the mode of fallback used */

#define SO_MARK_CELLFALLBACK_UUID  0x1132  /* Mark as initiated by cell fallback using UUID of the connection */
#define SO_APPLICATION_ID          0x1133  /* ID of attributing app - so_application_id_t */
                                           /* 0x1134 is SO_BINDTODEVICE, see socket.h */
#define SO_MARK_DOMAIN_INFO_SILENT 0x1135  /* Domain information should be silently withheld */

struct so_mark_cellfallback_uuid_args {
	uuid_t flow_uuid;
	int flow_cellfallback;
};

typedef struct {
	uid_t               uid;
	uuid_t              effective_uuid;
	uid_t               persona_id;
} so_application_id_t;

#define _NET_SERVICE_TYPE_COUNT 9
#define _NET_SERVICE_TYPE_UNSPEC        ((int)-1)

#define IS_VALID_NET_SERVICE_TYPE(c)                            \
	(c >= NET_SERVICE_TYPE_BE && c <= NET_SERVICE_TYPE_RD)

extern const int sotc_by_netservicetype[_NET_SERVICE_TYPE_COUNT];

/*
 * Facility to pass Network Service Type values using SO_TRAFFIC_CLASS
 * Mostly useful to simplify implementation of frameworks to adopt the new
 * Network Service Type values for Signaling.
 */
#define SO_TC_NET_SERVICE_OFFSET        10000
#define SO_TC_NETSVC_SIG        (SO_TC_NET_SERVICE_OFFSET + NET_SERVICE_TYPE_SIG)

#ifdef __APPLE__

#ifdef KERNEL_PRIVATE
#define SONPX_MASK_VALID                (SONPX_SETOPTSHUT)
#define IS_SO_TC_BACKGROUND(_tc_) ((_tc_) == SO_TC_BK || (_tc_) == SO_TC_BK_SYS)
#define IS_SO_TC_BACKGROUNDSYSTEM(_tc_) ((_tc_) == SO_TC_BK_SYS)
#endif /* KERNEL_PRIVATE */

#endif

/*
 * Address families.
 */
#define AF_AFP  36                      /* Used by AFP */
#define AF_MULTIPATH    39
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

/*
 * Protocol families, same as address families for now.
 */
#define PF_AFP          AF_AFP
#define PF_MULTIPATH    AF_MULTIPATH

#ifdef KERNEL_PRIVATE
#define PF_BRIDGE       ((uint32_t)0x62726467)  /* 'brdg' */
#define PF_NULL         ((uint32_t)0x6e756c6c)  /* 'null' */

#define CTL_NET_NAMES { \
	{ 0, 0 }, \
	{ "local", CTLTYPE_NODE }, \
	{ "inet", CTLTYPE_NODE }, \
	{ "implink", CTLTYPE_NODE }, \
	{ "pup", CTLTYPE_NODE }, \
	{ "chaos", CTLTYPE_NODE }, \
	{ "xerox_ns", CTLTYPE_NODE }, \
	{ "iso", CTLTYPE_NODE }, \
	{ "emca", CTLTYPE_NODE }, \
	{ "datakit", CTLTYPE_NODE }, \
	{ "ccitt", CTLTYPE_NODE }, \
	{ "ibm_sna", CTLTYPE_NODE }, \
	{ "decnet", CTLTYPE_NODE }, \
	{ "dec_dli", CTLTYPE_NODE }, \
	{ "lat", CTLTYPE_NODE }, \
	{ "hylink", CTLTYPE_NODE }, \
	{ "appletalk", CTLTYPE_NODE }, \
	{ "route", CTLTYPE_NODE }, \
	{ "link_layer", CTLTYPE_NODE }, \
	{ "xtp", CTLTYPE_NODE }, \
	{ "coip", CTLTYPE_NODE }, \
	{ "cnt", CTLTYPE_NODE }, \
	{ "rtip", CTLTYPE_NODE }, \
	{ "ipx", CTLTYPE_NODE }, \
	{ "sip", CTLTYPE_NODE }, \
	{ "pip", CTLTYPE_NODE }, \
	{ 0, 0 }, \
	{ "ndrv", CTLTYPE_NODE }, \
	{ "isdn", CTLTYPE_NODE }, \
	{ "key", CTLTYPE_NODE }, \
	{ "inet6", CTLTYPE_NODE }, \
	{ "natm", CTLTYPE_NODE }, \
	{ "sys", CTLTYPE_NODE }, \
	{ "netbios", CTLTYPE_NODE }, \
	{ "ppp", CTLTYPE_NODE }, \
	{ "hdrcomplete", CTLTYPE_NODE }, \
	{ "vsock", CTLTYPE_NODE }, \
}
#endif /* KERNEL_PRIVATE */

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
/*
 * PF_ROUTE - Routing table
 *
 * Three additional levels are defined:
 *	Fourth: address family, 0 is wildcard
 *	Fifth: type of info, defined below
 *	Sixth: flag(s) to mask with for NET_RT_FLAGS
 */
#define NET_RT_DUMPX            8       /* private */
#define NET_RT_DUMPX_FLAGS      9       /* private */
#define NET_RT_STAT_64          11      /* private */
#endif /* (_POSIX_C_SOURCE && !_DARWIN_C_SOURCE) */

/* These are supported values for SO_STATISTICS_EVENT */
#define SO_STATISTICS_EVENT_ENTER_CELLFALLBACK (1 << 0)
#define SO_STATISTICS_EVENT_EXIT_CELLFALLBACK  (1 << 1)
#define SO_STATISTICS_EVENT_RESERVED_1         (1 << 2)
#define SO_STATISTICS_EVENT_RESERVED_2         (1 << 3)


#ifdef KERNEL_PRIVATE
#define CTL_NET_RT_NAMES { \
	{ 0, 0 }, \
	{ "dump", CTLTYPE_STRUCT }, \
	{ "flags", CTLTYPE_STRUCT }, \
	{ "iflist", CTLTYPE_STRUCT }, \
	{ "stat", CTLTYPE_STRUCT }, \
	{ "trash", CTLTYPE_INT }, \
	{ "iflist2", CTLTYPE_STRUCT }, \
	{ "dump2", CTLTYPE_STRUCT }, \
	{ "dumpx", CTLTYPE_STRUCT }, \
	{ "dumpx_flags", CTLTYPE_STRUCT }, \
}

#endif /* KERNEL_PRIVATE */

/*
 * Extended version for sendmsg_x() and recvmsg_x() calls
 *
 * For recvmsg_x(), the size of the data received is given by the field
 * msg_datalen.
 *
 * For sendmsg_x(), the size of the data to send is given by the length of
 * the iovec array -- like sendmsg(). The field msg_datalen is ignored.
 */
struct msghdr_x {
	void            *__sized_by(msg_namelen) msg_name; /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	struct iovec    *msg_iov;       /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	void            *__sized_by(msg_controllen) msg_control; /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
	size_t          msg_datalen;    /* byte length of buffer in msg_iov */
};

#ifdef XNU_KERNEL_PRIVATE
/*
 * In-kernel representation of "struct msghdr" from
 * userspace. Has enough precision for 32-bit or
 * 64-bit clients, but does not need to be packed.
 */

struct user_msghdr {
	user_addr_t     msg_name;               /* optional address */
	socklen_t       msg_namelen;            /* size of address */
	vm_address_t    msg_iov;                /* scatter/gather array */
	int             msg_iovlen;             /* # elements in msg_iov */
	user_addr_t     msg_control;            /* ancillary data, see below */
	socklen_t       msg_controllen;         /* ancillary data buffer len */
	int             msg_flags;              /* flags on received message */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user_msghdr, user_msghdr);

/*
 * LP64 user version of struct msghdr.
 * WARNING - keep in sync with struct msghdr
 */

struct user64_msghdr {
	user64_addr_t   msg_name;               /* optional address */
	socklen_t       msg_namelen;            /* size of address */
	user64_addr_t   msg_iov;                /* scatter/gather array */
	int             msg_iovlen;             /* # elements in msg_iov */
	user64_addr_t   msg_control;            /* ancillary data, see below */
	socklen_t       msg_controllen;         /* ancillary data buffer len */
	int             msg_flags;              /* flags on received message */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user64_msghdr, user64_msghdr);

/*
 * ILP32 user version of struct msghdr.
 * WARNING - keep in sync with struct msghdr
 */

struct user32_msghdr {
	user32_addr_t   msg_name;       /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	user32_addr_t   msg_iov;        /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	user32_addr_t   msg_control;    /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user32_msghdr, user32_msghdr);

/*
 * In-kernel representation of "struct msghdr_x" from
 * userspace. Has enough precision for 32-bit or
 * 64-bit clients, but does not need to be packed.
 */

struct user_msghdr_x {
	user_addr_t     msg_name;       /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	vm_address_t    msg_iov;        /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	user_addr_t     msg_control;    /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
	size_t          msg_datalen;    /* byte length of buffer in msg_iov */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user_msghdr_x, user_msghdr_x);


/*
 * LP64 user version of struct msghdr_x
 * WARNING - keep in sync with struct msghdr_x
 */

struct user64_msghdr_x {
	user64_addr_t   msg_name;       /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	user64_addr_t   msg_iov;        /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	user64_addr_t   msg_control;    /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
	user64_size_t   msg_datalen;    /* byte length of buffer in msg_iov */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user64_msghdr_x, user64_msghdr_x);

/*
 * ILP32 user version of struct msghdr_x
 * WARNING - keep in sync with struct msghdr_x
 */

struct user32_msghdr_x {
	user32_addr_t   msg_name;       /* optional address */
	socklen_t       msg_namelen;    /* size of address */
	user32_addr_t   msg_iov;        /* scatter/gather array */
	int             msg_iovlen;     /* # elements in msg_iov */
	user32_addr_t   msg_control;    /* ancillary data, see below */
	socklen_t       msg_controllen; /* ancillary data buffer len */
	int             msg_flags;      /* flags on received message */
	user32_size_t   msg_datalen;    /* byte length of buffer in msg_iov */
};
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user32_msghdr_x, user32_msghdr_x);

/*
 * In-kernel representation of "struct sa_endpoints" from
 * userspace. Has enough precision for 32-bit or
 * 64-bit clients, but does not need to be packed.
 */

struct user_sa_endpoints {
	unsigned int    sae_srcif;      /* optional source interface */
	user_addr_t     sae_srcaddr;    /* optional source address */
	socklen_t       sae_srcaddrlen; /* size of source address */
	user_addr_t     sae_dstaddr;    /* destination address */
	socklen_t       sae_dstaddrlen; /* size of destination address */
};

/*
 * LP64 user version of struct sa_endpoints
 * WARNING - keep in sync with struct sa_endpoints
 */

struct user64_sa_endpoints {
	unsigned int    sae_srcif;      /* optional source interface */
	user64_addr_t   sae_srcaddr;    /* optional source address */
	socklen_t       sae_srcaddrlen; /* size of source address */
	user64_addr_t   sae_dstaddr;    /* destination address */
	socklen_t       sae_dstaddrlen; /* size of destination address */
};

/*
 * ILP32 user version of struct sa_endpoints
 * WARNING - keep in sync with struct sa_endpoints
 */

struct user32_sa_endpoints {
	unsigned int    sae_srcif;      /* optional source interface */
	user32_addr_t   sae_srcaddr;    /* optional source address */
	socklen_t       sae_srcaddrlen; /* size of source address */
	user32_addr_t   sae_dstaddr;    /* destination address */
	socklen_t       sae_dstaddrlen; /* size of destination address */
};

#endif /* XNU_KERNEL_PRIVATE */

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
#ifdef __APPLE__
#ifndef __APPLE_API_OBSOLETE
#define MSG_WAITSTREAM  0x200           /* wait up to full request.. may return partial */
#endif
#endif
#ifdef KERNEL_PRIVATE
#define MSG_COMPAT      0x8000          /* deprecated */
#define MSG_NBIO        0x20000         /* FIONBIO mode, used by fifofs */
#define MSG_SKIPCFIL    0x40000         /* skip pass content filter */
#endif

#define SCM_TIMESTAMP_CONTINUOUS        0x07    /* timestamp (uint64_t) */
#define SCM_MPKL_SEND_INFO              0x08    /* send info for multi-layer packet logging (struct so_mpkl_send_info) */
#define SCM_MPKL_RECV_INFO              0x09    /* receive info for multi-layer packet logging (struct so_mpkl_recv_info */

#ifdef KERNEL_PRIVATE
/*
 * 4.3 compat sockaddr (deprecated)
 */
struct osockaddr {
	__uint16_t      sa_family;      /* address family */
	char    sa_data[14];            /* up to 14 bytes of direct address */
};

/*
 * 4.3-compat message header (deprecated)
 */
struct omsghdr {
	void            *msg_name;              /* optional address */
	socklen_t       msg_namelen;            /* size of address */
	struct  iovec   *msg_iov;               /* scatter/gather array */
	int             msg_iovlen;             /* # elements in msg_iov */
	void            *msg_accrights;         /* access rights sent/rcvd */
	int             msg_accrightslen;
};

#define SA(s)   ((struct sockaddr *)(void *)(s))
#endif /* KERNEL_PRIVATE */


/*
 * Structure for SIOCGASSOCIDS
 */
struct so_aidreq {
	__uint32_t      sar_cnt;        /* number of associations */
	sae_associd_t   *sar_aidp;      /* array of association IDs */
};

#ifdef BSD_KERNEL_PRIVATE
struct so_aidreq32 {
	__uint32_t      sar_cnt;
	user32_addr_t   sar_aidp;
};

struct so_aidreq64 {
	__uint32_t      sar_cnt;
	user64_addr_t   sar_aidp __attribute__((aligned(8)));
};
#endif /* BSD_KERNEL_PRIVATE */

/*
 * Structure for SIOCGCONNIDS
 */
struct so_cidreq {
	sae_associd_t   scr_aid;        /* association ID */
	__uint32_t      scr_cnt;        /* number of connections */
	sae_connid_t    *scr_cidp;      /* array of connection IDs */
};

#ifdef BSD_KERNEL_PRIVATE
struct so_cidreq32 {
	sae_associd_t   scr_aid;
	__uint32_t      scr_cnt;
	user32_addr_t   scr_cidp;
};

struct so_cidreq64 {
	sae_associd_t   scr_aid;
	__uint32_t      scr_cnt;
	user64_addr_t   scr_cidp __attribute__((aligned(8)));
};
#endif /* BSD_KERNEL_PRIVATE */

/*
 * Structure for SIOCGCONNINFO
 */
struct so_cinforeq {
	sae_connid_t    scir_cid;               /* connection ID */
	__uint32_t      scir_flags;             /* see flags below */
	__uint32_t      scir_ifindex;           /* (last) outbound interface */
	__int32_t       scir_error;             /* most recent error */
	struct sockaddr *scir_src;              /* source address */
	socklen_t       scir_src_len;           /* source address len */
	struct sockaddr *scir_dst;              /* destination address */
	socklen_t       scir_dst_len;           /* destination address len */
	__uint32_t      scir_aux_type;          /* aux data type (CIAUX) */
	void            *scir_aux_data;         /* aux data */
	__uint32_t      scir_aux_len;           /* aux data len */
};

#ifdef BSD_KERNEL_PRIVATE
struct so_cinforeq32 {
	sae_connid_t    scir_cid;
	__uint32_t      scir_flags;
	__uint32_t      scir_ifindex;
	__int32_t       scir_error;
	user32_addr_t   scir_src;
	socklen_t       scir_src_len;
	user32_addr_t   scir_dst;
	socklen_t       scir_dst_len;
	__uint32_t      scir_aux_type;
	user32_addr_t   scir_aux_data;
	__uint32_t      scir_aux_len;
};

struct so_cinforeq64 {
	sae_connid_t    scir_cid;
	__uint32_t      scir_flags;
	__uint32_t      scir_ifindex;
	__int32_t       scir_error;
	user64_addr_t   scir_src        __attribute__((aligned(8)));
	socklen_t       scir_src_len;
	user64_addr_t   scir_dst        __attribute__((aligned(8)));
	socklen_t       scir_dst_len;
	__uint32_t      scir_aux_type;
	user64_addr_t   scir_aux_data   __attribute__((aligned(8)));
	__uint32_t      scir_aux_len;
};

#endif /* BSD_KERNEL_PRIVATE */

/* valid connection info flags */
#define CIF_CONNECTING          0x1     /* connection was attempted */
#define CIF_CONNECTED           0x2     /* connection is established */
#define CIF_DISCONNECTING       0x4     /* disconnection was attempted */
#define CIF_DISCONNECTED        0x8     /* has been disconnected */
#define CIF_BOUND_IF            0x10    /* bound to an interface */
#define CIF_BOUND_IP            0x20    /* bound to a src address */
#define CIF_BOUND_PORT          0x40    /* bound to a src port */
#define CIF_PREFERRED           0x80    /* connection is primary/preferred */
#define CIF_MP_CAPABLE          0x100   /* supports multipath protocol */
#define CIF_MP_READY            0x200   /* multipath protocol confirmed */
#define CIF_MP_DEGRADED         0x400   /* has lost its multipath capability */
#define CIF_MP_ACTIVE           0x800   /* this is the active subflow */
#define CIF_MP_V1               0x1000  /* MPTCP v1 is used */

/* valid connection info auxiliary data types */
#define CIAUX_TCP       0x1     /* TCP auxiliary data (conninfo_tcp_t) */
#define CIAUX_MPTCP     0x2     /* MPTCP auxiliary data (conninfo_multipathtcp) */

/*
 * Structure for SIOC{S,G}CONNORDER
 */
struct so_cordreq {
	sae_connid_t    sco_cid;                /* connection ID */
	__uint32_t      sco_rank;               /* rank (0 means unspecified) */
};

/*
 * Common structure for KEV_NETPOLICY_SUBCLASS
 */
struct netpolicy_event_data {
	__uint64_t      eupid;          /* effective unique PID */
	__uint64_t      epid;           /* effective PID */
	uuid_t          euuid;          /* effective UUID */
};

/*
 * NETPOLICY_IFDENIED event structure
 */
struct kev_netpolicy_ifdenied {
	struct netpolicy_event_data     ev_data;
	__uint32_t ev_if_functional_type;
};

/*
 * KEV_NETPOLICY_NETDENIED event structure
 */
struct kev_netpolicy_netdenied {
	struct netpolicy_event_data     ev_data;
	__uint32_t ev_network_type;
};

/*
 * Network Service Type to DiffServ Code Point mapping
 */
struct netsvctype_dscp_map {
	int             netsvctype;
	u_int8_t        dscp; /* 6 bits diffserv code point */
};

/*
 * Multi-layer packet logging require SO_MPK_LOG to be set
 */
struct so_mpkl_send_info {
	uuid_t          mpkl_uuid;
	__uint8_t       mpkl_proto;     /* see net/multi_layer_pkt_log.h */
};

struct so_mpkl_recv_info {
	__uint32_t      mpkl_seq;
	__uint8_t       mpkl_proto;     /* see net/multi_layer_pkt_log.h */
};

#ifndef KERNEL
__BEGIN_DECLS

extern int peeloff(int s, sae_associd_t);
extern int socket_delegate(int, int, int, pid_t);

/*
 * recvmsg_x() is a system call similar to recvmsg(2) to receive
 * several datagrams at once in the array of message headers "msgp".
 *
 * recvmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 *
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 *
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that describe where to
 * store a datagram in a scatter gather locations of buffers -- see recvmsg(2).
 * On output the field "msg_datalen" gives the length of the received datagram.
 *
 * The field "msg_flags" must be set to zero on input. On output, "msg_flags"
 * may have MSG_TRUNC set to indicate the trailing portion of the datagram was
 * discarded because the datagram was larger than the buffer supplied.
 * recvmsg_x() returns as soon as a datagram is truncated.
 *
 * recvmsg_x() may return with less than "cnt" datagrams received based on
 * the low water mark and the amount of data pending in the socket buffer.
 *
 * recvmsg_x() returns the number of datagrams that have been received,
 * or -1 if an error occurred.
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t recvmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);

/*
 * sendmsg_x() is a system call similar to send(2) to send
 * several datagrams at once in the array of message headers "msgp".
 *
 * sendmsg_x() can be used only with protocols handlers that have been specially
 * modified to support sending and receiving several datagrams at once.
 *
 * The size of the array "msgp" is given by the argument "cnt".
 *
 * The "flags" arguments supports only the value MSG_DONTWAIT.
 *
 * Each member of "msgp" array is of type "struct msghdr_x".
 *
 * The "msg_iov" and "msg_iovlen" are input parameters that specify the
 * data to be sent in a scatter gather locations of buffers -- see sendmsg(2).
 *
 * sendmsg_x() fails with EMSGSIZE if the sum of the length of the datagrams
 * is greater than the high water mark.
 *
 * Address and ancillary data are not supported so the following fields
 * must be set to zero on input:
 *   "msg_name", "msg_namelen", "msg_control" and "msg_controllen".
 *
 * The field "msg_flags" and "msg_datalen" must be set to zero on input.
 *
 * sendmsg_x() returns the number of datagrams that have been sent,
 * or -1 if an error occurred.
 *
 * NOTE: This a private system call, the API is subject to change.
 */
ssize_t sendmsg_x(int s, const struct msghdr_x *msgp, u_int cnt, int flags);
__END_DECLS
#endif /* !KERNEL */
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

#endif /* !_SYS_SOCKET_PRIVATE_H_ */
