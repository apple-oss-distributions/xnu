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

#include <sys/param.h>
#include <sys/protosw.h>
#include <sys/systm.h>
#include <sys/sysctl.h>

#include <kern/bits.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/inp_log.h>
#include <netinet/in_pcb.h>

#include <netinet/udp_log.h>
#include <netinet/udp_var.h>

SYSCTL_NODE(_net_inet_udp, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "UDP");

#if (DEVELOPMENT || DEBUG)
#define UDP_LOG_ENABLE_DEFAULT \
    (ULEF_CONNECT | ULEF_DST_LOCAL | ULEF_DST_GW)
#else /* (DEVELOPMENT || DEBUG) */
#define UDP_LOG_ENABLE_DEFAULT 0
#endif /* (DEVELOPMENT || DEBUG) */

uint32_t udp_log_enable_flags = UDP_LOG_ENABLE_DEFAULT;
SYSCTL_UINT(_net_inet_udp_log, OID_AUTO, enable,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udp_log_enable_flags, 0, "");


/*
 * The following is a help to describe the values of the flags
 */
#define X(name, value, description, ...) #description ":" #value " "
SYSCTL_STRING(_net_inet_udp_log, OID_AUTO, enable_usage, CTLFLAG_RD | CTLFLAG_LOCKED,
    UDP_ENABLE_FLAG_LIST, 0, "");
#undef X

/*
 *
 */
static int sysctl_udp_log_port SYSCTL_HANDLER_ARGS;

int udp_log_bind_anon_port = 0;
SYSCTL_INT(_net_inet_udp_log, OID_AUTO, bind_anon_port,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udp_log_bind_anon_port, 0, "");

int udp_log_local_port_included = 0;
SYSCTL_PROC(_net_inet_udp_log, OID_AUTO, local_port_included,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_local_port_included, 0, &sysctl_udp_log_port, "I", "");

int udp_log_remote_port_included = 0;
SYSCTL_PROC(_net_inet_udp_log, OID_AUTO, remote_port_included,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_remote_port_included, 0, &sysctl_udp_log_port, "I", "");

int udp_log_local_port_excluded = 0;
SYSCTL_PROC(_net_inet_udp_log, OID_AUTO, local_port_excluded,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_local_port_excluded, 0, &sysctl_udp_log_port, "I", "");

int udp_log_remote_port_excluded = 0;
SYSCTL_PROC(_net_inet_udp_log, OID_AUTO, remote_port_excluded,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &udp_log_remote_port_excluded, 0, &sysctl_udp_log_port, "I", "");

#define UDP_LOG_RATE_LIMIT 1000
static unsigned int udp_log_rate_limit = UDP_LOG_RATE_LIMIT;
SYSCTL_UINT(_net_inet_udp_log, OID_AUTO, rate_limit,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udp_log_rate_limit, 0, "");

/* 1 minute by default */
#define UDP_LOG_RATE_DURATION 60
static unsigned int udp_log_rate_duration = UDP_LOG_RATE_DURATION;
SYSCTL_UINT(_net_inet_udp_log, OID_AUTO, rate_duration,
    CTLFLAG_RW | CTLFLAG_LOCKED, &udp_log_rate_duration, 0, "");

static unsigned long udp_log_rate_max = 0;
SYSCTL_ULONG(_net_inet_udp_log, OID_AUTO, rate_max,
    CTLFLAG_RD | CTLFLAG_LOCKED, &udp_log_rate_max, "");

static unsigned long udp_log_rate_exceeded_total = 0;
SYSCTL_ULONG(_net_inet_udp_log, OID_AUTO, rate_exceeded_total,
    CTLFLAG_RD | CTLFLAG_LOCKED, &udp_log_rate_exceeded_total, "");

static unsigned long udp_log_rate_current = 0;
SYSCTL_ULONG(_net_inet_udp_log, OID_AUTO, rate_current,
    CTLFLAG_RD | CTLFLAG_LOCKED, &udp_log_rate_current, "");

static bool udp_log_rate_exceeded_logged = false;

static uint64_t udp_log_current_period = 0;

#define ADDRESS_STR_LEN (MAX_IPv6_STR_LEN + 6)


#define UDP_LOG_COMMON_FMT \
	    "[%s:%u<->%s:%u] " \
	    "interface: %s " \
	    "(skipped: %lu)\n"

#define UDP_LOG_COMMON_ARGS \
	laddr_buf, ntohs(local_port), faddr_buf, ntohs(foreign_port), \
	    ifp != NULL ? if_name(ifp) : "", \
	    udp_log_rate_exceeded_total

#define UDP_LOG_COMMON_PCB_FMT \
	UDP_LOG_COMMON_FMT \
	"so_gencnt: %llu " \
	"so_state: 0x%04x " \
	"process: %s:%u "

#define UDP_LOG_COMMON_PCB_ARGS \
	UDP_LOG_COMMON_ARGS, \
	so != NULL ? so->so_gencnt : 0, \
	so != NULL ? so->so_state : 0, \
	inp->inp_last_proc_name, so->last_pid

/*
 * Returns true when above the rate limit
 */
static bool
udp_log_is_rate_limited(void)
{
	uint64_t current_net_period = net_uptime();

	/* When set to zero it means to reset to default */
	if (udp_log_rate_duration == 0) {
		udp_log_rate_duration = UDP_LOG_RATE_DURATION;
	}
	if (udp_log_rate_limit == 0) {
		udp_log_rate_duration = UDP_LOG_RATE_LIMIT;
	}

	if (current_net_period > udp_log_current_period + udp_log_rate_duration) {
		if (udp_log_rate_current > udp_log_rate_max) {
			udp_log_rate_max = udp_log_rate_current;
		}
		udp_log_current_period = current_net_period;
		udp_log_rate_current = 0;
		udp_log_rate_exceeded_logged = false;
	}

	udp_log_rate_current += 1;

	if (udp_log_rate_current > (unsigned long) udp_log_rate_limit) {
		udp_log_rate_exceeded_total += 1;
		return true;
	}

	return false;
}

static bool
udp_log_port_allowed(struct inpcb *inp)
{
	if (udp_log_local_port_included != 0 || udp_log_remote_port_included != 0) {
		if (ntohs(inp->inp_lport) == udp_log_local_port_included ||
		    ntohs(inp->inp_fport) == udp_log_remote_port_included) {
			return true;
		} else {
			return false;
		}
	}
	if (udp_log_local_port_excluded != 0 || udp_log_remote_port_excluded != 0) {
		if (ntohs(inp->inp_lport) == udp_log_local_port_excluded ||
		    ntohs(inp->inp_fport) == udp_log_remote_port_excluded) {
			return false;
		}
	}

	return true;
}

static inline void
udp_log_common(struct inpcb *inp, const char *event, int error)
{
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	/* Clear the logging flags as one may reconnect an UDP socket */
	inp->inp_flags2 &= ~INP2_LOGGED_SUMMARY;
	inp->inp_flags2 |= INP2_LOGGING_ENABLED;

	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	inp_log_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define UDP_LOG_CONNECTION_FMT \
	    "udp %s: " \
	    UDP_LOG_COMMON_PCB_FMT \
	    "bytes in/out: %llu/%llu " \
	    "pkts in/out: %llu/%llu " \
	    "error: %d " \
	    "so_error: %d " \
	    "svc/tc: %u " \
	    "flow: 0x%x"

#define UDP_LOG_CONNECTION_ARGS \
	    event, \
	    UDP_LOG_COMMON_PCB_ARGS, \
	    inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	    inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	    error, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class, \
	    inp->inp_flowhash

	os_log(OS_LOG_DEFAULT, UDP_LOG_CONNECTION_FMT,
	    UDP_LOG_CONNECTION_ARGS);

#undef UDP_LOG_CONNECTION_FMT
#undef UDP_LOG_CONNECTION_ARGS
}

__attribute__((noinline))
void
udp_log_bind(struct inpcb *inp, int error)
{
	if (inp == NULL || inp->inp_socket == NULL) {
		return;
	}
	/* Do not log too much */
	if (udp_log_is_rate_limited()) {
		return;
	}
	/* Allow logging of bind errors regardless of the port */
	if (error == 0) {
		if (udp_log_bind_anon_port == 0 && (inp->inp_flags & INP_ANONPORT) != 0) {
			return;
		}
		if (udp_log_port_allowed(inp) == false) {
			return;
		}
	}
	udp_log_common(inp, "bind", error);
}

__attribute__((noinline))
void
udp_log_connect(struct inpcb *inp, int error)
{
	if (inp == NULL || inp->inp_socket == NULL) {
		return;
	}
	/* Do not log too much */
	if (udp_log_is_rate_limited()) {
		return;
	}
	/* Allow logging of connection errors regardless of the port */
	if (error == 0 && udp_log_port_allowed(inp) == false) {
		return;
	}
	udp_log_common(inp, "connect", error);
}

__attribute__((noinline))
void
udp_log_connection_summary(struct inpcb *inp)
{
	struct socket *so;
	struct ifnet *ifp;
	clock_sec_t duration_secs = 0;
	clock_usec_t duration_microsecs = 0;
	clock_sec_t connection_secs = 0;
	clock_usec_t connection_microsecs = 0;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (inp == NULL || inp->inp_socket == NULL) {
		return;
	}
	if ((inp->inp_flags2 & INP2_LOGGING_ENABLED) == 0) {
		return;
	}
	/* Make sure the summary is logged once */
	if (inp->inp_flags2 & INP2_LOGGED_SUMMARY) {
		return;
	}
	inp->inp_flags2 |= INP2_LOGGED_SUMMARY;
	inp->inp_flags2 &= ~INP2_LOGGING_ENABLED;

	/* UDP can be reconnected so clear the destination flags */
	inp->inp_log_flags = 0;

	/* Do not log too much */
	if (udp_log_is_rate_limited()) {
		return;
	}
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	/*
	 * inp_start_timestamp is when the UDP socket was open.
	 *
	 * inp_connect_timestamp is when the connection started on
	 */
	uint64_t now = mach_continuous_time();
	if (inp->inp_start_timestamp > 0) {
		uint64_t duration = now - inp->inp_start_timestamp;

		absolutetime_to_microtime(duration, &duration_secs, &duration_microsecs);
	}
	if (inp->inp_connect_timestamp > 0) {
		uint64_t duration = now - inp->inp_connect_timestamp;

		absolutetime_to_microtime(duration, &connection_secs, &connection_microsecs);
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	inp_log_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	/*
	 * Need to use 2 log messages because the size of the summary
	 */

#define UDP_LOG_CONNECTION_SUMMARY_FMT \
	    "udp_connection_summary " \
	    UDP_LOG_COMMON_PCB_FMT \
	    "Duration: %lu.%03d sec " \
	    "Conn_Time: %lu.%03d sec " \
	    "bytes in/out: %llu/%llu " \
	    "pkts in/out: %llu/%llu " \
	    "rxnospace pkts/bytes: %llu/%llu " \
	    "so_error: %d " \
	    "svc/tc: %u " \
	    "flow: 0x%x" \
	    "flowctl: %lluus (%llux) "

#define UDP_LOG_CONNECTION_SUMMARY_ARGS \
	    UDP_LOG_COMMON_PCB_ARGS, \
	    duration_secs, duration_microsecs / 1000, \
	    connection_secs, connection_microsecs / 1000, \
	    inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	    inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	    so->so_tc_stats[SO_STATS_SBNOSPACE].rxpackets, \
	    so->so_tc_stats[SO_STATS_SBNOSPACE].rxbytes, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class, \
	    inp->inp_flowhash, \
	    inp->inp_fadv_total_time, \
	    inp->inp_fadv_cnt

	os_log(OS_LOG_DEFAULT, UDP_LOG_CONNECTION_SUMMARY_FMT,
	    UDP_LOG_CONNECTION_SUMMARY_ARGS);
#undef UDP_LOG_CONNECTION_SUMMARY_FMT
#undef UDP_LOG_CONNECTION_SUMMARY_ARGS
}

__attribute__((noinline))
void
udp_log_message(const char *func_name, int line_no, struct inpcb *inp, const char *format, ...)
{
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	char message[256];

	if (inp == NULL || inp->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (udp_log_is_rate_limited()) {
		return;
	}

	if (!udp_log_port_allowed(inp)) {
		return;
	}

	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	inp_log_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define UDP_LOG_MESSAGE_FMT \
	    "udp (%s:%d): " \
	    UDP_LOG_COMMON_PCB_FMT \
	    "%s"

#define UDP_LOG_MESSAGE_ARGS \
	    func_name, line_no, \
	    UDP_LOG_COMMON_PCB_ARGS, \
	    format

	os_log(OS_LOG_DEFAULT, UDP_LOG_MESSAGE_FMT,
	    UDP_LOG_MESSAGE_ARGS);

#undef UDP_LOG_MESSAGE_FMT
#undef UDP_LOG_MESSAGE_ARGS
}

static bool
udp_log_pkt_addresses(void *hdr, bool outgoing,
    char *__sized_by(lbuflen) lbuf, socklen_t lbuflen,
    char *__sized_by(fbuflen) fbuf, socklen_t fbuflen)
{
	bool isipv6;

	isipv6 = (((struct ip *)hdr)->ip_v == 6);

	if (isipv6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)hdr;
		struct in6_addr src_addr6 = ip6->ip6_src;
		struct in6_addr dst_addr6 = ip6->ip6_dst;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
		if (memcmp(&src_addr6, &in6addr_loopback, sizeof(struct in6_addr)) == 0 ||
		    memcmp(&dst_addr6, &in6addr_loopback, sizeof(struct in6_addr)) == 0) {
			if (!(udp_log_enable_flags & ULEF_DST_LOOPBACK)) {
				return false;
			}
		}
#pragma clang diagnostic pop

		if (IN6_IS_ADDR_LINKLOCAL(&src_addr6)) {
			src_addr6.s6_addr16[1] = 0;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&dst_addr6)) {
			dst_addr6.s6_addr16[1] = 0;
		}

		if (inp_log_privacy != 0) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else if (outgoing) {
			inet_ntop(AF_INET6, &src_addr6, lbuf, lbuflen);
			inet_ntop(AF_INET6, &dst_addr6, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET6, &dst_addr6, lbuf, lbuflen);
			inet_ntop(AF_INET6, &src_addr6, fbuf, fbuflen);
		}
	} else {
		struct ip *ip = (struct ip *)hdr;

		if (ntohl(ip->ip_src.s_addr) == INADDR_LOOPBACK ||
		    ntohl(ip->ip_dst.s_addr) == INADDR_LOOPBACK) {
			if (!(udp_log_enable_flags & ULEF_DST_LOOPBACK)) {
				return false;
			}
		}

		if (inp_log_privacy != 0) {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		} else if (outgoing) {
			inet_ntop(AF_INET, (void *)&ip->ip_src.s_addr, lbuf, lbuflen);
			inet_ntop(AF_INET, (void *)&ip->ip_dst.s_addr, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET, (void *)&ip->ip_dst.s_addr, lbuf, lbuflen);
			inet_ntop(AF_INET, (void *)&ip->ip_src.s_addr, fbuf, fbuflen);
		}
	}
	return true;
}

__attribute__((noinline))
void
udp_log_drop_pcb(void *hdr, struct udphdr *uh, struct inpcb *inp, bool outgoing, const char *reason)
{
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	const char *direction = "";

	if (inp == NULL) {
		return;
	}
	so = inp->inp_socket;
	if (so == NULL) {
		return;
	}

	/* Do not log common drops after the connection termination is logged */
	if ((inp->inp_flags2 & INP2_LOGGED_SUMMARY) && ((so->so_state & SS_NOFDREF) ||
	    (so->so_flags & SOF_DEFUNCT) || (so->so_state & SS_CANTRCVMORE))) {
		return;
	}

	/* Do not log too much */
	if (udp_log_is_rate_limited()) {
		return;
	}

	/* Use the packet addresses when in the data path */
	if (hdr != NULL && uh != NULL) {
		if (outgoing) {
			local_port = uh->uh_sport;
			foreign_port = uh->uh_dport;
			direction = "outgoing ";
		} else {
			local_port = uh->uh_dport;
			foreign_port = uh->uh_sport;
			direction = "incoming ";
		}
		(void) udp_log_pkt_addresses(hdr, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	} else {
		local_port = inp->inp_lport;
		foreign_port = inp->inp_fport;
		inp_log_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

#define UDP_LOG_DROP_PCB_FMT \
	    "udp drop %s" \
	    UDP_LOG_COMMON_PCB_FMT \
	    "so_error: %d " \
	    "reason: %s"

#define UDP_LOG_DROP_PCB_ARGS \
	    direction, \
	    UDP_LOG_COMMON_PCB_ARGS, \
	    so->so_error, \
	    reason

	os_log(OS_LOG_DEFAULT, UDP_LOG_DROP_PCB_FMT,
	    UDP_LOG_DROP_PCB_ARGS);
#undef UDP_LOG_DROP_PCB_FMT
#undef UDP_LOG_DROP_PCB_ARGS
}
static int
sysctl_udp_log_port SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int new_value = *(uint16_t *)oidp->oid_arg1;

	error = sysctl_handle_int(oidp, &new_value, 0, req);
	if (error == 0) {
		if (new_value < 0 || new_value > UINT16_MAX) {
			return EINVAL;
		}
		*(int *)oidp->oid_arg1 = new_value;
	}
	return error;
}
