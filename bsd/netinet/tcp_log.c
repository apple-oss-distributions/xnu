/*
 * Copyright (c) 2018-2023 Apple Inc. All rights reserved.
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

#if !TCPDEBUG
#define TCPSTATES
#endif /* TCPDEBUG */
#include <netinet/tcp_fsm.h>

#include <netinet/tcp_log.h>

SYSCTL_NODE(_net_inet_tcp, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "TCP logs");

#if (DEVELOPMENT || DEBUG)
#define TCP_LOG_ENABLE_DEFAULT \
    (TLEF_CONNECTION | TLEF_DST_LOCAL | TLEF_DST_GW | \
    TLEF_DROP_NECP | TLEF_DROP_PCB | TLEF_DROP_PKT | \
    TLEF_SYN_RXMT)
#else /* (DEVELOPMENT || DEBUG) */
#define TCP_LOG_ENABLE_DEFAULT 0
#endif /* (DEVELOPMENT || DEBUG) */

uint32_t tcp_log_enable_flags = TCP_LOG_ENABLE_DEFAULT;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, enable,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_enable_flags, 0, "");

/*
 * The following is a help to describe the values of the flags
 */
#define X(name, value, description, ...) #description ":" #value " "
SYSCTL_STRING(_net_inet_tcp_log, OID_AUTO, enable_usage, CTLFLAG_RD | CTLFLAG_LOCKED,
    TCP_ENABLE_FLAG_LIST, 0, "");
#undef X

/*
 * Values for tcp_log_port when TLEF_RTT is enabled:
 *  0: log all TCP connections regardless of the port numbers
 *  1 to 65535: log TCP connections with this local or foreign port
 *  other: do not log (same effect as as tcp_log_rtt == 0)
 */
uint32_t tcp_log_port = 0;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rtt_port, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_log_port, 0, "");

/*
 * Bitmap for tcp_log_thflags_if_family when TLEF_THF_XXX is enabled:
 *  0: off
 *  other: only for interfaces with the corresponding interface family in the bitmap
 */
#if (DEVELOPMENT || DEBUG)
#define TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT (0xfffffffe & ~BIT(IFNET_FAMILY_LOOPBACK))
#else /* (DEVELOPMENT || DEBUG) */
#define TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT 0
#endif /* (DEVELOPMENT || DEBUG) */

static uint64_t tcp_log_thflags_if_family = TCP_LOG_THFLAGS_IF_FAMILY_DEFAULT;
SYSCTL_QUAD(_net_inet_tcp_log, OID_AUTO, thflags_if_family,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_thflags_if_family, "");


#define TCP_LOG_RATE_LIMIT 1000
static unsigned int tcp_log_rate_limit = TCP_LOG_RATE_LIMIT;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rate_limit,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_rate_limit, 0, "");

/* 1 minute by default */
#define TCP_LOG_RATE_DURATION 60
static unsigned int tcp_log_rate_duration = TCP_LOG_RATE_DURATION;
SYSCTL_UINT(_net_inet_tcp_log, OID_AUTO, rate_duration,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_log_rate_duration, 0, "");

static unsigned long tcp_log_rate_max = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_max,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_max, "");

static unsigned long tcp_log_rate_exceeded_total = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_exceeded_total,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_exceeded_total, "");

static unsigned long tcp_log_rate_current = 0;
SYSCTL_ULONG(_net_inet_tcp_log, OID_AUTO, rate_current,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_log_rate_current, "");

static bool tcp_log_rate_exceeded_logged = false;

static uint64_t tcp_log_current_period = 0;

#define ADDRESS_STR_LEN (MAX_IPv6_STR_LEN + 6)

#define TCP_LOG_COMMON_FMT \
	    "[%s:%u<->%s:%u] " \
	    "interface: %s " \
	    "(skipped: %lu)\n"

#define TCP_LOG_COMMON_ARGS \
	laddr_buf, ntohs(local_port), faddr_buf, ntohs(foreign_port), \
	    ifp != NULL ? if_name(ifp) : "", \
	    tcp_log_rate_exceeded_total

#define TCP_LOG_COMMON_PCB_FMT \
	TCP_LOG_COMMON_FMT \
	"so_gencnt: %llu " \
	"t_state: %s " \
	"process: %s:%u "

#define TCP_LOG_COMMON_PCB_ARGS \
	TCP_LOG_COMMON_ARGS, \
	so != NULL ? so->so_gencnt : 0, \
	tcpstates[tp->t_state], \
	inp->inp_last_proc_name, so->last_pid

/*
 * Returns true when above the rate limit
 */
static bool
tcp_log_is_rate_limited(void)
{
	uint64_t current_net_period = net_uptime();

	/* When set to zero it means to reset to default */
	if (tcp_log_rate_duration == 0) {
		tcp_log_rate_duration = TCP_LOG_RATE_DURATION;
	}
	if (tcp_log_rate_limit == 0) {
		tcp_log_rate_duration = TCP_LOG_RATE_LIMIT;
	}

	if (current_net_period > tcp_log_current_period + tcp_log_rate_duration) {
		if (tcp_log_rate_current > tcp_log_rate_max) {
			tcp_log_rate_max = tcp_log_rate_current;
		}
		tcp_log_current_period = current_net_period;
		tcp_log_rate_current = 0;
		tcp_log_rate_exceeded_logged = false;
	}

	tcp_log_rate_current += 1;

	if (tcp_log_rate_current > (unsigned long) tcp_log_rate_limit) {
		tcp_log_rate_exceeded_total += 1;
		return true;
	}

	return false;
}

static void
tcp_log_inp_addresses(struct inpcb *inp, char *lbuf, socklen_t lbuflen, char *fbuf, socklen_t fbuflen)
{
	/*
	 * Ugly but %{private} does not work in the kernel version of os_log()
	 */
	if (inp_log_privacy != 0) {
		if (inp->inp_vflag & INP_IPV6) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		}
	} else if (inp->inp_vflag & INP_IPV6) {
		struct in6_addr addr6;

		if (IN6_IS_ADDR_LINKLOCAL(&inp->in6p_laddr)) {
			addr6 = inp->in6p_laddr;
			addr6.s6_addr16[1] = 0;
			inet_ntop(AF_INET6, (void *)&addr6, lbuf, lbuflen);
		} else {
			inet_ntop(AF_INET6, (void *)&inp->in6p_laddr, lbuf, lbuflen);
		}

		if (IN6_IS_ADDR_LINKLOCAL(&inp->in6p_faddr)) {
			addr6 = inp->in6p_faddr;
			addr6.s6_addr16[1] = 0;
			inet_ntop(AF_INET6, (void *)&addr6, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET6, (void *)&inp->in6p_faddr, fbuf, fbuflen);
		}
	} else {
		inet_ntop(AF_INET, (void *)&inp->inp_laddr.s_addr, lbuf, lbuflen);
		inet_ntop(AF_INET, (void *)&inp->inp_faddr.s_addr, fbuf, fbuflen);
	}
}

__attribute__((noinline))
void
tcp_log_rtt_info(const char *func_name, int line_no, struct tcpcb *tp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	os_log(OS_LOG_DEFAULT,
	    "tcp_rtt_info (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "base_rtt: %u ms rttcur: %u ms srtt: %u ms rttvar: %u ms rttmin: %u ms rxtcur: %u rxtshift: %u",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS, get_base_rtt(tp),
	    tp->t_rttcur, tp->t_srtt >> TCP_RTT_SHIFT,
	    tp->t_rttvar >> TCP_RTTVAR_SHIFT,
	    tp->t_rttmin, tp->t_rxtcur, tp->t_rxtshift);
}

__attribute__((noinline))
void
tcp_log_rt_rtt(const char *func_name, int line_no, struct tcpcb *tp,
    struct rtentry *rt)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	/*
	 * Log RTT values in milliseconds
	 */
	os_log(OS_LOG_DEFAULT,
	    "tcp_rt_rtt (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "rt_rmx: RTV_RTT: %d ms rtt: %u ms rttvar: %u ms",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS,
	    (rt->rt_rmx.rmx_locks & RTV_RTT),
	    rt->rt_rmx.rmx_rtt / (RTM_RTTUNIT / TCP_RETRANSHZ),
	    rt->rt_rmx.rmx_rttvar / (RTM_RTTUNIT / TCP_RETRANSHZ));
}

__attribute__((noinline))
void
tcp_log_rtt_change(const char *func_name, int line_no, struct tcpcb *tp,
    int old_srtt, int old_rttvar)
{
	int srtt_diff;
	int rttvar_diff;

	srtt_diff = ABS(tp->t_srtt  - old_srtt) >> TCP_RTT_SHIFT;
	rttvar_diff =
	    ABS((tp->t_rttvar - old_rttvar) >> TCP_RTTVAR_SHIFT);
	if (srtt_diff >= 1000 || rttvar_diff >= 500) {
		struct inpcb *inp = tp->t_inpcb;
		struct socket *so = inp->inp_socket;
		struct ifnet *ifp;
		char laddr_buf[ADDRESS_STR_LEN];
		char faddr_buf[ADDRESS_STR_LEN];
		in_port_t local_port = inp->inp_lport;
		in_port_t foreign_port = inp->inp_fport;

		/* Do not log too much */
		if (tcp_log_is_rate_limited()) {
			return;
		}

		ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
		    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

		tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

		os_log(OS_LOG_DEFAULT,
		    "tcp_rtt_change (%s:%d) "
		    TCP_LOG_COMMON_PCB_FMT
		    "srtt: %u ms old_rtt: %u ms "
		    "rttvar: %u old_rttvar: %u ms ",
		    func_name, line_no,
		    TCP_LOG_COMMON_PCB_ARGS,
		    tp->t_srtt >> TCP_RTT_SHIFT,
		    old_srtt >> TCP_RTT_SHIFT,
		    tp->t_rttvar >> TCP_RTTVAR_SHIFT,
		    old_rttvar >> TCP_RTTVAR_SHIFT);
	}
}

__attribute__((noinline))
void
tcp_log_keepalive(const char *func_name, int line_no, struct tcpcb *tp,
    int32_t idle_time)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port = inp->inp_lport;
	in_port_t foreign_port = inp->inp_fport;

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	os_log(OS_LOG_DEFAULT,
	    "tcp_keepalive (%s:%d) "
	    TCP_LOG_COMMON_PCB_FMT
	    "snd_una: %u snd_max: %u "
	    "SO_KA: %d RSTALL: %d TFOPRB: %d idle_time: %u "
	    "KIDLE: %d KINTV: %d KCNT: %d",
	    func_name, line_no,
	    TCP_LOG_COMMON_PCB_ARGS,
	    tp->snd_una, tp->snd_max,
	    tp->t_inpcb->inp_socket->so_options & SO_KEEPALIVE,
	    tp->t_flagsext & TF_DETECT_READSTALL,
	    tp->t_tfo_probe_state == TFO_PROBE_PROBING,
	    idle_time,
	    TCP_CONN_KEEPIDLE(tp), TCP_CONN_KEEPINTVL(tp),
	    TCP_CONN_KEEPCNT(tp));
}

#define P_MS(ms, shift) ((ms) >> (shift)), (((ms) * 1000) >> (shift)) % 1000

__attribute__((noinline))
void
tcp_log_connection(struct tcpcb *tp, const char *event, int error)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL || event == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_CONNECT_FMT \
	    "tcp %s: " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "SYN in/out: %u/%u " \
	    "bytes in/out: %llu/%llu " \
	    "pkts in/out: %llu/%llu " \
	    "rtt: %u.%u ms " \
	    "rttvar: %u.%u ms " \
	    "base_rtt: %u ms " \
	    "error: %d " \
	    "so_error: %d " \
	    "svc/tc: %u " \
	    "flow: 0x%x"

#define TCP_LOG_CONNECT_ARGS \
	    event, \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    tp->t_syn_rcvd, tp->t_syn_sent, \
	    inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	    inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	    P_MS(tp->t_srtt, TCP_RTT_SHIFT), \
	    P_MS(tp->t_rttvar, TCP_RTTVAR_SHIFT), \
	    get_base_rtt(tp), \
	    error, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class, \
	    inp->inp_flowhash

	if (so->so_head == NULL) {
		os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT,
		    TCP_LOG_CONNECT_ARGS);
	} else {
#define TCP_LOG_CONN_Q_FMT \
	"so_qlimit: %d "\
	"so_qlen: %d "\
	"so_incqlen: %d "

#define TCP_LOG_CONN_Q_ARGS \
	so->so_head->so_qlimit, \
	so->so_head->so_qlen, \
	so->so_head->so_incqlen

		os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECT_FMT "\n" TCP_LOG_CONN_Q_FMT,
		    TCP_LOG_CONNECT_ARGS, TCP_LOG_CONN_Q_ARGS);
#undef TCP_LOG_CONN_Q_FMT
#undef TCP_LOG_CONN_Q_ARGS
	}
#undef TCP_LOG_CONNECT_FMT
#undef TCP_LOG_CONNECT_ARGS
}

__attribute__((noinline))
void
tcp_log_listen(struct tcpcb *tp, int error)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp->inp_socket;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_LISTEN_FMT \
	    "tcp listen: " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "so_qlimit: %d "\
	    "error: %d " \
	    "so_error: %d " \
	    "svc/tc: %u"

#define TCP_LOG_LISTEN_ARGS \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    so->so_qlimit, \
	    error, \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class

	os_log(OS_LOG_DEFAULT, TCP_LOG_LISTEN_FMT,
	    TCP_LOG_LISTEN_ARGS);
#undef TCP_LOG_LISTEN_FMT
#undef TCP_LOG_LISTEN_ARGS
}

static const char *
tcp_connection_client_accurate_ecn_state_to_string(tcp_connection_client_accurate_ecn_state_t state)
{
	switch (state) {
#define ECN_STATE_TO_STRING(_s, _str) \
	case tcp_connection_client_accurate_ecn_##_s: { \
	        return _str; \
	}
		ECN_STATE_TO_STRING(invalid, "Invalid")
		ECN_STATE_TO_STRING(feature_disabled, "Disabled")
		ECN_STATE_TO_STRING(feature_enabled, "Enabled")
		ECN_STATE_TO_STRING(negotiation_blackholed, "Blackholed")
		ECN_STATE_TO_STRING(ace_bleaching_detected, "ACE bleaching")
		ECN_STATE_TO_STRING(negotiation_success, "Capable")
		ECN_STATE_TO_STRING(negotiation_success_ect_mangling_detected, "ECT mangling")
		ECN_STATE_TO_STRING(negotiation_success_ect_bleaching_detected, "ECT bleaching")
#undef ECN_STATE_TO_STRING
	case tcp_connection_client_classic_ecn_available:
		return "Classic ECN";
	case tcp_connection_client_ecn_not_available:
		return "Unavailable";
	}
	return "Unknown";
}

static const char *
tcp_connection_server_accurate_ecn_state_to_string(tcp_connection_server_accurate_ecn_state_t state)
{
	switch (state) {
#define ECN_STATE_TO_STRING(_s, _str) \
	case tcp_connection_server_accurate_ecn_##_s: { \
	        return _str; \
	}
		ECN_STATE_TO_STRING(invalid, "Invalid")
		ECN_STATE_TO_STRING(feature_disabled, "Disabled")
		ECN_STATE_TO_STRING(feature_enabled, "Enabled")
		ECN_STATE_TO_STRING(requested, "Requested")
		ECN_STATE_TO_STRING(negotiation_blackholed, "Blackholed")
		ECN_STATE_TO_STRING(ace_bleaching_detected, "ACE bleaching")
		ECN_STATE_TO_STRING(negotiation_success, "Capable")
		ECN_STATE_TO_STRING(negotiation_success_ect_mangling_detected, "ECT mangling")
		ECN_STATE_TO_STRING(negotiation_success_ect_bleaching_detected, "ECT bleaching")
#undef ECN_STATE_TO_STRING
	case tcp_connection_server_no_ecn_requested:
		return "Not requested";
	case tcp_connection_server_classic_ecn_requested:
		return "Classic ECN requested";
	}
	return "Unknown";
}

__attribute__((noinline))
void
tcp_log_connection_summary(struct tcpcb *tp)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	uint32_t conntime = 0;
	uint32_t duration = 0;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	/* Make sure the summary is logged once */
	if (inp->inp_flags2 & INP2_LOGGED_SUMMARY) {
		return;
	}
	inp->inp_flags2 |= INP2_LOGGED_SUMMARY;

	/*
	 * t_connect_time is the time when the connection started on
	 * the first SYN.
	 *
	 * t_starttime is when the three way handshake was completed.
	 */
	if (tp->t_connect_time > 0) {
		duration = tcp_now - tp->t_connect_time;

		if (tp->t_starttime > 0) {
			conntime = tp->t_starttime - tp->t_connect_time;
		}
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	/*
	 * Need to use 2 log messages because the size of the summary
	 */

#define TCP_LOG_CONNECTION_SUMMARY_FMT \
	    "tcp_connection_summary " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "Duration: %u.%u sec " \
	    "Conn_Time: %u.%u sec " \
	    "bytes in/out: %llu/%llu " \
	    "pkts in/out: %llu/%llu " \
	    "pkt rxmit: %u " \
	    "ooo pkts: %u dup bytes in: %u ACKs delayed: %u delayed ACKs sent: %u\n" \
	    "rtt: %u.%03u ms "  \
	    "rttvar: %u.%03u ms " \
	    "base rtt: %u ms " \
	    "so_error: %d " \
	    "svc/tc: %u " \
	    "flow: 0x%x"

#define TCP_LOG_CONNECTION_SUMMARY_ARGS \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    duration / TCP_RETRANSHZ, duration % TCP_RETRANSHZ, \
	    conntime / TCP_RETRANSHZ, conntime % TCP_RETRANSHZ,  \
	    inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	    inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	    tp->t_stat.rxmitpkts, \
	    tp->t_rcvoopack, tp->t_stat.rxduplicatebytes, tp->t_stat.acks_delayed, tp->t_stat.delayed_acks_sent, \
	    P_MS(tp->t_srtt, TCP_RTT_SHIFT), \
	    P_MS(tp->t_rttvar, TCP_RTTVAR_SHIFT), \
	    get_base_rtt(tp), \
	    so->so_error, \
	    (so->so_flags1 & SOF1_TC_NET_SERV_TYPE) ? so->so_netsvctype : so->so_traffic_class, \
	    inp->inp_flowhash

	os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECTION_SUMMARY_FMT,
	    TCP_LOG_CONNECTION_SUMMARY_ARGS);
#undef TCP_LOG_CONNECTION_SUMMARY_FMT
#undef TCP_LOG_CONNECTION_SUMMARY_ARGS

#define TCP_LOG_CONNECTION_SUMMARY_FMT \
	    "tcp_connection_summary " \
	    TCP_LOG_COMMON_PCB_FMT \
	    "flowctl: %lluus (%llux) " \
	    "SYN in/out: %u/%u " \
	    "FIN in/out: %u/%u " \
	    "RST in/out: %u/%u " \
	    "AccECN (client/server): %s/%s\n" \

#define TCP_LOG_CONNECTION_SUMMARY_ARGS \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    inp->inp_fadv_total_time, \
	    inp->inp_fadv_cnt, \
	    tp->t_syn_rcvd, tp->t_syn_sent, \
	    tp->t_fin_rcvd, tp->t_fin_sent, \
	    tp->t_rst_rcvd, tp->t_rst_sent, \
	    tcp_connection_client_accurate_ecn_state_to_string(tp->t_client_accecn_state), \
	    tcp_connection_server_accurate_ecn_state_to_string(tp->t_server_accecn_state)

	os_log(OS_LOG_DEFAULT, TCP_LOG_CONNECTION_SUMMARY_FMT,
	    TCP_LOG_CONNECTION_SUMMARY_ARGS);
#undef TCP_LOG_CONNECTION_SUMMARY_FMT
#undef TCP_LOG_CONNECTION_SUMMARY_ARGS
}

__attribute__((noinline))
static bool
tcp_log_pkt_addresses(void *hdr, struct tcphdr *th, bool outgoing,
    char *lbuf, socklen_t lbuflen, char *fbuf, socklen_t fbuflen)
{
	bool isipv6;
	uint8_t thflags;

	isipv6 = (((struct ip *)hdr)->ip_v == 6);
	thflags = th->th_flags;

	if (isipv6) {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)hdr;

		if (memcmp(&ip6->ip6_src, &in6addr_loopback, sizeof(struct in6_addr)) == 0 ||
		    memcmp(&ip6->ip6_dst, &in6addr_loopback, sizeof(struct in6_addr)) == 0) {
			if (!(tcp_log_enable_flags & TLEF_DST_LOOPBACK)) {
				return false;
			}
		}

		if (inp_log_privacy != 0) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else if (outgoing) {
			inet_ntop(AF_INET6, &ip6->ip6_src, lbuf, lbuflen);
			inet_ntop(AF_INET6, &ip6->ip6_dst, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET6, &ip6->ip6_dst, lbuf, lbuflen);
			inet_ntop(AF_INET6, &ip6->ip6_src, fbuf, fbuflen);
		}
	} else {
		struct ip *ip = (struct ip *)hdr;

		if (ntohl(ip->ip_src.s_addr) == INADDR_LOOPBACK ||
		    ntohl(ip->ip_dst.s_addr) == INADDR_LOOPBACK) {
			if (!(tcp_log_enable_flags & TLEF_DST_LOOPBACK)) {
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

/*
 * Note: currently only used in the input path
 */
__attribute__((noinline))
void
tcp_log_drop_pcb(void *hdr, struct tcphdr *th, struct tcpcb *tp, bool outgoing, const char *reason)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	const char *direction = "";

	if (tp == NULL) {
		return;
	}
	inp = tp->t_inpcb;
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
	if (tcp_log_is_rate_limited()) {
		return;
	}

	/* Use the packet addresses when in the data path */
	if (hdr != NULL && th != NULL) {
		if (outgoing) {
			local_port = th->th_sport;
			foreign_port = th->th_dport;
			direction = "outgoing ";
		} else {
			local_port = th->th_dport;
			foreign_port = th->th_sport;
			direction = "incoming ";
		}
		(void) tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	} else {
		local_port = inp->inp_lport;
		foreign_port = inp->inp_fport;
		tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

#define TCP_LOG_DROP_PCB_FMT \
	    "tcp drop %s" \
	    TCP_LOG_COMMON_PCB_FMT \
	    "t_state: %s " \
	    "so_error: %d " \
	    "reason: %s"

#define TCP_LOG_DROP_PCB_ARGS \
	    direction, \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    tcpstates[tp->t_state], \
	    so->so_error, \
	    reason

	os_log(OS_LOG_DEFAULT, TCP_LOG_DROP_PCB_FMT,
	    TCP_LOG_DROP_PCB_ARGS);
#undef TCP_LOG_DROP_PCB_FMT
#undef TCP_LOG_DROP_PCB_ARGS
}

#define TCP_LOG_TH_FLAGS_COMMON_FMT \
	"tcp control %s " \
	"%s" \
	"%s" \
	"%s" \
	"%s" \
	TCP_LOG_COMMON_FMT

#define TCP_LOG_TH_FLAGS_COMMON_ARGS \
	outgoing ? "outgoing" : "incoming", \
	thflags & TH_SYN ? "SYN " : "", \
	thflags & TH_FIN ? "FIN " : "", \
	thflags & TH_RST ? "RST " : "", \
	thflags & TH_ACK ? "ACK " : "", \
	TCP_LOG_COMMON_ARGS

static bool
should_log_th_flags(uint8_t thflags, struct tcpcb *tp, bool outgoing, struct ifnet *ifp)
{
	/*
	 * Check logging is enabled for interface for TCP control packets
	 *
	 * Note: the type of tcp_log_thflags_if_family is uint64_t but we
	 * access its value as bit string so we have to pay extra care to avoid
	 * out of bound access
	 */
	if (ifp != NULL && (ifp->if_family >= (sizeof(tcp_log_thflags_if_family) << 3) ||
	    !bitstr_test((bitstr_t *)&tcp_log_thflags_if_family, ifp->if_family))) {
		return false;
	}
	/*
	 * Log when seeing 3 SYN retransmissions of more on a TCP PCB
	 */
	if (tp != NULL &&
	    ((thflags & TH_SYN) && (tcp_log_enable_flags & TLEF_SYN_RXMT) &&
	    ((outgoing && tp->t_syn_sent > 3) || (!outgoing && tp->t_syn_rcvd > 3)))) {
		return true;
	}
	/*
	 * Log control packet when enabled
	 */
	if ((((thflags & TH_SYN) && (tcp_log_enable_flags & TLEF_THF_SYN)) ||
	    ((thflags & TH_FIN) && (tcp_log_enable_flags & TLEF_THF_FIN)) ||
	    ((thflags & TH_RST) && (tcp_log_enable_flags & TLEF_THF_RST)))) {
		return true;
	}
	return false;
}

__attribute__((noinline))
void
tcp_log_th_flags(void *hdr, struct tcphdr *th, struct tcpcb *tp, bool outgoing, struct ifnet *ifp)
{
	struct inpcb *inp = tp->t_inpcb;
	struct socket *so = inp != NULL ? inp->inp_socket : NULL;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	uint8_t thflags;

	if (hdr == NULL || th == NULL) {
		return;
	}

	thflags = th->th_flags;

	if (should_log_th_flags(thflags, tp, outgoing, ifp) == false) {
		return;
	}

	if (outgoing) {
		local_port = th->th_sport;
		foreign_port = th->th_dport;
	} else {
		local_port = th->th_dport;
		foreign_port = th->th_sport;
	}
	if (!tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf))) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	/*
	 * When no PCB or socket just log the packet
	 */
	if (tp == NULL || so == NULL || inp == NULL) {
#define TCP_LOG_TH_FLAGS_NO_PCB_FMT \
	    TCP_LOG_TH_FLAGS_COMMON_FMT \
	    TCP_LOG_COMMON_FMT
#define TCP_LOG_TH_FLAGS_NO_PCB_ARGS \
	    TCP_LOG_TH_FLAGS_COMMON_ARGS, \
	    TCP_LOG_COMMON_ARGS

		os_log(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_NO_PCB_FMT,
		    TCP_LOG_TH_FLAGS_NO_PCB_ARGS);
#undef TCP_LOG_TH_FLAGS_NO_PCB_FMT
#undef TCP_LOG_TH_FLAGS_NO_PCB_ARGS
	} else {
#define TCP_LOG_TH_FLAGS_PCB_FMT \
	    TCP_LOG_TH_FLAGS_COMMON_FMT \
	    TCP_LOG_COMMON_PCB_FMT \
	    "SYN in/out: %u/%u "

#define TCP_LOG_TH_FLAGS_PCB_ARGS \
	    TCP_LOG_TH_FLAGS_COMMON_ARGS, \
	    TCP_LOG_COMMON_PCB_ARGS, \
	    tp->t_syn_rcvd, tp->t_syn_sent

		os_log(OS_LOG_DEFAULT, TCP_LOG_TH_FLAGS_PCB_FMT,
		    TCP_LOG_TH_FLAGS_PCB_ARGS);
#undef TCP_LOG_TH_FLAGS_PCB_FMT
#undef TCP_LOG_TH_FLAGS_PCB_ARGS
	}
}

__attribute__((noinline))
void
tcp_log_drop_pkt(void *hdr, struct tcphdr *th, struct ifnet *ifp, const char *reason)
{
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	uint8_t thflags;
	bool outgoing = false;  /* This is only for incoming packets */

	if (hdr == NULL || th == NULL) {
		return;
	}

	local_port = th->th_dport;
	foreign_port = th->th_sport;
	thflags = th->th_flags;

	if (should_log_th_flags(thflags, NULL, outgoing, ifp) == false) {
		return;
	}

	if (!tcp_log_pkt_addresses(hdr, th, outgoing, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf))) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

#define TCP_LOG_DROP_PKT_FMT \
	    "tcp drop incoming control packet " \
	        TCP_LOG_TH_FLAGS_COMMON_FMT \
	    "reason: %s"

#define TCP_LOG_DROP_PKT_ARGS \
	    TCP_LOG_TH_FLAGS_COMMON_ARGS, \
	    reason != NULL ? reason : ""

	os_log(OS_LOG_DEFAULT, TCP_LOG_DROP_PKT_FMT,
	    TCP_LOG_DROP_PKT_ARGS);
#undef TCP_LOG_DROP_PKT_FMT
#undef TCP_LOG_DROP_PKT_ARGS
}

__attribute__((noinline))
void
tcp_log_message(const char *func_name, int line_no, struct tcpcb *tp, const char *format, ...)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	char message[256];

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define TCP_LOG_MESSAGE_FMT \
	"tcp (%s:%d) " \
	TCP_LOG_COMMON_PCB_FMT \
	"bytes in/out: %llu/%llu " \
	"pkts in/out: %llu/%llu " \
	"%s"

#define TCP_LOG_MESSAGE_ARGS \
	func_name, line_no, \
	TCP_LOG_COMMON_PCB_ARGS, \
	inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	message

	os_log(OS_LOG_DEFAULT, TCP_LOG_MESSAGE_FMT,
	    TCP_LOG_MESSAGE_ARGS);
#undef TCP_LOG_MESSAGE_FMT
#undef TCP_LOG_MESSAGE_ARGS
}

#if SKYWALK
__attribute__((noinline))
void
tcp_log_fsw_flow(const char *func_name, int line_no, struct tcpcb *tp, const char *format, ...)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	uuid_string_t flow_uuid_str;
	char message[256];

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	uuid_unparse_upper(tp->t_flow_uuid, flow_uuid_str);

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define TCP_LOG_FSW_FLOW_MESSAGE_FMT \
	"tcp (%s:%d) " \
	TCP_LOG_COMMON_PCB_FMT \
	"flow %s %s"

#define TCP_LOG_FSW_FLOW_MESSAGE_ARGS \
	func_name, line_no, \
	TCP_LOG_COMMON_PCB_ARGS, \
	flow_uuid_str, \
	message

	os_log(OS_LOG_DEFAULT, TCP_LOG_FSW_FLOW_MESSAGE_FMT,
	    TCP_LOG_FSW_FLOW_MESSAGE_ARGS);
#undef TCP_LOG_FSW_FLOW_MESSAGE_FMT
#undef TCP_LOG_FSW_FLOW_MESSAGE_ARGS
}
#endif /* SKYWALK */

void
tcp_log_state_change(struct tcpcb *tp, int new_state)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	uint32_t conntime = 0;
	uint32_t duration = 0;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}
	if (new_state == tp->t_state) {
		return;
	}

	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}

	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	/*
	 * t_connect_time is the time when the connection started on
	 * the first SYN.
	 *
	 * t_starttime is when the three way handshake was completed.
	 */
	if (tp->t_connect_time > 0) {
		duration = tcp_now - tp->t_connect_time;

		if (tp->t_starttime > 0) {
			conntime = tp->t_starttime - tp->t_connect_time;
		}
	}

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

#define TCP_LOG_STATE_FMT \
	    "tcp_state_changed " \
	    TCP_LOG_COMMON_PCB_FMT

#define TCP_LOG_STATE_ARGS \
	TCP_LOG_COMMON_ARGS, \
	so != NULL ? so->so_gencnt : 0, \
	tcpstates[new_state], \
	inp->inp_last_proc_name, so->last_pid

	os_log(OS_LOG_DEFAULT, TCP_LOG_STATE_FMT,
	    TCP_LOG_STATE_ARGS);
#undef TCP_LOG_STATE_FMT
#undef TCP_LOG_STATE_ARGS
}

__attribute__((noinline))
void
tcp_log_output(const char *func_name, int line_no, struct tcpcb *tp, const char *format, ...)
{
	struct inpcb *inp;
	struct socket *so;
	struct ifnet *ifp;
	char laddr_buf[ADDRESS_STR_LEN];
	char faddr_buf[ADDRESS_STR_LEN];
	in_port_t local_port;
	in_port_t foreign_port;
	char message[256];

	if (tp == NULL || tp->t_inpcb == NULL || tp->t_inpcb->inp_socket == NULL) {
		return;
	}
	/* Log only when fron send() or connect() */
	if ((tp->t_flagsext & TF_USR_OUTPUT) == 0) {
		return;
	}
	/* Do not log too much */
	if (tcp_log_is_rate_limited()) {
		return;
	}
	inp = tp->t_inpcb;
	so = inp->inp_socket;

	local_port = inp->inp_lport;
	foreign_port = inp->inp_fport;

	ifp = inp->inp_last_outifp != NULL ? inp->inp_last_outifp :
	    inp->inp_boundifp != NULL ? inp->inp_boundifp : NULL;

	tcp_log_inp_addresses(inp, laddr_buf, sizeof(laddr_buf), faddr_buf, sizeof(faddr_buf));

	va_list ap;
	va_start(ap, format);
	vsnprintf(message, sizeof(message), format, ap);
	va_end(ap);

#define TCP_LOG_MESSAGE_FMT \
	"tcp (%s:%d) " \
	TCP_LOG_COMMON_PCB_FMT \
	"bytes in/out: %llu/%llu " \
	"pkts in/out: %llu/%llu " \
	"rxmit pkts/bytes: %u/%u" \
	"%s"

#define TCP_LOG_MESSAGE_ARGS \
	func_name, line_no, \
	TCP_LOG_COMMON_PCB_ARGS, \
	inp->inp_stat->rxbytes, inp->inp_stat->txbytes, \
	inp->inp_stat->rxpackets, inp->inp_stat->txpackets, \
	tp->t_stat.rxmitpkts, tp->t_stat.txretransmitbytes, \
	message

	os_log(OS_LOG_DEFAULT, TCP_LOG_MESSAGE_FMT,
	    TCP_LOG_MESSAGE_ARGS);
#undef TCP_LOG_MESSAGE_FMT
#undef TCP_LOG_MESSAGE_ARGS
}
