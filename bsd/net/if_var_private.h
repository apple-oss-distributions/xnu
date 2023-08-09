/*
 * Copyright (c) 2000-2022 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
 *    The Regents of the University of California.  All rights reserved.
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
 *    This product includes software developed by the University of
 *    California, Berkeley and its contributors.
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
 *    From: @(#)if.h    8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if_var.h,v 1.18.2.7 2001/07/24 19:10:18 brooks Exp $
 */

#ifndef _NET_IF_VAR_PRIVATE_H_
#define _NET_IF_VAR_PRIVATE_H_

#ifndef DRIVERKIT
#ifndef DRIVERKIT_PRIVATE
#include <net/if_var_status.h>
#endif
#include <net/route.h>
#include <stdint.h>
#include <sys/types.h>
#ifdef KERNEL_PRIVATE
#include <kern/locks.h>
#endif /* KERNEL_PRIVATE */

struct if_traffic_class {
	u_int64_t               ifi_ibepackets;/* TC_BE packets received on interface */
	u_int64_t               ifi_ibebytes;/* TC_BE bytes received on interface */
	u_int64_t               ifi_obepackets;/* TC_BE packet sent on interface */
	u_int64_t               ifi_obebytes;/* TC_BE bytes sent on interface */
	u_int64_t               ifi_ibkpackets;/* TC_BK packets received on interface */
	u_int64_t               ifi_ibkbytes;/* TC_BK bytes received on interface */
	u_int64_t               ifi_obkpackets;/* TC_BK packet sent on interface */
	u_int64_t               ifi_obkbytes;/* TC_BK bytes sent on interface */
	u_int64_t               ifi_ivipackets;/* TC_VI packets received on interface */
	u_int64_t               ifi_ivibytes;/* TC_VI bytes received on interface */
	u_int64_t               ifi_ovipackets;/* TC_VI packets sent on interface */
	u_int64_t               ifi_ovibytes;/* TC_VI bytes sent on interface */
	u_int64_t               ifi_ivopackets;/* TC_VO packets received on interface */
	u_int64_t               ifi_ivobytes;/* TC_VO bytes received on interface */
	u_int64_t               ifi_ovopackets;/* TC_VO packets sent on interface */
	u_int64_t               ifi_ovobytes;/* TC_VO bytes sent on interface */
	u_int64_t               ifi_ipvpackets;/* TC priv packets received on interface */
	u_int64_t               ifi_ipvbytes;/* TC priv bytes received on interface */
	u_int64_t               ifi_opvpackets;/* TC priv packets sent on interface */
	u_int64_t               ifi_opvbytes;/* TC priv bytes sent on interface */
};

struct if_data_extended {
	u_int64_t       ifi_alignerrs;/* unaligned (32-bit) input pkts */
	u_int64_t       ifi_dt_bytes;/* Data threshold counter */
	u_int64_t       ifi_fpackets;/* forwarded packets on interface */
	u_int64_t       ifi_fbytes; /* forwarded bytes on interface */
	u_int64_t       reserved[12];/* for future */
};

struct if_packet_stats {
	/* TCP */
	u_int64_t               ifi_tcp_badformat;
	u_int64_t               ifi_tcp_unspecv6;
	u_int64_t               ifi_tcp_synfin;
	u_int64_t               ifi_tcp_badformatipsec;
	u_int64_t               ifi_tcp_noconnnolist;
	u_int64_t               ifi_tcp_noconnlist;
	u_int64_t               ifi_tcp_listbadsyn;
	u_int64_t               ifi_tcp_icmp6unreach;
	u_int64_t               ifi_tcp_deprecate6;
	u_int64_t               ifi_tcp_rstinsynrcv;
	u_int64_t               ifi_tcp_ooopacket;
	u_int64_t               ifi_tcp_dospacket;
	u_int64_t               ifi_tcp_cleanup;
	u_int64_t               ifi_tcp_synwindow;
	u_int64_t               reserved[6];
	/* UDP */
	u_int64_t               ifi_udp_port_unreach;
	u_int64_t               ifi_udp_faithprefix;
	u_int64_t               ifi_udp_port0;
	u_int64_t               ifi_udp_badlength;
	u_int64_t               ifi_udp_badchksum;
	u_int64_t               ifi_udp_badmcast;
	u_int64_t               ifi_udp_cleanup;
	u_int64_t               ifi_udp_badipsec;
	u_int64_t               _reserved[4];
};

struct if_description {
	u_int32_t       ifd_maxlen; /* must be IF_DESCSIZE */
	u_int32_t       ifd_len;    /* actual ifd_desc length */
	u_int8_t        *ifd_desc;  /* ptr to desc buffer */
};

struct if_bandwidths {
	uint64_t       eff_bw;     /* effective bandwidth */
	uint64_t       max_bw;     /* maximum theoretical bandwidth */
};

struct if_latencies {
	u_int64_t       eff_lt;     /* effective latency */
	u_int64_t       max_lt;     /* maximum theoretical latency */
};

typedef enum {
	IF_NETEM_MODEL_NULL = 0,
	IF_NETEM_MODEL_NLC = 1,
} if_netem_model_t;

#define IF_NETEM_PARAMS_PSCALE  100000
struct if_netem_params {
	/* packet scheduler model */
	if_netem_model_t        ifnetem_model;

	/* bandwidth limit */
	uint64_t        ifnetem_bandwidth_bps;

	/* latency (normal distribution with jitter as stdev) */
	uint32_t        ifnetem_latency_ms;
	uint32_t        ifnetem_jitter_ms;

	/*
	 * NetEm probabilistic model parameters has a scaling factor of 100,000
	 * for 5 digits precision. For instance, probability 12.345% is
	 * expressed as uint32_t fixed point 12345 in ifnet_*_p variable below.
	 */
	/* random packet corruption */
	uint32_t        ifnetem_corruption_p;

	/* random packet duplication */
	uint32_t        ifnetem_duplication_p;

	/* 4 state Markov loss model */
	uint32_t        ifnetem_loss_p_gr_gl;/* P( gap_loss   | gap_rx     ) */
	uint32_t        ifnetem_loss_p_gr_bl;/* P( burst_loss | gap_rx     ) */
	uint32_t        ifnetem_loss_p_bl_br;/* P( burst_rx   | burst_loss ) */
	uint32_t        ifnetem_loss_p_bl_gr;/* P( gap_rx     | burst_loss ) */
	uint32_t        ifnetem_loss_p_br_bl;/* P( burst_loss | burst_rx   ) */

	uint32_t        ifnetem_loss_recovery_ms;/* time to recovery loss */

	/* random packet reordering */
	uint32_t        ifnetem_reordering_p;/* reorder probability */

	/*
	 * NetEm output scheduler by default is waken up upon input event as
	 * well as timer interval to avoid excessive delay. If
	 * ifnetem_output_ival is set to non-zero value, it overrides the
	 * default output interval as well as disables output scheduler wakeup
	 * upon input events.
	 */
	uint32_t        ifnetem_output_ival_ms;/* output interval */
};

struct if_rxpoll_stats {
	u_int32_t       ifi_poll_off_req;   /* total # of POLL_OFF reqs */
	u_int32_t       ifi_poll_off_err;   /* total # of POLL_OFF errors */
	u_int32_t       ifi_poll_on_req;    /* total # of POLL_ON reqs */
	u_int32_t       ifi_poll_on_err;    /* total # of POLL_ON errors */

	u_int32_t       ifi_poll_wakeups_avg;/* avg # of wakeup reqs */
	u_int32_t       ifi_poll_wakeups_lowat;/* wakeups low watermark */
	u_int32_t       ifi_poll_wakeups_hiwat;/* wakeups high watermark */

	u_int64_t       ifi_poll_packets;   /* total # of polled packets */
	u_int32_t       ifi_poll_packets_avg;/* average polled packets */
	u_int32_t       ifi_poll_packets_min;/* smallest polled packets */
	u_int32_t       ifi_poll_packets_max;/* largest polled packets */
	u_int32_t       ifi_poll_packets_lowat;/* packets low watermark */
	u_int32_t       ifi_poll_packets_hiwat;/* packets high watermark */

	u_int64_t       ifi_poll_bytes;     /* total # of polled bytes */
	u_int32_t       ifi_poll_bytes_avg; /* average polled bytes */
	u_int32_t       ifi_poll_bytes_min; /* smallest polled bytes */
	u_int32_t       ifi_poll_bytes_max; /* largest polled bytes */
	u_int32_t       ifi_poll_bytes_lowat;/* bytes low watermark */
	u_int32_t       ifi_poll_bytes_hiwat;/* bytes high watermark */

	u_int32_t       ifi_poll_packets_limit;/* max packets per poll call */
	u_int64_t       ifi_poll_interval_time;/* poll interval (nsec) */
};

struct if_netif_stats {
	u_int64_t       ifn_rx_mit_interval;/* rx mitigation ival (nsec) */
	u_int32_t       ifn_rx_mit_mode;    /* 0: static, 1: dynamic */
	u_int32_t       ifn_rx_mit_packets_avg;/* average # of packets */
	u_int32_t       ifn_rx_mit_packets_min;/* smallest # of packets */
	u_int32_t       ifn_rx_mit_packets_max;/* largest # of packets */
	u_int32_t       ifn_rx_mit_bytes_avg;/* average # of bytes */
	u_int32_t       ifn_rx_mit_bytes_min;/* smallest # of bytes */
	u_int32_t       ifn_rx_mit_bytes_max;/* largest # of bytes */
	u_int32_t       ifn_rx_mit_cfg_idx; /* current config selector */
	u_int32_t       ifn_rx_mit_cfg_packets_lowat;/* pkts low watermark */
	u_int32_t       ifn_rx_mit_cfg_packets_hiwat;/* pkts high watermark */
	u_int32_t       ifn_rx_mit_cfg_bytes_lowat;/* bytes low watermark */
	u_int32_t       ifn_rx_mit_cfg_bytes_hiwat;/* bytes high watermark */
	u_int32_t       ifn_rx_mit_cfg_interval;/* delay interval (nsec) */
};

struct if_tcp_ecn_perf_stat {
	u_int64_t total_txpkts;
	u_int64_t total_rxmitpkts;
	u_int64_t total_rxpkts;
	u_int64_t total_oopkts;
	u_int64_t total_reorderpkts;
	u_int64_t rtt_avg;
	u_int64_t rtt_var;
	u_int64_t sack_episodes;
	u_int64_t rxmit_drop;
	u_int64_t rst_drop;
	u_int64_t oo_percent;
	u_int64_t reorder_percent;
	u_int64_t rxmit_percent;
};

struct if_tcp_ecn_stat {
	u_int64_t timestamp;
	u_int64_t ecn_client_setup;
	u_int64_t ecn_server_setup;
	u_int64_t ecn_client_success;
	u_int64_t ecn_server_success;
	u_int64_t ecn_peer_nosupport;
	u_int64_t ecn_syn_lost;
	u_int64_t ecn_synack_lost;
	u_int64_t ecn_recv_ce;
	u_int64_t ecn_recv_ece;
	u_int64_t ecn_conn_recv_ce;
	u_int64_t ecn_conn_recv_ece;
	u_int64_t ecn_conn_plnoce;
	u_int64_t ecn_conn_plce;
	u_int64_t ecn_conn_noplce;
	u_int64_t ecn_fallback_synloss;
	u_int64_t ecn_fallback_reorder;
	u_int64_t ecn_fallback_ce;
	u_int64_t ecn_off_conn;
	u_int64_t ecn_total_conn;
	u_int64_t ecn_fallback_droprst;
	u_int64_t ecn_fallback_droprxmt;
	u_int64_t ecn_fallback_synrst;
	struct if_tcp_ecn_perf_stat ecn_on;
	struct if_tcp_ecn_perf_stat ecn_off;
};

struct if_lim_perf_stat {
	u_int64_t lim_dl_max_bandwidth; /* bits per second */
	u_int64_t lim_ul_max_bandwidth; /* bits per second */
	u_int64_t lim_total_txpkts; /* Total transmit packets, count */
	u_int64_t lim_total_rxpkts; /* Total receive packets, count */
	u_int64_t lim_total_retxpkts; /* Total retransmit packets */
	u_int64_t lim_packet_loss_percent; /* Packet loss rate */
	u_int64_t lim_total_oopkts; /* Total out-of-order packets */
	u_int64_t lim_packet_ooo_percent; /* Out-of-order packet rate */
	u_int64_t lim_rtt_variance; /* RTT variance, milliseconds */
	u_int64_t lim_rtt_average;  /* RTT average, milliseconds */
	u_int64_t lim_rtt_min;      /* RTT minimum, milliseconds */
	u_int64_t lim_conn_timeouts; /* connection timeouts */
	u_int64_t lim_conn_attempts; /* connection attempts */
	u_int64_t lim_conn_timeout_percent; /* Rate of connection timeouts */
	u_int64_t lim_bk_txpkts;    /* Transmit packets with BK service class, that use delay based algorithms */
	u_int64_t lim_dl_detected:1, /* Low internet */
	    lim_ul_detected:1;
};

#define IF_VAR_H_HAS_IFNET_STATS_PER_FLOW 1
struct ifnet_stats_per_flow {
	u_int64_t bk_txpackets;
	u_int64_t txpackets;
	u_int64_t rxpackets;
	u_int32_t txretransmitbytes;
	u_int32_t rxoutoforderbytes;
	u_int32_t rxmitpkts;
	u_int32_t rcvoopack;
	u_int32_t pawsdrop;
	u_int32_t sack_recovery_episodes;
	u_int32_t reordered_pkts;
	u_int32_t dsack_sent;
	u_int32_t dsack_recvd;
	u_int32_t srtt;
	u_int32_t rttupdated;
	u_int32_t rttvar;
	u_int32_t rttmin;
	u_int32_t bw_sndbw_max;
	u_int32_t bw_rcvbw_max;
	u_int32_t ecn_recv_ece;
	u_int32_t ecn_recv_ce;
	u_int32_t ecn_flags;
	u_int16_t ipv4:1,
	    local:1,
	    connreset:1,
	    conntimeout:1,
	    rxmit_drop:1,
	    ecn_fallback_synloss:1,
	    ecn_fallback_droprst:1,
	    ecn_fallback_droprxmt:1,
	    ecn_fallback_ce:1,
	    ecn_fallback_reorder:1;
};

struct if_interface_state {
	/*
	 * The bitmask tells which of the fields
	 * to consider:
	 * - When setting, to control which fields
	 *   are being modified;
	 * - When getting, it tells which fields are set.
	 */
	u_int8_t valid_bitmask;
#define IF_INTERFACE_STATE_RRC_STATE_VALID              0x1
#define IF_INTERFACE_STATE_LQM_STATE_VALID              0x2
#define IF_INTERFACE_STATE_INTERFACE_AVAILABILITY_VALID 0x4

	/*
	 * Valid only for cellular interface
	 */
	u_int8_t rrc_state;
#define IF_INTERFACE_STATE_RRC_STATE_IDLE       0x0
#define IF_INTERFACE_STATE_RRC_STATE_CONNECTED  0x1

	/*
	 * Values normalized to the edge of the following values
	 * that are defined on <net/if.h>:
	 *  IFNET_LQM_THRESH_BAD
	 *  IFNET_LQM_THRESH_POOR
	 *  IFNET_LQM_THRESH_GOOD
	 */
	int8_t lqm_state;

	/*
	 * Indicate if the underlying link is currently
	 * available
	 */
	u_int8_t interface_availability;
#define IF_INTERFACE_STATE_INTERFACE_AVAILABLE          0x0
#define IF_INTERFACE_STATE_INTERFACE_UNAVAILABLE        0x1
};

struct chain_len_stats {
	uint64_t        cls_one;
	uint64_t        cls_two;
	uint64_t        cls_three;
	uint64_t        cls_four;
	uint64_t        cls_five_or_more;
} __attribute__((__aligned__(sizeof(uint64_t))));

#ifdef BSD_KERNEL_PRIVATE
#define IFNETS_MAX      64

/*
 * Internal storage of if_data. This is bound to change. Various places in the
 * stack will translate this data structure in to the externally visible
 * if_data structure above.  Note that during interface attach time, the
 * embedded if_data structure in ifnet is cleared, with the exception of
 * some non-statistics related fields.
 */
struct if_data_internal {
	/* generic interface information */
	u_char          ifi_type;       /* ethernet, tokenring, etc */
	u_char          ifi_typelen;    /* Length of frame type id */
	u_char          ifi_physical;   /* e.g., AUI, Thinnet, 10base-T, etc */
	u_char          ifi_addrlen;    /* media address length */
	u_char          ifi_hdrlen;     /* media header length */
	u_char          ifi_recvquota;  /* polling quota for receive intrs */
	u_char          ifi_xmitquota;  /* polling quota for xmit intrs */
	u_char          ifi_unused1;    /* for future use */
	u_int32_t       ifi_mtu;        /* maximum transmission unit */
	u_int32_t       ifi_metric;     /* routing metric (external only) */
	u_int32_t       ifi_baudrate;   /* linespeed */
	/* volatile statistics */
	u_int64_t       ifi_ipackets;   /* packets received on interface */
	u_int64_t       ifi_ierrors;    /* input errors on interface */
	u_int64_t       ifi_opackets;   /* packets sent on interface */
	u_int64_t       ifi_oerrors;    /* output errors on interface */
	u_int64_t       ifi_collisions; /* collisions on csma interfaces */
	u_int64_t       ifi_ibytes;     /* total number of octets received */
	u_int64_t       ifi_obytes;     /* total number of octets sent */
	u_int64_t       ifi_imcasts;    /* packets received via multicast */
	u_int64_t       ifi_omcasts;    /* packets sent via multicast */
	u_int64_t       ifi_iqdrops;    /* dropped on input, this interface */
	u_int64_t       ifi_noproto;    /* destined for unsupported protocol */
	u_int32_t       ifi_recvtiming; /* usec spent receiving when timing */
	u_int32_t       ifi_xmittiming; /* usec spent xmitting when timing */
	u_int64_t       ifi_alignerrs;  /* unaligned (32-bit) input pkts */
	u_int64_t       ifi_dt_bytes;   /* Data threshold counter */
	u_int64_t       ifi_fpackets;   /* forwarded packets on interface */
	u_int64_t       ifi_fbytes;     /* forwarded bytes on interface */
	struct  timeval ifi_lastchange; /* time of last administrative change */
	struct  timeval ifi_lastupdown; /* time of last up/down event */
	u_int32_t       ifi_hwassist;   /* HW offload capabilities */
	u_int32_t       ifi_tso_v4_mtu; /* TCP Segment Offload IPv4 maximum segment size */
	u_int32_t       ifi_tso_v6_mtu; /* TCP Segment Offload IPv6 maximum segment size */
};
#endif /* BSD_KERNEL_PRIVATE */

#define if_mtu          if_data.ifi_mtu
#define if_type         if_data.ifi_type
#define if_typelen      if_data.ifi_typelen
#define if_physical     if_data.ifi_physical
#define if_addrlen      if_data.ifi_addrlen
#define if_hdrlen       if_data.ifi_hdrlen
#define if_metric       if_data.ifi_metric
#define if_baudrate     if_data.ifi_baudrate
#define if_hwassist     if_data.ifi_hwassist
#define if_ipackets     if_data.ifi_ipackets
#define if_ierrors      if_data.ifi_ierrors
#define if_opackets     if_data.ifi_opackets
#define if_oerrors      if_data.ifi_oerrors
#define if_collisions   if_data.ifi_collisions
#define if_ibytes       if_data.ifi_ibytes
#define if_obytes       if_data.ifi_obytes
#define if_imcasts      if_data.ifi_imcasts
#define if_omcasts      if_data.ifi_omcasts
#define if_iqdrops      if_data.ifi_iqdrops
#define if_noproto      if_data.ifi_noproto
#define if_lastchange   if_data.ifi_lastchange
#define if_recvquota    if_data.ifi_recvquota
#define if_xmitquota    if_data.ifi_xmitquota
#ifdef BSD_KERNEL_PRIVATE
#define if_tso_v4_mtu   if_data.ifi_tso_v4_mtu
#define if_tso_v6_mtu   if_data.ifi_tso_v6_mtu
#define if_alignerrs    if_data.ifi_alignerrs
#define if_dt_bytes     if_data.ifi_dt_bytes
#define if_fpackets     if_data.ifi_fpackets
#define if_fbytes       if_data.ifi_fbytes
#define if_lastupdown   if_data.ifi_lastupdown

/*
 * Forward structure declarations for function prototypes [sic].
 */
struct proc;
struct rtentry;
struct socket;
struct ifnet_filter;
struct mbuf;
struct ifaddr;
struct tqdummy;
struct proto_hash_entry;
struct dlil_threading_info;
struct tcpstat_local;
struct udpstat_local;
#if PF
struct pfi_kif;
#endif /* PF */
#if SKYWALK
struct nexus_netif_adapter;
#endif /* SKYWALK */

/* we use TAILQs so that the order of instantiation is preserved in the list */
TAILQ_HEAD(ifnethead, ifnet);
TAILQ_HEAD(ifaddrhead, ifaddr);
LIST_HEAD(ifmultihead, ifmultiaddr);
TAILQ_HEAD(tailq_head, tqdummy);
TAILQ_HEAD(ifnet_filter_head, ifnet_filter);
TAILQ_HEAD(ddesc_head_name, dlil_demux_desc);

extern bool intcoproc_unrestricted;
extern bool management_data_unrestricted;
extern bool management_control_unrestricted;
extern bool if_management_interface_check_needed;
extern int if_management_verbose;
#endif /* BSD_KERNEL_PRIVATE */

/*
 * All of the following IF_HWASSIST_* flags are defined in kpi_interface.h as
 * IFNET_* flags. These are redefined here as constants to avoid failures to
 * build user level programs that can not include kpi_interface.h. It is
 * important to keep this in sync with the definitions in kpi_interface.h.
 * The corresponding constant for each definition is mentioned in the comment.
 *
 * Bottom 16 bits reserved for hardware checksum
 */
#define IF_HWASSIST_CSUM_IP             0x0001  /* will csum IP, IFNET_CSUM_IP */
#define IF_HWASSIST_CSUM_TCP            0x0002  /* will csum TCP, IFNET_CSUM_TCP */
#define IF_HWASSIST_CSUM_UDP            0x0004  /* will csum UDP, IFNET_CSUM_UDP */
#define IF_HWASSIST_CSUM_IP_FRAGS       0x0008  /* will csum IP fragments, IFNET_CSUM_FRAGMENT */
#define IF_HWASSIST_CSUM_FRAGMENT       0x0010  /* will do IP fragmentation, IFNET_IP_FRAGMENT */
#define IF_HWASSIST_CSUM_TCPIPV6        0x0020  /* will csum TCPv6, IFNET_CSUM_TCPIPV6 */
#define IF_HWASSIST_CSUM_UDPIPV6        0x0040  /* will csum UDPv6, IFNET_CSUM_UDP */
#define IF_HWASSIST_CSUM_FRAGMENT_IPV6  0x0080  /* will do IPv6 fragmentation, IFNET_IPV6_FRAGMENT */
#define IF_HWASSIST_CSUM_PARTIAL        0x1000  /* simple Sum16 computation, IFNET_CSUM_PARTIAL */
#define IF_HWASSIST_CSUM_ZERO_INVERT    0x2000  /* capable of inverting csum of 0 to -0 (0xffff) */
#define IF_HWASSIST_CSUM_MASK           0xffff
#define IF_HWASSIST_CSUM_FLAGS(hwassist)        ((hwassist) & IF_HWASSIST_CSUM_MASK)

/* VLAN support */
#define IF_HWASSIST_VLAN_TAGGING        0x00010000      /* supports VLAN tagging, IFNET_VLAN_TAGGING */
#define IF_HWASSIST_VLAN_MTU            0x00020000      /* supports VLAN MTU-sized packet (for software VLAN), IFNET_VLAN_MTU */

/* TCP Segment Offloading support */

#define IF_HWASSIST_TSO_V4              0x00200000      /* will do TCP Segment offload for IPv4, IFNET_TSO_IPV4 */
#define IF_HWASSIST_TSO_V6              0x00400000      /* will do TCP Segment offload for IPv6, IFNET_TSO_IPV6 */

#define IFXNAMSIZ       (IFNAMSIZ + 8)  /* external name (name + unit) */
#define IFNET_NETWORK_ID_LEN 32

#ifdef BSD_KERNEL_PRIVATE
/*
 * ifnet is private to BSD portion of kernel
 */
#include <sys/mcache.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/classq/if_classq.h>
#include <net/if_types.h>
#include <net/route.h>

RB_HEAD(ll_reach_tree, if_llreach);     /* define struct ll_reach_tree */

#if SKYWALK
struct nexus_ifnet_ops {
	void (*ni_finalize)(struct nexus_netif_adapter *, struct ifnet *);
	void (*ni_reap)(struct nexus_netif_adapter *, struct ifnet *,
	    uint32_t, boolean_t);
	errno_t (*ni_dequeue)(struct nexus_netif_adapter *, uint32_t,
	    uint32_t, uint32_t, classq_pkt_t *, classq_pkt_t *, uint32_t *,
	    uint32_t *, boolean_t, errno_t);
	errno_t (*ni_get_len)(struct nexus_netif_adapter *, uint32_t,
	    uint32_t *, uint32_t *, errno_t);
	void (*ni_detach_notify)(struct nexus_netif_adapter *);
};
typedef struct {
	uuid_t          if_nif_provider;
	uuid_t          if_nif_instance;
	uuid_t          if_nif_attach;
} if_nexus_netif, *if_nexus_netif_t;

typedef struct {
	uuid_t          if_fsw_provider;
	uuid_t          if_fsw_instance;
	uuid_t          if_fsw_device;
	uint32_t        if_fsw_ipaddr_gencnt;
} if_nexus_flowswitch, *if_nexus_flowswitch_t;
#endif /* SKYWALK */

typedef errno_t (*dlil_input_func)(ifnet_t ifp, mbuf_t m_head,
    mbuf_t m_tail, const struct ifnet_stat_increment_param *s,
    boolean_t poll, struct thread *tp);
typedef errno_t (*dlil_output_func)(ifnet_t interface, mbuf_t data);

typedef u_int8_t        ipv6_router_mode_t;

#define if_name(ifp)    ifp->if_xname
/*
 * Structure defining a network interface.
 *
 * (Would like to call this struct ``if'', but C isn't PL/1.)
 */
struct ifnet {
	/*
	 * Lock (RW or mutex) to protect this data structure (static storage.)
	 */
	decl_lck_rw_data(, if_lock);
	void            *if_softc;      /* pointer to driver state */
	const char      *if_name;       /* name, e.g. ``en'' or ``lo'' */
	const char      *if_xname;      /* external name (name + unit) */
	struct if_description if_desc;  /* extended description */
	TAILQ_ENTRY(ifnet) if_link;     /* all struct ifnets are chained */
	TAILQ_ENTRY(ifnet) if_detaching_link; /* list of detaching ifnets */
	TAILQ_ENTRY(ifnet) if_ordered_link;     /* list of ordered ifnets */

	decl_lck_mtx_data(, if_ref_lock);
	u_int32_t       if_refflags;    /* see IFRF flags below */
	u_int32_t       if_refio;       /* number of io ops to the underlying driver */
	u_int32_t       if_threads_pending;    /* Threads created but waiting for first run */
	u_int32_t       if_datamov;     /* number of threads moving data */
	u_int32_t       if_drainers;    /* number of draining threads */
	u_int32_t       if_suspend;     /* number of suspend requests */

#define if_list         if_link
	struct ifaddrhead if_addrhead;  /* linked list of addresses per if */
#define if_addrlist     if_addrhead
	struct ifaddr   *if_lladdr;     /* link address (first/permanent) */

	u_int32_t       if_qosmarking_mode;     /* generation to use with NECP clients */

	int             if_pcount;      /* number of promiscuous listeners */
	struct bpf_if   *if_bpf;        /* packet filter structure */
	u_short         if_index;       /* numeric abbreviation for this if  */
	short           if_unit;        /* sub-unit for lower level driver */
	short           if_timer;       /* time 'til if_watchdog called */
	short           if_flags;       /* up/down, broadcast, etc. */
	u_int32_t       if_eflags;      /* see <net/if.h> */
	u_int32_t       if_xflags;      /* see <net/if.h> */

	int             if_capabilities;        /* interface features & capabilities */
	int             if_capenable;           /* enabled features & capabilities */

	void            *if_linkmib;    /* link-type-specific MIB data */
	uint32_t         if_linkmiblen;  /* length of above data */

	struct if_data_internal if_data __attribute__((aligned(8)));

	ifnet_family_t          if_family;      /* value assigned by Apple */
	ifnet_subfamily_t       if_subfamily;   /* value assigned by Apple */
	uintptr_t               if_family_cookie;
	volatile dlil_input_func if_input_dlil;
	volatile dlil_output_func if_output_dlil;
	volatile ifnet_start_func if_start;
	ifnet_output_func       if_output;
	ifnet_pre_enqueue_func  if_pre_enqueue;
	ifnet_ctl_func          if_output_ctl;
	ifnet_input_poll_func   if_input_poll;
	ifnet_ctl_func          if_input_ctl;
	ifnet_ioctl_func        if_ioctl;
	ifnet_set_bpf_tap       if_set_bpf_tap;
	ifnet_detached_func     if_free;
	ifnet_demux_func        if_demux;
	ifnet_event_func        if_event;
	ifnet_framer_func       if_framer_legacy;
	ifnet_framer_extended_func if_framer;
	ifnet_add_proto_func    if_add_proto;
	ifnet_del_proto_func    if_del_proto;
	ifnet_check_multi       if_check_multi;
	struct proto_hash_entry *if_proto_hash;
	ifnet_detached_func     if_detach;

	u_int32_t               if_flowhash;    /* interface flow control ID */

	decl_lck_mtx_data(, if_start_lock);
	u_int32_t               if_start_flags; /* see IFSF flags below */
	u_int32_t               if_start_req;
	u_int8_t                if_start_embryonic;
	u_int8_t                if_start_active; /* output is active */
	u_int16_t               if_start_delayed;
	u_int16_t               if_start_delay_qlen;
	u_int16_t               if_start_delay_idle;
	u_int64_t               if_start_delay_swin;
	u_int32_t               if_start_delay_cnt;
	u_int32_t               if_start_delay_timeout; /* nanoseconds */
	struct timespec         if_start_cycle;  /* restart interval */
	struct thread           *if_start_thread;

	struct ifclassq         *if_snd;         /* transmit queue */
	u_int32_t               if_output_sched_model;  /* tx sched model */

	struct if_bandwidths    if_output_bw;
	struct if_bandwidths    if_input_bw;

	struct if_latencies     if_output_lt;
	struct if_latencies     if_input_lt;

	decl_lck_mtx_data(, if_flt_lock);
	u_int32_t               if_flt_busy;
	u_int32_t               if_flt_waiters;
	struct ifnet_filter_head if_flt_head;
	uint32_t                if_flt_non_os_count;
	uint32_t                if_flt_no_tso_count;

	struct ifmultihead      if_multiaddrs;  /* multicast addresses */
	u_int32_t               if_updatemcasts; /* mcast addrs need updating */
	int                     if_amcount;     /* # of all-multicast reqs */
	decl_lck_mtx_data(, if_addrconfig_lock); /* for serializing addr config */
	struct in_multi         *if_allhostsinm; /* store all-hosts inm for this ifp */

	/*
	 * Opportunistic polling parameters.
	 */
	decl_lck_mtx_data(, if_poll_lock);
	struct if_poll_params {
		u_int16_t       poll_req;
		u_int16_t       poll_update; /* link update */
		u_int32_t       poll_flags;
#define IF_POLLF_READY          0x1     /* poll thread is ready */
#define IF_POLLF_RUNNING        0x2     /* poll thread is running/active */
#define IF_POLLF_TERMINATING    0x4     /* poll thread is terminating */
#define IF_POLLF_EMBRYONIC      0x8000  /* poll thread is being setup */
		struct timespec poll_cycle;  /* poll interval */
		struct thread   *poll_thread;

		ifnet_model_t   poll_mode;   /* current mode */
		struct pktcntr  poll_tstats; /* incremental polling statistics */
		struct if_rxpoll_stats poll_pstats;  /* polling statistics */
		struct pktcntr  poll_sstats; /* packets and bytes per sampling */
		struct timespec poll_mode_holdtime; /* mode holdtime in nsec */
		struct timespec poll_mode_lasttime; /* last mode change time in nsec */
		struct timespec poll_sample_holdtime; /* sampling holdtime in nsec */
		struct timespec poll_sample_lasttime; /* last sampling time in nsec */
		struct timespec poll_dbg_lasttime; /* last debug message time in nsec */
	} rxpoll_params;
#define if_poll_req     rxpoll_params.poll_req
#define if_poll_update  rxpoll_params.poll_update
#define if_poll_flags   rxpoll_params.poll_flags
#define if_poll_cycle   rxpoll_params.poll_cycle
#define if_poll_thread  rxpoll_params.poll_thread
#define if_poll_mode    rxpoll_params.poll_mode
#define if_poll_tstats  rxpoll_params.poll_tstats
#define if_poll_sstats  rxpoll_params.poll_sstats
#define if_poll_pstats  rxpoll_params.poll_pstats

#define if_poll_mode_holdtime    rxpoll_params.poll_mode_holdtime
#define if_poll_mode_lasttime    rxpoll_params.poll_mode_lasttime
#define if_poll_sample_holdtime  rxpoll_params.poll_sample_holdtime
#define if_poll_sample_lasttime  rxpoll_params.poll_sample_lasttime
#define if_poll_dbg_lasttime     rxpoll_params.poll_dbg_lasttime

#define if_rxpoll_offreq   rxpoll_params.poll_pstats.ifi_poll_off_req
#define if_rxpoll_offerr   rxpoll_params.poll_pstats.ifi_poll_off_err
#define if_rxpoll_onreq    rxpoll_params.poll_pstats.ifi_poll_on_req
#define if_rxpoll_onerr    rxpoll_params.poll_pstats.ifi_poll_on_err
#define if_rxpoll_wavg     rxpoll_params.poll_pstats.ifi_poll_wakeups_avg
#define if_rxpoll_wlowat   rxpoll_params.poll_pstats.ifi_poll_wakeups_lowat
#define if_rxpoll_whiwat   rxpoll_params.poll_pstats.ifi_poll_wakeups_hiwat
#define if_rxpoll_pavg     rxpoll_params.poll_pstats.ifi_poll_packets_avg
#define if_rxpoll_pmin     rxpoll_params.poll_pstats.ifi_poll_packets_min
#define if_rxpoll_pmax     rxpoll_params.poll_pstats.ifi_poll_packets_max
#define if_rxpoll_plowat   rxpoll_params.poll_pstats.ifi_poll_packets_lowat
#define if_rxpoll_phiwat   rxpoll_params.poll_pstats.ifi_poll_packets_hiwat
#define if_rxpoll_bavg     rxpoll_params.poll_pstats.ifi_poll_bytes_avg
#define if_rxpoll_bmin     rxpoll_params.poll_pstats.ifi_poll_bytes_min
#define if_rxpoll_bmax     rxpoll_params.poll_pstats.ifi_poll_bytes_max
#define if_rxpoll_blowat   rxpoll_params.poll_pstats.ifi_poll_bytes_lowat
#define if_rxpoll_bhiwat   rxpoll_params.poll_pstats.ifi_poll_bytes_hiwat
#define if_rxpoll_plim     rxpoll_params.poll_pstats.ifi_poll_packets_limit
#define if_rxpoll_ival     rxpoll_params.poll_pstats.ifi_poll_interval_time

	struct dlil_threading_info *if_inp;

	/* allocated once along with dlil_ifnet and is never freed */
	thread_call_t           if_dt_tcall;

	struct {
		u_int32_t       length;
		union {
			u_char  buffer[8];
			u_char  *ptr;
		} u;
	} if_broadcast;

#if PF
	struct pfi_kif          *if_pf_kif;
#endif /* PF */
#if SKYWALK
	struct nexus_ifnet_ops *if_na_ops;
	struct nexus_netif_adapter *if_na;

	/* compat netif attachment */
	if_nexus_netif          if_nx_netif;

	/* flowswitch attachment */
	if_nexus_flowswitch     if_nx_flowswitch;

	/* headroom space to be reserved in tx packets */
	uint16_t                if_tx_headroom;

	/* trailer space to be reserved in tx packets */
	uint16_t                if_tx_trailer;

	/*
	 * mitigation interval in microseconds for the rx interrupt mitigation
	 * logic while operating in the high throughput mode.
	 */
	uint32_t                if_rx_mit_ival;

	ifnet_start_func        if_save_start;
	ifnet_output_func       if_save_output;

	/*
	 * Number of threads waiting for the start callback to be finished;
	 * access is protected by if_start_lock; also serves as wait channel.
	 */
	uint32_t                if_start_waiters;
#endif /* SKYWALK */

	decl_lck_mtx_data(, if_cached_route_lock);
	u_int32_t               if_fwd_cacheok;
	struct route            if_fwd_route;   /* cached forwarding route */
	struct route            if_src_route;   /* cached ipv4 source route */
	struct route_in6        if_src_route6;  /* cached ipv6 source route */

	decl_lck_rw_data(, if_llreach_lock);
	struct ll_reach_tree    if_ll_srcs;     /* source link-layer tree */

	void                    *if_bridge;     /* bridge glue */

	u_int32_t               if_idle_flags;  /* idle flags */
	u_int32_t               if_idle_new_flags; /* temporary idle flags */
	u_int32_t               if_idle_new_flags_mask; /* temporary mask */
	u_int32_t               if_route_refcnt; /* idle: route ref count */
	u_int32_t               if_rt_sendts;   /* last of a real time packet */

	struct if_traffic_class if_tc __attribute__((aligned(8)));
#if INET
	struct igmp_ifinfo      *if_igi;        /* for IGMPv3 */
#endif /* INET */
	struct mld_ifinfo       *if_mli;        /* for MLDv2 */

	struct tcpstat_local    *if_tcp_stat;   /* TCP specific stats */
	struct udpstat_local    *if_udp_stat;   /* UDP specific stats */

	struct {
		int32_t         level;          /* cached logging level */
		u_int32_t       flags;          /* cached logging flags */
		int32_t         category;       /* cached category */
		int32_t         subcategory;    /* cached subcategory */
	} if_log;

	struct {
		struct ifnet    *ifp;           /* delegated ifp */
		u_int32_t       type;           /* delegated i/f type */
		u_int32_t       family;         /* delegated i/f family */
		u_int32_t       subfamily;      /* delegated i/f sub-family */
		uint32_t        expensive:1,    /* delegated i/f expensive? */
		    constrained:1;              /* delegated i/f constrained? */
	} if_delegated;

	uuid_t                  *if_agentids;   /* network agents attached to interface */
	u_int32_t               if_agentcount;

	volatile uint32_t       if_low_power_gencnt;

	u_int32_t               if_generation;  /* generation to use with NECP clients */
	u_int32_t               if_fg_sendts;   /* last send on a fg socket in seconds */

	u_int64_t               if_data_threshold;

	/* Total bytes in send socket buffer */
	int64_t                 if_sndbyte_total __attribute__ ((aligned(8)));
	/* Total unsent bytes in send socket buffer */
	int64_t                 if_sndbyte_unsent __attribute__ ((aligned(8)));
	/* count of times, when there was data to send when sleep is impending */
	uint32_t                if_unsent_data_cnt;

#if INET
	decl_lck_rw_data(, if_inetdata_lock);
	struct in_ifextra       *if_inetdata;
#endif /* INET */
	decl_lck_mtx_data(, if_inet6_ioctl_lock);
	boolean_t   if_inet6_ioctl_busy;
	decl_lck_rw_data(, if_inet6data_lock);
	struct in6_ifextra      *if_inet6data;
	decl_lck_rw_data(, if_link_status_lock);
	struct if_link_status   *if_link_status;
	struct if_interface_state       if_interface_state;
	struct if_tcp_ecn_stat *if_ipv4_stat;
	struct if_tcp_ecn_stat *if_ipv6_stat;

#if SKYWALK
	/* Keeps track of local ports bound to this interface
	 * Protected by the global lock in skywalk/netns/netns.c */
	SLIST_HEAD(, ns_token) if_netns_tokens;
#endif /* SKYWALK */
	struct if_lim_perf_stat if_lim_stat;

	uint32_t        if_tcp_kao_max;
	uint32_t        if_tcp_kao_cnt;

#if SKYWALK
	struct netem    *if_input_netem;
#endif /* SKYWALK */
	struct netem    *if_output_netem;

	ipv6_router_mode_t if_ipv6_router_mode; /* see <netinet6/in6_var.h> */

	u_int8_t        if_estimated_up_bucket;
	u_int8_t        if_estimated_down_bucket;
	u_int8_t        if_radio_type;
	u_int8_t        if_radio_channel;

	uint8_t         network_id[IFNET_NETWORK_ID_LEN];
	uint8_t         network_id_len;
	uint32_t        if_traffic_rule_count;
	uint32_t        if_traffic_rule_genid;
};

/* Interface event handling declarations */
extern struct eventhandler_lists_ctxt ifnet_evhdlr_ctxt;

typedef enum {
	INTF_EVENT_CODE_CREATED,
	INTF_EVENT_CODE_REMOVED,
	INTF_EVENT_CODE_STATUS_UPDATE,
	INTF_EVENT_CODE_IPADDR_ATTACHED,
	INTF_EVENT_CODE_IPADDR_DETACHED,
	INTF_EVENT_CODE_LLADDR_UPDATE,
	INTF_EVENT_CODE_MTU_CHANGED,
	INTF_EVENT_CODE_LOW_POWER_UPDATE,
} intf_event_code_t;

typedef void (*ifnet_event_fn)(struct eventhandler_entry_arg, struct ifnet *, struct sockaddr *, intf_event_code_t);
EVENTHANDLER_DECLARE(ifnet_event, ifnet_event_fn);

#define IF_TCP_STATINC(_ifp, _s) do {                                   \
    if ((_ifp)->if_tcp_stat != NULL)                                \
	    atomic_add_64(&(_ifp)->if_tcp_stat->_s, 1);             \
} while (0);

#define IF_UDP_STATINC(_ifp, _s) do {                                   \
    if ((_ifp)->if_udp_stat != NULL)                                \
	    atomic_add_64(&(_ifp)->if_udp_stat->_s, 1);             \
} while (0);

/*
 * Valid values for if_refflags
 */
#define IFRF_EMBRYONIC  0x1     /* ifnet is allocated; awaiting attach */
#define IFRF_ATTACHED   0x2     /* ifnet attach is completely done */
#define IFRF_DETACHING  0x4     /* detach has been requested */
#define IFRF_READY      0x8     /* data path is ready */

#define IFRF_ATTACH_MASK        \
    (IFRF_EMBRYONIC|IFRF_ATTACHED|IFRF_DETACHING)

#define IF_FULLY_ATTACHED(_ifp) \
    (((_ifp)->if_refflags & IFRF_ATTACH_MASK) == IFRF_ATTACHED)

#define IF_FULLY_ATTACHED_AND_READY(_ifp) \
    (IF_FULLY_ATTACHED(_ifp) && ((_ifp)->if_refflags & IFRF_READY))
/*
 * Valid values for if_start_flags
 */
#define IFSF_FLOW_CONTROLLED    0x1     /* flow controlled */
#define IFSF_TERMINATING        0x2     /* terminating */

/*
 * Structure describing a `cloning' interface.
 */
struct if_clone {
	LIST_ENTRY(if_clone) ifc_list;  /* on list of cloners */
	decl_lck_mtx_data(, ifc_mutex); /* To serialize clone create/delete */
	u_int32_t       ifc_minifs;     /* minimum number of interfaces */
	u_int32_t       ifc_maxunit;    /* maximum unit number */
	unsigned char   *ifc_units;     /* bitmap to handle units */
	u_int32_t       ifc_bmlen;      /* bitmap length */
	int             (*ifc_create)(struct if_clone *, u_int32_t, void *);
	int             (*ifc_destroy)(struct ifnet *);
	uint8_t         ifc_namelen;    /* length of name */
	char            ifc_name[IFNAMSIZ + 1]; /* name of device, e.g. `vlan' */
};

#define IF_CLONE_INITIALIZER(name, create, destroy, minifs, maxunit) {          \
    .ifc_name = "" name,                                                        \
    .ifc_namelen = (sizeof(name) - 1),                                          \
    .ifc_minifs = (minifs),                                                     \
    .ifc_maxunit = (maxunit),                                                   \
    .ifc_create = (create),                                                     \
    .ifc_destroy = (destroy)                                                    \
}

/*
 * Macros to manipulate ifqueue.  Users of these macros are responsible
 * for serialization, by holding whatever lock is appropriate for the
 * corresponding structure that is referring the ifqueue.
 */
#define IF_QFULL(ifq)           ((ifq)->ifq_len >= (ifq)->ifq_maxlen)
#define IF_DROP(ifq)            ((ifq)->ifq_drops++)

#define IF_ENQUEUE(ifq, m) do {                                     \
    (m)->m_nextpkt = NULL;                                          \
    if ((ifq)->ifq_tail == NULL)                                    \
	    (ifq)->ifq_head = m;                                    \
    else                                                            \
	    ((struct mbuf*)(ifq)->ifq_tail)->m_nextpkt = m;         \
    (ifq)->ifq_tail = m;                                            \
    (ifq)->ifq_len++;                                               \
} while (0)

#define IF_PREPEND(ifq, m) do {                                     \
    (m)->m_nextpkt = (mbuf_ref_t)(ifq)->ifq_head;                   \
    if ((ifq)->ifq_tail == NULL)                                    \
	    (ifq)->ifq_tail = (m);                                  \
    (ifq)->ifq_head = (m);                                          \
    (ifq)->ifq_len++;                                               \
} while (0)

#define IF_DEQUEUE(ifq, m) do {                                     \
    (m) = (mbuf_ref_t)(ifq)->ifq_head;                              \
    if (m != NULL) {                                                \
	    if (((ifq)->ifq_head = (m)->m_nextpkt) == NULL)         \
	            (ifq)->ifq_tail = NULL;                         \
	    (m)->m_nextpkt = NULL;                                  \
	    (ifq)->ifq_len--;                                       \
    }                                                               \
} while (0)

#define IF_REMQUEUE(ifq, m) do {                                    \
    mbuf_ref_t _p = (mbuf_ref_t)(ifq)->ifq_head;                    \
    mbuf_ref_t _n = (m)->m_nextpkt;                                 \
    if ((m) == _p)                                                  \
	    _p = NULL;                                              \
    while (_p != NULL) {                                            \
	    if (_p->m_nextpkt == (m))                               \
	            break;                                          \
	    _p = _p->m_nextpkt;                                     \
    }                                                               \
    VERIFY(_p != NULL || ((m) == (ifq)->ifq_head));                 \
    if ((m) == (ifq)->ifq_head)                                     \
	    (ifq)->ifq_head = _n;                                   \
    if ((m) == (ifq)->ifq_tail)                                     \
	    (ifq)->ifq_tail = _p;                                   \
    VERIFY((ifq)->ifq_tail != NULL || (ifq)->ifq_head == NULL);     \
    VERIFY((ifq)->ifq_len != 0);                                    \
    --(ifq)->ifq_len;                                               \
    if (_p != NULL)                                                 \
	    _p->m_nextpkt = _n;                                     \
    (m)->m_nextpkt = NULL;                                          \
} while (0)

#define IF_DRAIN(ifq) do {                                              \
    struct mbuf *_m;                                                \
    for (;;) {                                                      \
	    IF_DEQUEUE(ifq, _m);                                    \
	    if (_m == NULL)                                         \
	            break;                                          \
	    m_freem(_m);                                            \
    }                                                               \
} while (0)

/*
 * The ifaddr structure contains information about one address
 * of an interface.  They are maintained by the different address families,
 * are allocated and attached when an address is set, and are linked
 * together so all addresses for an interface can be located.
 */
struct ifaddr {
	decl_lck_mtx_data(, ifa_lock);  /* lock for ifaddr */
	uint32_t        ifa_refcnt;     /* ref count, use IFA_{ADD,REM}REF */
	uint32_t        ifa_debug;      /* debug flags */
	struct sockaddr *ifa_addr;      /* address of interface */
	struct sockaddr *ifa_dstaddr;   /* other end of p-to-p link */
#define ifa_broadaddr   ifa_dstaddr     /* broadcast address interface */
	struct sockaddr *ifa_netmask;   /* used to determine subnet */
	struct ifnet    *ifa_ifp;       /* back-pointer to interface */
	TAILQ_ENTRY(ifaddr) ifa_link;   /* queue macro glue */
	void (*ifa_rtrequest)           /* check or clean routes (+ or -)'d */
	(int, struct rtentry *, struct sockaddr *);
	uint32_t        ifa_flags;      /* mostly rt_flags for cloning */
	int32_t         ifa_metric;     /* cost of going out this interface */
	void (*ifa_free)(struct ifaddr *); /* callback fn for freeing */
	void (*ifa_trace)               /* callback fn for tracing refs */
	(struct ifaddr *, int);
	void (*ifa_attached)(struct ifaddr *); /* callback fn for attaching */
	void (*ifa_detached)(struct ifaddr *); /* callback fn for detaching */
	void *ifa_del_wc;               /* Wait channel to avoid address deletion races */
	int ifa_del_waiters;            /* Threads in wait to delete the address */
};

/*
 * Valid values for ifa_flags
 */
#define IFA_ROUTE       RTF_UP          /* route installed (0x1) */
#define IFA_CLONING     RTF_CLONING     /* (0x100) */

/*
 * Valid values for ifa_debug
 */
#define IFD_ATTACHED    0x1             /* attached to list */
#define IFD_ALLOC       0x2             /* dynamically allocated */
#define IFD_DEBUG       0x4             /* has debugging info */
#define IFD_LINK        0x8             /* link address */
#define IFD_TRASHED     0x10            /* in trash list */
#define IFD_DETACHING   0x20            /* detach is in progress */
#define IFD_NOTREADY    0x40            /* embryonic; not yet ready */

#define IFA_LOCK_ASSERT_HELD(_ifa)                                      \
    LCK_MTX_ASSERT(&(_ifa)->ifa_lock, LCK_MTX_ASSERT_OWNED)

#define IFA_LOCK_ASSERT_NOTHELD(_ifa)                                   \
    LCK_MTX_ASSERT(&(_ifa)->ifa_lock, LCK_MTX_ASSERT_NOTOWNED)

#define IFA_LOCK(_ifa)                                                  \
    lck_mtx_lock(&(_ifa)->ifa_lock)

#define IFA_LOCK_SPIN(_ifa)                                             \
    lck_mtx_lock_spin(&(_ifa)->ifa_lock)

#define IFA_CONVERT_LOCK(_ifa) do {                                     \
    IFA_LOCK_ASSERT_HELD(_ifa);                                     \
    lck_mtx_convert_spin(&(_ifa)->ifa_lock);                        \
} while (0)

#define IFA_UNLOCK(_ifa)                                                \
    lck_mtx_unlock(&(_ifa)->ifa_lock)

#define IFA_ADDREF(_ifa)                                                \
    ifa_addref(_ifa, 0)

#define IFA_ADDREF_LOCKED(_ifa)                                         \
    ifa_addref(_ifa, 1)

#define IFA_REMREF(_ifa) do {                                           \
    (void) ifa_remref(_ifa, 0);                                     \
} while (0)

#define IFA_REMREF_LOCKED(_ifa)                                         \
    ifa_remref(_ifa, 1)

/*
 * Multicast address structure.  This is analogous to the ifaddr
 * structure except that it keeps track of multicast addresses.
 * Also, the request count here is a count of requests for this
 * address, not a count of pointers to this structure; anonymous
 * membership(s) holds one outstanding request count.
 */
struct ifmultiaddr {
	decl_lck_mtx_data(, ifma_lock);
	u_int32_t ifma_refcount;        /* reference count */
	u_int32_t ifma_anoncnt;         /* # of anonymous requests */
	u_int32_t ifma_reqcnt;          /* total requests for this address */
	u_int32_t ifma_debug;           /* see ifa_debug flags */
	u_int32_t ifma_flags;           /* see below */
	LIST_ENTRY(ifmultiaddr) ifma_link; /* queue macro glue */
	struct sockaddr *ifma_addr;     /* address this membership is for */
	struct ifmultiaddr *ifma_ll;    /* link-layer translation, if any */
	struct ifnet *ifma_ifp;         /* back-pointer to interface */
	void *ifma_protospec;           /* protocol-specific state, if any */
	void (*ifma_trace)              /* callback fn for tracing refs */
	(struct ifmultiaddr *, int);
};

/*
 * Values for ifma_flags
 */
#define IFMAF_ANONYMOUS         0x1     /* has anonymous request ref(s) held */

#define IFMA_LOCK_ASSERT_HELD(_ifma)                                    \
    LCK_MTX_ASSERT(&(_ifma)->ifma_lock, LCK_MTX_ASSERT_OWNED)

#define IFMA_LOCK_ASSERT_NOTHELD(_ifma)                                 \
    LCK_MTX_ASSERT(&(_ifma)->ifma_lock, LCK_MTX_ASSERT_NOTOWNED)

#define IFMA_LOCK(_ifma)                                                \
    lck_mtx_lock(&(_ifma)->ifma_lock)

#define IFMA_LOCK_SPIN(_ifma)                                           \
    lck_mtx_lock_spin(&(_ifma)->ifma_lock)

#define IFMA_CONVERT_LOCK(_ifma) do {                                   \
    IFMA_LOCK_ASSERT_HELD(_ifma);                                   \
    lck_mtx_convert_spin(&(_ifma)->ifma_lock);                      \
} while (0)

#define IFMA_UNLOCK(_ifma)                                              \
    lck_mtx_unlock(&(_ifma)->ifma_lock)

#define IFMA_ADDREF(_ifma)                                              \
    ifma_addref(_ifma, 0)

#define IFMA_ADDREF_LOCKED(_ifma)                                       \
    ifma_addref(_ifma, 1)

#define IFMA_REMREF(_ifma)                                              \
    ifma_remref(_ifma)

/*
 * Indicate whether or not the immediate interface, or the interface delegated
 * by it, is a cellular interface (IFT_CELLULAR).  Delegated interface type is
 * set/cleared along with the delegated ifp; we cache the type for performance
 * to avoid dereferencing delegated ifp each time.
 *
 * Note that this is meant to be used only for accounting and policy purposes;
 * certain places need to explicitly know the immediate interface type, and
 * this macro should not be used there.
 *
 * The test is done against IFT_CELLULAR instead of IFNET_FAMILY_CELLULAR to
 * handle certain cases where the family isn't set to the latter.
 *
 * This macro also handles the case of IFNET_FAMILY_ETHERNET with
 * IFNET_SUBFAMILY_SIMCELL which is used to simulate a cellular interface
 * for testing purposes. The underlying interface is Ethernet but we treat
 * it as cellular for accounting and policy purposes.
 */
#define IFNET_IS_CELLULAR(_ifp)                                         \
    ((_ifp)->if_type == IFT_CELLULAR ||                             \
    (_ifp)->if_delegated.type == IFT_CELLULAR ||                    \
    (((_ifp)->if_family == IFNET_FAMILY_ETHERNET  &&                \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_SIMCELL)) ||            \
    ((_ifp)->if_delegated.family == IFNET_FAMILY_ETHERNET &&        \
    (_ifp)->if_delegated.subfamily == IFNET_SUBFAMILY_SIMCELL))

/*
 * Indicate whether or not the immediate interface, or the interface delegated
 * by it, is an ETHERNET interface.
 */
#define IFNET_IS_ETHERNET(_ifp)                                         \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET ||                  \
    (_ifp)->if_delegated.family == IFNET_FAMILY_ETHERNET)
/*
 * Indicate whether or not the immediate interface, or the interface delegated
 * by it, is a Wi-Fi interface (IFNET_SUBFAMILY_WIFI).  Delegated interface
 * subfamily is set/cleared along with the delegated ifp; we cache the subfamily
 * for performance to avoid dereferencing delegated ifp each time.
 *
 * Note that this is meant to be used only for accounting and policy purposes;
 * certain places need to explicitly know the immediate interface type, and
 * this macro should not be used there.
 *
 * The test is done against IFNET_SUBFAMILY_WIFI as the family may be set to
 * IFNET_FAMILY_ETHERNET (as well as type to IFT_ETHER) which is too generic.
 */
#define IFNET_IS_WIFI(_ifp)                                             \
    (((_ifp)->if_family == IFNET_FAMILY_ETHERNET  &&                \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_WIFI) ||                \
    ((_ifp)->if_delegated.family == IFNET_FAMILY_ETHERNET &&        \
    (_ifp)->if_delegated.subfamily == IFNET_SUBFAMILY_WIFI))

/*
 * Indicate whether or not the immediate interface, or the interface delegated
 * by it, is a Wired interface (several families).  Delegated interface
 * family is set/cleared along with the delegated ifp; we cache the family
 * for performance to avoid dereferencing delegated ifp each time.
 *
 * Note that this is meant to be used only for accounting and policy purposes;
 * certain places need to explicitly know the immediate interface type, and
 * this macro should not be used there.
 */
#define IFNET_IS_WIRED(_ifp)                                            \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET ||                  \
    (_ifp)->if_delegated.family == IFNET_FAMILY_ETHERNET ||         \
    (_ifp)->if_family == IFNET_FAMILY_FIREWIRE ||                   \
    (_ifp)->if_delegated.family == IFNET_FAMILY_FIREWIRE)

/*
 * Indicate whether or not the immediate WiFi interface is on an infrastructure
 * network
 */
#define IFNET_IS_WIFI_INFRA(_ifp)                               \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET &&          \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_WIFI &&         \
    !((_ifp)->if_eflags & IFEF_AWDL) &&                     \
    !((_ifp)->if_xflags & IFXF_LOW_LATENCY))

/*
 * Indicate whether or not the immediate interface is a companion link
 * interface.
 */
#define IFNET_IS_COMPANION_LINK(_ifp)                           \
    ((_ifp)->if_family == IFNET_FAMILY_IPSEC &&             \
    ((_ifp)->if_subfamily == IFNET_SUBFAMILY_BLUETOOTH ||   \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_WIFI ||         \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_QUICKRELAY ||   \
    (_ifp)->if_subfamily == IFNET_SUBFAMILY_DEFAULT))

/*
 * Indicate whether or not the immediate interface, or the interface delegated
 * by it, is marked as expensive.  The delegated interface is set/cleared
 * along with the delegated ifp; we cache the flag for performance to avoid
 * dereferencing delegated ifp each time.
 *
 * Note that this is meant to be used only for policy purposes.
 */
#define IFNET_IS_EXPENSIVE(_ifp)                                        \
    ((_ifp)->if_eflags & IFEF_EXPENSIVE ||                              \
    (_ifp)->if_delegated.expensive)

#define IFNET_IS_LOW_POWER(_ifp)                                        \
    (if_low_power_restricted != 0 &&                                \
    ((_ifp)->if_xflags & IFXF_LOW_POWER) ||                         \
    ((_ifp)->if_delegated.ifp != NULL &&                            \
    ((_ifp)->if_delegated.ifp->if_xflags & IFXF_LOW_POWER)))

#define IFNET_IS_CONSTRAINED(_ifp)                                      \
    ((_ifp)->if_xflags & IFXF_CONSTRAINED ||                            \
    (_ifp)->if_delegated.constrained)

/*
 * We don't support AWDL interface delegation.
 */
#define IFNET_IS_AWDL_RESTRICTED(_ifp)                                  \
    (((_ifp)->if_eflags & (IFEF_AWDL|IFEF_AWDL_RESTRICTED)) ==      \
    (IFEF_AWDL|IFEF_AWDL_RESTRICTED))

#define IFNET_IS_INTCOPROC(_ifp)                                        \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET &&                  \
     (_ifp)->if_subfamily == IFNET_SUBFAMILY_INTCOPROC)

#define IFNET_IS_VMNET(_ifp)                                            \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET &&                  \
     (_ifp)->if_subfamily == IFNET_SUBFAMILY_VMNET)

#define IFNET_IS_MANAGEMENT(_ifp)                                        \
     (((_ifp)->if_xflags & IFXF_MANAGEMENT) != 0)

/*
 * Indicate whether or not the immediate interface is IP over Thunderbolt.
 */
#define IFNET_IS_THUNDERBOLT_IP(_ifp)                                \
    ((_ifp)->if_family == IFNET_FAMILY_ETHERNET &&               \
     (_ifp)->if_subfamily == IFNET_SUBFAMILY_THUNDERBOLT)

extern int if_index;
extern struct ifnethead ifnet_head;
extern struct ifnethead ifnet_ordered_head;
extern struct ifnet **__counted_by(if_index) ifindex2ifnet;
extern u_int32_t if_sndq_maxlen;
extern u_int32_t if_rcvq_maxlen;
extern struct ifaddr **ifnet_addrs;
extern lck_attr_t ifa_mtx_attr;
extern lck_grp_t ifa_mtx_grp;
extern lck_grp_t ifnet_lock_group;
extern lck_attr_t ifnet_lock_attr;
extern ifnet_t lo_ifp;
extern uint32_t net_wake_pkt_debug;

extern int if_addmulti(struct ifnet *, const struct sockaddr *,
    struct ifmultiaddr **);
extern int if_addmulti_anon(struct ifnet *, const struct sockaddr *,
    struct ifmultiaddr **);
extern int if_allmulti(struct ifnet *, int);
extern int if_delmulti(struct ifnet *, const struct sockaddr *);
extern int if_delmulti_ifma(struct ifmultiaddr *);
extern int if_delmulti_anon(struct ifnet *, const struct sockaddr *);
extern void if_down(struct ifnet *);
extern int if_down_all(void);
extern void if_up(struct ifnet *);
__private_extern__ void if_updown(struct ifnet *ifp, int up);
extern int ifioctl(struct socket *, u_long, caddr_t, struct proc *);
extern int ifioctllocked(struct socket *, u_long, caddr_t, struct proc *);
extern struct ifnet *ifunit(const char *);
extern struct ifnet *ifunit_ref(const char *);
extern int ifunit_extract(const char *src, char *dst, size_t dstlen, int *unit);
extern struct ifnet *if_withname(struct sockaddr *);
extern void if_qflush(struct ifnet *, struct ifclassq *, bool);
extern void if_qflush_snd(struct ifnet *, bool);
extern void if_qflush_sc(struct ifnet *, mbuf_svc_class_t, u_int32_t,
    u_int32_t *, u_int32_t *, int);

extern struct if_clone *if_clone_lookup(const char *, u_int32_t *);
extern int if_clone_attach(struct if_clone *);
extern void if_clone_detach(struct if_clone *);
extern u_int32_t if_functional_type(struct ifnet *, bool);

extern errno_t if_mcasts_update(struct ifnet *);

typedef enum {
	IFNET_LCK_ASSERT_EXCLUSIVE,     /* RW: held as writer */
	IFNET_LCK_ASSERT_SHARED,        /* RW: held as reader */
	IFNET_LCK_ASSERT_OWNED,         /* RW: writer/reader, MTX: held */
	IFNET_LCK_ASSERT_NOTOWNED       /* not held */
} ifnet_lock_assert_t;

#define IF_LLADDR(_ifp) \
    (LLADDR(SDL(((_ifp)->if_lladdr)->ifa_addr)))

#define IF_INDEX_IN_RANGE(_ind_) ((_ind_) > 0 && \
    (unsigned int)(_ind_) <= (unsigned int)if_index)

__private_extern__ void ifnet_lock_assert(struct ifnet *, ifnet_lock_assert_t);
__private_extern__ void ifnet_lock_shared(struct ifnet *ifp);
__private_extern__ void ifnet_lock_exclusive(struct ifnet *ifp);
__private_extern__ void ifnet_lock_done(struct ifnet *ifp);

#if INET
__private_extern__ void if_inetdata_lock_shared(struct ifnet *ifp);
__private_extern__ void if_inetdata_lock_exclusive(struct ifnet *ifp);
__private_extern__ void if_inetdata_lock_done(struct ifnet *ifp);
#endif

__private_extern__ void if_inet6data_lock_shared(struct ifnet *ifp);
__private_extern__ void if_inet6data_lock_exclusive(struct ifnet *ifp);
__private_extern__ void if_inet6data_lock_done(struct ifnet *ifp);

__private_extern__ void ifnet_head_lock_shared(void);
__private_extern__ void ifnet_head_lock_exclusive(void);
__private_extern__ void ifnet_head_done(void);
__private_extern__ void ifnet_head_assert_exclusive(void);

__private_extern__ errno_t ifnet_set_idle_flags_locked(ifnet_t, u_int32_t,
    u_int32_t);
__private_extern__ int ifnet_is_attached(struct ifnet *, int refio);
__private_extern__ void ifnet_incr_pending_thread_count(struct ifnet *);
__private_extern__ void ifnet_decr_pending_thread_count(struct ifnet *);
__private_extern__ void ifnet_incr_iorefcnt(struct ifnet *);
__private_extern__ void ifnet_decr_iorefcnt(struct ifnet *);
__private_extern__ boolean_t ifnet_datamov_begin(struct ifnet *);
__private_extern__ void ifnet_datamov_end(struct ifnet *);
__private_extern__ void ifnet_datamov_suspend(struct ifnet *);
__private_extern__ boolean_t ifnet_datamov_suspend_if_needed(struct ifnet *);
__private_extern__ void ifnet_datamov_drain(struct ifnet *);
__private_extern__ void ifnet_datamov_suspend_and_drain(struct ifnet *);
__private_extern__ void ifnet_datamov_resume(struct ifnet *);
__private_extern__ void ifnet_set_start_cycle(struct ifnet *,
    struct timespec *);
__private_extern__ void ifnet_set_poll_cycle(struct ifnet *,
    struct timespec *);

__private_extern__ void if_attach_ifa(struct ifnet *, struct ifaddr *);
__private_extern__ void if_attach_link_ifa(struct ifnet *, struct ifaddr *);
__private_extern__ void if_detach_ifa(struct ifnet *, struct ifaddr *);
__private_extern__ void if_detach_link_ifa(struct ifnet *, struct ifaddr *);

__private_extern__ void dlil_if_lock(void);
__private_extern__ void dlil_if_unlock(void);
__private_extern__ void dlil_if_lock_assert(void);

extern struct ifaddr *ifa_ifwithaddr(const struct sockaddr *);
extern struct ifaddr *ifa_ifwithaddr_locked(const struct sockaddr *);
extern struct ifaddr *ifa_ifwithaddr_scoped(const struct sockaddr *,
    unsigned int);
extern struct ifaddr *ifa_ifwithaddr_scoped_locked(const struct sockaddr *,
    unsigned int);
extern struct ifaddr *ifa_ifwithdstaddr(const struct sockaddr *);
extern struct ifaddr *ifa_ifwithnet(const struct sockaddr *);
extern struct ifaddr *ifa_ifwithnet_scoped(const struct sockaddr *,
    unsigned int);
extern struct ifaddr *ifa_ifwithroute(int, const struct sockaddr *,
    const struct sockaddr *);
extern struct   ifaddr *ifa_ifwithroute_locked(int, const struct sockaddr *,
    const struct sockaddr *);
extern struct ifaddr *ifa_ifwithroute_scoped_locked(int,
    const struct sockaddr *, const struct sockaddr *, unsigned int);
extern struct ifaddr *ifaof_ifpforaddr_select(const struct sockaddr *, struct ifnet *);
extern struct ifaddr *ifaof_ifpforaddr(const struct sockaddr *, struct ifnet *);
__private_extern__ struct ifaddr *ifa_ifpgetprimary(struct ifnet *, int);
extern void ifa_addref(struct ifaddr *, int);
extern struct ifaddr *ifa_remref(struct ifaddr *, int);
extern void ifa_lock_init(struct ifaddr *);
extern void ifa_lock_destroy(struct ifaddr *);
extern void ifma_addref(struct ifmultiaddr *, int);
extern void ifma_remref(struct ifmultiaddr *);

extern void ifa_init(void);

__private_extern__ struct in_ifaddr *ifa_foraddr(unsigned int);
__private_extern__ struct in_ifaddr *ifa_foraddr_scoped(unsigned int,
    unsigned int);

struct ifreq;
extern errno_t ifnet_getset_opportunistic(struct ifnet *, u_long,
    struct ifreq *, struct proc *);
extern int ifnet_get_throttle(struct ifnet *, u_int32_t *);
extern int ifnet_set_throttle(struct ifnet *, u_int32_t);
extern errno_t ifnet_getset_log(struct ifnet *, u_long,
    struct ifreq *, struct proc *);
extern int ifnet_set_log(struct ifnet *, int32_t, uint32_t, int32_t, int32_t);
extern int ifnet_get_log(struct ifnet *, int32_t *, uint32_t *, int32_t *,
    int32_t *);
extern int ifnet_notify_address(struct ifnet *, int);
extern void ifnet_notify_data_threshold(struct ifnet *);

#define IF_AFDATA_RLOCK         if_afdata_rlock
#define IF_AFDATA_RUNLOCK       if_afdata_unlock
#define IF_AFDATA_WLOCK         if_afdata_wlock
#define IF_AFDATA_WUNLOCK       if_afdata_unlock
#define IF_AFDATA_WLOCK_ASSERT  if_afdata_wlock_assert
#define IF_AFDATA_LOCK_ASSERT   if_afdata_lock_assert
#define IF_AFDATA_UNLOCK_ASSERT if_afdata_unlock_assert

static inline void
if_afdata_rlock(struct ifnet *ifp, int af)
{
	switch (af) {
#if INET
	case AF_INET:
		lck_rw_lock_shared(&ifp->if_inetdata_lock);
		break;
#endif
	case AF_INET6:
		lck_rw_lock_shared(&ifp->if_inet6data_lock);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_runlock(struct ifnet *ifp, int af)
{
	switch (af) {
#if INET
	case AF_INET:
		lck_rw_done(&ifp->if_inetdata_lock);
		break;
#endif
	case AF_INET6:
		lck_rw_done(&ifp->if_inet6data_lock);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_wlock(struct ifnet *ifp, int af)
{
	switch (af) {
#if INET
	case AF_INET:
		lck_rw_lock_exclusive(&ifp->if_inetdata_lock);
		break;
#endif
	case AF_INET6:
		lck_rw_lock_exclusive(&ifp->if_inet6data_lock);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_unlock(struct ifnet *ifp, int af)
{
	switch (af) {
#if INET
	case AF_INET:
		lck_rw_done(&ifp->if_inetdata_lock);
		break;
#endif
	case AF_INET6:
		lck_rw_done(&ifp->if_inet6data_lock);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_wlock_assert(struct ifnet *ifp, int af)
{
#if !MACH_ASSERT
#pragma unused(ifp)
#endif
	switch (af) {
#if INET
	case AF_INET:
		LCK_RW_ASSERT(&ifp->if_inetdata_lock, LCK_RW_ASSERT_EXCLUSIVE);
		break;
#endif
	case AF_INET6:
		LCK_RW_ASSERT(&ifp->if_inet6data_lock, LCK_RW_ASSERT_EXCLUSIVE);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_unlock_assert(struct ifnet *ifp, int af)
{
#if !MACH_ASSERT
#pragma unused(ifp)
#endif
	switch (af) {
#if INET
	case AF_INET:
		LCK_RW_ASSERT(&ifp->if_inetdata_lock, LCK_RW_ASSERT_NOTHELD);
		break;
#endif
	case AF_INET6:
		LCK_RW_ASSERT(&ifp->if_inet6data_lock, LCK_RW_ASSERT_NOTHELD);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

static inline void
if_afdata_lock_assert(struct ifnet *ifp, int af)
{
#if !MACH_ASSERT
#pragma unused(ifp)
#endif
	switch (af) {
#if INET
	case AF_INET:
		LCK_RW_ASSERT(&ifp->if_inetdata_lock, LCK_RW_ASSERT_HELD);
		break;
#endif
	case AF_INET6:
		LCK_RW_ASSERT(&ifp->if_inet6data_lock, LCK_RW_ASSERT_HELD);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	return;
}

struct in6_addr;
__private_extern__ struct in6_ifaddr *ifa_foraddr6(struct in6_addr *);
__private_extern__ struct in6_ifaddr *ifa_foraddr6_scoped(struct in6_addr *,
    unsigned int);

__private_extern__ void if_data_internal_to_if_data(struct ifnet *ifp,
    const struct if_data_internal *if_data_int, struct if_data *if_data);
__private_extern__ void if_data_internal_to_if_data64(struct ifnet *ifp,
    const struct if_data_internal *if_data_int, struct if_data64 *if_data64);
__private_extern__ void if_copy_traffic_class(struct ifnet *ifp,
    struct if_traffic_class *if_tc);
__private_extern__ void if_copy_data_extended(struct ifnet *ifp,
    struct if_data_extended *if_de);
__private_extern__ void if_copy_packet_stats(struct ifnet *ifp,
    struct if_packet_stats *if_ps);
__private_extern__ void if_copy_rxpoll_stats(struct ifnet *ifp,
    struct if_rxpoll_stats *if_rs);
__private_extern__ void if_copy_netif_stats(struct ifnet *ifp,
    struct if_netif_stats *if_ns);

__private_extern__ struct rtentry *ifnet_cached_rtlookup_inet(struct ifnet *,
    struct in_addr);
__private_extern__ struct rtentry *ifnet_cached_rtlookup_inet6(struct ifnet *,
    struct in6_addr *);

__private_extern__ u_int32_t if_get_protolist(struct ifnet * ifp,
    u_int32_t *protolist, u_int32_t count);
__private_extern__ void if_free_protolist(u_int32_t *list);
__private_extern__ errno_t if_state_update(struct ifnet *,
    struct if_interface_state *);
__private_extern__ void if_get_state(struct ifnet *,
    struct if_interface_state *);
__private_extern__ errno_t if_probe_connectivity(struct ifnet *ifp,
    u_int32_t conn_probe);
__private_extern__ void if_lqm_update(struct ifnet *, int32_t, int);
__private_extern__ void ifnet_update_sndq(struct ifclassq *, cqev_t);
__private_extern__ void ifnet_update_rcv(struct ifnet *, cqev_t);

__private_extern__ void ifnet_flowadv(uint32_t);

__private_extern__ errno_t ifnet_set_input_bandwidths(struct ifnet *,
    struct if_bandwidths *);
__private_extern__ errno_t ifnet_set_output_bandwidths(struct ifnet *,
    struct if_bandwidths *, boolean_t);
__private_extern__ u_int64_t ifnet_output_linkrate(struct ifnet *);
__private_extern__ u_int64_t ifnet_input_linkrate(struct ifnet *);

__private_extern__ errno_t ifnet_set_input_latencies(struct ifnet *,
    struct if_latencies *);
__private_extern__ errno_t ifnet_set_output_latencies(struct ifnet *,
    struct if_latencies *, boolean_t);

__private_extern__ void ifnet_clear_netagent(uuid_t);

__private_extern__ int ifnet_set_netsignature(struct ifnet *, uint8_t,
    uint8_t, uint16_t, uint8_t *);
__private_extern__ int ifnet_get_netsignature(struct ifnet *, uint8_t,
    uint8_t *, uint16_t *, uint8_t *);

struct ipv6_prefix;
__private_extern__ int ifnet_set_nat64prefix(struct ifnet *,
    struct ipv6_prefix *);
__private_extern__ int ifnet_get_nat64prefix(struct ifnet *,
    struct ipv6_prefix *);

/* Required exclusive ifnet_head lock */
__private_extern__ void ifnet_remove_from_ordered_list(struct ifnet *);

__private_extern__ void ifnet_increment_generation(struct ifnet *);
__private_extern__ u_int32_t ifnet_get_generation(struct ifnet *);

/* Adding and deleting netagents will take ifnet lock */
__private_extern__ int if_add_netagent(struct ifnet *, uuid_t);
__private_extern__ int if_add_netagent_locked(struct ifnet *, uuid_t);
__private_extern__ int if_delete_netagent(struct ifnet *, uuid_t);
__private_extern__ boolean_t if_check_netagent(struct ifnet *, uuid_t);

#if SKYWALK
extern unsigned int if_enable_fsw_ip_netagent;
static inline boolean_t
if_is_fsw_ip_netagent_enabled(void)
{
	return if_enable_fsw_ip_netagent != 0;
}
extern unsigned int if_enable_fsw_transport_netagent;
static inline boolean_t
if_is_fsw_transport_netagent_enabled(void)
{
	return if_enable_fsw_transport_netagent != 0;
}
static inline boolean_t
if_is_fsw_netagent_enabled(void)
{
	return if_is_fsw_transport_netagent_enabled() ||
	       if_is_fsw_ip_netagent_enabled();
}
#endif /* SKYWALK */

extern int if_set_qosmarking_mode(struct ifnet *, u_int32_t);
__private_extern__ uint32_t ifnet_mbuf_packetpreamblelen(struct ifnet *);
__private_extern__ void intf_event_enqueue_nwk_wq_entry(struct ifnet *ifp,
    struct sockaddr *addrp, uint32_t intf_event_code);
__private_extern__ void ifnet_update_stats_per_flow(struct ifnet_stats_per_flow *,
    struct ifnet *);
__private_extern__ int if_get_tcp_kao_max(struct ifnet *);
#if XNU_TARGET_OS_OSX
__private_extern__ errno_t ifnet_framer_stub(struct ifnet *, struct mbuf **,
    const struct sockaddr *, const char *, const char *, u_int32_t *,
    u_int32_t *);
#endif /* XNU_TARGET_OS_OSX */
__private_extern__ void ifnet_enqueue_multi_setup(struct ifnet *, uint16_t,
    uint16_t);
__private_extern__ errno_t ifnet_enqueue_mbuf(struct ifnet *, struct mbuf *,
    boolean_t, boolean_t *);
__private_extern__ errno_t ifnet_enqueue_mbuf_chain(struct ifnet *,
    struct mbuf *, struct mbuf *, uint32_t, uint32_t, boolean_t, boolean_t *);
__private_extern__ int ifnet_enqueue_netem(void *handle, pktsched_pkt_t *pkts,
    uint32_t n_pkts);
#if SKYWALK
struct __kern_packet;
extern errno_t ifnet_enqueue_pkt(struct ifnet *,
    struct __kern_packet *, boolean_t, boolean_t *);
extern errno_t ifnet_enqueue_ifcq_pkt(struct ifnet *, struct ifclassq *,
    struct __kern_packet *, boolean_t, boolean_t *);
extern errno_t ifnet_enqueue_pkt_chain(struct ifnet *, struct __kern_packet *,
    struct __kern_packet *, uint32_t, uint32_t, boolean_t, boolean_t *);
extern errno_t ifnet_enqueue_ifcq_pkt_chain(struct ifnet *, struct ifclassq *,
    struct __kern_packet *, struct __kern_packet *, uint32_t, uint32_t, boolean_t,
    boolean_t *);
extern errno_t ifnet_set_output_handler(struct ifnet *, ifnet_output_func);
extern void ifnet_reset_output_handler(struct ifnet *);
extern errno_t ifnet_set_start_handler(struct ifnet *, ifnet_start_func);
extern void ifnet_reset_start_handler(struct ifnet *);

#define SK_NXS_MS_IF_ADDR_GENCNT_INC(ifp)        \
    atomic_add_32(&(ifp)->if_nx_flowswitch.if_fsw_ipaddr_gencnt, 1);
#endif /* SKYWALK */

extern int if_low_power_verbose;
extern int if_low_power_restricted;
extern void if_low_power_evhdlr_init(void);
extern int if_set_low_power(struct ifnet *, bool);
extern u_int32_t if_set_eflags(ifnet_t, u_int32_t);
extern void if_clear_eflags(ifnet_t, u_int32_t);
extern u_int32_t if_set_xflags(ifnet_t, u_int32_t);
extern void if_clear_xflags(ifnet_t, u_int32_t);
extern boolean_t sa_equal(const struct sockaddr *, const struct sockaddr *);
extern void ifnet_update_traffic_rule_genid(struct ifnet *);
extern boolean_t ifnet_sync_traffic_rule_genid(struct ifnet *, uint32_t *);
extern void ifnet_update_traffic_rule_count(struct ifnet *, uint32_t);

#endif /* BSD_KERNEL_PRIVATE */
#endif /* DRIVERKIT */

#endif /* !_NET_IF_VAR_PRIVATE_H_ */
