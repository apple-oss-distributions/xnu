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
 * Copyright (c) 1982, 1986, 1993
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
 *    @(#)tcp.h    8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/netinet/tcp.h,v 1.13.2.3 2001/03/01 22:08:42 jlemon Exp $
 */

#ifndef _NETINET_TCP_PRIVATE_H_
#define _NETINET_TCP_PRIVATE_H_

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)

#define TCP_INFO                        0x200   /* retrieve tcp_info structure */
#define TCP_MEASURE_SND_BW              0x202   /* Measure sender's bandwidth for this connection */

#define TCP_MEASURE_BW_BURST    0x203   /* Burst size to use for bandwidth measurement */
#define TCP_PEER_PID            0x204   /* Lookup pid of the process we're connected to */
#define TCP_ADAPTIVE_READ_TIMEOUT       0x205   /* Read timeout used as a multiple of RTT */
#define TCP_OPTION_UNUSED_0             0x206   /* UNUSED */
#define TCP_ADAPTIVE_WRITE_TIMEOUT      0x207   /* Write timeout used as a multiple of RTT */
#define TCP_NOTIMEWAIT                  0x208   /* Avoid going into time-wait */
#define TCP_DISABLE_BLACKHOLE_DETECTION 0x209   /* disable PMTU blackhole detection */
#define TCP_ECN_MODE                    0x210   /* fine grain control for A/B testing */
#define TCP_KEEPALIVE_OFFLOAD           0x211   /* offload keep alive processing to firmware */

/*
 * TCP_ECN_MODE values
 */
#define ECN_MODE_DEFAULT                0x0     /* per interface or system wide default */
#define ECN_MODE_ENABLE                 0x1     /* force enable ECN on connection */
#define ECN_MODE_DISABLE                0x2     /* force disable ECN on connection */

/*
 * TCP_NOTIFY_ACKNOWLEDGEMENT
 *
 * Application can use this socket option to get a notification when
 * data that is currently written to the socket is acknowledged. The input
 * argument given to this socket option is a marker_id that will be used for
 * returning the notification. The application can continue to write
 * data after setting the marker. There can be multiple of these events
 * outstanding on a socket at any time up to a max of TCP_MAX_NOTIFY_ACK.
 *
 * To get the completed notifications, getsockopt should be called with the
 * TCP_NOTIFY_ACKNOWLEDGEMENT with the following tcp_notify_ack_complete
 * structure as an out argument. At most TCP_MAX_NOTIFY_ACK ids will be
 * returned if they have been successfully acknowledged in each call.
 */

#define TCP_MAX_NOTIFY_ACK      10

typedef u_int32_t       tcp_notify_ack_id_t;

struct tcp_notify_ack_complete {
	u_int32_t       notify_pending;/* still pending */
	u_int32_t       notify_complete_count;
	tcp_notify_ack_id_t notify_complete_id[TCP_MAX_NOTIFY_ACK];
};

#define TCP_NOTIFY_ACKNOWLEDGEMENT      0x212   /* Notify when data is acknowledged */
#define MPTCP_SERVICE_TYPE              0x213   /* MPTCP Service type */
#define TCP_FASTOPEN_FORCE_HEURISTICS   0x214   /* Make sure TFO-heuristics never get disabled */

#define MPTCP_SVCTYPE_HANDOVER          0 /* Default 0 */
#define MPTCP_SVCTYPE_INTERACTIVE       1
#define MPTCP_SVCTYPE_AGGREGATE         2
#define MPTCP_SVCTYPE_TARGET_BASED      3
#define MPTCP_SVCTYPE_PURE_HANDOVER     4
#define MPTCP_SVCTYPE_MAX               5

/*
 * Specify minimum time in seconds before which an established
 * TCP connection will not be dropped when there is no response from the
 * peer
 */
#define TCP_RXT_MINIMUM_TIMEOUT         0x215

#define TCP_RXT_MINIMUM_TIMEOUT_LIMIT   (5 * 60) /* Limit is 5 minutes */

#define MPTCP_ALTERNATE_PORT            0x216
#define MPTCP_FORCE_ENABLE              0x217
#define TCP_FASTOPEN_FORCE_ENABLE       0x218
#define MPTCP_EXPECTED_PROGRESS_TARGET  0x219
#define MPTCP_FORCE_VERSION             0x21a
#define TCP_ENABLE_L4S                  0x21b   /* Enable or disable L4S */

/* When adding new socket-options, you need to make sure MPTCP supports these as well! */

/*
 * The TCP_INFO socket option is a private API and is subject to change
 */
#pragma pack(4)

#define TCPI_OPT_TIMESTAMPS     0x01
#define TCPI_OPT_SACK           0x02
#define TCPI_OPT_WSCALE         0x04
#define TCPI_OPT_ECN            0x08

#define TCPI_FLAG_LOSSRECOVERY  0x01    /* Currently in loss recovery */
#define TCPI_FLAG_STREAMING_ON  0x02    /* Streaming detection on */

struct tcp_conn_status {
	union {
		struct {
			unsigned int    probe_activated : 1;
			unsigned int    write_probe_failed : 1;
			unsigned int    read_probe_failed : 1;
			unsigned int    conn_probe_failed : 1;
		};
		uint32_t        pad_field;
	};
};

#define TCPINFO_HAS_L4S_ 1
typedef enum {
	tcp_connection_client_accurate_ecn_invalid                                    = 0,
	tcp_connection_client_accurate_ecn_feature_disabled                           = 1,
	tcp_connection_client_accurate_ecn_feature_enabled                            = 2,
	tcp_connection_client_classic_ecn_available                                   = 3,
	tcp_connection_client_ecn_not_available                                       = 4,
	tcp_connection_client_accurate_ecn_negotiation_blackholed                     = 5,
	tcp_connection_client_accurate_ecn_ace_bleaching_detected                     = 6,
	tcp_connection_client_accurate_ecn_negotiation_success                        = 7,
	tcp_connection_client_accurate_ecn_negotiation_success_ect_mangling_detected  = 8,
	tcp_connection_client_accurate_ecn_negotiation_success_ect_bleaching_detected = 9,
} tcp_connection_client_accurate_ecn_state_t;

typedef enum {
	tcp_connection_server_accurate_ecn_invalid                                    = 0,
	tcp_connection_server_accurate_ecn_feature_disabled                           = 1,
	tcp_connection_server_accurate_ecn_feature_enabled                            = 2,
	tcp_connection_server_no_ecn_requested                                        = 3,
	tcp_connection_server_classic_ecn_requested                                   = 4,
	tcp_connection_server_accurate_ecn_requested                                  = 5,
	tcp_connection_server_accurate_ecn_negotiation_blackholed                     = 6,
	tcp_connection_server_accurate_ecn_ace_bleaching_detected                     = 7,
	tcp_connection_server_accurate_ecn_negotiation_success                        = 8,
	tcp_connection_server_accurate_ecn_negotiation_success_ect_mangling_detected  = 9,
	tcp_connection_server_accurate_ecn_negotiation_success_ect_bleaching_detected = 10,
} tcp_connection_server_accurate_ecn_state_t;

/*
 * Add new fields to this structure at the end only. This will preserve
 * binary compatibility.
 */
struct tcp_info {
	u_int8_t        tcpi_state;                 /* TCP FSM state. */
	u_int8_t        tcpi_options;       /* Options enabled on conn. */
	u_int8_t        tcpi_snd_wscale;    /* RFC1323 send shift value. */
	u_int8_t        tcpi_rcv_wscale;    /* RFC1323 recv shift value. */

	u_int32_t       tcpi_flags;                 /* extra flags (TCPI_FLAG_xxx) */

	u_int32_t       tcpi_rto;                   /* Retransmission timeout in milliseconds */
	u_int32_t       tcpi_snd_mss;       /* Max segment size for send. */
	u_int32_t       tcpi_rcv_mss;       /* Max segment size for receive. */

	u_int32_t       tcpi_rttcur;        /* Most recent value of RTT */
	u_int32_t       tcpi_srtt;          /* Sender's Smoothed RTT */
	u_int32_t       tcpi_rttvar;        /* RTT variance */
	u_int32_t       tcpi_rttbest;       /* Best RTT we've seen */

	u_int32_t       tcpi_snd_ssthresh;  /* Slow start threshold. */
	u_int32_t       tcpi_snd_cwnd;      /* Send congestion window. */

	u_int32_t       tcpi_rcv_space;     /* Advertised recv window. */

	u_int32_t       tcpi_snd_wnd;       /* Advertised send window. */
	u_int32_t       tcpi_snd_nxt;       /* Next egress seqno */
	u_int32_t       tcpi_rcv_nxt;       /* Next ingress seqno */

	int32_t         tcpi_last_outif;    /* if_index of interface used to send last */
	u_int32_t       tcpi_snd_sbbytes;   /* bytes in snd buffer including data inflight */

	u_int64_t       tcpi_txpackets __attribute__((aligned(8))); /* total packets sent */
	u_int64_t       tcpi_txbytes __attribute__((aligned(8)));
	/* total bytes sent */
	u_int64_t       tcpi_txretransmitbytes __attribute__((aligned(8)));
	/* total bytes retransmitted */
	u_int64_t       tcpi_txunacked __attribute__((aligned(8)));
	/* current number of bytes not acknowledged */
	u_int64_t       tcpi_rxpackets __attribute__((aligned(8))); /* total packets received */
	u_int64_t       tcpi_rxbytes __attribute__((aligned(8)));
	/* total bytes received */
	u_int64_t       tcpi_rxduplicatebytes __attribute__((aligned(8)));
	/* total duplicate bytes received */
	u_int64_t       tcpi_rxoutoforderbytes __attribute__((aligned(8)));
	/* total out of order bytes received */
	u_int64_t       tcpi_snd_bw __attribute__((aligned(8)));    /* measured send bandwidth in bits/sec */
	u_int8_t        tcpi_synrexmits;    /* Number of syn retransmits before connect */
	u_int8_t        tcpi_unused1;
	u_int16_t       tcpi_unused2;
	u_int64_t       tcpi_cell_rxpackets __attribute((aligned(8)));/* packets received over cellular */
	u_int64_t       tcpi_cell_rxbytes __attribute((aligned(8)));/* bytes received over cellular */
	u_int64_t       tcpi_cell_txpackets __attribute((aligned(8)));/* packets transmitted over cellular */
	u_int64_t       tcpi_cell_txbytes __attribute((aligned(8)));/* bytes transmitted over cellular */
	u_int64_t       tcpi_wifi_rxpackets __attribute((aligned(8)));/* packets received over Wi-Fi */
	u_int64_t       tcpi_wifi_rxbytes __attribute((aligned(8)));/* bytes received over Wi-Fi */
	u_int64_t       tcpi_wifi_txpackets __attribute((aligned(8)));/* packets transmitted over Wi-Fi */
	u_int64_t       tcpi_wifi_txbytes __attribute((aligned(8)));/* bytes transmitted over Wi-Fi */
	u_int64_t       tcpi_wired_rxpackets __attribute((aligned(8)));/* packets received over Wired */
	u_int64_t       tcpi_wired_rxbytes __attribute((aligned(8)));/* bytes received over Wired */
	u_int64_t       tcpi_wired_txpackets __attribute((aligned(8)));/* packets transmitted over Wired */
	u_int64_t       tcpi_wired_txbytes __attribute((aligned(8)));/* bytes transmitted over Wired */
	struct tcp_conn_status  tcpi_connstatus;/* status of connection probes */

	u_int16_t
	    tcpi_tfo_cookie_req:1, /* Cookie requested? */
	    tcpi_tfo_cookie_rcv:1, /* Cookie received? */
	    tcpi_tfo_syn_loss:1,   /* Fallback to reg. TCP after SYN-loss */
	    tcpi_tfo_syn_data_sent:1, /* SYN+data has been sent out */
	    tcpi_tfo_syn_data_acked:1, /* SYN+data has been fully acknowledged */
	    tcpi_tfo_syn_data_rcv:1, /* Server received SYN+data with a valid cookie */
	    tcpi_tfo_cookie_req_rcv:1, /* Server received cookie-request */
	    tcpi_tfo_cookie_sent:1, /* Server announced cookie */
	    tcpi_tfo_cookie_invalid:1, /* Server received an invalid cookie */
	    tcpi_tfo_cookie_wrong:1, /* Our sent cookie was wrong */
	    tcpi_tfo_no_cookie_rcv:1, /* We did not receive a cookie upon our request */
	    tcpi_tfo_heuristics_disable:1, /* TFO-heuristics disabled it */
	    tcpi_tfo_send_blackhole:1, /* A sending-blackhole got detected */
	    tcpi_tfo_recv_blackhole:1, /* A receiver-blackhole got detected */
	    tcpi_tfo_onebyte_proxy:1; /* A proxy acknowledges all but one byte of the SYN */

#define TCPINFO_HAS_L4S_STATE 1
	u_int16_t       tcpi_ecn_client_setup:1,    /* Attempted ECN setup from client side */
	    tcpi_ecn_server_setup:1,                /* Attempted ECN setup from server side */
	    tcpi_ecn_success:1,                     /* peer negotiated ECN */
	    tcpi_ecn_lost_syn:1,                    /* Lost SYN with ECN setup */
	    tcpi_ecn_lost_synack:1,                 /* Lost SYN-ACK with ECN setup */
	    tcpi_local_peer:1,                      /* Local to the host or the subnet */
	    tcpi_if_cell:1,                 /* Interface is cellular */
	    tcpi_if_wifi:1,                 /* Interface is WiFi */
	    tcpi_if_wired:1,                /* Interface is wired - ethernet , thunderbolt etc,. */
	    tcpi_if_wifi_infra:1,           /* Interface is wifi infrastructure */
	    tcpi_if_wifi_awdl:1,            /* Interface is wifi AWDL */
	    tcpi_snd_background:1,          /* Using delay based algorithm on sender side */
	    tcpi_rcv_background:1,          /* Using delay based algorithm on receive side */
	    tcpi_l4s_enabled:1;             /* Whether L4S is enabled or not */

	u_int32_t       tcpi_ecn_recv_ce;   /* Packets received with CE */
	u_int32_t       tcpi_ecn_recv_cwr;  /* Packets received with CWR */

	u_int32_t       tcpi_rcvoopack;     /* out-of-order packets received */
	u_int32_t       tcpi_pawsdrop;      /* segments dropped due to PAWS */
	u_int32_t       tcpi_sack_recovery_episode;/* SACK recovery episodes */
	u_int32_t       tcpi_reordered_pkts;/* packets reorderd */
	u_int32_t       tcpi_dsack_sent;    /* Sent DSACK notification */
	u_int32_t       tcpi_dsack_recvd;   /* Received a valid DSACK option */
	u_int32_t       tcpi_flowhash;      /* Unique id for the connection */

	u_int64_t       tcpi_txretransmitpackets __attribute__((aligned(8)));

#define TCPINFO_HAS_RCV_RTT 1
	uint32_t       tcpi_rcv_srtt;       /* Receiver's Smoothed RTT */
	uint32_t       tcpi_client_accecn_state;   /* Client's Accurate ECN state */
	uint32_t       tcpi_server_accecn_state;   /* Server's Accurate ECN state as seen by clent */
	uint64_t       tcpi_ecn_capable_packets_sent;   /* Packets sent with ECT */
	uint64_t       tcpi_ecn_capable_packets_acked;  /* Packets sent with ECT that were ACKed */
	uint64_t       tcpi_ecn_capable_packets_marked; /* Packets sent with ECT that were marked, same as delivered_ce_packets */
	uint64_t       tcpi_ecn_capable_packets_lost;   /* Packets sent with ECT that were lost */

#define TCPINFO_HAS_L4S 1
	uint64_t       tcpi_received_ce_packets;
	uint64_t       tcpi_received_ect0_bytes;
	uint64_t       tcpi_received_ect1_bytes;
	uint64_t       tcpi_received_ce_bytes;
	uint64_t       tcpi_delivered_ect0_bytes;
	uint64_t       tcpi_delivered_ect1_bytes;
	uint64_t       tcpi_delivered_ce_bytes;

#define TCPINFO_HAS_LIMITED_TIME 1
	uint64_t       tcpi_flow_control_total_time;
	uint64_t       tcpi_rcvwnd_limited_total_time;
};

struct tcp_measure_bw_burst {
	u_int32_t       min_burst_size;/* Minimum number of packets to use */
	u_int32_t       max_burst_size;/* Maximum number of packets to use */
};

/*
 * Note that IPv6 link local addresses should have the appropriate scope ID
 */

struct info_tuple {
	u_int8_t        itpl_proto;
	union {
#if !__has_ptrcheck
		struct sockaddr                 _itpl_sa;
#endif
		struct __sockaddr_header        _itpl_sah;
		struct sockaddr_in              _itpl_sin;
		struct sockaddr_in6             _itpl_sin6;
	} itpl_localaddr;
	union {
#if !__has_ptrcheck
		struct sockaddr                 _itpl_sa;
#endif
		struct __sockaddr_header        _itpl_sah;
		struct sockaddr_in              _itpl_sin;
		struct sockaddr_in6             _itpl_sin6;
	} itpl_remoteaddr;
};

#if !__has_ptrcheck
#define itpl_local_sa           itpl_localaddr._itpl_sa
#define itpl_remote_sa          itpl_remoteaddr._itpl_sa
#endif

#define itpl_local_sah          itpl_localaddr._itpl_sah
#define itpl_local_sin          itpl_localaddr._itpl_sin
#define itpl_local_sin6         itpl_localaddr._itpl_sin6
#define itpl_remote_sah         itpl_remoteaddr._itpl_sah
#define itpl_remote_sin         itpl_remoteaddr._itpl_sin
#define itpl_remote_sin6        itpl_remoteaddr._itpl_sin6

/*
 * TCP connection info auxiliary data (CIAUX_TCP)
 *
 * Do not add new fields to this structure, just add them to tcp_info
 * structure towards the end. This will preserve binary compatibility.
 */
typedef struct conninfo_tcp {
	struct tcp_info         tcpci_tcp_info;/* TCP info */
} conninfo_tcp_t;

#pragma pack()

struct mptcp_itf_stats {
	u_short  ifindex;
	uint16_t switches;
	uint32_t is_expensive:1;
	uint64_t mpis_txbytes __attribute__((aligned(8)));
	uint64_t mpis_rxbytes __attribute__((aligned(8)));
	uint64_t mpis_wifi_txbytes __attribute__((aligned(8)));
	uint64_t mpis_wifi_rxbytes __attribute__((aligned(8)));
	uint64_t mpis_wired_txbytes __attribute__((aligned(8)));
	uint64_t mpis_wired_rxbytes __attribute__((aligned(8)));
	uint64_t mpis_cell_txbytes __attribute__((aligned(8)));
	uint64_t mpis_cell_rxbytes __attribute__((aligned(8)));
};

/* Version solely used to let libnetcore survive */
#define CONNINFO_MPTCP_VERSION  3
typedef struct conninfo_multipathtcp {
	uint32_t        mptcpci_subflow_count;
	uint32_t        mptcpci_switch_count;
	sae_connid_t    mptcpci_subflow_connids[4];

	uint64_t        mptcpci_init_rxbytes;
	uint64_t        mptcpci_init_txbytes;

#define MPTCP_ITFSTATS_SIZE     4
	struct mptcp_itf_stats mptcpci_itfstats[MPTCP_ITFSTATS_SIZE];

	uint32_t        mptcpci_flags;
#define MPTCPCI_FIRSTPARTY      0x01
} conninfo_multipathtcp_t;
#endif /* (_POSIX_C_SOURCE && !_DARWIN_C_SOURCE) */

#endif /* _NETINET_TCP_PRIVATE_H_ */
