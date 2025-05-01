/*
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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

/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <TargetConditionals.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <os/log.h>
#include <darwintest.h>
#include "skywalk_test_driver.h"
#include "skywalk_test_utils.h"
#include "skywalk_test_common.h"

#define STR(x) _STR(x)
#define _STR(x) #x

#define ENABLE_UPP              true /* channel in user packet pool mode */

#define OUR_FLOWSWITCH_PORT     (NEXUS_PORT_FLOW_SWITCH_CLIENT + 1)

#define FETH0_PORT              0x1234
#define FETH1_PORT              0x5678

#if TARGET_OS_WATCH
#define XFER_TXRX_PACKET_COUNT  20000
#define XFER_TXRX_BATCH_COUNT   4
#define XFER_TXRX_TIMEOUT_SECS  0
#define XFER_TXRX_TIMEOUT_NSECS (100 * 1000 * 1000)

#define XFER_PING_PACKET_COUNT  10000
#define XFER_PING_BATCH_COUNT   64
#define XFER_PING_TIMEOUT_SECS  4
#define XFER_PING_TIMEOUT_NSECS (500 * 1000 * 1000)
#define XFER_PING_CHILD1_RX_TIMEOUT_SECS        4
#define XFER_PING_CHILD1_RX_TIMEOUT_NSECS       0
#define XFER_PING_FADV_TIMEOUT_SECS     2
#define XFER_PING_FADV_TIMEOUT_NSECS    0

#else /* TARGET_OS_WATCH */
#define XFER_TXRX_PACKET_COUNT  (250 * 1000)
#define XFER_TXRX_BATCH_COUNT   8
#define XFER_TXRX_TIMEOUT_SECS  0
#define XFER_TXRX_TIMEOUT_NSECS (100 * 1000 * 1000)

#define XFER_PING_PACKET_COUNT  (125 * 1000)
#define XFER_PING_BATCH_COUNT   128
#define XFER_PING_TIMEOUT_SECS  4
#define XFER_PING_TIMEOUT_NSECS (500 * 1000 * 1000)
#define XFER_PING_CHILD1_RX_TIMEOUT_SECS        4
#define XFER_PING_CHILD1_RX_TIMEOUT_NSECS       0
#define XFER_PING_FADV_TIMEOUT_SECS     2
#define XFER_PING_FADV_TIMEOUT_NSECS    0
#endif /* TARGET_OS_WATCH */

#define XFER_IFADV_INTERVAL     30
#define XFER_TXRX_PACKET_COUNT_LONG     (XFER_TXRX_PACKET_COUNT * 10)
#define XFER_PING_PACKET_COUNT_LONG     (XFER_PING_PACKET_COUNT * 5)
#define XFER_AQM_PING_BATCH_COUNT       8
#define XFER_AQM_PING_PACKET_COUNT      (XFER_AQM_PING_BATCH_COUNT * 4)
#define XFER_CLASSQ_UPDATE_INTERVAL     100     /* milliseconds */
/*
 * delay interval for the classq update interval to elapse.
 * We add some extra delay to the update interval to account for timer drift.
 */
#define XFER_CLASSQ_UPDATE_INTERVAL_ELAPSE_DELAY        \
    (XFER_CLASSQ_UPDATE_INTERVAL + 500) /* milliseconds */

#define XFER_TXRX_PACKET_COUNT_SHORT    (XFER_TXRX_PACKET_COUNT / 10)

/*
 * For overwhelm transfer tests we try to send a large batch of packets
 * over a smaller ring size
 */
#define XFER_TXRX_OVERWHELM_BATCH_COUNT         2048
#define XFER_TXRX_OVERWHELM_FSW_TX_RING_SIZE            \
    (XFER_TXRX_OVERWHELM_BATCH_COUNT / 2)
#define XFER_TXRX_OVERWHELM_FSW_RX_RING_SIZE            \
    XFER_TXRX_OVERWHELM_FSW_TX_RING_SIZE

#define XFER_TXRX_MULTI_BUFLET_BUF_SIZE         512
#define XFER_TXRX_MULTI_BUFLET_MAX_FRAGS        4 /* packet size = 2048 */

#define XFER_RECV_END_PAYLOAD   "DEADBEEF"      /* receiver end payload */
#define XFER_QOSMARKING_FASTLANE_PREFIX "FASTLANE."
#define XFER_QOSMARKING_RFC4594_PREFIX  "RFC4594."

#define XFER_TX_PKT_DROP_RATE   100

/* dummy packet identifier constants */
#define XFER_PKTID_PAYLOAD_TYPE    0xFA
#define XFER_PKTID_STREAM_ID       0xFB

static struct sktc_nexus_handles        handles;
static uint32_t inject_error_rmask;
static uint32_t skt_disable_nxctl_check;

#define INJECT_CODE_IDX_MAX     2
struct fsw_inject_codes {
	int         ic_code;
	uint32_t    ic_rmask;
	int         ic_stat_idx[INJECT_CODE_IDX_MAX];
};
#define IC_RMASK_UNSPEC (-1)

#define _S1(code, a)     {(code), IC_RMASK_UNSPEC, {(a), -1}}
#define _S2(code, a, b)   {(code), IC_RMASK_UNSPEC, {(a), (b)}}
#define _S3(code, a, b, c)   {(code), a, {(b), (c)}}

static const struct fsw_inject_codes fsw_inject_codes[] = {
	/* flow_pkt_classify() returns ENXIO */
	_S1(1, FSW_STATS_RX_FLOW_EXTRACT_ERR),

	/* ms_copy_to_dev_mbuf() sets mbuf to NULL */
	/*_S2(11,	FSW_STATS_DROP, FSW_STATS_DROP_NOMEM_MBUF), */

	/* ms_copy_to_dev_pkt() set pkt to NULL */
	_S2(12, FSW_STATS_DROP, FSW_STATS_DROP_NOMEM_PKT),

	/* ms_dev_output() QP_PACKET sets pkt_drop to TRUE */
	_S2(14, FSW_STATS_DROP, FSW_STATS_TX_AQM_DROP),

	/*
	 * Can result in a later kernel panic when the nexus is closed
	 * so do not use for now.
	 */

	/* fsw_ms_user_port_flush() spkt->pkt_qum_flags set to
	 *  (spkt->pkt_qum_flags | QUMF_DROPPED) */
	_S1(20, FSW_STATS_DROP),

	/* fsw_ms_user_port_flush() is_frag TRUE */
	/*_S1(21, FSW_STATS_DROP), */

	/*
	 * 31 Triggers a kernel assertion. Do not use.
	 * 32 only makes sense if 31 is also enabled.
	 */
	/* ms_lookup() fakes flow entry not found */
	/*_S1(31,	FSW_STATS_TXLOOKUP_NOMATCH), */
	/* ms_lookup() fakes NULL host_na */
	/*_S1(32,	FSW_STATS_HOST_NOT_ATTACHED), */

	/*
	 * 33 to 43 apply to outbound (to device) or inbound to legacy stack
	 * so cannot (yet) be tested. Some of them can also trigger kernel
	 * assertions.
	 */

	/* fsw_resolve() returns EJUSTRETURN */
	_S1(35, FSW_STATS_TX_RESOLV_PENDING),

	/* fsw_resolve() returns error other than EJUSTRETURN but flow route has stale entry */
	_S1(36, FSW_STATS_TX_RESOLV_STALE),
#if 0
	/* ms_lookup() fails to track packet */
	_S2(33, FSW_STATS_RXLOOKUP_TRACKERR, FSW_STATS_TXLOOKUP_TRACKERR),
	/* ms_lookup() wrong uuid. */
	_S2(34, FSW_STATS_RXLOOKUP_INVALID_ID, FSW_STATS_TXLOOKUP_INVALID_ID),

	/* ms_dev_port_flush_enqueue_dst() kr_space_avail to zero. */
	_S1(40, FSW_STATS_DST_KRSPACE_DROP),

	/* ms_dev_port_flush_enqueue_dst() n (needed) to zero. */
	_S1(41, FSW_STATS_DROP),

	/* ms_dev_port_flush_enqueue_dst() fake pp_alloc_packet_batch()
	 *  returning ENOMEM. */
	_S1(42, FSW_STATS_NOMEM_PKT),

	/* ms_dev_port_flush_enqueue_dst() fake ms_copy_packet_from_dev()
	 *  returning EINVAL. */
	_S1(43, FSW_STATS_DROP)
#endif
};
#define INJECT_CODE_COUNT       (sizeof(fsw_inject_codes) / \
	                         sizeof(fsw_inject_codes[0]))

static packet_svc_class_t packet_svc_class[] =
{
	PKT_SC_BK_SYS,
	PKT_SC_BK,
	PKT_SC_BE,
	PKT_SC_RD,
	PKT_SC_OAM,
	PKT_SC_AV,
	PKT_SC_RV,
	PKT_SC_VI,
	PKT_SC_VO,
	PKT_SC_CTL
};

#define NUM_SVC_CLASS                   \
    (sizeof (packet_svc_class) / sizeof (packet_svc_class[0]))
#define XFER_WMM_PING_BATCH_COUNT       8
#define XFER_WMM_PING_PACKET_COUNT      \
    (XFER_WMM_PING_BATCH_COUNT * NUM_SVC_CLASS)

/* test identifiers for flowswitch event tests */
#define SKT_FSW_EVENT_TEST_NONE               0
#define SKT_FSW_EVENT_TEST_IF_ADV_ENABLED     1
#define SKT_FSW_EVENT_TEST_IF_ADV_DISABLED    2
#define SKT_FSW_EVENT_TEST_CHANNEL_EVENTS         3

/* flowswitch xfer test event flags */
#define SKT_FSW_EVFLAG_IFADV            0x1
#define SKT_FSW_EVFLAG_CHANNEL          0x2

/* test identifiers for ping-pong tests */
#define SKT_FSW_PING_PONG_TEST_DEFAULT        0
#define SKT_FSW_PING_PONG_TEST_LOW_LATENCY    1
#define SKT_FSW_PING_PONG_TEST_MULTI_LLINK    2
/****************************************************************/

/* Parent-child tests */
#define CHILD_FLOWSWITCH_PORT     OUR_FLOWSWITCH_PORT + 1
#define DEMUX_PAYLOAD_OFFSET      offsetof(my_payload, data)
#define DEMUX_PAYLOAD_VALUE       0xFFFF
#define MAX_DEMUX_OFFSET          900

static inline uint16_t
skt_xfer_fold_sum_final(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */
	return ~sum & 0xffff;
}

static int
connect_flow(nexus_controller_t ncd,
    const uuid_t fsw, nexus_port_t nx_port, const uuid_t flow,
    int protocol, uint16_t flags,
    struct in_addr src_addr, in_port_t src_port,
    struct in_addr dst_addr, in_port_t dst_port,
    flowadv_idx_t *flowadv_idx, uint64_t qset_id)
{
	struct nx_flow_req nfr;
	int error;

	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = protocol;
	nfr.nfr_nx_port = nx_port;
	uuid_copy(nfr.nfr_flow_uuid, flow);
	nfr.nfr_flags = flags;
	/* src */
	nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_saddr.sa.sa_family = AF_INET;
	nfr.nfr_saddr.sin.sin_port = htons(src_port);
	nfr.nfr_saddr.sin.sin_addr = src_addr;
	/* dst */
	nfr.nfr_daddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_daddr.sa.sa_family = AF_INET;
	nfr.nfr_daddr.sin.sin_port = htons(dst_port);
	nfr.nfr_daddr.sin.sin_addr = dst_addr;
	nfr.nfr_flowadv_idx = FLOWADV_IDX_NONE;
	nfr.nfr_qset_id = qset_id;
	error = __os_nexus_flow_add(ncd, fsw, &nfr);

	if (error) {
		SKT_LOG("__os_nexus_flow_add/nsbind failed %s (%d)\n",
		    strerror(errno), errno);
		error = errno;
	} else if (nfr.nfr_nx_port != nx_port) {
		T_LOG("nfr_nx_port %d != nx_port %d\n",
		    nfr.nfr_nx_port, nx_port);
		error = EINVAL;
	}
	*flowadv_idx = nfr.nfr_flowadv_idx;
	return error;
}

static int
connect_child_flow(nexus_controller_t ncd,
    const uuid_t fsw, nexus_port_t nx_port, const uuid_t flow,
    int protocol, uint16_t flags,
    struct in_addr src_addr, in_port_t src_port,
    struct in_addr dst_addr, in_port_t dst_port,
    flowadv_idx_t *flowadv_idx, uint64_t qset_id, const uuid_t parent_flow,
    struct flow_demux_pattern *demux_patterns, uint8_t demux_pattern_count)
{
	struct nx_flow_req nfr;
	int error;

	memset(&nfr, 0, sizeof(nfr));
	nfr.nfr_ip_protocol = protocol;
	nfr.nfr_nx_port = nx_port;
	uuid_copy(nfr.nfr_flow_uuid, flow);
	nfr.nfr_flags = flags;
	/* src */
	nfr.nfr_saddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_saddr.sa.sa_family = AF_INET;
	nfr.nfr_saddr.sin.sin_port = htons(src_port);
	nfr.nfr_saddr.sin.sin_addr = src_addr;
	/* dst */
	nfr.nfr_daddr.sa.sa_len = sizeof(struct sockaddr_in);
	nfr.nfr_daddr.sa.sa_family = AF_INET;
	nfr.nfr_daddr.sin.sin_port = htons(dst_port);
	nfr.nfr_daddr.sin.sin_addr = dst_addr;
	nfr.nfr_flowadv_idx = FLOWADV_IDX_NONE;
	nfr.nfr_qset_id = qset_id;
	uuid_copy(nfr.nfr_parent_flow_uuid, parent_flow);

	for (int i = 0; i < demux_pattern_count; i++) {
		bcopy(&demux_patterns[i], &nfr.nfr_flow_demux_patterns[i],
		    sizeof(struct flow_demux_pattern));
	}
	nfr.nfr_flow_demux_count = demux_pattern_count;
	error = __os_nexus_flow_add(ncd, fsw, &nfr);

	if (error) {
		SKT_LOG("__os_nexus_flow_add/nsbind failed %s (%d)\n",
		    strerror(errno), errno);
		error = errno;
	} else if (nfr.nfr_nx_port != nx_port) {
		T_LOG("nfr_nx_port %d != nx_port %d\n",
		    nfr.nfr_nx_port, nx_port);
		error = EINVAL;
	}
	*flowadv_idx = nfr.nfr_flowadv_idx;
	return error;
}


static inline uint32_t
skt_xfer_get_chan_max_frags(const channel_t chd)
{
	return (uint32_t)sktc_get_channel_attr(chd, CHANNEL_ATTR_MAX_FRAGS);
}

static inline void
sktc_xfer_copy_data_to_packet(channel_port_t port, packet_t ph,
    const void * data, uint16_t data_len, uint16_t start_offset,
    bool csum_offload, uint32_t *partial_csum)
{
	char *baddr;
	buflet_t buf, pbuf = NULL;
	uint16_t clen, bdlim, blen;
	uint16_t len = data_len;
	uint32_t partial = 0;
	size_t  frame_length = data_len + start_offset;
	int error;

	buf = os_packet_get_next_buflet(ph, NULL);
	assert(buf != NULL);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);
	bdlim = blen = os_buflet_get_data_limit(buf);
	baddr += start_offset;
	blen -= start_offset;

	/* copy the data */
	while (len != 0) {
		if (blen == 0) {
			error = os_buflet_set_data_length(buf, bdlim);
			SKTC_ASSERT_ERR(error == 0);
			pbuf = buf;
#if ENABLE_UPP
			error = os_channel_buflet_alloc(port->chan, &buf);
			SKTC_ASSERT_ERR(error == 0);
			assert(buf != NULL);
			error = os_packet_add_buflet(ph, pbuf, buf);
			SKTC_ASSERT_ERR(error == 0);
#else
			buf = os_packet_get_next_buflet(ph, pbuf);
			assert(buf != NULL);
#endif
			error = os_buflet_set_data_offset(buf, 0);
			SKTC_ASSERT_ERR(error == 0);
			baddr = os_buflet_get_object_address(buf);
			assert(baddr != NULL);
			bdlim = blen = os_buflet_get_data_limit(buf);
		}
		clen = MIN(blen, len);
		if (csum_offload) {
			bcopy(data, baddr, clen);
		} else {
			partial = ~os_copy_and_inet_checksum(data, baddr, clen,
			    partial);
		}
		len -= clen;
		blen -= clen;
		data += clen;
		baddr += clen;
		assert(len == 0 || blen == 0);
	}
	if (pbuf == NULL) {
		error = os_buflet_set_data_length(buf, frame_length);
	} else {
		error = os_buflet_set_data_length(buf, clen);
	}
	SKTC_ASSERT_ERR(error == 0);
	if (!csum_offload) {
		*partial_csum = partial;
	}
}
/****************************************************************/

#if SKT_XFER_DEBUG
static const char *
inet_ptrtoa(const void * ptr)
{
	struct in_addr  ip;

	bcopy(ptr, &ip, sizeof(ip));
	return inet_ntoa(ip);
}

static void
ip_frame_dump(const void * buf, size_t buf_len)
{
	ip_tcp_header_t *       ip_tcp;
	ip_udp_header_t *       ip_udp;
	int                     ip_len;

	assert(buf_len >= sizeof(struct ip));
	ip_udp = (ip_udp_header_t *)buf;
	ip_tcp = (ip_tcp_header_t *)buf;
	ip_len = ntohs(ip_udp->ip.ip_len);
	T_LOG("ip src %s ", inet_ptrtoa(&ip_udp->ip.ip_src));
	T_LOG("dst %s len %d id %d\n",
	    inet_ptrtoa(&ip_udp->ip.ip_dst), ip_len,
	    ntohs(ip_udp->ip.ip_id));
	assert(buf_len >= ip_len);
	assert(ip_udp->ip.ip_v == IPVERSION);
	assert(ip_udp->ip.ip_hl == (sizeof(struct ip) >> 2));
	switch (ip_udp->ip.ip_p) {
	case IPPROTO_UDP: {
		int     udp_len;
		int     data_len;

		assert(buf_len >= sizeof(*ip_udp));
		udp_len = ntohs(ip_udp->udp.uh_ulen);
		data_len = udp_len - (int)sizeof(ip_udp->udp);
		T_LOG(
			"UDP src 0x%x dst 0x%x len %d csum 0x%x datalen %d\n",
			ntohs(ip_udp->udp.uh_sport),
			ntohs(ip_udp->udp.uh_dport),
			udp_len,
			ntohs(ip_udp->udp.uh_sum),
			data_len);
		break;
	}
	case IPPROTO_TCP: {
		assert(buf_len >= sizeof(*ip_tcp));
		T_LOG(
			"TCP src 0x%x dst 0x%x seq %u ack %u "
			"off %d flags 0x%x win %d csum 0x%x\n",
			ntohs(ip_tcp->tcp.th_sport),
			ntohs(ip_tcp->tcp.th_dport),
			ntohl(ip_tcp->tcp.th_seq),
			ntohl(ip_tcp->tcp.th_ack),
			ip_tcp->tcp.th_off,
			ip_tcp->tcp.th_flags,
			ntohs(ip_tcp->tcp.th_win),
			ntohs(ip_tcp->tcp.th_sum));
		break;
	}
	default:
		break;
	}
}
#endif

static int              ip_id;

static size_t
tcp_frame_populate(channel_port_t port, packet_t ph, struct in_addr src_ip,
    uint16_t src_port, struct in_addr dst_ip, uint16_t dst_port,
    const void * data, size_t data_len, bool connect,
    bool csum_offload)
{
	int                     error;
	size_t                  frame_length;
	ip_tcp_header_t *       ip_tcp;
	char *                  baddr;
	tcp_pseudo_hdr_t *      tcp_pseudo;
	buflet_t                buf;
	uint16_t                bdlim;
	uint32_t                partial = 0;

	buf = os_packet_get_next_buflet(ph, NULL);
	assert(buf != NULL);
	error = os_buflet_set_data_offset(buf, 0);
	SKTC_ASSERT_ERR(error == 0);
	bdlim = os_buflet_get_data_limit(buf);
	assert(bdlim != 0);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);

	frame_length = sizeof(*ip_tcp) + data_len;
#if ENABLE_UPP
	assert((os_packet_get_buflet_count(ph) == 1));
	assert((skt_xfer_get_chan_max_frags(port->chan) * bdlim) >=
	    frame_length);
#else
	assert((os_packet_get_buflet_count(ph) * bdlim) >= frame_length);
#endif
	assert(bdlim >= sizeof(ip_tcp_header_t));

	error = os_packet_set_link_header_length(ph, 0);
	SKTC_ASSERT_ERR(error == 0);
	/* determine frame offsets */
	ip_tcp = (ip_tcp_header_t *)baddr;
	tcp_pseudo = (tcp_pseudo_hdr_t *)
	    (((char *)&ip_tcp->tcp) - sizeof(*tcp_pseudo));
	baddr += sizeof(*ip_tcp);

	/* copy the data */
	sktc_xfer_copy_data_to_packet(port, ph, data, data_len, sizeof(*ip_tcp),
	    csum_offload, &partial);

	/* fill in TCP header */
	ip_tcp->tcp.th_sport = htons(src_port);
	ip_tcp->tcp.th_dport = htons(dst_port);
	ip_tcp->tcp.th_flags |= (connect ? TH_SYN : TH_RST);
	ip_tcp->tcp.th_off = (sizeof(struct tcphdr)) >> 2;
	ip_tcp->tcp.th_sum = 0;
	if (csum_offload) {
		ip_tcp->tcp.th_sum = in_pseudo(src_ip.s_addr, dst_ip.s_addr,
		    htons(data_len + sizeof(ip_tcp->tcp) + IPPROTO_TCP));
		os_packet_set_inet_checksum(ph, PACKET_CSUM_PARTIAL,
		    sizeof(struct ip),
		    sizeof(struct ip) + offsetof(struct tcphdr, th_sum));
	} else {
		/* fill in TCP pseudo header (overwritten by IP header below) */
		tcp_pseudo_hdr_t *      tcp_pseudo;
		tcp_pseudo = (tcp_pseudo_hdr_t *)
		    (((char *)&ip_tcp->tcp) - sizeof(*tcp_pseudo));
		bcopy(&src_ip, &tcp_pseudo->src_ip, sizeof(src_ip));
		bcopy(&dst_ip, &tcp_pseudo->dst_ip, sizeof(dst_ip));
		tcp_pseudo->zero = 0;
		tcp_pseudo->proto = IPPROTO_TCP;
		tcp_pseudo->length = htons(sizeof(ip_tcp->tcp) + data_len);
		partial = os_inet_checksum(tcp_pseudo, sizeof(*tcp_pseudo)
		    + sizeof(ip_tcp->tcp), partial);
		ip_tcp->tcp.th_sum = skt_xfer_fold_sum_final(partial);
	}

	/* fill in IP header */
	bzero(ip_tcp, sizeof(ip_tcp->ip));
	ip_tcp->ip.ip_v = IPVERSION;
	ip_tcp->ip.ip_hl = sizeof(struct ip) >> 2;
	ip_tcp->ip.ip_ttl = MAXTTL;
	ip_tcp->ip.ip_p = IPPROTO_TCP;
	bcopy(&src_ip, &ip_tcp->ip.ip_src, sizeof(src_ip));
	bcopy(&dst_ip, &ip_tcp->ip.ip_dst, sizeof(dst_ip));
	ip_tcp->ip.ip_len = htons(sizeof(*ip_tcp) + data_len);
	ip_tcp->ip.ip_id = htons(ip_id++);

	/* compute the IP checksum */
	ip_tcp->ip.ip_sum = 0; /* needs to be zero for checksum */
	ip_tcp->ip.ip_sum = in_cksum(&ip_tcp->ip, sizeof(ip_tcp->ip), 0);
	return frame_length;
}

static size_t
udp_frame_populate(channel_port_t port, packet_t ph, struct in_addr src_ip,
    uint16_t src_port, struct in_addr dst_ip, uint16_t dst_port,
    const void * data, size_t data_len, bool csum_offload,
    uint16_t fragment_id, size_t total_udp_len)
{
	int                     error;
	size_t                  frame_length;
	ip_udp_header_t *       ip_udp;
	char *                  baddr;
	udp_pseudo_hdr_t *      udp_pseudo;
	buflet_t                buf;
	uint16_t                bdlim;
	uint32_t                partial = 0;

	buf = os_packet_get_next_buflet(ph, NULL);
	assert(buf != NULL);
	error = os_buflet_set_data_offset(buf, 0);
	SKTC_ASSERT_ERR(error == 0);
	bdlim = os_buflet_get_data_limit(buf);
	assert(bdlim != 0);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);

	frame_length = sizeof(*ip_udp) + data_len;
#if ENABLE_UPP
	assert((os_packet_get_buflet_count(ph) == 1));
	assert((skt_xfer_get_chan_max_frags(port->chan) * bdlim) >=
	    frame_length);
#else
	assert((os_packet_get_buflet_count(ph) * bdlim) >= frame_length);
#endif
	assert(bdlim >= sizeof(ip_udp_header_t));

	error = os_packet_set_link_header_length(ph, 0);
	SKTC_ASSERT_ERR(error == 0);
	/* determine frame offsets */
	ip_udp = (ip_udp_header_t *)baddr;
	udp_pseudo = (udp_pseudo_hdr_t *)
	    (((char *)&ip_udp->udp) - sizeof(*udp_pseudo));
	baddr += sizeof(*ip_udp);

	/* copy the data */
	sktc_xfer_copy_data_to_packet(port, ph, data, data_len, sizeof(*ip_udp),
	    csum_offload, &partial);

	/* fill in UDP header */
	ip_udp->udp.uh_sport = htons(src_port);
	ip_udp->udp.uh_dport = htons(dst_port);
	ip_udp->udp.uh_ulen = htons(sizeof(ip_udp->udp) + total_udp_len);
	ip_udp->udp.uh_sum = 0;
	if (csum_offload) {
		ip_udp->udp.uh_sum = in_pseudo(src_ip.s_addr, dst_ip.s_addr,
		    htons(total_udp_len + sizeof(ip_udp->udp) + IPPROTO_UDP));
		os_packet_set_inet_checksum(ph,
		    PACKET_CSUM_PARTIAL | PACKET_CSUM_ZERO_INVERT,
		    sizeof(struct ip),
		    sizeof(struct ip) + offsetof(struct udphdr, uh_sum));
	} else {
		/* fill in UDP pseudo header (overwritten by IP header below) */
		udp_pseudo_hdr_t *udp_pseudo;
		udp_pseudo = (udp_pseudo_hdr_t *)
		    (((char *)&ip_udp->udp) - sizeof(*udp_pseudo));
		bcopy(&src_ip, &udp_pseudo->src_ip, sizeof(src_ip));
		bcopy(&dst_ip, &udp_pseudo->dst_ip, sizeof(dst_ip));
		udp_pseudo->zero = 0;
		udp_pseudo->proto = IPPROTO_UDP;
		udp_pseudo->length = htons(sizeof(ip_udp->udp) + total_udp_len);
		partial = os_inet_checksum(udp_pseudo, sizeof(*udp_pseudo)
		    + sizeof(ip_udp->udp), partial);
		ip_udp->udp.uh_sum = skt_xfer_fold_sum_final(partial);
	}

	/* fill in IP header */
	bzero(ip_udp, sizeof(ip_udp->ip));
	ip_udp->ip.ip_v = IPVERSION;
	ip_udp->ip.ip_hl = sizeof(struct ip) >> 2;
	ip_udp->ip.ip_ttl = MAXTTL;
	ip_udp->ip.ip_p = IPPROTO_UDP;
	bcopy(&src_ip, &ip_udp->ip.ip_src, sizeof(src_ip));
	bcopy(&dst_ip, &ip_udp->ip.ip_dst, sizeof(dst_ip));
	ip_udp->ip.ip_len = htons(sizeof(*ip_udp) + data_len);
	if (fragment_id != 0) {
		ip_udp->ip.ip_id = htons(fragment_id);
		ip_udp->ip.ip_off = htons(IP_MF);
	} else {
		ip_udp->ip.ip_id = htons(ip_id++);
	}

	/* compute the IP header checksum */
	ip_udp->ip.ip_sum = 0; /* needs to be zero for checksum */
	ip_udp->ip.ip_sum = in_cksum(&ip_udp->ip, sizeof(ip_udp->ip), 0);
	return frame_length;
}

static size_t
ip_frame_populate(channel_port_t port, packet_t ph, uint8_t protocol,
    struct in_addr src_ip, struct in_addr dst_ip, const void * data,
    size_t data_len, uint16_t fragment_id, uint16_t fragment_offset,
    bool last_fragment)
{
	int                     error;
	size_t                  frame_length;
	struct ip               *ip;
	char *                  baddr;
	buflet_t                buf;
	uint16_t                bdlim;

	buf = os_packet_get_next_buflet(ph, NULL);
	assert(buf != NULL);
	error = os_buflet_set_data_offset(buf, 0);
	SKTC_ASSERT_ERR(error == 0);
	bdlim = os_buflet_get_data_limit(buf);
	assert(bdlim != 0);
	baddr = os_buflet_get_object_address(buf);
	assert(baddr != NULL);

	frame_length = sizeof(*ip) + data_len;
#if ENABLE_UPP
	assert((os_packet_get_buflet_count(ph) == 1));
	assert((skt_xfer_get_chan_max_frags(port->chan) * bdlim) >=
	    frame_length);
#else
	assert((os_packet_get_buflet_count(ph) * bdlim) >= frame_length);
#endif
	assert(bdlim >= sizeof(*ip));

	error = os_packet_set_link_header_length(ph, 0);
	SKTC_ASSERT_ERR(error == 0);
	/* determine frame offsets */
	ip = (struct ip*)baddr;
	baddr += sizeof(*ip);

	/* fill in IP header */
	bzero(ip, sizeof(*ip));
	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_ttl = MAXTTL;
	ip->ip_p = protocol;
	bcopy(&src_ip, &ip->ip_src, sizeof(src_ip));
	bcopy(&dst_ip, &ip->ip_dst, sizeof(dst_ip));
	ip->ip_len = htons(sizeof(*ip) + data_len);
	if (fragment_id != 0) {
		ip->ip_id = htons(fragment_id);
		ip->ip_off = htons(last_fragment ? 0 : IP_MF) | htons(fragment_offset / 8);
	} else {
		ip->ip_id = htons(ip_id++);
	}

	/* compute the IP header checksum */
	ip->ip_sum = 0; /* needs to be zero for checksum */
	ip->ip_sum = in_cksum(ip, sizeof(*ip), 0);

	/* copy the data */
	sktc_xfer_copy_data_to_packet(port, ph, data, data_len, sizeof(*ip),
	    TRUE, NULL);
	return frame_length;
}

static size_t
frame_populate(channel_port_t port, packet_t ph, int protocol,
    struct in_addr src_ip, uint16_t src_port, struct in_addr dst_ip,
    uint16_t dst_port, const void * data, size_t data_len, uuid_t flow_id,
    bool connect, packet_svc_class_t svc_class, bool csum_offload,
    uint16_t fragment_id, size_t total_data_len, uint16_t fragment_offset,
    bool last_fragment)
{
	size_t  ret;
	int     error;

	switch (protocol) {
	case IPPROTO_TCP:
		ret = tcp_frame_populate(port, ph, src_ip, src_port, dst_ip,
		    dst_port, data, data_len, connect, csum_offload);
		break;
	case IPPROTO_UDP:
		assert(connect == FALSE);
		if (fragment_offset > 0) {
			ret = ip_frame_populate(port, ph, protocol, src_ip,
			    dst_ip, data, data_len, fragment_id,
			    fragment_offset, last_fragment);
		} else {
			ret = udp_frame_populate(port, ph, src_ip, src_port,
			    dst_ip, dst_port, data, data_len, csum_offload,
			    fragment_id, total_data_len);
		}
		break;
	default:
		ret = ip_frame_populate(port, ph, protocol, src_ip, dst_ip,
		    data, data_len, fragment_id, fragment_offset,
		    last_fragment);
		break;
	}
	error = os_packet_set_service_class(ph, svc_class);
	SKTC_ASSERT_ERR(error == 0);
	os_packet_set_flow_uuid(ph, flow_id);
	error = os_packet_finalize(ph);
	SKTC_ASSERT_ERR(error == 0);
	assert(ret == os_packet_get_data_length(ph));
	return ret;
}

static size_t
tcp_frame_process(packet_t ph, void *data, size_t data_max)
{
	buflet_t buflet;
	size_t pkt_len, data_len, ip_len, buf_len;
	uint32_t bdoff;
	void *buf;
	ip_tcp_header_t *ip_tcp;
	uint16_t csum;

	/**********************************************************************/
	/* process 1st buflet which contains protocol header */
	buflet = os_packet_get_next_buflet(ph, NULL);
	assert(buflet != NULL);
	buf_len = os_buflet_get_data_length(buflet);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	ip_tcp = (ip_tcp_header_t *)buf;

	pkt_len = os_packet_get_data_length(ph);
	ip_len = ntohs(ip_tcp->ip.ip_len);
	assert(ip_len <= pkt_len);
	data_len = ip_len - sizeof(*ip_tcp);
	assert(data_len <= data_max);

	/* IP */
	assert(ip_tcp->ip.ip_p == IPPROTO_TCP);

	/* verify IP header checksum */
	csum = in_cksum(&ip_tcp->ip, sizeof(ip_tcp->ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, "ip header checksum", buf, buf_len);
		fflush(stderr);
		assert(0);
	}

	/* starts TCP partial checksum on 1st buflet */
	buf_len = MIN(ip_len, buf_len);
	csum = os_inet_checksum(&ip_tcp->tcp, buf_len - sizeof(struct ip), 0);
	if (data != NULL) {     /* copy the data */
		bcopy(buf + sizeof(*ip_tcp), data, buf_len - sizeof(*ip_tcp));
		data += (buf_len - sizeof(*ip_tcp));
	}

	/**********************************************************************/
	/* iterate through the rest of buflets */
	ip_len -= buf_len;
	while (ip_len != 0) {
		buflet = os_packet_get_next_buflet(ph, buflet);
		assert(buflet != NULL);
		bdoff = os_buflet_get_data_offset(buflet);
		buf = os_buflet_get_object_address(buflet) + bdoff;
		assert(buf != 0);
		buf_len = os_buflet_get_data_length(buflet);
		assert(buf_len != 0);
		csum = os_inet_checksum(buf, buf_len, csum);
		if (data != NULL) {     /* copy the data */
			bcopy(buf, data, buf_len);
			data += buf_len;
		}
		ip_len -= buf_len;
	}

	csum = in_pseudo(ip_tcp->ip.ip_src.s_addr, ip_tcp->ip.ip_dst.s_addr,
	    csum + htons(data_len + sizeof(struct tcphdr) + IPPROTO_TCP));
	csum ^= 0xffff;
	if (csum != 0) {
		sktu_dump_buffer(stderr, "tcp packet bad checksum", buf,
		    ntohs(ip_tcp->ip.ip_len));
		fflush(stderr);
		assert(0);
	}

	return data_len;
}

static size_t
udp_frame_process(packet_t ph, void *data, size_t data_max)
{
	buflet_t buflet;
	size_t pkt_len, buf_len, ip_len, data_len;
	uint32_t bdoff;
	void *buf;
	ip_udp_header_t *ip_udp;
	uint16_t csum;

	/**********************************************************************/
	/* process 1st buflet which contains protocol header */
	buflet = os_packet_get_next_buflet(ph, NULL);
	assert(buflet != NULL);
	buf_len = os_buflet_get_data_length(buflet);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	ip_udp = (ip_udp_header_t *)buf;

	pkt_len = os_packet_get_data_length(ph);
	ip_len = ntohs(ip_udp->ip.ip_len);
	assert(ip_len <= pkt_len);
	data_len = ip_len - sizeof(*ip_udp);
	assert(data_len <= data_max);

	assert(ip_udp->ip.ip_p == IPPROTO_UDP);

	/* verify IP header checksum */
	csum = in_cksum(&ip_udp->ip, sizeof(ip_udp->ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, "ip header checksum", buf, ip_len);
		fflush(stderr);
		assert(0);
	}

	/* starts UDP partial checksum on 1st buflet */
	buf_len = MIN(ip_len, buf_len);
	csum = os_inet_checksum(&ip_udp->udp, buf_len - sizeof(struct ip), 0);

	if (data != NULL) {     /* copy the data */
		bcopy(buf + sizeof(*ip_udp), data, buf_len - sizeof(*ip_udp));
		data += (buf_len - sizeof(*ip_udp));
	}

	/**********************************************************************/
	/* iterate through the rest of buflets */
	ip_len -= buf_len;
	while (ip_len != 0) {
		buflet = os_packet_get_next_buflet(ph, buflet);
		assert(buflet != NULL);
		bdoff = os_buflet_get_data_offset(buflet);
		buf = os_buflet_get_object_address(buflet) + bdoff;
		assert(buf != 0);
		buf_len = os_buflet_get_data_length(buflet);
		buf_len = MIN(buf_len, ip_len);
		assert(buf_len != 0);
		if (ip_udp->udp.uh_sum != 0) {
			csum = os_inet_checksum(buf, buf_len, csum);
		}
		if (data != NULL) {     /* copy the data */
			bcopy(buf, data, buf_len);
			data += buf_len;
		}
		ip_len -= buf_len;
	}

	/* verify UDP checksum */
	if (ip_udp->ip.ip_off == 0 &&
	    ip_udp->udp.uh_sum != 0) {
		csum = in_pseudo(ip_udp->ip.ip_src.s_addr, ip_udp->ip.ip_dst.s_addr,
		    csum + htons(data_len + sizeof(struct udphdr) + IPPROTO_UDP));
		csum ^= 0xffff;
		if (csum != 0) {
			sktu_dump_buffer(stderr, "udp packet bad checksum", buf,
			    ntohs(ip_udp->ip.ip_len));
			fflush(stderr);
			assert(0);
		}
	}

	return data_len;
}

static size_t
ip_frame_process(packet_t ph, void * data, size_t data_max)
{
	buflet_t buflet;
	size_t pkt_len, buf_len, data_len;
	uint32_t bdoff;
	void *buf;
	struct ip *ip;
	uint16_t csum;

	/**********************************************************************/
	/* process 1st buflet which contains protocol header */
	buflet = os_packet_get_next_buflet(ph, NULL);
	assert(buflet != NULL);
	buf_len = os_buflet_get_data_length(buflet);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	ip = (struct ip*)buf;

	pkt_len = os_packet_get_data_length(ph);
	assert(pkt_len == ntohs(ip->ip_len));
	data_len = pkt_len - sizeof(*ip);
	assert(data_len <= data_max);

	/* verify IP header checksum */
	csum = in_cksum(ip, sizeof(*ip), 0);
	if (csum != 0) {
		sktu_dump_buffer(stderr, "ip header checksum", buf, buf_len);
		fflush(stderr);
		assert(0);
	}

	if (data != NULL) {     /* copy the data */
		bcopy(buf + sizeof(*ip), data, buf_len - sizeof(*ip));
		data += (buf_len - sizeof(*ip));
	}

	/**********************************************************************/
	/* iterate through the rest of buflets */
	pkt_len -= buf_len;
	while (pkt_len != 0) {
		buflet = os_packet_get_next_buflet(ph, buflet);
		assert(buflet != NULL);
		bdoff = os_buflet_get_data_offset(buflet);
		buf = os_buflet_get_object_address(buflet) + bdoff;
		assert(buf != 0);
		buf_len = os_buflet_get_data_length(buflet);
		assert(buf_len != 0);
		if (data != NULL) {     /* copy the data */
			bcopy(buf, data, buf_len);
			data += buf_len;
		}
		pkt_len -= buf_len;
	}

	return data_len;
}

struct qosmarking_mapping {
	char            *svc_str;
	uint32_t        svc;
	uint32_t        dscp;
};

#define QOSMARKING_MAPPINGS(X)          \
	/*SVC_CLASS		FASTLANE	RFC4594	*/      \
	X(PKT_SC_BK,		_DSCP_AF11,	_DSCP_CS1)      \
	X(PKT_SC_BK_SYS,	_DSCP_AF11,	_DSCP_CS1)      \
	X(PKT_SC_BE,		_DSCP_DF,	_DSCP_DF)       \
	X(PKT_SC_RD,		_DSCP_AF21,	_DSCP_AF21)     \
	X(PKT_SC_OAM,		_DSCP_CS2,	_DSCP_CS2)      \
	X(PKT_SC_AV,		_DSCP_AF31,	_DSCP_AF31)     \
	X(PKT_SC_RV,		_DSCP_CS4,	_DSCP_CS4)      \
	X(PKT_SC_VI,		_DSCP_AF41,	_DSCP_AF41)     \
	X(PKT_SC_SIG,		_DSCP_CS3,	_DSCP_CS5)      \
	X(PKT_SC_VO,		_DSCP_EF,	_DSCP_EF)       \
	X(PKT_SC_CTL,		_DSCP_DF,	_DSCP_CS6)

#define MAP_TO_FASTLANE(a, b, c) {#a, a, b},
#define MAP_TO_RFC4594(a, b, c)  {#a, a, c},

#define QOSMARKING_SVC_MAX      11

struct qosmarking_mapping fastlane_mappings[] = {
	QOSMARKING_MAPPINGS(MAP_TO_FASTLANE)
};

struct qosmarking_mapping rfc4594_mappings[] = {
	QOSMARKING_MAPPINGS(MAP_TO_RFC4594)
};

static size_t
frame_process(packet_t ph, void *data, size_t data_max, bool verify_qos)
{
	buflet_t buflet;
	void *buf;
	struct ip *ip;
	size_t buf_len, ret;

	buflet = os_packet_get_next_buflet(ph, NULL);
	assert(buflet != NULL);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	buf_len = os_buflet_get_data_length(buflet);
	ip = buf;

	switch (ip->ip_p) {
	case IPPROTO_TCP:
		ret = tcp_frame_process(ph, data, data_max);
		break;
	case IPPROTO_UDP:
		ret = udp_frame_process(ph, data, data_max);
		break;
	default:
		ret = ip_frame_process(ph, data, data_max);
		break;
	}

	if (verify_qos) {
		struct qosmarking_mapping *table = NULL;
		int i;
		my_payload_t payload = data;
		char *svc_str = payload->data;
		size_t svc_str_len = data_max;
		packet_svc_class_t svc = os_packet_get_service_class(ph);
		int dscp = ip->ip_tos >> IPTOS_DSCP_SHIFT;
#define EXPECT(var, val)        \
	        if (var != val) {       \
	                T_LOG("expected "#var" %d got %d\n",  \
	                    val, var);  \
	                sktu_dump_buffer(stderr, "packet dump", buf, buf_len);  \
	                fflush(stderr); \
	                assert(0);      \
	        }

		if (strncmp(svc_str, XFER_QOSMARKING_FASTLANE_PREFIX,
		    strlen(XFER_QOSMARKING_FASTLANE_PREFIX)) == 0) {
			table = fastlane_mappings;
			svc_str += strlen(XFER_QOSMARKING_FASTLANE_PREFIX);
			svc_str_len -= strlen(XFER_QOSMARKING_FASTLANE_PREFIX);
		} else if (strncmp(svc_str, XFER_QOSMARKING_RFC4594_PREFIX,
		    strlen(XFER_QOSMARKING_RFC4594_PREFIX)) == 0) {
			table = rfc4594_mappings;
			svc_str += strlen(XFER_QOSMARKING_RFC4594_PREFIX);
			svc_str_len -= strlen(XFER_QOSMARKING_RFC4594_PREFIX);
		} else if (strncmp(svc_str, XFER_RECV_END_PAYLOAD,
		    strlen(XFER_RECV_END_PAYLOAD)) == 0) {
			return ret;
		} else {
			T_LOG("unkown qosmarking mode %s\n", svc_str);
			assert(0);
		}

		for (i = 0; i < QOSMARKING_SVC_MAX; i++) {
			if (strncmp(svc_str, table[i].svc_str, svc_str_len) == 0) {
				EXPECT(svc, table[i].svc);
				EXPECT(dscp, table[i].dscp);
				T_LOG("verified %s\n", svc_str);
				break;
			}
		}

		if (i == QOSMARKING_SVC_MAX) {
			T_LOG("unkown svc class %s\n", svc_str);
		}
	}

	return ret;
}

static void
channel_port_send(channel_port_t port, uuid_t flow_id,
    int protocol,
    uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port,
    my_payload_t payload, int payload_length,
    uint32_t limit, bool must_complete_batch,
    bool connect, packet_svc_class_t svc_class,
    bool csum_offload,
    void (^packet_prehook)(packet_t p))
{
	int                     error;
	channel_slot_t          last_slot = NULL;
	packet_id_t pktid = {OS_PACKET_PKTID_VERSION_CURRENT,
		             XFER_PKTID_PAYLOAD_TYPE, 0, 0, XFER_PKTID_STREAM_ID, 0};

	assert(payload->packet_number < limit);
	while (1) {
		int                     frame_length;
		slot_prop_t             prop;
		channel_slot_t          slot;
		packet_t                pkt = 0;
		void                    *buf;
		size_t                  buf_len;
		buflet_t                buflet;

		/* grab a slot and populate it */
		slot = os_channel_get_next_slot(port->tx_ring, last_slot,
		    &prop);
		if (slot == NULL) {
			if (must_complete_batch &&
			    payload->packet_number < limit) {
				/* couldn't complete batch */
				T_LOG(
					"TX didn't complete batch (%u < %u)\n",
					payload->packet_number, limit);
				assert(0);
			}
			break;
		}

		if (port->user_packet_pool) {
			assert(prop.sp_buf_ptr == 0);
			assert(prop.sp_len == 0);
			error = os_channel_packet_alloc(port->chan, &pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			assert(prop.sp_buf_ptr != 0);
			assert(prop.sp_len != 0);
			pkt = os_channel_slot_get_packet(port->tx_ring, slot);
		}
		assert(pkt != 0);
		buflet = os_packet_get_next_buflet(pkt, NULL);
		assert(buflet != NULL);
		buf = os_buflet_get_object_address(buflet) +
		    os_buflet_get_data_offset(buflet);
		assert(buf != NULL);
		buf_len = os_buflet_get_data_limit(buflet);
		assert(buf_len != 0);
		if (!port->user_packet_pool) {
			assert(buf == (void *)prop.sp_buf_ptr);
			assert(buf_len == prop.sp_len);
		}

		frame_length = frame_populate(port, pkt, protocol,
		    port->ip_addr, src_port, dst_ip, dst_port, (void *)payload,
		    payload_length, flow_id, connect, svc_class, csum_offload,
		    0, payload_length, 0, FALSE);

		pktid.pktid_sequence_number = payload->packet_number;
		pktid.pktid_timestamp = pktid.pktid_sequence_number;
		assert(os_packet_set_packetid(pkt, &pktid) == 0);

		if (packet_prehook != NULL) {
			packet_prehook(pkt);
		}

#if SKT_XFER_DEBUG
		T_LOG("\nPort %d transmitting %d bytes:\n",
		    port->port, frame_length);
		ip_frame_dump(buf, frame_length);
#endif
		assert(frame_length != 0);
		if (port->user_packet_pool) {
			error = os_channel_slot_attach_packet(port->tx_ring,
			    slot, pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			prop.sp_len = frame_length;
			os_channel_set_slot_properties(port->tx_ring, slot,
			    &prop);
		}
		last_slot = slot;
		payload->packet_number++;
		if (payload->packet_number >= limit) {
			break;
		}
	}
	if (last_slot != NULL) {
		error = os_channel_advance_slot(port->tx_ring, last_slot);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(port->chan, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}
}

static void
channel_port_send_fragments(channel_port_t port, uuid_t flow_id,
    int protocol, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port,
    my_payload_t payload, int payload_length,
    uint16_t fragment_count,
    packet_svc_class_t svc_class,
    bool csum_offload, bool error_ids)
{
	int error = 0;
	channel_slot_t last_slot = NULL;

	uint16_t fragment_id = ip_id++;

	for (int fragment_i = 0; fragment_i < fragment_count; fragment_i++) {
		int frame_length = 0;
		slot_prop_t prop;
		channel_slot_t slot = NULL;
		packet_t pkt = 0;
		void *buf = NULL;
		size_t buf_len = 0;
		buflet_t buflet = NULL;

		/* grab a slot and populate it */
		slot = os_channel_get_next_slot(port->tx_ring, last_slot,
		    &prop);
		if (slot == NULL) {
			if (fragment_i < fragment_count) {
				/* couldn't complete fragment */
				T_LOG(
					"TX didn't complete fragment (%u < %u)\n",
					fragment_i, fragment_count);
				assert(0);
			}
			break;
		}

		if (port->user_packet_pool) {
			assert(prop.sp_buf_ptr == 0);
			assert(prop.sp_len == 0);
			error = os_channel_packet_alloc(port->chan, &pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			assert(prop.sp_buf_ptr != 0);
			assert(prop.sp_len != 0);
			pkt = os_channel_slot_get_packet(port->tx_ring, slot);
		}
		assert(pkt != 0);
		buflet = os_packet_get_next_buflet(pkt, NULL);
		assert(buflet != NULL);
		buf = os_buflet_get_object_address(buflet) +
		    os_buflet_get_data_offset(buflet);
		assert(buf != NULL);
		buf_len = os_buflet_get_data_limit(buflet);
		assert(buf_len != 0);
		if (!port->user_packet_pool) {
			assert(buf == (void *)prop.sp_buf_ptr);
			assert(buf_len == prop.sp_len);
		}

		if (fragment_i == 0) {
			frame_length = frame_populate(port, pkt, protocol,
			    port->ip_addr, src_port, dst_ip, dst_port,
			    (void *)payload, payload_length, flow_id, FALSE,
			    svc_class, csum_offload, fragment_id,
			    fragment_count * payload_length, 0, FALSE);
		} else {
			frame_length = frame_populate(port, pkt, protocol,
			    port->ip_addr, src_port, dst_ip, dst_port,
			    (void *)payload, payload_length, flow_id, FALSE,
			    svc_class, csum_offload,
			    fragment_id, fragment_count * payload_length,
			    fragment_i * payload_length + sizeof(struct udphdr),
			    fragment_i == (fragment_count - 1));
		}

#if SKT_XFER_DEBUG
		T_LOG("\nPort %d transmitting %d bytes:\n",
		    port->port, frame_length);
		ip_frame_dump(buf, frame_length);
#endif
		assert(frame_length != 0);
		if (port->user_packet_pool) {
			error = os_channel_slot_attach_packet(port->tx_ring,
			    slot, pkt);
			SKTC_ASSERT_ERR(error == 0);
		} else {
			prop.sp_len = frame_length;
			os_channel_set_slot_properties(port->tx_ring, slot,
			    &prop);
		}
		last_slot = slot;

		if (error_ids) {
			fragment_id = ip_id++;
		}
	}
	if (last_slot != NULL) {
		error = os_channel_advance_slot(port->tx_ring, last_slot);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(port->chan, CHANNEL_SYNC_TX);
		SKTC_ASSERT_ERR(error == 0);
	}
}

static int
channel_port_receive_payload(channel_port_t port, my_payload_t payload,
    bool verify_qos)
{
	int error;
	slot_prop_t prop;
	channel_slot_t slot;
	packet_t pkt;
	void *buf;
	size_t frame_length;
	buflet_t buflet;

	slot = os_channel_get_next_slot(port->rx_ring, NULL, &prop);
	if (slot == NULL) {
		return ENOENT;
	}
	assert(prop.sp_buf_ptr != 0);

	pkt = os_channel_slot_get_packet(port->rx_ring, slot);
	assert(pkt != 0);
	if (port->user_packet_pool) {
		error = os_channel_slot_detach_packet(port->rx_ring,
		    slot, pkt);
		SKTC_ASSERT_ERR(error == 0);
	}

	buflet = os_packet_get_next_buflet(pkt, NULL);
	assert(buflet != NULL);
	buf = os_buflet_get_object_address(buflet) +
	    os_buflet_get_data_offset(buflet);
	frame_length = os_packet_get_data_length(pkt);

	(void) frame_process(pkt, payload, frame_length, verify_qos);

#if SKT_XFER_DEBUG
	T_LOG("\nPort %d received %lu bytes:\n",
	    port->port, frame_length);

	ip_frame_dump(buf, frame_length);
#endif
	if (port->user_packet_pool) {
		error = os_channel_packet_free(port->chan, pkt);
		SKTC_ASSERT_ERR(error == 0);
	}

	error = os_channel_advance_slot(port->rx_ring, slot);
	SKTC_ASSERT_ERR(error == 0);
	error = os_channel_sync(port->chan, CHANNEL_SYNC_RX);
	SKTC_ASSERT_ERR(error == 0);

	return 0;
}

static void
channel_port_receive(int child, channel_port_t port, uint16_t our_port,
    struct in_addr peer_ip,
    uint32_t limit,
    uint32_t * receive_count,
    uint32_t * receive_index,
    bool errors_ok,
    uint32_t * pkts_dropped)
{
	int                     error;
	channel_slot_t          last_slot = NULL;

	assert(*receive_index < limit);

	*pkts_dropped = 0;

	while (1) {
		int                     frame_length;
		ip_udp_header_t *       ip_udp;
		my_payload              payload;
		slot_prop_t             prop;
		channel_slot_t          slot;
		packet_t                pkt;
		char                    *buf;
		uint16_t                pkt_len;
		uint32_t                                bdoff;
		buflet_t                buflet;
		uint8_t                 aggr_type;
		uint32_t                buflet_cnt;

		slot = os_channel_get_next_slot(port->rx_ring, last_slot,
		    &prop);
		if (slot == NULL) {
			break;
		}
		assert(prop.sp_buf_ptr != 0);

		pkt = os_channel_slot_get_packet(port->rx_ring, slot);
		assert(pkt != 0);
		if (port->user_packet_pool) {
			error = os_channel_slot_detach_packet(port->rx_ring,
			    slot, pkt);
			SKTC_ASSERT_ERR(error == 0);
		}
		buflet = os_packet_get_next_buflet(pkt, NULL);
		assert(buflet != NULL);
		bdoff = os_buflet_get_data_offset(buflet);
		buf = os_buflet_get_object_address(buflet) + bdoff;
		pkt_len = os_packet_get_data_length(pkt);
		assert(buf == (void *)prop.sp_buf_ptr);
		assert(pkt_len == prop.sp_len);

		frame_length = sizeof(*ip_udp) + sizeof(my_payload);
		assert(os_packet_get_link_header_length(pkt) == 0);

		buflet_cnt = os_packet_get_buflet_count(pkt);
		aggr_type = os_packet_get_aggregation_type(pkt);
		assert((aggr_type == PKT_AGGR_NONE) || (buflet_cnt > 1));

		(void) frame_process(pkt, &payload, pkt_len, FALSE);

#if SKT_XFER_DEBUG
		T_LOG("\nPort %d received %d bytes:\n",
		    port->port, frame_length);

		ip_frame_dump(buf, frame_length);
#endif
		last_slot = slot;
		if (*receive_index != payload.packet_number) {
			if (!errors_ok) {
				assert(payload.packet_number > *receive_index);
			}
			uint32_t        dropped;

			dropped = payload.packet_number - *receive_index;
			*pkts_dropped += dropped;
#if SKT_XFER_DEBUG
			T_LOG(
				"child %d dropped %u (received #%u, expected #%u)\n",
				child, dropped, payload.packet_number,
				*receive_index);
#endif
			*receive_index = payload.packet_number;
		}

		if (port->user_packet_pool) {
			error = os_channel_packet_free(port->chan, pkt);
			SKTC_ASSERT_ERR(error == 0);
		}
		(*receive_count)++;
		(*receive_index)++;
		if (*receive_index == limit) {
			break;
		}
	}
	if (last_slot != NULL) {
		error = os_channel_advance_slot(port->rx_ring, last_slot);
		SKTC_ASSERT_ERR(error == 0);
		error = os_channel_sync(port->chan, CHANNEL_SYNC_RX);
		SKTC_ASSERT_ERR(error == 0);
	}
}

static void
channel_port_receive_all(channel_port_t port, uuid_t flow_id,
    uint16_t src_port, struct in_addr dst_ip, uint16_t dst_port,
    int16_t should_receive_count, bool verify_qos)
{
	int error;
	struct kevent evlist, kev;
	int kq;
	uint16_t received_count = 0;

	kq = kqueue();
	assert(kq != -1);

	EV_SET(&kev, port->fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);
	struct timespec timeout;
	timeout.tv_sec = 10;
	timeout.tv_nsec = 0;

	for (;;) {
		/* wait for RX to become available */
		error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
		if (error <= 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/* time out */
			T_LOG(
				"Error, timeout for final right packet\n");
			assert(0);
		}
		if (evlist.flags & EV_ERROR) {
			int err = evlist.data;

			if (err == EAGAIN) {
				break;
			}
			SKTC_ASSERT_ERR(err == 0);
		}

		if (evlist.filter == EVFILT_READ) {
			my_payload payload;
			channel_port_receive_payload(port, &payload, verify_qos);
			/* packet signaling end of test */
			if (strcmp(payload.data, XFER_RECV_END_PAYLOAD) == 0) {
				if (should_receive_count >= 0 &&
				    received_count != should_receive_count) {
					T_LOG(
						"Error, only received %d/%d\n",
						received_count,
						should_receive_count);
					assert(0);
				}
				T_LOG("received EOF packet\n");
				break;
			}
			received_count++;
			T_LOG("Received [%d/%d] %s\n",
			    received_count, should_receive_count, payload.data);
			if (should_receive_count >= 0 &&
			    received_count > should_receive_count) {
				T_LOG("Error, rx wrong packet\n");
				assert(0);
			}
		} else {
			T_LOG("%lu event %d?\n", evlist.ident,
			    evlist.filter);
			assert(0);
			break;
		}
	}

	T_LOG("child exit\n");
	fflush(stderr);

	close(kq);
}

static void
send_and_receive(channel_port_t port, uuid_t flow_id, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port, uint32_t how_many,
    uint32_t batch_size, int child, bool wrong_flow_id, bool errors_ok,
    uint32_t event_flags, bool ifadv_enabled)
{
	int             n_events, error;
#define N_EVENTS_MAX    3
	struct kevent   evlist[N_EVENTS_MAX];
	struct kevent   kev[N_EVENTS_MAX];
	int             kq;
	my_payload      payload;
	double          percent;
	uint32_t        receive_packet_count;
	uint32_t        receive_packet_index;
	bool       rx_complete;
	struct timespec timeout;
	bool       tx_complete;
	uint32_t        pkts_dropped;
	uint32_t        n_ifadv_events = 0, n_chan_events = 0;

	T_LOG("Sending to %s:%d\n", inet_ntoa(dst_ip), dst_port);
	bzero(&payload, sizeof(payload));
	kq = kqueue();
	assert(kq != -1);
	rx_complete = tx_complete = FALSE;
	receive_packet_count = 0;
	receive_packet_index = 0;
	EV_SET(kev + 0, port->fd, EVFILT_WRITE,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	EV_SET(kev + 1, port->fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	n_events = 2;
	if ((event_flags & SKT_FSW_EVFLAG_IFADV) != 0) {
		assert(n_events < N_EVENTS_MAX);
		EV_SET(kev + n_events, port->fd, EVFILT_NW_CHANNEL,
		    EV_ADD | EV_ENABLE, NOTE_IF_ADV_UPD, 0, NULL);
		n_events++;
	}
	if ((event_flags & SKT_FSW_EVFLAG_CHANNEL) != 0) {
		assert(n_events < N_EVENTS_MAX);
		EV_SET(kev + n_events, port->fd, EVFILT_NW_CHANNEL,
		    EV_ADD | EV_ENABLE, NOTE_CHANNEL_EVENT, 0, NULL);
		n_events++;
	}
	error = kevent(kq, kev, n_events, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);
	timeout.tv_sec = XFER_TXRX_TIMEOUT_SECS;
	timeout.tv_nsec = XFER_TXRX_TIMEOUT_NSECS;
	while (!rx_complete || !tx_complete) {
		/* wait for TX/RX to become available */
		error = kevent(kq, NULL, 0, evlist, N_EVENTS_MAX, &timeout);
		if (error <= 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/* missed seeing last few packets */
			if (!errors_ok) {
				T_LOG("child %d: timed out, TX %s "
				    "RX %s\n", child,
				    tx_complete ? "complete" :"incomplete",
				    rx_complete ? "complete" :"incomplete");
			}
			break;
		}
		for (int i = 0; i < error; i++) {
			if (evlist[i].flags & EV_ERROR) {
				int     err = evlist[i].data;

				if (err == EAGAIN) {
					break;
				}
				SKTC_ASSERT_ERR(err == 0);
			}

			switch (evlist[i].filter) {
			case EVFILT_NW_CHANNEL: {
				if ((evlist[i].fflags & NOTE_IF_ADV_UPD) != 0) {
					skt_process_if_adv(port->port, port->chan);
					n_ifadv_events++;
				}
				if ((evlist[i].fflags & NOTE_CHANNEL_EVENT) != 0) {
					skt_process_channel_event(port->chan,
					    XFER_PKTID_PAYLOAD_TYPE, XFER_PKTID_STREAM_ID,
					    ^(const os_channel_event_packet_transmit_status_t *pkt_ev) {
							assert(pkt_ev->packet_status ==
							CHANNEL_EVENT_PKT_TRANSMIT_STATUS_ERR_RETRY_FAILED);
						}, NULL, NULL);
					n_chan_events++;
				}
				break;
			}
			case EVFILT_WRITE: {
				uint32_t        next_batch;

				next_batch = payload.packet_number
				    + batch_size;
				if (next_batch > how_many) {
					next_batch = how_many;
				}
				channel_port_send(port, flow_id,
				    IPPROTO_UDP,
				    src_port,
				    dst_ip, dst_port,
				    &payload, sizeof(payload),
				    next_batch, FALSE, FALSE,
				    PKT_SC_BE, TRUE, NULL);
				if (payload.packet_number >= how_many) {
					assert(payload.packet_number
					    == how_many);
					T_LOG(
						"TX child %d: completed %u\n",
						child, how_many);
					tx_complete = TRUE;
#if SKT_XFER_DEBUG
					T_LOG(
						"child %d: disable TX\n",
						child);
#endif
					EV_SET(kev,
					    port->fd, EVFILT_WRITE,
					    EV_DELETE, 0, 0, NULL);
					error = kevent(kq, kev, 1,
					    NULL, 0, NULL);
					SKTC_ASSERT_ERR(error == 0);
				}
				break;
			}
			case EVFILT_READ: {
				channel_port_receive(child, port, src_port, dst_ip,
				    how_many,
				    &receive_packet_count,
				    &receive_packet_index,
				    errors_ok, &pkts_dropped);
				if (receive_packet_index >= how_many) {
					assert(receive_packet_index
					    == how_many);
#if SKT_XFER_DEBUG
					T_LOG(
						"child %d: disable RX\n",
						child);
#endif
					EV_SET(kev, port->fd, EVFILT_READ,
					    EV_DELETE, 0, 0, NULL);
					error = kevent(kq, kev, 1,
					    NULL, 0, NULL);
					SKTC_ASSERT_ERR(error == 0);
					rx_complete = TRUE;
				}
				break;
			}
			default:
				T_LOG("%lu event %d?\n",
				    evlist[i].ident,
				    evlist[i].filter);
				assert(0);
				break;
			}
		}
	}
	percent = 1.0 * receive_packet_count / how_many * 100.0;
	T_LOG("RX child %d: received %u (of %u) %1.02f%%\n",
	    child, receive_packet_count, how_many, percent);
	T_LOG("child %d: received %u ifadv events\n",
	    child, n_ifadv_events);

	if (!errors_ok) {
		if (wrong_flow_id) {
			assert(receive_packet_count == 0);
		} else {
			assert(receive_packet_count > 0);
		}
	}
	if ((event_flags & SKT_FSW_EVFLAG_IFADV) != 0) {
		if (ifadv_enabled) {
			assert(n_ifadv_events != 0);
		} else {
			assert(n_ifadv_events == 0);
		}
	}
	if ((event_flags & SKT_FSW_EVFLAG_CHANNEL) != 0) {
		assert(n_chan_events != 0);
	}
	close(kq);
}

static void
ping_pong(channel_port_t port, uuid_t flow_id, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port, uint32_t how_many,
    uint32_t batch_size, int child, bool wrong_flow_id,
    flowadv_idx_t flowadv_idx, bool test_aqm, bool test_wmm,
    uint16_t demux_offset)
{
	int             error;
#define N_EVENTS        2
	struct kevent   evlist[N_EVENTS];
	bool            expect_flowadv = FALSE;
	bool            expect_stall = FALSE;
	struct timespec fadv_timeout;
	struct kevent   kev[N_EVENTS];
	int             kq;
	my_payload      payload;
	double          percent;
	uint32_t        next_receive_count;
	uint32_t        receive_packet_count;
	uint32_t        receive_packet_index;
	struct timespec rcv_timeout;
	bool            rx_complete;
	bool            sending;
	struct timespec snd_timeout;
	int             snd_batch_cnt = 0;
	struct timespec *timeout;
	bool            tx_complete;
	packet_svc_class_t      svc_class = PKT_SC_BE;
	uint32_t        pkts_dropped;

	if (test_aqm) {
		assert(how_many / batch_size == 4);
	}
	T_LOG("Sending to %s:%d\n", inet_ntoa(dst_ip), dst_port);
	bzero(&payload, sizeof(payload));
	kq = kqueue();
	assert(kq != -1);
	rx_complete = tx_complete = FALSE;
	receive_packet_count = 0;
	receive_packet_index = 0;
	next_receive_count = batch_size;

	snd_timeout.tv_sec = XFER_PING_TIMEOUT_SECS;
	snd_timeout.tv_nsec = XFER_PING_TIMEOUT_NSECS;
	fadv_timeout.tv_sec = XFER_PING_FADV_TIMEOUT_SECS;
	fadv_timeout.tv_nsec = XFER_PING_FADV_TIMEOUT_NSECS;

	if (test_aqm && child == 1) {
		/*
		 * child-1 will not receive packets on time when
		 * child-0's send interface is throttled, hence it
		 * requires a larger timeout.
		 */
		rcv_timeout.tv_sec = XFER_PING_CHILD1_RX_TIMEOUT_SECS;
		rcv_timeout.tv_nsec = XFER_PING_CHILD1_RX_TIMEOUT_NSECS;
	} else {
		rcv_timeout.tv_sec = XFER_PING_TIMEOUT_SECS;
		rcv_timeout.tv_nsec = XFER_PING_TIMEOUT_NSECS;
	}

	if (test_aqm) {
		/*
		 * flow advisory filter always reports an initial event,
		 * check for that.
		 */
		EV_SET(kev + 0, port->fd, EVFILT_NW_CHANNEL, EV_ADD,
		    NOTE_FLOW_ADV_UPDATE, 0, NULL);
		error = kevent(kq, kev, 1, NULL, 0, NULL);
		SKTC_ASSERT_ERR(error == 0);
		timeout = &fadv_timeout;
		error = kevent(kq, NULL, 0, evlist, N_EVENTS, timeout);
		SKTC_ASSERT_ERR(error == 1);
	}

	if (demux_offset <= MAX_DEMUX_OFFSET) {
		payload.data[demux_offset] = DEMUX_PAYLOAD_VALUE;
		payload.data[demux_offset + 1] = DEMUX_PAYLOAD_VALUE >> 8;
	}

	if (child == 0) {
		sending = TRUE;
		EV_SET(kev, port->fd, EVFILT_WRITE,
		    EV_ADD | EV_ENABLE, 0, 0, NULL);
	} else {
		sending = FALSE;
		EV_SET(kev, port->fd, EVFILT_READ,
		    EV_ADD | EV_ENABLE, 0, 0, NULL);
	}
	error = kevent(kq, kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	while (!rx_complete || !tx_complete) {
		if (expect_flowadv) {
			timeout = &fadv_timeout;
		} else if (sending) {
			timeout = &snd_timeout;
		} else {
			timeout = &rcv_timeout;
		}

		/* wait for something to happen */
		error = kevent(kq, NULL, 0, evlist, N_EVENTS, timeout);
		if (error <= 0) {
			int     err = errno;

			if (err == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			T_LOG(
				"child %d: timed out TX %s RX %s FA %s\n",
				child,
				tx_complete ? "complete" : "incomplete",
				rx_complete ? "complete" : "incomplete",
				expect_flowadv ? "incomplete" : "complete");
			/*
			 * Test should fail if it times out while expecting a
			 * channel flow advisory event.
			 */
			assert(!expect_flowadv);
			break;
		}
		if (error != 1) {
			T_LOG("child %d: got %d events, expected 1\n",
			    child, error);
			assert(0);
		} else if (evlist[0].flags & EV_ERROR) {
			int     err = evlist[0].data;

			if (err == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(err == 0);
		}

		/* check that the correct event fired */
		if (expect_flowadv) {
			int n_kev = 0;
			assert(child == 0);
			assert(evlist[0].filter == EVFILT_NW_CHANNEL);
			assert(evlist[0].fflags & NOTE_FLOW_ADV_UPDATE);
			error = os_channel_flow_admissible(port->tx_ring,
			    flow_id, flowadv_idx);
			if (expect_stall) {
				/*
				 * when flow control is enabled
				 * os_channel_flow_admissible() should return
				 * ENOBUFS.
				 */
				SKTC_ASSERT_ERR(error == ENOBUFS);
				/*
				 * Now, enable dequeuing on the interface.
				 * This will allow the buffered 2nd batch of
				 * packets to be sent out the interface as
				 * well as trigger a flow advisory event
				 * to resume send on the channel.
				 */
				T_LOG("child %d, enable dequeue "
				    "on feth0\n", child);
				error =
				    sktc_ifnet_feth0_set_dequeue_stall(FALSE);
				SKTC_ASSERT_ERR(error == 0);
				expect_stall = FALSE;
				expect_flowadv = TRUE;
#if SKT_XFER_DEBUG
				T_LOG("child %d: enable FA "
				    "no stall\n", child);
#endif
			} else {
				/* flow must be admissible on the channel */
				SKTC_ASSERT_ERR(error == 0);
#if SKT_XFER_DEBUG
				T_LOG("child %d: Disable FA\n",
				    child);
#endif
				/*
				 * Flow control tested so remove flow advisory
				 * filter.
				 */
				EV_SET(kev + 0, port->fd, EVFILT_NW_CHANNEL,
				    EV_DELETE, 0, 0, NULL);
				expect_flowadv = FALSE;
				n_kev = 1;

				/*
				 * Now enabling receiving acks for the 2nd batch
				 * of packets.
				 */
				assert(!rx_complete);
				/* enable RX */
				EV_SET(kev + n_kev, port->fd, EVFILT_READ,
				    EV_ADD, 0, 0, NULL);
				n_kev++;
#if SKT_XFER_DEBUG
				T_LOG("child %d: enable RX\n", child);
#endif
				/*
				 * child 0 should now expect acks for the 2nd
				 * batch of packets.
				 */
				sending = FALSE;
				timeout = &rcv_timeout;
			}
			assert(n_kev <= N_EVENTS);
			if (n_kev > 0) {
				error = kevent(kq, kev, n_kev, NULL, 0, NULL);
				SKTC_ASSERT_ERR(error == 0);
			}
			continue;
		} else {
			/*
			 * verify that flow advisory event is reported
			 * only when expected.
			 */
			assert(evlist[0].filter != EVFILT_NW_CHANNEL);
		}

		if (sending) {
			uint32_t        next_batch;
			int             n_kev = 0;
			bool       skip_receive = FALSE;

			assert(evlist[0].filter == EVFILT_WRITE);
			if (test_wmm) {
				svc_class = packet_svc_class[(snd_batch_cnt %
				    NUM_SVC_CLASS)];
			}
			snd_batch_cnt++;
			next_batch = payload.packet_number + batch_size;
			if (next_batch > how_many) {
				next_batch = how_many;
			}

			if (test_aqm && child == 0 && snd_batch_cnt == 2) {
				/*
				 * disable dequeue on feth0 before sending the
				 * 2nd batch of packets.
				 * These UDP packet will now get buffered at the
				 * interface AQM.
				 */
				T_LOG("child %d, disable dequeue on"
				    " feth0\n", child);
				error =
				    sktc_ifnet_feth0_set_dequeue_stall(TRUE);
				SKTC_ASSERT_ERR(error == 0);
			}

			if (test_aqm && child == 0 && snd_batch_cnt == 3) {
				/*
				 * wait for interface update interval to elapse
				 * before sending the 3rd batch of packets.
				 * These UDP packets wil be dropped by AQM.
				 */
				T_LOG("child %d, sleep for update"
				    " interval (%d ms)\n", child,
				    XFER_CLASSQ_UPDATE_INTERVAL_ELAPSE_DELAY);
				usleep(
					XFER_CLASSQ_UPDATE_INTERVAL_ELAPSE_DELAY *
					1000);
			}

			/* Flow should be writable */
			if (!wrong_flow_id) {
				error =
				    os_channel_flow_admissible(port->tx_ring,
				    flow_id, flowadv_idx);
				SKTC_ASSERT_ERR(error == 0);
			}

			channel_port_send(port, flow_id, IPPROTO_UDP,
			    src_port, dst_ip, dst_port, &payload,
			    sizeof(payload), next_batch, TRUE, FALSE,
			    svc_class, TRUE, NULL);
#if SKT_XFER_DEBUG
			T_LOG(
				"TX child %d: %s %u of %u\n", child,
				(child == 0) ? "ping" : "pong",
				next_batch, how_many);
#endif
			if (payload.packet_number >= how_many) {
				assert(payload.packet_number
				    == how_many);
				T_LOG(
					"TX child %d: completed %u\n",
					child,
					how_many);
				tx_complete = TRUE;
			}

			if (test_aqm && child == 0 && snd_batch_cnt == 2) {
				/* 2nd batch of packets are not going to reach
				 * the receiver at child 1 until dequeuing is
				 * re-enabled on feth0.
				 * Skip receiving and send the 3rd batch of
				 * packets.
				 */
				continue;
			}

			if (test_aqm && child == 0 && snd_batch_cnt == 3) {
				/*
				 * sending the 3rd batch of packets should have
				 * triggered flow advisory event on the channel.
				 * The flow should not be admissible now.
				 */
				expect_flowadv = TRUE;
				expect_stall = TRUE;
				timeout = &fadv_timeout;
#if SKT_XFER_DEBUG
				T_LOG("child %d: expect stall\n",
				    child);
#endif
				/*
				 * packets will not reach receiver at child 1,
				 * until dequeuing on feth0 is re-enabled,
				 * so skip receiving.
				 */
				skip_receive = TRUE;
			}
#if SKT_XFER_DEBUG
			T_LOG("child %d disable TX\n", child);
#endif
			EV_SET(kev + n_kev, port->fd, EVFILT_WRITE, EV_DELETE,
			    0, 0, NULL);
			n_kev++;

			if (!skip_receive && !rx_complete) {
				/* enable RX */
				assert(n_kev == 1);
				EV_SET(kev + n_kev, port->fd, EVFILT_READ,
				    EV_ADD, 0, 0, NULL);
				n_kev++;
#if SKT_XFER_DEBUG
				T_LOG("child %d: enable RX\n", child);
#endif
			}
			assert(n_kev <= N_EVENTS);
			if (n_kev > 0) {
				error = kevent(kq, kev, n_kev, NULL, 0, NULL);
				SKTC_ASSERT_ERR(error == 0);
			}
			sending = FALSE;
		} else {
			assert(evlist[0].filter == EVFILT_READ);
			pkts_dropped = 0;
			channel_port_receive(child, port, src_port, dst_ip,
			    how_many,
			    &receive_packet_count,
			    &receive_packet_index,
			    false, &pkts_dropped);

			if (pkts_dropped != 0) {
				/*
				 * ping-pong test shouldn't have any packet
				 * drop, unless intentional during AQM test.
				 */
				assert(test_aqm);
				assert(pkts_dropped ==
				    XFER_AQM_PING_BATCH_COUNT);
			}
			if (receive_packet_index >= how_many) {
				assert(receive_packet_index == how_many);
				rx_complete = TRUE;
			}
			if (rx_complete ||
			    receive_packet_index >= next_receive_count) {
				int     n_kev;
#if SKT_XFER_DEBUG
				T_LOG(
					"child %d: disable RX\n", child);
#endif
				EV_SET(kev, port->fd, EVFILT_READ, EV_DELETE,
				    0, 0, NULL);
				n_kev = 1;
				next_receive_count = receive_packet_index +
				    batch_size;
				if (next_receive_count >= how_many) {
					next_receive_count = how_many;
				}
				if (!tx_complete) {
					/* re-enable TX */
					EV_SET(kev + n_kev,
					    port->fd, EVFILT_WRITE,
					    EV_ADD, 0, 0, NULL);
#if SKT_XFER_DEBUG
					T_LOG(
						"child %d: enable TX\n", child);
#endif
					n_kev++;
					sending = TRUE;
					if (child == 1) {
						payload.packet_number +=
						    pkts_dropped;
					}
				} else if (!rx_complete) {
					assert(tx_complete);
					/*
					 * If Tx is completed and there are
					 * packets expected to be received
					 * re-enable Rx.
					 */
#if SKT_XFER_DEBUG
					T_LOG(
						"child %d: enable RX\n", child);
#endif
					n_kev = 0;
				}
				if (n_kev) {
					error = kevent(kq, kev, n_kev, NULL, 0, NULL);
					SKTC_ASSERT_ERR(error == 0);
				}
			}
		}
	}
	percent = 1.0 * receive_packet_count / how_many * 100.0;
	T_LOG("RX child %d: received %u (of %u) %1.02f%%\n",
	    child, receive_packet_count, how_many, percent);
	/* wait to give the packet(s) a chance to make it to the other end */
	usleep(100 * 1000);
	if (test_aqm) {
		/*
		 * while testing AQM functionaliy we should have dropped
		 * one batch of packets out of the 4 batches
		 */
		assert(receive_packet_count == ((how_many * 3) / 4));
	} else if (wrong_flow_id) {
		assert(receive_packet_count == 0);
	} else {
		assert(receive_packet_count == how_many);
	}
#if SKT_XFER_DEBUG
	if (receive_packet_count < how_many) {
		T_LOG("Child %d waiting", child);
		fflush(stdout);
		for (int i = 0; i < 5; i++) {
			sleep(1);
			T_LOG(".");
			fflush(stdout);
		}
		T_LOG("\n");
		assert(0);
	}
#endif
	close(kq);
}

static void
send_tcp(channel_port_t port, uuid_t flow_id, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port, uint32_t how_many,
    uint32_t batch_size, int child, bool connect)
{
	int             error;
	struct kevent   ev;
	struct kevent   kev;
	int             kq;
	my_payload      payload;
	struct timespec timeout;
	bool       tx_complete;

	T_LOG("Sending to %s:%d\n", inet_ntoa(dst_ip), dst_port);
	bzero(&payload, sizeof(payload));
	kq = kqueue();
	assert(kq != -1);
	tx_complete = FALSE;

	EV_SET(&kev, port->fd, EVFILT_WRITE,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);
	timeout.tv_sec = 1;
	timeout.tv_nsec = 0;
	while (!tx_complete) {
		/* wait for TX to become available */
		error = kevent(kq, NULL, 0, &ev, 1, &timeout);
		if (error <= 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/* missed seeing last few packets */
			T_LOG("child %d timed out, TX %s\n",
			    child,
			    tx_complete ? "complete" : "incomplete");
			break;
		}
		if (ev.flags & EV_ERROR) {
			int     err = ev.data;

			if (err == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(err == 0);
		}
		switch (ev.filter) {
		case EVFILT_WRITE: {
			uint32_t        next_batch;

			next_batch = payload.packet_number
			    + batch_size;
			if (next_batch > how_many) {
				next_batch = how_many;
			}
			channel_port_send(port, flow_id,
			    IPPROTO_TCP,
			    src_port,
			    dst_ip, dst_port,
			    &payload, sizeof(payload),
			    next_batch, FALSE, connect,
			    PKT_SC_BE, TRUE, NULL);
			if (payload.packet_number >= how_many) {
				assert(payload.packet_number
				    == how_many);
				T_LOG(
					"TX child %d: completed %u\n",
					child, how_many);
				tx_complete = TRUE;
#if SKT_XFER_DEBUG
				T_LOG(
					"child %d: disable TX\n",
					child);
#endif
				EV_SET(&kev,
				    port->fd, EVFILT_WRITE,
				    EV_DELETE, 0, 0, NULL);
				error = kevent(kq, &kev, 1,
				    NULL, 0, NULL);
				SKTC_ASSERT_ERR(error == 0);
			}
			break;
		}
		default:
			T_LOG("%lu event %d?\n",
			    ev.ident,
			    ev.filter);
			assert(0);
			break;
		}
	}
	close(kq);
}

static uint64_t
set_error_inject_mask(uint64_t *mask)
{
	uint64_t old_mask = 0;
	size_t old_size = sizeof(old_mask);
	int error;

	error =
	    sysctlbyname("kern.skywalk.flowswitch.fsw_inject_error",
	    &old_mask, &old_size, mask, mask ? sizeof(*mask) : 0);

	if ((error != 0) && skywalk_in_driver) {
		T_LOG("sysctlbyname failed for fsw_inject_error "
		    "error %d\n", error);
	} else {
		SKTC_ASSERT_ERR(error == 0);
	}
	return old_mask;
}

static void
do_error_receive(int child, channel_port_t port, uuid_t flow_id, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port, uint32_t how_many)
{
	int             error;
	struct kevent   evlist, kev;
	int             kq;
	my_payload      payload;
	uint32_t        receive_packet_count;
	uint32_t        receive_packet_index;
	struct timespec timeout;
	uint32_t        pkts_dropped;

	bzero(&payload, sizeof(payload));
	kq = kqueue();
	assert(kq != -1);
	receive_packet_count = 0;
	receive_packet_index = 0;

	EV_SET(&kev, port->fd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);

	for (;;) {
		/* wait for RX to become available */
		timeout.tv_sec = 1;
		timeout.tv_nsec = 0;
		error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
		if (error <= 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/*
			 * Timed out. Check if test is complete
			 * Mask will be zero when parent is finished
			 */
			if (set_error_inject_mask(NULL) == 0) {
				break;
			}

			/* Otherwise continue receiving */
			receive_packet_count = 0;
			receive_packet_index = 0;
			continue;
		}
		if (evlist.flags & EV_ERROR) {
			int     err = evlist.data;

			if (err == EAGAIN) {
				break;
			}
			SKTC_ASSERT_ERR(err == 0);
		}

		if (evlist.filter == EVFILT_READ) {
			channel_port_receive(child, port, src_port, dst_ip,
			    how_many,
			    &receive_packet_count,
			    &receive_packet_index,
			    true, &pkts_dropped);
		} else {
			T_LOG("%lu event %d?\n",
			    evlist.ident, evlist.filter);
			assert(0);
			break;
		}
	}

	close(kq);
}

static void
do_error_send(channel_port_t port, uuid_t flow_id, uint16_t src_port,
    struct in_addr dst_ip, uint16_t dst_port, uint32_t how_many,
    uint32_t batch_size)
{
	int             error;
	struct kevent   evlist;
	struct kevent   kev;
	int             kq;
	my_payload      payload;
	uint32_t        receive_packet_count;
	uint32_t        receive_packet_index;
	bool       tx_complete;
	struct timespec timeout;

	bzero(&payload, sizeof(payload));
	kq = kqueue();
	assert(kq != -1);
	receive_packet_count = 0;
	receive_packet_index = 0;
	EV_SET(&kev, port->fd, EVFILT_WRITE,
	    EV_ADD | EV_ENABLE, 0, 0, NULL);
	error = kevent(kq, &kev, 1, NULL, 0, NULL);
	SKTC_ASSERT_ERR(error == 0);
	tx_complete = false;

	while (!tx_complete) {
		/* wait for TX to become available */
		timeout.tv_sec = 5;
		timeout.tv_nsec = 0;
		error = kevent(kq, NULL, 0, &evlist, 1, &timeout);
		if (error < 0) {
			if (errno == EAGAIN) {
				continue;
			}
			SKTC_ASSERT_ERR(error == 0);
		}
		if (error == 0) {
			/* Timeout. Not supposed to happen. */
			break;
		}

		if (evlist.flags & EV_ERROR) {
			int     err = evlist.data;

			if (err == EAGAIN) {
				break;
			}
			SKTC_ASSERT_ERR(err == 0);
		}

		if (evlist.filter == EVFILT_WRITE) {
			uint32_t        next_batch;

			next_batch = payload.packet_number + batch_size;
			if (next_batch > how_many) {
				next_batch = how_many;
			}
			channel_port_send(port, flow_id, IPPROTO_UDP, src_port,
			    dst_ip, dst_port, &payload, sizeof(payload),
			    next_batch, FALSE, FALSE, PKT_SC_BE, TRUE, NULL);
			if (payload.packet_number >= how_many) {
				assert(payload.packet_number
				    == how_many);
				tx_complete = true;
#if SKT_XFER_DEBUG
				T_LOG("disable TX\n");
#endif
				EV_SET(&kev,
				    port->fd, EVFILT_WRITE,
				    EV_DELETE, 0, 0, NULL);
				error = kevent(kq, &kev, 1,
				    NULL, 0, NULL);
				SKTC_ASSERT_ERR(error == 0);
			}
		} else {
			T_LOG("%lu event %d?\n",
			    evlist.ident, evlist.filter);
			assert(0);
			break;
		}
	}
	close(kq);
}

#define MAX_LLINKS 256
static void
get_qset_id_from_llinks(struct sktc_nexus_handles *handles, uint64_t *qset_id)
{
	struct nx_llink_info_req *nlir;
	size_t len;
	uint64_t qset_select;
	int err, i, llink_idx, qset_idx;

	len = sizeof(*nlir) + MAX_LLINKS * sizeof(struct nx_llink_info);
	nlir = malloc(len);
	nlir->nlir_version = NETIF_LLINK_INFO_VERSION;
	nlir->nlir_llink_cnt = MAX_LLINKS;

	err = __os_nexus_get_llink_info(handles->controller,
	    handles->netif_nx_uuid, nlir, len);
	if (err != 0) {
		T_LOG("__os_nexus_llink_info failed: %d\n", err);
		free(nlir);
		return;
	}
	qset_select = mach_absolute_time();
	T_LOG("\nqset_select: 0x%llx\n", qset_select);
	T_LOG("llink_cnt: %d\n", nlir->nlir_llink_cnt);
	for (i = 0; i < nlir->nlir_llink_cnt; i++) {
		struct nx_llink_info *nli;
		int j;

		nli = &nlir->nlir_llink[i];
		T_LOG("\tlink_id: 0x%llx\n", nli->nli_link_id);
		T_LOG("\tlink_id_internal: 0x%x\n", nli->nli_link_id_internal);
		T_LOG("\tstate: 0x%x\n", nli->nli_state);
		T_LOG("\tflags: 0x%x\n", nli->nli_flags);
		T_LOG("\tqset_cnt: %d\n", nli->nli_qset_cnt);
		for (j = 0; j < nli->nli_qset_cnt; j++) {
			struct nx_qset_info *nqi;

			nqi = &nli->nli_qset[j];
			T_LOG("\t\tqset_id: %llx\n", nqi->nqi_id);
			T_LOG("\t\tflags: 0x%x\n", nqi->nqi_flags);
			T_LOG("\t\tnum_rx_queues: %d\n", nqi->nqi_num_rx_queues);
			T_LOG("\t\tnum_tx_queues: %d\n", nqi->nqi_num_tx_queues);

			/* randomly pick a qset for steering */
			if (((qset_select) % nlir->nlir_llink_cnt) == i &&
			    ((qset_select >> 16) % nli->nli_qset_cnt) == j) {
				llink_idx = i;
				qset_idx = j;
				*qset_id = nqi->nqi_id;
			}
		}
	}
	T_LOG("chosen llink_idx: %d\n", llink_idx);
	T_LOG("chosen qset_idx: %d\n", qset_idx);
	T_LOG("chosen qset_id: 0x%llx\n\n", *qset_id);
	free(nlir);
}

static int
setup_flowswitch_and_flow(struct sktc_nexus_handles * handles,
    const char * ifname, int protocol, uint16_t flags, struct in_addr our_ip,
    struct in_addr our_mask, uint16_t our_port, pid_t the_pid,
    struct in_addr peer_ip, uint16_t peer_port, uuid_t flow_id,
    flowadv_idx_t *flowadv_idx, int tx_ring_size, int rx_ring_size,
    int buf_size, int max_frags, bool multi_llink)
{
	int             error;
	uint64_t        qset_id = 0;

	bzero(handles, sizeof(*handles));
	strlcpy(handles->netif_ifname, ifname, sizeof(handles->netif_ifname));
	handles->netif_addr = our_ip;
	handles->netif_mask = our_mask;
	sktc_create_flowswitch_no_address(handles, tx_ring_size,
	    rx_ring_size, buf_size, max_frags, 0);
	error = os_nexus_controller_bind_provider_instance(handles->controller,
	    handles->fsw_nx_uuid, OUR_FLOWSWITCH_PORT, the_pid, NULL, NULL, 0,
	    NEXUS_BIND_PID);
	if (error != 0) {
		return error;
	}

	if (multi_llink) {
		get_qset_id_from_llinks(handles, &qset_id);
		assert(qset_id != 0);
	}
	if (uuid_is_null(flow_id)) {
		uuid_generate(flow_id);
	}
	error = connect_flow(handles->controller, handles->fsw_nx_uuid,
	    OUR_FLOWSWITCH_PORT, flow_id, protocol, flags, handles->netif_addr,
	    our_port, peer_ip, peer_port, flowadv_idx, qset_id);
	return error;
}

static void
setup_flowswitch(struct sktc_nexus_handles * handles,
    const char * ifname, pid_t the_pid,
    int tx_ring_size, int rx_ring_size,
    int buf_size, int max_frags)
{
	bzero(handles, sizeof(*handles));
	strlcpy(handles->netif_ifname, ifname, sizeof(handles->netif_ifname));
	sktc_create_flowswitch_no_address(handles, tx_ring_size,
	    rx_ring_size, buf_size, max_frags, 0);
	return;
}

static int
fetch_if_flowswitch_and_setup_flow(struct sktc_nexus_handles * handles,
    const char * ifname, int protocol, uint16_t flags, struct in_addr our_ip,
    struct in_addr our_mask, uint16_t our_port, pid_t the_pid,
    struct in_addr peer_ip, uint16_t peer_port, uuid_t flow_id,
    flowadv_idx_t *flowadv_idx, int tx_ring_size, int rx_ring_size,
    int buf_size, int max_frags, bool multi_llink, uuid_t parent_flow_id,
    struct flow_demux_pattern *demux_patterns, uint8_t demux_pattern_count)
{
	int             error;
	uint64_t        qset_id = 0;
	bool            child_flow = (demux_pattern_count > 0);

	bzero(handles, sizeof(*handles));
	strlcpy(handles->netif_ifname, ifname, sizeof(handles->netif_ifname));
	handles->netif_addr = our_ip;
	handles->netif_mask = our_mask;

	if (handles->netif_ifname[0] == '\0') {
		T_LOG("%s: no interface name specified\n",
		    __func__);
		return EINVAL;
	}
	if (strlen(handles->netif_ifname) >= IFNAMSIZ) {
		T_LOG("%s: invalid interface name specified %s\n",
		    __func__, handles->netif_ifname);
		return EINVAL;
	}

	handles->controller = os_nexus_controller_create();
	if (handles->controller == NULL) {
		SKT_LOG(
			"%s: os_nexus_controller_create failed, %s (%d)\n",
			__func__, strerror(errno), errno);
		return ENOMEM;
	}

	if ((sktc_get_netif_nexus(handles->netif_ifname, handles->netif_nx_uuid) &&
	    sktc_get_flowswitch_nexus(handles->netif_ifname, handles->fsw_nx_uuid))) {
		if (child_flow) {
			error = os_nexus_controller_bind_provider_instance(handles->controller,
			    handles->fsw_nx_uuid, CHILD_FLOWSWITCH_PORT, the_pid, NULL, NULL, 0,
			    NEXUS_BIND_PID);
		} else {
			error = os_nexus_controller_bind_provider_instance(handles->controller,
			    handles->fsw_nx_uuid, OUR_FLOWSWITCH_PORT, the_pid, NULL, NULL, 0,
			    NEXUS_BIND_PID);
		}
		if (error != 0) {
			SKT_LOG("PID %d: nexus controller bind failed: %s\n",
			    getpid(), strerror(errno));
			return error;
		}

		if (multi_llink) {
			get_qset_id_from_llinks(handles, &qset_id);
			assert(qset_id != 0);
		}
		if (uuid_is_null(flow_id)) {
			uuid_generate(flow_id);
		}
		if (child_flow) {
			error = connect_child_flow(handles->controller, handles->fsw_nx_uuid,
			    CHILD_FLOWSWITCH_PORT, flow_id, protocol, flags, handles->netif_addr,
			    our_port, peer_ip, peer_port, flowadv_idx, qset_id, parent_flow_id,
			    demux_patterns, demux_pattern_count);
		} else {
			error = connect_flow(handles->controller, handles->fsw_nx_uuid,
			    OUR_FLOWSWITCH_PORT, flow_id, protocol, flags, handles->netif_addr,
			    our_port, peer_ip, peer_port, flowadv_idx, qset_id);
		}
	} else {
		T_LOG(
			"%s: failed to find existing netif/flowswitch instance\n", __func__);
		return ENOENT;
	}

	return error;
}

#define FAKE_ETHER_NAME         "feth"
#define FAKE_ETHER_NAME_LEN     (sizeof(FAKE_ETHER_NAME) - 1)

static void
set_feth_mac_addr(struct ether_addr *feth_macaddr, uint32_t unit)
{
	/*
	 * FETH MAC addresses are hardcoded in if_fake.c, but it's not exposed.
	 * We use the same hardcoded values here.
	 */
	bcopy(FAKE_ETHER_NAME, feth_macaddr->octet, FAKE_ETHER_NAME_LEN);
	feth_macaddr->octet[ETHER_ADDR_LEN - 2] = (unit & 0xff00) >> 8;
	feth_macaddr->octet[ETHER_ADDR_LEN - 1] = unit & 0xff;
}

static int
skt_xfer_udp_common(int child, uint32_t how_many, uint32_t batch_size,
    bool do_ping_pong, bool wrong_flow_id, bool test_aqm,
    bool test_wmm, int tx_ring_size, int rx_ring_size, int buf_size,
    int max_frags, int event_test_id, bool low_latency, bool multi_llink,
    bool test_redirect)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx;
	uint32_t        event_flags = 0;
	bool            ifadv_enabled = false;
	bool            chan_event_enabled = false;
	bool            errors_ok = false;
	uint16_t        nfr_flags = 0;
	struct ether_addr feth0_macaddr;
	struct ether_addr feth1_macaddr;

	if (test_aqm || test_wmm) {
		assert(do_ping_pong);
		assert(!wrong_flow_id);
	}

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	nfr_flags |= (low_latency ? NXFLOWREQF_LOW_LATENCY : 0);

	if (test_redirect && child == 0) {
		setup_flowswitch(&handles, FETH0_NAME, getpid(),
		    tx_ring_size, rx_ring_size, buf_size, max_frags);

		setup_flowswitch(&handles, RD0_NAME, getpid(),
		    tx_ring_size, rx_ring_size, buf_size, max_frags);

		error = fetch_if_flowswitch_and_setup_flow(&handles, RD0_NAME,
		    IPPROTO_UDP, 0, our_ip, our_mask, our_port, getpid(), peer_ip,
		    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false, NULL,
		    NULL, 0);
	} else {
		/* set up the flowswitch over the right interface */
		error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
		    nfr_flags, our_ip, our_mask, our_port, getpid(), peer_ip,
		    peer_port, flow_id, &flowadv_idx, tx_ring_size, rx_ring_size,
		    buf_size, max_frags, multi_llink);
	}

	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP,
		    event_test_id == SKT_FSW_EVENT_TEST_CHANNEL_EVENTS ? true : false,
		    low_latency);
		assert(port.chan != NULL);
	}

	set_feth_mac_addr(&feth0_macaddr, 0);
	set_feth_mac_addr(&feth1_macaddr, 1);

	/* warm up the arp cache before starting the actual test */
	if (child == 0) {
		if ((error = skt_add_arp_entry(peer_ip, &feth1_macaddr)) != 0) {
			T_LOG("Child 0: ARP entry add failed\n");
			return 1;
		}
	} else {
		if ((error = skt_add_arp_entry(peer_ip, &feth0_macaddr)) != 0) {
			T_LOG("Child 1: ARP entry add failed\n");
			return 1;
		}
	}

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	if (wrong_flow_id) {
		uuid_generate(flow_id);
	}
	if (do_ping_pong) {
		ping_pong(&port, flow_id, our_port, peer_ip, peer_port,
		    how_many, batch_size, child, wrong_flow_id, flowadv_idx,
		    test_aqm, test_wmm, MAX_DEMUX_OFFSET + 1);
	} else {
		switch (event_test_id) {
		case SKT_FSW_EVENT_TEST_NONE:
			break;
		case SKT_FSW_EVENT_TEST_IF_ADV_ENABLED: {
			event_flags |= SKT_FSW_EVFLAG_IFADV;
			assert(os_channel_configure_interface_advisory(port.chan, TRUE) == 0);
			ifadv_enabled = true;
			break;
		}
		case SKT_FSW_EVENT_TEST_IF_ADV_DISABLED: {
			event_flags |= SKT_FSW_EVFLAG_IFADV;
			assert(os_channel_configure_interface_advisory(port.chan, FALSE) == 0);
			break;
		}
		case SKT_FSW_EVENT_TEST_CHANNEL_EVENTS: {
			chan_event_enabled = true;
			event_flags |= SKT_FSW_EVFLAG_CHANNEL;
			errors_ok = true;
			break;
		}
		default:
			T_LOG("unknown event test id %d\n",
			    event_test_id);
			assert(0);
			break;
		}
		send_and_receive(&port, flow_id, our_port, peer_ip, peer_port,
		    how_many, batch_size, child, wrong_flow_id, errors_ok,
		    event_flags, ifadv_enabled);
	}

#if SKT_XFER_DEBUG
	T_LOG("got input %d from parent in child %d, starting test\n",
	    buf[0], child);
#endif
	return 0;
}

static int
get_fsw_stats(struct fsw_stats *result)
{
	int i, ret;
	size_t length = 0;
	size_t width = sizeof(struct sk_stats_flow_switch);
	void *buffer, *scan;
	struct sk_stats_flow_switch *sfs;

	ret =  sysctl_buf(SK_STATS_FLOW_SWITCH, &buffer, &length, NULL, 0);
	if (ret != 0 || buffer == NULL || length == 0) {
		T_LOG("get_fsw_stats: Failed to get stats\n");
		return ret;
	}

	assert((length % width) == 0);
	scan = buffer;
	memset(result, 0, sizeof(*result));

	/*
	 * XXX: I don't like pointer arithmetic on a void ptr, but
	 * this code was lifted from skywalk_cmds and clang doesn't
	 * seem to care.
	 */
	ret = ENOENT;
	while (scan < (buffer + length)) {
		sfs = scan;
		scan += sizeof(*sfs);

		if (strcmp(sfs->sfs_if_name, FETH0_NAME) != 0 &&
		    strcmp(sfs->sfs_if_name, FETH1_NAME) != 0) {
			continue;
		}
		ret = 0;

		for (i = 0;
		    i < (sizeof(*result) / sizeof(STATS_VAL(result, 0))); i++) {
			STATS_ADD(result, i, STATS_VAL(&sfs->sfs_fsws, i));
		}
	}

	free(buffer);

	return ret;
}

static int
skt_xfer_udp_with_errors_common(int child, uint32_t how_many,
    uint32_t batch_size)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	int             errbit, rv;
	uint64_t        emask;
	uuid_string_t   uuidstr;
	flowadv_idx_t   flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		child = 1;
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/*
	 * Start the receiver
	 */
	if (child == 0) {
		do_error_receive(child, &port, flow_id, our_port, peer_ip, peer_port,
		    INJECT_CODE_COUNT * how_many);
		return 0;
	}

	/*
	 * For each injection code:
	 *	Take a snapshot of fsw_stats
	 *	Invoke send_and_receive()
	 *	Take a snapshot of fsw_stats
	 *	Verify stats counter associated to injection code increased.
	 */
	for (errbit = 0; errbit < INJECT_CODE_COUNT; errbit++) {
		struct fsw_stats stats_before, stats_after;
		const struct fsw_inject_codes *ic;
		uint32_t error_rmask;
		const int *sidx;
		int st;

		ic = &fsw_inject_codes[errbit];

		T_LOG("Injecting error bit %d\n", ic->ic_code);
		fflush(stderr);

		emask = (1ULL << ic->ic_code);
		emask = set_error_inject_mask(&emask);

		rv = get_fsw_stats(&stats_before);
		assert(rv == 0);

		if (ic->ic_rmask != IC_RMASK_UNSPEC) {
			error_rmask = ic->ic_rmask;
			error_rmask = sktu_set_inject_error_rmask(&error_rmask);
		}

		do_error_send(&port, flow_id, our_port, peer_ip, peer_port,
		    how_many, batch_size);

		T_LOG("Tx completed for error bit %d\n", ic->ic_code);

		rv = get_fsw_stats(&stats_after);
		assert(rv == 0);

		if (ic->ic_rmask != IC_RMASK_UNSPEC) {
			error_rmask = sktu_set_inject_error_rmask(&error_rmask);
		}

		/* random error injection could fail to inject at all */
		if (STATS_VAL(&stats_after, _FSW_STATS_ERROR_INJECTIONS) ==
		    STATS_VAL(&stats_before, _FSW_STATS_ERROR_INJECTIONS)) {
			T_LOG("skip non-injected error bit %d\n",
			    ic->ic_code);
			continue;
		}

		for (sidx = ic->ic_stat_idx, st = 0;
		    st < INJECT_CODE_IDX_MAX; st++, sidx++) {
			uint64_t counter;

			if (*sidx < 0) {
				continue;
			}

			counter = STATS_VAL(&stats_after, *sidx);
			counter -= STATS_VAL(&stats_before, *sidx);

			if (counter == 0) {
				T_LOG("Counter idx %d didn't "
				    "change for error %d. Before %lld, "
				    "After %lld\n", st, ic->ic_code,
				    STATS_VAL(&stats_before, *sidx),
				    STATS_VAL(&stats_after, *sidx));
				return 1;
			}
		}
	}

	emask = 0;
	set_error_inject_mask(&emask);

	return 0;
}

static int
skt_xfer_tcpflood(int child, uint32_t how_many, uint32_t batch_size, bool synflood)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_TCP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
#if SKT_XFER_DEBUG
	T_LOG("got input %d from parent in child %d, starting test\n",
	    buf[0], child);
#endif
	port.ip_addr = our_ip;
	send_tcp(&port, flow_id, our_port, peer_ip, peer_port,
	    how_many, batch_size, child, synflood);
	return 0;
}

static int
skt_xfer_portzero(int child, int protocol)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = "feth0";
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = 0;
	} else {
		ifname = "feth1";
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = 0;
	}

	/* this should fail with EADDRNOTAVAIL (port 0) */
	error = setup_flowswitch_and_flow(&handles, ifname, protocol,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);

	if (error != EINVAL) {
		T_LOG("expected %d but got %s (%d)\n", EINVAL,
		    strerror(error), error);
		return 1;
	}
	return 0;
}

static int
skt_xfer_setuponly(int child)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_TCP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	} else {
		while (1) {
			T_LOG("Child %d waiting\n", child);
			sleep(5);
		}
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
#if SKT_XFER_DEBUG
	T_LOG("got input %d from parent in child %d, starting test\n",
	    buf[0], child);
#endif
	return 0;
}

static void
send_bad_flow(channel_port_t port, uuid_t flow_id,
    int protocol, uint16_t src_port, struct in_addr dst_ip, uint16_t dst_port,
    my_payload_t payload)
{
	struct fsw_stats stats_before, stats_after;
	uint64_t counter;
	int ret;

	ret = get_fsw_stats(&stats_before);
	assert(ret == 0);

	channel_port_send(port, flow_id, protocol, src_port, dst_ip, dst_port,
	    payload, sizeof(*payload), 1, FALSE, FALSE, PKT_SC_BE, FALSE, NULL);

	ret = get_fsw_stats(&stats_after);
	assert(ret == 0);

	counter = STATS_VAL(&stats_after, FSW_STATS_DROP);
	counter -= STATS_VAL(&stats_before, FSW_STATS_DROP);

	if (counter == 0) {
		T_LOG("Flow not ours wasn't dropped");
		assert(0);
	}
	T_LOG("dropped %"PRIu64"\n", counter);
}

static int
skt_xfer_flowmatch(int child)
{
	char buf[1] = { 0 };
	int error;
	const char * ifname;
	uuid_t flow_id = {};
	uuid_t nowhere_flow_id;
	struct in_addr our_ip, peer_ip, nowhere_ip;
	struct in_addr our_mask;
	uint16_t our_port, peer_port;
	channel_port port;
	ssize_t ret;
	uuid_string_t uuidstr;
	flowadv_idx_t flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		child = 1;
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* Start the receiver */
	if (child == 0) {
		channel_port_receive_all(&port, flow_id, our_port, peer_ip,
		    peer_port, 0, FALSE);
		return 0;
	}

	my_payload payload;
	bzero(&payload, sizeof(payload));
	payload.packet_number = 0;

	nowhere_ip = sktc_nowhere_in_addr();
	do{
		uuid_generate_random(nowhere_flow_id);
	} while (!uuid_compare(nowhere_flow_id, flow_id));

	/* Send with wrong flow id */
	T_LOG("Send with wrong flow id...\t");
	payload.packet_number = 0;
	strncpy(payload.data, "wrong flow id", sizeof(payload.data));
	send_bad_flow(&port, nowhere_flow_id,
	    IPPROTO_UDP, our_port, peer_ip, peer_port, &payload);

	/* Send with wrong protocol */
	T_LOG("Send with wrong protocol...\t");
	payload.packet_number = 0;
	strncpy(payload.data, "wrong protocol", sizeof(payload.data));
	send_bad_flow(&port, flow_id,
	    IPPROTO_TCP, our_port, peer_ip, peer_port, &payload);

	/* Send with wrong src port */
	T_LOG("Send with wrong src port...\t");
	payload.packet_number = 0;
	strncpy(payload.data, "wrong src port", sizeof(payload.data));
	send_bad_flow(&port, flow_id,
	    IPPROTO_UDP, our_port + 1, peer_ip, peer_port, &payload);

	/* Send with wrong dst IP */
	T_LOG("Send with wrong dst IP...\t");
	payload.packet_number = 0;
	strncpy(payload.data, "wrong dst IP", sizeof(payload.data));
	send_bad_flow(&port, flow_id,
	    IPPROTO_UDP, our_port, nowhere_ip, peer_port, &payload);

	/* Send with wrong dst port */
	T_LOG("Send with wrong dst port...\t");
	payload.packet_number = 0;
	strncpy(payload.data, "wrong dst port", sizeof(payload.data));
	send_bad_flow(&port, flow_id,
	    IPPROTO_UDP, our_port, peer_ip, peer_port + 1, &payload);

	/* Send something right to single receiver to end */
	payload.packet_number = 0;
	strncpy(payload.data, XFER_RECV_END_PAYLOAD, sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);

	return 0;
}

/* see rdar://problem/38427726 for details */
static int
skt_xfer_flowcleanup(int child, uint32_t how_many, uint32_t batch_size)
{
	char            buf[1] = { 0 };
	int             error;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx = FLOWADV_IDX_NONE;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/*
	 * set up the flowswitch over the right interface and bind a
	 * 5 tuple flow.
	 */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	SKTC_ASSERT_ERR(error == 0);
	assert(flowadv_idx != FLOWADV_IDX_NONE);

	/* open channel */
	sktu_channel_port_init(&port, handles.fsw_nx_uuid, OUR_FLOWSWITCH_PORT,
	    ENABLE_UPP, false, false);
	assert(port.chan != NULL);

	/*
	 * Close the channel. This also triggers the closure of the flow
	 * created above and the removal of nexus port binding.
	 */
	os_channel_destroy(port.chan);

	/* bind again to the same port */
	error = os_nexus_controller_bind_provider_instance(handles.controller,
	    handles.fsw_nx_uuid, OUR_FLOWSWITCH_PORT, getpid(),
	    NULL, NULL, 0, NEXUS_BIND_PID);
	SKTC_ASSERT_ERR(!error);

	/* open a new flow */
	uuid_generate(flow_id);
	flowadv_idx = FLOWADV_IDX_NONE;
	error = connect_flow(handles.controller, handles.fsw_nx_uuid,
	    OUR_FLOWSWITCH_PORT, flow_id, IPPROTO_UDP, 0,
	    handles.netif_addr, our_port, peer_ip, peer_port, &flowadv_idx, 0);
	SKTC_ASSERT_ERR(!error);
	assert(flowadv_idx != FLOWADV_IDX_NONE);

	/* re-open channel on the same port */
	sktu_channel_port_init(&port, handles.fsw_nx_uuid, OUR_FLOWSWITCH_PORT,
	    ENABLE_UPP, false, false);
	assert(port.chan != NULL);
	port.ip_addr = our_ip;

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* perform ping pong test */
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, how_many,
	    batch_size, child, FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);

	return 0;
}

static int
skt_xfer_csumoffload(int child, int protocol)
{
	char buf[1] = { 0 };
	int error;
	const char * ifname;
	uuid_t flow_id = {};
	uuid_t nowhere_flow_id;
	struct in_addr our_ip, peer_ip;
	struct in_addr our_mask;
	uint16_t our_port, peer_port;
	channel_port port;
	ssize_t ret;
	uuid_string_t uuidstr;
	flowadv_idx_t flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* Start the receiver */
	if (child == 0) {
		channel_port_receive_all(&port, flow_id, our_port, peer_ip,
		    peer_port, 2, FALSE);
		return 0;
	}

	my_payload payload;
	bzero(&payload, sizeof(payload));
	payload.packet_number = 0;

	do{
		uuid_generate_random(nowhere_flow_id);
	} while (!uuid_compare(nowhere_flow_id, flow_id));

	/* send with checksum offloading */
	payload.packet_number = 0;
	strlcpy(payload.data, "any", sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    TRUE, NULL);

	/* send without checksum offloading */
	payload.packet_number = 0;
	strlcpy(payload.data, "any", sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);

	/* signal receiver to stop */
	payload.packet_number = 0;
	strlcpy(payload.data, XFER_RECV_END_PAYLOAD, sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);
	return 0;
}

static void
skt_xfer_enable_qos_marking_interface(const char *ifname, uint32_t mode)
{
	/* setup ifnet for qos marking */
	int s;
	struct  ifreq ifr;
	unsigned long ioc;

	assert(mode != IFRTYPE_QOSMARKING_MODE_NONE);

	assert((s = socket(AF_INET, SOCK_DGRAM, 0)) >= 0);

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ioc = SIOCSQOSMARKINGMODE;
	ifr.ifr_qosmarking_mode = mode;
	assert(ioctl(s, ioc, (caddr_t)&ifr) == 0);

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ioc = SIOCSQOSMARKINGENABLED;
	ifr.ifr_qosmarking_enabled = 1;
	assert(ioctl(s, ioc, (caddr_t)&ifr) == 0);
}

static int
skt_xfer_qosmarking(int child, uint32_t mode)
{
	char buf[1] = { 0 };
	int error;
	const char * ifname;
	uuid_t flow_id = {};
	uuid_t nowhere_flow_id;
	struct in_addr our_ip, peer_ip;
	struct in_addr our_mask;
	uint16_t our_port, peer_port;
	channel_port port;
	ssize_t ret;
	uuid_string_t uuidstr;
	flowadv_idx_t flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
		skt_xfer_enable_qos_marking_interface(ifname, mode);
	} else {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
		skt_xfer_enable_qos_marking_interface(ifname, mode);
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* Start the receiver who would verify the Qos marking */
	if (child == 0) {
		channel_port_receive_all(&port, flow_id, our_port, peer_ip,
		    peer_port, -1, TRUE);
		return 0;
	}

	my_payload payload;

	do{
		uuid_generate_random(nowhere_flow_id);
	} while (!uuid_compare(nowhere_flow_id, flow_id));

	/* test qos marking with and without checksum offload */

#define __SEND_SC(svc, csum_offload) \
	bzero(&payload, sizeof(payload));\
	payload.packet_number = 0;\
	if (mode == IFRTYPE_QOSMARKING_FASTLANE) {      \
	        strlcpy(payload.data, XFER_QOSMARKING_FASTLANE_PREFIX, sizeof(payload.data));   \
	} else if (mode == IFRTYPE_QOSMARKING_RFC4594) {        \
	        strlcpy(payload.data, XFER_QOSMARKING_RFC4594_PREFIX, sizeof(payload.data));    \
	}       \
	strlcat(payload.data, #svc, sizeof(payload.data));\
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,\
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, svc, csum_offload, NULL);    \

#define SEND_SC(svc)    \
	__SEND_SC(svc, FALSE);  \
	__SEND_SC(svc, TRUE);

	SEND_SC(PKT_SC_BK);
	SEND_SC(PKT_SC_BK_SYS);
	SEND_SC(PKT_SC_BE);
	SEND_SC(PKT_SC_RD);
	SEND_SC(PKT_SC_OAM);
	SEND_SC(PKT_SC_AV);
	SEND_SC(PKT_SC_RV);
	SEND_SC(PKT_SC_VI);
	SEND_SC(PKT_SC_SIG);
	SEND_SC(PKT_SC_VO);
	SEND_SC(PKT_SC_CTL);

#undef  SEND_SC
#undef  __SEND_SC

	/* signal receiver to stop */
	payload.packet_number = 0;
	strlcpy(payload.data, XFER_RECV_END_PAYLOAD, sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);

	return 0;
}

static int
skt_xfer_listener_tcp_rst(int child)
{
	char buf[1] = { 0 };
	int error;
	const char * ifname;
	uuid_t flow_id = {};
	uuid_t listener_flow_id, connecting_flow_id;
	struct in_addr our_ip, peer_ip, zero_ip;
	struct in_addr our_mask;
	uint16_t our_port, peer_port, listener_port;
	channel_port port;
	ssize_t ret;
	uuid_string_t uuidstr;
	flowadv_idx_t flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		/* connector and RST receiver */
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
		listener_port = FETH0_PORT + 1;
	} else {
		/* listener */
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
		listener_port = FETH0_PORT + 1;
	}

	zero_ip = (struct in_addr){.s_addr = htonl(INADDR_ANY)};

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif

	if (child == 0) {
		do{
			uuid_generate_random(connecting_flow_id);
		} while (!uuid_compare(connecting_flow_id, flow_id));
		flowadv_idx_t tmp_flowadv_idx = FLOWADV_IDX_NONE;
		error = connect_flow(handles.controller, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, connecting_flow_id, IPPROTO_TCP, 0,
		    our_ip, our_port, peer_ip, listener_port, &tmp_flowadv_idx,
		    0);
		SKTC_ASSERT_ERR(!error);
		assert(tmp_flowadv_idx != FLOWADV_IDX_NONE);
	} else {
		do{
			uuid_generate_random(listener_flow_id);
		} while (!uuid_compare(listener_flow_id, flow_id));
		flowadv_idx_t tmp_flowadv_idx = FLOWADV_IDX_NONE;
		error = connect_flow(handles.controller, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, listener_flow_id, IPPROTO_TCP, 0,
		    our_ip, listener_port, zero_ip, 0, &tmp_flowadv_idx, 0);
		SKTC_ASSERT_ERR(!error);
		assert(tmp_flowadv_idx != FLOWADV_IDX_NONE);
	}

	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* Start the receiver */
	if (child == 0) {
		channel_port_receive_all(&port, flow_id, listener_port, peer_ip,
		    peer_port, 1, FALSE);
		return 0;
	}

	my_payload payload;
	bzero(&payload, sizeof(payload));
	payload.packet_number = 0;
	channel_port_send(&port, listener_flow_id, IPPROTO_TCP, listener_port,
	    peer_ip, peer_port, &payload, sizeof(payload), 1, FALSE, FALSE,
	    PKT_SC_BE, TRUE, NULL);

	sleep(1);

	/* Send something right to single receiver to end */
	payload.packet_number = 1;
	strncpy(payload.data, XFER_RECV_END_PAYLOAD, sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 2, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);

	return 0;
}

int
skt_xfer_udp_frags(int child, bool error_ids)
{
	char buf[1] = { 0 };
	int error;
	const char * ifname;
	uuid_t flow_id = {};
	struct in_addr our_ip, peer_ip;
	struct in_addr our_mask;
	uint16_t our_port, peer_port;
	channel_port port;
	ssize_t ret;
	uuid_string_t uuidstr;
	flowadv_idx_t flowadv_idx;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (child == 0) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
	} else {
		child = 1;
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
	}

	/* set up the flowswitch over the right interface */
	error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
	    0, our_ip, our_mask, our_port, getpid(), peer_ip,
	    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    OUR_FLOWSWITCH_PORT, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}
	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("child %d signaled\n", child);
#endif

	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	uuid_unparse(handles.fsw_nx_uuid, uuidstr);
	T_LOG("Child %d nexus uuid: '%s'\n", child, uuidstr);
	fflush(stderr);

	/* warm up the arp cache before starting the actual test */
	T_LOG("child %d: Warm up ARP cache\n", child);
	ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, child,
	    FALSE, flowadv_idx, FALSE, FALSE, MAX_DEMUX_OFFSET + 1);
	T_LOG("child %d: Test Start\n", child);

	/* Start the receiver */
	if (child == 0) {
		channel_port_receive_all(&port, flow_id, our_port, peer_ip,
		    peer_port, error_ids ? 0 : 4, FALSE);
		return 0;
	}

	my_payload payload;
	bzero(&payload, sizeof(payload));
	payload.packet_number = 0;

	channel_port_send_fragments(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, (sizeof(payload.data) & ~0x7), 4,
	    PKT_SC_BE, FALSE, error_ids);

	bzero(&payload, sizeof(payload));
	payload.packet_number = 0;
	strncpy(payload.data, XFER_RECV_END_PAYLOAD, sizeof(payload.data));
	channel_port_send(&port, flow_id, IPPROTO_UDP, our_port, peer_ip,
	    peer_port, &payload, sizeof(payload), 1, FALSE, FALSE, PKT_SC_BE,
	    FALSE, NULL);

	return 0;
}

static int
skt_xfer_udp_parent_child(int id, uint16_t demux_offset)
{
#define CHILD_ID           0
#define REMOTE_ID          1
#define PARENT_ID          2

#define PARENT_FLOW_UUID   "1B4E28BA-2FA1-11D2-883F-B9A761BDE3FB"
#define CHILD_FLOW_UUID    "1B4E28BA-2FA1-11D2-883F-B9A761BDE3FD"

	char            buf[1] = { 0 };
	int             error = 0;
	const char *    ifname;
	uuid_t          flow_id = {};
	struct in_addr  our_ip;
	struct in_addr  our_mask;
	uint16_t        our_port;
	struct in_addr  peer_ip;
	uint16_t        peer_port;
	channel_port    port;
	ssize_t         ret;
	flowadv_idx_t   flowadv_idx;
	nexus_port_t    nx_port;
	uuid_t          parent_flow_id = {};
	uint16_t        flags = 0;

	our_mask = sktc_make_in_addr(IN_CLASSC_NET);

	if (id == PARENT_ID) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
		nx_port = OUR_FLOWSWITCH_PORT;
		flags = NXFLOWREQF_PARENT;
		uuid_parse(PARENT_FLOW_UUID, flow_id);
	} else if (id == CHILD_ID) {
		ifname = FETH0_NAME;
		our_ip = sktc_feth0_in_addr();
		peer_ip = sktc_feth1_in_addr();
		our_port = FETH0_PORT;
		peer_port = FETH1_PORT;
		nx_port = CHILD_FLOWSWITCH_PORT;
		uuid_parse(CHILD_FLOW_UUID, flow_id);
		uuid_parse(PARENT_FLOW_UUID, parent_flow_id);
		// Wait for the parent to setup the flow-switch
		sleep(1);
	} else if (id == REMOTE_ID) {
		ifname = FETH1_NAME;
		our_ip = sktc_feth1_in_addr();
		peer_ip = sktc_feth0_in_addr();
		our_port = FETH1_PORT;
		peer_port = FETH0_PORT;
		nx_port = OUR_FLOWSWITCH_PORT;
	}

	if (id == PARENT_ID || id == REMOTE_ID) {
		// set up the flowswitch
		error = setup_flowswitch_and_flow(&handles, ifname, IPPROTO_UDP,
		    flags, our_ip, our_mask, our_port, getpid(), peer_ip,
		    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false);
	} else if (id == CHILD_ID) {
		// child will reuse parent interface and flowswitch
		struct flow_demux_pattern demux_patterns[1];
		memset(demux_patterns, 0, sizeof(struct flow_demux_pattern));

		uint16_t payload_byte = DEMUX_PAYLOAD_VALUE;
		demux_patterns[0].fdp_offset = DEMUX_PAYLOAD_OFFSET + demux_offset;
		demux_patterns[0].fdp_mask[0] = 0xFF;
		demux_patterns[0].fdp_mask[1] = 0xFF;
		demux_patterns[0].fdp_value[0] = payload_byte;
		demux_patterns[0].fdp_value[1] = payload_byte >> 8;
		demux_patterns[0].fdp_len = sizeof(payload_byte);
		error = fetch_if_flowswitch_and_setup_flow(&handles, ifname,
		    IPPROTO_UDP, 0, our_ip, our_mask, our_port, getpid(), peer_ip,
		    peer_port, flow_id, &flowadv_idx, -1, -1, -1, -1, false, parent_flow_id,
		    demux_patterns, 1);
	}
	if (error == 0) {
		sktu_channel_port_init(&port, handles.fsw_nx_uuid,
		    nx_port, ENABLE_UPP, false, false);
		assert(port.chan != NULL);
	}

	if ((ret = write(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("write fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
#if SKT_XFER_DEBUG
	T_LOG("ID %d signaled\n", id);
#endif
	/* Wait for go signal */
	if ((ret = read(MPTEST_SEQ_FILENO, buf, sizeof(buf))) == -1) {
		SKT_LOG("read fail: %s\n", strerror(errno));
		return 1;
	}
	assert(ret == 1);
	if (error != 0) {
		return 1;
	}
	port.ip_addr = our_ip;

	/* warm up the arp cache before starting the actual test */
	if (id == CHILD_ID || id == REMOTE_ID) {
		T_LOG("child %d: Warm up ARP cache\n", id);
		ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 1, 1, id,
		    FALSE, flowadv_idx, FALSE, FALSE, demux_offset);

		T_LOG("child %d: Test Start\n", id);
		ping_pong(&port, flow_id, our_port, peer_ip, peer_port, 5, 5, id,
		    FALSE, flowadv_idx, FALSE, FALSE, demux_offset);
	} else if (id == PARENT_ID) {
		// Wait for the child ping-pong to complete
		sleep(1);
	}

	return 0;
}

static int
skt_xfer_udp_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_TXRX_PACKET_COUNT,
	           XFER_TXRX_BATCH_COUNT, FALSE, FALSE, FALSE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_long_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_TXRX_PACKET_COUNT_LONG,
	           XFER_TXRX_BATCH_COUNT, FALSE, FALSE, FALSE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_overwhelm_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_TXRX_PACKET_COUNT,
	           XFER_TXRX_OVERWHELM_BATCH_COUNT, FALSE, FALSE, FALSE, FALSE,
	           XFER_TXRX_OVERWHELM_FSW_TX_RING_SIZE,
	           XFER_TXRX_OVERWHELM_FSW_RX_RING_SIZE, -1, -1,
	           SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_overwhelm_long_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_TXRX_PACKET_COUNT_LONG,
	           XFER_TXRX_OVERWHELM_BATCH_COUNT, FALSE, FALSE, FALSE, FALSE,
	           XFER_TXRX_OVERWHELM_FSW_TX_RING_SIZE,
	           XFER_TXRX_OVERWHELM_FSW_RX_RING_SIZE, -1, -1,
	           SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_ping_pong_main(int argc, char *argv[])
{
	int child, test_id;
	bool low_latency;
	bool multi_llink;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = atoi(argv[5]);

	low_latency = (test_id == SKT_FSW_PING_PONG_TEST_LOW_LATENCY);
	multi_llink = (test_id == SKT_FSW_PING_PONG_TEST_MULTI_LLINK);
	return skt_xfer_udp_common(child, XFER_PING_PACKET_COUNT,
	           XFER_PING_BATCH_COUNT, TRUE, FALSE, FALSE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, low_latency, multi_llink,
	           false);
}

static int
skt_xfer_rd_udp_ping_pong_main(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = atoi(argv[5]);

	return skt_xfer_udp_common(child, XFER_PING_PACKET_COUNT,
	           XFER_PING_BATCH_COUNT, TRUE, FALSE, FALSE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, true);
}

static int
skt_xfer_udp_ping_pong_one_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, 1, 1, TRUE, FALSE, FALSE, FALSE,
	           -1, -1, -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_ping_pong_long_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_PING_PACKET_COUNT_LONG,
	           XFER_PING_BATCH_COUNT, TRUE, FALSE, FALSE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_ping_pong_one_wrong_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, 1, 1, TRUE, TRUE, FALSE, FALSE,
	           -1, -1, -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_tcp_syn_flood_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_tcpflood(child, 10000, 64, TRUE);
}

static int
skt_xfer_tcp_rst_flood_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_tcpflood(child, 10000, 64, FALSE);
}

static int
skt_xfer_udp_ping_pong_aqm_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_AQM_PING_PACKET_COUNT,
	           XFER_AQM_PING_BATCH_COUNT, TRUE, FALSE, TRUE, FALSE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

static int
skt_xfer_udp_with_errors_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_with_errors_common(child,
	           XFER_TXRX_PACKET_COUNT, XFER_TXRX_BATCH_COUNT);
}

static int
skt_xfer_tcp_port_zero_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_portzero(child, IPPROTO_TCP);
}

static int
skt_xfer_udp_port_zero_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_portzero(child, IPPROTO_UDP);
}

static int
skt_xfer_setuponly_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	return skt_xfer_setuponly(child);
}

static int
skt_xfer_udp_ping_pong_wmm_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_WMM_PING_PACKET_COUNT,
	           XFER_WMM_PING_BATCH_COUNT, TRUE, FALSE, FALSE, TRUE, -1, -1,
	           -1, -1, SKT_FSW_EVENT_TEST_NONE, false, false, false);
}

int
skt_xfer_flowmatch_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_flowmatch(child);
}

static int
skt_xfer_flowcleanup_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_flowcleanup(child, 128, 8);
}

static int
skt_xfer_udp_ping_pong_multi_buflet_main(int argc, char *argv[])
{
	int             child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	return skt_xfer_udp_common(child, XFER_PING_PACKET_COUNT,
	           XFER_PING_BATCH_COUNT, TRUE, FALSE, FALSE, FALSE, -1, -1,
	           XFER_TXRX_MULTI_BUFLET_BUF_SIZE,
	           XFER_TXRX_MULTI_BUFLET_MAX_FRAGS, SKT_FSW_EVENT_TEST_NONE,
	           false, false, false);
}

static int
skt_xfer_csumoffload_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	skt_xfer_csumoffload(child, IPPROTO_UDP);

	return 0;
}

static int
skt_xfer_fastlane_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	skt_xfer_qosmarking(child, IFRTYPE_QOSMARKING_FASTLANE);

	return 0;
}

static int
skt_xfer_rfc4594_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	skt_xfer_qosmarking(child, IFRTYPE_QOSMARKING_RFC4594);

	return 0;
}

static int
skt_xfer_listener_tcp_rst_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	skt_xfer_listener_tcp_rst(child);

	return 0;
}

static int
skt_xfer_udp_frags_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	skt_xfer_udp_frags(child, FALSE);

	return 0;
}

static int
skt_xfer_udp_bad_frags_main(int argc, char *argv[])
{
	int child;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);

	skt_xfer_udp_frags(child, TRUE);

	return 0;
}

static int
skt_xfer_udp_ifadv_main(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = atoi(argv[5]);

	return skt_xfer_udp_common(child, XFER_TXRX_PACKET_COUNT,
	           XFER_TXRX_BATCH_COUNT, FALSE, FALSE, FALSE, FALSE,
	           -1, -1, -1, -1, test_id, false, false, false);
}

static int
skt_xfer_parent_child_flow_main(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = 0;

	return skt_xfer_udp_parent_child(child, 0);
}

static int
skt_xfer_parent_child_flow_main_offset_400(int argc, char *argv[])
{
	int child, test_id;

	assert(!strcmp(argv[3], "--child"));
	child = atoi(argv[4]);
	test_id = 0;

	return skt_xfer_udp_parent_child(child, 400);
}

static void
skt_xfer_init_txstart(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_rd_init(void)
{
	int err;
	uint32_t disable_nxctl_check = 1;
	size_t len = sizeof(skt_disable_nxctl_check);

	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_disable_nxctl_check, &len, &disable_nxctl_check,
	    sizeof(disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE);
	sktc_ifnet_rd_create();
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

/* QoS Marking App Policy needs to be set before child is launched */
static int restricted_old;
static void
skt_xfer_init_enable_qos_marking_policy(void)
{
	int zero = 0;
	size_t restricted_old_size = sizeof(restricted_old);
	assert(sysctlbyname("net.qos.policy.restricted",
	    &restricted_old, &restricted_old_size,
	    &zero, sizeof(zero)) == 0);
}

static void
skt_xfer_init_txstart_fastlane(void)
{
	skt_xfer_init_txstart();
	skt_xfer_init_enable_qos_marking_policy();
}

static void
skt_xfer_init_txstart_fcs(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART |
	    FETH_FLAGS_FCS);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_txstart_trailer(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART |
	    FETH_FLAGS_TRAILER);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native_fastlane(void)
{
	skt_xfer_init_native();
	skt_xfer_init_enable_qos_marking_policy();
}

static void
skt_xfer_init_native_split_pools(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_NONSHAREDSPLITPOOLS);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native_fcs(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_FCS);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native_trailer(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE |
	    FETH_FLAGS_TRAILER);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_llink(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_LLINK);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_llink_wmm(void)
{
	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_LLINK |
	    FETH_FLAGS_WMM);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_llink_multi(void)
{
	int err;
	uint32_t disable_nxctl_check = 1;
	size_t len = sizeof(skt_disable_nxctl_check);

	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_disable_nxctl_check, &len, &disable_nxctl_check,
	    sizeof(disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_MULTI_LLINK);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_fini(void)
{
#if SKT_XFER_DEBUG
	T_LOG("Waiting");
	fflush(stdout);
	for (int i = 0; i < 5; i++) {
		sleep(1);
		T_LOG(".");
		fflush(stdout);
	}
	T_LOG("\n");
#endif
	sktc_ifnet_feth0_set_dequeue_stall(FALSE);
	sktc_ifnet_feth1_set_dequeue_stall(FALSE);
	sktc_ifnet_feth_pair_destroy();
	sktc_restore_ip_reass();
	sktc_restore_fsw_rx_agg_tcp();
}

static void
skt_xfer_rd_fini(void)
{
#if SKT_XFER_DEBUG
	T_LOG("Waiting");
	fflush(stdout);
	for (int i = 0; i < 5; i++) {
		sleep(1);
		T_LOG(".");
		fflush(stdout);
	}
	T_LOG("\n");
#endif
	int err;

	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL, &skt_disable_nxctl_check,
	    sizeof(skt_disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth0_set_dequeue_stall(FALSE);
	sktc_ifnet_feth1_set_dequeue_stall(FALSE);
	sktc_ifnet_feth_pair_destroy();
	sktc_ifnet_rd_destroy();
	sktc_restore_ip_reass();
	sktc_restore_fsw_rx_agg_tcp();
}

static void
skt_xfer_fini_fastlane(void)
{
	/* restore sysctl */
	assert(sysctlbyname("net.qos.policy.restricted", NULL, NULL,
	    &restricted_old, sizeof(restricted_old)) == 0);

	skt_xfer_fini();
}

static void
skt_xfer_fini_llink_multi(void)
{
	int err;

	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL, &skt_disable_nxctl_check,
	    sizeof(skt_disable_nxctl_check));
	assert(err == 0);
	skt_xfer_fini();
}

static void
skt_xfer_errors_init(void)
{
	uint64_t emask = (1ull << 63);
	uint32_t rmask = 0x7ff;

	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE);
	set_error_inject_mask(&emask);
	inject_error_rmask = sktu_set_inject_error_rmask(&rmask);
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_errors_compat_init(void)
{
	uint64_t emask = (1ull << 63);
	uint32_t rmask = 0x7ff;

	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
	set_error_inject_mask(&emask);
	inject_error_rmask = sktu_set_inject_error_rmask(&rmask);
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_errors_fini(void)
{
	uint64_t emask = 0;

	set_error_inject_mask(&emask);
	(void) sktu_set_inject_error_rmask(&inject_error_rmask);
	sktc_ifnet_feth_pair_destroy();
	sktc_restore_fsw_rx_agg_tcp();
}

static void
skt_xfer_multi_buflet_fini()
{
	sktc_restore_channel_buflet_alloc();
	skt_xfer_fini();
}

static void
skt_xfer_init_native_wmm(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_WMM);
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native_multi_buflet(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_MULTI_BUFLET |
	    FETH_FLAGS_TX_HEADROOM);
	sktc_enable_channel_buflet_alloc();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_native_multi_buflet_copy(void)
{
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE | FETH_FLAGS_MULTI_BUFLET |
	    FETH_FLAGS_NONSHAREDPOOL | FETH_FLAGS_TX_HEADROOM);
	sktc_enable_ip_reass();
	sktc_enable_channel_buflet_alloc();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_ifadv(void)
{
	int intvl = XFER_IFADV_INTERVAL; /* in milliseconds */

	assert(sysctlbyname("net.link.fake.if_adv_intvl",
	    NULL, 0, &intvl, sizeof(intvl)) == 0);
	skt_xfer_init_native();
}

static void
skt_xfer_fini_ifadv(void)
{
	int intvl = 0; /* disable */

	skt_xfer_fini();
	assert(sysctlbyname("net.link.fake.if_adv_intvl",
	    NULL, 0, &intvl, sizeof(intvl)) == 0);
}

static void
skt_xfer_init_chan_event(void)
{
	int drops = XFER_TX_PKT_DROP_RATE;
	assert(sysctlbyname("net.link.fake.tx_drops",
	    NULL, 0, &drops, sizeof(drops)) == 0);

	skt_xfer_init_native();
}

static void
skt_xfer_fini_chan_event(void)
{
	skt_xfer_fini();
	int drops = 0;
	assert(sysctlbyname("net.link.fake.tx_drops",
	    NULL, 0, &drops, sizeof(drops)) == 0);
}

static void
skt_xfer_init_chan_event_async(void)
{
	int tx_compl_mode = 1; /* async mode */
	assert(sysctlbyname("net.link.fake.tx_completion_mode",
	    NULL, 0, &tx_compl_mode, sizeof(tx_compl_mode)) == 0);
	skt_xfer_init_chan_event();
}

static void
skt_xfer_fini_chan_event_async(void)
{
	int tx_compl_mode = 0; /* sync mode (default) */
	skt_xfer_fini_chan_event();
	assert(sysctlbyname("net.link.fake.tx_completion_mode",
	    NULL, 0, &tx_compl_mode, sizeof(tx_compl_mode)) == 0);
}

static void
skt_xfer_init_parent_child_flow(void)
{
	int err;
	uint32_t disable_nxctl_check = 1;
	size_t len = sizeof(skt_disable_nxctl_check);

	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_disable_nxctl_check, &len, &disable_nxctl_check,
	    sizeof(disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_TXSTART);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_init_parent_child_flow_native(void)
{
	int err;
	uint32_t disable_nxctl_check = 1;
	size_t len = sizeof(skt_disable_nxctl_check);

	sktc_set_classq_update_intervals(XFER_CLASSQ_UPDATE_INTERVAL *
	    1000 * 1000);
	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    &skt_disable_nxctl_check, &len, &disable_nxctl_check,
	    sizeof(disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth_pair_create(FETH_FLAGS_NATIVE);
	sktc_reset_classq_update_intervals();
	sktc_enable_ip_reass();
	sktc_config_fsw_rx_agg_tcp(0);
}

static void
skt_xfer_fini_parent_child_flow(void)
{
#if SKT_XFER_DEBUG
	T_LOG("Waiting");
	fflush(stdout);
	for (int i = 0; i < 5; i++) {
		sleep(1);
		T_LOG(".");
		fflush(stdout);
	}
	T_LOG("\n");
#endif
	int err;

	err = sysctlbyname("kern.skywalk.disable_nxctl_check",
	    NULL, NULL, &skt_disable_nxctl_check,
	    sizeof(skt_disable_nxctl_check));
	assert(err == 0);
	sktc_ifnet_feth0_set_dequeue_stall(FALSE);
	sktc_ifnet_feth1_set_dequeue_stall(FALSE);
	sktc_ifnet_feth_pair_destroy();
	sktc_restore_ip_reass();
	sktc_restore_fsw_rx_agg_tcp();
}

struct skywalk_mptest skt_xferudp = {
	"xferudp", "UDP bi-directional transfer over fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpn = {
	"xferudpn",
	"UDP bi-directional transfer over native fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpnsp = {
	"xferudpnsp",
	"UDP bi-directional transfer over native fake ethernet pair"
	" with split rx/tx pools",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_split_pools, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpfcs = {
	"xferudpfcs",
	"UDP bi-directional transfer over fake ethernet pair"
	" with link frame check sequence",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart_fcs, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudptrailer = {
	"xferudptrailer",
	"UDP bi-directional transfer over fake ethernet pair"
	" with link trailer",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart_trailer, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpnfcs = {
	"xferudpnfcs",
	"UDP bi-directional transfer over native fake ethernet pair"
	" with link frame check sequence",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_fcs, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpntrailer = {
	"xferudpntrailer",
	"UDP bi-directional transfer over native fake ethernet pair"
	" with link trailer",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_trailer, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudplong = {
	"xferudplong",
	"UDP bi-directional transfer over fake ethernet pair longer duration",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudplongn = {
	"xferudplongn",
	"UDP bi-directional transfer over"
	" native fake ethernet pair longer duration",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpoverwhelm = {
	"xferudpoverwhelm",
	"UDP bi-directional transfer over fake ethernet pair overwhelm",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_overwhelm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpoverwhelmn = {
	"xferudpoverwhelmn",
	"UDP bi-directional transfer over native fake ethernet pair overwhelm",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_overwhelm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpoverwhelmnsp = {
	"xferudpoverwhelmnsp",
	"UDP bi-directional transfer over native fake ethernet pair overwhelm"
	" with split rx/tx pools",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_overwhelm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_split_pools, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpoverwhelmlong = {
	"xferudpoverwhelmlong",
	"UDP bi-directional transfer over fake ethernet pair overwhelm long",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_overwhelm_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpoverwhelmlongn = {
	"xferudpoverwhelmlongn",
	"UDP bi-directional transfer over"
	" native fake ethernet pair overwhelm long",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_overwhelm_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpping = {
	"xferudpping", "UDP ping-pong over fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_DEFAULT)},
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingn = {
	"xferudppingn", "UDP ping-pong over native fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_DEFAULT)},
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpping1 = {
	"xferudpping1", "UDP ping-pong once over fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_one_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpping1n = {
	"xferudpping1n", "UDP ping-pong once over native fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_one_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppinglong = {
	"xferudppinglong",
	"UDP ping-pong over fake ethernet pair longer duration",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppinglongn = {
	"xferudppinglongn",
	"UDP ping-pong over native fake ethernet pair longer duration",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_long_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpping1wrong = {
	"xferudpping1wrong",
	"UDP ping-pong once over fake ethernet pair with wrong flow IDs",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_one_wrong_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferrdudpping = {
	"xferrdudpping",
	"UDP ping-pong between redirect and fake ethernet interface",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_rd_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_DEFAULT)},
	skt_xfer_rd_init, skt_xfer_rd_fini, {},
};

struct skywalk_mptest skt_xfertcpsynflood = {
	"xfertcpsynflood",
	"TCP SYN flood",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	1, skt_xfer_tcp_syn_flood_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xfertcprstflood = {
	"xfertcprstflood",
	"TCP RST flood",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	1, skt_xfer_tcp_rst_flood_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpping_aqm = {
	"xferudppingaqm", "UDP ping-pong over fake ethernet pair with AQM",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_aqm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingn_aqm = {
	"xferudppingnaqm", "UDP ping-pong over native fake ethernet pair with"
	" AQM",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_aqm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpwitherrors = {
	"xferudpwitherrors",
	"UDP bi-directional transfer over"
	" native fake ethernet pair with injected errors",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS |
	SK_FEATURE_DEV_OR_DEBUG,
	2, skt_xfer_udp_with_errors_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_errors_init, skt_xfer_errors_fini, {},
};

struct skywalk_mptest skt_xferudpwitherrorscompat = {
	"xferudpwitherrorscompat",
	"UDP bi-directional transfer over"
	" compat fake ethernet pair with injected errors",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS |
	SK_FEATURE_DEV_OR_DEBUG,
	2, skt_xfer_udp_with_errors_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_errors_compat_init, skt_xfer_errors_fini, {},
};

struct skywalk_mptest skt_xfertcpportzero = {
	"xfertcpportzero",
	"TCP connect to port 0",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	1, skt_xfer_tcp_port_zero_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpportzero = {
	"xferudpportzero",
	"UDP connect to port 0",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	1, skt_xfer_udp_port_zero_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xfersetuponly = {
	"xfersetuponly", "setup fake ethernet pair only",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_setuponly_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xfersetuponlyn = {
	"xfersetuponlyn", "setup native fake ethernet pair only",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_setuponly_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingn_wmm = {
	"xferudppingnwmm", "UDP ping-pong over native fake ethernet pair in wmm"
	" mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_wmm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_wmm, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferflowmatch = {
	"xferflowmatch",
	"Packets not matching registered flow tuple should be dropped",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_flowmatch_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferflowcleanup = {
	"xferflowcleanup",
	"verification of flow cleanup on channel close",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_flowcleanup_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingn_mb = {
	"xferudppingnmb", "UDP ping-pong over native fake ethernet pair with"
	" multi-buflet packet",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS |
	SK_FEATURE_DEV_OR_DEBUG,
	2, skt_xfer_udp_ping_pong_multi_buflet_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_multi_buflet, skt_xfer_multi_buflet_fini, {},
};

struct skywalk_mptest skt_xferudppingn_mbc = {
	"xferudppingnmbc", "UDP ping-pong over native fake ethernet pair with"
	" multi-buflet packet in copy packet mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS |
	SK_FEATURE_DEV_OR_DEBUG,
	2, skt_xfer_udp_ping_pong_multi_buflet_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_multi_buflet_copy, skt_xfer_multi_buflet_fini, {},
};

struct skywalk_mptest skt_xfercsumoffload = {
	"xfercsumoffload",
	"Packet checksum offload",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_csumoffload_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xfercsumoffloadn = {
	"xfercsumoffloadn",
	"Packet checksum offload over native",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_csumoffload_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferfastlane = {
	"xferqosmarking_fastlane",
	"fastlane qos marking",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_fastlane_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart_fastlane, skt_xfer_fini_fastlane, {},
};

struct skywalk_mptest skt_xferfastlanen = {
	"xferqosmarking_fastlanen",
	"fastlane qos marking over native",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_fastlane_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_fastlane, skt_xfer_fini_fastlane, {},
};

struct skywalk_mptest skt_xferrfc4594 = {
	"xferqosmarking_rfc4594",
	"rfc4594 qos marking",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_rfc4594_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_txstart_fastlane, skt_xfer_fini_fastlane, {},
};

struct skywalk_mptest skt_xferrfc4594n = {
	"xferqosmarking_rfc4594n",
	"rfc4594 qos marking over native",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_rfc4594_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native_fastlane, skt_xfer_fini_fastlane, {},
};

struct skywalk_mptest skt_xferlistenertcprst = {
	"xferlistenertcprst",
	"TCP Listner should be able to send RST",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_listener_tcp_rst_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpfrags = {
	"xferudpfrags",
	"UDP fragmentation test (channel flow Tx)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_frags_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpbadfrags = {
	"xferudpbadfrags",
	"UDP fragmentation test (channel flow Tx)",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_bad_frags_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudpifadvenable = {
	"xferudpifadvenable",
	"flowswitch interface advisory enabled test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ifadv_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_EVENT_TEST_IF_ADV_ENABLED)},
	skt_xfer_init_ifadv, skt_xfer_fini_ifadv, {},
};

struct skywalk_mptest skt_xferudpifadvdisable = {
	"xferudpifadvdisable",
	"flowswitch interface advisory disabled test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ifadv_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_EVENT_TEST_IF_ADV_DISABLED)},
	skt_xfer_init_ifadv, skt_xfer_fini_ifadv, {},
};

struct skywalk_mptest skt_xferudppingnll = {
	"xferudppingnll",
	"UDP ping-pong over low latency channel on native fake ethernet pair",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_LOW_LATENCY)},
	skt_xfer_init_native, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingllink = {
	"xferudppingllink", "UDP ping-pong over fake ethernet pair in llink mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_DEFAULT)},
	skt_xfer_init_llink, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingllink_wmm = {
	"xferudppingllinkwmm", "UDP ping-pong over fake ethernet pair in llink & wmm mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_wmm_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_llink_wmm, skt_xfer_fini, {},
};

struct skywalk_mptest skt_xferudppingllink_multi = {
	"xferudppingllinkmulti", "UDP ping-pong over fake ethernet pair in multi llink mode",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ping_pong_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_PING_PONG_TEST_MULTI_LLINK)},
	skt_xfer_init_llink_multi, skt_xfer_fini_llink_multi, {},
};

struct skywalk_mptest skt_xferudpchanevents = {
	"skt_xferudpchanevents",
	"flowswitch channel events test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ifadv_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_EVENT_TEST_CHANNEL_EVENTS)},
	skt_xfer_init_chan_event, skt_xfer_fini_chan_event, {},
};

struct skywalk_mptest skt_xferudpchaneventsasync = {
	"skt_xferudpchaneventsasync",
	"flowswitch channel events in async mode test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	2, skt_xfer_udp_ifadv_main,
	{ NULL, NULL, NULL, NULL, NULL,
	  STR(SKT_FSW_EVENT_TEST_CHANNEL_EVENTS)},
	skt_xfer_init_chan_event_async, skt_xfer_fini_chan_event_async, {},
};

struct skywalk_mptest skt_xferparentchildflow = {
	"skt_xferparentchild",
	"flowswitch parent child flows test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	3, skt_xfer_parent_child_flow_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_parent_child_flow, skt_xfer_fini_parent_child_flow, {},
};

struct skywalk_mptest skt_xferparentchildflow_offset_400 = {
	"skt_xferparentchild_offset_400",
	"flowswitch parent child flows test with demux offset 400",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	3, skt_xfer_parent_child_flow_main_offset_400,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_parent_child_flow, skt_xfer_fini_parent_child_flow, {},
};

struct skywalk_mptest skt_xferparentchildflown = {
	"skt_xferparentchildn",
	"flowswitch parent child flows on native fake ethernet interface test",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	3, skt_xfer_parent_child_flow_main,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_parent_child_flow_native, skt_xfer_fini_parent_child_flow, {},
};

struct skywalk_mptest skt_xferparentchildflown_offset_400 = {
	"skt_xferparentchildn_offset_400",
	"flowswitch parent child flows on native fake ethernet interface test with demux offset 400",
	SK_FEATURE_SKYWALK | SK_FEATURE_NEXUS_NETIF | SK_FEATURE_DEV_OR_DEBUG |
	SK_FEATURE_NEXUS_FLOWSWITCH | SK_FEATURE_NETNS,
	3, skt_xfer_parent_child_flow_main_offset_400,
	{ NULL, NULL, NULL, NULL, NULL, NULL },
	skt_xfer_init_parent_child_flow_native, skt_xfer_fini_parent_child_flow, {},
};
