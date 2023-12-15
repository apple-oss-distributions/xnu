/*
 * Copyright (c) 2015-2023 Apple Inc. All rights reserved.
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
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 *  BSD LICENSE
 *
 * Copyright(c) 2015 NEC Europe Ltd. All rights reserved.
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in
 *      the documentation and/or other materials provided with the
 *      distribution.
 *    * Neither the name of NEC Europe Ltd. nor the names of
 *      its contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/netif/nx_netif_compat.h>
#include <kern/sched_prim.h>
#include <sys/kdebug.h>
#include <sys/sdt.h>
#include <net/bpf.h>
#include <net/if_ports_used.h>
#include <net/pktap.h>
#include <net/pktsched/pktsched_netem.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/in_var.h>

extern kern_return_t thread_terminate(thread_t);

#define FSW_ZONE_MAX                  256
#define FSW_ZONE_NAME                 "skywalk.nx.fsw"

static uint64_t fsw_reap_last __sk_aligned(8);
static uint64_t fsw_want_purge __sk_aligned(8);

#define NX_FSW_FE_TABLESZ       256     /* some power of 2 */
static uint32_t fsw_fe_table_size = NX_FSW_FE_TABLESZ;

#define NX_FSW_FOB_HASHSZ       31      /* some mersenne prime */
static uint32_t fsw_flow_owner_buckets = NX_FSW_FOB_HASHSZ;

#define NX_FSW_FRB_HASHSZ       128     /* some power of 2 */
static uint32_t fsw_flow_route_buckets = NX_FSW_FRB_HASHSZ;

#define NX_FSW_FRIB_HASHSZ      13      /* some mersenne prime */
static uint32_t fsw_flow_route_id_buckets = NX_FSW_FRIB_HASHSZ;

#define NX_FSW_FLOW_REAP_INTERVAL 1     /* seconds */
static uint32_t fsw_flow_reap_interval = NX_FSW_FLOW_REAP_INTERVAL;

#define NX_FSW_FLOW_PURGE_THRES 0       /* purge every N reaps (0 = disable) */
static uint32_t fsw_flow_purge_thresh = NX_FSW_FLOW_PURGE_THRES;

#define FSW_REAP_IVAL            (MAX(1, fsw_flow_reap_interval))
#define FSW_REAP_SK_THRES        (FSW_REAP_IVAL << 5)
#define FSW_REAP_IF_THRES        (FSW_REAP_IVAL << 5)
#define FSW_DRAIN_CH_THRES       (FSW_REAP_IVAL << 5)
#define FSW_IFSTATS_THRES        1

#define NX_FSW_CHANNEL_REAP_THRES 1000  /* threshold (bytes/sec) for reaping*/
uint64_t fsw_channel_reap_thresh = NX_FSW_CHANNEL_REAP_THRES;

#define RX_BUFLET_BATCH_COUNT 64 /* max batch size for buflet allocation */

uint32_t fsw_rx_batch = NX_FSW_RXBATCH; /* # of packets per batch (RX) */
uint32_t fsw_tx_batch = NX_FSW_TXBATCH; /* # of packets per batch (TX) */
uint32_t fsw_gso_batch = 8;
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_batch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_rx_batch, 0,
    "flowswitch Rx batch size");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, tx_batch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_tx_batch, 0,
    "flowswitch Tx batch size");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, gso_batch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_gso_batch, 0,
    "flowswitch GSO batch size");
SYSCTL_QUAD(_kern_skywalk_flowswitch, OID_AUTO, reap_throughput,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_channel_reap_thresh,
    "flowswitch channel reap threshold throughput (bytes/sec)");
#endif /* !DEVELOPMENT && !DEBUG */

SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_agg_tcp,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_fsw_rx_agg_tcp, 0,
    "flowswitch RX aggregation for tcp flows (enable/disable)");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_agg_tcp_host,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_fsw_rx_agg_tcp_host, 0,
    "flowswitch RX aggregation for tcp kernel path (0/1/2 (off/on/auto))");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, gso_mtu,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_fsw_gso_mtu, 0,
    "flowswitch GSO for tcp flows (mtu > 0: enable, mtu == 0: disable)");

/*
 * IP reassembly
 * The "kern.skywalk.flowswitch.ip_reass" sysctl can be used to force
 * enable/disable the reassembly routine regardless of whether the
 * transport netagent is enabled or not.
 *
 * 'fsw_ip_reass' is a tri-state:
 *    0 means force IP reassembly off
 *    1 means force IP reassembly on
 *    2 means don't force the value, use what's appropriate for this flowswitch
 */
#define FSW_IP_REASS_FORCE_OFF          0
#define FSW_IP_REASS_FORCE_ON           1
#define FSW_IP_REASS_NO_FORCE           2

uint32_t fsw_ip_reass = FSW_IP_REASS_NO_FORCE;

static int
fsw_ip_reass_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, fsw_ip_reass, sizeof(fsw_ip_reass),
	    &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FSW_IP_REASS_NO_FORCE) {
			return EINVAL;
		}
		fsw_ip_reass = new_value;
	}
	return error;
}

SYSCTL_PROC(_kern_skywalk_flowswitch, OID_AUTO, ip_reass,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, fsw_ip_reass_sysctl, "IU",
    "adjust flowswitch IP reassembly");

#if (DEVELOPMENT || DEBUG)
static uint64_t _fsw_inject_error = 0;
#define _FSW_INJECT_ERROR(_en, _ev, _ec, _f, ...) \
	_SK_INJECT_ERROR(_fsw_inject_error, _en, _ev, _ec, \
	&FSW_STATS_VAL(_FSW_STATS_ERROR_INJECTIONS), _f, __VA_ARGS__)

#define _FSW_INJECT_ERROR_SET(_en, _f, ...) do { \
	if (__improbable(((_fsw_inject_error) & (1ULL << (_en))) != 0)) { \
	        SK_DF(SK_VERB_ERROR_INJECT, "injecting error %d", (_en));\
	        if ((_f) != NULL)                                       \
	                (_f)(__VA_ARGS__);                              \
	}                                                               \
} while (0)

SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, flow_owner_buckets,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_flow_owner_buckets, 0, "");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, fe_table_size,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_fe_table_size, 0, "");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, flow_route_buckets,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_flow_route_buckets, 0, "");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO,
    flow_route_id_buckets, CTLFLAG_RW | CTLFLAG_LOCKED,
    &fsw_flow_route_id_buckets, 0, "");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, flow_reap_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_flow_reap_interval, 0, "");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, flow_purge_thresh,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_flow_purge_thresh, 0, "");
SYSCTL_QUAD(_kern_skywalk_flowswitch, OID_AUTO, fsw_inject_error,
    CTLFLAG_RW | CTLFLAG_LOCKED, &_fsw_inject_error, "");
#else
#define _FSW_INJECT_ERROR(_en, _ev, _ec, _f, ...) do { } while (0)
#define _FSW_INJECT_ERROR_SET(_en, _f, ...) do { } while (0)
#endif /* !DEVELOPMENT && !DEBUG */

static void fsw_linger_remove_internal(struct flow_entry_linger_head *,
    struct flow_entry *);
static void fsw_reap_thread_func(void *, wait_result_t);
static void fsw_reap_thread_cont(void *, wait_result_t);
static void fsw_purge_cache(struct nx_flowswitch *, boolean_t);
static void fsw_drain_channels(struct nx_flowswitch *, uint64_t, boolean_t);
static uint32_t fsw_process_deferred(struct nx_flowswitch *);
static uint32_t fsw_process_linger(struct nx_flowswitch *, uint32_t *);

static int copy_packet_from_dev(struct nx_flowswitch *, struct __kern_packet *,
    struct __kern_packet *);

static void fsw_ifp_inc_traffic_class_in_pkt(struct ifnet *, kern_packet_t);
static void fsw_ifp_inc_traffic_class_out_pkt(struct ifnet *, uint32_t,
    uint32_t, uint32_t);

static int __fsw_dp_inited = 0;

int
fsw_dp_init(void)
{
	_CASSERT(FSW_VP_DEV == 0);
	_CASSERT(FSW_VP_HOST == 1);
	_CASSERT((FSW_VP_HOST + FSW_VP_DEV) < FSW_VP_USER_MIN);
	_CASSERT((FSW_VP_HOST + FSW_VP_DEV) < NEXUS_PORT_FLOW_SWITCH_CLIENT);

	ASSERT(!__fsw_dp_inited);

	flow_mgr_init();
	flow_init();

	__fsw_dp_inited = 1;

	return 0;
}

void
fsw_dp_uninit(void)
{
	if (__fsw_dp_inited) {
		flow_fini();
		flow_mgr_fini();

		__fsw_dp_inited = 0;
	}
}

static void
dp_free_pktq(struct nx_flowswitch *fsw __sk_unused, struct pktq *pktq)
{
	pp_free_pktq(pktq);
}

#define dp_drop_pktq(fsw, pktq) do { \
	uint32_t _len = KPKTQ_LEN(pktq); \
	if (KPKTQ_EMPTY(pktq)) { \
	        ASSERT(_len == 0); \
	        return; \
	} \
	SK_DF(SK_VERB_FSW_DP | SK_VERB_DROP, "drop %d packets", _len); \
	FSW_STATS_ADD(FSW_STATS_DROP, _len); \
	DTRACE_SKYWALK1(fsw__dp__drop, int, _len); \
	dp_free_pktq(fsw, pktq); \
} while (0)

SK_NO_INLINE_ATTRIBUTE
void
fsw_snoop(struct nx_flowswitch *fsw, struct flow_entry *fe, bool input)
{
	pid_t pid;
	char proc_name_buf[FLOW_PROCESS_NAME_LENGTH];
	char *proc_name = NULL;
	pid_t epid;
	char eproc_name_buf[FLOW_PROCESS_NAME_LENGTH];
	char *eproc_name = NULL;
	sa_family_t af;
	bool tap_early = false;
	struct __kern_packet *pkt;

	ASSERT(fe != NULL);
	ASSERT(fsw->fsw_ifp != NULL);

	if (fe->fe_nx_port == FSW_VP_HOST) {
		/* allow packets to be tapped before aggregation happens */
		tap_early = (input && fe->fe_key.fk_proto == IPPROTO_TCP);
		if (!tap_early) {
			/* all other traffic will be tapped in the dlil input path */
			return;
		}
	}
	if (fe->fe_key.fk_ipver == IPVERSION) {
		af = AF_INET;
	} else if (fe->fe_key.fk_ipver == IPV6_VERSION) {
		af = AF_INET6;
	} else {
		return;
	}

	pid = fe->fe_pid;
	if (fe->fe_proc_name[0] != '\0') {
		(void) strlcpy(proc_name_buf, fe->fe_proc_name,
		    sizeof(proc_name_buf));
		proc_name = proc_name_buf;
	}
	epid = fe->fe_epid;
	if (fe->fe_eproc_name[0] != '\0') {
		(void) strlcpy(eproc_name_buf, fe->fe_eproc_name,
		    sizeof(eproc_name_buf));
		eproc_name = eproc_name_buf;
	}
	if (input) {
		KPKTQ_FOREACH(pkt, &fe->fe_rx_pktq) {
			pktap_input_packet(fsw->fsw_ifp, af,
			    fsw->fsw_ifp_dlt, pid, proc_name, epid,
			    eproc_name, SK_PKT2PH(pkt), NULL, 0,
			    IPPROTO_TCP, fe->fe_flowid,
			    tap_early ? PTH_FLAG_SOCKET: PTH_FLAG_NEXUS_CHAN);
		}
	} else {
		KPKTQ_FOREACH(pkt, &fe->fe_tx_pktq) {
			pktap_output_packet(fsw->fsw_ifp, af,
			    fsw->fsw_ifp_dlt, pid, proc_name, epid,
			    eproc_name, SK_PKT2PH(pkt), NULL, 0,
			    0, 0, PTH_FLAG_NEXUS_CHAN);
		}
	}
}

#if (DEVELOPMENT || DEBUG)
static void
_fsw_error35_handler(int step, struct flow_route *fr, struct __kern_packet *pkt,
    int *ret)
{
	static boolean_t _err35_flag_modified = FALSE;

	switch (step) {
	case 1:
		if ((fr->fr_flags & (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO)) ==
		    (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO)) {
			fr->fr_flags &= ~FLOWRTF_RESOLVED;
			_err35_flag_modified = TRUE;
		}
		break;

	case 2:
		if (!_err35_flag_modified) {
			return;
		}
		if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
			m_freem(pkt->pkt_mbuf);
			pkt->pkt_pflags &= ~PKT_F_MBUF_DATA;
			pkt->pkt_mbuf = NULL;
		}
		*ret = EJUSTRETURN;
		fr->fr_flags |= FLOWRTF_RESOLVED;
		_err35_flag_modified = FALSE;
		break;

	default:
		VERIFY(0);
		/* not reached */
	}
}

static void
_fsw_error36_handler(int step, struct flow_route *fr, int *ret)
{
	static boolean_t _err36_flag_modified = FALSE;

	switch (step) {
	case 1:
		if ((fr->fr_flags & (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO)) ==
		    (FLOWRTF_RESOLVED | FLOWRTF_HAS_LLINFO)) {
			fr->fr_flags &= ~FLOWRTF_RESOLVED;
			_err36_flag_modified = TRUE;
		}
		break;

	case 2:
		if (!_err36_flag_modified) {
			return;
		}
		*ret = ENETUNREACH;
		fr->fr_flags |= FLOWRTF_RESOLVED;
		_err36_flag_modified = FALSE;
		break;

	default:
		VERIFY(0);
		/* not reached */
	}
}
#else /* !DEVELOPMENT && !DEBUG */
#define _fsw_error35_handler(...)
#define _fsw_error36_handler(...)
#endif /* DEVELOPMENT || DEBUG */

/*
 * Check if the source packet content can fit into the destination
 * ring's packet. Returns TRUE if the source packet can fit.
 * Note: Failures could be caused by misconfigured packet pool sizes,
 * missing packet size check again MTU or if the source packet is from
 * a compat netif and the attached mbuf is larger than MTU due to LRO.
 */
static inline boolean_t
validate_pkt_len(struct __kern_packet *spkt, kern_packet_t dph,
    uint32_t skip_l2hlen, uint32_t l2hlen, uint16_t headroom,
    uint32_t *copy_len)
{
	uint32_t tlen = 0;
	uint32_t splen = spkt->pkt_length - skip_l2hlen;

	if (l2hlen != 0) {
		VERIFY(skip_l2hlen == 0);
		tlen += l2hlen;
	} else if ((spkt->pkt_link_flags & PKT_LINKF_ETHFCS) != 0) {
		splen -= ETHER_CRC_LEN;
	}

	tlen += splen;
	*copy_len = splen;

	return tlen <= ((__packet_get_buflet_count(dph) *
	       PP_BUF_SIZE_DEF(SK_PTR_ADDR_KPKT(dph)->pkt_qum.qum_pp)) -
	       headroom);
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
copy_packet_from_dev_log(struct __kern_packet *spkt,
    struct __kern_packet *dpkt, struct proc *p)
{
	uint64_t logflags = ((SK_VERB_FSW | SK_VERB_RX) |
	    ((spkt->pkt_pflags & PKT_F_MBUF_DATA) ?
	    SK_VERB_COPY_MBUF : SK_VERB_COPY));
	char *daddr;
	MD_BUFLET_ADDR_ABS(dpkt, daddr);
	SK_DF(logflags, "%s(%d) splen %u dplen %u hr %u l2 %u",
	    sk_proc_name_address(p), sk_proc_pid(p), spkt->pkt_length,
	    dpkt->pkt_length, (uint32_t)dpkt->pkt_headroom,
	    (uint32_t)dpkt->pkt_l2_len);
	SK_DF(logflags | SK_VERB_DUMP, "%s",
	    sk_dump("buf", daddr, dpkt->pkt_length, 128, NULL, 0));
}
#else
#define copy_packet_from_dev_log(...)
#endif /* SK_LOG */


static inline int
copy_packet_from_dev(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	/*
	 * source and destination nexus don't share the packet pool
	 * sync operation here is to
	 * - alloc packet for the rx(dst) ring
	 * - copy data/metadata from src packet to dst packet
	 * - attach alloc'd packet to rx(dst) ring
	 */
	kern_packet_t dph = SK_PTR_ENCODE(dpkt,
	    METADATA_TYPE(dpkt), METADATA_SUBTYPE(dpkt));
	kern_packet_t sph = SK_PTR_ENCODE(spkt, METADATA_TYPE(spkt),
	    METADATA_SUBTYPE(spkt));
	boolean_t do_cksum_rx;
	uint16_t skip_l2h_len = spkt->pkt_l2_len;
	uint16_t iphlen;
	uint32_t dlen;
	int err;

	if (__improbable(!validate_pkt_len(spkt, dph, skip_l2h_len, 0, 0,
	    &dlen))) {
		SK_ERR("bufcnt %d, bufsz %d", __packet_get_buflet_count(dph),
		    PP_BUF_SIZE_DEF(dpkt->pkt_qum.qum_pp));
		FSW_STATS_INC(FSW_STATS_RX_COPY_BAD_LEN);
		return EINVAL;
	}

	/* Copy packet metadata */
	_QUM_COPY(&(spkt)->pkt_qum, &(dpkt)->pkt_qum);
	_PKT_COPY(spkt, dpkt);
	ASSERT(!(dpkt->pkt_qum.qum_qflags & QUM_F_KERNEL_ONLY) ||
	    PP_KERNEL_ONLY(dpkt->pkt_qum.qum_pp));
	ASSERT(dpkt->pkt_mbuf == NULL);

	dpkt->pkt_headroom = 0;
	dpkt->pkt_l2_len = 0;

	/* don't include IP header from partial sum */
	if (__probable((spkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED) != 0)) {
		iphlen = spkt->pkt_flow_ip_hlen;
		do_cksum_rx = sk_cksum_rx;
	} else {
		iphlen = 0;
		do_cksum_rx = FALSE;
	}

	/* Copy packet payload */
	if ((spkt->pkt_pflags & PKT_F_MBUF_DATA) &&
	    (spkt->pkt_pflags & PKT_F_TRUNCATED)) {
		FSW_STATS_INC(FSW_STATS_RX_COPY_MBUF2PKT);
		/*
		 * Source packet has truncated contents (just enough for
		 * the classifer) of an mbuf from the compat driver; copy
		 * the entire entire mbuf contents to destination packet.
		 */
		m_adj(spkt->pkt_mbuf, skip_l2h_len);
		ASSERT((uint32_t)m_pktlen(spkt->pkt_mbuf) >= dlen);
		fsw->fsw_pkt_copy_from_mbuf(NR_RX, dph, 0,
		    spkt->pkt_mbuf, 0, dlen, do_cksum_rx, iphlen);
	} else {
		FSW_STATS_INC(FSW_STATS_RX_COPY_PKT2PKT);
		/*
		 * Source packet has full contents, either from an mbuf
		 * that came up from the compat driver, or because it
		 * originated on the native driver; copy to destination.
		 */
		fsw->fsw_pkt_copy_from_pkt(NR_RX, dph, 0, sph,
		    (spkt->pkt_headroom + spkt->pkt_l2_len), dlen, do_cksum_rx,
		    iphlen, 0, FALSE);
	}

#if DEBUG || DEVELOPMENT
	if (__improbable(pkt_trailers > 0)) {
		dlen += pkt_add_trailers(dph, dlen, iphlen);
	}
#endif /* DEBUG || DEVELOPMENT */

	/* Finalize and attach packet to Rx ring */
	METADATA_ADJUST_LEN(dpkt, 0, 0);
	err = __packet_finalize(dph);
	VERIFY(err == 0);

	copy_packet_from_dev_log(spkt, dpkt, kernproc);

	if (spkt->pkt_pflags & PKT_F_MBUF_DATA) {
		ifp_inc_traffic_class_in(fsw->fsw_ifp, spkt->pkt_mbuf);
		mbuf_free(spkt->pkt_mbuf);
		KPKT_CLEAR_MBUF_DATA(spkt);
	} else {
		fsw_ifp_inc_traffic_class_in_pkt(fsw->fsw_ifp, dph);
	}

	if (__probable(do_cksum_rx != 0)) {
		FSW_STATS_INC(FSW_STATS_RX_COPY_SUM);
	}

	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static struct __kern_packet *
rx_process_ip_frag(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	char *pkt_buf;
	void *l3_hdr;
	uint16_t nfrags, tlen;
	int err = 0;

	switch (fsw_ip_reass) {
	case FSW_IP_REASS_FORCE_OFF:
		return pkt;
	case FSW_IP_REASS_FORCE_ON:
		break;
	default:
		if (!FSW_NETAGENT_ENABLED(fsw) ||
		    flow_mgr_get_num_flows(fsw->fsw_flow_mgr) == 0) {
			return pkt;
		}
		break;
	}

	MD_BUFLET_ADDR_ABS(pkt, pkt_buf);
	l3_hdr = pkt_buf + pkt->pkt_headroom + pkt->pkt_l2_len;

	ASSERT(fsw->fsw_ipfm != NULL);
	ASSERT((pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED) != 0);

	if (pkt->pkt_flow_ip_ver == IPVERSION) {
		err = fsw_ip_frag_reass_v4(fsw->fsw_ipfm, &pkt,
		    (struct ip *)l3_hdr, &nfrags, &tlen);
	} else {
		ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);
		/* we only handle frag header immediately after v6 header */
		err = fsw_ip_frag_reass_v6(fsw->fsw_ipfm, &pkt,
		    (struct ip6_hdr *)l3_hdr,
		    (struct ip6_frag *)((uintptr_t)l3_hdr + sizeof(struct ip6_hdr)),
		    &nfrags, &tlen);
	}
	if (__improbable(err != 0)) {
		/* if we get a bad fragment, free it */
		pp_free_packet_single(pkt);
		pkt = NULL;
	} else {
		ASSERT(!((pkt != NULL) ^ (nfrags > 0)));
	}

	return pkt;
}

SK_NO_INLINE_ATTRIBUTE
static void
rx_prepare_packet_mbuf(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	ASSERT(pkt->pkt_pflags & PKT_F_MBUF_DATA);
	uint32_t mlen = (uint32_t)m_pktlen(pkt->pkt_mbuf);
	kern_packet_t ph =  SK_PTR_ENCODE(pkt,
	    METADATA_TYPE(pkt), METADATA_SUBTYPE(pkt));
	/*
	 * This is the case when the packet is coming in from
	 * compat-netif. This packet only has valid metadata
	 * and an attached mbuf. We need to copy enough data
	 * from the mbuf to the packet buffer for the
	 * classifier. Compat netif packet pool is configured
	 * with buffer size of NETIF_COMPAT_MAX_MBUF_DATA_COPY
	 * which is just enough to hold the protocol headers
	 * for the flowswitch classifier.
	 */

	pkt->pkt_headroom = 0;
	METADATA_ADJUST_LEN(pkt, 0, 0);
	/*
	 * Copy the initial 128 bytes of the packet for
	 * classification.
	 * Ethernet(14) + IPv6 header(40) +
	 * + IPv6 fragment header(8) +
	 * TCP header with options(60).
	 */
	fsw->fsw_pkt_copy_from_mbuf(NR_RX, ph,
	    pkt->pkt_headroom, pkt->pkt_mbuf, 0,
	    MIN(mlen, NETIF_COMPAT_MAX_MBUF_DATA_COPY),
	    FALSE, 0);

	int err = __packet_finalize_with_mbuf(pkt);
	VERIFY(err == 0);
}

static struct __kern_packet *
rx_prepare_packet(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	pkt->pkt_qum_qflags &= ~QUM_F_FLOW_CLASSIFIED;

	if (__improbable(pkt->pkt_pflags & PKT_F_MBUF_DATA)) {
		rx_prepare_packet_mbuf(fsw, pkt);
	}

	return pkt;
}

static struct flow_entry *
lookup_flow_with_pkt(struct nx_flowswitch *fsw, struct __kern_packet *pkt,
    bool input, struct flow_entry *prev_fe)
{
	struct flow_key key __sk_aligned(16);
	struct flow_entry *fe = NULL;

	ASSERT(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED);
	flow_pkt2key(pkt, input, &key);

	if (__probable(prev_fe != NULL &&
	    prev_fe->fe_key.fk_mask == FKMASK_5TUPLE)) {
		uint16_t saved_mask = key.fk_mask;
		key.fk_mask = FKMASK_5TUPLE;
		if (flow_key_cmp_mask(&prev_fe->fe_key, &key, &fk_mask_5tuple) == 0) {
			flow_entry_retain(prev_fe);
			fe = prev_fe;
		} else {
			key.fk_mask = saved_mask;
		}
	}

top:
	if (__improbable(fe == NULL)) {
		fe = flow_mgr_find_fe_by_key(fsw->fsw_flow_mgr, &key);
	}

	if (__improbable(fe != NULL &&
	    (fe->fe_flags & (FLOWENTF_PARENT | FLOWENTF_CHILD)) != 0)) {
		/* Rx */
		if (input) {
			if (fe->fe_flags & FLOWENTF_PARENT) {
				struct flow_entry *child_fe = rx_lookup_child_flow(fsw, fe, pkt);
				if (child_fe != NULL) {
					flow_entry_release(&fe);
					fe = child_fe;
				}
			} else {
				if (!rx_flow_demux_match(fsw, fe, pkt)) {
					flow_entry_release(&fe);
					fe = NULL;
					goto top;
				}
			}
		} else {
			/* Tx */
			if (__improbable(!_UUID_MATCH(pkt->pkt_flow_id, fe->fe_uuid))) {
				if (__probable(fe->fe_flags & FLOWENTF_PARENT)) {
					struct flow_entry *parent_fe = fe;
					fe = tx_lookup_child_flow(parent_fe, pkt->pkt_flow_id);
					flow_entry_release(&parent_fe);
				} else {
					flow_entry_release(&fe);
					fe = NULL;
					goto top;
				}
			}
		}
	}

	SK_LOG_VAR(char fkbuf[FLOWKEY_DBGBUF_SIZE]);
	SK_DF(SK_VERB_FSW_DP | SK_VERB_LOOKUP,
	    "%s %s %s \"%s\" fe 0x%llx",
	    input ? "Rx" : "Tx", if_name(fsw->fsw_ifp),
	    sk_proc_name_address(current_proc()),
	    fk_as_string(&key, fkbuf, sizeof(fkbuf)),
	    SK_KVA(fe));

	return fe;
}

SK_NO_INLINE_ATTRIBUTE
static bool
pkt_is_for_listener(struct flow_entry *fe, struct __kern_packet *pkt)
{
	struct nx_flowswitch *fsw = fe->fe_fsw;
	struct ifnet *ifp = fsw->fsw_ifp;
	struct in_ifaddr *ia = NULL;
	struct in_ifaddr *best_ia = NULL;
	struct in6_ifaddr *ia6 = NULL;
	struct in6_ifaddr *best_ia6 = NULL;
	struct ifnet *match_ifp = NULL;
	struct __flow *flow = pkt->pkt_flow;
	bool result = false;

	ASSERT(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED);

	if (flow->flow_ip_ver == IPVERSION) {
		if (IN_ZERONET(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    IN_LOOPBACK(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    IN_LINKLOCAL(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    IN_DS_LITE(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    IN_6TO4_RELAY_ANYCAST(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    IN_MULTICAST(ntohl(flow->flow_ipv4_dst.s_addr)) ||
		    INADDR_BROADCAST == flow->flow_ipv4_dst.s_addr) {
			result = true;
			goto done;
		}

		/*
		 * Check for a match in the hash bucket.
		 */
		lck_rw_lock_shared(&in_ifaddr_rwlock);
		TAILQ_FOREACH(ia, INADDR_HASH(flow->flow_ipv4_dst.s_addr), ia_hash) {
			if (IA_SIN(ia)->sin_addr.s_addr == flow->flow_ipv4_dst.s_addr) {
				best_ia = ia;
				match_ifp = ia->ia_ifp;

				if (match_ifp == ifp) {
					break;
				}
				/*
				 * Continue the loop in case there's a exact match with another
				 * interface
				 */
			}
		}

		if (best_ia != NULL) {
			if (match_ifp != ifp && ipforwarding == 0 &&
			    (match_ifp->if_family == IFNET_FAMILY_IPSEC ||
			    match_ifp->if_family == IFNET_FAMILY_UTUN)) {
				/*
				 * Drop when interface address check is strict and forwarding
				 * is disabled
				 */
			} else {
				lck_rw_done(&in_ifaddr_rwlock);
				result = true;
				goto done;
			}
		}
		lck_rw_done(&in_ifaddr_rwlock);

		if (ifp->if_flags & IFF_BROADCAST) {
			/*
			 * Check for broadcast addresses.
			 *
			 * Only accept broadcast packets that arrive via the matching
			 * interface.  Reception of forwarded directed broadcasts would be
			 * handled via ip_forward() and ether_frameout() with the loopback
			 * into the stack for SIMPLEX interfaces handled by ether_frameout().
			 */
			struct ifaddr *ifa;

			ifnet_lock_shared(ifp);
			TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
				if (ifa->ifa_addr->sa_family != AF_INET) {
					continue;
				}
				ia = ifatoia(ifa);
				if (satosin(&ia->ia_broadaddr)->sin_addr.s_addr == flow->flow_ipv4_dst.s_addr ||
				    ia->ia_netbroadcast.s_addr == flow->flow_ipv4_dst.s_addr) {
					ifnet_lock_done(ifp);
					result = true;
					goto done;
				}
			}
			ifnet_lock_done(ifp);
		}
	} else {
		if (IN6_IS_ADDR_LOOPBACK(&flow->flow_ipv6_dst) ||
		    IN6_IS_ADDR_LINKLOCAL(&flow->flow_ipv6_dst) ||
		    IN6_IS_ADDR_MULTICAST(&flow->flow_ipv6_dst)) {
			result = true;
			goto done;
		}

		/*
		 * Check for exact addresses in the hash bucket.
		 */
		lck_rw_lock_shared(&in6_ifaddr_rwlock);
		TAILQ_FOREACH(ia6, IN6ADDR_HASH(&flow->flow_ipv6_dst), ia6_hash) {
			if (in6_are_addr_equal_scoped(&ia6->ia_addr.sin6_addr, &flow->flow_ipv6_dst, ia6->ia_ifp->if_index, ifp->if_index)) {
				if ((ia6->ia6_flags & (IN6_IFF_NOTREADY | IN6_IFF_CLAT46))) {
					continue;
				}
				best_ia6 = ia6;
				if (ia6->ia_ifp == ifp) {
					break;
				}
				/*
				 * Continue the loop in case there's a exact match with another
				 * interface
				 */
			}
		}
		if (best_ia6 != NULL) {
			if (best_ia6->ia_ifp != ifp && ip6_forwarding == 0 &&
			    (best_ia6->ia_ifp->if_family == IFNET_FAMILY_IPSEC ||
			    best_ia6->ia_ifp->if_family == IFNET_FAMILY_UTUN)) {
				/*
				 * Drop when interface address check is strict and forwarding
				 * is disabled
				 */
			} else {
				lck_rw_done(&in6_ifaddr_rwlock);
				result = true;
				goto done;
			}
		}
		lck_rw_done(&in6_ifaddr_rwlock);
	}

	/*
	 * In forwarding mode, if the destination address
	 * of the packet does not match any interface
	 * address, it maybe destined to the client device
	 */
	SK_DF(SK_VERB_FSW_DP | SK_VERB_RX | SK_VERB_FLOW,
	    "Rx flow does not match interface address");
done:
	return result;
}

static struct flow_entry *
rx_lookup_flow(struct nx_flowswitch *fsw, struct __kern_packet *pkt,
    struct flow_entry *prev_fe)
{
	struct flow_entry *fe;

	fe = lookup_flow_with_pkt(fsw, pkt, true, prev_fe);
	_FSW_INJECT_ERROR(2, fe, NULL, flow_entry_release, &fe);
	if (fe == NULL) {
		FSW_STATS_INC(FSW_STATS_RX_FLOW_NOT_FOUND);
		return NULL;
	}

	if (__improbable(fe->fe_key.fk_mask == FKMASK_2TUPLE &&
	    fe->fe_flags & FLOWENTF_LISTENER) &&
	    !pkt_is_for_listener(fe, pkt)) {
		FSW_STATS_INC(FSW_STATS_RX_PKT_NOT_LISTENER);
		flow_entry_release(&fe);
		return NULL;
	}

	if (__improbable(fe->fe_flags & FLOWENTF_TORN_DOWN)) {
		FSW_STATS_INC(FSW_STATS_RX_FLOW_TORNDOWN);
		SK_DF(SK_VERB_FSW_DP | SK_VERB_RX | SK_VERB_FLOW,
		    "Rx flow torn down");
		flow_entry_release(&fe);
		fe = NULL;
	}

	return fe;
}

static inline void
rx_flow_batch_packet(struct flow_entry_list *fes, struct flow_entry *fe,
    struct __kern_packet *pkt)
{
	if (__improbable(pkt->pkt_flow_ip_is_frag)) {
		fe->fe_rx_frag_count++;
	}

	/* KPKTQ_ENQUEUE_LIST is needed until frags become chained buflet */
	if (KPKTQ_EMPTY(&fe->fe_rx_pktq)) {
		ASSERT(KPKTQ_LEN(&fe->fe_rx_pktq) == 0);
		TAILQ_INSERT_TAIL(fes, fe, fe_rx_link);
		KPKTQ_ENQUEUE_LIST(&fe->fe_rx_pktq, pkt);
	} else {
		ASSERT(!TAILQ_EMPTY(fes));
		KPKTQ_ENQUEUE_LIST(&fe->fe_rx_pktq, pkt);
		flow_entry_release(&fe);
	}
}

static void
tx_flow_batch_packet(struct flow_entry_list *fes, struct flow_entry *fe,
    struct __kern_packet *pkt)
{
	/* record frag continuation */
	if (__improbable(pkt->pkt_flow_ip_is_first_frag)) {
		ASSERT(pkt->pkt_flow_ip_is_frag);
		fe->fe_tx_is_cont_frag = true;
		fe->fe_tx_frag_id = pkt->pkt_flow_ip_frag_id;
	} else if (__probable(!pkt->pkt_flow_ip_is_frag)) {
		fe->fe_tx_is_cont_frag = false;
		fe->fe_tx_frag_id = 0;
	}

	if (KPKTQ_EMPTY(&fe->fe_tx_pktq)) {
		ASSERT(KPKTQ_LEN(&fe->fe_tx_pktq) == 0);
		TAILQ_INSERT_TAIL(fes, fe, fe_tx_link);
		KPKTQ_ENQUEUE(&fe->fe_tx_pktq, pkt);
	} else {
		ASSERT(!TAILQ_EMPTY(fes));
		KPKTQ_ENQUEUE(&fe->fe_tx_pktq, pkt);
		flow_entry_release(&fe);
	}
}

static inline void
fsw_rx_ring_dequeue_pktq(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    uint32_t n_pkts_max, struct pktq *pktq, uint32_t *n_bytes)
{
	uint32_t n_pkts = 0;
	slot_idx_t idx, idx_end;
	idx = r->ckr_khead;
	idx_end = r->ckr_rhead;

	ASSERT(KPKTQ_EMPTY(pktq));
	*n_bytes = 0;
	for (; n_pkts < n_pkts_max && idx != idx_end;
	    idx = SLOT_NEXT(idx, r->ckr_lim)) {
		struct __kern_slot_desc *ksd = KR_KSD(r, idx);
		struct __kern_packet *pkt = ksd->sd_pkt;

		ASSERT(pkt->pkt_nextpkt == NULL);
		KR_SLOT_DETACH_METADATA(r, ksd);

		_FSW_INJECT_ERROR(20, pkt->pkt_qum_qflags,
		    pkt->pkt_qum_qflags | QUM_F_DROPPED, null_func);
		if (__improbable(((pkt->pkt_qum_qflags & QUM_F_DROPPED) != 0))
		    || (pkt->pkt_length == 0)) {
			FSW_STATS_INC(FSW_STATS_DROP);
			pp_free_packet_single(pkt);
			continue;
		}
		n_pkts++;
		*n_bytes += pkt->pkt_length;

		KPKTQ_ENQUEUE(pktq, pkt);
	}
	r->ckr_khead = idx;
	r->ckr_ktail = SLOT_PREV(idx, r->ckr_lim);
}

/*
 * This is only for estimating how many packets each GSO packet will need.
 * The number does not need to be exact because any leftover packets allocated
 * will be freed.
 */
static uint32_t
estimate_gso_pkts(struct __kern_packet *pkt)
{
	packet_tso_flags_t tso_flags;
	uint16_t mss;
	uint32_t n_pkts = 0, total_hlen = 0, total_len = 0;

	tso_flags = pkt->pkt_csum_flags & PACKET_CSUM_TSO_FLAGS;
	mss = pkt->pkt_proto_seg_sz;

	if (tso_flags == PACKET_TSO_IPV4) {
		total_hlen = sizeof(struct ip) + sizeof(struct tcphdr);
	} else if (tso_flags == PACKET_TSO_IPV6) {
		total_hlen = sizeof(struct ip6_hdr) + sizeof(struct tcphdr);
	}
	if (total_hlen != 0 && mss != 0) {
		total_len = pkt->pkt_length;
		n_pkts = (uint32_t)
		    (SK_ROUNDUP((total_len - total_hlen), mss) / mss);
	}
	DTRACE_SKYWALK5(estimate__gso, packet_tso_flags_t, tso_flags,
	    uint32_t, total_hlen, uint32_t, total_len, uint16_t, mss,
	    uint32_t, n_pkts);
	return n_pkts;
}

/*
 * This function retrieves a chain of packets of the same type only
 * (GSO or non-GSO).
 */
static inline void
fsw_tx_ring_dequeue_pktq(struct nx_flowswitch *fsw,
    struct __kern_channel_ring *r, uint32_t n_pkts_max,
    struct pktq *pktq, uint32_t *n_bytes, uint32_t *gso_pkts_estimate)
{
	uint32_t n_pkts = 0;
	slot_idx_t idx, idx_end;
	idx = r->ckr_khead;
	idx_end = r->ckr_rhead;
	struct nexus_vp_adapter *vpna = VPNA(KRNA(r));
	boolean_t gso_enabled, gso_required;
	uint32_t gso_pkts;

	gso_enabled = (fsw->fsw_tso_mode == FSW_TSO_MODE_SW);
	ASSERT(KPKTQ_EMPTY(pktq));
	*n_bytes = 0;
	for (; n_pkts < n_pkts_max &&
	    (!gso_enabled || fsw_gso_batch == 0 ||
	    *gso_pkts_estimate < fsw_gso_batch) &&
	    idx != idx_end; idx = SLOT_NEXT(idx, r->ckr_lim)) {
		struct __kern_slot_desc *ksd = KR_KSD(r, idx);
		struct __kern_packet *pkt = ksd->sd_pkt;

		ASSERT(pkt->pkt_nextpkt == NULL);

		_FSW_INJECT_ERROR(20, pkt->pkt_qum_qflags,
		    pkt->pkt_qum_qflags | QUM_F_DROPPED, null_func);
		if (__improbable(((pkt->pkt_qum_qflags & QUM_F_DROPPED) != 0))
		    || (pkt->pkt_length == 0)) {
			KR_SLOT_DETACH_METADATA(r, ksd);
			FSW_STATS_INC(FSW_STATS_DROP);
			pp_free_packet_single(pkt);
			continue;
		}
		if (gso_enabled) {
			gso_pkts = estimate_gso_pkts(pkt);

			/*
			 * We use the first packet to determine what
			 * type the subsequent ones need to be (GSO or
			 * non-GSO).
			 */
			if (n_pkts == 0) {
				gso_required = (gso_pkts != 0);
			} else {
				if (gso_required != (gso_pkts != 0)) {
					break;
				}
			}
			*gso_pkts_estimate += gso_pkts;
		}
		KR_SLOT_DETACH_METADATA(r, ksd);
		if (NA_CHANNEL_EVENT_ATTACHED(&vpna->vpna_up)) {
			__packet_set_tx_nx_port(SK_PKT2PH(pkt),
			    vpna->vpna_nx_port, vpna->vpna_gencnt);
		}
		n_pkts++;
		*n_bytes += pkt->pkt_length;
		KPKTQ_ENQUEUE(pktq, pkt);
	}
	r->ckr_khead = idx;
	r->ckr_ktail = SLOT_PREV(idx, r->ckr_lim);
	DTRACE_SKYWALK5(tx__ring__dequeue, struct nx_flowswitch *, fsw,
	    ifnet_t, fsw->fsw_ifp, uint32_t, n_pkts, uint32_t, *n_bytes,
	    uint32_t, *gso_pkts_estimate);
}

static void
fsw_ring_enqueue_pktq(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    struct pktq *pktq)
{
#pragma unused(fsw)
	struct __kern_packet *pkt;
	struct __kern_quantum *kqum;
	uint32_t kr_space_avail = 0;
	uint32_t n, n_pkts = 0, n_bytes = 0;
	slot_idx_t idx = 0, idx_start = 0, idx_end = 0;

	kr_enter(r, TRUE);

	idx_start = r->ckr_ktail;
	kr_space_avail = kr_available_slots_rxring(r);
	_FSW_INJECT_ERROR(40, kr_space_avail, 0, null_func);
	n = MIN(kr_space_avail, KPKTQ_LEN(pktq));
	_FSW_INJECT_ERROR(41, n, 0, null_func);
	idx_end = SLOT_INCREMENT(idx_start, n, r->ckr_lim);

	idx = idx_start;
	while (idx != idx_end) {
		KPKTQ_DEQUEUE(pktq, pkt);
		kqum = SK_PTR_ADDR_KQUM(pkt);
		kqum->qum_qflags |= QUM_F_FINALIZED;
		n_pkts++;
		n_bytes += pkt->pkt_length;
		KR_SLOT_ATTACH_METADATA(r, KR_KSD(r, idx), kqum);
		if (__improbable(pkt->pkt_trace_id != 0)) {
			KDBG(SK_KTRACE_PKT_RX_FSW | DBG_FUNC_END, pkt->pkt_trace_id);
			KDBG(SK_KTRACE_PKT_RX_CHN | DBG_FUNC_START, pkt->pkt_trace_id);
		}
		idx = SLOT_NEXT(idx, r->ckr_lim);
	}

	kr_update_stats(r, n_pkts, n_bytes);

	/*
	 * ensure slot attachments are visible before updating the
	 * tail pointer
	 */
	os_atomic_thread_fence(seq_cst);

	r->ckr_ktail = idx_end;

	kr_exit(r);

	r->ckr_na_notify(r, kernproc, NA_NOTEF_PUSH);

	SK_DF(SK_VERB_FSW_DP | SK_VERB_RING, "%s enqueued %d pkts",
	    r->ckr_name, n_pkts);
}

static void
pkts_to_pktq(struct __kern_packet *pkts[], uint32_t n_pkts, struct pktq *pktq)
{
	ASSERT(KPKTQ_EMPTY(pktq));

	for (uint32_t i = 0; i < n_pkts; i++) {
		struct __kern_packet *pkt = pkts[i];
		ASSERT(pkt->pkt_nextpkt == NULL);
		KPKTQ_ENQUEUE(pktq, pkt);
	}
}

/*
 * This function is modeled after nx_netif_host_grab_pkts() in nx_netif_host.c.
 */
SK_NO_INLINE_ATTRIBUTE
static void
convert_native_pktq_to_mbufs(struct nx_flowswitch *fsw, struct pktq *pktq,
    struct mbuf **m_headp, struct mbuf **m_tailp, uint32_t *cnt, uint32_t *bytes)
{
	uint32_t tot_cnt;
	unsigned int num_segs = 1;
	struct mbuf *mhead, *head = NULL, *tail = NULL, **tailp = &head;
	uint32_t mhead_cnt, mhead_bufsize;
	uint32_t mhead_waste = 0;
	uint32_t mcnt = 0, mbytes = 0;
	uint32_t largest, max_pkt_len;
	struct __kern_packet *pkt;
	struct kern_pbufpool *pp;

	tot_cnt = KPKTQ_LEN(pktq);
	ASSERT(tot_cnt > 0);
	mhead_cnt = tot_cnt;

	/*
	 * Opportunistically batch-allocate the mbufs based on the largest
	 * packet size we've seen in the recent past.  Note that we reset
	 * fe_rx_largest_size below if we notice that we're under-utilizing the
	 * allocated buffers (thus disabling this batch allocation).
	 */
	largest = *(volatile uint32_t*)&fsw->fsw_rx_largest_size; /* read once */
	if (__probable(largest != 0)) {
		if (largest <= MCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, MCLBYTES,
			    &num_segs, M_NOWAIT, 1, 0);
			mhead_bufsize = MCLBYTES;
		} else if (largest <= MBIGCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, MBIGCLBYTES,
			    &num_segs, M_NOWAIT, 1, 0);
			mhead_bufsize = MBIGCLBYTES;
		} else if (largest <= M16KCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, M16KCLBYTES,
			    &num_segs, M_NOWAIT, 1, 0);
			mhead_bufsize = M16KCLBYTES;
		} else if (largest <= M16KCLBYTES * 2) {
			num_segs = 2;
			mhead = m_allocpacket_internal(&mhead_cnt, M16KCLBYTES * 2,
			    &num_segs, M_NOWAIT, 1, 0);
			mhead_bufsize = M16KCLBYTES * 2;
		} else {
			mhead = NULL;
			mhead_bufsize = mhead_cnt = 0;
		}
	} else {
		mhead = NULL;
		mhead_bufsize = mhead_cnt = 0;
	}
	DTRACE_SKYWALK4(bufstats, uint32_t, largest, uint32_t, mhead_bufsize,
	    uint32_t, mhead_cnt, uint32_t, tot_cnt);

	pp = __DECONST(struct kern_pbufpool *, KPKTQ_FIRST(pktq)->pkt_qum.qum_pp);
	max_pkt_len = PP_BUF_SIZE_DEF(pp) * pp->pp_max_frags;

	KPKTQ_FOREACH(pkt, pktq) {
		uint32_t tot_len, len;
		uint16_t pad, llhlen, iphlen;
		boolean_t do_cksum_rx;
		struct mbuf *m;
		int error;

		llhlen = pkt->pkt_l2_len;
		len = pkt->pkt_length;
		if (__improbable(len > max_pkt_len || llhlen > len)) {
			DTRACE_SKYWALK2(bad__len, struct nx_flowswitch *, fsw,
			    struct __kern_packet *, pkt);
			FSW_STATS_INC(FSW_STATS_DROP);
			FSW_STATS_INC(FSW_STATS_RX_COPY_BAD_LEN);
			continue;
		}
		/* begin payload on 32-bit boundary; figure out the padding */
		pad = (uint16_t)P2ROUNDUP(llhlen, sizeof(uint32_t)) - llhlen;
		tot_len = pad + len;

		/* remember largest packet size */
		if (__improbable(largest < tot_len)) {
			largest = MAX(tot_len, MCLBYTES);
		}

		/*
		 * If the above batch allocation returned partial
		 * success, we try a blocking allocation here again.
		 */
		m = mhead;
		if (__improbable(m == NULL || tot_len > mhead_bufsize)) {
			ASSERT(mhead != NULL || mhead_cnt == 0);
			num_segs = 1;
			if (tot_len > M16KCLBYTES) {
				num_segs = 0;
			}
			if ((error = mbuf_allocpacket(MBUF_DONTWAIT, tot_len,
			    &num_segs, &m)) != 0) {
				DTRACE_SKYWALK2(bad__len,
				    struct nx_flowswitch *, fsw,
				    struct __kern_packet *, pkt);
				FSW_STATS_INC(FSW_STATS_DROP_NOMEM_MBUF);
				FSW_STATS_INC(FSW_STATS_DROP);
				continue;
			}
		} else {
			mhead = m->m_nextpkt;
			m->m_nextpkt = NULL;
			ASSERT(mhead_cnt != 0);
			--mhead_cnt;

			/* check if we're underutilizing large buffers */
			if (__improbable(mhead_bufsize > MCLBYTES &&
			    tot_len < (mhead_bufsize >> 1))) {
				++mhead_waste;
			}
			/*
			 * Clean up unused mbuf.
			 * Ony need to do this when we pre-alloc 2x16K mbufs
			 */
			if (__improbable(mhead_bufsize >= tot_len + M16KCLBYTES)) {
				ASSERT(mhead_bufsize == 2 * M16KCLBYTES);
				struct mbuf *m_extra = m->m_next;
				ASSERT(m_extra != NULL);
				ASSERT(m_extra->m_len == 0);
				ASSERT(M_SIZE(m_extra) == M16KCLBYTES);
				m->m_next = NULL;
				m_freem(m_extra);
				FSW_STATS_INC(FSW_STATS_RX_WASTED_16KMBUF);
			}
		}
		m->m_data += pad;
		m->m_pkthdr.pkt_hdr = mtod(m, uint8_t *);

		/* don't include IP header from partial sum */
		if (__probable((pkt->pkt_qum_qflags &
		    QUM_F_FLOW_CLASSIFIED) != 0)) {
			iphlen = pkt->pkt_flow_ip_hlen;
			do_cksum_rx = sk_cksum_rx;
		} else {
			iphlen = 0;
			do_cksum_rx = FALSE;
		}

		fsw->fsw_pkt_copy_to_mbuf(NR_RX, SK_PKT2PH(pkt),
		    pkt->pkt_headroom, m, 0, len, do_cksum_rx,
		    llhlen + iphlen);

		FSW_STATS_INC(FSW_STATS_RX_COPY_PKT2MBUF);
		if (do_cksum_rx) {
			FSW_STATS_INC(FSW_STATS_RX_COPY_SUM);
		}
#if DEBUG || DEVELOPMENT
		if (__improbable(pkt_trailers > 0)) {
			(void) pkt_add_trailers_mbuf(m, llhlen + iphlen);
		}
#endif /* DEBUG || DEVELOPMENT */
		m_adj(m, llhlen);

		m->m_pkthdr.rcvif = fsw->fsw_ifp;
		if (__improbable((pkt->pkt_link_flags &
		    PKT_LINKF_ETHFCS) != 0)) {
			m->m_flags |= M_HASFCS;
		}
		if (__improbable(pkt->pkt_pflags & PKT_F_WAKE_PKT)) {
			m->m_pkthdr.pkt_flags |= PKTF_WAKE_PKT;
		}
		ASSERT(m->m_nextpkt == NULL);
		tail = m;
		*tailp = m;
		tailp = &m->m_nextpkt;
		mcnt++;
		mbytes += m_pktlen(m);
	}
	/* free any leftovers */
	if (__improbable(mhead != NULL)) {
		DTRACE_SKYWALK1(mhead__leftover, uint32_t, mhead_cnt);
		ASSERT(mhead_cnt != 0);
		(void) m_freem_list(mhead);
		mhead = NULL;
		mhead_cnt = 0;
	}

	/* reset if most packets (>50%) are smaller than our batch buffers */
	if (__improbable(mhead_waste > ((uint32_t)tot_cnt >> 1))) {
		DTRACE_SKYWALK4(mhead__waste, struct nx_flowswitch *, fsw,
		    struct flow_entry *, NULL, uint32_t, mhead_waste,
		    uint32_t, tot_cnt);
		largest = 0;
	}

	if (largest != fsw->fsw_rx_largest_size) {
		os_atomic_store(&fsw->fsw_rx_largest_size, largest, release);
	}

	pp_free_pktq(pktq);
	*m_headp = head;
	*m_tailp = tail;
	*cnt = mcnt;
	*bytes = mbytes;
}

/*
 * This function only extracts the mbuf from the packet. The caller frees
 * the packet.
 */
static inline struct mbuf *
convert_compat_pkt_to_mbuf(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	struct mbuf *m;
	struct pkthdr *mhdr;
	uint16_t llhlen;

	m = pkt->pkt_mbuf;
	ASSERT(m != NULL);

	llhlen = pkt->pkt_l2_len;
	if (llhlen > pkt->pkt_length) {
		m_freem(m);
		KPKT_CLEAR_MBUF_DATA(pkt);
		DTRACE_SKYWALK2(bad__len, struct nx_flowswitch *, fsw,
		    struct __kern_packet *, pkt);
		FSW_STATS_INC(FSW_STATS_DROP);
		FSW_STATS_INC(FSW_STATS_RX_COPY_BAD_LEN);
		return NULL;
	}
	mhdr = &m->m_pkthdr;
	if ((mhdr->csum_flags & CSUM_DATA_VALID) == 0 &&
	    PACKET_HAS_PARTIAL_CHECKSUM(pkt)) {
		mhdr->csum_flags &= ~CSUM_RX_FLAGS;
		mhdr->csum_flags |= (CSUM_DATA_VALID | CSUM_PARTIAL);
		mhdr->csum_rx_start = pkt->pkt_csum_rx_start_off;
		mhdr->csum_rx_val = pkt->pkt_csum_rx_value;
	}
#if DEBUG || DEVELOPMENT
	uint32_t extra = 0;
	if (__improbable(pkt_trailers > 0)) {
		extra = pkt_add_trailers_mbuf(m, llhlen);
	}
#endif /* DEBUG || DEVELOPMENT */
	m_adj(m, llhlen);
	ASSERT((uint32_t)m_pktlen(m) == ((pkt->pkt_length - llhlen) + extra));
	KPKT_CLEAR_MBUF_DATA(pkt);
	return m;
}

SK_NO_INLINE_ATTRIBUTE
static void
convert_compat_pktq_to_mbufs(struct nx_flowswitch *fsw, struct pktq *pktq,
    struct mbuf **m_head, struct mbuf **m_tail, uint32_t *cnt, uint32_t *bytes)
{
	struct __kern_packet *pkt;
	struct mbuf *m, *head = NULL, *tail = NULL, **tailp = &head;
	uint32_t c = 0, b = 0;

	KPKTQ_FOREACH(pkt, pktq) {
		m = convert_compat_pkt_to_mbuf(fsw, pkt);
		if (__improbable(m == NULL)) {
			continue;
		}
		tail = m;
		*tailp = m;
		tailp = &m->m_nextpkt;
		c++;
		b += m_pktlen(m);
	}
	pp_free_pktq(pktq);
	*m_head = head;
	*m_tail = tail;
	*cnt = c;
	*bytes = b;
}

void
fsw_host_sendup(ifnet_t ifp, struct mbuf *m_head, struct mbuf *m_tail,
    uint32_t cnt, uint32_t bytes)
{
	struct ifnet_stat_increment_param s;

	bzero(&s, sizeof(s));
	s.packets_in = cnt;
	s.bytes_in = bytes;
	dlil_input_handler(ifp, m_head, m_tail, &s, FALSE, NULL);
}

void
fsw_host_rx(struct nx_flowswitch *fsw, struct pktq *pktq)
{
	struct mbuf *m_head = NULL, *m_tail = NULL;
	uint32_t cnt = 0, bytes = 0;
	ifnet_fsw_rx_cb_t cb;
	void *cb_arg;
	boolean_t compat;

	ASSERT(!KPKTQ_EMPTY(pktq));
	if (ifnet_get_flowswitch_rx_callback(fsw->fsw_ifp, &cb, &cb_arg) == 0) {
		ASSERT(cb != NULL);
		ASSERT(cb_arg != NULL);
		/* callback consumes packets */
		(*cb)(cb_arg, pktq);
		ifnet_release_flowswitch_rx_callback(fsw->fsw_ifp);
		return;
	}

	/* All packets in the pktq must have the same type */
	compat = ((KPKTQ_FIRST(pktq)->pkt_pflags & PKT_F_MBUF_DATA) != 0);
	if (compat) {
		convert_compat_pktq_to_mbufs(fsw, pktq, &m_head, &m_tail, &cnt,
		    &bytes);
	} else {
		convert_native_pktq_to_mbufs(fsw, pktq, &m_head, &m_tail, &cnt,
		    &bytes);
	}
	if (__improbable(m_head == NULL)) {
		DTRACE_SKYWALK1(empty__head, struct nx_flowswitch *, fsw);
		return;
	}
	fsw_host_sendup(fsw->fsw_ifp, m_head, m_tail, cnt, bytes);
}

void
fsw_ring_enqueue_tail_drop(struct nx_flowswitch *fsw,
    struct __kern_channel_ring *r, struct pktq *pktq)
{
	fsw_ring_enqueue_pktq(fsw, r, pktq);
	FSW_STATS_ADD(FSW_STATS_RX_DST_RING_FULL, KPKTQ_LEN(pktq));
	dp_drop_pktq(fsw, pktq);
}

static struct nexus_adapter *
flow_get_na(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct kern_nexus *nx = fsw->fsw_nx;
	struct nexus_adapter *na = NULL;
	nexus_port_t port = fe->fe_nx_port;

	if (port == FSW_VP_DEV || port == FSW_VP_HOST) {
		SK_ERR("dev or host ports have no NA");
		return NULL;
	}

	if (__improbable(!nx_port_is_valid(nx, port))) {
		SK_DF(SK_VERB_FSW_DP, "%s[%d] port no longer valid",
		    if_name(fsw->fsw_ifp), port);
		return NULL;
	}

	na = nx_port_get_na(nx, port);
	if (__improbable(na == NULL)) {
		FSW_STATS_INC(FSW_STATS_DST_NXPORT_INVALID);
		SK_DF(SK_VERB_FSW_DP, "%s[%d] NA no longer valid",
		    if_name(fsw->fsw_ifp), port);
		return NULL;
	}

	if (__improbable(!NA_IS_ACTIVE(na))) {
		FSW_STATS_INC(FSW_STATS_DST_NXPORT_INACTIVE);
		SK_DF(SK_VERB_FSW_DP, "%s[%d] NA no longer active",
		    if_name(fsw->fsw_ifp), port);
		return NULL;
	}

	if (__improbable(nx_port_is_defunct(nx, port))) {
		FSW_STATS_INC(FSW_STATS_DST_NXPORT_DEFUNCT);
		SK_DF(SK_VERB_FSW_DP, "%s[%d] NA defuncted",
		    if_name(fsw->fsw_ifp), port);
		return NULL;
	}

	return na;
}

static inline struct __kern_channel_ring *
flow_get_ring(struct nx_flowswitch *fsw, struct flow_entry *fe, enum txrx txrx)
{
	struct nexus_vp_adapter *na = NULL;
	struct __kern_channel_ring *r = NULL;

	na = VPNA(flow_get_na(fsw, fe));
	if (__improbable(na == NULL)) {
		return NULL;
	}

	switch (txrx) {
	case NR_RX:
		r = &na->vpna_up.na_rx_rings[0];
		break;
	case NR_TX:
		r = &na->vpna_up.na_tx_rings[0];
		break;
	default:
		__builtin_unreachable();
		VERIFY(0);
	}

	if (__improbable(KR_DROP(r))) {
		FSW_STATS_INC(FSW_STATS_DST_RING_DROPMODE);
		SK_DF(SK_VERB_FSW_DP | SK_VERB_RING, "r %0xllx %s drop mode",
		    r->ckr_name, SK_KVA(r));
		return NULL;
	}

	ASSERT(KRNA(r)->na_md_type == NEXUS_META_TYPE_PACKET);

#if (DEVELOPMENT || DEBUG)
	if (r != NULL) {
		_FSW_INJECT_ERROR(4, r, NULL, null_func);
	}
#endif /* DEVELOPMENT || DEBUG */

	return r;
}

struct __kern_channel_ring *
fsw_flow_get_rx_ring(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	return flow_get_ring(fsw, fe, NR_RX);
}

static inline struct __kern_channel_ring *
fsw_flow_get_tx_ring(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	return flow_get_ring(fsw, fe, NR_TX);
}

static bool
dp_flow_route_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct flow_route *fr = fe->fe_route;
	struct ifnet *ifp = fsw->fsw_ifp;

	if (__improbable(!(fe->fe_flags & FLOWENTF_NONVIABLE) &&
	    !fe->fe_want_nonviable && (fe->fe_key.fk_mask & FKMASK_SRC) &&
	    fe->fe_laddr_gencnt != ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt &&
	    !flow_route_key_validate(&fe->fe_key, ifp, &fe->fe_laddr_gencnt))) {
		/*
		 * The source address is no longer around; we want this
		 * flow to be nonviable, but that requires holding the lock
		 * as writer (which isn't the case now.)  Indicate that
		 * we need to finalize the nonviable later down below.
		 *
		 * We also request that the flow route be re-configured,
		 * if this is a connected mode flow.
		 *
		 */
		if (!(fe->fe_flags & FLOWENTF_NONVIABLE)) {
			/*
			 * fsw_pending_nonviable is a hint for reaper thread;
			 * due to the fact that setting fe_want_nonviable and
			 * incrementing fsw_pending_nonviable counter is not
			 * atomic, let the increment happen first, and the
			 * thread losing the CAS does decrement.
			 */
			os_atomic_inc(&fsw->fsw_pending_nonviable, relaxed);
			if (os_atomic_cmpxchg(&fe->fe_want_nonviable, 0, 1, acq_rel)) {
				fsw_reap_sched(fsw);
			} else {
				os_atomic_dec(&fsw->fsw_pending_nonviable, relaxed);
			}
		}
		if (fr != NULL) {
			os_atomic_inc(&fr->fr_want_configure, relaxed);
		}
	}

	/* if flow was (or is going to be) marked as nonviable, drop it */
	if (__improbable(fe->fe_want_nonviable ||
	    (fe->fe_flags & FLOWENTF_NONVIABLE) != 0)) {
		SK_DF(SK_VERB_FSW_DP | SK_VERB_FLOW, "flow 0x%llx non-viable",
		    SK_KVA(fe));
		return false;
	}
	return true;
}

bool
dp_flow_rx_route_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	bool okay;
	okay = dp_flow_route_process(fsw, fe);
#if (DEVELOPMENT || DEBUG)
	if (okay) {
		_FSW_INJECT_ERROR(5, okay, false, null_func);
	}
#endif /* DEVELOPMENT || DEBUG */

	return okay;
}

void
dp_flow_rx_process(struct nx_flowswitch *fsw, struct flow_entry *fe,
    uint32_t flags)
{
#pragma unused(flags)
	struct pktq dpkts;              /* dst pool alloc'ed packets */
	struct pktq disposed_pkts;         /* done src packets */
	struct pktq dropped_pkts;         /* dropped src packets */
	struct pktq transferred_pkts;         /* dst packet ready for ring */
	struct __kern_packet *pkt, *tpkt;
	struct kern_pbufpool *dpp;
	uint32_t n_pkts = KPKTQ_LEN(&fe->fe_rx_pktq);
	uint64_t buf_array[RX_BUFLET_BATCH_COUNT];
	uint16_t buf_array_iter = 0;
	uint32_t cnt, buf_cnt = 0;
	int err;

	KPKTQ_INIT(&dpkts);
	KPKTQ_INIT(&dropped_pkts);
	KPKTQ_INIT(&disposed_pkts);
	KPKTQ_INIT(&transferred_pkts);

	if (__improbable(!dp_flow_rx_route_process(fsw, fe))) {
		SK_ERR("Rx route bad");
		fsw_snoop_and_dequeue(fe, &dropped_pkts, true);
		FSW_STATS_ADD(FSW_STATS_RX_FLOW_NONVIABLE, n_pkts);
		goto done;
	}

	if (fe->fe_nx_port == FSW_VP_HOST) {
		/*
		 * The host ring does not exist anymore so we can't take
		 * the enqueue path below. This path should only be hit
		 * for the rare tcp fragmentation case.
		 */
		fsw_host_rx(fsw, &fe->fe_rx_pktq);
		return;
	}

	/* find the ring */
	struct __kern_channel_ring *r;
	r = fsw_flow_get_rx_ring(fsw, fe);
	if (__improbable(r == NULL)) {
		fsw_snoop_and_dequeue(fe, &dropped_pkts, true);
		goto done;
	}

	/* snoop before L2 is stripped */
	if (__improbable(pktap_total_tap_count != 0)) {
		fsw_snoop(fsw, fe, true);
	}

	dpp = r->ckr_pp;
	/* batch allocate enough packets */
	err = pp_alloc_pktq(dpp, 1, &dpkts, n_pkts, NULL, NULL,
	    SKMEM_NOSLEEP);
	if (__improbable(err == ENOMEM)) {
		ASSERT(KPKTQ_EMPTY(&dpkts));
		KPKTQ_CONCAT(&dropped_pkts, &fe->fe_rx_pktq);
		FSW_STATS_ADD(FSW_STATS_DROP_NOMEM_PKT, n_pkts);
		SK_ERR("failed to alloc %u pkts for kr %s, 0x%llu", n_pkts,
		    r->ckr_name, SK_KVA(r));
		goto done;
	}

	/*
	 * estimate total number of buflets for the packet chain.
	 */
	cnt = howmany(fe->fe_rx_pktq_bytes, PP_BUF_SIZE_DEF(dpp));
	if (cnt > n_pkts) {
		ASSERT(dpp->pp_max_frags > 1);
		cnt -= n_pkts;
		buf_cnt = MIN(RX_BUFLET_BATCH_COUNT, cnt);
		err = pp_alloc_buflet_batch(dpp, buf_array, &buf_cnt,
		    SKMEM_NOSLEEP, false);
		if (__improbable(buf_cnt == 0)) {
			KPKTQ_CONCAT(&dropped_pkts, &fe->fe_rx_pktq);
			FSW_STATS_ADD(FSW_STATS_DROP_NOMEM_PKT, n_pkts);
			SK_ERR("failed to alloc %d buflets (err %d) for kr %s, "
			    "0x%llu", cnt, err, r->ckr_name, SK_KVA(r));
			goto done;
		}
		err = 0;
	}

	/* extra processing for user flow */
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_rx_pktq, tpkt) {
		err = 0;
		KPKTQ_REMOVE(&fe->fe_rx_pktq, pkt);
		if (fe->fe_rx_pktq_bytes > pkt->pkt_flow_ulen) {
			fe->fe_rx_pktq_bytes -= pkt->pkt_flow_ulen;
		} else {
			fe->fe_rx_pktq_bytes = 0;
		}
		err = flow_pkt_track(fe, pkt, true);
		_FSW_INJECT_ERROR(33, err, EPROTO, null_func);
		if (__improbable(err != 0)) {
			SK_ERR("flow_pkt_track failed (err %d)", err);
			FSW_STATS_INC(FSW_STATS_RX_FLOW_TRACK_ERR);
			/* if need to trigger RST */
			if (err == ENETRESET) {
				flow_track_abort_tcp(fe, pkt, NULL);
			}
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			continue;
		}

		/* transfer to dpkt */
		if (pkt->pkt_qum.qum_pp != dpp) {
			struct __kern_buflet *bprev, *bnew;
			struct __kern_packet *dpkt = NULL;
			uint32_t n_bufs, i;

			KPKTQ_DEQUEUE(&dpkts, dpkt);
			if (__improbable(dpkt == NULL)) {
				FSW_STATS_INC(FSW_STATS_DROP_NOMEM_PKT);
				KPKTQ_ENQUEUE(&dropped_pkts, pkt);
				continue;
			}
			n_bufs = howmany(pkt->pkt_length, PP_BUF_SIZE_DEF(dpp));
			n_bufs--;
			for (i = 0; i < n_bufs; i++) {
				if (__improbable(buf_cnt == 0)) {
					ASSERT(dpp->pp_max_frags > 1);
					buf_array_iter = 0;
					cnt = howmany(fe->fe_rx_pktq_bytes,
					    PP_BUF_SIZE_DEF(dpp));
					n_pkts = KPKTQ_LEN(&fe->fe_rx_pktq);
					if (cnt >= n_pkts) {
						cnt -= n_pkts;
					} else {
						cnt = 0;
					}
					cnt += (n_bufs - i);
					buf_cnt = MIN(RX_BUFLET_BATCH_COUNT,
					    cnt);
					cnt = buf_cnt;
					err = pp_alloc_buflet_batch(dpp,
					    buf_array, &buf_cnt,
					    SKMEM_NOSLEEP, false);
					if (__improbable(buf_cnt == 0)) {
						FSW_STATS_INC(FSW_STATS_DROP_NOMEM_PKT);
						KPKTQ_ENQUEUE(&dropped_pkts,
						    pkt);
						pkt = NULL;
						pp_free_packet_single(dpkt);
						dpkt = NULL;
						SK_ERR("failed to alloc %d "
						    "buflets (err %d) for "
						    "kr %s, 0x%llu", cnt, err,
						    r->ckr_name, SK_KVA(r));
						break;
					}
					err = 0;
				}
				ASSERT(buf_cnt != 0);
				if (i == 0) {
					PKT_GET_FIRST_BUFLET(dpkt, 1, bprev);
				}
				bnew = (kern_buflet_t)buf_array[buf_array_iter];
				buf_array[buf_array_iter] = 0;
				buf_array_iter++;
				buf_cnt--;
				VERIFY(kern_packet_add_buflet(SK_PKT2PH(dpkt),
				    bprev, bnew) == 0);
				bprev = bnew;
			}
			if (__improbable(err != 0)) {
				continue;
			}
			err = copy_packet_from_dev(fsw, pkt, dpkt);
			_FSW_INJECT_ERROR(43, err, EINVAL, null_func);
			if (__improbable(err != 0)) {
				SK_ERR("copy packet failed (err %d)", err);
				KPKTQ_ENQUEUE(&dropped_pkts, pkt);
				pp_free_packet_single(dpkt);
				dpkt = NULL;
				continue;
			}
			KPKTQ_ENQUEUE(&disposed_pkts, pkt);
			pkt = dpkt;
		}
		_UUID_COPY(pkt->pkt_flow_id, fe->fe_uuid);
		_UUID_COPY(pkt->pkt_policy_euuid, fe->fe_eproc_uuid);
		pkt->pkt_policy_id = fe->fe_policy_id;
		pkt->pkt_skip_policy_id = fe->fe_skip_policy_id;
		pkt->pkt_transport_protocol = fe->fe_transport_protocol;
		if (pkt->pkt_bufs_cnt > 1) {
			pkt->pkt_aggr_type = PKT_AGGR_SINGLE_IP;
			pkt->pkt_seg_cnt = 1;
		}
		KPKTQ_ENQUEUE(&transferred_pkts, pkt);
	}
	KPKTQ_FINI(&fe->fe_rx_pktq);
	KPKTQ_CONCAT(&fe->fe_rx_pktq, &transferred_pkts);
	KPKTQ_FINI(&transferred_pkts);

	fsw_ring_enqueue_tail_drop(fsw, r, &fe->fe_rx_pktq);

done:
	/* Free unused buflets */
	while (buf_cnt > 0) {
		pp_free_buflet(dpp, (kern_buflet_t)(buf_array[buf_array_iter]));
		buf_array[buf_array_iter] = 0;
		buf_array_iter++;
		buf_cnt--;
	}
	dp_free_pktq(fsw, &dpkts);
	dp_free_pktq(fsw, &disposed_pkts);
	dp_drop_pktq(fsw, &dropped_pkts);
}

static inline void
rx_flow_process(struct nx_flowswitch *fsw, struct flow_entry *fe,
    uint32_t flags)
{
	ASSERT(!KPKTQ_EMPTY(&fe->fe_rx_pktq));
	ASSERT(KPKTQ_LEN(&fe->fe_rx_pktq) != 0);

	SK_DF(SK_VERB_FSW_DP | SK_VERB_RX, "Rx %d pkts for fe %p port %d",
	    KPKTQ_LEN(&fe->fe_rx_pktq), fe, fe->fe_nx_port);

	/* flow related processing (default, agg, fpd, etc.) */
	fe->fe_rx_process(fsw, fe, flags);

	if (__improbable(fe->fe_want_withdraw)) {
		fsw_reap_sched(fsw);
	}

	KPKTQ_FINI(&fe->fe_rx_pktq);
}

static inline void
dp_rx_process_wake_packet(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	/*
	 * We only care about wake packets of flows that belong the flow switch
	 * as wake packets for the host stack are handled by the host input
	 * function
	 */
#if (DEBUG || DEVELOPMENT)
	if (__improbable(fsw->fsw_ifp->if_xflags & IFXF_MARK_WAKE_PKT)) {
		/*
		 * This is a one shot command
		 */
		fsw->fsw_ifp->if_xflags &= ~IFXF_MARK_WAKE_PKT;

		pkt->pkt_pflags |= PKT_F_WAKE_PKT;
	}
#endif /* (DEBUG || DEVELOPMENT) */
	if (__improbable(pkt->pkt_pflags & PKT_F_WAKE_PKT)) {
		if_ports_used_match_pkt(fsw->fsw_ifp, pkt);
	}
}

static void
_fsw_receive_locked(struct nx_flowswitch *fsw, struct pktq *pktq)
{
	struct __kern_packet *pkt, *tpkt;
	struct flow_entry_list fes = TAILQ_HEAD_INITIALIZER(fes);
	struct flow_entry *fe, *prev_fe;
	sa_family_t af;
	struct pktq host_pkts, dropped_pkts;
	int err;

	KPKTQ_INIT(&host_pkts);
	KPKTQ_INIT(&dropped_pkts);

	if (__improbable(FSW_QUIESCED(fsw))) {
		DTRACE_SKYWALK1(rx__quiesced, struct nx_flowswitch *, fsw);
		KPKTQ_CONCAT(&dropped_pkts, pktq);
		goto done;
	}
	if (__improbable(fsw->fsw_demux == NULL)) {
		KPKTQ_CONCAT(&dropped_pkts, pktq);
		goto done;
	}

	prev_fe = NULL;
	KPKTQ_FOREACH_SAFE(pkt, pktq, tpkt) {
		if (__probable(tpkt)) {
			void *baddr;
			MD_BUFLET_ADDR_ABS_PKT(tpkt, baddr);
			SK_PREFETCH(baddr, 0);
			/* prefetch L3 and L4 flow structs */
			SK_PREFETCHW(tpkt->pkt_flow, 0);
			SK_PREFETCHW(tpkt->pkt_flow, 128);
		}

		KPKTQ_REMOVE(pktq, pkt);

		pkt = rx_prepare_packet(fsw, pkt);

		af = fsw->fsw_demux(fsw, pkt);
		if (__improbable(af == AF_UNSPEC)) {
			KPKTQ_ENQUEUE(&host_pkts, pkt);
			continue;
		}

		err = flow_pkt_classify(pkt, fsw->fsw_ifp, af, TRUE);
		_FSW_INJECT_ERROR(1, err, ENXIO, null_func);
		if (__improbable(err != 0)) {
			FSW_STATS_INC(FSW_STATS_RX_FLOW_EXTRACT_ERR);
			KPKTQ_ENQUEUE(&host_pkts, pkt);
			continue;
		}

		if (__improbable(pkt->pkt_flow_ip_is_frag)) {
			pkt = rx_process_ip_frag(fsw, pkt);
			if (pkt == NULL) {
				continue;
			}
		}

		prev_fe = fe = rx_lookup_flow(fsw, pkt, prev_fe);
		if (__improbable(fe == NULL)) {
			KPKTQ_ENQUEUE_LIST(&host_pkts, pkt);
			continue;
		}

		fe->fe_rx_pktq_bytes += pkt->pkt_flow_ulen;

		dp_rx_process_wake_packet(fsw, pkt);

		rx_flow_batch_packet(&fes, fe, pkt);
		prev_fe = fe;
	}

	struct flow_entry *tfe = NULL;
	TAILQ_FOREACH_SAFE(fe, &fes, fe_rx_link, tfe) {
		rx_flow_process(fsw, fe, 0);
		TAILQ_REMOVE(&fes, fe, fe_rx_link);
		fe->fe_rx_pktq_bytes = 0;
		fe->fe_rx_frag_count = 0;
		flow_entry_release(&fe);
	}

	if (!KPKTQ_EMPTY(&host_pkts)) {
		fsw_host_rx(fsw, &host_pkts);
	}

done:
	dp_drop_pktq(fsw, &dropped_pkts);
}

#if (DEVELOPMENT || DEBUG)
static void
fsw_rps_rx(struct nx_flowswitch *fsw, uint32_t id,
    struct __kern_packet *pkt)
{
	struct fsw_rps_thread *frt = &fsw->fsw_rps_threads[id];

	lck_mtx_lock_spin(&frt->frt_lock);
	KPKTQ_ENQUEUE(&frt->frt_pktq, pkt);
	lck_mtx_unlock(&frt->frt_lock);
}

static void
fsw_rps_thread_schedule(struct nx_flowswitch *fsw, uint32_t id)
{
	struct fsw_rps_thread *frt = &fsw->fsw_rps_threads[id];

	ASSERT(frt->frt_thread != THREAD_NULL);
	lck_mtx_lock_spin(&frt->frt_lock);
	ASSERT(!(frt->frt_flags & (FRT_TERMINATING | FRT_TERMINATED)));

	frt->frt_requests++;
	if (!(frt->frt_flags & FRT_RUNNING)) {
		thread_wakeup((caddr_t)frt);
	}
	lck_mtx_unlock(&frt->frt_lock);
}

__attribute__((noreturn))
static void
fsw_rps_thread_cont(void *v, wait_result_t w)
{
	struct fsw_rps_thread *frt = v;
	struct nx_flowswitch *fsw = frt->frt_fsw;

	lck_mtx_lock(&frt->frt_lock);
	if (__improbable(w == THREAD_INTERRUPTIBLE ||
	    (frt->frt_flags & FRT_TERMINATING) != 0)) {
		goto terminate;
	}
	if (KPKTQ_EMPTY(&frt->frt_pktq)) {
		goto done;
	}
	frt->frt_flags |= FRT_RUNNING;

	for (;;) {
		uint32_t requests = frt->frt_requests;
		struct pktq pkts;

		KPKTQ_INIT(&pkts);
		KPKTQ_CONCAT(&pkts, &frt->frt_pktq);
		lck_mtx_unlock(&frt->frt_lock);

		sk_protect_t protect;
		protect = sk_sync_protect();
		FSW_RLOCK(fsw);
		_fsw_receive_locked(fsw, &pkts);
		FSW_RUNLOCK(fsw);
		sk_sync_unprotect(protect);

		lck_mtx_lock(&frt->frt_lock);
		if ((frt->frt_flags & FRT_TERMINATING) != 0 ||
		    requests == frt->frt_requests) {
			frt->frt_requests = 0;
			break;
		}
	}

done:
	lck_mtx_unlock(&frt->frt_lock);
	if (!(frt->frt_flags & FRT_TERMINATING)) {
		frt->frt_flags &= ~FRT_RUNNING;
		assert_wait(frt, THREAD_UNINT);
		thread_block_parameter(fsw_rps_thread_cont, frt);
		__builtin_unreachable();
	} else {
terminate:
		LCK_MTX_ASSERT(&frt->frt_lock, LCK_MTX_ASSERT_OWNED);
		frt->frt_flags &= ~(FRT_RUNNING | FRT_TERMINATING);
		frt->frt_flags |= FRT_TERMINATED;

		if (frt->frt_flags & FRT_TERMINATEBLOCK) {
			thread_wakeup((caddr_t)&frt);
		}
		lck_mtx_unlock(&frt->frt_lock);

		SK_D("fsw_rx_%s_%d terminated", if_name(fsw->fsw_ifp),
		    frt->frt_idx);

		/* for the extra refcnt from kernel_thread_start() */
		thread_deallocate(current_thread());
		/* this is the end */
		thread_terminate(current_thread());
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* must never get here */
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static void
fsw_rps_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct fsw_rps_thread *frt = v;
	struct nx_flowswitch *fsw = frt->frt_fsw;

	char thread_name[MAXTHREADNAMESIZE];
	bzero(thread_name, sizeof(thread_name));
	(void) snprintf(thread_name, sizeof(thread_name), "fsw_rx_%s_%d",
	    if_name(fsw->fsw_ifp), frt->frt_idx);
	thread_set_thread_name(frt->frt_thread, thread_name);
	SK_D("%s spawned", thread_name);

	net_thread_marks_push(NET_THREAD_SYNC_RX);
	assert_wait(frt, THREAD_UNINT);
	(void) thread_block_parameter(fsw_rps_thread_cont, frt);

	__builtin_unreachable();
}

static void
fsw_rps_thread_join(struct nx_flowswitch *fsw, uint32_t i)
{
	struct fsw_rps_thread *frt = &fsw->fsw_rps_threads[i];
	uint64_t f = (1 * NSEC_PER_MSEC);
	uint64_t s = (1000 * NSEC_PER_SEC);
	uint32_t c = 0;

	lck_mtx_lock(&frt->frt_lock);
	frt->frt_flags |= FRT_TERMINATING;

	while (!(frt->frt_flags & FRT_TERMINATED)) {
		uint64_t t = 0;
		nanoseconds_to_absolutetime((c++ == 0) ? f : s, &t);
		clock_absolutetime_interval_to_deadline(t, &t);
		ASSERT(t != 0);

		frt->frt_flags |= FRT_TERMINATEBLOCK;
		if (!(frt->frt_flags & FRT_RUNNING)) {
			thread_wakeup_one((caddr_t)frt);
		}
		(void) assert_wait_deadline(&frt->frt_thread, THREAD_UNINT, t);
		lck_mtx_unlock(&frt->frt_lock);
		thread_block(THREAD_CONTINUE_NULL);
		lck_mtx_lock(&frt->frt_lock);
		frt->frt_flags &= ~FRT_TERMINATEBLOCK;
	}
	ASSERT(frt->frt_flags & FRT_TERMINATED);
	lck_mtx_unlock(&frt->frt_lock);
	frt->frt_thread = THREAD_NULL;
}

static void
fsw_rps_thread_spawn(struct nx_flowswitch *fsw, uint32_t i)
{
	kern_return_t error;
	struct fsw_rps_thread *frt = &fsw->fsw_rps_threads[i];
	lck_mtx_init(&frt->frt_lock, &nexus_lock_group, &nexus_lock_attr);
	frt->frt_idx = i;
	frt->frt_fsw = fsw;
	error = kernel_thread_start(fsw_rps_thread_func, frt, &frt->frt_thread);
	ASSERT(!error);
	KPKTQ_INIT(&frt->frt_pktq);
}

int
fsw_rps_set_nthreads(struct nx_flowswitch* fsw, uint32_t n)
{
	if (n > FSW_RPS_MAX_NTHREADS) {
		SK_ERR("rps nthreads %d, max %d", n, FSW_RPS_MAX_NTHREADS);
		return EINVAL;
	}

	FSW_WLOCK(fsw);
	if (n < fsw->fsw_rps_nthreads) {
		for (uint32_t i = n; i < fsw->fsw_rps_nthreads; i++) {
			fsw_rps_thread_join(fsw, i);
		}
		fsw->fsw_rps_threads = krealloc_type(struct fsw_rps_thread,
		    fsw->fsw_rps_nthreads, n, fsw->fsw_rps_threads,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	} else if (n > fsw->fsw_rps_nthreads) {
		fsw->fsw_rps_threads = krealloc_type(struct fsw_rps_thread,
		    fsw->fsw_rps_nthreads, n, fsw->fsw_rps_threads,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
		for (uint32_t i = fsw->fsw_rps_nthreads; i < n; i++) {
			fsw_rps_thread_spawn(fsw, i);
		}
	}
	fsw->fsw_rps_nthreads = n;
	FSW_WUNLOCK(fsw);
	return 0;
}

static uint32_t
get_rps_id(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
	sa_family_t af = fsw->fsw_demux(fsw, pkt);
	if (__improbable(af == AF_UNSPEC)) {
		return 0;
	}

	flow_pkt_classify(pkt, fsw->fsw_ifp, af, true);

	if (__improbable((pkt->pkt_qum_qflags &
	    QUM_F_FLOW_CLASSIFIED) == 0)) {
		return 0;
	}

	struct flow_key key;
	flow_pkt2key(pkt, true, &key);
	key.fk_mask = FKMASK_5TUPLE;

	uint32_t id = flow_key_hash(&key) % fsw->fsw_rps_nthreads;

	return id;
}

#endif /* !DEVELOPMENT && !DEBUG */

void
fsw_receive(struct nx_flowswitch *fsw, struct pktq *pktq)
{
	FSW_RLOCK(fsw);
#if (DEVELOPMENT || DEBUG)
	if (fsw->fsw_rps_nthreads != 0) {
		struct __kern_packet *pkt, *tpkt;
		bitmap_t map = 0;

		_CASSERT(BITMAP_LEN(FSW_RPS_MAX_NTHREADS) == 1);
		KPKTQ_FOREACH_SAFE(pkt, pktq, tpkt) {
			uint32_t id = get_rps_id(fsw, pkt);
			KPKTQ_REMOVE(pktq, pkt);
			fsw_rps_rx(fsw, id, pkt);
			bitmap_set(&map, id);
		}
		for (int i = bitmap_first(&map, 64); i >= 0;
		    i = bitmap_next(&map, i)) {
			fsw_rps_thread_schedule(fsw, i);
		}
	} else
#endif /* !DEVELOPMENT && !DEBUG */
	{
		_fsw_receive_locked(fsw, pktq);
	}
	FSW_RUNLOCK(fsw);
}

int
fsw_dev_input_netem_dequeue(void *handle, pktsched_pkt_t * pkts,
    uint32_t n_pkts)
{
#pragma unused(handle)
	struct nx_flowswitch *fsw = handle;
	struct __kern_packet *kpkts[FSW_VP_DEV_BATCH_MAX];
	struct pktq pktq;
	sk_protect_t protect;
	uint32_t i;

	ASSERT(n_pkts <= FSW_VP_DEV_BATCH_MAX);

	for (i = 0; i < n_pkts; i++) {
		ASSERT(pkts[i].pktsched_ptype == QP_PACKET);
		ASSERT(pkts[i].pktsched_pkt_kpkt != NULL);
		kpkts[i] = pkts[i].pktsched_pkt_kpkt;
	}

	protect = sk_sync_protect();
	KPKTQ_INIT(&pktq);
	pkts_to_pktq(kpkts, n_pkts, &pktq);

	fsw_receive(fsw, &pktq);
	KPKTQ_FINI(&pktq);
	sk_sync_unprotect(protect);

	return 0;
}

static void
fsw_dev_input_netem_enqueue(struct nx_flowswitch *fsw, struct pktq *q)
{
	classq_pkt_t p;
	struct netem *ne;
	struct __kern_packet *pkt, *tpkt;

	ASSERT(fsw->fsw_ifp != NULL);
	ne = fsw->fsw_ifp->if_input_netem;
	ASSERT(ne != NULL);
	KPKTQ_FOREACH_SAFE(pkt, q, tpkt) {
		bool pdrop;
		KPKTQ_REMOVE(q, pkt);
		CLASSQ_PKT_INIT_PACKET(&p, pkt);
		netem_enqueue(ne, &p, &pdrop);
	}
}

void
fsw_devna_rx(struct nexus_adapter *devna, struct __kern_packet *pkt_head,
    struct nexus_pkt_stats *out_stats)
{
	struct __kern_packet *pkt = pkt_head, *next;
	struct nx_flowswitch *fsw;
	uint32_t n_bytes = 0, n_pkts = 0;
	uint64_t total_pkts = 0, total_bytes = 0;
	struct pktq q;

	KPKTQ_INIT(&q);
	if (__improbable(devna->na_ifp == NULL ||
	    (fsw = fsw_ifp_to_fsw(devna->na_ifp)) == NULL)) {
		SK_ERR("fsw not attached, dropping %d pkts", KPKTQ_LEN(&q));
		pp_free_packet_chain(pkt_head, NULL);
		return;
	}
	while (pkt != NULL) {
		if (__improbable(pkt->pkt_trace_id != 0)) {
			KDBG(SK_KTRACE_PKT_RX_DRV | DBG_FUNC_END, pkt->pkt_trace_id);
			KDBG(SK_KTRACE_PKT_RX_FSW | DBG_FUNC_START, pkt->pkt_trace_id);
		}
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		if (__probable((pkt->pkt_qum_qflags & QUM_F_DROPPED) == 0)) {
			KPKTQ_ENQUEUE(&q, pkt);
			n_bytes += pkt->pkt_length;
		} else {
			DTRACE_SKYWALK1(non__finalized__drop,
			    struct __kern_packet *, pkt);
			FSW_STATS_INC(FSW_STATS_RX_PKT_NOT_FINALIZED);
			pp_free_packet_single(pkt);
			pkt = NULL;
		}
		n_pkts = KPKTQ_LEN(&q);
		if (n_pkts == fsw_rx_batch || (next == NULL && n_pkts > 0)) {
			if (__improbable(fsw->fsw_ifp->if_input_netem != NULL)) {
				fsw_dev_input_netem_enqueue(fsw, &q);
			} else {
				fsw_receive(fsw, &q);
			}
			total_pkts += n_pkts;
			total_bytes += n_bytes;
			n_pkts = 0;
			n_bytes = 0;
			KPKTQ_FINI(&q);
		}
		pkt = next;
	}
	ASSERT(KPKTQ_LEN(&q) == 0);
	FSW_STATS_ADD(FSW_STATS_RX_PACKETS, total_pkts);
	if (out_stats != NULL) {
		out_stats->nps_pkts = total_pkts;
		out_stats->nps_bytes = total_bytes;
	}
	KDBG(SK_KTRACE_FSW_DEV_RING_FLUSH, SK_KVA(devna), total_pkts, total_bytes);
}

static int
dp_copy_to_dev_mbuf(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	struct mbuf *m = NULL;
	uint32_t bdlen, bdlim, bdoff;
	uint8_t *bdaddr;
	unsigned int one = 1;
	int err = 0;

	err = mbuf_allocpacket(MBUF_DONTWAIT,
	    (fsw->fsw_frame_headroom + spkt->pkt_length), &one, &m);
#if (DEVELOPMENT || DEBUG)
	if (m != NULL) {
		_FSW_INJECT_ERROR(11, m, NULL, m_freem, m);
	}
#endif /* DEVELOPMENT || DEBUG */
	if (__improbable(m == NULL)) {
		FSW_STATS_INC(FSW_STATS_DROP_NOMEM_MBUF);
		err = ENOBUFS;
		goto done;
	}

	MD_BUFLET_ADDR_ABS_DLEN(dpkt, bdaddr, bdlen, bdlim, bdoff);
	if (fsw->fsw_frame_headroom > bdlim) {
		SK_ERR("not enough space in buffer for headroom");
		err = EINVAL;
		goto done;
	}

	dpkt->pkt_headroom = fsw->fsw_frame_headroom;
	dpkt->pkt_mbuf = m;
	dpkt->pkt_pflags |= PKT_F_MBUF_DATA;

	/* packet copy into mbuf */
	fsw->fsw_pkt_copy_to_mbuf(NR_TX, SK_PTR_ENCODE(spkt,
	    METADATA_TYPE(spkt), METADATA_SUBTYPE(spkt)), 0, m,
	    fsw->fsw_frame_headroom, spkt->pkt_length,
	    PACKET_HAS_PARTIAL_CHECKSUM(spkt),
	    spkt->pkt_csum_tx_start_off);
	FSW_STATS_INC(FSW_STATS_TX_COPY_PKT2MBUF);

	/* header copy into dpkt buffer for classification */
	kern_packet_t sph = SK_PTR_ENCODE(spkt,
	    METADATA_TYPE(spkt), METADATA_SUBTYPE(spkt));
	kern_packet_t dph = SK_PTR_ENCODE(dpkt,
	    METADATA_TYPE(dpkt), METADATA_SUBTYPE(dpkt));
	uint32_t copy_len = MIN(spkt->pkt_length, bdlim - dpkt->pkt_headroom);
	fsw->fsw_pkt_copy_from_pkt(NR_TX, dph, dpkt->pkt_headroom,
	    sph, spkt->pkt_headroom, copy_len, FALSE, 0, 0, 0);

	/*
	 * fsw->fsw_frame_headroom is after m_data, thus we treat m_data same as
	 * buflet baddr m_data always points to the beginning of packet and
	 * should represents the same as baddr + headroom
	 */
	ASSERT((uintptr_t)m->m_data ==
	    ((uintptr_t)mbuf_datastart(m) + fsw->fsw_frame_headroom));

done:
	return err;
}

static int
dp_copy_to_dev_pkt(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	uint16_t headroom = fsw->fsw_frame_headroom + ifp->if_tx_headroom;

	if (headroom > UINT8_MAX) {
		SK_ERR("headroom too large %d", headroom);
		return ERANGE;
	}
	dpkt->pkt_headroom = (uint8_t)headroom;
	ASSERT((dpkt->pkt_headroom & 0x7) == 0);
	dpkt->pkt_l2_len = 0;
	dpkt->pkt_link_flags = spkt->pkt_link_flags;

	kern_packet_t sph = SK_PTR_ENCODE(spkt,
	    METADATA_TYPE(spkt), METADATA_SUBTYPE(spkt));
	kern_packet_t dph = SK_PTR_ENCODE(dpkt,
	    METADATA_TYPE(dpkt), METADATA_SUBTYPE(dpkt));
	fsw->fsw_pkt_copy_from_pkt(NR_TX, dph,
	    dpkt->pkt_headroom, sph, spkt->pkt_headroom,
	    spkt->pkt_length, PACKET_HAS_PARTIAL_CHECKSUM(spkt),
	    (spkt->pkt_csum_tx_start_off - spkt->pkt_headroom),
	    (spkt->pkt_csum_tx_stuff_off - spkt->pkt_headroom),
	    (spkt->pkt_csum_flags & PACKET_CSUM_ZERO_INVERT));

	FSW_STATS_INC(FSW_STATS_TX_COPY_PKT2PKT);

	return 0;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
dp_copy_to_dev_log(struct nx_flowswitch *fsw, const struct kern_pbufpool *pp,
    struct __kern_packet *spkt, struct __kern_packet *dpkt, int error)
{
	struct proc *p = current_proc();
	struct ifnet *ifp = fsw->fsw_ifp;
	uint64_t logflags = (SK_VERB_FSW_DP | SK_VERB_TX);

	if (error == ERANGE) {
		SK_ERR("packet too long, hr(fr+tx)+slen (%u+%u)+%u > "
		    "dev_pp_max %u", (uint32_t)fsw->fsw_frame_headroom,
		    (uint32_t)ifp->if_tx_headroom, spkt->pkt_length,
		    (uint32_t)pp->pp_max_frags * PP_BUF_SIZE_DEF(pp));
	} else if (error == ENOBUFS) {
		SK_DF(logflags, "%s(%d) packet allocation failure",
		    sk_proc_name_address(p), sk_proc_pid(p));
	} else if (error == 0) {
		ASSERT(dpkt != NULL);
		char *daddr;
		MD_BUFLET_ADDR_ABS(dpkt, daddr);
		SK_DF(logflags, "%s(%d) splen %u dplen %u hr %u (fr/tx %u/%u)",
		    sk_proc_name_address(p), sk_proc_pid(p), spkt->pkt_length,
		    dpkt->pkt_length, (uint32_t)dpkt->pkt_headroom,
		    (uint32_t)fsw->fsw_frame_headroom,
		    (uint32_t)ifp->if_tx_headroom);
		SK_DF(logflags | SK_VERB_DUMP, "%s",
		    sk_dump("buf", daddr, dpkt->pkt_length, 128, NULL, 0));
	} else {
		SK_DF(logflags, "%s(%d) error %d", error);
	}
}
#else
#define dp_copy_to_dev_log(...)
#endif /* SK_LOG */

static void
fsw_pkt_copy_metadata(struct __kern_packet *spkt, struct __kern_packet *dpkt)
{
	ASSERT(!(spkt->pkt_pflags & PKT_F_MBUF_MASK));
	ASSERT(!(spkt->pkt_pflags & PKT_F_PKT_MASK));

	SK_PREFETCHW(dpkt->pkt_qum_buf.buf_addr, 0);
	/* Copy packet metadata */
	_QUM_COPY(&(spkt)->pkt_qum, &(dpkt)->pkt_qum);
	_PKT_COPY(spkt, dpkt);
	_PKT_COPY_TX_PORT_DATA(spkt, dpkt);
	ASSERT((dpkt->pkt_qum.qum_qflags & QUM_F_KERNEL_ONLY) ||
	    !PP_KERNEL_ONLY(dpkt->pkt_qum.qum_pp));
	ASSERT(dpkt->pkt_mbuf == NULL);

	/* Copy AQM metadata */
	dpkt->pkt_flowsrc_type = spkt->pkt_flowsrc_type;
	dpkt->pkt_flowsrc_fidx = spkt->pkt_flowsrc_fidx;
	_CASSERT((offsetof(struct __flow, flow_src_id) % 8) == 0);
	_UUID_COPY(dpkt->pkt_flowsrc_id, spkt->pkt_flowsrc_id);
	_UUID_COPY(dpkt->pkt_policy_euuid, spkt->pkt_policy_euuid);
	dpkt->pkt_policy_id = spkt->pkt_policy_id;
	dpkt->pkt_skip_policy_id = spkt->pkt_skip_policy_id;
}

static int
dp_copy_to_dev(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	const struct kern_pbufpool *pp = dpkt->pkt_qum.qum_pp;
	struct ifnet *ifp = fsw->fsw_ifp;
	uint32_t dev_pkt_len;
	int err = 0;

	fsw_pkt_copy_metadata(spkt, dpkt);
	switch (fsw->fsw_classq_enq_ptype) {
	case QP_MBUF:
		err = dp_copy_to_dev_mbuf(fsw, spkt, dpkt);
		break;

	case QP_PACKET:
		dev_pkt_len = fsw->fsw_frame_headroom + ifp->if_tx_headroom +
		    spkt->pkt_length;
		if (dev_pkt_len > pp->pp_max_frags * PP_BUF_SIZE_DEF(pp)) {
			FSW_STATS_INC(FSW_STATS_TX_COPY_BAD_LEN);
			err = ERANGE;
			goto done;
		}
		err = dp_copy_to_dev_pkt(fsw, spkt, dpkt);
		break;

	default:
		VERIFY(0);
		__builtin_unreachable();
	}
done:
	dp_copy_to_dev_log(fsw, pp, spkt, dpkt, err);
	return err;
}

static int
dp_copy_headers_to_dev(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	uint8_t *sbaddr, *dbaddr;
	uint16_t headroom = fsw->fsw_frame_headroom + fsw->fsw_ifp->if_tx_headroom;
	uint16_t hdrs_len_estimate = (uint16_t)MIN(spkt->pkt_length, 128);

	fsw_pkt_copy_metadata(spkt, dpkt);

	MD_BUFLET_ADDR_ABS(spkt, sbaddr);
	ASSERT(sbaddr != NULL);
	sbaddr += spkt->pkt_headroom;

	MD_BUFLET_ADDR_ABS(dpkt, dbaddr);
	ASSERT(dbaddr != NULL);
	dpkt->pkt_headroom = (uint8_t)headroom;
	dbaddr += headroom;

	pkt_copy(sbaddr, dbaddr, hdrs_len_estimate);
	METADATA_SET_LEN(dpkt, hdrs_len_estimate, headroom);

	/* packet length is set to the full length */
	dpkt->pkt_length = spkt->pkt_length;
	dpkt->pkt_pflags |= PKT_F_TRUNCATED;
	return 0;
}

static struct mbuf *
convert_pkt_to_mbuf(struct __kern_packet *pkt)
{
	ASSERT(pkt->pkt_pflags & PKT_F_MBUF_DATA);
	ASSERT(pkt->pkt_mbuf != NULL);
	struct mbuf *m = pkt->pkt_mbuf;

	/* pass additional metadata generated from flow parse/lookup */
	_CASSERT(sizeof(m->m_pkthdr.pkt_flowid) ==
	    sizeof(pkt->pkt_flow_token));
	_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_srcid) ==
	    sizeof(pkt->pkt_flowsrc_token));
	_CASSERT(sizeof(m->m_pkthdr.pkt_mpriv_fidx) ==
	    sizeof(pkt->pkt_flowsrc_fidx));
	m->m_pkthdr.pkt_svc = pkt->pkt_svc_class;
	m->m_pkthdr.pkt_proto = pkt->pkt_flow->flow_ip_proto;
	m->m_pkthdr.pkt_flowid = pkt->pkt_flow_token;
	m->m_pkthdr.comp_gencnt = pkt->pkt_comp_gencnt;
	m->m_pkthdr.pkt_flowsrc = pkt->pkt_flowsrc_type;
	m->m_pkthdr.pkt_mpriv_srcid = pkt->pkt_flowsrc_token;
	m->m_pkthdr.pkt_mpriv_fidx = pkt->pkt_flowsrc_fidx;

	if (pkt->pkt_transport_protocol == IPPROTO_QUIC) {
		m->m_pkthdr.pkt_ext_flags |= PKTF_EXT_QUIC;
	}

	/* The packet should have a timestamp by the time we get here. */
	m->m_pkthdr.pkt_timestamp = pkt->pkt_timestamp;
	m->m_pkthdr.pkt_flags &= ~PKTF_TS_VALID;

	m->m_pkthdr.pkt_flags &= ~PKT_F_COMMON_MASK;
	m->m_pkthdr.pkt_flags |= (pkt->pkt_pflags & PKT_F_COMMON_MASK);
	/* set pkt_hdr so that AQM can find IP header and mark ECN bits */
	m->m_pkthdr.pkt_hdr = m->m_data + pkt->pkt_l2_len;

	if ((pkt->pkt_pflags & PKT_F_START_SEQ) != 0) {
		m->m_pkthdr.tx_start_seq = ntohl(pkt->pkt_flow_tcp_seq);
	}
	KPKT_CLEAR_MBUF_DATA(pkt);

	/* mbuf has been consumed, release packet as well */
	ASSERT(pkt->pkt_qum.qum_ksd == NULL);
	pp_free_packet_single(pkt);
	return m;
}

static void
convert_pkt_to_mbuf_list(struct __kern_packet *pkt_list,
    struct mbuf **head, struct mbuf **tail,
    uint32_t *cnt, uint32_t *bytes)
{
	struct __kern_packet *pkt = pkt_list, *next;
	struct mbuf *m_head = NULL, **m_tailp = &m_head, *m = NULL;
	uint32_t c = 0, b = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		m = convert_pkt_to_mbuf(pkt);
		ASSERT(m != NULL);

		*m_tailp = m;
		m_tailp = &m->m_nextpkt;
		c++;
		b += m_pktlen(m);
		pkt = next;
	}
	if (head != NULL) {
		*head = m_head;
	}
	if (tail != NULL) {
		*tail = m;
	}
	if (cnt != NULL) {
		*cnt = c;
	}
	if (bytes != NULL) {
		*bytes = b;
	}
}

SK_NO_INLINE_ATTRIBUTE
static int
classq_enqueue_flow_single(struct nx_flowswitch *fsw,
    struct __kern_packet *pkt)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	boolean_t pkt_drop = FALSE;
	int err;

	FSW_LOCK_ASSERT_HELD(fsw);
	ASSERT(fsw->fsw_classq_enabled);
	ASSERT(pkt->pkt_flow_token != 0);
	fsw_ifp_inc_traffic_class_out_pkt(ifp, pkt->pkt_svc_class,
	    1, pkt->pkt_length);

	if (__improbable(pkt->pkt_trace_id != 0)) {
		KDBG(SK_KTRACE_PKT_TX_FSW | DBG_FUNC_END, pkt->pkt_trace_id);
		KDBG(SK_KTRACE_PKT_TX_AQM | DBG_FUNC_START, pkt->pkt_trace_id);
	}

	switch (fsw->fsw_classq_enq_ptype) {
	case QP_MBUF: {                         /* compat interface */
		struct mbuf *m;

		m = convert_pkt_to_mbuf(pkt);
		ASSERT(m != NULL);
		pkt = NULL;

		/* ifnet_enqueue consumes mbuf */
		err = ifnet_enqueue_mbuf(ifp, m, false, &pkt_drop);
		m = NULL;
#if (DEVELOPMENT || DEBUG)
		if (__improbable(!pkt_drop)) {
			_FSW_INJECT_ERROR(14, pkt_drop, TRUE, null_func);
		}
#endif /* DEVELOPMENT || DEBUG */
		if (pkt_drop) {
			FSW_STATS_INC(FSW_STATS_DROP);
			FSW_STATS_INC(FSW_STATS_TX_AQM_DROP);
		}
		break;
	}
	case QP_PACKET: {                       /* native interface */
		/* ifnet_enqueue consumes packet */
		err = ifnet_enqueue_pkt(ifp, pkt, false, &pkt_drop);
		pkt = NULL;
#if (DEVELOPMENT || DEBUG)
		if (__improbable(!pkt_drop)) {
			_FSW_INJECT_ERROR(14, pkt_drop, TRUE, null_func);
		}
#endif /* DEVELOPMENT || DEBUG */
		if (pkt_drop) {
			FSW_STATS_INC(FSW_STATS_DROP);
			FSW_STATS_INC(FSW_STATS_TX_AQM_DROP);
		}
		break;
	}
	default:
		err = EINVAL;
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return err;
}

static int
classq_enqueue_flow_chain(struct nx_flowswitch *fsw,
    struct __kern_packet *pkt_head, struct __kern_packet *pkt_tail,
    uint32_t cnt, uint32_t bytes)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	boolean_t pkt_drop = FALSE;
	uint32_t svc;
	int err;

	FSW_LOCK_ASSERT_HELD(fsw);
	ASSERT(fsw->fsw_classq_enabled);
	ASSERT(pkt_head->pkt_flow_token != 0);

	/*
	 * All packets in the flow should have the same svc.
	 */
	svc = pkt_head->pkt_svc_class;
	fsw_ifp_inc_traffic_class_out_pkt(ifp, svc, cnt, bytes);

	switch (fsw->fsw_classq_enq_ptype) {
	case QP_MBUF: {                         /* compat interface */
		struct mbuf *m_head = NULL, *m_tail = NULL;
		uint32_t c = 0, b = 0;

		convert_pkt_to_mbuf_list(pkt_head, &m_head, &m_tail, &c, &b);
		ASSERT(m_head != NULL && m_tail != NULL);
		ASSERT(c == cnt);
		ASSERT(b == bytes);
		pkt_head = NULL;

		/* ifnet_enqueue consumes mbuf */
		err = ifnet_enqueue_mbuf_chain(ifp, m_head, m_tail, cnt,
		    bytes, FALSE, &pkt_drop);
		m_head = NULL;
		m_tail = NULL;
#if (DEVELOPMENT || DEBUG)
		if (__improbable(!pkt_drop)) {
			_FSW_INJECT_ERROR(14, pkt_drop, TRUE, null_func);
		}
#endif /* DEVELOPMENT || DEBUG */
		if (pkt_drop) {
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_DROP, cnt);
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_TX_AQM_DROP,
			    cnt);
		}
		break;
	}
	case QP_PACKET: {                       /* native interface */
		/* ifnet_enqueue consumes packet */
		err = ifnet_enqueue_pkt_chain(ifp, pkt_head, pkt_tail, cnt,
		    bytes, FALSE, &pkt_drop);
		pkt_head = NULL;
#if (DEVELOPMENT || DEBUG)
		if (__improbable(!pkt_drop)) {
			_FSW_INJECT_ERROR(14, pkt_drop, TRUE, null_func);
		}
#endif /* DEVELOPMENT || DEBUG */
		if (pkt_drop) {
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_DROP, cnt);
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_TX_AQM_DROP,
			    cnt);
		}
		break;
	}
	default:
		err = EINVAL;
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return err;
}

/*
 * This code path needs to be kept for interfaces without logical link support.
 */
static void
classq_enqueue_flow(struct nx_flowswitch *fsw, struct flow_entry *fe,
    bool chain, uint32_t cnt, uint32_t bytes)
{
	bool flowadv_is_set = false;
	struct __kern_packet *pkt, *tail, *tpkt;
	flowadv_idx_t flow_adv_idx;
	bool flowadv_cap;
	flowadv_token_t flow_adv_token;
	int err;

	SK_DF(SK_VERB_FSW_DP | SK_VERB_AQM, "%s classq enqueued %d pkts",
	    if_name(fsw->fsw_ifp), KPKTQ_LEN(&fe->fe_tx_pktq));

	if (chain) {
		pkt = KPKTQ_FIRST(&fe->fe_tx_pktq);
		tail = KPKTQ_LAST(&fe->fe_tx_pktq);
		KPKTQ_INIT(&fe->fe_tx_pktq);
		if (pkt == NULL) {
			return;
		}
		flow_adv_idx = pkt->pkt_flowsrc_fidx;
		flowadv_cap = ((pkt->pkt_pflags & PKT_F_FLOW_ADV) != 0);
		flow_adv_token = pkt->pkt_flow_token;

		err = classq_enqueue_flow_chain(fsw, pkt, tail, cnt, bytes);

		/* set flow advisory if needed */
		if (__improbable((err == EQFULL || err == EQSUSPENDED) &&
		    flowadv_cap)) {
			flowadv_is_set = na_flowadv_set(flow_get_na(fsw, fe),
			    flow_adv_idx, flow_adv_token);
		}
		DTRACE_SKYWALK3(chain__enqueue, uint32_t, cnt, uint32_t, bytes,
		    bool, flowadv_is_set);
	} else {
		uint32_t c = 0, b = 0;

		KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
			KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);

			flow_adv_idx = pkt->pkt_flowsrc_fidx;
			flowadv_cap = ((pkt->pkt_pflags & PKT_F_FLOW_ADV) != 0);
			flow_adv_token = pkt->pkt_flow_token;

			c++;
			b += pkt->pkt_length;
			err = classq_enqueue_flow_single(fsw, pkt);

			/* set flow advisory if needed */
			if (__improbable(!flowadv_is_set &&
			    ((err == EQFULL || err == EQSUSPENDED) &&
			    flowadv_cap))) {
				flowadv_is_set = na_flowadv_set(
					flow_get_na(fsw, fe), flow_adv_idx,
					flow_adv_token);
			}
		}
		ASSERT(c == cnt);
		ASSERT(b == bytes);
		DTRACE_SKYWALK3(non__chain__enqueue, uint32_t, cnt, uint32_t, bytes,
		    bool, flowadv_is_set);
	}

	/* notify flow advisory event */
	if (__improbable(flowadv_is_set)) {
		struct __kern_channel_ring *r = fsw_flow_get_tx_ring(fsw, fe);
		if (__probable(r)) {
			na_flowadv_event(r);
			SK_DF(SK_VERB_FLOW_ADVISORY | SK_VERB_TX,
			    "%s(%d) notified of flow update",
			    sk_proc_name_address(current_proc()),
			    sk_proc_pid(current_proc()));
		}
	}
}

/*
 * Logical link code path
 */
static void
classq_qset_enqueue_flow(struct nx_flowswitch *fsw, struct flow_entry *fe,
    bool chain, uint32_t cnt, uint32_t bytes)
{
#pragma unused(chain)
	struct __kern_packet *pkt, *tail;
	flowadv_idx_t flow_adv_idx;
	bool flowadv_is_set = false;
	bool flowadv_cap;
	flowadv_token_t flow_adv_token;
	uint32_t flowctl = 0, dropped = 0;
	int err;

	SK_DF(SK_VERB_FSW_DP | SK_VERB_AQM, "%s classq enqueued %d pkts",
	    if_name(fsw->fsw_ifp), KPKTQ_LEN(&fe->fe_tx_pktq));

	pkt = KPKTQ_FIRST(&fe->fe_tx_pktq);
	tail = KPKTQ_LAST(&fe->fe_tx_pktq);
	KPKTQ_INIT(&fe->fe_tx_pktq);
	if (pkt == NULL) {
		return;
	}
	flow_adv_idx = pkt->pkt_flowsrc_fidx;
	flowadv_cap = ((pkt->pkt_pflags & PKT_F_FLOW_ADV) != 0);
	flow_adv_token = pkt->pkt_flow_token;

	err = netif_qset_enqueue(fe->fe_qset, pkt, tail, cnt, bytes,
	    &flowctl, &dropped);

	if (__improbable(err != 0)) {
		/* set flow advisory if needed */
		if (flowctl > 0 && flowadv_cap) {
			flowadv_is_set = na_flowadv_set(flow_get_na(fsw, fe),
			    flow_adv_idx, flow_adv_token);

			/* notify flow advisory event */
			if (flowadv_is_set) {
				struct __kern_channel_ring *r =
				    fsw_flow_get_tx_ring(fsw, fe);
				if (__probable(r)) {
					na_flowadv_event(r);
					SK_DF(SK_VERB_FLOW_ADVISORY |
					    SK_VERB_TX,
					    "%s(%d) notified of flow update",
					    sk_proc_name_address(current_proc()),
					    sk_proc_pid(current_proc()));
				}
			}
		}
		if (dropped > 0) {
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_DROP, dropped);
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_TX_AQM_DROP,
			    dropped);
		}
	}
}

static void
tx_finalize_packet(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
#pragma unused(fsw)
	/* finalize here; no more changes to buflets after classq */
	if (__probable(!(pkt->pkt_pflags & PKT_F_MBUF_DATA))) {
		kern_packet_t ph = SK_PTR_ENCODE(pkt,
		    METADATA_TYPE(pkt), METADATA_SUBTYPE(pkt));
		int err = __packet_finalize(ph);
		VERIFY(err == 0);
	}
}

static bool
dp_flow_tx_route_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct flow_route *fr = fe->fe_route;
	int err;

	ASSERT(fr != NULL);

	if (__improbable(!dp_flow_route_process(fsw, fe))) {
		return false;
	}
	if (fe->fe_qset_select == FE_QSET_SELECT_DYNAMIC) {
		flow_qset_select_dynamic(fsw, fe, TRUE);
	}

	_FSW_INJECT_ERROR(35, fr->fr_flags, fr->fr_flags,
	    _fsw_error35_handler, 1, fr, NULL, NULL);
	_FSW_INJECT_ERROR(36, fr->fr_flags, fr->fr_flags,
	    _fsw_error36_handler, 1, fr, NULL);

	/*
	 * See if we need to resolve the flow route; note the test against
	 * fr_flags here is done without any lock for performance.  Thus
	 * it's possible that we race against the thread performing route
	 * event updates for a packet (which is OK).  In any case we should
	 * not have any assertion on fr_flags value(s) due to the lack of
	 * serialization.
	 */
	if (fr->fr_flags & FLOWRTF_RESOLVED) {
		goto frame;
	}

	struct __kern_packet *pkt, *tpkt;
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		err = fsw->fsw_resolve(fsw, fr, pkt);
		_FSW_INJECT_ERROR_SET(35, _fsw_error35_handler, 2, fr, pkt, &err);
		_FSW_INJECT_ERROR_SET(36, _fsw_error36_handler, 2, fr, &err);
		/*
		 * If resolver returns EJUSTRETURN then we drop the pkt as the
		 * resolver should have converted the pkt into mbuf (or
		 * detached the attached mbuf from pkt) and added it to the
		 * llinfo queue. If we do have a cached llinfo, then proceed
		 * to using it even though it may be stale (very unlikely)
		 * while the resolution is in progress.
		 * Otherwise, any other error results in dropping pkt.
		 */
		if (err == EJUSTRETURN) {
			KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);
			pp_free_packet_single(pkt);
			FSW_STATS_INC(FSW_STATS_TX_RESOLV_PENDING);
			continue;
		} else if (err != 0 && (fr->fr_flags & FLOWRTF_HAS_LLINFO)) {
			/* use existing llinfo */
			FSW_STATS_INC(FSW_STATS_TX_RESOLV_STALE);
		} else if (err != 0) {
			KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);
			pp_free_packet_single(pkt);
			FSW_STATS_INC(FSW_STATS_TX_RESOLV_FAIL);
			continue;
		}
	}

frame:
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		if (fsw->fsw_frame != NULL) {
			fsw->fsw_frame(fsw, fr, pkt);
		}
	}

	return true;
}

static void
dp_listener_flow_tx_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
#pragma unused(fsw)
	struct __kern_packet *pkt, *tpkt;
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);
		/* listener is only allowed TCP RST */
		if (pkt->pkt_flow_ip_proto == IPPROTO_TCP &&
		    (pkt->pkt_flow_tcp_flags & TH_RST) != 0) {
			flow_track_abort_tcp(fe, NULL, pkt);
		} else {
			char *addr;
			MD_BUFLET_ADDR_ABS(pkt, addr);
			SK_ERR("listener flow sends non-RST packet %s",
			    sk_dump(sk_proc_name_address(current_proc()),
			    addr, pkt->pkt_length, 128, NULL, 0));
		}
		pp_free_packet_single(pkt);
	}
}

static void
fsw_update_timestamps(struct __kern_packet *pkt, volatile uint64_t *fg_ts,
    volatile uint64_t *rt_ts, ifnet_t ifp)
{
	struct timespec now;
	uint64_t now_nsec = 0;

	if (!(pkt->pkt_pflags & PKT_F_TS_VALID) || pkt->pkt_timestamp == 0) {
		nanouptime(&now);
		net_timernsec(&now, &now_nsec);
		pkt->pkt_timestamp = now_nsec;
	}
	pkt->pkt_pflags &= ~PKT_F_TS_VALID;

	/*
	 * If the packet service class is not background,
	 * update the timestamps on the interface, as well as
	 * the ones in nexus-wide advisory to indicate recent
	 * activity on a foreground flow.
	 */
	if (!(pkt->pkt_pflags & PKT_F_BACKGROUND)) {
		ifp->if_fg_sendts = (uint32_t)_net_uptime;
		if (fg_ts != NULL) {
			*fg_ts = _net_uptime;
		}
	}
	if (pkt->pkt_pflags & PKT_F_REALTIME) {
		ifp->if_rt_sendts = (uint32_t)_net_uptime;
		if (rt_ts != NULL) {
			*rt_ts = _net_uptime;
		}
	}
}

static bool
fsw_chain_enqueue_enabled(struct nx_flowswitch *fsw, bool gso_enabled)
{
	return fsw_chain_enqueue != 0 &&
	       fsw->fsw_ifp->if_output_netem == NULL &&
	       (fsw->fsw_ifp->if_eflags & IFEF_ENQUEUE_MULTI) == 0 &&
	       gso_enabled;
}

void
dp_flow_tx_process(struct nx_flowswitch *fsw, struct flow_entry *fe,
    uint32_t flags)
{
	struct pktq dropped_pkts;
	bool chain, gso = ((flags & FLOW_PROC_FLAG_GSO) != 0);
	uint32_t cnt = 0, bytes = 0;
	volatile struct sk_nexusadv *nxadv = NULL;
	volatile uint64_t *fg_ts = NULL;
	volatile uint64_t *rt_ts = NULL;
	uint8_t qset_idx = (fe->fe_qset != NULL) ? fe->fe_qset->nqs_idx : 0;

	KPKTQ_INIT(&dropped_pkts);
	ASSERT(!KPKTQ_EMPTY(&fe->fe_tx_pktq));
	if (__improbable(fe->fe_flags & FLOWENTF_LISTENER)) {
		dp_listener_flow_tx_process(fsw, fe);
		return;
	}
	if (__improbable(!dp_flow_tx_route_process(fsw, fe))) {
		SK_RDERR(5, "Tx route bad");
		FSW_STATS_ADD(FSW_STATS_TX_FLOW_NONVIABLE,
		    KPKTQ_LEN(&fe->fe_tx_pktq));
		KPKTQ_CONCAT(&dropped_pkts, &fe->fe_tx_pktq);
		goto done;
	}
	chain = fsw_chain_enqueue_enabled(fsw, gso);
	if (chain) {
		nxadv = fsw->fsw_nx->nx_adv.flowswitch_nxv_adv;
		if (nxadv != NULL) {
			fg_ts = &nxadv->nxadv_fg_sendts;
			rt_ts = &nxadv->nxadv_rt_sendts;
		}
	}
	struct __kern_packet *pkt, *tpkt;
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		int err = 0;

		err = flow_pkt_track(fe, pkt, false);
		if (__improbable(err != 0)) {
			SK_RDERR(5, "flow_pkt_track failed (err %d)", err);
			FSW_STATS_INC(FSW_STATS_TX_FLOW_TRACK_ERR);
			KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			continue;
		}
		_UUID_COPY(pkt->pkt_policy_euuid, fe->fe_eproc_uuid);
		pkt->pkt_transport_protocol = fe->fe_transport_protocol;

		/* set AQM related values for outgoing packet */
		if (fe->fe_adv_idx != FLOWADV_IDX_NONE) {
			pkt->pkt_pflags |= PKT_F_FLOW_ADV;
			pkt->pkt_flowsrc_type = FLOWSRC_CHANNEL;
			pkt->pkt_flowsrc_fidx = fe->fe_adv_idx;
		} else {
			pkt->pkt_pflags &= ~PKT_F_FLOW_ADV;
		}
		_UUID_CLEAR(pkt->pkt_flow_id);
		pkt->pkt_flow_token = fe->fe_flowid;
		pkt->pkt_pflags |= PKT_F_FLOW_ID;
		pkt->pkt_qset_idx = qset_idx;
		pkt->pkt_policy_id = fe->fe_policy_id;
		pkt->pkt_skip_policy_id = fe->fe_skip_policy_id;

		/*
		 * The same code is exercised per packet for the non-chain case
		 * (see ifnet_enqueue_ifclassq()). It's replicated here to avoid
		 * re-walking the chain later.
		 */
		if (chain) {
			fsw_update_timestamps(pkt, fg_ts, rt_ts, fsw->fsw_ifp);
		}
		/* mark packet tos/svc_class */
		fsw_qos_mark(fsw, fe, pkt);

		tx_finalize_packet(fsw, pkt);
		bytes += pkt->pkt_length;
		cnt++;
	}

	/* snoop after it's finalized */
	if (__improbable(pktap_total_tap_count != 0)) {
		fsw_snoop(fsw, fe, false);
	}
	if (fe->fe_qset != NULL) {
		classq_qset_enqueue_flow(fsw, fe, chain, cnt, bytes);
	} else {
		classq_enqueue_flow(fsw, fe, chain, cnt, bytes);
	}
done:
	dp_drop_pktq(fsw, &dropped_pkts);
}

static struct flow_entry *
tx_process_continuous_ip_frag(struct nx_flowswitch *fsw,
    struct flow_entry *prev_fe, struct __kern_packet *pkt)
{
	ASSERT(!pkt->pkt_flow_ip_is_first_frag);

	if (__improbable(pkt->pkt_flow_ip_frag_id == 0)) {
		FSW_STATS_INC(FSW_STATS_TX_FRAG_BAD_ID);
		SK_ERR("%s(%d) invalid zero fragment id",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()));
		return NULL;
	}

	SK_DF(SK_VERB_FSW_DP | SK_VERB_TX,
	    "%s(%d) continuation frag, id %u",
	    sk_proc_name_address(current_proc()),
	    sk_proc_pid(current_proc()),
	    pkt->pkt_flow_ip_frag_id);
	if (__improbable(prev_fe == NULL ||
	    !prev_fe->fe_tx_is_cont_frag)) {
		SK_ERR("%s(%d) unexpected continuation frag",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()),
		    pkt->pkt_flow_ip_frag_id);
		FSW_STATS_INC(FSW_STATS_TX_FRAG_BAD_CONT);
		return NULL;
	}
	if (__improbable(pkt->pkt_flow_ip_frag_id !=
	    prev_fe->fe_tx_frag_id)) {
		FSW_STATS_INC(FSW_STATS_TX_FRAG_BAD_CONT);
		SK_ERR("%s(%d) wrong continuation frag id %u expecting %u",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()),
		    pkt->pkt_flow_ip_frag_id,
		    prev_fe->fe_tx_frag_id);
		return NULL;
	}

	return prev_fe;
}

static struct flow_entry *
tx_lookup_flow(struct nx_flowswitch *fsw, struct __kern_packet *pkt,
    struct flow_entry *prev_fe)
{
	struct flow_entry *fe;

	fe = lookup_flow_with_pkt(fsw, pkt, false, prev_fe);
	if (__improbable(fe == NULL)) {
		goto done;
	}

	if (__improbable(fe->fe_flags & FLOWENTF_TORN_DOWN)) {
		SK_RDERR(5, "Tx flow torn down");
		FSW_STATS_INC(FSW_STATS_TX_FLOW_TORNDOWN);
		flow_entry_release(&fe);
		goto done;
	}

	_FSW_INJECT_ERROR(34, pkt->pkt_flow_id[0], fe->fe_uuid[0] + 1,
	    null_func);

	if (__improbable(!_UUID_MATCH(pkt->pkt_flow_id, fe->fe_uuid))) {
		uuid_string_t flow_id_str, pkt_id_str;
		sk_uuid_unparse(fe->fe_uuid, flow_id_str);
		sk_uuid_unparse(pkt->pkt_flow_id, pkt_id_str);
		SK_ERR("pkt flow id %s != flow id %s", pkt_id_str, flow_id_str);
		flow_entry_release(&fe);
		FSW_STATS_INC(FSW_STATS_TX_FLOW_BAD_ID);
	}

done:
	return fe;
}

static inline void
tx_flow_process(struct nx_flowswitch *fsw, struct flow_entry *fe,
    uint32_t flags)
{
	ASSERT(!KPKTQ_EMPTY(&fe->fe_tx_pktq));
	ASSERT(KPKTQ_LEN(&fe->fe_tx_pktq) != 0);

	SK_DF(SK_VERB_FSW_DP | SK_VERB_TX, "TX %d pkts from fe %p port %d",
	    KPKTQ_LEN(&fe->fe_tx_pktq), fe, fe->fe_nx_port);

	/* flow related processing (default, agg, etc.) */
	fe->fe_tx_process(fsw, fe, flags);

	KPKTQ_FINI(&fe->fe_tx_pktq);
}

#if SK_LOG
static void
dp_tx_log_pkt(uint64_t verb, char *desc, struct __kern_packet *pkt)
{
	char *pkt_buf;
	MD_BUFLET_ADDR_ABS(pkt, pkt_buf);
	SK_DF(verb, "%s(%d) %s %s", sk_proc_name_address(current_proc()),
	    sk_proc_pid(current_proc()), desc, sk_dump("buf", pkt_buf,
	    pkt->pkt_length, 128, NULL, 0));
}
#else /* !SK_LOG */
#define dp_tx_log_pkt(...)
#endif /* !SK_LOG */

static void
dp_tx_pktq(struct nx_flowswitch *fsw, struct pktq *spktq)
{
	struct __kern_packet *spkt, *pkt;
	struct flow_entry_list fes = TAILQ_HEAD_INITIALIZER(fes);
	struct flow_entry *fe, *prev_fe;
	struct pktq dropped_pkts, dpktq;
	struct nexus_adapter *dev_na;
	struct kern_pbufpool *dev_pp;
	struct ifnet *ifp;
	sa_family_t af;
	uint32_t n_pkts, n_flows = 0;
	boolean_t do_pacing = FALSE;

	int err;
	KPKTQ_INIT(&dpktq);
	KPKTQ_INIT(&dropped_pkts);
	n_pkts = KPKTQ_LEN(spktq);

	FSW_RLOCK(fsw);
	if (__improbable(FSW_QUIESCED(fsw))) {
		DTRACE_SKYWALK1(tx__quiesced, struct nx_flowswitch *, fsw);
		SK_ERR("flowswitch detached, dropping %d pkts", n_pkts);
		KPKTQ_CONCAT(&dropped_pkts, spktq);
		goto done;
	}
	dev_na = fsw->fsw_dev_ch->ch_na;
	if (__improbable(dev_na == NULL)) {
		SK_ERR("dev port not attached, dropping %d pkts", n_pkts);
		FSW_STATS_ADD(FSW_STATS_DST_NXPORT_INACTIVE, n_pkts);
		KPKTQ_CONCAT(&dropped_pkts, spktq);
		goto done;
	}
	/*
	 * fsw_ifp should still be valid at this point. If fsw is detached
	 * after fsw_lock is released, this ifp will remain valid and
	 * netif_transmit() will behave properly even if the ifp is in
	 * detached state.
	 */
	ifp = fsw->fsw_ifp;

	/* batch allocate enough packets */
	dev_pp = na_kr_get_pp(dev_na, NR_TX);

	err = pp_alloc_pktq(dev_pp, dev_pp->pp_max_frags, &dpktq, n_pkts, NULL,
	    NULL, SKMEM_NOSLEEP);
#if DEVELOPMENT || DEBUG
	if (__probable(err != ENOMEM)) {
		_FSW_INJECT_ERROR(12, err, ENOMEM, pp_free_pktq, &dpktq);
	}
#endif /* DEVELOPMENT || DEBUG */
	if (__improbable(err == ENOMEM)) {
		ASSERT(KPKTQ_EMPTY(&dpktq));
		KPKTQ_CONCAT(&dropped_pkts, spktq);
		FSW_STATS_ADD(FSW_STATS_DROP_NOMEM_PKT, n_pkts);
		SK_ERR("failed to alloc %u pkts from device pool", n_pkts);
		goto done;
	} else if (__improbable(err == EAGAIN)) {
		FSW_STATS_ADD(FSW_STATS_DROP_NOMEM_PKT,
		    (n_pkts - KPKTQ_LEN(&dpktq)));
		FSW_STATS_ADD(FSW_STATS_DROP,
		    (n_pkts - KPKTQ_LEN(&dpktq)));
	}

	n_pkts = KPKTQ_LEN(&dpktq);
	prev_fe = NULL;
	KPKTQ_FOREACH(spkt, spktq) {
		if (n_pkts == 0) {
			break;
		}
		--n_pkts;

		KPKTQ_DEQUEUE(&dpktq, pkt);
		ASSERT(pkt != NULL);
		err = dp_copy_to_dev(fsw, spkt, pkt);
		if (__improbable(err != 0)) {
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			continue;
		}

		do_pacing |= ((pkt->pkt_pflags & PKT_F_OPT_TX_TIMESTAMP) != 0);
		af = fsw_ip_demux(fsw, pkt);
		if (__improbable(af == AF_UNSPEC)) {
			dp_tx_log_pkt(SK_VERB_ERROR, "demux err", pkt);
			FSW_STATS_INC(FSW_STATS_TX_DEMUX_ERR);
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			continue;
		}

		err = flow_pkt_classify(pkt, ifp, af, false);
		if (__improbable(err != 0)) {
			dp_tx_log_pkt(SK_VERB_ERROR, "flow extract err", pkt);
			FSW_STATS_INC(FSW_STATS_TX_FLOW_EXTRACT_ERR);
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			continue;
		}

		if (__improbable(pkt->pkt_flow_ip_is_frag &&
		    !pkt->pkt_flow_ip_is_first_frag)) {
			fe = tx_process_continuous_ip_frag(fsw, prev_fe, pkt);
			if (__probable(fe != NULL)) {
				flow_entry_retain(fe);
				goto flow_batch;
			} else {
				FSW_STATS_INC(FSW_STATS_TX_FRAG_BAD_CONT);
				KPKTQ_ENQUEUE(&dropped_pkts, pkt);
				continue;
			}
		}

		fe = tx_lookup_flow(fsw, pkt, prev_fe);
		if (__improbable(fe == NULL)) {
			FSW_STATS_INC(FSW_STATS_TX_FLOW_NOT_FOUND);
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			prev_fe = NULL;
			continue;
		}
flow_batch:
		tx_flow_batch_packet(&fes, fe, pkt);
		prev_fe = fe;
	}

	struct flow_entry *tfe = NULL;
	TAILQ_FOREACH_SAFE(fe, &fes, fe_tx_link, tfe) {
		tx_flow_process(fsw, fe, 0);
		TAILQ_REMOVE(&fes, fe, fe_tx_link);
		fe->fe_tx_is_cont_frag = false;
		fe->fe_tx_frag_id = 0;
		flow_entry_release(&fe);
		n_flows++;
	}

done:
	FSW_RUNLOCK(fsw);
	if (n_flows > 0) {
		netif_transmit(ifp, NETIF_XMIT_FLAG_CHANNEL | (do_pacing ? NETIF_XMIT_FLAG_PACING : 0));
	}
	dp_drop_pktq(fsw, &dropped_pkts);
	KPKTQ_FINI(&dropped_pkts);
	KPKTQ_FINI(&dpktq);
}

static sa_family_t
get_tso_af(struct __kern_packet *pkt)
{
	packet_tso_flags_t tso_flags;

	tso_flags = pkt->pkt_csum_flags & PACKET_CSUM_TSO_FLAGS;
	if (tso_flags == PACKET_TSO_IPV4) {
		return AF_INET;
	} else if (tso_flags == PACKET_TSO_IPV6) {
		return AF_INET6;
	} else {
		panic("invalid tso flags: 0x%x\n", tso_flags);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static inline void
update_flow_info(struct __kern_packet *pkt, void *iphdr, void *tcphdr,
    uint16_t payload_sz)
{
	struct tcphdr *tcp = tcphdr;

	DTRACE_SKYWALK4(update__flow__info, struct __kern_packet *, pkt,
	    void *, iphdr, void *, tcphdr, uint16_t, payload_sz);
	pkt->pkt_flow_ip_hdr = (mach_vm_address_t)iphdr;
	pkt->pkt_flow_tcp_hdr = (mach_vm_address_t)tcphdr;
	pkt->pkt_flow_tcp_flags = tcp->th_flags;
	pkt->pkt_flow_tcp_seq = tcp->th_seq;
	pkt->pkt_flow_ulen = payload_sz;
}

static int
do_gso(struct nx_flowswitch *fsw, int af, struct __kern_packet *orig_pkt,
    struct __kern_packet *first_pkt, struct pktq *dev_pktq,
    struct pktq *gso_pktq)
{
	ifnet_t ifp = fsw->fsw_ifp;
	struct __kern_packet *pkt = first_pkt;
	uint8_t proto = pkt->pkt_flow_ip_proto;
	uint16_t ip_hlen = pkt->pkt_flow_ip_hlen;
	uint16_t tcp_hlen = pkt->pkt_flow_tcp_hlen;
	uint16_t total_hlen = ip_hlen + tcp_hlen;
	uint16_t mtu = (uint16_t)ifp->if_mtu;
	uint16_t mss = pkt->pkt_proto_seg_sz, payload_sz;
	uint32_t n, n_pkts, off = 0, total_len = orig_pkt->pkt_length;
	uint16_t headroom = fsw->fsw_frame_headroom + ifp->if_tx_headroom;
	kern_packet_t orig_ph = SK_PKT2PH(orig_pkt);
	uint8_t *orig_pkt_baddr;
	struct tcphdr *tcp;
	struct ip *ip;
	struct ip6_hdr *ip6;
	uint32_t tcp_seq;
	uint16_t ipid;
	uint32_t pseudo_hdr_csum, bufsz;

	ASSERT(headroom <= UINT8_MAX);
	if (proto != IPPROTO_TCP) {
		SK_ERR("invalid proto: %d", proto);
		DTRACE_SKYWALK3(invalid__proto, struct nx_flowswitch *,
		    fsw, ifnet_t, ifp, uint8_t, proto);
		return EINVAL;
	}
	if (mss == 0 || mss > (mtu - total_hlen)) {
		SK_ERR("invalid args: mss %d, mtu %d, total_hlen %d",
		    mss, mtu, total_hlen);
		DTRACE_SKYWALK5(invalid__args1, struct nx_flowswitch *,
		    fsw, ifnet_t, ifp, uint16_t, mss, uint16_t, mtu,
		    uint32_t, total_hlen);
		return EINVAL;
	}
	bufsz = PP_BUF_SIZE_DEF(pkt->pkt_qum.qum_pp);
	if ((headroom + total_hlen + mss) > bufsz) {
		SK_ERR("invalid args: headroom %d, total_hlen %d, "
		    "mss %d, bufsz %d", headroom, total_hlen, mss, bufsz);
		DTRACE_SKYWALK6(invalid__args2, struct nx_flowswitch *,
		    fsw, ifnet_t, ifp, uint16_t, headroom, uint16_t,
		    total_hlen, uint16_t, mss, uint32_t, bufsz);
		return EINVAL;
	}
	n_pkts = (uint32_t)(SK_ROUNDUP((total_len - total_hlen), mss) / mss);

	ASSERT(pkt->pkt_headroom == headroom);
	ASSERT(pkt->pkt_length == total_len);
	ASSERT(pkt->pkt_l2_len == 0);
	ASSERT((pkt->pkt_qum.qum_qflags & QUM_F_FINALIZED) == 0);
	ASSERT((pkt->pkt_pflags & PKT_F_TRUNCATED) != 0);
	pkt->pkt_pflags &= ~PKT_F_TRUNCATED;
	pkt->pkt_proto_seg_sz = 0;
	pkt->pkt_csum_flags = 0;
	MD_BUFLET_ADDR_ABS(orig_pkt, orig_pkt_baddr);
	orig_pkt_baddr += orig_pkt->pkt_headroom;

	if (af == AF_INET) {
		ip = (struct ip *)pkt->pkt_flow_ip_hdr;
		tcp = (struct tcphdr *)pkt->pkt_flow_tcp_hdr;
		ipid = ip->ip_id;
		pseudo_hdr_csum = in_pseudo(pkt->pkt_flow_ipv4_src.s_addr,
		    pkt->pkt_flow_ipv4_dst.s_addr, 0);
	} else {
		ASSERT(af == AF_INET6);
		tcp = (struct tcphdr *)pkt->pkt_flow_tcp_hdr;
		pseudo_hdr_csum = in6_pseudo(&pkt->pkt_flow_ipv6_src,
		    &pkt->pkt_flow_ipv6_dst, 0);
	}
	tcp_seq = ntohl(tcp->th_seq);

	for (n = 1, payload_sz = mss, off = total_hlen; off < total_len;
	    off += payload_sz) {
		uint8_t *baddr, *baddr0;
		uint32_t partial;

		if (pkt == NULL) {
			n++;
			KPKTQ_DEQUEUE(dev_pktq, pkt);
			ASSERT(pkt != NULL);
		}
		MD_BUFLET_ADDR_ABS(pkt, baddr0);
		baddr = baddr0;
		baddr += headroom;

		/* Copy headers from the original packet */
		if (n != 1) {
			ASSERT(pkt != first_pkt);
			pkt_copy(orig_pkt_baddr, baddr, total_hlen);
			fsw_pkt_copy_metadata(first_pkt, pkt);

			ASSERT((pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED) != 0);
			/* flow info still needs to be updated below */
			bcopy(first_pkt->pkt_flow, pkt->pkt_flow,
			    sizeof(*pkt->pkt_flow));
			pkt->pkt_trace_id = 0;
			ASSERT(pkt->pkt_headroom == headroom);
		} else {
			METADATA_SET_LEN(pkt, 0, 0);
		}
		baddr += total_hlen;

		/* Copy/checksum the payload from the original packet */
		if (off + payload_sz > total_len) {
			payload_sz = (uint16_t)(total_len - off);
		}
		pkt_copypkt_sum(orig_ph,
		    (uint16_t)(orig_pkt->pkt_headroom + off),
		    SK_PKT2PH(pkt), headroom + total_hlen, payload_sz,
		    &partial, TRUE);

		DTRACE_SKYWALK6(copy__csum, struct nx_flowswitch *, fsw,
		    ifnet_t, ifp, uint8_t *, baddr, uint16_t, payload_sz,
		    uint16_t, mss, uint32_t, partial);
		FSW_STATS_INC(FSW_STATS_TX_COPY_PKT2PKT);

		/*
		 * Adjust header information and fill in the missing fields.
		 */
		if (af == AF_INET) {
			ip = (struct ip *)(void *)(baddr0 + pkt->pkt_headroom);
			tcp = (struct tcphdr *)(void *)((caddr_t)ip + ip_hlen);

			if (n != n_pkts) {
				tcp->th_flags &= ~(TH_FIN | TH_PUSH);
			}
			if (n != 1) {
				tcp->th_flags &= ~TH_CWR;
				tcp->th_seq = htonl(tcp_seq);
			}
			update_flow_info(pkt, ip, tcp, payload_sz);

			ip->ip_id = htons((ipid)++);
			ip->ip_len = htons(ip_hlen + tcp_hlen + payload_sz);
			ip->ip_sum = 0;
			ip->ip_sum = inet_cksum_buffer(ip, 0, 0, ip_hlen);
			tcp->th_sum = 0;
			partial = __packet_cksum(tcp, tcp_hlen, partial);
			partial += htons(tcp_hlen + IPPROTO_TCP + payload_sz);
			partial += pseudo_hdr_csum;
			ADDCARRY(partial);
			tcp->th_sum = ~(uint16_t)partial;
		} else {
			ASSERT(af == AF_INET6);
			ip6 = (struct ip6_hdr *)(baddr0 + pkt->pkt_headroom);
			tcp = (struct tcphdr *)(void *)((caddr_t)ip6 + ip_hlen);

			if (n != n_pkts) {
				tcp->th_flags &= ~(TH_FIN | TH_PUSH);
			}
			if (n != 1) {
				tcp->th_flags &= ~TH_CWR;
				tcp->th_seq = htonl(tcp_seq);
			}
			update_flow_info(pkt, ip6, tcp, payload_sz);

			ip6->ip6_plen = htons(tcp_hlen + payload_sz);
			tcp->th_sum = 0;
			partial = __packet_cksum(tcp, tcp_hlen, partial);
			partial += htonl(tcp_hlen + IPPROTO_TCP + payload_sz);
			partial += pseudo_hdr_csum;
			ADDCARRY(partial);
			tcp->th_sum = ~(uint16_t)partial;
		}
		tcp_seq += payload_sz;
		METADATA_ADJUST_LEN(pkt, total_hlen, headroom);
#if (DEVELOPMENT || DEBUG)
		struct __kern_buflet *bft;
		uint32_t blen;
		PKT_GET_FIRST_BUFLET(pkt, 1, bft);
		blen = __buflet_get_data_length(bft);
		if (blen != total_hlen + payload_sz) {
			panic("blen (%d) != total_len + payload_sz (%d)\n",
			    blen, total_hlen + payload_sz);
		}
#endif /* DEVELOPMENT || DEBUG */

		pkt->pkt_length = total_hlen + payload_sz;
		KPKTQ_ENQUEUE(gso_pktq, pkt);
		pkt = NULL;

		/*
		 * Note that at this point the packet is not yet finalized.
		 * The finalization happens in dp_flow_tx_process() after
		 * the framing is done.
		 */
	}
	ASSERT(n == n_pkts);
	ASSERT(off == total_len);
	DTRACE_SKYWALK7(gso__done, struct nx_flowswitch *, fsw, ifnet_t, ifp,
	    uint32_t, n_pkts, uint32_t, total_len, uint16_t, ip_hlen,
	    uint16_t, tcp_hlen, uint8_t *, orig_pkt_baddr);
	return 0;
}

static void
tx_flow_enqueue_gso_pktq(struct flow_entry_list *fes, struct flow_entry *fe,
    struct pktq *gso_pktq)
{
	if (KPKTQ_EMPTY(&fe->fe_tx_pktq)) {
		ASSERT(KPKTQ_LEN(&fe->fe_tx_pktq) == 0);
		TAILQ_INSERT_TAIL(fes, fe, fe_tx_link);
		KPKTQ_ENQUEUE_MULTI(&fe->fe_tx_pktq, KPKTQ_FIRST(gso_pktq),
		    KPKTQ_LAST(gso_pktq), KPKTQ_LEN(gso_pktq));
		KPKTQ_INIT(gso_pktq);
	} else {
		ASSERT(!TAILQ_EMPTY(fes));
		KPKTQ_ENQUEUE_MULTI(&fe->fe_tx_pktq, KPKTQ_FIRST(gso_pktq),
		    KPKTQ_LAST(gso_pktq), KPKTQ_LEN(gso_pktq));
		KPKTQ_INIT(gso_pktq);
		flow_entry_release(&fe);
	}
}

static void
dp_gso_pktq(struct nx_flowswitch *fsw, struct pktq *spktq,
    uint32_t gso_pkts_estimate)
{
	struct __kern_packet *spkt, *pkt;
	struct flow_entry_list fes = TAILQ_HEAD_INITIALIZER(fes);
	struct flow_entry *fe, *prev_fe;
	struct pktq dpktq;
	struct nexus_adapter *dev_na;
	struct kern_pbufpool *dev_pp;
	struct ifnet *ifp;
	sa_family_t af;
	uint32_t n_pkts, n_flows = 0;
	int err;

	KPKTQ_INIT(&dpktq);
	n_pkts = KPKTQ_LEN(spktq);

	FSW_RLOCK(fsw);
	if (__improbable(FSW_QUIESCED(fsw))) {
		DTRACE_SKYWALK1(tx__quiesced, struct nx_flowswitch *, fsw);
		SK_ERR("flowswitch detached, dropping %d pkts", n_pkts);
		dp_drop_pktq(fsw, spktq);
		goto done;
	}
	dev_na = fsw->fsw_dev_ch->ch_na;
	if (__improbable(dev_na == NULL)) {
		SK_ERR("dev port not attached, dropping %d pkts", n_pkts);
		FSW_STATS_ADD(FSW_STATS_DST_NXPORT_INACTIVE, n_pkts);
		dp_drop_pktq(fsw, spktq);
		goto done;
	}
	/*
	 * fsw_ifp should still be valid at this point. If fsw is detached
	 * after fsw_lock is released, this ifp will remain valid and
	 * netif_transmit() will behave properly even if the ifp is in
	 * detached state.
	 */
	ifp = fsw->fsw_ifp;
	dev_pp = na_kr_get_pp(dev_na, NR_TX);

	/*
	 * Batch allocate enough packets to perform GSO on all
	 * packets in spktq.
	 */
	err = pp_alloc_pktq(dev_pp, dev_pp->pp_max_frags, &dpktq,
	    gso_pkts_estimate, NULL, NULL, SKMEM_NOSLEEP);
#if DEVELOPMENT || DEBUG
	if (__probable(err != ENOMEM)) {
		_FSW_INJECT_ERROR(12, err, ENOMEM, pp_free_pktq, &dpktq);
	}
#endif /* DEVELOPMENT || DEBUG */
	/*
	 * We either get all packets or none. No partial allocations.
	 */
	if (__improbable(err != 0)) {
		if (err == ENOMEM) {
			ASSERT(KPKTQ_EMPTY(&dpktq));
		} else {
			dp_free_pktq(fsw, &dpktq);
		}
		DTRACE_SKYWALK1(gso__no__mem, int, err);
		dp_drop_pktq(fsw, spktq);
		FSW_STATS_ADD(FSW_STATS_DROP_NOMEM_PKT, n_pkts);
		SK_ERR("failed to alloc %u pkts from device pool",
		    gso_pkts_estimate);
		goto done;
	}
	prev_fe = NULL;
	KPKTQ_FOREACH(spkt, spktq) {
		KPKTQ_DEQUEUE(&dpktq, pkt);
		ASSERT(pkt != NULL);
		/*
		 * Copy only headers to the first packet of the GSO chain.
		 * The headers will be used for classification below.
		 */
		err = dp_copy_headers_to_dev(fsw, spkt, pkt);
		if (__improbable(err != 0)) {
			pp_free_packet_single(pkt);
			DTRACE_SKYWALK2(copy__headers__failed,
			    struct nx_flowswitch *, fsw,
			    struct __kern_packet *, spkt);
			continue;
		}
		af = get_tso_af(pkt);
		ASSERT(af == AF_INET || af == AF_INET6);

		err = flow_pkt_classify(pkt, ifp, af, false);
		if (__improbable(err != 0)) {
			dp_tx_log_pkt(SK_VERB_ERROR, "flow extract err", pkt);
			FSW_STATS_INC(FSW_STATS_TX_FLOW_EXTRACT_ERR);
			pp_free_packet_single(pkt);
			DTRACE_SKYWALK4(classify__failed,
			    struct nx_flowswitch *, fsw,
			    struct __kern_packet *, spkt,
			    struct __kern_packet *, pkt,
			    int, err);
			continue;
		}
		/*
		 * GSO cannot be done on a fragment and it's a bug in user
		 * space to mark a fragment as needing GSO.
		 */
		if (__improbable(pkt->pkt_flow_ip_is_frag)) {
			FSW_STATS_INC(FSW_STATS_TX_FRAG_BAD_CONT);
			pp_free_packet_single(pkt);
			DTRACE_SKYWALK3(is__frag,
			    struct nx_flowswitch *, fsw,
			    struct __kern_packet *, spkt,
			    struct __kern_packet *, pkt);
			continue;
		}
		fe = tx_lookup_flow(fsw, pkt, prev_fe);
		if (__improbable(fe == NULL)) {
			FSW_STATS_INC(FSW_STATS_TX_FLOW_NOT_FOUND);
			pp_free_packet_single(pkt);
			DTRACE_SKYWALK3(lookup__failed,
			    struct nx_flowswitch *, fsw,
			    struct __kern_packet *, spkt,
			    struct __kern_packet *, pkt);
			prev_fe = NULL;
			continue;
		}
		/*
		 * Perform GSO on spkt using the flow information
		 * obtained above.
		 */
		struct pktq gso_pktq;
		KPKTQ_INIT(&gso_pktq);
		err = do_gso(fsw, af, spkt, pkt, &dpktq, &gso_pktq);
		if (__probable(err == 0)) {
			tx_flow_enqueue_gso_pktq(&fes, fe, &gso_pktq);
			prev_fe = fe;
		} else {
			DTRACE_SKYWALK1(gso__error, int, err);
			/* TODO: increment error stat */
			pp_free_packet_single(pkt);
			flow_entry_release(&fe);
			prev_fe = NULL;
		}
		KPKTQ_FINI(&gso_pktq);
	}
	struct flow_entry *tfe = NULL;
	TAILQ_FOREACH_SAFE(fe, &fes, fe_tx_link, tfe) {
		/* Chain-enqueue can be used for GSO chains */
		tx_flow_process(fsw, fe, FLOW_PROC_FLAG_GSO);
		TAILQ_REMOVE(&fes, fe, fe_tx_link);
		flow_entry_release(&fe);
		n_flows++;
	}
done:
	FSW_RUNLOCK(fsw);
	if (n_flows > 0) {
		netif_transmit(ifp, NETIF_XMIT_FLAG_CHANNEL);
	}

	/*
	 * It's possible for packets to be left in dpktq because
	 * gso_pkts_estimate is only an estimate. The actual number
	 * of packets needed could be less.
	 */
	uint32_t dpktq_len;
	if ((dpktq_len = KPKTQ_LEN(&dpktq)) > 0) {
		DTRACE_SKYWALK2(leftover__dev__pkts,
		    struct nx_flowswitch *, fsw, uint32_t, dpktq_len);
		dp_free_pktq(fsw, &dpktq);
	}
	KPKTQ_FINI(&dpktq);
}

static inline void
fsw_dev_ring_flush(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    struct proc *p)
{
#pragma unused(p)
	uint32_t total_pkts = 0, total_bytes = 0;

	for (;;) {
		struct pktq pktq;
		KPKTQ_INIT(&pktq);
		uint32_t n_bytes;
		fsw_rx_ring_dequeue_pktq(fsw, r, fsw_rx_batch, &pktq, &n_bytes);
		if (n_bytes == 0) {
			break;
		}
		total_pkts += KPKTQ_LEN(&pktq);
		total_bytes += n_bytes;

		if (__probable(fsw->fsw_ifp->if_input_netem == NULL)) {
			fsw_receive(fsw, &pktq);
		} else {
			fsw_dev_input_netem_enqueue(fsw, &pktq);
		}
		KPKTQ_FINI(&pktq);
	}

	KDBG(SK_KTRACE_FSW_DEV_RING_FLUSH, SK_KVA(r), total_pkts, total_bytes);
	DTRACE_SKYWALK2(fsw__dp__dev__ring__flush, uint32_t, total_pkts,
	    uint32_t, total_bytes);

	/* compute mitigation rate for delivered traffic */
	if (__probable(r->ckr_netif_mit_stats != NULL)) {
		r->ckr_netif_mit_stats(r, total_pkts, total_bytes);
	}
}

static inline void
fsw_user_ring_flush(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    struct proc *p)
{
#pragma unused(p)
	static packet_trace_id_t trace_id = 0;
	uint32_t total_pkts = 0, total_bytes = 0;

	for (;;) {
		struct pktq pktq;
		KPKTQ_INIT(&pktq);
		uint32_t n_bytes;
		uint32_t gso_pkts_estimate = 0;

		fsw_tx_ring_dequeue_pktq(fsw, r, fsw_tx_batch, &pktq, &n_bytes,
		    &gso_pkts_estimate);
		if (n_bytes == 0) {
			break;
		}
		total_pkts += KPKTQ_LEN(&pktq);
		total_bytes += n_bytes;

		KPKTQ_FIRST(&pktq)->pkt_trace_id = ++trace_id;
		KDBG(SK_KTRACE_PKT_TX_FSW | DBG_FUNC_START,
		    KPKTQ_FIRST(&pktq)->pkt_trace_id);

		if (gso_pkts_estimate > 0) {
			dp_gso_pktq(fsw, &pktq, gso_pkts_estimate);
		} else {
			dp_tx_pktq(fsw, &pktq);
		}
		dp_free_pktq(fsw, &pktq);
		KPKTQ_FINI(&pktq);
	}
	kr_update_stats(r, total_pkts, total_bytes);

	KDBG(SK_KTRACE_FSW_USER_RING_FLUSH, SK_KVA(r), total_pkts, total_bytes);
	DTRACE_SKYWALK2(fsw__dp__user__ring__flush, uint32_t, total_pkts,
	    uint32_t, total_bytes);
}

void
fsw_ring_flush(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    struct proc *p)
{
	struct nexus_vp_adapter *vpna = VPNA(KRNA(r));

	ASSERT(sk_is_sync_protected());
	ASSERT(vpna->vpna_nx_port != FSW_VP_HOST);
	ASSERT(vpna->vpna_up.na_md_type == NEXUS_META_TYPE_PACKET);

	if (vpna->vpna_nx_port == FSW_VP_DEV) {
		fsw_dev_ring_flush(fsw, r, p);
	} else {
		fsw_user_ring_flush(fsw, r, p);
	}
}

int
fsw_dp_ctor(struct nx_flowswitch *fsw)
{
	uint32_t fe_cnt = fsw_fe_table_size;
	uint32_t fob_cnt = fsw_flow_owner_buckets;
	uint32_t frb_cnt = fsw_flow_route_buckets;
	uint32_t frib_cnt = fsw_flow_route_id_buckets;
	struct kern_nexus *nx = fsw->fsw_nx;
	char name[64];
	int error = 0;

	/* just in case */
	if (fe_cnt == 0) {
		fe_cnt = NX_FSW_FE_TABLESZ;
		ASSERT(fe_cnt != 0);
	}
	if (fob_cnt == 0) {
		fob_cnt = NX_FSW_FOB_HASHSZ;
		ASSERT(fob_cnt != 0);
	}
	if (frb_cnt == 0) {
		frb_cnt = NX_FSW_FRB_HASHSZ;
		ASSERT(frb_cnt != 0);
	}
	if (frib_cnt == 0) {
		frib_cnt = NX_FSW_FRIB_HASHSZ;
		ASSERT(frib_cnt != 0);
	}

	/* make sure fe_cnt is a power of two, else round up */
	if ((fe_cnt & (fe_cnt - 1)) != 0) {
		fe_cnt--;
		fe_cnt |= (fe_cnt >> 1);
		fe_cnt |= (fe_cnt >> 2);
		fe_cnt |= (fe_cnt >> 4);
		fe_cnt |= (fe_cnt >> 8);
		fe_cnt |= (fe_cnt >> 16);
		fe_cnt++;
	}

	/* make sure frb_cnt is a power of two, else round up */
	if ((frb_cnt & (frb_cnt - 1)) != 0) {
		frb_cnt--;
		frb_cnt |= (frb_cnt >> 1);
		frb_cnt |= (frb_cnt >> 2);
		frb_cnt |= (frb_cnt >> 4);
		frb_cnt |= (frb_cnt >> 8);
		frb_cnt |= (frb_cnt >> 16);
		frb_cnt++;
	}

	lck_mtx_init(&fsw->fsw_detach_barrier_lock, &nexus_lock_group,
	    &nexus_lock_attr);
	lck_mtx_init(&fsw->fsw_reap_lock, &nexus_lock_group, &nexus_lock_attr);
	lck_mtx_init(&fsw->fsw_linger_lock, &nexus_lock_group, &nexus_lock_attr);
	TAILQ_INIT(&fsw->fsw_linger_head);

	(void) snprintf(name, sizeof(name), "%s_%llu", NX_FSW_NAME, nx->nx_id);
	error = nx_advisory_alloc(nx, name,
	    &NX_PROV(nx)->nxprov_region_params[SKMEM_REGION_NEXUSADV],
	    NEXUS_ADVISORY_TYPE_FLOWSWITCH);
	if (error != 0) {
		fsw_dp_dtor(fsw);
		return error;
	}

	fsw->fsw_flow_mgr = flow_mgr_create(fe_cnt, fob_cnt, frb_cnt, frib_cnt);
	if (fsw->fsw_flow_mgr == NULL) {
		fsw_dp_dtor(fsw);
		return error;
	}

	/* generic name; will be customized upon ifattach */
	(void) snprintf(fsw->fsw_reap_name, sizeof(fsw->fsw_reap_name),
	    FSW_REAP_THREADNAME, name, "");

	if (kernel_thread_start(fsw_reap_thread_func, fsw,
	    &fsw->fsw_reap_thread) != KERN_SUCCESS) {
		panic_plain("%s: can't create thread", __func__);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	/* this must not fail */
	VERIFY(fsw->fsw_reap_thread != NULL);

	SK_DF(SK_VERB_MEM, "fsw 0x%llx ALLOC", SK_KVA(fsw));


	return error;
}

void
fsw_dp_dtor(struct nx_flowswitch *fsw)
{
	uint64_t f = (1 * NSEC_PER_MSEC);         /* 1 ms */
	uint64_t s = (1000 * NSEC_PER_SEC);         /* 1 sec */
	uint32_t i = 0;

#if (DEVELOPMENT || DEBUG)
	if (fsw->fsw_rps_threads != NULL) {
		for (i = 0; i < fsw->fsw_rps_nthreads; i++) {
			fsw_rps_thread_join(fsw, i);
		}
		kfree_type(struct fsw_rps_thread, fsw->fsw_rps_threads);
	}
#endif /* !DEVELOPMENT && !DEBUG */

	nx_advisory_free(fsw->fsw_nx);

	if (fsw->fsw_reap_thread != THREAD_NULL) {
		/* signal thread to begin self-termination */
		lck_mtx_lock(&fsw->fsw_reap_lock);
		fsw->fsw_reap_flags |= FSW_REAPF_TERMINATING;

		/*
		 * And wait for thread to terminate; use another
		 * wait channel here other than fsw_reap_flags to
		 * make it more explicit.  In the event the reaper
		 * thread misses a wakeup, we'll try again once
		 * every second (except for the first time).
		 */
		while (!(fsw->fsw_reap_flags & FSW_REAPF_TERMINATED)) {
			uint64_t t = 0;

			nanoseconds_to_absolutetime((i++ == 0) ? f : s, &t);
			clock_absolutetime_interval_to_deadline(t, &t);
			ASSERT(t != 0);

			fsw->fsw_reap_flags |= FSW_REAPF_TERMINATEBLOCK;
			if (!(fsw->fsw_reap_flags & FSW_REAPF_RUNNING)) {
				thread_wakeup((caddr_t)&fsw->fsw_reap_flags);
			}
			(void) assert_wait_deadline(&fsw->fsw_reap_thread,
			    THREAD_UNINT, t);
			lck_mtx_unlock(&fsw->fsw_reap_lock);
			thread_block(THREAD_CONTINUE_NULL);
			lck_mtx_lock(&fsw->fsw_reap_lock);
			fsw->fsw_reap_flags &= ~FSW_REAPF_TERMINATEBLOCK;
		}
		ASSERT(fsw->fsw_reap_flags & FSW_REAPF_TERMINATED);
		lck_mtx_unlock(&fsw->fsw_reap_lock);
		fsw->fsw_reap_thread = THREAD_NULL;
	}

	/* free any remaining flow entries in the linger list */
	fsw_linger_purge(fsw);

	if (fsw->fsw_flow_mgr != NULL) {
		flow_mgr_destroy(fsw->fsw_flow_mgr);
		fsw->fsw_flow_mgr = NULL;
	}


	lck_mtx_destroy(&fsw->fsw_detach_barrier_lock, &nexus_lock_group);
	lck_mtx_destroy(&fsw->fsw_reap_lock, &nexus_lock_group);
	lck_mtx_destroy(&fsw->fsw_linger_lock, &nexus_lock_group);
}

void
fsw_linger_insert(struct flow_entry *fe)
{
	struct nx_flowswitch *fsw = fe->fe_fsw;
	SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
	SK_DF(SK_VERB_FLOW, "entry \"%s\" fe 0x%llx flags 0x%b",
	    fe_as_string(fe, dbgbuf, sizeof(dbgbuf)), SK_KVA(fe),
	    fe->fe_flags, FLOWENTF_BITS);

	net_update_uptime();

	ASSERT(flow_entry_refcnt(fe) >= 1);
	ASSERT(fe->fe_flags & FLOWENTF_TORN_DOWN);
	ASSERT(fe->fe_flags & FLOWENTF_DESTROYED);
	ASSERT(!(fe->fe_flags & FLOWENTF_LINGERING));
	ASSERT(fe->fe_flags & FLOWENTF_WAIT_CLOSE);
	ASSERT(fe->fe_linger_wait != 0);
	fe->fe_linger_expire = (_net_uptime + fe->fe_linger_wait);
	os_atomic_or(&fe->fe_flags, FLOWENTF_LINGERING, relaxed);

	lck_mtx_lock_spin(&fsw->fsw_linger_lock);
	TAILQ_INSERT_TAIL(&fsw->fsw_linger_head, fe, fe_linger_link);
	fsw->fsw_linger_cnt++;
	VERIFY(fsw->fsw_linger_cnt != 0);
	lck_mtx_unlock(&fsw->fsw_linger_lock);

	fsw_reap_sched(fsw);
}

static void
fsw_linger_remove_internal(struct flow_entry_linger_head *linger_head,
    struct flow_entry *fe)
{
	SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
	SK_DF(SK_VERB_FLOW, "entry \"%s\" fe 0x%llx flags 0x%b",
	    fe_as_string(fe, dbgbuf, sizeof(dbgbuf)), SK_KVA(fe),
	    fe->fe_flags, FLOWENTF_BITS);

	ASSERT(fe->fe_flags & FLOWENTF_TORN_DOWN);
	ASSERT(fe->fe_flags & FLOWENTF_DESTROYED);
	ASSERT(fe->fe_flags & FLOWENTF_LINGERING);
	os_atomic_andnot(&fe->fe_flags, FLOWENTF_LINGERING, relaxed);

	TAILQ_REMOVE(linger_head, fe, fe_linger_link);
	flow_entry_release(&fe);
}

static void
fsw_linger_remove(struct flow_entry *fe)
{
	struct nx_flowswitch *fsw = fe->fe_fsw;

	LCK_MTX_ASSERT(&fsw->fsw_linger_lock, LCK_MTX_ASSERT_OWNED);

	fsw_linger_remove_internal(&fsw->fsw_linger_head, fe);
	VERIFY(fsw->fsw_linger_cnt != 0);
	fsw->fsw_linger_cnt--;
}

void
fsw_linger_purge(struct nx_flowswitch *fsw)
{
	struct flow_entry *fe, *tfe;

	lck_mtx_lock(&fsw->fsw_linger_lock);
	TAILQ_FOREACH_SAFE(fe, &fsw->fsw_linger_head, fe_linger_link, tfe) {
		fsw_linger_remove(fe);
	}
	ASSERT(fsw->fsw_linger_cnt == 0);
	ASSERT(TAILQ_EMPTY(&fsw->fsw_linger_head));
	lck_mtx_unlock(&fsw->fsw_linger_lock);
}

void
fsw_reap_sched(struct nx_flowswitch *fsw)
{
	ASSERT(fsw->fsw_reap_thread != THREAD_NULL);
	lck_mtx_lock_spin(&fsw->fsw_reap_lock);
	if (!(fsw->fsw_reap_flags & FSW_REAPF_RUNNING) &&
	    !(fsw->fsw_reap_flags & (FSW_REAPF_TERMINATING | FSW_REAPF_TERMINATED))) {
		thread_wakeup((caddr_t)&fsw->fsw_reap_flags);
	}
	lck_mtx_unlock(&fsw->fsw_reap_lock);
}

__attribute__((noreturn))
static void
fsw_reap_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct nx_flowswitch *fsw = v;

	ASSERT(fsw->fsw_reap_thread == current_thread());
	thread_set_thread_name(current_thread(), fsw->fsw_reap_name);

	net_update_uptime();

	lck_mtx_lock(&fsw->fsw_reap_lock);
	VERIFY(!(fsw->fsw_reap_flags & FSW_REAPF_RUNNING));
	(void) assert_wait(&fsw->fsw_reap_flags, THREAD_UNINT);
	lck_mtx_unlock(&fsw->fsw_reap_lock);
	thread_block_parameter(fsw_reap_thread_cont, fsw);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static void
fsw_reap_thread_cont(void *v, wait_result_t wres)
{
	struct nx_flowswitch *fsw = v;
	boolean_t low;
	uint64_t t = 0;

	SK_DF(SK_VERB_FLOW, "%s: running", fsw->fsw_reap_name);

	lck_mtx_lock(&fsw->fsw_reap_lock);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (fsw->fsw_reap_flags & FSW_REAPF_TERMINATING) != 0)) {
		goto terminate;
	}

	ASSERT(!(fsw->fsw_reap_flags & FSW_REAPF_TERMINATED));
	fsw->fsw_reap_flags |= FSW_REAPF_RUNNING;
	lck_mtx_unlock(&fsw->fsw_reap_lock);

	net_update_uptime();

	/* prevent detach from happening while we're here */
	if (!fsw_detach_barrier_add(fsw)) {
		SK_ERR("%s: netagent detached", fsw->fsw_reap_name);
		t = 0;
	} else {
		uint32_t fe_nonviable, fe_freed, fe_aborted;
		uint32_t fr_freed, fr_resid = 0;
		struct ifnet *ifp = fsw->fsw_ifp;
		uint64_t i = FSW_REAP_IVAL;
		uint64_t now = _net_uptime;
		uint64_t last;

		ASSERT(fsw->fsw_ifp != NULL);

		/*
		 * Pass 1: process any deferred {withdrawn,nonviable} requests.
		 */
		fe_nonviable = fsw_process_deferred(fsw);

		/*
		 * Pass 2: remove any expired lingering flows.
		 */
		fe_freed = fsw_process_linger(fsw, &fe_aborted);

		/*
		 * Pass 3: prune idle flow routes.
		 */
		fr_freed = flow_route_prune(fsw->fsw_flow_mgr,
		    ifp, &fr_resid);

		/*
		 * Pass 4: prune flow table
		 *
		 */
		cuckoo_hashtable_try_shrink(fsw->fsw_flow_mgr->fm_flow_table);

		SK_DF(SK_VERB_FLOW, "%s: fe_nonviable %u/%u fe_freed %u/%u "
		    "fe_aborted %u fr_freed %u/%u",
		    fsw->fsw_flow_mgr->fm_name, fe_nonviable,
		    (fe_nonviable + fsw->fsw_pending_nonviable),
		    fe_freed, fsw->fsw_linger_cnt, fe_aborted, fe_freed,
		    (fe_freed + fr_resid));

		/* see if VM memory level is critical */
		low = skmem_lowmem_check();

		/*
		 * If things appear to be idle, we can prune away cached
		 * object that have fallen out of the working sets (this
		 * is different than purging).  Every once in a while, we
		 * also purge the caches.  Note that this is done across
		 * all flowswitch instances, and so we limit this to no
		 * more than once every FSW_REAP_SK_THRES seconds.
		 */
		last = os_atomic_load(&fsw_reap_last, relaxed);
		if ((low || (last != 0 && (now - last) >= FSW_REAP_SK_THRES)) &&
		    os_atomic_cmpxchg(&fsw_reap_last, last, now, acq_rel)) {
			fsw_purge_cache(fsw, low);

			/* increase sleep interval if idle */
			if (kdebug_enable == 0 && fsw->fsw_linger_cnt == 0 &&
			    fsw->fsw_pending_nonviable == 0 && fr_resid == 0) {
				i <<= 3;
			}
		} else if (last == 0) {
			os_atomic_store(&fsw_reap_last, now, release);
		}

		/*
		 * Additionally, run thru the list of channels and prune
		 * or purge away cached objects on "idle" channels.  This
		 * check is rate limited to no more than once every
		 * FSW_DRAIN_CH_THRES seconds.
		 */
		last = fsw->fsw_drain_channel_chk_last;
		if (low || (last != 0 && (now - last) >= FSW_DRAIN_CH_THRES)) {
			SK_DF(SK_VERB_FLOW, "%s: pruning channels",
			    fsw->fsw_flow_mgr->fm_name);

			fsw->fsw_drain_channel_chk_last = now;
			fsw_drain_channels(fsw, now, low);
		} else if (__improbable(last == 0)) {
			fsw->fsw_drain_channel_chk_last = now;
		}

		/*
		 * Finally, invoke the interface's reap callback to
		 * tell it to prune or purge away cached objects if
		 * it is idle.  This check is rate limited to no more
		 * than once every FSW_REAP_IF_THRES seconds.
		 */
		last = fsw->fsw_drain_netif_chk_last;
		if (low || (last != 0 && (now - last) >= FSW_REAP_IF_THRES)) {
			ASSERT(fsw->fsw_nifna != NULL);

			if (ifp->if_na_ops != NULL &&
			    ifp->if_na_ops->ni_reap != NULL) {
				SK_DF(SK_VERB_FLOW, "%s: pruning netif",
				    fsw->fsw_flow_mgr->fm_name);
				ifp->if_na_ops->ni_reap(ifp->if_na, ifp,
				    FSW_REAP_IF_THRES, low);
			}

			fsw->fsw_drain_netif_chk_last = now;
		} else if (__improbable(last == 0)) {
			fsw->fsw_drain_netif_chk_last = now;
		}

		/* emit periodic interface stats ktrace */
		last = fsw->fsw_reap_last;
		if (last != 0 && (now - last) >= FSW_IFSTATS_THRES) {
			KDBG(SK_KTRACE_AON_IF_STATS, ifp->if_data.ifi_ipackets,
			    ifp->if_data.ifi_ibytes * 8,
			    ifp->if_data.ifi_opackets,
			    ifp->if_data.ifi_obytes * 8);

			fsw->fsw_reap_last = now;
		} else if (__improbable(last == 0)) {
			fsw->fsw_reap_last = now;
		}

		nanoseconds_to_absolutetime(i * NSEC_PER_SEC, &t);
		clock_absolutetime_interval_to_deadline(t, &t);
		ASSERT(t != 0);

		/* allow any pending detach to proceed */
		fsw_detach_barrier_remove(fsw);
	}

	lck_mtx_lock(&fsw->fsw_reap_lock);
	if (!(fsw->fsw_reap_flags & FSW_REAPF_TERMINATING)) {
		fsw->fsw_reap_flags &= ~FSW_REAPF_RUNNING;
		(void) assert_wait_deadline(&fsw->fsw_reap_flags,
		    THREAD_UNINT, t);
		lck_mtx_unlock(&fsw->fsw_reap_lock);
		thread_block_parameter(fsw_reap_thread_cont, fsw);
		/* NOTREACHED */
		__builtin_unreachable();
	} else {
terminate:
		LCK_MTX_ASSERT(&fsw->fsw_reap_lock, LCK_MTX_ASSERT_OWNED);
		fsw->fsw_reap_flags &= ~(FSW_REAPF_RUNNING | FSW_REAPF_TERMINATING);
		fsw->fsw_reap_flags |= FSW_REAPF_TERMINATED;
		/*
		 * And signal any thread waiting for us to terminate;
		 * wait channel here other than fsw_reap_flags to make
		 * it more explicit.
		 */
		if (fsw->fsw_reap_flags & FSW_REAPF_TERMINATEBLOCK) {
			thread_wakeup((caddr_t)&fsw->fsw_reap_thread);
		}
		lck_mtx_unlock(&fsw->fsw_reap_lock);

		SK_DF(SK_VERB_FLOW, "%s: terminating", fsw->fsw_reap_name);

		/* for the extra refcnt from kernel_thread_start() */
		thread_deallocate(current_thread());
		/* this is the end */
		thread_terminate(current_thread());
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* must never get here */
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

static void
fsw_drain_channels(struct nx_flowswitch *fsw, uint64_t now, boolean_t low)
{
	struct kern_nexus *nx = fsw->fsw_nx;

	/* flowswitch protects NA via fsw_lock, see fsw_port_alloc/free */
	FSW_RLOCK(fsw);

	/* uncrustify doesn't handle C blocks properly */
	/* BEGIN IGNORE CODESTYLE */
	nx_port_foreach(nx, ^(nexus_port_t p) {
		struct nexus_adapter *na = nx_port_get_na(nx, p);
		if (na == NULL || na->na_work_ts == 0 || na->na_rx_rings == NULL) { 
			return;
		}

		boolean_t purge;

		/*
		 * If some activity happened in the last FSW_DRAIN_CH_THRES
		 * seconds on this channel, we reclaim memory if the channel 
		 * throughput is less than the reap threshold value.
		 */
		if ((now - na->na_work_ts) < FSW_DRAIN_CH_THRES) {
			struct __kern_channel_ring *ring;
			channel_ring_stats *stats;
			uint64_t bps;

			ring = na->na_rx_rings;
			stats = &ring->ckr_stats;
			bps = stats->crs_bytes_per_second;

			if (bps < fsw_channel_reap_thresh) {
				purge = FALSE;
				na_drain(na, purge);
			}
			return;
		}

		/*
		 * If NA has been inactive for some time (twice the drain
		 * threshold), we clear the work timestamp to temporarily skip
		 * this channel until it's active again.  Purging cached objects
		 * can be expensive since we'd need to allocate and construct
		 * them again, so we do it only when necessary.
		 */
		if (low || ((now - na->na_work_ts) >= (FSW_DRAIN_CH_THRES << 1))) {
			na->na_work_ts = 0;
			purge = TRUE;
		} else {
			purge = FALSE;
		}

		na_drain(na, purge);  /* purge/prune caches */
	});
	/* END IGNORE CODESTYLE */

	FSW_RUNLOCK(fsw);
}

static void
fsw_purge_cache(struct nx_flowswitch *fsw, boolean_t low)
{
#pragma unused(fsw)
	uint64_t o = os_atomic_inc_orig(&fsw_want_purge, relaxed);
	uint32_t p = fsw_flow_purge_thresh;
	boolean_t purge = (low || (o != 0 && p != 0 && (o % p) == 0));

	SK_DF(SK_VERB_FLOW, "%s: %s caches",
	    fsw->fsw_flow_mgr->fm_name,
	    (purge ? "purge" : "prune"));

	skmem_cache_reap_now(sk_fo_cache, purge);
	skmem_cache_reap_now(sk_fe_cache, purge);
	skmem_cache_reap_now(sk_fab_cache, purge);
	skmem_cache_reap_now(flow_route_cache, purge);
	skmem_cache_reap_now(flow_stats_cache, purge);
	netns_reap_caches(purge);
	skmem_reap_caches(purge);

#if CONFIG_MBUF_MCACHE
	if (if_is_fsw_transport_netagent_enabled() && purge) {
		mbuf_drain(FALSE);
	}
#endif /* CONFIG_MBUF_MCACHE */
}

static void
fsw_flow_handle_low_power(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	/* When the interface is in low power mode, the flow is nonviable */
	if (!(fe->fe_flags & FLOWENTF_NONVIABLE) &&
	    os_atomic_cmpxchg(&fe->fe_want_nonviable, 0, 1, acq_rel)) {
		os_atomic_inc(&fsw->fsw_pending_nonviable, relaxed);
	}
}

static uint32_t
fsw_process_deferred(struct nx_flowswitch *fsw)
{
	struct flow_entry_dead sfed __sk_aligned(8);
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	struct flow_entry_dead *fed, *tfed;
	LIST_HEAD(, flow_entry_dead) fed_head =
	    LIST_HEAD_INITIALIZER(fed_head);
	uint32_t i, nonviable = 0;
	boolean_t lowpowermode = FALSE;

	bzero(&sfed, sizeof(sfed));

	/*
	 * The flows become nonviable when the interface
	 * is in low power mode (edge trigger)
	 */
	if ((fsw->fsw_ifp->if_xflags & IFXF_LOW_POWER) &&
	    fsw->fsw_ifp->if_low_power_gencnt != fsw->fsw_low_power_gencnt) {
		lowpowermode = TRUE;
		fsw->fsw_low_power_gencnt = fsw->fsw_ifp->if_low_power_gencnt;
	}

	/*
	 * Scan thru the flow entry tree, and commit any pending withdraw or
	 * nonviable requests.  We may need to push stats and/or unassign the
	 * nexus from NECP, but we cannot do that while holding the locks;
	 * build a temporary list for those entries.
	 */
	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		struct flow_owner_bucket *fob = flow_mgr_get_fob_at_idx(fm, i);
		struct flow_owner *fo;

		/*
		 * Grab the lock at all costs when handling low power mode
		 */
		if (__probable(!lowpowermode)) {
			if (!FOB_TRY_LOCK(fob)) {
				continue;
			}
		} else {
			FOB_LOCK(fob);
		}

		FOB_LOCK_ASSERT_HELD(fob);
		RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
			struct flow_entry *fe;

			RB_FOREACH(fe, flow_entry_id_tree,
			    &fo->fo_flow_entry_id_head) {
				/* try first as reader; skip if we can't */
				if (__improbable(lowpowermode)) {
					fsw_flow_handle_low_power(fsw, fe);
				}
				if (__improbable(fe->fe_flags & FLOWENTF_HALF_CLOSED)) {
					os_atomic_andnot(&fe->fe_flags, FLOWENTF_HALF_CLOSED, relaxed);
					flow_namespace_half_close(&fe->fe_port_reservation);
				}

				/* if not withdrawn/nonviable, skip */
				if (!fe->fe_want_withdraw &&
				    !fe->fe_want_nonviable) {
					continue;
				}
				/*
				 * Here we're holding the lock as writer;
				 * don't spend too much time as we're
				 * blocking the data path now.
				 */
				ASSERT(!uuid_is_null(fe->fe_uuid));
				/* only need flow UUID and booleans */
				uuid_copy(sfed.fed_uuid, fe->fe_uuid);
				sfed.fed_want_clonotify =
				    (fe->fe_flags & FLOWENTF_CLOSE_NOTIFY);
				sfed.fed_want_nonviable = fe->fe_want_nonviable;
				flow_entry_teardown(fo, fe);

				/* do this outside the flow bucket lock */
				fed = flow_entry_dead_alloc(Z_WAITOK);
				ASSERT(fed != NULL);
				*fed = sfed;
				LIST_INSERT_HEAD(&fed_head, fed, fed_link);
			}
		}
		FOB_UNLOCK(fob);
	}

	/*
	 * These nonviable flows are no longer useful since we've lost
	 * the source IP address; in the event the client monitors the
	 * viability of the flow, explicitly mark it as nonviable so
	 * that a new flow can be created.
	 */
	LIST_FOREACH_SAFE(fed, &fed_head, fed_link, tfed) {
		LIST_REMOVE(fed, fed_link);
		ASSERT(fsw->fsw_agent_session != NULL);

		/* if flow is closed early */
		if (fed->fed_want_clonotify) {
			necp_client_early_close(fed->fed_uuid);
		}

		/* if nonviable, unassign nexus attributes */
		if (fed->fed_want_nonviable) {
			(void) netagent_assign_nexus(fsw->fsw_agent_session,
			    fed->fed_uuid, NULL, 0);
		}

		flow_entry_dead_free(fed);
		++nonviable;
	}
	ASSERT(LIST_EMPTY(&fed_head));

	return nonviable;
}

static uint32_t
fsw_process_linger(struct nx_flowswitch *fsw, uint32_t *abort)
{
	struct flow_entry_linger_head linger_head =
	    TAILQ_HEAD_INITIALIZER(linger_head);
	struct flow_entry *fe, *tfe;
	uint64_t now = _net_uptime;
	uint32_t i = 0, cnt = 0, freed = 0;

	ASSERT(fsw->fsw_ifp != NULL);
	ASSERT(abort != NULL);
	*abort = 0;

	/*
	 * We don't want to contend with the datapath, so move
	 * everything that's in the linger list into a local list.
	 * This allows us to generate RSTs or free the flow entry
	 * outside the lock.  Any remaining flow entry in the local
	 * list will get re-added back to the head of the linger
	 * list, in front of any new ones added since then.
	 */
	lck_mtx_lock(&fsw->fsw_linger_lock);
	TAILQ_CONCAT(&linger_head, &fsw->fsw_linger_head, fe_linger_link);
	ASSERT(TAILQ_EMPTY(&fsw->fsw_linger_head));
	cnt = fsw->fsw_linger_cnt;
	fsw->fsw_linger_cnt = 0;
	lck_mtx_unlock(&fsw->fsw_linger_lock);

	TAILQ_FOREACH_SAFE(fe, &linger_head, fe_linger_link, tfe) {
		ASSERT(fe->fe_flags & FLOWENTF_TORN_DOWN);
		ASSERT(fe->fe_flags & FLOWENTF_DESTROYED);
		ASSERT(fe->fe_flags & FLOWENTF_LINGERING);

		/*
		 * See if this is a TCP flow that needs to generate
		 * a RST to the remote peer (if not already).
		 */
		if (flow_track_tcp_want_abort(fe)) {
			VERIFY(fe->fe_flags & FLOWENTF_ABORTED);
			ASSERT(!uuid_is_null(fe->fe_uuid));
			flow_track_abort_tcp(fe, NULL, NULL);
			(*abort)++;
			SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
			SK_DF(SK_VERB_FLOW, "entry \"%s\" fe 0x%llx "
			    "flags 0x%b [RST]", fe_as_string(fe, dbgbuf,
			    sizeof(dbgbuf)), SK_KVA(fe), fe->fe_flags,
			    FLOWENTF_BITS);
		}

		/*
		 * If flow has expired, remove from list and free;
		 * otherwise leave it around in the linger list.
		 */
		if (fe->fe_linger_expire <= now) {
			freed++;
			fsw_linger_remove_internal(&linger_head, fe);
			fe = NULL;
		}
		++i;
	}
	VERIFY(i == cnt && cnt >= freed);

	/*
	 * Add any remaining ones back into the linger list.
	 */
	lck_mtx_lock(&fsw->fsw_linger_lock);
	if (!TAILQ_EMPTY(&linger_head)) {
		ASSERT(TAILQ_EMPTY(&fsw->fsw_linger_head) || fsw->fsw_linger_cnt);
		TAILQ_CONCAT(&linger_head, &fsw->fsw_linger_head, fe_linger_link);
		ASSERT(TAILQ_EMPTY(&fsw->fsw_linger_head));
		TAILQ_CONCAT(&fsw->fsw_linger_head, &linger_head, fe_linger_link);
		fsw->fsw_linger_cnt += (cnt - freed);
	}
	ASSERT(TAILQ_EMPTY(&linger_head));
	lck_mtx_unlock(&fsw->fsw_linger_lock);

	return freed;
}

__attribute__((always_inline))
static inline void
fsw_ifp_inc_traffic_class_in_pkt(struct ifnet *ifp, kern_packet_t ph)
{
	switch (__packet_get_traffic_class(ph)) {
	case PKT_TC_BE:
		ifp->if_tc.ifi_ibepackets++;
		ifp->if_tc.ifi_ibebytes += SK_PTR_ADDR_KPKT(ph)->pkt_length;
		break;
	case PKT_TC_BK:
		ifp->if_tc.ifi_ibkpackets++;
		ifp->if_tc.ifi_ibkbytes += SK_PTR_ADDR_KPKT(ph)->pkt_length;
		break;
	case PKT_TC_VI:
		ifp->if_tc.ifi_ivipackets++;
		ifp->if_tc.ifi_ivibytes += SK_PTR_ADDR_KPKT(ph)->pkt_length;
		break;
	case PKT_TC_VO:
		ifp->if_tc.ifi_ivopackets++;
		ifp->if_tc.ifi_ivobytes += SK_PTR_ADDR_KPKT(ph)->pkt_length;
		break;
	default:
		break;
	}
}

__attribute__((always_inline))
static inline void
fsw_ifp_inc_traffic_class_out_pkt(struct ifnet *ifp, uint32_t svc,
    uint32_t cnt, uint32_t len)
{
	switch (svc) {
	case PKT_TC_BE:
		ifp->if_tc.ifi_obepackets += cnt;
		ifp->if_tc.ifi_obebytes += len;
		break;
	case PKT_TC_BK:
		ifp->if_tc.ifi_obkpackets += cnt;
		ifp->if_tc.ifi_obkbytes += len;
		break;
	case PKT_TC_VI:
		ifp->if_tc.ifi_ovipackets += cnt;
		ifp->if_tc.ifi_ovibytes += len;
		break;
	case PKT_TC_VO:
		ifp->if_tc.ifi_ovopackets += cnt;
		ifp->if_tc.ifi_ovobytes += len;
		break;
	default:
		break;
	}
}
