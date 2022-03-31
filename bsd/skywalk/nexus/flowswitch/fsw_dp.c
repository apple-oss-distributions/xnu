/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

extern kern_return_t thread_terminate(thread_t);

#define FSW_ZONE_MAX                  256
#define FSW_ZONE_NAME                 "skywalk.nx.fsw"

#define FSW_STATS_VAL(x)        STATS_VAL(&fsw->fsw_stats, x)
#define FSW_STATS_INC(x)        STATS_INC(&fsw->fsw_stats, x)
#define FSW_STATS_ADD(x, n)     STATS_ADD(&fsw->fsw_stats, x, n)

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

#define RX_BUFLET_BATCH_COUNT 64 /* max batch size for buflet allocation */

uint32_t fsw_rx_batch = NX_FSW_RXBATCH; /* # of packets per batch (RX) */
uint32_t fsw_tx_batch = NX_FSW_TXBATCH; /* # of packets per batch (TX) */
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_batch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_rx_batch, 0,
    "flowswitch Rx batch size");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, tx_batch,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_tx_batch, 0,
    "flowswitch Tx batch size");
#endif /* !DEVELOPMENT && !DEBUG */

SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_agg_tcp,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_fsw_rx_agg_tcp, 0,
    "flowswitch RX aggregation for tcp flows (enable/disable)");
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, rx_agg_tcp_host,
    CTLFLAG_RW | CTLFLAG_LOCKED, &sk_fsw_rx_agg_tcp_host, 0,
    "flowswitch RX aggregation for tcp kernel path (0/1/2 (off/on/auto))");

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
			    IPPROTO_TCP, fe->fe_inp_flowhash,
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
	       SK_PTR_ADDR_KPKT(dph)->pkt_qum.qum_pp->pp_buflet_size) - headroom);
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
		    dpkt->pkt_qum.qum_pp->pp_buflet_size);
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
		if (!FSW_NETAGENT_ENABLED(fsw)) {
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
lookup_flow_with_key(struct nx_flowswitch *fsw, struct __kern_packet *pkt,
    bool input, struct flow_entry *prev_fe)
{
	struct flow_key key __sk_aligned(16);
	struct flow_entry *fe;

	ASSERT(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED);
	flow_pkt2key(pkt, input, &key);

	if (__probable(prev_fe != NULL &&
	    prev_fe->fe_key.fk_mask == FKMASK_5TUPLE)) {
		uint16_t saved_mask = key.fk_mask;
		bool match;
		key.fk_mask = FKMASK_5TUPLE;
		match = (flow_key_cmp_mask(&prev_fe->fe_key,
		    &key, &fk_mask_5tuple)) == 0;
		if (match) {
			flow_entry_retain(prev_fe);
			return prev_fe;
		}
		key.fk_mask = saved_mask;
	}

	fe = flow_mgr_find_fe_by_key(fsw->fsw_flow_mgr, &key);

	SK_LOG_VAR(char fkbuf[FLOWKEY_DBGBUF_SIZE]);
	SK_DF(SK_VERB_FSW_DP | SK_VERB_LOOKUP,
	    "%s %s %s \"%s\" fe 0x%llx",
	    input ? "Rx" : "Tx", if_name(fsw->fsw_ifp),
	    sk_proc_name_address(current_proc()),
	    fk_as_string(&key, fkbuf, sizeof(fkbuf)),
	    SK_KVA(fe));

	return fe;
}

static struct flow_entry *
rx_lookup_flow(struct nx_flowswitch *fsw, struct __kern_packet *pkt,
    struct flow_entry *prev_fe)
{
	struct flow_entry *fe;
	fe = lookup_flow_with_key(fsw, pkt, true, prev_fe);
	_FSW_INJECT_ERROR(2, fe, NULL, flow_entry_release, &fe);
	if (fe == NULL) {
		FSW_STATS_INC(FSW_STATS_RX_FLOW_NOT_FOUND);
		fe = flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
	}

	if (__improbable(fe->fe_flags & FLOWENTF_TORN_DOWN)) {
		FSW_STATS_INC(FSW_STATS_RX_FLOW_TORNDOWN);
		SK_DF(SK_VERB_FSW_DP | SK_VERB_RX | SK_VERB_FLOW,
		    "Rx flow torn down, use host fe");
		flow_entry_release(&fe);
		fe = flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
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
fsw_ring_dequeue_pktq(struct nx_flowswitch *fsw, struct __kern_channel_ring *r,
    uint32_t n_pkts_max, struct pktq *pktq, uint32_t *n_bytes)
{
	uint32_t n_pkts = 0;

	KPKTQ_INIT(pktq);

	slot_idx_t idx, idx_end;
	idx = r->ckr_khead;
	idx_end = r->ckr_rhead;

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
	membar_sync();

	r->ckr_ktail = idx_end;

	/* ensure global visibility */
	membar_sync();

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
convert_native_pkt_to_mbuf_chain(struct nx_flowswitch *fsw,
    struct flow_entry *fe, struct __kern_packet *pkt_chain,
    struct mbuf **m_chain, struct mbuf **m_tail, uint32_t *cnt,
    uint32_t *bytes)
{
	uint32_t tot_cnt;
	unsigned int one = 1;
	struct mbuf *mhead, *chain = NULL, *tail = NULL, **tailp = &chain;
	uint32_t mhead_cnt, mhead_bufsize;
	uint32_t mhead_waste = 0;
	uint32_t mcnt = 0, mbytes = 0;
	uint32_t largest, max_pkt_len;
	struct __kern_packet *pkt;
	struct kern_pbufpool *pp;

	tot_cnt = *cnt;
	ASSERT(tot_cnt > 0);
	mhead_cnt = tot_cnt;

	/*
	 * Opportunistically batch-allocate the mbufs based on the largest
	 * packet size we've seen in the recent past.  Note that we reset
	 * fe_rx_largest_msize below if we notice that we're under-utilizing the
	 * allocated buffers (thus disabling this batch allocation).
	 */
	if (__probable((largest = fe->fe_rx_largest_msize) != 0)) {
		if (largest <= MCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, MCLBYTES,
			    &one, M_WAIT, 1, 0);
			mhead_bufsize = MCLBYTES;
		} else if (largest <= MBIGCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, MBIGCLBYTES,
			    &one, M_WAIT, 1, 0);
			mhead_bufsize = MBIGCLBYTES;
		} else if (largest <= M16KCLBYTES) {
			mhead = m_allocpacket_internal(&mhead_cnt, M16KCLBYTES,
			    &one, M_WAIT, 1, 0);
			mhead_bufsize = M16KCLBYTES;
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

	pp = __DECONST(struct kern_pbufpool *, pkt_chain->pkt_qum.qum_pp);
	max_pkt_len = pp->pp_buflet_size * pp->pp_max_frags;

	for (pkt = pkt_chain; pkt != NULL; pkt = pkt->pkt_nextpkt) {
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
		if (__improbable(fe->fe_rx_largest_msize < tot_len)) {
			fe->fe_rx_largest_msize = MAX(tot_len, MCLBYTES);
		}

		/*
		 * If the above batch allocation returned partial
		 * success, we try a blocking allocation here again.
		 */
		m = mhead;
		if (__improbable(m == NULL || tot_len > mhead_bufsize)) {
			ASSERT(mhead != NULL || mhead_cnt == 0);
			one = 1;
			if ((error = mbuf_allocpacket(MBUF_WAITOK, tot_len,
			    &one, &m)) != 0) {
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
		    struct flow_entry *, fe, uint32_t, mhead_waste,
		    uint32_t, tot_cnt);
		fe->fe_rx_largest_msize = 0;
	}
	pp_free_packet_chain(pkt_chain, NULL);
	*m_chain = chain;
	*m_tail = tail;
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
convert_compat_pkt_to_mbuf_chain(struct nx_flowswitch *fsw,
    struct flow_entry *fe, struct __kern_packet *pkt_chain,
    struct mbuf **m_chain, struct mbuf **m_tail, uint32_t *cnt,
    uint32_t *bytes)
{
#pragma unused (fe)
	struct __kern_packet *pkt;
	struct mbuf *m, *head = NULL, *tail = NULL, **tailp = &head;
	uint32_t c = 0, b = 0;

	for (pkt = pkt_chain; pkt != NULL; pkt = pkt->pkt_nextpkt) {
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
	ASSERT(c <= *cnt);
	pp_free_packet_chain(pkt_chain, NULL);
	*m_chain = head;
	*m_tail = tail;
	*cnt = c;
	*bytes = b;
}

void
fsw_host_sendup(ifnet_t ifp, struct mbuf *m_chain, struct mbuf *m_tail,
    uint32_t cnt, uint32_t bytes)
{
	struct ifnet_stat_increment_param s;

	bzero(&s, sizeof(s));
	s.packets_in = cnt;
	s.bytes_in = bytes;
	dlil_input_handler(ifp, m_chain, m_tail, &s, FALSE, NULL);
}

void
fsw_host_rx(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct pktq *q;
	struct __kern_packet *pkt_chain;
	struct mbuf *m_chain = NULL, *m_tail = NULL;
	uint32_t cnt = 0, bytes = 0;
	boolean_t compat;

	q = &fe->fe_rx_pktq;
	pkt_chain = KPKTQ_FIRST(q);
	cnt = KPKTQ_LEN(q);
	KPKTQ_INIT(q);
	if (__improbable(pkt_chain == NULL)) {
		DTRACE_SKYWALK2(empty__pktq, struct nx_flowswitch *,
		    fsw, struct flow_entry *, fe);
		return;
	}

	/* All packets in the chain must have the same type */
	compat = ((pkt_chain->pkt_pflags & PKT_F_MBUF_DATA) != 0);
	if (compat) {
		convert_compat_pkt_to_mbuf_chain(fsw, fe, pkt_chain, &m_chain,
		    &m_tail, &cnt, &bytes);
	} else {
		convert_native_pkt_to_mbuf_chain(fsw, fe, pkt_chain, &m_chain,
		    &m_tail, &cnt, &bytes);
	}
	if (__improbable(m_chain == NULL)) {
		DTRACE_SKYWALK2(empty__chain, struct nx_flowswitch *, fsw,
		    struct flow_entry *, fe);
		return;
	}
	fsw_host_sendup(fsw->fsw_ifp, m_chain, m_tail, cnt, bytes);
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
			atomic_add_32(&fsw->fsw_pending_nonviable, 1);
			if (atomic_test_set_32(&fe->fe_want_nonviable, 0, 1)) {
				fsw_reap_sched(fsw);
			} else {
				atomic_add_32(&fsw->fsw_pending_nonviable, -1);
			}
		}
		if (fr != NULL) {
			atomic_add_32(&fr->fr_want_configure, 1);
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
dp_flow_rx_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct pktq dpkts;              /* dst pool alloc'ed packets */
	struct pktq disposed_pkts;      /* done src packets */
	struct pktq dropped_pkts;       /* dropped src packets */
	struct pktq transferred_pkts;   /* dst packet ready for ring */
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
		fsw_host_rx(fsw, fe);
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
	cnt = howmany(fe->fe_rx_pktq_bytes, dpp->pp_buflet_size);
	if (cnt > n_pkts) {
		ASSERT(dpp->pp_max_frags > 1);
		cnt -= n_pkts;
		buf_cnt = MIN(RX_BUFLET_BATCH_COUNT, cnt);
		err = pp_alloc_buflet_batch(dpp, buf_array, &buf_cnt,
		    SKMEM_NOSLEEP);
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
			/* if need to trigger RST then deliver to host */
			if (err == ENETRESET) {
				struct flow_entry *host_fe;
				host_fe =
				    flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
				KPKTQ_ENQUEUE(&host_fe->fe_rx_pktq, pkt);
				continue;
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
			n_bufs = howmany(pkt->pkt_length, dpp->pp_buflet_size);
			n_bufs--;
			for (i = 0; i < n_bufs; i++) {
				if (__improbable(buf_cnt == 0)) {
					ASSERT(dpp->pp_max_frags > 1);
					buf_array_iter = 0;
					cnt = howmany(fe->fe_rx_pktq_bytes,
					    dpp->pp_buflet_size);
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
					    SKMEM_NOSLEEP);
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
rx_flow_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	ASSERT(!KPKTQ_EMPTY(&fe->fe_rx_pktq));
	ASSERT(KPKTQ_LEN(&fe->fe_rx_pktq) != 0);

	SK_DF(SK_VERB_FSW_DP | SK_VERB_RX, "Rx %d pkts for fe %p port %d",
	    KPKTQ_LEN(&fe->fe_rx_pktq), fe, fe->fe_nx_port);

	/* flow related processing (default, agg, fpd, etc.) */
	fe->fe_rx_process(fsw, fe);

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
dp_rx_pktq(struct nx_flowswitch *fsw, struct pktq *pktq)
{
	struct __kern_packet *pkt, *tpkt;
	struct flow_entry_list fes = TAILQ_HEAD_INITIALIZER(fes);
	struct flow_entry *fe, *prev_fe;
	sa_family_t af;
	struct pktq dropped_pkts;
	int err;

	KPKTQ_INIT(&dropped_pkts);

	FSW_RLOCK(fsw);
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
			fe = flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
			goto flow_batch;
		}

		err = flow_pkt_classify(pkt, fsw->fsw_ifp, af, TRUE);
		_FSW_INJECT_ERROR(1, err, ENXIO, null_func);
		if (__improbable(err != 0)) {
			FSW_STATS_INC(FSW_STATS_RX_FLOW_EXTRACT_ERR);
			fe = flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
			goto flow_batch;
		}

		if (__improbable(pkt->pkt_flow_ip_is_frag)) {
			pkt = rx_process_ip_frag(fsw, pkt);
			if (pkt == NULL) {
				continue;
			}
		}

		fe = rx_lookup_flow(fsw, pkt, prev_fe);
		if (__improbable(fe == NULL)) {
			KPKTQ_ENQUEUE(&dropped_pkts, pkt);
			prev_fe = NULL;
			continue;
		}

		fe->fe_rx_pktq_bytes += pkt->pkt_flow_ulen;

		dp_rx_process_wake_packet(fsw, pkt);

flow_batch:
		rx_flow_batch_packet(&fes, fe, pkt);
		prev_fe = fe;
	}

	struct flow_entry *tfe = NULL;
	TAILQ_FOREACH_SAFE(fe, &fes, fe_rx_link, tfe) {
		rx_flow_process(fsw, fe);
		TAILQ_REMOVE(&fes, fe, fe_rx_link);
		fe->fe_rx_pktq_bytes = 0;
		fe->fe_rx_frag_count = 0;
		flow_entry_release(&fe);
	}

	/* XXX(OPTIMIZE) need to re-circulate extras back to HOST */
	fe = flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
	if (!KPKTQ_EMPTY(&fe->fe_rx_pktq)) {
		ASSERT(KPKTQ_LEN(&fe->fe_rx_pktq) != 0);
		SK_DF(SK_VERB_FSW_DP | SK_VERB_RX,
		    "re-circulate %d pkts to HOST", KPKTQ_LEN(&fe->fe_rx_pktq));
		rx_flow_process(fsw, fe);
	}
	flow_entry_release(&fe);

done:
	FSW_RUNLOCK(fsw);

	dp_drop_pktq(fsw, &dropped_pkts);
}

static void
dp_rx_pkts(struct nx_flowswitch *fsw, struct __kern_packet *pkts[],
    uint32_t n_pkts)
{
	struct pktq pktq;
	KPKTQ_INIT(&pktq);
	pkts_to_pktq(pkts, n_pkts, &pktq);
	dp_rx_pktq(fsw, &pktq);
	KPKTQ_FINI(&pktq);
}

int
fsw_dev_input_netem_dequeue(void *handle, pktsched_pkt_t *pkts,
    uint32_t n_pkts)
{
#pragma unused(handle)
	struct nx_flowswitch *fsw = handle;
	struct __kern_packet *kpkts[FSW_VP_DEV_BATCH_MAX];
	sk_protect_t protect;
	uint32_t i;

	ASSERT(n_pkts <= FSW_VP_DEV_BATCH_MAX);

	for (i = 0; i < n_pkts; i++) {
		ASSERT(pkts[i].pktsched_ptype == QP_PACKET);
		ASSERT(pkts[i].pktsched_pkt_kpkt != NULL);
		kpkts[i] = pkts[i].pktsched_pkt_kpkt;
	}

	protect = sk_sync_protect();
	dp_rx_pkts(fsw, kpkts, n_pkts);
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
		boolean_t pdrop;
		KPKTQ_REMOVE(q, pkt);
		CLASSQ_PKT_INIT_PACKET(&p, pkt);
		netem_enqueue(ne, &p, &pdrop);
	}
}

void
fsw_devna_rx(struct nexus_adapter *devna, struct __kern_packet *pkt_chain,
    struct nexus_pkt_stats *out_stats)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct nx_flowswitch *fsw;
	uint32_t n_bytes = 0, n_pkts = 0;
	uint64_t total_pkts = 0, total_bytes = 0;
	struct pktq q;

	KPKTQ_INIT(&q);
	if (__improbable(devna->na_ifp == NULL ||
	    (fsw = fsw_ifp_to_fsw(devna->na_ifp)) == NULL)) {
		SK_ERR("fsw not attached, dropping %d pkts", KPKTQ_LEN(&q));
		pp_free_packet_chain(pkt_chain, NULL);
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
			if (__probable(fsw->fsw_ifp->if_input_netem == NULL)) {
				dp_rx_pktq(fsw, &q);
			} else {
				fsw_dev_input_netem_enqueue(fsw, &q);
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
	uint16_t bdlen, bdlim, bdoff;
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
		    (uint32_t)pp->pp_max_frags * pp->pp_buflet_size);
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

static int
dp_copy_to_dev(struct nx_flowswitch *fsw, struct __kern_packet *spkt,
    struct __kern_packet *dpkt)
{
	const struct kern_pbufpool *pp = dpkt->pkt_qum.qum_pp;
	struct ifnet *ifp = fsw->fsw_ifp;
	uint32_t dev_pkt_len;
	int err = 0;

	ASSERT(!(spkt->pkt_pflags & PKT_F_MBUF_MASK));
	ASSERT(!(spkt->pkt_pflags & PKT_F_PKT_MASK));

	SK_PREFETCHW(dpkt->pkt_qum_buf.buf_addr, 0);
	/* Copy packet metadata */
	_QUM_COPY(&(spkt)->pkt_qum, &(dpkt)->pkt_qum);
	_PKT_COPY(spkt, dpkt);
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

	switch (fsw->fsw_classq_enq_ptype) {
	case QP_MBUF:
		err = dp_copy_to_dev_mbuf(fsw, spkt, dpkt);
		break;

	case QP_PACKET:
		dev_pkt_len = fsw->fsw_frame_headroom + ifp->if_tx_headroom +
		    spkt->pkt_length;
		if (dev_pkt_len > pp->pp_max_frags * pp->pp_buflet_size) {
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

	/* The packet should have a timestamp by the time we get here. */
	m->m_pkthdr.pkt_timestamp = pkt->pkt_timestamp;
	m->m_pkthdr.pkt_flags &= ~PKTF_TS_VALID;

	m->m_pkthdr.pkt_flags &= ~PKT_F_COMMON_MASK;
	m->m_pkthdr.pkt_flags |= (pkt->pkt_pflags & PKT_F_COMMON_MASK);
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
convert_pkt_to_mbuf_chain(struct __kern_packet *pkt_chain,
    struct mbuf **chain, struct mbuf **tail,
    uint32_t *cnt, uint32_t *bytes)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct mbuf *m_chain = NULL, **m_tailp = &m_chain, *m = NULL;
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
	if (chain != NULL) {
		*chain = m_chain;
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
	/*
	 * we are using the first 4 bytes of flow_id as the AQM flow
	 * identifier.
	 */
	ASSERT(!uuid_is_null(pkt->pkt_flow_id));
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
    struct __kern_packet *pkt_chain, struct __kern_packet *pkt_tail,
    uint32_t cnt, uint32_t bytes)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	boolean_t pkt_drop = FALSE;
	uint32_t svc;
	int err;

	FSW_LOCK_ASSERT_HELD(fsw);
	ASSERT(fsw->fsw_classq_enabled);
	/*
	 * we are using the first 4 bytes of flow_id as the AQM flow
	 * identifier.
	 */
	ASSERT(!uuid_is_null(pkt_chain->pkt_flow_id));

	/*
	 * All packets in the flow should have the same svc.
	 */
	svc = pkt_chain->pkt_svc_class;
	fsw_ifp_inc_traffic_class_out_pkt(ifp, svc, cnt, bytes);

	switch (fsw->fsw_classq_enq_ptype) {
	case QP_MBUF: {                         /* compat interface */
		struct mbuf *m_chain = NULL, *m_tail = NULL;
		uint32_t c = 0, b = 0;

		convert_pkt_to_mbuf_chain(pkt_chain, &m_chain, &m_tail, &c, &b);
		ASSERT(m_chain != NULL && m_tail != NULL);
		ASSERT(c == cnt);
		ASSERT(b == bytes);
		pkt_chain = NULL;

		/* ifnet_enqueue consumes mbuf */
		err = ifnet_enqueue_mbuf_chain(ifp, m_chain, m_tail, cnt,
		    bytes, FALSE, &pkt_drop);
		m_chain = NULL;
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
		err = ifnet_enqueue_pkt_chain(ifp, pkt_chain, pkt_tail, cnt,
		    bytes, FALSE, &pkt_drop);
		pkt_chain = NULL;
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
    boolean_t chain, uint32_t cnt, uint32_t bytes)
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
    boolean_t chain, uint32_t cnt, uint32_t bytes)
{
	struct __kern_packet *pkt, *tail;
	flowadv_idx_t flow_adv_idx;
	bool flowadv_is_set = false;
	bool flowadv_cap;
	flowadv_token_t flow_adv_token;
	uint32_t flowctl = 0, dropped = 0;
	int err;

	SK_DF(SK_VERB_FSW_DP | SK_VERB_AQM, "%s classq enqueued %d pkts",
	    if_name(fsw->fsw_ifp), KPKTQ_LEN(&fe->fe_tx_pktq));

	/*
	 * Not supporting chains for now
	 */
	VERIFY(!chain);
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
	struct __kern_packet *pkt, *tpkt;
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		KPKTQ_REMOVE(&fe->fe_tx_pktq, pkt);
		/* listener is only allowed TCP RST */
		if (pkt->pkt_flow_ip_proto == IPPROTO_TCP &&
		    (pkt->pkt_flow_tcp_flags & TH_RST) != 0) {
			fsw_flow_abort_tcp(fsw, fe, pkt);
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

/*
 * TODO:
 * We can check the flow entry as well to only allow chain enqueue
 * on flows matching a certain criteria.
 */
static boolean_t
fsw_chain_enqueue_enabled(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
#pragma unused(fe)
	return fsw_chain_enqueue != 0 &&
	       fsw->fsw_ifp->if_output_netem == NULL &&
	       (fsw->fsw_ifp->if_eflags & IFEF_ENQUEUE_MULTI) == 0 &&
	       fe->fe_qset == NULL;
}

void
dp_flow_tx_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct pktq dropped_pkts;
	boolean_t chain;
	uint32_t cnt = 0, bytes = 0;
	volatile struct sk_nexusadv *nxadv = NULL;
	volatile uint64_t *fg_ts = NULL;
	volatile uint64_t *rt_ts = NULL;

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
	chain = fsw_chain_enqueue_enabled(fsw, fe);
	if (chain) {
		nxadv = fsw->fsw_nx->nx_adv.flowswitch_nxv_adv;
		if (nxadv != NULL) {
			fg_ts = &nxadv->nxadv_fg_sendts;
			rt_ts = &nxadv->nxadv_rt_sendts;
		}
	}
	struct __kern_packet *pkt, *tpkt;
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_tx_pktq, tpkt) {
		int err = flow_pkt_track(fe, pkt, false);
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
		pkt->pkt_pflags |= PKT_F_FLOW_ID;

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

	fe = lookup_flow_with_key(fsw, pkt, false, prev_fe);
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
tx_flow_process(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	ASSERT(!KPKTQ_EMPTY(&fe->fe_tx_pktq));
	ASSERT(KPKTQ_LEN(&fe->fe_tx_pktq) != 0);

	SK_DF(SK_VERB_FSW_DP | SK_VERB_TX, "TX %d pkts from fe %p port %d",
	    KPKTQ_LEN(&fe->fe_tx_pktq), fe, fe->fe_nx_port);

	/* flow related processing (default, agg, etc.) */
	fe->fe_tx_process(fsw, fe);

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
		tx_flow_process(fsw, fe);
		TAILQ_REMOVE(&fes, fe, fe_tx_link);
		fe->fe_tx_is_cont_frag = false;
		fe->fe_tx_frag_id = 0;
		flow_entry_release(&fe);
		n_flows++;
	}

done:
	FSW_RUNLOCK(fsw);
	if (n_flows > 0) {
		netif_transmit(ifp, NETIF_XMIT_FLAG_CHANNEL);
	}
	dp_drop_pktq(fsw, &dropped_pkts);
	KPKTQ_FINI(&dropped_pkts);
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
		fsw_ring_dequeue_pktq(fsw, r, fsw_rx_batch, &pktq, &n_bytes);
		if (n_bytes == 0) {
			break;
		}
		total_pkts += KPKTQ_LEN(&pktq);
		total_bytes += n_bytes;

		if (__probable(fsw->fsw_ifp->if_input_netem == NULL)) {
			dp_rx_pktq(fsw, &pktq);
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
		fsw_ring_dequeue_pktq(fsw, r, fsw_tx_batch, &pktq, &n_bytes);
		if (n_bytes == 0) {
			break;
		}
		total_pkts += KPKTQ_LEN(&pktq);
		total_bytes += n_bytes;

		KPKTQ_FIRST(&pktq)->pkt_trace_id = ++trace_id;
		KDBG(SK_KTRACE_PKT_TX_FSW | DBG_FUNC_START, KPKTQ_FIRST(&pktq)->pkt_trace_id);

		dp_tx_pktq(fsw, &pktq);
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

	flow_mgr_setup_host_flow(fsw->fsw_flow_mgr, fsw);

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
	uint64_t f = (1 * NSEC_PER_MSEC);       /* 1 ms */
	uint64_t s = (1000 * NSEC_PER_SEC);    /* 1 sec */
	uint32_t i = 0;

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
		flow_mgr_teardown_host_flow(fsw->fsw_flow_mgr);
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
	atomic_bitset_32(&fe->fe_flags, FLOWENTF_LINGERING);

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
	atomic_bitclear_32(&fe->fe_flags, FLOWENTF_LINGERING);

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
		atomic_get_64(last, &fsw_reap_last);
		if ((low || (last != 0 && (now - last) >= FSW_REAP_SK_THRES)) &&
		    atomic_test_set_64(&fsw_reap_last, last, now)) {
			fsw_purge_cache(fsw, low);

			/* increase sleep interval if idle */
			if (kdebug_enable == 0 && fsw->fsw_linger_cnt == 0 &&
			    fsw->fsw_pending_nonviable == 0 && fr_resid == 0) {
				i <<= 3;
			}
		} else if (last == 0) {
			atomic_set_64(&fsw_reap_last, now);
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
		if (na == NULL || na->na_work_ts == 0 ||
		    (now - na->na_work_ts) < FSW_DRAIN_CH_THRES) {
			return;
		}

		/*
		 * If NA has been inactive for some time (twice the drain
		 * threshold), we clear the work timestamp to temporarily skip
		 * this channel until it's active again.  Purging cached objects
		 * can be expensive since we'd need to allocate and construct
		 * them again, so we do it only when necessary.
		 */
		boolean_t purge;
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
	uint64_t o = atomic_add_64_ov(&fsw_want_purge, 1);
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
	eventhandler_reap_caches(purge);
	netns_reap_caches(purge);
	skmem_reap_caches(purge);
	necp_client_reap_caches(purge);

	if (if_is_fsw_transport_netagent_enabled() && purge) {
		mbuf_drain(FALSE);
	}
}

static void
fsw_flow_handle_low_power(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	/* When the interface is in low power mode, the flow is nonviable */
	if (!(fe->fe_flags & FLOWENTF_NONVIABLE) &&
	    atomic_test_set_32(&fe->fe_want_nonviable, 0, 1)) {
		atomic_add_32(&fsw->fsw_pending_nonviable, 1);
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
					atomic_bitclear_32(&fe->fe_flags, FLOWENTF_HALF_CLOSED);
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
			fsw_flow_abort_tcp(fsw, fe, NULL);
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

/* Send RST for a given TCP flow; Use @pkt as template if given */
void
fsw_flow_abort_tcp(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct __kern_packet *pkt)
{
	struct flow_track *src, *dst;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct tcphdr *th;
	uint16_t len, tlen;
	struct mbuf *m;
	uint8_t ipver;

	/* guaranteed by caller */
	ASSERT(fsw->fsw_ifp != NULL);

	src = &fe->fe_ltrack;
	dst = &fe->fe_rtrack;

	if (pkt != NULL) {
		ipver = pkt->pkt_flow_ip_ver;
	} else {
		ipver = fe->fe_key.fk_ipver;
	}

	tlen = sizeof(struct tcphdr);
	if (ipver == IPVERSION) {
		len = sizeof(struct ip) + tlen;
	} else {
		ASSERT(ipver == IPV6_VERSION);
		len = sizeof(struct ip6_hdr) + tlen;
	}

	m = m_gethdr(M_WAITOK, MT_HEADER);
	VERIFY(m != NULL);

	m->m_pkthdr.pkt_proto = IPPROTO_TCP;
	m->m_data += max_linkhdr;               /* 32-bit aligned */
	m->m_pkthdr.len = m->m_len = len;

	/* zero out for checksum */
	bzero(m->m_data, len);

	if (ipver == IPVERSION) {
		ip = mtod(m, struct ip *);

		/* IP header fields included in the TCP checksum */
		ip->ip_p = IPPROTO_TCP;
		ip->ip_len = htons(tlen);
		if (pkt == NULL) {
			ip->ip_src = fe->fe_key.fk_src4;
			ip->ip_dst = fe->fe_key.fk_dst4;
		} else {
			ip->ip_src = pkt->pkt_flow_ipv4_src;
			ip->ip_dst = pkt->pkt_flow_ipv4_dst;
		}

		th = (struct tcphdr *)(void *)((char *)ip + sizeof(*ip));
	} else {
		ip6 = mtod(m, struct ip6_hdr *);

		/* IP header fields included in the TCP checksum */
		ip6->ip6_nxt = IPPROTO_TCP;
		ip6->ip6_plen = htons(tlen);
		if (pkt == NULL) {
			ip6->ip6_src = fe->fe_key.fk_src6;
			ip6->ip6_dst = fe->fe_key.fk_dst6;
		} else {
			ip6->ip6_src = pkt->pkt_flow_ipv6_src;
			ip6->ip6_dst = pkt->pkt_flow_ipv6_dst;
		}

		th = (struct tcphdr *)(void *)((char *)ip6 + sizeof(*ip6));
	}

	/*
	 * TCP header (fabricate a pure RST).
	 */
	if (pkt == NULL) {
		th->th_sport = fe->fe_key.fk_sport;
		th->th_dport = fe->fe_key.fk_dport;
		th->th_seq = htonl(src->fse_seqlo);     /* peer's last ACK */
		th->th_ack = 0;
		th->th_flags = TH_RST;
	} else {
		th->th_sport = pkt->pkt_flow_tcp_src;
		th->th_dport = pkt->pkt_flow_tcp_dst;
		th->th_seq = pkt->pkt_flow_tcp_seq;
		th->th_ack = pkt->pkt_flow_tcp_ack;
		th->th_flags = pkt->pkt_flow_tcp_flags;
	}
	th->th_off = (tlen >> 2);
	th->th_win = 0;

	FSW_STATS_INC(FSW_STATS_FLOWS_ABORTED);

	if (ipver == IPVERSION) {
		struct ip_out_args ipoa;
		struct route ro;

		bzero(&ipoa, sizeof(ipoa));
		ipoa.ipoa_boundif = fsw->fsw_ifp->if_index;
		ipoa.ipoa_flags = (IPOAF_SELECT_SRCIF | IPOAF_BOUND_IF |
		    IPOAF_BOUND_SRCADDR);
		ipoa.ipoa_sotc = SO_TC_UNSPEC;
		ipoa.ipoa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

		/* TCP checksum */
		th->th_sum = in_cksum(m, len);

		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_tos = 0;
		/*
		 * ip_output() expects ip_len and ip_off to be in host order.
		 */
		ip->ip_len = len;
		ip->ip_off = IP_DF;
		ip->ip_ttl = (uint8_t)ip_defttl;
		ip->ip_sum = 0;

		bzero(&ro, sizeof(ro));
		(void) ip_output(m, NULL, &ro, IP_OUTARGS, NULL, &ipoa);
		ROUTE_RELEASE(&ro);
	} else {
		struct ip6_out_args ip6oa;
		struct route_in6 ro6;

		bzero(&ip6oa, sizeof(ip6oa));
		ip6oa.ip6oa_boundif = fsw->fsw_ifp->if_index;
		ip6oa.ip6oa_flags = (IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_IF |
		    IP6OAF_BOUND_SRCADDR);
		ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
		ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

		/* TCP checksum */
		th->th_sum = in6_cksum(m, IPPROTO_TCP,
		    sizeof(struct ip6_hdr), tlen);

		ip6->ip6_vfc |= IPV6_VERSION;
		ip6->ip6_hlim = IPV6_DEFHLIM;

		ip6_output_setsrcifscope(m, fsw->fsw_ifp->if_index, NULL);
		ip6_output_setdstifscope(m, fsw->fsw_ifp->if_index, NULL);

		bzero(&ro6, sizeof(ro6));
		(void) ip6_output(m, NULL, &ro6, IPV6_OUTARGS,
		    NULL, NULL, &ip6oa);
		ROUTE_RELEASE(&ro6);
	}
}

void
fsw_flow_abort_quic(struct flow_entry *fe, uint8_t *token)
{
	struct quic_stateless_reset {
		uint8_t ssr_header[30];
		uint8_t ssr_token[QUIC_STATELESS_RESET_TOKEN_SIZE];
	};
	struct nx_flowswitch *fsw = fe->fe_fsw;
	struct ip *ip;
	struct ip6_hdr *ip6;
	struct udphdr *uh;
	struct quic_stateless_reset *qssr;
	uint16_t len, l3hlen, ulen;
	struct mbuf *m;
	unsigned int one = 1;
	int error;

	/* guaranteed by caller */
	ASSERT(fsw->fsw_ifp != NULL);

	/* skip zero token */
	bool is_zero_token = true;
	for (size_t i = 0; i < QUIC_STATELESS_RESET_TOKEN_SIZE; i++) {
		if (token[i] != 0) {
			is_zero_token = false;
			break;
		}
	}
	if (is_zero_token) {
		return;
	}

	ulen = sizeof(struct udphdr) + sizeof(struct quic_stateless_reset);
	if (fe->fe_key.fk_ipver == IPVERSION) {
		l3hlen = sizeof(struct ip);
	} else {
		ASSERT(fe->fe_key.fk_ipver == IPV6_VERSION);
		l3hlen = sizeof(struct ip6_hdr);
	}

	len = l3hlen + ulen;

	error = mbuf_allocpacket(MBUF_DONTWAIT, max_linkhdr + len, &one, &m);
	if (error != 0) {
		return;
	}
	VERIFY(m != 0);

	m->m_pkthdr.pkt_proto = IPPROTO_UDP;
	m->m_data += max_linkhdr;               /* 32-bit aligned */
	m->m_pkthdr.len = m->m_len = len;

	/* zero out for checksum */
	bzero(m->m_data, len);

	if (fe->fe_key.fk_ipver == IPVERSION) {
		ip = mtod(m, struct ip *);
		ip->ip_p = IPPROTO_UDP;
		ip->ip_len = htons(ulen);
		ip->ip_src = fe->fe_key.fk_src4;
		ip->ip_dst = fe->fe_key.fk_dst4;
		uh = (struct udphdr *)(void *)((char *)ip + sizeof(*ip));
	} else {
		ip6 = mtod(m, struct ip6_hdr *);
		ip6->ip6_nxt = IPPROTO_UDP;
		ip6->ip6_plen = htons(ulen);
		ip6->ip6_src = fe->fe_key.fk_src6;
		ip6->ip6_dst = fe->fe_key.fk_dst6;
		uh = (struct udphdr *)(void *)((char *)ip6 + sizeof(*ip6));
	}

	/* UDP header */
	uh->uh_sport = fe->fe_key.fk_sport;
	uh->uh_dport = fe->fe_key.fk_dport;
	uh->uh_ulen = htons(ulen);

	/* QUIC stateless reset */
	qssr = (struct quic_stateless_reset *)(uh + 1);
	read_frandom(&qssr->ssr_header, sizeof(qssr->ssr_header));
	qssr->ssr_header[0] = (qssr->ssr_header[0] & 0x3f) | 0x40;
	memcpy(qssr->ssr_token, token, QUIC_STATELESS_RESET_TOKEN_SIZE);

	FSW_STATS_INC(FSW_STATS_FLOWS_ABORTED);

	if (fe->fe_key.fk_ipver == IPVERSION) {
		struct ip_out_args ipoa;
		struct route ro;

		bzero(&ipoa, sizeof(ipoa));
		ipoa.ipoa_boundif = fsw->fsw_ifp->if_index;
		ipoa.ipoa_flags = (IPOAF_SELECT_SRCIF | IPOAF_BOUND_IF |
		    IPOAF_BOUND_SRCADDR);
		ipoa.ipoa_sotc = SO_TC_UNSPEC;
		ipoa.ipoa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

		uh->uh_sum = in_cksum(m, len);
		if (uh->uh_sum == 0) {
			uh->uh_sum = 0xffff;
		}

		ip->ip_v = IPVERSION;
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_tos = 0;
		/*
		 * ip_output() expects ip_len and ip_off to be in host order.
		 */
		ip->ip_len = len;
		ip->ip_off = IP_DF;
		ip->ip_ttl = (uint8_t)ip_defttl;
		ip->ip_sum = 0;

		bzero(&ro, sizeof(ro));
		(void) ip_output(m, NULL, &ro, IP_OUTARGS, NULL, &ipoa);
		ROUTE_RELEASE(&ro);
	} else {
		struct ip6_out_args ip6oa;
		struct route_in6 ro6;

		bzero(&ip6oa, sizeof(ip6oa));
		ip6oa.ip6oa_boundif = fsw->fsw_ifp->if_index;
		ip6oa.ip6oa_flags = (IP6OAF_SELECT_SRCIF | IP6OAF_BOUND_IF |
		    IP6OAF_BOUND_SRCADDR);
		ip6oa.ip6oa_sotc = SO_TC_UNSPEC;
		ip6oa.ip6oa_netsvctype = _NET_SERVICE_TYPE_UNSPEC;

		uh->uh_sum = in6_cksum(m, IPPROTO_UDP, sizeof(struct ip6_hdr),
		    ulen);
		if (uh->uh_sum == 0) {
			uh->uh_sum = 0xffff;
		}

		ip6->ip6_vfc |= IPV6_VERSION;
		ip6->ip6_hlim = IPV6_DEFHLIM;
		ip6_output_setsrcifscope(m, fsw->fsw_ifp->if_index, NULL);
		ip6_output_setdstifscope(m, fsw->fsw_ifp->if_index, NULL);

		bzero(&ro6, sizeof(ro6));
		(void) ip6_output(m, NULL, &ro6, IPV6_OUTARGS,
		    NULL, NULL, &ip6oa);
		ROUTE_RELEASE(&ro6);
	}
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
