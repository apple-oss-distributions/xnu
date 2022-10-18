/*
 * Copyright (c) 2020-2022 Apple Inc. All rights reserved.
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
 * Copyright (C) 2014, Stefano Garzarella - Universita` di Pisa.
 * All rights reserved.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/malloc.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcpip.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/ethernet.h>
#include <net/pktap.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>

#define CSUM_GSO_MASK    0x00300000
#define CSUM_GSO_OFFSET  20
#define CSUM_TO_GSO(x) ((x & CSUM_GSO_MASK) >> CSUM_GSO_OFFSET)

enum netif_gso_type {
	GSO_NONE,
	GSO_TCP4,
	GSO_TCP6,
	GSO_END_OF_TYPE
};

uint32_t netif_chain_enqueue = 1;
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, chain_enqueue,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_chain_enqueue, 0,
    "netif chain enqueue");
#endif /* (DEVELOPMENT || DEBUG) */

/*
 * Array of function pointers that execute GSO depending on packet type
 */
int (*netif_gso_functions[GSO_END_OF_TYPE]) (struct ifnet*, struct mbuf*);

/*
 * Structure that contains the state during the TCP segmentation
 */
struct netif_gso_ip_tcp_state {
	void (*update)(struct netif_gso_ip_tcp_state*,
	    struct __kern_packet *pkt, uint8_t *baddr);
	void (*internal)(struct netif_gso_ip_tcp_state*, uint32_t partial,
	    uint16_t payload_len);
	union {
		struct ip *ip;
		struct ip6_hdr *ip6;
	} hdr;
	int af;
	struct tcphdr *tcp;
	struct kern_pbufpool *pp;
	uint32_t psuedo_hdr_csum;
	uint32_t tcp_seq;
	uint16_t hlen;
	uint16_t mss;
	uint16_t ip_id;
	uint8_t mac_hlen;
	uint8_t ip_hlen;
	uint8_t tcp_hlen;
};

static inline uint8_t
netif_gso_get_frame_header_len(struct mbuf *m, uint8_t *hlen)
{
	uint64_t len;
	char *ph = m->m_pkthdr.pkt_hdr;

	if (__improbable(m_pktlen(m) == 0 || ph == NULL ||
	    ph < (char *)m->m_data)) {
		return ERANGE;
	}
	len = (ph - m->m_data);
	if (__improbable(len > UINT8_MAX)) {
		return ERANGE;
	}
	*hlen = (uint8_t)len;
	return 0;
}

static inline int
netif_gso_check_netif_active(struct ifnet *ifp, struct mbuf *m,
    struct kern_pbufpool **pp)
{
	struct __kern_channel_ring *kring;
	struct nx_netif *nif = NA(ifp)->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct kern_nexus *nx = nif->nif_nx;
	struct nexus_adapter *hwna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	uint32_t sc_idx = MBUF_SCIDX(m_get_service_class(m));

	if (__improbable(!NA_IS_ACTIVE(hwna))) {
		STATS_INC(nifs, NETIF_STATS_DROP_NA_INACTIVE);
		SK_DF(SK_VERB_NETIF,
		    "\"%s\" (0x%llx) not in skywalk mode anymore",
		    hwna->na_name, SK_KVA(hwna));
		return ENXIO;
	}

	VERIFY(sc_idx < KPKT_SC_MAX_CLASSES);
	kring = &hwna->na_tx_rings[hwna->na_kring_svc_lut[sc_idx]];
	if (__improbable(KR_DROP(kring))) {
		STATS_INC(nifs, NETIF_STATS_DROP_KRDROP_MODE);
		SK_DF(SK_VERB_NETIF,
		    "kr \"%s\" (0x%llx) krflags 0x%b or %s in drop mode",
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS, ifp->if_xname);
		return ENXIO;
	}
	*pp = kring->ckr_pp;
	return 0;
}

static inline boolean_t
netif_chain_enqueue_enabled(struct ifnet *ifp)
{
	return netif_chain_enqueue != 0 && ifp->if_output_netem == NULL &&
	       (ifp->if_eflags & IFEF_ENQUEUE_MULTI) == 0;
}

static inline int
netif_gso_send(struct ifnet *ifp, struct __kern_packet *head,
    struct __kern_packet *tail, uint32_t count, uint32_t bytes)
{
	struct nx_netif *nif = NA(ifp)->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct netif_qset *qset = NULL;
	uint64_t qset_id = 0;
	int error = 0;
	boolean_t dropped;

	if (NX_LLINK_PROV(nif->nif_nx) &&
	    ifp->if_traffic_rule_count > 0 &&
	    nxctl_inet_traffic_rule_find_qset_id_with_pkt(ifp->if_xname,
	    head, &qset_id) == 0) {
		qset = nx_netif_find_qset(nif, qset_id);
		ASSERT(qset != NULL);
	}
	if (netif_chain_enqueue_enabled(ifp)) {
		dropped = false;
		if (qset != NULL) {
			head->pkt_qset_idx = qset->nqs_idx;
			error = ifnet_enqueue_ifcq_pkt_chain(ifp, qset->nqs_ifcq,
			    head, tail, count, bytes, false, &dropped);
		} else {
			error = ifnet_enqueue_pkt_chain(ifp, head, tail,
			    count, bytes, false, &dropped);
		}
		if (__improbable(dropped)) {
			STATS_ADD(nifs, NETIF_STATS_TX_DROP_ENQ_AQM, count);
			STATS_ADD(nifs, NETIF_STATS_DROP, count);
		}
	} else {
		struct __kern_packet *pkt = head, *next;
		uint32_t c = 0, b = 0;

		while (pkt != NULL) {
			int err;

			next = pkt->pkt_nextpkt;
			pkt->pkt_nextpkt = NULL;
			c++;
			b += pkt->pkt_length;

			dropped = false;
			if (qset != NULL) {
				pkt->pkt_qset_idx = qset->nqs_idx;
				err = ifnet_enqueue_ifcq_pkt(ifp, qset->nqs_ifcq,
				    pkt, false, &dropped);
			} else {
				err = ifnet_enqueue_pkt(ifp, pkt, false, &dropped);
			}
			if (error == 0 && __improbable(err != 0)) {
				error = err;
			}
			if (__improbable(dropped)) {
				STATS_INC(nifs, NETIF_STATS_TX_DROP_ENQ_AQM);
				STATS_INC(nifs, NETIF_STATS_DROP);
			}
			pkt = next;
		}
		ASSERT(c == count);
		ASSERT(b == bytes);
	}
	if (qset != NULL) {
		nx_netif_qset_release(&qset);
	}
	netif_transmit(ifp, NETIF_XMIT_FLAG_HOST);
	return error;
}

/*
 * Segment and transmit a queue of packets which fit the given mss + hdr_len.
 * m points to mbuf chain to be segmented.
 * This function splits the payload (m-> m_pkthdr.len - hdr_len)
 * into segments of length MSS bytes and then copy the first hdr_len bytes
 * from m at the top of each segment.
 */
static inline int
netif_gso_tcp_segment_mbuf(struct mbuf *m, struct ifnet *ifp,
    struct netif_gso_ip_tcp_state *state, struct kern_pbufpool *pp)
{
	uuid_t euuid;
	struct pktq pktq_alloc, pktq_seg;
	uint64_t timestamp = 0;
	uint64_t pflags;
	int error = 0;
	uint32_t policy_id;
	uint32_t svc_class;
	uint32_t n, n_pkts, n_bytes;
	int32_t off = 0, total_len = m->m_pkthdr.len;
	uint8_t tx_headroom = (uint8_t)ifp->if_tx_headroom;
	struct netif_stats *nifs = &NA(ifp)->nifna_netif->nif_stats;
	struct __kern_packet *pkt_chain_head, *pkt_chain_tail;
	uint16_t mss = state->mss;
	bool skip_pktap;

	VERIFY(total_len > state->hlen);
	VERIFY(((tx_headroom + state->mac_hlen) & 0x1) == 0);
	VERIFY((tx_headroom + state->hlen + mss) <= PP_BUF_SIZE_DEF(pp));

	KPKTQ_INIT(&pktq_alloc);
	KPKTQ_INIT(&pktq_seg);
	/* batch allocate enough packets */
	n_pkts = (uint32_t)(SK_ROUNDUP((total_len - state->hlen), mss) / mss);
	error = pp_alloc_pktq(pp, 1, &pktq_alloc, n_pkts, NULL,
	    NULL, SKMEM_NOSLEEP);
	if (__improbable(error != 0)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NOMEM);
		SK_ERR("failed to alloc %u pkts", n_pkts);
		pp_free_pktq(&pktq_alloc);
		error = ENOBUFS;
		goto done;
	}

	ASSERT(m->m_pkthdr.pkt_proto == IPPROTO_TCP);
	ASSERT((m->m_flags & M_BCAST) == 0);
	ASSERT((m->m_flags & M_MCAST) == 0);
	ASSERT(((m->m_pkthdr.pkt_flags & PKTF_TX_COMPL_TS_REQ) == 0));
	pflags = m->m_pkthdr.pkt_flags & PKT_F_COMMON_MASK;
	pflags |= PKTF_START_SEQ;
	(void) mbuf_get_timestamp(m, &timestamp, NULL);
	necp_get_app_uuid_from_packet(m, euuid);
	policy_id = necp_get_policy_id_from_packet(m);
	svc_class = m_get_service_class(m);
	skip_pktap = (m->m_pkthdr.pkt_flags & PKTF_SKIP_PKTAP) != 0 ||
	    pktap_total_tap_count == 0;

	for (n = 1, off = state->hlen; off < total_len; off += mss, n++) {
		uint8_t *baddr, *baddr0;
		uint32_t partial;
		struct __kern_packet *pkt;

		KPKTQ_DEQUEUE(&pktq_alloc, pkt);
		ASSERT(pkt != NULL);

		/* get buffer address from packet */
		MD_BUFLET_ADDR_ABS(pkt, baddr0);
		baddr = baddr0;
		baddr += tx_headroom;

		/*
		 * Copy the link-layer, IP and TCP header from the
		 * original packet.
		 */
		m_copydata(m, 0, state->hlen, baddr);
		baddr += state->hlen;

		/*
		 * Copy the payload from original packet and
		 * compute partial checksum on the payload.
		 */
		if (off + mss > total_len) {
			/* if last segment is less than mss */
			mss = (uint16_t)(total_len - off);
		}
		partial = m_copydata_sum(m, off, mss, baddr, 0, NULL);

		/*
		 * update packet metadata
		 */
		pkt->pkt_headroom = tx_headroom;
		pkt->pkt_l2_len = state->mac_hlen;
		pkt->pkt_link_flags = 0;
		pkt->pkt_csum_flags = 0;
		pkt->pkt_csum_tx_start_off = 0;
		pkt->pkt_csum_tx_stuff_off = 0;
		uuid_copy(pkt->pkt_policy_euuid, euuid);
		pkt->pkt_policy_id = policy_id;
		pkt->pkt_timestamp = timestamp;
		pkt->pkt_svc_class = svc_class;
		pkt->pkt_pflags |= pflags;
		pkt->pkt_flowsrc_type = m->m_pkthdr.pkt_flowsrc;
		pkt->pkt_flow_token = m->m_pkthdr.pkt_flowid;
		pkt->pkt_comp_gencnt = m->m_pkthdr.comp_gencnt;
		pkt->pkt_flow_ip_proto = IPPROTO_TCP;
		pkt->pkt_transport_protocol = IPPROTO_TCP;
		pkt->pkt_flow_tcp_seq = htonl(state->tcp_seq);

		state->update(state, pkt, baddr0);
		/*
		 * FIN or PUSH flags if present will be set only on the last
		 * segment.
		 */
		if (n != n_pkts) {
			state->tcp->th_flags &= ~(TH_FIN | TH_PUSH);
		}
		/*
		 * CWR flag if present is set only on the first segment
		 * and cleared on the subsequent segments.
		 */
		if (n != 1) {
			state->tcp->th_flags &= ~TH_CWR;
			state->tcp->th_seq = htonl(state->tcp_seq);
		}
		ASSERT(state->tcp->th_seq == pkt->pkt_flow_tcp_seq);
		state->internal(state, partial, mss);
		METADATA_ADJUST_LEN(pkt, state->hlen + mss, tx_headroom);
		VERIFY(__packet_finalize(SK_PKT2PH(pkt)) == 0);
		KPKTQ_ENQUEUE(&pktq_seg, pkt);
		if (!skip_pktap) {
			nx_netif_pktap_output(ifp, state->af, pkt);
		}
	}
	ASSERT(off == total_len);
	STATS_ADD(nifs, NETIF_STATS_GSO_SEG, n_pkts);

	/* ifnet_enqueue_pkt_chain() consumes the packet chain */
	pkt_chain_head = KPKTQ_FIRST(&pktq_seg);
	pkt_chain_tail = KPKTQ_LAST(&pktq_seg);
	KPKTQ_INIT(&pktq_seg);
	n_bytes = total_len + (state->hlen * (n_pkts - 1));

	error = netif_gso_send(ifp, pkt_chain_head, pkt_chain_tail,
	    n_pkts, n_bytes);

done:
	KPKTQ_FINI(&pktq_alloc);
	return error;
}

/*
 * Update the pointers to TCP and IPv4 headers
 */
static void
netif_gso_ipv4_tcp_update(struct netif_gso_ip_tcp_state *state,
    struct __kern_packet *pkt, uint8_t *baddr)
{
	state->hdr.ip = (struct ip *)(void *)(baddr + pkt->pkt_headroom +
	    pkt->pkt_l2_len);
	state->tcp = (struct tcphdr *)(void *)((caddr_t)(state->hdr.ip) +
	    state->ip_hlen);
}

/*
 * Finalize the TCP and IPv4 headers
 */
static void
netif_gso_ipv4_tcp_internal(struct netif_gso_ip_tcp_state *state,
    uint32_t partial, uint16_t payload_len)
{
	/*
	 * Update IP header
	 */
	state->hdr.ip->ip_id = htons((state->ip_id)++);
	state->hdr.ip->ip_len = htons(state->ip_hlen + state->tcp_hlen +
	    payload_len);
	/*
	 * IP header checksum
	 */
	state->hdr.ip->ip_sum = 0;
	state->hdr.ip->ip_sum = inet_cksum_buffer(state->hdr.ip, 0, 0,
	    state->ip_hlen);
	/*
	 * TCP Checksum
	 */
	state->tcp->th_sum = 0;
	partial = __packet_cksum(state->tcp, state->tcp_hlen, partial);
	partial += htons(state->tcp_hlen + IPPROTO_TCP + payload_len);
	partial += state->psuedo_hdr_csum;
	ADDCARRY(partial);
	state->tcp->th_sum = ~(uint16_t)partial;
	/*
	 * Update tcp sequence number in gso state
	 */
	state->tcp_seq += payload_len;
}

/*
 * Updates the pointers to TCP and IPv6 headers
 */
static void
netif_gso_ipv6_tcp_update(struct netif_gso_ip_tcp_state *state,
    struct __kern_packet *pkt, uint8_t *baddr)
{
	state->hdr.ip6 = (struct ip6_hdr *)(baddr + pkt->pkt_headroom +
	    pkt->pkt_l2_len);
	state->tcp = (struct tcphdr *)(void *)((caddr_t)(state->hdr.ip6) +
	    state->ip_hlen);
}

/*
 * Finalize the TCP and IPv6 headers
 */
static void
netif_gso_ipv6_tcp_internal(struct netif_gso_ip_tcp_state *state,
    uint32_t partial, uint16_t payload_len)
{
	/*
	 * Update IP header
	 */
	state->hdr.ip6->ip6_plen = htons(state->tcp_hlen + payload_len);
	/*
	 * TCP Checksum
	 */
	state->tcp->th_sum = 0;
	partial = __packet_cksum(state->tcp, state->tcp_hlen, partial);
	partial += htonl(state->tcp_hlen + IPPROTO_TCP + payload_len);
	partial += state->psuedo_hdr_csum;
	ADDCARRY(partial);
	state->tcp->th_sum = ~(uint16_t)partial;
	/*
	 * Update tcp sequence number
	 */
	state->tcp_seq += payload_len;
}

/*
 * Init the state during the TCP segmentation
 */
static inline void
netif_gso_ip_tcp_init_state(struct netif_gso_ip_tcp_state *state,
    struct mbuf *m, uint8_t mac_hlen, uint8_t ip_hlen, bool isipv6)
{
	if (isipv6) {
		state->af = AF_INET6;
		state->hdr.ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) +
		    mac_hlen);
		/* should be atleast 16 bit aligned */
		VERIFY(((uintptr_t)state->hdr.ip6 & (uintptr_t)0x1) == 0);
		state->tcp = (struct tcphdr *)(void *)((caddr_t)
		    (state->hdr.ip6) + ip_hlen);
		state->update = netif_gso_ipv6_tcp_update;
		state->internal = netif_gso_ipv6_tcp_internal;
		state->psuedo_hdr_csum = in6_pseudo(&state->hdr.ip6->ip6_src,
		    &state->hdr.ip6->ip6_dst, 0);
	} else {
		struct in_addr ip_src, ip_dst;

		state->af = AF_INET;
		state->hdr.ip = (struct ip *)(void *)(mtod(m, uint8_t *) +
		    mac_hlen);
		/* should be atleast 16 bit aligned */
		VERIFY(((uintptr_t)state->hdr.ip & (uintptr_t)0x1) == 0);
		state->ip_id = ntohs(state->hdr.ip->ip_id);
		state->tcp = (struct tcphdr *)(void *)((caddr_t)
		    (state->hdr.ip) + ip_hlen);
		state->update = netif_gso_ipv4_tcp_update;
		state->internal = netif_gso_ipv4_tcp_internal;
		bcopy(&state->hdr.ip->ip_src, &ip_src, sizeof(ip_src));
		bcopy(&state->hdr.ip->ip_dst, &ip_dst, sizeof(ip_dst));
		state->psuedo_hdr_csum = in_pseudo(ip_src.s_addr,
		    ip_dst.s_addr, 0);
	}

	state->mac_hlen = mac_hlen;
	state->ip_hlen = ip_hlen;
	state->tcp_hlen = (uint8_t)(state->tcp->th_off << 2);
	state->hlen = mac_hlen + ip_hlen + state->tcp_hlen;
	VERIFY(m->m_pkthdr.tso_segsz != 0);
	state->mss = (uint16_t)m->m_pkthdr.tso_segsz;
	state->tcp_seq = ntohl(state->tcp->th_seq);
}

/*
 * GSO on TCP/IPv4
 */
static int
netif_gso_ipv4_tcp(struct ifnet *ifp, struct mbuf *m)
{
	struct ip *ip;
	struct kern_pbufpool *pp = NULL;
	struct netif_gso_ip_tcp_state state;
	uint16_t hlen;
	uint8_t ip_hlen;
	uint8_t mac_hlen;
	struct netif_stats *nifs = &NA(ifp)->nifna_netif->nif_stats;
	boolean_t pkt_dropped = false;
	int error;

	STATS_INC(nifs, NETIF_STATS_GSO_PKT);
	if (__improbable(m->m_pkthdr.pkt_proto != IPPROTO_TCP)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NONTCP);
		error = ENOTSUP;
		pkt_dropped = true;
		goto done;
	}

	error = netif_gso_check_netif_active(ifp, m, &pp);
	if (__improbable(error != 0)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NA_INACTIVE);
		error = ENXIO;
		pkt_dropped = true;
		goto done;
	}

	error = netif_gso_get_frame_header_len(m, &mac_hlen);
	if (__improbable(error != 0)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_BADLEN);
		pkt_dropped = true;
		goto done;
	}

	hlen = mac_hlen + sizeof(struct ip);
	if (__improbable(m->m_len < hlen)) {
		m = m_pullup(m, hlen);
		if (m == NULL) {
			STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NOMEM);
			error = ENOBUFS;
			pkt_dropped = true;
			goto done;
		}
	}
	ip = (struct ip *)(void *)(mtod(m, uint8_t *) + mac_hlen);
	ip_hlen = (uint8_t)(ip->ip_hl << 2);
	hlen = mac_hlen + ip_hlen + sizeof(struct tcphdr);
	if (__improbable(m->m_len < hlen)) {
		m = m_pullup(m, hlen);
		if (m == NULL) {
			STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NOMEM);
			error = ENOBUFS;
			pkt_dropped = true;
			goto done;
		}
	}
	netif_gso_ip_tcp_init_state(&state, m, mac_hlen, ip_hlen, false);
	error = netif_gso_tcp_segment_mbuf(m, ifp, &state, pp);
done:
	m_freem(m);
	if (__improbable(pkt_dropped)) {
		STATS_INC(nifs, NETIF_STATS_DROP);
	}
	return error;
}

/*
 * GSO on TCP/IPv6
 */
static int
netif_gso_ipv6_tcp(struct ifnet *ifp, struct mbuf *m)
{
	struct ip6_hdr *ip6;
	struct kern_pbufpool *pp = NULL;
	struct netif_gso_ip_tcp_state state;
	int lasthdr_off;
	uint16_t hlen;
	uint8_t ip_hlen;
	uint8_t mac_hlen;
	struct netif_stats *nifs = &NA(ifp)->nifna_netif->nif_stats;
	boolean_t pkt_dropped = false;
	int error;

	STATS_INC(nifs, NETIF_STATS_GSO_PKT);
	if (__improbable(m->m_pkthdr.pkt_proto != IPPROTO_TCP)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NONTCP);
		error = ENOTSUP;
		pkt_dropped = true;
		goto done;
	}

	error = netif_gso_check_netif_active(ifp, m, &pp);
	if (__improbable(error != 0)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NA_INACTIVE);
		error = ENXIO;
		pkt_dropped = true;
		goto done;
	}

	error = netif_gso_get_frame_header_len(m, &mac_hlen);
	if (__improbable(error != 0)) {
		STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_BADLEN);
		pkt_dropped = true;
		goto done;
	}

	hlen = mac_hlen + sizeof(struct ip6_hdr);
	if (__improbable(m->m_len < hlen)) {
		m = m_pullup(m, hlen);
		if (m == NULL) {
			STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NOMEM);
			error = ENOBUFS;
			pkt_dropped = true;
			goto done;
		}
	}
	ip6 = (struct ip6_hdr *)(mtod(m, uint8_t *) + mac_hlen);
	lasthdr_off = ip6_lasthdr(m, mac_hlen, IPPROTO_IPV6, NULL) - mac_hlen;
	VERIFY(lasthdr_off <= UINT8_MAX);
	ip_hlen = (uint8_t)lasthdr_off;
	hlen = mac_hlen + ip_hlen + sizeof(struct tcphdr);
	if (__improbable(m->m_len < hlen)) {
		m = m_pullup(m, hlen);
		if (m == NULL) {
			STATS_INC(nifs, NETIF_STATS_GSO_PKT_DROP_NOMEM);
			error = ENOBUFS;
			pkt_dropped = true;
			goto done;
		}
	}
	netif_gso_ip_tcp_init_state(&state, m, mac_hlen, ip_hlen, true);
	error = netif_gso_tcp_segment_mbuf(m, ifp, &state, pp);
done:
	m_freem(m);
	if (__improbable(pkt_dropped)) {
		STATS_INC(nifs, NETIF_STATS_DROP);
	}
	return error;
}

int
netif_gso_dispatch(struct ifnet *ifp, struct mbuf *m)
{
	int gso_flags;

	ASSERT(m->m_nextpkt == NULL);
	gso_flags = CSUM_TO_GSO(m->m_pkthdr.csum_flags);
	VERIFY(gso_flags < GSO_END_OF_TYPE);
	return netif_gso_functions[gso_flags](ifp, m);
}

void
netif_gso_init(void)
{
	_CASSERT(CSUM_TO_GSO(~(CSUM_TSO_IPV4 | CSUM_TSO_IPV6)) == GSO_NONE);
	_CASSERT(CSUM_TO_GSO(CSUM_TSO_IPV4) == GSO_TCP4);
	_CASSERT(CSUM_TO_GSO(CSUM_TSO_IPV6) == GSO_TCP6);
	netif_gso_functions[GSO_NONE] = nx_netif_host_output;
	netif_gso_functions[GSO_TCP4] = netif_gso_ipv4_tcp;
	netif_gso_functions[GSO_TCP6] = netif_gso_ipv6_tcp;
}

void
netif_gso_fini(void)
{
	netif_gso_functions[GSO_NONE] = NULL;
	netif_gso_functions[GSO_TCP4] = NULL;
	netif_gso_functions[GSO_TCP6] = NULL;
}
