/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <net/pktap.h>
#include <sys/sdt.h>

SK_NO_INLINE_ATTRIBUTE
struct __kern_packet *
nx_netif_alloc_packet(struct kern_pbufpool *pp, uint32_t sz, kern_packet_t *php)
{
	kern_packet_t ph;
	ph = pp_alloc_packet_by_size(pp, sz, SKMEM_NOSLEEP);
	if (__improbable(ph == 0)) {
		DTRACE_SKYWALK2(alloc__fail, struct kern_pbufpool *,
		    pp, size_t, sz);
		return NULL;
	}
	if (php != NULL) {
		*php = ph;
	}
	return SK_PTR_ADDR_KPKT(ph);
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_free_packet(struct __kern_packet *pkt)
{
	pp_free_packet_single(pkt);
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_free_packet_chain(struct __kern_packet *pkt_chain, int *cnt)
{
	pp_free_packet_chain(pkt_chain, cnt);
}

static void
__check_convert_flags(uint32_t flags)
{
	VERIFY((flags & (NETIF_CONVERT_TX | NETIF_CONVERT_RX)) != 0);
	VERIFY((flags & (NETIF_CONVERT_TX | NETIF_CONVERT_RX)) !=
	    (NETIF_CONVERT_TX | NETIF_CONVERT_RX));
}

SK_NO_INLINE_ATTRIBUTE
static void
fill_vlan_info(struct __kern_packet *fpkt)
{
	uint8_t *buf;
	struct ether_vlan_header *evl;
	uint16_t tag;
	boolean_t tag_in_pkt = FALSE;

	if (fpkt->pkt_length < sizeof(*evl)) {
		DTRACE_SKYWALK2(bad__len, struct __kern_packet *, fpkt,
		    uint32_t, fpkt->pkt_length);
		return;
	}
	MD_BUFLET_ADDR_ABS(fpkt, buf);
	buf += fpkt->pkt_headroom;
	evl = (struct ether_vlan_header *)(void *)buf;
	if (ntohs(evl->evl_encap_proto) == ETHERTYPE_VLAN) {
		tag = ntohs(evl->evl_tag);
		tag_in_pkt = TRUE;
		DTRACE_SKYWALK1(tag__in__pkt, uint16_t, tag);
	} else {
		struct mbuf *m;
		struct __kern_packet *pkt;

		/*
		 * A filter packet must always have an mbuf or a packet
		 * attached.
		 */
		VERIFY((fpkt->pkt_pflags & PKT_F_MBUF_DATA) != 0 ||
		    (fpkt->pkt_pflags & PKT_F_PKT_DATA) != 0);

		if ((fpkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
			m = fpkt->pkt_mbuf;
			VERIFY(m != NULL);
			if (mbuf_get_vlan_tag(m, &tag) != 0) {
				return;
			}
			DTRACE_SKYWALK1(tag__from__mbuf, uint16_t, tag);
		} else if ((fpkt->pkt_pflags & PKT_F_PKT_DATA) != 0) {
			pkt = fpkt->pkt_pkt;
			VERIFY(pkt != NULL);

			/*
			 * The attached packet could have an mbuf attached
			 * if it came from the compat path.
			 */
			if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
				m = fpkt->pkt_mbuf;
				VERIFY(m != NULL);
				if (mbuf_get_vlan_tag(m, &tag) != 0) {
					return;
				}
				DTRACE_SKYWALK1(tag__from__inner__mbuf,
				    uint16_t, tag);
			} else {
				/*
				 * XXX
				 * No native driver today fills in the vlan tag
				 * metadata. This code will work when the driver
				 * adds support for this.
				 */
				VERIFY((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
				if (__packet_get_vlan_tag(SK_PKT2PH(pkt), &tag,
				    NULL) != 0) {
					return;
				}
				DTRACE_SKYWALK1(tag__from__pkt, uint16_t, tag);
			}
		} else {
			panic("filter packet has no mbuf or packet attached: "
			    "pkt_pflags 0x%llx\n", fpkt->pkt_pflags);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}
	kern_packet_set_vlan_tag(SK_PKT2PH(fpkt), tag, tag_in_pkt);
}

static struct __kern_packet *
nx_netif_mbuf_to_filter_pkt(struct nexus_netif_adapter *nifna,
    struct mbuf *m, uint32_t flags)
{
	struct __kern_packet *fpkt = NULL;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct kern_pbufpool *pp = nif->nif_filter_pp;
	ifnet_t ifp = nif->nif_ifp;
	boolean_t is_l3, truncated = FALSE;
	enum txrx type;
	uint8_t off, hlen;
	kern_packet_t fph;
	int err, mlen;

	__check_convert_flags(flags);
	is_l3 = (ifp->if_family == IFNET_FAMILY_UTUN ||
	    ifp->if_family == IFNET_FAMILY_IPSEC);

	off = ((flags & NETIF_CONVERT_TX) != 0) ?
	    (uint8_t)ifp->if_tx_headroom : 0;
	hlen = is_l3 ? 0 : ifnet_hdrlen(ifp);
	mlen = m_pktlen(m);

	ASSERT(pp != NULL);
	if (__improbable((off + mlen) > PP_BUF_SIZE_DEF(pp))) {
		VERIFY(off < PP_BUF_SIZE_DEF(pp));
		mlen = PP_BUF_SIZE_DEF(pp) - off;
		truncated = TRUE;

		DTRACE_SKYWALK5(mbuf__truncated,
		    struct nexus_netif_adapter *, nifna,
		    struct mbuf *, m, uint8_t, off, int, mlen,
		    uint32_t, PP_BUF_SIZE_DEF(pp));
		STATS_INC(nifs, NETIF_STATS_FILTER_PKT_TRUNCATED);
	}
	fpkt = nx_netif_alloc_packet(pp, off + mlen, &fph);
	if (__improbable(fpkt == NULL)) {
		DTRACE_SKYWALK2(alloc__fail, struct nexus_netif_adapter *,
		    nifna, struct mbuf *, m);
		STATS_INC(nifs, NETIF_STATS_FILTER_DROP_PKT_ALLOC_FAIL);
		goto drop;
	}
	type = ((flags & NETIF_CONVERT_TX) != 0) ? NR_TX : NR_RX;

	if (__improbable((m->m_flags & M_HASFCS) != 0)) {
		if (type != NR_RX) {
			/*
			 * There shouldn't be an FCS for TX packets
			 */
			DTRACE_SKYWALK2(bad__flags,
			    struct nexus_netif_adapter *,
			    nifna, struct mbuf *, m);
			goto drop;
		}
		if (mlen > ETHER_CRC_LEN) {
			mlen -= ETHER_CRC_LEN;
		} else {
			DTRACE_SKYWALK3(bad__pkt__size,
			    struct nexus_netif_adapter *,
			    nifna, struct mbuf *, m, int, mlen);
			goto drop;
		}
	}
	/*
	 * XXX
	 * If the source packet has any checksum flags, the filter packet will
	 * not have valid checksums. To fill in the checksums, we need to do
	 * something similar to bridge_finalize_cksum() for packets.
	 */
	err = __packet_initialize_with_mbuf(fpkt, m, off, hlen);
	VERIFY(err == 0);
	nif->nif_pkt_copy_from_mbuf(type, fph, off, m, 0,
	    mlen, FALSE, 0);

	err = __packet_finalize_with_mbuf(fpkt);
	VERIFY(err == 0);

	/*
	 * XXX
	 * __packet_finalize_with_mbuf() sets pkt_length to the non-truncated
	 * length. We need to change it back to the truncated length.
	 */
	fpkt->pkt_length = mlen;
	if (!is_l3) {
		fill_vlan_info(fpkt);
	}

	/*
	 * Verify that __packet_finalize_with_mbuf() is setting the truncated
	 * flag correctly.
	 */
	if (truncated) {
		VERIFY((fpkt->pkt_pflags & PKT_F_TRUNCATED) != 0);
	} else {
		VERIFY((fpkt->pkt_pflags & PKT_F_TRUNCATED) == 0);
	}
	return fpkt;
drop:
	if (fpkt != NULL) {
		/* ensure mbuf hasn't been attached */
		ASSERT(fpkt->pkt_mbuf == NULL &&
		    (fpkt->pkt_pflags & PKT_F_MBUF_DATA) == 0);
		nx_netif_free_packet(fpkt);
	}
	STATS_INC(nifs, NETIF_STATS_DROP);
	m_freem(m);
	return NULL;
}

struct __kern_packet *
nx_netif_mbuf_to_filter_pkt_chain(struct nexus_netif_adapter *nifna,
    struct mbuf *m_chain, uint32_t flags)
{
	struct mbuf *m = m_chain, *next;
	struct __kern_packet *pkt_head = NULL, *pkt;
	struct __kern_packet **pkt_tailp = &pkt_head;
	int c = 0;

	while (m != NULL) {
		next = m->m_nextpkt;
		m->m_nextpkt = NULL;

		pkt = nx_netif_mbuf_to_filter_pkt(nifna, m, flags);
		if (pkt != NULL) {
			c++;
			*pkt_tailp = pkt;
			pkt_tailp = &pkt->pkt_nextpkt;
		}
		m = next;
	}
	DTRACE_SKYWALK2(pkt__chain, struct __kern_packet *, pkt_head,
	    int, c);
	return pkt_head;
}

static struct mbuf *
nx_netif_filter_pkt_to_mbuf(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt, uint32_t flags)
{
#pragma unused (nifna)
	struct mbuf *m;

	__check_convert_flags(flags);
	ASSERT((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0);

	m = pkt->pkt_mbuf;
	ASSERT(m != NULL);
	KPKT_CLEAR_MBUF_DATA(pkt);
	nx_netif_free_packet(pkt);
	return m;
}

struct mbuf *
nx_netif_filter_pkt_to_mbuf_chain(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct mbuf *m_head = NULL, *m;
	struct mbuf **m_tailp = &m_head;
	int c = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		m = nx_netif_filter_pkt_to_mbuf(nifna, pkt, flags);
		if (m != NULL) {
			c++;
			*m_tailp = m;
			m_tailp = &m->m_nextpkt;
		}
		pkt = next;
	}
	DTRACE_SKYWALK2(mbuf__chain, struct mbuf *, m_head, int, c);
	return m_head;
}

struct __kern_packet *
nx_netif_pkt_to_filter_pkt(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt, uint32_t flags)
{
	struct __kern_packet *fpkt = NULL;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct kern_pbufpool *pp = nif->nif_filter_pp;
	ifnet_t ifp = nif->nif_ifp;
	boolean_t is_l3, truncated = FALSE;
	enum txrx type;
	uint8_t off, hlen;
	struct mbuf *m = NULL;
	kern_packet_t fph, ph;
	int err, plen;

	__check_convert_flags(flags);
	ph = SK_PKT2PH(pkt);
	is_l3 = (ifp->if_family == IFNET_FAMILY_UTUN ||
	    ifp->if_family == IFNET_FAMILY_IPSEC);

	off = ((flags & NETIF_CONVERT_TX) != 0) ?
	    (uint8_t)ifp->if_tx_headroom : 0;
	hlen = is_l3 ? 0 : ifnet_hdrlen(ifp);

	/*
	 * The packet coming from the compat path could be empty or has
	 * truncated contents. We have to copy the contents from the
	 * attached mbuf. We also don't support attaching a filter
	 * packet (one that already has a packet attached) to another
	 * filter packet.
	 */
	ASSERT((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
	if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
		m = pkt->pkt_mbuf;
		plen = m_pktlen(m);
	} else {
		plen = pkt->pkt_length;
	}
	ASSERT(pp != NULL);
	if (__improbable((off + plen) > PP_BUF_SIZE_DEF(pp))) {
		VERIFY(off < PP_BUF_SIZE_DEF(pp));
		plen = PP_BUF_SIZE_DEF(pp) - off;
		truncated = TRUE;

		DTRACE_SKYWALK5(pkt__truncated,
		    struct nexus_netif_adapter *, nifna,
		    struct __kern_packet *, pkt, uint8_t, off,
		    int, plen, uint32_t, PP_BUF_SIZE_DEF(pp));
		STATS_INC(nifs, NETIF_STATS_FILTER_PKT_TRUNCATED);
	}
	fpkt = nx_netif_alloc_packet(pp, off + plen, &fph);
	if (__improbable(fpkt == NULL)) {
		DTRACE_SKYWALK2(alloc__fail, struct nexus_netif_adapter *,
		    nifna, struct __kern_packet *, pkt);
		STATS_INC(nifs, NETIF_STATS_FILTER_DROP_PKT_ALLOC_FAIL);
		goto drop;
	}
	fpkt->pkt_link_flags = 0;
	fpkt->pkt_headroom = off;
	fpkt->pkt_l2_len = hlen;
	type = ((flags & NETIF_CONVERT_TX) != 0) ? NR_TX : NR_RX;

	if (__improbable((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) != 0 ||
	    (m != NULL && (m->m_flags & M_HASFCS) != 0))) {
		if (type != NR_RX) {
			/*
			 * There shouldn't be an FCS for TX packets
			 */
			DTRACE_SKYWALK2(bad__flags,
			    struct nexus_netif_adapter *, nifna,
			    struct __kern_packet *, pkt);
			goto drop;
		}
		if (plen > ETHER_CRC_LEN) {
			plen -= ETHER_CRC_LEN;
		} else {
			DTRACE_SKYWALK3(bad__pkt__size,
			    struct nexus_netif_adapter *, nifna,
			    struct __kern_packet *, pkt, int, plen);
			goto drop;
		}
	}
	/*
	 * XXX
	 * If the source packet has any checksum flags, the filter packet will
	 * not have valid checksums. To fill in the checksums, we need to do
	 * something similar to bridge_finalize_cksum() for packets.
	 */
	if (m != NULL) {
		nif->nif_pkt_copy_from_mbuf(type, fph, off, m, 0,
		    plen, FALSE, 0);
	} else {
		nif->nif_pkt_copy_from_pkt(type, fph, off, ph,
		    pkt->pkt_headroom, plen, FALSE, 0, 0, FALSE);
	}
	ASSERT((fpkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
	ASSERT((fpkt->pkt_pflags & PKT_F_MBUF_DATA) == 0);
	ASSERT(fpkt->pkt_pkt == NULL);
	ASSERT(pkt->pkt_nextpkt == NULL);
	fpkt->pkt_pkt = pkt;
	fpkt->pkt_pflags |= PKT_F_PKT_DATA;
	if (truncated) {
		fpkt->pkt_pflags |= PKT_F_TRUNCATED;
	}
	/*
	 * XXX
	 * Unlike the mbuf case, __packet_finalize below correctly sets
	 * pkt_length to the buflet length (possibly truncated). We set
	 * pkt_length here so that fill_vlan_info can use it.
	 */
	fpkt->pkt_length = plen;
	if (!is_l3) {
		fill_vlan_info(fpkt);
	}
	err = __packet_finalize(fph);
	VERIFY(err == 0);
	return fpkt;
drop:
	if (fpkt != NULL) {
		/* ensure pkt hasn't been attached */
		ASSERT(fpkt->pkt_pkt == NULL &&
		    (fpkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
		nx_netif_free_packet(fpkt);
	}
	STATS_INC(nifs, NETIF_STATS_DROP);
	nx_netif_free_packet(pkt);
	return NULL;
}

struct __kern_packet *
nx_netif_pkt_to_filter_pkt_chain(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct __kern_packet *p_head = NULL, *p;
	struct __kern_packet **p_tailp = &p_head;
	int c = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		p = nx_netif_pkt_to_filter_pkt(nifna, pkt, flags);
		if (p != NULL) {
			c++;
			*p_tailp = p;
			p_tailp = &p->pkt_nextpkt;
		}
		pkt = next;
	}
	DTRACE_SKYWALK2(pkt__chain, struct __kern_packet *, p_head, int, c);
	return p_head;
}

static struct __kern_packet *
nx_netif_filter_pkt_to_pkt(struct nexus_netif_adapter *nifna,
    struct __kern_packet *fpkt, uint32_t flags)
{
#pragma unused (nifna)
	struct __kern_packet *pkt;

	__check_convert_flags(flags);
	ASSERT((fpkt->pkt_pflags & PKT_F_PKT_DATA) != 0);
	ASSERT((fpkt->pkt_pflags & PKT_F_MBUF_DATA) == 0);

	pkt = fpkt->pkt_pkt;
	ASSERT(pkt != NULL);
	KPKT_CLEAR_PKT_DATA(fpkt);
	nx_netif_free_packet(fpkt);
	return pkt;
}

struct __kern_packet *
nx_netif_filter_pkt_to_pkt_chain(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct __kern_packet *p_head = NULL, *p;
	struct __kern_packet **p_tailp = &p_head;
	int c = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		p = nx_netif_filter_pkt_to_pkt(nifna, pkt, flags);
		if (p != NULL) {
			c++;
			*p_tailp = p;
			p_tailp = &p->pkt_nextpkt;
		}
		pkt = next;
	}
	DTRACE_SKYWALK2(pkt__chain, struct __kern_packet *, p_head, int, c);
	return p_head;
}

struct mbuf *
nx_netif_pkt_to_mbuf(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt, uint32_t flags)
{
	struct nx_netif *nif = nifna->nifna_netif;
	ifnet_t ifp = nif->nif_ifp;
	struct mbuf *m;
	unsigned int one = 1;
	size_t len;
	uint16_t pad, hlen;
	kern_packet_t ph;
	enum txrx type;
	int err;

	__check_convert_flags(flags);
	/* Compat packets or filter packets should never land here */
	ASSERT((pkt->pkt_pflags & PKT_F_MBUF_DATA) == 0);
	ASSERT((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);

	/* Outbound packets should not have this */
	ASSERT((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) == 0);

	/* This function is only meant to be used in the custom ether TX path */
	ASSERT((flags & NETIF_CONVERT_TX) != 0);
	type = NR_TX;

	/* Packet must include L2 header */
	hlen = ifnet_hdrlen(ifp);
	pad = (uint16_t)P2ROUNDUP(hlen, sizeof(uint32_t)) - hlen;
	len = pkt->pkt_length;

	err = mbuf_allocpacket(MBUF_WAITOK, pad + len, &one, &m);
	VERIFY(err == 0);
	m->m_data += pad;
	m->m_pkthdr.pkt_hdr = mtod(m, uint8_t *);
	ph = SK_PTR_ENCODE(pkt, METADATA_TYPE(pkt), METADATA_SUBTYPE(pkt));

	nif->nif_pkt_copy_to_mbuf(type, ph, pkt->pkt_headroom,
	    m, 0, (uint32_t)len, FALSE, 0);
	nx_netif_free_packet(pkt);
	return m;
}

struct __kern_packet *
nx_netif_pkt_to_pkt(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt, uint32_t flags)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct nexus_adapter *na = &nifna->nifna_up;
	struct netif_stats *nifs = &nif->nif_stats;
	ifnet_t ifp = nif->nif_ifp;
	struct kern_pbufpool *pp;
	struct __kern_packet *dpkt = NULL;
	struct mbuf *m = NULL;
	uint8_t off, hlen;
	int len;
	kern_packet_t ph, dph;
	enum txrx type;
	int err;

	__check_convert_flags(flags);
	/* Filter packets should never land here */
	ASSERT((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);

	/* Only support these target NAs for now */
	type = ((flags & NETIF_CONVERT_TX) != 0) ? NR_TX : NR_RX;
	if (type == NR_TX) {
		ASSERT(na->na_type == NA_NETIF_DEV ||
		    na->na_type == NA_NETIF_COMPAT_DEV);
		pp = skmem_arena_nexus(na->na_arena)->arn_tx_pp;
		off = (uint8_t)ifp->if_tx_headroom;
	} else {
		ASSERT(na->na_type == NA_NETIF_VP ||
		    na->na_type == NA_NETIF_DEV);
		pp = skmem_arena_nexus(na->na_arena)->arn_rx_pp;
		off = 0;
	}
	/* Packet must include L2 header */
	hlen = ifnet_hdrlen(ifp);

	/*
	 * Source packet has no data. Need to copy from the attached mbuf.
	 */
	if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
		/* An outbound packet shouldn't have an mbuf attached */
		ASSERT(na->na_type == NA_NETIF_VP ||
		    na->na_type == NA_NETIF_DEV);
		m = pkt->pkt_mbuf;
		len = m_pktlen(m);
	} else {
		len = pkt->pkt_length;
	}
	ASSERT(pp != NULL);

	ph = SK_PKT2PH(pkt);
	dpkt = nx_netif_alloc_packet(pp, off + len, &dph);
	if (__improbable(dpkt == NULL)) {
		if (type == NR_TX) {
			STATS_INC(nifs, NETIF_STATS_VP_DROP_TX_ALLOC_FAIL);
		} else {
			STATS_INC(nifs, NETIF_STATS_VP_DROP_RX_ALLOC_FAIL);
		}
		DTRACE_SKYWALK2(alloc__fail, struct nexus_netif_adapter *,
		    nifna, struct __kern_packet *, pkt);
		goto drop;
	}
	if (__improbable((off + len) > PP_BUF_SIZE_DEF(pp))) {
		STATS_INC(nifs, NETIF_STATS_VP_DROP_PKT_TOO_BIG);
		DTRACE_SKYWALK5(pkt__too__large,
		    struct nexus_netif_adapter *, nifna,
		    struct __kern_packet *, pkt, uint8_t, off, int, len,
		    uint32_t, PP_BUF_SIZE_DEF(pp));
		goto drop;
	}
	if (__improbable((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) != 0 ||
	    (m != NULL && (m->m_flags & M_HASFCS) != 0))) {
		if (type != NR_RX) {
			/*
			 * There shouldn't be an FCS for TX packets
			 */
			DTRACE_SKYWALK2(bad__flags,
			    struct nexus_netif_adapter *, nifna,
			    struct __kern_packet *, pkt);
			goto drop;
		}
		if (len > ETHER_CRC_LEN) {
			len -= ETHER_CRC_LEN;
		} else {
			DTRACE_SKYWALK3(bad__pkt__size,
			    struct nexus_netif_adapter *, nifna,
			    struct __kern_packet *, pkt, int, len);
			goto drop;
		}
	}
	dpkt->pkt_link_flags = 0;
	dpkt->pkt_headroom = off;
	dpkt->pkt_l2_len = hlen;

	/* Copy optional metadata */
	dpkt->pkt_pflags = (pkt->pkt_pflags & PKT_F_COPY_MASK);
	_PKT_COPY_OPT_DATA(pkt, dpkt);

	/* Copy Transmit completion metadata */
	_PKT_COPY_TX_PORT_DATA(pkt, dpkt);

	/* Copy packet contents */
	if (m != NULL) {
		nif->nif_pkt_copy_from_mbuf(type, dph, off, m, 0,
		    len, FALSE, 0);
	} else {
		nif->nif_pkt_copy_from_pkt(type, dph, off, ph,
		    pkt->pkt_headroom, len, FALSE, 0, 0, FALSE);
	}
	err = __packet_finalize(dph);
	VERIFY(err == 0);
	nx_netif_free_packet(pkt);
	return dpkt;

drop:
	if (dpkt != NULL) {
		nx_netif_free_packet(dpkt);
	}
	STATS_INC(nifs, NETIF_STATS_DROP);
	nx_netif_free_packet(pkt);
	return NULL;
}

void
nx_netif_mbuf_chain_info(struct mbuf *m_head, struct mbuf **m_tail,
    uint32_t *cnt, uint32_t *bytes)
{
	struct mbuf *m = m_head, *tail = NULL;
	uint32_t c = 0, b = 0;

	while (m != NULL) {
		c++;
		b += m_pktlen(m);
		tail = m;
		m = m->m_nextpkt;
	}
	if (m_tail != NULL) {
		*m_tail = tail;
	}
	if (cnt != NULL) {
		*cnt = c;
	}
	if (bytes != NULL) {
		*bytes = b;
	}
}

void
nx_netif_pkt_chain_info(struct __kern_packet *p_head,
    struct __kern_packet **p_tail, uint32_t *cnt, uint32_t *bytes)
{
	struct __kern_packet *p = p_head, *tail = NULL;
	uint32_t c = 0, b = 0;

	while (p != NULL) {
		c++;
		b += p->pkt_length;
		tail = p;
		p = p->pkt_nextpkt;
	}
	if (p_tail != NULL) {
		*p_tail = tail;
	}
	if (cnt != NULL) {
		*cnt = c;
	}
	if (bytes != NULL) {
		*bytes = b;
	}
}

int
nx_netif_get_max_mtu(ifnet_t ifp, uint32_t *max_mtu)
{
	struct ifreq ifr;
	int err;

	bzero(&ifr, sizeof(ifr));
	err = ifnet_ioctl(ifp, 0, SIOCGIFDEVMTU, &ifr);
	if (err != 0) {
		SK_ERR("SIOCGIFDEVMTU failed for %s\n", if_name(ifp));
		return err;
	}
	*max_mtu = MAX(ifr.ifr_devmtu.ifdm_max, ifr.ifr_devmtu.ifdm_current);
	return 0;
}

void
nx_netif_pktap_output(ifnet_t ifp, int af, struct __kern_packet *pkt)
{
	uint32_t dlt;
	uint32_t flags = PTH_FLAG_SOCKET;

	switch (ifp->if_family) {
	case IFNET_FAMILY_ETHERNET:
		dlt = DLT_EN10MB;
		break;
	case IFNET_FAMILY_CELLULAR:
	case IFNET_FAMILY_UTUN:
	case IFNET_FAMILY_IPSEC:
		dlt = DLT_RAW;
		break;
	default:
		DTRACE_SKYWALK1(invalid__family, ifnet_t, ifp);
		return;
	}
	if ((pkt->pkt_pflags & PKT_F_KEEPALIVE) != 0) {
		flags |= PTH_FLAG_KEEP_ALIVE;
	}
	if ((pkt->pkt_pflags & PKT_F_REXMT) != 0) {
		flags |= PTH_FLAG_REXMIT;
	}
	pktap_output_packet(ifp, af, dlt, -1, NULL, -1, NULL, SK_PKT2PH(pkt),
	    NULL, 0, pkt->pkt_flow_ip_proto, pkt->pkt_flow_token, flags);
}

__attribute__((always_inline))
inline void
netif_ifp_inc_traffic_class_out_pkt(struct ifnet *ifp, uint32_t svc,
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
