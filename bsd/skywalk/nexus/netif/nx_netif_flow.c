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
#include <netinet/ip6.h>
#include <netinet6/in6_var.h>
#include <net/pktap.h>
#include <sys/sdt.h>
#include <os/log.h>

/* This is just a list for now for simplicity. */
struct netif_list_flowtable {
	struct netif_flow_head  lft_flow_list;
};

static netif_flow_lookup_t netif_flow_list_lookup;
static netif_flow_insert_t netif_flow_list_insert;
static netif_flow_remove_t netif_flow_list_remove;
static netif_flow_table_alloc_t netif_flow_list_table_alloc;
static netif_flow_table_free_t netif_flow_list_table_free;

static netif_flow_match_t netif_flow_ethertype_match;
static netif_flow_info_t netif_flow_ethertype_info;
static netif_flow_match_t netif_flow_ipv6_ula_match;
static netif_flow_info_t netif_flow_ipv6_ula_info;

/*
 * Two flow table types can share the same internal implementation.
 * Using a list for now for simplicity.
 */
static struct netif_flowtable_ops netif_ethertype_ops = {
	.nfo_lookup = netif_flow_list_lookup,
	.nfo_match = netif_flow_ethertype_match,
	.nfo_info = netif_flow_ethertype_info,
	.nfo_insert = netif_flow_list_insert,
	.nfo_remove = netif_flow_list_remove,
	.nfo_table_alloc = netif_flow_list_table_alloc,
	.nfo_table_free = netif_flow_list_table_free
};

static struct netif_flowtable_ops netif_ipv6_ula_ops = {
	.nfo_lookup = netif_flow_list_lookup,
	.nfo_match = netif_flow_ipv6_ula_match,
	.nfo_info = netif_flow_ipv6_ula_info,
	.nfo_insert = netif_flow_list_insert,
	.nfo_remove = netif_flow_list_remove,
	.nfo_table_alloc = netif_flow_list_table_alloc,
	.nfo_table_free = netif_flow_list_table_free
};

static int
netif_flow_get_buf_pkt(struct __kern_packet *pkt, size_t minlen,
    uint8_t **buf, uint32_t *len)
{
	uint8_t *baddr;

	if (pkt->pkt_length < minlen) {
		return EINVAL;
	}
	MD_BUFLET_ADDR_ABS(pkt, baddr);
	baddr += pkt->pkt_headroom;

	*buf = baddr;
	*len = pkt->pkt_length;
	return 0;
}

static int
netif_flow_get_buf_mbuf(struct mbuf *m, size_t minlen,
    uint8_t **buf, uint32_t *len)
{
	/*
	 * XXX
	 * Not pulling up here if mbuf is not contiguous.
	 * This does not impact the current use case (ethertype
	 * demux).
	 */
	if (mbuf_len(m) < minlen) {
		return EINVAL;
	}
	*buf = mbuf_data(m);
	*len = m_pktlen(m);
	return 0;
}

static int
netif_flow_get_buf(struct __kern_packet *pkt, size_t minlen,
    uint8_t **buf, uint32_t *len)
{
	ASSERT((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
	if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
		ASSERT(pkt->pkt_mbuf != NULL);
		return netif_flow_get_buf_mbuf(pkt->pkt_mbuf, minlen, buf, len);
	}
	return netif_flow_get_buf_pkt(pkt, minlen, buf, len);
}

static int
netif_flow_ethertype_info(struct __kern_packet *pkt,
    struct netif_flow_desc *fd, uint32_t flags)
{
#pragma unused (flags)
	ether_header_t *eh;
	uint32_t len;
	uint16_t etype;
	uint16_t tag;
	uint8_t *buf;
	int err;

	err = netif_flow_get_buf(pkt, sizeof(ether_header_t), &buf,
	    &len);
	if (err != 0) {
		DTRACE_SKYWALK2(get__buf__failed, struct __kern_packet *,
		    pkt, int, err);
		return err;
	}
	eh = (ether_header_t *)(void *)buf;
	if (__probable((((uintptr_t)buf) & 1) == 0)) {
		etype = eh->ether_type;
	} else {
		bcopy(&eh->ether_type, &etype, sizeof(etype));
	}
	etype = ntohs(etype);

	if (kern_packet_get_vlan_tag(SK_PKT2PH(pkt), &tag, NULL) == 0) {
		DTRACE_SKYWALK2(hw__vlan, struct __kern_packet *, pkt,
		    uint16_t, tag);
	} else if (etype == ETHERTYPE_VLAN) {
		struct ether_vlan_header *evh;

		DTRACE_SKYWALK2(encap__vlan, struct __kern_packet *, pkt,
		    uint8_t *, buf);
		if ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
			struct mbuf *m = pkt->pkt_mbuf;

			if (mbuf_len(m) < sizeof(*evh)) {
				DTRACE_SKYWALK1(mbuf__too__small,
				    struct mbuf *, m);
				return EINVAL;
			}
		} else {
			if (len < sizeof(*evh)) {
				DTRACE_SKYWALK2(pkt__too__small,
				    struct __kern_packet *, pkt,
				    uint32_t, len);
				return EINVAL;
			}
		}
		evh = (struct ether_vlan_header *)eh;
		if (__probable((((uintptr_t)evh) & 1) == 0)) {
			tag = evh->evl_tag;
			etype = evh->evl_proto;
		} else {
			bcopy(&evh->evl_tag, &tag, sizeof(tag));
			bcopy(&evh->evl_proto, &etype, sizeof(etype));
		}
		tag = ntohs(tag);
		etype = ntohs(etype);
	} else {
		tag = 0;
	}
	/* Only accept priority tagged packets */
	if (EVL_VLANOFTAG(tag) != 0) {
		DTRACE_SKYWALK2(vlan__non__zero,
		    struct __kern_packet *, pkt, uint16_t, tag);
		return ENOTSUP;
	}
	DTRACE_SKYWALK4(extracted__info, struct __kern_packet *, pkt,
	    uint8_t *, buf, uint16_t, tag, uint16_t, etype);
	fd->fd_ethertype = etype;
	return 0;
}

static boolean_t
netif_flow_ethertype_match(struct netif_flow_desc *fd1,
    struct netif_flow_desc *fd2)
{
	return fd1->fd_ethertype == fd2->fd_ethertype;
}

static int
netif_flow_ipv6_ula_info(struct __kern_packet *pkt,
    struct netif_flow_desc *fd, uint32_t flags)
{
	ether_header_t *eh;
	uint32_t len;
	uint8_t *buf;
	struct ip6_hdr *ip6h;
	void *laddr, *raddr;
	uint16_t etype;
	int err;

	err = netif_flow_get_buf(pkt, sizeof(*eh) + sizeof(*ip6h),
	    &buf, &len);
	if (err != 0) {
		DTRACE_SKYWALK2(get__buf__failed, struct __kern_packet *,
		    pkt, int, err);
		return err;
	}
	eh = (ether_header_t *)(void *)buf;
	ip6h = (struct ip6_hdr *)(eh + 1);

	bcopy(&eh->ether_type, &etype, sizeof(etype));
	etype = ntohs(etype);
	if (etype != ETHERTYPE_IPV6) {
		return ENOENT;
	}
	if (len < sizeof(*eh) + sizeof(*ip6h)) {
		return EINVAL;
	}
	if ((flags & NETIF_FLOW_OUTBOUND) != 0) {
		laddr = &ip6h->ip6_src;
		raddr = &ip6h->ip6_dst;
	} else {
		laddr = &ip6h->ip6_dst;
		raddr = &ip6h->ip6_src;
	}
	bcopy(laddr, &fd->fd_laddr, sizeof(struct in6_addr));
	bcopy(raddr, &fd->fd_raddr, sizeof(struct in6_addr));
	return 0;
}

static boolean_t
netif_flow_ipv6_ula_match(struct netif_flow_desc *fd1, struct netif_flow_desc *fd2)
{
	return IN6_ARE_ADDR_EQUAL(&fd1->fd_laddr, &fd2->fd_laddr) &&
	       IN6_ARE_ADDR_EQUAL(&fd1->fd_raddr, &fd2->fd_raddr);
}

static int
netif_flow_list_lookup(struct netif_flowtable *ft, struct __kern_packet *pkt,
    uint32_t flags, struct netif_flow **f)
{
	struct netif_list_flowtable *lft = ft->ft_internal;
	struct netif_flowtable_ops *fops = ft->ft_ops;
	struct netif_flow *nf;
	struct netif_flow_desc fd;
	int err;

	/* XXX returns the first flow if "accept all" is on */
	if (nx_netif_vp_accept_all != 0) {
		nf = SLIST_FIRST(&lft->lft_flow_list);
		goto done;
	}
	err = fops->nfo_info(pkt, &fd, flags);
	if (err != 0) {
		return err;
	}
	SLIST_FOREACH(nf, &lft->lft_flow_list, nf_table_link) {
		if (fops->nfo_match(&nf->nf_desc, &fd)) {
			break;
		}
	}
done:
	if (nf == NULL) {
		return ENOENT;
	}
	*f = nf;
	return 0;
}

static int
netif_flow_list_insert(struct netif_flowtable *ft, struct netif_flow *f)
{
	struct netif_list_flowtable *lft = ft->ft_internal;
	struct netif_flow *nf;

	SLIST_FOREACH(nf, &lft->lft_flow_list, nf_table_link) {
		if (nf->nf_port == f->nf_port ||
		    ft->ft_ops->nfo_match(&nf->nf_desc, &f->nf_desc)) {
			break;
		}
	}
	if (nf != NULL) {
		return EEXIST;
	}
	SLIST_INSERT_HEAD(&lft->lft_flow_list, f, nf_table_link);
	return 0;
}

static void
netif_flow_list_remove(struct netif_flowtable *ft, struct netif_flow *f)
{
	struct netif_list_flowtable *lft = ft->ft_internal;

	SLIST_REMOVE(&lft->lft_flow_list, f, netif_flow, nf_table_link);
}

static struct netif_flowtable *
netif_flow_list_table_alloc(struct netif_flowtable_ops *ops)
{
	struct netif_flowtable *ft;
	struct netif_list_flowtable *lft;

	ft = skn_alloc_type(flowtable, struct netif_flowtable,
	    Z_WAITOK | Z_NOFAIL, skmem_tag_netif_flow);
	lft = skn_alloc_type(list_flowtable, struct netif_list_flowtable,
	    Z_WAITOK | Z_NOFAIL, skmem_tag_netif_flow);
	/*
	 * For now lft just holds a list. We can use any data structure here.
	 */
	SLIST_INIT(&lft->lft_flow_list);
	ft->ft_internal = lft;
	ft->ft_ops = ops;
	return ft;
}

static void
netif_flow_list_table_free(struct netif_flowtable *ft)
{
	struct netif_list_flowtable *lft;

	ASSERT(ft->ft_ops != NULL);
	ft->ft_ops = NULL;

	ASSERT(ft->ft_internal != NULL);
	lft = ft->ft_internal;
	ASSERT(SLIST_EMPTY(&lft->lft_flow_list));

	skn_free_type(list_flowtable, struct netif_list_flowtable, lft);
	ft->ft_internal = NULL;

	skn_free_type(flowtable, struct netif_flowtable, ft);
}

static void
nx_netif_flow_deliver(struct nx_netif *nif, struct netif_flow *f,
    void *data, uint32_t flags)
{
#pragma unused(nif)
	f->nf_cb_func(f->nf_cb_arg, data, flags);
}

void
nx_netif_snoop(struct nx_netif *nif, struct __kern_packet *pkt,
    boolean_t inbound)
{
	/* pktap only supports IPv4 or IPv6 packets */
	if (!NETIF_IS_LOW_LATENCY(nif)) {
		return;
	}
	if (inbound) {
		pktap_input_packet(nif->nif_ifp, AF_INET6, DLT_EN10MB,
		    -1, NULL, -1, NULL, SK_PKT2PH(pkt), NULL, 0, 0, 0,
		    PTH_FLAG_NEXUS_CHAN);
	} else {
		pktap_output_packet(nif->nif_ifp, AF_INET6, DLT_EN10MB,
		    -1, NULL, -1, NULL, SK_PKT2PH(pkt), NULL, 0, 0, 0,
		    PTH_FLAG_NEXUS_CHAN);
	}
}

/*
 * This function ensures that the interface's mac address matches:
 * -the destination mac address of inbound packets
 * -the source mac address of outbound packets
 */
boolean_t
nx_netif_validate_macaddr(struct nx_netif *nif, struct __kern_packet *pkt,
    uint32_t flags)
{
	struct netif_stats *nifs = &nif->nif_stats;
	struct ifnet *ifp = nif->nif_ifp;
	uint8_t local_addr[ETHER_ADDR_LEN], *addr;
	boolean_t valid = FALSE, outbound, mbcast;
	ether_header_t *eh;
	uint32_t len;
	uint8_t *buf;

	/*
	 * No need to hold any lock for the checks below because we are not
	 * accessing any shared state.
	 */
	if (netif_flow_get_buf(pkt, sizeof(ether_header_t), &buf, &len) != 0) {
		STATS_INC(nifs, NETIF_STATS_VP_BAD_PKT_LEN);
		DTRACE_SKYWALK2(bad__pkt__sz, struct nx_netif *, nif,
		    struct __kern_packet *, pkt);
		return FALSE;
	}
	DTRACE_SKYWALK4(dump__buf, struct nx_netif *, nif,
	    struct __kern_packet *, pkt, void *, buf, uint32_t, len);

	eh = (ether_header_t *)(void *)buf;
	outbound = ((flags & NETIF_FLOW_OUTBOUND) != 0);
	addr = outbound ? eh->ether_shost : eh->ether_dhost;
	mbcast = ((addr[0] & 1) != 0);

	if (NETIF_IS_LOW_LATENCY(nif)) {
		/* disallow multicast/broadcast as both src or dest macaddr */
		if (mbcast) {
			DTRACE_SKYWALK4(mbcast__pkt__llw,
			    struct nx_netif *, nif, struct __kern_packet *, pkt,
			    void *, buf, uint32_t, len);
			goto done;
		}
		/* only validate macaddr for outbound packets */
		if (!outbound) {
			DTRACE_SKYWALK4(skip__check__llw,
			    struct nx_netif *, nif, struct __kern_packet *, pkt,
			    void *, buf, uint32_t, len);
			return TRUE;
		}
	} else {
		if (mbcast) {
			if (outbound) {
				/* disallow multicast/broadcast as src macaddr */
				DTRACE_SKYWALK4(mbcast__src,
				    struct nx_netif *, nif,
				    struct __kern_packet *, pkt,
				    void *, buf, uint32_t, len);
				goto done;
			} else {
				/* allow multicast/broadcast as dest macaddr */
				DTRACE_SKYWALK4(mbcast__dest,
				    struct nx_netif *, nif,
				    struct __kern_packet *, pkt,
				    void *, buf, uint32_t, len);
				return TRUE;
			}
		}
	}
	if (ifnet_lladdr_copy_bytes(ifp, local_addr, sizeof(local_addr)) != 0) {
		STATS_INC(nifs, NETIF_STATS_VP_BAD_MADDR_LEN);
		DTRACE_SKYWALK2(bad__addr__len, struct nx_netif *, nif,
		    struct ifnet *, ifp);
		return FALSE;
	}
	valid = (_ether_cmp(local_addr, addr) == 0);
done:
	if (!valid) {
		/*
		 * A non-matching mac addr is not an error for the input path
		 * because we are expected to get such packets. These packets
		 * are already counted as NETIF_STATS_FLOW_NOT_FOUND.
		 */
		if (outbound) {
			STATS_INC(nifs, NETIF_STATS_VP_BAD_MADDR);
		}
		DTRACE_SKYWALK2(bad__addr, struct nx_netif *, nif,
		    struct __kern_packet *, pkt);
	}
	return valid;
}

/*
 * Checks whether a packet matches the specified flow's description.
 * This is used for validating outbound packets.
 */
boolean_t
nx_netif_flow_match(struct nx_netif *nif, struct __kern_packet *pkt,
    struct netif_flow *f, uint32_t flags)
{
	struct netif_stats *nifs = &nif->nif_stats;
	struct netif_flowtable *ft;
	struct netif_flowtable_ops *fops;
	struct netif_flow_desc fd;
	boolean_t match = FALSE;
	int err;

	/*
	 * Unlike the lookup case, ft cannot be NULL here because there
	 * should be a table to hold our flow. No locking is needed because
	 * no one can close our channel while we have ongoing syncs.
	 */
	VERIFY((ft = nif->nif_flow_table) != NULL);
	fops = ft->ft_ops;

	/*
	 * We increment error stats here but not when we classify because in
	 * this case a match is expected.
	 */
	err = fops->nfo_info(pkt, &fd, flags);
	if (err != 0) {
		STATS_INC(nifs, NETIF_STATS_VP_FLOW_INFO_ERR);
		DTRACE_SKYWALK3(info__err, struct nx_netif *, nif, int, err,
		    struct __kern_packet *, pkt);
		return FALSE;
	}
	match = fops->nfo_match(&f->nf_desc, &fd);
	if (!match) {
		STATS_INC(nifs, NETIF_STATS_VP_FLOW_NOT_MATCH);
		DTRACE_SKYWALK3(not__match, struct nx_netif *, nif,
		    struct netif_flow *, f, struct __kern_packet *, pkt);
	}
	return match;
}

struct netif_flow *
nx_netif_flow_classify(struct nx_netif *nif, struct __kern_packet *pkt,
    uint32_t flags)
{
	struct netif_stats *nifs = &nif->nif_stats;
	struct netif_flow *f = NULL;
	struct netif_flowtable *ft;
	int err;

	lck_mtx_lock(&nif->nif_flow_lock);
	if ((nif->nif_flow_flags & NETIF_FLOW_FLAG_ENABLED) == 0) {
		STATS_INC(nifs, NETIF_STATS_VP_FLOW_DISABLED);
		DTRACE_SKYWALK1(disabled, struct nx_netif *, nif);
		goto fail;
	}
	if ((ft = nif->nif_flow_table) == NULL) {
		STATS_INC(nifs, NETIF_STATS_VP_FLOW_EMPTY_TABLE);
		DTRACE_SKYWALK1(empty__flowtable, struct nx_netif *, nif);
		goto fail;
	}
	err = ft->ft_ops->nfo_lookup(ft, pkt, flags, &f);
	if (err != 0) {
		/* caller increments counter */
		DTRACE_SKYWALK1(not__found, struct nx_netif *, nif);
		goto fail;
	}
	f->nf_refcnt++;
	lck_mtx_unlock(&nif->nif_flow_lock);
	return f;

fail:
	lck_mtx_unlock(&nif->nif_flow_lock);
	return NULL;
}

void
nx_netif_flow_release(struct nx_netif *nif, struct netif_flow *nf)
{
	lck_mtx_lock(&nif->nif_flow_lock);
	if (--nf->nf_refcnt == 0) {
		wakeup(&nf->nf_refcnt);
	}
	lck_mtx_unlock(&nif->nif_flow_lock);
}

static struct netif_flow *
flow_classify(struct nx_netif *nif, struct __kern_packet *pkt, uint32_t flags)
{
	if (nx_netif_vp_accept_all == 0 &&
	    !nx_netif_validate_macaddr(nif, pkt, flags)) {
		return NULL;
	}
	return nx_netif_flow_classify(nif, pkt, flags);
}

errno_t
nx_netif_demux(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, struct __kern_packet **remain,
    uint32_t flags)
{
	struct __kern_packet *pkt = pkt_chain, *next;
	struct __kern_packet *head = NULL, **tailp = &head;
	struct __kern_packet *rhead = NULL, **rtailp = &rhead;
	struct netif_flow *nf, *prev_nf = NULL;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	int c = 0, r = 0, delivered = 0, bytes = 0, rbytes = 0, plen = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		ASSERT((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
		plen = ((pkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) ?
		    m_pktlen(pkt->pkt_mbuf) : pkt->pkt_length;

		/*
		 * The returned nf is refcounted to ensure it doesn't
		 * disappear while packets are being delivered.
		 */
		nf = flow_classify(nif, pkt, flags);
		if (nf != NULL) {
			nx_netif_snoop(nif, pkt, TRUE);

			/*
			 * Keep growing the chain until we classify to a
			 * different nf.
			 */
			if (prev_nf != NULL) {
				if (prev_nf != nf) {
					DTRACE_SKYWALK5(deliver,
					    struct nx_netif *, nif,
					    struct netif_flow *, prev_nf,
					    struct __kern_packet *, head,
					    int, c, uint32_t, flags);

					nx_netif_flow_deliver(nif,
					    prev_nf, head, flags);
					nx_netif_flow_release(nif, prev_nf);
					prev_nf = nf;
					head = NULL;
					tailp = &head;
					delivered += c;
					c = 0;
				} else {
					/*
					 * one reference is enough.
					 */
					nx_netif_flow_release(nif, nf);
				}
			} else {
				prev_nf = nf;
			}
			c++;
			bytes += plen;
			*tailp = pkt;
			tailp = &pkt->pkt_nextpkt;
		} else {
			r++;
			rbytes += plen;
			*rtailp = pkt;
			rtailp = &pkt->pkt_nextpkt;
		}
		pkt = next;
	}
	if (head != NULL) {
		ASSERT(prev_nf != NULL);
		DTRACE_SKYWALK5(deliver__last, struct nx_netif *,
		    nif, struct netif_flow *, prev_nf, struct __kern_packet *,
		    pkt, int, c, uint32_t, flags);

		nx_netif_flow_deliver(nif, prev_nf, head, flags);
		nx_netif_flow_release(nif, prev_nf);
		prev_nf = NULL;
		head = NULL;
		tailp = &head;
		delivered += c;
	}
	if (rhead != NULL) {
		if (remain != NULL) {
			*remain = rhead;
		} else {
			nx_netif_free_packet_chain(rhead, NULL);
		}
	}
	STATS_ADD(nifs, NETIF_STATS_VP_FLOW_FOUND, delivered);
	STATS_ADD(nifs, NETIF_STATS_VP_FLOW_NOT_FOUND, r);
	DTRACE_SKYWALK5(demux__delivered, struct nx_netif *,
	    nif, int, delivered, int, r, int, bytes, int, rbytes);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static errno_t
nx_netif_flowtable_init(struct nx_netif *nif, netif_flowtable_type_t type)
{
	struct netif_flowtable *ft;
	struct netif_flowtable_ops *fops;

	switch (type) {
	case FT_TYPE_ETHERTYPE:
		fops = &netif_ethertype_ops;
		break;
	case FT_TYPE_IPV6_ULA:
		fops = &netif_ipv6_ula_ops;
		break;
	default:
		return ENOTSUP;
	}
	ft = fops->nfo_table_alloc(fops);
	if (ft == NULL) {
		return ENOMEM;
	}
	nif->nif_flow_table = ft;
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_flowtable_fini(struct nx_netif *nif)
{
	struct netif_flowtable *ft = nif->nif_flow_table;

	ASSERT(ft != NULL);
	ft->ft_ops->nfo_table_free(ft);
	nif->nif_flow_table = NULL;
}

/*
 * netif doesn't keep accounting of flow statistics, this log message will
 * print a snapshot of the current netif stats at the time of flow creation
 * and removal. For a netif on interfaces like "llwX", the difference in these
 * stats at creation vs removal will be analogous to flow stats as there will
 * be atmost one flow active at any given time.
 */
static inline void
nx_netif_flow_log(struct nx_netif *nif, struct netif_flow *nf, boolean_t add)
{
	int i;
	struct netif_stats *nifs = &nif->nif_stats;

	os_log(OS_LOG_DEFAULT, "netif flowstats (%s): if %s, nx_port %d, "
	    "ethertype 0x%x, src %s, dst %s", add ? "add" : "remove",
	    if_name(nif->nif_ifp), nf->nf_port, nf->nf_desc.fd_ethertype,
	    ip6_sprintf(&nf->nf_desc.fd_laddr),
	    ip6_sprintf(&nf->nf_desc.fd_raddr));
	for (i = 0; i < __NETIF_STATS_MAX; i++) {
		if (STATS_VAL(nifs, i) == 0) {
			continue;
		}
		os_log(OS_LOG_DEFAULT, "%s: %llu", netif_stats_str(i),
		    STATS_VAL(nifs, i));
	}
}

errno_t
nx_netif_flow_add(struct nx_netif *nif, nexus_port_t port,
    struct netif_flow_desc *desc, void *cb_arg,
    errno_t (*cb_func)(void *, void *, uint32_t),
    struct netif_flow **nfp)
{
	struct netif_flow *nf = NULL;
	struct netif_flowtable *ft;
	struct netif_stats *nifs = &nif->nif_stats;
	boolean_t refcnt_incr = FALSE, new_table = FALSE;
	errno_t err = 0;

	lck_mtx_lock(&nif->nif_flow_lock);
	nf = sk_alloc_type(struct netif_flow, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_netif_flow);
	bcopy(desc, &nf->nf_desc, sizeof(*desc));
	nf->nf_port = port;
	nf->nf_refcnt = 0;
	nf->nf_cb_arg = cb_arg;
	nf->nf_cb_func = cb_func;

	if (++nif->nif_flow_cnt == 1) {
		netif_flowtable_type_t ft_type;

		ft_type = NETIF_IS_LOW_LATENCY(nif) ? FT_TYPE_IPV6_ULA :
		    FT_TYPE_ETHERTYPE;

		err = nx_netif_flowtable_init(nif, ft_type);
		if (err != 0) {
			STATS_INC(nifs, NETIF_STATS_VP_FLOW_TABLE_INIT_FAIL);
			DTRACE_SKYWALK1(flowtable__init__fail,
			    struct nx_netif *, nif);
			goto fail;
		}
		new_table = TRUE;
	}
	refcnt_incr = TRUE;
	ft = nif->nif_flow_table;
	err = ft->ft_ops->nfo_insert(ft, nf);
	if (err != 0) {
		STATS_INC(nifs, NETIF_STATS_VP_FLOW_INSERT_FAIL);
		DTRACE_SKYWALK1(insert__fail, struct nx_netif *, nif);
		goto fail;
	}
	SLIST_INSERT_HEAD(&nif->nif_flow_list, nf, nf_link);
	if (nfp != NULL) {
		*nfp = nf;
	}
	STATS_INC(nifs, NETIF_STATS_VP_FLOW_ADD);
	lck_mtx_unlock(&nif->nif_flow_lock);
	SK_DF(SK_VERB_VP, "flow add successful: if %s, nif 0x%llx",
	    if_name(nif->nif_ifp), SK_KVA(nif));
	nx_netif_flow_log(nif, nf, TRUE);
	return 0;

fail:
	if (nf != NULL) {
		sk_free_type(struct netif_flow, nf);
	}
	if (refcnt_incr && --nif->nif_flow_cnt == 0) {
		if (new_table) {
			nx_netif_flowtable_fini(nif);
		}
	}
	lck_mtx_unlock(&nif->nif_flow_lock);
	SK_ERR("flow add failed: if %s, nif 0x%llx, err %d",
	    if_name(nif->nif_ifp), SK_KVA(nif), err);
	return err;
}

errno_t
nx_netif_flow_remove(struct nx_netif *nif, struct netif_flow *nf)
{
	struct netif_flowtable_ops *fops;
	struct netif_flowtable *ft;
	struct netif_stats *nifs = &nif->nif_stats;

	lck_mtx_lock(&nif->nif_flow_lock);
	SLIST_REMOVE(&nif->nif_flow_list, nf, netif_flow, nf_link);
	ft = nif->nif_flow_table;
	ASSERT(ft != NULL);
	fops = ft->ft_ops;
	fops->nfo_remove(ft, nf);

	while (nf->nf_refcnt > 0) {
		DTRACE_SKYWALK1(wait__refcnt, struct netif_flow *, nf);
		(void) msleep(&nf->nf_refcnt,
		    &nif->nif_flow_lock, (PZERO + 1),
		    __FUNCTION__, NULL);
	}
	if (--nif->nif_flow_cnt == 0) {
		nx_netif_flowtable_fini(nif);
	}
	STATS_INC(nifs, NETIF_STATS_VP_FLOW_REMOVE);
	lck_mtx_unlock(&nif->nif_flow_lock);

	SK_DF(SK_VERB_VP, "flow remove: if %s, nif 0x%llx",
	    if_name(nif->nif_ifp), SK_KVA(nif));
	nx_netif_flow_log(nif, nf, FALSE);
	sk_free_type(struct netif_flow, nf);
	return 0;
}

void
nx_netif_flow_init(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	if (!ifnet_needs_netif_netagent(ifp) && !NETIF_IS_LOW_LATENCY(nif)) {
		SK_DF(SK_VERB_VP, "%s: flows not supported due to missing "
		    "if_attach_nx flag or invalid interface type",
		    if_name(ifp));
		return;
	}
	if (ifp->if_family != IFNET_FAMILY_ETHERNET) {
		SK_DF(SK_VERB_VP, "%s: flows not supported on "
		    "interface family %d", if_name(ifp), ifp->if_family);
		return;
	}
	ASSERT(nif->nif_flow_flags == 0);
	lck_mtx_init(&nif->nif_flow_lock, &nexus_lock_group,
	    &nexus_lock_attr);

	SLIST_INIT(&nif->nif_flow_list);
	nif->nif_flow_table = NULL;
	nif->nif_flow_cnt = 0;
	nif->nif_flow_flags |= NETIF_FLOW_FLAG_INITIALIZED;

	SK_DF(SK_VERB_VP, "%s: flows initialized", if_name(ifp));
}

void
nx_netif_flow_fini(struct nx_netif *nif)
{
	if ((nif->nif_flow_flags & NETIF_FLOW_FLAG_INITIALIZED) == 0) {
		SK_DF(SK_VERB_VP, "%s: flows not initialized",
		    if_name(nif->nif_ifp));
		return;
	}
	nif->nif_flow_flags &= ~NETIF_FLOW_FLAG_INITIALIZED;

	/* This should've been cleared before we get to this point */
	ASSERT((nif->nif_flow_flags & NETIF_FLOW_FLAG_ENABLED) == 0);
	ASSERT(nif->nif_flow_cnt == 0);
	ASSERT(nif->nif_flow_table == NULL);
	ASSERT(SLIST_EMPTY(&nif->nif_flow_list));

	lck_mtx_destroy(&nif->nif_flow_lock, &nexus_lock_group);

	SK_DF(SK_VERB_VP, "%s: flows uninitialization done",
	    if_name(nif->nif_ifp));
}

static void
nx_netif_flow_set_enable(struct nx_netif *nif, boolean_t set)
{
	/*
	 * No locking needed while checking for the initialized bit because
	 * if this were not set, no other flag would be modified.
	 */
	if ((nif->nif_flow_flags & NETIF_FLOW_FLAG_INITIALIZED) == 0) {
		return;
	}
	lck_mtx_lock(&nif->nif_flow_lock);
	if (set) {
		SK_DF(SK_VERB_VP, "%s: flow enable, nif 0x%llx",
		    if_name(nif->nif_ifp), SK_KVA(nif));
		nif->nif_flow_flags |= NETIF_FLOW_FLAG_ENABLED;
	} else {
		SK_DF(SK_VERB_VP, "%s: flow disable, nif 0x%llx",
		    if_name(nif->nif_ifp), SK_KVA(nif));
		nif->nif_flow_flags &= ~NETIF_FLOW_FLAG_ENABLED;
	}
	lck_mtx_unlock(&nif->nif_flow_lock);
}

void
nx_netif_flow_enable(struct nx_netif *nif)
{
	nx_netif_flow_set_enable(nif, TRUE);
}

void
nx_netif_flow_disable(struct nx_netif *nif)
{
	nx_netif_flow_set_enable(nif, FALSE);
}
