/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
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

/* $FreeBSD: src/sys/netinet6/frag6.c,v 1.2.2.5 2001/07/03 11:01:50 ume Exp $ */
/* $KAME: frag6.c,v 1.31 2001/05/17 13:45:34 jinmei Exp $ */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * @file
 * flowswitch IP Reassembly for both v4 and v6
 *
 * Implementation of IP packet fragmentation and reassembly.
 *
 */

#include <sys/domain.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>

#define IPFM_MAX_FRAGS_PER_QUEUE        128     /* RFC 791 64K/(512 min MTU) */
#define IPFM_MAX_QUEUES                 1024    /* same as ip/ip6 */
#define IPFM_FRAG_TTL                   60      /* RFC 2460 */
#define IPFM_TIMEOUT_TCALL_INTERVAL     1

static uint32_t ipfm_max_frags_per_queue = IPFM_MAX_FRAGS_PER_QUEUE;
static uint32_t ipfm_frag_ttl = IPFM_FRAG_TTL;
static uint32_t ipfm_timeout_tcall_ival = IPFM_TIMEOUT_TCALL_INTERVAL;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_kern_skywalk_flowswitch, OID_AUTO,
    ipfm_max_frags_per_queue, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ipfm_max_frags_per_queue, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

SYSCTL_INT(_kern_skywalk_flowswitch, OID_AUTO, ipfm_frag_ttl,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ipfm_frag_ttl, 0, "");
SYSCTL_INT(_kern_skywalk_flowswitch, OID_AUTO,
    ipfm_timeout_tcall_ival, CTLFLAG_RW | CTLFLAG_LOCKED,
    &ipfm_timeout_tcall_ival, 0, "");

static LCK_GRP_DECLARE(fsw_ipfm_lock_group, "sk_fsw_ipfm_lock");
static LCK_ATTR_DECLARE(fsw_ipfm_lock_attr, 0, 0);

/* @internal ip fragment wrapper (chained in an ipfq) for __kern_packet */
struct ipf {
	struct ipf      *ipf_down;
	struct ipf      *ipf_up;
	struct __kern_packet *ipf_pkt;
	int             ipf_len;        /* fragmentable part length */
	int             ipf_off;        /* fragment offset */
	uint16_t        ipf_mff;        /* more fragment bit in frag off */
};

/* @internal ip fragment lookup key */
struct ipf_key {
	uint64_t        ipfk_addr[4];   /* src + dst ip addr (v4/v6) */
	uint32_t        ipfk_ident;     /* IP identification */
	uint16_t        ipfk_len;       /* len of ipfk_addr field */
};

enum {
	IPFK_LEN_V4 = 2 * sizeof(struct in_addr),
	IPFK_LEN_V6 = 2 * sizeof(struct in6_addr),
};

/*
 * @internal
 * IP reassembly queue structure.  Each fragment (struct ipf)
 * being reassembled is attached to one of these structures.
 */
struct ipfq {
	struct ipf      *ipfq_down;     /* fragment chain */
	struct ipf      *ipfq_up;
	struct ipfq     *ipfq_next;     /* queue chain */
	struct ipfq     *ipfq_prev;
	uint64_t        ipfq_timestamp; /* time of creation */
	struct ipf_key  ipfq_key;       /* ipfq search key */
	uint16_t        ipfq_nfrag;     /* # of fragments in queue */
	uint16_t        ipfq_unfraglen; /* len of unfragmentable part */
	bool            ipfq_is_dirty;  /* q is dirty, don't use */
};

/*
 * @internal (externally opaque)
 * flowswitch IP Fragment Manager
 */
struct fsw_ip_frag_mgr {
	struct skoid    ipfm_skoid;
	struct ipfq     ipfm_q;         /* ip reassembly queues */
	uint32_t        ipfm_q_limit;   /* limit # of reass queues */
	uint32_t        ipfm_q_count;   /* # of allocated reass queues */
	uint32_t        ipfm_f_limit;   /* limit # of ipfs */
	uint32_t        ipfm_f_count;   /* current # of allocated ipfs */
	decl_lck_mtx_data(, ipfm_lock); /* guard reass and timeout cleanup */
	thread_call_t   ipfm_timeout_tcall;     /* frag timeout thread */

	struct ifnet    *ipfm_ifp;
	struct fsw_stats *ipfm_stats;   /* indirect stats in fsw */
};

static int ipf_process(struct fsw_ip_frag_mgr *, struct __kern_packet **,
    struct ipf_key *, uint16_t, uint16_t, uint16_t, uint16_t, uint16_t *,
    uint16_t *);
static int ipf_key_cmp(struct ipf_key *, struct ipf_key *);
static void ipf_enq(struct ipf *, struct ipf *);
static void ipf_deq(struct ipf *);
static void ipfq_insque(struct ipfq *, struct ipfq *);
static void ipfq_remque(struct ipfq *);
static uint32_t ipfq_freef(struct fsw_ip_frag_mgr *mgr, struct ipfq *,
    void (*)(struct fsw_ip_frag_mgr *, struct ipf *));

static void ipfq_timeout(thread_call_param_t, thread_call_param_t);
static void ipfq_sched_timeout(struct fsw_ip_frag_mgr *, boolean_t);

static struct ipfq *ipfq_alloc(struct fsw_ip_frag_mgr *mgr, int how);
static void ipfq_free(struct fsw_ip_frag_mgr *mgr, struct ipfq *q);
static uint32_t ipfq_freefq(struct fsw_ip_frag_mgr *mgr, struct ipfq *q,
    void (*ipf_cb)(struct fsw_ip_frag_mgr *, struct ipf *));
static struct ipf *ipf_alloc(struct fsw_ip_frag_mgr *mgr);
static void ipf_free(struct fsw_ip_frag_mgr *mgr, struct ipf *f);
static void ipf_free_pkt(struct ipf *f);
static void ipfq_drain(struct fsw_ip_frag_mgr *);
static int ipfq_drain_sysctl SYSCTL_HANDLER_ARGS;
void ipf_icmp_param_err(struct fsw_ip_frag_mgr *, struct __kern_packet *pkt,
    int param);
void ipf_icmp_timeout_err(struct fsw_ip_frag_mgr *, struct ipf *f);

/* Create a flowswitch IP fragment manager. */
struct fsw_ip_frag_mgr *
fsw_ip_frag_mgr_create(struct nx_flowswitch *fsw, struct ifnet *ifp,
    size_t f_limit)
{
	struct fsw_ip_frag_mgr *mgr;

	/* ipf/ipfq uses mbufs for IP fragment queue structures */
	_CASSERT(sizeof(struct ipfq) <= _MLEN);
	_CASSERT(sizeof(struct ipf) <= _MLEN);

	ASSERT(ifp != NULL);

	mgr = sk_alloc_type(struct fsw_ip_frag_mgr, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_fsw_frag_mgr);

	mgr->ipfm_q.ipfq_next = mgr->ipfm_q.ipfq_prev = &mgr->ipfm_q;
	lck_mtx_init(&mgr->ipfm_lock, &fsw_ipfm_lock_group, &fsw_ipfm_lock_attr);

	mgr->ipfm_timeout_tcall =
	    thread_call_allocate_with_options(ipfq_timeout, mgr,
	    THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	VERIFY(mgr->ipfm_timeout_tcall != NULL);

	mgr->ipfm_ifp = ifp;
	mgr->ipfm_stats = &fsw->fsw_stats;

	/* Use caller provided limit (caller knows pool size) */
	ASSERT(f_limit >= 2 && f_limit < UINT32_MAX);
	mgr->ipfm_f_limit = (uint32_t)f_limit;
	mgr->ipfm_f_count = 0;
	mgr->ipfm_q_limit = MIN(IPFM_MAX_QUEUES, mgr->ipfm_f_limit / 2);
	mgr->ipfm_q_count = 0;

	skoid_create(&mgr->ipfm_skoid, SKOID_DNODE(fsw->fsw_skoid), "ipfm", 0);
	skoid_add_uint(&mgr->ipfm_skoid, "frag_limit", CTLFLAG_RW,
	    &mgr->ipfm_f_limit);
	skoid_add_uint(&mgr->ipfm_skoid, "frag_count", CTLFLAG_RD,
	    &mgr->ipfm_f_count);
	skoid_add_uint(&mgr->ipfm_skoid, "queue_limit", CTLFLAG_RW,
	    &mgr->ipfm_q_limit);
	skoid_add_uint(&mgr->ipfm_skoid, "queue_count", CTLFLAG_RD,
	    &mgr->ipfm_q_count);
	skoid_add_handler(&mgr->ipfm_skoid, "drain", CTLFLAG_RW,
	    ipfq_drain_sysctl, mgr, 0);

	return mgr;
}

/* Free a flowswitch IP fragment manager. */
void
fsw_ip_frag_mgr_destroy(struct fsw_ip_frag_mgr *mgr)
{
	thread_call_t tcall;

	lck_mtx_lock(&mgr->ipfm_lock);
	if ((tcall = mgr->ipfm_timeout_tcall) != NULL) {
		lck_mtx_unlock(&mgr->ipfm_lock);
		(void) thread_call_cancel_wait(tcall);
		(void) thread_call_free(tcall);
		mgr->ipfm_timeout_tcall = NULL;
		lck_mtx_lock(&mgr->ipfm_lock);
	}

	ipfq_drain(mgr);

	lck_mtx_unlock(&mgr->ipfm_lock);
	lck_mtx_destroy(&mgr->ipfm_lock, &fsw_ipfm_lock_group);

	skoid_destroy(&mgr->ipfm_skoid);
	sk_free_type(struct fsw_ip_frag_mgr, mgr);
}

/*
 * Reassemble a received IPv4 fragment.
 *
 * @param mgr
 *   fragment manager
 * @param pkt
 *   received packet (must have ipv4 header validated)
 * @param ip4
 *   pointer to the packet's IPv4 header
 * @param nfrags
 *   number of fragments reassembled
 * @return
 *   Successfully processed (not fully reassembled)
 *     ret = 0, *pkt = NULL(ipfm owns it), *nfrags=0
 *   Successfully reassembled
 *     ret = 0, *pkt = 1st fragment(fragments chained in ordrer by pkt_nextpkt)
 *     *nfrags = number of all fragments (>0)
 *   Error
 *     ret != 0 && *pkt unmodified (caller to decide what to do with *pkt)
 *     *nfrags = 0
 */
int
fsw_ip_frag_reass_v4(struct fsw_ip_frag_mgr *mgr, struct __kern_packet **pkt,
    struct ip *ip4, uint16_t *nfrags, uint16_t *tlen)
{
	struct ipf_key key;
	uint16_t unfragpartlen, offflag, fragoff, fragpartlen, fragflag;
	int err;

	STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_V4);

	bcopy((void *)&ip4->ip_src, (void *)key.ipfk_addr, IPFK_LEN_V4);
	key.ipfk_len = IPFK_LEN_V4;
	key.ipfk_ident = (uint32_t)ip4->ip_id;

	unfragpartlen = (uint16_t)(ip4->ip_hl << 2);
	offflag = ntohs(ip4->ip_off);
	fragoff = (uint16_t)(offflag << 3);
	fragpartlen = ntohs(ip4->ip_len) - (uint16_t)(ip4->ip_hl << 2);
	fragflag = offflag & IP_MF;

	err = ipf_process(mgr, pkt, &key, unfragpartlen, fragoff, fragpartlen,
	    fragflag, nfrags, tlen);

	/*
	 * If packet has been reassembled compute the user data length.
	 */
	if (*pkt != NULL) {
		struct __kern_packet *p = *pkt;
		struct ip *iph = (struct ip *)p->pkt_flow_ip_hdr;

		p->pkt_flow_ulen = ntohs(iph->ip_len) -
		    p->pkt_flow_ip_hlen - p->pkt_flow->flow_l4._l4_hlen;
	}
	return err;
}

/*
 * Reassemble a received IPv6 fragment.
 *
 * @param mgr
 *   fragment manager
 * @param pkt
 *   received packet (must have ipv6 header validated)
 * @param ip6
 *   pointer to the packet's IPv6 header
 * @param ip6f
 *   pointer to the packet's IPv6 Fragment Header
 * @param nfrags
 *   number of fragments reassembled
 * @return
 *   Successfully processed (not fully reassembled)
 *     ret = 0, *pkt = NULL(ipfm owns it), *nfrags=0
 *   Successfully reassembled
 *     ret = 0, *pkt = 1st fragment(fragments chained in ordrer by pkt_nextpkt)
 *     *nfrags = number of all fragments (>0)
 *   Error
 *     ret != 0 && *pkt unmodified (caller to decide what to do with *pkt)
 *     *nfrags = 0
 */
int
fsw_ip_frag_reass_v6(struct fsw_ip_frag_mgr *mgr, struct __kern_packet **pkt,
    struct ip6_hdr *ip6, struct ip6_frag *ip6f, uint16_t *nfrags,
    uint16_t *tlen)
{
	struct ipf_key key;
	ptrdiff_t ip6f_ptroff = (uintptr_t)ip6f - (uintptr_t)ip6;
	uint16_t ip6f_off, fragoff, fragpartlen, unfragpartlen, fragflag;
	int err;

	STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_V6);

	/* jumbo payload can't contain a fragment header */
	if (ip6->ip6_plen == 0) {
		*nfrags = 0;
		return ERANGE;
	}

	ASSERT(ip6f_ptroff < UINT16_MAX);
	ip6f_off = (uint16_t)ip6f_ptroff;
	fragoff = ntohs(ip6f->ip6f_offlg & IP6F_OFF_MASK);
	fragpartlen = ntohs(ip6->ip6_plen) -
	    (ip6f_off + sizeof(struct ip6_frag) - sizeof(struct ip6_hdr));
	unfragpartlen = ip6f_off;
	fragflag = ip6f->ip6f_offlg & IP6F_MORE_FRAG;

	/*
	 * RFC 6946: Handle "atomic" fragments (offset and m bit set to 0)
	 * upfront, unrelated to any reassembly.
	 *
	 * Flow classifier should process those as non-frag, ipfm shouldn't see
	 * them.
	 */
	ASSERT((ip6f->ip6f_offlg & ~IP6F_RESERVED_MASK) != 0);

	bcopy((void *)&ip6->ip6_src, (void *)key.ipfk_addr, IPFK_LEN_V6);
	key.ipfk_len = IPFK_LEN_V6;
	key.ipfk_ident = ip6f->ip6f_ident;

	err = ipf_process(mgr, pkt, &key, unfragpartlen, fragoff, fragpartlen,
	    fragflag, nfrags, tlen);

	/*
	 * If packet has been reassembled compute the user data length.
	 */
	if (*pkt != NULL) {
		struct __kern_packet *p = *pkt;
		struct ip6_hdr *ip6h = (struct ip6_hdr *)p->pkt_flow_ip_hdr;

		p->pkt_flow_ulen = ntohs(ip6h->ip6_plen) -
		    p->pkt_flow->flow_l4._l4_hlen;
	}
	return err;
}

static struct mbuf *
ipf_pkt2mbuf(struct fsw_ip_frag_mgr *mgr, struct __kern_packet *pkt)
{
	unsigned int one = 1;
	struct mbuf *m = NULL;
	uint8_t *buf;
	struct ip6_hdr *ip6;
	uint32_t l3t_len;
	int err;

	l3t_len = pkt->pkt_length - pkt->pkt_l2_len;
	if (pkt->pkt_link_flags & PKT_LINKF_ETHFCS) {
		l3t_len -= ETHER_CRC_LEN;
	}

	err = mbuf_allocpacket(MBUF_WAITOK, l3t_len, &one, &m);
	VERIFY(err == 0);
	ASSERT(l3t_len <= mbuf_maxlen(m));

	if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
		bcopy(pkt->pkt_mbuf->m_data + pkt->pkt_l2_len,
		    m->m_data, l3t_len);
	} else {
		MD_BUFLET_ADDR_ABS(pkt, buf);
		buf += (pkt->pkt_headroom + pkt->pkt_l2_len);
		bcopy(buf, m->m_data, l3t_len);
	}
	m->m_pkthdr.len = m->m_len = l3t_len;

	ip6 = mtod(m, struct ip6_hdr *);
	/* note for casting: IN6_IS_SCOPE_ doesn't need alignment */
	if (IN6_IS_SCOPE_LINKLOCAL((struct in6_addr *)(uintptr_t)&ip6->ip6_src)) {
		if (in6_embedded_scope) {
			ip6->ip6_src.s6_addr16[1] = htons(mgr->ipfm_ifp->if_index);
		}
		ip6_output_setsrcifscope(m, mgr->ipfm_ifp->if_index, NULL);
	}
	if (IN6_IS_SCOPE_EMBED((struct in6_addr *)(uintptr_t)&ip6->ip6_dst)) {
		if (in6_embedded_scope) {
			ip6->ip6_dst.s6_addr16[1] = htons(mgr->ipfm_ifp->if_index);
		}
		ip6_output_setdstifscope(m, mgr->ipfm_ifp->if_index, NULL);
	}

	return m;
}

/*
 * Since this function can be called while holding fsw_ip_frag_mgr.ipfm_lock,
 * we need to ensure we don't enter the driver directly because a deadlock
 * can happen if this same thread tries to get the workloop lock.
 */
static void
ipf_icmp6_error_flag(struct mbuf *m, int type, int code, int param, int flags)
{
	sk_protect_t protect = sk_async_transmit_protect();
	icmp6_error_flag(m, type, code, param, flags);
	sk_async_transmit_unprotect(protect);
}

/*
 * @internal IP fragment ICMP parameter problem error handling
 *
 * @param param
 *   offending parameter offset, only applicable to ICMPv6
 */
void
ipf_icmp_param_err(struct fsw_ip_frag_mgr *mgr, struct __kern_packet *pkt,
    int param_offset)
{
	if (pkt->pkt_flow_ip_ver != IPV6_VERSION) {
		return;
	}

	struct mbuf *m = NULL;
	m = ipf_pkt2mbuf(mgr, pkt);
	if (__probable(m != NULL)) {
		ipf_icmp6_error_flag(m, ICMP6_PARAM_PROB, ICMP6_PARAMPROB_HEADER,
		    param_offset, 0);
	}

	/* m would be free by icmp6_error_flag function */
}

/* @internal IP fragment ICMP timeout error handling */
void
ipf_icmp_timeout_err(struct fsw_ip_frag_mgr *mgr, struct ipf *f)
{
	struct __kern_packet *pkt = f->ipf_pkt;
	ASSERT(pkt != NULL);

	/* no icmp error packet for ipv4 */
	if (pkt->pkt_flow_ip_ver != IPV6_VERSION) {
		return;
	}

	/* only for the first fragment */
	if (f->ipf_off != 0) {
		return;
	}

	struct mbuf *m = NULL;
	m = ipf_pkt2mbuf(mgr, pkt);
	if (__probable(m != NULL)) {
		ipf_icmp6_error_flag(m, ICMP6_TIME_EXCEEDED,
		    ICMP6_TIME_EXCEED_REASSEMBLY, 0, 0);
	}

	/* m would be free by icmp6_error_flag function */
}

/* @internal IP fragment processing, v4/v6 agonistic */
int
ipf_process(struct fsw_ip_frag_mgr *mgr, struct __kern_packet **pkt_ptr,
    struct ipf_key *key, uint16_t unfraglen, uint16_t fragoff,
    uint16_t fragpartlen, uint16_t fragflag, uint16_t *nfrags, uint16_t *tlen)
{
	struct __kern_packet *pkt = *pkt_ptr;
	struct __kern_packet *pkt_reassed = NULL;
	struct ipfq *q, *mq = &mgr->ipfm_q;
	struct ipf *f, *f_new, *f_down;
	uint32_t nfrags_freed;
	int next;
	int first_frag = 0;
	int err = 0;

	*nfrags = 0;

	SK_DF(SK_VERB_IP_FRAG, "id %5d  fragoff %5d  fragpartlen %5d  "
	    "fragflag 0x%x", key->ipfk_ident, fragoff, fragpartlen, fragflag);

	/*
	 * Make sure that all fragments except last one have a data length
	 * that's a non-zero multiple of 8 bytes.
	 */
	if (fragflag && (fragpartlen == 0 || (fragpartlen & 0x7) != 0)) {
		SK_DF(SK_VERB_IP_FRAG, "frag not multiple of 8 bytes");
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_DROP_BAD_LEN);
		ipf_icmp_param_err(mgr, pkt,
		    offsetof(struct ip6_hdr, ip6_plen));
		return ERANGE;
	}

	lck_mtx_lock(&mgr->ipfm_lock);

	/* find ipfq */
	for (q = mq->ipfq_next; q != mq; q = q->ipfq_next) {
		if (ipf_key_cmp(key, &q->ipfq_key) == 0) {
			if (q->ipfq_is_dirty) {
				SK_DF(SK_VERB_IP_FRAG, "found dirty q, skip");
				err = EINVAL;
				goto done;
			}
			break;
		}
	}

	/* not found, create new ipfq */
	if (q == mq) {
		first_frag = 1;

		q = ipfq_alloc(mgr, M_DONTWAIT);
		if (q == NULL) {
			STATS_INC(mgr->ipfm_stats,
			    FSW_STATS_RX_FRAG_DROP_NOMEM);
			err = ENOMEM;
			goto done;
		}

		ipfq_insque(q, mq);
		net_update_uptime();

		bcopy(key, &q->ipfq_key, sizeof(struct ipf_key));
		q->ipfq_down = q->ipfq_up = (struct ipf *)q;
		q->ipfq_unfraglen = 0;
		q->ipfq_nfrag = 0;
		q->ipfq_timestamp = _net_uptime;
	}

	ASSERT(!q->ipfq_is_dirty);

	/* this queue has reached per queue frag limit */
	if (q->ipfq_nfrag > ipfm_max_frags_per_queue) {
		nfrags_freed = ipfq_freefq(mgr, q, NULL);
		STATS_ADD(mgr->ipfm_stats,
		    FSW_STATS_RX_FRAG_DROP_PER_QUEUE_LIMIT, nfrags_freed);
		err = ENOMEM;
		goto done;
	}

	/*
	 * If it's the 1st fragment, record the length of the
	 * unfragmentable part and the next header of the fragment header.
	 */
	if (fragoff == 0) {
		q->ipfq_unfraglen = unfraglen;
	}

	/* Check that the reassembled packet would not exceed 65535 bytes. */
	if (q->ipfq_unfraglen + fragoff + fragpartlen > IP_MAXPACKET) {
		SK_DF(SK_VERB_IP_FRAG, "frag too big");
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_BAD);
		ipf_icmp_param_err(mgr, pkt, sizeof(struct ip6_hdr) +
		    offsetof(struct ip6_frag, ip6f_offlg));
		err = ERANGE;
		goto done;
	}

	/*
	 * If it's the 1st fragment, do the above check for each
	 * fragment already stored in the reassembly queue.
	 * If an error is found, still return 0, since we don't return
	 * ownership of a chain of offending packets back to caller.
	 */
	if (fragoff == 0) {
		for (f = q->ipfq_down; f != (struct ipf *)q; f = f_down) {
			f_down = f->ipf_down;
			if (q->ipfq_unfraglen + f->ipf_off + f->ipf_len >
			    IP_MAXPACKET) {
				SK_DF(SK_VERB_IP_FRAG, "frag too big");
				STATS_INC(mgr->ipfm_stats,
				    FSW_STATS_RX_FRAG_BAD);
				ipf_deq(f);
				ipf_free_pkt(f);
				ipf_free(mgr, f);
			}
		}
	}

	f_new = ipf_alloc(mgr);
	if (f_new == NULL) {
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_DROP_NOMEM);
		err = ENOMEM;
		goto done;
	}

	f_new->ipf_mff = fragflag;
	f_new->ipf_off = fragoff;
	f_new->ipf_len = fragpartlen;
	f_new->ipf_pkt = pkt;

	if (first_frag) {
		f = (struct ipf *)q;
		goto insert;
	}

	/* Find a segment which begins after this one does. */
	for (f = q->ipfq_down; f != (struct ipf *)q; f = f->ipf_down) {
		if (f->ipf_off > f_new->ipf_off) {
			break;
		}
	}

	/*
	 * If any of the fragments being reassembled overlap with any
	 * other fragments being reassembled for the same packet,
	 * reassembly of that packet must be abandoned and all the
	 * fragments that have been received for that packet must be
	 * discarded, and no ICMP error messages should be sent.
	 *
	 * It should be noted that fragments may be duplicated in the
	 * network.  Instead of treating these exact duplicate fragments
	 * as overlapping fragments, an implementation may choose to
	 * detect this case and drop exact duplicate fragments while
	 * keeping the other fragments belonging to the same packet.
	 *
	 * https://tools.ietf.org/html/rfc8200#appendix-B
	 *
	 * We apply this rule for both for IPv4 and IPv6 here.
	 */
	if (((f->ipf_up != (struct ipf *)q) &&  /* prev frag spans into f_new */
	    (f->ipf_up->ipf_off + f->ipf_up->ipf_len - f_new->ipf_off > 0)) ||
	    ((f != (struct ipf *)q) &&  /* f_new spans into next */
	    (f_new->ipf_off + f_new->ipf_len - f->ipf_off > 0))) {
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_BAD);
		/* Check for exact duplicate offset/length */
		if (((f->ipf_up != (struct ipf *)q) &&
		    ((f->ipf_up->ipf_off != f_new->ipf_off) ||
		    (f->ipf_up->ipf_len != f_new->ipf_len))) ||
		    ((f != (struct ipf *)q) &&
		    ((f->ipf_off != f_new->ipf_off) ||
		    (f->ipf_len != f_new->ipf_len)))) {
			SK_DF(SK_VERB_IP_FRAG, "frag overlap");
			ipf_free(mgr, f_new);
			/* give up over-lapping fragments queue */
			SK_DF(SK_VERB_IP_FRAG, "free overlapping queue");
			ipfq_freef(mgr, q, NULL);
			q->ipfq_is_dirty = true;
		} else {
			ipf_free(mgr, f_new);
			SK_DF(SK_VERB_IP_FRAG, "frag dup");
		}
		err = ERANGE;
		goto done;
	}

insert:
	/*
	 * Stick new segment in its place;
	 * check for complete reassembly.
	 * Move to front of packet queue, as we are
	 * the most recently active fragmented packet.
	 */
	ipf_enq(f_new, f->ipf_up);
	q->ipfq_nfrag++;
	next = 0;
	for (f = q->ipfq_down; f != (struct ipf *)q; f = f->ipf_down) {
		/* there is a hole */
		if (f->ipf_off != next) {
			goto done;
		}
		next += f->ipf_len;
	}
	/* we haven't got last frag yet */
	if (f->ipf_up->ipf_mff) {
		goto done;
	}

	/*
	 * Reassembly is complete; concatenate fragments.
	 */
	f = q->ipfq_down;
	f_down = f->ipf_down;
	pkt_reassed = f->ipf_pkt;
	*nfrags = 1;
	while (f_down != (struct ipf *)q) {
		/* chain __kern_packet with pkt_nextpkt ptr */
		f->ipf_pkt->pkt_nextpkt = f_down->ipf_pkt;
		(*nfrags)++;
		(*tlen) += f_down->ipf_len;
		f_down = f->ipf_down;
		ipf_deq(f);
		ipf_free(mgr, f);
		f = f_down;
		f_down = f->ipf_down;
	}
	ipf_free(mgr, f);

	err = 0;
	STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_REASSED);
	ipfq_remque(q);
	ipfq_free(mgr, q);

done:
	/* ipfm take ownership of, or return assembled packet, if no error */
	if (err == 0) {
		/* reass'ed packet if done; NULL otherwise */
		*pkt_ptr = pkt_reassed;
	}
	ipfq_sched_timeout(mgr, FALSE);
	lck_mtx_unlock(&mgr->ipfm_lock);
	return err;
}

static int
ipf_key_cmp(struct ipf_key *a, struct ipf_key *b)
{
	int d;

	if ((d = (a->ipfk_len - b->ipfk_len)) != 0) {
		return d;
	}

	if ((d = (a->ipfk_ident - b->ipfk_ident)) != 0) {
		return d;
	}

	return memcmp(a->ipfk_addr, b->ipfk_addr, a->ipfk_len);
}

/*
 * Put an ip fragment on a reassembly chain.
 * Like insque, but pointers in middle of structure.
 */
static void
ipf_enq(struct ipf *f, struct ipf *up6)
{
	f->ipf_up = up6;
	f->ipf_down = up6->ipf_down;
	up6->ipf_down->ipf_up = f;
	up6->ipf_down = f;
}

/*
 * To ipf_enq as remque is to insque.
 */
static void
ipf_deq(struct ipf *f)
{
	f->ipf_up->ipf_down = f->ipf_down;
	f->ipf_down->ipf_up = f->ipf_up;
}

static void
ipfq_insque(struct ipfq *new, struct ipfq *old)
{
	new->ipfq_prev = old;
	new->ipfq_next = old->ipfq_next;
	old->ipfq_next->ipfq_prev = new;
	old->ipfq_next = new;
}

static void
ipfq_remque(struct ipfq *p6)
{
	p6->ipfq_prev->ipfq_next = p6->ipfq_next;
	p6->ipfq_next->ipfq_prev = p6->ipfq_prev;
}

static void
ipfq_timeout(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	struct fsw_ip_frag_mgr *mgr = arg0;
	struct ipfq *q;
	uint64_t now, elapsed;
	uint32_t nfreed = 0;

	net_update_uptime();
	now = _net_uptime;

	SK_DF(SK_VERB_IP_FRAG, "run");
	lck_mtx_lock(&mgr->ipfm_lock);
	q = mgr->ipfm_q.ipfq_next;
	if (q) {
		while (q != &mgr->ipfm_q) {
			q = q->ipfq_next;
			elapsed = now - q->ipfq_prev->ipfq_timestamp;
			if (elapsed > ipfm_frag_ttl) {
				SK_DF(SK_VERB_IP_FRAG, "timing out q id %5d",
				    q->ipfq_prev->ipfq_key.ipfk_ident);
				nfreed = ipfq_freefq(mgr, q->ipfq_prev,
				    q->ipfq_is_dirty ? NULL :
				    ipf_icmp_timeout_err);
			}
		}
	}

	/* If running out of resources, drain ipfm queues (oldest one first) */
	if (mgr->ipfm_f_count >= mgr->ipfm_f_limit ||
	    mgr->ipfm_q_count >= mgr->ipfm_q_limit) {
		SK_DF(SK_VERB_IP_FRAG, "draining (frag %d/%d queue %d/%d)",
		    mgr->ipfm_f_count, mgr->ipfm_f_limit, mgr->ipfm_q_count,
		    mgr->ipfm_q_limit);
		uint32_t target_q_count = mgr->ipfm_q_count / 2;
		while (mgr->ipfm_q_count > target_q_count) {
			nfreed += ipfq_freefq(mgr, mgr->ipfm_q.ipfq_prev,
			    q->ipfq_is_dirty ? NULL : ipf_icmp_timeout_err);
		}
	}

	STATS_ADD(mgr->ipfm_stats, FSW_STATS_RX_FRAG_DROP_TIMEOUT, nfreed);

	/* re-arm the purge timer if there's work to do */
	if (mgr->ipfm_q_count > 0) {
		ipfq_sched_timeout(mgr, TRUE);
	}
	lck_mtx_unlock(&mgr->ipfm_lock);
}

static void
ipfq_sched_timeout(struct fsw_ip_frag_mgr *mgr, boolean_t in_tcall)
{
	uint32_t delay = MAX(1, ipfm_timeout_tcall_ival);       /* seconds */
	thread_call_t tcall = mgr->ipfm_timeout_tcall;
	uint64_t now = mach_absolute_time();
	uint64_t ival, deadline = now;

	LCK_MTX_ASSERT(&mgr->ipfm_lock, LCK_MTX_ASSERT_OWNED);

	ASSERT(tcall != NULL);
	if (mgr->ipfm_q_count > 0 &&
	    (!thread_call_isactive(tcall) || in_tcall)) {
		nanoseconds_to_absolutetime(delay * NSEC_PER_SEC, &ival);
		clock_deadline_for_periodic_event(ival, now, &deadline);
		(void) thread_call_enter_delayed(tcall, deadline);
	}
}

/*
 * @internal drain all ressambly queue for shutdown.
 *
 * @discussion Shutdown is called when if_detach happens, so no time exceeded
 * icmp error are generated here.
 */
static void
ipfq_drain(struct fsw_ip_frag_mgr *mgr)
{
	LCK_MTX_ASSERT(&mgr->ipfm_lock, LCK_MTX_ASSERT_OWNED);
	while (mgr->ipfm_q.ipfq_next != &mgr->ipfm_q) {
		ipfq_freefq(mgr, mgr->ipfm_q.ipfq_next, NULL);
	}
}

static int
ipfq_drain_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	struct fsw_ip_frag_mgr *mgr = arg1;

	SKOID_PROC_CALL_GUARD;

	lck_mtx_lock(&mgr->ipfm_lock);
	ipfq_drain(mgr);
	lck_mtx_unlock(&mgr->ipfm_lock);

	return 0;
}

static struct ipfq *
ipfq_alloc(struct fsw_ip_frag_mgr *mgr, int how)
{
	struct mbuf *t;
	struct ipfq *q;

	if (mgr->ipfm_q_count > mgr->ipfm_q_limit) {
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_DROP_QUEUE_LIMIT);
		return NULL;
	}

	t = m_get(how, MT_FTABLE);
	if (t != NULL) {
		mgr->ipfm_q_count++;
		q = mtod(t, struct ipfq *);
		bzero(q, sizeof(*q));
		q->ipfq_is_dirty = false;
	} else {
		q = NULL;
	}
	return q;
}

/* free q */
static void
ipfq_free(struct fsw_ip_frag_mgr *mgr, struct ipfq *q)
{
	(void) m_free(dtom(q));
	mgr->ipfm_q_count--;
}

/*
 * Free all fragments, keep q.
 * @return: number of frags freed
 */
static uint32_t
ipfq_freef(struct fsw_ip_frag_mgr *mgr, struct ipfq *q,
    void (*ipf_cb)(struct fsw_ip_frag_mgr *, struct ipf *))
{
	struct ipf *f, *down6;
	uint32_t nfrags = 0;

	for (f = q->ipfq_down; f != (struct ipf *)q; f = down6) {
		nfrags++;
		down6 = f->ipf_down;
		ipf_deq(f);
		if (ipf_cb != NULL) {
			(*ipf_cb)(mgr, f);
		}
		ipf_free_pkt(f);
		ipf_free(mgr, f);
	}

	return nfrags;
}

/* Free both all fragments and q
 * @return: number of frags freed
 */
static uint32_t
ipfq_freefq(struct fsw_ip_frag_mgr *mgr, struct ipfq *q,
    void (*ipf_cb)(struct fsw_ip_frag_mgr *, struct ipf *))
{
	uint32_t freed_count;
	freed_count = ipfq_freef(mgr, q, ipf_cb);
	ipfq_remque(q);
	ipfq_free(mgr, q);
	return freed_count;
}

static struct ipf *
ipf_alloc(struct fsw_ip_frag_mgr *mgr)
{
	struct mbuf *t;
	struct ipf *f;

	if (mgr->ipfm_f_count > mgr->ipfm_f_limit) {
		STATS_INC(mgr->ipfm_stats, FSW_STATS_RX_FRAG_DROP_FRAG_LIMIT);
		return NULL;
	}

	t = m_get(M_DONTWAIT, MT_FTABLE);
	if (t != NULL) {
		mgr->ipfm_f_count++;
		f = mtod(t, struct ipf *);
		bzero(f, sizeof(*f));
	} else {
		f = NULL;
	}
	return f;
}

static void
ipf_free_pkt(struct ipf *f)
{
	struct __kern_packet *pkt = f->ipf_pkt;
	ASSERT(pkt != NULL);
	pp_free_packet(__DECONST(struct kern_pbufpool *, pkt->pkt_qum.qum_pp),
	    SK_PTR_ADDR(pkt));
}

static void
ipf_free(struct fsw_ip_frag_mgr *mgr, struct ipf *f)
{
	(void) m_free(dtom(f));
	mgr->ipfm_f_count--;
}
