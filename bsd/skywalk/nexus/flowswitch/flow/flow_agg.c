/*
 * Copyright (c) 2019-2022 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/netif/nx_netif_compat.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/pktap.h>
#include <sys/sdt.h>

#define MAX_BUFLET_COUNT        (64)
#define TCP_FLAGS_IGNORE        (TH_FIN|TH_SYN|TH_RST|TH_URG)
#define PKT_IS_MBUF(_pkt)       (_pkt->pkt_pflags & PKT_F_MBUF_DATA)
#define PKT_IS_TRUNC_MBUF(_pkt) (PKT_IS_MBUF(_pkt) &&           \
	                        (_pkt->pkt_pflags & PKT_F_TRUNCATED))

/*
 * This structure holds per-super object (mbuf/packet) flow aggregation states.
 */
struct flow_agg {
	union {
		struct {
			union {
				void *          _fa_sobj;
				struct mbuf *   _fa_smbuf;      /* super mbuf */
				struct __kern_packet *_fa_spkt; /* super pkt */
			};
			uint8_t *_fa_sptr;        /* ptr to super IP header */
			bool     _fa_sobj_is_pkt; /* super obj is pkt or mbuf */
			/*
			 * super obj is not large enough to hold the IP & TCP
			 * header in a contiguous buffer.
			 */
			bool     _fa_sobj_is_short;
			uint32_t _fa_tcp_seq;     /* expected next sequence # */
			uint32_t _fa_ulen;        /* expected next ulen */
			uint32_t _fa_total;       /* total aggregated bytes */
		} __flow_agg;
		uint64_t __flow_agg_data[4];
	};
#define fa_sobj           __flow_agg._fa_sobj
#define fa_smbuf          __flow_agg._fa_smbuf
#define fa_spkt           __flow_agg._fa_spkt
#define fa_sptr           __flow_agg._fa_sptr
#define fa_sobj_is_pkt    __flow_agg._fa_sobj_is_pkt
#define fa_sobj_is_short  __flow_agg._fa_sobj_is_short
#define fa_tcp_seq        __flow_agg._fa_tcp_seq
#define fa_ulen           __flow_agg._fa_ulen
#define fa_total          __flow_agg._fa_total
};

#define FLOW_AGG_CLEAR(_fa) do {                                        \
	_CASSERT(sizeof(struct flow_agg) == 32);                        \
	sk_zero_32(_fa);                                                \
} while (0)

#define MASK_SIZE       80      /* size of struct {ip,ip6}_tcp_mask */

struct ip_tcp_mask {
	struct ip       ip_m;
	struct tcphdr   tcp_m;
	uint32_t        tcp_option_m[MAX_TCPOPTLEN / sizeof(uint32_t)];
};

static const struct ip_tcp_mask ip_tcp_mask
__sk_aligned(16) =
{
	.ip_m = {
		.ip_hl = 0xf,
		.ip_v = 0xf,
		.ip_tos = 0xff,
		/* Not checked; aggregated packet's ip_len is increasing */
		.ip_len = 0,
		.ip_id = 0,
		.ip_off = 0xffff,
		.ip_ttl = 0xff,
		.ip_p = 0xff,
		.ip_sum = 0,
		.ip_src.s_addr = 0xffffffff,
		.ip_dst.s_addr = 0xffffffff,
	},
	.tcp_m = {
		.th_sport = 0xffff,
		.th_dport = 0xffff,
		.th_seq = 0,
		.th_ack = 0xffffffff,
		.th_x2 = 0xf,
		.th_off = 0xf,
		.th_flags = ~TH_PUSH,
		.th_win = 0xffff,
		.th_sum = 0,
		.th_urp = 0xffff,
	},
	.tcp_option_m = {
		/* Max 40 bytes of TCP options */
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
		0,      /* Filling up to MASK_SIZE */
	},
};

struct ip6_tcp_mask {
	struct ip6_hdr  ip6_m;
	struct tcphdr   tcp_m;
	uint32_t        tcp_option_m[5]; /* 5 bytes to fill up to MASK_SIZE */
};

static const struct ip6_tcp_mask ip6_tcp_mask
__sk_aligned(16) =
{
	.ip6_m = {
		.ip6_ctlun.ip6_un1.ip6_un1_flow = 0xffffffff,
		/* Not checked; aggregated packet's ip_len is increasing */
		.ip6_ctlun.ip6_un1.ip6_un1_plen = 0,
		.ip6_ctlun.ip6_un1.ip6_un1_nxt = 0xff,
		.ip6_ctlun.ip6_un1.ip6_un1_hlim = 0xff,
		.ip6_src.__u6_addr.__u6_addr32[0] = 0xffffff,
		.ip6_src.__u6_addr.__u6_addr32[1] = 0xffffff,
		.ip6_src.__u6_addr.__u6_addr32[2] = 0xffffff,
		.ip6_src.__u6_addr.__u6_addr32[3] = 0xffffff,
		.ip6_dst.__u6_addr.__u6_addr32[0] = 0xffffff,
		.ip6_dst.__u6_addr.__u6_addr32[1] = 0xffffff,
		.ip6_dst.__u6_addr.__u6_addr32[2] = 0xffffff,
		.ip6_dst.__u6_addr.__u6_addr32[3] = 0xffffff,
	},
	.tcp_m = {
		.th_sport = 0xffff,
		.th_dport = 0xffff,
		.th_seq = 0,
		.th_ack = 0xffffffff,
		.th_x2 = 0xf,
		.th_off = 0xf,
		.th_flags = ~TH_PUSH,
		.th_win = 0xffff,
		.th_sum = 0,
		.th_urp = 0xffff,
	},
	.tcp_option_m = {
		/* Max 40 bytes of TCP options */
		0xffffffff,
		0xffffffff,
		0xffffffff,
		0,          /* Filling up to MASK_SIZE */
		0,          /* Filling up to MASK_SIZE */
	},
};


#if SK_LOG
SK_LOG_ATTRIBUTE
static void
_pkt_agg_log(struct __kern_packet *pkt, struct proc *p, bool is_input)
{
	SK_LOG_VAR(uint64_t logflags = ((SK_VERB_FSW | SK_VERB_RX) |
	    (PKT_IS_MBUF(pkt) ? SK_VERB_COPY_MBUF : SK_VERB_COPY)));

	kern_packet_t ph = SK_PKT2PH(pkt);
	uint64_t bufcnt = 1;
	if (!is_input) {
		bufcnt = kern_packet_get_buflet_count(ph);
	}

	SK_DF(logflags, "%s(%d) %spkt 0x%llx plen %u",
	    sk_proc_name_address(p), sk_proc_pid(p), is_input ? "s":"d",
	    SK_KVA(pkt), pkt->pkt_length);

	SK_DF(logflags, "%spkt csumf/rxstart/rxval 0x%x/%u/0x%04x",
	    is_input ? "s":"d", pkt->pkt_csum_flags,
	    (uint32_t)pkt->pkt_csum_rx_start_off,
	    (uint32_t)pkt->pkt_csum_rx_value);

	if (!is_input) {
		kern_buflet_t buf = kern_packet_get_next_buflet(ph, NULL);

		/* Individual buflets */
		for (uint64_t i = 0; i < bufcnt && buf != NULL; i++) {
			SK_DF(logflags | SK_VERB_DUMP, "%s",
			    sk_dump("buf", kern_buflet_get_data_address(buf),
			    pkt->pkt_length, 128, NULL, 0));
			buf = kern_packet_get_next_buflet(ph, buf);
		}
	}
}

#define pkt_agg_log(_pkt, _p, _is_input) do {                           \
	if (__improbable(sk_verbose != 0)) {                            \
	        _pkt_agg_log(_pkt, _p, _is_input);                      \
	}                                                               \
} while (0)

SK_LOG_ATTRIBUTE
static void
_mbuf_agg_log(struct mbuf *m, struct proc *p, bool is_mbuf)
{
	SK_LOG_VAR(uint64_t logflags = ((SK_VERB_FSW | SK_VERB_RX) |
	    (is_mbuf ? SK_VERB_COPY_MBUF : SK_VERB_COPY)));

	SK_DF(logflags, "%s(%d) dest mbuf 0x%llx pktlen %u",
	    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(m),
	    m->m_pkthdr.len);

	SK_DF(logflags, "dest mbuf csumf/rxstart/rxval 0x%x/%u/0x%04x",
	    m->m_pkthdr.csum_flags, (uint32_t)m->m_pkthdr.csum_rx_start,
	    (uint32_t)m->m_pkthdr.csum_rx_val);

	/* Dump the first mbuf */
	ASSERT(m->m_data != NULL);
	SK_DF(logflags | SK_VERB_DUMP, "%s", sk_dump("buf",
	    (uint8_t *)m->m_data, m->m_len, 128, NULL, 0));
}

#define mbuf_agg_log(_m, _p, _is_mbuf) do {                             \
	if (__improbable(sk_verbose != 0)) {                            \
	        _mbuf_agg_log(_m, _p, _is_mbuf);                        \
	}                                                               \
} while (0)

SK_LOG_ATTRIBUTE
static void
_mchain_agg_log(struct mbuf *m, struct proc *p, bool is_mbuf)
{
	SK_LOG_VAR(uint64_t logflags = ((SK_VERB_FSW | SK_VERB_RX) |
	    (is_mbuf ? SK_VERB_COPY_MBUF : SK_VERB_COPY)));

	while (m != NULL) {
		SK_DF(logflags, "%s(%d) dest mbuf 0x%llx pktlen %u",
		    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(m),
		    m->m_pkthdr.len);

		SK_DF(logflags, "dest mbuf csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    m->m_pkthdr.csum_flags, (uint32_t)m->m_pkthdr.csum_rx_start,
		    (uint32_t)m->m_pkthdr.csum_rx_val);

		m = m->m_nextpkt;
	}
}

#define mchain_agg_log(_m, _p, _is_mbuf) do {                           \
	if (__improbable(sk_verbose != 0)) {                            \
	        _mchain_agg_log(_m, _p, _is_mbuf);                      \
	}                                                               \
} while (0)
#else
#define pkt_agg_log(...)
#define mbuf_agg_log(...)
#define mchain_agg_log(...)
#endif /* SK_LOG */

/*
 * Checksum only for packet with mbuf.
 */
static bool
mbuf_csum(struct __kern_packet *pkt, struct mbuf *m, bool verify_l3,
    uint16_t *data_csum)
{
	ASSERT(data_csum != NULL);

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX));
	uint32_t plen = pkt->pkt_l2_len + pkt->pkt_flow_ip_hlen +
	    pkt->pkt_flow_tcp_hlen + pkt->pkt_flow_ulen;
	uint16_t l4len = plen - pkt->pkt_l2_len - pkt->pkt_flow_ip_hlen;
	uint16_t start = pkt->pkt_l2_len;
	uint32_t partial = 0;
	uint16_t csum = 0;

	ASSERT(plen == m_pktlen(m));

	/* Some compat drivers compute full checksum */
	if ((m->m_pkthdr.csum_flags & CSUM_RX_FULL_FLAGS) ==
	    CSUM_RX_FULL_FLAGS) {
		SK_DF(logflags, "HW csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    m->m_pkthdr.csum_flags, m->m_pkthdr.csum_rx_start,
		    m->m_pkthdr.csum_rx_val);

		/* Compute the data_csum */
		struct tcphdr *tcp =
		    (struct tcphdr *)(void *)(mtod(m, uint8_t *) +
		    pkt->pkt_l2_len + pkt->pkt_flow_ip_hlen);
		/* 16-bit alignment is sufficient */
		ASSERT(IS_P2ALIGNED(tcp, sizeof(uint16_t)));

		uint16_t th_sum = tcp->th_sum;
		tcp->th_sum = 0;

		partial = m_sum16(m, start + pkt->pkt_flow_ip_hlen,
		    pkt->pkt_flow_tcp_hlen);
		partial += htons(l4len + IPPROTO_TCP);
		if (pkt->pkt_flow_ip_ver == IPVERSION) {
			csum = in_pseudo(pkt->pkt_flow_ipv4_src.s_addr,
			    pkt->pkt_flow_ipv4_dst.s_addr, partial);
		} else {
			ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);
			csum = in6_pseudo(&pkt->pkt_flow_ipv6_src,
			    &pkt->pkt_flow_ipv6_dst, partial);
		}
		/* Restore the original checksum */
		tcp->th_sum = th_sum;
		th_sum = __packet_fix_sum(th_sum, csum, 0);
		*data_csum = ~th_sum & 0xffff;
		if ((m->m_pkthdr.csum_rx_val ^ 0xffff) == 0) {
			return true;
		} else {
			return false;
		}
	}
	/* Reset the csum RX flags */
	m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;
	if (verify_l3) {
		csum = m_sum16(m, start, pkt->pkt_flow_ip_hlen);
		SK_DF(logflags, "IP copy+sum %u(%u) (csum 0x%04x)",
		    start, pkt->pkt_flow_ip_hlen, csum);
		m->m_pkthdr.csum_flags |= CSUM_IP_CHECKED;
		if ((csum ^ 0xffff) != 0) {
			return false;
		} else {
			m->m_pkthdr.csum_flags |= CSUM_IP_VALID;
		}
	}
	/* Compute L4 header checksum */
	partial = m_sum16(m, start + pkt->pkt_flow_ip_hlen,
	    pkt->pkt_flow_tcp_hlen);
	/* Compute payload checksum */
	start += (pkt->pkt_flow_ip_hlen + pkt->pkt_flow_tcp_hlen);
	*data_csum = m_sum16(m, start, (plen - start));

	/* Fold in the data checksum to TCP checksum */
	partial += *data_csum;
	partial += htons(l4len + IPPROTO_TCP);
	if (pkt->pkt_flow_ip_ver == IPVERSION) {
		csum = in_pseudo(pkt->pkt_flow_ipv4_src.s_addr,
		    pkt->pkt_flow_ipv4_dst.s_addr, partial);
	} else {
		ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);
		csum = in6_pseudo(&pkt->pkt_flow_ipv6_src,
		    &pkt->pkt_flow_ipv6_dst, partial);
	}
	SK_DF(logflags, "TCP copy+sum %u(%u) (csum 0x%04x)",
	    start - pkt->pkt_flow_tcp_hlen, l4len, csum);
	// Set start to 0 for full checksum
	m->m_pkthdr.csum_rx_start = 0;
	m->m_pkthdr.csum_rx_val = csum;
	m->m_pkthdr.csum_flags |= (CSUM_DATA_VALID | CSUM_PSEUDO_HDR);
	if ((csum ^ 0xffff) != 0) {
		return false;
	}

	return true;
}

/* structure to pass an array of data buffers */
typedef struct _dbuf_array {
	union {
		struct __kern_buflet *dba_buflet[MAX_BUFLET_COUNT];
		struct mbuf *dba_mbuf[MAX_BUFLET_COUNT];
	};
	uint8_t dba_num_dbufs;
	bool dba_is_buflet;
} _dbuf_array_t;

static inline void
_copy_data_sum_dbuf(struct __kern_packet *spkt, uint16_t soff, uint16_t plen,
    uint32_t *partial_sum, boolean_t *odd_start, _dbuf_array_t *dbuf,
    boolean_t do_csum)
{
	uint8_t i = 0;
	uint16_t buf_off = 0;
	uint16_t buflet_dlim;
	uint16_t buflet_dlen;

	ASSERT(plen > 0);
	if (!dbuf->dba_is_buflet) {
		/*
		 * Assumption about a single mbuf is being asserted due to the
		 * reason that the current usage always passes one mbuf and the
		 * routine has not been tested with multiple mbufs.
		 */
		ASSERT(dbuf->dba_num_dbufs == 1);
		ASSERT((mbuf_maxlen(dbuf->dba_mbuf[0]) -
		    dbuf->dba_mbuf[0]->m_len) >= plen);
		buf_off = dbuf->dba_mbuf[0]->m_len;
	} else {
		buflet_dlim = kern_buflet_get_data_limit(dbuf->dba_buflet[0]);
		buflet_dlen = kern_buflet_get_data_length(dbuf->dba_buflet[0]);
		ASSERT(buflet_dlen < buflet_dlim);
		buf_off = buflet_dlen;
	}
	while (plen > 0) {
		uint16_t tmplen;
		uint16_t dbuf_lim;
		uint8_t *dbuf_addr;

		if (dbuf->dba_is_buflet) {
			ASSERT(i < dbuf->dba_num_dbufs);
			ASSERT(kern_buflet_get_data_offset(dbuf->dba_buflet[i])
			    == 0);
			dbuf_addr =
			    kern_buflet_get_data_address(dbuf->dba_buflet[i]);
			dbuf_lim = buflet_dlim - buf_off;
		} else {
			dbuf_addr = mtod(dbuf->dba_mbuf[i], uint8_t *);
			dbuf_lim = mbuf_maxlen(dbuf->dba_mbuf[i]) - buf_off;
		}
		dbuf_addr += buf_off;
		tmplen = min(plen, dbuf_lim);
		if (PKT_IS_TRUNC_MBUF(spkt)) {
			if (do_csum) {
				*partial_sum = m_copydata_sum(spkt->pkt_mbuf,
				    soff, tmplen, dbuf_addr, *partial_sum,
				    odd_start);
			} else {
				m_copydata(spkt->pkt_mbuf, soff, tmplen,
				    dbuf_addr);
			}
		} else {
			*partial_sum = pkt_copyaddr_sum(SK_PKT2PH(spkt),
			    soff, dbuf_addr, tmplen, do_csum, *partial_sum,
			    odd_start);
		}
		if (dbuf->dba_is_buflet) {
			VERIFY(kern_buflet_set_data_length(dbuf->dba_buflet[i],
			    tmplen + buf_off) == 0);
		} else {
			dbuf->dba_mbuf[i]->m_len += tmplen;
			dbuf->dba_mbuf[i]->m_pkthdr.len += tmplen;
		}
		soff += tmplen;
		plen -= tmplen;
		buf_off = 0;
		i++;
	}
	ASSERT(plen == 0);
}

/*
 * Copy (fill) and checksum for packet.
 * spkt: source IP packet.
 * plen: length of data in spkt (IP hdr + TCP hdr + TCP payload).
 * verify_l3: verify IPv4 header checksum.
 * currm: destination mbuf.
 * currp: destination skywalk packet.
 * dbuf: additional destination data buffer(s), used when current destination
 * packet is out of space.
 * added: amount of data copied from spkt to the additional buffer.
 * data_sum: 16-bit folded partial checksum of the copied TCP payload.
 */
static bool
copy_pkt_csum_packed(struct __kern_packet *spkt, uint32_t plen,
    _dbuf_array_t *dbuf, bool verify_l3, struct mbuf *currm,
    struct __kern_buflet *currp, uint16_t *data_csum, int *added)
{
	ASSERT(data_csum != NULL);

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX |
	    SK_VERB_COPY));

	uint16_t start = 0, csum = 0;
	uint32_t len = 0;
	uint32_t l4len;
	/* soff is only used for packets */
	uint16_t soff = spkt->pkt_headroom + spkt->pkt_l2_len;
	uint32_t data_partial = 0, partial = 0;
	int32_t curr_oldlen;
	uint32_t curr_trailing;
	char *curr_ptr;
	int32_t curr_len;
	uint16_t data_off;
	uint32_t tmplen;
	boolean_t odd_start = FALSE;
	bool verify_l4;

	/* One of them must be != NULL, but they can't be both set */
	VERIFY((currm != NULL || currp != NULL) &&
	    ((currm != NULL) != (currp != NULL)));

	if (currm != NULL) {
		curr_oldlen = currm->m_len;
		curr_trailing = (uint32_t)M_TRAILINGSPACE(currm);
		curr_ptr = mtod(currm, char *) + currm->m_len;
		curr_len = currm->m_len;
	} else {
		curr_oldlen = currp->buf_dlen;
		curr_trailing = currp->buf_dlim - currp->buf_doff -
		    currp->buf_dlen;
		curr_ptr = (char *)(currp->buf_addr + currp->buf_doff +
		    currp->buf_dlen);
		curr_len = currp->buf_dlen;
	}

	/* Verify checksum only for IPv4 */
	len = spkt->pkt_flow_ip_hlen;
	verify_l3 = (verify_l3 && !PACKET_HAS_VALID_IP_CSUM(spkt));
	if (verify_l3) {
		if (PKT_IS_TRUNC_MBUF(spkt)) {
			partial = os_cpu_in_cksum_mbuf(spkt->pkt_mbuf,
			    len, 0, 0);
		} else {
			partial = pkt_sum(SK_PKT2PH(spkt), soff, len);
		}

		csum = __packet_fold_sum(partial);
		SK_DF(logflags, "IP copy+sum %u(%u) (csum 0x%04x)", 0,
		    len, csum);
		spkt->pkt_csum_flags |= PACKET_CSUM_IP_CHECKED;
		if ((csum ^ 0xffff) != 0) {
			/* No need to copy & checkum TCP+payload */
			return false;
		} else {
			spkt->pkt_csum_flags |= PACKET_CSUM_IP_VALID;
		}
	}

	verify_l4 = ((spkt->pkt_csum_flags & PACKET_CSUM_RX_FULL_FLAGS) !=
	    PACKET_CSUM_RX_FULL_FLAGS);

	/* Copy & verify TCP checksum */
	start = spkt->pkt_flow_ip_hlen + spkt->pkt_flow_tcp_hlen;
	l4len = plen - spkt->pkt_flow_ip_hlen;
	len = plen - start;
	if (PKT_IS_TRUNC_MBUF(spkt)) {
		tmplen = min(len, curr_trailing);
		odd_start = FALSE;

		/* First, simple checksum on the TCP header */
		if (verify_l4) {
			partial = os_cpu_in_cksum_mbuf(spkt->pkt_mbuf,
			    spkt->pkt_flow_tcp_hlen, spkt->pkt_flow_ip_hlen, 0);
		}

		/* Now, copy & sum the payload */
		if (tmplen > 0) {
			data_partial = m_copydata_sum(spkt->pkt_mbuf,
			    start, tmplen, curr_ptr, 0, &odd_start);
			curr_len += tmplen;
		}
		data_off = start + tmplen;
	} else {
		tmplen = min(len, curr_trailing);
		odd_start = FALSE;

		/* First, simple checksum on the TCP header */
		if (verify_l4) {
			partial = pkt_sum(SK_PKT2PH(spkt), (soff +
			    spkt->pkt_flow_ip_hlen), spkt->pkt_flow_tcp_hlen);
		}

		/* Now, copy & sum the payload */
		if (tmplen > 0) {
			data_partial = pkt_copyaddr_sum(SK_PKT2PH(spkt),
			    (soff + start), (uint8_t *)curr_ptr, tmplen,
			    true, 0, &odd_start);
			curr_len += tmplen;
		}
		data_off = soff + start + tmplen;
	}

	/* copy & sum remaining payload in additional buffers */
	if ((len - tmplen) > 0) {
		ASSERT(dbuf != NULL);
		_copy_data_sum_dbuf(spkt, data_off, (len - tmplen),
		    &data_partial, &odd_start, dbuf, true);
		*added = (len - tmplen);
	}

	/* Fold data checksum to 16 bit */
	*data_csum = __packet_fold_sum(data_partial);

	if (currm != NULL) {
		currm->m_len = curr_len;
	} else {
		currp->buf_dlen = curr_len;
	}

	if (verify_l4) {
		/* Fold in the data checksum to TCP checksum */
		partial += *data_csum;
		partial += htons(l4len + IPPROTO_TCP);
		if (spkt->pkt_flow_ip_ver == IPVERSION) {
			csum = in_pseudo(spkt->pkt_flow_ipv4_src.s_addr,
			    spkt->pkt_flow_ipv4_dst.s_addr, partial);
		} else {
			ASSERT(spkt->pkt_flow_ip_ver == IPV6_VERSION);
			csum = in6_pseudo(&spkt->pkt_flow_ipv6_src,
			    &spkt->pkt_flow_ipv6_dst, partial);
		}
		/* pkt metadata will be transfer to super packet */
		__packet_set_inet_checksum(SK_PKT2PH(spkt),
		    PACKET_CSUM_RX_FULL_FLAGS, 0, csum, false);
	} else {
		/* grab csum value from offload */
		csum = spkt->pkt_csum_rx_value;
	}

	SK_DF(logflags, "TCP copy+sum %u(%u) (csum 0x%04x)",
	    start - spkt->pkt_flow_tcp_hlen, l4len, ntohs(csum));

	if ((csum ^ 0xffff) != 0) {
		/*
		 * Revert whatever we did here!
		 * currm/currp should be restored to previous value.
		 * dbuf (for additional payload) should be restore to 0.
		 */
		if (currm != NULL) {
			currm->m_len = curr_oldlen;
		} else {
			currp->buf_dlen = curr_oldlen;
		}
		if (dbuf != NULL) {
			for (int i = 0; i < dbuf->dba_num_dbufs; i++) {
				if (dbuf->dba_is_buflet) {
					struct __kern_buflet *b = dbuf->dba_buflet[i];
					kern_buflet_set_data_length(b, 0);
					kern_buflet_set_data_offset(b, 0);
				} else {
					struct mbuf *m = dbuf->dba_mbuf[i];
					m->m_len = m->m_pkthdr.len = 0;
				}
			}
		}

		return false;
	}

	return true;
}

/*
 * Copy and checksum for packet or packet with mbuf
 * data_csum is only supported for bsd flows
 */
static bool
copy_pkt_csum(struct __kern_packet *pkt, uint32_t plen, _dbuf_array_t *dbuf,
    uint16_t *data_csum, bool verify_l3)
{
	/*
	 * To keep this routine simple and optimal, we are asserting on the
	 * assumption that the smallest flowswitch packet pool buffer should
	 * be large enough to hold the IP and TCP headers in the first buflet.
	 */
	_CASSERT(NX_FSW_MINBUFSIZE >= NETIF_COMPAT_MAX_MBUF_DATA_COPY);

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX |
	    (PKT_IS_MBUF(pkt) ? SK_VERB_COPY_MBUF : SK_VERB_COPY)));

	uint16_t start = 0, csum = 0;
	uint32_t len = 0;
	/* soff is only used for packets */
	uint16_t soff = pkt->pkt_headroom + pkt->pkt_l2_len;
	uint32_t data_partial = 0, partial = 0;
	boolean_t odd_start = false;
	uint32_t data_len;
	uint16_t dbuf_off;
	uint16_t copied_len = 0;
	bool l3_csum_ok;
	uint8_t *daddr;

	if (dbuf->dba_is_buflet) {
		daddr = kern_buflet_get_data_address(dbuf->dba_buflet[0]);
		daddr += kern_buflet_get_data_length(dbuf->dba_buflet[0]);
	} else {
		daddr = mtod(dbuf->dba_mbuf[0], uint8_t *);
		daddr += dbuf->dba_mbuf[0]->m_len;
		ASSERT(mbuf_maxlen(dbuf->dba_mbuf[0]) >= plen);
	}

	/* Some compat drivers compute full checksum */
	if (PKT_IS_MBUF(pkt) && ((pkt->pkt_mbuf->m_pkthdr.csum_flags &
	    CSUM_RX_FULL_FLAGS) == CSUM_RX_FULL_FLAGS)) {
		/* copy only */
		_copy_data_sum_dbuf(pkt, PKT_IS_TRUNC_MBUF(pkt) ? 0: soff,
		    plen, &partial, &odd_start, dbuf, false);
		csum = pkt->pkt_mbuf->m_pkthdr.csum_rx_val;
		SK_DF(logflags, "HW csumf/rxstart/rxval 0x%x/%u/0x%04x",
		    pkt->pkt_mbuf->m_pkthdr.csum_flags,
		    pkt->pkt_mbuf->m_pkthdr.csum_rx_start, csum);
		/* pkt metadata will be transfer to super packet */
		__packet_set_inet_checksum(SK_PKT2PH(pkt),
		    PACKET_CSUM_RX_FULL_FLAGS, 0, csum, false);
		if ((csum ^ 0xffff) == 0) {
			return true;
		} else {
			return false;
		}
	}
	/* Copy l3 & verify checksum only for IPv4 */
	start = 0;
	len = pkt->pkt_flow_ip_hlen;
	if (PKT_IS_TRUNC_MBUF(pkt)) {
		partial = m_copydata_sum(pkt->pkt_mbuf, start, len,
		    (daddr + start), 0, NULL);
	} else {
		partial = pkt_copyaddr_sum(SK_PKT2PH(pkt), soff,
		    (daddr + start), len, true, 0, NULL);
	}
	verify_l3 = (verify_l3 && !PACKET_HAS_VALID_IP_CSUM(pkt));
	l3_csum_ok = !verify_l3;
	if (verify_l3) {
		csum = __packet_fold_sum(partial);
		SK_DF(logflags, "IP copy+sum %u(%u) (csum 0x%04x)",
		    start, len, csum);
		pkt->pkt_csum_flags |= PACKET_CSUM_IP_CHECKED;
		if ((csum ^ 0xffff) != 0) {
			/* proceed to copy the rest of packet */
		} else {
			pkt->pkt_csum_flags |= PACKET_CSUM_IP_VALID;
			l3_csum_ok = true;
		}
	}
	copied_len += pkt->pkt_flow_ip_hlen;

	/* Copy & verify TCP checksum */
	start = pkt->pkt_flow_ip_hlen;
	len = plen - start;

	if (PKT_IS_TRUNC_MBUF(pkt)) {
		/* First, copy and sum TCP header */
		partial = m_copydata_sum(pkt->pkt_mbuf, start,
		    pkt->pkt_flow_tcp_hlen, (daddr + start), 0, NULL);

		data_len = len - pkt->pkt_flow_tcp_hlen;
		start += pkt->pkt_flow_tcp_hlen;
		dbuf_off = start;
		/* Next, copy and sum payload (if any) */
	} else {
		/* First, copy and sum TCP header */
		partial = pkt_copyaddr_sum(SK_PKT2PH(pkt), (soff + start),
		    (daddr + start), pkt->pkt_flow_tcp_hlen, true, 0, NULL);

		data_len = len - pkt->pkt_flow_tcp_hlen;
		start += pkt->pkt_flow_tcp_hlen;
		dbuf_off = start;
		start += soff;
	}
	copied_len += pkt->pkt_flow_tcp_hlen;

	if (dbuf->dba_is_buflet) {
		VERIFY(kern_buflet_set_data_length(dbuf->dba_buflet[0],
		    kern_buflet_get_data_length(dbuf->dba_buflet[0]) +
		    copied_len) == 0);
	} else {
		dbuf->dba_mbuf[0]->m_len += copied_len;
		dbuf->dba_mbuf[0]->m_pkthdr.len += copied_len;
	}

	/* copy and sum payload (if any) */
	if (data_len > 0) {
		odd_start = false;
		_copy_data_sum_dbuf(pkt, start, data_len, &data_partial,
		    &odd_start, dbuf, l3_csum_ok);
	}

	if (__improbable(!l3_csum_ok)) {
		return false;
	}

	/* Fold data sum to 16 bit and then into the partial */
	*data_csum = __packet_fold_sum(data_partial);

	/* Fold in the data checksum to TCP checksum */
	partial += *data_csum;

	partial += htons(len + IPPROTO_TCP);
	if (pkt->pkt_flow_ip_ver == IPVERSION) {
		csum = in_pseudo(pkt->pkt_flow_ipv4_src.s_addr,
		    pkt->pkt_flow_ipv4_dst.s_addr, partial);
	} else {
		ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);
		csum = in6_pseudo(&pkt->pkt_flow_ipv6_src,
		    &pkt->pkt_flow_ipv6_dst, partial);
	}

	SK_DF(logflags, "TCP copy+sum %u(%u) (csum 0x%04x)",
	    pkt->pkt_flow_ip_hlen, len, csum);

	/* pkt metadata will be transfer to super packet */
	__packet_set_inet_checksum(SK_PKT2PH(pkt), PACKET_CSUM_RX_FULL_FLAGS,
	    0, csum, false);
	if ((csum ^ 0xffff) != 0) {
		return false;
	}

	return true;
}

SK_INLINE_ATTRIBUTE
static void
flow_agg_init_common(struct flow_agg *fa, struct __kern_packet *pkt)
{
	switch (pkt->pkt_flow_ip_ver) {
	case IPVERSION:
		if (pkt->pkt_flow_ip_hlen != sizeof(struct ip)) {
			return;
		}
		break;
	case IPV6_VERSION:
		if (pkt->pkt_flow_ip_hlen != sizeof(struct ip6_hdr)) {
			return;
		}
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	fa->fa_tcp_seq = ntohl(pkt->pkt_flow_tcp_seq) + pkt->pkt_flow_ulen;
	fa->fa_ulen = pkt->pkt_flow_ulen;
	fa->fa_total = pkt->pkt_flow_ip_hlen +
	    pkt->pkt_flow_tcp_hlen + pkt->pkt_flow_ulen;
}

static void
flow_agg_init_smbuf(struct flow_agg *fa, struct mbuf *smbuf,
    struct __kern_packet *pkt)
{
	FLOW_AGG_CLEAR(fa);

	ASSERT(smbuf != NULL);
	fa->fa_smbuf = smbuf;

	fa->fa_sptr = mtod(smbuf, uint8_t *);
	ASSERT(fa->fa_sptr != NULL);

	/*
	 * Note here we use 'pkt' instead of 'smbuf', since we rely on the
	 * contents of the flow structure which don't exist in 'smbuf'.
	 */
	flow_agg_init_common(fa, pkt);
}

static void
flow_agg_init_spkt(struct flow_agg *fa, struct __kern_packet *spkt,
    struct __kern_packet *pkt)
{
	FLOW_AGG_CLEAR(fa);

	ASSERT(spkt != NULL);
	fa->fa_spkt = spkt;
	fa->fa_sobj_is_pkt = true;
	VERIFY(spkt->pkt_headroom == 0 && spkt->pkt_l2_len == 0);

	MD_BUFLET_ADDR_ABS(spkt, fa->fa_sptr);
	ASSERT(fa->fa_sptr != NULL);

	/*
	 * Note here we use 'pkt' instead of 'spkt', since we rely on the
	 * contents of the flow structure which don't exist in 'spkt'.
	 */
	flow_agg_init_common(fa, pkt);
}

SK_INLINE_ATTRIBUTE
static bool
ipv4_tcp_memcmp(const uint8_t *h1, const uint8_t *h2)
{
	return sk_memcmp_mask_64B(h1, h2, (const uint8_t *)&ip_tcp_mask) == 0;
}

SK_INLINE_ATTRIBUTE
static bool
ipv6_tcp_memcmp(const uint8_t *h1, const uint8_t *h2)
{
	return sk_memcmp_mask_80B(h1, h2, (const uint8_t *)&ip6_tcp_mask) == 0;
}

SK_INLINE_ATTRIBUTE
static bool
can_agg_fastpath(struct flow_agg *fa, struct __kern_packet *pkt,
    struct fsw_stats *fsws)
{
	bool match;

	ASSERT(fa->fa_sptr != NULL);
	_CASSERT(sizeof(struct ip6_tcp_mask) == MASK_SIZE);
	_CASSERT(sizeof(struct ip_tcp_mask) == MASK_SIZE);

	if (__improbable(pkt->pkt_length < MASK_SIZE)) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_SHORT_TCP);
		goto slow_path;
	}

	if (__improbable(fa->fa_sobj_is_short)) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_SHORT_MBUF);
		goto slow_path;
	}

	if (__improbable(pkt->pkt_flow_tcp_hlen !=
	    (sizeof(struct tcphdr) + TCPOLEN_TSTAMP_APPA))) {
		goto slow_path;
	}

	switch (pkt->pkt_flow_ip_ver) {
	case IPVERSION:
		match = ipv4_tcp_memcmp(fa->fa_sptr,
		    (uint8_t *)pkt->pkt_flow_ip_hdr);
		break;
	case IPV6_VERSION:
		match = ipv6_tcp_memcmp(fa->fa_sptr,
		    (uint8_t *)pkt->pkt_flow_ip_hdr);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (__improbable(!match)) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_MASK_TCP);
		goto slow_path;
	}
	if (__improbable(pkt->pkt_flow_ulen != fa->fa_ulen)) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_ULEN_TCP);
		goto slow_path;
	}

	STATS_INC(fsws, FSW_STATS_RX_AGG_OK_FASTPATH_TCP);
	fa->fa_tcp_seq += pkt->pkt_flow_ulen;
	fa->fa_ulen = pkt->pkt_flow_ulen;
	return true;

slow_path:
	return false;
}

SK_NO_INLINE_ATTRIBUTE
static bool
can_agg_slowpath(struct flow_agg *fa, struct __kern_packet *pkt,
    struct fsw_stats *fsws)
{
	uint8_t *sl3_hdr = fa->fa_sptr;
	uint32_t sl3tlen = 0;
	uint16_t sl3hlen = 0;

	DTRACE_SKYWALK2(aggr__slow, struct __kern_packet *, pkt,
	    uint8_t *, sl3_hdr);

	ASSERT(sl3_hdr != NULL);

	/*
	 * Compare IP header length, TOS, frag flags and IP options
	 * For IPv4, the options should match exactly
	 * For IPv6, if options are present, bail out
	 */
	if (pkt->pkt_flow_ip_ver == IPVERSION) {
		struct ip *siph = (struct ip *)(void *)sl3_hdr;
		struct ip *iph = (struct ip *)pkt->pkt_flow_ip_hdr;

		ASSERT(siph->ip_v == IPVERSION);
		/* 16-bit alignment is sufficient (handles mbuf case) */
		ASSERT(IS_P2ALIGNED(siph, sizeof(uint16_t)));
		ASSERT(IS_P2ALIGNED(iph, sizeof(uint16_t)));

		sl3hlen = (siph->ip_hl << 2);
		if (sl3hlen != pkt->pkt_flow_ip_hlen) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_HLEN_IP);
			DTRACE_SKYWALK2(aggr__fail2, uint16_t, sl3hlen, uint8_t,
			    pkt->pkt_flow_ip_hlen);
			return false;
		}

		if (siph->ip_ttl != iph->ip_ttl) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_TTL_IP);
			DTRACE_SKYWALK2(aggr__fail3, uint8_t, siph->ip_ttl,
			    uint8_t, iph->ip_ttl);
			return false;
		}

		if (siph->ip_tos != iph->ip_tos) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_TOS_IP);
			DTRACE_SKYWALK2(aggr__fail4, uint8_t, siph->ip_tos,
			    uint8_t, iph->ip_tos);
			return false;
		}
		/* For IPv4, DF bit should match */
		if ((ntohs(siph->ip_off) & (IP_DF | IP_RF)) !=
		    (ntohs(iph->ip_off) & (IP_DF | IP_RF))) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_OFF_IP);
			DTRACE_SKYWALK2(aggr__fail5, uint16_t,
			    ntohs(siph->ip_off), uint16_t, ntohs(iph->ip_off));
			return false;
		}

		uint8_t ip_opts_len = pkt->pkt_flow_ip_hlen -
		    sizeof(struct ip);
		if (ip_opts_len > 0 &&
		    memcmp((uint8_t *)(siph + 1), (uint8_t *)(iph + 1),
		    ip_opts_len) != 0) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_OPT_IP);
			DTRACE_SKYWALK3(aggr__fail6, uint8_t, ip_opts_len,
			    uint8_t *, (uint8_t *)(siph + 1), uint8_t *,
			    (uint8_t *)(iph + 1));
			return false;
		}
		sl3tlen = ntohs(siph->ip_len);
	} else {
		struct ip6_hdr *sip6 = (struct ip6_hdr *)(void *)sl3_hdr;
		struct ip6_hdr *ip6 = (struct ip6_hdr *)pkt->pkt_flow_ip_hdr;

		ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);
		ASSERT((sip6->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION);
		/* 16-bit alignment is sufficient (handles mbuf case) */
		ASSERT(IS_P2ALIGNED(sip6, sizeof(uint16_t)));

		if (pkt->pkt_flow_ip_hlen != sizeof(struct ip6_hdr)) {
			/*
			 * Don't aggregate if extension header is present in
			 * packet. N.B. currently flow switch only classifies
			 * frag header
			 */
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_HLEN_IP);
			DTRACE_SKYWALK1(aggr__fail7, uint8_t,
			    pkt->pkt_flow_ip_hlen);
			return false;
		}

		sl3hlen = sizeof(struct ip6_hdr);
		/* For IPv6, flow info mask covers TOS and flow label */
		if (memcmp(&sip6->ip6_flow, &ip6->ip6_flow,
		    sizeof(sip6->ip6_flow)) != 0) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_TOS_IP);
			DTRACE_SKYWALK2(aggr__fail8, uint32_t,
			    ntohl(sip6->ip6_flow), uint32_t,
			    ntohl(ip6->ip6_flow));
			return false;
		}

		if (sip6->ip6_hlim != ip6->ip6_hlim) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_TTL_IP);
			DTRACE_SKYWALK2(aggr__fail9, uint8_t, sip6->ip6_hlim,
			    uint8_t, ip6->ip6_hlim);
			return false;
		}

		sl3tlen = (sizeof(struct ip6_hdr) + ntohs(sip6->ip6_plen));
	}

	/*
	 * For TCP header, compare ACK number and window size
	 * Compare TCP flags
	 * Compare TCP header length and TCP options
	 */
	struct tcphdr *stcp = (struct tcphdr *)(void *)(sl3_hdr + sl3hlen);
	struct tcphdr *tcp = (struct tcphdr *)pkt->pkt_flow_tcp_hdr;

	uint16_t sl4hlen = (stcp->th_off << 2);
	if (memcmp(&stcp->th_ack, &tcp->th_ack, sizeof(stcp->th_ack)) != 0 ||
	    memcmp(&stcp->th_win, &tcp->th_win, sizeof(stcp->th_win)) != 0) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_ACKWIN_TCP);
		DTRACE_SKYWALK4(aggr__fail9, uint32_t, ntohl(stcp->th_ack),
		    uint32_t, ntohl(tcp->th_ack), uint16_t, ntohs(stcp->th_win),
		    uint16_t, ntohs(tcp->th_win));
		return false;
	}

	if ((stcp->th_flags & ~(TH_PUSH)) != (tcp->th_flags & ~(TH_PUSH))) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_FLAGS_TCP);
		DTRACE_SKYWALK2(aggr__fail10, uint8_t, stcp->th_flags,
		    uint8_t, tcp->th_flags);
		return false;
	}

	if (sl4hlen != pkt->pkt_flow_tcp_hlen) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_HLEN_TCP);
		DTRACE_SKYWALK2(aggr__fail11, uint8_t, sl4hlen,
		    uint8_t, pkt->pkt_flow_tcp_hlen);
		return false;
	}

	uint8_t tcp_opts_len = pkt->pkt_flow_tcp_hlen - sizeof(struct tcphdr);
	/*
	 * We know that the TCP-option lengthes are the same thanks to the above
	 * sl4hlen check
	 */
	if (tcp_opts_len > 0 && memcmp((uint8_t *)(stcp + 1),
	    (uint8_t *)(tcp + 1), tcp_opts_len) != 0) {
		/*
		 * Fast-path header prediction:
		 *
		 * TCP Timestamp option is usually put after two NOP-headers,
		 * and thus total TCP-option length is 12. If that's the case,
		 * we can aggregate as only the TCP time-stamp option differs.
		 */
		if (tcp_opts_len != TCPOLEN_TSTAMP_APPA) {
			STATS_INC(fsws, FSW_STATS_RX_AGG_NO_EXOPT_TCP);
			DTRACE_SKYWALK1(aggr__fail13, uint8_t, tcp_opts_len);
			return false;
		} else {
			uint32_t sts_hdr, ts_hdr;
			if (IS_P2ALIGNED(stcp + 1, sizeof(uint32_t))) {
				sts_hdr = *((uint32_t *)(stcp + 1));
			} else {
				bcopy(stcp + 1, &sts_hdr, sizeof(sts_hdr));
			}
			if (IS_P2ALIGNED(tcp + 1, sizeof(uint32_t))) {
				ts_hdr = *((uint32_t *)(tcp + 1));
			} else {
				bcopy(tcp + 1, &ts_hdr, sizeof(ts_hdr));
			}

			if (sts_hdr != htonl(TCPOPT_TSTAMP_HDR) ||
			    ts_hdr != htonl(TCPOPT_TSTAMP_HDR)) {
				STATS_INC(fsws, FSW_STATS_RX_AGG_NO_OPTTS_TCP);
				DTRACE_SKYWALK2(aggr__fail14, uint32_t,
				    sts_hdr, uint32_t, ts_hdr);
				return false;
			}
		}
	}
	STATS_INC(fsws, FSW_STATS_RX_AGG_OK_SLOWPATH_TCP);
	fa->fa_tcp_seq += pkt->pkt_flow_ulen;
	fa->fa_ulen = pkt->pkt_flow_ulen;
	return true;
}

static bool
flow_agg_is_ok(struct flow_agg *fa, struct __kern_packet *pkt,
    struct fsw_stats *fsws)
{
	/* Shouldn't exceed the ip_len beyond MIN(custom ip_len, 64K) */
	const uint32_t max_ip_len = MIN(sk_fsw_rx_agg_tcp, IP_MAXPACKET);
	bool can_agg = false;

	DTRACE_SKYWALK2(aggr__check, struct flow_agg *, fa,
	    struct __kern_packet *, pkt);

	ASSERT(pkt->pkt_flow_ip_proto == IPPROTO_TCP);
	if (__improbable(pkt->pkt_flow_tcp_agg_fast != 0)) {
		pkt->pkt_flow_tcp_agg_fast = 0;
	}
	/*
	 * Don't aggregate if any of the following is true:
	 * 1. TCP flag is other than TH_{ACK,PUSH}
	 * 2. Payload length is 0 (pure ACK)
	 * 3. This is the first packet
	 * 4. TCP sequence number is not expected
	 * 5. We would've exceeded the maximum aggregated size
	 * 6. It's not the first packet and the wake flag is set
	 */
	if (__improbable((pkt->pkt_flow_tcp_flags & TCP_FLAGS_IGNORE) != 0 ||
	    pkt->pkt_flow_ulen == 0 || fa->fa_sobj == NULL)) {
		DTRACE_SKYWALK1(aggr__fail1a, struct __kern_packet *, pkt);
		goto done;
	}
	if (__improbable(ntohl(pkt->pkt_flow_tcp_seq) != fa->fa_tcp_seq)) {
		DTRACE_SKYWALK2(aggr__fail1b, uint32_t,
		    ntohl(pkt->pkt_flow_tcp_seq), uint32_t, fa->fa_tcp_seq);
		STATS_INC(fsws, FSW_STATS_RX_AGG_NO_SEQN_TCP);
		goto done;
	}
	if (__improbable((fa->fa_total + pkt->pkt_flow_ulen) > max_ip_len)) {
		DTRACE_SKYWALK3(aggr__fail1c, uint32_t, fa->fa_total,
		    uint32_t, pkt->pkt_flow_ulen, uint32_t, max_ip_len);
		/* We've reached aggregation limit */
		STATS_INC(fsws, FSW_STATS_RX_AGG_LIMIT);
		goto done;
	}
	if (__improbable((pkt->pkt_pflags & PKT_F_WAKE_PKT) && fa->fa_total > 0)) {
		DTRACE_SKYWALK1(aggr__fail1d, struct __kern_packet *, pkt);
		goto done;
	}

	can_agg = can_agg_fastpath(fa, pkt, fsws);
	if (can_agg) {
		pkt->pkt_flow_tcp_agg_fast = 1;
		goto done;
	}

	can_agg = can_agg_slowpath(fa, pkt, fsws);
	ASSERT(!pkt->pkt_flow_tcp_agg_fast);

done:
	return can_agg;
}

static void
flow_agg_merge_hdr(struct flow_agg *fa, struct __kern_packet *pkt,
    uint16_t data_csum, struct fsw_stats *fsws)
{
	struct tcphdr *stcp, *tcp;
	uint8_t *l3hdr, l3hlen;
	uint16_t old_l3len = 0;
	uint8_t result;

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX));

	ASSERT(fa->fa_sobj != NULL);
	ASSERT(!fa->fa_sobj_is_pkt ||
	    (fa->fa_spkt->pkt_headroom == 0 && fa->fa_spkt->pkt_l2_len == 0));
	uint8_t *sl3_hdr = fa->fa_sptr;
	ASSERT(sl3_hdr != NULL);

	fa->fa_total += pkt->pkt_flow_ulen;

	/*
	 * Update the IP header as:
	 * 1. Set the IP ID (IPv4 only) to that of the new packet
	 * 2. Set the ttl to the lowest of the two
	 * 3. Increment the IP length by the payload length of new packet
	 * 4. Leave the IP (IPv4 only) checksum as is
	 * Update the resp. flow classification fields, if any
	 * Nothing to update for TCP header for now
	 */
	if (pkt->pkt_flow_ip_ver == IPVERSION) {
		struct ip *siph = (struct ip *)(void *)sl3_hdr;

		/* 16-bit alignment is sufficient (handles mbuf case) */
		ASSERT(IS_P2ALIGNED(siph, sizeof(uint16_t)));

		l3hdr = (uint8_t *)siph;
		l3hlen = siph->ip_hl << 2;

		old_l3len = ntohs(siph->ip_len);
		uint16_t l3tlen = ntohs(siph->ip_len) + pkt->pkt_flow_ulen;
		siph->ip_len = htons(l3tlen);
		siph->ip_sum = __packet_fix_sum(siph->ip_sum, 0,
		    htons(pkt->pkt_flow_ulen));

		SK_DF(logflags, "Agg IP len %u", ntohs(siph->ip_len));
	} else {
		struct ip6_hdr *sip6 = (struct ip6_hdr *)(void *)sl3_hdr;

		/* 16-bit alignment is sufficient (handles mbuf case) */
		ASSERT(IS_P2ALIGNED(sip6, sizeof(uint16_t)));
		ASSERT((sip6->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION);
		ASSERT(pkt->pkt_flow_ip_ver == IPV6_VERSION);

		l3hdr = (uint8_t *)sip6;
		l3hlen = sizeof(struct ip6_hdr);

		/* No extension headers should be present */
		ASSERT(pkt->pkt_flow_ip_hlen == sizeof(struct ip6_hdr));

		old_l3len = ntohs(sip6->ip6_plen) + sizeof(struct ip6_hdr);
		uint16_t l3plen = ntohs(sip6->ip6_plen) + pkt->pkt_flow_ulen;
		sip6->ip6_plen = htons(l3plen);

		SK_DF(logflags, "Agg IP6 len %u", ntohs(sip6->ip6_plen));
	}

	if (__probable(pkt->pkt_flow_tcp_agg_fast)) {
		STATS_INC(fsws, FSW_STATS_RX_AGG_MERGE_FASTPATH_IP);
	} else {
		STATS_INC(fsws, FSW_STATS_RX_AGG_MERGE_SLOWPATH_IP);
	}

	stcp = (struct tcphdr *)(void *)(l3hdr + l3hlen);
	tcp = (struct tcphdr *)pkt->pkt_flow_tcp_hdr;
	/* 16-bit alignment is sufficient (handles mbuf case) */
	ASSERT(IS_P2ALIGNED(stcp, sizeof(uint16_t)));
	ASSERT(IS_P2ALIGNED(tcp, sizeof(uint16_t)));

	/*
	 * If it is bigger, that means there are TCP-options that need to be
	 * copied over.
	 */
	if (pkt->pkt_flow_tcp_hlen > sizeof(struct tcphdr) ||
	    (stcp->th_flags & TH_PUSH) == 0) {
		VERIFY(stcp->th_off << 2 == pkt->pkt_flow_tcp_hlen);
		if (__improbable(!pkt->pkt_flow_tcp_agg_fast &&
		    memcmp(stcp + 1, tcp + 1, (pkt->pkt_flow_tcp_hlen -
		    sizeof(struct tcphdr))) != 0)) {
			uint8_t *sopt = (uint8_t *)(stcp + 1);
			uint8_t *opt = (uint8_t *)(tcp + 1);

			uint32_t ntsval, ntsecr;
			bcopy((void *)(opt + 4), &ntsval, sizeof(ntsval));
			bcopy((void *)(opt + 8), &ntsecr, sizeof(ntsecr));

			__packet_fix_hdr_sum(sopt + 4, &stcp->th_sum, ntsval);
			__packet_fix_hdr_sum(sopt + 8, &stcp->th_sum, ntsecr);

			STATS_INC(fsws, FSW_STATS_RX_AGG_MERGE_SLOWPATH_TCP);
		} else {
			STATS_INC(fsws, FSW_STATS_RX_AGG_MERGE_FASTPATH_TCP);
		}

		if ((stcp->th_flags & TH_PUSH) == 0 &&
		    (tcp->th_flags & TH_PUSH) != 0) {
			uint16_t old, new;
			old = *(uint16_t *)(void *)(&stcp->th_ack + 1);
			/* If the new segment has a PUSH-flag, append it! */
			stcp->th_flags |= tcp->th_flags & TH_PUSH;
			new = *(uint16_t *)(void *)(&stcp->th_ack + 1);
			stcp->th_sum = __packet_fix_sum(stcp->th_sum, old, new);
		}
	}

	/* Update pseudo header checksum */
	stcp->th_sum = __packet_fix_sum(stcp->th_sum, 0,
	    htons(pkt->pkt_flow_ulen));

	/* Update data checksum  */
	if (__improbable(old_l3len & 0x1)) {
		/* swap the byte order, refer to rfc 1071 section 2 */
		stcp->th_sum = __packet_fix_sum(stcp->th_sum, 0,
		    ntohs(data_csum));
	} else {
		stcp->th_sum = __packet_fix_sum(stcp->th_sum, 0, data_csum);
	}

	if (fa->fa_sobj_is_pkt) {
		struct __kern_packet *spkt = fa->fa_spkt;
		spkt->pkt_aggr_type = PKT_AGGR_SINGLE_IP;
		spkt->pkt_flow_ulen += pkt->pkt_flow_ulen;
		/*
		 * Super packet length includes L3 and L4
		 * header length for first packet only.
		 */
		spkt->pkt_length += pkt->pkt_flow_ulen;
		if (spkt->pkt_seg_cnt == 0) {
			/* First time we append packets, need to set it to 1 */
			spkt->pkt_seg_cnt = 1;
		}
		_CASSERT(sizeof(result) == sizeof(spkt->pkt_seg_cnt));
		if (!os_add_overflow(1, spkt->pkt_seg_cnt, &result)) {
			spkt->pkt_seg_cnt = result;
		}
		SK_DF(logflags, "Agg pkt len %u TCP csum 0x%04x",
		    spkt->pkt_length, ntohs(stcp->th_sum));
	} else {
		struct mbuf *smbuf = fa->fa_smbuf;
		smbuf->m_pkthdr.len += pkt->pkt_flow_ulen;
		if (smbuf->m_pkthdr.seg_cnt == 0) {
			/* First time we append packets, need to set it to 1 */
			smbuf->m_pkthdr.seg_cnt = 1;
		}
		_CASSERT(sizeof(result) == sizeof(smbuf->m_pkthdr.seg_cnt));
		if (!os_add_overflow(1, smbuf->m_pkthdr.seg_cnt, &result)) {
			smbuf->m_pkthdr.seg_cnt = result;
		}
		SK_DF(logflags, "Agg mbuf len %u TCP csum 0x%04x",
		    smbuf->m_pkthdr.len, ntohs(stcp->th_sum));
	}
}

/*
 * Copy metadata from source packet to destination packet
 */
static void
pkt_copy_metadata(struct __kern_packet *spkt, struct __kern_packet *dpkt)
{
	/* Copy packet metadata */
	_QUM_COPY(&(spkt)->pkt_qum, &(dpkt)->pkt_qum);
	_PKT_COPY(spkt, dpkt);
}

static void
pkt_finalize(kern_packet_t ph)
{
	int err = __packet_finalize(ph);
	VERIFY(err == 0);
#if (DEVELOPMENT || DEBUG)
	struct __kern_packet *pkt = SK_PTR_ADDR_KPKT(ph);
	uint8_t *buf;
	MD_BUFLET_ADDR_ABS(pkt, buf);
	buf += pkt->pkt_headroom + pkt->pkt_l2_len;
	DTRACE_SKYWALK2(aggr__finalize, struct __kern_packet *, pkt,
	    uint8_t *, buf);
#endif
}

SK_INLINE_ATTRIBUTE
static inline uint32_t
_estimate_buflet_cnt(struct flow_entry *fe, struct kern_pbufpool *pp)
{
	uint32_t cnt;

	_CASSERT(MAX_BUFLET_COUNT <= UINT8_MAX);
	cnt = howmany(((fe->fe_rx_pktq_bytes + sizeof(struct ip6_hdr)) +
	    sizeof(struct tcphdr)), pp->pp_buflet_size);
	cnt = MAX(KPKTQ_LEN(&fe->fe_rx_pktq), cnt);
	cnt = MIN(cnt, MAX_BUFLET_COUNT);
	return cnt;
}

SK_INLINE_ATTRIBUTE
static inline void
_append_dbuf_array_to_kpkt(kern_packet_t ph, kern_buflet_t pbuf,
    _dbuf_array_t *dbuf_array, kern_buflet_t *lbuf)
{
	for (uint8_t i = 0; i < dbuf_array->dba_num_dbufs; i++) {
		kern_buflet_t buf = dbuf_array->dba_buflet[i];
		VERIFY(kern_packet_add_buflet(ph, pbuf, buf) == 0);
		pbuf = buf;
		dbuf_array->dba_buflet[i] = NULL;
	}
	ASSERT(pbuf != NULL);
	dbuf_array->dba_num_dbufs = 0;
	*lbuf = pbuf;
}

SK_INLINE_ATTRIBUTE
static inline void
_free_dbuf_array(struct kern_pbufpool *pp,
    _dbuf_array_t *dbuf_array)
{
	for (uint8_t i = 0; i < dbuf_array->dba_num_dbufs; i++) {
		kern_buflet_t buf = dbuf_array->dba_buflet[i];
		pp_free_buflet(pp, buf);
		dbuf_array->dba_buflet[i] = NULL;
	}
	dbuf_array->dba_num_dbufs = 0;
}

SK_NO_INLINE_ATTRIBUTE
static void
flow_rx_agg_channel(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct pktq *dropped_pkts, bool is_mbuf)
{
#define __RX_AGG_CHAN_DROP_SOURCE_PACKET(_pkt)    do {   \
	KPKTQ_ENQUEUE(dropped_pkts, (_pkt));             \
	(_pkt) = NULL;                                   \
	FLOW_AGG_CLEAR(&fa);                             \
	prev_csum_ok = false;                            \
} while (0)
	struct flow_agg fa;             /* states */
	FLOW_AGG_CLEAR(&fa);

	struct pktq pkts;               /* dst super packets */
	struct pktq disposed_pkts;      /* done src packets */

	KPKTQ_INIT(&pkts);
	KPKTQ_INIT(&disposed_pkts);

	struct __kern_channel_ring *ring;
	ring = fsw_flow_get_rx_ring(fsw, fe);
	if (__improbable(ring == NULL)) {
		SK_ERR("Rx ring is NULL");
		KPKTQ_CONCAT(dropped_pkts, &fe->fe_rx_pktq);
		STATS_ADD(&fsw->fsw_stats, FSW_STATS_DST_NXPORT_INVALID,
		    KPKTQ_LEN(dropped_pkts));
		return;
	}
	struct kern_pbufpool *dpp = ring->ckr_pp;
	ASSERT(dpp->pp_max_frags > 1);

	struct __kern_packet *pkt, *tpkt;
	/* state for super packet */
	struct __kern_packet *spkt = NULL;
	kern_packet_t sph = 0;
	kern_buflet_t sbuf = NULL;
	bool prev_csum_ok = false, csum_ok, agg_ok;
	uint16_t spkts = 0, bufcnt = 0;
	int err;

	struct fsw_stats *fsws = &fsw->fsw_stats;

	/* state for buflet batch alloc */
	uint32_t bh_cnt, bh_cnt_tmp;
	uint8_t iter = 0;
	uint64_t buf_arr[MAX_BUFLET_COUNT];
	_dbuf_array_t dbuf_array = {.dba_is_buflet = true, .dba_num_dbufs = 0};

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX));
	SK_DF(logflags, "Rx input queue len %u", KPKTQ_LEN(&fe->fe_rx_pktq));

	bh_cnt_tmp = bh_cnt = _estimate_buflet_cnt(fe, dpp);
	err = pp_alloc_buflet_batch(dpp, buf_arr, &bh_cnt, SKMEM_NOSLEEP);
	if (__improbable(bh_cnt == 0)) {
		SK_ERR("failed to alloc %u buflets (err %d), use slow path",
		    bh_cnt_tmp, err);
	}
	bool is_ipv4 = (fe->fe_key.fk_ipver == IPVERSION);
	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_rx_pktq, tpkt) {
		if (tpkt != NULL) {
			void *baddr;
			MD_BUFLET_ADDR_ABS_PKT(tpkt, baddr);
			SK_PREFETCH(baddr, 0);
		}

		ASSERT(pkt->pkt_qum.qum_pp != dpp);
		ASSERT(is_mbuf == !!(PKT_IS_MBUF(pkt)));
		ASSERT(fe->fe_key.fk_ipver == pkt->pkt_flow_ip_ver);
		ASSERT((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) == 0);
		ASSERT(!pkt->pkt_flow_ip_is_frag);
		ASSERT(pkt->pkt_flow_ip_proto == IPPROTO_TCP);

		csum_ok = false;
		agg_ok = false;
		/* supports TCP only */
		uint32_t thlen = (pkt->pkt_flow_ip_hlen +
		    pkt->pkt_flow_tcp_hlen);
		uint32_t plen = (thlen + pkt->pkt_flow_ulen);
		uint16_t data_csum = 0;

		KPKTQ_REMOVE(&fe->fe_rx_pktq, pkt);
		fe->fe_rx_pktq_bytes -= pkt->pkt_flow_ulen;
		err = flow_pkt_track(fe, pkt, true);
		if (__improbable(err != 0)) {
			STATS_INC(fsws, FSW_STATS_RX_FLOW_TRACK_ERR);
			/* if need to trigger RST then deliver to host */
			if (err == ENETRESET) {
				struct flow_entry *host_fe;
				host_fe =
				    flow_mgr_get_host_fe(fsw->fsw_flow_mgr);
				KPKTQ_ENQUEUE(&host_fe->fe_rx_pktq, pkt);
				continue;
			}
			SK_ERR("flow_pkt_track failed (err %d)", err);
			__RX_AGG_CHAN_DROP_SOURCE_PACKET(pkt);
			continue;
		}

		if (is_mbuf) {          /* compat */
			m_adj(pkt->pkt_mbuf, pkt->pkt_l2_len);
			pkt->pkt_svc_class = m_get_service_class(pkt->pkt_mbuf);
		}

		if (prev_csum_ok && sbuf) {
			ASSERT(fa.fa_spkt == spkt);
			ASSERT(spkt == NULL || fa.fa_sobj_is_pkt);
			agg_ok = flow_agg_is_ok(&fa, pkt, fsws);
			agg_ok = (agg_ok && bufcnt < dpp->pp_max_frags);

			if (agg_ok && sbuf->buf_dlim - sbuf->buf_doff -
			    sbuf->buf_dlen >= plen - thlen) {
				/*
				 * No need for a new packet, just
				 * append to curr_m.
				 */
				csum_ok = copy_pkt_csum_packed(pkt, plen, NULL,
				    is_ipv4, NULL, sbuf, &data_csum, NULL);

				if (!csum_ok) {
					STATS_INC(fsws,
					    FSW_STATS_RX_AGG_BAD_CSUM);
					SK_ERR("Checksum for aggregation "
					    "is wrong");
					DTRACE_SKYWALK(aggr__chan_packed_tcp_csum_fail1);
					/*
					 * Turns out, checksum is wrong!
					 * Fallback to no-agg mode.
					 */
					agg_ok = false;
				} else {
					flow_agg_merge_hdr(&fa, pkt,
					    data_csum, fsws);
					goto next;
				}
			}
		}

		/* calculate number of buflets required */
		bh_cnt_tmp = howmany(plen, dpp->pp_buflet_size);
		if (__improbable(bh_cnt_tmp > MAX_BUFLET_COUNT)) {
			STATS_INC(fsws, FSW_STATS_DROP_NOMEM_PKT);
			SK_ERR("packet too big: bufcnt %d len %d", bh_cnt_tmp,
			    plen);
			__RX_AGG_CHAN_DROP_SOURCE_PACKET(pkt);
			continue;
		}
		if (bh_cnt < bh_cnt_tmp) {
			uint32_t tmp;

			if (iter != 0) {
				/*
				 * rearrange the array for additional
				 * allocation
				 */
				uint8_t i;
				for (i = 0; i < bh_cnt; i++, iter++) {
					buf_arr[i] = buf_arr[iter];
					buf_arr[iter] = 0;
				}
				iter = 0;
			}
			tmp = _estimate_buflet_cnt(fe, dpp);
			tmp = MAX(tmp, bh_cnt_tmp);
			tmp -= bh_cnt;
			ASSERT(tmp <= (MAX_BUFLET_COUNT - bh_cnt));
			err = pp_alloc_buflet_batch(dpp, &buf_arr[bh_cnt],
			    &tmp, SKMEM_NOSLEEP);
			bh_cnt += tmp;
			if (__improbable((tmp == 0) || (bh_cnt < bh_cnt_tmp))) {
				STATS_INC(fsws, FSW_STATS_DROP_NOMEM_PKT);
				SK_ERR("buflet alloc failed (err %d)", err);
				__RX_AGG_CHAN_DROP_SOURCE_PACKET(pkt);
				continue;
			}
		}
		/* Use pre-allocated buflets */
		ASSERT(bh_cnt >= bh_cnt_tmp);
		dbuf_array.dba_num_dbufs = bh_cnt_tmp;
		while (bh_cnt_tmp-- > 0) {
			dbuf_array.dba_buflet[bh_cnt_tmp] =
			    (kern_buflet_t)(buf_arr[iter]);
			buf_arr[iter] = 0;
			bh_cnt--;
			iter++;
		}
		/* copy and checksum TCP data */
		if (agg_ok) {
			int added = 0;
			ASSERT(dbuf_array.dba_num_dbufs != 0);
			csum_ok = copy_pkt_csum_packed(pkt, plen, &dbuf_array,
			    is_ipv4, NULL, sbuf, &data_csum, &added);

			if (__improbable(!csum_ok)) {
				STATS_INC(fsws, FSW_STATS_RX_AGG_BAD_CSUM);
				SK_ERR("Checksum for aggregation on new "
				    "mbuf is wrong");
				DTRACE_SKYWALK(aggr__chan_packed_tcp_csum_fail2);
				agg_ok = false;
				/* reset the used buflets */
				uint8_t j;
				for (j = 0; j < dbuf_array.dba_num_dbufs; j++) {
					VERIFY(kern_buflet_set_data_length(
						    dbuf_array.dba_buflet[j], 0) == 0);
				}
				goto non_agg;
			}

			/*
			 * There was not enough space in curr_m, thus we must
			 * have added to m->m_data.
			 */
			VERIFY(added > 0);
		} else {
non_agg:
			ASSERT(dbuf_array.dba_num_dbufs != 0);
			csum_ok = copy_pkt_csum(pkt, plen, &dbuf_array,
			    &data_csum, is_ipv4);
			if (__improbable(!csum_ok)) {
				STATS_INC(fsws, FSW_STATS_RX_AGG_BAD_CSUM);
				SK_ERR("%d incorrect csum", __LINE__);
				DTRACE_SKYWALK(aggr__chan_tcp_csum_fail);
			}
		}
		if (agg_ok) {
			ASSERT(fa.fa_spkt == spkt);
			ASSERT(spkt == NULL || fa.fa_sobj_is_pkt);
			/* update current packet header */
			flow_agg_merge_hdr(&fa, pkt, data_csum, fsws);
			ASSERT(dbuf_array.dba_num_dbufs > 0);
			bufcnt += dbuf_array.dba_num_dbufs;
			_append_dbuf_array_to_kpkt(sph, sbuf, &dbuf_array,
			    &sbuf);
		} else {
			/* Finalize the current super packet */
			if (sph != 0) {
				spkts++;
				if (bufcnt > 1) {
					spkt->pkt_aggr_type =
					    PKT_AGGR_SINGLE_IP;
				}
				pkt_finalize(sph);
				pkt_agg_log(spkt, kernproc, false);
				DTRACE_SKYWALK1(aggr__buflet__count, uint16_t,
				    bufcnt);
				sph = 0;
				spkt = NULL;
				FLOW_AGG_CLEAR(&fa);
			}

			/* New super packet */
			err = kern_pbufpool_alloc_nosleep(dpp, 0, &sph);
			if (__improbable(err != 0)) {
				STATS_INC(fsws, FSW_STATS_DROP_NOMEM_PKT);
				SK_ERR("packet alloc failed (err %d)", err);
				_free_dbuf_array(dpp, &dbuf_array);
				__RX_AGG_CHAN_DROP_SOURCE_PACKET(pkt);
				continue;
			}
			spkt = SK_PTR_ADDR_KPKT(sph);
			pkt_copy_metadata(pkt, spkt);
			/* Packet length for super packet starts from L3 */
			spkt->pkt_length = plen;
			spkt->pkt_flow_ulen =  pkt->pkt_flow_ulen;
			spkt->pkt_headroom = 0;
			spkt->pkt_l2_len = 0;
			spkt->pkt_seg_cnt = 1;

			ASSERT(dbuf_array.dba_num_dbufs > 0);
			bufcnt = dbuf_array.dba_num_dbufs;
			sbuf = kern_packet_get_next_buflet(sph, NULL);
			_append_dbuf_array_to_kpkt(sph, sbuf, &dbuf_array,
			    &sbuf);

			KPKTQ_ENQUEUE(&pkts, spkt);
			_UUID_COPY(spkt->pkt_flow_id, fe->fe_uuid);
			_UUID_COPY(spkt->pkt_policy_euuid, fe->fe_eproc_uuid);
			spkt->pkt_policy_id = fe->fe_policy_id;
			spkt->pkt_transport_protocol =
			    fe->fe_transport_protocol;
			flow_agg_init_spkt(&fa, spkt, pkt);
		}
next:
		pkt_agg_log(pkt, kernproc, true);
		prev_csum_ok = csum_ok;
		KPKTQ_ENQUEUE(&disposed_pkts, pkt);
	}

	/* Free unused buflets */
	while (bh_cnt > 0) {
		pp_free_buflet(dpp, (kern_buflet_t)(buf_arr[iter]));
		buf_arr[iter] = 0;
		bh_cnt--;
		iter++;
	}
	/* Finalize the last super packet */
	if (sph != 0) {
		spkts++;
		if (bufcnt > 1) {
			spkt->pkt_aggr_type = PKT_AGGR_SINGLE_IP;
		}
		pkt_finalize(sph);
		pkt_agg_log(spkt, kernproc, false);
		DTRACE_SKYWALK1(aggr__buflet__count, uint16_t, bufcnt);
		sph = 0;
		spkt = NULL;
		FLOW_AGG_CLEAR(&fa);
	}
	DTRACE_SKYWALK1(aggr__spkt__count, uint16_t, spkts);
	if (__improbable(is_mbuf)) {
		STATS_ADD(fsws, FSW_STATS_RX_AGG_MBUF2PKT, spkts);
	} else {
		STATS_ADD(fsws, FSW_STATS_RX_AGG_PKT2PKT, spkts);
	}
	FLOW_STATS_IN_ADD(fe, spackets, spkts);

	KPKTQ_FINI(&fe->fe_rx_pktq);
	KPKTQ_CONCAT(&fe->fe_rx_pktq, &pkts);
	KPKTQ_FINI(&pkts);

	fsw_ring_enqueue_tail_drop(fsw, ring, &fe->fe_rx_pktq);

	pp_free_pktq(&disposed_pkts);
}

SK_NO_INLINE_ATTRIBUTE
static void
flow_rx_agg_host(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct pktq *dropped_pkts, bool is_mbuf)
{
#define __RX_AGG_HOST_DROP_SOURCE_PACKET(_pkt)    do {   \
	drop_packets++;                                  \
	drop_bytes += (_pkt)->pkt_length;                \
	KPKTQ_ENQUEUE(dropped_pkts, (_pkt));             \
	(_pkt) = NULL;                                   \
	FLOW_AGG_CLEAR(&fa);                             \
	prev_csum_ok = false;                            \
} while (0)
	struct flow_agg fa;             /* states */
	FLOW_AGG_CLEAR(&fa);

	struct pktq disposed_pkts;      /* done src packets */
	KPKTQ_INIT(&disposed_pkts);

	int alloced = 0;
	int factor;

	struct __kern_packet *pkt, *tpkt;
	/* points to the first mbuf of chain */
	struct mbuf *m_chain = NULL;
	/* super mbuf, at the end it points to last mbuf packet */
	struct  mbuf *smbuf = NULL, *curr_m = NULL;
	bool prev_csum_ok = false, csum_ok, agg_ok;
	uint16_t smbufs = 0;
	uint32_t bytes = 0, rcvd_ulen = 0;
	uint32_t rcvd_packets = 0, rcvd_bytes = 0; /* raw packets & bytes */
	uint32_t drop_packets = 0, drop_bytes = 0; /* dropped packets & bytes */
	uint32_t largest_smbuf = 0;
	int err = 0;

	struct fsw_stats *fsws = &fsw->fsw_stats;
	bool is_ipv4 = (fe->fe_key.fk_ipver == IPVERSION);

	SK_LOG_VAR(uint64_t logflags = (SK_VERB_FSW | SK_VERB_RX));

	/* state for mbuf batch alloc */
	uint32_t mhead_cnt;
	uint32_t mhead_bufsize;
	struct mbuf * mhead = NULL;

	uint16_t l2len = KPKTQ_FIRST(&fe->fe_rx_pktq)->pkt_l2_len;

	SK_DF(logflags, "Rx input queue bytes %u", fe->fe_rx_pktq_bytes);

	if (__probable(!is_mbuf)) {
		uint32_t max_ip_len = MIN(sk_fsw_rx_agg_tcp, IP_MAXPACKET);

		/*
		 *  Batch mbuf alloc is based on
		 * convert_native_pkt_to_mbuf_chain
		 */
		if (__probable(fe->fe_rx_largest_msize != 0 &&
		    max_ip_len > 0)) {
			unsigned int one;
			int wait;

			if (fe->fe_rx_largest_msize <= MCLBYTES) {
				mhead_bufsize = MCLBYTES;
			} else if (fe->fe_rx_largest_msize <= MBIGCLBYTES) {
				mhead_bufsize = MBIGCLBYTES;
			} else {
				mhead_bufsize = M16KCLBYTES;
			}

try_again:
			if (fe->fe_rx_pktq_bytes != 0) {
				uint32_t aggregation_size =
				    MAX(fe->fe_rx_largest_msize, MCLBYTES);

				aggregation_size =
				    MIN(aggregation_size, mhead_bufsize);

				factor = (fe->fe_rx_pktq_bytes / max_ip_len) *
				    (MAX(sizeof(struct ip),
				    sizeof(struct ip6_hdr)) +
				    sizeof(struct tcphdr));

				mhead_cnt = MAX(((fe->fe_rx_pktq_bytes +
				    factor) / aggregation_size) + 1, 1);
			} else {
				/* No payload, thus it's all small-sized ACKs/... */
				mhead_bufsize = MHLEN;
				mhead_cnt = KPKTQ_LEN(&fe->fe_rx_pktq);
			}

			one = 1;

			if (mhead_bufsize >= MBIGCLBYTES) {
				wait = M_NOWAIT;
			} else {
				wait = M_WAITOK;
			}

			mhead = m_allocpacket_internal(&mhead_cnt,
			    mhead_bufsize, &one, wait, 1, 0);

			if (mhead == NULL) {
				if (mhead_bufsize == M16KCLBYTES) {
					mhead_bufsize = MBIGCLBYTES;
					goto try_again;
				}

				if (mhead_bufsize == MBIGCLBYTES) {
					mhead_bufsize = MCLBYTES;
					goto try_again;
				}
			}
		} else {
			mhead = NULL;
			mhead_bufsize = mhead_cnt = 0;
		}
		SK_DF(logflags, "batch alloc'ed %u mbufs of size %u", mhead_cnt,
		    mhead_bufsize);
	}

	KPKTQ_FOREACH_SAFE(pkt, &fe->fe_rx_pktq, tpkt) {
		if (tpkt != NULL) {
			void *baddr;
			MD_BUFLET_ADDR_ABS_PKT(tpkt, baddr);
			SK_PREFETCH(baddr, 0);
		}

		/* Validate l2 len, ip vers, is_mbuf */
		ASSERT(pkt->pkt_l2_len == l2len);
		ASSERT(is_mbuf == !!(PKT_IS_MBUF(pkt)));
		ASSERT(fe->fe_key.fk_ipver == pkt->pkt_flow_ip_ver);
		ASSERT(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED);
		ASSERT((pkt->pkt_link_flags & PKT_LINKF_ETHFCS) == 0);
		ASSERT(!pkt->pkt_flow_ip_is_frag);
		ASSERT(pkt->pkt_flow_ip_proto == IPPROTO_TCP);

		csum_ok = false;
		agg_ok = false;
		/*
		 * As we only agg packets with same hdr length,
		 * leverage the pkt metadata
		 */
		uint32_t thlen = (pkt->pkt_flow_ip_hlen +
		    pkt->pkt_flow_tcp_hlen);
		uint32_t plen = (thlen + pkt->pkt_flow_ulen);

		/*
		 * Rather than calling flow_pkt_track() for each
		 * packet here, we accumulate received packet stats
		 * for the call to flow_track_stats() below.  This
		 * is because flow tracking is a no-op for traffic
		 * that belongs to the host stack.
		 */
		rcvd_ulen += pkt->pkt_flow_ulen;
		rcvd_bytes += pkt->pkt_length;
		rcvd_packets++;

		KPKTQ_REMOVE(&fe->fe_rx_pktq, pkt);
		fe->fe_rx_pktq_bytes -= pkt->pkt_flow_ulen;

		/* packet is for BSD flow, create a mbuf chain */
		uint32_t len = (l2len + plen);
		uint16_t data_csum = 0;
		struct mbuf *m;
		if (__improbable(is_mbuf)) {
			m = pkt->pkt_mbuf;
			/* Detach mbuf from source pkt */
			KPKT_CLEAR_MBUF_DATA(pkt);

			uint32_t trailer = (m_pktlen(m) - len);
			ASSERT((uint32_t)m_pktlen(m) >= plen);
			/* Remove the trailer */
			if (trailer > 0) {
				m_adj(m, -trailer);
			}
			/* attached mbuf is already allocated */
			csum_ok = mbuf_csum(pkt, m, is_ipv4, &data_csum);
		} else {                /* native */
			uint16_t pad = P2ROUNDUP(l2len, sizeof(uint32_t)) -
			    l2len;
			uint32_t tot_len = (len + pad);
			/* remember largest aggregated packet size */
			if (smbuf) {
				if (largest_smbuf < (uint32_t)m_pktlen(smbuf)) {
					largest_smbuf =
					    (uint32_t)m_pktlen(smbuf);
				}
			}

			if (prev_csum_ok && curr_m) {
				ASSERT(fa.fa_smbuf == smbuf);
				ASSERT(!fa.fa_sobj_is_pkt);
				agg_ok = flow_agg_is_ok(&fa, pkt, fsws);

				if (agg_ok &&
				    M_TRAILINGSPACE(curr_m) >= plen - thlen) {
					/*
					 * No need for a new mbuf,
					 * just append to curr_m.
					 */
					csum_ok = copy_pkt_csum_packed(pkt,
					    plen, NULL, is_ipv4, curr_m, NULL,
					    &data_csum, NULL);

					if (!csum_ok) {
						STATS_INC(fsws,
						    FSW_STATS_RX_AGG_BAD_CSUM);
						SK_ERR("Checksum for "
						    "aggregation is wrong");
						DTRACE_SKYWALK(aggr__host_packed_tcp_csum_fail1);
						/*
						 * Turns out, checksum is wrong!
						 * Fallback to no-agg mode.
						 */
						agg_ok = 0;
					} else {
						/*
						 * We only added payload,
						 * thus -thlen.
						 */
						bytes += (plen - thlen);
						flow_agg_merge_hdr(&fa, pkt,
						    data_csum, fsws);
						goto next;
					}
				}
			}

			/*
			 * If the batch allocation returned partial success,
			 * we try blocking allocation here again
			 */
			m = mhead;
			if (__improbable(m == NULL ||
			    tot_len > mhead_bufsize)) {
				unsigned int one = 1;

				ASSERT(mhead_cnt == 0 || mhead != NULL);
				err = mbuf_allocpacket(MBUF_WAITOK, tot_len,
				    &one, &m);
				if (err != 0) {
					STATS_INC(fsws,
					    FSW_STATS_RX_DROP_NOMEM_BUF);
					SK_ERR("mbuf alloc failed (err %d)",
					    err);
					__RX_AGG_HOST_DROP_SOURCE_PACKET(pkt);
					continue;
				}
				alloced++;
			} else {
				ASSERT(mhead_cnt > 0);
				mhead = m->m_nextpkt;
				m->m_nextpkt = NULL;
				mhead_cnt--;
			}
			m->m_data += pad;
			m->m_pkthdr.pkt_hdr = mtod(m, uint8_t *);

			/*
			 * copy and checksum l3, l4 and payload
			 * l2 header is copied later only if we
			 * can't agg as an optimization
			 */
			m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;
			_dbuf_array_t dbuf_array = {.dba_is_buflet = false};
			if (agg_ok) {
				int added = 0;
				dbuf_array.dba_mbuf[0] = m;
				dbuf_array.dba_num_dbufs = 1;
				csum_ok = copy_pkt_csum_packed(pkt, plen,
				    &dbuf_array, is_ipv4, curr_m, NULL,
				    &data_csum, &added);

				if (!csum_ok) {
					STATS_INC(fsws,
					    FSW_STATS_RX_AGG_BAD_CSUM);
					SK_ERR("Checksum for aggregation "
					    "on new mbuf is wrong");
					DTRACE_SKYWALK(aggr__host_packed_tcp_csum_fail2);
					agg_ok = false;
					goto non_agg;
				}

				/*
				 * There was not enough space in curr_m,
				 * thus we must have added to m->m_data.
				 */
				VERIFY(added > 0);
				VERIFY(m->m_len == m->m_pkthdr.len &&
				    (uint32_t)m->m_len <=
				    (uint32_t)mbuf_maxlen(m));

				/*
				 * We account for whatever we added
				 * to m later on, thus - added.
				 */
				bytes += plen - thlen - added;
			} else {
non_agg:
				dbuf_array.dba_mbuf[0] = m;
				dbuf_array.dba_num_dbufs = 1;
				m->m_len += l2len;
				m->m_pkthdr.len += l2len;
				csum_ok = copy_pkt_csum(pkt, plen, &dbuf_array,
				    &data_csum, is_ipv4);
				if (__improbable(!csum_ok)) {
					STATS_INC(fsws, FSW_STATS_RX_AGG_BAD_CSUM);
					SK_ERR("%d incorrect csum", __LINE__);
					DTRACE_SKYWALK(aggr__host_tcp_csum_fail);
				}
				VERIFY(m->m_len == m->m_pkthdr.len &&
				    (uint32_t)m->m_len <=
				    (uint32_t)mbuf_maxlen(m));
			}

			STATS_INC(fsws, FSW_STATS_RX_COPY_PKT2MBUF);
			STATS_INC(fsws, FSW_STATS_RX_COPY_SUM);

			m->m_pkthdr.csum_rx_start = pkt->pkt_csum_rx_start_off;
			m->m_pkthdr.csum_rx_val = pkt->pkt_csum_rx_value;
			/*
			 *  Note that these flags have same value,
			 * except PACKET_CSUM_PARTIAL
			 */
			m->m_pkthdr.csum_flags |= (pkt->pkt_csum_flags &
			    PACKET_CSUM_RX_FLAGS);

			/* Set the rcvif */
			m->m_pkthdr.rcvif = fsw->fsw_ifp;
		}
		ASSERT(m != NULL);
		ASSERT((m->m_flags & M_PKTHDR) && m->m_pkthdr.pkt_hdr != NULL);
		ASSERT((m->m_flags & M_HASFCS) == 0);
		ASSERT(m->m_nextpkt == NULL);

		if (__improbable(is_mbuf)) {
			if ((uint32_t) m->m_len < (l2len + thlen)) {
				m = m_pullup(m, (l2len + thlen));
				if (m == NULL) {
					STATS_INC(fsws,
					    FSW_STATS_RX_DROP_NOMEM_BUF);
					SK_ERR("mbuf pullup failed (err %d)",
					    err);
					__RX_AGG_HOST_DROP_SOURCE_PACKET(pkt);
					continue;
				}
				m->m_pkthdr.pkt_hdr = mtod(m, uint8_t *);
			}
			if (prev_csum_ok && csum_ok) {
				ASSERT(fa.fa_smbuf == smbuf);
				agg_ok = flow_agg_is_ok(&fa, pkt, fsws);
			}
		}

		if (agg_ok) {
			ASSERT(fa.fa_smbuf == smbuf);
			ASSERT(!fa.fa_sobj_is_pkt);
			if (__improbable(is_mbuf)) {
				bytes += (m_pktlen(m) - l2len);
				/* adjust mbuf by l2, l3 and l4  hdr */
				m_adj(m, l2len + thlen);
			} else {
				bytes += m_pktlen(m);
			}

			m->m_flags &= ~M_PKTHDR;
			flow_agg_merge_hdr(&fa, pkt, data_csum, fsws);
			while (curr_m->m_next != NULL) {
				curr_m = curr_m->m_next;
			}
			curr_m->m_next = m;
			curr_m = m;
			m = NULL;
		} else {
			if ((uint32_t) m->m_len < l2len) {
				m = m_pullup(m, l2len);
				if (m == NULL) {
					STATS_INC(fsws,
					    FSW_STATS_RX_DROP_NOMEM_BUF);
					SK_ERR("mbuf pullup failed (err %d)",
					    err);
					__RX_AGG_HOST_DROP_SOURCE_PACKET(pkt);
					continue;
				}
				m->m_pkthdr.pkt_hdr = mtod(m, uint8_t *);
			}

			/* copy l2 header for native */
			if (__probable(!is_mbuf)) {
				uint16_t llhoff = pkt->pkt_headroom;
				uint8_t *baddr;
				MD_BUFLET_ADDR_ABS(pkt, baddr);
				ASSERT(baddr != NULL);
				baddr += llhoff;
				pkt_copy(baddr, m->m_data, l2len);
			}
			/* adjust mbuf by l2 hdr */
			m_adj(m, l2len);
			bytes += m_pktlen(m);

			/*
			 * aggregated packets can be skipped by pktap because
			 * the original pre-aggregated chain already passed through
			 * pktap (see fsw_snoop()) before entering this function.
			 */
			m->m_pkthdr.pkt_flags |= PKTF_SKIP_PKTAP;

			if (m_chain == NULL) {
				/* this is the start of the chain */
				m_chain = m;
				smbuf = m;
				curr_m = m;
			} else if (smbuf != NULL) {
				/*
				 * set m to be next packet
				 */
				mbuf_agg_log(smbuf, kernproc, is_mbuf);
				smbuf->m_nextpkt = m;
				smbuf = m;
				curr_m = m;
			} else {
				VERIFY(0);
			}

			smbufs++;
			m = NULL;

			flow_agg_init_smbuf(&fa, smbuf, pkt);
			/*
			 * if the super packet is an mbuf which can't accomodate
			 * (sizeof(struct ip6_tcp_mask) in a single buffer then
			 * do the aggregation check in slow path.
			 * Note that an mbuf without cluster has only 80 bytes
			 * available for data, sizeof(struct ip6_tcp_mask) is
			 * also 80 bytes, so if the packet contains an
			 * ethernet header, this mbuf won't be able to fully
			 * contain "struct ip6_tcp_mask" data in a single
			 * buffer.
			 */
			if (pkt->pkt_flow_ip_ver == IPV6_VERSION) {
				if (__improbable(smbuf->m_len <
				    ((smbuf->m_data -
				    (caddr_t)(smbuf->m_pkthdr.pkt_hdr)) +
				    MASK_SIZE))) {
					fa.fa_sobj_is_short = true;
				}
			}
		}
next:
		pkt_agg_log(pkt, kernproc, true);
		prev_csum_ok = csum_ok;
		KPKTQ_ENQUEUE(&disposed_pkts, pkt);
	}

	KPKTQ_FINI(&fe->fe_rx_pktq);

	/* Free any leftover mbufs, true only for native  */
	if (__improbable(mhead != NULL)) {
		ASSERT(mhead_cnt != 0);
		(void) m_freem_list(mhead);
		mhead = NULL;
		mhead_cnt = 0;
		mhead_bufsize = 0;
	}

	if (fe->fe_rx_largest_msize > largest_smbuf) {
		/*
		 * Make it slowly move towards smbuf if we consistently get
		 * non-aggregatable size.
		 *
		 * If we start at 16K, this makes us go to 4K within 6 rounds
		 * and down to 2K within 12 rounds.
		 */
		fe->fe_rx_largest_msize -=
		    ((fe->fe_rx_largest_msize - largest_smbuf) >> 2);
	} else {
		fe->fe_rx_largest_msize +=
		    ((largest_smbuf - fe->fe_rx_largest_msize) >> 2);
	}

	if (smbufs > 0) {
		/* Last smbuf */
		mbuf_agg_log(smbuf, kernproc, is_mbuf);
		SK_DF(logflags, "smbuf count %u", smbufs);

		ASSERT(m_chain != NULL);
		ASSERT(smbuf != NULL);
		/*
		 * Call fsw_host_sendup() with mbuf chain
		 * directly.
		 */
		mchain_agg_log(m_chain, kernproc, is_mbuf);
		fsw_host_sendup(fsw->fsw_ifp, m_chain, smbuf, smbufs, bytes);

		if (__improbable(is_mbuf)) {
			STATS_ADD(fsws, FSW_STATS_RX_AGG_MBUF2MBUF, smbufs);
		} else {
			STATS_ADD(fsws, FSW_STATS_RX_AGG_PKT2MBUF, smbufs);
		}
		FLOW_STATS_IN_ADD(fe, spackets, smbufs);

		ASSERT((fe->fe_flags & FLOWENTF_TRACK) == 0);
	}

	/* record (raw) number of packets and bytes */
	ASSERT((int)(rcvd_bytes - drop_bytes) > 0);
	ASSERT((int)(rcvd_packets - drop_packets) > 0);
	flow_track_stats(fe, (rcvd_bytes - drop_bytes),
	    (rcvd_packets - drop_packets), (rcvd_ulen != 0), true);

	pp_free_pktq(&disposed_pkts);
}

void
flow_rx_agg_tcp(struct nx_flowswitch *fsw, struct flow_entry *fe)
{
	struct pktq dropped_pkts;
	bool is_mbuf;

	if (__improbable(fe->fe_rx_frag_count > 0)) {
		dp_flow_rx_process(fsw, fe);
		return;
	}

	KPKTQ_INIT(&dropped_pkts);

	if (!dp_flow_rx_route_process(fsw, fe)) {
		SK_ERR("Rx route bad");
		fsw_snoop_and_dequeue(fe, &dropped_pkts, true);
		STATS_ADD(&fsw->fsw_stats, FSW_STATS_RX_FLOW_NONVIABLE,
		    KPKTQ_LEN(&dropped_pkts));
		goto done;
	}

	is_mbuf = !!(PKT_IS_MBUF(KPKTQ_FIRST(&fe->fe_rx_pktq)));

	if (fe->fe_nx_port == FSW_VP_HOST) {
		boolean_t do_rx_agg;

		/* BSD flow */
		if (sk_fsw_rx_agg_tcp_host != SK_FSW_RX_AGG_TCP_HOST_AUTO) {
			do_rx_agg = (sk_fsw_rx_agg_tcp_host ==
			    SK_FSW_RX_AGG_TCP_HOST_ON);
		} else {
			do_rx_agg = !dlil_has_ip_filter() &&
			    !dlil_has_if_filter(fsw->fsw_ifp);
		}
		if (__improbable(!do_rx_agg)) {
			fsw_host_rx(fsw, fe);
			return;
		}
		if (__improbable(pktap_total_tap_count != 0)) {
			fsw_snoop(fsw, fe, true);
		}
		flow_rx_agg_host(fsw, fe, &dropped_pkts, is_mbuf);
	} else {
		/* channel flow */
		if (__improbable(pktap_total_tap_count != 0)) {
			fsw_snoop(fsw, fe, true);
		}
		flow_rx_agg_channel(fsw, fe, &dropped_pkts, is_mbuf);
	}

done:
	pp_free_pktq(&dropped_pkts);
}
