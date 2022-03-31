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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#define CL_SKIP_ON(t)                           \
	if (__improbable(t)) {                  \
	        SK_ERR("%d: skip " #t, __LINE__); \
	        SK_ERR("%s %s", if_name(ifp), sk_dump("buf", \
	            pkt_buf + pkt->pkt_headroom, pkt->pkt_length, \
	            MIN(128, bdlen), NULL, 0)); \
	        error = ENOTSUP;                \
	        goto done;                      \
	}

#define CL_SKIP_L4()                            \
	do {                                    \
	        pkt->pkt_flow_ip_hlen = l3hlen; \
	        pkt->pkt_flow_tcp_src = 0;      \
	        pkt->pkt_flow_tcp_dst = 0;      \
	        error = 0;                      \
	        goto done;                      \
	} while (0);

/*
 * Packet flow parser
 *
 * Parse a continuous chunk of packet header fields.
 *
 * The idea here is that while we have the headers in the CPU cache,
 * do as much parsing as necessary and store the results in __flow.
 *
 * We assume that outbound packets from the host (BSD) stack never
 * get here, i.e. we only handle channel-based outbound traffic.
 *
 * @param pkt
 *   packet to be classified
 * @param ifp
 *   associated network interface
 * @param af
 *   address family
 * @param input
 *   is it input
 *
 * @return
 * We return ENOTSUP to indicate that we can't classify the packet,
 * and that the packet should still be forwarded to the lookup path.
 * Any other non-zero value will cause the packet to be dropped.
 *
 */
int
flow_pkt_classify(struct __kern_packet *pkt, struct ifnet *ifp, sa_family_t af,
    bool input)
{
	/* these begin at the same offset in the packet, hence the unions */
	union {
		volatile struct ip *_iph;
		volatile struct ip6_hdr *_ip6;
	} _l3;
#define iph _l3._iph
#define ip6 _l3._ip6
	union {
		volatile struct tcphdr *_tcph;
		volatile struct udphdr *_udph;
	} _l4;
#define tcph _l4._tcph
#define udph _l4._udph
	uint32_t mtu = ifp->if_mtu;

	size_t pkt_len;       /* remaining packet length left for parsing */
	uint16_t cls_len;

	/*
	 * These are length parsed from packet header, needs to be
	 * incrementally validated from l3 to l4
	 */
	uint8_t l3hlen = 0;    /* IP header length */
	uint16_t l3tlen = 0;    /* total length of IP packet */
	uint8_t l4hlen = 0;    /* TCP/UDP header length */
	uint16_t ulen = 0;      /* user data length */

	int error = 0;

	/* must be 16-bytes aligned due to use of sk_copy* below */
	_CASSERT((offsetof(struct __flow, flow_l3) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_ipv4_src) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_ipv6_src) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_l4) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_tcp_src) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_udp_src) % 16) == 0);
	_CASSERT((offsetof(struct __flow, flow_esp_spi) % 16) == 0);

	_CASSERT(sizeof(struct __flow_l3_ipv4_addrs) == 8);
	_CASSERT((offsetof(struct __flow_l3_ipv4_addrs, _dst) -
	    offsetof(struct __flow_l3_ipv4_addrs, _src)) ==
	    (offsetof(struct ip, ip_dst) - offsetof(struct ip, ip_src)));

	_CASSERT(sizeof(struct __flow_l3_ipv6_addrs) == 32);
	_CASSERT((offsetof(struct __flow_l3_ipv6_addrs, _dst) -
	    offsetof(struct __flow_l3_ipv6_addrs, _src)) ==
	    (offsetof(struct ip6_hdr, ip6_dst) -
	    offsetof(struct ip6_hdr, ip6_src)));

	/* __flow_l4_tcp must mirror tcphdr for the first 16-bytes */
	_CASSERT(sizeof(struct __flow_l4_tcp) == 16);
	_CASSERT((offsetof(struct __flow_l4_tcp, _dst) -
	    offsetof(struct __flow_l4_tcp, _src)) ==
	    (offsetof(struct tcphdr, th_dport) -
	    offsetof(struct tcphdr, th_sport)));
	_CASSERT((offsetof(struct __flow_l4_tcp, _seq) -
	    offsetof(struct __flow_l4_tcp, _src)) ==
	    (offsetof(struct tcphdr, th_seq) -
	    offsetof(struct tcphdr, th_sport)));
	_CASSERT((offsetof(struct __flow_l4_tcp, _ack) -
	    offsetof(struct __flow_l4_tcp, _src)) ==
	    (offsetof(struct tcphdr, th_ack) -
	    offsetof(struct tcphdr, th_sport)));
	_CASSERT((offsetof(struct __flow_l4_tcp, _flags) -
	    offsetof(struct __flow_l4_tcp, _src)) ==
	    (offsetof(struct tcphdr, th_flags) -
	    offsetof(struct tcphdr, th_sport)));
	_CASSERT((offsetof(struct __flow_l4_tcp, _win) -
	    offsetof(struct __flow_l4_tcp, _src)) ==
	    (offsetof(struct tcphdr, th_win) -
	    offsetof(struct tcphdr, th_sport)));

	/* ensure same offsets use for TCP and UDP */
	_CASSERT(sizeof(struct __flow_l4_udp) == 8);
	_CASSERT(offsetof(struct __flow, flow_tcp_src) ==
	    offsetof(struct __flow, flow_udp_src));
	_CASSERT(offsetof(struct __flow, flow_tcp_dst) ==
	    offsetof(struct __flow, flow_udp_dst));


	/* parsing starts from l3, count SDU length after l2 header */
	ASSERT(pkt->pkt_l2_len <= pkt->pkt_length);
	pkt_len = pkt->pkt_length - pkt->pkt_l2_len;

	/*
	 * we restrict the data length available for classification to the
	 * portion of L3 datagram available in the first buflet.
	 */
	/*
	 * compat netif sets the packet length and buflet data length
	 * metadata to the original length of the packet although the
	 * actual buffer is limited to NETIF_COMPAT_BUF_SIZE (128 bytes).
	 */
	uint8_t *pkt_buf, *l3_hdr;
	uint16_t bdlen, bdlim, bdoff;

	MD_BUFLET_ADDR_ABS_DLEN(pkt, pkt_buf, bdlen, bdlim, bdoff);
	cls_len = bdlim - bdoff;
	cls_len -= pkt->pkt_l2_len;
	cls_len = (uint16_t)MIN(cls_len, pkt_len);
	VERIFY(pkt_len >= cls_len);

	/* takes care of ip6 assignment too */
	l3_hdr = pkt_buf + pkt->pkt_headroom + pkt->pkt_l2_len;
	iph = (volatile struct ip *)(void *)l3_hdr;

	VERIFY(af != AF_UNSPEC);

	pkt->pkt_flow_ip_ver = 0;

	/*
	 * This code is in the hot data path, so we try to be as efficient
	 * as possible, and hence the use of unrolled loads/stores.
	 */

	/***************** L3 header (IP/IPv6) *****************/
	switch (af) {
	case AF_INET:
		CL_SKIP_ON(cls_len < sizeof(struct ip));
		l3hlen = (uint8_t)(iph->ip_hl << 2);
		CL_SKIP_ON(l3hlen < sizeof(struct ip));
		CL_SKIP_ON(cls_len < l3hlen);

		/* don't allow outgoing channel-based packet with option(s) */
		CL_SKIP_ON(!input && l3hlen != sizeof(struct ip));

		l3tlen = ntohs(iph->ip_len);

		CL_SKIP_ON(l3tlen < l3hlen);
		CL_SKIP_ON(pkt_len < l3tlen);
		CL_SKIP_ON(iph->ip_v != IPVERSION);

		if (__probable(IS_P2ALIGNED(&iph->ip_src, 8))) {
			sk_copy64_8(__DECONST(uint64_t *, &iph->ip_src),
			    (uint64_t *)(void *)&pkt->pkt_flow_ipv4_src);
		} else if (IS_P2ALIGNED(&iph->ip_src, 4)) {
			sk_copy32_8(__DECONST(uint32_t *, &iph->ip_src),
			    (uint32_t *)(void *)&pkt->pkt_flow_ipv4_src);
		} else {
			bcopy(__DECONST(void *, &iph->ip_src),
			    (void *)&pkt->pkt_flow_ipv4_addrs,
			    sizeof(struct __flow_l3_ipv4_addrs));
		}

		pkt->pkt_flow_ip_ver = IPVERSION;
		pkt->pkt_flow_ip_proto = iph->ip_p;
		pkt->pkt_flow_ip_hdr = (mach_vm_address_t)iph;

		if (__improbable(ntohs(iph->ip_off) & ~(IP_DF | IP_RF))) {
			pkt->pkt_flow_ip_is_frag = TRUE;
			pkt->pkt_flow_ip_frag_id = iph->ip_id;
			/* we only parse l4 in the 1st frag */
			if ((ntohs(iph->ip_off) & IP_OFFMASK) != 0) {
				pkt->pkt_flow_ip_is_first_frag = FALSE;
				CL_SKIP_L4();
			} else {
				pkt->pkt_flow_ip_is_first_frag = TRUE;
			}
		}
		break;

	case AF_INET6:
		l3hlen = sizeof(struct ip6_hdr);
		CL_SKIP_ON(cls_len < l3hlen);

		l3tlen = l3hlen + ntohs(ip6->ip6_plen);
		CL_SKIP_ON(pkt_len < l3tlen);
		CL_SKIP_ON((ip6->ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION);

		if (__probable(IS_P2ALIGNED(&ip6->ip6_src, 8))) {
			sk_copy64_32(__DECONST(uint64_t *, &ip6->ip6_src),
			    (uint64_t *)(void *)&pkt->pkt_flow_ipv6_src);
		} else if (IS_P2ALIGNED(&ip6->ip6_src, 4)) {
			sk_copy32_32(__DECONST(uint32_t *, &ip6->ip6_src),
			    (uint32_t *)(void *)&pkt->pkt_flow_ipv6_src);
		} else {
			bcopy(__DECONST(void *, &ip6->ip6_src),
			    (void *)&pkt->pkt_flow_ipv6_addrs,
			    sizeof(struct __flow_l3_ipv6_addrs));
		}

		pkt->pkt_flow_ip_ver = IPV6_VERSION;
		pkt->pkt_flow_ip_proto = ip6->ip6_nxt;
		pkt->pkt_flow_ip_hdr = (mach_vm_address_t)ip6;

		/* only parse the next immediate extension header for frags */
		if (__improbable(ip6->ip6_nxt == IPPROTO_FRAGMENT)) {
			volatile struct ip6_frag *ip6f;
			ip6f = (volatile struct ip6_frag *)(ip6 + 1);
			CL_SKIP_ON(cls_len < l3hlen + sizeof(struct ip6_frag));
			pkt->pkt_flow_ip_is_frag = 1;
			pkt->pkt_flow_ip_frag_id = ip6f->ip6f_ident;
			pkt->pkt_flow_ip_proto = ip6f->ip6f_nxt;
			l3hlen += sizeof(struct ip6_frag);
			CL_SKIP_ON(l3tlen < l3hlen);
			/* we only parse l4 in the 1st frag */
			if ((ip6f->ip6f_offlg & IP6F_OFF_MASK) != 0) {
				pkt->pkt_flow_ip_is_first_frag = FALSE;
				CL_SKIP_L4();
			} else {
				pkt->pkt_flow_ip_is_first_frag = TRUE;
			}
			/* process atomic frag as non-frag */
			if ((ip6f->ip6f_offlg & ~IP6F_RESERVED_MASK) == 0) {
				pkt->pkt_flow_ip_is_frag = 0;
			}
		}
		break;

	default:
		error = ENOTSUP;
		goto done;
	}

	pkt->pkt_flow_ip_hlen = l3hlen;
	if (__improbable(pkt->pkt_flow_ip_proto != IPPROTO_TCP &&
	    pkt->pkt_flow_ip_proto != IPPROTO_UDP)) {
		error = 0;
		goto done;
	}

	/**************** L4 header (TCP/UDP) *****************/

	/* this takes care of UDP header as well (see l4 union var) */
	tcph = __DECONST(volatile struct tcphdr *,
	    (volatile uint8_t *)iph + l3hlen);
	ulen = (l3tlen - l3hlen);
	if (__probable(pkt->pkt_flow_ip_proto == IPPROTO_TCP)) {
		CL_SKIP_ON((cls_len < l3hlen + sizeof(*tcph)) ||
		    (ulen < sizeof(*tcph)));
		l4hlen = (uint8_t)(tcph->th_off << 2);
		CL_SKIP_ON(l4hlen < sizeof(*tcph));
		CL_SKIP_ON(l4hlen > ulen);
		pkt->pkt_flow_tcp_hlen = l4hlen;
		pkt->pkt_flow_tcp_hdr = (mach_vm_address_t)tcph;
	} else {
		CL_SKIP_ON((cls_len < l3hlen + sizeof(*udph)) ||
		    (ulen < sizeof(*udph)));
		l4hlen = sizeof(*udph);
		CL_SKIP_ON(l4hlen > ulen);
		pkt->pkt_flow_udp_hlen = l4hlen;
		pkt->pkt_flow_udp_hdr = (mach_vm_address_t)udph;
	}

	if (__probable(!pkt->pkt_flow_ip_is_frag)) {
		ulen -= l4hlen;
		pkt->pkt_flow_ulen = ulen;
	} else {
		/*
		 * We can't determine user data length for fragment until
		 * it is reassembled.
		 */
		pkt->pkt_flow_ulen = 0;
	}

	if (__probable(IS_P2ALIGNED(&tcph->th_sport, 4))) {
		if (__probable(pkt->pkt_flow_ip_proto == IPPROTO_TCP)) {
			sk_copy32_16(__DECONST(uint32_t *, &tcph->th_sport),
			    (uint32_t *)(void *)&pkt->pkt_flow_tcp_src);
		} else {
			sk_copy32_8(__DECONST(uint32_t *, &udph->uh_sport),
			    (uint32_t *)(void *)&pkt->pkt_flow_udp_src);
		}
	} else {
		if (__probable(pkt->pkt_flow_ip_proto == IPPROTO_TCP)) {
			bcopy(__DECONST(void *, &tcph->th_sport),
			    (void *)&pkt->pkt_flow_tcp,
			    sizeof(struct __flow_l4_tcp));
		} else {
			bcopy(__DECONST(void *, &udph->uh_sport),
			    (void *)&pkt->pkt_flow_udp,
			    sizeof(struct __flow_l4_udp));
		}
	}

	if (!input && pkt->pkt_flow_ip_proto == IPPROTO_TCP &&
	    pkt->pkt_flow_ulen != 0) {
		/*
		 * Following the logic in tcp_output(), we mark
		 * this if the payload is non-zero; note that
		 * the pkt_flow_tcp_seq is in network byte order.
		 */
		pkt->pkt_pflags |= PKT_F_START_SEQ;
	}
done:
	if (__probable(error == 0)) {
		SK_DF(SK_VERB_FLOW_CLASSIFY, "pkt_length %u l3_ip_len %u "
		    "l3_ip_ver 0x%x l3_proto %u l4_sport %u l4_dport %u",
		    pkt->pkt_length, l3tlen, pkt->pkt_flow_ip_ver,
		    pkt->pkt_flow_ip_proto, ntohs(pkt->pkt_flow_tcp_src),
		    ntohs(pkt->pkt_flow_tcp_dst));
		/* on output, trim metadata length if not same as IP length */
		if (!input) {
			if (__improbable(pkt->pkt_length != l3tlen)) {
				SK_ERR("packet is too long (%u), trimming to "
				    "IP length (%d)", pkt->pkt_length, l3tlen);
				METADATA_SET_LEN(pkt, l3tlen, bdoff);
			}
			if (__improbable(pkt->pkt_length > mtu)) {
				SK_ERR("dropped; length (%u) exceeds MTU (%d)",
				    pkt->pkt_length, mtu);
				SK_ERR("%s", sk_dump("buf", l3_hdr, cls_len,
				    128, NULL, 0));
				error = EMSGSIZE;
				goto fail;
			}
		}
		/*
		 * Mark QUM_F_FLOW_CLASSIFIED on the packet to indicate
		 * that the __flow structure has valid info now.
		 */
		pkt->pkt_qum_qflags |= QUM_F_FLOW_CLASSIFIED;
		return 0;
	}

fail:
	ASSERT(error != 0 && !(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED));
	KPKT_CLEAR_FLOW_ALL(pkt->pkt_flow);

	return error;
}
