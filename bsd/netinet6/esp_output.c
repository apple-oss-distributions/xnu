/*
 * Copyright (c) 2008-2017, 2022-2023 Apple Inc. All rights reserved.
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

/*	$FreeBSD: src/sys/netinet6/esp_output.c,v 1.1.2.3 2002/04/28 05:40:26 suz Exp $	*/
/*	$KAME: esp_output.c,v 1.44 2001/07/26 06:53:15 jinmei Exp $	*/

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

#define _IP_VHL

/*
 * RFC1827/2406 Encapsulated Security Payload.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/syslog.h>

#include <net/if.h>
#include <net/route.h>
#include <net/multi_layer_pkt_log.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_var.h>
#include <netinet/udp.h> /* for nat traversal */
#include <netinet/tcp.h>
#include <netinet/in_tclass.h>

#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/icmp6.h>

#include <netinet6/ipsec.h>
#include <netinet6/ipsec6.h>
#include <netinet6/ah.h>
#include <netinet6/ah6.h>
#include <netinet6/esp.h>
#include <netinet6/esp6.h>
#include <netkey/key.h>
#include <netkey/keydb.h>

#include <net/net_osdep.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#endif // SKYWALK

#include <sys/kdebug.h>
#define DBG_LAYER_BEG           NETDBG_CODE(DBG_NETIPSEC, 1)
#define DBG_LAYER_END           NETDBG_CODE(DBG_NETIPSEC, 3)
#define DBG_FNC_ESPOUT          NETDBG_CODE(DBG_NETIPSEC, (4 << 8))
#define DBG_FNC_ENCRYPT         NETDBG_CODE(DBG_NETIPSEC, (5 << 8))

static int esp_output(struct mbuf *, u_char *, struct mbuf *,
    int, struct secasvar *sav);

extern int      esp_udp_encap_port;
extern u_int64_t natt_now;

/*
 * compute ESP header size.
 */
size_t
esp_hdrsiz(__unused struct ipsecrequest *isr)
{
#if 0
	/* sanity check */
	if (isr == NULL) {
		panic("esp_hdrsiz: NULL was passed.");
	}


	lck_mtx_lock(sadb_mutex);
	{
		struct secasvar *sav;
		const struct esp_algorithm *algo;
		const struct ah_algorithm *aalgo;
		size_t ivlen;
		size_t authlen;
		size_t hdrsiz;
		size_t maxpad;

		/*%%%% this needs to change - no sav in ipsecrequest any more */
		sav = isr->sav;

		if (isr->saidx.proto != IPPROTO_ESP) {
			panic("unsupported mode passed to esp_hdrsiz");
		}

		if (sav == NULL) {
			goto estimate;
		}
		if (sav->state != SADB_SASTATE_MATURE
		    && sav->state != SADB_SASTATE_DYING) {
			goto estimate;
		}

		/* we need transport mode ESP. */
		algo = esp_algorithm_lookup(sav->alg_enc);
		if (!algo) {
			goto estimate;
		}
		ivlen = sav->ivlen;
		if (ivlen < 0) {
			goto estimate;
		}

		if (algo->padbound) {
			maxpad = algo->padbound;
		} else {
			maxpad = 4;
		}
		maxpad += 1; /* maximum 'extendsiz' is padbound + 1, see esp_output */

		if (sav->flags & SADB_X_EXT_OLD) {
			/* RFC 1827 */
			hdrsiz = sizeof(struct esp) + ivlen + maxpad;
		} else {
			/* RFC 2406 */
			aalgo = ah_algorithm_lookup(sav->alg_auth);
			if (aalgo && sav->replay[0] != NULL && sav->key_auth) {
				authlen = (aalgo->sumsiz)(sav);
			} else {
				authlen = 0;
			}
			hdrsiz = sizeof(struct newesp) + ivlen + maxpad + authlen;
		}

		/*
		 * If the security association indicates that NATT is required,
		 * add the size of the NATT encapsulation header:
		 */
		if ((sav->flags & SADB_X_EXT_NATT) != 0) {
			hdrsiz += sizeof(struct udphdr) + 4;
		}

		lck_mtx_unlock(sadb_mutex);
		return hdrsiz;
	}
estimate:
	lck_mtx_unlock(sadb_mutex);
#endif
	/*
	 * ASSUMING:
	 *	sizeof(struct newesp) > sizeof(struct esp). (8)
	 *	esp_max_ivlen() = max ivlen for CBC mode
	 *	17 = (maximum padding length without random padding length)
	 *	   + (Pad Length field) + (Next Header field).
	 *	64 = maximum ICV we support.
	 *  sizeof(struct udphdr) in case NAT traversal is used
	 */
	return sizeof(struct newesp) + esp_max_ivlen() + 17 + AH_MAXSUMSIZE + sizeof(struct udphdr);
}

/*
 * Modify the packet so that the payload is encrypted.
 * The mbuf (m) must start with IPv4 or IPv6 header.
 * On failure, free the given mbuf and return NULL.
 *
 * on invocation:
 *	m   nexthdrp md
 *	v   v        v
 *	IP ......... payload
 * during the encryption:
 *	m   nexthdrp mprev md
 *	v   v        v     v
 *	IP ............... esp iv payload pad padlen nxthdr
 *	                   <--><-><------><--------------->
 *	                   esplen plen    extendsiz
 *	                       ivlen
 *	                   <-----> esphlen
 *	<-> hlen
 *	<-----------------> espoff
 */
static int
esp_output(
	struct mbuf *m,
	u_char *nexthdrp,
	struct mbuf *md,
	int af,
	struct secasvar *sav)
{
	struct mbuf *n;
	struct mbuf *mprev;
	struct esp *esp;
	struct esptail *esptail;
	const struct esp_algorithm *algo;
	struct tcphdr th = {};
	u_int32_t spi;
	u_int32_t seq;
	size_t inner_payload_len = 0;
	u_int8_t inner_protocol = 0;
	u_int8_t nxt = 0;
	size_t plen;    /*payload length to be encrypted*/
	size_t espoff;
	size_t esphlen; /* sizeof(struct esp/newesp) + ivlen */
	int ivlen;
	int afnumber;
	size_t extendsiz;
	int error = 0;
	struct ipsecstat *stat;
	struct udphdr *udp = NULL;
	int     udp_encapsulate = (sav->flags & SADB_X_EXT_NATT && (af == AF_INET || af == AF_INET6) &&
	    ((esp_udp_encap_port & 0xFFFF) != 0 || sav->natt_encapsulated_src_port != 0));

	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_START, sav->ivlen, 0, 0, 0, 0);
	switch (af) {
	case AF_INET:
		afnumber = 4;
		stat = &ipsecstat;
		break;
	case AF_INET6:
		afnumber = 6;
		stat = &ipsec6stat;
		break;
	default:
		ipseclog((LOG_ERR, "esp_output: unsupported af %d\n", af));
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 1, 0, 0, 0, 0);
		return 0;       /* no change at all */
	}

	mbuf_traffic_class_t traffic_class = 0;
	if ((sav->flags2 & SADB_X_EXT_SA2_SEQ_PER_TRAFFIC_CLASS) ==
	    SADB_X_EXT_SA2_SEQ_PER_TRAFFIC_CLASS) {
		u_int8_t dscp = 0;
		switch (af) {
		case AF_INET:
		{
			struct ip *ip = mtod(m, struct ip *);
			dscp = ip->ip_tos >> IPTOS_DSCP_SHIFT;
			break;
		}
		case AF_INET6:
		{
			struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
			dscp = (ntohl(ip6->ip6_flow) & IP6FLOW_DSCP_MASK) >> IP6FLOW_DSCP_SHIFT;
			break;
		}
		default:
			panic("esp_output: should not reach here");
		}
		traffic_class = rfc4594_dscp_to_tc(dscp);
	}

	/* some sanity check */
	if ((sav->flags & SADB_X_EXT_OLD) == 0 && sav->replay[traffic_class] == NULL) {
		switch (af) {
		case AF_INET:
		{
			struct ip *ip;

			ip = mtod(m, struct ip *);
			ipseclog((LOG_DEBUG, "esp4_output: internal error: "
			    "sav->replay is null: %x->%x, SPI=%u\n",
			    (u_int32_t)ntohl(ip->ip_src.s_addr),
			    (u_int32_t)ntohl(ip->ip_dst.s_addr),
			    (u_int32_t)ntohl(sav->spi)));
			IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
			break;
		}
		case AF_INET6:
			ipseclog((LOG_DEBUG, "esp6_output: internal error: "
			    "sav->replay is null: SPI=%u\n",
			    (u_int32_t)ntohl(sav->spi)));
			IPSEC_STAT_INCREMENT(ipsec6stat.out_inval);
			break;
		default:
			panic("esp_output: should not reach here");
		}
		m_freem(m);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 2, 0, 0, 0, 0);
		return EINVAL;
	}

	algo = esp_algorithm_lookup(sav->alg_enc);
	if (!algo) {
		ipseclog((LOG_ERR, "esp_output: unsupported algorithm: "
		    "SPI=%u\n", (u_int32_t)ntohl(sav->spi)));
		m_freem(m);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 3, 0, 0, 0, 0);
		return EINVAL;
	}
	spi = sav->spi;
	ivlen = sav->ivlen;
	/* should be okey */
	if (ivlen < 0) {
		panic("invalid ivlen");
	}

	{
		/*
		 * insert ESP header.
		 * XXX inserts ESP header right after IPv4 header.  should
		 * chase the header chain.
		 * XXX sequential number
		 */
		struct ip *ip = NULL;
		struct ip6_hdr *ip6 = NULL;
		size_t esplen; /* sizeof(struct esp/newesp) */
		size_t hlen = 0; /* ip header len */

		if (sav->flags & SADB_X_EXT_OLD) {
			/* RFC 1827 */
			esplen = sizeof(struct esp);
		} else {
			/* RFC 2406 */
			if (sav->flags & SADB_X_EXT_DERIV) {
				esplen = sizeof(struct esp);
			} else {
				esplen = sizeof(struct newesp);
			}
		}
		esphlen = esplen + ivlen;

		for (mprev = m; mprev && mprev->m_next != md; mprev = mprev->m_next) {
			;
		}
		if (mprev == NULL || mprev->m_next != md) {
			ipseclog((LOG_DEBUG, "esp%d_output: md is not in chain\n",
			    afnumber));
			m_freem(m);
			KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 4, 0, 0, 0, 0);
			return EINVAL;
		}

		plen = 0;
		for (n = md; n; n = n->m_next) {
			plen += n->m_len;
		}

		switch (af) {
		case AF_INET:
			ip = mtod(m, struct ip *);
#ifdef _IP_VHL
			hlen = IP_VHL_HL(ip->ip_vhl) << 2;
#else
			hlen = ip->ip_hl << 2;
#endif
			break;
		case AF_INET6:
			ip6 = mtod(m, struct ip6_hdr *);
			hlen = sizeof(*ip6);
			break;
		}

		/* grab info for packet logging */
		struct secashead *sah = sav->sah;
		if (net_mpklog_enabled &&
		    sah != NULL && sah->ipsec_if != NULL) {
			ifnet_t ifp = sah->ipsec_if;

			if ((ifp->if_xflags & IFXF_MPK_LOG) == IFXF_MPK_LOG) {
				size_t iphlen = 0;

				if (sav->sah->saidx.mode == IPSEC_MODE_TUNNEL) {
					struct ip *inner_ip = mtod(md, struct ip *);
					if (IP_VHL_V(inner_ip->ip_vhl) == IPVERSION) {
#ifdef _IP_VHL
						iphlen = IP_VHL_HL(inner_ip->ip_vhl) << 2;
#else
						iphlen = inner_ip->ip_hl << 2;
#endif
						inner_protocol = inner_ip->ip_p;
					} else if (IP_VHL_V(inner_ip->ip_vhl) == 6) {
						struct ip6_hdr *inner_ip6 = mtod(md, struct ip6_hdr *);
						iphlen = sizeof(struct ip6_hdr);
						inner_protocol = inner_ip6->ip6_nxt;
					}

					if (inner_protocol == IPPROTO_TCP) {
						if ((int)(iphlen + sizeof(th)) <=
						    (m->m_pkthdr.len - m->m_len)) {
							m_copydata(md, (int)iphlen, sizeof(th), (u_int8_t *)&th);
						}

						inner_payload_len = m->m_pkthdr.len - m->m_len - iphlen - (th.th_off << 2);
					}
				} else {
					iphlen = hlen;
					if (af == AF_INET) {
						inner_protocol = ip->ip_p;
					} else if (af == AF_INET6) {
						inner_protocol = ip6->ip6_nxt;
					}

					if (inner_protocol == IPPROTO_TCP) {
						if ((int)(iphlen + sizeof(th)) <=
						    m->m_pkthdr.len) {
							m_copydata(m, (int)iphlen, sizeof(th), (u_int8_t *)&th);
						}

						inner_payload_len = m->m_pkthdr.len - iphlen - (th.th_off << 2);
					}
				}
			}
		}

		/* make the packet over-writable */
		mprev->m_next = NULL;
		if ((md = ipsec_copypkt(md)) == NULL) {
			m_freem(m);
			error = ENOBUFS;
			goto fail;
		}
		mprev->m_next = md;

		/*
		 * Translate UDP source port back to its original value.
		 * SADB_X_EXT_NATT_MULTIPLEUSERS is only set for transort mode.
		 */
		if ((sav->flags & SADB_X_EXT_NATT_MULTIPLEUSERS) != 0) {
			/* if not UDP - drop it */
			if (ip->ip_p != IPPROTO_UDP) {
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EINVAL;
				goto fail;
			}

			udp = mtod(md, struct udphdr *);

			/* if src port not set in sav - find it */
			if (sav->natt_encapsulated_src_port == 0) {
				if (key_natt_get_translated_port(sav) == 0) {
					m_freem(m);
					error = EINVAL;
					goto fail;
				}
			}
			if (sav->remote_ike_port == htons(udp->uh_dport)) {
				/* translate UDP port */
				udp->uh_dport = sav->natt_encapsulated_src_port;
				udp->uh_sum = 0; /* don't need checksum with ESP auth */
			} else {
				/* drop the packet - can't translate the port */
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EINVAL;
				goto fail;
			}
		}


		espoff = m->m_pkthdr.len - plen;

		if (udp_encapsulate) {
			esphlen += sizeof(struct udphdr);
			espoff += sizeof(struct udphdr);
		}

		/*
		 * grow the mbuf to accomodate ESP header.
		 * before: IP ... payload
		 * after:  IP ... [UDP] ESP IV payload
		 */
		if (M_LEADINGSPACE(md) < esphlen || (md->m_flags & M_EXT) != 0) {
			MGET(n, M_DONTWAIT, MT_DATA);
			if (!n) {
				m_freem(m);
				error = ENOBUFS;
				goto fail;
			}
			VERIFY(esphlen <= INT32_MAX);
			n->m_len = (int)esphlen;
			mprev->m_next = n;
			n->m_next = md;
			m->m_pkthdr.len += esphlen;
			if (udp_encapsulate) {
				udp = mtod(n, struct udphdr *);
				esp = (struct esp *)(void *)((caddr_t)udp + sizeof(struct udphdr));
			} else {
				esp = mtod(n, struct esp *);
			}
		} else {
			md->m_len += esphlen;
			md->m_data -= esphlen;
			m->m_pkthdr.len += esphlen;
			esp = mtod(md, struct esp *);
			if (udp_encapsulate) {
				udp = mtod(md, struct udphdr *);
				esp = (struct esp *)(void *)((caddr_t)udp + sizeof(struct udphdr));
			} else {
				esp = mtod(md, struct esp *);
			}
		}

		switch (af) {
		case AF_INET:
			if (esphlen < (IP_MAXPACKET - ntohs(ip->ip_len))) {
				ip->ip_len = htons(ntohs(ip->ip_len) + (u_short)esphlen);
			} else {
				ipseclog((LOG_ERR,
				    "IPv4 ESP output: size exceeds limit\n"));
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EMSGSIZE;
				goto fail;
			}
			break;
		case AF_INET6:
			/* total packet length will be computed in ip6_output() */
			break;
		}
	}

	/* initialize esp header. */
	esp->esp_spi = spi;
	if ((sav->flags & SADB_X_EXT_OLD) == 0) {
		struct newesp *nesp;
		nesp = (struct newesp *)esp;
		if (sav->replay[traffic_class]->seq == sav->replay[traffic_class]->lastseq) {
			if ((sav->flags & SADB_X_EXT_CYCSEQ) == 0) {
				/* XXX Is it noisy ? */
				ipseclog((LOG_WARNING,
				    "replay counter overflowed. %s\n",
				    ipsec_logsastr(sav)));
				IPSEC_STAT_INCREMENT(stat->out_inval);
				m_freem(m);
				KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 5, 0, 0, 0, 0);
				return EINVAL;
			}
		}
		lck_mtx_lock(sadb_mutex);
		sav->replay[traffic_class]->count++;
		sav->replay[traffic_class]->seq++;
		lck_mtx_unlock(sadb_mutex);
		/*
		 * XXX sequence number must not be cycled, if the SA is
		 * installed by IKE daemon.
		 */
		nesp->esp_seq = htonl(sav->replay[traffic_class]->seq);
		seq = sav->replay[traffic_class]->seq;
	}

	{
		/*
		 * find the last mbuf. make some room for ESP trailer.
		 */
		struct ip *ip = NULL;
		size_t padbound;
		u_char *extend;
		int i;
		int randpadmax;

		if (algo->padbound) {
			padbound = algo->padbound;
		} else {
			padbound = 4;
		}
		/* ESP packet, including nxthdr field, must be length of 4n */
		if (padbound < 4) {
			padbound = 4;
		}

		extendsiz = padbound - (plen % padbound);
		if (extendsiz == 1) {
			extendsiz = padbound + 1;
		}

		/* random padding */
		switch (af) {
		case AF_INET:
			randpadmax = ip4_esp_randpad;
			break;
		case AF_INET6:
			randpadmax = ip6_esp_randpad;
			break;
		default:
			randpadmax = -1;
			break;
		}
		if (randpadmax < 0 || plen + extendsiz >= randpadmax) {
			;
		} else {
			size_t pad;

			/* round */
			randpadmax = (int)((randpadmax / padbound) * padbound);
			pad = (randpadmax - plen + extendsiz) / padbound;

			if (pad > 0) {
				pad = (random() % pad) * padbound;
			} else {
				pad = 0;
			}

			/*
			 * make sure we do not pad too much.
			 * MLEN limitation comes from the trailer attachment
			 * code below.
			 * 256 limitation comes from sequential padding.
			 * also, the 1-octet length field in ESP trailer imposes
			 * limitation (but is less strict than sequential padding
			 * as length field do not count the last 2 octets).
			 */
			if (extendsiz + pad <= MLEN && extendsiz + pad < 256) {
				extendsiz += pad;
			}
		}

		n = m;
		while (n->m_next) {
			n = n->m_next;
		}

		/*
		 * if M_EXT, the external mbuf data may be shared among
		 * two consequtive TCP packets, and it may be unsafe to use the
		 * trailing space.
		 */
		if (!(n->m_flags & M_EXT) && extendsiz < M_TRAILINGSPACE(n)) {
			extend = mtod(n, u_char *) + n->m_len;
			n->m_len += (int)extendsiz;
			m->m_pkthdr.len += extendsiz;
		} else {
			struct mbuf *nn;

			MGET(nn, M_DONTWAIT, MT_DATA);
			if (!nn) {
				ipseclog((LOG_DEBUG, "esp%d_output: can't alloc mbuf",
				    afnumber));
				m_freem(m);
				error = ENOBUFS;
				goto fail;
			}
			extend = mtod(nn, u_char *);
			VERIFY(extendsiz <= INT_MAX);
			nn->m_len = (int)extendsiz;
			nn->m_next = NULL;
			n->m_next = nn;
			n = nn;
			m->m_pkthdr.len += extendsiz;
		}
		switch (sav->flags & SADB_X_EXT_PMASK) {
		case SADB_X_EXT_PRAND:
			key_randomfill(extend, extendsiz);
			break;
		case SADB_X_EXT_PZERO:
			bzero(extend, extendsiz);
			break;
		case SADB_X_EXT_PSEQ:
			for (i = 0; i < extendsiz; i++) {
				extend[i] = (i + 1) & 0xff;
			}
			break;
		}

		nxt = *nexthdrp;
		if (udp_encapsulate) {
			*nexthdrp = IPPROTO_UDP;

			/* Fill out the UDP header */
			if (sav->natt_encapsulated_src_port != 0) {
				udp->uh_sport = (u_short)sav->natt_encapsulated_src_port;
			} else {
				udp->uh_sport = htons((u_short)esp_udp_encap_port);
			}
			udp->uh_dport = htons(sav->remote_ike_port);
			// udp->uh_len set later, after all length tweaks are complete
			udp->uh_sum = 0;

			/* Update last sent so we know if we need to send keepalive */
			sav->natt_last_activity = natt_now;
		} else {
			*nexthdrp = IPPROTO_ESP;
		}

		/* initialize esp trailer. */
		esptail = (struct esptail *)
		    (mtod(n, u_int8_t *) + n->m_len - sizeof(struct esptail));
		esptail->esp_nxt = nxt;
		VERIFY((extendsiz - 2) <= UINT8_MAX);
		esptail->esp_padlen = (u_int8_t)(extendsiz - 2);

		/* modify IP header (for ESP header part only) */
		switch (af) {
		case AF_INET:
			ip = mtod(m, struct ip *);
			if (extendsiz < (IP_MAXPACKET - ntohs(ip->ip_len))) {
				ip->ip_len = htons(ntohs(ip->ip_len) + (u_short)extendsiz);
			} else {
				ipseclog((LOG_ERR,
				    "IPv4 ESP output: size exceeds limit\n"));
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EMSGSIZE;
				goto fail;
			}
			break;
		case AF_INET6:
			/* total packet length will be computed in ip6_output() */
			break;
		}
	}

	/*
	 * pre-compute and cache intermediate key
	 */
	error = esp_schedule(algo, sav);
	if (error) {
		m_freem(m);
		IPSEC_STAT_INCREMENT(stat->out_inval);
		goto fail;
	}

	/*
	 * encrypt the packet, based on security association
	 * and the algorithm specified.
	 */
	if (!algo->encrypt) {
		panic("internal error: no encrypt function");
	}
	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_START, 0, 0, 0, 0, 0);
	if ((*algo->encrypt)(m, espoff, plen + extendsiz, sav, algo, ivlen)) {
		/* m is already freed */
		ipseclog((LOG_ERR, "packet encryption failure\n"));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		error = EINVAL;
		KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 1, error, 0, 0, 0);
		goto fail;
	}
	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 2, 0, 0, 0, 0);

	/*
	 * calculate ICV if required.
	 */
	size_t siz = 0;
	u_char authbuf[AH_MAXSUMSIZE] __attribute__((aligned(4)));

	if (algo->finalizeencrypt) {
		siz = algo->icvlen;
		if ((*algo->finalizeencrypt)(sav, authbuf, siz)) {
			ipseclog((LOG_ERR, "packet encryption ICV failure\n"));
			IPSEC_STAT_INCREMENT(stat->out_inval);
			error = EINVAL;
			KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 1, error, 0, 0, 0);
			goto fail;
		}
		goto fill_icv;
	}

	if (!sav->replay[traffic_class]) {
		goto noantireplay;
	}
	if (!sav->key_auth) {
		goto noantireplay;
	}
	if (sav->key_auth == SADB_AALG_NONE) {
		goto noantireplay;
	}

	{
		const struct ah_algorithm *aalgo;

		aalgo = ah_algorithm_lookup(sav->alg_auth);
		if (!aalgo) {
			goto noantireplay;
		}
		siz = ((aalgo->sumsiz)(sav) + 3) & ~(4 - 1);
		if (AH_MAXSUMSIZE < siz) {
			panic("assertion failed for AH_MAXSUMSIZE");
		}

		if (esp_auth(m, espoff, m->m_pkthdr.len - espoff, sav, authbuf)) {
			ipseclog((LOG_ERR, "ESP checksum generation failure\n"));
			m_freem(m);
			error = EINVAL;
			IPSEC_STAT_INCREMENT(stat->out_inval);
			goto fail;
		}
	}

fill_icv:
	{
		struct ip *ip;
		u_char *p;

		n = m;
		while (n->m_next) {
			n = n->m_next;
		}

		if (!(n->m_flags & M_EXT) && siz < M_TRAILINGSPACE(n)) { /* XXX */
			n->m_len += siz;
			m->m_pkthdr.len += siz;
			p = mtod(n, u_char *) + n->m_len - siz;
		} else {
			struct mbuf *nn;

			MGET(nn, M_DONTWAIT, MT_DATA);
			if (!nn) {
				ipseclog((LOG_DEBUG, "can't alloc mbuf in esp%d_output",
				    afnumber));
				m_freem(m);
				error = ENOBUFS;
				goto fail;
			}
			nn->m_len = (int)siz;
			nn->m_next = NULL;
			n->m_next = nn;
			n = nn;
			m->m_pkthdr.len += siz;
			p = mtod(nn, u_char *);
		}
		bcopy(authbuf, p, siz);

		/* modify IP header (for ESP header part only) */
		switch (af) {
		case AF_INET:
			ip = mtod(m, struct ip *);
			if (siz < (IP_MAXPACKET - ntohs(ip->ip_len))) {
				ip->ip_len = htons(ntohs(ip->ip_len) + (u_short)siz);
			} else {
				ipseclog((LOG_ERR,
				    "IPv4 ESP output: size exceeds limit\n"));
				IPSEC_STAT_INCREMENT(ipsecstat.out_inval);
				m_freem(m);
				error = EMSGSIZE;
				goto fail;
			}
			break;
		case AF_INET6:
			/* total packet length will be computed in ip6_output() */
			break;
		}
	}

	if (udp_encapsulate) {
		struct ip *ip;
		struct ip6_hdr *ip6;

		switch (af) {
		case AF_INET:
			ip = mtod(m, struct ip *);
			udp->uh_ulen = htons((u_int16_t)(ntohs(ip->ip_len) - (IP_VHL_HL(ip->ip_vhl) << 2)));
			break;
		case AF_INET6:
			ip6 = mtod(m, struct ip6_hdr *);
			VERIFY((plen + siz + extendsiz + esphlen) <= UINT16_MAX);
			udp->uh_ulen = htons((u_int16_t)(plen + siz + extendsiz + esphlen));
			udp->uh_sum = in6_pseudo(&ip6->ip6_src, &ip6->ip6_dst, htonl(ntohs(udp->uh_ulen) + IPPROTO_UDP));
			m->m_pkthdr.csum_flags = (CSUM_UDPIPV6 | CSUM_ZERO_INVERT);
			m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
			break;
		}
	}

noantireplay:
	if (net_mpklog_enabled && sav->sah != NULL &&
	    sav->sah->ipsec_if != NULL &&
	    (sav->sah->ipsec_if->if_xflags & IFXF_MPK_LOG) &&
	    inner_protocol == IPPROTO_TCP) {
		MPKL_ESP_OUTPUT_TCP(esp_mpkl_log_object,
		    ntohl(spi), seq,
		    ntohs(th.th_sport), ntohs(th.th_dport),
		    ntohl(th.th_seq), ntohl(th.th_ack),
		    inner_payload_len, th.th_flags);
	}

	lck_mtx_lock(sadb_mutex);
	if (!m) {
		ipseclog((LOG_ERR,
		    "NULL mbuf after encryption in esp%d_output", afnumber));
	} else {
		IPSEC_STAT_INCREMENT(stat->out_success);
	}
	IPSEC_STAT_INCREMENT(stat->out_esphist[sav->alg_enc]);
	lck_mtx_unlock(sadb_mutex);
	key_sa_recordxfer(sav, m->m_pkthdr.len);
	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 6, 0, 0, 0, 0);
	return 0;

fail:
	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 7, error, 0, 0, 0);
	return error;
}

int
esp4_output(
	struct mbuf *m,
	struct secasvar *sav)
{
	struct ip *ip;
	if (m->m_len < sizeof(struct ip)) {
		ipseclog((LOG_DEBUG, "esp4_output: first mbuf too short\n"));
		m_freem(m);
		return EINVAL;
	}
	ip = mtod(m, struct ip *);
	/* XXX assumes that m->m_next points to payload */
	return esp_output(m, &ip->ip_p, m->m_next, AF_INET, sav);
}

int
esp6_output(
	struct mbuf *m,
	u_char *nexthdrp,
	struct mbuf *md,
	struct secasvar *sav)
{
	if (m->m_len < sizeof(struct ip6_hdr)) {
		ipseclog((LOG_DEBUG, "esp6_output: first mbuf too short\n"));
		m_freem(m);
		return EINVAL;
	}
	return esp_output(m, nexthdrp, md, AF_INET6, sav);
}

int
esp_kpipe_output(struct secasvar *sav, kern_packet_t sph, kern_packet_t dph)
{
	struct newesp *esp = NULL;
	struct esptail *esptail = NULL;
	struct ipsecstat *stat = NULL;
	uint8_t *sbaddr = NULL, *dbaddr = NULL;
	uint8_t *src_payload = NULL, *dst_payload = NULL;
	uint8_t *iv = NULL;
	uint8_t *auth_buf = NULL;
	const struct esp_algorithm *e_algo = NULL;
	const struct ah_algorithm *a_algo = NULL;
	mbuf_traffic_class_t traffic_class = 0;
	size_t iphlen = 0, esphlen = 0, padbound = 0, extendsiz = 0, plen = 0;
	size_t auth_size = 0, add_ip_len = 0;
	int af = 0, ivlen = 0;
	uint32_t slim = 0, slen = 0;
	uint32_t dlim = 0, dlen = 0;
	uint8_t dscp = 0, nxt_proto = 0;
	int err = 0;

	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_START, sav->ivlen, 0, 0, 0, 0);

	VERIFY(sav->sah->saidx.mode == IPSEC_MODE_TRANSPORT);
	VERIFY((sav->flags & (SADB_X_EXT_OLD | SADB_X_EXT_DERIV |
	    SADB_X_EXT_NATT | SADB_X_EXT_NATT_MULTIPLEUSERS |
	    SADB_X_EXT_CYCSEQ | SADB_X_EXT_PMASK)) == 0);

	MD_BUFLET_ADDR(SK_PTR_ADDR_KPKT(sph), sbaddr);
	kern_buflet_t sbuf = __packet_get_next_buflet(sph, NULL);
	VERIFY(sbuf != NULL);
	slen = __buflet_get_data_length(sbuf);
	slim = __buflet_get_data_limit(sbuf);
	slim -= __buflet_get_data_offset(sbuf);

	MD_BUFLET_ADDR(SK_PTR_ADDR_KPKT(dph), dbaddr);
	kern_buflet_t dbuf = __packet_get_next_buflet(dph, NULL);
	VERIFY(dbuf != NULL);
	dlen = __buflet_get_data_length(dbuf);
	dlim = __buflet_get_data_limit(dbuf);
	dlim -= __buflet_get_data_offset(dbuf);

	struct ip *ip_hdr = (struct ip *)(void *)sbaddr;
	ASSERT(IP_HDR_ALIGNED_P(ip_hdr));

	u_int ip_vers = IP_VHL_V(ip_hdr->ip_vhl);
	switch (ip_vers) {
	case IPVERSION: {
#ifdef _IP_VHL
		iphlen = IP_VHL_HL(ip_hdr->ip_vhl) << 2;
#else /* _IP_VHL */
		iphlen = ip_hdr->ip_hl << 2;
#endif /* _IP_VHL */
		dscp = ip_hdr->ip_tos >> IPTOS_DSCP_SHIFT;
		nxt_proto = ip_hdr->ip_p;
		stat = &ipsecstat;
		af = AF_INET;
		break;
	}
	case 6: {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)sbaddr;
		iphlen = sizeof(struct ip6_hdr);
		dscp = (ntohl(ip6->ip6_flow) & IP6FLOW_DSCP_MASK) >> IP6FLOW_DSCP_SHIFT;
		nxt_proto = ip6->ip6_nxt;
		stat = &ipsec6stat;
		af = AF_INET6;
		break;
	}
	default:
		panic("esp kpipe output, ipversion %u, SPI=%x",
		    ip_vers, ntohl(sav->spi));
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (__improbable(slen <= iphlen)) {
		esp_log_info("esp kpipe output, slen(%u) <= iphlen(%zu) "
		    "SPI=%x\n", slen, iphlen, ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 1, EINVAL, 0, 0, 0);
		return EINVAL;
	}

	if ((sav->flags2 & SADB_X_EXT_SA2_SEQ_PER_TRAFFIC_CLASS) ==
	    SADB_X_EXT_SA2_SEQ_PER_TRAFFIC_CLASS) {
		traffic_class = rfc4594_dscp_to_tc(dscp);
	}
	if (__improbable(sav->replay[traffic_class] == NULL)) {
		esp_log_info("esp kpipe output, missing "
		    "replay window, SPI=%x\n", ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 2, EINVAL, 0, 0, 0);
		return EINVAL;
	}

	e_algo = esp_algorithm_lookup(sav->alg_enc);
	if (__improbable(e_algo == NULL)) {
		esp_log_info("esp kpipe output: unsupported algorithm, SPI=%x\n",
		    ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 3, EINVAL, 0, 0, 0);
		return EINVAL;
	}

	if ((sav->flags & SADB_X_EXT_IIV) == 0) {
		ivlen = sav->ivlen;
		if (__improbable(ivlen < 0)) {
			panic("invalid ivlen(%d) SPI=%x", ivlen, ntohl(sav->spi));
			/* NOTREACHED */
			__builtin_unreachable();
		}

		iv = dbaddr + iphlen + sizeof(struct newesp);
	}

	esphlen = sizeof(struct newesp) + ivlen;
	if (e_algo->padbound) {
		padbound = e_algo->padbound;
		/*ESP packet, including nxthdr field, must be length of 4n */
		if (padbound < 4) {
			padbound = 4;
		}
	} else {
		padbound = 4;
	}
	plen = slen - iphlen;
	extendsiz = padbound - (plen % padbound);
	if (extendsiz == 1) {
		extendsiz = padbound + 1;
	}
	VERIFY(extendsiz <= UINT8_MAX);
	if (e_algo->finalizeencrypt) {
		auth_size = e_algo->icvlen;
	} else {
		a_algo = ah_algorithm_lookup(sav->alg_auth);
		if (a_algo != NULL) {
			auth_size = ((a_algo->sumsiz)(sav) + 3) & ~(4 - 1);
			if (__improbable(auth_size > AH_MAXSUMSIZE)) {
				panic("auth size %zu greater than AH_MAXSUMSIZE",
				    auth_size);
				/* NOTREACHED */
				__builtin_unreachable();
			}
		}
	}

	/*
	 * Validate destination buffer has sufficient space -
	 * {IP header + ESP header + Payload + Padding + ESP trailer + ESP Auth}
	 */
	size_t total_len = iphlen + esphlen + plen + extendsiz + auth_size;
	if (__improbable(total_len > dlim)) {
		esp_log_info("esp kpipe output: destination buffer too short");
		IPSEC_STAT_INCREMENT(stat->out_nomem);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 4, EMSGSIZE, 0, 0, 0);
		return EMSGSIZE;
	}

	/*
	 * Validate source buffer has sufficient space to including padding and
	 * ESP trailer. This is done so that source buffer can be passed as
	 * input to encrypt cipher.
	 */
	if (__improbable((slen + extendsiz) > slim)) {
		esp_log_info("esp kpipe output: source buffer too short");
		IPSEC_STAT_INCREMENT(stat->out_nomem);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 5, EMSGSIZE, 0, 0, 0);
		return EMSGSIZE;
	}

	/*
	 * Increment IP payload length to include ESP header length +
	 * Padding + ESP trailer + ESP Auth
	 */
	add_ip_len = esphlen + extendsiz + auth_size;
	switch (af) {
	case AF_INET: {
		struct ip *ip = (struct ip *)(void *)dbaddr;
		ASSERT(IP_HDR_ALIGNED_P(ip));
		if (__probable(ntohs(ip->ip_len) + add_ip_len <= IP_MAXPACKET)) {
			ip->ip_len = htons(ntohs(ip->ip_len) + (u_short)add_ip_len);
			ip->ip_p = IPPROTO_ESP;
			ip->ip_sum = 0; // Recalculate checksum
			ip->ip_sum = in_cksum_hdr_opt(ip);
		} else {
			esp_log_info("esp kpipe output: ipv4 packet "
			    "size exceeded, ip payload len %u, SPI=%x\n",
			    ntohs(ip->ip_len), ntohl(sav->spi));
			IPSEC_STAT_INCREMENT(stat->out_nomem);
			KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 6, EMSGSIZE, 0, 0, 0);
			return EMSGSIZE;
		}
		break;
	}
	case AF_INET6: {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)dbaddr;
		if (__probable(ntohs(ip6->ip6_plen) + add_ip_len <= IP_MAXPACKET)) {
			ip6->ip6_plen = htons(ntohs(ip6->ip6_plen) + (u_short)add_ip_len);
			ip6->ip6_nxt = IPPROTO_ESP;
		} else {
			esp_log_info("esp kpipe output: ipv6 packet "
			    "size exceeded, ip payload len %u, SPI=%x\n",
			    ntohs(ip6->ip6_plen), ntohl(sav->spi));
			IPSEC_STAT_INCREMENT(stat->out_nomem);
			KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 7, EMSGSIZE, 0, 0, 0);
			return EMSGSIZE;
		}
		break;
	}
	}

	if (__improbable(sav->replay[traffic_class]->seq >=
	    sav->replay[traffic_class]->lastseq)) {
		esp_log_info("replay counter overflowed, SPI=%x\n", ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 8, EINVAL, 0, 0, 0);
		return EINVAL;
	}

	os_atomic_inc(&sav->replay[traffic_class]->count, relaxed);

	esp = (struct newesp *)(void *)(dbaddr + iphlen);
	ASSERT(IS_P2ALIGNED(esp, sizeof(uint32_t)));
	esp->esp_spi = sav->spi;
	esp->esp_seq = htonl(os_atomic_inc(&sav->replay[traffic_class]->seq, relaxed));

	esptail = (struct esptail *)(sbaddr + slen + extendsiz - sizeof(struct esptail));
	esptail->esp_nxt = nxt_proto;
	esptail->esp_padlen = (u_int8_t)(extendsiz - 2);

	/*
	 * pre-compute and cache intermediate key
	 */
	err = esp_schedule(e_algo, sav);
	if (__improbable(err != 0)) {
		esp_log_info("esp schedule failed %d, SPI=%x\n", err, ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 9, err, 0, 0, 0);
		return err;
	}

	if (__improbable(!e_algo->encrypt_pkt)) {
		panic("esp kpipe output: missing algo encrypt pkt");
		/* NOTREACHED */
		__builtin_unreachable();
	}

	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_START, 0, 0, 0, 0, 0);
	src_payload = sbaddr + iphlen;
	dst_payload = dbaddr + iphlen + esphlen;
	if (__improbable((err = (*e_algo->encrypt_pkt)(sav, src_payload, plen + extendsiz,
	    esp, iv, ivlen, dst_payload, plen + extendsiz)) != 0)) {
		esp_log_info("esp encrypt failed %d, SPI=%x\n", err, ntohl(sav->spi));
		IPSEC_STAT_INCREMENT(stat->out_inval);
		KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 1, err, 0, 0, 0);
		KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 10, err, 0, 0, 0);
		return err;
	}
	KERNEL_DEBUG(DBG_FNC_ENCRYPT | DBG_FUNC_END, 2, 0, 0, 0, 0);

	auth_buf = dst_payload + plen + extendsiz;
	if (e_algo->finalizeencrypt) {
		if (__improbable((err = (*e_algo->finalizeencrypt)(sav, auth_buf,
		    auth_size)) != 0)) {
			esp_log_info("esp finalize encrypt failed %d, SPI=%x\n",
			    err, ntohl(sav->spi));
			IPSEC_STAT_INCREMENT(stat->out_inval);
			KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 11, err, 0, 0, 0);
			return err;
		}
	} else if (sav->key_auth != NULL && auth_size > 0) {
		if (__improbable((err = esp_auth_data(sav, (uint8_t *)esp,
		    esphlen + plen + extendsiz, auth_buf, auth_size)) != 0)) {
			esp_log_info("esp auth data failed %d, SPI=%x\n",
			    err, ntohl(sav->spi));
			IPSEC_STAT_INCREMENT(stat->out_inval);
			KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 12, err, 0, 0, 0);
			return err;
		}
	}

	__buflet_set_data_length(dbuf, (uint16_t)total_len);

	IPSEC_STAT_INCREMENT(stat->out_success);
	IPSEC_STAT_INCREMENT(stat->out_esphist[sav->alg_enc]);
	key_sa_recordxfer(sav, total_len);
	KERNEL_DEBUG(DBG_FNC_ESPOUT | DBG_FUNC_END, 13, 0, 0, 0, 0);
	return 0;
}
