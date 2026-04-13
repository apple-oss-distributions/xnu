/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 McAfee, Inc.
 * Copyright (c) 2006,2013 Andre Oppermann, Internet Business Solutions AG
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Jonathan Lemon
 * and McAfee Research, the Security Research Division of McAfee, Inc. under
 * DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program. [2001 McAfee, Inc.]
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include "tcp_includes.h"

#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
#include <net/if_var_private.h>
#include <netinet/in_tclass.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_syncookie.h>
#include <netinet6/nd6.h>
#include <net/siphash.h>
#include <os/ptrtools.h>
#include <sys/random.h>

extern int path_mtu_discovery;
int tcp_syncookie_hmac_sha256 = 0;

SYSCTL_INT(_net_inet_tcp, OID_AUTO, syncookie_hmac_sha256,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tcp_syncookie_hmac_sha256, 0,
    "0: disable, 1: Use HMAC with SHA-256 for generating SYN cookie");

static bool
syncookie_respond(struct socket *so, struct tcpcb *tp, struct tcp_inp *tpi, uint16_t flags,
    struct sockaddr *local, struct sockaddr *remote);
static uint32_t syncookie_siphash(struct tcp_inp *tpi, uint8_t flags, uint8_t key[SYNCOOKIE_SECRET_SIZE]);
static uint32_t syncookie_hmac_sha256(struct tcp_inp *tpi, uint8_t flags, uint8_t key[CCSHA256_OUTPUT_SIZE]);
static uint32_t syncookie_mac(struct tcp_inp *tpi, uint8_t flags, uint8_t secbit);
static tcp_seq syncookie_generate(struct tcp_inp *tpi, bool has_ecn);
static bool syncookie_lookup(struct tcp_inp *tpi);
static void syncookie_reseed(void);

static struct syncookie_secret tcp_syncookie_secret;

/*
 * This function gets called when we receive an ACK for a
 * socket in the LISTEN state.  We create the connection
 * and set its state based on information from SYN cookies
 * and options/flags received in last ACK. The returned
 * tcpcb is in the SYN-RECEIVED state.
 *
 * Return true on success and false on failure.
 */
bool
tcp_syncookie_ack(struct tcp_inp *tpi, struct socket **so2, int* dropsocket)
{
#define TCP_LOG_HDR (isipv6 ? (void *)ip6 : (void *)ip)

	ASSERT((tcp_get_flags(tpi->th) & (TH_RST | TH_ACK | TH_SYN)) == TH_ACK);
	/*
	 * We don't support syncache, so see if this ACK is
	 * a returning syncookie. To do this,  check that the
	 * syncookie is valid.
	 */
	bool ret = syncookie_lookup(tpi);

	if (ret == false) {
		TCP_LOG(*tpi->tp, "Segment failed SYNCOOKIE authentication, "
		    "segment was rejected (either ACK was sent to listener after connection was closed OR spoofed)");
		goto failed;
	}

	ret = tcp_create_server_socket(tpi, so2, NULL, dropsocket);

	if (ret == false) {
		goto failed;
	}

	ret = tcp_setup_server_socket(tpi, *so2, true);

	/* Set snd state for newly created tcpcb */
	(*tpi->tp)->snd_nxt = (*tpi->tp)->snd_max = tpi->th->th_ack;

	if (ret == false) {
		/*
		 * We failed to setup the server socket, return failure
		 * so that tcp_input can cleanup the socket and the
		 * incoming segment
		 */
		goto failed;
	}
	*dropsocket = 0;         /* committed to socket */

	if (__improbable(*so2 == NULL)) {
		tcpstat.tcps_sc_aborted++;
	} else {
		tcpstat.tcps_sc_completed++;
	}

	return true;

failed:
	return false;
}

static uint8_t
syncookie_process_accecn_syn(struct tcpcb *tp, uint32_t ace_flags,
    uint8_t ip_ecn)
{
	uint8_t setup_flags = 0;
	switch (ace_flags) {
	case (0 | 0 | 0):
		/* No ECN */
		break;
	case (0 | TH_CWR | TH_ECE):
		/* Legacy ECN-setup */
		setup_flags |= SC_ECN_SETUP;
		break;
	case (TH_ACE):
		/* Accurate ECN */
		if (tp->l4s_enabled) {
			switch (ip_ecn) {
			case IPTOS_ECN_NOTECT:
				setup_flags |= SC_ACE_SETUP_NOT_ECT;
				break;
			case IPTOS_ECN_ECT1:
				setup_flags |= SC_ACE_SETUP_ECT1;
				break;
			case IPTOS_ECN_ECT0:
				setup_flags |= SC_ACE_SETUP_ECT0;
				break;
			case IPTOS_ECN_CE:
				setup_flags |= SC_ACE_SETUP_CE;
				break;
			}
		} else {
			/*
			 * If AccECN is not enabled, ignore
			 * the TH_AE bit and do Legacy ECN-setup
			 */
			setup_flags |= SC_ECN_SETUP;
		}
		OS_FALLTHROUGH;
	default:
		/* Forward Compatibility */
		/* Accurate ECN */
		if (tp->l4s_enabled) {
			switch (ip_ecn) {
			case IPTOS_ECN_NOTECT:
				setup_flags |= SC_ACE_SETUP_NOT_ECT;
				break;
			case IPTOS_ECN_ECT1:
				setup_flags |= SC_ACE_SETUP_ECT1;
				break;
			case IPTOS_ECN_ECT0:
				setup_flags |= SC_ACE_SETUP_ECT0;
				break;
			case IPTOS_ECN_CE:
				setup_flags |= SC_ACE_SETUP_CE;
				break;
			}
		}
		break;
	}
	return setup_flags;
}

static uint16_t
syncookie_respond_accecn(uint8_t setup_flags, uint16_t thflags)
{
	switch (setup_flags) {
	case SC_ECN_SETUP:
		thflags |= TH_ECE;
		break;
	case SC_ACE_SETUP_NOT_ECT:
		thflags |= TH_CWR;
		break;
	case SC_ACE_SETUP_ECT1:
		thflags |= (TH_CWR | TH_ECE);
		break;
	case SC_ACE_SETUP_ECT0:
		thflags |= TH_AE;
		break;
	case SC_ACE_SETUP_CE:
		thflags |= (TH_AE | TH_CWR);
		break;
	}

	return thflags;
}

/*
 * Given a LISTEN socket and an inbound SYN request, generate
 * a SYN cookie, and send back a segment:
 *	<SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
 * to the source.
 */
void
tcp_syncookie_syn(struct tcp_inp *tpi, struct sockaddr *local,
    struct sockaddr *remote)
{
	struct socket *so = tpi->so;
	struct inpcb *inp;
	struct tcpcb *tp;
	uint8_t ip_tos, ip_ecn;
	uint8_t ace_setup_flags = 0;

	/* make sure inp is locked for listen socket */
	socket_lock_assert_owned(so);

	ASSERT((tcp_get_flags(tpi->th) & (TH_RST | TH_ACK | TH_SYN)) == TH_SYN);

	ASSERT((so->so_options & SO_ACCEPTCONN) != 0);

	/* Reseed the key if SYNCOOKIE_LIFETIME time has elapsed */
	if (tcp_now > tcp_syncookie_secret.last_updated +
	    SYNCOOKIE_LIFETIME * TCP_RETRANSHZ) {
		syncookie_reseed();
	}
	inp = sotoinpcb(so);
	tp = sototcpcb(so);

	if (tpi->isipv6) {
		if ((inp->in6p_outputopts == NULL) ||
		    (inp->in6p_outputopts->ip6po_tclass == -1)) {
			ip_tos = 0;
		} else {
			ip_tos = (uint8_t)inp->in6p_outputopts->ip6po_tclass;
		}
	} else {
		ip_tos = inp->inp_ip_tos;
	}

	ip_ecn = ip_tos & IPTOS_ECN_MASK;

	/* Is ECN enabled? */
	bool is_ecn = tcp_ecn_enabled(tp->ecn_flags);
	/* ECN Handshake */
	if (is_ecn) {
		int ace_flags = ((tpi->th->th_x2 << 8) | tpi->th->th_flags) & TH_ACE;
		ace_setup_flags = syncookie_process_accecn_syn(tp, ace_flags, ip_ecn);
	}
	bool classic_ecn = !!(ace_setup_flags & SC_ECN_SETUP);

	tpi->iss = syncookie_generate(tpi, classic_ecn);

	uint16_t output_flags = TH_SYN | TH_ACK;
	output_flags = syncookie_respond_accecn(ace_setup_flags, output_flags);
	/*
	 * Do a standard 3-way handshake.
	 */
	if (syncookie_respond(so, tp, tpi, output_flags, local, remote)) {
		tcpstat.tcps_sndacks++;
		tcpstat.tcps_sndtotal++;
	} else {
		tcpstat.tcps_sc_dropped++;
	}
	if (tpi->m != NULL) {
		m_freem(tpi->m);
	}
}

/*
 * Send SYN|ACK to the peer in response to a peer's SYN segment
 */
static bool
syncookie_respond(struct socket *so, struct tcpcb *tp, struct tcp_inp *tpi, uint16_t flags,
    struct sockaddr *local, struct sockaddr *remote)
{
	struct tcptemp *__single t_template;
	struct mbuf *__single m;
	tcp_seq seq;
	uint16_t mss = 0;
	uint32_t win;

	if (flags & TH_SYN) {
		seq = tpi->iss;
	} else {
		seq = tpi->iss + 1;
	}

	t_template = tcp_maketemplate(tp, &m, local, remote);
	if (t_template != NULL) {
		/* Use the properties of listener socket for sending SYN-ACK with cookie */
		struct inpcb *inp = tp->t_inpcb;

		uint16_t min_protoh = tpi->isipv6 ? sizeof(struct ip6_hdr) + sizeof(struct tcphdr)
		    : sizeof(struct tcpiphdr);
		if (tpi->isipv6) {
			mss = (uint16_t)IN6_LINKMTU(tpi->ifp);
		} else {
			mss = (uint16_t)tpi->ifp->if_mtu;
		}
		mss -= min_protoh;

		win = ((so->so_rcv.sb_flags & SB_USRSIZE) != 0) ?
		    so->so_rcv.sb_hiwat : tcp_autorcvbuf_max;
		win = imin(win, TCP_MAXWIN);
		uint8_t rcv_scale = tcp_get_max_rwinscale(tp, so);

		struct tcp_respond_args tra;

		bzero(&tra, sizeof(tra));
		tra.nocell = INP_NO_CELLULAR(inp) ? 1 : 0;
		tra.noexpensive = INP_NO_EXPENSIVE(inp) ? 1 : 0;
		tra.noconstrained = INP_NO_CONSTRAINED(inp) ? 1 : 0;
		tra.awdl_unrestricted = INP_AWDL_UNRESTRICTED(inp) ? 1 : 0;
		tra.intcoproc_allowed = INP_INTCOPROC_ALLOWED(inp) ? 1 : 0;
		tra.management_allowed = INP_MANAGEMENT_ALLOWED(inp) ? 1 : 0;
		tra.keep_alive = 1;
		if (tp->t_inpcb->inp_flags & INP_BOUND_IF) {
			tra.ifscope = tp->t_inpcb->inp_boundifp->if_index;
		} else {
			tra.ifscope = IFSCOPE_NONE;
		}
		tcp_respond((struct tcpcb*) 0, t_template->tt_ipgen, sizeof(t_template->tt_ipgen),
		    &t_template->tt_t, (struct mbuf *)NULL,
		    tpi->th->th_seq + 1, seq, win, flags, tpi->to, mss, rcv_scale, tpi->ts_offset, &tra, true);
		(void) m_free(m);

		tcpstat.tcps_sc_sendcookie++;

		return true;
	} else {
		return false;
	}
}

/*
 * The purpose of syncookies is to handle spoofed SYN flooding DoS attacks
 * that exceed the capacity of the listen queue by avoiding the storage of any
 * of the SYNs we receive.  Syncookies defend against blind SYN flooding
 * attacks where the attacker does not have access to our responses.
 *
 * Syncookies encode and include all necessary information about the
 * connection setup within the SYN|ACK that we send back.  That way we
 * can avoid keeping any local state until the ACK to our SYN|ACK returns
 * (if ever).
 *
 * The only reliable information persisting the 3WHS is our initial sequence
 * number ISS of 32 bits.  Syncookies embed a cryptographically sufficient
 * strong hash (MAC) value and a few bits of TCP SYN options in the ISS
 * of our SYN|ACK.  The MAC can be recomputed when the ACK to our SYN|ACK
 * returns and signifies a legitimate connection if it matches the ACK.
 *
 * The available space of 32 bits to store the hash and to encode the SYN
 * option information is very tight and we should have at least 24 bits for
 * the MAC to keep the number of guesses by blind spoofing reasonably high.
 *
 * SYN option information we have to encode to fully restore a connection:
 * MSS: is imporant to chose an optimal segment size to avoid IP level
 *   fragmentation along the path.  The common MSS values can be encoded
 *   in a 3-bit table.  Uncommon values are captured by the next lower value
 *   in the table leading to a slight increase in packetization overhead.
 * WSCALE: is necessary to allow large windows to be used for high delay-
 *   bandwidth product links.  Not scaling the window when it was initially
 *   negotiated is bad for performance as lack of scaling further decreases
 *   the apparent available send window.  We only need to encode the WSCALE
 *   we received from the remote end.  Our end can be recalculated at any
 *   time.  The common WSCALE values can be encoded in a 3-bit table.
 *   Uncommon values are captured by the next lower value in the table
 *   making us under-estimate the available window size halving our
 *   theoretically possible maximum throughput for that connection.
 * SACK: Greatly assists in packet loss recovery and requires 1 bit.
 * TIMESTAMP is not encoded because it is a permanent option
 *   that is included in all segments on a connection.  We enable it when
 *   the ACK has it.
 * Accurate ECN is not encoded because the last ACK has enough state to
 *   determine the state negotiated during SYN/ACK.
 *
 * Security of syncookies and attack vectors:
 *
 * The MAC is computed over (faddr||laddr||fport||lport||irs||flags)
 * together with the global secret to make it unique per connection attempt.
 * Thus any change of any of those parameters results in a different MAC output
 * in an unpredictable way unless a collision is encountered.  24 bits of the
 * MAC are embedded into the ISS.
 *
 * To prevent replay attacks two rotating global secrets are updated with a
 * new random value every 15 seconds.  The life-time of a syncookie is thus
 * 15-30 seconds.
 *
 * Vector 1: Attacking the secret.  This requires finding a weakness in the
 * MAC itself or the way it is used here.  The attacker can do a chosen plain
 * text attack by varying and testing the all parameters under his control.
 * The strength depends on the size and randomness of the secret, and the
 * cryptographic security of the MAC function.  Due to the constant updating
 * of the secret the attacker has at most 29.999 seconds to find the secret
 * and launch spoofed connections.  After that he has to start all over again.
 *
 * Vector 2: Collision attack on the MAC of a single ACK.  With a 24 bit MAC
 * size an average of 4,823 attempts are required for a 50% chance of success
 * to spoof a single syncookie (birthday collision paradox).  However the
 * attacker is blind and doesn't know if one of his attempts succeeded unless
 * he has a side channel to interfere success from.  A single connection setup
 * success average of 90% requires 8,790 packets, 99.99% requires 17,578 packets.
 * This many attempts are required for each one blind spoofed connection.  For
 * every additional spoofed connection he has to launch another N attempts.
 * Thus for a sustained rate 100 spoofed connections per second approximately
 * 1,800,000 packets per second would have to be sent.
 *
 * NB: The MAC function should be fast so that it doesn't become a CPU
 * exhaustion attack vector itself.
 *
 * References:
 *  RFC4987 TCP SYN Flooding Attacks and Common Mitigations
 *  SYN cookies were first proposed by cryptographer Dan J. Bernstein in 1996
 *   http://cr.yp.to/syncookies.html    (overview)
 *   http://cr.yp.to/syncookies/archive (details)
 *
 *
 * Schematic construction of a syncookie enabled Initial Sequence Number:
 *  0        1         2         3
 *  12345678901234567890123456789012
 * |xxxxxxxxxxxxxxxxxxxxxxxxWWWMMMSP|
 *
 *  x 24 MAC (truncated)
 *  W  3 Send Window Scale index
 *  M  2 MSS index
 *  E  1 Classic ECN permitted
 *  S  1 SACK permitted
 *  P  1 Odd/even secret
 */
/*
 * Distribution and probability of certain MSS values.  Those in between are
 * rounded down to the next lower one.
 */
static uint16_t tcp_sc_msstab_v4[] = { 536, 1300, 1460, 4036 };

static uint16_t tcp_sc_msstab_v6[] = { 1220, 1420, 1440, 4016 };

/*
 * Distribution and probability of certain WSCALE values.  We have to map the
 * (send) window scale (shift) option with a range of 0-14 from 4 bits into 3
 * bits based on prevalence of certain values.  Where we don't have an exact
 * match for are rounded down to the next lower one letting us under-estimate
 * the true available window.  At the moment this would happen only for the
 * very uncommon values 2, 5 and those above 9 (more than 32MB socket buffer
 * and window size).  The absence of the WSCALE option (no scaling in either
 * direction) is encoded with index zero.
 */
static uint8_t tcp_sc_wstab[] = { 0, 1, 3, 4, 6, 7, 8, 9 };

#define nitems(_x_) (sizeof(_x_) / sizeof(*_x_))

/*
 * Compute the MAC for the SYN cookie.  SIPHASH-2-4 is chosen for its speed
 * and good cryptographic properties.
 */
static uint32_t
syncookie_siphash(struct tcp_inp *tpi, uint8_t flags, uint8_t key[SYNCOOKIE_SECRET_SIZE])
{
	SIPHASH_CTX ctx;
	uint32_t siphash[2];

	SipHash24_Init(&ctx);
	SipHash_SetKey(&ctx, key);
	if (tpi->isipv6) {
		SipHash_Update(&ctx, &tpi->ip6->ip6_src.s6_addr, sizeof(tpi->ip6->ip6_src.s6_addr));
		SipHash_Update(&ctx, &tpi->ip6->ip6_dst.s6_addr, sizeof(tpi->ip6->ip6_dst.s6_addr));
	} else {
		SipHash_Update(&ctx, &tpi->ip->ip_src.s_addr, sizeof(tpi->ip->ip_src.s_addr));
		SipHash_Update(&ctx, &tpi->ip->ip_dst.s_addr, sizeof(tpi->ip->ip_dst.s_addr));
	}

	SipHash_Update(&ctx, &tpi->th->th_sport, sizeof(tpi->th->th_sport));
	SipHash_Update(&ctx, &tpi->th->th_dport, sizeof(tpi->th->th_dport));
	SipHash_Update(&ctx, &tpi->irs, sizeof(tpi->irs));
	SipHash_Update(&ctx, &flags, sizeof(flags));
	SipHash_Final((u_int8_t *)&siphash, &ctx);

	tpi->ts_offset = siphash[1];

	return siphash[0] ^ siphash[1];
}

/*
 * HMAC with SHA-256 is only used for comparison with Siphash
 */
static uint32_t
syncookie_hmac_sha256(struct tcp_inp *tpi, uint8_t flags, uint8_t key[CCSHA256_OUTPUT_SIZE])
{
	/* SHA256 mac is 32 bytes */
	uint32_t mac[8] = {};
	const struct ccdigest_info *di = ccsha256_di();

	cchmac_ctx_decl(di->state_size, di->block_size, ctx);
	cchmac_init(di, ctx, CCSHA256_OUTPUT_SIZE, key);
	if (tpi->isipv6) {
		cchmac_update(di, ctx, sizeof(tpi->ip6->ip6_src.s6_addr), &tpi->ip6->ip6_src.s6_addr);
		cchmac_update(di, ctx, sizeof(tpi->ip6->ip6_dst.s6_addr), &tpi->ip6->ip6_dst.s6_addr);
	} else {
		cchmac_update(di, ctx, sizeof(tpi->ip->ip_src.s_addr), &tpi->ip->ip_src.s_addr);
		cchmac_update(di, ctx, sizeof(tpi->ip->ip_dst.s_addr), &tpi->ip->ip_dst.s_addr);
	}
	cchmac_update(di, ctx, sizeof(tpi->th->th_sport), &tpi->th->th_sport);
	cchmac_update(di, ctx, sizeof(tpi->th->th_dport), &tpi->th->th_dport);
	cchmac_update(di, ctx, sizeof(tpi->irs), &tpi->irs);
	cchmac_update(di, ctx, sizeof(flags), &flags);
	cchmac_final(di, ctx, (uint8_t *)mac);

	tpi->ts_offset = mac[1];

	return mac[0] ^ mac[1] ^ mac[2] ^ mac[3] ^ mac[4] ^ mac[5] ^ mac[6] ^ mac[7];
}

static uint32_t
syncookie_mac(struct tcp_inp *tpi, uint8_t flags, uint8_t secbit)
{
	if (tcp_syncookie_hmac_sha256) {
		/* key size is 32 bytes */
		return syncookie_hmac_sha256(tpi, flags, (uint8_t *) tcp_syncookie_secret.key);
	} else {
		/* key size is 16 bytes */
		return syncookie_siphash(tpi, flags, tcp_syncookie_secret.key[secbit]);
	}
}

static tcp_seq
syncookie_generate(struct tcp_inp *tpi, bool has_ecn)
{
	uint8_t i, secbit, peer_wscale = 0;
	uint32_t iss, hash;
	syncookie cookie;
	uint16_t peer_mss = 0;

	cookie.cookie = 0;

	struct tcpopt *to = tpi->to;

	if (to->to_flags & TOF_MSS) {
		peer_mss = to->to_mss;  /* peer mss may be zero */
	}
	if (to->to_flags & TOF_SCALE) {
		peer_wscale = to->to_wscale;
	}

	/* Map our computed MSS into the 2-bit index. */
	if (tpi->isipv6) {
		for (i = nitems(tcp_sc_msstab_v6) - 1;
		    tcp_sc_msstab_v6[i] > peer_mss && i > 0;
		    i--) {
			;
		}
	} else {
		for (i = nitems(tcp_sc_msstab_v4) - 1;
		    tcp_sc_msstab_v4[i] > peer_mss && i > 0;
		    i--) {
			;
		}
	}
	cookie.flags.mss_idx = i;
	/*
	 * Map the send window scale into the 3-bit index but only if
	 * the wscale option was received.
	 */
	if (peer_wscale > 0) {
		for (i = nitems(tcp_sc_wstab) - 1;
		    tcp_sc_wstab[i] > peer_wscale && i > 0;
		    i--) {
			;
		}
		cookie.flags.wscale_idx = i;
	}
	/* Can we do SACK? */
	if (to->to_flags & TOF_SACKPERM) {
		cookie.flags.sack_ok = 1;
	}

	/* Should we do classic ECN? */
	if (has_ecn) {
		cookie.flags.ecn_ok = 1;
	}

	/* Which of the two secrets to use. */
	secbit = tcp_syncookie_secret.oddeven & 0x1;
	cookie.flags.odd_even = secbit;
	tpi->irs = tpi->th->th_seq;
	hash = syncookie_mac(tpi, cookie.cookie, secbit);
	/*
	 * Put the flags into the hash and XOR them to get better ISS number
	 * variance.  This doesn't enhance the cryptographic strength and is
	 * done to prevent the 8 cookie bits from showing up directly on the
	 * wire.
	 */
	iss = hash & ~0xff;
	iss |= cookie.cookie ^ (hash >> 24);

	tcpstat.tcps_sc_sendcookie++;

	return iss;
}

/*
 * Validate received SYN cookie in th_ack. Returns true on success
 * and a false on failure
 */
static bool
syncookie_lookup(struct tcp_inp *tpi)
{
	syncookie cookie;
	uint32_t hash;
	tcp_seq ack;
	/*
	 * Pull information out of SYN-ACK/ACK and revert sequence number
	 * advances.
	 */
	ack = tpi->th->th_ack - 1;
	tpi->irs = tpi->th->th_seq - 1;

	/*
	 * Unpack the flags containing enough information to restore the
	 * connection.
	 */
	cookie.cookie = (ack & 0xff) ^ (ack >> 24);
	hash = syncookie_mac(tpi, cookie.cookie, cookie.flags.odd_even);

	/* The recomputed hash failed to match the ACK */
	if ((ack & ~0xff) != (hash & ~0xff)) {
		return false;
	}
	if (tpi->isipv6) {
		tpi->peer_mss = tcp_sc_msstab_v6[cookie.flags.mss_idx];
	} else {
		tpi->peer_mss = tcp_sc_msstab_v4[cookie.flags.mss_idx];
	}

	/* Only use wscale if it was enabled in the orignal SYN. */
	if (cookie.flags.wscale_idx > 0) {
		tpi->peer_wscale = tcp_sc_wstab[cookie.flags.wscale_idx];
	}
	if (cookie.flags.sack_ok) {
		tpi->sackok = true;
	}

	if (cookie.flags.ecn_ok) {
		tpi->ecnok = true;
	}

	tcpstat.tcps_sc_recvcookie++;
	return true;
}

/*
 * We reseed when we receive a new connection request if
 * last update was done SYNCOOKIE_LIFETIME ago
 */
static void
syncookie_reseed(void)
{
	struct syncookie_secret *secret = &tcp_syncookie_secret;
	uint8_t *secbits;
	int secbit;

	/*
	 * Reseeding the secret doesn't have to be protected by a lock.
	 * It only must be ensured that the new random values are visible
	 * to all CPUs in a SMP environment.  The atomic with release
	 * semantics ensures that.
	 */
	secbit = (secret->oddeven & 0x1) ? 0 : 1;
	secbits = secret->key[secbit];
	read_frandom(secbits, SYNCOOKIE_SECRET_SIZE);
	os_atomic_add(&secret->oddeven, 1, relaxed);

	tcp_syncookie_secret.last_updated = tcp_now;
}

void
tcp_syncookie_init()
{
	/* Init syncookie secret */
	read_frandom(tcp_syncookie_secret.key[0], SYNCOOKIE_SECRET_SIZE);
	read_frandom(tcp_syncookie_secret.key[1], SYNCOOKIE_SECRET_SIZE);
	tcp_syncookie_secret.last_updated = tcp_now;
}
