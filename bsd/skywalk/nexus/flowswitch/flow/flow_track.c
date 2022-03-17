/*
 * Copyright (c) 2017-2020 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/in_stat.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/kdebug.h>

/* min/max linger time (in seconds */
#define FLOWTRACK_LINGER_MIN    1
#define FLOWTRACK_LINGER_MAX    120

/* maximum allowed rate of SYNs per second */
#define FLOWTRACK_SYN_RATE      20

static int flow_track_tcp(struct flow_entry *, struct flow_track *,
    struct flow_track *, struct __kern_packet *, bool);
static int flow_track_udp(struct flow_entry *, struct flow_track *,
    struct flow_track *, struct __kern_packet *, bool);

static void
flow_track_tcp_get_wscale(struct flow_track *s, struct __kern_packet *pkt)
{
	const uint8_t *hdr = (uint8_t *)(void *)pkt->pkt_flow_tcp_hdr;
	int hlen = pkt->pkt_flow_tcp_hlen;
	uint8_t optlen, wscale = 0;
	const uint8_t *opt;

	_CASSERT(sizeof(s->fse_flags) == sizeof(uint16_t));
	ASSERT(hlen >= (int)sizeof(struct tcphdr));

	opt = hdr + sizeof(struct tcphdr);
	hlen -= sizeof(struct tcphdr);
	while (hlen >= 3) {
		switch (*opt) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			++opt;
			--hlen;
			break;
		case TCPOPT_WINDOW:
			wscale = opt[2];
			if (wscale > TCP_MAX_WINSHIFT) {
				wscale = TCP_MAX_WINSHIFT;
			}
			atomic_bitset_16(&s->fse_flags, FLOWSTATEF_WSCALE);
			OS_FALLTHROUGH;
		default:
			optlen = opt[1];
			if (optlen < 2) {
				optlen = 2;
			}
			hlen -= optlen;
			opt += optlen;
			break;
		}
	}
	s->fse_wscale = wscale;
}

static void
flow_track_tcp_init(struct flow_entry *fe, struct flow_track *src,
    struct flow_track *dst, struct __kern_packet *pkt)
{
#pragma unused(dst)
	const uint8_t tcp_flags = pkt->pkt_flow_tcp_flags;

	/*
	 * Source state initialization.
	 */
	src->fse_state = TCPS_SYN_SENT;
	src->fse_seqlo = ntohl(pkt->pkt_flow_tcp_seq);
	src->fse_seqhi = (src->fse_seqlo + pkt->pkt_flow_ulen + 1);
	if (tcp_flags & TH_SYN) {
		src->fse_seqhi++;
		flow_track_tcp_get_wscale(src, pkt);
	}
	if (tcp_flags & TH_FIN) {
		src->fse_seqhi++;
	}

	src->fse_max_win = MAX(ntohs(pkt->pkt_flow_tcp_win), 1);
	if (src->fse_flags & FLOWSTATEF_WSCALE) {
		/* remove scale factor from initial window */
		int win = src->fse_max_win;
		ASSERT(src->fse_wscale <= TCP_MAX_WINSHIFT);
		win += (1 << src->fse_wscale);
		src->fse_max_win = (uint16_t)((win - 1) >> src->fse_wscale);
	}

	/*
	 * Destination state initialization.
	 */
	dst->fse_state = TCPS_CLOSED;
	dst->fse_seqhi = 1;
	dst->fse_max_win = 1;

	/*
	 * Linger time (in seconds).
	 */
	fe->fe_linger_wait = (2 * tcp_msl) / TCP_RETRANSHZ;
	if (fe->fe_linger_wait < FLOWTRACK_LINGER_MIN) {
		fe->fe_linger_wait = FLOWTRACK_LINGER_MIN;
	} else if (fe->fe_linger_wait > FLOWTRACK_LINGER_MAX) {
		fe->fe_linger_wait = FLOWTRACK_LINGER_MAX;
	}

	atomic_bitset_32(&fe->fe_flags, FLOWENTF_INITED);
}

/*
 * The TCP ACK RTT tracking is a coarse grain measurement of the time it takes
 * for a endpoint to process incoming segment and generate ACK, at the point of
 * observation. For flowswitch, it means that:
 *
 *     local end RTT  = local stack processing time
 *     remote end RTT = driver + network + remote endpoint's processing time
 *
 * Since the measurement is lightweight and sampling based, it won't learn and
 * distinguish lost segment's ACK.  So we could occasionally get large RTT
 * sample from an ACK to a retransmitted segment.  Thus rtt_max is not any
 * meaningful to us.
 */
__attribute__((always_inline))
static inline void
flow_track_tcp_rtt(struct flow_entry *fe, boolean_t input,
    struct flow_track *src, struct flow_track *dst, uint8_t tcp_flags,
    uint32_t seq, uint32_t ack, uint32_t ulen)
{
#pragma unused(fe, input) /* KDBG defined as noop in release build */
	uint64_t dst_last, src_last;
	uint64_t now, time_diff;
	uint32_t curval, oldval;
	clock_sec_t tv_sec;
	clock_usec_t tv_usec;

	src_last = src->fse_rtt.frtt_last;
	dst_last = dst->fse_rtt.frtt_last;

	/* start a new RTT tracking session under sampling rate limit */
	if (dst_last == 0 ||
	    _net_uptime - dst_last > FLOWTRACK_RTT_SAMPLE_INTERVAL) {
		if (ulen > 0 &&
		    dst->fse_rtt.frtt_timestamp == 0) {
			dst->fse_rtt.frtt_timestamp = mach_absolute_time();
			dst->fse_rtt.frtt_last = _net_uptime;
			dst->fse_rtt.frtt_seg_begin = seq;
			dst->fse_rtt.frtt_seg_end = seq + ulen;
			KDBG((SK_KTRACE_FSW_FLOW_TRACK_RTT | DBG_FUNC_START),
			    SK_KVA(fe), fe->fe_pid, ntohs(fe->fe_key.fk_sport),
			    input ? 1 : 0);
		}
	}

	/* we have an ACK, see if current tracking session matches it */
	if (tcp_flags & TH_ACK) {
		if (src->fse_rtt.frtt_timestamp != 0 &&
		    src->fse_rtt.frtt_seg_begin <= ack) {
			now = mach_absolute_time();
			time_diff = now - src->fse_rtt.frtt_timestamp;

			absolutetime_to_microtime(time_diff, &tv_sec, &tv_usec);
			curval = (uint32_t)(tv_usec + tv_sec * 1000 * 1000);
			oldval = src->fse_rtt.frtt_usec;
			if (oldval == 0) {
				src->fse_rtt.frtt_usec = curval;
			} else {
				/* same EWMA decay as TCP RTT */
				src->fse_rtt.frtt_usec =
				    ((oldval << 4) - oldval + curval) >> 4;
			}

			/* reset RTT tracking session */
			src->fse_rtt.frtt_timestamp = 0;
			src->fse_rtt.frtt_last = 0;
			KDBG((SK_KTRACE_FSW_FLOW_TRACK_RTT | DBG_FUNC_END),
			    SK_KVA(fe), fe->fe_pid, ntohs(fe->fe_key.fk_sport),
			    input ? 0 : 1);

			/* publish rtt stats into flow_stats object */
			/* just store both to avoid branch prediction etc. */
			fe->fe_stats->fs_lrtt = fe->fe_ltrack.fse_rtt_usec;
			fe->fe_stats->fs_rrtt = fe->fe_rtrack.fse_rtt_usec;
		}
	}
}

/*
 * The TCP connection tracking logic is based on Guido van Rooij's paper:
 * http://www.sane.nl/events/sane2000/papers/rooij.pdf
 *
 * In some ways, we act as a middlebox that passively tracks the TCP windows
 * of each connection on flows marked with FLOWENTF_TRACK.  We never modify
 * the packet or generate any response (e.g. RST) to the sender; thus we are
 * simply a silent observer.  The information we gather here is used later
 * if we need to generate a valid {FIN|RST} segment when the flow is nonviable.
 *
 * The implementation is borrowed from Packet Filter, and is further
 * simplified to cater for our use cases.
 */
#define FTF_NODELAY     0x1     /* want flow to get immediate attention */
#define FTF_HALFCLOSED  0x2     /* want flow to be marked as half closed */
#define FTF_WAITCLOSE   0x4     /* want flow to linger after close */
#define FTF_CLOSENOTIFY 0x8     /* want to notify NECP upon torn down */
#define FTF_WITHDRAWN   0x10     /* want flow to be torn down */
#define FTF_SYN_RLIM    0x20    /* want flow to rate limit SYN */
#define FTF_RST_RLIM    0x40    /* want flow to rate limit RST */
__attribute__((always_inline))
static inline int
flow_track_tcp(struct flow_entry *fe, struct flow_track *src,
    struct flow_track *dst, struct __kern_packet *pkt, bool input)
{
	const uint8_t tcp_flags = pkt->pkt_flow_tcp_flags;
	uint16_t win = ntohs(pkt->pkt_flow_tcp_win);
	uint32_t ack, end, seq, orig_seq;
	uint32_t ftflags = 0;
	uint8_t sws, dws;
	int ackskew, err = 0;

	if (__improbable((fe->fe_flags & FLOWENTF_INITED) == 0)) {
		flow_track_tcp_init(fe, src, dst, pkt);
	}

	flow_track_tcp_rtt(fe, input, src, dst, tcp_flags,
	    ntohl(pkt->pkt_flow_tcp_seq), ntohl(pkt->pkt_flow_tcp_ack),
	    pkt->pkt_flow_ulen);

	if (__improbable(dst->fse_state >= TCPS_FIN_WAIT_2 &&
	    src->fse_state >= TCPS_FIN_WAIT_2)) {
		if ((tcp_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
			src->fse_state = dst->fse_state = TCPS_CLOSED;
			ftflags |= FTF_SYN_RLIM;
		}
		if (tcp_flags & TH_RST) {
			ftflags |= FTF_RST_RLIM;
		}
		if (input) {
			err = ENETRESET;
		}
		goto done;
	}

	if (__probable((tcp_flags & TH_SYN) == 0 &&
	    src->fse_wscale != 0 && dst->fse_wscale != 0)) {
		sws = src->fse_wscale;
		dws = dst->fse_wscale;
	} else {
		sws = dws = 0;
	}

	orig_seq = seq = ntohl(pkt->pkt_flow_tcp_seq);
	if (__probable(src->fse_seqlo != 0)) {
		ack = ntohl(pkt->pkt_flow_tcp_ack);
		end = seq + pkt->pkt_flow_ulen;
		if (tcp_flags & TH_SYN) {
			if ((tcp_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
				ftflags |= FTF_SYN_RLIM;
			}
			end++;
		}
		if (tcp_flags & TH_FIN) {
			end++;
		}
		if (tcp_flags & TH_RST) {
			ftflags |= FTF_RST_RLIM;
		}
	} else {
		/* first packet from this end; set its state */
		ack = ntohl(pkt->pkt_flow_tcp_ack);
		end = seq + pkt->pkt_flow_ulen;
		if (tcp_flags & TH_SYN) {
			if ((tcp_flags & (TH_SYN | TH_ACK)) == TH_SYN) {
				ftflags |= FTF_SYN_RLIM;
			}
			end++;
			if (dst->fse_flags & FLOWSTATEF_WSCALE) {
				flow_track_tcp_get_wscale(src, pkt);
				if (src->fse_flags & FLOWSTATEF_WSCALE) {
					/*
					 * Remove scale factor from
					 * initial window.
					 */
					sws = src->fse_wscale;
					win = (uint16_t)(((u_int32_t)win + (1 << sws) - 1)
					    >> sws);
					dws = dst->fse_wscale;
				} else {
					/* fixup other window */
					dst->fse_max_win <<= dst->fse_wscale;
					/* in case of a retrans SYN|ACK */
					dst->fse_wscale = 0;
				}
			}
		}
		if (tcp_flags & TH_FIN) {
			end++;
		}
		if (tcp_flags & TH_RST) {
			ftflags |= FTF_RST_RLIM;
		}

		src->fse_seqlo = seq;
		if (src->fse_state < TCPS_SYN_SENT) {
			src->fse_state = TCPS_SYN_SENT;
		}

		/*
		 * May need to slide the window (seqhi may have been set by
		 * the crappy stack check or if we picked up the connection
		 * after establishment).
		 */
		if (src->fse_seqhi == 1 || SEQ_GEQ(end +
		    MAX(1, dst->fse_max_win << dws), src->fse_seqhi)) {
			src->fse_seqhi = end + MAX(1, dst->fse_max_win << dws);
		}
		if (win > src->fse_max_win) {
			src->fse_max_win = win;
		}
	}

	if (!(tcp_flags & TH_ACK)) {
		/* let it pass through the ack skew check */
		ack = dst->fse_seqlo;
	} else if ((ack == 0 &&
	    (tcp_flags & (TH_ACK | TH_RST)) == (TH_ACK | TH_RST)) ||
	    /* broken tcp stacks do not set ack */
	    (dst->fse_state < TCPS_SYN_SENT)) {
		/*
		 * Many stacks (ours included) will set the ACK number in an
		 * FIN|ACK if the SYN times out -- no sequence to ACK.
		 */
		ack = dst->fse_seqlo;
	}

	if (seq == end) {
		/* ease sequencing restrictions on no data packets */
		seq = src->fse_seqlo;
		end = seq;
	}

	ackskew = dst->fse_seqlo - ack;

#define MAXACKWINDOW (0xffff + 1500)    /* 1500 is an arbitrary fudge factor */
	if (SEQ_GEQ(src->fse_seqhi, end) &&
	    /* last octet inside other's window space */
	    SEQ_GEQ(seq, src->fse_seqlo - (dst->fse_max_win << dws)) &&
	    /* retrans: not more than one window back */
	    (ackskew >= -MAXACKWINDOW) &&
	    /* acking not more than one reassembled fragment backwards */
	    (ackskew <= (MAXACKWINDOW << sws)) &&
	    /* acking not more than one window forward */
	    (!(tcp_flags & TH_RST) || orig_seq == src->fse_seqlo ||
	    (orig_seq == src->fse_seqlo + 1) ||
	    (orig_seq + 1 == src->fse_seqlo))) {
		/* require an exact/+1 sequence match on resets when possible */

		/* update max window */
		if (src->fse_max_win < win) {
			src->fse_max_win = win;
		}
		/* synchronize sequencing */
		if (SEQ_GT(end, src->fse_seqlo)) {
			src->fse_seqlo = end;
		}
		/* slide the window of what the other end can send */
		if (SEQ_GEQ(ack + (win << sws), dst->fse_seqhi)) {
			dst->fse_seqhi = ack + MAX((win << sws), 1);
		}

		/* update states */
		if (tcp_flags & TH_SYN) {
			if (src->fse_state < TCPS_SYN_SENT) {
				src->fse_state = TCPS_SYN_SENT;
				ftflags |= FTF_NODELAY;
			}
		}
		if (tcp_flags & TH_FIN) {
			if (src->fse_state < TCPS_CLOSING) {
				src->fse_seqlast = orig_seq;
				src->fse_state = TCPS_CLOSING;
				ftflags |= FTF_NODELAY;
			}
		}
		if (tcp_flags & TH_ACK) {
			/*
			 * Avoid transitioning to ESTABLISHED when our SYN
			 * is ACK'd along with a RST.  The sending TCP may
			 * still retransmit the SYN (after dropping some
			 * options like ECN, etc.)
			 */
			if (dst->fse_state == TCPS_SYN_SENT &&
			    !(tcp_flags & TH_RST)) {
				dst->fse_state = TCPS_ESTABLISHED;
				ftflags |= (FTF_WAITCLOSE | FTF_CLOSENOTIFY |
				    FTF_NODELAY);
			} else if (dst->fse_state == TCPS_CLOSING &&
			    ack == dst->fse_seqlast + 1) {
				dst->fse_state = TCPS_FIN_WAIT_2;
				ftflags |= (FTF_WAITCLOSE | FTF_NODELAY);
				if (src->fse_state >= TCPS_FIN_WAIT_2) {
					ftflags |= FTF_WITHDRAWN;
				} else {
					ftflags |= FTF_HALFCLOSED;
				}
			}
		}
		if ((tcp_flags & TH_RST) &&
		    (src->fse_state == TCPS_ESTABLISHED ||
		    dst->fse_state == TCPS_ESTABLISHED)) {
			/*
			 * If either endpoint is in ESTABLISHED, transition
			 * both to TIME_WAIT.  Otherwise, keep the existing
			 * state as is, e.g. SYN_SENT.
			 */
			src->fse_state = dst->fse_state = TCPS_TIME_WAIT;
			ftflags |= (FTF_WITHDRAWN | FTF_WAITCLOSE | FTF_NODELAY);
		}
		if (tcp_flags & TH_PUSH) {
			ftflags |= FTF_NODELAY;
		}
	} else if ((dst->fse_state < TCPS_SYN_SENT ||
	    dst->fse_state >= TCPS_FIN_WAIT_2 ||
	    src->fse_state >= TCPS_FIN_WAIT_2) &&
	    SEQ_GEQ(src->fse_seqhi + MAXACKWINDOW, end) &&
	    /* within a window forward of the originating packet */
	    SEQ_GEQ(seq, src->fse_seqlo - MAXACKWINDOW)) {
		/* within a window backward of the originating packet */

		/* BEGIN CSTYLED */
		/*
		 * This currently handles three situations:
		 *  1) Stupid stacks will shotgun SYNs before their peer
		 *     replies.
		 *  2) When flow tracking catches an already established
		 *     stream (the flow states are cleared, etc.)
		 *  3) Packets get funky immediately after the connection
		 *     closes (this should catch spurious ACK|FINs that
		 *     web servers like to spew after a close).
		 *
		 * This must be a little more careful than the above code
		 * since packet floods will also be caught here.
		 */
		/* END CSTYLED */

		/* update max window */
		if (src->fse_max_win < win) {
			src->fse_max_win = win;
		}
		/* synchronize sequencing */
		if (SEQ_GT(end, src->fse_seqlo)) {
			src->fse_seqlo = end;
		}
		/* slide the window of what the other end can send */
		if (SEQ_GEQ(ack + (win << sws), dst->fse_seqhi)) {
			dst->fse_seqhi = ack + MAX((win << sws), 1);
		}

		/*
		 * Cannot set dst->fse_seqhi here since this could be a
		 * shotgunned SYN and not an already established connection.
		 */

		if (tcp_flags & TH_FIN) {
			if (src->fse_state < TCPS_CLOSING) {
				src->fse_seqlast = orig_seq;
				src->fse_state = TCPS_CLOSING;
				ftflags |= FTF_NODELAY;
			}
		}
		if (tcp_flags & TH_RST) {
			src->fse_state = dst->fse_state = TCPS_TIME_WAIT;
			ftflags |= (FTF_WAITCLOSE | FTF_NODELAY);
		}
		if (tcp_flags & TH_PUSH) {
			ftflags |= FTF_NODELAY;
		}
	} else {
		if (dst->fse_state == TCPS_SYN_SENT &&
		    src->fse_state == TCPS_SYN_SENT) {
			src->fse_seqlo = 0;
			src->fse_seqhi = 1;
			src->fse_max_win = 1;
		}
	}

done:
	/*
	 * If this needs immediate attention, indicate so.
	 */
	if (__improbable((ftflags & FTF_NODELAY) != 0)) {
		fe->fe_rx_nodelay = true;
		ftflags &= ~FTF_NODELAY;
	} else {
		fe->fe_rx_nodelay = false;
	}

	if (__improbable((ftflags & FTF_HALFCLOSED) != 0)) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_HALF_CLOSED);
		ftflags &= ~FTF_HALFCLOSED;
	}

	/*
	 * Hold on to namespace for a while after the flow is closed.
	 */
	if (__improbable((ftflags & FTF_WAITCLOSE) != 0 &&
	    (fe->fe_flags & FLOWENTF_WAIT_CLOSE) == 0)) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_WAIT_CLOSE);
		ftflags &= ~FTF_WAITCLOSE;
	}

	/*
	 * Notify NECP upon tear down (for established flows).
	 */
	if (__improbable((ftflags & FTF_CLOSENOTIFY) != 0 &&
	    (fe->fe_flags & FLOWENTF_CLOSE_NOTIFY) == 0)) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_CLOSE_NOTIFY);
		ftflags &= ~FTF_CLOSENOTIFY;
	}

	/*
	 * Flow is withdrawn; the port we have should not be included in
	 * the list of offloaded ports, as the connection is no longer
	 * usable (we're not expecting any more data).
	 * Also clear FLOWENTF_HALF_CLOSED flag here. It's fine if reaper
	 * thread hadn't pickedup FLOWENTF_HALF_CLOSED, as it will pick up
	 * FLOWENTF_WITHDRAWN and notify netns of full withdrawn.
	 */
	if (__improbable((ftflags & FTF_WITHDRAWN) != 0)) {
		ftflags &= ~FTF_WITHDRAWN;
		if (fe->fe_flags & FLOWENTF_HALF_CLOSED) {
			atomic_bitclear_32(&fe->fe_flags, FLOWENTF_HALF_CLOSED);
		}
		fe->fe_want_withdraw = 1;
	}

	/*
	 * If no other work is needed, we're done.
	 */
	if (ftflags == 0 || input) {
		return err;
	}

	/*
	 * If we're over the rate limit for outbound SYNs, drop packet.
	 */
	if (__improbable((ftflags & FTF_SYN_RLIM) != 0)) {
		uint32_t now = (uint32_t)_net_uptime;
		if ((now - src->fse_syn_ts) > 1) {
			src->fse_syn_ts = now;
			src->fse_syn_cnt = 0;
		}
		if (++src->fse_syn_cnt > FLOWTRACK_SYN_RATE) {
			err = EPROTO;
		}
	}

	return err;
}
#undef FTF_NODELAY
#undef FTF_WAITCLOSE
#undef FTF_CLOSENOTIFY
#undef FTF_WITHDRAWN
#undef FTF_SYN_RLIM
#undef FTF_RST_RLIM

boolean_t
flow_track_tcp_want_abort(struct flow_entry *fe)
{
	struct flow_track *src = &fe->fe_ltrack;
	struct flow_track *dst = &fe->fe_rtrack;

	if (fe->fe_key.fk_proto != IPPROTO_TCP ||
	    (fe->fe_flags & FLOWENTF_ABORTED)) {
		goto done;
	}

	/* this can be enhanced; for now rely on established state */
	if (src->fse_state == TCPS_ESTABLISHED ||
	    dst->fse_state == TCPS_ESTABLISHED) {
		src->fse_state = dst->fse_state = TCPS_TIME_WAIT;
		/* don't process more than once */
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_ABORTED);
		return TRUE;
	}
done:
	return FALSE;
}

static void
flow_track_udp_init(struct flow_entry *fe, struct flow_track *src,
    struct flow_track *dst, struct __kern_packet *pkt)
{
#pragma unused(pkt)
	/*
	 * Source state initialization.
	 */
	src->fse_state = FT_STATE_NO_TRAFFIC;

	/*
	 * Destination state initialization.
	 */
	dst->fse_state = FT_STATE_NO_TRAFFIC;

	atomic_bitset_32(&fe->fe_flags, FLOWENTF_INITED);
}

__attribute__((always_inline))
static inline int
flow_track_udp(struct flow_entry *fe, struct flow_track *src,
    struct flow_track *dst, struct __kern_packet *pkt, bool input)
{
#pragma unused(input)
	if (__improbable((fe->fe_flags & FLOWENTF_INITED) == 0)) {
		flow_track_udp_init(fe, src, dst, pkt);
	}

	if (__improbable(src->fse_state == FT_STATE_NO_TRAFFIC)) {
		src->fse_state = FT_STATE_SINGLE;
	}
	if (__improbable(dst->fse_state == FT_STATE_SINGLE)) {
		dst->fse_state = FT_STATE_MULTIPLE;
	}

	return 0;
}

void
flow_track_stats(struct flow_entry *fe, uint64_t bytes, uint64_t packets,
    bool active, bool in)
{
	volatile struct sk_stats_flow_track *fst;

	if (in) {
		fst = &fe->fe_stats->fs_rtrack;
	} else {
		fst = &fe->fe_stats->fs_ltrack;
	}

	fst->sft_bytes += bytes;
	fst->sft_packets += packets;

	if (__probable(active)) {
		in_stat_set_activity_bitmap(&fe->fe_stats->fs_activity,
		    _net_uptime);
	}
}

int
flow_pkt_track(struct flow_entry *fe, struct __kern_packet *pkt, bool in)
{
	struct flow_track *src, *dst;
	int ret = 0;

	_CASSERT(SFT_STATE_CLOSED == FT_STATE_CLOSED);
	_CASSERT(SFT_STATE_LISTEN == FT_STATE_LISTEN);
	_CASSERT(SFT_STATE_SYN_SENT == FT_STATE_SYN_SENT);
	_CASSERT(SFT_STATE_SYN_RECEIVED == FT_STATE_SYN_RECEIVED);
	_CASSERT(SFT_STATE_ESTABLISHED == FT_STATE_ESTABLISHED);
	_CASSERT(SFT_STATE_CLOSE_WAIT == FT_STATE_CLOSE_WAIT);
	_CASSERT(SFT_STATE_FIN_WAIT_1 == FT_STATE_FIN_WAIT_1);
	_CASSERT(SFT_STATE_CLOSING == FT_STATE_CLOSING);
	_CASSERT(SFT_STATE_LAST_ACK == FT_STATE_LAST_ACK);
	_CASSERT(SFT_STATE_FIN_WAIT_2 == FT_STATE_FIN_WAIT_2);
	_CASSERT(SFT_STATE_TIME_WAIT == FT_STATE_TIME_WAIT);
	_CASSERT(SFT_STATE_NO_TRAFFIC == FT_STATE_NO_TRAFFIC);
	_CASSERT(SFT_STATE_SINGLE == FT_STATE_SINGLE);
	_CASSERT(SFT_STATE_MULTIPLE == FT_STATE_MULTIPLE);
	_CASSERT(SFT_STATE_MAX == FT_STATE_MAX);

	_CASSERT(FT_STATE_CLOSED == TCPS_CLOSED);
	_CASSERT(FT_STATE_LISTEN == TCPS_LISTEN);
	_CASSERT(FT_STATE_SYN_SENT == TCPS_SYN_SENT);
	_CASSERT(FT_STATE_SYN_RECEIVED == TCPS_SYN_RECEIVED);
	_CASSERT(FT_STATE_ESTABLISHED == TCPS_ESTABLISHED);
	_CASSERT(FT_STATE_CLOSE_WAIT == TCPS_CLOSE_WAIT);
	_CASSERT(FT_STATE_FIN_WAIT_1 == TCPS_FIN_WAIT_1);
	_CASSERT(FT_STATE_CLOSING == TCPS_CLOSING);
	_CASSERT(FT_STATE_LAST_ACK == TCPS_LAST_ACK);
	_CASSERT(FT_STATE_FIN_WAIT_2 == TCPS_FIN_WAIT_2);
	_CASSERT(FT_STATE_TIME_WAIT == TCPS_TIME_WAIT);

	ASSERT(pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED);

	if (in) {
		src = &fe->fe_rtrack;
		dst = &fe->fe_ltrack;
	} else {
		src = &fe->fe_ltrack;
		dst = &fe->fe_rtrack;
	}

	flow_track_stats(fe, (pkt->pkt_length - pkt->pkt_l2_len), 1,
	    (pkt->pkt_flow_ulen != 0), in);

	/* skip flow state tracking on non-initial fragments */
	if (pkt->pkt_flow_ip_is_frag && !pkt->pkt_flow_ip_is_first_frag) {
		return 0;
	}

	switch (pkt->pkt_flow_ip_proto) {
	case IPPROTO_TCP:
		if (__probable((fe->fe_flags & FLOWENTF_TRACK) != 0)) {
			ret = flow_track_tcp(fe, src, dst, pkt, in);
		}
		break;

	case IPPROTO_UDP:
		if (__probable((fe->fe_flags & FLOWENTF_TRACK) != 0)) {
			ret = flow_track_udp(fe, src, dst, pkt, in);
		}
		break;
	}

	return ret;
}
