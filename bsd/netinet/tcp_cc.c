/*
 * Copyright (c) 2013-2021 Apple Inc. All rights reserved.
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

#include "tcp_includes.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/kern_control.h>
#include <sys/domain.h>

#include <netinet/in.h>
#include <mach/sdt.h>
#include <libkern/OSAtomic.h>

#include <libkern/OSTypes.h>

extern struct tcp_cc_algo tcp_cc_newreno;
extern struct tcp_cc_algo tcp_cc_ledbat;
extern struct tcp_cc_algo tcp_cc_cubic;

 #define SET_SNDSB_IDEAL_SIZE(sndsb, size) \
	sndsb->sb_idealsize = min(max(tcp_sendspace, tp->snd_ssthresh), \
	tcp_autosndbuf_max);

/* Array containing pointers to currently implemented TCP CC algorithms */
struct tcp_cc_algo* tcp_cc_algo_list[TCP_CC_ALGO_COUNT];

static struct tcp_cc_algo tcp_cc_algo_none;
/*
 * Initialize TCP congestion control algorithms.
 */

void
tcp_cc_init(void)
{
	bzero(&tcp_cc_algo_list, sizeof(tcp_cc_algo_list));
	bzero(&tcp_cc_algo_none, sizeof(tcp_cc_algo_none));

	tcp_cc_algo_list[TCP_CC_ALGO_NONE] = &tcp_cc_algo_none;
	tcp_cc_algo_list[TCP_CC_ALGO_NEWRENO_INDEX] = &tcp_cc_newreno;
	tcp_cc_algo_list[TCP_CC_ALGO_BACKGROUND_INDEX] = &tcp_cc_ledbat;
	tcp_cc_algo_list[TCP_CC_ALGO_CUBIC_INDEX] = &tcp_cc_cubic;

	tcp_ccdbg_control_register();
}

void
tcp_cc_resize_sndbuf(struct tcpcb *tp)
{
	struct sockbuf *sb;
	/*
	 * If the send socket buffer size is bigger than ssthresh,
	 * it is time to trim it because we do not want to hold
	 * too many mbufs in the socket buffer
	 */
	sb = &tp->t_inpcb->inp_socket->so_snd;
	if (sb->sb_hiwat > tp->snd_ssthresh &&
	    (sb->sb_flags & SB_AUTOSIZE)) {
		if (sb->sb_idealsize > tp->snd_ssthresh) {
			SET_SNDSB_IDEAL_SIZE(sb, tp->snd_ssthresh);
		}
		sb->sb_flags |= SB_TRIM;
	}
}

void
tcp_bad_rexmt_fix_sndbuf(struct tcpcb *tp)
{
	struct sockbuf *sb;
	sb = &tp->t_inpcb->inp_socket->so_snd;
	if ((sb->sb_flags & (SB_TRIM | SB_AUTOSIZE)) == (SB_TRIM | SB_AUTOSIZE)) {
		/*
		 * If there was a retransmission that was not necessary
		 * then the size of socket buffer can be restored to
		 * what it was before
		 */
		SET_SNDSB_IDEAL_SIZE(sb, tp->snd_ssthresh);
		if (sb->sb_hiwat <= sb->sb_idealsize) {
			sbreserve(sb, sb->sb_idealsize);
			sb->sb_flags &= ~SB_TRIM;
		}
	}
}

/*
 * Calculate initial cwnd according to RFC3390.
 */
void
tcp_cc_cwnd_init_or_reset(struct tcpcb *tp)
{
	if (tp->t_flags & TF_LOCAL) {
		tp->snd_cwnd = tp->t_maxseg * ss_fltsz_local;
	} else {
		if (tcp_cubic_minor_fixes) {
			tp->snd_cwnd = tcp_initial_cwnd(tp);
		} else {
			/* initial congestion window according to RFC 3390 */
			tp->snd_cwnd = min(4 * tp->t_maxseg,
			    max(2 * tp->t_maxseg, TCP_CC_CWND_INIT_BYTES));
		}
	}
}

/*
 * Indicate whether this ack should be delayed.
 * Here is the explanation for different settings of tcp_delack_enabled:
 *  - when set to 1, the behavior is same as when set to 2. We kept this
 *    for binary compatibility.
 *  - when set to 2, will "ack every other packet"
 *      - if our last ack wasn't a 0-sized window.
 *      - if the peer hasn't sent us a TH_PUSH data packet (radar 3649245).
 *              If TH_PUSH is set, take this as a clue that we need to ACK
 *              with no delay. This helps higher level protocols who
 *              won't send us more data even if the window is open
 *              because their last "segment" hasn't been ACKed
 *  - when set to 3,  will do "streaming detection"
 *      - if we receive more than "maxseg_unacked" full packets
 *        in the last 100ms
 *      - if the connection is not in slow-start or idle or
 *        loss/recovery states
 *      - if those criteria aren't met, it will ack every other packet.
 */
int
tcp_cc_delay_ack(struct tcpcb *tp, struct tcphdr *th)
{
	switch (tcp_delack_enabled) {
	case 1:
	case 2:
		if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
		    (th->th_flags & TH_PUSH) == 0 &&
		    (tp->t_unacksegs == 1)) {
			return 1;
		}
		break;
	case 3:
		if (tcp_ack_strategy == TCP_ACK_STRATEGY_LEGACY) {
			if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
			    (th->th_flags & TH_PUSH) == 0 &&
			    ((tp->t_unacksegs == 1) ||
			    ((tp->t_flags & TF_STRETCHACK) &&
			    tp->t_unacksegs < maxseg_unacked))) {
				return 1;
			}
		} else {
			uint32_t recwin;

			/* Get the receive-window we would announce */
			recwin = tcp_sbspace(tp);
			if (recwin > (uint32_t)(TCP_MAXWIN << tp->rcv_scale)) {
				recwin = (uint32_t)(TCP_MAXWIN << tp->rcv_scale);
			}

			/* Delay ACK, if:
			 *
			 * 1. We are not sending a zero-window
			 * 2. We are not forcing fast ACKs
			 * 3. We have more than the low-water mark in receive-buffer
			 * 4. The receive-window is not increasing
			 * 5. We have less than or equal of an MSS unacked or
			 *    Window actually has been growing larger than the initial value by half of it.
			 *    (this makes sure that during ramp-up we ACK every second MSS
			 *    until we pass the tcp_recvspace * 1.5-threshold)
			 * 6. We haven't waited for half a BDP
			 * 7. The amount of unacked data is less than the maximum ACK-burst (256 MSS)
			 *    We try to avoid having the sender end up hitting huge ACK-ranges.
			 *
			 * (a note on 6: The receive-window is
			 * roughly 2 BDP. Thus, recwin / 4 means half a BDP and
			 * thus we enforce an ACK roughly twice per RTT - even
			 * if the app does not read)
			 */
			if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
			    tp->t_forced_acks == 0 &&
			    tp->t_inpcb->inp_socket->so_rcv.sb_cc > tp->t_inpcb->inp_socket->so_rcv.sb_lowat &&
			    recwin <= tp->t_last_recwin &&
			    (tp->rcv_nxt - tp->last_ack_sent <= tp->t_maxseg ||
			    recwin > (uint32_t)(tcp_recvspace + (tcp_recvspace >> 1))) &&
			    (tp->rcv_nxt - tp->last_ack_sent) < (recwin >> 2) &&
			    (tp->rcv_nxt - tp->last_ack_sent) < 256 * tp->t_maxseg) {
				tp->t_stat.acks_delayed++;
				return 1;
			}
		}
		break;
	}
	return 0;
}

void
tcp_cc_allocate_state(struct tcpcb *tp)
{
	if ((tp->tcp_cc_index == TCP_CC_ALGO_CUBIC_INDEX ||
	    tp->tcp_cc_index == TCP_CC_ALGO_BACKGROUND_INDEX) &&
	    tp->t_ccstate == NULL) {
		tp->t_ccstate = &tp->_t_ccstate;

		bzero(tp->t_ccstate, sizeof(*tp->t_ccstate));
	}
}

/*
 * If stretch ack was disabled automatically on long standing connections,
 * re-evaluate the situation after 15 minutes to enable it.
 */
#define TCP_STRETCHACK_DISABLE_WIN (15 * 60 * TCP_RETRANSHZ)
void
tcp_cc_after_idle_stretchack(struct tcpcb *tp)
{
	struct tcp_globals *globals;
	int32_t tdiff;

	if (!(tp->t_flagsext & TF_DISABLE_STRETCHACK)) {
		return;
	}

	globals = tcp_get_globals(tp);
	tdiff = timer_diff(tcp_globals_now(globals), 0, tp->rcv_nostrack_ts, 0);
	if (tdiff < 0) {
		tdiff = -tdiff;
	}

	if (tdiff > TCP_STRETCHACK_DISABLE_WIN) {
		tp->t_flagsext &= ~TF_DISABLE_STRETCHACK;
		tp->t_stretchack_delayed = 0;

		tcp_reset_stretch_ack(tp);
	}
}

/*
 * Detect if the congestion window is non-validated according to
 * draft-ietf-tcpm-newcwv-07
 */
inline uint32_t
tcp_cc_is_cwnd_nonvalidated(struct tcpcb *tp)
{
	struct socket *so = tp->t_inpcb->inp_socket;

	if (tp->t_pipeack == 0) {
		tp->t_flagsext &= ~TF_CWND_NONVALIDATED;
		return 0;
	}

	/*
	 * The congestion window is validated if the number of bytes acked
	 * is more than half of the current window or if there is more
	 * data to send in the send socket buffer
	 */
	if (tp->t_pipeack >= (tp->snd_cwnd >> 1) ||
	    (so != NULL && so->so_snd.sb_cc > tp->snd_cwnd)) {
		tp->t_flagsext &= ~TF_CWND_NONVALIDATED;
	} else {
		tp->t_flagsext |= TF_CWND_NONVALIDATED;
	}

	return tp->t_flagsext & TF_CWND_NONVALIDATED;
}

/*
 * Adjust congestion window in response to congestion in non-validated
 * phase.
 */
inline void
tcp_cc_adjust_nonvalidated_cwnd(struct tcpcb *tp)
{
	tp->t_pipeack = tcp_get_max_pipeack(tp);
	tcp_clear_pipeack_state(tp);
	tp->snd_cwnd = (max(tp->t_pipeack, tp->t_lossflightsize) >> 1);
	if (tcp_cubic_minor_fixes) {
		tp->snd_cwnd = max(tp->snd_cwnd, tp->t_maxseg);
	} else {
		tp->snd_cwnd = max(tp->snd_cwnd, TCP_CC_CWND_INIT_BYTES);
	}
	tp->snd_cwnd += tp->t_maxseg * tcprexmtthresh;
	tp->t_flagsext &= ~TF_CWND_NONVALIDATED;
}

/*
 * Return maximum of all the pipeack samples. Since the number of samples
 * TCP_PIPEACK_SAMPLE_COUNT is 3 at this time, it will be simpler to do
 * a comparision. We should change ths if the number of samples increases.
 */
inline uint32_t
tcp_get_max_pipeack(struct tcpcb *tp)
{
	uint32_t max_pipeack = 0;
	max_pipeack = (tp->t_pipeack_sample[0] > tp->t_pipeack_sample[1]) ?
	    tp->t_pipeack_sample[0] : tp->t_pipeack_sample[1];
	max_pipeack = (tp->t_pipeack_sample[2] > max_pipeack) ?
	    tp->t_pipeack_sample[2] : max_pipeack;

	return max_pipeack;
}

inline void
tcp_clear_pipeack_state(struct tcpcb *tp)
{
	bzero(tp->t_pipeack_sample, sizeof(tp->t_pipeack_sample));
	tp->t_pipeack_ind = 0;
	tp->t_lossflightsize = 0;
}
