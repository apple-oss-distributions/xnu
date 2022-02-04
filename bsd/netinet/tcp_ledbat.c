/*
 * Copyright (c) 2010-2020 Apple Inc. All rights reserved.
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
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/protosw.h>
#include <sys/mcache.h>
#include <sys/sysctl.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>

#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcpip.h>
#include <netinet/tcp_cc.h>

#include <libkern/OSAtomic.h>

/* This file implements an alternate TCP congestion control algorithm
 * for background transport developed by LEDBAT working group at IETF and
 * described in draft: draft-ietf-ledbat-congestion-02
 *
 * Currently, it also implements LEDBAT++ as described in draft
 * draft-irtf-iccrg-ledbat-plus-plus-01.
 */

#define GAIN_CONSTANT               (16)
#define DEFER_SLOWDOWN_DURATION     (30 * 1000) /* 30s */

int tcp_ledbat_init(struct tcpcb *tp);
int tcp_ledbat_cleanup(struct tcpcb *tp);
void tcp_ledbat_cwnd_init(struct tcpcb *tp);
void tcp_ledbat_congestion_avd(struct tcpcb *tp, struct tcphdr *th);
void tcp_ledbat_ack_rcvd(struct tcpcb *tp, struct tcphdr *th);
static void ledbat_pp_ack_rcvd(struct tcpcb *tp, uint32_t bytes_acked);
void tcp_ledbat_pre_fr(struct tcpcb *tp);
void tcp_ledbat_post_fr(struct tcpcb *tp, struct tcphdr *th);
void tcp_ledbat_after_idle(struct tcpcb *tp);
void tcp_ledbat_after_timeout(struct tcpcb *tp);
static int tcp_ledbat_delay_ack(struct tcpcb *tp, struct tcphdr *th);
void tcp_ledbat_switch_cc(struct tcpcb *tp);

struct tcp_cc_algo tcp_cc_ledbat = {
	.name = "ledbat",
	.init = tcp_ledbat_init,
	.cleanup = tcp_ledbat_cleanup,
	.cwnd_init = tcp_ledbat_cwnd_init,
	.congestion_avd = tcp_ledbat_congestion_avd,
	.ack_rcvd = tcp_ledbat_ack_rcvd,
	.pre_fr = tcp_ledbat_pre_fr,
	.post_fr = tcp_ledbat_post_fr,
	.after_idle = tcp_ledbat_after_idle,
	.after_timeout = tcp_ledbat_after_timeout,
	.delay_ack = tcp_ledbat_delay_ack,
	.switch_to = tcp_ledbat_switch_cc
};

/* Target queuing delay in milliseconds. This includes the processing
 * and scheduling delay on both of the end-hosts. A LEDBAT sender tries
 * to keep queuing delay below this limit. When the queuing delay
 * goes above this limit, a LEDBAT sender will start reducing the
 * congestion window.
 *
 * The LEDBAT draft says that target queue delay MUST be 100 ms for
 * inter-operability.
 * As we are enabling LEDBAT++ by default, we are updating the target
 * queuing delay to 60ms as recommended by the draft.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, target_qdelay, 40, "Target queuing delay");

/* Allowed increase and tether are used to place an upper bound on
 * congestion window based on the amount of data that is outstanding.
 * This will limit the congestion window when the amount of data in
 * flight is little because the application is writing to the socket
 * intermittently and is preventing the connection from becoming idle .
 *
 * max_allowed_cwnd = allowed_increase + (tether * flight_size)
 * cwnd = min(cwnd, max_allowed_cwnd)
 *
 * 'Allowed_increase' parameter is set to 8. If the flight size is zero, then
 * we want the congestion window to be at least 8 packets to reduce the
 * delay induced by delayed ack. This helps when the receiver is acking
 * more than 2 packets at a time (stretching acks for better performance).
 *
 * 'Tether' is also set to 2. We do not want this to limit the growth of cwnd
 * during slow-start.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_allowed_increase, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, allowed_increase, 8,
    "Additive constant used to calculate max allowed congestion window");

/* Left shift for cwnd to get tether value of 2 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_tether_shift, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tether_shift, 1, "Tether shift for max allowed congestion window");

/* Start with an initial window of 2. This will help to get more accurate
 * minimum RTT measurement in the beginning. It will help to probe
 * the path slowly and will not add to the existing delay if the path is
 * already congested. Using 2 packets will reduce the delay induced by delayed-ack.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_ss_fltsz, CTLFLAG_RW | CTLFLAG_LOCKED,
    uint32_t, bg_ss_fltsz, 2, "Initial congestion window for background transport");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, ledbat_plus_plus, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_ledbat_plus_plus, 1, "Use LEDBAT++");

extern int rtt_samples_per_slot;

#if DEVELOPMENT || DEBUG
static void
update_cwnd(struct tcpcb *tp, uint32_t update, bool is_incr)
#else
static void
update_cwnd(struct tcpcb *tp, uint32_t update, __unused bool is_incr)
#endif
{
	uint32_t max_allowed_cwnd = 0, flight_size = 0;
	uint32_t base_rtt = get_base_rtt(tp);
	uint32_t curr_rtt = tcp_use_min_curr_rtt ? tp->curr_rtt_min :
	    tp->t_rttcur;

	/* If we do not have a good RTT measurement yet, increment
	 * congestion window by the default value.
	 */
	if (base_rtt == 0 || curr_rtt == 0) {
		tp->snd_cwnd += update;
		goto check_max;
	}

	if (curr_rtt <= (base_rtt + target_qdelay)) {
		/*
		 * Delay decreased or remained the same, we can increase
		 * the congestion window according to RFC 3465.
		 *
		 * Move background slow-start threshold to current
		 * congestion window so that the next time (after some idle
		 * period), we can attempt to do slow-start till here if there
		 * is no increase in rtt
		 */
		if (tp->bg_ssthresh < tp->snd_cwnd) {
			tp->bg_ssthresh = tp->snd_cwnd;
		}
		tp->snd_cwnd += update;
		tp->snd_cwnd = tcp_round_to(tp->snd_cwnd, tp->t_maxseg);
	} else {
		if (tcp_ledbat_plus_plus) {
			assert(is_incr == false);
			tp->snd_cwnd -= update;
		} else {
			/* In response to an increase in rtt, reduce the congestion
			 * window by one-eighth. This will help to yield immediately
			 * to a competing stream.
			 */
			uint32_t redwin;

			redwin = tp->snd_cwnd >> 3;
			tp->snd_cwnd -= redwin;
		}

		if (tp->snd_cwnd < bg_ss_fltsz * tp->t_maxseg) {
			tp->snd_cwnd = bg_ss_fltsz * tp->t_maxseg;
		}

		tp->snd_cwnd = tcp_round_to(tp->snd_cwnd, tp->t_maxseg);
		/* Lower background slow-start threshold so that the connection
		 * will go into congestion avoidance phase
		 */
		if (tp->bg_ssthresh > tp->snd_cwnd) {
			tp->bg_ssthresh = tp->snd_cwnd;
		}
	}
check_max:
	if (!tcp_ledbat_plus_plus) {
		/* Calculate the outstanding flight size and restrict the
		 * congestion window to a factor of flight size.
		 */
		flight_size = tp->snd_max - tp->snd_una;

		max_allowed_cwnd = (allowed_increase * tp->t_maxseg)
		    + (flight_size << tether_shift);
		tp->snd_cwnd = min(tp->snd_cwnd, max_allowed_cwnd);
	} else {
		tp->snd_cwnd = min(tp->snd_cwnd, TCP_MAXWIN << tp->snd_scale);
	}
}

static inline void
tcp_ledbat_clear_state(struct tcpcb *tp)
{
	tp->t_ccstate->ledbat_slowdown_events = 0;
	tp->t_ccstate->ledbat_slowdown_ts = 0;
	tp->t_ccstate->ledbat_slowdown_begin = 0;
	tp->t_ccstate->ledbat_md_bytes_acked = 0;
}

int
tcp_ledbat_init(struct tcpcb *tp)
{
	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_ledbat.num_sockets);
	tcp_ledbat_clear_state(tp);
	return 0;
}

int
tcp_ledbat_cleanup(struct tcpcb *tp)
{
#pragma unused(tp)
	OSDecrementAtomic((volatile SInt32 *)&tcp_cc_ledbat.num_sockets);
	return 0;
}

/*
 * Initialize the congestion window for a connection
 */
void
tcp_ledbat_cwnd_init(struct tcpcb *tp)
{
	tp->snd_cwnd = tp->t_maxseg * bg_ss_fltsz;
	tp->bg_ssthresh = tp->snd_ssthresh;
}

/* Function to handle an in-sequence ack which is fast-path processing
 * of an in sequence ack in tcp_input function (called as header prediction).
 * This gets called only during congestion avoidance phase.
 */
void
tcp_ledbat_congestion_avd(struct tcpcb *tp, struct tcphdr *th)
{
	int acked = 0;
	u_int32_t incr = 0;

	acked = BYTES_ACKED(th, tp);

	if (tcp_ledbat_plus_plus) {
		ledbat_pp_ack_rcvd(tp, acked);
	} else {
		tp->t_bytes_acked += acked;
		if (tp->t_bytes_acked > tp->snd_cwnd) {
			tp->t_bytes_acked -= tp->snd_cwnd;
			incr = tp->t_maxseg;
		}

		if (tp->snd_cwnd < tp->snd_wnd && incr > 0) {
			update_cwnd(tp, incr, true);
		}
	}
}

/*
 * Compute the denominator
 * MIN(16, ceil(2 * TARGET / base))
 */
static uint32_t
ledbat_gain(uint32_t base_rtt)
{
	return MIN(GAIN_CONSTANT, tcp_ceil(2 * target_qdelay /
	           (double)base_rtt));
}

/*
 * Congestion avoidance for ledbat++
 */
static void
ledbat_pp_congestion_avd(struct tcpcb *tp, uint32_t bytes_acked,
    uint32_t base_rtt, uint32_t curr_rtt)
{
	uint32_t update = 0;
	/*
	 * Set the next slowdown time i.e. 9 times the duration
	 * of previous slowdown except the initial slowdown.
	 */
	if (tp->t_ccstate->ledbat_slowdown_ts == 0) {
		uint32_t slowdown_duration = 0;
		if (tp->t_ccstate->ledbat_slowdown_events > 0) {
			slowdown_duration = tcp_now -
			    tp->t_ccstate->ledbat_slowdown_begin;

			if (tp->bg_ssthresh > tp->snd_cwnd) {
				/*
				 * Special case for slowdowns (other than initial)
				 * where cwnd doesn't recover fully to previous
				 * ssthresh
				 */
				slowdown_duration *= 2;
			}
		}
		tp->t_ccstate->ledbat_slowdown_ts = tcp_now +
		    (9 * slowdown_duration);
		if (slowdown_duration == 0) {
			tp->t_ccstate->ledbat_slowdown_ts += (2 * (tp->t_srtt >> TCP_RTT_SHIFT));
		}
		/* Reset the start */
		tp->t_ccstate->ledbat_slowdown_begin = 0;

		/* On exit slow start due to higher qdelay, cap the ssthresh */
		if (tp->bg_ssthresh > tp->snd_cwnd) {
			tp->bg_ssthresh = tp->snd_cwnd;
		}
	}

	if (curr_rtt <= base_rtt + target_qdelay) {
		/* Additive increase */
		tp->t_bytes_acked += bytes_acked;
		if (tp->t_bytes_acked >= tp->snd_cwnd) {
			update = tp->t_maxseg;
			tp->t_bytes_acked -= tp->snd_cwnd;
			update_cwnd(tp, update, true);
		}
	} else {
		/*
		 * Multiplicative decrease
		 * W -= min(W * (qdelay/target - 1), W/2) (per RTT)
		 * To calculate per bytes acked, it becomes
		 * W -= min((qdelay/target - 1), 1/2) * bytes_acked
		 */
		uint32_t qdelay = curr_rtt > base_rtt ?
		    (curr_rtt - base_rtt) : 0;

		tp->t_ccstate->ledbat_md_bytes_acked += bytes_acked;
		if (tp->t_ccstate->ledbat_md_bytes_acked >= tp->snd_cwnd) {
			update = (uint32_t)(MIN(((double)qdelay / target_qdelay
			    - 1), 0.5) * (double)tp->snd_cwnd);
			tp->t_ccstate->ledbat_md_bytes_acked -= tp->snd_cwnd;
			update_cwnd(tp, update, false);

			if (tp->t_ccstate->ledbat_slowdown_ts != 0) {
				/*
				 * As the window has been reduced,
				 * defer the slowdown.
				 */
				tp->t_ccstate->ledbat_slowdown_ts = tcp_now +
				    DEFER_SLOWDOWN_DURATION;
			}
		}
	}
}

/*
 * Different handling for ack received for ledbat++
 */
static void
ledbat_pp_ack_rcvd(struct tcpcb *tp, uint32_t bytes_acked)
{
	uint32_t update = 0;
	const uint32_t base_rtt = get_base_rtt(tp);
	const uint32_t curr_rtt = tcp_use_min_curr_rtt ? tp->curr_rtt_min :
	    tp->t_rttcur;
	const uint32_t ss_target = (uint32_t)(3 * target_qdelay / 4);

	/*
	 * Slowdown period - first slowdown
	 * is 2RTT after we exit initial slow start.
	 * Subsequent slowdowns are after 9 times the
	 * previous slow down durations.
	 */
	if (tp->t_ccstate->ledbat_slowdown_ts != 0 &&
	    tcp_now >= tp->t_ccstate->ledbat_slowdown_ts) {
		if (tp->t_ccstate->ledbat_slowdown_begin == 0) {
			tp->t_ccstate->ledbat_slowdown_begin = tcp_now;
			tp->t_ccstate->ledbat_slowdown_events++;
		}
		if (tcp_now < tp->t_ccstate->ledbat_slowdown_ts +
		    (2 * (tp->t_srtt >> TCP_RTT_SHIFT))) {
			// Set cwnd to 2 packets and return
			if (tp->snd_cwnd > bg_ss_fltsz * tp->t_maxseg) {
				if (tp->bg_ssthresh < tp->snd_cwnd) {
					tp->bg_ssthresh = tp->snd_cwnd;
				}
				tp->snd_cwnd = bg_ss_fltsz * tp->t_maxseg;
				/* Reset total bytes acked */
				tp->t_bytes_acked = 0;
			}
			return;
		}
	}
	if (curr_rtt == 0 || base_rtt == 0) {
		update = MIN(bytes_acked, TCP_CC_CWND_INIT_PKTS *
		    tp->t_maxseg);
		update_cwnd(tp, update, true);
	} else if (tp->snd_cwnd < tp->bg_ssthresh &&
	    ((tp->t_ccstate->ledbat_slowdown_events > 0 &&
	    curr_rtt <= (base_rtt + target_qdelay)) ||
	    curr_rtt <= (base_rtt + ss_target))) {
		/*
		 * Modified slow start with a dynamic GAIN
		 * If the queuing delay is larger than 3/4 of the target
		 * delay, exit slow start, iff, it is the initial slow start.
		 * After the initial slow start, during CA, window growth
		 * will be bound by ssthresh.
		 */
		tp->t_bytes_acked += bytes_acked;
		uint32_t gain_factor = ledbat_gain(base_rtt);
		if (tp->t_bytes_acked >= tp->t_maxseg * gain_factor) {
			update = MIN(tp->t_bytes_acked / gain_factor,
			    TCP_CC_CWND_INIT_PKTS * tp->t_maxseg);
			tp->t_bytes_acked = 0;
			update_cwnd(tp, update, true);
		}

		/* Reset the next slowdown timestamp */
		if (tp->t_ccstate->ledbat_slowdown_ts != 0) {
			tp->t_ccstate->ledbat_slowdown_ts = 0;
		}
	} else {
		/* Congestion avoidance */
		ledbat_pp_congestion_avd(tp, bytes_acked, base_rtt, curr_rtt);
	}
}

/* Function to process an ack.
 */
void
tcp_ledbat_ack_rcvd(struct tcpcb *tp, struct tcphdr *th)
{
	/*
	 * RFC 3465 - Appropriate Byte Counting.
	 *
	 * If the window is currently less than ssthresh,
	 * open the window by the number of bytes ACKed by
	 * the last ACK, however clamp the window increase
	 * to an upper limit "L".
	 *
	 * In congestion avoidance phase, open the window by
	 * one segment each time "bytes_acked" grows to be
	 * greater than or equal to the congestion window.
	 */

	uint32_t cw = tp->snd_cwnd;
	uint32_t incr = tp->t_maxseg;
	uint32_t acked = 0;

	acked = BYTES_ACKED(th, tp);

	if (tcp_ledbat_plus_plus) {
		ledbat_pp_ack_rcvd(tp, acked);
		return;
	}

	tp->t_bytes_acked += acked;

	if (cw >= tp->bg_ssthresh) {
		/* congestion-avoidance */
		if (tp->t_bytes_acked < cw) {
			/* No need to increase yet. */
			incr = 0;
		}
	} else {
		/*
		 * If the user explicitly enables RFC3465
		 * use 2*SMSS for the "L" param.  Otherwise
		 * use the more conservative 1*SMSS.
		 *
		 * (See RFC 3465 2.3 Choosing the Limit)
		 */
		u_int abc_lim;

		abc_lim = (tp->snd_nxt == tp->snd_max) ? incr * 2 : incr;

		incr = ulmin(acked, abc_lim);
	}
	if (tp->t_bytes_acked >= cw) {
		tp->t_bytes_acked -= cw;
	}
	if (incr > 0) {
		update_cwnd(tp, incr, true);
	}
}

void
tcp_ledbat_pre_fr(struct tcpcb *tp)
{
	uint32_t win;

	win = min(tp->snd_wnd, tp->snd_cwnd);

	if (tp->t_flagsext & TF_CWND_NONVALIDATED) {
		tp->t_lossflightsize = tp->snd_max - tp->snd_una;
		win = max(tp->t_pipeack, tp->t_lossflightsize);
	} else {
		tp->t_lossflightsize = 0;
	}

	win = win / 2;
	win = tcp_round_to(win, tp->t_maxseg);
	if (win < 2 * tp->t_maxseg) {
		win = 2 * tp->t_maxseg;
	}
	tp->snd_ssthresh = win;
	if (tp->bg_ssthresh > tp->snd_ssthresh) {
		tp->bg_ssthresh = tp->snd_ssthresh;
	}

	tcp_cc_resize_sndbuf(tp);
}

void
tcp_ledbat_post_fr(struct tcpcb *tp, struct tcphdr *th)
{
	int32_t ss;

	if (th) {
		ss = tp->snd_max - th->th_ack;
	} else {
		ss = tp->snd_max - tp->snd_una;
	}

	/*
	 * Complete ack.  Inflate the congestion window to
	 * ssthresh and exit fast recovery.
	 *
	 * Window inflation should have left us with approx.
	 * snd_ssthresh outstanding data.  But in case we
	 * would be inclined to send a burst, better to do
	 * it via the slow start mechanism.
	 *
	 * If the flight size is zero, then make congestion
	 * window to be worth at least 2 segments to avoid
	 * delayed acknowledgement (draft-ietf-tcpm-rfc3782-bis-05).
	 */
	if (ss < (int32_t)tp->snd_ssthresh) {
		tp->snd_cwnd = max(ss, tp->t_maxseg) + tp->t_maxseg;
	} else {
		tp->snd_cwnd = tp->snd_ssthresh;
	}
	tp->t_bytes_acked = 0;
	tp->t_ccstate->ledbat_md_bytes_acked = 0;
}

/*
 * Function to handle connections that have been idle for
 * some time. Slow start to get ack "clock" running again.
 * Clear base history after idle time.
 */
void
tcp_ledbat_after_idle(struct tcpcb *tp)
{
	tcp_ledbat_clear_state(tp);
	/* Reset the congestion window */
	tp->snd_cwnd = tp->t_maxseg * bg_ss_fltsz;
	tp->t_bytes_acked = 0;
	tp->t_ccstate->ledbat_md_bytes_acked = 0;
}

/* Function to change the congestion window when the retransmit
 * timer fires. The behavior is the same as that for best-effort
 * TCP, reduce congestion window to one segment and start probing
 * the link using "slow start". The slow start threshold is set
 * to half of the current window. Lower the background slow start
 * threshold also.
 */
void
tcp_ledbat_after_timeout(struct tcpcb *tp)
{
	if (tp->t_state >= TCPS_ESTABLISHED) {
		tcp_ledbat_clear_state(tp);
		tcp_ledbat_pre_fr(tp);
		tp->snd_cwnd = tp->t_maxseg;
	}
}

/*
 * Indicate whether this ack should be delayed.
 * We can delay the ack if:
 *      - our last ack wasn't a 0-sized window.
 *      - the peer hasn't sent us a TH_PUSH data packet: if he did, take this
 *      as a clue that we need to ACK without any delay. This helps higher
 *	level protocols who won't send us more data even if the window is
 *      open because their last "segment" hasn't been ACKed
 * Otherwise the receiver will ack every other full-sized segment or when the
 * delayed ack timer fires. This will help to generate better rtt estimates for
 * the other end if it is a ledbat sender.
 *
 */

static int
tcp_ledbat_delay_ack(struct tcpcb *tp, struct tcphdr *th)
{
	if (tcp_ack_strategy == TCP_ACK_STRATEGY_MODERN) {
		return tcp_cc_delay_ack(tp, th);
	} else {
		if ((tp->t_flags & TF_RXWIN0SENT) == 0 &&
		    (th->th_flags & TH_PUSH) == 0 && (tp->t_unacksegs == 1)) {
			return 1;
		}
		return 0;
	}
}

/* Change a connection to use ledbat. First, lower bg_ssthresh value
 * if it needs to be.
 */
void
tcp_ledbat_switch_cc(struct tcpcb *tp)
{
	uint32_t cwnd;
	tcp_ledbat_clear_state(tp);

	if (tp->bg_ssthresh == 0 || tp->bg_ssthresh > tp->snd_ssthresh) {
		tp->bg_ssthresh = tp->snd_ssthresh;
	}

	cwnd = min(tp->snd_wnd, tp->snd_cwnd);

	if (tp->snd_cwnd > tp->bg_ssthresh) {
		cwnd = cwnd / tp->t_maxseg;
	} else {
		cwnd = cwnd / 2 / tp->t_maxseg;
	}

	if (cwnd < bg_ss_fltsz) {
		cwnd = bg_ss_fltsz;
	}

	tp->snd_cwnd = cwnd * tp->t_maxseg;
	tp->t_bytes_acked = 0;

	OSIncrementAtomic((volatile SInt32 *)&tcp_cc_ledbat.num_sockets);
}
