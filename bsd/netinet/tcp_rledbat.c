/*
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>

#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>

/*
 * This file implements a LBE congestion control algorithm
 * to compute the receive window of a background transport
 * which uses same algorithm as ledbat-plus-plus.
 */

#define GAIN_CONSTANT               (16)
#define DEFER_SLOWDOWN_DURATION     (30 * 1000) /* 30s */

SYSCTL_SKMEM_TCP_INT(OID_AUTO, rledbat, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_rledbat, 1, "Use Receive LEDBAT");

void tcp_rledbat_init(struct tcpcb *tp);
void tcp_rledbat_cleanup(struct tcpcb *tp);
void tcp_rledbat_rwnd_init(struct tcpcb *tp);
void tcp_rledbat_data_rcvd(struct tcpcb *tp, struct tcphdr *th,
    struct tcpopt *to, uint32_t segment_len);
uint32_t tcp_rledbat_get_rlwin(struct tcpcb *tp);
void tcp_rledbat_after_idle(struct tcpcb *tp);
void tcp_rledbat_switch_to(struct tcpcb *tp);

struct tcp_rcv_cc_algo tcp_cc_rledbat = {
	.name = "rledbat",
	.init = tcp_rledbat_init,
	.cleanup = tcp_rledbat_cleanup,
	.rwnd_init = tcp_rledbat_rwnd_init,
	.data_rcvd = tcp_rledbat_data_rcvd,
	.get_rlwin = tcp_rledbat_get_rlwin,
	.after_idle = tcp_rledbat_after_idle,
	.switch_to = tcp_rledbat_switch_to,
};

static inline void
rledbat_clear_state(struct tcpcb *tp)
{
	tp->t_rlstate.num_slowdown_events = 0;
	tp->t_rlstate.slowdown_ts = 0;
	tp->t_rlstate.slowdown_begin = 0;
	tp->t_rlstate.rcvd_bytes = 0;
	tp->t_rlstate.md_rcvd_bytes = 0;
	tp->t_rlstate.drained_bytes = 0;
}

void
tcp_rledbat_init(struct tcpcb *tp)
{
	OSIncrementAtomic((volatile int *)&tcp_cc_rledbat.num_sockets);
	rledbat_clear_state(tp);

	tp->t_rlstate.win = tp->t_maxseg * bg_ss_fltsz;
	tp->t_rlstate.ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
}

void
tcp_rledbat_cleanup(struct tcpcb *tp)
{
#pragma unused(tp)
	OSDecrementAtomic((volatile int *)&tcp_cc_rledbat.num_sockets);
}

/*
 * Initialize the receive window for a connection
 */
void
tcp_rledbat_rwnd_init(struct tcpcb *tp)
{
	tp->t_rlstate.win = tp->t_maxseg * bg_ss_fltsz;

	/* If the ssthresh hasn't been set, do it now */
	if (tp->t_rlstate.ssthresh == 0) {
		tp->t_rlstate.ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	}
}

/*
 * Compute the denominator
 * MIN(16, ceil(2 * TARGET / base))
 */
static uint32_t
rledbat_gain(uint32_t base_rtt)
{
	return MIN(GAIN_CONSTANT, tcp_ceil(2 * target_qdelay /
	           (double)base_rtt));
}

/*
 * Congestion avoidance for ledbat++
 */
static void
rledbat_congestion_avd(struct tcpcb *tp, uint32_t segment_len,
    uint32_t base_rtt, uint32_t curr_rtt)
{
	uint32_t update = 0;
	/*
	 * Set the next slowdown time i.e. 9 times the duration
	 * of previous slowdown except the initial slowdown.
	 */
	if (tp->t_rlstate.slowdown_ts == 0) {
		uint32_t slowdown_duration = 0;
		if (tp->t_rlstate.num_slowdown_events > 0) {
			slowdown_duration = tcp_now -
			    tp->t_rlstate.slowdown_begin;

			if (tp->t_rlstate.ssthresh > tp->t_rlstate.win) {
				/*
				 * Special case for slowdowns (other than initial)
				 * where cwnd doesn't recover fully to previous
				 * ssthresh
				 */
				slowdown_duration *= 2;
			}
		}
		tp->t_rlstate.slowdown_ts = tcp_now +
		    (9 * slowdown_duration);
		if (slowdown_duration == 0) {
			tp->t_rlstate.slowdown_ts += (2 * (tp->rcv_srtt >> TCP_RTT_SHIFT));
		}
		/* Reset the start */
		tp->t_rlstate.slowdown_begin = 0;

		/* On exit slow start due to higher qdelay, cap the ssthresh */
		if (tp->t_rlstate.ssthresh > tp->t_rlstate.win) {
			tp->t_rlstate.ssthresh = tp->t_rlstate.win;
		}
	}

	if (curr_rtt <= base_rtt + (uint32_t)target_qdelay) {
		/* Additive increase */
		tp->t_rlstate.rcvd_bytes += segment_len;
		if (tp->t_rlstate.rcvd_bytes >= tp->t_rlstate.win) {
			update = tp->t_maxseg;
			tp->t_rlstate.rcvd_bytes -= tp->t_rlstate.win;
			/*
			 * Move background slow-start threshold to current
			 * congestion window so that the next time (after some idle
			 * period), we can attempt to do slow-start till here if there
			 * is no increase in rtt
			 */
			if (tp->t_rlstate.ssthresh < tp->t_rlstate.win) {
				tp->t_rlstate.ssthresh = tp->t_rlstate.win;
			}
			tp->t_rlstate.win += update;
			tp->t_rlstate.win = min(tcp_round_to(tp->t_rlstate.win,
			    tp->t_maxseg), TCP_MAXWIN << tp->rcv_scale);
		}
	} else {
		/*
		 * If we are still within 1 RTT of previous reduction
		 * due to loss, do nothing
		 */
		if (tcp_now < tp->t_rlstate.reduction_end) {
			return;
		}
		/*
		 * Multiplicative decrease
		 * W -= min(W * (qdelay/target - 1), W/2) (per RTT)
		 * To calculate per bytes acked, it becomes
		 * W -= min((qdelay/target - 1), 1/2) * bytes_acked
		 */
		uint32_t qdelay = curr_rtt > base_rtt ?
		    (curr_rtt - base_rtt) : 0;

		tp->t_rlstate.md_rcvd_bytes += segment_len;
		if (tp->t_rlstate.md_rcvd_bytes >= tp->t_rlstate.win) {
			update = (uint32_t)(MIN(((double)qdelay / target_qdelay - 1), 0.5) *
			    (double)tp->t_rlstate.win);
			tp->t_rlstate.md_rcvd_bytes -= tp->t_rlstate.win;
			tp->t_rlstate.win -= update;

			if (tp->t_rlstate.win < bg_ss_fltsz * tp->t_maxseg) {
				tp->t_rlstate.win = bg_ss_fltsz * tp->t_maxseg;
			}

			tp->t_rlstate.win = tcp_round_to(tp->t_rlstate.win, tp->t_maxseg);
			/*
			 * Lower background slow-start threshold so that the connection
			 * will stay in congestion avoidance phase
			 */
			if (tp->t_rlstate.ssthresh > tp->t_rlstate.win) {
				tp->t_rlstate.ssthresh = tp->t_rlstate.win;
			}

			if (tp->t_rlstate.slowdown_ts != 0) {
				/* As the window has been reduced, defer the slowdown */
				tp->t_rlstate.slowdown_ts = tcp_now +
				    DEFER_SLOWDOWN_DURATION;
			}
		}
	}
}

/*
 * Update win based on ledbat++ algo
 */
void
tcp_rledbat_data_rcvd(struct tcpcb *tp, struct tcphdr *th,
    struct tcpopt *to, uint32_t segment_len)
{
	uint32_t update = 0;
	const uint32_t base_rtt = get_base_rtt(tp);
	const uint32_t curr_rtt = tcp_use_min_curr_rtt ? tp->curr_rtt_min :
	    tp->t_rttcur;
	const uint32_t ss_target = (uint32_t)(3 * target_qdelay / 4);
	tp->t_rlstate.drained_bytes += segment_len;

	/*
	 * Slowdown period - first slowdown
	 * is 2RTT after we exit initial slow start.
	 * Subsequent slowdowns are after 9 times the
	 * previous slow down durations.
	 */
	if (tp->t_rlstate.slowdown_ts != 0 &&
	    tcp_now >= tp->t_rlstate.slowdown_ts) {
		if (tp->t_rlstate.slowdown_begin == 0) {
			tp->t_rlstate.slowdown_begin = tcp_now;
			tp->t_rlstate.num_slowdown_events++;
		}
		if (tcp_now < tp->t_rlstate.slowdown_ts +
		    (2 * (tp->rcv_srtt >> TCP_RTT_SHIFT))) {
			// Set rwnd to 2 packets and return
			if (tp->t_rlstate.win > bg_ss_fltsz * tp->t_maxseg) {
				if (tp->t_rlstate.ssthresh < tp->t_rlstate.win) {
					tp->t_rlstate.ssthresh = tp->t_rlstate.win;
				}
				tp->t_rlstate.win = bg_ss_fltsz * tp->t_maxseg;
				/* Reset total bytes acked */
				tp->t_rlstate.rcvd_bytes = 0;
			}
			return;
		}
	}

	/*
	 * Detect retransmissions first by checking if the current
	 * received sequence is smaller than largest and its
	 * timestamp is higher than the largest so far. Reduce
	 * win based on fast recovery only once per effective RTT.
	 *
	 * Note: As we are detecting retransmissions (not packet loss),
	 * we are giving some leeway for the next window reduction.
	 */
	if (SEQ_LT(th->th_seq + segment_len, tp->rcv_high) &&
	    TSTMP_GEQ(to->to_tsval, tp->tsv_high)) {
		if (tcp_now < tp->t_rlstate.reduction_end) {
			/* still need to wait for reduction end to elapse */
			return;
		}

		uint32_t win = tp->t_rlstate.win / 2;
		win = tcp_round_to(win, tp->t_maxseg);
		if (win < 2 * tp->t_maxseg) {
			win = 2 * tp->t_maxseg;
		}
		tp->t_rlstate.ssthresh = win;
		tp->t_rlstate.win = win;

		/* Reset the received bytes */
		tp->t_rlstate.rcvd_bytes = 0;
		tp->t_rlstate.md_rcvd_bytes = 0;

		/* Update the reduction end time */
		tp->t_rlstate.reduction_end = tcp_now + 2 *
		    (tp->rcv_srtt >> TCP_RTT_SHIFT);

		if (tp->t_rlstate.slowdown_ts != 0) {
			/* As the window has been halved, defer the slowdown. */
			tp->t_rlstate.slowdown_ts = tcp_now +
			    DEFER_SLOWDOWN_DURATION;
		}
		return;
	}

	/* Now we can do slow start or CA */
	if (curr_rtt == 0 || base_rtt == 0) {
		update = MIN(segment_len, TCP_CC_CWND_INIT_PKTS *
		    tp->t_maxseg);
		tp->t_rlstate.win += update;
		tp->t_rlstate.win = min(tp->t_rlstate.win,
		    TCP_MAXWIN << tp->rcv_scale);
	} else if (tp->t_rlstate.win < tp->t_rlstate.ssthresh &&
	    ((tp->t_rlstate.num_slowdown_events > 0 &&
	    curr_rtt <= (base_rtt + (uint32_t)target_qdelay)) ||
	    curr_rtt <= (base_rtt + ss_target))) {
		/*
		 * Modified slow start with a dynamic GAIN
		 * If the queuing delay is larger than 3/4 of the target
		 * delay, exit slow start, iff, it is the initial slow start.
		 * After the initial slow start, during CA, window growth
		 * will be bound by ssthresh.
		 */
		tp->t_rlstate.rcvd_bytes += segment_len;
		uint32_t gain_factor = rledbat_gain(base_rtt);
		if (tp->t_rlstate.rcvd_bytes >= tp->t_maxseg * gain_factor) {
			update = MIN(tp->t_rlstate.rcvd_bytes / gain_factor,
			    TCP_CC_CWND_INIT_PKTS * tp->t_maxseg);
			tp->t_rlstate.rcvd_bytes = 0;
			tp->t_rlstate.win += update;
			tp->t_rlstate.win = min(tcp_round_to(tp->t_rlstate.win,
			    tp->t_maxseg), TCP_MAXWIN << tp->rcv_scale);
		}

		/* Reset the next slowdown timestamp */
		if (tp->t_rlstate.slowdown_ts != 0) {
			tp->t_rlstate.slowdown_ts = 0;
		}
	} else {
		/* Congestion avoidance */
		rledbat_congestion_avd(tp, segment_len, base_rtt, curr_rtt);
	}
}

uint32_t
tcp_rledbat_get_rlwin(struct tcpcb *tp)
{
	/* rlwin is either greater or smaller by at most drained bytes */
	if (tp->t_rlstate.win > tp->t_rlstate.win_ws ||
	    tp->t_rlstate.win_ws - tp->t_rlstate.win <
	    tp->t_rlstate.drained_bytes) {
		tp->t_rlstate.win_ws = tp->t_rlstate.win;
	} else if (tp->t_rlstate.win < tp->t_rlstate.win_ws) {
		/*
		 * rlwin is smaller, decrease the advertised window
		 * only by drained bytes at a time
		 */
		tp->t_rlstate.win_ws = tp->t_rlstate.win_ws -
		    tp->t_rlstate.drained_bytes;
	}
	tp->t_rlstate.drained_bytes = 0;
	/* Round up to the receive window scale */
	tp->t_rlstate.win_ws = tcp_round_up(tp->t_rlstate.win_ws,
	    1 << tp->rcv_scale);

	return tp->t_rlstate.win_ws;
}

/*
 * Function to handle connections that have been idle for
 * some time. Slow start to get ack "clock" running again.
 * Clear base history after idle time.
 */
void
tcp_rledbat_after_idle(struct tcpcb *tp)
{
	rledbat_clear_state(tp);
	/* Reset the rledbat window */
	tp->t_rlstate.win = tp->t_maxseg * bg_ss_fltsz;
}

void
tcp_rledbat_switch_to(struct tcpcb *tp)
{
	rledbat_clear_state(tp);

	uint32_t win = 0;

	if (tp->t_rlstate.win == 0) {
		/*
		 * Use half of previous window, the algorithm
		 * will quickly reduce the window if there is still
		 * high queueing delay.
		 */
		win = (tp->rcv_adv - tp->rcv_nxt) / 2;
	} else {
		/* Reduce the window by half from the previous value */
		win = tp->t_rlstate.win / 2;
	}

	win = tcp_round_to(win, tp->t_maxseg);
	if (win < bg_ss_fltsz * tp->t_maxseg) {
		win = bg_ss_fltsz * tp->t_maxseg;
	}
	tp->t_rlstate.win = win;

	/* ssthresh should be at most the inital value */
	if (tp->t_rlstate.ssthresh == 0) {
		tp->t_rlstate.ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	} else {
		tp->t_rlstate.ssthresh = MIN(tp->t_rlstate.ssthresh,
		    TCP_MAXWIN << TCP_MAX_WINSHIFT);
	}
}
