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

 #include "tcp_includes.h"

static int tcp_prague_init(struct tcpcb *tp);
static int tcp_prague_cleanup(struct tcpcb *tp);
static void tcp_prague_cwnd_init_or_reset(struct tcpcb *tp);
static void tcp_prague_ack_rcvd(struct tcpcb *tp, struct tcphdr *th);
static void tcp_prague_pre_fr(struct tcpcb *tp);
static void tcp_prague_post_fr(struct tcpcb *tp, struct tcphdr *th);
static void tcp_prague_after_timeout(struct tcpcb *tp);
static int tcp_prague_delay_ack(struct tcpcb *tp, struct tcphdr *th);
static void tcp_prague_switch_cc(struct tcpcb *tp);
static void tcp_prague_clear_state(struct tcpcb *tp);
static void tcp_prague_process_ecn(struct tcpcb *tp, struct tcphdr *th, uint32_t new_bytes_marked,
    uint32_t packets_marked, uint32_t packets_acked);
static void tcp_prague_set_bytes_acked(struct tcpcb *tp, uint32_t acked);

static void prague_update_pacer_state(struct tcpcb *tp);
static void prague_ca_after_ce(struct tcpcb *tp, uint32_t acked);

extern float cbrtf(float x);

struct tcp_cc_algo tcp_cc_prague = {
	.name = "prague",
	.init = tcp_prague_init,
	.cleanup = tcp_prague_cleanup,
	.cwnd_init = tcp_prague_cwnd_init_or_reset,
	.congestion_avd = tcp_prague_ack_rcvd,
	.ack_rcvd = tcp_prague_ack_rcvd,
	.pre_fr = tcp_prague_pre_fr,
	.post_fr = tcp_prague_post_fr,
	.after_idle = tcp_prague_cwnd_init_or_reset,
	.after_timeout = tcp_prague_after_timeout,
	.delay_ack = tcp_prague_delay_ack,
	.process_ecn = tcp_prague_process_ecn,
	.set_bytes_acked = tcp_prague_set_bytes_acked,
	.switch_to = tcp_prague_switch_cc
};

/*
 * Prague state includes:
 * 1. Exponentially Weighted Moving Average (EWMA) -> alpha, of fraction of CE marks [0,1]
 * 2. g is the estimation gain, a real number between 0 and 1, we use 1/2^4
 * 3. scaled_alpha is alpha / g or alpha << g_shift
 */
#define ALPHA_SHIFT                 (20)
#define G_SHIFT                     (4)
#define CWND_SHIFT                  (20)
#define MAX_ALPHA                   (1ULL << ALPHA_SHIFT)
#define REF_RTT_RATE                (25)   /* 25 ms */

#define BURST_SHIFT (12)        /* 1/(2^12) = 0.000244s, we allow a burst queue of at least 250us */

#define PACING_INITIAL_RTT (100)   /* 100ms, Only used to calculate startup pacer rate */
#define MSEC_PER_SEC       (1000)  /* milliseconds per second */

static float cubic_beta = 0.7f;
static float cubic_one_sub_beta = 0.3f;
static float cubic_one_add_beta = 1.7f;
static float cubic_fast_convergence_factor = 0.85f;
static float cubic_c_factor = 0.4f;

/*
 * Compute the target congestion window for the next RTT according to
 * cubic equation when an ack is received.
 *
 * W(t) = C(t-K)^3 + Wmax
 */
static uint32_t
cubic_target(struct tcpcb *tp, uint32_t srtt)
{
	struct tcp_globals *globals = tcp_get_globals(tp);
	float K = 0;

	if (tp->t_ccstate->cubic_epoch_start == 0) {
		/*
		 * This is the beginning of a new epoch after recovery, initialize
		 * some of the variables that we need to use for computing the
		 * congestion window later.
		 */
		tp->t_ccstate->cubic_epoch_start = tcp_globals_now(globals);
		if (tp->t_ccstate->cubic_epoch_start == 0) {
			tp->t_ccstate->cubic_epoch_start = 1;
		}
		if (tp->snd_cwnd < tp->t_ccstate->cubic_W_max) {
			/*
			 * Compute cubic epoch period, this is the time
			 * period that the window will take to increase to
			 * Wmax again after reduction due to loss.
			 */

			K = ((float)(tp->t_ccstate->cubic_W_max - tp->snd_cwnd)) / cubic_c_factor / tp->t_maxseg;
			K = cbrtf(K);
			tp->t_ccstate->cubic_K = K * TCP_RETRANSHZ; /* in milliseconds */
			tp->t_ccstate->cubic_origin_point = tp->t_ccstate->cubic_W_max;
		} else {
			tp->t_ccstate->cubic_K = 0;
			tp->t_ccstate->cubic_origin_point = tp->t_ccstate->cubic_W_max = tp->snd_cwnd;
		}
	}

	if (tp->t_ccstate->cubic_origin_point == 0) {
		os_log_error(OS_LOG_DEFAULT, "Prague CC: Cubic origin point should be greater than 0");
	}
	/*
	 * Compute the target window W(t+RTT) for the next RTT using,
	 * W(t) = C(t-K)^3 + W_max
	 */
	uint32_t elapsed_time = timer_diff(tcp_globals_now(globals), 0, tp->t_ccstate->cubic_epoch_start, 0);
	elapsed_time += srtt;

	float var = (elapsed_time - tp->t_ccstate->cubic_K) / TCP_RETRANSHZ;
	var = var * var * var * cubic_c_factor * tp->t_maxseg;

	int32_t cwnd = (int32_t)((float)tp->t_ccstate->cubic_origin_point + var);
	uint32_t w_cubic_next = cwnd > 0 ? (uint32_t)cwnd : 0;

	/* Apply the lower and upper bound */
	if (w_cubic_next < tp->snd_cwnd) {
		/* Make sure that cwnd is non-decreasing */
		w_cubic_next = tp->snd_cwnd;
	} else if (w_cubic_next > (uint32_t)(1.5 * tp->snd_cwnd)) {
		w_cubic_next = (uint32_t)(1.5 * tp->snd_cwnd);
	}

	return w_cubic_next;
}

static uint32_t
reno_friendly_win(struct tcpcb *tp, struct tcphdr *th)
{
	if (tp->t_ccstate->reno_cwnd == 0) {
		/*
		 * Start of the epoch, we set the reno_cwnd to cwnd at
		 * the start of the congestion avoidance stage
		 */
		tp->t_ccstate->reno_cwnd = tp->snd_cwnd;
		tp->t_ccstate->reno_acked = BYTES_ACKED(th, tp);
	}
	tp->t_ccstate->reno_acked += BYTES_ACKED(th, tp);

	/*
	 * Increase by ai_factor * MSS, once per RTT. Counting bytes_acked
	 * against the snd_cwnd represents exactly one RTT at full rate.
	 */
	while (tp->t_ccstate->reno_acked >= tp->snd_cwnd) {
		/* Enough bytes have been ACK'd for TCP to do AIMD */
		tp->t_ccstate->reno_acked -= tp->snd_cwnd;

		/*
		 * Compute Reno Friendly window using,
		 *  W_est(t) = W_max*ß + [3*(1-ß)/(1+ß)] * (bytes_acked/reno_cwnd)
		 */
		float alpha_aimd = 0;
		if (tp->t_ccstate->reno_cwnd < tp->t_ccstate->cubic_W_max) {
			alpha_aimd = (float)3 * (cubic_one_sub_beta) / (cubic_one_add_beta);
		} else {
			alpha_aimd = 1;
		}

		tp->t_ccstate->reno_cwnd += (uint32_t)(tp->t_maxseg * alpha_aimd);
	}

	return tp->t_ccstate->reno_cwnd;
}

static void
tcp_cubic_ack_ca(struct tcpcb *tp, struct tcphdr *th, uint32_t acked)
{
	uint32_t cubic_target_win;
	uint64_t incr_bytes_acked = 0;

	/* Do not increase congestion window in non-validated phase */
	if (tcp_cc_is_cwnd_nonvalidated(tp) != 0) {
		return;
	}

	tp->t_bytes_acked += acked;
	uint32_t srtt = tp->t_srtt >> TCP_RTT_SHIFT;
	/*
	 * First compute cubic target window as given in RFC 9438 Section 4.2
	 */
	cubic_target_win = cubic_target(tp, srtt);

	/* Compute Reno-friendly window */
	uint32_t reno_win = reno_friendly_win(tp, th);
	reno_win = tcp_round_to(reno_win, tp->t_maxseg);

	if (tp->snd_cwnd < cubic_target_win) {
		/*
		 * Compute how many bytes need to be acknowledged
		 * before we can increase the cwnd by one segment.
		 * It is given by cwnd / (target - cwnd)
		 */
		incr_bytes_acked = (uint64_t)tp->snd_cwnd * tp->t_maxseg;
		incr_bytes_acked /= (cubic_target_win - tp->snd_cwnd);
	}

	if (tp->snd_cwnd < reno_win) {
		uint64_t incr_reno_bytes_acked = (uint64_t)tp->snd_cwnd * tp->t_maxseg;
		incr_reno_bytes_acked /= (reno_win - tp->snd_cwnd);

		if (incr_reno_bytes_acked < incr_bytes_acked) {
			/*
			 * Cubic is in Reno-friendly region as less bytes
			 * are needed to increase in Reno way.
			 */
			incr_bytes_acked = incr_reno_bytes_acked;
		}
	}

	if (incr_bytes_acked > 0 && tp->t_bytes_acked >= incr_bytes_acked) {
		tp->t_bytes_acked -= incr_bytes_acked;
		tp->snd_cwnd = min(tp->snd_cwnd + tp->t_maxseg, TCP_MAXWIN << tp->snd_scale);
	}
}

static void
tcp_prague_ack_rcvd(struct tcpcb *tp, struct tcphdr *th)
{
	/* Do not increase the congestion window in non-validated phase */
	if (tcp_cc_is_cwnd_nonvalidated(tp) != 0) {
		return;
	}

	uint32_t acked = tp->t_ccstate->prague_bytes_acked;

	if (acked == 0) {
		return;
	}

	if (tp->snd_cwnd >= tp->snd_ssthresh) {
		/* Congestion avoidance phase */
		if (tp->t_ccstate->reduced_due_to_ce) {
			prague_ca_after_ce(tp, acked);
		} else {
			tcp_cubic_ack_ca(tp, th, acked);
		}
	} else {
		/*
		 * Maximum burst-size is limited to the initial congestion-window.
		 * We know that the network can survive this kind of burst.
		 */
		uint32_t abc_lim = tcp_initial_cwnd(tp);
		uint32_t incr = min(acked, abc_lim);
		tp->snd_cwnd += incr;
	}

	tp->snd_cwnd = tcp_round_to(tp->snd_cwnd, tp->t_maxseg);
	if (tp->snd_cwnd < 2 * tp->t_maxseg) {
		tp->snd_cwnd =  2 * tp->t_maxseg;
	}

	prague_update_pacer_state(tp);
}

static void
tcp_prague_pre_fr(struct tcpcb *tp)
{
	tp->t_ccstate->cubic_epoch_start = 0;

	uint32_t win = tp->snd_cwnd;
	if (tp->t_flagsext & TF_CWND_NONVALIDATED) {
		tp->t_lossflightsize = tcp_flight_size(tp);
		win = max(tp->t_pipeack, tp->t_lossflightsize);
	} else {
		tp->t_lossflightsize = 0;
	}
	/*
	 * Note the congestion window at which packet loss occurred as
	 * cub_W_max.
	 *
	 * If the current congestion window is less than the last Wmax when
	 * loss occurred, it indicates that capacity available in the
	 * network has gone down. This can happen if a new flow has started
	 * and it is capturing some of the bandwidth. To reach convergence
	 * quickly, backoff a little more.
	 */
	if (win < tp->t_ccstate->cubic_W_max) {
		tp->t_ccstate->cubic_W_max = (uint32_t)((float)win * cubic_fast_convergence_factor);
	} else {
		tp->t_ccstate->cubic_W_max = win;
	}

	/* Calculate congestion window by multiplying with beta factor */
	win = (uint32_t)(win * cubic_beta);
	win = tcp_round_to(win, tp->t_maxseg);
	if (win < 2 * tp->t_maxseg) {
		win =  2 * tp->t_maxseg;
	}
	tp->snd_ssthresh = win;
	tcp_cc_resize_sndbuf(tp);

	tp->t_ccstate->num_cong_events_loss++;
	tp->t_ccstate->in_loss = 1;
	tp->t_ccstate->reduced_due_to_ce = false;
}

static void
tcp_prague_post_fr(struct tcpcb *tp, __unused struct tcphdr *th)
{
	/*
	 * Since we do cwnd validation during pre_fr,
	 * we can safely set cwnd to ssthresh.
	 */
	tp->snd_cwnd = tp->snd_ssthresh;

	prague_update_pacer_state(tp);

	tp->t_ccstate->reno_cwnd = 0;
	tp->t_ccstate->reno_acked = 0;

	tp->t_ccstate->in_loss = 0;
}

static bool
rtt_elapsed(uint32_t largest_snd_nxt, uint32_t ack)
{
	/*
	 * A packet with sequence higher than largest sent sequence at
	 * the start of the round has been acknowledged
	 * Packet must have been sent after the processing of this ACK
	 */
	return largest_snd_nxt == 0 || SEQ_GT(ack, largest_snd_nxt);
}

static void
prague_update_pacer_state(struct tcpcb *tp)
{
	uint32_t srtt = tp->t_srtt >> TCP_RTT_SHIFT;
	if (srtt == 0) {
		srtt = PACING_INITIAL_RTT;
	}

	uint64_t rate = tp->snd_cwnd;

	/* Use 200% rate when in slow start */
	if (tp->snd_cwnd < tp->snd_ssthresh) {
		rate *= 2;
	}

	/* Multiply by MSEC_PER_SEC as srtt is in milliseconds */
	rate *= MSEC_PER_SEC;
	rate = rate / srtt;

	uint32_t burst = (uint32_t)(rate >> BURST_SHIFT);

	tp->t_pacer.rate = rate;
	tp->t_pacer.tso_burst_size = max(tp->t_maxseg, burst);
}

/*
 * RTT independence using square of RTT ratio to acheive rate fairness.
 * For additive increase, alpha = (RTT / REF_RTT) ^ 2
 * 1. Grow by 1MSS per target RTT; i.e. by a ratio of actual / target RTT and
 * 2. Growing by 1MSS translates to a sending rate increase proportional to the
 * same RTT ratio.
 *
 * Update infrequently whenever a change in srtt is expected.
 */
static void
prague_ai_alpha_rate(struct tcpcb *tp)
{
	uint32_t srtt = tp->t_srtt >> TCP_RTT_SHIFT;
	if (srtt == 0 || srtt > REF_RTT_RATE) {
		tp->t_ccstate->prague_alpha_ai = (1 << CWND_SHIFT);
		return;
	}

	uint64_t numer = srtt << CWND_SHIFT;
	numer *= srtt;
	uint64_t divisor = REF_RTT_RATE * REF_RTT_RATE;

	tp->t_ccstate->prague_alpha_ai = (uint64_t)((numer + (divisor >> 1)) / divisor);
}

/*
 * Handle an ACK in congestion avoidance phase
 * after the decrease happened due to CE
 */
static void
prague_ca_after_ce(struct tcpcb *tp, uint32_t acked)
{
	tp->t_bytes_acked += acked;
	/*
	 * To increase cwnd by 1MSS, we need cwnd / alpha_ai bytes
	 * to be acknowledged. Scale cwnd by CWND_SHIFT as alpha_ai
	 * is already scaled to avoid floating point arithmetic
	 */
	uint64_t bytes_needed_for_increase = (uint64_t)tp->snd_cwnd << CWND_SHIFT;
	bytes_needed_for_increase /= tp->t_ccstate->prague_alpha_ai;

	if (tp->t_bytes_acked >= bytes_needed_for_increase) {
		tp->t_bytes_acked -= bytes_needed_for_increase;
		tp->snd_cwnd += tp->t_maxseg;
	}
}

static void
prague_update_alpha(struct tcpcb *tp, uint32_t ack, uint32_t packets_marked,
    uint32_t packets_acked)
{
	if (!rtt_elapsed(tp->t_ccstate->snd_nxt_alpha, ack)) {
		/* One RTT hasn't elapsed yet, don't update alpha */
		os_log(OS_LOG_DEFAULT, "one RTT hasn't elapsed, not updating alpha");
		return;
	}

	if (!tp->t_ccstate->ever_saw_ce) {
		return;
	}

	uint32_t newly_marked = 0, newly_acked = 0;

	if (packets_marked > tp->t_ccstate->prague_packets_marked) {
		newly_marked = packets_marked - tp->t_ccstate->prague_packets_marked;
	}

	if (packets_acked > tp->t_ccstate->prague_packets_acked) {
		newly_acked = packets_acked - tp->t_ccstate->prague_packets_acked;
	} else {
		os_log_error(OS_LOG_DEFAULT,
		    "No new packets were ACK'ed, we shouldn't be called");
		return;
	}

	uint64_t scaled_alpha = tp->t_ccstate->prague_scaled_alpha;

	/*
	 * We currently don't react to local AQM for TCP Prague
	 */
	uint64_t p = (newly_marked << ALPHA_SHIFT) / newly_acked;
	/*
	 * Equation for alpha,
	 * alpha = (1 - g) * alpha + g * F (fraction of marked / acked)
	 * alpha = alpha - (alpha >> g_shift) + (marked << (alpha_shift -
	 * g_shift)) / acked, OR
	 * scaled_alpha = scaled_alpha - (scaled_alpha >> g_shift) +
	 * (marked << alpha_shift) / acked
	 */
	scaled_alpha = scaled_alpha - (scaled_alpha >> G_SHIFT) + p;
	tp->t_ccstate->prague_scaled_alpha = MIN(MAX_ALPHA << G_SHIFT, scaled_alpha);

	/* New round for alpha */
	tp->t_ccstate->snd_nxt_alpha = tp->snd_nxt;
	tp->t_ccstate->prague_packets_marked = packets_marked;
	tp->t_ccstate->prague_packets_acked = packets_acked;
}

static bool
prague_cwr(struct tcpcb *tp)
{
	// If we are currently in loss recovery, then do nothing
	if (tp->t_ccstate->in_loss) {
		os_log(OS_LOG_DEFAULT, "currently in loss recovery, no need to do CWR");
		return false;
	}

	tp->t_ccstate->num_cong_events_ce++;
	const uint64_t alpha = tp->t_ccstate->prague_scaled_alpha >> G_SHIFT;

	/*
	 * For Prague, the recovery time is only set during packet
	 * loss and we allow any ACKs that don't have CE marks to
	 * increase cwnd during ack_end, even in CWR state.
	 *
	 * On entering CWR, cwnd = cwnd * (1 - DCTCP.alpha) / 2
	 */
	uint64_t reduction =
	    (tp->snd_cwnd * alpha) >> (ALPHA_SHIFT + 1);
	tp->snd_cwnd -= reduction;

	/* If no more increase due to non-CE acked bytes, then round it */
	if (tp->t_ccstate->prague_bytes_acked == 0) {
		tp->snd_cwnd = tcp_round_to(tp->snd_cwnd, tp->t_maxseg);
	}
	/* Should be at least 2 MSS */
	if (tp->snd_cwnd < 2 * tp->t_maxseg) {
		tp->snd_cwnd =  2 * tp->t_maxseg;
	}

	tp->snd_ssthresh = tp->snd_cwnd;

	tp->t_ccstate->reduced_due_to_ce = true;

	return true;
}

static void
tcp_prague_process_ecn(struct tcpcb *tp, struct tcphdr *th, uint32_t new_bytes_marked,
    uint32_t packets_marked, uint32_t packets_acked)
{
	if (__improbable(packets_marked < tp->t_ccstate->prague_ce_counter ||
	    packets_acked < tp->t_ccstate->prague_packets_acked)) {
		os_log_error(OS_LOG_DEFAULT, "new CE count (%u) can't be less than current CE count (%u)"
		    "OR newly ACKed (%u) can't be less that current ACKed (%u)",
		    packets_marked, tp->t_ccstate->prague_ce_counter,
		    packets_acked, tp->t_ccstate->prague_packets_acked);
	}

	if (packets_marked > tp->t_ccstate->prague_ce_counter) {
		tp->t_ccstate->ever_saw_ce = true;
	}
	/*
	 * update alpha of fraction of marked packets,
	 * even when there are no new CE counts
	 */
	if (packets_acked > tp->t_ccstate->prague_packets_acked) {
		prague_update_alpha(tp, th->th_ack, packets_marked, packets_acked);
	}

	if (packets_marked == tp->t_ccstate->prague_ce_counter) {
		/* No change in CE */
		return;
	}

	os_log(OS_LOG_DEFAULT, "%u packets were newly CE marked",
	    packets_marked - tp->t_ccstate->prague_ce_counter);
	/*
	 * Received an ACK with new CE counts, subtract CE marked bytes
	 * from bytes_acked, so that we use only unmarked bytes to
	 * increase cwnd during ACK processing
	 */
	if (tp->t_ccstate->prague_bytes_acked > new_bytes_marked) {
		tp->t_ccstate->prague_bytes_acked -= new_bytes_marked;
	} else {
		tp->t_ccstate->prague_bytes_acked = 0;
	}

	/* Update CE count even if we are already in CWR */
	tp->t_ccstate->prague_ce_counter = packets_marked;

	/* Update AIMD alpha as SRTT might have changed */
	prague_ai_alpha_rate(tp);

	if (!rtt_elapsed(tp->t_ccstate->snd_nxt_cwr, th->th_ack)) {
		/* One RTT hasn't elapsed yet, don't doing CWR */
		os_log(OS_LOG_DEFAULT, "one RTT hasn't elapsed, not doing CWR");
		return;
	}

	/* CWR reduction if new counts are received */
	bool cwnd_changed = prague_cwr(tp);

	/* Update pacer state if cwnd has changed */
	if (cwnd_changed) {
		prague_update_pacer_state(tp);
	}
	/* New round for CWR */
	tp->t_ccstate->snd_nxt_cwr = tp->snd_nxt;
}

static void
tcp_prague_set_bytes_acked(struct tcpcb *tp, uint32_t acked)
{
	/* Set bytes_acked which will be used later during ack_rcvd() */
	tp->t_ccstate->prague_bytes_acked = acked;
}

static void
tcp_prague_clear_state(struct tcpcb *tp)
{
	tp->snd_cwnd_prev = 0;
	tp->t_ccstate->num_cong_events_loss = 0;
	tp->t_ccstate->num_cong_events_ce = 0;
	tp->t_ccstate->prague_alpha_ai = (1 << CWND_SHIFT);

	/* CUBIC state */
	tp->t_ccstate->cubic_K = 0;
	//prague->cubic_acked = 0;
	tp->t_ccstate->cubic_epoch_start = 0;
	tp->t_ccstate->cubic_origin_point = 0;
	tp->t_ccstate->cubic_W_max = 0;
}

int
tcp_prague_init(struct tcpcb *tp)
{
	os_atomic_inc(&tcp_cc_prague.num_sockets, relaxed);

	VERIFY(tp->t_ccstate != NULL);

	tp->t_ccstate->prague_scaled_alpha = (MAX_ALPHA << G_SHIFT);
	tcp_prague_clear_state(tp);
	return 0;
}

int
tcp_prague_cleanup(struct tcpcb *tp)
{
#pragma unused(tp)
	os_atomic_dec(&tcp_cc_prague.num_sockets, relaxed);
	return 0;
}

/*
 * Initialize the congestion window for a connection
 */
void
tcp_prague_cwnd_init_or_reset(struct tcpcb *tp)
{
	VERIFY(tp->t_ccstate != NULL);

	tcp_prague_clear_state(tp);
	tcp_cc_cwnd_init_or_reset(tp);
	tp->t_pipeack = 0;
	tcp_clear_pipeack_state(tp);

	/* Start counting bytes for RFC 3465 again */
	tp->t_bytes_acked = 0;

	/*
	 * slow start threshold could get initialized to a lower value
	 * when there is a cached value in the route metrics. In this case,
	 * the connection can enter congestion avoidance without any packet
	 * loss and Cubic will enter steady-state too early. It is better
	 * to always probe to find the initial slow-start threshold.
	 */
	if (tp->t_inpcb->inp_stat->txbytes <= tcp_initial_cwnd(tp) &&
	    tp->snd_ssthresh < (TCP_MAXWIN << TCP_MAX_WINSHIFT)) {
		tp->snd_ssthresh = TCP_MAXWIN << TCP_MAX_WINSHIFT;
	}

	/* Initialize cubic last max to be same as ssthresh */
	tp->t_ccstate->cubic_W_max = tp->snd_ssthresh;

	/* Set initial pacer state */
	uint64_t startup_rate =
	    tp->snd_cwnd * MSEC_PER_SEC / PACING_INITIAL_RTT;
	uint32_t startup_burst_size = tp->t_maxseg;
	tp->t_pacer.rate = startup_rate;
	tp->t_pacer.tso_burst_size = startup_burst_size;
}

static void
tcp_prague_after_timeout(struct tcpcb *tp)
{
	VERIFY(tp->t_ccstate != NULL);

	/*
	 * Avoid adjusting congestion window due to SYN retransmissions.
	 * If more than one byte (SYN) is outstanding then it is still
	 * needed to adjust the window.
	 */
	if (tp->t_state < TCPS_ESTABLISHED &&
	    ((int)(tp->snd_max - tp->snd_una) <= 1)) {
		return;
	}

	if (!IN_FASTRECOVERY(tp)) {
		tcp_prague_clear_state(tp);
		tcp_prague_pre_fr(tp);
	}

	/*
	 * Close the congestion window down to one segment as a retransmit
	 * timeout might indicate severe congestion.
	 */
	tp->snd_cwnd = tp->t_maxseg;
}

static int
tcp_prague_delay_ack(struct tcpcb *tp, struct tcphdr *th)
{
	return tcp_cc_delay_ack(tp, th);
}

/*
 * When switching from a different CC it is better for Cubic to start
 * fresh. The state required for Cubic calculation might be stale and it
 * might not represent the current state of the network. If it starts as
 * a new connection it will probe and learn the existing network conditions.
 */
static void
tcp_prague_switch_cc(struct tcpcb *tp)
{
	tcp_prague_cwnd_init_or_reset(tp);

	os_atomic_inc(&tcp_cc_prague.num_sockets, relaxed);
}
