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

#include "tcp_includes.h"

#define REORDERING_WINDOW_FLOOR (2) /* If min_rtt is too small, at least wait for a reordering window of 2ms */

/* RACK is implemented by following RFC 8985 */
void
tcp_rack_transmit_seg(struct tcpcb *tp, struct tcp_seg_sent *seg, tcp_seq start, tcp_seq end,
    uint32_t xmit_ts, uint8_t flags)
{
	seg->start_seq = start;
	seg->end_seq = end;
	seg->xmit_ts = xmit_ts;

	/*
	 * Set dsack round_end at the start of a (re) transmission
	 * round to the segment with the smallest sequence sent
	 */
	if (SEQ_LT(start, tp->rack.dsack_round_end)) {
		tp->rack.dsack_round_end = start;
	}
	seg->flags |= flags;
	if (seg->flags & TCP_RACK_RETRANSMITTED) {
		tp->bytes_retransmitted += tcp_seg_len(seg);
	}
	/*
	 * Set segs_retransmitted ONLY when it is not set, otherwise new segments
	 * can clear this even if there are retransmitted segments
	 */
	if (!tp->rack.segs_retransmitted) {
		tp->rack.segs_retransmitted = !!(flags & TCP_RACK_RETRANSMITTED);
	}
}

/* If segment (t1, seq1) was sent after segment (t2, seq2) */
static bool
tcp_rack_sent_after(uint32_t t1, uint32_t seq1, uint32_t t2, uint32_t seq2)
{
	return (t1 > t2) || (t1 == t2 && SEQ_GT(seq1, seq2));
}

void
tcp_rack_update_reordering_win_persist(struct tcpcb *tp)
{
	if (tp->rack.reo_wnd_persist != 0) {
		tp->rack.reo_wnd_persist--;
	}
}

void
tcp_rack_bad_rexmt_restore(struct tcpcb *tp)
{
	/* Force RACK to re-examine losses */
	tp->rack.advanced = 1;

	/* Restore reordering window persist value */
	tp->rack.reo_wnd_persist = MIN(tp->rack.reo_wnd_persist + 1,
	    TCP_RACK_RECOVERY_PERSIST_MAX);
}

void
tcp_rack_reset_segs_retransmitted(struct tcpcb *tp)
{
	tp->rack.segs_retransmitted = false;
}

/* MUST be called before we have processed dup ACKs and made a decision to enter recovery */
static uint32_t
tcp_rack_reordering_window(struct tcpcb *tp, uint32_t dup_acks, bool in_rto)
{
	if (tp->t_reordered_pkts == 0) {
		/*
		 * When no reordering has been observed, the RACK.reo_wnd is set
		 * to 0 both during fast and RTO recovery. OR if we are entering
		 * fast recovery due to SACKed segments/dup ACKs >= DupThresh.
		 * When reo_wnd is set to 0, loss is detected if RACK.RTT time has
		 * elapsed since packet was sent.
		 */
		if (IN_FASTRECOVERY(tp) || dup_acks >= tp->t_rexmtthresh || in_rto) {
			return 0;
		}
	}
	/*
	 * reordering window = N * Min_RTT/4,
	 * limited to a max value of 2*SRTT.
	 */
	uint32_t srtt = (uint32_t)tp->t_srtt >> TCP_RTT_SHIFT;
	uint32_t reordering_window = (tp->rack.reo_wnd_multi * get_base_rtt(tp)) >> 2;
	if (reordering_window > 2 * srtt) {
		reordering_window = 2 * srtt;
	}
	reordering_window = MAX(reordering_window, REORDERING_WINDOW_FLOOR);

	return reordering_window;
}

static uint32_t
tcp_rack_detect_segment_lost(struct tcpcb *tp, struct tcp_seg_sent *seg,
    uint32_t reordering_window, bool *loss_detected)
{
	/* After the segment is sent, wait for (RTT + reordering window) */
	uint32_t wait_ts = seg->xmit_ts + tp->rack.rtt + reordering_window;
	if (TSTMP_GEQ(tcp_now, wait_ts)) {
		/*
		 * Segment should be marked as lost as it was sent
		 * (RTT + reordering window) time ago.
		 */
		tcp_mark_seg_lost(tp, seg);
		if (loss_detected != NULL) {
			*loss_detected = true;
		}
		return 0;
	}
	return wait_ts - tcp_now;
}

/*
 * RFC 8985,
 * Step 1: Update RACK.min_RTT (done in tcp_input)
 * Step 2: Update the state for the most recently sent segment that has been delivered.
 */
void
tcp_rack_update_segment_acked(struct tcpcb *tp, uint32_t tsecr,
    uint32_t xmit_ts, uint32_t end_seq,
    bool retransmitted)
{
	/*
	 * Step 1: Update RACK.min_RTT - is done in tcp_input ACK processing
	 */
	uint32_t rtt = tcp_now - xmit_ts;
	if (rtt == 0) {
		/*
		 * As rtt has millisecond precision,
		 * make adjustment for sub ms RTT
		 */
		rtt = 1;
	}
	/*
	 * RFC 8985 - An ACK can acknowledge retransmitted data and because retransmissions
	 * can be spurious, ignore ACKs for such retransmitted segments.
	 * Ignore a segment if any of its sequence range has been retransmitted
	 * before and if either of two conditions is true:
	 * 1. The TSecr of the ACK's timestamp option (if available) indicates the ACK was not
	 *	acknowledging the last (re)transmission OR tsecr was invalid (greater than tcp_now)
	 * 2. If TSecr is not available or ACK arrives immediately after last retransmission,
	 *  check if the segment was last (re)transmitted less than RACK.min_rtt ago.
	 */
	if (retransmitted) {
		if ((tsecr != 0 && (TSTMP_LT(tsecr, xmit_ts) || TSTMP_GT(tsecr, tcp_now)))
		    || rtt < get_base_rtt(tp)) {
			/* This is a spurious inference as either
			 * tsecr doesn't lie between xmit_ts and now OR
			 * the rtt computed using the xmit_ts of this segment
			 * is less than base-rtt.
			 */
			return;
		}
	}

	if (tcp_rack_sent_after(xmit_ts, end_seq, tp->rack.xmit_ts, tp->rack.end_seq)) {
		tp->rack.advanced = 1;
		tp->rack.xmit_ts = xmit_ts;
		tp->rack.end_seq = end_seq;
		tp->rack.rtt = rtt;

		/* Cancel the RACK reordering timer as we have received a new ACK */
		tp->t_timer[TCPT_REORDER] = 0;
	}
}

/*
 * Step 3: Reordering detection is done in tcp_sack_detect_reordering
 * Step 4: Update the RACK reordering window.
 */
void
tcp_rack_update_reordering_window(struct tcpcb *tp, tcp_seq highest_acked_sacked)
{
	/*
	 * RACK.reo_wnd starts with a value of RACK.min_RTT/4. After that, RACK
	 * dynamically adapts to higher degrees of reordering using DSACK
	 * option from the receiver.
	 * To deal with temporary reordering, RACK persists using the inflated
	 * RACK.reo_wnd for up to 16 loss recoveries, after which it resets
	 * RACK.reo_wnd to its starting value.
	 */

	/*
	 * Ignore DSACK if an RTT hasn't passed as
	 * highest_acked_sacked <= previous dsack_round_end
	 */
	if (SEQ_LEQ(highest_acked_sacked, tp->rack.dsack_round_end)) {
		tp->rack.dsack_round_seen = 0;
	}
	/*
	 * Start of the new dsack round.
	 * Grow the reordering window once per round that sees DSACK on an ACK.
	 * Reordering window persists for 16 loss recoveries (that don't receive DSACK).
	 * On receiving DSACK, we reset window persist to 16 as it
	 * indicates that reordering is still happening.
	 */
	if (tp->rack.dsack_round_seen == 1) {
		tp->rack.dsack_round_seen = 0;
		tp->rack.dsack_round_end = tp->snd_nxt;
		tp->rack.reo_wnd_multi = (uint8_t)(min(0xFF, tp->rack.reo_wnd_multi + 1));
		tp->rack.reo_wnd_persist = TCP_RACK_RECOVERY_PERSIST_MAX;
	} else if (tp->rack.reo_wnd_persist == 0) {
		tp->rack.reo_wnd_multi = 1;
	}
}

/*
 * Step 5: Detect losses
 * Call this only after S/ACK has been processed, so that s/acked segments
 * are either removed or marked accordingly
 */
static uint32_t
tcp_rack_detect_loss(struct tcpcb *tp, uint32_t dup_acks, bool *loss_detected)
{
	struct tcp_seg_sent *seg = NULL;
	uint32_t reordering_timeout = 0;
	uint32_t reordering_window = tcp_rack_reordering_window(tp, dup_acks, false);

	TAILQ_FOREACH(seg, &tp->t_segs_sent, tx_link) {
		/*
		 * No segment after this segment has been acknowledged yet,
		 * hence RACK.segment is not after this segment
		 */
		if (!tcp_rack_sent_after(tp->rack.xmit_ts, tp->rack.end_seq,
		    seg->xmit_ts, seg->end_seq)) {
			break;
		}

		/* Skip already marked lost but not yet retransmitted segments */
		if (seg->flags & TCP_SEGMENT_LOST &&
		    !(seg->flags & TCP_RACK_RETRANSMITTED)) {
			continue;
		}

		if (seg->flags & TCP_SEGMENT_SACKED) {
			continue;
		}

		uint32_t remaining = tcp_rack_detect_segment_lost(tp, seg, reordering_window, loss_detected);
		if (remaining) {
			/*
			 * We only want to arm the timer at max wait time as we are
			 * expecting to get ACKs to do RACK processing. Only in the
			 * worst case, when we don't receive ACKs, we set the timeout
			 * to be the wait time for the most recently sent packet.
			 */
			reordering_timeout = max(remaining, reordering_timeout);
		}
	}
	return reordering_timeout;
}

/*
 * Call during input processing to detect loss.
 * If loss is detected, enter_fr will be true and
 * tcp_input will enter fast recovery
 */
bool
tcp_rack_detect_loss_and_arm_timer(struct tcpcb *tp, uint32_t dup_acks)
{
	uint32_t reordering_timeout = 0;
	bool loss_detected = false;

	if (!tp->rack.advanced) {
		return false;
	}

	/* Cancel any existing RACK reordering timer as we are going to re-fire it if needed */
	tp->t_timer[TCPT_REORDER] = 0;

	reordering_timeout = tcp_rack_detect_loss(tp, dup_acks, &loss_detected);
	if (reordering_timeout) {
		tp->t_timer[TCPT_REORDER] = OFFSET_FROM_START(tp,
		    reordering_timeout + REORDERING_WINDOW_FLOOR);
		/* Since losses can be marked at future point, clear the TLP timer */
		tp->t_timer[TCPT_PTO] = 0;
	} else {
		/* Cancel any pending timers */
		tp->t_timer[TCPT_REORDER] = 0;
	}

	return loss_detected;
}

/* Reordering timeout has expired, detect loss and enter recovery */
void
tcp_rack_reordering_timeout(struct tcpcb *tp, uint32_t dup_acks)
{
	bool enter_fr = false;

	tcp_rack_detect_loss(tp, dup_acks, &enter_fr);

	if (enter_fr) {
		/* Some packets have been marked as lost */
		if (!IN_FASTRECOVERY(tp)) {
			tcp_rexmt_save_state(tp);
			tcp_enter_fast_recovery(tp);
		}
		tcpstat.tcps_rack_reordering_timeout_recovery_episode++;
		tp->t_rack_reo_timeout_recovery_episode++;
		tcp_output(tp);
	}
}

void
tcp_rack_loss_on_rto(struct tcpcb *tp, bool in_rto)
{
	struct tcp_seg_sent *seg = NULL;
	uint32_t reordering_window = tcp_rack_reordering_window(tp, 0, in_rto);

	TAILQ_FOREACH(seg, &tp->t_segs_sent, tx_link) {
		/* Mark the first unacknowledged segment as lost */
		if (seg->start_seq == tp->snd_una) {
			tcp_mark_seg_lost(tp, seg);
		}
		/*
		 * Mark any segment for which time elapsed since transmit
		 * is at least the sum of recent RTT and reordering window
		 */
		tcp_rack_detect_segment_lost(tp, seg, reordering_window, NULL);
	}
}

uint32_t
tcp_rack_adjust(struct tcpcb *tp, uint32_t cwin)
{
	uint32_t max_len = 0;
	struct tcp_seg_sent *seg = NULL;

	/*
	 * We traverse RB tree (instead of time-ordered list)
	 * as it would be faster to look for a seg such that
	 * seg->start <= snd_nxt < seg->end
	 */
	RB_FOREACH(seg, tcp_seg_sent_tree_head, &tp->t_segs_sent_tree) {
		if (max_len >= cwin) {
			break;
		}
		if (seg->flags & TCP_SEGMENT_SACKED) {
			if (SEQ_LT(tp->snd_nxt, seg->end_seq) &&
			    SEQ_GEQ(tp->snd_nxt, seg->start_seq)) {
				tp->snd_nxt = seg->end_seq;
			}
			break;
		}
		if (SEQ_LT(tp->snd_nxt, seg->end_seq)) {
			max_len += tcp_seg_len(seg);
		}
	}

	return max_len;
}

/* This function is only used during retransmissions. */
struct tcp_seg_sent *
tcp_rack_output(struct tcpcb *tp, uint32_t cwin, uint16_t *rack_seg_len)
{
	struct tcp_seg_sent *seg = NULL;

	TAILQ_FOREACH(seg, &tp->t_segs_sent, tx_link) {
		if (seg->flags & TCP_SEGMENT_SACKED) {
			continue;
		}
		if (seg->flags & TCP_SEGMENT_LOST && !(seg->flags & TCP_RACK_RETRANSMITTED)) {
			/* We don't do TSO for retransmissions and only send MSS sized segments */
			uint16_t allowed_size = (uint16_t)min(cwin, tp->t_maxseg);
			/*
			 * When entire segment can be retransmitted,
			 * lost segment is moved to the end of the time-ordered
			 * list in tcp_seg_sent_insert.
			 *
			 * When entire segment can't be retransmitted,
			 * we move the seg->start by amount of data
			 * retransmitted during tcp_seg_sent_insert
			 */
			*rack_seg_len = tcp_seg_len(seg) <= allowed_size ?
			    (uint16_t)tcp_seg_len(seg) : allowed_size;

			break;
		}
	}

	return seg;
}

/*
 * Check if a retransmitted segment was completed covered by received
 * (first) DSACK block
 */
void
tcp_rack_detect_reordering_dsack(struct tcpcb *tp, tcp_seq start, tcp_seq end)
{
	struct tcp_seg_sent *seg = NULL;

	TAILQ_FOREACH(seg, &tp->t_segs_sent, tx_link) {
		if (seg->flags & TCP_SEGMENT_RETRANSMITTED_ATLEAST_ONCE) {
			if (SEQ_LEQ(start, seg->start_seq) && SEQ_GEQ(end, seg->end_seq)) {
				tp->t_reordered_pkts++;
			}
		}
	}
}

void
tcp_rack_detect_reordering_acked(struct tcpcb *tp, struct tcp_seg_sent *seg)
{
	/*
	 * A never retransmitted segment below fack was delivered.
	 * Ignore the segments that have already been sacked before
	 */
	if (SEQ_LT(seg->end_seq, tp->snd_fack) &&
	    (seg->flags & (TCP_SEGMENT_SACKED | TCP_SEGMENT_RETRANSMITTED_ATLEAST_ONCE)) == 0) {
		tp->t_reordered_pkts++;
	}
}
