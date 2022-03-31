/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/netif/nx_netif.h>
#include <sys/kdebug.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>

extern kern_return_t thread_terminate(thread_t);

#define NETIF_POLL_EWMA(old, new, decay) do {                                 \
	uint32_t _avg;                                                 \
	if ((_avg = (old)) > 0)                                         \
	        _avg = (((_avg << (decay)) - _avg) + (new)) >> (decay); \
	else                                                            \
	        _avg = (new);                                           \
	(old) = _avg;                                                   \
} while (0)

/* rate limit debug messages */
struct timespec netif_poll_dbgrate = { .tv_sec = 1, .tv_nsec = 0 };

static inline void
nx_netif_rxpoll_set_mode(struct ifnet *ifp, ifnet_model_t mode)
{
	errno_t err;
	uint64_t ival;
	struct timespec ts;
	struct ifnet_model_params p = { .model = mode, .reserved = { 0 } };

	if ((ival = ifp->if_rxpoll_ival) < IF_RXPOLL_INTERVALTIME_MIN) {
		ival = IF_RXPOLL_INTERVALTIME_MIN;
	}

	if ((err = ((*ifp->if_input_ctl)(ifp, IFNET_CTL_SET_INPUT_MODEL,
	    sizeof(p), &p))) != 0) {
		SK_ERR("%s: error setting polling mode to %s (%d)",
		    if_name(ifp), (mode == IFNET_MODEL_INPUT_POLL_ON) ?
		    "ON" : "OFF", err);
	}

	switch (mode) {
	case IFNET_MODEL_INPUT_POLL_OFF:
		ifnet_set_poll_cycle(ifp, NULL);
		ifp->if_rxpoll_offreq++;
		if (err != 0) {
			ifp->if_rxpoll_offerr++;
		}
		break;

	case IFNET_MODEL_INPUT_POLL_ON:
		net_nsectimer(&ival, &ts);
		ifnet_set_poll_cycle(ifp, &ts);
		ifp->if_rxpoll_onreq++;
		if (err != 0) {
			ifp->if_rxpoll_onerr++;
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

/*
 * Updates the input poll statistics and determines the next mode based
 * on the configured thresholds.
 */
static inline void
netif_rxpoll_compat_update_rxpoll_stats(struct ifnet *ifp,
    struct ifnet_stat_increment_param *s)
{
	uint32_t poll_thresh = 0, poll_ival = 0;
	uint32_t m_cnt, m_size, poll_req = 0;
	struct timespec now, delta;
	ifnet_model_t mode;
	uint64_t ival;

	ASSERT(net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL));
	LCK_MTX_ASSERT(&ifp->if_poll_lock, LCK_MTX_ASSERT_NOTOWNED);

	/* total packets and bytes passed in by driver */
	m_cnt = s->packets_in;
	m_size = s->bytes_in;

	lck_mtx_lock_spin(&ifp->if_poll_lock);
	if ((ival = ifp->if_rxpoll_ival) < IF_RXPOLL_INTERVALTIME_MIN) {
		ival = IF_RXPOLL_INTERVALTIME_MIN;
	}
	/* Link parameters changed? */
	if (ifp->if_poll_update != 0) {
		ifp->if_poll_update = 0;
		(void) netif_rxpoll_set_params(ifp, NULL, TRUE);
	}

	/* Current operating mode */
	mode = ifp->if_poll_mode;

	nanouptime(&now);
	if (!net_timerisset(&ifp->if_poll_sample_lasttime)) {
		*(&ifp->if_poll_sample_lasttime) = now;
	}

	net_timersub(&now, &ifp->if_poll_sample_lasttime, &delta);
	if (if_rxpoll && net_timerisset(&ifp->if_poll_sample_holdtime)) {
		uint32_t ptot, btot;

		/* Accumulate statistics for current sampling */
		PKTCNTR_ADD(&ifp->if_poll_sstats, m_cnt, m_size);

		if (net_timercmp(&delta, &ifp->if_poll_sample_holdtime, <)) {
			goto skip;
		}
		*(&ifp->if_poll_sample_lasttime) = now;

		/* Calculate min/max of inbound bytes */
		btot = (uint32_t)ifp->if_poll_sstats.bytes;
		if (ifp->if_rxpoll_bmin == 0 || ifp->if_rxpoll_bmin > btot) {
			ifp->if_rxpoll_bmin = btot;
		}
		if (btot > ifp->if_rxpoll_bmax) {
			ifp->if_rxpoll_bmax = btot;
		}

		/* Calculate EWMA of inbound bytes */
		NETIF_POLL_EWMA(ifp->if_rxpoll_bavg, btot, if_rxpoll_decay);

		/* Calculate min/max of inbound packets */
		ptot = (uint32_t)ifp->if_poll_sstats.packets;
		if (ifp->if_rxpoll_pmin == 0 || ifp->if_rxpoll_pmin > ptot) {
			ifp->if_rxpoll_pmin = ptot;
		}
		if (ptot > ifp->if_rxpoll_pmax) {
			ifp->if_rxpoll_pmax = ptot;
		}

		/* Calculate EWMA of inbound packets */
		NETIF_POLL_EWMA(ifp->if_rxpoll_pavg, ptot, if_rxpoll_decay);

		/* Reset sampling statistics */
		PKTCNTR_CLEAR(&ifp->if_poll_sstats);

#if (SK_LOG && (DEVELOPMENT || DEBUG))
		if (__improbable(sk_verbose & SK_VERB_NETIF_POLL)) {
			if (!net_timerisset(&ifp->if_poll_dbg_lasttime)) {
				*(&ifp->if_poll_dbg_lasttime) = *(&now);
			}
			net_timersub(&now, &ifp->if_poll_dbg_lasttime, &delta);
			if (net_timercmp(&delta, &netif_poll_dbgrate, >=)) {
				*(&ifp->if_poll_dbg_lasttime) = *(&now);
				SK_DF(SK_VERB_NETIF_POLL,
				    "%s: [%s] pkts avg %d max %d "
				    "limits [%d/%d], bytes avg %d "
				    "limits [%d/%d]", if_name(ifp),
				    (ifp->if_poll_mode ==
				    IFNET_MODEL_INPUT_POLL_ON) ?
				    "ON" : "OFF", ifp->if_rxpoll_pavg,
				    ifp->if_rxpoll_pmax,
				    ifp->if_rxpoll_plowat,
				    ifp->if_rxpoll_phiwat,
				    ifp->if_rxpoll_bavg,
				    ifp->if_rxpoll_blowat,
				    ifp->if_rxpoll_bhiwat);
			}
		}
#endif /* (SK_LOG && (DEVELOPMENT || DEBUG)) */

		/* Perform mode transition, if necessary */
		if (!net_timerisset(&ifp->if_poll_mode_lasttime)) {
			*(&ifp->if_poll_mode_lasttime) = *(&now);
		}

		net_timersub(&now, &ifp->if_poll_mode_lasttime, &delta);
		if (net_timercmp(&delta, &ifp->if_poll_mode_holdtime, <)) {
			goto skip;
		}

		if (ifp->if_rxpoll_pavg <= ifp->if_rxpoll_plowat &&
		    ifp->if_rxpoll_bavg <= ifp->if_rxpoll_blowat &&
		    ifp->if_poll_mode != IFNET_MODEL_INPUT_POLL_OFF) {
			mode = IFNET_MODEL_INPUT_POLL_OFF;
		} else if (ifp->if_rxpoll_pavg >= ifp->if_rxpoll_phiwat &&
		    ifp->if_rxpoll_bavg >= ifp->if_rxpoll_bhiwat &&
		    ifp->if_poll_mode != IFNET_MODEL_INPUT_POLL_ON) {
			mode = IFNET_MODEL_INPUT_POLL_ON;
		}

		if (mode != ifp->if_poll_mode) {
			ifp->if_poll_mode = mode;
			*(&ifp->if_poll_mode_lasttime) = *(&now);
			poll_req++;
		}
	}
skip:
	/* update rxpoll stats */
	if (ifp->if_poll_tstats.packets != 0) {
		ifp->if_poll_pstats.ifi_poll_packets +=
		    ifp->if_poll_tstats.packets;
		ifp->if_poll_tstats.packets = 0;
	}
	if (ifp->if_poll_tstats.bytes != 0) {
		ifp->if_poll_pstats.ifi_poll_bytes +=
		    ifp->if_poll_tstats.bytes;
		ifp->if_poll_tstats.bytes = 0;
	}

	lck_mtx_unlock(&ifp->if_poll_lock);
	/*
	 * If there's a mode change, perform a downcall to the driver
	 * for the new mode. This function is called from the poller thread
	 * which holds a reference on the ifnet.
	 */
	if (poll_req != 0) {
		nx_netif_rxpoll_set_mode(ifp, mode);
	}

	/* Signal the poller thread to do work if required */
	if (mode == IFNET_MODEL_INPUT_POLL_ON && m_cnt > 1 &&
	    (poll_ival = if_rxpoll_interval_pkts) > 0) {
		poll_thresh = m_cnt;
	}
	if (poll_thresh != 0 && poll_ival > 0 &&
	    (--poll_thresh % poll_ival) == 0) {
		lck_mtx_lock_spin(&ifp->if_poll_lock);
		ifp->if_poll_req++;
		lck_mtx_unlock(&ifp->if_poll_lock);
	}
}

/*
 * Must be called on an attached ifnet (caller is expected to check.)
 * Caller may pass NULL for poll parameters to indicate "auto-tuning."
 */
errno_t
netif_rxpoll_set_params(struct ifnet *ifp, struct ifnet_poll_params *p,
    boolean_t locked)
{
	errno_t err;

	VERIFY(ifp != NULL);
	if ((ifp->if_eflags & IFEF_RXPOLL) == 0) {
		return ENXIO;
	}
	err = dlil_rxpoll_validate_params(p);
	if (err != 0) {
		return err;
	}

	if (!locked) {
		lck_mtx_lock(&ifp->if_poll_lock);
	}
	LCK_MTX_ASSERT(&ifp->if_poll_lock, LCK_MTX_ASSERT_OWNED);
	/*
	 * Normally, we'd reset the parameters to the auto-tuned values
	 * if the the poller thread detects a change in link rate.  If the
	 * driver provides its own parameters right after a link rate
	 * changes, but before the input thread gets to run, we want to
	 * make sure to keep the driver's values.  Clearing if_poll_update
	 * will achieve that.
	 */
	if (p != NULL && !locked && ifp->if_poll_update != 0) {
		ifp->if_poll_update = 0;
	}
	dlil_rxpoll_update_params(ifp, p);
	if (!locked) {
		lck_mtx_unlock(&ifp->if_poll_lock);
	}
	return 0;
}

static inline void
netif_rxpoll_poll_driver(struct ifnet *ifp, uint32_t m_lim,
    struct ifnet_stat_increment_param *s, struct timespec *start_time,
    struct timespec *poll_duration)
{
	struct mbuf *m_head = NULL, *m_tail = NULL;
	uint32_t m_cnt = 0, m_totlen = 0;
	struct timespec now;

	/* invoke the driver's input poll routine */
	((*ifp->if_input_poll)(ifp, 0, m_lim, &m_head, &m_tail, &m_cnt,
	&m_totlen));
	VERIFY((m_cnt > 0) || ((m_head == NULL) && (m_tail == NULL)));

	s->packets_in = m_cnt;
	s->bytes_in = m_totlen;
	/*
	 * Bracket the work done with timestamps to compute the effective
	 * poll interval.
	 */
	nanouptime(start_time);
	(void) ifnet_input_poll(ifp, m_head, m_tail,
	    (m_head != NULL) ? s : NULL);
	nanouptime(&now);
	net_timersub(&now, start_time, poll_duration);

	SK_DF(SK_VERB_NETIF_POLL, "%s: polled %d pkts, pkts avg %d max %d, "
	    "wreq avg %d, bytes avg %d", if_name(ifp), m_cnt,
	    ifp->if_rxpoll_pavg, ifp->if_rxpoll_pmax, ifp->if_rxpoll_wavg,
	    ifp->if_rxpoll_bavg);
}

static inline void
netif_rxpoll_process_interrupt(struct ifnet *ifp, proc_t p,
    struct ifnet_stat_increment_param *s, struct nx_mbq *rcvq)
{
	struct nexus_adapter *na = &NA(ifp)->nifna_up;

	nx_mbq_lock_spin(rcvq);
	s->packets_in = nx_mbq_len(rcvq);
	s->bytes_in = (uint32_t)nx_mbq_size(rcvq);
	nx_mbq_unlock(rcvq);
	(void) nx_netif_mit_rx_intr((NAKR(na, NR_RX)), p, 0, NULL);
}

__attribute__((noreturn))
static void
netif_rxpoll_compat_thread_cont(void *v, wait_result_t wres)
{
	struct ifnet *ifp = v;
	struct timespec *ts = NULL;
	struct timespec start_time, poll_intvl, poll_duration;
	struct ifnet_stat_increment_param s;

	VERIFY(ifp->if_eflags & IFEF_RXPOLL);
	bzero(&s, sizeof(s));
	net_timerclear(&start_time);

	lck_mtx_lock_spin(&ifp->if_poll_lock);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (ifp->if_poll_flags & IF_POLLF_TERMINATING) != 0)) {
		goto terminate;
	}

	ifp->if_poll_flags |= IF_POLLF_RUNNING;
	/*
	 * Keep on servicing until no more request.
	 */

	for (;;) {
		uint16_t req = ifp->if_poll_req;
		struct nexus_adapter *na = &NA(ifp)->nifna_up;
		struct __kern_channel_ring *kring = &na->na_rx_rings[0];
		struct nx_mbq *rxq = &kring->ckr_rx_queue;
		uint32_t m_lim;
		boolean_t poll, poll_again = false;

		m_lim = (ifp->if_rxpoll_plim != 0) ? ifp->if_rxpoll_plim :
		    MAX((nx_mbq_limit(rxq)), (ifp->if_rxpoll_phiwat << 2));
		poll = (ifp->if_poll_mode == IFNET_MODEL_INPUT_POLL_ON);
		lck_mtx_unlock(&ifp->if_poll_lock);

		net_timerclear(&poll_duration);

		/* If no longer attached, there's nothing to do;
		 * else hold an IO refcnt to prevent the interface
		 * from being detached (will be released below.)
		 */
		if (!ifnet_is_attached(ifp, 1)) {
			lck_mtx_lock_spin(&ifp->if_poll_lock);
			break;
		}

		if (poll) {
			netif_rxpoll_poll_driver(ifp, m_lim, &s, &start_time,
			    &poll_duration);
			/*
			 * if the polled duration is more than the poll
			 * interval, then poll again to catch up.
			 */
			ASSERT(net_timerisset(&ifp->if_poll_cycle));
			if (net_timercmp(&poll_duration, &ifp->if_poll_cycle,
			    >=)) {
				poll_again = true;
			}
		} else {
			netif_rxpoll_process_interrupt(ifp, kernproc, &s, rxq);
			net_timerclear(&start_time);
		}

		netif_rxpoll_compat_update_rxpoll_stats(ifp, &s);
		/* Release the io ref count */
		ifnet_decr_iorefcnt(ifp);

		lck_mtx_lock_spin(&ifp->if_poll_lock);

		/* if signalled to terminate */
		if (__improbable((ifp->if_poll_flags & IF_POLLF_TERMINATING)
		    != 0)) {
			break;
		}
		/* if there's no pending request, we're done. */
		if (!poll_again && (req == ifp->if_poll_req)) {
			break;
		}
	}

	ifp->if_poll_req = 0;
	ifp->if_poll_flags &= ~IF_POLLF_RUNNING;
	/*
	 * Wakeup N ns from now, else sleep indefinitely (ts = NULL)
	 * until ifnet_poll() is called again.
	 */
	/* calculate work duration (since last start work time) */
	if (ifp->if_poll_mode == IFNET_MODEL_INPUT_POLL_ON) {
		ASSERT(net_timerisset(&ifp->if_poll_cycle));
		ASSERT(net_timercmp(&poll_duration, &ifp->if_poll_cycle, <));
		net_timersub(&ifp->if_poll_cycle, &poll_duration, &poll_intvl);
		ASSERT(net_timerisset(&poll_intvl));
		ts = &poll_intvl;
	} else {
		ts = NULL;
	}

	if (__probable((ifp->if_poll_flags & IF_POLLF_TERMINATING) == 0)) {
		uint64_t deadline = TIMEOUT_WAIT_FOREVER;

		if (ts != NULL) {
			uint64_t interval;

			_CASSERT(IF_RXPOLL_INTERVALTIME_MIN >= (1ULL * 1000));
			net_timerusec(ts, &interval);
			ASSERT(interval <= UINT32_MAX);
			clock_interval_to_deadline((uint32_t)interval, NSEC_PER_USEC,
			    &deadline);
		}

		(void) assert_wait_deadline(&ifp->if_poll_thread,
		    THREAD_UNINT, deadline);
		lck_mtx_unlock(&ifp->if_poll_lock);
		(void) thread_block_parameter(netif_rxpoll_compat_thread_cont,
		    ifp);
		/* NOTREACHED */
	} else {
terminate:
		/* interface is detached (maybe while asleep)? */
		ifnet_set_poll_cycle(ifp, NULL);
		ifp->if_poll_flags &= ~IF_POLLF_READY;

		/* clear if_poll_thread to allow termination to continue */
		ASSERT(ifp->if_poll_thread != THREAD_NULL);
		ifp->if_poll_thread = THREAD_NULL;
		wakeup((caddr_t)&ifp->if_poll_thread);
		lck_mtx_unlock(&ifp->if_poll_lock);
		SK_DF(SK_VERB_NETIF_POLL, "%s: poller thread terminated",
		    if_name(ifp));
		/* for the extra refcnt from kernel_thread_start() */
		thread_deallocate(current_thread());
		/* this is the end */
		thread_terminate(current_thread());
		/* NOTREACHED */
	}

	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
void
netif_rxpoll_compat_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	char thread_name[MAXTHREADNAMESIZE];
	struct ifnet *ifp = v;

	VERIFY(ifp->if_eflags & IFEF_RXPOLL);
	VERIFY(current_thread() == ifp->if_poll_thread);

	/* construct the name for this thread, and then apply it */
	bzero(thread_name, sizeof(thread_name));
	(void) snprintf(thread_name, sizeof(thread_name),
	    "skywalk_netif_poller_%s", ifp->if_xname);
	thread_set_thread_name(ifp->if_poll_thread, thread_name);

	lck_mtx_lock(&ifp->if_poll_lock);
	VERIFY(!(ifp->if_poll_flags & (IF_POLLF_READY | IF_POLLF_RUNNING)));
	/* tell nx_netif_compat_na_activate() to proceed */
	ifp->if_poll_flags |= IF_POLLF_READY;
	wakeup((caddr_t)&ifp->if_poll_flags);
	(void) assert_wait(&ifp->if_poll_thread, THREAD_UNINT);
	lck_mtx_unlock(&ifp->if_poll_lock);
	(void) thread_block_parameter(netif_rxpoll_compat_thread_cont, ifp);
	/* NOTREACHED */
	__builtin_unreachable();
}
