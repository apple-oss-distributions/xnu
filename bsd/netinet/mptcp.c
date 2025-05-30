/*
 * Copyright (c) 2012-2021 Apple Inc. All rights reserved.
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

/*
 * A note on the MPTCP/NECP-interactions:
 *
 * MPTCP uses NECP-callbacks to get notified of interface/policy events.
 * MPTCP registers to these events at the MPTCP-layer for interface-events
 * through a call to necp_client_register_multipath_cb.
 * To get per-flow events (aka per TCP-subflow), we register to it with
 * necp_client_register_socket_flow. Both registrations happen by using the
 * necp-client-uuid that comes from the app.
 *
 * The locking is rather tricky. In general, we expect the lock-ordering to
 * happen from necp-fd -> necp->client -> mpp_lock.
 *
 * There are however some subtleties.
 *
 * 1. When registering the multipath_cb, we are holding the mpp_lock. This is
 * safe, because it is the very first time this MPTCP-connection goes into NECP.
 * As we go into NECP we take the NECP-locks and thus are guaranteed that no
 * NECP-locks will deadlock us. Because these NECP-events will also first take
 * the NECP-locks. Either they win the race and thus won't find our
 * MPTCP-connection. Or, MPTCP wins the race and thus it will safely install
 * the callbacks while holding the NECP lock.
 *
 * 2. When registering the subflow-callbacks we must unlock the mpp_lock. This,
 * because we have already registered callbacks and we might race against an
 * NECP-event that will match on our socket. So, we have to unlock to be safe.
 *
 * 3. When removing the multipath_cb, we do it in mp_pcbdispose(). The
 * so_usecount has reached 0. We must be careful to not remove the mpp_socket
 * pointers before we unregistered the callback. Because, again we might be
 * racing against an NECP-event. Unregistering must happen with an unlocked
 * mpp_lock, because of the lock-ordering constraint. It could be that
 * before we had a chance to unregister an NECP-event triggers. That's why
 * we need to check for the so_usecount in mptcp_session_necp_cb. If we get
 * there while the socket is being garbage-collected, the use-count will go
 * down to 0 and we exit. Removal of the multipath_cb again happens by taking
 * the NECP-locks so any running NECP-events will finish first and exit cleanly.
 *
 * 4. When removing the subflow-callback, we do it in in_pcbdispose(). Again,
 * the socket-lock must be unlocked for lock-ordering constraints. This gets a
 * bit tricky here, as in tcp_garbage_collect we hold the mp_so and so lock.
 * So, we drop the mp_so-lock as soon as the subflow is unlinked with
 * mptcp_subflow_del. Then, in in_pcbdispose we drop the subflow-lock.
 * If an NECP-event was waiting on the lock in mptcp_subflow_necp_cb, when it
 * gets it, it will realize that the subflow became non-MPTCP and retry (see
 * tcp_lock). Then it waits again on the subflow-lock. When we drop this lock
 * in in_pcbdispose, and enter necp_inpcb_dispose, this one will have to wait
 * for the NECP-lock (held by the other thread that is taking care of the NECP-
 * event). So, the event now finally gets the subflow-lock and then hits an
 * so_usecount that is 0 and exits. Eventually, we can remove the subflow from
 * the NECP callback.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/mcache.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/protosw.h>

#include <kern/zalloc.h>
#include <kern/locks.h>

#include <mach/sdt.h>

#include <net/droptap.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_var.h>
#include <netinet/mptcp_var.h>
#include <netinet/mptcp.h>
#include <netinet/mptcp_seq.h>
#include <netinet/mptcp_opt.h>
#include <netinet/mptcp_timer.h>

int mptcp_enable = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, enable, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_enable, 0, "Enable Multipath TCP Support");

/*
 * Number of times to try negotiating MPTCP on SYN retransmissions.
 * We haven't seen any reports of a middlebox that is dropping all SYN-segments
 * that have an MPTCP-option. Thus, let's be generous and retransmit it 4 times.
 */
int mptcp_mpcap_retries = 4;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, mptcp_cap_retr,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_mpcap_retries, 0, "Number of MP Capable SYN Retries");

/*
 * By default, DSS checksum is turned off, revisit if we ever do
 * MPTCP for non SSL Traffic.
 */
int mptcp_dss_csum = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, dss_csum, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_dss_csum, 0, "Enable DSS checksum");

/*
 * When mptcp_fail_thresh number of retransmissions are sent, subflow failover
 * is attempted on a different path.
 */
int mptcp_fail_thresh = 1;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, fail, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_fail_thresh, 0, "Failover threshold");

/*
 * MPTCP subflows have TCP keepalives set to ON. Set a conservative keeptime
 * as carrier networks mostly have a 30 minute to 60 minute NAT Timeout.
 * Some carrier networks have a timeout of 10 or 15 minutes.
 */
int mptcp_subflow_keeptime = 60 * 14;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, keepalive, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_subflow_keeptime, 0, "Keepalive in seconds");

int mptcp_rtthist_rtthresh = 600;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rtthist_thresh, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_rtthist_rtthresh, 0, "Rtt threshold");

int mptcp_rtothresh = 1500;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, rto_thresh, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_rtothresh, 0, "RTO threshold");

/*
 * Probe the preferred path, when it is not in use
 */
uint32_t mptcp_probeto = 1000;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, probeto, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_probeto, 0, "Disable probing by setting to 0");

uint32_t mptcp_probecnt = 5;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, probecnt, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_probecnt, 0, "Number of probe writes");

uint32_t mptcp_enable_v1 = 1;
SYSCTL_UINT(_net_inet_mptcp, OID_AUTO, enable_v1, CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_enable_v1, 0, "Enable or disable v1");

static int
sysctl_mptcp_version_check SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error;
	int new_value = *(int *)oidp->oid_arg1;
	int old_value = *(int *)oidp->oid_arg1;

	error = sysctl_handle_int(oidp, &new_value, 0, req);
	if (!error) {
		if (new_value != MPTCP_VERSION_0 && new_value != MPTCP_VERSION_1) {
			return EINVAL;
		}
		*(int *)oidp->oid_arg1 = new_value;
	}

	os_log(OS_LOG_DEFAULT,
	    "%s:%u sysctl net.inet.tcp.mptcp_preferred_version: %d -> %d)",
	    proc_best_name(current_proc()), proc_selfpid(),
	    old_value, *(int *)oidp->oid_arg1);

	return error;
}

int mptcp_preferred_version = MPTCP_VERSION_1;
SYSCTL_PROC(_net_inet_tcp, OID_AUTO, mptcp_preferred_version,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &mptcp_preferred_version, 0, &sysctl_mptcp_version_check, "I", "");

int mptcp_reass_total_qlen = 0;
SYSCTL_INT(_net_inet_mptcp, OID_AUTO, reass_qlen,
    CTLFLAG_RD | CTLFLAG_LOCKED, &mptcp_reass_total_qlen, 0,
    "Total number of MPTCP segments in reassembly queues");

static int
mptcp_reass_present(struct socket *mp_so)
{
	struct mptses *mpte = mpsotompte(mp_so);
	struct mptcb *mp_tp = mpte->mpte_mptcb;
	struct tseg_qent *q;
	int dowakeup = 0;
	int flags = 0;
	int count = 0;

	/*
	 * Present data to user, advancing rcv_nxt through
	 * completed sequence space.
	 */
	if (mp_tp->mpt_state < MPTCPS_ESTABLISHED) {
		return flags;
	}
	q = LIST_FIRST(&mp_tp->mpt_segq);
	if (!q || q->tqe_m->m_pkthdr.mp_dsn != mp_tp->mpt_rcvnxt) {
		return flags;
	}

	/*
	 * If there is already another thread doing reassembly for this
	 * connection, it is better to let it finish the job --
	 * (radar 16316196)
	 */
	if (mp_tp->mpt_flags & MPTCPF_REASS_INPROG) {
		return flags;
	}

	mp_tp->mpt_flags |= MPTCPF_REASS_INPROG;

	do {
		mp_tp->mpt_rcvnxt += q->tqe_len;
		LIST_REMOVE(q, tqe_q);
		if (mp_so->so_state & SS_CANTRCVMORE) {
			m_freem(q->tqe_m);
		} else {
			flags = !!(q->tqe_m->m_pkthdr.pkt_flags & PKTF_MPTCP_DFIN);
			if (sbappendstream_rcvdemux(mp_so, q->tqe_m)) {
				dowakeup = 1;
			}
		}
		tcp_reass_qent_free(q);
		mp_tp->mpt_reassqlen--;
		count++;
		q = LIST_FIRST(&mp_tp->mpt_segq);
	} while (q && q->tqe_m->m_pkthdr.mp_dsn == mp_tp->mpt_rcvnxt);
	mp_tp->mpt_flags &= ~MPTCPF_REASS_INPROG;

	if (count > 0) {
		OSAddAtomic(-count, &mptcp_reass_total_qlen);
	}
	if (dowakeup) {
		sorwakeup(mp_so); /* done with socket lock held */
	}
	return flags;
}

static int
mptcp_reass(struct socket *mp_so, struct pkthdr *phdr, int *tlenp, struct mbuf *m)
{
	struct mptcb *mp_tp = mpsotomppcb(mp_so)->mpp_pcbe->mpte_mptcb;
	u_int64_t mb_dsn = phdr->mp_dsn;
	struct tseg_qent *q;
	struct tseg_qent *p = NULL;
	struct tseg_qent *nq;
	struct tseg_qent *te = NULL;
	uint32_t qlimit;

	/*
	 * Limit the number of segments in the reassembly queue to prevent
	 * holding on to too many segments (and thus running out of mbufs).
	 * Make sure to let the missing segment through which caused this
	 * queue.  Always keep one global queue entry spare to be able to
	 * process the missing segment.
	 */
	qlimit = MIN(MAX(100, mp_so->so_rcv.sb_hiwat >> 10),
	    (tcp_autorcvbuf_max >> 10));
	if (mb_dsn != mp_tp->mpt_rcvnxt &&
	    (mp_tp->mpt_reassqlen + 1) >= qlimit) {
		tcpstat.tcps_mptcp_rcvmemdrop++;
		m_freem(m);
		*tlenp = 0;
		return 0;
	}

	/* Allocate a new queue entry. If we can't, just drop the pkt. XXX */
	te = tcp_reass_qent_alloc();

	mp_tp->mpt_reassqlen++;
	OSIncrementAtomic(&mptcp_reass_total_qlen);

	/*
	 * Find a segment which begins after this one does.
	 */
	LIST_FOREACH(q, &mp_tp->mpt_segq, tqe_q) {
		if (MPTCP_SEQ_GT(q->tqe_m->m_pkthdr.mp_dsn, mb_dsn)) {
			break;
		}
		p = q;
	}

	/*
	 * If there is a preceding segment, it may provide some of
	 * our data already.  If so, drop the data from the incoming
	 * segment.  If it provides all of our data, drop us.
	 */
	if (p != NULL) {
		int64_t i;
		/* conversion to int (in i) handles seq wraparound */
		i = p->tqe_m->m_pkthdr.mp_dsn + p->tqe_len - mb_dsn;
		if (i > 0) {
			if (i >= *tlenp) {
				tcpstat.tcps_mptcp_rcvduppack++;
				m_freem(m);
				tcp_reass_qent_free(te);
				te = NULL;
				mp_tp->mpt_reassqlen--;
				OSDecrementAtomic(&mptcp_reass_total_qlen);
				/*
				 * Try to present any queued data
				 * at the left window edge to the user.
				 * This is needed after the 3-WHS
				 * completes.
				 */
				goto out;
			}
			VERIFY(i <= INT_MAX);
			m_adj(m, (int)i);
			*tlenp -= i;
			phdr->mp_dsn += i;
		}
	}

	tcpstat.tcps_mp_oodata++;

	/*
	 * While we overlap succeeding segments trim them or,
	 * if they are completely covered, dequeue them.
	 */
	while (q) {
		int64_t i = (mb_dsn + *tlenp) - q->tqe_m->m_pkthdr.mp_dsn;
		if (i <= 0) {
			break;
		}

		if (i < q->tqe_len) {
			q->tqe_m->m_pkthdr.mp_dsn += i;
			q->tqe_len -= i;

			VERIFY(i <= INT_MAX);
			m_adj(q->tqe_m, (int)i);
			break;
		}

		nq = LIST_NEXT(q, tqe_q);
		LIST_REMOVE(q, tqe_q);
		m_freem(q->tqe_m);
		tcp_reass_qent_free(q);
		mp_tp->mpt_reassqlen--;
		OSDecrementAtomic(&mptcp_reass_total_qlen);
		q = nq;
	}

	/* Insert the new segment queue entry into place. */
	te->tqe_m = m;
	te->tqe_th = NULL;
	te->tqe_len = *tlenp;

	if (p == NULL) {
		LIST_INSERT_HEAD(&mp_tp->mpt_segq, te, tqe_q);
	} else {
		LIST_INSERT_AFTER(p, te, tqe_q);
	}

out:
	return mptcp_reass_present(mp_so);
}

/*
 * MPTCP input, called when data has been read from a subflow socket.
 */
void
mptcp_input(struct mptses *mpte, struct mbuf *m)
{
	struct socket *mp_so;
	struct mptcb *mp_tp = NULL;
	int count = 0, wakeup = 0;
	struct mbuf *save = NULL, *prev = NULL;
	struct mbuf *freelist = NULL, *tail = NULL;

	ASSERT(m->m_flags & M_PKTHDR);
	if (__improbable((m->m_flags & M_PKTHDR) == 0)) {
		m_drop_list(m, NULL, DROPTAP_FLAG_DIR_IN | DROPTAP_FLAG_L2_MISSING, DROP_REASON_MPTCP_INPUT_MALFORMED, NULL, 0);
		return;
	}

	mp_so = mptetoso(mpte);
	mp_tp = mpte->mpte_mptcb;

	socket_lock_assert_owned(mp_so);

	DTRACE_MPTCP(input);

	mp_tp->mpt_rcvwnd = imax(mptcp_sbspace(mp_tp), (int)(mp_tp->mpt_rcvadv - mp_tp->mpt_rcvnxt));

	/*
	 * Each mbuf contains MPTCP Data Sequence Map
	 * Process the data for reassembly, delivery to MPTCP socket
	 * client, etc.
	 *
	 */
	count = mp_so->so_rcv.sb_cc;

	/*
	 * In the degraded fallback case, data is accepted without DSS map
	 */
	if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) {
		struct mbuf *iter;
		int mb_dfin;
fallback:
		mb_dfin = 0;
		mptcp_sbrcv_grow(mp_tp);

		iter = m;
		while (iter) {
			if ((iter->m_flags & M_PKTHDR) &&
			    (iter->m_pkthdr.pkt_flags & PKTF_MPTCP_DFIN)) {
				mb_dfin = 1;
			}

			if ((iter->m_flags & M_PKTHDR) && m_pktlen(iter) == 0) {
				/* Don't add zero-length packets, so jump it! */
				if (prev == NULL) {
					m = iter->m_next;
					m_free(iter);
					iter = m;
				} else {
					prev->m_next = iter->m_next;
					m_free(iter);
					iter = prev->m_next;
				}

				/* It was a zero-length packet so next one must be a pkthdr */
				VERIFY(iter == NULL || iter->m_flags & M_PKTHDR);
			} else {
				prev = iter;
				iter = iter->m_next;
			}
		}

		/*
		 * assume degraded flow as this may be the first packet
		 * without DSS, and the subflow state is not updated yet.
		 */
		if (sbappendstream_rcvdemux(mp_so, m)) {
			sorwakeup(mp_so);
		}

		DTRACE_MPTCP5(receive__degraded, struct mbuf *, m,
		    struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mptses *, mpte);
		count = mp_so->so_rcv.sb_cc - count;

		mp_tp->mpt_rcvnxt += count;

		if (mb_dfin) {
			mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_FIN);
			socantrcvmore(mp_so);
		}
		return;
	}

	do {
		u_int64_t mb_dsn;
		int32_t mb_datalen;
		int64_t todrop;
		int mb_dfin = 0;

		VERIFY(m->m_flags & M_PKTHDR);

		/* If fallback occurs, mbufs will not have PKTF_MPTCP set */
		if (!(m->m_pkthdr.pkt_flags & PKTF_MPTCP)) {
			goto fallback;
		}

		save = m->m_next;
		/*
		 * A single TCP packet formed of multiple mbufs
		 * holds DSS mapping in the first mbuf of the chain.
		 * Other mbufs in the chain may have M_PKTHDR set
		 * even though they belong to the same TCP packet
		 * and therefore use the DSS mapping stored in the
		 * first mbuf of the mbuf chain. mptcp_input() can
		 * get an mbuf chain with multiple TCP packets.
		 */
		while (save && (!(save->m_flags & M_PKTHDR) ||
		    !(save->m_pkthdr.pkt_flags & PKTF_MPTCP))) {
			prev = save;
			save = save->m_next;
		}
		if (prev) {
			prev->m_next = NULL;
		} else {
			m->m_next = NULL;
		}

		mb_dsn = m->m_pkthdr.mp_dsn;
		mb_datalen = m->m_pkthdr.mp_rlen;

		todrop = (mb_dsn + mb_datalen) - (mp_tp->mpt_rcvnxt + mp_tp->mpt_rcvwnd);
		if (todrop > 0) {
			tcpstat.tcps_mptcp_rcvpackafterwin++;

			os_log_info(mptcp_log_handle, "%s - %lx: dropping dsn %u dlen %u rcvnxt %u rcvwnd %u todrop %lld\n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
			    (uint32_t)mb_dsn, mb_datalen, (uint32_t)mp_tp->mpt_rcvnxt,
			    mp_tp->mpt_rcvwnd, todrop);

			if (todrop >= mb_datalen) {
				if (freelist == NULL) {
					freelist = m;
				} else {
					tail->m_next = m;
				}

				if (prev != NULL) {
					tail = prev;
				} else {
					tail = m;
				}

				m = save;
				prev = save = NULL;
				continue;
			} else {
				VERIFY(todrop <= INT_MAX);
				m_adj(m, (int)-todrop);
				mb_datalen -= todrop;
				m->m_pkthdr.mp_rlen -= todrop;
			}

			/*
			 * We drop from the right edge of the mbuf, thus the
			 * DATA_FIN is dropped as well
			 */
			m->m_pkthdr.pkt_flags &= ~PKTF_MPTCP_DFIN;
		}

		if (MPTCP_SEQ_LT(mb_dsn, mp_tp->mpt_rcvnxt)) {
			if (MPTCP_SEQ_LEQ((mb_dsn + mb_datalen),
			    mp_tp->mpt_rcvnxt)) {
				if (freelist == NULL) {
					freelist = m;
				} else {
					tail->m_next = m;
				}

				if (prev != NULL) {
					tail = prev;
				} else {
					tail = m;
				}

				m = save;
				prev = save = NULL;
				continue;
			} else {
				VERIFY((mp_tp->mpt_rcvnxt - mb_dsn) <= INT_MAX);
				m_adj(m, (int)(mp_tp->mpt_rcvnxt - mb_dsn));
				mb_datalen -= (mp_tp->mpt_rcvnxt - mb_dsn);
				mb_dsn = mp_tp->mpt_rcvnxt;
				VERIFY(mb_datalen >= 0 && mb_datalen <= USHRT_MAX);
				m->m_pkthdr.mp_rlen = (uint16_t)mb_datalen;
				m->m_pkthdr.mp_dsn = mb_dsn;
			}
		}

		if (MPTCP_SEQ_GT(mb_dsn, mp_tp->mpt_rcvnxt) ||
		    !LIST_EMPTY(&mp_tp->mpt_segq)) {
			mb_dfin = mptcp_reass(mp_so, &m->m_pkthdr, &mb_datalen, m);

			goto next;
		}
		mb_dfin = !!(m->m_pkthdr.pkt_flags & PKTF_MPTCP_DFIN);

		mptcp_sbrcv_grow(mp_tp);

		if (sbappendstream_rcvdemux(mp_so, m)) {
			wakeup = 1;
		}

		DTRACE_MPTCP6(receive, struct mbuf *, m, struct socket *, mp_so,
		    struct sockbuf *, &mp_so->so_rcv,
		    struct sockbuf *, &mp_so->so_snd,
		    struct mptses *, mpte,
		    struct mptcb *, mp_tp);
		count = mp_so->so_rcv.sb_cc - count;
		tcpstat.tcps_mp_rcvtotal++;
		tcpstat.tcps_mp_rcvbytes += count;

		mp_tp->mpt_rcvnxt += count;

next:
		if (mb_dfin) {
			mptcp_close_fsm(mp_tp, MPCE_RECV_DATA_FIN);
			socantrcvmore(mp_so);
		}
		m = save;
		prev = save = NULL;
		count = mp_so->so_rcv.sb_cc;
	} while (m);

	if (freelist) {
		m_freem(freelist);
	}

	if (wakeup) {
		sorwakeup(mp_so);
	}
}

boolean_t
mptcp_can_send_more(struct mptcb *mp_tp, boolean_t ignore_reinject)
{
	struct socket *mp_so = mptetoso(mp_tp->mpt_mpte);

	/*
	 * Always send if there is data in the reinject-queue.
	 */
	if (!ignore_reinject && mp_tp->mpt_mpte->mpte_reinjectq) {
		return TRUE;
	}

	/*
	 * Don't send, if:
	 *
	 * 1. snd_nxt >= snd_max : Means, basically everything has been sent.
	 *    Except when using TFO, we might be doing a 0-byte write.
	 * 2. snd_una + snd_wnd <= snd_nxt: No space in the receiver's window
	 * 3. snd_nxt + 1 == snd_max and we are closing: A DATA_FIN is scheduled.
	 */

	if (!(mp_so->so_flags1 & SOF1_PRECONNECT_DATA) && MPTCP_SEQ_GEQ(mp_tp->mpt_sndnxt, mp_tp->mpt_sndmax)) {
		return FALSE;
	}

	if (MPTCP_SEQ_LEQ(mp_tp->mpt_snduna + mp_tp->mpt_sndwnd, mp_tp->mpt_sndnxt)) {
		return FALSE;
	}

	if (mp_tp->mpt_sndnxt + 1 == mp_tp->mpt_sndmax && mp_tp->mpt_state > MPTCPS_CLOSE_WAIT) {
		return FALSE;
	}

	if (mp_tp->mpt_state >= MPTCPS_FIN_WAIT_2) {
		return FALSE;
	}

	return TRUE;
}

/*
 * MPTCP output.
 */
int
mptcp_output(struct mptses *mpte)
{
	struct mptcb *mp_tp;
	struct mptsub *mpts;
	struct mptsub *mpts_tried = NULL;
	struct socket *mp_so;
	struct mptsub *preferred_mpts __single = NULL;
	uint64_t old_snd_nxt;
	int error = 0;

	mp_so = mptetoso(mpte);
	mp_tp = mpte->mpte_mptcb;

	socket_lock_assert_owned(mp_so);

	if (mp_so->so_flags & SOF_DEFUNCT) {
		return 0;
	}

	VERIFY(!(mpte->mpte_mppcb->mpp_flags & MPP_WUPCALL));
	mpte->mpte_mppcb->mpp_flags |= MPP_WUPCALL;

	old_snd_nxt = mp_tp->mpt_sndnxt;
	while (mptcp_can_send_more(mp_tp, FALSE)) {
		/* get the "best" subflow to be used for transmission */
		mpts = mptcp_get_subflow(mpte, &preferred_mpts);
		if (mpts == NULL) {
			break;
		}

		/* In case there's just one flow, we reattempt later */
		if (mpts_tried != NULL &&
		    (mpts == mpts_tried || (mpts->mpts_flags & MPTSF_FAILINGOVER))) {
			mpts_tried->mpts_flags &= ~MPTSF_FAILINGOVER;
			mpts_tried->mpts_flags |= MPTSF_ACTIVE;
			mptcp_start_timer(mpte, MPTT_REXMT);
			break;
		}

		/*
		 * Automatic sizing of send socket buffer. Increase the send
		 * socket buffer size if all of the following criteria are met
		 *	1. the receiver has enough buffer space for this data
		 *	2. send buffer is filled to 7/8th with data (so we actually
		 *	   have data to make use of it);
		 */
		if ((mp_so->so_snd.sb_flags & (SB_AUTOSIZE | SB_TRIM)) == SB_AUTOSIZE) {
			if ((mp_tp->mpt_sndwnd / 4 * 5) >= mp_so->so_snd.sb_hiwat &&
			    mp_so->so_snd.sb_cc >= (mp_so->so_snd.sb_hiwat / 8 * 7)) {
				if (sbreserve(&mp_so->so_snd,
				    min(mp_so->so_snd.sb_hiwat + tcp_autosndbuf_inc,
				    tcp_autosndbuf_max)) == 1) {
					mp_so->so_snd.sb_idealsize = mp_so->so_snd.sb_hiwat;
				}
			}
		}

		DTRACE_MPTCP3(output, struct mptses *, mpte, struct mptsub *, mpts,
		    struct socket *, mp_so);
		error = mptcp_subflow_output(mpte, mpts, 0);
		if (error) {
			/* can be a temporary loss of source address or other error */
			mpts->mpts_flags |= MPTSF_FAILINGOVER;
			mpts->mpts_flags &= ~MPTSF_ACTIVE;
			mpts_tried = mpts;
			if (error != ECANCELED) {
				os_log_error(mptcp_log_handle, "%s - %lx: Error = %d mpts_flags %#x\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte),
				    error, mpts->mpts_flags);
			}
			break;
		}
		/* The model is to have only one active flow at a time */
		mpts->mpts_flags |= MPTSF_ACTIVE;
		mpts->mpts_probesoon = mpts->mpts_probecnt = 0;

		/* Allows us to update the smoothed rtt */
		if (mptcp_probeto && mpts != preferred_mpts && preferred_mpts != NULL) {
			if (preferred_mpts->mpts_probesoon) {
				if ((tcp_now - preferred_mpts->mpts_probesoon) > mptcp_probeto) {
					mptcp_subflow_output(mpte, preferred_mpts, MPTCP_SUBOUT_PROBING);
					if (preferred_mpts->mpts_probecnt >= mptcp_probecnt) {
						preferred_mpts->mpts_probesoon = 0;
						preferred_mpts->mpts_probecnt = 0;
					}
				}
			} else {
				preferred_mpts->mpts_probesoon = tcp_now;
				preferred_mpts->mpts_probecnt = 0;
			}
		}

		if (mpte->mpte_active_sub == NULL) {
			mpte->mpte_active_sub = mpts;
		} else if (mpte->mpte_active_sub != mpts) {
			mpte->mpte_active_sub->mpts_flags &= ~MPTSF_ACTIVE;
			mpte->mpte_active_sub = mpts;

			mptcpstats_inc_switch(mpte, mpts);
		}
	}

	if (mp_tp->mpt_state > MPTCPS_CLOSE_WAIT) {
		if (mp_tp->mpt_sndnxt + 1 == mp_tp->mpt_sndmax &&
		    mp_tp->mpt_snduna == mp_tp->mpt_sndnxt) {
			mptcp_finish_usrclosed(mpte);
		}
	}

	mptcp_handle_deferred_upcalls(mpte->mpte_mppcb, MPP_WUPCALL);

	/* subflow errors should not be percolated back up */
	return 0;
}


static struct mptsub *
mptcp_choose_subflow(struct mptsub *mpts, struct mptsub *curbest, int *currtt)
{
	struct tcpcb *tp = sototcpcb(mpts->mpts_socket);

	/*
	 * Lower RTT? Take it, if it's our first one, or
	 * it doesn't has any loss, or the current one has
	 * loss as well.
	 */
	if (tp->t_srtt && *currtt > tp->t_srtt &&
	    (curbest == NULL || tp->t_rxtshift == 0 ||
	    sototcpcb(curbest->mpts_socket)->t_rxtshift)) {
		*currtt = tp->t_srtt;
		return mpts;
	}

	/*
	 * If we find a subflow without loss, take it always!
	 */
	if (curbest &&
	    sototcpcb(curbest->mpts_socket)->t_rxtshift &&
	    tp->t_rxtshift == 0) {
		*currtt = tp->t_srtt;
		return mpts;
	}

	return curbest != NULL ? curbest : mpts;
}

static struct mptsub *
mptcp_return_subflow(struct mptsub *mpts)
{
	if (mpts && mptcp_subflow_cwnd_space(mpts->mpts_socket) <= 0) {
		return NULL;
	}

	return mpts;
}

static boolean_t
mptcp_subflow_is_slow(struct mptses *mpte, struct mptsub *mpts)
{
	struct tcpcb *tp = sototcpcb(mpts->mpts_socket);
	int fail_thresh = mptcp_fail_thresh;

	if (mpte->mpte_svctype == MPTCP_SVCTYPE_HANDOVER || mpte->mpte_svctype == MPTCP_SVCTYPE_PURE_HANDOVER) {
		fail_thresh *= 2;
	}

	return tp->t_rxtshift >= fail_thresh &&
	       (mptetoso(mpte)->so_snd.sb_cc || mpte->mpte_reinjectq);
}

/*
 * Return the most eligible subflow to be used for sending data.
 */
struct mptsub *
mptcp_get_subflow(struct mptses *mpte, struct mptsub **preferred)
{
	struct tcpcb *besttp, *secondtp;
	struct inpcb *bestinp, *secondinp;
	struct mptsub *mpts;
	struct mptsub *best = NULL;
	struct mptsub *second_best = NULL;
	int exp_rtt = INT_MAX, cheap_rtt = INT_MAX;

	/*
	 * First Step:
	 * Choose the best subflow for cellular and non-cellular interfaces.
	 */

	TAILQ_FOREACH(mpts, &mpte->mpte_subflows, mpts_entry) {
		struct socket *so = mpts->mpts_socket;
		struct tcpcb *tp = sototcpcb(so);
		struct inpcb *inp = sotoinpcb(so);

		/*
		 * First, the hard conditions to reject subflows
		 * (e.g., not connected,...)
		 */
		if (inp->inp_last_outifp == NULL) {
			continue;
		}

		if (INP_WAIT_FOR_IF_FEEDBACK(inp)) {
			continue;
		}

		/* There can only be one subflow in degraded state */
		if (mpts->mpts_flags & MPTSF_MP_DEGRADED) {
			best = mpts;
			break;
		}

		/*
		 * If this subflow is waiting to finally send, do it!
		 */
		if (so->so_flags1 & SOF1_PRECONNECT_DATA) {
			return mptcp_return_subflow(mpts);
		}

		/*
		 * Only send if the subflow is MP_CAPABLE. The exceptions to
		 * this rule (degraded or TFO) have been taken care of above.
		 */
		if (!(mpts->mpts_flags & MPTSF_MP_CAPABLE)) {
			continue;
		}

		if ((so->so_state & SS_ISDISCONNECTED) ||
		    !(so->so_state & SS_ISCONNECTED) ||
		    !TCPS_HAVEESTABLISHED(tp->t_state) ||
		    tp->t_state > TCPS_CLOSE_WAIT) {
			continue;
		}

		/*
		 * Second, the soft conditions to find the subflow with best
		 * conditions for each set (aka cellular vs non-cellular)
		 */
		if (IFNET_IS_CELLULAR(inp->inp_last_outifp)) {
			second_best = mptcp_choose_subflow(mpts, second_best,
			    &exp_rtt);
		} else {
			best = mptcp_choose_subflow(mpts, best, &cheap_rtt);
		}
	}

	/*
	 * If there is no preferred or backup subflow, and there is no active
	 * subflow use the last usable subflow.
	 */
	if (best == NULL) {
		return mptcp_return_subflow(second_best);
	}

	if (second_best == NULL) {
		return mptcp_return_subflow(best);
	}

	besttp = sototcpcb(best->mpts_socket);
	bestinp = sotoinpcb(best->mpts_socket);
	secondtp = sototcpcb(second_best->mpts_socket);
	secondinp = sotoinpcb(second_best->mpts_socket);

	if (preferred != NULL) {
		*preferred = mptcp_return_subflow(best);
	}

	/*
	 * Second Step: Among best and second_best. Choose the one that is
	 * most appropriate for this particular service-type.
	 */
	if (mpte->mpte_svctype == MPTCP_SVCTYPE_PURE_HANDOVER) {
		return mptcp_return_subflow(best);
	} else if (mpte->mpte_svctype == MPTCP_SVCTYPE_HANDOVER) {
		/*
		 * Only handover if Symptoms tells us to do so.
		 */
		if (!IFNET_IS_CELLULAR(bestinp->inp_last_outifp) &&
		    mptcp_wifi_quality_for_session(mpte) != MPTCP_WIFI_QUALITY_GOOD &&
		    mptcp_subflow_is_slow(mpte, best)) {
			return mptcp_return_subflow(second_best);
		}

		return mptcp_return_subflow(best);
	} else if (mpte->mpte_svctype == MPTCP_SVCTYPE_INTERACTIVE) {
		int rtt_thresh = mptcp_rtthist_rtthresh << TCP_RTT_SHIFT;
		int rto_thresh = mptcp_rtothresh;

		/* Adjust with symptoms information */
		if (!IFNET_IS_CELLULAR(bestinp->inp_last_outifp) &&
		    mptcp_wifi_quality_for_session(mpte) != MPTCP_WIFI_QUALITY_GOOD) {
			rtt_thresh /= 2;
			rto_thresh /= 2;
		}

		if (besttp->t_srtt && secondtp->t_srtt &&
		    besttp->t_srtt >= rtt_thresh &&
		    secondtp->t_srtt < rtt_thresh) {
			tcpstat.tcps_mp_sel_rtt++;
			return mptcp_return_subflow(second_best);
		}

		if (mptcp_subflow_is_slow(mpte, best) &&
		    secondtp->t_rxtshift == 0) {
			return mptcp_return_subflow(second_best);
		}

		/* Compare RTOs, select second_best if best's rto exceeds rtothresh */
		if (besttp->t_rxtcur && secondtp->t_rxtcur &&
		    besttp->t_rxtcur >= rto_thresh &&
		    secondtp->t_rxtcur < rto_thresh) {
			tcpstat.tcps_mp_sel_rto++;

			return mptcp_return_subflow(second_best);
		}

		/*
		 * None of the above conditions for sending on the secondary
		 * were true. So, let's schedule on the best one, if he still
		 * has some space in the congestion-window.
		 */
		return mptcp_return_subflow(best);
	} else if (mpte->mpte_svctype >= MPTCP_SVCTYPE_AGGREGATE) {
		struct mptsub *tmp;

		/*
		 * We only care about RTT when aggregating
		 */
		if (besttp->t_srtt > secondtp->t_srtt) {
			tmp = best;
			best = second_best;
			besttp = secondtp;
			bestinp = secondinp;

			second_best = tmp;
			secondtp = sototcpcb(second_best->mpts_socket);
			secondinp = sotoinpcb(second_best->mpts_socket);
		}

		/* Is there still space in the congestion window? */
		if (mptcp_subflow_cwnd_space(bestinp->inp_socket) <= 0) {
			return mptcp_return_subflow(second_best);
		}

		return mptcp_return_subflow(best);
	} else {
		panic("Unknown service-type configured for MPTCP");
	}

	return NULL;
}

void
mptcp_close_fsm(struct mptcb *mp_tp, uint32_t event)
{
	struct socket *mp_so = mptetoso(mp_tp->mpt_mpte);

	socket_lock_assert_owned(mp_so);

	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp,
	    uint32_t, event);

	switch (mp_tp->mpt_state) {
	case MPTCPS_CLOSED:
	case MPTCPS_LISTEN:
		mp_tp->mpt_state = MPTCPS_TERMINATE;
		break;

	case MPTCPS_ESTABLISHED:
		if (event == MPCE_CLOSE) {
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_1;
			mp_tp->mpt_sndmax += 1; /* adjust for Data FIN */
		} else if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_CLOSE_WAIT;
		}
		break;

	case MPTCPS_CLOSE_WAIT:
		if (event == MPCE_CLOSE) {
			mp_tp->mpt_state = MPTCPS_LAST_ACK;
			mp_tp->mpt_sndmax += 1; /* adjust for Data FIN */
		}
		break;

	case MPTCPS_FIN_WAIT_1:
		if (event == MPCE_RECV_DATA_ACK) {
			mp_tp->mpt_state = MPTCPS_FIN_WAIT_2;
		} else if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_CLOSING;
		}
		break;

	case MPTCPS_CLOSING:
		if (event == MPCE_RECV_DATA_ACK) {
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		}
		break;

	case MPTCPS_LAST_ACK:
		if (event == MPCE_RECV_DATA_ACK) {
			mptcp_close(mp_tp->mpt_mpte, mp_tp);
		}
		break;

	case MPTCPS_FIN_WAIT_2:
		if (event == MPCE_RECV_DATA_FIN) {
			mp_tp->mpt_rcvnxt += 1; /* adj remote data FIN */
			mp_tp->mpt_state = MPTCPS_TIME_WAIT;
		}
		break;

	case MPTCPS_TIME_WAIT:
	case MPTCPS_TERMINATE:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
	}
	DTRACE_MPTCP2(state__change, struct mptcb *, mp_tp,
	    uint32_t, event);
}

/* If you change this function, match up mptcp_update_rcv_state_f */
void
mptcp_update_dss_rcv_state(struct mptcp_dsn_opt *dss_info, struct tcpcb *tp,
    uint16_t csum)
{
	struct mptcb *mp_tp = tptomptp(tp);
	u_int64_t full_dsn = 0;

	NTOHL(dss_info->mdss_dsn);
	NTOHL(dss_info->mdss_subflow_seqn);
	NTOHS(dss_info->mdss_data_len);

	/* XXX for autosndbuf grow sb here */
	MPTCP_EXTEND_DSN(mp_tp->mpt_rcvnxt, dss_info->mdss_dsn, full_dsn);
	mptcp_update_rcv_state_meat(mp_tp, tp,
	    full_dsn, dss_info->mdss_subflow_seqn, dss_info->mdss_data_len,
	    csum);
}

void
mptcp_update_rcv_state_meat(struct mptcb *mp_tp, struct tcpcb *tp,
    u_int64_t full_dsn, u_int32_t seqn, u_int16_t mdss_data_len,
    uint16_t csum)
{
	if (mdss_data_len == 0) {
		os_log_error(mptcp_log_handle, "%s - %lx: Infinite Mapping.\n",
		    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mp_tp->mpt_mpte));

		if ((mp_tp->mpt_flags & MPTCPF_CHECKSUM) && (csum != 0)) {
			os_log_error(mptcp_log_handle, "%s - %lx: Bad checksum %x \n",
			    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mp_tp->mpt_mpte), csum);
		}
		mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
		return;
	}

	mptcp_notify_mpready(tp->t_inpcb->inp_socket);

	tp->t_rcv_map.mpt_dsn = full_dsn;
	tp->t_rcv_map.mpt_sseq = seqn;
	tp->t_rcv_map.mpt_len = mdss_data_len;
	tp->t_rcv_map.mpt_csum = csum;
	tp->t_mpflags |= TMPF_EMBED_DSN;
}


static uint16_t
mptcp_input_csum(struct tcpcb *tp, struct mbuf *m, uint64_t dsn, uint32_t sseq,
    uint16_t dlen, uint16_t csum, int dfin)
{
	struct mptcb *mp_tp = tptomptp(tp);
	int real_len = dlen - dfin;
	uint32_t sum = 0;

	VERIFY(real_len >= 0);

	if (mp_tp == NULL) {
		return 0;
	}

	if (!(mp_tp->mpt_flags & MPTCPF_CHECKSUM)) {
		return 0;
	}

	if (tp->t_mpflags & TMPF_TCP_FALLBACK) {
		return 0;
	}

	/*
	 * The remote side may send a packet with fewer bytes than the
	 * claimed DSS checksum length.
	 */
	if ((int)m_length2(m, NULL) < real_len) {
		return 0xffff;
	}

	if (real_len != 0) {
		sum = m_sum16(m, 0, real_len);
	}

	sum += in_pseudo64(htonll(dsn), htonl(sseq), htons(dlen) + csum);
	ADDCARRY(sum);

	DTRACE_MPTCP3(checksum__result, struct tcpcb *, tp, struct mbuf *, m,
	    uint32_t, sum);

	return ~sum & 0xffff;
}

/*
 * MPTCP Checksum support
 * The checksum is calculated whenever the MPTCP DSS option is included
 * in the TCP packet. The checksum includes the sum of the MPTCP psuedo
 * header and the actual data indicated by the length specified in the
 * DSS option.
 */

int
mptcp_validate_csum(struct tcpcb *tp, struct mbuf *m, uint64_t dsn,
    uint32_t sseq, uint16_t dlen, uint16_t csum, int dfin)
{
	uint16_t mptcp_csum;

	mptcp_csum = mptcp_input_csum(tp, m, dsn, sseq, dlen, csum, dfin);
	if (mptcp_csum) {
		tp->t_mpflags |= TMPF_SND_MPFAIL;
		mptcp_notify_mpfail(tp->t_inpcb->inp_socket);
		m_freem(m);
		tcpstat.tcps_mp_badcsum++;
		return -1;
	}
	return 0;
}

uint16_t
mptcp_output_csum(struct mbuf *m, uint64_t dss_val, uint32_t sseq, uint16_t dlen)
{
	uint32_t sum = 0;

	if (dlen) {
		sum = m_sum16(m, 0, dlen);
	}

	dss_val = mptcp_hton64(dss_val);
	sseq = htonl(sseq);
	dlen = htons(dlen);
	sum += in_pseudo64(dss_val, sseq, dlen);

	ADDCARRY(sum);
	sum = ~sum & 0xffff;
	DTRACE_MPTCP2(checksum__result, struct mbuf *, m, uint32_t, sum);

	return (uint16_t)sum;
}

/*
 * When WiFi signal starts fading, there's more loss and RTT spikes.
 * Check if there has been a large spike by comparing against
 * a tolerable RTT spike threshold.
 */
boolean_t
mptcp_no_rto_spike(struct socket *so)
{
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));
	int32_t spike = 0;

	if (tp->t_rxtcur > mptcp_rtothresh) {
		spike = tp->t_rxtcur - mptcp_rtothresh;
	}

	if (spike > 0) {
		return FALSE;
	} else {
		return TRUE;
	}
}

void
mptcp_handle_deferred_upcalls(struct mppcb *mpp, uint32_t flag)
{
	VERIFY(mpp->mpp_flags & flag);
	mpp->mpp_flags &= ~flag;

	if (mptcp_should_defer_upcall(mpp)) {
		return;
	}

	if (mpp->mpp_flags & MPP_SHOULD_WORKLOOP) {
		mpp->mpp_flags &= ~MPP_SHOULD_WORKLOOP;

		mptcp_subflow_workloop(mpp->mpp_pcbe);
	}

	if (mpp->mpp_flags & MPP_SHOULD_RWAKEUP) {
		mpp->mpp_flags &= ~MPP_SHOULD_RWAKEUP;

		sorwakeup(mpp->mpp_socket);
	}

	if (mpp->mpp_flags & MPP_SHOULD_WWAKEUP) {
		mpp->mpp_flags &= ~MPP_SHOULD_WWAKEUP;

		sowwakeup(mpp->mpp_socket);
	}
}

static void
mptcp_reset_itfinfo(struct mpt_itf_info *info)
{
	memset(info, 0, sizeof(*info));
}

void
mptcp_session_necp_cb(void *handle, int action, uint32_t interface_index,
    uint32_t necp_flags, __unused bool *viable)
{
	boolean_t has_v4 = !!(necp_flags & NECP_CLIENT_RESULT_FLAG_HAS_IPV4);
	boolean_t has_v6 = !!(necp_flags & NECP_CLIENT_RESULT_FLAG_HAS_IPV6);
	boolean_t has_nat64 = !!(necp_flags & NECP_CLIENT_RESULT_FLAG_HAS_NAT64);
	boolean_t low_power = !!(necp_flags & NECP_CLIENT_RESULT_FLAG_INTERFACE_LOW_POWER);
	struct mppcb *mp = (struct mppcb *)handle;
	struct mptses *mpte = mptompte(mp);
	struct socket *mp_so;
	struct mptcb *mp_tp;
	uint32_t i, ifindex;
	struct ifnet *ifp;
	int locked = 0;

	ifindex = interface_index;
	VERIFY(ifindex != IFSCOPE_NONE);

	/* About to be garbage-collected (see note about MPTCP/NECP interactions) */
	if (mp->mpp_socket->so_usecount == 0) {
		return;
	}

	mp_so = mptetoso(mpte);

	if (action != NECP_CLIENT_CBACTION_INITIAL) {
		socket_lock(mp_so, 1);
		locked = 1;

		/* Check again, because it might have changed while waiting */
		if (mp->mpp_socket->so_usecount == 0) {
			goto out;
		}
	}

	socket_lock_assert_owned(mp_so);

	mp_tp = mpte->mpte_mptcb;

	ifnet_head_lock_shared();
	ifp = ifindex2ifnet[ifindex];
	ifnet_head_done();

	os_log(mptcp_log_handle, "%s - %lx: action: %u ifindex %u delegated to %u usecount %u mpt_flags %#x state %u v4 %u v6 %u nat64 %u power %u\n",
	    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), action, ifindex,
	    ifp && ifp->if_delegated.ifp ? ifp->if_delegated.ifp->if_index : IFSCOPE_NONE,
	    mp->mpp_socket->so_usecount, mp_tp->mpt_flags, mp_tp->mpt_state,
	    has_v4, has_v6, has_nat64, low_power);

	/* No need on fallen back sockets */
	if (mp_tp->mpt_flags & MPTCPF_FALLBACK_TO_TCP) {
		goto out;
	}

	/*
	 * When the interface goes in low-power mode we don't want to establish
	 * new subflows on it. Thus, mark it internally as non-viable.
	 */
	if (low_power) {
		action = NECP_CLIENT_CBACTION_NONVIABLE;
	}

	if (action == NECP_CLIENT_CBACTION_INITIAL) {
		mpte->mpte_flags |= MPTE_ITFINFO_INIT;
	}

	if (action == NECP_CLIENT_CBACTION_NONVIABLE) {
		for (i = 0; i < mpte->mpte_itfinfo_size; i++) {
			if (mpte->mpte_itfinfo[i].ifindex == IFSCOPE_NONE) {
				continue;
			}

			if (mpte->mpte_itfinfo[i].ifindex == ifindex) {
				mptcp_reset_itfinfo(&mpte->mpte_itfinfo[i]);
			}
		}

		mptcp_sched_create_subflows(mpte);
	} else if (action == NECP_CLIENT_CBACTION_VIABLE ||
	    action == NECP_CLIENT_CBACTION_INITIAL) {
		int found_slot = 0, slot_index = -1;
		struct sockaddr *dst;

		if (ifp == NULL) {
			goto out;
		}

		if (IFNET_IS_COMPANION_LINK(ifp)) {
			goto out;
		}

		if (IFNET_IS_EXPENSIVE(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_EXPENSIVE)) {
			goto out;
		}

		if (IFNET_IS_CONSTRAINED(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_CONSTRAINED)) {
			goto out;
		}

		if (IFNET_IS_CELLULAR(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_CELLULAR)) {
			goto out;
		}

		if (IS_INTF_CLAT46(ifp)) {
			has_v4 = FALSE;
		}

		/* Look for the slot on where to store/update the interface-info. */
		for (i = 0; i < mpte->mpte_itfinfo_size; i++) {
			/* Found a potential empty slot where we can put it */
			if (mpte->mpte_itfinfo[i].ifindex == 0) {
				found_slot = 1;
				slot_index = i;
			}

			/*
			 * The interface is already in our array. Check if we
			 * need to update it.
			 */
			if (mpte->mpte_itfinfo[i].ifindex == ifindex &&
			    (mpte->mpte_itfinfo[i].has_v4_conn != has_v4 ||
			    mpte->mpte_itfinfo[i].has_v6_conn != has_v6 ||
			    mpte->mpte_itfinfo[i].has_nat64_conn != has_nat64)) {
				found_slot = 1;
				slot_index = i;
				break;
			}

			if (mpte->mpte_itfinfo[i].ifindex == ifindex) {
				/*
				 * Ok, it's already there and we don't need
				 * to update it
				 */
				goto out;
			}
		}

		dst = mptcp_get_session_dst(mpte, has_v6, has_v4);
		if (dst && dst->sa_family == AF_INET &&
		    has_v6 && !has_nat64 && !has_v4) {
			if (found_slot) {
				mpte->mpte_itfinfo[slot_index].ifindex = ifindex;
				mpte->mpte_itfinfo[slot_index].has_v4_conn = has_v4;
				mpte->mpte_itfinfo[slot_index].has_v6_conn = has_v6;
				mpte->mpte_itfinfo[slot_index].has_nat64_conn = has_nat64;
			}
			goto out;
		}

		if (found_slot == 0) {
			int new_size = mpte->mpte_itfinfo_size * 2;
			struct mpt_itf_info *info = kalloc_data(sizeof(*info) * new_size, Z_ZERO);

			if (info == NULL) {
				os_log_error(mptcp_log_handle, "%s - %lx: malloc failed for %u\n",
				    __func__, (unsigned long)VM_KERNEL_ADDRPERM(mpte), new_size);
				goto out;
			}

			memcpy(info, mpte->mpte_itfinfo, mpte->mpte_itfinfo_size * sizeof(*info));

			if (mpte->mpte_itfinfo_size > MPTE_ITFINFO_SIZE) {
				kfree_data_counted_by(mpte->mpte_itfinfo, mpte->mpte_itfinfo_size);
			}

			/* We allocated a new one, thus the first must be empty */
			slot_index = mpte->mpte_itfinfo_size;

			mpte->mpte_itfinfo = info;
			mpte->mpte_itfinfo_size = new_size;
		}

		VERIFY(slot_index >= 0 && slot_index < (int)mpte->mpte_itfinfo_size);
		mpte->mpte_itfinfo[slot_index].ifindex = ifindex;
		mpte->mpte_itfinfo[slot_index].has_v4_conn = has_v4;
		mpte->mpte_itfinfo[slot_index].has_v6_conn = has_v6;
		mpte->mpte_itfinfo[slot_index].has_nat64_conn = has_nat64;

		mptcp_sched_create_subflows(mpte);
	}

out:
	if (locked) {
		socket_unlock(mp_so, 1);
	}
}

void
mptcp_set_restrictions(struct socket *mp_so)
{
	struct mptses *mpte = mpsotompte(mp_so);
	uint32_t i;

	socket_lock_assert_owned(mp_so);

	ifnet_head_lock_shared();

	for (i = 0; i < mpte->mpte_itfinfo_size; i++) {
		struct mpt_itf_info *info = &mpte->mpte_itfinfo[i];
		uint32_t ifindex = info->ifindex;
		struct ifnet *ifp;

		if (ifindex == IFSCOPE_NONE) {
			continue;
		}

		ifp = ifindex2ifnet[ifindex];
		if (ifp == NULL) {
			continue;
		}

		if (IFNET_IS_EXPENSIVE(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_EXPENSIVE)) {
			info->ifindex = IFSCOPE_NONE;
		}

		if (IFNET_IS_CONSTRAINED(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_CONSTRAINED)) {
			info->ifindex = IFSCOPE_NONE;
		}

		if (IFNET_IS_CELLULAR(ifp) &&
		    (mp_so->so_restrictions & SO_RESTRICT_DENY_CELLULAR)) {
			info->ifindex = IFSCOPE_NONE;
		}
	}

	ifnet_head_done();
}

#define DUMP_BUF_CHK() {        \
	clen -= k;              \
    if (clen < 1)           \
	    goto done;          \
    c += k;                 \
}

int
dump_mptcp_reass_qlen(char *str __sized_by(str_len), int str_len)
{
	char *c = str;
	int k, clen = str_len;

	if (mptcp_reass_total_qlen != 0) {
		k = scnprintf(c, clen, "\nmptcp reass qlen %d\n", mptcp_reass_total_qlen);
		DUMP_BUF_CHK();
	}

done:
	return str_len - clen;
}
