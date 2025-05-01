/*
 * Copyright (c) 1999-2024 Apple Inc. All rights reserved.
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

#include <net/if_var.h>
#include <net/dlil_var_private.h>
#include <net/dlil.h>
#include <net/dlil_sysctl.h>


#define DLIL_EWMA(old, new, decay) do {                                 \
	u_int32_t _avg;                                                 \
	if ((_avg = (old)) > 0)                                         \
	        _avg = (((_avg << (decay)) - _avg) + (new)) >> (decay); \
	else                                                            \
	        _avg = (new);                                           \
	(old) = _avg;                                                   \
} while (0)


/*
 * Detect whether a queue contains a burst that needs to be trimmed.
 */
#define MBUF_QUEUE_IS_OVERCOMMITTED(q)                                                                  \
	__improbable(MAX(if_rcvq_burst_limit, qlimit(q)) < qlen(q) &&           \
	                        qtype(q) == QP_MBUF)


/* rate limit debug messages */
struct timespec dlil_dbgrate = { .tv_sec = 1, .tv_nsec = 0 };

extern void proto_input_run(void);

static errno_t dlil_input_async(struct dlil_threading_info *inp, struct ifnet *ifp, struct mbuf *m_head, struct mbuf *m_tail, const struct ifnet_stat_increment_param *s, boolean_t poll, struct thread *tp);
static errno_t dlil_input_sync(struct dlil_threading_info *inp, struct ifnet *ifp, struct mbuf *m_head, struct mbuf *m_tail, const struct ifnet_stat_increment_param *s, boolean_t poll, struct thread *tp);
static void dlil_input_cksum_dbg(struct ifnet *ifp, struct mbuf *m, char *frame_header, protocol_family_t pf);
static void dlil_input_packet_list_common(struct ifnet *, mbuf_ref_t, u_int32_t, ifnet_model_t, boolean_t);
static void dlil_input_thread_func(void *, wait_result_t);
static void dlil_input_thread_cont(void *, wait_result_t);
static inline void dlil_input_wakeup(struct dlil_threading_info *inp);

static int dlil_interface_filters_input(struct ifnet *, mbuf_ref_ref_t, char **, protocol_family_t, boolean_t);

static void dlil_main_input_thread_func(void *, wait_result_t);
static void dlil_main_input_thread_cont(void *, wait_result_t);

static void dlil_rxpoll_input_thread_func(void *, wait_result_t);
static void dlil_rxpoll_input_thread_cont(void *, wait_result_t);

static uint32_t dlil_trim_overcomitted_queue_locked(class_queue_t *input_queue, dlil_freeq_t *freeq, struct ifnet_stat_increment_param *stat_delta);

static inline mbuf_t handle_bridge_early_input(ifnet_t ifp, mbuf_t m, u_int32_t cnt);
/*
 * Publicly visible functions.
 */

int
dlil_create_input_thread(ifnet_t ifp, struct dlil_threading_info *inp,
    thread_continue_t *thfunc)
{
	boolean_t dlil_rxpoll_input;
	thread_continue_t func = NULL;
	u_int32_t limit;
	int error = 0;

	dlil_rxpoll_input = (ifp != NULL && net_rxpoll &&
	    (ifp->if_eflags & IFEF_RXPOLL) && (ifp->if_xflags & IFXF_LEGACY));

	/* default strategy utilizes the DLIL worker thread */
	inp->dlth_strategy = dlil_input_async;

	/* NULL ifp indicates the main input thread, called at dlil_init time */
	if (ifp == NULL) {
		/*
		 * Main input thread only.
		 */
		func = dlil_main_input_thread_func;
		VERIFY(inp == dlil_main_input_thread);
		inp->dlth_name = tsnprintf(inp->dlth_name_storage, sizeof(inp->dlth_name_storage),
		    "main_input");
	} else if (dlil_rxpoll_input) {
		/*
		 * Legacy (non-netif) hybrid polling.
		 */
		func = dlil_rxpoll_input_thread_func;
		VERIFY(inp != dlil_main_input_thread);
		inp->dlth_name = tsnprintf(inp->dlth_name_storage, sizeof(inp->dlth_name_storage),
		    "%s_input_poll", if_name(ifp));
	} else if (net_async || (ifp->if_xflags & IFXF_LEGACY)) {
		/*
		 * Asynchronous strategy.
		 */
		func = dlil_input_thread_func;
		VERIFY(inp != dlil_main_input_thread);
		inp->dlth_name = tsnprintf(inp->dlth_name_storage, sizeof(inp->dlth_name_storage),
		    "%s_input", if_name(ifp));
	} else {
		/*
		 * Synchronous strategy if there's a netif below and
		 * the device isn't capable of hybrid polling.
		 */
		ASSERT(func == NULL);
		ASSERT(!(ifp->if_xflags & IFXF_LEGACY));
		VERIFY(inp != dlil_main_input_thread);
		ASSERT(!inp->dlth_affinity);
		inp->dlth_strategy = dlil_input_sync;
		inp->dlth_name = __unsafe_null_terminated_from_indexable(inp->dlth_name_storage);
	}
	VERIFY(inp->dlth_thread == THREAD_NULL);

	/* let caller know */
	if (thfunc != NULL) {
		*thfunc = func;
	}

	inp->dlth_lock_grp = lck_grp_alloc_init(inp->dlth_name, LCK_GRP_ATTR_NULL);
	lck_mtx_init(&inp->dlth_lock, inp->dlth_lock_grp, &dlil_lck_attributes);

	inp->dlth_ifp = ifp; /* NULL for main input thread */

	/*
	 * For interfaces that support opportunistic polling, set the
	 * low and high watermarks for outstanding inbound packets/bytes.
	 * Also define freeze times for transitioning between modes
	 * and updating the average.
	 */
	if (ifp != NULL && net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL)) {
		limit = MAX(if_rcvq_maxlen, IF_RCVQ_MINLEN);
		if (ifp->if_xflags & IFXF_LEGACY) {
			(void) dlil_rxpoll_set_params(ifp, NULL, FALSE);
		}
	} else {
		/*
		 * For interfaces that don't support opportunistic
		 * polling, set the burst limit to prevent memory exhaustion.
		 * The values of `if_rcvq_burst_limit' are safeguarded
		 * on customer builds by `sysctl_rcvq_burst_limit'.
		 */
		limit = if_rcvq_burst_limit;
	}

	_qinit(&inp->dlth_pkts, Q_DROPTAIL, limit, QP_MBUF);
	if (inp == dlil_main_input_thread) {
		dlil_main_threading_info_ref_t inpm =
		    __container_of(inp, struct dlil_main_threading_info, inp);
		_qinit(&inpm->lo_rcvq_pkts, Q_DROPTAIL, limit, QP_MBUF);
	}

	if (func == NULL) {
		ASSERT(!(ifp->if_xflags & IFXF_LEGACY));
		ASSERT(error == 0);
		error = ENODEV;
		goto done;
	}

	error = kernel_thread_start(func, inp, &inp->dlth_thread);
	if (error == KERN_SUCCESS) {
		thread_precedence_policy_data_t info;
		__unused kern_return_t kret;

		bzero(&info, sizeof(info));
		info.importance = 0;
		kret = thread_policy_set(inp->dlth_thread,
		    THREAD_PRECEDENCE_POLICY, (thread_policy_t)&info,
		    THREAD_PRECEDENCE_POLICY_COUNT);
		ASSERT(kret == KERN_SUCCESS);
		/*
		 * We create an affinity set so that the matching workloop
		 * thread or the starter thread (for loopback) can be
		 * scheduled on the same processor set as the input thread.
		 */
		if (net_affinity) {
			struct thread *tp __single = inp->dlth_thread;
			u_int32_t tag;
			/*
			 * Randomize to reduce the probability
			 * of affinity tag namespace collision.
			 */
			read_frandom(&tag, sizeof(tag));
			if (dlil_affinity_set(tp, tag) == KERN_SUCCESS) {
				thread_reference(tp);
				inp->dlth_affinity_tag = tag;
				inp->dlth_affinity = TRUE;
			}
		}
	} else if (inp == dlil_main_input_thread) {
		panic_plain("%s: couldn't create main input thread", __func__);
		/* NOTREACHED */
	} else {
		panic_plain("%s: couldn't create %s input thread", __func__,
		    if_name(ifp));
		/* NOTREACHED */
	}
	OSAddAtomic(1, &cur_dlil_input_threads);

done:
	return error;
}

void
dlil_terminate_input_thread(struct dlil_threading_info *inp)
{
	ifnet_ref_t ifp = inp->dlth_ifp;
	classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);

	VERIFY(current_thread() == inp->dlth_thread);
	VERIFY(inp != dlil_main_input_thread);

	OSAddAtomic(-1, &cur_dlil_input_threads);

#if TEST_INPUT_THREAD_TERMINATION
	{ /* do something useless that won't get optimized away */
		uint32_t        v = 1;
		for (uint32_t i = 0;
		    i < if_input_thread_termination_spin;
		    i++) {
			v = (i + 1) * v;
		}
		DLIL_PRINTF("the value is %d\n", v);
	}
#endif /* TEST_INPUT_THREAD_TERMINATION */

	lck_mtx_lock_spin(&inp->dlth_lock);
	_getq_all(&inp->dlth_pkts, &pkt, NULL, NULL, NULL);
	VERIFY((inp->dlth_flags & DLIL_INPUT_TERMINATE) != 0);
	inp->dlth_flags |= DLIL_INPUT_TERMINATE_COMPLETE;
	wakeup_one((caddr_t)&inp->dlth_flags);
	lck_mtx_unlock(&inp->dlth_lock);

	/* free up pending packets */
	if (pkt.cp_mbuf != NULL) {
		mbuf_freem_list(pkt.cp_mbuf);
	}

	/* for the extra refcnt from kernel_thread_start() */
	thread_deallocate(current_thread());

	if (dlil_verbose) {
		DLIL_PRINTF("%s: input thread terminated\n",
		    if_name(ifp));
	}

	/* this is the end */
	thread_terminate(current_thread());
	/* NOTREACHED */
}

boolean_t
dlil_is_rxpoll_input(thread_continue_t func)
{
	return func == dlil_rxpoll_input_thread_func;
}

errno_t
dlil_input_handler(struct ifnet *ifp, struct mbuf *m_head,
    struct mbuf *m_tail, const struct ifnet_stat_increment_param *s,
    boolean_t poll, struct thread *tp)
{
	dlil_threading_info_ref_t inp = ifp->if_inp;

	if (__improbable(inp == NULL)) {
		inp = dlil_main_input_thread;
	}

#if (DEVELOPMENT || DEBUG)
	if (__improbable(net_thread_is_marked(NET_THREAD_SYNC_RX))) {
		return dlil_input_sync(inp, ifp, m_head, m_tail, s, poll, tp);
	} else
#endif /* (DEVELOPMENT || DEBUG) */
	{
		return inp->dlth_strategy(inp, ifp, m_head, m_tail, s, poll, tp);
	}
}

__private_extern__ void
dlil_input_packet_list(struct ifnet *ifp, struct mbuf *m)
{
	return dlil_input_packet_list_common(ifp, m, 0,
	           IFNET_MODEL_INPUT_POLL_OFF, FALSE);
}

__private_extern__ void
dlil_input_packet_list_extended(struct ifnet *ifp, struct mbuf *m,
    u_int32_t cnt, ifnet_model_t mode)
{
	return dlil_input_packet_list_common(ifp, m, cnt, mode, TRUE);
}

/*
 * Static function implementations.
 */
static void
dlil_ifproto_input(struct if_proto * ifproto, mbuf_ref_t m)
{
	int error;

	if (ifproto->proto_kpi == kProtoKPI_v1) {
		/* Version 1 protocols get one packet at a time */
		while (m != NULL) {
			/*
			 * Version 1 KPI does not accept header len,
			 * hence the pointer to the frame header must be `__single'.
			 */
			char *frame_header_ptr __single;

			mbuf_t next_packet;

			next_packet = m->m_nextpkt;
			m->m_nextpkt = NULL;
			frame_header_ptr = m->m_pkthdr.pkt_hdr;

			m->m_pkthdr.pkt_hdr = NULL;
			error = (*ifproto->kpi.v1.input)(ifproto->ifp,
			    ifproto->protocol_family, m, frame_header_ptr);
			if (error != 0 && error != EJUSTRETURN) {
				m_drop_if(m, ifproto->ifp, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_IF_FILTER, NULL, 0);
			}
			m = next_packet;
		}
	} else if (ifproto->proto_kpi == kProtoKPI_v2) {
		/* Version 2 protocols support packet lists */
		error = (*ifproto->kpi.v2.input)(ifproto->ifp,
		    ifproto->protocol_family, m);
		if (error != 0 && error != EJUSTRETURN) {
			m_drop_list(m, ifproto->ifp, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_IF_FILTER, NULL, 0);
		}
	}
}

static errno_t
dlil_input_async(struct dlil_threading_info *inp,
    struct ifnet *ifp, struct mbuf *m_head, struct mbuf *m_tail,
    const struct ifnet_stat_increment_param *s, boolean_t poll,
    struct thread *tp)
{
	u_int32_t m_cnt = s->packets_in;
	u_int32_t m_size = s->bytes_in;
	boolean_t notify = FALSE;
	struct ifnet_stat_increment_param s_adj = *s;
	dlil_freeq_t freeq;
	MBUFQ_INIT(&freeq);

	/*
	 * If there is a matching DLIL input thread associated with an
	 * affinity set, associate this thread with the same set.  We
	 * will only do this once.
	 */
	lck_mtx_lock_spin(&inp->dlth_lock);
	if (inp != dlil_main_input_thread && inp->dlth_affinity && tp != NULL &&
	    ((!poll && inp->dlth_driver_thread == THREAD_NULL) ||
	    (poll && inp->dlth_poller_thread == THREAD_NULL))) {
		u_int32_t tag = inp->dlth_affinity_tag;

		if (poll) {
			VERIFY(inp->dlth_poller_thread == THREAD_NULL);
			inp->dlth_poller_thread = tp;
		} else {
			VERIFY(inp->dlth_driver_thread == THREAD_NULL);
			inp->dlth_driver_thread = tp;
		}
		lck_mtx_unlock(&inp->dlth_lock);

		/* Associate the current thread with the new affinity tag */
		(void) dlil_affinity_set(tp, tag);

		/*
		 * Take a reference on the current thread; during detach,
		 * we will need to refer to it in order to tear down its
		 * affinity.
		 */
		thread_reference(tp);
		lck_mtx_lock_spin(&inp->dlth_lock);
	}

	VERIFY(m_head != NULL || (m_tail == NULL && m_cnt == 0));

	/*
	 * Because of loopbacked multicast we cannot stuff the ifp in
	 * the rcvif of the packet header: loopback (lo0) packets use a
	 * dedicated list so that we can later associate them with lo_ifp
	 * on their way up the stack.  Packets for other interfaces without
	 * dedicated input threads go to the regular list.
	 */
	if (m_head != NULL) {
		classq_pkt_t head, tail;
		class_queue_t *input_queue;
		CLASSQ_PKT_INIT_MBUF(&head, m_head);
		CLASSQ_PKT_INIT_MBUF(&tail, m_tail);
		if (inp == dlil_main_input_thread && ifp == lo_ifp) {
			dlil_main_threading_info_ref_t inpm =
			    __container_of(inp, struct dlil_main_threading_info, inp);
			input_queue = &inpm->lo_rcvq_pkts;
		} else {
			input_queue = &inp->dlth_pkts;
		}

		_addq_multi(input_queue, &head, &tail, m_cnt, m_size);

		if (MBUF_QUEUE_IS_OVERCOMMITTED(input_queue)) {
			dlil_trim_overcomitted_queue_locked(input_queue, &freeq, &s_adj);
			inp->dlth_trim_pkts_dropped += s_adj.dropped;
			inp->dlth_trim_cnt += 1;

			os_log_error(OS_LOG_DEFAULT,
			    "%s %s burst limit %u (sysctl: %u) exceeded. "
			    "%u packets dropped [%u total in %u events]. new qlen %u ",
			    __func__, if_name(ifp), qlimit(input_queue), if_rcvq_burst_limit,
			    s_adj.dropped, inp->dlth_trim_pkts_dropped, inp->dlth_trim_cnt,
			    qlen(input_queue));
		}
	}

#if IFNET_INPUT_SANITY_CHK
	/*
	 * Verify that the original stat increment parameter
	 * accurately describes the input chain `m_head`.
	 * This is not affected by the trimming of input queue.
	 */
	if (__improbable(dlil_input_sanity_check != 0)) {
		u_int32_t count = 0, size = 0;
		struct mbuf *m0;

		for (m0 = m_head; m0; m0 = mbuf_nextpkt(m0)) {
			m_add_hdr_crumb_interface_input(m0, ifp->if_index, false);
			size += m_length(m0);
			count++;
		}

		if (count != m_cnt) {
			panic_plain("%s: invalid total packet count %u "
			    "(expected %u)\n", if_name(ifp), count, m_cnt);
			/* NOTREACHED */
			__builtin_unreachable();
		} else if (size != m_size) {
			panic_plain("%s: invalid total packet size %u "
			    "(expected %u)\n", if_name(ifp), size, m_size);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		inp->dlth_pkts_cnt += m_cnt;
	}
#else
	m_add_hdr_crumb_interface_input(m_head, ifp->if_index, true);
#endif /* IFNET_INPUT_SANITY_CHK */

	/* NOTE: use the adjusted parameter, vs the original one */
	dlil_input_stats_add(&s_adj, inp, ifp, poll);
	/*
	 * If we're using the main input thread, synchronize the
	 * stats now since we have the interface context.  All
	 * other cases involving dedicated input threads will
	 * have their stats synchronized there.
	 */
	if (inp == dlil_main_input_thread) {
		notify = dlil_input_stats_sync(ifp, inp);
	}

	dlil_input_wakeup(inp);
	lck_mtx_unlock(&inp->dlth_lock);

	/*
	 * Actual freeing of the excess packets must happen
	 * after the dlth_lock had been released.
	 */
	if (!MBUFQ_EMPTY(&freeq)) {
		m_drop_list(MBUFQ_FIRST(&freeq), ifp, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_BURST_LIMIT, NULL, 0);
	}

	if (notify) {
		ifnet_notify_data_threshold(ifp);
	}

	return 0;
}

static errno_t
dlil_input_sync(struct dlil_threading_info *inp,
    struct ifnet *ifp, struct mbuf *m_head, struct mbuf *m_tail,
    const struct ifnet_stat_increment_param *s, boolean_t poll,
    struct thread *tp)
{
#pragma unused(tp)
	u_int32_t m_cnt = s->packets_in;
	u_int32_t m_size = s->bytes_in;
	boolean_t notify = FALSE;
	classq_pkt_t head, tail;
	struct ifnet_stat_increment_param s_adj = *s;
	dlil_freeq_t freeq;
	MBUFQ_INIT(&freeq);

	ASSERT(inp != dlil_main_input_thread);

	/* XXX: should we just assert instead? */
	if (__improbable(m_head == NULL)) {
		return 0;
	}

	CLASSQ_PKT_INIT_MBUF(&head, m_head);
	CLASSQ_PKT_INIT_MBUF(&tail, m_tail);

	lck_mtx_lock_spin(&inp->dlth_lock);
	_addq_multi(&inp->dlth_pkts, &head, &tail, m_cnt, m_size);

	if (MBUF_QUEUE_IS_OVERCOMMITTED(&inp->dlth_pkts)) {
		dlil_trim_overcomitted_queue_locked(&inp->dlth_pkts, &freeq, &s_adj);
		inp->dlth_trim_pkts_dropped += s_adj.dropped;
		inp->dlth_trim_cnt += 1;

		os_log_error(OS_LOG_DEFAULT,
		    "%s %s burst limit %u (sysctl: %u) exceeded. "
		    "%u packets dropped [%u total in %u events]. new qlen %u \n",
		    __func__, if_name(ifp), qlimit(&inp->dlth_pkts), if_rcvq_burst_limit,
		    s_adj.dropped, inp->dlth_trim_pkts_dropped, inp->dlth_trim_cnt,
		    qlen(&inp->dlth_pkts));
	}

#if IFNET_INPUT_SANITY_CHK
	if (__improbable(dlil_input_sanity_check != 0)) {
		u_int32_t count = 0, size = 0;
		struct mbuf *m0;

		for (m0 = m_head; m0; m0 = mbuf_nextpkt(m0)) {
			m_add_hdr_crumb_interface_input(m0, ifp->if_index, false);
			size += m_length(m0);
			count++;
		}

		if (count != m_cnt) {
			panic_plain("%s: invalid total packet count %u "
			    "(expected %u)\n", if_name(ifp), count, m_cnt);
			/* NOTREACHED */
			__builtin_unreachable();
		} else if (size != m_size) {
			panic_plain("%s: invalid total packet size %u "
			    "(expected %u)\n", if_name(ifp), size, m_size);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		inp->dlth_pkts_cnt += m_cnt;
	}
#else
	m_add_hdr_crumb_interface_input(m_head, ifp->if_index, true);
#endif /* IFNET_INPUT_SANITY_CHK */

	/* NOTE: use the adjusted parameter, vs the original one */
	dlil_input_stats_add(&s_adj, inp, ifp, poll);

	m_cnt = qlen(&inp->dlth_pkts);
	_getq_all(&inp->dlth_pkts, &head, NULL, NULL, NULL);

#if SKYWALK
	/*
	 * If this interface is attached to a netif nexus,
	 * the stats are already incremented there; otherwise
	 * do it here.
	 */
	if (!(ifp->if_capabilities & IFCAP_SKYWALK))
#endif /* SKYWALK */
	notify = dlil_input_stats_sync(ifp, inp);

	lck_mtx_unlock(&inp->dlth_lock);

	/*
	 * Actual freeing of the excess packets must happen
	 * after the dlth_lock had been released.
	 */
	if (!MBUFQ_EMPTY(&freeq)) {
		m_drop_list(MBUFQ_FIRST(&freeq), ifp, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_BURST_LIMIT, NULL, 0);
	}

	if (notify) {
		ifnet_notify_data_threshold(ifp);
	}

	/*
	 * NOTE warning %%% attention !!!!
	 * We should think about putting some thread starvation
	 * safeguards if we deal with long chains of packets.
	 */
	if (head.cp_mbuf != NULL) {
		dlil_input_packet_list_extended(ifp, head.cp_mbuf,
		    m_cnt, ifp->if_poll_mode);
	}

	return 0;
}

static void
dlil_input_cksum_dbg(struct ifnet *ifp, struct mbuf *m, char *frame_header,
    protocol_family_t pf)
{
	uint16_t sum = 0;
	uint32_t hlen;

	if (frame_header == NULL ||
	    frame_header < (char *)mbuf_datastart(m) ||
	    frame_header > (char *)m->m_data) {
		DLIL_PRINTF("%s: frame header pointer 0x%llx out of range "
		    "[0x%llx,0x%llx] for mbuf 0x%llx\n", if_name(ifp),
		    (uint64_t)VM_KERNEL_ADDRPERM(frame_header),
		    (uint64_t)VM_KERNEL_ADDRPERM(mbuf_datastart(m)),
		    (uint64_t)VM_KERNEL_ADDRPERM(m->m_data),
		    (uint64_t)VM_KERNEL_ADDRPERM(m));
		return;
	}
	hlen = (uint32_t)(m->m_data - (uintptr_t)frame_header);

	switch (pf) {
	case PF_INET:
	case PF_INET6:
		break;
	default:
		return;
	}

	/*
	 * Force partial checksum offload; useful to simulate cases
	 * where the hardware does not support partial checksum offload,
	 * in order to validate correctness throughout the layers above.
	 */
	if (hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED) {
		uint32_t foff = hwcksum_dbg_partial_rxoff_forced;

		if (foff > (uint32_t)m->m_pkthdr.len) {
			return;
		}

		m->m_pkthdr.csum_flags &= ~CSUM_RX_FLAGS;

		/* Compute 16-bit 1's complement sum from forced offset */
		sum = m_sum16(m, foff, (m->m_pkthdr.len - foff));

		m->m_pkthdr.csum_flags |= (CSUM_DATA_VALID | CSUM_PARTIAL);
		m->m_pkthdr.csum_rx_val = sum;
		m->m_pkthdr.csum_rx_start = (uint16_t)(foff + hlen);

		hwcksum_dbg_partial_forced++;
		hwcksum_dbg_partial_forced_bytes += m->m_pkthdr.len;
	}

	/*
	 * Partial checksum offload verification (and adjustment);
	 * useful to validate and test cases where the hardware
	 * supports partial checksum offload.
	 */
	if ((m->m_pkthdr.csum_flags &
	    (CSUM_DATA_VALID | CSUM_PARTIAL | CSUM_PSEUDO_HDR)) ==
	    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
		uint32_t rxoff;

		/* Start offset must begin after frame header */
		rxoff = m->m_pkthdr.csum_rx_start;
		if (hlen > rxoff) {
			hwcksum_dbg_bad_rxoff++;
			if (dlil_verbose) {
				DLIL_PRINTF("%s: partial cksum start offset %d "
				    "is less than frame header length %d for "
				    "mbuf 0x%llx\n", if_name(ifp), rxoff, hlen,
				    (uint64_t)VM_KERNEL_ADDRPERM(m));
			}
			return;
		}
		rxoff -= hlen;

		if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED)) {
			/*
			 * Compute the expected 16-bit 1's complement sum;
			 * skip this if we've already computed it above
			 * when partial checksum offload is forced.
			 */
			sum = m_sum16(m, rxoff, (m->m_pkthdr.len - rxoff));

			/* Hardware or driver is buggy */
			if (sum != m->m_pkthdr.csum_rx_val) {
				hwcksum_dbg_bad_cksum++;
				if (dlil_verbose) {
					DLIL_PRINTF("%s: bad partial cksum value "
					    "0x%x (expected 0x%x) for mbuf "
					    "0x%llx [rx_start %d]\n",
					    if_name(ifp),
					    m->m_pkthdr.csum_rx_val, sum,
					    (uint64_t)VM_KERNEL_ADDRPERM(m),
					    m->m_pkthdr.csum_rx_start);
				}
				return;
			}
		}
		hwcksum_dbg_verified++;

		/*
		 * This code allows us to emulate various hardwares that
		 * perform 16-bit 1's complement sum beginning at various
		 * start offset values.
		 */
		if (hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_RXOFF_ADJ) {
			uint32_t aoff = hwcksum_dbg_partial_rxoff_adj;

			if (aoff == rxoff || aoff > (uint32_t)m->m_pkthdr.len) {
				return;
			}

			sum = m_adj_sum16(m, rxoff, aoff,
			    m_pktlen(m) - aoff, sum);

			m->m_pkthdr.csum_rx_val = sum;
			m->m_pkthdr.csum_rx_start = (uint16_t)(aoff + hlen);

			hwcksum_dbg_adjusted++;
		}
	}
}

static void
dlil_input_packet_list_common(struct ifnet *ifp_param, mbuf_ref_t m,
    u_int32_t cnt, ifnet_model_t mode, boolean_t ext)
{
	int error = 0;
	protocol_family_t protocol_family;
	mbuf_t next_packet;
	ifnet_t ifp = ifp_param;
	char *__single frame_header = NULL;
	if_proto_ref_t last_ifproto = NULL;
	mbuf_t pkt_first = NULL;
	mbuf_t *pkt_next = NULL;
	u_int32_t poll_thresh = 0, poll_ival = 0;
	int iorefcnt = 0;
	boolean_t skip_bridge_filter = FALSE;

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_START, 0, 0, 0, 0, 0);

	if (ext && mode == IFNET_MODEL_INPUT_POLL_ON && cnt > 1 &&
	    (poll_ival = if_rxpoll_interval_pkts) > 0) {
		poll_thresh = cnt;
	}
	if (bridge_enable_early_input != 0 &&
	    ifp != NULL && ifp->if_bridge != NULL) {
		m = handle_bridge_early_input(ifp, m, cnt);
		skip_bridge_filter = TRUE;
	}
	while (m != NULL) {
		if_proto_ref_t ifproto = NULL;
		uint32_t pktf_mask;     /* pkt flags to preserve */

		m_add_crumb(m, PKT_CRUMB_DLIL_INPUT);
		m_add_hdr_crumb_interface_input(m, ifp->if_index, false);

		if (ifp_param == NULL) {
			ifp = m->m_pkthdr.rcvif;
		}

		if ((ifp->if_eflags & IFEF_RXPOLL) &&
		    (ifp->if_xflags & IFXF_LEGACY) && poll_thresh != 0 &&
		    poll_ival > 0 && (--poll_thresh % poll_ival) == 0) {
			ifnet_poll(ifp);
		}

		/* Check if this mbuf looks valid */
		MBUF_INPUT_CHECK(m, ifp);

		next_packet = m->m_nextpkt;
		m->m_nextpkt = NULL;
		frame_header = m->m_pkthdr.pkt_hdr;
		m->m_pkthdr.pkt_hdr = NULL;

		/*
		 * Get an IO reference count if the interface is not
		 * loopback (lo0) and it is attached; lo0 never goes
		 * away, so optimize for that.
		 */
		if (ifp != lo_ifp) {
			/* iorefcnt is 0 if it hasn't been taken yet */
			if (iorefcnt == 0) {
				if (!ifnet_datamov_begin(ifp)) {
					m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_IF_DATAMOV_BEGIN, NULL, 0);
					goto next;
				}
			}
			iorefcnt = 1;
			/*
			 * Preserve the time stamp and skip pktap flags.
			 */
			pktf_mask = PKTF_TS_VALID | PKTF_SKIP_PKTAP;
		} else {
			/*
			 * If this arrived on lo0, preserve interface addr
			 * info to allow for connectivity between loopback
			 * and local interface addresses.
			 */
			pktf_mask = (PKTF_LOOP | PKTF_IFAINFO);
		}
		pktf_mask |= PKTF_WAKE_PKT;

		/* make sure packet comes in clean */
		m_classifier_init(m, pktf_mask);

		ifp_inc_traffic_class_in(ifp, m);

		/* find which protocol family this packet is for */
		ifnet_lock_shared(ifp);
		error = (*ifp->if_demux)(ifp, m, frame_header,
		    &protocol_family);
		ifnet_lock_done(ifp);
		if (error != 0) {
			if (error == EJUSTRETURN) {
				goto next;
			}
			protocol_family = 0;
		}
		/* check for an updated frame header */
		if (m->m_pkthdr.pkt_hdr != NULL) {
			frame_header = m->m_pkthdr.pkt_hdr;
			m->m_pkthdr.pkt_hdr = NULL;
		}

#if (DEVELOPMENT || DEBUG)
		/*
		 * For testing we do not care about broadcast and multicast packets as
		 * they are not as controllable as unicast traffic
		 */
		if (__improbable(ifp->if_xflags & IFXF_MARK_WAKE_PKT)) {
			if ((protocol_family == PF_INET || protocol_family == PF_INET6) &&
			    (m->m_flags & (M_BCAST | M_MCAST)) == 0) {
				/*
				 * This is a one-shot command
				 */
				ifp->if_xflags &= ~IFXF_MARK_WAKE_PKT;
				m->m_pkthdr.pkt_flags |= PKTF_WAKE_PKT;
			}
		}
#endif /* (DEVELOPMENT || DEBUG) */
		if (__improbable(net_wake_pkt_debug > 0 && (m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT))) {
			char buffer[64];
			size_t buflen = MIN(mbuf_pkthdr_len(m), sizeof(buffer));

			os_log(OS_LOG_DEFAULT, "wake packet from %s len %d",
			    ifp->if_xname, m_pktlen(m));
			if (mbuf_copydata(m, 0, buflen, buffer) == 0) {
				log_hexdump(buffer, buflen);
			}
		}

		pktap_input(ifp, protocol_family, m, frame_header);

		/* Drop v4 packets received on CLAT46 enabled cell interface */
		if (protocol_family == PF_INET && IS_INTF_CLAT46(ifp) &&
		    ifp->if_type == IFT_CELLULAR) {
			m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_CLAT64, NULL, 0);
			ip6stat.ip6s_clat464_in_v4_drop++;
			goto next;
		}

		/* Translate the packet if it is received on CLAT interface */
		if ((m->m_flags & M_PROMISC) == 0 &&
		    protocol_family == PF_INET6 &&
		    IS_INTF_CLAT46(ifp) &&
		    dlil_is_clat_needed(protocol_family, m)) {
			char *data = NULL;
			struct ether_header eh;
			struct ether_header *ehp = NULL;

			if (ifp->if_type == IFT_ETHER) {
				ehp = (struct ether_header *)(void *)frame_header;
				/* Skip RX Ethernet packets if they are not IPV6 */
				if (ntohs(ehp->ether_type) != ETHERTYPE_IPV6) {
					goto skip_clat;
				}

				/* Keep a copy of frame_header for Ethernet packets */
				char *fh = __unsafe_forge_bidi_indexable(char *, m->m_pkthdr.pkt_hdr, ifnet_hdrlen(ifp));
				if (fh) {
					bcopy(fh, (caddr_t)&eh, ETHER_HDR_LEN);
				}
			}
			error = dlil_clat64(ifp, &protocol_family, &m);
			data = mtod(m, char*);
			if (error != 0) {
				m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_CLAT64, NULL, 0);
				ip6stat.ip6s_clat464_in_drop++;
				goto next;
			}
			/* Native v6 should be No-op */
			if (protocol_family != PF_INET) {
				goto skip_clat;
			}

			/* Do this only for translated v4 packets. */
			switch (ifp->if_type) {
			case IFT_CELLULAR:
				frame_header = data;
				break;
			case IFT_ETHER:
				/*
				 * Drop if the mbuf doesn't have enough
				 * space for Ethernet header
				 */
				if (M_LEADINGSPACE(m) < ETHER_HDR_LEN) {
					m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_CLAT64, NULL, 0);
					ip6stat.ip6s_clat464_in_drop++;
					goto next;
				}
				/*
				 * Set the frame_header ETHER_HDR_LEN bytes
				 * preceeding the data pointer. Change
				 * the ether_type too.
				 * N.B. The variable `fh' is needed because
				 * the `frame_header' variable is `__single',
				 * and hence would not be appropriate for use with `bcopy'.
				 */
				char *fh = data - ETHER_HDR_LEN;
				frame_header = fh;
				eh.ether_type = htons(ETHERTYPE_IP);
				bcopy((caddr_t)&eh, fh, ETHER_HDR_LEN);
				break;
			}
		}
skip_clat:
		/*
		 * Match the wake packet against the list of ports that has been
		 * been queried by the driver before the device went to sleep
		 */
		if (__improbable(m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT)) {
			if (protocol_family != PF_INET && protocol_family != PF_INET6) {
				if_ports_used_match_mbuf(ifp, protocol_family, m);
			}
		}
		if (hwcksum_dbg != 0 && !(ifp->if_flags & IFF_LOOPBACK) &&
		    !(m->m_pkthdr.pkt_flags & PKTF_LOOP)) {
			dlil_input_cksum_dbg(ifp, m, frame_header,
			    protocol_family);
		}
		/*
		 * For partial checksum offload, we expect the driver to
		 * set the start offset indicating the start of the span
		 * that is covered by the hardware-computed checksum;
		 * adjust this start offset accordingly because the data
		 * pointer has been advanced beyond the link-layer header.
		 *
		 * Virtual lan types (bridge, vlan, bond) can call
		 * dlil_input_packet_list() with the same packet with the
		 * checksum flags set. Set a flag indicating that the
		 * adjustment has already been done.
		 */
		if ((m->m_pkthdr.csum_flags & CSUM_ADJUST_DONE) != 0) {
			/* adjustment has already been done */
		} else if ((m->m_pkthdr.csum_flags &
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) ==
		    (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			int adj;
			if (frame_header == NULL ||
			    frame_header < (char *)mbuf_datastart(m) ||
			    frame_header > (char *)m->m_data ||
			    (adj = (int)(m->m_data - (uintptr_t)frame_header)) >
			    m->m_pkthdr.csum_rx_start) {
				m->m_pkthdr.csum_data = 0;
				m->m_pkthdr.csum_flags &= ~CSUM_DATA_VALID;
				hwcksum_in_invalidated++;
			} else {
				m->m_pkthdr.csum_rx_start -= adj;
			}
			/* make sure we don't adjust more than once */
			m->m_pkthdr.csum_flags |= CSUM_ADJUST_DONE;
		}
		if (clat_debug) {
			pktap_input(ifp, protocol_family, m, frame_header);
		}

		if (m->m_flags & (M_BCAST | M_MCAST)) {
			os_atomic_inc(&ifp->if_imcasts, relaxed);
		}

		/* run interface filters */
		error = dlil_interface_filters_input(ifp, &m,
		    &frame_header, protocol_family, skip_bridge_filter);
		if (error != 0) {
			if (error != EJUSTRETURN) {
				m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_IF_FILTER, NULL, 0);
			}
			goto next;
		}
		/*
		 * A VLAN and Bond interface receives packets by attaching
		 * a "protocol" to the underlying interface.
		 * A promiscuous packet needs to be delivered to the
		 * VLAN or Bond interface since:
		 * - Bond interface member may not support setting the
		 *   MAC address, so packets are inherently "promiscuous"
		 * - A VLAN or Bond interface could be members of a bridge,
		 *   where promiscuous packets correspond to other
		 *   devices that the bridge forwards packets to/from
		 */
		if ((m->m_flags & M_PROMISC) != 0) {
			switch (protocol_family) {
			case PF_VLAN:
			case PF_BOND:
				/* VLAN and Bond get promiscuous packets */
				break;
			default:
				if (droptap_verbose > 0) {
					m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_PROMISC, NULL, 0);
				} else {
					m_freem(m);
				}
				goto next;
			}
		}

		/* Lookup the protocol attachment to this interface */
		if (protocol_family == 0) {
			ifproto = NULL;
		} else if (last_ifproto != NULL && last_ifproto->ifp == ifp &&
		    (last_ifproto->protocol_family == protocol_family)) {
			VERIFY(ifproto == NULL);
			ifproto = last_ifproto;
			if_proto_ref(last_ifproto);
		} else {
			VERIFY(ifproto == NULL);
			ifnet_lock_shared(ifp);
			/* callee holds a proto refcnt upon success */
			ifproto = find_attached_proto(ifp, protocol_family);
			ifnet_lock_done(ifp);
		}
		if (ifproto == NULL) {
			/* no protocol for this packet, discard */
			m_drop(m, DROPTAP_FLAG_DIR_IN, DROP_REASON_DLIL_NO_PROTO, NULL, 0);
			goto next;
		}
		if (ifproto != last_ifproto) {
			if (last_ifproto != NULL) {
				/* pass up the list for the previous protocol */
				dlil_ifproto_input(last_ifproto, pkt_first);
				pkt_first = NULL;
				if_proto_free(last_ifproto);
			}
			last_ifproto = ifproto;
			if_proto_ref(ifproto);
		}
		/* extend the list */
		m->m_pkthdr.pkt_hdr = frame_header;
		if (pkt_first == NULL) {
			pkt_first = m;
		} else {
			*pkt_next = m;
		}
		pkt_next = &m->m_nextpkt;

next:
		if (next_packet == NULL && last_ifproto != NULL) {
			/* pass up the last list of packets */
			dlil_ifproto_input(last_ifproto, pkt_first);
			if_proto_free(last_ifproto);
			last_ifproto = NULL;
		}
		if (ifproto != NULL) {
			if_proto_free(ifproto);
			ifproto = NULL;
		}

		m = next_packet;

		/* update the driver's multicast filter, if needed */
		if (ifp->if_updatemcasts > 0 && if_mcasts_update(ifp) == 0) {
			ifp->if_updatemcasts = 0;
		}
		if (iorefcnt == 1) {
			/* If the next mbuf is on a different interface, unlock data-mov */
			if (!m || (ifp != ifp_param && ifp != m->m_pkthdr.rcvif)) {
				ifnet_datamov_end(ifp);
				iorefcnt = 0;
			}
		}
	}

	KERNEL_DEBUG(DBG_FNC_DLIL_INPUT | DBG_FUNC_END, 0, 0, 0, 0, 0);
}

/*
 * Input thread for interfaces with legacy input model.
 */
__attribute__((noreturn))
static void
dlil_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	char thread_name_storage[MAXTHREADNAMESIZE];
	const char *__null_terminated thread_name;
	dlil_threading_info_ref_t inp = v;
	ifnet_ref_t ifp = inp->dlth_ifp;

	VERIFY(inp != dlil_main_input_thread);
	VERIFY(ifp != NULL);
	VERIFY(!(ifp->if_eflags & IFEF_RXPOLL) || !net_rxpoll ||
	    !(ifp->if_xflags & IFXF_LEGACY));
	VERIFY(ifp->if_poll_mode == IFNET_MODEL_INPUT_POLL_OFF ||
	    !(ifp->if_xflags & IFXF_LEGACY));
	VERIFY(current_thread() == inp->dlth_thread);

	/* construct the name for this thread, and then apply it */
	bzero(thread_name_storage, sizeof(thread_name_storage));
	thread_name = tsnprintf(thread_name_storage, sizeof(thread_name_storage),
	    "dlil_input_%s", ifp->if_xname);
	thread_set_thread_name(inp->dlth_thread, thread_name);

	lck_mtx_lock(&inp->dlth_lock);
	VERIFY(!(inp->dlth_flags & (DLIL_INPUT_EMBRYONIC | DLIL_INPUT_RUNNING)));
	(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
	inp->dlth_flags |= DLIL_INPUT_EMBRYONIC;
	/* wake up once to get out of embryonic state */
	dlil_input_wakeup(inp);
	lck_mtx_unlock(&inp->dlth_lock);
	(void) thread_block_parameter(dlil_input_thread_cont, inp);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static void
dlil_input_thread_cont(void *v, wait_result_t wres)
{
	dlil_threading_info_ref_t inp = v;
	ifnet_ref_t ifp = inp->dlth_ifp;

	lck_mtx_lock_spin(&inp->dlth_lock);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (inp->dlth_flags & DLIL_INPUT_TERMINATE))) {
		goto terminate;
	}

	VERIFY(!(inp->dlth_flags & DLIL_INPUT_RUNNING));
	inp->dlth_flags |= DLIL_INPUT_RUNNING;

	while (1) {
		struct mbuf *m = NULL;
		classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);
		boolean_t notify = FALSE;
		boolean_t embryonic;
		u_int32_t m_cnt;

		inp->dlth_flags &= ~DLIL_INPUT_WAITING;

		if (__improbable(embryonic =
		    (inp->dlth_flags & DLIL_INPUT_EMBRYONIC))) {
			inp->dlth_flags &= ~DLIL_INPUT_EMBRYONIC;
		}

		/*
		 * Protocol registration and injection must always use
		 * the main input thread; in theory the latter can utilize
		 * the corresponding input thread where the packet arrived
		 * on, but that requires our knowing the interface in advance
		 * (and the benefits might not worth the trouble.)
		 */
		VERIFY(!(inp->dlth_flags &
		    (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER)));

		/* Packets for this interface */
		m_cnt = qlen(&inp->dlth_pkts);
		_getq_all(&inp->dlth_pkts, &pkt, NULL, NULL, NULL);
		m = pkt.cp_mbuf;

		inp->dlth_wtot = 0;

#if SKYWALK
		/*
		 * If this interface is attached to a netif nexus,
		 * the stats are already incremented there; otherwise
		 * do it here.
		 */
		if (!(ifp->if_capabilities & IFCAP_SKYWALK))
#endif /* SKYWALK */
		notify = dlil_input_stats_sync(ifp, inp);

		lck_mtx_unlock(&inp->dlth_lock);

		if (__improbable(embryonic)) {
			ifnet_decr_pending_thread_count(ifp);
		}

		if (__improbable(notify)) {
			ifnet_notify_data_threshold(ifp);
		}

		/*
		 * NOTE warning %%% attention !!!!
		 * We should think about putting some thread starvation
		 * safeguards if we deal with long chains of packets.
		 */
		if (__probable(m != NULL)) {
			dlil_input_packet_list_extended(ifp, m,
			    m_cnt, ifp->if_poll_mode);
		}

		lck_mtx_lock_spin(&inp->dlth_lock);
		VERIFY(inp->dlth_flags & DLIL_INPUT_RUNNING);
		if (!(inp->dlth_flags & ~(DLIL_INPUT_RUNNING |
		    DLIL_INPUT_TERMINATE))) {
			break;
		}
	}

	inp->dlth_flags &= ~DLIL_INPUT_RUNNING;

	if (__improbable(inp->dlth_flags & DLIL_INPUT_TERMINATE)) {
terminate:
		lck_mtx_unlock(&inp->dlth_lock);
		dlil_terminate_input_thread(inp);
		/* NOTREACHED */
	} else {
		(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
		lck_mtx_unlock(&inp->dlth_lock);
		(void) thread_block_parameter(dlil_input_thread_cont, inp);
		/* NOTREACHED */
	}

	VERIFY(0);      /* we should never get here */
	/* NOTREACHED */
	__builtin_unreachable();
}

static inline void
dlil_input_wakeup(struct dlil_threading_info *inp)
{
	LCK_MTX_ASSERT(&inp->dlth_lock, LCK_MTX_ASSERT_OWNED);

	inp->dlth_flags |= DLIL_INPUT_WAITING;
	if (!(inp->dlth_flags & DLIL_INPUT_RUNNING)) {
		inp->dlth_wtot++;
		wakeup_one((caddr_t)&inp->dlth_flags);
	}
}

static int
dlil_interface_filters_input(struct ifnet *ifp, mbuf_ref_ref_t m_p,
    char **frame_header_p, protocol_family_t protocol_family,
    boolean_t skip_bridge)
{
	boolean_t               is_vlan_packet = FALSE;
	struct ifnet_filter     *filter;
	struct mbuf             *m = *m_p;

	is_vlan_packet = packet_has_vlan_tag(m);

	if (TAILQ_EMPTY(&ifp->if_flt_head)) {
		return 0;
	}

	/*
	 * Pass the inbound packet to the interface filters
	 */
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	/* prevent filter list from changing in case we drop the lock */
	if_flt_monitor_busy(ifp);
	TAILQ_FOREACH(filter, &ifp->if_flt_head, filt_next) {
		int result;

		/* exclude VLAN packets from external filters PR-3586856 */
		if (is_vlan_packet &&
		    (filter->filt_flags & DLIL_IFF_INTERNAL) == 0) {
			continue;
		}
		/* the bridge has already seen the packet */
		if (skip_bridge &&
		    (filter->filt_flags & DLIL_IFF_BRIDGE) != 0) {
			continue;
		}
		if (!filter->filt_skip && filter->filt_input != NULL &&
		    (filter->filt_protocol == 0 ||
		    filter->filt_protocol == protocol_family)) {
			lck_mtx_unlock(&ifp->if_flt_lock);

			result = (*filter->filt_input)(filter->filt_cookie,
			    ifp, protocol_family, m_p, frame_header_p);

			lck_mtx_lock_spin(&ifp->if_flt_lock);
			if (result != 0) {
				/* we're done with the filter list */
				if_flt_monitor_unbusy(ifp);
				lck_mtx_unlock(&ifp->if_flt_lock);
				return result;
			}
		}
	}
	/* we're done with the filter list */
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	/*
	 * Strip away M_PROTO1 bit prior to sending packet up the stack as
	 * it is meant to be local to a subsystem -- if_bridge for M_PROTO1
	 */
	if (*m_p != NULL) {
		(*m_p)->m_flags &= ~M_PROTO1;
	}

	return 0;
}

__attribute__((noreturn))
static void
dlil_main_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	dlil_threading_info_ref_t inp = v;

	VERIFY(inp == dlil_main_input_thread);
	VERIFY(inp->dlth_ifp == NULL);
	VERIFY(current_thread() == inp->dlth_thread);

	lck_mtx_lock(&inp->dlth_lock);
	VERIFY(!(inp->dlth_flags & (DLIL_INPUT_EMBRYONIC | DLIL_INPUT_RUNNING)));
	(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
	inp->dlth_flags |= DLIL_INPUT_EMBRYONIC;
	/* wake up once to get out of embryonic state */
	dlil_input_wakeup(inp);
	lck_mtx_unlock(&inp->dlth_lock);
	(void) thread_block_parameter(dlil_main_input_thread_cont, inp);
	/* NOTREACHED */
	__builtin_unreachable();
}

/*
 * Main input thread:
 *
 *   a) handles all inbound packets for lo0
 *   b) handles all inbound packets for interfaces with no dedicated
 *	input thread (e.g. anything but Ethernet/PDP or those that support
 *	opportunistic polling.)
 *   c) protocol registrations
 *   d) packet injections
 */
__attribute__((noreturn))
static void
dlil_main_input_thread_cont(void *v, wait_result_t wres)
{
	dlil_main_threading_info_ref_t inpm = v;
	dlil_threading_info_ref_t inp = v;

	/* main input thread is uninterruptible */
	VERIFY(wres != THREAD_INTERRUPTED);
	lck_mtx_lock_spin(&inp->dlth_lock);
	VERIFY(!(inp->dlth_flags & (DLIL_INPUT_TERMINATE |
	    DLIL_INPUT_RUNNING)));
	inp->dlth_flags |= DLIL_INPUT_RUNNING;

	while (1) {
		struct mbuf *m = NULL, *m_loop = NULL;
		u_int32_t m_cnt, m_cnt_loop;
		classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);
		boolean_t proto_req;
		boolean_t embryonic;

		inp->dlth_flags &= ~DLIL_INPUT_WAITING;

		if (__improbable(embryonic =
		    (inp->dlth_flags & DLIL_INPUT_EMBRYONIC))) {
			inp->dlth_flags &= ~DLIL_INPUT_EMBRYONIC;
		}

		proto_req = (inp->dlth_flags &
		    (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER));

		/* Packets for non-dedicated interfaces other than lo0 */
		m_cnt = qlen(&inp->dlth_pkts);
		_getq_all(&inp->dlth_pkts, &pkt, NULL, NULL, NULL);
		m = pkt.cp_mbuf;

		/* Packets exclusive to lo0 */
		m_cnt_loop = qlen(&inpm->lo_rcvq_pkts);
		_getq_all(&inpm->lo_rcvq_pkts, &pkt, NULL, NULL, NULL);
		m_loop = pkt.cp_mbuf;

		inp->dlth_wtot = 0;

		lck_mtx_unlock(&inp->dlth_lock);

		if (__improbable(embryonic)) {
			dlil_decr_pending_thread_count();
		}

		/*
		 * NOTE warning %%% attention !!!!
		 * We should think about putting some thread starvation
		 * safeguards if we deal with long chains of packets.
		 */
		if (__probable(m_loop != NULL)) {
			dlil_input_packet_list_extended(lo_ifp, m_loop,
			    m_cnt_loop, IFNET_MODEL_INPUT_POLL_OFF);
		}

		if (__probable(m != NULL)) {
			dlil_input_packet_list_extended(NULL, m,
			    m_cnt, IFNET_MODEL_INPUT_POLL_OFF);
		}

		if (__improbable(proto_req)) {
			proto_input_run();
		}

		lck_mtx_lock_spin(&inp->dlth_lock);
		VERIFY(inp->dlth_flags & DLIL_INPUT_RUNNING);
		/* main input thread cannot be terminated */
		VERIFY(!(inp->dlth_flags & DLIL_INPUT_TERMINATE));
		if (!(inp->dlth_flags & ~DLIL_INPUT_RUNNING)) {
			break;
		}
	}

	inp->dlth_flags &= ~DLIL_INPUT_RUNNING;
	(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
	lck_mtx_unlock(&inp->dlth_lock);
	(void) thread_block_parameter(dlil_main_input_thread_cont, inp);

	VERIFY(0);      /* we should never get here */
	/* NOTREACHED */
	__builtin_unreachable();
}

/*
 * Input thread for interfaces with opportunistic polling input model.
 */
__attribute__((noreturn))
static void
dlil_rxpoll_input_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	char thread_name_storage[MAXTHREADNAMESIZE];
	const char *__null_terminated thread_name;
	dlil_threading_info_ref_t inp = v;
	ifnet_ref_t ifp = inp->dlth_ifp;

	VERIFY(inp != dlil_main_input_thread);
	VERIFY(ifp != NULL && (ifp->if_eflags & IFEF_RXPOLL) &&
	    (ifp->if_xflags & IFXF_LEGACY));
	VERIFY(current_thread() == inp->dlth_thread);

	/* construct the name for this thread, and then apply it */
	bzero(thread_name_storage, sizeof(thread_name_storage));
	thread_name = tsnprintf(thread_name_storage, sizeof(thread_name_storage),
	    "dlil_input_poll_%s", ifp->if_xname);
	thread_set_thread_name(inp->dlth_thread, thread_name);

	lck_mtx_lock(&inp->dlth_lock);
	VERIFY(!(inp->dlth_flags & (DLIL_INPUT_EMBRYONIC | DLIL_INPUT_RUNNING)));
	(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
	inp->dlth_flags |= DLIL_INPUT_EMBRYONIC;
	/* wake up once to get out of embryonic state */
	dlil_input_wakeup(inp);
	lck_mtx_unlock(&inp->dlth_lock);
	(void) thread_block_parameter(dlil_rxpoll_input_thread_cont, inp);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static void
dlil_rxpoll_input_thread_cont(void *v, wait_result_t wres)
{
	dlil_threading_info_ref_t inp = v;
	ifnet_ref_t ifp = inp->dlth_ifp;
	struct timespec ts;

	lck_mtx_lock_spin(&inp->dlth_lock);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (inp->dlth_flags & DLIL_INPUT_TERMINATE))) {
		goto terminate;
	}

	VERIFY(!(inp->dlth_flags & DLIL_INPUT_RUNNING));
	inp->dlth_flags |= DLIL_INPUT_RUNNING;

	while (1) {
		struct mbuf *m = NULL;
		uint32_t m_cnt, poll_req = 0;
		uint64_t m_size = 0;
		ifnet_model_t mode;
		struct timespec now, delta;
		classq_pkt_t pkt = CLASSQ_PKT_INITIALIZER(pkt);
		boolean_t notify;
		boolean_t embryonic;
		uint64_t ival;

		inp->dlth_flags &= ~DLIL_INPUT_WAITING;

		if (__improbable(embryonic =
		    (inp->dlth_flags & DLIL_INPUT_EMBRYONIC))) {
			inp->dlth_flags &= ~DLIL_INPUT_EMBRYONIC;
			goto skip;
		}

		if ((ival = ifp->if_rxpoll_ival) < IF_RXPOLL_INTERVALTIME_MIN) {
			ival = IF_RXPOLL_INTERVALTIME_MIN;
		}

		/* Link parameters changed? */
		if (ifp->if_poll_update != 0) {
			ifp->if_poll_update = 0;
			(void) dlil_rxpoll_set_params(ifp, NULL, TRUE);
		}

		/* Current operating mode */
		mode = ifp->if_poll_mode;

		/*
		 * Protocol registration and injection must always use
		 * the main input thread; in theory the latter can utilize
		 * the corresponding input thread where the packet arrived
		 * on, but that requires our knowing the interface in advance
		 * (and the benefits might not worth the trouble.)
		 */
		VERIFY(!(inp->dlth_flags &
		    (DLIL_PROTO_WAITING | DLIL_PROTO_REGISTER)));

		/* Total count of all packets */
		m_cnt = qlen(&inp->dlth_pkts);

		/* Total bytes of all packets */
		m_size = qsize(&inp->dlth_pkts);

		/* Packets for this interface */
		_getq_all(&inp->dlth_pkts, &pkt, NULL, NULL, NULL);
		m = pkt.cp_mbuf;
		VERIFY(m != NULL || m_cnt == 0);

		nanouptime(&now);
		if (!net_timerisset(&ifp->if_poll_sample_lasttime)) {
			*(&ifp->if_poll_sample_lasttime) = *(&now);
		}

		net_timersub(&now, &ifp->if_poll_sample_lasttime, &delta);
		if (if_rxpoll && net_timerisset(&ifp->if_poll_sample_holdtime)) {
			u_int32_t ptot, btot;

			/* Accumulate statistics for current sampling */
			PKTCNTR_ADD(&ifp->if_poll_sstats, m_cnt, m_size);

			if (net_timercmp(&delta, &ifp->if_poll_sample_holdtime, <)) {
				goto skip;
			}

			*(&ifp->if_poll_sample_lasttime) = *(&now);

			/* Calculate min/max of inbound bytes */
			btot = (u_int32_t)ifp->if_poll_sstats.bytes;
			if (ifp->if_rxpoll_bmin == 0 || ifp->if_rxpoll_bmin > btot) {
				ifp->if_rxpoll_bmin = btot;
			}
			if (btot > ifp->if_rxpoll_bmax) {
				ifp->if_rxpoll_bmax = btot;
			}

			/* Calculate EWMA of inbound bytes */
			DLIL_EWMA(ifp->if_rxpoll_bavg, btot, if_rxpoll_decay);

			/* Calculate min/max of inbound packets */
			ptot = (u_int32_t)ifp->if_poll_sstats.packets;
			if (ifp->if_rxpoll_pmin == 0 || ifp->if_rxpoll_pmin > ptot) {
				ifp->if_rxpoll_pmin = ptot;
			}
			if (ptot > ifp->if_rxpoll_pmax) {
				ifp->if_rxpoll_pmax = ptot;
			}

			/* Calculate EWMA of inbound packets */
			DLIL_EWMA(ifp->if_rxpoll_pavg, ptot, if_rxpoll_decay);

			/* Reset sampling statistics */
			PKTCNTR_CLEAR(&ifp->if_poll_sstats);

			/* Calculate EWMA of wakeup requests */
			DLIL_EWMA(ifp->if_rxpoll_wavg, inp->dlth_wtot,
			    if_rxpoll_decay);
			inp->dlth_wtot = 0;

			if (dlil_verbose) {
				if (!net_timerisset(&ifp->if_poll_dbg_lasttime)) {
					*(&ifp->if_poll_dbg_lasttime) = *(&now);
				}
				net_timersub(&now, &ifp->if_poll_dbg_lasttime, &delta);
				if (net_timercmp(&delta, &dlil_dbgrate, >=)) {
					*(&ifp->if_poll_dbg_lasttime) = *(&now);
					DLIL_PRINTF("%s: [%s] pkts avg %d max %d "
					    "limits [%d/%d], wreq avg %d "
					    "limits [%d/%d], bytes avg %d "
					    "limits [%d/%d]\n", if_name(ifp),
					    (ifp->if_poll_mode ==
					    IFNET_MODEL_INPUT_POLL_ON) ?
					    "ON" : "OFF", ifp->if_rxpoll_pavg,
					    ifp->if_rxpoll_pmax,
					    ifp->if_rxpoll_plowat,
					    ifp->if_rxpoll_phiwat,
					    ifp->if_rxpoll_wavg,
					    ifp->if_rxpoll_wlowat,
					    ifp->if_rxpoll_whiwat,
					    ifp->if_rxpoll_bavg,
					    ifp->if_rxpoll_blowat,
					    ifp->if_rxpoll_bhiwat);
				}
			}

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
			    (ifp->if_rxpoll_bavg >= ifp->if_rxpoll_bhiwat ||
			    ifp->if_rxpoll_wavg >= ifp->if_rxpoll_whiwat) &&
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
		notify = dlil_input_stats_sync(ifp, inp);

		lck_mtx_unlock(&inp->dlth_lock);

		if (__improbable(embryonic)) {
			ifnet_decr_pending_thread_count(ifp);
		}

		if (__improbable(notify)) {
			ifnet_notify_data_threshold(ifp);
		}

		/*
		 * If there's a mode change and interface is still attached,
		 * perform a downcall to the driver for the new mode.  Also
		 * hold an IO refcnt on the interface to prevent it from
		 * being detached (will be release below.)
		 */
		if (poll_req != 0 && ifnet_is_attached(ifp, 1)) {
			struct ifnet_model_params p = {
				.model = mode, .reserved = { 0 }
			};
			errno_t err;

			if (dlil_verbose) {
				DLIL_PRINTF("%s: polling is now %s, "
				    "pkts avg %d max %d limits [%d/%d], "
				    "wreq avg %d limits [%d/%d], "
				    "bytes avg %d limits [%d/%d]\n",
				    if_name(ifp),
				    (mode == IFNET_MODEL_INPUT_POLL_ON) ?
				    "ON" : "OFF", ifp->if_rxpoll_pavg,
				    ifp->if_rxpoll_pmax, ifp->if_rxpoll_plowat,
				    ifp->if_rxpoll_phiwat, ifp->if_rxpoll_wavg,
				    ifp->if_rxpoll_wlowat, ifp->if_rxpoll_whiwat,
				    ifp->if_rxpoll_bavg, ifp->if_rxpoll_blowat,
				    ifp->if_rxpoll_bhiwat);
			}

			if ((err = ((*ifp->if_input_ctl)(ifp,
			    IFNET_CTL_SET_INPUT_MODEL, sizeof(p), &p))) != 0) {
				DLIL_PRINTF("%s: error setting polling mode "
				    "to %s (%d)\n", if_name(ifp),
				    (mode == IFNET_MODEL_INPUT_POLL_ON) ?
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
				ifnet_poll(ifp);
				ifp->if_rxpoll_onreq++;
				if (err != 0) {
					ifp->if_rxpoll_onerr++;
				}
				break;

			default:
				VERIFY(0);
				/* NOTREACHED */
			}

			/* Release the IO refcnt */
			ifnet_decr_iorefcnt(ifp);
		}

		/*
		 * NOTE warning %%% attention !!!!
		 * We should think about putting some thread starvation
		 * safeguards if we deal with long chains of packets.
		 */
		if (__probable(m != NULL)) {
			dlil_input_packet_list_extended(ifp, m, m_cnt, mode);
		}

		lck_mtx_lock_spin(&inp->dlth_lock);
		VERIFY(inp->dlth_flags & DLIL_INPUT_RUNNING);
		if (!(inp->dlth_flags & ~(DLIL_INPUT_RUNNING |
		    DLIL_INPUT_TERMINATE))) {
			break;
		}
	}

	inp->dlth_flags &= ~DLIL_INPUT_RUNNING;

	if (__improbable(inp->dlth_flags & DLIL_INPUT_TERMINATE)) {
terminate:
		lck_mtx_unlock(&inp->dlth_lock);
		dlil_terminate_input_thread(inp);
		/* NOTREACHED */
	} else {
		(void) assert_wait(&inp->dlth_flags, THREAD_UNINT);
		lck_mtx_unlock(&inp->dlth_lock);
		(void) thread_block_parameter(dlil_rxpoll_input_thread_cont,
		    inp);
		/* NOTREACHED */
	}

	VERIFY(0);      /* we should never get here */
	/* NOTREACHED */
	__builtin_unreachable();
}

static uint32_t
dlil_trim_overcomitted_queue_locked(class_queue_t *input_queue,
    dlil_freeq_t *freeq, struct ifnet_stat_increment_param *stat_delta)
{
	uint32_t overcommitted_qlen;    /* Length in packets. */
	uint64_t overcommitted_qsize;   /* Size in bytes. */
	uint32_t target_qlen;           /* The desired queue length after trimming. */
	uint32_t pkts_to_drop = 0;      /* Number of packets to drop. */
	uint32_t dropped_pkts = 0;      /* Number of packets that were dropped. */
	uint32_t dropped_bytes = 0;     /* Number of dropped bytes. */
	struct mbuf *m = NULL, *m_tmp = NULL;

	overcommitted_qlen = qlen(input_queue);
	overcommitted_qsize = qsize(input_queue);
	target_qlen = (qlimit(input_queue) * if_rcvq_trim_pct) / 100;

	if (overcommitted_qlen <= target_qlen) {
		/*
		 * The queue is already within the target limits.
		 */
		dropped_pkts = 0;
		goto out;
	}

	pkts_to_drop = overcommitted_qlen - target_qlen;

	/*
	 * Proceed to removing packets from the head of the queue,
	 * starting from the oldest, until the desired number of packets
	 * has been dropped.
	 */
	MBUFQ_FOREACH_SAFE(m, &qmbufq(input_queue), m_tmp) {
		if (pkts_to_drop <= dropped_pkts) {
			break;
		}
		MBUFQ_REMOVE(&qmbufq(input_queue), m);
		MBUFQ_NEXT(m) = NULL;
		MBUFQ_ENQUEUE(freeq, m);

		dropped_pkts += 1;
		dropped_bytes += m_length(m);
	}

	/*
	 * Adjust the length and the estimated size of the queue
	 * after trimming.
	 */
	VERIFY(overcommitted_qlen == target_qlen + dropped_pkts);
	qlen(input_queue) = target_qlen;

	/* qsize() is an approximation. */
	if (dropped_bytes < qsize(input_queue)) {
		qsize(input_queue) -= dropped_bytes;
	} else {
		qsize(input_queue) = 0;
	}

	/*
	 * Adjust the ifnet statistics increments, if needed.
	 */
	stat_delta->dropped += dropped_pkts;
	if (dropped_pkts < stat_delta->packets_in) {
		stat_delta->packets_in -= dropped_pkts;
	} else {
		stat_delta->packets_in = 0;
	}
	if (dropped_bytes < stat_delta->bytes_in) {
		stat_delta->bytes_in -= dropped_bytes;
	} else {
		stat_delta->bytes_in = 0;
	}

out:
	if (dlil_verbose) {
		/*
		 * The basic information about the drop is logged
		 * by the invoking function (dlil_input_{,a}sync).
		 * If `dlil_verbose' flag is set, provide more information
		 * that can be useful for debugging.
		 */
		DLIL_PRINTF("%s: "
		    "qlen: %u -> %u, "
		    "qsize: %llu -> %llu "
		    "qlimit: %u (sysctl: %u) "
		    "target_qlen: %u (if_rcvq_trim_pct: %u) pkts_to_drop: %u "
		    "dropped_pkts: %u dropped_bytes %u\n",
		    __func__,
		    overcommitted_qlen, qlen(input_queue),
		    overcommitted_qsize, qsize(input_queue),
		    qlimit(input_queue), if_rcvq_burst_limit,
		    target_qlen, if_rcvq_trim_pct, pkts_to_drop,
		    dropped_pkts, dropped_bytes);
	}

	return dropped_pkts;
}

static inline mbuf_t
handle_bridge_early_input(ifnet_t ifp, mbuf_t m, u_int32_t cnt)
{
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	if_flt_monitor_busy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);

	if (ifp->if_bridge != NULL) {
		m = bridge_early_input(ifp, m, cnt);
	}
	lck_mtx_lock_spin(&ifp->if_flt_lock);
	if_flt_monitor_unbusy(ifp);
	lck_mtx_unlock(&ifp->if_flt_lock);
	return m;
}
