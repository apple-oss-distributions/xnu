/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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
#include <sys/sdt.h>

static void
nx_netif_filter_tx_mbuf_enqueue(struct nexus_netif_adapter *nifna,
    struct mbuf *m_chain)
{
	struct __kern_packet *fpkt_chain;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;

	if (nif->nif_filter_cnt == 0) {
		uint32_t dropcnt = 0;

		nx_netif_mbuf_chain_info(m_chain, NULL, &dropcnt, NULL);
		m_freem_list(m_chain);
		DTRACE_SKYWALK2(mbuf__default__drop, struct nx_netif *, nif,
		    uint32_t, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_DEFAULT, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		return;
	}
	fpkt_chain = nx_netif_mbuf_to_filter_pkt_chain(nifna, m_chain,
	    NETIF_CONVERT_TX);
	if (fpkt_chain == NULL) {
		return;
	}
	(void) nx_netif_filter_inject(nifna, NULL, fpkt_chain,
	    NETIF_FILTER_TX | NETIF_FILTER_SOURCE);
}

SK_NO_INLINE_ATTRIBUTE
static struct mbuf *
get_next_mbuf(struct nx_mbq *mbqs, int *curr, int end)
{
	int i;
	struct mbuf *m = NULL;

	for (i = *curr; i >= end; i--) {
		if ((m = nx_mbq_safe_deq(&mbqs[i])) != NULL) {
			break;
		}
	}
	*curr = i;
	return m;
}

SK_NO_INLINE_ATTRIBUTE
static struct mbuf *
nx_netif_filter_tx_processed_mbuf_dequeue(struct nexus_netif_adapter *nifna,
    mbuf_svc_class_t sc, uint32_t pkt_limit, uint32_t byte_limit)
{
	struct nx_netif *nif = nifna->nifna_netif;
	int curr, end;
	uint32_t cnt = 0, bytes = 0;
	struct mbuf *m, *m_head = NULL, **m_tailp = &m_head;

	if (sc == MBUF_SC_UNSPEC) {
		/*
		 * If the sc is unspecified, walk the queues from the highest
		 * class to lowest.
		 */
		curr = MBUF_TC_MAX - 1;
		end = 0;
	} else {
		/*
		 * Only dequeue from the specified queue.
		 */
		if (!MBUF_VALID_SC(sc)) {
			sc = MBUF_SC_BE;
		}
		curr = MBUF_SC2TC(sc);
		end = curr;
	}
	while (cnt < pkt_limit && bytes < byte_limit) {
		m = get_next_mbuf(nif->nif_tx_processed_mbq, &curr, end);
		if (m == NULL) {
			break;
		}
		cnt++;
		bytes += m_pktlen(m);
		*m_tailp =  m;
		m_tailp = &m->m_nextpkt;
	}
	DTRACE_SKYWALK4(processed__mbuf__dequeue, struct nexus_netif_adapter *,
	    nifna, uint32_t, cnt, uint32_t, bytes, struct mbuf *, m_head);
	return m_head;
}

errno_t
nx_netif_filter_tx_processed_mbuf_enqueue(struct nexus_netif_adapter *nifna,
    mbuf_svc_class_t sc, struct mbuf *m_chain)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct mbuf *m_tail = NULL;
	uint32_t cnt = 0, bytes = 0, qlen = 0, tc;
	struct nx_mbq *q;

	/*
	 * It's not possible for sc to be unspecified here. Putting this check
	 * just to be safe.
	 */
	if (!MBUF_VALID_SC(sc)) {
		sc = MBUF_SC_BE;
	}
	tc = MBUF_SC2TC(sc);
	VERIFY(tc < MBUF_TC_MAX);
	q = &nif->nif_tx_processed_mbq[tc];
	nx_netif_mbuf_chain_info(m_chain, &m_tail, &cnt, &bytes);
	nx_mbq_lock_spin(q);
	if (__improbable((qlen = nx_mbq_len(q)) > nx_mbq_limit(q))) {
		nx_mbq_unlock(q);
		DTRACE_SKYWALK4(q__full, struct nexus_netif_adapter *, nifna,
		    struct nx_mbq *, q, uint32_t, qlen, struct mbuf *, m_chain);
		m_freem_list(m_chain);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_MBQ_FULL, cnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, cnt);
		return ENOBUFS;
	}
	nx_mbq_enq_multi(q, m_chain, m_tail, cnt, bytes);
	qlen = nx_mbq_len(q);

	DTRACE_SKYWALK4(processed__mbuf__enqueue, struct nexus_netif_adapter *,
	    nifna, struct nx_mbq *, q, uint32_t, qlen, uint32_t, cnt);
	nx_mbq_unlock(q);
	return 0;
}

static errno_t
nx_netif_tx_processed_mbuf_get_len(struct nexus_netif_adapter *nifna,
    mbuf_svc_class_t sc, uint32_t *packets, uint32_t *bytes, errno_t orig_err)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct nx_mbq *q;
	uint32_t qlen = 0;
	size_t qsize = 0;
	errno_t err = 0;
	int i;

	if (sc == MBUF_SC_UNSPEC) {
		for (i = MBUF_TC_MAX - 1; i >= 0; i--) {
			q = &nif->nif_tx_processed_mbq[i];
			nx_mbq_lock_spin(q);
			qlen += nx_mbq_len(q);
			qsize += nx_mbq_size(q);
			nx_mbq_unlock(q);
		}
	} else {
		if (!MBUF_VALID_SC(sc)) {
			sc = MBUF_SC_BE;
		}
		i = MBUF_SC2TC(sc);
		VERIFY(i >= 0 && i < MBUF_TC_MAX);
		q = &nif->nif_tx_processed_mbq[i];
		nx_mbq_lock_spin(q);
		qlen += nx_mbq_len(q);
		qsize += nx_mbq_size(q);
		nx_mbq_unlock(q);
	}
	if (packets != NULL) {
		*packets += qlen;
	}
	if (bytes != NULL) {
		*bytes += (uint32_t)qsize;
	}
	/* Original error takes precedence if we have no processed packets */
	if (qlen == 0) {
		err = orig_err;
	}

	DTRACE_SKYWALK6(processed__mbuf__qlen, struct nexus_netif_adapter *,
	    nifna, struct nx_mbq *, q, uint32_t, qlen, size_t, qsize,
	    uint32_t, (packets != NULL) ? *packets : 0,
	    uint32_t, (bytes != NULL) ? *bytes : 0);
	return err;
}

static void
fix_dequeue_mbuf_return_args(struct mbuf *m_chain, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t *cnt, uint32_t *len, errno_t orig_err,
    errno_t *err)
{
	struct mbuf *m_tail = NULL;
	uint32_t c = 0, l = 0;

	nx_netif_mbuf_chain_info(m_chain, &m_tail, &c, &l);
	if (head != NULL) {
		CLASSQ_PKT_INIT_MBUF(head, m_chain);
	}
	if (tail != NULL) {
		CLASSQ_PKT_INIT_MBUF(tail, m_tail);
	}
	if (cnt != NULL) {
		*cnt = c;
	}
	if (len != NULL) {
		*len = l;
	}

	*err = (m_chain == NULL) ? EAGAIN : 0;

	/*
	 * If we can't dequeue from either the AQM queue or the processed queue,
	 * the original (AQM queue) error takes precedence. If we can dequeue
	 * something, we ignore the original error. Most likely both errors
	 * can only be EAGAIN.
	 */
	if (*err != 0 && orig_err != 0) {
		*err = orig_err;
	}
}

/*
 * This is called after the driver has dequeued packets off from AQM.
 * This callback is used for redirecting new packets to filters and
 * processed packets back to the driver.
 */
errno_t
nx_netif_compat_tx_dequeue(struct nexus_netif_adapter *nifna,
    uint32_t sc, uint32_t pkt_limit, uint32_t byte_limit,
    classq_pkt_t *head, classq_pkt_t *tail, uint32_t *cnt, uint32_t *len,
    boolean_t drvmgt, errno_t orig_err)
{
#pragma unused(drvmgt)
	struct nx_netif *nif = nifna->nifna_netif;
	errno_t err;
	struct mbuf *m_chain;

	if (__probable(nif->nif_filter_cnt == 0 &&
	    !NETIF_DEFAULT_DROP_ENABLED(nif))) {
		return orig_err;
	}

	if (head->cp_mbuf != NULL) {
		ASSERT(head->cp_ptype == QP_MBUF);
		/*
		 * Moving new packets to filters.
		 * TODO:
		 * The number of packets to move should be dependent on
		 * the available ring space of the next filter. The limits
		 * should be adjusted at ifclassq_dequeue_common().
		 */
		nx_netif_filter_tx_mbuf_enqueue(nifna, head->cp_mbuf);
	}

	/*
	 * Move processed packets to the driver.
	 */
	m_chain = nx_netif_filter_tx_processed_mbuf_dequeue(nifna, sc,
	    pkt_limit, byte_limit);

	fix_dequeue_mbuf_return_args(m_chain, head, tail, cnt, len,
	    orig_err, &err);
	return err;
}

/*
 * This is called by the driver to get the ifnet queue length.
 * Since the processed queue is separate from the ifnet send queue, this count
 * needs to be retrieved separately and added to the ifnet send queue count.
 */
errno_t
nx_netif_compat_tx_get_len(struct nexus_netif_adapter *nifna, uint32_t sc,
    uint32_t *packets, uint32_t *bytes, errno_t orig_err)
{
	struct nx_netif *nif = nifna->nifna_netif;

	if (__probable(nif->nif_filter_cnt == 0)) {
		return orig_err;
	}
	return nx_netif_tx_processed_mbuf_get_len(nifna, sc, packets,
	           bytes, orig_err);
}
