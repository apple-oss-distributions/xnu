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
nx_netif_filter_tx_pkt_enqueue(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain)
{
	struct __kern_packet *fpkt_chain;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;

	if (nif->nif_filter_cnt == 0) {
		int dropcnt = 0;

		nx_netif_free_packet_chain(pkt_chain, &dropcnt);
		DTRACE_SKYWALK2(pkt__default__drop, struct nx_netif *, nif,
		    int, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_DEFAULT, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		return;
	}
	fpkt_chain = nx_netif_pkt_to_filter_pkt_chain(nifna, pkt_chain,
	    NETIF_CONVERT_TX);
	if (fpkt_chain == NULL) {
		return;
	}
	(void) nx_netif_filter_inject(nifna, NULL, fpkt_chain,
	    NETIF_FILTER_TX | NETIF_FILTER_SOURCE);
}

SK_NO_INLINE_ATTRIBUTE
static struct __kern_packet *
get_next_pkt(struct nx_pktq *pktqs, int *curr, int end)
{
	int i;
	struct __kern_packet *p = NULL;

	for (i = *curr; i >= end; i--) {
		if ((p = nx_pktq_safe_deq(&pktqs[i])) != NULL) {
			break;
		}
	}
	*curr = i;
	return p;
}

SK_NO_INLINE_ATTRIBUTE
static struct __kern_packet *
nx_netif_filter_tx_processed_pkt_dequeue(struct nexus_netif_adapter *nifna,
    kern_packet_svc_class_t sc, uint32_t pkt_limit, uint32_t byte_limit)
{
	struct nx_netif *nif = nifna->nifna_netif;
	int curr, end;
	uint32_t cnt = 0, bytes = 0;
	struct __kern_packet *p, *p_head = NULL, **p_tailp = &p_head;

	if (sc == KPKT_SC_UNSPEC) {
		/*
		 * If the sc is unspecified, walk the queues from the highest
		 * class to lowest.
		 */
		curr = KPKT_TC_MAX - 1;
		end = 0;
	} else {
		/*
		 * Only dequeue from the specified queue.
		 */
		if (!KPKT_VALID_SVC(sc)) {
			sc = KPKT_SC_BE;
		}
		curr = PKT_SC2TC(sc);
		end = curr;
	}
	while (cnt < pkt_limit && bytes < byte_limit) {
		p = get_next_pkt(nif->nif_tx_processed_pktq, &curr, end);
		if (p == NULL) {
			break;
		}
		cnt++;
		bytes += p->pkt_length;
		*p_tailp =  p;
		p_tailp = &p->pkt_nextpkt;
	}
	DTRACE_SKYWALK4(processed__pkt__dequeue, struct nexus_netif_adapter *,
	    nifna, uint32_t, cnt, uint32_t, bytes, struct __kern_packet *,
	    p_head);
	return p_head;
}

errno_t
nx_netif_filter_tx_processed_pkt_enqueue(struct nexus_netif_adapter *nifna,
    kern_packet_svc_class_t sc, struct __kern_packet *p_chain)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct __kern_packet *p_tail = NULL;
	uint32_t cnt = 0, bytes = 0, qlen = 0, tc;
	struct nx_pktq *q;

	/*
	 * It's not possible for sc to be unspecified here. Putting this check
	 * just to be safe.
	 */
	if (!KPKT_VALID_SVC(sc)) {
		sc = KPKT_SC_BE;
	}
	tc = PKT_SC2TC(sc);
	VERIFY(tc < KPKT_TC_MAX);
	q = &nif->nif_tx_processed_pktq[tc];
	nx_netif_pkt_chain_info(p_chain, &p_tail, &cnt, &bytes);
	nx_pktq_lock_spin(q);
	if (__improbable((qlen = nx_pktq_len(q)) > nx_pktq_limit(q))) {
		nx_pktq_unlock(q);
		DTRACE_SKYWALK4(q__full, struct nexus_netif_adapter *, nifna,
		    struct nx_pktq *, q, uint32_t, qlen,
		    struct __kern_packet *, p_chain);
		nx_netif_free_packet_chain(p_chain, NULL);
		STATS_ADD(nifs, NETIF_STATS_FILTER_DROP_PKTQ_FULL, cnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, cnt);
		return ENOBUFS;
	}
	nx_pktq_enq_multi(q, p_chain, p_tail, cnt, bytes);
	qlen = nx_pktq_len(q);

	DTRACE_SKYWALK4(processed__pkt__enqueue, struct nexus_netif_adapter *,
	    nifna, struct nx_pktq *, q, uint32_t, qlen, uint32_t, cnt);
	nx_pktq_unlock(q);
	return 0;
}

static errno_t
nx_netif_tx_processed_pkt_get_len(struct nexus_netif_adapter *nifna,
    kern_packet_svc_class_t sc, uint32_t *packets, uint32_t *bytes,
    errno_t orig_err)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct nx_pktq *q;
	uint32_t qlen = 0;
	size_t qsize = 0;
	errno_t err = 0;
	int i;

	if (sc == KPKT_SC_UNSPEC) {
		for (i = KPKT_TC_MAX - 1; i >= 0; i--) {
			q = &nif->nif_tx_processed_pktq[i];
			nx_pktq_lock_spin(q);
			qlen += nx_pktq_len(q);
			qsize += nx_pktq_size(q);
			nx_pktq_unlock(q);
		}
	} else {
		if (!KPKT_VALID_SVC(sc)) {
			sc = KPKT_SC_BE;
		}
		i = PKT_SC2TC(sc);
		VERIFY(i >= 0 && i < KPKT_TC_MAX);
		q = &nif->nif_tx_processed_pktq[i];
		nx_pktq_lock_spin(q);
		qlen += nx_pktq_len(q);
		qsize += nx_pktq_size(q);
		nx_pktq_unlock(q);
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

	DTRACE_SKYWALK6(processed__pkt__qlen, struct nexus_netif_adapter *,
	    nifna, struct nx_pktq *, q, uint32_t, qlen, size_t, qsize,
	    uint32_t, (packets != NULL) ? *packets : 0,
	    uint32_t, (bytes != NULL) ? *bytes : 0);
	return err;
}

static void
fix_dequeue_pkt_return_args(struct __kern_packet *p_chain, classq_pkt_t *head,
    classq_pkt_t *tail, uint32_t *cnt, uint32_t *len, errno_t orig_err,
    errno_t *err)
{
	struct __kern_packet *p_tail = NULL;
	uint32_t c = 0, l = 0;

	nx_netif_pkt_chain_info(p_chain, &p_tail, &c, &l);
	if (head != NULL) {
		CLASSQ_PKT_INIT_PACKET(head, p_chain);
	}
	if (tail != NULL) {
		CLASSQ_PKT_INIT_PACKET(tail, p_tail);
	}
	if (cnt != NULL) {
		*cnt = c;
	}
	if (len != NULL) {
		*len = l;
	}

	*err = (p_chain == NULL) ? EAGAIN : 0;

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
nx_netif_native_tx_dequeue(struct nexus_netif_adapter *nifna,
    uint32_t sc, uint32_t pkt_limit, uint32_t byte_limit,
    classq_pkt_t *head, classq_pkt_t *tail, uint32_t *cnt, uint32_t *len,
    boolean_t drvmgt, errno_t orig_err)
{
#pragma unused(drvmgt)
	struct nx_netif *nif = nifna->nifna_netif;
	errno_t err;
	struct __kern_packet *p_chain;

	if (__probable(nif->nif_filter_cnt == 0 &&
	    !NETIF_DEFAULT_DROP_ENABLED(nif))) {
		return orig_err;
	}
	if (head->cp_kpkt != NULL) {
		ASSERT(head->cp_ptype == QP_PACKET);
		/*
		 * Moving new packets to filters.
		 * TODO:
		 * The number of packets to move should be dependent on
		 * the available ring space of the next filter. The limits
		 * should be adjusted at ifclassq_dequeue_common().
		 */
		nx_netif_filter_tx_pkt_enqueue(nifna, head->cp_kpkt);
	}

	/*
	 * Move processed packets to the driver.
	 */
	p_chain = nx_netif_filter_tx_processed_pkt_dequeue(nifna, sc,
	    pkt_limit, byte_limit);

	fix_dequeue_pkt_return_args(p_chain, head, tail, cnt, len,
	    orig_err, &err);
	return err;
}

/*
 * This is called by the driver to get the ifnet queue length.
 * Since the processed queue is separate from the ifnet send queue, this count
 * needs to be retrieved separately and added to the ifnet send queue count.
 */
errno_t
nx_netif_native_tx_get_len(struct nexus_netif_adapter *nifna,
    uint32_t sc, uint32_t *packets, uint32_t *bytes,
    errno_t orig_err)
{
	struct nx_netif *nif = nifna->nifna_netif;

	if (__probable(nif->nif_filter_cnt == 0)) {
		return orig_err;
	}
	return nx_netif_tx_processed_pkt_get_len(nifna, sc, packets,
	           bytes, orig_err);
}
