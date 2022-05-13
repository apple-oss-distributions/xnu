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
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <pexpert/pexpert.h> /* for PE_parse_boot_argn */
#include <os/refcnt.h>
#include <sys/sdt.h>

#define NX_NETIF_TAG_QSET   "com.apple.skywalk.netif.qset"
static SKMEM_TAG_DEFINE(nx_netif_tag_qset, NX_NETIF_TAG_QSET);

#define NX_NETIF_TAG_LLINK_CFG   "com.apple.skywalk.netif.llink.cfg"
static SKMEM_TAG_DEFINE(nx_netif_tag_llink_cfg, NX_NETIF_TAG_LLINK_CFG);

LCK_ATTR_DECLARE(netif_llink_lock_attr, 0, 0);
static LCK_GRP_DECLARE(netif_llink_lock_group, "netif llink locks");

#if (DEVELOPMENT || DEBUG)
static TUNABLE(uint32_t, nx_netif_disable_llink, "sk_disable_llink", 0);
#endif /* (DEVELOPMENT || DEBUG) */

static struct netif_llink *nx_netif_llink_alloc(void);
static void nx_netif_llink_free(struct netif_llink **);
static struct netif_qset *nx_netif_qset_alloc(uint8_t, uint8_t);
static void nx_netif_qset_free(struct netif_qset **);
static void nx_netif_qset_setup_ifclassq(struct ifnet *, struct netif_llink *,
    struct netif_qset *);
static void nx_netif_qset_teardown_ifclassq(struct netif_qset *);
static void nx_netif_qset_init(struct netif_qset *, struct netif_llink *,
    uint8_t idx, struct kern_nexus_netif_llink_qset_init *);
static struct netif_qset *nx_netif_qset_create(struct netif_llink *,
    uint8_t, struct kern_nexus_netif_llink_qset_init *);
static void nx_netif_qset_destroy(struct netif_qset *);
static void nx_netif_llink_initialize(struct netif_llink *, struct nx_netif *,
    struct kern_nexus_netif_llink_init *);
static void nx_netif_driver_queue_destroy(struct netif_queue *);
static void nx_netif_driver_queue_init(struct netif_qset *,
    struct netif_queue *, kern_packet_svc_class_t, bool);
static struct netif_llink *nx_netif_llink_create_locked(struct nx_netif *,
    struct kern_nexus_netif_llink_init *);
static void nx_netif_default_llink_add(struct nx_netif *);
static int netif_qset_enqueue_single(struct netif_qset *,
    struct __kern_packet *, uint32_t *, uint32_t *);
static int nx_netif_llink_ext_init_queues(struct kern_nexus *,
    struct netif_llink *);
static void nx_netif_llink_ext_fini_queues(struct kern_nexus *,
    struct netif_llink *);

static uint32_t nx_netif_random_qset = 0;
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, random_qset,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nx_netif_random_qset, 0,
    "pick a random qset");
#endif /* DEVELOPMENT || DEBUG */

/* retains a reference for the callee */
static struct netif_llink *
nx_netif_llink_alloc(void)
{
	struct netif_llink *llink;

	llink = sk_alloc_type(struct netif_llink, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_netif_llink);
	os_ref_init(&llink->nll_refcnt, NULL);
	return llink;
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_llink_retain(struct netif_llink *llink)
{
	os_ref_retain(&llink->nll_refcnt);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_llink_free(struct netif_llink **pllink)
{
	struct netif_llink *llink = *pllink;
	struct netif_qset *qset, *tqset;

	VERIFY(llink->nll_state == NETIF_LLINK_STATE_DESTROYED);
	*pllink = NULL;
	SLIST_FOREACH_SAFE(qset, &llink->nll_qset_list, nqs_list, tqset) {
		SLIST_REMOVE(&llink->nll_qset_list, qset, netif_qset,
		    nqs_list);
		nx_netif_qset_destroy(qset);
	}
	sk_free_type(struct netif_llink, llink);
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_llink_release(struct netif_llink **pllink)
{
	struct netif_llink *llink = *pllink;

	*pllink = NULL;
	if (os_ref_release(&llink->nll_refcnt) == 0) {
		nx_netif_llink_free(&llink);
	}
}

/* retains a reference for the callee */
static struct netif_qset *
nx_netif_qset_alloc(uint8_t nrxqs, uint8_t ntxqs)
{
	struct netif_qset *qset;

	_CASSERT(sizeof(struct netif_queue) % sizeof(uint64_t) == 0);

	qset = sk_alloc_type_header_array(struct netif_qset, struct netif_queue,
	    nrxqs + ntxqs, Z_WAITOK | Z_NOFAIL, nx_netif_tag_qset);

	qset->nqs_num_rx_queues = nrxqs;
	qset->nqs_num_tx_queues =  ntxqs;
	return qset;
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_qset_retain(struct netif_qset *qset)
{
	/*
	 * Logical link is immutable, i.e. Queue Sets can't added/removed
	 * from it. We will rely on this property to simply acquire a refcnt
	 * on the logical link, which is the parent structure of a qset.
	 */
	nx_netif_llink_retain(qset->nqs_llink);
}

SK_NO_INLINE_ATTRIBUTE
void
nx_netif_qset_release(struct netif_qset **pqset)
{
	struct netif_qset *qset = *pqset;
	struct netif_llink *llink = qset->nqs_llink;

	*pqset = NULL;
	nx_netif_llink_release(&llink);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_qset_free(struct netif_qset **pqset)
{
	struct netif_qset *qset = *pqset;
	uint8_t i;

	VERIFY(qset->nqs_llink->nll_state == NETIF_LLINK_STATE_DESTROYED);

	for (i = 0; i < qset->nqs_num_rx_queues; i++) {
		nx_netif_driver_queue_destroy(NETIF_QSET_RX_QUEUE(qset, i));
	}
	for (i = 0; i < qset->nqs_num_tx_queues; i++) {
		nx_netif_driver_queue_destroy(NETIF_QSET_TX_QUEUE(qset, i));
	}
	if (qset->nqs_ifcq != NULL) {
		nx_netif_qset_teardown_ifclassq(qset);
	}
	qset->nqs_llink = NULL;
	sk_free_type_header_array(struct netif_qset, struct netif_queue,
	    qset->nqs_num_rx_queues + qset->nqs_num_tx_queues, qset);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_qset_destroy(struct netif_qset *qset)
{
	VERIFY(qset->nqs_llink->nll_state == NETIF_LLINK_STATE_DESTROYED);
	nx_netif_qset_free(&qset);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_qset_setup_ifclassq(struct ifnet *ifp, struct netif_llink *llink,
    struct netif_qset *qset)
{
	if (NETIF_DEFAULT_LLINK(llink) && NETIF_DEFAULT_QSET(qset)) {
		/* use the default AQM queues from ifnet */
		ifclassq_retain(ifp->if_snd);
		qset->nqs_ifcq = ifp->if_snd;
		return;
	}
	qset->nqs_ifcq = ifclassq_alloc();
	VERIFY(qset->nqs_ifcq != NULL);
	dlil_ifclassq_setup(ifp, qset->nqs_ifcq);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_qset_teardown_ifclassq(struct netif_qset *qset)
{
	ASSERT((qset->nqs_flags & NETIF_QSET_FLAG_AQM) != 0);

	if (NETIF_DEFAULT_LLINK(qset->nqs_llink) && NETIF_DEFAULT_QSET(qset)) {
		ifclassq_release(&qset->nqs_ifcq);
		return;
	}
	/* Drain and destroy send queue */
	ifclassq_teardown(qset->nqs_ifcq);
	ifclassq_release(&qset->nqs_ifcq);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_qset_init(struct netif_qset *qset, struct netif_llink *llink,
    uint8_t idx, struct kern_nexus_netif_llink_qset_init *qset_init)
{
#define _NETIF_QSET_MAX_TXQS    4
	kern_packet_svc_class_t svc[_NETIF_QSET_MAX_TXQS] =
	{KPKT_SC_VO, KPKT_SC_VI, KPKT_SC_BE, KPKT_SC_BK};
	struct ifnet *ifp = llink->nll_nif->nif_ifp;
	uint8_t i;

	/*
	 * no need to retain a reference for llink, as the logical link is
	 * immutable and qsets are created and destroyed along with logical
	 * link.
	 */
	qset->nqs_llink = llink;

	if (qset_init->nlqi_flags & KERN_NEXUS_NET_LLINK_QSET_DEFAULT) {
		qset->nqs_flags |= NETIF_QSET_FLAG_DEFAULT;
	}
	if (qset_init->nlqi_flags & KERN_NEXUS_NET_LLINK_QSET_LOW_LATENCY) {
		qset->nqs_flags |= NETIF_QSET_FLAG_LOW_LATENCY;
	}
	if (qset_init->nlqi_flags & KERN_NEXUS_NET_LLINK_QSET_AQM) {
		nx_netif_qset_setup_ifclassq(ifp, llink, qset);
		qset->nqs_flags |= NETIF_QSET_FLAG_AQM;
	}
	qset->nqs_id = NETIF_QSET_ID_ENCODE(llink->nll_link_id_internal, idx);
	qset->nqs_idx = idx;

	for (i = 0; i < qset->nqs_num_rx_queues; i++) {
		nx_netif_driver_queue_init(qset, NETIF_QSET_RX_QUEUE(qset, i),
		    KPKT_SC_UNSPEC, true);
	}

	/*
	 * TODO:
	 * Could be more flexible here to allow an arbitrary number of queues.
	 */
	if (qset->nqs_num_tx_queues > 1) {
		VERIFY(qset->nqs_num_tx_queues == _NETIF_QSET_MAX_TXQS);
		VERIFY(ifp->if_output_sched_model ==
		    IFNET_SCHED_MODEL_DRIVER_MANAGED);
		for (i = 0; i < _NETIF_QSET_MAX_TXQS; i++) {
			nx_netif_driver_queue_init(qset,
			    NETIF_QSET_TX_QUEUE(qset, i), svc[i], false);
		}
	} else {
		nx_netif_driver_queue_init(qset, NETIF_QSET_RX_QUEUE(qset, i),
		    KPKT_SC_UNSPEC, false);
	}
}

SK_NO_INLINE_ATTRIBUTE
static struct netif_qset *
nx_netif_qset_create(struct netif_llink *llink, uint8_t idx,
    struct kern_nexus_netif_llink_qset_init *qset_init)
{
	struct netif_qset *qset;

	qset = nx_netif_qset_alloc(qset_init->nlqi_num_rxqs,
	    qset_init->nlqi_num_txqs);
	nx_netif_qset_init(qset, llink, idx, qset_init);
	return qset;
}

static uint16_t
nx_netif_generate_internal_llink_id(struct nx_netif *nif)
{
	struct netif_llink *llink;
	struct netif_stats *nifs = &nif->nif_stats;
	uint16_t id;

again:
	id = (uint16_t)(random() % 65536);
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		if (__improbable(llink->nll_link_id_internal == id)) {
			break;
		}
	}
	if (__probable(llink == NULL && id != 0)) {
		return id;
	} else {
		STATS_INC(nifs, NETIF_STATS_LLINK_DUP_INT_ID_GENERATED);
		DTRACE_SKYWALK1(dup__llink__id__internal, uint16_t, id);
		goto again;
	}
}

static void
nx_netif_llink_initialize(struct netif_llink *llink, struct nx_netif *nif,
    struct kern_nexus_netif_llink_init *llink_init)
{
	uint8_t i;

	LCK_RW_ASSERT(&nif->nif_llink_lock, LCK_RW_ASSERT_EXCLUSIVE);

	llink->nll_nif = nif;
	llink->nll_link_id = llink_init->nli_link_id;
	if (llink_init->nli_flags & KERN_NEXUS_NET_LLINK_DEFAULT) {
		llink->nll_flags |= NETIF_LLINK_FLAG_DEFAULT;
	}
	llink->nll_link_id_internal = nx_netif_generate_internal_llink_id(nif);
	llink->nll_ctx = llink_init->nli_ctx;
	SLIST_INIT(&llink->nll_qset_list);

	for (i = 0; i < llink_init->nli_num_qsets; i++) {
		struct netif_qset *qset = nx_netif_qset_create(llink, i,
		    &llink_init->nli_qsets[i]);
		/* nx_netif_qset_create retains a reference for the callee */
		SLIST_INSERT_HEAD(&llink->nll_qset_list, qset, nqs_list);
		if (NETIF_DEFAULT_QSET(qset)) {
			/* there can only be one default queue set */
			VERIFY(llink->nll_default_qset == NULL);
			llink->nll_default_qset = qset;
		}
	}
	llink->nll_qset_cnt = llink_init->nli_num_qsets;
	/* there should be a default queue set */
	VERIFY(llink->nll_default_qset != NULL);
	llink->nll_state = NETIF_LLINK_STATE_INIT;
}

static void
nx_netif_driver_queue_destroy(struct netif_queue *drvq)
{
	VERIFY(drvq->nq_qset->nqs_llink->nll_state ==
	    NETIF_LLINK_STATE_DESTROYED);

	lck_mtx_lock(&drvq->nq_lock);
	VERIFY(KPKTQ_EMPTY(&drvq->nq_pktq));
	lck_mtx_unlock(&drvq->nq_lock);

	drvq->nq_qset = NULL;
	lck_mtx_destroy(&drvq->nq_lock, &netif_llink_lock_group);
}

static void
nx_netif_driver_queue_init(struct netif_qset *qset,
    struct netif_queue *drvq, kern_packet_svc_class_t svc, bool is_rx)
{
	lck_mtx_init(&drvq->nq_lock, &netif_llink_lock_group,
	    &netif_llink_lock_attr);

	lck_mtx_lock(&drvq->nq_lock);
	KPKTQ_INIT(&drvq->nq_pktq);
	lck_mtx_unlock(&drvq->nq_lock);

	/*
	 * no need to retain a reference for qset, as queue set is
	 * immutable and driver queue is part of the queue set data structure.
	 */
	drvq->nq_qset = qset;
	drvq->nq_svc = svc;
	if (is_rx) {
		drvq->nq_flags |= NETIF_QUEUE_IS_RX;
	}
}

SK_NO_INLINE_ATTRIBUTE
static struct netif_llink *
nx_netif_llink_create_locked(struct nx_netif *nif,
    struct kern_nexus_netif_llink_init *llink_init)
{
	struct netif_llink *llink;
	struct netif_stats *nifs = &nif->nif_stats;

	LCK_RW_ASSERT(&nif->nif_llink_lock, LCK_RW_ASSERT_EXCLUSIVE);
	llink = nx_netif_llink_alloc();
	nx_netif_llink_initialize(llink, nif, llink_init);
	/* nx_netif_llink_alloc retains a reference for the caller */
	STAILQ_INSERT_TAIL(&nif->nif_llink_list, llink, nll_link);
	nif->nif_llink_cnt++;
	STATS_INC(nifs, NETIF_STATS_LLINK_ADD);
	if (NETIF_DEFAULT_LLINK(llink)) {
		/* there can only be one default logical link */
		VERIFY(nif->nif_default_llink == NULL);
	}
	return llink;
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_llink_destroy_locked(struct nx_netif *nif, struct netif_llink **pllink)
{
	struct netif_stats *nifs = &nif->nif_stats;

	LCK_RW_ASSERT(&nif->nif_llink_lock, LCK_RW_ASSERT_EXCLUSIVE);
	(*pllink)->nll_state = NETIF_LLINK_STATE_DESTROYED;
	STAILQ_REMOVE(&nif->nif_llink_list, *pllink, netif_llink, nll_link);
	nif->nif_llink_cnt--;
	STATS_INC(nifs, NETIF_STATS_LLINK_REMOVE);
	nx_netif_llink_release(pllink);
}

int
nx_netif_llink_add(struct nx_netif *nif,
    struct kern_nexus_netif_llink_init *llink_init, struct netif_llink **pllink)
{
	int err;
	struct netif_llink *llink;
	struct netif_stats *nifs = &nif->nif_stats;

	*pllink = NULL;
	lck_rw_lock_exclusive(&nif->nif_llink_lock);
	/* ensure logical_link_id is unique */
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		if (llink->nll_link_id == llink_init->nli_link_id) {
			SK_ERR("duplicate llink_id 0x%llu",
			    llink_init->nli_link_id);
			STATS_INC(nifs, NETIF_STATS_LLINK_DUP_ID_GIVEN);
			DTRACE_SKYWALK1(dup__id__given, uint64_t,
			    llink_init->nli_link_id);
			lck_rw_unlock_exclusive(&nif->nif_llink_lock);
			return EINVAL;
		}
	}
	llink = nx_netif_llink_create_locked(nif, llink_init);
	lck_rw_unlock_exclusive(&nif->nif_llink_lock);
	VERIFY(llink != NULL);
	err = nx_netif_llink_ext_init_queues(nif->nif_nx, llink);
	if (err != 0) {
		lck_rw_lock_exclusive(&nif->nif_llink_lock);
		nx_netif_llink_destroy_locked(nif, &llink);
		lck_rw_unlock_exclusive(&nif->nif_llink_lock);
	} else {
		/* increment reference for the caller */
		nx_netif_llink_retain(llink);
		*pllink = llink;
	}
	return err;
}

int
nx_netif_llink_remove(struct nx_netif *nif,
    kern_nexus_netif_llink_id_t llink_id)
{
	bool llink_found = false;
	struct netif_llink *llink;
	struct netif_stats *nifs = &nif->nif_stats;

	lck_rw_lock_exclusive(&nif->nif_llink_lock);
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		if (llink->nll_link_id == llink_id) {
			llink_found = true;
			break;
		}
	}
	lck_rw_unlock_exclusive(&nif->nif_llink_lock);
	if (!llink_found) {
		STATS_INC(nifs, NETIF_STATS_LLINK_NOT_FOUND_REMOVE);
		DTRACE_SKYWALK1(not__found, uint64_t, llink_id);
		return ENOENT;
	}
	nx_netif_llink_ext_fini_queues(nif->nif_nx, llink);
	lck_rw_lock_exclusive(&nif->nif_llink_lock);
	nx_netif_llink_destroy_locked(nif, &llink);
	lck_rw_unlock_exclusive(&nif->nif_llink_lock);
	return 0;
}

static void
nx_netif_default_llink_add(struct nx_netif *nif)
{
	struct kern_nexus_netif_llink_init llink_init, *pllink_init;
	struct kern_nexus_netif_llink_qset_init qset;
	struct ifnet *ifp = nif->nif_ifp;
	struct netif_llink *llink;

	LCK_RW_ASSERT(&nif->nif_llink_lock, LCK_RW_ASSERT_EXCLUSIVE);
	VERIFY(SKYWALK_NATIVE(ifp));

	llink_init.nli_flags = KERN_NEXUS_NET_LLINK_DEFAULT;

	if (NX_LLINK_PROV(nif->nif_nx)) {
		VERIFY(nif->nif_default_llink_params != NULL);
		pllink_init = nif->nif_default_llink_params;
	} else {
		struct nexus_adapter *devna =
		    nx_port_get_na(nif->nif_nx, NEXUS_PORT_NET_IF_DEV);

		llink_init.nli_link_id = NETIF_LLINK_ID_DEFAULT;
		qset.nlqi_flags = KERN_NEXUS_NET_LLINK_QSET_DEFAULT;
		/*
		 * For the legacy mode of operation we will assume that
		 * AQM is not needed on low-latency interface.
		 */
		if (NETIF_IS_LOW_LATENCY(nif)) {
			qset.nlqi_flags |=
			    KERN_NEXUS_NET_LLINK_QSET_LOW_LATENCY;
		} else {
			qset.nlqi_flags |= KERN_NEXUS_NET_LLINK_QSET_AQM;
		}
		qset.nlqi_num_rxqs =
		    (uint8_t)na_get_nrings(devna, NR_RX);
		qset.nlqi_num_txqs =
		    (uint8_t)na_get_nrings(devna, NR_TX);
		llink_init.nli_num_qsets = 1;
		llink_init.nli_qsets = &qset;
		llink_init.nli_ctx = NULL;
		pllink_init = &llink_init;
	}
	llink = nx_netif_llink_create_locked(nif, pllink_init);
	/* there can only be one default logical link */
	VERIFY(nif->nif_default_llink == NULL);
	nx_netif_llink_retain(llink);
	/* obtain a reference for the default logical link pointer */
	nif->nif_default_llink = llink;
}

static void
nx_netif_default_llink_remove(struct nx_netif *nif)
{
	struct netif_llink *llink;

	LCK_RW_ASSERT(&nif->nif_llink_lock, LCK_RW_ASSERT_EXCLUSIVE);
	ASSERT(nif->nif_default_llink != NULL);
	ASSERT(nif->nif_llink_cnt == 1);
	llink = nif->nif_default_llink;
	nx_netif_llink_release(&nif->nif_default_llink);
	ASSERT(nif->nif_default_llink == NULL);
	nx_netif_llink_destroy_locked(nif, &llink);
}

__attribute__((always_inline))
static inline void
netif_ifp_inc_traffic_class_out_pkt(struct ifnet *ifp, uint32_t svc,
    uint32_t cnt, uint32_t len)
{
	switch (svc) {
	case PKT_TC_BE:
		ifp->if_tc.ifi_obepackets += cnt;
		ifp->if_tc.ifi_obebytes += len;
		break;
	case PKT_TC_BK:
		ifp->if_tc.ifi_obkpackets += cnt;
		ifp->if_tc.ifi_obkbytes += len;
		break;
	case PKT_TC_VI:
		ifp->if_tc.ifi_ovipackets += cnt;
		ifp->if_tc.ifi_ovibytes += len;
		break;
	case PKT_TC_VO:
		ifp->if_tc.ifi_ovopackets += cnt;
		ifp->if_tc.ifi_ovobytes += len;
		break;
	default:
		break;
	}
}

static int
netif_qset_enqueue_single(struct netif_qset *qset, struct __kern_packet *pkt,
    uint32_t *flowctl, uint32_t *dropped)
{
	struct ifnet *ifp = qset->nqs_ifcq->ifcq_ifp;
	boolean_t pkt_drop = FALSE;
	int err;

	/*
	 * we are using the first 4 bytes of flow_id as the AQM flow
	 * identifier.
	 */
	ASSERT(!uuid_is_null(pkt->pkt_flow_id));
	netif_ifp_inc_traffic_class_out_pkt(ifp, pkt->pkt_svc_class,
	    1, pkt->pkt_length);

	if (__improbable(pkt->pkt_trace_id != 0)) {
		KDBG(SK_KTRACE_PKT_TX_FSW | DBG_FUNC_END, pkt->pkt_trace_id);
		KDBG(SK_KTRACE_PKT_TX_AQM | DBG_FUNC_START, pkt->pkt_trace_id);
	}

	/* Only native path is supported */
	ASSERT((pkt->pkt_pflags & PKT_F_MBUF_DATA) == 0);
	ASSERT(pkt->pkt_mbuf == NULL);

	err = ifnet_enqueue_ifcq_pkt(ifp, qset->nqs_ifcq, pkt, false,
	    &pkt_drop);
	if (__improbable(err != 0)) {
		if ((err == EQFULL || err == EQSUSPENDED) && flowctl != NULL) {
			(*flowctl)++;
		}
		if (pkt_drop && dropped != NULL) {
			(*dropped)++;
		}
	}
	return err;
}

int
netif_qset_enqueue(struct netif_qset *qset, struct __kern_packet *pkt_chain,
    struct __kern_packet *tail, uint32_t cnt, uint32_t bytes, uint32_t *flowctl,
    uint32_t *dropped)
{
#pragma unused(tail)
	struct __kern_packet *pkt = pkt_chain;
	struct __kern_packet *next;
	struct netif_stats *nifs = &qset->nqs_llink->nll_nif->nif_stats;
	uint32_t c = 0, b = 0, drop_cnt = 0, flowctl_cnt = 0;
	int err = 0;

	/* drop packets if logical link state is destroyed */
	if (qset->nqs_llink->nll_state == NETIF_LLINK_STATE_DESTROYED) {
		pp_free_packet_chain(pkt_chain, (int *)&drop_cnt);
		STATS_ADD(nifs, NETIF_STATS_LLINK_TX_DROP_BAD_STATE, drop_cnt);
		if (dropped != NULL) {
			*dropped = drop_cnt;
		}
		return ENXIO;
	}

	/* We don't support chains for now */
	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
		c++;
		b += pkt->pkt_length;

		(void) netif_qset_enqueue_single(qset, pkt, &flowctl_cnt,
		    &drop_cnt);
		pkt = next;
	}
	VERIFY(c == cnt);
	VERIFY(b == bytes);
	if (flowctl != NULL && flowctl_cnt > 0) {
		*flowctl = flowctl_cnt;
		STATS_ADD(nifs, NETIF_STATS_LLINK_AQM_QFULL, flowctl_cnt);
		err = EIO;
	}
	if (dropped != NULL && drop_cnt > 0) {
		*dropped = drop_cnt;
		STATS_ADD(nifs, NETIF_STATS_LLINK_AQM_DROPPED, drop_cnt);
		err = EIO;
	}
	return err;
}

struct netif_qset *
nx_netif_get_default_qset_noref(struct nx_netif *nif)
{
	struct netif_qset *qset;
	struct netif_stats *nifs = &nif->nif_stats;

	ASSERT(NETIF_LLINK_ENABLED(nif));
	if (__improbable(nif->nif_default_llink->nll_state !=
	    NETIF_LLINK_STATE_INIT)) {
		STATS_INC(nifs, NETIF_STATS_LLINK_QSET_BAD_STATE);
		DTRACE_SKYWALK1(llink__bad__state, struct nx_netif *, nif);
		return NULL;
	}
	qset = nif->nif_default_llink->nll_default_qset;
	return qset;
}

static void
nx_netif_qset_hint_decode(uint64_t hint,
    uint16_t *link_id_internal, uint16_t *qset_idx)
{
	/* The top 32 bits are unused for now */
	*link_id_internal = (uint16_t)((0xffff0000 & hint) >> 16);
	*qset_idx = (uint16_t)((0x0000ffff & hint));
}

/* retains a reference for the caller */
static struct netif_qset *
nx_netif_get_default_qset(struct nx_netif *nif)
{
	struct netif_qset *qset;

	qset = nif->nif_default_llink->nll_default_qset;
	nx_netif_qset_retain(qset);
	return qset;
}

/*
 * Find the qset based on the qset hint. Fall back to the default qset
 * if not found. The random qset is used for experimentation.
 */
struct netif_qset *
nx_netif_find_qset(struct nx_netif *nif, uint64_t hint)
{
	uint16_t ll_id_internal, qset_idx;
	struct netif_llink *llink;
	struct netif_qset *qset;
	struct netif_stats *nifs = &nif->nif_stats;
	int i, j, random_id;

	ASSERT(NETIF_LLINK_ENABLED(nif));
	if (__improbable(nif->nif_default_llink->nll_state !=
	    NETIF_LLINK_STATE_INIT)) {
		STATS_INC(nifs, NETIF_STATS_LLINK_QSET_BAD_STATE);
		DTRACE_SKYWALK1(llink__bad__state, struct nx_netif *, nif);
		return NULL;
	}
	if (!NX_LLINK_PROV(nif->nif_nx) ||
	    (nx_netif_random_qset == 0 && hint == 0)) {
		goto def_qset;
	}
	if (nx_netif_random_qset == 0) {
		nx_netif_qset_hint_decode(hint, &ll_id_internal, &qset_idx);
	} else {
		ll_id_internal = 0;
		qset_idx = 0;
	}
	lck_rw_lock_shared(&nif->nif_llink_lock);
	i = 0;
	random_id = random();
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		if (nx_netif_random_qset != 0 &&
		    (random_id % nif->nif_llink_cnt) == i) {
			break;
		} else if (llink->nll_link_id_internal == ll_id_internal) {
			break;
		}
		i++;
	}
	if (llink == NULL) {
		STATS_INC(nifs, NETIF_STATS_LLINK_HINT_NOT_USEFUL);
		lck_rw_unlock_shared(&nif->nif_llink_lock);
		goto def_qset;
	}
	j = 0;
	random_id = random();
	SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
		if (nx_netif_random_qset != 0 &&
		    (random_id % llink->nll_qset_cnt) == j) {
			break;
		} else if (qset->nqs_idx == qset_idx) {
			break;
		}
		j++;
	}
	if (qset == NULL) {
		STATS_INC(nifs, NETIF_STATS_LLINK_HINT_NOT_USEFUL);
		lck_rw_unlock_shared(&nif->nif_llink_lock);
		goto def_qset;
	}
	nx_netif_qset_retain(qset);
	STATS_INC(nifs, NETIF_STATS_LLINK_NONDEF_QSET_USED);
	lck_rw_unlock_shared(&nif->nif_llink_lock);
	if (nx_netif_random_qset != 0) {
		SK_DF(SK_VERB_LLINK, "%s: random qset: qset %p, ifcq %p, "
		    "llink_idx %d, qset_idx %d", if_name(nif->nif_ifp),
		    qset, qset->nqs_ifcq, i, j);

		DTRACE_SKYWALK5(random__qset, struct nx_netif *, nif,
		    struct netif_qset *, qset, struct ifclassq *,
		    qset->nqs_ifcq, int, i, int, j);
	} else {
		SK_DF(SK_VERB_LLINK, "%s: non-default qset: qset %p, ifcq %p, "
		    " ll_id_internal 0x%x, qset_idx %d", if_name(nif->nif_ifp),
		    qset, qset->nqs_ifcq, ll_id_internal, qset_idx);

		DTRACE_SKYWALK5(nondef__qset, struct nx_netif *, nif,
		    struct netif_qset *, qset, struct ifclassq *,
		    qset->nqs_ifcq, uint16_t, ll_id_internal,
		    uint16_t, qset_idx);
	}
	return qset;

def_qset:
	STATS_INC(nifs, NETIF_STATS_LLINK_DEF_QSET_USED);
	qset = nx_netif_get_default_qset(nif);
	ASSERT(qset != NULL);

	SK_DF(SK_VERB_LLINK, "%s: default qset: qset %p, ifcq %p, hint %llx",
	    if_name(nif->nif_ifp), qset, qset->nqs_ifcq, hint);

	DTRACE_SKYWALK4(def__qset, struct nx_netif *, nif, struct netif_qset *,
	    qset, struct ifclassq *, qset->nqs_ifcq, uint64_t, hint);
	return qset;
}

void
nx_netif_llink_init(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

#if (DEVELOPMENT || DEBUG)
	if (__improbable(nx_netif_disable_llink != 0)) {
		SK_DF(SK_VERB_LLINK, "%s: llink is disabled",
		    if_name(nif->nif_ifp));
		return;
	}
#endif /* (DEVELOPMENT || DEBUG) */

	if (!SKYWALK_NATIVE(ifp)) {
		SK_DF(SK_VERB_LLINK,
		    "%s: llink is supported on native devices only",
		    if_name(ifp));
		return;
	}
	ASSERT(!NETIF_LLINK_ENABLED(nif));
	lck_rw_init(&nif->nif_llink_lock, &netif_llink_lock_group,
	    &netif_llink_lock_attr);

	lck_rw_lock_exclusive(&nif->nif_llink_lock);

	STAILQ_INIT(&nif->nif_llink_list);
	nif->nif_llink_cnt = 0;
	nx_netif_default_llink_add(nif);
	nif->nif_flags |= NETIF_FLAG_LLINK_INITIALIZED;

	lck_rw_unlock_exclusive(&nif->nif_llink_lock);

	SK_DF(SK_VERB_LLINK, "%s: llink initialized", if_name(ifp));
}

void
nx_netif_llink_fini(struct nx_netif *nif)
{
	if (!NETIF_LLINK_ENABLED(nif)) {
		SK_DF(SK_VERB_LLINK, "%s: llink not initialized",
		    if_name(nif->nif_ifp));
		return;
	}

	lck_rw_lock_exclusive(&nif->nif_llink_lock);

	nif->nif_flags &= ~NETIF_FLAG_LLINK_INITIALIZED;
	nx_netif_default_llink_remove(nif);
	ASSERT(nif->nif_llink_cnt == 0);
	ASSERT(STAILQ_EMPTY(&nif->nif_llink_list));

	lck_rw_unlock_exclusive(&nif->nif_llink_lock);

	nx_netif_llink_config_free(nif);
	lck_rw_destroy(&nif->nif_llink_lock, &netif_llink_lock_group);
	SK_DF(SK_VERB_LLINK, "%s: llink uninitialization done",
	    if_name(nif->nif_ifp));
}

int
nx_netif_validate_llink_config(struct kern_nexus_netif_llink_init *init,
    bool default_llink)
{
	struct kern_nexus_netif_llink_qset_init *qsinit;
	bool has_default_qset = false;
	bool default_llink_flag;
	uint8_t i;

	default_llink_flag =
	    ((init->nli_flags & KERN_NEXUS_NET_LLINK_DEFAULT) != 0);

	if (default_llink != default_llink_flag) {
		SK_ERR("default llink flag incompatible: default_llink(%s), "
		    "default_llink_flag(%s)",
		    default_llink ? "true" : "false",
		    default_llink_flag ? "true" : "false");
		return EINVAL;
	}
	if (init->nli_num_qsets == 0) {
		SK_ERR("num qsets is zero");
		return EINVAL;
	}
	if ((qsinit = init->nli_qsets) == NULL) {
		SK_ERR("qsets is NULL");
		return EINVAL;
	}
	for (i = 0; i < init->nli_num_qsets; i++) {
		if (qsinit[i].nlqi_flags &
		    KERN_NEXUS_NET_LLINK_QSET_DEFAULT) {
			if (has_default_qset) {
				SK_ERR("has more than one default qset");
				return EINVAL;
			}
			if (qsinit[i].nlqi_num_rxqs == 0) {
				SK_ERR("num_rxqs == 0");
				return EINVAL;
			}
			has_default_qset = true;
		}
		if (qsinit[i].nlqi_num_txqs == 0) {
			SK_ERR("num_txqs == 0");
			return EINVAL;
		}
		if ((qsinit[i].nlqi_flags &
		    KERN_NEXUS_NET_LLINK_QSET_WMM_MODE) &&
		    (qsinit[i].nlqi_num_txqs != NEXUS_NUM_WMM_QUEUES)) {
			SK_ERR("invalid wmm mode");
			return EINVAL;
		}
	}
	return 0;
}

int
nx_netif_default_llink_config(struct nx_netif *nif,
    struct kern_nexus_netif_llink_init *init)
{
	struct kern_nexus_netif_llink_qset_init *qsinit;
	int i, err;

	err = nx_netif_validate_llink_config(init, true);
	if (err != 0) {
		return err;
	}
	nif->nif_default_llink_params = sk_alloc_type(
		struct kern_nexus_netif_llink_init,
		Z_WAITOK | Z_NOFAIL, nx_netif_tag_llink_cfg);

	qsinit = sk_alloc_type_array(struct kern_nexus_netif_llink_qset_init,
	    init->nli_num_qsets, Z_WAITOK, nx_netif_tag_llink_cfg);
	if (qsinit == NULL) {
		SK_ERR("failed to alloc kern_nexus_netif_llink_qset_init");
		sk_free_type(struct kern_nexus_netif_llink_init,
		    nif->nif_default_llink_params);
		nif->nif_default_llink_params = NULL;
		return ENOMEM;
	}
	memcpy(nif->nif_default_llink_params, init,
	    __builtin_offsetof(struct kern_nexus_netif_llink_init,
	    nli_qsets));
	for (i = 0; i < init->nli_num_qsets; i++) {
		*(&qsinit[i]) = *(&init->nli_qsets[i]);
	}
	nif->nif_default_llink_params->nli_qsets = qsinit;
	return 0;
}

void
nx_netif_llink_config_free(struct nx_netif *nif)
{
	if (nif->nif_default_llink_params == NULL) {
		return;
	}
	sk_free_type_array(struct kern_nexus_netif_llink_qset_init,
	    nif->nif_default_llink_params->nli_num_qsets,
	    nif->nif_default_llink_params->nli_qsets);
	nif->nif_default_llink_params->nli_qsets = NULL;

	sk_free_type(struct kern_nexus_netif_llink_init,
	    nif->nif_default_llink_params);
	nif->nif_default_llink_params = NULL;
}

static int
nx_netif_llink_ext_init_queues(struct kern_nexus *nx, struct netif_llink *llink)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct kern_nexus_netif_provider_init *nxnpi;
	struct netif_qset *qset;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nx)->nif_stats;
	int err = 0;
	uint8_t i;

	nxnpi = &nxprov->nxprov_netif_ext;
	ASSERT(nxprov->nxprov_netif_ext.nxnpi_qset_init != NULL);
	ASSERT(nxprov->nxprov_netif_ext.nxnpi_queue_init != NULL);

	SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
		struct netif_queue *drvq;

		ASSERT((qset->nqs_flags & NETIF_QSET_FLAG_EXT_INITED) == 0);
		err = nxnpi->nxnpi_qset_init(nxprov, nx, llink->nll_ctx,
		    qset->nqs_idx, qset->nqs_id, qset, &qset->nqs_ctx);
		if (err != 0) {
			STATS_INC(nifs, NETIF_STATS_LLINK_QSET_INIT_FAIL);
			SK_ERR("nx: 0x%llx, qset: %d, qset init err %d",
			    SK_KVA(nx), qset->nqs_idx, err);
			goto out;
		}
		qset->nqs_flags |= NETIF_QSET_FLAG_EXT_INITED;

		for (i = 0; i < qset->nqs_num_rx_queues; i++) {
			drvq = NETIF_QSET_RX_QUEUE(qset, i);

			ASSERT((drvq->nq_flags & NETIF_QUEUE_EXT_INITED) == 0);
			err = nxnpi->nxnpi_queue_init(nxprov, nx, qset->nqs_ctx,
			    i, false, drvq, &drvq->nq_ctx);
			if (err != 0) {
				STATS_INC(nifs, NETIF_STATS_LLINK_RXQ_INIT_FAIL);
				SK_ERR("nx: 0x%llx qset: %d queue_init err %d",
				    SK_KVA(nx), qset->nqs_idx, err);
				goto out;
			}
			drvq->nq_flags |= NETIF_QUEUE_EXT_INITED;
		}
		for (i = 0; i < qset->nqs_num_tx_queues; i++) {
			drvq = NETIF_QSET_TX_QUEUE(qset, i);

			ASSERT((drvq->nq_flags & NETIF_QUEUE_EXT_INITED) == 0);
			err = nxnpi->nxnpi_queue_init(nxprov, nx, qset->nqs_ctx,
			    i, true, drvq, &drvq->nq_ctx);
			if (err != 0) {
				STATS_INC(nifs, NETIF_STATS_LLINK_TXQ_INIT_FAIL);
				SK_ERR("nx: 0x%llx qset: %d queue_init err %d",
				    SK_KVA(nx), qset->nqs_idx, err);
				goto out;
			}
			drvq->nq_flags |= NETIF_QUEUE_EXT_INITED;
		}
	}
out:
	if (err != 0) {
		nx_netif_llink_ext_fini_queues(nx, llink);
	}
	return err;
}

static void
nx_netif_llink_ext_fini_queues(struct kern_nexus *nx, struct netif_llink *llink)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	struct kern_nexus_netif_provider_init *nxnpi;
	struct netif_qset *qset;
	uint8_t i;

	nxnpi = &nxprov->nxprov_netif_ext;
	ASSERT(nxprov->nxprov_netif_ext.nxnpi_qset_fini != NULL);
	ASSERT(nxprov->nxprov_netif_ext.nxnpi_queue_fini != NULL);

	SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
		struct netif_queue *drvq;

		for (i = 0; i < qset->nqs_num_rx_queues; i++) {
			drvq = NETIF_QSET_RX_QUEUE(qset, i);
			if ((drvq->nq_flags & NETIF_QUEUE_EXT_INITED) == 0) {
				continue;
			}
			nxnpi->nxnpi_queue_fini(nxprov, nx, drvq->nq_ctx);
			drvq->nq_flags &= ~NETIF_QUEUE_EXT_INITED;
		}
		for (i = 0; i < qset->nqs_num_tx_queues; i++) {
			drvq = NETIF_QSET_TX_QUEUE(qset, i);
			if ((drvq->nq_flags & NETIF_QUEUE_EXT_INITED) == 0) {
				continue;
			}
			nxnpi->nxnpi_queue_fini(nxprov, nx, drvq->nq_ctx);
			drvq->nq_flags &= ~NETIF_QUEUE_EXT_INITED;
		}
		if ((qset->nqs_flags & NETIF_QSET_FLAG_EXT_INITED) == 0) {
			continue;
		}
		nxnpi->nxnpi_qset_fini(nxprov, nx, qset->nqs_ctx);
		qset->nqs_flags &= ~NETIF_QSET_FLAG_EXT_INITED;
	}
}

int
nx_netif_llink_ext_init_default_queues(struct kern_nexus *nx)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	return nx_netif_llink_ext_init_queues(nx, nif->nif_default_llink);
}

void
nx_netif_llink_ext_fini_default_queues(struct kern_nexus *nx)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	nx_netif_llink_ext_fini_queues(nx, nif->nif_default_llink);
}
