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
#include <IOKit/IOBSD.h>
#include <sys/sdt.h>

static uint32_t nx_netif_tx_processed_q_size = 2048;
uint32_t nx_netif_filter_default_drop = 0;
#define DEFAULT_DROP_ENTITLEMENT "com.apple.private.skywalk.default-drop"

static int
nx_netif_default_drop_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint32_t newval;
	int changed;
	int err;

	err = sysctl_io_number(req, nx_netif_filter_default_drop,
	    sizeof(nx_netif_filter_default_drop), &newval, &changed);
	if (err != 0) {
		return err;
	}
	if (changed != 0) {
		if (newval != 0 && newval != 1) {
			return EINVAL;
		}
		if (!kauth_cred_issuser(kauth_cred_get()) &&
		    !IOCurrentTaskHasEntitlement(DEFAULT_DROP_ENTITLEMENT)) {
			return EPERM;
		}
		nx_netif_filter_default_drop = newval;
	}
	return 0;
}

SYSCTL_PROC(_kern_skywalk_netif, OID_AUTO, default_drop,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    nx_netif_default_drop_sysctl, "IU", "Skywalk filter default drop");

SK_NO_INLINE_ATTRIBUTE
static errno_t
nx_netif_default_cb(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, uint32_t flags)
{
	if ((flags & NETIF_FILTER_RX) != 0) {
		return nx_netif_filter_rx_cb(nifna, pkt_chain, flags);
	}
	ASSERT((flags & NETIF_FILTER_TX) != 0);
	return nx_netif_filter_tx_cb(nifna, pkt_chain, flags);
}

errno_t
nx_netif_filter_inject(struct nexus_netif_adapter *nifna,
    struct netif_filter *f, struct __kern_packet *pkt_chain, uint32_t flags)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	int drop_stat = -1;
	uint32_t cnt;
	errno_t err;

	ASSERT(pkt_chain != NULL);
	lck_mtx_lock(&nif->nif_filter_lock);
	if ((nif->nif_filter_flags & NETIF_FILTER_FLAG_ENABLED) == 0) {
		DTRACE_SKYWALK2(disabled, struct nexus_netif_adapter *,
		    nifna, struct netif_filter *, f);
		drop_stat = NETIF_STATS_FILTER_DROP_DISABLED;
		err = ENETDOWN;
		goto drop;
	}
	if (f != NULL) {
		f = STAILQ_NEXT(f, nf_link);
		if (f != NULL) {
			f->nf_refcnt++;
		}
		/*
		 * f == NULL means we have reached the end of the filter chain.
		 * we call the default callback to forward the packet chain to
		 * its regular path.
		 */
	} else {
		ASSERT((flags & NETIF_FILTER_SOURCE) != 0);
		f = STAILQ_FIRST(&nif->nif_filter_list);
		if (__improbable(f == NULL)) {
			/*
			 * We got here because:
			 * 1. The caller checked the filter count without the
			 *    filter lock.
			 * 2. Found non-zero filters. Entering this path.
			 * 3. Filter was removed by the time the filter lock got
			 *    acquired.
			 */
			DTRACE_SKYWALK1(removed, struct nexus_netif_adapter *,
			    nifna);
			drop_stat = NETIF_STATS_FILTER_DROP_REMOVED;
			err = ENOENT;
		} else {
			f->nf_refcnt++;
		}
	}
drop:
	lck_mtx_unlock(&nif->nif_filter_lock);
	if (drop_stat != -1) {
		int dropcnt = 0;

		nx_netif_free_packet_chain(pkt_chain, &dropcnt);
		STATS_ADD(nifs, drop_stat, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
		DTRACE_SKYWALK3(inject__drop, struct nexus_netif_adapter *,
		    nifna, uint32_t, flags, int, dropcnt);
		return err;
	}

	nx_netif_pkt_chain_info(pkt_chain, NULL, &cnt, NULL);
	if ((flags & NETIF_FILTER_SOURCE) != 0) {
		if ((flags & NETIF_FILTER_RX) != 0) {
			STATS_ADD(nifs, NETIF_STATS_FILTER_RX_ENTER, cnt);
		} else {
			ASSERT((flags & NETIF_FILTER_TX) != 0);
			STATS_ADD(nifs, NETIF_STATS_FILTER_TX_ENTER, cnt);
		}
	} else if (f == NULL) {
		if ((flags & NETIF_FILTER_RX) != 0) {
			STATS_ADD(nifs, NETIF_STATS_FILTER_RX_EXIT, cnt);
		} else {
			ASSERT((flags & NETIF_FILTER_TX) != 0);
			STATS_ADD(nifs, NETIF_STATS_FILTER_TX_EXIT, cnt);
		}
	}

	/*
	 * No locks are held while calling callbacks.
	 */
	if (f != NULL) {
		err = f->nf_cb_func(f->nf_cb_arg, pkt_chain, flags);
	} else {
		err = nx_netif_default_cb(nifna, pkt_chain, flags);
	}
	lck_mtx_lock(&nif->nif_filter_lock);
	if (f != NULL) {
		if (--f->nf_refcnt == 0) {
			wakeup(&f->nf_refcnt);
		}
	}
	lck_mtx_unlock(&nif->nif_filter_lock);
	return err;
}

errno_t
nx_netif_filter_add(struct nx_netif *nif, nexus_port_t port, void *cb_arg,
    errno_t (*cb_func)(void *, struct __kern_packet *, uint32_t),
    struct netif_filter **nfp)
{
	struct netif_filter *nf = NULL;
	struct netif_stats *nifs = &nif->nif_stats;
	errno_t err = 0;

	lck_mtx_lock(&nif->nif_filter_lock);
	STAILQ_FOREACH(nf, &nif->nif_filter_list, nf_link) {
		if (nf->nf_port == port) {
			break;
		}
	}
	if (nf != NULL) {
		err = EEXIST;
		goto done;
	}
	nf = sk_alloc_type(struct netif_filter, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_netif_filter);
	nf->nf_port = port;
	nf->nf_refcnt = 0;
	nf->nf_cb_arg = cb_arg;
	nf->nf_cb_func = cb_func;
	STAILQ_INSERT_TAIL(&nif->nif_filter_list, nf, nf_link);
	STATS_INC(nifs, NETIF_STATS_FILTER_ADD);
	nif->nif_filter_cnt++;
	*nfp = nf;
done:
	lck_mtx_unlock(&nif->nif_filter_lock);
	if (err == 0) {
		/*
		 * Unlike DLIL filter, netif filter holds the attach
		 * IO refcnt on the underlying interface (by virtue of
		 * being part of netif), and thus adjusting this counter
		 * can be done atomically without having to worry about
		 * any synchronization with the detacher thread.
		 */
		ifnet_filter_update_tso(nif->nif_ifp, TRUE);
	}
	return err;
}

static void
nx_netif_filter_flushq(struct nx_netif *nif)
{
	struct netif_stats *nifs = &nif->nif_stats;
	uint32_t flushed = 0;
	int i;

	if (NETIF_IS_COMPAT(nif)) {
		for (i = 0; i < MBUF_TC_MAX; i++) {
			struct nx_mbq *q = &nif->nif_tx_processed_mbq[i];

			flushed += nx_mbq_len(q);
			nx_mbq_safe_purge(q);
		}
	} else {
		for (i = 0; i < KPKT_TC_MAX; i++) {
			struct nx_pktq *q = &nif->nif_tx_processed_pktq[i];

			flushed += nx_pktq_len(q);
			nx_pktq_safe_purge(q);
		}
	}
	if (flushed > 0) {
		DTRACE_SKYWALK2(filter__flush, struct nx_netif *, nif,
		    uint32_t, flushed);
		STATS_ADD(nifs, NETIF_STATS_FILTER_TX_FLUSH, flushed);
	}
}

errno_t
nx_netif_filter_remove(struct nx_netif *nif, struct netif_filter *nf)
{
	struct netif_stats *nifs = &nif->nif_stats;

	lck_mtx_lock(&nif->nif_filter_lock);
	STAILQ_REMOVE(&nif->nif_filter_list, nf, netif_filter, nf_link);
	if (--nif->nif_filter_cnt == 0) {
		nx_netif_filter_flushq(nif);
	}
	while (nf->nf_refcnt > 0) {
		DTRACE_SKYWALK1(wait__refcnt, struct netif_filter *, nf);
		(void) msleep(&nf->nf_refcnt,
		    &nif->nif_filter_lock, (PZERO + 1),
		    __FUNCTION__, NULL);
	}
	STATS_INC(nifs, NETIF_STATS_FILTER_REMOVE);
	lck_mtx_unlock(&nif->nif_filter_lock);
	sk_free_type(struct netif_filter, nf);
	/*
	 * Unlike DLIL filter, netif filter holds the attach
	 * IO refcnt on the underlying interface (by virtue of
	 * being part of netif), and thus adjusting this counter
	 * can be done atomically without having to worry about
	 * any synchronization with the detacher thread.
	 */
	ifnet_filter_update_tso(nif->nif_ifp, FALSE);
	return 0;
}

static void
nx_netif_filter_initq(struct nx_netif *nif)
{
	int i;

	if (NETIF_IS_COMPAT(nif)) {
		for (i = 0; i < MBUF_TC_MAX; i++) {
			nx_mbq_safe_init(NULL, &nif->nif_tx_processed_mbq[i],
			    nx_netif_tx_processed_q_size, &nexus_mbq_lock_group,
			    &nexus_lock_attr);
		}
	} else {
		for (i = 0; i < KPKT_TC_MAX; i++) {
			nx_pktq_safe_init(NULL, &nif->nif_tx_processed_pktq[i],
			    nx_netif_tx_processed_q_size, &nexus_pktq_lock_group,
			    &nexus_lock_attr);
		}
	}
}

void
nx_netif_filter_init(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	if (!ifnet_needs_netif_netagent(ifp)) {
		SK_DF(SK_VERB_FILTER, "%s: filters not supported due "
		    "to missing if_attach_nx flag", if_name(ifp));
		return;
	}
	if (NETIF_IS_LOW_LATENCY(nif)) {
		SK_DF(SK_VERB_FILTER, "%s: filters not supported on "
		    "low latency interface", if_name(ifp));
		return;
	}
	if (ifp->if_family != IFNET_FAMILY_ETHERNET &&
	    ifp->if_family != IFNET_FAMILY_UTUN &&
	    ifp->if_family != IFNET_FAMILY_IPSEC) {
		SK_DF(SK_VERB_FILTER, "%s: filters not supported on "
		    "interface family %d", if_name(ifp), ifp->if_family);
		return;
	}
	ASSERT(nif->nif_filter_flags == 0);
	lck_mtx_init(&nif->nif_filter_lock, &nexus_lock_group, &nexus_lock_attr);
	STAILQ_INIT(&nif->nif_filter_list);
	nx_netif_filter_initq(nif);

	nif->nif_filter_cnt = 0;
	nif->nif_filter_flags |= NETIF_FILTER_FLAG_INITIALIZED;
	SK_DF(SK_VERB_FILTER, "%s: filters initialized", if_name(ifp));
}

static void
nx_netif_filter_finiq(struct nx_netif *nif)
{
	int i;

	if (NETIF_IS_COMPAT(nif)) {
		for (i = 0; i < MBUF_TC_MAX; i++) {
			nx_mbq_safe_destroy(&nif->nif_tx_processed_mbq[i]);
		}
	} else {
		for (i = 0; i < KPKT_TC_MAX; i++) {
			nx_pktq_safe_destroy(&nif->nif_tx_processed_pktq[i]);
		}
	}
}

void
nx_netif_filter_fini(struct nx_netif *nif)
{
	if ((nif->nif_filter_flags & NETIF_FILTER_FLAG_INITIALIZED) == 0) {
		SK_DF(SK_VERB_FILTER, "%s: filters not initialized",
		    if_name(nif->nif_ifp));
		return;
	}
	nif->nif_filter_flags &= ~NETIF_FILTER_FLAG_INITIALIZED;

	/* This should've been cleared before we get to this point */
	ASSERT((nif->nif_filter_flags & NETIF_FILTER_FLAG_ENABLED) == 0);
	ASSERT(nif->nif_filter_cnt == 0);

	/*
	 * XXX
	 * We defer the buffer pool cleanup to here to ensure that everything
	 * has been quiesced.
	 */
	if (nif->nif_filter_pp != NULL) {
		pp_close(nif->nif_filter_pp);
		nif->nif_filter_pp = NULL;
	}
	nx_netif_filter_finiq(nif);
	ASSERT(STAILQ_EMPTY(&nif->nif_filter_list));
	lck_mtx_destroy(&nif->nif_filter_lock, &nexus_lock_group);
	SK_DF(SK_VERB_FILTER, "%s: filters uninitialization done",
	    if_name(nif->nif_ifp));
}

static void
nx_netif_filter_set_enable(struct nx_netif *nif, boolean_t set)
{
	/*
	 * No locking needed while checking for the initialized bit because
	 * if this were not set, no other flag would be modified.
	 */
	if ((nif->nif_filter_flags & NETIF_FILTER_FLAG_INITIALIZED) == 0) {
		return;
	}
	lck_mtx_lock(&nif->nif_filter_lock);
	if (set) {
		SK_DF(SK_VERB_FILTER, "%s: filter enabled, nif 0x%llx",
		    if_name(nif->nif_ifp), SK_KVA(nif));
		nif->nif_filter_flags |= NETIF_FILTER_FLAG_ENABLED;
	} else {
		SK_DF(SK_VERB_FILTER, "%s: filter disabled, nif 0x%llx",
		    if_name(nif->nif_ifp), SK_KVA(nif));
		nif->nif_filter_flags &= ~NETIF_FILTER_FLAG_ENABLED;
	}
	lck_mtx_unlock(&nif->nif_filter_lock);
}

void
nx_netif_filter_enable(struct nx_netif *nif)
{
	nx_netif_filter_set_enable(nif, TRUE);
}

void
nx_netif_filter_disable(struct nx_netif *nif)
{
	nx_netif_filter_set_enable(nif, FALSE);
}
