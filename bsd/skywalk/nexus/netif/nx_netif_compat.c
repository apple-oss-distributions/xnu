/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <mach/thread_act.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>

static void na_netif_compat_finalize(struct nexus_netif_adapter *,
    struct ifnet *);
static errno_t nx_netif_compat_receive(struct ifnet *ifp, struct mbuf *m_head,
    struct mbuf *m_tail, const struct ifnet_stat_increment_param *s,
    boolean_t poll, struct thread *tp);
static int nx_netif_compat_catch_rx(struct nexus_netif_compat_adapter *na,
    boolean_t enable);
static int nx_netif_compat_xmit_frame(struct nexus_adapter *, struct mbuf *,
    struct __kern_packet *);

static int nx_netif_compat_na_notify_tx(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_netif_compat_na_notify_rx(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_netif_compat_na_activate(struct nexus_adapter *,
    na_activate_mode_t);
static int nx_netif_compat_na_txsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_netif_compat_na_rxsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static void nx_netif_compat_na_dtor(struct nexus_adapter *na);

static void nx_netif_compat_tx_intr(struct ifnet *, enum txrx, uint32_t,
    uint32_t *);
static inline struct mbuf *nx_netif_compat_ring_alloc(int, int, uint16_t);
static inline void nx_netif_compat_ring_free(struct mbuf *m);
static void nx_netif_compat_ringcb(caddr_t cl, uint32_t size, caddr_t arg);

static uint32_t nx_netif_compat_tx_clean(struct netif_stats *nifs,
    struct __kern_channel_ring *kring);
static void nx_netif_compat_set_tx_event(struct __kern_channel_ring *kring,
    slot_idx_t khead);

static struct nexus_netif_compat_adapter *na_netif_compat_alloc(zalloc_flags_t);
static void na_netif_compat_free(struct nexus_adapter *);
#if DEBUG || DEVELOPMENT
static struct mbuf *nx_netif_rx_split(struct mbuf *, uint32_t);
#endif /* DEBUG || DEVELOPMENT */

#define MBUF_TXQ(m)     ((m)->m_pkthdr.pkt_flowid)
#define MBUF_RXQ(m)     ((m)->m_pkthdr.pkt_flowid)

#define NMB_PROPF_TX_NOTIFY     0x1     /* generate transmit event */
#define NMB_FLAGS_MASK          0x0000ffff
#define NMB_INDEX_MASK          0xffff0000
#define NMB_GET_FLAGS(p)        (((uint32_t)(p) & NMB_FLAGS_MASK))
#define NMB_SET_FLAGS(p, f)     (((uint32_t)(p) & ~NMB_FLAGS_MASK) | (f))
#define NMB_GET_INDEX(p)        (((uint32_t)(p) & NMB_INDEX_MASK) >> 16)
#define NMB_SET_INDEX(p, i)     (((uint32_t)(p) & ~NMB_INDEX_MASK) | (i << 16))

static SKMEM_TYPE_DEFINE(na_netif_compat_zone, struct nexus_netif_compat_adapter);

static int netif_tx_event_mode = 0;

#if (DEVELOPMENT || DEBUG)
SYSCTL_EXTENSIBLE_NODE(_kern_skywalk_netif, OID_AUTO, compat,
    CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk netif Nexus legacy compatibility support");
SYSCTL_INT(_kern_skywalk_netif_compat, OID_AUTO, tx_event_mode,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_tx_event_mode, 0, "");
static uint32_t netif_rx_split = 0;
SYSCTL_UINT(_kern_skywalk_netif_compat, OID_AUTO, rx_split,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_rx_split, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

struct kern_nexus_domain_provider nx_netif_compat_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_NET_IF_COMPAT,
	.nxdom_prov_flags =             NXDOMPROVF_DEFAULT,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_netif_prov_init,
		.dp_cb_fini =           nx_netif_prov_fini,
		.dp_cb_params =         nx_netif_prov_params,
		/*
		 * We must be using the native netif handlers below,
		 * since we act as the default domain provider; see
		 * kern_nexus_register_domain_provider().
		 */
		.dp_cb_mem_new =        nx_netif_prov_mem_new,
		.dp_cb_config =         nx_netif_prov_config,
		.dp_cb_nx_ctor =        nx_netif_prov_nx_ctor,
		.dp_cb_nx_dtor =        nx_netif_prov_nx_dtor,
		.dp_cb_nx_mem_info =    nx_netif_prov_nx_mem_info,
		.dp_cb_nx_mib_get =     nx_netif_prov_nx_mib_get,
		.dp_cb_nx_stop =        nx_netif_prov_nx_stop,
	},
};

struct nexus_ifnet_ops na_netif_compat_ops = {
	.ni_finalize = na_netif_compat_finalize,
	.ni_reap = nx_netif_reap,
	.ni_dequeue = nx_netif_compat_tx_dequeue,
	.ni_get_len = nx_netif_compat_tx_get_len,
};

#define SKMEM_TAG_NETIF_COMPAT_MIT      "com.apple.skywalk.netif.compat.mit"
static SKMEM_TAG_DEFINE(skmem_tag_netif_compat_mit, SKMEM_TAG_NETIF_COMPAT_MIT);

#define SKMEM_TAG_NETIF_COMPAT_POOL     "com.apple.skywalk.netif.compat.pool"
static SKMEM_TAG_DEFINE(skmem_tag_netif_compat_pool, SKMEM_TAG_NETIF_COMPAT_POOL);

void
nx_netif_compat_init(struct nxdom *nxdom)
{
	_CASSERT(NETIF_COMPAT_MAX_MBUF_DATA_COPY <= NETIF_COMPAT_BUF_SIZE);

	/*
	 * We want nxprov_create() coming from userland to use the
	 * netif_compat domain provider, so install it as default.
	 * This is verified by the caller.
	 */
	(void) nxdom_prov_add(nxdom, &nx_netif_compat_prov_s);
}

void
nx_netif_compat_fini(void)
{
	(void) nxdom_prov_del(&nx_netif_compat_prov_s);
}

static struct nexus_netif_compat_adapter *
na_netif_compat_alloc(zalloc_flags_t how)
{
	struct nexus_netif_compat_adapter *nca;

	_CASSERT(offsetof(struct nexus_netif_compat_adapter, nca_up) == 0);

	nca = zalloc_flags(na_netif_compat_zone, how | Z_ZERO);
	if (nca) {
		SK_DF(SK_VERB_MEM, "nca %p ALLOC", SK_KVA(nca));
	}
	return nca;
}

static void
na_netif_compat_free(struct nexus_adapter *na)
{
	struct nexus_netif_compat_adapter *nca =
	    (struct nexus_netif_compat_adapter *)na;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_refcount == 0);

	SK_DF(SK_VERB_MEM, "nca [dev+host] %p FREE", SK_KVA(nca));
	bzero(nca, sizeof(*nca));
	zfree(na_netif_compat_zone, nca);
}

/*
 * Callback invoked when the device driver frees an mbuf used
 * by skywalk to transmit a packet. This usually happens when
 * the NIC notifies the driver that transmission is completed.
 */
static void
nx_netif_compat_ringcb(caddr_t cl, uint32_t size, caddr_t arg)
{
#pragma unused(cl, size)
	struct mbuf *m = (void *)arg;
	struct ifnet *ifp = NULL;
	struct netif_stats *nifs = NULL;
	uintptr_t data; /* not used */
	uint32_t txq;
	errno_t err;

	err = mbuf_get_tx_compl_data(m, (uintptr_t *)&ifp, &data);
	ASSERT(err == 0);

	nifs = &NX_NETIF_PRIVATE(NA(ifp)->nifna_up.na_nx)->nif_stats;
	txq = MBUF_TXQ(m);

	for (;;) {
		uint32_t p = 0, i, f;

		(void) mbuf_cluster_get_prop(m, &p);
		f = NMB_GET_FLAGS(p);
		i = NMB_GET_INDEX(p);

		SK_DF(SK_VERB_NETIF, "%s m 0x%llx txq %u i %u f 0x%x",
		    if_name(ifp), SK_KVA(m), MBUF_TXQ(m), i, f);

		if (f & NMB_PROPF_TX_NOTIFY) {
			uint32_t pn;

			f &= ~NMB_PROPF_TX_NOTIFY;
			pn = NMB_SET_FLAGS(p, f);

			err = mbuf_cluster_set_prop(m, p, pn);
			if (err != 0) {
				if (err == EBUSY) {     /* try again */
					continue;
				}
				/* TODO: adi@apple.com -- what to do? */
				SK_ERR("Failed to clear TX_NOTIFY "
				    "m 0x%llx i %u err %d", SK_KVA(m), i, err);
			} else {
				nx_netif_compat_tx_intr(ifp, NR_TX, txq, NULL);
				SK_DF(SK_VERB_NETIF | SK_VERB_INTR | SK_VERB_TX,
				    "%s TX irq m 0x%llx txq %u i %u f 0x%x",
				    if_name(ifp), SK_KVA(m), MBUF_TXQ(m), i, f);
				STATS_INC(nifs, NETIF_STATS_TX_IRQ);
			}
		}
		break;
	}
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static struct mbuf *
nx_netif_compat_ring_alloc(int how, int len, uint16_t idx)
{
	struct mbuf *m = NULL;
	size_t size = len;
	uint32_t i;

	if (mbuf_ring_cluster_alloc(how, MBUF_TYPE_HEADER, &m,
	    nx_netif_compat_ringcb, &size) != 0) {
		return NULL;
	}

	for (;;) {
		uint32_t p = 0, pn;
		int err;

		(void) mbuf_cluster_get_prop(m, &p);
		pn = NMB_SET_FLAGS(p, 0);
		pn = NMB_SET_INDEX(pn, idx);

		err = mbuf_cluster_set_prop(m, p, pn);
		if (err != 0) {
			if (err == EBUSY) {     /* try again */
				continue;
			}
			SK_ERR("Failed to initialize properties m 0x%llx "
			    "err %d", SK_KVA(m), err);
			m_freem(m);
			return NULL;
		}
		(void) mbuf_cluster_get_prop(m, &p);
		i = NMB_GET_INDEX(p);
		ASSERT(i == idx);
		break;
	}

	SK_DF(SK_VERB_MEM, "alloc m 0x%llx size %u i %u",
	    SK_KVA(m), (uint32_t)size, i);

	return m;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_compat_ring_free(struct mbuf *m)
{
	if (m == NULL) {
		return;
	}

	for (;;) {
		uint32_t p = 0;
		int err;

		(void) mbuf_cluster_get_prop(m, &p);
		err = mbuf_cluster_set_prop(m, p, 0);
		if (err != 0) {
			if (err == EBUSY) {     /* try again */
				continue;
			}
			/* TODO: adi@apple.com -- what to do? */
			SK_ERR("Failed to clear properties m 0x%llx err %d",
			    SK_KVA(m), err);
		}
		break;
	}
	m_freem(m);
}

static void
nx_netif_compat_tx_intr(struct ifnet *ifp, enum txrx t, uint32_t q,
    uint32_t *work_done)
{
	struct nexus_adapter *na = &NA(ifp)->nifna_up;

	if (__improbable(!NA_IS_ACTIVE(na) || q >= na_get_nrings(na, t))) {
		if (q >= na_get_nrings(na, t)) {
			SK_ERR("na \"%s\" (0x%llx) invalid q %u >= %u",
			    na->na_name, SK_KVA(na), q, na_get_nrings(na, t));
		}
	} else {
		(void) nx_netif_mit_tx_intr((NAKR(na, t) + q), kernproc,
		    0, work_done);
	}
}

static int
nx_netif_compat_na_notify_tx(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags)
{
	/*
	 * This should never get executed, as nothing should be invoking
	 * the TX ring notify callback.  The compat adapter directly
	 * calls nx_netif_compat_tx_intr() for TX completion from within
	 * nx_netif_compat_ringcb().
	 *
	 * If we ever get here, use the original na_notify callback
	 * saved during na_activate().
	 */
	return kring->ckr_netif_notify(kring, p, flags);
}

static int
nx_netif_compat_na_notify_rx(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags)
{
	/*
	 * This should never get executed, as nothing should be invoking
	 * the RX ring notify callback.  The compat adapter directly
	 * calls nx_netif_mit_rx_intr() for RX completion from within
	 * nx_netif_compat_receive().
	 *
	 * If we ever get here, use the original na_notify callback
	 * saved during na_activate().
	 */
	return kring->ckr_netif_notify(kring, p, flags);
}

/* Enable/disable skywalk mode for a compat network interface. */
static int
nx_netif_compat_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;
	boolean_t tx_mit, rx_mit, tx_mit_simple, rx_mit_simple, rxpoll;
	uint32_t limit = (uint32_t)sk_netif_compat_rx_mbq_limit;
	struct nx_netif *nif = nifna->nifna_netif;
	struct nexus_netif_compat_adapter *nca;
	ifnet_t ifp = na->na_ifp;
	uint32_t i, r;
	int error;

	ASSERT(na->na_type == NA_NETIF_COMPAT_DEV);
	ASSERT(!(na->na_flags & NAF_HOST_ONLY));

	SK_DF(SK_VERB_NETIF, "na \"%s\" (0x%llx) %s", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode));

	nca = (struct nexus_netif_compat_adapter *)nifna;

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		ASSERT(SKYWALK_CAPABLE(na->na_ifp));

		nx_netif_mit_config(nifna, &tx_mit, &tx_mit_simple,
		    &rx_mit, &rx_mit_simple);

		/*
		 * Init the mitigation support on all the dev TX rings.
		 */
		if (na_get_nrings(na, NR_TX) != 0 && tx_mit) {
			nifna->nifna_tx_mit =
			    skn_alloc_type_array(tx_on, struct nx_netif_mit,
			    na_get_nrings(na, NR_TX), Z_WAITOK,
			    skmem_tag_netif_compat_mit);
			if (nifna->nifna_tx_mit == NULL) {
				SK_ERR("TX mitigation allocation failed");
				error = ENOMEM;
				goto out;
			}
		} else {
			ASSERT(nifna->nifna_tx_mit == NULL);
		}

		/*
		 * Init either poller or mitigation support on all the
		 * dev RX rings; they're mutually exclusive and poller
		 * takes precedence.
		 */
		rxpoll = (net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL));
		if (rxpoll) {
			int err;
			__unused kern_return_t kret;
			thread_precedence_policy_data_t info;

			ASSERT((ifp->if_xflags & IFXF_LEGACY) == 0);
			ASSERT(ifp->if_input_poll != NULL);
			ASSERT(ifp->if_input_ctl != NULL);
			if ((err =
			    kernel_thread_start(netif_rxpoll_compat_thread_func,
			    ifp, &ifp->if_poll_thread)) != KERN_SUCCESS) {
				panic_plain("%s: ifp=%p couldn't get a poll "
				    " thread; err=%d", __func__, ifp, err);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			VERIFY(ifp->if_poll_thread != NULL);

			/* wait until thread is ready */
			lck_mtx_lock(&ifp->if_poll_lock);
			while (!(ifp->if_poll_flags & IF_POLLF_READY)) {
				(void) assert_wait(&ifp->if_poll_flags,
				    THREAD_UNINT);
				lck_mtx_unlock(&ifp->if_poll_lock);
				(void) thread_block(THREAD_CONTINUE_NULL);
				lck_mtx_lock(&ifp->if_poll_lock);
			}
			lck_mtx_unlock(&ifp->if_poll_lock);

			bzero(&info, sizeof(info));
			info.importance = 1;
			kret = thread_policy_set(ifp->if_poll_thread,
			    THREAD_PRECEDENCE_POLICY, (thread_policy_t)&info,
			    THREAD_PRECEDENCE_POLICY_COUNT);
			ASSERT(kret == KERN_SUCCESS);
			limit = if_rcvq_maxlen;
			(void) netif_rxpoll_set_params(ifp, NULL, FALSE);
			ASSERT(nifna->nifna_rx_mit == NULL);
		} else if (rx_mit) {
			nifna->nifna_rx_mit =
			    skn_alloc_type_array(rx_on, struct nx_netif_mit,
			    na_get_nrings(na, NR_RX), Z_WAITOK,
			    skmem_tag_netif_compat_mit);
			if (nifna->nifna_rx_mit == NULL) {
				SK_ERR("RX mitigation allocation failed");
				if (nifna->nifna_tx_mit != NULL) {
					skn_free_type_array(rx_fail,
					    struct nx_netif_mit,
					    na_get_nrings(na, NR_TX),
					    nifna->nifna_tx_mit);
					nifna->nifna_tx_mit = NULL;
				}
				error = ENOMEM;
				goto out;
			}
		}

		/* intercept na_notify callback on the TX rings */
		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			na->na_tx_rings[r].ckr_netif_notify =
			    na->na_tx_rings[r].ckr_na_notify;
			na->na_tx_rings[r].ckr_na_notify =
			    nx_netif_compat_na_notify_tx;
			if (nifna->nifna_tx_mit != NULL) {
				nx_netif_mit_init(nif, na->na_ifp,
				    &nifna->nifna_tx_mit[r],
				    &na->na_tx_rings[r], tx_mit_simple);
			}
		}

		/* intercept na_notify callback on the RX rings */
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			na->na_rx_rings[r].ckr_netif_notify =
			    na->na_rx_rings[r].ckr_na_notify;
			na->na_rx_rings[r].ckr_na_notify =
			    nx_netif_compat_na_notify_rx;
			if (nifna->nifna_rx_mit != NULL) {
				nx_netif_mit_init(nif, na->na_ifp,
				    &nifna->nifna_rx_mit[r],
				    &na->na_rx_rings[r], rx_mit_simple);
			}
		}
		/*
		 * Initialize the rx queue, as nx_netif_compat_receive() can
		 * be called as soon as nx_netif_compat_catch_rx() returns.
		 */
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			struct __kern_channel_ring *kr = &na->na_rx_rings[r];

			nx_mbq_safe_init(kr, &kr->ckr_rx_queue, limit,
			    &nexus_mbq_lock_group, &nexus_lock_attr);
			SK_DF(SK_VERB_NETIF,
			    "na \"%s\" (0x%llx) initialized kr \"%s\" "
			    "(0x%llx) krflags 0x%b", na->na_name, SK_KVA(na),
			    kr->ckr_name, SK_KVA(kr), kr->ckr_flags, CKRF_BITS);
		}

		/*
		 * Prepare packet buffers for the tx rings; don't preallocate
		 * the mbufs here, leave this to nx_netif_compat_na_txsync().
		 */
		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			na->na_tx_rings[r].ckr_tx_pool = NULL;
		}

		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			na->na_tx_rings[r].ckr_tx_pool =
			    skn_alloc_type_array(tx_pool_on, struct mbuf *,
			    na_get_nslots(na, NR_TX), Z_WAITOK,
			    skmem_tag_netif_compat_pool);
			if (na->na_tx_rings[r].ckr_tx_pool == NULL) {
				SK_ERR("ckr_tx_pool allocation failed");
				error = ENOMEM;
				goto free_tx_pools;
			}
		}

		/* Prepare to intercept incoming traffic. */
		error = nx_netif_compat_catch_rx(nca, TRUE);
		if (error != 0) {
			SK_ERR("RX intercept failed (%d)", error);
			goto uncatch;
		}
		nx_netif_filter_enable(nifna->nifna_netif);
		nx_netif_flow_enable(nifna->nifna_netif);
		os_atomic_or(&na->na_flags, NAF_ACTIVE, relaxed);
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		ASSERT(SKYWALK_CAPABLE(na->na_ifp));
		break;

	case NA_ACTIVATE_MODE_OFF:
		/*
		 * Note that here we cannot assert SKYWALK_CAPABLE()
		 * as we're called in the destructor path.
		 */
		os_atomic_andnot(&na->na_flags, NAF_ACTIVE, relaxed);
		nx_netif_flow_disable(nifna->nifna_netif);
		nx_netif_filter_disable(nifna->nifna_netif);

		/*
		 * Signal the poller thread to terminate itself, and
		 * wait for it to exit.
		 */
		if (ifp->if_poll_thread != THREAD_NULL) {
			ASSERT(net_rxpoll && (ifp->if_eflags & IFEF_RXPOLL));
			ASSERT((ifp->if_xflags & IFXF_LEGACY) == 0);
			lck_mtx_lock_spin(&ifp->if_poll_lock);
			ifp->if_poll_flags |= IF_POLLF_TERMINATING;
			wakeup_one((caddr_t)&ifp->if_poll_thread);
			lck_mtx_unlock(&ifp->if_poll_lock);

			/* wait for poller thread to terminate */
			lck_mtx_lock(&ifp->if_poll_lock);
			while (ifp->if_poll_thread != THREAD_NULL) {
				SK_DF(SK_VERB_NETIF_POLL,
				    "%s: waiting for poller thread to terminate",
				    if_name(ifp));
				(void) msleep(&ifp->if_poll_thread,
				    &ifp->if_poll_lock, (PZERO - 1),
				    "netif_poll_thread_exit", NULL);
			}
			lck_mtx_unlock(&ifp->if_poll_lock);
			SK_DF(SK_VERB_NETIF_POLL,
			    "%s: poller thread termination complete",
			    if_name(ifp));
		}

		/* Do not intercept packets on the rx path. */
		(void) nx_netif_compat_catch_rx(nca, FALSE);

		/* Free the mbufs going to the channel rings */
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			nx_mbq_safe_purge(&na->na_rx_rings[r].ckr_rx_queue);
			nx_mbq_safe_destroy(&na->na_rx_rings[r].ckr_rx_queue);
		}

		/* reset all TX notify callbacks */
		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			na->na_tx_rings[r].ckr_na_notify =
			    na->na_tx_rings[r].ckr_netif_notify;
			na->na_tx_rings[r].ckr_netif_notify = NULL;
			if (nifna->nifna_tx_mit != NULL) {
				na->na_tx_rings[r].ckr_netif_mit_stats = NULL;
				nx_netif_mit_cleanup(&nifna->nifna_tx_mit[r]);
			}
		}

		if (nifna->nifna_tx_mit != NULL) {
			skn_free_type_array(tx_off, struct nx_netif_mit,
			    na_get_nrings(na, NR_TX), nifna->nifna_tx_mit);
			nifna->nifna_tx_mit = NULL;
		}

		/* reset all RX notify callbacks */
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			na->na_rx_rings[r].ckr_na_notify =
			    na->na_rx_rings[r].ckr_netif_notify;
			na->na_rx_rings[r].ckr_netif_notify = NULL;
			if (nifna->nifna_rx_mit != NULL) {
				na->na_rx_rings[r].ckr_netif_mit_stats = NULL;
				nx_netif_mit_cleanup(&nifna->nifna_rx_mit[r]);
			}
		}
		if (nifna->nifna_rx_mit != NULL) {
			skn_free_type_array(rx_off, struct nx_netif_mit,
			    na_get_nrings(na, NR_RX), nifna->nifna_rx_mit);
			nifna->nifna_rx_mit = NULL;
		}

		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			for (i = 0; i < na_get_nslots(na, NR_TX); i++) {
				nx_netif_compat_ring_free(na->
				    na_tx_rings[r].ckr_tx_pool[i]);
				na->na_tx_rings[r].ckr_tx_pool[i] = NULL;
			}
			skn_free_type_array(tx_pool_off,
			    struct mbuf *, na_get_nslots(na, NR_TX),
			    na->na_tx_rings[r].ckr_tx_pool);
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return 0;

uncatch:
	(void) nx_netif_compat_catch_rx(nca, FALSE);

free_tx_pools:
	for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
		if (na->na_tx_rings[r].ckr_tx_pool == NULL) {
			continue;
		}
		for (i = 0; i < na_get_nslots(na, NR_TX); i++) {
			nx_netif_compat_ring_free(
				na->na_tx_rings[r].ckr_tx_pool[i]);
			na->na_tx_rings[r].ckr_tx_pool[i] = NULL;
		}
		skn_free_type_array(tx_pool, struct mbuf *,
		    na_get_nslots(na, NR_TX), na->na_tx_rings[r].ckr_tx_pool);
		na->na_tx_rings[r].ckr_tx_pool = NULL;
	}
	if (nifna->nifna_tx_mit != NULL) {
		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			nx_netif_mit_cleanup(&nifna->nifna_tx_mit[r]);
		}
		skn_free_type_array(tx, struct nx_netif_mit,
		    na_get_nrings(na, NR_TX), nifna->nifna_tx_mit);
		nifna->nifna_tx_mit = NULL;
	}
	if (nifna->nifna_rx_mit != NULL) {
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			nx_netif_mit_cleanup(&nifna->nifna_rx_mit[r]);
		}
		skn_free_type_array(rx, struct nx_netif_mit,
		    na_get_nrings(na, NR_RX), nifna->nifna_rx_mit);
		nifna->nifna_rx_mit = NULL;
	}
	for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
		nx_mbq_safe_destroy(&na->na_rx_rings[r].ckr_rx_queue);
	}
out:

	return error;
}

/*
 * Record completed transmissions and update ktail.
 *
 * The oldest tx buffer not yet completed is at ckr_ktail + 1,
 * ckr_khead is the first unsent buffer.
 */
/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static uint32_t
nx_netif_compat_tx_clean(struct netif_stats *nifs,
    struct __kern_channel_ring *kring)
{
	const slot_idx_t lim = kring->ckr_lim;
	slot_idx_t nm_i = SLOT_NEXT(kring->ckr_ktail, lim);
	slot_idx_t khead = kring->ckr_khead;
	uint32_t n = 0;
	struct mbuf **ckr_tx_pool = kring->ckr_tx_pool;

	while (nm_i != khead) { /* buffers not completed */
		struct mbuf *m = ckr_tx_pool[nm_i];

		if (__improbable(m == NULL)) {
			/* this is done, try to replenish the entry */
			VERIFY(nm_i <= UINT16_MAX);
			ckr_tx_pool[nm_i] = m =
			    nx_netif_compat_ring_alloc(M_WAITOK,
			    kring->ckr_max_pkt_len, (uint16_t)nm_i);
			if (__improbable(m == NULL)) {
				STATS_INC(nifs, NETIF_STATS_DROP_NOMEM_MBUF);
				STATS_INC(nifs, NETIF_STATS_DROP);
				SK_DF(SK_VERB_MEM,
				    "mbuf allocation failed (slot %u)", nm_i);
				/* XXX how do we proceed ? break ? */
				return -ENOMEM;
			}
		} else if (mbuf_ring_cluster_is_active(m)) {
			break; /* This mbuf is still busy */
		}
		n++;
		nm_i = SLOT_NEXT(nm_i, lim);
	}
	kring->ckr_ktail = SLOT_PREV(nm_i, lim);

	SK_RDF(SK_VERB_NETIF, 10, "kr \"%s\" (0x%llx) tx completed [%u] -> "
	    "kh %u kt %u | rh %u rt %u", kring->ckr_name, SK_KVA(kring),
	    n, kring->ckr_khead, kring->ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail);

	return n;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_compat_set_tx_event(struct __kern_channel_ring *kring,
    slot_idx_t khead)
{
	const slot_idx_t lim = kring->ckr_lim;
	slot_idx_t ntc = SLOT_NEXT(kring->ckr_ktail, lim); /* next to clean */
	struct mbuf *m;
	slot_idx_t e;

	if (ntc == khead) {
		return; /* all buffers are free */
	}
	/*
	 * We have pending packet in the driver between ckr_ktail+1 and
	 * ckr_khead, and we have to choose one of these slots to generate
	 * a TX notification.  There is a race, but this is only called
	 * within TX sync which does a double check.
	 */
	if (__probable(netif_tx_event_mode == 0)) {
		/*
		 * Choose the first pending slot, to be safe against drivers
		 * reordering mbuf transmissions.
		 */
		e = ntc;
	} else {
		/*
		 * Choose a slot in the middle, so that we don't risk ending
		 * up in a situation where the client continuously wake up,
		 * fills one or a few TX slots and go to sleep again.
		 */
		slot_idx_t n = lim + 1;

		if (khead >= ntc) {
			e = (khead + ntc) >> 1;
		} else { /* wrap around */
			e = (khead + n + ntc) >> 1;
			if (e >= n) {
				e -= n;
			}
		}

		if (__improbable(e >= n)) {
			SK_ERR("This cannot happen");
			e = 0;
		}
	}
	m = kring->ckr_tx_pool[e];

	for (;;) {
		uint32_t p = 0, pn, i, f;
		int err;

		(void) mbuf_cluster_get_prop(m, &p);
		f = NMB_GET_FLAGS(p);
		i = NMB_GET_INDEX(p);

		if (f & NMB_PROPF_TX_NOTIFY) {
			/*
			 * This can happen if there is already an event
			 * on the ring slot 'e': There is nothing to do.
			 */
			SK_DF(SK_VERB_NETIF | SK_VERB_NOTIFY | SK_VERB_TX,
			    "TX_NOTIFY already set at %u m 0x%llx kc %u ntc %u",
			    e, SK_KVA(m), khead, ntc);
			return;
		}

		f |= NMB_PROPF_TX_NOTIFY;
		pn = NMB_SET_FLAGS(p, f);

		err = mbuf_cluster_set_prop(m, p, pn);
		if (err != 0) {
			if (err == EBUSY) {     /* try again */
				continue;
			}
			/* TODO: adi@apple.com -- what to do? */
			SK_ERR("Failed to set TX_NOTIFY at %u m 0x%llx kh %u "
			    "ntc %u, err %d", e, SK_KVA(m), khead, ntc, err);
		} else {
			SK_DF(SK_VERB_NETIF | SK_VERB_NOTIFY | SK_VERB_TX,
			    "Request TX_NOTIFY at %u m 0x%llx kh %u ntc %u",
			    e, SK_KVA(m), khead, ntc);
		}
		break;
	}
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_netif_compat_na_txsync_log(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags, slot_idx_t nm_i)
{
	SK_DF(SK_VERB_NETIF | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0x%x "
	    "nm_i %u, kh %u kt %u | rh %u rt %u",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags, nm_i, kring->ckr_khead, kring->ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail);
}
#endif /* SK_LOG */

/*
 * nx_netif_compat_na_txsync() transforms packets into mbufs and passes
 * them to the device driver.
 */
static int
nx_netif_compat_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	struct nexus_adapter *na = KRNA(kring);
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(na->na_nx)->nif_stats;
	slot_idx_t nm_i; /* index into the channel ring */        // j
	const slot_idx_t head = kring->ckr_rhead;
	uint32_t slot_count = 0;
	uint32_t byte_count = 0;

	STATS_INC(nifs, NETIF_STATS_TX_SYNC);

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	/*
	 * First part: process new packets to send.
	 */
	nm_i = kring->ckr_khead;
	if (nm_i != head) {     /* we have new packets to send */
		while (nm_i != head) {
			struct __kern_slot_desc *sd = KR_KSD(kring, nm_i);

			/* device-specific */
			struct mbuf *m;
			int tx_ret;
			/*
			 * Take a mbuf from the tx pool (replenishing the pool
			 * entry if necessary) and copy in the user packet.
			 */
			VERIFY(nm_i <= UINT16_MAX);
			m = kring->ckr_tx_pool[nm_i];
			if (__improbable(m == NULL)) {
				kring->ckr_tx_pool[nm_i] = m =
				    nx_netif_compat_ring_alloc(M_WAITOK,
				    kring->ckr_max_pkt_len, (uint16_t)nm_i);
				if (__improbable(m == NULL)) {
					STATS_INC(nifs, NETIF_STATS_DROP);
					STATS_INC(nifs,
					    NETIF_STATS_DROP_NOMEM_MBUF);
					SK_DF(SK_VERB_MEM,
					    "%s(%d) kr \"%s\" (0x%llx) "
					    "krflags 0x%b ckr_tx_pool[%u] "
					    "allocation failed",
					    sk_proc_name_address(p),
					    sk_proc_pid(p), kring->ckr_name,
					    SK_KVA(kring), kring->ckr_flags,
					    CKRF_BITS, nm_i);
					/*
					 * Here we could schedule a timer
					 * which retries to replenish after
					 * a while, and notifies the client
					 * when it manages to replenish some
					 * slot.  In any cae we break early
					 * to avoid crashes.
					 */
					break;
				}
				STATS_INC(nifs, NETIF_STATS_TX_REPL);
			}

			byte_count += sd->sd_pkt->pkt_length;
			slot_count++;

			/*
			 * We should ask notifications when CS_REPORT is set,
			 * or roughly every half ring.  To optimize this,
			 * we set a notification event when the client runs
			 * out of TX ring space, or when transmission fails.
			 * In the latter case we also break early.
			 */
			tx_ret = nx_netif_compat_xmit_frame(na, m, sd->sd_pkt);
			if (__improbable(tx_ret)) {
				SK_RD(5, "start_xmit failed: err %d "
				    "[nm_i %u, h %u, kt %u]",
				    tx_ret, nm_i, head, kring->ckr_ktail);
				/*
				 * No room for this mbuf in the device driver.
				 * Request a notification FOR A PREVIOUS MBUF,
				 * then call nx_netif_compat_tx_clean(kring) to
				 * do the double check and see if we can free
				 * more buffers.  If there is space continue,
				 * else break; NOTE: the double check is
				 * necessary if the problem occurs in the
				 * txsync call after selrecord().  Also, we
				 * need some way to tell the caller that not
				 * all buffers were queued onto the device
				 * (this was not a problem with native skywalk
				 * driver where space is preallocated). The
				 * bridge has a similar problem and we solve
				 * it there by dropping the excess packets.
				 */
				nx_netif_compat_set_tx_event(kring, nm_i);
				if (nx_netif_compat_tx_clean(nifs, kring)) {
					/* space now available */
					continue;
				} else {
					break;
				}
			}
			nm_i = SLOT_NEXT(nm_i, kring->ckr_lim);
			STATS_INC(nifs, NETIF_STATS_TX_PACKETS);
		}

		/*
		 * Update khead to the next slot to transmit; Here nm_i
		 * is not necesarrily head, we could break early.
		 */
		kring->ckr_khead = nm_i;

		kr_update_stats(kring, slot_count, byte_count);
	}

	/*
	 * Second, reclaim completed buffers
	 */
	if ((flags & NA_SYNCF_FORCE_RECLAIM) || kr_txempty(kring)) {
		/*
		 * No more available slots? Set a notification event on a
		 * channel slot that will be cleaned in the future.  No
		 * doublecheck is performed, since nx_netif_compat_na_txsync()
		 * will be called twice by ch_event().
		 */
		nx_netif_compat_set_tx_event(kring, nm_i);
	}
	kring->ckr_pending_intr = 0;

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_NETIF) != 0)) {
		nx_netif_compat_na_txsync_log(kring, p, flags, nm_i);
	}
#endif /* SK_LOG */

	(void) nx_netif_compat_tx_clean(nifs, kring);

	return 0;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_netif_compat_receive_log1(const struct __kern_channel_ring *kring,
    struct nx_mbq *q)
{
	SK_RD(10, "kr \"%s\" (0x%llx) krflags 0x%b FULL "
	    "(qlen %u qsize %llu), kc %u kt %u", kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, nx_mbq_len(q),
	    nx_mbq_size(q), kring->ckr_khead, kring->ckr_ktail);
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_netif_compat_receive_log2(const struct __kern_channel_ring *kring,
    struct nx_mbq *q, const struct ifnet_stat_increment_param *s)
{
	SK_RDF(SK_VERB_RX, 10, "kr \"%s\" (0x%llx) krflags 0x%b OK, "
	    "added %u packets %u bytes, now qlen %u qsize %llu",
	    kring->ckr_name, SK_KVA(kring), kring->ckr_flags, CKRF_BITS,
	    s->packets_in, s->bytes_in, nx_mbq_len(q), nx_mbq_size(q));
}
#endif /* SK_LOG */

/*
 * This is the default RX path for the compat netif nexus. Packets
 * are enqueued and later extracted by nx_netif_compat_na_rxsync().
 */
/* TODO: adi@apple.com -- implement chaining */
static errno_t
nx_netif_compat_receive(struct ifnet *ifp, struct mbuf *m_head,
    struct mbuf *m_tail, const struct ifnet_stat_increment_param *s,
    boolean_t poll, struct thread *tp)
{
#pragma unused(tp)
	boolean_t ifp_rxpoll = ((ifp->if_eflags & IFEF_RXPOLL) && net_rxpoll);
	struct nexus_adapter *na = &NA(ifp)->nifna_up;
	struct __kern_channel_ring *kring;
	struct netif_stats *nifs;
	uint32_t r, work_done;
	unsigned int qlimit;
	struct nx_mbq *q;
	errno_t err = 0;

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	if (__improbable(m_head == NULL)) {
		ASSERT(m_tail == NULL);
		ASSERT(poll);
		ASSERT(s->bytes_in == 0);
		ASSERT(s->packets_in == 0);
	}

	/* BEGIN CSTYLED */
	/*
	 * TODO: adi@apple.com -- this needs to be revisited once we
	 * have a clear definition of how multiple RX rings are mapped
	 * to flows; this would involve the hardware/driver doing some
	 * kind of classification and RSS-like demuxing.
	 *
	 * When we enable that, we'll need to consider sifting thru the
	 * mbuf chain we get from the caller, and enqueue them across
	 * per-ring temporary mbuf queue (along with marking the ring
	 * indicating pending packets.)  During second stage processing,
	 * we'll issue nx_netif_mit_rx_intr() on each marked ring to
	 * dispatch the packets upstream.
	 *
	 * r = MBUF_RXQ(m);
	 *
	 * if (r >= na->na_num_rx_rings)
	 *     r = r % na->na_num_rx_rings;
	 *
	 * kring = &na->na_rx_rings[r];
	 * q = &kring->ckr_rx_queue;
	 *
	 * For now, target only the first RX ring (ring 0).
	 */
	/* END CSTYLED */
	r = 0;  /* receive ring number */
	kring = &na->na_rx_rings[r];

	ASSERT(na->na_type == NA_NETIF_COMPAT_DEV);
	nifs = &NX_NETIF_PRIVATE(na->na_nx)->nif_stats;

	if (__improbable((!NA_IS_ACTIVE(na)) || KR_DROP(kring))) {
		/* BEGIN CSTYLED */
		/*
		 * If we deal with multiple rings, change above to:
		 *
		 * if (!NA_IS_ACTIVE(na) || r >= na_get_nrings(na, NR_RX)))
		 *
		 * then here do:
		 *
		 * if (r >= na_get_nrings(na, NR_RX)) {
		 *      SK_ERR("na \"%s\" (0x%llx) invalid r %u >= %u",
		 *          na->na_name, SK_KVA(na), r,
		 *          na_get_nrings(na, NR_RX));
		 * }
		 */
		/* END CSTYLED */
		m_freem_list(m_head);
		if (!NA_IS_ACTIVE(na)) {
			STATS_ADD(nifs, NETIF_STATS_DROP_NA_INACTIVE,
			    s->packets_in);
		} else if (KR_DROP(kring)) {
			STATS_ADD(nifs, NETIF_STATS_DROP_KRDROP_MODE,
			    s->packets_in);
		}
		STATS_ADD(nifs, NETIF_STATS_DROP, s->packets_in);
		err = ENXIO;
		goto done;
	}
	if (__improbable(m_head == NULL)) {
		goto send_packets;
	}

	q = &kring->ckr_rx_queue;
	nx_mbq_lock_spin(q);
	qlimit = nx_mbq_limit(q);
	if (ifp_rxpoll) {
		/*
		 * qlimit of the receive queue is much smaller when the
		 * interface is in oppurtunistic polling mode. In this case
		 * when the interface is operating in interrupt mode,
		 * a sudden burst of input packets can cause the receive queue
		 * to quickly buildup due to scheduling latency in waking up
		 * the poller thread. To avoid drops here due to this latency
		 * we provide a leeway on the qlimit.
		 */
		qlimit <<= 5;
	}
	if (__improbable(nx_mbq_len(q) > qlimit)) {
#if SK_LOG
		if (__improbable(sk_verbose != 0)) {
			nx_netif_compat_receive_log1(kring, q);
		}
#endif /* SK_LOG */
		nx_mbq_unlock(q);
		m_freem_list(m_head);
		STATS_ADD(nifs, NETIF_STATS_DROP_RXQ_OVFL, s->packets_in);
		STATS_ADD(nifs, NETIF_STATS_DROP, s->packets_in);
		goto send_packets;
	}
	nx_mbq_enq_multi(q, m_head, m_tail, s->packets_in, s->bytes_in);

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_NETIF) != 0)) {
		nx_netif_compat_receive_log2(kring, q, s);
	}
#endif /* SK_LOG */

	nx_mbq_unlock(q);

	(void) ifnet_stat_increment_in(ifp, s->packets_in, s->bytes_in,
	    s->errors_in);

	if (poll) {
		/* update incremental poll stats */
		PKTCNTR_ADD(&ifp->if_poll_tstats, s->packets_in, s->bytes_in);
	}

send_packets:
	/*
	 * if the interface supports oppurtunistic input polling, then the
	 * input packet processing is performed in context of the poller thread.
	 */
	if (!poll && ifp_rxpoll) {
		/* wakeup the poller thread */
		ifnet_poll(ifp);
	} else {
		/*
		 * wakeup the mitigation thread if needed to perform input
		 * packet processing.
		 * if the interface supports oppurtunistic input polling, then
		 * mitigation thread is not created and the input packet
		 * processing happens in context of the poller thread.
		 */
		err = nx_netif_mit_rx_intr((NAKR(na, NR_RX) + r), kernproc, 0,
		    &work_done);
	}
done:
	return err;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_netif_compat_na_rxsync_log(const struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags, slot_idx_t nm_i)
{
	SK_DF(SK_VERB_NETIF | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b "
	    "ring %u flags 0x%x nm_i %u kt %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, kring->ckr_ring_id, flags, nm_i, kring->ckr_ktail);
}
#endif /* SK_LOG */

#if DEBUG || DEVELOPMENT
/*
 * Split an mbuf chain at offset "split", such that the first mbuf
 * is a zero-length M_PKTHDR, followed by the rest of the mbufs.
 * Typically, the "split" value is equal to the size of the link
 * layer header, e.g. Ethernet header.
 */
static struct mbuf *
nx_netif_rx_split(struct mbuf *m0, uint32_t split)
{
	struct mbuf *m = m0;

	if (split == 0) {
		split = MHLEN;
		M_PREPEND(m, split, M_DONTWAIT, 0);
	} else {
		m->m_data -= split;
		m->m_len += split;
		m_pktlen(m) += split;

		ASSERT((uintptr_t)m->m_data >= (uintptr_t)mbuf_datastart(m));
		ASSERT((uintptr_t)m->m_data < ((uintptr_t)mbuf_datastart(m) +
		    mbuf_maxlen(m)));
	}
	if (m != NULL) {
		struct mbuf *n = m_split(m, split, M_DONTWAIT);
		if (n == NULL) {
			m_freem(m);
			return NULL;
		}
		m0 = m;
		ASSERT((uint32_t)m->m_len == split);
		m->m_data += split;
		m->m_len -= split;
		while (m->m_next != NULL) {
			m = m->m_next;
		}
		m->m_next = n;
		m = m0;
		m_pktlen(m) = m_length2(m, NULL);
	}

	return m;
}
#endif /* DEBUG || DEVELOPMENT */

/*
 * nx_netif_compat_na_rxsync() extracts mbufs from the queue filled by
 * nx_netif_compat_receive() and puts their content in the channel
 * receive ring.
 *
 * Accesses to kring are serialized via kring->ckr_rx_queue lock, because
 * the rx handler is asynchronous,
 */
static int
nx_netif_compat_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	struct nexus_adapter *na = KRNA(kring);
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;
	struct nx_netif *nif = nifna->nifna_netif;
	slot_idx_t nm_i;        /* index into the channel ring */
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(na->na_nx)->nif_stats;
	uint32_t npkts = 0;
	uint32_t byte_count = 0;
	const slot_idx_t lim = kring->ckr_lim;
	const slot_idx_t head = kring->ckr_rhead;
	boolean_t force_update = ((flags & NA_SYNCF_FORCE_READ) ||
	    kring->ckr_pending_intr != 0);
	struct mbuf *m;
	uint32_t n;
	uint32_t avail; /* in slots */
	int err, mlen;
	boolean_t attach_mbuf = FALSE;
	struct nx_mbq *q, tmpq;
	struct kern_pbufpool *pp = kring->ckr_pp;
	uint32_t ph_cnt, i = 0;

	ASSERT(pp->pp_max_frags == 1);
	ASSERT(head <= lim);

	/*
	 * First part: skip past packets that userspace has released.
	 * This can possibly make room for the second part.
	 * equivalent to kr_reclaim()
	 */
	if (kring->ckr_khead != head) {
		kring->ckr_khead = head;
		/* ensure global visibility */
		os_atomic_thread_fence(seq_cst);
	}

	STATS_INC(nifs, NETIF_STATS_RX_SYNC);

	/*
	 * Second part: import newly received packets.
	 */
	if (!force_update) {
		return 0;
	}

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	/* first empty slot in the receive ring */
	nm_i = kring->ckr_ktail;

	/*
	 * Compute the available space (in bytes) in this ring.
	 * The first slot that is not considered in is the one
	 * before ckr_khead.
	 */
	avail = kr_available_slots_rxring(kring);
	if (__improbable(avail == 0)) {
		return 0;
	}

	if (NA_KERNEL_ONLY(na)) {
		ASSERT(na->na_ifp != NULL &&
		    fsw_ifp_to_fsw(na->na_ifp) != NULL);
		/*
		 * We are not supporting attachment to bridge flowswitch
		 * for now, until we support PKT_F_MBUF_DATA packets
		 * in bridge flowswitch.
		 */
		attach_mbuf = TRUE;
	}

	/*
	 * Quickly move all of ckr_rx_queue to a temporary queue to dequeue
	 * from.  For each mbuf, attach or copy it to the packet attached
	 * to the slot.  Release the lock while we're doing that, to allow
	 * for the input thread to enqueue.
	 */
	q = &kring->ckr_rx_queue;
	nx_mbq_init(&tmpq, NX_MBQ_NO_LIMIT);
	nx_mbq_lock_spin(q);
	nx_mbq_concat(&tmpq, q);
	nx_mbq_unlock(q);

	if (__improbable(nx_mbq_len(&tmpq) == 0)) {
		return 0;
	}

	ph_cnt = MIN(avail, nx_mbq_len(&tmpq));
	err = kern_pbufpool_alloc_batch_nosleep(pp, 1, kring->ckr_scratch,
	    &ph_cnt);
	if (err == ENOMEM) {
		SK_DF(SK_VERB_MEM, "%s(%p) failed to alloc %d pkts for kr "
		    "0x%llu", sk_proc_name_address(p), sk_proc_pid(p), ph_cnt,
		    SK_KVA(kring));
		goto done;
	}
	ASSERT(ph_cnt != 0);

	for (n = 0; (n < ph_cnt) &&
	    ((m = nx_mbq_deq(&tmpq)) != NULL); n++) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, nm_i);
		struct __kern_packet *pkt;
		kern_packet_t ph;
		uint8_t hlen;
		uint16_t tag;
		char *h;

		ASSERT(m->m_flags & M_PKTHDR);
		mlen = m_pktlen(m);
		h = m->m_pkthdr.pkt_hdr;
		if (__improbable(mlen == 0 || h == NULL ||
		    h < (char *)mbuf_datastart(m) || h > (char *)m->m_data)) {
			STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
			SK_RD(5, "kr \"%s\" (0x%llx) m 0x%llx len %d"
			    "bad pkt_hdr", kring->ckr_name,
			    SK_KVA(kring), SK_KVA(m), mlen);
			m_freem(m);
			m = NULL;
			continue;
		}

		hlen = (uint8_t)(m->m_data - (uintptr_t)h);
		mlen += hlen;

#if DEBUG || DEVELOPMENT
		if (__improbable(netif_rx_split != 0)) {
			/* callee frees mbuf upon failure */
			if ((m = nx_netif_rx_split(m, hlen)) == NULL) {
				continue;
			}

			ASSERT((uintptr_t)m->m_data >=
			    (uintptr_t)mbuf_datastart(m));
			ASSERT((uintptr_t)m->m_data <
			    ((uintptr_t)mbuf_datastart(m) +
			    mbuf_maxlen(m)));
		}
#endif /* DEBUG || DEVELOPMENT */

		ph = kring->ckr_scratch[i];
		ASSERT(ph != 0);
		kring->ckr_scratch[i] = 0;
		pkt = SK_PTR_ADDR_KPKT(ph);
		++i;

		/*
		 * Wind back the data pointer to include any frame headers
		 * as part of the copy below.  The header length is then
		 * stored in the corresponding metadata area of the buffer.
		 */
		m->m_data -= hlen;
		m->m_len += hlen;
		m->m_pkthdr.len += hlen;
		ASSERT(mlen == m->m_pkthdr.len);

		pkt->pkt_link_flags = 0;
		if (m->m_flags & M_HASFCS) {
			pkt->pkt_link_flags |= PKT_LINKF_ETHFCS;
		}
		if (mbuf_get_vlan_tag(m, &tag) == 0) {
			(void) kern_packet_set_vlan_tag(SK_PKT2PH(pkt), tag,
			    FALSE);
		}
		SK_DF(SK_VERB_NETIF | SK_VERB_SYNC | SK_VERB_RX,
		    "kr \"%s\" (0x%llx) m 0x%llx idx %u slot_len %d",
		    kring->ckr_name, SK_KVA(kring), SK_KVA(m), nm_i, mlen);

		if (__probable(attach_mbuf)) {
			STATS_INC(nifs, NETIF_STATS_RX_COPY_ATTACH);
			err = __packet_initialize_with_mbuf(pkt, m, 0, hlen);
			VERIFY(err == 0);
		} else if (__probable(mlen <= (int)PP_BUF_SIZE_DEF(pp))) {
			STATS_INC(nifs, NETIF_STATS_RX_COPY_DIRECT);
			/*
			 * We're sending this up to a user channel opened
			 * directly to the netif; copy everything.
			 */
			err = __packet_set_headroom(ph, 0);
			VERIFY(err == 0);
			err = __packet_set_link_header_length(ph, hlen);
			VERIFY(err == 0);
			nif->nif_pkt_copy_from_mbuf(NR_RX, ph, 0, m, 0,
			    mlen, FALSE, 0);
			/* finalize and attach the packet */
			err = __packet_finalize(ph);
			VERIFY(err == 0);
			m_freem(m);
			m = NULL;
		} else {
			STATS_INC(nifs, NETIF_STATS_DROP_BADLEN);
			STATS_INC(nifs, NETIF_STATS_DROP);
			m_freem(m);
			m = NULL;
			kern_pbufpool_free(pp, ph);
			ph = 0;
			pkt = NULL;
			continue;
		}

		err = KR_SLOT_ATTACH_METADATA(kring, ksd,
		    (struct __kern_quantum *)pkt);
		ASSERT(err == 0);

		byte_count += mlen;
		++npkts;
		ASSERT(npkts < kring->ckr_num_slots);
		nm_i = SLOT_NEXT(nm_i, lim);
	}

	if (__improbable(i < ph_cnt)) {
		kern_pbufpool_free_batch(pp, &kring->ckr_scratch[i],
		    (ph_cnt - i));
	}

	ASSERT(npkts <= ph_cnt);
	kr_update_stats(kring, npkts, byte_count);

	if (npkts != 0) {
		kring->ckr_ktail = nm_i;
		STATS_ADD(nifs, NETIF_STATS_RX_PACKETS, npkts);
	}
	kring->ckr_pending_intr = 0;

#if SK_LOG
	if (__improbable((sk_verbose & SK_VERB_NETIF) != 0)) {
		nx_netif_compat_na_rxsync_log(kring, p, flags, nm_i);
	}
#endif /* SK_LOG */

done:
	/*
	 * If we didn't process all packets in temporary queue,
	 * move them back to the head of ckr_rx_queue.
	 */
	if (!nx_mbq_empty(&tmpq)) {
		nx_mbq_lock_spin(q);
		nx_mbq_concat(&tmpq, q);
		ASSERT(nx_mbq_empty(q));
		nx_mbq_concat(q, &tmpq);
		nx_mbq_unlock(q);
	}
	ASSERT(nx_mbq_empty(&tmpq));

	return 0;
}

static void
nx_netif_compat_na_dtor(struct nexus_adapter *na)
{
	struct ifnet *ifp;
	struct nexus_netif_compat_adapter *nca =
	    (struct nexus_netif_compat_adapter *)na;

	SK_LOCK_ASSERT_HELD();

	SK_DF(SK_VERB_NETIF, "na \"%s\" (0x%llx)", na->na_name, SK_KVA(na));

	/*
	 * If the finalizer callback hasn't been called for whatever
	 * reasons, pick up the embryonic ifnet stored in na_private.
	 * Otherwise, release the I/O refcnt of a non-NULL na_ifp.
	 */
	if ((ifp = na->na_ifp) == NULL) {
		ifp = na->na_private;
		na->na_private = NULL;
	} else {
		ifnet_decr_iorefcnt(ifp);
		na->na_ifp = NULL;
	}

	if (nca->nca_up.nifna_netif != NULL) {
		nx_netif_release(nca->nca_up.nifna_netif);
		nca->nca_up.nifna_netif = NULL;
	}
	ASSERT(!SKYWALK_NATIVE(ifp));
}

/*
 * nx_netif_compat_attach() makes it possible to use skywalk on
 * a device without native skywalk support.
 * This is less performant than native support but potentially
 * faster than raw sockets or similar schemes.
 */
int
nx_netif_compat_attach(struct kern_nexus *nx, struct ifnet *ifp)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_netif_compat_adapter *devnca = NULL;
	struct nexus_netif_compat_adapter *hostnca = NULL;
	struct nexus_adapter *devna = NULL;
	struct nexus_adapter *hostna = NULL;
	boolean_t embryonic = FALSE;
	uint32_t tx_rings, tx_slots;
	int retval = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!SKYWALK_NATIVE(ifp));
	ASSERT(!SKYWALK_CAPABLE(ifp));
	ASSERT(ifp->if_na == NULL);
	ASSERT(ifp->if_na_ops == NULL);

	devnca = na_netif_compat_alloc(Z_WAITOK);
	hostnca = na_netif_compat_alloc(Z_WAITOK);

	/*
	 * We can be called for two different interface states:
	 *
	 * Fully attached: get an io ref count; upon success, this
	 * holds a reference to the ifnet for the ifp pointer stored
	 * in 'na_ifp' down below for both adapters.
	 *
	 * Embryonic: temporary hold the ifnet in na_private, which
	 * upon a successful ifnet_attach(), will be moved over to
	 * the 'na_ifp' with an io ref count held.
	 *
	 * The ifnet in 'na_ifp' will be released by na_release_locked().
	 */
	if (!ifnet_is_attached(ifp, 1)) {
		if (!(ifp->if_refflags & IFRF_EMBRYONIC)) {
			ifp = NULL;
			retval = ENXIO;
			goto err;
		}
		embryonic = TRUE;
	}

	/* initialize the (compat) device netif adapter */
	devnca->nca_up.nifna_netif = nif;
	nx_netif_retain(nif);
	devna = &devnca->nca_up.nifna_up;
	(void) strncpy(devna->na_name, ifp->if_xname, sizeof(devna->na_name) - 1);
	devna->na_name[sizeof(devna->na_name) - 1] = '\0';
	uuid_generate_random(devna->na_uuid);
	if (embryonic) {
		/*
		 * We will move this over to na_ifp once
		 * the interface is fully attached.
		 */
		devna->na_private = ifp;
		ASSERT(devna->na_ifp == NULL);
	} else {
		ASSERT(devna->na_private == NULL);
		/* use I/O refcnt from ifnet_is_attached() */
		devna->na_ifp = ifp;
	}

	devna->na_type = NA_NETIF_COMPAT_DEV;
	devna->na_free = na_netif_compat_free;
	devna->na_activate = nx_netif_compat_na_activate;
	devna->na_txsync = nx_netif_compat_na_txsync;
	devna->na_rxsync = nx_netif_compat_na_rxsync;
	devna->na_dtor = nx_netif_compat_na_dtor;
	devna->na_krings_create = nx_netif_dev_krings_create;
	devna->na_krings_delete = nx_netif_dev_krings_delete;
	devna->na_special = nx_netif_na_special;

	*(nexus_stats_type_t *)(uintptr_t)&devna->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	if (skywalk_netif_direct_allowed(ifp->if_xname)) {
		tx_rings = nxp->nxp_tx_rings;
		tx_slots = nxp->nxp_tx_slots;
	} else {
		tx_rings = 0;
		tx_slots = 0;
	}
	na_set_nrings(devna, NR_TX, tx_rings);
	na_set_nrings(devna, NR_RX, nxp->nxp_rx_rings);
	na_set_nslots(devna, NR_TX, tx_slots);
	na_set_nslots(devna, NR_RX, nxp->nxp_rx_slots);
	/*
	 * Verify upper bounds; the parameters must have already been
	 * validated by nxdom_prov_params() by the time we get here.
	 */
	ASSERT(na_get_nrings(devna, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(devna, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(devna, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(devna, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	na_attach_common(devna, nx, &nx_netif_compat_prov_s);

	if ((retval = NX_DOM_PROV(nx)->nxdom_prov_mem_new(NX_DOM_PROV(nx),
	    nx, devna)) != 0) {
		ASSERT(devna->na_arena == NULL);
		/* we've transferred the refcnt to na_ifp above */
		ifp = NULL;
		goto err;
	}
	ASSERT(devna->na_arena != NULL);

	*(uint32_t *)(uintptr_t)&devna->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(devna->na_flowadv_max == 0 ||
	    skmem_arena_nexus(devna->na_arena)->arn_flowadv_obj != NULL);

	/* setup packet copy routines */
	if (skmem_arena_nexus(devna->na_arena)->arn_rx_pp->pp_max_frags > 1) {
		nif->nif_pkt_copy_from_mbuf =
		    pkt_copy_multi_buflet_from_mbuf;
		nif->nif_pkt_copy_to_mbuf =
		    pkt_copy_multi_buflet_to_mbuf;
	} else {
		nif->nif_pkt_copy_from_mbuf = pkt_copy_from_mbuf;
		nif->nif_pkt_copy_to_mbuf = pkt_copy_to_mbuf;
	}

	/* initialize the host netif adapter */
	hostnca->nca_up.nifna_netif = nif;
	nx_netif_retain(nif);
	hostna = &hostnca->nca_up.nifna_up;
	(void) snprintf(hostna->na_name, sizeof(hostna->na_name),
	    "%s^", devna->na_name);
	uuid_generate_random(hostna->na_uuid);
	if (embryonic) {
		/*
		 * We will move this over to na_ifp once
		 * the interface is fully attached.
		 */
		hostna->na_private = ifp;
		ASSERT(hostna->na_ifp == NULL);
	} else {
		ASSERT(hostna->na_private == NULL);
		hostna->na_ifp = devna->na_ifp;
		ifnet_incr_iorefcnt(hostna->na_ifp);
	}
	hostna->na_type = NA_NETIF_COMPAT_HOST;
	hostna->na_free = na_netif_compat_free;
	hostna->na_activate = nx_netif_host_na_activate;
	hostna->na_txsync = nx_netif_host_na_txsync;
	hostna->na_rxsync = nx_netif_host_na_rxsync;
	hostna->na_dtor = nx_netif_compat_na_dtor;
	hostna->na_krings_create = nx_netif_host_krings_create;
	hostna->na_krings_delete = nx_netif_host_krings_delete;
	hostna->na_special = nx_netif_host_na_special;

	os_atomic_or(&hostna->na_flags, NAF_HOST_ONLY, relaxed);
	*(nexus_stats_type_t *)(uintptr_t)&hostna->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	na_set_nrings(hostna, NR_TX, 1);
	na_set_nrings(hostna, NR_RX, 0);
	na_set_nslots(hostna, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(hostna, NR_RX, 0);

	na_attach_common(hostna, nx, &nx_netif_prov_s);

	if ((retval = NX_DOM_PROV(nx)->nxdom_prov_mem_new(NX_DOM_PROV(nx),
	    nx, hostna)) != 0) {
		ASSERT(hostna->na_arena == NULL);
		/* we've transferred the refcnt to na_ifp above */
		ifp = NULL;
		goto err;
	}
	ASSERT(hostna->na_arena != NULL);

	*(uint32_t *)(uintptr_t)&hostna->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(hostna->na_flowadv_max == 0 ||
	    skmem_arena_nexus(hostna->na_arena)->arn_flowadv_obj != NULL);

	/* these will be undone by destructor  */
	ifp->if_na_ops = &na_netif_compat_ops;
	ifp->if_na = &devnca->nca_up;
	na_retain_locked(devna);
	na_retain_locked(hostna);

	SKYWALK_SET_CAPABLE(ifp);

	NETIF_WLOCK(nif);
	nif->nif_ifp = ifp;
	retval = nx_port_alloc(nx, NEXUS_PORT_NET_IF_DEV, NULL, &devna, kernproc);
	ASSERT(retval == 0);
	retval = nx_port_alloc(nx, NEXUS_PORT_NET_IF_HOST, NULL, &hostna, kernproc);
	ASSERT(retval == 0);
	NETIF_WUNLOCK(nif);

#if SK_LOG
	uuid_string_t uuidstr;
	SK_DF(SK_VERB_NETIF, "na_name: \"%s\"", devna->na_name);
	SK_DF(SK_VERB_NETIF, "  UUID:        %s",
	    sk_uuid_unparse(devna->na_uuid, uuidstr));
	SK_DF(SK_VERB_NETIF, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(devna->na_nx), NX_DOM(devna->na_nx)->nxdom_name,
	    NX_DOM_PROV(devna->na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_NETIF, "  flags:       0x%b", devna->na_flags, NAF_BITS);
	SK_DF(SK_VERB_NETIF, "  flowadv_max: %u", devna->na_flowadv_max);
	SK_DF(SK_VERB_NETIF, "  rings:       tx %u rx %u",
	    na_get_nrings(devna, NR_TX), na_get_nrings(devna, NR_RX));
	SK_DF(SK_VERB_NETIF, "  slots:       tx %u rx %u",
	    na_get_nslots(devna, NR_TX), na_get_nslots(devna, NR_RX));
#if CONFIG_NEXUS_USER_PIPE
	SK_DF(SK_VERB_NETIF, "  next_pipe:   %u", devna->na_next_pipe);
	SK_DF(SK_VERB_NETIF, "  max_pipes:   %u", devna->na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
	SK_DF(SK_VERB_NETIF, "  ifp:         0x%llx %s [ioref %u]",
	    SK_KVA(ifp), ifp->if_xname, ifp->if_refio);
	SK_DF(SK_VERB_NETIF, "hostna: \"%s\"", hostna->na_name);
	SK_DF(SK_VERB_NETIF, "  UUID:        %s",
	    sk_uuid_unparse(hostna->na_uuid, uuidstr));
	SK_DF(SK_VERB_NETIF, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(hostna->na_nx), NX_DOM(hostna->na_nx)->nxdom_name,
	    NX_DOM_PROV(hostna->na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_NETIF, "  flags:       0x%b",
	    hostna->na_flags, NAF_BITS);
	SK_DF(SK_VERB_NETIF, "  flowadv_max: %u", hostna->na_flowadv_max);
	SK_DF(SK_VERB_NETIF, "  rings:       tx %u rx %u",
	    na_get_nrings(hostna, NR_TX), na_get_nrings(hostna, NR_RX));
	SK_DF(SK_VERB_NETIF, "  slots:       tx %u rx %u",
	    na_get_nslots(hostna, NR_TX), na_get_nslots(hostna, NR_RX));
#if CONFIG_NEXUS_USER_PIPE
	SK_DF(SK_VERB_NETIF, "  next_pipe:   %u", hostna->na_next_pipe);
	SK_DF(SK_VERB_NETIF, "  max_pipes:   %u", hostna->na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
	SK_DF(SK_VERB_NETIF, "  ifp:       0x%llx %s [ioref %u]", SK_KVA(ifp),
	    ifp->if_xname, ifp->if_refio);
#endif /* SK_LOG */

err:
	if (retval != 0) {
		ASSERT(ifp == NULL);
		if (devna != NULL) {
			if (devna->na_arena != NULL) {
				skmem_arena_release(devna->na_arena);
				devna->na_arena = NULL;
			}
			if (devna->na_ifp != NULL) {
				ifnet_decr_iorefcnt(devna->na_ifp);
				devna->na_ifp = NULL;
			}
			devna->na_private = NULL;
		}
		if (hostna != NULL) {
			if (hostna->na_arena != NULL) {
				skmem_arena_release(hostna->na_arena);
				hostna->na_arena = NULL;
			}
			if (hostna->na_ifp != NULL) {
				ifnet_decr_iorefcnt(hostna->na_ifp);
				hostna->na_ifp = NULL;
			}
			hostna->na_private = NULL;
		}
		if (devnca != NULL) {
			if (devnca->nca_up.nifna_netif != NULL) {
				nx_netif_release(devnca->nca_up.nifna_netif);
				devnca->nca_up.nifna_netif = NULL;
			}
			na_netif_compat_free((struct nexus_adapter *)devnca);
		}
		if (hostnca != NULL) {
			if (hostnca->nca_up.nifna_netif != NULL) {
				nx_netif_release(hostnca->nca_up.nifna_netif);
				hostnca->nca_up.nifna_netif = NULL;
			}
			na_netif_compat_free((struct nexus_adapter *)hostnca);
		}
	}
	return retval;
}

static void
na_netif_compat_finalize(struct nexus_netif_adapter *nifna, struct ifnet *ifp)
{
	na_netif_finalize(nifna, ifp);
}

/*
 * Intercept the rx routine in the standard device driver.
 * Second argument is non-zero to intercept, 0 to restore
 */
static int
nx_netif_compat_catch_rx(struct nexus_netif_compat_adapter *nca,
    boolean_t enable)
{
	struct ifnet *ifp = nca->nca_up.nifna_up.na_ifp;
	int err = 0;

	ASSERT(!(nca->nca_up.nifna_up.na_flags & NAF_HOST_ONLY));

	if (enable) {
		err = dlil_set_input_handler(ifp, nx_netif_compat_receive);
	} else {
		dlil_reset_input_handler(ifp);
	}
	return err;
}

/*
 * Transmit routine used by nx_netif_compat_na_txsync(). Returns 0 on success
 * and non-zero on error (which may be packet drops or other errors).
 * len identifies the channel buffer, m is the (preallocated) mbuf to use
 * for transmissions.
 *
 * We should add a reference to the mbuf so the m_freem() at the end
 * of the transmission does not consume resources.
 *
 * On FreeBSD, and on multiqueue cards, we can force the queue using
 *      if (M_HASHTYPE_GET(m) != M_HASHTYPE_NONE)
 *              i = m->m_pkthdr.flowid % adapter->num_queues;
 *      else
 *              i = curcpu % adapter->num_queues;
 *
 */
static int
nx_netif_compat_xmit_frame(struct nexus_adapter *na, struct mbuf *m,
    struct __kern_packet *pkt)
{
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(na->na_nx)->nif_stats;
	struct ifnet *ifp = na->na_ifp;
	kern_packet_t ph = SK_PTR_ENCODE(pkt, METADATA_TYPE(pkt),
	    METADATA_SUBTYPE(pkt));
	uint32_t len;
	int ret = 0;

	if ((ret = mbuf_ring_cluster_activate(m)) != 0) {
		panic("Failed to activate mbuf ring cluster 0x%llx (%d)",
		    SK_KVA(m), ret);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	len = pkt->pkt_length;

	/*
	 * The mbuf should be a cluster from our special pool,
	 * so we do not need to do an m_copyback but just copy.
	 */
	if (m->m_ext.ext_size < len) {
		SK_RD(5, "size %u < len %u", m->m_ext.ext_size, len);
		len = m->m_ext.ext_size;
	}

	STATS_INC(nifs, NETIF_STATS_TX_COPY_MBUF);
	if (PACKET_HAS_PARTIAL_CHECKSUM(pkt)) {
		STATS_INC(nifs, NETIF_STATS_TX_COPY_SUM);
	}

	nif->nif_pkt_copy_to_mbuf(NR_TX, ph, pkt->pkt_headroom, m, 0, len,
	    PACKET_HAS_PARTIAL_CHECKSUM(pkt), pkt->pkt_csum_tx_start_off);

	/* used for tx notification */
	ret = mbuf_set_tx_compl_data(m, (uintptr_t)ifp, (uintptr_t)NULL);
	ASSERT(ret == 0);

	ret = dlil_output_handler(ifp, m);
	return ret;
}
