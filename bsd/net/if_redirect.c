/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
 * if_redirect.c
 * Virtual network interface that redirects traffic to a delegate interface.
 */

#include <sys/sysctl.h>
#include <net/dlil.h>
#include <net/ethernet.h>
#include <net/kpi_interface.h>
#include <net/bpf.h>
#include <net/if_media.h>
#include <net/if_ether.h>
#include <net/if_redirect.h>
#include <os/log.h>

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>

#define RD_NAME                 "rd"
#define RD_MAXUNIT              IF_MAXUNIT
#define RD_ZONE_MAX_ELEM        MIN(IFNETS_MAX, RD_MAXUNIT)
#define RD_MAX_MTU              2048

#define RD_MAX_TX_RINGS         1
#define RD_MAX_RX_RINGS         1
#define RD_POOL_SIZE            1024

static uint8_t default_mac[ETHER_ADDR_LEN] = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5};

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, redirect, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Redirect interface");

static int if_redirect_debug = 0;
SYSCTL_INT(_net_link_redirect, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_redirect_debug, 0, "Redirect interface debug logs");

os_log_t redirect_log_handle = NULL;

#define RDLOG(level, format, ...) do {                                        \
	if (level == LOG_ERR) {                                               \
	        os_log_error(redirect_log_handle, "%s: " format "\n",         \
	            __FUNCTION__, ##__VA_ARGS__);                             \
	} else {                                                              \
	        if (__probable(if_redirect_debug == 0)) {                     \
	                break;                                                \
	        }                                                             \
	        if (level == LOG_DEBUG) {                                     \
	                os_log_debug(redirect_log_handle, "%s: " format "\n", \
	                    __FUNCTION__, ##__VA_ARGS__);                     \
	        } else if (level == LOG_INFO) {                               \
	                os_log_info(redirect_log_handle, "%s: " format "\n",  \
	                    __FUNCTION__, ##__VA_ARGS__);                     \
	        }                                                             \
	}                                                                     \
} while (0)

#define RDLOG_ERR(format, ...) RDLOG(LOG_ERR, format, ##__VA_ARGS__)
#define RDLOG_DBG(format, ...) RDLOG(LOG_DEBUG, format, ##__VA_ARGS__)
#define RDLOG_INFO(format, ...) RDLOG(LOG_INFO, format, ##__VA_ARGS__)

#define RD_MEDIA_LIST_MAX 27

typedef struct {
	uuid_t                 rnx_provider;
	uuid_t                 rnx_instance;
} redirect_nx, *redirect_nx_t;

typedef struct {
	char                   rd_name[IFNAMSIZ]; /* our unique id */
	lck_mtx_t              rd_lock;
	uint32_t               rd_ftype;
	ifnet_t                rd_ifp;
	ifnet_t                rd_delegate_ifp;

	/* General state of the interface */
	boolean_t              rd_detaching;
	boolean_t              rd_connected;

	/* Used for tracking delegate related state info */
	boolean_t              rd_self_ref;
	boolean_t              rd_delegate_parent_set;
	boolean_t              rd_delegate_ref;
	boolean_t              rd_fsw_rx_cb_set;
	boolean_t              rd_delegate_set;
	boolean_t              rd_mac_addr_set;
	boolean_t              rd_detach_notify_set;

	unsigned int           rd_max_mtu;
	uint32_t               rd_retain_count;
	kern_pbufpool_t        rd_pp;
	kern_channel_ring_t    rd_rx_ring[RD_MAX_RX_RINGS];
	kern_channel_ring_t    rd_tx_ring[RD_MAX_TX_RINGS];
	redirect_nx            rd_nx;
	struct netif_stats     *rd_nifs;
	void                   *rd_intf_adv_kern_ctx;
	thread_call_t          rd_doorbell_tcall;
	boolean_t              rd_doorbell_tcall_active;
	boolean_t              rd_waiting_for_tcall;
	bool                   rd_intf_adv_enabled;
	kern_nexus_capab_interface_advisory_notify_fn_t rd_intf_adv_notify;
} if_redirect, *if_redirect_t;

static if_redirect_t ifnet_get_if_redirect(ifnet_t);
static int redirect_clone_create(struct if_clone *, uint32_t, void *);
static int redirect_clone_destroy(ifnet_t);
static int redirect_ioctl(ifnet_t, u_long, void *);
static void redirect_if_free(ifnet_t);
static void redirect_free(if_redirect_t);
static errno_t redirect_demux(ifnet_t, mbuf_t, char *, protocol_family_t *);
static errno_t redirect_add_proto(ifnet_t, protocol_family_t,
    const struct ifnet_demux_desc *, uint32_t);
static errno_t redirect_del_proto(ifnet_t, protocol_family_t);
static void redirect_clear_delegate_locked(if_redirect_t);
static void redirect_clear_delegate(if_redirect_t);

static struct if_clone
    redirect_cloner = IF_CLONE_INITIALIZER(RD_NAME,
    redirect_clone_create,
    redirect_clone_destroy,
    0,
    RD_MAXUNIT);
static void interface_link_event(ifnet_t ifp, uint32_t event_code);

static LCK_GRP_DECLARE(redirect_lock_group, "redirect");
static LCK_ATTR_DECLARE(redirect_lock_attr, 0, 0);

#define RD_LOCK_INIT(rd) \
	lck_mtx_init(&(rd)->rd_lock, &redirect_lock_group, &redirect_lock_attr)
#define RD_LOCK(rd) \
	lck_mtx_lock(&(rd)->rd_lock)
#define RD_UNLOCK(rd) \
	lck_mtx_unlock(&(rd)->rd_lock)
#define RD_LOCK_DESTROY(rd) \
	lck_mtx_destroy(&(rd)->rd_lock, &redirect_lock_group)

static inline boolean_t
redirect_is_usable(if_redirect_t rd)
{
	return !rd->rd_detaching && rd->rd_connected;
}

static inline unsigned int
redirect_max_mtu(ifnet_t ifp)
{
	if_redirect_t rd;
	unsigned int max_mtu = ETHERMTU;

	rd = ifnet_get_if_redirect(ifp);
	if (rd == NULL) {
		RDLOG_ERR("rd is NULL");
		goto done;
	}
	max_mtu = rd->rd_max_mtu;
done:
	return max_mtu;
}

static void
redirect_free(if_redirect_t rd)
{
	VERIFY(rd->rd_retain_count == 0);

	if (rd->rd_pp != NULL) {
		pp_release(rd->rd_pp);
		rd->rd_pp = NULL;
	}
	RD_LOCK_DESTROY(rd);
	RDLOG_DBG("%s", rd->rd_name);
	kfree_type(if_redirect, rd);
}

static void
redirect_release(if_redirect_t rd)
{
	uint32_t old_retain_count;

	old_retain_count = OSDecrementAtomic(&rd->rd_retain_count);
	switch (old_retain_count) {
	case 0:
		VERIFY(old_retain_count != 0);
		break;
	case 1:
		redirect_free(rd);
		break;
	default:
		break;
	}
	return;
}

static void
redirect_retain(if_redirect_t rd)
{
	OSIncrementAtomic(&rd->rd_retain_count);
}

static void
redirect_bpf_tap(ifnet_t ifp, kern_packet_t pkt, bool input)
{
	uint32_t dlt;

	switch (ifp->if_family) {
	case IFNET_FAMILY_ETHERNET:
		dlt = DLT_EN10MB;
		break;
	case IFNET_FAMILY_CELLULAR:
	case IFNET_FAMILY_UTUN:
	case IFNET_FAMILY_IPSEC:
		dlt = DLT_RAW;
		break;
	default:
		DTRACE_SKYWALK1(invalid__family, ifnet_t, ifp);
		return;
	}

	if (input) {
		bpf_tap_packet_in(ifp, dlt, pkt, NULL, 0);
	} else {
		bpf_tap_packet_out(ifp, dlt, pkt, NULL, 0);
	}
}

static void
redirect_packet_pool_init_prepare(if_redirect_t rd,
    struct kern_pbufpool_init *pp_init)
{
	uint32_t max_mtu = rd->rd_max_mtu;

	bzero(pp_init, sizeof(*pp_init));
	pp_init->kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init->kbi_flags |= KBIF_VIRTUAL_DEVICE;
	pp_init->kbi_packets = RD_POOL_SIZE;
	pp_init->kbi_bufsize = max_mtu;
	pp_init->kbi_max_frags = 1;
	pp_init->kbi_buflets =  (2 * pp_init->kbi_packets); /* Tx/Rx pool */
	pp_init->kbi_buf_seg_size = skmem_usr_buf_seg_size;
	pp_init->kbi_ctx = NULL;
	pp_init->kbi_ctx_retain = NULL;
	pp_init->kbi_ctx_release = NULL;
}

static errno_t
redirect_packet_pool_make(if_redirect_t rd)
{
	struct kern_pbufpool_init pp_init;
	errno_t err;

	redirect_packet_pool_init_prepare(rd, &pp_init);
	(void)snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s pp", rd->rd_name);

	err = kern_pbufpool_create(&pp_init, &rd->rd_pp, NULL);
	return err;
}

static int
redirect_enqueue_pkt(struct nx_netif *nif, struct __kern_packet *pkt,
    boolean_t flush, boolean_t *drop)
{
	ifnet_t ifp = nif->nif_ifp;
	uint64_t qset_id;
	int err;

	if (NX_LLINK_PROV(nif->nif_nx) &&
	    ifp->if_traffic_rule_count > 0 &&
	    nxctl_inet_traffic_rule_find_qset_id_with_pkt(ifp->if_xname,
	    pkt, &qset_id) == 0) {
		struct netif_qset *qset;

		/*
		 * This always returns a qset because if the qset id is invalid the
		 * default qset is returned.
		 */
		qset = nx_netif_find_qset(nif, qset_id);
		ASSERT(qset != NULL);
		pkt->pkt_qset_idx = qset->nqs_idx;
		err = ifnet_enqueue_ifcq_pkt(ifp, qset->nqs_ifcq, pkt, flush, drop);
		nx_netif_qset_release(&qset);
	} else {
		/* callee consumes packet */
		err = ifnet_enqueue_pkt(ifp, pkt, flush, drop);
	}
	return err;
}

static int
redirect_enqueue_mbuf(struct nx_netif *nif, struct mbuf *m,
    boolean_t flush, boolean_t *drop)
{
	return ifnet_enqueue_mbuf(nif->nif_ifp, m, flush, drop);
}

static int
redirect_tx_submit(ifnet_t delegate_ifp, struct pktq *spktq, uint32_t if_flowhash)
{
	struct __kern_packet *spkt, *pkt;
	struct nx_netif *nif;
	struct netif_stats *nifs;
	struct nexus_netif_adapter *dev_nifna;
	struct mbuf *m;
	boolean_t drop, native, compat;
	errno_t err;
	int cnt = 0;

	if (!ifnet_datamov_begin(delegate_ifp)) {
		RDLOG_ERR("delegate interface is being detached");
		DTRACE_SKYWALK1(delegate__detached, ifnet_t, delegate_ifp);
		return ENXIO;
	}
	if (NA(delegate_ifp) == NULL) {
		RDLOG_ERR("nexus adapter is not present");
		DTRACE_SKYWALK1(no__nexus, ifnet_t, delegate_ifp);
		err = ENXIO;
		goto done;
	}
	dev_nifna = NA(delegate_ifp);
	nif = dev_nifna->nifna_netif;
	nifs = &nif->nif_stats;

	native = (dev_nifna->nifna_up.na_type == NA_NETIF_DEV);
	compat = (dev_nifna->nifna_up.na_type == NA_NETIF_COMPAT_DEV);

	while (KPKTQ_LEN(spktq) > 0) {
		KPKTQ_DEQUEUE(spktq, spkt);
		ASSERT(spkt != NULL);
		drop = FALSE;

		if (__probable(native)) {
			pkt = nx_netif_pkt_to_pkt(dev_nifna, spkt, NETIF_CONVERT_TX);
			if (pkt == NULL) {
				continue;
			}
			pkt->pkt_flowsrc_type = FLOWSRC_IFNET;
			pkt->pkt_flow_token = if_flowhash;
			pkt->pkt_pflags |= (PKT_F_FLOW_ADV | PKTF_FLOW_ID);

			netif_ifp_inc_traffic_class_out_pkt(delegate_ifp,
			    pkt->pkt_svc_class, 1, pkt->pkt_length);

			err = redirect_enqueue_pkt(nif, pkt, FALSE, &drop);
		} else {
			ASSERT(compat);
			m = nx_netif_pkt_to_mbuf(dev_nifna, spkt, NETIF_CONVERT_TX);
			if (m == NULL) {
				continue;
			}
			m->m_pkthdr.pkt_flowsrc = FLOWSRC_IFNET;
			m->m_pkthdr.pkt_mpriv_srcid = if_flowhash;
			m->m_pkthdr.pkt_flags =
			    (PKTF_FLOW_ID | PKTF_FLOW_ADV | PKTF_FLOW_LOCALSRC);

			ifp_inc_traffic_class_out(delegate_ifp, m);

			err = redirect_enqueue_mbuf(nif, m, FALSE, &drop);
		}
		if (__probable(err == 0)) {
			cnt++;
		} else {
			RDLOG_ERR("enqueue failed: %d", err);
			if (drop) {
				STATS_INC(nifs, NETIF_STATS_TX_DROP_ENQ_AQM);
				STATS_INC(nifs, NETIF_STATS_DROP);
			}
			DTRACE_SKYWALK3(enqueue__failed,
			    ifnet_t, delegate_ifp, boolean_t, drop, int, err);
			break;
		}
	}
done:
	if (cnt > 0) {
		netif_transmit(delegate_ifp, NETIF_XMIT_FLAG_REDIRECT);
	}
	ifnet_datamov_end(delegate_ifp);
	return err;
}

/*
 *  nexus netif domain provider
 */
static errno_t
redirect_nxdp_init(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
	return 0;
}

static void
redirect_nxdp_fini(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
}

static uuid_t redirect_nx_dom_prov;

static errno_t
redirect_register_nexus_domain_provider(void)
{
	const struct kern_nexus_domain_provider_init dp_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = redirect_nxdp_init,
		.nxdpi_fini = redirect_nxdp_fini
	};

	errno_t err = 0;

	/* redirect_nxdp_init() is called before this function returns */
	err = kern_nexus_register_domain_provider(NEXUS_TYPE_NET_IF,
	    (const uint8_t *)
	    "com.apple.redirect",
	    &dp_init, sizeof(dp_init),
	    &redirect_nx_dom_prov);
	if (err != 0) {
		RDLOG_ERR("failed to register domain provider");
		return err;
	}
	return 0;
}

/*
 * netif nexus routines
 */
static if_redirect_t
redirect_nexus_context(kern_nexus_t nexus)
{
	if_redirect_t rd;

	rd = (if_redirect_t)kern_nexus_get_context(nexus);
	assert(rd != NULL);
	return rd;
}

static errno_t
redirect_nx_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
#pragma unused(nxprov, channel, ring_ctx)
	if_redirect_t rd;

	rd = redirect_nexus_context(nexus);
	RD_LOCK(rd);
	if (rd->rd_detaching) {
		DTRACE_SKYWALK1(detaching, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	if (is_tx_ring) {
		_CASSERT(RD_MAX_TX_RINGS == 1);
		VERIFY(rd->rd_tx_ring[0] == NULL);
		rd->rd_tx_ring[0] = ring;
	} else {
		_CASSERT(RD_MAX_RX_RINGS == 1);
		VERIFY(rd->rd_rx_ring[0] == NULL);
		rd->rd_rx_ring[0] = ring;
	}

	rd->rd_nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	RD_UNLOCK(rd);
	RDLOG_INFO("%s: %s ring init", rd->rd_name,
	    is_tx_ring ? "TX" : "RX");
	return 0;
}

static void
redirect_nx_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov, ring)
	if_redirect_t rd;
	thread_call_t tcall = NULL;

	rd = redirect_nexus_context(nexus);
	RD_LOCK(rd);
	if (rd->rd_rx_ring[0] == ring) {
		RDLOG_INFO("%s: RX ring fini", rd->rd_name);
		rd->rd_rx_ring[0] = NULL;
	} else if (rd->rd_tx_ring[0] == ring) {
		RDLOG_INFO("%s: TX ring fini", rd->rd_name);
		tcall = rd->rd_doorbell_tcall;
		rd->rd_doorbell_tcall = NULL;
		rd->rd_tx_ring[0] = NULL;
	}
	rd->rd_nifs = NULL;
	RD_UNLOCK(rd);

	if (tcall != NULL) {
		boolean_t success;

		success = thread_call_cancel_wait(tcall);
		RDLOG_INFO("%s: thread_call_cancel %s",
		    rd->rd_name, success ? "SUCCESS" : "FAILURE");
		if (!success) {
			RD_LOCK(rd);
			if (rd->rd_doorbell_tcall_active) {
				rd->rd_waiting_for_tcall = TRUE;
				RDLOG_INFO("%s: *waiting for threadcall",
				    rd->rd_name);
				do {
					msleep(rd, &rd->rd_lock,
					    PZERO, "redirect threadcall", 0);
				} while (rd->rd_doorbell_tcall_active);
				RDLOG_INFO("%s: threadcall done",
				    rd->rd_name);
				rd->rd_waiting_for_tcall = FALSE;
			}
			RD_UNLOCK(rd);
		}
		success = thread_call_free(tcall);
		RDLOG_INFO("%s: thread_call_free %s",
		    rd->rd_name, success ? "SUCCESS" : "FAILURE");
		redirect_release(rd);
		VERIFY(success == TRUE);
	}
}

static errno_t
redirect_nx_pre_connect(kern_nexus_provider_t nxprov,
    proc_t proc, kern_nexus_t nexus, nexus_port_t port,
    kern_channel_t channel, void **channel_context)
{
#pragma unused(nxprov, proc, nexus, port, channel, channel_context)
	return 0;
}

static errno_t
redirect_nx_connected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_redirect_t rd = NULL;

	rd = redirect_nexus_context(nexus);
	RD_LOCK(rd);
	if (rd->rd_detaching) {
		DTRACE_SKYWALK1(detaching, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return EBUSY;
	}
	redirect_retain(rd);
	rd->rd_connected = TRUE;
	RD_UNLOCK(rd);

	RDLOG_DBG("%s: connected channel %p", rd->rd_name, channel);
	return 0;
}

static void
redirect_nx_pre_disconnect(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_redirect_t rd;

	rd = redirect_nexus_context(nexus);
	RDLOG_INFO("%s: pre-disconnect channel %p", rd->rd_name, channel);
	/* Quiesce the interface and flush any pending outbound packets */
	if_down(rd->rd_ifp);
	RD_LOCK(rd);
	rd->rd_connected = FALSE;
	RD_UNLOCK(rd);
}

static void
redirect_nx_disconnected(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_redirect_t rd;

	rd = redirect_nexus_context(nexus);
	RDLOG_INFO("%s: disconnected channel %p", rd->rd_name, channel);
	redirect_release(rd);
}

static errno_t
redirect_nx_slot_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, kern_channel_slot_t slot, uint32_t slot_index,
    struct kern_slot_prop **slot_prop_addr, void **slot_context)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index, slot_prop_addr, slot_context)
	return 0;
}

static void
redirect_nx_slot_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, kern_channel_slot_t slot, uint32_t slot_index)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index)
}

static errno_t
redirect_nx_sync_tx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
	if_redirect_t rd;
	ifnet_t ifp;
	kern_channel_slot_t last_tx_slot = NULL;
	ifnet_t delegate_ifp;
	struct kern_channel_ring_stat_increment stats;
	kern_channel_slot_t tx_slot = NULL;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	struct pktq tx_pktq;
	uint32_t n_pkts = 0;
	int error = 0;

	bzero(&stats, sizeof(stats));
	STATS_INC(nifs, NETIF_STATS_TX_SYNC);
	rd = redirect_nexus_context(nexus);
	RDLOG_INFO("%s ring %d flags 0x%x", rd->rd_name, tx_ring->ckr_ring_id, flags);

	if (__improbable(!redirect_is_usable(rd))) {
		RDLOG_INFO("%s is not usable", rd->rd_name);
		DTRACE_SKYWALK1(unusable, if_redirect_t, rd);
		return ENOENT;
	}
	ifp = rd->rd_ifp;
	delegate_ifp = rd->rd_delegate_ifp;

	KPKTQ_INIT(&tx_pktq);
	while ((tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL)) != NULL) {
		kern_packet_t sph;

		/* detach the packet from the TX ring */
		sph = kern_channel_slot_get_packet(tx_ring, tx_slot);
		VERIFY(sph != 0);
		kern_channel_slot_detach_packet(tx_ring, tx_slot, sph);

		/* bpf tap output */
		redirect_bpf_tap(ifp, sph, false);

		ASSERT(sph != 0);
		STATS_INC(nifs, NETIF_STATS_TX_COPY_DIRECT);
		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);

		stats.kcrsi_slots_transferred++;
		stats.kcrsi_bytes_transferred += kern_packet_get_data_length(sph);

		KPKTQ_ENQUEUE(&tx_pktq, SK_PTR_ADDR_KPKT(sph));
		n_pkts++;

		last_tx_slot = tx_slot;
	}
	if (last_tx_slot != NULL) {
		kern_channel_advance_slot(tx_ring, last_tx_slot);
		kern_channel_increment_ring_net_stats(tx_ring, ifp, &stats);
	}
	if (__improbable(delegate_ifp == NULL)) {
		RDLOG_INFO("%s has no delegate", rd->rd_name);
		DTRACE_SKYWALK1(no__delegate, if_redirect_t, rd);
		error = ENXIO;
		goto done;
	}
	if (n_pkts > 0) {
		redirect_tx_submit(delegate_ifp, &tx_pktq, ifp->if_flowhash);
	}
done:
	/*
	 * Packets not enqueued into delegate interface AQM
	 */
	if (KPKTQ_LEN(&tx_pktq) > 0) {
		DTRACE_SKYWALK2(unsent, if_redirect_t, rd, struct pktq *, &tx_pktq);
		STATS_ADD(nifs, NETIF_STATS_DROP_NO_DELEGATE, KPKTQ_LEN(&tx_pktq));
		pp_free_pktq(&tx_pktq);
	}
	return error;
}

static void
redirect_rx_cb(void *arg, struct pktq *spktq)
{
	if_redirect_t rd = arg;
	struct __kern_packet *spkt, *pkt;
	kern_packet_t ph;
	kern_channel_ring_t rx_ring = NULL;
	kern_channel_slot_t rx_slot = NULL, last_rx_slot = NULL;
	struct kern_channel_ring_stat_increment stats;
	int err;

	/*
	 * The ring cannot disappear before the callback is finished and removed.
	 */
	rx_ring = rd->rd_rx_ring[0];
	if (rx_ring == NULL) {
		DTRACE_SKYWALK2(no__ring__drop, if_redirect_t, rd, struct pktq *, spktq);
		pp_free_pktq(spktq);
		return;
	}
	bzero(&stats, sizeof(stats));
	kr_enter(rx_ring, TRUE);
	kern_channel_reclaim(rx_ring);

	while (KPKTQ_LEN(spktq) > 0) {
		KPKTQ_DEQUEUE(spktq, spkt);

		rx_slot = kern_channel_get_next_slot(rx_ring, last_rx_slot, NULL);
		if (rx_slot == NULL) {
			DTRACE_SKYWALK2(no__slot__drop, if_redirect_t, rd,
			    struct __kern_packet *, spkt);
			pp_free_packet_single(spkt);
			continue;
		}
		pkt = nx_netif_pkt_to_pkt(rd->rd_ifp->if_na, spkt, NETIF_CONVERT_RX);
		if (pkt == NULL) {
			DTRACE_SKYWALK1(copy__drop, if_redirect_t, rd);
			continue;
		}
		ph = SK_PKT2PH(pkt);
		stats.kcrsi_slots_transferred++;
		stats.kcrsi_bytes_transferred += kern_packet_get_data_length(ph);

		redirect_bpf_tap(rd->rd_ifp, ph, true);

		err = kern_channel_slot_attach_packet(rx_ring, rx_slot, ph);
		VERIFY(err == 0);
		last_rx_slot = rx_slot;
	}
	ASSERT(KPKTQ_EMPTY(spktq));
	if (last_rx_slot != NULL) {
		kern_channel_advance_slot(rx_ring, last_rx_slot);
		kern_channel_increment_ring_net_stats(rx_ring, rd->rd_ifp, &stats);
	}
	kr_exit(rx_ring);
	if (last_rx_slot != NULL) {
		kern_channel_notify(rx_ring, 0);
	}
}

static errno_t
redirect_nx_sync_rx(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, nexus, ring, flags)
	return 0;
}

static void
redirect_async_doorbell(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	errno_t error;
	if_redirect_t rd = (if_redirect_t)arg0;
	kern_channel_ring_t ring;
	boolean_t more;

	RD_LOCK(rd);
	ring = rd->rd_tx_ring[0];
	if (__improbable(!redirect_is_usable(rd) || ring == NULL)) {
		DTRACE_SKYWALK2(unusable, if_redirect_t, rd, kern_channel_ring_t, ring);
		goto done;
	}
	rd->rd_doorbell_tcall_active = TRUE;
	RD_UNLOCK(rd);

	error = kern_channel_tx_refill(ring, UINT32_MAX, UINT32_MAX, FALSE,
	    &more);
	if (error != 0 && error != EAGAIN) {
		RDLOG_ERR("%s: Tx refill failed %d", rd->rd_name, error);
	} else {
		RDLOG_DBG("%s: Tx refilled", rd->rd_name);
	}

	RD_LOCK(rd);
done:
	rd->rd_doorbell_tcall_active = FALSE;
	if (rd->rd_waiting_for_tcall) {
		RDLOG_INFO("%s: threadcall waking up waiter", rd->rd_name);
		wakeup((caddr_t)rd);
	}
	RD_UNLOCK(rd);
}

static void
redirect_schedule_async_doorbell(if_redirect_t rd)
{
	thread_call_t tcall;

	RD_LOCK(rd);
	if (__improbable(!redirect_is_usable(rd))) {
		DTRACE_SKYWALK1(unusable, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return;
	}
	tcall = rd->rd_doorbell_tcall;
	if (tcall != NULL) {
		thread_call_enter(tcall);
	} else {
		tcall = thread_call_allocate_with_options(redirect_async_doorbell,
		    (thread_call_param_t)rd,
		    THREAD_CALL_PRIORITY_KERNEL,
		    THREAD_CALL_OPTIONS_ONCE);
		if (tcall == NULL) {
			RDLOG_ERR("%s: tcall alloc failed", rd->rd_name);
		} else {
			rd->rd_doorbell_tcall = tcall;
			redirect_retain(rd);
			thread_call_enter(tcall);
		}
	}
	RD_UNLOCK(rd);
}

static errno_t
redirect_nx_tx_doorbell(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, ring, flags)
	errno_t error;
	if_redirect_t rd;

	rd = redirect_nexus_context(nexus);
	RDLOG_DBG("%s", rd->rd_name);

	if ((flags & KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL) == 0) {
		boolean_t more;
		/* synchronous tx refill */
		error = kern_channel_tx_refill(ring, UINT32_MAX, UINT32_MAX,
		    TRUE, &more);
		if (error != 0 && error != EAGAIN) {
			RDLOG_ERR("%s: Tx refill (sync) %d", rd->rd_name, error);
		} else {
			RDLOG_DBG("%s: Tx refilled (sync)", rd->rd_name);
		}
	} else {
		RDLOG_DBG("%s: schedule async refill", rd->rd_name);
		redirect_schedule_async_doorbell(rd);
	}
	return 0;
}

static errno_t
redirect_netif_prepare(kern_nexus_t nexus, ifnet_t ifp)
{
	if_redirect_t rd;

	rd = (if_redirect_t)kern_nexus_get_context(nexus);

	(void)ifnet_set_capabilities_enabled(ifp, 0, -1);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_mtu(ifp, ETHERMTU);
	ifnet_set_offload(ifp, 0);

	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET) {
		ifnet_set_flags(ifp,
		    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX, 0xffff);
		ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
		ifnet_set_hdrlen(ifp, sizeof(struct ether_header));
	} else {
		ifnet_set_flags(ifp, IFF_MULTICAST | IFF_POINTOPOINT, 0xffff);
	}
	return 0;
}

static void
redirect_delegate_adv_config(ifnet_t delegate_ifp, bool enable)
{
	struct nx_netif *delegate_nif;

	ASSERT(delegate_ifp != NULL);
	if (!SKYWALK_NATIVE(delegate_ifp)) {
		RDLOG_ERR("%s is not skywalk native", if_name(delegate_ifp));
		DTRACE_SKYWALK1(not__native, ifnet_t, delegate_ifp);
		return;
	}
	delegate_nif = NA(delegate_ifp)->nifna_netif;
	nx_netif_config_interface_advisory(delegate_nif->nif_nx, enable);
}

static errno_t
redirect_nx_intf_adv_config(void *prov_ctx, bool enable)
{
	if_redirect_t rd = (if_redirect_t)prov_ctx;

	RD_LOCK(rd);
	if (!redirect_is_usable(rd)) {
		RDLOG_ERR("cannot %s advisory on %s because it is not usable",
		    enable ? "enable" : "disable", if_name(rd->rd_ifp));
		DTRACE_SKYWALK1(unusable, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	if (rd->rd_intf_adv_enabled == enable) {
		RDLOG_ERR("advisory is already %s on %s",
		    enable ? "enable" : "disable", if_name(rd->rd_ifp));
		DTRACE_SKYWALK1(advisory__already__set, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	if (!rd->rd_delegate_set) {
		RDLOG_ERR("delegate is not set on %s", if_name(rd->rd_ifp));
		DTRACE_SKYWALK1(no__delegate, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	redirect_delegate_adv_config(rd->rd_delegate_ifp, enable);
	rd->rd_intf_adv_enabled = enable;
	RD_UNLOCK(rd);
	return 0;
}

static errno_t
fill_capab_interface_advisory(if_redirect_t rd, void *contents,
    uint32_t *len)
{
	struct kern_nexus_capab_interface_advisory *capab = contents;

	if (*len != sizeof(*capab)) {
		DTRACE_SKYWALK2(invalid__len, uint32_t, *len, size_t, sizeof(*capab));
		return EINVAL;
	}
	if (capab->kncia_version !=
	    KERN_NEXUS_CAPAB_INTERFACE_ADVISORY_VERSION_1) {
		DTRACE_SKYWALK2(invalid__ver, uint32_t, capab->kncia_version,
		    uint32_t, KERN_NEXUS_CAPAB_INTERFACE_ADVISORY_VERSION_1);
		return EINVAL;
	}
	VERIFY(capab->kncia_notify != NULL);
	rd->rd_intf_adv_kern_ctx = capab->kncia_kern_context;
	rd->rd_intf_adv_notify = capab->kncia_notify;
	capab->kncia_provider_context = rd;
	capab->kncia_config = redirect_nx_intf_adv_config;
	return 0;
}

static errno_t
redirect_nx_capab_config(kern_nexus_provider_t nxprov, kern_nexus_t nx,
    kern_nexus_capab_t capab, void *contents, uint32_t *len)
{
#pragma unused(nxprov)
	errno_t error;
	if_redirect_t rd;

	rd = redirect_nexus_context(nx);

	switch (capab) {
	case KERN_NEXUS_CAPAB_INTERFACE_ADVISORY:
		error = fill_capab_interface_advisory(rd, contents, len);
		break;
	default:
		error = ENOTSUP;
		break;
	}
	return error;
}

static errno_t
create_netif_provider_and_instance(if_redirect_t rd,
    struct ifnet_init_eparams *init_params, ifnet_t *ifp,
    uuid_t *provider, uuid_t *instance)
{
	errno_t err = 0;
	nexus_controller_t controller = kern_nexus_shared_controller();
	struct kern_nexus_net_init net_init = {};
	nexus_name_t provider_name = {};
	nexus_attr_t nexus_attr = NULL;

	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = redirect_nx_pre_connect,
		.nxpi_connected = redirect_nx_connected,
		.nxpi_pre_disconnect = redirect_nx_pre_disconnect,
		.nxpi_disconnected = redirect_nx_disconnected,
		.nxpi_ring_init = redirect_nx_ring_init,
		.nxpi_ring_fini = redirect_nx_ring_fini,
		.nxpi_slot_init = redirect_nx_slot_init,
		.nxpi_slot_fini = redirect_nx_slot_fini,
		.nxpi_sync_tx = redirect_nx_sync_tx,
		.nxpi_sync_rx = redirect_nx_sync_rx,
		.nxpi_tx_doorbell = redirect_nx_tx_doorbell,
		.nxpi_config_capab = redirect_nx_capab_config,
	};

	err = kern_nexus_attr_create(&nexus_attr);
	if (err != 0) {
		RDLOG_ERR("%s nexus attribution creation failed, error: %d",
		    rd->rd_name, err);
		DTRACE_SKYWALK2(attr__create__failed, if_redirect_t, rd, int, err);
		goto failed;
	}

	snprintf((char *)provider_name, sizeof(provider_name),
	    "com.apple.netif.%s", rd->rd_name);
	err = kern_nexus_controller_register_provider(controller,
	    redirect_nx_dom_prov,
	    provider_name,
	    &prov_init,
	    sizeof(prov_init),
	    nexus_attr,
	    provider);
	if (err != 0) {
		RDLOG_ERR("%s register provider failed, error %d", rd->rd_name, err);
		DTRACE_SKYWALK2(register__failed, if_redirect_t, rd, int, err);
		goto failed;
	}

	net_init.nxneti_version = KERN_NEXUS_NET_CURRENT_VERSION;
	net_init.nxneti_flags = 0;
	net_init.nxneti_eparams = init_params;
	net_init.nxneti_lladdr = NULL;
	net_init.nxneti_prepare = redirect_netif_prepare;
	net_init.nxneti_rx_pbufpool = rd->rd_pp;
	net_init.nxneti_tx_pbufpool = rd->rd_pp;
	err = kern_nexus_controller_alloc_net_provider_instance(controller,
	    *provider, rd, NULL, instance, &net_init, ifp);
	if (err != 0) {
		RDLOG_ERR("%s alloc net provider instance failed %d", rd->rd_name, err);
		DTRACE_SKYWALK2(alloc__provider__instance__failed, if_redirect_t, rd, int, err);
		kern_nexus_controller_deregister_provider(controller, *provider);
		uuid_clear(*provider);
		goto failed;
	}
failed:
	if (nexus_attr != NULL) {
		kern_nexus_attr_destroy(nexus_attr);
	}
	return err;
}

static errno_t
redirect_attach_netif_nexus(if_redirect_t rd,
    struct ifnet_init_eparams *init_params, ifnet_t *ifp)
{
	errno_t error = 0;
	redirect_nx_t nx = &rd->rd_nx;

	error = redirect_packet_pool_make(rd);
	if (error != 0) {
		RDLOG_ERR("%s packet pool make failed: %d", rd->rd_name, error);
		DTRACE_SKYWALK2(pool__make__failed, if_redirect_t, rd, int, error);
		return error;
	}

	return create_netif_provider_and_instance(rd, init_params, ifp,
	           &nx->rnx_provider, &nx->rnx_instance);
}

static void
detach_provider_and_instance(uuid_t provider, uuid_t instance)
{
	nexus_controller_t controller = kern_nexus_shared_controller();
	errno_t err;

	if (!uuid_is_null(instance)) {
		err = kern_nexus_controller_free_provider_instance(controller,
		    instance);
		if (err != 0) {
			RDLOG_ERR("free_provider_instance failed %d", err);
		}
		uuid_clear(instance);
	}
	if (!uuid_is_null(provider)) {
		err = kern_nexus_controller_deregister_provider(controller,
		    provider);
		if (err != 0) {
			RDLOG_ERR("deregister_provider failed %d", err);
		}
		uuid_clear(provider);
	}
	return;
}

static void
redirect_detach_netif_nexus(if_redirect_t rd)
{
	redirect_nx_t rnx = &rd->rd_nx;
	detach_provider_and_instance(rnx->rnx_provider, rnx->rnx_instance);
}

static void
interface_link_event(ifnet_t ifp, uint32_t event_code)
{
	struct event {
		uint32_t ifnet_family;
		uint32_t unit;
		char if_name[IFNAMSIZ];
	};
	_Alignas(struct kern_event_msg) char message[sizeof(struct kern_event_msg) + sizeof(struct event)] = { 0 };
	struct kern_event_msg *header = (struct kern_event_msg *)message;
	struct event *data = (struct event *)(header + 1);

	header->total_size = sizeof(message);
	header->vendor_code = KEV_VENDOR_APPLE;
	header->kev_class = KEV_NETWORK_CLASS;
	header->kev_subclass = KEV_DL_SUBCLASS;
	header->event_code = event_code;
	data->ifnet_family = ifnet_family(ifp);
	data->unit = (uint32_t)ifnet_unit(ifp);
	strlcpy(data->if_name, ifnet_name(ifp), IFNAMSIZ);
	ifnet_event(ifp, header);
}

static if_redirect_t
ifnet_get_if_redirect(ifnet_t ifp)
{
	return (if_redirect_t)ifnet_softc(ifp);
}

static int
redirect_clone_create(struct if_clone *ifc, uint32_t unit, void *param)
{
	int error;
	if_redirect_t rd;
	struct ifnet_init_eparams rd_init;
	struct if_redirect_create_params params;
	user_addr_t param_addr = (user_addr_t)param;
	ifnet_t ifp;

	if (param_addr == USER_ADDR_NULL) {
		RDLOG_ERR("create params not specified");
		DTRACE_SKYWALK2(no__param, struct if_clone *, ifc, uint32_t, unit);
		return EINVAL;
	}
	error = copyin(param_addr, &params, sizeof(params));
	if (error != 0) {
		RDLOG_ERR("copyin failed: error %d", error);
		DTRACE_SKYWALK1(copyin__failed, int, error);
		return error;
	}
	if ((params.ircp_type != RD_CREATE_PARAMS_TYPE &&
	    params.ircp_type != RD_CREATE_PARAMS_TYPE_NOATTACH) ||
	    params.ircp_len != sizeof(params)) {
		RDLOG_ERR("invalid type(0x%x) or len(0x%d)", params.ircp_type,
		    params.ircp_len);
		DTRACE_SKYWALK2(invalid__params, uint16_t, params.ircp_type,
		    uint16_t, params.ircp_len);
		return EINVAL;
	}
	if (params.ircp_ftype != IFRTYPE_FAMILY_ETHERNET &&
	    params.ircp_ftype != IFRTYPE_FAMILY_CELLULAR) {
		RDLOG_ERR("functional type(0x%x) not supported", params.ircp_ftype);
		DTRACE_SKYWALK1(invalid__ftype, uint32_t, params.ircp_ftype);
		return ENOTSUP;
	}

	rd = kalloc_type(if_redirect, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	RD_LOCK_INIT(rd);
	rd->rd_ftype = params.ircp_ftype;
	rd->rd_retain_count = 1;
	rd->rd_max_mtu = RD_MAX_MTU;

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(rd->rd_name, sizeof(rd->rd_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(rd->rd_name)) {
		redirect_release(rd);
		RDLOG_ERR("invalid ifc_name(%s) or unit(%d)", ifc->ifc_name, unit);
		DTRACE_SKYWALK2(invalid__name__or__unit, char *, ifc->ifc_name,
		    uint32_t, unit);
		return EINVAL;
	}

	bzero(&rd_init, sizeof(rd_init));
	rd_init.ver = IFNET_INIT_CURRENT_VERSION;
	rd_init.len = sizeof(rd_init);
	rd_init.flags |= (IFNET_INIT_SKYWALK_NATIVE | IFNET_INIT_IF_ADV);
	if (params.ircp_type == RD_CREATE_PARAMS_TYPE_NOATTACH) {
		rd_init.flags |= IFNET_INIT_NX_NOAUTO;
	}
	rd_init.uniqueid = rd->rd_name;
	rd_init.uniqueid_len = (uint32_t)strlen(rd->rd_name);
	rd_init.name = ifc->ifc_name;
	rd_init.unit = unit;
	rd_init.softc = rd;
	rd_init.ioctl = redirect_ioctl;
	rd_init.detach = redirect_if_free;
	rd_init.subfamily = IFNET_SUBFAMILY_REDIRECT;

	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET) {
		rd_init.family = IFNET_FAMILY_ETHERNET;
		rd_init.type = IFT_ETHER;
		rd_init.demux = ether_demux;
		rd_init.add_proto = ether_add_proto;
		rd_init.del_proto = ether_del_proto;
		rd_init.check_multi = ether_check_multi;
		rd_init.framer_extended = ether_frameout_extended;
		rd_init.broadcast_addr = etherbroadcastaddr;
		rd_init.broadcast_len = ETHER_ADDR_LEN;
	} else {
		rd_init.family = IFNET_FAMILY_CELLULAR;
		rd_init.type = IFT_CELLULAR;
		rd_init.demux = redirect_demux;
		rd_init.add_proto = redirect_add_proto;
		rd_init.del_proto = redirect_del_proto;
	}
	error = redirect_attach_netif_nexus(rd, &rd_init, &ifp);
	if (error != 0) {
		redirect_release(rd);
		RDLOG_ERR("attach netif nexus failed: error %d", error);
		DTRACE_SKYWALK1(attach__nexus__failed, int, error);
		return error;
	}

	/* take an additional reference for nexus controller */
	redirect_retain(rd);
	rd->rd_ifp = ifp;

	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET) {
		/* mac address will be set after delegate is configured */
		(void) ifnet_set_lladdr(ifp, default_mac, ETHER_ADDR_LEN);
		bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	} else {
		bpfattach(ifp, DLT_RAW, 0);
	}
	return 0;
}

/*
 * This function is meant for cleaning up everything, not just delegate
 * related info.
 */
static void
redirect_cleanup(if_redirect_t rd)
{
	redirect_clear_delegate(rd);
	rd->rd_intf_adv_enabled = false;
}

static int
redirect_clone_destroy(ifnet_t ifp)
{
	if_redirect_t rd;

	rd = ifnet_get_if_redirect(ifp);
	if (rd == NULL) {
		RDLOG_ERR("rd is NULL");
		DTRACE_SKYWALK1(null__rd, ifnet_t, ifp);
		return ENXIO;
	}
	RD_LOCK(rd);
	if (rd->rd_detaching) {
		RDLOG_ERR("%s is detaching", rd->rd_name);
		DTRACE_SKYWALK1(detaching, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return 0;
	}
	rd->rd_detaching = TRUE;
	RD_UNLOCK(rd);

	redirect_cleanup(rd);
	redirect_detach_netif_nexus(rd);
	/*
	 * Releasing reference held for nexus controller
	 */
	redirect_release(rd);
	interface_link_event(ifp, KEV_DL_LINK_OFF);
	ifnet_detach(ifp);
	return 0;
}

static int
if_redirect_request_copyin(user_addr_t user_addr,
    struct if_redirect_request *ifrr, uint64_t len)
{
	int error;

	if (user_addr == USER_ADDR_NULL || len < sizeof(*ifrr)) {
		RDLOG_ERR("user_addr(0x%llx) or len(%llu) < %lu",
		    user_addr, len, sizeof(*ifrr));
		error = EINVAL;
		goto done;
	}
	error = copyin(user_addr, ifrr, sizeof(*ifrr));
	if (error != 0) {
		RDLOG_ERR("copyin failed: %d", error);
		goto done;
	}
	if (ifrr->ifrr_reserved[0] != 0 || ifrr->ifrr_reserved[1] != 0 ||
	    ifrr->ifrr_reserved[2] != 0 || ifrr->ifrr_reserved[3] != 0) {
		RDLOG_ERR("reserved[0]=0x%llu, reserved[1]=0x%llu"
		    "reserved[2]=0x%llu, reserved[3]=0x%llu", ifrr->ifrr_reserved[0],
		    ifrr->ifrr_reserved[1], ifrr->ifrr_reserved[2],
		    ifrr->ifrr_reserved[3]);
		error = EINVAL;
		goto done;
	}
done:
	return error;
}

static void
redirect_detach_notify(void *arg)
{
	if_redirect_t rd = arg;

	redirect_clear_delegate(rd);
}

static int
redirect_set_delegate(if_redirect_t rd, ifnet_t delegate_ifp)
{
	ifnet_t ifp = rd->rd_ifp;
	int error;

	RD_LOCK(rd);
	if (rd->rd_detaching) {
		RDLOG_ERR("%s is detaching", rd->rd_name);
		DTRACE_SKYWALK2(detaching, if_redirect_t, rd, ifnet_t, delegate_ifp);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	if (rd->rd_delegate_ifp != NULL) {
		if (rd->rd_delegate_ifp == delegate_ifp) {
			RDLOG_ERR("cannot configure the same delegate");
			DTRACE_SKYWALK2(same__ifp, if_redirect_t, rd,
			    ifnet_t, delegate_ifp);
			RD_UNLOCK(rd);
			return EALREADY;
		} else {
			redirect_clear_delegate_locked(rd);
		}
	}
	ASSERT(rd->rd_delegate_ifp == NULL);

	if (!ifnet_is_attached(ifp, 1)) {
		RDLOG_ERR("failed to get self reference");
		DTRACE_SKYWALK2(ifp__detaching, if_redirect_t, rd, ifnet_t, ifp);
		error = ENXIO;
		goto fail;
	}
	ASSERT(!rd->rd_self_ref);
	rd->rd_self_ref = TRUE;

	/* This saves the reference taken above */
	error = ifnet_set_delegate_parent(delegate_ifp, ifp);
	if (error != 0) {
		RDLOG_ERR("failed to set delegate parent");
		DTRACE_SKYWALK4(set__delegate__parent__failed, if_redirect_t, rd,
		    ifnet_t, delegate_ifp, ifnet_t, ifp, int, error);
		goto fail;
	}
	ASSERT(!rd->rd_delegate_parent_set);
	rd->rd_delegate_parent_set = TRUE;

	if (!ifnet_is_attached(delegate_ifp, 1)) {
		RDLOG_ERR("failed to get delegate reference");
		DTRACE_SKYWALK2(delegate__detaching, if_redirect_t, rd,
		    ifnet_t, delegate_ifp);
		error = ENXIO;
		goto fail;
	}
	ASSERT(rd->rd_delegate_ifp == NULL);
	rd->rd_delegate_ifp = delegate_ifp;
	ASSERT(!rd->rd_delegate_ref);
	rd->rd_delegate_ref = TRUE;

	error = ifnet_set_flowswitch_rx_callback(delegate_ifp, redirect_rx_cb, rd);
	if (error != 0) {
		RDLOG_ERR("failed to set fsw rx callback: %d", error);
		DTRACE_SKYWALK3(set__fsw__rx__cb__fail, if_redirect_t, rd, ifnet_t,
		    delegate_ifp, int, error);
		goto fail;
	}
	ASSERT(!rd->rd_fsw_rx_cb_set);
	rd->rd_fsw_rx_cb_set = TRUE;

	error = ifnet_set_delegate(ifp, delegate_ifp);
	if (error != 0) {
		RDLOG_ERR("failed to set delegate ifp: %d", error);
		DTRACE_SKYWALK4(set__delegate__fail, if_redirect_t, rd, ifnet_t, ifp,
		    ifnet_t, delegate_ifp, int, error);
		goto fail;
	}
	ASSERT(!rd->rd_delegate_set);
	rd->rd_delegate_set = TRUE;

	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET) {
		uint8_t mac_addr[ETHER_ADDR_LEN];

		error = ifnet_lladdr_copy_bytes(delegate_ifp, mac_addr,
		    ETHER_ADDR_LEN);
		if (error != 0) {
			RDLOG_ERR("failed to get mac addr from %s, error %d",
			    if_name(delegate_ifp), error);
			DTRACE_SKYWALK3(lladdr__copy__fail, if_redirect_t, rd,
			    ifnet_t, delegate_ifp, int, error);
			goto fail;
		}
		error = ifnet_set_lladdr(ifp, mac_addr, ETHER_ADDR_LEN);
		if (error != 0) {
			RDLOG_ERR("failed to set mac addr for %s, error %d",
			    if_name(ifp), error);
			DTRACE_SKYWALK3(set__lladdr__fail, if_redirect_t, rd,
			    ifnet_t, ifp, int, error);
			goto fail;
		}
		ASSERT(!rd->rd_mac_addr_set);
		rd->rd_mac_addr_set = TRUE;
	}
	/*
	 * This is enabled out-of-band from redirect_set_delegate() but we should do
	 * this here in case we move to a different delegate.
	 */
	if (rd->rd_intf_adv_enabled) {
		redirect_delegate_adv_config(delegate_ifp, true);
	}
	ifnet_set_detach_notify(delegate_ifp, redirect_detach_notify, rd);
	rd->rd_detach_notify_set = TRUE;

	/*
	 * Check that the delegate is still attached. If not, the detach notify above
	 * could've been missed and we would have to cleanup everything here.
	 */
	if (!ifnet_is_attached(delegate_ifp, 0)) {
		RDLOG_ERR("delegate %s detached during setup", if_name(delegate_ifp));
		DTRACE_SKYWALK2(delegate__detached, if_redirect_t, rd,
		    ifnet_t, delegate_ifp);
		error = ENXIO;
		goto fail;
	}
	RD_UNLOCK(rd);
	return 0;

fail:
	redirect_clear_delegate_locked(rd);
	RD_UNLOCK(rd);
	return error;
}

static void
redirect_clear_delegate_locked(if_redirect_t rd)
{
	ifnet_t ifp = rd->rd_ifp;
	ifnet_t delegate_ifp = rd->rd_delegate_ifp;
	int error;

	if (rd->rd_detach_notify_set) {
		ASSERT(delegate_ifp != NULL);
		ifnet_set_detach_notify(delegate_ifp, NULL, NULL);
		rd->rd_detach_notify_set = FALSE;
	}
	if (rd->rd_intf_adv_enabled && delegate_ifp != NULL) {
		redirect_delegate_adv_config(delegate_ifp, false);
		/*
		 * We don't clear rd_intf_adv_enabled because we want to reenable
		 * advisory after moving to a different delegate.
		 */
	}
	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET && rd->rd_mac_addr_set) {
		ASSERT(delegate_ifp != NULL);
		error = ifnet_set_lladdr(ifp, default_mac, ETHER_ADDR_LEN);
		if (error != 0) {
			RDLOG_ERR("failed to set mac addr for %s, error %d",
			    if_name(ifp), error);
			DTRACE_SKYWALK3(set__lladdr__fail, if_redirect_t, rd,
			    ifnet_t, ifp, int, error);
		}
		rd->rd_mac_addr_set = FALSE;
	}
	if (rd->rd_delegate_set) {
		ASSERT(delegate_ifp != NULL);
		(void) ifnet_set_delegate(ifp, NULL);
		rd->rd_delegate_set = FALSE;
	}
	if (rd->rd_fsw_rx_cb_set) {
		ASSERT(delegate_ifp != NULL);
		(void) ifnet_set_flowswitch_rx_callback(delegate_ifp, NULL, NULL);
		rd->rd_fsw_rx_cb_set = FALSE;
	}
	if (rd->rd_delegate_ref) {
		ASSERT(delegate_ifp != NULL);
		rd->rd_delegate_ifp = NULL;
		ifnet_decr_iorefcnt(delegate_ifp);
		rd->rd_delegate_ref = FALSE;
	}
	if (rd->rd_delegate_parent_set) {
		ASSERT(delegate_ifp != NULL);
		ifnet_set_delegate_parent(delegate_ifp, NULL);
		rd->rd_delegate_parent_set = FALSE;
	}
	if (rd->rd_self_ref) {
		ifnet_decr_iorefcnt(ifp);
		rd->rd_self_ref = FALSE;
	}
}

static void
redirect_clear_delegate(if_redirect_t rd)
{
	RD_LOCK(rd);
	redirect_clear_delegate_locked(rd);
	RD_UNLOCK(rd);
}

static int
redirect_ioctl_set_delegate(ifnet_t ifp, user_addr_t user_addr, uint64_t len)
{
	if_redirect_t rd = NULL;
	struct if_redirect_request ifrr;
	ifnet_t delegate_ifp = NULL;
	int error;

	error = if_redirect_request_copyin(user_addr, &ifrr, len);
	if (error != 0) {
		RDLOG_ERR("if_redirect_request_copyin failed: error %d", error);
		DTRACE_SKYWALK4(copyin__failed, ifnet_t, ifp, user_addr_t, user_addr,
		    uint64_t, len, int, error);
		goto done;
	}
	if (ifrr.ifrr_delegate_name[0] == '\0') {
		RDLOG_ERR("NULL delegate name");
		DTRACE_SKYWALK1(null__delegate, ifnet_t, ifp);
		error = EINVAL;
		goto done;
	}
	/* ensure null termination */
	ifrr.ifrr_delegate_name[IFNAMSIZ - 1] = '\0';
	delegate_ifp = ifunit_ref(ifrr.ifrr_delegate_name);
	if (delegate_ifp == NULL) {
		RDLOG_ERR("delegate %s not found", ifrr.ifrr_delegate_name);
		DTRACE_SKYWALK2(invalid__name, ifnet_t, ifp, char *,
		    ifrr.ifrr_delegate_name);
		error = ENOENT;
		goto done;
	}
	rd = ifnet_get_if_redirect(ifp);
	if (rd == NULL) {
		RDLOG_ERR("rd is NULL");
		DTRACE_SKYWALK1(null__rd, ifnet_t, ifp);
		error = ENOENT;
		goto done;
	}
	/* Verify that the delegate type is supported */
	if (rd->rd_ftype == IFRTYPE_FAMILY_ETHERNET) {
		if (delegate_ifp->if_family != IFNET_FAMILY_ETHERNET) {
			RDLOG_ERR("%s's family %d not compatible "
			    "with ethernet functional type", if_name(delegate_ifp),
			    delegate_ifp->if_family);
			DTRACE_SKYWALK2(delegate__incompatible__ether, if_redirect_t, rd,
			    ifnet_t, delegate_ifp);
			error = EINVAL;
			goto done;
		}
		if (ifnet_is_low_latency(delegate_ifp)) {
			RDLOG_ERR("low latency %s cannot be a delegate",
			    if_name(delegate_ifp));
			DTRACE_SKYWALK2(delegate__is__ll, if_redirect_t, rd,
			    ifnet_t, delegate_ifp);
			error = EINVAL;
			goto done;
		}
	} else {
		ASSERT(rd->rd_ftype == IFRTYPE_FAMILY_CELLULAR);
		if (delegate_ifp->if_family != IFNET_FAMILY_CELLULAR &&
		    delegate_ifp->if_family != IFNET_FAMILY_UTUN &&
		    delegate_ifp->if_family != IFNET_FAMILY_IPSEC) {
			RDLOG_ERR("%s's family %d not compatible "
			    "with cellular functional type", if_name(delegate_ifp),
			    delegate_ifp->if_family);
			DTRACE_SKYWALK2(delegate__incompatible__cell, if_redirect_t, rd,
			    ifnet_t, delegate_ifp);
			error = EINVAL;
			goto done;
		}
	}
	if (delegate_ifp->if_subfamily == IFNET_SUBFAMILY_REDIRECT) {
		RDLOG_ERR("delegate %s cannot be redirect", if_name(delegate_ifp));
		DTRACE_SKYWALK2(delegate__is__redirect, if_redirect_t, rd,
		    ifnet_t, delegate_ifp);
		error = EINVAL;
		goto done;
	}
	error = redirect_set_delegate(rd, delegate_ifp);
done:
	if (delegate_ifp != NULL) {
		ifnet_decr_iorefcnt(delegate_ifp);
	}
	return error;
}

static int
redirect_set_drvspec(ifnet_t ifp, uint64_t cmd, uint64_t len,
    user_addr_t user_addr)
{
	int error;

	switch (cmd) {
	case RD_S_CMD_SET_DELEGATE:
		error = redirect_ioctl_set_delegate(ifp, user_addr, len);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static int
redirect_get_drvspec(ifnet_t ifp, uint64_t cmd, uint64_t len,
    user_addr_t user_addr)
{
#pragma unused(ifp, cmd, len, user_addr)
	return 0;
}

union ifdrvu {
	struct ifdrv32  *ifdrvu_32;
	struct ifdrv64  *ifdrvu_64;
	void            *ifdrvu_p;
};

static errno_t
redirect_ioctl(ifnet_t ifp, u_long cmd, void *data)
{
	if_redirect_t rd = NULL;
	struct ifreq *ifr = NULL;
	union ifdrvu drv;
	uint64_t drv_cmd;
	uint64_t drv_len;
	boolean_t drv_set_command = FALSE;
	user_addr_t user_addr;
	int error = 0;

	rd = ifnet_get_if_redirect(ifp);
	if (rd == NULL) {
		RDLOG_ERR("rd is NULL");
		DTRACE_SKYWALK1(null__rd, ifnet_t, ifp);
		return ENXIO;
	}
	RD_LOCK(rd);
	if (rd->rd_detaching) {
		RDLOG_ERR("%s is detaching", rd->rd_name);
		DTRACE_SKYWALK1(detaching, if_redirect_t, rd);
		RD_UNLOCK(rd);
		return ENXIO;
	}
	RD_UNLOCK(rd);

	ifr = (struct ifreq *)data;

	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;
	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64: {
		struct ifmediareq *ifmr;

		RD_LOCK(rd);
		if (rd->rd_ftype != IFRTYPE_FAMILY_ETHERNET) {
			DTRACE_SKYWALK1(not__ether, if_redirect_t, rd);
			RD_UNLOCK(rd);
			return EOPNOTSUPP;
		}
		ifmr = (struct ifmediareq *)data;
		ifmr->ifm_current = IFM_ETHER;
		ifmr->ifm_mask = 0;
		ifmr->ifm_status = (IFM_AVALID | IFM_ACTIVE);
		ifmr->ifm_active = IFM_ETHER;
		ifmr->ifm_count = 1;

		user_addr = (cmd == SIOCGIFMEDIA64) ?
		    ((struct ifmediareq64 *)ifmr)->ifmu_ulist :
		    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
		if (user_addr != USER_ADDR_NULL) {
			error = copyout(&ifmr->ifm_current, user_addr, sizeof(int));
		}
		RD_UNLOCK(rd);
		break;
	}
	case SIOCGIFDEVMTU: {
		struct ifdevmtu *devmtu_p;

		devmtu_p = &ifr->ifr_devmtu;
		devmtu_p->ifdm_current = ifnet_mtu(ifp);
		devmtu_p->ifdm_max = redirect_max_mtu(ifp);
		devmtu_p->ifdm_min = IF_MINMTU;
		break;
	}
	case SIOCSIFMTU:
		if ((unsigned int)ifr->ifr_mtu > redirect_max_mtu(ifp) ||
		    ifr->ifr_mtu < IF_MINMTU) {
			error = EINVAL;
		} else {
			error = ifnet_set_mtu(ifp, ifr->ifr_mtu);
		}
		break;
	case SIOCSIFFLAGS:
		if ((ifp->if_flags & IFF_UP) != 0) {
			/* marked up, set running if not already set */
			if ((ifp->if_flags & IFF_RUNNING) == 0) {
				/* set running */
				error = ifnet_set_flags(ifp, IFF_RUNNING,
				    IFF_RUNNING);
			}
		} else if ((ifp->if_flags & IFF_RUNNING) != 0) {
			/* marked down, clear running */
			error = ifnet_set_flags(ifp, 0, IFF_RUNNING);
		}
		break;
	case SIOCSDRVSPEC32:
	case SIOCSDRVSPEC64:
		error = proc_suser(current_proc());
		if (error != 0) {
			break;
		}
		drv_set_command = TRUE;
		OS_FALLTHROUGH;
	case SIOCGDRVSPEC32:
	case SIOCGDRVSPEC64:
		drv.ifdrvu_p = data;
		if (cmd == SIOCGDRVSPEC32 || cmd == SIOCSDRVSPEC32) {
			drv_cmd = drv.ifdrvu_32->ifd_cmd;
			drv_len = drv.ifdrvu_32->ifd_len;
			user_addr = CAST_USER_ADDR_T(drv.ifdrvu_32->ifd_data);
		} else {
			drv_cmd = drv.ifdrvu_64->ifd_cmd;
			drv_len = drv.ifdrvu_64->ifd_len;
			user_addr = drv.ifdrvu_64->ifd_data;
		}
		if (drv_set_command) {
			error = redirect_set_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
		} else {
			error = redirect_get_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
		}
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = 0;
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return error;
}

static void
redirect_if_free(ifnet_t ifp)
{
	if_redirect_t rd = NULL;

	if (ifp == NULL) {
		RDLOG_ERR("ifp is NULL");
		DTRACE_SKYWALK(null__ifp);
		return;
	}
	rd = ifnet_get_if_redirect(ifp);
	if (rd == NULL) {
		RDLOG_ERR("rd is NULL");
		DTRACE_SKYWALK1(null__rd, ifnet_t, ifp);
		return;
	}
	RD_LOCK(rd);
	ifp->if_softc = NULL;
	VERIFY(rd->rd_doorbell_tcall == NULL);
	RD_UNLOCK(rd);
	redirect_release(rd);
	ifnet_release(ifp);
	return;
}

/*
 * Network interface functions
 */
static errno_t
redirect_demux(__unused ifnet_t ifp, mbuf_t data, __unused char *frame_header,
    protocol_family_t *protocol)
{
	struct ip *ip;
	u_int ip_version;

	while (data != NULL && mbuf_len(data) < 1) {
		data = mbuf_next(data);
	}

	if (data == NULL) {
		RDLOG_DBG("data is NULL");
		DTRACE_SKYWALK(null__data);
		return ENOENT;
	}

	ip = mtod(data, struct ip *);
	ip_version = ip->ip_v;

	switch (ip_version) {
	case 4:
		*protocol = PF_INET;
		return 0;
	case 6:
		*protocol = PF_INET6;
		return 0;
	default:
		*protocol = PF_UNSPEC;
		break;
	}

	return 0;
}

static errno_t
redirect_add_proto(__unused ifnet_t interface, protocol_family_t protocol,
    __unused const struct ifnet_demux_desc *demux_array,
    __unused uint32_t demux_count)
{
	switch (protocol) {
	case PF_INET:
		return 0;
	case PF_INET6:
		return 0;
	default:
		break;
	}

	return ENOPROTOOPT;
}

static errno_t
redirect_del_proto(__unused ifnet_t interface,
    __unused protocol_family_t protocol)
{
	return 0;
}

__private_extern__ void
if_redirect_init(void)
{
	int error;

	redirect_log_handle = os_log_create("com.apple.xnu.net.redirect", "redirect");
	(void)redirect_register_nexus_domain_provider();
	error = if_clone_attach(&redirect_cloner);
	if (error != 0) {
		return;
	}
	return;
}
