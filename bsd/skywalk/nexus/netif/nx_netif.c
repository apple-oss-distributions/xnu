/*
 * Copyright (c) 2015-2023 Apple Inc. All rights reserved.
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
 * The netif nexus domain has two domain providers: native and compat, with
 * the latter being the default provider of this domain. The compat provider
 * has special handlers for NXCFG_CMD_ATTACH and NXCFG_CMD_DETACH, etc.
 *
 * A netif nexus instance can be in a native or compat mode; in either case,
 * it is associated with two instances of a nexus_adapter structure, and allows
 * at most two channels opened to the nexus.  Two two adapters correspond to
 * host and device ports, respectively.
 *
 * By itself, a netif nexus isn't associated with a network interface. The
 * association happens by attaching a network interface to the nexus instance.
 * A channel can only be successfully opened to a netif nexus after it has an
 * interface attached to it.
 *
 * During an attach, the interface is marked as Skywalk-capable, and its ifnet
 * structure refers to the attached netif nexus adapter via its if_na field.
 * The nexus also holds a reference to the interface on its na_ifp field. Note
 * that attaching to a netif_compat nexus does not alter the input/output data
 * path, nor does it remove any of the interface's hardware offload flags. It
 * merely associates the interface and netif nexus together.
 *
 * During a detach, the above references are dropped and the fields are cleared;
 * the interface is also marked as non-Skywalk-capable. This detach can happen
 * explicitly via a command down the nexus, or implicitly when the nexus goes
 * away (assuming there's no channel opened to it.)
 *
 * A userland channel can be opened to a netif nexus via the usual ch_open()
 * way, assuming the nexus provider is setup to allow access for the userland
 * process (either by binding the nexus port to PID, etc. or by creating the
 * nexus in the anonymous mode.)
 *
 * Alternatively, a kernel channel can also be opened to it by some kernel
 * subsystem, via ch_open_special(), e.g. by the flowswitch. Kernel channels
 * don't have any task mapping created, and the flag CHANF_KERNEL is used to
 * indicate that.
 *
 * Opening a channel to the host port of a native or compat netif causes the
 * ifnet output path to be redirected to nx_netif_host_transmit().  We also,
 * at present, disable any hardware offload features.
 *
 * Opening a channel to the device port of a compat netif causes the ifnet
 * input path to be redirected to nx_netif_compat_receive().  This is specific
 * to the compat variant, as the native variant's RX path already goes to
 * the native netif.
 *
 * During channel close, we restore the original I/O callbacks, as well as the
 * interface's offload flags.
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/upipe/nx_user_pipe.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <sys/kdebug.h>
#include <sys/sdt.h>
#include <os/refcnt.h>
#include <libkern/OSDebug.h>

#define NX_NETIF_MAXRINGS       NX_MAX_NUM_RING_PAIR
#define NX_NETIF_MINSLOTS       2       /* XXX same as above */
#define NX_NETIF_MAXSLOTS       NX_MAX_NUM_SLOT_PER_RING /* max # of slots */
#define NX_NETIF_TXRINGSIZE     512     /* default TX ring size */
#define NX_NETIF_RXRINGSIZE     1024    /* default RX ring size */
#define NX_NETIF_BUFSIZE        (2 * 1024)  /* default buffer size */
#define NX_NETIF_MINBUFSIZE     (128)  /* min buffer size */
#define NX_NETIF_MAXBUFSIZE     (32 * 1024) /* max buffer size */

/*
 * TODO: adi@apple.com -- minimum buflets for now; we will need to
 * have a way to adjust this based on the underlying interface's
 * parameters, e.g. jumbo MTU, large segment offload, etc.
 */
#define NX_NETIF_UMD_SIZE       _USER_PACKET_SIZE(BUFLETS_MIN)
#define NX_NETIF_KMD_SIZE       _KERN_PACKET_SIZE(BUFLETS_MIN)

/*
 * minimum stack space required for IOSkywalkFamily and Driver execution.
 */
#if XNU_TARGET_OS_OSX
#define NX_NETIF_MIN_DRIVER_STACK_SIZE    (kernel_stack_size >> 1)
#else /* !XNU_TARGET_OS_OSX */
#define NX_NETIF_MIN_DRIVER_STACK_SIZE    (kernel_stack_size >> 2)
#endif /* XNU_TARGET_OS_OSX */

static void nx_netif_dom_init(struct nxdom *);
static void nx_netif_dom_terminate(struct nxdom *);
static void nx_netif_dom_fini(struct nxdom *);
static int nx_netif_prov_params_adjust(
	const struct kern_nexus_domain_provider *, const struct nxprov_params *,
	struct nxprov_adjusted_params *);

static int nx_netif_dom_bind_port(struct kern_nexus *, nexus_port_t *,
    struct nxbind *, void *);
static int nx_netif_dom_unbind_port(struct kern_nexus *, nexus_port_t);
static int nx_netif_dom_connect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *);
static void nx_netif_dom_disconnect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *);
static void nx_netif_dom_defunct(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct proc *);
static void nx_netif_dom_defunct_finalize(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, boolean_t);

static void nx_netif_doorbell(struct ifnet *);
static int nx_netif_na_txsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_netif_na_rxsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static void nx_netif_na_dtor(struct nexus_adapter *na);
static int nx_netif_na_notify_tx(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_netif_na_notify_rx(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_netif_na_activate(struct nexus_adapter *, na_activate_mode_t);

static int nx_netif_ctl(struct kern_nexus *, nxcfg_cmd_t, void *,
    struct proc *);
static int nx_netif_ctl_attach(struct kern_nexus *, struct nx_spec_req *,
    struct proc *);
static int nx_netif_ctl_detach(struct kern_nexus *, struct nx_spec_req *);
static int nx_netif_attach(struct kern_nexus *, struct ifnet *);
static void nx_netif_flags_init(struct nx_netif *);
static void nx_netif_flags_fini(struct nx_netif *);
static void nx_netif_callbacks_init(struct nx_netif *);
static void nx_netif_callbacks_fini(struct nx_netif *);
static void nx_netif_capabilities_fini(struct nx_netif *);
static errno_t nx_netif_interface_advisory_notify(void *,
    const struct ifnet_interface_advisory *);

struct nxdom nx_netif_dom_s = {
	.nxdom_prov_head =
    STAILQ_HEAD_INITIALIZER(nx_netif_dom_s.nxdom_prov_head),
	.nxdom_type =           NEXUS_TYPE_NET_IF,
	.nxdom_md_type =        NEXUS_META_TYPE_PACKET,
	.nxdom_md_subtype =     NEXUS_META_SUBTYPE_RAW,
	.nxdom_name =           "netif",
	.nxdom_ports = {
		.nb_def = 2,
		.nb_min = 2,
		.nb_max = NX_NETIF_MAXPORTS,
	},
	.nxdom_tx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_NETIF_MAXRINGS,
	},
	.nxdom_rx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_NETIF_MAXRINGS,
	},
	.nxdom_tx_slots = {
		.nb_def = NX_NETIF_TXRINGSIZE,
		.nb_min = NX_NETIF_MINSLOTS,
		.nb_max = NX_NETIF_MAXSLOTS,
	},
	.nxdom_rx_slots = {
		.nb_def = NX_NETIF_RXRINGSIZE,
		.nb_min = NX_NETIF_MINSLOTS,
		.nb_max = NX_NETIF_MAXSLOTS,
	},
	.nxdom_buf_size = {
		.nb_def = NX_NETIF_BUFSIZE,
		.nb_min = NX_NETIF_MINBUFSIZE,
		.nb_max = NX_NETIF_MAXBUFSIZE,
	},
	.nxdom_large_buf_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = 0,
	},
	.nxdom_meta_size = {
		.nb_def = NX_NETIF_UMD_SIZE,
		.nb_min = NX_NETIF_UMD_SIZE,
		.nb_max = NX_METADATA_USR_MAX_SZ,
	},
	.nxdom_stats_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_STATS_MAX_SZ,
	},
	.nxdom_pipes = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_UPIPE_MAXPIPES,
	},
	.nxdom_flowadv_max = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_FLOWADV_MAX,
	},
	.nxdom_nexusadv_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_NEXUSADV_MAX_SZ,
	},
	.nxdom_capabilities = {
		.nb_def = NXPCAP_USER_CHANNEL,
		.nb_min = 0,
		.nb_max = NXPCAP_USER_CHANNEL,
	},
	.nxdom_qmap = {
		.nb_def = NEXUS_QMAP_TYPE_DEFAULT,
		.nb_min = NEXUS_QMAP_TYPE_DEFAULT,
		.nb_max = NEXUS_QMAP_TYPE_WMM,
	},
	.nxdom_max_frags = {
		.nb_def = NX_PBUF_FRAGS_DEFAULT,
		.nb_min = NX_PBUF_FRAGS_MIN,
		.nb_max = NX_PBUF_FRAGS_MAX,
	},
	.nxdom_init =           nx_netif_dom_init,
	.nxdom_terminate =      nx_netif_dom_terminate,
	.nxdom_fini =           nx_netif_dom_fini,
	.nxdom_find_port =      NULL,
	.nxdom_port_is_reserved = NULL,
	.nxdom_bind_port =      nx_netif_dom_bind_port,
	.nxdom_unbind_port =    nx_netif_dom_unbind_port,
	.nxdom_connect =        nx_netif_dom_connect,
	.nxdom_disconnect =     nx_netif_dom_disconnect,
	.nxdom_defunct =        nx_netif_dom_defunct,
	.nxdom_defunct_finalize = nx_netif_dom_defunct_finalize,
};

struct kern_nexus_domain_provider nx_netif_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_NET_IF,
	/*
	 * Don't install this as the default domain provider, i.e.
	 * NXDOMPROVF_DEFAULT flag not set; we want netif_compat
	 * provider to be the one handling userland-issued requests
	 * coming down thru nxprov_create() instead.
	 */
	.nxdom_prov_flags =             0,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_netif_prov_init,
		.dp_cb_fini =           nx_netif_prov_fini,
		.dp_cb_params =         nx_netif_prov_params,
		.dp_cb_mem_new =        nx_netif_prov_mem_new,
		.dp_cb_config =         nx_netif_prov_config,
		.dp_cb_nx_ctor =        nx_netif_prov_nx_ctor,
		.dp_cb_nx_dtor =        nx_netif_prov_nx_dtor,
		.dp_cb_nx_mem_info =    nx_netif_prov_nx_mem_info,
		.dp_cb_nx_mib_get =     nx_netif_prov_nx_mib_get,
		.dp_cb_nx_stop =        nx_netif_prov_nx_stop,
	},
};

struct nexus_ifnet_ops na_netif_ops = {
	.ni_finalize = na_netif_finalize,
	.ni_reap = nx_netif_reap,
	.ni_dequeue = nx_netif_native_tx_dequeue,
	.ni_get_len = nx_netif_native_tx_get_len,
};

#define NX_NETIF_DOORBELL_MAX_DEQUEUE    64
uint32_t nx_netif_doorbell_max_dequeue = NX_NETIF_DOORBELL_MAX_DEQUEUE;

#define NQ_TRANSFER_DECAY       2               /* ilog2 of EWMA decay rate (4) */
static uint32_t nq_transfer_decay = NQ_TRANSFER_DECAY;

#define NQ_ACCUMULATE_INTERVAL  2 /* 2 seconds */
static uint32_t nq_accumulate_interval = NQ_ACCUMULATE_INTERVAL;

static uint32_t nq_stat_enable = 0;

SYSCTL_EXTENSIBLE_NODE(_kern_skywalk, OID_AUTO, netif,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Skywalk network interface");
#if (DEVELOPMENT || DEBUG)
SYSCTL_STRING(_kern_skywalk_netif, OID_AUTO, sk_ll_prefix,
    CTLFLAG_RW | CTLFLAG_LOCKED, sk_ll_prefix, sizeof(sk_ll_prefix),
    "ifname prefix for enabling low latency support");
static uint32_t nx_netif_force_ifnet_start = 0;
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, force_ifnet_start,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nx_netif_force_ifnet_start, 0,
    "always use ifnet starter thread");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, doorbell_max_dequeue,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nx_netif_doorbell_max_dequeue,
    NX_NETIF_DOORBELL_MAX_DEQUEUE,
    "max packets to dequeue in doorbell context");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, netif_queue_transfer_decay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nq_transfer_decay,
    NQ_TRANSFER_DECAY, "ilog2 of EWMA decay rate of netif queue transfers");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, netif_queue_stat_accumulate_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nq_accumulate_interval,
    NQ_ACCUMULATE_INTERVAL, "accumulation interval for netif queue stats");
#endif /* !DEVELOPMENT && !DEBUG */

SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, netif_queue_stat_enable,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nq_stat_enable,
    0, "enable/disable stats collection for netif queue");

static SKMEM_TYPE_DEFINE(na_netif_zone, struct nexus_netif_adapter);

static SKMEM_TYPE_DEFINE(nx_netif_zone, struct nx_netif);

#define SKMEM_TAG_NETIF_MIT          "com.apple.skywalk.netif.mit"
static SKMEM_TAG_DEFINE(skmem_tag_netif_mit, SKMEM_TAG_NETIF_MIT);

#define SKMEM_TAG_NETIF_FILTER       "com.apple.skywalk.netif.filter"
SKMEM_TAG_DEFINE(skmem_tag_netif_filter, SKMEM_TAG_NETIF_FILTER);

#define SKMEM_TAG_NETIF_FLOW         "com.apple.skywalk.netif.flow"
SKMEM_TAG_DEFINE(skmem_tag_netif_flow, SKMEM_TAG_NETIF_FLOW);

#define SKMEM_TAG_NETIF_AGENT_FLOW   "com.apple.skywalk.netif.agent_flow"
SKMEM_TAG_DEFINE(skmem_tag_netif_agent_flow, SKMEM_TAG_NETIF_AGENT_FLOW);

#define SKMEM_TAG_NETIF_LLINK        "com.apple.skywalk.netif.llink"
SKMEM_TAG_DEFINE(skmem_tag_netif_llink, SKMEM_TAG_NETIF_LLINK);

#define SKMEM_TAG_NETIF_QSET         "com.apple.skywalk.netif.qset"
SKMEM_TAG_DEFINE(skmem_tag_netif_qset, SKMEM_TAG_NETIF_QSET);

#define SKMEM_TAG_NETIF_LLINK_INFO   "com.apple.skywalk.netif.llink_info"
SKMEM_TAG_DEFINE(skmem_tag_netif_llink_info, SKMEM_TAG_NETIF_LLINK_INFO);

/* use this for any temporary allocations */
#define SKMEM_TAG_NETIF_TEMP         "com.apple.skywalk.netif.temp"
static SKMEM_TAG_DEFINE(skmem_tag_netif_temp, SKMEM_TAG_NETIF_TEMP);

static void
nx_netif_dom_init(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED));

	_CASSERT(NEXUS_PORT_NET_IF_DEV == 0);
	_CASSERT(NEXUS_PORT_NET_IF_HOST == 1);
	_CASSERT(NEXUS_PORT_NET_IF_CLIENT == 2);
	_CASSERT(SK_NETIF_MIT_FORCE_OFF < SK_NETIF_MIT_FORCE_SIMPLE);
	_CASSERT(SK_NETIF_MIT_FORCE_SIMPLE < SK_NETIF_MIT_FORCE_ADVANCED);
	_CASSERT(SK_NETIF_MIT_FORCE_ADVANCED < SK_NETIF_MIT_AUTO);
	_CASSERT(SK_NETIF_MIT_AUTO == SK_NETIF_MIT_MAX);

	(void) nxdom_prov_add(nxdom, &nx_netif_prov_s);

	nx_netif_compat_init(nxdom);

	ASSERT(nxdom_prov_default[nxdom->nxdom_type] != NULL &&
	    strcmp(nxdom_prov_default[nxdom->nxdom_type]->nxdom_prov_name,
	    NEXUS_PROVIDER_NET_IF_COMPAT) == 0);

	netif_gso_init();
}

static void
nx_netif_dom_terminate(struct nxdom *nxdom)
{
	struct kern_nexus_domain_provider *nxdom_prov, *tnxdp;

	SK_LOCK_ASSERT_HELD();

	netif_gso_fini();
	nx_netif_compat_fini();

	STAILQ_FOREACH_SAFE(nxdom_prov, &nxdom->nxdom_prov_head,
	    nxdom_prov_link, tnxdp) {
		(void) nxdom_prov_del(nxdom_prov);
	}
}

static void
nx_netif_dom_fini(struct nxdom *nxdom)
{
#pragma unused(nxdom)
}

int
nx_netif_prov_init(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);
	return 0;
}

static int
nx_netif_na_notify_drop(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(kring, p, flags)
	return ENXIO;
}

int
nx_netif_prov_nx_stop(struct kern_nexus *nx)
{
	uint32_t r;
	struct nexus_adapter *na = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;

	SK_LOCK_ASSERT_HELD();
	ASSERT(nx != NULL);

	/* place all rings in drop mode */
	na_kr_drop(na, TRUE);

	/* ensure global visibility */
	os_atomic_thread_fence(seq_cst);

	/* reset all TX notify callbacks */
	for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
		while (!os_atomic_cmpxchg((void * volatile *)&na->na_tx_rings[r].ckr_na_notify,
		    ptrauth_nop_cast(void *, na->na_tx_rings[r].ckr_na_notify),
		    ptrauth_nop_cast(void *, &nx_netif_na_notify_drop), acq_rel)) {
			;
		}
		os_atomic_thread_fence(seq_cst);
		if (nifna->nifna_tx_mit != NULL) {
			nx_netif_mit_cleanup(&nifna->nifna_tx_mit[r]);
		}
	}
	if (nifna->nifna_tx_mit != NULL) {
		skn_free_type_array(tx, struct nx_netif_mit,
		    na_get_nrings(na, NR_TX), nifna->nifna_tx_mit);
		nifna->nifna_tx_mit = NULL;
	}

	/* reset all RX notify callbacks */
	for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
		while (!os_atomic_cmpxchg((void * volatile *)&na->na_rx_rings[r].ckr_na_notify,
		    ptrauth_nop_cast(void *, na->na_rx_rings[r].ckr_na_notify),
		    ptrauth_nop_cast(void *, &nx_netif_na_notify_drop), acq_rel)) {
			;
		}
		os_atomic_thread_fence(seq_cst);
		if (nifna->nifna_rx_mit != NULL) {
			nx_netif_mit_cleanup(&nifna->nifna_rx_mit[r]);
		}
	}
	if (nifna->nifna_rx_mit != NULL) {
		skn_free_type_array(rx, struct nx_netif_mit,
		    na_get_nrings(na, NR_RX), nifna->nifna_rx_mit);
		nifna->nifna_rx_mit = NULL;
	}
	return 0;
}

static inline void
nx_netif_compat_adjust_ring_size(struct nxprov_adjusted_params *adj,
    ifnet_t ifp)
{
	if (IFNET_IS_CELLULAR(ifp) && (ifp->if_unit != 0)) {
		*(adj->adj_rx_slots) = sk_netif_compat_aux_cell_rx_ring_sz;
		*(adj->adj_tx_slots) = sk_netif_compat_aux_cell_tx_ring_sz;
	} else if (IFNET_IS_WIFI(ifp)) {
		if (ifp->if_name[0] == 'a' && ifp->if_name[1] == 'p' &&
		    ifp->if_name[2] == '\0') {
			/* Wi-Fi Access Point */
			*(adj->adj_rx_slots) = sk_netif_compat_wap_rx_ring_sz;
			*(adj->adj_tx_slots) = sk_netif_compat_wap_tx_ring_sz;
		} else if (ifp->if_eflags & IFEF_AWDL) {
			/* AWDL */
			*(adj->adj_rx_slots) = sk_netif_compat_awdl_rx_ring_sz;
			*(adj->adj_tx_slots) = sk_netif_compat_awdl_tx_ring_sz;
		} else {
			/* Wi-Fi infrastructure */
			*(adj->adj_rx_slots) = sk_netif_compat_wif_rx_ring_sz;
			*(adj->adj_tx_slots) = sk_netif_compat_wif_tx_ring_sz;
		}
	} else if (IFNET_IS_ETHERNET(ifp)) {
#if !XNU_TARGET_OS_OSX
		/*
		 * On non-macOS platforms, treat all compat Ethernet
		 * interfaces as USB Ethernet with reduced ring sizes.
		 */
		*(adj->adj_rx_slots) = sk_netif_compat_usb_eth_rx_ring_sz;
		*(adj->adj_tx_slots) = sk_netif_compat_usb_eth_tx_ring_sz;
#else /* XNU_TARGET_OS_OSX */
		if (ifp->if_subfamily == IFNET_SUBFAMILY_USB) {
			*(adj->adj_rx_slots) =
			    sk_netif_compat_usb_eth_rx_ring_sz;
			*(adj->adj_tx_slots) =
			    sk_netif_compat_usb_eth_tx_ring_sz;
		}
#endif /* XNU_TARGET_OS_OSX */
	}
}

static int
nx_netif_prov_params_adjust(const struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_params *nxp, struct nxprov_adjusted_params *adj)
{
	/*
	 * for netif compat adjust the following parameters for memory
	 * optimization:
	 * - change the size of buffer object to 128 bytes.
	 * - don't allocate rx ring for host port and tx ring for dev port.
	 * - for cellular interfaces other than pdp_ip0 reduce the ring size.
	 *   Assumption here is that pdp_ip0 is always used as the data
	 *   interface.
	 * - reduce the ring size for AWDL interface.
	 * - reduce the ring size for USB ethernet interface.
	 */
	if (strcmp(nxdom_prov->nxdom_prov_name,
	    NEXUS_PROVIDER_NET_IF_COMPAT) == 0) {
		/*
		 * Leave the parameters default if userspace access may be
		 * needed. We can't use skywalk_direct_allowed() here because
		 * the drivers have not attached yet.
		 */
		if (skywalk_netif_direct_enabled()) {
			goto done;
		}

		*(adj->adj_buf_size) = NETIF_COMPAT_BUF_SIZE;
		*(adj->adj_tx_rings) = 1;
		if (IF_INDEX_IN_RANGE(nxp->nxp_ifindex)) {
			ifnet_t ifp;
			ifnet_head_lock_shared();
			ifp = ifindex2ifnet[nxp->nxp_ifindex];
			ifnet_head_done();
			VERIFY(ifp != NULL);
			nx_netif_compat_adjust_ring_size(adj, ifp);
		}
	} else { /* netif native */
		if (nxp->nxp_flags & NXPF_NETIF_LLINK) {
			*(adj->adj_tx_slots) = NX_NETIF_MINSLOTS;
			*(adj->adj_rx_slots) = NX_NETIF_MINSLOTS;
		}
		/*
		 * Add another extra ring for host port. Note that if the
		 * nexus isn't configured to use the same pbufpool for all of
		 * its ports, we'd end up allocating extra here.
		 * Not a big deal since that case isn't the default.
		 */
		*(adj->adj_tx_rings) += 1;
		*(adj->adj_rx_rings) += 1;

		if ((*(adj->adj_buf_size) < PKT_MAX_PROTO_HEADER_SIZE)) {
			SK_ERR("buf size too small, min (%d)",
			    PKT_MAX_PROTO_HEADER_SIZE);
			return EINVAL;
		}
		_CASSERT(sizeof(struct __kern_netif_intf_advisory) ==
		    NX_INTF_ADV_SIZE);
		*(adj->adj_nexusadv_size) = sizeof(struct netif_nexus_advisory);
	}
done:
	return 0;
}

int
nx_netif_prov_params(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS],
    uint32_t pp_region_config_flags)
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;

	return nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	           nxdom, nxdom, nxdom, pp_region_config_flags,
	           nx_netif_prov_params_adjust);
}

int
nx_netif_prov_mem_new(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nxdom_prov)
	int err = 0;
	boolean_t pp_truncated_buf = FALSE;
	boolean_t allow_direct;
	boolean_t kernel_only;

	SK_DF(SK_VERB_NETIF,
	    "nx 0x%llx (\"%s\":\"%s\") na \"%s\" (0x%llx)", SK_KVA(nx),
	    NX_DOM(nx)->nxdom_name, nxdom_prov->nxdom_prov_name, na->na_name,
	    SK_KVA(na));

	ASSERT(na->na_arena == NULL);
	if ((na->na_type == NA_NETIF_COMPAT_DEV) ||
	    (na->na_type == NA_NETIF_COMPAT_HOST)) {
		pp_truncated_buf = TRUE;
	}
	/*
	 * We do this check to determine whether to create the extra
	 * regions needed for userspace access. This is per interface.
	 * NX_USER_CHANNEL_PROV() is systemwide so it can't be used.
	 */
	allow_direct = skywalk_netif_direct_allowed(na->na_name);

	/*
	 * Both ports (host and dev) share the same packet buffer pool;
	 * the first time a port gets opened will allocate the pp that
	 * gets stored in the nexus, which will then be used by any
	 * subsequent opens.
	 */
	kernel_only = !allow_direct || !NX_USER_CHANNEL_PROV(nx);
	na->na_arena = skmem_arena_create_for_nexus(na,
	    NX_PROV(nx)->nxprov_region_params, &nx->nx_tx_pp,
	    &nx->nx_rx_pp, pp_truncated_buf, kernel_only, &nx->nx_adv, &err);
	ASSERT(na->na_arena != NULL || err != 0);
	ASSERT(nx->nx_tx_pp == NULL || (nx->nx_tx_pp->pp_md_type ==
	    NX_DOM(nx)->nxdom_md_type && nx->nx_tx_pp->pp_md_subtype ==
	    NX_DOM(nx)->nxdom_md_subtype));

	return err;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_get_llink_info(struct sockopt *sopt, struct kern_nexus *nx)
{
	struct nx_llink_info_req *nlir = NULL;
	struct nx_netif *nif;
	struct netif_llink *llink;
	uint16_t llink_cnt;
	size_t len, user_len;
	int err, i;

	nif = NX_NETIF_PRIVATE(nx);
	if (!NETIF_LLINK_ENABLED(nif)) {
		SK_ERR("llink mode not enabled");
		return ENOTSUP;
	}
	lck_rw_lock_shared(&nif->nif_llink_lock);
	llink_cnt = nif->nif_llink_cnt;
	if (llink_cnt == 0) {
		SK_ERR("zero llink cnt");
		err = ENXIO;
		goto done;
	}
	len = sizeof(*nlir) + (sizeof(struct nx_llink_info) * llink_cnt);
	/* preserve sopt_valsize because it gets overwritten by copyin */
	user_len = sopt->sopt_valsize;
	if (user_len < len) {
		SK_ERR("buffer too small");
		err = ENOBUFS;
		goto done;
	}
	nlir = sk_alloc_data(len, Z_WAITOK, skmem_tag_netif_llink_info);
	if (nlir == NULL) {
		SK_ERR("failed to allocate nlir");
		err = ENOMEM;
		goto done;
	}
	err = sooptcopyin(sopt, nlir, sizeof(*nlir), sizeof(*nlir));
	if (err != 0) {
		SK_ERR("copyin failed: %d", err);
		goto done;
	}
	if (nlir->nlir_version != NETIF_LLINK_INFO_VERSION) {
		SK_ERR("nlir version mismatch: %d != %d",
		    nlir->nlir_version, NETIF_LLINK_INFO_VERSION);
		err = ENOTSUP;
		goto done;
	}
	nlir->nlir_llink_cnt = llink_cnt;
	i = 0;
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		struct nx_llink_info *nli;
		struct netif_qset *qset;
		uint16_t qset_cnt;
		int j;

		nli = &nlir->nlir_llink[i];
		nli->nli_link_id = llink->nll_link_id;
		nli->nli_link_id_internal = llink->nll_link_id_internal;
		nli->nli_state = llink->nll_state;
		nli->nli_flags = llink->nll_flags;

		qset_cnt = llink->nll_qset_cnt;
		ASSERT(qset_cnt <= NETIF_LLINK_MAX_QSETS);
		nli->nli_qset_cnt = qset_cnt;

		j = 0;
		SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
			struct nx_qset_info *nqi;

			nqi = &nli->nli_qset[j];
			nqi->nqi_id = qset->nqs_id;
			nqi->nqi_flags = qset->nqs_flags;
			nqi->nqi_num_rx_queues = qset->nqs_num_rx_queues;
			nqi->nqi_num_tx_queues = qset->nqs_num_tx_queues;
			j++;
		}
		ASSERT(j == qset_cnt);
		i++;
	}
	ASSERT(i == llink_cnt);
	sopt->sopt_valsize = user_len;
	err = sooptcopyout(sopt, nlir, len);
	if (err != 0) {
		SK_ERR("sooptcopyout failed: %d", err);
	}
done:
	lck_rw_unlock_shared(&nif->nif_llink_lock);
	if (nlir != NULL) {
		sk_free_data(nlir, len);
	}
	return err;
}

int
nx_netif_prov_config(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nx_cfg_req *ncr, int sopt_dir,
    struct proc *p, kauth_cred_t cred)
{
#pragma unused(nxdom_prov)
	struct sockopt sopt;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	/* proceed only if the client possesses netif entitlement */
	if ((err = skywalk_priv_check_cred(p, cred,
	    PRIV_SKYWALK_REGISTER_NET_IF)) != 0) {
		goto done;
	}

	if (ncr->nc_req == USER_ADDR_NULL) {
		err = EINVAL;
		goto done;
	}

	/* to make life easier for handling copies */
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = sopt_dir;
	sopt.sopt_val = ncr->nc_req;
	sopt.sopt_valsize = ncr->nc_req_len;
	sopt.sopt_p = p;

	switch (ncr->nc_cmd) {
	case NXCFG_CMD_ATTACH:
	case NXCFG_CMD_DETACH: {
		struct nx_spec_req nsr;

		bzero(&nsr, sizeof(nsr));
		err = sooptcopyin(&sopt, &nsr, sizeof(nsr), sizeof(nsr));
		if (err != 0) {
			goto done;
		}

		/*
		 * Null-terminate in case this has an interface name;
		 * the union is already large enough for uuid_t.
		 */
		nsr.nsr_name[sizeof(nsr.nsr_name) - 1] = '\0';
		if (p != kernproc) {
			nsr.nsr_flags &= NXSPECREQ_MASK;
		}

		err = nx_netif_ctl(nx, ncr->nc_cmd, &nsr, p);
		if (err != 0) {
			goto done;
		}

		/* XXX: adi@apple.com -- can this copyout fail? */
		(void) sooptcopyout(&sopt, &nsr, sizeof(nsr));
		break;
	}
	case NXCFG_CMD_FLOW_ADD:
	case NXCFG_CMD_FLOW_DEL: {
		_CASSERT(offsetof(struct nx_flow_req, _nfr_kernel_field_end) ==
		    offsetof(struct nx_flow_req, _nfr_common_field_end));
		struct nx_flow_req nfr;

		bzero(&nfr, sizeof(nfr));
		err = sooptcopyin(&sopt, &nfr, sizeof(nfr), sizeof(nfr));
		if (err != 0) {
			goto done;
		}

		err = nx_netif_ctl(nx, ncr->nc_cmd, &nfr, p);
		if (err != 0) {
			goto done;
		}

		/* XXX: adi@apple.com -- can this copyout fail? */
		(void) sooptcopyout(&sopt, &nfr, sizeof(nfr));
		break;
	}
	case NXCFG_CMD_GET_LLINK_INFO: {
		err = nx_netif_get_llink_info(&sopt, nx);
		break;
	}
	default:
		err = EINVAL;
		goto done;
	}
done:
	SK_DF(err ? SK_VERB_ERROR : SK_VERB_NETIF,
	    "nexus 0x%llx (%s) cmd %d err %d", SK_KVA(nx),
	    NX_DOM_PROV(nx)->nxdom_prov_name, ncr->nc_cmd, err);
	return err;
}

void
nx_netif_prov_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);
}

int
nx_netif_prov_nx_ctor(struct kern_nexus *nx)
{
	struct nx_netif *n;
	char name[64];
	int error;

	SK_LOCK_ASSERT_HELD();
	ASSERT(nx->nx_arg == NULL);

	SK_D("nexus 0x%llx (%s)", SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name);

	nx->nx_arg = nx_netif_alloc(Z_WAITOK);
	n = NX_NETIF_PRIVATE(nx);
	if (NX_USER_CHANNEL_PROV(nx) &&
	    NX_PROV(nx)->nxprov_params->nxp_nexusadv_size != 0) {
		(void) snprintf(name, sizeof(name), "netif_%llu", nx->nx_id);
		error = nx_advisory_alloc(nx, name,
		    &NX_PROV(nx)->nxprov_region_params[SKMEM_REGION_NEXUSADV],
		    NEXUS_ADVISORY_TYPE_NETIF);
		if (error != 0) {
			nx_netif_free(n);
			return error;
		}
	}
	n->nif_nx = nx;
	SK_D("create new netif 0x%llx for nexus 0x%llx",
	    SK_KVA(NX_NETIF_PRIVATE(nx)), SK_KVA(nx));
	return 0;
}

void
nx_netif_prov_nx_dtor(struct kern_nexus *nx)
{
	struct nx_netif *n = NX_NETIF_PRIVATE(nx);

	SK_LOCK_ASSERT_HELD();

	SK_D("nexus 0x%llx (%s) netif 0x%llx", SK_KVA(nx),
	    NX_DOM_PROV(nx)->nxdom_prov_name, SK_KVA(n));

	/*
	 * XXX
	 * detach should be done separately to be symmetrical with attach.
	 */
	nx_advisory_free(nx);
	if (nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV) != NULL) {
		/* we're called by nx_detach(), so this cannot fail */
		int err = nx_netif_ctl_detach(nx, NULL);
		VERIFY(err == 0);
	}
	if (n->nif_dev_nxb != NULL) {
		nxb_free(n->nif_dev_nxb);
		n->nif_dev_nxb = NULL;
	}
	if (n->nif_host_nxb != NULL) {
		nxb_free(n->nif_host_nxb);
		n->nif_host_nxb = NULL;
	}
	SK_DF(SK_VERB_NETIF, "marking netif 0x%llx as free", SK_KVA(n));
	nx_netif_free(n);
	nx->nx_arg = NULL;
}

int
nx_netif_prov_nx_mem_info(struct kern_nexus *nx, struct kern_pbufpool **tpp,
    struct kern_pbufpool **rpp)
{
	ASSERT(nx->nx_tx_pp != NULL);
	ASSERT(nx->nx_rx_pp != NULL);

	if (tpp != NULL) {
		*tpp = nx->nx_tx_pp;
	}
	if (rpp != NULL) {
		*rpp = nx->nx_rx_pp;
	}

	return 0;
}

static size_t
__netif_mib_get_stats(struct kern_nexus *nx, void *out, size_t len)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct ifnet *ifp = nif->nif_ifp;
	struct sk_stats_net_if *sns = out;
	size_t actual_space = sizeof(struct sk_stats_net_if);

	if (out != NULL && actual_space <= len) {
		uuid_copy(sns->sns_nx_uuid, nx->nx_uuid);
		if (ifp != NULL) {
			(void) strlcpy(sns->sns_if_name, if_name(ifp), IFNAMSIZ);
		}
		sns->sns_nifs = nif->nif_stats;
	}

	return actual_space;
}

static size_t
__netif_mib_get_llinks(struct kern_nexus *nx, void *out, size_t len)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nx_llink_info *nli_list = out;
	size_t actual_space = 0;
	if (NETIF_LLINK_ENABLED(nif)) {
		lck_rw_lock_shared(&nif->nif_llink_lock);
		actual_space += nif->nif_llink_cnt * sizeof(struct nx_llink_info);

		if (out != NULL && actual_space <= len) {
			struct netif_llink *llink;
			int i = 0;
			STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
				struct nx_llink_info *nli;
				struct netif_qset *qset;
				uint16_t qset_cnt;
				int j;

				nli = &nli_list[i];
				uuid_copy(nli->nli_netif_uuid, nx->nx_uuid);
				nli->nli_link_id = llink->nll_link_id;
				nli->nli_link_id_internal = llink->nll_link_id_internal;
				nli->nli_state = llink->nll_state;
				nli->nli_flags = llink->nll_flags;

				qset_cnt = llink->nll_qset_cnt;
				ASSERT(qset_cnt <= NETIF_LLINK_MAX_QSETS);
				nli->nli_qset_cnt = qset_cnt;

				j = 0;
				SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
					struct nx_qset_info *nqi;

					nqi = &nli->nli_qset[j];
					nqi->nqi_id = qset->nqs_id;
					nqi->nqi_flags = qset->nqs_flags;
					nqi->nqi_num_rx_queues = qset->nqs_num_rx_queues;
					nqi->nqi_num_tx_queues = qset->nqs_num_tx_queues;
					j++;
				}
				ASSERT(j == qset_cnt);
				i++;
			}
			ASSERT(i == nif->nif_llink_cnt);
		}
		lck_rw_unlock_shared(&nif->nif_llink_lock);
	}

	return actual_space;
}

static size_t
__netif_mib_get_queue_stats(struct kern_nexus *nx, void *out, size_t len)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	uint8_t *itr = out;
	size_t actual_space = 0;
	if (!NETIF_LLINK_ENABLED(nif)) {
		return actual_space;
	}

	lck_rw_lock_shared(&nif->nif_llink_lock);
	struct netif_llink *llink;
	struct netif_qset *qset;
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
			actual_space += sizeof(struct netif_qstats_info) *
			    (qset->nqs_num_rx_queues + qset->nqs_num_tx_queues);
		}
	}
	if (out == NULL || actual_space > len) {
		lck_rw_unlock_shared(&nif->nif_llink_lock);
		return actual_space;
	}

	llink = NULL;
	qset = NULL;
	uint16_t i = 0, j = 0;
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		uint16_t qset_cnt;
		j = 0;
		qset_cnt = llink->nll_qset_cnt;
		ASSERT(qset_cnt <= NETIF_LLINK_MAX_QSETS);
		SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
			int queue_cnt = qset->nqs_num_rx_queues +
			    qset->nqs_num_tx_queues;
			for (uint16_t k = 0; k < queue_cnt; k++) {
				struct netif_qstats_info *nqi =
				    (struct netif_qstats_info *)(void *)itr;
				struct netif_queue *nq = &qset->nqs_driver_queues[k];
				nqi->nqi_qset_id = qset->nqs_id;
				nqi->nqi_queue_idx = k;
				if (KPKT_VALID_SVC(nq->nq_svc)) {
					nqi->nqi_svc = (packet_svc_class_t)nq->nq_svc;
				}
				if (nq->nq_flags & NETIF_QUEUE_IS_RX) {
					nqi->nqi_queue_flag = NQI_QUEUE_FLAG_IS_RX;
				}

				struct netif_qstats *nq_out = &nqi->nqi_stats;
				struct netif_qstats *nq_src = &nq->nq_stats;
				memcpy(nq_out, nq_src, sizeof(struct netif_qstats));

				itr += sizeof(struct netif_qstats_info);
			}
			j++;
		}
		ASSERT(j == qset_cnt);
		i++;
	}
	ASSERT(i == nif->nif_llink_cnt);

	lck_rw_unlock_shared(&nif->nif_llink_lock);
	return actual_space;
}

size_t
nx_netif_prov_nx_mib_get(struct kern_nexus *nx, struct nexus_mib_filter *filter,
    void *out, size_t len, struct proc *p)
{
#pragma unused(p)
	size_t ret;

	if ((filter->nmf_bitmap & NXMIB_FILTER_NX_UUID) &&
	    (uuid_compare(filter->nmf_nx_uuid, nx->nx_uuid)) != 0) {
		return 0;
	}

	switch (filter->nmf_type) {
	case NXMIB_NETIF_STATS:
		ret = __netif_mib_get_stats(nx, out, len);
		break;
	case NXMIB_LLINK_LIST:
		ret = __netif_mib_get_llinks(nx, out, len);
		break;
	case NXMIB_NETIF_QUEUE_STATS:
		ret = __netif_mib_get_queue_stats(nx, out, len);
		break;
	default:
		ret = 0;
		break;
	}
	return ret;
}

static int
nx_netif_dom_bind_port(struct kern_nexus *nx, nexus_port_t *nx_port,
    struct nxbind *nxb, void *info)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	nexus_port_t first, last, port;
	int error;

	ASSERT(nx_port != NULL);
	ASSERT(nxb != NULL);

	port = *nx_port;

	/*
	 * If port is:
	 * != NEXUS_PORT_ANY: attempt to bind to the specified port
	 * == NEXUS_PORT_ANY: find an available port, bind to it, and
	 *                    return back the assigned port.
	 */
	first = NEXUS_PORT_NET_IF_CLIENT;
	ASSERT(NXDOM_MAX(NX_DOM(nx), ports) <= NEXUS_PORT_MAX);
	last = (nexus_port_size_t)NXDOM_MAX(NX_DOM(nx), ports);
	ASSERT(first <= last);

	NETIF_WLOCK(nif);

	if (__improbable(first == last)) {
		error = ENOMEM;
	} else if (port != NEXUS_PORT_ANY) {
		error = nx_port_bind_info(nx, port, nxb, info);
		SK_DF(SK_VERB_NETIF, "port %d, bind err %d", port, error);
	} else {
		error = nx_port_find(nx, first, last - 1, &port);
		ASSERT(error != 0 || (port >= first && port < last));
		if (error == 0) {
			error = nx_port_bind_info(nx, port, nxb, info);
			SK_DF(SK_VERB_NETIF, "found port %d, bind err %d",
			    port, error);
		}
	}
	NETIF_WUNLOCK(nif);

	ASSERT(*nx_port == NEXUS_PORT_ANY || *nx_port == port);
	if (error == 0) {
		*nx_port = port;
	}

	SK_DF(error ? SK_VERB_ERROR : SK_VERB_NETIF,
	    "+++ netif 0x%llx nx_port %d, total %u active %u (err %d)",
	    SK_KVA(nif), (int)*nx_port, NX_NETIF_MAXPORTS,
	    nx->nx_active_ports, error);

	return error;
}

static int
nx_netif_dom_unbind_port(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	int error = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);

	NETIF_WLOCK(nif);
	error = nx_port_unbind(nx, nx_port);
	NETIF_WUNLOCK(nif);

	return error;
}

static int
nx_netif_dom_connect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
#pragma unused(nxdom_prov)
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	ASSERT(NX_DOM_PROV(nx) == nxdom_prov);
	ASSERT(nx->nx_prov->nxprov_params->nxp_type ==
	    nxdom_prov->nxdom_prov_dom->nxdom_type &&
	    nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_NET_IF);
	ASSERT(!(ch->ch_flags & CHANF_HOST));

	switch (chr->cr_port) {
	case NEXUS_PORT_NET_IF_DEV:
		if (chr->cr_mode & CHMODE_HOST) {
			err = EINVAL;
			goto done;
		}
		break;

	case NEXUS_PORT_NET_IF_HOST:
		if (!(chr->cr_mode & CHMODE_HOST)) {
			if (ch->ch_flags & CHANF_KERNEL) {
				err = EINVAL;
				goto done;
			}
			chr->cr_mode |= CHMODE_HOST;
		}
		/*
		 * This channel is exclusively opened to the host
		 * rings; don't notify the external provider.
		 */
		os_atomic_or(&ch->ch_flags, CHANF_HOST | CHANF_EXT_SKIP, relaxed);
		break;

	default:
		/*
		 * This channel is shared between netif and user process;
		 * don't notify the external provider.
		 */
		os_atomic_or(&ch->ch_flags, CHANF_EXT_SKIP, relaxed);
		break;
	}

	chr->cr_ring_set = RING_SET_DEFAULT;
	chr->cr_real_endpoint = chr->cr_endpoint = CH_ENDPOINT_NET_IF;
	(void) snprintf(chr->cr_name, sizeof(chr->cr_name), "netif:%llu:%.*s",
	    nx->nx_id, (int)nx->nx_prov->nxprov_params->nxp_namelen,
	    nx->nx_prov->nxprov_params->nxp_name);

	if (ch->ch_flags & CHANF_KERNEL) {
		err = na_connect_spec(nx, ch, chr, p);
	} else {
		err = na_connect(nx, ch, chr, ch0, nxb, p);
	}

	if (err == 0) {
		/*
		 * Mark the kernel slot descriptor region as busy; this
		 * prevents it from being torn-down at channel defunct
		 * time, as the (external) nexus owner may be calling
		 * KPIs that require accessing the slots.
		 */
		skmem_arena_nexus_sd_set_noidle(
			skmem_arena_nexus(ch->ch_na->na_arena), 1);
	}

done:
	return err;
}

static void
nx_netif_dom_disconnect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nxdom_prov)
	SK_LOCK_ASSERT_HELD();

	SK_D("channel 0x%llx -!- nexus 0x%llx (%s:\"%s\":%u:%d)", SK_KVA(ch),
	    SK_KVA(nx), nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	/*
	 * Release busy assertion held earlier in nx_netif_dom_connect();
	 * this allows for the final arena teardown to succeed.
	 */
	skmem_arena_nexus_sd_set_noidle(
		skmem_arena_nexus(ch->ch_na->na_arena), -1);

	if (ch->ch_flags & CHANF_KERNEL) {
		na_disconnect_spec(nx, ch);
	} else {
		na_disconnect(nx, ch);
	}
}

static void
nx_netif_dom_defunct(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct proc *p)
{
#pragma unused(nxdom_prov, nx)
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_NETIF_DEV ||
	    ch->ch_na->na_type == NA_NETIF_HOST ||
	    ch->ch_na->na_type == NA_NETIF_COMPAT_DEV ||
	    ch->ch_na->na_type == NA_NETIF_COMPAT_HOST ||
	    ch->ch_na->na_type == NA_NETIF_VP);

	na_ch_rings_defunct(ch, p);
}

static void
nx_netif_dom_defunct_finalize(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, boolean_t locked)
{
#pragma unused(nxdom_prov)
	struct ifnet *ifp;

	if (!locked) {
		SK_LOCK_ASSERT_NOTHELD();
		SK_LOCK();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
	} else {
		SK_LOCK_ASSERT_HELD();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	}

	ASSERT(ch->ch_na->na_type == NA_NETIF_DEV ||
	    ch->ch_na->na_type == NA_NETIF_HOST ||
	    ch->ch_na->na_type == NA_NETIF_COMPAT_DEV ||
	    ch->ch_na->na_type == NA_NETIF_COMPAT_HOST ||
	    ch->ch_na->na_type == NA_NETIF_VP);

	na_defunct(nx, ch, ch->ch_na, locked);
	ifp = ch->ch_na->na_ifp;
	if (ch->ch_na->na_type == NA_NETIF_VP && ifp != NULL &&
	    ifnet_is_low_latency(ifp)) {
		/*
		 * We release the VPNA's ifp here instead of waiting for the
		 * application to close the channel to trigger the release.
		 */
		DTRACE_SKYWALK2(release__vpna__ifp, struct nexus_adapter *,
		    ch->ch_na, struct ifnet *, ifp);
		ifnet_decr_iorefcnt(ifp);
		ch->ch_na->na_ifp = NULL;
	}
	SK_D("%s(%d): ch 0x%llx -/- nx 0x%llx (%s:\"%s\":%u:%d)",
	    ch->ch_name, ch->ch_pid, SK_KVA(ch), SK_KVA(nx),
	    nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	if (!locked) {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
		SK_UNLOCK();
	} else {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
		SK_LOCK_ASSERT_HELD();
	}
}

struct nexus_netif_adapter *
na_netif_alloc(zalloc_flags_t how)
{
	_CASSERT(offsetof(struct nexus_netif_adapter, nifna_up) == 0);

	return zalloc_flags(na_netif_zone, how | Z_ZERO);
}

void
na_netif_free(struct nexus_adapter *na)
{
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;

	SK_LOCK_ASSERT_HELD();
	SK_DF(SK_VERB_MEM, "nifna 0x%llx FREE", SK_KVA(nifna));

	ASSERT(na->na_refcount == 0);
	ASSERT(nifna->nifna_tx_mit == NULL);
	ASSERT(nifna->nifna_rx_mit == NULL);
	bzero(nifna, sizeof(*nifna));

	zfree(na_netif_zone, nifna);
}

/* Process NXCFG_CMD_ATTACH */
SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl_attach(struct kern_nexus *nx, struct nx_spec_req *nsr,
    struct proc *p)
{
	struct nx_netif *n = NX_NETIF_PRIVATE(nx);
	struct ifnet *ifp = NULL;
	boolean_t compat;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	ASSERT(NX_DOM(nx)->nxdom_type == NEXUS_TYPE_NET_IF);
	compat = (strcmp(NX_DOM_PROV(nx)->nxdom_prov_name,
	    NEXUS_PROVIDER_NET_IF_COMPAT) == 0);

	uuid_clear(nsr->nsr_if_uuid);
	/*
	 * The netif accepts either an interface name or a pointer to
	 * an ifnet, but never a UUID.
	 */
	if (nsr->nsr_flags & NXSPECREQ_UUID) {
		err = EINVAL;
		goto done;
	}
	if (nsr->nsr_flags & NXSPECREQ_IFP) {
		if (p != kernproc || (ifp = nsr->nsr_ifp) == NULL) {
			err = EINVAL;
			goto done;
		}
	} else if ((ifp = ifunit_ref(nsr->nsr_name)) == NULL) {
		err = ENXIO;
		goto done;
	}

	if ((compat && SKYWALK_NATIVE(ifp)) ||
	    (!compat && !SKYWALK_NATIVE(ifp))) {
		/* native driver for netif; non-native for netif_compat  */
		err = ENODEV;
	} else if (ifp->if_na != NULL || !uuid_is_null(n->nif_uuid)) {
		err = EBUSY;
	} else {
		ASSERT(uuid_is_null(n->nif_uuid));
		/*
		 * Upon success, callee will hold its own ifnet iorefcnt
		 * as well as a retain count on the nexus adapter.
		 */
		if (compat) {
			err = nx_netif_compat_attach(nx, ifp);
		} else {
			err = nx_netif_attach(nx, ifp);
		}

		if (err == 0) {
			/* return the adapter UUID */
			uuid_generate_random(n->nif_uuid);
			uuid_copy(nsr->nsr_if_uuid, n->nif_uuid);
#if (DEVELOPMENT || DEBUG)
			skoid_create(&n->nif_skoid,
			    SKOID_SNODE(_kern_skywalk_netif), if_name(ifp),
			    CTLFLAG_RW);
#endif /* !DEVELOPMENT && !DEBUG */
		}
	}
done:
	/* drop I/O refcnt from ifunit_ref() */
	if (ifp != NULL && !(nsr->nsr_flags & NXSPECREQ_IFP)) {
		ifnet_decr_iorefcnt(ifp);
	}

#if SK_LOG
	uuid_string_t uuidstr, ifuuidstr;
	const char *nustr;
	if (nsr->nsr_flags & NXSPECREQ_UUID) {
		nustr = sk_uuid_unparse(nsr->nsr_uuid, uuidstr);
	} else if (nsr->nsr_flags & NXSPECREQ_IFP) {
		(void) snprintf((char *)uuidstr, sizeof(uuidstr), "0x%llx",
		    SK_KVA(nsr->nsr_ifp));
		nustr = uuidstr;
	} else {
		nustr = nsr->nsr_name;
	}
	SK_DF(err ? SK_VERB_ERROR : SK_VERB_NETIF,
	    "nexus 0x%llx (%s) name/uuid \"%s\" if_uuid %s flags 0x%x err %d",
	    SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name, nustr,
	    sk_uuid_unparse(nsr->nsr_if_uuid, ifuuidstr), nsr->nsr_flags, err);
#endif /* SK_LOG */

	return err;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_clean(struct nx_netif *nif, boolean_t quiesce_needed)
{
	struct kern_nexus *nx = nif->nif_nx;
	struct ifnet *ifp;
	boolean_t suspended = FALSE;

	ifp = nif->nif_ifp;
	if (ifp == NULL) {
		return EALREADY;
	}
	/*
	 * For regular kernel-attached interfaces, quiescing is handled by
	 * the ifnet detach thread, which calls dlil_quiesce_and_detach_nexuses().
	 * For interfaces created by skywalk test cases, flowswitch/netif nexuses
	 * are constructed on the fly and can also be torn down on the fly.
	 * dlil_quiesce_and_detach_nexuses() won't help here because any nexus
	 * can be detached while the interface is still attached.
	 */
	if (quiesce_needed && ifnet_datamov_suspend_if_needed(ifp)) {
		SK_UNLOCK();
		suspended = TRUE;
		ifnet_datamov_drain(ifp);
		SK_LOCK();
	}
	nx_netif_callbacks_fini(nif);
	nx_netif_agent_fini(nif);
	nx_netif_capabilities_fini(nif);
	nx_netif_flow_fini(nif);
	nx_netif_filter_fini(nif);
	nx_netif_llink_fini(nif);
	nx_netif_flags_fini(nif);

	uuid_clear(nif->nif_uuid);
	/* nx_netif_{compat_}attach() held both references */
	na_release_locked(nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV));
	na_release_locked(nx_port_get_na(nx, NEXUS_PORT_NET_IF_HOST));
	nx_port_free(nx, NEXUS_PORT_NET_IF_DEV);
	nx_port_free(nx, NEXUS_PORT_NET_IF_HOST);

	ifp->if_na_ops = NULL;
	ifp->if_na = NULL;
	nif->nif_ifp = NULL;
	nif->nif_netif_nxadv = NULL;
	SKYWALK_CLEAR_CAPABLE(ifp);
	if (suspended) {
		ifnet_datamov_resume(ifp);
	}

#if (DEVELOPMENT || DEBUG)
	skoid_destroy(&nif->nif_skoid);
#endif /* !DEVELOPMENT && !DEBUG */
	return 0;
}

/* process NXCFG_CMD_DETACH */
SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl_detach(struct kern_nexus *nx, struct nx_spec_req *nsr)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	/*
	 * nsr is NULL when we're called from the destructor, and it
	 * implies that we'll detach whatever that is attached.
	 */
	if (nsr != NULL && uuid_is_null(nsr->nsr_if_uuid)) {
		err = EINVAL;
	} else if (nsr != NULL && uuid_compare(nsr->nsr_if_uuid,
	    nif->nif_uuid) != 0) {
		err = ESRCH;
	} else if (nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV) == NULL) {
		/* nx_netif_ctl_attach() not yet done or already detached */
		err = ENXIO;
	} else if (nx->nx_ch_count != 0) {
		/*
		 * There's at least a channel opened; we can't
		 * yank the interface from underneath the nexus
		 * since our dlil input/output handler may be
		 * running now.  Bail out and come back here
		 * again when the nexus detaches.
		 */
		err = EBUSY;
	} else {
		err = nx_netif_clean(nif, TRUE);
	}

#if SK_LOG
	if (nsr != NULL) {
		uuid_string_t ifuuidstr;
		SK_DF(err ? SK_VERB_ERROR : SK_VERB_NETIF,
		    "nexus 0x%llx (%s) if_uuid %s flags 0x%x err %d",
		    SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
		    sk_uuid_unparse(nsr->nsr_if_uuid, ifuuidstr),
		    nsr->nsr_flags, err);
	} else {
		SK_DF(err ? SK_VERB_ERROR : SK_VERB_NETIF,
		    "nexus 0x%llx (%s) err %d", SK_KVA(nx),
		    NX_DOM_PROV(nx)->nxdom_prov_name, err);
	}
#endif /* SK_LOG */

	return err;
}

/*
 * XXX
 * These checks are copied from fsw.c
 * There are no tests exercising this code. Do we still need this?
 */
SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl_flow_check(struct nx_netif *nif, nxcfg_cmd_t cmd,
    struct proc *p, struct nx_flow_req *req)
{
#pragma unused(nif)
	boolean_t need_check;
	int error;

	if (uuid_is_null(req->nfr_flow_uuid)) {
		return EINVAL;
	}
	req->nfr_flags &= NXFLOWREQF_MASK;
	req->nfr_flowadv_idx = FLOWADV_IDX_NONE;

	if (cmd == NXCFG_CMD_FLOW_DEL) {
		return 0;
	}
	need_check = FALSE;
	if (req->nfr_epid != -1 && proc_pid(p) != req->nfr_epid) {
		need_check = TRUE;
	} else if (!uuid_is_null(req->nfr_euuid)) {
		uuid_t uuid;

		/* get the UUID of the issuing process */
		proc_getexecutableuuid(p, uuid, sizeof(uuid));

		/*
		 * If this is not issued by a process for its own
		 * executable UUID and if the process does not have
		 * the necessary privilege, reject the request.
		 * The logic is similar to so_set_effective_uuid().
		 */
		if (uuid_compare(req->nfr_euuid, uuid) != 0) {
			need_check = TRUE;
		}
	}
	if (need_check) {
		kauth_cred_t cred = kauth_cred_proc_ref(p);
		error = priv_check_cred(cred,
		    PRIV_NET_PRIVILEGED_SOCKET_DELEGATE, 0);
		kauth_cred_unref(&cred);
		if (error != 0) {
			return error;
		}
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl_flow_add(struct nx_netif *nif, struct proc *p,
    struct nx_flow_req *req)
{
	int err;

	ASSERT(p != PROC_NULL);
	err = nx_netif_ctl_flow_check(nif, NXCFG_CMD_FLOW_ADD, p, req);
	if (err != 0) {
		return err;
	}

	/* init kernel only fields */
	nx_flow_req_internalize(req);
	req->nfr_context = NULL;
	req->nfr_flow_stats = NULL;
	req->nfr_port_reservation = NULL;
	req->nfr_pid = proc_pid(p);

	err = nx_netif_netagent_flow_add(nif, req);
	nx_flow_req_externalize(req);
	return err;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl_flow_del(struct nx_netif *nif, struct proc *p,
    struct nx_flow_req *req)
{
	int err;

	err = nx_netif_ctl_flow_check(nif, NXCFG_CMD_FLOW_DEL, p, req);
	if (err != 0) {
		return err;
	}

	nx_flow_req_internalize(req);
	req->nfr_pid = proc_pid(p);

	err = nx_netif_netagent_flow_del(nif, req);
	nx_flow_req_externalize(req);
	return err;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_ctl(struct kern_nexus *nx, nxcfg_cmd_t nc_cmd, void *data,
    struct proc *p)
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nx_spec_req *nsr = data;
	struct nx_flow_req *nfr = data;
	int error = 0;

	SK_LOCK_ASSERT_HELD();

	switch (nc_cmd) {
	case NXCFG_CMD_ATTACH:
		error = nx_netif_ctl_attach(nx, nsr, p);
		break;

	case NXCFG_CMD_DETACH:
		error = nx_netif_ctl_detach(nx, nsr);
		break;

	case NXCFG_CMD_FLOW_ADD:
		error = nx_netif_ctl_flow_add(nif, p, nfr);
		break;

	case NXCFG_CMD_FLOW_DEL:
		error = nx_netif_ctl_flow_del(nif, p, nfr);
		break;

	default:
		SK_ERR("invalid cmd %u", nc_cmd);
		error = EINVAL;
		break;
	}
	return error;
}

static void
nx_netif_llink_notify(struct kern_nexus *nx, struct netif_llink *llink,
    uint32_t flags)
{
#pragma unused(flags)
	struct netif_qset *qset;

	SLIST_FOREACH(qset, &llink->nll_qset_list, nqs_list) {
		(void) nx_tx_qset_notify(nx, qset->nqs_ctx);
	}
}

static void
nx_netif_llink_notify_all(struct kern_nexus *nx, uint32_t flags)
{
	struct nx_netif *nif;
	struct netif_llink *llink;

	nif = NX_NETIF_PRIVATE(nx);

	lck_rw_lock_shared(&nif->nif_llink_lock);
	STAILQ_FOREACH(llink, &nif->nif_llink_list, nll_link) {
		nx_netif_llink_notify(nx, llink, flags);
	}
	lck_rw_unlock_shared(&nif->nif_llink_lock);
}

/*
 * if_start() callback for native Skywalk interfaces, registered
 * at ifnet_allocate_extended() time, and invoked by the ifnet
 * starter thread.
 */
static void
nx_netif_doorbell_internal(struct ifnet *ifp, uint32_t flags)
{
	if (__improbable(ifp->if_na == NULL)) {
		return;
	}

	/*
	 * Do this only if the nexus adapter is active, i.e. a channel
	 * has been opened to it by the module above (flowswitch, etc.)
	 */
	struct nexus_adapter *hwna = &NA(ifp)->nifna_up;
	if (__probable(NA_IS_ACTIVE(hwna))) {
		struct kern_nexus *nx = hwna->na_nx;

		/* update our work timestamp */
		hwna->na_work_ts = _net_uptime;

		if (NX_LLINK_PROV(nx)) {
			nx_netif_llink_notify_all(nx, flags);
		} else {
			struct __kern_channel_ring *kring;

			/* for doorbell purposes, use TX ring 0 */
			kring = &hwna->na_tx_rings[0];

			/* Issue a synchronous TX doorbell on the netif device ring */
			kring->ckr_na_sync(kring, PROC_NULL,
			    (NA_SYNCF_NETIF_DOORBELL | NA_SYNCF_NETIF_IFSTART));
		}
	} else {
		struct netif_stats *nifs =
		    &NX_NETIF_PRIVATE(hwna->na_nx)->nif_stats;
		STATS_INC(nifs, NETIF_STATS_DROP_NA_INACTIVE);
	}
}

static void
nx_netif_doorbell(struct ifnet *ifp)
{
	nx_netif_doorbell_internal(ifp, NETIF_XMIT_FLAG_HOST);
}

/*
 * TX sync callback, called from nx_netif_doorbell() where we'd expect to
 * perform synchronous TX doorbell to the driver, by invoking the driver's
 * doorbell callback directly in the same thread context.  It is also called
 * when the layer above performs a TX sync operation, where we might need
 * to do an asynchronous doorbell instead, by simply calling ifnet_start().
 */
static int
nx_netif_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	struct ifnet *ifp = KRNA(kring)->na_ifp;
	boolean_t sync_only;
	int ret = 0;

	ASSERT(ifp != NULL);

	SK_DF(SK_VERB_NETIF | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	if (__improbable(!IF_FULLY_ATTACHED(ifp))) {
		SK_ERR("kr 0x%llx ifp %s (0x%llx), interface not attached",
		    SK_KVA(kring), if_name(ifp), SK_KVA(ifp));
		return ENXIO;
	}

	if (__improbable((ifp->if_start_flags & IFSF_FLOW_CONTROLLED) != 0)) {
		SK_DF(SK_VERB_SYNC | SK_VERB_TX, "kr 0x%llx ifp %s (0x%llx), "
		    "flow control ON", SK_KVA(kring), if_name(ifp),
		    SK_KVA(ifp));
		return ENXIO;
	}

	/* update our work timestamp */
	KRNA(kring)->na_work_ts = _net_uptime;

	sync_only = ((flags & NA_SYNCF_SYNC_ONLY) != 0) ||
	    !KR_KERNEL_ONLY(kring);
	/* regular sync (reclaim) */
	if ((flags & NA_SYNCF_NETIF) != 0 || __improbable(sync_only)) {
		ret = nx_sync_tx(kring, (flags & NA_SYNCF_FORCE_RECLAIM) ||
		    kring->ckr_pending_intr != 0);
		kring->ckr_pending_intr = 0;

		/* direct user channels do not need to use the doorbell */
		if (__improbable(sync_only)) {
			return ret;
		}
	}

	/*
	 * Doorbell call.  Here we do doorbell explicitly if the flag is
	 * set or implicitly if we're opened directly by a user channel.
	 * Synchronous vs. asynchronous depending on the context.
	 */
	if (__probable((flags & NA_SYNCF_NETIF_DOORBELL) != 0)) {
		if ((flags & NA_SYNCF_NETIF_IFSTART) != 0) {
			ASSERT(!(flags & NA_SYNCF_NETIF_IFSTART) ||
			    !(flags & NA_SYNCF_NETIF_ASYNC));
			nx_tx_doorbell(kring, (flags & NA_SYNCF_NETIF_ASYNC));
		} else {
			ifnet_start(ifp);
		}
	}

	return ret;
}

static int
nx_netif_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	int ret;

	SK_DF(SK_VERB_NETIF | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	ASSERT(kring->ckr_rhead <= kring->ckr_lim);

	/* update our work timestamp */
	KRNA(kring)->na_work_ts = _net_uptime;

	ret = nx_sync_rx(kring, (flags & NA_SYNCF_FORCE_READ) ||
	    kring->ckr_pending_intr != 0);
	kring->ckr_pending_intr = 0;

	return ret;
}

static void
nx_netif_na_dtor(struct nexus_adapter *na)
{
	struct ifnet *ifp;
	struct nexus_netif_adapter *nifna = NIFNA(na);

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_NETIF_DEV || na->na_type == NA_NETIF_HOST);

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

	if (nifna->nifna_netif != NULL) {
		nx_netif_release(nifna->nifna_netif);
		nifna->nifna_netif = NULL;
	}
	ASSERT(SKYWALK_NATIVE(ifp));
}

/*
 * Dispatch rx/tx interrupts to the channel rings.
 *
 * The 'notify' routine depends on what the ring is attached to.
 * - for a channel file descriptor, do an event wakeup on the individual
 *   waitqueue, plus one on the global one if needed (see na_notify)
 * - for a device port connected to a FlowSwitch, call the proper
 *   forwarding routine; see nx_fsw_tx_hwna_notify()
 *   or nx_fsw_rx_hwna_notify().
 */
int
nx_netif_common_intr(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags, uint32_t *work_done)
{
	struct netif_stats *nifs =
	    &NX_NETIF_PRIVATE(KRNA(kring)->na_nx)->nif_stats;
	int (*notify)(struct __kern_channel_ring *kring,
	    struct proc *, uint32_t flags);
	int ret;

	KDBG((SK_KTRACE_NETIF_COMMON_INTR | DBG_FUNC_START), SK_KVA(kring));

	SK_DF(SK_VERB_NETIF | SK_VERB_INTR |
	    ((kring->ckr_tx == NR_RX) ? SK_VERB_RX : SK_VERB_TX),
	    "na \"%s\" (0x%llx) kr \"%s\" (0x%llx) krflags 0x%b",
	    KRNA(kring)->na_name, SK_KVA(KRNA(kring)), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS);

	/* update our work timestamp */
	KRNA(kring)->na_work_ts = _net_uptime;

	kring->ckr_pending_intr++;
	if (work_done != NULL) {
		*work_done = 1; /* do not fire again */
	}
	/*
	 * We can't be calling ckr_na_notify here since we could already be
	 * intercepting it, else we'd end up recursively calling ourselves.
	 * Use the original na_notify callback saved during na_activate, or in
	 * the case when the module above us is the flowswitch, the notify
	 * routine that it has installed in place of our original one.
	 */
	if (__probable(!KR_DROP(kring) &&
	    (notify = kring->ckr_netif_notify) != NULL)) {
		ret = notify(kring, p, flags);
	} else {
		/*
		 * If the ring is in drop mode, pretend as if it's busy.
		 * This allows the mitigation thread to pause for a while
		 * before attempting again.
		 */
		ret = EBUSY;
	}
	if (__improbable(ret != 0)) {
		switch (kring->ckr_tx) {
		case NR_RX:
			if (ret == EBUSY) {
				STATS_INC(nifs, NETIF_STATS_RX_IRQ_BUSY);
			} else if (ret == EAGAIN) {
				STATS_INC(nifs, NETIF_STATS_RX_IRQ_AGAIN);
			} else {
				STATS_INC(nifs, NETIF_STATS_RX_IRQ_ERR);
			}
			break;

		case NR_TX:
			if (ret == EBUSY) {
				STATS_INC(nifs, NETIF_STATS_TX_IRQ_BUSY);
			} else if (ret == EAGAIN) {
				STATS_INC(nifs, NETIF_STATS_TX_IRQ_AGAIN);
			} else {
				STATS_INC(nifs, NETIF_STATS_TX_IRQ_ERR);
			}
			break;

		default:
			break;
		}
	}

	KDBG((SK_KTRACE_NETIF_COMMON_INTR | DBG_FUNC_END), SK_KVA(kring), ret);

	return ret;
}

static int
nx_netif_na_notify_tx(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	return nx_netif_mit_tx_intr(kring, p, flags, NULL);
}

static int
nx_netif_na_notify_rx(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	int ret;

	/*
	 * In the event the mitigation thread is disabled, protect
	 * against recursion by detecting if we're already in the
	 * context of an RX notify.  IOSkywalkFamily may invoke the
	 * notify callback as part of its RX sync callback.
	 */
	if (__probable(!sk_is_rx_notify_protected())) {
		sk_protect_t protect;
		uint32_t work_done;

		protect = sk_rx_notify_protect();
		ret = nx_netif_mit_rx_intr(kring, p, flags, &work_done);
		sk_sync_unprotect(protect);
	} else {
		ret = EAGAIN;
	}

	return ret;
}

static int
nx_netif_na_notify_rx_redirect(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	struct netif_stats *nifs =
	    &NX_NETIF_PRIVATE(KRNA(kring)->na_nx)->nif_stats;
	uint32_t work_done;

	ASSERT(kring->ckr_tx == NR_RX);
	STATS_INC(nifs, NETIF_STATS_RX_IRQ);
	return nx_netif_common_intr(kring, p, flags, &work_done);
}

void
nx_netif_mit_config(struct nexus_netif_adapter *nifna,
    boolean_t *tx_mit, boolean_t *tx_mit_simple,
    boolean_t *rx_mit, boolean_t *rx_mit_simple)
{
	struct nx_netif *nif = nifna->nifna_netif;

	/*
	 * TX mitigation is disabled by default, but can be
	 * overridden via "sk_netif_tx_mit=N" boot-arg, where
	 * N is one of SK_NETIF_MIT_FORCE_* values.
	 */
	*tx_mit = *tx_mit_simple = FALSE;
	switch (sk_netif_tx_mit) {
	case SK_NETIF_MIT_FORCE_SIMPLE:
		*tx_mit_simple = TRUE;
		OS_FALLTHROUGH;
	case SK_NETIF_MIT_FORCE_ADVANCED:
		*tx_mit = TRUE;
		break;
	case SK_NETIF_MIT_FORCE_OFF:
	case SK_NETIF_MIT_AUTO:
		ASSERT(*tx_mit == FALSE);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/*
	 * RX mitigation is enabled by default only for BSD-style
	 * virtual network interfaces, but can be overridden
	 * via "sk_netif_rx_mit=N" boot-arg, where N is one of
	 * SK_NETIF_MIT_FORCE_* values.
	 */
	*rx_mit = *rx_mit_simple = FALSE;
	switch (sk_netif_rx_mit) {
	case SK_NETIF_MIT_FORCE_OFF:
		ASSERT(*rx_mit == FALSE);
		break;
	case SK_NETIF_MIT_FORCE_SIMPLE:
		*rx_mit_simple = TRUE;
		OS_FALLTHROUGH;
	case SK_NETIF_MIT_FORCE_ADVANCED:
		*rx_mit = TRUE;
		break;
	case SK_NETIF_MIT_AUTO:
		*rx_mit_simple = TRUE;
		/*
		 * Enable RX mitigation thread only for BSD-style virtual (and
		 * regular) interfaces, since otherwise we may run out of stack
		 * when subjected to IPsec processing, etc.
		 */
		*rx_mit = (NX_PROV(nifna->nifna_up.na_nx)->nxprov_flags &
		    NXPROVF_VIRTUAL_DEVICE) && !NETIF_IS_LOW_LATENCY(nif);
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static int
nx_netif_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	struct nexus_netif_adapter *nifna = (struct nexus_netif_adapter *)na;
	boolean_t tx_mit, rx_mit, tx_mit_simple, rx_mit_simple;
	struct nx_netif *nif = nifna->nifna_netif;
	struct ifnet *ifp = na->na_ifp;
	int error = 0;
	uint32_t r;

	ASSERT(na->na_type == NA_NETIF_DEV);
	ASSERT(!(na->na_flags & NAF_HOST_ONLY));

	SK_DF(SK_VERB_NETIF, "na \"%s\" (0x%llx) %s [%s]", na->na_name,
	    SK_KVA(na), ifp->if_xname, na_activate_mode2str(mode));

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		ASSERT(SKYWALK_CAPABLE(ifp));

		nx_netif_mit_config(nifna, &tx_mit, &tx_mit_simple,
		    &rx_mit, &rx_mit_simple);

		/*
		 * Init the mitigation support on all the dev TX rings.
		 */
		if (tx_mit) {
			nifna->nifna_tx_mit =
			    skn_alloc_type_array(tx_on, struct nx_netif_mit,
			    na_get_nrings(na, NR_TX), Z_WAITOK,
			    skmem_tag_netif_mit);
			if (nifna->nifna_tx_mit == NULL) {
				SK_ERR("TX mitigation allocation failed");
				error = ENOMEM;
				goto out;
			}
		} else {
			ASSERT(nifna->nifna_tx_mit == NULL);
		}

		/*
		 * Init the mitigation support on all the dev RX rings.
		 */
		if (rx_mit) {
			nifna->nifna_rx_mit =
			    skn_alloc_type_array(rx_on, struct nx_netif_mit,
			    na_get_nrings(na, NR_RX), Z_WAITOK,
			    skmem_tag_netif_mit);
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
		} else {
			ASSERT(nifna->nifna_rx_mit == NULL);
		}

		/* intercept na_notify callback on the TX rings */
		for (r = 0; r < na_get_nrings(na, NR_TX); r++) {
			na->na_tx_rings[r].ckr_netif_notify =
			    na->na_tx_rings[r].ckr_na_notify;
			na->na_tx_rings[r].ckr_na_notify =
			    nx_netif_na_notify_tx;
			if (nifna->nifna_tx_mit != NULL) {
				nx_netif_mit_init(nif, ifp,
				    &nifna->nifna_tx_mit[r],
				    &na->na_tx_rings[r], tx_mit_simple);
			}
		}

		/* intercept na_notify callback on the RX rings */
		for (r = 0; r < na_get_nrings(na, NR_RX); r++) {
			na->na_rx_rings[r].ckr_netif_notify =
			    na->na_rx_rings[r].ckr_na_notify;
			na->na_rx_rings[r].ckr_na_notify = IFNET_IS_REDIRECT(ifp) ?
			    nx_netif_na_notify_rx_redirect : nx_netif_na_notify_rx;
			if (nifna->nifna_rx_mit != NULL) {
				nx_netif_mit_init(nif, ifp,
				    &nifna->nifna_rx_mit[r],
				    &na->na_rx_rings[r], rx_mit_simple);
			}
		}
		nx_netif_filter_enable(nif);
		nx_netif_flow_enable(nif);
		os_atomic_or(&na->na_flags, NAF_ACTIVE, relaxed);

		/* steer all start requests to netif; this must not fail */
		lck_mtx_lock(&ifp->if_start_lock);
		error = ifnet_set_start_handler(ifp, nx_netif_doorbell);
		VERIFY(error == 0);
		lck_mtx_unlock(&ifp->if_start_lock);
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		ASSERT(SKYWALK_CAPABLE(ifp));
		break;

	case NA_ACTIVATE_MODE_OFF:
		/*
		 * Note that here we cannot assert SKYWALK_CAPABLE()
		 * as we're called in the destructor path.
		 */
		os_atomic_andnot(&na->na_flags, NAF_ACTIVE, relaxed);
		nx_netif_flow_disable(nif);
		nx_netif_filter_disable(nif);

		/*
		 * Here we may block while holding sk_lock, but because
		 * we've cleared NAF_ACTIVE above, kern_channel_tx_refill()
		 * should immediately return.  A better approach would be
		 * to drop sk_lock and add a monitor for this routine.
		 */
		lck_mtx_lock(&ifp->if_start_lock);
		while (ifp->if_start_active != 0) {
			++ifp->if_start_waiters;
			(void) msleep(&ifp->if_start_waiters,
			    &ifp->if_start_lock, (PZERO - 1),
			    na->na_name, NULL);
		}
		/* steer all start requests to default handler */
		ifnet_reset_start_handler(ifp);
		lck_mtx_unlock(&ifp->if_start_lock);

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
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
out:
	return error;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_attach(struct kern_nexus *nx, struct ifnet *ifp)
__attribute__((optnone))
{
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_netif_adapter *devnifna = NULL;
	struct nexus_netif_adapter *hostnifna = NULL;
	struct nexus_adapter *devna = NULL;
	struct nexus_adapter *hostna = NULL;
	boolean_t embryonic = FALSE;
	int retval = 0;
	uint32_t na_flags;

	SK_LOCK_ASSERT_HELD();
	ASSERT(SKYWALK_NATIVE(ifp));
	ASSERT(!SKYWALK_CAPABLE(ifp));
	ASSERT(ifp->if_na == NULL);
	ASSERT(ifp->if_na_ops == NULL);

	devnifna = na_netif_alloc(Z_WAITOK);
	hostnifna = na_netif_alloc(Z_WAITOK);

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

	/* initialize the device netif adapter */
	devnifna->nifna_netif = nif;
	nx_netif_retain(nif);
	devna = &devnifna->nifna_up;
	devna->na_type = NA_NETIF_DEV;
	devna->na_free = na_netif_free;
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
	devna->na_activate = nx_netif_na_activate;
	devna->na_txsync = nx_netif_na_txsync;
	devna->na_rxsync = nx_netif_na_rxsync;
	devna->na_dtor = nx_netif_na_dtor;
	devna->na_krings_create = nx_netif_dev_krings_create;
	devna->na_krings_delete = nx_netif_dev_krings_delete;
	devna->na_special = nx_netif_na_special;

	na_flags = NAF_NATIVE;
	if (NX_PROV(nx)->nxprov_flags & NXPROVF_VIRTUAL_DEVICE) {
		na_flags |= NAF_VIRTUAL_DEVICE;
	}
	if (NX_LLINK_PROV(nx)) {
		/*
		 * while operating in logical link mode, we don't need to
		 * create backing memory regions for the rings as they are
		 * not used.
		 */
		na_flags |= NAF_MEM_NO_INIT;
	}
	os_atomic_or(&devna->na_flags, na_flags, relaxed);
	*(nexus_stats_type_t *)(uintptr_t)&devna->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	na_set_nrings(devna, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(devna, NR_RX, nxp->nxp_rx_rings);
	na_set_nslots(devna, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(devna, NR_RX, nxp->nxp_rx_slots);
	/*
	 * Verify upper bounds; the parameters must have already been
	 * validated by nxdom_prov_params() by the time we get here.
	 */
	ASSERT(na_get_nrings(devna, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(devna, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(devna, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(devna, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	na_attach_common(devna, nx, &nx_netif_prov_s);

	if ((retval = NX_DOM_PROV(nx)->nxdom_prov_mem_new(NX_DOM_PROV(nx),
	    nx, devna)) != 0) {
		ASSERT(devna->na_arena == NULL);
		goto err;
	}
	ASSERT(devna->na_arena != NULL);

	*(uint32_t *)(uintptr_t)&devna->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(devna->na_flowadv_max == 0 ||
	    skmem_arena_nexus(devna->na_arena)->arn_flowadv_obj != NULL);

	/* setup packet copy routines */
	if (skmem_arena_nexus(devna->na_arena)->arn_rx_pp->pp_max_frags > 1) {
		nif->nif_pkt_copy_from_mbuf = pkt_copy_multi_buflet_from_mbuf;
		nif->nif_pkt_copy_to_mbuf = pkt_copy_multi_buflet_to_mbuf;
		nif->nif_pkt_copy_from_pkt = pkt_copy_multi_buflet_from_pkt;
	} else {
		nif->nif_pkt_copy_from_mbuf = pkt_copy_from_mbuf;
		nif->nif_pkt_copy_to_mbuf = pkt_copy_to_mbuf;
		nif->nif_pkt_copy_from_pkt = pkt_copy_from_pkt;
	}

	/* initialize the host netif adapter */
	hostnifna->nifna_netif = nif;
	nx_netif_retain(nif);
	hostna = &hostnifna->nifna_up;
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
	hostna->na_type = NA_NETIF_HOST;
	hostna->na_free = na_netif_free;
	hostna->na_activate = nx_netif_host_na_activate;
	hostna->na_txsync = nx_netif_host_na_txsync;
	hostna->na_rxsync = nx_netif_host_na_rxsync;
	hostna->na_dtor = nx_netif_na_dtor;
	hostna->na_krings_create = nx_netif_host_krings_create;
	hostna->na_krings_delete = nx_netif_host_krings_delete;
	hostna->na_special = nx_netif_host_na_special;

	na_flags = NAF_HOST_ONLY | NAF_NATIVE;
	if (NX_LLINK_PROV(nx)) {
		/*
		 * while operating in logical link mode, we don't need to
		 * create backing memory regions for the rings as they are
		 * not used.
		 */
		na_flags |= NAF_MEM_NO_INIT;
	}
	os_atomic_or(&hostna->na_flags, na_flags, relaxed);
	*(nexus_stats_type_t *)(uintptr_t)&hostna->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	na_set_nrings(hostna, NR_TX, 1);
	na_set_nrings(hostna, NR_RX, 1);
	na_set_nslots(hostna, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(hostna, NR_RX, nxp->nxp_rx_slots);

	na_attach_common(hostna, nx, &nx_netif_prov_s);

	if ((retval = NX_DOM_PROV(nx)->nxdom_prov_mem_new(NX_DOM_PROV(nx),
	    nx, hostna)) != 0) {
		ASSERT(hostna->na_arena == NULL);
		goto err;
	}
	ASSERT(hostna->na_arena != NULL);

	*(uint32_t *)(uintptr_t)&hostna->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(hostna->na_flowadv_max == 0 ||
	    skmem_arena_nexus(hostna->na_arena)->arn_flowadv_obj != NULL);

	/* adjust the classq packet drop limit */
	if (embryonic) {
		uint32_t drop_lim;
		struct kern_pbufpool_memory_info pp_info;

		retval = kern_pbufpool_get_memory_info(nx->nx_tx_pp, &pp_info);
		VERIFY(retval == 0);

		/* set the drop limit as 80% of size of packet pool */
		drop_lim = (pp_info.kpm_packets * 4) / 5;
		VERIFY(drop_lim != 0);
		IFCQ_PKT_DROP_LIMIT(ifp->if_snd) = drop_lim;
	}

	/* these will be undone by destructor  */
	ifp->if_na_ops = &na_netif_ops;
	ifp->if_na = devnifna;
	na_retain_locked(devna);
	na_retain_locked(hostna);

	SKYWALK_SET_CAPABLE(ifp);

	NETIF_WLOCK(nif);
	nif->nif_ifp = ifp;
	nif->nif_netif_nxadv = nx->nx_adv.netif_nxv_adv;
	retval = nx_port_alloc(nx, NEXUS_PORT_NET_IF_DEV, NULL, &devna,
	    kernproc);
	ASSERT(retval == 0);
	retval = nx_port_alloc(nx, NEXUS_PORT_NET_IF_HOST, NULL, &hostna,
	    kernproc);
	ASSERT(retval == 0);
	NETIF_WUNLOCK(nif);

#if SK_LOG
	uuid_string_t uuidstr;
	SK_DF(SK_VERB_NETIF, "devna: \"%s\"", devna->na_name);
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
	SK_DF(SK_VERB_NETIF, "  ifp:         0x%llx %s [ioref %u]",
	    SK_KVA(ifp), ifp->if_xname, ifp->if_refio);
#endif /* SK_LOG */

err:
	if (retval != 0) {
		if (ifp != NULL) {
			if (!embryonic) {
				ifnet_decr_iorefcnt(ifp);
			}
			ifp = NULL;
		}
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
		if (devnifna != NULL) {
			if (devnifna->nifna_netif != NULL) {
				nx_netif_release(devnifna->nifna_netif);
				devnifna->nifna_netif = NULL;
			}
			na_netif_free((struct nexus_adapter *)devnifna);
		}
		if (hostnifna != NULL) {
			if (hostnifna->nifna_netif != NULL) {
				nx_netif_release(hostnifna->nifna_netif);
				hostnifna->nifna_netif = NULL;
			}
			na_netif_free((struct nexus_adapter *)hostnifna);
		}
	}
	return retval;
}

/*
 * Any per-netif state that can be discovered at attach time should be
 * initialized here.
 */
static void
nx_netif_flags_init(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;
	struct kern_nexus *nx = nif->nif_nx;
	struct nexus_adapter *devna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);

	switch (devna->na_type) {
	case NA_NETIF_DEV:
		if (strcmp(ifp->if_name, sk_ll_prefix) == 0) {
			nif->nif_flags |= NETIF_FLAG_LOW_LATENCY;
			if_set_xflags(ifp, IFXF_LOW_LATENCY);
		}
		break;
	case NA_NETIF_COMPAT_DEV:
		nif->nif_flags |= NETIF_FLAG_COMPAT;
		break;
	default:
		break;
	}
}

/*
 * This is also supposed to check for any inconsistent state at detach time.
 */
static void
nx_netif_flags_fini(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	if (ifp != NULL) {
		if_clear_xflags(ifp, IFXF_LOW_LATENCY);
	}
	nif->nif_flags = 0;
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_callbacks_init(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	/*
	 * XXX
	 * This function is meant to be called by na_netif_finalize(), which is
	 * called by ifnet_attach() while holding if_lock exclusively.
	 */
	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	if (ifnet_is_low_latency(ifp)) {
		ifnet_set_detach_notify_locked(ifp,
		    nx_netif_llw_detach_notify, ifp->if_na);
	}
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_callbacks_fini(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	if (ifnet_is_low_latency(ifp)) {
		ifnet_set_detach_notify(ifp, NULL, NULL);
	}
}

static void
configure_capab_interface_advisory(struct nx_netif *nif,
    nxprov_capab_config_fn_t capab_fn)
{
	struct kern_nexus_capab_interface_advisory capab;
	struct kern_nexus *nx = nif->nif_nx;
	uint32_t capab_len;
	int error;

	/* check/configure interface advisory notifications */
	if ((nif->nif_ifp->if_eflags & IFEF_ADV_REPORT) == 0) {
		return;
	}
	bzero(&capab, sizeof(capab));
	capab.kncia_version =
	    KERN_NEXUS_CAPAB_INTERFACE_ADVISORY_VERSION_1;
	*__DECONST(kern_nexus_capab_interface_advisory_notify_fn_t *,
	    &(capab.kncia_notify)) = nx_netif_interface_advisory_notify;
	*__DECONST(void **, &(capab.kncia_kern_context)) = nx;
	capab_len = sizeof(capab);
	error = capab_fn(NX_PROV(nx), nx,
	    KERN_NEXUS_CAPAB_INTERFACE_ADVISORY, &capab, &capab_len);
	if (error != 0) {
		DTRACE_SKYWALK2(interface__advisory__capab__error,
		    struct nx_netif *, nif, int, error);
		return;
	}
	VERIFY(capab.kncia_config != NULL);
	VERIFY(capab.kncia_provider_context != NULL);
	nif->nif_intf_adv_config = capab.kncia_config;
	nif->nif_intf_adv_prov_ctx = capab.kncia_provider_context;
	nif->nif_extended_capabilities |= NETIF_CAPAB_INTERFACE_ADVISORY;
}

static void
unconfigure_capab_interface_advisory(struct nx_netif *nif)
{
	if ((nif->nif_extended_capabilities & NETIF_CAPAB_INTERFACE_ADVISORY) == 0) {
		return;
	}
	nif->nif_intf_adv_config = NULL;
	nif->nif_intf_adv_prov_ctx = NULL;
	nif->nif_extended_capabilities &= ~NETIF_CAPAB_INTERFACE_ADVISORY;
}

static void
configure_capab_qset_extensions(struct nx_netif *nif,
    nxprov_capab_config_fn_t capab_fn)
{
	struct kern_nexus_capab_qset_extensions capab;
	struct kern_nexus *nx = nif->nif_nx;
	uint32_t capab_len;
	int error;

	if (!NX_LLINK_PROV(nx)) {
		DTRACE_SKYWALK1(not__llink__prov, struct nx_netif *, nif);
		return;
	}
	bzero(&capab, sizeof(capab));
	capab.cqe_version = KERN_NEXUS_CAPAB_QSET_EXTENSIONS_VERSION_1;
	capab_len = sizeof(capab);
	error = capab_fn(NX_PROV(nx), nx,
	    KERN_NEXUS_CAPAB_QSET_EXTENSIONS, &capab, &capab_len);
	if (error != 0) {
		DTRACE_SKYWALK2(qset__extensions__capab__error,
		    struct nx_netif *, nif, int, error);
		return;
	}
	VERIFY(capab.cqe_notify_steering_info != NULL);
	VERIFY(capab.cqe_prov_ctx != NULL);
	nif->nif_qset_extensions.qe_notify_steering_info =
	    capab.cqe_notify_steering_info;
	nif->nif_qset_extensions.qe_prov_ctx = capab.cqe_prov_ctx;
	nif->nif_extended_capabilities |= NETIF_CAPAB_QSET_EXTENSIONS;
}

static void
unconfigure_capab_qset_extensions(struct nx_netif *nif)
{
	if ((nif->nif_extended_capabilities & NETIF_CAPAB_QSET_EXTENSIONS) == 0) {
		return;
	}
	bzero(&nif->nif_qset_extensions, sizeof(nif->nif_qset_extensions));
	nif->nif_extended_capabilities &= ~NETIF_CAPAB_QSET_EXTENSIONS;
}

int
nx_netif_notify_steering_info(struct nx_netif *nif, struct netif_qset *qset,
    struct ifnet_traffic_descriptor_common *td, bool add)
{
	struct netif_qset_extensions *qset_ext;
	int err;

	if ((nif->nif_extended_capabilities & NETIF_CAPAB_QSET_EXTENSIONS) == 0) {
		return ENOTSUP;
	}
	qset_ext = &nif->nif_qset_extensions;
	VERIFY(qset_ext->qe_prov_ctx != NULL);
	VERIFY(qset_ext->qe_notify_steering_info != NULL);
	err = qset_ext->qe_notify_steering_info(qset_ext->qe_prov_ctx,
	    qset->nqs_ctx, td, add);
	return err;
}

static void
nx_netif_capabilities_init(struct nx_netif *nif)
{
	struct kern_nexus *nx = nif->nif_nx;
	nxprov_capab_config_fn_t capab_fn;

	if ((NX_PROV(nx)->nxprov_netif_ext.nxnpi_version) ==
	    KERN_NEXUS_PROVIDER_VERSION_NETIF) {
		capab_fn = NX_PROV(nx)->nxprov_netif_ext.nxnpi_config_capab;
		ASSERT(capab_fn != NULL);
	} else {
		capab_fn = NX_PROV(nx)->nxprov_ext.nxpi_config_capab;
	}
	if (capab_fn == NULL) {
		return;
	}
	configure_capab_interface_advisory(nif, capab_fn);
	configure_capab_qset_extensions(nif, capab_fn);
}

static void
nx_netif_capabilities_fini(struct nx_netif *nif)
{
	unconfigure_capab_interface_advisory(nif);
	unconfigure_capab_qset_extensions(nif);
}

static void
nx_netif_verify_tso_config(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;
	uint32_t tso_v4_mtu = 0;
	uint32_t tso_v6_mtu = 0;

	if ((ifp->if_hwassist & IFNET_TSO_IPV4) != 0) {
		tso_v4_mtu = ifp->if_tso_v4_mtu;
	}
	if ((ifp->if_hwassist & IFNET_TSO_IPV6) != 0) {
		tso_v6_mtu = ifp->if_tso_v6_mtu;
	}
	VERIFY(PP_BUF_SIZE_DEF(nif->nif_nx->nx_tx_pp) >=
	    max(tso_v4_mtu, tso_v6_mtu));
}

void
na_netif_finalize(struct nexus_netif_adapter *nifna, struct ifnet *ifp)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct kern_nexus *nx = nif->nif_nx;
	struct nexus_adapter *devna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	struct nexus_adapter *hostna = nx_port_get_na(nx,
	    NEXUS_PORT_NET_IF_HOST);

	ASSERT(devna != NULL);
	ASSERT(hostna != NULL);

	if (!ifnet_is_attached(ifp, 1)) {
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	ASSERT(devna->na_private == ifp);
	ASSERT(devna->na_ifp == NULL);
	/* use I/O refcnt held by ifnet_is_attached() above */
	devna->na_ifp = devna->na_private;
	devna->na_private = NULL;

	ASSERT(hostna->na_private == ifp);
	ASSERT(hostna->na_ifp == NULL);
	hostna->na_ifp = hostna->na_private;
	hostna->na_private = NULL;
	ifnet_incr_iorefcnt(hostna->na_ifp);

	nx_netif_flags_init(nif);
	nx_netif_llink_init(nif);
	nx_netif_filter_init(nif);
	nx_netif_flow_init(nif);
	nx_netif_capabilities_init(nif);
	nx_netif_agent_init(nif);
	(void) nxctl_inet_traffic_rule_get_count(ifp->if_xname,
	    &ifp->if_traffic_rule_count);
	nx_netif_verify_tso_config(nif);
	nx_netif_callbacks_init(nif);
}

void
nx_netif_reap(struct nexus_netif_adapter *nifna, struct ifnet *ifp,
    uint32_t thres, boolean_t low)
{
#pragma unused(ifp)
	struct nx_netif *nif = nifna->nifna_netif;
	struct kern_nexus *nx = nif->nif_nx;
	struct nexus_adapter *devna = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
	uint64_t now = _net_uptime;
	boolean_t purge;

	ASSERT(thres != 0);

	if (devna->na_work_ts == 0) {
		return;
	}

	/*
	 * Purge if it's has been inactive for some time (twice the drain
	 * threshold), and clear the work timestamp to temporarily skip this
	 * adapter until it's active again.  Purging cached objects can be
	 * expensive since we'd need to allocate and construct them again,
	 * so we do it only when necessary.
	 */
	if (low || (now - devna->na_work_ts) >= (thres << 1)) {
		devna->na_work_ts = 0;
		purge = TRUE;
	} else {
		purge = FALSE;
	}

	SK_DF(SK_VERB_NETIF, "%s: %s na %s", ifp->if_xname,
	    (purge ? "purging" : "pruning"), devna->na_name);

	/*
	 * Device and host adapters share the same packet buffer pool,
	 * so just reap the arena belonging to the device instance.
	 */
	skmem_arena_reap(devna->na_arena, purge);
}

/*
 * The purpose of this callback is to forceably remove resources held by VPNAs
 * in event of an interface detach. Without this callback an application can
 * prevent the detach from completing indefinitely. Note that this is only needed
 * for low latency VPNAs. Userspace do get notified about interface detach events
 * for other NA types (custom ether and filter) and will do the necessary cleanup.
 * The cleanup is done in two phases:
 * 1) VPNAs channels are defuncted. This releases the resources held by VPNAs and
 *    causes the device channel to be closed. All ifnet references held by VPNAs
 *    are also released.
 * 2) This cleans up the netif nexus and releases the two remaining ifnet
 *    references held by the device and host ports (nx_netif_clean()).
 */
void
nx_netif_llw_detach_notify(void *arg)
{
	struct nexus_netif_adapter *nifna = arg;
	struct nx_netif *nif = nifna->nifna_netif;
	struct kern_nexus *nx = nif->nif_nx;
	struct kern_channel **ch_list = NULL;
	struct kern_channel *ch;
	int err, i, all_ch_cnt = 0, vp_ch_cnt = 0;
	struct proc *p;

	ASSERT(NETIF_IS_LOW_LATENCY(nif));
	/*
	 * kern_channel_defunct() requires sk_lock to be not held. We
	 * will first find the list of channels we want to defunct and
	 * then call kern_channel_defunct() on each of them. The number
	 * of channels cannot increase after sk_lock is released since
	 * this interface is being detached.
	 */
	SK_LOCK();
	all_ch_cnt = nx->nx_ch_count;
	if (all_ch_cnt == 0) {
		DTRACE_SKYWALK1(no__channel, struct kern_nexus *, nx);
		SK_UNLOCK();
		return;
	}
	ch_list = sk_alloc_type_array(struct kern_channel *, all_ch_cnt,
	    Z_WAITOK | Z_NOFAIL, skmem_tag_netif_temp);

	STAILQ_FOREACH(ch, &nx->nx_ch_head, ch_link) {
		struct nexus_adapter *na = ch->ch_na;

		if (na != NULL && na->na_type == NA_NETIF_VP) {
			ASSERT(vp_ch_cnt < all_ch_cnt);

			/* retain channel to prevent it from being freed */
			ch_retain_locked(ch);
			ch_list[vp_ch_cnt] = ch;
			DTRACE_SKYWALK3(vp__ch__found, struct kern_nexus *, nx,
			    struct kern_channel *, ch, struct nexus_adapter *, na);
			vp_ch_cnt++;
		}
	}
	if (vp_ch_cnt == 0) {
		DTRACE_SKYWALK1(vp__ch__not__found, struct kern_nexus *, nx);
		sk_free_type_array(struct kern_channel *, all_ch_cnt, ch_list);
		SK_UNLOCK();
		return;
	}
	/* prevents the netif from being freed */
	nx_netif_retain(nif);
	SK_UNLOCK();

	for (i = 0; i < vp_ch_cnt; i++) {
		ch = ch_list[i];
		p = proc_find(ch->ch_pid);
		if (p == NULL) {
			SK_ERR("ch 0x%llx pid %d not found", SK_KVA(ch), ch->ch_pid);
			DTRACE_SKYWALK3(ch__pid__not__found, struct kern_nexus *, nx,
			    struct kern_channel *, ch, pid_t, ch->ch_pid);
			ch_release(ch);
			continue;
		}
		/*
		 * It is possible for the channel to be closed before defunct gets
		 * called. We need to get the fd lock here to ensure that the check
		 * for the closed state and the calling of channel defunct are done
		 * atomically.
		 */
		proc_fdlock(p);
		if ((ch->ch_flags & CHANF_ATTACHED) != 0) {
			kern_channel_defunct(p, ch);
		}
		proc_fdunlock(p);
		proc_rele(p);
		ch_release(ch);
	}
	sk_free_type_array(struct kern_channel *, all_ch_cnt, ch_list);

	SK_LOCK();
	/*
	 * Quiescing is not needed because:
	 * The defuncting above ensures that no more tx syncs could enter.
	 * The driver layer ensures that ifnet_detach() (this path) does not get
	 * called until RX upcalls have returned.
	 *
	 * Before sk_lock is reacquired above, userspace could close its channels
	 * and cause the nexus's destructor to be called. This is fine because we
	 * have retained the nif so it can't disappear.
	 */
	err = nx_netif_clean(nif, FALSE);
	if (err != 0) {
		SK_ERR("netif clean failed: err %d", err);
		DTRACE_SKYWALK2(nif__clean__failed, struct nx_netif *, nif, int, err);
	}
	nx_netif_release(nif);
	SK_UNLOCK();
}

void
nx_netif_copy_stats(struct nexus_netif_adapter *nifna,
    struct if_netif_stats *if_ns)
{
	struct nx_netif_mit *mit;
	struct mit_cfg_tbl *mit_cfg;

	if ((mit = nifna->nifna_rx_mit) == NULL) {
		return;
	}

	if ((mit->mit_flags & NETIF_MITF_INITIALIZED) == 0) {
		return;
	}

	if_ns->ifn_rx_mit_interval = mit->mit_interval;
	if_ns->ifn_rx_mit_mode = mit->mit_mode;
	if_ns->ifn_rx_mit_packets_avg = mit->mit_packets_avg;
	if_ns->ifn_rx_mit_packets_min = mit->mit_packets_min;
	if_ns->ifn_rx_mit_packets_max = mit->mit_packets_max;
	if_ns->ifn_rx_mit_bytes_avg = mit->mit_bytes_avg;
	if_ns->ifn_rx_mit_bytes_min = mit->mit_bytes_min;
	if_ns->ifn_rx_mit_bytes_max = mit->mit_bytes_max;
	if_ns->ifn_rx_mit_cfg_idx = mit->mit_cfg_idx;

	VERIFY(if_ns->ifn_rx_mit_cfg_idx < mit->mit_cfg_idx_max);
	mit_cfg = &mit->mit_tbl[if_ns->ifn_rx_mit_cfg_idx];
	if_ns->ifn_rx_mit_cfg_packets_lowat = mit_cfg->cfg_plowat;
	if_ns->ifn_rx_mit_cfg_packets_hiwat = mit_cfg->cfg_phiwat;
	if_ns->ifn_rx_mit_cfg_bytes_lowat = mit_cfg->cfg_blowat;
	if_ns->ifn_rx_mit_cfg_bytes_hiwat = mit_cfg->cfg_bhiwat;
	if_ns->ifn_rx_mit_cfg_interval = mit_cfg->cfg_ival;
}

int
nx_netif_na_special(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *chr, nxspec_cmd_t spec_cmd)
{
	ASSERT(na->na_type == NA_NETIF_DEV ||
	    na->na_type == NA_NETIF_COMPAT_DEV);
	return nx_netif_na_special_common(na, ch, chr, spec_cmd);
}

int
nx_netif_na_special_common(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *chr, nxspec_cmd_t spec_cmd)
{
	int error = 0;

	ASSERT(na->na_type == NA_NETIF_DEV || na->na_type == NA_NETIF_HOST ||
	    na->na_type == NA_NETIF_COMPAT_DEV ||
	    na->na_type == NA_NETIF_COMPAT_HOST);
	SK_LOCK_ASSERT_HELD();

	switch (spec_cmd) {
	case NXSPEC_CMD_CONNECT:
		/*
		 * netif adapter isn't created exclusively for kernel.
		 * We mark (and clear) NAF_KERNEL_ONLY flag upon a succesful
		 * na_special() connect and disconnect.
		 */
		if (NA_KERNEL_ONLY(na)) {
			error = EBUSY;
			goto done;
		}
		ASSERT(!(na->na_flags & NAF_SPEC_INIT));

		os_atomic_or(&na->na_flags, NAF_KERNEL_ONLY, relaxed);
		error = na_bind_channel(na, ch, chr);
		if (error != 0) {
			os_atomic_andnot(&na->na_flags, NAF_KERNEL_ONLY, relaxed);
			goto done;
		}
		os_atomic_or(&na->na_flags, NAF_SPEC_INIT, relaxed);
		break;

	case NXSPEC_CMD_DISCONNECT:
		ASSERT(NA_KERNEL_ONLY(na));
		ASSERT(na->na_channels > 0);
		ASSERT(na->na_flags & NAF_SPEC_INIT);
		na_unbind_channel(ch);
		os_atomic_andnot(&na->na_flags, (NAF_SPEC_INIT | NAF_KERNEL_ONLY), relaxed);
		break;

	case NXSPEC_CMD_START:
		na_kr_drop(na, FALSE);
		break;

	case NXSPEC_CMD_STOP:
		na_kr_drop(na, TRUE);
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
		lck_mtx_lock(&ch->ch_lock);
		nxprov_advise_disconnect(na->na_nx, ch);
		lck_mtx_unlock(&ch->ch_lock);
		break;

	default:
		error = EINVAL;
		break;
	}

done:
	SK_DF(error ? SK_VERB_ERROR : SK_VERB_NETIF,
	    "ch 0x%llx from na \"%s\" (0x%llx) naflags %b nx 0x%llx "
	    "spec_cmd %u (err %d)", SK_KVA(ch), na->na_name, SK_KVA(na),
	    na->na_flags, NAF_BITS, SK_KVA(ch->ch_nexus), spec_cmd, error);

	return error;
}

/*
 * Get a skywalk netif adapter for the port.
 */
int
nx_netif_na_find(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_adapter **nap, boolean_t create)
{
#pragma unused(ch)
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	boolean_t anon = NX_ANONYMOUS_PROV(nx);
	ch_endpoint_t ep = chr->cr_endpoint;
	nexus_port_t nx_port = chr->cr_port;
	struct nexus_adapter *na = NULL;
	struct ifnet *ifp;
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	*nap = NULL; /* default */

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("name \"%s\" spec_uuid \"%s\" port %d mode 0x%b pipe_id %u "
	    "ring_id %d ring_set %u ep_type %u:%u create %u%s",
	    chr->cr_name, sk_uuid_unparse(chr->cr_spec_uuid, uuidstr),
	    (int)chr->cr_port, chr->cr_mode, CHMODE_BITS,
	    chr->cr_pipe_id, (int)chr->cr_ring_id, chr->cr_ring_set,
	    chr->cr_real_endpoint, chr->cr_endpoint, create,
	    (ep != CH_ENDPOINT_NET_IF) ? " (skipped)" : "");
#endif /* SK_LOG */

	if (!create || ep != CH_ENDPOINT_NET_IF) {
		err = ENODEV;
		goto done;
	}

	ASSERT(NX_DOM(nx)->nxdom_type == NEXUS_TYPE_NET_IF);
	if (nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV) == NULL) {
		err = ENXIO;
		goto done;
	}
	ifp = nif->nif_ifp;
	if (!(SKYWALK_CAPABLE(ifp))) {
		SK_ERR("interface %s is no longer usable", if_name(ifp));
		err = ENOTSUP;
		goto done;
	}

	if (chr->cr_mode & CHMODE_LOW_LATENCY) {
		SK_ERR("low latency is not supported for netif channel");
		err = ENOTSUP;
		goto done;
	}

	switch (nx_port) {
	case NEXUS_PORT_NET_IF_DEV:
		/*
		 * We have to reject direct user open that's not explicitly
		 * allowed because netif nexuses do not by default have
		 * user memory regions.
		 */
		if (p != kernproc &&
		    (!skywalk_netif_direct_allowed(ifp->if_xname) ||
		    (kauth_cred_issuser(kauth_cred_get()) == 0 &&
		    (anon || nif->nif_dev_nxb == NULL || nxb == NULL ||
		    !nxb_is_equal(nif->nif_dev_nxb, nxb))))) {
			DTRACE_SKYWALK2(direct__not__allowed, struct ifnet *,
			    ifp, struct chreq *, chr);
			err = ENOTSUP;
			goto done;
		}
		if (chr->cr_mode & CHMODE_EVENT_RING) {
			SK_ERR("event ring is not supported for netif dev port channel");
			err = ENOTSUP;
			goto done;
		}
		na = nx_port_get_na(nx, NEXUS_PORT_NET_IF_DEV);
		break;

	case NEXUS_PORT_NET_IF_HOST:
		if (p != kernproc) {
			err = ENOTSUP;
			goto done;
		}
		if (chr->cr_mode & CHMODE_EVENT_RING) {
			SK_ERR("event ring is not supported for netif host port channel");
			err = ENOTSUP;
			goto done;
		}
		na = nx_port_get_na(nx, NEXUS_PORT_NET_IF_HOST);
		break;

	default:
		ASSERT(!(chr->cr_mode & CHMODE_CONFIG));

		NETIF_WLOCK(nif);
		err = nx_port_alloc(nx, nx_port, nxb, &na, p);
		if (err != 0) {
			NETIF_WUNLOCK(nif);
			goto done;
		}

		if (na == NULL) {
			if (chr->cr_mode & CHMODE_FILTER) {
				err = netif_filter_na_create(nx, chr, &na);
			} else {
				err = netif_vp_na_create(nx, chr, &na);
			}
			if (err != 0) {
				NETIF_WUNLOCK(nif);
				goto done;
			}
			err = nx_port_alloc(nx, nx_port, nxb, &na, p);
			if (err != 0) {
				NETIF_WUNLOCK(nif);
				goto done;
			}
		}
		NETIF_WUNLOCK(nif);

		break;
	}

	ASSERT(err == 0);
	ASSERT(na != NULL);

#if CONFIG_NEXUS_USER_PIPE
	if (NA_OWNED_BY_ANY(na) || na->na_next_pipe > 0) {
#else /* !CONFIG_NEXUS_USER_PIPE */
	if (NA_OWNED_BY_ANY(na)) {
#endif /* !CONFIG_NEXUS_USER_PIPE */
		err = EBUSY;
		na = NULL;
		goto done;
	}

	*nap = na;
	na_retain_locked(na);

done:
	ASSERT(err != 0 || na != NULL);
	if (err) {
		SK_ERR("na not found, err(%d)", err);
	} else {
		SK_DF(SK_VERB_NETIF, "found na 0x%llu", na);
	}
	return err;
}

/* na_krings_create callback for all netif device adapters */
int
nx_netif_dev_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	int ret;

	ASSERT(na->na_type == NA_NETIF_DEV ||
	    na->na_type == NA_NETIF_COMPAT_DEV);
	/*
	 * Allocate context structures for native netif only, for
	 * IOSkywalkFamily to store its object references.
	 */
	ret = na_rings_mem_setup(na, (na->na_flags & NAF_NATIVE), ch);

	/*
	 * We mark CKRF_DROP for kernel-only rings (kernel channel
	 * opened by the flowswitch, etc.) to prevent packets from
	 * going thru until after the client of the kernel channel
	 * has fully plumbed things on its side.  For userland-facing
	 * rings (regular channel opened to netif), this is not
	 * required, and so don't mark CKRF_DROP there.
	 */
	if (ret == 0 && NA_KERNEL_ONLY(na)) {
		na_kr_drop(na, TRUE);
	}

	return ret;
}

/* call with SK_LOCK held */
void
nx_netif_dev_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_NETIF_DEV ||
	    na->na_type == NA_NETIF_COMPAT_DEV);

	/* see comments in nx_netif_dev_krings_create() */
	if (NA_KERNEL_ONLY(na)) {
		na_kr_drop(na, TRUE);
	}

	na_rings_mem_teardown(na, ch, defunct);
}

struct nx_netif *
nx_netif_alloc(zalloc_flags_t how)
{
	struct nx_netif *n;

	SK_LOCK_ASSERT_HELD();

	n = zalloc_flags(nx_netif_zone, how | Z_ZERO);
	if (n == NULL) {
		return NULL;
	}

	NETIF_RWINIT(n);
	os_ref_init(&n->nif_refcnt, NULL);
	SK_DF(SK_VERB_MEM, "netif 0x%llx", SK_KVA(n));

	return n;
}

static void
nx_netif_destroy(struct nx_netif *n)
{
	ASSERT(n->nif_dev_nxb == NULL);
	ASSERT(n->nif_host_nxb == NULL);
	ASSERT(os_ref_get_count(&n->nif_refcnt) == 0);
	nx_netif_llink_config_free(n);
	SK_DF(SK_VERB_MEM, "netif 0x%llx", SK_KVA(n));
	NETIF_RWDESTROY(n);
	zfree(nx_netif_zone, n);
}

void
nx_netif_release(struct nx_netif *n)
{
	SK_LOCK_ASSERT_HELD();

	SK_DF(SK_VERB_MEM, "netif 0x%llx, refcnt %d", SK_KVA(n),
	    os_ref_get_count(&n->nif_refcnt));
	if (os_ref_release(&n->nif_refcnt) == 0) {
		nx_netif_destroy(n);
	}
}

void
nx_netif_retain(struct nx_netif *n)
{
	SK_LOCK_ASSERT_HELD();

	/* retaining an object with a zero refcount is not allowed */
	ASSERT(os_ref_get_count(&n->nif_refcnt) >= 1);
	os_ref_retain(&n->nif_refcnt);
	SK_DF(SK_VERB_MEM, "netif 0x%llx, refcnt %d", SK_KVA(n),
	    os_ref_get_count(&n->nif_refcnt));
}

void
nx_netif_free(struct nx_netif *n)
{
	nx_netif_release(n);
}

static int
nx_netif_interface_advisory_report(struct kern_nexus *nx,
    const struct ifnet_interface_advisory *advisory)
{
	struct kern_nexus *notify_nx;
	struct __kern_netif_intf_advisory *intf_adv;
	struct nx_netif *nif = NX_NETIF_PRIVATE(nx);
	ifnet_t difp = nif->nif_ifp, parent = NULL;

	/* If we are a delegate, notify the parent instead */
	if (ifnet_get_delegate_parent(difp, &parent) == 0) {
		nif = parent->if_na->nifna_netif;
	}
	if (nif->nif_fsw_nxadv != NULL) {
		ASSERT(nif->nif_fsw != NULL);
		intf_adv = &nif->nif_fsw_nxadv->_nxadv_intf_adv;
		notify_nx = nif->nif_fsw->fsw_nx;
	} else {
		intf_adv = &nif->nif_netif_nxadv->__kern_intf_adv;
		notify_nx = nif->nif_nx;
	}
	/*
	 * copy the advisory report in shared memory
	 */
	intf_adv->cksum = os_cpu_copy_in_cksum(advisory, &intf_adv->adv,
	    sizeof(*advisory), 0);
	STATS_INC(&nif->nif_stats, NETIF_STATS_IF_ADV_UPD_RECV);
	/*
	 * notify user channels on advisory report availability
	 */
	nx_interface_advisory_notify(notify_nx);
	if (parent != NULL) {
		ifnet_release_delegate_parent(difp);
	}
	return 0;
}

static errno_t
nx_netif_interface_advisory_notify(void *kern_ctx,
    const struct ifnet_interface_advisory *advisory)
{
	_CASSERT(offsetof(struct ifnet_interface_advisory, version) ==
	    offsetof(struct ifnet_interface_advisory, header.version));
	_CASSERT(offsetof(struct ifnet_interface_advisory, direction) ==
	    offsetof(struct ifnet_interface_advisory, header.direction));
	_CASSERT(offsetof(struct ifnet_interface_advisory, _reserved) ==
	    offsetof(struct ifnet_interface_advisory, header.interface_type));

	if (__improbable(kern_ctx == NULL || advisory == NULL)) {
		return EINVAL;
	}
	if (__improbable((advisory->header.version <
	    IF_INTERFACE_ADVISORY_VERSION_MIN) ||
	    (advisory->header.version > IF_INTERFACE_ADVISORY_VERSION_MAX))) {
		SK_ERR("Invalid advisory version %d", advisory->header.version);
		return EINVAL;
	}
	if (__improbable((advisory->header.direction !=
	    IF_INTERFACE_ADVISORY_DIRECTION_TX) &&
	    (advisory->header.direction !=
	    IF_INTERFACE_ADVISORY_DIRECTION_RX))) {
		SK_ERR("Invalid advisory direction %d",
		    advisory->header.direction);
		return EINVAL;
	}
	if (__improbable(((advisory->header.interface_type <
	    IF_INTERFACE_ADVISORY_INTERFACE_TYPE_MIN) ||
	    (advisory->header.interface_type >
	    IF_INTERFACE_ADVISORY_INTERFACE_TYPE_MAX)) &&
	    (advisory->header.version >= IF_INTERFACE_ADVISORY_VERSION_2))) {
		SK_ERR("Invalid advisory interface type %d",
		    advisory->header.interface_type);
		return EINVAL;
	}
	return nx_netif_interface_advisory_report(kern_ctx, advisory);
}

void
nx_netif_config_interface_advisory(struct kern_nexus *nx, bool enable)
{
	struct kern_nexus *nx_netif;
	struct nx_netif *nif;

	if (NX_REJECT_ACT(nx) || (nx->nx_flags & NXF_CLOSED) != 0) {
		return;
	}
	if (NX_PROV(nx)->nxprov_params->nxp_type == NEXUS_TYPE_FLOW_SWITCH) {
		struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
		nx_netif = fsw->fsw_nifna->na_nx;
	} else {
		nx_netif = nx;
	}
	ASSERT(NX_PROV(nx_netif)->nxprov_params->nxp_type == NEXUS_TYPE_NET_IF);
	nif = NX_NETIF_PRIVATE(nx_netif);
	if (nif->nif_intf_adv_config != NULL) {
		nif->nif_intf_adv_config(nif->nif_intf_adv_prov_ctx, enable);
	}
}

/*
 * This function has no use anymore since we are now passing truncated packets
 * to filters. We keep this logic just in case we need to prevent certain
 * packets from being passed to filters.
 */
static boolean_t
packet_is_filterable(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt)
{
#pragma unused (nifna, pkt)
	return TRUE;
}

/*
 * This function is only meant for supporting the RX path because the TX path
 * will not send packets > MTU size due to the disabling of TSO when filters
 * are enabled.
 */
static void
get_filterable_packets(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, struct __kern_packet **fpkt_chain,
    struct __kern_packet **passthrough_chain)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct __kern_packet *pkt = pkt_chain, *next, *fpkt;
	struct __kern_packet *fpkt_head = NULL, *passthrough_head = NULL;
	struct __kern_packet **fpkt_tailp = &fpkt_head;
	struct __kern_packet **passthrough_tailp = &passthrough_head;
	int fcnt = 0, pcnt = 0, dcnt = 0;

	while (pkt != NULL) {
		next = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;

		if (!packet_is_filterable(nifna, pkt)) {
			pcnt++;
			*passthrough_tailp = pkt;
			passthrough_tailp = &pkt->pkt_nextpkt;
			pkt = next;
			continue;
		}
		fpkt = nx_netif_pkt_to_filter_pkt(nifna, pkt, NETIF_CONVERT_RX);
		if (fpkt != NULL) {
			fcnt++;
			*fpkt_tailp = fpkt;
			fpkt_tailp = &fpkt->pkt_nextpkt;
		} else {
			dcnt++;
		}
		pkt = next;
	}
	*fpkt_chain = fpkt_head;
	*passthrough_chain = passthrough_head;

	/*
	 * No need to increment drop stats because that's already
	 * done in nx_netif_pkt_to_filter_pkt.
	 */
	STATS_ADD(nifs, NETIF_STATS_FILTER_RX_NOT_FILTERABLE, pcnt);
	DTRACE_SKYWALK6(filterable, struct nexus_netif_adapter *, nifna,
	    int, fcnt, int, pcnt, int, dcnt, struct __kern_packet *,
	    fpkt_head, struct __kern_packet *, passthrough_head);
}

/*
 * This is only used by ring-based notify functions for now.
 * When a qset-based notify becomes available, this function can be used
 * unmodified.
 */
void
netif_receive(struct nexus_netif_adapter *nifna,
    struct __kern_packet *pkt_chain, struct nexus_pkt_stats *stats)
{
	struct nx_netif *nif = nifna->nifna_netif;
	struct nexus_adapter *na = &nifna->nifna_up;
	struct netif_stats *nifs = &nif->nif_stats;
	int err, dropcnt, dropstat = -1;

	/* update our work timestamp */
	na->na_work_ts = _net_uptime;

	if (nif->nif_filter_cnt > 0) {
		struct __kern_packet *fpkt_chain = NULL;
		struct __kern_packet *passthrough_chain = NULL;

		get_filterable_packets(nifna, pkt_chain, &fpkt_chain,
		    &passthrough_chain);
		if (fpkt_chain != NULL) {
			(void) nx_netif_filter_inject(nifna, NULL, fpkt_chain,
			    NETIF_FILTER_RX | NETIF_FILTER_SOURCE);
		}
		if (passthrough_chain != NULL) {
			pkt_chain = passthrough_chain;
		} else {
			return;
		}
	} else if (nx_netif_filter_default_drop != 0) {
		DTRACE_SKYWALK2(rx__default__drop, struct nx_netif *, nif,
		    struct __kern_packet *, pkt_chain);
		dropstat = NETIF_STATS_FILTER_DROP_DEFAULT;
		goto drop;
	}
	if (nif->nif_flow_cnt > 0) {
		struct __kern_packet *remain = NULL;

		err = nx_netif_demux(nifna, pkt_chain, &remain,
		    NETIF_FLOW_SOURCE);
		if (remain == NULL) {
			return;
		}
		pkt_chain = remain;
	}
	if (na->na_rx != NULL) {
		na->na_rx(na, pkt_chain, stats);
	} else {
		DTRACE_SKYWALK2(no__rx__cb, struct nx_netif *, nif,
		    struct __kern_packet *, pkt_chain);
		dropstat = NETIF_STATS_DROP_NO_RX_CB;
		goto drop;
	}
	return;
drop:
	dropcnt = 0;
	nx_netif_free_packet_chain(pkt_chain, &dropcnt);
	if (dropstat != -1) {
		STATS_ADD(nifs, dropstat, dropcnt);
	}
	STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
}

static slot_idx_t
netif_rate_limit(struct __kern_channel_ring *r, uint64_t rate,
    slot_idx_t begin, slot_idx_t end, boolean_t *rate_limited)
{
	uint64_t elapsed;
	uint64_t now;
	struct __kern_packet *pkt;
	clock_sec_t sec;
	clock_usec_t usec;
	slot_idx_t i;

	if (__probable(rate == 0)) {
		return end;
	}

	/* init tbr if not so */
	if (__improbable(r->ckr_tbr_token == CKR_TBR_TOKEN_INVALID)) {
		r->ckr_tbr_token = rate;
		r->ckr_tbr_depth = rate;
		r->ckr_tbr_last = mach_absolute_time();
	} else {
		now = mach_absolute_time();
		elapsed = now - r->ckr_tbr_last;
		absolutetime_to_microtime(elapsed, &sec, &usec);
		r->ckr_tbr_token +=
		    ((sec * USEC_PER_SEC + usec) * rate / USEC_PER_SEC);
		if (__improbable(r->ckr_tbr_token > r->ckr_tbr_depth)) {
			r->ckr_tbr_token = r->ckr_tbr_depth;
		}
		r->ckr_tbr_last = now;
	}

	*rate_limited = FALSE;
	for (i = begin; i != end; i = SLOT_NEXT(i, r->ckr_lim)) {
		pkt = KR_KSD(r, i)->sd_pkt;
		if (__improbable(pkt == NULL)) {
			continue;
		}
		if (__improbable(r->ckr_tbr_token <= 0)) {
			end = i;
			*rate_limited = TRUE;
			break;
		}
		r->ckr_tbr_token -= pkt->pkt_length * 8;
	}

	SK_DF(SK_VERB_FSW | SK_VERB_RX, "ckr %p %s rate limited at %d",
	    r, r->ckr_name, i);

	return end;
}

SK_NO_INLINE_ATTRIBUTE
static struct __kern_packet *
consume_pkts(struct __kern_channel_ring *ring, slot_idx_t end)
{
	struct __kern_packet *pkt_chain = NULL, **tailp = &pkt_chain;
	slot_idx_t idx = ring->ckr_rhead;

	while (idx != end) {
		struct __kern_slot_desc *ksd = KR_KSD(ring, idx);
		struct __kern_packet *pkt = ksd->sd_pkt;

		ASSERT(pkt->pkt_nextpkt == NULL);
		KR_SLOT_DETACH_METADATA(ring, ksd);
		*tailp = pkt;
		tailp = &pkt->pkt_nextpkt;
		idx = SLOT_NEXT(idx, ring->ckr_lim);
	}
	ring->ckr_rhead = end;
	ring->ckr_rtail = ring->ckr_ktail;
	return pkt_chain;
}

int
netif_rx_notify_default(struct __kern_channel_ring *ring, struct proc *p,
    uint32_t flags)
{
	struct nexus_adapter *hwna;
	struct nexus_netif_adapter *nifna;
	struct nx_netif *nif;
	struct __kern_packet *pkt_chain;
	struct nexus_pkt_stats stats;
	sk_protect_t protect;
	slot_idx_t ktail;
	int err = 0;

	KDBG((SK_KTRACE_NETIF_RX_NOTIFY_DEFAULT | DBG_FUNC_START),
	    SK_KVA(ring));

	ASSERT(ring->ckr_tx == NR_RX);
	ASSERT(!NA_KERNEL_ONLY(KRNA(ring)) || KR_KERNEL_ONLY(ring));

	err = kr_enter(ring, ((flags & NA_NOTEF_CAN_SLEEP) != 0));
	if (err != 0) {
		/* not a serious error, so no need to be chatty here */
		SK_DF(SK_VERB_FSW,
		    "hwna \"%s\" (0x%llx) kr \"%s\" (0x%llx) krflags 0x%b "
		    "(%d)", KRNA(ring)->na_name, SK_KVA(KRNA(ring)),
		    ring->ckr_name, SK_KVA(ring), ring->ckr_flags,
		    CKRF_BITS, err);
		goto out;
	}
	if (__improbable(KR_DROP(ring))) {
		kr_exit(ring);
		err = ENODEV;
		goto out;
	}
	hwna = KRNA(ring);
	nifna = NIFNA(hwna);
	nif = nifna->nifna_netif;
	if (__improbable(hwna->na_ifp == NULL)) {
		kr_exit(ring);
		err = ENODEV;
		goto out;
	}
	protect = sk_sync_protect();
	err = ring->ckr_na_sync(ring, p, 0);
	if (err != 0 && err != EAGAIN) {
		goto put_out;
	}

	/* read the tail pointer once */
	ktail = ring->ckr_ktail;
	if (__improbable(ring->ckr_khead == ktail)) {
		SK_DF(SK_VERB_FSW | SK_VERB_NOTIFY | SK_VERB_RX,
		    "how strange, interrupt with no packets on hwna "
		    "\"%s\" (0x%llx)", KRNA(ring)->na_name, SK_KVA(KRNA(ring)));
		goto put_out;
	}
	ktail = netif_rate_limit(ring, nif->nif_input_rate, ring->ckr_rhead,
	    ktail, &ring->ckr_rate_limited);

	pkt_chain = consume_pkts(ring, ktail);
	if (pkt_chain != NULL) {
		netif_receive(nifna, pkt_chain, &stats);

		if (ring->ckr_netif_mit_stats != NULL &&
		    stats.nps_pkts != 0 && stats.nps_bytes != 0) {
			ring->ckr_netif_mit_stats(ring, stats.nps_pkts,
			    stats.nps_bytes);
		}
	}

put_out:
	sk_sync_unprotect(protect);
	kr_exit(ring);

out:
	KDBG((SK_KTRACE_NETIF_RX_NOTIFY_DEFAULT | DBG_FUNC_END),
	    SK_KVA(ring), err);
	return err;
}

int
netif_rx_notify_fast(struct __kern_channel_ring *ring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	sk_protect_t protect;
	struct nexus_adapter *hwna;
	struct nexus_pkt_stats stats = {};
	uint32_t i, count;
	int err = 0;

	KDBG((SK_KTRACE_NETIF_RX_NOTIFY_FAST | DBG_FUNC_START),
	    SK_KVA(ring));

	/* XXX
	 * sk_sync_protect() is not needed for this case because
	 * we are not using the dev ring. Unfortunately lots of
	 * macros used by fsw still require this.
	 */
	protect = sk_sync_protect();
	hwna = KRNA(ring);
	count = na_get_nslots(hwna, NR_RX);
	err = nx_rx_sync_packets(ring, ring->ckr_scratch, &count);
	if (__improbable(err != 0)) {
		SK_ERR("nx_rx_sync_packets failed: %d", err);
		DTRACE_SKYWALK2(rx__sync__packets__failed,
		    struct __kern_channel_ring *, ring, int, err);
		goto out;
	}
	DTRACE_SKYWALK1(chain__count, uint32_t, count);
	for (i = 0; i < count; i++) {
		struct __kern_packet *pkt_chain;

		pkt_chain = SK_PTR_ADDR_KPKT(ring->ckr_scratch[i]);
		ASSERT(pkt_chain != NULL);
		netif_receive(NIFNA(KRNA(ring)), pkt_chain, &stats);

		if (ring->ckr_netif_mit_stats != NULL &&
		    stats.nps_pkts != 0 && stats.nps_bytes != 0) {
			ring->ckr_netif_mit_stats(ring, stats.nps_pkts,
			    stats.nps_bytes);
		}
	}
out:
	sk_sync_unprotect(protect);
	KDBG((SK_KTRACE_NETIF_RX_NOTIFY_FAST | DBG_FUNC_END),
	    SK_KVA(ring), err);
	return err;
}


/*
 * Configure the NA to operate in a particular mode.
 */
static channel_ring_notify_t
netif_hwna_get_notify(struct __kern_channel_ring *ring, netif_mode_t mode)
{
	channel_ring_notify_t notify = NULL;
	boolean_t has_sync_pkts = (sk_rx_sync_packets != 0 &&
	    nx_has_rx_sync_packets(ring));

	if (mode == NETIF_MODE_FSW) {
		notify = (has_sync_pkts ? netif_rx_notify_fast :
		    netif_rx_notify_default);
	} else if (mode == NETIF_MODE_LLW) {
		notify = (has_sync_pkts ? netif_llw_rx_notify_fast :
		    netif_llw_rx_notify_default);
	}
	return notify;
}


static uint32_t
netif_mode_to_flag(netif_mode_t mode)
{
	uint32_t flag = 0;

	if (mode == NETIF_MODE_FSW) {
		flag = NAF_MODE_FSW;
	} else if (mode == NETIF_MODE_LLW) {
		flag = NAF_MODE_LLW;
	}
	return flag;
}

static void
netif_hwna_config_mode(struct nexus_adapter *hwna, netif_mode_t mode,
    void (*rx)(struct nexus_adapter *, struct __kern_packet *,
    struct nexus_pkt_stats *), boolean_t set)
{
	uint32_t i;
	uint32_t flag;

	ASSERT(hwna->na_type == NA_NETIF_DEV ||
	    hwna->na_type == NA_NETIF_COMPAT_DEV);

	for (i = 0; i < na_get_nrings(hwna, NR_RX); i++) {
		struct __kern_channel_ring *kr = &NAKR(hwna, NR_RX)[i];
		channel_ring_notify_t notify = netif_hwna_get_notify(kr, mode);

		if (set) {
			kr->ckr_save_notify = kr->ckr_netif_notify;
			kr->ckr_netif_notify = notify;
		} else {
			kr->ckr_netif_notify = kr->ckr_save_notify;
			kr->ckr_save_notify = NULL;
		}
	}
	if (set) {
		hwna->na_rx = rx;
		flag = netif_mode_to_flag(mode);
		os_atomic_or(&hwna->na_flags, flag, relaxed);
	} else {
		hwna->na_rx = NULL;
		os_atomic_andnot(&hwna->na_flags, (NAF_MODE_FSW | NAF_MODE_LLW), relaxed);
	}
}

void
netif_hwna_set_mode(struct nexus_adapter *hwna, netif_mode_t mode,
    void (*rx)(struct nexus_adapter *, struct __kern_packet *,
    struct nexus_pkt_stats *))
{
	return netif_hwna_config_mode(hwna, mode, rx, TRUE);
}

void
netif_hwna_clear_mode(struct nexus_adapter *hwna)
{
	return netif_hwna_config_mode(hwna, NETIF_MODE_NONE, NULL, FALSE);
}

static void
netif_inject_rx(struct nexus_adapter *na, struct __kern_packet *pkt_chain)
{
	struct nexus_netif_adapter *nifna = NIFNA(na);
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct __kern_channel_ring *r;
	struct nexus_pkt_stats stats;
	sk_protect_t protect;
	boolean_t ring_drop = FALSE;
	int err, dropcnt;

	if (!NA_OWNED_BY_FSW(na)) {
		DTRACE_SKYWALK1(fsw__disabled, struct nexus_adapter *, na);
		goto fail;
	}
	ASSERT(na->na_rx != NULL);

	/*
	 * XXX
	 * This function is called when a filter injects a packet back to the
	 * regular RX path. We can assume the ring is 0 for now because RSS
	 * is not supported. This needs to be revisited when we add support for
	 * RSS.
	 */
	r = &na->na_rx_rings[0];
	ASSERT(r->ckr_tx == NR_RX);
	err = kr_enter(r, TRUE);
	VERIFY(err == 0);

	if (__improbable(KR_DROP(r))) {
		kr_exit(r);
		DTRACE_SKYWALK2(ring__drop, struct nexus_adapter *, na,
		    struct __kern_channel_ring *, r);
		ring_drop = TRUE;
		goto fail;
	}
	protect = sk_sync_protect();
	na->na_rx(na, pkt_chain, &stats);

	if (r->ckr_netif_mit_stats != NULL &&
	    stats.nps_pkts != 0 && stats.nps_bytes != 0) {
		r->ckr_netif_mit_stats(r, stats.nps_pkts, stats.nps_bytes);
	}
	sk_sync_unprotect(protect);

	kr_exit(r);
	return;

fail:
	dropcnt = 0;
	nx_netif_free_packet_chain(pkt_chain, &dropcnt);
	if (ring_drop) {
		STATS_ADD(nifs, NETIF_STATS_DROP_KRDROP_MODE, dropcnt);
	}
	STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
}

/*
 * This is called when an inbound packet has traversed all filters.
 */
errno_t
nx_netif_filter_rx_cb(struct nexus_netif_adapter *nifna,
    struct __kern_packet *fpkt_chain, uint32_t flags)
{
#pragma unused (flags)
	struct nx_netif *nif = nifna->nifna_netif;
	struct netif_stats *nifs = &nif->nif_stats;
	struct nexus_adapter *na = &nifna->nifna_up;
	struct __kern_packet *pkt_chain;
	int err;

	pkt_chain = nx_netif_filter_pkt_to_pkt_chain(nifna,
	    fpkt_chain, NETIF_CONVERT_RX);
	if (pkt_chain == NULL) {
		return ENOMEM;
	}
	if (nif->nif_flow_cnt > 0) {
		struct __kern_packet *remain = NULL;

		err = nx_netif_demux(nifna, pkt_chain, &remain,
		    NETIF_FLOW_INJECT);
		if (remain == NULL) {
			return err;
		}
		pkt_chain = remain;
	}
	if (na->na_rx != NULL) {
		netif_inject_rx(na, pkt_chain);
	} else {
		int dropcnt = 0;
		nx_netif_free_packet_chain(pkt_chain, &dropcnt);
		STATS_ADD(nifs,
		    NETIF_STATS_FILTER_DROP_NO_RX_CB, dropcnt);
		STATS_ADD(nifs, NETIF_STATS_DROP, dropcnt);
	}
	return 0;
}

/*
 * This is called when an outbound packet has traversed all filters.
 */
errno_t
nx_netif_filter_tx_cb(struct nexus_netif_adapter *nifna,
    struct __kern_packet *fpkt_chain, uint32_t flags)
{
#pragma unused (flags)
	struct nx_netif *nif = nifna->nifna_netif;
	struct nexus_adapter *na = &nifna->nifna_up;
	int err;

	if (NETIF_IS_COMPAT(nif)) {
		struct mbuf *m_chain;
		mbuf_svc_class_t sc;

		m_chain = nx_netif_filter_pkt_to_mbuf_chain(nifna,
		    fpkt_chain, NETIF_CONVERT_TX);
		if (m_chain == NULL) {
			return ENOMEM;
		}
		/*
		 * All packets in the chain have the same service class.
		 * If the sc is missing or invalid, a valid value will be
		 * returned.
		 */
		sc = mbuf_get_service_class(m_chain);
		err = nx_netif_filter_tx_processed_mbuf_enqueue(nifna,
		    sc, m_chain);
	} else {
		struct __kern_packet *pkt_chain;
		kern_packet_svc_class_t sc;

		pkt_chain = nx_netif_filter_pkt_to_pkt_chain(nifna,
		    fpkt_chain, NETIF_CONVERT_TX);
		if (pkt_chain == NULL) {
			return ENOMEM;
		}
		/*
		 * All packets in the chain have the same service class.
		 * If the sc is missing or invalid, a valid value will be
		 * returned.
		 */
		sc = kern_packet_get_service_class(SK_PKT2PH(pkt_chain));
		err = nx_netif_filter_tx_processed_pkt_enqueue(nifna,
		    sc, pkt_chain);
	}
	/* Tell driver to resume dequeuing */
	ifnet_start(na->na_ifp);
	return err;
}

void
nx_netif_vp_region_params_adjust(struct nexus_adapter *na,
    struct skmem_region_params *srp)
{
#pragma unused(na, srp)
	return;
}

/* returns true, if starter thread is utilized */
static bool
netif_use_starter_thread(struct ifnet *ifp, uint32_t flags)
{
#if (DEVELOPMENT || DEBUG)
	if (__improbable(nx_netif_force_ifnet_start != 0)) {
		ifnet_start(ifp);
		return true;
	}
#endif /* !DEVELOPMENT && !DEBUG */
	/*
	 * use starter thread in following conditions:
	 * - interface is not skywalk native
	 * - interface attached to virtual driver (ipsec, utun)
	 * - TBR is enabled
	 * - delayed start mechanism is in use
	 * - remaining stack space on the thread is not enough for driver
	 * - caller is in rx workloop context
	 * - caller is from the flowswitch path doing ARP resolving
	 * - caller requires the use of starter thread (stack usage)
	 * - caller requires starter thread for pacing
	 */
	if (!SKYWALK_NATIVE(ifp) || NA(ifp) == NULL ||
	    !NA_IS_ACTIVE(&NA(ifp)->nifna_up) ||
	    ((NA(ifp)->nifna_up.na_flags & NAF_VIRTUAL_DEVICE) != 0) ||
	    IFCQ_TBR_IS_ENABLED(ifp->if_snd) ||
	    (ifp->if_eflags & IFEF_ENQUEUE_MULTI) ||
	    (flags & NETIF_XMIT_FLAG_PACING) != 0 ||
	    sk_is_rx_notify_protected() ||
	    sk_is_async_transmit_protected() ||
	    (sk_is_sync_protected() && (flags & NETIF_XMIT_FLAG_HOST) != 0)) {
		DTRACE_SKYWALK2(use__starter__thread, struct ifnet *, ifp,
		    uint32_t, flags);
		ifnet_start(ifp);
		return true;
	}
	lck_mtx_lock_spin(&ifp->if_start_lock);
	/* interface is flow controlled */
	if (__improbable(ifp->if_start_flags & IFSF_FLOW_CONTROLLED)) {
		lck_mtx_unlock(&ifp->if_start_lock);
		return true;
	}
	/* if starter thread is active, utilize it */
	if (ifp->if_start_active) {
		ifp->if_start_req++;
		lck_mtx_unlock(&ifp->if_start_lock);
		return true;
	}
	lck_mtx_unlock(&ifp->if_start_lock);
	/* Check remaining stack space */
	if ((OSKernelStackRemaining() < NX_NETIF_MIN_DRIVER_STACK_SIZE)) {
		ifnet_start(ifp);
		return true;
	}
	return false;
}

void
netif_transmit(struct ifnet *ifp, uint32_t flags)
{
	if (netif_use_starter_thread(ifp, flags)) {
		return;
	}
	/*
	 * If no longer attached, don't issue doorbell as ifp
	 * is being destroyed; else hold an IO refcnt to
	 * prevent the interface from being detached.
	 */
	if (!ifnet_datamov_begin(ifp)) {
		return;
	}
	nx_netif_doorbell_internal(ifp, flags);
	/*
	 * Release the IO refcnt taken above.
	 */
	ifnet_datamov_end(ifp);
}

static struct ifclassq *
netif_get_default_ifcq(struct nexus_adapter *hwna)
{
	struct nx_netif *nif;
	struct ifclassq *ifcq;

	nif = NX_NETIF_PRIVATE(hwna->na_nx);
	if (NETIF_LLINK_ENABLED(nif)) {
		struct netif_qset *qset;

		/*
		 * Use the default ifcq for now.
		 * In the future this could be chosen by the caller.
		 */
		qset = nx_netif_get_default_qset_noref(nif);
		ASSERT(qset != NULL);
		ifcq = qset->nqs_ifcq;
	} else {
		ifcq = nif->nif_ifp->if_snd;
	}
	return ifcq;
}

static errno_t
netif_deq_packets(struct nexus_adapter *hwna, struct ifclassq *ifcq,
    uint32_t pkt_limit, uint32_t byte_limit, struct __kern_packet **head,
    boolean_t *pkts_pending, kern_packet_svc_class_t sc,
    uint32_t *pkt_cnt, uint32_t *bytes, uint8_t qset_idx)
{
	classq_pkt_t pkt_head = CLASSQ_PKT_INITIALIZER(pkt_head);
	struct ifnet *ifp = hwna->na_ifp;
	uint32_t pkts_cnt;
	uint32_t bytes_cnt;
	errno_t rc;

	ASSERT(ifp != NULL);
	ASSERT(ifp->if_output_sched_model < IFNET_SCHED_MODEL_MAX);
	ASSERT((pkt_limit != 0) && (byte_limit != 0));

	if (ifcq == NULL) {
		ifcq = netif_get_default_ifcq(hwna);
	}
	if (ifp->if_output_sched_model == IFNET_SCHED_MODEL_DRIVER_MANAGED) {
		rc = ifclassq_dequeue_sc(ifcq, (mbuf_svc_class_t)sc,
		    pkt_limit, byte_limit, &pkt_head, NULL, pkt_cnt, bytes, qset_idx);
	} else {
		rc = ifclassq_dequeue(ifcq, pkt_limit, byte_limit,
		    &pkt_head, NULL, pkt_cnt, bytes, qset_idx);
	}
	ASSERT((rc == 0) || (rc == EAGAIN));
	ASSERT((pkt_head.cp_ptype == QP_PACKET) || (pkt_head.cp_kpkt == NULL));

	ifclassq_get_len(ifcq, (mbuf_svc_class_t)sc, qset_idx,
	    &pkts_cnt, &bytes_cnt);
	*pkts_pending = pkts_cnt > 0;

	*head = pkt_head.cp_kpkt;
	return rc;
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
netif_no_ring_space_log(const struct nexus_adapter *na,
    const kern_channel_ring_t ring)
{
	SK_DF(SK_VERB_SYNC | SK_VERB_TX,
	    "no ring space: na \"%s\" [%u] "
	    "\"%s\"(kh %u kt %u kl %u | rh %u rt %u)"
	    "\"%s\"(kh %u kt %u kl %u | rh %u rt %u)",
	    na->na_name, ring->ckr_ring_id,
	    ring->ckr_name, ring->ckr_khead,
	    ring->ckr_ktail, ring->ckr_klease,
	    ring->ckr_rhead, ring->ckr_rtail);
}
#endif /* SK_LOG */

/*
 * netif refill function for rings
 */
errno_t
netif_ring_tx_refill(const kern_channel_ring_t ring, uint32_t pkt_limit,
    uint32_t byte_limit, boolean_t tx_doorbell_ctxt, boolean_t *pkts_pending,
    boolean_t canblock)
{
	struct nexus_adapter *hwna;
	struct ifnet *ifp;
	struct __kern_packet *head = NULL;
	sk_protect_t protect;
	errno_t rc = 0;
	errno_t sync_err = 0;
	uint32_t npkts = 0, consumed = 0;
	uint32_t flags;
	slot_idx_t idx, ktail;
	int ring_space = 0;

	KDBG((SK_KTRACE_NETIF_RING_TX_REFILL | DBG_FUNC_START), SK_KVA(ring));

	VERIFY(ring != NULL);
	hwna = KRNA(ring);
	ifp = hwna->na_ifp;

	ASSERT(hwna->na_type == NA_NETIF_DEV);
	ASSERT(ring->ckr_tx == NR_TX);
	*pkts_pending = FALSE;

	if (__improbable(pkt_limit == 0 || byte_limit == 0)) {
		SK_ERR("invalid limits plim %d, blim %d",
		    pkt_limit, byte_limit);
		rc = EINVAL;
		goto out;
	}

	if (__improbable(!IF_FULLY_ATTACHED(ifp))) {
		SK_ERR("hwna 0x%llx ifp %s (0x%llx), interface not attached",
		    SK_KVA(hwna), if_name(ifp), SK_KVA(ifp));
		rc = ENXIO;
		goto out;
	}

	if (__improbable((ifp->if_start_flags & IFSF_FLOW_CONTROLLED) != 0)) {
		SK_DF(SK_VERB_SYNC | SK_VERB_TX, "hwna 0x%llx ifp %s (0x%llx), "
		    "flow control ON", SK_KVA(hwna), if_name(ifp), SK_KVA(ifp));
		rc = ENXIO;
		goto out;
	}

	/*
	 * if the ring is busy, it means another dequeue is in
	 * progress, so ignore this request and return success.
	 */
	if (kr_enter(ring, canblock) != 0) {
		rc = 0;
		goto out;
	}
	/* mark thread with sync-in-progress flag */
	protect = sk_sync_protect();

	if (__improbable(KR_DROP(ring) ||
	    !NA_IS_ACTIVE(ring->ckr_na))) {
		SK_ERR("hw-kr 0x%llx stopped", SK_KVA(ring));
		rc = ENXIO;
		goto done;
	}

	idx = ring->ckr_rhead;
	ktail = ring->ckr_ktail;
	/* calculate available space on tx ring */
	ring_space = ktail - idx;
	if (ring_space < 0) {
		ring_space += ring->ckr_num_slots;
	}
	if (ring_space == 0) {
		struct ifclassq *ifcq;

		/* no space in ring, driver should retry */
#if SK_LOG
		if (__improbable((sk_verbose &
		    (SK_VERB_SYNC | SK_VERB_TX)) != 0)) {
			netif_no_ring_space_log(hwna, ring);
		}
#endif /* SK_LOG */
		ifcq = netif_get_default_ifcq(hwna);
		if (IFCQ_LEN(ifcq) != 0) {
			*pkts_pending = TRUE;
		}
		/*
		 * We ran out of space in ring, most probably
		 * because the driver is slow to drain its TX queue.
		 * We want another doorbell to be generated as soon
		 * as the TX notify completion happens; mark this
		 * through ckr_pending_doorbell counter.  Do this
		 * regardless of whether there's any pending packet.
		 */
		ring->ckr_pending_doorbell++;
		rc = EAGAIN;
		goto sync_ring;
	}

	if ((uint32_t)ring_space < pkt_limit) {
		pkt_limit = ring_space;
	}

	if (tx_doorbell_ctxt &&
	    ((hwna->na_flags & NAF_VIRTUAL_DEVICE) == 0)) {
		pkt_limit = MIN(pkt_limit,
		    nx_netif_doorbell_max_dequeue);
	}

	rc = netif_deq_packets(hwna, NULL, pkt_limit, byte_limit,
	    &head, pkts_pending, ring->ckr_svc, NULL, NULL, 0);

	/*
	 * There's room in ring; if we haven't dequeued everything,
	 * mark ckr_pending_doorbell for the next TX notify to issue
	 * a TX door bell; otherwise, clear it.  The next packet that
	 * gets enqueued will trigger a door bell again.
	 */
	if (*pkts_pending) {
		ring->ckr_pending_doorbell++;
	} else if (ring->ckr_pending_doorbell != 0) {
		ring->ckr_pending_doorbell = 0;
	}

	if (rc != 0) {
		/*
		 * This is expected sometimes as the IOSkywalkFamily
		 * errs on the side of caution to perform an extra
		 * dequeue when multiple doorbells are pending;
		 * nothing to dequeue, do a sync if there are slots
		 * to reclaim else just return.
		 */
		SK_DF(SK_VERB_SYNC | SK_VERB_TX,
		    "nothing to dequeue, err %d", rc);

		if ((uint32_t)ring_space == ring->ckr_lim) {
			goto done;
		} else {
			goto sync_ring;
		}
	}
	/* move the dequeued packets to tx ring */
	while (head != NULL && idx != ktail) {
		ASSERT(npkts <= pkt_limit);
		struct __kern_packet *pkt = head;
		KR_SLOT_ATTACH_METADATA(ring, KR_KSD(ring, idx),
		    (struct __kern_quantum *)pkt);
		npkts++;
		if (__improbable(pkt->pkt_trace_id != 0)) {
			KDBG(SK_KTRACE_PKT_TX_AQM | DBG_FUNC_END, pkt->pkt_trace_id);
			KDBG(SK_KTRACE_PKT_TX_DRV | DBG_FUNC_START, pkt->pkt_trace_id);
		}
		idx = SLOT_NEXT(idx, ring->ckr_lim);
		head = pkt->pkt_nextpkt;
		pkt->pkt_nextpkt = NULL;
	}

	/*
	 * We checked for ring space earlier so the ring should have enough
	 * space for the entire chain.
	 */
	ASSERT(head == NULL);
	ring->ckr_rhead = idx;

sync_ring:
	flags = NA_SYNCF_NETIF;
	if (ring->ckr_pending_doorbell != 0) {
		flags |= (NA_SYNCF_NETIF_DOORBELL | NA_SYNCF_NETIF_ASYNC);
	}

	ring->ckr_khead_pre = ring->ckr_khead;
	sync_err = ring->ckr_na_sync(ring, kernproc, flags);
	if (sync_err != 0 && sync_err != EAGAIN) {
		SK_ERR("unexpected sync err %d", sync_err);
		if (rc == 0) {
			rc = sync_err;
		}
		goto done;
	}
	/*
	 * Verify that the driver has detached packets from the consumed slots.
	 */
	idx = ring->ckr_khead_pre;
	consumed = 0;
	while (idx != ring->ckr_khead) {
		struct __kern_slot_desc *ksd = KR_KSD(ring, idx);

		consumed++;
		VERIFY(!KSD_VALID_METADATA(ksd));
		idx = SLOT_NEXT(idx, ring->ckr_lim);
	}
	ring->ckr_khead_pre = ring->ckr_khead;

done:
	sk_sync_unprotect(protect);
	kr_exit(ring);
out:
	KDBG((SK_KTRACE_NETIF_RING_TX_REFILL | DBG_FUNC_END),
	    SK_KVA(ring), rc, 0, npkts);

	return rc;
}

#define NQ_EWMA(old, new, decay) do {                               \
	u_int64_t _avg;                                                 \
	if (__probable((_avg = (old)) > 0))                             \
	        _avg = (((_avg << (decay)) - _avg) + (new)) >> (decay); \
	else                                                            \
	        _avg = (new);                                           \
	(old) = _avg;                                                   \
} while (0)

static void
kern_netif_increment_queue_stats(kern_netif_queue_t queue,
    uint32_t pkt_count, uint32_t byte_count)
{
	struct netif_llink *llink = queue->nq_qset->nqs_llink;
	struct ifnet *ifp = llink->nll_nif->nif_ifp;
	if ((queue->nq_flags & NETIF_QUEUE_IS_RX) == 0) {
		os_atomic_add(&ifp->if_data.ifi_opackets, pkt_count, relaxed);
		os_atomic_add(&ifp->if_data.ifi_obytes, byte_count, relaxed);
	} else {
		os_atomic_add(&ifp->if_data.ifi_ipackets, pkt_count, relaxed);
		os_atomic_add(&ifp->if_data.ifi_ibytes, byte_count, relaxed);
	}

	if (ifp->if_data_threshold != 0) {
		ifnet_notify_data_threshold(ifp);
	}

	uint64_t now;
	uint64_t diff_secs;
	struct netif_qstats *stats = &queue->nq_stats;

	if (nq_stat_enable == 0) {
		return;
	}

	if (__improbable(pkt_count == 0)) {
		return;
	}

	stats->nq_num_xfers++;
	stats->nq_total_bytes += byte_count;
	stats->nq_total_pkts += pkt_count;
	if (pkt_count > stats->nq_max_pkts) {
		stats->nq_max_pkts = pkt_count;
	}
	if (stats->nq_min_pkts == 0 ||
	    pkt_count < stats->nq_min_pkts) {
		stats->nq_min_pkts = pkt_count;
	}

	now = net_uptime();
	if (__probable(queue->nq_accumulate_start != 0)) {
		diff_secs = now - queue->nq_accumulate_start;
		if (diff_secs >= nq_accumulate_interval) {
			uint64_t        bps;
			uint64_t        pps;
			uint64_t        pps_ma;

			/* bytes per second */
			bps = queue->nq_accumulated_bytes / diff_secs;
			NQ_EWMA(stats->nq_bytes_ps_ma,
			    bps, nq_transfer_decay);
			stats->nq_bytes_ps = bps;

			/* pkts per second */
			pps = queue->nq_accumulated_pkts / diff_secs;
			pps_ma = stats->nq_pkts_ps_ma;
			NQ_EWMA(pps_ma, pps, nq_transfer_decay);
			stats->nq_pkts_ps_ma = (uint32_t)pps_ma;
			stats->nq_pkts_ps = (uint32_t)pps;

			/* start over */
			queue->nq_accumulate_start = now;
			queue->nq_accumulated_bytes = 0;
			queue->nq_accumulated_pkts = 0;

			stats->nq_min_pkts = 0;
			stats->nq_max_pkts = 0;
		}
	} else {
		queue->nq_accumulate_start = now;
	}
	queue->nq_accumulated_bytes += byte_count;
	queue->nq_accumulated_pkts += pkt_count;
}

void
kern_netif_queue_rx_enqueue(kern_netif_queue_t queue, kern_packet_t ph_chain,
    uint32_t count, uint32_t flags)
{
#pragma unused (count)
	struct netif_queue *q = queue;
	struct netif_llink *llink = q->nq_qset->nqs_llink;
	struct __kern_packet *pkt_chain = SK_PTR_ADDR_KPKT(ph_chain);
	bool flush = ((flags & KERN_NETIF_QUEUE_RX_ENQUEUE_FLAG_FLUSH) != 0);
	struct pktq *pktq = &q->nq_pktq;
	struct netif_stats *nifs = &llink->nll_nif->nif_stats;
	struct nexus_pkt_stats stats;
	sk_protect_t protect;

	ASSERT((q->nq_flags & NETIF_QUEUE_IS_RX) != 0);
	if (llink->nll_state == NETIF_LLINK_STATE_DESTROYED) {
		int drop_cnt = 0;

		pp_free_packet_chain(pkt_chain, &drop_cnt);
		STATS_ADD(nifs, NETIF_STATS_LLINK_RX_DROP_BAD_STATE, drop_cnt);
		return;
	}
	KPKTQ_ENQUEUE_LIST(pktq, pkt_chain);
	if (flush) {
		pkt_chain = KPKTQ_FIRST(pktq);
		KPKTQ_INIT(pktq);

		protect = sk_sync_protect();
		netif_receive(NA(llink->nll_nif->nif_ifp), pkt_chain, &stats);
		sk_sync_unprotect(protect);
		kern_netif_increment_queue_stats(queue, (uint32_t)stats.nps_pkts,
		    (uint32_t)stats.nps_bytes);
	}
}

errno_t
kern_netif_queue_tx_dequeue(kern_netif_queue_t queue, uint32_t pkt_limit,
    uint32_t byte_limit, boolean_t *pending, kern_packet_t *ph_chain)
{
	struct netif_queue *q = queue;
	struct netif_llink *llink = q->nq_qset->nqs_llink;
	struct netif_stats *nifs = &llink->nll_nif->nif_stats;
	struct nexus_adapter *hwna;
	struct __kern_packet *pkt_chain = NULL;
	uint32_t bytes = 0, pkt_cnt = 0;
	errno_t rc;

	ASSERT((q->nq_flags & NETIF_QUEUE_IS_RX) == 0);
	if (llink->nll_state == NETIF_LLINK_STATE_DESTROYED) {
		STATS_INC(nifs, NETIF_STATS_LLINK_AQM_DEQ_BAD_STATE);
		return ENXIO;
	}
	hwna = &NA(llink->nll_nif->nif_ifp)->nifna_up;

	if (((hwna->na_flags & NAF_VIRTUAL_DEVICE) == 0) &&
	    sk_is_tx_notify_protected()) {
		pkt_limit = MIN(pkt_limit, nx_netif_doorbell_max_dequeue);
	}
	rc = netif_deq_packets(hwna, q->nq_qset->nqs_ifcq, pkt_limit,
	    byte_limit, &pkt_chain, pending, q->nq_svc, &pkt_cnt, &bytes,
	    q->nq_qset->nqs_idx);

	if (pkt_cnt > 0) {
		kern_netif_increment_queue_stats(queue, pkt_cnt, bytes);
	}
	if (pkt_chain != NULL) {
		*ph_chain = SK_PKT2PH(pkt_chain);
	}
	return rc;
}

errno_t
kern_netif_qset_tx_queue_len(kern_netif_qset_t qset, uint32_t svc,
    uint32_t * pkts_cnt, uint32_t * bytes_cnt)
{
	VERIFY(qset != NULL);
	VERIFY(pkts_cnt != NULL);
	VERIFY(bytes_cnt != NULL);

	return ifclassq_get_len(qset->nqs_ifcq, svc, qset->nqs_idx, pkts_cnt,
	           bytes_cnt);
}

void
kern_netif_set_qset_combined(kern_netif_qset_t qset)
{
	VERIFY(qset != NULL);
	VERIFY(qset->nqs_ifcq != NULL);

	ifclassq_set_grp_combined(qset->nqs_ifcq, qset->nqs_idx);
}

void
kern_netif_set_qset_separate(kern_netif_qset_t qset)
{
	VERIFY(qset != NULL);
	VERIFY(qset->nqs_ifcq != NULL);

	ifclassq_set_grp_separated(qset->nqs_ifcq, qset->nqs_idx);
}

errno_t
kern_nexus_netif_llink_add(struct kern_nexus *nx,
    struct kern_nexus_netif_llink_init *llink_init)
{
	errno_t err;
	struct nx_netif *nif;
	struct netif_llink *llink;
	struct netif_stats *nifs;

	VERIFY(nx != NULL);
	VERIFY(llink_init != NULL);
	VERIFY((nx->nx_flags & NXF_ATTACHED) != 0);

	nif = NX_NETIF_PRIVATE(nx);
	nifs = &nif->nif_stats;

	err = nx_netif_validate_llink_config(llink_init, false);
	if (err != 0) {
		SK_ERR("Invalid llink init params");
		STATS_INC(nifs, NETIF_STATS_LLINK_ADD_BAD_PARAMS);
		return err;
	}

	err = nx_netif_llink_add(nif, llink_init, &llink);
	return err;
}

errno_t
kern_nexus_netif_llink_remove(struct kern_nexus *nx,
    kern_nexus_netif_llink_id_t llink_id)
{
	struct nx_netif *nif;

	VERIFY(nx != NULL);
	VERIFY((nx->nx_flags & NXF_ATTACHED) != 0);

	nif = NX_NETIF_PRIVATE(nx);
	return nx_netif_llink_remove(nif, llink_id);
}

errno_t
kern_netif_queue_get_service_class(kern_netif_queue_t queue,
    kern_packet_svc_class_t *svc)
{
	*svc = queue->nq_svc;
	return 0;
}
