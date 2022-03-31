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
#if SKYWALK

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/kern_event.h>
#include <sys/mcache.h>
#include <sys/syslog.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_vlan_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_types.h>
#include <libkern/OSAtomic.h>

#include <net/dlil.h>

#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <net/if_media.h>
#include <net/ether_if_module.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/channel/channel_var.h>

static boolean_t
is_power_of_two(unsigned int val)
{
	return (val & (val - 1)) == 0;
}

#define HEADLESS_ZERO_IFNAME         "zero"
#define HEADLESS_NULL_IFNAME         "null"

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, headless, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "headless interface");

static int if_headless_nxattach = 0;
SYSCTL_INT(_net_link_headless, OID_AUTO, nxattach,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_headless_nxattach, 0,
    "headless interface auto-attach nexus");

static int if_headless_debug = 0;
SYSCTL_INT(_net_link_headless, OID_AUTO, debug,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_headless_debug, 0,
    "headless interface debug logs");

static int if_headless_multibuflet = 0;
SYSCTL_INT(_net_link_headless, OID_AUTO, multibuflet,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_headless_multibuflet, 0,
    "headless interface using multi-buflet packets");

static int if_headless_packet_length = 1500;
SYSCTL_INT(_net_link_headless, OID_AUTO, packet_length,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_headless_packet_length, 0,
    "headless interface packet length");

static int if_headless_create_payload = 0;
SYSCTL_INT(_net_link_headless, OID_AUTO, create_payload,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_headless_create_payload, 0,
    "headless interface create payload data or not");

/*
 * SIOCSDRVSPEC
 */
enum {
	IF_HEADLESS_S_CMD_NONE              = 0,
	IF_HEADLESS_S_CMD_SET_MEDIA         = 1,
};

#define IF_HEADLESS_MEDIA_LIST_MAX  27

struct if_headless_media {
	int32_t         iffm_current;
	uint32_t        iffm_count;
	uint32_t        iffm_reserved[3];
	int32_t         iffm_list[IF_HEADLESS_MEDIA_LIST_MAX];
};

struct if_headless_request {
	uint64_t        iffr_reserved[4];
	union {
		char    iffru_buf[128];         /* stable size */
		struct if_headless_media    iffru_media;
	} iffr_u;
#define iffr_media      iffr_u.iffru_media
};

/* sysctl net.link.headless.tx_headroom */
#define headless_TX_HEADROOM_MAX      32
static uint16_t if_headless_tx_headroom = 0;

extern void if_headless_init(void);

static int
headless_tx_headroom_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint16_t new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_headless_tx_headroom,
	    sizeof(if_headless_tx_headroom), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > headless_TX_HEADROOM_MAX ||
		    (new_value % 8) != 0) {
			return EINVAL;
		}
		if_headless_tx_headroom = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_headless, OID_AUTO, tx_headroom,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, headless_tx_headroom_sysctl, "IU", "headless ethernet Tx headroom");

/* sysctl net.link.headless.max_mtu */
#define headless_MAX_MTU_DEFAULT    2048
#define headless_MAX_MTU_MAX        ((16 * 1024) - ETHER_HDR_LEN)

static unsigned int if_headless_max_mtu = headless_MAX_MTU_DEFAULT;

/* sysctl net.link.headless.buflet_size */
#define headless_BUFLET_SIZE_MIN            512
#define headless_BUFLET_SIZE_MAX            2048

static unsigned int if_headless_buflet_size = headless_BUFLET_SIZE_MIN;

static int
headless_max_mtu_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_headless_max_mtu,
	    sizeof(if_headless_max_mtu), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > headless_MAX_MTU_MAX ||
		    new_value < ETHERMTU ||
		    new_value <= if_headless_buflet_size) {
			return EINVAL;
		}
		if_headless_max_mtu = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_headless, OID_AUTO, max_mtu,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, headless_max_mtu_sysctl, "IU", "headless interface maximum MTU");

static int
headless_buflet_size_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_headless_buflet_size,
	    sizeof(if_headless_buflet_size), &new_value, &changed);
	if (error == 0 && changed != 0) {
		/* must be a power of 2 between min and max */
		if (new_value > headless_BUFLET_SIZE_MAX ||
		    new_value < headless_BUFLET_SIZE_MIN ||
		    !is_power_of_two(new_value) ||
		    new_value >= if_headless_max_mtu) {
			return EINVAL;
		}
		if_headless_buflet_size = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_headless, OID_AUTO, buflet_size,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, headless_buflet_size_sysctl, "IU", "headless interface buflet size");

/**
** virtual ethernet structures, types
**/

#define IFF_NUM_TX_RINGS_WMM_MODE       4
#define IFF_NUM_RX_RINGS_WMM_MODE       1
#define IFF_MAX_TX_RINGS        IFF_NUM_TX_RINGS_WMM_MODE
#define IFF_MAX_RX_RINGS        IFF_NUM_RX_RINGS_WMM_MODE

typedef uint16_t        iff_flags_t;
#define IFF_FLAGS_HWCSUM                0x0001
#define IFF_FLAGS_BSD_MODE              0x0002
#define IFF_FLAGS_DETACHING             0x0004
#define IFF_FLAGS_WMM_MODE              0x0008
#define IFF_FLAGS_MULTIBUFLETS          0x0010
#define IFF_FLAGS_COPYPKT_MODE          0x0020

typedef struct {
	kern_pbufpool_t         fpp_pp;
	uint32_t                fpp_retain_count;
} headless_packet_pool, *headless_packet_pool_t;

typedef struct {
	uuid_t                  fnx_provider;
	uuid_t                  fnx_instance;
} headless_nx, *headless_nx_t;

struct if_headless {
	struct if_clone *       iff_cloner;
	char                    iff_name[IFNAMSIZ]; /* our unique id */
	ifnet_t                 iff_ifp;
	iff_flags_t             iff_flags;
	uint32_t                iff_retain_count;
	ifnet_t                 iff_peer;       /* the other end */
	int                     iff_media_current;
	int                     iff_media_active;
	uint32_t                iff_media_count;
	int                     iff_media_list[IF_HEADLESS_MEDIA_LIST_MAX];
	struct mbuf *           iff_pending_tx_packet;
	boolean_t               iff_start_busy;
	unsigned int            iff_max_mtu;
	headless_nx                 iff_nx;
	kern_channel_ring_t     iff_rx_ring[IFF_MAX_RX_RINGS];
	kern_channel_ring_t     iff_tx_ring[IFF_MAX_TX_RINGS];
	thread_call_t           iff_doorbell_tcall;
	boolean_t               iff_tcall_active;
	boolean_t               iff_waiting_for_tcall;
	boolean_t               iff_channel_connected;
	headless_packet_pool_t      iff_fpp;
	uint16_t                iff_tx_headroom;
};

typedef struct if_headless * if_headless_ref;

static if_headless_ref
ifnet_get_if_headless(ifnet_t ifp);

#define HEADLESS_DPRINTF(fmt, ...)                                  \
	{ if (if_headless_debug != 0) printf("%s " fmt, __func__, ## __VA_ARGS__); }

static inline void
headless_set_detaching(if_headless_ref headlessif)
{
	headlessif->iff_flags |= IFF_FLAGS_DETACHING;
}

static inline boolean_t
headless_is_detaching(if_headless_ref headlessif)
{
	return (headlessif->iff_flags & IFF_FLAGS_DETACHING) != 0;
}

static inline boolean_t
headless_using_multibuflets(if_headless_ref headlessif)
{
	return (headlessif->iff_flags & IFF_FLAGS_MULTIBUFLETS) != 0;
}

#define HEADLESS_MAXUNIT    IF_MAXUNIT
#define HEADLESS_ZONE_MAX_ELEM      MIN(IFNETS_MAX, HEADLESS_MAXUNIT)

static  int headless_clone_create(struct if_clone *, u_int32_t, void *);
static  int headless_clone_destroy(ifnet_t);
static  int headless_ioctl(ifnet_t ifp, u_long cmd, void * addr);
static  void headless_if_free(ifnet_t ifp);
static  void headless_ifnet_set_attrs(if_headless_ref headlessif, ifnet_t ifp);
static  void headless_free(if_headless_ref headlessif);

static struct if_clone
    headless_zero_cloner = IF_CLONE_INITIALIZER(HEADLESS_ZERO_IFNAME,
    headless_clone_create,
    headless_clone_destroy,
    0,
    HEADLESS_MAXUNIT,
    HEADLESS_ZONE_MAX_ELEM,
    sizeof(struct if_headless));

static struct if_clone
    headless_null_cloner = IF_CLONE_INITIALIZER(HEADLESS_NULL_IFNAME,
    headless_clone_create,
    headless_clone_destroy,
    0,
    HEADLESS_MAXUNIT,
    HEADLESS_ZONE_MAX_ELEM,
    sizeof(struct if_headless));

static  void interface_link_event(ifnet_t ifp, u_int32_t event_code);

/* some media words to pretend to be ethernet */
static int default_media_words[] = {
	IFM_MAKEWORD(IFM_ETHER, 0, 0, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_10G_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_2500_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_5000_T, IFM_FDX, 0),
};
#define default_media_words_count (sizeof(default_media_words)          \
	                           / sizeof (default_media_words[0]))

/**
** veth locks
**/

static LCK_GRP_DECLARE(headless_lck_grp, "headless");
static LCK_MTX_DECLARE(headless_lck_mtx, &headless_lck_grp);

static inline void
headless_lock(void)
{
	lck_mtx_lock(&headless_lck_mtx);
}

static inline void
headless_unlock(void)
{
	lck_mtx_unlock(&headless_lck_mtx);
}

static inline unsigned int
headless_max_mtu(ifnet_t ifp)
{
	if_headless_ref     headlessif;
	unsigned int    max_mtu = ETHERMTU;

	headless_lock();
	headlessif = ifnet_get_if_headless(ifp);
	if (headlessif != NULL) {
		max_mtu = headlessif->iff_max_mtu;
	}
	headless_unlock();
	return max_mtu;
}

static void
headless_packet_pool_free(headless_packet_pool_t fpp)
{
	kern_pbufpool_destroy(fpp->fpp_pp);
	kfree_type(headless_packet_pool, fpp);
}

static void
headless_free(if_headless_ref headlessif)
{
	assert(headlessif->iff_retain_count == 0);
	if (headlessif->iff_fpp != NULL) {
		headless_packet_pool_free(headlessif->iff_fpp);
	}

	HEADLESS_DPRINTF("%s\n", headlessif->iff_name);
	if_clone_softc_deallocate(headlessif->iff_cloner, headlessif);
}

static void
headless_release(if_headless_ref headlessif)
{
	u_int32_t               old_retain_count;

	old_retain_count = OSDecrementAtomic(&headlessif->iff_retain_count);
	switch (old_retain_count) {
	case 0:
		assert(old_retain_count != 0);
		break;
	case 1:
		headless_free(headlessif);
		break;
	default:
		break;
	}
	return;
}

static void
headless_retain(if_headless_ref headlessif)
{
	OSIncrementAtomic(&headlessif->iff_retain_count);
}

static void
headless_seg_ctor_fn(const kern_pbufpool_t pp, const kern_segment_t buf_seg,
    const IOSKMemoryDescriptor buf_desc)
{
#pragma unused(pp, buf_seg, buf_desc)
}

static void
headless_seg_dtor_fn(const kern_pbufpool_t pp, const kern_segment_t buf_seg,
    const IOSKMemoryDescriptor buf_desc)
{
#pragma unused(pp, buf_seg, buf_desc)
}

static headless_packet_pool_t
headless_packet_pool_alloc(boolean_t multi_buflet, unsigned int max_mtu)
{
	headless_packet_pool_t              fpp = NULL;
	errno_t                         error;
	struct kern_pbufpool *          pp;
	struct kern_pbufpool_init       pp_init;

	bzero(&pp_init, sizeof(pp_init));
	pp_init.kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init.kbi_flags |= KBIF_USER_ACCESS;
	pp_init.kbi_flags |= KBIF_VIRTUAL_DEVICE;
	(void)snprintf((char *)pp_init.kbi_name, sizeof(pp_init.kbi_name),
	    "%s", "headless ethernet");
	pp_init.kbi_packets = 4096; /* XXX make this configurable */
	if (multi_buflet) {
		pp_init.kbi_bufsize = if_headless_buflet_size;
		pp_init.kbi_max_frags = howmany(max_mtu, if_headless_buflet_size);
		pp_init.kbi_buflets = pp_init.kbi_packets *
		    pp_init.kbi_max_frags;
		pp_init.kbi_flags |= KBIF_BUFFER_ON_DEMAND;
	} else {
		pp_init.kbi_bufsize = max_mtu;
		pp_init.kbi_max_frags = 1;
		pp_init.kbi_buflets = pp_init.kbi_packets;
	}
	pp_init.kbi_buf_seg_size = skmem_usr_buf_seg_size;
	if (skywalk_netif_direct_enabled()) {
		pp_init.kbi_flags |= KBIF_USER_ACCESS;
	}
	pp_init.kbi_buf_seg_ctor = headless_seg_ctor_fn;
	pp_init.kbi_buf_seg_dtor = headless_seg_dtor_fn;
	pp_init.kbi_ctx = NULL;
	pp_init.kbi_ctx_retain = NULL;
	pp_init.kbi_ctx_release = NULL;

	error = kern_pbufpool_create(&pp_init, &pp, NULL);
	if (error != 0) {
		printf("%s: kern_pbufpool_create failed %d\n", __func__, error);
	} else {
		fpp = kalloc_type(headless_packet_pool, Z_WAITOK | Z_ZERO);
		fpp->fpp_pp = pp;
		fpp->fpp_retain_count = 1;
	}
	return fpp;
}

/**
** nexus netif domain provider
**/
static errno_t
headless_nxdp_init(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
	return 0;
}

static void
headless_nxdp_fini(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
}

static uuid_t                   headless_nx_dom_prov;

static errno_t
headless_register_nexus_domain_provider(void)
{
	const struct kern_nexus_domain_provider_init dp_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = headless_nxdp_init,
		.nxdpi_fini = headless_nxdp_fini
	};
	errno_t                         err = 0;

	/* headless_nxdp_init() is called before this function returns */
	err = kern_nexus_register_domain_provider(NEXUS_TYPE_NET_IF,
	    (const uint8_t *)
	    "com.apple.headless",
	    &dp_init, sizeof(dp_init),
	    &headless_nx_dom_prov);
	if (err != 0) {
		printf("%s: failed to register domain provider\n", __func__);
		return err;
	}
	return 0;
}

/**
** netif nexus routines
**/
static if_headless_ref
headless_nexus_context(kern_nexus_t nexus)
{
	if_headless_ref headlessif;

	headlessif = (if_headless_ref)kern_nexus_get_context(nexus);
	assert(headlessif != NULL);
	return headlessif;
}

static errno_t
headless_nx_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
	if_headless_ref     headlessif;
#pragma unused(nxprov, channel, ring_ctx)
	headless_lock();
	headlessif = headless_nexus_context(nexus);
	if (headless_is_detaching(headlessif)) {
		headless_unlock();
		return 0;
	}
	if (is_tx_ring) {
		assert(headlessif->iff_tx_ring[0] == NULL);
		headlessif->iff_tx_ring[0] = ring;
	} else {
		assert(headlessif->iff_rx_ring[0] == NULL);
		headlessif->iff_rx_ring[0] = ring;
	}
	headless_unlock();
	HEADLESS_DPRINTF("%s: %s ring init\n",
	    headlessif->iff_name, is_tx_ring ? "TX" : "RX");
	return 0;
}

static void
headless_nx_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov, ring)
	if_headless_ref     headlessif;
	thread_call_t   tcall = NULL;

	headless_lock();
	headlessif = headless_nexus_context(nexus);
	if (headlessif->iff_rx_ring[0] == ring) {
		headlessif->iff_rx_ring[0] = NULL;
		HEADLESS_DPRINTF("%s: RX ring fini\n", headlessif->iff_name);
	} else if (headlessif->iff_tx_ring[0] == ring) {
		tcall = headlessif->iff_doorbell_tcall;
		headlessif->iff_doorbell_tcall = NULL;
		headlessif->iff_tx_ring[0] = NULL;
	}
	headless_unlock();
	if (tcall != NULL) {
		boolean_t       success;

		success = thread_call_cancel_wait(tcall);
		HEADLESS_DPRINTF("%s: thread_call_cancel %s\n",
		    headlessif->iff_name,
		    success ? "SUCCESS" : "FAILURE");
		if (!success) {
			headless_lock();
			if (headlessif->iff_tcall_active) {
				headlessif->iff_waiting_for_tcall = TRUE;
				HEADLESS_DPRINTF("%s: *waiting for threadcall\n",
				    headlessif->iff_name);
				do {
					msleep(headlessif, &headless_lck_mtx,
					    PZERO, "headless threadcall", 0);
				} while (headlessif->iff_tcall_active);
				HEADLESS_DPRINTF("%s: ^threadcall done\n",
				    headlessif->iff_name);
				headlessif->iff_waiting_for_tcall = FALSE;
			}
			headless_unlock();
		}
		success = thread_call_free(tcall);
		HEADLESS_DPRINTF("%s: thread_call_free %s\n",
		    headlessif->iff_name,
		    success ? "SUCCESS" : "FAILURE");
		headless_release(headlessif);
		assert(success == TRUE);
	}
}

static errno_t
headless_nx_pre_connect(kern_nexus_provider_t nxprov,
    proc_t proc, kern_nexus_t nexus, nexus_port_t port, kern_channel_t channel,
    void **channel_context)
{
#pragma unused(nxprov, proc, nexus, port, channel, channel_context)
	return 0;
}

static errno_t
headless_nx_connected(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_headless_ref headlessif;

	headlessif = headless_nexus_context(nexus);
	headless_lock();
	if (headless_is_detaching(headlessif)) {
		headless_unlock();
		return EBUSY;
	}
	headless_retain(headlessif);
	headlessif->iff_channel_connected = TRUE;
	headless_unlock();
	HEADLESS_DPRINTF("%s: connected channel %p\n",
	    headlessif->iff_name, channel);
	return 0;
}

static void
headless_nx_pre_disconnect(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_headless_ref headlessif;

	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s: pre-disconnect channel %p\n",
	    headlessif->iff_name, channel);
	/* Quiesce the interface and flush any pending outbound packets. */
	if_down(headlessif->iff_ifp);
	headless_lock();
	headlessif->iff_channel_connected = FALSE;
	headless_unlock();
}

static void
headless_nx_disconnected(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_headless_ref headlessif;

	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s: disconnected channel %p\n",
	    headlessif->iff_name, channel);
	headless_release(headlessif);
}

static errno_t
headless_nx_slot_init(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index, struct kern_slot_prop **slot_prop_addr,
    void **slot_context)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index, slot_prop_addr, slot_context)
	return 0;
}

static void
headless_nx_slot_fini(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index)
}

static errno_t
headless_nx_sync_tx(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
	if_headless_ref         headlessif;
	ifnet_t                 ifp;
	kern_channel_slot_t     last_tx_slot = NULL;
	struct kern_channel_ring_stat_increment stats = {
		.kcrsi_slots_transferred = 0, .kcrsi_bytes_transferred = 0
	};
	kern_channel_slot_t     tx_slot;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	STATS_INC(nifs, NETIF_STATS_TX_SYNC);
	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s ring %d flags 0x%x\n", headlessif->iff_name,
	    tx_ring->ckr_ring_id, flags);

	headless_lock();
	if (headless_is_detaching(headlessif) ||
	    !headlessif->iff_channel_connected) {
		headless_unlock();
		return 0;
	}
	headless_unlock();
	ifp = headlessif->iff_ifp;
	tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	while (tx_slot != NULL) {
		kern_packet_t   ph;

		/* detach the packet from the TX ring */
		ph = kern_channel_slot_get_packet(tx_ring, tx_slot);
		assert(ph != 0);
		kern_channel_slot_detach_packet(tx_ring, tx_slot, ph);

		kern_pbufpool_free(headlessif->iff_fpp->fpp_pp, ph);
		last_tx_slot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);
		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);
	}

	if (last_tx_slot != NULL) {
		kern_channel_advance_slot(tx_ring, last_tx_slot);
		kern_channel_increment_ring_net_stats(tx_ring, ifp, &stats);
	}
	return 0;
}

static errno_t
headless_nx_sync_rx_null(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov, rx_ring, flags)
	if_headless_ref headlessif;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s:\n", headlessif->iff_name);
	STATS_INC(nifs, NETIF_STATS_RX_SYNC);
	return 0;
}

static errno_t
headless_nx_sync_rx(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t rx_ring, uint32_t flags)
{
#pragma unused(nxprov)
	if_headless_ref         headlessif;
	ifnet_t                 ifp;
	kern_channel_slot_t     last_rx_slot = NULL;
	struct kern_channel_ring_stat_increment stats = {
		.kcrsi_slots_transferred = 0, .kcrsi_bytes_transferred = 0
	};
	kern_channel_slot_t     rx_slot;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	kern_channel_reclaim(rx_ring);
	STATS_INC(nifs, NETIF_STATS_RX_SYNC);
	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s ring %d flags 0x%x\n", headlessif->iff_name,
	    rx_ring->ckr_ring_id, flags);

	headless_lock();
	if (headless_is_detaching(headlessif) ||
	    !headlessif->iff_channel_connected) {
		headless_unlock();
		return 0;
	}
	headless_unlock();
	ifp = headlessif->iff_ifp;
	rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);
	kern_pbufpool_t pp = headlessif->iff_fpp->fpp_pp;
	while (rx_slot != NULL) {
		kern_packet_t ph;
		kern_buflet_t buf = NULL;
		int err;
		err = kern_pbufpool_alloc(pp, 1, &ph);
		buf = kern_packet_get_next_buflet(ph, buf);
		kern_buflet_set_data_offset(buf, 0);
		if (if_headless_create_payload) {
			// This is a plain TCP SYN packet
			void *addr = kern_buflet_get_data_address(buf);
			uint64_t *u64 = addr;
			*(u64 + 0) = 0xc100d51dc3355b68ULL;
			*(u64 + 1) = 0x004500084019c564ULL;
			*(u64 + 2) = 0x0634004000004000ULL;
			*(u64 + 3) = 0x716111e3068d11c0ULL;
			*(u64 + 4) = 0xc0118d06e3116171ULL;
			*(u64 + 5) = 0x8a3700000000b002ULL;
			*(u64 + 6) = 0x02b000000000378aULL;
			*(u64 + 7) = 0x010106030301b405ULL;
			*(u64 + 8) = 0x000022cc5c940a08ULL;
			*(u64 + 9) = 0x0000040200000000ULL;
		}
		kern_buflet_set_data_length(buf, (uint16_t)if_headless_packet_length);
		err = kern_packet_set_headroom(ph, 0);
		ASSERT(err == 0);
		err = kern_packet_set_link_header_length(ph, 14);
		ASSERT(err == 0);
		kern_packet_finalize(ph);

		kern_channel_slot_attach_packet(rx_ring, rx_slot, ph);

		STATS_INC(nifs, NETIF_STATS_RX_PACKETS);
		last_rx_slot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	if (last_rx_slot != NULL) {
		kern_channel_advance_slot(rx_ring, last_rx_slot);
		kern_channel_increment_ring_net_stats(rx_ring, ifp, &stats);
	}
	return 0;
}

static void
headless_async_doorbell(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	errno_t                 error;
	if_headless_ref         headlessif = (if_headless_ref)arg0;
	kern_channel_ring_t     ring;
	boolean_t               more;

	headless_lock();
	ring = headlessif->iff_tx_ring[0];
	if (headless_is_detaching(headlessif) ||
	    !headlessif->iff_channel_connected ||
	    ring == NULL) {
		goto done;
	}
	headlessif->iff_tcall_active = TRUE;
	headless_unlock();
	error = kern_channel_tx_refill(ring, UINT32_MAX,
	    UINT32_MAX, FALSE, &more);
	if (error != 0) {
		HEADLESS_DPRINTF("%s: TX refill failed %d\n",
		    headlessif->iff_name, error);
	} else {
		HEADLESS_DPRINTF("%s: TX refilled\n", headlessif->iff_name);
	}

	headless_lock();
done:
	headlessif->iff_tcall_active = FALSE;
	if (headlessif->iff_waiting_for_tcall) {
		HEADLESS_DPRINTF("%s: threadcall waking up waiter\n",
		    headlessif->iff_name);
		wakeup((caddr_t)headlessif);
	}
	headless_unlock();
}

static void
headless_schedule_async_doorbell(if_headless_ref headlessif)
{
	thread_call_t   tcall;

	headless_lock();
	if (headless_is_detaching(headlessif) ||
	    !headlessif->iff_channel_connected) {
		headless_unlock();
		return;
	}
	tcall = headlessif->iff_doorbell_tcall;
	if (tcall != NULL) {
		thread_call_enter(tcall);
	} else {
		tcall = thread_call_allocate_with_options(headless_async_doorbell,
		    (thread_call_param_t)headlessif,
		    THREAD_CALL_PRIORITY_KERNEL,
		    THREAD_CALL_OPTIONS_ONCE);
		if (tcall == NULL) {
			printf("%s: %s tcall alloc failed\n",
			    __func__, headlessif->iff_name);
		} else {
			headlessif->iff_doorbell_tcall = tcall;
			headless_retain(headlessif);
			thread_call_enter(tcall);
		}
	}
	headless_unlock();
}

static errno_t
headless_nx_tx_doorbell(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, ring, flags)
	errno_t         error;
	if_headless_ref     headlessif;

	headlessif = headless_nexus_context(nexus);
	HEADLESS_DPRINTF("%s\n", headlessif->iff_name);

	if ((flags & KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL) == 0) {
		boolean_t       more;
		/* synchronous tx refill */
		error = kern_channel_tx_refill(ring, UINT32_MAX,
		    UINT32_MAX, TRUE, &more);
		if (error != 0) {
			HEADLESS_DPRINTF("%s: TX refill (sync) %d\n",
			    headlessif->iff_name, error);
		} else {
			HEADLESS_DPRINTF("%s: TX refilled (sync)\n",
			    headlessif->iff_name);
		}
	} else {
		HEADLESS_DPRINTF("%s: schedule async refill\n",
		    headlessif->iff_name);
		headless_schedule_async_doorbell(headlessif);
	}
	return 0;
}

static errno_t
headless_netif_prepare(kern_nexus_t nexus, ifnet_t ifp)
{
	if_headless_ref headlessif;

	headlessif = (if_headless_ref)kern_nexus_get_context(nexus);
	headless_ifnet_set_attrs(headlessif, ifp);
	return 0;
}

static errno_t
create_netif_provider_and_instance(if_headless_ref headlessif,
    struct ifnet_init_eparams * init_params, ifnet_t *ifp,
    uuid_t * provider, uuid_t * instance)
{
	errno_t                 err;
	nexus_controller_t      controller = kern_nexus_shared_controller();
	struct kern_nexus_net_init net_init;
	nexus_name_t            provider_name;
	nexus_attr_t            nexus_attr = NULL;
	struct kern_nexus_provider_init prov_init = {
		.nxpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxpi_pre_connect = headless_nx_pre_connect,
		.nxpi_connected = headless_nx_connected,
		.nxpi_pre_disconnect = headless_nx_pre_disconnect,
		.nxpi_disconnected = headless_nx_disconnected,
		.nxpi_ring_init = headless_nx_ring_init,
		.nxpi_ring_fini = headless_nx_ring_fini,
		.nxpi_slot_init = headless_nx_slot_init,
		.nxpi_slot_fini = headless_nx_slot_fini,
		.nxpi_sync_tx = headless_nx_sync_tx,
		.nxpi_sync_rx = headless_nx_sync_rx,
		.nxpi_tx_doorbell = headless_nx_tx_doorbell,
	};

	if (headlessif->iff_cloner == &headless_zero_cloner) {
		prov_init.nxpi_sync_rx = headless_nx_sync_rx;
		prov_init.nxpi_sync_tx = headless_nx_sync_tx;
	} else if (headlessif->iff_cloner == &headless_null_cloner) {
		prov_init.nxpi_sync_rx = headless_nx_sync_rx_null;
		prov_init.nxpi_sync_tx = headless_nx_sync_tx;
	}

	_CASSERT(IFF_MAX_RX_RINGS == 1);

	snprintf((char *)provider_name, sizeof(provider_name),
	    "com.apple.netif.%s", headlessif->iff_name);
	err = kern_nexus_controller_register_provider(controller,
	    headless_nx_dom_prov,
	    provider_name,
	    &prov_init,
	    sizeof(prov_init),
	    nexus_attr,
	    provider);
	if (err != 0) {
		printf("%s register provider failed, error %d\n",
		    __func__, err);
		goto failed;
	}
	bzero(&net_init, sizeof(net_init));
	net_init.nxneti_version = KERN_NEXUS_NET_CURRENT_VERSION;
	net_init.nxneti_flags = 0;
	net_init.nxneti_eparams = init_params;
	net_init.nxneti_lladdr = NULL;
	net_init.nxneti_prepare = headless_netif_prepare;
	net_init.nxneti_rx_pbufpool = headlessif->iff_fpp->fpp_pp;
	net_init.nxneti_tx_pbufpool = headlessif->iff_fpp->fpp_pp;
	err = kern_nexus_controller_alloc_net_provider_instance(controller,
	    *provider,
	    headlessif,
	    NULL,
	    instance,
	    &net_init,
	    ifp);
	if (err != 0) {
		printf("%s alloc_net_provider_instance failed, %d\n",
		    __func__, err);
		kern_nexus_controller_deregister_provider(controller,
		    *provider);
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
headless_attach_netif_nexus(if_headless_ref headlessif,
    struct ifnet_init_eparams * init_params, ifnet_t *ifp)
{
	headless_packet_pool_t      fpp;
	headless_nx_t               nx = &headlessif->iff_nx;
	boolean_t               multi_buflet;

	multi_buflet = headless_using_multibuflets(headlessif);
	fpp = headless_packet_pool_alloc(multi_buflet, headlessif->iff_max_mtu);
	if (fpp == NULL) {
		return ENOMEM;
	}
	headlessif->iff_fpp = fpp;
	return create_netif_provider_and_instance(headlessif, init_params, ifp,
	           &nx->fnx_provider,
	           &nx->fnx_instance);
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
			printf("%s free_provider_instance failed %d\n",
			    __func__, err);
		}
		uuid_clear(instance);
	}
	if (!uuid_is_null(provider)) {
		err = kern_nexus_controller_deregister_provider(controller,
		    provider);
		if (err != 0) {
			printf("%s deregister_provider %d\n", __func__, err);
		}
		uuid_clear(provider);
	}
	return;
}

static void
headless_detach_netif_nexus(headless_nx_t nx)
{
	detach_provider_and_instance(nx->fnx_provider, nx->fnx_instance);
}

/**
** headless interface routines
**/
static void
headless_ifnet_set_attrs(if_headless_ref headlessif, ifnet_t ifp)
{
	(void)ifnet_set_capabilities_enabled(ifp, 0, -1);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_mtu(ifp, ETHERMTU);
	ifnet_set_flags(ifp,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    0xffff);
	ifnet_set_hdrlen(ifp, sizeof(struct ether_header));
	if ((headlessif->iff_flags & IFF_FLAGS_HWCSUM) != 0) {
		ifnet_set_offload(ifp,
		    IFNET_CSUM_IP | IFNET_CSUM_TCP | IFNET_CSUM_UDP |
		    IFNET_CSUM_TCPIPV6 | IFNET_CSUM_UDPIPV6);
	} else {
		ifnet_set_offload(ifp, 0);
	}
}

static void
interface_link_event(ifnet_t ifp, u_int32_t event_code)
{
	struct event {
		u_int32_t ifnet_family;
		u_int32_t unit;
		char if_name[IFNAMSIZ];
	};
	_Alignas(struct kern_event_msg) char message[sizeof(struct kern_event_msg) + sizeof(struct event)] = { 0 };
	struct kern_event_msg *header = (struct kern_event_msg*)message;
	struct event *data = (struct event *)(header + 1);

	header->total_size   = sizeof(message);
	header->vendor_code  = KEV_VENDOR_APPLE;
	header->kev_class    = KEV_NETWORK_CLASS;
	header->kev_subclass = KEV_DL_SUBCLASS;
	header->event_code   = event_code;
	data->ifnet_family   = ifnet_family(ifp);
	data->unit           = (u_int32_t)ifnet_unit(ifp);
	strlcpy(data->if_name, ifnet_name(ifp), IFNAMSIZ);
	ifnet_event(ifp, header);
}

static if_headless_ref
ifnet_get_if_headless(ifnet_t ifp)
{
	return (if_headless_ref)ifnet_softc(ifp);
}

static int
headless_clone_create(struct if_clone *ifc, u_int32_t unit, void *params)
{
#pragma unused(params)
	int                             error;
	if_headless_ref                 headlessif;
	struct ifnet_init_eparams       headless_init;
	ifnet_t                         ifp;
	uint8_t                         mac_address[ETHER_ADDR_LEN];

	headlessif = if_clone_softc_allocate(ifc);
	if (headlessif == NULL) {
		return ENOBUFS;
	}
	headlessif->iff_retain_count = 1;
	if (strcmp(ifc->ifc_name, HEADLESS_ZERO_IFNAME) == 0) {
		headlessif->iff_cloner = &headless_zero_cloner;
		ASSERT(strlen(HEADLESS_ZERO_IFNAME) == 4);
		bcopy(HEADLESS_ZERO_IFNAME, mac_address, 4);
	} else {
		headlessif->iff_cloner = &headless_null_cloner;
		ASSERT(strlen(HEADLESS_NULL_IFNAME) == 4);
		bcopy(HEADLESS_NULL_IFNAME, mac_address, 4);
	}
	mac_address[ETHER_ADDR_LEN - 2] = (unit & 0xff00) >> 8;
	mac_address[ETHER_ADDR_LEN - 1] = unit & 0xff;
	headlessif->iff_max_mtu = if_headless_max_mtu;

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(headlessif->iff_name, sizeof(headlessif->iff_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(headlessif->iff_name)) {
		headless_release(headlessif);
		return EINVAL;
	}
	bzero(&headless_init, sizeof(headless_init));
	headless_init.ver = IFNET_INIT_CURRENT_VERSION;
	headless_init.len = sizeof(headless_init);
	headless_init.flags |= IFNET_INIT_SKYWALK_NATIVE;
	if (if_headless_multibuflet != 0) {
		headlessif->iff_flags |= IFF_FLAGS_MULTIBUFLETS;
	}

	headlessif->iff_tx_headroom = if_headless_tx_headroom;
	headless_init.tx_headroom = headlessif->iff_tx_headroom;
	if (if_headless_nxattach == 0) {
		headless_init.flags |= IFNET_INIT_NX_NOAUTO;
	}
	headless_init.uniqueid = headlessif->iff_name;
	headless_init.uniqueid_len = (uint32_t)strlen(headlessif->iff_name);
	headless_init.name = ifc->ifc_name;
	headless_init.unit = unit;
	headless_init.family = IFNET_FAMILY_ETHERNET;
	headless_init.type = IFT_ETHER;
	headless_init.demux = ether_demux;
	headless_init.add_proto = ether_add_proto;
	headless_init.del_proto = ether_del_proto;
	headless_init.check_multi = ether_check_multi;
	headless_init.framer_extended = ether_frameout_extended;
	headless_init.softc = headlessif;
	headless_init.ioctl = headless_ioctl;
	headless_init.set_bpf_tap = NULL;
	headless_init.detach = headless_if_free;
	headless_init.broadcast_addr = etherbroadcastaddr;
	headless_init.broadcast_len = ETHER_ADDR_LEN;
	error = headless_attach_netif_nexus(headlessif, &headless_init, &ifp);
	if (error != 0) {
		headless_release(headlessif);
		return error;
	}
	/* take an additional reference to ensure that it doesn't go away */
	headless_retain(headlessif);
	headlessif->iff_ifp = ifp;
	headlessif->iff_media_count = default_media_words_count;
	bcopy(default_media_words, headlessif->iff_media_list,
	    sizeof(default_media_words));
	ifnet_set_lladdr(ifp, mac_address, sizeof(mac_address));

	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));

	interface_link_event(ifp, KEV_DL_LINK_ON);

	return 0;
}

static int
headless_clone_destroy(ifnet_t ifp)
{
	if_headless_ref     headlessif;
	headless_nx         nx;
	boolean_t       nx_attached = FALSE;

	interface_link_event(ifp, KEV_DL_LINK_OFF);
	headless_lock();
	headlessif = ifnet_get_if_headless(ifp);
	if (headlessif == NULL || headless_is_detaching(headlessif)) {
		headless_unlock();
		return 0;
	}
	headless_set_detaching(headlessif);
	nx_attached = TRUE;
	nx = headlessif->iff_nx;
	bzero(&headlessif->iff_nx, sizeof(headlessif->iff_nx));
	headless_unlock();

	if (nx_attached) {
		headless_detach_netif_nexus(&nx);
		headless_release(headlessif);
	}
	ifnet_detach(ifp);
	return 0;
}

static int
headless_set_media(ifnet_t ifp, struct if_headless_request * iffr)
{
	if_headless_ref     headlessif;
	int             error;

	if (iffr->iffr_media.iffm_count > IF_HEADLESS_MEDIA_LIST_MAX) {
		/* list is too long */
		return EINVAL;
	}
	headless_lock();
	headlessif = ifnet_get_if_headless(ifp);
	if (headlessif == NULL) {
		error = EINVAL;
		goto done;
	}
	headlessif->iff_media_count = iffr->iffr_media.iffm_count;
	bcopy(iffr->iffr_media.iffm_list, headlessif->iff_media_list,
	    iffr->iffr_media.iffm_count * sizeof(headlessif->iff_media_list[0]));
#if 0
	/* XXX: "auto-negotiate" active with peer? */
	/* generate link status event? */
	headlessif->iff_media_current = iffr->iffr_media.iffm_current;
#endif
	error = 0;
done:
	headless_unlock();
	return error;
}

static int
if_headless_request_copyin(user_addr_t user_addr,
    struct if_headless_request *iffr, size_t len)
{
	int     error;

	if (user_addr == USER_ADDR_NULL || len < sizeof(*iffr)) {
		error = EINVAL;
		goto done;
	}
	error = copyin(user_addr, iffr, sizeof(*iffr));
	if (error != 0) {
		goto done;
	}
	if (iffr->iffr_reserved[0] != 0 || iffr->iffr_reserved[1] != 0 ||
	    iffr->iffr_reserved[2] != 0 || iffr->iffr_reserved[3] != 0) {
		error = EINVAL;
		goto done;
	}
done:
	return error;
}

static int
headless_set_drvspec(ifnet_t ifp, uint64_t cmd, size_t len,
    user_addr_t user_addr)
{
	int                     error;
	struct if_headless_request  iffr;

	switch (cmd) {
	case IF_HEADLESS_S_CMD_SET_MEDIA:
		error = if_headless_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		error = headless_set_media(ifp, &iffr);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static int
headless_get_drvspec(ifnet_t ifp, uint64_t cmd, size_t len,
    user_addr_t user_addr)
{
#pragma unused(ifp, len, user_addr)
	int                     error = EOPNOTSUPP;

	switch (cmd) {
	default:
		break;
	}
	return error;
}

union ifdrvu {
	struct ifdrv32  *ifdrvu_32;
	struct ifdrv64  *ifdrvu_64;
	void            *ifdrvu_p;
};

static int
headless_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
	unsigned int            count;
	struct ifdevmtu *       devmtu_p;
	union ifdrvu            drv;
	uint64_t                drv_cmd;
	uint64_t                drv_len;
	boolean_t               drv_set_command = FALSE;
	int                     error = 0;
	struct ifmediareq *     ifmr;
	struct ifreq *          ifr;
	if_headless_ref             headlessif;
	int                     status;
	user_addr_t             user_addr;

	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
		headless_lock();
		headlessif = ifnet_get_if_headless(ifp);
		if (headlessif == NULL) {
			headless_unlock();
			return EOPNOTSUPP;
		}
		status = (headlessif->iff_peer != NULL)
		    ? (IFM_AVALID | IFM_ACTIVE) : IFM_AVALID;
		ifmr = (struct ifmediareq *)data;
		user_addr = (cmd == SIOCGIFMEDIA64) ?
		    CAST_USER_ADDR_T(((struct ifmediareq64 *)ifmr)->ifmu_ulist) :
		    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
		count = ifmr->ifm_count;
		ifmr->ifm_active = IFM_ETHER;
		ifmr->ifm_current = IFM_ETHER;
		ifmr->ifm_mask = 0;
		ifmr->ifm_status = status;
		if (user_addr == USER_ADDR_NULL) {
			ifmr->ifm_count = headlessif->iff_media_count;
		} else if (count > 0) {
			if (count > headlessif->iff_media_count) {
				count = headlessif->iff_media_count;
			}
			ifmr->ifm_count = count;
			error = copyout(&headlessif->iff_media_list, user_addr,
			    count * sizeof(int));
		}
		headless_unlock();
		break;

	case SIOCGIFDEVMTU:
		devmtu_p = &ifr->ifr_devmtu;
		devmtu_p->ifdm_current = ifnet_mtu(ifp);
		devmtu_p->ifdm_max = headless_max_mtu(ifp);
		devmtu_p->ifdm_min = IF_MINMTU;
		break;

	case SIOCSIFMTU:
		if ((unsigned int)ifr->ifr_mtu > headless_max_mtu(ifp) ||
		    ifr->ifr_mtu < IF_MINMTU) {
			error = EINVAL;
		} else {
			error = ifnet_set_mtu(ifp, ifr->ifr_mtu);
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
			user_addr = CAST_USER_ADDR_T(drv.ifdrvu_64->ifd_data);
		}
		if (drv_set_command) {
			error = headless_set_drvspec(ifp, drv_cmd,
			    (size_t)drv_len, user_addr);
		} else {
			error = headless_get_drvspec(ifp, drv_cmd,
			    (size_t)drv_len, user_addr);
		}
		break;

	case SIOCSIFLLADDR:
		error = ifnet_set_lladdr(ifp, ifr->ifr_addr.sa_data,
		    ifr->ifr_addr.sa_len);
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
headless_if_free(ifnet_t ifp)
{
	if_headless_ref             headlessif;

	if (ifp == NULL) {
		return;
	}
	headless_lock();
	headlessif = ifnet_get_if_headless(ifp);
	if (headlessif == NULL) {
		headless_unlock();
		return;
	}
	ifp->if_softc = NULL;
	assert(headlessif->iff_doorbell_tcall == NULL);
	headless_unlock();
	headless_release(headlessif);
	ifnet_release(ifp);
	return;
}

void
if_headless_init(void)
{
	int error;

	(void)headless_register_nexus_domain_provider();
	error = if_clone_attach(&headless_zero_cloner);
	if (error != 0) {
		return;
	}
	error = if_clone_attach(&headless_null_cloner);
	if (error != 0) {
		if_clone_detach(&headless_zero_cloner);
		return;
	}
	return;
}
#else /* !SKYWALK */
extern void if_headless_init(void);

void
if_headless_init(void)
{
	/* nothing here */
}
#endif /* SKYWALK */
