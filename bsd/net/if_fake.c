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
 * if_fake.c
 * - fake network interface used for testing
 * - "feth" (e.g. "feth0", "feth1") is a virtual ethernet interface that allows
 *   two instances to have their output/input paths "crossed-over" so that
 *   output on one is input on the other
 */

/*
 * Modification History:
 *
 * September 9, 2015	Dieter Siegmund (dieter@apple.com)
 * - created
 */

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
#include <net/if_fake_var.h>
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
#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/channel/channel_var.h>
#endif /* SKYWALK */

static boolean_t
is_power_of_two(unsigned int val)
{
	return (val & (val - 1)) == 0;
}

#define FAKE_ETHER_NAME         "feth"

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, fake, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "Fake interface");

static int if_fake_txstart = 1;
SYSCTL_INT(_net_link_fake, OID_AUTO, txstart, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_txstart, 0, "Fake interface TXSTART mode");

static int if_fake_hwcsum = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, hwcsum, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_hwcsum, 0, "Fake interface simulate hardware checksum");

static int if_fake_nxattach = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, nxattach, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_nxattach, 0, "Fake interface auto-attach nexus");

static int if_fake_bsd_mode = 1;
SYSCTL_INT(_net_link_fake, OID_AUTO, bsd_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_bsd_mode, 0, "Fake interface attach as BSD interface");

static int if_fake_debug = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_debug, 0, "Fake interface debug logs");

static int if_fake_wmm_mode = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, wmm_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_wmm_mode, 0, "Fake interface in 802.11 WMM mode");

static int if_fake_multibuflet = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, multibuflet, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_multibuflet, 0, "Fake interface using multi-buflet packets");

static int if_fake_low_latency = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, low_latency, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_low_latency, 0, "Fake interface with a low latency qset");

static int if_fake_switch_combined_mode = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, switch_combined_mode,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_fake_switch_combined_mode, 0,
    "Switch a qset between combined and separate mode during dequeues");

static int if_fake_switch_mode_frequency = 10;
SYSCTL_INT(_net_link_fake, OID_AUTO, switch_mode_frequency,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_fake_switch_mode_frequency, 0,
    "The number of dequeues before we switch between the combined and separated mode");

static int if_fake_tso_support = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, tso_support, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_tso_support, 0, "Fake interface with support for TSO offload");

typedef enum {
	IFF_PP_MODE_GLOBAL = 0,         /* share a global pool */
	IFF_PP_MODE_PRIVATE = 1,        /* creates its own rx/tx pool */
	IFF_PP_MODE_PRIVATE_SPLIT = 2,  /* creates its own split rx & tx pool */
} iff_pktpool_mode_t;
static iff_pktpool_mode_t if_fake_pktpool_mode = IFF_PP_MODE_GLOBAL;
SYSCTL_INT(_net_link_fake, OID_AUTO, pktpool_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_pktpool_mode, IFF_PP_MODE_GLOBAL,
    "Fake interface packet pool mode (0 global, 1 private, 2 private split");

#define FETH_LINK_LAYER_AGGRETATION_FACTOR_MAX 512
#define FETH_LINK_LAYER_AGGRETATION_FACTOR_DEF 96
static int if_fake_link_layer_aggregation_factor =
    FETH_LINK_LAYER_AGGRETATION_FACTOR_DEF;
static int
feth_link_layer_aggregation_factor_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_link_layer_aggregation_factor,
	    sizeof(if_fake_link_layer_aggregation_factor), &new_value,
	    &changed);
	if (error == 0 && changed != 0) {
		if (new_value <= 0 ||
		    new_value > FETH_LINK_LAYER_AGGRETATION_FACTOR_MAX) {
			return EINVAL;
		}
		if_fake_link_layer_aggregation_factor = new_value;
	}
	return error;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, link_layer_aggregation_factor,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_link_layer_aggregation_factor_sysctl, "IU",
    "Fake interface link layer aggregation factor");

#define FETH_TX_HEADROOM_MAX      32
static unsigned int if_fake_tx_headroom = FETH_TX_HEADROOM_MAX;
static int
feth_tx_headroom_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_tx_headroom,
	    sizeof(if_fake_tx_headroom), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_TX_HEADROOM_MAX ||
		    (new_value % 8) != 0) {
			return EINVAL;
		}
		if_fake_tx_headroom = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, tx_headroom,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_tx_headroom_sysctl, "IU", "Fake ethernet Tx headroom");

static int if_fake_fcs = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, fcs, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_fcs, 0, "Fake interface using frame check sequence");

#define FETH_TRAILER_LENGTH_MAX 28
char feth_trailer[FETH_TRAILER_LENGTH_MAX + 1] = "trailertrailertrailertrailer";
static unsigned int if_fake_trailer_length = 0;
static int
feth_trailer_length_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_trailer_length,
	    sizeof(if_fake_trailer_length), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_TRAILER_LENGTH_MAX) {
			return EINVAL;
		}
		if_fake_trailer_length = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, trailer_length,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_trailer_length_sysctl, "IU", "Fake interface frame trailer length");

/* sysctl net.link.fake.max_mtu */
#define FETH_MAX_MTU_DEFAULT    2048
#define FETH_MAX_MTU_MAX        ((16 * 1024) - ETHER_HDR_LEN)

static unsigned int if_fake_max_mtu = FETH_MAX_MTU_DEFAULT;

/* sysctl net.link.fake.buflet_size */
#define FETH_BUFLET_SIZE_MIN            512
#define FETH_BUFLET_SIZE_MAX            (32 * 1024)
#define FETH_TSO_BUFLET_SIZE            (16 * 1024)

static unsigned int if_fake_buflet_size = FETH_BUFLET_SIZE_MIN;
static unsigned int if_fake_tso_buffer_size = FETH_TSO_BUFLET_SIZE;

static int
feth_tso_buffer_size_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_tso_buffer_size,
	    sizeof(if_fake_tso_buffer_size), &new_value, &changed);
	if (error == 0 && changed != 0) {
		/* must be a power of 2 between min and max */
		if (new_value > FETH_BUFLET_SIZE_MAX ||
		    new_value < FETH_BUFLET_SIZE_MIN ||
		    !is_power_of_two(new_value)) {
			return EINVAL;
		}
		if_fake_tso_buffer_size = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, tso_buf_size,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_tso_buffer_size_sysctl, "IU", "Fake interface TSO buffer size");

static int
feth_max_mtu_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_max_mtu,
	    sizeof(if_fake_max_mtu), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_MAX_MTU_MAX ||
		    new_value < ETHERMTU ||
		    new_value <= if_fake_buflet_size) {
			return EINVAL;
		}
		if_fake_max_mtu = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, max_mtu,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_max_mtu_sysctl, "IU", "Fake interface maximum MTU");

static int
feth_buflet_size_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_buflet_size,
	    sizeof(if_fake_buflet_size), &new_value, &changed);
	if (error == 0 && changed != 0) {
		/* must be a power of 2 between min and max */
		if (new_value > FETH_BUFLET_SIZE_MAX ||
		    new_value < FETH_BUFLET_SIZE_MIN ||
		    !is_power_of_two(new_value) ||
		    new_value >= if_fake_max_mtu) {
			return EINVAL;
		}
		if_fake_buflet_size = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, buflet_size,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_buflet_size_sysctl, "IU", "Fake interface buflet size");

static unsigned int if_fake_user_access = 0;

static int
feth_user_access_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_user_access,
	    sizeof(if_fake_user_access), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value != 0) {
			if (new_value != 1) {
				return EINVAL;
			}
		}
		if_fake_user_access = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, user_access,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, feth_user_access_sysctl, "IU", "Fake interface user access");

/* sysctl net.link.fake.if_adv_intvl (unit: millisecond) */
#define FETH_IF_ADV_INTVL_MIN            10
#define FETH_IF_ADV_INTVL_MAX            INT_MAX

static int if_fake_if_adv_interval = 0; /* no interface advisory */
static int
feth_if_adv_interval_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_if_adv_interval,
	    sizeof(if_fake_if_adv_interval), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if ((new_value != 0) && (new_value > FETH_IF_ADV_INTVL_MAX ||
		    new_value < FETH_IF_ADV_INTVL_MIN)) {
			return EINVAL;
		}
		if_fake_if_adv_interval = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, if_adv_intvl,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_if_adv_interval_sysctl, "IU",
    "Fake interface will generate interface advisories reports at the specified interval in ms");

/* sysctl net.link.fake.tx_drops */
/*
 * Fake ethernet will drop packet on the transmit path at the specified
 * rate, i.e drop one in every if_fake_tx_drops number of packets.
 */
#define FETH_TX_DROPS_MIN            0
#define FETH_TX_DROPS_MAX            INT_MAX
static int if_fake_tx_drops = 0; /* no packets are dropped */
static int
feth_fake_tx_drops_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_tx_drops,
	    sizeof(if_fake_tx_drops), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_TX_DROPS_MAX ||
		    new_value < FETH_TX_DROPS_MIN) {
			return EINVAL;
		}
		if_fake_tx_drops = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, tx_drops,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_fake_tx_drops_sysctl, "IU",
    "Fake interface will intermittently drop packets on Tx path");

/* sysctl net.link.fake.tx_completion_mode */
typedef enum {
	IFF_TX_COMPL_MODE_SYNC = 0,
	IFF_TX_COMPL_MODE_ASYNC = 1,
} iff_tx_completion_mode_t;
static iff_tx_completion_mode_t if_tx_completion_mode = IFF_TX_COMPL_MODE_SYNC;
static int
feth_fake_tx_completion_mode_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_tx_completion_mode,
	    sizeof(if_tx_completion_mode), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > IFF_TX_COMPL_MODE_ASYNC ||
		    new_value < IFF_TX_COMPL_MODE_SYNC) {
			return EINVAL;
		}
		if_tx_completion_mode = new_value;
	}
	return 0;
}
SYSCTL_PROC(_net_link_fake, OID_AUTO, tx_completion_mode,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_fake_tx_completion_mode_sysctl, "IU",
    "Fake interface tx completion mode (0 synchronous, 1 asynchronous)");

/* sysctl net.link.fake.llink_cnt */

/* The maximum number of logical links (including default link) */
#define FETH_MAX_LLINKS 16
/*
 * The default number of logical links (including default link).
 * Zero means logical link mode is disabled.
 */
#define FETH_DEF_LLINKS 0

static uint32_t if_fake_llink_cnt = FETH_DEF_LLINKS;
static int
feth_fake_llink_cnt_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_llink_cnt,
	    sizeof(if_fake_llink_cnt), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value > FETH_MAX_LLINKS) {
			return EINVAL;
		}
		if_fake_llink_cnt = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, llink_cnt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_fake_llink_cnt_sysctl, "IU",
    "Fake interface logical link count");

/* sysctl net.link.fake.qset_cnt */

/* The maximum number of qsets for each logical link */
#define FETH_MAX_QSETS  16
/* The default number of qsets for each logical link */
#define FETH_DEF_QSETS  4

static uint32_t if_fake_qset_cnt = FETH_DEF_QSETS;
static int
feth_fake_qset_cnt_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_fake_qset_cnt,
	    sizeof(if_fake_qset_cnt), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value == 0 ||
		    new_value > FETH_MAX_QSETS) {
			return EINVAL;
		}
		if_fake_qset_cnt = new_value;
	}
	return 0;
}

SYSCTL_PROC(_net_link_fake, OID_AUTO, qset_cnt,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
    feth_fake_qset_cnt_sysctl, "IU",
    "Fake interface queue set count");

/**
** virtual ethernet structures, types
**/

#define IFF_NUM_TX_RINGS_WMM_MODE       4
#define IFF_NUM_RX_RINGS_WMM_MODE       1
#define IFF_MAX_TX_RINGS        IFF_NUM_TX_RINGS_WMM_MODE
#define IFF_MAX_RX_RINGS        IFF_NUM_RX_RINGS_WMM_MODE
#define IFF_NUM_TX_QUEUES_WMM_MODE      4
#define IFF_NUM_RX_QUEUES_WMM_MODE      1
#define IFF_MAX_TX_QUEUES       IFF_NUM_TX_QUEUES_WMM_MODE
#define IFF_MAX_RX_QUEUES       IFF_NUM_RX_QUEUES_WMM_MODE

#define IFF_MAX_BATCH_SIZE 32

typedef uint16_t        iff_flags_t;
#define IFF_FLAGS_HWCSUM                0x0001
#define IFF_FLAGS_BSD_MODE              0x0002
#define IFF_FLAGS_DETACHING             0x0004
#define IFF_FLAGS_WMM_MODE              0x0008
#define IFF_FLAGS_MULTIBUFLETS          0x0010
#define IFF_FLAGS_TSO_SUPPORT           0x0020

#if SKYWALK

typedef struct {
	uuid_t                  fnx_provider;
	uuid_t                  fnx_instance;
} fake_nx, *fake_nx_t;

typedef struct {
	kern_netif_queue_t      fq_queue;
} fake_queue;

typedef struct {
	kern_netif_qset_t       fqs_qset; /* provided by xnu */
	fake_queue              fqs_rx_queue[IFF_MAX_RX_QUEUES];
	fake_queue              fqs_tx_queue[IFF_MAX_TX_QUEUES];
	uint32_t                fqs_rx_queue_cnt;
	uint32_t                fqs_tx_queue_cnt;
	uint32_t                fqs_llink_idx;
	uint32_t                fqs_idx;
	uint32_t                fqs_dequeue_cnt;
	uint64_t                fqs_id;
	boolean_t               fqs_combined_mode;
} fake_qset;

typedef struct {
	uint64_t                fl_id;
	uint32_t                fl_idx;
	uint32_t                fl_qset_cnt;
	fake_qset               fl_qset[FETH_MAX_QSETS];
} fake_llink;

static kern_pbufpool_t         S_pp;

#define IFF_TT_OUTPUT   0x01 /* generate trace_tag on output */
#define IFF_TT_INPUT    0x02 /* generate trace_tag on input */
static int if_fake_trace_tag_flags = 0;
SYSCTL_INT(_net_link_fake, OID_AUTO, trace_tag, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_fake_trace_tag_flags, 0, "Fake interface generate trace_tag");
static packet_trace_tag_t if_fake_trace_tag_current = 1;

#endif /* SKYWALK */

struct if_fake {
	char                    iff_name[IFNAMSIZ]; /* our unique id */
	ifnet_t                 iff_ifp;
	iff_flags_t             iff_flags;
	uint32_t                iff_retain_count;
	ifnet_t                 iff_peer;       /* the other end */
	int                     iff_media_current;
	int                     iff_media_active;
	uint32_t                iff_media_count;
	int                     iff_media_list[IF_FAKE_MEDIA_LIST_MAX];
	struct mbuf *           iff_pending_tx_packet;
	boolean_t               iff_start_busy;
	unsigned int            iff_max_mtu;
	uint32_t                iff_fcs;
	uint32_t                iff_trailer_length;
#if SKYWALK
	fake_nx                 iff_nx;
	struct netif_stats      *iff_nifs;
	uint32_t                iff_nifs_ref;
	uint32_t                iff_llink_cnt;
	kern_channel_ring_t     iff_rx_ring[IFF_MAX_RX_RINGS];
	kern_channel_ring_t     iff_tx_ring[IFF_MAX_TX_RINGS];
	fake_llink             *iff_llink __counted_by(FETH_MAX_LLINKS);
	thread_call_t           iff_doorbell_tcall;
	thread_call_t           iff_if_adv_tcall;
	boolean_t               iff_doorbell_tcall_active;
	boolean_t               iff_waiting_for_tcall;
	boolean_t               iff_channel_connected;
	iff_pktpool_mode_t      iff_pp_mode;
	kern_pbufpool_t         iff_rx_pp;
	kern_pbufpool_t         iff_tx_pp;
	uint32_t                iff_tx_headroom;
	unsigned int            iff_adv_interval;
	uint32_t                iff_tx_drop_rate;
	uint32_t                iff_tx_pkts_count;
	iff_tx_completion_mode_t iff_tx_completion_mode;
	bool                    iff_intf_adv_enabled;
	void                    *iff_intf_adv_kern_ctx;
	kern_nexus_capab_interface_advisory_notify_fn_t iff_intf_adv_notify;
#endif /* SKYWALK */
};

typedef struct if_fake * if_fake_ref;

static if_fake_ref
ifnet_get_if_fake(ifnet_t ifp);

#define FETH_DPRINTF(fmt, ...)                                  \
	{ if (if_fake_debug != 0) printf("%s " fmt, __func__, ## __VA_ARGS__); }

static inline boolean_t
feth_in_bsd_mode(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_BSD_MODE) != 0;
}

static inline void
feth_set_detaching(if_fake_ref fakeif)
{
	fakeif->iff_flags |= IFF_FLAGS_DETACHING;
}

static inline boolean_t
feth_is_detaching(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_DETACHING) != 0;
}

static int
feth_enable_dequeue_stall(ifnet_t ifp, uint32_t enable)
{
	int error;

	if (enable != 0) {
		error = ifnet_disable_output(ifp);
	} else {
		error = ifnet_enable_output(ifp);
	}

	return error;
}

#if SKYWALK
static inline boolean_t
feth_in_wmm_mode(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_WMM_MODE) != 0;
}

static inline boolean_t
feth_using_multibuflets(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_MULTIBUFLETS) != 0;
}
static void feth_detach_netif_nexus(if_fake_ref fakeif);

static inline boolean_t
feth_has_intf_advisory_configured(if_fake_ref fakeif)
{
	return fakeif->iff_adv_interval > 0;
}

static inline bool
feth_supports_tso(if_fake_ref fakeif)
{
	return (fakeif->iff_flags & IFF_FLAGS_TSO_SUPPORT) != 0;
}
#endif /* SKYWALK */

#define FETH_MAXUNIT    IF_MAXUNIT
#define FETH_ZONE_MAX_ELEM      MIN(IFNETS_MAX, FETH_MAXUNIT)

static  int feth_clone_create(struct if_clone *, u_int32_t, void *);
static  int feth_clone_destroy(ifnet_t);
static  int feth_output(ifnet_t ifp, struct mbuf *m);
static  void feth_start(ifnet_t ifp);
static  int feth_ioctl(ifnet_t ifp, u_long cmd, void * addr);
static  int feth_config(ifnet_t ifp, ifnet_t peer);
static  void feth_if_free(ifnet_t ifp);
static  void feth_ifnet_set_attrs(if_fake_ref fakeif, ifnet_t ifp);
static  void feth_free(if_fake_ref fakeif);

static struct if_clone
    feth_cloner = IF_CLONE_INITIALIZER(FAKE_ETHER_NAME,
    feth_clone_create,
    feth_clone_destroy,
    0,
    FETH_MAXUNIT);
static  void interface_link_event(ifnet_t ifp, u_int32_t event_code);

/* some media words to pretend to be ethernet */
static int default_media_words[] = {
	IFM_MAKEWORD(IFM_ETHER, 0, 0, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_10G_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_2500_T, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_5000_T, IFM_FDX, 0),

	IFM_MAKEWORD(IFM_ETHER, IFM_10G_KX4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_20G_KR2, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_2500_SX, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_25G_KR, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_40G_SR4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_50G_CR2, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_56G_R4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_100G_CR4, IFM_FDX, 0),
	IFM_MAKEWORD(IFM_ETHER, IFM_400G_AUI8, IFM_FDX, 0),
};
#define default_media_words_count (sizeof(default_media_words)          \
	                           / sizeof (default_media_words[0]))

/**
** veth locks
**/

static LCK_GRP_DECLARE(feth_lck_grp, "fake");
static LCK_MTX_DECLARE(feth_lck_mtx, &feth_lck_grp);

static inline void
feth_lock(void)
{
	lck_mtx_lock(&feth_lck_mtx);
}

static inline void
feth_unlock(void)
{
	lck_mtx_unlock(&feth_lck_mtx);
}

static inline int
get_max_mtu(int bsd_mode, unsigned int max_mtu)
{
	unsigned int    mtu;

	if (bsd_mode != 0) {
		mtu = (njcl > 0) ? (M16KCLBYTES - ETHER_HDR_LEN)
		    : MBIGCLBYTES - ETHER_HDR_LEN;
		if (mtu > max_mtu) {
			mtu = max_mtu;
		}
	} else {
		mtu = max_mtu;
	}
	return mtu;
}

static inline unsigned int
feth_max_mtu(ifnet_t ifp)
{
	if_fake_ref     fakeif;
	unsigned int    max_mtu = ETHERMTU;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		max_mtu = fakeif->iff_max_mtu;
	}
	feth_unlock();
	return max_mtu;
}

static void
feth_free(if_fake_ref fakeif)
{
	VERIFY(fakeif->iff_retain_count == 0);
	if (feth_in_bsd_mode(fakeif)) {
		if (fakeif->iff_pending_tx_packet) {
			m_freem(fakeif->iff_pending_tx_packet);
		}
	}
#if SKYWALK
	else {
		if (fakeif->iff_pp_mode == IFF_PP_MODE_GLOBAL) {
			VERIFY(fakeif->iff_rx_pp == S_pp);
			VERIFY(fakeif->iff_tx_pp == S_pp);
			pp_release(fakeif->iff_rx_pp);
			fakeif->iff_rx_pp = NULL;
			pp_release(fakeif->iff_tx_pp);
			fakeif->iff_tx_pp = NULL;
			feth_lock();
			if (S_pp->pp_refcnt == 1) {
				pp_release(S_pp);
				S_pp = NULL;
			}
			feth_unlock();
		} else {
			if (fakeif->iff_rx_pp != NULL) {
				pp_release(fakeif->iff_rx_pp);
				fakeif->iff_rx_pp = NULL;
			}
			if (fakeif->iff_tx_pp != NULL) {
				pp_release(fakeif->iff_tx_pp);
				fakeif->iff_tx_pp = NULL;
			}
		}
	}
#endif /* SKYWALK */

	FETH_DPRINTF("%s\n", fakeif->iff_name);
	kfree_type(fake_llink, FETH_MAX_LLINKS, fakeif->iff_llink);
	kfree_type(struct if_fake, fakeif);
}

static void
feth_release(if_fake_ref fakeif)
{
	u_int32_t               old_retain_count;

	old_retain_count = OSDecrementAtomic(&fakeif->iff_retain_count);
	switch (old_retain_count) {
	case 0:
		VERIFY(old_retain_count != 0);
		break;
	case 1:
		feth_free(fakeif);
		break;
	default:
		break;
	}
	return;
}

#if SKYWALK

static void
feth_retain(if_fake_ref fakeif)
{
	OSIncrementAtomic(&fakeif->iff_retain_count);
}

static void
feth_packet_pool_init_prepare(if_fake_ref fakeif,
    struct kern_pbufpool_init *pp_init)
{
	uint32_t max_mtu = fakeif->iff_max_mtu;
	uint32_t buflet_size = if_fake_buflet_size;

	bzero(pp_init, sizeof(*pp_init));
	pp_init->kbi_version = KERN_PBUFPOOL_CURRENT_VERSION;
	pp_init->kbi_flags |= KBIF_VIRTUAL_DEVICE;
	pp_init->kbi_packets = 1024; /* TBD configurable */
	if (feth_supports_tso(fakeif)) {
		buflet_size = if_fake_tso_buffer_size;
	}
	if (feth_using_multibuflets(fakeif)) {
		pp_init->kbi_bufsize = buflet_size;
		pp_init->kbi_max_frags = howmany(max_mtu, buflet_size);
		pp_init->kbi_buflets = pp_init->kbi_packets *
		    pp_init->kbi_max_frags;
		pp_init->kbi_flags |= KBIF_BUFFER_ON_DEMAND;
	} else {
		pp_init->kbi_bufsize = max(max_mtu, buflet_size);
		pp_init->kbi_max_frags = 1;
		pp_init->kbi_buflets = pp_init->kbi_packets;
	}
	pp_init->kbi_buf_seg_size = skmem_usr_buf_seg_size;
	if (if_fake_user_access != 0) {
		pp_init->kbi_flags |= KBIF_USER_ACCESS;
	}
	pp_init->kbi_ctx = NULL;
	pp_init->kbi_ctx_retain = NULL;
	pp_init->kbi_ctx_release = NULL;
}

static errno_t
feth_packet_pool_make(if_fake_ref fakeif)
{
	struct kern_pbufpool_init pp_init;
	errno_t err;

	feth_packet_pool_init_prepare(fakeif, &pp_init);

	switch (fakeif->iff_pp_mode) {
	case IFF_PP_MODE_GLOBAL:
		feth_lock();
		if (S_pp == NULL) {
			(void)snprintf((char *)pp_init.kbi_name,
			    sizeof(pp_init.kbi_name), "%s", "feth shared pp");
			err = kern_pbufpool_create(&pp_init, &S_pp, NULL);
		}
		pp_retain(S_pp);
		feth_unlock();
		fakeif->iff_rx_pp = S_pp;
		pp_retain(S_pp);
		fakeif->iff_tx_pp = S_pp;
		break;
	case IFF_PP_MODE_PRIVATE:
		(void)snprintf((char *)pp_init.kbi_name,
		    sizeof(pp_init.kbi_name), "%s pp", fakeif->iff_name);
		err = kern_pbufpool_create(&pp_init, &fakeif->iff_rx_pp, NULL);
		pp_retain(fakeif->iff_rx_pp);
		fakeif->iff_tx_pp = fakeif->iff_rx_pp;
		break;
	case IFF_PP_MODE_PRIVATE_SPLIT:
		(void)snprintf((char *)pp_init.kbi_name,
		    sizeof(pp_init.kbi_name), "%s rx pp", fakeif->iff_name);
		pp_init.kbi_flags &= ~(KBIF_IODIR_IN | KBIF_IODIR_OUT |
		    KBIF_BUFFER_ON_DEMAND | KBIF_KERNEL_READONLY);
		pp_init.kbi_flags |= (KBIF_IODIR_IN | KBIF_BUFFER_ON_DEMAND);
		pp_init.kbi_packets = 1024;
		pp_init.kbi_bufsize = if_fake_link_layer_aggregation_factor * 1024;
		err = kern_pbufpool_create(&pp_init, &fakeif->iff_rx_pp, NULL);
		if (err != 0) {
			printf("%s: rx pp create failed %d\n", __func__, err);
			return err;
		}
		pp_init.kbi_flags &= ~(KBIF_IODIR_IN | KBIF_IODIR_OUT |
		    KBIF_BUFFER_ON_DEMAND | KBIF_KERNEL_READONLY);
		pp_init.kbi_flags |= KBIF_IODIR_OUT;
		pp_init.kbi_packets = 1024;            /* TBD configurable */
		pp_init.kbi_bufsize = fakeif->iff_max_mtu;
		(void)snprintf((char *)pp_init.kbi_name,
		    sizeof(pp_init.kbi_name), "%s tx pp", fakeif->iff_name);
		err = kern_pbufpool_create(&pp_init, &fakeif->iff_tx_pp, NULL);
		if (err != 0) {
			printf("%s: tx pp create failed %d\n", __func__, err);
			pp_release(fakeif->iff_rx_pp);
			return err;
		}
		break;
	default:
		VERIFY(0);
		__builtin_unreachable();
	}

	return 0;
}

static void
feth_packet_set_trace_tag(kern_packet_t ph, int flag)
{
	if (if_fake_trace_tag_flags & flag) {
		if (++if_fake_trace_tag_current == 0) {
			if_fake_trace_tag_current = 1;
		}
		kern_packet_set_trace_tag(ph, if_fake_trace_tag_current);
	}
}

static errno_t
feth_clone_packet(if_fake_ref dif, kern_packet_t sph, kern_packet_t *pdph)
{
	errno_t err = 0;
	kern_pbufpool_t pp = dif->iff_rx_pp;
	kern_packet_t dph = 0, dph0 = 0;
	kern_buflet_t sbuf, dbuf0 = NULL, dbuf;
	void *saddr, *daddr;
	uint32_t soff, doff;
	uint32_t slen, dlen;
	uint32_t dlim0, dlim;

	sbuf = kern_packet_get_next_buflet(sph, NULL);
	saddr = kern_buflet_get_data_address(sbuf);
	doff = soff = kern_buflet_get_data_offset(sbuf);
	dlen = slen = kern_buflet_get_data_length(sbuf);

	/* packet clone is only supported for single-buflet */
	ASSERT(kern_packet_get_buflet_count(sph) == 1);
	ASSERT(soff == kern_packet_get_headroom(sph));
	ASSERT(slen == kern_packet_get_data_length(sph));

	dph0 = *pdph;
	if (dph0 == 0) {
		dlim0 = 0;
	} else {
		dbuf0 = kern_packet_get_next_buflet(dph0, NULL);
		ASSERT(kern_buflet_get_object_limit(dbuf0) ==
		    PP_BUF_OBJ_SIZE_DEF(pp));
		ASSERT(kern_buflet_get_data_limit(dbuf0) % 16 == 0);
		dlim0 = ((uintptr_t)kern_buflet_get_object_address(dbuf0) +
		    kern_buflet_get_object_limit(dbuf0)) -
		    ((uintptr_t)kern_buflet_get_data_address(dbuf0) +
		    kern_buflet_get_data_limit(dbuf0));
	}

	if (doff + dlen > dlim0) {
		err = kern_pbufpool_alloc_nosleep(pp, 1, &dph);
		if (err != 0) {
			STATS_INC(dif->iff_nifs, NETIF_STATS_DROP);
			STATS_INC(dif->iff_nifs, NETIF_STATS_DROP_NOMEM_PKT);
			return err;
		}
		dbuf = kern_packet_get_next_buflet(dph, NULL);
		ASSERT(kern_buflet_get_data_address(dbuf) ==
		    kern_buflet_get_object_address(dbuf));
		daddr = kern_buflet_get_data_address(dbuf);
		dlim = kern_buflet_get_object_limit(dbuf);
		ASSERT(dlim == PP_BUF_OBJ_SIZE_DEF(pp));
	} else {
		err = kern_packet_clone_nosleep(dph0, &dph, KPKT_COPY_LIGHT);
		if (err != 0) {
			printf("%s: packet clone err %d\n", __func__, err);
			return err;
		}
		dbuf = kern_packet_get_next_buflet(dph, NULL);
		ASSERT(kern_buflet_get_object_address(dbuf) ==
		    kern_buflet_get_object_address(dbuf0));
		daddr = (void *)((uintptr_t)kern_buflet_get_data_address(dbuf0) +
		    kern_buflet_get_data_limit(dbuf0));
		dlim = dlim0;
	}

	ASSERT(doff + dlen <= dlim);

	ASSERT((uintptr_t)daddr % 16 == 0);

	bcopy((const void *)((uintptr_t)saddr + soff),
	    (void *)((uintptr_t)daddr + doff), slen);

	dlim = MIN(dlim, P2ROUNDUP(doff + dlen, 16));
	err = kern_buflet_set_data_address(dbuf, daddr);
	VERIFY(err == 0);
	err = kern_buflet_set_data_limit(dbuf, dlim);
	VERIFY(err == 0);
	err = kern_buflet_set_data_length(dbuf, dlen);
	VERIFY(err == 0);
	err = kern_buflet_set_data_offset(dbuf, doff);
	VERIFY(err == 0);
	err = kern_packet_set_headroom(dph, doff);
	VERIFY(err == 0);
	err = kern_packet_set_link_header_length(dph,
	    kern_packet_get_link_header_length(sph));
	VERIFY(err == 0);
	err = kern_packet_set_service_class(dph,
	    kern_packet_get_service_class(sph));
	VERIFY(err == 0);
	err = kern_packet_finalize(dph);
	VERIFY(err == 0);
	*pdph = dph;

	return err;
}

static inline void
feth_copy_buflet(kern_buflet_t sbuf, kern_buflet_t dbuf)
{
	errno_t err;
	uint16_t off, len;
	uint8_t *saddr, *daddr;

	saddr = kern_buflet_get_data_address(sbuf);
	off = kern_buflet_get_data_offset(sbuf);
	len = kern_buflet_get_data_length(sbuf);
	daddr = kern_buflet_get_data_address(dbuf);
	bcopy((saddr + off), (daddr + off), len);
	err = kern_buflet_set_data_offset(dbuf, off);
	VERIFY(err == 0);
	err = kern_buflet_set_data_length(dbuf, len);
	VERIFY(err == 0);
}

static int
feth_add_packet_trailer(kern_packet_t ph, void *trailer, size_t trailer_len)
{
	errno_t err = 0;

	ASSERT(trailer_len <= FETH_TRAILER_LENGTH_MAX);

	kern_buflet_t buf = NULL, iter = NULL;
	while ((iter = kern_packet_get_next_buflet(ph, iter)) != NULL) {
		buf = iter;
	}
	ASSERT(buf != NULL);

	uint16_t dlim = kern_buflet_get_data_limit(buf);
	uint16_t doff = kern_buflet_get_data_offset(buf);
	uint16_t dlen = kern_buflet_get_data_length(buf);

	size_t trailer_room = dlim - doff - dlen;

	if (trailer_room < trailer_len) {
		printf("not enough room");
		return ERANGE;
	}

	void *data = (void *)((uintptr_t)kern_buflet_get_data_address(buf) + doff + dlen);
	memcpy(data, trailer, trailer_len);

	err = kern_buflet_set_data_length(buf, dlen + trailer_len);
	VERIFY(err == 0);

	err = kern_packet_finalize(ph);
	VERIFY(err == 0);

	FETH_DPRINTF("%s %zuB trailer added\n", __func__, trailer_len);

	return 0;
}

static int
feth_add_packet_fcs(kern_packet_t ph)
{
	uint32_t crc = 0;
	int err;

	ASSERT(sizeof(crc) == ETHER_CRC_LEN);

	kern_buflet_t buf = NULL;
	while ((buf = kern_packet_get_next_buflet(ph, buf)) != NULL) {
		uint16_t doff = kern_buflet_get_data_offset(buf);
		uint16_t dlen = kern_buflet_get_data_length(buf);
		void *data = (void *)((uintptr_t)kern_buflet_get_data_address(buf) + doff);
		crc = crc32(crc, data, dlen);
	}

	err = feth_add_packet_trailer(ph, &crc, ETHER_CRC_LEN);
	if (!err) {
		return err;
	}

	err = kern_packet_set_link_ethfcs(ph);
	VERIFY(err == 0);

	return 0;
}

static errno_t
feth_copy_packet(if_fake_ref dif, kern_packet_t sph, kern_packet_t *pdph)
{
	errno_t err = 0;
	uint16_t i, bufcnt;
	mach_vm_address_t baddr;
	kern_buflet_t sbuf = NULL, dbuf = NULL;
	kern_pbufpool_t pp = dif->iff_rx_pp;
	kern_packet_t dph;
	boolean_t multi_buflet = feth_using_multibuflets(dif);

	bufcnt = kern_packet_get_buflet_count(sph);
	ASSERT((bufcnt == 1) || multi_buflet);
	*pdph = 0;

	err = kern_pbufpool_alloc_nosleep(pp, 1, &dph);
	if (err != 0) {
		STATS_INC(dif->iff_nifs, NETIF_STATS_DROP);
		STATS_INC(dif->iff_nifs, NETIF_STATS_DROP_NOMEM_PKT);
		return err;
	}

	/* pre-constructed single buflet packet copy */
	sbuf = kern_packet_get_next_buflet(sph, NULL);
	dbuf = kern_packet_get_next_buflet(dph, NULL);
	feth_copy_buflet(sbuf, dbuf);

	if (!multi_buflet) {
		goto done;
	}

	/* un-constructed multi-buflet packet copy */
	for (i = 1; i < bufcnt; i++) {
		kern_buflet_t dbuf_next = NULL;

		sbuf = kern_packet_get_next_buflet(sph, sbuf);
		VERIFY(sbuf != NULL);
		err = kern_pbufpool_alloc_buflet_nosleep(pp, &dbuf_next, true);
		if (err != 0) {
			STATS_INC(dif->iff_nifs, NETIF_STATS_DROP);
			STATS_INC(dif->iff_nifs, NETIF_STATS_DROP_NOMEM_BUF);
			break;
		}
		ASSERT(dbuf_next != NULL);
		feth_copy_buflet(sbuf, dbuf_next);
		err = kern_packet_add_buflet(dph, dbuf, dbuf_next);
		VERIFY(err == 0);
		dbuf = dbuf_next;
	}
	if (__improbable(err != 0)) {
		dbuf = NULL;
		while (i-- != 0) {
			dbuf = kern_packet_get_next_buflet(dph, dbuf);
			VERIFY(dbuf != NULL);
			baddr = (mach_vm_address_t)
			    kern_buflet_get_data_address(dbuf);
			VERIFY(baddr != 0);
		}
		kern_pbufpool_free(pp, dph);
		dph = 0;
	}

done:
	if (__probable(err == 0)) {
		err = kern_packet_set_headroom(dph,
		    kern_packet_get_headroom(sph));
		VERIFY(err == 0);
		err = kern_packet_set_link_header_length(dph,
		    kern_packet_get_link_header_length(sph));
		VERIFY(err == 0);
		err = kern_packet_set_service_class(dph,
		    kern_packet_get_service_class(sph));
		VERIFY(err == 0);
		err = kern_packet_finalize(dph);
		VERIFY(err == 0);
		VERIFY(bufcnt == kern_packet_get_buflet_count(dph));
		*pdph = dph;
	}
	return err;
}

static inline void
feth_update_pkt_tso_metadata_for_rx(kern_packet_t ph)
{
	/*
	 * Nothing to do if not a TSO offloaded packet.
	 */
	uint16_t seg_sz = 0;
	(void) kern_packet_get_protocol_segment_size(ph, &seg_sz);
	if (seg_sz == 0) {
		return;
	}
	/*
	 * For RX, make the packet appear as a fully validated LRO packet.
	 */
	packet_csum_flags_t csum_flags = PACKET_CSUM_IP_CHECKED |
	    PACKET_CSUM_IP_VALID | PACKET_CSUM_DATA_VALID |
	    PACKET_CSUM_PSEUDO_HDR;
	(void) kern_packet_set_inet_checksum(ph, csum_flags, 0, 0xFFFF, FALSE);
	return;
}

static void
feth_rx_submit(if_fake_ref sif, if_fake_ref dif, kern_packet_t sphs[],
    uint32_t n_pkts)
{
	errno_t err = 0;
	struct kern_channel_ring_stat_increment stats;
	kern_channel_ring_t rx_ring = NULL;
	kern_channel_slot_t rx_slot = NULL, last_rx_slot = NULL;
	kern_packet_t sph = 0, dph = 0;

	memset(&stats, 0, sizeof(stats));

	rx_ring = dif->iff_rx_ring[0];
	if (rx_ring == NULL) {
		return;
	}

	kr_enter(rx_ring, TRUE);
	kern_channel_reclaim(rx_ring);
	rx_slot = kern_channel_get_next_slot(rx_ring, NULL, NULL);

	for (uint32_t i = 0; i < n_pkts && rx_slot != NULL; i++) {
		sph = sphs[i];

		switch (dif->iff_pp_mode) {
		case IFF_PP_MODE_GLOBAL:
			sphs[i] = 0;
			dph = sph;
			feth_update_pkt_tso_metadata_for_rx(dph);
			err = kern_packet_finalize(dph);
			VERIFY(err == 0);
			break;
		case IFF_PP_MODE_PRIVATE:
			err = feth_copy_packet(dif, sph, &dph);
			break;
		case IFF_PP_MODE_PRIVATE_SPLIT:
			err = feth_clone_packet(dif, sph, &dph);
			break;
		default:
			VERIFY(0);
			__builtin_unreachable();
		}
		if (__improbable(err != 0)) {
			continue;
		}

		if (sif->iff_trailer_length != 0) {
			feth_add_packet_trailer(dph, feth_trailer,
			    sif->iff_trailer_length);
		}
		if (sif->iff_fcs != 0) {
			feth_add_packet_fcs(dph);
		}
		feth_packet_set_trace_tag(dph, IFF_TT_INPUT);
		bpf_tap_packet_in(dif->iff_ifp, DLT_EN10MB, dph, NULL, 0);
		stats.kcrsi_slots_transferred++;
		stats.kcrsi_bytes_transferred
		        += kern_packet_get_data_length(dph);

		/* attach the packet to the RX ring */
		err = kern_channel_slot_attach_packet(rx_ring, rx_slot, dph);
		VERIFY(err == 0);
		last_rx_slot = rx_slot;
		rx_slot = kern_channel_get_next_slot(rx_ring, rx_slot, NULL);
	}

	if (last_rx_slot != NULL) {
		kern_channel_advance_slot(rx_ring, last_rx_slot);
		kern_channel_increment_ring_net_stats(rx_ring, dif->iff_ifp,
		    &stats);
	}

	if (rx_ring != NULL) {
		kr_exit(rx_ring);
		kern_channel_notify(rx_ring, 0);
	}
}

static void
feth_rx_queue_submit(if_fake_ref sif, if_fake_ref dif, uint32_t llink_idx,
    uint32_t qset_idx, kern_packet_t sphs[], uint32_t n_pkts)
{
	errno_t err = 0;
	kern_netif_queue_t queue;
	kern_packet_t sph = 0, dph = 0;
	fake_llink *llink;
	fake_qset *qset;

	if (llink_idx >= dif->iff_llink_cnt) {
		printf("%s: invalid llink_idx idx %d (max %d) on peer %s\n",
		    __func__, llink_idx, dif->iff_llink_cnt, dif->iff_name);
		return;
	}
	llink = &dif->iff_llink[llink_idx];
	if (qset_idx >= llink->fl_qset_cnt) {
		printf("%s: invalid qset_idx %d (max %d) on peer %s\n",
		    __func__, qset_idx, llink->fl_qset_cnt, dif->iff_name);
		return;
	}
	qset = &dif->iff_llink[llink_idx].fl_qset[qset_idx];
	queue = qset->fqs_rx_queue[0].fq_queue;
	if (queue == NULL) {
		printf("%s: NULL default queue (llink_idx %d, qset_idx %d) "
		    "on peer %s\n", __func__, llink_idx, qset_idx,
		    dif->iff_name);
		return;
	}
	for (uint32_t i = 0; i < n_pkts; i++) {
		uint32_t flags;

		sph = sphs[i];

		switch (dif->iff_pp_mode) {
		case IFF_PP_MODE_GLOBAL:
			sphs[i] = 0;
			dph = sph;
			feth_update_pkt_tso_metadata_for_rx(dph);
			break;
		case IFF_PP_MODE_PRIVATE:
			err = feth_copy_packet(dif, sph, &dph);
			break;
		case IFF_PP_MODE_PRIVATE_SPLIT:
			err = feth_clone_packet(dif, sph, &dph);
			break;
		default:
			VERIFY(0);
			__builtin_unreachable();
		}
		if (__improbable(err != 0)) {
			continue;
		}

		if (sif->iff_trailer_length != 0) {
			feth_add_packet_trailer(dph, feth_trailer,
			    sif->iff_trailer_length);
		}
		if (sif->iff_fcs != 0) {
			feth_add_packet_fcs(dph);
		}
		feth_packet_set_trace_tag(dph, IFF_TT_INPUT);
		bpf_tap_packet_in(dif->iff_ifp, DLT_EN10MB, dph, NULL, 0);

		flags = (i == n_pkts - 1) ?
		    KERN_NETIF_QUEUE_RX_ENQUEUE_FLAG_FLUSH : 0;
		kern_netif_queue_rx_enqueue(queue, dph, 1, flags);
	}
}

static void
feth_tx_complete(if_fake_ref fakeif, kern_packet_t phs[], uint32_t nphs)
{
	for (uint32_t i = 0; i < nphs; i++) {
		kern_packet_t ph = phs[i];
		if (ph == 0) {
			continue;
		}
		int err = kern_packet_set_tx_completion_status(ph, 0);
		VERIFY(err == 0);
		kern_packet_tx_completion(ph, fakeif->iff_ifp);
		kern_pbufpool_free(fakeif->iff_tx_pp, phs[i]);
		phs[i] = 0;
	}
}

/* returns true if the packet is selected for TX error & dropped */
static bool
feth_tx_complete_error(if_fake_ref fakeif, kern_packet_t *ph,
    struct netif_stats *nifs)
{
	int err;

	if (fakeif->iff_tx_drop_rate == 0 ||
	    fakeif->iff_tx_pkts_count != fakeif->iff_tx_drop_rate) {
		return false;
	}
	/* simulate TX completion error on the packet */
	if (fakeif->iff_tx_completion_mode == IFF_TX_COMPL_MODE_SYNC) {
		err = kern_packet_set_tx_completion_status(*ph,
		    CHANNEL_EVENT_PKT_TRANSMIT_STATUS_ERR_RETRY_FAILED);
		VERIFY(err == 0);
		kern_packet_tx_completion(*ph, fakeif->iff_ifp);
	} else {
		uint32_t nx_port_id = 0;
		os_channel_event_packet_transmit_status_t pkt_tx_status = {0};

		pkt_tx_status.packet_status =
		    CHANNEL_EVENT_PKT_TRANSMIT_STATUS_ERR_RETRY_FAILED;
		do {
			err = kern_packet_get_packetid(*ph,
			    &pkt_tx_status.packet_id);
			if (err != 0) {
				break;
			}
			err = kern_packet_get_tx_nexus_port_id(*ph,
			    &nx_port_id);
			if (err != 0) {
				break;
			}
			err = kern_channel_event_transmit_status(
				fakeif->iff_ifp, &pkt_tx_status, nx_port_id);
		} while (0);
		if (err != 0) {
			FETH_DPRINTF("err %d, nx_port_id: 0x%x\n",
			    err, nx_port_id);
		}
	}
	fakeif->iff_tx_pkts_count = 0;
	kern_pbufpool_free(fakeif->iff_tx_pp, *ph);
	*ph = 0;
	STATS_INC(nifs, NETIF_STATS_DROP);
	return true;
}

static void
feth_if_adv(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	errno_t                            error;
	if_fake_ref                        fakeif = (if_fake_ref)arg0;
	struct ifnet_interface_advisory    if_adv;
	struct ifnet_stats_param           if_stat;

	feth_lock();
	if (feth_is_detaching(fakeif) || !fakeif->iff_channel_connected) {
		feth_unlock();
		return;
	}
	feth_unlock();

	if (!fakeif->iff_intf_adv_enabled) {
		goto done;
	}

	error = ifnet_stat(fakeif->iff_ifp, &if_stat);
	if (error != 0) {
		FETH_DPRINTF("%s: ifnet_stat() failed %d\n",
		    fakeif->iff_name, error);
		goto done;
	}
	if_adv.header.version = IF_INTERFACE_ADVISORY_VERSION_CURRENT;
	if_adv.header.direction = IF_INTERFACE_ADVISORY_DIRECTION_TX;
	if_adv.header.interface_type =
	    IF_INTERFACE_ADVISORY_INTERFACE_TYPE_WIFI;
	if_adv.capacity.timestamp = mach_absolute_time();
	if_adv.capacity.rate_trend_suggestion =
	    IF_INTERFACE_ADVISORY_RATE_SUGGESTION_RAMP_NEUTRAL;
	if_adv.capacity.max_bandwidth = 1000 * 1000 * 1000; /* 1Gbps */
	if_adv.capacity.total_byte_count = if_stat.packets_out;
	if_adv.capacity.average_throughput = 1000 * 1000 * 1000; /* 1Gbps */
	if_adv.capacity.flushable_queue_size = UINT32_MAX;
	if_adv.capacity.non_flushable_queue_size = UINT32_MAX;
	if_adv.capacity.average_delay = 1; /* ms */

	error = fakeif->iff_intf_adv_notify(fakeif->iff_intf_adv_kern_ctx,
	    &if_adv);
	if (error != 0) {
		FETH_DPRINTF("%s: interface advisory report failed %d\n",
		    fakeif->iff_name, error);
	}

done:
	feth_lock();
	if (!feth_is_detaching(fakeif) && fakeif->iff_channel_connected) {
		uint64_t deadline;
		clock_interval_to_deadline(fakeif->iff_adv_interval,
		    NSEC_PER_MSEC, &deadline);
		thread_call_enter_delayed(fakeif->iff_if_adv_tcall, deadline);
	}
	feth_unlock();
}

static int
feth_if_adv_tcall_create(if_fake_ref fakeif)
{
	uint64_t deadline;

	feth_lock();
	ASSERT(fakeif->iff_if_adv_tcall == NULL);
	ASSERT(fakeif->iff_adv_interval > 0);
	ASSERT(fakeif->iff_channel_connected);
	fakeif->iff_if_adv_tcall =
	    thread_call_allocate_with_options(feth_if_adv,
	    (thread_call_param_t)fakeif, THREAD_CALL_PRIORITY_KERNEL,
	    THREAD_CALL_OPTIONS_ONCE);
	if (fakeif->iff_if_adv_tcall == NULL) {
		printf("%s: %s if_adv tcall alloc failed\n", __func__,
		    fakeif->iff_name);
		return ENXIO;
	}
	/* retain for the interface advisory thread call */
	feth_retain(fakeif);
	clock_interval_to_deadline(fakeif->iff_adv_interval,
	    NSEC_PER_MSEC, &deadline);
	thread_call_enter_delayed(fakeif->iff_if_adv_tcall, deadline);
	feth_unlock();
	return 0;
}

static void
feth_if_adv_tcall_destroy(if_fake_ref fakeif)
{
	thread_call_t tcall;

	feth_lock();
	ASSERT(fakeif->iff_if_adv_tcall != NULL);
	tcall = fakeif->iff_if_adv_tcall;
	feth_unlock();
	(void) thread_call_cancel_wait(tcall);
	if (!thread_call_free(tcall)) {
		boolean_t freed;
		(void) thread_call_cancel_wait(tcall);
		freed = thread_call_free(tcall);
		VERIFY(freed);
	}
	feth_lock();
	fakeif->iff_if_adv_tcall = NULL;
	feth_unlock();
	/* release for the interface advisory thread call */
	feth_release(fakeif);
}


/**
** nexus netif domain provider
**/
static errno_t
feth_nxdp_init(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
	return 0;
}

static void
feth_nxdp_fini(kern_nexus_domain_provider_t domprov)
{
#pragma unused(domprov)
}

static uuid_t                   feth_nx_dom_prov;

static errno_t
feth_register_nexus_domain_provider(void)
{
	const struct kern_nexus_domain_provider_init dp_init = {
		.nxdpi_version = KERN_NEXUS_DOMAIN_PROVIDER_CURRENT_VERSION,
		.nxdpi_flags = 0,
		.nxdpi_init = feth_nxdp_init,
		.nxdpi_fini = feth_nxdp_fini
	};
	errno_t                         err = 0;

	/* feth_nxdp_init() is called before this function returns */
	err = kern_nexus_register_domain_provider(NEXUS_TYPE_NET_IF,
	    (const uint8_t *)
	    "com.apple.feth",
	    &dp_init, sizeof(dp_init),
	    &feth_nx_dom_prov);
	if (err != 0) {
		printf("%s: failed to register domain provider\n", __func__);
		return err;
	}
	return 0;
}

/**
** netif nexus routines
**/
static if_fake_ref
feth_nexus_context(kern_nexus_t nexus)
{
	if_fake_ref fakeif;

	fakeif = (if_fake_ref)kern_nexus_get_context(nexus);
	assert(fakeif != NULL);
	return fakeif;
}

static uint8_t
feth_find_tx_ring_by_svc(kern_packet_svc_class_t svc_class)
{
	switch (svc_class) {
	case KPKT_SC_VO:
		return 0;
	case KPKT_SC_VI:
		return 1;
	case KPKT_SC_BE:
		return 2;
	case KPKT_SC_BK:
		return 3;
	default:
		VERIFY(0);
		return 0;
	}
}

static errno_t
feth_nx_ring_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_t channel, kern_channel_ring_t ring, boolean_t is_tx_ring,
    void **ring_ctx)
{
	if_fake_ref     fakeif;
	int             err;
#pragma unused(nxprov, channel, ring_ctx)
	feth_lock();
	fakeif = feth_nexus_context(nexus);
	if (feth_is_detaching(fakeif)) {
		feth_unlock();
		return 0;
	}
	if (is_tx_ring) {
		if (feth_in_wmm_mode(fakeif)) {
			kern_packet_svc_class_t svc_class;
			uint8_t ring_idx;

			err = kern_channel_get_service_class(ring, &svc_class);
			VERIFY(err == 0);
			ring_idx = feth_find_tx_ring_by_svc(svc_class);
			VERIFY(ring_idx < IFF_NUM_TX_RINGS_WMM_MODE);
			VERIFY(fakeif->iff_tx_ring[ring_idx] == NULL);
			fakeif->iff_tx_ring[ring_idx] = ring;
		} else {
			VERIFY(fakeif->iff_tx_ring[0] == NULL);
			fakeif->iff_tx_ring[0] = ring;
		}
	} else {
		VERIFY(fakeif->iff_rx_ring[0] == NULL);
		fakeif->iff_rx_ring[0] = ring;
	}
	fakeif->iff_nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	feth_unlock();
	FETH_DPRINTF("%s: %s ring init\n",
	    fakeif->iff_name, is_tx_ring ? "TX" : "RX");
	return 0;
}

static void
feth_nx_ring_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    kern_channel_ring_t ring)
{
#pragma unused(nxprov, ring)
	if_fake_ref     fakeif;
	thread_call_t   tcall = NULL;

	feth_lock();
	fakeif = feth_nexus_context(nexus);
	if (fakeif->iff_rx_ring[0] == ring) {
		fakeif->iff_rx_ring[0] = NULL;
		FETH_DPRINTF("%s: RX ring fini\n", fakeif->iff_name);
	} else if (feth_in_wmm_mode(fakeif)) {
		int i;
		for (i = 0; i < IFF_MAX_TX_RINGS; i++) {
			if (fakeif->iff_tx_ring[i] == ring) {
				fakeif->iff_tx_ring[i] = NULL;
				break;
			}
		}
		for (i = 0; i < IFF_MAX_TX_RINGS; i++) {
			if (fakeif->iff_tx_ring[i] != NULL) {
				break;
			}
		}
		if (i == IFF_MAX_TX_RINGS) {
			tcall = fakeif->iff_doorbell_tcall;
			fakeif->iff_doorbell_tcall = NULL;
		}
		FETH_DPRINTF("%s: TX ring fini\n", fakeif->iff_name);
	} else if (fakeif->iff_tx_ring[0] == ring) {
		tcall = fakeif->iff_doorbell_tcall;
		fakeif->iff_doorbell_tcall = NULL;
		fakeif->iff_tx_ring[0] = NULL;
	}
	fakeif->iff_nifs = NULL;
	feth_unlock();
	if (tcall != NULL) {
		boolean_t       success;

		success = thread_call_cancel_wait(tcall);
		FETH_DPRINTF("%s: thread_call_cancel %s\n",
		    fakeif->iff_name,
		    success ? "SUCCESS" : "FAILURE");
		if (!success) {
			feth_lock();
			if (fakeif->iff_doorbell_tcall_active) {
				fakeif->iff_waiting_for_tcall = TRUE;
				FETH_DPRINTF("%s: *waiting for threadcall\n",
				    fakeif->iff_name);
				do {
					msleep(fakeif, &feth_lck_mtx,
					    PZERO, "feth threadcall", 0);
				} while (fakeif->iff_doorbell_tcall_active);
				FETH_DPRINTF("%s: ^threadcall done\n",
				    fakeif->iff_name);
				fakeif->iff_waiting_for_tcall = FALSE;
			}
			feth_unlock();
		}
		success = thread_call_free(tcall);
		FETH_DPRINTF("%s: thread_call_free %s\n",
		    fakeif->iff_name,
		    success ? "SUCCESS" : "FAILURE");
		feth_release(fakeif);
		VERIFY(success == TRUE);
	}
}

static errno_t
feth_nx_pre_connect(kern_nexus_provider_t nxprov,
    proc_t proc, kern_nexus_t nexus, nexus_port_t port, kern_channel_t channel,
    void **channel_context)
{
#pragma unused(nxprov, proc, nexus, port, channel, channel_context)
	return 0;
}

static errno_t
feth_nx_connected(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	int err;
	if_fake_ref fakeif;

	fakeif = feth_nexus_context(nexus);
	feth_lock();
	if (feth_is_detaching(fakeif)) {
		feth_unlock();
		return EBUSY;
	}
	feth_retain(fakeif);
	fakeif->iff_channel_connected = TRUE;
	feth_unlock();
	if (feth_has_intf_advisory_configured(fakeif)) {
		err = feth_if_adv_tcall_create(fakeif);
		if (err != 0) {
			return err;
		}
	}
	FETH_DPRINTF("%s: connected channel %p\n",
	    fakeif->iff_name, channel);
	return 0;
}

static void
feth_nx_pre_disconnect(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_fake_ref fakeif;

	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s: pre-disconnect channel %p\n",
	    fakeif->iff_name, channel);
	/* Quiesce the interface and flush any pending outbound packets. */
	if_down(fakeif->iff_ifp);
	feth_lock();
	fakeif->iff_channel_connected = FALSE;
	feth_unlock();
	if (fakeif->iff_if_adv_tcall != NULL) {
		feth_if_adv_tcall_destroy(fakeif);
	}
}

static void
feth_nx_disconnected(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_t channel)
{
#pragma unused(nxprov, channel)
	if_fake_ref fakeif;

	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s: disconnected channel %p\n",
	    fakeif->iff_name, channel);
	feth_release(fakeif);
}

static errno_t
feth_nx_slot_init(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index, struct kern_slot_prop **slot_prop_addr,
    void **slot_context)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index, slot_prop_addr, slot_context)
	return 0;
}

static void
feth_nx_slot_fini(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, kern_channel_slot_t slot,
    uint32_t slot_index)
{
#pragma unused(nxprov, nexus, ring, slot, slot_index)
}

static errno_t
feth_nx_sync_tx(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t tx_ring, uint32_t flags)
{
#pragma unused(nxprov)
	if_fake_ref             fakeif;
	ifnet_t                 ifp;
	kern_channel_slot_t     last_tx_slot = NULL;
	ifnet_t                 peer_ifp;
	if_fake_ref             peer_fakeif = NULL;
	struct kern_channel_ring_stat_increment stats;
	kern_channel_slot_t     tx_slot;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	kern_packet_t           pkts[IFF_MAX_BATCH_SIZE];
	uint32_t                n_pkts = 0;

	memset(&stats, 0, sizeof(stats));

	STATS_INC(nifs, NETIF_STATS_TX_SYNC);
	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s ring %d flags 0x%x\n", fakeif->iff_name,
	    tx_ring->ckr_ring_id, flags);

	feth_lock();
	if (feth_is_detaching(fakeif) || !fakeif->iff_channel_connected) {
		feth_unlock();
		return 0;
	}
	ifp = fakeif->iff_ifp;
	peer_ifp = fakeif->iff_peer;
	if (peer_ifp != NULL) {
		peer_fakeif = ifnet_get_if_fake(peer_ifp);
		if (peer_fakeif != NULL) {
			if (feth_is_detaching(peer_fakeif) ||
			    !peer_fakeif->iff_channel_connected) {
				goto done;
			}
		} else {
			goto done;
		}
	} else {
		goto done;
	}
	tx_slot = kern_channel_get_next_slot(tx_ring, NULL, NULL);
	while (tx_slot != NULL) {
		uint16_t off;
		kern_packet_t sph;

		/* detach the packet from the TX ring */
		sph = kern_channel_slot_get_packet(tx_ring, tx_slot);
		VERIFY(sph != 0);
		kern_channel_slot_detach_packet(tx_ring, tx_slot, sph);

		/* bpf tap output */
		off = kern_packet_get_headroom(sph);
		VERIFY(off >= fakeif->iff_tx_headroom);
		kern_packet_set_link_header_length(sph, ETHER_HDR_LEN);
		feth_packet_set_trace_tag(sph, IFF_TT_OUTPUT);
		bpf_tap_packet_out(ifp, DLT_EN10MB, sph, NULL, 0);

		/* drop packets, if requested */
		fakeif->iff_tx_pkts_count++;
		if (feth_tx_complete_error(fakeif, &sph, nifs)) {
			goto next_tx_slot;
		}
		ASSERT(sph != 0);
		STATS_INC(nifs, NETIF_STATS_TX_COPY_DIRECT);
		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);

		stats.kcrsi_slots_transferred++;
		stats.kcrsi_bytes_transferred
		        += kern_packet_get_data_length(sph);

		/* prepare batch for receiver */
		pkts[n_pkts++] = sph;
		if (n_pkts == IFF_MAX_BATCH_SIZE) {
			feth_rx_submit(fakeif, peer_fakeif, pkts, n_pkts);
			feth_tx_complete(fakeif, pkts, n_pkts);
			n_pkts = 0;
		}

next_tx_slot:
		last_tx_slot = tx_slot;
		tx_slot = kern_channel_get_next_slot(tx_ring, tx_slot, NULL);
	}

	/* catch last batch for receiver */
	if (n_pkts != 0) {
		feth_rx_submit(fakeif, peer_fakeif, pkts, n_pkts);
		feth_tx_complete(fakeif, pkts, n_pkts);
		n_pkts = 0;
	}

	if (last_tx_slot != NULL) {
		kern_channel_advance_slot(tx_ring, last_tx_slot);
		kern_channel_increment_ring_net_stats(tx_ring, ifp, &stats);
	}
done:
	feth_unlock();
	return 0;
}

static errno_t
feth_nx_sync_rx(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, ring, flags)
	if_fake_ref             fakeif;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;

	STATS_INC(nifs, NETIF_STATS_RX_SYNC);
	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s:\n", fakeif->iff_name);
	return 0;
}

static errno_t
feth_nx_tx_dequeue_driver_managed(if_fake_ref fakeif, boolean_t doorbell_ctxt)
{
	int i;
	errno_t error = 0;
	boolean_t more;

	for (i = 0; i < IFF_NUM_TX_RINGS_WMM_MODE; i++) {
		kern_channel_ring_t ring = fakeif->iff_tx_ring[i];
		if (ring != NULL) {
			error = kern_channel_tx_refill(ring, UINT32_MAX,
			    UINT32_MAX, doorbell_ctxt, &more);
		}
		if (error != 0) {
			FETH_DPRINTF("%s: TX refill ring %d (%s) %d\n",
			    fakeif->iff_name, ring->ckr_ring_id,
			    doorbell_ctxt ? "sync" : "async", error);
			if (!((error == EAGAIN) || (error == EBUSY))) {
				break;
			}
		} else {
			FETH_DPRINTF("%s: TX refilled ring %d (%s)\n",
			    fakeif->iff_name, ring->ckr_ring_id,
			    doorbell_ctxt ? "sync" : "async");
		}
	}
	return error;
}

static void
feth_async_doorbell(thread_call_param_t arg0, thread_call_param_t arg1)
{
#pragma unused(arg1)
	errno_t                 error;
	if_fake_ref             fakeif = (if_fake_ref)arg0;
	kern_channel_ring_t     ring;
	boolean_t               more;

	feth_lock();
	ring = fakeif->iff_tx_ring[0];
	if (feth_is_detaching(fakeif) ||
	    !fakeif->iff_channel_connected ||
	    ring == NULL) {
		goto done;
	}
	fakeif->iff_doorbell_tcall_active = TRUE;
	feth_unlock();
	if (feth_in_wmm_mode(fakeif)) {
		error = feth_nx_tx_dequeue_driver_managed(fakeif, FALSE);
	} else {
		error = kern_channel_tx_refill(ring, UINT32_MAX,
		    UINT32_MAX, FALSE, &more);
	}
	if (error != 0) {
		FETH_DPRINTF("%s: TX refill failed %d\n",
		    fakeif->iff_name, error);
	} else {
		FETH_DPRINTF("%s: TX refilled\n", fakeif->iff_name);
	}

	feth_lock();
done:
	fakeif->iff_doorbell_tcall_active = FALSE;
	if (fakeif->iff_waiting_for_tcall) {
		FETH_DPRINTF("%s: threadcall waking up waiter\n",
		    fakeif->iff_name);
		wakeup((caddr_t)fakeif);
	}
	feth_unlock();
}

static void
feth_schedule_async_doorbell(if_fake_ref fakeif)
{
	thread_call_t   tcall;

	feth_lock();
	if (feth_is_detaching(fakeif) || !fakeif->iff_channel_connected) {
		feth_unlock();
		return;
	}
	tcall = fakeif->iff_doorbell_tcall;
	if (tcall != NULL) {
		thread_call_enter(tcall);
	} else {
		tcall = thread_call_allocate_with_options(feth_async_doorbell,
		    (thread_call_param_t)fakeif,
		    THREAD_CALL_PRIORITY_KERNEL,
		    THREAD_CALL_OPTIONS_ONCE);
		if (tcall == NULL) {
			printf("%s: %s tcall alloc failed\n",
			    __func__, fakeif->iff_name);
		} else {
			fakeif->iff_doorbell_tcall = tcall;
			feth_retain(fakeif);
			thread_call_enter(tcall);
		}
	}
	feth_unlock();
}

static errno_t
feth_nx_tx_doorbell(kern_nexus_provider_t nxprov,
    kern_nexus_t nexus, kern_channel_ring_t ring, uint32_t flags)
{
#pragma unused(nxprov, ring, flags)
	errno_t         error;
	if_fake_ref     fakeif;

	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s\n", fakeif->iff_name);

	if ((flags & KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL) == 0) {
		boolean_t       more;
		/* synchronous tx refill */
		if (feth_in_wmm_mode(fakeif)) {
			error = feth_nx_tx_dequeue_driver_managed(fakeif, TRUE);
		} else {
			error = kern_channel_tx_refill(ring, UINT32_MAX,
			    UINT32_MAX, TRUE, &more);
		}
		if (error != 0) {
			FETH_DPRINTF("%s: TX refill (sync) %d\n",
			    fakeif->iff_name, error);
		} else {
			FETH_DPRINTF("%s: TX refilled (sync)\n",
			    fakeif->iff_name);
		}
	} else {
		FETH_DPRINTF("%s: schedule async refill\n", fakeif->iff_name);
		feth_schedule_async_doorbell(fakeif);
	}
	return 0;
}

static errno_t
feth_netif_prepare(kern_nexus_t nexus, ifnet_t ifp)
{
	if_fake_ref fakeif;

	fakeif = (if_fake_ref)kern_nexus_get_context(nexus);
	feth_ifnet_set_attrs(fakeif, ifp);
	return 0;
}

static errno_t
feth_nx_intf_adv_config(void *prov_ctx, bool enable)
{
	if_fake_ref fakeif = prov_ctx;

	feth_lock();
	fakeif->iff_intf_adv_enabled = enable;
	feth_unlock();
	FETH_DPRINTF("%s enable %d\n", fakeif->iff_name, enable);
	return 0;
}

static errno_t
fill_capab_interface_advisory(if_fake_ref fakeif, void *contents, uint32_t *len)
{
	struct kern_nexus_capab_interface_advisory *capab = contents;

	if (*len != sizeof(*capab)) {
		return EINVAL;
	}
	if (capab->kncia_version !=
	    KERN_NEXUS_CAPAB_INTERFACE_ADVISORY_VERSION_1) {
		return EINVAL;
	}
	if (!feth_has_intf_advisory_configured(fakeif)) {
		return ENOTSUP;
	}
	VERIFY(capab->kncia_notify != NULL);
	fakeif->iff_intf_adv_kern_ctx = capab->kncia_kern_context;
	fakeif->iff_intf_adv_notify = capab->kncia_notify;
	capab->kncia_provider_context = fakeif;
	capab->kncia_config = feth_nx_intf_adv_config;
	return 0;
}

static errno_t
feth_notify_steering_info(void *prov_ctx, void *qset_ctx,
    struct ifnet_traffic_descriptor_common *td, bool add)
{
#pragma unused(td)
	if_fake_ref fakeif = prov_ctx;
	fake_qset *qset = qset_ctx;

	FETH_DPRINTF("%s: notify_steering_info: qset_id 0x%llx, %s\n",
	    fakeif->iff_name, qset->fqs_id, add ? "add" : "remove");
	return 0;
}

static errno_t
fill_capab_qset_extensions(if_fake_ref fakeif, void *contents, uint32_t *len)
{
	struct kern_nexus_capab_qset_extensions *capab = contents;

	if (*len != sizeof(*capab)) {
		return EINVAL;
	}
	if (capab->cqe_version !=
	    KERN_NEXUS_CAPAB_QSET_EXTENSIONS_VERSION_1) {
		return EINVAL;
	}
	capab->cqe_prov_ctx = fakeif;
	capab->cqe_notify_steering_info = feth_notify_steering_info;
	return 0;
}

static errno_t
feth_nx_capab_config(kern_nexus_provider_t nxprov, kern_nexus_t nx,
    kern_nexus_capab_t capab, void *contents, uint32_t *len)
{
#pragma unused(nxprov)
	errno_t error;
	if_fake_ref fakeif;

	fakeif = feth_nexus_context(nx);
	FETH_DPRINTF("%s\n", fakeif->iff_name);

	switch (capab) {
	case KERN_NEXUS_CAPAB_INTERFACE_ADVISORY:
		error = fill_capab_interface_advisory(fakeif, contents, len);
		break;
	case KERN_NEXUS_CAPAB_QSET_EXTENSIONS:
		error = fill_capab_qset_extensions(fakeif, contents, len);
		break;
	default:
		error = ENOTSUP;
		break;
	}
	return error;
}

static int
feth_set_tso(ifnet_t ifp)
{
	ifnet_offload_t offload;
	uint32_t tso_v4_mtu, tso_v6_mtu;
	int error;

	offload = IFNET_TSO_IPV4 | IFNET_TSO_IPV6;
	tso_v4_mtu = if_fake_tso_buffer_size;
	tso_v6_mtu = if_fake_tso_buffer_size;
	error = ifnet_set_offload(ifp, offload);
	if (error != 0) {
		printf("%s: set TSO offload failed on %s, err %d\n", __func__,
		    if_name(ifp), error);
		return error;
	}
	error = ifnet_set_tso_mtu(ifp, AF_INET, tso_v4_mtu);
	if (error != 0) {
		printf("%s: set TSO MTU IPv4 failed on %s, err %d\n", __func__,
		    if_name(ifp), error);
		return error;
	}
	error = ifnet_set_tso_mtu(ifp, AF_INET6, tso_v6_mtu);
	if (error != 0) {
		printf("%s: set TSO MTU IPv6 failed on %s, err %d\n", __func__,
		    if_name(ifp), error);
		return error;
	}
	return 0;
}

static errno_t
create_netif_provider_and_instance(if_fake_ref fakeif,
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
		.nxpi_pre_connect = feth_nx_pre_connect,
		.nxpi_connected = feth_nx_connected,
		.nxpi_pre_disconnect = feth_nx_pre_disconnect,
		.nxpi_disconnected = feth_nx_disconnected,
		.nxpi_ring_init = feth_nx_ring_init,
		.nxpi_ring_fini = feth_nx_ring_fini,
		.nxpi_slot_init = feth_nx_slot_init,
		.nxpi_slot_fini = feth_nx_slot_fini,
		.nxpi_sync_tx = feth_nx_sync_tx,
		.nxpi_sync_rx = feth_nx_sync_rx,
		.nxpi_tx_doorbell = feth_nx_tx_doorbell,
		.nxpi_config_capab = feth_nx_capab_config,
	};

	_CASSERT(IFF_MAX_RX_RINGS == 1);
	err = kern_nexus_attr_create(&nexus_attr);
	if (err != 0) {
		printf("%s nexus attribute creation failed, error %d\n",
		    __func__, err);
		goto failed;
	}
	if (feth_in_wmm_mode(fakeif)) {
		err = kern_nexus_attr_set(nexus_attr, NEXUS_ATTR_TX_RINGS,
		    IFF_NUM_TX_RINGS_WMM_MODE);
		VERIFY(err == 0);
		err = kern_nexus_attr_set(nexus_attr, NEXUS_ATTR_RX_RINGS,
		    IFF_NUM_RX_RINGS_WMM_MODE);
		VERIFY(err == 0);
		err = kern_nexus_attr_set(nexus_attr, NEXUS_ATTR_QMAP,
		    NEXUS_QMAP_TYPE_WMM);
		VERIFY(err == 0);
	}

	err = kern_nexus_attr_set(nexus_attr, NEXUS_ATTR_ANONYMOUS, 1);
	VERIFY(err == 0);
	snprintf((char *)provider_name, sizeof(provider_name),
	    "com.apple.netif.%s", fakeif->iff_name);
	err = kern_nexus_controller_register_provider(controller,
	    feth_nx_dom_prov,
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
	net_init.nxneti_prepare = feth_netif_prepare;
	net_init.nxneti_rx_pbufpool = fakeif->iff_rx_pp;
	net_init.nxneti_tx_pbufpool = fakeif->iff_tx_pp;
	err = kern_nexus_controller_alloc_net_provider_instance(controller,
	    *provider,
	    fakeif,
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
	if (feth_supports_tso(fakeif)) {
		if ((err = feth_set_tso(*ifp)) != 0) {
			goto failed;
		}
	}

failed:
	if (nexus_attr != NULL) {
		kern_nexus_attr_destroy(nexus_attr);
	}
	return err;
}

/*
 * The nif_stats need to be referenced because we don't want it set
 * to NULL until the last llink is removed.
 */
static void
get_nexus_stats(if_fake_ref fakeif, kern_nexus_t nexus)
{
	if (++fakeif->iff_nifs_ref == 1) {
		ASSERT(fakeif->iff_nifs == NULL);
		fakeif->iff_nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	}
}

static void
clear_nexus_stats(if_fake_ref fakeif)
{
	if (--fakeif->iff_nifs_ref == 0) {
		ASSERT(fakeif->iff_nifs != NULL);
		fakeif->iff_nifs = NULL;
	}
}

static errno_t
feth_nx_qset_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    void *llink_ctx, uint8_t qset_idx, uint64_t qset_id, kern_netif_qset_t qset,
    void **qset_ctx)
{
#pragma unused(nxprov)
	if_fake_ref fakeif;
	fake_llink *fl = llink_ctx;
	fake_qset *fqs;

	feth_lock();
	fakeif = feth_nexus_context(nexus);
	if (feth_is_detaching(fakeif)) {
		feth_unlock();
		printf("%s: %s: detaching\n", __func__, fakeif->iff_name);
		return ENXIO;
	}
	if (qset_idx >= fl->fl_qset_cnt) {
		feth_unlock();
		printf("%s: %s: invalid qset_idx %d\n", __func__,
		    fakeif->iff_name, qset_idx);
		return EINVAL;
	}
	fqs = &fl->fl_qset[qset_idx];
	ASSERT(fqs->fqs_qset == NULL);
	fqs->fqs_qset = qset;
	fqs->fqs_id = qset_id;
	*qset_ctx = fqs;

	/* XXX This should really be done during registration */
	get_nexus_stats(fakeif, nexus);
	feth_unlock();
	return 0;
}

static void
feth_nx_qset_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    void *qset_ctx)
{
#pragma unused(nxprov)
	if_fake_ref fakeif;
	fake_qset *fqs = qset_ctx;

	feth_lock();
	fakeif = feth_nexus_context(nexus);
	clear_nexus_stats(fakeif);
	ASSERT(fqs->fqs_qset != NULL);
	fqs->fqs_qset = NULL;
	fqs->fqs_id = 0;
	feth_unlock();
}

static errno_t
feth_nx_queue_init(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    void *qset_ctx, uint8_t qidx, bool tx, kern_netif_queue_t queue,
    void **queue_ctx)
{
#pragma unused(nxprov)
	if_fake_ref fakeif;
	fake_qset *fqs = qset_ctx;
	fake_queue *fq;

	feth_lock();
	fakeif = feth_nexus_context(nexus);
	if (feth_is_detaching(fakeif)) {
		printf("%s: %s: detaching\n", __func__, fakeif->iff_name);
		feth_unlock();
		return ENXIO;
	}
	if (tx) {
		if (qidx >= fqs->fqs_tx_queue_cnt) {
			printf("%s: %s: invalid tx qidx %d\n", __func__,
			    fakeif->iff_name, qidx);
			feth_unlock();
			return EINVAL;
		}
		fq = &fqs->fqs_tx_queue[qidx];
	} else {
		if (qidx >= fqs->fqs_rx_queue_cnt) {
			printf("%s: %s: invalid rx qidx %d\n", __func__,
			    fakeif->iff_name, qidx);
			feth_unlock();
			return EINVAL;
		}
		fq = &fqs->fqs_rx_queue[qidx];
	}
	ASSERT(fq->fq_queue == NULL);
	fq->fq_queue = queue;
	*queue_ctx = fq;
	feth_unlock();
	return 0;
}

static void
feth_nx_queue_fini(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    void *queue_ctx)
{
#pragma unused(nxprov, nexus)
	fake_queue *fq = queue_ctx;

	feth_lock();
	ASSERT(fq->fq_queue != NULL);
	fq->fq_queue = NULL;
	feth_unlock();
}

static void
feth_nx_tx_queue_deliver_pkt_chain(if_fake_ref fakeif, kern_packet_t sph,
    struct netif_stats *nifs, if_fake_ref peer_fakeif,
    uint32_t llink_idx, uint32_t qset_idx)
{
	kern_packet_t pkts[IFF_MAX_BATCH_SIZE];
	uint32_t n_pkts = 0;

	while (sph != 0) {
		uint16_t off;
		kern_packet_t next;

		next = kern_packet_get_next(sph);
		kern_packet_set_next(sph, 0);

		/* bpf tap output */
		off = kern_packet_get_headroom(sph);
		VERIFY(off >= fakeif->iff_tx_headroom);
		kern_packet_set_link_header_length(sph, ETHER_HDR_LEN);
		feth_packet_set_trace_tag(sph, IFF_TT_OUTPUT);
		bpf_tap_packet_out(fakeif->iff_ifp, DLT_EN10MB, sph, NULL, 0);

		/* drop packets, if requested */
		fakeif->iff_tx_pkts_count++;
		if (feth_tx_complete_error(fakeif, &sph, nifs)) {
			goto next_pkt;
		}
		ASSERT(sph != 0);
		STATS_INC(nifs, NETIF_STATS_TX_COPY_DIRECT);
		STATS_INC(nifs, NETIF_STATS_TX_PACKETS);

		/* prepare batch for receiver */
		pkts[n_pkts++] = sph;
		if (n_pkts == IFF_MAX_BATCH_SIZE) {
			feth_rx_queue_submit(fakeif, peer_fakeif, llink_idx,
			    qset_idx, pkts, n_pkts);
			feth_tx_complete(fakeif, pkts, n_pkts);
			n_pkts = 0;
		}
next_pkt:
		sph = next;
	}
	/* catch last batch for receiver */
	if (n_pkts != 0) {
		feth_rx_queue_submit(fakeif, peer_fakeif, llink_idx, qset_idx,
		    pkts, n_pkts);
		feth_tx_complete(fakeif, pkts, n_pkts);
		n_pkts = 0;
	}
}

static errno_t
feth_nx_tx_qset_notify(kern_nexus_provider_t nxprov, kern_nexus_t nexus,
    void *qset_ctx, uint32_t flags)
{
#pragma unused(nxprov)
	if_fake_ref             fakeif;
	ifnet_t                 ifp;
	ifnet_t                 peer_ifp;
	if_fake_ref             peer_fakeif = NULL;
	struct netif_stats *nifs = &NX_NETIF_PRIVATE(nexus)->nif_stats;
	fake_qset               *qset = qset_ctx;
	boolean_t               detaching, connected;
	uint32_t                i;
	errno_t                 err;

	STATS_INC(nifs, NETIF_STATS_TX_SYNC);
	fakeif = feth_nexus_context(nexus);
	FETH_DPRINTF("%s qset %p, idx %d, flags 0x%x\n", fakeif->iff_name, qset,
	    qset->fqs_idx, flags);

	feth_lock();
	detaching = feth_is_detaching(fakeif);
	connected = fakeif->iff_channel_connected;
	if (detaching || !connected) {
		FETH_DPRINTF("%s: %s: detaching %s, channel connected %s\n",
		    __func__, fakeif->iff_name,
		    (detaching ? "true" : "false"),
		    (connected ? "true" : "false"));
		feth_unlock();
		return 0;
	}
	ifp = fakeif->iff_ifp;
	peer_ifp = fakeif->iff_peer;
	if (peer_ifp != NULL) {
		peer_fakeif = ifnet_get_if_fake(peer_ifp);
		if (peer_fakeif != NULL) {
			detaching = feth_is_detaching(peer_fakeif);
			connected = peer_fakeif->iff_channel_connected;
			if (detaching || !connected) {
				FETH_DPRINTF("%s: peer %s: detaching %s, "
				    "channel connected %s\n",
				    __func__, peer_fakeif->iff_name,
				    (detaching ? "true" : "false"),
				    (connected ? "true" : "false"));
				goto done;
			}
		} else {
			FETH_DPRINTF("%s: peer_fakeif is NULL\n", __func__);
			goto done;
		}
	} else {
		printf("%s: peer_ifp is NULL\n", __func__);
		goto done;
	}

	if (if_fake_switch_combined_mode &&
	    qset->fqs_dequeue_cnt >= if_fake_switch_mode_frequency) {
		if (qset->fqs_combined_mode) {
			kern_netif_set_qset_separate(qset->fqs_qset);
		} else {
			kern_netif_set_qset_combined(qset->fqs_qset);
		}
		qset->fqs_combined_mode = !qset->fqs_combined_mode;
		qset->fqs_dequeue_cnt = 0;
	}

	for (i = 0; i < qset->fqs_tx_queue_cnt; i++) {
		kern_packet_t sph = 0;
		kern_netif_queue_t queue = qset->fqs_tx_queue[i].fq_queue;
		boolean_t more = FALSE;

		err = kern_netif_queue_tx_dequeue(queue, UINT32_MAX, UINT32_MAX,
		    &more, &sph);
		if (err != 0 && err != EAGAIN) {
			FETH_DPRINTF("%s queue %p dequeue failed: err "
			    "%d\n", fakeif->iff_name, queue, err);
		}
		feth_nx_tx_queue_deliver_pkt_chain(fakeif, sph, nifs,
		    peer_fakeif, qset->fqs_llink_idx, qset->fqs_idx);
	}

done:
	feth_unlock();
	return 0;
}

static void
fill_qset_info_and_params(if_fake_ref fakeif, fake_llink *llink_info,
    uint32_t qset_idx, struct kern_nexus_netif_llink_qset_init *qset_init,
    bool is_def, bool is_low_latency)
{
	fake_qset *qset_info = &llink_info->fl_qset[qset_idx];

	qset_init->nlqi_flags =
	    (is_def ? KERN_NEXUS_NET_LLINK_QSET_DEFAULT : 0) |
	    (is_low_latency ? KERN_NEXUS_NET_LLINK_QSET_LOW_LATENCY : 0) |
	    KERN_NEXUS_NET_LLINK_QSET_AQM;

	if (feth_in_wmm_mode(fakeif)) {
		qset_init->nlqi_flags |= KERN_NEXUS_NET_LLINK_QSET_WMM_MODE;
		qset_init->nlqi_num_txqs = IFF_NUM_TX_QUEUES_WMM_MODE;
		qset_init->nlqi_num_rxqs = IFF_NUM_RX_QUEUES_WMM_MODE;
	} else {
		qset_init->nlqi_num_txqs = 1;
		qset_init->nlqi_num_rxqs = 1;
	}
	qset_info->fqs_tx_queue_cnt = qset_init->nlqi_num_txqs;
	qset_info->fqs_rx_queue_cnt = qset_init->nlqi_num_rxqs;

	/* These are needed for locating the peer qset */
	qset_info->fqs_llink_idx = llink_info->fl_idx;
	qset_info->fqs_idx = qset_idx;
}

static void
fill_llink_info_and_params(if_fake_ref fakeif, uint32_t llink_idx,
    struct kern_nexus_netif_llink_init *llink_init, uint32_t llink_id,
    struct kern_nexus_netif_llink_qset_init *qset_init, uint32_t qset_cnt,
    uint32_t flags)
{
	fake_llink *llink_info = &fakeif->iff_llink[llink_idx];
	uint32_t i;
	bool create_ll_qset = if_fake_low_latency && (llink_idx != 0);

	for (i = 0; i < qset_cnt; i++) {
		fill_qset_info_and_params(fakeif, llink_info, i,
		    &qset_init[i], i == 0, create_ll_qset && i == 1);
	}
	llink_info->fl_idx = llink_idx;

	/* This doesn't have to be the same as llink_idx */
	llink_info->fl_id = llink_id;
	llink_info->fl_qset_cnt = qset_cnt;

	llink_init->nli_link_id = llink_id;
	llink_init->nli_num_qsets = qset_cnt;
	llink_init->nli_qsets = qset_init;
	llink_init->nli_flags = flags;
	llink_init->nli_ctx = llink_info;
}

static errno_t
create_non_default_llinks(if_fake_ref fakeif)
{
	struct kern_nexus *nx;
	fake_nx_t fnx = &fakeif->iff_nx;
	struct kern_nexus_netif_llink_init llink_init;
	struct kern_nexus_netif_llink_qset_init qset_init[FETH_MAX_QSETS];
	errno_t err;
	uint64_t llink_id;
	uint32_t i;

	nx = nx_find(fnx->fnx_instance, FALSE);
	if (nx == NULL) {
		printf("%s: %s: nx not found\n", __func__, fakeif->iff_name);
		return ENXIO;
	}
	/* Default llink starts at index 0 */
	for (i = 1; i < if_fake_llink_cnt; i++) {
		llink_id = (uint64_t)i;

		/*
		 * The llink_init and qset_init structures are reused for
		 * each llink creation.
		 */
		fill_llink_info_and_params(fakeif, i, &llink_init,
		    llink_id, qset_init, if_fake_qset_cnt, 0);
		err = kern_nexus_netif_llink_add(nx, &llink_init);
		if (err != 0) {
			printf("%s: %s: llink add failed, error %d\n",
			    __func__, fakeif->iff_name, err);
			goto fail;
		}
		fakeif->iff_llink_cnt++;
	}
	nx_release(nx);
	return 0;

fail:
	for (i = 0; i < fakeif->iff_llink_cnt; i++) {
		int e;

		e = kern_nexus_netif_llink_remove(nx, fakeif->
		    iff_llink[i].fl_id);
		if (e != 0) {
			printf("%s: %s: llink remove failed, llink_id 0x%llx, "
			    "error %d\n", __func__, fakeif->iff_name,
			    fakeif->iff_llink[i].fl_id, e);
		}
		fakeif->iff_llink[i].fl_id = 0;
	}
	fakeif->iff_llink_cnt = 0;
	nx_release(nx);
	return err;
}

static errno_t
create_netif_llink_provider_and_instance(if_fake_ref fakeif,
    struct ifnet_init_eparams * init_params, ifnet_t *ifp,
    uuid_t * provider, uuid_t * instance)
{
	errno_t                 err;
	nexus_controller_t      controller = kern_nexus_shared_controller();
	struct kern_nexus_net_init net_init;
	struct kern_nexus_netif_llink_init llink_init;
	struct kern_nexus_netif_llink_qset_init qsets[FETH_MAX_QSETS];

	nexus_name_t            provider_name;
	nexus_attr_t            nexus_attr = NULL;
	struct kern_nexus_netif_provider_init prov_init = {
		.nxnpi_version = KERN_NEXUS_DOMAIN_PROVIDER_NETIF,
		.nxnpi_flags = NXPIF_VIRTUAL_DEVICE,
		.nxnpi_pre_connect = feth_nx_pre_connect,
		.nxnpi_connected = feth_nx_connected,
		.nxnpi_pre_disconnect = feth_nx_pre_disconnect,
		.nxnpi_disconnected = feth_nx_disconnected,
		.nxnpi_qset_init = feth_nx_qset_init,
		.nxnpi_qset_fini = feth_nx_qset_fini,
		.nxnpi_queue_init = feth_nx_queue_init,
		.nxnpi_queue_fini = feth_nx_queue_fini,
		.nxnpi_tx_qset_notify = feth_nx_tx_qset_notify,
		.nxnpi_config_capab = feth_nx_capab_config,
	};

	err = kern_nexus_attr_create(&nexus_attr);
	if (err != 0) {
		printf("%s nexus attribute creation failed, error %d\n",
		    __func__, err);
		goto failed;
	}

	err = kern_nexus_attr_set(nexus_attr, NEXUS_ATTR_ANONYMOUS, 1);
	VERIFY(err == 0);

	snprintf((char *)provider_name, sizeof(provider_name),
	    "com.apple.netif.%s", fakeif->iff_name);
	err = kern_nexus_controller_register_provider(controller,
	    feth_nx_dom_prov,
	    provider_name,
	    (struct kern_nexus_provider_init *)&prov_init,
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
	net_init.nxneti_prepare = feth_netif_prepare;
	net_init.nxneti_rx_pbufpool = fakeif->iff_rx_pp;
	net_init.nxneti_tx_pbufpool = fakeif->iff_tx_pp;

	/*
	 * Assume llink id is same as the index for if_fake.
	 * This is not required for other drivers.
	 */
	_CASSERT(NETIF_LLINK_ID_DEFAULT == 0);
	fill_llink_info_and_params(fakeif, 0, &llink_init,
	    NETIF_LLINK_ID_DEFAULT, qsets, if_fake_qset_cnt,
	    KERN_NEXUS_NET_LLINK_DEFAULT);

	net_init.nxneti_llink = &llink_init;

	err = kern_nexus_controller_alloc_net_provider_instance(controller,
	    *provider, fakeif, NULL, instance, &net_init, ifp);
	if (err != 0) {
		printf("%s alloc_net_provider_instance failed, %d\n",
		    __func__, err);
		kern_nexus_controller_deregister_provider(controller,
		    *provider);
		uuid_clear(*provider);
		goto failed;
	}
	fakeif->iff_llink_cnt++;

	if (if_fake_llink_cnt > 1) {
		err = create_non_default_llinks(fakeif);
		if (err != 0) {
			printf("%s create_non_default_llinks failed, %d\n",
			    __func__, err);
			feth_detach_netif_nexus(fakeif);
			goto failed;
		}
	}
	if (feth_supports_tso(fakeif)) {
		if ((err = feth_set_tso(*ifp)) != 0) {
			goto failed;
		}
	}
failed:
	if (nexus_attr != NULL) {
		kern_nexus_attr_destroy(nexus_attr);
	}
	return err;
}

static errno_t
feth_attach_netif_nexus(if_fake_ref fakeif,
    struct ifnet_init_eparams * init_params, ifnet_t *ifp)
{
	errno_t                 error;
	fake_nx_t               nx = &fakeif->iff_nx;

	error = feth_packet_pool_make(fakeif);
	if (error != 0) {
		return error;
	}
	if (if_fake_llink_cnt == 0) {
		return create_netif_provider_and_instance(fakeif, init_params,
		           ifp, &nx->fnx_provider, &nx->fnx_instance);
	} else {
		return create_netif_llink_provider_and_instance(fakeif,
		           init_params, ifp, &nx->fnx_provider,
		           &nx->fnx_instance);
	}
}

static void
remove_non_default_llinks(if_fake_ref fakeif)
{
	struct kern_nexus *nx;
	fake_nx_t fnx = &fakeif->iff_nx;
	uint32_t i;

	if (fakeif->iff_llink_cnt <= 1) {
		return;
	}
	nx = nx_find(fnx->fnx_instance, FALSE);
	if (nx == NULL) {
		printf("%s: %s: nx not found\n", __func__,
		    fakeif->iff_name);
		return;
	}
	/* Default llink (at index 0) is freed separately */
	for (i = 1; i < fakeif->iff_llink_cnt; i++) {
		int err;

		err = kern_nexus_netif_llink_remove(nx, fakeif->
		    iff_llink[i].fl_id);
		if (err != 0) {
			printf("%s: %s: llink remove failed, llink_id 0x%llx, "
			    "error %d\n", __func__, fakeif->iff_name,
			    fakeif->iff_llink[i].fl_id, err);
		}
		fakeif->iff_llink[i].fl_id = 0;
	}
	fakeif->iff_llink_cnt = 0;
	nx_release(nx);
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
feth_detach_netif_nexus(if_fake_ref fakeif)
{
	fake_nx_t fnx = &fakeif->iff_nx;

	remove_non_default_llinks(fakeif);
	detach_provider_and_instance(fnx->fnx_provider, fnx->fnx_instance);
}

#endif /* SKYWALK */

/**
** feth interface routines
**/
static void
feth_ifnet_set_attrs(if_fake_ref fakeif, ifnet_t ifp)
{
	(void)ifnet_set_capabilities_enabled(ifp, 0, -1);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_mtu(ifp, ETHERMTU);
	ifnet_set_flags(ifp,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX,
	    0xffff);
	ifnet_set_hdrlen(ifp, sizeof(struct ether_header));
	if ((fakeif->iff_flags & IFF_FLAGS_HWCSUM) != 0) {
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

static if_fake_ref
ifnet_get_if_fake(ifnet_t ifp)
{
	return (if_fake_ref)ifnet_softc(ifp);
}

static int
feth_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int                             error;
	if_fake_ref                     fakeif;
	struct ifnet_init_eparams       feth_init;
	ifnet_t                         ifp;
	uint8_t                         mac_address[ETHER_ADDR_LEN];
	fake_llink                     *iff_llink;

	iff_llink = kalloc_type(fake_llink, FETH_MAX_LLINKS, Z_WAITOK_ZERO);
	if (iff_llink == NULL) {
		return ENOBUFS;
	}
	fakeif = kalloc_type(struct if_fake, Z_WAITOK_ZERO_NOFAIL);
	fakeif->iff_llink = iff_llink;
	fakeif->iff_retain_count = 1;
#define FAKE_ETHER_NAME_LEN     (sizeof(FAKE_ETHER_NAME) - 1)
	_CASSERT(FAKE_ETHER_NAME_LEN == 4);
	bcopy(FAKE_ETHER_NAME, mac_address, FAKE_ETHER_NAME_LEN);
	mac_address[ETHER_ADDR_LEN - 2] = (unit & 0xff00) >> 8;
	mac_address[ETHER_ADDR_LEN - 1] = unit & 0xff;
	if (if_fake_bsd_mode != 0) {
		fakeif->iff_flags |= IFF_FLAGS_BSD_MODE;
	}
	if (if_fake_hwcsum != 0) {
		fakeif->iff_flags |= IFF_FLAGS_HWCSUM;
	}
	fakeif->iff_max_mtu = get_max_mtu(if_fake_bsd_mode, if_fake_max_mtu);
	fakeif->iff_fcs = if_fake_fcs;
	fakeif->iff_trailer_length = if_fake_trailer_length;

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(fakeif->iff_name, sizeof(fakeif->iff_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(fakeif->iff_name)) {
		feth_release(fakeif);
		return EINVAL;
	}
	bzero(&feth_init, sizeof(feth_init));
	feth_init.ver = IFNET_INIT_CURRENT_VERSION;
	feth_init.len = sizeof(feth_init);
	if (feth_in_bsd_mode(fakeif)) {
		if (if_fake_txstart != 0) {
			feth_init.start = feth_start;
		} else {
			feth_init.flags |= IFNET_INIT_LEGACY;
			feth_init.output = feth_output;
		}
	}
#if SKYWALK
	else {
		feth_init.flags |= IFNET_INIT_SKYWALK_NATIVE;
		/*
		 * Currently we support WMM mode only for Skywalk native
		 * interface.
		 */
		if (if_fake_wmm_mode != 0) {
			fakeif->iff_flags |= IFF_FLAGS_WMM_MODE;
		}

		if (if_fake_multibuflet != 0) {
			fakeif->iff_flags |= IFF_FLAGS_MULTIBUFLETS;
		}

		if (if_fake_multibuflet != 0 &&
		    if_fake_pktpool_mode == IFF_PP_MODE_PRIVATE_SPLIT) {
			printf("%s: multi-buflet not supported for split rx &"
			    " tx pool", __func__);
			feth_release(fakeif);
			return EINVAL;
		}

		fakeif->iff_pp_mode = if_fake_pktpool_mode;
		if (if_fake_tso_support != 0) {
			if (fakeif->iff_pp_mode != IFF_PP_MODE_GLOBAL) {
				printf("%s: TSO mode requires global packet"
				    " pool mode\n", __func__);
				return EINVAL;
			}
			fakeif->iff_flags |= IFF_FLAGS_TSO_SUPPORT;
		}

		fakeif->iff_tx_headroom = if_fake_tx_headroom;
		fakeif->iff_adv_interval = if_fake_if_adv_interval;
		if (fakeif->iff_adv_interval > 0) {
			feth_init.flags |= IFNET_INIT_IF_ADV;
		}
		fakeif->iff_tx_drop_rate = if_fake_tx_drops;
		fakeif->iff_tx_completion_mode = if_tx_completion_mode;
	}
	feth_init.tx_headroom = fakeif->iff_tx_headroom;
#endif /* SKYWALK */
	if (if_fake_nxattach == 0) {
		feth_init.flags |= IFNET_INIT_NX_NOAUTO;
	}
	feth_init.uniqueid = fakeif->iff_name;
	feth_init.uniqueid_len = strlen(fakeif->iff_name);
	feth_init.name = ifc->ifc_name;
	feth_init.unit = unit;
	feth_init.family = IFNET_FAMILY_ETHERNET;
	feth_init.type = IFT_ETHER;
	feth_init.demux = ether_demux;
	feth_init.add_proto = ether_add_proto;
	feth_init.del_proto = ether_del_proto;
	feth_init.check_multi = ether_check_multi;
	feth_init.framer_extended = ether_frameout_extended;
	feth_init.softc = fakeif;
	feth_init.ioctl = feth_ioctl;
	feth_init.set_bpf_tap = NULL;
	feth_init.detach = feth_if_free;
	feth_init.broadcast_addr = etherbroadcastaddr;
	feth_init.broadcast_len = ETHER_ADDR_LEN;
	if (feth_in_bsd_mode(fakeif)) {
		error = ifnet_allocate_extended(&feth_init, &ifp);
		if (error) {
			feth_release(fakeif);
			return error;
		}
		feth_ifnet_set_attrs(fakeif, ifp);
	}
#if SKYWALK
	else {
		if (feth_in_wmm_mode(fakeif)) {
			feth_init.output_sched_model =
			    IFNET_SCHED_MODEL_DRIVER_MANAGED;
		}
		error = feth_attach_netif_nexus(fakeif, &feth_init, &ifp);
		if (error != 0) {
			feth_release(fakeif);
			return error;
		}
		/* take an additional reference to ensure that it doesn't go away */
		feth_retain(fakeif);
		fakeif->iff_ifp = ifp;
	}
#endif /* SKYWALK */
	fakeif->iff_media_count = MIN(default_media_words_count, IF_FAKE_MEDIA_LIST_MAX);
	bcopy(default_media_words, fakeif->iff_media_list,
	    fakeif->iff_media_count * sizeof(fakeif->iff_media_list[0]));
	if (feth_in_bsd_mode(fakeif)) {
		error = ifnet_attach(ifp, NULL);
		if (error) {
			ifnet_release(ifp);
			feth_release(fakeif);
			return error;
		}
		fakeif->iff_ifp = ifp;
	}

	ifnet_set_lladdr(ifp, mac_address, sizeof(mac_address));

	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	return 0;
}

static int
feth_clone_destroy(ifnet_t ifp)
{
	if_fake_ref     fakeif;
#if SKYWALK
	boolean_t       nx_attached = FALSE;
#endif /* SKYWALK */

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL || feth_is_detaching(fakeif)) {
		feth_unlock();
		return 0;
	}
	feth_set_detaching(fakeif);
#if SKYWALK
	nx_attached = !feth_in_bsd_mode(fakeif);
#endif /* SKYWALK */
	feth_unlock();

#if SKYWALK
	if (nx_attached) {
		feth_detach_netif_nexus(fakeif);
		feth_release(fakeif);
	}
#endif /* SKYWALK */
	feth_config(ifp, NULL);
	ifnet_detach(ifp);
	return 0;
}

static void
feth_enqueue_input(ifnet_t ifp, struct mbuf * m)
{
	struct ifnet_stat_increment_param stats = {};

	stats.packets_in = 1;
	stats.bytes_in = (uint32_t)mbuf_pkthdr_len(m) + ETHER_HDR_LEN;
	ifnet_input(ifp, m, &stats);
}

static struct mbuf *
copy_mbuf(struct mbuf *m)
{
	struct mbuf *   copy_m;
	uint32_t        pkt_len;
	uint32_t        offset;

	if ((m->m_flags & M_PKTHDR) == 0) {
		return NULL;
	}
	pkt_len = m->m_pkthdr.len;
	MGETHDR(copy_m, M_DONTWAIT, MT_DATA);
	if (copy_m == NULL) {
		goto failed;
	}
	if (pkt_len > MHLEN) {
		if (pkt_len <= MCLBYTES) {
			MCLGET(copy_m, M_DONTWAIT);
		} else if (pkt_len <= MBIGCLBYTES) {
			copy_m = m_mbigget(copy_m, M_DONTWAIT);
		} else if (pkt_len <= M16KCLBYTES && njcl > 0) {
			copy_m = m_m16kget(copy_m, M_DONTWAIT);
		} else {
			printf("if_fake: copy_mbuf(): packet too large %d\n",
			    pkt_len);
			goto failed;
		}
		if (copy_m == NULL || (copy_m->m_flags & M_EXT) == 0) {
			goto failed;
		}
	}
	mbuf_setlen(copy_m, pkt_len);
	copy_m->m_pkthdr.len = pkt_len;
	copy_m->m_pkthdr.pkt_svc = m->m_pkthdr.pkt_svc;
	offset = 0;
	while (m != NULL && offset < pkt_len) {
		uint32_t        frag_len;

		frag_len = m->m_len;
		if (frag_len > (pkt_len - offset)) {
			printf("if_fake_: Large mbuf fragment %d > %d\n",
			    frag_len, (pkt_len - offset));
			goto failed;
		}
		m_copydata(m, 0, frag_len, mtodo(copy_m, offset));
		offset += frag_len;
		m = m->m_next;
	}
	return copy_m;

failed:
	if (copy_m != NULL) {
		m_freem(copy_m);
	}
	return NULL;
}

static int
feth_add_mbuf_trailer(struct mbuf *m, void *trailer, size_t trailer_len)
{
	int ret;
	ASSERT(trailer_len <= FETH_TRAILER_LENGTH_MAX);

	ret = m_append(m, trailer_len, (caddr_t)trailer);
	if (ret == 1) {
		FETH_DPRINTF("%s %zuB trailer added\n", __func__, trailer_len);
		return 0;
	}
	printf("%s m_append failed\n", __func__);
	return ENOTSUP;
}

static int
feth_add_mbuf_fcs(struct mbuf *m)
{
	uint32_t pkt_len, offset = 0;
	uint32_t crc = 0;
	int err = 0;

	ASSERT(sizeof(crc) == ETHER_CRC_LEN);

	pkt_len = m->m_pkthdr.len;
	struct mbuf *iter = m;
	while (iter != NULL && offset < pkt_len) {
		uint32_t frag_len = iter->m_len;
		ASSERT(frag_len <= (pkt_len - offset));
		crc = crc32(crc, mtod(iter, void *), frag_len);
		offset += frag_len;
		iter = m->m_next;
	}

	err = feth_add_mbuf_trailer(m, &crc, ETHER_CRC_LEN);
	if (err != 0) {
		return err;
	}

	m->m_flags |= M_HASFCS;

	return 0;
}

static void
feth_output_common(ifnet_t ifp, struct mbuf * m, ifnet_t peer,
    iff_flags_t flags, bool fcs, void *trailer, size_t trailer_len)
{
	void *          frame_header;

	frame_header = mbuf_data(m);
	if ((flags & IFF_FLAGS_HWCSUM) != 0) {
		m->m_pkthdr.csum_data = 0xffff;
		m->m_pkthdr.csum_flags =
		    CSUM_DATA_VALID | CSUM_PSEUDO_HDR |
		    CSUM_IP_CHECKED | CSUM_IP_VALID;
	}

	(void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
	bpf_tap_out(ifp, DLT_EN10MB, m, NULL, 0);

	if (trailer != 0) {
		feth_add_mbuf_trailer(m, trailer, trailer_len);
	}
	if (fcs) {
		feth_add_mbuf_fcs(m);
	}

	(void)mbuf_pkthdr_setrcvif(m, peer);
	mbuf_pkthdr_setheader(m, frame_header);
	mbuf_pkthdr_adjustlen(m, -ETHER_HDR_LEN);
	(void)mbuf_setdata(m, (char *)mbuf_data(m) + ETHER_HDR_LEN,
	    mbuf_len(m) - ETHER_HDR_LEN);
	bpf_tap_in(peer, DLT_EN10MB, m, frame_header,
	    sizeof(struct ether_header));
	feth_enqueue_input(peer, m);
}

static void
feth_start(ifnet_t ifp)
{
	struct mbuf *   copy_m = NULL;
	if_fake_ref     fakeif;
	iff_flags_t     flags = 0;
	bool            fcs;
	size_t          trailer_len;
	ifnet_t         peer = NULL;
	struct mbuf *   m;
	struct mbuf *   save_m;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		feth_unlock();
		return;
	}

	if (fakeif->iff_start_busy) {
		feth_unlock();
		printf("if_fake: start is busy\n");
		return;
	}

	peer = fakeif->iff_peer;
	flags = fakeif->iff_flags;
	fcs = fakeif->iff_fcs;
	trailer_len = fakeif->iff_trailer_length;

	/* check for pending TX */
	m = fakeif->iff_pending_tx_packet;
	if (m != NULL) {
		if (peer != NULL) {
			copy_m = copy_mbuf(m);
			if (copy_m == NULL) {
				feth_unlock();
				return;
			}
		}
		fakeif->iff_pending_tx_packet = NULL;
		m_freem(m);
		m = NULL;
	}
	fakeif->iff_start_busy = TRUE;
	feth_unlock();
	save_m = NULL;
	for (;;) {
		if (copy_m != NULL) {
			VERIFY(peer != NULL);
			feth_output_common(ifp, copy_m, peer, flags, fcs,
			    feth_trailer, trailer_len);
			copy_m = NULL;
		}
		if (ifnet_dequeue(ifp, &m) != 0) {
			break;
		}
		if (peer == NULL) {
			m_freem(m);
		} else {
			copy_m = copy_mbuf(m);
			if (copy_m == NULL) {
				save_m = m;
				break;
			}
			m_freem(m);
		}
	}
	peer = NULL;
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		fakeif->iff_start_busy = FALSE;
		if (save_m != NULL && fakeif->iff_peer != NULL) {
			/* save it for next time */
			fakeif->iff_pending_tx_packet = save_m;
			save_m = NULL;
		}
	}
	feth_unlock();
	if (save_m != NULL) {
		/* didn't save packet, so free it */
		m_freem(save_m);
	}
}

static int
feth_output(ifnet_t ifp, struct mbuf * m)
{
	struct mbuf *           copy_m;
	if_fake_ref             fakeif;
	iff_flags_t             flags;
	bool                    fcs;
	size_t                  trailer_len;
	ifnet_t                 peer = NULL;

	if (m == NULL) {
		return 0;
	}
	copy_m = copy_mbuf(m);
	m_freem(m);
	m = NULL;
	if (copy_m == NULL) {
		/* count this as an output error */
		ifnet_stat_increment_out(ifp, 0, 0, 1);
		return 0;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif != NULL) {
		peer = fakeif->iff_peer;
		flags = fakeif->iff_flags;
		fcs = fakeif->iff_fcs;
		trailer_len = fakeif->iff_trailer_length;
	}
	feth_unlock();
	if (peer == NULL) {
		m_freem(copy_m);
		ifnet_stat_increment_out(ifp, 0, 0, 1);
		return 0;
	}
	feth_output_common(ifp, copy_m, peer, flags, fcs, feth_trailer,
	    trailer_len);
	return 0;
}

static int
feth_config(ifnet_t ifp, ifnet_t peer)
{
	int             connected = FALSE;
	int             disconnected = FALSE;
	int             error = 0;
	if_fake_ref     fakeif = NULL;

	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		error = EINVAL;
		goto done;
	}
	if (peer != NULL) {
		/* connect to peer */
		if_fake_ref     peer_fakeif;

		peer_fakeif = ifnet_get_if_fake(peer);
		if (peer_fakeif == NULL) {
			error = EINVAL;
			goto done;
		}
		if (feth_is_detaching(fakeif) ||
		    feth_is_detaching(peer_fakeif) ||
		    peer_fakeif->iff_peer != NULL ||
		    fakeif->iff_peer != NULL) {
			error = EBUSY;
			goto done;
		}
#if SKYWALK
		if (fakeif->iff_pp_mode !=
		    peer_fakeif->iff_pp_mode) {
			error = EINVAL;
			goto done;
		}
#endif /* SKYWALK */
		fakeif->iff_peer = peer;
		peer_fakeif->iff_peer = ifp;
		connected = TRUE;
	} else if (fakeif->iff_peer != NULL) {
		/* disconnect from peer */
		if_fake_ref     peer_fakeif;

		peer = fakeif->iff_peer;
		peer_fakeif = ifnet_get_if_fake(peer);
		if (peer_fakeif == NULL) {
			/* should not happen */
			error = EINVAL;
			goto done;
		}
		fakeif->iff_peer = NULL;
		peer_fakeif->iff_peer = NULL;
		disconnected = TRUE;
	}

done:
	feth_unlock();

	/* generate link status event if we connect or disconnect */
	if (connected) {
		interface_link_event(ifp, KEV_DL_LINK_ON);
		interface_link_event(peer, KEV_DL_LINK_ON);
	} else if (disconnected) {
		interface_link_event(ifp, KEV_DL_LINK_OFF);
		interface_link_event(peer, KEV_DL_LINK_OFF);
	}
	return error;
}

static int
feth_set_media(ifnet_t ifp, struct if_fake_request * iffr)
{
	if_fake_ref     fakeif;
	int             error;

	if (iffr->iffr_media.iffm_count > IF_FAKE_MEDIA_LIST_MAX) {
		/* list is too long */
		return EINVAL;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		error = EINVAL;
		goto done;
	}
	fakeif->iff_media_count = iffr->iffr_media.iffm_count;
	bcopy(iffr->iffr_media.iffm_list, fakeif->iff_media_list,
	    iffr->iffr_media.iffm_count * sizeof(fakeif->iff_media_list[0]));
#if 0
	/* XXX: "auto-negotiate" active with peer? */
	/* generate link status event? */
	fakeif->iff_media_current = iffr->iffr_media.iffm_current;
#endif
	error = 0;
done:
	feth_unlock();
	return error;
}

static int
if_fake_request_copyin(user_addr_t user_addr,
    struct if_fake_request *iffr, u_int32_t len)
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
feth_set_drvspec(ifnet_t ifp, uint32_t cmd, u_int32_t len,
    user_addr_t user_addr)
{
	int                     error;
	struct if_fake_request  iffr;
	ifnet_t                 peer;

	switch (cmd) {
	case IF_FAKE_S_CMD_SET_PEER:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		if (iffr.iffr_peer_name[0] == '\0') {
			error = feth_config(ifp, NULL);
			break;
		}

		/* ensure nul termination */
		iffr.iffr_peer_name[IFNAMSIZ - 1] = '\0';
		peer = ifunit(iffr.iffr_peer_name);
		if (peer == NULL) {
			error = ENXIO;
			break;
		}
		if (ifnet_type(peer) != IFT_ETHER) {
			error = EINVAL;
			break;
		}
		if (strcmp(ifnet_name(peer), FAKE_ETHER_NAME) != 0) {
			error = EINVAL;
			break;
		}
		error = feth_config(ifp, peer);
		break;
	case IF_FAKE_S_CMD_SET_MEDIA:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		error = feth_set_media(ifp, &iffr);
		break;
	case IF_FAKE_S_CMD_SET_DEQUEUE_STALL:
		error = if_fake_request_copyin(user_addr, &iffr, len);
		if (error != 0) {
			break;
		}
		error = feth_enable_dequeue_stall(ifp,
		    iffr.iffr_dequeue_stall);
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return error;
}

static int
feth_get_drvspec(ifnet_t ifp, u_int32_t cmd, u_int32_t len,
    user_addr_t user_addr)
{
	int                     error = EOPNOTSUPP;
	if_fake_ref             fakeif;
	struct if_fake_request  iffr;
	ifnet_t                 peer;

	switch (cmd) {
	case IF_FAKE_G_CMD_GET_PEER:
		if (len < sizeof(iffr)) {
			error = EINVAL;
			break;
		}
		feth_lock();
		fakeif = ifnet_get_if_fake(ifp);
		if (fakeif == NULL) {
			feth_unlock();
			error = EOPNOTSUPP;
			break;
		}
		peer = fakeif->iff_peer;
		feth_unlock();
		bzero(&iffr, sizeof(iffr));
		if (peer != NULL) {
			strlcpy(iffr.iffr_peer_name,
			    if_name(peer),
			    sizeof(iffr.iffr_peer_name));
		}
		error = copyout(&iffr, user_addr, sizeof(iffr));
		break;
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
feth_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
	unsigned int            count;
	struct ifdevmtu *       devmtu_p;
	union ifdrvu            drv;
	uint32_t                drv_cmd;
	uint32_t                drv_len;
	boolean_t               drv_set_command = FALSE;
	int                     error = 0;
	struct ifmediareq *     ifmr;
	struct ifreq *          ifr;
	if_fake_ref             fakeif;
	int                     status;
	user_addr_t             user_addr;

	ifr = (struct ifreq *)data;
	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
		feth_lock();
		fakeif = ifnet_get_if_fake(ifp);
		if (fakeif == NULL) {
			feth_unlock();
			return EOPNOTSUPP;
		}
		status = (fakeif->iff_peer != NULL)
		    ? (IFM_AVALID | IFM_ACTIVE) : IFM_AVALID;
		ifmr = (struct ifmediareq *)data;
		user_addr = (cmd == SIOCGIFMEDIA64) ?
		    ((struct ifmediareq64 *)ifmr)->ifmu_ulist :
		    CAST_USER_ADDR_T(((struct ifmediareq32 *)ifmr)->ifmu_ulist);
		count = ifmr->ifm_count;
		ifmr->ifm_active = IFM_ETHER;
		ifmr->ifm_current = IFM_ETHER;
		ifmr->ifm_mask = 0;
		ifmr->ifm_status = status;
		if (user_addr == USER_ADDR_NULL) {
			ifmr->ifm_count = fakeif->iff_media_count;
		} else if (count > 0) {
			if (count > fakeif->iff_media_count) {
				count = fakeif->iff_media_count;
			}
			ifmr->ifm_count = count;
			error = copyout(&fakeif->iff_media_list, user_addr,
			    count * sizeof(int));
		}
		feth_unlock();
		break;

	case SIOCGIFDEVMTU:
		devmtu_p = &ifr->ifr_devmtu;
		devmtu_p->ifdm_current = ifnet_mtu(ifp);
		devmtu_p->ifdm_max = feth_max_mtu(ifp);
		devmtu_p->ifdm_min = IF_MINMTU;
		break;

	case SIOCSIFMTU:
		if ((unsigned int)ifr->ifr_mtu > feth_max_mtu(ifp) ||
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
			user_addr = drv.ifdrvu_64->ifd_data;
		}
		if (drv_set_command) {
			error = feth_set_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
		} else {
			error = feth_get_drvspec(ifp, drv_cmd, drv_len,
			    user_addr);
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
feth_if_free(ifnet_t ifp)
{
	if_fake_ref             fakeif;

	if (ifp == NULL) {
		return;
	}
	feth_lock();
	fakeif = ifnet_get_if_fake(ifp);
	if (fakeif == NULL) {
		feth_unlock();
		return;
	}
	ifp->if_softc = NULL;
#if SKYWALK
	VERIFY(fakeif->iff_doorbell_tcall == NULL);
#endif /* SKYWALK */
	feth_unlock();
	feth_release(fakeif);
	ifnet_release(ifp);
	return;
}

__private_extern__ void
if_fake_init(void)
{
	int error;

#if SKYWALK
	(void)feth_register_nexus_domain_provider();
#endif /* SKYWALK */
	error = if_clone_attach(&feth_cloner);
	if (error != 0) {
		return;
	}
	return;
}
