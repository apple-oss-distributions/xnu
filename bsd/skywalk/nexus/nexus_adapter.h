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
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#ifndef _SKYWALK_NEXUS_ADAPTER_H_
#define _SKYWALK_NEXUS_ADAPTER_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/os_skywalk_private.h>
#include <skywalk/os_packet_private.h>

#define NEXUS_ADAPTER_NAMELEN   64

struct chreq;
struct kern_nexus;
struct __kern_channel_ring;
struct nexus_vp_adapter;
struct nexus_upipe_adapter;

typedef enum {
	NA_INVALID = 0,         /* uninitialized */
	NA_PSEUDO,              /* struct nexus_adapter */
#if CONFIG_NEXUS_USER_PIPE
	NA_USER_PIPE,           /* struct nexus_upipe_adapter */
#endif /* CONFIG_NEXUS_USER_PIPE */
#if CONFIG_NEXUS_KERNEL_PIPE
	NA_KERNEL_PIPE,         /* struct nexus_kpipe_adapter */
#endif /* CONFIG_NEXUS_KERNEL_PIPE */
#if CONFIG_NEXUS_MONITOR
	NA_MONITOR,             /* struct nexus_monitor_adapter */
#endif /* CONFIG_NEXUS_MONITOR */
#if CONFIG_NEXUS_NETIF
	NA_NETIF_DEV,           /* struct nexus_netif_adapter (dev) */
	NA_NETIF_HOST,          /* struct nexus_netif_adapter (host) */
	NA_NETIF_COMPAT_DEV,    /* struct nexus_netif_compat_adapter (dev) */
	NA_NETIF_COMPAT_HOST,   /* struct nexus_netif_compat_adapter (host) */
	NA_NETIF_FILTER,        /* struct nexus_netif_adapter (vp) */
	NA_NETIF_VP,            /* struct nexus_netif_adapter (vp) */
#endif /* CONFIG_NEXUS_NETIF */
#if CONFIG_NEXUS_FLOWSWITCH
	NA_FLOWSWITCH_VP,       /* struct nexus_vp_adapter */
#endif /* CONFIG_NEXUS_FLOWSWITCH */
} nexus_adapter_type_t;

typedef enum {
	NXSPEC_CMD_CONNECT =    0,
	NXSPEC_CMD_DISCONNECT = 1,
	NXSPEC_CMD_START =      2,
	NXSPEC_CMD_STOP =       3,
} nxspec_cmd_t;

typedef enum {
	NA_ACTIVATE_MODE_ON =   0,      /* activate adapter */
	NA_ACTIVATE_MODE_DEFUNCT,       /* defunct an activate adapter */
	NA_ACTIVATE_MODE_OFF,           /* deactivate adapter */
} na_activate_mode_t;

struct nexus_pkt_stats {
	uint64_t nps_pkts;
	uint64_t nps_bytes;
};

/*
 * The "struct nexus_adapter" contains all base fields needed to support
 * Nexus adapter operations.  There are different types of Nexus adapters
 * (upipe, kpipe, fsw, monitor, vp, ...) so a nexus_adapter is
 * always the first field in the derived type.
 */
struct nexus_adapter {
	volatile uint32_t               na_flags;       /* NAF_* flags */
	nexus_adapter_type_t            na_type;        /* nexus type */
	const nexus_meta_type_t         na_md_type;     /* metadata type */
	const nexus_meta_subtype_t      na_md_subtype;  /* metadata subtype */

	nexus_port_t na_nx_port;

	/*
	 * Number of user-space descriptors using this interface,
	 * which is equal to the number of channel schema objects
	 * in the mapped region.
	 */
	uint32_t na_channels;

	/* number of adapter transmit and receive rings */
	uint32_t na_num_rx_rings;
	uint32_t na_num_tx_rings;

	/* number of ring pairs used by packet allocator */
	uint32_t na_num_allocator_ring_pairs;

	/* number of event rings */
	uint32_t na_num_event_rings;

	uint64_t na_work_ts;            /* when we last worked on it */

	/*
	 * na_{tx,rx,alloc,free,event}_rings are private but allocated
	 * as a contiguous chunk of memory.
	 */
	struct __kern_channel_ring *na_tx_rings; /* array of TX rings. */
	struct __kern_channel_ring *na_rx_rings; /* array of RX rings. */

	/*
	 * na_nx refers to the nexus instance associated with this
	 * nexus adapter; in cases such as the virtual port adapter
	 * of a flow switch nexus used for user pipe, this will
	 * indicate the latter.  The na_nxdom_prov will point to
	 * the actual nexus domain associated with the adapter.
	 */
	struct kern_nexus *na_nx;

	/*
	 * Standard refcount to control the lifetime of the adapter
	 * (it should be equal to the lifetime of the corresponding ifp)
	 */
	volatile uint32_t na_refcount;

	int na_si_users[NR_ALL];         /* # of users per global wait queue */
	struct ch_selinfo na_si[NR_ALL]; /* global wait queues */

	/*
	 * Memory arena.
	 */
	struct skmem_arena *na_arena;

	/*
	 * Number of descriptor in each queue.
	 */
	uint32_t na_num_tx_slots;
	uint32_t na_num_rx_slots;
	uint32_t na_num_allocator_slots;
	uint32_t na_num_event_slots;

	/*
	 * Combined slot count of all rings.
	 * Used for allocating slot_ctx and scratch memory.
	 */
	uint32_t na_total_slots;

	/*
	 * For tracking ring memory allocated by sk_alloc()
	 */
	size_t na_rings_mem_sz;

	/*
	 * Flow advisory (if applicable).
	 */
	const uint32_t na_flowadv_max;  /* max # of flow advisory entries */

	/*
	 * Shareable statistics (if applicable).
	 */
	const nexus_stats_type_t na_stats_type; /* stats type */

	/*
	 * Array of packet allocator and event rings
	 */
	struct __kern_channel_ring *na_alloc_rings;
	struct __kern_channel_ring *na_free_rings;
	struct __kern_channel_ring *na_event_rings;

	uint64_t na_ch_mit_ival;        /* mitigation interval */

	/*
	 * The actual nexus domain associated with the adapter.
	 */
	struct kern_nexus_domain_provider *na_nxdom_prov;

	/*
	 * Array of slot contexts.  This covers enough space to hold
	 * slot contexts of slot_ctx size for all of the TX and RX rings,
	 * It is optional and is requested at na_krings_create() time.
	 */
	struct slot_ctx *na_slot_ctxs;

	/*
	 * Array of packet handlers, enough for all slots in the
	 * TX and RX rings of this adapter.  It is automatically
	 * created at na_krings_create() time.
	 */
	kern_packet_t *na_scratch;

	void *na_tailroom; /* space below the rings array (used for leases) */

#if CONFIG_NEXUS_FLOWSWITCH || CONFIG_NEXUS_NETIF
	/*
	 * Additional information attached to this adapter by other
	 * Skywalk subsystems; currently used by flow switch and netif.
	 */
	void *na_private;

	/*
	 * References to the ifnet and device routines, used by the netif
	 * nexus adapter functions.  A non-NULL na_ifp indicates an io ref
	 * count to the ifnet that needs to be released at adapter detach
	 * time (at which point it will be nullifed).
	 */
	struct ifnet *na_ifp;
	/*
	 * lookup table to retrieve the ring corresponding to a service
	 * class. we store the ring index in na_(tx/rx)_rings array.
	 */
	uint8_t na_kring_svc_lut[KPKT_SC_MAX_CLASSES];
#endif /* CONFIG_NEXUS_FLOWSWITCH || CONFIG_NEXUS_NETIF */

#if CONFIG_NEXUS_USER_PIPE
	uint32_t na_next_pipe;  /* next free slot in the array */
	uint32_t na_max_pipes;  /* size of the array */
	/* array of pipes that have this adapter as a parent */
	struct nexus_upipe_adapter **na_pipes;
#endif /* CONFIG_NEXUS_USER_PIPE */

	char na_name[NEXUS_ADAPTER_NAMELEN];    /* diagnostics */
	uuid_t na_uuid;

	/*
	 * na_activate() is called to activate, defunct or deactivate a nexus
	 * adapter.  This is invoked by na_bind_channel(), the first time a
	 * channel is opened to the adapter; by na_defunct() when an open
	 * channel gets defunct; as well as by na_unbind_channel() when the
	 * last channel instance opened to the adapter is closed.
	 */
	int (*na_activate)(struct nexus_adapter *, na_activate_mode_t);
	/*
	 * na_special() is an optional callback implemented by nexus types
	 * that support kernel channel (special mode).  This allows the nexus
	 * to override the logic surrounding na_{bind,unbind}_channel() calls.
	 */
	int (*na_special)(struct nexus_adapter *, struct kern_channel *,
	    struct chreq *, nxspec_cmd_t);
	/*
	 * na_txsync() pushes packets to the underlying device;
	 * na_rxsync() collects packets from the underlying device.
	 */
	int (*na_txsync)(struct __kern_channel_ring *kring, struct proc *,
	    uint32_t flags);
	int (*na_rxsync)(struct __kern_channel_ring *kring, struct proc *,
	    uint32_t flags);
#define NA_SYNCF_MONITOR                0x1
#define NA_SYNCF_FORCE_READ             0x2
#define NA_SYNCF_FORCE_RECLAIM          0x4
#define NA_SYNCF_NETIF                  0x8     /* netif normal sync */
#define NA_SYNCF_NETIF_ASYNC            0x10    /* asynchronous doorbell */
#define NA_SYNCF_NETIF_DOORBELL         0x20    /* doorbell request */
#define NA_SYNCF_NETIF_IFSTART          0x40    /* in if_start context */
#define NA_SYNCF_FORCE_UPP_SYNC         0x80    /* force upp sync alloc/free */
#define NA_SYNCF_UPP_PURGE              0x100   /* purge upp alloc pool */
#define NA_SYNCF_SYNC_ONLY              0x200   /* sync only, no doorbell */

	/*
	 * na_notify() is used to act ater data have become available,
	 * or the state of the ring has changed.  Depending on the nexus
	 * type, this may involve triggering an event and/or performing
	 * additional work such as calling na_txsync().
	 */
	int (*na_notify)(struct __kern_channel_ring *kring, struct proc *,
	    uint32_t flags);
#define NA_NOTEF_MONITOR        0x1
#define NA_NOTEF_IN_KEVENT      0x2
#define NA_NOTEF_CAN_SLEEP      0x4     /* OK to block in kr_enter() */
#define NA_NOTEF_NETIF          0x8     /* same as NA_SYNCF_NETIF */
#define NA_NOTEF_PUSH           0x100   /* need immediate attention */

	/*
	 * na_channel_event_notify() is used to send events on the user channel.
	 */
	int (*na_channel_event_notify)(struct nexus_adapter *,
	    struct __kern_packet *, struct __kern_channel_event *, uint16_t);
	/*
	 * na_config() is an optional callback for returning nexus-specific
	 * configuration information.  This is implemented by nexus types
	 * that handle dynamically changing configs.
	 */
	int (*na_config)(struct nexus_adapter *,
	    uint32_t *txr, uint32_t *txd, uint32_t *rxr, uint32_t *rxd);
	/*
	 * na_krings_create() creates and initializes the __kern_channel_ring
	 * arrays, as well as initializing the callback routines within;
	 * na_krings_delete() cleans up and destroys the kernel rings.
	 */
	int (*na_krings_create)(struct nexus_adapter *, struct kern_channel *);
	void (*na_krings_delete)(struct nexus_adapter *, struct kern_channel *,
	    boolean_t);
	/*
	 * na_dtor() is the destructor callback that is invoked when the
	 * last reference to the nexus adapter has been released.
	 */
	void (*na_dtor)(struct nexus_adapter *);
	/*
	 * na_free() is the free callback that gets invoked after the
	 * adapter has been destroyed.
	 */
	void (*na_free)(struct nexus_adapter *);

	/*
	 * packet-chain-based callbacks for passing packets up the stack.
	 * The inject variant is used by filters for rejecting packets
	 * into the rx path from user space.
	 */
	void (*na_rx)(struct nexus_adapter *,
	    struct __kern_packet *, struct nexus_pkt_stats *);
};

/* valid values for na_flags */
#define NAF_ACTIVE              0x1     /* skywalk is active */
#define NAF_HOST_ONLY           0x2     /* host adapter (no device rings) */
#define NAF_SPEC_INIT           0x4     /* na_special() initialized */
#define NAF_NATIVE              0x8     /* skywalk native netif adapter */
#define NAF_MEM_NO_INIT         0x10    /* na_kr_setup() skipped */
#define NAF_SLOT_CONTEXT        0x20    /* na_slot_ctxs is valid */
#define NAF_USER_PKT_POOL       0x40    /* na supports user packet pool */
#define NAF_TX_MITIGATION       0x80    /* na supports TX event mitigation */
#define NAF_RX_MITIGATION       0x100   /* na supports RX event mitigation */
#define NAF_DEFUNCT             0x200   /* no longer in service */
#define NAF_MEM_LOANED          0x400   /* arena owned by another adapter */
#define NAF_REJECT              0x800   /* not accepting channel activities */
#define NAF_EVENT_RING          0x1000  /* NA is providing event ring */
#define NAF_CHANNEL_EVENT_ATTACHED 0x2000 /* kevent registered for ch events */
#define NAF_VIRTUAL_DEVICE      0x8000  /* netif adapter for virtual device */
#define NAF_MODE_FSW            0x10000 /* NA is owned by fsw */
#define NAF_MODE_LLW            0x20000 /* NA is owned by llw */
#define NAF_LOW_LATENCY         0x40000 /* Low latency NA */
#define NAF_DRAINING            0x80000 /* NA is being drained */
/*
 * defunct allowed flag.
 * Currently used only by the parent nexus adapter of user-pipe nexus
 * to indicate that defuncting is allowed on the channels.
 */
#define NAF_DEFUNCT_OK          0x80000
#define NAF_KERNEL_ONLY (1U << 31) /* used internally, not usable by userland */

#define NAF_BITS                                                         \
	"\020\01ACTIVE\02HOST_ONLY\03SPEC_INIT\04NATIVE"                 \
	"\05MEM_NO_INIT\06SLOT_CONTEXT\07USER_PKT_POOL"                  \
	"\010TX_MITIGATION\011RX_MITIGATION\012DEFUNCT\013MEM_LOANED"    \
	"\014REJECT\015EVENT_RING\016EVENT_ATTACH"                       \
	"\020VIRTUAL\021MODE_FSW\022MODE_LLW\023LOW_LATENCY\024DRAINING" \
	"\040KERNEL_ONLY"

#define NA_FREE(na) do {                                                 \
	(na)->na_free(na);                                               \
} while (0)

/*
 * NA returns a pointer to the struct nexus_adapter from the ifp's netif nexus.
 */
#define NA(_ifp)                ((_ifp)->if_na)

__attribute__((always_inline))
static inline uint32_t
na_get_nslots(const struct nexus_adapter *na, enum txrx t)
{
	switch (t) {
	case NR_TX:
		return na->na_num_tx_slots;
	case NR_RX:
		return na->na_num_rx_slots;
	case NR_A:
	case NR_F:
		return na->na_num_allocator_slots;
	case NR_EV:
		return na->na_num_event_slots;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

__attribute__((always_inline))
static inline void
na_set_nslots(struct nexus_adapter *na, enum txrx t, uint32_t v)
{
	switch (t) {
	case NR_TX:
		na->na_num_tx_slots = v;
		break;
	case NR_RX:
		na->na_num_rx_slots = v;
		break;
	case NR_A:
	case NR_F:
		na->na_num_allocator_slots = v;
		break;
	case NR_EV:
		na->na_num_event_slots = v;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

__attribute__((always_inline))
static inline uint32_t
na_get_nrings(const struct nexus_adapter *na, enum txrx t)
{
	switch (t) {
	case NR_TX:
		return na->na_num_tx_rings;
	case NR_RX:
		return na->na_num_rx_rings;
	case NR_A:
	case NR_F:
		return na->na_num_allocator_ring_pairs;
	case NR_EV:
		return na->na_num_event_rings;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

__attribute__((always_inline))
static inline void
na_set_nrings(struct nexus_adapter *na, enum txrx t, uint32_t v)
{
	switch (t) {
	case NR_TX:
		na->na_num_tx_rings = v;
		break;
	case NR_RX:
		na->na_num_rx_rings = v;
		break;
	case NR_A:
	case NR_F:
		na->na_num_allocator_ring_pairs = v;
		break;
	case NR_EV:
		na->na_num_event_rings = v;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

__attribute__((always_inline))
static inline struct __kern_channel_ring *
NAKR(struct nexus_adapter *na, enum txrx t)
{
	switch (t) {
	case NR_TX:
		return na->na_tx_rings;
	case NR_RX:
		return na->na_rx_rings;
	case NR_A:
		return na->na_alloc_rings;
	case NR_F:
		return na->na_free_rings;
	case NR_EV:
		return na->na_event_rings;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

/*
 * If the adapter is owned by the kernel, neither another flow switch nor user
 * can use it; if the adapter is owned by a user, only users can share it.
 * Evaluation must be done under SK_LOCK().
 */
#define NA_KERNEL_ONLY(_na)     (((_na)->na_flags & NAF_KERNEL_ONLY) != 0)
#define NA_OWNED_BY_ANY(_na) \
	(NA_KERNEL_ONLY(_na) || ((_na)->na_channels > 0))
#define NA_OWNED_BY_FSW(_na) \
	(((_na)->na_flags & NAF_MODE_FSW) != 0)
#define NA_OWNED_BY_LLW(_na) \
	(((_na)->na_flags & NAF_MODE_LLW) != 0)

/*
 * Whether the adapter has been activated via na_activate() call.
 */
#define NA_IS_ACTIVE(_na)       (((_na)->na_flags & NAF_ACTIVE) != 0)
#define NA_IS_DEFUNCT(_na)       (((_na)->na_flags & NAF_DEFUNCT) != 0)
#define NA_CHANNEL_EVENT_ATTACHED(_na)   \
    (((_na)->na_flags & NAF_CHANNEL_EVENT_ATTACHED) != 0)
/*
 * Whether channel activities are rejected by the adapter.  This takes the
 * nexus adapter argument separately, as ch->ch_na may not be set yet.
 */
__attribute__((always_inline))
static inline boolean_t
na_reject_channel(struct kern_channel *ch, struct nexus_adapter *na)
{
	boolean_t reject;

	ASSERT(ch->ch_na == NULL || ch->ch_na == na);

	if ((na->na_flags & NAF_REJECT) || NX_REJECT_ACT(na->na_nx)) {
		/* set trapdoor NAF_REJECT flag */
		if (!(na->na_flags & NAF_REJECT)) {
			SK_ERR("%s(%d) marked as non-permissive",
			    ch->ch_name, ch->ch_pid);
			atomic_bitset_32(&na->na_flags, NAF_REJECT);
			ch_deactivate(ch);
		}
		reject = TRUE;
	} else {
		reject = FALSE;
	}

	return reject;
}

#if SK_LOG
__attribute__((always_inline))
static inline const char *
na_activate_mode2str(na_activate_mode_t m)
{
	switch (m) {
	case NA_ACTIVATE_MODE_ON:
		return "on";
	case NA_ACTIVATE_MODE_DEFUNCT:
		return "defunct";
	case NA_ACTIVATE_MODE_OFF:
		return "off";
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}
#endif /* SK_LOG */

__BEGIN_DECLS
extern void na_init(void);
extern void na_fini(void);

extern int na_bind_channel(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *);
extern void na_unbind_channel(struct kern_channel *ch);

/*
 * Common routine for all functions that create a nexus adapter. It performs
 * two main tasks:
 * - if the na points to an ifp, mark the ifp as Skywalk capable
 *   using na as its native adapter;
 * - provide defaults for the setup callbacks and the memory allocator
 */
extern void na_attach_common(struct nexus_adapter *,
    struct kern_nexus *, struct kern_nexus_domain_provider *);
/*
 * Update the ring parameters (number and size of tx and rx rings).
 * It calls the nm_config callback, if available.
 */
extern int na_update_config(struct nexus_adapter *na);

extern int na_rings_mem_setup(struct nexus_adapter *, uint32_t, boolean_t,
    struct kern_channel *);
extern void na_rings_mem_teardown(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
extern void na_ch_rings_defunct(struct kern_channel *, struct proc *);

/* convenience wrappers for na_set_all_rings, used in drivers */
extern void na_disable_all_rings(struct nexus_adapter *);
extern void na_enable_all_rings(struct nexus_adapter *);
extern void na_lock_all_rings(struct nexus_adapter *);
extern void na_unlock_all_rings(struct nexus_adapter *);
extern int na_interp_ringid(struct nexus_adapter *, ring_id_t, ring_set_t,
    uint32_t[NR_TXRX], uint32_t[NR_TXRX]);
extern struct kern_pbufpool *na_kr_get_pp(struct nexus_adapter *, enum txrx);

extern int na_find(struct kern_channel *, struct kern_nexus *,
    struct chreq *, struct kern_channel *, struct nxbind *,
    struct proc *, struct nexus_adapter **, boolean_t);
extern void na_retain_locked(struct nexus_adapter *na);
extern int na_release_locked(struct nexus_adapter *na);

extern int na_connect(struct kern_nexus *, struct kern_channel *,
    struct chreq *, struct kern_channel *, struct nxbind *, struct proc *);
extern void na_disconnect(struct kern_nexus *, struct kern_channel *);
extern void na_defunct(struct kern_nexus *, struct kern_channel *,
    struct nexus_adapter *, boolean_t);
extern int na_connect_spec(struct kern_nexus *, struct kern_channel *,
    struct chreq *, struct proc *);
extern void na_disconnect_spec(struct kern_nexus *, struct kern_channel *);
extern void na_start_spec(struct kern_nexus *, struct kern_channel *);
extern void na_stop_spec(struct kern_nexus *, struct kern_channel *);

extern int na_pseudo_create(struct kern_nexus *, struct chreq *,
    struct nexus_adapter **);
extern void na_kr_drop(struct nexus_adapter *, boolean_t);
extern void na_flowadv_entry_alloc(const struct nexus_adapter *, uuid_t,
    const flowadv_idx_t);
extern void na_flowadv_entry_free(const struct nexus_adapter *, uuid_t,
    const flowadv_idx_t);
extern bool na_flowadv_set(const struct nexus_adapter *,
    const flowadv_idx_t, const flowadv_token_t);
extern boolean_t na_flowadv_clear(const struct kern_channel *,
    const flowadv_idx_t, const flowadv_token_t);
extern void na_flowadv_event(struct __kern_channel_ring *);
extern void na_post_event(struct __kern_channel_ring *, boolean_t, boolean_t,
    boolean_t, uint32_t);

extern void na_drain(struct nexus_adapter *, boolean_t);

__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_NEXUS_ADAPTER_H_ */
