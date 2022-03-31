/*
 * Copyright (c) 2015-2020 Apple Inc. All rights reserved.
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
 * Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo, Giuseppe Lettieri.
 * All rights reserved.
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

#ifndef _SKYWALK_CHANNEL_CHANNELVAR_H_
#define _SKYWALK_CHANNEL_CHANNELVAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/os_channel_private.h>
#include <skywalk/nexus/nexus_mbq.h>
#include <skywalk/nexus/nexus_pktq.h>
#include <skywalk/mem/skmem_region_var.h>
#include <skywalk/mem/skmem_arena_var.h>

struct ch_selinfo {
	decl_lck_mtx_data(, csi_lock);
	struct selinfo  csi_si;
	uint32_t        csi_flags;
	uint32_t        csi_pending;
	uint64_t        csi_eff_interval;
	uint64_t        csi_interval;
	thread_call_t   csi_tcall;
};

/* values for csi_flags */
#define CSI_KNOTE               0x1             /* kernel note attached */
#define CSI_MITIGATION          0x10            /* has mitigation */
#define CSI_DESTROYED           (1U << 31)      /* has been destroyed */

#define CSI_LOCK(_csi)                  \
	lck_mtx_lock(&(_csi)->csi_lock)
#define CSI_LOCK_ASSERT_HELD(_csi)      \
	LCK_MTX_ASSERT(&(_csi)->csi_lock, LCK_MTX_ASSERT_OWNED)
#define CSI_LOCK_ASSERT_NOTHELD(_csi)   \
	LCK_MTX_ASSERT(&(_csi)->csi_lock, LCK_MTX_ASSERT_NOTOWNED)
#define CSI_UNLOCK(_csi)                        \
	lck_mtx_unlock(&(_csi)->csi_lock)

/* mitigation intervals in ns */
#define CH_MIT_IVAL_DEFAULT     (0)
#define CH_MIT_IVAL_WIFI        CH_MIT_IVAL_DEFAULT
#define CH_MIT_IVAL_CELLULAR    CH_MIT_IVAL_DEFAULT
#define CH_MIT_IVAL_ETHERNET    CH_MIT_IVAL_DEFAULT

/*
 * Kernel version of __user_slot_desc.
 *
 * Keep slot descriptor as minimal as possible.
 * TODO: wshen0123@apple.com -- Should we make use of RX/TX
 * preparation/writeback descriptors (in a union)?
 */
struct __kern_slot_desc {
	union {
		struct __kern_quantum *sd_qum;
		struct __kern_packet *sd_pkt;
		struct __kern_buflet *sd_buf;
		void *sd_md;                    /* metadata address */
	};

#ifndef __LP64__
	uint32_t        _sd_pad[1];
#endif /* !__LP64__ */
};

/* _sd_{user,kern} are at same offset in the preamble */
#define SLOT_DESC_KSD(_sdp)     \
	((struct __kern_slot_desc *)((uintptr_t)&(_sdp)->_sd_private))

/*
 * Optional, per-slot context information.  An array of these structures
 * is allocated per nexus_adapter, and each real kring will have its slots
 * correspond to one.  This the 'arg' value is retrieved via the slot_init
 * nexus provider callback, and is retrievable via subsequently via calls
 * to kern_channel_slot_get_context().
 */
struct slot_ctx {
	mach_vm_address_t       slot_ctx_arg;   /* per-slot context */
};

extern lck_attr_t channel_lock_attr;
extern uint64_t __ch_umd_redzone_cookie;
extern uint32_t kr_stat_enable;

struct kern_nexus;
enum na_sync_mode;

struct kern_channel {
	decl_lck_mtx_data(, ch_lock);
	struct nexus_adapter    *ch_na;
	struct kern_nexus       *ch_nexus;
	struct ch_info          *ch_info;
	struct kern_pbufpool    *ch_pp;

	uint32_t                ch_refcnt;
	volatile uint32_t       ch_flags;       /* CHANF_* flags */

	/* range of tx/rx/allocator/event rings to scan */
	ring_id_t               ch_first[NR_ALL];
	ring_id_t               ch_last[NR_ALL];

	struct __user_channel_schema *ch_schema;

	/*
	 * Pointers to the selinfo to be used for selrecord.
	 * Either the local or the global one depending on the
	 * number of rings.
	 */
	struct ch_selinfo       *ch_si[NR_ALL];

	STAILQ_ENTRY(kern_channel) ch_link;
	STAILQ_ENTRY(kern_channel) ch_link_if_adv;
	void                    *ch_ctx;
	mach_vm_offset_t        ch_schema_offset;
	struct skmem_arena_mmap_info ch_mmap;
	int                     ch_fd;          /* might be -1 if no fd */
	pid_t                   ch_pid;         /* process ID */
	char                    ch_name[32];    /* process name */
};

/* valid values for ch_flags */
#define CHANF_ATTACHED          0x1     /* attached and connected to nexus */
#define CHANF_PLATFORM          0x2     /* platform binary process */
#define CHANF_KERNEL            0x4     /* kernel only; has no task map */
#define CHANF_RXONLY            0x8     /* receive only, no transmit */
#define CHANF_USER_PACKET_POOL  0x10    /* userspace using packet pool */
#define CHANF_EXCLUSIVE         0x20    /* exclusive bind to ring(s) */
#define CHANF_NONXREF           0x40    /* has no nexus reference */
#define CHANF_HOST              0x80    /* opened to host (kernel) stack */
#define CHANF_EXT_SKIP          0x100   /* don't notify external provider */
#define CHANF_EXT_PRECONNECT    0x200   /* successful nxpi_pre_connect() */
#define CHANF_EXT_CONNECTED     0x400   /* successful nxpi_connected() */
#define CHANF_EVENT_RING        0x1000  /* channel has event rings */
#define CHANF_IF_ADV            0x2000  /* interface advisory is active */
#define CHANF_DEFUNCT_SKIP      0x4000  /* defunct skipped due to active use */
#define CHANF_CLOSING           (1U << 30) /* channel is being closed */
#define CHANF_DEFUNCT           (1U << 31) /* channel is now defunct */

#define CHANF_BITS                                                      \
	"\020\01ATTACHED\02PLATFORM\03KERNEL\04RXONLY\05USER_PKT_POOL"  \
	"\06EXCLUSIVE\07NONXREF\010HOST\011EXT_SKIP\012EXT_PRECONNECT"  \
	"\013EXT_CONNECTED\015EVENT\016ADVISORY"            \
	"\017DEFUNCT_SKIP\037CLOSING\040DEFUNCT"

/* valid values for ch_kevhints */
#define CHAN_FILT_HINT_FLOW_ADV_UPD     0x1     /* flow advisory update */
#define CHAN_FILT_HINT_CHANNEL_EVENT    0x2     /* channel event */
#define CHAN_FILT_HINT_IF_ADV_UPD       0x4     /* Interface advisory update */

#define CHAN_FILT_HINT_BITS    "\020\01FLOW_ADV\02CHANNEL_EVENT\03IF_ADV"

typedef enum {
	RING_SET_ALL = 0,               /* all rings */
	RING_SET_DEFAULT = RING_SET_ALL,
} ring_set_t;

typedef enum {
	CH_ENDPOINT_NULL = 0,
	CH_ENDPOINT_USER_PIPE_MASTER,
	CH_ENDPOINT_USER_PIPE_SLAVE,
	CH_ENDPOINT_KERNEL_PIPE,
	CH_ENDPOINT_NET_IF,
	CH_ENDPOINT_FLOW_SWITCH,
} ch_endpoint_t;

#define CHREQ_NAMELEN   64

struct chreq {
	char            cr_name[CHREQ_NAMELEN];         /* in */
	uuid_t          cr_spec_uuid;                   /* in */
	struct ch_ev_thresh cr_tx_lowat;                /* in */
	struct ch_ev_thresh cr_rx_lowat;                /* in */
	nexus_port_t    cr_port;                        /* in/out */
	uint32_t        cr_mode;                        /* in */
	uint32_t        cr_pipe_id;                     /* in */
	ring_id_t       cr_ring_id;                     /* in */
	ring_set_t      cr_ring_set;                    /* out */
	ch_endpoint_t   cr_real_endpoint;               /* out */
	ch_endpoint_t   cr_endpoint;                    /* out */
	mach_vm_size_t  cr_memsize;                     /* out */
	mach_vm_offset_t cr_memoffset;                  /* out */
};

/*
 * Private, kernel view of a ring.  Keeps track of the status of
 * a ring across system calls.
 *
 *	ckr_khead	Index of the next buffer to refill.  It corresponds
 *			to ring_head at the time the system call returns.
 *
 *	ckr_ktail	Index of the first buffer owned by the kernel.
 *
 *			On RX, ckr_khead to ckr_ktail are receive buffers that
 *			are not yet released.  ckr_khead is advanced following
 *			ring_head, ckr_ktail is advanced on incoming packets.
 *
 *			On TX, ckr_rhead has been filled by the sender but not
 *			sent yet to the destination; ckr_rhead to ckr_ktail are
 *			available for new transmissions, and ckr_ktail to
 *			ckr_khead-1 are pending transmissions.
 *
 * Here is the layout for the RX and TX rings.
 *
 *            RX RING                         TX RING
 *
 *       +-----------------+            +-----------------+
 *       |                 |            |                 |
 *       |XXX free slot XXX|            |XXX free slot XXX|
 *       +-----------------+            +-----------------+
 * head->| owned by user   |<-khead     | not sent to nic |<-khead
 *       |                 |            | yet             |
 *       |                 |            |                 |
 *       +-----------------+            +     ------      +
 * tail->|                 |<-ktail     |                 |<-klease
 *       | (being          | ...        |                 | ...
 *       |  prepared)      | ...        |                 | ...
 *       +-----------------+ ...        |                 | ...
 *       |                 |<-klease    +-----------------+
 *       |                 |      tail->|                 |<-ktail
 *       |                 |            |                 |
 *       |                 |            |                 |
 *       |                 |            |                 |
 *       +-----------------+            +-----------------+
 *
 * The head/tail (user view) and khead/ktail (kernel view)
 * are used in the normal operation of the adapter.
 *
 * For flow switch nexus:
 *
 * The following fields are used to implement lock-free copy of packets
 * from input to output ports in flow switch:
 *
 *	ckr_klease	Buffer after the last one being copied.
 *			A writer in nx_fsw_vp_flush() reserves N buffers
 *			from ckr_klease, advances it, then does the
 *			copy outside the lock.
 *
 *			In RX rings (used for flow switch ports):
 *				ckr_ktail <= ckr_klease < nkr_khead+N-1
 *
 *			In TX rings (used for NIC or host stack ports):
 *				nkr_khead <= ckr_klease < nkr_ktail
 *
 *	ckr_leases	Array of ckr_num_slots where writers can report
 *			completion of their block. CKR_NOSLOT (~0) indicates
 *			that the writer has not finished yet
 *
 *	ckr_lease_idx	Index of next free slot in ckr_leases, to be assigned.
 *
 * The kring is manipulated by txsync/rxsync and generic kring function.
 *
 * Concurrent rxsync or txsync on the same ring are prevented through
 * by na_kr_(try)get() which in turn uses ckr_busy.  This is all we need
 * for NIC rings, and for TX rings attached to the host stack.
 *
 * RX rings attached to the host stack use an nx_mbq (ckr_rx_queue) on both
 * nx_netif_rxsync_from_host() and nx_netif_compat_transmit(). The nx_mbq is
 * protected by its internal lock.
 *
 * RX rings attached to the flow switch are accessed by both senders
 * and receiver.  They are protected through the q_lock on the RX ring.
 *
 * When a ring is the output of a switch port (RX ring for a flow switch
 * port, TX ring for the host stack or NIC), slots are reserved in blocks
 * through ckr_klease which points to the next unused slot.
 *
 * On an RX ring, ckr_klease is always after ckr_ktail, and completions cause
 * ckr_ktail to advance.  On a TX ring, ckr_klease is always between ckr_khead
 * and ckr_ktail, and completions cause ckr_khead to advance.
 *
 * nx_fsw_vp_na_kr_space()
 *   returns the maximum number of slots that can be assigned.
 *
 * nx_fsw_vp_na_kr_lease() reserves the required number of buffers,
 *    advances ckr_klease and also returns an entry in a circular
 *    array where completions should be reported.
 *
 * For netif nexus:
 *
 * The indexes in the NIC and rings are offset by ckr_hwofs slots.  This is
 * so that, on a reset, buffers owned by userspace are not modified by the
 * kernel.  In particular:
 *
 * RX rings: the next empty buffer (ckr_ktail + ckr_hwofs) coincides with
 *      the next empty buffer as known by the hardware "next to check".
 * TX rings: ckr_khead + ckr_hwofs coincides with "next to send".
 *
 */
typedef int (*channel_ring_notify_t)(struct __kern_channel_ring *,
    struct proc *, uint32_t);

struct __kern_channel_ring {
	struct __user_channel_ring      *ckr_ring;

	uint32_t                ckr_flags;      /* CKRF_* flags */
	slot_idx_t              ckr_num_slots;  /* # of slots */
	uint32_t                ckr_max_pkt_len;/* max pp pkt size */
	uint32_t                ckr_largest;    /* largest packet seen */
	const slot_idx_t        ckr_lim; /* ckr_num_slots - 1 */
	enum txrx               ckr_tx;  /* kind of ring (tx/rx/alloc/free) */

	volatile slot_idx_t     ckr_khead;
	volatile slot_idx_t     ckr_ktail;
	/*
	 * value of ckr_khead recorded at TX prologue (pre-sync)
	 */
	volatile slot_idx_t     ckr_khead_pre;
	/*
	 * Copies of values in user rings, so we do not need to look
	 * at the ring (which could be modified). These are set in the
	 * *sync_prologue()/finalize() routines.
	 */
	volatile slot_idx_t     ckr_rhead;
	volatile slot_idx_t     ckr_rtail;

	/* EWMA decay rate */
	uint32_t                ckr_transfer_decay;

	uint64_t                ckr_ready_bytes;
	uint64_t                ckr_ready_slots;

	/*
	 * While ckr_state is set, no new [tr]xsync operations can be
	 * started on this kring.  This is used by na_disable_all_rings()
	 * to find a synchronization point where critical data structures
	 * pointed to by the kring can be added or removed.
	 */
	decl_lck_spin_data(, ckr_slock);
	struct thread *ckr_owner; /* busy owner */
	uint32_t ckr_busy;      /* prevent kring modifications */
	uint32_t ckr_want;      /* # of threads that lost the race */
	uint32_t ckr_state;     /* KR_* states */

	/* current working set for the allocator ring */
	volatile uint32_t       ckr_alloc_ws;

	struct nexus_adapter *ckr_na;   /* adapter this kring belongs to */
	struct kern_pbufpool *ckr_pp;   /* adapter's packet buffer pool */

	/*
	 * Array of __slot_desc each representing slot-specific data, e.g.
	 * index to metadata, etc.  There is exactly one descriptor for each
	 * slot in the ring.  Note that the size of the array may be greater
	 * than the number of slots for this ring, and so we constrain
	 * range with [ckr_ksds, ckr_ksds_last] during validations.
	 */
	struct __slot_desc *ckr_usds;   /* slot desc array (user) */
	struct __slot_desc *ckr_ksds;   /* slot desc array (kernel) */
	struct __slot_desc *ckr_ksds_last; /* cache last ksd */
	struct skmem_cache *ckr_ksds_cache; /* owning skmem_cache for ksd */

	uint32_t        ckr_ring_id;      /* ring ID */

	boolean_t       ckr_rate_limited; /* ring is rate limited */

	/*
	 * Array of packet handles for as many slots as there are in the
	 * ring; this is useful for storing an array of kern_packet_t to
	 * be used when invoking the packet APIs.  Only safe to be used
	 * in the context of a sync as we're single-threaded then.
	 * The memory is owned by the nexus adapter.
	 */
	uint64_t        *ckr_scratch;

	/*
	 * [tx]sync callback for this kring.  The default na_kring_create
	 * callback (na_kr_create) sets the ckr_na_sync callback of each
	 * tx(rx) kring to the corresponding na_txsync(na_rxsync) taken
	 * from the nexus_adapter.
	 *
	 * Overrides: the above configuration is not changed by
	 * any of the nm_krings_create callbacks.
	 */
	int (*ckr_na_sync)(struct __kern_channel_ring *,
	    struct proc *, uint32_t);
	int(*volatile ckr_na_notify)(struct __kern_channel_ring *,
	    struct proc *, uint32_t);

	int (*ckr_prologue)(struct kern_channel *,
	    struct __kern_channel_ring *, const slot_idx_t,
	    uint32_t *, uint64_t *, struct proc *);
	void (*ckr_finalize)(struct kern_channel *,
	    struct __kern_channel_ring *, const slot_idx_t, struct proc *);

	/* time of last channel sync (updated at sync prologue time) */
	uint64_t        ckr_sync_time;

#if CONFIG_NEXUS_FLOWSWITCH
	/* The following fields are for flow switch support */
	int (*ckr_save_notify)(struct __kern_channel_ring *kring,
	    struct proc *, uint32_t flags);
	uint32_t        *ckr_leases;
#define CKR_NOSLOT      ((uint32_t)~0)  /* used in nkr_*lease* */
	slot_idx_t      ckr_klease;
	slot_idx_t      ckr_lease_idx;
#endif /* CONFIG_NEXUS_FLOWSWITCH */

	kern_packet_svc_class_t ckr_svc;

	/*
	 * (Optional) array of slot contexts for as many slots as there
	 * are in the ring; the memory is owned by the nexus adapter.
	 */
	uint32_t        ckr_slot_ctxs_set; /* number of valid/set contexts */
	struct slot_ctx *ckr_slot_ctxs; /* (optional) array of slot contexts */

	void            *ckr_ctx;       /* ring context */

	struct ch_selinfo ckr_si;       /* per-ring wait queue */

#if CONFIG_NEXUS_NETIF
	/*
	 * netif adapters intercepts ckr_na_notify in order to
	 * mitigate IRQ events; the actual notification is done
	 * by invoking the original notify callback routine
	 * saved at na_activate() time.
	 */
	int (*ckr_netif_notify)(struct __kern_channel_ring *kring,
	    struct proc *, uint32_t flags);
	void (*ckr_netif_mit_stats)(struct __kern_channel_ring *kring,
	    uint64_t, uint64_t);
	struct nx_netif_mit *ckr_mit;

	volatile uint32_t ckr_pending_intr;
	volatile uint32_t ckr_pending_doorbell;

	/*
	 * Support for adapters without native Skywalk support.
	 * On tx rings we preallocate an array of tx buffers
	 * (same size as the channel ring), on rx rings we
	 * store incoming mbufs in a queue that is drained by
	 * a rxsync.
	 */
	struct mbuf     **ckr_tx_pool;
	struct nx_mbq   ckr_rx_queue;   /* intercepted rx mbufs. */
#endif /* CONFIG_NEXUS_NETIF */

#if CONFIG_NEXUS_USER_PIPE
	/* if this is a pipe ring, pointer to the other end */
	struct __kern_channel_ring *ckr_pipe;
	/* pointer to hidden rings see nx_user_pipe.c for details) */
	struct __user_channel_ring *ckr_save_ring;
#endif /* CONFIG_NEXUS_USER_PIPE */

	/*
	 * Protects kring in the event of multiple writers;
	 * only used by flow switch and monitor.
	 */
	decl_lck_mtx_data(, ckr_qlock);

#if CONFIG_NEXUS_MONITOR
	/* array of krings that are monitoring this kring */
	struct __kern_channel_ring **ckr_monitors;
	uint32_t ckr_max_monitors; /* current size of the monitors array */
	uint32_t ckr_n_monitors; /* next unused entry in the monitor array */
	/*
	 * Monitors work by intercepting the sync and notify callbacks of the
	 * monitored krings. This is implemented by replacing the pointers
	 * above and saving the previous ones in mon_* pointers below
	 */
	int (*ckr_mon_sync)(struct __kern_channel_ring *kring, struct proc *,
	    uint32_t flags);
	int (*ckr_mon_notify)(struct __kern_channel_ring *kring, struct proc *,
	    uint32_t flags);

	uint32_t ckr_mon_tail;  /* last seen slot on rx */
	/* index of this ring in the monitored ring array */
	uint32_t ckr_mon_pos;
#endif /* CONFIG_NEXUS_MONITOR */

	uint32_t        ckr_users;      /* existing bindings for this ring */

	/* ring flush rate limit */
	int64_t         ckr_tbr_token;
	int64_t         ckr_tbr_depth;
	uint64_t        ckr_tbr_last;
#define CKR_TBR_TOKEN_INVALID   INT64_MAX

	/* stats capturing errors */
	channel_ring_error_stats ckr_err_stats
	__attribute__((aligned(sizeof(uint64_t))));

	/* stats capturing actual data movement (nexus provider's view) */
	channel_ring_stats ckr_stats
	__attribute__((aligned(sizeof(uint64_t))));
	uint64_t        ckr_accumulated_bytes;
	uint64_t        ckr_accumulated_slots;
	uint64_t        ckr_accumulate_start; /* in seconds */

	/* stats capturing user activities per sync (user's view) */
	channel_ring_user_stats ckr_usr_stats
	__attribute__((aligned(sizeof(uint64_t))));
	uint64_t        ckr_user_accumulated_bytes;
	uint64_t        ckr_user_accumulated_slots;
	uint64_t        ckr_user_accumulated_syncs;
	uint64_t        ckr_user_accumulate_start; /* in seconds */

	lck_grp_t       *ckr_qlock_group;
	lck_grp_t       *ckr_slock_group;

	char            ckr_name[64];   /* diagnostic */
} __attribute__((__aligned__(CHANNEL_CACHE_ALIGN_MAX)));

#define KR_LOCK(_kr)                    \
	lck_mtx_lock(&(_kr)->ckr_qlock)
#define KR_LOCK_SPIN(_kr)               \
	lck_mtx_lock_spin(&(_kr)->ckr_qlock)
#define KR_LOCK_TRY(_kr)                \
	lck_mtx_try_lock(&(_kr)->ckr_qlock)
#define KR_LOCK_ASSERT_HELD(_kr)        \
	LCK_MTX_ASSERT(&(_kr)->ckr_qlock, LCK_MTX_ASSERT_OWNED)
#define KR_LOCK_ASSERT_NOTHELD(_kr)     \
	LCK_MTX_ASSERT(&(_kr)->ckr_qlock, LCK_MTX_ASSERT_NOTOWNED)
#define KR_UNLOCK(_kr)                  \
	lck_mtx_unlock(&(_kr)->ckr_qlock)

/* valid values for ckr_flags */
#define CKRF_EXCLUSIVE          0x1     /* exclusive binding */
#define CKRF_DROP               0x2     /* drop all mode */
#define CKRF_HOST               0x4     /* host ring */
#define CKRF_MEM_RING_INITED    0x8     /* na_kr_setup() succeeded */
#define CKRF_MEM_SD_INITED      0x10    /* na_kr_setup() succeeded  */
#define CKRF_EXT_RING_INITED    0x20    /* nxpi_ring_init() succeeded */
#define CKRF_EXT_SLOTS_INITED   0x40    /* nxpi_slot_init() succeeded */
#define CKRF_SLOT_CONTEXT       0x80    /* ckr_slot_ctxs is valid */
#define CKRF_MITIGATION         0x100   /* supports event mitigation */
#define CKRF_DEFUNCT            0x200   /* no longer in service */
#define CKRF_KERNEL_ONLY        (1U << 31) /* not usable by userland */

#define CKRF_BITS                                                       \
	"\020\01EXCLUSIVE\02DROP\03HOST\04MEM_RING_INITED"              \
	"\05MEM_SD_INITED\06EXT_RING_INITED\07EXT_SLOTS_INITED"         \
	"\010SLOT_CONTEXT\011MITIGATION\012DEFUNCT\040KERNEL_ONLY"

#define KRNA(_kr)       \
	((__DECONST(struct __kern_channel_ring *, _kr))->ckr_na)

#define KR_KERNEL_ONLY(_kr)     \
	(((_kr)->ckr_flags & CKRF_KERNEL_ONLY) != 0)
#define KR_DROP(_kr)            \
	(((_kr)->ckr_flags & (CKRF_DROP|CKRF_DEFUNCT)) != 0)

/* valid values for ckr_state */
enum {
	KR_READY = 0,
	KR_STOPPED,             /* unbounded stop */
	KR_LOCKED,              /* bounded, brief stop for mutual exclusion */
};

#define KR_KSD(_kring, _slot_idx)       \
	(SLOT_DESC_KSD(&(_kring)->ckr_ksds[_slot_idx]))

#define KR_USD(_kring, _slot_idx)       \
	(SLOT_DESC_USD(&(_kring)->ckr_usds[_slot_idx]))

__attribute__((always_inline))
static inline slot_idx_t
KR_SLOT_INDEX(const struct __kern_channel_ring *kr,
    const struct __slot_desc *slot)
{
	ASSERT(slot >= kr->ckr_ksds && slot <= kr->ckr_ksds_last);
	return (slot_idx_t)(slot - kr->ckr_ksds);
}

/* Helper macros for slot descriptor, decoupled for KSD/USD. */

#define KSD_VALID_METADATA(_ksd)                                        \
	((_ksd)->sd_md != NULL)

#define KSD_INIT(_ksd) do {                                             \
	(_ksd)->sd_md = NULL;                                           \
} while (0)

#define KSD_ATTACH_METADATA(_ksd, _md_addr) do {                        \
	ASSERT((_ksd) != NULL);                                         \
	ASSERT((_ksd)->sd_md == NULL);                                  \
	(_ksd)->sd_md = (_md_addr);                                     \
} while (0)

#define KSD_DETACH_METADATA(_ksd) do {                                  \
	ASSERT((_ksd) != NULL);                                         \
	ASSERT((_ksd)->sd_md != NULL);                                  \
	(_ksd)->sd_md = NULL;                                           \
} while (0)

#define KSD_RESET(_ksd) KSD_INIT(_ksd)

#define USD_INIT(_usd) do {                                             \
	(_usd)->sd_md_idx = OBJ_IDX_NONE;                               \
	(_usd)->sd_flags = 0;                                           \
	(_usd)->sd_len = 0;                                             \
} while (0)

#define USD_ATTACH_METADATA(_usd, _md_idx) do {                         \
	ASSERT((_usd) != NULL);                                         \
	ASSERT((_usd)->sd_md_idx == OBJ_IDX_NONE);                      \
	ASSERT(((_usd)->sd_flags & SD_IDX_VALID) == 0);                 \
	(_usd)->sd_md_idx = (_md_idx);                                  \
	(_usd)->sd_flags |= SD_IDX_VALID;                               \
	/* mask off non-user flags */                                   \
	(_usd)->sd_flags &= SD_FLAGS_USER;                              \
} while (0);

#define USD_DETACH_METADATA(_usd) do {                                  \
	ASSERT((_usd) != NULL);                                         \
	(_usd)->sd_md_idx = OBJ_IDX_NONE;                               \
	/* mask off non-user flags */                                   \
	(_usd)->sd_flags &= SD_FLAGS_USER;                              \
	(_usd)->sd_flags &= ~SD_IDX_VALID;                              \
} while (0)

#define USD_RESET(_usd) USD_INIT(_usd)

#define USD_SET_LENGTH(_usd, _md_len) do {                              \
	ASSERT((_usd) != NULL);                                         \
	(_usd)->sd_len = _md_len;                                       \
} while (0)

#define _USD_COPY(_src, _dst) do {                                      \
	_CASSERT(sizeof (struct __user_slot_desc) == 8);                \
	sk_copy64_8((uint64_t *)(void *)_src, (uint64_t *)(void *)_dst); \
} while (0)

#define _USD_SWAP(_usd1, _usd2) do {                                    \
	struct __user_slot_desc _tusd                                   \
	    __attribute((aligned(sizeof (uint64_t))));                  \
	_USD_COPY(_usd1, &_tusd);                                       \
	_USD_COPY(_usd2, _usd1);                                        \
	_USD_COPY(&_tusd, _usd2);                                       \
} while (0)

#define _KSD_COPY(_src, _dst) do {                                      \
	_CASSERT(sizeof (struct __kern_slot_desc) == 8);                \
	sk_copy64_8((uint64_t *)(void *)_src, (uint64_t *)(void *)_dst); \
} while (0)

#define _KSD_SWAP(_ksd1, _ksd2) do {                                    \
	struct __kern_slot_desc _tksd                                   \
	    __attribute((aligned(sizeof (uint64_t))));                  \
	_KSD_COPY(_ksd1, &_tksd);                                       \
	_KSD_COPY(_ksd2, _ksd1);                                        \
	_KSD_COPY(&_tksd, _ksd2);                                       \
} while (0)

#define SD_SWAP(_ksd1, _usd1, _ksd2, _usd2) do {                        \
	_USD_SWAP(_usd1, _usd2);                                        \
	_KSD_SWAP(_ksd1, _ksd2);                                        \
	/* swap packet attachment */                                    \
	*(struct __kern_slot_desc **)(uintptr_t)&(_ksd1)->sd_qum->qum_ksd = \
	    (_ksd1); \
	*(struct __kern_slot_desc **)(uintptr_t)&(_ksd2)->sd_qum->qum_ksd = \
	    (_ksd2); \
} while (0)

#define _MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim) do { \
	struct __kern_quantum *_q = SK_PTR_ADDR_KQUM(_md);              \
	switch (METADATA_TYPE(_q)) {                                    \
	case NEXUS_META_TYPE_PACKET: {                                  \
	        struct __kern_packet *_p =                              \
	            (struct __kern_packet *)(void *)(_md);              \
	        struct __kern_buflet *_kbft;                            \
	        PKT_GET_FIRST_BUFLET(_p, _p->pkt_bufs_cnt, _kbft);      \
	        (_addr) = __DECONST(void *, _kbft->buf_addr);           \
	        (_objaddr) = _kbft->buf_objaddr;                        \
	        (_doff) = _kbft->buf_doff;                              \
	        (_dlen) = _kbft->buf_dlen;                              \
	        (_dlim) = _kbft->buf_dlim;                              \
	        break;                                                  \
	}                                                               \
	default:                                                        \
	        (_addr) = __DECONST(void *, _q->qum_buf[0].buf_addr);   \
	        (_objaddr) = _q->qum_buf[0].buf_objaddr;                \
	        (_doff) = _q->qum_buf[0].buf_doff;                      \
	        (_dlen) = _q->qum_buf[0].buf_dlen;                      \
	        (_dlim) = _q->qum_buf[0].buf_dlim;                      \
	        break;                                                  \
	}                                                               \
	ASSERT((_addr) != NULL);                                        \
	ASSERT((_objaddr) != NULL);                                     \
} while (0)

#define _MD_BUFLET_ADDR_PKT(_md, _addr) do { \
	ASSERT(METADATA_TYPE(SK_PTR_ADDR_KQUM(_md)) ==                  \
	    NEXUS_META_TYPE_PACKET);                                    \
	struct __kern_packet *_p = (struct __kern_packet *)(void *)(_md); \
	struct __kern_buflet *_kbft;                                    \
	PKT_GET_FIRST_BUFLET(_p, _p->pkt_bufs_cnt, _kbft);              \
	(_addr) = __DECONST(void *, _kbft->buf_addr);                   \
	ASSERT((_addr) != NULL);                                        \
} while (0)


/*
 * Return the data offset adjusted virtual address of a buffer associated
 * with the metadata; for metadata with multiple buflets, this is the
 * first buffer's address.
 */
#define MD_BUFLET_ADDR(_md, _val) do {                                  \
	void *_addr, *_objaddr;                                         \
	uint16_t _doff, _dlen, _dlim;                                   \
	_MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim);  \
	/* skip past buflet data offset */                              \
	(_val) = (void *)((uint8_t *)_addr + _doff);                    \
} while (0)

/*
 * Return the absolute virtual address of a buffer associated with the
 * metadata; for metadata with multiple buflets, this is the first
 * buffer's address.
 */
#define MD_BUFLET_ADDR_ABS(_md, _val) do {                              \
	void *_addr, *_objaddr;                                         \
	uint16_t _doff, _dlen, _dlim;                                   \
	_MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim);  \
	(_val) = (void *)_addr;                                         \
} while (0)

/* similar to MD_BUFLET_ADDR_ABS() but optimized only for packets */
#define MD_BUFLET_ADDR_ABS_PKT(_md, _val) do {                          \
	void *_addr;                                                    \
	_MD_BUFLET_ADDR_PKT(_md, _addr);                                \
	(_val) = (void *)_addr;                                         \
} while (0)


#define MD_BUFLET_ADDR_ABS_DLEN(_md, _val, _dlen, _dlim, _doff) do {    \
	void *_addr, *_objaddr;                                         \
	_MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim);  \
	(_val) = (void *)_addr;                                         \
} while (0)


/*
 * Return the buffer's object address associated with the metadata; for
 * metadata with multiple buflets, this is the first buffer's object address.
 */
#define MD_BUFLET_OBJADDR(_md, _val) do {                               \
	void *_addr, *_objaddr;                                         \
	uint16_t _doff, _dlen, _dlim;                                   \
	_MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim);  \
	(_val) = (void *)_objaddr;                                      \
} while (0)

/*
 * Return the data offset adjusted virtual address of a buffer associated
 * with the metadata; for metadata with multiple buflets, this is the
 * first buffer's address and data length.
 */
#define MD_BUFLET_ADDR_DLEN(_md, _val, _dlen) do {                      \
	void *_addr, *_objaddr;                                         \
	uint16_t _doff, _dlim;                                          \
	_MD_BUFLET_ADDROFF(_md, _addr, _objaddr, _doff, _dlen, _dlim);  \
	/* skip past buflet data offset */                              \
	(_val) = (void *)((uint8_t *)_addr + _doff);                    \
} while (0)

/* kr_space: return available space for enqueue into kring */
__attribute__((always_inline))
static inline uint32_t
kr_available_slots(struct __kern_channel_ring *kr)
{
	int busy;
	uint32_t space;

	busy = (int)(kr->ckr_klease - kr->ckr_khead);
	if (busy < 0) {
		busy += kr->ckr_num_slots;
	}
	space = kr->ckr_lim - (uint32_t)busy;

	return space;
}

/* kr_space: return available space for enqueue into Rx kring */
__attribute__((always_inline))
static inline uint32_t
kr_available_slots_rxring(struct __kern_channel_ring *rxkring)
{
	int busy;
	uint32_t space;

	/* # of rx busy (unclaimed) slots */
	busy = (int)(rxkring->ckr_ktail - rxkring->ckr_khead);
	if (busy < 0) {
		busy += rxkring->ckr_num_slots;
	}

	/* # of rx avail free slots (subtract busy from max) */
	space = rxkring->ckr_lim - (uint32_t)busy;
	return space;
}

/*
 * kr_reserve_slots: reserve n slots from kr in range [start, end).
 * return ticket for later publish those reserved correspondingly.
 */
__attribute__((always_inline))
static inline uint32_t
kr_reserve_slots_locked(struct __kern_channel_ring *kr, uint32_t n,
    uint32_t *start, uint32_t *end, uint32_t *ticket)
{
	uint32_t n_available;
	const uint32_t lim = kr->ckr_lim;

	n_available = kr_available_slots(kr);
	if (n > n_available) {
		n = n_available;
	}

	*ticket = kr->ckr_lease_idx;
	kr->ckr_leases[*ticket] = CKR_NOSLOT;
	kr->ckr_lease_idx = SLOT_NEXT(*ticket, lim);

	*start = kr->ckr_klease;
	*end = *start + n;
	if (*end > lim) {
		*end -= lim + 1;
	}
	kr->ckr_klease = *end;

	ASSERT(kr->ckr_khead < kr->ckr_num_slots);
	ASSERT(kr->ckr_ktail < kr->ckr_num_slots);
	ASSERT(kr->ckr_klease < kr->ckr_num_slots);
	ASSERT(kr->ckr_lease_idx < kr->ckr_num_slots);

	return n;
}

/*
 * kr_publish_slots: publish slots previously reserved in [start, end).
 * Should only be called after slots and associated packets have been deep
 * enqueued and made available.
 */
__attribute__((always_inline))
static inline void
kr_publish_slots(struct __kern_channel_ring *kr, struct proc *p,
    uint32_t start, uint32_t end, uint32_t ticket)
{
	uint32_t *l = kr->ckr_leases;
	uint32_t update_pos;
	boolean_t new_bufs = FALSE;

	ASSERT(start < kr->ckr_num_slots);
	ASSERT(end < kr->ckr_num_slots);
	ASSERT(ticket < kr->ckr_num_slots);

	l[ticket] = end;

	KR_LOCK(kr);
	update_pos = kr->ckr_ktail;
	if (__probable(start == update_pos)) {
		/*
		 * All slots before start have been reported,
		 * so scan subsequent leases to see if other ranges
		 * have been completed, and to a selwakeup or txsync.
		 */
		while (ticket != kr->ckr_lease_idx &&
		    l[ticket] != CKR_NOSLOT) {
			end = l[ticket];
			l[ticket] = CKR_NOSLOT;
			ticket = SLOT_NEXT(ticket, kr->ckr_lim);
		}
		/*
		 * end is the new 'write' position. end != start
		 * means there are new buffers to report
		 */
		if (__probable(end != start)) {
			kr->ckr_ktail = end;
			new_bufs = TRUE;
		}
	}
	KR_UNLOCK(kr);

	if (new_bufs) {
		kr->ckr_na_notify(kr, p, 0);
	}
}

extern kern_allocation_name_t skmem_tag_ch_key;

#if (DEVELOPMENT || DEBUG)
SYSCTL_DECL(_kern_skywalk_channel);
#endif /* !DEVELOPMENT && !DEBUG */

__BEGIN_DECLS
extern int channel_init(void);
extern void channel_fini(void);

extern struct kern_channel *ch_open(struct ch_init *, struct proc *,
    int, int *);
extern struct kern_channel *ch_open_special(struct kern_nexus *,
    struct chreq *, boolean_t, int *);
extern void ch_close(struct kern_channel *, boolean_t);
extern void ch_close_special(struct kern_channel *);
extern int ch_kqfilter(struct kern_channel *, struct knote *,
    struct kevent_qos_s *kev);
extern boolean_t ch_is_multiplex(struct kern_channel *, enum txrx);
extern int ch_select(struct kern_channel *, int, void *, struct proc *);
extern int ch_get_opt(struct kern_channel *, struct sockopt *);
extern int ch_set_opt(struct kern_channel *, struct sockopt *);
extern void ch_deactivate(struct kern_channel *);
extern void ch_retain(struct kern_channel *);
extern void ch_retain_locked(struct kern_channel *);
extern int ch_release(struct kern_channel *);
extern int ch_release_locked(struct kern_channel *);
extern void ch_dtor(void *);

extern void csi_init(struct ch_selinfo *, boolean_t, uint64_t);
extern void csi_destroy(struct ch_selinfo *);
extern void csi_selrecord_one(struct __kern_channel_ring *, struct proc *,
    void *);
extern void csi_selrecord_all(struct nexus_adapter *, enum txrx, struct proc *,
    void *);
extern void csi_selwakeup_one(struct __kern_channel_ring *, boolean_t,
    boolean_t, boolean_t, uint32_t);
extern void csi_selwakeup_all(struct nexus_adapter *, enum txrx, boolean_t,
    boolean_t, boolean_t, uint32_t);

extern void kr_init_to_mhints(struct __kern_channel_ring *, uint32_t);
extern int kr_enter(struct __kern_channel_ring *, boolean_t);
extern void kr_exit(struct __kern_channel_ring *);
extern void kr_start(struct __kern_channel_ring *);
extern void kr_stop(struct __kern_channel_ring *kr, uint32_t state);
extern void kr_update_stats(struct __kern_channel_ring *kring,
    uint32_t slot_count, uint32_t byte_count);
extern boolean_t kr_txempty(struct __kern_channel_ring *kring);
extern uint32_t kr_reclaim(struct __kern_channel_ring *kr);

extern slot_idx_t kr_txsync_prologue(struct kern_channel *,
    struct __kern_channel_ring *, struct proc *);
extern int kr_txprologue(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, uint32_t *, uint64_t *,
    struct proc *);
extern int kr_txprologue_upp(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, uint32_t *, uint64_t *,
    struct proc *);

extern void kr_txsync_finalize(struct kern_channel *,
    struct __kern_channel_ring *, struct proc *);
extern void kr_txfinalize(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, struct proc *p);
extern void kr_txfinalize_upp(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, struct proc *p);

extern slot_idx_t kr_rxsync_prologue(struct kern_channel *ch,
    struct __kern_channel_ring *kring, struct proc *p);
extern int kr_rxprologue(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, uint32_t *, uint64_t *,
    struct proc *);
extern int kr_rxprologue_nodetach(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, uint32_t *, uint64_t *,
    struct proc *);
extern int kr_rxprologue_upp(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, uint32_t *, uint64_t *,
    struct proc *);

extern void kr_rxsync_finalize(struct kern_channel *ch,
    struct __kern_channel_ring *kring, struct proc *p);
extern void kr_rxfinalize(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, struct proc *p);
extern void kr_rxfinalize_upp(struct kern_channel *,
    struct __kern_channel_ring *, const slot_idx_t, struct proc *p);

extern void kr_txkring_reclaim_and_refill(struct __kern_channel_ring *kring,
    slot_idx_t index);
extern slot_idx_t kr_alloc_sync_prologue(struct __kern_channel_ring *kring,
    struct proc *p);
extern slot_idx_t kr_free_sync_prologue(struct __kern_channel_ring *kring,
    struct proc *p);
extern void kr_alloc_sync_finalize(struct __kern_channel_ring *kring,
    struct proc *p);
extern void kr_free_sync_finalize(struct __kern_channel_ring *kring,
    struct proc *p);
extern int kr_internalize_metadata(struct kern_channel *,
    struct __kern_channel_ring *, const uint32_t, struct __kern_quantum *,
    struct proc *);
extern void kr_externalize_metadata(struct __kern_channel_ring *,
    const uint32_t, struct __kern_quantum *, struct proc *);
extern slot_idx_t kr_event_sync_prologue(struct __kern_channel_ring *kring,
    struct proc *p);
extern void kr_event_sync_finalize(struct kern_channel *ch,
    struct __kern_channel_ring *kring, struct proc *p);

#if SK_LOG
extern void kr_log_bad_ring(struct __kern_channel_ring *);
#else
#define kr_log_bad_ring(_kr)    do { ((void)0); } while (0)
#endif /* SK_LOG */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_CHANNEL_CHANNELVAR_H_ */
