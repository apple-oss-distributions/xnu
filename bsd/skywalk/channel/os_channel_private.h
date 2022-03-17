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

#ifndef _SKYWALK_OS_CHANNEL_PRIVATE_H_
#define _SKYWALK_OS_CHANNEL_PRIVATE_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/guarded.h>
#include <sys/utsname.h>
#include <skywalk/os_channel.h>
#include <skywalk/os_stats_private.h>

/* BEGIN CSTYLED */
/*
 * The userspace data structures used by Skywalk are shown below.
 *
 * The kernel allocates the regions for the various object types,
 * and maps them to the userspace task in a contiguous span, one
 * after another.
 *
 * Each channel file descriptor comes with its own memory map,
 * and the layout of the rest of the objects is described in the
 * __user_channel_schema structure associated with the channel.
 * This schema structure is mapped read-only in the task.
 *
 *     +=======================+
 *     | __user_channel_schema | (1 per channel fd)
 *     +=======================+
 *     |     csm_ver           |
 *     |     csm_flags         |
 *     |-----------------------|
 *     |     csm_tx_rings      |
 *     |     csm_rx_rings      |
 *     | csm_allocator_rings   |
 *     |    csm_event_rings    |
 *     |-----------------------|
 *     |     csm_stats_ofs     | <<---+
 *     |-----------------------|      |
 *     |     csm_flowadv_max   |      |
 *     |     csm_flowadv_ofs   | <<---+ relative to base of memory map
 *     |-----------------------|      |
 *     | csm_md_redzone_cookie |      |
 *     |     csm_md_type       |      |
 *     |     csm_md_subtype    |      |
 *     |-----------------------|      |
 *     |     csm_stats_ofs     | <<---+
 *     |     csm_stats_type    |      |
 *     |-----------------------|      |
 *     |     csm_nexusadv_ofs  | <<---+
 *     |-----------------------|
 *     |     csm_kern_name     |
 *     |     csm_kern_uuid     |
 *     |-----------------------|
 *     | TX  csm_ring_ofs[0]   | <<---+
 *     | TX  csm_sd_ofs[0]     |      |
 *     :        ...            :      |
 *     | TX  csm_ring_ofs[t]   |      |
 *     | TX  csm_sd_ofs[t]     |      |
 *     |-----------------------|      |
 *     | RX  csm_ring_ofs[0]   | <<---+ these offsets are relative
 *     | RX  csm_sd_ofs[0]     |      | to each schema structure
 *     :        ...            :      |
 *     | RX  csm_ring_ofs[t]   |      |
 *     | RX  csm_sd_ofs[t]     |      |
 *     |-----------------------|      |
 *     | A   csm_ring_ofs[0]   |      |
 *     | A   csm_sd_ofs[0]     |      |
 *     :        ...            :      |
 *     | A   csm_ring_ofs[t]   | <<---+
 *     | A   csm_sd_ofs[t]     |      |
 *     |-----------------------|      |
 *     | F   csm_ring_ofs[0]   |      |
 *     | F   csm_sd_ofs[0]     |      |
 *     :        ...            :      |
 *     | F   csm_ring_ofs[t]   | <<---+
 *     | F   csm_sd_ofs[t]     |      |
 *     |-----------------------|      |
 *     | EV  csm_ring_ofs[0]   | <<---+
 *     | EV  csm_sd_ofs[0]     |
 *     +-----------------------+
 *         (variable length)
 *
 * On nexus adapters that support statistics or flow advisory, the
 * csm_stats_ofs or csm_flowadv_ofs would be non-zero, and their values
 * represent the offset to the respective objects from the base of the
 * memory map.  This is because those regions are shared amongst all
 * channels opened to the adapter associated with the nexus port.
 *
 * Other regions, such as rings and slot descriptors, are unique to the
 * channel itself.  They are always present, and their values indicated
 * by csm_{ring,sd}_ofs represent the offset to the respective objects
 * from the schema pointer (not from base of memory map.)  This is done
 * to support channels bound to any of the adapter's ring-pairs.
 *
 * See notes below on CSM_CURRENT_VERSION.
 */
/* END CSTYLED */
#define CHANNEL_SCHEMA_KERN_NAME        _SYS_NAMELEN
struct __user_channel_schema {
	/*
	 * Schema properties, kernel version string and kernel
	 * executable UUID (for debugging).  These 4 fields
	 * must be at the beginning of the structure.
	 */
	const uint32_t  csm_ver;                /* schema layout version */
	const volatile uint32_t csm_flags;      /* CSM_* flags */
	const char      csm_kern_name[CHANNEL_SCHEMA_KERN_NAME];
	const uuid_t    csm_kern_uuid;

	/*
	 * The rest of the fields may be rearranged as needed, with
	 * the expectation that CSM_CURRENT_VERSION be bumped up on
	 * each modification.
	 */

	/*
	 * The number of packet rings available for this channel.
	 */
	const uint32_t  csm_tx_rings;   /* # of tx rings */
	const uint32_t  csm_rx_rings;   /* # of rx rings */

	/*
	 * The number of allocator ring pair available for this channel.
	 * If the channel supports user packet pool then 1 pair of
	 * alloc/free ring per channel are used to manage the packet
	 * allocation from userspace.
	 * If the channel supports multi-buflet packet then an additional pair
	 * of alloc/free ring is used to manage the buffer (buflet) allocation
	 * from userspace.
	 */
	const uint32_t  csm_allocator_ring_pairs;

	/*
	 * number of event rings for this channel.
	 */
	const uint32_t  csm_num_event_rings;

	/*
	 * Flow advisory region offset; this field will be 0 if the
	 * nexus isn't capable of flow advisory scheme.  Otherwise,
	 * it points to a table of flow advisory entries, and the
	 * total number of entries is indicated by csm_flowadv_max.
	 */
	const uint32_t          csm_flowadv_max;
	const mach_vm_offset_t  csm_flowadv_ofs
	__attribute__((aligned(sizeof(uint64_t))));

	/*
	 * Metadata region redzone, type and sub-type.
	 */
	const uint64_t  csm_md_redzone_cookie   /* metadata redzone cookie */
	__attribute__((aligned(sizeof(uint64_t))));
	const nexus_meta_type_t csm_md_type;    /* metadata type */
	const nexus_meta_subtype_t csm_md_subtype; /* metadata subtype */

	/*
	 * Statistics region offset; each nexus is free to use this
	 * region and break it up into multiple smaller regions if
	 * needed.  The definition and interpretation of the contents
	 * is left to the nexus.  The value of this field will be 0
	 * if the nexus doesn't facilitate shareable statistics.
	 */
	const mach_vm_offset_t  csm_stats_ofs
	__attribute__((aligned(sizeof(uint64_t))));
	const nexus_stats_type_t csm_stats_type;

	/*
	 * Nexus advisory region offset; this field will be 0 if the
	 * nexus isn't providing any nexus-wide advisories.  Otherwise,
	 * it points to the nexus advisory structure.
	 */
	const mach_vm_offset_t csm_nexusadv_ofs
	__attribute__((aligned(sizeof(uint64_t))));

	/*
	 * The following array contains the offset of each channel ring
	 * from the beginning of this structure, as well as the ring's
	 * slot descriptor, in the following order:
	 *
	 * tx rings (csm_tx_rings-csm_htx_rings)
	 * rx rings (csm_rx_rings-csm_hrx_rings)
	 * allocator rings (either 2 or 4 or none) (optional)
	 * event rings (optional)
	 *
	 * The area is filled up by the kernel, and then only read
	 * by userspace code.
	 */
	struct {
		const mach_vm_offset_t  ring_off; /* __user_channel_ring */
		const mach_vm_offset_t  sd_off;   /* __slot_desc */
	} csm_ring_ofs[0] __attribute__((aligned(sizeof(uint64_t))));
};

/*
 * Schema layout version.  Make sure to bump this up each time
 * struct __user_channel_schema layout is modified.  This helps
 * to ensure that both kernel and libsystem_kernel are in sync,
 * as otherwise we'd assert due to version mismatch.
 */
#define CSM_CURRENT_VERSION     14

/* valid values for csm_flags */
#define CSM_PRIV_MEM    0x1             /* private memory region */
#define CSM_ACTIVE      (1U << 31)      /* channel is active */

#define CSM_BITS        "\020\01PRIV_MEM\040ACTIVE"

/* the size of __user_channel_schema structure for n total rings */
#define CHANNEL_SCHEMA_SIZE(n) \
	__builtin_offsetof(struct __user_channel_schema, csm_ring_ofs[(n)])

/*
 * Some fields should be cache-aligned to reduce contention.
 * The alignment is architecture and OS dependent; we use an
 * estimate that should cover most architectures.
 */
#define CHANNEL_CACHE_ALIGN_MAX 128     /* max cache line size */

/*
 * Ring kind.
 */
#define CR_KIND_RX              0       /* same as NR_RX */
#define CR_KIND_TX              1       /* same as NR_TX */
#define CR_KIND_ALLOC           2       /* same as NR_A */
#define CR_KIND_FREE            3       /* same as NR_F */
#define CR_KIND_EVENT           4       /* same as NR_EV */

typedef uint32_t slot_idx_t;

typedef uint32_t obj_idx_t;
#define OBJ_IDX_NONE    ((obj_idx_t)-1)

/*
 * This structure contains per-slot properties for userspace.  If the flag
 * SD_IDX_VALID is set, the descriptor contains the index of the metadata
 * attached to the slot.
 *
 * TODO: adi@apple.com -- this will be made read-write for user pool.
 * TODO: wshen0123@apple.com -- Should we make use of RX/TX
 * preparation/writeback descriptors (in a union) for sd_len?
 */
struct __user_slot_desc {
	obj_idx_t       sd_md_idx;      /* metadata index */
	uint16_t        sd_flags;       /* slot flags */
	/*
	 * XXX: sd_len is currently used only for the purpose of acoounting
	 * for the number of bytes pending to be read by the user channel.
	 * Currently the maximum size of a packet being transported on user
	 * channel is <= UINT16_MAX, so sd_len being uint16_t is fine, but
	 * this needs to be changed if we want to go beyond UINT16_MAX.
	 */
	uint16_t        sd_len;         /* slot len */
};

/* valid values for sd_flags */
#define SD_IDX_VALID    0x1             /* slot has metadata attached */
#ifdef KERNEL
#define SD_LEN_VALID    0x2             /* slot has packet length recorded */
#define SD_KERNEL_ONLY  (1 << 15)       /* kernel only; no user counterpart */

#define SD_FLAGS_USER   (SD_IDX_VALID)
/* invariant flags we want to keep */
#define SD_SAVE_MASK    (SD_KERNEL_ONLY)
#endif /* KERNEL */
/*
 * SD_VALID_METADATA() returns TRUE if the slot has an attached metadata
 */
#define SD_VALID_METADATA(_sd)                                          \
	(!!((_sd)->sd_flags & SD_IDX_VALID))

/*
 * Slot descriptor.
 */
struct __slot_desc {
	union {
		struct __user_slot_desc _sd_user;
		uint64_t                _sd_private[1];
	};
};

#define SLOT_DESC_SZ            (sizeof (struct __slot_desc))
#define SLOT_DESC_USD(_sdp)     (&(_sdp)->_sd_user)

/*
 * Ring.
 *
 * Channel representation of a TX or RX ring (also known as "queue").
 * This is a queue implemented as a fixed-size circular array.
 * At the software level the important fields are: head, cur, tail.
 *
 * The __user_channel_ring, and all slots and buffers in the range
 * [head .. tail-1] are owned by the user program; the kernel only
 * accesses them during a channel system call and in the user thread
 * context.
 */
struct __user_channel_ring {
	/*
	 * In TX rings:
	 *
	 *   head	first slot available for transmission;
	 *   tail	(readonly) first slot reserved to the kernel
	 *   khead	(readonly) kernel's view of next slot to send
	 *		since last sync.
	 *
	 * [head .. tail-1] can be used for new packets to send;
	 *
	 * 'head' must be incremented as slots are filled with new packets to
	 * be sent;
	 *
	 * In RX rings:
	 *
	 *   head	first valid received packet;
	 *   tail	(readonly) first slot reserved to the kernel
	 *   khead	(readonly) kernel's view of next slot to reclaim
	 *		since last sync.
	 *
	 * [head .. tail-1] contain received packets;
	 *
	 * 'head' must be incremented as slots are consumed and can be returned
	 * to the kernel;
	 *
	 */
	volatile slot_idx_t     ring_head;      /* (u) first user slot */
	const volatile slot_idx_t ring_tail;    /* (k) first kernel slot */
	const volatile slot_idx_t ring_khead;   /* (k) next to send/reclaim */

	const uint32_t  ring_num_slots; /* # of slots in the ring */
	const uint32_t  ring_buf_size;  /* size of each buffer */
	const uint16_t  ring_md_size;   /* size of each metadata */
	const uint16_t  ring_bft_size;  /* size of each buflet metadata */
	const uint16_t  ring_id;        /* unused */
	const uint16_t  ring_kind;      /* kind of ring (tx or rx) */

	/*
	 * Base addresses of {buf, metadata, slot descriptor} regions
	 * from this ring descriptor.  This facilitates computing the
	 * addresses of those regions in the task's mapped memory.
	 */
	const mach_vm_offset_t  ring_buf_base   /* base of buffer region */
	__attribute((aligned(sizeof(uint64_t))));
	const mach_vm_offset_t  ring_md_base    /* base of metadata region */
	__attribute((aligned(sizeof(uint64_t))));
	const mach_vm_offset_t  ring_sd_base    /* base of slot desc region */
	__attribute((aligned(sizeof(uint64_t))));
	/*
	 * base of buflet metadata region
	 * value of 0 means that external buflet metadata is not present.
	 */
	const mach_vm_offset_t  ring_bft_base
	__attribute((aligned(sizeof(uint64_t))));

	const volatile uint64_t ring_sync_time /* (k) time of last sync */
	__attribute((aligned(sizeof(uint64_t))));
	const volatile uint64_t ring_notify_time /* (k) time of last notify */
	__attribute((aligned(sizeof(uint64_t))));
	/* current working set for the packet allocator ring */
	const volatile uint32_t ring_alloc_ws;
	/* current working set for the buflet allocator ring */
	const volatile uint32_t ring_alloc_buf_ws;
};

/* check if space is available in the ring */
#define CHANNEL_RING_EMPTY(_ring) ((_ring)->ring_head == (_ring)->ring_tail)

/*
 * Flow advisory.
 *
 * Each flow that is registered with the nexus capable of supporting
 * flow advisory is given an entry.  Each entry resides in the flow
 * advisory table that is mapped to the task.
 */
struct __flowadv_entry {
	union {
		uint64_t        fae_id_64[2];
		uint32_t        fae_id_32[4];
		uuid_t          fae_id;         /* flow ID */
	};
#ifdef KERNEL
#define fae_token               fae_id_32[0]
#endif /* KERNEL */
	volatile uint32_t       fae_flags;      /* flags */
	uint32_t                __fae_pad;
} __attribute__((aligned(sizeof(uint64_t))));

#define FLOWADVF_VALID          0x1     /* flow is valid */
#define FLOWADVF_SUSPENDED      0x2     /* flow is suspended */

/* channel event threshold */
struct ch_ev_thresh {
	channel_threshold_unit_t cet_unit;
	uint32_t                cet_value;
};

/*
 * Channel information.
 */
struct ch_info {
	union {
		uint64_t  cinfo_ch_id_64[2];
		uint32_t  cinfo_ch_id_32[4];
		uuid_t    cinfo_ch_id;          /* Channel UUID */
	};
#ifdef KERNEL
#define cinfo_ch_token  cinfo_ch_id_32[0]
#endif /* KERNEL */
	uint32_t          cinfo_ch_mode;        /* CHMODE_* flags */
	ring_id_t         cinfo_ch_ring_id;     /* Channel ring (or any) */
	struct nxprov_params cinfo_nxprov_params; /* Nexus provider params */
	uuid_t            cinfo_nx_uuid;        /* Nexus instance UUID */
	nexus_port_t      cinfo_nx_port;        /* Nexus instance port */
	uint32_t          cinfo_num_bufs;       /* # buffers in user pool */
	mach_vm_size_t    cinfo_mem_map_size;   /* size of VM map */
	mach_vm_address_t cinfo_mem_base;       /* VM mapping for task */
	mach_vm_offset_t  cinfo_schema_offset;  /* offset in VM map */
	ring_id_t         cinfo_first_tx_ring;  /* first TX ring ID */
	ring_id_t         cinfo_last_tx_ring;   /* last TX ring ID */
	ring_id_t         cinfo_first_rx_ring;  /* first RX ring ID */
	ring_id_t         cinfo_last_rx_ring;   /* last RX ring ID */
	struct ch_ev_thresh cinfo_tx_lowat;     /* TX low-watermark */
	struct ch_ev_thresh cinfo_rx_lowat;     /* RX low-watermark */
} __attribute__((aligned(sizeof(uint64_t))));

#include <skywalk/os_nexus_private.h>

#define CHANNEL_INIT_VERSION_1          1
#define CHANNEL_INIT_CURRENT_VERSION    CHANNEL_INIT_VERSION_1

/*
 * Channel init parameters.
 */
struct ch_init {
	uint32_t        ci_version;     /* in: CHANNEL_INIT_CURRENT_VERSION */
	uint32_t        ci_ch_mode;     /* in: CHMODE_* flags */
	ring_id_t       ci_ch_ring_id;  /* in: Channel ring */
	nexus_port_t    ci_nx_port;     /* in: Nexus instance port */
	uuid_t          ci_nx_uuid;     /* in: Nexus instance UUID */
	user_addr_t     ci_key;         /* in: key blob */
	uint32_t        ci_key_len;     /* in: key length */
	uint32_t        __ci_align;     /* reserved */
	struct ch_ev_thresh ci_tx_lowat; /* in: TX low-watermark */
	struct ch_ev_thresh ci_rx_lowat; /* in: RX low-watermark */
	guardid_t       ci_guard;       /* out: guard ID */
};

#define CHMODE_MONITOR_TX               0x00000001
#define CHMODE_MONITOR_RX               0x00000002
#define CHMODE_MONITOR_NO_COPY          0x00000004     /* only if mon tx/rx is set */
#define CHMODE_USER_PACKET_POOL         0x00000008
#define CHMODE_DEFUNCT_OK               0x00000010
#define CHMODE_FILTER                   0x00000020     /* packet filter channel */
#define CHMODE_EVENT_RING               0x00000040
#define CHMODE_LOW_LATENCY              0x00000080
#define CHMODE_EXCLUSIVE                0x00000200
#define CHMODE_MONITOR                  \
	(CHMODE_MONITOR_TX | CHMODE_MONITOR_RX)
#ifdef KERNEL
/* mask off userland-settable bits */
#define CHMODE_MASK                                     \
	(CHMODE_MONITOR | CHMODE_MONITOR_NO_COPY |      \
	CHMODE_USER_PACKET_POOL | CHMODE_FILTER  |      \
	CHMODE_DEFUNCT_OK | CHMODE_EVENT_RING | CHMODE_EXCLUSIVE | \
	CHMODE_LOW_LATENCY)
#define CHMODE_KERNEL                   0x00001000  /* special, in-kernel */
#define CHMODE_NO_NXREF                 0x00002000  /* does not hold nx refcnt */
#define CHMODE_CONFIG                   0x00004000  /* provider config mode */
#define CHMODE_HOST                     0x00008000  /* to host (kernel) stack */

#define CHMODE_BITS                                                       \
	"\020\01MON_TX\02MON_RX\03NO_COPY\04USER_PKT_POOL"                \
	"\05DEFUNCT_OK\06FILTER\07EVENT_RING\010LOW_LATENCY\012EXCLUSIVE" \
	"\015KERNEL\016NO_NXREF\017CONFIG\020HOST"
#endif /* KERNEL */

/*
 * Channel options.
 */
#define CHOPT_TX_LOWAT_THRESH   1  /* (get/set) ch_ev_thresh */
#define CHOPT_RX_LOWAT_THRESH   2  /* (get/set) ch_ev_thresh */
#define CHOPT_IF_ADV_CONF       3  /* (set) enable/disable interface advisory events on the channel */

#ifndef KERNEL
/*
 * Channel ring descriptor.
 */
struct channel_ring_desc {
	const struct channel    *chrd_channel;
	const volatile uint32_t *chrd_csm_flags;
	const struct __user_channel_ring *chrd_ring;

	/*
	 * Array of __slot_desc each representing slot-specific data.
	 * There is exactly one descriptor for each slot in the ring.
	 */
	struct __slot_desc *chrd_slot_desc;

	/* local per-ring copies for easy access */
	const nexus_meta_type_t chrd_md_type;
	const nexus_meta_subtype_t chrd_md_subtype;
	const mach_vm_address_t chrd_shmem_base_addr;
	const mach_vm_address_t chrd_buf_base_addr;
	const mach_vm_address_t chrd_md_base_addr;
	const mach_vm_address_t chrd_sd_base_addr;
	const mach_vm_address_t chrd_bft_base_addr;
	const uint32_t          chrd_max_bufs; /* max length of buflet chain */
} __attribute__((aligned(sizeof(uint64_t))));

/*
 * Channel descriptor.
 */
struct channel {
	int             chd_fd;
	sync_flags_t    chd_sync_flags;
	guardid_t       chd_guard;
	struct ch_info  *chd_info;

	const volatile struct __user_channel_schema *chd_schema;
	const volatile void *chd_nx_stats;
	const volatile struct __flowadv_entry *chd_nx_flowadv;
	const volatile struct __kern_nexus_adv_metadata *chd_nx_adv;

	const nexus_meta_type_t chd_md_type;
	const nexus_meta_subtype_t chd_md_subtype;
	const uint8_t chd_alloc_ring_idx;
	const uint8_t chd_free_ring_idx;
	const uint8_t chd_buf_alloc_ring_idx;
	const uint8_t chd_buf_free_ring_idx;
#if defined(LIBSYSCALL_INTERFACE)
#define CHD_RING_IDX_NONE    (uint8_t)-1
#endif /* LIBSYSCALL_INTERFACE */

	/*
	 * Per-ring descriptor, aligned at max cache line boundary
	 */
	struct channel_ring_desc        chd_rings[0]
	__attribute__((aligned(sizeof(uint64_t))));
};

#define CHD_SIZE(n) \
	((size_t)(&((struct channel *)0)->chd_rings[n]))

#define CHD_INFO_SIZE           (sizeof (struct ch_info))
#define CHD_INFO(_chd)          ((_chd)->chd_info)
#define CHD_PARAMS(_chd)        (&CHD_INFO(_chd)->cinfo_nxprov_params)
#define CHD_SCHEMA(_chd)        \
	(__DECONST(struct __user_channel_schema *, (_chd)->chd_schema))
#define CHD_NX_STATS(_chd)      \
	(__DECONST(void *, (_chd)->chd_nx_stats))
#define CHD_NX_FLOWADV(_chd)    \
	(__DECONST(struct __flowadv_entry *, (_chd)->chd_nx_flowadv))
#define CHD_NX_ADV_MD(_chd)    __DECONST(struct __kern_nexus_adv_metadata *, \
    ((_chd)->chd_nx_adv))
#define CHD_NX_ADV_NETIF(_adv_md)    \
    (struct netif_nexus_advisory *)(void *)(_adv_md + 1)
#define CHD_NX_ADV_FSW(_adv_md)    (struct sk_nexusadv *)(void *)(_adv_md + 1)

/*
 * Channel attributes.
 */
struct channel_attr {
	uint32_t        cha_tx_rings;
	uint32_t        cha_rx_rings;
	uint32_t        cha_tx_slots;
	uint32_t        cha_rx_slots;
	uint32_t        cha_buf_size;
	uint32_t        cha_meta_size;
	uint32_t        cha_stats_size;
	uint32_t        cha_exclusive;
	uint32_t        cha_monitor;
	uint32_t        cha_key_len;
	void            *cha_key;
	struct ch_ev_thresh cha_tx_lowat;
	struct ch_ev_thresh cha_rx_lowat;
	uint32_t        cha_nexus_type;
	uint32_t        cha_nexus_extensions;
	uint32_t        cha_nexus_mhints;
	uint32_t        cha_nexus_ifindex;
	uint32_t        cha_flowadv_max;
	nexus_meta_type_t cha_nexus_meta_type;
	nexus_meta_subtype_t cha_nexus_meta_subtype;
	uint32_t        cha_nexus_checksum_offload;
	uint32_t        cha_user_packet_pool;
	uint32_t        cha_nexusadv_size;
	uint32_t        cha_nexus_defunct_ok;
	uint32_t        cha_filter;
	uint32_t        cha_enable_event_ring;
	uint32_t        cha_max_frags;
	uint32_t        cha_num_buffers;
	uint32_t        cha_low_latency;
};

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
__BEGIN_DECLS
extern int __channel_open(struct ch_init *init, const uint32_t init_len);
extern int __channel_get_info(int c, struct ch_info *cinfo,
    const uint32_t cinfolen);
extern int __channel_sync(int c, const int mode, const sync_flags_t flags);
extern int __channel_get_opt(int c, const uint32_t opt, void *aoptval,
    uint32_t *aoptlen);
extern int __channel_set_opt(int c, const uint32_t opt, const void *aoptval,
    const uint32_t optlen);
__END_DECLS
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
#endif /* !KERNEL */
#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_OS_CHANNEL_PRIVATE_H_ */
