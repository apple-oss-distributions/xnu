/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_OS_PACKET_H_
#define _SKYWALK_OS_PACKET_H_

#ifdef PRIVATE

#include <stdint.h>
#include <sys/types.h>
#include <sys/cdefs.h>
#include <uuid/uuid.h>
#include <mach/boolean.h>
#include <mach/vm_types.h>
#include <skywalk/os_nexus.h>

/*
 * @enum packet_svc_class_t
 * @abstract Service class of a packet
 * @discussion Property that represents the category of service
 *      of a packet. This information may be used by the driver
 *      and at the link level.
 * @constant PKT_SC_BK_SYS "Background System-Initiated", high delay
 *      tolerant, high loss tolerant, elastic flow, variable size &
 *      long-lived.
 * @constant PKT_SC_BK "Background", user-initiated, high delay tolerant,
 *      high loss tolerant, elastic flow, variable size.  This level
 *      corresponds to WMM access class "BG".
 * @constant PKT_SC_BE "Best Effort", unclassified/standard.  This is
 *      the default service class; pretty much a mix of everything.
 *      This level corresponds to WMM access class "BE".
 * @constant PKT_SC_RD
 *      "Responsive Data", a notch higher than "Best Effort", medium
 *      delay tolerant, medium loss tolerant, elastic flow, bursty,
 *      long-lived.
 * @constant PKT_SC_OAM "Operations, Administration, and Management",
 *      medium delay tolerant, low-medium loss tolerant, elastic &
 *      inelastic flows, variable size.
 * @constant PKT_SC_AV "Multimedia Audio/Video Streaming", medium delay
 *      tolerant, low-medium loss tolerant, elastic flow, constant
 *      packet interval, variable rate & size.
 * @constant PKT_SC_RV "Responsive Multimedia Audio/Video", low delay
 *      tolerant, low-medium loss tolerant, elastic flow, variable
 *      packet interval, rate and size.
 * @constant PKT_SC_VI "Interactive Video", low delay tolerant, low-
 *      medium loss tolerant, elastic flow, constant packet interval,
 *      variable rate & size.  This level corresponds to WMM access
 *      class "VI".
 * @constant PKT_SC_SIG "Signaling", low delay tolerant, low loss
 *      tolerant, inelastic flow, jitter tolerant, rate is bursty but
 *      short, variable size. e.g. SIP.  This level corresponds to WMM
 *      access class "VI".
 * @constant PKT_SC_VO "Interactive Voice", low delay tolerant, low loss
 *      tolerant, inelastic flow, constant packet rate, somewhat fixed
 *      size.  This level corresponds to WMM access class "VO" or
 *      PKT_TC_VO.
 * @constant PKT_SC_CTL "Network Control", low delay tolerant, low loss
 *      tolerant, inelastic flow, rate is short & burst, variable size.
 */
typedef enum {
	PKT_SC_BK_SYS   = 0x00080090, /* lowest class */
	PKT_SC_BK       = 0x00100080,

	PKT_SC_BE       = 0x00000000,
	PKT_SC_RD       = 0x00180010,
	PKT_SC_OAM      = 0x00200020,

	PKT_SC_AV       = 0x00280120,
	PKT_SC_RV       = 0x00300110,
	PKT_SC_VI       = 0x00380100,
	PKT_SC_SIG      = 0x00380130,

	PKT_SC_VO       = 0x00400180,
	PKT_SC_CTL      = 0x00480190, /* highest class */
} packet_svc_class_t;

/* CSTYLED */
/*!
 * @enum packet_traffic_class_t
 * @abstract Traffic class of a packet
 * @discussion Property that represent the category of traffic of a packet.
 *	This information may be used by the driver and at the link level.
 * @constant PKT_TC_BE Best effort, normal class.
 * @constant PKT_TC_BK Background, low priority or bulk traffic.
 * @constant PKT_TC_VI Interactive video, constant bit rate, low latency.
 * @constant PKT_TC_VO Interactive voice, constant bit rate, lowest latency.
 */
typedef enum {
	PKT_TC_BE       = 0,
	PKT_TC_BK       = 1,
	PKT_TC_VI       = 2,
	PKT_TC_VO       = 3,
} packet_traffic_class_t;

/*
 * These conversion macros rely on the corresponding PKT_SC and
 * PKT_TC values in order to establish the following mapping:
 *
 *	PKT_SC_BK_SYS	] ==>	PKT_TC_BK
 *	PKT_SC_BK	]
 *
 *	PKT_SC_BE	] ==>	PKT_TC_BE
 *	PKT_SC_RD	]
 *	PKT_SC_OAM	]
 *
 *	PKT_SC_AV	] ==>	PKT_TC_VI
 *	PKT_SC_RV	]
 *	PKT_SC_VI	]
 *	PKT_SC_SIG	]
 *
 *	PKT_SC_VO	] ==>	PKT_TC_VO
 *	PKT_SC_CTL	]
 *
 * The values assigned to each service class allows for a fast mapping to
 * the corresponding PKT_TC traffic class values, as well as to retrieve the
 * assigned index; therefore care must be taken when comparing against these
 * values.  Use the corresponding class and index macros to retrieve the
 * corresponding portion, and never assume that a higher class corresponds
 * to a higher index.
 */
#define PKT_SCVAL(x)            ((x) & 0xffff)
#define PKT_SC2TC(_sc)          (PKT_SCVAL(_sc) >> 7)
#define PKT_TC2SCVAL(_tc)       ((_tc) << 7)

#define PKT_SCVAL_BK_SYS        PKT_SCVAL(PKT_SC_BK_SYS)
#define PKT_SCVAL_BK            PKT_SCVAL(PKT_SC_BK)
#define PKT_SCVAL_BE            PKT_SCVAL(PKT_SC_BE)
#define PKT_SCVAL_RD            PKT_SCVAL(PKT_SC_RD)
#define PKT_SCVAL_OAM           PKT_SCVAL(PKT_SC_OAM)
#define PKT_SCVAL_AV            PKT_SCVAL(PKT_SC_AV)
#define PKT_SCVAL_RV            PKT_SCVAL(PKT_SC_RV)
#define PKT_SCVAL_VI            PKT_SCVAL(PKT_SC_VI)
#define PKT_SCVAL_SIG           PKT_SCVAL(PKT_SC_SIG)
#define PKT_SCVAL_VO            PKT_SCVAL(PKT_SC_VO)
#define PKT_SCVAL_CTL           PKT_SCVAL(PKT_SC_CTL)

/*
 * Packet checksum offload flags.
 */
typedef uint32_t packet_csum_flags_t;
typedef uint32_t packet_trace_id_t;

/*
 * PACKET_CSUM_PARTIAL indicates the following:
 *
 * On transmit, the start and stuff offsets are significant, and that the
 * module setting this information is requesting that the layer below it
 * compute 16-bit 1's complement sum from the location marked by the start
 * offset to the end of the packet, and store the resulted sum at the
 * location marked by the stuff offset.  If PACKET_CSUM_ZERO_INVERT is set,
 * and if the resulted sum is 0, it will be converted to -0 (0xffff).
 *
 * On receive, the start offset and checksum value are significant, and
 * that the module computing the 16-bit 1's complement and setting this
 * information is requesting that the layer above it perform any necessary
 * adjustments to exclude/include data span that's not applicable, as well
 * as to validate the checksum value.
 */
#define PACKET_CSUM_PARTIAL     0x01     /* partial one's complement */
#define PACKET_CSUM_ZERO_INVERT 0x02     /* invert resulted 0 to 0xffff */

/*
 * Below flags are for RX.
 */
#define PACKET_CSUM_IP_CHECKED  0x0100    /* did IP checksum */
#define PACKET_CSUM_IP_VALID    0x0200    /* and the IP checksum is valid */
#define PACKET_CSUM_DATA_VALID  0x0400    /* csum_rx_val is valid */
#define PACKET_CSUM_PSEUDO_HDR  0x0800    /* csum_rx_val includes pseudo hdr */

#define PACKET_HAS_VALID_IP_CSUM(_p) \
    (((_p)->pkt_csum_flags & (PACKET_CSUM_IP_CHECKED | PACKET_CSUM_IP_VALID)) \
     == (PACKET_CSUM_IP_CHECKED | PACKET_CSUM_IP_VALID))

#define PACKET_HAS_PARTIAL_CHECKSUM(_p) \
	((_p)->pkt_csum_flags & (PACKET_CSUM_PARTIAL))

#define PACKET_CSUM_RX_FULL_FLAGS \
	(PACKET_CSUM_IP_CHECKED | PACKET_CSUM_IP_VALID | \
	PACKET_CSUM_DATA_VALID | PACKET_CSUM_PSEUDO_HDR)

#define PACKET_CSUM_RX_FLAGS \
	(PACKET_CSUM_RX_FULL_FLAGS | PACKET_CSUM_PARTIAL)

/*
 * TODO: adi@apple.com -- these are temporary and should be removed later.
 */
#define OS_PACKET_HAS_CHECKSUM_API      1
#define OS_PACKET_HAS_SEGMENT_COUNT     1
#define OS_PACKET_HAS_TRACING_API       1

/*
 * Valid values for pkt_aggr_type.
 */
#define PKT_AGGR_NONE                0x00 /* no aggregation */
#define PKT_AGGR_IP_CHAIN            0x01 /* buflet chain of discrete IP packets containing contiguous L4 frames */
#define PKT_AGGR_SINGLE_IP           0x02 /* buflet chain representing single IP packet */
#define PKT_AGGR_SINGLE_IP_PACKED    0x03 /* buflet chain representing single IP packet in packed format */

/*
 * packet_id is a per packet metadata which can be set on a packet by the
 * application. It can be used to identify either an individual or a group
 * of packets within the networking stack and driver.
 */
typedef struct packet_id {
	/*
	 * version of this structure.
	 */
	uint8_t     pktid_version;
#define OS_PACKET_PKTID_VERSION_1          1
#define OS_PACKET_PKTID_VERSION_CURRENT    OS_PACKET_PKTID_VERSION_1
	/*
	 * payload type of the packet, opaque to the network stack.
	 */
	uint8_t     pktid_payload_type;
	/*
	 * packet sequence number, monotonically increasing.
	 */
	uint16_t    pktid_sequence_number;
	/*
	 * packet timestamp, monotonically increasing and opaque to the
	 * network stack. Sample rate of the timestamp clock is determined
	 * by the application.
	 */
	uint32_t    pktid_timestamp;
	/*
	 * Identifier for streams defined by the application.
	 */
	uint32_t    pktid_stream_identifier;
	/*
	 * reserved for future use.
	 */
	uint32_t    _reserved;
} packet_id_t;

/*
 * Packet Trace code
 * Used with os_packet_trace_* functions.
 * Total of 12bit (0xABC) code space available, current sub-code allocation is:
 *     0x00C code space for FSW Rx path.
 *     0x01C code space for FSW Tx path.
 *
 * More sub-code can be added for other packet data path, e.g. uPipe, BSD, etc.
 *
 * Note:
 *     1. Needs to include <sys/kdebug.h> to use the values.
 *     2. When making changes to sub-code/value, update static assertions in
 *        pp_init and probe list ariadne-plists/skywalk-tracepoints.plist.
 *
 */
/* Rx Group */
#define PKT_TRACE_RX_DRV_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x001) | DBG_FUNC_START)
#define PKT_TRACE_RX_DRV_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x001) | DBG_FUNC_END)

#define PKT_TRACE_RX_FSW_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x002) | DBG_FUNC_START)
#define PKT_TRACE_RX_FSW_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x002) | DBG_FUNC_END)

#define PKT_TRACE_RX_CHN_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x003) | DBG_FUNC_START)
#define PKT_TRACE_RX_CHN_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x003) | DBG_FUNC_END)


/* Tx Group */
#define PKT_TRACE_TX_FSW_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x010) | DBG_FUNC_START)
#define PKT_TRACE_TX_FSW_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x010) | DBG_FUNC_END)

#define PKT_TRACE_TX_AQM_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x011) | DBG_FUNC_START)
#define PKT_TRACE_TX_AQM_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x011) | DBG_FUNC_END)

#define PKT_TRACE_TX_DRV_START      (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x012) | DBG_FUNC_START)
#define PKT_TRACE_TX_DRV_END        (SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x012) | DBG_FUNC_END)


#ifndef KERNEL
/*
 * User APIs.
 */

/*
 * Opaque handles.
 */
struct __user_buflet;
typedef uint64_t                        packet_t;
typedef struct __user_buflet            *buflet_t;

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
/*
 * Packets specific.
 */
extern int os_packet_set_headroom(const packet_t, const uint8_t);
extern uint8_t os_packet_get_headroom(const packet_t);
extern int os_packet_set_link_header_length(const packet_t, const uint8_t);
extern uint8_t os_packet_get_link_header_length(const packet_t);
extern int os_packet_set_link_broadcast(const packet_t);
extern boolean_t os_packet_get_link_broadcast(const packet_t);
extern int os_packet_set_link_multicast(const packet_t);
extern boolean_t os_packet_get_link_multicast(const packet_t);
extern int os_packet_set_link_ethfcs(const packet_t);
extern boolean_t os_packet_get_link_ethfcs(const packet_t);
extern int os_packet_set_transport_traffic_background(const packet_t);
extern boolean_t os_packet_get_transport_traffic_background(const packet_t);
extern int os_packet_set_transport_traffic_realtime(const packet_t);
extern boolean_t os_packet_get_transport_traffic_realtime(const packet_t);
extern int os_packet_set_transport_retransmit(const packet_t);
extern boolean_t os_packet_get_transport_retransmit(const packet_t);
extern int os_packet_set_transport_last_packet(const packet_t);
extern int os_packet_set_service_class(const packet_t,
    const packet_svc_class_t);
extern packet_svc_class_t os_packet_get_service_class(const packet_t);
extern int os_packet_set_compression_generation_count(const packet_t, const uint32_t);
extern uint32_t os_packet_get_compression_generation_count(const packet_t);
extern int os_packet_set_traffic_class(const packet_t, packet_traffic_class_t);
extern packet_traffic_class_t os_packet_get_traffic_class(const packet_t);
extern int os_packet_set_inet_checksum(const packet_t,
    const packet_csum_flags_t, const uint16_t, const uint16_t);
extern packet_csum_flags_t os_packet_get_inet_checksum(const packet_t,
    uint16_t *, uint16_t *);
extern void os_packet_set_group_start(const packet_t);
extern boolean_t os_packet_get_group_start(const packet_t);
extern void os_packet_set_group_end(const packet_t);
extern boolean_t os_packet_get_group_end(const packet_t);
extern int os_packet_set_expire_time(const packet_t, const uint64_t);
extern int os_packet_get_expire_time(const packet_t, uint64_t *);
extern int os_packet_set_token(const packet_t, const void *, const uint16_t);
extern int os_packet_get_packetid(const packet_t, packet_id_t *);
extern int os_packet_set_packetid(const packet_t, packet_id_t *);
extern int os_packet_set_vlan_tag(const packet_t, const uint16_t,
    const boolean_t);
extern int os_packet_get_vlan_tag(const packet_t, uint16_t *, boolean_t *);
extern uint16_t os_packet_get_vlan_id(const uint16_t);
extern uint8_t os_packet_get_vlan_priority(const uint16_t);
#define HAS_OS_PACKET_GET_WAKE_FLAG 1
extern boolean_t os_packet_get_wake_flag(const packet_t);
#define HAS_OS_PACKET_KEEP_ALIVE 1
extern boolean_t os_packet_get_keep_alive(const packet_t);
extern void os_packet_set_keep_alive(const packet_t, const boolean_t);
extern boolean_t os_packet_get_truncated(const packet_t);
extern uint8_t os_packet_get_aggregation_type(const packet_t ph);

/*
 * Quantum & Packets.
 */
extern void os_packet_set_flow_uuid(const packet_t, const uuid_t flow_uuid);
extern void os_packet_get_flow_uuid(const packet_t, uuid_t *flow_uuid);
extern void os_packet_clear_flow_uuid(const packet_t);
extern uint32_t os_packet_get_data_length(const packet_t);
extern uint32_t os_packet_get_buflet_count(const packet_t);
extern buflet_t os_packet_get_next_buflet(const packet_t, const buflet_t);
extern uint32_t os_packet_get_segment_count(const packet_t ph);
extern int os_packet_finalize(const packet_t);
extern int os_packet_add_buflet(const packet_t ph, const buflet_t bprev,
    const buflet_t bnew);
/* increment use count on packet */
extern int os_packet_increment_use_count(const packet_t ph);
/* decrement use count on packet and retrieve new value  */
extern int os_packet_decrement_use_count(const packet_t ph, uint16_t *use_cnt);

extern packet_trace_id_t os_packet_get_trace_id(const packet_t ph);
extern void os_packet_set_trace_id(const packet_t ph, packet_trace_id_t);
extern void os_packet_trace_event(const packet_t ph, uint32_t);

/*
 * Misc.
 */
extern uint32_t os_inet_checksum(const void *, uint32_t, uint32_t);
extern uint32_t os_copy_and_inet_checksum(const void *, void *,
    uint32_t, uint32_t);

/*
 * Buflets.
 */
extern int os_buflet_set_data_offset(const buflet_t, const uint16_t);
extern uint16_t os_buflet_get_data_offset(const buflet_t);
extern int os_buflet_set_data_length(const buflet_t, const uint16_t);
extern uint16_t os_buflet_get_data_length(const buflet_t);
extern void *os_buflet_get_object_address(const buflet_t);
extern uint32_t os_buflet_get_object_limit(const buflet_t);
extern void *os_buflet_get_data_address(const buflet_t);
extern uint16_t os_buflet_get_data_limit(const buflet_t);
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
#else /* KERNEL */
/*
 * Kernel APIs.
 */

/*
 * Opaque handles.
 */
struct __kern_buflet;
struct kern_pbufpool;
struct sksegment;

typedef struct kern_pbufpool            *kern_pbufpool_t;
typedef uint64_t                        kern_packet_t;
typedef uint32_t                        kern_packet_idx_t;
typedef struct __kern_buflet            *kern_buflet_t;
typedef uint32_t                        kern_obj_idx_seg_t;
typedef struct sksegment                *kern_segment_t;
typedef uint32_t                        kern_segment_idx_t;

/*
 * @typedef pbuf_seg_ctor_fn_t
 * @abstract Buffer segment constructor callback.
 * @param buf_seg Buffer segment handle.
 * @param buf_desc IOSKMemoryDescriptor handle for buffer segment.
 * @discussion This callback is invoked when a segment has been activated.
 *      If applicable, the owner should wire/prepare the memory and insert
 *      it into the memory mapper (IOMMU/DART) prior to returning.
 */
typedef void (*pbuf_seg_ctor_fn_t)(const kern_pbufpool_t,
    const kern_segment_t buf_seg, const IOSKMemoryDescriptor buf_desc);

/*
 * @typedef pbuf_seg_dtor_fn_t
 * @abstract Buffer segment destructor callback.
 * @param buf_seg Buffer segment handle.
 * @param buf_desc IOSKMemoryDescriptor handle for buffer segment.
 * @discussion This callback is invoked when a segment is about to be
 *      freed.  The owner should reverse what had been done earlier
 *      at pbuf_seg_ctor_fn_t() constructor time.  If applicable,
 *      it should remove the memory from mapper (IOMMU/DART), and
 *      unwire/complete it prior to returning.
 */
typedef void (*pbuf_seg_dtor_fn_t)(const kern_pbufpool_t,
    const kern_segment_t buf_seg, const IOSKMemoryDescriptor buf_desc);

typedef void (*pbuf_ctx_retain_fn_t)(void *const ctx);
typedef void (*pbuf_ctx_release_fn_t)(void *const ctx);

typedef uint8_t pbufpool_name_t[64];

/*
 * Kernel packet buffer pool init.
 */
struct kern_pbufpool_init {
	uint32_t                kbi_version;    /* current version */
	pbufpool_name_t         kbi_name;       /* optional */
	uint32_t                kbi_flags;      /* see KBI_* */
	uint32_t                kbi_packets;    /* required */
	uint32_t                kbi_max_frags;  /* max buflets per packet */
	uint32_t                kbi_buflets;    /* >= packets (optional) */
	uint32_t                kbi_bufsize;    /* required */
	uint32_t                kbi_buf_seg_size; /* optional */
	pbuf_seg_ctor_fn_t      kbi_buf_seg_ctor; /* optional */
	pbuf_seg_dtor_fn_t      kbi_buf_seg_dtor; /* optional */
	void *                  kbi_ctx;         /* optional */
	pbuf_ctx_retain_fn_t    kbi_ctx_retain;  /* optional */
	pbuf_ctx_release_fn_t   kbi_ctx_release; /* optional */
};

#define KBIF_QUANTUM            0x1     /* simple packet (non-networking) */
#define KBIF_PERSISTENT         0x2     /* persistent memory (wired) */
#define KBIF_MONOLITHIC         0x4     /* single segment mode */
#define KBIF_BUFFER_ON_DEMAND   0x8     /* attach/detach buffers on demand */
#define KBIF_INHIBIT_CACHE      0x10    /* caching-inhibited */
#define KBIF_USER_ACCESS        0x20    /* allow userspace access */
#define KBIF_VIRTUAL_DEVICE     0x40    /* device is virtual (no DMA) */
#define KBIF_PHYS_CONTIGUOUS    0x80    /* physically-contiguous segment(s) */
#define KBIF_IODIR_IN           0x100   /* io direction in (device to host) */
#define KBIF_IODIR_OUT          0x200   /* io direction out (host to device) */
#define KBIF_KERNEL_READONLY    0x400   /* kernel read-only */
#define KBIF_NO_MAGAZINES       0x800   /* disable per-CPU magazines layer */

#define KERN_PBUFPOOL_VERSION_1         1
#define KERN_PBUFPOOL_VERSION_2         2       /* added ctx retain/release */
#define KERN_PBUFPOOL_CURRENT_VERSION   KERN_PBUFPOOL_VERSION_2

/*
 * Kernel packet buffer pool memory info.
 */
struct kern_pbufpool_memory_info {
	uint32_t                kpm_flags;      /* see KPMF_* */
	uint32_t                kpm_packets;    /* number of packets */
	uint32_t                kpm_max_frags;  /* max buflets per packet */
	uint32_t                kpm_buflets;    /* number of buflets */
	uint32_t                kpm_bufsize;    /* size of each buffer */
	uint32_t                kpm_bufsegs;    /* number of buffer segments */
	uint32_t                kpm_buf_seg_size; /* size of a buffer segment */
} __attribute__((aligned(64)));

#define KPMF_EXTERNAL           0x1             /* externally configured */

/*
 * Kernel packet representation of packet_svc_class_t.
 *
 * We have a separate enum to separate the namespace just in case we need it.
 */
typedef enum {
#ifdef BSD_KERNEL_PRIVATE
	KPKT_SC_UNSPEC  = -1, /* Internal: not specified */
#endif /* BSD_KERNEL_PRIVATE */
	KPKT_SC_BK_SYS  = PKT_SC_BK_SYS, /* lowest class */
	KPKT_SC_BK      = PKT_SC_BK,

	KPKT_SC_BE      = PKT_SC_BE,
	KPKT_SC_RD      = PKT_SC_RD,
	KPKT_SC_OAM     = PKT_SC_OAM,

	KPKT_SC_AV      = PKT_SC_AV,
	KPKT_SC_RV      = PKT_SC_RV,
	KPKT_SC_VI      = PKT_SC_VI,
	KPKT_SC_SIG     = PKT_SC_SIG,

	KPKT_SC_VO      = PKT_SC_VO,
	KPKT_SC_CTL     = PKT_SC_CTL, /* highest class */
} kern_packet_svc_class_t;

/* Maximum number of KPKT_SC values (excluding KPKT_SC_UNSPEC) */
#define KPKT_SC_MAX_CLASSES     10

#define KPKT_VALID_SVC(c)                                               \
	(c == KPKT_SC_BK_SYS || c == KPKT_SC_BK || c == KPKT_SC_BE ||   \
	c == KPKT_SC_RD || c == KPKT_SC_OAM || c == KPKT_SC_AV ||       \
	c == KPKT_SC_RV || c == KPKT_SC_VI || c == KPKT_SC_SIG ||       \
	c == KPKT_SC_VO || c == KPKT_SC_CTL)

#define KPKT_SVCIDX(c)          ((((c) >> 16) & 0xff) >> 3)

/*
 * Kernel packet representation of packet_traffic_class_t.
 *
 * We have a separate enum to separate the namespace just in case we need it.
 */
typedef enum {
#ifdef BSD_KERNEL_PRIVATE
	KPKT_TC_UNSPEC  = -1,           /* Internal: not specified */
#endif /* BSD_KERNEL_PRIVATE */
	KPKT_TC_BE      = PKT_TC_BE,
	KPKT_TC_BK      = PKT_TC_BK,
	KPKT_TC_VI      = PKT_TC_VI,
	KPKT_TC_VO      = PKT_TC_VO,
#ifdef BSD_KERNEL_PRIVATE
	KPKT_TC_MAX     = 4,            /* Internal: traffic class count */
#endif /* BSD_KERNEL_PRIVATE */
} kern_packet_traffic_class_t;

/*
 * Modes for cloning a kernel packet.
 *
 * The "heavy" mode copies most of the metadata (except those pertaining
 * to linkages to other objects), allocates new buffer(s) for the
 * cloned packet, and copies old buffer(s) to new one(s).
 *
 * The "light" mode is to be used on a packet that's recently allocated,
 * as the cloning process involves copying minimal metadata information,
 * as well as adding reference(s) to the buffer(s) rather than copying.
 */
typedef enum {
	KPKT_COPY_HEAVY = 0,   /* copy everything including buffers */
	KPKT_COPY_LIGHT        /* minimal copy, adding refs to buffers */
} kern_packet_copy_mode_t;

__BEGIN_DECLS
/*
 * Packets specific.
 */
extern errno_t kern_packet_set_headroom(const kern_packet_t, const uint8_t);
extern uint8_t kern_packet_get_headroom(const kern_packet_t);
/* deprecated -- use kern_packet_set_headroom instead */
extern errno_t kern_packet_set_link_header_offset(const kern_packet_t,
    const uint8_t);
/* deprecated -- use kern_packet_get_headroom instead */
extern uint16_t kern_packet_get_link_header_offset(const kern_packet_t);
extern errno_t kern_packet_set_link_header_length(const kern_packet_t,
    const uint8_t);
extern uint8_t kern_packet_get_link_header_length(const kern_packet_t);
extern errno_t kern_packet_set_link_broadcast(const kern_packet_t);
extern boolean_t kern_packet_get_link_broadcast(const kern_packet_t);
extern errno_t kern_packet_set_link_multicast(const kern_packet_t);
extern boolean_t kern_packet_get_link_multicast(const kern_packet_t);
extern errno_t kern_packet_set_link_ethfcs(const kern_packet_t);
extern boolean_t kern_packet_get_link_ethfcs(const kern_packet_t);
/* deprecated -- use kern_packet_set_link_header_length instead */
extern errno_t kern_packet_set_network_header_offset(const kern_packet_t,
    const uint16_t);
/* deprecated -- use kern_packet_get_link_header_length instead */
extern uint16_t kern_packet_get_network_header_offset(const kern_packet_t);
extern errno_t kern_packet_set_transport_traffic_background(
	const kern_packet_t);
extern boolean_t kern_packet_get_transport_traffic_background(
	const kern_packet_t);
extern errno_t kern_packet_set_transport_traffic_realtime(const kern_packet_t);
extern boolean_t kern_packet_get_transport_traffic_realtime(
	const kern_packet_t);
/* deprecated */
extern errno_t kern_packet_set_transport_header_offset(const kern_packet_t,
    const uint16_t);
/* deprecated */
extern uint16_t kern_packet_get_transport_header_offset(const kern_packet_t);
extern errno_t kern_packet_set_transport_retransmit(const kern_packet_t);
extern boolean_t kern_packet_get_transport_retransmit(const kern_packet_t);
extern boolean_t kern_packet_get_transport_new_flow(const kern_packet_t);
extern boolean_t kern_packet_get_transport_last_packet(const kern_packet_t);
extern errno_t kern_packet_set_service_class(const kern_packet_t,
    const kern_packet_svc_class_t);
extern kern_packet_svc_class_t kern_packet_get_service_class(
	const kern_packet_t);
extern errno_t kern_packet_get_service_class_index(
	const kern_packet_svc_class_t, uint32_t *);
extern boolean_t kern_packet_is_high_priority(
	const kern_packet_t);
extern errno_t kern_packet_set_traffic_class(const kern_packet_t,
    kern_packet_traffic_class_t);
extern kern_packet_traffic_class_t kern_packet_get_traffic_class(
	const kern_packet_t);
extern errno_t kern_packet_set_inet_checksum(const kern_packet_t,
    const packet_csum_flags_t, const uint16_t, const uint16_t);
extern packet_csum_flags_t kern_packet_get_inet_checksum(const kern_packet_t,
    uint16_t *, uint16_t *);
extern errno_t kern_packet_get_timestamp(const kern_packet_t, uint64_t *,
    boolean_t *);
extern errno_t kern_packet_set_timestamp(const kern_packet_t, uint64_t,
    boolean_t);
extern errno_t kern_packet_get_timestamp_requested(const kern_packet_t,
    boolean_t *);
extern errno_t kern_packet_get_tx_completion_status(const kern_packet_t,
    kern_return_t *);
extern errno_t kern_packet_set_tx_completion_status(const kern_packet_t,
    kern_return_t);
extern void kern_packet_tx_completion(const kern_packet_t, ifnet_t);
extern void kern_packet_set_group_start(const kern_packet_t);
extern boolean_t kern_packet_get_group_start(const kern_packet_t);
extern void kern_packet_set_group_end(const kern_packet_t);
extern boolean_t kern_packet_get_group_end(const kern_packet_t);
extern errno_t kern_packet_set_expire_time(const kern_packet_t, const uint64_t);
extern errno_t kern_packet_get_expire_time(const kern_packet_t, uint64_t *);
extern errno_t kern_packet_set_token(const kern_packet_t, const void *,
    const uint16_t);
extern errno_t kern_packet_get_token(const kern_packet_t, void *, uint16_t *);
extern errno_t kern_packet_get_packetid(const kern_packet_t, packet_id_t *);
extern errno_t kern_packet_set_vlan_tag(const kern_packet_t, const uint16_t,
    const boolean_t);
extern errno_t kern_packet_get_vlan_tag(const kern_packet_t, uint16_t *,
    boolean_t *);
extern uint16_t kern_packet_get_vlan_id(const uint16_t);
extern uint8_t kern_packet_get_vlan_priority(const uint16_t);
extern void kern_packet_set_wake_flag(const kern_packet_t);
extern boolean_t kern_packet_get_wake_flag(const kern_packet_t);

/*
 * Quantum & Packets.
 */
extern void kern_packet_set_flow_uuid(const kern_packet_t, const uuid_t);
extern void kern_packet_get_flow_uuid(const kern_packet_t, uuid_t *);
extern void kern_packet_clear_flow_uuid(const kern_packet_t);
extern void kern_packet_get_euuid(const kern_packet_t, uuid_t);
extern void kern_packet_set_policy_id(const kern_packet_t, uint32_t);
extern uint32_t kern_packet_get_policy_id(const kern_packet_t);
extern kern_packet_idx_t kern_packet_get_object_index(const kern_packet_t);
extern uint32_t kern_packet_get_data_length(const kern_packet_t);
extern uint32_t kern_packet_get_buflet_count(const kern_packet_t);
extern errno_t kern_packet_set_buflet_count(const kern_packet_t, uint32_t);
extern kern_buflet_t kern_packet_get_next_buflet(const kern_packet_t,
    const kern_buflet_t);
extern errno_t kern_packet_finalize(const kern_packet_t);
extern errno_t kern_packet_clone(const kern_packet_t, kern_packet_t *,
    kern_packet_copy_mode_t);
extern errno_t kern_packet_clone_nosleep(const kern_packet_t, kern_packet_t *,
    kern_packet_copy_mode_t);
extern errno_t kern_packet_add_buflet(const kern_packet_t ph,
    const kern_buflet_t bprev, const kern_buflet_t bnew);
extern void kern_packet_append(const kern_packet_t, const kern_packet_t);
extern kern_packet_t kern_packet_get_next(const kern_packet_t);
extern void kern_packet_set_next(const kern_packet_t, const kern_packet_t);
extern void kern_packet_set_chain_counts(const kern_packet_t, uint32_t,
    uint32_t);
extern void kern_packet_get_chain_counts(const kern_packet_t, uint32_t *,
    uint32_t *);

/*
 * Misc.
 */
extern uint32_t kern_inet_checksum(const void *, uint32_t, uint32_t);
extern uint32_t kern_copy_and_inet_checksum(const void *, void *,
    uint32_t, uint32_t);
extern void kern_packet_set_trace_id(const kern_packet_t, packet_trace_id_t);
extern packet_trace_id_t kern_packet_get_trace_id(const kern_packet_t);
extern void kern_packet_trace_event(const kern_packet_t, uint32_t);
extern errno_t kern_packet_copy_bytes(const kern_packet_t, size_t, size_t,
    void*);

/*
 * Buflets.
 */
extern errno_t kern_buflet_set_data_address(const kern_buflet_t, const void *);
extern void *kern_buflet_get_data_address(const kern_buflet_t);
extern errno_t kern_buflet_set_data_offset(const kern_buflet_t, const uint16_t);
extern uint16_t kern_buflet_get_data_offset(const kern_buflet_t);
extern errno_t kern_buflet_set_data_length(const kern_buflet_t, const uint16_t);
extern uint16_t kern_buflet_get_data_length(const kern_buflet_t);
extern void *kern_buflet_get_object_address(const kern_buflet_t);
extern uint32_t kern_buflet_get_object_limit(const kern_buflet_t);
extern kern_segment_t kern_buflet_get_object_segment(const kern_buflet_t,
    kern_obj_idx_seg_t *);
extern errno_t kern_buflet_set_data_limit(const kern_buflet_t, const uint16_t);
extern uint16_t kern_buflet_get_data_limit(const kern_buflet_t);

/*
 * Packet buffer pool.
 */
typedef void (*alloc_cb_func_t)(kern_packet_t packet, uint32_t pkt_index,
    const void *ctx);
extern errno_t kern_pbufpool_create(const struct kern_pbufpool_init *,
    kern_pbufpool_t *, struct kern_pbufpool_memory_info *);
extern void *kern_pbufpool_get_context(const kern_pbufpool_t pbufpool);
extern errno_t kern_pbufpool_get_memory_info(const kern_pbufpool_t pbufpool,
    struct kern_pbufpool_memory_info *pbufpool_mem_ref);
extern errno_t kern_pbufpool_alloc(const kern_pbufpool_t pbufpool,
    const uint32_t bufcnt, kern_packet_t *packet);
extern errno_t kern_pbufpool_alloc_batch(const kern_pbufpool_t pbufpool,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size);
extern errno_t kern_pbufpool_alloc_batch_callback(
	const kern_pbufpool_t pbufpool, const uint32_t bufcnt, kern_packet_t *array,
	uint32_t *size, alloc_cb_func_t cb, const void *ctx);
extern errno_t kern_pbufpool_alloc_nosleep(const kern_pbufpool_t pbufpool,
    const uint32_t bufcnt, kern_packet_t *packet);
extern errno_t kern_pbufpool_alloc_batch_nosleep(const kern_pbufpool_t pbufpool,
    const uint32_t bufcnt, kern_packet_t *array, uint32_t *size);
extern errno_t kern_pbufpool_alloc_batch_nosleep_callback(
	const kern_pbufpool_t pbufpool, const uint32_t bufcnt,
	kern_packet_t *array, uint32_t *size, alloc_cb_func_t cb, const void *ctx);
extern void kern_pbufpool_free(const kern_pbufpool_t pbufpool, kern_packet_t);
extern void kern_pbufpool_free_batch(const kern_pbufpool_t pbufpool,
    kern_packet_t *array, uint32_t size);
extern void kern_pbufpool_free_chain(const kern_pbufpool_t pbufpool,
    kern_packet_t chain);
extern errno_t kern_pbufpool_alloc_buffer(const kern_pbufpool_t pbufpool,
    mach_vm_address_t *buffer, kern_segment_t *sg, kern_obj_idx_seg_t *sg_idx);
extern errno_t kern_pbufpool_alloc_buffer_nosleep(const kern_pbufpool_t
    pbufpool, mach_vm_address_t *buffer, kern_segment_t *sg,
    kern_obj_idx_seg_t *sg_idx);
extern void kern_pbufpool_free_buffer(const kern_pbufpool_t pbufpool,
    mach_vm_address_t baddr);
extern errno_t kern_pbufpool_alloc_buflet(const kern_pbufpool_t,
    kern_buflet_t *);
extern errno_t kern_pbufpool_alloc_buflet_nosleep(const kern_pbufpool_t,
    kern_buflet_t *);
extern void kern_pbufpool_destroy(kern_pbufpool_t);
extern kern_segment_idx_t kern_segment_get_index(const kern_segment_t);
__END_DECLS
#endif /* KERNEL */
#endif /* PRIVATE */
#endif /* !_SKYWALK_OS_PACKET_H_ */
