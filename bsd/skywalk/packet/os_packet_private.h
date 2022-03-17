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

#ifndef _SKYWALK_OS_PACKET_PRIVATE_H_
#define _SKYWALK_OS_PACKET_PRIVATE_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
#include <skywalk/os_packet.h>
#include <skywalk/os_nexus_private.h>
#include <skywalk/os_channel_private.h>
#include <libkern/OSByteOrder.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#if defined(BSD_KERNEL_PRIVATE)
/*
 * Flow (currently for kernel, potentially for userland one day).
 *
 * XXX: When we expose this to userland, we need to be make sure to NOT
 * expose kernel pointer/address values embedded within.
 *
 * Values in flow_{l2,l3,l4} are stored in network byte order.  Pointers
 * are defined using mach_vm_address_t because it's stable across user
 * and kernel, and therefore keeps the structure size the same.
 *
 * Because this structure might be initialized on a per-packet allocation
 * basis, it as well as some of its member sub-subtructures are allocated
 * on a 16-bytes address boundary to allow 128-bit operations on platforms
 * that support them.
 *
 * XXX: when adding new fields, try to leverage __pad ones first.
 *
 * TODO: we should consider embedding a flow_key structure here and
 * use that to store the tuples.  That way we can leverage that for
 * flow lookups without having to copy things back-and-forth.
 */
struct __flow {
	union {
		/*
		 * The following is always zeroed out on each alloc.
		 */
		struct __flow_init {
			/*
			 * Layer 3
			 */
			struct __flow_l3 {
				union {
					struct __flow_l3_ipv4_addrs {
						struct in_addr _src;
						struct in_addr _dst;
					} _l3_ipv4;
					struct __flow_l3_ipv6_addrs {
						struct in6_addr _src;
						struct in6_addr _dst;
					} _l3_ipv6;
				};
				uint8_t  _l3_ip_ver;
				uint8_t  _l3_proto;
				uint8_t  _l3_hlen;
				unsigned _l3_is_frag : 1;
				unsigned _l3_is_first_frag : 1;
				unsigned _l3_reserved_flags : 6;
				uint32_t _l3_frag_id;
				mach_vm_address_t _l3_ptr;
			} __l3;
			/*
			 * AQM
			 */
			struct __flow_classq {
				uint32_t _fcq_hash;  /* classq-specific hash */
				uint32_t _fcq_flags; /* classq-specific flags */
			} __classq;
			/*
			 * Misc.
			 */
			uint32_t __ulen;      /* user data length */
			uint8_t  __ulp_encap; /* e.g. IPPROTO_QUIC */
			uint8_t  __pad[3];
			uint64_t __pad64[2];
			/*
			 * Flow Source.
			 */
			struct __flow_source {
				union {
					/* source identifier */
					uint64_t _fsrc_id_64[2];
					uint32_t _fsrc_id_32[4];
					uuid_t   _fsrc_id;
				} __attribute__((aligned(sizeof(uint64_t))));
				flowadv_idx_t _fsrc_fidx; /* flow adv. index */
				uint8_t       _fsrc_type; /* FLOWSRC_* mbuf.h */
				uint8_t       _fsrc_pad[3];
			} __source;
			/*
			 * Policy.
			 */
			struct __flow_policy {
				uint32_t _fpc_id; /* policy id of pkt sender */
				uint32_t _fpc_pad;
				union {
					/* process identifier */
					uint64_t _fpc_euuid_64[2];
					uint32_t _fpc_euuid_32[4];
					uuid_t   _fpc_euuid;
				} __attribute__((aligned(sizeof(uint64_t))));
			} __policy;
		} flow_init;
		uint64_t flow_init_data[16];
	} __attribute((aligned(16)));
#define flow_l3                 flow_init.__l3
#define flow_classq             flow_init.__classq
#define flow_ulen               flow_init.__ulen
#define flow_ulp_encap          flow_init.__ulp_encap
#define flow_source             flow_init.__source
#define flow_policy             flow_init.__policy

#define flow_ipv4_addrs         flow_l3._l3_ipv4
#define flow_ipv4_src           flow_l3._l3_ipv4._src
#define flow_ipv4_dst           flow_l3._l3_ipv4._dst
#define flow_ipv6_addrs         flow_l3._l3_ipv6
#define flow_ipv6_src           flow_l3._l3_ipv6._src
#define flow_ipv6_dst           flow_l3._l3_ipv6._dst
#define flow_ip_ver             flow_l3._l3_ip_ver
#define flow_ip_proto           flow_l3._l3_proto
#define flow_ip_hlen            flow_l3._l3_hlen
#define flow_ip_hdr             flow_l3._l3_ptr
#define flow_ip_frag_id         flow_l3._l3_frag_id
#define flow_ip_is_frag         flow_l3._l3_is_frag
#define flow_ip_is_first_frag   flow_l3._l3_is_first_frag

#define flow_classq_hash        flow_classq._fcq_hash
#define flow_classq_flags       flow_classq._fcq_flags

#define flow_src_token          flow_source._fsrc_id_32[0]
#define flow_src_id             flow_source._fsrc_id
#define flow_src_fidx           flow_source._fsrc_fidx
#define flow_src_type           flow_source._fsrc_type

#define flow_policy_id          flow_policy._fpc_id
#define flow_policy_euuid       flow_policy._fpc_euuid

	/*
	 * Layer 4.
	 */
	union {
		struct __flow_l4 {
			union {
				struct __flow_l4_tcp {
					in_port_t _src;
					in_port_t _dst;
					uint32_t _seq;
					uint32_t _ack;
					union {
						struct {
#if BYTE_ORDER == LITTLE_ENDIAN
							uint8_t _tcp_res:4;
							uint8_t _off:4;
#else /* BYTE_ORDER == BIG_ENDIAN */
							uint8_t _off:4;
							uint8_t _tcp_res:4;
#endif /* BYTE_ORDER == BIG_ENDIAN */
							uint8_t _flags;
							uint16_t _win;
						};
						uint32_t _ofw;
					};
				} _l4_tcp;
				struct __flow_l4_udp {
					in_port_t _src;
					in_port_t _dst;
					uint32_t _ls;
				} _l4_udp;
				struct __flow_l4_esp {
					uint32_t _spi;
				} _l4_esp;
			};
			uint8_t _l4_hlen;
			uint8_t _l4_agg_fast;
			uint8_t _l4_pad[6];
			mach_vm_address_t _l4_ptr;
		} flow_l4;
		uint64_t flow_l4_data[4];
	} __attribute((aligned(sizeof(uint64_t))));
#define flow_tcp                flow_l4._l4_tcp
#define flow_tcp_src            flow_l4._l4_tcp._src
#define flow_tcp_dst            flow_l4._l4_tcp._dst
#define flow_tcp_seq            flow_l4._l4_tcp._seq
#define flow_tcp_ack            flow_l4._l4_tcp._ack
#define flow_tcp_off            flow_l4._l4_tcp._off
#define flow_tcp_flags          flow_l4._l4_tcp._flags
#define flow_tcp_win            flow_l4._l4_tcp._win
#define flow_tcp_hlen           flow_l4._l4_hlen
#define flow_tcp_hdr            flow_l4._l4_ptr
#define flow_tcp_agg_fast       flow_l4._l4_agg_fast
#define flow_udp                flow_l4._l4_udp
#define flow_udp_src            flow_l4._l4_udp._src
#define flow_udp_dst            flow_l4._l4_udp._dst
#define flow_udp_hlen           flow_l4._l4_hlen
#define flow_udp_hdr            flow_l4._l4_ptr
#define flow_esp_spi            flow_l4._l4_esp._spi
} __attribute((aligned(16)));
#endif /* BSD_KERNEL_PRIVATE */

/*
 * Maximum size of L2, L3 & L4 headers combined.
 */
#define PKT_MAX_PROTO_HEADER_SIZE       256

/* based on 2KB buflet size */
#define BUFLETS_MIN             1       /* Ethernet MTU (default) */
#define BUFLETS_9K_JUMBO        5       /* 9000 bytes MTU */
#define BUFLETS_GSO             46      /* 64KB GSO, Ethernet MTU */

/*
 * Common buflet structure shared by {__user,__kern}_buflet.
 */
struct __buflet {
	union {
		/* for skmem batch alloc/free */
		uint64_t __buflet_next;
		/* address of next buflet in chain */
		const mach_vm_address_t __nbft_addr;
	};
	/* buffer data address */
	const mach_vm_address_t __baddr;
	/* index of buflet object in the owning buflet region */
	const obj_idx_t __bft_idx;
	/* buffer object index in buffer region */
	const obj_idx_t __bidx;
	/* object index in buflet region of next buflet(for buflet chaining) */
	const obj_idx_t __nbft_idx;
	const uint16_t  __dlim;         /* maximum length */
	uint16_t        __dlen;         /* length of data in buflet */
	uint16_t        __doff;         /* offset of data in buflet */
	const uint16_t  __flag;
#define BUFLET_FLAG_EXTERNAL    0x0001
} __attribute((packed));

/*
 * A buflet represents the smallest buffer fragment representing
 * part of the packet.  The index refers to the position of the buflet
 * in the pool, and the data length represents the actual payload
 * size -- not the buflet size itself as it is fixed for all objects
 * in the pool.
 */
struct __user_buflet {
	/*
	 * Common area between user and kernel variants.
	 */
	struct __buflet buf_com;
#define buf_addr        buf_com.__baddr
#define buf_nbft_addr   buf_com.__nbft_addr
#define buf_idx         buf_com.__bidx
#define buf_nbft_idx    buf_com.__nbft_idx
#define buf_dlim        buf_com.__dlim
#define buf_dlen        buf_com.__dlen
#define buf_doff        buf_com.__doff
#define buf_flag        buf_com.__flag
#define buf_bft_idx_reg buf_com.__bft_idx
};

#define BUF_BADDR(_buf, _addr)                                              \
	*__DECONST(mach_vm_address_t *, &(_buf)->buf_addr) =                \
	(mach_vm_address_t)(_addr)

#define BUF_BIDX(_buf, _idx)                                                \
	*__DECONST(obj_idx_t *, &(_buf)->buf_idx) = (obj_idx_t)(_idx)

#define BUF_NBFT_ADDR(_buf, _addr)                                          \
	*__DECONST(mach_vm_address_t *, &(_buf)->buf_nbft_addr) =           \
	(mach_vm_address_t)(_addr)

#define BUF_NBFT_IDX(_buf, _idx)                                            \
	*__DECONST(obj_idx_t *, &(_buf)->buf_nbft_idx) = (obj_idx_t)(_idx)

#define BUF_BFT_IDX_REG(_buf, _idx)    \
	*__DECONST(obj_idx_t *, &(_buf)->buf_bft_idx_reg) = (_idx)

#define UBUF_LINK(_pubft, _ubft) do {                                   \
	ASSERT((_ubft) != NULL);                                        \
	BUF_NBFT_ADDR(_pubft, _ubft);                                   \
	BUF_NBFT_IDX(_pubft, (_ubft)->buf_bft_idx_reg);                 \
} while (0)

#ifdef KERNEL
#define BUF_CTOR(_buf, _baddr, _bidx, _dlim, _dlen, _doff, _nbaddr, _nbidx, _bflag) do {  \
	_CASSERT(sizeof ((_buf)->buf_addr) == sizeof (mach_vm_address_t)); \
	_CASSERT(sizeof ((_buf)->buf_idx) == sizeof (obj_idx_t));       \
	_CASSERT(sizeof ((_buf)->buf_dlim) == sizeof (uint16_t));       \
	BUF_BADDR(_buf, _baddr);                                        \
	BUF_NBFT_ADDR(_buf, _nbaddr);                                   \
	BUF_BIDX(_buf, _bidx);                                          \
	BUF_NBFT_IDX(_buf, _nbidx);                                     \
	*(uint16_t *)(uintptr_t)&(_buf)->buf_dlim = (_dlim);            \
	(_buf)->buf_dlen = (_dlen);                                     \
	(_buf)->buf_doff = (_doff);                                     \
	*(uint16_t *)(uintptr_t)&(_buf)->buf_flag = (_bflag);           \
} while (0)

#define BUF_INIT(_buf, _dlen, _doff) do {                               \
	(_buf)->buf_dlen = (_dlen);                                     \
	(_buf)->buf_doff = (_doff);                                     \
} while (0)

#endif /* KERNEL */

#ifdef KERNEL
#define BUF_IN_RANGE(_buf)                                              \
	((_buf)->buf_addr >= (mach_vm_address_t)(_buf)->buf_objaddr &&  \
	((uintptr_t)(_buf)->buf_addr + (_buf)->buf_dlim) <=             \
	((uintptr_t)(_buf)->buf_objaddr + (_buf)->buf_objlim) &&        \
	((_buf)->buf_doff + (_buf)->buf_dlen) <= (_buf)->buf_dlim)
#else /* !KERNEL */
#define BUF_IN_RANGE(_buf)                                              \
	(((_buf)->buf_doff + (_buf)->buf_dlen) <= (_buf)->buf_dlim)
#endif /* !KERNEL */

/*
 * Metadata preamble.  This structure is placed at begining of each
 * __{user,kern}_{quantum,packet} object.  Each user metadata object has a
 * unique red zone pattern, which is an XOR of the redzone cookie and
 * offset of the metadata object in the object's region.  Due to the use
 * of tagged pointer, we need the structure size to be multiples of 16.
 * See SK_PTR_TAG() definition for details.
 */
struct __metadata_preamble {
	union {
		uint64_t        _mdp_next;      /* for batch alloc/free (K) */
		uint64_t        mdp_redzone;    /* red zone cookie (U) */
	};
	const obj_idx_t         mdp_idx;        /* index within region (UK) */
	uint16_t                mdp_type;       /* nexus_meta_type_t (UK) */
	uint16_t                mdp_subtype;    /* nexus_meta_subtype_t (UK) */
};

#define METADATA_PREAMBLE_SZ    (sizeof (struct __metadata_preamble))

#define METADATA_PREAMBLE(_md)                  \
	((struct __metadata_preamble *)         \
	((mach_vm_address_t)(_md) - METADATA_PREAMBLE_SZ))

#define METADATA_IDX(_md)                       \
	(METADATA_PREAMBLE(_md)->mdp_idx)

#define METADATA_TYPE(_md)                      \
	(METADATA_PREAMBLE(_md)->mdp_type)

#define METADATA_SUBTYPE(_md)                   \
	(METADATA_PREAMBLE(_md)->mdp_subtype)

/*
 * Common packet structure shared by {__user,__kern}_quantum.
 */
struct __quantum {
	union {
		uuid_t          __uuid;         /* flow UUID */
		uint8_t         __val8[16];
		uint16_t        __val16[8];
		uint32_t        __val32[4];
		uint64_t        __val64[2];
	} __flow_id_u;
#define __q_flow_id             __flow_id_u.__uuid
#define __q_flow_id_val8        __flow_id_u.__val8
#define __q_flow_id_val16       __flow_id_u.__val16
#define __q_flow_id_val32       __flow_id_u.__val32
#define __q_flow_id_val64       __flow_id_u.__val64

	uint32_t                __q_len;

	/* QoS service class, see packet_svc_class_t */
	uint32_t                __q_svc_class;  /* PKT_SC_* values */

	/*
	 * See notes on _QUM_{INTERNALIZE,EXTERNALIZE}() regarding
	 * portion of this structure above __flags that gets copied.
	 * Adding more user-mutable fields after __flags would also
	 * require adjusting those macros as well.
	 */
	volatile uint16_t       __q_flags;      /* QUMF_* flags */
	uint16_t                __q_pad[3];
} __attribute((aligned(sizeof(uint64_t))));

/*
 * Quantum.
 *
 * This structure is aligned for efficient copy and accesses.
 * It is the user version of the __kernel_quantum structure.
 *
 * XXX: Do NOT store kernel pointer/address values here.
 */
struct __user_quantum {
	/*
	 * Common area between user and kernel variants.
	 */
	struct __quantum qum_com;
#define qum_flow_id             qum_com.__q_flow_id
#define qum_flow_id_val8        qum_com.__q_flow_id_val8
#define qum_flow_id_val16       qum_com.__q_flow_id_val16
#define qum_flow_id_val32       qum_com.__q_flow_id_val32
#define qum_flow_id_val64       qum_com.__q_flow_id_val64
#define qum_len                 qum_com.__q_len
#define qum_qflags              qum_com.__q_flags
#define qum_svc_class           qum_com.__q_svc_class

	/*
	 * Userland specific.
	 */
	struct __user_buflet    qum_buf[1];             /* 1 buflet */
	/*
	 * use count for packet.
	 */
	uint16_t qum_usecnt;
} __attribute((aligned(sizeof(uint64_t))));

/*
 * Valid values for (16-bit) qum_qflags.
 */
#define QUM_F_FINALIZED         0x0001  /* has been finalized */
#define QUM_F_DROPPED           0x0002  /* has been dropped */
#define QUM_F_FLOW_CLASSIFIED   0x0010  /* flow has been classified */
#ifdef KERNEL
#define QUM_F_INTERNALIZED      0x1000  /* has been internalized */
#define QUM_F_KERNEL_ONLY       0x8000  /* kernel only; no user counterpart */

/* invariant flags we want to keep */
#define QUM_F_SAVE_MASK         (QUM_F_KERNEL_ONLY)
/* kernel-only flags that's never externalized */
#define QUM_F_KERNEL_FLAGS      (QUM_F_INTERNALIZED|QUM_F_KERNEL_ONLY)
#endif /* KERNEL */

#ifdef KERNEL
#define _KQUM_CTOR(_kqum, _flags, _len, _baddr, _bidx, _dlim, _qidx) do {    \
	(_kqum)->qum_flow_id_val64[0] = 0;                                   \
	(_kqum)->qum_flow_id_val64[1] = 0;                                   \
	(_kqum)->qum_qflags = (_flags);                                      \
	(_kqum)->qum_len = (_len);                                           \
	_CASSERT(sizeof(METADATA_IDX(_kqum)) == sizeof(obj_idx_t));          \
	*(obj_idx_t *)(uintptr_t)&METADATA_IDX(_kqum) = (_qidx);             \
	BUF_CTOR(&(_kqum)->qum_buf[0], (_baddr), (_bidx), (_dlim), 0, 0, 0,  \
	    OBJ_IDX_NONE, 0);                                                \
} while (0)

#define _KQUM_INIT(_kqum, _flags, _len, _qidx) do {                          \
	(_kqum)->qum_flow_id_val64[0] = 0;                                   \
	(_kqum)->qum_flow_id_val64[1] = 0;                                   \
	(_kqum)->qum_qflags = (_flags);                                      \
	(_kqum)->qum_len = (_len);                                           \
	BUF_INIT(&(_kqum)->qum_buf[0], 0, 0);                                \
} while (0)
#endif /* KERNEL */

/*
 * Common packet structure shared by {__user,__kern}_packet.
 */
struct __packet_com {
	/* Link layer (offset relevant to first buflet) */
	uint16_t __link_flags;                          /* PKT_LINKF_* flags */

	/*
	 * Headroom/protocol header length
	 *
	 * Since the security model of Skywalk nexus is that we doesn't trust
	 * packets either from above (userspace) or below (driver/firmware),
	 * the only metadata field that nexus makes use of from external is the
	 * headroom. Based on headroom, the flowswitch starts demux routine on
	 * l2 header, if any. The l2_len is stored in this step. Then the flow
	 * extraction (l3+l4 flow) begins parsing from (headroom + l2_len).
	 *
	 * __headroom is the empty buffer space before any packet data,
	 * it is also the equivalent to the first header offset.
	 *
	 * __l2_len is l2 (link layer) protocol header length, if any.
	 */
	uint8_t __headroom;
	uint8_t __l2_len;

	/*
	 * Checksum offload.
	 *
	 * Partial checksum does not require any header parsing and is
	 * therefore simpler to implement both in software and hardware.
	 *
	 * On transmit, PKT_CSUMF_PARTIAL indicates that a partial one's
	 * complement checksum to be computed on the span starting from
	 * pkt_csum_tx_start_off to the end of the packet, and have the
	 * resulted checksum value written at the location specified by
	 * pkt_csum_tx_stuff_off.
	 *
	 * The PKT_CSUMF_ZERO_INVERT flag is used on transmit to indicate
	 * that the value 0xffff (negative 0 in one's complement) must be
	 * substituted for the value of 0.  This is set for UDP packets,
	 * since otherwise the receiver may not validate the checksum
	 * (UDP/IPv4), or drop the packet altogether (UDP/IPv6).
	 *
	 * On receive, PKT_CSUMF_PARTIAL indicates that a partial one's
	 * complement checksum has been computed on the span beginning at
	 * pkt_csum_rx_start_off to the end of the packet, and that the
	 * computed value is now stored in pkt_csum_rx_value.
	 *
	 * All offsets are relative to the base of the first buflet.
	 */
	uint32_t __csum_flags;                          /* PKT_CSUMF_* flags */
	union {
		struct {
			uint16_t __csum_start_off;      /* start offset */
			uint16_t __csum_value;          /* checksum value */
		} __csum_rx;
		struct {
			uint16_t __csum_start_off;      /* start offset */
			uint16_t __csum_stuff_off;      /* stuff offset */
		} __csum_tx;
		uint32_t __csum_data;
	};

	/* Compression generation count */
	uint32_t __comp_gencnt;

	/*
	 * Trace ID for each sampled packet.
	 * Non-zero ID indicates that the packet is being actively traced.
	 */
	packet_trace_id_t __trace_id;

	/* Aggregation type */
	uint8_t __aggr_type;                           /* PKT_AGGR_* values */
	uint8_t __seg_cnt;                             /* Number of LRO-packets */

	uint8_t __padding[2];

	/*
	 * See notes on _PKT_{INTERNALIZE,EXTERNALIZE}() regarding portion
	 * of this structure above __p_flags that gets copied.  Adding
	 * more user-mutable fields after __p_flags would also require
	 * adjusting those macros as well.
	 */
	union {
		volatile uint32_t __flags32[2];
		volatile uint64_t __flags;              /* PKT_F_* flags */
	};
} __attribute((aligned(sizeof(uint64_t))));

struct __packet {
	union {
		uint64_t                __pkt_data[4];
		struct __packet_com     __pkt_com;
	};
#define __p_link_flags          __pkt_com.__link_flags
#define __p_headroom            __pkt_com.__headroom
#define __p_l2_len              __pkt_com.__l2_len
#define __p_csum_flags          __pkt_com.__csum_flags
#define __p_csum_rx             __pkt_com.__csum_rx
#define __p_csum_tx             __pkt_com.__csum_tx
#define __p_csum_data           __pkt_com.__csum_data
#define __p_comp_gencnt         __pkt_com.__comp_gencnt
#define __p_aggr_type           __pkt_com.__aggr_type
#define __p_seg_cnt             __pkt_com.__seg_cnt
#define __p_trace_id            __pkt_com.__trace_id
#define __p_flags32             __pkt_com.__flags32
#define __p_flags               __pkt_com.__flags
};

/* optional packet token types */
#define PKT_OPT_TOKEN_TYPE_OPAQUE       1 /* token has opaque data */
#define PKT_OPT_TOKEN_TYPE_PACKET_ID    2 /* token has packet_id */

/* maximum token size */
#define PKT_OPT_MAX_TOKEN_SIZE          16

struct __packet_opt_com {
	uint32_t        __token_type;
	uint16_t        __token_len;
	uint16_t        __vlan_tag;
	union {
		uint64_t        __token_data[2];
		uint8_t         __token[PKT_OPT_MAX_TOKEN_SIZE];
	};
	uint64_t        __expire_ts;
} __attribute((aligned(sizeof(uint64_t))));

struct __packet_opt {
	union {
		uint64_t                __pkt_opt_data[4];
		struct __packet_opt_com __pkt_opt_com;
	};
#define __po_token_type         __pkt_opt_com.__token_type
#define __po_token_len          __pkt_opt_com.__token_len
#define __po_vlan_tag           __pkt_opt_com.__vlan_tag
#define __po_token_data         __pkt_opt_com.__token_data
#define __po_token              __pkt_opt_com.__token
#define __po_expire_ts          __pkt_opt_com.__expire_ts
};

/*
 * Packet.
 *
 * This structure is aligned for efficient copy and accesses.
 * It is the user version of the __kern_packet structure.
 *
 * XXX: Do NOT store kernel pointer/address values here.
 */
struct __user_packet {
	struct __user_quantum   pkt_qum;
#define pkt_flow_id             pkt_qum.qum_flow_id
#define pkt_flow_id_64          pkt_qum.qum_flow_id_val64
#define pkt_qum_qflags          pkt_qum.qum_qflags
#define pkt_length              pkt_qum.qum_len
#define pkt_qum_buf             pkt_qum.qum_buf[0]
#define pkt_svc_class           pkt_qum.qum_svc_class
#ifdef KERNEL
/*
 * We are using the first 4 bytes of flow_id as the AQM flow identifier.
 * flow identifier should be a psuedo random number. flow_id should be
 * generated using uuid_generate() where the first 4 bytes are random.
 */
#define pkt_flow_token          pkt_qum.qum_flow_id_val32[0]
#endif /* KERNEL */

	/*
	 * Common area between user and kernel variants.
	 */
	struct __packet pkt_com;
#define pkt_link_flags          pkt_com.__p_link_flags
#define pkt_headroom            pkt_com.__p_headroom
#define pkt_l2_len              pkt_com.__p_l2_len
#define pkt_csum_flags          pkt_com.__p_csum_flags
#define pkt_csum_rx_start_off   pkt_com.__p_csum_rx.__csum_start_off
#define pkt_csum_rx_value       pkt_com.__p_csum_rx.__csum_value
#define pkt_csum_tx_start_off   pkt_com.__p_csum_tx.__csum_start_off
#define pkt_csum_tx_stuff_off   pkt_com.__p_csum_tx.__csum_stuff_off
#define pkt_csum_data           pkt_com.__p_csum_data
#define pkt_comp_gencnt         pkt_com.__p_comp_gencnt
#define pkt_aggr_type           pkt_com.__p_aggr_type
#define pkt_seg_cnt             pkt_com.__p_seg_cnt
#define pkt_trace_id            pkt_com.__p_trace_id
#if BYTE_ORDER == LITTLE_ENDIAN
#define pkt_pflags32            pkt_com.__p_flags32[0]
#else /* BYTE_ORDER != LITTLE_ENDIAN */
#define pkt_pflags32            pkt_com.__p_flags32[1]
#endif /* BYTE_ORDER != LITTLE_ENDIAN */
#define pkt_pflags              pkt_com.__p_flags

	/*
	 * Optional common metadata.
	 */
	struct __packet_opt pkt_com_opt;

	/*
	 * Userland specific.
	 */

	/*
	 * pkt_{bufs,max} aren't part of the common area, on purpose,
	 * since we selectively update them on internalize/externalize.
	 */
	const uint16_t  pkt_bufs_max;       /* maximum size of buflet chain */
	const uint16_t  pkt_bufs_cnt;       /* buflet chain size */
} __attribute((aligned(sizeof(uint64_t))));

/* the size of __user_packet structure for n total buflets */
#define _USER_PACKET_SIZE(n) sizeof(struct __user_packet)

/*
 * Valid values for pkt_link_flags.
 */
#define PKT_LINKF_BCAST         0x0001  /* send/received as link-level bcast */
#define PKT_LINKF_MCAST         0x0002  /* send/received as link-level mcast */
#define PKT_LINKF_ETHFCS        0x0004  /* has Ethernet FCS */

/*
 * XXX IMPORTANT - READ THIS XXX
 *
 * Valid values for (64-bit) pkt_pflags.
 *
 * The lower 32-bit values are equivalent to PKTF_* flags used by mbufs,
 * hence the unused values are reserved.  Do not use define any of these
 * values unless they correspond to PKTF_* flags.  Make sure to do the
 * following when adding a value in the lower 32-bit range:
 *
 * a. If the flag is kernel-only, prefix it with 2 underscore characters,
 *    then add a PKT_F_* alias under the KERNEL block conditional.  This
 *    will help ensure that the libsyscall code doesn't mistakenly use it.
 *
 * b. In pp_init(), add compile-time assertion to ensure that the PKT_F_*
 *    value matches the corresponding PKTF_* as defined in <sys/mbuf.h>.
 *
 * c. Add the new flag to PKT_F_USER_MASK depending on whether it's allowed
 *    to be user by userland.  Flags not added to this mask will only be
 *    used by the kernel.  We only internalize and externalize flags listed
 *    in PKT_F_USER_MASK.
 *
 * d. Add the new flag to PKT_F_COMMON_MASK.
 *
 * When adding an upper 32-bit value, ensure (a) and (c) above are done.
 *
 * Legend:
 *
 * (K)        - Kernel-only
 * (U+K)      - User and kernel
 * (reserved) - Only to be used for mapping with mbuf PKTF_* flags
 */
#define __PKT_F_FLOW_ID         0x0000000000000001ULL /* (K) */
#define __PKT_F_FLOW_ADV        0x0000000000000002ULL /* (K) */
/*                              0x0000000000000004ULL    (reserved) */
/*                              0x0000000000000008ULL    (reserved) */
/*                              0x0000000000000010ULL    (reserved) */
/*                              0x0000000000000020ULL    (reserved) */
/*                              0x0000000000000040ULL    (reserved) */
/*                              0x0000000000000080ULL    (reserved) */
/*                              0x0000000000000100ULL    (reserved) */
/*                              0x0000000000000200ULL    (reserved) */
#define PKT_F_WAKE_PKT          0x0000000000000400ULL /* (U+K) */
/*                              0x0000000000000800ULL    (reserved) */
/*                              0x0000000000001000ULL    (reserved) */
/*                              0x0000000000002000ULL    (reserved) */
/*                              0x0000000000004000ULL    (reserved) */
#define PKT_F_BACKGROUND        0x0000000000008000ULL /* (U+K) */
/*                              0x0000000000010000ULL    (reserved) */
/*                              0x0000000000020000ULL    (reserved) */
#define PKT_F_KEEPALIVE         0x0000000000040000ULL /* (U+K) */
#define PKT_F_REALTIME          0x0000000000080000ULL /* (U+K) */
/*                              0x0000000000100000ULL    (reserved) */
#define PKT_F_REXMT             0x0000000000200000ULL /* (U+K) */
/*                              0x0000000000400000ULL    (reserved) */
#define __PKT_F_TX_COMPL_TS_REQ 0x0000000000800000ULL /* (K) */
#define __PKT_F_TS_VALID        0x0000000001000000ULL /* (K) */
/*                              0x0000000002000000ULL    (reserved) */
#define __PKT_F_NEW_FLOW        0x0000000004000000ULL /* (K) */
#define __PKT_F_START_SEQ       0x0000000008000000ULL /* (K) */
#define PKT_F_LAST_PKT          0x0000000010000000ULL /* (U+K) */
/*                              0x0000000020000000ULL    (reserved) */
/*                              0x0000000040000000ULL    (reserved) */
/*                              0x0000000080000000ULL    (reserved) */
/*                              ---------------------    upper 32-bit below */
#define PKT_F_OPT_GROUP_START   0x0000000100000000ULL /* (U+K) */
#define PKT_F_OPT_GROUP_END     0x0000000200000000ULL /* (U+K) */
#define PKT_F_OPT_EXPIRE_TS     0x0000000400000000ULL /* (U+K) */
#define PKT_F_OPT_TOKEN         0x0000000800000000ULL /* (U+K) */
#define __PKT_F_FLOW_DATA       0x0000001000000000ULL /* (K) */
#define __PKT_F_TX_COMPL_DATA   0x0000002000000000ULL /* (K) */
#define __PKT_F_MBUF_DATA       0x0000004000000000ULL /* (K) */
#define PKT_F_TRUNCATED         0x0000008000000000ULL /* (U+K) */
#define __PKT_F_PKT_DATA        0x0000010000000000ULL /* (K) */
#define PKT_F_PROMISC           0x0000020000000000ULL /* (U+K) */
#define PKT_F_OPT_VLTAG         0x0000040000000000ULL /* (U+K) */
#define PKT_F_OPT_VLTAG_IN_PKT  0x0000080000000000ULL /* (U+K) */
/*                              0x0000100000000000ULL */
/*                              0x0000200000000000ULL */
/*                              0x0000400000000000ULL */
/*                              0x0000800000000000ULL */
/*                              0x0001000000000000ULL */
/*                              0x0002000000000000ULL */
/*                              0x0004000000000000ULL */
/*                              0x0008000000000000ULL */
/*                              0x0010000000000000ULL */
/*                              0x0020000000000000ULL */
/*                              0x0040000000000000ULL */
/*                              0x0080000000000000ULL */
#define __PKT_F_OPT_ALLOC       0x0100000000000000ULL /* (K) */
#define __PKT_F_FLOW_ALLOC      0x0200000000000000ULL /* (K) */
#define __PKT_F_TX_COMPL_ALLOC  0x0400000000000000ULL /* (K) */
/*                              0x0800000000000000ULL */
/*                              0x1000000000000000ULL */
/*                              0x2000000000000000ULL */
/*                              0x4000000000000000ULL */
/*                              0x8000000000000000ULL */

/*
 * Packet option flags.
 */
#define PKT_F_OPT_DATA                                                  \
	(PKT_F_OPT_GROUP_START | PKT_F_OPT_GROUP_END |                  \
	PKT_F_OPT_EXPIRE_TS | PKT_F_OPT_TOKEN |                         \
	PKT_F_OPT_VLTAG | PKT_F_OPT_VLTAG_IN_PKT)

#ifdef KERNEL
/*
 * Flags exposed to user (and kernel).  See notes above.
 */
#define PKT_F_USER_MASK                                                 \
	(PKT_F_BACKGROUND | PKT_F_REALTIME | PKT_F_REXMT |              \
	PKT_F_LAST_PKT | PKT_F_OPT_DATA | PKT_F_PROMISC |               \
	PKT_F_TRUNCATED | PKT_F_WAKE_PKT)

/*
 * Aliases for kernel-only flags.  See notes above.  The ones marked
 * with (common) have corresponding PKTF_* definitions and are also
 * included in PKF_F_COMMON_MASK below.
 */
#define PKT_F_FLOW_ID           __PKT_F_FLOW_ID         /* (common) */
#define PKT_F_FLOW_ADV          __PKT_F_FLOW_ADV        /* (common) */
#define PKT_F_TX_COMPL_TS_REQ   __PKT_F_TX_COMPL_TS_REQ /* (common) */
#define PKT_F_TS_VALID          __PKT_F_TS_VALID        /* (common) */
#define PKT_F_NEW_FLOW          __PKT_F_NEW_FLOW        /* (common) */
#define PKT_F_START_SEQ         __PKT_F_START_SEQ       /* (common) */
#define PKT_F_FLOW_DATA         __PKT_F_FLOW_DATA
#define PKT_F_TX_COMPL_DATA     __PKT_F_TX_COMPL_DATA
#define PKT_F_MBUF_DATA         __PKT_F_MBUF_DATA
#define PKT_F_PKT_DATA          __PKT_F_PKT_DATA
#define PKT_F_OPT_ALLOC         __PKT_F_OPT_ALLOC
#define PKT_F_FLOW_ALLOC        __PKT_F_FLOW_ALLOC
#define PKT_F_TX_COMPL_ALLOC    __PKT_F_TX_COMPL_ALLOC

/*
 * Flags related to mbuf attached to the packet.
 */
#define PKT_F_MBUF_MASK         (PKT_F_MBUF_DATA | PKT_F_TRUNCATED)

/*
 * Flags related to packet attached to the packet.
 */
#define PKT_F_PKT_MASK         (PKT_F_PKT_DATA | PKT_F_TRUNCATED)

/*
 * Invariant flags kept during _PKT_COPY().  At the moment we keep
 * all except those related to the attached mbuf.
 */
#define PKT_F_COPY_MASK         (~(PKT_F_MBUF_MASK | PKT_F_PKT_MASK))

/*
 * Lower 32-bit flags common to mbuf and __kern_packet.  See notes above.
 * DO NOT add flags to this mask unless they have equivalent PKTF_* flags
 * defined in <sys/mbuf.h>
 */
#define PKT_F_COMMON_MASK                                               \
	(PKT_F_BACKGROUND | PKT_F_REALTIME | PKT_F_REXMT |              \
	PKT_F_LAST_PKT | PKT_F_FLOW_ID | PKT_F_FLOW_ADV |               \
	PKT_F_TX_COMPL_TS_REQ | PKT_F_TS_VALID | PKT_F_NEW_FLOW |       \
	PKT_F_START_SEQ | PKT_F_KEEPALIVE | PKT_F_WAKE_PKT)

/*
 * Flags retained across alloc/free.
 */
#define PKT_F_INIT_MASK                                                 \
	(PKT_F_OPT_ALLOC | PKT_F_FLOW_ALLOC | PKT_F_TX_COMPL_ALLOC)
#endif /* KERNEL */

/*
 * 64-bit tagged pointer (limit tag to least significant byte).
 * We use 2 bits to encode type, and another 2 bits for subtype.
 */
#define SK_PTR_TYPE_MASK        ((uint64_t)0x3)         /* 00 11 */
#define SK_PTR_SUBTYPE_MASK     ((uint64_t)0xc)         /* 11 00 */
#define SK_PTR_TAG_MASK         ((uint64_t)0xf)         /* 11 11 */

#define SK_PTR_TAG(_p)          ((uint64_t)(_p) & SK_PTR_TAG_MASK)
#define SK_PTR_ADDR_MASK        (~SK_PTR_TAG_MASK)

#define SK_PTR_TYPE(_p)         ((uint64_t)(_p) & SK_PTR_TYPE_MASK)
#define SK_PTR_TYPE_ENC(_t)     ((uint64_t)(_t) & SK_PTR_TYPE_MASK)

#define SK_PTR_SUBTYPE(_p)      (((uint64_t)(_p) & SK_PTR_SUBTYPE_MASK) >> 2)
#define SK_PTR_SUBTYPE_ENC(_s)  (((uint64_t)(_s) << 2) & SK_PTR_SUBTYPE_MASK)

#define SK_PTR_ADDR(_p)         ((uint64_t)(_p) & SK_PTR_ADDR_MASK)
#define SK_PTR_ADDR_ENC(_p)     ((uint64_t)(_p) & SK_PTR_ADDR_MASK)

#define SK_PTR_ENCODE(_p, _t, _s)       \
	(SK_PTR_ADDR_ENC(_p) | SK_PTR_TYPE_ENC(_t) | SK_PTR_SUBTYPE_ENC(_s))

#define SK_PTR_ADDR_UQUM(_ph)   ((struct __user_quantum *)SK_PTR_ADDR(_ph))
#define SK_PTR_ADDR_UPKT(_ph)   ((struct __user_packet *)SK_PTR_ADDR(_ph))

#ifdef KERNEL
__BEGIN_DECLS
/*
 * Packets.
 */
extern struct mbuf *kern_packet_get_mbuf(const kern_packet_t);
__END_DECLS
#else /* !KERNEL */
#if defined(LIBSYSCALL_INTERFACE)
__BEGIN_DECLS
extern void pkt_subtype_assert_fail(const packet_t, uint64_t, uint64_t);
extern void pkt_type_assert_fail(const packet_t, uint64_t);
__END_DECLS
#endif /* LIBSYSCALL_INTERFACE */
#endif /* !KERNEL */
#if defined(LIBSYSCALL_INTERFACE) || defined(BSD_KERNEL_PRIVATE)
#include <skywalk/packet_common.h>
#endif /* LIBSYSCALL_INTERFACE || BSD_KERNEL_PRIVATE */
#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_OS_PACKET_PRIVATE_H_ */
