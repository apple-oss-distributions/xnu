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

#ifndef _SKYWALK_PACKET_PACKETVAR_H_
#define _SKYWALK_PACKET_PACKETVAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/os_packet_private.h>

/*
 * Kernel variant of __user_buflet.
 *
 * The main difference here is the support for shared buffers, where
 * multiple buflets may point to the same buffer object at different
 * data span within it, each holding a reference to the buffer object,
 * i.e. the "use" count.  The buf_addr therefore points to the beginning
 * of the data span; the buf_len describes the length of the span; and
 * the buf_doff describes the offset relative to the beginning of the
 * span as noted by buf_addr.  The buffer object is stored in buf_objaddr.
 */
struct __kern_buflet {
	/*
	 * Common area between user and kernel variants.
	 */
	struct __buflet buf_com;
	/*
	 * Kernel specific.
	 */
	/* buffer control of the buffer object */
	const struct skmem_bufctl *buf_ctl;
#if !defined(__LP64__)
	uint32_t __padding;
#endif /* !__LP64__ */

#define buf_objaddr     buf_ctl->bc_addr
#define buf_objlim      buf_ctl->bc_lim
} __attribute((packed));

struct __kern_buflet_ext {
	/*
	 * This is an overlay structure on nexus adapter.
	 */
	struct __kern_buflet kbe_overlay;
	/*
	 *  extended variant specific.
	 */
	/* mirrored user buflet */
	struct __user_buflet const *kbe_buf_user;

	/* buflet user packet pool hash bucket linkage */
	SLIST_ENTRY(__kern_buflet_ext) kbe_buf_upp_link;

	/* pid of the process using the buflet */
	pid_t kbe_buf_pid;
} __attribute((packed));

#define KBUF_CTOR(_kbuf, _baddr, _bidxreg, _bc, _pp) do {               \
	_CASSERT(sizeof ((_kbuf)->buf_addr) == sizeof (mach_vm_address_t));\
	/* kernel variant (deconst) */                                  \
	BUF_CTOR(_kbuf, _baddr, _bidxreg, (_pp)->pp_buflet_size, 0, 0,  \
	    (_kbuf)->buf_nbft_addr, (_kbuf)->buf_nbft_idx, (_kbuf)->buf_flag);\
	*(struct skmem_bufctl **)(uintptr_t)&(_kbuf)->buf_ctl = (_bc);  \
	/* this may be called to initialize unused buflets */           \
	if (__probable((_bc) != NULL)) {                                \
	        skmem_bufctl_use(_bc);                                  \
	}                                                               \
	/* no need to construct user variant as it is done in externalize */ \
} while (0)

#define KBUF_EXT_CTOR(_kbuf, _ubuf, _baddr, _bidxreg, _bc,              \
	    _bft_idx_reg, _pp) do {                                     \
	ASSERT(_bft_idx_reg != OBJ_IDX_NONE);                           \
	_CASSERT(sizeof((_kbuf)->buf_flag) == sizeof(uint16_t));        \
	/* we don't set buf_nbft_addr here as during construction it */ \
	/* is used by skmem batch alloc logic                        */ \
	*__DECONST(uint16_t *, &(_kbuf)->buf_flag) = BUFLET_FLAG_EXTERNAL;\
	BUF_NBFT_IDX(_kbuf, OBJ_IDX_NONE);                              \
	BUF_BFT_IDX_REG(_kbuf, _bft_idx_reg);                           \
	*__DECONST(struct __user_buflet **,                             \
	&((struct __kern_buflet_ext *)(_kbuf))->kbe_buf_user) = (_ubuf);\
	KBUF_CTOR(_kbuf, _baddr, _bidxreg, _bc, _pp);                   \
} while (0)

#define KBUF_INIT(_kbuf) do {                                           \
	ASSERT((_kbuf)->buf_ctl != NULL);                               \
	ASSERT((_kbuf)->buf_addr != 0);                                 \
	ASSERT((_kbuf)->buf_dlim != 0);                                 \
	/* kernel variant (deconst) */                                  \
	BUF_INIT(_kbuf, 0, 0);                                          \
} while (0)

#define KBUF_EXT_INIT(_kbuf, _pp) do {                                  \
	ASSERT((_kbuf)->buf_ctl != NULL);                               \
	ASSERT((_kbuf)->buf_flag & BUFLET_FLAG_EXTERNAL);               \
	ASSERT((_kbuf)->buf_bft_idx_reg != OBJ_IDX_NONE);               \
	BUF_BADDR(_kbuf, (_kbuf)->buf_ctl->bc_addr);                    \
	BUF_NBFT_ADDR(_kbuf, 0);                                        \
	BUF_NBFT_IDX(_kbuf, OBJ_IDX_NONE);                              \
	*__DECONST(uint16_t *, &(_kbuf)->buf_dlim) = (_pp)->pp_buflet_size;\
	(_kbuf)->buf_dlen = 0;                                          \
	(_kbuf)->buf_doff = 0;                                          \
	((struct __kern_buflet_ext *)(_kbuf))->kbe_buf_pid = (pid_t)-1; \
	((struct __kern_buflet_ext *)(_kbuf))->kbe_buf_upp_link.sle_next = NULL;\
} while (0)

/* initialize struct __user_buflet from struct __kern_buflet */
#define UBUF_INIT(_kbuf, _ubuf) do {                                    \
	BUF_CTOR(_ubuf, 0, (_kbuf)->buf_idx, (_kbuf)->buf_dlim,         \
	    (_kbuf)->buf_dlen, (_kbuf)->buf_doff, (_kbuf)->buf_nbft_addr,\
	    (_kbuf)->buf_nbft_idx, (_kbuf)->buf_flag);                  \
	BUF_BFT_IDX_REG(_ubuf, (_kbuf)->buf_bft_idx_reg);              \
} while (0)

#define KBUF_EXTERNALIZE(_kbuf, _ubuf, _pp) do {                       \
	ASSERT((_kbuf)->buf_dlim == (_pp)->pp_buflet_size);            \
	ASSERT((_kbuf)->buf_addr != 0);                                \
	/* For now, user-facing pool does not support shared */        \
	/* buffer, since otherwise the ubuf and kbuf buffer  */        \
	/* indices would not match.  Assert this is the case.*/        \
	ASSERT((_kbuf)->buf_addr == (mach_vm_address_t)(_kbuf)->buf_objaddr);\
	/* Initialize user buflet metadata from kernel buflet */       \
	UBUF_INIT(_kbuf, _ubuf);                                       \
} while (0)

#define KBUF_LINK(_pkbuf, _kbuf) do {                                   \
	ASSERT(__DECONST(void *, (_pkbuf)->buf_nbft_addr) == NULL);     \
	ASSERT(__DECONST(obj_idx_t, (_pkbuf)->buf_nbft_idx) == OBJ_IDX_NONE); \
	ASSERT((_kbuf) != NULL);                                        \
	ASSERT((_kbuf)->buf_bft_idx_reg != OBJ_IDX_NONE);               \
	BUF_NBFT_ADDR(_pkbuf, _kbuf);                                   \
	BUF_NBFT_IDX(_pkbuf, (_kbuf)->buf_bft_idx_reg);                 \
} while (0)

#define KBUF_DTOR(_kbuf, _usecnt) do {                                  \
	if (__probable((_kbuf)->buf_ctl != NULL)) {                     \
	        (_usecnt) = skmem_bufctl_unuse(                         \
	            __DECONST(struct skmem_bufctl *, (_kbuf)->buf_ctl));\
	        *(struct skmem_bufctl **)                               \
	            (uintptr_t)&(_kbuf)->buf_ctl = NULL;                \
	}                                                               \
	BUF_BADDR(_kbuf, 0);                                            \
	BUF_BIDX(_kbuf, OBJ_IDX_NONE);                                  \
} while (0)

/*
 * Copy kernel buflet (and add reference count to buffer).
 */
#define _KBUF_COPY(_skb, _dkb) do {                                     \
	ASSERT((_skb)->buf_nbft_addr == 0);                             \
	ASSERT((_skb)->buf_nbft_idx == OBJ_IDX_NONE);                   \
	ASSERT(!((_dkb)->buf_flag & BUFLET_FLAG_EXTERNAL));             \
	_CASSERT(sizeof(struct __kern_buflet) == 44);                   \
	/* copy everything in the kernel buflet */                      \
	sk_copy64_40((uint64_t *)(void *)(_skb), (uint64_t *)(void *)(_dkb));\
	((uint32_t *)(void *)(_dkb))[10] = ((uint32_t *)(void *)(_skb))[10];\
	ASSERT((_dkb)->buf_ctl == (_skb)->buf_ctl);                     \
	_CASSERT(sizeof((_dkb)->buf_flag) == sizeof(uint16_t));         \
	*__DECONST(uint16_t *, &(_dkb)->buf_flag) &= ~BUFLET_FLAG_EXTERNAL;\
	if (__probable((_dkb)->buf_ctl != NULL)) {                      \
	        skmem_bufctl_use(__DECONST(struct skmem_bufctl *,       \
	            (_dkb)->buf_ctl));                                  \
	}                                                               \
} while (0)

/*
 * Kernel variant of __user_quantum.
 */
struct __kern_quantum {
	/*
	 * Common area between user and kernel variants.
	 */
	struct __quantum qum_com;

	/*
	 * Kernel specific.
	 */
	SLIST_ENTRY(__kern_quantum)     qum_upp_link;
	const struct kern_pbufpool      *qum_pp;
	const struct __user_quantum     *qum_user;
	const struct __kern_slot_desc   *qum_ksd;
	struct __kern_buflet            qum_buf[1];     /* 1 buflet */
	pid_t                           qum_pid;
} __attribute((aligned(sizeof(uint64_t))));

#define KQUM_CTOR(_kqum, _midx, _uqum, _pp, _qflags) do {               \
	ASSERT((uintptr_t)(_kqum) != (uintptr_t)(_uqum));               \
	_CASSERT(sizeof(METADATA_IDX(_kqum)) == sizeof(obj_idx_t));     \
	/* kernel variant (deconst) */                                  \
	_KQUM_CTOR(_kqum, (PP_KERNEL_ONLY(_pp) ?                        \
	    QUM_F_KERNEL_ONLY : 0) | _qflags, 0, 0, OBJ_IDX_NONE,       \
	    (_pp)->pp_buflet_size, _midx);                              \
	_CASSERT(NEXUS_META_TYPE_MAX <= UINT16_MAX);                    \
	METADATA_TYPE(_kqum) = (uint16_t)(_pp)->pp_md_type;             \
	_CASSERT(NEXUS_META_SUBTYPE_MAX <= UINT16_MAX);                 \
	METADATA_SUBTYPE(_kqum) = (uint16_t)(_pp)->pp_md_subtype;       \
	*(struct kern_pbufpool **)(uintptr_t)&(_kqum)->qum_pp = (_pp);  \
	*(struct __user_quantum **)(uintptr_t)&(_kqum)->qum_user = (_uqum); \
	*(obj_idx_t *)(uintptr_t)&METADATA_IDX(_kqum) = (_midx);        \
	(_kqum)->qum_pid = (pid_t)-1;                                   \
	*(struct __kern_slot_desc **)(uintptr_t)&(_kqum)->qum_ksd = NULL;\
	/* no need to construct user variant as it is done in externalize */ \
} while (0)

#define KQUM_INIT(_kqum, _flags) do {                                   \
	ASSERT((_kqum)->qum_ksd == NULL);                               \
	ASSERT((_kqum)->qum_pid == (pid_t)-1);                          \
	/* kernel variant (deconst) */                                  \
	_KQUM_INIT(_kqum, (PP_KERNEL_ONLY((_kqum)->qum_pp) ?            \
	    QUM_F_KERNEL_ONLY : 0) | _flags, 0, METADATA_IDX(_kqum));   \
	/* no need to initialize user variant as it is done in externalize */ \
} while (0)

__attribute__((always_inline))
inline boolean_t
_UUID_MATCH(uuid_t u1, uuid_t u2)
{
	uint64_t *a = (uint64_t *)(void *) u1;
	uint64_t *b = (uint64_t *)(void *) u2;
	bool first_same = (a[0] == b[0]);
	bool second_same = (a[1] == b[1]);

	return first_same && second_same;
}

#define _UUID_COPY(_dst, _src) do {                                     \
	_CASSERT(sizeof (uuid_t) == 16);                                \
	sk_copy64_16((uint64_t *)(void *)_src, (uint64_t *)(void *)_dst); \
} while (0)

#define _UUID_CLEAR(_u) do {                            \
	uint64_t *__dst = (uint64_t *)(void *)(_u);     \
	_CASSERT(sizeof (uuid_t) == 16);                \
	*(__dst++) = 0; /* qw[0] */                     \
	*(__dst)   = 0; /* qw[1] */                     \
} while (0)

/*
 * _QUM_COPY only copies the user metadata portion of the quantum;
 * at the moment this is everything from the beginning down to __q_flags,
 * but no more.  It preserves the destination's QUM_F_SAVE_MASK bits.
 *
 * NOTE: this needs to be adjusted if more user-mutable field is added
 * after __q_flags.
 */
#define _QUM_COPY(_skq, _dkq) do {                                          \
	volatile uint16_t _sf = ((_dkq)->qum_qflags & QUM_F_SAVE_MASK);     \
	_CASSERT(sizeof (_sf) == sizeof ((_dkq)->qum_qflags));              \
	_CASSERT(offsetof(struct __quantum, __q_flags) == 24);              \
	/* copy everything above (and excluding) __q_flags */               \
	sk_copy64_24((uint64_t *)(void *)&(_skq)->qum_com,                  \
	    (uint64_t *)(void *)&(_dkq)->qum_com);                          \
	/* copy __q_flags and restore saved bits */                         \
	(_dkq)->qum_qflags = ((_skq)->qum_qflags & ~QUM_F_SAVE_MASK) | _sf; \
} while (0)

/*
 * _QUM_INTERNALIZE internalizes a portion of the quantum that includes
 * user visible fields without overwriting the portion that's private to
 * the kernel; see comments on _QUM_COPY().
 */
#define _QUM_INTERNALIZE(_uq, _kq) do {                                 \
	_QUM_COPY(_uq, _kq);                                            \
	/* drop all but QUM_F_SAVE_MASK */                              \
	(_kq)->qum_qflags &= QUM_F_SAVE_MASK;                           \
} while (0)

/*
 * _QUM_EXTERNALIZE externalizes a portion of the quantum that's user
 * visible without including fields that's private to the kernel; at
 * the moment this is everything from the begininng down to __q_flags,
 * but no more.  It does NOT preserve the destination's QUM_F_SAVE_MASK
 * bits, but instead copies all bits except QUMF_KERNEL_FLAGS ones.
 *
 * NOTE: this needs to be adjusted if more user-mutable field is added
 * after __q_flags.  This macro is used only during externalize.
 */
#define _QUM_EXTERNALIZE(_kq, _uq) do {                                  \
	_CASSERT(offsetof(struct __quantum, __q_flags) == 24);           \
	_CASSERT(sizeof(METADATA_IDX(_uq)) == sizeof(obj_idx_t));        \
	/* copy __quantum excluding qum_qflags */                        \
	sk_copy64_24((uint64_t *)(void *)&(_kq)->qum_com,                \
	    (uint64_t *)(void *)&(_uq)->qum_com);                        \
	/* copy qum_qflags excluding saved bits */                       \
	(_uq)->qum_qflags = ((_kq)->qum_qflags & ~QUM_F_KERNEL_FLAGS);   \
	/* re-initialize user metadata */                                \
	*(obj_idx_t *)(uintptr_t)&METADATA_IDX(_uq) = METADATA_IDX(_kq); \
	METADATA_TYPE(_uq) = METADATA_TYPE(_kq);                         \
	METADATA_SUBTYPE(_uq) = METADATA_SUBTYPE(_kq);                   \
	(_uq)->qum_usecnt = 0;                                           \
} while (0)

/*
 * Transmit completion.
 */
struct __packet_compl {
	/*
	 * Tx completion data
	 * _arg & _data: context data which are passed as arguments
	 * to the registered Tx completion callback.
	 * _tx_status: Tx status set by the driver.
	 */
	union {
		uint64_t        compl_data64[3];
		struct {
			uintptr_t       _cb_arg;
			uintptr_t       _cb_data;
			uint32_t        _tx_status;
			uint32_t        _pad;
		} compl_data;
	};
	/* bitmap indicating the requested packet completion callbacks */
	uint32_t        compl_callbacks;
	/* Context identifier for a given packet completion */
	uint32_t        compl_context;
};

/*
 * Kernel variant of __user_packet.
 */
struct __kern_packet {
	struct __kern_quantum   pkt_qum;
#define pkt_user        pkt_qum.qum_user

	/*
	 * Common area between user and kernel variants.
	 */
	struct __packet         pkt_com;

	/*
	 * Option common area (PKT_F_OPT_DATA),
	 * non-NULL if PKT_F_OPT_ALLOC is set.
	 */
	struct __packet_opt     *pkt_com_opt;

	/* TX: enqueue time, RX: receive timestamp */
	uint64_t                pkt_timestamp;

	/* next chain in queue; used while enqueuing to classq or reass */
	struct __kern_packet    *pkt_nextpkt;

	/*
	 * Attached mbuf or pkt.
	 * Used by compat netif driver (PKT_F_MBUF_DATA) or interface
	 * filters (PKT_F_PKT_DATA).
	 */
	union {
		struct mbuf             *pkt_mbuf;
		struct __kern_packet    *pkt_pkt;
	};
	/*
	 * Flow classifier data (PKT_F_FLOW_DATA),
	 * non-NULL if PKT_F_FLOW_ALLOC is set.
	 */
	struct __flow           *pkt_flow;       /* classifier info */
#define pkt_flow_ipv4_addrs     pkt_flow->flow_ipv4_addrs
#define pkt_flow_ipv4_src       pkt_flow->flow_ipv4_src
#define pkt_flow_ipv4_dst       pkt_flow->flow_ipv4_dst
#define pkt_flow_ipv6_addrs     pkt_flow->flow_ipv6_addrs
#define pkt_flow_ipv6_src       pkt_flow->flow_ipv6_src
#define pkt_flow_ipv6_dst       pkt_flow->flow_ipv6_dst
#define pkt_flow_ip_ver         pkt_flow->flow_ip_ver
#define pkt_flow_ip_proto       pkt_flow->flow_ip_proto
#define pkt_flow_ip_hdr         pkt_flow->flow_ip_hdr
#define pkt_flow_tcp            pkt_flow->flow_tcp
#define pkt_flow_tcp_src        pkt_flow->flow_tcp_src
#define pkt_flow_tcp_dst        pkt_flow->flow_tcp_dst
#define pkt_flow_tcp_seq        pkt_flow->flow_tcp_seq
#define pkt_flow_tcp_ack        pkt_flow->flow_tcp_ack
#define pkt_flow_tcp_off        pkt_flow->flow_tcp_off
#define pkt_flow_tcp_flags      pkt_flow->flow_tcp_flags
#define pkt_flow_tcp_win        pkt_flow->flow_tcp_win
#define pkt_flow_tcp_hlen       pkt_flow->flow_tcp_hlen
#define pkt_flow_tcp_hdr        pkt_flow->flow_tcp_hdr
#define pkt_flow_tcp_agg_fast   pkt_flow->flow_tcp_agg_fast
#define pkt_flow_udp            pkt_flow->flow_udp
#define pkt_flow_udp_src        pkt_flow->flow_udp_src
#define pkt_flow_udp_dst        pkt_flow->flow_udp_dst
#define pkt_flow_udp_hlen       pkt_flow->flow_udp_hlen
#define pkt_flow_udp_hdr        pkt_flow->flow_udp_hdr
#define pkt_flow_esp_spi        pkt_flow->flow_esp_spi
#define pkt_transport_protocol  pkt_flow->flow_ulp_encap
#define pkt_flow_ip_hlen        pkt_flow->flow_ip_hlen
#define pkt_flow_ulen           pkt_flow->flow_ulen
#define pkt_flow_ip_frag_id     pkt_flow->flow_ip_frag_id
#define pkt_flow_ip_is_frag     pkt_flow->flow_ip_is_frag
#define pkt_flow_ip_is_first_frag pkt_flow->flow_ip_is_first_frag
#define pkt_flowsrc_token       pkt_flow->flow_src_token
#define pkt_flowsrc_id          pkt_flow->flow_src_id
#define pkt_flowsrc_fidx        pkt_flow->flow_src_fidx
#define pkt_flowsrc_type        pkt_flow->flow_src_type
#define pkt_classq_hash         pkt_flow->flow_classq_hash
#define pkt_classq_flags        pkt_flow->flow_classq_flags
#define pkt_policy_id           pkt_flow->flow_policy_id
#define pkt_policy_euuid        pkt_flow->flow_policy_euuid

	/*
	 * Transmit completion data (PKT_TX_COMPL_DATA),
	 * non-NULL if PKT_F_TX_COMPL_ALLOC is set.
	 */
	struct __packet_compl   *pkt_tx_compl;   /* TX completion info */
#define pkt_tx_compl_data       pkt_tx_compl->compl_data
#define pkt_tx_compl_data64     pkt_tx_compl->compl_data64
#define pkt_tx_compl_cb_arg     pkt_tx_compl->compl_data._cb_arg
#define pkt_tx_compl_cb_data    pkt_tx_compl->compl_data._cb_data
#define pkt_tx_compl_status     pkt_tx_compl->compl_data._tx_status
#define pkt_tx_compl_callbacks  pkt_tx_compl->compl_callbacks
#define pkt_tx_compl_context    pkt_tx_compl->compl_context

	/*
	 * Kernel specific.
	 *
	 * pkt_{bufs,max} aren't part of the common area, on purpose,
	 * since we selectively update them on internalize/externalize.
	 */
	const uint16_t  pkt_bufs_max;       /* maximum size of buflet chain */
	const uint16_t  pkt_bufs_cnt;       /* buflet chain size */
	uint32_t        pkt_chain_count;    /* number of packets in chain */
	uint32_t        pkt_chain_bytes;    /* number of bytes in chain */
} __attribute((aligned(sizeof(uint64_t))));

/* the size of __user_packet structure for n total buflets */
#define _KERN_PACKET_SIZE(n) sizeof(struct __kern_packet)

/*
 * Valid values for pkt_flags.
 */
#define PKT_KFLAGS_TX_COMPL     0x8     /* has pkt_tx_compl */

#define _PKT_COM_INIT(_p, _pflags) do {                                 \
	/* save packet flags since it might be wiped out */             \
	volatile uint64_t __pflags = (_pflags);                         \
	/* first wipe it clean */                                       \
	_CASSERT(sizeof(struct __packet_com) == 32);                    \
	_CASSERT(sizeof(struct __packet) == 32);                        \
	sk_zero_32(&(_p)->pkt_com.__pkt_data[0]);                       \
	/* then initialize */                                           \
	(_p)->pkt_pflags = (__pflags);                                  \
	(_p)->pkt_svc_class = KPKT_SC_UNSPEC;                           \
} while (0)

#define _PKT_CTOR(_p, _pflags, _bufcnt, _maxfrags) do {                 \
	_PKT_COM_INIT(_p, _pflags);                                     \
	_CASSERT(sizeof ((_p)->pkt_bufs_max) == sizeof (uint16_t));     \
	_CASSERT(sizeof ((_p)->pkt_bufs_cnt) == sizeof (uint16_t));     \
	/* deconst */                                                   \
	*(uint16_t *)(uintptr_t)&(_p)->pkt_bufs_max = (_maxfrags);      \
	*(uint16_t *)(uintptr_t)&(_p)->pkt_bufs_cnt = (_bufcnt);        \
} while (0)

#define KPKT_CLEAR_MBUF_PKT_DATA(_pk) do {                              \
	_CASSERT(offsetof(struct __kern_packet, pkt_mbuf) ==            \
	    offsetof(struct __kern_packet, pkt_pkt));                   \
	(_pk)->pkt_pflags &= ~(PKT_F_MBUF_MASK|PKT_F_PKT_MASK);         \
	/* the following also clears pkt_pkt */                         \
	(_pk)->pkt_mbuf = NULL;                                         \
} while (0)

#define KPKT_CLEAR_MBUF_DATA(_pk) do {                                  \
	(_pk)->pkt_pflags &= ~PKT_F_MBUF_MASK;                          \
	(_pk)->pkt_mbuf = NULL;                                         \
} while (0)

#define KPKT_CLEAR_PKT_DATA(_pk) do {                                   \
	(_pk)->pkt_pflags &= ~PKT_F_PKT_MASK;                           \
	(_pk)->pkt_pkt = NULL;                                          \
} while (0)

#define KPKT_CLEAR_FLOW_INIT(_fl) do {                                  \
	_CASSERT(sizeof ((_fl)->flow_init_data) == 128);                \
	sk_zero_128(&(_fl)->flow_init_data[0]);                         \
} while (0)

#define KPKT_CLEAR_FLOW_ALL(_fl) do {                                   \
	bzero(_fl, sizeof(struct __flow));                              \
} while (0)

#define _KPKT_CTOR_PRIV_VARS(_p, _opt, _flow, _txcomp) do {             \
	(_p)->pkt_com_opt = (_opt);                                     \
	(_p)->pkt_flow = (_flow);                                       \
	(_p)->pkt_tx_compl = (_txcomp);                                 \
} while (0)

#define _KPKT_INIT_PRIV_VARS(_p) do {                                   \
	struct __flow *__fl = (_p)->pkt_flow;                           \
	(_p)->pkt_timestamp = 0;                                        \
	(_p)->pkt_nextpkt = NULL;                                       \
	KPKT_CLEAR_MBUF_PKT_DATA(_p);                                   \
	if (__probable(__fl != NULL)) {                                 \
	        KPKT_CLEAR_FLOW_INIT(__fl);                             \
	}                                                               \
	(_p)->pkt_chain_count = (_p)->pkt_chain_bytes = 0;              \
} while (0)

#define KPKT_CTOR(_pk, _pflags, _opt, _flow, _txcomp, _midx, _pu, _pp,  \
	    _bufcnt, _maxfrags, _qflags) do {                           \
	ASSERT((uintptr_t)(_pk) != (uintptr_t)(_pu));                   \
	/* ASSERT((_pu) != NULL || PP_KERNEL_ONLY(_pp)); */             \
	/* kernel (and user) quantum */                                 \
	KQUM_CTOR(&(_pk)->pkt_qum, _midx,                               \
	    (((_pu) == NULL) ? NULL : &(_pu)->pkt_qum), _pp, _qflags);  \
	/* kernel packet variant */                                     \
	_PKT_CTOR(_pk, _pflags, _bufcnt, _maxfrags);                    \
	_KPKT_CTOR_PRIV_VARS(_pk, _opt, _flow, _txcomp);                \
	/* no need to construct user variant as it is done in externalize */ \
} while (0)

#define KPKT_INIT(_pk, _flags) do {                                     \
	KQUM_INIT(&(_pk)->pkt_qum, _flags);                             \
	_PKT_COM_INIT(_pk, (_pk)->pkt_pflags);                          \
	_KPKT_INIT_PRIV_VARS(_pk);                                      \
	/* no need to initialize user variant as it is done in externalize */ \
} while (0)

#define _KPKT_INIT_TX_COMPL_DATA(_p) do {                               \
	if (((_p)->pkt_pflags & PKT_F_TX_COMPL_DATA) == 0) {            \
	        ASSERT((_p)->pkt_pflags & PKT_F_TX_COMPL_ALLOC);        \
	        (_p)->pkt_pflags |= PKT_F_TX_COMPL_DATA;                \
	        _CASSERT(sizeof((_p)->pkt_tx_compl_data64) == 24);      \
	/* 32-bit compl_data should be in the union */          \
	        _CASSERT(sizeof((_p)->pkt_tx_compl_data) <= 24);        \
	        (_p)->pkt_tx_compl_data64[0] = 0;                       \
	        (_p)->pkt_tx_compl_data64[1] = 0;                       \
	        (_p)->pkt_tx_compl_data64[2] = 0;                       \
	}                                                               \
} while (0)

/*
 * Copy optional meta data.
 * Both source and destination must be a kernel packet.
 */
#define _PKT_COPY_OPT_DATA(_skp, _dkp) do {                             \
	if (__improbable(((_skp)->pkt_pflags & PKT_F_OPT_DATA) != 0)) { \
	        _CASSERT(sizeof(struct __packet_opt) == 32);            \
	        ASSERT((_skp)->pkt_pflags & PKT_F_OPT_ALLOC);           \
	        sk_copy64_32((uint64_t *)(void *)(_skp)->pkt_com_opt,   \
	            (uint64_t *)(void *)(_dkp)->pkt_com_opt);           \
	}                                                               \
} while (0)

/*
 * _PKT_COPY only copies the user metadata portion of the packet;
 * at the moment this is everything from the beginning down to __p_flags,
 * but no more.  It additionally copies only QUM_F_COPY_MASK bits from
 * the source __p_flags to the destination's.
 *
 * NOTE: this needs to be adjusted if more user-mutable field is added
 * after __p_flags.
 */
#define _PKT_COPY(_skp, _dkp) do {                                      \
	_CASSERT(sizeof(struct __packet) == 32);                        \
	_CASSERT(sizeof(struct __packet_com) == 32);                    \
	_CASSERT(offsetof(struct __packet, __p_flags) == 24);           \
	/* copy __packet excluding pkt_pflags */                        \
	sk_copy64_24((uint64_t *)(void *)&(_skp)->pkt_com,              \
	    (uint64_t *)(void *)&(_dkp)->pkt_com);                      \
	/* copy relevant pkt_pflags bits */                             \
	(_dkp)->pkt_pflags = ((_skp)->pkt_pflags & PKT_F_COPY_MASK);    \
	/* copy __packet_opt if applicable */                           \
	_PKT_COPY_OPT_DATA((_skp), (_dkp));                             \
} while (0)

/*
 * _PKT_INTERNALIZE internalizes a portion of the packet that includes
 * user visible fields without overwriting the portion that's private to
 * the kernel.
 *
 * NOTE: this needs to be adjusted if more user-mutable data is added
 * after __p_flags.  This macro is used only during internalize.
 */
#define _PKT_INTERNALIZE(_up, _kp) do {                                 \
	volatile uint64_t _kf = ((_kp)->pkt_pflags & ~PKT_F_USER_MASK); \
	_CASSERT(sizeof(struct __packet) == 32);                        \
	_CASSERT(sizeof(struct __packet_com) == 32);                    \
	_CASSERT(offsetof(struct __packet, __p_flags) == 24);           \
	/* copy __packet excluding pkt_pflags */                        \
	sk_copy64_24((uint64_t *)(void *)&(_up)->pkt_com,               \
	    (uint64_t *)(void *)&(_kp)->pkt_com);                       \
	/* copy pkt_pflags and restore kernel bits */                   \
	(_kp)->pkt_pflags = ((_up)->pkt_pflags & PKT_F_USER_MASK) | _kf;\
	/* copy (internalize) __packet_opt if applicable */             \
	if (__improbable(((_kp)->pkt_pflags & PKT_F_OPT_DATA) != 0)) {  \
	        _CASSERT(sizeof(struct __packet_opt) == 32);            \
	        ASSERT((_kp)->pkt_pflags & PKT_F_OPT_ALLOC);            \
	        sk_copy64_32((uint64_t *)(void *)&(_up)->pkt_com_opt,   \
	            (uint64_t *)(void *)(_kp)->pkt_com_opt);            \
	}                                                               \
} while (0)

/*
 * _PKT_EXTERNALIZE externalizes a portion of the packet that's user
 * visible without including fields that's private to the kernel; at the
 * moment this is everything from the beginning down to __p_flags,
 * but no more.
 *
 * NOTE: this needs to be adjusted if more user-mutable data is added
 * after __p_flags.  This macro is used only during externalize.
 */
#define _PKT_EXTERNALIZE(_kp, _up) do {                                 \
	_CASSERT(sizeof(struct __packet) == 32);                        \
	_CASSERT(sizeof(struct __packet_com) == 32);                    \
	_CASSERT(offsetof(struct __packet, __p_flags) == 24);           \
	/* copy __packet excluding pkt_pflags */                        \
	sk_copy64_24((uint64_t *)(void *)&(_kp)->pkt_com,               \
	    (uint64_t *)(void *)&(_up)->pkt_com);                       \
	/* copy pkt_pflags excluding kernel bits */                     \
	(_up)->pkt_pflags = ((_kp)->pkt_pflags & PKT_F_USER_MASK);      \
	/* copy (externalize) __packet_opt if applicable */             \
	if (__improbable(((_kp)->pkt_pflags & PKT_F_OPT_DATA) != 0)) {  \
	        _CASSERT(sizeof(struct __packet_opt) == 32);            \
	        ASSERT((_kp)->pkt_pflags & PKT_F_OPT_ALLOC);            \
	        sk_copy64_32((uint64_t *)(void *)(_kp)->pkt_com_opt,    \
	            (uint64_t *)(void *)&(_up)->pkt_com_opt);           \
	}                                                               \
} while (0)

#define SK_PTR_ADDR_KQUM(_ph)   ((struct __kern_quantum *)SK_PTR_ADDR(_ph))
#define SK_PTR_ADDR_KPKT(_ph)   ((struct __kern_packet *)SK_PTR_ADDR(_ph))
#define SK_PTR_KPKT(_pa)        ((struct __kern_packet *)(void *)(_pa))
#define SK_PKT2PH(_pkt) \
    (SK_PTR_ENCODE((_pkt), METADATA_TYPE((_pkt)), METADATA_SUBTYPE((_pkt))))

/*
 * Set the length of the data to various places: __user_slot_desc,
 * __kern_quantum, and for a packet, the buflet.
 * !!! This should be used only for dropping the packet as the macro
 * is not functionally correct.
 *
 * TODO: adi@apple.com -- maybe finalize here as well?
 */
#define METADATA_SET_LEN(_md, _len, _doff) do {                         \
	struct __kern_quantum *_q =                                     \
	    (struct __kern_quantum *)(void *)(_md);                     \
	_q->qum_len = (_len);                                           \
	switch (METADATA_TYPE(_q)) {                                    \
	case NEXUS_META_TYPE_PACKET: {                                  \
	        struct __kern_packet *_p =                              \
	            (struct __kern_packet *)(void *)(_md);              \
	        struct __kern_buflet *_kbft;                            \
	        PKT_GET_FIRST_BUFLET(_p, _p->pkt_bufs_cnt, _kbft);      \
	        _kbft->buf_dlen = (_len);                               \
	        _kbft->buf_doff = (_doff);                              \
	        break;                                                  \
	}                                                               \
	default:                                                        \
	        ASSERT(METADATA_TYPE(_q) == NEXUS_META_TYPE_QUANTUM);   \
	        _q->qum_buf[0].buf_dlen = (_len);                       \
	        _q->qum_buf[0].buf_doff = (_doff);                      \
	        break;                                                  \
	}                                                               \
} while (0)

#define METADATA_ADJUST_LEN(_md, _len, _doff) do {                      \
	struct __kern_quantum *_q =                                     \
	    (struct __kern_quantum *)(void *)(_md);                     \
	switch (METADATA_TYPE(_q)) {                                    \
	case NEXUS_META_TYPE_PACKET: {                                  \
	        struct __kern_packet *_p =                              \
	            (struct __kern_packet *)(void *)(_md);              \
	        struct __kern_buflet *_kbft;                            \
	        PKT_GET_FIRST_BUFLET(_p, _p->pkt_bufs_cnt, _kbft);      \
	        _kbft->buf_dlen += (_len);                               \
	        _kbft->buf_doff = (_doff);                              \
	        break;                                                  \
	}                                                               \
	default:                                                        \
	        ASSERT(METADATA_TYPE(_q) == NEXUS_META_TYPE_QUANTUM);   \
	        _q->qum_buf[0].buf_dlen += (_len);                      \
	        _q->qum_buf[0].buf_doff = (_doff);                      \
	        break;                                                  \
	}                                                               \
} while (0)

__attribute__((always_inline))
static inline kern_packet_t
SD_GET_TAGGED_METADATA(const struct __kern_slot_desc *ksd)
{
	return __improbable(ksd->sd_md == NULL) ? 0 :
	       SK_PTR_ENCODE(ksd->sd_md, METADATA_TYPE(ksd->sd_qum),
	           METADATA_SUBTYPE(ksd->sd_qum));
}

__attribute__((always_inline))
static inline errno_t
KR_SLOT_ATTACH_METADATA(const kern_channel_ring_t kring,
    struct __kern_slot_desc *ksd, struct __kern_quantum *kqum)
{
	obj_idx_t idx = KR_SLOT_INDEX(kring,
	    (struct __slot_desc *)(void *)ksd);

	/* Ensure this is only done by the thread doing a sync syscall */
	ASSERT(sk_is_sync_protected());
	ASSERT(kqum->qum_pp == kring->ckr_pp);
	ASSERT(kqum->qum_ksd == NULL);
	/*
	 * Packets being attached to a slot should always be internalized.
	 * Internalized packet should be in finalized or dropped state.
	 */
	ASSERT(kqum->qum_qflags & QUM_F_INTERNALIZED);
	ASSERT(((kqum->qum_qflags & QUM_F_FINALIZED) != 0) ^
	    ((kqum->qum_qflags & QUM_F_DROPPED) != 0));

	kqum->qum_ksd = ksd;

	KSD_ATTACH_METADATA(ksd, kqum);
	if (!KR_KERNEL_ONLY(kring)) {
		USD_ATTACH_METADATA(KR_USD(kring, idx), METADATA_IDX(kqum));
	}

	return 0;
}

__attribute__((always_inline))
static inline struct __kern_quantum *
KR_SLOT_DETACH_METADATA(const kern_channel_ring_t kring,
    struct __kern_slot_desc *ksd)
{
	struct __kern_quantum *kqum = ksd->sd_qum;
	obj_idx_t idx = KR_SLOT_INDEX(kring,
	    (struct __slot_desc *)(void *)ksd);

	/* Ensure this is only done by the thread doing a sync syscall */
	ASSERT(sk_is_sync_protected());
	ASSERT(KSD_VALID_METADATA(ksd));
	ASSERT(kqum->qum_ksd == ksd);
	ASSERT(kqum->qum_pp == kring->ckr_pp);
	/*
	 * Packets being attached to a slot would always be internalized.
	 * We also detach externalized packets on an rx ring on behalf
	 * of the user space if the channel is not in user packet pool mode.
	 * Externalized packet should be in finalized or dropped state.
	 */
	ASSERT((kqum->qum_qflags & (QUM_F_INTERNALIZED)) ||
	    ((((kqum->qum_qflags & QUM_F_FINALIZED) != 0) ^
	    ((kqum->qum_qflags & QUM_F_DROPPED) != 0))));

	/* detaching requires the packet to be finalized later */
	kqum->qum_qflags &= ~QUM_F_FINALIZED;
	kqum->qum_ksd = NULL;

	KSD_DETACH_METADATA(ksd);
	if (!KR_KERNEL_ONLY(kring)) {
		USD_DETACH_METADATA(KR_USD(kring, idx));
	}

	return kqum;
}

__attribute__((always_inline))
static inline errno_t
KR_SLOT_ATTACH_BUF_METADATA(const kern_channel_ring_t kring,
    struct __kern_slot_desc *ksd, struct __kern_buflet *kbuf)
{
	obj_idx_t idx = KR_SLOT_INDEX(kring,
	    (struct __slot_desc *)(void *)ksd);

	/* Ensure this is only done by the thread doing a sync syscall */
	ASSERT(sk_is_sync_protected());

	KSD_ATTACH_METADATA(ksd, kbuf);
	/*
	 * buflet is attached only to the user packet pool alloc ring.
	 */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(kring->ckr_tx == CR_KIND_ALLOC);
	USD_ATTACH_METADATA(KR_USD(kring, idx), kbuf->buf_bft_idx_reg);
	return 0;
}

#if (DEVELOPMENT || DEBUG)
SYSCTL_DECL(_kern_skywalk_packet);
extern int pkt_trailers;
#endif /* !DEVELOPMENT && !DEBUG */

typedef void (pkt_copy_from_pkt_t)(const enum txrx, kern_packet_t,
    const uint16_t, kern_packet_t, const uint16_t, const uint32_t,
    const boolean_t, const uint16_t, const uint16_t, const boolean_t);

typedef void (pkt_copy_from_mbuf_t)(const enum txrx, kern_packet_t,
    const uint16_t, struct mbuf *, const uint16_t, const uint32_t,
    const boolean_t, const uint16_t);

typedef void (pkt_copy_to_mbuf_t)(const enum txrx, kern_packet_t,
    const uint16_t, struct mbuf *, const uint16_t, const uint32_t,
    const boolean_t, const uint16_t);

__BEGIN_DECLS
extern void pkt_subtype_assert_fail(const kern_packet_t, uint64_t, uint64_t);
extern void pkt_type_assert_fail(const kern_packet_t, uint64_t);

extern pkt_copy_from_pkt_t pkt_copy_from_pkt;
extern pkt_copy_from_pkt_t pkt_copy_multi_buflet_from_pkt;
extern pkt_copy_from_mbuf_t pkt_copy_from_mbuf;
extern pkt_copy_from_mbuf_t pkt_copy_multi_buflet_from_mbuf;
extern pkt_copy_to_mbuf_t pkt_copy_to_mbuf;
extern pkt_copy_to_mbuf_t pkt_copy_multi_buflet_to_mbuf;

extern void pkt_copypkt_sum(kern_packet_t, uint16_t, kern_packet_t,
    uint16_t, uint16_t, uint32_t *, boolean_t);
extern uint32_t
pkt_copyaddr_sum(kern_packet_t sph, uint16_t soff, uint8_t *dbaddr,
    uint16_t len, boolean_t do_csum, uint32_t initial_sum, boolean_t *odd_start);
extern uint32_t pkt_sum(kern_packet_t, uint16_t, uint16_t);
extern uint32_t pkt_mcopypkt_sum(mbuf_t, int, kern_packet_t, uint16_t,
    uint16_t, boolean_t);
extern uint32_t
m_copydata_sum(struct mbuf *m, int off, int len, void *vp, uint32_t initial_sum,
    boolean_t *odd_start);
extern void pkt_copy(void *src, void *dst, size_t len);

#if (DEVELOPMENT || DEBUG)
extern uint32_t pkt_add_trailers(kern_packet_t, const uint32_t, const uint16_t);
extern uint32_t pkt_add_trailers_mbuf(struct mbuf *, const uint16_t);
#endif /* !DEVELOPMENT && !DEBUG */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_PACKET_PACKETVAR_H_ */
