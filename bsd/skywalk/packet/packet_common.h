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

#ifndef _SKYWALK_PACKET_COMMON_H_
#define _SKYWALK_PACKET_COMMON_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
/*
 * Routines common to kernel and userland.  This file is intended to
 * be included by code implementing the packet APIs, in particular,
 * the Skywalk kernel and libsyscall code.
 */

#include <skywalk/os_packet_private.h>
#include <net/if_vlan_var.h>
#include <sys/errno.h>
#include <sys/kdebug.h>

#ifndef KERNEL
/*
 * User.
 */
#if !defined(LIBSYSCALL_INTERFACE)
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */
#define QUM_ADDR(_ph)   SK_PTR_ADDR_UQUM(_ph)
#define PKT_ADDR(_ph)   SK_PTR_ADDR_UPKT(_ph)
#define BLT_ADDR(_bp)   ((struct __user_buflet *)(uintptr_t)_bp)
#else /* KERNEL */
/*
 * Kernel.
 */
#include <skywalk/packet/packet_var.h>
#include <skywalk/packet/pbufpool_var.h>
#define QUM_ADDR(_ph)   SK_PTR_ADDR_KQUM(_ph)
#define PKT_ADDR(_ph)   SK_PTR_ADDR_KPKT(_ph)
#define BLT_ADDR(_bp)   ((struct __kern_buflet *)(uintptr_t)_bp)
#define PKT_HAS_ATTACHED_MBUF(_ph)              \
	((PKT_ADDR(_ph)->pkt_pflags & PKT_F_MBUF_DATA) != 0)
#endif /* KERNEL */

/*
 * Common.
 */
#if (DEBUG || DEVELOPMENT)
#define PKT_SUBTYPE_ASSERT(_ph, _type, _subtype) do {                   \
	if (__improbable(SK_PTR_TYPE(_ph) != (uint64_t)(_type) ||       \
	    SK_PTR_SUBTYPE(_ph) != (uint64_t)(_subtype))) {             \
	        pkt_subtype_assert_fail(_ph, _type, _subtype);          \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)

#define PKT_TYPE_ASSERT(_ph, _type) do {                                \
	if (__improbable(SK_PTR_TYPE(_ph) != (uint64_t)(_type))) {      \
	        pkt_type_assert_fail(_ph, _type);                       \
	/* NOTREACHED */                                        \
	        __builtin_unreachable();                                \
	}                                                               \
} while (0)
#else /* !DEBUG && !DEVELOPMENT */
#define PKT_SUBTYPE_ASSERT(_ph, _type, _subtype)        ((void)0)
#define PKT_TYPE_ASSERT(_ph, _type)                     ((void)0)
#endif /* !DEBUG && !DEVELOPMENT */

#define QUM_GET_NEXT_BUFLET(_qum, _pbuf, _buf) do {                     \
	ASSERT((_pbuf) == NULL || (_pbuf) == (_qum)->qum_buf);          \
	(_buf) = (((_pbuf) == NULL) ? (_qum)->qum_buf : NULL);          \
} while (0)

#define PKT_GET_FIRST_BUFLET(_pkt, _bcnt, _buf) do {                    \
	if (__improbable((_bcnt) == 0)) {                               \
	        (_buf) = NULL;                                          \
	        break;                                                  \
	}                                                               \
	if (__probable((_pkt)->pkt_qum_buf.buf_addr != 0)) {            \
	        (_buf) = &(_pkt)->pkt_qum_buf;                          \
	} else {                                                        \
	        (_buf) = __DECONST(void *, (_pkt)->pkt_qum_buf.buf_nbft_addr);\
	}                                                               \
} while (0)

#define _PKT_GET_NEXT_BUFLET(_pkt, _bcnt, _pbuf, _buf) do {             \
	if ((_pbuf) == NULL) {                                          \
	        PKT_GET_FIRST_BUFLET(_pkt, _bcnt, _buf);                \
	} else {                                                        \
	        (_buf) = __DECONST(void *, (_pbuf)->buf_nbft_addr);     \
	}                                                               \
} while (0)

#ifndef KERNEL
#define PKT_GET_NEXT_BUFLET(_pkt, _bcnt, _pbuf, _buf) do {              \
	_PKT_GET_NEXT_BUFLET(_pkt, _bcnt, _pbuf, _buf);                 \
} while (0)
#else /* KERNEL */
#define PKT_GET_NEXT_BUFLET(_pkt, _bcnt, _pbuf, _buf) do {              \
	ASSERT(((_bcnt) >= 1) || ((_pbuf) == NULL));                    \
	_PKT_GET_NEXT_BUFLET(_pkt, _bcnt, _pbuf, _buf);                 \
} while (0)
#endif /* KERNEL */

__attribute__((always_inline))
static inline int
__packet_set_headroom(const uint64_t ph, const uint8_t headroom)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	if (__probable(headroom < PKT_ADDR(ph)->pkt_qum_buf.buf_dlim)) {
		PKT_ADDR(ph)->pkt_headroom = headroom;
		return 0;
	}
	return ERANGE;
}

__attribute__((always_inline))
static inline uint8_t
__packet_get_headroom(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	return PKT_ADDR(ph)->pkt_headroom;
}

__attribute__((always_inline))
static inline int
__packet_set_link_header_length(const uint64_t ph, const uint8_t len)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if (__probable(len <= PKT_ADDR(ph)->pkt_qum_buf.buf_dlim)) {
		PKT_ADDR(ph)->pkt_l2_len = len;
		return 0;
	}
	return ERANGE;
}

__attribute__((always_inline))
static inline uint8_t
__packet_get_link_header_length(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return PKT_ADDR(ph)->pkt_l2_len;
}

__attribute__((always_inline))
static inline int
__packet_set_link_broadcast(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	PKT_ADDR(ph)->pkt_link_flags |= PKT_LINKF_BCAST;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_link_broadcast(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	return (PKT_ADDR(ph)->pkt_link_flags & PKT_LINKF_BCAST) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_link_multicast(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	PKT_ADDR(ph)->pkt_link_flags |= PKT_LINKF_MCAST;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_link_multicast(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	return (PKT_ADDR(ph)->pkt_link_flags & PKT_LINKF_MCAST) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_link_ethfcs(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	PKT_ADDR(ph)->pkt_link_flags |= PKT_LINKF_ETHFCS;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_link_ethfcs(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	return (PKT_ADDR(ph)->pkt_link_flags & PKT_LINKF_ETHFCS) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_transport_traffic_background(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_BACKGROUND;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_transport_traffic_background(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_BACKGROUND) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_transport_traffic_realtime(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_REALTIME;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_transport_traffic_realtime(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_REALTIME) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_transport_retransmit(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_REXMT;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_transport_retransmit(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_REXMT) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_transport_last_packet(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_LAST_PKT;
	return 0;
}

__attribute__((always_inline))
static inline int
__packet_set_group_start(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_OPT_GROUP_START;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_group_start(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_GROUP_START) != 0;
}

__attribute__((always_inline))
static inline int
__packet_set_group_end(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_OPT_GROUP_END;
	return 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_group_end(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_GROUP_END) != 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_get_expire_time(const uint64_t ph, uint64_t *ts)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_EXPIRE_TS) == 0) {
		return ENOENT;
	}
	if (ts == NULL) {
		return EINVAL;
	}
	*ts = po->__po_expire_ts;
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_expire_time(const uint64_t ph, const uint64_t ts)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
	if (ts != 0) {
		po->__po_expire_ts = ts;
		PKT_ADDR(ph)->pkt_pflags |= PKT_F_OPT_EXPIRE_TS;
	} else {
		po->__po_expire_ts = 0;
		PKT_ADDR(ph)->pkt_pflags &= ~PKT_F_OPT_EXPIRE_TS;
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_opt_get_token(const struct __packet_opt *po, void *token,
    uint16_t *len, uint8_t *type)
{
	uint16_t tlen = po->__po_token_len;
	uint8_t ttype;

	if (token == NULL || len == NULL || type == NULL || tlen > *len || po->__po_token_type > UINT8_MAX) {
		return EINVAL;
	}
	ttype = (uint8_t)po->__po_token_type;

	ASSERT(tlen <= PKT_OPT_MAX_TOKEN_SIZE);
	_CASSERT((__builtin_offsetof(struct __packet_opt, __po_token) % 8) == 0);
	bcopy(po->__po_token, token, tlen);
	*len = tlen;
	*type = ttype;
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_get_token(const uint64_t ph, void *token, uint16_t *len)
{
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
	uint8_t type;
	errno_t err;

	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_TOKEN) == 0) {
		return ENOENT;
	}
	err = __packet_opt_get_token(po, token, len, &type);
	if ((err == 0) && (type != PKT_OPT_TOKEN_TYPE_OPAQUE)) {
		err = ENOENT;
	}
	return err;
}

__attribute__((always_inline))
static inline errno_t
__packet_opt_set_token(struct __packet_opt *po, const void *token,
    const uint16_t len, const uint8_t type, volatile uint64_t *pflags)
{
	_CASSERT((__builtin_offsetof(struct __packet_opt, __po_token) % 8) == 0);
	if (len != 0) {
		if (token == NULL || len > PKT_OPT_MAX_TOKEN_SIZE ||
		    type == 0) {
			return EINVAL;
		}
		if (__probable(IS_P2ALIGNED(token, 8))) {
			uint64_t *token64 = __DECONST(void *, token);
			po->__po_token_data[0] = *token64;
			po->__po_token_data[1] = *(token64 + 1);
		} else {
			bcopy(token, po->__po_token, len);
		}
		po->__po_token_len = len;
		po->__po_token_type = type;
		*pflags |= PKT_F_OPT_TOKEN;
	} else {
		_CASSERT(sizeof(po->__po_token_data[0]) == 8);
		_CASSERT(sizeof(po->__po_token_data[1]) == 8);
		_CASSERT(sizeof(po->__po_token) == 16);
		po->__po_token_data[0] = 0;
		po->__po_token_data[1] = 0;
		po->__po_token_len = 0;
		po->__po_token_type = 0;
		*pflags &= ~PKT_F_OPT_TOKEN;
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_token(const uint64_t ph, const void *token, const uint16_t len)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
#ifdef KERNEL
	return __packet_opt_set_token(PKT_ADDR(ph)->pkt_com_opt, token, len,
	           PKT_OPT_TOKEN_TYPE_OPAQUE, &PKT_ADDR(ph)->pkt_pflags);
#else /* !KERNEL */
	return __packet_opt_set_token(&PKT_ADDR(ph)->pkt_com_opt, token, len,
	           PKT_OPT_TOKEN_TYPE_OPAQUE, &PKT_ADDR(ph)->pkt_pflags);
#endif /* !KERNEL */
}

__attribute__((always_inline))
static inline errno_t
__packet_get_packetid(const uint64_t ph, packet_id_t *pktid)
{
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
	uint16_t len = sizeof(packet_id_t);
	uint8_t type;
	errno_t err;

	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_TOKEN) == 0) {
		return ENOENT;
	}
	err = __packet_opt_get_token(po, pktid, &len, &type);
	if ((err == 0) && ((type != PKT_OPT_TOKEN_TYPE_PACKET_ID) ||
	    (len != sizeof(packet_id_t)))) {
		err = ENOENT;
	}
	return err;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_packetid(const uint64_t ph, const packet_id_t *pktid)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
#ifdef KERNEL
	return __packet_opt_set_token(PKT_ADDR(ph)->pkt_com_opt, pktid,
	           sizeof(packet_id_t), PKT_OPT_TOKEN_TYPE_PACKET_ID,
	           &PKT_ADDR(ph)->pkt_pflags);
#else /* !KERNEL */
	return __packet_opt_set_token(&PKT_ADDR(ph)->pkt_com_opt, pktid,
	           sizeof(packet_id_t), PKT_OPT_TOKEN_TYPE_PACKET_ID,
	           &PKT_ADDR(ph)->pkt_pflags);
#endif /* !KERNEL */
}

__attribute__((always_inline))
static inline errno_t
__packet_get_vlan_tag(const uint64_t ph, uint16_t *vlan_tag,
    boolean_t *tag_in_pkt)
{
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
	uint64_t pflags;

	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	pflags = PKT_ADDR(ph)->pkt_pflags;
	if ((pflags & PKT_F_OPT_VLTAG) == 0) {
		return ENOENT;
	}
	if (vlan_tag != NULL) {
		*vlan_tag = po->__po_vlan_tag;
	}
	if (tag_in_pkt != NULL) {
		*tag_in_pkt = ((pflags & PKT_F_OPT_VLTAG_IN_PKT) != 0);
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_vlan_tag(const uint64_t ph, const uint16_t vlan_tag,
    const boolean_t tag_in_pkt)
{
#ifdef KERNEL
	struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
	struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */

	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_OPT_VLTAG;
	po->__po_vlan_tag = vlan_tag;

	if (tag_in_pkt) {
		PKT_ADDR(ph)->pkt_pflags |= PKT_F_OPT_VLTAG_IN_PKT;
	}
	return 0;
}

__attribute__((always_inline))
static inline uint16_t
__packet_get_vlan_id(const uint16_t vlan_tag)
{
	return EVL_VLANOFTAG(vlan_tag);
}

__attribute__((always_inline))
static inline uint8_t
__packet_get_vlan_priority(const uint16_t vlan_tag)
{
	return EVL_PRIOFTAG(vlan_tag);
}

#ifdef KERNEL
__attribute__((always_inline))
static inline void
__packet_set_wake_flag(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_pflags |= PKT_F_WAKE_PKT;
}
#endif

__attribute__((always_inline))
static inline boolean_t
__packet_get_wake_flag(const uint64_t ph)
{
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_WAKE_PKT) != 0;
}

__attribute__((always_inline))
static inline void
__packet_set_keep_alive(const uint64_t ph, const boolean_t is_keep_alive)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if (is_keep_alive) {
		PKT_ADDR(ph)->pkt_pflags |= PKT_F_KEEPALIVE;
	} else {
		PKT_ADDR(ph)->pkt_pflags &= ~PKT_F_KEEPALIVE;
	}
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_keep_alive(const uint64_t ph)
{
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_KEEPALIVE) != 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_truncated(const uint64_t ph)
{
	PKT_SUBTYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET, NEXUS_META_SUBTYPE_RAW);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_TRUNCATED) != 0;
}

#ifdef KERNEL
__attribute__((always_inline))
static inline boolean_t
__packet_get_transport_new_flow(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_NEW_FLOW) != 0;
}

__attribute__((always_inline))
static inline boolean_t
__packet_get_transport_last_packet(const uint64_t ph)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	return (PKT_ADDR(ph)->pkt_pflags & PKT_F_LAST_PKT) != 0;
}
#endif /* KERNEL */

__attribute__((always_inline))
static inline int
__packet_set_service_class(const uint64_t ph, const uint32_t sc)
{
	int err = 0;

	_CASSERT(sizeof(QUM_ADDR(ph)->qum_svc_class == sizeof(uint32_t)));

	switch (sc) {
	case PKT_SC_BE:
	case PKT_SC_BK_SYS:
	case PKT_SC_BK:
	case PKT_SC_RD:
	case PKT_SC_OAM:
	case PKT_SC_AV:
	case PKT_SC_RV:
	case PKT_SC_VI:
	case PKT_SC_SIG:
	case PKT_SC_VO:
	case PKT_SC_CTL:
		QUM_ADDR(ph)->qum_svc_class = sc;
		break;

	default:
		err = EINVAL;
		break;
	}

	return err;
}

__attribute__((always_inline))
static inline uint32_t
__packet_get_service_class(const uint64_t ph)
{
	uint32_t sc;

	_CASSERT(sizeof(QUM_ADDR(ph)->qum_svc_class == sizeof(uint32_t)));

	switch (QUM_ADDR(ph)->qum_svc_class) {
	case PKT_SC_BE:         /* most likely best effort */
	case PKT_SC_BK_SYS:
	case PKT_SC_BK:
	case PKT_SC_RD:
	case PKT_SC_OAM:
	case PKT_SC_AV:
	case PKT_SC_RV:
	case PKT_SC_VI:
	case PKT_SC_SIG:
	case PKT_SC_VO:
	case PKT_SC_CTL:
		sc = QUM_ADDR(ph)->qum_svc_class;
		break;

	default:
		sc = PKT_SC_BE;
		break;
	}

	return sc;
}

__attribute__((always_inline))
static inline void
__packet_set_comp_gencnt(const uint64_t ph, const uint32_t gencnt)
{
	_CASSERT(sizeof(PKT_ADDR(ph)->pkt_comp_gencnt == sizeof(uint32_t)));
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	PKT_ADDR(ph)->pkt_comp_gencnt = gencnt;
}

__attribute__((always_inline))
static inline uint32_t
__packet_get_comp_gencnt(const uint64_t ph)
{
	_CASSERT(sizeof(PKT_ADDR(ph)->pkt_comp_gencnt == sizeof(uint32_t)));
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	return PKT_ADDR(ph)->pkt_comp_gencnt;
}


__attribute__((always_inline))
static inline int
__packet_set_traffic_class(const uint64_t ph, const uint32_t tc)
{
	uint32_t val = PKT_TC2SCVAL(tc);        /* just the val portion */
	uint32_t sc;

	switch (val) {
	case PKT_SCVAL_BK_SYS:
		sc = PKT_SC_BK_SYS;
		break;
	case PKT_SCVAL_BK:
		sc = PKT_SC_BK;
		break;
	case PKT_SCVAL_BE:
		sc = PKT_SC_BE;
		break;
	case PKT_SCVAL_RD:
		sc = PKT_SC_RD;
		break;
	case PKT_SCVAL_OAM:
		sc = PKT_SC_OAM;
		break;
	case PKT_SCVAL_AV:
		sc = PKT_SC_AV;
		break;
	case PKT_SCVAL_RV:
		sc = PKT_SC_RV;
		break;
	case PKT_SCVAL_VI:
		sc = PKT_SC_VI;
		break;
	case PKT_SCVAL_SIG:
		sc = PKT_SC_SIG;
		break;
	case PKT_SCVAL_VO:
		sc = PKT_SC_VO;
		break;
	case PKT_SCVAL_CTL:
		sc = PKT_SC_CTL;
		break;
	default:
		sc = PKT_SC_BE;
		break;
	}

	return __packet_set_service_class(ph, sc);
}

__attribute__((always_inline))
static inline uint32_t
__packet_get_traffic_class(const uint64_t ph)
{
	return PKT_SC2TC(__packet_get_service_class(ph));
}

__attribute__((always_inline))
static inline int
__packet_set_inet_checksum(const uint64_t ph, const packet_csum_flags_t flags,
    const uint16_t start, const uint16_t stuff_val, boolean_t tx)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	PKT_ADDR(ph)->pkt_csum_flags = flags;

	if (tx) {
		PKT_ADDR(ph)->pkt_csum_tx_start_off = start;
		PKT_ADDR(ph)->pkt_csum_tx_stuff_off = stuff_val;
	} else {
		PKT_ADDR(ph)->pkt_csum_rx_start_off = start;
		PKT_ADDR(ph)->pkt_csum_rx_value = stuff_val;
	}
	return 0;
}

__attribute__((always_inline))
static inline packet_csum_flags_t
__packet_get_inet_checksum(const uint64_t ph, uint16_t *start,
    uint16_t *stuff_val, boolean_t tx)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	if (tx) {
		if (__probable(start != NULL)) {
			*start = PKT_ADDR(ph)->pkt_csum_tx_start_off;
		}
		if (__probable(stuff_val != NULL)) {
			*stuff_val = PKT_ADDR(ph)->pkt_csum_tx_stuff_off;
		}
	} else {
		if (__probable(start != NULL)) {
			*start = PKT_ADDR(ph)->pkt_csum_rx_start_off;
		}
		if (__probable(stuff_val != NULL)) {
			*stuff_val = PKT_ADDR(ph)->pkt_csum_rx_value;
		}
	}
	return PKT_ADDR(ph)->pkt_csum_flags;
}

__attribute__((always_inline))
static inline void
__packet_set_flow_uuid(const uint64_t ph, const uuid_t flow_uuid)
{
	struct __quantum *q = &QUM_ADDR(ph)->qum_com;

	/*
	 * Anticipate a nicely (8-bytes) aligned UUID from caller;
	 * the one in qum_flow_id is always 8-byte aligned.
	 */
	if (__probable(IS_P2ALIGNED(flow_uuid, sizeof(uint64_t)))) {
		uint64_t *id_64 = (uint64_t *)(uintptr_t)flow_uuid;
		q->__q_flow_id_val64[0] = id_64[0];
		q->__q_flow_id_val64[1] = id_64[1];
	} else if (__probable(IS_P2ALIGNED(flow_uuid, sizeof(uint32_t)))) {
		uint32_t *id_32 = (uint32_t *)(uintptr_t)flow_uuid;
		q->__q_flow_id_val32[0] = id_32[0];
		q->__q_flow_id_val32[1] = id_32[1];
		q->__q_flow_id_val32[2] = id_32[2];
		q->__q_flow_id_val32[3] = id_32[3];
	} else {
		bcopy(flow_uuid, q->__q_flow_id, sizeof(uuid_t));
	}
}

__attribute__((always_inline))
static inline void
__packet_get_flow_uuid(const uint64_t ph, uuid_t flow_uuid)
{
	struct __quantum *q = &QUM_ADDR(ph)->qum_com;

	/*
	 * Anticipate a nicely (8-bytes) aligned UUID from caller;
	 * the one in qum_flow_id is always 8-byte aligned.
	 */
	if (__probable(IS_P2ALIGNED(flow_uuid, sizeof(uint64_t)))) {
		uint64_t *id_64 = (uint64_t *)(uintptr_t)flow_uuid;
		id_64[0] = q->__q_flow_id_val64[0];
		id_64[1] = q->__q_flow_id_val64[1];
	} else if (__probable(IS_P2ALIGNED(flow_uuid, sizeof(uint32_t)))) {
		uint32_t *id_32 = (uint32_t *)(uintptr_t)flow_uuid;
		id_32[0] = q->__q_flow_id_val32[0];
		id_32[1] = q->__q_flow_id_val32[1];
		id_32[2] = q->__q_flow_id_val32[2];
		id_32[3] = q->__q_flow_id_val32[3];
	} else {
		bcopy(q->__q_flow_id, flow_uuid, sizeof(uuid_t));
	}
}

__attribute__((always_inline))
static inline void
__packet_clear_flow_uuid(const uint64_t ph)
{
	struct __quantum *q = &QUM_ADDR(ph)->qum_com;
	q->__q_flow_id_val64[0] = 0;
	q->__q_flow_id_val64[1] = 0;
}

__attribute__((always_inline))
static inline uint8_t
__packet_get_aggregation_type(const uint64_t ph)
{
	_CASSERT(sizeof(PKT_ADDR(ph)->pkt_aggr_type == sizeof(uint8_t)));
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	return PKT_ADDR(ph)->pkt_aggr_type;
}

__attribute__((always_inline))
static inline uint32_t
__packet_get_data_length(const uint64_t ph)
{
	return QUM_ADDR(ph)->qum_len;
}

__attribute__((always_inline))
static inline uint16_t
__packet_get_buflet_count(const uint64_t ph)
{
	uint16_t bcnt = 0;

	switch (SK_PTR_TYPE(ph)) {
	case NEXUS_META_TYPE_PACKET:
		bcnt = PKT_ADDR(ph)->pkt_bufs_cnt;
#ifdef KERNEL
		VERIFY(bcnt != 0 ||
		    PP_HAS_BUFFER_ON_DEMAND(PKT_ADDR(ph)->pkt_qum.qum_pp));
#else /* !KERNEL */
		/*
		 * Handle the case where the metadata region gets
		 * redirected to anonymous zero-filled pages at
		 * defunct time.  There's always 1 buflet in the
		 * packet metadata, so pretend that's the count.
		 */
		if (__improbable(bcnt == 0)) {
			bcnt = 1;
		}
#endif /* !KERNEL */
		break;
	case NEXUS_META_TYPE_QUANTUM:
		bcnt = 1;
		break;
	default:
#ifdef KERNEL
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
#endif /* KERNEL */
		break;
	}
	return bcnt;
}

__attribute__((always_inline))
static inline int
__packet_add_buflet(const uint64_t ph, const void *bprev0, const void *bnew0)
{
	uint16_t bcnt;

#ifdef KERNEL
	kern_buflet_t bprev = __DECONST(kern_buflet_t, bprev0);
	kern_buflet_t bnew = __DECONST(kern_buflet_t, bnew0);

	VERIFY(PKT_ADDR(ph) && bnew && (bnew != bprev));
	VERIFY(PP_HAS_BUFFER_ON_DEMAND(PKT_ADDR(ph)->pkt_qum.qum_pp));
#else /* !KERNEL */
	buflet_t bprev = __DECONST(buflet_t, bprev0);
	buflet_t bnew = __DECONST(buflet_t, bnew0);

	if (__improbable(!PKT_ADDR(ph) || !bnew || (bnew == bprev))) {
		return EINVAL;
	}
#endif /* !KERNEL */

	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	bcnt = PKT_ADDR(ph)->pkt_bufs_cnt;

#ifdef KERNEL
	VERIFY((bprev != NULL || bcnt == 0) &&
	    (bcnt < PKT_ADDR(ph)->pkt_bufs_max));
#else /* !KERNEL */
	if (__improbable(bcnt >= PKT_ADDR(ph)->pkt_bufs_max) ||
	    (bprev == NULL && bcnt != 0)) {
		return EINVAL;
	}
#endif /* !KERNEL */

#ifdef KERNEL
#if DEVELOPMENT || DEBUG
	/* check if bprev is the last buflet in the chain */
	struct __kern_buflet *pbft, *kbft;
	int n = bcnt;

	PKT_GET_FIRST_BUFLET(PKT_ADDR(ph), bcnt, pbft);
	kbft = pbft;

	while ((kbft != NULL) && n--) {
		pbft = kbft;
		kbft = __DECONST(struct __kern_buflet *, kbft->buf_nbft_addr);
	}
	ASSERT(n == 0);
	ASSERT(bprev == pbft);
#endif /* DEVELOPMENT || DEBUG */
#endif /* KERNEL */

	if (bprev == NULL) {
		bprev = &PKT_ADDR(ph)->pkt_qum_buf;
	}
#ifdef KERNEL
	KBUF_LINK(bprev, bnew);
#else /* !KERNEL */
	UBUF_LINK(bprev, bnew);
#endif /* !KERNEL */

	*(uint16_t *)(uintptr_t)&PKT_ADDR(ph)->pkt_bufs_cnt = ++bcnt;
	return 0;
}

__attribute__((always_inline))
static inline void *
__packet_get_next_buflet(const uint64_t ph, const void *bprev0)
{
#ifdef KERNEL
	kern_buflet_t bprev = __DECONST(kern_buflet_t, bprev0);
#else /* !KERNEL */
	buflet_t bprev = __DECONST(buflet_t, bprev0);
#endif /* !KERNEL */
	void *bcur = NULL;

	switch (SK_PTR_TYPE(ph)) {
	case NEXUS_META_TYPE_PACKET: {
		uint32_t bcnt = PKT_ADDR(ph)->pkt_bufs_cnt;
#ifdef KERNEL
		ASSERT(bcnt != 0 ||
		    PP_HAS_BUFFER_ON_DEMAND(PKT_ADDR(ph)->pkt_qum.qum_pp));
#else /* !KERNEL */
		/*
		 * Handle the case where the metadata region gets
		 * redirected to anonymous zero-filled pages at
		 * defunct time.  There's always 1 buflet in the
		 * packet metadata, so pretend that's the count.
		 */
		if (__improbable(bcnt == 0)) {
			bcnt = 1;
			bprev = NULL;
		}
#endif /* !KERNEL */
		PKT_GET_NEXT_BUFLET(PKT_ADDR(ph), bcnt, BLT_ADDR(bprev), bcur);
		break;
	}
	case NEXUS_META_TYPE_QUANTUM:
		QUM_GET_NEXT_BUFLET(QUM_ADDR(ph), BLT_ADDR(bprev), bcur);
		break;
	default:
#ifdef KERNEL
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
#endif /* KERNEL */
		break;
	}
	return bcur;
}

__attribute__((always_inline))
static inline uint8_t
__packet_get_segment_count(const uint64_t ph)
{
	_CASSERT(sizeof(PKT_ADDR(ph)->pkt_seg_cnt == sizeof(uint8_t)));
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	return PKT_ADDR(ph)->pkt_seg_cnt;
}

__attribute__((always_inline))
static inline uint16_t
__buflet_get_data_limit(const void *buf)
{
	return BLT_ADDR(buf)->buf_dlim;
}

#ifdef KERNEL
__attribute__((always_inline))
static inline errno_t
__buflet_set_data_limit(const void *buf, const uint16_t dlim)
{
	/* buffer region is always marked as shareable */
	ASSERT(BLT_ADDR(buf)->buf_ctl->bc_flags & SKMEM_BUFCTL_SHAREOK);

	/* full bounds checking will be performed during finalize */
	if (__probable((uint32_t)dlim <= BLT_ADDR(buf)->buf_objlim)) {
		_CASSERT(sizeof(BLT_ADDR(buf)->buf_dlim) == sizeof(uint16_t));
		/* deconst */
		*(uint16_t *)(uintptr_t)&BLT_ADDR(buf)->buf_dlim = dlim;
		return 0;
	}
	return ERANGE;
}
#endif /* KERNEL */

__attribute__((always_inline))
static inline uint16_t
__buflet_get_data_offset(const void *buf)
{
	return BLT_ADDR(buf)->buf_doff;
}

/*
 * ******************************************************************
 * Checks in __packet_finalize for packet finalized from userland
 * ******************************************************************
 *  +-------+---------------------------+---------------------------+
 *  |         NEXUS_META_SUBTYPE_RAW    | NEXUS_META_SUBTYPE_PAYLOAD|
 *  |-------+---------------------------+---------------------------+
 *  |buflet | (bdoff + len) <= dlim     | (bdoff + len) <= dlim     |
 *  |l2_off | l2 == bdoff && l2 < bdlim | l2 = l3 = 0 && doff == 0  |
 *  |l3_off | l3 = l2                   | l3 == 0                   |
 *  |l4_off | l4 = l3 = l2              | l4 = l3 = 0               |
 *  +-------+---------------------------+---------------------------+
 *
 * ******************************************************************
 * Checks in __packet_finalize for packet finalized from kernel
 * ******************************************************************
 *  +-------+---------------------------+---------------------------+
 *  |         NEXUS_META_SUBTYPE_RAW    | NEXUS_META_SUBTYPE_PAYLOAD|
 *  |-------+---------------------------+---------------------------+
 *  |buflet | (bdoff + len) <= dlim     | (bdoff + len) <= dlim     |
 *  |l2_off | l2 == bdoff && l2 < bdlim | l2 = l3 = 0 && doff == 0  |
 *  |l3_off | l3 >= l2 && l3 <bdlim     | l3 == 0                   |
 *  |l4_off | l4 = l3                   | l4 = l3 = 0               |
 *  +-------+---------------------------+---------------------------+
 *
 */
__attribute__((always_inline))
static inline int
__packet_finalize(const uint64_t ph)
{
	void *bcur = NULL, *bprev = NULL;
	uint32_t len, bcnt, bdoff0, bdlim0;
	int err = 0;

#ifdef KERNEL
	ASSERT(QUM_ADDR(ph)->qum_qflags & QUM_F_INTERNALIZED);
#endif /* KERNEL */
	QUM_ADDR(ph)->qum_qflags &= ~(QUM_F_DROPPED | QUM_F_FINALIZED);

	bcnt = __packet_get_buflet_count(ph);
	len = QUM_ADDR(ph)->qum_len = 0;

	while (bcnt--) {
		bcur = __packet_get_next_buflet(ph, bprev);

#ifdef KERNEL
		ASSERT(bcur != NULL);
		ASSERT(BLT_ADDR(bcur)->buf_addr != 0);
#else  /* !KERNEL */
		if (__improbable(bcur == NULL)) {
			err = ERANGE;
			break;
		}
#endif /* KERNEL */

		/* save data offset from the first buflet */
		if (bprev == NULL) {
			bdoff0 = __buflet_get_data_offset(bcur);
			bdlim0 = __buflet_get_data_limit(bcur);
		}

#ifndef KERNEL
		if (__improbable(!BUF_IN_RANGE(BLT_ADDR(bcur)))) {
			err = ERANGE;
			break;
		}
#else /* !KERNEL */
		if (__improbable(!BUF_IN_RANGE(BLT_ADDR(bcur)) &&
		    !PKT_HAS_ATTACHED_MBUF(ph))) {
			err = ERANGE;
			break;
		}
#endif /* KERNEL */
		len += BLT_ADDR(bcur)->buf_dlen;
		bprev = bcur;
	}

	if (__improbable(err != 0)) {
		goto done;
	}

	switch (SK_PTR_TYPE(ph)) {
	case NEXUS_META_TYPE_PACKET:
		/* validate header offsets in packet */
		switch (SK_PTR_SUBTYPE(ph)) {
		case NEXUS_META_SUBTYPE_RAW:
			/* ensure that L2 == bdoff && L2 < bdlim */
			if (__improbable((PKT_ADDR(ph)->pkt_headroom !=
			    bdoff0) || (PKT_ADDR(ph)->pkt_headroom >=
			    bdlim0))) {
				err = ERANGE;
				goto done;
			}
#ifndef KERNEL
			/* Overwrite L2 len for raw packets from user space */
			PKT_ADDR(ph)->pkt_l2_len = 0;
#else /* !KERNEL */
			/* ensure that L3 >= L2 && L3 < bdlim */
			if (__improbable((PKT_ADDR(ph)->pkt_headroom +
			    PKT_ADDR(ph)->pkt_l2_len) >= bdlim0)) {
				err = ERANGE;
				goto done;
			}
#endif /* KERNEL */
			break;
		case NEXUS_META_SUBTYPE_PAYLOAD:
			/*
			 * For payload packet there is no concept of headroom
			 * and L3 offset should always be 0
			 */
			if (__improbable((PKT_ADDR(ph)->pkt_headroom != 0) ||
			    (bdoff0 != 0) ||
			    (PKT_ADDR(ph)->pkt_l2_len != 0))) {
				err = ERANGE;
				goto done;
			}
			break;
		default:
#ifdef KERNEL
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
#endif /* KERNEL */
			break;
		}

		if (__improbable(PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_DATA)) {
#ifdef KERNEL
			struct __packet_opt *po = PKT_ADDR(ph)->pkt_com_opt;
#else /* !KERNEL */
			struct __packet_opt *po = &PKT_ADDR(ph)->pkt_com_opt;
#endif /* !KERNEL */
			if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_EXPIRE_TS) &&
			    po->__po_expire_ts == 0) {
				err = EINVAL;
				goto done;
			}
			if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_OPT_TOKEN) &&
			    po->__po_token_len == 0) {
				err =  EINVAL;
				goto done;
			}
			ASSERT(err == 0);
		}

		/*
		 * NOTE: we don't need the validation for total packet length
		 * as checking if each buflet is in range and that
		 * (pkt_headroom == bdoff0), should cover this check.
		 */
		break;

	default:
		/* nothing to do currently for quantum */
		break;
	}

done:
	if (__probable(err == 0)) {
		QUM_ADDR(ph)->qum_len = len;
		QUM_ADDR(ph)->qum_qflags |= QUM_F_FINALIZED;
	} else {
		QUM_ADDR(ph)->qum_len = 0;
		QUM_ADDR(ph)->qum_qflags |= QUM_F_DROPPED;
	}

	return err;
}

__attribute__((always_inline))
static inline boolean_t
__packet_is_finalized(const uint64_t ph)
{
	return QUM_ADDR(ph)->qum_qflags & QUM_F_FINALIZED;
}

#ifdef KERNEL
/*
 * function to initialize a packet with mbuf chain.
 * Apart from the attached mbuf, the packet can also be used to convey
 * additional metadata like the headroom and L2 header length.
 * For a packet with attached mbuf, the pkt_length conveys the length of
 * the attached mbuf. If the data copied is partial then PKT_F_TRUNCATED is
 * also set.
 */
__attribute__((always_inline))
static inline int
__packet_initialize_with_mbufchain(struct __kern_packet *pkt, struct mbuf *mbuf,
    uint8_t headroom, uint8_t l2len)
{
	VERIFY(METADATA_TYPE(pkt) == NEXUS_META_TYPE_PACKET);
	VERIFY(pkt->pkt_qum.qum_qflags & QUM_F_INTERNALIZED);
	VERIFY((pkt->pkt_pflags & PKT_F_MBUF_MASK) == 0);
	VERIFY((pkt->pkt_pflags & PKT_F_PKT_DATA) == 0);
	VERIFY(pkt->pkt_mbuf == NULL);

	pkt->pkt_qum.qum_qflags &= ~(QUM_F_DROPPED | QUM_F_FINALIZED);
	pkt->pkt_mbuf = mbuf;
	pkt->pkt_pflags |= (PKT_F_MBUF_DATA | PKT_F_TRUNCATED);
	pkt->pkt_headroom = headroom;
	pkt->pkt_l2_len = l2len;
	pkt->pkt_length = m_pktlen(mbuf);
	pkt->pkt_qum_buf.buf_dlen = 0;
	pkt->pkt_qum_buf.buf_doff = 0;
	pkt->pkt_qum.qum_qflags |= QUM_F_FINALIZED;
	return 0;
}

__attribute__((always_inline))
static inline int
__packet_initialize_with_mbuf(struct __kern_packet *pkt, struct mbuf *mbuf,
    uint8_t headroom, uint8_t l2len)
{
	__packet_initialize_with_mbufchain(pkt, mbuf, headroom, l2len);
	VERIFY(mbuf->m_nextpkt == NULL);
	return 0;
}

/*
 * function to finalize a packet with attached mbuf.
 */
__attribute__((always_inline))
static inline int
__packet_finalize_with_mbuf(struct __kern_packet *pkt)
{
	uint16_t bdoff, bdlim, bdlen;
	struct __kern_buflet *buf;
	int err = 0;

	VERIFY(METADATA_TYPE(pkt) == NEXUS_META_TYPE_PACKET);
	VERIFY((pkt->pkt_pflags & (PKT_F_MBUF_DATA | PKT_F_PKT_DATA)) ==
	    PKT_F_MBUF_DATA);
	VERIFY(pkt->pkt_mbuf != NULL);
	ASSERT(pkt->pkt_qum.qum_qflags & QUM_F_INTERNALIZED);
	VERIFY(pkt->pkt_bufs_cnt == 1);
	PKT_GET_FIRST_BUFLET(pkt, pkt->pkt_bufs_cnt, buf);
	ASSERT(buf->buf_addr != 0);

	pkt->pkt_qum.qum_qflags &= ~(QUM_F_DROPPED | QUM_F_FINALIZED);
	pkt->pkt_pflags &= ~PKT_F_TRUNCATED;
	bdlen = buf->buf_dlen;
	bdlim = buf->buf_dlim;
	bdoff = buf->buf_doff;
	if (__improbable(!BUF_IN_RANGE(buf))) {
		err = ERANGE;
		goto done;
	}

	/* validate header offsets in packet */
	switch (METADATA_SUBTYPE(pkt)) {
	case NEXUS_META_SUBTYPE_RAW:
		if (__improbable((pkt->pkt_headroom != bdoff) ||
		    (pkt->pkt_headroom >= bdlim))) {
			err = ERANGE;
			goto done;
		}
		if (__improbable((pkt->pkt_headroom +
		    pkt->pkt_l2_len) >= bdlim)) {
			err = ERANGE;
			goto done;
		}
		break;

	case NEXUS_META_SUBTYPE_PAYLOAD:
		/*
		 * For payload packet there is no concept of headroom.
		 */
		if (__improbable((pkt->pkt_headroom != 0) || (bdoff != 0) ||
		    (pkt->pkt_l2_len != 0))) {
			err = ERANGE;
			goto done;
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
		break;
	}


	if (__improbable(pkt->pkt_pflags & PKT_F_OPT_DATA)) {
		struct __packet_opt *po = pkt->pkt_com_opt;

		if ((pkt->pkt_pflags & PKT_F_OPT_EXPIRE_TS) &&
		    po->__po_expire_ts == 0) {
			err = EINVAL;
			goto done;
		}
		if ((pkt->pkt_pflags & PKT_F_OPT_TOKEN) &&
		    po->__po_token_len == 0) {
			err =  EINVAL;
			goto done;
		}
	}
	ASSERT(err == 0);

done:
	if (__probable(err == 0)) {
		pkt->pkt_length = (uint32_t)m_pktlen(pkt->pkt_mbuf);
		if (bdlen < pkt->pkt_length) {
			pkt->pkt_pflags |= PKT_F_TRUNCATED;
		}
		pkt->pkt_qum.qum_qflags |= QUM_F_FINALIZED;
	} else {
		pkt->pkt_length = 0;
		pkt->pkt_qum.qum_qflags |= QUM_F_DROPPED;
	}

	return err;
}

__attribute__((always_inline))
static inline uint32_t
__packet_get_object_index(const uint64_t ph)
{
	return METADATA_IDX(QUM_ADDR(ph));
}

__attribute__((always_inline))
static inline errno_t
__packet_get_timestamp(const uint64_t ph, uint64_t *ts, boolean_t *valid)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_TS_VALID) != 0) {
		if (valid != NULL) {
			*valid = TRUE;
		}
		*ts = PKT_ADDR(ph)->pkt_timestamp;
	} else {
		if (valid != NULL) {
			*valid = FALSE;
		}
		*ts = 0;
	}

	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_timestamp(const uint64_t ph, uint64_t ts, boolean_t valid)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);

	if (valid) {
		PKT_ADDR(ph)->pkt_timestamp = ts;
		PKT_ADDR(ph)->pkt_pflags |= PKT_F_TS_VALID;
	} else {
		PKT_ADDR(ph)->pkt_pflags &= ~PKT_F_TS_VALID;
		PKT_ADDR(ph)->pkt_timestamp = 0;
	}

	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_get_tx_completion_data(const uint64_t ph, uintptr_t *cb_arg,
    uintptr_t *cb_data)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_TX_COMPL_DATA) != 0) {
		ASSERT((PKT_ADDR(ph)->pkt_pflags & PKT_F_TX_COMPL_ALLOC));
		*cb_arg = PKT_ADDR(ph)->pkt_tx_compl_cb_arg;
		*cb_data = PKT_ADDR(ph)->pkt_tx_compl_cb_data;
	} else {
		*cb_arg = 0;
		*cb_data = 0;
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_tx_completion_data(const uint64_t ph, uintptr_t cb_arg,
    uintptr_t cb_data)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	_KPKT_INIT_TX_COMPL_DATA(PKT_ADDR(ph));
	PKT_ADDR(ph)->pkt_tx_compl_cb_arg = cb_arg;
	PKT_ADDR(ph)->pkt_tx_compl_cb_data = cb_data;
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_get_timestamp_requested(const uint64_t ph, boolean_t *requested)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_TX_COMPL_TS_REQ) != 0) {
		*requested = TRUE;
	} else {
		*requested = FALSE;
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_get_tx_completion_status(const uint64_t ph, kern_return_t *status)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	if ((PKT_ADDR(ph)->pkt_pflags & PKT_F_TX_COMPL_DATA) != 0) {
		ASSERT((PKT_ADDR(ph)->pkt_pflags & PKT_F_TX_COMPL_ALLOC));
		*status = (kern_return_t)PKT_ADDR(ph)->pkt_tx_compl_status;
	} else {
		*status = 0;
	}
	return 0;
}

__attribute__((always_inline))
static inline errno_t
__packet_set_tx_completion_status(const uint64_t ph, kern_return_t status)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	_KPKT_INIT_TX_COMPL_DATA(PKT_ADDR(ph));
	PKT_ADDR(ph)->pkt_tx_compl_status = (uint32_t)status;
	return 0;
}
#endif /* KERNEL */

extern uint32_t os_cpu_in_cksum(const void *, uint32_t, uint32_t);

__attribute__((always_inline))
static inline uint16_t
__packet_fold_sum(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */
	return sum & 0xffff;
}

__attribute__((always_inline))
static inline uint16_t
__packet_fold_sum_final(uint32_t sum)
{
	sum = (sum >> 16) + (sum & 0xffff);     /* 17-bit */
	sum = (sum >> 16) + (sum & 0xffff);     /* 16-bit + carry */
	sum = (sum >> 16) + (sum & 0xffff);     /* final carry */
	return ~sum & 0xffff;
}

__attribute__((always_inline))
static inline uint32_t
__packet_cksum(const void *data, uint32_t len, uint32_t sum0)
{
	return os_cpu_in_cksum(data, len, sum0);
}

extern uint32_t os_cpu_copy_in_cksum(const void *, void *, uint32_t, uint32_t);

__attribute__((always_inline))
static inline uint32_t
__packet_copy_and_sum(const void *src, void *dst, uint32_t len, uint32_t sum0)
{
	return os_cpu_copy_in_cksum(src, dst, len, sum0);
}

__attribute__((always_inline))
static inline uint16_t
__packet_fix_sum(uint16_t csum, uint16_t old, uint16_t new)
{
	uint32_t c = csum + old - new;
	c = (c >> 16) + (c & 0xffff);   /* Only add carry once */

	return c & 0xffff;
}

/* MUST be used for uint32_t fields */
__attribute__((always_inline))
static inline void
__packet_fix_hdr_sum(uint8_t *field, uint16_t *csum, uint32_t new)
{
	uint32_t old;
	memcpy(&old, field, sizeof(old));
	memcpy(field, &new, sizeof(uint32_t));
	*csum = __packet_fix_sum(__packet_fix_sum(*csum, (uint16_t)(old >> 16),
	    (uint16_t)(new >> 16)), (uint16_t)(old & 0xffff),
	    (uint16_t)(new & 0xffff));
}

__attribute__((always_inline))
static inline void *
__buflet_get_data_address(const void *buf)
{
	return (void *)(BLT_ADDR(buf)->buf_addr);
}

#ifdef KERNEL
__attribute__((always_inline))
static inline errno_t
__buflet_set_data_address(const void *buf, const void *addr)
{
	/* buffer region is always marked as shareable */
	ASSERT(BLT_ADDR(buf)->buf_ctl->bc_flags & SKMEM_BUFCTL_SHAREOK);

	/* full bounds checking will be performed during finalize */
	if (__probable((uintptr_t)addr >=
	    (uintptr_t)BLT_ADDR(buf)->buf_objaddr)) {
		_CASSERT(sizeof(BLT_ADDR(buf)->buf_addr) ==
		    sizeof(mach_vm_address_t));
		/* deconst */
		*(mach_vm_address_t *)(uintptr_t)&BLT_ADDR(buf)->buf_addr =
		    (mach_vm_address_t)addr;
		return 0;
	}
	return ERANGE;
}
#endif /* KERNEL */

__attribute__((always_inline))
static inline int
__buflet_set_data_offset(const void *buf, const uint16_t doff)
{
#ifdef KERNEL
	/*
	 * Kernel-specific assertion.  For user space, the metadata
	 * region gets redirected to anonymous zero-filled pages at
	 * defunct time, so ignore it there.
	 */
	ASSERT(BLT_ADDR(buf)->buf_dlim != 0);

	if (__probable((uint32_t)doff <= BLT_ADDR(buf)->buf_objlim)) {
		BLT_ADDR(buf)->buf_doff = doff;
		return 0;
	}
	return ERANGE;
#else /* !KERNEL */
	BLT_ADDR(buf)->buf_doff = doff;
	return 0;
#endif /* KERNEL */
}

__attribute__((always_inline))
static inline int
__buflet_set_data_length(const void *buf, const uint16_t dlen)
{
#ifdef KERNEL
	/*
	 * Kernel-specific assertion.  For user space, the metadata
	 * region gets redirected to anonymous zero-filled pages at
	 * defunct time, so ignore it there.
	 */
	ASSERT(BLT_ADDR(buf)->buf_dlim != 0);

	if (__probable((uint32_t)dlen <= BLT_ADDR(buf)->buf_objlim)) {
		BLT_ADDR(buf)->buf_dlen = dlen;
		return 0;
	}
	return ERANGE;
#else /* !KERNEL */
	BLT_ADDR(buf)->buf_dlen = dlen;
	return 0;
#endif /* KERNEL */
}

__attribute__((always_inline))
static inline uint16_t
__buflet_get_data_length(const void *buf)
{
	return BLT_ADDR(buf)->buf_dlen;
}

#ifdef KERNEL
__attribute__((always_inline))
static inline struct sksegment *
__buflet_get_object_segment(const void *buf, kern_obj_idx_seg_t *idx)
{
	_CASSERT(sizeof(obj_idx_t) == sizeof(kern_obj_idx_seg_t));

	if (idx != NULL) {
		*idx = BLT_ADDR(buf)->buf_ctl->bc_idx;
	}

	return BLT_ADDR(buf)->buf_ctl->bc_slab->sl_seg;
}
#endif /* KERNEL */

__attribute__((always_inline))
static inline void *
__buflet_get_object_address(const void *buf)
{
#ifdef KERNEL
	return (void *)(BLT_ADDR(buf)->buf_objaddr);
#else /* !KERNEL */
	/*
	 * For user space, shared buffer is not available and hence the data
	 * address is immutable and is always the same as the underlying
	 * buffer object address itself.
	 */
	return __buflet_get_data_address(buf);
#endif /* !KERNEL */
}

__attribute__((always_inline))
static inline uint32_t
__buflet_get_object_limit(const void *buf)
{
#ifdef KERNEL
	return BLT_ADDR(buf)->buf_objlim;
#else /* !KERNEL */
	/*
	 * For user space, shared buffer is not available and hence the data
	 * limit is immutable and is always the same as the underlying buffer
	 * object limit itself.
	 */
	return (uint32_t)__buflet_get_data_limit(buf);
#endif /* !KERNEL */
}

__attribute__((always_inline))
static inline packet_trace_id_t
__packet_get_trace_id(const uint64_t ph)
{
	switch (SK_PTR_TYPE(ph)) {
	case NEXUS_META_TYPE_PACKET:
		return PKT_ADDR(ph)->pkt_trace_id;
		break;
	default:
		return 0;
	}
}

__attribute__((always_inline))
static inline void
__packet_set_trace_id(const uint64_t ph, packet_trace_id_t id)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	PKT_ADDR(ph)->pkt_trace_id = id;
}

__attribute__((always_inline))
static inline void
__packet_trace_event(const uint64_t ph, uint32_t event)
{
	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
#ifdef KERNEL
#pragma unused(event, ph)
	KDBG(event, PKT_ADDR(ph)->pkt_trace_id);
#else /* !KERNEL */
	kdebug_trace(event, PKT_ADDR(ph)->pkt_trace_id, 0, 0, 0);
#endif /* !KERNEL */
}

#ifdef KERNEL
__attribute__((always_inline))
static inline void
__packet_perform_tx_completion_callbacks(const kern_packet_t ph, ifnet_t ifp)
{
	/*
	 * NOTE: this function can be called with ifp as NULL.
	 */
	uint64_t ts;
	kern_return_t tx_status;
	uintptr_t cb_arg, cb_data;
	struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(ph);

	ASSERT((kpkt->pkt_pflags & PKT_F_TX_COMPL_TS_REQ) != 0);
	(void) __packet_get_tx_completion_status(ph, &tx_status);
	__packet_get_tx_completion_data(ph, &cb_arg, &cb_data);
	__packet_get_timestamp(ph, &ts, NULL);
	while (kpkt->pkt_tx_compl_callbacks != 0) {
		mbuf_tx_compl_func cb;
		uint32_t i;

		i = ffs(kpkt->pkt_tx_compl_callbacks) - 1;
		kpkt->pkt_tx_compl_callbacks &= ~(1 << i);
		cb = m_get_tx_compl_callback(i);
		if (__probable(cb != NULL)) {
			cb(kpkt->pkt_tx_compl_context, ifp, ts, cb_arg, cb_data,
			    tx_status);
		}
	}
	kpkt->pkt_pflags &= ~PKT_F_TX_COMPL_TS_REQ;
}
#endif /* KERNEL */

#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_PACKET_COMMON_H_ */
