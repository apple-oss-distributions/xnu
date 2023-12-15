/*
 * Copyright (c) 2016-2022 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <netinet/tcp_var.h>

static int kern_packet_clone_internal(const kern_packet_t, kern_packet_t *,
    uint32_t, kern_packet_copy_mode_t);

#if (DEBUG || DEVELOPMENT)
__attribute__((noreturn))
void
pkt_subtype_assert_fail(const kern_packet_t ph, uint64_t type, uint64_t subtype)
{
	panic("invalid packet handle 0x%llx (type %llu != %llu || "
	    "subtype %llu != %llu)", ph, SK_PTR_TYPE(ph), type,
	    SK_PTR_SUBTYPE(ph), subtype);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
void
pkt_type_assert_fail(const kern_packet_t ph, uint64_t type)
{
	panic("invalid packet handle 0x%llx (type %llu != %llu)",
	    ph, SK_PTR_TYPE(ph), type);
	/* NOTREACHED */
	__builtin_unreachable();
}
#endif /* DEBUG || DEVELOPMENT */

errno_t
kern_packet_set_headroom(const kern_packet_t ph, const uint8_t headroom)
{
	return __packet_set_headroom(ph, headroom);
}

uint8_t
kern_packet_get_headroom(const kern_packet_t ph)
{
	return __packet_get_headroom(ph);
}

errno_t
kern_packet_set_link_header_offset(const kern_packet_t ph, const uint8_t off)
{
	return __packet_set_headroom(ph, off);
}

uint16_t
kern_packet_get_link_header_offset(const kern_packet_t ph)
{
	return __packet_get_headroom(ph);
}

errno_t
kern_packet_set_link_header_length(const kern_packet_t ph, const uint8_t off)
{
	return __packet_set_link_header_length(ph, off);
}

uint8_t
kern_packet_get_link_header_length(const kern_packet_t ph)
{
	return __packet_get_link_header_length(ph);
}

errno_t
kern_packet_set_link_broadcast(const kern_packet_t ph)
{
	return __packet_set_link_broadcast(ph);
}

boolean_t
kern_packet_get_link_broadcast(const kern_packet_t ph)
{
	return __packet_get_link_broadcast(ph);
}

errno_t
kern_packet_set_link_multicast(const kern_packet_t ph)
{
	return __packet_set_link_multicast(ph);
}

errno_t
kern_packet_set_link_ethfcs(const kern_packet_t ph)
{
	return __packet_set_link_ethfcs(ph);
}

boolean_t
kern_packet_get_link_multicast(const kern_packet_t ph)
{
	return __packet_get_link_multicast(ph);
}

boolean_t
kern_packet_get_link_ethfcs(const kern_packet_t ph)
{
	return __packet_get_link_ethfcs(ph);
}

/* deprecated -- no effect, use set_link_header_length instead  */
errno_t
kern_packet_set_network_header_offset(const kern_packet_t ph,
    const uint16_t off)
{
#pragma unused(ph, off)
	return 0;
}

/* deprecated -- use get_link_header_length instead  */
uint16_t
kern_packet_get_network_header_offset(const kern_packet_t ph)
{
	return (uint16_t)__packet_get_headroom(ph) +
	       (uint16_t)__packet_get_link_header_length(ph);
}

/* deprecated */
errno_t
kern_packet_set_transport_header_offset(const kern_packet_t ph,
    const uint16_t off)
{
#pragma unused(ph, off)
	return 0;
}

/* deprecated */
uint16_t
kern_packet_get_transport_header_offset(const kern_packet_t ph)
{
#pragma unused(ph)
	return 0;
}

boolean_t
kern_packet_get_transport_traffic_background(const kern_packet_t ph)
{
	return __packet_get_transport_traffic_background(ph);
}

boolean_t
kern_packet_get_transport_traffic_realtime(const kern_packet_t ph)
{
	return __packet_get_transport_traffic_realtime(ph);
}

boolean_t
kern_packet_get_transport_retransmit(const kern_packet_t ph)
{
	return __packet_get_transport_retransmit(ph);
}

boolean_t
kern_packet_get_transport_new_flow(const kern_packet_t ph)
{
	return __packet_get_transport_new_flow(ph);
}

boolean_t
kern_packet_get_transport_last_packet(const kern_packet_t ph)
{
	return __packet_get_transport_last_packet(ph);
}

int
kern_packet_set_service_class(const kern_packet_t ph,
    const kern_packet_svc_class_t sc)
{
	return __packet_set_service_class(ph, sc);
}

kern_packet_svc_class_t
kern_packet_get_service_class(const kern_packet_t ph)
{
	return __packet_get_service_class(ph);
}

errno_t
kern_packet_set_compression_generation_count(const kern_packet_t ph,
    uint32_t gencnt)
{
	return __packet_set_comp_gencnt(ph, gencnt);
}

errno_t
kern_packet_get_compression_generation_count(const kern_packet_t ph, uint32_t *pgencnt)
{
	return __packet_get_comp_gencnt(ph, pgencnt);
}

errno_t
kern_packet_get_service_class_index(const kern_packet_svc_class_t svc,
    uint32_t *index)
{
	if (index == NULL || !KPKT_VALID_SVC(svc)) {
		return EINVAL;
	}

	*index = KPKT_SVCIDX(svc);
	return 0;
}

boolean_t
kern_packet_is_high_priority(const kern_packet_t ph)
{
	uint32_t sc;
	boolean_t is_hi_priority;

	sc = __packet_get_service_class(ph);

	switch (sc) {
	case PKT_SC_VI:
	case PKT_SC_SIG:
	case PKT_SC_VO:
	case PKT_SC_CTL:
		is_hi_priority = (PKT_ADDR(ph)->pkt_comp_gencnt == 0 ||
		    PKT_ADDR(ph)->pkt_comp_gencnt == TCP_ACK_COMPRESSION_DUMMY);
		break;

	case PKT_SC_BK_SYS:
	case PKT_SC_BK:
	case PKT_SC_BE:
	case PKT_SC_RD:
	case PKT_SC_OAM:
	case PKT_SC_AV:
	case PKT_SC_RV:
	default:
		is_hi_priority = false;
	}
	return is_hi_priority;
}

errno_t
kern_packet_set_traffic_class(const kern_packet_t ph,
    kern_packet_traffic_class_t tc)
{
	return __packet_set_traffic_class(ph, tc);
}

kern_packet_traffic_class_t
kern_packet_get_traffic_class(const kern_packet_t ph)
{
	return __packet_get_traffic_class(ph);
}

errno_t
kern_packet_set_inet_checksum(const kern_packet_t ph,
    const packet_csum_flags_t flags, const uint16_t start,
    const uint16_t stuff, const boolean_t tx)
{
	return __packet_set_inet_checksum(ph, flags, start, stuff, tx);
}

packet_csum_flags_t
kern_packet_get_inet_checksum(const kern_packet_t ph, uint16_t *start,
    uint16_t *val, const boolean_t tx)
{
	return __packet_get_inet_checksum(ph, start, val, tx);
}

void
kern_packet_set_flow_uuid(const kern_packet_t ph, const uuid_t flow_uuid)
{
	__packet_set_flow_uuid(ph, flow_uuid);
}

void
kern_packet_get_flow_uuid(const kern_packet_t ph, uuid_t *flow_uuid)
{
	__packet_get_flow_uuid(ph, *flow_uuid);
}

void
kern_packet_clear_flow_uuid(const kern_packet_t ph)
{
	__packet_clear_flow_uuid(ph);
}

void
kern_packet_get_euuid(const kern_packet_t ph, uuid_t euuid)
{
	if (__probable(SK_PTR_TYPE(ph) == NEXUS_META_TYPE_PACKET)) {
		uuid_copy(euuid, PKT_ADDR(ph)->pkt_policy_euuid);
	} else {
		uuid_clear(euuid);
	}
}

void
kern_packet_set_policy_id(const kern_packet_t ph, uint32_t policy_id)
{
	if (__probable(SK_PTR_TYPE(ph) == NEXUS_META_TYPE_PACKET)) {
		PKT_ADDR(ph)->pkt_policy_id = policy_id;
	}
}

uint32_t
kern_packet_get_policy_id(const kern_packet_t ph)
{
	if (__probable(SK_PTR_TYPE(ph) == NEXUS_META_TYPE_PACKET)) {
		return PKT_ADDR(ph)->pkt_policy_id;
	} else {
		return 0;
	}
}

void
kern_packet_set_skip_policy_id(const kern_packet_t ph, uint32_t skip_policy_id)
{
	if (__probable(SK_PTR_TYPE(ph) == NEXUS_META_TYPE_PACKET)) {
		PKT_ADDR(ph)->pkt_skip_policy_id = skip_policy_id;
	}
}

uint32_t
kern_packet_get_skip_policy_id(const kern_packet_t ph)
{
	if (__probable(SK_PTR_TYPE(ph) == NEXUS_META_TYPE_PACKET)) {
		return PKT_ADDR(ph)->pkt_skip_policy_id;
	} else {
		return 0;
	}
}

uint32_t
kern_packet_get_data_length(const kern_packet_t ph)
{
	return __packet_get_data_length(ph);
}

uint32_t
kern_packet_get_buflet_count(const kern_packet_t ph)
{
	return __packet_get_buflet_count(ph);
}

kern_buflet_t
kern_packet_get_next_buflet(const kern_packet_t ph, const kern_buflet_t bprev)
{
	return __packet_get_next_buflet(ph, bprev);
}

errno_t
kern_packet_finalize(const kern_packet_t ph)
{
	return __packet_finalize(ph);
}

kern_packet_idx_t
kern_packet_get_object_index(const kern_packet_t ph)
{
	return __packet_get_object_index(ph);
}

errno_t
kern_packet_get_timestamp(const kern_packet_t ph, uint64_t *ts,
    boolean_t *valid)
{
	return __packet_get_timestamp(ph, ts, valid);
}

errno_t
kern_packet_set_timestamp(const kern_packet_t ph, uint64_t ts, boolean_t valid)
{
	return __packet_set_timestamp(ph, ts, valid);
}

struct mbuf *
kern_packet_get_mbuf(const kern_packet_t pkt)
{
	struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(pkt);

	if ((kpkt->pkt_pflags & PKT_F_MBUF_DATA) != 0) {
		return kpkt->pkt_mbuf;
	}
	return NULL;
}

errno_t
kern_packet_get_timestamp_requested(const kern_packet_t ph,
    boolean_t *requested)
{
	return __packet_get_timestamp_requested(ph, requested);
}

void
kern_packet_tx_completion(const kern_packet_t ph, ifnet_t ifp)
{
	struct __kern_packet *kpkt = SK_PTR_ADDR_KPKT(ph);

	PKT_TYPE_ASSERT(ph, NEXUS_META_TYPE_PACKET);
	/*
	 * handling of transmit completion events.
	 */
	(void) kern_channel_event_transmit_status_with_packet(ph, ifp);

	/*
	 * handling of transmit completion timestamp request callbacks.
	 */
	if ((kpkt->pkt_pflags & PKT_F_TX_COMPL_TS_REQ) != 0) {
		__packet_perform_tx_completion_callbacks(ph, ifp);
	}
}

errno_t
kern_packet_get_tx_completion_status(const kern_packet_t ph,
    kern_return_t *status)
{
	return __packet_get_tx_completion_status(ph, status);
}

errno_t
kern_packet_set_tx_completion_status(const kern_packet_t ph,
    kern_return_t status)
{
	return __packet_set_tx_completion_status(ph, status);
}

void
kern_packet_set_group_start(const kern_packet_t ph)
{
	(void) __packet_set_group_start(ph);
}

boolean_t
kern_packet_get_group_start(const kern_packet_t ph)
{
	return __packet_get_group_start(ph);
}

void
kern_packet_set_group_end(const kern_packet_t ph)
{
	(void) __packet_set_group_end(ph);
}

boolean_t
kern_packet_get_group_end(const kern_packet_t ph)
{
	return __packet_get_group_end(ph);
}

errno_t
kern_packet_get_expire_time(const kern_packet_t ph, uint64_t *ts)
{
	return __packet_get_expire_time(ph, ts);
}

errno_t
kern_packet_set_expire_time(const kern_packet_t ph, const uint64_t ts)
{
	return __packet_set_expire_time(ph, ts);
}

errno_t
kern_packet_get_expiry_action(const kern_packet_t ph, packet_expiry_action_t *pea)
{
	return __packet_get_expiry_action(ph, pea);
}

errno_t
kern_packet_set_expiry_action(const kern_packet_t ph, packet_expiry_action_t pea)
{
	return __packet_set_expiry_action(ph, pea);
}

errno_t
kern_packet_get_token(const kern_packet_t ph, void *token, uint16_t *len)
{
	return __packet_get_token(ph, token, len);
}

errno_t
kern_packet_set_token(const kern_packet_t ph, const void *token,
    const uint16_t len)
{
	return __packet_set_token(ph, token, len);
}

errno_t
kern_packet_get_packetid(const kern_packet_t ph, packet_id_t *pktid)
{
	return __packet_get_packetid(ph, pktid);
}

errno_t
kern_packet_set_vlan_tag(const kern_packet_t ph, const uint16_t tag,
    const boolean_t tag_in_pkt)
{
	return __packet_set_vlan_tag(ph, tag, tag_in_pkt);
}

errno_t
kern_packet_get_vlan_tag(const kern_packet_t ph, uint16_t *tag,
    boolean_t *tag_in_pkt)
{
	return __packet_get_vlan_tag(ph, tag, tag_in_pkt);
}

uint16_t
kern_packet_get_vlan_id(const uint16_t tag)
{
	return __packet_get_vlan_id(tag);
}

uint8_t
kern_packet_get_vlan_priority(const uint16_t tag)
{
	return __packet_get_vlan_priority(tag);
}

errno_t
kern_packet_get_app_metadata(const kern_packet_t ph,
    packet_app_metadata_type_t *app_type, uint8_t *app_metadata)
{
	return __packet_get_app_metadata(ph, app_type, app_metadata);
}

void
kern_packet_set_wake_flag(const kern_packet_t ph)
{
	return __packet_set_wake_flag(ph);
}

boolean_t
kern_packet_get_wake_flag(const kern_packet_t ph)
{
	return __packet_get_wake_flag(ph);
}

uint32_t
kern_inet_checksum(const void *data, uint32_t len, uint32_t sum0)
{
	return __packet_cksum(data, len, sum0);
}

uint32_t
kern_copy_and_inet_checksum(const void *src, void *dst, uint32_t len,
    uint32_t sum0)
{
	uint32_t sum = __packet_copy_and_sum(src, dst, len, sum0);
	return __packet_fold_sum_final(sum);
}

/*
 * Source packet must be finalized (not dropped); cloned packet does not
 * inherit the finalized flag, or the classified flag, so caller is
 * responsible for finalizing it and classifying it (as needed).
 */
static int
kern_packet_clone_internal(const kern_packet_t ph1, kern_packet_t *ph2,
    uint32_t skmflag, kern_packet_copy_mode_t mode)
{
	struct kern_pbufpool *pool;
	struct __kern_packet *p1 = SK_PTR_ADDR_KPKT(ph1);
	struct __kern_packet *p2 = NULL;
	struct __kern_buflet *p1_buf, *p2_buf;
	uint16_t bufs_cnt_alloc;
	int m_how;
	int err;

	/* TODO: Add quantum support */
	VERIFY(SK_PTR_TYPE(ph1) == NEXUS_META_TYPE_PACKET);

	/* Source needs to be finalized (not dropped) and with 1 buflet */
	if ((p1->pkt_qum.qum_qflags & QUM_F_DROPPED) != 0 ||
	    p1->pkt_bufs_cnt == 0) {
		return EINVAL;
	}

	/* TODO: Add multi-buflet support */
	VERIFY(p1->pkt_bufs_cnt == 1);

	switch (mode) {
	case KPKT_COPY_HEAVY:
		/*
		 * Allocate a packet with the same number of buffers as that
		 * of the source packet's; this cannot be 0 per check above.
		 */
		bufs_cnt_alloc = p1->pkt_bufs_cnt;
		break;

	case KPKT_COPY_LIGHT:
		/*
		 * Allocate an "empty" packet with no buffers attached; this
		 * will work only on pools marked with "on-demand", which is
		 * the case today for device drivers needing shared buffers
		 * support.
		 *
		 * TODO: We could make this generic and applicable to regular
		 * pools, but it would involve detaching the buffer that comes
		 * attached to the constructed packet; this wouldn't be that
		 * lightweight in nature, but whatever.  In such a case the
		 * number of buffers requested during allocation is the same
		 * as the that of the source packet's.  For now, let it fail
		 * naturally on regular pools, as part of allocation below.
		 *
		 * XXX: This would also fail on quantums as we currently
		 * restrict quantums to have exactly one buffer.
		 */
		bufs_cnt_alloc = 0;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	*ph2 = 0;
	pool = __DECONST(struct kern_pbufpool *, SK_PTR_ADDR_KQUM(ph1)->qum_pp);
	if (skmflag & SKMEM_NOSLEEP) {
		err = kern_pbufpool_alloc_nosleep(pool, bufs_cnt_alloc, ph2);
		m_how = M_NOWAIT;
	} else {
		err = kern_pbufpool_alloc(pool, bufs_cnt_alloc, ph2);
		ASSERT(err != ENOMEM);
		m_how = M_WAIT;
	}
	if (__improbable(err != 0)) {
		/* See comments above related to KPKT_COPY_{HEAVY,LIGHT} */
		goto error;
	}
	p2 = SK_PTR_ADDR_KPKT(*ph2);

	/* Copy packet metadata */
	_QUM_COPY(&(p1)->pkt_qum, &(p2)->pkt_qum);
	_PKT_COPY(p1, p2);
	ASSERT(p2->pkt_mbuf == NULL);
	ASSERT(p2->pkt_bufs_max == p1->pkt_bufs_max);

	/* clear trace id */
	p2->pkt_trace_id = 0;
	/* clear finalized and classified bits from clone */
	p2->pkt_qum.qum_qflags &= ~(QUM_F_FINALIZED | QUM_F_FLOW_CLASSIFIED);

	switch (mode) {
	case KPKT_COPY_HEAVY:
		/*
		 * Heavy: Copy buffer contents and extra metadata.
		 */
		ASSERT(p2->pkt_bufs_cnt == p1->pkt_bufs_cnt);
		if (__probable(p1->pkt_bufs_cnt != 0)) {
			uint8_t *saddr, *daddr;
			uint32_t copy_len;
			/*
			 * TODO -- wshen0123@apple.com
			 * Packets from compat driver could have dlen > dlim
			 * for flowswitch flow compatibility, cleanup when we
			 * make them consistent.
			 */
			PKT_GET_FIRST_BUFLET(p1, p1->pkt_bufs_cnt, p1_buf);
			PKT_GET_FIRST_BUFLET(p2, p2->pkt_bufs_cnt, p2_buf);
			saddr = (void *)p1_buf->buf_addr;
			daddr = (void *)p2_buf->buf_addr;
			copy_len = MIN(p1_buf->buf_dlen, p1_buf->buf_dlim);
			if (copy_len != 0) {
				bcopy(saddr, daddr, copy_len);
			}
			*__DECONST(uint32_t *, &p2_buf->buf_dlim) =
			    p1_buf->buf_dlim;
			p2_buf->buf_dlen = p1_buf->buf_dlen;
			p2_buf->buf_doff = p1_buf->buf_doff;
		}

		/* Copy AQM metadata */
		p2->pkt_flowsrc_type = p1->pkt_flowsrc_type;
		p2->pkt_flowsrc_fidx = p1->pkt_flowsrc_fidx;
		_CASSERT((offsetof(struct __flow, flow_src_id) % 8) == 0);
		_UUID_COPY(p2->pkt_flowsrc_id, p1->pkt_flowsrc_id);
		_UUID_COPY(p2->pkt_policy_euuid, p1->pkt_policy_euuid);
		p2->pkt_policy_id = p1->pkt_policy_id;
		p2->pkt_skip_policy_id = p1->pkt_skip_policy_id;

		p2->pkt_pflags = p1->pkt_pflags;
		if (p1->pkt_pflags & PKT_F_MBUF_DATA) {
			ASSERT(p1->pkt_mbuf != NULL);
			p2->pkt_mbuf = m_dup(p1->pkt_mbuf, m_how);
			if (p2->pkt_mbuf == NULL) {
				KPKT_CLEAR_MBUF_DATA(p2);
				err = ENOBUFS;
				goto error;
			}
		}
		break;

	case KPKT_COPY_LIGHT:
		/*
		 * Lightweight: Duplicate buflet(s) and add refs.
		 */
		ASSERT(p1->pkt_mbuf == NULL);
		ASSERT(p2->pkt_bufs_cnt == 0);
		if (__probable(p1->pkt_bufs_cnt != 0)) {
			PKT_GET_FIRST_BUFLET(p1, p1->pkt_bufs_cnt, p1_buf);
			p2_buf = &p2->pkt_qum_buf;
			*__DECONST(uint16_t *, &p2->pkt_bufs_cnt) =
			    p1->pkt_bufs_cnt;
			_KBUF_COPY(p1_buf, p2_buf);
			ASSERT(p2_buf->buf_nbft_addr == 0);
			ASSERT(p2_buf->buf_nbft_idx == OBJ_IDX_NONE);
		}
		ASSERT(p2->pkt_bufs_cnt == p1->pkt_bufs_cnt);
		ASSERT(p2->pkt_bufs_max == p1->pkt_bufs_max);
		ASSERT(err == 0);
		break;
	}

error:
	if (err != 0 && p2 != NULL) {
		uint32_t usecnt = 0;

		ASSERT(p2->pkt_mbuf == NULL);
		if (__probable(mode == KPKT_COPY_LIGHT)) {
			/*
			 * This is undoing what _KBUF_COPY() did earlier,
			 * in case this routine is modified to handle regular
			 * pool (not on-demand), which also decrements the
			 * shared buffer's usecnt.  For regular pool, calling
			 * kern_pubfpool_free() will not yield a call to
			 * destroy the metadata.
			 */
			PKT_GET_FIRST_BUFLET(p2, p2->pkt_bufs_cnt, p2_buf);
			KBUF_DTOR(p2_buf, usecnt);
		}
		kern_pbufpool_free(pool, *ph2);
		*ph2 = 0;
	}

	return err;
}

errno_t
kern_packet_clone(const kern_packet_t ph1, kern_packet_t *ph2,
    kern_packet_copy_mode_t mode)
{
	return kern_packet_clone_internal(ph1, ph2, 0, mode);
}

errno_t
kern_packet_clone_nosleep(const kern_packet_t ph1, kern_packet_t *ph2,
    kern_packet_copy_mode_t mode)
{
	return kern_packet_clone_internal(ph1, ph2, SKMEM_NOSLEEP, mode);
}

errno_t
kern_packet_add_buflet(const kern_packet_t ph, const kern_buflet_t bprev,
    const kern_buflet_t bnew)
{
	return __packet_add_buflet(ph, bprev, bnew);
}

void
kern_packet_append(const kern_packet_t ph1, const kern_packet_t ph2)
{
	/*
	 * TODO:
	 * Add assert for non-zero ph2 here after changing IOSkywalkFamily
	 * to use kern_packet_set_next() for clearing the next pointer.
	 */
	kern_packet_set_next(ph1, ph2);
}

kern_packet_t
kern_packet_get_next(const kern_packet_t ph)
{
	struct __kern_packet *p, *next;

	p = SK_PTR_ADDR_KPKT(ph);
	next = p->pkt_nextpkt;
	return next == NULL ? 0 : SK_PKT2PH(next);
}

void
kern_packet_set_next(const kern_packet_t ph1, const kern_packet_t ph2)
{
	struct __kern_packet *p1, *p2;

	ASSERT(ph1 != 0);
	p1 = SK_PTR_ADDR_KPKT(ph1);
	p2 = (ph2 == 0 ? NULL : SK_PTR_ADDR_KPKT(ph2));
	p1->pkt_nextpkt = p2;
}

void
kern_packet_set_chain_counts(const kern_packet_t ph, uint32_t count,
    uint32_t bytes)
{
	struct __kern_packet *p;

	p = SK_PTR_ADDR_KPKT(ph);
	p->pkt_chain_count = count;
	p->pkt_chain_bytes = bytes;
}

void
kern_packet_get_chain_counts(const kern_packet_t ph, uint32_t *count,
    uint32_t *bytes)
{
	struct __kern_packet *p;

	p = SK_PTR_ADDR_KPKT(ph);
	*count = p->pkt_chain_count;
	*bytes = p->pkt_chain_bytes;
}

errno_t
kern_buflet_set_data_offset(const kern_buflet_t buf, const uint32_t doff)
{
	return __buflet_set_data_offset(buf, doff);
}

uint32_t
kern_buflet_get_data_offset(const kern_buflet_t buf)
{
	return __buflet_get_data_offset(buf);
}

errno_t
kern_buflet_set_data_length(const kern_buflet_t buf, const uint32_t dlen)
{
	return __buflet_set_data_length(buf, dlen);
}

uint32_t
kern_buflet_get_data_length(const kern_buflet_t buf)
{
	return __buflet_get_data_length(buf);
}

void *
kern_buflet_get_object_address(const kern_buflet_t buf)
{
	return __buflet_get_object_address(buf);
}

uint32_t
kern_buflet_get_object_limit(const kern_buflet_t buf)
{
	return __buflet_get_object_limit(buf);
}

void *
kern_buflet_get_data_address(const kern_buflet_t buf)
{
	return __buflet_get_data_address(buf);
}

errno_t
kern_buflet_set_data_address(const kern_buflet_t buf, const void *daddr)
{
	return __buflet_set_data_address(buf, daddr);
}

errno_t
kern_buflet_set_buffer_offset(const kern_buflet_t buf, const uint32_t off)
{
	return __buflet_set_buffer_offset(buf, off);
}

kern_segment_t
kern_buflet_get_object_segment(const kern_buflet_t buf,
    kern_obj_idx_seg_t *idx)
{
	return __buflet_get_object_segment(buf, idx);
}

uint32_t
kern_buflet_get_data_limit(const kern_buflet_t buf)
{
	return __buflet_get_data_limit(buf);
}

errno_t
kern_buflet_set_data_limit(const kern_buflet_t buf, const uint32_t dlim)
{
	return __buflet_set_data_limit(buf, dlim);
}

packet_trace_id_t
kern_packet_get_trace_id(const kern_packet_t ph)
{
	return __packet_get_trace_id(ph);
}

void
kern_packet_set_trace_id(const kern_packet_t ph, packet_trace_id_t trace_id)
{
	return __packet_set_trace_id(ph, trace_id);
}

void
kern_packet_trace_event(const kern_packet_t ph, uint32_t event)
{
	return __packet_trace_event(ph, event);
}

errno_t
kern_packet_copy_bytes(kern_packet_t pkt, size_t off, size_t len, void* out_data)
{
	kern_buflet_t buflet = NULL;
	size_t count;
	uint8_t *addr;
	uint32_t buflet_len;

	buflet = __packet_get_next_buflet(pkt, buflet);
	if (buflet == NULL) {
		return EINVAL;
	}
	buflet_len = __buflet_get_data_length(buflet);
	if (len > buflet_len) {
		return EINVAL;
	}
	if (off > buflet_len) {
		return EINVAL;
	}
	addr = __buflet_get_data_address(buflet);
	if (addr == NULL) {
		return EINVAL;
	}
	addr += __buflet_get_data_offset(buflet);
	addr += off;
	count = MIN(len, buflet_len - off);
	bcopy((void *) addr, out_data, count);

	return 0;
}


errno_t
kern_packet_get_flowid(const kern_packet_t ph, packet_flowid_t *pflowid)
{
	return __packet_get_flowid(ph, pflowid);
}

void
kern_packet_set_trace_tag(const kern_packet_t ph, packet_trace_tag_t tag)
{
	__packet_set_trace_tag(ph, tag);
}

packet_trace_tag_t
kern_packet_get_trace_tag(const kern_packet_t ph)
{
	return __packet_get_trace_tag(ph);
}

errno_t
kern_packet_get_tx_nexus_port_id(const kern_packet_t ph, uint32_t *nx_port_id)
{
	return __packet_get_tx_nx_port_id(ph, nx_port_id);
}

uint16_t
kern_packet_get_protocol_segment_size(const kern_packet_t ph)
{
	return __packet_get_protocol_segment_size(ph);
}

void
kern_packet_set_segment_count(const kern_packet_t ph, uint8_t segcount)
{
	__packet_set_segment_count(ph, segcount);
}

void *
kern_packet_get_priv(const kern_packet_t ph)
{
	return __packet_get_priv(ph);
}

void
kern_packet_set_priv(const kern_packet_t ph, void *priv)
{
	return __packet_set_priv(ph, priv);
}

void
kern_packet_get_tso_flags(const kern_packet_t ph, packet_tso_flags_t *flags)
{
	return __packet_get_tso_flags(ph, flags);
}

errno_t
kern_packet_check_for_expiry_and_notify(
	const kern_packet_t ph, ifnet_t ifp, uint16_t origin, uint16_t status)
{
	errno_t err = 0;
	uint32_t nx_port_id = 0;
	packet_expiry_action_t exp_action = PACKET_EXPIRY_ACTION_NONE;
	os_channel_event_packet_transmit_expired_t exp_notif = {0};

	if (__improbable(!ifp)) {
		return EINVAL;
	}

	err = __packet_get_expire_time(ph, &exp_notif.packet_tx_expiration_deadline);
	if (__probable(err)) {
		if (err == ENOENT) {
			/* Expiration time is not set; can not continue; not an error. */
			return 0;
		}
		return err;
	}

	err = __packet_get_expiry_action(ph, &exp_action);
	if (__probable(err)) {
		if (err == ENOENT) {
			/* Expiry action is not set; can not continue; not an error. */
			return 0;
		}
		return err;
	}

	if (exp_action == PACKET_EXPIRY_ACTION_NONE) {
		/* Expiry action is no-op; can not continue; not an error. */
		return 0;
	}

	exp_notif.packet_tx_expiration_timestamp = mach_absolute_time();

	/* Check whether the packet has expired */
	if (exp_notif.packet_tx_expiration_timestamp < exp_notif.packet_tx_expiration_deadline) {
		/* The packet hasn't expired yet; can not continue; not an error */
		return 0;
	}

	/* The packet has expired and notification is requested */
	err = __packet_get_packetid(ph, &exp_notif.packet_id);
	if (__improbable(err)) {
		return err;
	}

	err = __packet_get_tx_nx_port_id(ph, &nx_port_id);
	if (__improbable(err)) {
		return err;
	}

	exp_notif.packet_tx_expiration_status = status;
	exp_notif.packet_tx_expiration_origin = origin;

	/* Send the notification status */
	err = kern_channel_event_transmit_expired(
		ifp, &exp_notif, nx_port_id);

	return err;
}
