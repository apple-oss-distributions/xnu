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


#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <skywalk/os_skywalk_private.h>

#ifndef LIBSYSCALL_INTERFACE
#error "LIBSYSCALL_INTERFACE not defined"
#endif /* !LIBSYSCALL_INTERFACE */

#if (DEBUG || DEVELOPMENT)
__attribute__((noreturn))
void
pkt_subtype_assert_fail(const packet_t ph, uint64_t type __unused,
    uint64_t subtype __unused)
{
	SK_ABORT_WITH_CAUSE("invalid packet subtype", ph);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
void
pkt_type_assert_fail(const packet_t ph, uint64_t type __unused)
{
	SK_ABORT_WITH_CAUSE("invalid packet type", ph);
	/* NOTREACHED */
	__builtin_unreachable();
}
#endif /* DEBUG || DEVELOPMENT */

int
os_packet_set_headroom(const packet_t ph, const uint8_t headroom)
{
	return __packet_set_headroom(ph, headroom);
}

uint8_t
os_packet_get_headroom(const packet_t ph)
{
	return __packet_get_headroom(ph);
}

int
os_packet_set_link_header_length(const packet_t ph, const uint8_t off)
{
	return __packet_set_link_header_length(ph, off);
}

uint8_t
os_packet_get_link_header_length(const packet_t ph)
{
	return __packet_get_link_header_length(ph);
}

int
os_packet_set_link_broadcast(const packet_t ph)
{
	return __packet_set_link_broadcast(ph);
}

boolean_t
os_packet_get_link_broadcast(const packet_t ph)
{
	return __packet_get_link_broadcast(ph);
}

int
os_packet_set_link_multicast(const packet_t ph)
{
	return __packet_set_link_multicast(ph);
}

boolean_t
os_packet_get_link_multicast(const packet_t ph)
{
	return __packet_get_link_multicast(ph);
}

int
os_packet_set_link_ethfcs(const packet_t ph)
{
	return __packet_set_link_ethfcs(ph);
}

boolean_t
os_packet_get_link_ethfcs(const packet_t ph)
{
	return __packet_get_link_ethfcs(ph);
}

int
os_packet_set_transport_traffic_background(const packet_t ph)
{
	return __packet_set_transport_traffic_background(ph);
}

boolean_t
os_packet_get_transport_traffic_background(const packet_t ph)
{
	return __packet_get_transport_traffic_background(ph);
}

int
os_packet_set_transport_traffic_realtime(const packet_t ph)
{
	return __packet_set_transport_traffic_realtime(ph);
}

boolean_t
os_packet_get_transport_traffic_realtime(const packet_t ph)
{
	return __packet_get_transport_traffic_realtime(ph);
}

int
os_packet_set_transport_retransmit(const packet_t ph)
{
	return __packet_set_transport_retransmit(ph);
}

boolean_t
os_packet_get_transport_retransmit(const packet_t ph)
{
	return __packet_get_transport_retransmit(ph);
}

int
os_packet_set_transport_last_packet(const packet_t ph)
{
	return __packet_set_transport_last_packet(ph);
}

int
os_packet_set_service_class(const packet_t ph, const packet_svc_class_t sc)
{
	return __packet_set_service_class(ph, sc);
}

packet_svc_class_t
os_packet_get_service_class(const packet_t ph)
{
	return __packet_get_service_class(ph);
}

int
os_packet_set_compression_generation_count(const packet_t ph, const uint32_t gencnt)
{
	return __packet_set_comp_gencnt(ph, gencnt);
}

int
os_packet_get_compression_generation_count(const packet_t ph, uint32_t *pgencnt)
{
	return __packet_get_comp_gencnt(ph, pgencnt);
}

int
os_packet_set_traffic_class(const packet_t ph, packet_traffic_class_t tc)
{
	return __packet_set_traffic_class(ph, tc);
}

packet_traffic_class_t
os_packet_get_traffic_class(const packet_t ph)
{
	return __packet_get_traffic_class(ph);
}

int
os_packet_set_inet_checksum(const packet_t ph, const packet_csum_flags_t flags,
    const uint16_t start, const uint16_t stuff)
{
	return __packet_set_inet_checksum(ph, flags, start, stuff, TRUE);
}

packet_csum_flags_t
os_packet_get_inet_checksum(const packet_t ph, uint16_t *start, uint16_t *val)
{
	return __packet_get_inet_checksum(ph, start, val, FALSE);
}

void
os_packet_get_flow_uuid(const packet_t ph, uuid_t *flow_uuid)
{
	__packet_get_flow_uuid(ph, *flow_uuid);
}

void
os_packet_set_flow_uuid(const packet_t ph, const uuid_t flow_uuid)
{
	__packet_set_flow_uuid(ph, flow_uuid);
}

void
os_packet_clear_flow_uuid(const packet_t ph)
{
	__packet_clear_flow_uuid(ph);
}

void
os_packet_set_group_start(const packet_t ph)
{
	(void) __packet_set_group_start(ph);
}

boolean_t
os_packet_get_group_start(const packet_t ph)
{
	return __packet_get_group_start(ph);
}

void
os_packet_set_group_end(const packet_t ph)
{
	(void) __packet_set_group_end(ph);
}

boolean_t
os_packet_get_group_end(const packet_t ph)
{
	return __packet_get_group_end(ph);
}

int
os_packet_get_expire_time(const packet_t ph, uint64_t *ts)
{
	return __packet_get_expire_time(ph, ts);
}

int
os_packet_set_expire_time(const packet_t ph, const uint64_t ts)
{
	return __packet_set_expire_time(ph, ts);
}

int
os_packet_get_expiry_action(const packet_t ph, packet_expiry_action_t *pea)
{
	return __packet_get_expiry_action(ph, pea);
}

int
os_packet_set_expiry_action(const packet_t ph, const packet_expiry_action_t pea)
{
	return __packet_set_expiry_action(ph, pea);
}

int
os_packet_get_token(const packet_t ph, void *token, uint16_t *len)
{
	return __packet_get_token(ph, token, len);
}

int
os_packet_set_token(const packet_t ph, const void *token,
    const uint16_t len)
{
	return __packet_set_token(ph, token, len);
}

int
os_packet_get_packetid(const packet_t ph, packet_id_t *pktid)
{
	return __packet_get_packetid(ph, pktid);
}

int
os_packet_set_packetid(const packet_t ph, packet_id_t *pktid)
{
	return __packet_set_packetid(ph, pktid);
}

int
os_packet_set_vlan_tag(const packet_t ph, const uint16_t tag,
    const boolean_t tag_in_pkt)
{
	return __packet_set_vlan_tag(ph, tag, tag_in_pkt);
}

int
os_packet_get_vlan_tag(const packet_t ph, uint16_t *tag, boolean_t *tag_in_pkt)
{
	return __packet_get_vlan_tag(ph, tag, tag_in_pkt);
}

uint16_t
os_packet_get_vlan_id(const uint16_t tag)
{
	return __packet_get_vlan_id(tag);
}

uint8_t
os_packet_get_vlan_priority(const uint16_t tag)
{
	return __packet_get_vlan_priority(tag);
}

int
os_packet_set_app_metadata(const packet_t ph,
    const packet_app_metadata_type_t app_type, const uint8_t app_metadata)
{
	return __packet_set_app_metadata(ph, app_type, app_metadata);
}

boolean_t
os_packet_get_wake_flag(const packet_t ph)
{
	return __packet_get_wake_flag(ph);
}

boolean_t
os_packet_get_keep_alive(const packet_t ph)
{
	return __packet_get_keep_alive(ph);
}

void
os_packet_set_keep_alive(const packet_t ph, const boolean_t is_keep_alive)
{
	__packet_set_keep_alive(ph, is_keep_alive);
}

boolean_t
os_packet_get_truncated(const packet_t ph)
{
	return __packet_get_truncated(ph);
}

void
os_packet_set_l4s_flag(const packet_t ph, const boolean_t is_l4s)
{
	__packet_set_l4s_flag(ph, is_l4s);
}

uint32_t
os_packet_get_data_length(const packet_t ph)
{
	return __packet_get_data_length(ph);
}

uint32_t
os_packet_get_buflet_count(const packet_t ph)
{
	return __packet_get_buflet_count(ph);
}

buflet_t
os_packet_get_next_buflet(const packet_t ph, const buflet_t bprev)
{
	return __packet_get_next_buflet(ph, bprev);
}

uint32_t
os_packet_get_segment_count(const packet_t ph)
{
	return __packet_get_segment_count(ph);
}

int
os_packet_finalize(const packet_t ph)
{
	return __packet_finalize(ph);
}

int
os_packet_add_buflet(const packet_t ph, const buflet_t bprev,
    const buflet_t bnew)
{
	return __packet_add_buflet(ph, bprev, bnew);
}

int
os_packet_increment_use_count(const packet_t ph)
{
	if (__improbable(QUM_ADDR(ph)->qum_usecnt == 0xFFFF)) {
		return ERANGE;
	}
	QUM_ADDR(ph)->qum_usecnt++;
	return 0;
}

int
os_packet_decrement_use_count(const packet_t ph, uint16_t *use_cnt)
{
	if (__improbable(QUM_ADDR(ph)->qum_usecnt == 0)) {
		return ERANGE;
	}
	*use_cnt = --QUM_ADDR(ph)->qum_usecnt;
	return 0;
}

uint8_t
os_packet_get_aggregation_type(const packet_t ph)
{
	return __packet_get_aggregation_type(ph);
}

uint32_t
os_inet_checksum(const void *data, uint32_t len, uint32_t sum0)
{
	return __packet_cksum(data, len, sum0);
}

uint32_t
os_copy_and_inet_checksum(const void *src, void *dst, uint32_t len,
    uint32_t sum0)
{
	uint32_t sum = __packet_copy_and_sum(src, dst, len, sum0);
	return __packet_fold_sum_final(sum);
}

uint16_t
os_buflet_get_data_offset(const buflet_t buf)
{
	return __buflet_get_data_offset(buf);
}

uint16_t
os_buflet_get_data_length(const buflet_t buf)
{
	return __buflet_get_data_length(buf);
}

int
os_buflet_set_data_offset(const buflet_t buf, const uint16_t doff)
{
	return __buflet_set_data_offset(buf, doff);
}

int
os_buflet_set_data_length(const buflet_t buf, const uint16_t dlen)
{
	return __buflet_set_data_length(buf, dlen);
}

void *
os_buflet_get_object_address(const buflet_t buf)
{
	return __buflet_get_object_address(buf);
}

uint32_t
os_buflet_get_object_limit(const buflet_t buf)
{
	return __buflet_get_object_limit(buf);
}

void *
os_buflet_get_data_address(const buflet_t buf)
{
	return __buflet_get_data_address(buf);
}

uint16_t
os_buflet_get_data_limit(const buflet_t buf)
{
	return __buflet_get_data_limit(buf);
}

uint16_t
os_buflet_get_object_offset(const buflet_t buf)
{
	return __buflet_get_buffer_offset(buf);
}

uint16_t
os_buflet_get_gro_len(const buflet_t buf)
{
	return __buflet_get_gro_len(buf);
}

void *
os_buflet_get_next_buf(const buflet_t buflet, const void *prev_buf)
{
	return __buflet_get_next_buf(buflet, prev_buf);
}

packet_trace_id_t
os_packet_get_trace_id(const packet_t ph)
{
	return __packet_get_trace_id(ph);
}

void
os_packet_set_trace_id(const packet_t ph, packet_trace_id_t trace_id)
{
	__packet_set_trace_id(ph, trace_id);
}

void
os_packet_trace_event(const packet_t ph, uint32_t event)
{
	return __packet_trace_event(ph, event);
}

int
os_packet_set_protocol_segment_size(const packet_t ph, uint16_t proto_seg_sz)
{
	return __packet_set_protocol_segment_size(ph, proto_seg_sz);
}

void
os_packet_set_tso_flags(const packet_t ph, packet_tso_flags_t flags)
{
	return __packet_set_tso_flags(ph, flags);
}
