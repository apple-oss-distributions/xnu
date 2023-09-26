/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>


/*
 * Notification destination, can be either direct netif device,
 * or a flowswitch.
 */
struct __notif_dest {
	uint8_t dest_type;
#define __NOTIF_DEST_NONE 0
#define __NOTIF_DEST_FSW 1
#define __NOTIF_DEST_NETIF 2
	union {
		struct nx_flowswitch *dest_fsw;
		struct nx_netif          *dest_netif;
	};
	const char *dest_desc;
};

/* Create a notification destination from an ifnet device */
static inline errno_t
__notif_dest_by_ifp(struct __notif_dest *dest, const ifnet_t ifp)
{
	struct nx_flowswitch *fsw;
	struct nx_netif *netif;

	if (dest == NULL || ifp == NULL) {
		return EINVAL;
	}

	if (!IF_FULLY_ATTACHED(ifp)) {
		return ENXIO;
	}

	if ((fsw = fsw_ifp_to_fsw(ifp)) != NULL) {
		dest->dest_type = __NOTIF_DEST_FSW;
		dest->dest_fsw = fsw;
		dest->dest_desc = if_name(ifp);
		return 0;
	}

	if ((netif = NA(ifp)->nifna_netif) != NULL) {
		dest->dest_type =  __NOTIF_DEST_NETIF;
		dest->dest_netif = netif;
		dest->dest_desc = if_name(ifp);
		return 0;
	}

	return ENOENT;
}

/* Create a notification destination from a flowswitch uuid */
static inline errno_t
__notif_dest_by_nx_uuid(struct __notif_dest *dest, const uuid_t nx_uuid)
{
	struct kern_nexus *nx;
	struct nx_flowswitch *fsw;

	if (dest == NULL) {
		return EINVAL;
	}

	if ((nx = nx_find(nx_uuid, FALSE)) == NULL) {
		return ENOENT;
	}

	if ((fsw = NX_FSW_PRIVATE(nx)) == NULL) {
		return ENOENT;
	}

	dest->dest_type = __NOTIF_DEST_FSW;
	dest->dest_fsw = fsw;
	dest->dest_desc = (fsw->fsw_ifp != NULL)
	    ? if_name(fsw->fsw_ifp)
	    : "detached fsw";
	return 0;
}

/* function to send a packet channel event.
 *
 * Note on the event length limitations:
 * The event that goes onto the channel is emplaced
 * in a stack-allocated buffer, which includes
 * the space for the packet channel event data.
 * The size of the payload is governed by the
 * `CHANNEL_EVENT_MAX_PAYLOAD_LEN' constant.
 * See more details in `os_channel_event.h'
 */

static inline errno_t
kern_channel_packet_event_notify(struct __notif_dest *dest,
    os_channel_event_type_t event_type, size_t event_dlen,
    uint8_t *event_data, uint32_t nx_port_id)
{
	char buf[CHANNEL_EVENT_MAX_LEN]
	__attribute((aligned(sizeof(uint64_t))));
	struct __kern_channel_event *event =
	    (struct __kern_channel_event *)(void *)buf;

	if (dest == NULL || dest->dest_desc == NULL) {
		return EINVAL;
	}

	if (sizeof(buf) < sizeof(event) + event_dlen) {
		return EINVAL;
	}
	if ((event_type < CHANNEL_EVENT_MIN) || (CHANNEL_EVENT_MAX < event_type)) {
		return EINVAL;
	}

	event->ev_type = event_type;
	event->ev_flags = 0;
	event->_reserved = 0;
	event->ev_dlen = (uint16_t)event_dlen;
	memcpy(event->ev_data, event_data, event_dlen);

	SK_DF(SK_VERB_EVENTS, "%s[%d] kern_channel_event: %p dest_type: %hu len: %hu "
	    "type: %u flags: %u res: %hu dlen: %hu",
	    dest->dest_desc, nx_port_id, event, event_dlen,
	    event->ev_type, event->ev_flags, event->_reserved, event->ev_dlen);

	switch (dest->dest_type) {
	case __NOTIF_DEST_NETIF:
		return netif_vp_na_channel_event(dest->dest_netif,
		           nx_port_id, event, CHANNEL_EVENT_MAX_LEN);
	case __NOTIF_DEST_FSW:
		return fsw_vp_na_channel_event(dest->dest_fsw,
		           nx_port_id, event, CHANNEL_EVENT_MAX_LEN);
	default:
		return EINVAL;
	}
}

errno_t
kern_channel_event_transmit_status_with_packet(const kern_packet_t ph,
    const ifnet_t ifp)
{
	errno_t err;
	uint32_t nx_port_id;
	os_channel_event_packet_transmit_status_t pkt_tx_status;
	struct __notif_dest dest = {0, {NULL}, NULL};

	if ((err = __notif_dest_by_ifp(&dest, ifp)) != 0) {
		return err;
	}

	(void) __packet_get_tx_completion_status(ph,
	    &pkt_tx_status.packet_status);
	if (pkt_tx_status.packet_status == KERN_SUCCESS) {
		return 0;
	}
	err = __packet_get_packetid(ph, &pkt_tx_status.packet_id);
	if (__improbable(err != 0)) {
		return err;
	}
	err = __packet_get_tx_nx_port_id(ph, &nx_port_id);
	if (__improbable(err != 0)) {
		return err;
	}

	return kern_channel_packet_event_notify(&dest,
	           CHANNEL_EVENT_PACKET_TRANSMIT_STATUS,
	           sizeof(pkt_tx_status), (uint8_t*)&pkt_tx_status, nx_port_id);
}

errno_t
kern_channel_event_transmit_status(const ifnet_t ifp,
    os_channel_event_packet_transmit_status_t *pkt_tx_status,
    uint32_t nx_port_id)
{
	errno_t err;
	struct __notif_dest dest = {0, {NULL}, NULL};

	if ((err = __notif_dest_by_ifp(&dest, ifp)) != 0) {
		return err;
	}

	return kern_channel_packet_event_notify(&dest,
	           CHANNEL_EVENT_PACKET_TRANSMIT_STATUS,
	           sizeof(*pkt_tx_status), (uint8_t*)pkt_tx_status, nx_port_id);
}

errno_t
kern_channel_event_transmit_status_with_nexus(const uuid_t nx_uuid,
    os_channel_event_packet_transmit_status_t *pkt_tx_status,
    uint32_t nx_port_id)
{
	errno_t err;
	struct __notif_dest dest = {0, {NULL}, NULL};

	if ((err = __notif_dest_by_nx_uuid(&dest, nx_uuid)) != 0) {
		return err;
	}

	return kern_channel_packet_event_notify(&dest,
	           CHANNEL_EVENT_PACKET_TRANSMIT_STATUS,
	           sizeof(*pkt_tx_status), (uint8_t*)pkt_tx_status, nx_port_id);
}

errno_t
kern_channel_event_transmit_expired(const ifnet_t ifp,
    os_channel_event_packet_transmit_expired_t *pkt_tx_expired,
    uint32_t nx_port_id)
{
	errno_t err;
	struct __notif_dest dest = {0, {NULL}, NULL};

	if ((err = __notif_dest_by_ifp(&dest, ifp)) != 0) {
		return err;
	}

	return kern_channel_packet_event_notify(&dest,
	           CHANNEL_EVENT_PACKET_TRANSMIT_EXPIRED,
	           sizeof(*pkt_tx_expired), (uint8_t*)pkt_tx_expired, nx_port_id);
}

extern errno_t
kern_channel_event_transmit_expired_with_nexus(const uuid_t nx_uuid,
    os_channel_event_packet_transmit_expired_t *pkt_tx_expired,
    uint32_t nx_port_id)
{
	errno_t err;
	struct __notif_dest dest = {0, {NULL}, NULL};

	if ((err = __notif_dest_by_nx_uuid(&dest, nx_uuid)) != 0) {
		return err;
	}

	return kern_channel_packet_event_notify(&dest,
	           CHANNEL_EVENT_PACKET_TRANSMIT_EXPIRED,
	           sizeof(*pkt_tx_expired), (uint8_t*)pkt_tx_expired, nx_port_id);
}

/* routine to post kevent notification for the event ring */
void
kern_channel_event_notify(struct __kern_channel_ring *kring)
{
	ASSERT(kring->ckr_tx == NR_TX);

	SK_DF(SK_VERB_EVENTS, "%s(%d) na \"%s\" (0x%llx) kr 0x%llx",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    KRNA(kring)->na_name, SK_KVA(KRNA(kring)), SK_KVA(kring));

	na_post_event(kring, TRUE, FALSE, FALSE, CHAN_FILT_HINT_CHANNEL_EVENT);
}

/* sync routine for the event ring */
int
kern_channel_event_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	(void) kr_reclaim(kring);
	return 0;
}
