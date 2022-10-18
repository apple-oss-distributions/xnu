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

/* function to send the packet transmit status event on the channel */
static inline errno_t
kern_channel_event_transmit_status_notify(const ifnet_t ifp,
    os_channel_event_packet_transmit_status_t *pkt_tx_status,
    uint32_t nx_port_id)
{
	char buf[CHANNEL_EVENT_TX_STATUS_LEN]
	__attribute((aligned(sizeof(uint64_t))));
	struct __kern_channel_event *event =
	    (struct __kern_channel_event *)(void *)buf;
	os_channel_event_packet_transmit_status_t *ts_ev =
	    (os_channel_event_packet_transmit_status_t *)&event->ev_data;

	if (!IF_FULLY_ATTACHED(ifp)) {
		return ENXIO;
	}

	event->ev_type = CHANNEL_EVENT_PACKET_TRANSMIT_STATUS;
	event->ev_flags = 0;
	event->_reserved = 0;
	event->ev_dlen = sizeof(os_channel_event_packet_transmit_status_t);
	*ts_ev = *pkt_tx_status;

	struct nx_flowswitch *fsw = fsw_ifp_to_fsw(ifp);
	if (fsw == NULL) {
		return netif_vp_na_channel_event(NA(ifp)->nifna_netif,
		           nx_port_id, event, CHANNEL_EVENT_TX_STATUS_LEN);
	} else {
		return fsw_vp_na_channel_event(fsw, nx_port_id, event,
		           CHANNEL_EVENT_TX_STATUS_LEN);
	}
}

errno_t
kern_channel_event_transmit_status_with_packet(const kern_packet_t ph,
    const ifnet_t ifp)
{
	int err;
	uint32_t nx_port_id;
	os_channel_event_packet_transmit_status_t pkt_tx_status;

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
	return kern_channel_event_transmit_status_notify(ifp, &pkt_tx_status,
	           nx_port_id);
}

errno_t
kern_channel_event_transmit_status(const ifnet_t ifp,
    os_channel_event_packet_transmit_status_t *pkt_tx_status,
    uint32_t nx_port_id)
{
	return kern_channel_event_transmit_status_notify(ifp, pkt_tx_status,
	           nx_port_id);
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
