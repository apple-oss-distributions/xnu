/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

/* function to send the packet transmit status event on the channel */
errno_t
kern_channel_event_transmit_status(const kern_packet_t ph, const ifnet_t ifp)
{
	errno_t err;
	packet_id_t pktid;
	kern_return_t tx_status;
	struct nexus_adapter *devna;
	char buf[CHANNEL_EVENT_TX_STATUS_LEN]__attribute((aligned(sizeof(uint64_t))));
	struct __kern_channel_event *event =
	    (struct __kern_channel_event *)(void *)buf;
	os_channel_event_packet_transmit_status_t *ts_ev =
	    (os_channel_event_packet_transmit_status_t *)&event->ev_data;

	if (!IF_FULLY_ATTACHED(ifp)) {
		return ENXIO;
	}
	devna = &NA(ifp)->nifna_up;
	ASSERT((devna->na_type == NA_NETIF_DEV) ||
	    (devna->na_type == NA_NETIF_COMPAT_DEV));
	if (devna->na_channel_event_notify == NULL) {
		return ENOTSUP;
	}
	/*
	 * currently interface advisory is only supported for netif
	 * in low latency mode.
	 */
	if (!NETIF_IS_LOW_LATENCY(NIFNA(devna)->nifna_netif)) {
		return ENOTSUP;
	}
	err = __packet_get_packetid(ph, &pktid);
	if (err != 0) {
		return err;
	}
	(void) __packet_get_tx_completion_status(ph, &tx_status);
	ASSERT(tx_status != 0);
	event->ev_type = CHANNEL_EVENT_PACKET_TRANSMIT_STATUS;
	event->ev_flags = 0;
	event->_reserved = 0;
	event->ev_dlen = sizeof(os_channel_event_packet_transmit_status_t);
	ts_ev->packet_status = tx_status;
	ts_ev->packet_id = pktid;
	return devna->na_channel_event_notify(devna, SK_PTR_ADDR_KPKT(ph),
	           event, CHANNEL_EVENT_TX_STATUS_LEN);
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
