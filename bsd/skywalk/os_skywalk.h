/*
 * Copyright (c) 2015-2016 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_OS_SKYWALK_H
#define _SKYWALK_OS_SKYWALK_H

#ifdef PRIVATE
#include <skywalk/os_channel.h>
#include <skywalk/os_nexus.h>
#include <skywalk/os_packet.h>
#endif /* PRIVATE */

/*
 * Skywalk ktrace event ID
 *
 * Always on events are captured by artrace by default. Others can be
 * selectively enabled via artrace -f S0x08[subclass], whereas [subclass] is
 * one of DBG_SKYWALK_{ALWAYSON, FLOWSWITCH, NETIF, CHANNEL, PACKET}.
 *
 * Please keep values in sync with skywalk_signposts.plist and assertions in
 * skywalk_self_tests.
 */
/** @always-on subclass */
#define SK_KTRACE_AON_IF_STATS                  SKYWALKDBG_CODE(DBG_SKYWALK_ALWAYSON, 0x001)

/** @flowswitch subclass */
#define SK_KTRACE_FSW_DEV_RING_FLUSH            SKYWALKDBG_CODE(DBG_SKYWALK_FLOWSWITCH, 0x001)
#define SK_KTRACE_FSW_USER_RING_FLUSH           SKYWALKDBG_CODE(DBG_SKYWALK_FLOWSWITCH, 0x002)
#define SK_KTRACE_FSW_FLOW_TRACK_RTT            SKYWALKDBG_CODE(DBG_SKYWALK_FLOWSWITCH, 0x004)

/** @netif subclass */
#define SK_KTRACE_NETIF_RING_TX_REFILL          SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x001)
#define SK_KTRACE_NETIF_HOST_ENQUEUE            SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x002)
#define SK_KTRACE_NETIF_MIT_RX_INTR             SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x003)
#define SK_KTRACE_NETIF_COMMON_INTR             SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x004)
#define SK_KTRACE_NETIF_RX_NOTIFY_DEFAULT       SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x005)
#define SK_KTRACE_NETIF_RX_NOTIFY_FAST          SKYWALKDBG_CODE(DBG_SKYWALK_NETIF, 0x006)

/** @channel subclass */
#define SK_KTRACE_CHANNEL_TX_REFILL             SKYWALKDBG_CODE(DBG_SKYWALK_CHANNEL, 0x1)

/** @packet subclass */
/*
 * Used with os_packet_trace_* functions.
 * Total of 12bit (0xABC) code space available, current sub-code allocation is:
 *     0x00C code space for FSW Rx path.
 *     0x01C code space for FSW Tx path.
 * More sub-code can be added for other packet data path, e.g. uPipe, BSD, etc.
 */
/* @packet::rx group */
#define SK_KTRACE_PKT_RX_DRV                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x001)
#define SK_KTRACE_PKT_RX_FSW                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x002)
#define SK_KTRACE_PKT_RX_CHN                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x003)
/* @packet::tx group */
#define SK_KTRACE_PKT_TX_FSW                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x010)
#define SK_KTRACE_PKT_TX_AQM                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x011)
#define SK_KTRACE_PKT_TX_DRV                    SKYWALKDBG_CODE(DBG_SKYWALK_PACKET, 0x012)

#endif /* _SKYWALK_OS_SKYWALK_H */
