/*
 * Copyright (c) 1999-2024 Apple Inc. All rights reserved.
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
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <stdint.h>

#include <net/dlil_sysctl.h>
#include <net/dlil_var_private.h>
#include <net/net_api_stats.h>
#include <net/net_sysctl.h>

#if SKYWALK
#include <skywalk/os_skywalk_private.h>
#endif /* SKYWALK */

static int sysctl_rxpoll SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_mode_holdtime SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_sample_holdtime SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_interval_time SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_wlowat SYSCTL_HANDLER_ARGS;
static int sysctl_rxpoll_whiwat SYSCTL_HANDLER_ARGS;
static int sysctl_sndq_maxlen SYSCTL_HANDLER_ARGS;
static int sysctl_rcvq_maxlen SYSCTL_HANDLER_ARGS;
static int sysctl_rcvq_burst_limit SYSCTL_HANDLER_ARGS;
static int sysctl_rcvq_trim_pct SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_mode SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_partial_rxoff_forced SYSCTL_HANDLER_ARGS;
static int sysctl_hwcksum_dbg_partial_rxoff_adj SYSCTL_HANDLER_ARGS;
static int sysctl_tx_chain_len_stats SYSCTL_HANDLER_ARGS;
static int if_enable_fsw_transport_netagent_sysctl SYSCTL_HANDLER_ARGS;

#if TEST_INPUT_THREAD_TERMINATION
static int sysctl_input_thread_termination_spin SYSCTL_HANDLER_ARGS;
#endif /* TEST_INPUT_THREAD_TERMINATION */

#if (DEVELOPMENT || DEBUG)
static int sysctl_get_kao_frames SYSCTL_HANDLER_ARGS;
static int if_attach_nx_sysctl SYSCTL_HANDLER_ARGS;
#endif /* DEVELOPMENT | DEBUG */



SYSCTL_DECL(_net_link_generic_system);

/******************************************************************************
* Section: DLIL send and receive queues.                                     *
******************************************************************************/
#define IF_SNDQ_MINLEN  32
uint32_t if_sndq_maxlen = IFQ_MAXLEN; /* should it be IFQ_SNDQ_MAXLEN ? */
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, sndq_maxlen,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_sndq_maxlen, IFQ_MAXLEN,
    sysctl_sndq_maxlen, "I", "Default transmit queue max length");

uint32_t if_rcvq_maxlen = IF_RCVQ_MAXLEN;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rcvq_maxlen,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rcvq_maxlen, IFQ_MAXLEN,
    sysctl_rcvq_maxlen, "I", "Default receive queue max length");

uint32_t if_delaybased_queue = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, delaybased_queue,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_delaybased_queue, 1,
    "enable delay based dynamic queue sizing");

uint32_t ifnet_start_delayed = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, start_delayed,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifnet_start_delayed, 0,
    "number of times start was delayed");

uint32_t ifnet_delay_start_disabled = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, start_delay_disabled,
    CTLFLAG_RW | CTLFLAG_LOCKED, &ifnet_delay_start_disabled, 0,
    "number of times start was delayed");

/*
 * Protect against possible memory starvation that may happen
 * when the driver is pushing data faster than the AP can process.
 *
 * If at any point during DLIL input phase any of the input queues
 * exceeds the burst limit, DLIL will start to trim the queue,
 * by returning mbufs in the input queue to the cache from which
 * the mbufs were originally allocated, starting from the oldest
 * mbuf and continuing until the new limit (see below) is reached.
 *
 * In order to avoid a steplocked equilibrium, the trimming
 * will continue PAST the burst limit, until the corresponding
 * input queue is reduced to `if_rcvq_trim_pct' %.
 *
 * For example, if the input queue limit is 1024 packets,
 * and the trim percentage (`if_rcvq_trim_pct') is 80 %,
 * the trimming will continue until the queue contains 819 packets
 * (1024 * 80 / 100 == 819).
 *
 * Setting the burst limit too low can hurt the throughput,
 * while setting the burst limit too high can defeat the purpose.
 */
#define IF_RCVQ_BURST_LIMIT_MIN         1024
#define IF_RCVQ_BURST_LIMIT_DEFAULT     8192
#define IF_RCVQ_BURST_LIMIT_MAX         32768
uint32_t if_rcvq_burst_limit = IF_RCVQ_BURST_LIMIT_DEFAULT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rcvq_burst_limit,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rcvq_burst_limit, IF_RCVQ_BURST_LIMIT_DEFAULT,
    sysctl_rcvq_burst_limit, "I", "Upper memory limit for inbound data");

#define IF_RCVQ_TRIM_PCT_MIN            20
#define IF_RCVQ_TRIM_PCT_DEFAULT        80
#define IF_RCVQ_TRIM_PCT_MAX            100
uint32_t if_rcvq_trim_pct = IF_RCVQ_TRIM_PCT_DEFAULT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rcvq_trim_pct,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rcvq_trim_pct, IF_RCVQ_TRIM_PCT_DEFAULT,
    sysctl_rcvq_trim_pct, "I",
    "Percentage (0 - 100) of the queue limit to keep after detecting an overflow burst");

struct chain_len_stats tx_chain_len_stats;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, tx_chain_len_stats,
    CTLFLAG_RD | CTLFLAG_LOCKED, 0, 9,
    sysctl_tx_chain_len_stats, "S", "");

uint32_t tx_chain_len_count = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, tx_chain_len_count,
    CTLFLAG_RW | CTLFLAG_LOCKED, &tx_chain_len_count, 0, "");

/******************************************************************************
* Section: DLIL opportunistic rx polling.                                    *
******************************************************************************/

uint32_t if_rxpoll = 1;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll, 0,
    sysctl_rxpoll, "I", "enable opportunistic input polling");

#define IF_RXPOLL_DECAY                 2   /* ilog2 of EWMA decay rate (4) */
uint32_t if_rxpoll_decay = IF_RXPOLL_DECAY;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_decay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_decay, IF_RXPOLL_DECAY,
    "ilog2 of EWMA decay rate of avg inbound packets");

#define IF_RXPOLL_MODE_HOLDTIME_MIN     (10ULL * 1000 * 1000)   /* 10 ms */
#define IF_RXPOLL_MODE_HOLDTIME         (1000ULL * 1000 * 1000) /* 1 sec */
uint64_t if_rxpoll_mode_holdtime = IF_RXPOLL_MODE_HOLDTIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_freeze_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_mode_holdtime,
    IF_RXPOLL_MODE_HOLDTIME, sysctl_rxpoll_mode_holdtime,
    "Q", "input poll mode freeze time");

#define IF_RXPOLL_SAMPLETIME_MIN        (1ULL * 1000 * 1000)    /* 1 ms */
#define IF_RXPOLL_SAMPLETIME            (10ULL * 1000 * 1000)   /* 10 ms */
uint64_t if_rxpoll_sample_holdtime = IF_RXPOLL_SAMPLETIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_sample_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_sample_holdtime,
    IF_RXPOLL_SAMPLETIME, sysctl_rxpoll_sample_holdtime,
    "Q", "input poll sampling time");

/* Input poll interval definitions */
#define IF_RXPOLL_INTERVALTIME_MIN      (1ULL * 1000)           /* 1 us */
#define IF_RXPOLL_INTERVALTIME          (1ULL * 1000 * 1000)    /* 1 ms */
uint64_t if_rxpoll_interval_time = IF_RXPOLL_INTERVALTIME;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_interval_time,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_interval_time,
    IF_RXPOLL_INTERVALTIME, sysctl_rxpoll_interval_time,
    "Q", "input poll interval (time)");

#define IF_RXPOLL_INTERVAL_PKTS         0   /* 0 (disabled) */
uint32_t if_rxpoll_interval_pkts = IF_RXPOLL_INTERVAL_PKTS;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_interval_pkts,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_interval_pkts,
    IF_RXPOLL_INTERVAL_PKTS, "input poll interval (packets)");

#define IF_RXPOLL_WLOWAT                10
uint32_t if_sysctl_rxpoll_wlowat = IF_RXPOLL_WLOWAT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_wakeups_lowat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_sysctl_rxpoll_wlowat,
    IF_RXPOLL_WLOWAT, sysctl_rxpoll_wlowat,
    "I", "input poll wakeup low watermark");

#define IF_RXPOLL_WHIWAT                100
uint32_t if_sysctl_rxpoll_whiwat = IF_RXPOLL_WHIWAT;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, rxpoll_wakeups_hiwat,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &if_sysctl_rxpoll_whiwat,
    IF_RXPOLL_WHIWAT, sysctl_rxpoll_whiwat,
    "I", "input poll wakeup high watermark");

uint32_t if_rxpoll_max = 0;  /* automatic */
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, rxpoll_max,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_rxpoll_max, 0,
    "max packets per poll call");

#if TEST_INPUT_THREAD_TERMINATION
uint32_t if_input_thread_termination_spin = 0 /* disabled */;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, input_thread_termination_spin,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_input_thread_termination_spin, 0,
    sysctl_input_thread_termination_spin,
    "I", "input thread termination spin limit");
#endif /* TEST_INPUT_THREAD_TERMINATION */

uint32_t cur_dlil_input_threads = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, dlil_input_threads,
    CTLFLAG_RD | CTLFLAG_LOCKED, &cur_dlil_input_threads, 0,
    "Current number of DLIL input threads");


/******************************************************************************
* Section: hardware-assisted checksum mechanism.                             *
******************************************************************************/

uint32_t hwcksum_tx = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_tx,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_tx, 0,
    "enable transmit hardware checksum offload");

uint32_t hwcksum_rx = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_rx,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_rx, 0,
    "enable receive hardware checksum offload");

uint64_t hwcksum_in_invalidated = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_in_invalidated, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_in_invalidated, "inbound packets with invalidated hardware cksum");

uint32_t hwcksum_dbg = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, hwcksum_dbg,
    CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg, 0,
    "enable hardware cksum debugging");

uint32_t hwcksum_dbg_mode = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, hwcksum_dbg_mode,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg_mode,
    0, sysctl_hwcksum_dbg_mode, "I", "hardware cksum debugging mode");

uint64_t hwcksum_dbg_partial_forced = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_forced, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_forced, "packets forced using partial cksum");

uint64_t hwcksum_dbg_partial_forced_bytes = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_forced_bytes, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_forced_bytes, "bytes forced using partial cksum");

uint32_t hwcksum_dbg_partial_rxoff_forced = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_partial_rxoff_forced, CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &hwcksum_dbg_partial_rxoff_forced, 0,
    sysctl_hwcksum_dbg_partial_rxoff_forced, "I",
    "forced partial cksum rx offset");

uint32_t hwcksum_dbg_partial_rxoff_adj = 0;
SYSCTL_PROC(_net_link_generic_system, OID_AUTO, hwcksum_dbg_partial_rxoff_adj,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, &hwcksum_dbg_partial_rxoff_adj,
    0, sysctl_hwcksum_dbg_partial_rxoff_adj, "I",
    "adjusted partial cksum rx offset");

uint64_t hwcksum_dbg_verified = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_verified, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_verified, "packets verified for having good checksum");

uint64_t hwcksum_dbg_bad_cksum = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_bad_cksum, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_bad_cksum, "packets with bad hardware calculated checksum");

uint64_t hwcksum_dbg_bad_rxoff = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_bad_rxoff, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_bad_rxoff, "packets with invalid rxoff");

uint64_t hwcksum_dbg_adjusted = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_adjusted, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_adjusted, "packets with rxoff adjusted");

uint64_t hwcksum_dbg_finalized_hdr = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_finalized_hdr, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_finalized_hdr, "finalized headers");

uint64_t hwcksum_dbg_finalized_data = 0;
SYSCTL_QUAD(_net_link_generic_system, OID_AUTO,
    hwcksum_dbg_finalized_data, CTLFLAG_RD | CTLFLAG_LOCKED,
    &hwcksum_dbg_finalized_data, "finalized payloads");


/******************************************************************************
* Section: DLIL debugging, notifications and sanity checks                   *
******************************************************************************/

uint32_t if_flowadv = 1;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, flow_advisory,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_flowadv, 1,
    "enable flow-advisory mechanism");

uint32_t threshold_notify = 1;           /* enable/disable */
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, threshold_notify,
    CTLFLAG_RW | CTLFLAG_LOCKED, &threshold_notify, 0, "");

uint32_t threshold_interval = 2; /* in seconds */;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, threshold_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &threshold_interval, 0, "");

struct net_api_stats net_api_stats;
SYSCTL_STRUCT(_net, OID_AUTO, api_stats, CTLFLAG_RD | CTLFLAG_LOCKED,
    &net_api_stats, net_api_stats, "");

#if DEBUG
int dlil_verbose = 1;
#else
int dlil_verbose = 0;
#endif /* DEBUG */

SYSCTL_INT(_net_link_generic_system, OID_AUTO, dlil_verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED, &dlil_verbose, 0, "Log DLIL error messages");

uint32_t net_wake_pkt_debug = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, wake_pkt_debug,
    CTLFLAG_RW | CTLFLAG_LOCKED, &net_wake_pkt_debug, 0, "");

#if IFNET_INPUT_SANITY_CHK
uint32_t dlil_input_sanity_check = 0;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, dlil_input_sanity_check,
    CTLFLAG_RW | CTLFLAG_LOCKED, &dlil_input_sanity_check, 0,
    "Turn on sanity checking in DLIL input");
#endif /* IFNET_INPUT_SANITY_CHK */


#if (DEVELOPMENT || DEBUG)

static int sysctl_get_kao_frames SYSCTL_HANDLER_ARGS;
SYSCTL_NODE(_net_link_generic_system, OID_AUTO, get_kao_frames,
    CTLFLAG_RD | CTLFLAG_LOCKED, sysctl_get_kao_frames, "");

SYSCTL_PROC(_net_link_generic_system, OID_AUTO, if_attach_nx,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, &if_attach_nx_sysctl, "IU", "attach nexus");

#endif /* DEVELOPMENT || DEBUG */

SYSCTL_PROC(_net_link_generic_system, OID_AUTO, enable_netagent,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, &if_enable_fsw_transport_netagent_sysctl, "IU",
    "enable flowswitch netagent");

#define DEFAULT_IF_LINK_HEURISTIC \
    (IF_LINK_HEURISTICS_CELLULAR | IF_LINK_HEURISTICS_LINK_CONGESTED)
uint32_t if_link_heuristics_flags = DEFAULT_IF_LINK_HEURISTIC;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, link_heuristics_flags,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_link_heuristics_flags, DEFAULT_IF_LINK_HEURISTIC, "");

int if_link_heuristics_lqm_max = 0;
SYSCTL_INT(_net_link_generic_system, OID_AUTO, link_heuristics_lqm_max,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_link_heuristics_lqm_max, 0, "Max value to enable link heuristics");

uint32_t if_link_heuristics_delay = IF_LINK_HEURISTICS_DELAY_MSECS;
SYSCTL_UINT(_net_link_generic_system, OID_AUTO, link_heuristics_delay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &if_link_heuristics_delay, IF_LINK_HEURISTICS_DELAY_MSECS, "");


#if TEST_INPUT_THREAD_TERMINATION
static int
sysctl_input_thread_termination_spin SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_input_thread_termination_spin;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (net_rxpoll == 0) {
		return ENXIO;
	}

	if_input_thread_termination_spin = i;
	return err;
}
#endif /* TEST_INPUT_THREAD_TERMINATION */

static int
sysctl_rxpoll SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_rxpoll;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (net_rxpoll == 0) {
		return ENXIO;
	}

	if_rxpoll = i;
	return err;
}

static int
sysctl_rxpoll_mode_holdtime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_mode_holdtime;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (q < IF_RXPOLL_MODE_HOLDTIME_MIN) {
		q = IF_RXPOLL_MODE_HOLDTIME_MIN;
	}

	if_rxpoll_mode_holdtime = q;

	return err;
}

static int
sysctl_rxpoll_sample_holdtime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_sample_holdtime;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (q < IF_RXPOLL_SAMPLETIME_MIN) {
		q = IF_RXPOLL_SAMPLETIME_MIN;
	}

	if_rxpoll_sample_holdtime = q;

	return err;
}

static int
sysctl_rxpoll_interval_time SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = if_rxpoll_interval_time;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (q < IF_RXPOLL_INTERVALTIME_MIN) {
		q = IF_RXPOLL_INTERVALTIME_MIN;
	}

	if_rxpoll_interval_time = q;

	return err;
}

static int
sysctl_rxpoll_wlowat SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_sysctl_rxpoll_wlowat;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (i == 0 || i >= if_sysctl_rxpoll_whiwat) {
		return EINVAL;
	}

	if_sysctl_rxpoll_wlowat = i;
	return err;
}

static int
sysctl_rxpoll_whiwat SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = if_sysctl_rxpoll_whiwat;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (i <= if_sysctl_rxpoll_wlowat) {
		return EINVAL;
	}

	if_sysctl_rxpoll_whiwat = i;
	return err;
}

static int
sysctl_sndq_maxlen SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_sndq_maxlen;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (i < IF_SNDQ_MINLEN) {
		i = IF_SNDQ_MINLEN;
	}

	if_sndq_maxlen = i;
	return err;
}

static int
sysctl_rcvq_maxlen SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_rcvq_maxlen;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (i < IF_RCVQ_MINLEN) {
		i = IF_RCVQ_MINLEN;
	}

	if_rcvq_maxlen = i;
	return err;
}

static int
sysctl_rcvq_burst_limit SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_rcvq_burst_limit;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

/*
 * Safeguard the burst limit to "sane" values on customer builds.
 */
#if !(DEVELOPMENT || DEBUG)
	if (i < IF_RCVQ_BURST_LIMIT_MIN) {
		i = IF_RCVQ_BURST_LIMIT_MIN;
	}

	if (IF_RCVQ_BURST_LIMIT_MAX < i) {
		i = IF_RCVQ_BURST_LIMIT_MAX;
	}
#endif

	if_rcvq_burst_limit = i;
	return err;
}

static int
sysctl_rcvq_trim_pct SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int i, err;

	i = if_rcvq_burst_limit;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (IF_RCVQ_TRIM_PCT_MAX < i) {
		i = IF_RCVQ_TRIM_PCT_MAX;
	}

	if (i < IF_RCVQ_TRIM_PCT_MIN) {
		i = IF_RCVQ_TRIM_PCT_MIN;
	}

	if_rcvq_trim_pct = i;
	return err;
}

static int
sysctl_hwcksum_dbg_mode SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint32_t i;
	int err;

	i = hwcksum_dbg_mode;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (hwcksum_dbg == 0) {
		return ENODEV;
	}

	if ((i & ~HWCKSUM_DBG_MASK) != 0) {
		return EINVAL;
	}

	hwcksum_dbg_mode = (i & HWCKSUM_DBG_MASK);

	return err;
}

static int
sysctl_hwcksum_dbg_partial_rxoff_forced SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = hwcksum_dbg_partial_rxoff_forced;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_FORCED)) {
		return ENODEV;
	}

	hwcksum_dbg_partial_rxoff_forced = i;

	return err;
}

static int
sysctl_hwcksum_dbg_partial_rxoff_adj SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	u_int32_t i;
	int err;

	i = hwcksum_dbg_partial_rxoff_adj;

	err = sysctl_handle_int(oidp, &i, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (!(hwcksum_dbg_mode & HWCKSUM_DBG_PARTIAL_RXOFF_ADJ)) {
		return ENODEV;
	}

	hwcksum_dbg_partial_rxoff_adj = i;

	return err;
}

static int
sysctl_tx_chain_len_stats SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int err;

	if (req->oldptr == USER_ADDR_NULL) {
	}
	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}
	err = SYSCTL_OUT(req, &tx_chain_len_stats,
	    sizeof(struct chain_len_stats));

	return err;
}

#if (DEVELOPMENT || DEBUG)
/*
 * The sysctl variable name contains the input parameters of
 * ifnet_get_keepalive_offload_frames()
 *  ifp (interface index): name[0]
 *  frames_array_count:    name[1]
 *  frame_data_offset:     name[2]
 * The return length gives used_frames_count
 */
static int
sysctl_get_kao_frames SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp)
	DECLARE_SYSCTL_HANDLER_ARG_ARRAY(int, 3, name, namelen);
	int idx;
	ifnet_t ifp = NULL;
	u_int32_t frames_array_count;
	size_t frame_data_offset;
	u_int32_t used_frames_count;
	struct ifnet_keepalive_offload_frame *frames_array = NULL;
	int error = 0;
	u_int32_t i;

	/*
	 * Only root can get look at other people TCP frames
	 */
	error = proc_suser(current_proc());
	if (error != 0) {
		goto done;
	}
	/*
	 * Validate the input parameters
	 */
	if (req->newptr != USER_ADDR_NULL) {
		error = EPERM;
		goto done;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		error = EINVAL;
		goto done;
	}
	if (req->oldlen == 0) {
		error = EINVAL;
		goto done;
	}
	idx = name[0];
	frames_array_count = name[1];
	frame_data_offset = name[2];

	/* Make sure the passed buffer is large enough */
	if (frames_array_count * sizeof(struct ifnet_keepalive_offload_frame) >
	    req->oldlen) {
		error = ENOMEM;
		goto done;
	}

	ifnet_head_lock_shared();
	if (!IF_INDEX_IN_RANGE(idx)) {
		ifnet_head_done();
		error = ENOENT;
		goto done;
	}
	ifp = ifindex2ifnet[idx];
	ifnet_head_done();

	frames_array = (struct ifnet_keepalive_offload_frame *)kalloc_data(
		frames_array_count * sizeof(struct ifnet_keepalive_offload_frame),
		Z_WAITOK);
	if (frames_array == NULL) {
		error = ENOMEM;
		goto done;
	}

	error = ifnet_get_keepalive_offload_frames(ifp, frames_array,
	    frames_array_count, frame_data_offset, &used_frames_count);
	if (error != 0) {
		DLIL_PRINTF("%s: ifnet_get_keepalive_offload_frames error %d\n",
		    __func__, error);
		goto done;
	}

	for (i = 0; i < used_frames_count; i++) {
		error = SYSCTL_OUT(req, frames_array + i,
		    sizeof(struct ifnet_keepalive_offload_frame));
		if (error != 0) {
			goto done;
		}
	}
done:
	if (frames_array != NULL) {
		kfree_data(frames_array, frames_array_count *
		    sizeof(struct ifnet_keepalive_offload_frame));
	}
	return error;
}

static int
if_attach_nx_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error = sysctl_io_number(req, if_attach_nx, sizeof(if_attach_nx),
	    &new_value, &changed);
	if (error) {
		return error;
	}
	if (changed) {
		if ((new_value & IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT) !=
		    (if_attach_nx & IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT)) {
			return ENOTSUP;
		}
		if_attach_nx = new_value;
	}
	return 0;
}

#endif /* DEVELOPMENT || DEBUG */

static int
if_enable_fsw_transport_netagent_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	unsigned int new_value;
	int changed;
	int error;

	error = sysctl_io_number(req, if_enable_fsw_transport_netagent,
	    sizeof(if_enable_fsw_transport_netagent),
	    &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value != 0 && new_value != 1) {
			/* only allow 0 or 1 */
			error = EINVAL;
		} else if ((if_attach_nx & IF_ATTACH_NX_FSW_TRANSPORT_NETAGENT) != 0) {
			/* netagent can be enabled/disabled */
			if_enable_fsw_transport_netagent = new_value;
			if (new_value == 0) {
				kern_nexus_deregister_netagents();
			} else {
				kern_nexus_register_netagents();
			}
		} else {
			/* netagent can't be enabled */
			error = ENOTSUP;
		}
	}
	return error;
}
