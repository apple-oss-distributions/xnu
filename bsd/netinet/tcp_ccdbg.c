/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include "tcp_includes.h"

#include <sys/domain.h>
#include <sys/sdt.h>

#define TCP_CCDBG_NOUNIT 0xffffffff
static kern_ctl_ref tcp_ccdbg_ctlref = NULL;
volatile uint32_t tcp_ccdbg_unit = TCP_CCDBG_NOUNIT;

/* Allow only one socket to connect at any time for debugging */
static errno_t
tcp_ccdbg_control_connect(kern_ctl_ref kctl, struct sockaddr_ctl *sac,
    void **uinfo)
{
#pragma unused(kctl)
#pragma unused(uinfo)

	UInt32 old_value = TCP_CCDBG_NOUNIT;
	UInt32 new_value = sac->sc_unit;

	if (tcp_ccdbg_unit != old_value) {
		return EALREADY;
	}

	if (OSCompareAndSwap(old_value, new_value, &tcp_ccdbg_unit)) {
		return 0;
	} else {
		return EALREADY;
	}
}

static errno_t
tcp_ccdbg_control_disconnect(kern_ctl_ref kctl, u_int32_t unit, void *uinfo)
{
#pragma unused(kctl, unit, uinfo)

	if (unit == tcp_ccdbg_unit) {
		UInt32 old_value = tcp_ccdbg_unit;
		UInt32 new_value = TCP_CCDBG_NOUNIT;
		if (tcp_ccdbg_unit == new_value) {
			return 0;
		}

		if (!OSCompareAndSwap(old_value, new_value,
		    &tcp_ccdbg_unit)) {
			log(LOG_DEBUG,
			    "failed to disconnect tcp_cc debug control");
		}
	}
	return 0;
}

inline void
tcp_ccdbg_trace(struct tcpcb *tp, struct tcphdr *th, int32_t event)
{
#if !CONFIG_DTRACE
#pragma unused(th)
#endif /* !CONFIG_DTRACE */
	struct inpcb *inp = tp->t_inpcb;

	if (tcp_cc_debug && tcp_ccdbg_unit > 0) {
		struct tcp_cc_debug_state dbg_state;
		struct timespec tv;

		bzero(&dbg_state, sizeof(dbg_state));

		nanotime(&tv);
		/* Take time in seconds */
		dbg_state.ccd_tsns = (tv.tv_sec * 1000000000) + tv.tv_nsec;
		inet_ntop(SOCK_DOM(inp->inp_socket),
		    ((SOCK_DOM(inp->inp_socket) == PF_INET) ?
		    (void *)&inp->inp_laddr.s_addr :
		    (void *)&inp->in6p_laddr), dbg_state.ccd_srcaddr,
		    sizeof(dbg_state.ccd_srcaddr));
		dbg_state.ccd_srcport = ntohs(inp->inp_lport);
		inet_ntop(SOCK_DOM(inp->inp_socket),
		    ((SOCK_DOM(inp->inp_socket) == PF_INET) ?
		    (void *)&inp->inp_faddr.s_addr :
		    (void *)&inp->in6p_faddr), dbg_state.ccd_destaddr,
		    sizeof(dbg_state.ccd_destaddr));
		dbg_state.ccd_destport = ntohs(inp->inp_fport);

		dbg_state.ccd_snd_cwnd = tp->snd_cwnd;
		dbg_state.ccd_snd_wnd = tp->snd_wnd;
		dbg_state.ccd_snd_ssthresh = tp->snd_ssthresh;
		dbg_state.ccd_pipeack = tp->t_pipeack;
		dbg_state.ccd_rttcur = tp->t_rttcur;
		dbg_state.ccd_rxtcur = tp->t_rxtcur;
		dbg_state.ccd_srtt = tp->t_srtt >> TCP_RTT_SHIFT;
		dbg_state.ccd_event = event;
		dbg_state.ccd_sndcc = inp->inp_socket->so_snd.sb_cc;
		dbg_state.ccd_sndhiwat = inp->inp_socket->so_snd.sb_hiwat;
		dbg_state.ccd_bytes_acked = tp->t_bytes_acked;
		dbg_state.ccd_cc_index = tp->tcp_cc_index;
		switch (tp->tcp_cc_index) {
		case TCP_CC_ALGO_CUBIC_INDEX:
			dbg_state.u.cubic_state.ccd_last_max =
			    tp->t_ccstate->cub_last_max;
			dbg_state.u.cubic_state.ccd_tcp_win =
			    tp->t_ccstate->cub_tcp_win;
			dbg_state.u.cubic_state.ccd_avg_lastmax =
			    tp->t_ccstate->cub_avg_lastmax;
			dbg_state.u.cubic_state.ccd_mean_deviation =
			    tp->t_ccstate->cub_mean_dev;
			break;
		case TCP_CC_ALGO_BACKGROUND_INDEX:
			dbg_state.u.ledbat_state.led_base_rtt =
			    get_base_rtt(tp);
			break;
		default:
			break;
		}

		ctl_enqueuedata(tcp_ccdbg_ctlref, tcp_ccdbg_unit,
		    &dbg_state, sizeof(dbg_state), 0);
	}
	DTRACE_TCP5(cc, void, NULL, struct inpcb *, inp,
	    struct tcpcb *, tp, struct tcphdr *, th, int32_t, event);
}

void
tcp_ccdbg_control_register(void)
{
	struct kern_ctl_reg ccdbg_control;
	errno_t err;

	bzero(&ccdbg_control, sizeof(ccdbg_control));
	strlcpy(ccdbg_control.ctl_name, TCP_CC_CONTROL_NAME,
	    sizeof(ccdbg_control.ctl_name));
	ccdbg_control.ctl_connect = tcp_ccdbg_control_connect;
	ccdbg_control.ctl_disconnect = tcp_ccdbg_control_disconnect;
	ccdbg_control.ctl_flags |= CTL_FLAG_PRIVILEGED;
	ccdbg_control.ctl_flags |= CTL_FLAG_REG_SOCK_STREAM;
	ccdbg_control.ctl_sendsize = 32 * 1024;

	err = ctl_register(&ccdbg_control, &tcp_ccdbg_ctlref);
	if (err != 0) {
		log(LOG_ERR, "failed to register tcp_cc debug control");
	}
}
