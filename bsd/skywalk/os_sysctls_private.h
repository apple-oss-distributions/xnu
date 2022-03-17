/*
 * Copyright (c) 2017-2018 Apple Inc. All rights reserved.
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

#ifndef _SKYWALK_OS_SYSCTLS_H_
#define _SKYWALK_OS_SYSCTLS_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
#include <stdint.h>

/*
 * X (type, field, default_value)
 *
 * Note: When defining X, be sure to use '...' such that adding fields will
 * not break building your project. See the use of SKMEM_SYSCTL_TCP_LIST
 * to define struct skmem_sysctl below for an example.
 */
#define SKMEM_SYSCTL_TCP_LIST                                           \
	X(int32_t, bg_target_qdelay, 40)                                \
	X(int32_t, bg_allowed_increase, 8)                              \
	X(int32_t, bg_tether_shift, 1)                                  \
	X(uint32_t, bg_ss_fltsz, 2)                                     \
	X(int32_t, use_newreno, 0)                                      \
	X(int32_t, cubic_tcp_friendliness, 0)                           \
	X(int32_t, cubic_fast_convergence, 0)                           \
	X(int32_t, cubic_use_minrtt, 0)                                 \
	X(int32_t, delayed_ack, 3)                                      \
	X(int32_t, recvbg, 0)                                           \
	X(int32_t, drop_synfin, 1)                                      \
	X(int32_t, slowlink_wsize, 8192)                                \
	X(int32_t, maxseg_unacked, 8)                                   \
	X(int32_t, rfc3465, 1)                                          \
	X(int32_t, rfc3465_lim2, 1)                                     \
	X(int32_t, recv_allowed_iaj, 5)                                 \
	X(uint32_t, doautorcvbuf, 1)                                    \
	X(uint32_t, autorcvbufmax, 2 * 1024 * 1024)                     \
	X(int32_t, rcvsspktcnt, 512)                                    \
	X(int32_t, path_mtu_discovery, 1)                               \
	X(int32_t, local_slowstart_flightsize, 8)                       \
	X(uint32_t, ecn_setup_percentage, 50)                           \
	X(int32_t, ecn_initiate_out, 0)                                 \
	X(int32_t, ecn_negotiate_in, 0)                                 \
	X(int32_t, packetchain, 50)                                     \
	X(int32_t, socket_unlocked_on_output, 1)                        \
	X(int32_t, min_iaj_win, 16)                                     \
	X(int32_t, acc_iaj_react_limit, 200)                            \
	X(uint32_t, autosndbufinc, 8 * 1024)                            \
	X(uint32_t, autosndbufmax, 2 * 1024 * 1024)                     \
	X(uint32_t, rtt_recvbg, 1)                                      \
	X(uint32_t, recv_throttle_minwin, 16 * 1024)                    \
	X(int32_t, enable_tlp, 1)                                       \
	X(int32_t, sack, 1)                                             \
	X(int32_t, sack_maxholes, 128)                                  \
	X(int32_t, sack_globalmaxholes, 65536)                          \
	X(int32_t, mssdflt, 512)                                        \
	X(int32_t, v6mssdflt, 1024)                                     \
	X(int32_t, fastopen_backlog, 10)                                \
	X(int32_t, fastopen, 0x3)                                       \
	X(int32_t, minmss, 216)                                         \
	X(int32_t, icmp_may_rst, 1)                                     \
	X(int32_t, rtt_min, 100)                                        \
	X(int32_t, rexmt_slop, 200)                                     \
	X(int32_t, randomize_ports, 0)                                  \
	X(int32_t, win_scale_factor, 3)                                 \
	X(int32_t, keepinit, 75 * 1000)                                 \
	X(int32_t, keepidle, 120 * 60 * 1000)                           \
	X(int32_t, keepintvl, 75 * 1000)                                \
	X(int32_t, keepcnt, 8)                                          \
	X(int32_t, msl, 15 * 1000)                                      \
	X(uint32_t, max_persist_timeout, 0)                             \
	X(int32_t, always_keepalive, 0)                                 \
	X(uint32_t, timer_fastmode_idlemax, 10)                         \
	X(int32_t, broken_peer_syn_rexmit_thres, 10)                    \
	X(int32_t, pmtud_blackhole_detection, 1)                        \
	X(uint32_t, pmtud_blackhole_mss, 1200)                          \
	X(int32_t, sendspace, 1448*256)                                 \
	X(int32_t, recvspace, 1448*384)                                 \
	X(uint32_t, microuptime_init, 0)                                \
	X(uint32_t, now_init, 0)                                        \
	X(uint32_t, challengeack_limit, 10)                             \
	X(int32_t, do_rfc5961, 1)                                       \
	X(int32_t, init_rtt_from_cache, 1)                              \
	X(uint32_t, autotunereorder, 1)                                 \
	X(uint32_t, do_ack_compression, 1)                              \
	X(uint32_t, ack_compression_rate, 5)                            \
	X(int32_t, do_better_lr, 1)                                     \
	X(int32_t, cubic_minor_fixes, 1)                                \
	X(int32_t, cubic_rfc_compliant, 1)                              \
	X(int32_t, aggressive_rcvwnd_inc, 1)                            \
	X(int32_t, ack_strategy, 1)                                     \
	X(int32_t, flow_control_response, 1)                            \
	X(int32_t, randomize_timestamps, 1)                             \
	X(uint32_t, ledbat_plus_plus, 1)                                \
	X(uint32_t, use_ledbat, 0)                                      \
	X(uint32_t, rledbat, 1)                                         \
	X(uint32_t, use_min_curr_rtt, 1)                                \
	X(uint32_t, fin_timeout, 30)

#define SKMEM_SYSCTL_KERN_IPC_LIST                                      \
	X(uint32_t, throttle_best_effort, 0)

#define SKMEM_SYSCTL_TCP_HAS_DEFAULT_VALUES 1
#define SKMEM_SYSCTL_TCP_HAS_INIT_TIME  1
#define SKMEM_SYSCTL_TCP_HAS_INIT_RTT_FROM_CACHE 1
#define SKMEM_SYSCTL_TCP_HAS_AUTOTUNEREORDER 1
#define SKMEM_SYSCTL_TCP_HAS_BETTER_LR 1
#define SKMEM_SYSCTL_HAS_KERN_IPC_THROTTLE_BEST_EFFORT 1
#define SKMEM_SYSCTL_TCP_HAS_AGGRESSIVE_RWND_INC 1
#define SKMEM_SYSCTL_TCP_HAS_ACK_STRATEGY 1
#define SKMEM_SYSCTL_TCP_HAS_FLOW_CONTROL_RESPONSE 1
#define SKMEM_SYSCTL_TCP_HAS_RANDOMIZED_TIMESTAMPS 1
#define SKMEM_SYSCTL_TCP_HAS_LEDBAT_PLUS_PLUS 1
#define SKMEM_SYSCTL_TCP_HAS_RLEDBAT 1
#define SKMEM_SYSCTL_TCP_HAS_FIN_TIMEOUT 1
/*
 * When adding a new type above, be sure to add a corresponding
 * printf format below. Clients use NW_SYSCTL_PRI_##type
 */
#define NW_SYSCTL_PRI_int32_t   PRIi32
#define NW_SYSCTL_PRI_uint32_t  PRIu32

#define SKMEM_SYSCTL_VERSION    3

typedef struct skmem_sysctl {
	uint32_t        version;
	struct {
#define X(type, field, ...)     type field;
		SKMEM_SYSCTL_TCP_LIST
#undef  X
	} tcp;
	struct {
		struct {
		#define X(type, field, ...)     type field;
			SKMEM_SYSCTL_KERN_IPC_LIST
		#undef  X
		} ipc;
	} kern;
} skmem_sysctl;

/*
 * Skywalk logical link information
 * Output: Array of struct nx_llink_info entry (per logical link).
 */
#define SK_LLINK_LIST_SYSCTL         "kern.skywalk.llink_list"

#ifdef KERNEL
/*
 * SYSCTL_SKMEM is infrastructure for keeping a shared memory region
 * in sync with a subset of syctl values in the networking stack.
 */
__BEGIN_DECLS
extern void skmem_sysctl_init(void);
extern void *skmem_get_sysctls_obj(size_t *);
extern int skmem_sysctl_handle_int(struct sysctl_oid *oidp, void *arg1,
    int arg2, struct sysctl_req *req);
__END_DECLS

#define SYSCTL_SKMEM_UPDATE_FIELD(field, value) do {                    \
	skmem_sysctl *swptr = skmem_get_sysctls_obj(NULL);              \
	if (swptr) {                                                    \
	        swptr->field = value;                                   \
	}                                                               \
} while (0)

/*
 * Danger - the void* cast below eliminates an alignment warning.
 * In this case it should be safe because offset should be an offset in to
 * the structure, so it should already be aligned. Nonetheless, there's
 * still a check above to ensure offset is aligned properly.
 */
#define SYSCTL_SKMEM_UPDATE_AT_OFFSET(offset, value) do {               \
	if (offset >= 0 &&                                              \
	    offset + sizeof (typeof(value)) <= sizeof (skmem_sysctl)) { \
	        skmem_sysctl *swptr = skmem_get_sysctls_obj(NULL);      \
	        void *offp = (u_int8_t *)swptr + offset;                \
	        if (swptr &&                                            \
	            ((uintptr_t)offp) % _Alignof(typeof(value)) == 0) { \
	                *(typeof(value)*)offp = (value);                \
	        }                                                       \
	}                                                               \
} while (0)

#define SYSCTL_SKMEM_INT(parent, oid, sysctl_name, access, ptr, offset, descr) \
	SYSCTL_OID(parent, oid, sysctl_name, CTLTYPE_INT|access,        \
	    ptr, offset, skmem_sysctl_handle_int, "I", descr);          \
	_Static_assert((__builtin_constant_p(ptr) ||                    \
	    sizeof (*(ptr)) == sizeof (int)), "invalid ptr");           \
	_Static_assert(offset % _Alignof(int) == 0, "invalid offset")

#define SYSCTL_SKMEM_TCP_INT(oid, sysctl_name, access, variable_type,   \
	    variable_name, initial_value, descr)                                \
	variable_type variable_name = initial_value;                    \
	SYSCTL_SKMEM_INT(_net_inet_tcp, oid, sysctl_name, access,       \
	    &variable_name, offsetof(skmem_sysctl, tcp.sysctl_name), descr)

#define SYSCTL_SKMEM_KERN_IPC_INT(oid, sysctl_name, access, variable_type,      \
	    variable_name, initial_value, descr)                                \
	variable_type variable_name = initial_value;                    \
	SYSCTL_SKMEM_INT(_kern_ipc, oid, sysctl_name, access,           \
	    &variable_name, offsetof(skmem_sysctl, kern.ipc.sysctl_name), descr)
#endif /* KERNEL */
#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_OS_SYSCTLS_H_ */
