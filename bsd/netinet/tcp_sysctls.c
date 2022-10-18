/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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

#include <netinet/tcp_sysctls.h>
#include <netinet/tcp_var.h>

#include <sys/sysctl.h>

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_tcp_friendliness, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_cubic_tcp_friendliness, 0, "Enable TCP friendliness");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_fast_convergence, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_cubic_fast_convergence, 0, "Enable fast convergence");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_use_minrtt, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_cubic_use_minrtt, 0, "use a min of 5 sec rtt");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_minor_fixes, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_cubic_minor_fixes, 1, "Minor fixes to TCP Cubic");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, cubic_rfc_compliant, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_cubic_rfc_compliant, 1, "RFC Compliance for TCP Cubic");

/* Target queuing delay in milliseconds. This includes the processing
 * and scheduling delay on both of the end-hosts. A LEDBAT sender tries
 * to keep queuing delay below this limit. When the queuing delay
 * goes above this limit, a LEDBAT sender will start reducing the
 * congestion window.
 *
 * The LEDBAT draft says that target queue delay MUST be 100 ms for
 * inter-operability.
 * As we are enabling LEDBAT++ by default, we are updating the target
 * queuing delay to 60ms as recommended by the draft.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_target_qdelay, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, target_qdelay, 40, "Target queuing delay");

/* Allowed increase and tether are used to place an upper bound on
 * congestion window based on the amount of data that is outstanding.
 * This will limit the congestion window when the amount of data in
 * flight is little because the application is writing to the socket
 * intermittently and is preventing the connection from becoming idle .
 *
 * max_allowed_cwnd = allowed_increase + (tether * flight_size)
 * cwnd = min(cwnd, max_allowed_cwnd)
 *
 * 'Allowed_increase' parameter is set to 8. If the flight size is zero, then
 * we want the congestion window to be at least 8 packets to reduce the
 * delay induced by delayed ack. This helps when the receiver is acking
 * more than 2 packets at a time (stretching acks for better performance).
 *
 * 'Tether' is also set to 2. We do not want this to limit the growth of cwnd
 * during slow-start.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_allowed_increase, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_ledbat_allowed_increase, 8,
    "Additive constant used to calculate max allowed congestion window");

/* Left shift for cwnd to get tether value of 2 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_tether_shift, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_ledbat_tether_shift, 1, "Tether shift for max allowed congestion window");

/* Start with an initial window of 2. This will help to get more accurate
 * minimum RTT measurement in the beginning. It will help to probe
 * the path slowly and will not add to the existing delay if the path is
 * already congested. Using 2 packets will reduce the delay induced by delayed-ack.
 */
SYSCTL_SKMEM_TCP_INT(OID_AUTO, bg_ss_fltsz, CTLFLAG_RW | CTLFLAG_LOCKED,
    uint32_t, bg_ss_fltsz, 2, "Initial congestion window for background transport");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, ledbat_plus_plus, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_ledbat_plus_plus, 1, "Use LEDBAT++");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, rledbat, CTLFLAG_RW | CTLFLAG_LOCKED,
    int, tcp_rledbat, 1, "Use Receive LEDBAT");

int tcp_cc_debug;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, cc_debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &tcp_cc_debug, 0, "Enable debug data collection");

extern struct tcp_cc_algo tcp_cc_newreno;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, newreno_sockets,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_cc_newreno.num_sockets,
    0, "Number of sockets using newreno");

extern struct tcp_cc_algo tcp_cc_ledbat;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, background_sockets,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_cc_ledbat.num_sockets,
    0, "Number of sockets using background transport");

#if (DEVELOPMENT || DEBUG)
SYSCTL_SKMEM_TCP_INT(OID_AUTO, use_ledbat,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_use_ledbat, 0,
    "Use TCP LEDBAT for testing");
#else
SYSCTL_SKMEM_TCP_INT(OID_AUTO, use_ledbat,
    CTLFLAG_RD | CTLFLAG_LOCKED, int, tcp_use_ledbat, 0,
    "Use TCP LEDBAT for testing");
#endif /* (DEVELOPMENT || DEBUG) */

extern struct tcp_cc_algo tcp_cc_cubic;
SYSCTL_INT(_net_inet_tcp, OID_AUTO, cubic_sockets,
    CTLFLAG_RD | CTLFLAG_LOCKED, &tcp_cc_cubic.num_sockets,
    0, "Number of sockets using cubic");

SYSCTL_SKMEM_TCP_INT(OID_AUTO, use_newreno,
    CTLFLAG_RW | CTLFLAG_LOCKED, int, tcp_use_newreno, 0,
    "Use TCP NewReno by default");
