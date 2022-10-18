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

#ifndef _NETINET_TCP_SYSCTLS_H_
#define _NETINET_TCP_SYSCTLS_H_

#include <sys/types.h>

extern int tcp_cubic_tcp_friendliness;
extern int tcp_cubic_fast_convergence;
extern int tcp_cubic_use_minrtt;
extern int tcp_cubic_minor_fixes;
extern int tcp_cubic_rfc_compliant;

extern int target_qdelay;
extern int tcp_ledbat_allowed_increase;
extern int tcp_ledbat_tether_shift;
extern uint32_t bg_ss_fltsz;
extern int tcp_ledbat_plus_plus;

extern int tcp_rledbat;

extern int tcp_cc_debug;
extern int tcp_use_ledbat;
extern int tcp_use_newreno;

#endif /* _NETINET_TCP_SYSCTLS_H_ */
