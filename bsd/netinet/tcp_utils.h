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

#ifndef _NETINET_TCP_UTILS_H_
#define _NETINET_TCP_UTILS_H_

#include <netinet/tcp_var.h>

struct tcp_globals {};

static inline struct tcp_globals *
tcp_get_globals(struct tcpcb *tp)
{
#pragma unused(tp)
	return NULL;
}

static inline uint32_t
tcp_globals_now(struct tcp_globals *globals)
{
#pragma unused(globals)
	return tcp_now;
}

extern void tcp_ccdbg_control_register(void);
extern void tcp_ccdbg_trace(struct tcpcb *tp, struct tcphdr *th, int32_t event);

#endif /* _NETINET_TCP_UTILS_H_ */
