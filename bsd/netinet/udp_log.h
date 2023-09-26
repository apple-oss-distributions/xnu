/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _NETINET_UDP_LOG_H_
#define _NETINET_UDP_LOG_H_

extern uint32_t udp_log_enable_flags;
extern uint32_t udp_log_port;

#define UDP_ENABLE_FLAG_LIST \
	X(ULEF_BIND,            0x00000002, bind) \
	X(ULEF_CONNECTION,      0x00000001, connection) \
	X(ULEF_LOG,             0x00000008, log)        \
	X(ULEF_DST_LOOPBACK,    0x00000010, loop)       \
	X(ULEF_DST_LOCAL,       0x00000020, local)      \
	X(ULEF_DST_GW,          0x00000040, gw)         \
	X(ULEF_DROP_NECP,       0x00001000, dropnecp)   \
	X(ULEF_DROP_PCB,        0x00002000, droppcb)    \
	X(ULEF_DROP_PKT,        0x00004000, droppkt)

/*
 * Flag values for udp_log_enable_flags
 */
enum {
#define X(name, value, ...) name = value,
	UDP_ENABLE_FLAG_LIST
#undef X
};

#define ULEF_MASK_DST (ULEF_DST_LOOPBACK | ULEF_DST_LOCAL | ULEF_DST_GW)

extern void udp_log_bind(struct inpcb *inp, const char *event, int error);
extern void udp_log_connection(struct inpcb *inp, const char *event, int error);
extern void udp_log_connection_summary(struct inpcb *inp);

static inline bool
udp_is_log_enabled(struct inpcb *inp, uint32_t req_flags)
{
	if (inp == NULL) {
		return false;
	}
	/*
	 * First find out the kind of destination
	 */
	if (inp->inp_log_flags == 0) {
		if (inp->inp_vflag & INP_IPV6) {
			if (IN6_IS_ADDR_LOOPBACK(&inp->in6p_laddr) ||
			    IN6_IS_ADDR_LOOPBACK(&inp->in6p_faddr)) {
				inp->inp_log_flags |= ULEF_DST_LOOPBACK;
			}
		} else {
			if (ntohl(inp->inp_laddr.s_addr) == INADDR_LOOPBACK ||
			    ntohl(inp->inp_faddr.s_addr) == INADDR_LOOPBACK) {
				inp->inp_log_flags |= ULEF_DST_LOOPBACK;
			}
		}
		/* We only check for loopback */
		if (inp->inp_log_flags == 0) {
			inp->inp_log_flags |= ULEF_DST_LOCAL | ULEF_DST_GW;
		}
	}
	/*
	 * Check separately the destination flags that are per TCP connection
	 * and the other functional flags that are global
	 */
	return (inp->inp_log_flags & udp_log_enable_flags & ULEF_MASK_DST) &&
	       (udp_log_enable_flags & (req_flags & ~ULEF_MASK_DST));
}

#define UDP_LOG_BIND(inp, error) if (udp_is_log_enabled(inp, ULEF_BIND)) \
    udp_log_connection((inp), "bind", (error))

#define UDP_LOG_CONNECT(inp, error) if (udp_is_log_enabled(inp, ULEF_CONNECTION)) \
    udp_log_connection((inp), "connect", (error))

#define UDP_LOG_CONNECTION_SUMMARY(inp) if (udp_is_log_enabled(inp, ULEF_CONNECTION)) \
    udp_log_connection_summary((inp))


#endif /* _NETINET_UDP_LOG_H_ */
