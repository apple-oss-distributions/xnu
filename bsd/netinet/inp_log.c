/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <netinet/in_var.h>
#include <netinet/inp_log.h>

SYSCTL_NODE(_net_inet_ip, OID_AUTO, log, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "TCP/IP + UDP logs");

#if (DEVELOPMENT || DEBUG)
#define INP_LOG_PRIVACY_DEFAULT 0
#else
#define INP_LOG_PRIVACY_DEFAULT 1
#endif /* (DEVELOPMENT || DEBUG) */

int inp_log_privacy = INP_LOG_PRIVACY_DEFAULT;
SYSCTL_INT(_net_inet_ip_log, OID_AUTO, privacy,
    CTLFLAG_RW | CTLFLAG_LOCKED, &inp_log_privacy, 0, "");

void
inp_log_addresses(struct inpcb *inp, char *lbuf, socklen_t lbuflen, char *fbuf, socklen_t fbuflen)
{
	/*
	 * Ugly but %{private} does not work in the kernel version of os_log()
	 */
	if (inp_log_privacy != 0) {
		if (inp->inp_vflag & INP_IPV6) {
			strlcpy(lbuf, "<IPv6-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv6-redacted>", fbuflen);
		} else {
			strlcpy(lbuf, "<IPv4-redacted>", lbuflen);
			strlcpy(fbuf, "<IPv4-redacted>", fbuflen);
		}
	} else if (inp->inp_vflag & INP_IPV6) {
		struct in6_addr addr6;

		if (IN6_IS_ADDR_LINKLOCAL(&inp->in6p_laddr)) {
			addr6 = inp->in6p_laddr;
			addr6.s6_addr16[1] = 0;
			inet_ntop(AF_INET6, (void *)&addr6, lbuf, lbuflen);
		} else {
			inet_ntop(AF_INET6, (void *)&inp->in6p_laddr, lbuf, lbuflen);
		}

		if (IN6_IS_ADDR_LINKLOCAL(&inp->in6p_faddr)) {
			addr6 = inp->in6p_faddr;
			addr6.s6_addr16[1] = 0;
			inet_ntop(AF_INET6, (void *)&addr6, fbuf, fbuflen);
		} else {
			inet_ntop(AF_INET6, (void *)&inp->in6p_faddr, fbuf, fbuflen);
		}
	} else {
		inet_ntop(AF_INET, (void *)&inp->inp_laddr.s_addr, lbuf, lbuflen);
		inet_ntop(AF_INET, (void *)&inp->inp_faddr.s_addr, fbuf, fbuflen);
	}
}
