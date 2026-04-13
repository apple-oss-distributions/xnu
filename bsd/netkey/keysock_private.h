/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#ifndef _KEYSOCK_PRIVATE_H_
#define _KEYSOCK_PRIVATE_H_

#include <sys/socket.h>
#include <sys/socketvar.h>

struct xkeysockpcb {
	uint32_t        xkp_len;
	uint32_t        xkp_kind;
	uint64_t        xkp_gencnt;
	uint16_t        xkp_family;
	uint16_t        xkp_protocol;
	union {
		struct sockaddr         xkfu_addr;       /* destination address */
		char                    xkfu_dummy1[256];
	} xk_fu;
#define xkp_faddr xk_fu.xkfu_addr
	union {
		struct sockaddr         xklu_addr;       /* destination address */
		char                    xklu_dummy1[256];
	} xk_lu;
#define xkp_laddr xk_lu.xklu_addr
};
#define HAS_XKEYSOCKPCB 1

#endif /* _KEYSOCK_PRIVATE_H_ */
