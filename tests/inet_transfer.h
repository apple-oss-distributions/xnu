/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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
 * inet_transfer.h
 * - perform IPv4/IPv6 UDP/TCP transfer tests
 */

#ifndef _S_INET_TRANSFER_H
#define _S_INET_TRANSFER_H

#include <stdint.h>
#include <netinet/in.h>

static inline const char *
af_get_str(uint8_t af)
{
	return (af == AF_INET) ? "IPv4" : "IPv6";
}

static inline const char *
ipproto_get_str(uint8_t proto)
{
	const char * str;

	switch (proto) {
	case IPPROTO_UDP:
		str = "UDP";
		break;
	case IPPROTO_TCP:
		str = "TCP";
		break;
	default:
		str = "<?>";
		break;
	}
	return str;
}

typedef union {
	struct in_addr  v4;
	struct in6_addr v6;
} inet_address, *inet_address_t;

typedef struct {
	uint8_t         af;
	uint8_t         proto;
	uint16_t        port;
	inet_address    addr;
} inet_endpoint, *inet_endpoint_t;

bool
inet_transfer_local(inet_endpoint_t server_endpoint,
    int server_if_index,
    int client_if_index);

void
inet_test_traffic(uint8_t af, inet_address_t server,
    const char * server_ifname, int server_if_index,
    const char * client_ifname, int client_if_index);

const char *
inet_transfer_error_string(void);

#endif /* _S_INET_TRANSFER_H */
