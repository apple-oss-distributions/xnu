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
#ifndef _SKYWALK_NAMESPACE_FLOWIDNS_H_
#define _SKYWALK_NAMESPACE_FLOWIDNS_H_

/*
 * The flowidns (Flow ID namespace) module provides functionality to allocate
 * globally unique identifier for a flow.
 */

typedef uint32_t flowidns_flowid_t;

typedef enum {
	FLOWIDNS_DOMAIN_MIN = 0,
	FLOWIDNS_DOMAIN_IPSEC = FLOWIDNS_DOMAIN_MIN,
	FLOWIDNS_DOMAIN_FLOWSWITCH,
	FLOWIDNS_DOMAIN_INPCB,
	FLOWIDNS_DOMAIN_PF,
	FLOWIDNS_DOMAIN_MAX = FLOWIDNS_DOMAIN_PF
} flowidns_domain_id_t;

struct flowidns_flow_key {
	union {
		struct in_addr  _v4;
		struct in6_addr _v6;
	} ffk_laddr; /* local IP address */
	union {
		struct in_addr  _v4;
		struct in6_addr _v6;
	} ffk_raddr; /* remote IP address */
	union {
		struct {
			uint16_t _lport; /* local port */
			uint16_t _rport; /* remote port */
		} ffk_ports;
		uint32_t ffk_spi; /* IPSec ESP/AH SPI */
		uint32_t ffk_protoid; /* opaque protocol id */
	};
	uint8_t ffk_af; /* IP address family AF_INET* */
	uint8_t ffk_proto; /* IP protocol IP_PROTO_* */
};

#define ffk_laddr_v4    ffk_laddr._v4
#define ffk_laddr_v6    ffk_laddr._v6
#define ffk_raddr_v4    ffk_raddr._v4
#define ffk_raddr_v6    ffk_raddr._v6
#define ffk_lport       ffk_ports._lport
#define ffk_rport       ffk_ports._rport

extern int flowidns_init(void);
extern void flowidns_fini(void);

/*
 * Allocate a globally unique flow identifier.
 */
extern void flowidns_allocate_flowid(flowidns_domain_id_t domain,
    struct flowidns_flow_key *flow_key, flowidns_flowid_t *flowid);

/*
 * Release an allocated flow identifier.
 */
extern void flowidns_release_flowid(flowidns_flowid_t flowid);

#endif /* !_SKYWALK_NAMESPACE_FLOWIDNS_H_ */
