/*
 * Copyright (c) 2015-2017 Apple Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/random.h>

#include <skywalk/os_skywalk_private.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h> /* for ipport_firstauto and ipport_lastauto */

#include <skywalk/nexus/flowswitch/flow/flow_var.h>

/*
 * caller needs to do local addr resolution (e.g. hostos_sk_source_addr_select)
 * before calling this if a specific laddr is to be reserved. Otherwise it
 * would bind to ADDR_ANY.
 */
int
flow_namespace_create(union sockaddr_in_4_6 *laddr, uint8_t protocol,
    netns_token *token, boolean_t listener, struct ns_flow_info *nfi)
{
	sa_family_t af = laddr->sa.sa_family;
	uint32_t *addr;
	uint32_t netns_rsv_flags = NETNS_SKYWALK;
	uint8_t addr_len;
	int err;
	int so_type = 0;

	*token = NULL;

	if (__improbable(!netns_is_enabled())) {
		SK_ERR("netns is not enabled");
		return ENOTSUP;
	}

	if (listener) {
		netns_rsv_flags = NETNS_LISTENER;
	} else {
		netns_rsv_flags = NETNS_SKYWALK;
	}

	/* validate protocol */
	switch (protocol) {
	case IPPROTO_UDP:
		so_type = SOCK_DGRAM;
		break;

	case IPPROTO_TCP:
		so_type = SOCK_STREAM;
		break;

	default:
		SK_ERR("invalid protocol (%d)", protocol);
		return EINVAL;
	}

	/* set up addresses */
	switch (af) {
	case AF_INET:
		addr = (uint32_t *)&laddr->sin.sin_addr;
		addr_len = 4;
		break;

	case AF_INET6:
		addr = (uint32_t *)&laddr->sin6.sin6_addr;
		addr_len = 16;
		break;

	default:
		SK_ERR("invalid src address family (%d)", laddr->sa.sa_family);
		return EINVAL;
	}

	/* Assign an ephemeral port, if no port was specified */
	if (laddr->sin.sin_port == 0) {
		err = netns_reserve_ephemeral(token, addr, addr_len, protocol,
		    &laddr->sin.sin_port, netns_rsv_flags, nfi);
	} else {
		err = netns_reserve(token, addr, addr_len, protocol,
		    laddr->sin.sin_port, netns_rsv_flags, nfi);
	}

	SK_DF(SK_VERB_FLOW, "token (%s port %d) BIND",
	    (protocol == IPPROTO_TCP) ? "tcp" : "udp",
	    ntohs(laddr->sin.sin_port));

	return err;
}

void
flow_namespace_destroy(netns_token *token)
{
	netns_release(token);
}

void
flow_namespace_half_close(netns_token *token)
{
	if (NETNS_TOKEN_VALID(token)) {
		netns_half_close(token);
	}
}

void
flow_namespace_withdraw(netns_token *token)
{
	if (NETNS_TOKEN_VALID(token)) {
		netns_withdraw(token);
	}
}
