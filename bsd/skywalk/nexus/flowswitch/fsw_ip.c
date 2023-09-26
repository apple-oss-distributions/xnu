/*
 * Copyright (c) 2016-2020 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>

sa_family_t fsw_ip_demux(struct nx_flowswitch *, struct __kern_packet *);

int
fsw_ip_setup(struct nx_flowswitch *fsw, struct ifnet *ifp)
{
#pragma unused(ifp)
	fsw->fsw_resolve = fsw_generic_resolve;
	fsw->fsw_demux = fsw_ip_demux;
	fsw->fsw_frame = NULL;
	fsw->fsw_frame_headroom = 0;
	return 0;
}

sa_family_t
fsw_ip_demux(struct nx_flowswitch *fsw, struct __kern_packet *pkt)
{
#pragma unused(fsw)
	const struct ip *iph;
	const struct ip6_hdr *ip6h;
	sa_family_t af = AF_UNSPEC;
	uint32_t bdlen, bdlim, bdoff;
	uint8_t *baddr;

	MD_BUFLET_ADDR_ABS_DLEN(pkt, baddr, bdlen, bdlim, bdoff);
	baddr += pkt->pkt_headroom;
	iph = (struct ip *)(void *)baddr;
	ip6h = (struct ip6_hdr *)(void *)baddr;

	if ((pkt->pkt_length >= sizeof(*iph)) &&
	    (pkt->pkt_headroom + sizeof(*iph)) <= bdlim &&
	    (iph->ip_v == IPVERSION)) {
		af = AF_INET;
	} else if ((pkt->pkt_length >= sizeof(*ip6h)) &&
	    (pkt->pkt_headroom + sizeof(*ip6h) <= bdlim) &&
	    ((ip6h->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION)) {
		af = AF_INET6;
	} else {
		SK_ERR("unrecognized pkt, hr %u len %u", pkt->pkt_headroom,
		    pkt->pkt_length);
	}

	pkt->pkt_l2_len = 0;

	return af;
}
