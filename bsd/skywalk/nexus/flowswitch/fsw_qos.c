/*
 * Copyright (c) 2017-2019 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/flowswitch/fsw_var.h>

#include <netinet/in_tclass.h>

static inline uint16_t
fsw_qos_csum_fixup(uint16_t cksum, uint16_t old, uint16_t new)
{
	uint32_t l;

	l = cksum + old - new;
	l = (l >> 16) + (l & 0xffff);
	l = l & 0xffff;
	return (uint16_t)l;
}

static inline void
fsw_qos_set_ip_tos(struct ip *ip, uint8_t dscp)
{
	uint8_t old_tos;
	old_tos = ip->ip_tos;
	ip->ip_tos &= IPTOS_ECN_MASK;
	ip->ip_tos |= (u_char)(dscp << IPTOS_DSCP_SHIFT);
	ip->ip_sum = fsw_qos_csum_fixup(ip->ip_sum, htons(old_tos),
	    htons(ip->ip_tos));
}

static inline void
fsw_qos_set_ipv6_tc(struct ip6_hdr *ip6, uint8_t dscp)
{
	ip6->ip6_flow &= ~htonl(IP6FLOW_DSCP_MASK);
	ip6->ip6_flow |= htonl((u_int32_t)dscp << IP6FLOW_DSCP_SHIFT);
}

static inline void
fsw_qos_set_pkt_dscp(struct __kern_packet *pkt, uint8_t dscp)
{
	struct ip *ip;
	struct ip6_hdr *ip6;

	if (pkt->pkt_flow->flow_ip_ver == IPVERSION) {
		ip = (struct ip *)pkt->pkt_flow->flow_ip_hdr;
		fsw_qos_set_ip_tos(ip, dscp);
	} else {
		ASSERT(pkt->pkt_flow->flow_ip_ver == IPV6_VERSION);
		ip6 = (struct ip6_hdr *)pkt->pkt_flow->flow_ip_hdr;
		fsw_qos_set_ipv6_tc(ip6, dscp);
	}

	if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
		if (pkt->pkt_flow->flow_ip_ver == IPVERSION) {
			ip = (struct ip *)(void *)
			    (pkt->pkt_mbuf->m_data + pkt->pkt_l2_len);
			fsw_qos_set_ip_tos(ip, dscp);
		} else {
			ip6 = (struct ip6_hdr *)(void *)
			    (pkt->pkt_mbuf->m_data + pkt->pkt_l2_len);
			fsw_qos_set_ipv6_tc(ip6, dscp);
		}
	}
}

void
fsw_qos_mark(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct __kern_packet *pkt)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	uint8_t dscp = 0;

	ASSERT(KPKT_VALID_SVC(fe->fe_svc_class));

	/* if unspecified, use flow's default traffic class */
	if (__improbable(!KPKT_VALID_SVC(pkt->pkt_svc_class))) {
		pkt->pkt_svc_class = fe->fe_svc_class;
	}

	/* QoS marking not enabled */
	if ((ifp->if_eflags & IFEF_QOSMARKING_ENABLED) == 0 ||
	    ifp->if_qosmarking_mode == IFRTYPE_QOSMARKING_MODE_NONE) {
		SK_DF(SK_VERB_QOS, "%s: QoS Marking off", if_name(ifp));
		return;
	}

	/* QoS enabled, whitelisted app? */
	if ((fe->fe_flags & FLOWENTF_QOS_MARKING) == 0) {
		/* limit dscp and svc_class to BE/BK and DF */
		switch (pkt->pkt_svc_class) {
		case PKT_SC_BE:
		case PKT_SC_BK:
		case PKT_SC_BK_SYS:
		case PKT_SC_CTL:
			break;
		default:
			pkt->pkt_svc_class = PKT_SC_BE;
			break;
		}
		SK_DF(SK_VERB_QOS, "%s: restrict flow svc to BE", if_name(ifp));
	}

	switch (ifp->if_qosmarking_mode) {
	case IFRTYPE_QOSMARKING_FASTLANE:
		dscp = fastlane_sc_to_dscp(pkt->pkt_svc_class);
		break;
	case IFRTYPE_QOSMARKING_RFC4594:
		dscp = rfc4594_sc_to_dscp(pkt->pkt_svc_class);
		break;
#if (DEBUG || DEVELOPMENT)
	case IFRTYPE_QOSMARKING_CUSTOM:
		dscp = custom_sc_to_dscp(pkt->pkt_svc_class);
		break;
#endif /* (DEBUG || DEVELOPMENT) */
	default:
		panic("%s: QoS Marking mode invalid!", if_name(ifp));
		/* NOTREACHED */
		__builtin_unreachable();
	}

	SK_DF(SK_VERB_QOS, "%s: set dscp to %02d", if_name(ifp), dscp);
	fsw_qos_set_pkt_dscp(pkt, dscp);
}

boolean_t
fsw_qos_default_restricted()
{
	return !!net_qos_policy_restricted;
}
