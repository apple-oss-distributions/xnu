/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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
#include <skywalk/nexus/netif/nx_netif.h>
#include <sys/random.h>
#include <sys/sdt.h>
#include <net/sockaddr_utils.h>

#define NETIF_AGENT_FLOW_MAX            16

/* automatically register a netagent at constructor time */
static int nif_netagent = 1;

#if (DEVELOPMENT || DEBUG)
SYSCTL_INT(_kern_skywalk_netif, OID_AUTO, netagent,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nif_netagent, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

SK_NO_INLINE_ATTRIBUTE
static int
get_mac_addr(struct nx_netif *nif, struct ether_addr *addr)
{
	struct ifnet *ifp = nif->nif_ifp;
	struct ifaddr *lladdr;

	ASSERT(ifp != NULL);
	lladdr = ifp->if_lladdr;

	if (SDL(lladdr->ifa_addr)->sdl_alen == ETHER_ADDR_LEN &&
	    SDL(lladdr->ifa_addr)->sdl_type == IFT_ETHER) {
		ifnet_lladdr_copy_bytes(ifp, addr, ETHER_ADDR_LEN);
		return 0;
	}
	return ENOTSUP;
}

static uint64_t ipv6_ula_interface_id = 1;

/*
 * Generating an IPV6 ULA based on RFC4193
 */
SK_NO_INLINE_ATTRIBUTE
static void
get_ipv6_ula(struct in6_addr *addr)
{
	uint8_t buf[16];
	uint64_t interface_id;

	bzero(buf, sizeof(buf));

	/* Start with the 0xfc prefix with local bit set */
	buf[0] = 0xfd;

	/*
	 * RFC4193 describes a sample method to generate 40bit pseudo-random
	 * Global ID based on current time and EUI-64.
	 * Simplify it by just generating random bytes since after all the
	 * uniqueness matters, not the way it's achieved.
	 */
	read_frandom(&buf[1], 5);

	/* Hardcode subnet number to 0 */
	buf[6] = 0;
	buf[7] = 0;

	/* Use a monotonically increasing interface ID */
	interface_id = htonll(ipv6_ula_interface_id);
	bcopy(&interface_id, &buf[8], sizeof(uint64_t));
	do {
		ipv6_ula_interface_id++;
	} while (ipv6_ula_interface_id == 0);

	/* Return the generated address */
	_CASSERT(sizeof(buf) == sizeof(struct in6_addr));
	bcopy(buf, addr, sizeof(struct in6_addr));

#if SK_LOG
	char addrbuf[MAX_IPv6_STR_LEN];
	SK_DF(SK_VERB_NETIF, "generated IPv6 address: %s",
	    inet_ntop(AF_INET6, addr, addrbuf, sizeof(addrbuf)));
#endif /* SK_LOG */
}

SK_NO_INLINE_ATTRIBUTE
static void
get_ipv6_sockaddr(struct sockaddr_in6 *sin6)
{
	sin6->sin6_len = sizeof(struct sockaddr_in6);
	sin6->sin6_family = AF_INET6;
	get_ipv6_ula(&sin6->sin6_addr);
}

SK_NO_INLINE_ATTRIBUTE
static int
validate_ipv6_sockaddr(struct sockaddr_in6 *sin6)
{
	if (sin6->sin6_family != AF_INET6) {
		SK_ERR("invalid source family");
		return EINVAL;
	}
	if (sin6->sin6_len != sizeof(struct sockaddr_in6)) {
		SK_ERR("invalid source length");
		return EINVAL;
	}
	/*
	 * XXX
	 * We should use the stricter check IN6_IS_ADDR_UNIQUE_LOCAL().
	 * Leaving this as is for now because this gives us more
	 * flexibility on what addresses can be used for testing.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)) {
		SK_ERR("address unspecified");
		return EINVAL;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static boolean_t
flow_ipv6_ula_match(struct netif_agent_flow *naf, struct nx_flow_req *nfr)
{
	struct in6_addr *s1, *s2, *d1, *d2;

	if (naf->naf_pid != nfr->nfr_pid) {
		DTRACE_SKYWALK2(pid__mismatch, pid_t, naf->naf_pid,
		    pid_t, nfr->nfr_pid);
		return FALSE;
	}
	if ((naf->naf_flags & NXFLOWREQF_IPV6_ULA) == 0) {
		DTRACE_SKYWALK1(type__mismatch, uint16_t, naf->naf_flags);
		return FALSE;
	}
	s1 = &naf->naf_saddr.sin6.sin6_addr;
	s2 = &nfr->nfr_saddr.sin6.sin6_addr;
	if (!IN6_ARE_ADDR_EQUAL(s1, s2)) {
		DTRACE_SKYWALK2(saddr__mismatch, struct in6_addr *, s1,
		    struct in6_addr *, s2);
		return FALSE;
	}
	d1 = &naf->naf_daddr.sin6.sin6_addr;
	d2 = &nfr->nfr_daddr.sin6.sin6_addr;
	if (!IN6_ARE_ADDR_EQUAL(d1, d2)) {
		DTRACE_SKYWALK2(daddr__mismatch, struct in6_addr *, d1,
		    struct in6_addr *, d2);
		return FALSE;
	}
	return TRUE;
}

static uint16_t forbidden_ethertypes[] = {
	ETHERTYPE_IP,
	ETHERTYPE_ARP,
	ETHERTYPE_REVARP,
	ETHERTYPE_VLAN,
	ETHERTYPE_IPV6,
	ETHERTYPE_PAE,
	ETHERTYPE_RSN_PREAUTH,
};
#define FORBIDDEN_ETHERTYPES \
    (sizeof(forbidden_ethertypes) / sizeof(forbidden_ethertypes[0]))

SK_NO_INLINE_ATTRIBUTE
static int
validate_ethertype(uint16_t ethertype)
{
	uint32_t i;

	for (i = 0; i < FORBIDDEN_ETHERTYPES; i++) {
		if (forbidden_ethertypes[i] == ethertype) {
			SK_ERR("ethertype 0x%x not allowed", ethertype);
			return EINVAL;
		}
	}
	if (ethertype <= ETHERMTU) {
		SK_ERR("ethertype <= ETHERMTU");
		return EINVAL;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_fill_port_info(struct nx_netif *nif, struct nx_flow_req *nfr,
    struct netif_port_info **npip)
{
#pragma unused(nif)
	struct netif_flow_desc *fd;
	struct netif_port_info *npi;
	struct netif_stats *nifs = &nif->nif_stats;
	uint32_t stat;
	int err;

	if ((nfr->nfr_flags & (NXFLOWREQF_CUSTOM_ETHER |
	    NXFLOWREQF_IPV6_ULA)) == 0) {
		return 0;
	}
	npi = sk_alloc_data(sizeof(*npi), Z_WAITOK | Z_NOFAIL,
	    skmem_tag_nx_port_info);
	npi->npi_hdr.ih_type = NX_PORT_INFO_TYPE_NETIF;
	npi->npi_hdr.ih_size = sizeof(*npi);

	fd = &npi->npi_fd;
	if ((nfr->nfr_flags & NXFLOWREQF_CUSTOM_ETHER) != 0) {
		if ((err = validate_ethertype(nfr->nfr_ethertype)) != 0) {
			stat = NETIF_STATS_AGENT_BAD_ETHERTYPE;
			goto fail;
		}
		fd->fd_ethertype = nfr->nfr_ethertype;
	}
	if ((nfr->nfr_flags & NXFLOWREQF_IPV6_ULA) != 0) {
		struct sockaddr_in6 *sin6;

		sin6 = &nfr->nfr_saddr.sin6;
		if ((err = validate_ipv6_sockaddr(sin6)) != 0) {
			stat = NETIF_STATS_AGENT_BAD_IPV6_ADDR;
			goto fail;
		}
		fd->fd_laddr = sin6->sin6_addr;

		sin6 = &nfr->nfr_daddr.sin6;
		if ((err = validate_ipv6_sockaddr(sin6)) != 0) {
			stat = NETIF_STATS_AGENT_BAD_IPV6_ADDR;
			goto fail;
		}
		fd->fd_raddr = sin6->sin6_addr;
	}
	*npip = npi;
	return 0;
fail:
	STATS_INC(nifs, stat);
	if (npi != NULL) {
		sk_free_data(npi, sizeof(*npi));
	}
	return err;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_flow_bind(struct nx_netif *nif, struct nx_flow_req *nfr)
{
	uuid_t uuid_key;
	nexus_port_t nx_port;
	struct nxbind nxb;
	struct proc *p;
	struct kern_nexus *nx = nif->nif_nx;
	struct netif_port_info *npi = NULL;
	pid_t pid = nfr->nfr_pid;
	int err;
#if SK_LOG
	uuid_string_t uuidstr;
#endif /* SK_LOG */

	if ((nfr->nfr_flags & NXFLOWREQF_LISTENER) != 0) {
		return ENOTSUP;
	}
	p = proc_find(pid);
	if (p == PROC_NULL) {
		SK_ERR("process for pid %d doesn't exist", pid);
		return EINVAL;
	}
	nfr->nfr_proc = p;
	uuid_generate_random(uuid_key);
	bzero(&nxb, sizeof(nxb));
	nxb.nxb_flags |= NXBF_MATCH_UNIQUEID;
	nxb.nxb_uniqueid = proc_uniqueid(p);
	nxb.nxb_pid = pid;
	nxb.nxb_flags |= NXBF_MATCH_KEY;
	nxb.nxb_key_len = sizeof(uuid_key);
	nxb.nxb_key = sk_alloc_data(nxb.nxb_key_len, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_nx_key);
	bcopy(uuid_key, nxb.nxb_key, nxb.nxb_key_len);

	err = nx_netif_netagent_fill_port_info(nif, nfr, &npi);
	if (err != 0) {
		sk_free_data(nxb.nxb_key, nxb.nxb_key_len);
		nfr->nfr_proc = NULL;
		proc_rele(p);
		return err;
	}
	/*
	 * callee holds on to nxb_key on success. no need to free.
	 */
	nx_port = NEXUS_PORT_ANY;
	err = NX_DOM(nx)->nxdom_bind_port(nx, &nx_port, &nxb, npi);
	if (err != 0) {
		sk_free_data(nxb.nxb_key, nxb.nxb_key_len);
		if (npi != NULL) {
			sk_free_data(npi, sizeof(*npi));
		}
		nfr->nfr_proc = NULL;
		proc_rele(p);
		SK_ERR("%s(%d) failed to bind flow_uuid %s to a "
		    "nx_port (err %d)", sk_proc_name_address(p),
		    pid, sk_uuid_unparse(nfr->nfr_flow_uuid,
		    uuidstr), err);
		return err;
	}
	bcopy(uuid_key, nfr->nfr_bind_key, sizeof(uuid_key));
	nfr->nfr_nx_port = nx_port;
	nfr->nfr_proc = NULL;
	proc_rele(p);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_flow_unbind(struct nx_netif *nif, struct nx_flow_req *nfr)
{
	int err;
	struct kern_nexus *nx = nif->nif_nx;

	if ((nfr->nfr_flags & NXFLOWREQF_LISTENER) != 0) {
		return ENOTSUP;
	}
	err = NX_DOM(nx)->nxdom_unbind_port(nif->nif_nx, nfr->nfr_nx_port);
	if (err != 0) {
		SK_ERR("nxdom_unbind_port failed: %d", err);
		return err;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_check_flags(struct nx_netif *nif, struct nx_flow_req *nfr,
    boolean_t add)
{
	uint16_t flags = nfr->nfr_flags;

	if ((nif->nif_agent_flags & NETIF_AGENT_FLAG_ADDED) == 0) {
		SK_ERR("no agent added");
		return ENOTSUP;
	}
	if ((flags & NXFLOWREQF_FILTER) != 0) {
		if ((flags & ~NXFLOWREQF_FILTER) != 0) {
			SK_ERR("filter: incompatible with other features");
			return EINVAL;
		}
		if ((nif->nif_filter_flags &
		    NETIF_FILTER_FLAG_INITIALIZED) == 0) {
			SK_ERR("filter: uninitialized");
			return ENOTSUP;
		}
	}
	if ((flags & NXFLOWREQF_CUSTOM_ETHER) != 0) {
		if ((flags & ~NXFLOWREQF_CUSTOM_ETHER) != 0) {
			SK_ERR("custom ether: incompatible "
			    "with other features");
			return EINVAL;
		}
		if ((nif->nif_flow_flags &
		    NETIF_FLOW_FLAG_INITIALIZED) == 0) {
			SK_ERR("custom ether: uninitialized");
			return ENOTSUP;
		}
	}
	if ((flags & NXFLOWREQF_IPV6_ULA) != 0) {
		if ((flags & ~(NXFLOWREQF_IPV6_ULA | NXFLOWREQF_LISTENER)) != 0) {
			SK_ERR("IPv6 ULA: incompatible with other features");
			return EINVAL;
		}
		if (!NETIF_IS_LOW_LATENCY(nif)) {
			SK_ERR("IPv6 ULA: not supported on this nexus");
			return ENOTSUP;
		}
	}
	if (add && (flags & (NXFLOWREQF_FILTER | NXFLOWREQF_CUSTOM_ETHER |
	    NXFLOWREQF_IPV6_ULA)) == 0) {
		SK_ERR("flow type must be specified");
		return EINVAL;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_listener_flow_add(struct nx_netif *nif,
    struct nx_flow_req *nfr)
{
	int err;

	if ((nfr->nfr_flags & NXFLOWREQF_IPV6_ULA) == 0) {
		SK_ERR("listener flow not suppported");
		return ENOTSUP;
	}
	err = get_mac_addr(nif, &nfr->nfr_etheraddr);
	if (err != 0) {
		SK_ERR("get mac addr failed; %d", err);
		return err;
	}
	get_ipv6_sockaddr(&nfr->nfr_saddr.sin6);
	return 0;
}

/*
 * This is for handling the case where the same flow (same ipv6
 * local_addr:remote_addr tuple) is added twice. Instead of failing the
 * second flow add, we would return the existing flow's nexus port. This
 * would allow libnetcore to reuse the existing channel instead of opening
 * a new one. Note that sidecar is not affected by this because it always
 * adds flows with unique addresses.
 */
SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_flow_find(struct nx_netif *nif,
    struct nx_flow_req *nfr)
{
	struct netif_agent_flow *naf;

	/* Only support llw flows */
	if ((nfr->nfr_flags & NXFLOWREQF_IPV6_ULA) == 0) {
		return ENOTSUP;
	}
	lck_mtx_lock(&nif->nif_agent_lock);
	SLIST_FOREACH(naf, &nif->nif_agent_flow_list, naf_link) {
		if (flow_ipv6_ula_match(naf, nfr)) {
			break;
		}
	}
	if (naf == NULL) {
		DTRACE_SKYWALK2(dupflow__not__found, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr);
		lck_mtx_unlock(&nif->nif_agent_lock);
		return ENOENT;
	}
	nfr->nfr_nx_port = naf->naf_nx_port;
	uuid_copy(nfr->nfr_bind_key, naf->naf_bind_key);
	lck_mtx_unlock(&nif->nif_agent_lock);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_netif_netagent_fill_flow_info(struct netif_agent_flow *naf,
    struct nx_flow_req *nfr)
{
	uuid_copy(naf->naf_flow_uuid, nfr->nfr_flow_uuid);
	uuid_copy(naf->naf_bind_key, nfr->nfr_bind_key);
	naf->naf_nx_port = nfr->nfr_nx_port;
	naf->naf_flags = nfr->nfr_flags;
	naf->naf_pid = nfr->nfr_pid;

	/* We only keep flow info for llw flows */
	if ((naf->naf_flags & NXFLOWREQF_IPV6_ULA) != 0) {
		naf->naf_saddr = nfr->nfr_saddr;
		naf->naf_daddr = nfr->nfr_daddr;
	}
}

int
nx_netif_netagent_flow_add(struct nx_netif *nif, struct nx_flow_req *nfr)
{
	int err;
	struct netif_agent_flow *naf;
	struct netif_stats *nifs = &nif->nif_stats;

	err = nx_netif_netagent_check_flags(nif, nfr, TRUE);
	if (err != 0) {
		SK_ERR("flow request inconsistent with current config");
		DTRACE_SKYWALK3(invalid__flags, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr, int, err);
		return err;
	}
	err = nx_netif_netagent_flow_find(nif, nfr);
	if (err == 0) {
		SK_ERR("found existing flow: nx_port = %d", nfr->nfr_nx_port);
		DTRACE_SKYWALK2(found__flow, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr);
		STATS_INC(nifs, NETIF_STATS_AGENT_DUP_FLOW);
		return 0;
	}
	if ((nfr->nfr_flags & NXFLOWREQF_LISTENER) != 0) {
		return nx_netif_netagent_listener_flow_add(nif, nfr);
	}
	naf = sk_alloc_type(struct netif_agent_flow, Z_WAITOK | Z_NOFAIL,
	    skmem_tag_netif_agent_flow);

	if ((nfr->nfr_flags &
	    (NXFLOWREQF_CUSTOM_ETHER | NXFLOWREQF_IPV6_ULA)) != 0) {
		err = get_mac_addr(nif, &nfr->nfr_etheraddr);
		if (err != 0) {
			SK_ERR("get mac addr failed: %d", err);
			sk_free_type(struct netif_agent_flow, naf);
			return err;
		}
	}
	lck_mtx_lock(&nif->nif_agent_lock);
	err = nx_netif_netagent_flow_bind(nif, nfr);
	if (err != 0) {
		SK_ERR("netagent flow bind failed: %d", err);
		DTRACE_SKYWALK3(bind__failed, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr, int, err);
		sk_free_type(struct netif_agent_flow, naf);
		lck_mtx_unlock(&nif->nif_agent_lock);
		return err;
	}
	nx_netif_netagent_fill_flow_info(naf, nfr);
	SLIST_INSERT_HEAD(&nif->nif_agent_flow_list, naf, naf_link);
	nif->nif_agent_flow_cnt++;

#if SK_LOG
	uuid_string_t uuidstr;

	SK_DF(SK_VERB_NETIF, "flow uuid: %s",
	    sk_uuid_unparse(naf->naf_flow_uuid, uuidstr));
	SK_DF(SK_VERB_NETIF, "nx port: %d", naf->naf_nx_port);
	SK_DF(SK_VERB_NETIF, "nx key: %s",
	    sk_uuid_unparse(nfr->nfr_bind_key, uuidstr));

	if ((nfr->nfr_flags & NXFLOWREQF_FILTER) != 0) {
		SK_DF(SK_VERB_NETIF, "flow type: filter");
	}
	if ((nfr->nfr_flags & NXFLOWREQF_CUSTOM_ETHER) != 0) {
		SK_DF(SK_VERB_NETIF, "flow type: custom ether");
		SK_DF(SK_VERB_NETIF, "ethertype: 0x%x", nfr->nfr_ethertype);
	}
	if ((nfr->nfr_flags & NXFLOWREQF_IPV6_ULA) != 0) {
		char local[MAX_IPv6_STR_LEN];
		char remote[MAX_IPv6_STR_LEN];

		SK_DF(SK_VERB_NETIF, "flow type: IPv6 ULA");
		SK_DF(SK_VERB_NETIF, "IPv6 local: %s",
		    inet_ntop(AF_INET6, &nfr->nfr_saddr.sin6.sin6_addr,
		    local, sizeof(local)));
		SK_DF(SK_VERB_NETIF, "IPv6 remote: %s",
		    inet_ntop(AF_INET6, &nfr->nfr_daddr.sin6.sin6_addr,
		    remote, sizeof(remote)));
	}
#endif /* SK_LOG */
	lck_mtx_unlock(&nif->nif_agent_lock);
	return 0;
}

int
nx_netif_netagent_flow_del(struct nx_netif *nif, struct nx_flow_req *nfr)
{
	int err;
	struct netif_agent_flow *naf = NULL;

	err = nx_netif_netagent_check_flags(nif, nfr, FALSE);
	if (err != 0) {
		SK_ERR("flow request inconsistent with current config");
		DTRACE_SKYWALK3(invalid__flags, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr, int, err);
		return err;
	}

	/* no-op for listener */
	if ((nfr->nfr_flags & NXFLOWREQF_LISTENER) != 0) {
		DTRACE_SKYWALK2(listener, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr);
		return 0;
	}
	lck_mtx_lock(&nif->nif_agent_lock);
	SLIST_FOREACH(naf, &nif->nif_agent_flow_list, naf_link) {
		if (uuid_compare(naf->naf_flow_uuid, nfr->nfr_flow_uuid) == 0) {
			break;
		}
	}
	if (naf == NULL) {
		SK_ERR("netagent flow not found");
		DTRACE_SKYWALK2(flow__not__found, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr);
		lck_mtx_unlock(&nif->nif_agent_lock);
		return ENOENT;
	}
	/* use the port from the agent flow, not the request */
	nfr->nfr_nx_port = naf->naf_nx_port;

	err = nx_netif_netagent_flow_unbind(nif, nfr);
	if (err != 0) {
		SK_ERR("netagent flow unbind failed: %d", err);
		DTRACE_SKYWALK3(unbind__failed, struct nx_netif *, nif,
		    struct nx_flow_req *, nfr, int, err);
		/*
		 * The channel auto closed the port. We can just
		 * clean up our agent flow.
		 */
	}
	SLIST_REMOVE(&nif->nif_agent_flow_list, naf, netif_agent_flow,
	    naf_link);
	sk_free_type(struct netif_agent_flow, naf);
	nif->nif_agent_flow_cnt--;
	lck_mtx_unlock(&nif->nif_agent_lock);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_agent_flow_purge(struct nx_netif *nif)
{
	struct netif_agent_flow *naf, *naf_tmp;
	uint32_t cnt = 0;

	lck_mtx_lock(&nif->nif_agent_lock);
	SLIST_FOREACH_SAFE(naf, &nif->nif_agent_flow_list, naf_link, naf_tmp) {
		SLIST_REMOVE(&nif->nif_agent_flow_list, naf, netif_agent_flow,
		    naf_link);
		/*
		 * Since this gets called during detach, all ports will be
		 * unbound and freed by the nexus cleanup path. Nothing to
		 * do here.
		 */
		sk_free_type(struct netif_agent_flow, naf);
		cnt++;
	}
	SK_DF(SK_VERB_NETIF, "agent flows purged: %d", cnt);
	DTRACE_SKYWALK2(agent__flows__purge, struct nx_netif *, nif,
	    uint32_t, cnt);
	ASSERT(nif->nif_agent_flow_cnt == cnt);
	nif->nif_agent_flow_cnt = 0;
	lck_mtx_unlock(&nif->nif_agent_lock);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_handle_interpose_flow_add(struct nx_netif *nif,
    uuid_t flow_uuid, pid_t pid, struct necp_client_nexus_parameters *cparams,
    void **results, size_t *results_length)
{
#pragma unused(cparams)
	int err;
	struct nx_flow_req nfr;
	void *message;
	size_t len;

	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_pid = pid;
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_flags |= NXFLOWREQF_FILTER;

	err = nx_netif_netagent_flow_add(nif, &nfr);
	if (err != 0) {
		return err;
	}
	message =
	    necp_create_nexus_assign_message(nif->nif_nx->nx_uuid,
	    nfr.nfr_nx_port, nfr.nfr_bind_key, sizeof(nfr.nfr_bind_key),
	    NULL, NULL, NULL, 0, NULL, &len);
	if (message == NULL) {
		(void) nx_netif_netagent_flow_del(nif, &nfr);
		return ENOMEM;
	}
	*results = message;
	*results_length = len;
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_handle_custom_ether_flow_add(struct nx_netif *nif,
    uuid_t flow_uuid, pid_t pid, struct necp_client_nexus_parameters *cparams,
    void **results, size_t *results_length)
{
	int err;
	struct nx_flow_req nfr;
	void *message;
	size_t len;

	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_pid = pid;
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_ethertype = cparams->ethertype;
	nfr.nfr_flags |= NXFLOWREQF_CUSTOM_ETHER;

	err = nx_netif_netagent_flow_add(nif, &nfr);
	if (err != 0) {
		return err;
	}
	message =
	    necp_create_nexus_assign_message(nif->nif_nx->nx_uuid,
	    nfr.nfr_nx_port, nfr.nfr_bind_key, sizeof(nfr.nfr_bind_key),
	    NULL, NULL, &nfr.nfr_etheraddr, 0, NULL, &len);
	if (message == NULL) {
		(void) nx_netif_netagent_flow_del(nif, &nfr);
		return ENOMEM;
	}
	*results = message;
	*results_length = len;
	return 0;
}

#define IS_V6_ADDR(addr) \
    ((addr)->sin6.sin6_family == AF_INET6)

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_handle_ipv6_ula_flow_add(struct nx_netif *nif,
    uuid_t flow_uuid, pid_t pid, struct necp_client_nexus_parameters *cparams,
    void **results, size_t *results_length)
{
	int err;
	struct nx_flow_req nfr;
	struct necp_client_endpoint local_endpoint;
	struct necp_client_endpoint remote_endpoint;
	void *message;
	size_t len;

	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_pid = pid;
	nfr.nfr_nx_port = NEXUS_PORT_ANY;
	nfr.nfr_flags |= NXFLOWREQF_IPV6_ULA;
	if (cparams->is_listener) {
		/*
		 * Preserve input args if possible
		 */
		if (IS_V6_ADDR(&cparams->local_addr)) {
			bcopy(&cparams->local_addr,
			    &nfr.nfr_saddr, sizeof(nfr.nfr_saddr));
		}
		if (IS_V6_ADDR(&cparams->remote_addr)) {
			bcopy(&cparams->remote_addr,
			    &nfr.nfr_daddr, sizeof(nfr.nfr_daddr));
		}
		nfr.nfr_flags |= NXFLOWREQF_LISTENER;
	} else {
		/*
		 * Both local and remote addresses must be specified.
		 */
		if (!IS_V6_ADDR(&cparams->local_addr)) {
			SK_ERR("local addr missing");
			return EINVAL;
		}
		bcopy(&cparams->local_addr,
		    &nfr.nfr_saddr, sizeof(nfr.nfr_saddr));

		if (!IS_V6_ADDR(&cparams->remote_addr)) {
			SK_ERR("remote addr missing");
			return EINVAL;
		}
		bcopy(&cparams->remote_addr,
		    &nfr.nfr_daddr, sizeof(nfr.nfr_daddr));
	}
	err = nx_netif_netagent_flow_add(nif, &nfr);
	if (err != 0) {
		return err;
	}
	bzero(&local_endpoint, sizeof(local_endpoint));
	SOCKADDR_COPY(&nfr.nfr_saddr.sin6, &local_endpoint.u.sin6,
	    sizeof(local_endpoint.u.sin6));

	if (cparams->is_listener) {
		uuid_t zero_nx_uuid;

		bzero(zero_nx_uuid, sizeof(uuid_t));
		message = necp_create_nexus_assign_message(
			zero_nx_uuid, NEXUS_PORT_ANY, NULL,
			0, &local_endpoint, NULL,
			&nfr.nfr_etheraddr, 0, NULL, &len);
	} else {
		bzero(&remote_endpoint, sizeof(remote_endpoint));
		SOCKADDR_COPY(&nfr.nfr_daddr.sin6, &remote_endpoint.u.sin6,
		    sizeof(remote_endpoint.u.sin6));

		message = necp_create_nexus_assign_message(
			nif->nif_nx->nx_uuid, nfr.nfr_nx_port, nfr.nfr_bind_key,
			sizeof(nfr.nfr_bind_key), &local_endpoint,
			&remote_endpoint, &nfr.nfr_etheraddr, 0, NULL, &len);
	}
	if (message == NULL) {
		/* This is a no-op for the listener flow */
		(void) nx_netif_netagent_flow_del(nif, &nfr);
		return ENOMEM;
	}
	*results = message;
	*results_length = len;
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_handle_flow_add(struct nx_netif *nif,
    uuid_t flow_uuid, pid_t pid, struct necp_client_nexus_parameters *cparams,
    void **results, size_t *results_length)
{
	int err = 0;

	ASSERT(cparams != NULL);
	ASSERT(results != NULL && *results == NULL);
	ASSERT(results_length != NULL && *results_length == 0);

	if (cparams->is_interpose) {
		err = nx_netif_netagent_handle_interpose_flow_add(nif,
		    flow_uuid, pid, cparams, results, results_length);
	} else if (cparams->is_custom_ether) {
		err = nx_netif_netagent_handle_custom_ether_flow_add(nif,
		    flow_uuid, pid, cparams, results, results_length);
	} else if (NETIF_IS_LOW_LATENCY(nif)) {
		err = nx_netif_netagent_handle_ipv6_ula_flow_add(nif,
		    flow_uuid, pid, cparams, results, results_length);
	}
	if (err != 0) {
		ASSERT(*results == NULL);
		ASSERT(*results_length == 0);
		return err;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
nx_netif_netagent_handle_flow_del(struct nx_netif *nif,
    uuid_t flow_uuid, pid_t pid, boolean_t abort)
{
#pragma unused(abort)
	struct nx_flow_req nfr;

	bzero(&nfr, sizeof(nfr));
	uuid_copy(nfr.nfr_flow_uuid, flow_uuid);
	nfr.nfr_pid = pid;
	return nx_netif_netagent_flow_del(nif, &nfr);
}

static int
nx_netif_netagent_event(u_int8_t event, uuid_t flow_uuid, pid_t pid,
    void *context, void *ctx, struct necp_client_agent_parameters *cparams,
    void **results, size_t *results_length)
{
#pragma unused(context)
	struct nx_netif *nif;
	int err = 0;

	nif = (struct nx_netif *)ctx;
	ASSERT(nif != NULL);

	switch (event) {
	case NETAGENT_EVENT_NEXUS_FLOW_INSERT:
		/* these are required for this event */
		ASSERT(cparams != NULL);
		ASSERT(results != NULL);
		ASSERT(results_length != NULL);
		*results = NULL;
		*results_length = 0;
		err = nx_netif_netagent_handle_flow_add(nif, flow_uuid, pid,
		    &cparams->u.nexus_request, results, results_length);
		break;

	case NETAGENT_EVENT_NEXUS_FLOW_REMOVE:
	case NETAGENT_EVENT_NEXUS_FLOW_ABORT:
		err = nx_netif_netagent_handle_flow_del(nif, flow_uuid, pid,
		    (event == NETAGENT_EVENT_NEXUS_FLOW_REMOVE));
		break;

	default:
		/* events not handled */
		return 0;
	}

	return err;
}

static int
nx_netif_agent_register(struct nx_netif *nif, uint32_t features)
{
	struct netagent_nexus_agent agent;
	int err = 0;

	_CASSERT(FLOWADV_IDX_NONE == UINT32_MAX);
	_CASSERT(NECP_FLOWADV_IDX_INVALID == FLOWADV_IDX_NONE);

	if (!nif_netagent) {
		return ENOTSUP;
	}
	nif->nif_agent_session = netagent_create(&nx_netif_netagent_event, nif);
	if (nif->nif_agent_session == NULL) {
		return ENOMEM;
	}

	bzero(&agent, sizeof(agent));
	uuid_generate_random(agent.agent.netagent_uuid);
	uuid_copy(nif->nif_agent_uuid, agent.agent.netagent_uuid);
	(void) snprintf(agent.agent.netagent_domain,
	    sizeof(agent.agent.netagent_domain), "%s", "Skywalk");
	(void) snprintf(agent.agent.netagent_type,
	    sizeof(agent.agent.netagent_type), "%s", "NetIf");
	(void) snprintf(agent.agent.netagent_desc,
	    sizeof(agent.agent.netagent_desc), "%s", "Userspace Networking");

	agent.agent.netagent_flags =
	    (NETAGENT_FLAG_ACTIVE | NETAGENT_FLAG_NEXUS_LISTENER | features);

	agent.agent.netagent_data_size = sizeof(struct netagent_nexus);
	agent.nexus_data.frame_type = NETAGENT_NEXUS_FRAME_TYPE_LINK;
	agent.nexus_data.endpoint_assignment_type =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_ADDRESS;
	agent.nexus_data.endpoint_request_types[0] =
	    NETAGENT_NEXUS_ENDPOINT_TYPE_ADDRESS;
	agent.nexus_data.nexus_flags |=
	    (NETAGENT_NEXUS_FLAG_ASSERT_UNSUPPORTED |
	    NETAGENT_NEXUS_FLAG_SUPPORTS_USER_PACKET_POOL);
	if (NETIF_IS_LOW_LATENCY(nif)) {
		agent.nexus_data.nexus_flags |=
		    NETAGENT_NEXUS_FLAG_SHOULD_USE_EVENT_RING;
	}

	if ((err = netagent_register(nif->nif_agent_session,
	    (struct netagent *)&agent)) != 0) {
		netagent_destroy(nif->nif_agent_session);
		nif->nif_agent_session = NULL;
		uuid_clear(nif->nif_agent_uuid);
	}
	nif->nif_agent_flags |= NETIF_AGENT_FLAG_REGISTERED;
	return err;
}

static void
nx_netif_agent_unregister(struct nx_netif *nif)
{
	if ((nif->nif_agent_flags & NETIF_AGENT_FLAG_REGISTERED) == 0) {
		return;
	}
	nif->nif_agent_flags &= ~NETIF_AGENT_FLAG_REGISTERED;

	ASSERT(nif->nif_agent_session != NULL);
	netagent_destroy(nif->nif_agent_session);
	nif->nif_agent_session = NULL;
	uuid_clear(nif->nif_agent_uuid);
}

static uint32_t
nx_netif_agent_get_features(struct nx_netif *nif)
{
	uint32_t features = 0;

	if ((nif->nif_filter_flags & NETIF_FILTER_FLAG_INITIALIZED) != 0) {
		features |= (NETAGENT_FLAG_INTERPOSE_NEXUS |
		    NETAGENT_FLAG_NETWORK_PROVIDER);
	}
	if ((nif->nif_flow_flags & NETIF_FLOW_FLAG_INITIALIZED) != 0) {
		if (NETIF_IS_LOW_LATENCY(nif)) {
			features |= NETAGENT_FLAG_NEXUS_PROVIDER;
		} else {
			features |= NETAGENT_FLAG_CUSTOM_ETHER_NEXUS;
		}
		features |= NETAGENT_FLAG_NETWORK_PROVIDER;
	}
	return features;
}

void
nx_netif_agent_init(struct nx_netif *nif)
{
	int err;
	ifnet_t ifp = nif->nif_ifp;
	uint32_t features = 0;

	ASSERT(ifp != NULL);
	features = nx_netif_agent_get_features(nif);
	if (features == 0) {
		SK_DF(SK_VERB_NETIF, "%s: no feature supported", if_name(ifp));
		return;
	}
	ASSERT(nif->nif_agent_flags == 0);
	lck_mtx_init(&nif->nif_agent_lock, &nexus_lock_group, &nexus_lock_attr);

	SLIST_INIT(&nif->nif_agent_flow_list);
	nif->nif_agent_flow_cnt = 0;

	err = nx_netif_agent_register(nif, features);
	if (err != 0) {
		SK_DF(SK_VERB_ERROR, "%s: agent register failed: err %d",
		    if_name(ifp), err);
		return;
	}
	ASSERT(!uuid_is_null(nif->nif_agent_uuid));
	err = if_add_netagent_locked(ifp, nif->nif_agent_uuid);
	if (err != 0) {
		nx_netif_agent_unregister(nif);
		SK_DF(SK_VERB_ERROR, "%s: agent add failed: err %d",
		    if_name(ifp), err);
		return;
	}
	nif->nif_agent_flags |= NETIF_AGENT_FLAG_ADDED;

	SK_DF(SK_VERB_NETIF, "%s: agent init complete", if_name(ifp));
}

void
nx_netif_agent_fini(struct nx_netif *nif)
{
	ifnet_t ifp = nif->nif_ifp;

	ASSERT(ifp != NULL);
	if ((nif->nif_agent_flags & NETIF_AGENT_FLAG_ADDED) == 0) {
		SK_DF(SK_VERB_NETIF, "%s: no agent added", if_name(ifp));
		return;
	}
	nif->nif_agent_flags &= ~NETIF_AGENT_FLAG_ADDED;
	ASSERT(!uuid_is_null(nif->nif_agent_uuid));
	if_delete_netagent(ifp, nif->nif_agent_uuid);

	nx_netif_agent_unregister(nif);

	/*
	 * XXX
	 * This is asymmetrical with nx_netif_agent_init(). But we have to
	 * cleanup here because the interface is detaching.
	 */
	nx_netif_agent_flow_purge(nif);
	ASSERT(nif->nif_agent_flow_cnt == 0);
	ASSERT(SLIST_EMPTY(&nif->nif_agent_flow_list));
	lck_mtx_destroy(&nif->nif_agent_lock, &nexus_lock_group);
	SK_DF(SK_VERB_NETIF, "%s: agent fini complete", if_name(ifp));
}
