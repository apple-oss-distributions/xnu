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

/*
 * The flowidns (Flow ID namespace) module provides functionality to allocate
 * globally unique identifier for a flow.
 * Currently we have four modules (flowswitch, inpcb, PF & IPSec driver) in our
 * stack which need to generate flow identifiers. These modules stamp every
 * outgoing packet with a flowID. This flowID can be used by other upstream
 * components in the device for flow classification purpose. For example, the
 * FQ-Codel algorithm relies on this per packet flowID to avoid parsing every
 * packet header for flow classification. A globally unique flowID can also be
 * used by the networking feature offload engines operating at link layer to
 * avoid flow classification operations.
 * For performance reasons we use the concept of a flow domain and the
 * data structures used by the flowidns module have per domain instance.
 * These domains represent the above mentioned four modules generating the
 * flowID. This allows us to avoid global lock being used while allocating &
 * releasing flowID. FlowID is a 32-bit unsigned integer and the 2 most
 * significant bits of flowID are used to encode the domain ID. This
 * encoding also means that the flowID generator only needs to ensure
 * uniqueness of identifier within a domain.
 */

#include <skywalk/os_skywalk.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/namespace/flowidns.h>
#include <dev/random/randomdev.h>
#include <sys/sdt.h>

/* maximum number of flowID generation retries in case of collision */
#define FLOWIDNS_MAX_FLOWID_GEN_RETRY  5

/* 2 most significant bits of the flowID are used to encode the flow domain */
#define FLOWIDNS_FLOWID_DOMAIN_SHIFT   30
#define FLOWIDNS_FLOWID_DOMAIN_MASK    (0x03 << FLOWIDNS_FLOWID_DOMAIN_SHIFT)

#define FLOWIDNS_FLOWID_SET_DOMAIN(_dom, _fid)    do {         \
	(_fid) &= ~FLOWIDNS_FLOWID_DOMAIN_MASK;                \
	(_fid) |= ((_dom) << FLOWIDNS_FLOWID_DOMAIN_SHIFT);    \
} while (0)

#define FLOWIDNS_FLOWID_GET_DOMAIN(_dom, _fid)    do {    \
	(_dom) = (_fid) >> FLOWIDNS_FLOWID_DOMAIN_SHIFT;  \
} while (0)

#define FLOWIDNS_DOM_LOCK(_dom)    \
	lck_mtx_lock(&(flowidns_domain_array[(_dom)].fd_mtx))
#define FLOWIDNS_DOM_UNLOCK(_dom)    \
	lck_mtx_unlock(&(flowidns_domain_array[(_dom)].fd_mtx))

struct flowidns_flowid_tree_node {
	RB_ENTRY(flowidns_flowid_tree_node) fftn_link;
	struct flowidns_flow_key            fftn_flowkey;
	flowidns_flowid_t                   fftn_flowid;
};

static LCK_GRP_DECLARE(flowidns_lock_group, "flowidns_lock");
static int __flowidns_inited = 0;

static ZONE_DEFINE(flowidns_fftn_zone, SKMEM_ZONE_PREFIX ".flowidns.fftn",
    sizeof(struct flowidns_flowid_tree_node), ZC_NONE);

__attribute__((always_inline))
static inline int
fftn_cmp(const struct flowidns_flowid_tree_node *fftn1,
    const struct flowidns_flowid_tree_node *fftn2)
{
	return (signed)(fftn1->fftn_flowid - fftn2->fftn_flowid);
}

RB_HEAD(flowidns_flowid_tree, flowidns_flowid_tree_node);
RB_PROTOTYPE(flowidns_flowid_tree, flowidns_flowid_tree_node, fftn_link,
    fftn_cmp);
RB_GENERATE(flowidns_flowid_tree, flowidns_flowid_tree_node, fftn_link,
    fftn_cmp);

struct flowidns_domain {
	decl_lck_mtx_data(, fd_mtx);
	struct flowidns_flowid_tree    fd_flowid_tree;
	uint32_t                       fd_id;
	uint64_t                       fd_nallocs;
	uint64_t                       fd_nreleases;
	uint64_t                       fd_ncollisions;
};

static struct flowidns_domain flowidns_domain_array[FLOWIDNS_DOMAIN_MAX + 1];

static struct flowidns_flowid_tree_node *
flowidns_fftn_alloc(bool can_block)
{
	struct flowidns_flowid_tree_node *fftn = NULL;
	zalloc_flags_t zflags;

	zflags = can_block ? Z_WAITOK_ZERO : Z_NOWAIT_ZERO;
	fftn = zalloc_flags(flowidns_fftn_zone, zflags);
	return fftn;
}

static void
flowidns_fftn_free(struct flowidns_flowid_tree_node *fftn)
{
	zfree(flowidns_fftn_zone, fftn);
}

static struct flowidns_flowid_tree_node *
flowidns_find_fftn(flowidns_flowid_t flowid, flowidns_domain_id_t domain)
{
	struct flowidns_flowid_tree_node find = { .fftn_flowid = flowid };

	return RB_FIND(flowidns_flowid_tree,
	           &(flowidns_domain_array[domain].fd_flowid_tree), &find);
}

void
flowidns_allocate_flowid(flowidns_domain_id_t domain,
    struct flowidns_flow_key *pflow_key, flowidns_flowid_t *pflowid)
{
	struct flowidns_flowid_tree_node *fftn = NULL, *dup = NULL;
	uint32_t flowid = 0;
	int retry_cnt = 0;

	VERIFY(__flowidns_inited == 1);
	VERIFY(pflowid != NULL);
	VERIFY(pflow_key != NULL);
	VERIFY(domain >= FLOWIDNS_DOMAIN_MIN &&
	    domain <= FLOWIDNS_DOMAIN_MAX);

	FLOWIDNS_DOM_LOCK(domain);

	fftn = flowidns_fftn_alloc(true);
	if (__improbable(fftn == NULL)) {
		panic_plain("failed to allocate flowid node\n");
	}
retry:
	/* try to get a non-zero flow identifier */
	do {
		read_frandom(&flowid, sizeof(flowid));
	} while (__improbable(flowid == 0));

	FLOWIDNS_FLOWID_SET_DOMAIN(domain, flowid);

	fftn->fftn_flowid = flowid;
	fftn->fftn_flowkey = *pflow_key;
	dup = RB_INSERT(flowidns_flowid_tree,
	    &(flowidns_domain_array[domain].fd_flowid_tree), fftn);

	/* try to get a unique flow identifier */
	if (dup != NULL) {
		retry_cnt++;
		flowidns_domain_array[domain].fd_ncollisions++;
		SK_ERR("duplicate flowid 0x%x generated, retrying %d",
		    flowid, retry_cnt);
		/*
		 * safeguard to check if we need a better hash strategy.
		 */
		VERIFY(retry_cnt <= FLOWIDNS_MAX_FLOWID_GEN_RETRY);
		goto retry;
	}
	*pflowid = flowid;
	flowidns_domain_array[domain].fd_nallocs++;
	VERIFY(flowidns_domain_array[domain].fd_nallocs != 0);

	FLOWIDNS_DOM_UNLOCK(domain);

	DTRACE_SKYWALK2(fidalloc, uint32_t, domain, uint32_t, flowid);
}

void
flowidns_release_flowid(flowidns_flowid_t flowid)
{
	struct flowidns_flowid_tree_node *fftn;
	flowidns_domain_id_t domain;

	VERIFY(__flowidns_inited == 1);
	VERIFY(flowid != 0);

	FLOWIDNS_FLOWID_GET_DOMAIN(domain, flowid);
	VERIFY(domain >= FLOWIDNS_DOMAIN_MIN &&
	    domain <= FLOWIDNS_DOMAIN_MAX);

	DTRACE_SKYWALK2(fidrel, uint32_t, domain, uint32_t, flowid);

	FLOWIDNS_DOM_LOCK(domain);

	fftn = flowidns_find_fftn(flowid, domain);
	if (fftn == NULL) {
		panic_plain("flowid 0x%x not found in domain %d\n", flowid,
		    domain);
	}
	RB_REMOVE(flowidns_flowid_tree,
	    &(flowidns_domain_array[domain].fd_flowid_tree), fftn);
	ASSERT(fftn->fftn_flowid == flowid);
	flowidns_fftn_free(fftn);
	flowidns_domain_array[domain].fd_nreleases++;
	VERIFY(flowidns_domain_array[domain].fd_nreleases != 0);

	FLOWIDNS_DOM_UNLOCK(domain);
}

int
flowidns_init()
{
	flowidns_domain_id_t domain;

	VERIFY(__flowidns_inited == 0);
	_CASSERT(SFH_DOMAIN_IPSEC == FLOWIDNS_DOMAIN_IPSEC);
	_CASSERT(SFH_DOMAIN_FLOWSWITCH == FLOWIDNS_DOMAIN_FLOWSWITCH);
	_CASSERT(SFH_DOMAIN_INPCB == FLOWIDNS_DOMAIN_INPCB);
	_CASSERT(SFH_DOMAIN_PF == FLOWIDNS_DOMAIN_PF);
	_CASSERT(FLOWIDNS_DOMAIN_MIN == 0);
	/*
	 * FLOWIDNS_FLOWID_DOMAIN_{MASK, SHIFT} macros are based on below
	 * assumption.
	 */
	_CASSERT(FLOWIDNS_DOMAIN_MAX == 3);

	for (domain = FLOWIDNS_DOMAIN_MIN; domain <= FLOWIDNS_DOMAIN_MAX;
	    domain++) {
		bzero(&flowidns_domain_array[domain],
		    sizeof(struct flowidns_domain));
		flowidns_domain_array[domain].fd_id = domain;
		lck_mtx_init(&(flowidns_domain_array[domain].fd_mtx),
		    &flowidns_lock_group, NULL);
		RB_INIT(&(flowidns_domain_array[domain].fd_flowid_tree));
	}

	__flowidns_inited = 1;
	SK_D("initialized flow ID namespace");
	return 0;
}

void
flowidns_fini(void)
{
	flowidns_domain_id_t domain;
	struct flowidns_flowid_tree_node *fftn, *fftn_tmp;

	VERIFY(__flowidns_inited == 1);

	for (domain = FLOWIDNS_DOMAIN_MIN; domain <= FLOWIDNS_DOMAIN_MAX;
	    domain++) {
		FLOWIDNS_DOM_LOCK(domain);

		RB_FOREACH_SAFE(fftn, flowidns_flowid_tree,
		    &(flowidns_domain_array[domain].fd_flowid_tree),
		    fftn_tmp) {
			RB_REMOVE(flowidns_flowid_tree,
			    &(flowidns_domain_array[domain].fd_flowid_tree),
			    fftn);
			flowidns_fftn_free(fftn);
		}

		FLOWIDNS_DOM_UNLOCK(domain);

		lck_mtx_destroy(&(flowidns_domain_array[domain].fd_mtx),
		    &flowidns_lock_group);
	}

	__flowidns_inited = 0;
}

static int flowidns_stats_sysctl SYSCTL_HANDLER_ARGS;
SYSCTL_PROC(_kern_skywalk_stats, OID_AUTO, flowidns,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, flowidns_stats_sysctl, "-",
    "flowid allocations (struct sk_stats_flowidns_header, "
    "skywalk/os_stats_private.h)");

static int
flowidns_dump_domain(struct sysctl_req *req, struct flowidns_domain *domain)
{
	struct flowidns_flowid_tree_node *fftn;
	struct sk_stats_flowidns_header header;
	struct sk_stats_flowidns_record record;
	uint64_t n_records;
	int err;

	/* Fill out header */
	memset(&header, 0, sizeof(header));
	header.sfh_domain = domain->fd_id;
	header.sfh_nallocs = domain->fd_nallocs;
	header.sfh_nreleases = domain->fd_nreleases;
	header.sfh_ncollisions = domain->fd_ncollisions;
	n_records = domain->fd_nallocs - domain->fd_nreleases;
	VERIFY(n_records <= UINT32_MAX);
	header.sfh_nrecords = (uint32_t)n_records;

	err = SYSCTL_OUT(req, &header, sizeof(header));
	if (err) {
		return err;
	}

	/* Fill out records */
	RB_FOREACH(fftn, flowidns_flowid_tree, &domain->fd_flowid_tree) {
		VERIFY(n_records > 0);
		n_records--;
		bzero(&record, sizeof(record));
		record.sfr_flowid = fftn->fftn_flowid;
		record.sfr_af = fftn->fftn_flowkey.ffk_af;
		record.sfr_ipproto = fftn->fftn_flowkey.ffk_proto;
		record.sfr_protoid = fftn->fftn_flowkey.ffk_protoid;
		_CASSERT(sizeof(fftn->fftn_flowkey.ffk_laddr) ==
		    sizeof(record.sfr_laddr));
		_CASSERT(sizeof(fftn->fftn_flowkey.ffk_raddr) ==
		    sizeof(record.sfr_raddr));
		bcopy(&(fftn->fftn_flowkey.ffk_laddr), &record.sfr_laddr,
		    sizeof(record.sfr_laddr));
		bcopy(&(fftn->fftn_flowkey.ffk_raddr), &record.sfr_raddr,
		    sizeof(record.sfr_raddr));

		err = SYSCTL_OUT(req, &record, sizeof(record));
		if (err) {
			return err;
		}
	}
	VERIFY(n_records == 0);
	return 0;
}

static int
flowidns_stats_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	flowidns_domain_id_t domain;
	int err = 0;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		return EPERM;
	}

	if (__flowidns_inited == 0) {
		return ENOTSUP;
	}

	net_update_uptime();

	for (domain = FLOWIDNS_DOMAIN_MIN; domain <= FLOWIDNS_DOMAIN_MAX;
	    domain++) {
		FLOWIDNS_DOM_LOCK(domain);
		err = flowidns_dump_domain(req, &flowidns_domain_array[domain]);
		FLOWIDNS_DOM_UNLOCK(domain);
		if (err != 0) {
			return err;
		}
	}
	/*
	 * If this is just a request for length, add slop because
	 * this is dynamically changing data
	 */
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx += 20 * sizeof(struct sk_stats_flowidns_record);
	}
	return err;
}
