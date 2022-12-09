/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
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
 * Flow Routes.
 *
 * Each (non-listener) flow entry is always associated with a flow route
 * object.  Multiple flow entries sharing the same remote address will use
 * the same flow route for that address.  The flow route object contains
 * the route information for the remote node.  It gets allocated when a
 * flow entry requests to connect, and is garbage-collected when it's no
 * longer referred to after its expiration time has passed.
 *
 * A flow route also contains the default local address that's used to
 * reach the remote node.  This may not necessarily be the same local
 * address used by the flow entry, if it has explicitly bound the entry
 * to another local address.  But for the majority of cases, having the
 * local address be present in the flow route allows us to avoid doing
 * source address selection each time a connect request happens.
 *
 * When the remote node is reachable via a gateway, the gateway address
 * portion of the flow route contains its IP address and the flow route
 * is marked with FLOWRTF_GATEWAY.  We use this to optimize the gateway
 * route lookup, since otherwise we'd have to perform an extra lookup
 * each time we need to resolve the route.
 *
 * When the remote node is directly on the link, the FLOWRTF_ONLINK flag
 * is set, and the gateway address isn't used.  The target address used
 * for resolution will the the remote address itself.
 *
 * On links with link-layer information, we store the resolved address
 * of the target node (which may be the gateway's) in the flow route,
 * and mark the flow route with FLOWRTF_HAS_LLINFO.
 *
 * Each flow route also registers itself to receive route events when
 * the underlying rtentry is updated or deleted.
 */

#include <skywalk/os_skywalk_private.h>

#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_arp.h>
#include <netinet6/nd6.h>
#include <net/route.h>

extern struct rtstat rtstat;

static LCK_GRP_DECLARE(flow_route_lock_group, "sk_flow_route_lock");
static LCK_ATTR_DECLARE(flow_route_lock_attr, 0, 0);

static int fr_cmp(const struct flow_route *, const struct flow_route *);
static int fr_id_cmp(const struct flow_route *, const struct flow_route *);
static struct flow_route *fr_alloc(boolean_t);
static void fr_free(struct flow_route *);
static uint32_t flow_route_bucket_purge_common(struct flow_route_bucket *,
    uint32_t *, boolean_t, boolean_t);
static void flow_route_ev_callback(struct eventhandler_entry_arg,
    struct sockaddr *, int, struct sockaddr *, int);

RB_GENERATE_PREV(flow_route_tree, flow_route, fr_link, fr_cmp);
RB_GENERATE_PREV(flow_route_id_tree, flow_route, fr_id_link, fr_id_cmp);

#define FR_ZONE_NAME    "flow.route"

static unsigned int flow_route_size;            /* size of flow_route */
struct skmem_cache *flow_route_cache;           /* cache for flow_route */

static int __flow_route_inited = 0;

#define FLOW_ROUTE_EXPIRE       600     /* seconds */
static unsigned int flow_route_expire = FLOW_ROUTE_EXPIRE;

SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, flow_route_expire,
    CTLFLAG_RW | CTLFLAG_LOCKED, &flow_route_expire, 0, "");

void
flow_route_init(void)
{
	ASSERT(!__flow_route_inited);

	flow_route_size = sizeof(struct flow_route);
	flow_route_cache = skmem_cache_create(FR_ZONE_NAME, flow_route_size,
	    sizeof(uint64_t), NULL, NULL, NULL, NULL, NULL, 0);

	__flow_route_inited = 1;
}

void
flow_route_fini(void)
{
	if (__flow_route_inited) {
		skmem_cache_destroy(flow_route_cache);
		flow_route_cache = NULL;

		__flow_route_inited = 0;
	}
}

struct flow_route_bucket *
flow_route_buckets_alloc(size_t frb_cnt, size_t *frb_sz, size_t *tot_sz)
{
	uint32_t cache_sz = skmem_cpu_cache_line_size();
	struct flow_route_bucket *frb;
	void *frb_buf, **frb_pbuf;
	size_t frb_tot_sz;

	/* each bucket is CPU cache-aligned */
	*frb_sz = P2ROUNDUP(sizeof(*frb), cache_sz);

	/* total size includes extra for alignment requirements */
	*tot_sz = frb_tot_sz = (sizeof(void *) + (frb_cnt * (*frb_sz)) + cache_sz);
	// rdar://88962126
	/* BEGIN IGNORE CODESTYLE */
	__typed_allocators_ignore_push
	frb_buf = sk_alloc(frb_tot_sz, Z_WAITOK, skmem_tag_fsw_frb_hash);
	__typed_allocators_ignore_pop
	/* END IGNORE CODESTYLE */
	if (__improbable(frb_buf == NULL)) {
		return NULL;
	}

	/*
	 * In case we didn't get a cache-aligned memory, round it up
	 * accordingly.  This is needed in order to get the rest of
	 * the structure members aligned properly.  It also means that
	 * the memory span gets shifted due to the round up, but it
	 * is okay since we've allocated extra space for this.
	 */
	frb = (struct flow_route_bucket *)
	    P2ROUNDUP((intptr_t)frb_buf + sizeof(void *), cache_sz);
	frb_pbuf = (void **)((intptr_t)frb - sizeof(void *));
	ASSERT((intptr_t)frb_pbuf >= (intptr_t)frb_buf);
	ASSERT(((intptr_t)frb + (frb_cnt * (*frb_sz))) <=
	    ((intptr_t)frb_buf + frb_tot_sz));
	*frb_pbuf = frb_buf;

	SK_DF(SK_VERB_MEM, "frb 0x%llx frb_cnt %zu frb_sz %zu "
	    "(total %zu bytes, frb_buf 0x%llx) ALLOC", SK_KVA(frb), frb_cnt,
	    *frb_sz, frb_tot_sz, SK_KVA(frb_buf));

	return frb;
}

void
flow_route_buckets_free(struct flow_route_bucket *frb, size_t tot_sz)
{
	void *frb_buf, **frb_pbuf;

	/* get the original address that we stuffed in earlier and free it */
	frb_pbuf = (void **)((intptr_t)frb - sizeof(void *));
	frb_buf = *frb_pbuf;
	SK_DF(SK_VERB_MEM, "frb 0x%llx (frb_buf 0x%llx) FREE",
	    SK_KVA(frb), SK_KVA(frb_buf));
	// rdar://88962126
	__typed_allocators_ignore_push
	sk_free(frb_buf, tot_sz);
	__typed_allocators_ignore_pop
}

void
flow_route_bucket_init(struct flow_route_bucket *frb)
{
	ASSERT(IS_P2ALIGNED(frb, skmem_cpu_cache_line_size()));
	lck_rw_init(&frb->frb_lock, &flow_route_lock_group,
	    &flow_route_lock_attr);
	RB_INIT(&frb->frb_head);
}

void
flow_route_bucket_destroy(struct flow_route_bucket *frb)
{
	ASSERT(RB_EMPTY(&frb->frb_head));
	lck_rw_destroy(&frb->frb_lock, &flow_route_lock_group);
}

static struct flow_route *
flow_route_find_by_addr(struct flow_route_bucket *frb,
    union sockaddr_in_4_6 *dst)
{
	struct flow_route *fr;
	struct flow_route find;

	FRB_LOCK_ASSERT_HELD(frb);

	switch (SA(dst)->sa_family) {
	case AF_INET:
		find.fr_af = AF_INET;
		find.fr_addr_len = sizeof(struct in_addr);
		find.fr_addr_key = (void *)&SIN(dst)->sin_addr;
		break;

	case AF_INET6:
		find.fr_af = AF_INET6;
		find.fr_addr_len = sizeof(struct in6_addr);
		find.fr_addr_key = (void *)&SIN6(dst)->sin6_addr;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	fr = RB_FIND(flow_route_tree, &frb->frb_head, &find);
	if (fr != NULL) {
		flow_route_retain(fr);  /* for the caller */
	}
	return fr;
}

struct flow_route_id_bucket *
flow_route_id_buckets_alloc(size_t frib_cnt, size_t *frib_sz, size_t *tot_sz)
{
	uint32_t cache_sz = skmem_cpu_cache_line_size();
	struct flow_route_id_bucket *frib;
	void *frib_buf, **frib_pbuf;
	size_t frib_tot_sz;

	/* each bucket is CPU cache-aligned */
	*frib_sz = P2ROUNDUP(sizeof(*frib), cache_sz);

	/* total size includes extra for alignment requirements */
	*tot_sz = frib_tot_sz = (sizeof(void *) + (frib_cnt * (*frib_sz)) + cache_sz);
	// rdar://88962126
	/* BEGIN IGNORE CODESTYLE */
	__typed_allocators_ignore_push
	frib_buf = sk_alloc(frib_tot_sz, Z_WAITOK, skmem_tag_fsw_frib_hash);
	__typed_allocators_ignore_pop
	/* END IGNORE CODESTYLE */
	if (__improbable(frib_buf == NULL)) {
		return NULL;
	}

	/*
	 * In case we didn't get a cache-aligned memory, round it up
	 * accordingly.  This is needed in order to get the rest of
	 * the structure members aligned properly.  It also means that
	 * the memory span gets shifted due to the round up, but it
	 * is okay since we've allocated extra space for this.
	 */
	frib = (struct flow_route_id_bucket *)
	    P2ROUNDUP((intptr_t)frib_buf + sizeof(void *), cache_sz);
	frib_pbuf = (void **)((intptr_t)frib - sizeof(void *));
	ASSERT((intptr_t)frib_pbuf >= (intptr_t)frib_buf);
	ASSERT(((intptr_t)frib + (frib_cnt * (*frib_sz))) <=
	    ((intptr_t)frib_buf + frib_tot_sz));
	*frib_pbuf = frib_buf;

	SK_DF(SK_VERB_MEM, "frib 0x%llx frib_cnt %zu frib_sz %zu "
	    "(total %zu bytes, frib_buf 0x%llx) ALLOC", SK_KVA(frib), frib_cnt,
	    *frib_sz, frib_tot_sz, SK_KVA(frib_buf));

	return frib;
}

void
flow_route_id_buckets_free(struct flow_route_id_bucket *frib, size_t tot_sz)
{
	void *frib_buf, **frib_pbuf;

	/* get the original address that we stuffed in earlier and free it */
	frib_pbuf = (void **)((intptr_t)frib - sizeof(void *));
	frib_buf = *frib_pbuf;
	SK_DF(SK_VERB_MEM, "frib 0x%llx (frib_buf 0x%llx) FREE", SK_KVA(frib),
	    SK_KVA(frib_buf));
	// rdar://88962126
	__typed_allocators_ignore_push
	sk_free(frib_buf, tot_sz);
	__typed_allocators_ignore_pop
}

void
flow_route_id_bucket_init(struct flow_route_id_bucket *frib)
{
	ASSERT(IS_P2ALIGNED(frib, skmem_cpu_cache_line_size()));
	lck_rw_init(&frib->frib_lock, &flow_route_lock_group,
	    &flow_route_lock_attr);
	RB_INIT(&frib->frib_head);
}

void
flow_route_id_bucket_destroy(struct flow_route_id_bucket *frib)
{
	ASSERT(RB_EMPTY(&frib->frib_head));
	lck_rw_destroy(&frib->frib_lock, &flow_route_lock_group);
}

static struct flow_route *
flow_route_find_by_uuid(struct flow_route_id_bucket *frib, uuid_t id)
{
	struct flow_route *fr;
	struct flow_route find;

	FRIB_LOCK_ASSERT_HELD(frib);

	uuid_copy(find.fr_uuid, id);
	fr = RB_FIND(flow_route_id_tree, &frib->frib_head, &find);
	if (fr != NULL) {
		flow_route_retain(fr);  /* for the caller */
	}
	return fr;
}

static struct flow_route *
fr_alloc(boolean_t cansleep)
{
	struct flow_route *fr;

	if ((fr = skmem_cache_alloc(flow_route_cache,
	    (cansleep ? SKMEM_SLEEP : SKMEM_NOSLEEP))) != NULL) {
		bzero(fr, flow_route_size);
		lck_spin_init(&fr->fr_reflock, &flow_route_lock_group,
		    &flow_route_lock_attr);
		lck_mtx_init(&fr->fr_lock, &flow_route_lock_group,
		    &flow_route_lock_attr);
		uuid_generate_random(fr->fr_uuid);

		SK_DF(SK_VERB_MEM, "allocated fr 0x%llx", SK_KVA(fr));
	}

	return fr;
}

static void
fr_free(struct flow_route *fr)
{
	SK_DF(SK_VERB_MEM, "freeing fr 0x%llx", SK_KVA(fr));

	VERIFY(!(fr->fr_flags & FLOWRTF_ATTACHED));
	VERIFY(fr->fr_usecnt == 0);

	FR_LOCK(fr);
	/* callee frees route entry */
	flow_route_cleanup(fr);
	VERIFY(fr->fr_rt_dst == NULL);
	VERIFY(fr->fr_rt_gw == NULL);
	VERIFY(fr->fr_rt_evhdlr_tag == NULL);
	FR_UNLOCK(fr);

	lck_mtx_destroy(&fr->fr_lock, &flow_route_lock_group);
	lck_spin_destroy(&fr->fr_reflock, &flow_route_lock_group);

	skmem_cache_free(flow_route_cache, fr);
}

static inline int
fr_cmp(const struct flow_route *a, const struct flow_route *b)
{
	int d;

	if ((d = (a->fr_af - b->fr_af)) != 0) {
		return d;
	}
	if ((d = flow_ip_cmp(a->fr_addr_key, b->fr_addr_key,
	    b->fr_addr_len)) != 0) {
		return d;
	}

	return 0;
}

static inline int
fr_id_cmp(const struct flow_route *a, const struct flow_route *b)
{
	return uuid_compare(a->fr_uuid, b->fr_uuid);
}

static inline int
fr_use_stable_address(struct nx_flow_req *req)
{
	int use_stable_address = ip6_prefer_tempaddr ? 0 : 1;
	if (req != NULL &&
	    (req->nfr_flags & NXFLOWREQF_OVERRIDE_ADDRESS_SELECTION)) {
		use_stable_address = (req->nfr_flags & NXFLOWREQF_USE_STABLE_ADDRESS) ? 1 : 0;
	}
	return use_stable_address;
}

int
flow_route_configure(struct flow_route *fr, struct ifnet *ifp, struct nx_flow_req *req)
{
#if SK_LOG
	char old_s[MAX_IPv6_STR_LEN];   /* src */
	char src_s[MAX_IPv6_STR_LEN];   /* src */
	char dst_s[MAX_IPv6_STR_LEN];   /* dst */
#endif /* SK_LOG */
	struct rtentry *rt = NULL, *gwrt = NULL;
	int err = 0;

	FR_LOCK_ASSERT_HELD(fr);

	/*
	 * If there is a route entry for the final destination, see if
	 * it's no longer valid and perform another routing table lookup.
	 * A non-NULL fr_rt_dst is always associated with a route event
	 * registration, and the route reference is held there.
	 */
	rt = fr->fr_rt_dst;
	if (rt == NULL || !(rt->rt_flags & RTF_UP) || fr->fr_want_configure) {
		struct eventhandler_entry_arg ee_arg;

		/* callee frees route entry */
		flow_route_cleanup(fr);

		/* lookup destination route */
		ASSERT(err == 0);
		rt = rtalloc1_scoped(SA(&fr->fr_faddr), 1, 0, ifp->if_index);
		if (rt == NULL) {
			err = EHOSTUNREACH;
			SK_ERR("no route to %s on %s (err %d)",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
		} else {
			/*
			 * If route points to another interface and the
			 * route's gateway isn't link-layer, reject it.
			 * We make an exception otherwise, since local
			 * interface addresses resolve this way.
			 */
			if (rt->rt_ifp != ifp && rt->rt_ifp != lo_ifp &&
			    (rt->rt_gateway == NULL ||
			    SA(rt->rt_gateway)->sa_family != AF_LINK)) {
				err = EHOSTUNREACH;
				SK_ERR("route to %s on %s != %s (err %d)",
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), rt->rt_ifp->if_xname,
				    ifp->if_xname, err);
			}
		}

		if (err != 0) {
			goto done;
		}

		ASSERT(fr->fr_mgr != NULL);
		ASSERT(!uuid_is_null(fr->fr_mgr->fm_uuid));
		ASSERT(!uuid_is_null(fr->fr_uuid));
		ASSERT(!uuid_is_null(fr->fr_nx_uuid));

		bzero(&ee_arg, sizeof(ee_arg));
		uuid_copy(ee_arg.ee_fm_uuid, fr->fr_mgr->fm_uuid);
		uuid_copy(ee_arg.ee_fr_uuid, fr->fr_uuid);

		/*
		 * Register for changes on destination route; this covers both
		 * cases where the destination is on-link, or if it is off-link
		 * and is using a gateway route.  This also transfers the refcnt
		 * of the route entry to the event handler, released later when
		 * it is deregistered.
		 */
		ASSERT(fr->fr_rt_dst == NULL);
		ASSERT(fr->fr_rt_evhdlr_tag == NULL);
		fr->fr_rt_dst = rt;             /* move reference to fr */
		fr->fr_rt_evhdlr_tag =
		    EVENTHANDLER_REGISTER(&rt->rt_evhdlr_ctxt, route_event,
		    flow_route_ev_callback, ee_arg, EVENTHANDLER_PRI_ANY);
		ASSERT(fr->fr_rt_evhdlr_tag != NULL);
		atomic_bitclear_32(&fr->fr_flags, FLOWRTF_DELETED);

		/*
		 * Lookup gateway route (if any); returns locked gwrt
		 * with a reference bumped up.
		 */
		err = route_to_gwroute(SA(&fr->fr_faddr), rt, &gwrt);
		if (err != 0) {
			/*
			 * Reference held by fr_rt_dst will be taken
			 * care of by flow_route_cleanup() below, so
			 * make sure we don't do an extra rtfree().
			 */
			rt = NULL;
			ASSERT(gwrt == NULL);
			SK_ERR("no gw route to %s on %s (err %d)",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
			goto done;
		}

		/* if RTF_GATEWAY isn't set, gwrt == rt */
		ASSERT(gwrt != NULL);
		RT_LOCK_ASSERT_HELD(gwrt);

		/*
		 * Must have been cleared via cleanup, and that we're
		 * single-threaded here for fr by virtue of fr_lock.
		 */
		ASSERT(!(fr->fr_flags & (FLOWRTF_GATEWAY | FLOWRTF_ONLINK)));

		if (gwrt != rt && (rt->rt_flags & RTF_GATEWAY) &&
		    (rt->rt_gateway->sa_family == AF_INET ||
		    rt->rt_gateway->sa_family == AF_INET6)) {
			struct sockaddr_storage ss;

			ASSERT(fr->fr_rt_gw == NULL);
			/* locked via route_to_gwroute() above */
			fr->fr_rt_gw = gwrt;    /* move reference to fr */
			RT_ADDREF_LOCKED(gwrt); /* for this routine */
			/*
			 * Destination is off-link and is reachable
			 * thru an IP gateway route.  Save the IP
			 * address of the gateway in fr_gaddr.
			 */
			(void) sa_copy(rt->rt_gateway, &ss, NULL);
			_CASSERT(sizeof(fr->fr_gaddr) <= sizeof(ss));
			bcopy(&ss, &fr->fr_gaddr, sizeof(fr->fr_gaddr));
			atomic_bitset_32(&fr->fr_flags, FLOWRTF_GATEWAY);
		} else if (IS_DIRECT_HOSTROUTE(rt)) {
			/*
			 * Destination is on-link.
			 */
			atomic_bitset_32(&fr->fr_flags, FLOWRTF_ONLINK);
		}
		RT_UNLOCK(gwrt);
	}
	RT_ADDREF(rt);          /* for this routine */

	/* see if we need to re-select default source address */
	int use_stable_address = fr_use_stable_address(req);
	if (fr->fr_want_configure ||
	    fr->fr_laddr_gencnt != ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt ||
	    !(fr->fr_flags & FLOWRTF_STABLE_ADDR) != !use_stable_address) {
		union sockaddr_in_4_6 old = fr->fr_laddr;
		if (use_stable_address) {
			atomic_bitset_32(&fr->fr_flags, FLOWRTF_STABLE_ADDR);
		} else {
			atomic_bitclear_32(&fr->fr_flags, FLOWRTF_STABLE_ADDR);
		}
		if ((err = flow_route_select_laddr(&fr->fr_laddr, &fr->fr_faddr,
		    ifp, rt, &fr->fr_laddr_gencnt, use_stable_address)) != 0) {
			SK_ERR("no usable src address to reach %s on %s "
			    "(err %d)", sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
			goto done;
		}
		if (bcmp(&old, &fr->fr_laddr, SA(&old)->sa_len) != 0) {
			SK_ERR("src address is now %s (was %s) to reach %s "
			    "on %s", sk_sa_ntop(SA(&fr->fr_laddr), src_s,
			    sizeof(src_s)), sk_sa_ntop(SA(&old), old_s,
			    sizeof(old_s)), sk_sa_ntop(SA(&fr->fr_faddr),
			    dst_s, sizeof(dst_s)), ifp->if_xname);
		}
	}
	ASSERT(err == 0);

done:
	if (__probable(err == 0)) {
		atomic_set_32(&fr->fr_want_configure, 0);
	} else {
		/* callee frees route entry */
		flow_route_cleanup(fr);
	}

	if (gwrt != NULL) {
		ASSERT(rt != NULL);
		if (gwrt == rt) {
			RT_REMREF(gwrt);
		} else {
			rtfree(gwrt);
		}
		gwrt = NULL;
	}

	if (rt != NULL) {
		rtfree(rt);
		rt = NULL;
	}

	return err;
}

int
flow_route_find(struct kern_nexus *nx, struct flow_mgr *fm,
    struct ifnet *ifp, struct nx_flow_req *req,
    flow_route_ctor_fn_t fr_ctor, flow_route_resolve_fn_t fr_resolve,
    void *arg, struct flow_route **frp)
{
#if SK_LOG
	char src_s[MAX_IPv6_STR_LEN];   /* dst */
	char dst_s[MAX_IPv6_STR_LEN];   /* dst */
	char gw_s[MAX_IPv6_STR_LEN];    /* gw */
#endif /* SK_LOG */
	union sockaddr_in_4_6 *daddr = &req->nfr_daddr;
	struct flow_route_bucket *frb;
	struct flow_route_id_bucket *frib;
	struct flow_route *fr = NULL;
	int err = 0;

	ASSERT(fr_ctor != NULL && fr_resolve != NULL);

	ASSERT(frp != NULL);
	*frp = NULL;

	frb = flow_mgr_get_frb_by_addr(fm, daddr);

	int use_stable_address = fr_use_stable_address(req);

	/* see if there is a cached flow route (as reader) */
	FRB_RLOCK(frb);
	fr = flow_route_find_by_addr(frb, daddr);
	if (fr != NULL) {
		if (__improbable(fr->fr_want_configure || fr->fr_laddr_gencnt !=
		    ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt) ||
		    __improbable(!(fr->fr_flags & FLOWRTF_STABLE_ADDR) != !use_stable_address)) {
			atomic_add_32(&fr->fr_want_configure, 1);
			FR_LOCK(fr);
			err = flow_route_configure(fr, ifp, req);
			if (err != 0) {
				SK_ERR("fr 0x%llx error re-configuring dst %s "
				    "on %s (err %d) [R]", SK_KVA(fr),
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname, err);
			}
			FR_UNLOCK(fr);
		}
		if (err == 0) {
			SK_DF(SK_VERB_FLOW_ROUTE,
			    "fr 0x%llx found for dst %s " "on %s [R,%u]",
			    SK_KVA(fr), sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, fr->fr_usecnt);
		}
		FRB_RUNLOCK(frb);       /* reader */
		goto done;
	}

	/*
	 * Flow route doesn't exist; become a writer and prepare to
	 * allocate one.  We could be racing with other threads here,
	 * so check first if there is now a cached flow route that
	 * got created by the winning thread.
	 */
	if (!FRB_RLOCKTOWLOCK(frb)) {
		FRB_WLOCK(frb);
	}

	fr = flow_route_find_by_addr(frb, daddr);
	if (fr != NULL) {
		if (__improbable(fr->fr_want_configure) ||
		    __improbable(!(fr->fr_flags & FLOWRTF_STABLE_ADDR) != !use_stable_address)) {
			FR_LOCK(fr);
			err = flow_route_configure(fr, ifp, req);
			if (err != 0) {
				SK_ERR("fr 0x%llx error re-configuring dst %s "
				    "on %s (err %d) [W]", SK_KVA(fr),
				    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
				    sizeof(dst_s)), ifp->if_xname, err);
			}
			FR_UNLOCK(fr);
		}
		if (err == 0) {
			SK_DF(SK_VERB_FLOW_ROUTE,
			    "fr 0x%llx found for dst %s on %s [W,%u]",
			    SK_KVA(fr), sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, fr->fr_usecnt);
		}
		FRB_WUNLOCK(frb);       /* writer */
		goto done;
	}

	/* allocate one */
	fr = fr_alloc(TRUE);
	fr->fr_faddr = *daddr;          /* remote address */

	switch (SA(&fr->fr_faddr)->sa_family) {
	case AF_INET:
		SIN(&fr->fr_faddr)->sin_port = 0;
		fr->fr_addr_len = sizeof(struct in_addr);
		fr->fr_addr_key = &SIN(&fr->fr_faddr)->sin_addr;
		break;

	case AF_INET6:
		SIN6(&fr->fr_faddr)->sin6_port = 0;
		fr->fr_addr_len = sizeof(struct in6_addr);
		fr->fr_addr_key = &SIN6(&fr->fr_faddr)->sin6_addr;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	ASSERT(!uuid_is_null(fr->fr_uuid));
	uuid_copy(fr->fr_nx_uuid, nx->nx_uuid);
	*(struct flow_mgr **)(uintptr_t)&fr->fr_mgr = fm;

	/* force configure newly-created flow route */
	atomic_add_32(&fr->fr_want_configure, 1);

	FR_LOCK(fr);
	if ((err = flow_route_configure(fr, ifp, req)) != 0) {
		SK_ERR("fr 0x%llx error configuring dst %s on %s (err %d)",
		    SK_KVA(fr), sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
		    sizeof(dst_s)), ifp->if_xname, err);
		FR_UNLOCK(fr);
		FRB_WUNLOCK(frb);       /* writer */
		/* not yet in tree, so free immediately */
		fr_free(fr);
		fr = NULL;
		goto done;
	}

	/* execute nexus-specific constructor */
	fr_ctor(arg, fr);
	FR_UNLOCK(fr);

	frib = flow_mgr_get_frib_by_uuid(fm, fr->fr_uuid);
	FRIB_WLOCK(frib);

	*(struct flow_route_bucket **)(uintptr_t)&fr->fr_frb = frb;
	*(struct flow_route_id_bucket **)(uintptr_t)&fr->fr_frib = frib;

	FRB_WLOCK_ASSERT_HELD(frb);
	FRIB_WLOCK_ASSERT_HELD(frib);

	RB_INSERT(flow_route_tree, &frb->frb_head, fr);
	RB_INSERT(flow_route_id_tree, &frib->frib_head, fr);

	atomic_bitset_32(&fr->fr_flags, FLOWRTF_ATTACHED);

#if DEBUG
	/* sanity checks for comparator routines */
	VERIFY(flow_route_find_by_addr(frb, &fr->fr_faddr) == fr);
	flow_route_release(fr);
	VERIFY(flow_route_find_by_uuid(frib, fr->fr_uuid) == fr);
	flow_route_release(fr);
#endif /* DEBUG */

	/* for the trees */
	_CASSERT(FLOW_ROUTE_MINREF == 2);
	flow_route_retain(fr);
	flow_route_retain(fr);
	ASSERT(fr->fr_usecnt == FLOW_ROUTE_MINREF);

	/* for the caller */
	flow_route_retain(fr);

	FRIB_WUNLOCK(frib);     /* writer */
	FRB_WUNLOCK(frb);       /* writer */

	/* execute nexus-specific resolver */
	if (!(fr->fr_flags & FLOWRTF_RESOLVED) &&
	    (err = fr_resolve(arg, fr, NULL)) != 0) {
		if (fr->fr_flags & FLOWRTF_GATEWAY) {
			SK_ERR("fr 0x%llx resolve %s gw %s on %s (err %d)",
			    SK_KVA(fr), (err == EJUSTRETURN ? "pending" :
			    "fail"), sk_sa_ntop(SA(&fr->fr_gaddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
		} else {
			SK_ERR("fr 0x%llx resolve %s dst %s on %s (err %d)",
			    SK_KVA(fr), (err == EJUSTRETURN ? "pending" :
			    "fail"), sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
		}
		if (err == EJUSTRETURN) {
			err = 0;
		} else {
			goto done;
		}
	}
	ASSERT(err == 0);

#if SK_LOG
	if (fr->fr_flags & FLOWRTF_GATEWAY) {
		SK_DF(SK_VERB_FLOW_ROUTE,
		    "add fr 0x%llx %s -> %s via gw %s on %s", SK_KVA(fr),
		    sk_sa_ntop(SA(&fr->fr_laddr), src_s, sizeof(src_s)),
		    sk_sa_ntop(SA(&fr->fr_faddr), dst_s, sizeof(dst_s)),
		    sk_sa_ntop(SA(&fr->fr_gaddr), gw_s, sizeof(gw_s)),
		    ifp->if_xname);
	} else {
		SK_DF(SK_VERB_FLOW_ROUTE,
		    "add fr 0x%llx %s -> %s on %s", SK_KVA(fr),
		    sk_sa_ntop(SA(&fr->fr_laddr), src_s, sizeof(src_s)),
		    sk_sa_ntop(SA(&fr->fr_faddr), dst_s, sizeof(dst_s)),
		    ifp->if_xname);
	}
#endif /* SK_LOG */

done:
	if (err == 0) {
		ASSERT(fr != NULL);
		*frp = fr;
	} else if (fr != NULL) {
		/* can't directly call fr_free() if it's in the tree */
		flow_route_release(fr);
		fr = NULL;
	}

	return err;
}

void
flow_route_retain(struct flow_route *fr)
{
	lck_spin_lock(&fr->fr_reflock);
	if (fr->fr_usecnt++ == FLOW_ROUTE_MINREF) {
		fr->fr_expire = 0;
	}
	lck_spin_unlock(&fr->fr_reflock);
}

void
flow_route_release(struct flow_route *fr)
{
	bool should_free = false;

	lck_spin_lock(&fr->fr_reflock);
	VERIFY(fr->fr_usecnt > 0);
	if (fr->fr_flags & FLOWRTF_ATTACHED) {
		if (fr->fr_usecnt-- == (FLOW_ROUTE_MINREF + 1)) {
			fr->fr_expire = _net_uptime + flow_route_expire;
		}
	} else {
		/*
		 * fr is no longer in lookup tree, so there shouldn't be
		 * further usecnt, if we reach 0 usecnt, then this is the very
		 * last reference and is safe to unlock and call fr_free.
		 */
		if (--(fr->fr_usecnt) == 0) {
			should_free = true;
		}
	}
	lck_spin_unlock(&fr->fr_reflock);

	if (should_free) {
		fr_free(fr);
	}
}

static uint32_t
flow_route_bucket_purge_common(struct flow_route_bucket *frb, uint32_t *resid,
    boolean_t all, boolean_t early_expire)
{
#if SK_LOG
	char ss[MAX_IPv6_STR_LEN];      /* dst */
	char ds[MAX_IPv6_STR_LEN];      /* dst */
	char gs[MAX_IPv6_STR_LEN];      /* gw */
#endif /* SK_LOG */
	struct flow_route *fr, *tfr;
	uint64_t now = net_uptime();
	uint32_t i = 0, tot = 0;

	FRB_WLOCK_ASSERT_HELD(frb);

	RB_FOREACH_SAFE(fr, flow_route_tree, &frb->frb_head, tfr) {
		struct flow_route_id_bucket *frib =
		    __DECONST(struct flow_route_id_bucket *, fr->fr_frib);

		++tot;
		/*
		 * We're not holding fr_lock here, since this is a
		 * best-effort check.  If there's a race and we miss
		 * it now, we'll come back again shortly.
		 */
		lck_spin_lock(&fr->fr_reflock);
		if (!all && (fr->fr_usecnt > FLOW_ROUTE_MINREF ||
		    (fr->fr_expire > now && !early_expire &&
		    !(fr->fr_flags & FLOWRTF_DELETED)))) {
			lck_spin_unlock(&fr->fr_reflock);
			SK_DF(SK_VERB_FLOW_ROUTE, "skipping fr 0x%llx "
			    "refcnt %u expire %llu", SK_KVA(fr),
			    fr->fr_usecnt, fr->fr_expire);
			continue;
		}
		lck_spin_unlock(&fr->fr_reflock);

		/*
		 * If "all" is set, flow entries must be gone by now, as
		 * we must be called by flow_route_bucket_purge_all().
		 * It also means that the caller has acquired writer lock
		 * on all flow {route,route_id} buckets, and fr_usecnt
		 * must be at its minimum value now.
		 */
		if (!all) {
			FRIB_WLOCK(frib);
		}
		FRIB_WLOCK_ASSERT_HELD(frib);

		_CASSERT(FLOW_ROUTE_MINREF == 2);
		ASSERT(fr->fr_usecnt >= FLOW_ROUTE_MINREF);

		RB_REMOVE(flow_route_tree, &frb->frb_head, fr);
		RB_REMOVE(flow_route_id_tree, &frib->frib_head, fr);

		atomic_bitclear_32(&fr->fr_flags, FLOWRTF_ATTACHED);

#if SK_LOG
		if (fr->fr_flags & FLOWRTF_GATEWAY) {
			SK_DF(SK_VERB_FLOW_ROUTE,
			    "remove fr 0x%llx %s -> %s via gw %s [exp %lld]",
			    SK_KVA(fr),
			    sk_sa_ntop(SA(&fr->fr_laddr), ss, sizeof(ss)),
			    sk_sa_ntop(SA(&fr->fr_faddr), ds, sizeof(ds)),
			    sk_sa_ntop(SA(&fr->fr_gaddr), gs, sizeof(gs)),
			    (int64_t)(fr->fr_expire - now));
		} else {
			SK_DF(SK_VERB_FLOW_ROUTE,
			    "remove fr 0x%llx %s -> %s [exp %lld]", SK_KVA(fr),
			    sk_sa_ntop(SA(&fr->fr_laddr), ss, sizeof(ss)),
			    sk_sa_ntop(SA(&fr->fr_faddr), ds, sizeof(ds)),
			    (int64_t)(fr->fr_expire - now));
		}
#endif /* SK_LOG */

		/* for the trees */
		flow_route_release(fr);
		flow_route_release(fr);
		++i;

		if (!all) {
			FRIB_WUNLOCK(frib);
		}
	}

	if (resid != NULL) {
		*resid = (tot - i);
	}

	return i;
}

void
flow_route_bucket_purge_all(struct flow_route_bucket *frb)
{
	(void) flow_route_bucket_purge_common(frb, NULL, TRUE, FALSE);
}

static uint32_t
flow_route_bucket_prune(struct flow_route_bucket *frb, struct ifnet *ifp,
    uint32_t *resid)
{
	uint64_t now = net_uptime();
	struct flow_route *fr;
	uint32_t i = 0, tot = 0;
	boolean_t ifdown = !(ifp->if_flags & IFF_UP);

	FRB_RLOCK(frb);
	RB_FOREACH(fr, flow_route_tree, &frb->frb_head) {
		++tot;
		/* loose check; do this without holding fr_reflock */
		if (fr->fr_usecnt > FLOW_ROUTE_MINREF ||
		    (fr->fr_expire > now && !ifdown &&
		    !(fr->fr_flags & FLOWRTF_DELETED))) {
			continue;
		}
		++i;
	}

	/*
	 * If there's nothing to prune or there's a writer, we're done.
	 * Note that if we failed to upgrade to writer, the lock would
	 * have been released automatically.
	 */
	if (i == 0 || !FRB_RLOCKTOWLOCK(frb)) {
		if (i == 0) {
			FRB_RUNLOCK(frb);
		}
		if (resid != NULL) {
			*resid = (tot - i);
		}
		return 0;
	}

	SK_DF(SK_VERB_FLOW_ROUTE, "purging at least %u idle routes on %s",
	    i, ifp->if_xname);

	/* purge idle ones */
	i = flow_route_bucket_purge_common(frb, resid, FALSE, ifdown);
	FRB_WUNLOCK(frb);

	return i;
}

uint32_t
flow_route_prune(struct flow_mgr *fm, struct ifnet *ifp,
    uint32_t *tot_resid)
{
	uint32_t pruned = 0;
	uint32_t resid;
	uint32_t i;

	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		struct flow_route_bucket *frb = flow_mgr_get_frb_at_idx(fm, i);
		pruned += flow_route_bucket_prune(frb, ifp, &resid);
		if (tot_resid != NULL) {
			*tot_resid += resid;
		}
	}

	return pruned;
}

/*
 * This runs in the context of eventhandler invocation routine which loops
 * through all the registered callbacks.  Care must be taken to not call
 * any primitives here that would lead to routing changes in the same context
 * as it would lead to deadlock in eventhandler code.
 */
static void
flow_route_ev_callback(struct eventhandler_entry_arg ee_arg,
    struct sockaddr *dst, int route_ev, struct sockaddr *gw_addr, int flags)
{
#pragma unused(dst, flags)
#if SK_LOG
	char dst_s[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */
	struct flow_route_id_bucket *frib = NULL;
	struct flow_route *fr = NULL;
	struct flow_mgr *fm;

	VERIFY(!uuid_is_null(ee_arg.ee_fm_uuid));
	VERIFY(!uuid_is_null(ee_arg.ee_fr_uuid));

	/*
	 * Upon success, callee will hold flow manager lock as reader,
	 * and we'll need to unlock it below.  Otherwise there's no
	 * need to unlock here and just return.
	 */
	fm = flow_mgr_find_lock(ee_arg.ee_fm_uuid);
	if (fm == NULL) {
		SK_ERR("Event %s for dst %s ignored; flow manager not found",
		    route_event2str(route_ev), sk_sa_ntop(dst, dst_s,
		    sizeof(dst_s)));
		return;
	}

	SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s event %s", fm->fm_name,
	    sk_sa_ntop(dst, dst_s, sizeof(dst_s)), route_event2str(route_ev));

	do {
		frib = flow_mgr_get_frib_by_uuid(fm, ee_arg.ee_fr_uuid);

		FRIB_RLOCK(frib);
		/* callee returns a reference that we need to release below */
		fr = flow_route_find_by_uuid(frib, ee_arg.ee_fr_uuid);
		if (fr == NULL) {
			SK_ERR("%s: dst %s flow route not found", fm->fm_name,
			    sk_sa_ntop(dst, dst_s, sizeof(dst_s)));
			break;
		}

		/*
		 * Grab fr_lock to prevent flow route configuration or
		 * resolver from using stale info while we are updating.
		 */
		FR_LOCK(fr);

		switch (route_ev) {
		case ROUTE_ENTRY_REFRESH:
			/*
			 * This is the case where the route entry has been
			 * updated (for example through RTM_CHANGE).  Some
			 * of it may not warrant a lookup again and some of
			 * it may.  For now, mark flow to perform a look-up
			 * again as the gateway may have changed.
			 */
			atomic_add_32(&fr->fr_want_configure, 1);
			atomic_bitclear_32(&fr->fr_flags, FLOWRTF_RESOLVED);
			SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s route changed",
			    fm->fm_name, sk_sa_ntop(dst, dst_s,
			    sizeof(dst_s)));
			break;

		case ROUTE_ENTRY_DELETED:
			/*
			 * NOTE: flow_route_cleanup() should not be called
			 * to de-register eventhandler in the context of
			 * eventhandler callback to avoid deadlock in
			 * eventhandler code.  Instead, just mark the flow
			 * route un-resolved.  When it is being used again
			 * or being deleted the old eventhandler must be
			 * de-registered.
			 */
			atomic_add_32(&fr->fr_want_configure, 1);
			atomic_bitclear_32(&fr->fr_flags, FLOWRTF_RESOLVED);
			atomic_bitset_32(&fr->fr_flags, FLOWRTF_DELETED);
			SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s route deleted",
			    fm->fm_name, sk_sa_ntop(dst, dst_s,
			    sizeof(dst_s)));
			break;

		case ROUTE_LLENTRY_STALE:
			/*
			 * When the route entry is deemed unreliable or old
			 * enough to trigger a route lookup again.  Don't
			 * reconfigure the flow route, but simply attempt
			 * to resolve it next time to trigger a probe.
			 */
			atomic_add_32(&fr->fr_want_probe, 1);
			atomic_bitclear_32(&fr->fr_flags, FLOWRTF_RESOLVED);
			SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s llentry stale",
			    fm->fm_name, sk_sa_ntop(dst, dst_s,
			    sizeof(dst_s)));
			break;

		case ROUTE_LLENTRY_CHANGED:
			/*
			 * When the link-layer info has changed; replace
			 * cached llinfo in the flow route (treat this
			 * as ROUTE_LLENTRY_RESOLVED).
			 */
			OS_FALLTHROUGH;

		case ROUTE_LLENTRY_RESOLVED:
			/*
			 * SDL address length may be 0 for cellular.
			 * If Ethernet, copy into flow route and mark
			 * it as cached.  In all cases, mark the flow
			 * route as resolved.
			 */
			ASSERT(SDL(gw_addr)->sdl_family == AF_LINK);
			if (SDL(gw_addr)->sdl_alen == ETHER_ADDR_LEN) {
				FLOWRT_UPD_ETH_DST(fr, LLADDR(SDL(gw_addr)));
				SK_DF(SK_VERB_FLOW_ROUTE,
				    "%s: dst %s llentry %s", fm->fm_name,
				    sk_sa_ntop(dst, dst_s, sizeof(dst_s)),
				    (!(fr->fr_flags & FLOWRTF_HAS_LLINFO) ?
				    "resolved" : "changed"));
				atomic_bitset_32(&fr->fr_flags,
				    FLOWRTF_HAS_LLINFO);
			} else {
				atomic_bitclear_32(&fr->fr_flags,
				    FLOWRTF_HAS_LLINFO);
			}
			atomic_bitset_32(&fr->fr_flags, FLOWRTF_RESOLVED);
#if SK_LOG
			if (__improbable((sk_verbose & SK_VERB_FLOW_ROUTE) !=
			    0) && (fr->fr_flags & FLOWRTF_HAS_LLINFO)) {
				SK_DF(SK_VERB_FLOW_ROUTE,
				    "%s: fr 0x%llx eth_type 0x%x "
				    "eth_src %x:%x:%x:%x:%x:%x "
				    "eth_dst %x:%x:%x:%x:%x:%x [%s])",
				    fm->fm_name, SK_KVA(fr),
				    ntohs(fr->fr_eth.ether_type),
				    fr->fr_eth.ether_shost[0],
				    fr->fr_eth.ether_shost[1],
				    fr->fr_eth.ether_shost[2],
				    fr->fr_eth.ether_shost[3],
				    fr->fr_eth.ether_shost[4],
				    fr->fr_eth.ether_shost[5],
				    fr->fr_eth.ether_dhost[0],
				    fr->fr_eth.ether_dhost[1],
				    fr->fr_eth.ether_dhost[2],
				    fr->fr_eth.ether_dhost[3],
				    fr->fr_eth.ether_dhost[4],
				    fr->fr_eth.ether_dhost[5],
				    sk_sa_ntop(dst, dst_s, sizeof(dst_s)));
			}
#endif /* SK_LOG */
			break;

		case ROUTE_LLENTRY_DELETED:
			/*
			 * If the route entry points to a router and an
			 * RTM_DELETE has been issued on it; force the
			 * flow route to be reconfigured.
			 */
			atomic_add_32(&fr->fr_want_configure, 1);
			atomic_bitclear_32(&fr->fr_flags,
			    (FLOWRTF_HAS_LLINFO | FLOWRTF_RESOLVED));
			SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s llentry deleted",
			    fm->fm_name, sk_sa_ntop(dst, dst_s,
			    sizeof(dst_s)));
			break;

		case ROUTE_LLENTRY_PROBED:
			/*
			 * When the resolver has begun probing the target;
			 * nothing to do here.
			 */
			SK_DF(SK_VERB_FLOW_ROUTE, "%s: dst %s llentry probed",
			    fm->fm_name, sk_sa_ntop(dst, dst_s,
			    sizeof(dst_s)));
			break;

		case ROUTE_LLENTRY_UNREACH:
			/*
			 * When the route entry is marked with RTF_REJECT
			 * or the probes have timed out, reconfigure.
			 */
			atomic_add_32(&fr->fr_want_configure, 1);
			atomic_bitclear_32(&fr->fr_flags, FLOWRTF_RESOLVED);
			SK_ERR("%s: dst %s llentry unreachable", fm->fm_name,
			    sk_sa_ntop(dst, dst_s, sizeof(dst_s)));
			break;

		default:
			break;
		}
	} while (0);

	if (fr != NULL) {
		flow_route_release(fr);
		FR_UNLOCK(fr);
	}

	if (frib != NULL) {
		FRIB_UNLOCK(frib);
	}

	if (fm != NULL) {
		flow_mgr_unlock();
	}
}

int
flow_route_select_laddr(union sockaddr_in_4_6 *src, union sockaddr_in_4_6 *dst,
    struct ifnet *ifp, struct rtentry *rt, uint32_t *ipaddr_gencnt,
    int use_stable_address)
{
#if SK_LOG
	char src_s[MAX_IPv6_STR_LEN];   /* src */
	char dst_s[MAX_IPv6_STR_LEN];   /* dst */
#endif /* SK_LOG */
	sa_family_t af = SA(dst)->sa_family;
	struct ifnet *src_ifp = NULL;
	struct ifaddr *ifa = NULL;
	int err = 0;

	/* see comments in flow_route_configure() regarding loopback */
	ASSERT(rt->rt_ifp == ifp || rt->rt_ifp == lo_ifp);

	switch (af) {
	case AF_INET: {
		ifnet_lock_shared(ifp);
		if (__improbable(rt->rt_ifa->ifa_debug & IFD_DETACHING) != 0) {
			err = EHOSTUNREACH;
			SK_ERR("route to %s has src address marked detaching "
			    "(err %d)", inet_ntop(AF_INET,
			    &SIN(dst)->sin_addr, dst_s, sizeof(dst_s)), err);
			ifnet_lock_done(ifp);
			break;
		}
		SIN(src)->sin_len = sizeof(struct sockaddr_in);
		SIN(src)->sin_family = AF_INET;
		SIN(src)->sin_addr = IA_SIN(rt->rt_ifa)->sin_addr;
		ASSERT(SIN(src)->sin_addr.s_addr != INADDR_ANY);
		*ipaddr_gencnt = ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt;
		ifnet_lock_done(ifp);
		break;
	}

	case AF_INET6: {
		struct in6_addr src_storage, *in6;
		struct route_in6 ro = {};
		uint32_t hints = (use_stable_address ? 0 : IPV6_SRCSEL_HINT_PREFER_TMPADDR);
		ro.ro_rt = rt;

		if ((in6 = in6_selectsrc_core(SIN6(dst), hints,
		    ifp, 0, &src_storage, &src_ifp, &err, &ifa, &ro)) == NULL) {
			if (err == 0) {
				err = EADDRNOTAVAIL;
			}
			VERIFY(src_ifp == NULL);
			SK_ERR("src address to dst %s on %s not available "
			    "(err %d)", inet_ntop(AF_INET6,
			    &SIN6(dst)->sin6_addr, dst_s, sizeof(dst_s)),
			    ifp->if_xname, err);
			break;
		}

		VERIFY(src_ifp != NULL);
		VERIFY(ifa != NULL);

		if (__improbable(src_ifp != ifp)) {
			if (err == 0) {
				err = ENETUNREACH;
			}
			SK_ERR("dst %s, src %s ifp %s != %s (err %d)",
			    inet_ntop(AF_INET6, &SIN6(dst)->sin6_addr,
			    dst_s, sizeof(dst_s)),
			    inet_ntop(AF_INET6, &SIN6(src)->sin6_addr,
			    src_s, sizeof(src_s)),
			    src_ifp->if_xname, ifp->if_xname, err);
			break;
		}

		ifnet_lock_shared(ifp);
		if (__improbable(ifa->ifa_debug & IFD_DETACHING) != 0) {
			err = EHOSTUNREACH;
			SK_ERR("IPv6 address selected is marked to be "
			    "detached (err %d)", err);
			ifnet_lock_done(ifp);
			break;
		}

		/* clear embedded scope if link-local src */
		if (IN6_IS_SCOPE_EMBED(in6)) {
			if (in6_embedded_scope) {
				SIN6(src)->sin6_scope_id = ntohs(in6->s6_addr16[1]);
				in6->s6_addr16[1] = 0;
			} else {
				SIN6(src)->sin6_scope_id = src_ifp->if_index;
			}
		}
		SIN6(src)->sin6_len = sizeof(struct sockaddr_in6);
		SIN6(src)->sin6_family = AF_INET6;
		SIN6(src)->sin6_addr = *in6;
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&SIN6(src)->sin6_addr));
		*ipaddr_gencnt = ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt;
		ifnet_lock_done(ifp);
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (ifa != NULL) {
		IFA_REMREF(ifa);
	}

	if (src_ifp != NULL) {
		ifnet_release(src_ifp);
	}

#if SK_LOG
	if (err == 0 && __improbable((sk_verbose & SK_VERB_FLOW_ROUTE) != 0)) {
		SK_DF(SK_VERB_FLOW_ROUTE, "src %s to dst %s on %s",
		    sk_sa_ntop(SA(src), src_s, sizeof(src_s)),
		    sk_sa_ntop(SA(dst), dst_s, sizeof(dst_s)),
		    ifp->if_xname);
	}
#endif /* SK_LOG */

	return err;
}

void
flow_route_cleanup(struct flow_route *fr)
{
#if SK_LOG
	char ss[MAX_IPv6_STR_LEN];      /* dst */
	char ds[MAX_IPv6_STR_LEN];      /* dst */
	char gs[MAX_IPv6_STR_LEN];      /* gw */
#endif /* SK_LOG */

	FR_LOCK_ASSERT_HELD(fr);

	if (fr->fr_rt_evhdlr_tag != NULL) {
		ASSERT(fr->fr_rt_dst != NULL);
		route_event_enqueue_nwk_wq_entry(fr->fr_rt_dst, NULL,
		    ROUTE_EVHDLR_DEREGISTER, fr->fr_rt_evhdlr_tag, FALSE);
		fr->fr_rt_evhdlr_tag = NULL;
		fr->fr_rt_dst = NULL;
	}
	ASSERT(fr->fr_rt_dst == NULL);
	if (fr->fr_rt_gw != NULL) {
		rtfree(fr->fr_rt_gw);
		fr->fr_rt_gw = NULL;
	}

#if SK_LOG
	if (fr->fr_flags & FLOWRTF_GATEWAY) {
		SK_DF(SK_VERB_FLOW_ROUTE,
		    "clean fr 0x%llx %s -> %s via gw %s", SK_KVA(fr),
		    sk_sa_ntop(SA(&fr->fr_laddr), ss, sizeof(ss)),
		    sk_sa_ntop(SA(&fr->fr_faddr), ds, sizeof(ds)),
		    sk_sa_ntop(SA(&fr->fr_gaddr), gs, sizeof(gs)));
	} else if (fr->fr_flags & FLOWRTF_ONLINK) {
		SK_DF(SK_VERB_FLOW_ROUTE,
		    "clean fr 0x%llx %s -> %s", SK_KVA(fr),
		    sk_sa_ntop(SA(&fr->fr_laddr), ss, sizeof(ss)),
		    sk_sa_ntop(SA(&fr->fr_faddr), ds, sizeof(ds)));
	}
#endif /* SK_LOG */

	atomic_bitclear_32(&fr->fr_flags, (FLOWRTF_GATEWAY | FLOWRTF_ONLINK));
}

static boolean_t
_flow_route_laddr_validate(struct flow_ip_addr *src_ip0, uint8_t ip_v,
    struct ifnet *ifp, uint32_t *gencnt)
{
	boolean_t address_found = TRUE;
	struct ifaddr *ifa = NULL;
	struct flow_ip_addr src_ip = {};
	uint32_t scope = ifp->if_index;

	VERIFY(gencnt != NULL);
	VERIFY(ip_v == IPVERSION || ip_v == IPV6_VERSION);

	if (ip_v == IPVERSION) {
		memcpy(&src_ip._v4, &src_ip0->_v4, sizeof(src_ip._v4));

		ifa = (struct ifaddr *)ifa_foraddr_scoped(
			src_ip._v4.s_addr, scope);
	} else {
		memcpy(&src_ip, src_ip0, sizeof(*src_ip0));

		if (in6_embedded_scope && IN6_IS_SCOPE_EMBED(&src_ip._v6)) {
			src_ip._v6.s6_addr16[1] = htons((uint16_t)scope);
		}
		ifa = (struct ifaddr *)ifa_foraddr6_scoped(&src_ip._v6,
		    scope);
	}

	if (__improbable(ifa == NULL)) {
		address_found = FALSE;
		goto done;
	}

	ifnet_lock_shared(ifp);
	if (__improbable(ifa->ifa_debug & IFD_DETACHING) != 0) {
		address_found = FALSE;
		ifnet_lock_done(ifp);
		goto done;
	}

	if (ip_v == IPV6_VERSION) {
		struct in6_ifaddr *ia6 = (struct in6_ifaddr *)ifa;

		/*
		 * Fail if IPv6 address is not ready or if the address
		 * is reserved * for CLAT46.
		 */
		if (__improbable(ia6->ia6_flags &
		    (IN6_IFF_NOTREADY | IN6_IFF_CLAT46)) != 0) {
			address_found = FALSE;
			ifnet_lock_done(ifp);
			goto done;
		}
	} else {
		/*
		 * If interface has CLAT46 enabled, fail IPv4 bind.
		 * Since this implies network is NAT64/DNS64, Internet
		 * effectively becomes reachable over IPv6.  If on
		 * system IPv4 to IPv6 translation is required, that
		 * should be handled solely through bump in the API.
		 * The in kernel translation is only done for apps
		 * directly using low level networking APIs.
		 */
		if (__improbable(IS_INTF_CLAT46(ifp))) {
			address_found = FALSE;
			ifnet_lock_done(ifp);
			goto done;
		}
	}

	*gencnt = ifp->if_nx_flowswitch.if_fsw_ipaddr_gencnt;
	ifnet_lock_done(ifp);
done:
	if (ifa != NULL) {
		IFA_REMREF(ifa);
	}

	return address_found;
}

boolean_t
flow_route_laddr_validate(union sockaddr_in_4_6 *saddr, struct ifnet *ifp,
    uint32_t *gencnt)
{
	VERIFY(saddr->sa.sa_family == AF_INET ||
	    saddr->sa.sa_family == AF_INET6);

	struct flow_ip_addr *ipa;
	uint8_t ipv;
	if (saddr->sa.sa_family == AF_INET) {
		ipv = IPVERSION;
		ipa = (struct flow_ip_addr *)(void *)&saddr->sin.sin_addr;
	} else {
		ipv = IPV6_VERSION;
		ipa = (struct flow_ip_addr *)(void *)&saddr->sin6.sin6_addr;
	}

	return _flow_route_laddr_validate(ipa, ipv, ifp, gencnt);
}

boolean_t
flow_route_key_validate(struct flow_key *fk, struct ifnet *ifp,
    uint32_t *gencnt)
{
	return _flow_route_laddr_validate(&fk->fk_src, fk->fk_ipver, ifp,
	           gencnt);
}
