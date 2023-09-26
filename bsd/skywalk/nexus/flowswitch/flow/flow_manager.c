/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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
#include <skywalk/os_skywalk.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/ip6_var.h>
#include <netkey/key.h>
#include <netinet/udp.h>

#include <skywalk/nexus/flowswitch/flow/flow_var.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif /* CONFIG_MACF */

#include <net/net_api_stats.h>

#define SKMEM_TAG_FSW_FLOW_MGR "com.apple.skywalk.fsw.flow_mgr"
static SKMEM_TAG_DEFINE(skmem_tag_fsw_flow_mgr, SKMEM_TAG_FSW_FLOW_MGR);

static LCK_GRP_DECLARE(flow_mgr_lock_group, "sk_flow_mgr_lock");
static LCK_RW_DECLARE(flow_mgr_lock, &flow_mgr_lock_group);

static int fm_cmp(const struct flow_mgr *,
    const struct flow_mgr *);

RB_HEAD(flow_mgr_tree, flow_mgr);
RB_PROTOTYPE_PREV(flow_mgr_tree, flow_mgr, fm_link, fm_cmp);
RB_GENERATE_PREV(flow_mgr_tree, flow_mgr, fm_link, fm_cmp);

/* protected by the global lock flow_mgr_lock */
static struct flow_mgr_tree flow_mgr_head;

static int __flow_mgr_inited = 0;

void
flow_mgr_init(void)
{
	ASSERT(!__flow_mgr_inited);

	RB_INIT(&flow_mgr_head);
	__flow_mgr_inited = 1;
}

void
flow_mgr_fini(void)
{
	if (__flow_mgr_inited) {
		VERIFY(RB_EMPTY(&flow_mgr_head));

		__flow_mgr_inited = 0;
	}
}

static int
__fe_cuckoo_cmp(struct cuckoo_node *node, void *key0)
{
	struct flow_entry *fe = container_of(node, struct flow_entry, fe_cnode);
	struct flow_key *key = key0;
	const struct flow_key *mask;

	/*
	 * This can probably be made more efficient by having "mask" be
	 * set by the original caller at the time the key is initialized,
	 * though that needs to be done carefully to ensure there is no
	 * mismatch between fk_mask value and "mask" itself.
	 */
	switch (key->fk_mask) {
	case FKMASK_5TUPLE:
		mask = &fk_mask_5tuple;
		break;
	case FKMASK_4TUPLE:
		mask = &fk_mask_4tuple;
		break;
	case FKMASK_3TUPLE:
		mask = &fk_mask_3tuple;
		break;
	case FKMASK_2TUPLE:
		mask = &fk_mask_2tuple;
		break;
	case FKMASK_IPFLOW3:
		mask = &fk_mask_ipflow3;
		break;
	case FKMASK_IPFLOW2:
		mask = &fk_mask_ipflow2;
		break;
	case FKMASK_IPFLOW1:
		mask = &fk_mask_ipflow1;
		break;
	default:
		return flow_key_cmp(&fe->fe_key, key);
	}

	return flow_key_cmp_mask(&fe->fe_key, key, mask);
}

static void
__fe_cuckoo_retain(struct cuckoo_node *node)
{
	struct flow_entry *fe = container_of(node, struct flow_entry, fe_cnode);
	return flow_entry_retain(fe);
}

static void
__fe_cuckoo_release(struct cuckoo_node *node)
{
#pragma unused(node)
	struct flow_entry *fe = container_of(node, struct flow_entry, fe_cnode);
	flow_entry_release(&fe);
}

struct flow_mgr *
flow_mgr_create(size_t fe_cnt, size_t fob_cnt,
    size_t frb_cnt, size_t frib_cnt)
{
	struct flow_mgr *fm = NULL;
	size_t fob_sz, frb_sz, frib_sz;
	size_t fob_tot_sz, frb_tot_sz, frib_tot_sz;
	uint32_t i;

	/* caller needs to ensure {fb,frb}_cnt is a power of two */
	ASSERT(frb_cnt != 0 && ((frb_cnt & (frb_cnt - 1)) == 0));
	ASSERT(fob_cnt != 0);
	ASSERT(frib_cnt != 0);

	fm = sk_alloc_type(struct flow_mgr, Z_WAITOK | Z_NOFAIL, skmem_tag_fsw_flow_mgr);

	struct cuckoo_hashtable_params p = {
		.cht_capacity = fe_cnt,
		.cht_obj_cmp = __fe_cuckoo_cmp,
		.cht_obj_retain = __fe_cuckoo_retain,
		.cht_obj_release = __fe_cuckoo_release,
	};
	fm->fm_flow_table = cuckoo_hashtable_create(&p);
	if (fm->fm_flow_table == NULL) {
		flow_mgr_destroy(fm);
		return NULL;
	}

	/*
	 * flow_owner_bucket cache-aligned objects.
	 */
	fm->fm_owner_buckets = flow_owner_buckets_alloc(fob_cnt, &fob_sz, &fob_tot_sz);
	if (fm->fm_owner_buckets == NULL) {
		flow_mgr_destroy(fm);
		return NULL;
	}
	/* const overrides */
	*(size_t *)(uintptr_t)&fm->fm_owner_buckets_cnt = fob_cnt;
	*(size_t *)(uintptr_t)&fm->fm_owner_bucket_sz = fob_sz;
	*(size_t *)(uintptr_t)&fm->fm_owner_bucket_tot_sz = fob_tot_sz;

	/*
	 * flow_route_bucket cache-aligned objects.
	 */
	fm->fm_route_buckets = flow_route_buckets_alloc(frb_cnt, &frb_sz, &frb_tot_sz);
	if (fm->fm_route_buckets == NULL) {
		flow_mgr_destroy(fm);
		return NULL;
	}
	/* const overrides */
	*(size_t *)(uintptr_t)&fm->fm_route_buckets_cnt = frb_cnt;
	*(size_t *)(uintptr_t)&fm->fm_route_bucket_sz = frb_sz;
	*(size_t *)(uintptr_t)&fm->fm_route_bucket_tot_sz = frb_tot_sz;

	/*
	 * flow_route_id_bucket cache-aligned objects.
	 */
	fm->fm_route_id_buckets =
	    flow_route_id_buckets_alloc(frib_cnt, &frib_sz, &frib_tot_sz);
	if (fm->fm_route_id_buckets == NULL) {
		flow_mgr_destroy(fm);
		return NULL;
	}
	/* const overrides */
	*(size_t *)(uintptr_t)&fm->fm_route_id_buckets_cnt = frib_cnt;
	*(size_t *)(uintptr_t)&fm->fm_route_id_bucket_sz = frib_sz;
	*(size_t *)(uintptr_t)&fm->fm_route_id_bucket_tot_sz = frib_tot_sz;

	/* construct flow_owner_buckets */
	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		struct flow_owner_bucket *fob = flow_mgr_get_fob_at_idx(fm, i);
		flow_owner_bucket_init(fob);
		/* const override */
		*(size_t *)(uintptr_t)&fob->fob_idx = i;
	}

	/* construct flow_route_buckets */
	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		struct flow_route_bucket *frb = flow_mgr_get_frb_at_idx(fm, i);
		flow_route_bucket_init(frb);
		/* const override */
		*(size_t *)(uintptr_t)&frb->frb_idx = i;
	}

	/* construct flow_route_id_buckets */
	for (i = 0; i < fm->fm_route_id_buckets_cnt; i++) {
		struct flow_route_id_bucket *frib =
		    flow_mgr_get_frib_at_idx(fm, i);
		flow_route_id_bucket_init(frib);
		/* const override */
		*(size_t *)(uintptr_t)&frib->frib_idx = i;
	}

	uuid_generate_random(fm->fm_uuid);

	lck_rw_lock_exclusive(&flow_mgr_lock);
	RB_INSERT(flow_mgr_tree, &flow_mgr_head, fm);
#if DEBUG
	struct flow_mgr find;
	uuid_copy(find.fm_uuid, fm->fm_uuid);
	/* make sure our tree compare routine is sane */
	ASSERT(RB_FIND(flow_mgr_tree,
	    &flow_mgr_head, &find) == fm);
#endif /* DEBUG */
	lck_rw_done(&flow_mgr_lock);

	fm->fm_flow_hash_masks[0] = FKMASK_5TUPLE;
	fm->fm_flow_hash_masks[1] = FKMASK_4TUPLE;
	fm->fm_flow_hash_masks[2] = FKMASK_3TUPLE;
	fm->fm_flow_hash_masks[3] = FKMASK_2TUPLE;
	fm->fm_flow_hash_masks[4] = FKMASK_IPFLOW3;
	fm->fm_flow_hash_masks[5] = FKMASK_IPFLOW2;
	fm->fm_flow_hash_masks[6] = FKMASK_IPFLOW1;

	memset(&fm->fm_flow_hash_count, 0, sizeof(fm->fm_flow_hash_count));

	return fm;
}

void
flow_mgr_destroy(struct flow_mgr *fm)
{
	uint32_t i;

	lck_rw_lock_exclusive(&flow_mgr_lock);
	ASSERT(!uuid_is_null(fm->fm_uuid));

	if (fm->fm_flow_table != NULL) {
		cuckoo_hashtable_free(fm->fm_flow_table);
	}

	if (fm->fm_owner_buckets != NULL) {
		for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
			struct flow_owner_bucket *fob =
			    flow_mgr_get_fob_at_idx(fm, i);
			ASSERT(fob->fob_idx == i);
			flow_owner_bucket_destroy(fob);
		}
		flow_owner_buckets_free(fm->fm_owner_buckets,
		    fm->fm_owner_bucket_tot_sz);
		fm->fm_owner_buckets = NULL;
		*(uint32_t *)(uintptr_t)&fm->fm_owner_buckets_cnt = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_owner_bucket_sz = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_owner_bucket_tot_sz = 0;
	}
	ASSERT(fm->fm_owner_buckets_cnt == 0);
	ASSERT(fm->fm_owner_bucket_sz == 0);
	ASSERT(fm->fm_owner_bucket_tot_sz == 0);

	if (fm->fm_route_buckets != NULL) {
		for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
			struct flow_route_bucket *frb =
			    flow_mgr_get_frb_at_idx(fm, i);
			ASSERT(frb->frb_idx == i);
			flow_route_bucket_destroy(frb);
		}
		flow_route_buckets_free(fm->fm_route_buckets,
		    fm->fm_route_bucket_tot_sz);
		fm->fm_route_buckets = NULL;
		*(uint32_t *)(uintptr_t)&fm->fm_route_buckets_cnt = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_route_bucket_sz = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_route_bucket_tot_sz = 0;
	}
	ASSERT(fm->fm_route_buckets_cnt == 0);
	ASSERT(fm->fm_route_bucket_sz == 0);
	ASSERT(fm->fm_route_bucket_tot_sz == 0);

	if (fm->fm_route_id_buckets != NULL) {
		for (i = 0; i < fm->fm_route_id_buckets_cnt; i++) {
			struct flow_route_id_bucket *frib =
			    flow_mgr_get_frib_at_idx(fm, i);
			ASSERT(frib->frib_idx == i);
			flow_route_id_bucket_destroy(frib);
		}
		flow_route_id_buckets_free(fm->fm_route_id_buckets,
		    fm->fm_route_id_bucket_tot_sz);
		fm->fm_route_id_buckets = NULL;
		*(uint32_t *)(uintptr_t)&fm->fm_route_id_buckets_cnt = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_route_id_bucket_sz = 0;
		*(uint32_t *)(uintptr_t)&fm->fm_route_id_bucket_tot_sz = 0;
	}
	ASSERT(fm->fm_route_id_buckets_cnt == 0);
	ASSERT(fm->fm_route_id_bucket_sz == 0);
	ASSERT(fm->fm_route_id_bucket_tot_sz == 0);

	uuid_clear(fm->fm_uuid);
	RB_REMOVE(flow_mgr_tree, &flow_mgr_head, fm);
	lck_rw_done(&flow_mgr_lock);

	sk_free_type(struct flow_mgr, fm);
}

void
flow_mgr_terminate(struct flow_mgr *fm)
{
	uint32_t i;

	/*
	 * Purge all flow entries.
	 */
	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		struct flow_owner_bucket *fob =
		    flow_mgr_get_fob_at_idx(fm, i);
		FOB_LOCK(fob);
		fob->fob_busy_flags |= FOBF_DEAD;
	}
	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		struct flow_owner_bucket *fob =
		    flow_mgr_get_fob_at_idx(fm, i);
		SK_DF(SK_VERB_FLOW, "purging fob 0x%llx [%u]", SK_KVA(fob), i);
		flow_owner_bucket_purge_all(fob);
	}

	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		FOB_UNLOCK(flow_mgr_get_fob_at_idx(fm, i));
	}

	/*
	 * Purge all flow routes.
	 */
	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		struct flow_route_bucket *frb =
		    flow_mgr_get_frb_at_idx(fm, i);
		FRB_WLOCK(frb);
	}
	for (i = 0; i < fm->fm_route_id_buckets_cnt; i++) {
		FRIB_WLOCK(flow_mgr_get_frib_at_idx(fm, i));
	}

	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		struct flow_route_bucket *frb =
		    flow_mgr_get_frb_at_idx(fm, i);
		SK_DF(SK_VERB_FLOW, "purging frb 0x%llx [%u]", SK_KVA(frb), i);
		flow_route_bucket_purge_all(frb);
	}

	for (i = 0; i < fm->fm_route_id_buckets_cnt; i++) {
		FRIB_WUNLOCK(flow_mgr_get_frib_at_idx(fm, i));
	}
	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		FRB_WUNLOCK(flow_mgr_get_frb_at_idx(fm, i));
	}
}

/*
 * Must be matched with a call to flow_mgr_unlock().  Upon success will
 * return the flow manager address of the specified UUID, and will acquire
 * the global flow_mgr_lock as reader.  The caller is then expected to release
 * the lock.
 */
struct flow_mgr *
flow_mgr_find_lock(uuid_t uuid)
{
	struct flow_mgr *fm, find;

	uuid_copy(find.fm_uuid, uuid);

	lck_rw_lock_shared(&flow_mgr_lock);

	fm = RB_FIND(flow_mgr_tree, &flow_mgr_head, &find);
	if (fm == NULL) {
		lck_rw_done(&flow_mgr_lock);
		return NULL;
	}

	/* caller is expected to call flow_mgr_unlock() when done */
	LCK_RW_ASSERT(&flow_mgr_lock, LCK_RW_ASSERT_SHARED);
	return fm;
}

/*
 * Must be matched with a successful call to flow_mgr_find_lock().
 */
void
flow_mgr_unlock(void)
{
	lck_rw_done(&flow_mgr_lock);
}

static inline int
fm_cmp(const struct flow_mgr *a, const struct flow_mgr *b)
{
	return uuid_compare(a->fm_uuid, b->fm_uuid);
}

static void
flow_mgr_clear_embedded_scope_id(struct sockaddr_in6 *addr)
{
	struct in6_addr *in6;
	in6 = &addr->sin6_addr;
	if (in6_embedded_scope && IN6_IS_SCOPE_EMBED(in6)) {
		addr->sin6_scope_id = ntohs(in6->s6_addr16[1]);
		in6->s6_addr16[1] = 0;
	}
}

#if CONFIG_MACF
static bool
flow_req_check_mac_allowed(struct nx_flow_req *req)
{
	int socktype;
	switch (req->nfr_ip_protocol) {
	case IPPROTO_TCP:
		socktype = SOCK_STREAM;
		break;

	case IPPROTO_UDP:
		socktype = SOCK_DGRAM;
		break;

	default:
		/* Custom IP protocol, which is treated as IP diagram type */
		socktype = SOCK_DGRAM;
		return 0;
	}

	if (req->nfr_flags & NXFLOWREQF_LISTENER) {
		return mac_skywalk_flow_check_listen(req->nfr_proc, NULL,
		           SA(&req->nfr_saddr.sa), socktype, req->nfr_ip_protocol);
	} else {
		return mac_skywalk_flow_check_connect(req->nfr_proc, NULL,
		           SA(&req->nfr_daddr.sa), socktype, req->nfr_ip_protocol);
	}
}
#endif /* CONFIG_MACF */

static bool
flow_req_needs_netns_reservation(struct nx_flow_req *req)
{
	uint8_t proto = req->nfr_ip_protocol;
	return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

static bool
flow_req_needs_protons_reservation(struct nx_flow_req *req)
{
	uint8_t proto = req->nfr_ip_protocol;
	return proto != IPPROTO_TCP && proto != IPPROTO_UDP &&
	       proto != IPPROTO_ESP && proto != IPPROTO_AH;
}

static bool
flow_req_needs_ipsec_reservation(struct nx_flow_req *req)
{
	uint8_t proto = req->nfr_ip_protocol;
	return proto == IPPROTO_ESP || proto == IPPROTO_AH;
}

static void
flow_set_port_info(struct ns_flow_info *nfi, struct nx_flow_req *req)
{
	union sockaddr_in_4_6 *saddr = &req->nfr_saddr;
	union sockaddr_in_4_6 *daddr = &req->nfr_daddr;

	bzero(nfi, sizeof(struct ns_flow_info));

	nfi->nfi_ifp = req->nfr_ifp;

	nfi->nfi_laddr = *saddr;
	nfi->nfi_faddr = *daddr;

	nfi->nfi_protocol = req->nfr_ip_protocol;

	uuid_copy(nfi->nfi_flow_uuid, req->nfr_flow_uuid);
	ASSERT(!uuid_is_null(nfi->nfi_flow_uuid));

	nfi->nfi_owner_pid = req->nfr_pid;
	if (req->nfr_epid != -1) {
		nfi->nfi_effective_pid = req->nfr_epid;
		proc_name(req->nfr_epid, nfi->nfi_effective_name,
		    sizeof(nfi->nfi_effective_name));
	} else {
		nfi->nfi_effective_pid = -1;
	}

	proc_name(req->nfr_pid, nfi->nfi_owner_name,
	    sizeof(nfi->nfi_owner_name));
}

static int
flow_req_prepare_namespace(struct nx_flow_req *req)
{
	SK_LOG_VAR(char src_s[MAX_IPv6_STR_LEN]);
	int err = 0;

	if (flow_req_needs_netns_reservation(req)) {
		if (!NETNS_TOKEN_VALID(&req->nfr_port_reservation)) {
			union sockaddr_in_4_6 *saddr = &req->nfr_saddr;
			struct ns_flow_info nfi;
			netns_token ns_token;
			flow_set_port_info(&nfi, req);
			err = flow_namespace_create(saddr,
			    req->nfr_ip_protocol, &ns_token,
			    req->nfr_flags, &nfi);
			if (err != 0) {
				SK_ERR("netns for %s.%u failed",
				    sk_sa_ntop(SA(saddr), src_s, sizeof(src_s)),
				    sk_sa_get_port(SA(saddr)));
				goto fail;
			}
			req->nfr_port_reservation = ns_token;
			req->nfr_flags &= ~NXFLOWREQF_EXT_PORT_RSV;
		} else {
			/* Validate PID associated with provided reservation */
			struct ns_flow_info nfi = {};
			err = netns_get_flow_info(&req->nfr_port_reservation,
			    &nfi);
			/* flow info could be NULL for socket flow */
			if (!err && (req->nfr_pid != nfi.nfi_owner_pid ||
			    (req->nfr_epid != -1 && nfi.nfi_effective_pid !=
			    req->nfr_epid))) {
				SK_ERR("netns flow info mismatch, "
				    "req_(e)pid %d(%d), nfr_(e)pid %d(%d)",
				    req->nfr_pid, req->nfr_epid,
				    nfi.nfi_owner_pid, nfi.nfi_effective_pid);
				err = EPERM;
				goto fail;
			}
			req->nfr_flags |= NXFLOWREQF_EXT_PORT_RSV;
		}
	}

	if (flow_req_needs_ipsec_reservation(req)) {
		union sockaddr_in_4_6 *saddr = &req->nfr_saddr;
		union sockaddr_in_4_6 *daddr = &req->nfr_daddr;
		void *ipsec_token = NULL;
		ASSERT(req->nfr_ipsec_reservation == NULL);
		err = key_reserve_custom_ipsec(&ipsec_token, saddr,
		    daddr, req->nfr_ip_protocol);
		if (err != 0) {
			SK_ERR("custom ipsec %u reserve %s failed",
			    req->nfr_ip_protocol,
			    sk_sa_ntop(SA(saddr), src_s, sizeof(src_s)));
			goto fail;
		}
		req->nfr_ipsec_reservation = ipsec_token;
	}

	if (flow_req_needs_protons_reservation(req)) {
		struct protons_token *ns_token = NULL;
		if (!protons_token_is_valid(req->nfr_proto_reservation)) {
			err = protons_reserve(&ns_token, req->nfr_pid,
			    req->nfr_epid, req->nfr_ip_protocol);
			if (err != 0) {
				SK_ERR("protocol %u namespace failed",
				    req->nfr_ip_protocol);
				goto fail;
			}
			req->nfr_flags &= ~NXFLOWREQF_EXT_PROTO_RSV;
			req->nfr_proto_reservation = ns_token;
		} else {
			/* Validate PID associated with provided reservation */
			if (!protons_token_has_matching_pid(req->nfr_proto_reservation,
			    req->nfr_pid, req->nfr_epid)) {
				SK_ERR("protons token pid mismatch");
				err = EPERM;
				goto fail;
			}
			req->nfr_flags |= NXFLOWREQF_EXT_PROTO_RSV;
		}
	}

	return 0;

fail:
	VERIFY(err != 0);
	SK_ERR("perparation failed (err %d)", err);
	return err;
}

static int
flow_req_prepare(struct nx_flow_req *req, struct kern_nexus *nx,
    struct flow_mgr *fm, struct ifnet *ifp, flow_route_ctor_fn_t fr_ctor,
    flow_route_resolve_fn_t fr_resolve, void *fr_arg)
{
	int err = 0;
	union sockaddr_in_4_6 *saddr = &req->nfr_saddr;
	union sockaddr_in_4_6 *daddr = &req->nfr_daddr;
	uint8_t protocol = req->nfr_ip_protocol;

	sa_family_t saf, daf, xaf, af;

	saf = SA(saddr)->sa_family;
	daf = SA(daddr)->sa_family;
	xaf = saf ^ daf;
	if (xaf != 0 && xaf != saf && xaf != daf) {
		SK_ERR("invalid saddr af %d daddr af %d", saf, daf);
		return EINVAL;
	}
	af = (xaf == 0) ? saf : xaf;

	bool has_saddr = false, has_daddr = false;
	bool has_sport = false, has_dport = false;
	uint16_t sport, dport;
	uint8_t sa_len;
	switch (af) {
	case AF_INET:
		sa_len = sizeof(struct sockaddr_in);
		has_saddr = (SIN(saddr)->sin_addr.s_addr != INADDR_ANY);
		has_daddr = (SIN(daddr)->sin_addr.s_addr != INADDR_ANY);
		sport = SIN(saddr)->sin_port;
		dport = SIN(daddr)->sin_port;
		has_sport = (sport != 0);
		has_dport = (dport != 0);

		if ((has_saddr && SIN(saddr)->sin_len != sa_len) ||
		    (has_daddr && SIN(daddr)->sin_len != sa_len)) {
			SK_ERR("sin_len invalid");
			err = EINVAL;
			goto fail;
		}
		if ((has_saddr && IN_MULTICAST(ntohl(SIN(saddr)->sin_addr.s_addr))) ||
		    (has_daddr && IN_MULTICAST(ntohl(SIN(daddr)->sin_addr.s_addr)))) {
			SK_ERR("multicast flow not yet supported");
			err = EADDRNOTAVAIL;
			goto fail;
		}
		if (__probable(protocol == IPPROTO_TCP)) {
			INC_ATOMIC_INT64_LIM(
				net_api_stats.nas_nx_flow_inet6_stream_total);
		} else {
			INC_ATOMIC_INT64_LIM(
				net_api_stats.nas_nx_flow_inet6_dgram_total);
		}
		break;

	case AF_INET6:
		sa_len = sizeof(struct sockaddr_in6);
		has_saddr = !IN6_IS_ADDR_UNSPECIFIED(&SIN6(saddr)->sin6_addr);
		has_daddr = !IN6_IS_ADDR_UNSPECIFIED(&SIN6(daddr)->sin6_addr);
		sport = SIN6(saddr)->sin6_port;
		dport = SIN6(daddr)->sin6_port;
		has_sport = (sport != 0);
		has_dport = (dport != 0);
		if ((has_saddr && SIN6(saddr)->sin6_len != sa_len) ||
		    (has_daddr && SIN6(daddr)->sin6_len != sa_len)) {
			SK_ERR("sin_len invalid");
			err = EINVAL;
			goto fail;
		}
		/* clear embedded scope if link-local src */
		if (has_saddr) {
			flow_mgr_clear_embedded_scope_id(SIN6(saddr));
			if (!in6_embedded_scope && IN6_IS_SCOPE_EMBED(&SIN6(saddr)->sin6_addr)) {
				SIN6(saddr)->sin6_scope_id = ifp->if_index;
			}
		}
		if (has_daddr) {
			flow_mgr_clear_embedded_scope_id(SIN6(daddr));
			if (!in6_embedded_scope && IN6_IS_SCOPE_EMBED(&SIN6(daddr)->sin6_addr)) {
				SIN6(daddr)->sin6_scope_id = ifp->if_index;
			}
		}
		if ((has_saddr && IN6_IS_ADDR_MULTICAST(&SIN6(saddr)->sin6_addr)) ||
		    (has_daddr && IN6_IS_ADDR_MULTICAST(&SIN6(daddr)->sin6_addr))) {
			SK_ERR("multicast flow not yet supported");
			err = EADDRNOTAVAIL;
			goto fail;
		}
		if (__probable(protocol == IPPROTO_TCP)) {
			INC_ATOMIC_INT64_LIM(
				net_api_stats.nas_nx_flow_inet_stream_total);
		} else {
			INC_ATOMIC_INT64_LIM(
				net_api_stats.nas_nx_flow_inet_dgram_total);
		}
		break;

	default:
		SK_ERR("unknown address families saf %d daf %d", saf, daf);
		err = EINVAL;
		goto fail;
	}

	SA(saddr)->sa_family = SA(daddr)->sa_family = af;
	SA(saddr)->sa_len = SA(daddr)->sa_len = sa_len;

	if (__improbable(has_saddr && !flow_route_laddr_validate(saddr, ifp,
	    &req->nfr_saddr_gencnt))) {
		SK_LOG_VAR(char src_s[MAX_IPv6_STR_LEN]);
		SK_ERR("src address %s is not valid",
		    sk_sa_ntop(SA(saddr), src_s, sizeof(src_s)));
		err = EADDRNOTAVAIL;
		goto fail;
	}

	bool is_tcp_udp = (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
	if (!is_tcp_udp) {
		if (has_sport || has_dport) {
			SK_ERR("non-zero port for IP flow");
			return EINVAL;
		}
	} else {
		/* dst:dport as connected, 0:0 as listener, but not partial */
		if (has_daddr != has_dport) {
			err = EINVAL;
			SK_ERR("invalid dst/dport for TCP/UDP (err %d)", err);
			goto fail;
		}
	}

	if (!has_daddr && !has_dport) {
		req->nfr_flags |= NXFLOWREQF_LISTENER;
	}

	if (req->nfr_transport_protocol == 0) {
		req->nfr_transport_protocol = req->nfr_ip_protocol;
	}

	bool is_child_flow = !uuid_is_null(req->nfr_parent_flow_uuid);
	if ((is_child_flow && req->nfr_flow_demux_count == 0) ||
	    (!is_child_flow && req->nfr_flow_demux_count > 0)) {
		err = EINVAL;
		SK_ERR("invalid flow demux count");
		goto fail;
	}

	if (req->nfr_flow_demux_count > 0) {
		if (req->nfr_transport_protocol != IPPROTO_UDP) {
			err = EINVAL;
			SK_ERR("invalid transport protocol(%u) for flow demux",
			    req->nfr_transport_protocol);
			goto fail;
		}

		for (int i = 0; i < req->nfr_flow_demux_count; i++) {
			if (req->nfr_flow_demux_patterns[i].fdp_len > FLOW_DEMUX_MAX_LEN ||
			    req->nfr_flow_demux_patterns[i].fdp_len == 0) {
				err = EINVAL;
				SK_ERR("invalid flow demux pattern len %u",
				    req->nfr_flow_demux_patterns[i].fdp_len);
				goto fail;
			}
			if (req->nfr_flow_demux_patterns[i].fdp_offset +
			    req->nfr_flow_demux_patterns[i].fdp_len > MAX_PKT_DEMUX_LIMIT) {
				err = EINVAL;
				SK_ERR("invalid demux offset plus length(%u > %d)",
				    req->nfr_flow_demux_patterns[i].fdp_offset +
				    req->nfr_flow_demux_patterns[i].fdp_len, MAX_PKT_DEMUX_LIMIT);
				goto fail;
			}
		}
	}

	req->nfr_ifp = ifp;

#if CONFIG_MACF
	err = flow_req_check_mac_allowed(req);
	if (err != 0) {
		SK_ERR("flow req failed MAC check");
		goto fail;
	}
#endif /* CONFIG_MACF */

	/* setup flow route and prepare saddr if needed */
	if (__probable(has_daddr || has_dport)) {
		struct flow_route *fr = NULL;
		err = flow_route_find(nx, fm, ifp, req, fr_ctor,
		    fr_resolve, fr_arg, &fr);
		if (__improbable(err != 0)) {
			SK_ERR("flow route lookup failed");
			ASSERT(fr == NULL);
			goto fail;
		}
		ASSERT(fr != NULL);
		/* Pick up the default source address from flow route. */
		if (!has_saddr) {
			*saddr = fr->fr_laddr;
			SIN(saddr)->sin_port = sport;
		}
		req->nfr_route = fr;
		fr = NULL;
	}

	/* child flow do not hold namespace references */
	if (__probable(uuid_is_null(req->nfr_parent_flow_uuid))) {
		err = flow_req_prepare_namespace(req);
		if (err != 0) {
			goto fail;
		}
	}

	return 0;

fail:
	VERIFY(err != 0);
	if (req->nfr_route != NULL) {
		flow_route_release(req->nfr_route);
		req->nfr_route = NULL;
	}
	SK_ERR("preparation failed (err %d)", err);
	return err;
}

static void
flow_req_cleanup(struct nx_flow_req *req)
{
	if (NETNS_TOKEN_VALID(&req->nfr_port_reservation) &&
	    !(req->nfr_flags & NXFLOWREQF_EXT_PORT_RSV)) {
		netns_release(&req->nfr_port_reservation);
	}

	if (protons_token_is_valid(req->nfr_proto_reservation) &&
	    !(req->nfr_flags & NXFLOWREQF_EXT_PROTO_RSV)) {
		protons_release(&req->nfr_proto_reservation);
	}

	if (key_custom_ipsec_token_is_valid(req->nfr_ipsec_reservation)) {
		key_release_custom_ipsec(&req->nfr_ipsec_reservation);
	}
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
flow_req_dump(char *desc, struct nx_flow_req *req)
{
	if (!(sk_verbose & SK_VERB_FLOW)) {
		return;
	}

	union sockaddr_in_4_6 *saddr = &req->nfr_saddr;
	union sockaddr_in_4_6 *daddr = &req->nfr_daddr;
	uint8_t protocol = req->nfr_ip_protocol;
	char src_s[MAX_IPv6_STR_LEN];
	char dst_s[MAX_IPv6_STR_LEN];
	uint8_t sipver = 0, dipver = 0;
	uint16_t sport = 0, dport = 0;
	uuid_string_t uuid_s;

	// unsanitized req, treat source and destination AF separately
	if (saddr->sa.sa_family == AF_INET) {
		sipver = IPVERSION;
		(void) inet_ntop(AF_INET, &SIN(saddr)->sin_addr, src_s,
		    sizeof(src_s));
		sport = ntohs(saddr->sin.sin_port);
	} else if (saddr->sa.sa_family == AF_INET6) {
		sipver = IPV6_VERSION;
		(void) inet_ntop(AF_INET6, &SIN6(saddr)->sin6_addr, src_s,
		    sizeof(src_s));
		sport = ntohs(saddr->sin6.sin6_port);
	} else {
		sipver = 0;
		strlcpy(src_s, "INV", sizeof(src_s));
	}
	if (daddr->sa.sa_family == AF_INET) {
		dipver = IPVERSION;
		(void) inet_ntop(AF_INET, &SIN(daddr)->sin_addr, dst_s,
		    sizeof(dst_s));
		dport = ntohs(daddr->sin.sin_port);
	} else if (daddr->sa.sa_family == AF_INET6) {
		dipver = IPV6_VERSION;
		(void) inet_ntop(AF_INET6, &SIN6(daddr)->sin6_addr, dst_s,
		    sizeof(dst_s));
		dport = ntohs(daddr->sin6.sin6_port);
	} else {
		dipver = 0;
		strlcpy(dst_s, "INV", sizeof(src_s));
	}

	SK_DF(SK_VERB_FLOW,
	    "%s %s sipver=%u,dipver=%u,src=%s,dst=%s,proto=%d,sport=%u,dport=%d"
	    " nx_port=%u,flags 0x%b", desc, sk_uuid_unparse(req->nfr_flow_uuid,
	    uuid_s), sipver, dipver, src_s, dst_s, protocol, sport, dport,
	    req->nfr_nx_port, req->nfr_flags, NXFLOWREQF_BITS);
}
#else
#define flow_req_dump(str, req) do { ((void)0); } while (0)
#endif /* SK_LOG */

/*
 * Upon success, returns a non-NULL fb that is (writer) locked.
 */
int
flow_mgr_flow_add(struct kern_nexus *nx, struct flow_mgr *fm,
    struct flow_owner *fo, struct ifnet *ifp, struct nx_flow_req *req,
    flow_route_ctor_fn_t fr_ctor, flow_route_resolve_fn_t fr_resolve,
    void *fr_arg)
{
	struct flow_entry *fe;
	int err = 0;

	ASSERT(ifp != NULL);
	ASSERT(fr_ctor != NULL && fr_resolve != NULL);
	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));

	flow_req_dump("req", req);

	if (!(req->nfr_flags & NXFLOWREQF_ASIS)) {
		err = flow_req_prepare(req, nx, fm, ifp, fr_ctor, fr_resolve, fr_arg);
		if (err != 0) {
			SK_ERR("flow req preparation failure (err %d)", err);
			return err;
		}
	}

	/*
	 * Add entry in flowswitch table; upon success, flow entry adds a
	 * retain count on the flow route (we'll always need to release the
	 * refcnt from flow_route_find), and the local address:port of the
	 * flow entry will be set.
	 */
	fe = flow_entry_alloc(fo, req, &err);
	if (__improbable(fe == NULL)) {
		ASSERT(err != 0);
		goto fail;
	}

	VERIFY(NETNS_TOKEN_VALID(&fe->fe_port_reservation) ||
	    !(fe->fe_key.fk_mask & FKMASK_SPORT) ||
	    req->nfr_flags & NXFLOWREQF_ASIS ||
	    (fe->fe_flags & FLOWENTF_CHILD));
	VERIFY((req->nfr_flags & NXFLOWREQF_FLOWADV) ^
	    (req->nfr_flowadv_idx == FLOWADV_IDX_NONE));
	req->nfr_flowadv_idx = fe->fe_adv_idx;

	flow_req_dump("added ", req);

	if (fe != NULL) {
		flow_entry_release(&fe);
	}

	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	if (req->nfr_saddr.sa.sa_family == AF_INET6 &&
	    IN6_IS_SCOPE_EMBED(&req->nfr_saddr.sin6.sin6_addr)) {
		req->nfr_saddr.sin6.sin6_scope_id = ifnet_index(
			fsw->fsw_ifp);
	}
	if (req->nfr_daddr.sa.sa_family == AF_INET6 &&
	    IN6_IS_SCOPE_EMBED(&req->nfr_daddr.sin6.sin6_addr)) {
		req->nfr_daddr.sin6.sin6_scope_id = ifnet_index(
			fsw->fsw_ifp);
	}

	return 0;

fail:
	VERIFY(err != 0);
	flow_req_cleanup(req);

	return err;
}

struct flow_owner_bucket *
flow_mgr_get_fob_by_pid(struct flow_mgr *fm, pid_t pid)
{
	return flow_mgr_get_fob_at_idx(fm,
	           (pid % fm->fm_owner_buckets_cnt));
}

struct flow_entry *
flow_mgr_get_fe_by_uuid_rlock(struct flow_mgr *fm, uuid_t uuid)
{
	uint32_t i;
	struct flow_owner_bucket *fob;
	struct flow_owner *fo;
	struct flow_entry *fe;

	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		fob = flow_mgr_get_fob_at_idx(fm, i);
		FOB_LOCK_SPIN(fob);
		RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
			fe = flow_entry_find_by_uuid(fo, uuid);
			if (fe != NULL) {
				FOB_LOCK_CONVERT(fob);
				FOB_UNLOCK(fob);
				return fe;
			}
		}
		FOB_UNLOCK(fob);
	}
	return NULL;
}

struct flow_route_bucket *
flow_mgr_get_frb_by_addr(struct flow_mgr *fm,
    union sockaddr_in_4_6 *daddr)
{
	uint32_t a = 0x9e3779b9, b = 0x9e3779b9, c = flow_seed;

	switch (SA(daddr)->sa_family) {
	case AF_INET: {
		uint8_t *p = (uint8_t *)&SIN(daddr)->sin_addr.s_addr;
		b += ((uint32_t)p[3]);
		a += ((uint32_t)p[2]) << 24;
		a += ((uint32_t)p[1]) << 16;
		a += ((uint32_t)p[0]) << 8;
		break;
	}

	case AF_INET6: {
		b += SIN6(daddr)->sin6_addr.s6_addr32[3];
		a += SIN6(daddr)->sin6_addr.s6_addr32[2];
		a += SIN6(daddr)->sin6_addr.s6_addr32[1];
		a += SIN6(daddr)->sin6_addr.s6_addr32[0];
		break;
	}

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* mix */
	a -= b; a -= c; a ^= (c >> 13);
	b -= c; b -= a; b ^= (a << 8);
	c -= a; c -= b; c ^= (b >> 13);
	a -= b; a -= c; a ^= (c >> 12);
	b -= c; b -= a; b ^= (a << 16);
	c -= a; c -= b; c ^= (b >> 5);
	a -= b; a -= c; a ^= (c >> 3);
	b -= c; b -= a; b ^= (a << 10);
	c -= a; c -= b; c ^= (b >> 15);

	c &= (fm->fm_route_buckets_cnt - 1);

	return flow_mgr_get_frb_at_idx(fm, c);
}

struct flow_route_id_bucket *
flow_mgr_get_frib_by_uuid(struct flow_mgr *fm, uuid_t fr_uuid)
{
	union {
		uuid_t   uuid __sk_aligned(8);
		uint64_t u64[2];
	} u;
	uint64_t key;

	_CASSERT(sizeof(u.uuid) == sizeof(u.u64));
	uuid_copy(u.uuid, fr_uuid);

	/* XOR fold UUID down to 4-bytes */
	key = (u.u64[0] ^ u.u64[1]);
	key = ((key >> 32) ^ (key & 0xffffffff));

	/* add some offset to get more entropy */
	return flow_mgr_get_frib_at_idx(fm,
	           ((uint32_t)key % fm->fm_route_id_buckets_cnt));
}

static int
flow_hash_mask_add(struct flow_mgr *fm, uint32_t mask, int32_t v)
{
	for (uint32_t i = 0; i < FKMASK_IDX_MAX; i++) {
		if (fm->fm_flow_hash_masks[i] == mask) {
			os_atomic_add(&fm->fm_flow_hash_count[i], v, relaxed);
			return 0;
		}
	}
	SK_ERR("unkown hash mask 0x%x", mask);
	return ENOTSUP;
}

int
flow_mgr_flow_hash_mask_add(struct flow_mgr *fm, uint32_t mask)
{
	return flow_hash_mask_add(fm, mask, 1);
}

int
flow_mgr_flow_hash_mask_del(struct flow_mgr *fm, uint32_t mask)
{
	return flow_hash_mask_add(fm, mask, -1);
}

#if SK_LOG
SK_NO_INLINE_ATTRIBUTE
static void
__flow_mgr_find_fe_by_key_prelog(struct flow_key *key)
{
	SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
	SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP, "key %s",
	    fk_as_string(key, dbgbuf, sizeof(dbgbuf)));
}

SK_NO_INLINE_ATTRIBUTE
static void
__flow_mgr_find_fe_by_key_epilog(struct flow_entry *fe)
{
	SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
	if (fe != NULL) {
		SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP, "fe 0x%llx \"%s\"",
		    SK_KVA(fe), fe_as_string(fe, dbgbuf, sizeof(dbgbuf)));
	} else {
		SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP, "fe not found");
	}
}
#else
#define __flow_mgr_find_fe_by_key_prelog(key) do { ((void)0); } while (0)
#define __flow_mgr_find_fe_by_key_epilog(fe) do { ((void)0); } while (0)
#endif /* SK_LOG */

struct flow_entry *
flow_mgr_find_fe_by_key(struct flow_mgr *fm, struct flow_key *key)
{
	struct cuckoo_node *node = NULL;
	struct flow_entry *fe = NULL;
	uint32_t hash = 0;
	uint16_t saved_mask = key->fk_mask;

	__flow_mgr_find_fe_by_key_prelog(key);

	for (int i = 0; i < FKMASK_IDX_MAX; i++) {
		size_t count = fm->fm_flow_hash_count[i];
		uint16_t mask = fm->fm_flow_hash_masks[i];
		if (count == 0 || mask == 0) {
			SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP,
			    "[%d] mask=%08x count=%zu skiped",
			    i, mask, count);
			continue;
		}
		key->fk_mask = mask;
		hash = flow_key_hash(key);
		node = cuckoo_hashtable_find_with_hash(fm->fm_flow_table, key, hash);
		SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP,
		    "[%d] mask=%08x hash %08x node 0x%llx", i, mask, hash,
		    SK_KVA(node));
		if (node != NULL) {
			fe = container_of(node, struct flow_entry, fe_cnode);
			/* v4 only listener fe shouldn't get v6 connection */
			if (__improbable(fe->fe_key.fk_mask == FKMASK_2TUPLE &&
			    fe->fe_key.fk_ipver == IPVERSION &&
			    key->fk_ipver == IPV6_VERSION)) {
				flow_entry_release(&fe);
				ASSERT(fe == NULL);
				SK_DF(SK_VERB_FLOW | SK_VERB_LOOKUP,
				    "\tskip v4 only fe");
				continue;
			}
			break;
		}
	}

	key->fk_mask = saved_mask;

	__flow_mgr_find_fe_by_key_epilog(fe);

	return fe;
}

struct flow_entry *
flow_mgr_find_conflicting_fe(struct flow_mgr *fm, struct flow_key *key)
{
	struct cuckoo_node *node = NULL;
	struct flow_entry *fe = NULL;
	uint32_t hash = 0;

	hash = flow_key_hash(key);
	node = cuckoo_hashtable_find_with_hash(fm->fm_flow_table, key, hash);
	if (node != NULL) {
		fe = container_of(node, struct flow_entry, fe_cnode);
		return fe;
	}

	/* listener flow confliction will be checked at netns reservation */
	return fe;
}

void
flow_mgr_foreach_flow(struct flow_mgr *fm,
    void (^flow_handler)(struct flow_entry *fe))
{
	cuckoo_hashtable_foreach(fm->fm_flow_table,
	    ^(struct cuckoo_node *node, uint32_t hv) {
		#pragma unused(hv)
		struct flow_entry *fe;
		fe = container_of(node, struct flow_entry, fe_cnode);
		flow_handler(fe);

		if (fe->fe_flags & FLOWENTF_PARENT) {
		        struct flow_entry *child_fe;
		        lck_rw_lock_shared(&fe->fe_child_list_lock);
		        TAILQ_FOREACH(child_fe, &fe->fe_child_list, fe_child_link) {
		                flow_handler(child_fe);
			}
		        lck_rw_unlock_shared(&fe->fe_child_list_lock);
		}
	}
	    );
}

bool
rx_flow_demux_match(struct nx_flowswitch *fsw, struct flow_entry *fe, struct __kern_packet *pkt)
{
	struct udphdr *uh;
	uint8_t *pkt_buf;
	uint32_t bdlen, bdlim, bdoff, pkt_payload_len;
	uint8_t *demux_data;

	ASSERT(fe->fe_flags & FLOWENTF_CHILD);
	ASSERT(fe->fe_demux_pattern_count > 0);

	if (fe->fe_flags & (FLOWENTF_TORN_DOWN | FLOWENTF_NONVIABLE)) {
		return false;
	}

	/*
	 * Demux only supported for UDP packets with payload
	 */
	if (__improbable(pkt->pkt_flow_ip_proto != IPPROTO_UDP)) {
		return false;
	}

	uh = (struct udphdr *)pkt->pkt_flow_udp_hdr;
	if (__improbable(uh == NULL || pkt->pkt_flow_ulen == 0)) {
		return false;
	}

	int udp_payload_offset = pkt->pkt_l2_len + pkt->pkt_flow_ip_hlen + sizeof(*uh);

	MD_BUFLET_ADDR_ABS_DLEN(pkt, pkt_buf, bdlen, bdlim, bdoff);
	pkt_payload_len = bdlim - bdoff;
	pkt_payload_len = MIN(pkt_payload_len, pkt->pkt_length);
	pkt_payload_len -= udp_payload_offset;

	for (int index = 0; index < fe->fe_demux_pattern_count; index++) {
		struct flow_demux_pattern *demux_pattern = &fe->fe_demux_patterns[index].fdp_demux_pattern;
		ASSERT(demux_pattern->fdp_len > 0);

		if (pkt->pkt_flow_ulen >= demux_pattern->fdp_offset + demux_pattern->fdp_len) {
			if (__probable(pkt_payload_len >= demux_pattern->fdp_offset + demux_pattern->fdp_len)) {
				demux_data = (uint8_t *)(uh + 1) + demux_pattern->fdp_offset;
			} else {
				if (pkt->pkt_pflags & PKT_F_MBUF_DATA) {
					m_copydata(pkt->pkt_mbuf, udp_payload_offset + demux_pattern->fdp_offset,
					    demux_pattern->fdp_len, fe->fe_demux_pkt_data);
					demux_data = fe->fe_demux_pkt_data;
				} else {
					FSW_STATS_INC(FSW_STATS_RX_DEMUX_SHORT_ERR);
					return false;
				}
			}

			int result = -1;
			if (fe->fe_demux_patterns[index].fdp_memcmp_mask != NULL) {
				result = fe->fe_demux_patterns[index].fdp_memcmp_mask(demux_data,
				    demux_pattern->fdp_value, demux_pattern->fdp_mask);
			} else {
				result = sk_memcmp_mask(demux_data, demux_pattern->fdp_value,
				    demux_pattern->fdp_mask, demux_pattern->fdp_len);
			}

			if (result == 0) {
				return true;
			}
		}
	}

	return false;
}

struct flow_entry *
rx_lookup_child_flow(struct nx_flowswitch *fsw, struct flow_entry *parent_fe,
    struct __kern_packet *pkt)
{
	struct flow_entry *child_fe;

	/*
	 * Demux only supported for UDP packets with payload
	 */
	if (__improbable(pkt->pkt_flow_ip_proto != IPPROTO_UDP)) {
		return NULL;
	}

	lck_rw_lock_shared(&parent_fe->fe_child_list_lock);

	TAILQ_FOREACH(child_fe, &parent_fe->fe_child_list, fe_child_link) {
		if (rx_flow_demux_match(fsw, child_fe, pkt)) {
			flow_entry_retain(child_fe);
			lck_rw_unlock_shared(&parent_fe->fe_child_list_lock);
			return child_fe;
		}
	}

	lck_rw_unlock_shared(&parent_fe->fe_child_list_lock);
	return NULL;
}

struct flow_entry *
tx_lookup_child_flow(struct flow_entry *parent_fe, uuid_t flow_id)
{
	struct flow_entry *child_fe;

	ASSERT(parent_fe->fe_flags & FLOWENTF_PARENT);

	lck_rw_lock_shared(&parent_fe->fe_child_list_lock);
	TAILQ_FOREACH(child_fe, &parent_fe->fe_child_list, fe_child_link) {
		if (_UUID_MATCH(flow_id, child_fe->fe_uuid)) {
			flow_entry_retain(child_fe);
			lck_rw_unlock_shared(&parent_fe->fe_child_list_lock);
			return child_fe;
		}
	}

	lck_rw_unlock_shared(&parent_fe->fe_child_list_lock);
	return NULL;
}
