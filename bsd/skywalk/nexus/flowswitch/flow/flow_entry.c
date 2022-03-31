/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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

#include <dev/random/randomdev.h>
#include <net/flowhash.h>
#include <netkey/key.h>

#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>
#include <skywalk/nexus/netif/nx_netif.h>

struct flow_entry *fe_alloc(boolean_t);
static void fe_free(struct flow_entry *);
static int fe_id_cmp(const struct flow_entry *, const struct flow_entry *);
static void fe_stats_init(struct flow_entry *);
static void fe_stats_update(struct flow_entry *);

RB_GENERATE_PREV(flow_entry_id_tree, flow_entry, fe_id_link, fe_id_cmp);

os_refgrp_decl(static, flow_entry_refgrp, "flow_entry", NULL);

extern struct zone *sk_fed_zone;

const struct flow_key fk_mask_2tuple
__sk_aligned(16) =
{
	.fk_mask = FKMASK_2TUPLE,
	.fk_ipver = 0,
	.fk_proto = 0xff,
	.fk_sport = 0xffff,
	.fk_dport = 0,
	.fk_src._addr64[0] = 0,
	.fk_src._addr64[1] = 0,
	.fk_dst._addr64[0] = 0,
	.fk_dst._addr64[1] = 0,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_3tuple
__sk_aligned(16) =
{
	.fk_mask = FKMASK_3TUPLE,
	.fk_ipver = 0xff,
	.fk_proto = 0xff,
	.fk_sport = 0xffff,
	.fk_dport = 0,
	.fk_src._addr64[0] = 0xffffffffffffffffULL,
	.fk_src._addr64[1] = 0xffffffffffffffffULL,
	.fk_dst._addr64[0] = 0,
	.fk_dst._addr64[1] = 0,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_4tuple
__sk_aligned(16) =
{
	.fk_mask = FKMASK_4TUPLE,
	.fk_ipver = 0xff,
	.fk_proto = 0xff,
	.fk_sport = 0xffff,
	.fk_dport = 0xffff,
	.fk_src._addr64[0] = 0xffffffffffffffffULL,
	.fk_src._addr64[1] = 0xffffffffffffffffULL,
	.fk_dst._addr64[0] = 0,
	.fk_dst._addr64[1] = 0,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_5tuple
__sk_aligned(16) =
{
	.fk_mask = FKMASK_5TUPLE,
	.fk_ipver = 0xff,
	.fk_proto = 0xff,
	.fk_sport = 0xffff,
	.fk_dport = 0xffff,
	.fk_src._addr64[0] = 0xffffffffffffffffULL,
	.fk_src._addr64[1] = 0xffffffffffffffffULL,
	.fk_dst._addr64[0] = 0xffffffffffffffffULL,
	.fk_dst._addr64[1] = 0xffffffffffffffffULL,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_ipflow1
__sk_aligned(16) =
{
	.fk_mask = FKMASK_IPFLOW1,
	.fk_ipver = 0,
	.fk_proto = 0xff,
	.fk_sport = 0,
	.fk_dport = 0,
	.fk_src._addr64[0] = 0,
	.fk_src._addr64[1] = 0,
	.fk_dst._addr64[0] = 0,
	.fk_dst._addr64[1] = 0,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_ipflow2
__sk_aligned(16) =
{
	.fk_mask = FKMASK_IPFLOW2,
	.fk_ipver = 0xff,
	.fk_proto = 0xff,
	.fk_sport = 0,
	.fk_dport = 0,
	.fk_src._addr64[0] = 0xffffffffffffffffULL,
	.fk_src._addr64[1] = 0xffffffffffffffffULL,
	.fk_dst._addr64[0] = 0,
	.fk_dst._addr64[1] = 0,
	.fk_pad[0] = 0,
};

const struct flow_key fk_mask_ipflow3
__sk_aligned(16) =
{
	.fk_mask = FKMASK_IPFLOW3,
	.fk_ipver = 0xff,
	.fk_proto = 0xff,
	.fk_sport = 0,
	.fk_dport = 0,
	.fk_src._addr64[0] = 0xffffffffffffffffULL,
	.fk_src._addr64[1] = 0xffffffffffffffffULL,
	.fk_dst._addr64[0] = 0xffffffffffffffffULL,
	.fk_dst._addr64[1] = 0xffffffffffffffffULL,
	.fk_pad[0] = 0,
};

struct flow_owner *
flow_owner_find_by_pid(struct flow_owner_bucket *fob, pid_t pid, void *context,
    bool low_latency)
{
	struct flow_owner find = { .fo_context = context, .fo_pid = pid,
		                   .fo_low_latency = low_latency};

	ASSERT(low_latency == true || low_latency == false);
	FOB_LOCK_ASSERT_HELD(fob);
	return RB_FIND(flow_owner_tree, &fob->fob_owner_head, &find);
}

struct flow_entry *
flow_entry_find_by_uuid(struct flow_owner *fo, uuid_t uuid)
{
	struct flow_entry find, *fe = NULL;
	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));

	uuid_copy(find.fe_uuid, uuid);
	fe = RB_FIND(flow_entry_id_tree, &fo->fo_flow_entry_id_head, &find);
	if (fe != NULL) {
		flow_entry_retain(fe);
	}

	return fe;
}

/* writer-lock must be owned for memory management functions */
struct flow_entry *
flow_entry_alloc(struct flow_owner *fo, struct nx_flow_req *req, int *perr)
{
	SK_LOG_VAR(char dbgbuf[FLOWENTRY_DBGBUF_SIZE]);
	nexus_port_t nx_port = req->nfr_nx_port;
	struct flow_entry *fe = NULL;
	flowadv_idx_t fadv_idx = FLOWADV_IDX_NONE;
	struct nexus_adapter *dev_na;
	struct nx_netif *nif;
	int err;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));
	ASSERT(nx_port != NEXUS_PORT_ANY);
	ASSERT(!fo->fo_nx_port_destroyed);

	*perr = 0;

	struct flow_key key __sk_aligned(16);
	err = flow_req2key(req, &key);
	if (__improbable(err != 0)) {
		SK_ERR("invalid request (err %d)", err);
		goto done;
	}

	struct flow_mgr *fm = fo->fo_fsw->fsw_flow_mgr;
	fe = flow_mgr_find_conflicting_fe(fm, &key);
	if (fe != NULL) {
		SK_ERR("entry \"%s\" already exists at fe 0x%llx "
		    "flags 0x%b %s(%d)", fe_as_string(fe,
		    dbgbuf, sizeof(dbgbuf)), SK_KVA(fe), fe->fe_flags,
		    FLOWENTF_BITS, fe->fe_proc_name,
		    fe->fe_pid);
		/* don't return it */
		flow_entry_release(&fe);
		err = EEXIST;
		goto done;
	}

	if ((req->nfr_flags & NXFLOWREQF_FLOWADV) &&
	    (flow_owner_flowadv_index_alloc(fo, &fadv_idx) != 0)) {
		SK_ERR("failed to alloc flowadv index for flow %s",
		    sk_uuid_unparse(req->nfr_flow_uuid, dbgbuf));
		/* XXX: what is the most appropriate error code ? */
		err = ENOSPC;
		goto done;
	}

	fe = fe_alloc(TRUE);
	if (__improbable(fe == NULL)) {
		err = ENOMEM;
		goto done;
	}

	fe->fe_key = key;
	if (req->nfr_route != NULL) {
		fe->fe_laddr_gencnt = req->nfr_route->fr_laddr_gencnt;
	} else {
		fe->fe_laddr_gencnt = req->nfr_saddr_gencnt;
	}

	if (__improbable(req->nfr_flags & NXFLOWREQF_LISTENER)) {
		/* mark this as listener mode */
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_LISTENER);
	} else {
		ASSERT((fe->fe_key.fk_ipver == IPVERSION &&
		    fe->fe_key.fk_src4.s_addr != INADDR_ANY) ||
		    (fe->fe_key.fk_ipver == IPV6_VERSION &&
		    !IN6_IS_ADDR_UNSPECIFIED(&fe->fe_key.fk_src6)));

		/* mark this as connected mode */
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_CONNECTED);
	}

	fe->fe_port_reservation = req->nfr_port_reservation;
	req->nfr_port_reservation = NULL;
	if (req->nfr_flags & NXFLOWREQF_EXT_PORT_RSV) {
		fe->fe_flags |= FLOWENTF_EXTRL_PORT;
	}
	fe->fe_proto_reservation = req->nfr_proto_reservation;
	req->nfr_proto_reservation = NULL;
	if (req->nfr_flags & NXFLOWREQF_EXT_PROTO_RSV) {
		fe->fe_flags |= FLOWENTF_EXTRL_PROTO;
	}
	fe->fe_ipsec_reservation = req->nfr_ipsec_reservation;
	req->nfr_ipsec_reservation = NULL;

	fe->fe_tx_process = dp_flow_tx_process;
	fe->fe_rx_process = dp_flow_rx_process;

	if (nx_port == FSW_VP_HOST) {
		fe->fe_rx_process = fsw_host_rx;
	}

	dev_na = fo->fo_fsw->fsw_dev_ch->ch_na;
	nif = NX_NETIF_PRIVATE(dev_na->na_nx);
	if (NETIF_LLINK_ENABLED(nif)) {
		fe->fe_qset = nx_netif_find_qset(nif, req->nfr_qset_id);
	}
	if (req->nfr_flags & NXFLOWREQF_LOW_LATENCY) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_LOW_LATENCY);
	}

	fe->fe_transport_protocol = req->nfr_transport_protocol;
	if (sk_fsw_rx_agg_tcp &&
	    (fo->fo_fsw->fsw_nx->nx_prov->nxprov_params->nxp_max_frags > 1) &&
	    (fe->fe_key.fk_proto == IPPROTO_TCP) &&
	    (fe->fe_key.fk_mask == FKMASK_5TUPLE)) {
		fe->fe_rx_process = flow_rx_agg_tcp;
	}
	uuid_copy(fe->fe_uuid, req->nfr_flow_uuid);
	if ((req->nfr_flags & NXFLOWREQF_LISTENER) == 0 &&
	    (req->nfr_flags & NXFLOWREQF_TRACK) != 0) {
		switch (req->nfr_ip_protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			atomic_bitset_32(&fe->fe_flags, FLOWENTF_TRACK);
			break;
		default:
			break;
		}
	}

	if (req->nfr_flags & NXFLOWREQF_QOS_MARKING) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_QOS_MARKING);
	}

	if (req->nfr_route != NULL) {
		fe->fe_route = req->nfr_route;
		req->nfr_route = NULL;
	}

	fe->fe_nx_port = nx_port;
	fe->fe_adv_idx = fadv_idx;

	if (fe->fe_adv_idx != FLOWADV_IDX_NONE && fo->fo_nx_port_na != NULL) {
		na_flowadv_entry_alloc(fo->fo_nx_port_na, fe->fe_uuid,
		    fe->fe_adv_idx);
	}

	if (KPKT_VALID_SVC(req->nfr_svc_class)) {
		fe->fe_svc_class = (kern_packet_svc_class_t)req->nfr_svc_class;
	} else {
		fe->fe_svc_class = KPKT_SC_BE;
	}

	uuid_copy(fe->fe_eproc_uuid, req->nfr_euuid);
	fe->fe_policy_id = req->nfr_policy_id;
	fe->fe_inp_flowhash = req->nfr_inp_flowhash;

	err = flow_mgr_flow_hash_mask_add(fm, fe->fe_key.fk_mask);
	ASSERT(err == 0);

	fe->fe_key_hash = flow_key_hash(&fe->fe_key);
	err = cuckoo_hashtable_add_with_hash(fm->fm_flow_table, &fe->fe_cnode,
	    fe->fe_key_hash);
	if (err != 0) {
		SK_ERR("flow table add failed (err %d)", err);
		flow_mgr_flow_hash_mask_del(fm, fe->fe_key.fk_mask);
		goto done;
	}

	RB_INSERT(flow_entry_id_tree, &fo->fo_flow_entry_id_head, fe);
	flow_entry_retain(fe);  /* one refcnt in id_tree */

	*(struct nx_flowswitch **)(uintptr_t)&fe->fe_fsw = fo->fo_fsw;
	fe->fe_pid = fo->fo_pid;
	if (req->nfr_epid != -1 && req->nfr_epid != fo->fo_pid) {
		fe->fe_epid = req->nfr_epid;
		proc_name(fe->fe_epid, fe->fe_eproc_name,
		    sizeof(fe->fe_eproc_name));
	} else {
		fe->fe_epid = -1;
	}

	(void) snprintf(fe->fe_proc_name, sizeof(fe->fe_proc_name), "%s",
	    fo->fo_name);

	fe_stats_init(fe);
	flow_stats_retain(fe->fe_stats);
	req->nfr_flow_stats = fe->fe_stats;

#if SK_LOG
	SK_DF(SK_VERB_FLOW, "allocated entry \"%s\" fe 0x%llx flags 0x%b "
	    "[fo 0x%llx ]", fe_as_string(fe, dbgbuf,
	    sizeof(dbgbuf)), SK_KVA(fe), fe->fe_flags, FLOWENTF_BITS,
	    SK_KVA(fo));
#endif /* SK_LOG */

done:
	if (err != 0) {
		if (fadv_idx != FLOWADV_IDX_NONE) {
			flow_owner_flowadv_index_free(fo, fadv_idx);
		}
		if (fe != NULL) {
			flow_entry_release(&fe);
		}
	}
	*perr = err;
	return fe;
}

void
flow_entry_teardown(struct flow_owner *fo, struct flow_entry *fe)
{
#if SK_LOG
	char dbgbuf[FLOWENTRY_DBGBUF_SIZE];
	SK_DF(SK_VERB_FLOW, "entry \"%s\" fe 0x%llx flags 0x%b [fo 0x%llx] "
	    "non_via %d withdrawn %d", fe_as_string(fe, dbgbuf, sizeof(dbgbuf)),
	    SK_KVA(fe), fe->fe_flags, FLOWENTF_BITS, SK_KVA(fo),
	    fe->fe_want_nonviable, fe->fe_want_withdraw);
#endif /* SK_LOG */
	struct nx_flowswitch *fsw = fo->fo_fsw;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));

	ASSERT(!(fe->fe_flags & FLOWENTF_DESTROYED));
	ASSERT(!(fe->fe_flags & FLOWENTF_LINGERING));
	ASSERT(fsw != NULL);

	if (atomic_test_set_32(&fe->fe_want_nonviable, 1, 0)) {
		ASSERT(fsw->fsw_pending_nonviable != 0);
		atomic_add_32(&fsw->fsw_pending_nonviable, -1);
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_NONVIABLE);
	}

	/* always withdraw namespace during tear down */
	if (!(fe->fe_flags & FLOWENTF_EXTRL_PORT) &&
	    !(fe->fe_flags & FLOWENTF_WITHDRAWN)) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_WITHDRAWN);
		atomic_set_32(&fe->fe_want_withdraw, 0);
		/* local port is now inactive; not eligible for offload */
		flow_namespace_withdraw(&fe->fe_port_reservation);
	}

	/* we may get here multiple times, so check */
	if (!(fe->fe_flags & FLOWENTF_TORN_DOWN)) {
		atomic_bitset_32(&fe->fe_flags, FLOWENTF_TORN_DOWN);
		if (fe->fe_adv_idx != FLOWADV_IDX_NONE) {
			if (fo->fo_nx_port_na != NULL) {
				na_flowadv_entry_free(fo->fo_nx_port_na,
				    fe->fe_uuid, fe->fe_adv_idx);
			}
			flow_owner_flowadv_index_free(fo, fe->fe_adv_idx);
			fe->fe_adv_idx = FLOWADV_IDX_NONE;
		}
	}
	ASSERT(fe->fe_adv_idx == FLOWADV_IDX_NONE);
	ASSERT(fe->fe_flags & FLOWENTF_TORN_DOWN);
}

void
flow_entry_destroy(struct flow_owner *fo, struct flow_entry *fe, bool nolinger,
    void *close_params)
{
	struct flow_mgr *fm = fo->fo_fsw->fsw_flow_mgr;
	int err;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));

	/* one in flow_table, one in id_tree, one here */
	ASSERT(flow_entry_refcnt(fe) > 2);

	flow_entry_teardown(fo, fe);

	err = flow_mgr_flow_hash_mask_del(fm, fe->fe_key.fk_mask);
	ASSERT(err == 0);

	uint32_t hash;
	hash = flow_key_hash(&fe->fe_key);
	cuckoo_hashtable_del(fm->fm_flow_table, &fe->fe_cnode, hash);

	RB_REMOVE(flow_entry_id_tree, &fo->fo_flow_entry_id_head, fe);
	struct flow_entry *tfe = fe;
	flow_entry_release(&tfe);

	ASSERT(!(fe->fe_flags & FLOWENTF_DESTROYED));
	atomic_bitset_32(&fe->fe_flags, FLOWENTF_DESTROYED);

	if (fe->fe_transport_protocol == IPPROTO_QUIC) {
		if (!nolinger && close_params != NULL) {
			fsw_flow_abort_quic(fe, close_params);
		}
		flow_entry_release(&fe);
	} else if (nolinger || !(fe->fe_flags & FLOWENTF_WAIT_CLOSE)) {
		flow_entry_release(&fe);
	} else {
		fsw_linger_insert(fe);
	}
}

uint32_t
flow_entry_refcnt(struct flow_entry *fe)
{
	return os_ref_get_count(&fe->fe_refcnt);
}

void
flow_entry_retain(struct flow_entry *fe)
{
	os_ref_retain(&fe->fe_refcnt);
}

void
flow_entry_release(struct flow_entry **pfe)
{
	struct flow_entry *fe = *pfe;
	ASSERT(fe != NULL);
	*pfe = NULL;    /* caller lose reference */
#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		char dbgbuf[FLOWENTRY_DBGBUF_SIZE];
		SK_DF(SK_VERB_FLOW, "entry \"%s\" fe 0x%llx flags 0x%b",
		    fe_as_string(fe, dbgbuf, sizeof(dbgbuf)), SK_KVA(fe),
		    fe->fe_flags, FLOWENTF_BITS);
	}
#endif /* SK_LOG */

	if (__improbable(os_ref_release(&fe->fe_refcnt) == 0)) {
		fe->fe_nx_port = NEXUS_PORT_ANY;
		if (fe->fe_route != NULL) {
			flow_route_release(fe->fe_route);
			fe->fe_route = NULL;
		}
		if (fe->fe_qset != NULL) {
			nx_netif_qset_release(&fe->fe_qset);
			ASSERT(fe->fe_qset == NULL);
		}
		fe_free(fe);
	}
}

struct flow_entry_dead *
flow_entry_dead_alloc(zalloc_flags_t how)
{
	struct flow_entry_dead *fed;

	fed = zalloc_flags(sk_fed_zone, how | Z_ZERO);
	if (fed != NULL) {
		SK_DF(SK_VERB_MEM, "fed 0x%llx ALLOC", SK_KVA(fed));
	}
	return fed;
}

void
flow_entry_dead_free(struct flow_entry_dead *fed)
{
	SK_DF(SK_VERB_MEM, "fed 0x%llx FREE", SK_KVA(fed));
	zfree(sk_fed_zone, fed);
}

static void
fe_stats_init(struct flow_entry *fe)
{
	struct nx_flowswitch *fsw = fe->fe_fsw;
	struct sk_stats_flow *sf = &fe->fe_stats->fs_stats;

	ASSERT(fe->fe_stats != NULL);
	ASSERT(os_ref_get_count(&fe->fe_stats->fs_refcnt) >= 1);

	bzero(sf, sizeof(*sf));
	uuid_copy(sf->sf_nx_uuid, fsw->fsw_nx->nx_uuid);
	(void) strlcpy(sf->sf_if_name, fsw->fsw_flow_mgr->fm_name, IFNAMSIZ);
	sf->sf_if_index = fsw->fsw_ifp->if_index;
	sf->sf_pid = fe->fe_pid;
	sf->sf_epid = fe->fe_epid;
	(void) snprintf(sf->sf_proc_name, sizeof(sf->sf_proc_name), "%s",
	    fe->fe_proc_name);
	(void) snprintf(sf->sf_eproc_name, sizeof(sf->sf_eproc_name), "%s",
	    fe->fe_eproc_name);

	sf->sf_nx_port = fe->fe_nx_port;
	sf->sf_key = fe->fe_key;
	sf->sf_protocol = fe->fe_transport_protocol;
	sf->sf_svc_class = fe->fe_svc_class;
	sf->sf_adv_idx = fe->fe_adv_idx;

	if (fe->fe_flags & FLOWENTF_TRACK) {
		sf->sf_flags |= SFLOWF_TRACK;
	}
	if (fe->fe_flags & FLOWENTF_LISTENER) {
		sf->sf_flags |= SFLOWF_LISTENER;
	}
	if (fe->fe_route != NULL && fe->fe_route->fr_flags & FLOWRTF_ONLINK) {
		sf->sf_flags |= SFLOWF_ONLINK;
	}

	fe_stats_update(fe);
}

static void
fe_stats_update(struct flow_entry *fe)
{
	struct sk_stats_flow *sf = &fe->fe_stats->fs_stats;

	ASSERT(fe->fe_stats != NULL);
	ASSERT(os_ref_get_count(&fe->fe_stats->fs_refcnt) >= 1);

	if (fe->fe_flags & FLOWENTF_CONNECTED) {
		sf->sf_flags |= SFLOWF_CONNECTED;
	}
	if (fe->fe_flags & FLOWENTF_QOS_MARKING) {
		sf->sf_flags |= SFLOWF_QOS_MARKING;
	}
	if (fe->fe_flags & FLOWENTF_WAIT_CLOSE) {
		sf->sf_flags |= SFLOWF_WAIT_CLOSE;
	}
	if (fe->fe_flags & FLOWENTF_CLOSE_NOTIFY) {
		sf->sf_flags |= SFLOWF_CLOSE_NOTIFY;
	}
	if (fe->fe_flags & FLOWENTF_ABORTED) {
		sf->sf_flags |= SFLOWF_ABORTED;
	}
	if (fe->fe_flags & FLOWENTF_NONVIABLE) {
		sf->sf_flags |= SFLOWF_NONVIABLE;
	}
	if (fe->fe_flags & FLOWENTF_WITHDRAWN) {
		sf->sf_flags |= SFLOWF_WITHDRAWN;
	}
	if (fe->fe_flags & FLOWENTF_TORN_DOWN) {
		sf->sf_flags |= SFLOWF_TORN_DOWN;
	}
	if (fe->fe_flags & FLOWENTF_DESTROYED) {
		sf->sf_flags |= SFLOWF_DESTROYED;
	}
	if (fe->fe_flags & FLOWENTF_LINGERING) {
		sf->sf_flags |= SFLOWF_LINGERING;
	}
	if (fe->fe_flags & FLOWENTF_LOW_LATENCY) {
		sf->sf_flags |= SFLOWF_LOW_LATENCY;
	}

	sf->sf_bucket_idx = SFLOW_BUCKET_NONE;

	sf->sf_ltrack.sft_state = fe->fe_ltrack.fse_state;
	sf->sf_ltrack.sft_seq = fe->fe_ltrack.fse_seqlo;
	sf->sf_ltrack.sft_max_win = fe->fe_ltrack.fse_max_win;
	sf->sf_ltrack.sft_wscale = fe->fe_ltrack.fse_wscale;
	sf->sf_rtrack.sft_state = fe->fe_rtrack.fse_state;
	sf->sf_rtrack.sft_seq = fe->fe_rtrack.fse_seqlo;
	sf->sf_rtrack.sft_max_win = fe->fe_rtrack.fse_max_win;
}

void
flow_entry_stats_get(struct flow_entry *fe, struct sk_stats_flow *sf)
{
	_CASSERT(sizeof(fe->fe_stats->fs_stats) == sizeof(*sf));

	fe_stats_update(fe);
	bcopy(&fe->fe_stats->fs_stats, sf, sizeof(*sf));
}

struct flow_entry *
fe_alloc(boolean_t can_block)
{
	struct flow_entry *fe;

	_CASSERT((offsetof(struct flow_entry, fe_key) % 16) == 0);

	fe = skmem_cache_alloc(sk_fe_cache,
	    can_block ? SKMEM_SLEEP : SKMEM_NOSLEEP);
	if (fe == NULL) {
		return NULL;
	}

	/*
	 * fe_key is 16-bytes aligned which requires fe to begin on
	 * a 16-bytes boundary as well.  This alignment is specified
	 * at sk_fe_cache creation time and we assert here.
	 */
	ASSERT(IS_P2ALIGNED(fe, 16));
	bzero(fe, sk_fe_size);

	fe->fe_stats = flow_stats_alloc(can_block);
	if (fe->fe_stats == NULL) {
		skmem_cache_free(sk_fe_cache, fe);
		return NULL;
	}

	SK_DF(SK_VERB_MEM, "fe 0x%llx ALLOC", SK_KVA(fe));

	os_ref_init(&fe->fe_refcnt, &flow_entry_refgrp);

	KPKTQ_INIT(&fe->fe_rx_pktq);
	KPKTQ_INIT(&fe->fe_tx_pktq);

	return fe;
}

static void
fe_free(struct flow_entry *fe)
{
	ASSERT(fe->fe_flags & FLOWENTF_TORN_DOWN);
	ASSERT(fe->fe_flags & FLOWENTF_DESTROYED);
	ASSERT(!(fe->fe_flags & FLOWENTF_LINGERING));
	ASSERT(fe->fe_route == NULL);

	ASSERT(fe->fe_stats != NULL);
	flow_stats_release(fe->fe_stats);
	fe->fe_stats = NULL;

	/* only at very last existence of flow releases namespace reservation */
	if (!(fe->fe_flags & FLOWENTF_EXTRL_PORT) &&
	    NETNS_TOKEN_VALID(&fe->fe_port_reservation)) {
		flow_namespace_destroy(&fe->fe_port_reservation);
		ASSERT(!NETNS_TOKEN_VALID(&fe->fe_port_reservation));
	}
	fe->fe_port_reservation = NULL;

	if (!(fe->fe_flags & FLOWENTF_EXTRL_PROTO) &&
	    protons_token_is_valid(fe->fe_proto_reservation)) {
		protons_release(&fe->fe_proto_reservation);
	}
	fe->fe_proto_reservation = NULL;

	if (key_custom_ipsec_token_is_valid(fe->fe_ipsec_reservation)) {
		key_release_custom_ipsec(&fe->fe_ipsec_reservation);
	}
	fe->fe_ipsec_reservation = NULL;

	skmem_cache_free(sk_fe_cache, fe);
}

static __inline__ int
fe_id_cmp(const struct flow_entry *a, const struct flow_entry *b)
{
	return uuid_compare(a->fe_uuid, b->fe_uuid);
}

#if SK_LOG
SK_NO_INLINE_ATTRIBUTE
char *
fk_as_string(const struct flow_key *fk, char *dst, size_t dsz)
{
	int af;
	char src_s[MAX_IPv6_STR_LEN];
	char dst_s[MAX_IPv6_STR_LEN];

	af = fk->fk_ipver == 4 ? AF_INET : AF_INET6;

	(void) inet_ntop(af, &fk->fk_src, src_s, sizeof(src_s));
	(void) inet_ntop(af, &fk->fk_dst, dst_s, sizeof(dst_s));
	(void) snprintf(dst, dsz,
	    "ipver=%u,src=%s,dst=%s,proto=0x%02u,sport=%u,dport=%u "
	    "mask=%08x,hash=%08x",
	    fk->fk_ipver, src_s, dst_s, fk->fk_proto, ntohs(fk->fk_sport),
	    ntohs(fk->fk_dport), fk->fk_mask, flow_key_hash(fk));

	return dst;
}

SK_NO_INLINE_ATTRIBUTE
char *
fe_as_string(const struct flow_entry *fe, char *dst, size_t dsz)
{
	char keybuf[FLOWKEY_DBGBUF_SIZE]; /* just for debug message */
	uuid_string_t uuidstr;

	fk_as_string(&fe->fe_key, keybuf, sizeof(keybuf));

	(void) snprintf(dst, dsz,
	    "fe 0x%llx proc %s nx_port %d flow_uuid %s %s tp_proto=0x%02u",
	    SK_KVA(fe), fe->fe_proc_name, (int)fe->fe_nx_port,
	    sk_uuid_unparse(fe->fe_uuid, uuidstr),
	    keybuf, fe->fe_transport_protocol);

	return dst;
}
#endif /* SK_LOG */
