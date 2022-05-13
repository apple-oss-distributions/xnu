/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/netif/nx_netif_compat.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/pktsched/pktsched_netem.h>
#include <sys/eventhandler.h>

#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_flowswitch, OID_AUTO, chain_enqueue,
    CTLFLAG_RW | CTLFLAG_LOCKED, &fsw_chain_enqueue, 0, "");
#endif /* !DEVELOPMENT && !DEBUG */

uint32_t fsw_chain_enqueue = 0;
static int __nx_fsw_inited = 0;
static eventhandler_tag __nx_fsw_ifnet_eventhandler_tag = NULL;
static eventhandler_tag __nx_fsw_protoctl_eventhandler_tag = NULL;

static ZONE_DEFINE(nx_fsw_zone, SKMEM_ZONE_PREFIX ".nx.fsw",
    sizeof(struct nx_flowswitch), ZC_ZFREE_CLEARMEM);

static ZONE_DEFINE(nx_fsw_stats_zone, SKMEM_ZONE_PREFIX ".nx.fsw.stats",
    sizeof(struct __nx_stats_fsw), ZC_ZFREE_CLEARMEM);

#define SKMEM_TAG_FSW_PORTS     "com.apple.skywalk.fsw.ports"
SKMEM_TAG_DEFINE(skmem_tag_fsw_ports, SKMEM_TAG_FSW_PORTS);

#define SKMEM_TAG_FSW_FOB_HASH "com.apple.skywalk.fsw.fsw.fob.hash"
SKMEM_TAG_DEFINE(skmem_tag_fsw_fob_hash, SKMEM_TAG_FSW_FOB_HASH);

#define SKMEM_TAG_FSW_FRB_HASH "com.apple.skywalk.fsw.fsw.frb.hash"
SKMEM_TAG_DEFINE(skmem_tag_fsw_frb_hash, SKMEM_TAG_FSW_FRB_HASH);

#define SKMEM_TAG_FSW_FRIB_HASH "com.apple.skywalk.fsw.fsw.frib.hash"
SKMEM_TAG_DEFINE(skmem_tag_fsw_frib_hash, SKMEM_TAG_FSW_FRIB_HASH);

#define SKMEM_TAG_FSW_FRAG_MGR "com.apple.skywalk.fsw.fsw.frag.mgr"
SKMEM_TAG_DEFINE(skmem_tag_fsw_frag_mgr, SKMEM_TAG_FSW_FRAG_MGR);

/* 64-bit mask with range */
#define BMASK64(_beg, _end)     \
	((NX_FSW_CHUNK_FREE >> (63 - (_end))) & ~((1ULL << (_beg)) - 1))

static int fsw_detach(struct nx_flowswitch *fsw, struct nexus_adapter *hwna,
    boolean_t purge);

int
fsw_attach_vp(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_vp_adapter **vpna)
{
#pragma unused(ch)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	char *cr_name = chr->cr_name;
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!(chr->cr_mode & CHMODE_CONFIG));
	*vpna = NULL;

	/* if there's an existing adapter on the nexus port then use it */
	FSW_WLOCK(fsw);
	err = fsw_port_alloc(fsw, nxb, vpna, chr->cr_port, p, FALSE, FALSE);
	FSW_WUNLOCK(fsw);

	if (err != 0) {
		ASSERT(*vpna == NULL);
		goto out;
	} else if (*vpna != NULL) {
		/*
		 * Use the existing adapter on that port; fsw_port_alloc()
		 * callback has retained a reference count on the adapter.
		 */
		goto out;
	}
	ASSERT(*vpna == NULL);

	/* create a virtual port; callee holds vpna ref */
	err = fsw_vp_na_create(nx, chr, vpna);
	if (err != 0) {
		SK_ERR("vpna create failed (err %d)", err);
		goto out;
	}

	/* attach vp to fsw */
	err = fsw_vp_na_attach(nx, cr_name, &(*vpna)->vpna_up);
	if (err != 0) {
		SK_ERR("vpna \"%s\" fsw attach failed (err %d)",
		    (*vpna)->vpna_up.na_name, err);
		goto out;
	}

	FSW_WLOCK(fsw);
	err = fsw_port_alloc(fsw, nxb, vpna, (*vpna)->vpna_nx_port, p, FALSE, FALSE);
	FSW_WUNLOCK(fsw);

out:
	if ((*vpna) != NULL) {
		SK_DF(err ? SK_VERB_ERROR : SK_VERB_FSW,
		    "vpna \"%s\" (0x%llx) refs %u to fsw \"%s\" "
		    "nx_port %d (err %d)", (*vpna)->vpna_up.na_name,
		    SK_KVA(&(*vpna)->vpna_up), (*vpna)->vpna_up.na_refcount,
		    cr_name, (int)(*vpna)->vpna_nx_port, err);

		if (err != 0) {
			na_release_locked(&(*vpna)->vpna_up);
			*vpna = NULL;
		}
	}

	return err;
}

static int
fsw_nx_check(struct nx_flowswitch *fsw, struct kern_nexus *hw_nx)
{
#pragma unused(fsw)
	nexus_type_t hw_nxdom_type = NX_DOM(hw_nx)->nxdom_type;

	if (hw_nxdom_type != NEXUS_TYPE_NET_IF) {
		return EINVAL;
	}

	/* it's a netif below */
	return 0;
}

static int
fsw_ctl_flow_add(struct nx_flowswitch *fsw, struct proc *p,
    struct nx_flow_req *req)
{
	struct flow_owner *fo;
	int error = 0;

	ASSERT(p != PROC_NULL);

	if (p != kernproc) {
		/* special port shouldn't be bound via this method */
		if (req->nfr_nx_port < FSW_VP_USER_MIN) {
			return EINVAL;
		}
		req->nfr_flags |= (NXFLOWREQF_TRACK | NXFLOWREQF_FLOWADV);
	} else {
		/* no flow track or advisory support for bsd flow */
		ASSERT((req->nfr_flags & NXFLOWREQF_TRACK) == 0);
		ASSERT((req->nfr_flags & NXFLOWREQF_FLOWADV) == 0);
		ASSERT((req->nfr_flags & NXFLOWREQF_LOW_LATENCY) == 0);
	}

	/* init kernel only fields */
	if (p != kernproc) {
		nx_flow_req_internalize(req);
	}
	req->nfr_pid = proc_pid(p);
	if (req->nfr_epid == -1) {
		req->nfr_epid = proc_pid(p);
	}

	fo = fsw_flow_add(fsw, req, &error);
	ASSERT(fo != NULL || error != 0);

	if (error == 0) {
		// user space don't need this flow stats
		flow_stats_release(req->nfr_flow_stats);
	}
	if (p != kernproc) {
		nx_flow_req_externalize(req);
	}

	return error;
}

static int
fsw_ctl_flow_del(struct nx_flowswitch *fsw, struct proc *p,
    struct nx_flow_req *req)
{
	int err;

	nx_flow_req_internalize(req);
	req->nfr_pid = proc_pid(p);
	err = fsw_flow_del(fsw, req, TRUE, NULL);

	nx_flow_req_externalize(req);
	return err;
}

static int
fsw_setup_ifp(struct nx_flowswitch *fsw, struct nexus_adapter *hwna)
{
	int error = 0;
	struct ifnet *ifp = hwna->na_ifp;
	struct kern_pbufpool *pp = skmem_arena_nexus(hwna->na_arena)->arn_rx_pp;
	size_t f_limit = pp->pp_kmd_region->skr_c_obj_cnt / 2;

	ASSERT((hwna->na_type == NA_NETIF_HOST) ||
	    (hwna->na_type == NA_NETIF_COMPAT_HOST));

	SK_LOCK_ASSERT_HELD();

	/*
	 * XXX: we don't support non TXSTART interface.
	 * There are assumptions in fsw_port_flush_enqueue_dst() about
	 * single threaded write to destination rings.
	 */
	if ((ifp->if_eflags & IFEF_TXSTART) == 0) {
		SK_ERR("non TXSTART interface not supported ifp(0x%llx)",
		    SK_KVA(ifp));
		return ENOTSUP;
	}

	FSW_WLOCK(fsw);

	ASSERT(fsw->fsw_ifp == NULL);
	ASSERT(fsw->fsw_nifna == NULL);
	ASSERT(fsw->fsw_resolve == NULL);
	ASSERT(fsw->fsw_frame == NULL);
	ASSERT(fsw->fsw_demux == NULL);
	ASSERT(fsw->fsw_pkt_copy_from_pkt == NULL);
	ASSERT(fsw->fsw_pkt_copy_from_mbuf == NULL);
	ASSERT(fsw->fsw_pkt_copy_to_mbuf == NULL);

	fsw->fsw_ipfm = fsw_ip_frag_mgr_create(fsw, ifp, f_limit);
	if (fsw->fsw_ipfm == NULL) {
		FSW_WUNLOCK(fsw);
		return ENOMEM;
	}

	switch (ifp->if_family) {
	case IFNET_FAMILY_ETHERNET:
		error = fsw_ethernet_setup(fsw, ifp);
		fsw->fsw_ifp_dlt = DLT_EN10MB;
		break;

	case IFNET_FAMILY_CELLULAR:
		error = fsw_cellular_setup(fsw, ifp);
		fsw->fsw_ifp_dlt = DLT_RAW;
		break;

	default:
		if (ifp->if_family == IFNET_FAMILY_IPSEC ||
		    ifp->if_family == IFNET_FAMILY_UTUN) {
			error = fsw_ip_setup(fsw, ifp);
			fsw->fsw_ifp_dlt = DLT_RAW;
			break;
		}
		error = ENOTSUP;
		break;
	}

	if (error != 0) {
		FSW_WUNLOCK(fsw);
		return error;
	}

	ASSERT(fsw->fsw_resolve != NULL);

	if (NX_PROV(fsw->fsw_nx)->nxprov_region_params[SKMEM_REGION_KMD].
	    srp_max_frags > 1 || pp->pp_max_frags > 1) {
		fsw->fsw_pkt_copy_from_pkt = pkt_copy_multi_buflet_from_pkt;
		fsw->fsw_pkt_copy_from_mbuf = pkt_copy_multi_buflet_from_mbuf;
		fsw->fsw_pkt_copy_to_mbuf = pkt_copy_multi_buflet_to_mbuf;
	} else {
		fsw->fsw_pkt_copy_from_pkt = pkt_copy_from_pkt;
		fsw->fsw_pkt_copy_from_mbuf = pkt_copy_from_mbuf;
		fsw->fsw_pkt_copy_to_mbuf = pkt_copy_to_mbuf;
	}

	/*
	 * Since it is possible for fsw to refer to the ifp after all
	 * underlying hwnas are freed (see fsw_teardown_ifp()), we need
	 * an extra reference to the ifp here.
	 *
	 * We also cache the netif adapter of the interface, as it's
	 * needed for each packet enqueued to the classq.  There is no
	 * need to retain a refcnt for the same reason as above.
	 *
	 * We hold the busy lock across these, just in case an interface
	 * detach and reattach happens, as fsw_flow_bind() relies on the
	 * same lock as well before making its checks.
	 */
	lck_mtx_lock(&fsw->fsw_detach_barrier_lock);

	ASSERT((ifp->if_eflags & IFEF_TXSTART) != 0);
	fsw->fsw_ifp = ifp;
	fsw->fsw_nifna = &ifp->if_na->nifna_up;
	ifp->if_na->nifna_netif->nif_fsw = fsw;
	ifp->if_na->nifna_netif->nif_fsw_nxadv =
	    fsw->fsw_nx->nx_adv.flowswitch_nxv_adv;
	(void) strlcpy(fsw->fsw_flow_mgr->fm_name,
	    if_name(ifp), IFNAMSIZ);

	fsw_classq_setup(fsw, hwna);
	fsw->fsw_classq_enabled = TRUE;
	fsw->fsw_src_lla_gencnt = 0;

	ASSERT(fsw->fsw_reap_thread != THREAD_NULL);
	(void) snprintf(fsw->fsw_reap_name, sizeof(fsw->fsw_reap_name),
	    FSW_REAP_THREADNAME, ifp->if_xname, "");
	thread_set_thread_name(fsw->fsw_reap_thread, fsw->fsw_reap_name);

	error = fsw_netagent_register(fsw, ifp);
	SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
	    "fsw_netagent_register %s (family %u) (err %d)",
	    if_name(ifp), ifp->if_family, error);

	/*
	 * Clear NXF_REJECT to allow new channels to be opened
	 * to this nexus, in case this is an interface reattach.
	 * Otherwise this flag should already be cleared.
	 */
	if (error == 0) {
		atomic_bitclear_32(&fsw->fsw_nx->nx_flags, NXF_REJECT);
	}

	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);

	/*
	 * Wake up the reaper thread.
	 */
	if (error == 0) {
		fsw_reap_sched(fsw);
	}

	/* init skoid */
	skoid_create(&fsw->fsw_skoid,
	    SKOID_SNODE(_kern_skywalk_flowswitch), if_name(ifp),
	    CTLFLAG_RW);

	FSW_WUNLOCK(fsw);

	return error;
}

static void
fsw_teardown_ifp(struct nx_flowswitch *fsw, struct nexus_adapter *hwna)
{
	struct ifnet *ifp;

	SK_LOCK_ASSERT_HELD();

	FSW_WLOCK_ASSERT_HELD(fsw);
	ifp = fsw->fsw_ifp;
	ASSERT(ifp != NULL);
	ASSERT((ifp->if_eflags & IFEF_TXSTART) != 0);

	fsw_netagent_unregister(fsw, ifp);

	if (fsw->fsw_ipfm != NULL) {
		fsw_ip_frag_mgr_destroy(fsw->fsw_ipfm);
	}

	skoid_destroy(&fsw->fsw_skoid);

	SK_DF(SK_VERB_FSW, "%sdetached from %s (family %u)",
	    ((fsw->fsw_agent_session != NULL) ? "netagent" : ""),
	    if_name(ifp), ifp->if_family);

	if (hwna != NULL) {
		fsw_classq_teardown(fsw, hwna);
	}

	/*
	 * Set NXF_REJECT on the nexus, which would cause existing adapters
	 * to be marked similarly; channels associated with them would then
	 * cease to function.
	 */
	atomic_bitset_32(&fsw->fsw_nx->nx_flags, NXF_REJECT);

	/* see notes on fsw_na_attach() about I/O refcnt */
	if (ifp->if_na != NULL) {
		ifp->if_na->nifna_netif->nif_fsw = NULL;
		ifp->if_na->nifna_netif->nif_fsw_nxadv = NULL;
		membar_sync();
	}

	fsw->fsw_ifp = NULL;
	fsw->fsw_nifna = NULL;
	fsw->fsw_resolve = NULL;
	fsw->fsw_frame = NULL;
	fsw->fsw_frame_headroom = 0;
	fsw->fsw_demux = NULL;
	fsw->fsw_classq_enabled = FALSE;
	fsw->fsw_pkt_copy_from_pkt = NULL;
	fsw->fsw_pkt_copy_from_mbuf = NULL;
	fsw->fsw_pkt_copy_to_mbuf = NULL;

	if (ifp->if_input_netem != NULL) {
		netem_destroy(ifp->if_input_netem);
		ifp->if_input_netem = NULL;
	}

	ASSERT(fsw->fsw_reap_thread != THREAD_NULL);
	(void) snprintf(fsw->fsw_reap_name, sizeof(fsw->fsw_reap_name),
	    FSW_REAP_THREADNAME, if_name(ifp), "_detached");
	thread_set_thread_name(fsw->fsw_reap_thread, fsw->fsw_reap_name);
}

static int
fsw_host_setup(struct nx_flowswitch *fsw)
{
	struct nexus_adapter *hwna;
	struct ifnet *ifp;

	SK_LOCK_ASSERT_HELD();

	hwna = fsw->fsw_host_ch->ch_na;
	ASSERT(hwna != NULL);


	/* the netif below must have an ifnet attached (dev/host port) */
	if ((ifp = hwna->na_ifp) == NULL) {
		return ENXIO;
	}

	/*
	 * XXX: we don't support multiple rx rings yet.
	 * There are assumptions in fsw_port_flush_enqueue_dst() about
	 * single threaded write to destination rings.
	 */
	if (SKYWALK_NATIVE(ifp) && (hwna->na_num_rx_rings > 1)) {
		SK_ERR("ifp(0x%llx): multiple rx rings(%d) not supported",
		    SK_KVA(ifp), hwna->na_num_rx_rings);
		return ENOTSUP;
	}

	lck_mtx_lock(&fsw->fsw_detach_barrier_lock);
	if ((fsw->fsw_detach_flags & FSW_DETACHF_DETACHING) != 0) {
		lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
		return EBUSY;
	}
	fsw->fsw_detach_flags = 0;
	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);

	int error = fsw_setup_ifp(fsw, hwna);
	ASSERT(error != 0 || fsw->fsw_ifp != NULL);
	if (error != 0) {
		return error;
	}

	/* update the interface index */
	ASSERT(NX_PROV(fsw->fsw_nx)->nxprov_params->nxp_ifindex == 0);
	NX_PROV(fsw->fsw_nx)->nxprov_params->nxp_ifindex = ifp->if_index;
	return 0;
}

static int
fsw_host_teardown(struct nx_flowswitch *fsw)
{
	struct nexus_adapter *hwna = fsw->fsw_host_ch->ch_na;

	SK_LOCK_ASSERT_HELD();
	return fsw_detach(fsw, hwna, FALSE);
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
fsw_ctl_attach_log(const struct nx_spec_req *nsr,
    const struct kern_nexus *nx, int err)
{
	uuid_string_t uuidstr, ifuuidstr;
	const char *nustr;

	if (nsr->nsr_flags & NXSPECREQ_UUID) {
		nustr = sk_uuid_unparse(nsr->nsr_uuid, uuidstr);
	} else if (nsr->nsr_flags & NXSPECREQ_IFP) {
		(void) snprintf((char *)uuidstr, sizeof(uuidstr), "0x%llx",
		    SK_KVA(nsr->nsr_ifp));
		nustr = uuidstr;
	} else {
		nustr = nsr->nsr_name;
	}

	SK_DF(err ? SK_VERB_ERROR : SK_VERB_FSW,
	    "nexus 0x%llx (%s) name/uuid \"%s\" if_uuid %s flags 0x%x err %d",
	    SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name, nustr,
	    sk_uuid_unparse(nsr->nsr_if_uuid, ifuuidstr), nsr->nsr_flags, err);
}
#endif /* SK_LOG */

SK_NO_INLINE_ATTRIBUTE
static void
fsw_netif_set_callbacks_common(struct nx_flowswitch *fsw, boolean_t set)
{
	struct nexus_adapter *hwna = fsw->fsw_dev_ch->ch_na;

	ASSERT(hwna->na_type == NA_NETIF_DEV ||
	    hwna->na_type == NA_NETIF_COMPAT_DEV);

	if (set) {
		netif_hwna_set_mode(hwna, NETIF_MODE_FSW, fsw_devna_rx);
	} else {
		netif_hwna_clear_mode(hwna);
	}
}

SK_NO_INLINE_ATTRIBUTE
static void
fsw_netif_set_callbacks(struct nx_flowswitch *fsw)
{
	fsw_netif_set_callbacks_common(fsw, TRUE);
}

SK_NO_INLINE_ATTRIBUTE
static void
fsw_netif_clear_callbacks(struct nx_flowswitch *fsw)
{
	fsw_netif_set_callbacks_common(fsw, FALSE);
}

SK_NO_INLINE_ATTRIBUTE
static void
fsw_dp_start(struct nx_flowswitch *fsw)
{
	ASSERT(fsw->fsw_dev_ch != NULL);
	ASSERT(fsw->fsw_host_ch != NULL);

	fsw_netif_set_callbacks(fsw);
	na_start_spec(fsw->fsw_dev_ch->ch_nexus, fsw->fsw_dev_ch);
	na_start_spec(fsw->fsw_host_ch->ch_nexus, fsw->fsw_host_ch);
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_dp_stop(struct nx_flowswitch *fsw, struct ifnet **ifpp)
{
	struct ifnet *ifp;

	FSW_WLOCK(fsw);
	if ((fsw->fsw_state_flags & FSW_STATEF_QUIESCED) != 0) {
		FSW_WUNLOCK(fsw);
		return EALREADY;
	}
	fsw->fsw_state_flags |= FSW_STATEF_QUIESCED;
	FSW_WUNLOCK(fsw);

	/*
	 * For regular kernel-attached interfaces, quiescing is handled by
	 * the ifnet detach thread, which calls dlil_quiesce_and_detach_nexuses().
	 * For interfaces created by skywalk test cases, flowswitch/netif nexuses
	 * are constructed on the fly and can also be torn down on the fly.
	 * dlil_quiesce_and_detach_nexuses() won't help here because any nexus
	 * can be detached while the interface is still attached.
	 */
	if ((ifp = fsw->fsw_ifp) != NULL &&
	    ifnet_datamov_suspend_if_needed(ifp)) {
		SK_UNLOCK();
		ifnet_datamov_drain(ifp);
		/* Reference will be released by caller */
		*ifpp = ifp;
		SK_LOCK();
	}
	ASSERT(fsw->fsw_dev_ch != NULL);
	ASSERT(fsw->fsw_host_ch != NULL);
	na_stop_spec(fsw->fsw_host_ch->ch_nexus, fsw->fsw_host_ch);
	na_stop_spec(fsw->fsw_dev_ch->ch_nexus, fsw->fsw_dev_ch);
	fsw_netif_clear_callbacks(fsw);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_netif_port_setup(struct nx_flowswitch *fsw, struct kern_nexus *hw_nx,
    boolean_t host)
{
	struct chreq chr;
	struct kern_channel *ch;
	int err;

	bzero(&chr, sizeof(chr));
	uuid_copy(chr.cr_spec_uuid, hw_nx->nx_uuid);
	chr.cr_ring_id = CHANNEL_RING_ID_ANY;
	chr.cr_port = host ? NEXUS_PORT_NET_IF_HOST : NEXUS_PORT_NET_IF_DEV;
	chr.cr_mode |= CHMODE_CONFIG | (host ? CHMODE_HOST : 0);

	err = 0;
	ch = ch_open_special(hw_nx, &chr, FALSE, &err);
	if (ch == NULL) {
		SK_ERR("ch_open_special(%s) failed: %d",
		    host ? "host" : "dev", err);
		return err;
	}
	if (host) {
		fsw->fsw_host_ch = ch;
	} else {
		fsw->fsw_dev_ch = ch;
	}
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_netif_port_teardown(struct nx_flowswitch *fsw, boolean_t host)
{
	struct kern_channel *ch;

	ch = host ? fsw->fsw_host_ch : fsw->fsw_dev_ch;
	if (ch == NULL) {
		return EINVAL;
	}
	if (host) {
		fsw->fsw_host_ch = NULL;
	} else {
		fsw->fsw_dev_ch = NULL;
	}
	ch_close_special(ch);
	(void) ch_release_locked(ch);
	return 0;
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_devna_setup(struct nx_flowswitch *fsw, struct kern_nexus *hw_nx)
{
	return fsw_netif_port_setup(fsw, hw_nx, FALSE);
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_hostna_setup(struct nx_flowswitch *fsw, struct kern_nexus *hw_nx)
{
	return fsw_netif_port_setup(fsw, hw_nx, TRUE);
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_devna_teardown(struct nx_flowswitch *fsw)
{
	return fsw_netif_port_teardown(fsw, FALSE);
}

SK_NO_INLINE_ATTRIBUTE
static int
fsw_hostna_teardown(struct nx_flowswitch *fsw)
{
	return fsw_netif_port_teardown(fsw, TRUE);
}

/* Process NXCFG_CMD_ATTACH */
SK_NO_INLINE_ATTRIBUTE
static int
fsw_ctl_attach(struct kern_nexus *nx, struct proc *p, struct nx_spec_req *nsr)
{
#pragma unused(p)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	struct kern_nexus *hw_nx = NULL;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	/*
	 * The flowswitch only accepts UUID as an identifier, since it
	 * represents the UUID of the kernel object we are trying to
	 * attach to this flowswitch.
	 */
	if ((nsr->nsr_flags & (NXSPECREQ_UUID | NXSPECREQ_IFP)) !=
	    NXSPECREQ_UUID || uuid_is_null(nsr->nsr_uuid)) {
		err = EINVAL;
		goto done;
	}

	if (fsw->fsw_dev_ch != NULL) {
		ASSERT(fsw->fsw_host_ch != NULL);
		err = EEXIST;
		goto done;
	}

	hw_nx = nx_find(nsr->nsr_uuid, TRUE);
	if (hw_nx == NULL) {
		err = ENOENT;
		goto done;
	} else if (hw_nx == nx) {
		err = EINVAL;
		goto done;
	}

	/* preflight check to see if the nexus is attachable to us */
	err = fsw_nx_check(fsw, hw_nx);
	if (err != 0) {
		goto done;
	}

	err = fsw_devna_setup(fsw, hw_nx);
	if (err != 0) {
		goto done;
	}

	err = fsw_hostna_setup(fsw, hw_nx);
	if (err != 0) {
		(void) fsw_devna_teardown(fsw);
		goto done;
	}

	err = fsw_host_setup(fsw);
	if (err != 0) {
		(void) fsw_hostna_teardown(fsw);
		(void) fsw_devna_teardown(fsw);
		goto done;
	}

	fsw_dp_start(fsw);

	/* return the devna UUID */
	uuid_copy(nsr->nsr_if_uuid, fsw->fsw_dev_ch->ch_na->na_uuid);
	ASSERT(!uuid_is_null(nsr->nsr_if_uuid));
done:
#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		fsw_ctl_attach_log(nsr, nx, err);
	}
#endif /* SK_LOG */

	if (hw_nx != NULL) {
		nx_release_locked(hw_nx);
	}

	return err;
}

SK_NO_INLINE_ATTRIBUTE
static void
fsw_cleanup(struct nx_flowswitch *fsw)
{
	int err;
	struct ifnet *ifp = NULL;

	if (fsw->fsw_dev_ch == NULL) {
		ASSERT(fsw->fsw_host_ch == NULL);
		return;
	}
	err = fsw_dp_stop(fsw, &ifp);
	if (err != 0) {
		return;
	}
	err = fsw_host_teardown(fsw);
	VERIFY(err == 0);

	err = fsw_hostna_teardown(fsw);
	VERIFY(err == 0);

	err = fsw_devna_teardown(fsw);
	VERIFY(err == 0);

	if (ifp != NULL) {
		ifnet_datamov_resume(ifp);
	}
}

int
fsw_ctl_detach(struct kern_nexus *nx, struct proc *p,
    struct nx_spec_req *nsr)
{
#pragma unused(p)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	/*
	 * nsr is NULL when we're called from the destructor, and it
	 * implies that we'll detach everything that is attached.
	 */
	if (nsr == NULL) {
		fsw_cleanup(fsw);
		ASSERT(fsw->fsw_dev_ch == NULL);
		ASSERT(fsw->fsw_host_ch == NULL);
		goto done;
	}

	if (uuid_is_null(nsr->nsr_if_uuid)) {
		err = EINVAL;
		goto done;
	} else if (fsw->fsw_dev_ch == NULL || fsw->fsw_host_ch == NULL) {
		err = ENXIO;
		goto done;
	}

	/* check if the devna uuid is correct */
	if (uuid_compare(nsr->nsr_if_uuid,
	    fsw->fsw_dev_ch->ch_na->na_uuid) != 0) {
		err = ESRCH;
		goto done;
	}
	fsw_cleanup(fsw);

done:
#if SK_LOG
	if (nsr != NULL) {
		uuid_string_t ifuuidstr;
		SK_DF(err ? SK_VERB_ERROR : SK_VERB_FSW,
		    "nexus 0x%llx (%s) if_uuid %s flags 0x%x err %d",
		    SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
		    sk_uuid_unparse(nsr->nsr_if_uuid, ifuuidstr),
		    nsr->nsr_flags, err);
	} else {
		SK_DF(err ? SK_VERB_ERROR : SK_VERB_FSW,
		    "nexus 0x%llx (%s) ANY err %d", SK_KVA(nx),
		    NX_DOM_PROV(nx)->nxdom_prov_name, err);
	}
#endif /* SK_LOG */

	return err;
}

static int
fsw_netem_config(struct nx_flowswitch *fsw, void *data)
{
	struct ifnet *ifp = fsw->fsw_ifp;
	struct if_netem_params *params = data;
	int ret;

	if (ifp == NULL) {
		return ENODEV;
	}

	SK_LOCK_ASSERT_HELD();
#define fsw_INPUT_NETEM_THREADNAME   "if_input_netem_%s@fsw"
#define fsw_INPUT_NETEM_THREADNAME_LEN       32
	char netem_name[fsw_INPUT_NETEM_THREADNAME_LEN];
	(void) snprintf(netem_name, sizeof(netem_name),
	    fsw_INPUT_NETEM_THREADNAME, if_name(ifp));
	ret = netem_config(&ifp->if_input_netem, netem_name, params, fsw,
	    fsw_dev_input_netem_dequeue, FSW_VP_DEV_BATCH_MAX);

	return ret;
}

int
fsw_ctl(struct kern_nexus *nx, nxcfg_cmd_t nc_cmd, struct proc *p,
    void *data)
{
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	struct nx_spec_req *nsr = data;
	struct nx_flow_req *req = data;
	boolean_t need_check;
	int error = 0;

	switch (nc_cmd) {
	case NXCFG_CMD_FLOW_ADD:
	case NXCFG_CMD_FLOW_DEL:
		if (uuid_is_null(req->nfr_flow_uuid)) {
			error = EINVAL;
			goto done;
		}
		if (p != kernproc) {
			req->nfr_flags &= NXFLOWREQF_MASK;
		}
		req->nfr_flowadv_idx = FLOWADV_IDX_NONE;

		if (nc_cmd == NXCFG_CMD_FLOW_DEL) {
			break;
		}

		need_check = FALSE;
		if (req->nfr_epid != -1 && proc_pid(p) != req->nfr_epid) {
			need_check = TRUE;
		} else if (!uuid_is_null(req->nfr_euuid)) {
			uuid_t uuid;

			/* get the UUID of the issuing process */
			proc_getexecutableuuid(p, uuid, sizeof(uuid));

			/*
			 * If this is not issued by a process for its own
			 * executable UUID and if the process does not have
			 * the necessary privilege, reject the request.
			 * The logic is similar to so_set_effective_uuid().
			 */
			if (uuid_compare(req->nfr_euuid, uuid) != 0) {
				need_check = TRUE;
			}
		}
		if (need_check) {
			kauth_cred_t cred = kauth_cred_proc_ref(p);
			error = priv_check_cred(cred,
			    PRIV_NET_PRIVILEGED_SOCKET_DELEGATE, 0);
			kauth_cred_unref(&cred);
			if (error != 0) {
				goto done;
			}
		}
		break;

	default:
		break;
	}

	switch (nc_cmd) {
	case NXCFG_CMD_ATTACH:
		error = fsw_ctl_attach(nx, p, nsr);
		break;

	case NXCFG_CMD_DETACH:
		error = fsw_ctl_detach(nx, p, nsr);
		break;

	case NXCFG_CMD_FLOW_ADD:       /* struct nx_flow_req */
		error = fsw_ctl_flow_add(fsw, p, data);
		break;

	case NXCFG_CMD_FLOW_DEL:     /* struct nx_flow_req */
		error = fsw_ctl_flow_del(fsw, p, data);
		break;
	case NXCFG_CMD_NETEM:           /* struct if_netem_params */
		error = fsw_netem_config(fsw, data);
		break;

	default:
		SK_ERR("invalid cmd %u", nc_cmd);
		error = EINVAL;
		break;
	}

done:
	return error;
}

struct nx_flowswitch *
fsw_ifp_to_fsw(struct ifnet *ifp)
{
	struct nx_flowswitch *fsw = NULL;

	if (ifp->if_na != NULL) {
		fsw = ifp->if_na->nifna_netif->nif_fsw;
	}
	return fsw;
}

static void
fsw_ifnet_event_callback(struct eventhandler_entry_arg ee_arg __unused,
    struct ifnet *ifp, struct sockaddr *ip_addr __unused,
    intf_event_code_t intf_ev_code)
{
	struct nx_flowswitch *fsw = NULL;

	if (ifp->if_na == NULL) {
		return;
	}

	SK_LOCK();
	fsw = fsw_ifp_to_fsw(ifp);
	if (fsw != NULL) {
		switch (intf_ev_code) {
		case INTF_EVENT_CODE_LLADDR_UPDATE:
			if ((fsw->fsw_ifp == NULL) ||
			    (fsw->fsw_ifp_dlt != DLT_EN10MB)) {
				break;
			}

			VERIFY(fsw->fsw_ifp == ifp);
			SK_DF(SK_VERB_FSW, "MAC address change detected for %s",
			    if_name(fsw->fsw_ifp));
			(void) ifnet_lladdr_copy_bytes(ifp, fsw->fsw_ether_shost,
			    ETHER_ADDR_LEN);
			atomic_add_32(&fsw->fsw_src_lla_gencnt, 1);
			break;

		case INTF_EVENT_CODE_LOW_POWER_UPDATE:
			if (fsw->fsw_ifp == NULL) {
				break;
			}

			VERIFY(fsw->fsw_ifp == ifp);

			if (ifp->if_xflags & IFXF_LOW_POWER) {
				SK_DF(SK_VERB_FSW,
				    "Low power mode updated for %s",
				    if_name(fsw->fsw_ifp));

				fsw_reap_sched(fsw);
			}
			break;

		default:
			break;
		}
	}
	SK_UNLOCK();
}

static void
fsw_protoctl_event_callback(struct eventhandler_entry_arg ee_arg,
    struct ifnet *ifp, struct sockaddr *p_laddr, struct sockaddr *p_raddr,
    uint16_t lport, uint16_t rport, uint8_t proto, uint32_t protoctl_event_code,
    struct protoctl_ev_val *p_val)
{
#pragma unused(ee_arg)
	struct nx_flowswitch *fsw = NULL;
	struct flow_entry *fe = NULL;
	boolean_t netagent_update_flow = FALSE;
	uuid_t fe_uuid;

	if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
		return;
	}

	/*
	 * XXX Right now only handle the event if we have enough
	 * information to match the entire flow.
	 */
	if (lport == 0 || rport == 0 || p_laddr == NULL || p_raddr == NULL) {
		return;
	}

	SK_LOCK();
	fsw = fsw_ifp_to_fsw(ifp);
	if (fsw == NULL) {
		goto out;
	}

	if (!fsw_detach_barrier_add(fsw)) {
		fsw = NULL;
		SK_ERR("netagent detached");
		goto out;
	}

	struct flow_key fk __sk_aligned(16);
	FLOW_KEY_CLEAR(&fk);
	fk.fk_proto = proto;
	if (p_laddr->sa_family == AF_INET) {
		fk.fk_ipver = IPVERSION;
		fk.fk_src4 = SIN(p_laddr)->sin_addr;
		fk.fk_dst4 = SIN(p_raddr)->sin_addr;
	} else {
		fk.fk_ipver = IPV6_VERSION;
		fk.fk_src6 = SIN6(p_laddr)->sin6_addr;
		fk.fk_dst6 = SIN6(p_raddr)->sin6_addr;
	}
	fk.fk_sport = lport;
	fk.fk_dport = rport;
	fk.fk_mask = FKMASK_5TUPLE;

	fe = flow_mgr_find_fe_by_key(fsw->fsw_flow_mgr, &fk);
	if (__improbable(fe == NULL)) {
		goto out;
	}

	uuid_copy(fe_uuid, fe->fe_uuid);
	/*
	 * If the protocol notification is for TCP, make sure
	 * protocol event received is for bytes in the flight.
	 * XXX Redirect events are not delivered as protocol events
	 * but as better route events.
	 * Also redirect events do not indicate loss of the packet.
	 */
	if (proto != IPPROTO_TCP) {
		p_val->tcp_seq_number = 0;
	}

	netagent_update_flow = TRUE;

out:
	SK_UNLOCK();

	if (netagent_update_flow) {
		int error = 0;
#if SK_LOG
		char dbgbuf[FLOWENTRY_DBGBUF_SIZE];
		SK_DF(SK_VERB_FLOW, "Update flow entry \"%s\" for protocol "
		    "event %d with value %d and tcp sequence number %d",
		    fe_as_string(fe, dbgbuf, sizeof(dbgbuf)),
		    protoctl_event_code, p_val->val, p_val->tcp_seq_number);
#endif /* SK_LOG */
		if ((error = netagent_update_flow_protoctl_event(
			    fsw->fsw_agent_session, fe_uuid, protoctl_event_code,
			    p_val->val, p_val->tcp_seq_number)) != 0) {
#if SK_LOG
			SK_DF(SK_VERB_FLOW, "Error: %d. Could not update "
			    "flow entry \"%s\" for protocol event %d with "
			    "value %d and tcp sequence number %d", error,
			    dbgbuf, protoctl_event_code, p_val->val,
			    p_val->tcp_seq_number);
#endif /* SK_LOG */
		}
	}

	if (fe != NULL) {
		flow_entry_release(&fe);
	}

	if (fsw != NULL) {
		fsw_detach_barrier_remove(fsw);
	}
}

int
fsw_netagent_add_remove(struct kern_nexus *nx, boolean_t add)
{
	struct nx_flowswitch *fsw = NULL;
	int error = 0;

	SK_LOCK_ASSERT_HELD();
	VERIFY(nx != NULL);
	VERIFY(NX_PROV(nx) != NULL);
	VERIFY(NX_DOM_PROV(nx) != NULL);

	if (NX_DOM(nx)->nxdom_type != NEXUS_TYPE_FLOW_SWITCH) {
		error = EINVAL;
		goto out;
	}

	fsw = NX_FSW_PRIVATE(nx);
	VERIFY(fsw != NULL);
	FSW_WLOCK(fsw);

	if (fsw->fsw_agent_session == NULL) {
		error = ENXIO;
		goto out;
	}

	ASSERT(!uuid_is_null(fsw->fsw_agent_uuid));

	if (add) {
		if (FSW_NETAGENT_ADDED(fsw)) {
			/* agent already added */
			error = EEXIST;
		} else {
			fsw->fsw_state_flags |= FSW_STATEF_NETAGENT_ADDED;
			if (if_is_fsw_netagent_enabled()) {
				fsw->fsw_state_flags
				        |= FSW_STATEF_NETAGENT_ENABLED;
			}
			if_add_netagent(fsw->fsw_ifp, fsw->fsw_agent_uuid);
			SK_D("flowswitch netagent added for interface %s",
			    if_name(fsw->fsw_ifp));
		}
	} else {
		if (!FSW_NETAGENT_ADDED(fsw)) {
			/* agent has not been added */
			error = ENOENT;
		} else {
			fsw->fsw_state_flags &= ~(FSW_STATEF_NETAGENT_ADDED |
			    FSW_STATEF_NETAGENT_ENABLED);
			if_delete_netagent(fsw->fsw_ifp, fsw->fsw_agent_uuid);
			SK_D("flowswitch netagent removed for interface %s",
			    if_name(fsw->fsw_ifp));
		}
	}
out:
	if (fsw != NULL) {
		FSW_UNLOCK(fsw);
	}
	return error;
}

void
fsw_netagent_update(struct kern_nexus *nx)
{
	struct nx_flowswitch *fsw = NULL;

	SK_LOCK_ASSERT_HELD();
	VERIFY(nx != NULL);
	VERIFY(NX_PROV(nx) != NULL);
	VERIFY(NX_DOM_PROV(nx) != NULL);

	if (NX_DOM(nx)->nxdom_type != NEXUS_TYPE_FLOW_SWITCH) {
		goto out;
	}
	fsw = NX_FSW_PRIVATE(nx);
	VERIFY(fsw != NULL);
	FSW_WLOCK(fsw);
	if (fsw->fsw_agent_session == NULL) {
		goto out;
	}
	ASSERT(!uuid_is_null(fsw->fsw_agent_uuid));
	uint32_t flags = netagent_get_flags(fsw->fsw_agent_uuid);
	const bool ip_agent = ifnet_needs_fsw_ip_netagent(fsw->fsw_ifp);
	const bool transport_agent = ifnet_needs_fsw_transport_netagent(fsw->fsw_ifp);
	if (ip_agent || transport_agent) {
		flags |= NETAGENT_FLAG_NEXUS_LISTENER;
	} else {
		flags &= ~NETAGENT_FLAG_NEXUS_LISTENER;
	}
	if (transport_agent) {
		flags |= NETAGENT_FLAG_NEXUS_PROVIDER;
	} else {
		flags &= ~NETAGENT_FLAG_NEXUS_PROVIDER;
	}
	if (ip_agent) {
		flags |= NETAGENT_FLAG_CUSTOM_IP_NEXUS;
	} else {
		flags &= ~NETAGENT_FLAG_CUSTOM_IP_NEXUS;
	}
	if (netagent_set_flags(fsw->fsw_agent_uuid, flags) == 0) {
		SK_D("flowswitch netagent updated for interface %s",
		    if_name(fsw->fsw_ifp));
	}
out:
	if (fsw != NULL) {
		FSW_UNLOCK(fsw);
	}
}

static int
fsw_port_ctor(struct nx_flowswitch *fsw, struct nexus_vp_adapter *vpna,
    const struct nxbind *nxb)
{
#pragma unused(nxb)
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(nxb == NULL || !(nxb->nxb_flags & NXBF_MATCH_UNIQUEID) ||
	    vpna->vpna_pid == nxb->nxb_pid);

	/*
	 * Reject regular channel open requests unless there is
	 * something attached to the host port of the flowswitch.
	 */
	if (vpna->vpna_nx_port >= FSW_VP_USER_MIN) {
		struct nexus_adapter *na = &vpna->vpna_up;
		struct ifnet *ifp = fsw->fsw_ifp;

		if (ifp == NULL) {
			err = ENXIO;
			goto done;
		}

		/* if adapter supports mitigation, set default value */
		if (na->na_flags & (NAF_TX_MITIGATION | NAF_RX_MITIGATION)) {
			if (IFNET_IS_WIFI(ifp)) {
				na->na_ch_mit_ival = CH_MIT_IVAL_WIFI;
			} else if (IFNET_IS_CELLULAR(ifp)) {
				na->na_ch_mit_ival = CH_MIT_IVAL_CELLULAR;
			} else if (IFNET_IS_ETHERNET(ifp)) {
				na->na_ch_mit_ival = CH_MIT_IVAL_ETHERNET;
			} else {
				na->na_ch_mit_ival = CH_MIT_IVAL_DEFAULT;
			}
		}
	}

done:
	SK_DF(err ? SK_VERB_ERROR : SK_VERB_FSW,
	    "fsw 0x%llx nx_port %d vpna_pid %d vpna_pid_bound %u mit_ival %llu "
	    "(err %d)", SK_KVA(fsw), (int)vpna->vpna_nx_port, vpna->vpna_pid,
	    vpna->vpna_pid_bound, vpna->vpna_up.na_ch_mit_ival, err);

	return err;
}

static bool
fsw_port_dtor(struct nx_flowswitch *fsw, const struct nexus_vp_adapter *vpna)
{
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	nexus_port_t nx_port = vpna->vpna_nx_port;
	uint32_t purge_cnt;

	ASSERT(fsw == vpna->vpna_fsw);
	ASSERT(nx_port != NEXUS_PORT_ANY);

	/*
	 * If this nexus port was bound to a PID, we just need to look at a
	 * single bucket and iterate from there.  Note that in any case, we
	 * can't just search for a single flow_owner based on the PID itself,
	 * since a given process may be opening multiple channels to the
	 * flowswitch; hence we search for the ones matching this nexus port.
	 *
	 * Close any open flows on the port and remove the flow owner and
	 * nexus port binding.
	 */
	purge_cnt = flow_owner_detach_nexus_port(fm, vpna->vpna_pid_bound,
	    vpna->vpna_pid, nx_port, FALSE);

	SK_DF(SK_VERB_FSW,
	    "fsw 0x%llx nx_port %d pid %d pid_bound %u defunct %u "
	    "purged %u", SK_KVA(fsw), (int)nx_port,
	    vpna->vpna_pid, vpna->vpna_pid_bound, vpna->vpna_defunct,
	    purge_cnt);

	return purge_cnt != 0;
}

/*
 * Flowswitch nexus port allocator.
 *
 * A nexus port is represented by a bit in the port bitmap; its state is
 * either free or allocated.  A free state implies that the port has no
 * nxbind AND no nexus adapter association.  An allocated state means that
 * either it has a nxbind OR a nexus adapter assocation.  This routine
 * manages the nexus adapter association with a nexus port; nxbind is
 * handled separately via nx_fsw_port_bind().
 *
 * The caller of this routine may optionally pass in a NULL nexus adapter.
 * In such a case (*vpna is NULL), this routine checks to see if the port
 * has already been associated with an adapter, and returns a reference to
 * that adapter.  No action is taken on a port that doesn't have an adapter
 * associated.  Otherwise (*vpna is non-NULL), this routine associates that
 * adapter with a port that's not already associated with one; the reference
 * to the adapter is untouched here, as the caller is expected to handle it.
 *
 * The flowswitch code invokes this routine each time it is requested to
 * find an adapter via nx_fsw_na_find().  The counterpart of this routine,
 * nx_fsw_port_free(), is only executed ONCE by the adapter's destructor.
 * This allows for multiple channels to be opened to a nexus port, each
 * time holding a reference to that same nexus adapter.  The releasing of
 * the nexus port only happens when the last channel closes.
 */
static int
fsw_port_alloc__(struct nx_flowswitch *fsw, struct nxbind *nxb,
    struct nexus_vp_adapter **vpna, nexus_port_t nx_port, struct proc *p)
{
	struct kern_nexus *nx = fsw->fsw_nx;
	boolean_t refonly = FALSE;
	int error = 0;

	FSW_WLOCK_ASSERT_HELD(fsw);

	error = nx_port_alloc(nx, nx_port, nxb, (struct nexus_adapter **)vpna, p);
	if (error == 0 && *vpna != NULL && !refonly) {
		/* initialize the nexus port and the adapter occupying it */
		(*vpna)->vpna_fsw = fsw;
		(*vpna)->vpna_nx_port = nx_port;
		(*vpna)->vpna_pid = proc_pid(p);
		if (nxb != NULL && (nxb->nxb_flags & NXBF_MATCH_UNIQUEID)) {
			ASSERT((*vpna)->vpna_pid == nxb->nxb_pid);
			(*vpna)->vpna_pid_bound = TRUE;
		} else {
			(*vpna)->vpna_pid_bound = FALSE;
		}

		error = fsw_port_ctor(fsw, *vpna, nxb);
		if (error != 0) {
			fsw_port_free(fsw, (*vpna),
			    (*vpna)->vpna_nx_port, FALSE);
		}
	}

#if SK_LOG
	if (*vpna != NULL) {
		SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
		    "+++ vpna \"%s\" (0x%llx) <-> fsw 0x%llx "
		    "%sport %d refonly %u (err %d)",
		    (*vpna)->vpna_up.na_name, SK_KVA(*vpna), SK_KVA(fsw),
		    nx_fsw_dom_port_is_reserved(nx, nx_port) ?
		    "[reserved] " : "", (int)nx_port, refonly, error);
	} else {
		SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
		    "+++ fsw 0x%llx nx_port %d refonly %u "
		    "(err %d)", SK_KVA(fsw), (int)nx_port, refonly, error);
	}
#endif /* SK_LOG */

	return error;
}

int
fsw_port_alloc(struct nx_flowswitch *fsw, struct nxbind *nxb,
    struct nexus_vp_adapter **vpna, nexus_port_t nx_port, struct proc *p,
    boolean_t ifattach, boolean_t host)
{
	int err = 0;

	FSW_WLOCK_ASSERT_HELD(fsw);

	if (ifattach) {
		/* override port to either NX_FSW_{HOST,DEV} */
		nx_port = (host ? FSW_VP_HOST : FSW_VP_DEV);
		/* allocate reserved port for ifattach */
		err = fsw_port_alloc__(fsw, nxb, vpna, nx_port, p);
	} else if (host) {
		/* host is valid only for ifattach */
		err = EINVAL;
	} else {
		/* nexus port otherwise (reserve dev and host for ifattach) */
		err = fsw_port_alloc__(fsw, nxb, vpna, nx_port, p);
	}

	return err;
}

/*
 * Remove nexus port association from a nexus adapter.  This call is
 * the opposite of fsw_port_alloc(), except that it is called only
 * at nx_fsw_vp_na_dtor() destructor time.  See above notes
 * on fsw_port_alloc().
 */
void
fsw_port_free(struct nx_flowswitch *fsw, struct nexus_vp_adapter *vpna,
    nexus_port_t nx_port, boolean_t defunct)
{
	struct kern_nexus *nx = fsw->fsw_nx;

	FSW_WLOCK_ASSERT_HELD(fsw);
	ASSERT(vpna->vpna_fsw == fsw);

	if (defunct) {
		vpna->vpna_defunct = TRUE;
		nx_port_defunct(nx, nx_port);
	}

	bool destroyed = fsw_port_dtor(fsw, vpna);
	if (destroyed) {
		/*
		 * If the extension's destructor no longer needs to be
		 * bound to any channel client, release the binding.
		 */
		nx_port_unbind(nx, nx_port);
	}

	/*
	 * If this is a defunct, then stop here as the port is still
	 * occupied by the channel.  We'll come here again later when
	 * the actual close happens.
	 */
	if (defunct) {
		return;
	}

	SK_DF(SK_VERB_FSW, "--- vpna \"%s\" (0x%llx) -!- fsw 0x%llx "
	    "nx_port %d defunct %u", vpna->vpna_up.na_name, SK_KVA(vpna),
	    SK_KVA(fsw), (int)nx_port, vpna->vpna_defunct);

	nx_port_free(nx, nx_port);
	vpna->vpna_fsw = NULL;
	vpna->vpna_nx_port = NEXUS_PORT_ANY;
	vpna->vpna_pid_bound = FALSE;
	vpna->vpna_pid = -1;
	vpna->vpna_defunct = FALSE;
}

int
fsw_port_na_activate(struct nx_flowswitch *fsw,
    struct nexus_vp_adapter *vpna, na_activate_mode_t mode)
{
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	uint32_t fo_cnt = 0;

	SK_LOCK_ASSERT_HELD();

	/* The following code relies on the static value asserted below */
	_CASSERT(FSW_VP_DEV == 0);
	_CASSERT(FSW_VP_HOST == 1);

	ASSERT(NA_IS_ACTIVE(&vpna->vpna_up));
	ASSERT(vpna->vpna_nx_port != NEXUS_PORT_ANY);

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		break;

	case NA_ACTIVATE_MODE_OFF:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* nothing further to do for special ports */
	if (vpna->vpna_nx_port < FSW_VP_USER_MIN) {
		goto done;
	}

	/* activate any flow owner related resources (e.g. flowadv), if any */
	fo_cnt = flow_owner_activate_nexus_port(fm, vpna->vpna_pid_bound,
	    vpna->vpna_pid, vpna->vpna_nx_port, &vpna->vpna_up, mode);

done:
	SK_DF(SK_VERB_FSW,
	    "fsw 0x%llx %s nx_port %d vpna_pid %d vpna_pid_bound %u fo_cnt %u",
	    SK_KVA(fsw), na_activate_mode2str(mode), (int)vpna->vpna_nx_port,
	    vpna->vpna_pid, vpna->vpna_pid_bound, fo_cnt);

	return 0;
}

int
fsw_port_na_defunct(struct nx_flowswitch *fsw, struct nexus_vp_adapter *vpna)
{
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(vpna->vpna_nx_port >= FSW_VP_USER_MIN);

	/*
	 * During defunct, we want to purge all flows associated to this
	 * port and the flow owner as well.  This is accomplished as part
	 * of calling the port's destructor.  However, we still want to
	 * occupy the nexus port since there's a channel open to it.
	 */
	FSW_WLOCK(fsw);
	if (!vpna->vpna_defunct) {
		fsw_port_free(fsw, vpna, vpna->vpna_nx_port, TRUE);
	} else {
		err = EALREADY;
	}
	FSW_WUNLOCK(fsw);

	return err;
}

static size_t
fsw_mib_get_flow(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len)
{
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	size_t sf_size = sizeof(struct sk_stats_flow);
	__block size_t actual_space = 0;
	__block struct sk_stats_flow *sf = out;
	struct flow_entry *fe;

	FSW_LOCK_ASSERT_HELD(fsw);

	if (filter->nmf_bitmap & NXMIB_FILTER_FLOW_ID) {
		fe = flow_mgr_get_fe_by_uuid_rlock(fm, filter->nmf_flow_id);
		if (fe != NULL) {
			if (out != NULL && len >= sf_size) {
				flow_entry_stats_get(fe, sf);
			}

			flow_entry_release(&fe);
			return sf_size;
		}
		return 0;
	} else if (filter->nmf_bitmap & NXMIB_FILTER_INFO_TUPLE) {
		struct info_tuple *itpl = &filter->nmf_info_tuple;
		struct flow_key fk;
		bzero(&fk, sizeof(fk));
		if (itpl->itpl_local_sa.sa_family == AF_INET &&
		    itpl->itpl_remote_sa.sa_family == AF_INET) {
			fk.fk_mask = FKMASK_5TUPLE;
			fk.fk_ipver = IPVERSION;
			fk.fk_proto = itpl->itpl_proto;
			fk.fk_src4 = itpl->itpl_local_sin.sin_addr;
			fk.fk_dst4 = itpl->itpl_remote_sin.sin_addr;
			fk.fk_sport = itpl->itpl_local_sin.sin_port;
			fk.fk_dport = itpl->itpl_remote_sin.sin_port;
		} else if (itpl->itpl_local_sa.sa_family == AF_INET6 &&
		    itpl->itpl_remote_sa.sa_family == AF_INET6) {
			fk.fk_mask = FKMASK_5TUPLE;
			fk.fk_ipver = IPV6_VERSION;
			fk.fk_proto = itpl->itpl_proto;
			fk.fk_src6 = itpl->itpl_local_sin6.sin6_addr;
			fk.fk_dst6 = itpl->itpl_remote_sin6.sin6_addr;
			fk.fk_sport = itpl->itpl_local_sin6.sin6_port;
			fk.fk_dport = itpl->itpl_remote_sin6.sin6_port;
		} else {
			SK_ERR("invalid info tuple: local af %d remote af %d",
			    itpl->itpl_local_sa.sa_family,
			    itpl->itpl_remote_sa.sa_family);
			return 0;
		}

		fe = flow_mgr_find_fe_by_key(fsw->fsw_flow_mgr, &fk);
		if (fe != NULL) {
			if (out != NULL && len >= sf_size) {
				flow_entry_stats_get(fe, sf);
			}
			flow_entry_release(&fe);
			return sf_size;
		}
		return 0;
	}

	flow_mgr_foreach_flow(fsw->fsw_flow_mgr, ^(struct flow_entry *_fe) {
		actual_space += sf_size;

		if (out == NULL || actual_space > len) {
		        return;
		}

		flow_entry_stats_get(_fe, sf);
		sf++;
	});

	/*
	 * Also return the ones in deferred free list.
	 */
	lck_mtx_lock(&fsw->fsw_linger_lock);
	TAILQ_FOREACH(fe, &fsw->fsw_linger_head, fe_linger_link) {
		actual_space += sf_size;
		if (out == NULL || actual_space > len) {
			continue;
		}

		flow_entry_stats_get(fe, sf);
		sf++;
	}
	lck_mtx_unlock(&fsw->fsw_linger_lock);

	return actual_space;
}

static size_t
fsw_mib_get_flow_adv(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len)
{
#pragma unused(filter)
	uint32_t fae_idx;
	size_t actual_space = 0;
	struct kern_channel *ch = NULL;
	struct sk_stats_flow_adv *sfa = NULL;
	struct sk_stats_flow_adv_ent *sfae = NULL;
	struct __flowadv_entry *fae = NULL;
	size_t sfa_size = sizeof(struct sk_stats_flow_adv);
	size_t sfae_size = sizeof(struct sk_stats_flow_adv_ent);
	uint32_t max_flowadv =
	    fsw->fsw_nx->nx_prov->nxprov_params->nxp_flowadv_max;

	SK_LOCK_ASSERT_HELD();

	sfa = out;
	/* copyout flow advisory table (allocated entries only) */
	STAILQ_FOREACH(ch, &fsw->fsw_nx->nx_ch_head, ch_link) {
		struct skmem_arena *ar;
		struct skmem_arena_nexus *arn;
		struct nexus_adapter *na;

		/* ch_lock isn't needed here since sk_lock is held */
		if ((ch->ch_flags & CHANF_CLOSING) ||
		    (na = ch->ch_na) == NULL) {
			/* channel is closing */
			continue;
		}

		ar = na->na_arena;
		arn = skmem_arena_nexus(ar);

		AR_LOCK(ar);
		if (arn->arn_flowadv_obj == NULL) {
			ASSERT(ar->ar_flags & ARF_DEFUNCT);
			AR_UNLOCK(ar);
			continue;
		}
		actual_space += sfa_size;
		/* fill out flowadv_table info */
		if (out != NULL && actual_space <= len) {
			uuid_copy(sfa->sfa_nx_uuid, fsw->fsw_nx->nx_uuid);
			(void) strlcpy(sfa->sfa_if_name,
			    fsw->fsw_flow_mgr->fm_name, IFNAMSIZ);
			sfa->sfa_owner_pid = ch->ch_pid;
			sfa->sfa_entries_count = 0;
		}

		/* fill out flowadv_entries */
		sfae = &sfa->sfa_entries[0];
		for (fae_idx = 0; fae_idx < max_flowadv; fae_idx++) {
			fae = &arn->arn_flowadv_obj[fae_idx];
			if (!uuid_is_null(fae->fae_id)) {
				actual_space += sfae_size;
				if (out == NULL || actual_space > len) {
					continue;
				}

				/* fill out entry */
				uuid_copy(sfae->sfae_flow_id, fae->fae_id);
				sfae->sfae_flags = fae->fae_flags;
				sfae++;
				sfa->sfa_entries_count++;
			}
		}
		sfa = (struct sk_stats_flow_adv *)
		    ((uintptr_t)out + actual_space);
		AR_UNLOCK(ar);
	}

	return actual_space;
}

static inline void
fsw_fo2sfo(struct nx_flowswitch *fsw, struct flow_owner *fo,
    struct sk_stats_flow_owner *sfo)
{
	struct flow_mgr *fm = fsw->fsw_flow_mgr;

	uuid_copy(sfo->sfo_nx_uuid, fsw->fsw_nx->nx_uuid);
	(void) strlcpy(sfo->sfo_if_name, fsw->fsw_flow_mgr->fm_name,
	    IFNAMSIZ);
	sfo->sfo_bucket_idx = flow_mgr_get_fob_idx(fm, FO_BUCKET(fo));

	(void) snprintf(sfo->sfo_name, sizeof(sfo->sfo_name), "%s",
	    fo->fo_name);
	sfo->sfo_pid = fo->fo_pid;
	sfo->sfo_nx_port = fo->fo_nx_port;
	sfo->sfo_nx_port_pid_bound = fo->fo_nx_port_pid_bound;
	sfo->sfo_nx_port_destroyed = fo->fo_nx_port_destroyed;
}

static size_t
fsw_mib_get_flow_owner(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len)
{
#pragma unused(filter)
	uint32_t i;
	size_t actual_space = 0;
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	struct sk_stats_flow_owner *sfo = out;
	size_t sfo_size = sizeof(struct sk_stats_flow_owner);
	struct flow_owner *fo;

	FSW_LOCK_ASSERT_HELD(fsw);

	/*
	 * Ideally we'd like to hide the bucket level details from flow library
	 * user, but there is no simple way to iterate flow_owner with
	 * buckets/RB_TREE nested. So keep it as is.
	 */
	for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
		struct flow_owner_bucket *fob = flow_mgr_get_fob_at_idx(fm, i);
		FOB_LOCK(fob);
		RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
			actual_space += sfo_size;
			if (out == NULL || actual_space > len) {
				continue;
			}

			fsw_fo2sfo(fsw, fo, sfo);
			sfo++;
		}
		FOB_UNLOCK(fob);
	}

	return actual_space;
}

static inline void
fsw_fr2sfr(struct nx_flowswitch *fsw, struct flow_route *fr,
    struct sk_stats_flow_route *sfr, boolean_t ll_scrub)
{
	uuid_copy(sfr->sfr_nx_uuid, fsw->fsw_nx->nx_uuid);
	uuid_copy(sfr->sfr_uuid, fr->fr_uuid);
	(void) strlcpy(sfr->sfr_if_name, fsw->fsw_flow_mgr->fm_name,
	    IFNAMSIZ);

	sfr->sfr_bucket_idx = fr->fr_frb->frb_idx;
	sfr->sfr_id_bucket_idx = fr->fr_frib->frib_idx;

	if (fr->fr_flags & FLOWRTF_ATTACHED) {
		sfr->sfr_flags |= SFLOWRTF_ATTACHED;
	}
	if (fr->fr_flags & FLOWRTF_ONLINK) {
		sfr->sfr_flags |= SFLOWRTF_ONLINK;
	}
	if (fr->fr_flags & FLOWRTF_GATEWAY) {
		sfr->sfr_flags |= SFLOWRTF_GATEWAY;
	}
	if (fr->fr_flags & FLOWRTF_RESOLVED) {
		sfr->sfr_flags |= SFLOWRTF_RESOLVED;
	}
	if (fr->fr_flags & FLOWRTF_HAS_LLINFO) {
		sfr->sfr_flags |= SFLOWRTF_HAS_LLINFO;
	}
	if (fr->fr_flags & FLOWRTF_DELETED) {
		sfr->sfr_flags |= SFLOWRTF_DELETED;
	}
	if (fr->fr_flags & FLOWRTF_DST_LL_MCAST) {
		sfr->sfr_flags |= SFLOWRTF_DST_LL_MCAST;
	}
	if (fr->fr_flags & FLOWRTF_DST_LL_BCAST) {
		sfr->sfr_flags |= SFLOWRTF_DST_LL_BCAST;
	}

	lck_spin_lock(&fr->fr_reflock);
	ASSERT(fr->fr_usecnt >= FLOW_ROUTE_MINREF);
	sfr->sfr_usecnt = fr->fr_usecnt - FLOW_ROUTE_MINREF;
	if (fr->fr_expire != 0) {
		sfr->sfr_expire = (int64_t)(fr->fr_expire - net_uptime());
	} else {
		sfr->sfr_expire = 0;
	}
	lck_spin_unlock(&fr->fr_reflock);

	sfr->sfr_laddr = fr->fr_laddr;
	sfr->sfr_faddr = fr->fr_faddr;
	sfr->sfr_gaddr = fr->fr_gaddr;

	if (ll_scrub) {
		static const uint8_t unspec[ETHER_ADDR_LEN] = {[0] = 2 };
		bcopy(&unspec, &sfr->sfr_ether_dhost, ETHER_ADDR_LEN);
	} else {
		bcopy(&fr->fr_eth.ether_dhost, &sfr->sfr_ether_dhost,
		    ETHER_ADDR_LEN);
	}
}

#if CONFIG_MACF
extern int dlil_lladdr_ckreq;
#endif /* CONFIG_MACF */

static size_t
fsw_mib_get_flow_route(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len, struct proc *p)
{
#pragma unused(filter)
	uint32_t i;
	size_t actual_space = 0;
	struct flow_mgr *fm = fsw->fsw_flow_mgr;
	struct sk_stats_flow_route *sfr = out;
	size_t sfo_size = sizeof(struct sk_stats_flow_route);
	struct flow_route *fr;
	boolean_t ll_scrub;

	FSW_LOCK_ASSERT_HELD(fsw);

	/*
	 * To get the link-layer info, the caller must have the following
	 * in their sandbox profile (or not be sandboxed at all), else we
	 * scrub it clean just like dlil_ifaddr_bytes() does:
	 *
	 * (allow system-info (info-type "net.link.addr"))
	 *
	 * If scrubbed, we return 02:00:00:00:00:00.
	 */
#if CONFIG_MACF
	ll_scrub = (dlil_lladdr_ckreq &&
	    skywalk_mac_system_check_proc_cred(p, "net.link.addr") != 0);
#else /* !CONFIG_MACF */
	ll_scrub = FALSE;
#endif /* !CONFIG_MACF */

	for (i = 0; i < fm->fm_route_buckets_cnt; i++) {
		struct flow_route_bucket *frb = flow_mgr_get_frb_at_idx(fm, i);
		FRB_RLOCK(frb);
		RB_FOREACH(fr, flow_route_tree, &frb->frb_head) {
			actual_space += sfo_size;
			if (out == NULL || actual_space > len) {
				continue;
			}

			fsw_fr2sfr(fsw, fr, sfr, ll_scrub);
			sfr++;
		}
		FRB_UNLOCK(frb);
	}

	return actual_space;
}

static inline void
fsw_nxs2nus(struct nx_flowswitch *fsw, struct nexus_mib_filter *filter,
    pid_t pid, struct __nx_stats_fsw *nxs, struct sk_stats_userstack *sus)
{
	uuid_copy(sus->sus_nx_uuid, fsw->fsw_nx->nx_uuid);
	(void) strlcpy(sus->sus_if_name, fsw->fsw_flow_mgr->fm_name,
	    IFNAMSIZ);
	sus->sus_owner_pid = pid;

	if (filter->nmf_type & NXMIB_IP_STATS) {
		sus->sus_ip  = nxs->nxs_ipstat;
	}

	if (filter->nmf_type & NXMIB_IP6_STATS) {
		sus->sus_ip6 = nxs->nxs_ip6stat;
	}

	if (filter->nmf_type & NXMIB_TCP_STATS) {
		sus->sus_tcp = nxs->nxs_tcpstat;
	}

	if (filter->nmf_type & NXMIB_UDP_STATS) {
		sus->sus_udp = nxs->nxs_udpstat;
	}

	if (filter->nmf_type & NXMIB_QUIC_STATS) {
		sus->sus_quic = nxs->nxs_quicstat;
	}
}

static size_t
fsw_mib_get_userstack_stats(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len)
{
	size_t actual_space = 0;
	struct kern_channel *ch;
	struct __nx_stats_fsw *nxs;
	struct sk_stats_userstack *sus = out;
	size_t sus_size = sizeof(struct sk_stats_userstack);

	SK_LOCK_ASSERT_HELD();

	/* copyout saved stats from closed ports */
	if (((filter->nmf_bitmap & NXMIB_FILTER_PID) &&
	    (filter->nmf_pid == 0)) ||
	    !(filter->nmf_bitmap & NXMIB_FILTER_PID)) {
		actual_space += sus_size;
		if (out != NULL && actual_space <= len) {
			nxs = fsw->fsw_closed_na_stats;
			fsw_nxs2nus(fsw, filter, 0, nxs, sus);
			sus++;
		}
	}

	/*
	 * XXX Currently a proc only opens one channel to nexus so we don't do
	 * per proc aggregation of inet stats now as this needs lots of code
	 */
	/* copyout per process stats */
	STAILQ_FOREACH(ch, &fsw->fsw_nx->nx_ch_head, ch_link) {
		struct skmem_arena *ar;
		struct nexus_adapter *na;

		/* ch_lock isn't needed here since sk_lock is held */
		if ((ch->ch_flags & CHANF_CLOSING) ||
		    (na = ch->ch_na) == NULL) {
			/* channel is closing */
			continue;
		}

		if ((filter->nmf_bitmap & NXMIB_FILTER_PID) &&
		    filter->nmf_pid != ch->ch_pid) {
			continue;
		}

		ar = na->na_arena;

		AR_LOCK(ar);
		nxs = skmem_arena_nexus(ar)->arn_stats_obj;
		if (nxs == NULL) {
			ASSERT(ar->ar_flags & ARF_DEFUNCT);
			AR_UNLOCK(ar);
			continue;
		}

		actual_space += sus_size;
		if (out == NULL || actual_space > len) {
			AR_UNLOCK(ar);
			continue;
		}

		fsw_nxs2nus(fsw, filter, ch->ch_pid, nxs, sus);
		sus++;
		AR_UNLOCK(ar);
	}

	return actual_space;
}

static size_t
fsw_mib_get_stats(struct nx_flowswitch *fsw, void *out, size_t len)
{
	struct sk_stats_flow_switch *sfs = out;
	size_t actual_space = sizeof(struct sk_stats_flow_switch);

	if (out != NULL && actual_space <= len) {
		uuid_copy(sfs->sfs_nx_uuid, fsw->fsw_nx->nx_uuid);
		(void) strlcpy(sfs->sfs_if_name,
		    fsw->fsw_flow_mgr->fm_name, IFNAMSIZ);
		sfs->sfs_fsws = fsw->fsw_stats;
	}

	return actual_space;
}

size_t
fsw_mib_get(struct nx_flowswitch *fsw, struct nexus_mib_filter *filter,
    void *out, size_t len, struct proc *p)
{
	size_t ret;

	switch (filter->nmf_type) {
	case NXMIB_FSW_STATS:
		ret = fsw_mib_get_stats(fsw, out, len);
		break;
	case NXMIB_FLOW:
		ret = fsw_mib_get_flow(fsw, filter, out, len);
		break;
	case NXMIB_FLOW_OWNER:
		ret = fsw_mib_get_flow_owner(fsw, filter, out, len);
		break;
	case NXMIB_FLOW_ROUTE:
		ret = fsw_mib_get_flow_route(fsw, filter, out, len, p);
		break;
	case NXMIB_TCP_STATS:
	case NXMIB_UDP_STATS:
	case NXMIB_IP_STATS:
	case NXMIB_IP6_STATS:
	case NXMIB_USERSTACK_STATS:
		ret = fsw_mib_get_userstack_stats(fsw, filter, out, len);
		break;
	case NXMIB_FLOW_ADV:
		ret = fsw_mib_get_flow_adv(fsw, filter, out, len);
		break;
	default:
		ret = 0;
		break;
	}

	return ret;
}

void
fsw_fold_stats(struct nx_flowswitch *fsw,
    void *data, nexus_stats_type_t type)
{
	ASSERT(data != NULL);
	FSW_LOCK_ASSERT_HELD(fsw);

	switch (type) {
	case NEXUS_STATS_TYPE_FSW:
	{
		struct __nx_stats_fsw *d, *s;
		d = fsw->fsw_closed_na_stats;
		s = data;
		ip_stats_fold(&d->nxs_ipstat, &s->nxs_ipstat);
		ip6_stats_fold(&d->nxs_ip6stat, &s->nxs_ip6stat);
		tcp_stats_fold(&d->nxs_tcpstat, &s->nxs_tcpstat);
		udp_stats_fold(&d->nxs_udpstat, &s->nxs_udpstat);
		quic_stats_fold(&d->nxs_quicstat, &s->nxs_quicstat);
		break;
	}
	case NEXUS_STATS_TYPE_CHAN_ERRORS:
	{
		struct __nx_stats_channel_errors *s = data;
		fsw_vp_channel_error_stats_fold(&fsw->fsw_stats, s);
		break;
	}
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

boolean_t
fsw_detach_barrier_add(struct nx_flowswitch *fsw)
{
	lck_mtx_lock_spin(&fsw->fsw_detach_barrier_lock);
	if (__improbable(fsw->fsw_detach_flags != 0 ||
	    fsw->fsw_ifp == NULL || fsw->fsw_agent_session == NULL)) {
		lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
		return FALSE;
	}
	fsw->fsw_detach_barriers++;
	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);

	return TRUE;
}

void
fsw_detach_barrier_remove(struct nx_flowswitch *fsw)
{
	lck_mtx_lock_spin(&fsw->fsw_detach_barrier_lock);
	ASSERT((fsw->fsw_detach_flags & FSW_DETACHF_DETACHED) == 0);
	ASSERT(fsw->fsw_detach_barriers != 0);
	fsw->fsw_detach_barriers--;
	/* if there's a thread waiting to detach the interface, let it know */
	if (__improbable((fsw->fsw_detach_waiters > 0) &&
	    (fsw->fsw_detach_barriers == 0))) {
		fsw->fsw_detach_waiters = 0;
		wakeup(&fsw->fsw_detach_waiters);
	}
	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
}

/*
 * Generic resolver for non-Ethernet interfaces.
 */
int
fsw_generic_resolve(struct nx_flowswitch *fsw, struct flow_route *fr,
    struct __kern_packet *pkt)
{
#pragma unused(pkt)
#if SK_LOG
	char dst_s[MAX_IPv6_STR_LEN];
#endif /* SK_LOG */
	struct ifnet *ifp = fsw->fsw_ifp;
	struct rtentry *tgt_rt = NULL;
	int err = 0;

	ASSERT(fr != NULL);
	ASSERT(ifp != NULL);

	FR_LOCK(fr);
	/*
	 * If the destination is on-link, we use the final destination
	 * address as target.  If it's off-link, we use the gateway
	 * address instead.  Point tgt_rt to the the destination or
	 * gateway route accordingly.
	 */
	if (fr->fr_flags & FLOWRTF_ONLINK) {
		tgt_rt = fr->fr_rt_dst;
	} else if (fr->fr_flags & FLOWRTF_GATEWAY) {
		tgt_rt = fr->fr_rt_gw;
	}

	/*
	 * Perform another routing table lookup if necessary.
	 */
	if (tgt_rt == NULL || !(tgt_rt->rt_flags & RTF_UP) ||
	    fr->fr_want_configure) {
		if (fr->fr_want_configure == 0) {
			atomic_add_32(&fr->fr_want_configure, 1);
		}
		err = flow_route_configure(fr, ifp, NULL);
		if (err != 0) {
			SK_ERR("failed to configure route to %s on %s (err %d)",
			    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
			    sizeof(dst_s)), ifp->if_xname, err);
			goto done;
		}

		/* refresh pointers */
		if (fr->fr_flags & FLOWRTF_ONLINK) {
			tgt_rt = fr->fr_rt_dst;
		} else if (fr->fr_flags & FLOWRTF_GATEWAY) {
			tgt_rt = fr->fr_rt_gw;
		}
	}

	if (__improbable(!(fr->fr_flags & (FLOWRTF_ONLINK | FLOWRTF_GATEWAY)))) {
		err = EHOSTUNREACH;
		SK_ERR("invalid route for %s on %s (err %d)",
		    sk_sa_ntop(SA(&fr->fr_faddr), dst_s,
		    sizeof(dst_s)), ifp->if_xname, err);
		goto done;
	}

	ASSERT(tgt_rt != NULL);

done:
	if (__probable(err == 0)) {
		/*
		 * There's no actual resolution taking place here, so just
		 * mark it with FLOWRTF_RESOLVED for consistency.
		 */
		atomic_bitset_32(&fr->fr_flags, FLOWRTF_RESOLVED);
		atomic_set_32(&fr->fr_want_probe, 0);
	} else {
		atomic_bitclear_32(&fr->fr_flags, FLOWRTF_RESOLVED);
		flow_route_cleanup(fr);
	}
	FR_UNLOCK(fr);

	return err;
}

void
fsw_init(void)
{
	_CASSERT(NX_FSW_CHUNK_FREE == (uint64_t)-1);
	_CASSERT(PKT_MAX_PROTO_HEADER_SIZE <= NX_FSW_MINBUFSIZE);

	if (!__nx_fsw_inited) {
		/*
		 * Register callbacks for interface & protocol events
		 * Use dummy arg for callback cookie.
		 */
		__nx_fsw_ifnet_eventhandler_tag =
		    EVENTHANDLER_REGISTER(&ifnet_evhdlr_ctxt,
		    ifnet_event, fsw_ifnet_event_callback,
		    eventhandler_entry_dummy_arg, EVENTHANDLER_PRI_ANY);
		VERIFY(__nx_fsw_ifnet_eventhandler_tag != NULL);

		__nx_fsw_protoctl_eventhandler_tag =
		    EVENTHANDLER_REGISTER(&protoctl_evhdlr_ctxt,
		    protoctl_event, fsw_protoctl_event_callback,
		    eventhandler_entry_dummy_arg, EVENTHANDLER_PRI_ANY);
		VERIFY(__nx_fsw_protoctl_eventhandler_tag != NULL);
		__nx_fsw_inited = 1;
	}
}

void
fsw_uninit(void)
{
	if (__nx_fsw_inited) {
		EVENTHANDLER_DEREGISTER(&ifnet_evhdlr_ctxt, ifnet_event,
		    __nx_fsw_ifnet_eventhandler_tag);
		EVENTHANDLER_DEREGISTER(&protoctl_evhdlr_ctxt, protoctl_event,
		    __nx_fsw_protoctl_eventhandler_tag);

		__nx_fsw_inited = 0;
	}
}

struct nx_flowswitch *
fsw_alloc(zalloc_flags_t how)
{
	struct nx_flowswitch *fsw;
	struct __nx_stats_fsw *nsfw;

	SK_LOCK_ASSERT_HELD();

	nsfw = zalloc_flags(nx_fsw_stats_zone, how | Z_ZERO);
	if (nsfw == NULL) {
		return NULL;
	}

	fsw = zalloc_flags(nx_fsw_zone, how | Z_ZERO);
	if (fsw == NULL) {
		zfree(nx_fsw_stats_zone, nsfw);
		return NULL;
	}

	FSW_RWINIT(fsw);
	fsw->fsw_dev_ch = NULL;
	fsw->fsw_host_ch = NULL;
	fsw->fsw_closed_na_stats = nsfw;

	SK_DF(SK_VERB_MEM, "fsw 0x%llx ALLOC", SK_KVA(fsw));

	return fsw;
}

static int
fsw_detach(struct nx_flowswitch *fsw, struct nexus_adapter *hwna,
    boolean_t purge)
{
	struct kern_nexus_provider *nx_prov = fsw->fsw_nx->nx_prov;
	boolean_t do_dtor = FALSE;

	SK_LOCK_ASSERT_HELD();

	/*
	 * return error if the the host port detach is in progress
	 * or already detached.
	 * For the case of flowswitch free (i.e. purge is TRUE) we have to
	 * cleanup everything, so we will block if needed.
	 */
	lck_mtx_lock(&fsw->fsw_detach_barrier_lock);
	if (!purge && fsw->fsw_detach_flags != 0) {
		SK_ERR("fsw detaching");
		lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
		return EBUSY;
	}
	VERIFY(purge || fsw->fsw_detach_flags == 0);
	/*
	 * mark the flowswitch as detaching and release sk_lock while
	 * waiting for other threads to exit. Maintain lock/unlock
	 * ordering between the two locks.
	 */
	fsw->fsw_detach_flags |= FSW_DETACHF_DETACHING;
	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
	SK_UNLOCK();

	/*
	 * wait until all threads needing accesses to the flowswitch
	 * netagent get out, and mark this as detached to prevent
	 * further access requests from being admitted.
	 */
	lck_mtx_lock(&fsw->fsw_detach_barrier_lock);
	while (fsw->fsw_detach_barriers != 0) {
		fsw->fsw_detach_waiters++;
		(void) msleep(&fsw->fsw_detach_waiters,
		    &fsw->fsw_detach_barrier_lock,
		    (PZERO + 1), __FUNCTION__, NULL);
	}
	VERIFY(fsw->fsw_detach_barriers == 0);
	VERIFY(fsw->fsw_detach_flags != 0);
	fsw->fsw_detach_flags &= ~FSW_DETACHF_DETACHING;
	/*
	 * if the NA detach thread as well as the flowswitch free thread were
	 * both waiting, then the thread which wins the race is responsible
	 * for doing the dtor work.
	 */
	if (fsw->fsw_detach_flags == 0) {
		fsw->fsw_detach_flags |= FSW_DETACHF_DETACHED;
		do_dtor = TRUE;
	}
	VERIFY(fsw->fsw_detach_flags == FSW_DETACHF_DETACHED);
	lck_mtx_unlock(&fsw->fsw_detach_barrier_lock);
	SK_LOCK();

	FSW_WLOCK(fsw);
	if (do_dtor) {
		if (fsw->fsw_ifp != NULL) {
			fsw_teardown_ifp(fsw, hwna);
			ASSERT(fsw->fsw_ifp == NULL);
			ASSERT(fsw->fsw_nifna == NULL);
		}
		bzero(fsw->fsw_slla, sizeof(fsw->fsw_slla));
		nx_prov->nxprov_params->nxp_ifindex = 0;
		/* free any flow entries in the deferred list */
		fsw_linger_purge(fsw);
	}
	/*
	 * If we are destroying the instance, release lock to let all
	 * outstanding agent threads to enter, followed by waiting until
	 * all of them exit the critical section before continuing.
	 */
	if (purge) {
		FSW_UNLOCK(fsw);
		flow_mgr_terminate(fsw->fsw_flow_mgr);
		FSW_WLOCK(fsw);
	}
	FSW_WUNLOCK(fsw);
	return 0;
}

void
fsw_free(struct nx_flowswitch *fsw)
{
	int err;

	SK_LOCK_ASSERT_HELD();
	ASSERT(fsw != NULL);

	err = fsw_detach(fsw, NULL, TRUE);
	VERIFY(err == 0);

	fsw_dp_dtor(fsw);

	ASSERT(fsw->fsw_dev_ch == NULL);
	ASSERT(fsw->fsw_host_ch == NULL);
	ASSERT(fsw->fsw_closed_na_stats != NULL);
	zfree(nx_fsw_stats_zone, fsw->fsw_closed_na_stats);
	fsw->fsw_closed_na_stats = NULL;
	FSW_RWDESTROY(fsw);

	SK_DF(SK_VERB_MEM, "fsw 0x%llx FREE", SK_KVA(fsw));
	zfree(nx_fsw_zone, fsw);
}
