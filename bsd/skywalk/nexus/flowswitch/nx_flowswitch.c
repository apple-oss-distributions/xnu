/*
 * Copyright (c) 2015-2023 Apple Inc. All rights reserved.
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


/*
 * This module implements the flow switch for Skywalk
 *
 * --- FLOW SWITCH ---
 *
 * For each switch, a lock protects deletion of ports. When configuring
 * or deleting a new port, the lock is acquired in exclusive mode (after
 * holding SK_LOCK).  When forwarding, the lock is acquired in shared
 * mode (without SK_LOCK).  The lock is held throughout the entire
 * forwarding cycle, during which the thread may incur in a page fault.
 * Hence it is important that sleepable shared locks are used.
 *
 * On the rx ring, the per-port lock is grabbed initially to reserve
 * a number of slot in the ring, then the lock is released, packets are
 * copied from source to destination, and then the lock is acquired again
 * and the receive ring is updated.  (A similar thing is done on the tx
 * ring for NIC and host stack ports attached to the switch)
 *
 * When a netif is attached to a flowswitch, two kernel channels are opened:
 * The device and host channels. The device channel provides the device
 * datapath. The host channel is not used in the datapath. It is there
 * only for providing some callbacks for activating the hostna (e.g.
 * intercepting host packets).
 */

#include <net/bpf.h>
#include <netinet/tcp_seq.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/upipe/nx_user_pipe.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/nexus_var.h>
#include <sys/protosw.h>
#include <sys/domain.h>

SYSCTL_EXTENSIBLE_NODE(_kern_skywalk, OID_AUTO, flowswitch,
    CTLFLAG_RW | CTLFLAG_LOCKED, 0, "Skywalk FlowSwitch");

static void nx_fsw_dom_init(struct nxdom *);
static void nx_fsw_dom_terminate(struct nxdom *);
static void nx_fsw_dom_fini(struct nxdom *);
static int nx_fsw_dom_find_port(struct kern_nexus *, boolean_t, nexus_port_t *);
static int nx_fsw_dom_bind_port(struct kern_nexus *, nexus_port_t *,
    struct nxbind *, void *);
static int nx_fsw_dom_unbind_port(struct kern_nexus *, nexus_port_t);
static int nx_fsw_dom_connect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *);
static void nx_fsw_dom_disconnect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *);
static void nx_fsw_dom_defunct(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct proc *);
static void nx_fsw_dom_defunct_finalize(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, boolean_t);

static int nx_fsw_prov_init(struct kern_nexus_domain_provider *);
static int nx_fsw_prov_params_adjust(const struct kern_nexus_domain_provider *,
    const struct nxprov_params *, struct nxprov_adjusted_params *);
static int nx_fsw_prov_params(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS], uint32_t);
static int nx_fsw_prov_mem_new(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nexus_adapter *);
static int nx_fsw_prov_config(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nx_cfg_req *, int, struct proc *,
    kauth_cred_t);
static void nx_fsw_prov_fini(struct kern_nexus_domain_provider *);
static int nx_fsw_prov_nx_ctor(struct kern_nexus *);
static void nx_fsw_prov_nx_dtor(struct kern_nexus *);
static size_t nx_fsw_prov_mib_get(struct kern_nexus *nx,
    struct nexus_mib_filter *, void *, size_t, struct proc *);

struct nxdom nx_flowswitch_dom_s = {
	.nxdom_prov_head =
    STAILQ_HEAD_INITIALIZER(nx_flowswitch_dom_s.nxdom_prov_head),
	.nxdom_type =           NEXUS_TYPE_FLOW_SWITCH,
	.nxdom_md_type =        NEXUS_META_TYPE_PACKET,
	.nxdom_md_subtype =     NEXUS_META_SUBTYPE_RAW,
	.nxdom_name =           "flowswitch",
	.nxdom_ports = {
		.nb_def = NX_FSW_VP_MAX,
		.nb_min = NX_FSW_VP_MIN,
		.nb_max = NX_FSW_VP_MAX,
	},
	.nxdom_tx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_FSW_MAXRINGS,
	},
	.nxdom_rx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_FSW_MAXRINGS,
	},
	.nxdom_tx_slots = {
		.nb_def = NX_FSW_TXRINGSIZE,
		.nb_min = NX_FSW_MINSLOTS,
		.nb_max = NX_FSW_MAXSLOTS,
	},
	.nxdom_rx_slots = {
		.nb_def = NX_FSW_RXRINGSIZE,
		.nb_min = NX_FSW_MINSLOTS,
		.nb_max = NX_FSW_MAXSLOTS,
	},
	.nxdom_buf_size = {
		.nb_def = NX_FSW_BUFSIZE,
		.nb_min = NX_FSW_MINBUFSIZE,
		.nb_max = NX_FSW_MAXBUFSIZE,
	},
	.nxdom_large_buf_size = {
		.nb_def = NX_FSW_DEF_LARGE_BUFSIZE,
		.nb_min = NX_FSW_MIN_LARGE_BUFSIZE,
		.nb_max = NX_FSW_MAX_LARGE_BUFSIZE,
	},
	.nxdom_meta_size = {
		.nb_def = NX_FSW_UMD_SIZE,
		.nb_min = NX_FSW_UMD_SIZE,
		.nb_max = NX_METADATA_USR_MAX_SZ,
	},
	.nxdom_stats_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_STATS_MAX_SZ,
	},
	.nxdom_pipes = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_UPIPE_MAXPIPES,
	},
	.nxdom_flowadv_max = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_FLOWADV_MAX,
	},
	.nxdom_nexusadv_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = NX_NEXUSADV_MAX_SZ,
	},
	.nxdom_capabilities = {
		.nb_def = NXPCAP_USER_CHANNEL,
		.nb_min = 0,
		.nb_max = (NXPCAP_CHECKSUM_PARTIAL | NXPCAP_USER_PACKET_POOL |
    NXPCAP_USER_CHANNEL),
	},
	.nxdom_qmap = {
		.nb_def = NEXUS_QMAP_TYPE_INVALID,
		.nb_min = NEXUS_QMAP_TYPE_INVALID,
		.nb_max = NEXUS_QMAP_TYPE_INVALID,
	},
	.nxdom_max_frags = {
		.nb_def = NX_PBUF_FRAGS_DEFAULT,
		.nb_min = NX_PBUF_FRAGS_MIN,
		.nb_max = NX_PBUF_FRAGS_MAX,
	},
	.nxdom_init =           nx_fsw_dom_init,
	.nxdom_terminate =      nx_fsw_dom_terminate,
	.nxdom_fini =           nx_fsw_dom_fini,
	.nxdom_connect =        nx_fsw_dom_connect,
	.nxdom_find_port =      nx_fsw_dom_find_port,
	.nxdom_port_is_reserved = nx_fsw_dom_port_is_reserved,
	.nxdom_bind_port =      nx_fsw_dom_bind_port,
	.nxdom_unbind_port =    nx_fsw_dom_unbind_port,
	.nxdom_disconnect =     nx_fsw_dom_disconnect,
	.nxdom_defunct =        nx_fsw_dom_defunct,
	.nxdom_defunct_finalize = nx_fsw_dom_defunct_finalize,
};

struct kern_nexus_domain_provider nx_fsw_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_FLOW_SWITCH,
	.nxdom_prov_flags =             NXDOMPROVF_DEFAULT,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_fsw_prov_init,
		.dp_cb_fini =           nx_fsw_prov_fini,
		.dp_cb_params =         nx_fsw_prov_params,
		.dp_cb_mem_new =        nx_fsw_prov_mem_new,
		.dp_cb_config =         nx_fsw_prov_config,
		.dp_cb_nx_ctor =        nx_fsw_prov_nx_ctor,
		.dp_cb_nx_dtor =        nx_fsw_prov_nx_dtor,
		.dp_cb_nx_mem_info =    NULL,   /* not supported */
		.dp_cb_nx_mib_get =     nx_fsw_prov_mib_get,
		.dp_cb_nx_stop =        NULL,
	},
};


static void
nx_fsw_dom_init(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED));

	/* Generic initialization */
	fsw_init();
	fsw_dp_init();

	(void) nxdom_prov_add(nxdom, &nx_fsw_prov_s);
}

static void
nx_fsw_dom_terminate(struct nxdom *nxdom)
{
	struct kern_nexus_domain_provider *nxdom_prov, *tnxdp;

	SK_LOCK_ASSERT_HELD();

	STAILQ_FOREACH_SAFE(nxdom_prov, &nxdom->nxdom_prov_head,
	    nxdom_prov_link, tnxdp) {
		(void) nxdom_prov_del(nxdom_prov);
	}

	fsw_dp_uninit();

	/* Generic uninitialization */
	fsw_uninit();
}

static void
nx_fsw_dom_fini(struct nxdom *nxdom)
{
#pragma unused(nxdom)
}

static int
nx_fsw_prov_init(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);
	return 0;
}

static int
nx_fsw_prov_params_adjust(const struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_params *nxp, struct nxprov_adjusted_params *adj)
{
#pragma unused(nxdom_prov, nxp)
	_CASSERT(NX_FSW_AFRINGSIZE <= NX_FSW_RXRINGSIZE);
	_CASSERT(NX_FSW_AFRINGSIZE <= NX_FSW_TXRINGSIZE);

	*(adj->adj_md_subtype) = NEXUS_META_SUBTYPE_PAYLOAD;
	*(adj->adj_stats_size) = sizeof(struct __nx_stats_fsw);
	VERIFY(sk_max_flows > 0 && sk_max_flows <= NX_FLOWADV_MAX);
	*(adj->adj_flowadv_max) = sk_max_flows;
	*(adj->adj_nexusadv_size) = sizeof(struct sk_nexusadv);
	*(adj->adj_caps) |= NXPCAP_USER_PACKET_POOL;
	if (sk_cksum_tx != 0) {
		*(adj->adj_caps) |= NXPCAP_CHECKSUM_PARTIAL;
	}
	*(adj->adj_alloc_rings) = *(adj->adj_free_rings) =
	    ((nxp->nxp_max_frags > 1) && (sk_channel_buflet_alloc != 0)) ?
	    2 : 1;
	*(adj->adj_alloc_slots) = *(adj->adj_free_slots) =
	    NX_FSW_AFRINGSIZE;

	if (!SKMEM_MEM_CONSTRAINED_DEVICE() &&
	    (*(adj->adj_buf_region_segment_size) < NX_FSW_BUF_SEG_SIZE)) {
		*(adj->adj_buf_region_segment_size) = NX_FSW_BUF_SEG_SIZE;
	}

	if (*(adj->adj_max_frags) > 1) {
		uint32_t fsw_maxbufs = SKMEM_MEM_CONSTRAINED_DEVICE() ?
		    NX_FSW_MAXBUFFERS_MEM_CONSTRAINED : NX_FSW_MAXBUFFERS;
		uint32_t magazine_max_objs;

		*(adj->adj_max_buffers) = (sk_fsw_max_bufs != 0) ?
		    sk_fsw_max_bufs : fsw_maxbufs;

		/*
		 * Given that packet objects are the ones cached, use the
		 * metadata size to determine the extra amount of objects
		 * at magazine layer.
		 */
		magazine_max_objs = skmem_cache_magazine_max(
			NX_METADATA_PACKET_SZ(*(adj->adj_max_frags)) +
			METADATA_PREAMBLE_SZ);

		/*
		 * Adjust the max buffers to account for the increase
		 * associated with per-CPU caching.
		 */
		if (skmem_allow_magazines() &&
		    magazine_max_objs < *(adj->adj_max_buffers)) {
			*(adj->adj_max_buffers) -= magazine_max_objs;
		}
	}
	if (SKMEM_MEM_CONSTRAINED_DEVICE() || (fsw_use_dual_sized_pool == 0) ||
	    (*(adj->adj_max_frags) <= 1)) {
		*(adj->adj_large_buf_size) = 0;
	}
	return 0;
}

static int
nx_fsw_prov_params(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS],
    uint32_t pp_region_config_flags)
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;

	/* USD regions need to be writable to support user packet pool */
	srp[SKMEM_REGION_TXAUSD].srp_cflags &= ~SKMEM_REGION_CR_UREADONLY;
	srp[SKMEM_REGION_RXFUSD].srp_cflags &= ~SKMEM_REGION_CR_UREADONLY;

	return nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	           nxdom, nxdom, nxdom, pp_region_config_flags,
	           nx_fsw_prov_params_adjust);
}

static void
fsw_vp_region_params_setup(struct nexus_adapter *na, struct skmem_region_params *srp0,
    struct skmem_region_params *srp)
{
	int i;
	uint32_t totalrings, nslots, afslots, evslots, lbaslots;

	/* copy default flowswitch parameters initialized in nxprov_params_adjust() */
	for (i = 0; i < SKMEM_REGIONS; i++) {
		srp[i] = srp0[i];
	}
	/* customize parameters that could vary across NAs */
	totalrings = na_get_nrings(na, NR_TX) + na_get_nrings(na, NR_RX) +
	    na_get_nrings(na, NR_A) + na_get_nrings(na, NR_F) +
	    na_get_nrings(na, NR_EV) + na_get_nrings(na, NR_LBA);

	srp[SKMEM_REGION_SCHEMA].srp_r_obj_size =
	    (uint32_t)CHANNEL_SCHEMA_SIZE(totalrings);
	srp[SKMEM_REGION_SCHEMA].srp_r_obj_cnt = totalrings;
	skmem_region_params_config(&srp[SKMEM_REGION_SCHEMA]);

	srp[SKMEM_REGION_RING].srp_r_obj_size =
	    sizeof(struct __user_channel_ring);
	srp[SKMEM_REGION_RING].srp_r_obj_cnt = totalrings;
	skmem_region_params_config(&srp[SKMEM_REGION_RING]);

	nslots = na_get_nslots(na, NR_TX);
	afslots = na_get_nslots(na, NR_A);
	evslots = na_get_nslots(na, NR_EV);
	lbaslots = na_get_nslots(na, NR_LBA);
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_size =
	    MAX(MAX(MAX(nslots, afslots), evslots), lbaslots) * SLOT_DESC_SZ;
	srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt =
	    na_get_nrings(na, NR_TX) + na_get_nrings(na, NR_A) +
	    na_get_nrings(na, NR_EV) + na_get_nrings(na, NR_LBA);
	skmem_region_params_config(&srp[SKMEM_REGION_TXAKSD]);

	/* USD and KSD objects share the same size and count */
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_size =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_size;
	srp[SKMEM_REGION_TXAUSD].srp_r_obj_cnt =
	    srp[SKMEM_REGION_TXAKSD].srp_r_obj_cnt;
	skmem_region_params_config(&srp[SKMEM_REGION_TXAUSD]);
}

static int
nx_fsw_prov_mem_new(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nxdom_prov)
	int err = 0;
	struct skmem_region_params *srp0 = NX_PROV(nx)->nxprov_region_params;
	struct skmem_region_params srp[SKMEM_REGIONS];

	SK_DF(SK_VERB_FSW,
	    "nx 0x%llx (\"%s\":\"%s\") na \"%s\" (0x%llx)", SK_KVA(nx),
	    NX_DOM(nx)->nxdom_name, nxdom_prov->nxdom_prov_name, na->na_name,
	    SK_KVA(na));

	ASSERT(na->na_type == NA_FLOWSWITCH_VP);
	ASSERT(na->na_arena == NULL);
	ASSERT((na->na_flags & NAF_USER_PKT_POOL) != 0);

	fsw_vp_region_params_setup(na, srp0, srp);
	/*
	 * Each port in the flow switch is isolated from one another;
	 * use NULL for the packet buffer pool references to indicate
	 * this, since otherwise we'd be sharing the same pp for the
	 * entire switch (maybe for a future, special use case?)
	 *
	 * This means that clients calling kern_nexus_get_pbufpool()
	 * will get NULL, but this is fine based on current design
	 * of providing port isolation, and also since we don't expose
	 * the flow switch to external kernel clients.
	 */
	na->na_arena = skmem_arena_create_for_nexus(na, srp, NULL, NULL, FALSE,
	    !NX_USER_CHANNEL_PROV(nx), &nx->nx_adv, &err);
	ASSERT(na->na_arena != NULL || err != 0);
	return err;
}

static int
nx_fsw_prov_config(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nx_cfg_req *ncr, int sopt_dir,
    struct proc *p, kauth_cred_t cred)
{
#pragma unused(nxdom_prov)
	struct sockopt sopt;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	if (ncr->nc_req == USER_ADDR_NULL) {
		err = EINVAL;
		goto done;
	}

	/* to make life easier for handling copies */
	bzero(&sopt, sizeof(sopt));
	sopt.sopt_dir = sopt_dir;
	sopt.sopt_val = ncr->nc_req;
	sopt.sopt_valsize = ncr->nc_req_len;
	sopt.sopt_p = p;

	/* avoid _MALLOCing at the cost of this ugly switch block */
	switch (ncr->nc_cmd) {
	case NXCFG_CMD_ATTACH:
	case NXCFG_CMD_DETACH: {
		/* proceed only if the client possesses flow switch entitlement */
		if (cred == NULL || (err = skywalk_priv_check_cred(p, cred,
		    PRIV_SKYWALK_REGISTER_FLOW_SWITCH)) != 0) {
			SK_ERR("missing nxctl credential");
			err = EPERM;
			goto done;
		}

		struct nx_spec_req nsr;
		bzero(&nsr, sizeof(nsr));
		err = sooptcopyin(&sopt, &nsr, sizeof(nsr), sizeof(nsr));
		if (err != 0) {
			goto done;
		}

		/*
		 * Null-terminate in case this has an interface name;
		 * the union is already large enough for uuid_t.
		 */
		nsr.nsr_name[sizeof(nsr.nsr_name) - 1] = '\0';
		if (p != kernproc) {
			nsr.nsr_flags &= NXSPECREQ_MASK;
		}

		err = fsw_ctl(nx, ncr->nc_cmd, p, &nsr);
		if (err != 0) {
			goto done;
		}

		err = sooptcopyout(&sopt, &nsr, sizeof(nsr));
		break;
	}

	case NXCFG_CMD_FLOW_ADD:
	case NXCFG_CMD_FLOW_DEL: {
		/* need to have owner nxctl or kernnxctl */
		if (cred == NULL) {
			SK_ERR("missing nxctl credential");
			err = EPERM;
			goto done;
		}
	} /* fall through */
	case NXCFG_CMD_FLOW_CONFIG: {
		/* checks flow PID ownership instead of nxctl creditial */
		struct nx_flow_req nfr;
		bzero(&nfr, sizeof(nfr));
		err = sooptcopyin(&sopt, &nfr, sizeof(nfr), sizeof(nfr));
		if (err != 0) {
			goto done;
		}

		err = fsw_ctl(nx, ncr->nc_cmd, p, &nfr);
		if (err != 0) {
			goto done;
		}

		err = sooptcopyout(&sopt, &nfr, sizeof(nfr));
		break;
	}

	case NXCFG_CMD_NETEM: {
		struct if_netem_params inp;

		bzero(&inp, sizeof(inp));
		err = sooptcopyin(&sopt, &inp, sizeof(inp), sizeof(inp));
		if (err != 0) {
			goto done;
		}
		err = fsw_ctl(nx, ncr->nc_cmd, p, &inp);
		if (err != 0) {
			goto done;
		}
		break;
	}

	default:
		err = EINVAL;
		goto done;
	}

done:
	SK_DF(err ? SK_VERB_ERROR: SK_VERB_FSW,
	    "nexus 0x%llx (%s) cmd %d (err %d)", SK_KVA(nx),
	    NX_DOM_PROV(nx)->nxdom_prov_name, ncr->nc_cmd, err);
	return err;
}

static void
nx_fsw_prov_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);
}

static int
nx_fsw_prov_nx_ctor(struct kern_nexus *nx)
{
	struct nx_flowswitch *fsw;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nx->nx_arg == NULL);

	SK_D("nexus 0x%llx (%s)", SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name);

	fsw = fsw_alloc(Z_WAITOK);
	nx->nx_arg = fsw;
	fsw->fsw_nx = nx;
	fsw->fsw_tx_rings = NX_PROV(nx)->nxprov_params->nxp_tx_rings;
	fsw->fsw_rx_rings = NX_PROV(nx)->nxprov_params->nxp_rx_rings;

	FSW_WLOCK(fsw);

	fsw_dp_ctor(fsw);

	FSW_WUNLOCK(fsw);

	SK_D("create new fsw 0x%llx for nexus 0x%llx",
	    SK_KVA(NX_FSW_PRIVATE(nx)), SK_KVA(nx));

	return 0;
}

static void
nx_fsw_prov_nx_dtor(struct kern_nexus *nx)
{
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	int err;

	SK_LOCK_ASSERT_HELD();

	SK_D("nexus 0x%llx (%s) fsw 0x%llx", SK_KVA(nx),
	    NX_DOM_PROV(nx)->nxdom_prov_name, SK_KVA(fsw));

	err = fsw_ctl_detach(nx, current_proc(), NULL);
	ASSERT(err == 0);       /* this cannot fail */
	ASSERT(fsw->fsw_dev_ch == NULL);
	ASSERT(fsw->fsw_host_ch == NULL);

	SK_DF(SK_VERB_FSW, "marking fsw 0x%llx as free", SK_KVA(fsw));
	fsw_free(fsw);
	nx->nx_arg = NULL;
}

static size_t
nx_fsw_prov_mib_get(struct kern_nexus *nx, struct nexus_mib_filter *filter,
    void *out, size_t len, struct proc *p)
{
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);

	/* this check doesn't require holding fsw_lock */
	if ((filter->nmf_bitmap & NXMIB_FILTER_NX_UUID) &&
	    (uuid_compare(filter->nmf_nx_uuid,
	    fsw->fsw_nx->nx_uuid)) != 0) {
		return 0;
	}

	/* intercept NXMIB_FSW_STATS here since it's for flowswitch */
	FSW_RLOCK(fsw);
	len = fsw_mib_get(fsw, filter, out, len, p);
	FSW_UNLOCK(fsw);

	return len;
}

boolean_t
nx_fsw_dom_port_is_reserved(struct kern_nexus *nx, nexus_port_t nx_port)
{
#pragma unused(nx)
	return nx_port < NEXUS_PORT_FLOW_SWITCH_CLIENT;
}

static int
nx_fsw_dom_find_port(struct kern_nexus *nx, boolean_t rsvd,
    nexus_port_t *nx_port)
{
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	nexus_port_t first, last, port;
	int error;

	ASSERT(nx_port != NULL);

	port = *nx_port;
	ASSERT(port == NEXUS_PORT_ANY);

	if (rsvd) {
		first = 0;
		last = NEXUS_PORT_FLOW_SWITCH_CLIENT;
	} else {
		first = NEXUS_PORT_FLOW_SWITCH_CLIENT;
		ASSERT(NXDOM_MAX(NX_DOM(nx), ports) <= NEXUS_PORT_MAX);
		last = (nexus_port_size_t)NXDOM_MAX(NX_DOM(nx), ports);
	}
	ASSERT(first <= last);

	FSW_WLOCK(fsw);
	if (__improbable(first == last)) {
		error = ENOSPC;
	} else {
		error = nx_port_find(nx, first, last - 1, &port);
		ASSERT(error != 0 || (port >= first && port < last));
	}
	FSW_WUNLOCK(fsw);

	SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
	    "nx 0x%llx \"%s\" %snx_port %d [%u,%u] (err %d)", SK_KVA(nx),
	    nx->nx_prov->nxprov_params->nxp_name, (rsvd ? "[reserved] " : ""),
	    (int)port, first, (last - 1), error);

	if (error == 0) {
		*nx_port = port;
	}

	return error;
}

static int
nx_fsw_dom_bind_port(struct kern_nexus *nx, nexus_port_t *nx_port,
    struct nxbind *nxb, void *info)
{
#pragma unused(info)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	nexus_port_t first, last, port;
	int error;

	ASSERT(nx_port != NULL);
	ASSERT(nxb != NULL);

	port = *nx_port;

	/* can't bind reserved ports to client credentials */
	if (nx_fsw_dom_port_is_reserved(nx, port)) {
		return EDOM;
	}

	/*
	 * Allow clients to bind to regular ports (non-reserved);
	 * reserved ports aren't subject to bind/unbind, since
	 * they are used for internal purposes.
	 */
	first = NEXUS_PORT_FLOW_SWITCH_CLIENT;
	ASSERT(NXDOM_MAX(NX_DOM(nx), ports) <= NEXUS_PORT_MAX);
	last = (nexus_port_size_t)NXDOM_MAX(NX_DOM(nx), ports);
	ASSERT(first <= last);

	FSW_WLOCK(fsw);
	if (__improbable(first == last)) {
		error = ENOSPC;
	} else if (port != NEXUS_PORT_ANY) {
		error = nx_port_bind(nx, port, nxb);
	} else {
		error = nx_port_find(nx, first, last - 1, &port);
		ASSERT(error != 0 || (port >= first && port < last));
		if (error == 0) {
			error = nx_port_bind(nx, port, nxb);
		}
	}
	FSW_WUNLOCK(fsw);

	SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
	    "nx 0x%llx \"%s\" nx_port %d [%u,%u] (err %d)", SK_KVA(nx),
	    nx->nx_prov->nxprov_params->nxp_name, (int)port,
	    first, (last - 1), error);

	ASSERT(*nx_port == NEXUS_PORT_ANY || *nx_port == port);
	if (error == 0) {
		*nx_port = port;
	}

	return error;
}

static int
nx_fsw_dom_unbind_port(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	int error;

	FSW_WLOCK(fsw);
	error = nx_port_unbind(nx, nx_port);
	FSW_WUNLOCK(fsw);

	SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
	    "nx 0x%llx \"%s\" nx_port %d (err %d)", SK_KVA(nx),
	    nx->nx_prov->nxprov_params->nxp_name, (int)nx_port, error);

	return error;
}

static int
nx_fsw_dom_connect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
#pragma unused(nxdom_prov)
	nexus_port_t port = chr->cr_port;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	ASSERT(nx->nx_prov->nxprov_params->nxp_type ==
	    nxdom_prov->nxdom_prov_dom->nxdom_type &&
	    nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_FLOW_SWITCH);
	ASSERT(!(ch->ch_flags & CHANF_HOST));

	if (port != NEXUS_PORT_ANY && port >= NXDOM_MAX(NX_DOM(nx), ports)) {
		err = EDOM;
		goto done;
	}

	chr->cr_real_endpoint = chr->cr_endpoint = CH_ENDPOINT_FLOW_SWITCH;
	if (ch->ch_flags & CHANF_KERNEL) {
		uuid_string_t uuidstr;
		ASSERT(!uuid_is_null(chr->cr_spec_uuid));
		(void) snprintf(chr->cr_name, sizeof(chr->cr_name),
		    "%s_%llu:%s", NX_FSW_NAME, nx->nx_id,
		    sk_uuid_unparse(chr->cr_spec_uuid, uuidstr));
		chr->cr_ring_set = RING_SET_DEFAULT;
		if (chr->cr_mode & CHMODE_HOST) {
			os_atomic_or(&ch->ch_flags, CHANF_HOST, relaxed);
		}
		err = na_connect_spec(nx, ch, chr, p);
	} else {
		ASSERT(port != NEXUS_PORT_ANY);
		if (chr->cr_mode & CHMODE_HOST) {
			/* not allowed unless kernel (special) channel */
			err = EINVAL;
			goto done;
		}
		(void) snprintf(chr->cr_name, sizeof(chr->cr_name),
		    "%s_%llu:%u", NX_FSW_NAME, nx->nx_id, port);
		chr->cr_ring_set = RING_SET_DEFAULT;
		err = na_connect(nx, ch, chr, ch0, nxb, p);
	}

done:
	return err;
}

static void
nx_fsw_dom_disconnect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nxdom_prov)
	SK_LOCK_ASSERT_HELD();

	SK_D("channel 0x%llx -!- nexus 0x%llx (%s:\"%s\":%u:%d)", SK_KVA(ch),
	    SK_KVA(nx), nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	if (ch->ch_flags & CHANF_KERNEL) {
		na_disconnect_spec(nx, ch);
	} else {
		na_disconnect(nx, ch);
	}
}

static void
nx_fsw_dom_defunct(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct proc *p)
{
#pragma unused(nxdom_prov)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_FLOWSWITCH_VP);

	/*
	 * Hold the flowswitch lock as writer; this prevents all data path
	 * accesses to the flowswitch, and allows us to mark the rings with
	 * CKRF_DEFUNCT.  Unlike some other nexus types, the flowswitch
	 * doesn't utilize kr_{enter,exit} for serialization, at present.
	 */
	FSW_WLOCK(fsw);
	na_ch_rings_defunct(ch, p);
	FSW_WUNLOCK(fsw);
}

static void
nx_fsw_dom_defunct_finalize(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, boolean_t locked)
{
#pragma unused(nxdom_prov)
	struct nx_flowswitch *fsw = NX_FSW_PRIVATE(nx);
	int err = 0;

	if (!locked) {
		SK_LOCK_ASSERT_NOTHELD();
		SK_LOCK();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
	} else {
		SK_LOCK_ASSERT_HELD();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	}

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_FLOWSWITCH_VP);
	ASSERT(VPNA(ch->ch_na)->vpna_nx_port == ch->ch_info->cinfo_nx_port);

	err = fsw_port_na_defunct(fsw, VPNA(ch->ch_na));

	if (err == 0) {
		na_defunct(nx, ch, ch->ch_na, locked);
	}

	SK_D("%s(%d): ch 0x%llx -/- nx 0x%llx (%s:\"%s\":%u:%d) err %d",
	    ch->ch_name, ch->ch_pid, SK_KVA(ch), SK_KVA(nx),
	    nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port,
	    (int)ch->ch_info->cinfo_ch_ring_id, err);

	if (!locked) {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
		SK_UNLOCK();
	} else {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
		SK_LOCK_ASSERT_HELD();
	}
}

#if SK_LOG
/* Hoisted out of line to reduce kernel stack footprint */
SK_LOG_ATTRIBUTE
static void
nx_fsw_na_find_log(const struct chreq *chr, boolean_t create)
{
	uuid_string_t uuidstr;

	SK_D("name \"%s\" spec_uuid \"%s\" nx_port %d mode 0x%b pipe_id %u "
	    "ring_id %d ring_set %u ep_type %u:%u create %u%s",
	    chr->cr_name, sk_uuid_unparse(chr->cr_spec_uuid, uuidstr),
	    (int)chr->cr_port, chr->cr_mode, CHMODE_BITS, chr->cr_pipe_id,
	    (int)chr->cr_ring_id, chr->cr_ring_set, chr->cr_real_endpoint,
	    chr->cr_endpoint, create, (strncmp(chr->cr_name, NX_FSW_NAME,
	    sizeof(NX_FSW_NAME) - 1) != 0) ? " (skipped)" : "");
}
#endif /* SK_LOG */

/*
 * Try to get a reference to a Nexus adapter attached to a flow switch.
 * If the adapter is found (or is created), this function returns 0, a
 * non NULL pointer is returned into *na, and the caller holds a
 * reference to the adapter.
 * If an adapter is not found, then no reference is grabbed and the
 * function returns an error code, or 0 if there is just a flow switch prefix
 * mismatch. Therefore the caller holds a reference when
 * (*na != NULL && return == 0).
 */
int
nx_fsw_na_find(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_adapter **na, boolean_t create)
{
#pragma unused(ch)
	struct nexus_vp_adapter *vpna = NULL;
	char *cr_name = chr->cr_name;
	struct nx_flowswitch *fsw;
	int error = 0;

	SK_LOCK_ASSERT_HELD();
	*na = NULL;     /* default return value */

#if SK_LOG
	if (__improbable(sk_verbose != 0)) {
		nx_fsw_na_find_log(chr, create);
	}
#endif /* SK_LOG */

	/* first try to see if this is a flow switch port. */
	if (strncmp(cr_name, NX_FSW_NAME, sizeof(NX_FSW_NAME) - 1) != 0) {
		return 0;  /* no error, but no flow switch prefix */
	}
	ASSERT(nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_FLOW_SWITCH);
	fsw = NX_FSW_PRIVATE(nx);
	ASSERT(fsw != NULL);

	if (!create) {
		return ENXIO;
	}

	/*
	 * The flowswitch VP is only attachable from a user channel so none of
	 * these flags should be set.
	 */
	ASSERT((chr->cr_mode & (CHMODE_KERNEL | CHMODE_CONFIG)) == 0);
	error = fsw_attach_vp(nx, ch, chr, nxb, p, &vpna);
	ASSERT(vpna == NULL || error == 0);

	if (error == 0) {
		/* use reference held by nx_fsw_attach_vp above */
		*na = &vpna->vpna_up;
		SK_DF(SK_VERB_FSW,
		    "vpna \"%s\" (0x%llx) refs %u to fsw \"%s\" nx_port %d",
		    (*na)->na_name, SK_KVA(*na), (*na)->na_refcount,
		    cr_name, (int)vpna->vpna_nx_port);
	}

	return error;
}

int
nx_fsw_netagent_add(struct kern_nexus *nx)
{
	return fsw_netagent_add_remove(nx, TRUE);
}

int
nx_fsw_netagent_remove(struct kern_nexus *nx)
{
	return fsw_netagent_add_remove(nx, FALSE);
}

void
nx_fsw_netagent_update(struct kern_nexus *nx)
{
	fsw_netagent_update(nx);
}
