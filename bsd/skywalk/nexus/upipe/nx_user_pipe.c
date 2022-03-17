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

/*
 * Copyright (C) 2014 Giuseppe Lettieri. All rights reserved.
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
#include <skywalk/nexus/upipe/nx_user_pipe.h>

#define NX_UPIPE_RINGSIZE       128 /* default ring size */
#define NX_UPIPE_MAXRINGS       NX_MAX_NUM_RING_PAIR
#define NX_UPIPE_MINSLOTS       2       /* XXX same as above */
#define NX_UPIPE_MAXSLOTS       4096    /* XXX same as above */
#define NX_UPIPE_BUFSIZE        (2 * 1024)
#define NX_UPIPE_MINBUFSIZE     1024
#define NX_UPIPE_MAXBUFSIZE     (16 * 1024)
#define NX_UPIPE_MHINTS         NEXUS_MHINTS_NORMAL

static int nx_upipe_na_alloc(struct nexus_adapter *, uint32_t);
static struct nexus_upipe_adapter *nx_upipe_find(struct nexus_adapter *,
    uint32_t);
static int nx_upipe_na_add(struct nexus_adapter *,
    struct nexus_upipe_adapter *);
static void nx_upipe_na_remove(struct nexus_adapter *,
    struct nexus_upipe_adapter *);
static int nx_upipe_na_txsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_upipe_na_txsync_locked(struct __kern_channel_ring *,
    struct proc *, uint32_t, int *, boolean_t);
static int nx_upipe_na_rxsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_upipe_na_krings_create(struct nexus_adapter *,
    struct kern_channel *);
static int nx_upipe_na_activate(struct nexus_adapter *, na_activate_mode_t);
static void nx_upipe_na_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
static void nx_upipe_na_dtor(struct nexus_adapter *);

static void nx_upipe_dom_init(struct nxdom *);
static void nx_upipe_dom_terminate(struct nxdom *);
static void nx_upipe_dom_fini(struct nxdom *);
static int nx_upipe_dom_bind_port(struct kern_nexus *, nexus_port_t *,
    struct nxbind *, void *);
static int nx_upipe_dom_unbind_port(struct kern_nexus *, nexus_port_t);
static int nx_upipe_dom_connect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *);
static void nx_upipe_dom_disconnect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *);
static void nx_upipe_dom_defunct(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct proc *);
static void nx_upipe_dom_defunct_finalize(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, boolean_t);

static int nx_upipe_prov_init(struct kern_nexus_domain_provider *);
static int nx_upipe_prov_params_adjust(
	const struct kern_nexus_domain_provider *, const struct nxprov_params *,
	struct nxprov_adjusted_params *);
static int nx_upipe_prov_params(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS]);
static int nx_upipe_prov_mem_new(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nexus_adapter *);
static void nx_upipe_prov_fini(struct kern_nexus_domain_provider *);
static int nx_upipe_prov_nx_ctor(struct kern_nexus *);
static void nx_upipe_prov_nx_dtor(struct kern_nexus *);

static struct nexus_upipe_adapter *na_upipe_alloc(zalloc_flags_t);
static void na_upipe_free(struct nexus_adapter *);

static struct nx_upipe *nx_upipe_alloc(zalloc_flags_t);
static void nx_upipe_free(struct nx_upipe *);

#if (DEVELOPMENT || DEBUG)
static uint32_t nx_upipe_mhints = 0;
SYSCTL_NODE(_kern_skywalk, OID_AUTO, upipe, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk upipe tuning");
SYSCTL_UINT(_kern_skywalk_upipe, OID_AUTO, nx_mhints,
    CTLFLAG_RW | CTLFLAG_LOCKED, &nx_upipe_mhints, 0,
    "upipe nexus memory usage hints");
#endif /* (DEVELOPMENT || DEBUG) */

struct nxdom nx_upipe_dom_s = {
	.nxdom_prov_head =
    STAILQ_HEAD_INITIALIZER(nx_upipe_dom_s.nxdom_prov_head),
	.nxdom_type =           NEXUS_TYPE_USER_PIPE,
	.nxdom_md_type =        NEXUS_META_TYPE_QUANTUM,
	.nxdom_md_subtype =     NEXUS_META_SUBTYPE_PAYLOAD,
	.nxdom_name =           "upipe",
	.nxdom_ports =          {
		.nb_def = 2,
		.nb_min = 2,
		.nb_max = 2,
	},
	.nxdom_tx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_UPIPE_MAXRINGS,
	},
	.nxdom_rx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_UPIPE_MAXRINGS,
	},
	.nxdom_tx_slots = {
		.nb_def = NX_UPIPE_RINGSIZE,
		.nb_min = NX_UPIPE_MINSLOTS,
		.nb_max = NX_UPIPE_MAXSLOTS,
	},
	.nxdom_rx_slots = {
		.nb_def = NX_UPIPE_RINGSIZE,
		.nb_min = NX_UPIPE_MINSLOTS,
		.nb_max = NX_UPIPE_MAXSLOTS,
	},
	.nxdom_buf_size = {
		.nb_def = NX_UPIPE_BUFSIZE,
		.nb_min = NX_UPIPE_MINBUFSIZE,
		.nb_max = NX_UPIPE_MAXBUFSIZE,
	},
	.nxdom_meta_size = {
		.nb_def = NX_METADATA_OBJ_MIN_SZ,
		.nb_min = NX_METADATA_OBJ_MIN_SZ,
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
	.nxdom_mhints = {
		.nb_def = NX_UPIPE_MHINTS,
		.nb_min = NEXUS_MHINTS_NORMAL,
		.nb_max = (NEXUS_MHINTS_NORMAL | NEXUS_MHINTS_WILLNEED |
    NEXUS_MHINTS_LOWLATENCY | NEXUS_MHINTS_HIUSE),
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
		.nb_min = NXPCAP_USER_CHANNEL,
		.nb_max = NXPCAP_USER_CHANNEL,
	},
	.nxdom_qmap = {
		.nb_def = NEXUS_QMAP_TYPE_INVALID,
		.nb_min = NEXUS_QMAP_TYPE_INVALID,
		.nb_max = NEXUS_QMAP_TYPE_INVALID,
	},
	.nxdom_max_frags = {
		.nb_def = NX_PBUF_FRAGS_DEFAULT,
		.nb_min = NX_PBUF_FRAGS_MIN,
		.nb_max = NX_PBUF_FRAGS_DEFAULT,
	},
	.nxdom_init =           nx_upipe_dom_init,
	.nxdom_terminate =      nx_upipe_dom_terminate,
	.nxdom_fini =           nx_upipe_dom_fini,
	.nxdom_find_port =      NULL,
	.nxdom_port_is_reserved = NULL,
	.nxdom_bind_port =      nx_upipe_dom_bind_port,
	.nxdom_unbind_port =    nx_upipe_dom_unbind_port,
	.nxdom_connect =        nx_upipe_dom_connect,
	.nxdom_disconnect =     nx_upipe_dom_disconnect,
	.nxdom_defunct =        nx_upipe_dom_defunct,
	.nxdom_defunct_finalize = nx_upipe_dom_defunct_finalize,
};

static struct kern_nexus_domain_provider nx_upipe_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_USER_PIPE,
	.nxdom_prov_flags =             NXDOMPROVF_DEFAULT,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_upipe_prov_init,
		.dp_cb_fini =           nx_upipe_prov_fini,
		.dp_cb_params =         nx_upipe_prov_params,
		.dp_cb_mem_new =        nx_upipe_prov_mem_new,
		.dp_cb_config =         NULL,
		.dp_cb_nx_ctor =        nx_upipe_prov_nx_ctor,
		.dp_cb_nx_dtor =        nx_upipe_prov_nx_dtor,
		.dp_cb_nx_mem_info =    NULL,
		.dp_cb_nx_mib_get =     NULL,
		.dp_cb_nx_stop =        NULL,
	},
};

static ZONE_DECLARE(na_upipe_zone, SKMEM_ZONE_PREFIX ".na.upipe",
    sizeof(struct nexus_upipe_adapter), ZC_ZFREE_CLEARMEM);

static ZONE_DECLARE(nx_upipe_zone, SKMEM_ZONE_PREFIX ".nx.upipe",
    sizeof(struct nx_upipe), ZC_ZFREE_CLEARMEM);

#define SKMEM_TAG_PIPES "com.apple.skywalk.pipes"
static kern_allocation_name_t skmem_tag_pipes;

static void
nx_upipe_dom_init(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED));

	ASSERT(skmem_tag_pipes == NULL);
	skmem_tag_pipes = kern_allocation_name_allocate(SKMEM_TAG_PIPES, 0);
	ASSERT(skmem_tag_pipes != NULL);

	(void) nxdom_prov_add(nxdom, &nx_upipe_prov_s);
}

static void
nx_upipe_dom_terminate(struct nxdom *nxdom)
{
	struct kern_nexus_domain_provider *nxdom_prov, *tnxdp;

	STAILQ_FOREACH_SAFE(nxdom_prov, &nxdom->nxdom_prov_head,
	    nxdom_prov_link, tnxdp) {
		(void) nxdom_prov_del(nxdom_prov);
	}

	if (skmem_tag_pipes != NULL) {
		kern_allocation_name_release(skmem_tag_pipes);
		skmem_tag_pipes = NULL;
	}
}

static void
nx_upipe_dom_fini(struct nxdom *nxdom)
{
#pragma unused(nxdom)
}

static int
nx_upipe_prov_init(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);
	return 0;
}

static int
nx_upipe_prov_params_adjust(const struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_params *nxp, struct nxprov_adjusted_params *adj)
{
#pragma unused(nxdom_prov, nxp)
	/*
	 * User pipe requires double the amount of rings.
	 * The ring counts must also be symmetrical.
	 */
	if (*(adj->adj_tx_rings) != *(adj->adj_rx_rings)) {
		SK_ERR("rings: tx (%u) != rx (%u)", *(adj->adj_tx_rings),
		    *(adj->adj_rx_rings));
		return EINVAL;
	}

	*(adj->adj_tx_rings) *= 2;
	*(adj->adj_rx_rings) *= 2;

	if (adj->adj_buf_srp->srp_r_seg_size == 0) {
		adj->adj_buf_srp->srp_r_seg_size = skmem_usr_buf_seg_size;
	}

	/* enable magazines layer for metadata */
	*(adj->adj_md_magazines) = TRUE;

	return 0;
}

static int
nx_upipe_prov_params(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS])
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;
	int err;

	err = nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	    nxdom, nxdom, nxdom, nx_upipe_prov_params_adjust);
#if (DEVELOPMENT || DEBUG)
	/* sysctl override */
	if ((err == 0) && (nx_upipe_mhints != 0)) {
		nxp->nxp_mhints = nx_upipe_mhints;
	}
#endif /* (DEVELOPMENT || DEBUG) */
	return err;
}

static int
nx_upipe_prov_mem_new(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nxdom_prov)
	int err = 0;

	SK_DF(SK_VERB_USER_PIPE,
	    "nx 0x%llx (\"%s\":\"%s\") na \"%s\" (0x%llx)", SK_KVA(nx),
	    NX_DOM(nx)->nxdom_name, nxdom_prov->nxdom_prov_name, na->na_name,
	    SK_KVA(na));

	ASSERT(na->na_arena == NULL);
	ASSERT(NX_USER_CHANNEL_PROV(nx));
	/*
	 * The underlying nexus adapters already share the same memory
	 * allocator, and thus we don't care about storing the pp in
	 * the nexus.
	 *
	 * This means that clients calling kern_nexus_get_pbufpool()
	 * will get NULL, but this is fine since we don't expose the
	 * user pipe to external kernel clients.
	 */
	na->na_arena = skmem_arena_create_for_nexus(na,
	    NX_PROV(nx)->nxprov_region_params, NULL, NULL, FALSE,
	    FALSE, NULL, &err);
	ASSERT(na->na_arena != NULL || err != 0);

	return err;
}

static void
nx_upipe_prov_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);
}

static int
nx_upipe_prov_nx_ctor(struct kern_nexus *nx)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(nx->nx_arg == NULL);

	SK_D("nexus 0x%llx (%s)", SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name);

	nx->nx_arg = nx_upipe_alloc(Z_WAITOK);
	SK_D("create new upipe 0x%llx for nexus 0x%llx",
	    SK_KVA(NX_UPIPE_PRIVATE(nx)), SK_KVA(nx));

	return 0;
}

static void
nx_upipe_prov_nx_dtor(struct kern_nexus *nx)
{
	struct nx_upipe *u = NX_UPIPE_PRIVATE(nx);

	SK_LOCK_ASSERT_HELD();

	SK_D("nexus 0x%llx (%s) upipe 0x%llx", SK_KVA(nx),
	    NX_DOM_PROV(nx)->nxdom_prov_name, SK_KVA(u));

	if (u->nup_cli_nxb != NULL) {
		nxb_free(u->nup_cli_nxb);
		u->nup_cli_nxb = NULL;
	}
	if (u->nup_srv_nxb != NULL) {
		nxb_free(u->nup_srv_nxb);
		u->nup_srv_nxb = NULL;
	}

	SK_DF(SK_VERB_USER_PIPE, "marking upipe 0x%llx as free", SK_KVA(u));
	nx_upipe_free(u);
	nx->nx_arg = NULL;
}

static struct nexus_upipe_adapter *
na_upipe_alloc(zalloc_flags_t how)
{
	struct nexus_upipe_adapter *pna;

	_CASSERT(offsetof(struct nexus_upipe_adapter, pna_up) == 0);

	pna = zalloc_flags(na_upipe_zone, how | Z_ZERO);
	if (pna) {
		pna->pna_up.na_type = NA_USER_PIPE;
		pna->pna_up.na_free = na_upipe_free;
	}
	return pna;
}

static void
na_upipe_free(struct nexus_adapter *na)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;

	ASSERT(pna->pna_up.na_refcount == 0);
	SK_DF(SK_VERB_MEM, "pna 0x%llx FREE", SK_KVA(pna));
	bzero(pna, sizeof(*pna));
	zfree(na_upipe_zone, pna);
}

static int
nx_upipe_dom_bind_port(struct kern_nexus *nx, nexus_port_t *nx_port,
    struct nxbind *nxb0, void *info)
{
#pragma unused(info)
	struct nx_upipe *u = NX_UPIPE_PRIVATE(nx);
	struct nxbind *nxb = NULL;
	int error = 0;

	ASSERT(nx_port != NULL);
	ASSERT(nxb0 != NULL);

	switch (*nx_port) {
	case NEXUS_PORT_USER_PIPE_CLIENT:
	case NEXUS_PORT_USER_PIPE_SERVER:
		if ((*nx_port == NEXUS_PORT_USER_PIPE_CLIENT &&
		    u->nup_cli_nxb != NULL) ||
		    (*nx_port == NEXUS_PORT_USER_PIPE_SERVER &&
		    u->nup_srv_nxb != NULL)) {
			error = EEXIST;
			break;
		}

		nxb = nxb_alloc(Z_WAITOK);
		nxb_move(nxb0, nxb);
		if (*nx_port == NEXUS_PORT_USER_PIPE_CLIENT) {
			u->nup_cli_nxb = nxb;
		} else {
			u->nup_srv_nxb = nxb;
		}

		ASSERT(error == 0);
		break;

	default:
		error = EDOM;
		break;
	}

	return error;
}

static int
nx_upipe_dom_unbind_port(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nx_upipe *u = NX_UPIPE_PRIVATE(nx);
	struct nxbind *nxb = NULL;
	int error = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);

	switch (nx_port) {
	case NEXUS_PORT_USER_PIPE_CLIENT:
	case NEXUS_PORT_USER_PIPE_SERVER:
		if ((nx_port == NEXUS_PORT_USER_PIPE_CLIENT &&
		    u->nup_cli_nxb == NULL) ||
		    (nx_port == NEXUS_PORT_USER_PIPE_SERVER &&
		    u->nup_srv_nxb == NULL)) {
			error = ENOENT;
			break;
		}

		if (nx_port == NEXUS_PORT_USER_PIPE_CLIENT) {
			nxb = u->nup_cli_nxb;
			u->nup_cli_nxb = NULL;
		} else {
			nxb = u->nup_srv_nxb;
			u->nup_srv_nxb = NULL;
		}
		nxb_free(nxb);
		ASSERT(error == 0);
		break;

	default:
		error = EDOM;
		break;
	}

	return error;
}

static int
nx_upipe_dom_connect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
#pragma unused(nxdom_prov)
	nexus_port_t port = chr->cr_port;
	int err = 0;

	SK_LOCK_ASSERT_HELD();

	ASSERT(NX_DOM_PROV(nx) == nxdom_prov);
	ASSERT(nx->nx_prov->nxprov_params->nxp_type ==
	    nxdom_prov->nxdom_prov_dom->nxdom_type &&
	    nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_USER_PIPE);

	/*
	 * XXX: channel in user packet pool mode is not supported for
	 * user-pipe for now.
	 */
	if (chr->cr_mode & CHMODE_USER_PACKET_POOL) {
		SK_ERR("User packet pool mode not supported for upipe");
		err = ENOTSUP;
		goto done;
	}

	if (chr->cr_mode & CHMODE_EVENT_RING) {
		SK_ERR("event ring is not supported for upipe");
		err = ENOTSUP;
		goto done;
	}

	if (chr->cr_mode & CHMODE_LOW_LATENCY) {
		SK_ERR("low latency is not supported for upipe");
		err = ENOTSUP;
		goto done;
	}

	if (port == NEXUS_PORT_USER_PIPE_SERVER) {
		chr->cr_real_endpoint = CH_ENDPOINT_USER_PIPE_MASTER;
	} else if (port == NEXUS_PORT_USER_PIPE_CLIENT) {
		chr->cr_real_endpoint = CH_ENDPOINT_USER_PIPE_SLAVE;
	} else {
		err = EINVAL;
		goto done;
	}

	chr->cr_endpoint = chr->cr_real_endpoint;
	chr->cr_ring_set = RING_SET_DEFAULT;
	chr->cr_pipe_id = 0;
	(void) snprintf(chr->cr_name, sizeof(chr->cr_name), "upipe:%llu:%.*s",
	    nx->nx_id, (int)nx->nx_prov->nxprov_params->nxp_namelen,
	    nx->nx_prov->nxprov_params->nxp_name);

	err = na_connect(nx, ch, chr, ch0, nxb, p);
done:
	return err;
}

static void
nx_upipe_dom_disconnect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nxdom_prov)
	SK_LOCK_ASSERT_HELD();

	SK_D("channel 0x%llx -!- nexus 0x%llx (%s:\"%s\":%u:%d)", SK_KVA(ch),
	    SK_KVA(nx), nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	na_disconnect(nx, ch);
	/*
	 * Set NXF_REJECT on the nexus which would cause any channel on the
	 * peer adapter to cease to function.
	 */
	if (NX_PROV(nx)->nxprov_params->nxp_reject_on_close) {
		atomic_bitset_32(&nx->nx_flags, NXF_REJECT);
	}
}

static void
nx_upipe_dom_defunct(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct proc *p)
{
#pragma unused(nxdom_prov, nx)
	struct nexus_adapter *na = ch->ch_na;
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;
	ring_id_t qfirst = ch->ch_first[NR_TX];
	ring_id_t qlast = ch->ch_last[NR_TX];
	uint32_t i;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(na->na_type == NA_USER_PIPE);

	/*
	 * Inform the peer receiver thread in nx_upipe_na_rxsync() or the
	 * peer transmit thread in nx_upipe_na_txsync() about
	 * this endpoint going defunct.  We utilize the TX ring's
	 * lock for serialization, since that is what's being used
	 * by the receiving endpoint.
	 */
	for (i = qfirst; i < qlast; i++) {
		/*
		 * For maintaining lock ordering between the two channels of
		 * user pipe.
		 */
		if (pna->pna_role == CH_ENDPOINT_USER_PIPE_MASTER) {
			(void) kr_enter(&NAKR(na, NR_TX)[i], TRUE);
			(void) kr_enter(NAKR(na, NR_RX)[i].ckr_pipe, TRUE);
		} else {
			(void) kr_enter(NAKR(na, NR_RX)[i].ckr_pipe, TRUE);
			(void) kr_enter(&NAKR(na, NR_TX)[i], TRUE);
		}
	}

	na_ch_rings_defunct(ch, p);

	for (i = qfirst; i < qlast; i++) {
		if (pna->pna_role == CH_ENDPOINT_USER_PIPE_MASTER) {
			(void) kr_exit(NAKR(na, NR_RX)[i].ckr_pipe);
			(void) kr_exit(&NAKR(na, NR_TX)[i]);
		} else {
			(void) kr_exit(&NAKR(na, NR_TX)[i]);
			(void) kr_exit(NAKR(na, NR_RX)[i].ckr_pipe);
		}
	}
}

static void
nx_upipe_dom_defunct_finalize(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, boolean_t locked)
{
#pragma unused(nxdom_prov)
	struct nexus_upipe_adapter *pna =
	    (struct nexus_upipe_adapter *)ch->ch_na;

	if (!locked) {
		SK_LOCK_ASSERT_NOTHELD();
		SK_LOCK();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
	} else {
		SK_LOCK_ASSERT_HELD();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	}

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_USER_PIPE);

	/*
	 * At this point, we know that the arena shared by the master and
	 * slave adapters has no more valid mappings on the channels opened
	 * to them.  We need to invoke na_defunct() on both adapters to
	 * release any remaining slots attached to their rings.
	 *
	 * Note that the 'ch' that we pass in here is irrelevant as we
	 * don't support user packet pool for user pipe.
	 */
	na_defunct(nx, ch, &pna->pna_up, locked);
	if (pna->pna_peer != NULL) {
		na_defunct(nx, ch, &pna->pna_peer->pna_up, locked);
	}

	/*
	 * And if their parent adapter (the memory owner) is a pseudo
	 * nexus adapter that we initially created in nx_upipe_na_find(),
	 * invoke na_defunct() on it now to do the final teardown on
	 * the arena.
	 */
	if (pna->pna_parent->na_type == NA_PSEUDO) {
		na_defunct(nx, ch, pna->pna_parent, locked);
	}

	SK_D("%s(%d): ch 0x%llx -/- nx 0x%llx (%s:\"%s\":%u:%d)",
	    ch->ch_name, ch->ch_pid, SK_KVA(ch), SK_KVA(nx),
	    nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	if (!locked) {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
		SK_UNLOCK();
	} else {
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
		SK_LOCK_ASSERT_HELD();
	}
}

/* allocate the pipe array in the parent adapter */
static int
nx_upipe_na_alloc(struct nexus_adapter *na, uint32_t npipes)
{
	struct nexus_upipe_adapter **npa;
	size_t len, orig_len;

	if (npipes <= na->na_max_pipes) {
		/* we already have more entries that requested */
		return 0;
	}
	if (npipes < na->na_next_pipe || npipes > NX_UPIPE_MAXPIPES) {
		return EINVAL;
	}

	orig_len = sizeof(struct nexus_upipe_adapter *) * na->na_max_pipes;
	len = sizeof(struct nexus_upipe_adapter *) * npipes;
	npa = sk_realloc(na->na_pipes, orig_len, len, Z_WAITOK, skmem_tag_pipes);
	if (npa == NULL) {
		return ENOMEM;
	}

	na->na_pipes = npa;
	na->na_max_pipes = npipes;

	return 0;
}

/* deallocate the parent array in the parent adapter */
void
nx_upipe_na_dealloc(struct nexus_adapter *na)
{
	if (na->na_pipes) {
		if (na->na_next_pipe > 0) {
			SK_ERR("freeing not empty pipe array for %s "
			    "(%u dangling pipes)!", na->na_name,
			    na->na_next_pipe);
		}
		sk_free(na->na_pipes,
		    sizeof(struct nexus_upipe_adapter *) * na->na_max_pipes);
		na->na_pipes = NULL;
		na->na_max_pipes = 0;
		na->na_next_pipe = 0;
	}
}

/* find a pipe endpoint with the given id among the parent's pipes */
static struct nexus_upipe_adapter *
nx_upipe_find(struct nexus_adapter *parent, uint32_t pipe_id)
{
	uint32_t i;
	struct nexus_upipe_adapter *na;

	for (i = 0; i < parent->na_next_pipe; i++) {
		na = parent->na_pipes[i];
		if (na->pna_id == pipe_id) {
			return na;
		}
	}
	return NULL;
}

/* add a new pipe endpoint to the parent array */
static int
nx_upipe_na_add(struct nexus_adapter *parent, struct nexus_upipe_adapter *na)
{
	if (parent->na_next_pipe >= parent->na_max_pipes) {
		uint32_t npipes = parent->na_max_pipes ?
		    2 * parent->na_max_pipes : 2;
		int error = nx_upipe_na_alloc(parent, npipes);
		if (error) {
			return error;
		}
	}

	parent->na_pipes[parent->na_next_pipe] = na;
	na->pna_parent_slot = parent->na_next_pipe;
	parent->na_next_pipe++;
	return 0;
}

/* remove the given pipe endpoint from the parent array */
static void
nx_upipe_na_remove(struct nexus_adapter *parent, struct nexus_upipe_adapter *na)
{
	uint32_t n;
	n = --parent->na_next_pipe;
	if (n != na->pna_parent_slot) {
		struct nexus_upipe_adapter **p =
		    &parent->na_pipes[na->pna_parent_slot];
		*p = parent->na_pipes[n];
		(*p)->pna_parent_slot = na->pna_parent_slot;
	}
	parent->na_pipes[n] = NULL;
}

static int
nx_upipe_na_txsync(struct __kern_channel_ring *txkring, struct proc *p,
    uint32_t flags)
{
	struct __kern_channel_ring *rxkring = txkring->ckr_pipe;
	volatile uint64_t *tx_tsync, *tx_tnote, *rx_tsync;
	int sent = 0, ret = 0;

	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u "
	    "flags 0x%x -> kr \"%s\" (0x%llx) krflags 0x%b ring %u",
	    sk_proc_name_address(p), sk_proc_pid(p), txkring->ckr_name,
	    SK_KVA(txkring), txkring->ckr_flags, CKRF_BITS,
	    txkring->ckr_ring_id, flags, rxkring->ckr_name, SK_KVA(rxkring),
	    rxkring->ckr_flags, CKRF_BITS, rxkring->ckr_ring_id);

	/*
	 * Serialize write access to the transmit ring, since another
	 * thread coming down for rxsync might pick up pending slots.
	 */
	ASSERT(txkring->ckr_owner == current_thread());

	/*
	 * Record the time of sync and grab sync time of other side;
	 * use atomic store and load since we're not holding the
	 * lock used by the receive ring.  This allows us to avoid
	 * the potentially costly membar_sync().
	 */
	/* deconst */
	tx_tsync = __DECONST(uint64_t *, &txkring->ckr_ring->ring_sync_time);
	atomic_set_64(tx_tsync, txkring->ckr_sync_time);

	/*
	 * Read from the peer's kring, not its user ring; the peer's channel
	 * may be defunct, in which case it's unsafe to access its user ring.
	 */
	rx_tsync = __DECONST(uint64_t *, &rxkring->ckr_sync_time);
	tx_tnote = __DECONST(uint64_t *, &txkring->ckr_ring->ring_notify_time);
	*tx_tnote = atomic_add_64_ov(rx_tsync, 0);

	if (__probable(txkring->ckr_rhead != txkring->ckr_khead)) {
		sent = nx_upipe_na_txsync_locked(txkring, p, flags,
		    &ret, FALSE);
	}

	if (sent != 0) {
		(void) rxkring->ckr_na_notify(rxkring, p, 0);
	}

	return ret;
}

int
nx_upipe_na_txsync_locked(struct __kern_channel_ring *txkring, struct proc *p,
    uint32_t flags, int *ret, boolean_t rx)
{
#pragma unused(p, flags, rx)
	struct __kern_channel_ring *rxkring = txkring->ckr_pipe;
	const slot_idx_t lim_tx = txkring->ckr_lim;
	const slot_idx_t lim_rx = rxkring->ckr_lim;
	slot_idx_t j, k;
	int n, m, b, sent = 0;
	uint32_t byte_count = 0;
	int limit; /* max # of slots to transfer */

	*ret = 0;

	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\", kh %3u kt %3u | "
	    "rh %3u rt %3u [pre%s]", sk_proc_name_address(p),
	    sk_proc_pid(p), txkring->ckr_name, txkring->ckr_khead,
	    txkring->ckr_ktail, txkring->ckr_rhead,
	    txkring->ckr_rtail, rx ? "*" : "");
	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\", kh %3u kt %3u | "
	    "rh %3u rt %3u [pre%s]", sk_proc_name_address(p),
	    sk_proc_pid(p), rxkring->ckr_name, rxkring->ckr_khead,
	    rxkring->ckr_ktail, rxkring->ckr_rhead,
	    rxkring->ckr_rtail, rx ? "*" : "");

	if (__improbable(KR_DROP(txkring) || KR_DROP(rxkring))) {
		*ret = ENXIO;
		goto done;
	}

	j = rxkring->ckr_ktail; /* RX */
	k = txkring->ckr_khead;  /* TX */

	/* # of new tx slots */
	n = txkring->ckr_rhead - txkring->ckr_khead;
	if (n < 0) {
		n += txkring->ckr_num_slots;
	}
	limit = n;

	/* # of rx busy (unclaimed) slots */
	b = j - rxkring->ckr_khead;
	if (b < 0) {
		b += rxkring->ckr_num_slots;
	}

	/* # of rx avail free slots (subtract busy from max) */
	m = lim_rx - b;
	if (m < limit) {
		limit = m;
	}

	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" -> new %u, kr \"%s\" "
	    "-> free %u", sk_proc_name_address(p), sk_proc_pid(p),
	    txkring->ckr_name, n, rxkring->ckr_name, m);

	/* rxring is full, or nothing to send? */
	if (__improbable((sent = limit) == 0)) {
		SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
		    "%s(%d) kr \"%s\" -> %s%s",
		    sk_proc_name_address(p), sk_proc_pid(p), (n > m) ?
		    rxkring->ckr_name : txkring->ckr_name, ((n > m) ?
		    "no room avail" : "no new slots"),
		    (rx ? " (lost race, ok)" : ""));
		goto done;
	}

	ASSERT(limit > 0);
	while (limit--) {
		struct __kern_slot_desc *ksd_tx = KR_KSD(txkring, k);
		struct __user_slot_desc *usd_tx = KR_USD(txkring, k);
		struct __kern_slot_desc *ksd_rx = KR_KSD(rxkring, j);
		struct __user_slot_desc *usd_rx = KR_USD(rxkring, j);
		struct __kern_quantum *kqum;

		kqum = ksd_tx->sd_qum;
		/*
		 * Packets failing internalization should be dropped in
		 * TX sync prologue.
		 */
		ASSERT((kqum->qum_qflags & (QUM_F_INTERNALIZED |
		    QUM_F_FINALIZED)) == (QUM_F_INTERNALIZED |
		    QUM_F_FINALIZED));

		byte_count += kqum->qum_len;

		/*
		 * Swap the slots.
		 *
		 * XXX: adi@apple.com -- this bypasses the slot attach/detach
		 * interface, and needs to be changed when upipe adopts the
		 * packet APIs.  SD_SWAP() will perform a block copy of the
		 * swap, and will readjust the kernel slot descriptor's sd_user
		 * accordingly.
		 */
		SD_SWAP(ksd_rx, usd_rx, ksd_tx, usd_tx);

		j = SLOT_NEXT(j, lim_rx);
		k = SLOT_NEXT(k, lim_tx);
	}

	kr_update_stats(rxkring, sent, byte_count);
	if (__improbable(kr_stat_enable != 0)) {
		txkring->ckr_stats = rxkring->ckr_stats;
	}

	/*
	 * Make sure the slots are updated before ckr_ktail reach global
	 * visibility, since we are not holding rx ring's kr_enter().
	 */
	membar_sync();

	rxkring->ckr_ktail = j;
	txkring->ckr_khead = k;
	txkring->ckr_ktail = SLOT_PREV(k, lim_tx);

done:
	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\", kh %3u kt %3u | "
	    "rh %3u rt %3u [post%s]", sk_proc_name_address(p),
	    sk_proc_pid(p), txkring->ckr_name, txkring->ckr_khead,
	    txkring->ckr_ktail, txkring->ckr_rhead,
	    txkring->ckr_rtail, rx ? "*" : "");
	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\", kh %3u kt %3u | "
	    "rh %3u rt %3u [post%s]", sk_proc_name_address(p),
	    sk_proc_pid(p), rxkring->ckr_name, rxkring->ckr_khead,
	    rxkring->ckr_ktail, rxkring->ckr_rhead,
	    rxkring->ckr_rtail, rx ? "*" : "");

	return sent;
}

static int
nx_upipe_na_rxsync(struct __kern_channel_ring *rxkring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	struct __kern_channel_ring *txkring = rxkring->ckr_pipe;
	volatile uint64_t *rx_tsync, *rx_tnote, *tx_tsync;
	const slot_idx_t lim_rx = rxkring->ckr_lim;
	int n; /* new slots from transmit side */
	int m, b, ret = 0;
	uint32_t r;

	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u "
	    "flags 0x%x <- kr \"%s\" (0x%llx) krflags 0x%b ring %u",
	    sk_proc_name_address(p), sk_proc_pid(p), rxkring->ckr_name,
	    SK_KVA(rxkring), rxkring->ckr_flags, CKRF_BITS,
	    rxkring->ckr_ring_id, flags, txkring->ckr_name, SK_KVA(txkring),
	    txkring->ckr_flags, CKRF_BITS, txkring->ckr_ring_id);

	ASSERT(rxkring->ckr_owner == current_thread());

	/* reclaim and get # of rx reclaimed slots */
	r = kr_reclaim(rxkring);

	/* # of rx busy (unclaimed) slots */
	b = rxkring->ckr_ktail - rxkring->ckr_khead;
	if (b < 0) {
		b += rxkring->ckr_num_slots;
	}

	/* # of rx avail free slots (subtract busy from max) */
	m = lim_rx - b;

	/*
	 * Check if there's any new slots on transmit ring; do this
	 * first without acquiring that ring's ckr_qlock, and use
	 * the memory barrier (paired with second one in txsync.)
	 * If we missed the race we'd just pay the cost of acquiring
	 * ckr_qlock and potentially returning from "internal txsync"
	 * without anything to process, which is okay.
	 */
	membar_sync();
	n = txkring->ckr_rhead - txkring->ckr_khead;
	if (n < 0) {
		n += txkring->ckr_num_slots;
	}

	SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" <- free %u, kr \"%s\" <- new %u",
	    sk_proc_name_address(p), sk_proc_pid(p),
	    rxkring->ckr_name, m, txkring->ckr_name, n);

	/*
	 * Record the time of sync and grab sync time of other side;
	 * use atomic store and load since we're not holding the
	 * lock used by the receive ring.  This allows us to avoid
	 * the potentially costly membar_sync().
	 */
	/* deconst */
	rx_tsync = __DECONST(uint64_t *, &rxkring->ckr_ring->ring_sync_time);
	atomic_set_64(rx_tsync, rxkring->ckr_sync_time);

	/*
	 * Read from the peer's kring, not its user ring; the peer's channel
	 * may be defunct, in which case it's unsafe to access its user ring.
	 */
	tx_tsync = __DECONST(uint64_t *, &txkring->ckr_sync_time);
	rx_tnote = __DECONST(uint64_t *, &rxkring->ckr_ring->ring_notify_time);
	*rx_tnote = atomic_add_64_ov(tx_tsync, 0);

	/*
	 * If we have slots to pick up from the transmit side and and we
	 * have space available, perform an equivalent of "internal txsync".
	 *
	 * Acquire write access to the transmit (peer) ring,
	 * Serialize write access to it, since another thread
	 * coming down for txsync might add new slots.
	 * If we fail to get the kring lock, then don't worry because
	 * there's already a transmit sync in progress to move packets.
	 */
	if (__probable(n != 0 && m != 0 && (flags & NA_SYNCF_MONITOR) == 0)) {
		(void) kr_enter(txkring, TRUE);
		n = nx_upipe_na_txsync_locked(txkring, p, flags, &ret, TRUE);
		kr_exit(txkring);
	} else {
		n = 0;
	}

	/*
	 * If we have reclaimed some slots or transferred new slots
	 * from the transmit side, notify the other end.  Also notify
	 * ourselves to pick up newly transferred ones, if any.
	 */
	if (__probable(r != 0 || n != 0)) {
		SK_DF(SK_VERB_USER_PIPE | SK_VERB_SYNC | SK_VERB_RX,
		    "%s(%d) kr \"%s\", kh %3u kt %3u | "
		    "rh %3u rt %3u [rel %u new %u]",
		    sk_proc_name_address(p), sk_proc_pid(p), rxkring->ckr_name,
		    rxkring->ckr_khead, rxkring->ckr_ktail,
		    rxkring->ckr_rhead, rxkring->ckr_rtail, r, n);

		(void) txkring->ckr_na_notify(txkring, p, 0);
	}

	return ret;
}

static int
nx_upipe_na_rings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;
	struct nexus_adapter *ona = &pna->pna_peer->pna_up;
	int error = 0;
	enum txrx t;
	uint32_t i;

	/*
	 * Create krings and all the rings for this end;
	 * we'll update ckr_save_ring pointers below.
	 */
	error = na_rings_mem_setup(na, 0, FALSE, ch);
	if (error != 0) {
		goto err;
	}

	/* update our hidden ring pointers */
	for_rx_tx(t) {
		for (i = 0; i < na_get_nrings(na, t); i++) {
			NAKR(na, t)[i].ckr_save_ring =
			    NAKR(na, t)[i].ckr_ring;
		}
	}

	/* now, create krings and rings of the other end */
	error = na_rings_mem_setup(ona, 0, FALSE, ch);
	if (error != 0) {
		na_rings_mem_teardown(na, ch, FALSE);   /* this end */
		goto err;
	}

	for_rx_tx(t) {
		for (i = 0; i < na_get_nrings(ona, t); i++) {
			NAKR(ona, t)[i].ckr_save_ring =
			    NAKR(ona, t)[i].ckr_ring;
		}
	}

	/* cross link the krings */
	for_rx_tx(t) {
		/* swap NR_TX <-> NR_RX (skip host ring) */
		enum txrx r = sk_txrx_swap(t);
		for (i = 0; i < na_get_nrings(na, t); i++) {
			NAKR(na, t)[i].ckr_pipe =
			    NAKR(&pna->pna_peer->pna_up, r) + i;
			NAKR(&pna->pna_peer->pna_up, r)[i].ckr_pipe =
			    NAKR(na, t) + i;
		}
	}
err:
	return error;
}

/*
 * Pipe endpoints are created and destroyed together, so that endopoints do not
 * have to check for the existence of their peer at each ?xsync.
 *
 * To play well with the existing nexus adapter infrastructure (refcounts etc.),
 * we adopt the following strategy:
 *
 * 1) The first endpoint that is created also creates the other endpoint and
 * grabs a reference to it.
 *
 *    state A)  user1 --> endpoint1 --> endpoint2
 *
 * 2) If, starting from state A, endpoint2 is then registered, endpoint1 gives
 * its reference to the user:
 *
 *    state B)  user1 --> endpoint1     endpoint2 <--- user2
 *
 * 3) Assume that, starting from state B endpoint2 is closed. In the unregister
 * callback endpoint2 notes that endpoint1 is still active and adds a reference
 * from endpoint1 to itself. When user2 then releases her own reference,
 * endpoint2 is not destroyed and we are back to state A. A symmetrical state
 * would be reached if endpoint1 were released instead.
 *
 * 4) If, starting from state A, endpoint1 is closed, the destructor notes that
 * it owns a reference to endpoint2 and releases it.
 *
 * Something similar goes on for the creation and destruction of the krings.
 */


/*
 * nx_upipe_na_krings_create.
 *
 * There are two cases:
 *
 * 1) state is
 *
 *        usr1 --> e1 --> e2
 *
 *    and we are e1. We have to create both sets
 *    of krings.
 *
 * 2) state is
 *
 *        usr1 --> e1 --> e2
 *
 *    and we are e2. e1 is certainly registered and our
 *    krings already exist, but they may be hidden.
 */
static int
nx_upipe_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;
	int error = 0;
	enum txrx t;
	uint32_t i;

	/*
	 * Verify symmetrical ring counts; validated
	 * at nexus provider registration time.
	 */
	ASSERT(na_get_nrings(na, NR_TX) == na_get_nrings(na, NR_RX));

	if (pna->pna_peer_ref) {
		/* case 1) above */
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 1, create everything", SK_KVA(na));
		error = nx_upipe_na_rings_create(na, ch);
	} else {
		/* case 2) above */
		/* recover the hidden rings */
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 2, hidden rings", SK_KVA(na));
		for_rx_tx(t) {
			for (i = 0; i < na_get_nrings(na, t); i++) {
				NAKR(na, t)[i].ckr_ring =
				    NAKR(na, t)[i].ckr_save_ring;
			}
		}
	}

	ASSERT(error == 0 || (na->na_tx_rings == NULL &&
	    na->na_rx_rings == NULL && na->na_slot_ctxs == NULL));
	ASSERT(error == 0 || (pna->pna_peer->pna_up.na_tx_rings == NULL &&
	    pna->pna_peer->pna_up.na_rx_rings == NULL &&
	    pna->pna_peer->pna_up.na_slot_ctxs == NULL));

	return error;
}

/*
 * nx_upipe_na_activate.
 *
 * There are two cases on registration (onoff==1)
 *
 * 1.a) state is
 *
 *        usr1 --> e1 --> e2
 *
 *      and we are e1. Nothing special to do.
 *
 * 1.b) state is
 *
 *        usr1 --> e1 --> e2 <-- usr2
 *
 *      and we are e2. Drop the ref e1 is holding.
 *
 *  There are two additional cases on unregister (onoff==0)
 *
 *  2.a) state is
 *
 *         usr1 --> e1 --> e2
 *
 *       and we are e1. Nothing special to do, e2 will
 *       be cleaned up by the destructor of e1.
 *
 *  2.b) state is
 *
 *         usr1 --> e1     e2 <-- usr2
 *
 *       and we are either e1 or e2. Add a ref from the
 *       other end and hide our rings.
 */
static int
nx_upipe_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;

	SK_LOCK_ASSERT_HELD();

	SK_DF(SK_VERB_USER_PIPE, "na \"%s\" (0x%llx) %s", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode));

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		break;

	case NA_ACTIVATE_MODE_OFF:
		atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	if (pna->pna_peer_ref) {
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 1.a or 2.a, nothing to do", SK_KVA(na));
		return 0;
	}

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 1.b, drop peer", SK_KVA(na));
		if (pna->pna_peer->pna_peer_ref) {
			pna->pna_peer->pna_peer_ref = FALSE;
			(void) na_release_locked(na);
		}
		break;

	case NA_ACTIVATE_MODE_OFF:
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 2.b, grab peer", SK_KVA(na));
		if (!pna->pna_peer->pna_peer_ref) {
			na_retain_locked(na);
			pna->pna_peer->pna_peer_ref = TRUE;
		}
		break;

	default:
		break;
	}

	return 0;
}

/*
 * nx_upipe_na_krings_delete.
 *
 * There are two cases:
 *
 * 1) state is
 *
 *                usr1 --> e1 --> e2
 *
 *    and we are e1 (e2 is not bound, so krings_delete cannot be
 *    called on it);
 *
 * 2) state is
 *
 *                usr1 --> e1     e2 <-- usr2
 *
 *    and we are either e1 or e2.
 *
 * In the former case we have to also delete the krings of e2;
 * in the latter case we do nothing (note that our krings
 * have already been hidden in the unregister callback).
 */
static void
nx_upipe_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;
	struct nexus_adapter *ona; /* na of the other end */
	uint32_t i;
	enum txrx t;

	SK_LOCK_ASSERT_HELD();

	if (!pna->pna_peer_ref) {
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: case 2, kept alive by peer", SK_KVA(na));
		/*
		 * If adapter is defunct (note the explicit test against
		 * NAF_DEFUNCT, and not the "defunct" parameter passed in
		 * by the caller), then the peer's channel has gone defunct.
		 * We get here because this channel was not defuncted, and
		 * that this is the last active reference to the adapter.
		 * At this point we tear everything down, since the caller
		 * will proceed to destroying the memory regions.
		 */
		if (na->na_flags & NAF_DEFUNCT) {
			na_rings_mem_teardown(na, ch, defunct);
		}
		return;
	}

	/* case 1) above */
	SK_DF(SK_VERB_USER_PIPE,
	    "0x%llx: case 1, deleting everyhing", SK_KVA(na));

	ASSERT(na->na_channels == 0 || (na->na_flags & NAF_DEFUNCT));

	/* restore the ring to be deleted on the peer */
	ona = &pna->pna_peer->pna_up;
	if (ona->na_tx_rings == NULL) {
		/*
		 * Already deleted, we must be on an
		 * cleanup-after-error path
		 * Just delete this end
		 */
		na_rings_mem_teardown(na, ch, defunct);
		return;
	}

	/* delete the memory rings */
	na_rings_mem_teardown(na, ch, defunct);

	if (!defunct) {
		for_rx_tx(t) {
			for (i = 0; i < na_get_nrings(ona, t); i++) {
				NAKR(ona, t)[i].ckr_ring =
				    NAKR(ona, t)[i].ckr_save_ring;
			}
		}
	}

	/* Delete the memory rings */
	na_rings_mem_teardown(ona, ch, defunct);
}

static void
nx_upipe_na_dtor(struct nexus_adapter *na)
{
	struct nexus_upipe_adapter *pna = (struct nexus_upipe_adapter *)na;
	struct nx_upipe *u = NX_UPIPE_PRIVATE(na->na_nx);

	SK_LOCK_ASSERT_HELD();

	SK_DF(SK_VERB_USER_PIPE, "0x%llx", SK_KVA(na));
	if (pna->pna_peer_ref) {
		SK_DF(SK_VERB_USER_PIPE,
		    "0x%llx: clean up peer 0x%llx", SK_KVA(na),
		    SK_KVA(&pna->pna_peer->pna_up));
		pna->pna_peer_ref = FALSE;
		(void) na_release_locked(&pna->pna_peer->pna_up);
	}
	if (pna->pna_role == CH_ENDPOINT_USER_PIPE_MASTER) {
		nx_upipe_na_remove(pna->pna_parent, pna);
	}
	(void) na_release_locked(pna->pna_parent);
	pna->pna_parent = NULL;

	/* release reference to parent adapter held by nx_upipe_na_find() */
	ASSERT(u->nup_pna_users != 0);
	if (--u->nup_pna_users == 0) {
		ASSERT(u->nup_pna != NULL);
		SK_DF(SK_VERB_USER_PIPE, "release parent: \"%s\" (0x%llx)",
		    u->nup_pna->na_name, SK_KVA(u->nup_pna));
		na_release_locked(u->nup_pna);
		u->nup_pna = NULL;
	}
}

int
nx_upipe_na_find(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_adapter **na, boolean_t create)
{
#pragma unused(ch, p)
	struct nx_upipe *u = NX_UPIPE_PRIVATE(nx);
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_adapter *pna = NULL; /* parent adapter */
	boolean_t anon = NX_ANONYMOUS_PROV(nx);
	struct nexus_upipe_adapter *mna, *sna, *req;
	ch_endpoint_t ep = chr->cr_endpoint;
	uint32_t pipe_id;
	int error;

	SK_LOCK_ASSERT_HELD();
	*na = NULL;

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("name \"%s\" spec_uuid \"%s\" port %d mode 0x%b pipe_id %u "
	    "ring_id %d ring_set %u ep_type %u:%u create %u%s",
	    chr->cr_name, sk_uuid_unparse(chr->cr_spec_uuid, uuidstr),
	    (int)chr->cr_port, chr->cr_mode, CHMODE_BITS,
	    chr->cr_pipe_id, (int)chr->cr_ring_id, chr->cr_ring_set,
	    chr->cr_real_endpoint, chr->cr_endpoint, create,
	    (ep != CH_ENDPOINT_USER_PIPE_MASTER &&
	    ep != CH_ENDPOINT_USER_PIPE_SLAVE) ? " (skipped)" : "");
#endif /* SK_LOG */

	if (ep != CH_ENDPOINT_USER_PIPE_MASTER &&
	    ep != CH_ENDPOINT_USER_PIPE_SLAVE) {
		return 0;
	}

	/*
	 * Check client credentials.
	 */
	if (chr->cr_port == NEXUS_PORT_USER_PIPE_SERVER) {
		if (!anon && (u->nup_srv_nxb == NULL || nxb == NULL ||
		    !nxb_is_equal(u->nup_srv_nxb, nxb))) {
			return EACCES;
		}
	} else {
		ASSERT(chr->cr_port == NEXUS_PORT_USER_PIPE_CLIENT);
		if (!anon && (u->nup_cli_nxb == NULL || nxb == NULL ||
		    !nxb_is_equal(u->nup_cli_nxb, nxb))) {
			return EACCES;
		}
	}

	/*
	 * First, try to find a previously-created parent adapter
	 * for this nexus; else, create one and store it in the
	 * nexus.  We'll release this at nexus destructor time.
	 */
	if ((pna = u->nup_pna) != NULL) {
		na_retain_locked(pna);  /* for us */
		SK_DF(SK_VERB_USER_PIPE, "found parent: \"%s\" (0x%llx)",
		    pna->na_name, SK_KVA(pna));
	} else {
		/* callee will hold a reference for us upon success */
		error = na_pseudo_create(nx, chr, &pna);
		if (error != 0) {
			SK_ERR("parent create failed: %d", error);
			return error;
		}
		/* hold an extra reference for nx_upipe */
		u->nup_pna = pna;
		na_retain_locked(pna);
		SK_DF(SK_VERB_USER_PIPE, "created parent: \"%s\" (0x%llx)",
		    pna->na_name, SK_KVA(pna));
	}

	/* next, lookup the pipe id in the parent list */
	req = NULL;
	pipe_id = chr->cr_pipe_id;
	mna = nx_upipe_find(pna, pipe_id);
	if (mna != NULL) {
		if (mna->pna_role == ep) {
			SK_DF(SK_VERB_USER_PIPE,
			    "found pipe_id %u directly at slot %u",
			    pipe_id, mna->pna_parent_slot);
			req = mna;
		} else {
			SK_DF(SK_VERB_USER_PIPE,
			    "found pipe_id %u indirectly at slot %u",
			    pipe_id, mna->pna_parent_slot);
			req = mna->pna_peer;
		}
		/*
		 * The pipe we have found already holds a ref to the parent,
		 * so we need to drop the one we got from above.
		 */
		(void) na_release_locked(pna);
		goto found;
	}
	SK_DF(SK_VERB_USER_PIPE,
	    "pipe_id %u not found, create %u", pipe_id, create);
	if (!create) {
		error = ENODEV;
		goto put_out;
	}
	/*
	 * We create both master and slave.
	 * The endpoint we were asked for holds a reference to
	 * the other one.
	 */
	mna = na_upipe_alloc(Z_WAITOK);

	ASSERT(mna->pna_up.na_type == NA_USER_PIPE);
	ASSERT(mna->pna_up.na_free == na_upipe_free);

	(void) snprintf(mna->pna_up.na_name, sizeof(mna->pna_up.na_name),
	    "%s{%u", pna->na_name, pipe_id);
	uuid_generate_random(mna->pna_up.na_uuid);

	mna->pna_id = pipe_id;
	mna->pna_role = CH_ENDPOINT_USER_PIPE_MASTER;
	mna->pna_parent = pna;
	mna->pna_up.na_txsync = nx_upipe_na_txsync;
	mna->pna_up.na_rxsync = nx_upipe_na_rxsync;
	mna->pna_up.na_activate = nx_upipe_na_activate;
	mna->pna_up.na_dtor = nx_upipe_na_dtor;
	mna->pna_up.na_krings_create = nx_upipe_na_krings_create;
	mna->pna_up.na_krings_delete = nx_upipe_na_krings_delete;
	mna->pna_up.na_arena = pna->na_arena;
	skmem_arena_retain((&mna->pna_up)->na_arena);
	atomic_bitset_32(&mna->pna_up.na_flags, NAF_MEM_LOANED);
	*(nexus_meta_type_t *)(uintptr_t)&mna->pna_up.na_md_type =
	    pna->na_md_type;
	*(nexus_meta_subtype_t *)(uintptr_t)&mna->pna_up.na_md_subtype =
	    pna->na_md_subtype;

	*(nexus_stats_type_t *)(uintptr_t)&mna->pna_up.na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;
	*(uint32_t *)(uintptr_t)&mna->pna_up.na_flowadv_max =
	    nxp->nxp_flowadv_max;
	ASSERT(mna->pna_up.na_flowadv_max == 0 ||
	    skmem_arena_nexus(mna->pna_up.na_arena)->arn_flowadv_obj != NULL);

	/*
	 * Parent adapter parameters must match the nexus provider's by the
	 * time we get here, since na_find() above shouldn't return
	 * one otherwise.
	 */
	na_set_nrings(&mna->pna_up, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(&mna->pna_up, NR_RX, nxp->nxp_rx_rings);
	na_set_nslots(&mna->pna_up, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(&mna->pna_up, NR_RX, nxp->nxp_rx_slots);
	ASSERT(na_get_nrings(&mna->pna_up, NR_TX) == na_get_nrings(pna, NR_TX));
	ASSERT(na_get_nrings(&mna->pna_up, NR_RX) == na_get_nrings(pna, NR_RX));
	ASSERT(na_get_nslots(&mna->pna_up, NR_TX) == na_get_nslots(pna, NR_TX));
	ASSERT(na_get_nslots(&mna->pna_up, NR_RX) == na_get_nslots(pna, NR_RX));

	na_attach_common(&mna->pna_up, nx, &nx_upipe_prov_s);

	/* register the master with the parent */
	error = nx_upipe_na_add(pna, mna);
	if (error != 0) {
		goto free_mna;
	}

	/* create the slave */
	sna = na_upipe_alloc(Z_WAITOK);

	/* most fields are the same, copy from master and then fix */
	bcopy(mna, sna, sizeof(*sna));
	skmem_arena_retain((&sna->pna_up)->na_arena);
	atomic_bitset_32(&sna->pna_up.na_flags, NAF_MEM_LOANED);

	ASSERT(sna->pna_up.na_type == NA_USER_PIPE);
	ASSERT(sna->pna_up.na_free == na_upipe_free);

	(void) snprintf(sna->pna_up.na_name, sizeof(sna->pna_up.na_name),
	    "%s}%d", pna->na_name, pipe_id);
	uuid_generate_random(sna->pna_up.na_uuid);

	sna->pna_role = CH_ENDPOINT_USER_PIPE_SLAVE;
	na_attach_common(&sna->pna_up, nx, &nx_upipe_prov_s);

	/* join the two endpoints */
	mna->pna_peer = sna;
	sna->pna_peer = mna;

	/*
	 * We already have a reference to the parent, but we
	 * need another one for the other endpoint we created
	 */
	na_retain_locked(pna);

	if ((chr->cr_mode & CHMODE_DEFUNCT_OK) != 0) {
		atomic_bitset_32(&pna->na_flags, NAF_DEFUNCT_OK);
	}

	if (ep == CH_ENDPOINT_USER_PIPE_MASTER) {
		req = mna;
		mna->pna_peer_ref = TRUE;
		na_retain_locked(&sna->pna_up);
	} else {
		req = sna;
		sna->pna_peer_ref = TRUE;
		na_retain_locked(&mna->pna_up);
	}

	/* parent adapter now has two users (mna and sna) */
	u->nup_pna_users += 2;

#if SK_LOG
	SK_DF(SK_VERB_USER_PIPE, "created master 0x%llx and slave 0x%llx",
	    SK_KVA(mna), SK_KVA(sna));
	SK_DF(SK_VERB_USER_PIPE, "mna: \"%s\"", mna->pna_up.na_name);
	SK_DF(SK_VERB_USER_PIPE, "  UUID:        %s",
	    sk_uuid_unparse(mna->pna_up.na_uuid, uuidstr));
	SK_DF(SK_VERB_USER_PIPE, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(mna->pna_up.na_nx), NX_DOM(mna->pna_up.na_nx)->nxdom_name,
	    NX_DOM_PROV(mna->pna_up.na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_USER_PIPE, "  flags:       0x%b",
	    mna->pna_up.na_flags, NAF_BITS);
	SK_DF(SK_VERB_USER_PIPE, "  flowadv_max: %u",
	    mna->pna_up.na_flowadv_max);
	SK_DF(SK_VERB_USER_PIPE, "  rings:       tx %u rx %u",
	    na_get_nrings(&mna->pna_up, NR_TX),
	    na_get_nrings(&mna->pna_up, NR_RX));
	SK_DF(SK_VERB_USER_PIPE, "  slots:       tx %u rx %u",
	    na_get_nslots(&mna->pna_up, NR_TX),
	    na_get_nslots(&mna->pna_up, NR_RX));
	SK_DF(SK_VERB_USER_PIPE, "  next_pipe:   %u", mna->pna_up.na_next_pipe);
	SK_DF(SK_VERB_USER_PIPE, "  max_pipes:   %u", mna->pna_up.na_max_pipes);
	SK_DF(SK_VERB_USER_PIPE, "  parent:      \"%s\"",
	    mna->pna_parent->na_name);
	SK_DF(SK_VERB_USER_PIPE, "  id:          %u", mna->pna_id);
	SK_DF(SK_VERB_USER_PIPE, "  role:        %u", mna->pna_role);
	SK_DF(SK_VERB_USER_PIPE, "  peer_ref:    %u", mna->pna_peer_ref);
	SK_DF(SK_VERB_USER_PIPE, "  parent_slot: %u", mna->pna_parent_slot);
	SK_DF(SK_VERB_USER_PIPE, "sna: \"%s\"", sna->pna_up.na_name);
	SK_DF(SK_VERB_USER_PIPE, "  UUID:        %s",
	    sk_uuid_unparse(sna->pna_up.na_uuid, uuidstr));
	SK_DF(SK_VERB_USER_PIPE, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(sna->pna_up.na_nx), NX_DOM(sna->pna_up.na_nx)->nxdom_name,
	    NX_DOM_PROV(sna->pna_up.na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_USER_PIPE, "  flags:       0x%b",
	    sna->pna_up.na_flags, NAF_BITS);
	SK_DF(SK_VERB_USER_PIPE, "  flowadv_max: %u",
	    sna->pna_up.na_flowadv_max);
	SK_DF(SK_VERB_USER_PIPE, "  rings:       tx %u rx %u",
	    na_get_nrings(&sna->pna_up, NR_TX),
	    na_get_nrings(&sna->pna_up, NR_RX));
	SK_DF(SK_VERB_USER_PIPE, "  slots:       tx %u rx %u",
	    na_get_nslots(&sna->pna_up, NR_TX),
	    na_get_nslots(&sna->pna_up, NR_RX));
	SK_DF(SK_VERB_USER_PIPE, "  next_pipe:   %u", sna->pna_up.na_next_pipe);
	SK_DF(SK_VERB_USER_PIPE, "  max_pipes:   %u", sna->pna_up.na_max_pipes);
	SK_DF(SK_VERB_USER_PIPE, "  parent:      \"%s\"",
	    sna->pna_parent->na_name);
	SK_DF(SK_VERB_USER_PIPE, "  id:          %u", sna->pna_id);
	SK_DF(SK_VERB_USER_PIPE, "  role:        %u", sna->pna_role);
	SK_DF(SK_VERB_USER_PIPE, "  peer_ref:    %u", sna->pna_peer_ref);
	SK_DF(SK_VERB_USER_PIPE, "  parent_slot: %u", sna->pna_parent_slot);
#endif /* SK_LOG */

found:

	SK_DF(SK_VERB_USER_PIPE, "pipe_id %u role %s at 0x%llx", pipe_id,
	    (req->pna_role == CH_ENDPOINT_USER_PIPE_MASTER ?
	    "master" : "slave"), SK_KVA(req));
	if ((chr->cr_mode & CHMODE_DEFUNCT_OK) == 0) {
		atomic_bitclear_32(&pna->na_flags, NAF_DEFUNCT_OK);
	}
	*na = &req->pna_up;
	na_retain_locked(*na);

	/*
	 * Keep the reference to the parent; it will be released
	 * by the adapter's destructor.
	 */
	return 0;

free_mna:
	if (mna->pna_up.na_arena != NULL) {
		skmem_arena_release((&mna->pna_up)->na_arena);
		mna->pna_up.na_arena = NULL;
	}
	NA_FREE(&mna->pna_up);
put_out:
	(void) na_release_locked(pna);
	return error;
}

static struct nx_upipe *
nx_upipe_alloc(zalloc_flags_t how)
{
	struct nx_upipe *u;

	SK_LOCK_ASSERT_HELD();

	u = zalloc_flags(nx_upipe_zone, how | Z_ZERO);
	if (u) {
		SK_DF(SK_VERB_MEM, "upipe 0x%llx ALLOC", SK_KVA(u));
	}
	return u;
}

static void
nx_upipe_free(struct nx_upipe *u)
{
	ASSERT(u->nup_pna == NULL);
	ASSERT(u->nup_pna_users == 0);
	ASSERT(u->nup_cli_nxb == NULL);
	ASSERT(u->nup_srv_nxb == NULL);

	SK_DF(SK_VERB_MEM, "upipe 0x%llx FREE", SK_KVA(u));
	zfree(nx_upipe_zone, u);
}
