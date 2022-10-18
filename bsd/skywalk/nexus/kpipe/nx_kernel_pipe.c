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
#include <skywalk/nexus/kpipe/nx_kernel_pipe.h>

/* XXX arbitrary */
#define NX_KPIPE_RINGSIZE       128 /* default ring size */
#define NX_KPIPE_MINSLOTS       2
#define NX_KPIPE_MAXSLOTS       4096
#define NX_KPIPE_MAXRINGS       NX_MAX_NUM_RING_PAIR
#define NX_KPIPE_BUFSIZE        (2 * 1024)
#define NX_KPIPE_MINBUFSIZE     64
#define NX_KPIPE_MAXBUFSIZE     (16 * 1024)

static int nx_kpipe_na_txsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_kpipe_na_rxsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_kpipe_na_activate(struct nexus_adapter *, na_activate_mode_t);
static void nx_kpipe_na_dtor(struct nexus_adapter *);
static int nx_kpipe_na_krings_create(struct nexus_adapter *,
    struct kern_channel *);
static void nx_kpipe_na_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);

static void nx_kpipe_dom_init(struct nxdom *);
static void nx_kpipe_dom_terminate(struct nxdom *);
static void nx_kpipe_dom_fini(struct nxdom *);
static int nx_kpipe_dom_bind_port(struct kern_nexus *, nexus_port_t *,
    struct nxbind *, void *);
static int nx_kpipe_dom_unbind_port(struct kern_nexus *, nexus_port_t);
static int nx_kpipe_dom_connect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *);
static void nx_kpipe_dom_disconnect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *);
static void nx_kpipe_dom_defunct(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct proc *);
static void nx_kpipe_dom_defunct_finalize(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, boolean_t);

static int nx_kpipe_prov_init(struct kern_nexus_domain_provider *);
static int nx_kpipe_prov_params_adjust(
	const struct kern_nexus_domain_provider *,
	const struct nxprov_params *, struct nxprov_adjusted_params *);
static int nx_kpipe_prov_params(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS], uint32_t);
static int nx_kpipe_prov_mem_new(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nexus_adapter *);
static void nx_kpipe_prov_fini(struct kern_nexus_domain_provider *);
static int nx_kpipe_prov_nx_ctor(struct kern_nexus *);
static void nx_kpipe_prov_nx_dtor(struct kern_nexus *);
static int nx_kpipe_prov_nx_mem_info(struct kern_nexus *,
    struct kern_pbufpool **, struct kern_pbufpool **);

static struct nexus_kpipe_adapter *na_kpipe_alloc(zalloc_flags_t);
static void na_kpipe_free(struct nexus_adapter *);

struct nxdom nx_kpipe_dom_s = {
	.nxdom_prov_head =
    STAILQ_HEAD_INITIALIZER(nx_kpipe_dom_s.nxdom_prov_head),
	.nxdom_type =           NEXUS_TYPE_KERNEL_PIPE,
	.nxdom_md_type =        NEXUS_META_TYPE_QUANTUM,
	.nxdom_md_subtype =     NEXUS_META_SUBTYPE_PAYLOAD,
	.nxdom_name =           "kpipe",
	.nxdom_ports =          {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_tx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_KPIPE_MAXRINGS,
	},
	.nxdom_rx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = NX_KPIPE_MAXRINGS,
	},
	.nxdom_tx_slots = {
		.nb_def = NX_KPIPE_RINGSIZE,
		.nb_min = NX_KPIPE_MINSLOTS,
		.nb_max = NX_KPIPE_MAXSLOTS,
	},
	.nxdom_rx_slots = {
		.nb_def = NX_KPIPE_RINGSIZE,
		.nb_min = NX_KPIPE_MINSLOTS,
		.nb_max = NX_KPIPE_MAXSLOTS,
	},
	.nxdom_buf_size = {
		.nb_def = NX_KPIPE_BUFSIZE,
		.nb_min = NX_KPIPE_MINBUFSIZE,
		.nb_max = NX_KPIPE_MAXBUFSIZE,
	},
	.nxdom_large_buf_size = {
		.nb_def = 0,
		.nb_min = 0,
		.nb_max = 0,
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
	.nxdom_init =           nx_kpipe_dom_init,
	.nxdom_terminate =      nx_kpipe_dom_terminate,
	.nxdom_fini =           nx_kpipe_dom_fini,
	.nxdom_find_port =      NULL,
	.nxdom_port_is_reserved = NULL,
	.nxdom_bind_port =      nx_kpipe_dom_bind_port,
	.nxdom_unbind_port =    nx_kpipe_dom_unbind_port,
	.nxdom_connect =        nx_kpipe_dom_connect,
	.nxdom_disconnect =     nx_kpipe_dom_disconnect,
	.nxdom_defunct =        nx_kpipe_dom_defunct,
	.nxdom_defunct_finalize = nx_kpipe_dom_defunct_finalize,
};

static struct kern_nexus_domain_provider nx_kpipe_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_KERNEL_PIPE,
	.nxdom_prov_flags =             NXDOMPROVF_DEFAULT,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_kpipe_prov_init,
		.dp_cb_fini =           nx_kpipe_prov_fini,
		.dp_cb_params =         nx_kpipe_prov_params,
		.dp_cb_mem_new =        nx_kpipe_prov_mem_new,
		.dp_cb_config =         NULL,
		.dp_cb_nx_ctor =        nx_kpipe_prov_nx_ctor,
		.dp_cb_nx_dtor =        nx_kpipe_prov_nx_dtor,
		.dp_cb_nx_mem_info =    nx_kpipe_prov_nx_mem_info,
		.dp_cb_nx_mib_get =     NULL,
		.dp_cb_nx_stop =        NULL,
	},
};

static ZONE_DEFINE(na_kpipe_zone, SKMEM_ZONE_PREFIX ".na.kpipe",
    sizeof(struct nexus_kpipe_adapter), ZC_ZFREE_CLEARMEM);

static void
nx_kpipe_dom_init(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED));

	(void) nxdom_prov_add(nxdom, &nx_kpipe_prov_s);
}

static void
nx_kpipe_dom_terminate(struct nxdom *nxdom)
{
	struct kern_nexus_domain_provider *nxdom_prov, *tnxdp;

	SK_LOCK_ASSERT_HELD();

	STAILQ_FOREACH_SAFE(nxdom_prov, &nxdom->nxdom_prov_head,
	    nxdom_prov_link, tnxdp) {
		(void) nxdom_prov_del(nxdom_prov);
	}
}

static void
nx_kpipe_dom_fini(struct nxdom *nxdom)
{
#pragma unused(nxdom)
}

static int
nx_kpipe_dom_bind_port(struct kern_nexus *nx, nexus_port_t *nx_port,
    struct nxbind *nxb0, void *info)
{
#pragma unused(info)
	struct nxbind *nxb = NULL;
	int error = 0;

	ASSERT(nx_port != NULL);
	ASSERT(nxb0 != NULL);

	switch (*nx_port) {
	case NEXUS_PORT_KERNEL_PIPE_CLIENT:
		if (nx->nx_arg != NULL) {
			error = EEXIST;
			break;
		}

		nxb = nxb_alloc(Z_WAITOK);
		nxb_move(nxb0, nxb);
		nx->nx_arg = nxb;

		ASSERT(error == 0);
		break;

	default:
		error = EDOM;
		break;
	}

	return error;
}

static int
nx_kpipe_dom_unbind_port(struct kern_nexus *nx, nexus_port_t nx_port)
{
	struct nxbind *nxb = NULL;
	int error = 0;

	ASSERT(nx_port != NEXUS_PORT_ANY);

	switch (nx_port) {
	case NEXUS_PORT_KERNEL_PIPE_CLIENT:
		if ((nxb = nx->nx_arg) == NULL) {
			error = ENOENT;
			break;
		}
		nx->nx_arg = NULL;
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
nx_kpipe_dom_connect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
#pragma unused(nxdom_prov)
	nexus_port_t port = chr->cr_port;
	int err = 0;

	SK_DF(SK_VERB_KERNEL_PIPE, "port %d mode 0x%b",
	    (int)port, chr->cr_mode, CHMODE_BITS);

	SK_LOCK_ASSERT_HELD();

	ASSERT(nx->nx_prov->nxprov_params->nxp_type ==
	    nxdom_prov->nxdom_prov_dom->nxdom_type &&
	    nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_KERNEL_PIPE);

	if (port != NEXUS_PORT_KERNEL_PIPE_CLIENT) {
		err = EINVAL;
		goto done;
	}

	/*
	 * XXX: user packet pool is not supported for kernel pipe for now.
	 */
	if (chr->cr_mode & CHMODE_USER_PACKET_POOL) {
		SK_ERR("User Packet pool mode not supported for kpipe");
		err = ENOTSUP;
		goto done;
	}

	if (chr->cr_mode & CHMODE_EVENT_RING) {
		SK_ERR("event ring is not supported for kpipe");
		err = ENOTSUP;
		goto done;
	}

	if (chr->cr_mode & CHMODE_LOW_LATENCY) {
		SK_ERR("low latency is not supported for kpipe");
		err = ENOTSUP;
		goto done;
	}

	chr->cr_ring_set = RING_SET_DEFAULT;
	chr->cr_real_endpoint = chr->cr_endpoint = CH_ENDPOINT_KERNEL_PIPE;
	(void) snprintf(chr->cr_name, sizeof(chr->cr_name), "kpipe:%llu:%.*s",
	    nx->nx_id, (int)nx->nx_prov->nxprov_params->nxp_namelen,
	    nx->nx_prov->nxprov_params->nxp_name);

	err = na_connect(nx, ch, chr, ch0, nxb, p);
	if (err == 0) {
		/*
		 * Mark the kernel slot descriptor region as busy; this
		 * prevents it from being torn-down at channel defunct
		 * time, as the (external) nexus owner may be calling
		 * KPIs that require accessing the slots.
		 */
		skmem_arena_nexus_sd_set_noidle(
			skmem_arena_nexus(ch->ch_na->na_arena), 1);
	}

done:
	return err;
}

static void
nx_kpipe_dom_disconnect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nxdom_prov, nx)
	SK_LOCK_ASSERT_HELD();

	SK_D("channel 0x%llx -!- nexus 0x%llx (%s:\"%s\":%u:%d)", SK_KVA(ch),
	    SK_KVA(nx), nxdom_prov->nxdom_prov_name, ch->ch_na->na_name,
	    ch->ch_info->cinfo_nx_port, (int)ch->ch_info->cinfo_ch_ring_id);

	/*
	 * Release busy assertion held earlier in nx_kpipe_dom_connect();
	 * this allows for the final arena teardown to succeed.
	 */
	skmem_arena_nexus_sd_set_noidle(
		skmem_arena_nexus(ch->ch_na->na_arena), -1);

	na_disconnect(nx, ch);
}

static void
nx_kpipe_dom_defunct(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct proc *p)
{
#pragma unused(nxdom_prov, nx)
	struct nexus_adapter *na = ch->ch_na;
	ring_id_t qfirst;
	ring_id_t qlast;
	enum txrx t;
	uint32_t i;

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_KERNEL_PIPE);

	/*
	 * Interface drivers like utun & IPsec access the kpipe rings
	 * outside of a kpipe channel sync context. They hold rights
	 * to the ring through kr_enter().
	 */
	for_rx_tx(t) {
		qfirst = ch->ch_first[t];
		qlast = ch->ch_last[t];

		for (i = qfirst; i < qlast; i++) {
			(void) kr_enter(&NAKR(na, t)[i], TRUE);
		}
	}

	na_ch_rings_defunct(ch, p);

	for_rx_tx(t) {
		qfirst = ch->ch_first[t];
		qlast = ch->ch_last[t];

		for (i = qfirst; i < qlast; i++) {
			kr_exit(&NAKR(na, t)[i]);
		}
	}
}

static void
nx_kpipe_dom_defunct_finalize(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, boolean_t locked)
{
#pragma unused(nxdom_prov)
	if (!locked) {
		SK_LOCK_ASSERT_NOTHELD();
		SK_LOCK();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_NOTOWNED);
	} else {
		SK_LOCK_ASSERT_HELD();
		LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);
	}

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ch->ch_na->na_type == NA_KERNEL_PIPE);

	na_defunct(nx, ch, ch->ch_na, locked);

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

static int
nx_kpipe_prov_init(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);
	return 0;
}

static int
nx_kpipe_prov_params_adjust(const struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_params *nxp, struct nxprov_adjusted_params *adj)
{
#pragma unused(nxdom_prov, nxp, adj)
	return 0;
}

static int
nx_kpipe_prov_params(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS],
    uint32_t pp_region_config_flags)
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;

	return nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	           nxdom, nxdom, nxdom, pp_region_config_flags,
	           nx_kpipe_prov_params_adjust);
}

static int
nx_kpipe_prov_mem_new(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nxdom_prov)
	int err = 0;

	SK_DF(SK_VERB_KERNEL_PIPE,
	    "nx 0x%llx (\"%s\":\"%s\") na \"%s\" (0x%llx)", SK_KVA(nx),
	    NX_DOM(nx)->nxdom_name, nxdom_prov->nxdom_prov_name, na->na_name,
	    SK_KVA(na));

	ASSERT(na->na_arena == NULL);
	ASSERT(NX_USER_CHANNEL_PROV(nx));
	/*
	 * Store pp in the nexus to handle kern_nexus_get_pbufpool() calls.
	 */
	na->na_arena = skmem_arena_create_for_nexus(na,
	    NX_PROV(nx)->nxprov_region_params, &nx->nx_tx_pp,
	    &nx->nx_rx_pp, 0, NULL, &err);
	ASSERT(na->na_arena != NULL || err != 0);
	ASSERT(nx->nx_tx_pp == NULL || (nx->nx_tx_pp->pp_md_type ==
	    NX_DOM(nx)->nxdom_md_type && nx->nx_tx_pp->pp_md_subtype ==
	    NX_DOM(nx)->nxdom_md_subtype));
	ASSERT(nx->nx_rx_pp == NULL || (nx->nx_rx_pp->pp_md_type ==
	    NX_DOM(nx)->nxdom_md_type && nx->nx_rx_pp->pp_md_subtype ==
	    NX_DOM(nx)->nxdom_md_subtype));

	return err;
}

static void
nx_kpipe_prov_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);
}

static int
nx_kpipe_prov_nx_ctor(struct kern_nexus *nx)
{
#pragma unused(nx)
	SK_LOCK_ASSERT_HELD();
	ASSERT(nx->nx_arg == NULL);
	return 0;
}

static void
nx_kpipe_prov_nx_dtor(struct kern_nexus *nx)
{
	struct nxbind *nxb;

	SK_LOCK_ASSERT_HELD();

	if ((nxb = nx->nx_arg) != NULL) {
		nxb_free(nxb);
		nx->nx_arg = NULL;
	}
}

static int
nx_kpipe_prov_nx_mem_info(struct kern_nexus *nx, struct kern_pbufpool **tpp,
    struct kern_pbufpool **rpp)
{
	ASSERT(nx->nx_tx_pp != NULL);
	ASSERT(nx->nx_rx_pp != NULL);

	if (tpp != NULL) {
		*tpp = nx->nx_tx_pp;
	}
	if (rpp != NULL) {
		*rpp = nx->nx_rx_pp;
	}

	return 0;
}

static struct nexus_kpipe_adapter *
na_kpipe_alloc(zalloc_flags_t how)
{
	struct nexus_kpipe_adapter *kna;

	_CASSERT(offsetof(struct nexus_kpipe_adapter, kna_up) == 0);

	kna = zalloc_flags(na_kpipe_zone, how | Z_ZERO);
	if (kna) {
		kna->kna_up.na_type = NA_KERNEL_PIPE;
		kna->kna_up.na_free = na_kpipe_free;
	}
	return kna;
}

static void
na_kpipe_free(struct nexus_adapter *na)
{
	struct nexus_kpipe_adapter *kna = (struct nexus_kpipe_adapter *)na;

	ASSERT(kna->kna_up.na_refcount == 0);
	SK_DF(SK_VERB_MEM, "kna 0x%llx FREE", SK_KVA(kna));
	bzero(kna, sizeof(*kna));
	zfree(na_kpipe_zone, kna);
}

static int
nx_kpipe_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	return nx_sync_tx(kring, (flags & NA_SYNCF_FORCE_RECLAIM));
}

static int
nx_kpipe_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p)
	SK_DF(SK_VERB_KERNEL_PIPE | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	ASSERT(kring->ckr_rhead <= kring->ckr_lim);

	return nx_sync_rx(kring, (flags & NA_SYNCF_FORCE_READ));
}

static int
nx_kpipe_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	ASSERT(na->na_type == NA_KERNEL_PIPE);

	SK_DF(SK_VERB_KERNEL_PIPE, "na \"%s\" (0x%llx) %s", na->na_name,
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

	return 0;
}

static void
nx_kpipe_na_dtor(struct nexus_adapter *na)
{
#pragma unused(na)
	ASSERT(na->na_type == NA_KERNEL_PIPE);
}

static int
nx_kpipe_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	ASSERT(na->na_type == NA_KERNEL_PIPE);
	/*
	 * The assumption here is that all kernel pipe instances
	 * are handled by IOSkywalkFamily, and thus we allocate
	 * the context area for it to store its object references.
	 */
	return na_rings_mem_setup(na, 0, TRUE, ch);
}

static void
nx_kpipe_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_KERNEL_PIPE);

	na_rings_mem_teardown(na, ch, defunct);
}

int
nx_kpipe_na_find(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_adapter **ret, boolean_t create)
{
#pragma unused(ch, p)
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_kpipe_adapter *kna;
	ch_endpoint_t ep = chr->cr_endpoint;
	struct nexus_adapter *na = NULL;
	int error = 0;

	SK_LOCK_ASSERT_HELD();
	*ret = NULL;

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("name \"%s\" spec_uuid \"%s\" port %d mode 0x%b pipe_id %u "
	    "ring_id %d ring_set %u ep_type %u:%u create %u%s",
	    chr->cr_name, sk_uuid_unparse(chr->cr_spec_uuid, uuidstr),
	    (int)chr->cr_port, chr->cr_mode, CHMODE_BITS,
	    chr->cr_pipe_id, (int)chr->cr_ring_id, chr->cr_ring_set,
	    chr->cr_real_endpoint, chr->cr_endpoint, create,
	    (ep != CH_ENDPOINT_KERNEL_PIPE) ? " (skipped)" : "");
#endif /* SK_LOG */

	if (ep != CH_ENDPOINT_KERNEL_PIPE) {
		return 0;
	}

	if (!create) {
		return ENODEV;
	}

	/*
	 * Check client credentials.
	 */
	if (!NX_ANONYMOUS_PROV(nx) && (nx->nx_arg == NULL || nxb == NULL ||
	    !nxb_is_equal(nx->nx_arg, nxb))) {
		return EACCES;
	}

	kna = na_kpipe_alloc(Z_WAITOK);

	na = &kna->kna_up;
	ASSERT(na->na_type == NA_KERNEL_PIPE);
	ASSERT(na->na_free == na_kpipe_free);

	(void) snprintf(na->na_name, sizeof(na->na_name),
	    "%s{%u", chr->cr_name, NEXUS_PORT_KERNEL_PIPE_CLIENT);
	uuid_generate_random(na->na_uuid);

	na->na_txsync = nx_kpipe_na_txsync;
	na->na_rxsync = nx_kpipe_na_rxsync;
	na->na_activate = nx_kpipe_na_activate;
	na->na_dtor = nx_kpipe_na_dtor;
	na->na_krings_create = nx_kpipe_na_krings_create;
	na->na_krings_delete = nx_kpipe_na_krings_delete;
	na_set_nrings(na, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(na, NR_RX, nxp->nxp_rx_rings);
	na_set_nslots(na, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(na, NR_RX, nxp->nxp_rx_slots);
	/*
	 * Verify upper bounds; the parameters must have already been
	 * validated by nxdom_prov_params() by the time we get here.
	 */
	ASSERT(na_get_nrings(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	*(nexus_stats_type_t *)(uintptr_t)&na->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	na_attach_common(na, nx, &nx_kpipe_prov_s);

	if ((error = NX_DOM_PROV(nx)->nxdom_prov_mem_new(NX_DOM_PROV(nx),
	    nx, na)) != 0) {
		ASSERT(na->na_arena == NULL);
		goto err;
	}
	ASSERT(na->na_arena != NULL);

	*(uint32_t *)(uintptr_t)&na->na_flowadv_max = nxp->nxp_flowadv_max;
	ASSERT(na->na_flowadv_max == 0 ||
	    skmem_arena_nexus(na->na_arena)->arn_flowadv_obj != NULL);

#if SK_LOG
	SK_DF(SK_VERB_KERNEL_PIPE, "created kpipe adapter 0x%llx", SK_KVA(kna));
	SK_DF(SK_VERB_KERNEL_PIPE, "na_name: \"%s\"", na->na_name);
	SK_DF(SK_VERB_KERNEL_PIPE, "  UUID:        %s",
	    sk_uuid_unparse(na->na_uuid, uuidstr));
	SK_DF(SK_VERB_KERNEL_PIPE, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(na->na_nx), NX_DOM(na->na_nx)->nxdom_name,
	    NX_DOM_PROV(na->na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_KERNEL_PIPE, "  flags:       0x%b",
	    na->na_flags, NAF_BITS);
	SK_DF(SK_VERB_KERNEL_PIPE, "  flowadv_max: %u", na->na_flowadv_max);
	SK_DF(SK_VERB_KERNEL_PIPE, "  rings:       tx %u rx %u",
	    na_get_nrings(na, NR_TX),
	    na_get_nrings(na, NR_RX));
	SK_DF(SK_VERB_KERNEL_PIPE, "  slots:       tx %u rx %u",
	    na_get_nslots(na, NR_TX),
	    na_get_nslots(na, NR_RX));
#if CONFIG_NEXUS_USER_PIPE
	SK_DF(SK_VERB_KERNEL_PIPE, "  next_pipe:   %u", na->na_next_pipe);
	SK_DF(SK_VERB_KERNEL_PIPE, "  max_pipes:   %u", na->na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
#endif /* SK_LOG */

	*ret = na;
	na_retain_locked(*ret);

	return 0;

err:
	ASSERT(na != NULL);
	if (na->na_arena != NULL) {
		skmem_arena_release(na->na_arena);
		na->na_arena = NULL;
	}
	NA_FREE(na);

	return error;
}

#if (DEVELOPMENT || DEBUG)
SYSCTL_NODE(_kern_skywalk, OID_AUTO, kpipe, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk kpipe tuning");
#endif
