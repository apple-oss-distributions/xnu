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

/*
 * $FreeBSD$
 *
 * Monitors
 *
 * netmap monitors can be used to do monitoring of network traffic
 * on another adapter, when the latter adapter is working in netmap mode.
 *
 * Monitors offer to userspace the same interface as any other netmap port,
 * with as many pairs of netmap rings as the monitored adapter.
 * However, only the rx rings are actually used. Each monitor rx ring receives
 * the traffic transiting on both the tx and rx corresponding rings in the
 * monitored adapter. During registration, the user can choose if she wants
 * to intercept tx only, rx only, or both tx and rx traffic.
 *
 * If the monitor is not able to cope with the stream of frames, excess traffic
 * will be dropped.
 *
 * If the monitored adapter leaves netmap mode, the monitor has to be restarted.
 *
 * Monitors can be either zero-copy or copy-based.
 *
 * Copy monitors see the frames before they are consumed:
 *
 *  - For tx traffic, this is when the application sends them, before they are
 *    passed down to the adapter.
 *
 *  - For rx traffic, this is when they are received by the adapter, before
 *    they are sent up to the application, if any (note that, if no
 *    application is reading from a monitored ring, the ring will eventually
 *    fill up and traffic will stop).
 *
 * Zero-copy monitors only see the frames after they have been consumed:
 *
 *  - For tx traffic, this is after the slots containing the frames have been
 *    marked as free. Note that this may happen at a considerably delay after
 *    frame transmission, since freeing of slots is often done lazily.
 *
 *  - For rx traffic, this is after the consumer on the monitored adapter
 *    has released them. In most cases, the consumer is a userspace
 *    application which may have modified the frame contents.
 *
 * Several copy monitors may be active on any ring.  Zero-copy monitors,
 * instead, need exclusive access to each of the monitored rings.  This may
 * change in the future, if we implement zero-copy monitor chaining.
 *
 */

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/monitor/nx_monitor.h>

static int nx_mon_na_txsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_mon_na_rxsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int nx_mon_na_krings_create(struct nexus_adapter *,
    struct kern_channel *);
static void nx_mon_na_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
static uint32_t nx_mon_txrx2chmode(enum txrx);
static int nx_mon_kr_alloc(struct __kern_channel_ring *, uint32_t);
static void nx_mon_kr_dealloc(struct __kern_channel_ring *);
static int nx_mon_na_krings_locks(struct nexus_adapter *,
    uint32_t[NR_TXRX], uint32_t[NR_TXRX]);
static void nx_mon_na_krings_unlock(struct nexus_adapter *,
    const uint32_t[NR_TXRX], const uint32_t[NR_TXRX]);
static int nx_mon_enable(struct nexus_adapter *, int);
static void nx_mon_disable(struct nexus_adapter *);
static int nx_mon_add(struct __kern_channel_ring *,
    struct __kern_channel_ring *, boolean_t);
static void nx_mon_del(struct __kern_channel_ring *,
    struct __kern_channel_ring *, boolean_t);
static int nx_mon_na_activate_common(struct nexus_adapter *,
    na_activate_mode_t, boolean_t);
static pkt_copy_from_pkt_t nx_mon_quantum_copy_64x;

static int nx_mon_zcopy_parent_sync(struct __kern_channel_ring *,
    struct proc *, uint32_t, enum txrx);
static int nx_mon_zcopy_na_activate(struct nexus_adapter *, na_activate_mode_t);
static void nx_mon_zcopy_na_dtor(struct nexus_adapter *);

static void nx_mon_parent_sync(struct __kern_channel_ring *, struct proc *,
    slot_idx_t, int);
static int nx_mon_na_activate(struct nexus_adapter *, na_activate_mode_t);
static void nx_mon_na_dtor(struct nexus_adapter *);

/*
 * monitors work by replacing the nm_sync() and possibly the
 * nm_notify() callbacks in the monitored rings.
 */
static int nx_mon_zcopy_parent_txsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_mon_zcopy_parent_rxsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_mon_parent_txsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_mon_parent_rxsync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int nx_mon_parent_notify(struct __kern_channel_ring *,
    struct proc *, uint32_t);

static void nx_mon_dom_init(struct nxdom *);
static void nx_mon_dom_terminate(struct nxdom *);
static void nx_mon_dom_fini(struct nxdom *);
static int nx_mon_dom_bind_port(struct kern_nexus *, nexus_port_t *,
    struct nxbind *, void *);
static int nx_mon_dom_unbind_port(struct kern_nexus *, nexus_port_t);
static int nx_mon_dom_connect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct chreq *,
    struct kern_channel *, struct nxbind *, struct proc *);
static void nx_mon_dom_disconnect(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *);
static void nx_mon_dom_defunct(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, struct proc *);
static void nx_mon_dom_defunct_finalize(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct kern_channel *, boolean_t);

static int nx_mon_prov_init(struct kern_nexus_domain_provider *);
static int nx_mon_prov_params_adjust(const struct kern_nexus_domain_provider *,
    const struct nxprov_params *, struct nxprov_adjusted_params *);
static int nx_mon_prov_params(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS], uint32_t);
static int nx_mon_prov_mem_new(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nexus_adapter *);
static void nx_mon_prov_fini(struct kern_nexus_domain_provider *);

static struct nexus_monitor_adapter *na_mon_alloc(zalloc_flags_t);
static void na_mon_free(struct nexus_adapter *);

struct nxdom nx_monitor_dom_s = {
	.nxdom_prov_head =
    STAILQ_HEAD_INITIALIZER(nx_monitor_dom_s.nxdom_prov_head),
	.nxdom_type =           NEXUS_TYPE_MONITOR,
	.nxdom_md_type =        NEXUS_META_TYPE_QUANTUM,
	.nxdom_md_subtype =     NEXUS_META_SUBTYPE_PAYLOAD,
	.nxdom_name =           "monitor",
	/*
	 * The following values don't really matter much, as a monitor
	 * isn't usable on its own; we just define them as non-zeroes.
	 */
	.nxdom_ports =          {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_tx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_rx_rings = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_tx_slots = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_rx_slots = {
		.nb_def = 1,
		.nb_min = 1,
		.nb_max = 1,
	},
	.nxdom_buf_size = {
		.nb_def = 64,
		.nb_min = 64,
		.nb_max = 64,
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
		.nb_max = 0,
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
	.nxdom_init =           nx_mon_dom_init,
	.nxdom_terminate =      nx_mon_dom_terminate,
	.nxdom_fini =           nx_mon_dom_fini,
	.nxdom_find_port =      NULL,
	.nxdom_port_is_reserved = NULL,
	.nxdom_bind_port =      nx_mon_dom_bind_port,
	.nxdom_unbind_port =    nx_mon_dom_unbind_port,
	.nxdom_connect =        nx_mon_dom_connect,
	.nxdom_disconnect =     nx_mon_dom_disconnect,
	.nxdom_defunct =        nx_mon_dom_defunct,
	.nxdom_defunct_finalize = nx_mon_dom_defunct_finalize,
};

static struct kern_nexus_domain_provider nx_monitor_prov_s = {
	.nxdom_prov_name =              NEXUS_PROVIDER_MONITOR,
	.nxdom_prov_flags =             NXDOMPROVF_DEFAULT,
	.nxdom_prov_cb = {
		.dp_cb_init =           nx_mon_prov_init,
		.dp_cb_fini =           nx_mon_prov_fini,
		.dp_cb_params =         nx_mon_prov_params,
		.dp_cb_mem_new =        nx_mon_prov_mem_new,
		.dp_cb_config =         NULL,
		.dp_cb_nx_ctor =        NULL,
		.dp_cb_nx_dtor =        NULL,
		.dp_cb_nx_mem_info =    NULL,           /* not supported */
		.dp_cb_nx_mib_get =     NULL,
	},
};

static SKMEM_TYPE_DEFINE(na_mon_zone, struct nexus_monitor_adapter);

#define SKMEM_TAG_MONITORS      "com.apple.skywalk.monitors"
static SKMEM_TAG_DEFINE(skmem_tag_monitors, SKMEM_TAG_MONITORS);

static void
nx_mon_dom_init(struct nxdom *nxdom)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(!(nxdom->nxdom_flags & NEXUSDOMF_INITIALIZED));

	(void) nxdom_prov_add(nxdom, &nx_monitor_prov_s);
}

static void
nx_mon_dom_terminate(struct nxdom *nxdom)
{
	struct kern_nexus_domain_provider *nxdom_prov, *tnxdp;

	STAILQ_FOREACH_SAFE(nxdom_prov, &nxdom->nxdom_prov_head,
	    nxdom_prov_link, tnxdp) {
		(void) nxdom_prov_del(nxdom_prov);
	}
}

static void
nx_mon_dom_fini(struct nxdom *nxdom)
{
#pragma unused(nxdom)
}

__attribute__((noreturn))
static int
nx_mon_dom_bind_port(struct kern_nexus *nx, nexus_port_t *nx_port,
    struct nxbind *nxb, void *info)
{
#pragma unused(nx, nx_port, nxb, info)
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static int
nx_mon_dom_unbind_port(struct kern_nexus *nx, nexus_port_t nx_port)
{
#pragma unused(nx, nx_port)
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static int
nx_mon_dom_connect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
#pragma unused(nxdom_prov, nx, ch, chr, ch0, nxb, p)
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

__attribute__((noreturn))
static void
nx_mon_dom_disconnect(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nxdom_prov, nx, ch)
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

static void
nx_mon_dom_defunct(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, struct proc *p)
{
#pragma unused(nxdom_prov, nx, ch, p)
}

static void
nx_mon_dom_defunct_finalize(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct kern_channel *ch, boolean_t locked)
{
#pragma unused(nxdom_prov, nx, ch, locked)
}

static int
nx_mon_prov_init(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("initializing %s", nxdom_prov->nxdom_prov_name);
	return 0;
}

static int
nx_mon_prov_params_adjust(const struct kern_nexus_domain_provider *nxdom_prov,
    const struct nxprov_params *nxp, struct nxprov_adjusted_params *adj)
{
#pragma unused(nxdom_prov, nxp, adj)

	return 0;
}

static int
nx_mon_prov_params(struct kern_nexus_domain_provider *nxdom_prov,
    const uint32_t req, const struct nxprov_params *nxp0,
    struct nxprov_params *nxp, struct skmem_region_params srp[SKMEM_REGIONS],
    uint32_t pp_region_config_flags)
{
	struct nxdom *nxdom = nxdom_prov->nxdom_prov_dom;

	return nxprov_params_adjust(nxdom_prov, req, nxp0, nxp, srp,
	           nxdom, nxdom, nxdom, pp_region_config_flags,
	           nx_mon_prov_params_adjust);
}

static int
nx_mon_prov_mem_new(struct kern_nexus_domain_provider *nxdom_prov,
    struct kern_nexus *nx, struct nexus_adapter *na)
{
#pragma unused(nxdom_prov)
	int err = 0;

	SK_DF(SK_VERB_MONITOR,
	    "nx 0x%llx (\"%s\":\"%s\") na \"%s\" (0x%llx)", SK_KVA(nx),
	    NX_DOM(nx)->nxdom_name, nxdom_prov->nxdom_prov_name, na->na_name,
	    SK_KVA(na));

	ASSERT(na->na_arena == NULL);
	ASSERT(NX_USER_CHANNEL_PROV(nx));
	/*
	 * The underlying nexus adapter uses the same memory allocator
	 * as the monitored adapter; don't store the pp in the nexus.
	 *
	 * This means that clients calling kern_nexus_get_pbufpool()
	 * will get NULL, but this is fine since we don't expose the
	 * monitor to external kernel clients.
	 */
	na->na_arena = skmem_arena_create_for_nexus(na,
	    NX_PROV(nx)->nxprov_region_params, NULL, NULL, 0, NULL, &err);
	ASSERT(na->na_arena != NULL || err != 0);

	return err;
}

static void
nx_mon_prov_fini(struct kern_nexus_domain_provider *nxdom_prov)
{
#pragma unused(nxdom_prov)
	SK_D("destroying %s", nxdom_prov->nxdom_prov_name);
}

static struct nexus_monitor_adapter *
na_mon_alloc(zalloc_flags_t how)
{
	struct nexus_monitor_adapter *mna;

	_CASSERT(offsetof(struct nexus_monitor_adapter, mna_up) == 0);

	mna = zalloc_flags(na_mon_zone, how | Z_ZERO);
	if (mna) {
		mna->mna_up.na_type = NA_MONITOR;
		mna->mna_up.na_free = na_mon_free;
	}
	return mna;
}

static void
na_mon_free(struct nexus_adapter *na)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;

	ASSERT(mna->mna_up.na_refcount == 0);
	SK_DF(SK_VERB_MEM, "mna 0x%llx FREE", SK_KVA(mna));
	bzero(mna, sizeof(*mna));
	zfree(na_mon_zone, mna);
}

/*
 * Functions common to both kind of monitors.
 */

/*
 * nm_sync callback for the monitor's own tx rings.
 * This makes no sense and always returns error
 */
static int
nx_mon_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(kring, p, flags)
	SK_DF(SK_VERB_MONITOR | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);
	return EIO;
}

/*
 * nm_sync callback for the monitor's own rx rings.
 * Note that the lock in nx_mon_zcopy_parent_sync only protects
 * writers among themselves. Synchronization between writers
 * (i.e., nx_mon_zcopy_parent_txsync and nx_mon_zcopy_parent_rxsync)
 * and readers (i.e., nx_mon_zcopy_parent_rxsync) relies on memory barriers.
 */
static int
nx_mon_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	SK_DF(SK_VERB_MONITOR | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);
	kring->ckr_khead = kring->ckr_rhead;
	membar_sync();
	return 0;
}

/*
 * na_krings_create callbacks for monitors.
 * We could use the default netmap_hw_krings_zmon, but
 * we don't need the nx_mbq.
 */
static int
nx_mon_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	ASSERT(na->na_type == NA_MONITOR);
	return na_rings_mem_setup(na, FALSE, ch);
}

/* na_krings_delete callback for monitors */
static void
nx_mon_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_MONITOR);
	na_rings_mem_teardown(na, ch, defunct);
}

__attribute__((always_inline))
static inline uint32_t
nx_mon_txrx2chmode(enum txrx t)
{
	return t == NR_RX ? CHMODE_MONITOR_RX : CHMODE_MONITOR_TX;
}

/* allocate the monitors array in the monitored kring */
static int
nx_mon_kr_alloc(struct __kern_channel_ring *kring, uint32_t n)
{
	struct __kern_channel_ring **nm;

	if (n <= kring->ckr_max_monitors) {
		/* we already have more entries that requested */
		return 0;
	}

	nm = sk_realloc_type_array(struct __kern_channel_ring *,
	    kring->ckr_max_monitors, n, kring->ckr_monitors,
	    Z_WAITOK, skmem_tag_monitors);
	if (nm == NULL) {
		return ENOMEM;
	}

	kring->ckr_monitors = nm;
	kring->ckr_max_monitors = n;

	return 0;
}

/* deallocate the parent array in the parent adapter */
static void
nx_mon_kr_dealloc(struct __kern_channel_ring *kring)
{
	if (kring->ckr_monitors != NULL) {
		if (kring->ckr_n_monitors > 0) {
			SK_ERR("freeing not empty monitor array for \"%s\" "
			    "(%u dangling monitors)!", kring->ckr_name,
			    kring->ckr_n_monitors);
		}
		sk_free_type_array(struct __kern_channel_ring *,
		    kring->ckr_max_monitors, kring->ckr_monitors);
		kring->ckr_monitors = NULL;
		kring->ckr_max_monitors = 0;
		kring->ckr_n_monitors = 0;
	}
}

static int
nx_mon_na_krings_locks(struct nexus_adapter *na,
    uint32_t qfirst[NR_TXRX], uint32_t qlast[NR_TXRX])
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;
	enum txrx t;
	int err = 0;

	for_rx_tx(t) {
		uint32_t i;

		if (!(mna->mna_mode & nx_mon_txrx2chmode(t))) {
			continue;
		}

		qfirst[t] = qlast[t] = mna->mna_first[t];

		/* synchronize with concurrently running nm_sync()s */
		for (i = mna->mna_first[t]; i < mna->mna_last[t]; i++) {
			struct __kern_channel_ring *kring;

			/* the parent adapter's kring */
			kring = &NAKR(pna, t)[i];
			kr_stop(kring, KR_LOCKED);
			qlast[t] = i + 1;
		}
		if (err != 0) {
			break;
		}
	}

	return err;
}

static void
nx_mon_na_krings_unlock(struct nexus_adapter *na,
    const uint32_t qfirst[NR_TXRX], const uint32_t qlast[NR_TXRX])
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;
	enum txrx t;

	for_rx_tx(t) {
		uint32_t i;

		if (!(mna->mna_mode & nx_mon_txrx2chmode(t))) {
			continue;
		}

		/* synchronize with concurrently running nm_sync()s */
		for (i = qfirst[t]; i < qlast[t]; i++) {
			struct __kern_channel_ring *kring;

			/* the parent adapter's kring */
			kring = &NAKR(pna, t)[i];
			kr_start(kring);
		}
	}
}

static int
nx_mon_enable(struct nexus_adapter *na, boolean_t zcopy)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;
	struct skmem_arena_nexus *na_arena = skmem_arena_nexus(pna->na_arena);
	uint32_t qfirst[NR_TXRX], qlast[NR_TXRX];
	enum txrx t;
	int err = 0;
	uint32_t i;

	ASSERT(!(na->na_flags & NAF_ACTIVE));

	bzero(&qfirst, sizeof(qfirst));
	bzero(&qlast, sizeof(qlast));

	/*
	 * Acquire the target kring(s).  q{first,last}0 represent the
	 * target ring set.  q{first,last} represent the ones that have
	 * been successfully acquired.  In the event the acquisition
	 * fails, we must release any previously-acquired rings.
	 */
	if ((err = nx_mon_na_krings_locks(na, qfirst, qlast)) != 0) {
		goto unlock;
	}

	ASSERT(na_arena->arn_rx_pp == na_arena->arn_tx_pp);
	if (na_arena->arn_rx_pp->pp_max_frags > 1) {
		VERIFY(na_arena->arn_rx_pp->pp_md_type == NEXUS_META_TYPE_PACKET);
		mna->mna_pkt_copy_from_pkt = pkt_copy_multi_buflet_from_pkt;
	} else {
		if (na_arena->arn_rx_pp->pp_md_type == NEXUS_META_TYPE_PACKET) {
			mna->mna_pkt_copy_from_pkt = pkt_copy_from_pkt;
		} else {
			mna->mna_pkt_copy_from_pkt = nx_mon_quantum_copy_64x;
		}
	}

	for_rx_tx(t) {
		if (!(mna->mna_mode & nx_mon_txrx2chmode(t))) {
			continue;
		}

		for (i = qfirst[t]; i < qlast[t]; i++) {
			struct __kern_channel_ring *kring, *mkring;

			/* the parent adapter's kring */
			kring = &NAKR(pna, t)[i];
			mkring = &na->na_rx_rings[i];
			err = nx_mon_add(mkring, kring, zcopy);
			if (err != 0) {
				break;
			}
		}
		if (err != 0) {
			break;
		}
	}

	if (err == 0) {
		atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
		goto unlock;
	}

	for_rx_tx(t) {
		if (!(mna->mna_mode & nx_mon_txrx2chmode(t))) {
			continue;
		}

		for (i = qfirst[t]; i < qlast[t]; i++) {
			struct __kern_channel_ring *kring, *mkring;

			/* the parent adapter's kring */
			kring = &NAKR(pna, t)[i];
			mkring = &na->na_rx_rings[i];
			nx_mon_del(mkring, kring, FALSE);
		}
	}
	ASSERT(!(na->na_flags & NAF_ACTIVE));

unlock:
	nx_mon_na_krings_unlock(na, qfirst, qlast);

	SK_DF(err ? SK_VERB_ERROR : SK_VERB_MONITOR,
	    "%s (0x%llx): mode 0x%x txrings[%u,%u], rxrings[%u,%u] err %d",
	    na->na_name, SK_KVA(na), mna->mna_mode, qfirst[NR_TX], qlast[NR_TX],
	    qfirst[NR_RX], qlast[NR_RX], err);

	return err;
}

static void
nx_mon_disable(struct nexus_adapter *na)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;
	uint32_t qfirst[NR_TXRX], qlast[NR_TXRX];
	enum txrx t;
	int err;
	uint32_t i;

	ASSERT(na->na_flags & NAF_ACTIVE);

	bzero(&qfirst, sizeof(qfirst));
	bzero(&qlast, sizeof(qlast));

	/* blocking kring(s) acquisition; must not fail */
	err = nx_mon_na_krings_locks(na, qfirst, qlast);
	ASSERT(err == 0);
	mna->mna_pkt_copy_from_pkt = NULL;
	for_rx_tx(t) {
		if (!(mna->mna_mode & nx_mon_txrx2chmode(t))) {
			continue;
		}

		for (i = qfirst[t]; i < qlast[t]; i++) {
			struct __kern_channel_ring *kring, *mkring;

			kring = &NAKR(pna, t)[i];
			mkring = &na->na_rx_rings[i];
			nx_mon_del(mkring, kring, FALSE);
		}
	}
	atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);

	nx_mon_na_krings_unlock(na, qfirst, qlast);
}

/*
 * Add the monitor mkring to the list of monitors of kring.
 * If this is the first monitor, intercept the callbacks
 */
static int
nx_mon_add(struct __kern_channel_ring *mkring,
    struct __kern_channel_ring *kring, boolean_t zcopy)
{
	int error;

	/* make sure the monitor array exists and is big enough */
	error = nx_mon_kr_alloc(kring, kring->ckr_n_monitors + 1);
	if (error != 0) {
		return error;
	}

	kring->ckr_monitors[kring->ckr_n_monitors] = mkring;
	mkring->ckr_mon_pos = kring->ckr_n_monitors;
	kring->ckr_n_monitors++;
	if (kring->ckr_n_monitors == 1) {
		/* this is the first monitor, intercept callbacks */
		SK_DF(SK_VERB_MONITOR,
		    "mkr \"%s\" (0x%llx) krflags 0x%b intercept callbacks "
		    "on kr \"%s\" (0x%llx) krflags 0x%b", mkring->ckr_name,
		    SK_KVA(mkring), mkring->ckr_flags, CKRF_BITS,
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS);
		kring->ckr_mon_sync = kring->ckr_na_sync;
		/*
		 * zcopy monitors do not override nm_notify(), but
		 * we save the original one regardless, so that
		 * nx_mon_del() does not need to know the
		 * monitor type
		 */
		kring->ckr_mon_notify = kring->ckr_na_notify;
		if (kring->ckr_tx == NR_TX) {
			kring->ckr_na_sync =
			    (zcopy ? nx_mon_zcopy_parent_txsync :
			    nx_mon_parent_txsync);
		} else {
			kring->ckr_na_sync =
			    (zcopy ? nx_mon_zcopy_parent_rxsync :
			    nx_mon_parent_rxsync);
			if (!zcopy) {
				/* also intercept notify */
				kring->ckr_na_notify = nx_mon_parent_notify;
				kring->ckr_mon_tail = kring->ckr_ktail;
			}
		}
	} else {
		SK_DF(SK_VERB_MONITOR,
		    "mkr \"%s\" (0x%llx) krflags 0x%b already intercept "
		    "callbacks on kr \"%s\" (0x%llx) krflags 0x%b, "
		    "%u monitors", mkring->ckr_name, SK_KVA(mkring),
		    mkring->ckr_flags, CKRF_BITS, kring->ckr_name,
		    SK_KVA(kring), kring->ckr_flags, CKRF_BITS,
		    kring->ckr_n_monitors);
	}
	return 0;
}

/*
 * Remove the monitor mkring from the list of monitors of kring.
 * If this is the last monitor, restore the original callbacks
 */
static void
nx_mon_del(struct __kern_channel_ring *mkring,
    struct __kern_channel_ring *kring, boolean_t all)
{
	ASSERT(kring->ckr_n_monitors != 0);
	if (all) {
		kring->ckr_n_monitors = 0;
	} else {
		kring->ckr_n_monitors--;
		if (mkring->ckr_mon_pos != kring->ckr_n_monitors) {
			kring->ckr_monitors[mkring->ckr_mon_pos] =
			    kring->ckr_monitors[kring->ckr_n_monitors];
			kring->ckr_monitors[mkring->ckr_mon_pos]->ckr_mon_pos =
			    mkring->ckr_mon_pos;
		}
		kring->ckr_monitors[kring->ckr_n_monitors] = NULL;
	}
	if (kring->ckr_n_monitors == 0) {
		/*
		 * This was the last monitor, restore callbacks
		 * and delete monitor array.
		 */
		SK_DF(SK_VERB_MONITOR,
		    "restoring sync callback on kr \"%s\" (0x%llx) "
		    "krflags 0x%b", kring->ckr_name, SK_KVA(kring),
		    kring->ckr_flags, CKRF_BITS);
		kring->ckr_na_sync = kring->ckr_mon_sync;
		kring->ckr_mon_sync = NULL;
		if (kring->ckr_tx == NR_RX) {
			SK_DF(SK_VERB_MONITOR,
			    "restoring notify callback on kr \"%s\" (0x%llx) "
			    "krflags 0x%b", kring->ckr_name, SK_KVA(kring),
			    kring->ckr_flags, CKRF_BITS);
			kring->ckr_na_notify = kring->ckr_mon_notify;
			kring->ckr_mon_notify = NULL;
		}
		nx_mon_kr_dealloc(kring);
	} else {
		SK_DF(SK_VERB_MONITOR,
		    "NOT restoring callbacks on kr \"%s\" (0x%llx) "
		    "krflags 0x%b, %u monitors left", kring->ckr_name,
		    SK_KVA(kring), kring->ckr_flags, CKRF_BITS,
		    kring->ckr_n_monitors);
	}
}

/*
 * This is called when the monitored adapter leaves skywalk mode (see
 * na_unbind_channel).  We need to notify the monitors that the monitored
 * rings are gone.  We do this by setting their mna->mna_pna to NULL.
 * Note that the rings must be stopped when this happens, so no monitor
 * ring callback can be active.
 */
void
nx_mon_stop(struct nexus_adapter *na)
{
	enum txrx t;

	SK_LOCK_ASSERT_HELD();

	/* skip if this adapter has no allocated rings */
	if (na->na_tx_rings == NULL) {
		return;
	}

	na_disable_all_rings(na);

	for_rx_tx(t) {
		uint32_t i;

		for (i = 0; i < na_get_nrings(na, t); i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];
			uint32_t j;

			for (j = 0; j < kring->ckr_n_monitors; j++) {
				struct __kern_channel_ring *mkring =
				    kring->ckr_monitors[j];
				struct nexus_monitor_adapter *mna =
				    (struct nexus_monitor_adapter *)
				    KRNA(mkring);

				/* forget about this adapter */
				if (mna->mna_pna != NULL) {
					ASSERT(na == mna->mna_pna);
					(void) na_release_locked(mna->mna_pna);
					mna->mna_pna = NULL;
				}
			}

			/*
			 * Remove all monitors and restore callbacks;
			 * this is important for nexus adapters that
			 * are linked to one another, e.g. pipe, since
			 * the callback changes on one adapter affects
			 * its peer during sync times.
			 */
			if (kring->ckr_n_monitors > 0) {
				nx_mon_del(NULL, kring, TRUE);
			}

			ASSERT(kring->ckr_monitors == NULL);
			ASSERT(kring->ckr_max_monitors == 0);
			ASSERT(kring->ckr_n_monitors == 0);
		}
	}

	na_enable_all_rings(na);
}

/*
 * Common functions for the na_activate() callbacks of both kind of
 * monitors.
 */
static int
nx_mon_na_activate_common(struct nexus_adapter *na, na_activate_mode_t mode,
    boolean_t zcopy)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;
	int err = 0;

	ASSERT(na->na_type == NA_MONITOR);

	SK_DF(SK_VERB_MONITOR, "na \"%s\" (0x%llx) %s zcopy %u", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode), zcopy);

	switch (mode) {
	case NA_ACTIVATE_MODE_ON:
		if (pna == NULL) {
			/* parent left skywalk mode, fatal */
			SK_ERR("%s: internal error", na->na_name);
			err = ENXIO;
		} else {
			err = nx_mon_enable(na, zcopy);
		}
		break;

	case NA_ACTIVATE_MODE_DEFUNCT:
		break;

	case NA_ACTIVATE_MODE_OFF:
		if (pna == NULL) {
			SK_DF(SK_VERB_MONITOR, "%s: parent left skywalk mode, "
			    "nothing to restore", na->na_name);
		} else {
			nx_mon_disable(na);
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return err;
}

/*
 * Functions specific for zero-copy monitors.
 */

/*
 * Common function for both zero-copy tx and rx nm_sync()
 * callbacks
 */
static int
nx_mon_zcopy_parent_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags, enum txrx tx)
{
	struct __kern_channel_ring *mkring = kring->ckr_monitors[0];
	int rel_slots, free_slots, busy, sent = 0;
	slot_idx_t beg, end, i;
	const slot_idx_t lim = kring->ckr_lim;
	const slot_idx_t mlim;
	int error = 0;

	if (mkring == NULL) {
		SK_RD(5, "NULL monitor on kr \"%s\" (0x%llx) krflags 0x%b",
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS);
		return 0;
	}

	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(!KR_KERNEL_ONLY(mkring));

	/* deconst */
	*(slot_idx_t *)(uintptr_t)&mlim = mkring->ckr_lim;

	/* get the relased slots (rel_slots) */
	if (tx == NR_TX) {
		beg = kring->ckr_ktail;
		error = kring->ckr_mon_sync(kring, p, NA_SYNCF_MONITOR | flags);
		if (error) {
			return error;
		}
		end = kring->ckr_ktail;
	} else { /* NR_RX */
		beg = kring->ckr_khead;
		end = kring->ckr_rhead;
	}

	rel_slots = end - beg;
	if (rel_slots < 0) {
		rel_slots += kring->ckr_num_slots;
	}

	if (!rel_slots) {
		/*
		 * No released slots, but we still need
		 * to call rxsync if this is a rx ring
		 */
		goto out_rxsync;
	}

	/*
	 * We need to lock the monitor receive ring, since it
	 * is the target of bot tx and rx traffic from the monitored
	 * adapter
	 */
	KR_LOCK(mkring);
	/* get the free slots available on the monitor ring */
	i = mkring->ckr_ktail;
	busy = i - mkring->ckr_khead;
	if (busy < 0) {
		busy += mkring->ckr_num_slots;
	}
	free_slots = mlim - busy;

	if (!free_slots) {
		goto out;
	}

	/* swap min(free_slots, rel_slots) slots */
	if (free_slots < rel_slots) {
		beg += (rel_slots - free_slots);
		if (beg >= kring->ckr_num_slots) {
			beg -= kring->ckr_num_slots;
		}
		rel_slots = free_slots;
	}

	sent = rel_slots;
	for (; rel_slots; rel_slots--) {
		/*
		 * Swap the slots.
		 *
		 * XXX: adi@apple.com -- this bypasses the slot attach/detach
		 * interface, and needs to be changed when monitor adopts the
		 * packet APIs.  SD_SWAP() will perform a block copy of the
		 * swap, and will readjust the kernel slot descriptor's sd_user
		 * accordingly.
		 */
		SD_SWAP(KR_KSD(mkring, i), KR_USD(mkring, i),
		    KR_KSD(kring, beg), KR_USD(kring, beg));

		SK_RD(5, "beg %u buf_idx %u", beg,
		    METADATA_IDX(KR_KSD(kring, beg)->sd_qum));

		beg = SLOT_NEXT(beg, lim);
		i = SLOT_NEXT(i, mlim);
	}
	membar_sync();
	mkring->ckr_ktail = i;

out:
	KR_UNLOCK(mkring);

	if (sent) {
		/* notify the new frames to the monitor */
		(void) mkring->ckr_na_notify(mkring, p, 0);
	}

out_rxsync:
	if (tx == NR_RX) {
		error = kring->ckr_mon_sync(kring, p, NA_SYNCF_MONITOR | flags);
	}

	return error;
}

/*
 * Callback used to replace the ckr_na_sync callback in the monitored tx rings.
 */
static int
nx_mon_zcopy_parent_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	SK_DF(SK_VERB_MONITOR,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b flags 0x%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, flags);
	return nx_mon_zcopy_parent_sync(kring, p, flags, NR_TX);
}

/* callback used to replace the nm_sync callback in the monitored rx rings */
static int
nx_mon_zcopy_parent_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	SK_DF(SK_VERB_MONITOR,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b flags 0x%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, flags);
	return nx_mon_zcopy_parent_sync(kring, p, flags, NR_RX);
}

static int
nx_mon_zcopy_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	return nx_mon_na_activate_common(na, mode, TRUE /* zcopy */);
}

/* na_dtor callback for monitors */
static void
nx_mon_zcopy_na_dtor(struct nexus_adapter *na)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_MONITOR);

	if (pna != NULL) {
		(void) na_release_locked(pna);
		mna->mna_pna = NULL;
	}
}

/*
 * Functions specific for copy monitors.
 */

static void
nx_mon_parent_sync(struct __kern_channel_ring *kring, struct proc *p,
    slot_idx_t first_new, int new_slots)
{
	nexus_meta_type_t md_type = KRNA(kring)->na_md_type;
	uint32_t j;

	for (j = 0; j < kring->ckr_n_monitors; j++) {
		struct __kern_channel_ring *mkring = kring->ckr_monitors[j];
		slot_idx_t i, mlim, beg;
		int free_slots, busy, sent = 0, m;
		const slot_idx_t lim = kring->ckr_lim;
		struct nexus_adapter *dst_na = KRNA(mkring);
		struct nexus_monitor_adapter *mna =
		    (struct nexus_monitor_adapter *)dst_na;
		uint32_t max_len = mkring->ckr_pp->pp_max_frags *
		    PP_BUF_SIZE_DEF(mkring->ckr_pp);

		/*
		 * src and dst adapters must share the same nexus;
		 * this test is done in nx_monitor_na_find().  This
		 * covers both buffer and metadata sizes.
		 */

		mlim = mkring->ckr_lim;

		/*
		 * We need to lock the monitor receive ring, since it
		 * is the target of both tx and rx traffics from the
		 * monitored adapter.
		 */
		KR_LOCK(mkring);
		/* get the free slots available on the monitor ring */
		i = mkring->ckr_ktail;
		busy = i - mkring->ckr_khead;
		if (busy < 0) {
			busy += mkring->ckr_num_slots;
		}
		free_slots = mlim - busy;

		if (!free_slots) {
			goto out;
		}

		/* copy min(free_slots, new_slots) slots */
		m = new_slots;
		beg = first_new;
		if (free_slots < m) {
			beg += (m - free_slots);
			if (beg >= kring->ckr_num_slots) {
				beg -= kring->ckr_num_slots;
			}
			m = free_slots;
		}

		ASSERT(KRNA(mkring)->na_md_type == md_type);

		for (; m; m--) {
			struct __kern_slot_desc *src_sd = KR_KSD(kring, beg);
			struct __kern_slot_desc *dst_sd = KR_KSD(mkring, i);
			struct __kern_packet *spkt, *dpkt;
			kern_packet_t sph, dph;
			uint32_t copy_len;

			if (!KSD_VALID_METADATA(src_sd)) {
				goto skip;
			}

			/* retreive packet handles from slot */
			spkt = src_sd->sd_pkt;
			sph = SK_PTR_ENCODE(spkt, METADATA_TYPE(spkt),
			    METADATA_SUBTYPE(spkt));
			dpkt = dst_sd->sd_pkt;
			dph = SK_PTR_ENCODE(dpkt, METADATA_TYPE(dpkt),
			    METADATA_SUBTYPE(dpkt));

			ASSERT(METADATA_TYPE(spkt) == METADATA_TYPE(dpkt));

			ASSERT(spkt->pkt_qum.qum_len <= (UINT32_MAX - 63));
			copy_len = spkt->pkt_qum.qum_len;

			/* round to a multiple of 64 */
			copy_len = (copy_len + 63) & ~63;

			if (__improbable(copy_len > max_len)) {
				SK_RD(5, "kr \"%s\" -> mkr \"%s\": "
				    "truncating %u to %u",
				    kring->ckr_name, mkring->ckr_name,
				    (uint32_t)copy_len, max_len);
				copy_len = max_len;
			}

			/* copy buffers */
			mna->mna_pkt_copy_from_pkt(kring->ckr_tx, dph, 0, sph,
			    0, copy_len, FALSE, 0, 0, FALSE);

			/* copy the associated meta data */
			_QUM_COPY(&(spkt)->pkt_qum, &(dpkt)->pkt_qum);
			if (md_type == NEXUS_META_TYPE_PACKET) {
				_PKT_COPY(spkt, dpkt);
				ASSERT(dpkt->pkt_mbuf == NULL);
			}

			ASSERT(!(dpkt->pkt_qum.qum_qflags & QUM_F_KERNEL_ONLY) ||
			    PP_KERNEL_ONLY(dpkt->pkt_qum.qum_pp));

			sent++;
			i = SLOT_NEXT(i, mlim);
skip:
			beg = SLOT_NEXT(beg, lim);
		}
		membar_sync();
		mkring->ckr_ktail = i;
out:
		KR_UNLOCK(mkring);

		if (sent) {
			/* notify the new frames to the monitor */
			(void) mkring->ckr_na_notify(mkring, p, 0);
		}
	}
}

/* callback used to replace the nm_sync callback in the monitored tx rings */
static int
nx_mon_parent_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	slot_idx_t first_new;
	int new_slots;
	nexus_type_t nx_type =
	    kring->ckr_na->na_nxdom_prov->nxdom_prov_dom->nxdom_type;

	/*
	 * For user pipe nexus, txsync can also be initated from RX process
	 * context, hence user pipe tx ring should be accessed holding
	 * ckr_qlock.
	 */
	if (nx_type == NEXUS_TYPE_USER_PIPE) {
		KR_LOCK(kring);
	}

	/* get the new slots */
	first_new = kring->ckr_khead;
	new_slots = kring->ckr_rhead - first_new;
	if (new_slots < 0) {
		new_slots += kring->ckr_num_slots;
	}
	if (new_slots) {
		nx_mon_parent_sync(kring, p, first_new, new_slots);
	}

	if (nx_type == NEXUS_TYPE_USER_PIPE) {
		KR_UNLOCK(kring);
	}

	return kring->ckr_mon_sync(kring, p, NA_SYNCF_MONITOR | flags);
}

/* callback used to replace the nm_sync callback in the monitored rx rings */
static int
nx_mon_parent_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	slot_idx_t first_new;
	int new_slots, error;

	/* get the new slots */
	error =  kring->ckr_mon_sync(kring, p, NA_SYNCF_MONITOR | flags);
	if (error) {
		return error;
	}
	first_new = kring->ckr_mon_tail;
	new_slots = kring->ckr_ktail - first_new;
	if (new_slots < 0) {
		new_slots += kring->ckr_num_slots;
	}
	if (new_slots) {
		nx_mon_parent_sync(kring, p, first_new, new_slots);
	}
	kring->ckr_mon_tail = kring->ckr_ktail;
	return 0;
}

/*
 * Callback used to replace the nm_notify() callback in the monitored rx rings
 */
static int
nx_mon_parent_notify(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	int err = 0;
	sk_protect_t protect = NULL;

	SK_DF(SK_VERB_MONITOR | SK_VERB_NOTIFY |
	    ((kring->ckr_tx == NR_TX) ? SK_VERB_TX : SK_VERB_RX),
	    "kr \"%s\" (0x%llx) krflags 0x%b flags 0x%x", kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, flags);
	/*
	 * ?xsync callbacks have tryget called by their callers,
	 * but here we have to call it by ourself.  If we can't
	 * acquire the exclusive sync right, skip the sync.
	 */
	if ((err = kr_enter(kring, FALSE)) == 0) {
		protect = sk_sync_protect();
		nx_mon_parent_rxsync(kring, p, NA_SYNCF_FORCE_READ);
		sk_sync_unprotect(protect);
		kr_exit(kring);
	}
	/* in all cases (even error), we must invoke notify */
	kring->ckr_mon_notify(kring, p, (NA_NOTEF_MONITOR | flags));
	return err;
}

static int
nx_mon_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	return nx_mon_na_activate_common(na, mode, FALSE /* no zcopy */);
}

static void
nx_mon_na_dtor(struct nexus_adapter *na)
{
	struct nexus_monitor_adapter *mna = (struct nexus_monitor_adapter *)na;
	struct nexus_adapter *pna = mna->mna_pna;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_MONITOR);

	if (pna != NULL) {
		(void) na_release_locked(pna);
		mna->mna_pna = NULL;
	}
}

/* check if chr is a request for a monitor adapter that we can satisfy */
int
nx_monitor_na_find(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct kern_channel *ch0, struct nxbind *nxb,
    struct proc *p, struct nexus_adapter **na, boolean_t create)
{
#pragma unused(ch)
	boolean_t zcopy = !!(chr->cr_mode & CHMODE_MONITOR_NO_COPY);
	struct nexus_adapter *pna = NULL; /* parent adapter */
	struct nexus_monitor_adapter *mna = NULL;
	char monsuff[10] = "";
	struct chreq pchr;
	uint32_t i;
	int error;
	enum txrx t;

	SK_LOCK_ASSERT_HELD();
	*na = NULL;

#if SK_LOG
	uuid_string_t uuidstr;
	SK_D("name \"%s\" spec_uuid \"%s\" port %d mode 0x%b pipe_id %u "
	    "ring_id %d ring_set %u ep_type %u:%u ch0 0x%llx create %u%s",
	    chr->cr_name, sk_uuid_unparse(chr->cr_spec_uuid, uuidstr),
	    (int)chr->cr_port, chr->cr_mode, CHMODE_BITS,
	    chr->cr_pipe_id, (int)chr->cr_ring_id, chr->cr_ring_set,
	    chr->cr_real_endpoint, chr->cr_endpoint, SK_KVA(ch0), create,
	    !(chr->cr_mode & CHMODE_MONITOR) ? " (skipped)" : "");
#endif /* SK_LOG */

	if (!(chr->cr_mode & CHMODE_MONITOR)) {
		return 0;
	}

	/* XXX: Don't allow user packet pool mode in monitor for now */
	if (chr->cr_mode & CHMODE_USER_PACKET_POOL) {
		SK_ERR("User Packet pool mode not supported for monitor");
		return ENOTSUP;
	}

	mna = na_mon_alloc(Z_WAITOK);

	ASSERT(mna->mna_up.na_type == NA_MONITOR);
	ASSERT(mna->mna_up.na_free == na_mon_free);

	/* override the ring set since we're monitoring */
	chr->cr_ring_set = RING_SET_ALL;

	if (ch0 != NULL) {
		/*
		 * We've been given the owning channel from ch_open();
		 * use this as shortcut since otherwise we'd have to
		 * find it ourselves.
		 */
#if (DEBUG || DEVELOPMENT)
		ASSERT(!(ch0->ch_info->cinfo_ch_mode & CHMODE_MONITOR));
		ASSERT(ch0->ch_info->cinfo_nx_port == chr->cr_port);
#endif /* DEBUG || DEVELOPMENT */
		pna = ch0->ch_na;
		na_retain_locked(pna);
	} else {
		/*
		 * First, try to find the adapter that we want to monitor
		 * We use the same chr, after we have turned off the monitor
		 * flags.  In this way we can potentially monitor everything
		 * skywalk understands, except other monitors.
		 */
		memcpy(&pchr, chr, sizeof(pchr));
		pchr.cr_mode &= ~CHMODE_MONITOR;
		error = na_find(ch, nx, &pchr, ch0, nxb, p, &pna, create);
		if (error != 0) {
			SK_ERR("parent lookup failed: %d", error);
			return error;
		}
	}
	ASSERT(pna != NULL);
	SK_DF(SK_VERB_MONITOR,
	    "found parent: \"%s\" (0x%llx)", pna->na_name, SK_KVA(pna));

	if (!NA_IS_ACTIVE(pna)) {
		/* parent not in skywalk mode */
		/*
		 * XXX we can wait for the parent to enter skywalk mode,
		 * by intercepting its na_activate() callback (2014-03-16)
		 */
		SK_ERR("parent \"%s\" (0x%llx) not in skywalk mode",
		    pna->na_name, SK_KVA(pna));
		error = ENXIO;
		goto put_out;
	} else if (zcopy && NA_KERNEL_ONLY(pna)) {
		/*
		 * Zero-copy mode requires the parent adapter to be
		 * created in a non-kernel-only mode.
		 */
		SK_ERR("parent \"%s\" (0x%llx) is in kernel-only mode",
		    pna->na_name, SK_KVA(pna));
		error = ENODEV;
		goto put_out;
	}

	/* grab all the rings we need in the parent */
	mna->mna_pna = pna;
	error = na_interp_ringid(pna, chr->cr_ring_id, chr->cr_ring_set,
	    mna->mna_first, mna->mna_last);
	if (error != 0) {
		SK_ERR("ring_mode %u ring_id %d error %d", chr->cr_ring_set,
		    (int)chr->cr_ring_id, error);
		goto put_out;
	}
	if (mna->mna_last[NR_TX] - mna->mna_first[NR_TX] == 1) {
		(void) snprintf(monsuff, 10, "-%u", mna->mna_first[NR_TX]);
	}
	(void) snprintf(mna->mna_up.na_name, sizeof(mna->mna_up.na_name),
	    "%s%s/%s%s%s", pna->na_name, monsuff, zcopy ? "z" : "",
	    (chr->cr_mode & CHMODE_MONITOR_TX) ? "r" : "",
	    (chr->cr_mode & CHMODE_MONITOR_RX) ? "t" : "");
	uuid_generate_random(mna->mna_up.na_uuid);

	/* these don't apply to the monitor adapter */
	*(nexus_stats_type_t *)(uintptr_t)&mna->mna_up.na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;
	*(uint32_t *)(uintptr_t)&mna->mna_up.na_flowadv_max = 0;

	if (zcopy) {
		/*
		 * Zero copy monitors need exclusive access
		 * to the monitored rings.
		 */
		for_rx_tx(t) {
			if (!(chr->cr_mode & nx_mon_txrx2chmode(t))) {
				continue;
			}
			for (i = mna->mna_first[t];
			    i < mna->mna_last[t]; i++) {
				struct __kern_channel_ring *kring =
				    &NAKR(pna, t)[i];
				if (kring->ckr_n_monitors > 0) {
					error = EBUSY;
					SK_ERR("kr \"%s\" already monitored "
					    "by \"%s\"", kring->ckr_name,
					    kring->ckr_monitors[0]->ckr_name);
					goto put_out;
				}
			}
		}
		mna->mna_up.na_activate = nx_mon_zcopy_na_activate;
		mna->mna_up.na_dtor = nx_mon_zcopy_na_dtor;
		/*
		 * To have zero copy, we need to use the same memory allocator
		 * as the monitored port.
		 */
		mna->mna_up.na_arena = pna->na_arena;
		skmem_arena_retain((&mna->mna_up)->na_arena);
		atomic_bitset_32(&mna->mna_up.na_flags, NAF_MEM_LOANED);
	} else {
		/* normal monitors are incompatible with zero copy ones */
		for_rx_tx(t) {
			if (!(chr->cr_mode & nx_mon_txrx2chmode(t))) {
				continue;
			}
			for (i = mna->mna_first[t];
			    i < mna->mna_last[t]; i++) {
				struct __kern_channel_ring *kring =
				    &NAKR(pna, t)[i];
				if (kring->ckr_n_monitors > 0 &&
				    KRNA(kring->ckr_monitors[0])->
				    na_activate == nx_mon_zcopy_na_activate) {
					error = EBUSY;
					SK_ERR("kr \"%s\" is busy (zcopy)",
					    kring->ckr_name);
					goto put_out;
				}
			}
		}
		mna->mna_up.na_activate = nx_mon_na_activate;
		mna->mna_up.na_dtor = nx_mon_na_dtor;
		/*
		 * allocate a new (private) allocator instance using the
		 * parent nexus configuration.
		 */
		if ((error = nx_monitor_prov_s.nxdom_prov_mem_new(
			    NX_DOM_PROV(nx), nx, &mna->mna_up)) != 0) {
			ASSERT(mna->mna_up.na_arena == NULL);
			goto put_out;
		}
		ASSERT(mna->mna_up.na_arena != NULL);
		mna->mna_up.na_rxsync = nx_mon_na_rxsync;
	}
	*(nexus_meta_type_t *)(uintptr_t)&mna->mna_up.na_md_type =
	    pna->na_md_type;
	*(nexus_meta_subtype_t *)(uintptr_t)&mna->mna_up.na_md_subtype =
	    pna->na_md_subtype;

	/* a do-nothing txsync: monitors cannot be used to inject packets */
	mna->mna_up.na_txsync = nx_mon_na_txsync;
	mna->mna_up.na_rxsync = nx_mon_na_rxsync;
	mna->mna_up.na_krings_create = nx_mon_na_krings_create;
	mna->mna_up.na_krings_delete = nx_mon_na_krings_delete;

	/*
	 * We set the number of our na_rx_rings to be
	 * max(na_num_tx_rings, na_num_rx_rings) in the parent
	 */
	na_set_nrings(&mna->mna_up, NR_TX, na_get_nrings(pna, NR_TX));
	na_set_nrings(&mna->mna_up, NR_RX, na_get_nrings(pna, NR_RX));
	if (na_get_nrings(pna, NR_TX) > na_get_nrings(pna, NR_RX)) {
		na_set_nrings(&mna->mna_up, NR_RX, na_get_nrings(pna, NR_TX));
	}
	na_set_nslots(&mna->mna_up, NR_TX, na_get_nslots(pna, NR_TX));
	na_set_nslots(&mna->mna_up, NR_RX, na_get_nslots(pna, NR_RX));

	na_attach_common(&mna->mna_up, nx, &nx_monitor_prov_s);

	/* remember the traffic directions we have to monitor */
	mna->mna_mode = (chr->cr_mode & CHMODE_MONITOR);

	/* keep the reference to the parent */
	*na = &mna->mna_up;
	na_retain_locked(*na);

	/* sanity check: monitor and monitored adapters must share the nexus */
	ASSERT((*na)->na_nx == pna->na_nx);

#if SK_LOG
	SK_DF(SK_VERB_MONITOR, "created monitor adapter 0x%llx", SK_KVA(mna));
	SK_DF(SK_VERB_MONITOR, "na_name: \"%s\"", mna->mna_up.na_name);
	SK_DF(SK_VERB_MONITOR, "  UUID:         %s",
	    sk_uuid_unparse(mna->mna_up.na_uuid, uuidstr));
	SK_DF(SK_VERB_MONITOR, "  nx:           0x%llx (\"%s\":\"%s\")",
	    SK_KVA(mna->mna_up.na_nx), NX_DOM(mna->mna_up.na_nx)->nxdom_name,
	    NX_DOM_PROV(mna->mna_up.na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_MONITOR, "  flags:        0x%b",
	    mna->mna_up.na_flags, NAF_BITS);
	SK_DF(SK_VERB_MONITOR, "  rings:        tx %u rx %u",
	    na_get_nrings(&mna->mna_up, NR_TX),
	    na_get_nrings(&mna->mna_up, NR_RX));
	SK_DF(SK_VERB_MONITOR, "  slots:        tx %u rx %u",
	    na_get_nslots(&mna->mna_up, NR_TX),
	    na_get_nslots(&mna->mna_up, NR_RX));
#if CONFIG_NEXUS_USER_PIPE
	SK_DF(SK_VERB_MONITOR, "  next_pipe:    %u", mna->mna_up.na_next_pipe);
	SK_DF(SK_VERB_MONITOR, "  max_pipes:    %u", mna->mna_up.na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
	SK_DF(SK_VERB_MONITOR, "  mna_tx_rings: [%u,%u)", mna->mna_first[NR_TX],
	    mna->mna_last[NR_TX]);
	SK_DF(SK_VERB_MONITOR, "  mna_rx_rings: [%u,%u)", mna->mna_first[NR_RX],
	    mna->mna_last[NR_RX]);
	SK_DF(SK_VERB_MONITOR, "  mna_mode:     %u", mna->mna_mode);
#endif /* SK_LOG */

	return 0;

put_out:
	if (pna != NULL) {
		(void) na_release_locked(pna);
		pna = NULL;
	}
	NA_FREE(&mna->mna_up);
	return error;
}

static void
nx_mon_quantum_copy_64x(const enum txrx t, kern_packet_t dph,
    const uint16_t doff, kern_packet_t sph, const uint16_t soff,
    const uint32_t len, const boolean_t unused_arg1,
    const uint16_t unused_arg2, const uint16_t unused_arg3,
    const boolean_t unused_arg4)
{
	/* for function prototype parity with pkt_copy_from_pkt_t */
#pragma unused(unused_arg1, unused_arg2, unused_arg3, unused_arg4)
#pragma unused(t, doff, soff)
	struct __kern_quantum *dqum = SK_PTR_ADDR_KQUM(dph);
	struct __kern_quantum *squm = SK_PTR_ADDR_KQUM(sph);
	uint8_t *sbuf, *dbuf;

	ASSERT(METADATA_TYPE(squm) == NEXUS_META_TYPE_QUANTUM);
	ASSERT(METADATA_TYPE(squm) == METADATA_TYPE(dqum));
	VERIFY(IS_P2ALIGNED(len, 64));

	MD_BUFLET_ADDR(squm, sbuf);
	MD_BUFLET_ADDR(dqum, dbuf);
	VERIFY(IS_P2ALIGNED(dbuf, sizeof(uint64_t)));

	if (__probable(IS_P2ALIGNED(sbuf, sizeof(uint64_t)))) {
		sk_copy64_64x((uint64_t *)(void *)sbuf,
		    (uint64_t *)(void *)dbuf, len);
	} else {
		bcopy(sbuf, dbuf, len);
	}
	/*
	 * This copy routine only copies to/from a buflet, so the length
	 * is guaranteed be <= the size of a buflet.
	 */
	VERIFY(len <= UINT16_MAX);
	METADATA_SET_LEN(dqum, (uint16_t)len, 0);
}
