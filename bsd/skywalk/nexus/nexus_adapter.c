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
 * Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo, Giuseppe Lettieri.
 * All rights reserved.
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
#include <sys/systm.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/monitor/nx_monitor.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/upipe/nx_user_pipe.h>
#include <skywalk/nexus/kpipe/nx_kernel_pipe.h>
#include <kern/thread.h>

static int na_krings_use(struct kern_channel *);
static void na_krings_unuse(struct kern_channel *);
static void na_krings_verify(struct nexus_adapter *);
static int na_notify(struct __kern_channel_ring *, struct proc *, uint32_t);
static void na_set_ring(struct nexus_adapter *, uint32_t, enum txrx, uint32_t);
static void na_set_all_rings(struct nexus_adapter *, uint32_t);
static int na_set_ringid(struct kern_channel *, ring_set_t, ring_id_t);
static void na_unset_ringid(struct kern_channel *);
static void na_teardown(struct nexus_adapter *, struct kern_channel *,
    boolean_t);

static int na_kr_create(struct nexus_adapter *, uint32_t, boolean_t);
static void na_kr_delete(struct nexus_adapter *);
static int na_kr_setup(struct nexus_adapter *, struct kern_channel *);
static void na_kr_teardown_all(struct nexus_adapter *, struct kern_channel *,
    boolean_t);
static void na_kr_teardown_txrx(struct nexus_adapter *, struct kern_channel *,
    boolean_t, struct proc *);
static int na_kr_populate_slots(struct __kern_channel_ring *);
static void na_kr_depopulate_slots(struct __kern_channel_ring *,
    struct kern_channel *, boolean_t defunct);

static int na_schema_alloc(struct kern_channel *);

static struct nexus_adapter *na_pseudo_alloc(zalloc_flags_t);
static void na_pseudo_free(struct nexus_adapter *);
static int na_pseudo_txsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int na_pseudo_rxsync(struct __kern_channel_ring *, struct proc *,
    uint32_t);
static int na_pseudo_activate(struct nexus_adapter *, na_activate_mode_t);
static void na_pseudo_dtor(struct nexus_adapter *);
static int na_pseudo_krings_create(struct nexus_adapter *,
    struct kern_channel *);
static void na_pseudo_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
static int na_packet_pool_alloc_sync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int na_packet_pool_free_sync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int na_packet_pool_alloc_buf_sync(struct __kern_channel_ring *,
    struct proc *, uint32_t);
static int na_packet_pool_free_buf_sync(struct __kern_channel_ring *,
    struct proc *, uint32_t);

#define NA_KRING_IDLE_TIMEOUT   (NSEC_PER_SEC * 30) /* 30 seconds */

static ZONE_DEFINE(na_pseudo_zone, SKMEM_ZONE_PREFIX ".na.pseudo",
    sizeof(struct nexus_adapter), ZC_ZFREE_CLEARMEM);

static int __na_inited = 0;

#define NA_NUM_WMM_CLASSES      4
#define NAKR_WMM_SC2RINGID(_s)  PKT_SC2TC(_s)
#define NAKR_SET_SVC_LUT(_n, _s)                                        \
	(_n)->na_kring_svc_lut[MBUF_SCIDX(_s)] = NAKR_WMM_SC2RINGID(_s)
#define NAKR_SET_KR_SVC(_n, _s)                                         \
	NAKR((_n), NR_TX)[NAKR_WMM_SC2RINGID(_s)].ckr_svc = (_s)

#define NA_UPP_ALLOC_LOWAT      8
static uint32_t na_upp_alloc_lowat = NA_UPP_ALLOC_LOWAT;

#define NA_UPP_REAP_INTERVAL    10 /* seconds */
static uint32_t na_upp_reap_interval = NA_UPP_REAP_INTERVAL;

#define NA_UPP_WS_HOLD_TIME     2 /* seconds */
static uint32_t na_upp_ws_hold_time = NA_UPP_WS_HOLD_TIME;

#define NA_UPP_REAP_MIN_PKTS    0
static uint32_t na_upp_reap_min_pkts = NA_UPP_REAP_MIN_PKTS;

#define NA_UPP_ALLOC_BUF_LOWAT     64
static uint32_t na_upp_alloc_buf_lowat = NA_UPP_ALLOC_BUF_LOWAT;

#if (DEVELOPMENT || DEBUG)
static  uint64_t _na_inject_error = 0;
#define _NA_INJECT_ERROR(_en, _ev, _ec, _f, ...) \
	_SK_INJECT_ERROR(_na_inject_error, _en, _ev, _ec, NULL, _f, __VA_ARGS__)

SYSCTL_UINT(_kern_skywalk, OID_AUTO, na_upp_ws_hold_time,
    CTLFLAG_RW | CTLFLAG_LOCKED, &na_upp_ws_hold_time,
    NA_UPP_WS_HOLD_TIME, "");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, na_upp_reap_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &na_upp_reap_interval,
    NA_UPP_REAP_INTERVAL, "");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, na_upp_reap_min_pkts,
    CTLFLAG_RW | CTLFLAG_LOCKED, &na_upp_reap_min_pkts,
    NA_UPP_REAP_MIN_PKTS, "");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, na_upp_alloc_lowat,
    CTLFLAG_RW | CTLFLAG_LOCKED, &na_upp_alloc_lowat,
    NA_UPP_ALLOC_LOWAT, "");
SYSCTL_UINT(_kern_skywalk, OID_AUTO, na_upp_alloc_buf_lowat,
    CTLFLAG_RW | CTLFLAG_LOCKED, &na_upp_alloc_buf_lowat,
    NA_UPP_ALLOC_BUF_LOWAT, "");
SYSCTL_QUAD(_kern_skywalk, OID_AUTO, na_inject_error,
    CTLFLAG_RW | CTLFLAG_LOCKED, &_na_inject_error, "");
#else
#define _NA_INJECT_ERROR(_en, _ev, _ec, _f, ...) do { } while (0)
#endif /* !DEVELOPMENT && !DEBUG */

#define SKMEM_TAG_NX_RINGS      "com.apple.skywalk.nexus.rings"
static SKMEM_TAG_DEFINE(skmem_tag_nx_rings, SKMEM_TAG_NX_RINGS);

#define SKMEM_TAG_NX_CONTEXTS   "com.apple.skywalk.nexus.contexts"
static SKMEM_TAG_DEFINE(skmem_tag_nx_contexts, SKMEM_TAG_NX_CONTEXTS);

#define SKMEM_TAG_NX_SCRATCH    "com.apple.skywalk.nexus.scratch"
static SKMEM_TAG_DEFINE(skmem_tag_nx_scratch, SKMEM_TAG_NX_SCRATCH);

#if !XNU_TARGET_OS_OSX
/* see KLDBootstrap::readPrelinkedExtensions() for details */
extern uuid_t kernelcache_uuid;
#else /* XNU_TARGET_OS_OSX */
/* see panic_init() for details */
extern unsigned char *kernel_uuid;
#endif /* XNU_TARGET_OS_OSX */

void
na_init(void)
{
	/*
	 * Changing the size of nexus_mdata structure won't break ABI,
	 * but we need to be mindful of memory consumption; Thus here
	 * we add a compile-time check to make sure the size is within
	 * the expected limit and that it's properly aligned.  This
	 * check may be adjusted in future as needed.
	 */
	_CASSERT(sizeof(struct nexus_mdata) <= 32 &&
	    IS_P2ALIGNED(sizeof(struct nexus_mdata), 8));
	_CASSERT(sizeof(struct nexus_mdata) <= sizeof(struct __user_quantum));

	/* see comments on nexus_meta_type_t */
	_CASSERT(NEXUS_META_TYPE_MAX == 3);
	_CASSERT(NEXUS_META_SUBTYPE_MAX == 3);

	ASSERT(!__na_inited);

	__na_inited = 1;
}

void
na_fini(void)
{
	if (__na_inited) {
		__na_inited = 0;
	}
}

/*
 * Interpret the ringid of an chreq, by translating it into a pair
 * of intervals of ring indices:
 *
 * [txfirst, txlast) and [rxfirst, rxlast)
 */
int
na_interp_ringid(struct nexus_adapter *na, ring_id_t ring_id,
    ring_set_t ring_set, uint32_t first[NR_TXRX], uint32_t last[NR_TXRX])
{
	enum txrx t;

	switch (ring_set) {
	case RING_SET_ALL:
		/*
		 * Ring pair eligibility: all ring(s).
		 */
		if (ring_id != CHANNEL_RING_ID_ANY &&
		    ring_id >= na_get_nrings(na, NR_TX) &&
		    ring_id >= na_get_nrings(na, NR_RX)) {
			SK_ERR("\"%s\": invalid ring_id %d for ring_set %u",
			    na->na_name, (int)ring_id, ring_set);
			return EINVAL;
		}
		for_rx_tx(t) {
			if (ring_id == CHANNEL_RING_ID_ANY) {
				first[t] = 0;
				last[t] = na_get_nrings(na, t);
			} else {
				first[t] = ring_id;
				last[t] = ring_id + 1;
			}
		}
		break;

	default:
		SK_ERR("\"%s\": invalid ring_set %u", na->na_name, ring_set);
		return EINVAL;
	}

	SK_DF(SK_VERB_NA | SK_VERB_RING,
	    "\"%s\": ring_id %d, ring_set %u tx [%u,%u) rx [%u,%u)",
	    na->na_name, (int)ring_id, ring_set, first[NR_TX], last[NR_TX],
	    first[NR_RX], last[NR_RX]);

	return 0;
}

/*
 * Set the ring ID. For devices with a single queue, a request
 * for all rings is the same as a single ring.
 */
static int
na_set_ringid(struct kern_channel *ch, ring_set_t ring_set, ring_id_t ring_id)
{
	struct nexus_adapter *na = ch->ch_na;
	int error;
	enum txrx t;
	uint32_t n_alloc_rings;

	if ((error = na_interp_ringid(na, ring_id, ring_set,
	    ch->ch_first, ch->ch_last)) != 0) {
		return error;
	}

	n_alloc_rings = na_get_nrings(na, NR_A);
	if (n_alloc_rings != 0) {
		ch->ch_first[NR_A] = ch->ch_first[NR_F] = 0;
		ch->ch_last[NR_A] = ch->ch_last[NR_F] =
		    ch->ch_first[NR_A] + n_alloc_rings;
	} else {
		ch->ch_first[NR_A] = ch->ch_last[NR_A] = 0;
		ch->ch_first[NR_F] = ch->ch_last[NR_F] = 0;
	}
	ch->ch_first[NR_EV] = 0;
	ch->ch_last[NR_EV] = ch->ch_first[NR_EV] + na_get_nrings(na, NR_EV);
	/* XXX: should we initialize na_si_users for event ring ? */

	/*
	 * Optimization: count the users registered for more than
	 * one ring, which are the ones sleeping on the global queue.
	 * The default na_notify() callback will then avoid signaling
	 * the global queue if nobody is using it
	 */
	for_rx_tx(t) {
		if (ch_is_multiplex(ch, t)) {
			na->na_si_users[t]++;
			ASSERT(na->na_si_users[t] != 0);
		}
	}
	return 0;
}

static void
na_unset_ringid(struct kern_channel *ch)
{
	struct nexus_adapter *na = ch->ch_na;
	enum txrx t;

	for_rx_tx(t) {
		if (ch_is_multiplex(ch, t)) {
			ASSERT(na->na_si_users[t] != 0);
			na->na_si_users[t]--;
		}
		ch->ch_first[t] = ch->ch_last[t] = 0;
	}
}

/*
 * Check that the rings we want to bind are not exclusively owned by a previous
 * bind.  If exclusive ownership has been requested, we also mark the rings.
 */
/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static int
na_krings_use(struct kern_channel *ch)
{
	struct nexus_adapter *na = ch->ch_na;
	struct __kern_channel_ring *kring;
	boolean_t excl = !!(ch->ch_flags & CHANF_EXCLUSIVE);
	enum txrx t;
	uint32_t i;

	SK_DF(SK_VERB_NA | SK_VERB_RING, "na \"%s\" (0x%llx) grabbing tx [%u,%u) rx [%u,%u)",
	    na->na_name, SK_KVA(na), ch->ch_first[NR_TX], ch->ch_last[NR_TX],
	    ch->ch_first[NR_RX], ch->ch_last[NR_RX]);

	/*
	 * First round: check that all the requested rings
	 * are neither alread exclusively owned, nor we
	 * want exclusive ownership when they are already in use
	 */
	for_all_rings(t) {
		for (i = ch->ch_first[t]; i < ch->ch_last[t]; i++) {
			kring = &NAKR(na, t)[i];
			if ((kring->ckr_flags & CKRF_EXCLUSIVE) ||
			    (kring->ckr_users && excl)) {
				SK_DF(SK_VERB_NA | SK_VERB_RING,
				    "kr \"%s\" (0x%llx) krflags 0x%b is busy",
				    kring->ckr_name, SK_KVA(kring),
				    kring->ckr_flags, CKRF_BITS);
				return EBUSY;
			}
		}
	}

	/*
	 * Second round: increment usage count and possibly
	 * mark as exclusive
	 */

	for_all_rings(t) {
		for (i = ch->ch_first[t]; i < ch->ch_last[t]; i++) {
			kring = &NAKR(na, t)[i];
			kring->ckr_users++;
			if (excl) {
				kring->ckr_flags |= CKRF_EXCLUSIVE;
			}
		}
	}

	return 0;
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static void
na_krings_unuse(struct kern_channel *ch)
{
	struct nexus_adapter *na = ch->ch_na;
	struct __kern_channel_ring *kring;
	boolean_t excl = !!(ch->ch_flags & CHANF_EXCLUSIVE);
	enum txrx t;
	uint32_t i;

	SK_DF(SK_VERB_NA | SK_VERB_RING,
	    "na \"%s\" (0x%llx) releasing tx [%u, %u) rx [%u, %u)",
	    na->na_name, SK_KVA(na), ch->ch_first[NR_TX], ch->ch_last[NR_TX],
	    ch->ch_first[NR_RX], ch->ch_last[NR_RX]);

	for_all_rings(t) {
		for (i = ch->ch_first[t]; i < ch->ch_last[t]; i++) {
			kring = &NAKR(na, t)[i];
			if (excl) {
				kring->ckr_flags &= ~CKRF_EXCLUSIVE;
			}
			kring->ckr_users--;
		}
	}
}

/* Hoisted out of line to reduce kernel stack footprint */
SK_NO_INLINE_ATTRIBUTE
static void
na_krings_verify(struct nexus_adapter *na)
{
	struct __kern_channel_ring *kring;
	enum txrx t;
	uint32_t i;

	for_all_rings(t) {
		for (i = 0; i < na_get_nrings(na, t); i++) {
			kring = &NAKR(na, t)[i];
			/* na_kr_create() validations */
			ASSERT(kring->ckr_num_slots > 0);
			ASSERT(kring->ckr_lim == (kring->ckr_num_slots - 1));
			ASSERT(kring->ckr_pp != NULL);

			if (!(kring->ckr_flags & CKRF_MEM_RING_INITED)) {
				continue;
			}
			/* na_kr_setup() validations */
			if (KR_KERNEL_ONLY(kring)) {
				ASSERT(kring->ckr_ring == NULL);
			} else {
				ASSERT(kring->ckr_ring != NULL);
			}
			ASSERT(kring->ckr_ksds_last ==
			    &kring->ckr_ksds[kring->ckr_lim]);
		}
	}
}

int
na_bind_channel(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *chr)
{
	struct kern_pbufpool *rx_pp = skmem_arena_nexus(na->na_arena)->arn_rx_pp;
	struct kern_pbufpool *tx_pp = skmem_arena_nexus(na->na_arena)->arn_tx_pp;
	uint32_t ch_mode = chr->cr_mode;
	int err = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(ch->ch_schema == NULL);
	ASSERT(ch->ch_na == NULL);

	/* ring configuration may have changed, fetch from the card */
	na_update_config(na);
	ch->ch_na = na; /* store the reference */
	err = na_set_ringid(ch, chr->cr_ring_set, chr->cr_ring_id);
	if (err != 0) {
		goto err;
	}

	atomic_bitclear_32(&ch->ch_flags, (CHANF_RXONLY | CHANF_EXCLUSIVE |
	    CHANF_USER_PACKET_POOL | CHANF_EVENT_RING));
	if (ch_mode & CHMODE_EXCLUSIVE) {
		atomic_bitset_32(&ch->ch_flags, CHANF_EXCLUSIVE);
	}
	/*
	 * Disallow automatic sync for monitor mode, since TX
	 * direction is disabled.
	 */
	if (ch_mode & CHMODE_MONITOR) {
		atomic_bitset_32(&ch->ch_flags, CHANF_RXONLY);
	}

	if (!!(na->na_flags & NAF_USER_PKT_POOL) ^
	    !!(ch_mode & CHMODE_USER_PACKET_POOL)) {
		SK_ERR("incompatible channel mode (0x%b), na_flags (0x%b)",
		    ch_mode, CHMODE_BITS, na->na_flags, NAF_BITS);
		err = EINVAL;
		goto err;
	}

	if (na->na_arena->ar_flags & ARF_DEFUNCT) {
		err = ENXIO;
		goto err;
	}

	if (ch_mode & CHMODE_USER_PACKET_POOL) {
		ASSERT(na->na_flags & NAF_USER_PKT_POOL);
		ASSERT(ch->ch_first[NR_A] != ch->ch_last[NR_A]);
		ASSERT(ch->ch_first[NR_F] != ch->ch_last[NR_F]);
		atomic_bitset_32(&ch->ch_flags, CHANF_USER_PACKET_POOL);
	}

	if (ch_mode & CHMODE_EVENT_RING) {
		ASSERT(na->na_flags & NAF_USER_PKT_POOL);
		ASSERT(na->na_flags & NAF_EVENT_RING);
		ASSERT(ch->ch_first[NR_EV] != ch->ch_last[NR_EV]);
		atomic_bitset_32(&ch->ch_flags, CHANF_EVENT_RING);
	}

	/*
	 * If this is the first channel of the adapter, create
	 * the rings and their in-kernel view, the krings.
	 */
	if (na->na_channels == 0) {
		err = na->na_krings_create(na, ch);
		if (err != 0) {
			goto err;
		}

		/*
		 * Sanity check; this is already done in na_kr_create(),
		 * but we do it here as well to validate na_kr_setup().
		 */
		na_krings_verify(na);
		*(nexus_meta_type_t *)(uintptr_t)&na->na_md_type =
		    skmem_arena_nexus(na->na_arena)->arn_rx_pp->pp_md_type;
		*(nexus_meta_subtype_t *)(uintptr_t)&na->na_md_subtype =
		    skmem_arena_nexus(na->na_arena)->arn_rx_pp->pp_md_subtype;
	}

	/*
	 * Validate ownership and usability of the krings; take into account
	 * whether some previous bind has exclusive ownership on them.
	 */
	err = na_krings_use(ch);
	if (err != 0) {
		goto err_del_rings;
	}

	/* for user-facing channel, create a new channel schema */
	if (!(ch->ch_flags & CHANF_KERNEL)) {
		err = na_schema_alloc(ch);
		if (err != 0) {
			goto err_rel_excl;
		}

		ASSERT(ch->ch_schema != NULL);
		ASSERT(ch->ch_schema_offset != (mach_vm_offset_t)-1);
	} else {
		ASSERT(ch->ch_schema == NULL);
		ch->ch_schema_offset = (mach_vm_offset_t)-1;
	}

	/* update our work timestamp */
	na->na_work_ts = net_uptime();

	/* update our work timestamp */
	na->na_work_ts = net_uptime();

	na->na_channels++;

	/*
	 * If user packet pool is desired, initialize the allocated
	 * object hash table in the pool, if not already.  This also
	 * retains a refcnt on the pool which the caller must release.
	 */
	ASSERT(ch->ch_pp == NULL);
	if (ch_mode & CHMODE_USER_PACKET_POOL) {
#pragma unused(tx_pp)
		ASSERT(rx_pp == tx_pp);
		err = pp_init_upp(rx_pp, TRUE);
		if (err != 0) {
			goto err_free_schema;
		}
		ch->ch_pp = rx_pp;
	}

	if (!NA_IS_ACTIVE(na)) {
		err = na->na_activate(na, NA_ACTIVATE_MODE_ON);
		if (err != 0) {
			goto err_release_pp;
		}

		SK_D("activated \"%s\" adapter 0x%llx", na->na_name,
		    SK_KVA(na));
		SK_D("  na_md_type:    %u", na->na_md_type);
		SK_D("  na_md_subtype: %u", na->na_md_subtype);
	}

	SK_D("ch 0x%llx", SK_KVA(ch));
	SK_D("  ch_flags:     0x%b", ch->ch_flags, CHANF_BITS);
	if (ch->ch_schema != NULL) {
		SK_D("  ch_schema:    0x%llx", SK_KVA(ch->ch_schema));
	}
	SK_D("  ch_na:        0x%llx (chcnt %u)", SK_KVA(ch->ch_na),
	    ch->ch_na->na_channels);
	SK_D("  ch_tx_rings:  [%u,%u)", ch->ch_first[NR_TX],
	    ch->ch_last[NR_TX]);
	SK_D("  ch_rx_rings:  [%u,%u)", ch->ch_first[NR_RX],
	    ch->ch_last[NR_RX]);
	SK_D("  ch_alloc_rings:  [%u,%u)", ch->ch_first[NR_A],
	    ch->ch_last[NR_A]);
	SK_D("  ch_free_rings:  [%u,%u)", ch->ch_first[NR_F],
	    ch->ch_last[NR_F]);
	SK_D("  ch_ev_rings:  [%u,%u)", ch->ch_first[NR_EV],
	    ch->ch_last[NR_EV]);

	return 0;

err_release_pp:
	if (ch_mode & CHMODE_USER_PACKET_POOL) {
		ASSERT(ch->ch_pp != NULL);
		pp_release(rx_pp);
		ch->ch_pp = NULL;
	}
err_free_schema:
	*(nexus_meta_type_t *)(uintptr_t)&na->na_md_type =
	    NEXUS_META_TYPE_INVALID;
	*(nexus_meta_subtype_t *)(uintptr_t)&na->na_md_subtype =
	    NEXUS_META_SUBTYPE_INVALID;
	ASSERT(na->na_channels != 0);
	na->na_channels--;
	if (ch->ch_schema != NULL) {
		skmem_cache_free(
			skmem_arena_nexus(na->na_arena)->arn_schema_cache,
			ch->ch_schema);
		ch->ch_schema = NULL;
		ch->ch_schema_offset = (mach_vm_offset_t)-1;
	}
err_rel_excl:
	na_krings_unuse(ch);
err_del_rings:
	if (na->na_channels == 0) {
		na->na_krings_delete(na, ch, FALSE);
	}
err:
	ch->ch_na = NULL;
	ASSERT(err != 0);

	return err;
}

/*
 * Undo everything that was done in na_bind_channel().
 */
/* call with SK_LOCK held */
void
na_unbind_channel(struct kern_channel *ch)
{
	struct nexus_adapter *na = ch->ch_na;

	SK_LOCK_ASSERT_HELD();

	ASSERT(na->na_channels != 0);
	na->na_channels--;

	/* release exclusive use if it was requested at bind time */
	na_krings_unuse(ch);

	if (na->na_channels == 0) {     /* last instance */
		SK_D("%s(%d): deleting last channel instance for %s",
		    ch->ch_name, ch->ch_pid, na->na_name);

		/*
		 * Free any remaining allocated packets attached to
		 * the slots, followed by a teardown of the arena.
		 */
		na_teardown(na, ch, FALSE);

		*(nexus_meta_type_t *)(uintptr_t)&na->na_md_type =
		    NEXUS_META_TYPE_INVALID;
		*(nexus_meta_subtype_t *)(uintptr_t)&na->na_md_subtype =
		    NEXUS_META_SUBTYPE_INVALID;
	} else {
		SK_D("%s(%d): %s has %u remaining channel instance(s)",
		    ch->ch_name, ch->ch_pid, na->na_name, na->na_channels);
	}

	/*
	 * Free any allocated packets (for the process) attached to the slots;
	 * note that na_teardown() could have done this there as well.
	 */
	if (ch->ch_pp != NULL) {
		ASSERT(ch->ch_flags & CHANF_USER_PACKET_POOL);
		pp_purge_upp(ch->ch_pp, ch->ch_pid);
		pp_release(ch->ch_pp);
		ch->ch_pp = NULL;
	}

	/* possibily decrement counter of tx_si/rx_si users */
	na_unset_ringid(ch);

	/* reap the caches now (purge if adapter is idle) */
	skmem_arena_reap(na->na_arena, (na->na_channels == 0));

	/* delete the csm */
	if (ch->ch_schema != NULL) {
		skmem_cache_free(
			skmem_arena_nexus(na->na_arena)->arn_schema_cache,
			ch->ch_schema);
		ch->ch_schema = NULL;
		ch->ch_schema_offset = (mach_vm_offset_t)-1;
	}

	/* destroy the memory map */
	skmem_arena_munmap_channel(na->na_arena, ch);

	/* mark the channel as unbound */
	atomic_bitclear_32(&ch->ch_flags, (CHANF_RXONLY | CHANF_EXCLUSIVE));
	ch->ch_na = NULL;

	/* and finally release the nexus adapter; this might free it */
	(void) na_release_locked(na);
}

static void
na_teardown(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	SK_LOCK_ASSERT_HELD();
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

#if CONFIG_NEXUS_MONITOR
	/*
	 * Walk through all the rings and tell any monitor
	 * that the port is going to exit Skywalk mode
	 */
	nx_mon_stop(na);
#endif /* CONFIG_NEXUS_MONITOR */

	/*
	 * Deactive the adapter.
	 */
	(void) na->na_activate(na,
	    (defunct ? NA_ACTIVATE_MODE_DEFUNCT : NA_ACTIVATE_MODE_OFF));

	/*
	 * Free any remaining allocated packets for this process.
	 */
	if (ch->ch_pp != NULL) {
		ASSERT(ch->ch_flags & CHANF_USER_PACKET_POOL);
		pp_purge_upp(ch->ch_pp, ch->ch_pid);
		if (!defunct) {
			pp_release(ch->ch_pp);
			ch->ch_pp = NULL;
		}
	}

	/*
	 * Delete rings and buffers.
	 */
	na->na_krings_delete(na, ch, defunct);
}

/* call with SK_LOCK held */
/*
 * Allocate the per-fd structure __user_channel_schema.
 */
static int
na_schema_alloc(struct kern_channel *ch)
{
	struct nexus_adapter *na = ch->ch_na;
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn;
	mach_vm_offset_t roff[SKMEM_REGIONS];
	struct __kern_channel_ring *kr;
	struct __user_channel_schema *csm;
	struct skmem_obj_info csm_oi, ring_oi, ksd_oi, usd_oi;
	mach_vm_offset_t base;
	uint32_t i, j, k, n[NR_ALL];
	enum txrx t;

	/* see comments for struct __user_channel_schema */
	_CASSERT(offsetof(struct __user_channel_schema, csm_ver) == 0);
	_CASSERT(offsetof(struct __user_channel_schema, csm_flags) ==
	    sizeof(csm->csm_ver));
	_CASSERT(offsetof(struct __user_channel_schema, csm_kern_name) ==
	    sizeof(csm->csm_ver) + sizeof(csm->csm_flags));
	_CASSERT(offsetof(struct __user_channel_schema, csm_kern_uuid) ==
	    sizeof(csm->csm_ver) + sizeof(csm->csm_flags) +
	    sizeof(csm->csm_kern_name));

	SK_LOCK_ASSERT_HELD();

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);
	arn = skmem_arena_nexus(ar);
	ASSERT(arn != NULL);
	for_all_rings(t) {
		n[t] = 0;
	}

	csm = skmem_cache_alloc(arn->arn_schema_cache, SKMEM_NOSLEEP);
	if (csm == NULL) {
		return ENOMEM;
	}

	skmem_cache_get_obj_info(arn->arn_schema_cache, csm, &csm_oi, NULL);
	bzero(csm, SKMEM_OBJ_SIZE(&csm_oi));

	*(uint32_t *)(uintptr_t)&csm->csm_ver = CSM_CURRENT_VERSION;

	/* kernel version and executable UUID */
	_CASSERT(sizeof(csm->csm_kern_name) == _SYS_NAMELEN);
	(void) strncpy((char *)(uintptr_t)csm->csm_kern_name,
	    version, sizeof(csm->csm_kern_name) - 1);
#if !XNU_TARGET_OS_OSX
	(void) memcpy((void *)(uintptr_t)csm->csm_kern_uuid,
	    kernelcache_uuid, sizeof(csm->csm_kern_uuid));
#else /* XNU_TARGET_OS_OSX */
	if (kernel_uuid != NULL) {
		(void) memcpy((void *)(uintptr_t)csm->csm_kern_uuid,
		    kernel_uuid, sizeof(csm->csm_kern_uuid));
	}
#endif /* XNU_TARGET_OS_OSX */

	for_rx_tx(t) {
		ASSERT((ch->ch_last[t] > 0) || (ch->ch_first[t] == 0));
		n[t] = ch->ch_last[t] - ch->ch_first[t];
		ASSERT(n[t] == 0 || n[t] <= na_get_nrings(na, t));
	}

	/* return total number of tx and rx rings for this channel */
	*(uint32_t *)(uintptr_t)&csm->csm_tx_rings = n[NR_TX];
	*(uint32_t *)(uintptr_t)&csm->csm_rx_rings = n[NR_RX];

	if (ch->ch_flags & CHANF_USER_PACKET_POOL) {
		*(uint32_t *)(uintptr_t)&csm->csm_allocator_ring_pairs =
		    na->na_num_allocator_ring_pairs;
		n[NR_A] = n[NR_F] = na->na_num_allocator_ring_pairs;
		ASSERT(n[NR_A] != 0 && n[NR_A] <= na_get_nrings(na, NR_A));
		ASSERT(n[NR_A] == (ch->ch_last[NR_A] - ch->ch_first[NR_A]));
		ASSERT(n[NR_F] == (ch->ch_last[NR_F] - ch->ch_first[NR_F]));
	}

	if (ch->ch_flags & CHANF_EVENT_RING) {
		n[NR_EV] = ch->ch_last[NR_EV] - ch->ch_first[NR_EV];
		ASSERT(n[NR_EV] != 0 && n[NR_EV] <= na_get_nrings(na, NR_EV));
		*(uint32_t *)(uintptr_t)&csm->csm_num_event_rings = n[NR_EV];
	}

	bzero(&roff, sizeof(roff));
	for (i = 0; i < SKMEM_REGIONS; i++) {
		if (ar->ar_regions[i] == NULL) {
			ASSERT(i == SKMEM_REGION_GUARD_HEAD ||
			    i == SKMEM_REGION_SCHEMA ||
			    i == SKMEM_REGION_RXBUF ||
			    i == SKMEM_REGION_TXBUF ||
			    i == SKMEM_REGION_RXKMD ||
			    i == SKMEM_REGION_TXKMD ||
			    i == SKMEM_REGION_UMD ||
			    i == SKMEM_REGION_UBFT ||
			    i == SKMEM_REGION_KBFT ||
			    i == SKMEM_REGION_RXKBFT ||
			    i == SKMEM_REGION_TXKBFT ||
			    i == SKMEM_REGION_TXAUSD ||
			    i == SKMEM_REGION_RXFUSD ||
			    i == SKMEM_REGION_USTATS ||
			    i == SKMEM_REGION_KSTATS ||
			    i == SKMEM_REGION_INTRINSIC ||
			    i == SKMEM_REGION_FLOWADV ||
			    i == SKMEM_REGION_NEXUSADV ||
			    i == SKMEM_REGION_SYSCTLS ||
			    i == SKMEM_REGION_GUARD_TAIL);
			continue;
		}

		/* not for nexus */
		ASSERT(i != SKMEM_REGION_SYSCTLS);

		/*
		 * Get region offsets from base of mmap span; the arena
		 * doesn't need to be mmap'd at this point, since we
		 * simply compute the relative offset.
		 */
		roff[i] = skmem_arena_get_region_offset(ar, i);
	}

	/*
	 * The schema is made up of the descriptor followed inline by an array
	 * of offsets to the tx, rx, allocator and event rings in the mmap span.
	 * They contain the offset between the ring and schema, so the
	 * information is usable in userspace to reach the ring from
	 * the schema.
	 */
	base = roff[SKMEM_REGION_SCHEMA] + SKMEM_OBJ_ROFF(&csm_oi);

	/* initialize schema with tx ring info */
	for (i = 0, j = ch->ch_first[NR_TX]; i < n[NR_TX]; i++, j++) {
		kr = &na->na_tx_rings[j];
		if (KR_KERNEL_ONLY(kr)) { /* skip kernel-only rings */
			continue;
		}

		ASSERT(kr->ckr_flags & CKRF_MEM_RING_INITED);
		skmem_cache_get_obj_info(arn->arn_ring_cache,
		    kr->ckr_ring, &ring_oi, NULL);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_ring_ofs[i].ring_off =
		    (roff[SKMEM_REGION_RING] + SKMEM_OBJ_ROFF(&ring_oi)) - base;

		ASSERT(kr->ckr_flags & CKRF_MEM_SD_INITED);
		skmem_cache_get_obj_info(kr->ckr_ksds_cache,
		    kr->ckr_ksds, &ksd_oi, &usd_oi);

		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_ring_ofs[i].sd_off =
		    (roff[SKMEM_REGION_TXAUSD] + SKMEM_OBJ_ROFF(&usd_oi)) -
		    base;
	}
	/* initialize schema with rx ring info */
	for (i = 0, j = ch->ch_first[NR_RX]; i < n[NR_RX]; i++, j++) {
		kr = &na->na_rx_rings[j];
		if (KR_KERNEL_ONLY(kr)) { /* skip kernel-only rings */
			continue;
		}

		ASSERT(kr->ckr_flags & CKRF_MEM_RING_INITED);
		skmem_cache_get_obj_info(arn->arn_ring_cache,
		    kr->ckr_ring, &ring_oi, NULL);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + n[NR_TX]].ring_off =
		    (roff[SKMEM_REGION_RING] + SKMEM_OBJ_ROFF(&ring_oi)) - base;

		ASSERT(kr->ckr_flags & CKRF_MEM_SD_INITED);
		skmem_cache_get_obj_info(kr->ckr_ksds_cache,
		    kr->ckr_ksds, &ksd_oi, &usd_oi);

		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + n[NR_TX]].sd_off =
		    (roff[SKMEM_REGION_RXFUSD] + SKMEM_OBJ_ROFF(&usd_oi)) -
		    base;
	}
	/* initialize schema with allocator ring info */
	for (i = 0, j = ch->ch_first[NR_A], k = n[NR_TX] + n[NR_RX];
	    i < n[NR_A]; i++, j++) {
		mach_vm_offset_t usd_roff;

		usd_roff = roff[SKMEM_REGION_TXAUSD];
		kr = &na->na_alloc_rings[j];
		ASSERT(kr->ckr_flags & CKRF_MEM_RING_INITED);
		ASSERT(kr->ckr_flags & CKRF_MEM_SD_INITED);

		skmem_cache_get_obj_info(arn->arn_ring_cache, kr->ckr_ring,
		    &ring_oi, NULL);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].ring_off =
		    (roff[SKMEM_REGION_RING] + SKMEM_OBJ_ROFF(&ring_oi)) - base;

		skmem_cache_get_obj_info(kr->ckr_ksds_cache, kr->ckr_ksds,
		    &ksd_oi, &usd_oi);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].sd_off =
		    (usd_roff + SKMEM_OBJ_ROFF(&usd_oi)) - base;
	}
	/* initialize schema with free ring info */
	for (i = 0, j = ch->ch_first[NR_F], k = n[NR_TX] + n[NR_RX] + n[NR_A];
	    i < n[NR_F]; i++, j++) {
		mach_vm_offset_t usd_roff;

		usd_roff = roff[SKMEM_REGION_RXFUSD];
		kr = &na->na_free_rings[j];
		ASSERT(kr->ckr_flags & CKRF_MEM_RING_INITED);
		ASSERT(kr->ckr_flags & CKRF_MEM_SD_INITED);

		skmem_cache_get_obj_info(arn->arn_ring_cache, kr->ckr_ring,
		    &ring_oi, NULL);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].ring_off =
		    (roff[SKMEM_REGION_RING] + SKMEM_OBJ_ROFF(&ring_oi)) - base;

		skmem_cache_get_obj_info(kr->ckr_ksds_cache, kr->ckr_ksds,
		    &ksd_oi, &usd_oi);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].sd_off =
		    (usd_roff + SKMEM_OBJ_ROFF(&usd_oi)) - base;
	}
	/* initialize schema with event ring info */
	for (i = 0, j = ch->ch_first[NR_EV], k = n[NR_TX] + n[NR_RX] +
	    n[NR_A] + n[NR_F]; i < n[NR_EV]; i++, j++) {
		ASSERT(csm->csm_num_event_rings != 0);
		kr = &na->na_event_rings[j];
		ASSERT(!KR_KERNEL_ONLY(kr));
		ASSERT(kr->ckr_flags & CKRF_MEM_RING_INITED);
		skmem_cache_get_obj_info(arn->arn_ring_cache,
		    kr->ckr_ring, &ring_oi, NULL);
		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].ring_off =
		    (roff[SKMEM_REGION_RING] + SKMEM_OBJ_ROFF(&ring_oi)) - base;

		ASSERT(kr->ckr_flags & CKRF_MEM_SD_INITED);
		skmem_cache_get_obj_info(kr->ckr_ksds_cache,
		    kr->ckr_ksds, &ksd_oi, &usd_oi);

		*(mach_vm_offset_t *)
		(uintptr_t)&csm->csm_ring_ofs[i + k].sd_off =
		    (roff[SKMEM_REGION_TXAUSD] + SKMEM_OBJ_ROFF(&usd_oi)) -
		    base;
	}

	*(uint64_t *)(uintptr_t)&csm->csm_md_redzone_cookie =
	    __ch_umd_redzone_cookie;
	*(nexus_meta_type_t *)(uintptr_t)&csm->csm_md_type = na->na_md_type;
	*(nexus_meta_subtype_t *)(uintptr_t)&csm->csm_md_subtype =
	    na->na_md_subtype;

	if (arn->arn_stats_obj != NULL) {
		ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] != NULL);
		ASSERT(roff[SKMEM_REGION_USTATS] != 0);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_stats_ofs =
		    roff[SKMEM_REGION_USTATS];
		*(nexus_stats_type_t *)(uintptr_t)&csm->csm_stats_type =
		    na->na_stats_type;
	} else {
		ASSERT(ar->ar_regions[SKMEM_REGION_USTATS] == NULL);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_stats_ofs = 0;
		*(nexus_stats_type_t *)(uintptr_t)&csm->csm_stats_type =
		    NEXUS_STATS_TYPE_INVALID;
	}

	if (arn->arn_flowadv_obj != NULL) {
		ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] != NULL);
		ASSERT(roff[SKMEM_REGION_FLOWADV] != 0);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_flowadv_ofs =
		    roff[SKMEM_REGION_FLOWADV];
		*(uint32_t *)(uintptr_t)&csm->csm_flowadv_max =
		    na->na_flowadv_max;
	} else {
		ASSERT(ar->ar_regions[SKMEM_REGION_FLOWADV] == NULL);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_flowadv_ofs = 0;
		*(uint32_t *)(uintptr_t)&csm->csm_flowadv_max = 0;
	}

	if (arn->arn_nexusadv_obj != NULL) {
		struct __kern_nexus_adv_metadata *adv_md;

		adv_md = arn->arn_nexusadv_obj;
		ASSERT(adv_md->knam_version == NX_ADVISORY_MD_CURRENT_VERSION);
		ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] != NULL);
		ASSERT(roff[SKMEM_REGION_NEXUSADV] != 0);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_nexusadv_ofs =
		    roff[SKMEM_REGION_NEXUSADV];
	} else {
		ASSERT(ar->ar_regions[SKMEM_REGION_NEXUSADV] == NULL);
		*(mach_vm_offset_t *)(uintptr_t)&csm->csm_nexusadv_ofs = 0;
	}

	ch->ch_schema = csm;
	ch->ch_schema_offset = base;

	return 0;
}

/*
 * Called by all routines that create nexus_adapters.
 * Attach na to the ifp (if any) and provide defaults
 * for optional callbacks. Defaults assume that we
 * are creating an hardware nexus_adapter.
 */
void
na_attach_common(struct nexus_adapter *na, struct kern_nexus *nx,
    struct kern_nexus_domain_provider *nxdom_prov)
{
	SK_LOCK_ASSERT_HELD();

	ASSERT(nx != NULL);
	ASSERT(nxdom_prov != NULL);
	ASSERT(na->na_krings_create != NULL);
	ASSERT(na->na_krings_delete != NULL);
	if (na->na_type != NA_NETIF_COMPAT_DEV) {
		ASSERT(na_get_nrings(na, NR_TX) != 0);
	}
	if (na->na_type != NA_NETIF_COMPAT_HOST) {
		ASSERT(na_get_nrings(na, NR_RX) != 0);
	}
	ASSERT(na->na_channels == 0);

	if (na->na_notify == NULL) {
		na->na_notify = na_notify;
	}

	na->na_nx = nx;
	na->na_nxdom_prov = nxdom_prov;

	SK_D("na 0x%llx nx 0x%llx nxtype %u ar 0x%llx",
	    SK_KVA(na), SK_KVA(nx), nxdom_prov->nxdom_prov_dom->nxdom_type,
	    SK_KVA(na->na_arena));
}

void
na_post_event(struct __kern_channel_ring *kring, boolean_t nodelay,
    boolean_t within_kevent, boolean_t selwake, uint32_t hint)
{
	struct nexus_adapter *na = KRNA(kring);
	enum txrx t = kring->ckr_tx;

	SK_DF(SK_VERB_EVENTS,
	    "%s(%d) na \"%s\" (0x%llx) kr 0x%llx kev %u sel %u hint 0x%b",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    na->na_name, SK_KVA(na), SK_KVA(kring), within_kevent, selwake,
	    hint, CHAN_FILT_HINT_BITS);

	csi_selwakeup_one(kring, nodelay, within_kevent, selwake, hint);
	/*
	 * optimization: avoid a wake up on the global
	 * queue if nobody has registered for more
	 * than one ring
	 */
	if (na->na_si_users[t] > 0) {
		csi_selwakeup_all(na, t, nodelay, within_kevent, selwake, hint);
	}
}

/* default notify callback */
static int
na_notify(struct __kern_channel_ring *kring, struct proc *p, uint32_t flags)
{
#pragma unused(p)
	SK_DF(SK_VERB_NOTIFY | ((kring->ckr_tx == NR_TX) ?
	    SK_VERB_TX : SK_VERB_RX),
	    "%s(%d) [%s] na \"%s\" (0x%llx) kr \"%s\" (0x%llx) krflags 0x%b "
	    "flags 0x%x, kh %u kt %u | h %u t %u",
	    sk_proc_name_address(p), sk_proc_pid(p),
	    (kring->ckr_tx == NR_TX) ? "W" : "R", KRNA(kring)->na_name,
	    SK_KVA(KRNA(kring)), kring->ckr_name, SK_KVA(kring),
	    kring->ckr_flags, CKRF_BITS, flags, kring->ckr_khead,
	    kring->ckr_ktail, kring->ckr_rhead, kring->ckr_rtail);

	na_post_event(kring, (flags & NA_NOTEF_PUSH),
	    (flags & NA_NOTEF_IN_KEVENT), TRUE, 0);

	return 0;
}

/*
 * Fetch configuration from the device, to cope with dynamic
 * reconfigurations after loading the module.
 */
/* call with SK_LOCK held */
int
na_update_config(struct nexus_adapter *na)
{
	uint32_t txr, txd, rxr, rxd;

	SK_LOCK_ASSERT_HELD();

	txr = txd = rxr = rxd = 0;
	if (na->na_config == NULL ||
	    na->na_config(na, &txr, &txd, &rxr, &rxd)) {
		/* take whatever we had at init time */
		txr = na_get_nrings(na, NR_TX);
		txd = na_get_nslots(na, NR_TX);
		rxr = na_get_nrings(na, NR_RX);
		rxd = na_get_nslots(na, NR_RX);
	}

	if (na_get_nrings(na, NR_TX) == txr &&
	    na_get_nslots(na, NR_TX) == txd &&
	    na_get_nrings(na, NR_RX) == rxr &&
	    na_get_nslots(na, NR_RX) == rxd) {
		return 0; /* nothing changed */
	}
	SK_D("stored config %s: txring %u x %u, rxring %u x %u",
	    na->na_name, na_get_nrings(na, NR_TX), na_get_nslots(na, NR_TX),
	    na_get_nrings(na, NR_RX), na_get_nslots(na, NR_RX));
	SK_D("new config %s: txring %u x %u, rxring %u x %u",
	    na->na_name, txr, txd, rxr, rxd);

	if (na->na_channels == 0) {
		SK_D("configuration changed (but fine)");
		na_set_nrings(na, NR_TX, txr);
		na_set_nslots(na, NR_TX, txd);
		na_set_nrings(na, NR_RX, rxr);
		na_set_nslots(na, NR_RX, rxd);
		return 0;
	}
	SK_ERR("configuration changed while active, this is bad...");
	return 1;
}

static void
na_kr_setup_netif_svc_map(struct nexus_adapter *na)
{
	uint32_t i;
	uint32_t num_tx_rings;

	ASSERT(na->na_type == NA_NETIF_DEV);
	num_tx_rings = na_get_nrings(na, NR_TX);

	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_BK_SYS) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_BK));
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_BE) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_RD));
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_BE) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_OAM));
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_AV) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_RV));
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_AV) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_VI));
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_VO) ==
	    NAKR_WMM_SC2RINGID(KPKT_SC_CTL));

	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_BK) < NA_NUM_WMM_CLASSES);
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_BE) < NA_NUM_WMM_CLASSES);
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_VI) < NA_NUM_WMM_CLASSES);
	_CASSERT(NAKR_WMM_SC2RINGID(KPKT_SC_VO) < NA_NUM_WMM_CLASSES);

	_CASSERT(MBUF_SCIDX(KPKT_SC_BK_SYS) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_BK) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_BE) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_RD) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_OAM) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_AV) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_RV) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_VI) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_SIG) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_VO) < KPKT_SC_MAX_CLASSES);
	_CASSERT(MBUF_SCIDX(KPKT_SC_CTL) < KPKT_SC_MAX_CLASSES);

	/*
	 * we support the following 2 configurations:
	 * 1. packets from all 10 service class map to one ring.
	 * 2. a 10:4 mapping between service classes and the rings. These 4
	 *    rings map to the 4 WMM access categories.
	 */
	if (na->na_nx->nx_prov->nxprov_params->nxp_qmap == NEXUS_QMAP_TYPE_WMM) {
		ASSERT(num_tx_rings == NEXUS_NUM_WMM_QUEUES);
		/* setup the adapter's service class LUT */
		NAKR_SET_SVC_LUT(na, KPKT_SC_BK_SYS);
		NAKR_SET_SVC_LUT(na, KPKT_SC_BK);
		NAKR_SET_SVC_LUT(na, KPKT_SC_BE);
		NAKR_SET_SVC_LUT(na, KPKT_SC_RD);
		NAKR_SET_SVC_LUT(na, KPKT_SC_OAM);
		NAKR_SET_SVC_LUT(na, KPKT_SC_AV);
		NAKR_SET_SVC_LUT(na, KPKT_SC_RV);
		NAKR_SET_SVC_LUT(na, KPKT_SC_VI);
		NAKR_SET_SVC_LUT(na, KPKT_SC_SIG);
		NAKR_SET_SVC_LUT(na, KPKT_SC_VO);
		NAKR_SET_SVC_LUT(na, KPKT_SC_CTL);

		/* Initialize the service class for each of the 4 ring */
		NAKR_SET_KR_SVC(na, KPKT_SC_BK);
		NAKR_SET_KR_SVC(na, KPKT_SC_BE);
		NAKR_SET_KR_SVC(na, KPKT_SC_VI);
		NAKR_SET_KR_SVC(na, KPKT_SC_VO);
	} else {
		ASSERT(na->na_nx->nx_prov->nxprov_params->nxp_qmap ==
		    NEXUS_QMAP_TYPE_DEFAULT);
		/* 10: 1 mapping */
		for (i = 0; i < KPKT_SC_MAX_CLASSES; i++) {
			na->na_kring_svc_lut[i] = 0;
		}
		for (i = 0; i < num_tx_rings; i++) {
			NAKR(na, NR_TX)[i].ckr_svc = KPKT_SC_UNSPEC;
		}
	}
}

static LCK_GRP_DECLARE(channel_txq_lock_group, "sk_ch_txq_lock");
static LCK_GRP_DECLARE(channel_rxq_lock_group, "sk_ch_rxq_lock");
static LCK_GRP_DECLARE(channel_txs_lock_group, "sk_ch_txs_lock");
static LCK_GRP_DECLARE(channel_rxs_lock_group, "sk_ch_rxs_lock");
static LCK_GRP_DECLARE(channel_alloc_lock_group, "sk_ch_alloc_lock");
static LCK_GRP_DECLARE(channel_evq_lock_group, "sk_ch_evq_lock");
static LCK_GRP_DECLARE(channel_evs_lock_group, "sk_ch_evs_lock");

static lck_grp_t *
na_kr_q_lck_grp(enum txrx t)
{
	switch (t) {
	case NR_TX:
		return &channel_txq_lock_group;
	case NR_RX:
		return &channel_rxq_lock_group;
	case NR_A:
	case NR_F:
		return &channel_alloc_lock_group;
	case NR_EV:
		return &channel_evq_lock_group;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static lck_grp_t *
na_kr_s_lck_grp(enum txrx t)
{
	switch (t) {
	case NR_TX:
		return &channel_txs_lock_group;
	case NR_RX:
		return &channel_rxs_lock_group;
	case NR_A:
	case NR_F:
		return &channel_alloc_lock_group;
	case NR_EV:
		return &channel_evs_lock_group;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
}

static void
kr_init_tbr(struct __kern_channel_ring *r)
{
	r->ckr_tbr_depth = CKR_TBR_TOKEN_INVALID;
	r->ckr_tbr_token = CKR_TBR_TOKEN_INVALID;
	r->ckr_tbr_last = 0;
}

struct kern_pbufpool *
na_kr_get_pp(struct nexus_adapter *na, enum txrx t)
{
	struct kern_pbufpool *pp = NULL;
	switch (t) {
	case NR_RX:
	case NR_F:
	case NR_EV:
		pp = skmem_arena_nexus(na->na_arena)->arn_rx_pp;
		break;
	case NR_TX:
	case NR_A:
		pp = skmem_arena_nexus(na->na_arena)->arn_tx_pp;
		break;
	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	return pp;
}

/*
 * Create the krings array and initialize the fields common to all adapters.
 * The array layout is this:
 *
 *                       +----------+
 * na->na_tx_rings ----->|          | \
 *                       |          |  } na->num_tx_ring
 *                       |          | /
 * na->na_rx_rings ----> +----------+
 *                       |          | \
 *                       |          |  } na->na_num_rx_rings
 *                       |          | /
 * na->na_alloc_rings -> +----------+
 *                       |          | \
 * na->na_free_rings --> +----------+  } na->na_num_allocator_ring_pairs
 *                       |          | /
 * na->na_event_rings -> +----------+
 *                       |          | \
 *                       |          |  } na->na_num_event_rings
 *                       |          | /
 *                       +----------+
 * na->na_tailroom ----->|          | \
 *                       |          |  } tailroom bytes
 *                       |          | /
 *                       +----------+
 *
 * The tailroom space is currently used by flow switch ports for allocating
 * leases.
 */
/* call with SK_LOCK held */
static int
na_kr_create(struct nexus_adapter *na, uint32_t tailroom, boolean_t alloc_ctx)
{
	lck_grp_t *q_lck_grp, *s_lck_grp;
	uint32_t i, len, ndesc;
	struct kern_pbufpool *pp = NULL;
	struct __kern_channel_ring *kring;
	uint32_t n[NR_ALL];
	int c, tot_slots, err = 0;
	enum txrx t;

	SK_LOCK_ASSERT_HELD();

	n[NR_TX] = na_get_nrings(na, NR_TX);
	n[NR_RX] = na_get_nrings(na, NR_RX);
	n[NR_A] = na_get_nrings(na, NR_A);
	n[NR_F] = na_get_nrings(na, NR_F);
	n[NR_EV] = na_get_nrings(na, NR_EV);

	len = ((n[NR_TX] + n[NR_RX] + n[NR_A] + n[NR_F] + n[NR_EV]) *
	    sizeof(struct __kern_channel_ring)) + tailroom;

	na->na_rings_mem_sz = (size_t)len;
	na->na_tx_rings = sk_alloc((size_t)len, Z_WAITOK, skmem_tag_nx_rings);
	if (__improbable(na->na_tx_rings == NULL)) {
		SK_ERR("Cannot allocate krings");
		err = ENOMEM;
		goto error;
	}
	na->na_rx_rings = na->na_tx_rings + n[NR_TX];
	if (n[NR_A] != 0) {
		na->na_alloc_rings = na->na_rx_rings + n[NR_RX];
		na->na_free_rings = na->na_alloc_rings + n[NR_A];
	} else {
		na->na_alloc_rings = na->na_free_rings = NULL;
	}
	if (n[NR_EV] != 0) {
		if (na->na_free_rings != NULL) {
			na->na_event_rings = na->na_free_rings + n[NR_F];
		} else {
			na->na_event_rings = na->na_rx_rings + n[NR_RX];
		}
	}

	/* total number of slots for TX/RX adapter rings */
	c = tot_slots = (n[NR_TX] * na_get_nslots(na, NR_TX)) +
	    (n[NR_RX] * na_get_nslots(na, NR_RX));

	/* for scratch space on alloc and free rings */
	if (n[NR_A] != 0) {
		tot_slots += n[NR_A] * na_get_nslots(na, NR_A);
		tot_slots += n[NR_F] * na_get_nslots(na, NR_F);
		c = tot_slots;
	}
	na->na_total_slots = tot_slots;

	/* slot context (optional) for all TX/RX ring slots of this adapter */
	if (alloc_ctx) {
		na->na_slot_ctxs =
		    skn_alloc_type_array(slot_ctxs, struct slot_ctx,
		    na->na_total_slots, Z_WAITOK, skmem_tag_nx_contexts);
		if (na->na_slot_ctxs == NULL) {
			SK_ERR("Cannot allocate slot contexts");
			err = ENOMEM;
			goto error;
		}
		atomic_bitset_32(&na->na_flags, NAF_SLOT_CONTEXT);
	}

	/*
	 * packet handle array storage for all TX/RX ring slots of this
	 * adapter.
	 */
	na->na_scratch = skn_alloc_type_array(scratch, kern_packet_t,
	    na->na_total_slots, Z_WAITOK, skmem_tag_nx_scratch);
	if (na->na_scratch == NULL) {
		SK_ERR("Cannot allocate slot contexts");
		err = ENOMEM;
		goto error;
	}

	/*
	 * All fields in krings are 0 except the one initialized below.
	 * but better be explicit on important kring fields.
	 */
	for_all_rings(t) {
		ndesc = na_get_nslots(na, t);
		pp = na_kr_get_pp(na, t);
		for (i = 0; i < n[t]; i++) {
			kring = &NAKR(na, t)[i];
			bzero(kring, sizeof(*kring));
			kring->ckr_na = na;
			kring->ckr_pp = pp;
			kring->ckr_max_pkt_len = pp->pp_buflet_size *
			    pp->pp_max_frags;
			kring->ckr_ring_id = i;
			kring->ckr_tx = t;
			kr_init_to_mhints(kring, ndesc);
			kr_init_tbr(kring);
			if (NA_KERNEL_ONLY(na)) {
				kring->ckr_flags |= CKRF_KERNEL_ONLY;
			}
			if (na->na_flags & NAF_HOST_ONLY) {
				kring->ckr_flags |= CKRF_HOST;
			}
			ASSERT((t >= NR_TXRX) || (c > 0));
			if ((t < NR_TXRX) &&
			    (na->na_flags & NAF_SLOT_CONTEXT)) {
				ASSERT(na->na_slot_ctxs != NULL);
				kring->ckr_flags |= CKRF_SLOT_CONTEXT;
				kring->ckr_slot_ctxs =
				    na->na_slot_ctxs + (tot_slots - c);
			}
			ASSERT(na->na_scratch != NULL);
			if (t < NR_TXRXAF) {
				kring->ckr_scratch =
				    na->na_scratch + (tot_slots - c);
			}
			if (t < NR_TXRXAF) {
				c -= ndesc;
			}
			switch (t) {
			case NR_A:
				if (i == 0) {
					kring->ckr_na_sync =
					    na_packet_pool_alloc_sync;
					kring->ckr_alloc_ws =
					    na_upp_alloc_lowat;
				} else {
					ASSERT(i == 1);
					kring->ckr_na_sync =
					    na_packet_pool_alloc_buf_sync;
					kring->ckr_alloc_ws =
					    na_upp_alloc_buf_lowat;
				}
				break;
			case NR_F:
				if (i == 0) {
					kring->ckr_na_sync =
					    na_packet_pool_free_sync;
				} else {
					ASSERT(i == 1);
					kring->ckr_na_sync =
					    na_packet_pool_free_buf_sync;
				}
				break;
			case NR_TX:
				kring->ckr_na_sync = na->na_txsync;
				if (na->na_flags & NAF_TX_MITIGATION) {
					kring->ckr_flags |= CKRF_MITIGATION;
				}
				switch (na->na_type) {
#if CONFIG_NEXUS_USER_PIPE
				case NA_USER_PIPE:
					ASSERT(!(na->na_flags &
					    NAF_USER_PKT_POOL));
					kring->ckr_prologue = kr_txprologue;
					kring->ckr_finalize = NULL;
					break;
#endif /* CONFIG_NEXUS_USER_PIPE */
#if CONFIG_NEXUS_MONITOR
				case NA_MONITOR:
					ASSERT(!(na->na_flags &
					    NAF_USER_PKT_POOL));
					kring->ckr_prologue = kr_txprologue;
					kring->ckr_finalize = NULL;
					break;
#endif /* CONFIG_NEXUS_MONITOR */
				default:
					if (na->na_flags & NAF_USER_PKT_POOL) {
						kring->ckr_prologue =
						    kr_txprologue_upp;
						kring->ckr_finalize =
						    kr_txfinalize_upp;
					} else {
						kring->ckr_prologue =
						    kr_txprologue;
						kring->ckr_finalize =
						    kr_txfinalize;
					}
					break;
				}
				break;
			case NR_RX:
				kring->ckr_na_sync = na->na_rxsync;
				if (na->na_flags & NAF_RX_MITIGATION) {
					kring->ckr_flags |= CKRF_MITIGATION;
				}
				switch (na->na_type) {
#if CONFIG_NEXUS_USER_PIPE
				case NA_USER_PIPE:
					ASSERT(!(na->na_flags &
					    NAF_USER_PKT_POOL));
					kring->ckr_prologue =
					    kr_rxprologue_nodetach;
					kring->ckr_finalize = kr_rxfinalize;
					break;
#endif /* CONFIG_NEXUS_USER_PIPE */
#if CONFIG_NEXUS_MONITOR
				case NA_MONITOR:
					ASSERT(!(na->na_flags &
					    NAF_USER_PKT_POOL));
					kring->ckr_prologue =
					    kr_rxprologue_nodetach;
					kring->ckr_finalize = kr_rxfinalize;
					break;
#endif /* CONFIG_NEXUS_MONITOR */
				default:
					if (na->na_flags & NAF_USER_PKT_POOL) {
						kring->ckr_prologue =
						    kr_rxprologue_upp;
						kring->ckr_finalize =
						    kr_rxfinalize_upp;
					} else {
						kring->ckr_prologue =
						    kr_rxprologue;
						kring->ckr_finalize =
						    kr_rxfinalize;
					}
					break;
				}
				break;
			case NR_EV:
				kring->ckr_na_sync = kern_channel_event_sync;
				break;
			default:
				VERIFY(0);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			if (t != NR_EV) {
				kring->ckr_na_notify = na->na_notify;
			} else {
				kring->ckr_na_notify = NULL;
			}
			(void) snprintf(kring->ckr_name,
			    sizeof(kring->ckr_name) - 1,
			    "%s %s%u%s", na->na_name, sk_ring2str(t), i,
			    ((kring->ckr_flags & CKRF_HOST) ? "^" : ""));
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "kr \"%s\" (0x%llx) krflags 0x%b rh %u rt %u",
			    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
			    CKRF_BITS, kring->ckr_rhead, kring->ckr_rtail);
			kring->ckr_state = KR_READY;
			q_lck_grp = na_kr_q_lck_grp(t);
			s_lck_grp = na_kr_s_lck_grp(t);
			kring->ckr_qlock_group = q_lck_grp;
			lck_mtx_init(&kring->ckr_qlock, kring->ckr_qlock_group,
			    &channel_lock_attr);
			kring->ckr_slock_group = s_lck_grp;
			lck_spin_init(&kring->ckr_slock, kring->ckr_slock_group,
			    &channel_lock_attr);
			csi_init(&kring->ckr_si,
			    (kring->ckr_flags & CKRF_MITIGATION),
			    na->na_ch_mit_ival);
		}
		csi_init(&na->na_si[t],
		    (na->na_flags & (NAF_TX_MITIGATION | NAF_RX_MITIGATION)),
		    na->na_ch_mit_ival);
	}
	ASSERT(c == 0);
	na->na_tailroom = na->na_rx_rings + n[NR_RX] + n[NR_A] + n[NR_F];

	if (na->na_type == NA_NETIF_DEV) {
		na_kr_setup_netif_svc_map(na);
	}

	/* validate now for cases where we create only krings */
	na_krings_verify(na);
	return 0;

error:
	ASSERT(err != 0);
	if (na->na_tx_rings != NULL) {
		sk_free(na->na_tx_rings, na->na_rings_mem_sz);
		na->na_tx_rings = NULL;
	}
	if (na->na_slot_ctxs != NULL) {
		ASSERT(na->na_flags & NAF_SLOT_CONTEXT);
		skn_free_type_array(slot_ctxs,
		    struct slot_ctx, na->na_total_slots,
		    na->na_slot_ctxs);
		na->na_slot_ctxs = NULL;
	}
	if (na->na_scratch != NULL) {
		skn_free_type_array(scratch,
		    kern_packet_t, na->na_total_slots,
		    na->na_scratch);
		na->na_scratch = NULL;
	}
	return err;
}

/* undo the actions performed by na_kr_create() */
/* call with SK_LOCK held */
static void
na_kr_delete(struct nexus_adapter *na)
{
	struct __kern_channel_ring *kring = na->na_tx_rings;
	enum txrx t;

	ASSERT((kring != NULL) && (na->na_tailroom != NULL));
	SK_LOCK_ASSERT_HELD();

	for_all_rings(t) {
		csi_destroy(&na->na_si[t]);
	}
	/* we rely on the krings layout described above */
	for (; kring != na->na_tailroom; kring++) {
		lck_mtx_destroy(&kring->ckr_qlock, kring->ckr_qlock_group);
		lck_spin_destroy(&kring->ckr_slock, kring->ckr_slock_group);
		csi_destroy(&kring->ckr_si);
		if (kring->ckr_flags & CKRF_SLOT_CONTEXT) {
			kring->ckr_flags &= ~CKRF_SLOT_CONTEXT;
			ASSERT(kring->ckr_slot_ctxs != NULL);
			kring->ckr_slot_ctxs = NULL;
		}
	}
	if (na->na_slot_ctxs != NULL) {
		ASSERT(na->na_flags & NAF_SLOT_CONTEXT);
		atomic_bitclear_32(&na->na_flags, NAF_SLOT_CONTEXT);
		skn_free_type_array(slot_ctxs,
		    struct slot_ctx, na->na_total_slots,
		    na->na_slot_ctxs);
		na->na_slot_ctxs = NULL;
	}
	if (na->na_scratch != NULL) {
		skn_free_type_array(scratch,
		    kern_packet_t, na->na_total_slots,
		    na->na_scratch);
		na->na_scratch = NULL;
	}
	ASSERT(!(na->na_flags & NAF_SLOT_CONTEXT));
	sk_free(na->na_tx_rings, na->na_rings_mem_sz);
	na->na_tx_rings = na->na_rx_rings = na->na_alloc_rings =
	    na->na_free_rings = na->na_event_rings = na->na_tailroom = NULL;
}

static void
na_kr_slot_desc_init(struct __slot_desc *ksds,
    boolean_t kernel_only, struct __slot_desc *usds, size_t ndesc)
{
	size_t i;

	bzero(ksds, ndesc * SLOT_DESC_SZ);
	if (usds != NULL) {
		ASSERT(!kernel_only);
		bzero(usds, ndesc * SLOT_DESC_SZ);
	} else {
		ASSERT(kernel_only);
	}

	for (i = 0; i < ndesc; i++) {
		KSD_INIT(SLOT_DESC_KSD(&ksds[i]));
		if (!kernel_only) {
			USD_INIT(SLOT_DESC_USD(&usds[i]));
		}
	}
}

/* call with SK_LOCK held */
static int
na_kr_setup(struct nexus_adapter *na, struct kern_channel *ch)
{
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn;
	mach_vm_offset_t roff[SKMEM_REGIONS];
	enum txrx t;
	uint32_t i;

	SK_LOCK_ASSERT_HELD();
	ASSERT(!(na->na_flags & NAF_MEM_NO_INIT));
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);
	arn = skmem_arena_nexus(ar);
	ASSERT(arn != NULL);

	bzero(&roff, sizeof(roff));
	for (i = 0; i < SKMEM_REGIONS; i++) {
		if (ar->ar_regions[i] == NULL) {
			continue;
		}

		/* not for nexus */
		ASSERT(i != SKMEM_REGION_SYSCTLS);

		/*
		 * Get region offsets from base of mmap span; the arena
		 * doesn't need to be mmap'd at this point, since we
		 * simply compute the relative offset.
		 */
		roff[i] = skmem_arena_get_region_offset(ar, i);
	}

	for_all_rings(t) {
		for (i = 0; i < na_get_nrings(na, t); i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];
			struct __user_channel_ring *ring = kring->ckr_ring;
			mach_vm_offset_t ring_off, usd_roff;
			struct skmem_obj_info oi, oim;
			uint32_t ndesc;

			if (ring != NULL) {
				SK_DF(SK_VERB_NA | SK_VERB_RING,
				    "kr 0x%llx (\"%s\") is already "
				    "initialized", SK_KVA(kring),
				    kring->ckr_name);
				continue; /* already created by somebody else */
			}

			if (!KR_KERNEL_ONLY(kring) &&
			    (ring = skmem_cache_alloc(arn->arn_ring_cache,
			    SKMEM_NOSLEEP)) == NULL) {
				SK_ERR("Cannot allocate %s_ring for kr "
				    "0x%llx (\"%s\")", sk_ring2str(t),
				    SK_KVA(kring), kring->ckr_name);
				goto cleanup;
			}
			kring->ckr_flags |= CKRF_MEM_RING_INITED;
			kring->ckr_ring = ring;
			ndesc = kring->ckr_num_slots;

			if (ring == NULL) {
				goto skip_user_ring_setup;
			}

			*(uint32_t *)(uintptr_t)&ring->ring_num_slots = ndesc;

			/* offset of current ring in mmap span */
			skmem_cache_get_obj_info(arn->arn_ring_cache,
			    ring, &oi, NULL);
			ring_off = (roff[SKMEM_REGION_RING] +
			    SKMEM_OBJ_ROFF(&oi));

			/*
			 * ring_{buf,md,sd}_ofs offsets are relative to the
			 * current ring, and not to the base of mmap span.
			 */
			*(mach_vm_offset_t *)(uintptr_t)&ring->ring_buf_base =
			    (roff[SKMEM_REGION_BUF] - ring_off);
			*(mach_vm_offset_t *)(uintptr_t)&ring->ring_md_base =
			    (roff[SKMEM_REGION_UMD] - ring_off);
			_CASSERT(sizeof(uint16_t) ==
			    sizeof(ring->ring_bft_size));
			if (roff[SKMEM_REGION_UBFT] != 0) {
				ASSERT(ar->ar_regions[SKMEM_REGION_UBFT] !=
				    NULL);
				*(mach_vm_offset_t *)(uintptr_t)
				&ring->ring_bft_base =
				    (roff[SKMEM_REGION_UBFT] - ring_off);
				*(uint16_t *)(uintptr_t)&ring->ring_bft_size =
				    (uint16_t)ar->ar_regions[SKMEM_REGION_UBFT]->
				    skr_c_obj_size;
				ASSERT(ring->ring_bft_size ==
				    ar->ar_regions[SKMEM_REGION_KBFT]->
				    skr_c_obj_size);
			} else {
				*(mach_vm_offset_t *)(uintptr_t)
				&ring->ring_bft_base = 0;
				*(uint16_t *)(uintptr_t)&ring->ring_md_size = 0;
			}

			if (t == NR_TX || t == NR_A || t == NR_EV) {
				usd_roff = roff[SKMEM_REGION_TXAUSD];
			} else {
				ASSERT(t == NR_RX || t == NR_F);
				usd_roff = roff[SKMEM_REGION_RXFUSD];
			}
			*(mach_vm_offset_t *)(uintptr_t)&ring->ring_sd_base =
			    (usd_roff - ring_off);

			/* copy values from kring */
			ring->ring_head = kring->ckr_rhead;
			*(slot_idx_t *)(uintptr_t)&ring->ring_khead =
			    kring->ckr_khead;
			*(slot_idx_t *)(uintptr_t)&ring->ring_tail =
			    kring->ckr_rtail;

			_CASSERT(sizeof(uint32_t) ==
			    sizeof(ring->ring_buf_size));
			_CASSERT(sizeof(uint16_t) ==
			    sizeof(ring->ring_md_size));
			*(uint32_t *)(uintptr_t)&ring->ring_buf_size =
			    ar->ar_regions[SKMEM_REGION_BUF]->skr_c_obj_size;
			if (ar->ar_regions[SKMEM_REGION_UMD] != NULL) {
				*(uint16_t *)(uintptr_t)&ring->ring_md_size =
				    (uint16_t)ar->ar_regions[SKMEM_REGION_UMD]->
				    skr_c_obj_size;
				ASSERT(ring->ring_md_size ==
				    ar->ar_regions[SKMEM_REGION_KMD]->
				    skr_c_obj_size);
			} else {
				*(uint16_t *)(uintptr_t)&ring->ring_md_size = 0;
				ASSERT(PP_KERNEL_ONLY(arn->arn_rx_pp));
				ASSERT(PP_KERNEL_ONLY(arn->arn_tx_pp));
			}

			/* ring info */
			_CASSERT(sizeof(uint16_t) == sizeof(ring->ring_id));
			_CASSERT(sizeof(uint16_t) == sizeof(ring->ring_kind));
			*(uint16_t *)(uintptr_t)&ring->ring_id =
			    (uint16_t)kring->ckr_ring_id;
			*(uint16_t *)(uintptr_t)&ring->ring_kind =
			    (uint16_t)kring->ckr_tx;

			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "%s_ring at 0x%llx kr 0x%llx (\"%s\")",
			    sk_ring2str(t), SK_KVA(ring), SK_KVA(kring),
			    kring->ckr_name);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  num_slots:  %u", ring->ring_num_slots);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  buf_base:   0x%llx",
			    (uint64_t)ring->ring_buf_base);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  md_base:    0x%llx",
			    (uint64_t)ring->ring_md_base);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  sd_base:    0x%llx",
			    (uint64_t)ring->ring_sd_base);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  h, t:    %u, %u, %u", ring->ring_head,
			    ring->ring_tail);
			SK_DF(SK_VERB_NA | SK_VERB_RING,
			    "  md_size:    %d",
			    (uint64_t)ring->ring_md_size);

			/* make sure they're in synch */
			_CASSERT(NR_RX == CR_KIND_RX);
			_CASSERT(NR_TX == CR_KIND_TX);
			_CASSERT(NR_A == CR_KIND_ALLOC);
			_CASSERT(NR_F == CR_KIND_FREE);
			_CASSERT(NR_EV == CR_KIND_EVENT);

skip_user_ring_setup:
			/*
			 * This flag tells na_kr_teardown_all() that it should
			 * go thru the checks to free up the slot maps.
			 */
			kring->ckr_flags |= CKRF_MEM_SD_INITED;
			if (t == NR_TX || t == NR_A || t == NR_EV) {
				kring->ckr_ksds_cache = arn->arn_txaksd_cache;
			} else {
				ASSERT(t == NR_RX || t == NR_F);
				kring->ckr_ksds_cache = arn->arn_rxfksd_cache;
			}
			kring->ckr_ksds =
			    skmem_cache_alloc(kring->ckr_ksds_cache,
			    SKMEM_NOSLEEP);
			if (kring->ckr_ksds == NULL) {
				SK_ERR("Cannot allocate %s_ksds for kr "
				    "0x%llx (\"%s\")", sk_ring2str(t),
				    SK_KVA(kring), kring->ckr_name);
				goto cleanup;
			}
			if (!KR_KERNEL_ONLY(kring)) {
				skmem_cache_get_obj_info(kring->ckr_ksds_cache,
				    kring->ckr_ksds, &oi, &oim);
				kring->ckr_usds = SKMEM_OBJ_ADDR(&oim);
			}
			na_kr_slot_desc_init(kring->ckr_ksds,
			    KR_KERNEL_ONLY(kring), kring->ckr_usds, ndesc);

			/* cache last slot descriptor address */
			ASSERT(kring->ckr_lim == (ndesc - 1));
			kring->ckr_ksds_last = &kring->ckr_ksds[kring->ckr_lim];

			if ((t < NR_TXRX) &&
			    !(na->na_flags & NAF_USER_PKT_POOL) &&
			    na_kr_populate_slots(kring) != 0) {
				SK_ERR("Cannot allocate buffers for kr "
				    "0x%llx (\"%s\")", SK_KVA(kring),
				    kring->ckr_name);
				goto cleanup;
			}
		}
	}

	return 0;

cleanup:
	na_kr_teardown_all(na, ch, FALSE);

	return ENOMEM;
}

static void
na_kr_teardown_common(struct nexus_adapter *na,
    struct __kern_channel_ring *kring, enum txrx t, struct kern_channel *ch,
    boolean_t defunct)
{
	struct skmem_arena_nexus *arn = skmem_arena_nexus(na->na_arena);
	struct __user_channel_ring *ckr_ring;
	boolean_t sd_idle, sd_inited;

	ASSERT(arn != NULL);
	kr_enter(kring, TRUE);
	/*
	 * Check for CKRF_MEM_SD_INITED and CKRF_MEM_RING_INITED
	 * to make sure that the freeing needs to happen (else just
	 * nullify the values).
	 * If this adapter owns the memory for the slot descriptors,
	 * check if the region is marked as busy (sd_idle is false)
	 * and leave the kring's slot descriptor fields alone if so,
	 * at defunct time.  At final teardown time, sd_idle must be
	 * true else we assert; this indicates a missing call to
	 * skmem_arena_nexus_sd_set_noidle().
	 */
	sd_inited = ((kring->ckr_flags & CKRF_MEM_SD_INITED) != 0);
	if (sd_inited) {
		/* callee will do KR_KSD(), so check */
		if (((t < NR_TXRX) || (t == NR_EV)) &&
		    (kring->ckr_ksds != NULL)) {
			na_kr_depopulate_slots(kring, ch, defunct);
		}
		/* leave CKRF_MEM_SD_INITED flag alone until idle */
		sd_idle = skmem_arena_nexus_sd_idle(arn);
		VERIFY(sd_idle || defunct);
	} else {
		sd_idle = TRUE;
	}

	if (sd_idle) {
		kring->ckr_flags &= ~CKRF_MEM_SD_INITED;
		if (kring->ckr_ksds != NULL) {
			if (sd_inited) {
				skmem_cache_free(kring->ckr_ksds_cache,
				    kring->ckr_ksds);
			}
			kring->ckr_ksds = NULL;
			kring->ckr_ksds_last = NULL;
			kring->ckr_usds = NULL;
		}
		ASSERT(kring->ckr_ksds_last == NULL);
		ASSERT(kring->ckr_usds == NULL);
	}

	if ((ckr_ring = kring->ckr_ring) != NULL) {
		kring->ckr_ring = NULL;
	}

	if (kring->ckr_flags & CKRF_MEM_RING_INITED) {
		ASSERT(ckr_ring != NULL || KR_KERNEL_ONLY(kring));
		if (ckr_ring != NULL) {
			skmem_cache_free(arn->arn_ring_cache, ckr_ring);
		}
		kring->ckr_flags &= ~CKRF_MEM_RING_INITED;
	}

	if (defunct) {
		/* if defunct, drop everything; see KR_DROP() */
		kring->ckr_flags |= CKRF_DEFUNCT;
	}
	kr_exit(kring);
}

/*
 * Teardown ALL rings of a nexus adapter; this includes {tx,rx,alloc,free,event}
 */
static void
na_kr_teardown_all(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	enum txrx t;

	ASSERT(na->na_arena->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	/* skip if this adapter has no allocated rings */
	if (na->na_tx_rings == NULL) {
		return;
	}

	for_all_rings(t) {
		for (uint32_t i = 0; i < na_get_nrings(na, t); i++) {
			na_kr_teardown_common(na, &NAKR(na, t)[i],
			    t, ch, defunct);
		}
	}
}

/*
 * Teardown only {tx,rx} rings assigned to the channel.
 */
static void
na_kr_teardown_txrx(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct, struct proc *p)
{
	enum txrx t;

	ASSERT(na->na_arena->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	for_rx_tx(t) {
		ring_id_t qfirst = ch->ch_first[t];
		ring_id_t qlast = ch->ch_last[t];
		uint32_t i;

		for (i = qfirst; i < qlast; i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];
			na_kr_teardown_common(na, kring, t, ch, defunct);

			/*
			 * Issue a notify to wake up anyone sleeping in kqueue
			 * so that they notice the newly defuncted channels and
			 * return an error
			 */
			kring->ckr_na_notify(kring, p, 0);
		}
	}
}

static int
na_kr_populate_slots(struct __kern_channel_ring *kring)
{
	const boolean_t kernel_only = KR_KERNEL_ONLY(kring);
	struct nexus_adapter *na = KRNA(kring);
	kern_pbufpool_t pp = kring->ckr_pp;
	uint32_t nslots = kring->ckr_num_slots;
	uint32_t start_idx, i;
	uint32_t sidx = 0;      /* slot counter */
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_quantum *kqum;
	nexus_type_t nexus_type;
	int err = 0;

	ASSERT(kring->ckr_tx < NR_TXRX);
	ASSERT(!(KRNA(kring)->na_flags & NAF_USER_PKT_POOL));
	ASSERT(na->na_arena->ar_type == SKMEM_ARENA_TYPE_NEXUS);
	ASSERT(pp != NULL);

	/*
	 * xxx_ppool: remove this special case
	 */
	nexus_type = na->na_nxdom_prov->nxdom_prov_dom->nxdom_type;

	switch (nexus_type) {
	case NEXUS_TYPE_FLOW_SWITCH:
	case NEXUS_TYPE_KERNEL_PIPE:
		/*
		 * xxx_ppool: This is temporary code until we come up with a
		 * scheme for user space to alloc & attach packets to tx ring.
		 */
		if (kernel_only || kring->ckr_tx == NR_RX) {
			return 0;
		}
		break;

	case NEXUS_TYPE_NET_IF:
		if (((na->na_type == NA_NETIF_DEV) ||
		    (na->na_type == NA_NETIF_HOST)) &&
		    (kernel_only || (kring->ckr_tx == NR_RX))) {
			return 0;
		}

		ASSERT((na->na_type == NA_NETIF_COMPAT_DEV) ||
		    (na->na_type == NA_NETIF_COMPAT_HOST) ||
		    (na->na_type == NA_NETIF_DEV) ||
		    (na->na_type == NA_NETIF_VP));

		if (!kernel_only) {
			if (kring->ckr_tx == NR_RX) {
				return 0;
			} else {
				break;
			}
		}

		ASSERT(kernel_only);

		if ((na->na_type == NA_NETIF_COMPAT_DEV) ||
		    (na->na_type == NA_NETIF_COMPAT_HOST)) {
			return 0;
		}
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();

	case NEXUS_TYPE_USER_PIPE:
	case NEXUS_TYPE_MONITOR:
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	/* Fill the ring with packets */
	sidx = start_idx = 0;
	for (i = 0; i < nslots; i++) {
		kqum = SK_PTR_ADDR_KQUM(pp_alloc_packet(pp, pp->pp_max_frags,
		    SKMEM_NOSLEEP));
		if (kqum == NULL) {
			err = ENOMEM;
			SK_ERR("ar 0x%llx (\"%s\") no more buffers "
			    "after %u of %u, err %d", SK_KVA(na->na_arena),
			    na->na_arena->ar_name, i, nslots, err);
			goto cleanup;
		}
		ksd = KR_KSD(kring, i);
		usd = (kernel_only ? NULL : KR_USD(kring, i));

		/* attach packet to slot */
		kqum->qum_ksd = ksd;
		ASSERT(!KSD_VALID_METADATA(ksd));
		KSD_ATTACH_METADATA(ksd, kqum);
		if (usd != NULL) {
			USD_ATTACH_METADATA(usd, METADATA_IDX(kqum));
			kr_externalize_metadata(kring, pp->pp_max_frags,
			    kqum, current_proc());
		}

		SK_DF(SK_VERB_MEM, " C ksd [%-3d, 0x%llx] kqum [%-3u, 0x%llx] "
		    " kbuf[%-3u, 0x%llx]", i, SK_KVA(ksd), METADATA_IDX(kqum),
		    SK_KVA(kqum), kqum->qum_buf[0].buf_idx,
		    SK_KVA(&kqum->qum_buf[0]));
		if (!(kqum->qum_qflags & QUM_F_KERNEL_ONLY)) {
			SK_DF(SK_VERB_MEM, " C usd [%-3d, 0x%llx] "
			    "uqum [%-3u, 0x%llx]  ubuf[%-3u, 0x%llx]",
			    (int)(usd ? usd->sd_md_idx : OBJ_IDX_NONE),
			    SK_KVA(usd), METADATA_IDX(kqum),
			    SK_KVA(kqum->qum_user),
			    kqum->qum_user->qum_buf[0].buf_idx,
			    SK_KVA(&kqum->qum_user->qum_buf[0]));
		}

		sidx = SLOT_NEXT(sidx, kring->ckr_lim);
	}

	SK_DF(SK_VERB_NA | SK_VERB_RING, "ar 0x%llx (\"%s\") populated %u slots from idx %u",
	    SK_KVA(na->na_arena), na->na_arena->ar_name, nslots, start_idx);

cleanup:
	if (err != 0) {
		sidx = start_idx;
		while (i-- > 0) {
			ksd = KR_KSD(kring, i);
			usd = (kernel_only ? NULL : KR_USD(kring, i));
			kqum = ksd->sd_qum;

			ASSERT(ksd == kqum->qum_ksd);
			KSD_RESET(ksd);
			if (usd != NULL) {
				USD_RESET(usd);
			}
			/* detach packet from slot */
			kqum->qum_ksd = NULL;
			pp_free_packet(pp, SK_PTR_ADDR(kqum));

			sidx = SLOT_NEXT(sidx, kring->ckr_lim);
		}
	}
	return err;
}

static void
na_kr_depopulate_slots(struct __kern_channel_ring *kring,
    struct kern_channel *ch, boolean_t defunct)
{
#pragma unused(ch)
	const boolean_t kernel_only = KR_KERNEL_ONLY(kring);
	uint32_t i, j, n = kring->ckr_num_slots;
	struct nexus_adapter *na = KRNA(kring);
	struct kern_pbufpool *pp = kring->ckr_pp;
	boolean_t upp = FALSE;
	obj_idx_t midx;

	ASSERT((kring->ckr_tx < NR_TXRX) || (kring->ckr_tx == NR_EV));
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	ASSERT(na->na_arena->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	if (((na->na_flags & NAF_USER_PKT_POOL) != 0) &&
	    (kring->ckr_tx != NR_EV)) {
		upp = TRUE;
	}
	for (i = 0, j = 0; i < n; i++) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, i);
		struct __user_slot_desc *usd;
		struct __kern_quantum *qum, *kqum;
		boolean_t free_packet = FALSE;
		int err;

		if (!KSD_VALID_METADATA(ksd)) {
			continue;
		}

		kqum = ksd->sd_qum;
		usd = (kernel_only ? NULL : KR_USD(kring, i));
		midx = METADATA_IDX(kqum);

		/*
		 * if the packet is internalized it should not be in the
		 * hash table of packets loaned to user space.
		 */
		if (upp && (kqum->qum_qflags & QUM_F_INTERNALIZED)) {
			if ((qum = pp_find_upp(pp, midx)) != NULL) {
				panic("internalized packet 0x%llx in htbl",
				    SK_KVA(qum));
				/* NOTREACHED */
				__builtin_unreachable();
			}
			free_packet = TRUE;
		} else if (upp) {
			/*
			 * if the packet is not internalized check if it is
			 * in the list of packets loaned to user-space.
			 * Remove from the list before freeing.
			 */
			ASSERT(!(kqum->qum_qflags & QUM_F_INTERNALIZED));
			qum = pp_remove_upp(pp, midx, &err);
			if (err != 0) {
				SK_ERR("un-allocated packet or buflet %d %p",
				    midx, SK_KVA(qum));
				if (qum != NULL) {
					free_packet = TRUE;
				}
			}
		} else {
			free_packet = TRUE;
		}

		/*
		 * Clear the user and kernel slot descriptors.  Note that
		 * if we are depopulating the slots due to defunct (and not
		 * due to normal deallocation/teardown), we leave the user
		 * slot descriptor alone.  At that point the process may
		 * be suspended, and later when it resumes it would just
		 * pick up the original contents and move forward with
		 * whatever it was doing.
		 */
		KSD_RESET(ksd);
		if (usd != NULL && !defunct) {
			USD_RESET(usd);
		}

		/* detach packet from slot */
		kqum->qum_ksd = NULL;

		SK_DF(SK_VERB_MEM, " D ksd [%-3d, 0x%llx] kqum [%-3u, 0x%llx] "
		    " kbuf[%-3u, 0x%llx]", i, SK_KVA(ksd),
		    METADATA_IDX(kqum), SK_KVA(kqum), kqum->qum_buf[0].buf_idx,
		    SK_KVA(&kqum->qum_buf[0]));
		if (!(kqum->qum_qflags & QUM_F_KERNEL_ONLY)) {
			SK_DF(SK_VERB_MEM, " D usd [%-3u, 0x%llx] "
			    "uqum [%-3u, 0x%llx]  ubuf[%-3u, 0x%llx]",
			    (int)(usd ? usd->sd_md_idx : OBJ_IDX_NONE),
			    SK_KVA(usd), METADATA_IDX(kqum),
			    SK_KVA(kqum->qum_user),
			    kqum->qum_user->qum_buf[0].buf_idx,
			    SK_KVA(&kqum->qum_user->qum_buf[0]));
		}

		if (free_packet) {
			pp_free_packet(pp, SK_PTR_ADDR(kqum)); ++j;
		}
	}

	SK_DF(SK_VERB_NA | SK_VERB_RING, "ar 0x%llx (\"%s\") depopulated %u of %u slots",
	    SK_KVA(KRNA(kring)->na_arena), KRNA(kring)->na_arena->ar_name,
	    j, n);
}

int
na_rings_mem_setup(struct nexus_adapter *na, uint32_t tailroom,
    boolean_t alloc_ctx, struct kern_channel *ch)
{
	boolean_t kronly;
	int err;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_channels == 0);
	/*
	 * If NAF_MEM_NO_INIT is set, then only create the krings and not
	 * the backing memory regions for the adapter.
	 */
	kronly = (na->na_flags & NAF_MEM_NO_INIT);
	ASSERT(!kronly || NA_KERNEL_ONLY(na));

	/*
	 * Create and initialize the common fields of the krings array.
	 * using the information that must be already available in the na.
	 * tailroom can be used to request the allocation of additional
	 * tailroom bytes after the krings array.  This is used by
	 * nexus_vp_adapter's (i.e., flow switch ports) to make room
	 * for leasing-related data structures.
	 */
	if ((err = na_kr_create(na, tailroom, alloc_ctx)) == 0 && !kronly) {
		err = na_kr_setup(na, ch);
		if (err != 0) {
			na_kr_delete(na);
		}
	}

	return err;
}

void
na_rings_mem_teardown(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_channels == 0 || (na->na_flags & NAF_DEFUNCT));

	/*
	 * Deletes the kring and ring array of the adapter. They
	 * must have been created using na_rings_mem_setup().
	 *
	 * XXX: adi@apple.com -- the parameter "ch" should not be
	 * needed here; however na_kr_depopulate_slots() needs to
	 * go thru the channel's user packet pool hash, and so for
	 * now we leave it here.
	 */
	na_kr_teardown_all(na, ch, defunct);
	if (!defunct) {
		na_kr_delete(na);
	}
}

void
na_ch_rings_defunct(struct kern_channel *ch, struct proc *p)
{
	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	/*
	 * Depopulate slots on the TX and RX rings of this channel,
	 * but don't touch other rings owned by other channels if
	 * this adapter is being shared.
	 */
	na_kr_teardown_txrx(ch->ch_na, ch, TRUE, p);
}

void
na_kr_drop(struct nexus_adapter *na, boolean_t drop)
{
	enum txrx t;
	uint32_t i;

	for_rx_tx(t) {
		for (i = 0; i < na_get_nrings(na, t); i++) {
			struct __kern_channel_ring *kring = &NAKR(na, t)[i];
			int error;
			error = kr_enter(kring, TRUE);
			if (drop) {
				kring->ckr_flags |= CKRF_DROP;
			} else {
				kring->ckr_flags &= ~CKRF_DROP;
			}

			if (error != 0) {
				SK_ERR("na \"%s\" (0x%llx) kr \"%s\" (0x%llx) "
				    "kr_enter failed %d",
				    na->na_name, SK_KVA(na),
				    kring->ckr_name, SK_KVA(kring),
				    error);
			} else {
				kr_exit(kring);
			}
			SK_D("na \"%s\" (0x%llx) kr \"%s\" (0x%llx) "
			    "krflags 0x%b", na->na_name, SK_KVA(na),
			    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
			    CKRF_BITS);
		}
	}
}

/*
 * Set the stopped/enabled status of ring.  When stopping, they also wait
 * for all current activity on the ring to terminate.  The status change
 * is then notified using the na na_notify callback.
 */
static void
na_set_ring(struct nexus_adapter *na, uint32_t ring_id, enum txrx t,
    uint32_t state)
{
	struct __kern_channel_ring *kr = &NAKR(na, t)[ring_id];

	/*
	 * Mark the ring as stopped/enabled, and run through the
	 * locks to make sure other users get to see it.
	 */
	if (state == KR_READY) {
		kr_start(kr);
	} else {
		kr_stop(kr, state);
	}
}


/* stop or enable all the rings of na */
static void
na_set_all_rings(struct nexus_adapter *na, uint32_t state)
{
	uint32_t i;
	enum txrx t;

	SK_LOCK_ASSERT_HELD();

	if (!NA_IS_ACTIVE(na)) {
		return;
	}

	for_rx_tx(t) {
		for (i = 0; i < na_get_nrings(na, t); i++) {
			na_set_ring(na, i, t, state);
		}
	}
}

/*
 * Convenience function used in drivers.  Waits for current txsync()s/rxsync()s
 * to finish and prevents any new one from starting.  Call this before turning
 * Skywalk mode off, or before removing the harware rings (e.g., on module
 * onload).  As a rule of thumb for linux drivers, this should be placed near
 * each napi_disable().
 */
void
na_disable_all_rings(struct nexus_adapter *na)
{
	na_set_all_rings(na, KR_STOPPED);
}

/*
 * Convenience function used in drivers.  Re-enables rxsync and txsync on the
 * adapter's rings In linux drivers, this should be placed near each
 * napi_enable().
 */
void
na_enable_all_rings(struct nexus_adapter *na)
{
	na_set_all_rings(na, KR_READY /* enabled */);
}

void
na_lock_all_rings(struct nexus_adapter *na)
{
	na_set_all_rings(na, KR_LOCKED);
}

void
na_unlock_all_rings(struct nexus_adapter *na)
{
	na_enable_all_rings(na);
}

int
na_connect(struct kern_nexus *nx, struct kern_channel *ch, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p)
{
	struct nexus_adapter *na = NULL;
	mach_vm_size_t memsize = 0;
	int err = 0;
	enum txrx t;

	ASSERT(!(chr->cr_mode & CHMODE_KERNEL));
	ASSERT(!(ch->ch_flags & CHANF_KERNEL));

	SK_LOCK_ASSERT_HELD();

	/* find the nexus adapter and return the reference */
	err = na_find(ch, nx, chr, ch0, nxb, p, &na, TRUE /* create */);
	if (err != 0) {
		ASSERT(na == NULL);
		goto done;
	}

	if (NA_KERNEL_ONLY(na)) {
		err = EBUSY;
		goto done;
	}

	/* reject if the adapter is defunct of non-permissive */
	if ((na->na_flags & NAF_DEFUNCT) || na_reject_channel(ch, na)) {
		err = ENXIO;
		goto done;
	}

	err = na_bind_channel(na, ch, chr);
	if (err != 0) {
		goto done;
	}

	ASSERT(ch->ch_schema != NULL);
	ASSERT(na == ch->ch_na);

	for_all_rings(t) {
		if (na_get_nrings(na, t) == 0) {
			ch->ch_si[t] = NULL;
			continue;
		}
		ch->ch_si[t] = ch_is_multiplex(ch, t) ? &na->na_si[t] :
		    &NAKR(na, t)[ch->ch_first[t]].ckr_si;
	}

	skmem_arena_get_stats(na->na_arena, &memsize, NULL);

	if (!(skmem_arena_nexus(na->na_arena)->arn_mode &
	    AR_NEXUS_MODE_EXTERNAL_PPOOL)) {
		atomic_bitset_32(__DECONST(uint32_t *,
		    &ch->ch_schema->csm_flags), CSM_PRIV_MEM);
	}

	err = skmem_arena_mmap(na->na_arena, p, &ch->ch_mmap);
	if (err != 0) {
		goto done;
	}

	atomic_bitset_32(__DECONST(uint32_t *, &ch->ch_schema->csm_flags),
	    CSM_ACTIVE);
	chr->cr_memsize = memsize;
	chr->cr_memoffset = ch->ch_schema_offset;

	SK_D("%s(%d) ch 0x%llx <-> nx 0x%llx (%s:\"%s\":%d:%d) na 0x%llx "
	    "naflags %b", sk_proc_name_address(p), sk_proc_pid(p),
	    SK_KVA(ch), SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
	    na->na_name, (int)chr->cr_port, (int)chr->cr_ring_id, SK_KVA(na),
	    na->na_flags, NAF_BITS);

done:
	if (err != 0) {
		if (ch->ch_schema != NULL || na != NULL) {
			if (ch->ch_schema != NULL) {
				ASSERT(na == ch->ch_na);
				/*
				 * Callee will unmap memory region if needed,
				 * as well as release reference held on 'na'.
				 */
				na_disconnect(nx, ch);
				na = NULL;
			}
			if (na != NULL) {
				(void) na_release_locked(na);
				na = NULL;
			}
		}
	}

	return err;
}

void
na_disconnect(struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nx)
	enum txrx t;

	SK_LOCK_ASSERT_HELD();

	SK_D("ch 0x%llx -!- nx 0x%llx (%s:\"%s\":%u:%d) na 0x%llx naflags %b",
	    SK_KVA(ch), SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
	    ch->ch_na->na_name, ch->ch_info->cinfo_nx_port,
	    (int)ch->ch_info->cinfo_ch_ring_id, SK_KVA(ch->ch_na),
	    ch->ch_na->na_flags, NAF_BITS);

	/* destroy mapping and release references */
	na_unbind_channel(ch);
	ASSERT(ch->ch_na == NULL);
	ASSERT(ch->ch_schema == NULL);
	for_all_rings(t) {
		ch->ch_si[t] = NULL;
	}
}

void
na_defunct(struct kern_nexus *nx, struct kern_channel *ch,
    struct nexus_adapter *na, boolean_t locked)
{
#pragma unused(nx)
	SK_LOCK_ASSERT_HELD();
	if (!locked) {
		lck_mtx_lock(&ch->ch_lock);
	}

	LCK_MTX_ASSERT(&ch->ch_lock, LCK_MTX_ASSERT_OWNED);

	if (!(na->na_flags & NAF_DEFUNCT)) {
		/*
		 * Mark this adapter as defunct to inform nexus-specific
		 * teardown handler called by na_teardown() below.
		 */
		atomic_bitset_32(&na->na_flags, NAF_DEFUNCT);

		/*
		 * Depopulate slots.
		 */
		na_teardown(na, ch, TRUE);

		/*
		 * And finally destroy any already-defunct memory regions.
		 * Do this only if the nexus adapter owns the arena, i.e.
		 * NAF_MEM_LOANED is not set.  Otherwise, we'd expect
		 * that this routine be called again for the real owner.
		 */
		if (!(na->na_flags & NAF_MEM_LOANED)) {
			skmem_arena_defunct(na->na_arena);
		}
	}

	SK_D("%s(%d): ch 0x%llx -/- nx 0x%llx (%s:\"%s\":%u:%d) "
	    "na 0x%llx naflags %b", ch->ch_name, ch->ch_pid,
	    SK_KVA(ch), SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
	    na->na_name, ch->ch_info->cinfo_nx_port,
	    (int)ch->ch_info->cinfo_ch_ring_id, SK_KVA(na),
	    na->na_flags, NAF_BITS);

	if (!locked) {
		lck_mtx_unlock(&ch->ch_lock);
	}
}

/*
 * TODO: adi@apple.com -- merge this into na_connect()
 */
int
na_connect_spec(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct proc *p)
{
#pragma unused(p)
	struct nexus_adapter *na = NULL;
	mach_vm_size_t memsize = 0;
	int error = 0;
	enum txrx t;

	ASSERT(chr->cr_mode & CHMODE_KERNEL);
	ASSERT(ch->ch_flags & CHANF_KERNEL);
	ASSERT(ch->ch_na == NULL);
	ASSERT(ch->ch_schema == NULL);

	SK_LOCK_ASSERT_HELD();

	error = na_find(ch, nx, chr, NULL, NULL, kernproc, &na, TRUE);
	if (error != 0) {
		goto done;
	}

	if (na == NULL) {
		error = EINVAL;
		goto done;
	}

	if (na->na_channels > 0) {
		error = EBUSY;
		goto done;
	}

	if (na->na_flags & NAF_DEFUNCT) {
		error = ENXIO;
		goto done;
	}

	/*
	 * Special connect requires the nexus adapter to handle its
	 * own channel binding and unbinding via na_special(); bail
	 * if this adapter doesn't support it.
	 */
	if (na->na_special == NULL) {
		error = ENOTSUP;
		goto done;
	}

	/* upon success, "ch->ch_na" will point to "na" */
	error = na->na_special(na, ch, chr, NXSPEC_CMD_CONNECT);
	if (error != 0) {
		ASSERT(ch->ch_na == NULL);
		goto done;
	}

	ASSERT(na->na_flags & NAF_SPEC_INIT);
	ASSERT(na == ch->ch_na);
	/* make sure this is still the case */
	ASSERT(ch->ch_schema == NULL);

	for_rx_tx(t) {
		ch->ch_si[t] = ch_is_multiplex(ch, t) ? &na->na_si[t] :
		    &NAKR(na, t)[ch->ch_first[t]].ckr_si;
	}

	skmem_arena_get_stats(na->na_arena, &memsize, NULL);
	chr->cr_memsize = memsize;

	SK_D("%s(%d) ch 0x%llx <-> nx 0x%llx (%s:\"%s\":%d:%d) na 0x%llx "
	    "naflags %b", sk_proc_name_address(p), sk_proc_pid(p),
	    SK_KVA(ch), SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
	    na->na_name, (int)chr->cr_port, (int)chr->cr_ring_id, SK_KVA(na),
	    na->na_flags, NAF_BITS);

done:
	if (error != 0) {
		if (ch->ch_na != NULL || na != NULL) {
			if (ch->ch_na != NULL) {
				ASSERT(na == ch->ch_na);
				/* callee will release reference on 'na' */
				na_disconnect_spec(nx, ch);
				na = NULL;
			}
			if (na != NULL) {
				(void) na_release_locked(na);
				na = NULL;
			}
		}
	}

	return error;
}

/*
 * TODO: adi@apple.com -- merge this into na_disconnect()
 */
void
na_disconnect_spec(struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nx)
	struct nexus_adapter *na = ch->ch_na;
	enum txrx t;
	int error;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na != NULL);
	ASSERT(na->na_flags & NAF_SPEC_INIT);   /* has been bound */

	SK_D("ch 0x%llx -!- nx 0x%llx (%s:\"%s\":%u:%d) na 0x%llx naflags %b",
	    SK_KVA(ch), SK_KVA(nx), NX_DOM_PROV(nx)->nxdom_prov_name,
	    na->na_name, ch->ch_info->cinfo_nx_port,
	    (int)ch->ch_info->cinfo_ch_ring_id, SK_KVA(na),
	    na->na_flags, NAF_BITS);

	/* take a reference for this routine */
	na_retain_locked(na);

	ASSERT(ch->ch_flags & CHANF_KERNEL);
	ASSERT(ch->ch_schema == NULL);
	ASSERT(na->na_special != NULL);
	/* unbind this channel */
	error = na->na_special(na, ch, NULL, NXSPEC_CMD_DISCONNECT);
	ASSERT(error == 0);
	ASSERT(!(na->na_flags & NAF_SPEC_INIT));

	/* now release our reference; this may be the last */
	na_release_locked(na);
	na = NULL;

	ASSERT(ch->ch_na == NULL);
	for_rx_tx(t) {
		ch->ch_si[t] = NULL;
	}
}

void
na_start_spec(struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nx)
	struct nexus_adapter *na = ch->ch_na;

	SK_LOCK_ASSERT_HELD();

	ASSERT(ch->ch_flags & CHANF_KERNEL);
	ASSERT(NA_KERNEL_ONLY(na));
	ASSERT(na->na_special != NULL);

	na->na_special(na, ch, NULL, NXSPEC_CMD_START);
}

void
na_stop_spec(struct kern_nexus *nx, struct kern_channel *ch)
{
#pragma unused(nx)
	struct nexus_adapter *na = ch->ch_na;

	SK_LOCK_ASSERT_HELD();

	ASSERT(ch->ch_flags & CHANF_KERNEL);
	ASSERT(NA_KERNEL_ONLY(na));
	ASSERT(na->na_special != NULL);

	na->na_special(na, ch, NULL, NXSPEC_CMD_STOP);
}

/*
 * MUST BE CALLED UNDER SK_LOCK()
 *
 * Get a refcounted reference to a nexus adapter attached
 * to the interface specified by chr.
 * This is always called in the execution of an ioctl().
 *
 * Return ENXIO if the interface specified by the request does
 * not exist, ENOTSUP if Skywalk is not supported by the interface,
 * EINVAL if parameters are invalid, ENOMEM if needed resources
 * could not be allocated.
 * If successful, hold a reference to the nexus adapter.
 *
 * No reference is kept on the real interface, which may then
 * disappear at any time.
 */
int
na_find(struct kern_channel *ch, struct kern_nexus *nx, struct chreq *chr,
    struct kern_channel *ch0, struct nxbind *nxb, struct proc *p,
    struct nexus_adapter **na, boolean_t create)
{
	int error = 0;

	_CASSERT(sizeof(chr->cr_name) == sizeof((*na)->na_name));

	*na = NULL;     /* default return value */

	SK_LOCK_ASSERT_HELD();

	/*
	 * We cascade through all possibile types of nexus adapter.
	 * All nx_*_na_find() functions return an error and an na,
	 * with the following combinations:
	 *
	 * error    na
	 *   0	   NULL		type doesn't match
	 *  !0	   NULL		type matches, but na creation/lookup failed
	 *   0	  !NULL		type matches and na created/found
	 *  !0    !NULL		impossible
	 */

#if CONFIG_NEXUS_MONITOR
	/* try to see if this is a monitor port */
	error = nx_monitor_na_find(nx, ch, chr, ch0, nxb, p, na, create);
	if (error != 0 || *na != NULL) {
		return error;
	}
#endif /* CONFIG_NEXUS_MONITOR */
#if CONFIG_NEXUS_USER_PIPE
	/* try to see if this is a pipe port */
	error = nx_upipe_na_find(nx, ch, chr, nxb, p, na, create);
	if (error != 0 || *na != NULL) {
		return error;
	}
#endif /* CONFIG_NEXUS_USER_PIPE */
#if CONFIG_NEXUS_KERNEL_PIPE
	/* try to see if this is a kernel pipe port */
	error = nx_kpipe_na_find(nx, ch, chr, nxb, p, na, create);
	if (error != 0 || *na != NULL) {
		return error;
	}
#endif /* CONFIG_NEXUS_KERNEL_PIPE */
#if CONFIG_NEXUS_FLOWSWITCH
	/* try to see if this is a flowswitch port */
	error = nx_fsw_na_find(nx, ch, chr, nxb, p, na, create);
	if (error != 0 || *na != NULL) {
		return error;
	}
#endif /* CONFIG_NEXUS_FLOWSWITCH */
#if CONFIG_NEXUS_NETIF
	error = nx_netif_na_find(nx, ch, chr, nxb, p, na, create);
	if (error != 0 || *na != NULL) {
		return error;
	}
#endif /* CONFIG_NEXUS_NETIF */

	ASSERT(*na == NULL);
	return ENXIO;
}

void
na_retain_locked(struct nexus_adapter *na)
{
	SK_LOCK_ASSERT_HELD();

	if (na != NULL) {
#if SK_LOG
		uint32_t oref = atomic_add_32_ov(&na->na_refcount, 1);
		SK_DF(SK_VERB_REFCNT, "na \"%s\" (0x%llx) refcnt %u chcnt %u",
		    na->na_name, SK_KVA(na), oref + 1, na->na_channels);
#else /* !SK_LOG */
		atomic_add_32(&na->na_refcount, 1);
#endif /* !SK_LOG */
	}
}

/* returns 1 iff the nexus_adapter is destroyed */
int
na_release_locked(struct nexus_adapter *na)
{
	uint32_t oref;

	SK_LOCK_ASSERT_HELD();

	ASSERT(na->na_refcount > 0);
	oref = atomic_add_32_ov(&na->na_refcount, -1);
	if (oref > 1) {
		SK_DF(SK_VERB_REFCNT, "na \"%s\" (0x%llx) refcnt %u chcnt %u",
		    na->na_name, SK_KVA(na), oref - 1, na->na_channels);
		return 0;
	}
	ASSERT(na->na_channels == 0);

	if (na->na_dtor != NULL) {
		na->na_dtor(na);
	}

	ASSERT(na->na_tx_rings == NULL && na->na_rx_rings == NULL);
	ASSERT(na->na_slot_ctxs == NULL);
	ASSERT(na->na_scratch == NULL);

#if CONFIG_NEXUS_USER_PIPE
	nx_upipe_na_dealloc(na);
#endif /* CONFIG_NEXUS_USER_PIPE */
	if (na->na_arena != NULL) {
		skmem_arena_release(na->na_arena);
		na->na_arena = NULL;
	}

	SK_DF(SK_VERB_MEM, "na \"%s\" (0x%llx) being freed",
	    na->na_name, SK_KVA(na));

	NA_FREE(na);
	return 1;
}

static struct nexus_adapter *
na_pseudo_alloc(zalloc_flags_t how)
{
	struct nexus_adapter *na;

	na = zalloc_flags(na_pseudo_zone, how | Z_ZERO);
	if (na) {
		na->na_type = NA_PSEUDO;
		na->na_free = na_pseudo_free;
	}
	return na;
}

static void
na_pseudo_free(struct nexus_adapter *na)
{
	ASSERT(na->na_refcount == 0);
	SK_DF(SK_VERB_MEM, "na 0x%llx FREE", SK_KVA(na));
	bzero(na, sizeof(*na));
	zfree(na_pseudo_zone, na);
}

static int
na_pseudo_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(kring, p, flags)
	SK_DF(SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	return 0;
}

static int
na_pseudo_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(kring, p, flags)
	SK_DF(SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	ASSERT(kring->ckr_rhead <= kring->ckr_lim);

	return 0;
}

static int
na_pseudo_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	SK_D("na \"%s\" (0x%llx) %s", na->na_name,
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
na_pseudo_dtor(struct nexus_adapter *na)
{
#pragma unused(na)
}

static int
na_pseudo_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	return na_rings_mem_setup(na, 0, FALSE, ch);
}

static void
na_pseudo_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	na_rings_mem_teardown(na, ch, defunct);
}

/*
 * Pseudo nexus adapter; typically used as a generic parent adapter.
 */
int
na_pseudo_create(struct kern_nexus *nx, struct chreq *chr,
    struct nexus_adapter **ret)
{
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_adapter *na;
	int error;

	SK_LOCK_ASSERT_HELD();
	*ret = NULL;

	na = na_pseudo_alloc(Z_WAITOK);

	ASSERT(na->na_type == NA_PSEUDO);
	ASSERT(na->na_free == na_pseudo_free);

	(void) strncpy(na->na_name, chr->cr_name, sizeof(na->na_name) - 1);
	na->na_name[sizeof(na->na_name) - 1] = '\0';
	uuid_generate_random(na->na_uuid);

	/*
	 * Verify upper bounds; for all cases including user pipe nexus,
	 * the parameters must have already been validated by corresponding
	 * nxdom_prov_params() function defined by each domain.
	 */
	na_set_nrings(na, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(na, NR_RX, nxp->nxp_rx_rings);
	na_set_nslots(na, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(na, NR_RX, nxp->nxp_rx_slots);
	ASSERT(na_get_nrings(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	na->na_txsync = na_pseudo_txsync;
	na->na_rxsync = na_pseudo_rxsync;
	na->na_activate = na_pseudo_activate;
	na->na_dtor = na_pseudo_dtor;
	na->na_krings_create = na_pseudo_krings_create;
	na->na_krings_delete = na_pseudo_krings_delete;

	*(nexus_stats_type_t *)(uintptr_t)&na->na_stats_type =
	    NEXUS_STATS_TYPE_INVALID;

	/* other fields are set in the common routine */
	na_attach_common(na, nx, NX_DOM_PROV(nx));

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
	uuid_string_t uuidstr;
	SK_D("na_name: \"%s\"", na->na_name);
	SK_D("  UUID:        %s", sk_uuid_unparse(na->na_uuid, uuidstr));
	SK_D("  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(na->na_nx), NX_DOM(na->na_nx)->nxdom_name,
	    NX_DOM_PROV(na->na_nx)->nxdom_prov_name);
	SK_D("  flags:       %b", na->na_flags, NAF_BITS);
	SK_D("  flowadv_max: %u", na->na_flowadv_max);
	SK_D("  rings:       tx %u rx %u",
	    na_get_nrings(na, NR_TX), na_get_nrings(na, NR_RX));
	SK_D("  slots:       tx %u rx %u",
	    na_get_nslots(na, NR_TX), na_get_nslots(na, NR_RX));
#if CONFIG_NEXUS_USER_PIPE
	SK_D("  next_pipe:   %u", na->na_next_pipe);
	SK_D("  max_pipes:   %u", na->na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
#endif /* SK_LOG */

	*ret = na;
	na_retain_locked(na);

	return 0;

err:
	if (na != NULL) {
		if (na->na_arena != NULL) {
			skmem_arena_release(na->na_arena);
			na->na_arena = NULL;
		}
		NA_FREE(na);
	}
	return error;
}

void
na_flowadv_entry_alloc(const struct nexus_adapter *na, uuid_t fae_id,
    const flowadv_idx_t fe_idx)
{
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn = skmem_arena_nexus(na->na_arena);
	struct __flowadv_entry *fae;

	ASSERT(NA_IS_ACTIVE(na) && na->na_flowadv_max != 0);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	AR_LOCK(ar);

	/* we must not get here if arena is defunct; this must be valid */
	ASSERT(arn->arn_flowadv_obj != NULL);

	VERIFY(fe_idx < na->na_flowadv_max);
	fae = &arn->arn_flowadv_obj[fe_idx];
	uuid_copy(fae->fae_id, fae_id);
	fae->fae_flags |= FLOWADVF_VALID;

	AR_UNLOCK(ar);
}

void
na_flowadv_entry_free(const struct nexus_adapter *na, uuid_t fae_id,
    const flowadv_idx_t fe_idx)
{
#pragma unused(fae_id)
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn = skmem_arena_nexus(ar);

	ASSERT(NA_IS_ACTIVE(na) && (na->na_flowadv_max != 0));
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	AR_LOCK(ar);

	ASSERT(arn->arn_flowadv_obj != NULL || (ar->ar_flags & ARF_DEFUNCT));
	if (arn->arn_flowadv_obj != NULL) {
		struct __flowadv_entry *fae;

		VERIFY(fe_idx < na->na_flowadv_max);
		fae = &arn->arn_flowadv_obj[fe_idx];
		ASSERT(uuid_compare(fae->fae_id, fae_id) == 0);
		uuid_clear(fae->fae_id);
		fae->fae_flags &= ~FLOWADVF_VALID;
	}

	AR_UNLOCK(ar);
}

bool
na_flowadv_set(const struct nexus_adapter *na, const flowadv_idx_t fe_idx,
    const flowadv_token_t flow_token)
{
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn = skmem_arena_nexus(ar);
	bool suspend;

	ASSERT(NA_IS_ACTIVE(na) && (na->na_flowadv_max != 0));
	ASSERT(fe_idx < na->na_flowadv_max);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	AR_LOCK(ar);

	ASSERT(arn->arn_flowadv_obj != NULL || (ar->ar_flags & ARF_DEFUNCT));

	if (arn->arn_flowadv_obj != NULL) {
		struct __flowadv_entry *fae = &arn->arn_flowadv_obj[fe_idx];

		_CASSERT(sizeof(fae->fae_token) == sizeof(flow_token));
		/*
		 * We cannot guarantee that the flow is still around by now,
		 * so check if that's the case and let the caller know.
		 */
		if ((suspend = (fae->fae_token == flow_token))) {
			ASSERT(fae->fae_flags & FLOWADVF_VALID);
			fae->fae_flags |= FLOWADVF_SUSPENDED;
		}
	} else {
		suspend = false;
	}
	if (suspend) {
		SK_DF(SK_VERB_FLOW_ADVISORY, "%s(%d) flow token 0x%llu fidx %u "
		    "SUSPEND", sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), flow_token, fe_idx);
	} else {
		SK_ERR("%s(%d) flow token 0x%llu fidx %u no longer around",
		    sk_proc_name_address(current_proc()),
		    sk_proc_pid(current_proc()), flow_token, fe_idx);
	}

	AR_UNLOCK(ar);

	return suspend;
}

int
na_flowadv_clear(const struct kern_channel *ch, const flowadv_idx_t fe_idx,
    const flowadv_token_t flow_token)
{
	struct nexus_adapter *na = ch->ch_na;
	struct skmem_arena *ar = na->na_arena;
	struct skmem_arena_nexus *arn = skmem_arena_nexus(ar);
	boolean_t resume;

	ASSERT(NA_IS_ACTIVE(na) && (na->na_flowadv_max != 0));
	ASSERT(fe_idx < na->na_flowadv_max);
	ASSERT(ar->ar_type == SKMEM_ARENA_TYPE_NEXUS);

	AR_LOCK(ar);

	ASSERT(arn->arn_flowadv_obj != NULL || (ar->ar_flags & ARF_DEFUNCT));

	if (arn->arn_flowadv_obj != NULL) {
		struct __flowadv_entry *fae = &arn->arn_flowadv_obj[fe_idx];

		_CASSERT(sizeof(fae->fae_token) == sizeof(flow_token));
		/*
		 * We cannot guarantee that the flow is still around by now,
		 * so check if that's the case and let the caller know.
		 */
		if ((resume = (fae->fae_token == flow_token))) {
			ASSERT(fae->fae_flags & FLOWADVF_VALID);
			fae->fae_flags &= ~FLOWADVF_SUSPENDED;
		}
	} else {
		resume = FALSE;
	}
	if (resume) {
		SK_DF(SK_VERB_FLOW_ADVISORY, "%s(%d): flow token 0x%x "
		    "fidx %u RESUME", ch->ch_name, ch->ch_pid, flow_token,
		    fe_idx);
	} else {
		SK_ERR("%s(%d): flow token 0x%x fidx %u no longer around",
		    ch->ch_name, ch->ch_pid, flow_token, fe_idx);
	}

	AR_UNLOCK(ar);

	return resume;
}

void
na_flowadv_event(struct __kern_channel_ring *kring)
{
	ASSERT(kring->ckr_tx == NR_TX);

	SK_DF(SK_VERB_EVENTS, "%s(%d) na \"%s\" (0x%llx) kr 0x%llx",
	    sk_proc_name_address(current_proc()), sk_proc_pid(current_proc()),
	    KRNA(kring)->na_name, SK_KVA(KRNA(kring)), SK_KVA(kring));

	na_post_event(kring, TRUE, FALSE, FALSE, CHAN_FILT_HINT_FLOW_ADV_UPD);
}

static int
na_packet_pool_free_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(flags, p)
	int n, ret = 0;
	slot_idx_t j;
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_quantum *kqum;
	struct kern_pbufpool *pp = kring->ckr_pp;
	uint32_t nfree = 0;

	/* packet pool list is protected by channel lock */
	ASSERT(!KR_KERNEL_ONLY(kring));

	/* # of new slots */
	n = kring->ckr_rhead - kring->ckr_khead;
	if (n < 0) {
		n += kring->ckr_num_slots;
	}

	/* nothing to free */
	if (__improbable(n == 0)) {
		SK_DF(SK_VERB_MEM | SK_VERB_SYNC, "%s(%d) kr \"%s\" %s",
		    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
		    "nothing to free");
		goto done;
	}

	j = kring->ckr_khead;
	PP_LOCK(pp);
	while (n--) {
		int err;

		ksd = KR_KSD(kring, j);
		usd = KR_USD(kring, j);

		if (__improbable(!SD_VALID_METADATA(usd))) {
			SK_ERR("bad slot %d 0x%llx", j, SK_KVA(ksd));
			ret = EINVAL;
			break;
		}

		kqum = pp_remove_upp_locked(pp, usd->sd_md_idx, &err);
		if (__improbable(err != 0)) {
			SK_ERR("un-allocated packet or buflet %d %p",
			    usd->sd_md_idx, SK_KVA(kqum));
			ret = EINVAL;
			break;
		}

		/* detach and free the packet */
		kqum->qum_qflags &= ~QUM_F_FINALIZED;
		kqum->qum_ksd = NULL;
		ASSERT(!KSD_VALID_METADATA(ksd));
		USD_DETACH_METADATA(usd);
		ASSERT(pp == kqum->qum_pp);
		ASSERT(nfree < kring->ckr_num_slots);
		kring->ckr_scratch[nfree++] = (uint64_t)kqum;
		j = SLOT_NEXT(j, kring->ckr_lim);
	}
	PP_UNLOCK(pp);

	if (__probable(nfree > 0)) {
		pp_free_packet_batch(pp, &kring->ckr_scratch[0], nfree);
	}

	kring->ckr_khead = j;
	kring->ckr_ktail = SLOT_PREV(j, kring->ckr_lim);

done:
	return ret;
}

static int
na_packet_pool_alloc_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	int b, err;
	uint32_t n = 0;
	slot_idx_t j;
	uint64_t now;
	uint32_t curr_ws, ph_needed, ph_cnt;
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_quantum *kqum;
	kern_pbufpool_t pp = kring->ckr_pp;
	pid_t pid = proc_pid(p);

	/* packet pool list is protected by channel lock */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(!PP_KERNEL_ONLY(pp));

	now = _net_uptime;
	if ((flags & NA_SYNCF_UPP_PURGE) != 0) {
		if (now - kring->ckr_sync_time >= na_upp_reap_interval) {
			kring->ckr_alloc_ws = na_upp_reap_min_pkts;
		}
		SK_DF(SK_VERB_MEM | SK_VERB_SYNC,
		    "%s: purged curr_ws(%d)", kring->ckr_name,
		    kring->ckr_alloc_ws);
		return 0;
	}
	/* reclaim the completed slots */
	kring->ckr_khead = kring->ckr_rhead;

	/* # of busy (unclaimed) slots */
	b = kring->ckr_ktail - kring->ckr_khead;
	if (b < 0) {
		b += kring->ckr_num_slots;
	}

	curr_ws = kring->ckr_alloc_ws;
	if (flags & NA_SYNCF_FORCE_UPP_SYNC) {
		/* increment the working set by 50% */
		curr_ws += (curr_ws >> 1);
		curr_ws = MIN(curr_ws, kring->ckr_lim);
	} else {
		if ((now - kring->ckr_sync_time >= na_upp_ws_hold_time) &&
		    (uint32_t)b >= (curr_ws >> 2)) {
			/* decrease the working set by 25% */
			curr_ws -= (curr_ws >> 2);
		}
	}
	curr_ws = MAX(curr_ws, na_upp_alloc_lowat);
	if (curr_ws > (uint32_t)b) {
		n = curr_ws - b;
	}
	kring->ckr_alloc_ws = curr_ws;
	kring->ckr_sync_time = now;

	/* min with # of avail free slots (subtract busy from max) */
	n = ph_needed = MIN(n, kring->ckr_lim - b);
	j = kring->ckr_ktail;
	SK_DF(SK_VERB_MEM | SK_VERB_SYNC,
	    "%s: curr_ws(%d), n(%d)", kring->ckr_name, curr_ws, n);

	if ((ph_cnt = ph_needed) == 0) {
		goto done;
	}

	err = kern_pbufpool_alloc_batch_nosleep(pp, 1, kring->ckr_scratch,
	    &ph_cnt);

	if (__improbable(ph_cnt == 0)) {
		SK_ERR("kr 0x%llx failed to alloc %u packet s(%d)",
		    SK_KVA(kring), ph_needed, err);
		kring->ckr_err_stats.cres_pkt_alloc_failures += ph_needed;
	} else {
		/*
		 * Add packets to the allocated list of user packet pool.
		 */
		pp_insert_upp_batch(pp, pid, kring->ckr_scratch, ph_cnt);
	}


	for (n = 0; n < ph_cnt; n++) {
		ksd = KR_KSD(kring, j);
		usd = KR_USD(kring, j);

		kqum = SK_PTR_ADDR_KQUM(kring->ckr_scratch[n]);
		kring->ckr_scratch[n] = 0;
		ASSERT(kqum != NULL);

		/* cleanup any stale slot mapping */
		KSD_RESET(ksd);
		ASSERT(usd != NULL);
		USD_RESET(usd);

		/*
		 * Since this packet is freshly allocated and we need to
		 * have the flag set for the attach to succeed, just set
		 * it here rather than calling __packet_finalize().
		 */
		kqum->qum_qflags |= QUM_F_FINALIZED;

		/* Attach packet to slot */
		KR_SLOT_ATTACH_METADATA(kring, ksd, kqum);
		/*
		 * externalize the packet as it is being transferred to
		 * user space.
		 */
		kr_externalize_metadata(kring, pp->pp_max_frags, kqum, p);

		j = SLOT_NEXT(j, kring->ckr_lim);
	}
done:
	ASSERT(j != kring->ckr_khead || j == kring->ckr_ktail);
	kring->ckr_ktail = j;
	return 0;
}

static int
na_packet_pool_free_buf_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(flags, p)
	int n, ret = 0;
	slot_idx_t j;
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_buflet *kbft;
	struct kern_pbufpool *pp = kring->ckr_pp;

	/* packet pool list is protected by channel lock */
	ASSERT(!KR_KERNEL_ONLY(kring));

	/* # of new slots */
	n = kring->ckr_rhead - kring->ckr_khead;
	if (n < 0) {
		n += kring->ckr_num_slots;
	}

	/* nothing to free */
	if (__improbable(n == 0)) {
		SK_DF(SK_VERB_MEM | SK_VERB_SYNC, "%s(%d) kr \"%s\" %s",
		    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
		    "nothing to free");
		goto done;
	}

	j = kring->ckr_khead;
	while (n--) {
		int err;

		ksd = KR_KSD(kring, j);
		usd = KR_USD(kring, j);

		if (__improbable(!SD_VALID_METADATA(usd))) {
			SK_ERR("bad slot %d 0x%llx", j, SK_KVA(ksd));
			ret = EINVAL;
			break;
		}

		kbft = pp_remove_upp_bft(pp, usd->sd_md_idx, &err);
		if (__improbable(err != 0)) {
			SK_ERR("un-allocated buflet %d %p", usd->sd_md_idx,
			    SK_KVA(kbft));
			ret = EINVAL;
			break;
		}

		/* detach and free the packet */
		ASSERT(!KSD_VALID_METADATA(ksd));
		USD_DETACH_METADATA(usd);
		pp_free_buflet(pp, kbft);
		j = SLOT_NEXT(j, kring->ckr_lim);
	}
	kring->ckr_khead = j;
	kring->ckr_ktail = SLOT_PREV(j, kring->ckr_lim);

done:
	return ret;
}

static int
na_packet_pool_alloc_buf_sync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
	int b, err;
	uint32_t n = 0;
	slot_idx_t j;
	uint64_t now;
	uint32_t curr_ws, bh_needed, bh_cnt;
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_buflet *kbft;
	struct __kern_buflet_ext *kbe;
	kern_pbufpool_t pp = kring->ckr_pp;
	pid_t pid = proc_pid(p);

	/* packet pool list is protected by channel lock */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(!PP_KERNEL_ONLY(pp));

	now = _net_uptime;
	if ((flags & NA_SYNCF_UPP_PURGE) != 0) {
		if (now - kring->ckr_sync_time >= na_upp_reap_interval) {
			kring->ckr_alloc_ws = na_upp_reap_min_pkts;
		}
		SK_DF(SK_VERB_MEM | SK_VERB_SYNC,
		    "%s: purged curr_ws(%d)", kring->ckr_name,
		    kring->ckr_alloc_ws);
		return 0;
	}
	/* reclaim the completed slots */
	kring->ckr_khead = kring->ckr_rhead;

	/* # of busy (unclaimed) slots */
	b = kring->ckr_ktail - kring->ckr_khead;
	if (b < 0) {
		b += kring->ckr_num_slots;
	}

	curr_ws = kring->ckr_alloc_ws;
	if (flags & NA_SYNCF_FORCE_UPP_SYNC) {
		/* increment the working set by 50% */
		curr_ws += (curr_ws >> 1);
		curr_ws = MIN(curr_ws, kring->ckr_lim);
	} else {
		if ((now - kring->ckr_sync_time >= na_upp_ws_hold_time) &&
		    (uint32_t)b >= (curr_ws >> 2)) {
			/* decrease the working set by 25% */
			curr_ws -= (curr_ws >> 2);
		}
	}
	curr_ws = MAX(curr_ws, na_upp_alloc_buf_lowat);
	if (curr_ws > (uint32_t)b) {
		n = curr_ws - b;
	}
	kring->ckr_alloc_ws = curr_ws;
	kring->ckr_sync_time = now;

	/* min with # of avail free slots (subtract busy from max) */
	n = bh_needed = MIN(n, kring->ckr_lim - b);
	j = kring->ckr_ktail;
	SK_DF(SK_VERB_MEM | SK_VERB_SYNC,
	    "%s: curr_ws(%d), n(%d)", kring->ckr_name, curr_ws, n);

	if ((bh_cnt = bh_needed) == 0) {
		goto done;
	}

	err = pp_alloc_buflet_batch(pp, kring->ckr_scratch, &bh_cnt,
	    SKMEM_NOSLEEP);

	if (bh_cnt == 0) {
		SK_ERR("kr 0x%llx failed to alloc %u buflets(%d)",
		    SK_KVA(kring), bh_needed, err);
		kring->ckr_err_stats.cres_pkt_alloc_failures += bh_needed;
	}

	for (n = 0; n < bh_cnt; n++) {
		struct __user_buflet *ubft;

		ksd = KR_KSD(kring, j);
		usd = KR_USD(kring, j);

		kbft = (struct __kern_buflet *)(kring->ckr_scratch[n]);
		kbe = (struct __kern_buflet_ext *)kbft;
		kring->ckr_scratch[n] = 0;
		ASSERT(kbft != NULL);

		/*
		 * Add buflet to the allocated list of user packet pool.
		 */
		pp_insert_upp_bft(pp, kbft, pid);

		/*
		 * externalize the buflet as it is being transferred to
		 * user space.
		 */
		ubft = __DECONST(struct __user_buflet *, kbe->kbe_buf_user);
		KBUF_EXTERNALIZE(kbft, ubft, pp);

		/* cleanup any stale slot mapping */
		KSD_RESET(ksd);
		ASSERT(usd != NULL);
		USD_RESET(usd);

		/* Attach buflet to slot */
		KR_SLOT_ATTACH_BUF_METADATA(kring, ksd, kbft);

		j = SLOT_NEXT(j, kring->ckr_lim);
	}
done:
	ASSERT(j != kring->ckr_khead || j == kring->ckr_ktail);
	kring->ckr_ktail = j;
	return 0;
}

/* The caller needs to ensure that the NA stays intact */
void
na_drain(struct nexus_adapter *na, boolean_t purge)
{
	/* will be cleared on next channel sync */
	if (!(atomic_bitset_32_ov(&na->na_flags, NAF_DRAINING) &
	    NAF_DRAINING) && NA_IS_ACTIVE(na)) {
		SK_DF(SK_VERB_NA, "%s: %s na 0x%llx flags %b",
		    na->na_name, (purge ? "purging" : "pruning"),
		    SK_KVA(na), na->na_flags, NAF_BITS);

		/* reap (purge/prune) caches in the arena */
		skmem_arena_reap(na->na_arena, purge);
	}
}
