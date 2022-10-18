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
#include <sys/sdt.h>

static void fsw_vp_na_dtor(struct nexus_adapter *);
static int fsw_vp_na_special(struct nexus_adapter *,
    struct kern_channel *, struct chreq *, nxspec_cmd_t);
static struct nexus_vp_adapter *fsw_vp_na_alloc(zalloc_flags_t);
static void fsw_vp_na_free(struct nexus_adapter *);
static int fsw_vp_na_channel_event_notify(struct nexus_adapter *vpna,
    struct __kern_channel_event *ev, uint16_t ev_len);

static ZONE_DEFINE(na_vp_zone, SKMEM_ZONE_PREFIX ".na.fsw.vp",
    sizeof(struct nexus_vp_adapter), ZC_ZFREE_CLEARMEM);

static uint16_t fsw_vpna_gencnt = 0;

/* na_activate() callback for flow switch ports */
int
fsw_vp_na_activate(struct nexus_adapter *na, na_activate_mode_t mode)
{
	int ret = 0;
	struct nexus_vp_adapter *vpna = (struct nexus_vp_adapter *)(void *)na;
	struct nx_flowswitch *fsw = vpna->vpna_fsw;

	ASSERT(na->na_type == NA_FLOWSWITCH_VP);

	SK_DF(SK_VERB_FSW, "na \"%s\" (0x%llx) %s", na->na_name,
	    SK_KVA(na), na_activate_mode2str(mode));

	/*
	 * Persistent ports may be put in Skywalk mode
	 * before being attached to a FlowSwitch.
	 */
	FSW_WLOCK(fsw);

	atomic_add_16(&fsw_vpna_gencnt, 1);
	vpna->vpna_gencnt = fsw_vpna_gencnt;

	if (mode == NA_ACTIVATE_MODE_ON) {
		atomic_bitset_32(&na->na_flags, NAF_ACTIVE);
	}

	ret = fsw_port_na_activate(fsw, vpna, mode);
	if (ret != 0) {
		SK_DF(SK_VERB_FSW, "na \"%s\" (0x%llx) %s err(%d)",
		    na->na_name, SK_KVA(na), na_activate_mode2str(mode), ret);
		if (mode == NA_ACTIVATE_MODE_ON) {
			atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);
		}
		goto done;
	}

	if (mode == NA_ACTIVATE_MODE_DEFUNCT ||
	    mode == NA_ACTIVATE_MODE_OFF) {
		struct skmem_arena_nexus *arn = skmem_arena_nexus(na->na_arena);

		if (mode == NA_ACTIVATE_MODE_OFF) {
			atomic_bitclear_32(&na->na_flags, NAF_ACTIVE);
		}

		AR_LOCK(na->na_arena);
		if (na->na_type == NA_FLOWSWITCH_VP &&
		    arn->arn_stats_obj != NULL) {
			fsw_fold_stats(fsw,
			    arn->arn_stats_obj, na->na_stats_type);
		}
		AR_UNLOCK(na->na_arena);

		enum txrx t;
		uint32_t i;
		struct __nx_stats_channel_errors stats;
		for_all_rings(t) {
			for (i = 0; i < na_get_nrings(na, t); i++) {
				stats.nxs_cres =
				    &NAKR(na, t)[i].ckr_err_stats;
				fsw_fold_stats(fsw, &stats,
				    NEXUS_STATS_TYPE_CHAN_ERRORS);
			}
		}
	}

done:
	FSW_WUNLOCK(fsw);
	return ret;
}

/* na_dtor callback for ephemeral flow switch ports */
static void
fsw_vp_na_dtor(struct nexus_adapter *na)
{
	struct nexus_vp_adapter *vpna = (struct nexus_vp_adapter *)(void *)na;
	struct nx_flowswitch *fsw = vpna->vpna_fsw;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_FLOWSWITCH_VP);

	SK_DF(SK_VERB_FSW, "na \"%s\" (0x%llx)", na->na_name, SK_KVA(na));

	if (fsw != NULL) {
		FSW_WLOCK(fsw);
		fsw_port_free(fsw, vpna, vpna->vpna_nx_port, FALSE);
		FSW_WUNLOCK(fsw);
	}
}

/*
 * na_krings_create callback for flow switch ports.
 * Calls the standard na_kr_create(), then adds leases on rx
 * rings and bdgfwd on tx rings.
 */
int
fsw_vp_na_krings_create(struct nexus_adapter *na, struct kern_channel *ch)
{
	ASSERT(na->na_type == NA_FLOWSWITCH_VP);

	return na_rings_mem_setup(na, 0, FALSE, ch);
}


/* na_krings_delete callback for flow switch ports. */
void
fsw_vp_na_krings_delete(struct nexus_adapter *na, struct kern_channel *ch,
    boolean_t defunct)
{
	ASSERT(na->na_type == NA_FLOWSWITCH_VP);

	na_rings_mem_teardown(na, ch, defunct);
}

/* na_txsync callback for flow switch ports */
int
fsw_vp_na_txsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(flags)
	struct nexus_vp_adapter *vpna = VPNA(KRNA(kring));
	struct nx_flowswitch *fsw = vpna->vpna_fsw;
	int error = 0;

	/*
	 * Flush packets if and only if the ring isn't in drop mode,
	 * and if the adapter is currently attached to a nexus port;
	 * otherwise we drop them.
	 */
	if (__probable(!KR_DROP(kring) && fsw != NULL)) {
		fsw_ring_flush(fsw, kring, p);
	} else {
		int dropped_pkts;
		/* packets between khead to rhead have been dropped */
		dropped_pkts = kring->ckr_rhead - kring->ckr_khead;
		if (dropped_pkts < 0) {
			dropped_pkts += kring->ckr_num_slots;
		}
		if (fsw != NULL) {
			STATS_INC(&fsw->fsw_stats, FSW_STATS_DST_RING_DROPMODE);
			STATS_ADD(&fsw->fsw_stats, FSW_STATS_DROP,
			    dropped_pkts);
		}
		/* we're dropping; claim all */
		slot_idx_t sidx = kring->ckr_khead;
		while (sidx != kring->ckr_rhead) {
			struct __kern_slot_desc *ksd = KR_KSD(kring, sidx);
			if (KSD_VALID_METADATA(ksd)) {
				struct __kern_packet *pkt = ksd->sd_pkt;
				(void) KR_SLOT_DETACH_METADATA(kring, ksd);
				pp_free_packet_single(pkt);
			}
			sidx = SLOT_NEXT(sidx, kring->ckr_lim);
		}
		kring->ckr_khead = kring->ckr_rhead;
		kring->ckr_ktail = SLOT_PREV(kring->ckr_rhead, kring->ckr_lim);
		error = ENODEV;
		SK_ERR("kr \"%s\" (0x%llx) krflags 0x%b in drop mode (err %d)",
		    kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
		    CKRF_BITS, error);
	}

	SK_DF(SK_VERB_FSW | SK_VERB_SYNC | SK_VERB_TX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u flags 0x%x",
	    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, kring->ckr_ring_id,
	    flags);

	return error;
}

/*
 * na_rxsync callback for flow switch ports.  We're already protected
 * against concurrent calls from userspace.
 */
int
fsw_vp_na_rxsync(struct __kern_channel_ring *kring, struct proc *p,
    uint32_t flags)
{
#pragma unused(p, flags)
	slot_idx_t head, khead_prev;

	head = kring->ckr_rhead;
	ASSERT(head <= kring->ckr_lim);

	/* First part, import newly received packets. */
	/* actually nothing to do here, they are already in the kring */

	/* Second part, skip past packets that userspace has released. */
	khead_prev = kring->ckr_khead;
	kring->ckr_khead = head;

	/* ensure global visibility */
	membar_sync();

	SK_DF(SK_VERB_FSW | SK_VERB_SYNC | SK_VERB_RX,
	    "%s(%d) kr \"%s\" (0x%llx) krflags 0x%b ring %u "
	    "kh %u (was %u) rh %u flags 0x%x", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, kring->ckr_ring_id, kring->ckr_khead, khead_prev,
	    kring->ckr_rhead, flags);

	return 0;
}

int
fsw_vp_na_attach(struct kern_nexus *nx, const char *cr_name,
    struct nexus_adapter *na)
{
#pragma unused(nx)
	SK_LOCK_ASSERT_HELD();
	ASSERT(nx->nx_prov->nxprov_params->nxp_type == NEXUS_TYPE_FLOW_SWITCH);
	ASSERT(VPNA(na)->vpna_fsw == NULL);

	(void) strncpy(na->na_name, cr_name, sizeof(na->na_name) - 1);
	na->na_name[sizeof(na->na_name) - 1] = '\0';

	return 0;
}

static int
fsw_vp_na_special(struct nexus_adapter *na, struct kern_channel *ch,
    struct chreq *chr, nxspec_cmd_t spec_cmd)
{
	int error = 0;

	SK_LOCK_ASSERT_HELD();
	ASSERT(na->na_type == NA_FLOWSWITCH_VP);

	/*
	 * fsw_vp_na_attach() must have created this adapter
	 * exclusively for kernel (NAF_KERNEL); leave this alone.
	 */
	ASSERT(NA_KERNEL_ONLY(na));

	switch (spec_cmd) {
	case NXSPEC_CMD_CONNECT:
		ASSERT(!(na->na_flags & NAF_SPEC_INIT));
		ASSERT(na->na_channels == 0);

		error = na_bind_channel(na, ch, chr);
		if (error != 0) {
			goto done;
		}

		atomic_bitset_32(&na->na_flags, NAF_SPEC_INIT);
		break;

	case NXSPEC_CMD_DISCONNECT:
		ASSERT(na->na_channels > 0);
		ASSERT(na->na_flags & NAF_SPEC_INIT);
		atomic_bitclear_32(&na->na_flags, NAF_SPEC_INIT);

		na_unbind_channel(ch);
		break;

	case NXSPEC_CMD_START:
		na_kr_drop(na, FALSE);
		break;

	case NXSPEC_CMD_STOP:
		na_kr_drop(na, TRUE);
		break;

	default:
		error = EINVAL;
		break;
	}

done:
	SK_DF(error ? SK_VERB_ERROR : SK_VERB_FSW,
	    "ch 0x%llx na \"%s\" (0x%llx) nx 0x%llx spec_cmd %u (err %d)",
	    SK_KVA(ch), na->na_name, SK_KVA(na), SK_KVA(ch->ch_nexus),
	    spec_cmd, error);

	return error;
}

/*
 * Create a nexus_vp_adapter that describes a flow switch port.
 */
int
fsw_vp_na_create(struct kern_nexus *nx, struct chreq *chr,
    struct nexus_vp_adapter **ret)
{
	struct nxprov_params *nxp = NX_PROV(nx)->nxprov_params;
	struct nexus_vp_adapter *vpna;
	struct nexus_adapter *na;
	int error;

	SK_LOCK_ASSERT_HELD();

	if ((chr->cr_mode & CHMODE_KERNEL) != 0) {
		SK_ERR("VP adapter can't be used by kernel");
		return ENOTSUP;
	}
	if ((chr->cr_mode & CHMODE_USER_PACKET_POOL) == 0) {
		SK_ERR("user packet pool required");
		return EINVAL;
	}

	vpna = fsw_vp_na_alloc(Z_WAITOK);

	ASSERT(vpna->vpna_up.na_type == NA_FLOWSWITCH_VP);
	ASSERT(vpna->vpna_up.na_free == fsw_vp_na_free);

	na = &vpna->vpna_up;
	(void) strncpy(na->na_name, chr->cr_name, sizeof(na->na_name) - 1);
	na->na_name[sizeof(na->na_name) - 1] = '\0';
	uuid_generate_random(na->na_uuid);

	/*
	 * Verify upper bounds; for all cases including user pipe nexus,
	 * as well as flow switch-based ones, the parameters must have
	 * already been validated by corresponding nxdom_prov_params()
	 * function defined by each domain.  The user pipe nexus would
	 * be checking against the flow switch's parameters there.
	 */
	na_set_nrings(na, NR_TX, nxp->nxp_tx_rings);
	na_set_nrings(na, NR_RX, nxp->nxp_rx_rings);
	/*
	 * If the packet pool is configured to be multi-buflet, then we
	 * need 2 pairs of alloc/free rings(for packet and buflet).
	 */
	na_set_nrings(na, NR_A, ((nxp->nxp_max_frags > 1) &&
	    (sk_channel_buflet_alloc != 0)) ? 2 : 1);
	na_set_nslots(na, NR_TX, nxp->nxp_tx_slots);
	na_set_nslots(na, NR_RX, nxp->nxp_rx_slots);
	na_set_nslots(na, NR_A, NX_FSW_AFRINGSIZE);
	ASSERT(na_get_nrings(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_rings.nb_max);
	ASSERT(na_get_nrings(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_rings.nb_max);
	ASSERT(na_get_nslots(na, NR_TX) <= NX_DOM(nx)->nxdom_tx_slots.nb_max);
	ASSERT(na_get_nslots(na, NR_RX) <= NX_DOM(nx)->nxdom_rx_slots.nb_max);

	atomic_bitset_32(&na->na_flags, NAF_USER_PKT_POOL);

	if (chr->cr_mode & CHMODE_LOW_LATENCY) {
		atomic_bitset_32(&na->na_flags, NAF_LOW_LATENCY);
	}

	if (chr->cr_mode & CHMODE_EVENT_RING) {
		na_set_nrings(na, NR_EV, NX_FSW_EVENT_RING_NUM);
		na_set_nslots(na, NR_EV, NX_FSW_EVENT_RING_SIZE);
		atomic_bitset_32(&na->na_flags, NAF_EVENT_RING);
		na->na_channel_event_notify = fsw_vp_na_channel_event_notify;
	}

	vpna->vpna_nx_port = chr->cr_port;
	na->na_dtor = fsw_vp_na_dtor;
	na->na_activate = fsw_vp_na_activate;
	na->na_txsync = fsw_vp_na_txsync;
	na->na_rxsync = fsw_vp_na_rxsync;
	na->na_krings_create = fsw_vp_na_krings_create;
	na->na_krings_delete = fsw_vp_na_krings_delete;
	na->na_special = fsw_vp_na_special;

	*(nexus_stats_type_t *)(uintptr_t)&na->na_stats_type =
	    NEXUS_STATS_TYPE_FSW;

	/* other fields are set in the common routine */
	na_attach_common(na, nx, &nx_fsw_prov_s);

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
	SK_DF(SK_VERB_FSW, "na_name: \"%s\"", na->na_name);
	SK_DF(SK_VERB_FSW, "  UUID:        %s", sk_uuid_unparse(na->na_uuid,
	    uuidstr));
	SK_DF(SK_VERB_FSW, "  nx:          0x%llx (\"%s\":\"%s\")",
	    SK_KVA(na->na_nx), NX_DOM(na->na_nx)->nxdom_name,
	    NX_DOM_PROV(na->na_nx)->nxdom_prov_name);
	SK_DF(SK_VERB_FSW, "  flags:       0x%b", na->na_flags, NAF_BITS);
	SK_DF(SK_VERB_FSW, "  stats_type:  %u", na->na_stats_type);
	SK_DF(SK_VERB_FSW, "  flowadv_max: %u", na->na_flowadv_max);
	SK_DF(SK_VERB_FSW, "  rings:       tx %u rx %u af %u",
	    na_get_nrings(na, NR_TX), na_get_nrings(na, NR_RX),
	    na_get_nrings(na, NR_A));
	SK_DF(SK_VERB_FSW, "  slots:       tx %u rx %u af %u",
	    na_get_nslots(na, NR_TX), na_get_nslots(na, NR_RX),
	    na_get_nslots(na, NR_A));
#if CONFIG_NEXUS_USER_PIPE
	SK_DF(SK_VERB_FSW, "  next_pipe:   %u", na->na_next_pipe);
	SK_DF(SK_VERB_FSW, "  max_pipes:   %u", na->na_max_pipes);
#endif /* CONFIG_NEXUS_USER_PIPE */
	SK_DF(SK_VERB_FSW, "  nx_port:     %d", (int)vpna->vpna_nx_port);
#endif /* SK_LOG */

	*ret = vpna;
	na_retain_locked(&vpna->vpna_up);

	return 0;

err:
	if (na->na_arena != NULL) {
		skmem_arena_release(na->na_arena);
		na->na_arena = NULL;
	}
	NA_FREE(&vpna->vpna_up);
	return error;
}

static struct nexus_vp_adapter *
fsw_vp_na_alloc(zalloc_flags_t how)
{
	struct nexus_vp_adapter *vpna;

	_CASSERT(offsetof(struct nexus_vp_adapter, vpna_up) == 0);

	vpna = zalloc_flags(na_vp_zone, how | Z_ZERO);
	if (vpna) {
		vpna->vpna_up.na_type = NA_FLOWSWITCH_VP;
		vpna->vpna_up.na_free = fsw_vp_na_free;
	}
	return vpna;
}

static void
fsw_vp_na_free(struct nexus_adapter *na)
{
	struct nexus_vp_adapter *vpna = (struct nexus_vp_adapter *)(void *)na;

	ASSERT(vpna->vpna_up.na_refcount == 0);
	SK_DF(SK_VERB_MEM, "vpna 0x%llx FREE", SK_KVA(vpna));
	bzero(vpna, sizeof(*vpna));
	zfree(na_vp_zone, vpna);
}

void
fsw_vp_channel_error_stats_fold(struct fsw_stats *fs,
    struct __nx_stats_channel_errors *es)
{
	STATS_ADD(fs, FSW_STATS_CHAN_ERR_UPP_ALLOC,
	    es->nxs_cres->cres_pkt_alloc_failures);
}

SK_NO_INLINE_ATTRIBUTE
static struct __kern_packet *
nx_fsw_alloc_packet(struct kern_pbufpool *pp, uint32_t sz, kern_packet_t *php)
{
	kern_packet_t ph;
	ph = pp_alloc_packet_by_size(pp, sz, SKMEM_NOSLEEP);
	if (__improbable(ph == 0)) {
		DTRACE_SKYWALK2(alloc__fail, struct kern_pbufpool *,
		    pp, size_t, sz);
		return NULL;
	}
	if (php != NULL) {
		*php = ph;
	}
	return SK_PTR_ADDR_KPKT(ph);
}

SK_NO_INLINE_ATTRIBUTE
static void
nx_fsw_free_packet(struct __kern_packet *pkt)
{
	pp_free_packet_single(pkt);
}

static int
fsw_vp_na_channel_event_notify(struct nexus_adapter *vpna,
    struct __kern_channel_event *ev, uint16_t ev_len)
{
	int err;
	char *baddr;
	kern_packet_t ph;
	kern_buflet_t buf;
	sk_protect_t protect;
	kern_channel_slot_t slot;
	struct __kern_packet *vpna_pkt = NULL;
	struct __kern_channel_event_metadata *emd;
	struct __kern_channel_ring *ring = &vpna->na_event_rings[0];
	struct fsw_stats *fs = &((struct nexus_vp_adapter *)(vpna))->vpna_fsw->fsw_stats;

	if (__improbable(!NA_IS_ACTIVE(vpna))) {
		STATS_INC(fs, FSW_STATS_EV_DROP_NA_INACTIVE);
		err = ENXIO;
		goto error;
	}
	if (__improbable(NA_IS_DEFUNCT(vpna))) {
		STATS_INC(fs, FSW_STATS_EV_DROP_NA_DEFUNCT);
		err = ENXIO;
		goto error;
	}
	if (!NA_CHANNEL_EVENT_ATTACHED(vpna)) {
		STATS_INC(fs, FSW_STATS_EV_DROP_KEVENT_INACTIVE);
		err = ENXIO;
		goto error;
	}
	if (__improbable(KR_DROP(ring))) {
		STATS_INC(fs, FSW_STATS_EV_DROP_KRDROP_MODE);
		err = ENXIO;
		goto error;
	}

	vpna_pkt = nx_fsw_alloc_packet(ring->ckr_pp, ev_len, &ph);
	if (__improbable(vpna_pkt == NULL)) {
		STATS_INC(fs, FSW_STATS_EV_DROP_NOMEM_PKT);
		err = ENOMEM;
		goto error;
	}
	buf = __packet_get_next_buflet(ph, NULL);
	baddr = __buflet_get_data_address(buf);
	emd = (struct __kern_channel_event_metadata *)(void *)baddr;
	emd->emd_etype = CHANNEL_EVENT_PACKET_TRANSMIT_STATUS;
	emd->emd_nevents = 1;
	bcopy(ev, (baddr + __KERN_CHANNEL_EVENT_OFFSET), ev_len);
	err = __buflet_set_data_length(buf,
	    (ev_len + __KERN_CHANNEL_EVENT_OFFSET));
	VERIFY(err == 0);
	err = __packet_finalize(ph);
	VERIFY(err == 0);
	kr_enter(ring, TRUE);
	protect = sk_sync_protect();
	slot = kern_channel_get_next_slot(ring, NULL, NULL);
	if (slot == NULL) {
		sk_sync_unprotect(protect);
		kr_exit(ring);
		STATS_INC(fs, FSW_STATS_EV_DROP_KRSPACE);
		err = ENOSPC;
		goto error;
	}
	err = kern_channel_slot_attach_packet(ring, slot, ph);
	VERIFY(err == 0);
	vpna_pkt = NULL;
	kern_channel_advance_slot(ring, slot);
	sk_sync_unprotect(protect);
	kr_exit(ring);
	kern_channel_event_notify(&vpna->na_tx_rings[0]);
	STATS_INC(fs, NETIF_STATS_EV_SENT);
	return 0;

error:
	ASSERT(err != 0);
	if (vpna_pkt != NULL) {
		nx_fsw_free_packet(vpna_pkt);
	}
	STATS_INC(fs, FSW_STATS_EV_DROP);
	return err;
}

static inline struct nexus_adapter *
fsw_find_port_vpna(struct nx_flowswitch *fsw, uint32_t nx_port_id)
{
	struct kern_nexus *nx = fsw->fsw_nx;
	struct nexus_adapter *na = NULL;
	nexus_port_t port;
	uint16_t gencnt;

	PKT_DECOMPOSE_NX_PORT_ID(nx_port_id, port, gencnt);

	if (port < FSW_VP_USER_MIN) {
		SK_ERR("non VPNA port");
		return NULL;
	}

	if (__improbable(!nx_port_is_valid(nx, port))) {
		SK_ERR("%s[%d] port no longer valid",
		    if_name(fsw->fsw_ifp), port);
		return NULL;
	}

	na = nx_port_get_na(nx, port);
	if (na != NULL && VPNA(na)->vpna_gencnt != gencnt) {
		return NULL;
	}
	return na;
}

errno_t
fsw_vp_na_channel_event(struct nx_flowswitch *fsw, uint32_t nx_port_id,
    struct __kern_channel_event *event, uint16_t event_len)
{
	int err = 0;
	struct nexus_adapter *fsw_vpna;

	FSW_RLOCK(fsw);
	struct fsw_stats *fs = &fsw->fsw_stats;

	fsw_vpna = fsw_find_port_vpna(fsw, nx_port_id);
	if (__improbable(fsw_vpna == NULL)) {
		err = ENXIO;
		STATS_INC(fs, FSW_STATS_EV_DROP_DEMUX_ERR);
		goto error;
	}
	if (__improbable(fsw_vpna->na_channel_event_notify == NULL)) {
		err = ENOTSUP;
		STATS_INC(fs, FSW_STATS_EV_DROP_EV_VPNA_NOTSUP);
		goto error;
	}
	err = fsw_vpna->na_channel_event_notify(fsw_vpna, event, event_len);
	FSW_RUNLOCK(fsw);
	return err;

error:
	STATS_INC(fs, FSW_STATS_EV_DROP);
	FSW_RUNLOCK(fsw);
	return err;
}
