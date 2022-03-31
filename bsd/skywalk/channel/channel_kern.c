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

#include <sys/kdebug.h>
#include <skywalk/os_skywalk_private.h>
#include <net/ntstat.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/upipe/nx_user_pipe.h>

#define KRING_EMPTY_TX(_kring, _index)  \
	((_kring)->ckr_rhead == (_index))

#define KRING_FULL_RX(_kring, _index)                                   \
	((_kring)->ckr_khead == SLOT_NEXT((_index), (_kring)->ckr_lim))

uint32_t
kern_channel_notify(const kern_channel_ring_t kring, uint32_t flags)
{
#pragma unused(flags)
	if (__improbable(KR_DROP(kring))) {
		return ENXIO;
	}

	return kring->ckr_na_notify(kring, kernproc, 0);
}

uint32_t
kern_channel_reclaim(const kern_channel_ring_t kring)
{
	return kr_reclaim(kring);
}

static inline uint32_t
_kern_channel_available_slot_count_tx(const kern_channel_ring_t kring,
    slot_idx_t index)
{
	ASSERT(kring->ckr_tx == NR_TX);

	if (kring->ckr_rhead < index) {
		return kring->ckr_num_slots + kring->ckr_rhead - index;
	}

	return kring->ckr_rhead - index;
}

static inline uint32_t
_kern_channel_available_slot_count_rx(const kern_channel_ring_t kring,
    slot_idx_t index)
{
	uint32_t busy;
	slot_idx_t lim = kring->ckr_lim;

	ASSERT(kring->ckr_tx == NR_RX);

	if (index < kring->ckr_khead) {
		busy = kring->ckr_num_slots + index - kring->ckr_khead;
	} else {
		busy = index - kring->ckr_khead;
	}

	ASSERT(lim >= busy);
	return lim - busy;
}

uint32_t
kern_channel_available_slot_count(const kern_channel_ring_t kring)
{
	if (kring->ckr_tx == NR_TX) {
		return _kern_channel_available_slot_count_tx(kring,
		           kring->ckr_khead);
	} else {
		return _kern_channel_available_slot_count_rx(kring,
		           kring->ckr_ktail);
	}
}

kern_channel_slot_t
kern_channel_get_next_slot(const kern_channel_ring_t kring,
    const kern_channel_slot_t slot0, struct kern_slot_prop *prop)
{
	kern_channel_slot_t slot;
	slot_idx_t slot_idx;

	/* Ensure this is only done by the thread doing a sync syscall */
	VERIFY(sk_is_sync_protected());

	if (__improbable(slot0 == NULL)) {
		if (kring->ckr_tx == NR_TX) {
			slot_idx = kring->ckr_khead;
		} else {
			slot_idx = kring->ckr_ktail;
		}
	} else {
		slot_idx = SLOT_NEXT(KR_SLOT_INDEX(kring, slot0),
		    kring->ckr_lim);
	}

	ASSERT(slot_idx < kring->ckr_num_slots);

	if (kring->ckr_tx == NR_TX) {
		if (__improbable(KRING_EMPTY_TX(kring, slot_idx))) {
			SK_DF(SK_VERB_SYNC | SK_VERB_TX,
			    "EMPTY_TX: na \"%s\" kr \"%s\" "
			    "i %u (kc %u kt %u kl %u | rh %u rt %u)",
			    KRNA(kring)->na_name,
			    kring->ckr_name, slot_idx, kring->ckr_khead,
			    kring->ckr_ktail, kring->ckr_klease,
			    kring->ckr_rhead, kring->ckr_rtail);
			slot = NULL;
		} else {
			slot = &kring->ckr_ksds[slot_idx];
		}
	} else {
		if (__improbable(KRING_FULL_RX(kring, slot_idx))) {
			SK_DF(SK_VERB_SYNC | SK_VERB_RX,
			    "FULL_RX: na \"%s\" kr \"%s\" "
			    "i %u (kc %u kt %u kl %u | rh %u rt %u)",
			    KRNA(kring)->na_name,
			    kring->ckr_name, slot_idx, kring->ckr_khead,
			    kring->ckr_ktail, kring->ckr_klease,
			    kring->ckr_rhead, kring->ckr_rtail);
			slot = NULL;
		} else {
			slot = &kring->ckr_ksds[slot_idx];
		}
	}

	if (prop != NULL) {
		bzero(prop, sizeof(*prop));
	}

	return slot;
}

static inline void
_kern_channel_advance_slot_tx(const kern_channel_ring_t kring, slot_idx_t index)
{
	/* Ensure this is only done by the thread doing a sync syscall */
	VERIFY(sk_is_sync_protected());
	kr_txkring_reclaim_and_refill(kring, index);
}

static inline void
_kern_channel_advance_slot_rx(const kern_channel_ring_t kring, slot_idx_t index)
{
	ASSERT(kring->ckr_tx == NR_RX || kring->ckr_tx == NR_EV);
	/* Ensure this is only done by the thread doing a sync syscall */
	VERIFY(sk_is_sync_protected());

	kring->ckr_ktail = SLOT_NEXT(index, kring->ckr_lim);
}

void
kern_channel_advance_slot(const kern_channel_ring_t kring,
    kern_channel_slot_t slot)
{
	slot_idx_t index = KR_SLOT_INDEX(kring, slot);
	ASSERT(index < kring->ckr_num_slots);

	if (kring->ckr_tx == NR_TX) {
		_kern_channel_advance_slot_tx(kring, index);
	} else {
		_kern_channel_advance_slot_rx(kring, index);
	}
}

void *
kern_channel_get_context(const kern_channel_t ch)
{
	return ch->ch_ctx;
}

void *
kern_channel_ring_get_context(const kern_channel_ring_t kring)
{
	return kring->ckr_ctx;
}

errno_t
kern_channel_ring_get_container(const kern_channel_ring_t kring,
    kern_packet_t **array, uint32_t *count)
{
	/* Ensure this is only done by the thread doing a sync syscall */
	VERIFY(sk_is_sync_protected());

	if (array == NULL) {
		return EINVAL;
	}

	*array = kring->ckr_scratch;
	if (count != NULL) {
		*count = na_get_nslots(kring->ckr_na, kring->ckr_tx);
	}

	return 0;
}

void *
kern_channel_slot_get_context(const kern_channel_ring_t kring,
    const kern_channel_slot_t slot)
{
	slot_idx_t i = KR_SLOT_INDEX(kring, slot);
	void *slot_ctx = NULL;

	if (kring->ckr_slot_ctxs != NULL) {
		slot_ctx = (void *)(kring->ckr_slot_ctxs[i].slot_ctx_arg);
	}

	return slot_ctx;
}

void
kern_channel_increment_ring_stats(kern_channel_ring_t kring,
    struct kern_channel_ring_stat_increment *stats)
{
	kr_update_stats(kring, stats->kcrsi_slots_transferred,
	    stats->kcrsi_bytes_transferred);
}

void
kern_channel_increment_ring_net_stats(kern_channel_ring_t kring,
    struct ifnet *ifp, struct kern_channel_ring_stat_increment *stats)
{
	if (kring->ckr_tx == NR_TX) {
		atomic_add_64(&ifp->if_data.ifi_opackets,
		    stats->kcrsi_slots_transferred);
		atomic_add_64(&ifp->if_data.ifi_obytes,
		    stats->kcrsi_bytes_transferred);
	} else {
		atomic_add_64(&ifp->if_data.ifi_ipackets,
		    stats->kcrsi_slots_transferred);
		atomic_add_64(&ifp->if_data.ifi_ibytes,
		    stats->kcrsi_bytes_transferred);
	}

	if (ifp->if_data_threshold != 0) {
		ifnet_notify_data_threshold(ifp);
	}

	kr_update_stats(kring, stats->kcrsi_slots_transferred,
	    stats->kcrsi_bytes_transferred);
}

kern_packet_t
kern_channel_slot_get_packet(const kern_channel_ring_t kring,
    const kern_channel_slot_t slot)
{
#if (DEVELOPMENT || DEBUG)
	/* catch invalid slot */
	slot_idx_t idx = KR_SLOT_INDEX(kring, slot);
	struct __kern_slot_desc *ksd = KR_KSD(kring, idx);
#else
#pragma unused(kring)
	struct __kern_slot_desc *ksd = SLOT_DESC_KSD(slot);
#endif /* (DEVELOPMENT || DEBUG) */
	struct __kern_quantum *kqum = ksd->sd_qum;

	if (__improbable(kqum == NULL ||
	    (kqum->qum_qflags & QUM_F_DROPPED) != 0)) {
		return 0;
	}

	return SD_GET_TAGGED_METADATA(ksd);
}

errno_t
kern_channel_slot_attach_packet(const kern_channel_ring_t kring,
    const kern_channel_slot_t slot, kern_packet_t ph)
{
#if (DEVELOPMENT || DEBUG)
	/* catch invalid slot */
	slot_idx_t idx = KR_SLOT_INDEX(kring, slot);
	struct __kern_slot_desc *ksd = KR_KSD(kring, idx);
#else
#pragma unused(kring)
	struct __kern_slot_desc *ksd = SLOT_DESC_KSD(slot);
#endif /* (DEVELOPMENT || DEBUG) */

	return KR_SLOT_ATTACH_METADATA(kring, ksd, SK_PTR_ADDR_KQUM(ph));
}

errno_t
kern_channel_slot_detach_packet(const kern_channel_ring_t kring,
    const kern_channel_slot_t slot, kern_packet_t ph)
{
#pragma unused(ph)
#if (DEVELOPMENT || DEBUG)
	/* catch invalid slot */
	slot_idx_t idx = KR_SLOT_INDEX(kring, slot);
	struct __kern_slot_desc *ksd = KR_KSD(kring, idx);
#else
	struct __kern_slot_desc *ksd = SLOT_DESC_KSD(slot);
#endif /* (DEVELOPMENT || DEBUG) */

	ASSERT(SK_PTR_ADDR_KQUM(ph) ==
	    SK_PTR_ADDR_KQUM(SD_GET_TAGGED_METADATA(ksd)));
	(void) KR_SLOT_DETACH_METADATA(kring, ksd);

	return 0;
}

static errno_t
kern_channel_tx_refill_common(const kern_channel_ring_t hw_kring,
    uint32_t pkt_limit, uint32_t byte_limit, boolean_t tx_doorbell_ctxt,
    boolean_t *pkts_pending, boolean_t canblock)
{
#pragma unused(tx_doorbell_ctxt)
	struct nexus_adapter *hwna;
	struct ifnet *ifp;
	sk_protect_t protect;
	errno_t rc = 0;
	errno_t sync_err = 0;

	KDBG((SK_KTRACE_CHANNEL_TX_REFILL | DBG_FUNC_START), SK_KVA(hw_kring));

	VERIFY(hw_kring != NULL);
	hwna = KRNA(hw_kring);
	ifp = hwna->na_ifp;

	ASSERT(hwna->na_type == NA_NETIF_DEV);
	ASSERT(hw_kring->ckr_tx == NR_TX);
	*pkts_pending = FALSE;

	if (__improbable(pkt_limit == 0 || byte_limit == 0)) {
		SK_ERR("invalid limits plim %d, blim %d",
		    pkt_limit, byte_limit);
		rc = EINVAL;
		goto out;
	}

	if (__improbable(!IF_FULLY_ATTACHED(ifp))) {
		SK_ERR("hwna 0x%llx ifp %s (0x%llx), interface not attached",
		    SK_KVA(hwna), if_name(ifp), SK_KVA(ifp));
		rc = ENXIO;
		goto out;
	}

	if (__improbable((ifp->if_start_flags & IFSF_FLOW_CONTROLLED) != 0)) {
		SK_DF(SK_VERB_SYNC | SK_VERB_TX, "hwna 0x%llx ifp %s (0x%llx), "
		    "flow control ON", SK_KVA(hwna), if_name(ifp), SK_KVA(ifp));
		rc = ENXIO;
		goto out;
	}

	/*
	 * if the ring is busy, it means another dequeue is in
	 * progress, so ignore this request and return success.
	 */
	if (kr_enter(hw_kring, canblock) != 0) {
		rc = 0;
		goto out;
	}

	if (__improbable(KR_DROP(hw_kring) ||
	    !NA_IS_ACTIVE(hw_kring->ckr_na))) {
		kr_exit(hw_kring);
		SK_ERR("hw-kr 0x%llx stopped", SK_KVA(hw_kring));
		rc = ENXIO;
		goto out;
	}

	/*
	 * Unlikely to get here, unless a channel is opened by
	 * a user process directly to the netif.  Issue a TX sync
	 * on the netif device TX ring.
	 */
	protect = sk_sync_protect();
	sync_err = hw_kring->ckr_na_sync(hw_kring, kernproc,
	    NA_SYNCF_NETIF);
	sk_sync_unprotect(protect);
	kr_exit(hw_kring);

	if (rc == 0) {
		rc = sync_err;
	}

out:
	KDBG((SK_KTRACE_CHANNEL_TX_REFILL | DBG_FUNC_END), SK_KVA(hw_kring),
	    rc, 0, 0);

	return rc;
}

errno_t
kern_channel_tx_refill(const kern_channel_ring_t hw_kring,
    uint32_t pkt_limit, uint32_t byte_limit, boolean_t tx_doorbell_ctxt,
    boolean_t *pkts_pending)
{
	if (NA_OWNED_BY_FSW(hw_kring->ckr_na)) {
		return netif_ring_tx_refill(hw_kring, pkt_limit,
		           byte_limit, tx_doorbell_ctxt, pkts_pending, FALSE);
	} else {
		return kern_channel_tx_refill_common(hw_kring, pkt_limit,
		           byte_limit, tx_doorbell_ctxt, pkts_pending, FALSE);
	}
}

errno_t
kern_channel_tx_refill_canblock(const kern_channel_ring_t hw_kring,
    uint32_t pkt_limit, uint32_t byte_limit, boolean_t tx_doorbell_ctxt,
    boolean_t *pkts_pending)
{
	if (NA_OWNED_BY_FSW(hw_kring->ckr_na)) {
		return netif_ring_tx_refill(hw_kring, pkt_limit,
		           byte_limit, tx_doorbell_ctxt, pkts_pending, TRUE);
	} else {
		return kern_channel_tx_refill_common(hw_kring, pkt_limit,
		           byte_limit, tx_doorbell_ctxt, pkts_pending, TRUE);
	}
}

errno_t
kern_channel_get_service_class(const kern_channel_ring_t kring,
    kern_packet_svc_class_t *svc)
{
	if ((KRNA(kring)->na_type != NA_NETIF_DEV) ||
	    (kring->ckr_tx == NR_RX) || (kring->ckr_svc == KPKT_SC_UNSPEC)) {
		return ENOTSUP;
	}
	*svc = kring->ckr_svc;
	return 0;
}

void
kern_channel_flowadv_clear(struct flowadv_fcentry *fce)
{
	const flowadv_token_t ch_token = fce->fce_flowsrc_token;
	const flowadv_token_t flow_token = fce->fce_flowid;
	const flowadv_idx_t flow_fidx = fce->fce_flowsrc_fidx;
	struct ifnet *ifp = fce->fce_ifp;
	struct nexus_adapter *hwna;
	struct kern_nexus *fsw_nx;
	struct kern_channel *ch = NULL;
	struct nx_flowswitch *fsw;

	_CASSERT(sizeof(ch->ch_info->cinfo_ch_token) == sizeof(ch_token));

	SK_LOCK();
	if (ifnet_is_attached(ifp, 0) == 0 || ifp->if_na == NULL) {
		goto done;
	}

	hwna = &ifp->if_na->nifna_up;
	VERIFY((hwna->na_type == NA_NETIF_DEV) ||
	    (hwna->na_type == NA_NETIF_COMPAT_DEV));

	if (!NA_IS_ACTIVE(hwna) || (fsw = fsw_ifp_to_fsw(ifp)) == NULL) {
		goto done;
	}

	fsw_nx = fsw->fsw_nx;
	VERIFY(fsw_nx != NULL);

	/* find the channel */
	STAILQ_FOREACH(ch, &fsw_nx->nx_ch_head, ch_link) {
		if (ch_token == ch->ch_info->cinfo_ch_token) {
			break;
		}
	}

	if (ch != NULL) {
		if (ch->ch_na != NULL &&
		    na_flowadv_clear(ch, flow_fidx, flow_token)) {
			/* trigger flow advisory kevent */
			na_flowadv_event(
				&ch->ch_na->na_tx_rings[ch->ch_first[NR_TX]]);
			SK_DF(SK_VERB_FLOW_ADVISORY,
			    "%s(%d) notified of flow update",
			    ch->ch_name, ch->ch_pid);
		} else if (ch->ch_na == NULL) {
			SK_DF(SK_VERB_FLOW_ADVISORY,
			    "%s(%d) is closing (flow update ignored)",
			    ch->ch_name, ch->ch_pid);
		}
	} else {
		SK_ERR("channel token 0x%x fidx %u on %s not found",
		    ch_token, flow_fidx, ifp->if_xname);
	}
done:
	SK_UNLOCK();
}

void
kern_channel_memstatus(struct proc *p, uint32_t status,
    struct kern_channel *ch)
{
#pragma unused(p, status)
	SK_LOCK_ASSERT_NOTHELD();

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(proc_pid(p) == ch->ch_pid);
	/*
	 * If we're already draining, then bail.  Otherwise, check it
	 * again via na_drain() with the channel lock held.
	 */
	if (ch->ch_na->na_flags & NAF_DRAINING) {
		return;
	}

	SK_DF(SK_VERB_CHANNEL, "%s(%d) ch 0x%llx flags 0x%b status %s",
	    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(ch),
	    ch->ch_flags, CHANF_BITS, sk_memstatus2str(status));

	/* serialize accesses against channel syscalls */
	lck_mtx_lock(&ch->ch_lock);
	na_drain(ch->ch_na, TRUE);   /* purge caches */
	lck_mtx_unlock(&ch->ch_lock);
}

static bool
_kern_channel_defunct_eligible(struct kern_channel *ch)
{
	struct nexus_upipe_adapter *pna;

	if ((ch->ch_info->cinfo_ch_mode & CHMODE_DEFUNCT_OK) == 0) {
		return false;
	}
	if (ch->ch_na->na_type != NA_USER_PIPE) {
		return true;
	}
	pna = (struct nexus_upipe_adapter *)ch->ch_na;
	if ((pna->pna_parent->na_flags & NAF_DEFUNCT_OK) == 0) {
		return false;
	}
	return true;
}

void
kern_channel_defunct(struct proc *p, struct kern_channel *ch)
{
#pragma unused(p)
	uint32_t ch_mode = ch->ch_info->cinfo_ch_mode;

	SK_LOCK_ASSERT_NOTHELD();

	ASSERT(!(ch->ch_flags & CHANF_KERNEL));
	ASSERT(proc_pid(p) == ch->ch_pid);
	/*
	 * If the channel is eligible for defunct, mark it as such.
	 * Otherwise, set the draining flag which tells the reaper
	 * thread to purge any cached objects associated with it.
	 * That draining flag will be cleared then, which allows the
	 * channel to cache objects again once the process is resumed.
	 */
	if (_kern_channel_defunct_eligible(ch)) {
		struct kern_nexus *nx = ch->ch_nexus;
		struct kern_nexus_domain_provider *nxdom_prov = NX_DOM_PROV(nx);
		boolean_t need_defunct;
		int err;

		/*
		 * This may be called often, so check first (without lock) if
		 * the trapdoor flag CHANF_DEFUNCT has been set and bail if so,
		 * for performance reasons.  This check is repeated below with
		 * the channel lock held.
		 */
		if (ch->ch_flags & CHANF_DEFUNCT) {
			return;
		}

		SK_DF(SK_VERB_CHANNEL, "%s(%d) ch 0x%llx flags 0x%b",
		    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(ch),
		    ch->ch_flags, CHANF_BITS);

		/* serialize accesses against channel syscalls */
		lck_mtx_lock(&ch->ch_lock);

		/*
		 * If opportunistic defunct is in effect, skip the rest of
		 * the defunct work based on two cases:
		 *
		 *   a) if the channel isn't using user packet pool; or
		 *   b) if the channel is using user packet pool and we
		 *      detect that there are outstanding allocations.
		 *
		 * Note that for case (a) above we essentially treat the
		 * channel as ineligible for defunct, and although it may
		 * be idle we'd leave the memory mapping intact.  This
		 * should not be a concern as the majority of channels are
		 * on flowswitches where user packet pool is mandatory.
		 *
		 * If skipping, mark the channel with CHANF_DEFUNCT_SKIP
		 * and increment the stats (for flowswitch only).
		 */
		if (sk_opp_defunct && (!(ch_mode & CHMODE_USER_PACKET_POOL) ||
		    !pp_isempty_upp(ch->ch_pp))) {
			if (ch->ch_na->na_type == NA_FLOWSWITCH_VP) {
				struct nx_flowswitch *fsw =
				    VPNA(ch->ch_na)->vpna_fsw;
				STATS_INC(&fsw->fsw_stats,
				    FSW_STATS_CHAN_DEFUNCT_SKIP);
			}
			(void) atomic_bitset_32_ov(&ch->ch_flags,
			    CHANF_DEFUNCT_SKIP);
			/* skip defunct */
			lck_mtx_unlock(&ch->ch_lock);
			return;
		}
		(void) atomic_bitclear_32(&ch->ch_flags, CHANF_DEFUNCT_SKIP);

		/*
		 * Proceed with the rest of the defunct work.
		 */
		if (atomic_bitset_32_ov(&ch->ch_flags, CHANF_DEFUNCT) &
		    CHANF_DEFUNCT) {
			/* already defunct; nothing to do */
			lck_mtx_unlock(&ch->ch_lock);
			return;
		}

		/* mark this channel as inactive */
		ch_deactivate(ch);

		/*
		 * Redirect memory regions for the map; upon success, instruct
		 * the nexus to finalize the defunct and teardown the respective
		 * memory regions.  It's crucial that the redirection happens
		 * first before freeing the objects, since the page protection
		 * flags get inherited only from unfreed segments.  Freed ones
		 * will cause VM_PROT_NONE to be used for the segment span, to
		 * catch use-after-free cases.  For unfreed objects, doing so
		 * may cause an exception when the process is later resumed
		 * and touches an address within the span; hence the ordering.
		 */
		if ((err = skmem_arena_mredirect(ch->ch_na->na_arena,
		    &ch->ch_mmap, p, &need_defunct)) == 0 && need_defunct) {
			/*
			 * Let the domain provider handle the initial tasks of
			 * the defunct that are specific to this channel.  It
			 * may safely free objects as the redirection is done.
			 */
			nxdom_prov->nxdom_prov_dom->nxdom_defunct(nxdom_prov,
			    nx, ch, p);
			/*
			 * Let the domain provider complete the defunct;
			 * do this after dropping the channel lock, as
			 * the nexus may end up acquiring other locks
			 * that would otherwise violate lock ordering.
			 * The channel refcnt is still held by virtue
			 * of the caller holding the process's file
			 * table lock.
			 */
			lck_mtx_unlock(&ch->ch_lock);
			nxdom_prov->nxdom_prov_dom->nxdom_defunct_finalize(
				nxdom_prov, nx, ch, FALSE);
		} else if (err == 0) {
			/*
			 * Let the domain provider handle the initial tasks of
			 * the defunct that are specific to this channel.  It
			 * may sadely free objects as the redirection is done.
			 */
			nxdom_prov->nxdom_prov_dom->nxdom_defunct(nxdom_prov,
			    nx, ch, p);
			lck_mtx_unlock(&ch->ch_lock);
		} else {
			/* already redirected; nothing to do */
			lck_mtx_unlock(&ch->ch_lock);
		}
	} else {
		lck_mtx_lock(&ch->ch_lock);
		na_drain(ch->ch_na, FALSE);  /* prune caches */
		lck_mtx_unlock(&ch->ch_lock);
	}
}
