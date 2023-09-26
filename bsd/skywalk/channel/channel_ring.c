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
#include <kern/sched_prim.h>
#include <sys/sdt.h>

static void kr_update_user_stats(struct __kern_channel_ring *,
    uint32_t, uint32_t);
static void kr_externalize_metadata_internal(struct __kern_channel_ring *,
    const uint32_t, struct __kern_quantum *, struct proc *);

#define KR_TRANSFER_DECAY       2       /* ilog2 of EWMA decay rate (4) */
static uint32_t kr_transfer_decay = 0;

#define KR_ACCUMULATE_INTERVAL  2 /* 2 seconds */
static uint32_t kr_accumulate_interval = KR_ACCUMULATE_INTERVAL;

#if (DEVELOPMENT || DEBUG)
#define KR_STAT_ENABLE          1
#else /* !(DEVELOPMENT || DEBUG) */
#define KR_STAT_ENABLE          0
#endif /* !(DEVELOPMENT || DEBUG) */
/* Enable/Disable ring stats collection */
uint32_t kr_stat_enable = KR_STAT_ENABLE;

#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk, OID_AUTO, ring_transfer_decay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kr_transfer_decay,
    0, "ilog2 of EWMA decay rate of ring transfers");

SYSCTL_UINT(_kern_skywalk, OID_AUTO, ring_stat_accumulate_interval,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kr_accumulate_interval,
    KR_ACCUMULATE_INTERVAL, "accumulation interval for ring stats");

uint32_t kr_disable_panic_on_sync_err = 0;
SYSCTL_UINT(_kern_skywalk, OID_AUTO, disable_panic_on_sync_err,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kr_disable_panic_on_sync_err,
    0, "disable panic on sync error");
#endif /* (DEVELOPMENT || DEBUG) */

SYSCTL_UINT(_kern_skywalk, OID_AUTO, ring_stat_enable,
    CTLFLAG_RW | CTLFLAG_LOCKED, &kr_stat_enable,
    0, "enable/disable stats collection for ring");

#define KR_EWMA(old, new, decay) do {                                   \
	u_int64_t _avg;                                                 \
	if (__probable((_avg = (old)) > 0))                             \
	        _avg = (((_avg << (decay)) - _avg) + (new)) >> (decay); \
	else                                                            \
	        _avg = (new);                                           \
	(old) = _avg;                                                   \
} while (0)

#define _BUF_DLIM(_buf, _pp)    (BUFLET_HAS_LARGE_BUF(_buf) ?           \
	PP_BUF_SIZE_LARGE(_pp) : PP_BUF_SIZE_DEF(_pp))

void
kr_init_to_mhints(struct __kern_channel_ring *kring, uint32_t nslots)
{
	uint32_t tail;

	tail = nslots - 1;

	kring->ckr_transfer_decay = KR_TRANSFER_DECAY;
	kring->ckr_num_slots = nslots;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_lim = (nslots - 1);
	kring->ckr_rhead = kring->ckr_khead = 0;
	/* IMPORTANT: Always keep one slot empty */
	kring->ckr_rtail = kring->ckr_ktail =
	    ((kring->ckr_tx == NR_TX) || (kring->ckr_tx == NR_F) ? tail : 0);
}

/*
 * Try to obtain exclusive right to issue the *sync() or state change
 * operations on the ring.  The right is obtained and must be later
 * relinquished via kr_exit() if and only if kr_enter() returns 0.
 *
 * In all cases the caller will typically skip the ring, possibly collecting
 * errors along the way.
 *
 * If the calling context does not allow sleeping, the caller must pass
 * FALSE in can_sleep; EBUSY may be returned if the right is held by
 * another thread.  Otherwise, the caller may block until the right is
 * released by the previous holder.
 */
int
kr_enter(struct __kern_channel_ring *kr, boolean_t can_sleep)
{
	lck_spin_lock(&kr->ckr_slock);
	if (kr->ckr_owner == current_thread()) {
		ASSERT(kr->ckr_busy != 0);
		kr->ckr_busy++;
		goto done;
	}
	if (!can_sleep) {
		if (kr->ckr_busy != 0) {
			lck_spin_unlock(&kr->ckr_slock);
			return EBUSY;
		}
	} else {
		while (kr->ckr_busy != 0) {
			kr->ckr_want++;
			(void) assert_wait(&kr->ckr_busy, THREAD_UNINT);
			lck_spin_unlock(&kr->ckr_slock);
			(void) thread_block(THREAD_CONTINUE_NULL);
			SK_DF(SK_VERB_LOCKS, "waited for kr \"%s\" "
			    "(0x%llx) busy=%u", kr->ckr_name,
			    SK_KVA(kr), kr->ckr_busy);
			lck_spin_lock(&kr->ckr_slock);
		}
	}
	LCK_SPIN_ASSERT(&kr->ckr_slock, LCK_ASSERT_OWNED);
	ASSERT(kr->ckr_busy == 0);
	kr->ckr_busy++;
	kr->ckr_owner = current_thread();
done:
	lck_spin_unlock(&kr->ckr_slock);

	SK_DF(SK_VERB_LOCKS, "kr \"%s\" (0x%llx) right acquired",
	    kr->ckr_name, SK_KVA(kr));

	return 0;
}

void
kr_exit(struct __kern_channel_ring *kr)
{
	uint32_t want = 0;

	lck_spin_lock(&kr->ckr_slock);
	ASSERT(kr->ckr_busy != 0);
	ASSERT(kr->ckr_owner == current_thread());
	if (--kr->ckr_busy == 0) {
		kr->ckr_owner = NULL;

		/*
		 * we're done with the kring;
		 * notify anyone that has lost the race
		 */
		if ((want = kr->ckr_want) != 0) {
			kr->ckr_want = 0;
			wakeup((void *)&kr->ckr_busy);
			lck_spin_unlock(&kr->ckr_slock);
		} else {
			lck_spin_unlock(&kr->ckr_slock);
		}
	} else {
		lck_spin_unlock(&kr->ckr_slock);
	}

	SK_DF(SK_VERB_LOCKS, "kr \"%s\" (0x%llx) right released (%u waiters)",
	    kr->ckr_name, SK_KVA(kr), want);
}


void
kr_start(struct __kern_channel_ring *kr)
{
	lck_spin_lock(&kr->ckr_slock);
	ASSERT(kr->ckr_busy != 0);
	ASSERT(kr->ckr_state == KR_STOPPED || kr->ckr_state == KR_LOCKED);
	/* now clear the state */
	kr->ckr_state = KR_READY;
	lck_spin_unlock(&kr->ckr_slock);

	kr_exit(kr);

	SK_DF(SK_VERB_LOCKS, "kr \"%s\" (0x%llx) is started",
	    kr->ckr_name, SK_KVA(kr));
}

/*
 * Put the kring in the 'stopped' state: either KR_STOPPED or KR_LOCKED.
 * Also marks the ring as busy, which would require either kr_start() at a
 * later point.
 */
void
kr_stop(struct __kern_channel_ring *kr, uint32_t state)
{
	uint32_t s;

	ASSERT(state == KR_STOPPED || state == KR_LOCKED);

	s = kr_enter(kr, TRUE);
	ASSERT(s == 0);

	lck_spin_lock(&kr->ckr_slock);
	ASSERT(kr->ckr_busy != 0);
	/* now set the state */
	kr->ckr_state = state;
	lck_spin_unlock(&kr->ckr_slock);

	SK_DF(SK_VERB_LOCKS,
	    "kr \"%s\" (0x%llx) krflags 0x%b is now stopped s=%u",
	    kr->ckr_name, SK_KVA(kr), kr->ckr_flags, CKRF_BITS, state);
}

static void
kr_update_user_stats(struct __kern_channel_ring *kring, uint32_t slot_count,
    uint32_t byte_count)
{
	uint64_t now;
	uint32_t transfer_decay = (kr_transfer_decay != 0) ?
	    kr_transfer_decay : kring->ckr_transfer_decay;
	channel_ring_user_stats_t stats = &kring->ckr_usr_stats;

	now = net_uptime();
	kring->ckr_sync_time = now;

	if (kr_stat_enable == 0) {
		return;
	}

	stats->crsu_number_of_syncs++;
	stats->crsu_total_bytes_transferred += byte_count;
	stats->crsu_total_slots_transferred += slot_count;

	if (slot_count > stats->crsu_max_slots_transferred) {
		stats->crsu_max_slots_transferred = slot_count;
	}

	if (stats->crsu_min_slots_transferred == 0 ||
	    slot_count < stats->crsu_min_slots_transferred) {
		stats->crsu_min_slots_transferred = slot_count;
	}

	if (__probable(kring->ckr_user_accumulate_start != 0)) {
		if ((now - kring->ckr_user_accumulate_start) >=
		    kr_accumulate_interval) {
			uint64_t        bps;
			uint64_t        sps;
			uint64_t        sps_ma;

			/* bytes per sync */
			bps = kring->ckr_user_accumulated_bytes /
			    kring->ckr_user_accumulated_syncs;
			KR_EWMA(stats->crsu_bytes_per_sync_ma,
			    bps, transfer_decay);
			stats->crsu_bytes_per_sync = bps;

			/* slots per sync */
			sps = kring->ckr_user_accumulated_slots /
			    kring->ckr_user_accumulated_syncs;
			sps_ma = stats->crsu_slots_per_sync_ma;
			KR_EWMA(sps_ma, sps, transfer_decay);
			stats->crsu_slots_per_sync_ma = (uint32_t)sps_ma;
			stats->crsu_slots_per_sync = (uint32_t)sps;

			/* start over */
			kring->ckr_user_accumulate_start = now;
			kring->ckr_user_accumulated_bytes = 0;
			kring->ckr_user_accumulated_slots = 0;
			kring->ckr_user_accumulated_syncs = 0;

			stats->crsu_min_slots_transferred = 0;
			stats->crsu_max_slots_transferred = 0;
		}
	} else {
		kring->ckr_user_accumulate_start = now;
	}

	kring->ckr_user_accumulated_bytes += byte_count;
	kring->ckr_user_accumulated_slots += slot_count;
	kring->ckr_user_accumulated_syncs++;
}

/* caller to make sure thread safety */
void
kr_update_stats(struct __kern_channel_ring *kring, uint32_t slot_count,
    uint32_t byte_count)
{
	uint64_t now;
	uint64_t diff_secs;
	channel_ring_stats_t stats = &kring->ckr_stats;
	uint32_t transfer_decay = (kr_transfer_decay != 0) ?
	    kr_transfer_decay : kring->ckr_transfer_decay;

	if (kr_stat_enable == 0) {
		return;
	}

	if (__improbable(slot_count == 0)) {
		return;
	}

	stats->crs_number_of_transfers++;
	stats->crs_total_bytes_transferred += byte_count;
	stats->crs_total_slots_transferred += slot_count;
	if (slot_count > stats->crs_max_slots_transferred) {
		stats->crs_max_slots_transferred = slot_count;
	}
	if (stats->crs_min_slots_transferred == 0 ||
	    slot_count < stats->crs_min_slots_transferred) {
		stats->crs_min_slots_transferred = slot_count;
	}

	now = net_uptime();
	if (__probable(kring->ckr_accumulate_start != 0)) {
		diff_secs = now - kring->ckr_accumulate_start;
		if (diff_secs >= kr_accumulate_interval) {
			uint64_t        bps;
			uint64_t        sps;
			uint64_t        sps_ma;

			/* bytes per second */
			bps = kring->ckr_accumulated_bytes / diff_secs;
			KR_EWMA(stats->crs_bytes_per_second_ma,
			    bps, transfer_decay);
			stats->crs_bytes_per_second = bps;

			/* slots per second */
			sps = kring->ckr_accumulated_slots / diff_secs;
			sps_ma = stats->crs_slots_per_second_ma;
			KR_EWMA(sps_ma, sps, transfer_decay);
			stats->crs_slots_per_second_ma = (uint32_t)sps_ma;
			stats->crs_slots_per_second = (uint32_t)sps;

			/* start over */
			kring->ckr_accumulate_start = now;
			kring->ckr_accumulated_bytes = 0;
			kring->ckr_accumulated_slots = 0;

			stats->crs_min_slots_transferred = 0;
			stats->crs_max_slots_transferred = 0;
		}
	} else {
		kring->ckr_accumulate_start = now;
	}
	kring->ckr_accumulated_bytes += byte_count;
	kring->ckr_accumulated_slots += slot_count;
}

/* True if no space in the tx ring. only valid after kr_txsync_prologue */
boolean_t
kr_txempty(struct __kern_channel_ring *kring)
{
	return kring->ckr_rhead == kring->ckr_ktail;
}

#if SK_LOG
/*
 * Error logging routine called when txsync/rxsync detects an error.
 * Expected to be called before killing the process with skywalk_kill_process()
 *
 * This routine is only called by the upper half of the kernel.
 * It only reads khead (which is changed only by the upper half, too)
 * and ktail (which may be changed by the lower half, but only on
 * a tx ring and only to increase it, so any error will be recovered
 * on the next call). For the above, we don't strictly need to call
 * it under lock.
 */
void
kr_log_bad_ring(struct __kern_channel_ring *kring)
{
	struct __user_channel_ring *ring = kring->ckr_ring;
	const slot_idx_t lim = kring->ckr_lim;
	slot_idx_t i;
	int errors = 0;

	// XXX KASSERT nm_kr_tryget
	SK_ERR("kr \"%s\" (0x%llx) krflags 0x%b", kring->ckr_name,
	    SK_KVA(kring), kring->ckr_flags, CKRF_BITS);
	// XXX probably wrong to trust userspace

	if (ring->ring_head > lim) {
		errors++;
	}
	if (ring->ring_tail > lim) {
		errors++;
	}
	for (i = 0; i <= lim; i++) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, i);
		struct __kern_quantum *kqum = ksd->sd_qum;
		obj_idx_t idx;
		uint32_t len;

		if (!KSD_VALID_METADATA(ksd)) {
			continue;
		}

		idx = METADATA_IDX(kqum);
		len = kqum->qum_len;
		if (len > kring->ckr_max_pkt_len) {
			SK_RDERR(5, "bad len at slot %u idx %u len %u",
			    i, idx, len);
		}
	}

	if (errors != 0) {
		SK_ERR("total %d errors", errors);
		SK_ERR("kr \"%s\" (0x%llx) krflags 0x%b crash, "
		    "head %u -> %u tail %u -> %u", kring->ckr_name,
		    SK_KVA(kring), kring->ckr_flags, CKRF_BITS, ring->ring_head,
		    kring->ckr_rhead, kring->ckr_khead,
		    ring->ring_tail, kring->ckr_ktail);
	}
}
#endif /* SK_LOG */

uint32_t
kr_reclaim(struct __kern_channel_ring *kr)
{
	int r = 0;

	VERIFY(sk_is_sync_protected());

	/*
	 * This is a no-op for TX ring, since the TX reclaim logic is only
	 * known to the nexus itself.  There, the nexus's TX sync code would
	 * figure out the number of slots that has been "transmitted", and
	 * advance the slot pointer accordingly.  This routine would then be
	 * called as a way to advise the system of such condition.
	 *
	 * For RX ring, this will reclaim user-released slots, and it is
	 * to be called by the provider's RX sync routine prior to its
	 * processing new slots (into the RX ring).
	 *
	 * It is therefore advised that this routine be called at the start
	 * of the RX sync callback, as well as at the end of the TX sync
	 * callback; the latter is useful in case we decide to implement
	 * more logic in future.
	 */
	if ((kr->ckr_tx == NR_RX) || (kr->ckr_tx == NR_EV)) {
		/* # of reclaimed slots */
		r = kr->ckr_rhead - kr->ckr_khead;
		if (r < 0) {
			r += kr->ckr_num_slots;
		}

		kr->ckr_khead = kr->ckr_rhead;
		/* ensure global visibility */
		os_atomic_thread_fence(seq_cst);
	}

	return (slot_idx_t)r;
}

/*
 * Nexus-specific kr_txsync_prologue() callback.
 */
int
kr_txprologue(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, uint32_t *byte_count, uint64_t *err_reason,
    struct proc *p)
{
	struct kern_pbufpool *pp = kring->ckr_pp;
	const uint32_t maxfrags = pp->pp_max_frags;
	slot_idx_t slot_idx = kring->ckr_rhead;

	ASSERT(!(KRNA(kring)->na_flags & NAF_USER_PKT_POOL));

	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __kern_quantum *kqum = ksd->sd_qum;
		int err;

		if (__improbable(!(kqum->qum_qflags & QUM_F_KERNEL_ONLY) &&
		    METADATA_IDX(kqum) != METADATA_IDX(kqum->qum_user))) {
			SK_ERR("qum index mismatch");
			*err_reason = SKYWALK_KILL_REASON_QUM_IDX_MISMATCH;
			return -1;
		}

		/* Internalize */
		err = kr_internalize_metadata(ch, kring, maxfrags, kqum, p);
		if (__improbable(err != 0)) {
			SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u dropped "
			    "(err %d) kh %u kt %u | rh %u rt %u | h %u t %u",
			    sk_proc_name_address(p), sk_proc_pid(p),
			    kring->ckr_name, SK_KVA(kring), slot_idx, err,
			    kring->ckr_khead, kring->ckr_ktail,
			    kring->ckr_rhead, kring->ckr_rtail,
			    kring->ckr_ring->ring_head,
			    kring->ckr_ring->ring_tail);
			*err_reason = SKYWALK_KILL_REASON_INTERNALIZE_FAILED;
			return -1;
		}

		*byte_count += kqum->qum_len;
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	return 0;
}

/*
 * Nexus-specific kr_txsync_prologue() callback - user packet pool variant.
 */
int
kr_txprologue_upp(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, uint32_t *byte_count, uint64_t *err_reason,
    struct proc *p)
{
	struct kern_pbufpool *pp = kring->ckr_pp;
	const uint32_t maxfrags = pp->pp_max_frags;
	slot_idx_t slot_idx = kring->ckr_rhead;
	struct __kern_quantum *kqum = NULL;
	bool free_pkt = false;
	int err = 0;

	ASSERT(KRNA(kring)->na_flags & NAF_USER_PKT_POOL);

	PP_LOCK(pp);
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __user_slot_desc *usd = KR_USD(kring, slot_idx);

		/*
		 * The channel is operating in user packet pool mode;
		 * check if the packet is in the allocated list.
		 */
		kqum = pp_remove_upp_locked(pp, usd->sd_md_idx, &err);
		if (__improbable(err != 0)) {
			if (kqum != NULL) {
				SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u "
				    "kqum %p, bad buflet chain",
				    sk_proc_name_address(p), sk_proc_pid(p),
				    kring->ckr_name, SK_KVA(kring), slot_idx,
				    SK_KVA(kqum));
				*err_reason =
				    SKYWALK_KILL_REASON_BAD_BUFLET_CHAIN;
				goto done;
			}

			SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u "
			    " unallocated packet %u kh %u kt %u | "
			    "rh %u rt %u | h %u t %u",
			    sk_proc_name_address(p), sk_proc_pid(p),
			    kring->ckr_name, SK_KVA(kring), slot_idx,
			    usd->sd_md_idx, kring->ckr_khead, kring->ckr_ktail,
			    kring->ckr_rhead, kring->ckr_rtail,
			    kring->ckr_ring->ring_head,
			    kring->ckr_ring->ring_tail);
			*err_reason = SKYWALK_KILL_REASON_UNALLOCATED_PKT;
			goto done;
		}

		if (__improbable(!(kqum->qum_qflags & QUM_F_KERNEL_ONLY) &&
		    METADATA_IDX(kqum) != METADATA_IDX(kqum->qum_user))) {
			SK_ERR("qum index mismatch");
			*err_reason = SKYWALK_KILL_REASON_QUM_IDX_MISMATCH;
			err = ERANGE;
			free_pkt = true;
			goto done;
		}

		/* Internalize */
		err = kr_internalize_metadata(ch, kring, maxfrags, kqum, p);
		if (__improbable(err != 0)) {
			SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u dropped "
			    "(err %d) kh %u kt %u | rh %u rt %u | h %u t %u",
			    sk_proc_name_address(p), sk_proc_pid(p),
			    kring->ckr_name, SK_KVA(kring), slot_idx, err,
			    kring->ckr_khead, kring->ckr_ktail,
			    kring->ckr_rhead, kring->ckr_rtail,
			    kring->ckr_ring->ring_head,
			    kring->ckr_ring->ring_tail);
			*err_reason = SKYWALK_KILL_REASON_INTERNALIZE_FAILED;
			free_pkt = true;
			goto done;
		}

		/*
		 * Attach packet to slot, detach mapping from alloc ring slot.
		 */
		kqum->qum_ksd = NULL;
		USD_RESET(usd);
		KR_SLOT_ATTACH_METADATA(kring, ksd, kqum);

		*byte_count += kqum->qum_len;
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

done:
	PP_UNLOCK(pp);
	if (__improbable(err != 0) && free_pkt) {
		ASSERT(kqum != NULL);
		kqum->qum_ksd = NULL;
		pp_free_packet(pp, (uint64_t)kqum);
	}
	return err;
}

#define NM_FAIL_ON(t, reason) if (__improbable(t)) { SK_ERR("fail " #t); \
	err_reason = reason; goto error; }
/*
 * Validate parameters in the TX/FREE ring/kring.
 *
 * ckr_rhead, ckr_rtail=ktail are stored from previous round.
 * khead is the next packet to send to the ring.
 *
 * We want
 *    khead <= *ckr_rhead <= head <= tail = *ckr_rtail <= ktail
 *
 * ckr_khead, ckr_rhead, ckr_rtail and ckr_ktail are reliable
 */
#define _KR_TXRING_VALIDATE(_kring, _ring, _kh, _kt, _rh, _krt) do {\
	slot_idx_t _n = (_kring)->ckr_num_slots;                        \
	/* kernel sanity checks */                                      \
	NM_FAIL_ON((_kh) >= _n || kring->ckr_rhead >= _n || (_krt) >= _n || \
	    (_kt) >= _n, SKYWALK_KILL_REASON_BASIC_SANITY);             \
	/* user basic sanity checks */                                  \
	NM_FAIL_ON((_rh) >= _n, SKYWALK_KILL_REASON_BASIC_SANITY);      \
	/* \
	 * user sanity checks. We only use 'cur', \
	 * A, B, ... are possible positions for cur: \
	 * \
	 *  0    A  cur   B  tail  C  n-1 \
	 *  0    D  tail  E  cur   F  n-1 \
	 * \
	 * B, F, D are valid. A, C, E are wrong \
	 */                                                             \
	if ((_krt) >= kring->ckr_rhead) {                               \
	/* want ckr_rhead <= head <= ckr_rtail */               \
	        NM_FAIL_ON((_rh) < kring->ckr_rhead || (_rh) > (_krt),  \
	            SKYWALK_KILL_REASON_HEAD_OOB);                      \
	} else { /* here ckr_rtail < ckr_rhead */                       \
	/* we need head outside ckr_rtail .. ckr_rhead */       \
	        NM_FAIL_ON((_rh) > (_krt) && (_rh) < kring->ckr_rhead,  \
	            SKYWALK_KILL_REASON_HEAD_OOB_WRAPPED);              \
	}                                                               \
	NM_FAIL_ON(ring->ring_tail != (_krt),                           \
	    SKYWALK_KILL_REASON_TAIL_MISMATCH);                         \
} while (0)

/*
 * Validate parameters in the ring/kring on entry for *_txsync().
 * Returns ring->ring_head if ok, or something >= kring->ckr_num_slots
 * in case of error, in order to force a reinit.
 */
slot_idx_t
kr_txsync_prologue(struct kern_channel *ch, struct __kern_channel_ring *kring,
    struct proc *p)
{
	struct __user_channel_ring *ring = kring->ckr_ring;
	slot_idx_t ckr_khead, ckr_ktail, ckr_rtail;
	slot_idx_t head;
	uint32_t byte_count = 0;
	uint64_t err_reason = 0;
	int slot_count;

	VERIFY(sk_is_sync_protected());
	/* assert that this routine is only called for user facing rings */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(kring->ckr_usds != NULL);

	/* read these once and use local copies */
	head = ring->ring_head;
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;
	os_atomic_thread_fence(seq_cst);
	ckr_rtail = kring->ckr_rtail;

	SK_DF(SK_VERB_SYNC | SK_VERB_TX, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, ckr_rtail,
	    ring->ring_head, ring->ring_tail);

	_KR_TXRING_VALIDATE(kring, ring, ckr_khead, ckr_ktail, head, ckr_rtail);

	/* # of new tx slots */
	slot_count = head - kring->ckr_rhead;
	if (slot_count < 0) {
		slot_count += kring->ckr_num_slots;
	}

	/*
	 * Invoke nexus-specific TX prologue callback, set in na_kr_create().
	 */
	if (kring->ckr_prologue != NULL && (kring->ckr_prologue(ch,
	    kring, head, &byte_count, &err_reason, p) != 0)) {
		goto error;
	}

	/* update the user's view of slots & bytes transferred */
	kr_update_user_stats(kring, slot_count, byte_count);

	/* update the kernel view of ring */
	kring->ckr_rhead = head;

	/* save for kr_txsync_finalize(); only khead is needed */
	kring->ckr_khead_pre = ckr_khead;

	return head;

error:
	SK_ERR("%s(%d) kr \"%s\" (0x%llx) krflags 0x%b error: kh %u kt %u | "
	    "rh %u rt %u | h %u t %u |", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, ckr_khead, ckr_ktail, kring->ckr_rhead,
	    ckr_rtail, head, ring->ring_tail);

	skywalk_kill_process(p, err_reason | SKYWALK_KILL_REASON_TX_SYNC);

	return kring->ckr_num_slots;
}

/*
 * Validate parameters in the ring/kring on entry for *_free_sync().
 * Returns ring->ring_head if ok, or something >= kring->ckr_num_slots
 * in case of error, in order to force a reinit.
 */
slot_idx_t
kr_free_sync_prologue(struct __kern_channel_ring *kring, struct proc *p)
{
	struct __user_channel_ring *ring = kring->ckr_ring;
	slot_idx_t ckr_khead, ckr_ktail, ckr_rtail;
	slot_idx_t head;
	uint64_t err_reason = 0;

	VERIFY(sk_is_sync_protected());
	/* read these once and use local copies */
	head = ring->ring_head;
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;
	os_atomic_thread_fence(seq_cst);
	ckr_rtail = kring->ckr_rtail;

	SK_DF(SK_VERB_SYNC, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, ckr_rtail, ring->ring_head, ring->ring_tail);

	_KR_TXRING_VALIDATE(kring, ring, ckr_khead, ckr_ktail, head, ckr_rtail);

	/* update the kernel view of ring */
	kring->ckr_rhead = head;
	return head;

error:
	SK_ERR("%s(%d) kr \"%s\" (0x%llx) krflags 0x%b error: kh %u kt %u | "
	    "rh %u rt %u | h %u t %u |", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, ckr_khead, ckr_ktail, kring->ckr_rhead,
	    ckr_rtail, head, ring->ring_tail);

	skywalk_kill_process(p, err_reason | SKYWALK_KILL_REASON_FREE_SYNC);
	return kring->ckr_num_slots;
}

/*
 * Nexus-specific kr_rxsync_prologue() callback.
 */
int
kr_rxprologue(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, uint32_t *byte_count, uint64_t *err_reason,
    struct proc *p)
{
#pragma unused(ch, p)
	slot_idx_t slot_idx = kring->ckr_rhead;
	uint32_t nfree = 0;

	ASSERT(!(KRNA(kring)->na_flags & NAF_USER_PKT_POOL));

	/*
	 * Iterating through the slots just read by user-space;
	 * ckr_rhead -> ring_head
	 */
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __kern_quantum *kqum = ksd->sd_qum;

		ASSERT(KSD_VALID_METADATA(ksd));
		/* # of new bytes transferred */
		*byte_count += kqum->qum_len;

		/* detach and free the packet */
		(void) KR_SLOT_DETACH_METADATA(kring, ksd);
		ASSERT(nfree < kring->ckr_num_slots);
		kring->ckr_scratch[nfree++] = (uint64_t)kqum;

		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	if (nfree > 0) {
		pp_free_packet_batch(kring->ckr_pp,
		    &kring->ckr_scratch[0], nfree);
	}

	/*
	 * Update userspace channel statistics of # readable bytes
	 * subtract byte counts from slots just given back to the kernel.
	 */
	if (kring->ckr_ready_bytes < *byte_count) {
		SK_ERR("%s(%d) kr \"%s\" (0x%llx) inconsistent ready bytes "
		    "(%u < %u)  kh %u kt %u | rh %u rt %u | h %u t %u",
		    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
		    SK_KVA(kring), kring->ckr_ready_bytes, *byte_count,
		    kring->ckr_khead, kring->ckr_ktail, kring->ckr_rhead,
		    kring->ckr_rtail, kring->ckr_ring->ring_head,
		    kring->ckr_ring->ring_tail);
		*err_reason = SKYWALK_KILL_REASON_INCONSISTENT_READY_BYTES;
		return -1;
	}
	kring->ckr_ready_bytes -= *byte_count;

	return 0;
}

/*
 * Nexus-specific kr_rxsync_prologue() callback - no detach variant.
 */
int
kr_rxprologue_nodetach(struct kern_channel *ch,
    struct __kern_channel_ring *kring, const slot_idx_t head,
    uint32_t *byte_count, uint64_t *err_reason, struct proc *p)
{
#pragma unused(ch, p)
	slot_idx_t slot_idx = kring->ckr_rhead;

	ASSERT(!(KRNA(kring)->na_flags & NAF_USER_PKT_POOL));

	/*
	 * Iterating through the slots just read by user-space;
	 * ckr_rhead -> ring_head
	 */
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __kern_quantum *kqum = ksd->sd_qum;

		ASSERT(KSD_VALID_METADATA(ksd));
		/* # of new bytes transferred */
		*byte_count += kqum->qum_len;
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	/*
	 * Update userspace channel statistics of # readable bytes
	 * subtract byte counts from slots just given back to the kernel.
	 */
	if (kring->ckr_ready_bytes < *byte_count) {
		SK_ERR("%s(%d) kr \"%s\" (0x%llx) inconsistent ready bytes "
		    "(%u < %u)  kh %u kt %u | rh %u rt %u | h %u t %u",
		    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
		    SK_KVA(kring), kring->ckr_ready_bytes, *byte_count,
		    kring->ckr_khead, kring->ckr_ktail, kring->ckr_rhead,
		    kring->ckr_rtail, kring->ckr_ring->ring_head,
		    kring->ckr_ring->ring_tail);
		*err_reason = SKYWALK_KILL_REASON_INCONSISTENT_READY_BYTES;
#if (DEVELOPMENT || DEBUG)
		if (kr_disable_panic_on_sync_err == 0) {
			panic("kr(0x%llx), inconsistent, head %u, ready %llu, "
			    "cnt %u", SK_KVA(kring), head,
			    kring->ckr_ready_bytes, *byte_count);
			/* NOTREACHED */
			__builtin_unreachable();
		}
#else /* (DEVELOPMENT || DEBUG) */
		return -1;
#endif /* !(DEVELOPMENT || DEBUG) */
	}
	kring->ckr_ready_bytes -= *byte_count;

	return 0;
}

/*
 * Nexus-specific kr_rxsync_prologue() callback - user packet pool variant.
 */
int
kr_rxprologue_upp(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, uint32_t *byte_count, uint64_t *err_reason,
    struct proc *p)
{
#pragma unused(ch, p)
	slot_idx_t slot_idx = kring->ckr_rhead;

	ASSERT(KRNA(kring)->na_flags & NAF_USER_PKT_POOL);

	/*
	 * Iterating through the slots just read by user-space;
	 * ckr_rhead -> ring_head
	 */
	while (slot_idx != head) {
		struct __user_slot_desc *usd = KR_USD(kring, slot_idx);

		/*
		 * This is a user facing ring opting in for the user packet
		 * pool mode, so ensure that the user has detached packet
		 * from slot.
		 */
		ASSERT(!KSD_VALID_METADATA(KR_KSD(kring, slot_idx)));
		if (SD_VALID_METADATA(usd)) {
			SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u not "
			    "detached md %u kh %u kt %u | rh %u rt %u |"
			    " h %u t %u", sk_proc_name_address(p),
			    sk_proc_pid(p), kring->ckr_name,
			    SK_KVA(kring), slot_idx, usd->sd_md_idx,
			    kring->ckr_khead, kring->ckr_ktail,
			    kring->ckr_rhead, kring->ckr_rtail,
			    kring->ckr_ring->ring_head,
			    kring->ckr_ring->ring_tail);
			*err_reason = SKYWALK_KILL_REASON_SLOT_NOT_DETACHED;
			return -1;
		}
		*byte_count += usd->sd_len;

		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	/*
	 * update userspace channel statistics of # readable bytes
	 * subtract byte counts from slots just given back to the kernel
	 */
	if (kring->ckr_ready_bytes < *byte_count) {
		SK_ERR("%s(%d) kr \"%s\" (0x%llx) inconsistent ready bytes "
		    "(%u < %u)  kh %u kt %u | rh %u rt %u | h %u t %u",
		    sk_proc_name_address(p), sk_proc_pid(p), kring->ckr_name,
		    SK_KVA(kring), kring->ckr_ready_bytes, *byte_count,
		    kring->ckr_khead, kring->ckr_ktail, kring->ckr_rhead,
		    kring->ckr_rtail, kring->ckr_ring->ring_head,
		    kring->ckr_ring->ring_tail);
		*err_reason = SKYWALK_KILL_REASON_INCONSISTENT_READY_BYTES;
		return -1;
	}
	kring->ckr_ready_bytes -= *byte_count;

	return 0;
}

/*
 * Validate parameters in the RX/ALLOC/EVENT ring/kring.
 * For a valid configuration,
 * khead <= head <= tail <= ktail
 *
 * We only consider head.
 * khead and ktail are reliable.
 */
#define _KR_RXRING_VALIDATE(_kring, _ring, _kh, _kt, _rh)       do {    \
	slot_idx_t _n = (_kring)->ckr_num_slots;                        \
	/* kernel sanity checks */                                      \
	NM_FAIL_ON((_kh) >= _n || (_kt) >= _n,                          \
	    SKYWALK_KILL_REASON_BASIC_SANITY);                          \
	/* user sanity checks */                                        \
	if ((_kt) >= (_kh)) {                                           \
	/* want khead <= head <= ktail */                       \
	        NM_FAIL_ON((_rh) < (_kh) || (_rh) > (_kt),              \
	            SKYWALK_KILL_REASON_HEAD_OOB);                      \
	} else {                                                        \
	/* we need head outside ktail..khead */                 \
	        NM_FAIL_ON((_rh) < (_kh) && (_rh) > (_kt),              \
	            SKYWALK_KILL_REASON_HEAD_OOB_WRAPPED);              \
	}                                                               \
	NM_FAIL_ON((_ring)->ring_tail != (_kring)->ckr_rtail,           \
	    SKYWALK_KILL_REASON_TAIL_MISMATCH);                         \
} while (0)

/*
 * Validate parameters in the ring/kring on entry for *_rxsync().
 * Returns ring->ring_head if ok, kring->ckr_num_slots on error,
 * in order to force a reinit.
 */
slot_idx_t
kr_rxsync_prologue(struct kern_channel *ch, struct __kern_channel_ring *kring,
    struct proc *p)
{
#pragma unused(ch)
	struct __user_channel_ring *ring = kring->ckr_ring;
	slot_idx_t ckr_khead, ckr_ktail;
	slot_idx_t head;
	uint32_t byte_count = 0;
	uint64_t err_reason = 0;
	int slot_count;

	VERIFY(sk_is_sync_protected());
	/* assert that this routine is only called for user facing rings */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(kring->ckr_usds != NULL);

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;

	SK_DF(SK_VERB_SYNC | SK_VERB_RX, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    ring->ring_head, ring->ring_tail);
	/*
	 * Before storing the new values, we should check they do not
	 * move backwards. However:
	 * - head is not an issue because the previous value is khead;
	 * - cur could in principle go back, however it does not matter
	 *   because we are processing a brand new rxsync()
	 */
	head = ring->ring_head; /* read only once */

	_KR_RXRING_VALIDATE(kring, ring, ckr_khead, ckr_ktail, head);

	/* # of reclaimed slots */
	slot_count = head - kring->ckr_rhead;
	if (slot_count < 0) {
		slot_count += kring->ckr_num_slots;
	}

	/*
	 * Invoke nexus-specific RX prologue callback, which may detach
	 * and free any consumed packets.  Configured in na_kr_create().
	 */
	if (kring->ckr_prologue != NULL && (kring->ckr_prologue(ch,
	    kring, head, &byte_count, &err_reason, p) != 0)) {
		goto error;
	}
	/* update the user's view of slots & bytes transferred */
	kr_update_user_stats(kring, slot_count, byte_count);

	/* update the kernel view of ring */
	kring->ckr_rhead = head;
	return head;

error:
	SK_ERR("%s(%d) kr \"%s\" (0x%llx) krflags 0x%b error: kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    ring->ring_head, ring->ring_tail);

	skywalk_kill_process(p, err_reason | SKYWALK_KILL_REASON_RX_SYNC);
	return kring->ckr_num_slots;
}

/*
 * Validate parameters on the ring/kring on entry for *_alloc_sync().
 * Returns ring->ring_head if ok, kring->ckr_num_slots on error,
 * in order to force a reinit.
 */
slot_idx_t
kr_alloc_sync_prologue(struct __kern_channel_ring *kring, struct proc *p)
{
	struct __user_channel_ring *ring = kring->ckr_ring;
	slot_idx_t ckr_khead, ckr_ktail;
	slot_idx_t head;
	uint64_t err_reason = 0;

	VERIFY(sk_is_sync_protected());

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;
	head = ring->ring_head;

	SK_DF(SK_VERB_SYNC, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    head, ring->ring_tail);
	/*
	 * Before storing the new values, we should check they do not
	 * move backwards. However, head is not an issue because the
	 * previous value is khead;
	 */
	_KR_RXRING_VALIDATE(kring, ring, ckr_khead, ckr_ktail, head);

	/* update the kernel view of ring */
	kring->ckr_rhead = head;
	return head;

error:
	SK_ERR("%s(%d) kr \"%s\" (0x%llx) krflags 0x%b error: kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    ring->ring_head, ring->ring_tail);

	skywalk_kill_process(p, err_reason | SKYWALK_KILL_REASON_ALLOC_SYNC);
	return kring->ckr_num_slots;
}

/*
 * Nexus-specific kr_txsync_finalize() callback.
 */
void
kr_txfinalize(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, struct proc *p)
{
#pragma unused(ch)
	struct kern_pbufpool *pp = kring->ckr_pp;
	slot_idx_t slot_idx;
	uint32_t ph_cnt, i = 0;
	int32_t ph_needed;
	int err;

	ASSERT(!(KRNA(kring)->na_flags & NAF_USER_PKT_POOL));

	/* use khead value from pre-sync time */
	slot_idx = kring->ckr_khead_pre;

	ph_needed = head - slot_idx;
	if (ph_needed < 0) {
		ph_needed += kring->ckr_num_slots;
	}
	if (ph_needed == 0) {
		return;
	}

	ph_cnt = (uint32_t)ph_needed;
	err = kern_pbufpool_alloc_batch(pp, 1, kring->ckr_scratch, &ph_cnt);
	VERIFY(err == 0 && ph_cnt == (uint32_t)ph_needed);

	/* recycle the transferred packets */
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		kern_packet_t ph;

		if (KSD_VALID_METADATA(ksd)) {
			goto next_slot;
		}

		ph = kring->ckr_scratch[i];
		ASSERT(ph != 0);
		kring->ckr_scratch[i] = 0;
		++i;

		/*
		 * Since this packet is freshly allocated and we need
		 * to have the flag set for the attach to succeed,
		 * just set it here rather than calling
		 * __packet_finalize().
		 */
		SK_PTR_ADDR_KQUM(ph)->qum_qflags |= QUM_F_FINALIZED;

		KR_SLOT_ATTACH_METADATA(kring, ksd, SK_PTR_ADDR_KQUM(ph));

		kr_externalize_metadata_internal(kring, pp->pp_max_frags,
		    SK_PTR_ADDR_KQUM(ph), p);
next_slot:
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	if (i != ph_cnt) {
		kern_pbufpool_free_batch(pp, &kring->ckr_scratch[i],
		    ph_cnt - i);
	}
}

/*
 * Nexus-specific kr_txsync_finalize() callback - user packet pool variant.
 */
void
kr_txfinalize_upp(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t head, struct proc *p)
{
#pragma unused(ch, p)
	slot_idx_t slot_idx;
	uint32_t nfree = 0;

	ASSERT(KRNA(kring)->na_flags & NAF_USER_PKT_POOL);

	/* use khead value from pre-sync time */
	slot_idx = kring->ckr_khead_pre;

	/* recycle the transferred packets */
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);

		if (KSD_VALID_METADATA(ksd)) {
			/* detach and free the packet */
			struct __kern_quantum *kqum = ksd->sd_qum;
			(void) KR_SLOT_DETACH_METADATA(kring, ksd);
			ASSERT(nfree < kring->ckr_num_slots);
			kring->ckr_scratch[nfree++] = (uint64_t)kqum;
		}

		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	if (__probable(nfree > 0)) {
		pp_free_packet_batch(kring->ckr_pp,
		    &kring->ckr_scratch[0], nfree);
	}
}

/*
 * Update kring and ring at the end of txsync.
 */
void
kr_txsync_finalize(struct kern_channel *ch, struct __kern_channel_ring *kring,
    struct proc *p)
{
	slot_idx_t ckr_khead, ckr_ktail;
	uint32_t slot_size;
	int32_t slot_diff;

	VERIFY(sk_is_sync_protected());
	/* assert that this routine is only called for user facing rings */
	ASSERT(!KR_KERNEL_ONLY(kring));

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;

	/*
	 * update userspace-facing channel statistics (# writable bytes/slots)
	 *
	 * Since the ring might be dynamically allocated, we can't rely on the
	 * tail pointer to calculate free TX space (the tail might be sitting
	 * at the edge of allocated ring space but be able to be pushed over
	 * into unallocated ring space).
	 *
	 * Instead, calculate free TX space by looking at what slots are
	 * available to the kernel for TX, and subtracting that from the total
	 * number of possible slots. This is effectively what userspace can
	 * write to.
	 */
	slot_size = PP_BUF_SIZE_DEF(kring->ckr_pp);
	slot_diff = kring->ckr_rhead - ckr_khead;
	if (slot_diff < 0) {
		slot_diff += kring->ckr_num_slots;
	}
	slot_diff = kring->ckr_lim - slot_diff;
	kring->ckr_ready_slots = slot_diff;
	kring->ckr_ready_bytes = slot_diff * slot_size;

	/*
	 * Invoke nexus-specific TX finalize callback, which may recycle any
	 * transferred packets and/or externalize new ones.  Some nexus don't
	 * have any callback set.  Configured in na_kr_create().
	 */
	if (kring->ckr_finalize != NULL) {
		kring->ckr_finalize(ch, kring, ckr_khead, p);
	}

	/* update ring tail/khead to what the kernel knows */
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_tail =
	    kring->ckr_rtail = ckr_ktail;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_khead = ckr_khead;

	SK_DF(SK_VERB_SYNC | SK_VERB_TX, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    kring->ckr_ring->ring_head,
	    kring->ckr_ring->ring_tail);
}

/*
 * Nexus-specific kr_rxsync_finalize() callback.
 */
void
kr_rxfinalize(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t tail, struct proc *p)
{
#pragma unused(ch)
	const uint32_t maxfrags = kring->ckr_pp->pp_max_frags;
	slot_idx_t slot_idx = kring->ckr_rtail;
	uint32_t byte_count = 0;

	while (slot_idx != tail) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __kern_quantum *kqum = ksd->sd_qum;

		/*
		 * nexus provider should never leave an empty slot on rx ring.
		 */
		VERIFY(kqum != NULL);
		kr_externalize_metadata_internal(kring, maxfrags, kqum, p);
		ASSERT(!(KR_USD(kring, slot_idx)->sd_flags & ~SD_FLAGS_USER));

		byte_count += kqum->qum_len;
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	kring->ckr_ready_bytes += byte_count;

	/* just recalculate slot count using pointer arithmetic */
	int32_t slot_diff = tail - kring->ckr_rhead;
	if (slot_diff < 0) {
		slot_diff += kring->ckr_num_slots;
	}
	kring->ckr_ready_slots = slot_diff;

#if CONFIG_NEXUS_NETIF
	/*
	 * If this is a channel opened directly to the netif nexus, provide
	 * it feedbacks on the number of packets and bytes consumed.  This
	 * will drive the receive mitigation strategy.
	 */
	if (__improbable(kring->ckr_netif_mit_stats != NULL) &&
	    slot_diff != 0 && byte_count != 0) {
		kring->ckr_netif_mit_stats(kring, slot_diff, byte_count);
	}
#endif /* CONFIG_NEXUS_NETIF */
}

/*
 * Nexus-specific kr_rxsync_finalize() callback - user packet pool variant.
 */
void
kr_rxfinalize_upp(struct kern_channel *ch, struct __kern_channel_ring *kring,
    const slot_idx_t tail, struct proc *p)
{
	const uint32_t maxfrags = kring->ckr_pp->pp_max_frags;
	slot_idx_t slot_idx = kring->ckr_rtail;
	struct kern_pbufpool *pp = kring->ckr_pp;
	uint32_t byte_count = 0;

	PP_LOCK(pp);
	while (slot_idx != tail) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __user_slot_desc *usd = KR_USD(kring, slot_idx);
		struct __kern_quantum *kqum = ksd->sd_qum;

		/*
		 * nexus provider should never leave an empty slot on rx ring.
		 */
		VERIFY(kqum != NULL);
		/*
		 * The channel is operating in packet allocator
		 * mode, so add packet to the allocated list.
		 */
		pp_insert_upp_locked(pp, kqum, ch->ch_pid);

		KSD_DETACH_METADATA(ksd);
		/* To calculate ckr_ready_bytes by kr_rxsync_prologue */
		USD_SET_LENGTH(usd, (uint16_t)kqum->qum_len);

		kr_externalize_metadata_internal(kring, maxfrags, kqum, p);
		ASSERT((usd->sd_flags & ~SD_FLAGS_USER) == 0);

		byte_count += kqum->qum_len;
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}
	PP_UNLOCK(pp);

	kring->ckr_ready_bytes += byte_count;

	/* just recalculate slot count using pointer arithmetic */
	int32_t slot_diff = tail - kring->ckr_rhead;
	if (slot_diff < 0) {
		slot_diff += kring->ckr_num_slots;
	}
	kring->ckr_ready_slots = slot_diff;

#if CONFIG_NEXUS_NETIF
	/*
	 * If this is a channel opened directly to the netif nexus, provide
	 * it feedbacks on the number of packets and bytes consumed.  This
	 * will drive the receive mitigation strategy.
	 */
	if (__improbable(kring->ckr_netif_mit_stats != NULL) &&
	    slot_diff != 0 && byte_count != 0) {
		kring->ckr_netif_mit_stats(kring, slot_diff, byte_count);
	}
#endif /* CONFIG_NEXUS_NETIF */
}

/*
 * Update kring and ring at the end of rxsync
 */
void
kr_rxsync_finalize(struct kern_channel *ch, struct __kern_channel_ring *kring,
    struct proc *p)
{
#pragma unused(ch, p)
	slot_idx_t ckr_khead, ckr_ktail;

	VERIFY(sk_is_sync_protected());
	/* assert that this routine is only called for user facing rings */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(kring->ckr_usds != NULL);

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;

	/*
	 * Invoke nexus-specific RX finalize callback; set in na_kr_create().
	 */
	if (kring->ckr_finalize != NULL) {
		kring->ckr_finalize(ch, kring, ckr_ktail, p);
	}

	/* update ring tail/khead to what the kernel knows */
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_tail =
	    kring->ckr_rtail = ckr_ktail;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_khead = ckr_khead;

	SK_DF(SK_VERB_SYNC | SK_VERB_RX, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    kring->ckr_ring->ring_head,
	    kring->ckr_ring->ring_tail);
}

void
kr_alloc_sync_finalize(struct __kern_channel_ring *kring, struct proc *p)
{
#pragma unused(p)
	slot_idx_t ckr_khead, ckr_ktail;

	VERIFY(sk_is_sync_protected());
	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;

	/* update ring tail/khead to what the kernel knows */
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_tail =
	    kring->ckr_rtail = ckr_ktail;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_khead = ckr_khead;
	*(uint32_t *)(uintptr_t)&kring->ckr_ring->ring_alloc_ws =
	    kring->ckr_alloc_ws;

	SK_DF(SK_VERB_SYNC, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u | ws %u",
	    sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    kring->ckr_ring->ring_head,
	    kring->ckr_ring->ring_tail, kring->ckr_alloc_ws);
}

void
kr_free_sync_finalize(struct __kern_channel_ring *kring, struct proc *p)
{
#pragma unused(p)
	slot_idx_t ckr_khead, ckr_ktail;

	VERIFY(sk_is_sync_protected());
	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;

	/* update ring tail/khead to what the kernel knows */
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_tail =
	    kring->ckr_rtail = ckr_ktail;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_khead = ckr_khead;

	SK_DF(SK_VERB_SYNC, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    kring->ckr_ring->ring_head,
	    kring->ckr_ring->ring_tail);
}

slot_idx_t
kr_event_sync_prologue(struct __kern_channel_ring *kring, struct proc *p)
{
	struct __user_channel_ring *ring = kring->ckr_ring;
	slot_idx_t ckr_khead, ckr_ktail;
	slot_idx_t head, slot_idx;
	uint64_t err_reason = 0;

	ASSERT(kring->ckr_tx == NR_EV);
	VERIFY(sk_is_sync_protected());

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;
	head = ring->ring_head;

	SK_DF(SK_VERB_SYNC, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    head, ring->ring_tail);
	/*
	 * Before storing the new values, we should check they do not
	 * move backwards. However, head is not an issue because the
	 * previous value is khead;
	 */
	_KR_RXRING_VALIDATE(kring, ring, ckr_khead, ckr_ktail, head);

	/*
	 * Iterating through the slots just read by user-space;
	 * ckr_rhead -> ring_head
	 */
	slot_idx = kring->ckr_rhead;
	while (slot_idx != head) {
		struct __kern_slot_desc *ksd = KR_KSD(kring, slot_idx);
		struct __user_slot_desc *usd = KR_USD(kring, slot_idx);
		/*
		 * ensure that the user has detached packet from slot.
		 */
		VERIFY(!KSD_VALID_METADATA(ksd));
		if (__improbable(SD_VALID_METADATA(usd))) {
			SK_ERR("%s(%d) kr \"%s\" (0x%llx) slot %u not "
			    "detached md %u kh %u kt %u | rh %u rt %u |"
			    " h %u t %u", sk_proc_name_address(p),
			    sk_proc_pid(p), kring->ckr_name,
			    SK_KVA(kring), slot_idx, usd->sd_md_idx,
			    ckr_khead, ckr_ktail, kring->ckr_rhead,
			    kring->ckr_rtail, ring->ring_head,
			    ring->ring_tail);
			err_reason = SKYWALK_KILL_REASON_SLOT_NOT_DETACHED;
			goto error;
		}
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}

	/* update the kernel view of ring */
	kring->ckr_rhead = head;
	return head;

error:
	SK_ERR("%s(%d) kr \"%s\" (0x%llx) krflags 0x%b error: kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, SK_KVA(kring), kring->ckr_flags,
	    CKRF_BITS, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    ring->ring_head, ring->ring_tail);

	skywalk_kill_process(p, err_reason | SKYWALK_KILL_REASON_EVENT_SYNC);
	return kring->ckr_num_slots;
}

void
kr_event_sync_finalize(struct kern_channel *ch,
    struct __kern_channel_ring *kring, struct proc *p)
{
#pragma unused(ch)
	struct kern_pbufpool *pp = kring->ckr_pp;
	const uint32_t maxfrags = pp->pp_max_frags;
	slot_idx_t ckr_khead, ckr_ktail, ckr_rhead;
	struct __kern_slot_desc *ksd;
	struct __user_slot_desc *usd;
	struct __kern_quantum *kqum;

	VERIFY(sk_is_sync_protected());
	/* assert that this routine is only called for user facing rings */
	ASSERT(!KR_KERNEL_ONLY(kring));
	ASSERT(kring->ckr_usds != NULL);
	ASSERT(kring->ckr_tx == NR_EV);

	/* read these once and use local copies */
	ckr_khead = kring->ckr_khead;
	ckr_ktail = kring->ckr_ktail;
	ckr_rhead = kring->ckr_rhead;

	slot_idx_t slot_idx = kring->ckr_rtail;
	PP_LOCK(pp);
	while (slot_idx != ckr_ktail) {
		ksd = KR_KSD(kring, slot_idx);
		usd = KR_USD(kring, slot_idx);
		kqum = ksd->sd_qum;

		/*
		 * Add packet to the allocated list of user packet pool.
		 */
		pp_insert_upp_locked(pp, kqum, ch->ch_pid);

		KSD_DETACH_METADATA(ksd);
		kr_externalize_metadata_internal(kring, maxfrags, kqum, p);
		ASSERT((usd->sd_flags & ~SD_FLAGS_USER) == 0);
		slot_idx = SLOT_NEXT(slot_idx, kring->ckr_lim);
	}
	PP_UNLOCK(pp);

	/* just recalculate slot count using pointer arithmetic */
	int32_t slot_diff = ckr_ktail - ckr_rhead;
	if (slot_diff < 0) {
		slot_diff += kring->ckr_num_slots;
	}
	kring->ckr_ready_slots = slot_diff;

	/* update ring tail/khead to what the kernel knows */
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_tail =
	    kring->ckr_rtail = ckr_ktail;
	*(slot_idx_t *)(uintptr_t)&kring->ckr_ring->ring_khead = ckr_khead;

	SK_DF(SK_VERB_SYNC | SK_VERB_RX, "%s(%d) kr \"%s\", kh %u kt %u | "
	    "rh %u rt %u | h %u t %u", sk_proc_name_address(p),
	    sk_proc_pid(p), kring->ckr_name, ckr_khead, ckr_ktail,
	    kring->ckr_rhead, kring->ckr_rtail,
	    kring->ckr_ring->ring_head,
	    kring->ckr_ring->ring_tail);
}
#undef NM_FAIL_ON

void
kr_txkring_reclaim_and_refill(struct __kern_channel_ring *kring,
    slot_idx_t index)
{
	const slot_idx_t lim = kring->ckr_lim;
	slot_idx_t next_index = SLOT_NEXT(index, lim);

	kring->ckr_khead = next_index;
	/* reclaim */
	kring->ckr_ktail = index;
}

/*
 * *************************************************************************
 * Checks on packet header offsets in kr_internalize_metadata
 * *************************************************************************
 *
 *  +----------+------------------------------+----------------------------+
 *  |          | NEXUS_META_SUBTYPE_RAW       | NEXUS_META_SUBTYPE_PAYLOAD |
 *  |----------+------------------------------+----------------------------+
 *  | buflet   | (bdoff + len) <= dlim        | (bdoff + len) <= dlim      |
 *  |----------+------------------------------+----------------------------+
 *  | headroom | hr == bdoff && hr < bdlim    | hr == 0 && bdoff == 0      |
 *  |----------+------------------------------+----------------------------+
 *  | l2_len   | hr + l2_len < bdim           | l2_len == 0                |
 *  |----------+------------------------------+----------------------------+
 */
int
kr_internalize_metadata(struct kern_channel *ch,
    struct __kern_channel_ring *kring, const uint32_t maxfrags,
    struct __kern_quantum *kqum, struct proc *p)
{
#pragma unused(kring, maxfrags, p)
	struct __user_buflet *ubuf, *pubuf;     /* user buflet */
	struct __kern_buflet *kbuf, *pkbuf;     /* kernel buflet */
	struct __user_quantum *uqum;            /* user source */
	struct __user_packet *upkt;
	struct __kern_packet *kpkt;
	const nexus_meta_type_t md_type = METADATA_TYPE(kqum);
	const nexus_meta_subtype_t md_subtype = METADATA_SUBTYPE(kqum);
	uint32_t len = 0, bdoff, bdlim;
	uint16_t bcnt = 0, bmax, i;
	boolean_t dropped;
	int err = 0;

	/*
	 * Verify that the quantum/packet belongs to the same pp as
	 * the one used by the adapter, i.e. the packet must have
	 * been allocated from the same pp and attached to the kring.
	 */
	ASSERT(kqum->qum_pp == kring->ckr_pp);

	_CASSERT(sizeof(uqum->qum_com) == sizeof(kqum->qum_com));
	_CASSERT(sizeof(upkt->pkt_com) == sizeof(kpkt->pkt_com));
	uqum = __DECONST(struct __user_quantum *, kqum->qum_user);
	ASSERT(!(kqum->qum_qflags & QUM_F_KERNEL_ONLY) && uqum != NULL);
	upkt = SK_PTR_ADDR_UPKT(uqum);
	kpkt = SK_PTR_ADDR_KPKT(kqum);

	DTRACE_SKYWALK3(internalize, struct __kern_channel_ring *, kring,
	    struct __kern_packet *, kpkt, struct __user_packet *, upkt);
	SK_DF(SK_VERB_MEM, "%s(%d) kring 0x%llx uqum 0x%llx -> kqum 0x%llx",
	    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(kring),
	    SK_KVA(uqum), SK_KVA(kqum));

	/* check if it's dropped before we internalize it */
	dropped = ((uqum->qum_qflags & QUM_F_DROPPED) != 0);

	/*
	 * Internalize common quantum metadata.
	 *
	 * For packet metadata, we trust the kernel copy for the buflet
	 * count and limit; any mismatch on the user copy will cause
	 * us to drop this packet.
	 */
	_QUM_INTERNALIZE(uqum, kqum);

	/* if marked as dropped, don't bother going further */
	if (__improbable(dropped)) {
		SK_ERR("%s(%d) kring 0x%llx dropped",
		    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(kring));
		err = ERANGE;
		goto done;
	}

	switch (md_type) {
	case NEXUS_META_TYPE_PACKET:
		/*
		 * Internalize common packet metadata.
		 */
		_PKT_INTERNALIZE(upkt, kpkt);

		switch (md_subtype) {
		case NEXUS_META_SUBTYPE_PAYLOAD:
			/* sanitize link layer fields for payload mode */
			kpkt->pkt_link_flags = 0;
			break;
		default:
			break;
		}

		if (__probable(ch != NULL)) {
			_UUID_COPY(kpkt->pkt_flowsrc_id,
			    ch->ch_info->cinfo_ch_id);
		}

		bcnt = upkt->pkt_bufs_cnt;
		bmax = kpkt->pkt_bufs_max;
		ASSERT(bmax == maxfrags);
		if (__improbable((bcnt == 0) || (bcnt > bmax) ||
		    (upkt->pkt_bufs_max != bmax))) {
			SK_ERR("%s(%d) kring 0x%llx bad bufcnt %d, %d, %d",
			    sk_proc_name_address(p), sk_proc_pid(p),
			    SK_KVA(kring), bcnt, bmax, upkt->pkt_bufs_max);
			err = ERANGE;
			goto done;
		}
		break;

	case NEXUS_META_TYPE_QUANTUM:
		ASSERT(maxfrags == 1);
		bcnt = bmax = 1;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	ASSERT(bcnt != 0);
	ubuf = pubuf = NULL;
	kbuf = pkbuf = NULL;

	/*
	 * Validate and internalize buflets.
	 */
	for (i = 0; i < bcnt; i++) {
		_CASSERT(offsetof(struct __kern_packet, pkt_qum) == 0);
		_CASSERT(offsetof(struct __user_packet, pkt_qum) == 0);
		_CASSERT(offsetof(struct __kern_quantum, qum_com) == 0);
		PKT_GET_NEXT_BUFLET(kpkt, bcnt, pkbuf, kbuf);
		ASSERT(kbuf != NULL);
		if (kbuf->buf_flag & BUFLET_FLAG_EXTERNAL) {
			ubuf = __DECONST(struct __user_buflet *,
			    ((struct __kern_buflet_ext *)kbuf)->kbe_buf_user);
		} else {
			ASSERT(i == 0);
			ubuf = __DECONST(struct __user_buflet *,
			    &uqum->qum_buf[0]);
		}
		ASSERT(ubuf != NULL);
		ASSERT((kbuf != pkbuf) && (ubuf != pubuf));
		ASSERT(kbuf->buf_dlim == _BUF_DLIM(kbuf, kqum->qum_pp));
		ASSERT(kbuf->buf_addr != 0);
		/*
		 * For now, user-facing pool does not support shared
		 * buffer, since otherwise the ubuf and kbuf buffer
		 * indices would not match.  Assert this is the case.
		 */
		ASSERT(kbuf->buf_addr == (mach_vm_address_t)kbuf->buf_objaddr);

		kbuf->buf_dlen = ubuf->buf_dlen;
		kbuf->buf_doff = ubuf->buf_doff;

		/*
		 * kernel and user metadata use the same object index
		 * also checks the sanity of buflet data offset and length
		 */
		if (__improbable(!BUF_IN_RANGE(kbuf) ||
		    ubuf->buf_idx != kbuf->buf_idx)) {
			kbuf->buf_dlen = kbuf->buf_doff = 0;
			SK_ERR("%s(%d) kring 0x%llx bad bufidx 0x%x, 0x%x",
			    sk_proc_name_address(p), sk_proc_pid(p),
			    SK_KVA(kring), kbuf->buf_idx, ubuf->buf_idx);
			err = ERANGE;
			goto done;
		}

		/* save data offset from the first buflet */
		if (pkbuf == NULL) {
			bdoff = kbuf->buf_doff;
		}

		/* all good to go */
		len += kbuf->buf_dlen;
		pubuf = ubuf;
		pkbuf = kbuf;
	}

	_CASSERT(offsetof(struct __kern_packet, pkt_length) ==
	    offsetof(struct __kern_packet, pkt_qum.qum_len));
	if (__improbable(kpkt->pkt_length != len)) {
		SK_ERR("%s(%d) kring 0x%llx bad pktlen %d, %d",
		    sk_proc_name_address(p), sk_proc_pid(p),
		    SK_KVA(kring), kpkt->pkt_length, len);
		err = ERANGE;
		goto done;
	}

	if ((err == 0) && (md_type == NEXUS_META_TYPE_PACKET)) {
		bdlim = PP_BUF_SIZE_DEF(kqum->qum_pp);
		switch (md_subtype) {
		case NEXUS_META_SUBTYPE_RAW:
			/*
			 * For a raw packet from user space we need to
			 * validate that headroom is sane and is in the
			 * first buflet.
			 */
			if (__improbable(kpkt->pkt_headroom != bdoff)) {
				SK_ERR("%s(%d) kring 0x%llx bad headroom %d, %d",
				    sk_proc_name_address(p), sk_proc_pid(p),
				    SK_KVA(kring), kpkt->pkt_headroom, bdoff);
				err = ERANGE;
				goto done;
			}
			if (__improbable(kpkt->pkt_headroom +
			    kpkt->pkt_l2_len >= bdlim)) {
				SK_ERR("%s(%d) kring 0x%llx bad headroom l2len %d, %d",
				    sk_proc_name_address(p), sk_proc_pid(p),
				    SK_KVA(kring), kpkt->pkt_l2_len, bdlim);
				err = ERANGE;
				goto done;
			}
			break;
		case NEXUS_META_SUBTYPE_PAYLOAD:
			/*
			 * For a payload packet from user space we need
			 * to validate that payload starts from 0 and L2
			 * length is 0.
			 */
			if (__improbable((kpkt->pkt_headroom != 0) ||
			    (kpkt->pkt_l2_len != 0))) {
				SK_ERR("%s(%d) kring 0x%llx bad headroom "
				    "payload subtype %d headroom %d l2len %d",
				    sk_proc_name_address(p), sk_proc_pid(p),
				    SK_KVA(kring), SK_PTR_SUBTYPE(kpkt),
				    kpkt->pkt_headroom, kpkt->pkt_l2_len);
				err = ERANGE;
				goto done;
			}
			break;
		default:
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}

		/* validate checksum offload properties */
		if (__probable(PACKET_HAS_PARTIAL_CHECKSUM(kpkt))) {
			uint16_t start = kpkt->pkt_csum_tx_start_off;
			uint16_t stuff = kpkt->pkt_csum_tx_stuff_off;
			if (__improbable(start > stuff ||
			    start > kpkt->pkt_length ||
			    (stuff + sizeof(uint16_t)) > kpkt->pkt_length)) {
				SK_ERR("%s(%d) flags 0x%x start %u stuff %u "
				    "len %u", sk_proc_name_address(p),
				    sk_proc_pid(p), kpkt->pkt_csum_flags,
				    start, stuff, kpkt->pkt_length);
				err = ERANGE;
				goto done;
			}
		} else {
			kpkt->pkt_csum_tx_start_off = 0;
			kpkt->pkt_csum_tx_stuff_off = 0;
		}
		*__DECONST(uint16_t *, &kpkt->pkt_bufs_cnt) = bcnt;
	}

done:
	if (__probable(err == 0)) {
		kqum->qum_len = len;
		kqum->qum_qflags |= (QUM_F_INTERNALIZED | QUM_F_FINALIZED);
	} else {
		kqum->qum_len = 0;
		kqum->qum_qflags |= (QUM_F_INTERNALIZED | QUM_F_DROPPED);
	}
	return err;
}

__attribute__((always_inline))
static inline void
kr_externalize_metadata_internal(struct __kern_channel_ring *kring,
    const uint32_t maxfrags, struct __kern_quantum *kqum, struct proc *p)
{
#pragma unused(kring, maxfrags, p)
	struct __kern_buflet *kbuf, *pkbuf;     /* kernel buflet */
	struct __user_buflet *ubuf, *pubuf;     /* user buflet */
	struct __user_quantum *uqum;            /* user destination */
	struct __user_packet *upkt;
	struct __kern_packet *kpkt;
	const nexus_meta_type_t md_type = METADATA_TYPE(kqum);
	const nexus_meta_subtype_t md_subtype = METADATA_SUBTYPE(kqum);
	uint32_t len = 0;
	uint16_t bcnt = 0, bmax, i;

	/*
	 * Verify that the quantum/packet belongs to the same pp as
	 * the one used by the adapter, i.e. the packet must have
	 * been allocated from the same pp and attached to the kring.
	 */
	ASSERT(kqum->qum_pp == kring->ckr_pp);
	ASSERT(kqum->qum_qflags & (QUM_F_FINALIZED | QUM_F_INTERNALIZED));

	_CASSERT(sizeof(kpkt->pkt_com) == sizeof(upkt->pkt_com));
	_CASSERT(sizeof(kqum->qum_com) == sizeof(uqum->qum_com));
	uqum = __DECONST(struct __user_quantum *, kqum->qum_user);
	ASSERT(!(kqum->qum_qflags & QUM_F_KERNEL_ONLY) && uqum != NULL);
	upkt = SK_PTR_ADDR_UPKT(uqum);
	kpkt = SK_PTR_ADDR_KPKT(kqum);

	DTRACE_SKYWALK3(externalize, struct __kern_channel_ring *, kring,
	    struct __kern_packet *, kpkt, struct __user_packet *, upkt);
	SK_DF(SK_VERB_MEM, "%s(%d) kring 0x%llx kqum 0x%llx -> uqum 0x%llx",
	    sk_proc_name_address(p), sk_proc_pid(p), SK_KVA(kring),
	    SK_KVA(kqum), SK_KVA(uqum));

	/*
	 * Externalize common quantum metadata.
	 */
	_QUM_EXTERNALIZE(kqum, uqum);

	switch (md_type) {
	case NEXUS_META_TYPE_PACKET: {
		bcnt = kpkt->pkt_bufs_cnt;
		bmax = kpkt->pkt_bufs_max;
		ASSERT(bmax == maxfrags);
		ASSERT(bcnt <= bmax);
		/*
		 * Externalize common packet metadata.
		 */
		_PKT_EXTERNALIZE(kpkt, upkt);

		/* sanitize buflet count and limit (deconst) */
		_CASSERT(sizeof(upkt->pkt_bufs_max) == sizeof(uint16_t));
		_CASSERT(sizeof(upkt->pkt_bufs_cnt) == sizeof(uint16_t));
		*(uint16_t *)(uintptr_t)&upkt->pkt_bufs_max = bmax;
		*(uint16_t *)(uintptr_t)&upkt->pkt_bufs_cnt = bcnt;

		switch (md_subtype) {
		case NEXUS_META_SUBTYPE_PAYLOAD:
			/* sanitize link layer fields for payload mode */
			upkt->pkt_headroom = 0;
			upkt->pkt_link_flags = 0;
			break;
		default:
			break;
		}
		break;
	}

	case NEXUS_META_TYPE_QUANTUM:
		ASSERT(maxfrags == 1);
		bcnt = bmax = 1;
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}

	ASSERT(bcnt != 0);
	/*
	 * special handling to externalize empty packet buflet.
	 */
	kbuf = &kpkt->pkt_qum.qum_buf[0];
	if (kbuf->buf_addr == 0) {
		ubuf = __DECONST(struct __user_buflet *,
		    &kpkt->pkt_qum.qum_user->qum_buf[0]);
		UBUF_INIT(kbuf, ubuf);
	}

	kbuf = pkbuf = NULL;
	ubuf = pubuf = NULL;
	/*
	 * Externalize buflets.
	 */
	for (i = 0; i < bcnt; i++) {
		_CASSERT(offsetof(struct __kern_packet, pkt_qum) == 0);
		PKT_GET_NEXT_BUFLET(kpkt, bcnt, pkbuf, kbuf);
		ASSERT(kbuf != NULL);

		if (kbuf->buf_flag & BUFLET_FLAG_EXTERNAL) {
			ubuf = __DECONST(struct __user_buflet *,
			    ((struct __kern_buflet_ext *)kbuf)->kbe_buf_user);
		} else {
			ASSERT(i == 0);
			ubuf = __DECONST(struct __user_buflet *,
			    &kpkt->pkt_qum.qum_user->qum_buf[0]);
		}

		ASSERT(ubuf != NULL);
		ASSERT((kbuf != pkbuf) && (ubuf != pubuf));
		ASSERT(BUF_IN_RANGE(kbuf));
		KBUF_EXTERNALIZE(kbuf, ubuf, kqum->qum_pp);

		/* all good to go */
		len += kbuf->buf_dlen;
		pkbuf = kbuf;
		pubuf = ubuf;
	}

	uqum->qum_len = len;
	uqum->qum_qflags |= QUM_F_FINALIZED;

	/*
	 * XXX: adi@apple.com -- do this during reclaim instead?
	 */
	kqum->qum_qflags &= ~QUM_F_INTERNALIZED;
}


void
kr_externalize_metadata(struct __kern_channel_ring *kring,
    const uint32_t maxfrags, struct __kern_quantum *kqum, struct proc *p)
{
	kr_externalize_metadata_internal(kring, maxfrags, kqum, p);
}
