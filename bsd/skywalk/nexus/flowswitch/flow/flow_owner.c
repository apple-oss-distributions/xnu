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
#include <skywalk/nexus/flowswitch/fsw_var.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>

static uint32_t flow_owner_bucket_purge_common(struct flow_owner_bucket *,
    nexus_port_t, boolean_t);
static int fo_cmp(const struct flow_owner *, const struct flow_owner *);
static struct flow_owner *fo_alloc(boolean_t);
static void fo_free(struct flow_owner *);

static LCK_GRP_DECLARE(flow_owner_lock_group, "sk_flow_owner_lock");
static LCK_ATTR_DECLARE(flow_owner_lock_attr, 0, 0);

RB_GENERATE_PREV(flow_owner_tree, flow_owner, fo_link, fo_cmp);

KALLOC_TYPE_VAR_DEFINE(KT_SK_FOB, struct flow_owner_bucket, KT_DEFAULT);

struct flow_owner_bucket *
flow_owner_buckets_alloc(size_t fob_cnt, size_t *fob_sz, size_t *tot_sz)
{
	size_t cache_sz = skmem_cpu_cache_line_size();
	struct flow_owner_bucket *fob;
	size_t fob_tot_sz;

	/* each bucket is CPU cache-aligned */
	*fob_sz = P2ROUNDUP(sizeof(*fob), cache_sz);
	*tot_sz = fob_tot_sz = fob_cnt * (*fob_sz);
	fob = sk_alloc_type_hash(KT_SK_FOB, fob_tot_sz, Z_WAITOK, skmem_tag_fsw_fob_hash);
	if (__improbable(fob == NULL)) {
		return NULL;
	}

#if !KASAN_CLASSIC
	/*
	 * except in KASAN_CLASSIC mode, kalloc will always maintain cacheline
	 * size alignment if the requested size is a multiple of a cacheline
	 * size (this is true for any size that is a power of two from 16 to
	 * PAGE_SIZE).
	 *
	 * Because this is an optimization only, it is OK to leave KASAN_CLASSIC
	 * not respect this.
	 */
	ASSERT(IS_P2ALIGNED(fob, cache_sz));
#endif

	SK_DF(SK_VERB_MEM, "fob 0x%llx fob_cnt %zu fob_sz %zu "
	    "(total %zu bytes) ALLOC", SK_KVA(fob), fob_cnt,
	    *fob_sz, fob_tot_sz);

	return fob;
}

void
flow_owner_buckets_free(struct flow_owner_bucket *fob, size_t tot_sz)
{
	SK_DF(SK_VERB_MEM, "fob 0x%llx FREE", SK_KVA(fob));
	sk_free_type_hash(KT_SK_FOB, tot_sz, fob);
}

void
flow_owner_bucket_init(struct flow_owner_bucket *fob)
{
#if !KASAN_CLASSIC
	ASSERT(IS_P2ALIGNED(fob, skmem_cpu_cache_line_size()));
#endif /* !KASAN_CLASSIC */
	lck_mtx_init(&fob->fob_lock, &flow_owner_lock_group,
	    &flow_owner_lock_attr);
	RB_INIT(&fob->fob_owner_head);
}

void
flow_owner_bucket_destroy(struct flow_owner_bucket *fob)
{
	/*
	 * In the event we are called as part of the nexus destructor,
	 * we need to wait until all threads have exited the flow close
	 * critical section, and that the flow_owner_bucket is empty.
	 * By the time we get here, the module initiating the request
	 * (e.g. NECP) has been quiesced, so any flow open requests would
	 * have been rejected.
	 */
	FOB_LOCK(fob);
	while (!RB_EMPTY(&fob->fob_owner_head)) {
		SK_ERR("waiting for fob 0x%llx to go idle", SK_KVA(fob));
		if (++(fob->fob_dtor_waiters) == 0) {   /* wraparound */
			fob->fob_dtor_waiters++;
		}
		(void) msleep(&fob->fob_dtor_waiters, &fob->fob_lock,
		    (PZERO - 1), __FUNCTION__, NULL);
	}
	while (fob->fob_busy_flags & FOBF_CLOSE_BUSY) {
		if (++(fob->fob_close_waiters) == 0) {  /* wraparound */
			fob->fob_close_waiters++;
		}
		(void) msleep(&fob->fob_close_waiters, &fob->fob_lock,
		    (PZERO - 1), __FUNCTION__, NULL);
	}
	ASSERT(RB_EMPTY(&fob->fob_owner_head));
	ASSERT(!(fob->fob_busy_flags & FOBF_OPEN_BUSY));
	ASSERT(!(fob->fob_busy_flags & FOBF_CLOSE_BUSY));
	FOB_UNLOCK(fob);
	lck_mtx_destroy(&fob->fob_lock, &flow_owner_lock_group);
}

static uint32_t
flow_owner_bucket_purge_common(struct flow_owner_bucket *fob,
    nexus_port_t nx_port, boolean_t if_idle)
{
	/* called by flow_owner_bucket_purge_all()? */
	boolean_t locked = (nx_port == NEXUS_PORT_ANY);
	struct flow_owner *fo, *tfo;
	struct flow_entry *fe, *tfe;
	uint32_t cnt = 0;

	if (!locked) {
		FOB_LOCK(fob);
	}
	FOB_LOCK_ASSERT_HELD(fob);

	RB_FOREACH_SAFE(fo, flow_owner_tree, &fob->fob_owner_head, tfo) {
		if (fo->fo_nx_port != nx_port && nx_port != NEXUS_PORT_ANY) {
			continue;
		}

		if (!if_idle || nx_port == NEXUS_PORT_ANY) {
			RB_FOREACH_SAFE(fe, flow_entry_id_tree,
			    &fo->fo_flow_entry_id_head, tfe) {
				ASSERT(fe->fe_nx_port == fo->fo_nx_port);
				flow_entry_retain(fe);
				flow_entry_destroy(fo, fe, FALSE, NULL);
			}
		}

		ASSERT(nx_port != NEXUS_PORT_ANY ||
		    RB_EMPTY(&fo->fo_flow_entry_id_head));

		if (RB_EMPTY(&fo->fo_flow_entry_id_head)) {
			flow_owner_free(fob, fo);
			++cnt;
		} else if (nx_port != NEXUS_PORT_ANY) {
			/* let ms_flow_unbind() know this port is gone */
			fo->fo_nx_port_destroyed = TRUE;
			VERIFY(fo->fo_nx_port_na == NULL);
		}
	}

	if (!locked) {
		FOB_UNLOCK(fob);
	}

	return cnt;
}

void
flow_owner_bucket_purge_all(struct flow_owner_bucket *fob)
{
	(void) flow_owner_bucket_purge_common(fob, NEXUS_PORT_ANY, TRUE);
}

static uint32_t
flow_owner_bucket_activate_nx_port_common(struct flow_owner_bucket *fob,
    nexus_port_t nx_port, struct nexus_adapter *nx_port_na,
    na_activate_mode_t mode)
{
	struct flow_owner *fo;
	struct flow_entry *fe;
	uint32_t cnt = 0;

	VERIFY(nx_port != NEXUS_PORT_ANY);
	FOB_LOCK(fob);

	RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
		if (fo->fo_nx_port_destroyed || (fo->fo_nx_port != nx_port)) {
			continue;
		}

		if (mode == NA_ACTIVATE_MODE_ON) {
			VERIFY(fo->fo_nx_port_na == NULL);
			*(struct nexus_adapter **)(uintptr_t)&fo->fo_nx_port_na = nx_port_na;
		}

		RB_FOREACH(fe, flow_entry_id_tree,
		    &fo->fo_flow_entry_id_head) {
			if (fe->fe_flags & FLOWENTF_TORN_DOWN) {
				continue;
			}
			VERIFY(fe->fe_nx_port == fo->fo_nx_port);
			if (fe->fe_adv_idx != FLOWADV_IDX_NONE) {
				if (mode == NA_ACTIVATE_MODE_ON) {
					na_flowadv_entry_alloc(
						fo->fo_nx_port_na, fe->fe_uuid,
						fe->fe_adv_idx, fe->fe_flowid);
				} else if (fo->fo_nx_port_na != NULL) {
					na_flowadv_entry_free(fo->fo_nx_port_na,
					    fe->fe_uuid, fe->fe_adv_idx,
					    fe->fe_flowid);
				}
			}
		}

		if (mode != NA_ACTIVATE_MODE_ON && fo->fo_nx_port_na != NULL) {
			*(struct nexus_adapter **)(uintptr_t)&fo->fo_nx_port_na = NULL;
		}

		++cnt;
	}

	FOB_UNLOCK(fob);
	return cnt;
}

uint32_t
flow_owner_activate_nexus_port(struct flow_mgr *fm,
    boolean_t pid_bound, pid_t pid, nexus_port_t nx_port,
    struct nexus_adapter *nx_port_na, na_activate_mode_t mode)
{
	struct flow_owner_bucket *fob;
	uint32_t fo_cnt = 0;

	VERIFY(nx_port != NEXUS_PORT_ANY);
	VERIFY(nx_port_na != NULL);

	if (pid_bound) {
		fob = flow_mgr_get_fob_by_pid(fm, pid);
		fo_cnt = flow_owner_bucket_activate_nx_port_common(fob, nx_port,
		    nx_port_na, mode);
	} else {
		uint32_t i;
		/*
		 * Otherwise, this can get expensive since we need to search
		 * thru all proc-mapping buckets to find the flows that are
		 * related to this nexus port.
		 */
		for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
			fob = flow_mgr_get_fob_at_idx(fm, i);
			fo_cnt += flow_owner_bucket_activate_nx_port_common(fob,
			    nx_port, nx_port_na, mode);
		}
	}
	/* There shouldn't be more than one flow owners on a nexus port */
	VERIFY(fo_cnt <= 1);
	return fo_cnt;
}

static void
flow_owner_bucket_attach_common(struct flow_owner_bucket *fob,
    nexus_port_t nx_port)
{
	struct flow_owner *fo;

	VERIFY(nx_port != NEXUS_PORT_ANY);
	FOB_LOCK(fob);

	RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
		if (fo->fo_nx_port_destroyed && (fo->fo_nx_port == nx_port)) {
			fo->fo_nx_port_destroyed = FALSE;
		}
	}

	FOB_UNLOCK(fob);
}

void
flow_owner_attach_nexus_port(struct flow_mgr *fm, boolean_t pid_bound,
    pid_t pid, nexus_port_t nx_port)
{
	struct flow_owner_bucket *fob;
	ASSERT(nx_port != NEXUS_PORT_ANY);

	if (pid_bound) {
		fob = flow_mgr_get_fob_by_pid(fm, pid);
		flow_owner_bucket_attach_common(fob, nx_port);
	} else {
		uint32_t i;
		/*
		 * Otherwise, this can get expensive since we need to search
		 * thru all proc-mapping buckets to find the flows that are
		 * related to this nexus port.
		 */
		for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
			fob = flow_mgr_get_fob_at_idx(fm, i);
			flow_owner_bucket_attach_common(fob, nx_port);
		}
	}
}

uint32_t
flow_owner_detach_nexus_port(struct flow_mgr *fm, boolean_t pid_bound,
    pid_t pid, nexus_port_t nx_port, boolean_t if_idle)
{
	struct flow_owner_bucket *fob;
	uint32_t purged = 0;
	ASSERT(nx_port != NEXUS_PORT_ANY);

	if (pid_bound) {
		fob = flow_mgr_get_fob_by_pid(fm, pid);
		purged = flow_owner_bucket_purge_common(fob, nx_port, if_idle);
	} else {
		uint32_t i;
		/*
		 * Otherwise, this can get expensive since we need to search
		 * thru all proc-mapping buckets to find the flows that are
		 * related to this nexus port.
		 */
		for (i = 0; i < fm->fm_owner_buckets_cnt; i++) {
			fob = flow_mgr_get_fob_at_idx(fm, i);
			purged += flow_owner_bucket_purge_common(fob,
			    nx_port, if_idle);
		}
	}
	return purged;
}

/* 64-bit mask with range */
#define FO_BMASK64(_beg, _end)  \
	((((uint64_t)0xffffffffffffffff) >>     \
	    (63 - (_end))) & ~((1ULL << (_beg)) - 1))

struct flow_owner *
flow_owner_alloc(struct flow_owner_bucket *fob, struct proc *p,
    nexus_port_t nx_port, bool nx_port_pid_bound, bool flowadv,
    struct nx_flowswitch *fsw, struct nexus_adapter *nx_port_na,
    void *context, bool low_latency)
{
	struct flow_owner *fo;
	const pid_t pid = proc_pid(p);

	_CASSERT(true == 1);
	_CASSERT(false == 0);
	ASSERT(low_latency == true || low_latency == false);
	ASSERT(nx_port != NEXUS_PORT_ANY);
	FOB_LOCK_ASSERT_HELD(fob);

#if DEBUG
	ASSERT(flow_owner_find_by_pid(fob, pid, context, low_latency) == NULL);
	RB_FOREACH(fo, flow_owner_tree, &fob->fob_owner_head) {
		if (!fo->fo_nx_port_destroyed && (fo->fo_nx_port == nx_port)) {
			VERIFY(0);
			/* NOTREACHED */
			__builtin_unreachable();
		}
	}
#endif /* DEBUG */

	fo = fo_alloc(TRUE);
	if (fo != NULL) {
		if (flowadv) {
			uint32_t i;

			if ((fo->fo_flowadv_bmap =
			    skmem_cache_alloc(sk_fab_cache, SKMEM_SLEEP)) == NULL) {
				SK_ERR("failed to alloc flow advisory bitmap");
				fo_free(fo);
				return NULL;
			}
			bzero(fo->fo_flowadv_bmap, sk_fab_size);
			fo->fo_flowadv_max = sk_max_flows;

			/* set the bits for free indices */
			for (i = 0; i < sk_fadv_nchunks; i++) {
				uint32_t end = 63;

				if (i == (sk_fadv_nchunks - 1)) {
					end = ((sk_max_flows - 1) %
					    FO_FLOWADV_CHUNK);
				}

				fo->fo_flowadv_bmap[i] = FO_BMASK64(0, end);
			}
		}
		RB_INIT(&fo->fo_flow_entry_id_head);
		/* const override */
		*(struct flow_owner_bucket **)(uintptr_t)&fo->fo_bucket = fob;
		fo->fo_context = context;
		fo->fo_pid = pid;
		(void) snprintf(fo->fo_name, sizeof(fo->fo_name), "%s",
		    proc_name_address(p));
		fo->fo_nx_port_pid_bound = nx_port_pid_bound;
		fo->fo_low_latency = low_latency;
		fo->fo_nx_port = nx_port;
		*(struct nexus_adapter **)(uintptr_t)&fo->fo_nx_port_na = nx_port_na;
		*(struct nx_flowswitch **)(uintptr_t)&fo->fo_fsw = fsw;
		RB_INSERT(flow_owner_tree, &fob->fob_owner_head, fo);

		SK_DF(SK_VERB_FLOW, "%s(%d) fob 0x%llx added fo 0x%llx "
		    "nx_port %d nx_port_pid_bound %d ll %d nx_port_na 0x%llx",
		    fo->fo_name, fo->fo_pid, SK_KVA(fob), SK_KVA(fo),
		    (int)nx_port, nx_port_pid_bound, fo->fo_low_latency,
		    SK_KVA(nx_port_na));
	}

	return fo;
}

void
flow_owner_free(struct flow_owner_bucket *fob, struct flow_owner *fo)
{
	FOB_LOCK_ASSERT_HELD(fob);

	ASSERT(fo->fo_bucket == fob);
	*(struct flow_owner_bucket **)(uintptr_t)&fo->fo_bucket = NULL;
	RB_REMOVE(flow_owner_tree, &fob->fob_owner_head, fo);

	ASSERT(fo->fo_num_flowadv == 0);
	skmem_cache_free(sk_fab_cache, fo->fo_flowadv_bmap);
	fo->fo_flowadv_bmap = NULL;

	/* wake up any thread blocked in flow_owner_bucket_destroy() */
	if (RB_EMPTY(&fob->fob_owner_head) && fob->fob_dtor_waiters > 0) {
		fob->fob_dtor_waiters = 0;
		wakeup(&fob->fob_dtor_waiters);
	}

	SK_DF(SK_VERB_FLOW, "%s(%d) fob 0x%llx removed fo 0x%llx nx_port %d",
	    fo->fo_name, fo->fo_pid, SK_KVA(fob), SK_KVA(fo),
	    (int)fo->fo_nx_port);

	fo_free(fo);
}

int
flow_owner_flowadv_index_alloc(struct flow_owner *fo, flowadv_idx_t *fadv_idx)
{
	bitmap_t *bmap = fo->fo_flowadv_bmap;
	size_t nchunks, i, j, idx = FLOWADV_IDX_NONE;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));
	ASSERT(fo->fo_flowadv_max != 0);

	nchunks = P2ROUNDUP(fo->fo_flowadv_max, FO_FLOWADV_CHUNK) /
	    FO_FLOWADV_CHUNK;

	for (i = 0; i < nchunks; i++) {
		j = ffsll(bmap[i]);
		if (j == 0) {
			/* All indices in this chunk are in use */
			continue;
		}
		--j;
		/* mark the index as in use */
		bit_clear(bmap[i], j);
		idx = (i * FO_FLOWADV_CHUNK) + j;
		break;
	}

	if (idx == FLOWADV_IDX_NONE) {
		SK_ERR("%s(%d) flow advisory table full: num %u max %u",
		    fo->fo_name, fo->fo_pid, fo->fo_num_flowadv,
		    fo->fo_flowadv_max);
		VERIFY(fo->fo_num_flowadv == fo->fo_flowadv_max);
		*fadv_idx = FLOWADV_IDX_NONE;
		return ENOSPC;
	}

	fo->fo_num_flowadv++;
	ASSERT(idx < ((flowadv_idx_t) -1));
	*fadv_idx = (flowadv_idx_t)idx;
	ASSERT(*fadv_idx < fo->fo_flowadv_max);
	return 0;
}

void
flow_owner_flowadv_index_free(struct flow_owner *fo, flowadv_idx_t fadv_idx)
{
	uint32_t chunk_idx, bit_pos;
	bitmap_t *bmap = fo->fo_flowadv_bmap;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));
	ASSERT(fo->fo_num_flowadv != 0);
	ASSERT((fo->fo_flowadv_max != 0) && (fadv_idx < fo->fo_flowadv_max));

	chunk_idx = fadv_idx / FO_FLOWADV_CHUNK;
	bit_pos = fadv_idx % FO_FLOWADV_CHUNK;
	ASSERT(!bit_test(bmap[chunk_idx], bit_pos));
	/* mark the index as free */
	bit_set(bmap[chunk_idx], bit_pos);
	fo->fo_num_flowadv--;
}

int
flow_owner_destroy_entry(struct flow_owner *fo, uuid_t uuid,
    bool nolinger, void *close_params)
{
	struct flow_entry *fe = NULL;
	int err = 0;

	FOB_LOCK_ASSERT_HELD(FO_BUCKET(fo));

	/* lookup such flow for this process */
	fe = flow_entry_find_by_uuid(fo, uuid);
	if (fe == NULL) {
		err = ENOENT;
	} else {
		/* free flow entry (OK to linger if caller asked) */
		flow_entry_destroy(fo, fe, nolinger, close_params);
	}

	return err;
}

static inline int
fo_cmp(const struct flow_owner *a, const struct flow_owner *b)
{
	if (a->fo_pid > b->fo_pid) {
		return 1;
	}
	if (a->fo_pid < b->fo_pid) {
		return -1;
	}
	if ((intptr_t)a->fo_context > (intptr_t)b->fo_context) {
		return 1;
	} else if ((intptr_t)a->fo_context < (intptr_t)b->fo_context) {
		return -1;
	}
	if (a->fo_low_latency != b->fo_low_latency) {
		if (a->fo_low_latency) {
			return 1;
		} else {
			return -1;
		}
	}
	return 0;
}

static struct flow_owner *
fo_alloc(boolean_t can_block)
{
	struct flow_owner *fo;

	fo = skmem_cache_alloc(sk_fo_cache,
	    can_block ? SKMEM_SLEEP : SKMEM_NOSLEEP);
	if (fo == NULL) {
		return NULL;
	}

	bzero(fo, sk_fo_size);

	SK_DF(SK_VERB_MEM, "fo 0x%llx ALLOC", SK_KVA(fo));

	return fo;
}

static void
fo_free(struct flow_owner *fo)
{
	ASSERT(fo->fo_bucket == NULL);
	ASSERT(RB_EMPTY(&fo->fo_flow_entry_id_head));
	ASSERT(fo->fo_flowadv_bmap == NULL);

	SK_DF(SK_VERB_MEM, "fo 0x%llx FREE", SK_KVA(fo));

	skmem_cache_free(sk_fo_cache, fo);
}
