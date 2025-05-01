/*
 * Copyright (c) 2016-2023 Apple Inc. All rights reserved.
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
#define _FN_KPRINTF
#include <pexpert/pexpert.h>    /* for PE_parse_boot_argn */
#include <libkern/OSDebug.h>    /* for OSBacktrace */
#include <kern/sched_prim.h>    /* for assert_wait */
#include <vm/vm_memtag.h>

static struct skmem_slab *skmem_slab_create(struct skmem_cache *, uint32_t);
static void skmem_slab_destroy(struct skmem_cache *, struct skmem_slab *);

/*
 * Too big a value will cause overflow and thus trip the assertion; the
 * idea here is to set an upper limit for the time that a particular
 * thread is allowed to perform retries before we give up and panic.
 */
#define SKMEM_SLAB_MAX_BACKOFF          (20 * USEC_PER_SEC) /* seconds */

/*
 * Threshold (in msec) after which we reset the exponential backoff value
 * back to its (random) initial value.  Note that we allow the actual delay
 * to be at most twice this value.
 */
#define SKMEM_SLAB_BACKOFF_THRES        1024    /* up to ~2 sec (2048 msec) */

/*
 * To reduce the likelihood of global synchronization between threads,
 * we use some random value to start the exponential backoff.
 */
#define SKMEM_SLAB_BACKOFF_RANDOM       4       /* range is [1,4] msec */

/*
 * Create a slab.
 */
static struct skmem_slab *
skmem_slab_create(struct skmem_cache *skm, uint32_t skmflag)
{
	struct skmem_region *skr = skm->skm_region;
	uint32_t objsize, chunks;
	size_t slabsize = skm->skm_slabsize;
	struct skmem_slab *__single sl;
	struct sksegment *__single sg, *__single sgm;
	char *buf, *__indexable slab;
	char *__indexable bufm;
	uint32_t slabm_size;
	void *__sized_by(slabm_size) slabm;

	/*
	 * Allocate a segment (a slab at our layer) from the region.
	 */
	slab = skmem_region_alloc(skr, &slabm, &sg, &sgm, skmflag,
	    skr->skr_params.srp_c_seg_size, &slabm_size);
	if (slab == NULL) {
		goto rg_alloc_failure;
	}

	if ((sl = skmem_cache_alloc(skmem_slab_cache, SKMEM_SLEEP)) == NULL) {
		goto slab_alloc_failure;
	}

	ASSERT(sg != NULL);
	ASSERT(sgm == NULL || sgm->sg_index == sg->sg_index);

	bzero(sl, sizeof(*sl));
	sl->sl_cache = skm;
	sl->sl_base = buf = slab;
	bufm = slabm;
	objsize = (uint32_t)skr->skr_c_obj_size;
	sl->sl_basem = __unsafe_forge_bidi_indexable(void *, bufm, objsize);
	ASSERT(skr->skr_c_obj_size <= UINT32_MAX);
	ASSERT(skm->skm_objsize == objsize);
	ASSERT((slabsize / objsize) <= UINT32_MAX);
	sl->sl_chunks = chunks = (uint32_t)(slabsize / objsize);
	sl->sl_seg = sg;
	sl->sl_segm = sgm;

	/*
	 * Create one or more buffer control structures for the slab,
	 * each one tracking a chunk of raw object from the segment,
	 * and insert these into the slab's list of buffer controls.
	 */
	ASSERT(chunks > 0);
	while (chunks != 0) {
		struct skmem_bufctl *__indexable bc;
		bc = skmem_cache_alloc(skmem_bufctl_cache, SKMEM_SLEEP);
		if (bc == NULL) {
			goto bufctl_alloc_failure;
		}

		bzero(bc, bc_size);
		bc->bc_lim = objsize;
		bc->bc_addr = buf;
		bc->bc_addrm = bufm;
		bc->bc_slab = sl;
		bc->bc_idx = (sl->sl_chunks - chunks);
		if (skr->skr_mode & SKR_MODE_SHAREOK) {
			bc->bc_flags |= SKMEM_BUFCTL_SHAREOK;
		}
		SLIST_INSERT_HEAD(&sl->sl_head, bc, bc_link);
		buf += objsize;
		if (bufm != NULL) {
			/* XXX -fbounds-safety */
			bufm = (char *)bufm + objsize;
		}
		--chunks;
	}

	SK_DF(SK_VERB_MEM_CACHE, "skm 0x%llx sl 0x%llx",
	    SK_KVA(skm), SK_KVA(sl));
	SK_DF(SK_VERB_MEM_CACHE, "  [%u] [0x%llx-0x%llx)", sl->sl_seg->sg_index,
	    SK_KVA(slab), SK_KVA(slab + objsize));

	return sl;

bufctl_alloc_failure:
	skmem_slab_destroy(skm, sl);

slab_alloc_failure:
	skmem_region_free(skr, slab, __unsafe_forge_bidi_indexable(void *,
	    slabm, skr->skr_c_obj_size));

rg_alloc_failure:
	os_atomic_inc(&skm->skm_sl_alloc_fail, relaxed);

	return NULL;
}

/*
 * Destroy a slab.
 */
static void
skmem_slab_destroy(struct skmem_cache *skm, struct skmem_slab *sl)
{
	struct skmem_bufctl *bc, *tbc;
	void *__single slab = sl->sl_base;
	void *__single slabm = sl->sl_basem;

	ASSERT(sl->sl_refcnt == 0);

	SK_DF(SK_VERB_MEM_CACHE, "skm 0x%llx sl 0x%llx",
	    SK_KVA(skm), SK_KVA(sl));
	SK_DF(SK_VERB_MEM_CACHE, "  [%u] [0x%llx-0x%llx)", sl->sl_seg->sg_index,
	    SK_KVA(slab), SK_KVA((uintptr_t)slab + skm->skm_objsize));

	/*
	 * Go through the slab's list of buffer controls and free
	 * them, and then free the slab itself back to its cache.
	 */
	SLIST_FOREACH_SAFE(bc, &sl->sl_head, bc_link, tbc) {
		SLIST_REMOVE(&sl->sl_head, bc, skmem_bufctl, bc_link);
		skmem_cache_free(skmem_bufctl_cache, bc);
	}
	skmem_cache_free(skmem_slab_cache, sl);

	/*
	 * Restore original tag before freeing back to system. sl->sl_base should
	 * have the original tag.
	 */
	if (skm->skm_region->skr_bufspec.memtag) {
		vm_memtag_store_tag(slab, skm->skm_slabsize);
	}

	/* and finally free the segment back to the backing region */
	skmem_region_free(skm->skm_region, slab, slabm);
}

/*
 * Allocate a raw object from the (locked) slab layer.  Normal region variant.
 */
int
skmem_slab_alloc_locked(struct skmem_cache *skm, struct skmem_obj_info *oi,
    struct skmem_obj_info *oim, uint32_t skmflag)
{
	struct skmem_bufctl_bkt *bcb;
	struct skmem_bufctl *bc;
	struct skmem_slab *sl;
	uint32_t retries = 0;
	uint64_t boff_total = 0;                /* in usec */
	uint64_t boff = 0;                      /* in msec */
	boolean_t new_slab;
	size_t bufsize;
	void *__sized_by(bufsize) buf;
#if CONFIG_KERNEL_TAGGING
	vm_map_address_t tagged_address;        /* address tagging */
	struct skmem_region *region;            /* region source for this slab */
#endif /* CONFIG_KERNEL_TAGGING */

	/* this flag is not for the caller to set */
	VERIFY(!(skmflag & SKMEM_FAILOK));

	/*
	 * A slab is either in a partially-allocated list (at least it has
	 * a free object available), or is in the empty list (everything
	 * has been allocated.)  If we can't find a partially-allocated
	 * slab, then we need to allocate a slab (segment) from the region.
	 */
again:
	SKM_SLAB_LOCK_ASSERT_HELD(skm);
	sl = TAILQ_FIRST(&skm->skm_sl_partial_list);
	if (sl == NULL) {
		uint32_t flags = skmflag;
		boolean_t retry;

		ASSERT(skm->skm_sl_partial == 0);
		SKM_SLAB_UNLOCK(skm);
		if (!(flags & SKMEM_NOSLEEP)) {
			/*
			 * Pick up a random value to start the exponential
			 * backoff, if this is the first round, or if the
			 * current value is over the threshold.  Otherwise,
			 * double the backoff value.
			 */
			if (boff == 0 || boff > SKMEM_SLAB_BACKOFF_THRES) {
				read_frandom(&boff, sizeof(boff));
				boff = (boff % SKMEM_SLAB_BACKOFF_RANDOM) + 1;
				ASSERT(boff > 0);
			} else if (os_mul_overflow(boff, 2, &boff)) {
				panic_plain("\"%s\": boff counter "
				    "overflows\n", skm->skm_name);
				/* NOTREACHED */
				__builtin_unreachable();
			}
			/* add this value (in msec) to the total (in usec) */
			if (os_add_overflow(boff_total,
			    (boff * NSEC_PER_USEC), &boff_total)) {
				panic_plain("\"%s\": boff_total counter "
				    "overflows\n", skm->skm_name);
				/* NOTREACHED */
				__builtin_unreachable();
			}
		}
		/*
		 * In the event of a race between multiple threads trying
		 * to create the last remaining (or the only) slab, let the
		 * loser(s) attempt to retry after waiting a bit.  The winner
		 * would have inserted the newly-created slab into the list.
		 */
		if (!(flags & SKMEM_NOSLEEP) &&
		    boff_total <= SKMEM_SLAB_MAX_BACKOFF) {
			retry = TRUE;
			++retries;
			flags |= SKMEM_FAILOK;
		} else {
			if (!(flags & SKMEM_NOSLEEP)) {
				panic_plain("\"%s\": failed to allocate "
				    "slab (sleeping mode) after %llu "
				    "msec, %u retries\n\n%s", skm->skm_name,
				    (boff_total / NSEC_PER_USEC), retries,
				    skmem_dump(skm->skm_region));
				/* NOTREACHED */
				__builtin_unreachable();
			}
			retry = FALSE;
		}

		/*
		 * Create a new slab.
		 */
		if ((sl = skmem_slab_create(skm, flags)) == NULL) {
			if (retry) {
				SK_ERR("\"%s\": failed to allocate "
				    "slab (%ssleeping mode): waiting for %llu "
				    "msec, total %llu msec, %u retries",
				    skm->skm_name,
				    (flags & SKMEM_NOSLEEP) ? "non-" : "",
				    boff, (boff_total / NSEC_PER_USEC), retries);
				VERIFY(boff > 0 && ((uint32_t)boff <=
				    (SKMEM_SLAB_BACKOFF_THRES * 2)));
				delay((uint32_t)boff * NSEC_PER_USEC);
				SKM_SLAB_LOCK(skm);
				goto again;
			} else {
				SK_RDERR(4, "\"%s\": failed to allocate slab "
				    "(%ssleeping mode)", skm->skm_name,
				    (flags & SKMEM_NOSLEEP) ? "non-" : "");
				SKM_SLAB_LOCK(skm);
			}
			return ENOMEM;
		}

		SKM_SLAB_LOCK(skm);
		skm->skm_sl_create++;
		if ((skm->skm_sl_bufinuse += sl->sl_chunks) >
		    skm->skm_sl_bufmax) {
			skm->skm_sl_bufmax = skm->skm_sl_bufinuse;
		}
	}
	skm->skm_sl_alloc++;

	new_slab = (sl->sl_refcnt == 0);
	ASSERT(new_slab || SKMEM_SLAB_IS_PARTIAL(sl));

	sl->sl_refcnt++;
	ASSERT(sl->sl_refcnt <= sl->sl_chunks);

	/*
	 * We either have a new slab, or a partially-allocated one.
	 * Remove a buffer control from the slab, and insert it to
	 * the allocated-address hash chain.
	 */
	bc = SLIST_FIRST(&sl->sl_head);
	ASSERT(bc != NULL);
	SLIST_REMOVE(&sl->sl_head, bc, skmem_bufctl, bc_link);

	/* sanity check */
	VERIFY(bc->bc_usecnt == 0);

	/*
	 * Also store the master object's region info for the caller.
	 */
	bzero(oi, sizeof(*oi));
#if CONFIG_KERNEL_TAGGING
	region = sl->sl_cache->skm_region;
	if (region->skr_mode & SKR_MODE_MEMTAG) {
		tagged_address = (vm_map_address_t)vm_memtag_generate_and_store_tag(bc->bc_addr,
		    skm->skm_objsize);
		/*
		 * XXX -fbounds-safety: tagged_address's type is vm_offset_t
		 * which is unsafe, so we have ot use __unsafe_forge here.
		 * Also, skm->skm_objsize is equal to bc->bc_addr (they're both
		 * set to skr->skr_c_obj_size)
		 */
		bufsize = skm->skm_objsize;
		/*
		 * XXX -fbounds-safety: Couldn't pass bufsize here, because
		 * compiler gives an error: cannot reference 'bufsize' after it
		 * is changed during consecutive assignments
		 */
		buf = __unsafe_forge_bidi_indexable(void *, tagged_address,
		    skm->skm_objsize);
	} else {
		bufsize = bc->bc_lim;
		buf = bc->bc_addr;
	}
#else /* !CONFIG_KERNEL_TAGGING */
	bufsize = bc->bc_lim;
	buf = bc->bc_addr;
#endif /* CONFIG_KERNEL_TAGGING */
	SKMEM_OBJ_SIZE(oi) = (uint32_t)bufsize;
	SKMEM_OBJ_ADDR(oi) = buf;
	SKMEM_OBJ_BUFCTL(oi) = bc;      /* master only; NULL for slave */
	ASSERT(skm->skm_objsize <= UINT32_MAX);
	SKMEM_OBJ_IDX_REG(oi) =
	    ((sl->sl_seg->sg_index * sl->sl_chunks) + bc->bc_idx);
	SKMEM_OBJ_IDX_SEG(oi) = bc->bc_idx;
	/*
	 * And for slave object.
	 */
	if (oim != NULL) {
		bzero(oim, sizeof(*oim));
		if (bc->bc_addrm != NULL) {
			SKMEM_OBJ_ADDR(oim) = __unsafe_forge_bidi_indexable(
				void *, bc->bc_addrm, SKMEM_OBJ_SIZE(oi));
			SKMEM_OBJ_SIZE(oim) = SKMEM_OBJ_SIZE(oi);
			SKMEM_OBJ_IDX_REG(oim) = SKMEM_OBJ_IDX_REG(oi);
			SKMEM_OBJ_IDX_SEG(oim) = SKMEM_OBJ_IDX_SEG(oi);
		}
	}

	if (skm->skm_mode & SKM_MODE_BATCH) {
		((struct skmem_obj *)buf)->mo_next = NULL;
	}

	/* insert to allocated-address hash chain */
	bcb = SKMEM_CACHE_HASH(skm, buf);
	SLIST_INSERT_HEAD(&bcb->bcb_head, bc, bc_link);

	if (SLIST_EMPTY(&sl->sl_head)) {
		/*
		 * If that was the last buffer control from this slab,
		 * insert the slab into the empty list.  If it was in
		 * the partially-allocated list, then remove the slab
		 * from there as well.
		 */
		ASSERT(sl->sl_refcnt == sl->sl_chunks);
		if (new_slab) {
			ASSERT(sl->sl_chunks == 1);
		} else {
			ASSERT(sl->sl_chunks > 1);
			ASSERT(skm->skm_sl_partial > 0);
			skm->skm_sl_partial--;
			TAILQ_REMOVE(&skm->skm_sl_partial_list, sl, sl_link);
		}
		skm->skm_sl_empty++;
		ASSERT(skm->skm_sl_empty != 0);
		TAILQ_INSERT_HEAD(&skm->skm_sl_empty_list, sl, sl_link);
	} else {
		/*
		 * The slab is not empty; if it was newly allocated
		 * above, then it's not in the partially-allocated
		 * list and so we insert it there.
		 */
		ASSERT(SKMEM_SLAB_IS_PARTIAL(sl));
		if (new_slab) {
			skm->skm_sl_partial++;
			ASSERT(skm->skm_sl_partial != 0);
			TAILQ_INSERT_HEAD(&skm->skm_sl_partial_list,
			    sl, sl_link);
		}
	}

	/* if auditing is enabled, record this transaction */
	if (__improbable((skm->skm_mode & SKM_MODE_AUDIT) != 0)) {
		skmem_audit_bufctl(bc);
	}

	return 0;
}

/*
 * Allocate a raw object from the (locked) slab layer.  Pseudo region variant.
 */
int
skmem_slab_alloc_pseudo_locked(struct skmem_cache *skm,
    struct skmem_obj_info *oi, struct skmem_obj_info *oim, uint32_t skmflag)
{
	zalloc_flags_t zflags = (skmflag & SKMEM_NOSLEEP) ? Z_NOWAIT : Z_WAITOK;
	struct skmem_region *skr = skm->skm_region;
	void *obj, *buf;

	/* this flag is not for the caller to set */
	VERIFY(!(skmflag & SKMEM_FAILOK));

	SKM_SLAB_LOCK_ASSERT_HELD(skm);

	ASSERT(skr->skr_reg == NULL && skr->skr_zreg != NULL);
	/* mirrored region is not applicable */
	ASSERT(!(skr->skr_mode & SKR_MODE_MIRRORED));
	/* batching is not yet supported */
	ASSERT(!(skm->skm_mode & SKM_MODE_BATCH));

	obj = zalloc_flags_buf(skr->skr_zreg, zflags | Z_ZERO);
	if (obj == NULL) {
		os_atomic_inc(&skm->skm_sl_alloc_fail, relaxed);
		return ENOMEM;
	}

#if KASAN
	/*
	 * Perform some fix-ups since the zone element isn't guaranteed
	 * to be on the aligned boundary.  The effective object size
	 * has been adjusted accordingly by skmem_region_create() earlier
	 * at cache creation time.
	 *
	 * 'buf' is the aligned address for this object.
	 */
	uintptr_t diff = P2ROUNDUP((intptr_t)obj + sizeof(u_int64_t),
	    skm->skm_bufalign) - (uintptr_t)obj;
	buf = (void *)((char *)obj + diff);

	/*
	 * Wind back a pointer size from the aligned address and
	 * save the original address so we can free it later.
	 */
	/*
	 * XXX -fbounds-safety: Since this function is for generic alloc, we
	 * cannot modify the struct like we did for struct skmem_cache.
	 * Unfortunately, __unsafe_forge_bidi_indexable seems to be the only
	 * choice.
	 */
	void **pbuf = __unsafe_forge_bidi_indexable(void **,
	    (intptr_t)buf - sizeof(void *), sizeof(void *));
	*pbuf = obj;

	VERIFY(((intptr_t)buf + skm->skm_bufsize) <=
	    ((intptr_t)obj + skm->skm_objsize));
#else /* !KASAN */
	/*
	 * We expect that the zone allocator would allocate elements
	 * rounded up to the requested alignment based on the effective
	 * object size computed in skmem_region_create() earlier, and
	 * 'buf' is therefore the element address itself.
	 */
	buf = obj;
#endif /* !KASAN */

	/* make sure the object is aligned */
	VERIFY(IS_P2ALIGNED(buf, skm->skm_bufalign));

	/*
	 * Return the object's info to the caller.
	 */
	bzero(oi, sizeof(*oi));
	SKMEM_OBJ_ADDR(oi) = buf;
#if KASAN
	SKMEM_OBJ_SIZE(oi) = (uint32_t)skm->skm_objsize -
	    (uint32_t)skm->skm_bufalign;
#else
	SKMEM_OBJ_SIZE(oi) = (uint32_t)skm->skm_objsize;
#endif
	ASSERT(skm->skm_objsize <= UINT32_MAX);
	if (oim != NULL) {
		bzero(oim, sizeof(*oim));
	}

	skm->skm_sl_alloc++;
	skm->skm_sl_bufinuse++;
	if (skm->skm_sl_bufinuse > skm->skm_sl_bufmax) {
		skm->skm_sl_bufmax = skm->skm_sl_bufinuse;
	}

	return 0;
}

/*
 * Allocate a raw object from the slab layer.
 */
int
skmem_slab_alloc(struct skmem_cache *skm, struct skmem_obj_info *oi,
    struct skmem_obj_info *oim, uint32_t skmflag)
{
	int err;

	SKM_SLAB_LOCK(skm);
	err = skm->skm_slab_alloc(skm, oi, oim, skmflag);
	SKM_SLAB_UNLOCK(skm);

	return err;
}

/*
 * Allocate raw object(s) from the slab layer.
 */
uint32_t
skmem_slab_batch_alloc(struct skmem_cache *skm, struct skmem_obj **list,
    uint32_t num, uint32_t skmflag)
{
	uint32_t need = num;

	ASSERT(list != NULL && (skm->skm_mode & SKM_MODE_BATCH));
	*list = NULL;

	SKM_SLAB_LOCK(skm);
	for (;;) {
		struct skmem_obj_info oi, oim;

		/*
		 * Get a single raw object from the slab layer.
		 */
		if (skm->skm_slab_alloc(skm, &oi, &oim, skmflag) != 0) {
			break;
		}

		*list = SKMEM_OBJ_ADDR(&oi);
		ASSERT((*list)->mo_next == NULL);
		/* store these inside the object itself */
		(*list)->mo_info = oi;
		(*list)->mo_minfo = oim;
		list = &(*list)->mo_next;

		ASSERT(need != 0);
		if (--need == 0) {
			break;
		}
	}
	SKM_SLAB_UNLOCK(skm);

	return num - need;
}

/*
 * Free a raw object to the (locked) slab layer.  Normal region variant.
 */
void
skmem_slab_free_locked(struct skmem_cache *skm, void *buf)
{
	struct skmem_bufctl *bc, *tbc;
	struct skmem_bufctl_bkt *bcb;
	struct skmem_slab *sl = NULL;
#if CONFIG_KERNEL_TAGGING
	struct skmem_region *region;
	vm_map_address_t tagged_addr;
#endif /* CONFIG_KERNEL_TAGGING */

	SKM_SLAB_LOCK_ASSERT_HELD(skm);
	ASSERT(buf != NULL);
	/* caller is expected to clear mo_next */
	ASSERT(!(skm->skm_mode & SKM_MODE_BATCH) ||
	    ((struct skmem_obj *)buf)->mo_next == NULL);

	/*
	 * Search the hash chain to find a matching buffer control for the
	 * given object address.  If found, remove the buffer control from
	 * the hash chain and insert it into the freelist.  Otherwise, we
	 * panic since the caller has given us a bogus address.
	 */
	skm->skm_sl_free++;
	bcb = SKMEM_CACHE_HASH(skm, buf);

	SLIST_FOREACH_SAFE(bc, &bcb->bcb_head, bc_link, tbc) {
		if (SKMEM_COMPARE_CANONICAL_ADDR(bc->bc_addr, buf, skm->skm_objsize)) {
			SLIST_REMOVE(&bcb->bcb_head, bc, skmem_bufctl, bc_link);
			sl = bc->bc_slab;
			break;
		}
	}

	if (bc == NULL) {
		panic("%s: attempt to free invalid or already-freed obj %p "
		    "on skm %p", __func__, buf, skm);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	ASSERT(sl != NULL && sl->sl_cache == skm);
	VERIFY(SKMEM_SLAB_MEMBER(sl, SKMEM_MEMTAG_STRIP_TAG(buf, skm->skm_objsize)));

	/* make sure this object is not currently in use by another object */
	VERIFY(bc->bc_usecnt == 0);

	/* if auditing is enabled, record this transaction */
	if (__improbable((skm->skm_mode & SKM_MODE_AUDIT) != 0)) {
		skmem_audit_bufctl(bc);
	}

	/* if clear on free is requested, zero out the object */
	if (skm->skm_mode & SKM_MODE_CLEARONFREE) {
		size_t size = skm->skm_objsize;
		void *buf_cpy = __unsafe_forge_bidi_indexable(void *, buf, size);
		bzero(buf_cpy, size);
		buf_cpy = NULL;
		size = 0;
	}

#if CONFIG_KERNEL_TAGGING
	region = skm->skm_region;
	if (region->skr_mode & SKR_MODE_MEMTAG) {
		tagged_addr = (vm_map_address_t)vm_memtag_generate_and_store_tag(buf, skm->skm_objsize);
	}
#endif /* CONFIG_KERNEL_TAGGING */

	/* insert the buffer control to the slab's freelist */
	SLIST_INSERT_HEAD(&sl->sl_head, bc, bc_link);

	ASSERT(sl->sl_refcnt >= 1);
	if (--sl->sl_refcnt == 0) {
		/*
		 * If this was the last outstanding object for the slab,
		 * remove the slab from the partially-allocated or empty
		 * list, and destroy the slab (segment) back to the region.
		 */
		if (sl->sl_chunks == 1) {
			ASSERT(skm->skm_sl_empty > 0);
			skm->skm_sl_empty--;
			TAILQ_REMOVE(&skm->skm_sl_empty_list, sl, sl_link);
		} else {
			ASSERT(skm->skm_sl_partial > 0);
			skm->skm_sl_partial--;
			TAILQ_REMOVE(&skm->skm_sl_partial_list, sl, sl_link);
		}
		ASSERT((int64_t)(skm->skm_sl_bufinuse - sl->sl_chunks) >= 0);
		skm->skm_sl_bufinuse -= sl->sl_chunks;
		skm->skm_sl_destroy++;
		SKM_SLAB_UNLOCK(skm);
		skmem_slab_destroy(skm, sl);
		SKM_SLAB_LOCK(skm);
		return;
	}

	ASSERT(bc == SLIST_FIRST(&sl->sl_head));
	if (SLIST_NEXT(bc, bc_link) == NULL) {
		/*
		 * If this is the first (potentially amongst many) object
		 * that's returned to the slab, remove the slab from the
		 * empty list and insert to end of the partially-allocated
		 * list. This should help avoid thrashing the partial slab
		 * since we avoid disturbing what's already at the front.
		 */
		ASSERT(sl->sl_refcnt == (sl->sl_chunks - 1));
		ASSERT(sl->sl_chunks > 1);
		ASSERT(skm->skm_sl_empty > 0);
		skm->skm_sl_empty--;
		TAILQ_REMOVE(&skm->skm_sl_empty_list, sl, sl_link);
		skm->skm_sl_partial++;
		ASSERT(skm->skm_sl_partial != 0);
		TAILQ_INSERT_TAIL(&skm->skm_sl_partial_list, sl, sl_link);
	}
}

/*
 * Free a raw object to the (locked) slab layer.  Pseudo region variant.
 */
void
skmem_slab_free_pseudo_locked(struct skmem_cache *skm, void *buf)
{
	struct skmem_region *skr = skm->skm_region;
	void *__single obj = buf;

	ASSERT(skr->skr_reg == NULL && skr->skr_zreg != NULL);

	SKM_SLAB_LOCK_ASSERT_HELD(skm);

	VERIFY(IS_P2ALIGNED(obj, skm->skm_bufalign));

#if KASAN
	/*
	 * Since we stuffed the original zone element address before
	 * the buffer address in KASAN mode, get it back since we're
	 * about to free it.
	 */
	void **pbuf = __unsafe_forge_bidi_indexable(void **,
	    ((intptr_t)obj - sizeof(void *)), sizeof(void *));

	VERIFY(((intptr_t)obj + skm->skm_bufsize) <=
	    ((intptr_t)*pbuf + skm->skm_objsize));

	obj = *pbuf;
#endif /* KASAN */

	/* free it to zone */
	zfree(skr->skr_zreg, obj);

	skm->skm_sl_free++;
	ASSERT(skm->skm_sl_bufinuse > 0);
	skm->skm_sl_bufinuse--;
}

/*
 * Free a raw object to the slab layer.
 */
void
skmem_slab_free(struct skmem_cache *skm, void *buf)
{
	if (skm->skm_mode & SKM_MODE_BATCH) {
		((struct skmem_obj *)buf)->mo_next = NULL;
	}

	SKM_SLAB_LOCK(skm);
	skm->skm_slab_free(skm, buf);
	SKM_SLAB_UNLOCK(skm);
}

/*
 * Free raw object(s) to the slab layer.
 */
void
skmem_slab_batch_free(struct skmem_cache *skm, struct skmem_obj *list)
{
	struct skmem_obj *listn;

	ASSERT(list != NULL && (skm->skm_mode & SKM_MODE_BATCH));

	SKM_SLAB_LOCK(skm);
	for (;;) {
		listn = list->mo_next;
		list->mo_next = NULL;

		/*
		 * Free a single object to the slab layer.
		 */
		skm->skm_slab_free(skm, (void *)list);

		/* if no more objects to free, we're done */
		if ((list = listn) == NULL) {
			break;
		}
	}
	SKM_SLAB_UNLOCK(skm);
}


/*
 * Given a buffer control, record the current transaction.
 */
__attribute__((noinline, cold, not_tail_called))
inline void
skmem_audit_bufctl(struct skmem_bufctl *bc)
{
	struct skmem_bufctl_audit *bca = (struct skmem_bufctl_audit *)bc;
	struct timeval tv;

	microuptime(&tv);
	bca->bc_thread = current_thread();
	bca->bc_timestamp = (uint32_t)((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
	bca->bc_depth = OSBacktrace(bca->bc_stack, SKMEM_STACK_DEPTH);
}
