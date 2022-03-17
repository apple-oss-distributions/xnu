/*
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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

#include "cuckoo_hashtable.h"

#define CUCKOO_TAG "com.apple.skywalk.libcuckoo"
kern_allocation_name_t cuckoo_tag;

SYSCTL_NODE(_kern_skywalk, OID_AUTO, libcuckoo, CTLFLAG_RW | CTLFLAG_LOCKED,
    0, "Skywalk Cuckoo Hashtable Library");

uint32_t cuckoo_verbose = 0;
#if (DEVELOPMENT || DEBUG)
SYSCTL_UINT(_kern_skywalk_libcuckoo, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED, &cuckoo_verbose, 0, "");
#endif /* DEVELOPMENT || DEBUG */

typedef enum cht_verb {
	CHTV_ERR = 0,
	CHTV_WARN = 1,
	CHTV_INFO = 2,
	CHTV_DEBUG = 3,
} cht_verb_t;

static LCK_GRP_DECLARE(cht_lock_group, "CHT_LOCK");
static LCK_ATTR_DECLARE(cht_lock_attr, 0, 0);

#if SK_LOG
#define cht_log(level, _fmt, ...)       \
	do {    \
	        if (level <= cuckoo_verbose) {  \
	                kprintf("Cuckoo: thread %p %-30s " _fmt "\n",   \
	                    current_thread(), __FUNCTION__, ##__VA_ARGS__);     \
	        }       \
	} while (0);
#else  /* !SK_LOG */
#define cht_log(_flag, _fmt, ...) do { ((void)0); } while (0)
#endif /* !SK_LOG */

#define cht_err(_fmt, ...) cht_log(CHTV_ERR, _fmt, ##__VA_ARGS__)
#define cht_warn(_fmt, ...) cht_log(CHTV_WARN, _fmt, ##__VA_ARGS__)
#define cht_info(_fmt, ...) cht_log(CHTV_INFO, _fmt, ##__VA_ARGS__)
#define cht_debug(_fmt, ...) cht_log(CHTV_DEBUG, _fmt, ##__VA_ARGS__)

static inline int
cuckoo_node_chain(struct cuckoo_node *node,
    struct cuckoo_node *new_node)
{
	struct cuckoo_node *prev_node = node;

	/* new node must be zero initialized */
	ASSERT(new_node->next == NULL);

	/* use tail insert to check for duplicate along list */
	while (__improbable(node != NULL)) {
		if (node == new_node) {
			return EEXIST;
		}
		prev_node = node;
		node = node->next;
	}

	prev_node->next = new_node;

	return 0;
}

static inline bool
cuckoo_node_del(struct cuckoo_node **pnode,
    struct cuckoo_node *del_node)
{
	ASSERT(pnode != NULL);

	struct cuckoo_node *node = *pnode;
	while (node != NULL && node != del_node) {
		pnode = &node->next;
		node = node->next;
	}
	if (__probable(node != NULL)) {
		*pnode = node->next;
		node->next = NULL;
		return true;
	}

	return false;
}

static inline void
cuckoo_node_set_next(struct cuckoo_node *node, struct cuckoo_node *next_node)
{
	node->next = next_node;
}

/* We probably won't add RCU soon so use simple pointer reference for now */
static inline struct cuckoo_node *
cuckoo_node_next(struct cuckoo_node *node)
{
	return node->next;
}

#define _CHT_MAX_LOAD_SHRINK 40       /* at least below 40% load to shrink */
#define _CHT_MIN_LOAD_EXPAND 85       /* cuckoo could hold 85% full table */

enum cuckoo_resize_ops {
	_CHT_RESIZE_EXPAND = 0,
	_CHT_RESIZE_SHRINK = 1,
};

/*
 * Following classic Cuckoo hash table design, cuckoo_hashtable use k hash
 * functions to derive multiple candidate hash table bucket indexes.
 * Here cuckoo_hashtable use k=2.
 *     prim_bkt_idx = bkt_idx[1] = hash[1](key) % N_BUCKETS
 *     alt_bkt_idx  = bkt_idx[2] = hash[2](key) % N_BUCKETS
 *
 * Currently, we let the caller pass in the actual key's hash value, because
 * in most of the use cases, caller probably have already calculated the hash
 * value of actual key (e.g. using hardware offloading or copy+hash). This also
 * save us from storing the key in the table (or any side data structure). So
 *
 *     hash[1] = hash    // hash(hash value) passed in from caller
 *     hash[2] = __alt_hash(hash[1])
 *
 * __alt_hash derives h2 using h1's high bits, since calculating primary
 * bucket index uses its low bits. So alt_hash is still a uniformly distributed
 * random variable (but not independent of h1, but is fine for hashtable usage).
 *
 * There is option to store h2 in the table bucket as well but cuckoo_hashtable
 * is not doing this to use less memory usage with the small price of a few
 * more cpu cycles during add/del operation. Assuming that the hashtable is
 * read-heavy rather than write-heavy, this is reasonable.
 *
 * In the rare case of full hash value collision, where
 *     hash[1] == hash[1]'
 * , there is no way for the hash table to differentiate two objects, thus we
 * need to chain the fully collided objects under the same bucket slot.
 * The caller need to walk the chain to explicitly compare the full length key
 * to find the correct object.
 *
 * Reference Counting
 * The hashtable assumes all objects are reference counted. It takes function
 * pointers that retain and release the object.
 * Adding to the table will call its retain function.
 * Deleting from the table will call its release function.
 *
 */

/* hash might be zero, so always use _node == NULL to test empty slot */
struct _slot {
	uint32_t                _hash;
	struct cuckoo_node      *_node;
};

/*
 * Cuckoo hashtable cache line awareness:
 *   - ARM platform has 128B CPU cache line.
 *   - Intel platform has 64B CPU cache line. However, hardware prefetcher
 *     treats cache lines as 128B chunk and prefetch the other 64B cache line.
 *
 * Thus cuckoo_hashtable use 128B as bucket size to make best use CPU cache
 * resource.
 */
#define _CHT_CACHELINE_CHUNK 128
#define _CHT_SLOT_INVAL UINT8_MAX
static const uint8_t _CHT_BUCKET_SLOTS =
    ((_CHT_CACHELINE_CHUNK - sizeof(lck_mtx_t) - sizeof(uint8_t)) /
    sizeof(struct _slot));

struct _bucket {
	struct _slot            _slots[_CHT_BUCKET_SLOTS];
	decl_lck_mtx_data(, _lock);
	uint8_t                 _inuse;
} __attribute__((aligned(_CHT_CACHELINE_CHUNK)));

struct cuckoo_hashtable {
	uint32_t        _bitmask;       /* 1s' mask for quick MOD */
	uint32_t        _n_buckets;     /* number of buckets */

	volatile uint32_t _n_entries;   /* number of entires in table */
	uint32_t          _capacity;    /* max number of entires */
	uint32_t          _rcapacity;   /* requested capacity */

	bool            _busy;
	uint32_t        _resize_waiters;
	decl_lck_rw_data(, _resize_lock);
	decl_lck_mtx_data(, _lock);

	struct _bucket  *_buckets;

	int (*_obj_cmp)(struct cuckoo_node *node, void *key);
	void (*_obj_retain)(struct cuckoo_node *);
	void (*_obj_release)(struct cuckoo_node *);
} __attribute__((aligned(_CHT_CACHELINE_CHUNK)));

static inline void
__slot_set(struct _slot *slt, uint32_t hash, struct cuckoo_node *node)
{
	slt->_hash = hash;
	slt->_node = node;
}

static inline void
__slot_reset(struct _slot *slt)
{
	slt->_hash = 0;
	slt->_node = NULL;
}

static inline uint32_t
__alt_hash(uint32_t hash)
{
#define _CHT_ALT_HASH_MIX       0x5bd1e995      /* Murmur hash mix */
	uint32_t tag = hash >> 16;
	uint32_t alt_hash = hash ^ ((tag + 1) * _CHT_ALT_HASH_MIX);
	return alt_hash;
}

static inline struct _bucket *
__get_bucket(struct cuckoo_hashtable *h, uint32_t b_i)
{
	return &h->_buckets[b_i];
}

static inline struct _bucket *
__prim_bucket(struct cuckoo_hashtable *h, uint32_t hash)
{
	return __get_bucket(h, hash & h->_bitmask);
}

static inline struct _bucket *
__alt_bucket(struct cuckoo_hashtable *h, uint32_t hash)
{
	return __get_bucket(h, __alt_hash(hash) & h->_bitmask);
}

#if SK_LOG
static inline size_t
__bucket_idx(struct cuckoo_hashtable *h, struct _bucket *b)
{
	return ((uintptr_t)b - (uintptr_t)&h->_buckets[0]) / sizeof(struct _bucket);
}
#endif /* SK_LOG */

static inline struct _slot *
__bucket_slot(struct _bucket *b, uint32_t slot_idx)
{
	return &b->_slots[slot_idx];
}

static inline bool
__slot_empty(struct _slot *s)
{
	return s->_node == NULL;
}

static inline uint32_t
__align32pow2(uint32_t v)
{
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;

	return v;
}

uint32_t
cuckoo_hashtable_load_factor(struct cuckoo_hashtable *h)
{
	return (100 * h->_n_entries) / (h->_n_buckets * _CHT_BUCKET_SLOTS);
}

/*
 * Cuckoo hashtable uses regular mutex.  Most operations(find/add) should
 * finish faster than a context switch.  It avoids using the spin lock since
 * it might cause issues on certain platforms (e.g. x86_64) where the trap
 * handler for dealing with FP/SIMD use would be invoked to perform thread-
 * specific allocations; the use of FP/SIMD here is related to the memory
 * compare with mask routines.  Even in case of another thread holding a
 * bucket lock and went asleep, cuckoo path search would try to find another
 * path without blockers.
 *
 * The only exception is table expansion, which could take a long time, we use
 * read/write lock to protect the whole table against any read/write in that
 * case.
 */

/* find/add only acquires table rlock, and serialize with bucket lock */
#define __lock_bucket(b)        lck_mtx_lock(&b->_lock)
#define __unlock_bucket(b)      lck_mtx_unlock(&b->_lock)

#define _CHT_DEADLOCK_THRESHOLD 20
static inline bool
__lock_bucket_with_backoff(struct _bucket *b)
{
	uint32_t try_counter = 0;
	while (!lck_mtx_try_lock(&b->_lock)) {
		if (try_counter++ > _CHT_DEADLOCK_THRESHOLD) {
			return false;
		}
	}
	return true;
}

#define __rlock_table(h)        lck_rw_lock_shared(&h->_resize_lock)
#define __unrlock_table(h)      lck_rw_unlock_shared(&h->_resize_lock)
#define __r2wlock_table(h)      lck_rw_lock_shared_to_exclusive(&h->_resize_lock)
#define __wlock_table(h)        lck_rw_lock_exclusive(&h->_resize_lock)
#define __unwlock_table(h)      lck_rw_unlock_exclusive(&h->_resize_lock)

static inline int
__resize_begin(struct cuckoo_hashtable *h)
{
	// takes care of concurrent resize
	lck_mtx_lock(&h->_lock);
	while (h->_busy) {
		if (++(h->_resize_waiters) == 0) {   /* wraparound */
			h->_resize_waiters++;
		}
		int error = msleep(&h->_resize_waiters, &h->_lock,
		    (PZERO + 1), __FUNCTION__, NULL);
		if (error == EINTR) {
			cht_warn("resize waiter was interrupted");
			ASSERT(h->_resize_waiters > 0);
			h->_resize_waiters--;
			lck_mtx_unlock(&h->_lock);
			return EINTR;
		}
		// resizer finished
		lck_mtx_unlock(&h->_lock);
		return EAGAIN;
	}

	h->_busy = true;
	lck_mtx_unlock(&h->_lock);

	// takes other readers offline
	__wlock_table(h);
	return 0;
}

static inline void
__resize_end(struct cuckoo_hashtable *h)
{
	__unwlock_table(h);
	lck_mtx_lock(&h->_lock);
	h->_busy = false;
	if (__improbable(h->_resize_waiters > 0)) {
		h->_resize_waiters = 0;
		wakeup(&h->_resize_waiters);
	}
	lck_mtx_unlock(&h->_lock);
}

void
cuckoo_hashtable_init(void)
{
	_CASSERT(sizeof(struct _bucket) <= _CHT_CACHELINE_CHUNK);
	ASSERT(cuckoo_tag == NULL);
	cuckoo_tag = kern_allocation_name_allocate(CUCKOO_TAG, 0);
	ASSERT(cuckoo_tag != NULL);
}

struct cuckoo_hashtable *
cuckoo_hashtable_create(struct cuckoo_hashtable_params *p)
{
	struct cuckoo_hashtable *h = NULL;
	uint32_t n = 0;
	uint32_t n_buckets = 0;
	struct _bucket *buckets = NULL;
	uint32_t i;

	if (p->cht_capacity > CUCKOO_HASHTABLE_ENTRIES_MAX ||
	    p->cht_capacity < _CHT_BUCKET_SLOTS) {
		return NULL;
	}

	ASSERT(p->cht_capacity < UINT32_MAX);
	n = (uint32_t)p->cht_capacity;
	h = sk_alloc_type(struct cuckoo_hashtable, Z_WAITOK | Z_NOFAIL, cuckoo_tag);

	n_buckets = __align32pow2(n / _CHT_BUCKET_SLOTS);
	buckets = sk_alloc_type_array(struct _bucket, n_buckets, Z_WAITOK, cuckoo_tag);
	if (buckets == NULL) {
		sk_free_type(struct cuckoo_hashtable, h);
		return NULL;
	}

	for (i = 0; i < n_buckets; i++) {
		lck_mtx_init(&buckets[i]._lock, &cht_lock_group, &cht_lock_attr);
	}

	lck_mtx_init(&h->_lock, &cht_lock_group, &cht_lock_attr);

	h->_n_entries = 0;
	h->_n_buckets = n_buckets;
	h->_capacity = h->_rcapacity = h->_n_buckets * _CHT_BUCKET_SLOTS;
	h->_bitmask = n_buckets - 1;
	h->_buckets = buckets;
	lck_rw_init(&h->_resize_lock, &cht_lock_group, &cht_lock_attr);
	h->_busy = false;
	h->_resize_waiters = 0;

	ASSERT(p->cht_obj_retain != NULL);
	ASSERT(p->cht_obj_release != NULL);
	ASSERT(p->cht_obj_cmp != NULL);
	h->_obj_cmp = p->cht_obj_cmp;
	h->_obj_retain = p->cht_obj_retain;
	h->_obj_release = p->cht_obj_release;

	return h;
}

void
cuckoo_hashtable_free(struct cuckoo_hashtable *h)
{
	uint32_t i;

	if (h == NULL) {
		return;
	}

	ASSERT(h->_n_entries == 0);

	if (h->_buckets != NULL) {
		for (i = 0; i < h->_n_buckets; i++) {
			lck_mtx_destroy(&h->_buckets[i]._lock, &cht_lock_group);
		}
		sk_free_type_array(struct _bucket, h->_n_buckets, h->_buckets);
	}
	sk_free_type(struct cuckoo_hashtable, h);
}

size_t
cuckoo_hashtable_entries(struct cuckoo_hashtable *h)
{
	return h->_n_entries;
}

size_t
cuckoo_hashtable_capacity(struct cuckoo_hashtable *h)
{
	return h->_n_buckets * _CHT_BUCKET_SLOTS;
}

size_t
cuckoo_hashtable_memory_footprint(struct cuckoo_hashtable *h)
{
	size_t total_meminuse = sizeof(struct cuckoo_hashtable) +
	    (h->_n_buckets * sizeof(struct _bucket));
	return total_meminuse;
}

static inline struct cuckoo_node *
__find_in_bucket(struct cuckoo_hashtable *h, struct _bucket *b, void *key,
    uint32_t hash)
{
	uint32_t i;
	struct cuckoo_node *node = NULL;

	__lock_bucket(b);
	if (b->_inuse == 0) {
		goto done;
	}
	for (i = 0; i < _CHT_BUCKET_SLOTS; i++) {
		if (b->_slots[i]._hash == hash) {
			node = b->_slots[i]._node;
			while (node != NULL) {
				if (h->_obj_cmp(node, key) == 0) {
					h->_obj_retain(node);
					goto done;
				}
				node = cuckoo_node_next(node);
			}
		}
	}

done:
	__unlock_bucket(b);
	return node;
}

/* will return node retained */
struct cuckoo_node *
cuckoo_hashtable_find_with_hash(struct cuckoo_hashtable *h, void *key,
    uint32_t hash)
{
	struct _bucket *b1, *b2;
	struct cuckoo_node *node = NULL;

	__rlock_table(h);

	b1 = __prim_bucket(h, hash);
	if ((node = __find_in_bucket(h, b1, key, hash)) != NULL) {
		goto done;
	}

	b2 = __alt_bucket(h, hash);
	if ((node = __find_in_bucket(h, b2, key, hash)) != NULL) {
		goto done;
	}

done:
	__unrlock_table(h);
	return node;
}

/*
 * To add a key into cuckoo_hashtable:
 *   1. First it searches the key's two candidate buckets b1, b2
 *   2. If there are slots available in b1 or b2, we place the key there
 *   3. Otherwise cuckoo_hashtable will have to probe and make space
 *
 * To move keys around (open addressing hash table), cuckoo_hashtable needs to
 * first find available slot via Cuckoo search. Here it uses bread-first-search
 * to find the shorted path towards an empty bucket slot.
 *
 */
static inline int
__add_to_bucket(struct cuckoo_hashtable *h, struct _bucket *b,
    struct cuckoo_node *node, uint32_t hash)
{
	int ret = -1;
	uint8_t avail_i = _CHT_SLOT_INVAL;

	__lock_bucket(b);
	if (b->_inuse == _CHT_BUCKET_SLOTS) {
		goto done;
	}
	for (uint8_t i = 0; i < _CHT_BUCKET_SLOTS; i++) {
		struct _slot *s = __bucket_slot(b, i);
		if (__slot_empty(s)) {
			if (avail_i == _CHT_SLOT_INVAL) {
				avail_i = i;
			}
		} else {
			/* chain to existing slot with same hash */
			if (__improbable(s->_hash == hash)) {
				ASSERT(s->_node != NULL);
				ret = cuckoo_node_chain(s->_node, node);
				if (ret != 0) {
					goto done;
				}
				cht_debug("hash %x node %p inserted [%zu][%d]",
				    hash, node, __bucket_idx(h, b), i);
				OSAddAtomic(1, &h->_n_entries);
				h->_obj_retain(node);
				goto done;
			}
		}
	}
	if (avail_i != _CHT_SLOT_INVAL) {
		h->_obj_retain(node);
		b->_slots[avail_i]._hash = hash;
		b->_slots[avail_i]._node = node;
		b->_inuse++;
		cht_debug("hash %x node %p inserted [%zu][%d]", hash, node,
		    __bucket_idx(h, b), avail_i);
		OSAddAtomic(1, &h->_n_entries);
		ret = 0;
	}
done:
	__unlock_bucket(b);
	return ret;
}

#define _CHT_BFS_QUEUE_LEN      UINT8_MAX
#define _CHT_BFS_QUEUE_END      (_CHT_BFS_QUEUE_LEN - _CHT_BUCKET_SLOTS)

struct _bfs_node {
	uint32_t        bkt_idx;
	uint8_t         prev_node_idx;
	uint8_t         prev_slot_idx;
};

/*
 * Move slots backwards on cuckoo path
 *
 * cuckoo_move would hold at most 2 locks at any time, moving from
 * the end of cuckoo path toward the bucket where new keys should be
 * stored. There could be chances of dead lock in case of multiple
 * writers have overlapping cuckoo path. We could arrange the order of
 * locking to avoid that but then we have to take all locks upfront,
 * which is not friendly to concurrent readers. So instead, we try to
 * take one by one(but still at most 2 locks holding at any time),
 * with backoff in mind.
 */
static int
cuckoo_move(struct cuckoo_hashtable *h, struct cuckoo_node *node,
    uint32_t hash, struct _bfs_node *queue, uint8_t leaf_node_idx,
    uint8_t leaf_slot)
{
	struct _bfs_node *prev_node, *curr_node;
	struct _bucket *from_bkt, *to_bkt, *alt_bkt;
	uint8_t from_slot, to_slot;

	curr_node = &queue[leaf_node_idx];
	to_bkt = __get_bucket(h, curr_node->bkt_idx);
	to_slot = leaf_slot;

	__lock_bucket(to_bkt);

	while (__probable(curr_node->prev_node_idx != _CHT_BFS_QUEUE_LEN)) {
		prev_node = &queue[curr_node->prev_node_idx];
		from_bkt = __get_bucket(h, prev_node->bkt_idx);
		from_slot = curr_node->prev_slot_idx;

		if (!__lock_bucket_with_backoff(from_bkt)) {
			/* a dead lock or a sleeping-thread holding the lock */
			__unlock_bucket(to_bkt);
			cht_warn("cuckoo move deadlock detected");
			return EINVAL;
		}

		/*
		 * Verify cuckoo path by checking:
		 * 1. from_bkt[from_slot]'s alternative bucket is still to_bkt
		 * 3. to_bkt[to_slot] is still vacant
		 */
		alt_bkt = __alt_bucket(h, from_bkt->_slots[from_slot]._hash);
		if (alt_bkt != to_bkt ||
		    !__slot_empty(__bucket_slot(to_bkt, to_slot))) {
			__unlock_bucket(from_bkt);
			__unlock_bucket(to_bkt);
			cht_warn("cuckoo move path invalid: %s %s",
			    alt_bkt != to_bkt ? "alt_bkt != to_bkt" : "",
			    !__slot_empty(__bucket_slot(to_bkt, to_slot)) ?
			    "!slot_empty(to_bkt, to_slot)" : "");
			return EINVAL;
		}

		cht_log(CHTV_DEBUG, "Move [0x%llx][%d] to [0x%llx][%d]",
		    from_bkt - h->_buckets, from_slot, to_bkt - h->_buckets,
		    to_slot);

		ASSERT(to_bkt->_slots[to_slot]._node == NULL);
		ASSERT(to_bkt->_slots[to_slot]._hash == 0);

		/* move entry backward */
		to_bkt->_slots[to_slot] = from_bkt->_slots[from_slot];
		to_bkt->_inuse++;
		__slot_reset(&from_bkt->_slots[from_slot]);
		from_bkt->_inuse--;

		__unlock_bucket(to_bkt);

		curr_node = prev_node;
		to_bkt = from_bkt;
		to_slot = from_slot;
	}

	ASSERT(curr_node->prev_node_idx == _CHT_BFS_QUEUE_LEN);
	ASSERT(curr_node->prev_slot_idx == _CHT_SLOT_INVAL);

	/* if root slot is no longer valid */
	if (to_bkt->_slots[to_slot]._node != NULL) {
		__unlock_bucket(to_bkt);
		return EINVAL;
	}

	to_bkt->_inuse++;
	__slot_set(&to_bkt->_slots[to_slot], hash, node);
	h->_obj_retain(node);
	__unlock_bucket(to_bkt);

	OSAddAtomic(1, &h->_n_entries);

	cht_debug("hash %x node %p inserted at [%zu][%d]", hash, node,
	    __bucket_idx(h, to_bkt), to_slot);

	return 0;
}

static int
cuckoo_probe(struct cuckoo_hashtable *h, struct cuckoo_node *node,
    uint32_t hash)
{
	struct _bfs_node queue[_CHT_BFS_QUEUE_LEN];
	uint8_t head, tail;
	struct _bucket *b;
	uint8_t avail_i;
	int ret = ENOMEM;

	/* probe starts from its primary bucket */
	queue[0].bkt_idx = hash & h->_bitmask;
	queue[0].prev_node_idx = _CHT_BFS_QUEUE_LEN;
	queue[0].prev_slot_idx = _CHT_SLOT_INVAL;

	head = 0;
	tail = 1;

	while (__probable(tail != head && tail < _CHT_BFS_QUEUE_END)) {
		b = __get_bucket(h, queue[head].bkt_idx);
		avail_i = _CHT_SLOT_INVAL;
		for (uint8_t i = 0; i < _CHT_BUCKET_SLOTS; i++) {
			struct _slot *s = __bucket_slot(b, i);
			if (__slot_empty(s)) {
				if (avail_i == _CHT_SLOT_INVAL) {
					avail_i = i;
				}
				continue;
			}

			/*
			 * Another node with same hash could have been probed
			 * into this bucket, chain to it.
			 */
			if (__improbable(s->_hash == hash)) {
				ASSERT(s->_node != NULL);
				ret = cuckoo_node_chain(s->_node, node);
				if (ret != 0) {
					goto done;
				}
				cht_debug("hash %x node %p inserted [%zu][%d]",
				    hash, node, __bucket_idx(h, b), i);
				OSAddAtomic(1, &h->_n_entries);
				h->_obj_retain(node);
				goto done;
			}

			queue[tail].bkt_idx = __alt_hash(s->_hash) & h->_bitmask;
			queue[tail].prev_node_idx = head;
			queue[tail].prev_slot_idx = i;
			tail++;
		}

		if (avail_i != _CHT_SLOT_INVAL) {
			ret = cuckoo_move(h, node, hash, queue, head, avail_i);
			if (ret == 0) {
				goto done;
			} else if (ret == EINVAL) {
				cht_warn("cukoo path invalidated");
				goto skip;
			} else {
				cht_err("faild: unknown err %d", ret);
				goto done;
			}
		}
skip:
		head++;
	}

	if (tail == head || tail >= _CHT_BFS_QUEUE_END) {
		cht_warn("failed: cuckoo probe out of search space "
		    "head %d tail %d (%d/%d, load factor %d%%)", head, tail,
		    h->_n_entries, h->_capacity,
		    cuckoo_hashtable_load_factor(h));
		ret = ENOSPC;
	} else {
		cht_warn("failed: cuckoo probe path invalidated "
		    " (%d/%d, load factor %d%%)", h->_n_entries, h->_capacity,
		    cuckoo_hashtable_load_factor(h));
		ret = EAGAIN;
	}
done:
	return ret;
}

static inline void
__foreach_node(struct cuckoo_hashtable *h, bool wlocked,
    void (^node_handler)(struct cuckoo_node *, uint32_t hash))
{
	if (!wlocked) {
		__rlock_table(h);
	}
	for (uint32_t i = 0; i < h->_n_buckets; i++) {
		struct _bucket *b = &h->_buckets[i];
		if (b->_inuse == 0) {
			continue;
		}
		if (!wlocked) {
			__lock_bucket(b);
		}
		for (uint32_t j = 0; j < _CHT_BUCKET_SLOTS; j++) {
			struct _slot *s = __bucket_slot(b, j);
			struct cuckoo_node *node = NULL, *next_node = NULL;
			node = s->_node;
			while (node != NULL) {
				next_node = cuckoo_node_next(node);
				node_handler(node, s->_hash);
				node = next_node;
			}
		}
		if (!wlocked) {
			__unlock_bucket(b);
		}
	}
	if (!wlocked) {
		__unrlock_table(h);
	}
}

void
cuckoo_hashtable_foreach(struct cuckoo_hashtable *h,
    void (^node_handler)(struct cuckoo_node *, uint32_t hash))
{
	__foreach_node(h, false, node_handler);
}

static void
cuckoo_dummy_retain(struct cuckoo_node *node)
{
#pragma unused(node)
}

static void
cuckoo_dummy_release(struct cuckoo_node *node)
{
#pragma unused(node)
}

static int
cuckoo_resize(struct cuckoo_hashtable *h, enum cuckoo_resize_ops option)
{
	int ret = 0;

	/* backoff from concurrent expansion */
	do {
		ret = __resize_begin(h);
		if (ret == EAGAIN) {
			cht_info("resize done by peer");
			return EAGAIN;
		}
	} while (ret == EINTR);

	uint32_t curr_capacity = h->_n_buckets * _CHT_BUCKET_SLOTS;
	uint32_t curr_load = (100 * h->_n_entries) / curr_capacity;
	uint32_t curr_buckets = h->_n_buckets;
	uint32_t new_capacity;
	__block size_t add_called = 0;

	/* check load factor to ensure we are not hitting something else */
	if (option == _CHT_RESIZE_EXPAND) {
		if (curr_load < _CHT_MIN_LOAD_EXPAND) {
			cht_warn("Warning: early expand at %f load", curr_load);
		}
		new_capacity = curr_capacity * 2;
	} else {
		if (curr_load > _CHT_MAX_LOAD_SHRINK ||
		    curr_capacity == h->_rcapacity) {
			goto done;
		}
		new_capacity = curr_capacity / 2;
	}

	cht_info("resize %d/(%d -> %d)", h->_n_entries,
	    curr_capacity, new_capacity);

	struct cuckoo_hashtable_params new_p = {
		.cht_capacity = new_capacity,
		.cht_obj_cmp = h->_obj_cmp,
		.cht_obj_retain = cuckoo_dummy_retain,
		.cht_obj_release = cuckoo_dummy_release,
	};
	struct cuckoo_hashtable *tmp_h;
	tmp_h = cuckoo_hashtable_create(&new_p);
	if (tmp_h == NULL) {
		ret = ENOMEM;
		goto done;
	}

	__foreach_node(h, true, ^(struct cuckoo_node *node, uint32_t hash) {
		int error = 0;
		cuckoo_node_set_next(node, NULL);
		error = cuckoo_hashtable_add_with_hash(tmp_h, node, hash);
		ASSERT(error == 0);
		add_called++;
	});

	if (__improbable(cuckoo_hashtable_entries(h) !=
	    cuckoo_hashtable_entries(tmp_h))) {
		panic("h %zu add_called %zu tmp_h %zu",
		    cuckoo_hashtable_entries(h), add_called,
		    cuckoo_hashtable_entries(tmp_h));
	}

	for (uint32_t i = 0; i < h->_n_buckets; i++) {
		lck_mtx_destroy(&h->_buckets[i]._lock, &cht_lock_group);
	}
	h->_n_buckets = tmp_h->_n_buckets;
	h->_capacity = h->_n_buckets * _CHT_BUCKET_SLOTS;
	h->_bitmask = tmp_h->_bitmask;
	sk_free_type_array(struct _bucket, curr_buckets, h->_buckets);

	h->_buckets = tmp_h->_buckets;
	lck_rw_destroy(&tmp_h->_resize_lock, &cht_lock_group);
	lck_mtx_destroy(&tmp_h->_lock, &cht_lock_group);
	sk_free_type(struct cuckoo_hashtable, tmp_h);

done:
	__resize_end(h);

	return ret;
}

static inline int
cuckoo_add_no_expand(struct cuckoo_hashtable *h,
    struct cuckoo_node *node, uint32_t hash)
{
	struct _bucket *b1, *b2;
	int ret = -1;

	__rlock_table(h);

	b1 = __prim_bucket(h, hash);
	if ((ret = __add_to_bucket(h, b1, node, hash)) == 0) {
		goto done;
	}

	b2 = __alt_bucket(h, hash);
	if ((ret = __add_to_bucket(h, b2, node, hash)) == 0) {
		goto done;
	}

	ret = cuckoo_probe(h, node, hash);
done:
	__unrlock_table(h);
	return ret;
}

int
cuckoo_hashtable_add_with_hash(struct cuckoo_hashtable *h,
    struct cuckoo_node *node, uint32_t hash)
{
	int ret;

	/* neutralize node to avoid non-terminating tail */
	ASSERT(cuckoo_node_next(node) == NULL);

	ret = cuckoo_add_no_expand(h, node, hash);
	if (ret == ENOSPC) {
		do {
			ret = cuckoo_resize(h, _CHT_RESIZE_EXPAND);
			if (ret != 0 && ret != EAGAIN) {
				break;
			}
			// this could still fail, when other threads added
			// enough objs that another resize is needed
			ret = cuckoo_add_no_expand(h, node, hash);
		} while (ret == ENOSPC);
	}

	return ret;
}

static inline int
__del_from_bucket(struct cuckoo_hashtable *h, struct _bucket *b,
    struct cuckoo_node *node, uint32_t hash)
{
	uint32_t i;

	__lock_bucket(b);
	for (i = 0; i < _CHT_BUCKET_SLOTS; i++) {
		if (b->_slots[i]._hash == hash) {
			if (cuckoo_node_del(&b->_slots[i]._node, node)) {
				h->_obj_release(node);
				OSAddAtomic(-1, &h->_n_entries);
				if (__slot_empty(__bucket_slot(b, i))) {
					b->_slots[i]._hash = 0;
					b->_inuse--;
				}
				__unlock_bucket(b);
				return 0;
			}
		}
	}
	__unlock_bucket(b);
	return ENOENT;
}

int
cuckoo_hashtable_del(struct cuckoo_hashtable *h,
    struct cuckoo_node *node, uint32_t hash)
{
	struct _bucket *b1, *b2;
	int ret = -1;

	__rlock_table(h);

	b1 = __prim_bucket(h, hash);
	if ((ret = __del_from_bucket(h, b1, node, hash)) == 0) {
		goto done;
	}

	b2 = __alt_bucket(h, hash);
	if ((ret = __del_from_bucket(h, b2, node, hash)) == 0) {
		goto done;
	}

done:
	if (ret == 0) {
		cuckoo_node_set_next(node, NULL);
	}
	__unrlock_table(h);
	return ret;
}

void
cuckoo_hashtable_try_shrink(struct cuckoo_hashtable *h)
{
	cuckoo_resize(h, _CHT_RESIZE_SHRINK);
}

#if (DEVELOPMENT || DEBUG)

static inline bool
cuckoo_node_looped(struct cuckoo_node *node)
{
	struct cuckoo_node *runner = node;

	if (node == NULL) {
		return false;
	}

	while (runner->next && runner->next->next) {
		runner = runner->next->next;
		node = node->next;

		if (runner == node) {
			return true;
		}
	}
	return false;
}

int
cuckoo_hashtable_health_check(struct cuckoo_hashtable *h)
{
	uint32_t hash;
	uint32_t i, j;
	struct _bucket *b;
	struct cuckoo_node *node;
	bool healthy = true;
	uint32_t seen = 0;

	__wlock_table(h);

	for (i = 0; i < h->_n_buckets; i++) {
		b = &h->_buckets[i];
		uint8_t inuse = 0;
		for (j = 0; j < _CHT_BUCKET_SLOTS; j++) {
			hash = b->_slots[j]._hash;
			node = b->_slots[j]._node;
			if (node != NULL) {
				inuse++;
			}
			while (node != NULL) {
				seen++;
				if ((__prim_bucket(h, hash) != b) &&
				    (__alt_bucket(h, hash) != b)) {
					panic("[%d][%d] stray hash %x node %p",
					    i, j, hash, node);
					healthy = false;
				}

				if (cuckoo_node_looped(node)) {
					panic("[%d][%d] looped hash %x node %p",
					    i, j, hash, node);
					healthy = false;
				}
				node = cuckoo_node_next(node);
			}
		}
		ASSERT(inuse == b->_inuse);
	}

	if (seen != h->_n_entries) {
		panic("seen %d != n_entries %d", seen, h->_n_entries);
	}

	__unwlock_table(h);

	if (!healthy) {
		cht_err("table unhealthy");
		return -1;
	} else {
		return 0;
	}
}

void
cuckoo_hashtable_dump(struct cuckoo_hashtable *h)
{
	uint32_t hash;
	struct cuckoo_node *node;
	uint32_t i, j;
	struct _bucket *b;

	cuckoo_hashtable_health_check(h);

	for (i = 0; i < h->_n_buckets; i++) {
		printf("%d\t", i);
		b = &h->_buckets[i];
		for (j = 0; j < _CHT_BUCKET_SLOTS; j++) {
			hash = b->_slots[j]._hash;
			node = b->_slots[j]._node;
			printf("0x%08x(%p) ", hash, node);
		}
		printf("\n");
	}
}
#endif /* !DEVELOPMENT && !DEBUG */
