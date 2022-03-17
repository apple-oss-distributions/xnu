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

#if (DEVELOPMENT || DEBUG)

#pragma clang optimize off

#include <libkern/OSAtomic.h>
#include <os/refcnt.h>
#include <skywalk/os_skywalk_private.h>
#include <skywalk/lib/cuckoo_hashtable.h>

#define CUCKOO_TEST_TAG "com.apple.skywalk.libcuckoo.test"
kern_allocation_name_t cuckoo_test_tag;

os_refgrp_decl(static, cht_obj_refgrp, "CuckooTestRefGroup", NULL);

static void cuckoo_test_start(void *, wait_result_t);
static void cuckoo_test_stop(void *, wait_result_t);

extern unsigned int ml_wait_max_cpus(void);

// threading related
static int cht_inited = 0;
static int cht_enabled;
static int cht_busy;

decl_lck_mtx_data(static, cht_lock);

static struct cuckoo_hashtable *h = NULL;

struct cht_thread_conf {
	thread_t        ctc_thread;     /* thread instance */
	uint32_t        ctc_nthreads;   /* number of threads */
	uint32_t        ctc_id;         /* thread id */
} __attribute__((aligned(CHANNEL_CACHE_ALIGN_MAX)));

static struct cht_thread_conf *chth_confs;
static uint32_t chth_nthreads;
static uint32_t chth_cnt;
static boolean_t chth_run;

enum {
	COS_NOT_ADDED = 0,      /* no inserted, available for insertion */
	COS_BUSY = -1,          /* being inserted/deleted */
	COS_ADDED = 1,          /* inserted, available for deletion  */
} co_state_t;

// Cuckoo hashtable key object

struct cht_obj {
	struct cuckoo_node      co_cnode;       // cuckoo node
	int64_t                 co_key;         // unique key
	uint32_t                co_hash;        // dummy hash value (not collision-free)
	os_refcnt_t             co_refcnt;      // reference count
	volatile int32_t        co_state;       // co_state_t
	uint32_t                co_seen;        // number of times seen
};

#if PLATFORM_WatchOS
static const uint32_t CHT_OBJ_MAX = 16 * 1024;
#else /* PLATFORM_WatchOS */
static const uint32_t CHT_OBJ_MAX = 512 * 1024;
#endif /* !PLATFORM_WatchOS */
static struct cht_obj *cht_objs;

static int
cht_obj_cmp__(struct cuckoo_node *node, void *key)
{
	struct cht_obj *co = container_of(node, struct cht_obj, co_cnode);
	int64_t key1 = *(int64_t *)key;

	if (co->co_key < key1) {
		return -1;
	} else if (co->co_key > key1) {
		return 1;
	}

	return 0;
}

static void
cht_obj_retain(struct cht_obj *co)
{
	(void)os_ref_retain(&co->co_refcnt);
}

static void
cht_obj_retain__(struct cuckoo_node *node)
{
	struct cht_obj *co = container_of(node, struct cht_obj, co_cnode);
	return cht_obj_retain(co);
}

static void
cht_obj_release(struct cht_obj *co)
{
	(void)os_ref_release(&co->co_refcnt);
}

static void
cht_obj_release__(struct cuckoo_node *node)
{
	struct cht_obj *co = container_of(node, struct cht_obj, co_cnode);
	cht_obj_release(co);
}

static int
cht_obj_refcnt(struct cht_obj *co)
{
	return os_ref_get_count(&co->co_refcnt);
}

static struct cuckoo_hashtable_params params_template = {
	.cht_capacity = 1024,
	.cht_obj_cmp = cht_obj_cmp__,
	.cht_obj_retain = cht_obj_retain__,
	.cht_obj_release = cht_obj_release__,
};

void
cht_test_init(void)
{
	if (OSCompareAndSwap(0, 1, &cht_inited)) {
		lck_mtx_init(&cht_lock, &sk_lock_group, &sk_lock_attr);

		ASSERT(cuckoo_test_tag == NULL);
		cuckoo_test_tag = kern_allocation_name_allocate(CUCKOO_TEST_TAG, 0);
		ASSERT(cuckoo_test_tag != NULL);
	}
}

void
cht_test_fini(void)
{
	lck_mtx_destroy(&cht_lock, &sk_lock_group);
}

static void
cht_obj_init()
{
	// init testing objects
	cht_objs = sk_alloc_type_array(struct cht_obj, CHT_OBJ_MAX,
	    Z_WAITOK, cuckoo_test_tag);
	VERIFY(cht_objs != NULL);

	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		cht_objs[i].co_key = i;
		do {
			read_random(&cht_objs[i].co_hash, sizeof(cht_objs[i].co_hash));
		} while (cht_objs[i].co_hash == 0);
		os_ref_init(&cht_objs[i].co_refcnt, &cht_obj_refgrp);
		cht_objs[i].co_state = COS_NOT_ADDED;
	}
}

static void
cht_obj_fini()
{
	VERIFY(cht_objs != NULL);
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		ASSERT(os_ref_release(&cht_objs[i].co_refcnt) == 0);
		cht_objs[i].co_state = COS_NOT_ADDED;
		cht_objs[i].co_seen = 0;
	}
	// init testing objects
	sk_free_type_array(struct cht_obj, CHT_OBJ_MAX, cht_objs);
}

static void
cht_basic_tests(void)
{
	SK_ERR("start");

	// Cuckoo hashtable creation
	h = cuckoo_hashtable_create(&params_template);

	// basic add/del
	struct cht_obj co1 = {
		.co_cnode = {NULL},
		.co_key = -1,
		.co_hash = 1,
		.co_state = COS_NOT_ADDED,
		.co_seen = 0
	};
	struct cht_obj co2 = {
		.co_cnode = {NULL},
		.co_key = -2,
		.co_hash = 1,
		.co_state = COS_NOT_ADDED,
		.co_seen = 0
	};
	os_ref_init(&co1.co_refcnt, &cht_obj_refgrp);
	os_ref_init(&co2.co_refcnt, &cht_obj_refgrp);

	struct cuckoo_node *node = NULL;
	__block struct cht_obj *co = NULL;
	int error = 0;

	// add objs with duplicate hash
	error = cuckoo_hashtable_add_with_hash(h, &co1.co_cnode, co1.co_hash);
	ASSERT(error == 0);

	error = cuckoo_hashtable_add_with_hash(h, &co2.co_cnode, co2.co_hash);
	ASSERT(error == 0);

	ASSERT(cuckoo_hashtable_entries(h) == 2);

	node = cuckoo_hashtable_find_with_hash(h, &co1.co_key, co1.co_hash);
	ASSERT(node != NULL);
	ASSERT(node == &co1.co_cnode);

	node = cuckoo_hashtable_find_with_hash(h, &co2.co_key, co2.co_hash);
	ASSERT(node != NULL);
	ASSERT(node == &co2.co_cnode);

	cuckoo_hashtable_del(h, &co1.co_cnode, co1.co_hash);

	node = cuckoo_hashtable_find_with_hash(h, &co1.co_key, co1.co_hash);
	ASSERT(node == NULL);

	node = cuckoo_hashtable_find_with_hash(h, &co2.co_key, co2.co_hash);
	ASSERT(node != NULL);
	ASSERT(node == &co2.co_cnode);

	cuckoo_hashtable_del(h, &co2.co_cnode, co2.co_hash);
	node = cuckoo_hashtable_find_with_hash(h, &co2.co_key, co2.co_hash);
	ASSERT(node == NULL);

	ASSERT(cuckoo_hashtable_entries(h) == 0);

	// add all objs
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		error = cuckoo_hashtable_add_with_hash(h, &co->co_cnode, co->co_hash);
		ASSERT(error == 0);
		ASSERT(cuckoo_hashtable_entries(h) == i + 1);
		co->co_state = COS_ADDED;
	}

	// find all objs
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		ASSERT(co->co_state = COS_ADDED);
		node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(node != NULL);
		ASSERT(node == &co->co_cnode);
		ASSERT(cht_obj_refcnt(co) == 3);
		cht_obj_release(co);
	}

	// walk all objs
	cuckoo_hashtable_foreach(h, ^(struct cuckoo_node *curr_node, uint32_t curr_hash) {
		co = container_of(curr_node, struct cht_obj, co_cnode);
		ASSERT(co->co_hash == curr_hash);
		ASSERT(cht_obj_refcnt(co) == 2);
		co->co_seen++;
	});

	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		ASSERT(co->co_seen == 1);
	}

	size_t memory_use_before_shrink = cuckoo_hashtable_memory_footprint(h);

	// del all objs
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		ASSERT(co->co_state = COS_ADDED);
		node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(cht_obj_refcnt(co) == 3);
		cuckoo_hashtable_del(h, &co->co_cnode, co->co_hash);
		cht_obj_release(co);
		ASSERT(cht_obj_refcnt(co) == 1);
		ASSERT(cuckoo_hashtable_entries(h) == CHT_OBJ_MAX - i - 1);
		co->co_seen = 0;
	}

	// shrink
	cuckoo_hashtable_try_shrink(h);

	ASSERT(cuckoo_hashtable_memory_footprint(h) < memory_use_before_shrink);

	// self healthy check
	cuckoo_hashtable_health_check(h);

	cuckoo_hashtable_free(h);

	SK_ERR("done");
}

static void
cht_concurrent_ops_begin()
{
	/* let skmem_test_start() know we're ready */
	lck_mtx_lock(&cht_lock);
	atomic_add_32(&chth_cnt, 1);
	wakeup((caddr_t)&chth_cnt);

	do {
		(void) msleep(&chth_run, &cht_lock, (PZERO - 1),
		    "chthfuncw", NULL);
	} while (!chth_run);
	lck_mtx_unlock(&cht_lock);
}

static void
cht_concurrent_ops_done()
{
	/* let skmem_test_start() know we're finished */
	lck_mtx_lock(&cht_lock);
	VERIFY(atomic_add_32_ov(&chth_cnt, -1) != 0);
	wakeup((caddr_t)&chth_cnt);
	lck_mtx_unlock(&cht_lock);
}

static void
cht_concurrent_add_init(void)
{
	h = cuckoo_hashtable_create(&params_template);
}

static void
cht_concurrent_add(void *v, wait_result_t w)
{
#pragma unused(v, w)
	cht_concurrent_ops_begin();

	struct cht_thread_conf *conf = v;
	uint32_t objs_per_cpu = CHT_OBJ_MAX / conf->ctc_nthreads;
	uint32_t objs_start_idx = objs_per_cpu * conf->ctc_id;
	uint32_t objs_to_add = objs_per_cpu;

	// last thread id add any tailing objs
	if (conf->ctc_id == conf->ctc_nthreads - 1) {
		objs_to_add += (CHT_OBJ_MAX % conf->ctc_nthreads);
	}

	for (uint32_t i = 0; i < objs_to_add; i++) {
		struct cht_obj *co = &cht_objs[objs_start_idx + i];
		int error = cuckoo_hashtable_add_with_hash(h, &co->co_cnode, co->co_hash);
		ASSERT(error == 0);
		co->co_state = COS_ADDED;

		struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(node != NULL);
		ASSERT(node == &co->co_cnode);
		cht_obj_release(co);
	}

	cht_concurrent_ops_done();
}

static void
cht_concurrent_add_check()
{
	__block struct cht_obj *co = NULL;
	struct cuckoo_node *node = NULL;

	// find all objs
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		ASSERT(co->co_state = COS_ADDED);
		node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(node != NULL);
		ASSERT(node == &co->co_cnode);
		ASSERT(cht_obj_refcnt(co) == 3);
		cht_obj_release(co);
	}

	// walk all objs
	cuckoo_hashtable_foreach(h, ^(struct cuckoo_node *curr_node, uint32_t curr_hash) {
		co = container_of(curr_node, struct cht_obj, co_cnode);
		ASSERT(co->co_hash == curr_hash);
		ASSERT(cht_obj_refcnt(co) == 2);
		co->co_seen++;
	});

	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		//ASSERT(co->co_seen == 1);
	}
}

static void
cht_concurrent_add_fini(void)
{
	struct cht_obj *co = NULL;
	struct cuckoo_node *node = NULL;

	// del all objs
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		co = &cht_objs[i];
		ASSERT(co->co_state = COS_ADDED);
		node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(cht_obj_refcnt(co) == 3);
		cuckoo_hashtable_del(h, &co->co_cnode, co->co_hash);
		cht_obj_release(co);
		ASSERT(cht_obj_refcnt(co) == 1);
		ASSERT(cuckoo_hashtable_entries(h) == CHT_OBJ_MAX - i - 1);
	}

	cuckoo_hashtable_free(h);
}


static void
cht_concurrent_del_init(void)
{
	h = cuckoo_hashtable_create(&params_template);

	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		struct cht_obj *co = &cht_objs[i];
		int error = cuckoo_hashtable_add_with_hash(h, &co->co_cnode, co->co_hash);
		ASSERT(error == 0);
		ASSERT(cuckoo_hashtable_entries(h) == i + 1);
		co->co_state = COS_ADDED;
	}
}

static void
cht_concurrent_del(void *v, wait_result_t w)
{
#pragma unused(v, w)
	cht_concurrent_ops_begin();

	struct cht_thread_conf *conf = v;
	uint32_t objs_per_cpu = CHT_OBJ_MAX / conf->ctc_nthreads;
	uint32_t objs_start_idx = objs_per_cpu * conf->ctc_id;
	uint32_t objs_to_del = objs_per_cpu;

	// last thread id add any tailing objs
	if (conf->ctc_id == conf->ctc_nthreads - 1) {
		objs_to_del += (CHT_OBJ_MAX % conf->ctc_nthreads);
	}

	for (uint32_t i = 0; i < objs_to_del; i++) {
		struct cht_obj *co = &cht_objs[objs_start_idx + i];
		int error = cuckoo_hashtable_del(h, &co->co_cnode, co->co_hash);
		ASSERT(error == 0);
		co->co_state = COS_NOT_ADDED;

		struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(node == NULL);
		ASSERT(cht_obj_refcnt(co) == 1);
	}

	cht_concurrent_ops_done();
}

static void
cht_concurrent_del_check()
{
	ASSERT(cuckoo_hashtable_entries(h) == 0);

	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		struct cht_obj *co = &cht_objs[i];
		struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
		ASSERT(node == NULL);
		ASSERT(cht_obj_refcnt(co) == 1);
	}
}

static void
cht_concurrent_del_fini(void)
{
	cuckoo_hashtable_free(h);
}

static void
cht_concurrent_duo_init(void)
{
	struct cuckoo_hashtable_params p = params_template;
	p.cht_capacity = CHT_OBJ_MAX / 2;
	h = cuckoo_hashtable_create(&p);

	// populate 1/3 of the objects
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i += 3) {
		struct cht_obj *co = &cht_objs[i];
		int error = cuckoo_hashtable_add_with_hash(h, &co->co_cnode, co->co_hash);
		ASSERT(error == 0);
		co->co_state = COS_ADDED;
	}
}

static void
cht_concurrent_duo(void *v, wait_result_t w)
{
#pragma unused(v, w)
#define DUO_ITERATIONS (2 * CHT_OBJ_MAX)

#define DUO_OPS_MASK   0x0000000f
#define DUO_OPS_ADD    0x9

#define DUO_IDX_MASK   0xfffffff0
#define DUO_IDX_SHIFT  0x8

	cht_concurrent_ops_begin();

	uint32_t *rands;
	rands = sk_alloc_data(sizeof(uint32_t) * DUO_ITERATIONS, Z_WAITOK, cuckoo_test_tag);
	VERIFY(rands != NULL);
	read_random(rands, sizeof(uint32_t) * DUO_ITERATIONS);

	for (uint32_t i = 0; i < DUO_ITERATIONS; i++) {
		uint32_t rand, ops, idx;
		rand = rands[i];
		ops = rand & DUO_OPS_MASK;
		idx = (rand >> DUO_IDX_SHIFT) % CHT_OBJ_MAX;

		// choose an ops (add, del, shrink)
		if (ops < DUO_OPS_ADD) {
			struct cht_obj *co = &cht_objs[idx];
			if (atomic_test_set_32(&co->co_state, COS_NOT_ADDED, COS_BUSY)) {
				struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
				ASSERT(node == NULL);
				int error = cuckoo_hashtable_add_with_hash(h, &co->co_cnode, co->co_hash);
				ASSERT(error == 0);
				ASSERT(cht_obj_refcnt(co) == 2);

				co->co_state = COS_ADDED;
			}
		} else {
			struct cht_obj *co = &cht_objs[idx];
			if (atomic_test_set_32(&co->co_state, COS_ADDED, COS_BUSY)) {
				struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
				ASSERT(node != NULL);
				ASSERT(node == &co->co_cnode);
				int error = cuckoo_hashtable_del(h, &co->co_cnode, co->co_hash);
				ASSERT(error == 0);
				ASSERT(cht_obj_refcnt(co) == 2);
				cht_obj_release(co);

				co->co_state = COS_NOT_ADDED;
			}
		}
	}

	sk_free_data(rands, sizeof(uint32_t) * DUO_ITERATIONS);
	cht_concurrent_ops_done();
}

static void
cht_concurrent_duo_check()
{
	size_t added = 0;
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		struct cht_obj *co = &cht_objs[i];
		if (co->co_state == COS_ADDED) {
			struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
			ASSERT(node != NULL);
			ASSERT(node == &co->co_cnode);
			added++;
			cht_obj_release(co);
		} else {
			struct cuckoo_node *node = cuckoo_hashtable_find_with_hash(h, &co->co_key, co->co_hash);
			ASSERT(node == NULL);
		}
	}

	ASSERT(added == cuckoo_hashtable_entries(h));
}

static void
cht_concurrent_duo_fini(void)
{
	for (uint32_t i = 0; i < CHT_OBJ_MAX; i++) {
		struct cht_obj *co = &cht_objs[i];
		if (co->co_state == COS_ADDED) {
			int error = cuckoo_hashtable_del(h, &co->co_cnode, co->co_hash);
			ASSERT(error == 0);
		}
	}

	ASSERT(cuckoo_hashtable_entries(h) == 0);

	cuckoo_hashtable_free(h);
}

static void
cht_concurrent_tests(
	void (*cht_concurrent_init)(void),
	void (*cht_concurrent_ops)(void *v, wait_result_t w),
	void (*cht_concurrent_check)(void),
	void (*cht_concurrent_fini)(void))
{
	uint32_t nthreads = MAX(2, ml_wait_max_cpus() * 3 / 4);

	SK_ERR("start, nthreads %d", nthreads);

	cht_concurrent_init();

	// init multithread test config
	if (chth_confs == NULL) {
		chth_nthreads = nthreads;
		chth_confs = sk_alloc_type_array(struct cht_thread_conf, nthreads,
		    Z_WAITOK | Z_NOFAIL, cuckoo_test_tag);
	}

	for (uint32_t i = 0; i < nthreads; i++) {
		chth_confs[i].ctc_nthreads = nthreads;
		chth_confs[i].ctc_id = i;
		if (kernel_thread_start(cht_concurrent_ops, (void *)&chth_confs[i],
		    &chth_confs[i].ctc_thread) != KERN_SUCCESS) {
			panic("failed to create cuckoo test thread");
			__builtin_unreachable();
		}
	}

	// wait for threads to spwan
	lck_mtx_lock(&cht_lock);
	do {
		struct timespec ts = { 0, 100 * USEC_PER_SEC };
		(void) msleep(&chth_cnt, &cht_lock, (PZERO - 1),
		    "skmtstartw", &ts);
	} while (chth_cnt < nthreads);
	VERIFY(chth_cnt == nthreads);
	lck_mtx_unlock(&cht_lock);

	// signal threads to run
	lck_mtx_lock(&cht_lock);
	VERIFY(!chth_run);
	chth_run = TRUE;
	wakeup((caddr_t)&chth_run);
	lck_mtx_unlock(&cht_lock);

	// wait until all threads are done
	lck_mtx_lock(&cht_lock);
	do {
		struct timespec ts = { 0, 100 * USEC_PER_SEC };
		(void) msleep(&chth_cnt, &cht_lock, (PZERO - 1),
		    "skmtstopw", &ts);
	} while (chth_cnt != 0);
	chth_run = FALSE;
	lck_mtx_unlock(&cht_lock);

	// check results
	cht_concurrent_check();

	cht_concurrent_fini();

	SK_ERR("done");
}

static void
cuckoo_test_start(void *v, wait_result_t w)
{
#pragma unused(v, w)
	lck_mtx_lock(&cht_lock);
	VERIFY(!cht_busy);
	cht_busy = 1;
	lck_mtx_unlock(&cht_lock);

	cht_obj_init();

	cht_basic_tests();

	cht_concurrent_tests(cht_concurrent_add_init, cht_concurrent_add, cht_concurrent_add_check, cht_concurrent_add_fini);
	cht_concurrent_tests(cht_concurrent_del_init, cht_concurrent_del, cht_concurrent_del_check, cht_concurrent_del_fini);
	cht_concurrent_tests(cht_concurrent_duo_init, cht_concurrent_duo, cht_concurrent_duo_check, cht_concurrent_duo_fini);

	lck_mtx_lock(&cht_lock);
	cht_enabled = 1;
	wakeup((caddr_t)&cht_enabled);
	lck_mtx_unlock(&cht_lock);
}

static void
cuckoo_test_stop(void *v, wait_result_t w)
{
#pragma unused(v, w)

	if (chth_confs != NULL) {
		sk_free_type_array(struct cht_thread_conf, chth_nthreads, chth_confs);
		chth_confs = NULL;
		chth_nthreads = 0;
	}

	cht_obj_fini();

	lck_mtx_lock(&cht_lock);
	VERIFY(cht_busy);
	cht_busy = 0;
	cht_enabled = 0;
	wakeup((caddr_t)&cht_enabled);
	lck_mtx_unlock(&cht_lock);
}

static int
sysctl_cuckoo_test(__unused struct sysctl_oid *oidp,
    __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	int error, newvalue, changed;
	thread_t th;
	thread_continue_t func;

	lck_mtx_lock(&cht_lock);
	if ((error = sysctl_io_number(req, cht_enabled, sizeof(int),
	    &newvalue, &changed)) != 0) {
		SK_ERR("failed to get new sysctl value");
		goto done;
	}

	if (changed && cht_enabled != newvalue) {
		if (newvalue && cht_busy) {
			SK_ERR("previous cuckoo test instance is still active");
			error = EBUSY;
			goto done;
		}

		if (newvalue) {
			func = cuckoo_test_start;
		} else {
			func = cuckoo_test_stop;
		}

		if (kernel_thread_start(func, NULL, &th) != KERN_SUCCESS) {
			SK_ERR("failed to create cuckoo test action thread");
			error = EBUSY;
			goto done;
		}
		do {
			SK_ERR("waiting for %s to complete",
			    newvalue ? "startup" : "shutdown");
			error = msleep(&cht_enabled, &cht_lock,
			    PWAIT | PCATCH, "skmtw", NULL);
			/* BEGIN CSTYLED */
			/*
			 * Loop exit conditions:
			 *   - we were interrupted
			 *     OR
			 *   - we are starting up and are enabled
			 *     (Startup complete)
			 *     OR
			 *   - we are starting up and are not busy
			 *     (Failed startup)
			 *     OR
			 *   - we are shutting down and are not busy
			 *     (Shutdown complete)
			 */
			/* END CSTYLED */
		} while (!((error == EINTR) || (newvalue && cht_enabled) ||
		    (newvalue && !cht_busy) || (!newvalue && !cht_busy)));

		SK_ERR("exited from msleep");
		thread_deallocate(th);
	}

done:
	lck_mtx_unlock(&cht_lock);
	return error;
}

SYSCTL_PROC(_kern_skywalk_libcuckoo, OID_AUTO, test,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED, NULL, 0,
    sysctl_cuckoo_test, "I", "Start Cuckoo hashtable test");

#endif /* DEVELOPMENT || DEBUG */
