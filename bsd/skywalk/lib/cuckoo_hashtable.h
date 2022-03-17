/*
 * Copyright (c) 2018 Apple Inc. All rights reserved.
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
#ifndef _CUCKOO_HASHTABLE_H_
#define _CUCKOO_HASHTABLE_H_

#ifdef BSD_KERNEL_PRIVATE

SYSCTL_DECL(_kern_skywalk_libcuckoo);

/*
 * Cuckoo Hash Table
 *
 * Cuckoo_hashtable is resizable, multi-reader/multi-write thread safe.
 */
#define CUCKOO_HASHTABLE_ENTRIES_MAX    (1<<24)

/*
 * Cuckoo_node is embedded in the object associated by cuckoo_hashtable,
 * so cuckoo_hashtable doesn't need to store key/value pair. This is designed
 * due to the fact that typical user of a hashtable would anyway have the key
 * stored elsewhere (most often in the looked-up object).
 *
 * The cuckoo_hashtabl_node forms a singly linked list of objects that have
 * exactly the same hash value (not just hash bucket collision). This is the
 * result of not storing full length key in the table. So the caller has to
 * traverse the list to add or find the correct object.
 *
 */
struct cuckoo_node {
	struct cuckoo_node *next;
};

#ifndef container_of
#define container_of(ptr, type, member) \
	((type*)(((uintptr_t)ptr) - offsetof(type, member)))
#endif

struct cuckoo_hashtable;

typedef int (*cuckoo_obj_cmp_func)(struct cuckoo_node *node, void *key);
typedef uint32_t (*cuckoo_obj_refcount_func)(struct cuckoo_node *);
typedef void (*cuckoo_obj_retain_func)(struct cuckoo_node *);
typedef void (*cuckoo_obj_release_func)(struct cuckoo_node *);

struct cuckoo_hashtable_params {
	size_t cht_capacity;
	cuckoo_obj_cmp_func cht_obj_cmp;
	cuckoo_obj_retain_func cht_obj_retain;
	cuckoo_obj_release_func cht_obj_release;
};

__BEGIN_DECLS
void cuckoo_hashtable_init(void);
struct cuckoo_hashtable * cuckoo_hashtable_create(
	struct cuckoo_hashtable_params *p);
void cuckoo_hashtable_free(struct cuckoo_hashtable *ht);

size_t cuckoo_hashtable_entries(struct cuckoo_hashtable *h);
size_t cuckoo_hashtable_capacity(struct cuckoo_hashtable *h);
uint32_t cuckoo_hashtable_load_factor(struct cuckoo_hashtable *h);
size_t cuckoo_hashtable_memory_footprint(struct cuckoo_hashtable *h);
void cuckoo_hashtable_try_shrink(struct cuckoo_hashtable *h);

int cuckoo_hashtable_add_with_hash(struct cuckoo_hashtable *h, struct cuckoo_node *node,
    uint32_t key);
int cuckoo_hashtable_del(struct cuckoo_hashtable *h, struct cuckoo_node *node,
    uint32_t key);
struct cuckoo_node *cuckoo_hashtable_find_with_hash(struct cuckoo_hashtable *h,
    void *key, uint32_t hv);

/*
 * There is no guarantee that keys concurrently operated would be returned by
 * walk function. But walk function won't return invalid key/node pairs.
 */
void cuckoo_hashtable_foreach(struct cuckoo_hashtable *ht,
    void (^handler)(struct cuckoo_node *node, uint32_t hv));

#if (DEVELOPMENT || DEBUG)
void cht_test_init(void);
void cht_test_fini(void);
int cuckoo_hashtable_health_check(struct cuckoo_hashtable *h);
void cuckoo_hashtable_dump(struct cuckoo_hashtable *h);
#endif /* !DEVELOPMENT && !DEBUG */

__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_CUCKOO_HASHTABLE_H_ */
