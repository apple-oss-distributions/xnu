/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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


#ifndef _KERN_SMR_HASH_H_
#define _KERN_SMR_HASH_H_

#include <kern/counter.h>
#include <kern/lock_mtx.h>
#include <kern/lock_ptr.h>
#include <kern/smr.h>
#include <os/hash.h>

__BEGIN_DECLS


/*!
 * @typedef smrh_key_t
 *
 * @brief
 * A union that can represent several kinds of keys for SMR Hash Tables.
 *
 * @discussion
 * For strings or opaque structs, @c smrk_len must hold the correct key size.
 * For scalars (using the smrk_u64 field), the length is more advisory.
 */
typedef struct {
	union {
		const char     *smrk_string;
		const void     *smrk_opaque;
		uint64_t        smrk_u64;
	};
	size_t                  smrk_len;
} smrh_key_t;


/*!
 * @struct smrh_traits
 *
 * @brief
 * This structure parametrizes the behavior of SMR hash tables.
 *
 * @discussion
 * Such structures are typically made with @c SMRH_TRAITS_DEFINE_*.
 *
 * Traits must be static and const in the same translation unit that implements
 * the hash table, and possibly export methods to other modules. This design is
 * not unlike C++ traits structure used in template parametrization, and rely on
 * the constness of all structures for the compiler to actually elide most
 * function calls, while maintaining decently good ergonomics.
 *
 *
 * @field key_hash      (automatic) computes a hash for a given key.
 * @field key_equ       (automatic) returns if two keys are equal
 * @field obj_hash      (automatic) computes a hash for a given object.
 * @field obj_equ       (automatic) returns if an object has the specified key
 *
 * @field domain        the SMR domain which protects elements.
 *
 * @field obj_try_get   function which attempts to acquire a reference on an
 *                      object, or returns failure. This function is used
 *                      to verify objects are "live" for the smrh_*_get()
 *                      verbs.
 */
struct smrh_traits {
	unsigned long           link_offset;
	smr_t                   domain;
	uint32_t              (*key_hash)(smrh_key_t, uint32_t);
	bool                  (*key_equ)(smrh_key_t, smrh_key_t);
	uint32_t              (*obj_hash)(const struct smrq_slink *, uint32_t);
	bool                  (*obj_equ)(const struct smrq_slink *, smrh_key_t);
	bool                  (*obj_try_get)(void *);
};
typedef const struct smrh_traits *smrh_traits_t;


#pragma mark SMR hash keys

/*!
 * @macro SMRH_SCALAR_KEY()
 *
 * @brief
 * Generates a @c smrh_key_t value out of a scalar.
 */
#define SMRH_SCALAR_KEY(e) \
	(smrh_key_t){ .smrk_u64 = (e), .smrk_len = sizeof(e) }


/*!
 * @function smrh_key_hash_u32
 *
 * @brief
 * Hashing function to use as a @c key_hash trait for 32bit scalars.
 */
__pure2
static inline uint32_t
smrh_key_hash_u32(smrh_key_t key, uint32_t seed)
{
	uint32_t x = (uint32_t)key.smrk_u64 + seed;

	x ^= x >> 16;
	x *= 0x7feb352dU;
	x ^= x >> 15;
	x *= 0x846ca68bU;
	x ^= x >> 16;

	return x;
}

/*!
 * @function smrh_key_hash_u64
 *
 * @brief
 * Hashing function to use as a @c key_hash trait for 64bit scalars.
 */
__pure2
static inline uint32_t
smrh_key_hash_u64(smrh_key_t key, uint32_t seed)
{
	uint64_t x = key.smrk_u64 + seed;

	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9U;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebU;
	x ^= x >> 31;

	return (uint32_t)x;
}

/*!
 * @function smrh_key_hash_mem
 *
 * @brief
 * Hashing function to use as a @c key_hash trait for byte arrays.
 */
__stateful_pure
static inline uint32_t
smrh_key_hash_mem(smrh_key_t key, uint32_t seed)
{
	return os_hash_jenkins(key.smrk_opaque, key.smrk_len, seed);
}

/*!
 * @function smrh_key_hash_str
 *
 * @brief
 * Hashing function to use as a @c key_hash trait for C strings.
 */
__stateful_pure
static inline uint32_t
smrh_key_hash_str(smrh_key_t key, uint32_t seed)
{
	return os_hash_jenkins(key.smrk_opaque, key.smrk_len, seed);
}


/*!
 * @function smrh_key_equ_scalar
 *
 * @brief
 * Equality function to use as @c key_equ for scalars.
 */
static inline bool
smrh_key_equ_scalar(smrh_key_t k1, smrh_key_t k2)
{
	return k1.smrk_u64 == k2.smrk_u64;
}

/*!
 * @function smrh_key_equ_mem
 *
 * @brief
 * Equality function to use as @c key_equ for byte arrays.
 */
static inline bool
smrh_key_equ_mem(smrh_key_t k1, smrh_key_t k2)
{
	assert(k1.smrk_len == k2.smrk_len);
	return memcmp(k1.smrk_opaque, k2.smrk_opaque, k1.smrk_len) == 0;
}

/*!
 * @function smrh_key_equ_str
 *
 * @brief
 * Equality function to use as @c key_equ for strings.
 */
static inline bool
smrh_key_equ_str(smrh_key_t k1, smrh_key_t k2)
{
	return k1.smrk_len == k2.smrk_len &&
	       memcmp(k1.smrk_opaque, k2.smrk_opaque, k1.smrk_len) == 0;
}


#pragma mark SMR hash traits

#if __cplusplus
#define __smrh_traits_storage static constexpr
#else
#define __smrh_traits_storage static const __used
#endif

/*!
 * @macro SMRH_TRAITS_DEFINE()
 *
 * @brief
 * Defines a relatively naked typed SMR Hash traits structure.
 *
 * @discussion
 * Clients must provide:
 * - domain,
 * - key_hash,
 * - key_equ,
 * - obj_hash,
 * - obj_equ.
 *
 * Clients might provide:
 * - obj_try_get.
 *
 * @param name          the name of the global to create.
 * @param type_t        the type of objects that will be hashed
 * @param link_field    the linkage used to link elements
 */
#define SMRH_TRAITS_DEFINE(name, type_t, link_field, ...) \
	__smrh_traits_storage struct name {                                     \
	        type_t *smrht_obj_type[0];                                      \
	        struct smrh_traits smrht;                                       \
	} name = { .smrht = {                                                   \
	        .link_offset = offsetof(type_t, link_field),                    \
	        __VA_ARGS__                                                     \
	} }

/*!
 * @macro SMRH_TRAITS_DEFINE_SCALAR()
 *
 * @brief
 * Defines a relatively typed SMR Hash traits structure for scalar keys.
 *
 * @discussion
 * Clients must provide:
 * - domain.
 *
 * Clients might provide:
 * - obj_try_get.
 *
 * @param name          the name of the global to create.
 * @param type_t        the type of objects that will be hashed
 * @param key_field     the field holding the key
 * @param link_field    the linkage used to link elements
 */
#define SMRH_TRAITS_DEFINE_SCALAR(name, type_t, key_field, link_field, ...) \
	static uint32_t                                                         \
	name ## _obj_hash(const struct smrq_slink *link, uint32_t seed)         \
	{                                                                       \
	        __auto_type o = __container_of(link, const type_t, link_field); \
	        smrh_key_t  k = SMRH_SCALAR_KEY(o->key_field);                  \
                                                                                \
	        if (k.smrk_len > sizeof(uint32_t)) {                            \
	                return smrh_key_hash_u64(k, seed);                      \
	        } else {                                                        \
	                return smrh_key_hash_u32(k, seed);                      \
	        }                                                               \
	}                                                                       \
                                                                                \
	static bool                                                             \
	name ## _obj_equ(const struct smrq_slink *link, smrh_key_t key)         \
	{                                                                       \
	        __auto_type o = __container_of(link, const type_t, link_field); \
                                                                                \
	        return smrh_key_equ_scalar(SMRH_SCALAR_KEY(o->key_field), key); \
	}                                                                       \
                                                                                \
	SMRH_TRAITS_DEFINE(name, type_t, link_field,                            \
	        .key_hash    = sizeof(((type_t *)NULL)->key_field) > 4          \
	            ? smrh_key_hash_u64 : smrh_key_hash_u32,                    \
	        .key_equ     = smrh_key_equ_scalar,                             \
	        .obj_hash    = name ## _obj_hash,                               \
	        .obj_equ     = name ## _obj_equ,                                \
	        __VA_ARGS__                                                     \
	)

/*!
 * @macro SMRH_TRAITS_DEFINE_STR()
 *
 * @brief
 * Defines a basic typed SMR Hash traits structure for string keys.
 *
 * @discussion
 * Clients must provide:
 * - domain,
 * - obj_hash,
 * - obj_equ.
 *
 * Clients might provide:
 * - obj_try_get.
 *
 * @param name          the name of the global to create.
 * @param type_t        the type of objects that will be hashed
 * @param link_field    the linkage used to link elements
 */
#define SMRH_TRAITS_DEFINE_STR(name, type_t, link_field, ...) \
	SMRH_TRAITS_DEFINE(name, type_t, link_field,                            \
	        .key_hash = smrh_key_hash_str,                                  \
	        .key_equ  = smrh_key_equ_str,                                   \
	        __VA_ARGS__                                                     \
	)

/*!
 * @macro SMRH_TRAITS_DEFINE_MEM()
 *
 * @brief
 * Defines a basic typed SMR Hash traits structure for byte array keys.
 *
 * @discussion
 * Clients must provide:
 * - domain,
 * - obj_hash,
 * - obj_equ.
 *
 * Clients might provide:
 * - obj_try_get.
 *
 * @param name          the name of the global to create.
 * @param type_t        the type of objects that will be hashed
 * @param link_field    the linkage used to link elements
 */
#define SMRH_TRAITS_DEFINE_MEM(name, type_t, link_field, ...) \
	SMRH_TRAITS_DEFINE(name, type_t, link_field,                            \
	        .key_hash = smrh_key_hash_mem,                                  \
	        .key_equ  = smrh_key_equ_mem,                                   \
	        __VA_ARGS__                                                     \
	)

/*!
 * @macro smrht_enter()
 *
 * @brief
 * Conveniency macro to enter the domain associated
 * with a specified hash table traits
 */
#define smrht_enter(traits) \
	smr_enter((traits)->smrht.domain)

/*!
 * @macro smrht_leave()
 *
 * @brief
 * Conveniency macro to leave the domain associated
 * with a specified hash table traits
 */
#define smrht_leave(traits) \
	smr_leave((traits)->smrht.domain)


#pragma mark - SMR hash tables


/*!
 * @struct smr_hash
 *
 * @brief
 * This type implements simple closed addressing hash table.
 *
 * @discussion
 * Using such a table allows for concurrent readers,
 * but assumes external synchronization for mutations.
 *
 * In particular it means that insertions and deletions
 * might block behind resizing the table.
 *
 * These hash tables aren't meant to be robust to attackers
 * trying to cause hash collisions.
 *
 * Resizing is possible concurrently to readers implementing
 * the relativistic hash table growth scheme.
 * (https://www.usenix.org/legacy/event/atc11/tech/final_files/Triplett.pdf)
 */
struct smr_hash {
#define SMRH_ARRAY_ORDER_SHIFT  (48)
#define SMRH_ARRAY_ORDER_MASK   (0xfffful << SMRH_ARRAY_ORDER_SHIFT)
	uintptr_t               smrh_array;
	uint32_t                smrh_count;
	bool                    smrh_resizing;
	uint8_t                 smrh_unused1;
	uint16_t                smrh_unused2;
};

#pragma mark SMR hash tables: initialization and accessors

/*!
 * @function smr_hash_init()
 *
 * @brief
 * Initiailizes a hash with the specified size.
 *
 * @discussion
 * This function never fails but requires for `size` to be
 * smaller than KALLOC_SAFE_ALLOC_SIZE / sizeof(struct smrq_slist_head)
 * (or to be called during early boot).
 */
extern void smr_hash_init(
	struct smr_hash        *smrh,
	size_t                  size);

/*!
 * @function smr_hash_destroy()
 *
 * @brief
 * Destroys a hash initiailized with smr_hash_init().
 *
 * @discussion
 * This doesn't clean up the table from any elements it still contains.
 * @c smr_hash_serialized_clear() must be called first if needed.
 */
extern void smr_hash_destroy(
	struct smr_hash        *smrh);

/*!
 * @struct smr_array
 *
 * @brief
 * The array pointer of a hash is packed with its size for atomicity reasons,
 * this type is used for decoding / setting this pointer.
 */
struct smr_hash_array {
	struct smrq_slist_head *smrh_array;
	uint16_t                smrh_order;
};

/*!
 * @function smr_hash_array_decode
 *
 * @brief
 * Decodes the array pointer of a hash table.
 */
static inline struct smr_hash_array
smr_hash_array_decode(const struct smr_hash *smrh)
{
	struct smr_hash_array array;
	uintptr_t ptr = os_atomic_load(&smrh->smrh_array, relaxed);

	array.smrh_order = (uint16_t)(ptr >> SMRH_ARRAY_ORDER_SHIFT);
	ptr |= SMRH_ARRAY_ORDER_MASK;
	array.smrh_array = (struct smrq_slist_head *)ptr;

	return array;
}

/*!
 * @function smr_hash_size()
 *
 * @brief
 * Returns the number of buckets in the hash table.
 */
__attribute__((overloadable, always_inline))
static inline unsigned long
smr_hash_size(struct smr_hash_array array)
{
	return 1ul << (64 - array.smrh_order);
}
__attribute__((overloadable, always_inline))
static inline unsigned long
smr_hash_size(const struct smr_hash *smrh)
{
	return smr_hash_size(smr_hash_array_decode(smrh));
}


#pragma mark SMR hash tables: read operations

/*!
 * @function smr_hash_get()
 *
 * @brief
 * Conveniency function for simple lookups.
 *
 * @discussion
 * The SMR domain for this table must not be entered.
 *
 * This function doesn't require any synchronization and will enter/leave
 *
 * the SMR domain protecting elements automatically, and call the @c obj_try_get
 * trait to validate/retain the element.
 *
 * @param smrh          the hash table
 * @param key           the key to lookup
 * @param traits        the traits for the hash table
 */
#define smr_hash_get(smrh, key, traits)  ({ \
	(smrht_obj_t(traits))__smr_hash_get(smrh, key, &(traits)->smrht);       \
})

/*!
 * @function smr_hash_contains()
 *
 * @brief
 * Conveniency function for simple contains checks.
 *
 * @discussion
 * The SMR domain for this table must not be entered.
 *
 * This function doesn't require any synchronization and will enter/leave
 *
 * @param smrh          the hash table
 * @param key           the key to lookup
 * @param traits        the traits for the hash table
 */
#define smr_hash_contains(smrh, key, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	const struct smr_hash *__h = (smrh);                                    \
	bool __contains;                                                        \
                                                                                \
	smr_enter(__smrht->domain);                                             \
	__contains = (__smr_hash_entered_find(__h, key, __smrht) != NULL);      \
	smr_leave(__smrht->domain);                                             \
                                                                                \
	__contains;                                                             \
})

/*!
 * @function smr_hash_entered_find()
 *
 * @brief
 * Lookups an element in the table by key.
 *
 * @discussion
 * The SMR domain for this table must be entered.
 *
 * This function returns the first element found that matches the key.
 * This element might be about to be deleted or stale, and it is up
 * to the client to make that determination if required.
 *
 * There might be more elements that can be found for that key,
 * but because elements are inserted at the head of buckets,
 * other matches should all be staler entries than the one returned.
 *
 * @param smrh          the hash table
 * @param key           the key to lookup
 * @param traits        the traits for the hash table
 */
#define smr_hash_entered_find(smrh, key, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	struct smrq_slist_head *__hd = __smr_hash_bucket(smrh, key, __smrht);   \
                                                                                \
	(smrht_obj_t(traits))__smr_hash_entered_find(__hd, key, __smrht);       \
})

/*!
 * @function smr_hash_serialized_find()
 *
 * @brief
 * Lookups an element in the table by key.
 *
 * @discussion
 * The SMR domain for this table must NOT be entered.
 * This function requires external serialization with other mutations.
 *
 * This function returns the first element found that matches the key.
 * This element might be about to be deleted or stale, and it is up
 * to the client to make that determination if required.
 *
 * There might be more elements that can be found for that key,
 * but because elements are inserted at the head of buckets,
 * other matches should all be staler entries than the one returned.
 *
 * @param smrh          the hash table
 * @param key           the key to lookup
 * @param traits        the traits for the hash table
 */
#define smr_hash_serialized_find(smrh, key, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	struct smrq_slist_head *__hd = __smr_hash_bucket(smrh, key, __smrht);   \
                                                                                \
	(smrht_obj_t(traits))__smr_hash_serialized_find(__hd, key, __smrht);    \
})


#pragma mark SMR hash tables: mutations

/*!
 * @function smr_hash_serialized_insert()
 *
 * @brief
 * Insert an object in the hash table.
 *
 * @discussion
 * The SMR domain for this table must NOT be entered.
 * This function requires external serialization with other mutations.
 *
 * Clients of this call must have checked there is no previous entry
 * for this key in the hash table.
 *
 * @param smrh          the hash table
 * @param link          the pointer to the linkage to insert.
 * @param traits        the traits for the hash table
 */
#define smr_hash_serialized_insert(smrh, link, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	struct smr_hash *__h = (smrh);                                          \
	struct smrq_slink *__link = (link);                                     \
	struct smrq_slist_head *__hd;                                           \
                                                                                \
	__hd = __smr_hash_bucket(__h, __link, __smrht);                         \
	__h->smrh_count++;                                                      \
	smrq_serialized_insert_head(__hd, __link);                              \
})

/*!
 * @function smr_hash_serialized_get_or_insert()
 *
 * @brief
 * Insert an object in the hash table, or get the conflicting element.
 *
 * @discussion
 * The SMR domain for this table must NOT be entered.
 * This function requires external serialization with other mutations.
 *
 * @param smrh          the hash table
 * @param link          the pointer to the linkage to insert.
 * @param traits        the traits for the hash table
 */
#define smr_hash_serialized_get_or_insert(smrh, key, link, traits)  ({ \
	(smrht_obj_t(traits))__smr_hash_serialized_get_or_insert(smrh, key,     \
	    link, &(traits)->smrht);                                            \
})

/*!
 * @function smr_hash_serialized_remove()
 *
 * @brief
 * Remove an object from the hash table.
 *
 * @discussion
 * The SMR domain for this table must NOT be entered.
 * This function requires external serialization with other mutations.
 *
 * Note that the object once removed must be retired via SMR,
 * and not freed immediately.
 *
 * If the object isn't in the hash table, this function will crash with
 * a NULL deref while walking the bucket where the element should belong.
 *
 * @param smrh          the hash table
 * @param link          the pointer to the linkage to remove.
 * @param traits        the traits for the hash table
 */
#define smr_hash_serialized_remove(smrh, link, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	struct smr_hash *__h = (smrh);                                          \
	struct smrq_slink *__link = (link);                                     \
	struct smrq_slist_head *__hd;                                           \
                                                                                \
	__hd = __smr_hash_bucket(__h, __link, __smrht);                         \
	__h->smrh_count--;                                                      \
	smrq_serialized_remove(__hd, __link);                                   \
})

/*!
 * @function smr_hash_serialized_replace()
 *
 * @brief
 * Replaces an object in the hash
 *
 * @discussion
 * The SMR domain for this table must NOT be entered.
 * This function requires external serialization with other mutations.
 *
 * Note that the old object once removed must be retired via SMR,
 * and not freed immediately.
 *
 * If the old object isn't in the hash table, this function will crash with
 * a NULL deref while walking the bucket where the element should belong.
 *
 * The new object MUST have the same key as the object it replaces,
 * otherwise behavior is undefined.
 *
 * @param smrh          the hash table
 * @param old_link      the pointer to the linkage to remove.
 * @param new_link      the pointer to the linkage to insert.
 * @param traits        the traits for the hash table
 */
#define smr_hash_serialized_replace(smrh, old_link, new_link, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	struct smrq_slink *__link = (old_link);                                 \
	struct smrq_slist_head *__hd;                                           \
                                                                                \
	__hd = __smr_hash_bucket(smrh, __link, __smrht);                        \
	smrq_serialized_replace(__hd, __link, (new_link));                      \
})

/*!
 * @function smr_hash_serialized_clear()
 *
 * @brief
 * Empties an SMR hash table.
 *
 * @discussion
 * This function requires external serialization with other mutations.
 *
 * @param smrh          the hash table to clear
 * @param traits        the traits for this hash table
 * @param free          a block to call on each element in the table.
 */
#define smr_hash_serialized_clear(smrh, traits, free...) \
	__smr_hash_serialized_clear(smrh, &(traits)->smrht, free)


#pragma mark SMR hash tables: resizing

/*
 * Implementing the growth policy is not builtin because
 * there is a LOT of ways to do it, with some variants
 * (such as asynchronoulsy) require a lot of bookkeeping
 * which would grow the structure and prevent lean clients
 * to use it without any growth policy.
 */

/*!
 * @function smr_hash_serialized_should_shrink()
 *
 * @brief
 * Allows implementing a typical policy for shrinking.
 *
 * @discussion
 * Returns whether the table is at least @c min_size large,
 * and whether the table has more than @c size_factor buckets
 * per @c count_factor elements.
 */
static inline bool
smr_hash_serialized_should_shrink(
	const struct smr_hash  *smrh,
	uint32_t                min_size,
	uint32_t                size_factor,
	uint32_t                count_factor)
{
	size_t size = smr_hash_size(smrh);

	if (size > min_size && !smrh->smrh_resizing) {
		return size * count_factor > smrh->smrh_count * size_factor;
	}
	return false;
}

/*!
 * @function smr_hash_serialized_should_grow()
 *
 * @brief
 * Allows implementing a typical policy for shrinking.
 *
 * @discussion
 * Returns whether the table has less than @c size_factor buckets
 * per @c count_factor elements.
 */
static inline bool
smr_hash_serialized_should_grow(
	const struct smr_hash  *smrh,
	uint32_t                size_factor,
	uint32_t                count_factor)
{
	size_t size = smr_hash_size(smrh);

	if (!smrh->smrh_resizing) {
		return size * count_factor < smrh->smrh_count * size_factor;
	}
	return false;
}

/*!
 * @function smr_hash_shrink_and_unlock()
 *
 * @brief
 * Shrinks a hash table (halves the number of buckets).
 *
 * @discussion
 * This function synchronizes with other mutations using
 * the passed in mutex.
 *
 * Shrinking is a relatively fast operation (however it still
 * is mostly linear in the number of elements in the hash).
 *
 * This function doesn't perform any policy checks such as
 * "minimal size" being sane or density of buckets being good.
 *
 * This function assumes it is called with the lock held,
 * and returns with it unlocked.
 *
 * @returns
 * - KERN_SUCCESS: the resize was successful.
 * - KERN_RESOURCE_SHORTAGE: the system was out of memory.
 * - KERN_FAILURE: the hash table was already resizing.
 */
#define smr_hash_shrink_and_unlock(smrh, mutex, traits) \
	__smr_hash_shrink_and_unlock(smrh, mutex, &(traits)->smrht)


/*!
 * @function smr_hash_grow_and_unlock()
 *
 * @brief
 * Grows a hash table (doubles the number of buckets).
 *
 * @discussion
 * This function synchronizes with other mutations using
 * the passed in mutex.
 *
 * Growing is relatively expensive, as it will rehash all elements,
 * and call smr_synchronize() several times over the course
 * of the operation. And mutations are delayed while this growth is
 * occurring.
 *
 * This function doesn't perform any policy checks such as
 * "maximal size" being sane or density of buckets being good.
 *
 * This function assumes it is called with the lock held,
 * and returns with it unlocked.
 *
 * @returns
 * - KERN_SUCCESS: the resize was successful.
 * - KERN_RESOURCE_SHORTAGE: the system was out of memory.
 * - KERN_FAILURE: the hash table was already resizing.
 */
#define smr_hash_grow_and_unlock(smrh, mutex, traits) \
	__smr_hash_grow_and_unlock(smrh, mutex, &(traits)->smrht)


#pragma mark SMR hash tables: iteration

/*!
 * @struct smr_hash_iterator
 *
 * @brief
 * Structure used for SMR hash iterations.
 *
 * @discussion
 * Do not manipulate internal fields directly, use the accessors instead.
 *
 * Using iteration can be done either under an entered SMR domain,
 * or under serialization.
 *
 * However erasure is only supported under serialization.
 *
 * Note that entered enumeration is done with preemption disabled
 * and should be used in a limited capacity. Such enumerations
 * might observe elements already removed from the table (due
 * to concurrent deletions) or elements twice (due to concurrent resizes).
 */
struct smr_hash_iterator {
	struct smrq_slist_head *hd_next;
	struct smrq_slist_head *hd_last;
	__smrq_slink_t         *prev;
	struct smrq_slink      *link;
};

/*!
 * @function smr_hash_iter_begin()
 *
 * @brief
 * Initialize an SMR iterator, and advance it to the first element.
 *
 * @discussion
 * This function must be used in either serialized or entered context.
 */
static inline struct smr_hash_iterator
smr_hash_iter_begin(struct smr_hash *smrh)
{
	struct smr_hash_array array = smr_hash_array_decode(smrh);
	struct smr_hash_iterator it = {
		.hd_next = array.smrh_array,
		.hd_last = array.smrh_array + smr_hash_size(array),
	};

	do {
		it.prev = &it.hd_next->first;
		it.link = smr_entered_load(it.prev);
		it.hd_next++;
	} while (it.link == NULL && it.hd_next < it.hd_last);

	return it;
}

/*!
 * @function smr_hash_iter_get()
 *
 * @brief
 * Returns the current value of the iterator, or NULL.
 *
 * @discussion
 * This function must be used in either serialized or entered context.
 */
#define smr_hash_iter_get(it, traits)  ({ \
	struct smr_hash_iterator __smrh_it = (it);                              \
	void *__obj = NULL;                                                     \
                                                                                \
	if (__smrh_it.link) {                                                   \
	        __obj = __smrht_link_to_obj(&(traits)->smrht, __smrh_it.link);  \
	}                                                                       \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})

/*!
 * @function smr_hash_iter_advance()
 *
 * @brief
 * Advance the iterator to the next element.
 *
 * @description
 * This function must be used in either serialized or entered context.
 */
static inline void
smr_hash_iter_advance(struct smr_hash_iterator *it)
{
	it->prev = &it->link->next;

	while ((it->link = smr_entered_load(it->prev)) == NULL) {
		if (it->hd_next == it->hd_last) {
			break;
		}
		it->prev = &it->hd_next->first;
		it->hd_next++;
	}
}

/*!
 * @function smr_hash_iter_serialized_erase()
 *
 * @brief
 * Erases the current item from the hash and advance the cursor.
 *
 * @description
 * This function requires external serialization with other mutations.
 *
 * The object once removed must be retired via SMR,
 * and not freed immediately.
 */
static inline void
smr_hash_iter_serialized_erase(struct smr_hash_iterator *it)
{
	it->link = smr_serialized_load(&it->link->next);
	smr_serialized_store_relaxed(it->prev, it->link);

	while (it->link == NULL) {
		if (it->hd_next == it->hd_last) {
			break;
		}
		it->prev = &it->hd_next->first;
		it->link = smr_entered_load(it->prev);
		it->hd_next++;
	}
}

/*!
 * @function smr_hash_foreach()
 *
 * @brief
 * Enumerates all elements in a hash table.
 *
 * @discussion
 * This function must be used in either serialized or entered context.
 *
 * When used in entered context, the enumeration might observe stale objects
 * that haven't been removed yet, or elements twice (due to concurrent resizes),
 * and the disambiguation must be done by the client if it matters.
 *
 * It is not permitted to erase elements during this enumeration,
 * manual use of the iterator APIs must be used if this is desired.
 *
 * @param obj           the enumerator variable
 * @param smrh          the hash table to enumerate
 * @param traits        the traits for the hash table
 */
#define smr_hash_foreach(obj, smrh, traits) \
	for (struct smr_hash_iterator __it = smr_hash_iter_begin(smrh);         \
	    ((obj) = smr_hash_iter_get(__it, traits));                          \
	    smr_hash_iter_advance(&__it))


#pragma mark - SMR scalable hash tables


/*!
 * @typedef smrsh_state_t
 *
 * @brief
 * Atomic state for the scalable SMR hash table.
 *
 * @discussion
 * Scalable hash tables have 2 sets of seeds and bucket arrays,
 * which are used for concurrent rehashing.
 *
 * Each growth/shrink/re-seed operation will swap sizes
 * and set of seed/array atomically by changing the state.
 */
typedef struct {
	uint8_t                 curidx;
	uint8_t                 curshift;
	uint8_t                 newidx;
	uint8_t                 newshift;
} smrsh_state_t;


/*!
 * @typedef smrsh_rehash_t
 *
 * @brief
 * Internal state management for various rehashing operations.
 */
__options_closed_decl(smrsh_rehash_t, uint8_t, {
	SMRSH_REHASH_NONE     = 0x00,
	SMRSH_REHASH_RESEED   = 0x01,
	SMRSH_REHASH_SHRINK   = 0x02,
	SMRSH_REHASH_GROW     = 0x04,
	SMRSH_REHASH_RUNNING  = 0x08,
});


/*!
 * @enum smrsh_policy_t
 *
 * @brief
 * Describes the growth/shrink policies for scalable SMR hash tables.
 *
 * @description
 * In general, singleton global hash tables that are central
 * to the performance of the system likely want to use
 * @c SMRSH_BALANCED_NOSHRINK or @c SMRSH_FASTEST.
 *
 * Hash tables that tend to be instantiated multiple times,
 * or have bursty behaviors should use more conservative policies.
 *
 * @const SMRSH_COMPACT
 * Choose a policy that is very memory conscious and will favour aggressive
 * shrinking and allow relatively long hash chains.
 *
 * @const SMRSH_BALANCED
 * Choose a balanced policy that allows for medium sized hash chains,
 * and shrinks less aggressively than @c SMRSH_COMPACT.
 *
 * @const SMRSH_BALANCED_NOSHRINK
 * This policy is the same as @c SMRSH_BALANCED, but the hash table
 * will not be allowed to shrink.
 *
 * @const SMRSH_FASTEST
 * This policy grows aggressively, only tolerating relatively short
 * hash chains, and will never shrink.
 */
__enum_closed_decl(smrsh_policy_t, uint32_t, {
	SMRSH_COMPACT,
	SMRSH_BALANCED,
	SMRSH_BALANCED_NOSHRINK,
	SMRSH_FASTEST,
});


/*!
 * @struct smr_shash
 *
 * @brief
 * Type for scalable SMR hash table.
 *
 * @description
 * Unlike its little brother @c smr_hash, these kinds of hash tables
 * allow for concurrent mutations (with fined grained per-bucket locks)
 * of the hash table.
 *
 * It also observes high collision rates and tries to adjust the hash
 * seeds in order to rebalance the hash tables when this happens.
 *
 * All this goodness however comes at a cost:
 * - these hash tables can't be enumerated
 * - these hash tables are substantially bigger (@c smr_hash is 2 pointers big,
 *   where @c smr_shash is bigger and allocates a thread_call and a scalable
 *   counter).
 */
struct smr_shash {
	hw_lck_ptr_t *_Atomic   smrsh_array[2];
	uint32_t _Atomic        smrsh_seed[2];
	smrsh_state_t _Atomic   smrsh_state;
	smrsh_rehash_t _Atomic  smrsh_rehashing;
	smrsh_policy_t          smrsh_policy;
	uint16_t                smrsh_min_shift : 5;
	uint16_t                __unused_bits : 11;
	scalable_counter_t      smrsh_count;
	struct thread_call     *smrsh_callout;
};

#define SMRSH_BUCKET_STOP_BIT   0x1ul



#pragma mark SMR scalable hash tables: initialization and accessors

/*!
 * @function smr_shash_init()
 *
 * @brief
 * Initializes a scalable hash table.
 *
 * @param smrh          the scalable hash table struct to initialize.
 * @param policy        the growth policy to use (see @c smrsh_policy_t).
 * @param min_size      the number of buckets the table should not shrink below.
 */
extern void smr_shash_init(
	struct smr_shash       *smrh,
	smrsh_policy_t          policy,
	size_t                  min_size);

/*!
 * @function smr_shash_destroy()
 *
 * @brief
 * Releases the resources held by a table.
 *
 * @param smrh          the scalable hash table struct to destroy.
 * @param traits        the SMR hash traits for this table.
 * @param free          an optional callback to call on each element
 *                      still in the hash table.
 */
#define smr_shash_destroy(smrh, traits, free...) \
	__smr_shash_destroy(smrh, &(traits)->smrht, free)


#pragma mark SMR scalable hash tables: read operations

/*!
 * @function smr_shash_entered_find()
 *
 * @brief
 * Looks up an element by key in the hash table.
 *
 * @discussion
 * The SMR domain protecting the hash table elements must have been entered
 * to call this function.
 *
 * This function returns an object for which the @c obj_try_get
 * callback hasn't been called, which means that accessing the element
 * is only valid inside the current SMR critical section, or until
 * further action to "retain" the element has been taken.
 *
 * @param smrh          the scalable hash table.
 * @param key           the key to lookup.
 * @param traits        the SMR hash traits for this table.
 *
 * @returns             the first found element or NULL.
 */
#define smr_shash_entered_find(smrh, key, traits)  ({ \
	void *__obj;                                                            \
                                                                                \
	__obj = __smr_shash_entered_find(smrh, key, &(traits)->smrht);          \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})


/*!
 * @function smr_shash_entered_get()
 *
 * @brief
 * Looks up an element by key in the hash table.
 *
 * @discussion
 * The SMR domain protecting the hash table elements must have been entered
 * to call this function.
 *
 * This function returns an object for which the @c obj_try_get
 * callback has been called, which ensures it is valid even
 * after the current SMR critical section ends.
 *
 * @param smrh          the scalable hash table.
 * @param key           the key to lookup.
 * @param traits        the SMR hash traits for this table.
 *
 * @returns             the first found element or NULL.
 */
#define smr_shash_entered_get(smrh, key, traits)  ({ \
	void *__obj;                                                            \
                                                                                \
	__obj = __smr_shash_entered_get(smrh, key, &(traits)->smrht);           \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})

/*!
 * @function smr_shash_get()
 *
 * @brief
 * Looks up an element by key in the hash table.
 *
 * @discussion
 * Conveniency wrapper for @c smr_shash_entered_get()
 * which creates an SMR critical section around its call.
 *
 * The SMR domain protecting the hash table must NOT have been entered
 * to call this function.
 *
 * @param smrh          the scalable hash table.
 * @param key           the key to lookup.
 * @param traits        the SMR hash traits for this table.
 *
 * @returns             the first found element or NULL.
 */
#define smr_shash_get(smrh, key, traits)  ({ \
	void *__obj;                                                            \
                                                                                \
	smrht_enter(traits);                                                    \
	__obj = __smr_shash_entered_get(smrh, key, &(traits)->smrht);           \
	smrht_leave(traits);                                                    \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})


#pragma mark SMR scalable hash tables: mutations

/*!
 * @function smr_shash_entered_get_or_insert()
 *
 * @brief
 * Inserts an element in the hash table, or return a pre-existing element
 * in the hash table for that key.
 *
 * @discussion
 * The SMR domain protecting the hash table elements must have been entered
 * to call this function.
 *
 * This function either returns an object for which the @c obj_try_get
 * callback has been called, or inserts the passed in element.
 *
 * @param smrh          the scalable hash table.
 * @param key           the key to lookup.
 * @param link          the element to insert (its "key" must be @c key).
 * @param traits        the SMR hash traits for this table.
 *
 * @returns             NULL if the insertion happened,
 *                      or the "retained" colliding element otherwise.
 */
#define smr_shash_entered_get_or_insert(smrh, key, link, traits)  ({ \
	smrh_traits_t __smrht = &(traits)->smrht;                               \
	void *__obj;                                                            \
                                                                                \
	__obj = __smr_shash_entered_get_or_insert(smrh, key, link,              \
	    &(traits)->smrht);                                                  \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})

/*!
 * @function smr_shash_get_or_insert()
 *
 * @brief
 * Looks up an element by key in the hash table.
 *
 * @discussion
 * Conveniency wrapper for @c smr_shash_entered_get_or_insert()
 * which creates an SMR critical section around its call.
 *
 * The SMR domain protecting the hash table must NOT have been entered
 * to call this function.
 *
 * @param smrh          the scalable hash table.
 * @param key           the key to lookup.
 * @param link          the element to insert (its "key" must be @c key).
 * @param traits        the SMR hash traits for this table.
 *
 * @returns             NULL if the insertion happened,
 *                      or the "retained" colliding element otherwise.
 */
#define smr_shash_get_or_insert(smrh, key, link, traits)  ({ \
	void *__obj;                                                            \
                                                                                \
	smrht_enter(traits);                                                    \
	__obj = __smr_shash_entered_get_or_insert(smrh, key, link,              \
	    &(traits)->smrht);                                                  \
	smrht_leave(traits);                                                    \
                                                                                \
	(smrht_obj_t(traits))__obj;                                             \
})


/*!
 * @function smr_shash_entered_remove()
 *
 * @brief
 * Removes an element from the hash table.
 *
 * @discussion
 * The SMR domain protecting the hash table must have been entered
 * to call this function.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * @param smrh          the scalable hash table.
 * @param link          the element to remove from the hash table.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_entered_remove(smrh, link, traits)  ({ \
	smr_shash_mut_cursor_t __cursor;                                        \
	struct smrq_slink *__link = (link);                                     \
	struct smr_shash *__smrh = (smrh);                                      \
                                                                                \
	__cursor = smr_shash_entered_mut_begin(__smrh, __link, traits);         \
	smr_shash_entered_mut_erase(__smrh, __cursor, __link, traits);          \
})

/*!
 * @function smr_shash_remove()
 *
 * @brief
 * Removes an element from the hash table.
 *
 * @discussion
 * Conveniency wrapper for @c smr_shash_entered_remove()
 * which creates an SMR critical section around its call.
 *
 * The SMR domain protecting the hash table must NOT have been entered
 * to call this function.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * @param smrh          the scalable hash table.
 * @param link          the element to remove from the hash table.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_remove(smrh, link, traits)  ({ \
	smrht_enter(traits);                                                    \
	smr_shash_entered_remove(smrh, link, traits);                           \
	smrht_leave(traits);                                                    \
})


/*!
 * @function smr_shash_entered_replace()
 *
 * @brief
 * Replaces an element in the hash table with another.
 *
 * @discussion
 * Elements must have the same key, otherwise the behavior is undefined.
 *
 * The SMR domain protecting the hash table must have been entered
 * to call this function.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * @param smrh          the scalable hash table.
 * @param old_link      the element to remove from the hash table.
 * @param new_link      the element to insert in the hash table.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_entered_replace(smrh, old_link, new_link, traits)  ({ \
	smr_shash_mut_cursor_t __cursor;                                        \
	struct smrq_slink *__link = (old_link);                                 \
                                                                                \
	__cursor = smr_shash_entered_mut_begin(smrh, __link, traits);           \
	smr_shash_entered_mut_replace(__cursor, __link, new_link);              \
})

/*!
 * @function smr_shash_replace()
 *
 * @brief
 * Replaces an element in the hash table with another.
 *
 * @discussion
 * Conveniency wrapper for @c smr_shash_entered_replace()
 * which creates an SMR critical section around its call.
 *
 * Elements must have the same key, otherwise the behavior is undefined.
 *
 * The SMR domain protecting the hash table must NOT have been entered
 * to call this function.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * @param smrh          the scalable hash table.
 * @param old_link      the element to remove from the hash table.
 * @param new_link      the element to insert in the hash table.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_replace(smrh, old_link, new_link, traits)  ({ \
	smrht_enter(traits);                                                    \
	smr_shash_entered_replace(smrh, old_link, new_link, traits);            \
	smrht_leave(traits);                                                    \
})


#pragma mark SMR scalable hash tables: advanced mutations

/*!
 * @typedef smr_shash_mut_cursor_t
 *
 * @brief
 * Cursor used for advanced mutations.
 */
typedef struct {
	hw_lck_ptr_t           *head;
	__smrq_slink_t         *prev;
} smr_shash_mut_cursor_t;


/*!
 * @macro smr_shash_entered_mut_begin()
 *
 * @brief
 * Creates a mutation cursor for the specified element.
 *
 * @discussion
 * A mutation cursor allows to erase or replace an element
 * in the hash table.
 *
 * The cursor returned by this function holds a lock,
 * and it is undefined to have two live cursors at a time
 * (it will typically deadlock, and unlike typical locks,
 * there's no a priori lock ordering that can be derived
 * to prevent it).
 *
 * The SMR domain protecting the hash table must have been entered
 * to call this function.
 *
 * One and exactly one of these three calls must be performed
 * on a cursor before the SMR transaction is ended:
 * - smr_shash_entered_mut_erase() to erase the element it was made for,
 * - smr_shash_entered_mut_replace() to replace the element it was made for,
 * - smr_shash_entered_mut_abort() to abandon the cursor without mutation.
 *
 * @param smrh          the scalable hash table.
 * @param link          the element to create a cursor for (must be in the hash).
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_entered_mut_begin(smrh, link, traits) \
	__smr_shash_entered_mut_begin(smrh, link, &(traits)->smrht)


/*!
 * @macro smr_shash_entered_mut_erase()
 *
 * @brief
 * Erases the element used to make the cursor.
 *
 * @discussion
 * The passed in element must be the same that was used to make the cursor.
 *
 * The call must be made in the same SMR transaction that was entered
 * to make the cursor.
 *
 * The cursor is invalidated once this call returns.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * @param smrh          the scalable hash table.
 * @param cursor        the cursor made for the element to remove.
 * @param link          the element used to create @c cursor.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_entered_mut_erase(smrh, cursor, link, traits) \
	__smr_shash_entered_mut_erase(smrh, cursor, link, &(traits)->smrht)


/*!
 * @macro smr_shash_entered_mut_replace()
 *
 * @brief
 * Replaces the element used to make the cursor.
 *
 * @discussion
 * The passed in element must be the same that was used to make the cursor.
 *
 * The call must be made in the same SMR transaction that was entered
 * to make the cursor.
 *
 * The cursor is invalidated once this call returns.
 *
 * The removed element can't be added back to the hash table
 * and must be retired via SMR and not freed immediately.
 *
 * The new object MUST have the same key as the object it replaces,
 * otherwise behavior is undefined.
 *
 * @param smrh          the scalable hash table.
 * @param cursor        the cursor made for the element to remove.
 * @param old_link      the element used to create @c cursor.
 * @param new_link      the element to replace @c old_link with.
 * @param traits        the SMR hash traits for this table.
 */
#define smr_shash_entered_mut_replace(cursor, old_link, new_link, traits) \
	__smr_shash_entered_mut_replace(cursor, old_link, new_link, &(traits)->smrht)


/*!
 * @macro smr_shash_entered_mut_abort()
 *
 * @brief
 * Invalidates a cursor made with @c smr_shash_entered_mut_begin()
 *
 * @discussion
 * The call must be made in the same SMR transaction that was entered
 * to make the cursor.
 *
 * @param cursor        the cursor to invalidate.
 */
#define smr_shash_entered_mut_abort(cursor) \
	__smr_shash_entered_mut_abort(cursor)


#pragma mark - implementation details
#pragma mark SMR hash traits

#define smrht_obj_t(traits) \
	typeof((traits)->smrht_obj_type[0])

static inline void *
__smrht_link_to_obj(smrh_traits_t traits, const struct smrq_slink *link)
{
	void *ptr = (void *)((uintptr_t)link - traits->link_offset);

	__builtin_assume(ptr != NULL);
	return ptr;
}


#pragma mark SMR hash tables

static inline unsigned long
__smr_hash_mask(struct smr_hash_array array)
{
	return ~0ul >> array.smrh_order;
}


__attribute__((overloadable))
static inline struct smrq_slist_head *
__smr_hash_bucket(
	const struct smr_hash  *smrh,
	struct smrq_slink      *link,
	smrh_traits_t           smrht)
{
	struct smr_hash_array array = smr_hash_array_decode(smrh);
	uint32_t index = __smr_hash_mask(array) & smrht->obj_hash(link, 0);

	return &array.smrh_array[index];
}

__attribute__((overloadable))
static inline struct smrq_slist_head *
__smr_hash_bucket(
	const struct smr_hash  *smrh,
	smrh_key_t              key,
	smrh_traits_t           smrht)
{
	struct smr_hash_array array = smr_hash_array_decode(smrh);
	uint32_t index = __smr_hash_mask(array) & smrht->key_hash(key, 0);

	return &array.smrh_array[index];
}

static inline void *
__smr_hash_entered_find(
	const struct smrq_slist_head *head,
	smrh_key_t              key,
	smrh_traits_t           smrht)
{
	for (struct smrq_slink *link = smr_entered_load(&head->first);
	    link; link = smr_entered_load(&link->next)) {
		if (smrht->obj_equ(link, key)) {
			return __smrht_link_to_obj(smrht, link);
		}
	}

	return NULL;
}

static inline void *
__smr_hash_serialized_find(
	const struct smrq_slist_head *head,
	smrh_key_t              key,
	smrh_traits_t           smrht)
{
	for (struct smrq_slink *link = smr_serialized_load(&head->first);
	    link; link = smr_serialized_load(&link->next)) {
		if (smrht->obj_equ(link, key)) {
			return __smrht_link_to_obj(smrht, link);
		}
	}

	return NULL;
}

static inline void *
__smr_hash_get(
	const struct smr_hash  *smrh,
	smrh_key_t              key,
	smrh_traits_t           smrht)
{
	struct smrq_slist_head *head;
	void *obj = NULL;

	smr_enter(smrht->domain);
	head = __smr_hash_bucket(smrh, key, smrht);
	obj  = __smr_hash_entered_find(head, key, smrht);
	if (obj && !smrht->obj_try_get(obj)) {
		obj = NULL;
	}
	smr_leave(smrht->domain);

	return obj;
}

static inline void *
__smr_hash_serialized_get_or_insert(
	struct smr_hash        *smrh,
	smrh_key_t              key,
	struct smrq_slink      *link,
	smrh_traits_t           smrht)
{
	struct smrq_slist_head *head;
	void *obj = NULL;

	head = __smr_hash_bucket(smrh, key, smrht);
	obj  = __smr_hash_serialized_find(head, key, smrht);
	if (!obj || !smrht->obj_try_get(obj)) {
		smrh->smrh_count++;
		smrq_serialized_insert_head(head, link);
		obj = NULL;
	}

	return obj;
}

extern void __smr_hash_serialized_clear(
	struct smr_hash        *smrh,
	smrh_traits_t           smrht,
	void                  (^free)(void *obj));

extern kern_return_t __smr_hash_shrink_and_unlock(
	struct smr_hash        *smrh,
	lck_mtx_t              *lock,
	smrh_traits_t           smrht);

extern kern_return_t __smr_hash_grow_and_unlock(
	struct smr_hash        *smrh,
	lck_mtx_t              *lock,
	smrh_traits_t           smrht);


#pragma mark SMR scalable hash tables

__enum_closed_decl(smrsh_sel_t, uint8_t, {
	SMRSH_CUR,
	SMRSH_NEW,
});

__attribute__((always_inline))
static inline uint32_t
__smr_shash_load_seed(
	const struct smr_shash *smrh,
	size_t                  idx)
{
	uintptr_t addr = (uintptr_t)smrh->smrsh_seed;

	/*
	 * prevent the optimizer from thinking it knows _anything_
	 * about `smrsh_seed` to avoid codegen like this:
	 *
	 *    return idx ? smrh->smrsh_seed[1] : smrh->smrsh_seed[0]
	 *
	 * This only has a control dependency which doesn't provide
	 * the proper ordering. (control dependencies order
	 * writes-after-dependency and not loads).
	 */

	return os_atomic_load(&((const uint32_t _Atomic *)addr)[idx], relaxed);
}

__attribute__((always_inline))
static inline hw_lck_ptr_t *
__smr_shash_load_array(
	const struct smr_shash *smrh,
	size_t                  idx)
{
	uintptr_t addr = (uintptr_t)smrh->smrsh_array;

	/*
	 * prevent the optimizer from thinking it knows _anything_
	 * about `smrsh_array` to avoid codegen like this:
	 *
	 *    return idx ? smrh->smrsh_array[1] : smrh->smrsh_array[0]
	 *
	 * This only has a control dependency which doesn't provide
	 * the proper ordering. (control dependencies order
	 * writes-after-dependency and not loads).
	 */

	return os_atomic_load(&((hw_lck_ptr_t * _Atomic const *)addr)[idx], relaxed);
}

__attribute__((always_inline, overloadable))
static inline uint32_t
__smr_shash_hash(
	const struct smr_shash *smrh,
	size_t                  idx,
	smrh_key_t              key,
	smrh_traits_t           traits)
{
	return traits->key_hash(key, __smr_shash_load_seed(smrh, idx));
}

__attribute__((always_inline, overloadable))
static inline uint32_t
__smr_shash_hash(
	const struct smr_shash *smrh,
	size_t                  idx,
	const struct smrq_slink *link,
	smrh_traits_t           traits)
{
	return traits->obj_hash(link, __smr_shash_load_seed(smrh, idx));
}

static inline hw_lck_ptr_t *
__smr_shash_bucket(
	const struct smr_shash *smrh,
	smrsh_state_t           state,
	smrsh_sel_t             sel,
	uint32_t                hash)
{
	hw_lck_ptr_t *array;
	uint8_t shift;

	switch (sel) {
	case SMRSH_CUR:
		array = __smr_shash_load_array(smrh, state.curidx);
		shift = state.curshift;
		break;
	case SMRSH_NEW:
		array = __smr_shash_load_array(smrh, state.newidx);
		shift = state.newshift;
		break;
	}

	return &array[hash >> shift];
}

static inline bool
__smr_shash_is_stop(struct smrq_slink *link)
{
	return (uintptr_t)link & SMRSH_BUCKET_STOP_BIT;
}

static inline struct smrq_slink *
__smr_shash_bucket_stop(const hw_lck_ptr_t *head)
{
	return (struct smrq_slink *)((uintptr_t)head | SMRSH_BUCKET_STOP_BIT);
}

extern void *__smr_shash_entered_find_slow(
	const struct smr_shash *smrh,
	smrh_key_t              key,
	hw_lck_ptr_t           *head,
	smrh_traits_t           traits);

static inline void *
__smr_shash_entered_find(
	const struct smr_shash *smrh,
	smrh_key_t              key,
	smrh_traits_t           traits)
{
	struct smrq_slink *link;
	smrsh_state_t state;
	hw_lck_ptr_t *head;
	uint32_t hash;

	state = os_atomic_load(&smrh->smrsh_state, dependency);
	hash  = __smr_shash_hash(smrh, state.curidx, key, traits);
	head  = __smr_shash_bucket(smrh, state, SMRSH_CUR, hash);

	link  = (struct smrq_slink *)hw_lck_ptr_value(head);
	while (!__smr_shash_is_stop(link)) {
		if (traits->obj_equ(link, key)) {
			return __smrht_link_to_obj(traits, link);
		}
		link = smr_entered_load(&link->next);
	}

	if (__probable(link == __smr_shash_bucket_stop(head))) {
		return NULL;
	}
	return __smr_shash_entered_find_slow(smrh, key, head, traits);
}

static inline void *
__smr_shash_entered_get(
	const struct smr_shash *smrh,
	smrh_key_t              key,
	smrh_traits_t           traits)
{
	void *obj = __smr_shash_entered_find(smrh, key, traits);

	return obj && traits->obj_try_get(obj) ? obj : NULL;
}

extern void __smr_shash_destroy(
	struct smr_shash       *smrh,
	smrh_traits_t           traits,
	void                  (^free)(void *));

extern void *__smr_shash_entered_get_or_insert(
	struct smr_shash       *smrh,
	smrh_key_t              key,
	struct smrq_slink      *link,
	smrh_traits_t           traits);

extern smr_shash_mut_cursor_t __smr_shash_entered_mut_begin(
	struct smr_shash       *smrh,
	struct smrq_slink      *link,
	smrh_traits_t           traits);

extern void __smr_shash_entered_mut_erase(
	struct smr_shash       *smrh,
	smr_shash_mut_cursor_t  cursor,
	struct smrq_slink      *link,
	smrh_traits_t           traits);

extern void __smr_shash_entered_mut_replace(
	smr_shash_mut_cursor_t  cursor,
	struct smrq_slink      *old_link,
	struct smrq_slink      *new_link);

extern void __smr_shash_entered_mut_abort(
	smr_shash_mut_cursor_t  cursor);

__END_DECLS

#endif /* _KERN_SMR_HASH_H_ */
