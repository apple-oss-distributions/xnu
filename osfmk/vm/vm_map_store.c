/*
 * Copyright (c) 2009-2020 Apple Inc. All rights reserved.
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

#define VM_MAP_STORE_PRIVATE 1
#include <kern/backtrace.h>
#include <mach/sdt.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_pageout.h> /* for vm_debug_events */
#include <sys/code_signing.h>
#include <vm/vm_entry_lock_internal.h>
#include <vm/vm_kern_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <libkern/crypto/rand.h>
#if __arm64__
#include <arm_neon.h>
#define VMS_USE_NEON            1
#else
#define VMS_USE_NEON            0
#endif

static crypto_random_ctx_t __zpercpu ks_rng_ctx;
#ifdef __BUILDING_XNU_LIB_UNITTEST__
static bool vmgo_enabled = true;
#else
static bool vmgo_enabled = false;
#endif

#if VM_KERNEL_POINTER_SIGNIFICANT_BITS >= 40 || __BUILDING_XNU_LIB_UNITTEST__
#define VMGO_SMALL_CONFIG       0

#define VMGO_CHUNK_LIMIT_2      MiB(128)
#define VMGO_CHUNK_LIMIT_3      MiB(4)
#define VMGO_CHUNK_LIMIT_4      KiB(128)
#else
/*
 * For smaller kernel VA ranges,
 * limit the reach of guard objects to avoid VA exhaustion.
 */
#define VMGO_SMALL_CONFIG       1

#define VMGO_MAX_KDATA_SIZE     MiB(128)

#define VMGO_CHUNK_LIMIT_2      MiB(64)
#define VMGO_CHUNK_LIMIT_3      MiB(2)
#define VMGO_CHUNK_LIMIT_4      KiB(64)
#endif
#define VMGO_MAX_ALIGNMENT      (KiB(256) - 1)
#define VMGO_USER_COUNT         64

struct vmgo_slab_pair {
	struct vm_guard_object_slab pair[2];
};

static_assert(sizeof(struct vm_map_store_node) % BIT(VMN_PACKED_PTR_SHIFT) == 0);
static_assert(sizeof(struct vm_map_entry) % BIT(VME_PACKED_PTR_SHIFT) == 0);
static_assert(sizeof(struct vm_map_store_node) == 256);
static_assert(sizeof(struct vms_path) <= 64, "keep stack usage reasonable");
static_assert(sizeof(struct vm_guard_object_chunk) % BIT(VME_PACKED_PTR_SHIFT) == 0);
static_assert(sizeof(vm_map_store_rsv_t) <= 16, "passed by register");

static_assert(MACH_VM_MAX_ADDRESS <= ((uint64_t)INT32_MAX << VMGO_START_SHIFT),
    "VMGO_START_SHIFT functions for userspace");
static_assert(VM_KERNEL_POINTER_SIGNIFICANT_BITS <= 32 + VMGO_START_SHIFT,
    "VMGO_START_SHIFT functions for kernelspace");

static_assert(64 < (1ull << (1ull << VMGO_COUNT_SHIFT_BITS)),
    "count_shift bits must be enough to encode log2(64) to cover vgoc_bitmap");
static_assert(16 <= (1ull << VMGO_QUARANTINED_BITS),
    "vgoc_quarantined bitfield is wide enough to encode 64/4 - 1");

ZONE_DECLARE_ID(ZONE_ID_VM_GO_CHUNKS, struct vm_guard_object_chunk);
KALLOC_TYPE_DEFINE(KT_GO_SLAB, struct vmgo_slab_pair, KT_PRIV_ACCT);

#define DTRACE_MAP_ENTRY_LINK(map, entry, size_entry) \
	DTRACE_VM4(map_entry_link,                                              \
	    vm_map_t, map,                                                      \
	    vm_map_entry_t, entry,                                              \
	    vm_address_t, (size_entry)->vme_start,                              \
	    vm_address_t, (size_entry)->vme_end)

#define DTRACE_MAP_ENTRY_UNLINK(map, entry, size_entry) \
	DTRACE_VM4(map_entry_unlink,                                            \
	    vm_map_t, map,                                                      \
	    vm_map_entry_t, entry,                                              \
	    vm_address_t, (size_entry)->vme_start,                              \
	    vm_address_t, (size_entry)->vme_end)

#define DTRACE_MAP_ENTRY_EXTEND(map, entry, end) \
	DTRACE_VM5(map_entry_extend,                                            \
	    vm_map_t, map,                                                      \
	    vm_map_entry_t, entry,                                              \
	    vm_address_t, (entry)->vme_start,                                   \
	    vm_address_t, (entry)->vme_end,                                     \
	    vm_address_t, end)


#pragma mark vm map store basic lookup

#if VMS_USE_NEON

/*!
 * @brief
 * NEON optimized version of the key bisection
 *
 * @discussion
 * In order to minimize branches, this function relies on the fact that
 * @c vms_node_set_count() sets a "NEON marker" to ~0ull past the last
 * element (when there is less than vms_fanout(node) keys).
 *
 * This is why the low bit of the searched key is always cleared,
 * this guarantees that the search will always at least stop before
 * that marker (we can do that because keys in that tree are page aligned,
 * and clearing any of the low 12 bits never changes the outcome of the lookup).
 *
 * The general algorithm is in 3 steps:
 *
 * - vectorize the (needle < key) lookup which produces
 *   ~0ull values in the array when true, 0 else
 *
 * - extract the low byte of each of these comparisons and swap their order
 *   (the vqtbl* calls), which will produce where top bits are all 0es and at
 *   some point, a byte becomes 0xff which is the "cutoff point"
 *
 * - use CLZ to count the zeroes which is 8 times the index at which the
 *   comparison flipped and is the index we're looking for.
 *
 * The search always ignores the first key since it's (1) misaligned
 * and (2) always "smaller" than the needle anyway since it's the minimum key.
 *
 * For inner nodes (20 keys) the search is split in 1 ignored + 8 + 8 + 3
 * For leaf nodes (15 keys) the search is split in 1 ignored + 8 + 6
 *
 * @param node          The node to search
 * @param needle        The needle
 * @param is_leaf       Whether the node is a leaf or not.
 */
__attribute__((always_inline, overloadable))
static uint16_t
vms_scan(vm_map_store_node_t node, vm_map_address_t needle, bool is_leaf)
{
	const uint64_t   indices = 0x0001020304050607 * 8;
	const uint64x2_t key     = vmovq_n_u64(needle & ~1ull); /* never look for ~0ull */
	uint64_t         mask;

	assert(vms_is_leaf(node) == is_leaf);
	static_assert(VMS_NODE_FANOUT == 15);
	static_assert(VMS_LEAF_FANOUT == 20);

	uint64x2x4_t keys8;
	uint64x2x3_t keys6;
	uint64x2x2_t keys4;
	uint8x16x4_t vcmp8;
	uint8x16x2_t vcmp4;

	keys8 = vld1q_u64_x4(vms_keyp(node, 1));
	vcmp8.val[0] = (uint8x16_t)(key < keys8.val[0]);
	vcmp8.val[1] = (uint8x16_t)(key < keys8.val[1]);
	vcmp8.val[2] = (uint8x16_t)(key < keys8.val[2]);
	vcmp8.val[3] = (uint8x16_t)(key < keys8.val[3]);
	mask = (uint64_t)vqtbl4_u8(vcmp8, (uint8x8_t)indices);
	if (mask) {
		return (uint16_t)__builtin_arm_clz64(mask) / 8;
	}

	if (is_leaf) {
		keys8 = vld1q_u64_x4(vms_keyp(node, 9));
		vcmp8.val[0] = (uint8x16_t)(key < keys8.val[0]);
		vcmp8.val[1] = (uint8x16_t)(key < keys8.val[1]);
		vcmp8.val[2] = (uint8x16_t)(key < keys8.val[2]);
		vcmp8.val[3] = (uint8x16_t)(key < keys8.val[3]);
	} else {
		keys6 = vld1q_u64_x3(vms_keyp(node, 9));
		vcmp8.val[0] = (uint8x16_t)(key < keys6.val[0]);
		vcmp8.val[1] = (uint8x16_t)(key < keys6.val[1]);
		vcmp8.val[2] = (uint8x16_t)(key < keys6.val[2]);
		vcmp8.val[3] = vdupq_n_u8(0xff);
	}
	mask = (uint64_t)vqtbl4_u8(vcmp8, (uint8x8_t)indices);
	if (!is_leaf || mask) {
		return 8 + (uint16_t)__builtin_arm_clz64(mask) / 8;
	}

	keys4.val[0][0] = *vms_keyp(node, 17);
	keys4.val[0][1] = *vms_keyp(node, 18);
	keys4.val[1][0] = *vms_keyp(node, 19);
	keys4.val[1][1] = ~0ull;

	vcmp4.val[0] = (uint8x16_t)(key < keys4.val[0]);
	vcmp4.val[1] = (uint8x16_t)(key < keys4.val[1]);

	mask = (uint64_t)vqtbl2_u8(vcmp4, (uint8x8_t)indices);
	return 16 + (uint16_t)__builtin_arm_clz64(mask) / 8;
}

/*!
 * @brief
 * Computes the hole mask for an internal node
 *
 * @discussion
 * This function relies on @c vms_node_set_count() setting unused hole masks
 * to 0, and always performs a vectorized "or" of all 15 slots at once.
 */
static uint32_t
vms_holes_inner(vm_map_store_node_t node)
{
	static_assert(VMS_NODE_FANOUT == 15);
	uintptr_t    base = (uintptr_t)vms_holesp(node, 0) - sizeof(uint32_t);
	uint32x4x4_t vec4;
	uint32x4_t   vec;

	vec4 = vld1q_u32_x4((void *)base);
	vec4.val[0][0] = 0;
	vec = vec4.val[0] | vec4.val[1] | vec4.val[2] | vec4.val[3];

	return vec[0] | vec[1] | vec[2] | vec[3];
}

#else /* !VMS_USE_NEON */

__attribute__((always_inline, overloadable))
static uint16_t
vms_scan(vm_map_store_node_t node, vm_map_address_t k, bool is_leaf __unused)
{
	uint16_t l = 1, r = node->vmsn_count;

	while (l < r) {
		uint16_t i = (l + r) / 2;

		if (k == *vms_keyp(node, i)) {
			return i;
		}

		if (k < *vms_keyp(node, i)) {
			r = i;
		} else {
			l = i + 1;
		}
	}

	return l - 1;
}

static uint32_t
vms_holes_inner(vm_map_store_node_t node)
{
	uint32_t mask = 0;

	for (uint16_t i = 0; i < node->vmsn_count; i++) {
		mask |= *vms_holesp(node, i);
	}

	return mask;
}

#endif /* !VMS_USE_NEON */

__attribute__((always_inline, overloadable))
static uint16_t
vms_scan(vm_map_store_node_t node, vm_map_address_t k)
{
	return vms_scan(node, k, vms_is_leaf(node));
}

/*!
 * @brief
 * Returns the single-bit mask corresponding of a hole of size @c size
 * for the node hole masks.
 *
 * @discussion
 * This function rounds the size class down.
 */
__attribute__((always_inline))
static uint32_t
vms_hole_mask_for_size_class(vm_map_size_t size)
{
	uint32_t bit = flsll(size >> (PAGE_MIN_SHIFT + 1));

	return 1u << MIN(bit, 31);
}

/*!
 * @brief
 * Returns the search mask to look up for hole of size @c size.
 *
 * @discussion
 * This sets all bits above the ones returned by
 * @c vms_hole_mask_for_size_class() including that bit.
 */
__attribute__((always_inline))
static uint32_t
vms_hole_mask_for_lookup(vm_map_size_t size)
{
	return -vms_hole_mask_for_size_class(size);
}

__attribute__((noinline))
static uint32_t
vms_holes_leaf(vm_map_store_node_t node)
{
	uint32_t mask = 0;

	for (uint16_t i = 0; i < node->vmsn_count; i++) {
		if (vms_is_null(*vms_valp(node, i))) {
			mask |= vms_hole_mask_for_size_class(vms_size(node, i));
		}
	}

	return mask;
}

__attribute__((always_inline))
__vms_extern(uint32_t)
vms_holes(vm_map_store_node_t node)
{
	return vms_is_leaf(node) ? vms_holes_leaf(node) : vms_holes_inner(node);
}


#pragma mark vm map store path

__vms_extern(vms_path_t)
vms_path_init(vms_path_t path, vm_map_store_root_t root)
{
	path->vmsp_cur   = (vms_slot_t){ root.vmsr_root, 0 };
	path->vmsp_pos   = 0;
	path->vmsp_depth = root.vmsr_depth;
	path->vmsp_stack = path->vmsp_inline;

	if (__improbable(root.vmsr_depth > VMS_PATH_INLINE)) {
		path->vmsp_stack = kalloc_type(struct vms_slot,
		    root.vmsr_depth, Z_WAITOK_ZERO_NOFAIL);
	}

	return path;
}

__vms_extern(void)
vms_path_destroy(vms_path_t path)
{
	if (__improbable(path->vmsp_depth > VMS_PATH_INLINE)) {
		kfree_type(struct vms_slot, path->vmsp_depth,
		    path->vmsp_stack);
	}
	path->vmsp_depth = 0;
	path->vmsp_stack = NULL;
}

static void
vms_path_scan(vms_path_t path, vm_map_address_t addr)
{
	path->vmsp_cur.vmss_idx = vms_scan(vms_node(path->vmsp_cur), addr);
}

/*!
 * @brief
 * Scan for a hole in an internal node, by updating a resolution path.
 *
 * @param path          The path to scan for, the current position
 *                      must not be a leaf.
 * @param mask          The hole mask search mask, as returned by
 *                      @c vms_hole_mask_for_lookup().
 * @param dir           The direction for the scan (+1 forward, -1 backwards).
 *
 * @returns
 * - true               a new candidate to descend into has been found.
 * - false              no hole was found.
 */
static bool
vms_path_scan_holes_in_node(vms_path_t path, uint32_t mask, int dir)
__attribute__((diagnose_if(dir != -1 && dir != 1, "dir must be +1 or -1", "error")))
{
	vms_slot_t slot  = path->vmsp_cur;
	uint16_t   count = vms_node(slot)->vmsn_count;

	if (dir < 0) {
		do {
			if (*vms_holesp(slot) & mask) {
				path->vmsp_cur.vmss_idx = slot.vmss_idx;
				return true;
			}
		} while (slot.vmss_idx-- > 0);

		path->vmsp_cur.vmss_idx = 0;
	} else {
		while (slot.vmss_idx < count) {
			if (*vms_holesp(slot) & mask) {
				path->vmsp_cur.vmss_idx = slot.vmss_idx;
				return true;
			}
			slot.vmss_idx += 1;
		}

		/*
		 * set the index to an invalid one past count,
		 * the caller must call vms_path_iter_{next,prev}().
		 */
		path->vmsp_cur.vmss_idx = VMS_NODE_FANOUT;
	}

	return false;
}

/*!
 * @brief
 * Scan for a hole in an internal node, by updating a resolution path.
 *
 * @param path          The path to scan for, the current position
 *                      must be a leaf.
 * @param size          The hole size to look for.
 * @param dir           The direction for the scan (+1 forward, -1 backwards).
 *
 * @returns
 * - true               a hole of at least @c size bytes has beeen found.
 * - false              no hole was found.
 */
static bool
vms_path_scan_holes_in_leaf(vms_path_t path, vm_map_size_t size, int dir)
__attribute__((diagnose_if(dir != -1 && dir != 1, "dir must be +1 or -1", "error")))
{
	vms_slot_t slot  = path->vmsp_cur;
	uint16_t   count = vms_node(slot)->vmsn_count;

	if (dir < 0) {
		do {
			if (vms_slot_is_null(slot) && vms_size(slot) >= size) {
				path->vmsp_cur.vmss_idx = slot.vmss_idx;
				return true;
			}
		} while (slot.vmss_idx-- > 0);

		path->vmsp_cur.vmss_idx = 0;
	} else {
		while (slot.vmss_idx < count) {
			if (vms_slot_is_null(slot) && vms_size(slot) >= size) {
				path->vmsp_cur.vmss_idx = slot.vmss_idx;
				return true;
			}
			slot.vmss_idx += 1;
		}

		/*
		 * set the index to an invalid one past count,
		 * the caller must call vms_path_iter_{next,prev}().
		 */
		path->vmsp_cur.vmss_idx = VMS_LEAF_FANOUT;
	}

	return false;
}


__attribute__((always_inline))
static inline void
vms_path_push(vms_path_t path)
{
	path->vmsp_stack[path->vmsp_pos++] = path->vmsp_cur;
	path->vmsp_cur.vmss_ptr = *vms_nodep(path->vmsp_cur);
	path->vmsp_cur.vmss_idx = 0;
}

__attribute__((always_inline))
__result_use_check
static inline bool
vms_path_pop(vms_path_t path)
{
	if (__probable(path->vmsp_pos)) {
		path->vmsp_cur = path->vmsp_stack[--path->vmsp_pos];
		return true;
	}
	return false;
}

__attribute__((noinline))
__vms_extern(vms_slot_t)
vms_path_resolve(vms_path_t path, vm_map_address_t addr)
{
	assert(path->vmsp_pos == 0);

	for (uint32_t pos = 0, depth = path->vmsp_depth; pos < depth; pos++) {
		vms_path_scan(path, addr);
		vms_path_push(path);
	}
	vms_path_scan(path, addr);
	return path->vmsp_cur;
}

/*!
 * @brief
 * Iterates to the next slot in path traversal iteration order
 *
 * @discussion
 * Note: this is not the inverse of @c vms_path_iter_prev(),
 *       considering the tree below the "prev" of "G" is "B",
 *       but the "next" of "B" is "C".
 *
 *                        R
 *            ╭───────────┼───────────╮
 *            A           B           C
 *        ╭───┼───╮   ╭───┼───╮   ╭───┼───╮
 *        D   E   F   G   H   I   J   K   L
 *
 * @returns
 * - true               A new slot was found
 * - false              The iteration ended
 */
__result_use_check
static bool
vms_path_iter_next(vms_path_t path)
{
	while (vms_slot_is_valid(path->vmsp_cur) || vms_path_pop(path)) {
		vm_map_store_node_t node = vms_node(path->vmsp_cur);

		if (path->vmsp_cur.vmss_idx + 1 < node->vmsn_count) {
			path->vmsp_cur.vmss_idx += 1;
			return true;
		}

		path->vmsp_cur = VMS_SLOT_INVALID;
	}

	return false;
}

/*!
 * @brief
 * Iterates to the previous slot in path traversal iteration order.
 *
 * @discussion
 * Note: this is not the inverse of @c vms_path_iter_next(),
 *       considering the tree below the "prev" of "G" is "B",
 *       but the "next" of "B" is "C".
 *
 *                        R
 *            ╭───────────┼───────────╮
 *            A           B           C
 *        ╭───┼───╮   ╭───┼───╮   ╭───┼───╮
 *        D   E   F   G   H   I   J   K   L
 *
 * @returns
 * - true               A new slot was found
 * - false              The iteration ended
 */
__result_use_check
static bool
vms_path_iter_prev(vms_path_t path)
{
	while (vms_slot_is_valid(path->vmsp_cur) || vms_path_pop(path)) {
		if (path->vmsp_cur.vmss_idx > 0) {
			path->vmsp_cur.vmss_idx -= 1;
			return true;
		}

		path->vmsp_cur = VMS_SLOT_INVALID;
	}

	return false;
}

/*!
 * @brief
 * Updates the start keys upwards in a B+tree.
 *
 * @discussion
 * This function is used when the start key of a node changed,
 * and as a result its parents must be notified to update their keys.
 *
 * @param path          The path leading to the node whose start changed.
 * @param start         The new start address for the node.
 */
static void
vms_path_update_start(vms_path_t path, vm_map_address_t start)
{
	*vms_keyp(path->vmsp_cur) = start;
	if (path->vmsp_cur.vmss_idx) {
		return;
	}
	for (uint32_t pos = path->vmsp_pos; pos-- > 0;) {
		*vms_keyp(path->vmsp_stack[pos]) = start;
		if (path->vmsp_stack[pos].vmss_idx) {
			break;
		}
	}
}

/*!
 * @brief
 * Updates the hole mask upwards in a B+tree.
 *
 * @discussion
 * This function will update holes until it notices that the hole masks no
 * longer change.
 *
 * @param path          The path leading to the node whose holes changed.
 * @param pos           The position in the path at which update must start.
 * @param node          A pointer to the node whose holes changed.
 */
__attribute__((noinline))
static void
vms_path_update_holes_lazily(
	vms_path_t              path,
	uint32_t                pos,
	vm_map_store_node_t     node)
{
	uint32_t mask = 0;

	while (pos-- > 0) {
		vms_slot_t slot  = path->vmsp_stack[pos];
		uint32_t   omask = *vms_holesp(slot);

		if (node) {
			mask  = vms_holes(node);
		} else {
			mask |= omask;
		}
		if (mask == omask) {
			break;
		}

		*vms_holesp(slot) = mask;
		node = (~mask & omask) ? vms_node(slot) : NULL;
	}
}

/*!
 * @brief
 * Updates the hole mask and start position upwards in a B+tree.
 *
 * @discussion
 * This function is a combination of @c vms_path_update_start()
 * and @c vms_path_update_holes_lazily() to be used when a node was split,
 * to update the holes and start of the right hand side node.
 */
__attribute__((noinline))
static void
vms_path_update_next_holes_lazily(
	vms_path_t              path,
	uint32_t                pos,
	vm_map_store_node_t     node,
	vm_map_address_t        start)
{
	uint32_t mask = 0;

	while (pos-- > 0) {
		vms_slot_t slot  = vms_slot_next(path->vmsp_stack[pos]);
		uint32_t   omask = *vms_holesp(slot);

		if (node) {
			mask  = vms_holes(node);
		} else {
			mask |= omask;
		}

		*vms_keyp(slot)   = start;
		*vms_holesp(slot) = mask;

		if (slot.vmss_idx > 0) {
			if (mask == omask) {
				break;
			}
			return vms_path_update_holes_lazily(path, pos, vms_node(slot));
		}

		node = (~mask & omask) ? vms_node(slot) : NULL;
	}
}

/*!
 * @brief
 * Eagerly update the hole mask position upwards in a B+tree.
 */
static void
vms_path_update_holes_eagerly(vms_path_t path, uint32_t pos, uint32_t mask)
{
	while (pos-- > 0) {
		vms_slot_t slot = path->vmsp_stack[pos];

		*vms_holesp(slot) = mask;
		mask = vms_holes_inner(vms_node(slot));
	}
}


#pragma mark vm map store creation/destruction

/*
 * This is done during EARLY_BOOT as it needs the corecrypto module to be
 * set up.
 */
__startup_func
static void
vm_map_store_crypto_init(void)
{
	vm_size_t ctx_size = crypto_random_kmem_ctx_size();

	ks_rng_ctx = zalloc_percpu_permanent(ctx_size, ZALIGN_PTR);
	zpercpu_foreach(ctx, ks_rng_ctx) {
		crypto_random_kmem_init(ctx);
	}
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, vm_map_store_crypto_init);

__vms_extern(vm_map_store_node_t)
vms_node_alloc(bool is_leaf)
{
	vm_map_store_node_t node;

	node = zalloc_id(ZONE_ID_VM_MAP_NODES, Z_WAITOK_ZERO_NOFAIL);
	node->vmsn_leaf = is_leaf;
	return node;
}

__attribute__((always_inline))
__vms_extern(void)
vms_node_set_count(vm_map_store_node_t node, uint16_t count)
{
	assert(count <= vms_fanout(node));
#if VMS_USE_NEON
	/*
	 * See vms_scan() we need this marker because the neon scan
	 * doesn't respect the "count", this marker serves as a "stop".
	 */
	if (count < vms_fanout(node)) {
		*vms_keyp(node, count) = ~0ull;
	}
	/*
	 * See vms_holes_inner() which doesn't respect the count,
	 * and assumes unused masks to be 0.
	 */
	if (vms_is_inner(node) && count < node->vmsn_count) {
		__builtin_bzero(vms_holesp(node, count),
		    (node->vmsn_count - count) * sizeof(uint32_t));
	}
#endif /* VMS_USE_NEON */

	node->vmsn_count = count;
}


static void
vms_node_free(vm_map_store_root_t *root, vm_map_store_node_t node)
{
	if (root->vmsr_hint == node) {
		root->vmsr_hint = NULL;
	}
	zfree_id(ZONE_ID_VM_MAP_NODES, node);
}

static vm_map_store_node_ptr_t
vms_node_list_free(vm_map_store_root_t *root, vm_map_store_node_t node)
{
	vm_map_store_node_ptr_t ret = { };

	if (vms_is_inner(node)) {
		ret = *vms_nodep(node, 0);
	}

	while (node) {
		vm_map_store_node_t next = vms_next_sibling(node);
		vms_node_free(root, node);
		node = next;
	}

	return ret;
}

/*!
 * @brief
 * Initializes the tree with a single hole covering [0, UINT64_MAX]
 */
__vms_extern(void)
vms_root_init(vm_map_store_root_t * root)
{
	vm_map_store_node_t leaf = vms_node_alloc(true);

	/*
	 * Implicitly because vms_node_alloc() zeroes the allocation"
	 *
	 * *vms_keyp(leaf, 0) = 0;
	 * *vms_valp(leaf, 0) = VMS_POINTER_NULL;
	 */
	vms_node_set_count(leaf, 1);
	root->vmsr_root = vms_pointer(leaf);
}

__vms_extern(void)
vms_root_destroy(vm_map_store_root_t * root)
{
	vm_map_store_node_ptr_t ptr = root->vmsr_root;

	while (!vms_is_null(ptr)) {
		ptr = vms_node_list_free(root, vms_node(ptr));
	}

	*root = (struct vm_map_store_root){ };
}

static void
vm_map_hdr_store_init(struct vm_map_header *hdr, uint32_t pageshift, bool cpy)
{
	hdr->links.prev     = CAST_TO_VM_MAP_ENTRY(hdr);
	hdr->links.next     = CAST_TO_VM_MAP_ENTRY(hdr);
	hdr->page_shift     = (uint16_t)pageshift;
	hdr->is_vm_map_copy = cpy;
	vm_map_header_init_invalid_lock(hdr);
}

void
vm_map_copy_store_init(vm_map_copy_t copy, uint32_t pageshift)
{
	vm_map_hdr_store_init(&copy->cpy_hdr, pageshift, true);
}

void
vm_map_store_init(vm_map_t map, uint32_t pageshift)
{
	vm_map_hdr_store_init(&map->hdr, pageshift, false);
	vms_root_init(&map->root);
}

void
vm_map_store_destroy(vm_map_t map)
{
	vms_root_destroy(&map->root);
}

void
vm_guard_object_enable(void)
{
	vmgo_enabled = true;
}

void
vm_guard_object_slab_init(vm_guard_object_slab_t slab)
{
	/*
	 * Callers all pass zero initialized memory, this function exists
	 * for forward compatbility if new fields are added that require
	 * non trivial initialization.
	 */
	(void)slab;
}

void
vm_map_guard_object_slab_init(vm_map_t map)
{
	if (map->guard_object_slabs != NULL) {
		return;
	}

	if (VM_MAP_IS_EXOTIC(map)) {
		return;
	}

	vm_map_ilk_lock(map);

	if (map->guard_object_slabs == NULL) {
		struct vmgo_slab_pair *pair;

		pair = zalloc_flags(KT_GO_SLAB, Z_WAITOK_ZERO_NOFAIL);
		vm_guard_object_slab_init(&pair->pair[0]);
		vm_guard_object_slab_init(&pair->pair[1]);
		map->guard_object_slabs = pair->pair;
	}

	vm_map_ilk_unlock(map);
}

void
vm_map_guard_object_slab_destroy(vm_map_t map)
{
	struct vmgo_slab_pair *pair;

	vm_map_ilk_lock(map);
	assert(map->hdr.nentries == 0);
	pair = __container_of(map->guard_object_slabs,
	    struct vmgo_slab_pair, pair[0]);
	map->guard_object_slabs = NULL;
	vm_map_ilk_unlock(map);

	assert(memcmp_zero_ptr_aligned(pair, sizeof(*pair)) == 0);
	zfree(KT_GO_SLAB, pair);
}


#pragma mark vm guard object helpers

/*!
 * @abstract
 * Returns the proper slab queue for a specified granule
 *
 * @param slab          The slab to return a queue for.
 * @param granule       The specified granule.
 * @param full          Whether to return the full or partial queue.
 */
__attribute__((const, always_inline, overloadable))
static inline vm_guard_object_chunk_t *
vmgo_slab_queue(
	vm_guard_object_slab_t  slab,
	uint8_t                 granule,
	bool                    full)
{
	if (full) {
		return &slab->vgos_full[granule - PAGE_SHIFT];
	} else {
		return &slab->vgos_partial[granule - PAGE_SHIFT];
	}
}

/*!
 * @abstract
 * Returns the proper slab queue for a specified chunk
 *
 * @param chunk         The specified chunk.
 * @param full          Whether to return the full or partial queue.
 */
__attribute__((const, always_inline, overloadable))
static inline vm_guard_object_chunk_t *
vmgo_slab_queue(vm_guard_object_chunk_t chunk, bool full)
{
	return vmgo_slab_queue(chunk->vgoc_slab, chunk->vgoc_granule, full);
}

/*!
 * @abstract
 * Enqueue a chunk onto a specified chunk list
 */
static void
vmgo_chunk_enqueue(
	vm_guard_object_chunk_t *const list,
	vm_guard_object_chunk_t chunk)
{
	vm_map_store_val_ptr_t  head_ptr, tail_ptr;
	vm_guard_object_chunk_t head, tail;

	assert(vms_is_null(chunk->vgoc_prev) && vms_is_null(chunk->vgoc_next));

	if (*list == NULL) {
		chunk->vgoc_next = chunk->vgoc_prev = vms_pointer(chunk);
		*list = chunk;
		return;
	}

	head     = *list;
	head_ptr = vms_pointer(head);
	tail_ptr = head->vgoc_prev;
	tail     = vms_chunk(tail_ptr);

	if (!vms_equal(tail->vgoc_next, head_ptr)) {
		ml_fatal_trap_invalid_list_linkage((uintptr_t)tail);
	}

	chunk->vgoc_next = head_ptr;
	chunk->vgoc_prev = tail_ptr;
	head->vgoc_prev = tail->vgoc_next = vms_pointer(chunk);
}

/*!
 * @abstract
 * Dequeue a chunk from a specified chunk list
 */
static void
vmgo_chunk_dequeue(vm_guard_object_chunk_t *list, vm_guard_object_chunk_t chunk)
{
	vm_map_store_val_ptr_t prev = chunk->vgoc_prev;
	vm_map_store_val_ptr_t next = chunk->vgoc_next;
	vm_map_store_val_ptr_t self = vms_pointer(chunk);

	if (!vms_equal(vms_chunk(prev)->vgoc_next, self) ||
	    !vms_equal(vms_chunk(next)->vgoc_prev, self)) {
		ml_fatal_trap_invalid_list_linkage((uintptr_t)chunk);
	}

	if (chunk == vms_chunk(next)) {
		*list = NULL;
	} else {
		vms_chunk(prev)->vgoc_next = next;
		vms_chunk(next)->vgoc_prev = prev;
		if (*list == chunk) {
			*list = vms_chunk(next);
		}
	}

	chunk->vgoc_prev = chunk->vgoc_next = VMS_POINTER_NULL;
}

/*!
 * @brief
 * Update a chunk with a mask of newly freed elements.
 *
 * @discussion
 * This function will update the various counters of the chunk
 * and return whether all slots have been freed, in which case
 * the caller is supposed to free the chunk.
 *
 * @param chunk         The chunk to update
 * @param freed_mask    The mask of slots that are now freed
 * @returns
 * - true               The chunk has been dequeued and should be freed
 * - false              The chunk still has used elements.
 */
static bool
vmgo_chunk_free_slots(vm_guard_object_chunk_t chunk, uint64_t freed_mask)
{
	const bool was_full = (chunk->vgoc_available == 0);
	uint8_t    qtn      = chunk->vgoc_quarantined;
	uint64_t   bitmap   = vmgo_bitmap(chunk) | freed_mask;

	chunk->vgoc_bitmap |= bitmap;

	if (bitmap == bits_mask(chunk->vgoc_count)) {
		vmgo_chunk_dequeue(vmgo_slab_queue(chunk, was_full), chunk);
		chunk->vgoc_available   = 0;
		chunk->vgoc_quarantined = 0;
		return true;
	}

	if (freed_mask & (freed_mask - 1)) {
		qtn += __builtin_popcountll(freed_mask);
	} else {
		/* power of 2 */
		qtn += 1;
	}

	assert3u(chunk->vgoc_available + qtn + vmgo_chunk_guards(chunk), ==,
	    __builtin_popcountll(bitmap));

	if (chunk->vgoc_available + qtn >= vmgo_chunk_guards(chunk)) {
		chunk->vgoc_available  += qtn;
		chunk->vgoc_quarantined = 0;
	} else {
		chunk->vgoc_quarantined = qtn;
	}

	if (was_full && chunk->vgoc_available) {
		vmgo_chunk_dequeue(vmgo_slab_queue(chunk, true), chunk);
		vmgo_chunk_enqueue(vmgo_slab_queue(chunk, false), chunk);
	}

	return false;
}

/*!
 * @brief
 * Update a chunk skiplist after an entry has been inserted.
 *
 * @discussion
 * Chunks have an 8-way skiplist that this function maintains.
 *
 * @param map           The map the entry was inserted into.
 * @param entry         An entry that was inserted into a chunk.
 */
static void
vmgo_chunk_skiplist_insert(vm_map_t map, vm_map_entry_t entry)
{
	vm_guard_object_chunk_t chunk = vms_chunk(entry->vme_chunk);
	vm_map_store_val_ptr_t  ptr   = vms_pointer(entry);
	vm_map_entry_t          prev  = entry->vme_prev;
	uint32_t                idx   = 0;

	if (prev != vm_map_to_entry(map) &&
	    vmgo_chunk_start(chunk) < prev->vme_end) {
		idx = vmgo_chunk_skiplist_idx(chunk, prev->vme_end - 1) + 1;
	}

	assert3u(entry->vme_end, <=, vmgo_chunk_end(chunk));
	while (idx <= vmgo_chunk_skiplist_idx(chunk, entry->vme_end - 1)) {
		chunk->vgoc_ptrs[idx++] = ptr;
	}
}

/*!
 * @brief
 * Selects a random set bit in the chunk bitmask.
 *
 * @param chunk         The specified chunk.
 * @returns             The position of the selected bit.
 */
__static_testable __mockable uint32_t
vmgo_chunk_select_random_slot(vm_guard_object_chunk_t chunk)
{
	uint32_t free   = vmgo_chunk_free_count(chunk);
	uint64_t bitmap = vmgo_bitmap(chunk);
	uint32_t zeroes = 0;
	uint32_t ones   = 0;
	uint64_t n      = 0;

	assert(free > 0 && __builtin_popcountll(bitmap) == free);

	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		n = kmem_get_random16((uint16_t)free - 1);
	} else {
		disable_preemption();
		crypto_random_uniform(zpercpu_get(ks_rng_ctx), free, &n);
		enable_preemption();
	}

	/* find the position of the <n>-th bit set in bitmap */
	while (bitmap) {
		uint32_t count = __builtin_ctzll(bitmap);

		zeroes += count;
		bitmap    >>= count;
		if (__probable(~bitmap)) {
			count = __builtin_ctzll(~bitmap);
		} else {
			count = 64;
		}
		if (count + ones > n) {
			return (uint32_t)(zeroes + n);
		}
		ones += count;
		bitmap   >>= count;
	}

	mach_assert_abort("couldn't find bit");
}

/*!
 * @brief
 * Allocates a new chunk for the specified size class, at a specified address.
 *
 * @param map           The map to reserve free space from.
 * @param slab          The slab to insert the newly allocated chunk into.
 * @param start         The address to allocate the chunk at.
 * @param size          The total size of the chunk.
 * @param count_shift   The count shift for this chunk.
 * @param granule       The granule to allocate for.
 * @returns             A newly allocated chunk
 */
static vm_guard_object_chunk_t
vmgo_chunk_alloc_fixed(
	vm_map_t                map,
	vm_guard_object_slab_t  slab,
	vm_map_address_t        start,
	vm_map_size_t           size,
	uint8_t                 count_shift,
	uint8_t                 granule)
{
	VMS_PATH_DECLARE(path, map->root);
	vm_guard_object_chunk_t chunk = NULL;
	vms_slot_t slot;
	uint8_t count = (uint8_t)(1u << count_shift);

	chunk = zalloc_id(ZONE_ID_VM_GO_CHUNKS, Z_WAITOK_ZERO_NOFAIL);
	chunk->vgoc_start       = (uint32_t)(start >> VMGO_START_SHIFT);
	chunk->vgoc_granule     = granule;
	chunk->vgoc_count       = count;
	chunk->vgoc_count_shift = count_shift;
	chunk->vgoc_bitmap      = bits_mask(1u << count_shift);
	chunk->vgoc_slab        = slab;

	/*
	 * the chunk start is highly packed and only works due to
	 * alignment of the chunk allocation being sufficient.
	 */
	assert(MIN(VMGO_MAX_ALIGNMENT, size - 1) >= bits_mask(VMGO_START_SHIFT));
	assert(start == vmgo_chunk_start(chunk));

	chunk->vgoc_available = count - MAX(1, count / 4);
	vmgo_chunk_enqueue(vmgo_slab_queue(chunk, false), chunk);

	slot = vms_path_resolve(path, start);
	vms_slot_assert_hole(slot);
	vms_slot_assert_contains(slot, start + size - 1);

	__vms_mut_insert(&map->root, path, start, start + size, vms_pointer(chunk));

	return chunk;
}

__attribute__((noinline))
__vms_extern(vm_guard_object_chunk_t)
vmgo_chunk_alloc_anywhere(
	vm_map_t                map,
	vm_guard_object_slab_t  slab,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	uint8_t                 granule,
	vm_map_address_t        mask)
{
	vm_map_store_rsv_t rsv = { };
	uint8_t            count_shift;
	vm_map_size_t      size;
	kern_return_t      kr;

	if (granule <= vmgo_size_to_granule(VMGO_CHUNK_LIMIT_4)) {
		static_assert(4 + PAGE_MIN_SHIFT >= VMGO_START_SHIFT,
		    "number of slots will meet alignment requirements");
		count_shift = 4; /* 16 slots */
	} else if (granule <= vmgo_size_to_granule(VMGO_CHUNK_LIMIT_3)) {
		count_shift = 3; /* 8 slots */
	} else if (granule <= vmgo_size_to_granule(VMGO_CHUNK_LIMIT_2)) {
		count_shift = 2; /* 4 slots */
	} else {
		count_shift = 1; /* 2 slots */
	}

	size  = 1ull << (count_shift + granule);
	mask |= VMGO_MAX_ALIGNMENT & (size - 1);

	kr = vm_map_store_find_space(map, range, VM_MAP_KERNEL_FLAGS_ANYWHERE(
		    .vmkf_last_free = vmk_flags.vmkf_last_free),
	    size, mask, &rsv);

	if (kr == KERN_SUCCESS) {
		return vmgo_chunk_alloc_fixed(map, slab,
		           vmsr_start(rsv), size, count_shift, granule);
	}

	return NULL;
}

__vms_extern(vm_map_address_t)
vmgo_chunk_reserve_slot(vm_guard_object_chunk_t chunk, uint32_t idx)
{
	uint64_t bitmap = vmgo_bitmap(chunk);

	assert(chunk->vgoc_available > 0 && bit_test(bitmap, idx));
	bit_clear(bitmap, idx);
	chunk->vgoc_bitmap = bitmap;

	if (--chunk->vgoc_available == 0) {
		vmgo_chunk_dequeue(vmgo_slab_queue(chunk, false), chunk);
		vmgo_chunk_enqueue(vmgo_slab_queue(chunk, true), chunk);
	}

	return vmgo_chunk_slot_start(chunk, idx);
}


#pragma mark vm map store lookup

/*!
 * @brief
 * Scans for the first VM map entry right after the specified slot
 */
static inline vm_map_entry_t
vms_slot_next_entry(vm_map_t map, vms_slot_t slot)
{
	slot = vms_slot_next(slot);

	while (vms_slot_is_valid(slot)) {
		if (vms_slot_is_entry(slot)) {
			return vms_slot_entry(slot);
		}

		if (vms_slot_is_chunk(slot)) {
			vm_guard_object_chunk_t chunk = vms_slot_chunk(slot);

			assert(!vms_is_chunk(chunk->vgoc_ptrs[0]));

			/*
			 * During a fixed-overwrite mapping replacement,
			 * it is possible for vm_map_enter() to drop the map
			 * lock, in which case a lookup can observe a chunk
			 * that has no entries.
			 */
			if (vms_is_entry(chunk->vgoc_ptrs[0])) {
				return vms_entry(chunk->vgoc_ptrs[0]);
			}
		}

		slot = vms_slot_next(slot);
	}

	return vm_map_to_entry(map);
}

/*!
 * @brief
 * Given a map and entry, returns the start of the hole before that entry,
 * or the start of @c entry if none exists.
 *
 * @param map           The specified map
 * @param entry         The specified entry, belonging to @c map
 */
static vm_map_address_t
vm_map_store_prev_hole_start(vm_map_t map, vm_map_entry_t entry)
{
	vm_map_entry_t prev = entry->vme_prev;

	if (__improbable(prev == vm_map_to_entry(map))) {
		return 0;
	}

	if (VME_IN_CHUNK(prev) &&
	    !vms_equal(prev->vme_chunk, entry->vme_chunk)) {
		return vmgo_chunk_end(vms_chunk(prev->vme_chunk));
	}

	return prev->vme_end;
}

/*!
 * @brief
 * Given a map and entry, returns the end of the hole after that entry,
 * or the end of @c entry if none exists.
 *
 * @param map           The specified map
 * @param entry         The specified entry, belonging to @c map
 */
static vm_map_address_t
vm_map_store_next_hole_end(vm_map_t map, vm_map_entry_t entry)
{
	vm_map_entry_t next = entry->vme_next;

	if (__improbable(next == vm_map_to_entry(map))) {
		return ~0ull;
	}

	if (VME_IN_CHUNK(next) &&
	    !vms_equal(next->vme_chunk, entry->vme_chunk)) {
		return vmgo_chunk_start(vms_chunk(next->vme_chunk));
	}

	return next->vme_start;
}

/*!
 * @brief
 * Scan for an entry containing a specified address starting at a given entry.
 *
 * @discussion
 * This function complexity is O(n) and should be used in cases where it is
 * known that the scan will be short, otherwise a b+tree based lookup is
 * preferrable.  The typical callers is to lookup an entry within the skiplist
 * of a chunk.
 *
 * @param map           The map @c entry belongs to.
 * @param entry         The entry to start scanning from.
 * @param address       The address to lookup.
 * @param or_next       Whether to return @c VM_MAP_ENTRY_NULL or the first
 *                      entry starting right after @c address if no entry
 *                      contains it.
 *
 * @returns
 * - a valid entry      An entry containing @c address.
 *
 * - a valid entry      The first entry whose start is after @c address if no
 *                      entry containing it is found and @c or_next is true.
 *
 * - VM_MAP_ENTRY_NULL  If no entry is found containing @c address,
 *                      and @c or_next is false.
 */
static inline vm_map_entry_t
vm_map_store_entry_scan(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_offset_t         address,
	bool                    or_next)
{
	while (entry != vm_map_to_entry(map) && entry->vme_end <= address) {
		entry = entry->vme_next;
	}
	if (entry != vm_map_to_entry(map) && entry->vme_start <= address) {
		return entry;
	}
	return or_next ? entry : VM_MAP_ENTRY_NULL;
}

__vms_extern(vms_slot_t)
vm_map_store_lookup(vm_map_t map, vm_map_address_t addr)
{
	uint32_t                depth = map->root.vmsr_depth;
	vm_map_store_node_t     node  = map->root.vmsr_hint;
	vm_map_store_node_ptr_t ptr   = vms_pointer(node);

	if (node == NULL || addr < vms_start(node) || vms_end(node) <= addr) {
		ptr  = map->root.vmsr_root;
		node = vms_node(ptr);

		for (uint16_t pos = 0; pos < depth; pos++) {
			ptr  = *vms_nodep(node, vms_scan(node, addr, false));
			node = vms_node(ptr);
		}

		map->root.vmsr_hint = node;
	}

	return (vms_slot_t){ ptr, vms_scan(node, addr, true) };
}

__attribute__((always_inline))
vm_map_entry_t
vm_map_store_lookup_entry(vm_map_t map, vm_map_offset_t addr, bool or_next)
{
	vms_slot_t slot;

	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_ANY);

	slot = vm_map_store_lookup(map, addr);

	if (vms_slot_is_entry(slot)) {
		return vms_slot_entry(slot);
	}

	if (vms_slot_is_chunk(slot)) {
		vm_guard_object_chunk_t chunk = vms_slot_chunk(slot);
		uint32_t                idx   = vmgo_chunk_skiplist_idx(chunk, addr);

		if (vms_is_entry(chunk->vgoc_ptrs[idx])) {
			vm_map_entry_t entry = vms_entry(chunk->vgoc_ptrs[idx]);

			return vm_map_store_entry_scan(map, entry, addr, or_next);
		}
	}

	if (or_next) {
		return vms_slot_next_entry(map, slot);
	}

	return VM_MAP_ENTRY_NULL;
}

vm_map_entry_t
vm_map_store_lookup_entry_kdp(vm_map_t map, vm_map_offset_t address)
{
	vms_slot_t slot;

	assert(!not_in_kdp && !kdp_vm_map_is_acquired_exclusive(map));

	slot = vm_map_store_lookup(map, address);
	return vms_slot_is_entry(slot) ? vms_slot_entry(slot) : VM_MAP_ENTRY_NULL;
}

vm_map_size_t
vm_map_store_lookup_hole(
	vm_map_t                map,
	vm_map_offset_t         address,
	vm_map_address_t        address_max)
{
	vm_map_address_t end;
	vms_slot_t       slot;

	assert_vm_map_ilk_owned_ignore_sealed(map, LCK_RW_TYPE_ANY);

	slot = vm_map_store_lookup(map, address);
	if (vms_slot_is_null(slot)) {
		end = vms_end(slot);
		return MIN(address_max, end) - address;
	}
	return 0;
}

bool
vm_map_store_has_entries(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_address_t        end)
{
	vm_map_entry_t entry = vm_map_store_lookup_entry(map, start, true);

	return start != end && entry != vm_map_to_entry(map) && entry->vme_start < end;
}

/*!
 * @brief
 * Looks up a hole within a specified range forward.
 *
 * @param map           The map to look a hole into.
 * @param range         The range to find the hole into.
 * @param vmk_flags     Flags affecting the lookup (vmkf_guard_before only).
 * @param size          The size of the hole being looked up.
 * @param mask          The required alignment for the hole
 *                      (if @c vmk_flags.vmkf_guard_before is set, this
 *                      alignment affects the start address after the guard).
 * @param rsv           The reservation being made.
 *
 * @returns
 * - KERN_SUCCESS       A hole was found
 * - KERN_NO_SPACE      No hole was found
 */
__attribute__((noinline))
static kern_return_t
vm_map_store_lookup_hole_forwards(
	vm_map_t                map,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *rsv)
{
	VMS_PATH_DECLARE(path, map->root);
	const uint32_t   smask = vms_hole_mask_for_lookup(size);
	vm_map_offset_t  guard_offset = 0;
	vm_map_address_t end;

	if (vmk_flags.vmkf_guard_before) {
		guard_offset = VM_MAP_PAGE_SIZE(map);
		assert(size > guard_offset);
		size -= guard_offset;
	} else if (map->disable_vmentry_reuse) {
		range.min_address = MAX(range.min_address,
		    map->highest_entry_end);
		guard_offset = PAGE_SIZE_64;
	}

	vms_path_scan(path, range.min_address);

	for (;;) {
		while (path->vmsp_pos < path->vmsp_depth) {
			if (vms_path_scan_holes_in_node(path, smask, +1)) {
				range.min_address = vms_start_after(path->vmsp_cur,
				    range.min_address);
				vms_path_push(path);
				vms_path_scan(path, range.min_address);
			} else if (!vms_path_iter_next(path)) {
				return KERN_NO_SPACE;
			}
		}

		if (vms_path_scan_holes_in_leaf(path, size, +1)) {
			range.min_address = vms_start_after(path->vmsp_cur,
			    range.min_address);
			if (os_add3_overflow(range.min_address,
			    guard_offset, mask, &range.min_address)) {
				return KERN_NO_SPACE;
			}
			range.min_address = range.min_address & ~mask;
			if (os_add_overflow(range.min_address, size, &end)) {
				return KERN_NO_SPACE;
			}

			if (end <= range.max_address &&
			    end <= vms_end(path->vmsp_cur)) {
				break;
			}
		}

		if (!vms_path_iter_next(path)) {
			return KERN_NO_SPACE;
		}
	}

	if (vmk_flags.vmkf_guard_before) {
		range.min_address -= guard_offset;
	}

	*rsv = vmsr_make(range.min_address,
	    vms_slot_next_entry(map, path->vmsp_cur));
	return KERN_SUCCESS;
}

/*!
 * @brief
 * Looks up a hole within a specified range backwards.
 *
 * @param map           The map to look a hole into.
 * @param range         The range to find the hole into.
 * @param vmk_flags     Flags affecting the lookup (vmkf_guard_before only).
 * @param size          The size of the hole being looked up.
 * @param mask          The required alignment for the hole
 *                      (if @c vmk_flags.vmkf_guard_before is set, this
 *                      alignment affects the start address after the guard).
 * @param rsv           The reservation being made.
 *
 * @returns
 * - KERN_SUCCESS       A hole was found
 * - KERN_NO_SPACE      No hole was found
 */
__attribute__((noinline))
static kern_return_t
vm_map_store_lookup_hole_backwards(
	vm_map_t                map,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *rsv)
{
	VMS_PATH_DECLARE(path, map->root);
	const uint32_t   smask = vms_hole_mask_for_lookup(size);
	vm_map_offset_t  guard_offset = 0;
	vm_map_address_t start;

	if (vmk_flags.vmkf_guard_before) {
		guard_offset = VM_MAP_PAGE_SIZE(map);
	}
	assert(size > guard_offset);
	size -= guard_offset;

	vms_path_scan(path, range.max_address - 1);

	for (;;) {
		while (path->vmsp_pos < path->vmsp_depth) {
			if (vms_path_scan_holes_in_node(path, smask, -1)) {
				range.max_address = vms_end_before(path->vmsp_cur,
				    range.max_address);
				vms_path_push(path);
				vms_path_scan(path, range.max_address - 1);
			} else if (!vms_path_iter_prev(path)) {
				return KERN_NO_SPACE;
			}
		}

		if (vms_path_scan_holes_in_leaf(path, size, -1)) {
			range.max_address = vms_end_before(path->vmsp_cur,
			    range.max_address);
			if (os_sub_overflow(range.max_address, size, &start)) {
				return KERN_NO_SPACE;
			}
			start = start & ~mask;
			if (os_sub_overflow(start, guard_offset, &start)) {
				return KERN_NO_SPACE;
			}

			if (start >= range.min_address &&
			    start >= vms_start(path->vmsp_cur)) {
				break;
			}
		}

		if (!vms_path_iter_prev(path)) {
			return KERN_NO_SPACE;
		}
	}

	*rsv = vmsr_make(start, vms_slot_next_entry(map, path->vmsp_cur));
	return KERN_SUCCESS;
}

__attribute__((noinline))
static kern_return_t
vm_map_store_find_space_random(
	vm_map_t                map,
	struct mach_vm_range    range,
	vm_map_size_t           size,
	vm_map_store_rsv_t     *rsv)
{
	vm_map_size_t total_size = range.max_address - range.min_address;

	if (size >= total_size) {
		return KERN_NO_SPACE;
	}

	assert(VM_MAP_PAGE_ALIGNED(size, VM_MAP_PAGE_MASK(map)));

	for (uint32_t tries = 0; tries < 1000; tries++) {
		vm_map_offset_t address = 0;
		vms_slot_t      slot;

		address = vm_map_trunc_page(range.min_address +
		    (early_random() % (total_size - size)),
		    VM_MAP_PAGE_MASK(map));

		slot = vm_map_store_lookup(map, address);
		if (vms_slot_is_null(slot) && address + size <= vms_end(slot)) {
			*rsv = vmsr_make(address, vms_slot_next_entry(map, slot));
			return KERN_SUCCESS;
		}
	}

	return KERN_NO_SPACE;
}

__attribute__((always_inline))
kern_return_t
vm_map_store_find_space(
	vm_map_t                map,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *rsv)
{
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	mask |= VM_MAP_PAGE_MASK(map);

	if (!map->disable_vmentry_reuse && vmk_flags.vmf_random_addr) {
		return vm_map_store_find_space_random(map, range, size, rsv);
	}

	if (vmk_flags.vmkf_last_free) {
		return vm_map_store_lookup_hole_backwards(map, range,
		           vmk_flags, size, mask, rsv);
	} else {
		if (map->disable_vmentry_reuse) {
			range.min_address = MAX(range.min_address,
			    map->highest_entry_end + PAGE_SIZE_64);
		}
		return vm_map_store_lookup_hole_forwards(map, range,
		           vmk_flags, size, mask, rsv);
	}
}

static bool
vm_guard_object_should_fallback(
	vm_map_t                map,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask)
{
	/*
	 * Various things that do not support or do not need guard objects:
	 *
	 * - guard-malloc (disable_vmentry_reuse)
	 * - permanent mappings
	 * - usage of superpages (intel only)
	 * - mmap(MAP_32BIT)
	 * - mmap(MAP_JIT)
	 */
	if (map->disable_vmentry_reuse ||
	    vmk_flags.vmf_permanent ||
#if __x86_64__
	    vmk_flags.vmf_superpage_size ||
#endif /* __x86_64__ */
	    vmk_flags.vmkf_map_jit ||
	    vmk_flags.vmkf_32bit_map_va) {
		return true;
	}

	/*
	 * Workaround for rdar://142262418; see comment in vm_map_store_remove.
	 * This is okay as we don't care strongly about maintaining the task's
	 * memory safety guarantees after it terminates.
	 */
	if (map->terminated) {
		return true;
	}

	/*
	 * If the requested alignment is wider than what guard objects can do,
	 * then we must delegate.
	 */
	if (mask > VMGO_MAX_ALIGNMENT) {
		return true;
	}

	/*
	 * Limit to 1Tb mappings
	 */
	if (size >= (1ull << VMGO_MAX_SIZE_SHIFT)) {
		return true;
	}

	if (map->pmap == kernel_pmap) {
#if VMGO_SMALL_CONFIG
		/*
		 * On smaller kernel address spaces, data mappings larger than
		 * VMGO_MAX_KDATA_SIZE can lead to VA exhaustion, so we must relax
		 * guard-objects.
		 */
		if (size > VMGO_MAX_KDATA_SIZE &&
		    (vmk_flags.vmkf_range_id == KMEM_RANGE_ID_DATA_SHARED ||
		    vmk_flags.vmkf_range_id == KMEM_RANGE_ID_DATA_PRIVATE)) {
			return true;
		}
#endif /* VMGO_SMALL_CONFIG */

		/* always use GO for the stacks even before launchd exists */
		if (vmk_flags.vm_tag == VM_KERN_MEMORY_STACK) {
			return false;
		}
	} else {
		switch (vmk_flags.vm_tag) {
		case VM_MEMORY_JAVASCRIPT_CORE:
		case VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR:
		case VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE:
		case VM_MEMORY_SANITIZER:
		case VM_MEMORY_TCMALLOC:
			/*
			 * JSC/WebKit GigaCages do not need guard objects.
			 * ASAN should also not use guard objects.
			 */
			return true;
		default:
			return false;
		}
	}

	/*
	 * Wait until pid 1 is made so that kext early allocations do not
	 * fragment the address space: these aren't attacker controlled.
	 */
	return !vmgo_enabled;
}

kern_return_t
vm_guard_object_find_space_anywhere(
	vm_map_t                map,
	vm_guard_object_slab_t  slab,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *rsv)
{
	vm_map_size_t           delta = 0;
	vm_map_offset_t         guard_offset = 0;
	vm_guard_object_chunk_t chunk = NULL;
	uint8_t                 granule;
	vm_map_address_t        addr;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	assert(!VM_MAP_IS_EXOTIC(map) &&
	    VM_MAP_PAGE_ALIGNED(size, VM_MAP_PAGE_MASK(map)));

	mask |= VM_MAP_PAGE_MASK(map);
	if (vmk_flags.vmkf_guard_before) {
		guard_offset = VM_MAP_PAGE_SIZE(map);
		delta = mask + 1 - guard_offset;
	}

	if (__improbable(vm_guard_object_should_fallback(map, vmk_flags, size, mask))) {
		/* signal the caller it should call vm_map_store_find_space() */
		return KERN_NOT_SUPPORTED;
	}

	granule = vmgo_size_to_granule(MAX(mask + 1, size) + delta);
	chunk   = *vmgo_slab_queue(slab, granule, false);
	if (chunk == NULL) {
		chunk = vmgo_chunk_alloc_anywhere(map, slab, range, vmk_flags,
		    granule, mask);
	}
	if (__improbable(chunk == NULL)) {
		return KERN_NO_SPACE;
	}

	addr = vmgo_chunk_reserve_slot(chunk,
	    vmgo_chunk_select_random_slot(chunk));
	addr = (addr + guard_offset + mask) & ~mask;
	*rsv = vmsr_make(addr - guard_offset, chunk);
	return KERN_SUCCESS;
}

void
vm_guard_object_find_space_abort(vm_map_t map, vm_map_store_rsv_t rsv)
{
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);

	if (vmsr_is_chunk(rsv)) {
		vm_guard_object_chunk_t chunk = vmsr_chunk(rsv);
		uint32_t idx = vmgo_chunk_slot(chunk, vmsr_start(rsv));

		assert(!bit_test(vmgo_bitmap(chunk), idx));

		if (vmgo_chunk_free_slots(chunk, BIT(idx))) {
			vm_map_address_t start = vmgo_chunk_start(chunk);
			vm_map_address_t end   = vmgo_chunk_end(chunk);
			vms_slot_t       slot;

			if (start > 0) {
				slot = vm_map_store_lookup(map, start - 1);
				if (vms_slot_is_null(slot)) {
					start = vms_start(slot);
				}
			}

			slot = vm_map_store_lookup(map, end);
			if (vms_slot_is_null(slot)) {
				end = vms_end(slot);
			}

			__vms_mut_erase(&map->root, start, end);
			zfree_id(ZONE_ID_VM_GO_CHUNKS, chunk);
		}
	}
}

bool
vm_guard_object_check_op_range(
	vm_map_entry_t          entry,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	vm_guard_object_chunk_t chunk  = vms_chunk(entry->vme_chunk);
	uint64_t                bitmap = vmgo_bitmap(chunk);
	uint32_t sidx, eidx;

	if (start < vmgo_chunk_start(chunk) || vmgo_chunk_end(chunk) < end) {
		return false;
	}

	sidx = vmgo_chunk_slot(chunk, start);
	eidx = vmgo_chunk_slot(chunk, end - 1);

	return sidx == eidx && !bit_test(bitmap, sidx);
}

#pragma mark vm map store mutation helpers

/*!
 * @brief
 * Creates a new root node for a B+tree which grew one level.
 */
static void
__vms_mut_root_make(
	vm_map_store_root_t    *root,
	vm_map_store_node_ptr_t lptr,
	uint32_t                lholes,
	vm_map_address_t        key,
	vm_map_store_node_ptr_t rptr,
	uint32_t                rholes)
{
	vm_map_store_node_t node = vms_node_alloc(false);

	vms_node_set_count(node, 2);
	*vms_keyp(node, 0)   = 0;
	*vms_nodep(node, 0)  = lptr;
	*vms_holesp(node, 0) = lholes;
	*vms_keyp(node, 1)   = key;
	*vms_nodep(node, 1)  = rptr;
	*vms_holesp(node, 1) = rholes;

	root->vmsr_root      = vms_pointer(node);
	root->vmsr_depth    += 1;
}

/*!
 * @brief
 * Removes superfluous root nodes in a B+tree.
 */
static void
__vms_mut_root_simplify(vm_map_store_root_t *root)
{
	vm_map_store_node_t node = vms_node(root->vmsr_root);

	while (node->vmsn_count == 1 && vms_is_inner(node)) {
		vm_map_store_node_ptr_t ptr = *vms_nodep(node, 0);

		root->vmsr_root   = ptr;
		root->vmsr_depth -= 1;
		vms_node_free(root, node);
		node = vms_node(ptr);
	}
}


/*!
 * @brief
 * Helper to move a number of keys/holes/values from one node to another.
 *
 * @discussion
 * This really performs the intuitive move from [spos, spos + count) in @c src
 * into the [dpos, dpos + count) range into @c dst.
 */
__attribute__((noinline))
static void
__vms_mut_node_memmove(
	vm_map_store_node_t     dst,
	uint16_t                dpos,
	vm_map_store_node_t     src,
	uint16_t                spos,
	uint16_t                count)
{
	assert(count); /* caller must check */

	if (vms_is_leaf(dst)) {
		memmove(vms_keyp(dst, dpos), vms_keyp(src, spos),
		    count * sizeof(vm_map_address_t));
		memmove(vms_valp(dst, dpos), vms_valp(src, spos),
		    count * sizeof(vm_map_store_val_ptr_t));
	} else if (count) {
		memmove(vms_keyp(dst, dpos), vms_keyp(src, spos),
		    count * sizeof(vm_map_address_t));
		memmove(vms_nodep(dst, dpos), vms_nodep(src, spos),
		    count * sizeof(vm_map_store_node_ptr_t));
		memmove(vms_holesp(dst, dpos), vms_holesp(src, spos),
		    count * sizeof(uint32_t));
	}
}
#define __vms_mut_node_memmove(dst, dpos, src, spos, count)  ({                 \
	uint16_t __count = (count);                                             \
	if (__count) {                                                          \
	        (__vms_mut_node_memmove)(dst, dpos, src, spos, __count);        \
	}                                                                       \
})

__vms_extern(vm_map_store_node_t)
__vms_node_split(
	vm_map_store_node_t     node1,
	uint16_t                idx,
	bool                    split_left,
	bool                    split_right,
	vms_slot_t            * wslot)
{
	/*
	 * cur:         The current count of elements in node1
	 *
	 * total:       The number of elements after the split
	 *
	 * len1/len2:   The resulting count of elements in node1 and node2
	 *              respectively at the end of the split
	 *
	 * llen/rlen:   The number of elements "left" (resp. "right") of the
	 *              insertion point (not including it) at the end of the
	 *              split.
	 *
	 * In other words these three values are equal and correspond to how
	 * many slots will exist across node1 and node2 at the end of the split:
	 *
	 *   total
	 *   cur + split_left + split_right
	 *   len1 + len2
	 *   llen + 1 + rlen
	 */
	const uint16_t      cur   = node1->vmsn_count;
	const uint16_t      total = cur + split_left + split_right;
	const uint16_t      llen  = idx + split_left;
	const uint16_t      rlen  = total - llen - 1;
	const uint16_t      len1  = (vms_fanout(node1) * 2 + 2) / 3;
	const uint16_t      len2  = total - len1;
	vm_map_store_node_t node2 = vms_node_alloc(vms_is_leaf(node1));

	/*
	 * We split at 2/3 + 1/2 rather than in the middle, as empirically,
	 * address spaces tend to "grow right" more than change to the "left".
	 *
	 * We also do not have linkages to the left (for node density reasons),
	 * which means we can always rebalance toward the right later,
	 * but rebalancing to the left is challenging.
	 */

	if (rlen <= len2) {
		__vms_mut_node_memmove(node2, len2 - rlen,
		    node1, cur - rlen, rlen);
		if (llen > len1) {
			__vms_mut_node_memmove(node2, 0,
			    node1, len1, llen - len1);
		}
	} else {
		__vms_mut_node_memmove(node2, 0,
		    node1, cur - len2, len2);
		__vms_mut_node_memmove(node1, llen + 1,
		    node1, cur - rlen, rlen - len2);
	}

	if (llen < len1) {
		wslot->vmss_ptr = vms_pointer(node1);
		wslot->vmss_idx = llen;
	} else {
		wslot->vmss_ptr = vms_pointer(node2);
		wslot->vmss_idx = llen - len1;
	}

	vms_node_set_count(node1, len1);
	vms_node_set_count(node2, len2);
	vms_link(node2, node1->vmsn_next_sibling);
	vms_link(node1, node2);

	return node2;
}

/*!
 * @brief
 * Function that rebalances entries between two adjacent nodes instead of
 * splitting them.
 *
 * @discussion
 * The semantics of this function are very similar to @c __vms_node_split(),
 * but doesn't allocate a new node.
 *
 * Callers are responsible for making sure the rebalance operation
 * will fit the two nodes.
 *
 * @param node1         The left node to rebalance from.
 * @param node2         The right node to rebalance into.
 * @param idx           The index for the current pivot,
 *                      It must be within [node, node->vmsn_count)
 * @param split_left    Whether the slot at @c idx must be split left.
 * @param split_right   Whether the slot at @c idx must be split right.
 * @param wslot         The slot to where the empty slot is.
 */
__attribute__((always_inline))
static void
__vms_node_rebalance(
	vm_map_store_node_t     node1,
	vm_map_store_node_t     node2,
	uint16_t                idx,
	bool                    split_left,
	bool                    split_right,
	vms_slot_t             *wslot)
{
	/*
	 * cur1/cur2    The current count of elements in node1 and node2.
	 *
	 * total:       The number of elements after the split
	 *
	 * len1/len2:   The resulting count of elements coming from node1,
	 *              in node1 and node2 respectively at the end of the
	 *              rebalance. It means len2 doesn't count the elements
	 *              already in node2 (== cur2).
	 *
	 * llen/rlen:   The number of elements "left" (resp. "right") of the
	 *              insertion point (not including it) comint from node 1,
	 *              at the end of the rebalance. It means rlen doesn't count
	 *              the elements already in node2 (== cur2).
	 *
	 * In other words these three values are equal and correspond to how
	 * many slots will exist across node1 and node2 at the end of the
	 * rebalance:
	 *
	 *   total
	 *   cur1 + split_left + split_right + cur2
	 *   len1 + len2 + cur2
	 *   llen + 1 + rlen + cur2
	 */
	const uint16_t cur1  = node1->vmsn_count;
	const uint16_t cur2  = node2->vmsn_count;
	const uint16_t total = cur1 + split_left + split_right + cur2;
	const uint16_t llen  = idx + split_left;
	const uint16_t rlen  = total - llen - 1 - cur2;
	const uint16_t len1  = (total + 1) / 2;
	const uint16_t len2  = total - len1 - cur2;

	__vms_mut_node_memmove(node2, len2, node2, 0, cur2);

	if (rlen <= len2) {
		__vms_mut_node_memmove(node2, len2 - rlen,
		    node1, cur1 - rlen, rlen);
		if (llen > len1) {
			__vms_mut_node_memmove(node2, 0,
			    node1, len1, llen - len1);
		}
	} else {
		__vms_mut_node_memmove(node2, 0,
		    node1, cur1 - len2, len2);
		__vms_mut_node_memmove(node1, llen + 1,
		    node1, cur1 - rlen, rlen - len2);
	}

	if (llen < len1) {
		wslot->vmss_ptr = vms_pointer(node1);
		wslot->vmss_idx = llen;
	} else {
		wslot->vmss_ptr = vms_pointer(node2);
		wslot->vmss_idx = llen - len1;
	}

	vms_node_set_count(node1, len1);
	vms_node_set_count(node2, len2 + cur2);
}

/*!
 * @brief
 * Attempts to insert new slots in an inner hole in place.
 */
__attribute__((always_inline))
static bool
__vms_mut_insert_inner_fast(
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_store_node_ptr_t ptr,
	uint32_t                rholes)
{
	vm_map_store_node_t node = vms_node(path->vmsp_cur);
	const uint16_t      cur  = node->vmsn_count;
	const uint16_t      idx  = path->vmsp_cur.vmss_idx;

	assert(vms_is_inner(node));
	__builtin_assume(node->vmsn_leaf == 0);

	if (cur + 1 <= vms_fanout(node)) {
		__vms_mut_node_memmove(node, idx + 1, node, idx,
		    node->vmsn_count - idx);
		vms_node_set_count(node, node->vmsn_count + 1);

		*vms_keyp(node, idx + 1)   = start;
		*vms_nodep(node, idx + 1)  = ptr;
		*vms_holesp(node, idx + 1) = rholes;
		return true;
	}

	return false;
}

/*!
 * @brief
 * Attempts to insert new slots in a leaf node in place.
 */
__attribute__((always_inline))
static bool
__vms_mut_insert_leaf_fast(
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_store_val_ptr_t  ptr)
{
	vm_map_store_node_t node = vms_node(path->vmsp_cur);
	const uint16_t      cur  = node->vmsn_count;
	const uint16_t      idx  = path->vmsp_cur.vmss_idx;

	assert(vms_is_leaf(node));
	__builtin_assume(node->vmsn_leaf == 1);

	if (cur + 1 <= vms_fanout(node)) {
		__vms_mut_node_memmove(node, idx + 1, node, idx,
		    node->vmsn_count - idx);
		vms_node_set_count(node, node->vmsn_count + 1);

		*vms_keyp(node, idx + 1) = start;
		*vms_valp(node, idx + 1) = ptr;
		return true;
	}

	return false;
}

/*!
 * @brief
 * Helper for __vms_mut_split() and __vms_mut_insert()
 *
 * @discussion
 * A split is when a given non-0 slot is split with non-0 values on each side.
 *
 * An insertion is whan a given hole slot is split into 2 or 3 new slots (the
 * 1-slot case is supposed to be handled by __vms_mut_insert()'s fastpath
 * already).
 *
 * @param root          A pointer to the root of the b+tree being mutated,
 *                      it can be updated if a new root node is being made.
 * @param path          A path resolved to where the insertion/split needs
 *                      to happen.  This function invalidates the path.
 * @param start         The address at which to perform the insertion/split.
 * @param rval          The new value corresponding to @c start (the r stands
 *                      for right-of-key)
 * @param end           When this function performs an insertion, and splits
 *                      a hole into up to 3 pieces, the key at which the
 *                      insertion ends.
 */
__attribute__((noinline))
static void
__vms_mut_insert_slow(
	vm_map_store_root_t    *root,
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_store_val_ptr_t  rval,
	vm_map_address_t        end)
{
	vms_slot_t              slot        = path->vmsp_cur;
	vm_map_store_node_t     node        = vms_node(slot);
	vm_map_store_node_t     nnode       = vms_next_sibling(node);
	bool                    split_left  = vms_start(slot) < start;
	bool                    split_right = end && end < vms_end(slot);
	bool                    leaf        = true;
	bool                    rebalance;
	uint32_t                lholes, rholes;
	vm_map_store_node_ptr_t rptr;
	vms_slot_t              wslot;

	do {
		const uint16_t cur   = node->vmsn_count;
		const uint16_t ncur  = nnode ? nnode->vmsn_count : 0;
		const uint16_t total = cur + split_left + split_right + ncur;

		if (nnode && total <= 2 * vms_fanout(node)) {
			__vms_node_rebalance(node, nnode, slot.vmss_idx,
			    split_left, split_right, &wslot);
			rebalance = true;
		} else {
			nnode = __vms_node_split(node, slot.vmss_idx,
			    split_left, split_right, &wslot);
			rebalance = false;
		}

		*vms_keyp(wslot) = start;
		if (leaf) {
			*vms_valp(wslot)   = rval;
		} else {
			*vms_nodep(wslot)  = rptr;
			*vms_holesp(wslot) = rholes;
		}
		if (split_right) {
			wslot = vms_slot_next(wslot);
			*vms_keyp(wslot)   = end;
		}

		lholes = vms_holes(node);
		start  = vms_start(nnode);
		rptr   = vms_pointer(nnode);
		rholes = vms_holes(nnode);

		if (!vms_path_pop(path)) {
			return __vms_mut_root_make(root, vms_pointer(node),
			           lholes, start, rptr, rholes);
		}

		slot        = path->vmsp_cur;
		node        = vms_node(slot);
		nnode       = vms_next_sibling(node);
		split_left  = true;
		split_right = false;
		leaf        = false;
		*vms_holesp(slot) = lholes;
	} while (!rebalance && !__vms_mut_insert_inner_fast(path, start, rptr, rholes));

	/*
	 * In the rebalance case we didn't call __vms_mut_insert_inner_fast()
	 * since we don't want to insert a new slot, but we still have to
	 * perform the various bounds and hole masks adjustments.
	 *
	 * There are two cases:
	 *
	 * - either the rebalance of the children fit in "node", in which case
	 *   we just need to update the bound and mask and propagate upwards...
	 *
	 * - or the rebalance was right at the edge between "node" and "nnode",
	 *   in which case we need to propagate that new boundary upward until
	 *   it's within a single node.
	 */

	if (rebalance && slot.vmss_idx + 1 < node->vmsn_count) {
		*vms_keyp(node, slot.vmss_idx + 1)   = start;
		*vms_holesp(node, slot.vmss_idx + 1) = rholes;
		rebalance = false;
	}

	vms_path_update_holes_lazily(path, path->vmsp_pos, node);

	if (rebalance) {
		*vms_keyp(nnode, 0)   = start;
		*vms_holesp(nnode, 0) = rholes;

		vms_path_update_next_holes_lazily(path, path->vmsp_pos,
		    nnode, start);
	}
}

__attribute__((always_inline))
__vms_extern(void)
__vms_mut_split(
	vm_map_store_root_t    *root,
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_store_val_ptr_t  ptr)
{
	if (!__vms_mut_insert_leaf_fast(path, start, ptr)) {
		__vms_mut_insert_slow(root, path, start, ptr, 0);
	}
}

__vms_extern(void)
__vms_mut_insert(
	vm_map_store_root_t   * root,
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vm_map_store_val_ptr_t  ptr)
{
	vms_slot_t          slot        = path->vmsp_cur;
	vm_map_store_node_t node        = vms_node(slot);
	const bool          split_left  = vms_start(slot) < start;
	const bool          split_right = end < vms_end(slot);
	const uint16_t      cur         = node->vmsn_count;
	const uint16_t      total       = cur + split_left + split_right;

	assert(vms_start(slot) <= start && end <= vms_end(slot));

	if (!split_left && !split_right) {
		*vms_valp(slot) = ptr;
		root->vmsr_hint = node;
	} else if (total <= vms_fanout(node)) {
		/*
		 * llen/rlen:   The number of elements "left" (resp. "right")
		 *              of the insertion point (not including it)
		 *              at the end of the insertion.
		 */
		const uint16_t llen = slot.vmss_idx + split_left;
		const uint16_t rlen = total - llen - 1;

		__vms_mut_node_memmove(node, llen + 1, node, cur - rlen, rlen);
		vms_node_set_count(node, total);

		*vms_keyp(node, llen) = start;
		*vms_valp(node, llen) = ptr;
		if (split_right) {
			*vms_keyp(node, llen + 1) = end;
		}
		root->vmsr_hint = node;
	} else {
		return __vms_mut_insert_slow(root, path, start, ptr, end);
	}

	vms_path_update_holes_lazily(path, path->vmsp_pos, node);
}

/*!
 * @brief
 * Helper for __vms_mut_fold() and __vms_mut_erase().
 *
 * @discussion
 * This function takes care of the case when a fold operation spans multiple
 * leaf nodes, or a leaf node was removed and parents need to be updated.
 *
 * The value of the erased range becomes that of the first slot of the range.
 *
 * @param root          A pointer to the root of the b+tree being mutated,
 *                      it can be updated if the root node has been made
 *                      obsolete.
 * @param path          A path resolved to where the fold needs to happen.
 * @param end           The point at which the erasure ends.
 */
__attribute__((noinline))
static void
__vms_mut_fold_slow(
	vm_map_store_root_t    *root,
	vms_path_t              path,
	vm_map_address_t        end)
{
	bool do_parent = false;

	do {
		vm_map_store_node_t start_node = vms_node(path->vmsp_cur);
		uint16_t            start_idx  = path->vmsp_cur.vmss_idx;
		vm_map_store_node_t end_node   = start_node;
		uint16_t            end_idx;

		do_parent = false;

		/* eliminate entire nodes to be freed beteen start and end */
		while (vms_end(end_node) <= end && vms_next_sibling(end_node)) {
			vm_map_store_node_ptr_t ptr = end_node->vmsn_next_sibling;

			if (start_node != end_node) {
				vms_link(start_node, ptr);
				vms_node_free(root, end_node);
				do_parent = true;
			}
			end_node = vms_node(ptr);
		}

		/* then scan for the end_idx in end_node */
		if (end == ~0ull) {
			end_idx = end_node->vmsn_count;
			do_parent = true;
		} else {
			end_idx = vms_scan(end_node, end);
			if (vms_start(end_node, end_idx) < end) {
				assert(vms_is_inner(start_node) &&
				    end_idx < end_node->vmsn_count);

				do_parent = true;

				*vms_keyp(end_node, end_idx) = end;
				*vms_holesp(end_node, end_idx) =
				    vms_holes(vms_node(*vms_nodep(end_node, end_idx)));
			}
		}

		/*
		 * and finally collapse start_node, end_node and possibly the
		 * node after end_node together depending on what fits.
		 */
		if (start_idx + 1 + end_node->vmsn_count - end_idx <=
		    vms_fanout(start_node)) {
			vm_map_store_node_t nnode = vms_next_sibling(end_node);

			__vms_mut_node_memmove(start_node, start_idx + 1,
			    end_node, end_idx, end_node->vmsn_count - end_idx);
			vms_node_set_count(start_node,
			    start_idx + 1 + end_node->vmsn_count - end_idx);

			if (end_node != start_node) {
				vms_link(start_node, end_node->vmsn_next_sibling);
				vms_node_free(root, end_node);
				do_parent = true;
			}

			if (nnode &&
			    start_node->vmsn_count + nnode->vmsn_count <=
			    vms_fanout(start_node)) {
				__vms_mut_node_memmove(start_node,
				    start_node->vmsn_count,
				    nnode, 0, nnode->vmsn_count);
				vms_node_set_count(start_node,
				    start_node->vmsn_count + nnode->vmsn_count);

				vms_link(start_node, nnode->vmsn_next_sibling);
				vms_node_free(root, nnode);
				do_parent = true;
			}

			end       = vms_end(start_node);
			end_node  = NULL;
		} else {
			__vms_mut_node_memmove(end_node, 0, end_node, end_idx,
			    end_node->vmsn_count - end_idx);
			vms_node_set_count(start_node, start_idx + 1);
			vms_node_set_count(end_node, end_node->vmsn_count - end_idx);

			do_parent = true;
			end       = vms_start(end_node);
		}

		/*
		 * Because we folded several nodes at once, we must recompute
		 * our hole mask.
		 */
		if (vms_is_inner(start_node)) {
			*vms_holesp(start_node, start_idx) =
			    vms_holes(vms_node(*vms_nodep(start_node, start_idx)));
		}
	} while (do_parent && vms_path_pop(path));

	vms_path_update_holes_eagerly(path, path->vmsp_pos,
	    vms_holes(vms_node(path->vmsp_cur)));
	__vms_mut_root_simplify(root);
}

__vms_extern(void)
__vms_mut_fold(
	vm_map_store_root_t   * root,
	vms_path_t              path,
	uint16_t                count,
	bool                    update_holes)
{
	vm_map_store_node_t node = vms_node(path->vmsp_cur);
	uint16_t            idx  = path->vmsp_cur.vmss_idx;
	vm_map_store_node_t next;

	assert(vms_is_leaf(node));
	assert(idx + 1 + count <= node->vmsn_count);

	__vms_mut_node_memmove(node, idx + 1, node, idx + 1 + count,
	    node->vmsn_count - idx - count - 1);
	vms_node_set_count(node, node->vmsn_count - count);

	next = vms_next_sibling(node);
	if (next && node->vmsn_count + next->vmsn_count < vms_fanout(node)) {
		/*
		 * the < is intentional to leave a little slop
		 * and create a small hysteresis
		 */
		__vms_mut_node_memmove(node, node->vmsn_count, next, 0,
		    next->vmsn_count);
		vms_node_set_count(node, node->vmsn_count + next->vmsn_count);
		vms_link(node, next->vmsn_next_sibling);
		vms_node_free(root, next);
		(void)vms_path_pop(path);

		__vms_mut_fold_slow(root, path, vms_end(node));
	} else if (update_holes) {
		vms_path_update_holes_lazily(path, path->vmsp_depth, node);
	}
}

__vms_extern(void)
__vms_mut_erase(
	vm_map_store_root_t   * root,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	VMS_PATH_DECLARE(path, *root);
	vm_map_store_node_t node;
	vms_slot_t          slot;

	slot = vms_path_resolve(path, start);
	vms_slot_assert_start(slot, start);
	node = vms_node(slot);

	*vms_valp(path->vmsp_cur) = VMS_POINTER_NULL;

	if (end == vms_end(node)) {
		uint16_t n = node->vmsn_count - slot.vmss_idx - 1;

		return __vms_mut_fold(root, path, n, true);
	}

	if (end < vms_end(node)) {
		uint16_t end_idx = vms_scan(node, end, true);
		uint16_t n       = end_idx - slot.vmss_idx - 1;

		assert3u(vms_end(node, end_idx - 1), ==, end);
		return __vms_mut_fold(root, path, n, true);
	}

	return __vms_mut_fold_slow(root, path, end);
}


#pragma mark vm map/copy insertion/removal

/*!
 * @brief
 * Insert an entry into the entry linked list.
 */
__attribute__((always_inline))
static void
vm_map_hdr_store_insert(
	struct vm_map_header   *hdr,
	vm_map_entry_t          entry,
	vm_map_entry_t          next)
{
	vm_map_entry_t prev = next->vme_prev;

	release_assert(entry->vme_start < entry->vme_end);

	if (mach_assert_enabled()) {
		if (!hdr->is_vm_map_copy) {
			if (next != vm_map_to_entry(vm_map_from_hdr(hdr))) {
				assert(entry->vme_end <= next->vme_start);
			}
			if (prev != vm_map_to_entry(vm_map_from_hdr(hdr))) {
				assert(prev->vme_end <= entry->vme_start);
			}
		}

		assert(VM_MAP_PAGE_ALIGNED(entry->vme_start, VM_MAP_HDR_PAGE_MASK(hdr)));
		assert(VM_MAP_PAGE_ALIGNED(entry->vme_end, VM_MAP_HDR_PAGE_MASK(hdr)));
		assert(VM_MAP_PAGE_ALIGNED(VME_OFFSET(entry), VM_MAP_HDR_PAGE_MASK(hdr)));
		assert(entry->vme_next == VM_MAP_ENTRY_NULL);
		assert(entry->vme_prev == VM_MAP_ENTRY_NULL);
	}

	if (prev->vme_next != next) {
		ml_fatal_trap_invalid_list_linkage((unsigned long)next);
	}

	hdr->nentries++;
	entry->links.prev = next->links.prev;
	entry->vme_next   = next;
	prev->vme_next    = entry;
	next->vme_prev    = entry;

#if MAP_ENTRY_INSERTION_DEBUG
	if (entry->vme_start_original == 0 && entry->vme_end_original == 0) {
		entry->vme_start_original = entry->vme_start;
		entry->vme_end_original = entry->vme_end;
	}
	btref_put(entry->vme_insertion_bt);
	entry->vme_insertion_bt = btref_get(__builtin_frame_address(0),
	    BTREF_GET_NOWAIT);
#endif
}

/*!
 * @brief
 * Removes an entry from the entry linked list.
 */
__attribute__((always_inline))
static vm_map_entry_t
vm_map_header_store_remove(struct vm_map_header *hdr, vm_map_entry_t entry)
{
	vm_map_entry_t prev = entry->vme_prev;
	vm_map_entry_t next = entry->vme_next;

	if (prev->vme_next != entry || next->vme_prev != entry) {
		ml_fatal_trap_invalid_list_linkage((unsigned long)entry);
	}

	hdr->nentries--;
	prev->vme_next  = next;
	next->vme_prev  = prev;
	entry->vme_prev = VM_MAP_ENTRY_NULL;
	entry->vme_next = VM_MAP_ENTRY_NULL;

	return next;
}

__attribute__((noinline))
void
vm_map_copy_store_insert_head(vm_map_copy_t copy, vm_map_entry_t entry)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);
	vm_map_hdr_store_insert(&copy->cpy_hdr, entry,
	    vm_map_copy_first_entry(copy));
}

__attribute__((noinline))
void
vm_map_copy_store_insert_tail(vm_map_copy_t copy, vm_map_entry_t entry)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);
	vm_map_hdr_store_insert(&copy->cpy_hdr, entry,
	    vm_map_copy_to_entry(copy));
}

__attribute__((noinline))
void
vm_map_copy_store_remove(struct vm_map_copy *copy, struct vm_map_entry *entry)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);
	vm_map_header_store_remove(&copy->cpy_hdr, entry);
}

__attribute__((noinline))
void
vm_map_store_insert(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_store_rsv_t      rsv,
	vm_map_kernel_flags_t   vmk_flags)
{
	VMS_PATH_DECLARE(path, map->root);
	vm_map_address_t e_start = entry->vme_start;
	vm_map_address_t e_end   = entry->vme_end;
	vms_slot_t       slot;
	vm_map_entry_t   next;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	assert((~entry->max_protection & entry->protection) == 0);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (entry->is_sub_map) {
		assert3u(VM_MAP_PAGE_SHIFT(VME_SUBMAP(entry)), >=,
		    VM_MAP_PAGE_SHIFT(map));
	}

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_LINK(map, entry, entry);
	}

	if (!VME_IS_SENTINEL(entry)) {
		map->size += VME_SIZE(entry);
	}

	/*
	 * GuardMalloc support:
	 *
	 * Some of these entries are created with MAP_FIXED.
	 * Some are created with a very high hint address.
	 *
	 * Make sure that that those special regions (nano, jit etc) don't
	 * result in our highest hint being set to near the end of the map
	 * and future alloctions getting KERN_NO_SPACE when running with
	 * guardmalloc.
	 */
	if (map->disable_vmentry_reuse &&
	    !vmk_flags.vmf_fixed &&
	    !vmk_flags.vmkf_last_free &&
	    map->highest_entry_end < e_end) {
		assert(!map->is_nested_map);
		map->highest_entry_end = e_end;
	}

#if CODE_SIGNING_MONITOR
	(void) vm_map_entry_cs_associate(map, entry, vmk_flags);
#else
	(void) vmk_flags;
#endif

	slot = vms_path_resolve(path, e_start);
	vms_slot_assert_contains(slot, e_end - 1);

	if (vms_slot_is_chunk(slot)) {
		vm_guard_object_chunk_t chunk = vms_slot_chunk(slot);
		uint32_t lidx, sidx, eidx;

		lidx = vmgo_chunk_skiplist_idx(chunk, e_start);
		sidx = vmgo_chunk_slot(chunk, e_start);
		eidx = vmgo_chunk_slot(chunk, e_end - 1) + 1;
		assert(!(vmgo_bitmap(chunk) & (bits_mask(eidx) - bits_mask(sidx))));

		if (vms_is_entry(chunk->vgoc_ptrs[lidx])) {
			next = vms_entry(chunk->vgoc_ptrs[lidx]);
			next = vm_map_store_entry_scan(map, next, e_end, true);
		} else {
			next = vms_slot_next_entry(map, slot);
		}

		vm_map_hdr_store_insert(&map->hdr, entry, next);

		entry->vme_chunk = vms_pointer(chunk);
		vmgo_chunk_skiplist_insert(map, entry);
	} else {
		vms_slot_assert_hole(slot);

		if (vmsr_is_entry(rsv)) {
			next = vmsr_entry(rsv);
		} else {
			assert(!vmsr_is_chunk(rsv));
			next = vms_slot_next_entry(map, slot);
		}
		vm_map_hdr_store_insert(&map->hdr, entry, next);

		__vms_mut_insert(&map->root, path, e_start, e_end, vms_pointer(entry));
	}
}

__attribute__((noinline))
void
vm_map_store_remove(vm_map_t map, vm_map_entry_t entry, vms_remove_options_t opts)
{
	vm_map_entry_t   next = entry->vme_next;
	vm_map_address_t h_start, h_end;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_UNLINK(map, entry, entry);
	}

	if (!VME_IS_SENTINEL(entry)) {
		map->size -= VME_SIZE(entry);
	}

	h_start = vm_map_store_prev_hole_start(map, entry);
	h_end   = vm_map_store_next_hole_end(map, entry);

	map->unlink_timestamp++;
	vm_map_header_store_remove(&map->hdr, entry);

	if (VME_IN_CHUNK(entry)) {
		vm_map_store_val_ptr_t  ptr     = vms_pointer(entry);
		vm_guard_object_chunk_t chunk   = vms_chunk(entry->vme_chunk);
		vm_map_store_val_ptr_t  nextptr = VMS_POINTER_NULL;
		int                     idx;

		if (h_end < vmgo_chunk_end(chunk)) {
			nextptr = vms_pointer(next);
		}
		idx = vmgo_chunk_skiplist_idx(chunk, entry->vme_end - 1);
		while (idx >= 0 && vms_equal(chunk->vgoc_ptrs[idx], ptr)) {
			chunk->vgoc_ptrs[idx--] = nextptr;
		}

		if (opts & VMS_REMOVE_FREE_SLOTS) {
			bool     free_chunk = false;
			bool     try_free   = true;
			uint32_t sidx, eidx;
			uint64_t mask;

			if (h_start <= vmgo_chunk_start(chunk)) {
				sidx = 0;
			} else {
				sidx = vmgo_chunk_slot(chunk, h_start - 1) + 1;
			}
			if (vmgo_chunk_end(chunk) <= h_end) {
				eidx = chunk->vgoc_count;
			} else {
				eidx = vmgo_chunk_slot(chunk, h_end);
			}

			mask = bits_mask(eidx) - bits_mask(sidx);
			mask &= ~vmgo_bitmap(chunk);

			/*
			 * Some drivers race overwrite mappings with map
			 * termination and assert success (rdar://142262418).
			 * If the available slot count is zero (due to quarantine),
			 * the overwrite will fail and trigger a panic.
			 *
			 * To handle this, we don't free slots in terminated maps,
			 * leaving the slot delegated to the original caller
			 * therefore allowing them to overwrite if they choose.
			 *
			 * We still free chunks when they contain no entries to
			 * avoid leaking chunks. We don't create new chunks in a
			 * terminated map, ensuring that the former "owners" of
			 * these slots can do their overwrites unhindered by
			 * guard objects.
			 */
			if (map->terminated) {
				try_free = (sidx == 0 && eidx == chunk->vgoc_count);
			}
			if (try_free) {
				free_chunk = sidx < eidx && mask &&
				    vmgo_chunk_free_slots(chunk, mask);
			}
			if (free_chunk) {
				__vms_mut_erase(&map->root, h_start, h_end);
				zfree_id(ZONE_ID_VM_GO_CHUNKS, chunk);
			}
		}
	} else {
		__vms_mut_erase(&map->root, h_start, h_end);
	}

	if (opts & VMS_REMOVE_FREE_ENTRY) {
		vm_map_entry_free_locked(map, entry);
	} else {
		entry->vme_chunk = VMS_POINTER_NULL;
		vm_entry_invalidate_waiters(map, entry);
	}
}


#pragma mark vm map/copy clip/swap

__abortlike
static void
__vm_map_store_clip_out_of_bounds_entry_panic(
	struct vm_map_header   *hdr,
	vm_map_entry_t          entry,
	vm_map_offset_t         where)
{
	panic("vm_map_clip(%p): Attempting to clip an VM map entry %p "
	    "outside of its bounds [0x%llx:0x%llx] at 0x%llx", hdr, entry,
	    entry->vme_start, entry->vme_end, where);
}

/*!
 * @brief
 * Backend for *_clip_start() functions.
 *
 * @discussion
 * Entries are inserted in argument order (@c new_entry, then @c entry).
 *
 * @param hdr           The map header to insert the new entry into
 * @param new_entry     The new entry to insert
 * @param entry         The entry being split (@c new_entry successor)
 * @param start         The address at which the split is made.
 */
__attribute__((always_inline))
static void
vm_map_hdr_store_clip_start(
	struct vm_map_header   *hdr,
	vm_map_entry_t          new_entry,
	vm_map_entry_t          entry,
	vm_map_offset_t         start)
{
	if (__improbable(start <= entry->vme_start || entry->vme_end <= start)) {
		__vm_map_store_clip_out_of_bounds_entry_panic(hdr, entry, start);
	}

	new_entry->vme_end = entry->vme_start = start;
	VME_OFFSET_SET(entry, VME_OFFSET(entry) + VME_SIZE(new_entry));
	new_entry->vme_chunk = entry->vme_chunk;

	if (!entry->is_sub_map && VME_OBJECT(entry)) {
		vm_object_mark_clipped_unlocked(VME_OBJECT(entry));
	}

	vm_map_hdr_store_insert(hdr, new_entry, entry);
}

/*!
 * @brief
 * Backend for *_clip_end() functions.
 *
 * @discussion
 * Entries are inserted in argument order (@c entry, then @c new_entry).
 *
 * @param hdr           The map header to insert the new entry into
 * @param entry         The entry being split (@c new_entry predecessor)
 * @param new_entry     The new entry to insert
 * @param end           The address at which the split is made.
 */
__attribute__((always_inline))
static void
vm_map_hdr_store_clip_end(
	struct vm_map_header   *hdr,
	vm_map_entry_t          entry,
	vm_map_entry_t          new_entry,
	vm_map_offset_t         end)
{
	if (__improbable(end <= entry->vme_start || entry->vme_end <= end)) {
		__vm_map_store_clip_out_of_bounds_entry_panic(hdr, entry, end);
	}

	entry->vme_end = new_entry->vme_start = end;
	VME_OFFSET_SET(new_entry, VME_OFFSET(new_entry) + VME_SIZE(entry));
	new_entry->vme_chunk = entry->vme_chunk;

	if (!entry->is_sub_map && VME_OBJECT(entry)) {
		vm_object_mark_clipped_unlocked(VME_OBJECT(entry));
	}

	vm_map_hdr_store_insert(hdr, new_entry, entry->vme_next);
}

__attribute__((noinline))
void
vm_map_copy_store_clip_start(
	vm_map_copy_t           copy,
	vm_map_entry_t          entry,
	vm_map_offset_t         start)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);

	if (start > entry->vme_start) {
		vm_map_entry_t new_entry = vm_map_copy_entry_copy(copy, entry);

		vm_map_hdr_store_clip_start(&copy->cpy_hdr, new_entry, entry, start);
	}
}

__attribute__((noinline))
void
vm_map_copy_store_clip_end(
	vm_map_copy_t           copy,
	vm_map_entry_t          entry,
	vm_map_offset_t         end)
{
	VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_COPY_ENTRY);

	if (end < entry->vme_end) {
		vm_map_entry_t new_entry = vm_map_copy_entry_copy(copy, entry);

		vm_map_hdr_store_clip_end(&copy->cpy_hdr, entry, new_entry, end);
	}
}

__attribute__((noinline))
vm_map_entry_t
vm_map_store_clip_start(vm_map_t map, vm_map_entry_t entry, vm_map_offset_t start)
{
	vm_map_address_t e_start = entry->vme_start;
	vm_map_address_t e_end   = entry->vme_end;
	vm_map_entry_t   new_entry;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	new_entry = vm_map_entry_copy_locked(map, entry);
	vm_map_hdr_store_clip_start(&map->hdr, new_entry, entry, start);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_UNLINK(map, entry, new_entry);
		DTRACE_MAP_ENTRY_LINK(map, new_entry, new_entry);
	}

	if (VME_IN_CHUNK(entry)) {
		vmgo_chunk_skiplist_insert(map, new_entry);
	} else {
		VMS_PATH_DECLARE(path, map->root);
		vms_slot_t slot;

		slot = vms_path_resolve(path, start);
		vms_slot_assert_entry(slot, e_start, entry, e_end);

		*vms_valp(slot) = vms_pointer(new_entry);
		__vms_mut_split(&map->root, path, start, vms_pointer(entry));
	}

	return new_entry;
}

__attribute__((noinline))
vm_map_entry_t
vm_map_store_clip_end(vm_map_t map, vm_map_entry_t entry, vm_map_offset_t end)
{
	vm_map_address_t e_start = entry->vme_start;
	vm_map_address_t e_end   = entry->vme_end;
	vm_map_entry_t   new_entry;

	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	new_entry = vm_map_entry_copy_locked(map, entry);
	vm_map_hdr_store_clip_end(&map->hdr, entry, new_entry, end);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_UNLINK(map, entry, new_entry);
		DTRACE_MAP_ENTRY_LINK(map, new_entry, new_entry);
	}

	if (VME_IN_CHUNK(entry)) {
		vmgo_chunk_skiplist_insert(map, new_entry);
	} else {
		VMS_PATH_DECLARE(path, map->root);
		vms_slot_t slot;

		slot = vms_path_resolve(path, end);
		vms_slot_assert_entry(slot, e_start, entry, e_end);

		__vms_mut_split(&map->root, path, end, vms_pointer(new_entry));
	}

	return new_entry;
}

__attribute__((noinline))
void
vm_map_store_swap(
	vm_map_t                map,
	vm_map_entry_t          old_entry,
	vm_map_entry_t          new_entry)
{
	vm_map_address_t e_start = old_entry->vme_start;
	vm_map_address_t e_end   = old_entry->vme_end;
	vms_slot_t       slot;

	assert(new_entry->vme_start == e_start);
	assert(new_entry->vme_end == e_end);
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(old_entry);
	VM_ENTRY_ASSERT_EXCL_OWNER(new_entry);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_UNLINK(map, old_entry, old_entry);
		DTRACE_MAP_ENTRY_LINK(map, new_entry, old_entry);
	}

	if (VME_IS_SENTINEL(old_entry) != VME_IS_SENTINEL(new_entry)) {
		if (VME_IS_SENTINEL(old_entry)) {
			map->size += e_end - e_start;
		} else {
			map->size -= e_end - e_start;
		}
	}

	map->unlink_timestamp++;
	vm_map_hdr_store_insert(&map->hdr, new_entry,
	    vm_map_header_store_remove(&map->hdr, old_entry));

	if (VME_IN_CHUNK(old_entry)) {
		new_entry->vme_chunk = old_entry->vme_chunk;
		old_entry->vme_chunk = VMS_POINTER_NULL;
		vmgo_chunk_skiplist_insert(map, new_entry);
	} else {
		slot = vm_map_store_lookup(map, e_start);
		vms_slot_assert_entry(slot, e_start, old_entry, e_end);

		*vms_valp(slot) = vms_pointer(new_entry);
	}

#if CODE_SIGNING_MONITOR
	(void) vm_map_entry_cs_associate(map, new_entry, VM_MAP_KERNEL_FLAGS_NONE);
#endif
	vm_entry_invalidate_waiters(map, old_entry);
}


#pragma mark vm map/copy merge/extend

__attribute__((noinline))
static void
vm_map_store_merge(
	vm_map_t                map,
	vm_map_entry_t          left,
	vm_map_entry_t          right,
	bool                    keep_left)
{
	vm_map_address_t l_start = left->vme_start;
	vm_map_address_t l_end   = left->vme_end;
	vm_map_address_t r_end   = right->vme_end;

	assert(l_end == right->vme_start);
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(left);
	VM_ENTRY_ASSERT_EXCL_OWNER(right);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_UNLINK(map, right, right);
		DTRACE_MAP_ENTRY_EXTEND(map, left, right->vme_end);
	}

	if (VME_IS_SENTINEL(left) != VME_IS_SENTINEL(right)) {
		if (keep_left) {
			if (VME_IS_SENTINEL(right)) {
				map->size += r_end - l_end;
			} else {
				map->size -= r_end - l_end;
			}
		} else {
			if (VME_IS_SENTINEL(left)) {
				map->size += l_end - l_start;
			} else {
				map->size -= l_end - l_start;
			}
		}
	}

	map->unlink_timestamp++;
	vm_map_header_store_remove(&map->hdr, keep_left ? right : left);

	if (keep_left) {
		left->vme_end = r_end;
	} else {
		right->vme_start = l_start;
		VME_OFFSET_SET(right, VME_OFFSET(left));
	}

	if (VME_IN_CHUNK(right)) {
		assert(vms_equal(left->vme_chunk, right->vme_chunk));
		vmgo_chunk_skiplist_insert(map, keep_left ? left : right);
	} else {
		VMS_PATH_DECLARE(path, map->root);

		vms_path_resolve(path, l_start);
		vms_slot_assert_entry(path->vmsp_cur, l_start, left, l_end);

		*vms_valp(path->vmsp_cur) = vms_pointer(keep_left ? left : right);
		if (r_end <= vms_end(vms_node(path->vmsp_cur))) {
			__vms_mut_fold(&map->root, path, 1, false);
		} else {
			__vms_mut_fold_slow(&map->root, path, r_end);
		}
	}

	vm_entry_invalidate_waiters(map, keep_left ? right : left);
}

__attribute__((always_inline))
void
vm_map_store_merge_left(
	vm_map_t                map,
	vm_map_entry_t          left,
	vm_map_entry_t          right)
{
	vm_map_store_merge(map, left, right, /* keep_left */ true);
}

__attribute__((noinline))
void
vm_map_store_merge_right(
	vm_map_t                map,
	vm_map_entry_t          left,
	vm_map_entry_t          right)
{
	vm_map_store_merge(map, left, right, /* keep_left */ false);
}

__attribute__((noinline))
void
vm_map_store_extend_right(
	vm_map_t                map,
	vm_map_entry_t          entry,
	vm_map_address_t        new_end)
{
	vm_map_address_t e_start = entry->vme_start;
	vm_map_address_t e_end   = entry->vme_end;
	vms_slot_t       slot;

	assert(e_end < new_end);
	assert(new_end <= vm_map_store_next_hole_end(map, entry));
	assert(VM_MAP_PAGE_ALIGNED(new_end, VM_MAP_PAGE_MASK(map)));
	assert_vm_map_ilk_owned(map, LCK_RW_TYPE_EXCLUSIVE);
	VM_ENTRY_ASSERT_EXCL_OWNER(entry);

	if (__improbable(vm_debug_events)) {
		DTRACE_MAP_ENTRY_EXTEND(map, entry, new_end);
	}

	if (!VME_IS_SENTINEL(entry)) {
		map->size += new_end - e_end;
	}
	entry->vme_end = new_end;

	if (VME_IN_CHUNK(entry)) {
		/*
		 * The entry is in a chunk, no need to resolve,
		 * just update the skiplist for the new bounds.
		 */
		vmgo_chunk_skiplist_insert(map, entry);
	} else if (new_end == vm_map_store_next_hole_end(map, entry)) {
		/*
		 * There is a hole right after the entry that we will remove.
		 */
		VMS_PATH_DECLARE(path, map->root);

		vms_path_resolve(path, e_start);
		vms_slot_assert_entry(path->vmsp_cur, e_start, entry, e_end);
		if (new_end <= vms_end(vms_node(path->vmsp_cur))) {
			return __vms_mut_fold(&map->root, path, 1, false);
		} else {
			return __vms_mut_fold_slow(&map->root, path, new_end);
		}
	} else {
		/*
		 * There is a hole right after the entry, but it will stay,
		 * we just need to possibly update the nodes bounds,
		 * and the hole mask for this node.
		 */
		VMS_PATH_DECLARE(path, map->root);

		slot = vms_path_resolve(path, e_end);
		vms_slot_assert_start(slot, e_end);
		vms_slot_assert_hole(slot);

		vms_path_update_start(path, new_end);
		vms_path_update_holes_lazily(path, path->vmsp_pos, vms_node(slot));
	}
}
