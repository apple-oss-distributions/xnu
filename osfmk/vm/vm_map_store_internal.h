/*
 * Copyright (c) 2009 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MAP_STORE_H
#define _VM_VM_MAP_STORE_H

#include <mach/shared_region.h>
#include <mach/vm_param.h>
#include <kern/bits.h>
#include <os/atomic_private.h>
#include <stdint.h>

__BEGIN_DECLS
__exported_push_hidden

struct _vm_map;
struct vm_map_entry;
struct vm_map_copy;
struct vm_map_header;

/*!
 * @brief
 * Type for a packed pointer to a VM map store node.
 */
typedef struct {
	uint32_t                vmsp_packed __kernel_ptr_semantics;
} vm_map_store_node_ptr_t;

/*!
 * @brief
 * Type for a packed pointer to a VM map store value.
 */
typedef struct {
	uint32_t                vmsp_packed : 31 __kernel_ptr_semantics;
	uint32_t                vmsp_chunk  : 1;
} vm_map_store_val_ptr_t;

/*!
 * @constant VMS_NODE_FANOUT
 * The fanout for the VM map store B+tree inner nodes.
 *
 * @constant VMS_LEAF_FANOUT
 * The fanout for the VM map store B+tree leaf nodes.
 */
#define VMS_NODE_FANOUT         15
#define VMS_LEAF_FANOUT         20

/*!
 * @brief
 * The type for a VM map store B+tree node.
 *
 * @field vmsn_count (any)
 * The number of slots in use in the node.
 *
 * @field vmsn_leaf (any)
 * Whether the node is a leaf (true) or an internal node (false).
 *
 * @field vmsn_next_sibling (inner nodes, leaf nodes)
 * The packed pointer to the next node at the same level in the B+tree,
 * or 0 if this is the last.
 *
 * @field vmsn_keys (inner nodes), vmsl_keys (leaf nodes)
 * The B+tree keys for this node.
 * Unlike a regular B+tree, the minimum key for the tree is held in slot [0].
 *
 *              ┌───┬───┬───┬───┬───┐
 *     keys   = │ 0 │ 1 │...│n-2│n-1│
 *              └─┬─┴─┬─┴─┬─┴─┬─┴─┬─┴─┐
 *     values =   │ 0 │ 1 │...│n-2│n-1│
 *                └───┴───┴───┴───┴───┘
 *
 * @field vmsn_ptrs (inner nodes), vmsl_ptrs (leaf nodes)
 * The B+tree values for each key.
 * For inner nodes, the value is a packed pointer to another node,
 * for leaves a packed value pointer.
 *
 * @field vmsn_holes (inner nodes)
 * A bitfield that represents the size classes for which a hole exists
 * within the subree corresponding to the current slot.
 *
 * @field vmsn_padding (any)
 * Unused
 */
typedef struct vm_map_store_node {
	uint16_t                vmsn_count;
	uint16_t                vmsn_leaf;      /* bool, but avoids padding */
	vm_map_store_node_ptr_t vmsn_next_sibling;
	union {
		struct {
			vm_map_address_t        vmsn_keys[VMS_NODE_FANOUT];
			vm_map_store_node_ptr_t vmsn_ptrs[VMS_NODE_FANOUT];
			uint32_t                vmsn_holes[VMS_NODE_FANOUT];
		};
		struct {
			vm_map_address_t        vmsl_keys[VMS_LEAF_FANOUT];
			vm_map_store_val_ptr_t  vmsl_ptrs[VMS_LEAF_FANOUT];
		};
	};
	uint64_t                vmsn_padding;   /* an OLC lock one day */
} *vm_map_store_node_t;

/*!
 * @brief
 * Represents the root of a VM map store B+tree.
 *
 * @field vmsr_root     The packed pointer to the root node of the B+tree
 * @field vmsr_depth    The depth of the tree (how many layers of inner nodes)
 * @field vmsr_hint     A cache of the last leaf node that was looked up or NULL
 */
typedef struct vm_map_store_root {
	vm_map_store_node_ptr_t vmsr_root;
	uint32_t                vmsr_depth;
	vm_map_store_node_t     vmsr_hint;
} vm_map_store_root_t;


/*!
 * @const VMGO_MAX_SIZE_SHIFT
 * The log2() of the maximum size for guard object slots that slabs can contain.
 * Currently 1Tb. Note that it doesn't mean that the address space is large
 * enough to actually find space for such large guard objects.
 *
 * @const VMGO_SIZE_CLASSES
 * The number of size classes in a slab.
 * A slot size is always (1) a power of two and (2) at least PAGE_SIZE large.
 *
 * @const VMGO_COUNT_SHIFT_BITS
 * The number of bits for the @c vgoc_count_shift field, which must represents
 * the shift of @c vgoc_count, which itself has to be any power of two between
 * 2 and 64.
 *
 * @const VMGO_QUARANTINED_BITS
 * The number of bits for the @c vgoc_quarantined field, which needs to
 * represent any value from 0 to 15 (64/4 - 1).
 *
 * @const VMGO_START_SHIFT
 * By how many bits to shift @c vgoc_start to compute the practical starting
 * VA for a guard object chunk. It implies that these are always at least
 * aligned to a (1u << VMGO_START_SHIFT == 64k) boundary.
 */
#define VMGO_MAX_SIZE_SHIFT     40
/*
 * for some platforms PAGE_SHIFT isn't a constant, fallback to PAGE_MIN_SHIFT,
 * it only wastes 2 entries in the array.
 */
#define VMGO_SIZE_CLASSES       (VMGO_MAX_SIZE_SHIFT - PAGE_MIN_SHIFT)
#define VMGO_COUNT_SHIFT_BITS   3
#define VMGO_QUARANTINED_BITS   4
#define VMGO_START_SHIFT        16

typedef struct vm_guard_object_slab *vm_guard_object_slab_t;

/*!
 * @brief
 * The type for a guard object chunk.
 *
 * @discussion
 * A guard object chunk is a collection of several slots of the same size,
 * that are used to return randomly selected allocations, maintaining
 * a guarantee of 25% density of guards that cause crashes when accessed.
 *
 * For a VM managed chunk, these invariants hold:
 *
 * - the number of bits set in vgoc_bitmap is equal to (vgoc_quarantined
 *   + vgoc_available + #guards),
 *
 * - slots that are free have no entry covering its corresponding VA range
 *   in the skiplist.
 *
 *
 * For a user managed chunk, these invariants hold:
 *
 * - vgoc_available = 0, vgoc_quarantined = 0, vgoc_count = 64;
 *
 * - all the VA of the chunk is covered by entries regardless of the state of
 *   the slots;
 *
 * - guarded slots (slots with their bit set in vgoc_bitmap) have no memory
 *   entered in the pmap, and trying to access this memory (copy, fault, ...)
 *   results in a protection failure.
 *
 *
 * @see doc/allocators/guard-objects.md for the rationale.
 *
 * Chunk configuration (immutable)
 * ~~~~~~~~~~~~~~~~~~~
 *
 * @field vgoc_slab             The owning slab for VM managed chunks.
 *
 * @field vgoc_start            A 32bit representation of the VA start for
 *                              that chunk in its map, use @c vmgo_chunk_start()
 *                              to convert into a proper @c vm_map_address_t.
 *
 * @field vgoc_granule          The slot size granule as a shift scale,
 *                              in number of bytes. Meaning that the size
 *                              of a slot is (1u << vgoc_granule).
 *
 * @field vgoc_count            The number of slots in the chunk.
 *                              (always a power of two smaller or equal to 64).
 *
 * @field vgoc_count_shift      The number of slots in the chunk, as a shift.
 *                              vgoc_count = 1u << vgoc_count_shift.
 *
 *
 * Chunk slot state (serialized by the map interlock)
 * ~~~~~~~~~~~~~~~~
 *
 * @field vgoc_quarantined      The number of quarantined slots
 *                              (always strictly smaller than vgoc_count / 4)
 *
 * @field vgoc_available        The number of allocatable slots
 *
 * @field vgoc_bitmap           The bitmap of free/guarded slots
 *
 *                              For user managed chunks, the serialization is
 *                              more subtle: the bitmap is updated atomically,
 *                              under at least a shared lock on all the entries.
 *                              Holding an exclusive lock guarantees stability
 *
 * @field vgoc_prev, vgoc_next  Linkage used to chain the chunk on its slab
 *                              size class or the map's guard_object_user list.
 *
 * @field vgoc_ptrs             A skiplist of entries this chunk points to.
 *
 *
 * Visually
 * ~~~~~~~~
 *
 * Below is a graphical representation of a chunk for the parameters:
 * - vgoc_count_shift = 3
 * - vgoc_count       = 8
 * - vgoc_bitmap      = 0xe9
 *
 *  vmgo_chunk_start()                                          vmgo_chunk_end()
 *   │                       1 << vgoc_granule                               │
 *   ▼                           ◀──────▶                                    ▼
 *   ╔════════╤════════╤════════╤════════╤════════╤════════╤════════╤════════╗
 *   ║ 0:free │ 1:used │ 2:used │ 3:free │ 4:used │ 5:free │ 6:free │ 7:free ║
 *   ╚════════╧════════╧════════╧════════╧════════╧════════╧════════╧════════╝
 *    ◀─────────────────────────────────────────────────────────────────────▶
 *                               vmgo_chunk_size()
 *
 *
 * For this configuration:
 * - the chunk has 2 guards (8/4)
 * - 3 chunks are used/allocated
 * - because the chunk has enough free slots (more than twice the number of
 *   guards) it won't have any quarantined slots and vgoc_available is 3.
 *
 * See doc/allocators/guard-objects.md for more details.
 */
typedef struct vm_guard_object_chunk {
	/* immutable fields */
	vm_guard_object_slab_t  vgoc_slab;
	uint32_t                vgoc_start;
	uint8_t                 vgoc_granule;
	uint8_t                 vgoc_count;
	uint8_t                 vgoc_count_shift : 4;

	/* mutable fields, serialized by the map lock */
	uint8_t                 vgoc_quarantined : 4;
	uint8_t                 vgoc_available;
	bitmap_t                vgoc_bitmap;

	vm_map_store_val_ptr_t  vgoc_prev;
	vm_map_store_val_ptr_t  vgoc_next;

	vm_map_store_val_ptr_t  vgoc_ptrs[8];
} *vm_guard_object_chunk_t;


/*!
 * @brief
 * The type for a guard object slab.
 *
 * @discussion
 * A guard object slab is a series of size-segregated list of guard object
 * chunks. The @c vgos_full lists contain chunks that have no available slots
 * (because they are all used or quarantined), and the @c vgos_partial lists
 * contain chunks that have at least one element available for allocations.
 * Empty chunks are not kept around, which is why there is no @c vgoc_empty
 * list.
 */
typedef struct vm_guard_object_slab {
	vm_guard_object_chunk_t vgos_partial[VMGO_SIZE_CLASSES];
	vm_guard_object_chunk_t vgos_full[VMGO_SIZE_CLASSES];
} *vm_guard_object_slab_t;

/*!
 * @brief
 * A struct holding the information about an allocation reservation.
 *
 * @field vmsr_start            The start address for the reservation
 * @field vmsr_is_chunk         Whether vmsr_value is a chunk or an entry.
 * @field vmsr_value            (optional) a pointer to the entry right after
 *                              this reservation, or the chunk containing
 *                              the reservation.
 */
typedef struct vm_map_store_rsv {
	long long               vmsr_start : 63;
	bool                    vmsr_is_chunk : 1;
	uintptr_t               vmsr_value;
} vm_map_store_rsv_t;

/*
 * Packing parameters for VM map store nodes
 */
#define VMN_PACKED_PTR_BITS         32
#define VMN_PACKED_PTR_SHIFT        8
#define VMN_PACKED_PTR_BASE         ((uintptr_t)VM_MIN_KERNEL_AND_KEXT_ADDRESS)

/*
 * Packing parameters for VM map entries
 */
#define VME_PACKED_PTR_BITS         31
#define VME_PACKED_PTR_SHIFT        6
#define VME_PACKED_PTR_BASE         ((uintptr_t)VM_MIN_KERNEL_AND_KEXT_ADDRESS)

#define VM_MAP_HDR_PAGE_SHIFT(hdr)  ((hdr)->page_shift)
#define VM_MAP_HDR_PAGE_SIZE(hdr)   (1 << VM_MAP_HDR_PAGE_SHIFT((hdr)))
#define VM_MAP_HDR_PAGE_MASK(hdr)   (VM_MAP_HDR_PAGE_SIZE((hdr)) - 1)


#pragma mark vm map store creation/destruction

/*!
 * @abstract
 * Initialize the store of a vm map copy.
 *
 * @param copy          The vm map copy to initialize
 * @param page_shift    The page_shift for this vm_map_copy_t.
 */
extern void vm_map_copy_store_init(
	struct vm_map_copy     *copy,
	uint32_t                page_shift);

/*!
 * @abstract
 * Initialize the store of a vm map.
 *
 * @param map           The vm map to initialize.
 * @param page_shift    The page_shift for this vm_map_t.
 */
extern void vm_map_store_init(
	struct _vm_map         *map,
	uint32_t                page_shift);

/*!
 * @abstract
 * Destroy the store of a vm map.
 *
 * @param map           The vm map to destroy the store for.
 */
extern void vm_map_store_destroy(
	struct _vm_map         *map);


/*!
 * @abstract
 * Enable the guard object policy system-wide.
 *
 * @discussion
 * Until pid 1 is made, guard objects are disabled so that early allocations
 * that tend to stay forever do not cause address space fragmentation.
 */
extern void vm_guard_object_enable(void);

/*!
 * @abstract
 * Initialize a guard object slab.
 *
 * @discussion
 * The kernel uses static global slabs that are initialized with this funciton.
 *
 * @param slab          The slab to initialize.
 */
extern void vm_guard_object_slab_init(
	vm_guard_object_slab_t  slab);

/*!
 * @abstract
 * Enable guard objects on a VM map.
 *
 * @discussion
 * Note that guard object slabs are only created when the process goes
 * multi-threaded, so that early allocations are neatly packed.
 *
 * Following a similar logic, guard objects aren't inherited across fork(),
 * guard objects will be re-enabled when (or if) the forked process goes
 * multi-threaded again.
 *
 * This function allocates two slabs, meant to be used for either "front"
 * of the address space.
 *
 * @param map           The map to initialize guard objects for.
 */
extern void vm_map_guard_object_slab_init(
	vm_map_t                map);

/*!
 * @abstract
 * Cleanup the guard object slab made by @c vm_guard_object_slab_init().
 */
extern void vm_map_guard_object_slab_destroy(
	vm_map_t                map);

#pragma mark vm map store lookup

/*!
 * @abstract
 * Lookup an entry in the specified map.
 *
 * @param map           The map to search.
 * @param address       The address to look for.
 * @param or_next       Whether to find the next possible
 *                      entry if the address corresponds to a hole.
 *
 * @returns
 * - an entry containing @c address on success.
 * - VM_MAP_ENTRY_NULL if @c address corresponds to a hole,
 *   and @c or_next is false.
 * - an entry starting after @c address if @c address corresponds to a hole
 *   and @c or_next is true, or @c vm_map_to_entry(map) if no such entry exists.
 */
extern struct vm_map_entry *vm_map_store_lookup_entry(
	struct _vm_map         *map,
	vm_map_offset_t         address,
	bool                    or_next);

/*!
 * @abstract
 * KDP only version of @c vm_map_store_lookup_entry().
 */
extern struct vm_map_entry *vm_map_store_lookup_entry_kdp(
	struct _vm_map         *map,
	vm_map_offset_t         address);

/*!
 * @abstract
 * Returns the size of the hole starting at a given address.
 *
 * @param map           The map to search.
 * @param address       The address to look for.
 * @param address_max   The max address allowed for the hole.
 *
 * @returns             The size of the hole starting at @c address,
 *                      0 if there's no hole at this address, or it ends there.
 */
extern vm_map_size_t vm_map_store_lookup_hole(
	struct _vm_map         *map,
	vm_map_offset_t         address,
	vm_map_offset_t         address_max);

/*!
 * @abstract
 * Returns whether there is any vm entry in the specified range.
 *
 * @param map           The map to search.
 * @param start         The range start.
 * @param end           The range end.
 *
 * @returns             Whether there are any existing vm entry in @c map,
 *                      within @c [start, end).
 */
extern bool vm_map_store_has_entries(
	struct _vm_map         *map,
	vm_map_offset_t         start,
	vm_map_offset_t         end);

/*!
 * @abstract
 * Locate free space in a map.
 *
 * @param map           The map to search.
 * @param range         The range to look into.
 * @param vmk_flags     Flags affecting lookup.
 * @param size          The size of the hole to find
 *                      (not including @c guard_offset).
 * @param mask          An alignment mask for the resulting allocation.
 *
 * @param reservation   The reservation being made (if KERN_SUCCESS is returned)
 *
 * @returns
 * - KERN_SUCCESS       A hole was found.
 * - KERN_NO_SPACE      No hole was found.
 */
extern kern_return_t vm_map_store_find_space(
	struct _vm_map         *map,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *reservation);


#pragma mark vm guard objects

/*!
 * @abstract
 * Return the guard object granule for a specified allocation size.
 */
__pure2
static inline uint8_t
vmgo_size_to_granule(vm_map_size_t size)
{
	static_assert(MACH_VM_MAX_ADDRESS <= (1ull << 47));
	static_assert(VM_KERNEL_POINTER_SIGNIFICANT_BITS <= 47);
	return (uint8_t)(flsll(size - 1));
}

/*!
 * @abstract
 * Returns the total size for a chunk
 */
__pure2
static inline vm_map_size_t
vmgo_chunk_size(vm_guard_object_chunk_t chunk)
{
	return (vm_map_size_t)chunk->vgoc_count << chunk->vgoc_granule;
}
/*!
 * @abstract
 * Returns the virtual address for the start of a chunk.
 */
__pure2
static inline vm_map_address_t
vmgo_chunk_start(vm_guard_object_chunk_t chunk)
{
	/* sign-extend vgoc_start to a vm_map_address_t */
	return (vm_map_address_t)(signed)chunk->vgoc_start << VMGO_START_SHIFT;
}
/*!
 * @abstract
 * Returns the virtual address for the end of a chunk.
 */
__pure2
static inline vm_map_address_t
vmgo_chunk_end(vm_guard_object_chunk_t chunk)
{
	return vmgo_chunk_start(chunk) + vmgo_chunk_size(chunk);
}

static inline uint64_t
vmgo_bitmap(vm_guard_object_chunk_t chunk)
{
	return chunk->vgoc_bitmap;
}

/*
 * VM Guard Object Chunk Slot computations.
 *
 * A chunk is made of @c vmgo_chunk_count(chunk) slots,
 * of size @c (1u << chunk->vgoc_granule) bytes.
 */
__pure2
static inline vm_map_address_t
vmgo_chunk_slot_start(vm_guard_object_chunk_t chunk, vm_map_size_t slot)
{
	assert(slot < chunk->vgoc_count);
	return vmgo_chunk_start(chunk) + (slot << chunk->vgoc_granule);
}
__pure2
static inline vm_map_address_t
vmgo_chunk_slot_end(vm_guard_object_chunk_t chunk, uint32_t slot)
{
	assert(slot < chunk->vgoc_count);
	return vmgo_chunk_start(chunk) + ((slot + 1) << chunk->vgoc_granule);
}
__pure2
static inline uint32_t
vmgo_chunk_slot(vm_guard_object_chunk_t chunk, vm_map_address_t address)
{
	address -= vmgo_chunk_start(chunk);
	return (uint32_t)(address >> chunk->vgoc_granule);
}


/*!
 * @abstract
 * Locate free space in a map using guard objects.
 *
 * @discussion
 * It is strictly required for correctness that empty chunks are not observable
 * to other callers. Therefore callers must be sure to insert into the allocated
 * slot (or abort) before dropping the interlock.
 *
 * @param map           The map to search.
 * @param slab          The guard object slab to use for chunks.
 * @param range         The range to look into.
 * @param vmk_flags     Flags affecting lookup.
 * @param size          The size of the hole to find
 *                      (not including @c guard_offset).
 * @param mask          An alignment mask for the resulting allocation.
 *
 * @param reservation   The reservation being made (if KERN_SUCCESS is returned)
 *
 * @returns
 * - KERN_SUCCESS       A hole was found. The caller must insert an entry
 *                      in this space, or free the reservation by calling
 *                      @c vm_guard_object_find_space_abort().
 * - KERN_NO_SPACE      No hole was found.
 * - KERN_NOT_SUPPORTED Guard objects can't be used for this request, and the
 *                      caller must fallback to @c vm_map_store_find_space().
 */
extern kern_return_t vm_guard_object_find_space_anywhere(
	vm_map_t                map,
	vm_guard_object_slab_t  slab,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	vm_map_size_t           size,
	vm_map_offset_t         mask,
	vm_map_store_rsv_t     *reservation);

/*!
 * @abstract
 * Returns a slot that was reserved with @c vm_guard_object_find_space_anywhere()
 * but unused.
 *
 * @param map           The map the reservation was made into.
 * @param reservation   The reservation to abort.
 */
extern void vm_guard_object_find_space_abort(
	vm_map_t                map,
	vm_map_store_rsv_t      reservation);

/*!
 * @abstract
 * Returns whether an operation is within the bounds of its guard object slot.
 *
 * @param entry         The entry to check the operation against,
 *                      the caller must have checked that this entry
 *                      is in a chunk.
 * @param start         The start of the operation.
 * @param end           The end of the operation.
 * @returns
 * - true               if the operation is contained within a slot
 * - false              if the operation exceeds the slot bounds
 */
extern bool vm_guard_object_check_op_range(
	struct vm_map_entry    *entry,
	vm_map_address_t        start,
	vm_map_address_t        end);


#pragma mark vm map/copy insertion/removal

/*!
 * @abstract
 * Insert an entry in a VM map copy at the head of the VM map copy.
 *
 * @param copy          The VM map copy to insert into.
 * @param entry         The entry to insert.
 */
extern void vm_map_copy_store_insert_head(
	struct vm_map_copy     *copy,
	struct vm_map_entry    *entry);

/*!
 * @abstract
 * Insert an entry in a VM map copy at the tail of the VM map copy.
 *
 * @param copy          The VM map copy to insert into.
 * @param entry         The entry to insert.
 */
extern void vm_map_copy_store_insert_tail(
	struct vm_map_copy     *copy,
	struct vm_map_entry    *entry);

/*!
 * @abstract
 * Remove an entry from a VM map copy.
 *
 * @param copy          The VM map copy to remove from.
 * @param entry         The entry to remove, it must be in the VM map copy.
 */
extern void vm_map_copy_store_remove(
	struct vm_map_copy     *copy,
	struct vm_map_entry    *entry);


/*!
 * @abstract
 * Insert an entry into a VM map.
 *
 * @discussion
 * The entry vme_start and vme_end must be set.
 * There must be a hole in the map corresponding to that range.
 *
 * @param map           The VM map to insert into.
 * @param entry         The entry to insert into the map.
 * @param reservation   The reservation made by @c vm_map_store_find_space().
 *                      Passing this back to @c vm_map_store_insert() is
 *                      optional and used as an optimization but the reservation
 *                      must have been made.
 * @param vmk_flags     The vm map kernel flags for the map operation being
 *                      done (it affects @c vm_map_entry_cs_associate(),
 *                      and @c vmf_fixed, @c vmkf_last_free which affects
 *                      guard-malloc policies).
 */
extern void vm_map_store_insert(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	vm_map_store_rsv_t      reservation,
	vm_map_kernel_flags_t   vmk_flags);

__attribute__((always_inline, overloadable))
static inline void
vm_map_store_insert(struct _vm_map *map, struct vm_map_entry *entry)
{
	/*
	 * Passing VM_MAP_KERNEL_FLAGS_FIXED() makes this insert have no other
	 * side effect than the insertion, in particular it leaves
	 * highest_entry_end alone.
	 */
	vm_map_store_insert(map, entry, (vm_map_store_rsv_t){ },
	    VM_MAP_KERNEL_FLAGS_FIXED());
}

/*!
 * @abstract
 * Options altering the behavior of @c vm_map_store_remove().
 *
 * @const VMS_REMOVE_NONE
 * No special behavior
 *
 * @const VMS_REMOVE_FREE_ENTRY
 * Free the removed entry on behalf of the caller by calling
 * @c vm_map_entry_free_locked().
 */
__options_decl(vms_remove_options_t, uint32_t, {
	VMS_REMOVE_NONE         = 0x0000,
	VMS_REMOVE_FREE_ENTRY   = 0x0001,
	VMS_REMOVE_FREE_SLOTS   = 0x0002,
});

/*!
 * @abstract
 * Remove an entry from a VM map.
 *
 * @param map           The VM map to remove from.
 * @param entry         The entry to remove from the map.
 */
extern void vm_map_store_remove(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	vms_remove_options_t    options);


#pragma mark vm map/copy clip/swap

/*!
 * @abstract
 * Clips an entry in a vm_map_copy_t to start at a greater start address.
 *
 * @discussion
 * The entry passed in will be set to start at the given address,
 * and a copy of the entry will be inserted before it.
 *
 * If the address requested is before the entry, this function does nothing.
 *
 * @param copy          The VM map copy @c entry belongs to.
 * @param entry         The entry to clip.
 * @param start         The address to clip at.
 */
extern void vm_map_copy_store_clip_start(
	struct vm_map_copy     *copy,
	struct vm_map_entry    *entry,
	vm_map_offset_t         start);

/*!
 * @abstract
 * Clips an entry in a vm_map_copy_t to end at a lesser end address.
 *
 * @discussion
 * The entry passed in will be set to end at the given address,
 * and a copy of the entry will be inserted after it.
 *
 * If the address requested is after the entry, this function does nothing.
 *
 * @param copy          The VM map copy @c entry belongs to.
 * @param entry         The entry to clip.
 * @param end           The address to clip at.
 */
extern void vm_map_copy_store_clip_end(
	vm_map_copy_t           copy,
	struct vm_map_entry    *entry,
	vm_map_offset_t         end);


/*!
 * @abstract
 * Clips an entry in a vm_map_t to start at a greater start address.
 *
 * @discussion
 * The entry passed in will be set to start at the given address,
 * and a copy of the entry will be inserted before it.
 *
 * @param map           The map @c entry belongs to.
 * @param entry         The entry to clip.
 * @param start         The address to clip at.
 * @returns             The newly inserted entry before @c entry.
 */
extern struct vm_map_entry *vm_map_store_clip_start(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	vm_map_offset_t         start);

/*!
 * @abstract
 * Clips an entry in a vm_map_t to end at a lesser end address.
 *
 * @discussion
 * The entry passed in will be set to end at the given address,
 * and a copy of the entry will be inserted after it.
 *
 * @param map           The map @c entry belongs to.
 * @param entry         The entry to clip.
 * @param end           The address to clip at.
 * @returns             The newly inserted entry after @c entry.
 */
extern struct vm_map_entry *vm_map_store_clip_end(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	vm_map_offset_t         end);

/*!
 * @abstract
 * Swap an entry in a vm_map_t with another one.
 *
 * @discussion
 * The bounds of @c new_entry must match @c old_entry's.
 *
 * @param map           The map @c old_entry belongs to.
 * @param old_entry     The entry to remove from @c map.
 * @param new_entry     The entry to swap @c old_entry with.
 */
extern void vm_map_store_swap(
	struct _vm_map         *map,
	struct vm_map_entry    *old_entry,
	struct vm_map_entry    *new_entry);


#pragma mark vm map/copy merge/extend

/*!
 * @abstract
 * Merge an entry into the one to its left.
 *
 * @discussion
 * @c left and @c right must be adjacent.
 *
 * @param map           The map @c left and @c right belong to.
 * @param left          The entry @c right will be merged into,
 *                      its bound will be extended to cover @c right.
 * @param right         The entry to merge into @c left,
 *                      it is up to the caller to dispose of it.
 */
extern void vm_map_store_merge_left(
	struct _vm_map         *map,
	struct vm_map_entry    *left,
	struct vm_map_entry    *right);

/*!
 * @abstract
 * Merge an entry into the one to its right.
 *
 * @discussion
 * @c left and @c right must be adjacent.
 *
 * @param map           The map @c left and @c right belong to.
 * @param left          The entry to merge into @c right,
 *                      it is up to the caller to dispose of it.
 * @param right         The entry @c left will be merged into,
 *                      its bound will be extended to cover @c left.
 */
extern void vm_map_store_merge_right(
	struct _vm_map         *map,
	struct vm_map_entry    *left,
	struct vm_map_entry    *right);

/*!
 * @abstract
 * Extend an entry into the hole to its right.
 *
 * @discussion
 * @c entry must be followed by a hole at ending at least at @c end.
 *
 * @param map           The map @c entry belongs to.
 * @param entry         The entry to extend, its bounds will be updated.
 * @param end           The new end for @c entry.
 */
extern void vm_map_store_extend_right(
	struct _vm_map         *map,
	struct vm_map_entry    *entry,
	vm_map_address_t        end);


#pragma mark vm map store pointer helpers

#define VMS_POINTER_NULL          ((vm_map_store_val_ptr_t){ })

/*!
 * @abstract
 * Converts a node into its packed representation.
 */
__attribute__((const, always_inline, overloadable))
static inline vm_map_store_node_ptr_t
vms_pointer(vm_map_store_node_t node)
{
	vm_map_store_node_ptr_t ptr = { };

	ptr.vmsp_packed = (uint32_t)VM_PACK_POINTER((vm_address_t)node, VMN_PACKED_PTR);
	return ptr;
}
__attribute__((const, always_inline, overloadable))
static inline vm_map_store_val_ptr_t
vms_pointer(struct vm_map_entry *entry)
{
	vm_map_store_val_ptr_t ptr = { };

	ptr.vmsp_packed = (uint32_t)VM_PACK_POINTER((vm_address_t)entry, VME_PACKED_PTR);
	ptr.vmsp_chunk  = false;
	return ptr;
}
__attribute__((const, always_inline, overloadable))
static inline vm_map_store_val_ptr_t
vms_pointer(vm_guard_object_chunk_t chunk)
{
	vm_map_store_val_ptr_t ptr = { };

	ptr.vmsp_packed = (uint32_t)VM_PACK_POINTER((vm_address_t)chunk, VME_PACKED_PTR);
	ptr.vmsp_chunk  = true;
	return ptr;
}


/*!
 * @abstract
 * Returns whether two pointers are equal.
 */
__attribute__((const, always_inline, overloadable))
static inline bool
vms_equal(vm_map_store_node_ptr_t p1, vm_map_store_node_ptr_t p2)
{
	return p1.vmsp_packed == p2.vmsp_packed;
}
__attribute__((const, always_inline, overloadable))
static inline bool
vms_equal(vm_map_store_val_ptr_t p1, vm_map_store_val_ptr_t p2)
{
	return p1.vmsp_chunk == p2.vmsp_chunk && p1.vmsp_packed == p2.vmsp_packed;
}


/*!
 * @abstract
 * Packed pointer helpers.
 */
__attribute__((const, always_inline, overloadable))
static inline bool
vms_is_null(vm_map_store_node_ptr_t ptr)
{
	return ptr.vmsp_packed == 0;
}
__attribute__((const, always_inline, overloadable))
static inline bool
vms_is_null(vm_map_store_val_ptr_t ptr)
{
	return ptr.vmsp_packed == 0;
}
__attribute__((const, always_inline))
static inline bool
vms_is_entry(vm_map_store_val_ptr_t ptr)
{
	return !vms_is_null(ptr) && !ptr.vmsp_chunk;
}
__attribute__((const, always_inline))
static inline bool
vms_is_chunk(vm_map_store_val_ptr_t ptr)
{
	return !vms_is_null(ptr) && ptr.vmsp_chunk;
}
__attribute__((const, always_inline))
static inline void *
vms_raw(vm_map_store_val_ptr_t ptr)
{
	return (void *)VM_UNPACK_POINTER(ptr.vmsp_packed, VME_PACKED_PTR);
}
__attribute__((const, always_inline))
static inline struct vm_map_entry *
vms_entry(vm_map_store_val_ptr_t ptr)
{
	assert(vms_is_entry(ptr));
	return (struct vm_map_entry *)vms_raw(ptr);
}
__attribute__((const, always_inline))
static inline vm_guard_object_chunk_t
vms_chunk(vm_map_store_val_ptr_t ptr)
{
	assert(vms_is_chunk(ptr));
	return (vm_guard_object_chunk_t)vms_raw(ptr);
}


#pragma mark vm map reservation helpers

__attribute__((const, always_inline, overloadable))
static inline vm_map_store_rsv_t
vmsr_make(vm_map_address_t addr, struct vm_map_entry *entry)
{
	vm_map_store_rsv_t rsv = {
		.vmsr_start    = (long long)addr,
		.vmsr_is_chunk = false,
		.vmsr_value    = (uintptr_t)entry,
	};

	return rsv;
}
__attribute__((const, always_inline, overloadable))
static inline vm_map_store_rsv_t
vmsr_make(vm_map_address_t addr, vm_guard_object_chunk_t chunk)
{
	vm_map_store_rsv_t rsv = {
		.vmsr_start    = (long long)addr,
		.vmsr_is_chunk = true,
		.vmsr_value    = (uintptr_t)chunk,
	};

	return rsv;
}

__attribute__((const, always_inline))
static inline vm_map_address_t
vmsr_start(vm_map_store_rsv_t rsv)
{
	return (vm_map_address_t)rsv.vmsr_start;
}
__attribute__((const, always_inline))
static inline bool
vmsr_is_entry(vm_map_store_rsv_t rsv)
{
	return !rsv.vmsr_is_chunk && rsv.vmsr_value;
}
__attribute__((const, always_inline))
static inline bool
vmsr_is_chunk(vm_map_store_rsv_t rsv)
{
	return rsv.vmsr_is_chunk && rsv.vmsr_value;
}
__attribute__((const, always_inline))
static inline struct vm_map_entry *
vmsr_entry(vm_map_store_rsv_t rsv)
{
	assert(vmsr_is_entry(rsv));
	return (struct vm_map_entry *)rsv.vmsr_value;
}
__attribute__((const, always_inline))
static inline vm_guard_object_chunk_t
vmsr_chunk(vm_map_store_rsv_t rsv)
{
	assert(vmsr_is_chunk(rsv));
	return (vm_guard_object_chunk_t)rsv.vmsr_value;
}


#if VM_MAP_STORE_PRIVATE || __BUILDING_XNU_LIB_UNITTEST__
#pragma mark - vm map store internals (exposed for testing purposes)

#if __BUILDING_XNU_LIB_UNITTEST__
#define __vms_extern(ty)        extern ty
#else
#define __vms_extern(ty)        static ty
#endif

/*!
 * @abstract
 * Represents a pair of a VM map store node pointer and an index in this node.
 *
 * @discussion
 * A slot is invalid if its @c vmss_ptr value is 0.
 *
 * This is used as a value type to describe that pair on the stack or as
 * a function parameter but not for use in any persistent data structure.
 */
typedef struct vms_slot {
	vm_map_store_node_ptr_t vmss_ptr;
	uint16_t                vmss_idx;
} vms_slot_t;

/*!
 * @abstract
 * A define for the canonical invalid slot.
 */
#define VMS_SLOT_INVALID ((struct vms_slot){ })


#pragma mark vm map store helpers

/*!
 * @abstract
 * Check if a node is a leaf or not
 */
__attribute__((always_inline, const))
static inline bool
vms_is_leaf(vm_map_store_node_t node)
{
	return node->vmsn_leaf;
}
__attribute__((always_inline, const))
static inline bool
vms_is_inner(vm_map_store_node_t node)
{
	return !node->vmsn_leaf;
}


/*!
 * @abstract
 * Returns the fanout of the node.
 */
__attribute__((always_inline, const))
static inline uint16_t
vms_fanout(vm_map_store_node_t node)
{
	return node->vmsn_leaf ? VMS_LEAF_FANOUT : VMS_NODE_FANOUT;
}


/*!
 * @abstract
 * Converts a packed pointer or slot into its corresponding node.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_store_node_t
vms_node(vm_map_store_node_ptr_t ptr)
{
	return (vm_map_store_node_t)VM_UNPACK_POINTER(ptr.vmsp_packed, VMN_PACKED_PTR);
}
__attribute__((always_inline, overloadable))
static inline vm_map_store_node_t
vms_node(vms_slot_t slot)
{
	return vms_node(slot.vmss_ptr);
}

/*!
 * @abstract
 * Returns the sibling of a node, or NULL.
 */
__attribute__((always_inline))
static inline vm_map_store_node_t
vms_next_sibling(vm_map_store_node_t node)
{
	return vms_node(node->vmsn_next_sibling);
}


/*!
 * @abstract
 * Returns the pointer to a slot key (start address).
 */
__attribute__((always_inline, overloadable))
static inline vm_map_address_t *
vms_keyp(vm_map_store_node_t node, uint16_t idx)
{
	assert(idx < vms_fanout(node));
	return vms_is_leaf(node) ? &node->vmsl_keys[idx] : &node->vmsn_keys[idx];
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t *
vms_keyp(vm_map_store_node_ptr_t ptr, uint16_t idx)
{
	return vms_keyp(vms_node(ptr), idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t *
vms_keyp(vms_slot_t slot)
{
	return vms_keyp(slot.vmss_ptr, slot.vmss_idx);
}


/*!
 * @abstract
 * Returns the pointer to a slot's node pointer.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_store_node_ptr_t *
vms_nodep(vm_map_store_node_t node, uint16_t idx)
{
	assert(vms_is_inner(node) && idx < VMS_NODE_FANOUT);
	__builtin_assume(node->vmsn_leaf == 0);
	return &node->vmsn_ptrs[idx];
}
__attribute__((always_inline, overloadable))
static inline vm_map_store_node_ptr_t *
vms_nodep(vm_map_store_node_ptr_t ptr, uint16_t idx)
{
	return vms_nodep(vms_node(ptr), idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_store_node_ptr_t *
vms_nodep(vms_slot_t slot)
{
	return vms_nodep(slot.vmss_ptr, slot.vmss_idx);
}


/*!
 * @abstract
 * Returns the pointer to a slot's hole bitmask.
 */
__attribute__((always_inline, overloadable))
static inline uint32_t *
vms_holesp(vm_map_store_node_t node, uint16_t idx)
{
	assert(vms_is_inner(node) && idx < VMS_NODE_FANOUT);
	__builtin_assume(node->vmsn_leaf == 0);
	return &node->vmsn_holes[idx];
}
__attribute__((always_inline, overloadable))
static inline uint32_t *
vms_holesp(vm_map_store_node_ptr_t ptr, uint16_t idx)
{
	return vms_holesp(vms_node(ptr), idx);
}
__attribute__((always_inline, overloadable))
static inline uint32_t *
vms_holesp(vms_slot_t slot)
{
	return vms_holesp(slot.vmss_ptr, slot.vmss_idx);
}


/*!
 * @abstract
 * Returns the pointer to a slot's value pointer.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_store_val_ptr_t *
vms_valp(vm_map_store_node_t node, uint16_t idx)
{
	assert(vms_is_leaf(node) && idx < VMS_LEAF_FANOUT);
	__builtin_assume(node->vmsn_leaf == 1);
	return &node->vmsl_ptrs[idx];
}
__attribute__((always_inline, overloadable))
static inline vm_map_store_val_ptr_t *
vms_valp(vm_map_store_node_ptr_t ptr, uint16_t idx)
{
	return vms_valp(vms_node(ptr), idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_store_val_ptr_t *
vms_valp(vms_slot_t slot)
{
	return vms_valp(slot.vmss_ptr, slot.vmss_idx);
}


/*!
 * @abstract
 * Returns the start address corresponding to a slot.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_start(vm_map_store_node_t node)
{
	return *vms_keyp(node, 0);
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_start(vm_map_store_node_t node, uint16_t idx)
{
	assert(idx < vms_fanout(node));
	return *vms_keyp(node, idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_start(vm_map_store_node_ptr_t ptr, uint16_t idx)
{
	return vms_start(vms_node(ptr), idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_start(vms_slot_t slot)
{
	return vms_start(vms_node(slot.vmss_ptr), slot.vmss_idx);
}

/*!
 * @abstract
 * Returns the start address corresponding to a slot,
 * or @c start whichever is larger.
 */
__attribute__((always_inline))
static inline vm_map_address_t
vms_start_after(vms_slot_t slot, vm_map_address_t start)
{
	vm_map_address_t addr = vms_start(slot);

	return start < addr ? addr : start;
}

/*!
 * @abstract
 * Returns the end address corresponding to a a slot.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_end(vm_map_store_node_t node)
{
	if (!vms_is_null(node->vmsn_next_sibling)) {
		return vms_start(node->vmsn_next_sibling, 0);
	}
	return ~0ull;
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_end(vm_map_store_node_t node, uint16_t idx)
{
	/* check if the next node is within this node or its sibling */
	if (idx + 1 < node->vmsn_count) {
		return *vms_keyp(node, idx + 1);
	}
	return vms_end(node);
}
__attribute__((always_inline, overloadable))
static inline vm_map_address_t
vms_end(vms_slot_t slot)
{
	return vms_end(vms_node(slot.vmss_ptr), slot.vmss_idx);
}

/*!
 * @abstract
 * Returns the end address corresponding to a slot,
 * or @c end whichever is smaller.
 */
__attribute__((always_inline))
static inline vm_map_address_t
vms_end_before(vms_slot_t slot, vm_map_address_t end)
{
	vm_map_address_t addr = vms_end(slot);

	return end > addr ? addr : end;
}

/*!
 * @abstract
 * Returns the size of a slot.
 */
__attribute__((always_inline, overloadable))
static inline vm_map_size_t
vms_size(vm_map_store_node_t node, uint16_t idx)
{
	return vms_end(node, idx) - vms_start(node, idx);
}
__attribute__((always_inline, overloadable))
static inline vm_map_size_t
vms_size(vms_slot_t slot)
{
	return vms_size(vms_node(slot), slot.vmss_idx);
}


/*!
 * @abstract
 * Links two node together.
 */
__attribute__((always_inline, overloadable))
static inline void
vms_link(vm_map_store_node_t left, vm_map_store_node_t right)
{
	left->vmsn_next_sibling = vms_pointer(right);
}
__attribute__((always_inline))
static inline void
vms_link(vm_map_store_node_t left, vm_map_store_node_ptr_t right)
{
	left->vmsn_next_sibling = right;
}

/*!
 * @abstract
 * Returns the hole mask for a given node.
 */
__vms_extern(uint32_t) vms_holes(
	vm_map_store_node_t     node);


#pragma mark vm map store slots

static inline bool
vms_slot_is_null(vms_slot_t slot)
{
	return vms_is_null(*vms_valp(slot));
}
static inline bool
vms_slot_is_entry(vms_slot_t slot)
{
	return vms_is_entry(*vms_valp(slot));
}
static inline bool
vms_slot_is_chunk(vms_slot_t slot)
{
	return vms_is_chunk(*vms_valp(slot));
}

static inline struct vm_map_entry *
vms_slot_entry(vms_slot_t slot)
{
	return vms_entry(*vms_valp(slot));
}
static inline vm_guard_object_chunk_t
vms_slot_chunk(vms_slot_t slot)
{
	return vms_chunk(*vms_valp(slot));
}


static inline bool
vms_slot_is_valid(vms_slot_t slot)
{
	return !vms_is_null(slot.vmss_ptr);
}

/*!
 * @brief
 * Returns the next slot at the same node level.
 *
 * @discussion
 * This can be used to implement iterators across nodes.
 * If the iteration goes past the last slot at this node level,
 * the slot becomes { .vms_ptr = VMS_POINTER_NULL, .vms_idx = 0 },
 * which can be tested with @c vms_slot_is_valid().
 */
static inline vms_slot_t
vms_slot_next(vms_slot_t slot)
{
	vm_map_store_node_t node = vms_node(slot);

	if (node && ++slot.vmss_idx >= node->vmsn_count) {
		slot.vmss_ptr = node->vmsn_next_sibling;
		slot.vmss_idx = 0;
	}
	return slot;
}

static inline void
vms_slot_assert_value(vms_slot_t slot, vm_map_store_val_ptr_t ptr)
{
#pragma unused(slot, ptr)
	assert3u(vms_valp(slot)->vmsp_packed, ==, ptr.vmsp_packed);
}

static inline void
vms_slot_assert_hole(vms_slot_t slot)
{
	vms_slot_assert_value(slot, VMS_POINTER_NULL);
}

static inline void
vms_slot_assert_start(vms_slot_t slot, vm_map_address_t addr)
{
#pragma unused(slot, addr)
	assert3u(vms_start(slot), ==, addr);
}

static inline void
vms_slot_assert_end(vms_slot_t slot, vm_map_address_t addr)
{
#pragma unused(slot, addr)
	assert3u(vms_end(slot), ==, addr);
}

static inline void
vms_slot_assert_entry(
	vms_slot_t              slot,
	vm_map_address_t        start,
	struct vm_map_entry    *entry,
	vm_map_address_t        end)
{
	vms_slot_assert_start(slot, start);
	vms_slot_assert_value(slot, vms_pointer(entry));
	vms_slot_assert_end(slot, end);
}

static inline void
vms_slot_assert_contains(vms_slot_t slot, vm_map_address_t addr)
{
#pragma unused(slot, addr)
	assert3u(vms_start(slot), <=, addr);
	assert3u(addr, <, vms_end(slot));
}


#pragma mark vm map store path

#define VMS_PATH_INLINE         5  /* this should cover 1.5M entries trees */

/*!
 * @abstract
 * Represents a path into a VM map store B+tree.
 *
 * @discussion
 * A path is modeled as a stack of slots.
 *
 * @field vmsp_cur      The slot currently at the "top" of the stack
 * @field vmsp_pos      The number of slots on the stack, not counting
 *                      the @c vmsp_cur one. It must be valued between
 *                      0 and @c vmsp_depth.
 *
 * @field vmsp_depth    A cache of the depth of the tree, which also is
 *                      the maximum number of elements in the stack (not
 *                      counting @c vmsp_cur).
 *
 * @field vmsp_stack    The stack of nodes leading to @c vmsp_cur.
 * @field vmsp_inline   Pre-allocated inline storage for @c vmsp_stack.
 */
typedef struct vms_path {
	vms_slot_t              vmsp_cur;
	uint32_t                vmsp_pos;
	uint32_t                vmsp_depth;
	vms_slot_t             *vmsp_stack;
	struct vms_slot         vmsp_inline[VMS_PATH_INLINE];
} *vms_path_t;

#define VMS_PATH_DECLARE(name, root) \
	__attribute__((cleanup(vms_path_destroy))) \
	struct vms_path name ## _store; \
	vms_path_t const name = vms_path_init(&name ## _store, root)


/*!
 * @brief
 * Initializes a VM map store b+tree path.
 *
 * @discussion
 * Called automatically by VMS_PATH_DECLARE().
 */
__vms_extern(vms_path_t) vms_path_init(
	vms_path_t              path,
	vm_map_store_root_t     root);

/*!
 * @brief
 * Cleans up a VM map store b+tree path.
 *
 * @discussion
 * Called automatically by VMS_PATH_DECLARE().
 */
__vms_extern(void) vms_path_destroy(
	vms_path_t              path);

/*!
 * @brief
 * Performs a path resolution to a given address.
 *
 * @discussion
 * The path must be freshly initialized, with its current node pointing
 * at the root of the B+tree.
 *
 * Path resolution is the operation that records the path taken inside
 * a B+tree to reach the slot corresponding to @c addr, which is then used
 * by mutation functions to propagate changes back upwards this path
 * as appropriate.
 *
 * @param path          The path to use for resolution
 * @param addr          The address to resolve
 */
__vms_extern(vms_slot_t) vms_path_resolve(
	vms_path_t              path,
	vm_map_address_t        addr);


#pragma mark vm guard object helpers

__pure2
static inline uint8_t
vmgo_chunk_guards(vm_guard_object_chunk_t chunk)
{
	return (chunk->vgoc_count / 4) ?: 1;
}
static inline uint8_t
vmgo_chunk_free_count(vm_guard_object_chunk_t chunk)
{
	uint8_t avail = chunk->vgoc_available;
	uint8_t qtn   = chunk->vgoc_quarantined;

	return avail + qtn + vmgo_chunk_guards(chunk);
}

__pure2
static inline uint32_t
vmgo_chunk_skiplist_idx(vm_guard_object_chunk_t chunk, vm_map_address_t address)
{
	address  -= vmgo_chunk_start(chunk);
	address  *= ARRAY_COUNT(chunk->vgoc_ptrs);
	address >>= chunk->vgoc_count_shift + chunk->vgoc_granule;
	return (uint32_t)address;
}

/*!
 * @brief
 * Allocates a new chunk for the specified size class.
 *
 * @discussion
 * This is used to add new chunks to a given slab, and will use the regular
 * VM map first-fit policy to find free space, observing the flags
 * vmkf_last_free bit.
 *
 * @param map           The map to reserve free space from.
 * @param slab          The slab to insert the newly allocated chunk into.
 * @param range         The range to limit the free space lookup to.
 * @param vmk_flags     The flags for the lookup, only the vmkf_last_free bit is
 *                      observed, others are ignored.
 * @param granule       The granule to allocate for.
 * @param mask          The required alignment mask.
 * @returns             A newly allocated chunk, or NULL if no space was found.
 */
__vms_extern(vm_guard_object_chunk_t) vmgo_chunk_alloc_anywhere(
	vm_map_t                map,
	vm_guard_object_slab_t  slab,
	struct mach_vm_range    range,
	vm_map_kernel_flags_t   vmk_flags,
	uint8_t                 granule,
	vm_map_address_t        mask);

/*!
 * @brief
 * Reserve a slot from a specified chunk.
 *
 * @discussion
 * The slot must be free, and the chunk must have available allocations.
 *
 * @param chunk         The chunk to reserve into.
 * @param idx           The slot index to reserve.
 * @returns             A newly allocated chunk, or NULL if no space was found.
 */
__vms_extern(vm_map_address_t) vmgo_chunk_reserve_slot(
	vm_guard_object_chunk_t chunk,
	uint32_t                idx);


#pragma mark vm map store creation/destruction

/*!
 * @brief
 * Allocate a new VM map store node.
 *
 * @param is_leaf        Whether the allocated node is a leaf (true)
 *                       or an internal node (false).
 */
__vms_extern(vm_map_store_node_t) vms_node_alloc(
	bool                    is_leaf);

/*!
 * @brief
 * Helper to update the @c vmsn_count field of a node.
 *
 * @discussion
 * This helper is required in order to maintain some invariants
 * the NEON accelerated lookups rely on.
 */
__vms_extern(void) vms_node_set_count(
	vm_map_store_node_t     node,
	uint16_t                count);


/*!
 * @brief
 * Initialize a VM map store B+tree root.
 */
__vms_extern(void) vms_root_init(
	vm_map_store_root_t   * root);

/*!
 * @brief
 * Destroys a VM map store created with @c vms_root_init().
 */
__vms_extern(void) vms_root_destroy(
	vm_map_store_root_t   * root);


#pragma mark vm map store lookup

/*!
 * @brief
 * Looks up the slot in a VM map store B+tree corresponding to an address.
 *
 * @param map           The map to search.
 * @param addr          The address to lookup.
 */
__vms_extern(vms_slot_t) vm_map_store_lookup(
	struct _vm_map         *map,
	vm_map_address_t        addr);


#pragma mark vm map store mutation helpers

/*!
 * @abstract
 * Internal helper to split a node at a given position,
 * in order to insert a new value at index @c idx.
 *
 * @discussion
 * It is expected that at least one of split_left or split_right is true.
 *
 * If the sequence of values is [a, b, c, d, e], and idx is 2 (corresponding to
 * the "c" value), then the resulting sequence will be the following.
 *
 * <insertion point> denotes where a hole has been left, and @c wslot will point
 * to it.  It is up to the caller to set the key and value for this slot,
 * as well as the key for the right value if @c split_right is true.
 *
 * - split_left=1 split_right=0: [a, b, c, <insertion point>, d, e]
 * - split_left=0 split_right=1: [a, b, <insertion point>, c, d, e]
 * - split_left=1 split_right=1: [a, b, c, <insertion point>, c, d, e]
 *
 * @param node          The node to split.
 * @param idx           The index for the current pivot,
 *                      It must be within [node, node->vmsn_count)
 * @param split_left    Whether the slot at @c idx must be split left.
 * @param split_right   Whether the slot at @c idx must be split right.
 * @param wslot         The slot corresponding to the insertion point.
 * @returns             The newly created node, linked after @c node.
 */
__vms_extern(vm_map_store_node_t) __vms_node_split(
	vm_map_store_node_t     node,
	uint16_t                idx,
	bool                    split_left,
	bool                    split_right,
	vms_slot_t            * wslot);

/*!
 * @abstract
 * Internal helper to split the node pointed at by @c path.
 *
 * @discussion
 * This function invalidates @c path.
 *
 * @param root          The root of the VM map store being mutated.
 * @param path          The path to the leaf node to split.
 * @param start         The start of the split point.
 * @param ptr           The new value to put into the right-part of the split.
 */
__vms_extern(void) __vms_mut_split(
	vm_map_store_root_t   * root,
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_store_val_ptr_t  ptr);

/*!
 * @abstract
 * Internal helper to help insert a node inside a given leaf.
 *
 * @discussion
 * This function invalidates @c path.
 *
 * It is expected that the path points to a slot that is a hole that contains
 * @c [start, end). If that hole is wider, it will be split to accomodate
 * for the insertion.
 *
 * @param root          The root of the VM map store being mutated.
 * @param path          The path to the leaf node to insert into.
 * @param start         The start address for the inserted value.
 * @param end           The end address for the inserted value.
 * @param ptr           The value to insert, it can't be a hole.
 */
__vms_extern(void) __vms_mut_insert(
	vm_map_store_root_t   * root,
	vms_path_t              path,
	vm_map_address_t        start,
	vm_map_address_t        end,
	vm_map_store_val_ptr_t  ptr);

/*!
 * @abstract
 * Internal helper to fold slots toward the left in a node.
 *
 * @discussion
 * Folding a series of slots [a, b, c] into a means erasing b and c,
 * and extend a's bound to cover that entire range.
 *
 * This function invalidates @c path.
 *
 * @param root          The root of the VM map store being mutated.
 * @param path          The path to the leaf node to insert into.
 * @param count         The number of slots to fold,
 *                      not including the one being folded into.
 * @param update_holes  Whether holes in this node will change as a result
 *                      of this call, and masks must be updated.
 */
__vms_extern(void) __vms_mut_fold(
	vm_map_store_root_t   * root,
	vms_path_t              path,
	uint16_t                count,
	bool                    update_holes);

/*!
 * @abstract
 * Internal helper to erase slots.
 *
 * @discussion
 * @c start and @end must be the actual boundaries of slots, and:
 * - @c start can't be the end of a hole,
 * - @c end can't be the start of a hole.
 *
 * @param root          The root of the VM map store being mutated.
 * @param start         The start address of the range to erase.
 * @param end           The end address of the range to erase.
 */
__vms_extern(void) __vms_mut_erase(
	vm_map_store_root_t   * root,
	vm_map_address_t        start,
	vm_map_address_t        end);


#endif /* VM_MAP_STORE_PRIVATE || __BUILDING_XNU_LIB_UNITTEST__ */

__exported_pop
__END_DECLS

#endif /* _VM_VM_MAP_STORE_H */
