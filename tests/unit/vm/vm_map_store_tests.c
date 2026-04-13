/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <darwintest.h>
#include <mocks/osfmk/unit_test_utils.h>
#include <mach/vm_map.h>
#include <vm/vm_map_store_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.store"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"));

#define VM_MAP_DEFAULT_MIN        GiB(1)
#define VM_MAP_DEFAULT_MAX        GiB(-1)


static struct {
	vm_map_store_root_t      *root;
	vm_map_t                  map;
	bool                      in_verification;

	vm_map_store_root_t       root_storage;
} t_info;

static uint32_t t_verification;

#pragma mark debugging help

__attribute__((noinline, used, overloadable))
static void
t_dump_node(vm_map_store_node_t node, uint32_t row, uint32_t column)
{
	const char *type = vms_is_leaf(node) ? "leaf" : "node";

	if (row != UINT32_MAX) {
		T_LOG("  %d.%-3.3d─ 0x%016lx 0x%016llx:0x%016llx %s\n",
		    row, column, (uintptr_t)node,
		    vms_start(node), vms_end(node), type);
	} else {
		T_LOG("  node  ─ 0x%016lx 0x%016llx:0x%016llx %s\n",
		    (uintptr_t)node, vms_start(node), vms_end(node), type);
	}

	for (uint16_t i = 0; i < node->vmsn_count; i++) {
		vm_map_address_t start = vms_start(node, i);
		vm_map_address_t end   = vms_end(node, i);
		const char      *sep   = "│";

		if (i + 1 == node->vmsn_count) {
			sep = "╰";
		}

		if (!vms_is_leaf(node)) {
			T_LOG("  %s %-2.2d   0x%016lx 0x%016llx:0x%016llx 0x%08x\n",
			    sep, i, (uintptr_t)vms_node(*vms_nodep(node, i)),
			    start, end, *vms_holesp(node, i));
			continue;
		}

		if (vms_is_null(*vms_valp(node, i))) {
			T_LOG("  %s %-2.2d   ------------------ 0x%016llx:0x%016llx\n",
			    sep, i, start, end);
		} else {
			T_LOG("  %s %-2.2d   0x%016lx 0x%016llx:0x%016llx\n",
			    sep, i, (uintptr_t)vms_raw(*vms_valp(node, i)), start, end);
		}

		if (i + 1 == node->vmsn_count) {
			sep = " ";
		}

		if (vms_is_chunk(*vms_valp(node, i))) {
			vm_guard_object_chunk_t chunk   = vms_chunk(*vms_valp(node, i));
			vm_map_size_t           granule = 1ul << chunk->vgoc_granule;
			vm_map_entry_t          vme     = vm_map_to_entry(t_info.map);

			T_LOG("  %s │\n", sep);
			T_LOG("  %s │ slab:     0x%016lx\n",
			    sep, (uintptr_t)chunk->vgoc_slab);
			T_LOG("  %s │ config:   %d x %d%c, %d guards\n",
			    sep, chunk->vgoc_count,
			    1 << (chunk->vgoc_granule % 10),
			        "VKMGT"[chunk->vgoc_granule / 10],
			        vmgo_chunk_guards(chunk));
			T_LOG("  %s │ avail:    %d\n", sep, chunk->vgoc_available);
			T_LOG("  %s │ used:     %d\n", sep, chunk->vgoc_count -
			    __builtin_popcountll(chunk->vgoc_bitmap));
			T_LOG("  %s │ qtn:      %d\n", sep, chunk->vgoc_quarantined);
			T_LOG("  %s │\n", sep);

			if (vms_is_entry(chunk->vgoc_ptrs[0])) {
				vme = vms_entry(chunk->vgoc_ptrs[0]);
			}
			for (uint32_t idx = 0; idx < chunk->vgoc_count; idx++) {
				vm_map_address_t cur  = start + idx * granule;
				vm_map_address_t end  = cur + granule;
				vm_map_address_t lim  = cur + granule;
				const char      *sep2 = "│";
				const char      *sep3 = NULL;
				const char      *dot  = " ";
				char             lbl[20];

				if (idx + 1 == chunk->vgoc_count) {
					sep2 = "╰";
				}
				if (!bit_test(chunk->vgoc_bitmap, idx)) {
					dot = "•";
				}

				snprintf(lbl, sizeof(lbl), "%s%s%2d", sep2, dot, idx);

				do {
					if (vme == vm_map_to_entry(t_info.map)) {
						lim = end;
					} else if (cur < vme->vme_start) {
						lim = MIN(end, vme->vme_start);
					} else {
						lim = MIN(end, vme->vme_end);
					}
					if (sep3 && lim == end) {
						sep3 = "╰";
					}
					if (sep3) {
						snprintf(lbl, sizeof(lbl),
						    "%s  %s", sep2, sep3);
					}

					if (vme == vm_map_to_entry(t_info.map)) {
						T_LOG("  %s %s ------------------ 0x%016llx:0x%016llx\n",
						    sep, lbl, cur, end);
						break;
					}

					if (cur < vme->vme_start) {
						T_LOG("  %s %s ------------------ 0x%016llx:0x%016llx\n",
						    sep, lbl, cur, lim);
					} else {
						T_LOG("  %s %s 0x%016lx 0x%016llx:0x%016llx\n",
						    sep, lbl, (uintptr_t)vme, cur, lim);
					}
					cur = lim;
					if (cur >= vme->vme_end) {
						vme = vme->vme_next;
					}
					if (idx + 1 == chunk->vgoc_count) {
						sep2 = " ";
					}
					sep3 = "│";
				} while (cur < end);
			}
		}
	}
}
__attribute__((noinline, used, overloadable))
static void
t_dump_node(vm_map_store_node_t node)
{
	return t_dump_node(node, UINT32_MAX, 0);
}
__attribute__((noinline, used, overloadable))
static void
t_dump_node(vm_map_store_node_ptr_t node_ptr)
{
	return t_dump_node(vms_node(node_ptr));
}
__attribute__((noinline, used, overloadable))
static void
t_dump_node(vms_slot_t slot)
{
	return t_dump_node(vms_node(slot));
}
__attribute__((noinline, used, overloadable))
static void
t_dump_node(uintptr_t node_addr)
{
	return t_dump_node((vm_map_store_node_t)node_addr);
}


__attribute__((noinline, used))
static void
t_dump(void)
{
	vm_map_store_node_ptr_t ptr   = t_info.root->vmsr_root;
	vm_map_store_node_t     child = vms_node(ptr);
	uint32_t                depth = 0;

	while (child) {
		vm_map_store_node_t node = child;
		uint32_t nidx = 0;

		if (vms_is_leaf(child)) {
			child = NULL;
		} else {
			child = vms_node(*vms_nodep(node, 0));
		}

		T_LOG("row %d\n", depth);
		while (node) {
			t_dump_node(node, depth, nidx++);
			node = vms_next_sibling(node);
		}

		depth++;
	}
}


__attribute__((noinline, used, overloadable))
static vm_map_store_node_t
t_vms_node(vm_map_store_node_ptr_t ptr)
{
	return vms_node(ptr);
}
__attribute__((noinline, used, overloadable))
static vm_map_store_node_t
t_vms_node(vms_slot_t slot)
{
	return vms_node(slot.vmss_ptr);
}
__attribute__((noinline, used, overloadable))
static vm_map_store_node_t
t_vms_node(uint32_t raw_ptr)
{
	return vms_node((vm_map_store_node_ptr_t){ .vmsp_packed = raw_ptr });
}


#pragma mark test helpers

typedef struct t_flat_nodes {
	uint32_t                len;
	vm_map_address_t       *keys;
	vm_map_store_val_ptr_t *vals;
} *t_flat_nodes_t;

static void
t_at_end(void)
{
	if (t_info.root) {
		t_dump();
	}
	if (t_info.in_verification) {
		T_LOG("");
		T_LOG("\e[38;5;1m" "~~~~~~~~ LLDB TIPS ~~~~~~~~" "\e[0m");
		T_LOG("");
		T_LOG("* To stop at the last OK validation use:");
		T_LOG("");
		T_LOG("\e[38;5;8m" "  breakpoint set -n t_validate_root -c 't_verification == %d'" "\e[0m",
		    t_verification - 1);
		T_LOG("");
		T_LOG("* Run the test, and on breakpoint hit:");
		T_LOG("");
		T_LOG("\e[38;5;8m" "  fin" "\e[0m");
		T_LOG("");
		T_LOG("* To dump the state of the map:");
		T_LOG("");
		T_LOG("\e[38;5;8m" "  p t_dump()" "\e[0m");
		T_LOG("");
		T_LOG("\e[38;5;1m" "~~~~~~~~~~~~~~~~~~~~~~~~~~~" "\e[0m");
		T_LOG("");
	}
}

static void
t_setup(bool do_map)
{
	static bool atend_done;

	/*
	 * This a hack: if the test asserts in the middle, mte_info_cells will
	 * not be freed, and be printed.
	 */
	if (!atend_done) {
		T_ATEND(t_at_end);
		atend_done = true;
	}

	T_QUIET; T_ASSERT_FALSE(t_info.root, "test_teardown was forgotten");

	if (do_map) {
		pmap_t pmap = pmap_create_options(NULL, 0, PMAP_CREATE_64BIT);

		t_info.map = vm_map_create_options(pmap, VM_MAP_DEFAULT_MIN,
		    VM_MAP_DEFAULT_MAX, VM_MAP_CREATE_DEFAULT);
		t_info.root = &t_info.map->root;
		vm_map_guard_object_slab_init(t_info.map);
	} else {
		t_info.root = &t_info.root_storage;
	}
}

static vm_map_t
t_setup_map(void)
{
	t_setup(true);
	return t_info.map;
}

static void
t_done(void)
{
	T_QUIET; T_ASSERT_NOTNULL(t_info.root, "t_done without t_setup?");

	if (t_info.map) {
		vm_map_destroy(t_info.map);
	} else {
		vms_root_destroy(t_info.root);
	}
	t_info.map  = VM_MAP_NULL;
	t_info.root = NULL;
}

static vm_map_store_root_t *
t_root(void)
{
	return t_info.root;
}

static vm_guard_object_slab_t
t_slab(void)
{
	return t_info.map->guard_object_slabs;
}

typedef struct t_setup_root_ctx {
	uint32_t               node;
	uint32_t               hole;
	uint32_t               column;
	uint16_t               idx;
} *t_setup_root_ctx_t;

__attribute__((overloadable))
static void
t_setup_root(
	uint32_t                leaves,
	vm_map_size_t           entry_size,
	vm_map_size_t         (^hole_size)(t_setup_root_ctx_t ctx))
{
	vm_map_store_node_t  head  = NULL;
	vm_map_store_node_t  tail  = NULL;
	vm_map_address_t     addr  = 0;
	bool                 hole  = true;
	uintptr_t            v     = 0;
	struct t_setup_root_ctx ctx = {
	};

	t_setup(false);

	if (leaves == 0) {
		vms_root_init(t_info.root);
		return;
	}

	head = tail = vms_node_alloc(true);
	t_root()->vmsr_root  = vms_pointer(head);
	t_root()->vmsr_depth = 0;

	while (ctx.node <= leaves) {
		vm_map_store_node_t node = tail;
		vm_size_t           size;

		if (ctx.idx == VMS_LEAF_FANOUT) {
			node     = vms_node_alloc(true);
			ctx.idx  = 0;
			ctx.column++;
			vms_link(tail, node);
			tail = node;
		}

		if (hole && hole_size && (size = hole_size(&ctx))) {
			vms_node_set_count(node, ctx.idx + 1);
			*vms_keyp(node, ctx.idx) = addr;
			*vms_valp(node, ctx.idx) = VMS_POINTER_NULL;
			addr     += size;
			hole      = false;
			ctx.node += 1;
			ctx.hole += 1;
			ctx.idx  += 1;
		} else {
			vms_node_set_count(node, ctx.idx + 1);
			*vms_keyp(node, ctx.idx) = addr;
			if (!hole_size && ctx.node == leaves) {
				*vms_valp(node, ctx.idx) = VMS_POINTER_NULL;
			} else {
				v += 0x4;
				vms_valp(node, ctx.idx)->vmsp_packed = v;
			}
			addr     += entry_size;
			hole      = true;
			ctx.node += 1;
			ctx.idx  += 1;
		}
	}

	while (head != tail) {
		vm_map_store_node_t bottom = head;

		head = tail = vms_node_alloc(false);
		t_root()->vmsr_root = vms_pointer(head);
		t_root()->vmsr_depth++;

		for (; bottom; bottom = vms_next_sibling(bottom)) {
			vm_map_store_node_t node = tail;
			uint32_t            pos  = node->vmsn_count;

			if (pos == VMS_NODE_FANOUT) {
				node = vms_node_alloc(false);
				pos  = 0;
				vms_link(tail, node);
				tail = node;
			}

			vms_node_set_count(node, pos + 1);
			*vms_keyp(node, pos)   = vms_start(bottom);
			*vms_nodep(node, pos)  = vms_pointer(bottom);
			*vms_holesp(node, pos) = vms_holes(bottom);
		}
	}
}
__attribute__((overloadable))
static void
t_setup_root(uint32_t leaves, vm_map_size_t stride)
{
	return t_setup_root(leaves, stride, NULL);
}

__attribute__((noinline))
static vms_slot_t
t_find_leaf(uint32_t n)
{
	vm_map_store_node_t node = vms_node(t_root()->vmsr_root);

	while (!vms_is_leaf(node)) {
		node = vms_node(*vms_nodep(node, 0));
	}

	while (n >= node->vmsn_count) {
		n   -= node->vmsn_count;
		node = vms_next_sibling(node);
	}

	return (vms_slot_t){ vms_pointer(node), (uint16_t)n };
}

static vm_map_store_val_ptr_t
t_generate_entry(void)
{
	static vm_map_store_val_ptr_t curv = {
		.vmsp_packed = 0x1000,
	};

	curv.vmsp_packed += 4;
	return curv;
}

static vm_map_entry_t
t_add_entry(
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_size_t           size,
	vm_map_address_t       *end_p)
{
	vm_map_address_t end   = start + size;;
	vm_map_entry_t   entry = vm_map_entry_create_locked(map, start, end);

	entry->protection = VM_PROT_DEFAULT;
	entry->max_protection = VM_PROT_ALL;
	vm_map_store_insert(map, entry);
	vm_entry_unlock_exclusive(map, entry);
	if (end_p) {
		*end_p = end;
	}
	return entry;
}

static uint32_t
t_node_row_len(vm_map_store_node_t node)
{
	uint32_t n = 0;

	do {
		n++;
	} while ((node = vms_next_sibling(node)));

	return n;
}

__attribute__((overloadable))
static t_flat_nodes_t
t_flatten(vm_map_store_node_t node)
{
	t_flat_nodes_t flat;
	uint32_t pos = 0;

	while (!vms_is_leaf(node)) {
		node = vms_node(*vms_nodep(node, 0));
	}

	for (vm_map_store_node_t n = node; n; n = vms_next_sibling(n)) {
		pos += n->vmsn_count;
	}

	flat = calloc(1, sizeof(struct t_flat_nodes));
	flat->len  = pos;
	flat->keys = calloc(pos, sizeof(vm_map_address_t));
	flat->vals = calloc(pos, sizeof(uintptr_t));

	pos = 0;
	for (vm_map_store_node_t n = node; n; n = vms_next_sibling(n)) {
		for (uint32_t i = 0; i < n->vmsn_count; i++) {
			flat->keys[pos] = *vms_keyp(n, i);
			flat->vals[pos] = *vms_valp(n, i);
			pos++;
		}
	}

	return flat;
}
__attribute__((overloadable))
static t_flat_nodes_t
t_flatten(void)
{
	return t_flatten(vms_node(t_root()->vmsr_root));
}

static void
t_flatten_free(t_flat_nodes_t flat)
{
	free(flat->keys);
	free(flat->vals);
	free(flat);
}


#pragma mark tree validation

typedef struct t_tree_validation_ctx {
	vm_map_store_root_t    *root;
	vm_map_entry_t          next_e;
	uint32_t                node_counts[20];
	uint32_t                seen_entries;
} *t_tree_validation_ctx_t;

__attribute__((noinline))
static void
t_validate_go_chunk(
	t_tree_validation_ctx_t ctx,
	vm_guard_object_chunk_t chunk,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	vm_map_address_t skip   = start;
	vm_map_address_t last   = start;
	size_t           idx    = 0;
	uint64_t         bitmap = bits_mask(chunk->vgoc_count);
	vm_map_size_t    step   = vmgo_chunk_size(chunk) / ARRAY_COUNT(chunk->vgoc_ptrs);
	vm_map_entry_t   vme;

	T_QUIET; T_ASSERT_EQ(vmgo_chunk_start(chunk), start,
	    "chunk(0x%016lx) check start", (uintptr_t)chunk);
	T_QUIET; T_ASSERT_EQ(vmgo_chunk_end(chunk), end,
	    "chunk(0x%016lx) check end", (uintptr_t)chunk);
	T_QUIET; T_ASSERT_TRUE(vms_is_entry(chunk->vgoc_ptrs[0]),
	    "chunk(0x%016lx) must have at least one entry", (uintptr_t)chunk);

	vme = vms_entry(chunk->vgoc_ptrs[0]);
	T_QUIET; T_ASSERT_EQ_PTR(vme, ctx->next_e,
	    "chunk(0x%016lx) expected entry", (uintptr_t)chunk);

	do {
		uint32_t sidx, eidx;

		while (vme != vm_map_to_entry(t_info.map) && skip < vme->vme_end) {
			T_QUIET; T_ASSERT_TRUE(vms_equal(chunk->vgoc_ptrs[idx],
			    vms_pointer(vme)),
			    "chunk(0x%016lx) check skiplist %zd", (uintptr_t)chunk, idx);
			idx++;
			skip += step;
		}
		T_QUIET; T_ASSERT_GE(vme->vme_start, start,
		    "chunk(0x%016lx) entry(0x%016lx) fits",
		    (uintptr_t)chunk, (uintptr_t)vme);
		T_QUIET; T_ASSERT_LE(vme->vme_end, end,
		    "chunk(0x%016lx) entry(0x%016lx) fits",
		    (uintptr_t)chunk, (uintptr_t)vme);

		sidx = vmgo_chunk_slot(chunk, vme->vme_start);
		eidx = vmgo_chunk_slot(chunk, vme->vme_end - 1) + 1;
		bitmap &= ~(bits_mask(eidx) - bits_mask(sidx));

		last = vme->vme_end;
		vme  = vme->vme_next;
		ctx->seen_entries++;
	} while (vme != vm_map_to_entry(t_info.map) && vme->vme_start < end);

	for (; idx < ARRAY_COUNT(chunk->vgoc_ptrs); idx++) {
		T_QUIET; T_ASSERT_TRUE(vms_is_null(chunk->vgoc_ptrs[idx]),
		    "chunk(0x%016lx) check skiplist %zd", (uintptr_t)chunk, idx);
	}

	T_QUIET; T_ASSERT_EQ(chunk->vgoc_bitmap, bitmap,
	    "chunk(0x%016lx) bitmap is correct", (uintptr_t)chunk);
	T_QUIET; T_ASSERT_EQ(vmgo_chunk_free_count(chunk),
	    __builtin_popcountll(chunk->vgoc_bitmap),
	    "chunk(0x%016lx) free count is correct", (uintptr_t)chunk);
	T_QUIET; T_ASSERT_LT(0 + chunk->vgoc_quarantined, vmgo_chunk_guards(chunk),
	    "chunk(0x%016lx) quarantine makes sense", (uintptr_t)chunk);

	ctx->next_e = vme;
}

__attribute__((noinline))
static void
t_validate_subtree(
	t_tree_validation_ctx_t ctx,
	vm_map_store_node_t     node,
	uint32_t                depth,
	vm_map_address_t        start,
	vm_map_address_t        end)
{
	T_QUIET; T_ASSERT_GT(ctx->node_counts[depth], 0,
	    "node(0x%016lx) is expected", (uintptr_t)node);
	ctx->node_counts[depth]--;

	T_QUIET; T_ASSERT_LE(node->vmsn_count,
	    vms_is_leaf(node) ? VMS_LEAF_FANOUT : VMS_NODE_FANOUT,
	    "node(0x%016lx) check count", (uintptr_t)node);
#if __arm64__ /* uses Neon */
	if (node->vmsn_count < (vms_is_leaf(node) ? VMS_LEAF_FANOUT : VMS_NODE_FANOUT)) {
		T_QUIET; T_ASSERT_EQ(*vms_keyp(node, node->vmsn_count), ~0ull,
		    "node(0x%016lx) check neon marker", (uintptr_t)node);
	}
#endif

	/* check keys */
	T_QUIET; T_ASSERT_EQ(vms_start(node), start,
	    "node(0x%016lx) check start", (uintptr_t)node);
	T_QUIET; T_ASSERT_EQ(vms_end(node), end,
	    "node(0x%016lx) check end", (uintptr_t)node);

	for (uint32_t i = 0; i < node->vmsn_count; i++) {
		T_QUIET; T_ASSERT_LT(vms_start(node, i), vms_end(node, i),
		    "node(0x%016lx) idx(%d) check start < end", (uintptr_t)node, i);
	}

	/* check values */
	for (uint32_t i = 0; i < node->vmsn_count; i++) {
		vm_map_address_t       start = vms_start(node, i);
		vm_map_address_t       end   = vms_end(node, i);
		vm_map_store_val_ptr_t val;

		if (!vms_is_leaf(node)) {
			vm_map_store_node_ptr_t ptr = *vms_nodep(node, i);

			t_validate_subtree(ctx, vms_node(ptr),
			    depth + 1, start, end);
			T_QUIET; T_ASSERT_EQ(*vms_holesp(node, i),
			    vms_holes(vms_node(ptr)),
			    "node(0x%016lx) idx(%d) check holes",
			    (uintptr_t)node, i);
			continue;
		}

		val = *vms_valp(node, i);
		if (vms_is_null(val)) {
			continue;
		}

		if (!t_info.map) {
			ctx->seen_entries++;
			continue;
		}

		if (vms_is_entry(val)) {
			vm_map_entry_t e = vms_entry(val);

			T_QUIET; T_ASSERT_EQ_PTR(e, ctx->next_e,
			    "node(0x%016lx) idx(%d) expected entry",
			    (uintptr_t)node, i);
			T_QUIET; T_ASSERT_EQ(e->vme_start, start,
			    "node(0x%016lx) idx(%d) check entry start",
			    (uintptr_t)node, i);
			T_QUIET; T_ASSERT_EQ(e->vme_end, end,
			    "node(0x%016lx) idx(%d) check entry end",
			    (uintptr_t)node, i);
			ctx->next_e = e->vme_next;
			ctx->seen_entries++;
		} else {
			t_validate_go_chunk(ctx, vms_chunk(val), start, end);
		}
	}
}

__attribute__((noinline))
static void
t_validate_root(void)
{
	struct t_tree_validation_ctx ctx = { };
	vm_map_store_node_t root = vms_node(t_root()->vmsr_root);
	vm_map_store_node_t node = root;
	uint32_t depth = 0;

	t_info.in_verification = true;
	if (t_info.map) {
		ctx.next_e = vm_map_first_entry(t_info.map);
	}

	while (!vms_is_leaf(node)) {
		ctx.node_counts[depth] = t_node_row_len(node);
		node = vms_node(*vms_nodep(node, 0));
		depth++;
	}
	ctx.node_counts[depth] = t_node_row_len(node);

	T_QUIET; T_ASSERT_EQ(t_root()->vmsr_depth, depth,
	    "check depth");

	t_validate_subtree(&ctx, root, 0, 0, ~0ull);

	for (uint32_t i = 0; i < ARRAY_COUNT(ctx.node_counts); i++) {
		T_QUIET; T_ASSERT_EQ(ctx.node_counts[0], 0,
		    "saw all nodes");
	}

	if (t_info.map) {
		T_QUIET; T_ASSERT_EQ(t_info.map->hdr.nentries, ctx.seen_entries,
		    "saw all entries");
	}

	t_verification++;
	t_info.in_verification = false;
}


#pragma mark vm map store root tests

T_DECL(vms_create, "creation/destruction")
{
	t_flat_nodes_t flat;

	t_setup_root(15, MiB(10));
	t_validate_root();
	flat = t_flatten();
	T_EXPECT_EQ(flat->len, 16, "created a 1-level store with 15 leaves");
	t_flatten_free(flat);
	t_dump();
	t_done();

	t_setup_root(150, MiB(10));
	t_validate_root();
	flat = t_flatten();
	T_EXPECT_EQ(flat->len, 151, "created a 2-level store with 150 leaves");
	t_flatten_free(flat);
	t_done();

	t_setup_root(1500, MiB(10));
	t_validate_root();
	flat = t_flatten();
	T_EXPECT_EQ(flat->len, 1501, "created a 3-level store with 1500 leaves");
	t_flatten_free(flat);
	t_done();
}

T_DECL(vms_node_split, "test the low level __vms_node_split() function")
{
	vm_map_store_node_t n1, n2;
	t_flat_nodes_t flat;
	vms_slot_t wslot;

	T_LOG("Test nodes splitting, inserting to the right");
	for (uint16_t idx = 0; idx < VMS_LEAF_FANOUT - 1; idx++) {
		t_setup_root(VMS_LEAF_FANOUT - 1, MiB(16));
		n1 = vms_node(t_root()->vmsr_root);
		n2 = __vms_node_split(n1, idx, true, false, &wslot);

		*vms_keyp(wslot) = MiB(16 * idx + 8);
		vms_valp(wslot)->vmsp_packed = 0x41ul;

		flat = t_flatten(n1);

		T_QUIET; T_ASSERT_EQ_PTR(n2, vms_next_sibling(n1),
		    "idx(%d) siblings are set right", idx);
		T_QUIET; T_ASSERT_NULL(vms_next_sibling(n2),
		    "idx(%d) siblings are set right", idx);
		T_QUIET; T_ASSERT_EQ(flat->len, VMS_LEAF_FANOUT + 1,
		    "idx(%d) should have 16 nodes", idx);

		for (uint16_t i = 0; i <= VMS_LEAF_FANOUT; i++) {
			if (i <= idx) {
				T_QUIET; T_ASSERT_EQ(flat->keys[i],
				    0ull + MiB(16 * i),
				    "idx(%d) i(%d) key is correct", idx, i);
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    (i + 1) * 4,
				    "idx(%d) i(%d) val is correct", idx, i);
			} else if (i == idx + 1) {
				T_QUIET; T_ASSERT_EQ(flat->keys[i],
				    0ull + MiB(16 * i - 8),
				    "idx(%d) i(%d) key is correct", idx, i);
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    0x41,
				    "idx(%d) i(%d) val is correct", idx, i);
			} else {
				T_QUIET; T_ASSERT_EQ(flat->keys[i],
				    0ull + MiB(16 * i - 16),
				    "idx(%d) i(%d) key is correct", idx, i);
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    i < VMS_LEAF_FANOUT ? i * 4 : 0,
				    "idx(%d) i(%d) val is correct", idx, i);
			}
		}

		t_flatten_free(flat);
		t_done();

		T_PASS("__vms_node_split(len=%d, %d, true, false)",
		    VMS_LEAF_FANOUT, idx);
	}

	T_LOG("Test nodes splitting, inserting to the left");
	for (uint16_t idx = 0; idx < VMS_LEAF_FANOUT - 1; idx++) {
		t_setup_root(VMS_LEAF_FANOUT - 1, MiB(16));
		n1 = vms_node(t_root()->vmsr_root);
		n2 = __vms_node_split(n1, idx, false, true, &wslot);

		*vms_keyp(wslot) = MiB(16 * idx);
		vms_valp(wslot)->vmsp_packed = 0x41ul;
		*vms_keyp(vms_slot_next(wslot)) = MiB(16 * idx + 8);

		flat = t_flatten(n1);

		T_QUIET; T_ASSERT_EQ_PTR(n2, vms_next_sibling(n1),
		    "idx(%d) siblings are set right", idx);
		T_QUIET; T_ASSERT_NULL(vms_next_sibling(n2),
		    "idx(%d) siblings are set right", idx);
		T_QUIET; T_ASSERT_EQ(flat->len, VMS_LEAF_FANOUT + 1,
		    "idx(%d) should have %d nodes", idx, VMS_LEAF_FANOUT + 1);

		for (uint16_t i = 0; i <= VMS_LEAF_FANOUT; i++) {
			if (i <= idx) {
				T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i),
				    "idx(%d) i(%d) key is correct", idx, i);
			} else if (i == idx + 1) {
				T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i - 8),
				    "idx(%d) i(%d) key is correct", idx, i);
			} else {
				T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i - 16),
				    "idx(%d) i(%d) key is correct", idx, i);
			}

			if (i < idx) {
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    (i + 1) * 4,
				    "idx(%d) i(%d) val is correct", idx, i);
			} else if (i == idx) {
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    0x41,
				    "idx(%d) i(%d) val is correct", idx, i);
			} else {
				T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
				    i < VMS_LEAF_FANOUT ? i * 4 : 0,
				    "idx(%d) i(%d) val is correct", idx, i);
			}
		}

		t_flatten_free(flat);
		t_done();

		T_PASS("__vms_node_split(len=%d, %d, true, false)",
		    VMS_LEAF_FANOUT, idx);
	}

	T_LOG("Test nodes splitting, inserting to the middle");
	for (uint16_t len = VMS_LEAF_FANOUT - 2; len < VMS_LEAF_FANOUT; len++) {
		for (uint16_t idx = 0; idx < len; idx++) {
			t_setup_root(len, MiB(16));
			n1 = vms_node(t_root()->vmsr_root);
			n2 = __vms_node_split(n1, idx, true, true, &wslot);

			*vms_keyp(wslot) = MiB(16 * idx + 4);
			vms_valp(wslot)->vmsp_packed = 0x41ul;
			*vms_keyp(vms_slot_next(wslot)) = MiB(16 * idx + 12);

			flat = t_flatten(n1);

			T_QUIET; T_ASSERT_EQ_PTR(n2, vms_next_sibling(n1),
			    "idx(%d) siblings are set right", idx);
			T_QUIET; T_ASSERT_NULL(vms_next_sibling(n2),
			    "idx(%d) siblings are set right", idx);
			T_QUIET; T_ASSERT_EQ(flat->len, len + 3,
			    "idx(%d) should have %d nodes", idx, len + 3);

			for (uint16_t i = 0; i < len + 3; i++) {
				if (i <= idx) {
					T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i),
					    "idx(%d) i(%d) key is correct", idx, i);
				} else if (i == idx + 1) {
					T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i - 12),
					    "idx(%d) i(%d) key is correct", idx, i);
				} else if (i == idx + 2) {
					T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i - 20),
					    "idx(%d) i(%d) key is correct", idx, i);
				} else {
					T_QUIET; T_ASSERT_EQ(flat->keys[i], 0ull + MiB(16 * i - 32),
					    "idx(%d) i(%d) key is correct", idx, i);
				}

				if (i <= idx) {
					T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
					    (i + 1) * 4,
					    "idx(%d) i(%d) val is correct", idx, i);
				} else if (i == idx + 1) {
					T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
					    0x41,
					    "idx(%d) i(%d) val is correct", idx, i);
				} else if (i == idx + 2) {
					T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
					    (idx + 1) * 4,
					    "idx(%d) i(%d) val is correct", idx, i);
				} else {
					T_QUIET; T_ASSERT_EQ(0u + flat->vals[i].vmsp_packed,
					    i < len + 2 ? (i - 1) * 4 : 0,
					    "idx(%d) i(%d) val is correct", idx, i);
				}
			}

			t_flatten_free(flat);
			t_done();

			T_PASS("__vms_node_split(len=%d, %d, true, true)",
			    len, idx);
		}
	}
}

static void
t_vms_root_clip_end(vm_map_address_t start, vm_map_store_val_ptr_t ptr)
{
	/* replicate the logic of vm_map_store_insert */
	VMS_PATH_DECLARE(path, *t_root());
	vms_slot_t slot;

	slot = vms_path_resolve(path, start);
	__vms_mut_split(t_root(), path, start, ptr);
}

T_DECL(vms_mut_split, "test the low level __vms_mut_split() function")
{
	t_flat_nodes_t flat;

	t_setup_root(400, MiB(2));

	for (uint32_t idx = 0; idx < 400; idx++) {
		t_vms_root_clip_end(idx * MiB(2) + MiB(1),
		    (vm_map_store_val_ptr_t){ .vmsp_packed = 0x1000 + idx + 1 });
		t_validate_root();
	}

	T_PASS("Could split right 200 times");

	t_done();
}

static void
t_vms_root_insert(
	vm_map_address_t        start,
	vm_map_address_t        end,
	vm_map_store_val_ptr_t  ptr)
{
	/* replicate the logic of vm_map_store_insert */
	VMS_PATH_DECLARE(path, *t_root());
	vms_slot_t slot;

	slot = vms_path_resolve(path, start);
	vms_slot_assert_hole(slot);
	vms_slot_assert_contains(slot, end - 1);

	__vms_mut_insert(t_root(), path, start, end, ptr);
}

T_DECL(vms_insert, "test the low level __vms_mut_insert() function")
{
	vm_map_address_t start = GiB(1);

	t_setup_root(0, 0);
	t_validate_root();

	for (uint32_t i = 0; i < 100; i++) {
		t_vms_root_insert(start + MiB(8 * i + 0),
		    start + MiB(8 * i + 1),
		    t_generate_entry());
		t_validate_root();
	}
	T_PASS("Created 100 entries of 1M every 8M with phase 0");

	for (uint32_t i = 0; i < 100; i++) {
		t_vms_root_insert(start + MiB(8 * i + 1),
		    start + MiB(8 * i + 2),
		    t_generate_entry());
		t_validate_root();
	}
	T_PASS("Created 100 entries of 1M every 8M with phase 1M");

	for (uint32_t i = 0; i < 100; i++) {
		t_vms_root_insert(start + MiB(8 * i + 4),
		    start + MiB(8 * i + 5),
		    t_generate_entry());
		t_validate_root();
	}
	T_PASS("Created 100 entries of 1M every 8M with phase 4M");

	for (uint32_t i = 0; i < 100; i++) {
		t_vms_root_insert(start + MiB(8 * i + 7),
		    start + MiB(8 * i + 8),
		    t_generate_entry());
		t_validate_root();
	}
	T_PASS("Created 100 entries of 1M every 8M with phase 7M");

	t_done();
}

static void
t_vms_root_fold(uint32_t n, vm_map_store_val_ptr_t ptr, uint32_t count)
{
	VMS_PATH_DECLARE(path, *t_root());
	vms_slot_t slot = t_find_leaf(n);

	vms_path_resolve(path, vms_start(slot));
	*vms_valp(path->vmsp_cur) = ptr;
	__vms_mut_fold(t_root(), path, count, true);
}

T_DECL(vms_fold, "test the low level __vms_mut_fold() function")
{
	const uint32_t leaves = 2 * VMS_NODE_FANOUT * VMS_LEAF_FANOUT + 4;

	for (uint16_t i = 0; i < leaves - 1; i++) {
		uint32_t idx = i % VMS_LEAF_FANOUT;

		for (uint32_t n = 1; idx + 1 + n <= VMS_LEAF_FANOUT; idx++) {
			t_setup_root(leaves, MiB(1), ^(t_setup_root_ctx_t ctx){
				return (ctx->hole * ctx->hole + 1ull) * PAGE_SIZE;
			});

			t_vms_root_fold(i, t_generate_entry(), n);
			t_validate_root();
			t_done();
		}
	}

	T_PASS("Tested many fold combinations");
}

T_DECL(vms_erase, "test the low level __vms_mut_erase() function")
{
	const uint32_t leaves  = 2 * VMS_NODE_FANOUT * VMS_NODE_FANOUT + 4;
	const uint32_t lastrun = leaves - 3 * VMS_NODE_FANOUT;

	for (uint16_t i = 0; i < leaves; i++) {
		/* pattern is H E E E H E E E H ... */

		if (i % 4 == 1) {
			/* can't erase starting on an E following H */
			continue;
		}

		for (uint16_t j = MAX(i + 1, lastrun); j <= leaves; j++) {
			/* can't erase starting on an E followed by H */
			if (j % 4 == 3) {
				continue;
			}

			t_setup_root(leaves, MiB(1), ^(t_setup_root_ctx_t ctx){
				if (4 * ctx->hole > ctx->node) {
				        return 0ull;
				}
				return (ctx->hole * ctx->hole + 1ull) * PAGE_SIZE;
			});

			__vms_mut_erase(t_root(),
			    vms_start(t_find_leaf(i)),
			    vms_end(t_find_leaf(j)));

			t_validate_root();

			t_done();
		}
	}

	T_PASS("Tested many erase combinations");
}

#pragma mark VM map tests

T_DECL(map_create, "creation/destruction")
{
	vm_map_t       map   = t_setup_map();
	vm_map_entry_t entry = VM_MAP_ENTRY_NULL;

	vm_map_ilk_lock(map);

	T_EXPECT_NOTNULL(map, "created an empty map");

	T_EXPECT_FALSE(vm_map_lookup_or_next(map, 0, &entry), "no entry exists");
	T_EXPECT_EQ_PTR(entry, vm_map_to_entry(map), "returned entry is the map");

	T_EXPECT_EQ(vm_map_store_lookup_hole(map, VM_MAP_DEFAULT_MIN, VM_MAP_DEFAULT_MAX),
	    VM_MAP_DEFAULT_MAX - VM_MAP_DEFAULT_MIN,
	    "the map should have a single big hole");

	vm_map_ilk_unlock(map);

	t_done();
}

T_DECL(map_insert, "insertions")
{
	vm_map_t         map   = t_setup_map();
	vm_map_address_t start = GiB(1);

	vm_map_ilk_lock(map);

	t_validate_root();

	T_LOG("Create 100 entries of 1M every 8M with phase 0");
	for (uint32_t i = 0; i < 100; i++) {
		t_add_entry(map, start + MiB(8 * i + 0), MiB(1), NULL);
		t_validate_root();
	}

	T_LOG("Create 100 entries of 1M every 8M with phase 1M");
	for (uint32_t i = 0; i < 100; i++) {
		t_add_entry(map, start + MiB(8 * i + 1), MiB(1), NULL);
		t_validate_root();
	}

	T_LOG("Create 100 entries of 1M every 8M with phase 4M");
	for (uint32_t i = 0; i < 100; i++) {
		t_add_entry(map, start + MiB(8 * i + 4), MiB(1), NULL);
		t_validate_root();
	}

	T_LOG("Create 100 entries of 1M every 8M with phase 7M");
	for (uint32_t i = 0; i < 100; i++) {
		t_add_entry(map, start + MiB(8 * i + 7), MiB(1), NULL);
		t_validate_root();
	}

	start += GiB(1);

	vm_map_ilk_unlock(map);

	t_done();
}

static void
t_do_lookups(vm_map_t map)
{
	vm_map_address_t last_end = 0;

	for (vm_map_entry_t e = vm_map_first_entry(map);
	    e != vm_map_to_entry(map);
	    e = e->vme_next) {
		vm_map_address_t e_start = e->vme_start;
		vm_map_address_t e_end   = e->vme_end;
		vm_map_address_t start_minus_30k = e_start - KiB(30);

		if (last_end + KiB(30) <= e_start) {
			T_QUIET; T_ASSERT_EQ(0ull + KiB(30),
			    vm_map_store_lookup_hole(map, start_minus_30k, vm_map_max(map)),
			    "check some hole before entry %p", e);
			T_QUIET; T_ASSERT_EQ_PTR(VM_MAP_ENTRY_NULL,
			    vm_map_store_lookup_entry(map, start_minus_30k, false),
			    "can't find an entry in hole %p", e);
			T_QUIET; T_ASSERT_EQ_PTR(e,
			    vm_map_store_lookup_entry(map, start_minus_30k, true),
			    "or-next finds entry %p", e);
		}

		T_QUIET; T_ASSERT_EQ_PTR(e,
		    vm_map_store_lookup_entry(map, e_start, false),
		    "entry %p found by its start", e);
		T_QUIET; T_ASSERT_EQ_PTR(e,
		    vm_map_store_lookup_entry(map, e_start, true),
		    "entry %p found by its start (or-next)", e);
		T_QUIET; T_ASSERT_EQ_PTR(e,
		    vm_map_store_lookup_entry(map, e_end - 1, false),
		    "entry %p found by its last byte", e);
		T_QUIET; T_ASSERT_EQ_PTR(e,
		    vm_map_store_lookup_entry(map, e_end - 1, true),
		    "entry %p found by its last byte (or-next)", e);
		T_QUIET; T_ASSERT_NE_PTR(e,
		    vm_map_store_lookup_entry(map, e_end, false),
		    "entry %p not found by its end bound", e);
		T_QUIET; T_ASSERT_EQ_PTR(e->vme_next,
		    vm_map_store_lookup_entry(map, e_end, true),
		    "entry %p found by %p's end bound (or-next)",
		    e->vme_next, e);

		last_end = e_end;
	}
	T_PASS("verified all lookups");
};

T_DECL(map_lookup, "lookups")
{
	vm_map_t         map   = t_setup_map();
	vm_map_address_t start = GiB(1);

	vm_map_ilk_lock(map);

	t_validate_root();

	for (uint32_t i = 0; i < 10; i++) {
		t_add_entry(map, start, ptoa(3ul << i), &start);
		t_validate_root();
	}

	t_do_lookups(map);

	while (map->root.vmsr_depth < 2) {
		for (uint32_t i = 0; i < 10; i++) {
			t_add_entry(map, start, MiB(1), &start);
			t_validate_root();
		}

		for (uint32_t i = 0; i < 20; i++) {
			start += MiB(1);
			t_add_entry(map, start, MiB(1), &start);
			t_validate_root();
		}

		t_do_lookups(map);
	}

	vm_map_ilk_unlock(map);

	t_done();
}

T_DECL(map_find_space, "finding space")
{
	vm_map_t map = t_setup_map();
	vm_map_address_t start = -(1ull << 60);
	vm_map_address_t end   = -TiB(1);
	vm_map_address_t cur   = start;
	vm_map_address_t mid;

	vm_map_ilk_lock(map);

	t_add_entry(map, cur, TiB(1), &cur);

	for (uint32_t hole = PAGE_SHIFT; hole < PAGE_SHIFT + 5; hole++) {
		cur += (1ull << hole);
		t_add_entry(map, cur, GiB(1), &cur);
	}

	for (uint32_t hole = PAGE_SHIFT; hole < PAGE_SHIFT + 5; hole++) {
		struct mach_vm_range range = {
			.min_address = start,
			.max_address = vm_map_max(map),
		};
		vm_map_store_rsv_t rsv;
		kern_return_t      kr;
		vm_map_entry_t     e;

		kr = vm_map_store_find_space(map, range,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_last_free = false),
		    1ull << hole, 0, &rsv);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "find space 0x%llx", 1ull << hole);
		e  = vmsr_entry(rsv);
		T_QUIET; T_ASSERT_EQ(e->vme_start - e->vme_prev->vme_end,
		    1ull << hole, "perfect hole at 0x%llx", vmsr_start(rsv));
	}
	T_PASS("Found all the right holes forwards (single leaf)");

	for (uint32_t hole = PAGE_SHIFT + 5; hole < 50; hole++) {
		cur += (1ull << hole);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
	}
	mid = cur;
	for (uint32_t hole = 50; hole-- > PAGE_SHIFT;) {
		cur += (1ull << hole);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
		t_add_entry(map, cur, MiB(256), &cur);
	}

	for (uint32_t hole = PAGE_SHIFT; hole < 50; hole++) {
		struct mach_vm_range range = {
			.min_address = start,
			.max_address = vm_map_max(map),
		};
		vm_map_store_rsv_t rsv;
		kern_return_t      kr;
		vm_map_entry_t     e;

		kr = vm_map_store_find_space(map, range,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_last_free = false),
		    1ull << hole, 0, &rsv);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "find space 0x%llx", 1ull << hole);
		e  = vmsr_entry(rsv);
		T_QUIET; T_ASSERT_EQ(e->vme_start - e->vme_prev->vme_end,
		    1ull << hole, "perfect hole at 0x%llx", vmsr_start(rsv));
		T_QUIET; T_ASSERT_LT(vmsr_start(rsv), mid, "before split");
	}
	T_PASS("Found all the right holes forwards");

	for (uint32_t hole = PAGE_SHIFT; hole < 50; hole++) {
		struct mach_vm_range range = {
			.min_address = start,
			.max_address = cur,
		};
		vm_map_store_rsv_t rsv;
		kern_return_t      kr;
		vm_map_entry_t     e;

		kr = vm_map_store_find_space(map, range,
		    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmkf_last_free = true),
		    1ull << hole, 0, &rsv);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr,
		    "find space 0x%llx", 1ull << hole);
		e  = vmsr_entry(rsv);
		T_QUIET; T_ASSERT_EQ(e->vme_start - e->vme_prev->vme_end,
		    1ull << hole, "perfect hole at 0x%llx", vmsr_start(rsv));
		T_QUIET; T_ASSERT_GE(vmsr_start(rsv), mid, "before split");
	}
	T_PASS("Found all the right holes backwards");

	vm_map_ilk_unlock(map);

	t_done();
}


#pragma mark VM guard object tests

T_DECL(go_create, "creation/destruction")
{
	vm_map_t             map   = t_setup_map();
	vm_map_entry_t       entry = VM_MAP_ENTRY_NULL;
	struct mach_vm_range range = { vm_map_min(map), vm_map_max(map) };
	vm_map_store_rsv_t   rsv;
	kern_return_t        kr;

	vm_map_ilk_lock(map);

	T_EXPECT_NOTNULL(map, "created an empty map");

	T_EXPECT_FALSE(vm_map_lookup_or_next(map, 0, &entry), "no entry exists");
	T_EXPECT_EQ_PTR(entry, vm_map_to_entry(map), "returned entry is the map");

	kr = vm_guard_object_find_space_anywhere(map, t_slab(), range,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(), MiB(1), 0, &rsv);
	T_ASSERT_MACH_SUCCESS(kr, "vmgo_find_space");
	T_ASSERT_NE_PTR(vmsr_chunk(rsv), NULL, "Found a chunk");
	t_add_entry(map, vmsr_start(rsv), MiB(1), NULL);

	kr = vm_guard_object_find_space_anywhere(map, t_slab(), range,
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(), MiB(1), 0, &rsv);
	T_ASSERT_MACH_SUCCESS(kr, "vmgo_find_space");
	T_ASSERT_NE_PTR(vmsr_chunk(rsv), NULL, "Found a chunk");
	t_add_entry(map, vmsr_start(rsv) + 0 * KiB(128), KiB(128), NULL);
	t_add_entry(map, vmsr_start(rsv) + 1 * KiB(128), KiB(128), NULL);
	t_add_entry(map, vmsr_start(rsv) + 2 * KiB(128), KiB(128), NULL);
	t_add_entry(map, vmsr_start(rsv) + 3 * KiB(128), KiB(128), NULL);

	t_dump();
	t_validate_root();

	vm_map_ilk_unlock(map);

	t_done();
}

static void
t_lock_entry(vm_map_entry_t e)
{
	kern_return_t kr;

	kr = vm_entry_lock_exclusive(t_info.map, LCK_RW_TYPE_EXCLUSIVE,
	    e, e->vme_start, THREAD_UNINT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "locking the entry should work");
}

static void
t_unlock_entry(vm_map_entry_t e)
{
	vm_entry_unlock_exclusive(t_info.map, e);
}

static void
t_remove_entry(vm_map_t map, vm_map_address_t addr)
{
	vm_map_entry_t e = vm_map_lookup(map, addr);

	T_QUIET; T_ASSERT_NE_PTR(e, VM_MAP_ENTRY_NULL, "entry exists");
	T_QUIET; T_ASSERT_EQ(e->vme_start, addr, "entry start is correct");

	t_lock_entry(e);
	vm_map_store_remove(map, e,
	    VMS_REMOVE_FREE_ENTRY | VMS_REMOVE_FREE_SLOTS);
	t_validate_root();
}

T_DECL(go_slots, "check slot management")
{
	vm_map_t                map       = t_setup_map();
	struct mach_vm_range    range     = { vm_map_min(map), vm_map_max(map) };
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	uint32_t                idx;
	vm_map_entry_t          e1, e2, e3;
	vm_guard_object_chunk_t chunk;
	vm_map_address_t        start;

	vm_map_ilk_lock(map);

	chunk = vmgo_chunk_alloc_anywhere(map, t_slab(), range, vmk_flags,
	    vmgo_size_to_granule(MiB(1)), 0);
	T_ASSERT_NE_PTR(chunk, NULL, "could allocate a chunk");
	T_ASSERT_EQ(chunk->vgoc_count, 8, "Check test assumptions");

	T_LOG("check that various entry splits can be manipulated and freed");

	/* left, hole, right */
	start = vmgo_chunk_reserve_slot(chunk, 0);
	e1 = t_add_entry(map, start + 0 * KiB(128), KiB(128), NULL);
	e2 = t_add_entry(map, start + 7 * KiB(128), KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e3 = vm_map_store_clip_start(map, e1, e1->vme_start + KiB(64));
	t_unlock_entry(e1);
	t_unlock_entry(e3);
	t_validate_root();

	t_lock_entry(e2);
	e3 = vm_map_store_clip_start(map, e2, e2->vme_start + KiB(64));
	t_unlock_entry(e2);
	t_unlock_entry(e3);
	t_validate_root();

	/* hole, middle, hole */
	start = vmgo_chunk_reserve_slot(chunk, 1);
	e1 = t_add_entry(map, start + 1 * KiB(128), 6 * KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e2 = vm_map_store_clip_start(map, e1, e1->vme_start + 3 * KiB(128));
	t_unlock_entry(e1);
	t_unlock_entry(e2);
	t_validate_root();

	/* full */
	start = vmgo_chunk_reserve_slot(chunk, 3);
	e1 = t_add_entry(map, start + 0 * KiB(128), 8 * KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e2 = vm_map_store_clip_start(map, e1, e1->vme_start + 3 * KiB(128));
	t_unlock_entry(e1);
	t_unlock_entry(e2);
	t_validate_root();

	/* hole, left, hole, right, hole */
	start = vmgo_chunk_reserve_slot(chunk, 4);
	e1 = t_add_entry(map, start + 1 * KiB(128), KiB(128), NULL);
	e2 = t_add_entry(map, start + 6 * KiB(128), KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e3 = vm_map_store_clip_start(map, e1, e1->vme_start + KiB(64));
	t_unlock_entry(e1);
	t_unlock_entry(e3);
	t_validate_root();

	t_lock_entry(e2);
	e3 = vm_map_store_clip_start(map, e2, e2->vme_start + KiB(64));
	t_unlock_entry(e2);
	t_unlock_entry(e3);
	t_validate_root();

	/* left, hole */
	start = vmgo_chunk_reserve_slot(chunk, 6);
	e1 = t_add_entry(map, start + 0 * KiB(128), 6 * KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e2 = vm_map_store_clip_start(map, e1, e1->vme_start + 3 * KiB(128));
	t_unlock_entry(e1);
	t_unlock_entry(e2);
	t_validate_root();


	/* hole, right */
	start = vmgo_chunk_reserve_slot(chunk, 7);
	e1 = t_add_entry(map, start + 2 * KiB(128), 6 * KiB(128), NULL);
	t_validate_root();

	t_lock_entry(e1);
	e2 = vm_map_store_clip_start(map, e1, e1->vme_start + 3 * KiB(128));
	t_unlock_entry(e1);
	t_unlock_entry(e2);
	t_validate_root();

	t_dump();

	T_ASSERT_EQ(chunk->vgoc_available, 0, "6 slots should be used");

	T_LOG("Now deallocate everything and check that the chunk disappears");

	idx   = 0;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	t_remove_entry(map, start + 1 * KiB(64));
	T_QUIET; T_ASSERT_FALSE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is still in use", idx);
	t_remove_entry(map, start + 0 * KiB(64));
	T_QUIET; T_ASSERT_FALSE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is still in use", idx);
	t_remove_entry(map, start + 15 * KiB(64));
	T_QUIET; T_ASSERT_FALSE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is still in use", idx);
	t_remove_entry(map, start + 14 * KiB(64));
	T_QUIET; T_ASSERT_EQ(0 + chunk->vgoc_quarantined, 1, "quarantine increased");
	T_QUIET; T_ASSERT_EQ(chunk->vgoc_available, 0, "quarantine increased");
	T_ASSERT_TRUE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is freed", idx);

	idx   = 1;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	t_remove_entry(map, start + 1 * KiB(128));
	T_QUIET; T_ASSERT_FALSE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is still in use", idx);
	t_remove_entry(map, start + 4 * KiB(128));
	T_QUIET; T_ASSERT_EQ(0 + chunk->vgoc_quarantined, 0, "quarantine cleared");
	T_QUIET; T_ASSERT_EQ(chunk->vgoc_available, 2, "quarantine cleared");
	T_ASSERT_TRUE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is freed", idx);

	idx   = 7;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	t_remove_entry(map, start + 2 * KiB(128));
	T_QUIET; T_ASSERT_FALSE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is still in use", idx);
	t_remove_entry(map, start + 5 * KiB(128));
	T_QUIET; T_ASSERT_EQ(chunk->vgoc_available, 3, "availability increased");
	T_ASSERT_TRUE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is freed", idx);

	idx   = 4;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	e1    = vm_map_lookup(map, start + 3 * KiB(64));
	t_lock_entry(e1);
	vm_map_store_extend_right(map, e1, start + 6 * KiB(128));
	t_unlock_entry(e1);
	t_validate_root();
	t_remove_entry(map, start + 2 * KiB(64));
	t_remove_entry(map, start + 3 * KiB(64));
	t_remove_entry(map, start + 12 * KiB(64));
	t_remove_entry(map, start + 13 * KiB(64));
	T_QUIET; T_ASSERT_EQ(chunk->vgoc_available, 4, "availability increased");
	T_ASSERT_TRUE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is freed", idx);

	idx   = 6;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	t_remove_entry(map, start + 0 * KiB(128));
	t_remove_entry(map, start + 3 * KiB(128));
	T_QUIET; T_ASSERT_EQ(chunk->vgoc_available, 5, "availability increased");
	T_ASSERT_TRUE(bit_test(chunk->vgoc_bitmap, idx),
	    "slot %d is freed", idx);

	idx   = 3;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);
	t_remove_entry(map, start + 0 * KiB(128));
	t_remove_entry(map, start + 3 * KiB(128));

	T_ASSERT_EQ(map->hdr.nentries, 0, "all entries are gone");
	T_ASSERT_NE(vm_map_store_lookup_hole(map, start, vm_map_max(map)), 0ull,
	    "the chunk should have been freed");

	vm_map_ilk_unlock(map);

	t_done();
}

T_DECL(go_slot_bounds, "check slot bound crossing")
{
	vm_map_t                map       = t_setup_map();
	struct mach_vm_range    range     = { vm_map_min(map), vm_map_max(map) };
	vm_map_kernel_flags_t   vmk_flags = VM_MAP_KERNEL_FLAGS_ANYWHERE();
	uint32_t                idx;
	vm_map_entry_t          e1, e2, e3;
	vm_guard_object_chunk_t chunk;
	vm_map_address_t        start;
	kern_return_t           kr;

	vm_map_ilk_lock(map);

	chunk = vmgo_chunk_alloc_anywhere(map, t_slab(), range, vmk_flags,
	    vmgo_size_to_granule(MiB(1)), 0);
	T_ASSERT_NE_PTR(chunk, NULL, "could allocate a chunk");
	T_ASSERT_EQ(chunk->vgoc_count, 8, "Check test assumptions");

	start = vmgo_chunk_reserve_slot(chunk, 0);
	t_add_entry(map, start, MiB(1), NULL);

	start = vmgo_chunk_reserve_slot(chunk, 1);
	t_add_entry(map, start, MiB(1), NULL);

	/* create a cross-slot coalesced entry */
	start = vmgo_chunk_reserve_slot(chunk, 4);
	start = vmgo_chunk_reserve_slot(chunk, 3);
	t_add_entry(map, start, MiB(2), NULL);

	vm_map_ilk_unlock(map);

	t_dump();

	idx   = 0;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);

	kr = vm_protect(map, start, KiB(256), FALSE, VM_PROT_READ);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");
	kr = vm_protect(map, start, MiB(1), FALSE, VM_PROT_DEFAULT);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");

	kr = vm_protect(map, start, MiB(1) + KiB(128), false, VM_PROT_READ);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "vm_protect outside of a slot fails");


	idx   = 3;
	start = vmgo_chunk_start(chunk) + idx * MiB(1);

	kr = vm_protect(map, start + 7 * KiB(128), MiB(1), false, VM_PROT_READ);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "vm_protect outside of a slot fails");

	kr = vm_protect(map, start + 2 * KiB(128), MiB(1), false, VM_PROT_READ);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "vm_protect outside of a slot fails");

	kr = vm_protect(map, start, KiB(256), FALSE, VM_PROT_READ);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");
	kr = vm_protect(map, start, MiB(1), FALSE, VM_PROT_WRITE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");

	kr = vm_protect(map, start + MiB(1), KiB(256), FALSE, VM_PROT_READ);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");
	kr = vm_protect(map, start + MiB(1), MiB(1), FALSE, VM_PROT_WRITE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_protect within a slot works");

	kr = vm_protect(map, start, MiB(1) + KiB(128), false, VM_PROT_READ);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_GUARD_OBJECT_SLOT,
	    "vm_protect outside of a slot fails");

	t_done();
}

T_DECL(go_vm_region, "check that vm_region fake entries work")
{
	vm_map_t         map = t_setup_map();
	vm_map_address_t base, addr;
	vm_map_address_t slot1, slot2;
	kern_return_t    kr;

	/*
	 * base allocation
	 */

	base = 0;
	kr = mach_vm_allocate_kernel(map, &base, MiB(1),
	    VM_MAP_KERNEL_FLAGS_ANYWHERE(.vmf_guard_object_optout = true));
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "allocate 1");

	/*
	 * regular guard object chunks
	 */

	kr = mach_vm_allocate_kernel(map, &slot1, MiB(8),
	    VM_MAP_KERNEL_FLAGS_ANYWHERE());
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "allocate 8M");

	kr = mach_vm_allocate_kernel(map, &slot2, MiB(8),
	    VM_MAP_KERNEL_FLAGS_ANYWHERE());
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "allocate 8M");

	if (slot1 > slot2) {
		addr = slot1;
		slot1 = slot2;
		slot2 = addr;
	}

	kr = vm_map_remove_guard(map, slot1, slot1 + MiB(1),
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "poke hole at [0x%016llx, 0x%016llx)",
	    slot1 + MiB(0), slot1 + MiB(1));

	kr = vm_map_remove_guard(map, slot1 + MiB(2), slot1 + MiB(3),
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "poke hole at [0x%016llx, 0x%016llx)",
	    slot1 + MiB(2), slot1 + MiB(3));

	kr = vm_map_protect(map, slot1 + MiB(4), slot1 + MiB(5),
	    false, VM_PROT_READ);
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "mprotect [0x%016llx, 0x%016llx)",
	    slot1 + MiB(4), slot1 + MiB(5));

	kr = vm_map_remove_guard(map, slot1 + MiB(7), slot1 + MiB(8),
	    VM_MAP_REMOVE_NO_FLAGS, KMEM_GUARD_NONE);
	t_validate_root();
	T_ASSERT_MACH_SUCCESS(kr, "poke hole at [0x%016llx, 0x%016llx)",
	    slot1 + MiB(7), slot1 + MiB(8));

	__auto_type check_entry = ^void (
		vm_map_address_t        where,
		vm_map_address_t        start,
		vm_map_address_t        end,
		vm_prot_t               prot)
	{
		mach_msg_type_number_t      count = VM_REGION_BASIC_INFO;
		struct vm_region_basic_info info;
		vm_map_address_t            addr = where;
		vm_map_size_t               size;
		kern_return_t               ret;

		ret = vm_map_region(map, &addr, &size, VM_REGION_BASIC_INFO,
		    (vm_region_info_t)&info, &count, NULL);
		T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "vm_map_region(0x%016llx)", where);
		T_QUIET; T_ASSERT_EQ(start, addr,
		    "entry start [0x%016llx, 0x%016llx) == [0x%016llx, 0x%016llx)",
		    start, end, addr, addr + size);
		T_QUIET; T_ASSERT_EQ(end, addr + size,
		    "entry end [0x%016llx, 0x%016llx) == [0x%016llx, 0x%016llx)",
		    start, end, addr, addr + size);
		T_QUIET; T_ASSERT_EQ(info.protection, prot, "entry protections");
		T_PASS("checked 0x%016llx -> [0x%016llx, 0x%016llx) %c%c%c/%c%c%c",
		    where, start, end,
		    (prot & VM_PROT_READ) ? 'r' : '-',
		    (prot & VM_PROT_WRITE) ? 'w' : '-',
		    (prot & VM_PROT_EXECUTE) ? 'x' : '-',
		    (info.max_protection & VM_PROT_READ) ? 'r' : '-',
		    (info.max_protection & VM_PROT_WRITE) ? 'w' : '-',
		    (info.max_protection & VM_PROT_EXECUTE) ? 'x' : '-');
	};

#define foreach(it, ...) \
	for (vm_map_address_t __i = 0, it; \
	    (it = ((vm_map_address_t[]){ __VA_ARGS__, 0 })[__i]); \
	    __i++)

	T_LOG("Checking the first allocation");

	foreach(where, 1, base - 1, base, base + 1, base + MiB(1) - 1) {
		check_entry(where, base, base + MiB(1), VM_PROT_DEFAULT);
	}

	T_LOG("Checking the second VM chunk");

	addr = base + MiB(1);

	foreach(where,
	    addr, addr < slot1 ? slot1 - 1 : slot1,
	    slot1, slot1 + MiB(1) - 1) {
		check_entry(where, addr, slot1 + MiB(1),
		    VM_PROT_NONE);
	}

	foreach(where, slot1 + MiB(1), slot1 + MiB(2) - 1) {
		check_entry(where, slot1 + MiB(1), slot1 + MiB(2),
		    VM_PROT_DEFAULT);
	}

	foreach(where, slot1 + MiB(2), slot1 + MiB(3) - 1) {
		check_entry(where, slot1 + MiB(2), slot1 + MiB(3),
		    VM_PROT_NONE);
	}

	foreach(where, slot1 + MiB(3), slot1 + MiB(4) - 1) {
		check_entry(where, slot1 + MiB(3), slot1 + MiB(4),
		    VM_PROT_DEFAULT);
	}

	foreach(where, slot1 + MiB(4), slot1 + MiB(5) - 1) {
		check_entry(where, slot1 + MiB(4), slot1 + MiB(5),
		    VM_PROT_READ);
	}

	foreach(where, slot1 + MiB(5), slot1 + MiB(7) - 1) {
		check_entry(where, slot1 + MiB(5), slot1 + MiB(7),
		    VM_PROT_DEFAULT);
	}

	foreach(where, slot1 + MiB(7), slot1 + MiB(8) - 1, slot2 - 1) {
		check_entry(where, slot1 + MiB(7), slot2,
		    VM_PROT_NONE);
	}

	foreach(where, slot2, slot2 + MiB(8) - 1) {
		check_entry(where, slot2, slot2 + MiB(8), VM_PROT_DEFAULT);
	}

	addr = base + MiB(17);
	if (slot2 < addr) {
		foreach(where, slot2, addr - 1) {
			check_entry(where, slot2, addr, VM_PROT_NONE);
		}
	}

	{
		mach_msg_type_number_t n     = MiB(20) >> PAGE_SHIFT;
		mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT;
		vm_page_info_basic_t   info  = calloc(n, sizeof(struct vm_page_info_basic));

		init_task_ledgers();

		kr = vm_map_page_range_info_internal(map, base, base + MiB(17),
		    PAGE_SHIFT, VM_PAGE_INFO_BASIC,
		    (vm_page_info_t)info, &count);

		T_ASSERT_MACH_SUCCESS(kr, "vm_map_page_range_info_internal()");

		free(info);
	}

#undef foreach
	t_done();
}
