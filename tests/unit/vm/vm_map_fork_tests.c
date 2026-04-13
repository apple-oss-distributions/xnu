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
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/mock_pmap.h"
#include "mocks/osfmk/mock_thread.h"

#include <vm/vm_fault_internal.h>
#include <vm/vm_map_internal.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_test_utils_internal.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.vm.vm_map_fork_tests"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true)
	);

#pragma mark Generic helper macros

#define GET_INSTANCE(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, NAME, ...) NAME

#define ONE_IF_NOT_EMPTY_ELSE_ZERO(...) (0 __VA_OPT__(+ 1))
#define _GC_9(a, b, c, d, e, f, g, h, i) (8 + ONE_IF_NOT_EMPTY_ELSE_ZERO(i))
#define _GC_8(a, b, c, d, e, f, g, h) (7 + ONE_IF_NOT_EMPTY_ELSE_ZERO(h))
#define _GC_7(a, b, c, d, e, f, g) (6 + ONE_IF_NOT_EMPTY_ELSE_ZERO(g))
#define _GC_6(a, b, c, d, e, f) (5 + ONE_IF_NOT_EMPTY_ELSE_ZERO(f))
#define _GC_5(a, b, c, d, e) (4 + ONE_IF_NOT_EMPTY_ELSE_ZERO(e))
#define _GC_4(a, b, c, d) (3+ ONE_IF_NOT_EMPTY_ELSE_ZERO(d))
#define _GC_3(a, b, c) (2 + ONE_IF_NOT_EMPTY_ELSE_ZERO(c))
#define _GC_2(a, b) (1 + ONE_IF_NOT_EMPTY_ELSE_ZERO(b))
#define _GC_1(a) (0 + ONE_IF_NOT_EMPTY_ELSE_ZERO(a))
#define _GC_0() (0)
#define _GET_COUNT(...) GET_INSTANCE(__0 __VA_OPT__(,) __VA_ARGS__, _GC_9, _GC_8, _GC_7, _GC_6, _GC_5, _GC_4, _GC_3, _GC_2, _GC_1, _GC_0)(__VA_ARGS__)
/* Count number of values passed to macro (up to 9). */
#define GET_COUNT(...) _GET_COUNT(__VA_ARGS__)

static_assert(GET_COUNT() == 0, "No args is 0");
static_assert(GET_COUNT(a) == 1, "Single arg is 1");
static_assert(GET_COUNT(a, b) == 2, "Two args is 2");
static_assert(GET_COUNT(1, 2, 3, 4, 5, 6, 7, 8, 9) == 9, "Nine args is 9");
static_assert(GET_COUNT(a b) == 1, "Single arg is 1 even with space");
static_assert(GET_COUNT(a b, c) == 2, "Two args is 2 even with space on first");
static_assert(GET_COUNT(a, b c) == 2, "Two args is 2 even with space on second");
static_assert(GET_COUNT((a, b)) == 1, "Single arg is 1 even with parenthesized comma");
static_assert(GET_COUNT(a, ) == 1, "Single arg is 1 even with trailing comma");
static_assert(GET_COUNT(a, b, ) == 2, "Two args is 2 even with trailing comma");
static_assert(GET_COUNT(1, 2, 3, 4, 5, 6, 7, 8, ) == 8, "Eight args is 8 even with trailing comma");

#pragma mark Config types and macros

/*
 * There are a few macro tricks in this section. If you're not trying to mess
 * with this code, it's probably easier to understand it by example by looking
 * at how tests use it.
 */

typedef struct {
	vm_object_size_t size;
	bool internal;
	bool true_share;
	bool shadowed;
	bool owned; /* sets task owner */
	int purgeable;
	memory_object_copy_strategy_t copy_strategy;
} object_config_t;
#define QUICK_OBJECT(...)                                           \
    _Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
    ((object_config_t) {                                            \
	        .size = PAGE_SIZE,                                      \
	        .internal = true,                                       \
	        .true_share = false,                                    \
	        .shadowed = false,                                      \
	        .purgeable = VM_PURGABLE_DENY,                          \
	        .copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,          \
	        __VA_ARGS__                                             \
	})                                                              \
    _Pragma("clang diagnostic pop")

struct map_config;

typedef struct {
	vm_map_offset_t start;
	vm_map_offset_t end;
	vm_inherit_t inheritance;
	bool needs_copy;
	vm_map_offset_t offset;
	vm_prot_t prot;
	vm_prot_t max_prot;
	unsigned short wired_count;
	bool permanent;
	bool used_for_jit;
	bool is_shared;
	bool use_pmap;
	bool is_submap;
	int target_id;
} entry_config_t;
#define __QUICK_ENTRY(...)                                          \
    _Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	 ((entry_config_t) {                                            \
	        .inheritance = VM_INHERIT_COPY,                         \
	        .needs_copy = false,                                    \
	        .offset = 0,                                            \
	        .prot = VM_PROT_DEFAULT,                                \
	        .max_prot = VM_PROT_ALL,                                \
	        .wired_count = 0,                                       \
	        .permanent = false,                                     \
	        .used_for_jit = false,                                  \
	        .is_shared = false,                                     \
	        .use_pmap = true,                                       \
	        __VA_ARGS__                                             \
	})                                                              \
    _Pragma("clang diagnostic pop")
#define QUICK_ENTRY(...) __QUICK_ENTRY(.is_submap = false, __VA_ARGS__)
#define QUICK_SUBMAP_ENTRY(...) __QUICK_ENTRY(.is_submap = true, __VA_ARGS__)

#define MAX_ENTRIES_IN_MAP (10)
typedef struct map_config {
	vm_map_offset_t min;
	vm_map_offset_t max;
	bool is_4k;
	size_t entries_count;
	entry_config_t entries[MAX_ENTRIES_IN_MAP];
} map_config_t;
#define QUICK_MAP(...)                                              \
    _Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	((map_config_t) {                                               \
	        .min = 0x0,                                             \
	        .max = -PAGE_SIZE,                                      \
	        .is_4k = false,                                         \
	        __VA_ARGS__                                             \
	})                                                              \
    _Pragma("clang diagnostic pop")
#define MAP_ENTRIES(...) .entries_count = GET_COUNT(__VA_ARGS__), .entries = {__VA_ARGS__}

__enum_closed_decl(object_id_t, uint8_t, {
	OBJECT_ID_1,
	OBJECT_ID_2,
	OBJECT_ID_3,
	MAX_OBJECTS_IN_VM,
	OBJECT_ID_FOR_NULL = -1,
});
__enum_closed_decl(map_id_t, uint8_t, {
	MAP_ID_1,
	MAP_ID_2,
	MAP_ID_3,
	MAX_MAPS_IN_VM,
});

typedef struct {
	size_t objects_count;
	object_config_t objects[MAX_OBJECTS_IN_VM];
	size_t maps_count;
	map_config_t maps[MAX_MAPS_IN_VM];
} vm_config_t;

#define CONFIG_OBJECTS(...) .objects_count = GET_COUNT(__VA_ARGS__), .objects = {__VA_ARGS__}
#define CONFIG_MAPS(...) .maps_count = GET_COUNT(__VA_ARGS__), .maps = {__VA_ARGS__}

typedef struct {
	vm_config_t *config;
	task_t task; /* for ownership tracking */
	vm_object_t objects[MAX_OBJECTS_IN_VM];
	vm_map_t maps[MAX_MAPS_IN_VM];
} vm_state_t;

#define Config manipulation helpers

static inline vm_map_size_t
entry_size(entry_config_t *config)
{
	return config->end - config->start;
}

static inline int
state_get_main_map_id(vm_state_t *state)
{
	return state->config->maps_count - 1;
}

static inline vm_map_t
state_get_main_map(vm_state_t *state)
{
	return state->maps[state_get_main_map_id(state)];
}

#pragma mark Config checking

static void
assert_sound_config(vm_config_t *config)
{
	int object_refs[MAX_OBJECTS_IN_VM] = { 0 };
	int object_seen_nc[MAX_OBJECTS_IN_VM] = { false };
	int map_refs[MAX_MAPS_IN_VM] = { 0 };

	assert3u(config->objects_count, <=, MAX_OBJECTS_IN_VM);
	assert3u(config->maps_count, <=, MAX_MAPS_IN_VM);

	for (int i = 0; i < config->objects_count; i++) {
		object_config_t *object_config = &config->objects[i];
		assert3u(object_config->size, ==, vm_map_round_page(object_config->size, PAGE_MASK));
		if (object_config->purgeable != VM_PURGABLE_DENY) {
			assert3u(object_config->copy_strategy, ==, MEMORY_OBJECT_COPY_NONE);
		}
		if (object_config->owned) {
			assert3u(object_config->copy_strategy, !=, MEMORY_OBJECT_COPY_SYMMETRIC);
		}
	}

	for (int i = 0; i < config->maps_count; i++) {
		map_config_t *map_config = &config->maps[i];
		int page_mask = map_config->is_4k ? FOURK_PAGE_MASK : PAGE_MASK;
		assert3u(map_config->min, ==, vm_map_round_page(map_config->min, page_mask));
		assert3u(map_config->max, ==, vm_map_round_page(map_config->max, page_mask));
		assert3u(map_config->min, <, map_config->max);
		vm_map_offset_t prev_end = 0;
		bool in_submap = (i < (config->maps_count - 1));
		for (int j = 0; j < map_config->entries_count; j++) {
			entry_config_t *entry_config = &map_config->entries[j];
			assert3u(entry_config->start, <, entry_config->end);
			assert3u(entry_config->start, ==, vm_map_round_page(entry_config->start, page_mask));
			assert3u(entry_config->end, ==, vm_map_round_page(entry_config->end, page_mask));
			assert3u(prev_end, <=, entry_config->start);
			prev_end = entry_config->end;
			assert3u(entry_config->prot & entry_config->max_prot, ==, entry_config->prot);
			if (in_submap) {
				assert(entry_config->is_shared);
				assert(!entry_config->needs_copy);
			}
			vm_map_offset_t target_size;
			if (entry_config->is_submap) {
				assert(!in_submap);
				assert(!entry_config->used_for_jit);
				map_id_t id = entry_config->target_id;
				assert3u(id, <, i); /* Must not refer to a map defined later in the config. */
				map_refs[id]++;
				map_config_t *submap_config = &config->maps[id];
				assert3u(map_config->is_4k, ==, submap_config->is_4k);
				target_size = submap_config->max - submap_config->min;
			} else {
				object_id_t id = entry_config->target_id;
				if (id == OBJECT_ID_FOR_NULL) {
					assert(!in_submap);
					assert(!entry_config->needs_copy);
					assert(!entry_config->used_for_jit);
					assert3u(entry_config->wired_count, ==, 0);

					target_size = entry_size(entry_config);
					assert3u(entry_config->offset, ==, 0);
				} else {
					assert3u(id, <, config->objects_count);
					object_refs[id]++;

					object_config_t *object_config = &config->objects[id];

					if (entry_config->needs_copy) {
						assert3u(object_config->copy_strategy, ==, MEMORY_OBJECT_COPY_SYMMETRIC);
						object_seen_nc[id] = true;
					}
					if (entry_config->wired_count) {
						assert3u(object_config->copy_strategy, !=, MEMORY_OBJECT_COPY_SYMMETRIC);
					}
					if (entry_config->used_for_jit) {
						assert3u(object_config->copy_strategy, ==, MEMORY_OBJECT_COPY_NONE);
					}
					if (!entry_config->needs_copy && object_config->shadowed) {
						assert3u(object_config->size, !=, entry_size(entry_config));
					}

					if (in_submap) {
						assert3u(object_config->copy_strategy, !=, MEMORY_OBJECT_COPY_SYMMETRIC);
						assert(object_config->true_share);
					}

					target_size = object_config->size;
				}
			}
			/* Skip bytes ignored by the offset. */
			assert3u(entry_config->offset, <, target_size);
			target_size -= entry_config->offset;
			/* Make sure there is enough memory for the whole entry. */
			assert3u(entry_size(entry_config), <=, target_size);
		}
	}

	/*
	 * Check reference counts.
	 * if objects/maps are not referenced they got declared in the config but
	 * are unused. Complain to help the tester catch issues.
	 */
	for (int i = 0; i < config->objects_count; i++) {
		assert3u(object_refs[i], >=, 1);
		if ((object_refs[i] > 1) && !object_seen_nc[i]) {
			assert3u(config->objects[i].copy_strategy, !=, MEMORY_OBJECT_COPY_SYMMETRIC);
		}
	}
	assert3u(config->maps_count, >=, 1); /* There should be a map. */
	for (int i = 0; i < config->maps_count - 1; i++) { /* Handle last map separately. */
		assert3u(map_refs[i], >=, 1);
	}
	/*
	 * Last map should not be used as a submap anywhere. It is the top map
	 * the tester will fork.
	 */
	assert3u(map_refs[config->maps_count - 1], ==, 0);
}

#pragma mark Functions for creating test state from a config

static vm_map_t
create_map(vm_map_offset_t min, vm_map_offset_t max, bool is_4k)
{
	int page_shift = is_4k ? FOURK_PAGE_SHIFT : PAGE_SHIFT;
	return vm_map_create_with_page_shift(pmap_create_options(NULL, 0, PMAP_CREATE_64BIT), min, max, page_shift, 0);
}

static vm_object_t
make_object(vm_state_t *state, object_config_t *object_config)
{
	vm_object_t obj = vm_object_allocate(object_config->size, VM_MAP_SERIAL_NONE);
	obj->internal = object_config->internal;
	if (!object_config->internal) {
		obj->pager_ready = true;
	}
	obj->true_share = object_config->true_share;
	obj->shadowed = object_config->shadowed;
	obj->purgable = object_config->purgeable;
	obj->copy_strategy = object_config->copy_strategy;
	if (object_config->owned) {
		obj->vo_owner = state->task;
		obj->vo_ledger_tag = VM_LEDGER_TAG_DEFAULT;
	}
	return obj;
}

static vm_map_entry_t
make_entry(vm_state_t *state, vm_map_t map, entry_config_t *entry_config)
{
	vm_map_offset_t start = entry_config->start;
	vm_map_offset_t end = entry_config->end;
	vm_map_entry_t entry = vm_test_add_map_entry(map, start, end);
	vm_map_ilk_lock(map);
	assert3u(KERN_SUCCESS, ==,
	    vm_entry_lock_exclusive(map, LCK_RW_TYPE_EXCLUSIVE, entry, start, THREAD_UNINT));
	entry->inheritance = entry_config->inheritance;
	entry->needs_copy = entry_config->needs_copy;
	entry->wired_count = entry_config->wired_count;
	entry->protection = entry_config->prot;
	entry->max_protection = entry_config->max_prot;
	entry->vme_permanent = entry_config->permanent;
	entry->is_shared = entry_config->is_shared;
	entry->use_pmap = entry_config->use_pmap;
	if (entry_config->is_submap) {
		vm_map_t submap = state->maps[entry_config->target_id];
		VME_SUBMAP_SET(entry, submap);
	} else {
		object_id_t id = entry_config->target_id;
		if (id != OBJECT_ID_FOR_NULL) {
			vm_object_t obj = state->objects[id];
			if (obj == VM_OBJECT_NULL) {
				state->objects[id] = make_object(state, &state->config->objects[id]);
				obj = state->objects[id];
			} else {
				vm_object_reference(obj);
			}
			VME_OBJECT_SET(entry, obj, false, 0);
		}
	}
	VME_OFFSET_SET(entry, entry_config->offset);

	if (entry_config->used_for_jit) {
		entry->used_for_jit = true;
		map->jit_entry_exists = true;
	}

	vm_entry_unlock_exclusive(map, entry);
	vm_map_ilk_unlock(map);
	return entry;
}

static vm_map_t
make_map(vm_state_t *state, map_config_t *config, int vmmap_sealed)
{
	vm_map_t map = create_map(config->min, config->max, config->is_4k);
	map->vmmap_sealed = vmmap_sealed;

	assert3u(map->hdr.nentries, ==, 0);
	for (uint32_t i = 0; i < config->entries_count; i++) {
		entry_config_t *entry_config = &config->entries[i];
		make_entry(state, map, entry_config);
	}
	assert3u(map->hdr.nentries, ==, config->entries_count);
	return map;
}

static vm_state_t *
make_vm(vm_config_t *config)
{
	assert_sound_config(config);
	vm_state_t *state = calloc(1, sizeof(vm_state_t));
	state->config = config;

	task_t task = fake_alloc_init_task_and_proc();
	state->task = task;
	for (int i = 0; i < config->maps_count; i++) {
		int sealed = (i < config->maps_count - 1) ? VM_MAP_WILL_BE_SEALED : VM_MAP_NOT_SEALED;
		vm_map_t map = make_map(state, &config->maps[i], sealed);
		if (sealed == VM_MAP_WILL_BE_SEALED) {
			vm_map_seal(map, true);
		} else {
			task->map = map;
		}
		state->maps[i] = map;
	}
	return state;
}

#pragma mark Code that validates maps are as expected

typedef enum {
	FORK_OUTCOME_DROPPED = 1,
	FORK_OUTCOME_SHARED,
	FORK_OUTCOME_COPY_SYM,
	FORK_OUTCOME_COPY_DELAY,
	FORK_OUTCOME_COPY_NONE,
} fork_outcome_t;

static fork_outcome_t
determine_fork_outcome(vm_state_t *state, entry_config_t *entry_config, int options)
{
	switch (entry_config->inheritance) {
	case VM_INHERIT_NONE:
		if (options & VM_MAP_FORK_SHARE_IF_INHERIT_NONE) {
			return FORK_OUTCOME_SHARED;
		}
		return FORK_OUTCOME_DROPPED;
	case VM_INHERIT_SHARE:
		return FORK_OUTCOME_SHARED;
	case VM_INHERIT_COPY:
		if (entry_config->is_submap) {
			return FORK_OUTCOME_DROPPED;
		}
		if (entry_config->target_id == OBJECT_ID_FOR_NULL) {
			/* this matches the expected behavior best because we won't set needs_copy */
			return FORK_OUTCOME_COPY_NONE;
		}
		object_config_t *object_config = &state->config->objects[entry_config->target_id];

		if (object_config->owned && (options & VM_MAP_FORK_SHARE_IF_OWNED)) {
			return FORK_OUTCOME_SHARED;
		}

		if (entry_config->wired_count == 0) {
			if ((!object_config->true_share) &&
			    (object_config->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC)) {
				return FORK_OUTCOME_COPY_SYM;
			}
		}
		if (!(entry_config->max_prot & VM_PROT_READ)) {
			/* copyin error path */
			return FORK_OUTCOME_DROPPED;
		}
		if ((object_config->copy_strategy == MEMORY_OBJECT_COPY_DELAY) &&
		    (entry_config->wired_count == 0)) {
			return FORK_OUTCOME_COPY_DELAY;
		}
		return FORK_OUTCOME_COPY_NONE;
	default:
		T_FAIL("Unexpected inheritance.");
		__builtin_unreachable();
	}
}

typedef enum {
	MAP_IS_SOURCE_PRE_FORK,
	MAP_IS_SOURCE_POST_FORK,
	MAP_IS_DEST,
} validation_mode_t;

static uint32_t
get_expected_object_ref_count(
	vm_state_t *state,
	entry_config_t *entry_config, bool in_submap,
	int options, validation_mode_t mode);

static bool
will_fork_create_new_private_object(
	vm_state_t *state,
	entry_config_t *entry_config, bool in_submap,
	int options)
{
	assert(!entry_config->is_submap);
	object_id_t id = entry_config->target_id;
	if (id == OBJECT_ID_FOR_NULL) {
		return false;
	}
	if (in_submap) {
		return false;
	}
	object_config_t *object_config = &state->config->objects[id];
	if (object_config->copy_strategy != MEMORY_OBJECT_COPY_SYMMETRIC) {
		return false;
	}
	if (entry_config->needs_copy ||               /* case 1 */
	    object_config->shadowed ||                 /* case 2 */
	    (!object_config->true_share &&             /* case 3 */
	    (object_config->size > entry_config->end - entry_config->start))) {
		if ((object_config->size == entry_size(entry_config)) &&
		    (1 == get_expected_object_ref_count(state, entry_config, false, options, MAP_IS_SOURCE_PRE_FORK))) {
			/* vm_object_shadow optimization code skips new object creation */
			return false;
		}
		return true;
	}
	return false;
}

static bool
new_object_created(
	vm_state_t *state,
	entry_config_t *entry_config, bool in_submap,
	int options, validation_mode_t mode)
{
	assert(!entry_config->is_submap);
	object_id_t id = entry_config->target_id;
	fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);

	if (mode == MAP_IS_SOURCE_PRE_FORK) {
		return false;
	}

	if (in_submap) {
		return false;
	}

	if (id == OBJECT_ID_FOR_NULL) {
		if (fork_outcome == FORK_OUTCOME_SHARED) {
			return true;
		}
		return false;
	}

	object_config_t *object_config = &state->config->objects[id];

	if (fork_outcome == FORK_OUTCOME_SHARED) {
		if (will_fork_create_new_private_object(state, entry_config, false, options)) {
			return true;
		}
	}

	if (mode != MAP_IS_DEST) {
		return false;
	}

	if (((fork_outcome == FORK_OUTCOME_COPY_DELAY) ||
	    (fork_outcome == FORK_OUTCOME_COPY_NONE))) {
		return true;
	}
	return false;
}

/*
 * Computes the expected object ref count for the entry pointed to by the
 * entry described by `entry_config` at the time specified by `mode`.
 */
static uint32_t
get_expected_object_ref_count(
	vm_state_t *state,
	entry_config_t *entry_config, bool in_submap,
	int options, validation_mode_t mode)
{
	uint32_t ref_count = 0;
	object_id_t id = entry_config->target_id;
	if (id == OBJECT_ID_FOR_NULL) {
		assert3u(determine_fork_outcome(state, entry_config, options), ==, FORK_OUTCOME_SHARED);
		return 2;
	}
	bool obj_is_new = false;
	if (mode != MAP_IS_SOURCE_PRE_FORK) { // avoid circular call graph
		obj_is_new = new_object_created(state, entry_config, in_submap, options, mode);
	}
	bool counted_ref_from_copy = false;
	bool entry_has_different_obj;
	for (int i = 0; i < state->config->maps_count; i++) {
		map_config_t *map_config = &state->config->maps[i];
		bool curr_in_submap = (i < state->config->maps_count - 1);
		for (int j = 0; j < map_config->entries_count; j++) {
			entry_config_t *curr_entry_config = &map_config->entries[j];
			if (curr_entry_config->is_submap) {
				continue;
			}
			if (curr_entry_config->target_id != id) {
				continue;
			}
			if (mode == MAP_IS_SOURCE_PRE_FORK) {
				ref_count += 1; // expect ref from source map
				continue;
			}
			if (curr_in_submap) {
				if (in_submap || !obj_is_new) {
					ref_count += 1; // expect ref from submap
				}
				continue;
			}
			fork_outcome_t fork_outcome = determine_fork_outcome(state, curr_entry_config, options);
			if (obj_is_new && (entry_config != curr_entry_config) &&
			    (fork_outcome != FORK_OUTCOME_COPY_DELAY)) {
				/*
				 * forking created a new object on this entry, and this entry
				 * is not the one we're concerned with. this entry can't have
				 * the same object as us, unless it was a copy delay, where
				 * all copies point at the same copy symmetric object.
				 */
				continue;
			}
			switch (fork_outcome) {
			case FORK_OUTCOME_DROPPED:
				ref_count += 1; // expect ref from source map
				break;
			case FORK_OUTCOME_SHARED:
				entry_has_different_obj = (entry_config != curr_entry_config) &&
				    will_fork_create_new_private_object(state, curr_entry_config, in_submap, options);
				if (entry_has_different_obj) {
					ref_count += 1; // expect ref from shadow pointer
				} else {
					ref_count += 2; // expect ref from both maps
				}
				break;
			case FORK_OUTCOME_COPY_SYM:
				// copy quickly case
				ref_count += 2; // expect ref from both maps
				break;
			case FORK_OUTCOME_COPY_DELAY:
				if (!obj_is_new) {
					ref_count += 1; // ref from source map
					if (!counted_ref_from_copy) {
						ref_count += 1; /* the copy object has a reference to this object */
						counted_ref_from_copy = true; /* make sure we only count it once */
					}
				} else {
					ref_count += 1; // ref from dest map
				}
				break;
			case FORK_OUTCOME_COPY_NONE:
				ref_count += 1; // expect only this ref
				break;
			default:
				T_FAIL("Unexpected fork path.");
			}
		}
	}

	return ref_count;
}

static void
update_object_config(
	vm_state_t *state,
	entry_config_t *entry_config, object_config_t *object_config,
	int options, validation_mode_t mode)
{
	fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);

	if (fork_outcome == FORK_OUTCOME_SHARED) {
		if (object_config->copy_strategy == MEMORY_OBJECT_COPY_SYMMETRIC) {
			if (will_fork_create_new_private_object(state, entry_config, false, options)) {
				object_config->internal = true;
				object_config->true_share = false;
				object_config->size = vm_object_round_page(entry_size(entry_config));
			}
			object_config->copy_strategy = MEMORY_OBJECT_COPY_DELAY;
		}
	}

	if (mode != MAP_IS_DEST) {
		return;
	}
	/* DEST-only updates */

	if ((fork_outcome != FORK_OUTCOME_COPY_DELAY) &&
	    (fork_outcome != FORK_OUTCOME_COPY_NONE)) {
		return;
	}

	object_config->internal = true;
	object_config->true_share = false;

	if (fork_outcome == FORK_OUTCOME_COPY_DELAY) {
		object_config->size = vm_object_round_page(entry_size(entry_config) + entry_config->offset);
		/* The result of copy delay is a copy symmetric object. */
		object_config->copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
		return;
	}

	assert3u(fork_outcome, ==, FORK_OUTCOME_COPY_NONE);
	object_config->size = vm_object_round_page(entry_size(entry_config));

	if ((object_config->purgeable != VM_PURGABLE_DENY) &&
	    (options & VM_MAP_FORK_PRESERVE_PURGEABLE)) {
		object_config->copy_strategy = MEMORY_OBJECT_COPY_NONE;
		object_config->true_share = true;
	} else if (entry_config->used_for_jit) {
		object_config->copy_strategy = MEMORY_OBJECT_COPY_NONE;
	} else {
		object_config->copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC;
	}

	if (!(options & VM_MAP_FORK_PRESERVE_PURGEABLE)) {
		// Not preserving purgeable, expect default purgeability.
		object_config->purgeable = VM_PURGABLE_DENY;
	}
}

static void
check_object_against_config(
	vm_state_t *state,
	entry_config_t *entry_config, vm_object_t object, bool in_submap,
	int options, validation_mode_t mode)
{
	assert(!entry_config->is_submap);
	fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);
	object_id_t id = entry_config->target_id;
	object_config_t object_config; // local storage
	vm_object_t original_object = VM_OBJECT_NULL;

	if (id == OBJECT_ID_FOR_NULL) {
		if ((mode == MAP_IS_SOURCE_PRE_FORK) || (fork_outcome != FORK_OUTCOME_SHARED)) {
			T_QUIET; T_ASSERT_EQ_PTR(VM_OBJECT_NULL, object, "object is null as expected");
			return;
		}
		object_config = QUICK_OBJECT(.size = entry_size(entry_config));
	} else {
		object_config = state->config->objects[id]; // local copy
		original_object = state->objects[id];
	}
	T_QUIET; T_ASSERT_NE_PTR(VM_OBJECT_NULL, object, "object is non-null as expected");

	vm_object_assert_not_owned(object);

	if (!in_submap && (mode != MAP_IS_SOURCE_PRE_FORK)) {
		update_object_config(state, entry_config, &object_config, options, mode);
	}

	if (!in_submap && new_object_created(state, entry_config, in_submap, options, mode)) {
		T_QUIET; T_ASSERT_NE_PTR(original_object, object, "Object was changed.");
	} else {
		T_QUIET; T_ASSERT_EQ_PTR(original_object, object, "Points to expected object.");
	}

	T_QUIET; T_ASSERT_EQ(object->vo_size, object_config.size, "Object size is as expected");
	T_QUIET; T_ASSERT_EQ((bool)object->internal, object_config.internal, "Internalness is as expected");
	T_QUIET; T_ASSERT_EQ((bool)object->true_share, object_config.true_share, "True-sharedness is as expected");
	T_QUIET; T_ASSERT_EQ((int)object->purgable, object_config.purgeable, "Purgeable is as expected");

	T_QUIET; T_ASSERT_EQ(object->copy_strategy, object_config.copy_strategy, "Copy strategy is as expected");

	uint32_t ex_ref_count = get_expected_object_ref_count(state, entry_config, in_submap, options, mode);
	T_QUIET; T_ASSERT_EQ(os_ref_get_count_raw(&object->ref_count), ex_ref_count, "Object ref count is as expected.");
}

static void
update_entry_config(vm_state_t *state, entry_config_t *config, int options, validation_mode_t mode)
{
	fork_outcome_t fork_outcome = determine_fork_outcome(state, config, options);

	if (fork_outcome == FORK_OUTCOME_SHARED) {
		config->is_shared = true;
	}

	switch (fork_outcome) {
	case FORK_OUTCOME_COPY_DELAY:
		if (mode != MAP_IS_DEST) {
			break;
		}
	case FORK_OUTCOME_COPY_SYM:
		config->needs_copy = true;
		break;
	case FORK_OUTCOME_SHARED:
	case FORK_OUTCOME_COPY_NONE:
		config->needs_copy = false;
		break;
	default:
		break;
	}

	if (mode != MAP_IS_DEST) {
		return;
	}
	/* DEST-only updates */

	if ((fork_outcome == FORK_OUTCOME_COPY_DELAY) ||
	    (fork_outcome == FORK_OUTCOME_COPY_NONE)) {
		config->is_shared = false;
	}

	config->wired_count = 0;
	if (fork_outcome != FORK_OUTCOME_COPY_SYM) {
		config->permanent = false;
	}
	if ((config->inheritance == VM_INHERIT_NONE) &&
	    (options & VM_MAP_FORK_SHARE_IF_INHERIT_NONE)) {
		config->prot &= ~VM_PROT_WRITE;
		config->max_prot &= ~VM_PROT_WRITE;
	}

	if (config->is_submap) {
		return;
	}
	/* non-submap-entry-only updates */

	object_id_t id = config->target_id;
	if (id == OBJECT_ID_FOR_NULL) {
		return;
	}
	object_config_t *object_config = &state->config->objects[id];
	if ((fork_outcome == FORK_OUTCOME_COPY_NONE) &&
	    (options & VM_MAP_FORK_PRESERVE_PURGEABLE) &&
	    (object_config->purgeable != VM_PURGABLE_DENY)) {
		config->use_pmap = false;
	}
}

/* Forward declare to check submaps from submap entries. */
static void
check_map_against_config(vm_state_t *state, map_id_t id, vm_map_t map, int options, validation_mode_t mode);

static void
check_entry_against_config(
	vm_state_t *state,
	entry_config_t *entry_config, vm_map_entry_t entry, bool in_submap,
	int options, validation_mode_t mode)
{
	fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);

	T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "entry is not NULL");

	if (entry_config->is_submap) {
		map_id_t id = entry_config->target_id;
		T_QUIET; T_ASSERT_EQ_PTR(state->maps[id], VME_SUBMAP(entry), "Points to expected submap.");
		check_map_against_config(state, id, VME_SUBMAP(entry), options, mode);
	} else {
		check_object_against_config(state, entry_config, VME_OBJECT(entry), in_submap, options, mode);
	}

	entry_config_t config = *entry_config; // local copy
	if (!in_submap && (mode != MAP_IS_SOURCE_PRE_FORK)) {
		update_entry_config(state, &config, options, mode);
	}

	if (in_submap) {
		VM_ENTRY_ASSERT_LOCK_INVALID(entry, VMEL_INVALID_REASON_SEALED_SUBMAP);
	} else {
		VM_ENTRY_ASSERT_NOT_OWNER(entry);
	}

	T_QUIET; T_ASSERT_EQ(entry->vme_start, config.start, "Start addr is as expected");
	T_QUIET; T_ASSERT_EQ(entry->vme_end, config.end, "End addr is as expected");
	T_QUIET; T_ASSERT_EQ((bool)entry->used_for_jit, config.used_for_jit, "JIT-ness is as expected");
	T_QUIET; T_ASSERT_EQ((vm_inherit_t)entry->inheritance, config.inheritance, "Inheritance is as expected");
	T_QUIET; T_ASSERT_EQ(VME_OFFSET(entry), config.offset, "Offset is as expected");
	T_QUIET; T_ASSERT_EQ_INT((bool)entry->is_sub_map, config.is_submap, "Submapness is as expected");
	T_QUIET; T_ASSERT_EQ_UINT(entry->wired_count, config.wired_count, "Wired count is as expected");
	T_QUIET; T_ASSERT_EQ((bool)entry->vme_permanent, config.permanent, "Permanence is as expected");
	T_QUIET; T_ASSERT_EQ((bool)entry->needs_copy, config.needs_copy, "needs_copy is as expected");
	T_QUIET; T_ASSERT_EQ((vm_prot_t)entry->protection, config.prot, "Protection is as expected");
	T_QUIET; T_ASSERT_EQ((vm_prot_t)entry->max_protection, config.max_prot, "Max protection is as expected");
	T_QUIET; T_ASSERT_EQ_INT((bool)entry->is_shared, config.is_shared, "Sharedness is as expected");
	T_QUIET; T_ASSERT_EQ_INT((bool)entry->use_pmap, config.use_pmap, "use_pmap bit is as expected");
}

static bool
jit_entry_exists_gets_updated(vm_state_t *state, entry_config_t *entry_config, int options, validation_mode_t mode)
{
	fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);

	if (!entry_config->used_for_jit) {
		return false;
	}
	if (mode != MAP_IS_DEST) {
		return true;
	}
	if (fork_outcome == FORK_OUTCOME_SHARED) {
		/* jit_entry_exists is NOT updated in the share path */
		return false;
	}
	/* jit entries have copy_none objects, and we are in the VM_INHERIT_COPY path */
	assert3u(fork_outcome, ==, FORK_OUTCOME_COPY_NONE);
	/* jit_entry_exists is updated in the copy path... */
	assert(!entry_config->is_submap);
	object_id_t id = entry_config->target_id;
	assert(id != OBJECT_ID_FOR_NULL);
	object_config_t *object_config = &state->config->objects[id];
	if (entry_config->wired_count || object_config->true_share) {
		/* ...except for an early return case for wired entries or true_share objects*/
		return false;
	}
	return true;
}

static int
count_gap_entries(vm_state_t *state, map_id_t id)
{
	map_config_t *config = &state->config->maps[id];
	bool in_submap = (id < state->config->maps_count - 1);

	if (!in_submap) {
		return 0;
	}
	/* submap case, it was sealed, so we need to count gaps to predict extra entries */
	int gap_entries = 0;
	vm_map_address_t last = 0;
	for (int i = 0; i < config->entries_count; i++) {
		entry_config_t *entry_config = &config->entries[i];
		if (entry_config->start != last) {
			gap_entries += 1;
		}
		last = entry_config->end;
	}
	if (last < config->max) {
		gap_entries += 1;
	}
	return gap_entries;
}

static void
check_map_against_config(vm_state_t *state, map_id_t id, vm_map_t map, int options, validation_mode_t mode)
{
	vm_map_entry_t entry;
	map_config_t *config = &state->config->maps[id];
	bool in_submap = (id < state->config->maps_count - 1);

	T_QUIET; T_ASSERT_NE_PTR(map, VM_MAP_NULL, "Non-null map.");

	assert_vm_map_ilk_not_owned(map);

	T_QUIET; T_ASSERT_EQ(map->min_offset, config->min, "Map min offset is as expected.");
	T_QUIET; T_ASSERT_EQ(map->max_offset, config->max, "Map max offset is as expected.");
	int ex_page_shift = config->is_4k ? FOURK_PAGE_SHIFT : PAGE_SHIFT;
	T_QUIET; T_ASSERT_EQ(vm_map_page_shift(map), ex_page_shift, "Map page shift is as expected.");

	int seen_expected_entries = 0;
	bool has_jit = false;
	for (int i = 0; i < config->entries_count; i++) {
		entry_config_t *entry_config = &config->entries[i];
		fork_outcome_t fork_outcome = determine_fork_outcome(state, entry_config, options);
		vm_map_ilk_lock_allow_sealed(map);
		entry = vm_map_lookup(map, entry_config->start);
		vm_map_ilk_unlock_allow_sealed(map);
		if ((mode == MAP_IS_DEST) && (fork_outcome == FORK_OUTCOME_DROPPED)) {
			T_QUIET; T_ASSERT_EQ_PTR(entry, VM_MAP_ENTRY_NULL, "Entry was dropped as expected.");
			continue;
		}
		T_QUIET; T_ASSERT_NE_PTR(entry, VM_MAP_ENTRY_NULL, "Found entry at expected location.");
		check_entry_against_config(state, entry_config, entry, in_submap, options, mode);
		if (jit_entry_exists_gets_updated(state, entry_config, options, mode)) {
			has_jit = true;
		}

		seen_expected_entries++;
	}

	T_QUIET; T_ASSERT_EQ_INT(has_jit, (bool)map->jit_entry_exists, "Map JIT-ness is as expected.");

	T_QUIET; T_ASSERT_EQ_INT(seen_expected_entries + count_gap_entries(state, id), map->hdr.nentries, "All entries in map are expected.");
}

static void
check_top_map_against_config(vm_state_t *state, vm_map_t map, int options, validation_mode_t mode)
{
	check_map_against_config(state, state_get_main_map_id(state), map, options, mode);
	T_QUIET; T_ASSERT_EQ(os_ref_get_count_raw(&map->map_refcnt), 1, "Map references are as expected.");
}

static void
run_fork_test_on_config(vm_config_t *config, int options)
{
	vm_state_t *state = make_vm(config);
	vm_map_t old_map = state_get_main_map(state);
	check_top_map_against_config(state, old_map, options, MAP_IS_SOURCE_PRE_FORK);
	T_PASS("Source map is ok pre-fork");

	vm_map_t new_map = vm_map_fork(0, old_map, options);

	check_top_map_against_config(state, old_map, options, MAP_IS_SOURCE_POST_FORK);
	T_PASS("Source map is ok post-fork");
	check_top_map_against_config(state, new_map, options, MAP_IS_DEST);
	T_PASS("Dest map is ok post-fork");
}

#pragma mark Tests

T_DECL(test_vm_map_fork_params, "Test vm_map_fork param checking")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS([MAP_ID_1] = QUICK_MAP()),
	};
	vm_state_t *state = make_vm(&config);
	vm_map_t map = state_get_main_map(state);
	check_top_map_against_config(state, map, 0, MAP_IS_SOURCE_PRE_FORK);

	T_ASSERT_EQ_PTR(VM_MAP_NULL, vm_map_fork(0, map, 0xfffffff), "Invalid options.");
}

T_DECL(test_vm_map_fork_pmap_creation_error, "Test vm_map_fork handling of pmap creation error")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS([MAP_ID_1] = QUICK_MAP()),
	};
	vm_state_t *state = make_vm(&config);
	vm_map_t map = state_get_main_map(state);
	check_top_map_against_config(state, map, 0, MAP_IS_SOURCE_PRE_FORK);

	__block bool called = false;
	T_MOCK_SET_CALLBACK(pmap_create_options,
	    pmap_t,
	    (ledger_t ledger, vm_map_size_t size, unsigned int flags), {
		called = true;
		return NULL;
	});

	T_ASSERT_EQ_PTR(VM_MAP_NULL, vm_map_fork(0, map, 0), "pmap creation error.");

	T_ASSERT_EQ(called, true, "pmap_create_options was called");
}

T_DECL(test_vm_map_fork_kernel_map_panic, "Test that vm_map_fork(kernel_map) panics")
{
	vm_map_t map = vm_map_create_options(kernel_pmap, 0, 0xfffffffffffff, 0);
	T_ASSERT_PANIC_CONTAINS({
		(void)vm_map_fork(0, map, 0);
	}, "attempting to fork from a kernel map", "vm_map_fork(kernel_map)");
	T_PASS("ok");
}

#pragma mark Basic testing

T_DECL(test_vm_map_fork_empty, "Test vm_map_fork on empty map")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS([MAP_ID_1] = QUICK_MAP()),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_inherit_none, "Test vm_map_fork on entry with no inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_inherit_share, "Test vm_map_fork on entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_inherit_copy_quickly, "Test vm_map_fork on entry with copy quickly inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_inherit_copy_none, "Test vm_map_fork on entry with copy none inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_inherit_copy_delay, "Test vm_map_fork on entry with copy delay inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Test forking on wired entries

T_DECL(test_vm_map_fork_wired_none, "Test vm_map_fork on wired entry with none inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						.wired_count = 1),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_wired_share, "Test vm_map_fork on wired entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.wired_count = 1),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_wired_copy_delay, "Test vm_map_fork on wired entry with copy delay inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						.wired_count = 1),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_wired_copy_none, "Test vm_map_fork on wired entry with copy none inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						.wired_count = 1),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Flag testing for VM_MAP_FORK_SHARE_IF_INHERIT_NONE

T_DECL(test_vm_map_fork_inherit_none_to_shared,
    "Test vm_map_fork on entry with none inheritance changed to shared by flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_SHARE_IF_INHERIT_NONE);
}

#pragma mark Flag testing for VM_MAP_FORK_PRESERVE_PURGEABLE

T_DECL(test_vm_map_fork_preserve_purgeable_non_volatile,
    "Test vm_map_fork on entry pointing to purgeable nonvolatile object with preserve flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .purgeable = VM_PURGABLE_NONVOLATILE,
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_PRESERVE_PURGEABLE);
}

T_DECL(test_vm_map_fork_preserve_purgeable_volatile,
    "Test vm_map_fork on entry pointing to purgeable volatile object with preserve flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .purgeable = VM_PURGABLE_VOLATILE,
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_PRESERVE_PURGEABLE);
}

T_DECL(test_vm_map_fork_dont_preserve_purgeable_non_volatile,
    "Test vm_map_fork on entry pointing to purgeable nonvolatile object without preserve flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .purgeable = VM_PURGABLE_NONVOLATILE,
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Flag testing for VM_MAP_FORK_CORPSE_FOOTPRINT

T_DECL(test_vm_map_fork_corpse_footprint, "Test vm_map_fork for corpse footprint on single entry")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_CORPSE_FOOTPRINT);
}

T_DECL(test_vm_map_fork_corpse_footprint_shutdown,
    "Test vm_map_fork for corpse footprint on single entry, shut down immediately")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	int options = VM_MAP_FORK_CORPSE_FOOTPRINT;
	vm_state_t *state = make_vm(&config);
	vm_map_t map = state_get_main_map(state);
	check_top_map_against_config(state, map, 0, MAP_IS_SOURCE_PRE_FORK);

	__block bool called = false;
	T_MOCK_SET_CALLBACK(get_system_inshutdown,
	    int, (), {
		called = true;
		return true;
	});

	T_ASSERT_EQ_PTR(VM_MAP_NULL, vm_map_fork(0, map, options), "Returned null due to system shutdown.");
	T_QUIET; T_ASSERT_EQ(called, true, "get_system_inshutdown was called");
}

#pragma mark Flag testing for VM_MAP_FORK_SHARE_IF_OWNED

T_DECL(test_vm_map_fork_share_if_owned_not_owned, "Test vm_map_fork on unowned object with share if owned flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_SHARE_IF_OWNED);
}

T_DECL(test_vm_map_fork_share_if_owned, "Test vm_map_fork on owned object with share if owned flag")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.owned = true,
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, VM_MAP_FORK_SHARE_IF_OWNED);
}

#pragma mark Testing for needs_copy and related issues

T_DECL(test_vm_map_fork_needs_copy_copy_quickly, "Test vm_map_fork copy quickly on needs_copy entry")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_needs_copy_share, "Test vm_map_fork share on needs_copy entry")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.needs_copy = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_shadowed_share,
    "Test vm_map_fork share on entry with shadowed object")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.shadowed = true,
				.size = 2 * PAGE_SIZE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_larger_object_share,
    "Test vm_map_fork share on entry point at object larger than itself")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = 2 * PAGE_SIZE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing for null objects

T_DECL(test_vm_map_fork_null_object_none,
    "Test vm_map_fork none inheritance on entry pointing at null object")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_FOR_NULL,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_null_object_copy,
    "Test vm_map_fork copy inheritance on entry pointing at null object")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_FOR_NULL,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_null_object_share,
    "Test vm_map_fork share inheritance on entry pointing at null object")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_FOR_NULL,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing for JIT entries

T_DECL(test_vm_map_fork_jit_copy_none, "Test vm_map_fork on JIT entry with copy none inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.used_for_jit = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_jit_share, "Test vm_map_fork on JIT entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.used_for_jit = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_jit_wired_copy,
    "Test vm_map_fork on wired JIT entry with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.used_for_jit = true,
						.wired_count = 1,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_jit_true_share_copy,
    "Test vm_map_fork on JIT entry with copy inheritance pointing to true share object")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				.true_share = true,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.used_for_jit = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing for permanent entries

T_DECL(test_vm_map_fork_permanent_copy_quickly, "Test vm_map_fork on permanent entry after quick copy")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.permanent = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_permanent_copy_none, "Test vm_map_fork on permanent entry after none copy")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.permanent = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_permanent_copy_delay, "Test vm_map_fork on permanent entry after delay copy")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.permanent = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_permanent_share, "Test vm_map_fork on permanent entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.permanent = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing for submap entries

T_DECL(test_vm_map_fork_submap_none, "Test vm_map_fork on empty submap entry with no inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(MAP_ENTRIES()),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_submap_share, "Test vm_map_fork on empty submap entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(MAP_ENTRIES()),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_submap_copy, "Test vm_map_fork on empty submap entry with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(MAP_ENTRIES()),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_submap_with_entries_none, "Test vm_map_fork on submap entry with no inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    .true_share = true,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.is_shared = true,
						),
					),
				),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_submap_with_entries_share, "Test vm_map_fork on empty submap entry with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    .true_share = true,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.is_shared = true,
						),
					),
				),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_submap_with_entries_copy, "Test vm_map_fork on empty submap entry with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    .true_share = true,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.is_shared = true,
						),
					),
				),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing for copyin error path

T_DECL(test_vm_map_fork_copyin_error, "Test vm_map_fork on PROT_NONE entry to force copyin to error")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.size = PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.prot = VM_PROT_NONE,
						.max_prot = VM_PROT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing iteration between multiple entries, no gap

T_DECL(test_vm_map_fork_multiple_no_gap_none, "Test vm_map_fork on 2 entries with none inheritance and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = PAGE_SIZE,
						.end = PAGE_SIZE + PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_no_gap_share, "Test vm_map_fork on 2 entries with share inheritance and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = PAGE_SIZE,
						.end = PAGE_SIZE + PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_no_gap_copy_quickly, "Test vm_map_fork on 2 entries with quick copies and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = PAGE_SIZE,
						.end = PAGE_SIZE + PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_no_gap_copy_delay, "Test vm_map_fork on 2 entries with delay copies and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			[OBJECT_ID_2] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = PAGE_SIZE,
						.end = PAGE_SIZE + PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Testing iteration between multiple entries, with a gap

T_DECL(test_vm_map_fork_multiple_gap_none, "Test vm_map_fork on 2 entries with none inheritance and a gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_gap_share, "Test vm_map_fork on 2 entries with share inheritance and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_gap_copy_quickly, "Test vm_map_fork on 2 entries with quick copies and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(),
			[OBJECT_ID_2] = QUICK_OBJECT(),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_multiple_gap_copy_delay, "Test vm_map_fork on 2 entries with delay copies and no gap")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			[OBJECT_ID_2] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Test entries CoW-sharing an object

T_DECL(test_vm_map_fork_on_cow_shared_copy,
    "Test vm_map_fork on cow-shared object with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_cow_shared_share,
    "Test vm_map_fork on cow-shared object with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_cow_shared_mixed_copy_share,
    "Test vm_map_fork on cow-shared object with 1 copy 1 share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_cow_shared_mixed_share_copy,
    "Test vm_map_fork on cow-shared object with 1 share 1 copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_cow_shared_triple_copy,
    "Test vm_map_fork on triply cow-shared object with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 4 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_cow_shared_triple_share,
    "Test vm_map_fork on triply cow-shared object with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 4 * PAGE_SIZE,
						.needs_copy = true,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Test entries sharing an object

T_DECL(test_vm_map_fork_on_shared_copy,
    "Test vm_map_fork on shared object with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_shared_share,
    "Test vm_map_fork on shared object with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_shared_mixed_copy_share,
    "Test vm_map_fork on shared object with 1 copy 1 share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_shared_mixed_share_copy,
    "Test vm_map_fork on shared object with 1 share 1 copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_on_shared_triple_copy,
    "Test vm_map_fork on triply shared object with copy inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 4 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}


T_DECL(test_vm_map_fork_on_shared_triple_share,
    "Test vm_map_fork on triply shared object with share inheritance")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 0x0,
						.end = PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 2 * PAGE_SIZE,
						.end = 3 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 4 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Test 4k maps

T_DECL(test_vm_map_fork_4k_copy_sym, "Test vm_map_fork on sym copy of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_4k_copy_delay, "Test vm_map_fork on delay copy of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_4k_copy_none, "Test vm_map_fork on none copy of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_4k_share, "Test vm_map_fork on sharing of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_4k_with_offset, "Test vm_map_fork on delayed copy of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .size = 4 * PAGE_SIZE,
		    .copy_strategy = MEMORY_OBJECT_COPY_DELAY,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						.offset = 15 * FOURK_PAGE_SIZE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_4k_none, "Test vm_map_fork on none inheritance of entry in 4k map")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT(
		    .copy_strategy = MEMORY_OBJECT_COPY_NONE,
		    )),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.is_4k = true,
				.max = -FOURK_PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = FOURK_PAGE_SIZE,
						.end = 2 * FOURK_PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Test whole map (fork does not ignore entries outside of map bounds)


T_DECL(test_vm_map_fork_copy_after_max, "Test vm_map_fork coping entry after map max")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.min = PAGE_SIZE,
				.max = 2 * PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 4 * PAGE_SIZE,
						.end = 5 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

T_DECL(test_vm_map_fork_share_after_max, "Test vm_map_fork sharing entry after map max")
{
	vm_config_t config = {
		CONFIG_OBJECTS([OBJECT_ID_1] = QUICK_OBJECT()),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				.min = PAGE_SIZE,
				.max = 2 * PAGE_SIZE,
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 4 * PAGE_SIZE,
						.end = 5 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}

#pragma mark Everything bagel

T_DECL(test_vm_map_fork_everything_bagel, "Test vm_map_fork on an everything bagel")
{
	vm_config_t config = {
		CONFIG_OBJECTS(
			[OBJECT_ID_1] = QUICK_OBJECT(
				.true_share = true,
				.internal = false,
				.copy_strategy = MEMORY_OBJECT_COPY_NONE,
				),
			[OBJECT_ID_2] = QUICK_OBJECT(
				.true_share = true,
				.internal = false,
				.size = 3 * PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_DELAY,
				),
			[OBJECT_ID_3] = QUICK_OBJECT(
				.size = 3 * PAGE_SIZE,
				.copy_strategy = MEMORY_OBJECT_COPY_SYMMETRIC,
				),
			),
		CONFIG_MAPS(
			[MAP_ID_1] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = PAGE_SIZE,
						.end = 2 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.is_shared = true,
						.prot = VM_PROT_READ,
						.max_prot = VM_PROT_DEFAULT,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 4 * PAGE_SIZE,
						.is_shared = true,
						),
					),
				),
			[MAP_ID_2] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 10 * PAGE_SIZE,
						.end = 12 * PAGE_SIZE,
						.permanent = true,
						.is_shared = true,
						.offset = PAGE_SIZE,
						.prot = VM_PROT_READ,
						.max_prot = VM_PROT_READ | VM_PROT_EXECUTE,
						),
					),
				),
			[MAP_ID_3] = QUICK_MAP(
				MAP_ENTRIES(
					QUICK_ENTRY(
						.target_id = OBJECT_ID_1,
						.start = PAGE_SIZE,
						.end = 2 * PAGE_SIZE,
						.is_shared = true,
						),
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_1,
						.start = 3 * PAGE_SIZE,
						.end = 7 * PAGE_SIZE,
						.offset = PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_2,
						.start = 9 * PAGE_SIZE,
						.end = 10 * PAGE_SIZE,
						.offset = PAGE_SIZE,
						.prot = VM_PROT_ALL,
						.max_prot = VM_PROT_ALL,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_3,
						.start = 12 * PAGE_SIZE,
						.end = 13 * PAGE_SIZE,
						.inheritance = VM_INHERIT_NONE,
						.needs_copy = true,
						),
					QUICK_SUBMAP_ENTRY(
						.target_id = MAP_ID_2,
						.start = 13 * PAGE_SIZE,
						.end = 20 * PAGE_SIZE,
						.offset = 8 * PAGE_SIZE,
						.inheritance = VM_INHERIT_COPY,
						.needs_copy = true,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_3,
						.start = 22 * PAGE_SIZE,
						.end = 23 * PAGE_SIZE,
						.offset = 2 * PAGE_SIZE,
						.needs_copy = true,
						),
					QUICK_ENTRY(
						.target_id = OBJECT_ID_3,
						.start = 27 * PAGE_SIZE,
						.end = 30 * PAGE_SIZE,
						.inheritance = VM_INHERIT_SHARE,
						.needs_copy = true,
						),
					),
				),
			),
	};
	run_fork_test_on_config(&config, 0);
}
