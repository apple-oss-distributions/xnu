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

#include "checker.h"
#include <kern/assert.h>

#define WATCHPOINT_MAP_INITIAL_CAPACITY 4096  /* must be power of 2 */
#define WATCHPOINT_MAP_MAX_LOAD_FACTOR 0.75

static inline size_t
hash_address(uintptr_t addr, size_t capacity)
{
	size_t hash = (size_t)addr;
	hash = (hash ^ (hash >> 16)) * 31;
	hash = (hash ^ (hash >> 16)) * 31;
	hash = hash ^ (hash >> 16);
	return hash % capacity;
}

struct watchpoint_entry {
	union {
		void *pc; /* program point of the memory operation instruction */
		struct backtrace_array *backtrace; /* backtrace collected at program point of the memory operation instruction */
	};
	uintptr_t address; /* address of the memory operation happening on the fiber with id=fiber_id */
	int fiber_id; /* id of the fiber in which the memory operation is happening */
	uint8_t size; /* size of the memory operation (up to 16 bytes) */
	uint8_t access_type; /* enum access_type */
	uint8_t has_backtrace; /* if true, use the backtrace field of the union */
};

static void
watchpoint_entry_init(struct watchpoint_entry* entry, uintptr_t address, enum access_type type, size_t size, fiber_t fiber)
{
	FIBERS_ASSERT(entry != NULL, "watchpoint_entry_init: null entry");
	FIBERS_ASSERT(size <= 16, "watchpoint_entry_init: invalid size"); // no access is bigger than sizeof(int128)

	entry->address = address;
	entry->fiber_id = fiber->id;
	entry->access_type = (uint8_t)type;
	entry->size = (uint8_t)size;
	// default to pc=0
	entry->pc = 0;
	entry->has_backtrace = 0;
}

struct watchpoint_node {
	struct watchpoint_entry entry;
	struct watchpoint_node *next;
};

// A simple hashmap to store watchpoint_entry indexed by watchpoint_entry.address
struct watchpoint_map {
	struct watchpoint_node **buckets;
	size_t count;
	size_t capacity;
};

static bool
watchpoint_map_is_initialized(struct watchpoint_map* map)
{
	return map->capacity != 0 && map->buckets != NULL;
}

void
watchpoint_map_init(struct watchpoint_map* map)
{
	map->count = 0;
	map->capacity = WATCHPOINT_MAP_INITIAL_CAPACITY;
	map->buckets = calloc(map->capacity, sizeof(struct watchpoint_node*));
}

// Currently the watchpoint map has a global scope, so this function is unnecessary
// We keep it here for future usage
/*
 *  void
 *  watchpoint_map_destroy(struct watchpoint_map* map)
 *  {
 *       if (map->buckets) {
 *               for (size_t i = 0; i < map->capacity; ++i) {
 *                       struct watchpoint_node* current = map->buckets[i];
 *                       while (current != NULL) {
 *                               struct watchpoint_node* to_free = current;
 *                               current = current->next;
 *                               free(to_free);
 *                       }
 *               }
 *               free(map->buckets);
 *       }
 *       map->buckets = NULL;
 *       map->count = 0;
 *       map->capacity = 0;
 *  }
 */

static bool
watchpoint_map_resize(struct watchpoint_map* map, size_t new_capacity)
{
	if (new_capacity < map->count) {
		return false;
	}
	struct watchpoint_node** new_buckets = calloc(new_capacity, sizeof(struct watchpoint_node*));
	if (new_buckets == NULL) {
		return false;
	}

	/* rehash all existing entries into the new buckets */
	for (size_t i = 0; i < map->capacity; ++i) {
		struct watchpoint_node* current = map->buckets[i];
		while (current != NULL) {
			struct watchpoint_node* node_to_move = current;
			current = current->next;

			size_t new_index = hash_address(node_to_move->entry.address, new_capacity);
			node_to_move->next = new_buckets[new_index];
			new_buckets[new_index] = node_to_move;
		}
	}

	free(map->buckets);
	map->buckets = new_buckets;
	map->capacity = new_capacity;
	return true;
}

void
watchpoint_map_add(struct watchpoint_map* map, struct watchpoint_entry entry)
{
	if (((double)map->count / map->capacity) >= WATCHPOINT_MAP_MAX_LOAD_FACTOR) {
		watchpoint_map_resize(map, map->capacity * 2);
	}

	struct watchpoint_node* new_node = malloc(sizeof(struct watchpoint_node));
	new_node->entry = entry;
	new_node->next = NULL;

	size_t index = hash_address(entry.address, map->capacity);
	new_node->next = map->buckets[index];
	map->buckets[index] = new_node;
	map->count++;
}

bool
watchpoint_map_find_remove(struct watchpoint_map* map, uintptr_t address, fiber_t fiber, struct watchpoint_entry* removed_entry)
{
	size_t index = hash_address(address, map->capacity);

	struct watchpoint_node* current = map->buckets[index];
	struct watchpoint_node* prev = NULL;

	while (current != NULL) {
		if (current->entry.address == address && current->entry.fiber_id == fiber->id) {
			if (removed_entry) {
				memcpy(removed_entry, &current->entry, sizeof(struct watchpoint_entry));
			}

			if (prev == NULL) {
				map->buckets[index] = current->next;
			} else {
				prev->next = current->next;
			}
			free(current);
			map->count--;
			return true;
		}
		prev = current;
		current = current->next;
	}

	return false;
}

static void
report_race(uintptr_t current_addr, size_t current_size, enum access_type current_type, struct watchpoint_entry* conflicting_entry)
{
	raw_printf("==== Warning: Fibers data race checker violation ====\n");
	raw_printf("%s of size %d at %p by fiber %d\n", current_type == ACCESS_TYPE_STORE ? "Write" : "Read", current_size, (void*)current_addr, fibers_current->id);
	if (fibers_debug) {
		print_current_backtrace();
	}

	raw_printf("Previous %s of size %d at %p by fiber %d\n", conflicting_entry->access_type == ACCESS_TYPE_STORE ? "write" : "read", conflicting_entry->size, (void*)conflicting_entry->address, conflicting_entry->fiber_id);
	if (conflicting_entry->has_backtrace) {
		print_collected_backtrace(conflicting_entry->backtrace);
	} else {
		struct backtrace_array bt = { .buffer = {(void*)conflicting_entry->pc}, .nptrs = 1 };
		print_collected_backtrace(&bt);
	}

	if (fibers_abort_on_error) {
		abort();
	}
}

static inline void
report_missing_race(uintptr_t current_addr, size_t current_size, enum access_type current_type)
{
	raw_printf("==== Warning: Fibers data race checker violation ====\n");
	raw_printf("%s of size %d at %p by fiber %d\n", current_type == ACCESS_TYPE_STORE ? "Write" : "Read", current_size, (void*)current_addr, fibers_current->id);
	if (fibers_debug) {
		print_current_backtrace();
	}

	raw_printf("Watchpoint was unexpectedly missing or modified by another fiber during yield.\n");
	if (fibers_abort_on_error) {
		abort();
	}
}

void
report_value_race(uintptr_t current_addr, size_t current_size, enum access_type current_type)
{
	raw_printf("==== Warning: Fibers data race checker violation ====\n");
	raw_printf("%s of size %d at %p by fiber %d\n", current_type == ACCESS_TYPE_STORE ? "Write" : "Read", current_size, (void*)current_addr, fibers_current->id);
	if (fibers_debug) {
		print_current_backtrace();
	}

	raw_printf("Value was modified in between the operation by another fiber during yield.\n");
	if (fibers_abort_on_error) {
		abort();
	}
}

static inline bool
ranges_overlap(uintptr_t addr1, size_t size1, uintptr_t addr2, size_t size2)
{
	if (size1 == 0 || size2 == 0) {
		return false;
	}
	uintptr_t end1 = addr1 + size1;
	uintptr_t end2 = addr2 + size2;
	if (end1 < addr1 || end2 < addr2) {
		return false;
	}
	return addr1 < end2 && addr2 < end1;
}

/*
 * Check for conflicting memory accesses to the same region happening in another fiber.
 * Concurrent loads are allowed, loads in-between a store are not.
 */
static inline bool
check_for_conflicts(struct watchpoint_map* map, uintptr_t current_addr, size_t current_size, enum access_type current_type)
{
	/* range: [current_addr - 16, current_addr + 16] (33 addresses) */
	uintptr_t start_check_addr = (current_addr > 16) ? (current_addr - 16) : 0;
	uintptr_t end_check_addr = current_addr + 16;

	for (uintptr_t check_addr = start_check_addr;; ++check_addr) {
		size_t index = hash_address(check_addr, map->capacity);
		struct watchpoint_node* node = map->buckets[index];

		while (node != NULL) {
			struct watchpoint_entry* existing_entry = &node->entry;

			if (ranges_overlap(current_addr, current_size, existing_entry->address, existing_entry->size)) {
				if (current_type == ACCESS_TYPE_STORE) {
					/* any access in between a store is a race */
					report_race(current_addr, current_size, current_type, existing_entry);
					return true;
				} else if (existing_entry->access_type == ACCESS_TYPE_STORE) {
					/* allow other loads in between a load, but not a store */
					report_race(current_addr, current_size, current_type, existing_entry);
					return true;
				}
			}
			node = node->next;
		}
		if (check_addr == end_check_addr) {
			break;
		}
	}

	return false;
}

static struct watchpoint_map checker_watchpoints;

bool
check_and_set_watchpoint(void *pc, uintptr_t address, size_t size, enum access_type access_type)
{
	if (!watchpoint_map_is_initialized(&checker_watchpoints)) {
		watchpoint_map_init(&checker_watchpoints);
	}

	if (check_for_conflicts(&checker_watchpoints, address, size, access_type)) {
		return false;
	} else {
		struct watchpoint_entry new_watchpoint;
		watchpoint_entry_init(&new_watchpoint, address, access_type, size, fibers_current);
		if (fibers_debug) {
			new_watchpoint.backtrace = collect_current_backtrace();
			new_watchpoint.has_backtrace = 1;
		} else {
			new_watchpoint.pc = pc;
		}

		watchpoint_map_add(&checker_watchpoints, new_watchpoint);
		return true;
	}
}

void
post_check_and_remove_watchpoint(uintptr_t address, size_t size, enum access_type access_type)
{
	struct watchpoint_entry removed_entry;
	if (watchpoint_map_find_remove(&checker_watchpoints, address, fibers_current, &removed_entry)) {
		FIBERS_ASSERT(removed_entry.address == address, "race? internal error");
		FIBERS_ASSERT(removed_entry.access_type == access_type, "race? internal error");
		FIBERS_ASSERT(removed_entry.size == size, "race? internal error");
		FIBERS_ASSERT(removed_entry.fiber_id == fibers_current->id, "race? internal error");

		if (removed_entry.has_backtrace) {
			free(removed_entry.backtrace);
		}
	} else {
		report_missing_race(address, size, access_type);
	}
}
