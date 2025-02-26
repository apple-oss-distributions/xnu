/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <stdbool.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <os/base.h>
#include <sys/syslog.h>
#include <net/sockaddr_utils.h>
#include <net/trie_utility.h>

int net_trie_log_level = LOG_DEBUG;
static os_log_t net_trie_log_handle = NULL;
#define NET_TRIE_DEBUG_SEARCH 0

#define NET_TRIE_LOG(level, fmt, ...)                                                                                   \
do {                                                                                                                    \
    if (net_trie_log_level >= level && net_trie_log_handle) {                                                           \
	if (level == LOG_ERR) {                                                                                         \
	    os_log_error(net_trie_log_handle, "NET_TRIE - %s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);     \
	} else {                                                                                                        \
	    os_log(net_trie_log_handle, "NET_TRIE - %s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__);           \
	}                                                                                                               \
    }                                                                                                                   \
} while (0)

#define TRIE_CHILD_SET(t, i, b, node)                                                                                   \
    {                                                                                                                   \
	if (b >= FIRST_PRINTABLE_ASCII && b <= LAST_PRINTABLE_ASCII) {                                                  \
	    (((t)->child_maps + (CHILD_MAP_SIZE * TRIE_NODE(t, i).child_map))[(b - FIRST_PRINTABLE_ASCII)]) = node;     \
	}  else {                                                                                                       \
	    NET_TRIE_LOG(LOG_ERR, "NETrie - out of printable acsii range <%X>", b);                                     \
	}                                                                                                               \
    }

static uint16_t
trie_node_alloc(struct net_trie *trie)
{
	if (trie->nodes_free_next < trie->nodes_count) {
		uint16_t node_idx = trie->nodes_free_next++;
		TRIE_NODE(trie, node_idx).child_map = NULL_TRIE_IDX;
		return node_idx;
	} else {
		return NULL_TRIE_IDX;
	}
}

static uint16_t
trie_child_map_alloc(struct net_trie *trie)
{
	if (trie->child_maps_free_next < trie->child_maps_count) {
		return trie->child_maps_free_next++;
	} else {
		return NULL_TRIE_IDX;
	}
}

static uint16_t
trie_bytes_move(struct net_trie *trie, uint16_t bytes_idx, size_t bytes_size)
{
	uint16_t start = trie->bytes_free_next;
	if (start + bytes_size <= trie->bytes_count) {
		if (start != bytes_idx) {
			memmove(&TRIE_BYTE(trie, start), &TRIE_BYTE(trie, bytes_idx), bytes_size);
		}
		trie->bytes_free_next += bytes_size;
		return start;
	} else {
		return NULL_TRIE_IDX;
	}
}

static boolean_t
net_trie_has_high_ascii(const uint8_t * __sized_by(string_length)string, size_t string_length)
{
	for (int i = 0; i < (int)string_length; i++) {
		if (HIGH_ASCII(string[i])) {
			return true;
		}
	}
	return false;
}

boolean_t
net_trie_init(struct net_trie *new_trie, size_t prefix_count, size_t leaf_count, size_t bytes_count)
{
	size_t bytes_mem_size;
	size_t child_maps_mem_size;
	size_t nodes_mem_size;
	size_t trie_memory_size = 0;
	size_t nodes_count = 0;
	size_t maps_count = 0;
	int data_memory_offset = 0;

	if (new_trie == NULL) {
		return false;
	}

	if (net_trie_log_handle == NULL) {
		net_trie_log_handle = os_log_create("com.apple.xnu.net.trie", "net_trie");
	}

	memset(new_trie, 0, sizeof(struct net_trie));

	if (new_trie == NULL || prefix_count <= 0 || leaf_count <= 0 || bytes_count <= 0) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - null trie, no prefix/leaf count or no byte count", __FUNCTION__);
		return false;
	}

	if (os_add3_overflow(prefix_count, leaf_count, 1, &nodes_count)) { /* + 1 for the root node */
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Overflow while computing the number of nodes", __FUNCTION__);
		return false;
	}

	if (os_add_overflow(prefix_count, 1, &maps_count)) { /* + 1 for the root node */
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Overflow while computing the number of maps", __FUNCTION__);
		return false;
	}

	if (bytes_count > UINT16_MAX || nodes_count > UINT16_MAX || maps_count > UINT16_MAX) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Invalid bytes count (%lu), nodes count (%lu) or maps count (%lu)", __FUNCTION__, bytes_count, nodes_count, maps_count);
		return false;
	}

	if (os_mul_overflow(sizeof(*new_trie->nodes), (size_t)nodes_count, &nodes_mem_size) ||
	    os_mul3_overflow(sizeof(*new_trie->child_maps), CHILD_MAP_SIZE, (size_t)maps_count, &child_maps_mem_size) ||
	    os_mul_overflow(sizeof(*new_trie->bytes), (size_t)bytes_count, &bytes_mem_size) ||
	    os_add3_overflow(nodes_mem_size, child_maps_mem_size, bytes_mem_size, &trie_memory_size)) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Overflow while computing trie memory sizes", __FUNCTION__);
		return false;
	}

	if (trie_memory_size > MAX_TRIE_MEMORY) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Trie memory size (%lu) is too big (maximum is %u)", __FUNCTION__, trie_memory_size, MAX_TRIE_MEMORY);
		return false;
	}

	NET_TRIE_LOG(LOG_DEBUG, "%s: NET_TRIE - initializing (Nodes count = %lu, child maps count = %lu, bytes_count = %lu, total memory size %lu)", __FUNCTION__, nodes_count, maps_count, bytes_count, trie_memory_size);

	void *memory = (u_int8_t *)kalloc_data(trie_memory_size, Z_WAITOK | Z_ZERO);
	if (memory == NULL) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Failed to allocate %lu bytes of memory for the trie", __FUNCTION__, trie_memory_size);
		return false;
	}
	new_trie->memory = memory;
	new_trie->trie_memory_size = trie_memory_size;

	new_trie->magic = NET_TRIE_MAGIC;
	new_trie->version = NET_TRIE_FORMAT_VERSION;

	new_trie->nodes_mem_size = nodes_mem_size;
	new_trie->child_maps_mem_size = child_maps_mem_size;
	new_trie->bytes_mem_size = bytes_mem_size;

	/* Initialize the free lists */
	uint8_t *data_memory = (uint8_t *)new_trie->memory + data_memory_offset;
	new_trie->nodes = (struct net_trie_node *)(void *)(data_memory);
	new_trie->nodes_count = (uint16_t)nodes_count;
	new_trie->nodes_free_next = 0;
	memset(new_trie->nodes, 0, nodes_mem_size);

	new_trie->child_maps = (uint16_t *)(void *)(data_memory + nodes_mem_size);
	new_trie->child_maps_count = (uint16_t)maps_count;
	new_trie->child_maps_free_next = 0;
	memset(new_trie->child_maps, 0xff, child_maps_mem_size);

	new_trie->bytes = (uint8_t *)(void *)(data_memory + nodes_mem_size + child_maps_mem_size);
	new_trie->bytes_count = (uint16_t)bytes_count;
	new_trie->bytes_free_next = 0;
	memset(new_trie->bytes, 0, bytes_mem_size);

	/* The root is an empty node */
	new_trie->root = trie_node_alloc(new_trie);

	return true;
}

boolean_t
net_trie_init_with_mem(struct net_trie *new_trie, uint8_t * __sized_by(trie_memory_size) memory, size_t trie_memory_size,
    size_t nodes_mem_size, size_t child_maps_mem_size, size_t bytes_mem_size,
    uint16_t nodes_count, uint16_t child_maps_count, uint16_t bytes_count)
{
	size_t test_trie_memory_size = 0;
	size_t test_nodes_mem_size = 0;
	size_t test_child_maps_mem_size = 0;
	size_t test_bytes_mem_size = 0;

	if (new_trie == NULL || memory == NULL) {
		return false;
	}

	if (net_trie_log_handle == NULL) {
		net_trie_log_handle = os_log_create("com.apple.xnu.net.trie", "net_trie");
	}

	// Validate all passed in sizes and counts:
	if (os_add3_overflow(nodes_mem_size, child_maps_mem_size, bytes_mem_size, &test_trie_memory_size) ||
	    os_mul_overflow(sizeof(*new_trie->nodes), (size_t)nodes_count, &test_nodes_mem_size) ||
	    os_mul3_overflow(sizeof(*new_trie->child_maps), CHILD_MAP_SIZE, (size_t)child_maps_count, &test_child_maps_mem_size) ||
	    os_mul_overflow(sizeof(*new_trie->bytes), (size_t)bytes_count, &test_bytes_mem_size)) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Overflow while validating trie memory sizes", __FUNCTION__);
		return false;
	}
	if (test_trie_memory_size != trie_memory_size) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - passed in mem sizes (nodes %zu maps %zu bytes %zu) not equal to total mem %zu",
		    __FUNCTION__, nodes_mem_size, child_maps_mem_size, bytes_mem_size, trie_memory_size);
		return false;
	}
	if (test_nodes_mem_size != nodes_mem_size) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - passed in nodes_count %d not valid", __FUNCTION__, nodes_count);
		return false;
	}
	if (test_child_maps_mem_size != child_maps_mem_size) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - passed in maps_count %d not valid", __FUNCTION__, child_maps_count);
		return false;
	}
	if (test_bytes_mem_size != bytes_mem_size) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - passed in bytes_count %d not valid", __FUNCTION__, bytes_count);
		return false;
	}

	memset(new_trie, 0, sizeof(struct net_trie));

	new_trie->memory = memory;
	new_trie->trie_memory_size = trie_memory_size;
	NET_TRIE_LOG(LOG_DEBUG, "%s: NET_TRIE - initialized with malloc %zu", __FUNCTION__, trie_memory_size);

	new_trie->magic = NET_TRIE_MAGIC;
	new_trie->version = NET_TRIE_FORMAT_VERSION;

	new_trie->nodes_mem_size = nodes_mem_size;
	new_trie->child_maps_mem_size = child_maps_mem_size;
	new_trie->bytes_mem_size = bytes_mem_size;

	uint8_t *data_memory = (uint8_t *)new_trie->memory;
	new_trie->nodes = (struct net_trie_node *)(void *)(data_memory);
	new_trie->nodes_count = (uint16_t)nodes_count;

	new_trie->child_maps = (uint16_t *)(void *)(data_memory + nodes_mem_size);
	new_trie->child_maps_count = (uint16_t)child_maps_count;

	new_trie->bytes = (uint8_t *)(void *)(data_memory + nodes_mem_size + child_maps_mem_size);
	new_trie->bytes_count = (uint16_t)bytes_count;

	/* The root points to the first node */
	new_trie->root = 0;

	NET_TRIE_LOG(LOG_DEBUG, "%s: NET_TRIE - initialized - mem %X (size %zu) nodes %X (size %zu count %d) maps %X (size %zu count %d) bytes %X (size %zu count %d)",
	    __FUNCTION__,
	    (unsigned int)new_trie->memory, new_trie->trie_memory_size,
	    (unsigned int)new_trie->nodes, new_trie->nodes_mem_size, new_trie->nodes_count,
	    (unsigned int)new_trie->child_maps, new_trie->child_maps_mem_size, new_trie->child_maps_count,
	    (unsigned int)new_trie->bytes, new_trie->bytes_mem_size, new_trie->bytes_count);

	return true;
}

void
net_trie_free(struct net_trie *new_trie)
{
	if (new_trie == NULL || new_trie->memory == NULL) {
		return;
	}
	kfree_data_sized_by(new_trie->memory, new_trie->trie_memory_size);
	memset(new_trie, 0, sizeof(struct net_trie));
}

uint16_t
net_trie_insert(struct net_trie *trie,
    const uint8_t * __sized_by(string_length) string, size_t string_length,
    const uint8_t * __sized_by(metadata_length) metadata, size_t metadata_length,
    boolean_t reverse)
{
	if (trie->memory == NULL || string == NULL || string_length == 0) {
		return NULL_TRIE_IDX;
	}

	if (string_length > UINT16_MAX || trie->bytes_free_next + (uint16_t)string_length > trie->bytes_count) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - failed insert - out of allocated memory", __FUNCTION__);
		return NULL_TRIE_IDX;
	}

	if (net_trie_has_high_ascii(string, string_length)) {
		NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - failed insert - non-printable ASCII not supported", __FUNCTION__);
		return NULL_TRIE_IDX;
	}

	char *byte = (char *)&TRIE_BYTE(trie, trie->bytes_free_next);

	if (reverse) {
		for (size_t i = 0, j = string_length - 1; i < string_length; i++, j--) {
			byte[i] = string[j];
		}
	} else {
		memcpy(byte, string, string_length);
	}

	uint16_t current = trie->root;
	uint16_t child = trie->root;
	uint16_t string_end = trie->bytes_free_next + (uint16_t)string_length;
	uint16_t string_idx = trie->bytes_free_next;
	uint16_t string_remainder = (uint16_t)string_length;

	while (child != NULL_TRIE_IDX) {
		uint16_t parent = current;
		uint16_t node_idx;
		uint16_t current_end;

		current = child;
		child = NULL_TRIE_IDX;

		current_end = TRIE_NODE(trie, current).start + TRIE_NODE(trie, current).length;

		for (node_idx = TRIE_NODE(trie, current).start;
		    node_idx < current_end &&
		    string_idx < string_end &&
		    TRIE_BYTE(trie, node_idx) == TRIE_BYTE(trie, string_idx);
		    node_idx++, string_idx++) {
			;
		}

		string_remainder = string_end - string_idx;

		if (node_idx < (TRIE_NODE(trie, current).start + TRIE_NODE(trie, current).length)) {
			/*
			 * We did not reach the end of the current node's string.
			 * We need to split the current node into two:
			 *   1. A new node that contains the prefix of the node that matches
			 *      the prefix of the string being inserted.
			 *   2. The current node modified to point to the remainder
			 *      of the current node's string.
			 */
			uint16_t prefix = trie_node_alloc(trie);
			if (prefix == NULL_TRIE_IDX) {
				NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Ran out of trie nodes while splitting an existing node", __FUNCTION__);
				return NULL_TRIE_IDX;
			}

			/*
			 * Prefix points to the portion of the current nodes's string that has matched
			 * the input string thus far.
			 */
			TRIE_NODE(trie, prefix).start = TRIE_NODE(trie, current).start;
			TRIE_NODE(trie, prefix).length = (node_idx - TRIE_NODE(trie, current).start);
			if (string_remainder == 0) {
				TRIE_NODE(trie, prefix).is_leaf = true;

				/* Store the metadata */
				if (metadata && metadata_length > 0) {
					char *byte_ptr = (char *)&TRIE_BYTE(trie, trie->bytes_free_next);
					memcpy(byte_ptr, metadata, metadata_length);
					TRIE_NODE(trie, prefix).metadata = trie_bytes_move(trie, trie->bytes_free_next, metadata_length);
					TRIE_NODE(trie, prefix).metadata_length = (uint16_t)metadata_length;
				}
			}

			/*
			 * Prefix has the current node as the child corresponding to the first byte
			 * after the split.
			 */
			TRIE_NODE(trie, prefix).child_map = trie_child_map_alloc(trie);
			if (TRIE_NODE(trie, prefix).child_map == NULL_TRIE_IDX) {
				NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Ran out of child maps while splitting an existing node", __FUNCTION__);
				return NULL_TRIE_IDX;
			}
			TRIE_CHILD_SET(trie, prefix, TRIE_BYTE(trie, node_idx), current);

			/* Parent has the prefix as the child correspoding to the first byte in the prefix */
			TRIE_CHILD_SET(trie, parent, TRIE_BYTE(trie, TRIE_NODE(trie, prefix).start), prefix);

			/* Current node is adjusted to point to the remainder */
			TRIE_NODE(trie, current).start = node_idx;
			TRIE_NODE(trie, current).length -= TRIE_NODE(trie, prefix).length;

			/* We want to insert the new leaf (if any) as a child of the prefix */
			current = prefix;
		}

		if (string_remainder > 0) {
			/*
			 * We still have bytes in the string that have not been matched yet.
			 * If the current node has children, iterate to the child corresponding
			 * to the next byte in the string.
			 */
			if (TRIE_NODE(trie, current).child_map != NULL_TRIE_IDX) {
				child = TRIE_CHILD_GET(trie, current, TRIE_BYTE(trie, string_idx));
			}
		}
	} /* while (child != NULL_TRIE_IDX) */

	if (string_remainder > 0) {
		/* Add a new leaf containing the remainder of the string */
		uint16_t leaf = trie_node_alloc(trie);
		if (leaf == NULL_TRIE_IDX) {
			NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Ran out of trie nodes while inserting a new leaf", __FUNCTION__);
			return NULL_TRIE_IDX;
		}

		TRIE_NODE(trie, leaf).start = trie_bytes_move(trie, string_idx, string_remainder);
		if (TRIE_NODE(trie, leaf).start == NULL_TRIE_IDX) {
			NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Ran out of bytes while inserting a new leaf", __FUNCTION__);
			return NULL_TRIE_IDX;
		}
		TRIE_NODE(trie, leaf).length = string_remainder;
		TRIE_NODE(trie, leaf).is_leaf = true;

		/* Store the metadata */
		if (metadata && metadata_length > 0) {
			char *byte_ptr = (char *)&TRIE_BYTE(trie, trie->bytes_free_next);
			memcpy(byte_ptr, metadata, metadata_length);
			TRIE_NODE(trie, leaf).metadata = trie_bytes_move(trie, trie->bytes_free_next, metadata_length);
			TRIE_NODE(trie, leaf).metadata_length = (uint16_t)metadata_length;
		}

		/* Set the new leaf as the child of the current node */
		if (TRIE_NODE(trie, current).child_map == NULL_TRIE_IDX) {
			TRIE_NODE(trie, current).child_map = trie_child_map_alloc(trie);
			if (TRIE_NODE(trie, current).child_map == NULL_TRIE_IDX) {
				NET_TRIE_LOG(LOG_ERR, "%s: NET_TRIE - Ran out of child maps while inserting a new leaf", __FUNCTION__);
				return NULL_TRIE_IDX;
			}
		}
		TRIE_CHILD_SET(trie, current, TRIE_BYTE(trie, TRIE_NODE(trie, leaf).start), leaf);
		current = leaf;
	} /* else duplicate or this string is a prefix of one of the existing strings */

	return current;
}

uint16_t
net_trie_search(struct net_trie *trie,
    const uint8_t * __sized_by(string_length) string, size_t string_length,
    const uint8_t * __sized_by(*metadata_length) * metadata, size_t *metadata_length,
    boolean_t reverse, boolean_t partial_match_allowed, char partial_match_terminator,
    boolean_t *high_ascii_detected, check_metadata_func check_metadata)
{
	if (trie->memory == NULL || string == NULL || string_length == 0) {
		return NULL_TRIE_IDX;
	}

	uint16_t last_matched = NULL_TRIE_IDX;
	uint16_t current = trie->root;
	int16_t string_idx = reverse ? (int16_t)(string_length - 1) : 0;

#if NET_TRIE_DEBUG_SEARCH
	NET_TRIE_LOG(LOG_DEBUG, "NET_TRIE - search %s len %zu reverse %d", string, string_length, reverse);
#endif

	while (current != NULL_TRIE_IDX) {
		uint16_t next = NULL_TRIE_IDX;
		uint16_t node_end = TRIE_NODE(trie, current).start + TRIE_NODE(trie, current).length;
		uint16_t node_idx;

		if (reverse) {
			for (node_idx = TRIE_NODE(trie, current).start;
			    node_idx < node_end && string_idx >= 0 && string[string_idx] == TRIE_BYTE(trie, node_idx);
			    node_idx++, string_idx--) {
#if NET_TRIE_DEBUG_SEARCH
				NET_TRIE_LOG(LOG_DEBUG, "%c", string[string_idx]);
#endif
				;
			}
		} else {
			for (node_idx = TRIE_NODE(trie, current).start;
			    node_idx < node_end && string_idx < (int16_t)string_length && string[string_idx] == TRIE_BYTE(trie, node_idx);
			    node_idx++, string_idx++) {
#if NET_TRIE_DEBUG_SEARCH
				NET_TRIE_LOG(LOG_DEBUG, "%c", string[string_idx]);
#endif
				;
			}
		}

		// High Ascii detection -
		// Any char matching the node string are not high Ascii.  Only need to check mismatched char.
		if (string_idx >= 0 && string_idx < (int16_t)string_length && HIGH_ASCII(string[string_idx])) {
			if (high_ascii_detected) {
				*high_ascii_detected = true;
			}
			return NULL_TRIE_IDX;
		}

#if NET_TRIE_DEBUG_SEARCH
		NET_TRIE_LOG(LOG_DEBUG, "NET_TRIE - node_idx %d node_end %d", node_idx, node_end);
#endif

		if (node_idx == node_end) {
			boolean_t exact_matched = ((reverse && string_idx < 0) || (string_idx == (int16_t)string_length));
			boolean_t partial_matched = (!exact_matched && partial_match_allowed && (string[string_idx] == partial_match_terminator));

#if NET_TRIE_DEBUG_SEARCH
			NET_TRIE_LOG(LOG_DEBUG, "NET_TRIE - reverse %d string_idx %d byte %d leaf %d (exact_matched %d partial_matched %d)",
			    reverse, string_idx, string_idx >= 0 && string_idx < (int16_t)string_length ? string[string_idx] : 888,
			    TRIE_NODE(trie, current).is_leaf, exact_matched, partial_matched);
#endif

			if (TRIE_NODE(trie, current).is_leaf == true) {
				uint16_t metadata_idex = TRIE_NODE(trie, current).metadata;
				const uint8_t *data = (metadata_idex > 0) ? &TRIE_BYTE(trie, metadata_idex) : NULL;
				size_t length = TRIE_NODE(trie, current).metadata_length;

				// Consider a match only if the metadata qualifies
				if (check_metadata == NULL || check_metadata(data, length)) {
					if (exact_matched) {
						// Provide access of leaf metadata to caller
						if (metadata && metadata_length) {
							if (data != NULL && length > 0) {
								*metadata = data;
								*metadata_length = length;
							}
						}
						return current; /* Got an exact match */
					} else if (partial_matched) {
						// Remember the last partial match but continue to try exact match
						last_matched = current;
					}
				}
			}
			if (string_idx >= 0 && string_idx < (int16_t)string_length &&
			    TRIE_NODE(trie, current).child_map != NULL_TRIE_IDX) {
				next = TRIE_CHILD_GET(trie, current, string[string_idx]);
			}
		}
		current = next;
	}

	// Couldn't find an exact match, but there is a closest partial match
	if (last_matched != NULL_TRIE_IDX) {
		// Provide access of leaf metadata to caller
		if (metadata && metadata_length) {
			uint16_t metadata_idex = TRIE_NODE(trie, last_matched).metadata;
			const uint8_t *data = (metadata_idex > 0) ? &TRIE_BYTE(trie, metadata_idex) : NULL;
			size_t length = TRIE_NODE(trie, last_matched).metadata_length;
			if (data != NULL && length > 0) {
				*metadata = data;
				*metadata_length = length;
			}
		}
		return last_matched;
	}

	// High Ascii detection -
	// Failed to match entire/partial string, complete the high Ascii check
	if (high_ascii_detected) {
		if (reverse) {
			for (; string_idx >= 0; string_idx--) {
				if (HIGH_ASCII(string[string_idx])) {
					*high_ascii_detected = true;
					break;
				}
			}
		} else {
			for (; string_idx < (int16_t)string_length; string_idx++) {
				if (HIGH_ASCII(string[string_idx])) {
					*high_ascii_detected = true;
					break;
				}
			}
		}
	}

	return NULL_TRIE_IDX;
}
