/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#include <machine/endian.h>
#include <net/flowhash.h>
#include <net/bloom_filter.h>
#include <os/base.h>

#define kNetBloomFilterBitsPerTableElement (sizeof(uint32_t) * 8)

size_t
net_bloom_filter_get_size(uint32_t num_bits)
{
	if (num_bits == 0) {
		return sizeof(struct net_bloom_filter);
	}

	uint32_t num_elements = howmany(num_bits, kNetBloomFilterBitsPerTableElement);
	return sizeof(struct net_bloom_filter) + (sizeof(uint32_t) * num_elements);
}

struct net_bloom_filter *
net_bloom_filter_create(uint32_t num_bits)
{
	if (num_bits == 0) {
		return NULL;
	}

	const size_t size = net_bloom_filter_get_size(num_bits);
	struct net_bloom_filter *filter = (struct net_bloom_filter *)kalloc_data(size, Z_WAITOK | Z_ZERO);
	if (filter == NULL) {
		return NULL;
	}

	filter->b_table_num_bits = num_bits;
	return filter;
}

void
net_bloom_filter_destroy(struct net_bloom_filter *filter)
{
	if (filter != NULL) {
		uint8_t *filter_buffer = (uint8_t *)filter;
		kfree_data(filter_buffer, net_bloom_filter_get_size(filter->b_table_num_bits));
	}
}

static inline void
net_bloom_filter_insert_using_function(struct net_bloom_filter *filter,
    net_flowhash_fn_t *function,
    const void *buffer,
    uint32_t length)
{
	u_int32_t hash = (function(buffer, length, 0) % filter->b_table_num_bits);
	u_int32_t index = hash / kNetBloomFilterBitsPerTableElement;
	u_int32_t bit = hash % kNetBloomFilterBitsPerTableElement;
	(filter->b_table[index]) |= (1ull << bit);
}

void
net_bloom_filter_insert(struct net_bloom_filter *filter,
    const void *buffer,
    uint32_t length)
{
	net_bloom_filter_insert_using_function(filter, &net_flowhash_jhash, buffer, length);
	net_bloom_filter_insert_using_function(filter, &net_flowhash_mh3_x86_32, buffer, length);
	net_bloom_filter_insert_using_function(filter, &net_flowhash_mh3_x64_128, buffer, length);
}

static inline bool
net_bloom_filter_contains_using_function(struct net_bloom_filter *filter,
    net_flowhash_fn_t *function,
    const void *buffer,
    uint32_t length)
{
	u_int32_t hash = (function(buffer, length, 0) % filter->b_table_num_bits);
	u_int32_t index = hash / kNetBloomFilterBitsPerTableElement;
	u_int32_t bit = hash % kNetBloomFilterBitsPerTableElement;
	return (filter->b_table[index]) & (1ull << bit);
}

bool
net_bloom_filter_contains(struct net_bloom_filter *filter,
    const void *buffer,
    uint32_t length)
{
	return net_bloom_filter_contains_using_function(filter, &net_flowhash_jhash, buffer, length) &&
	       net_bloom_filter_contains_using_function(filter, &net_flowhash_mh3_x86_32, buffer, length) &&
	       net_bloom_filter_contains_using_function(filter, &net_flowhash_mh3_x64_128, buffer, length);
}
