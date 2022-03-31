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

#ifndef _NET_BLOOM_FILTER_H_
#define _NET_BLOOM_FILTER_H_

#include <sys/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

// A Bloom Filter is a space-efficient probabilistic data structure
// that is used to test whether an element is a member of a set. It has a small
// rate of false positives, but it is guaranteed to have no false negatives.
//
// net_bloom_filter is a minimal implementation for use in kernel networking
// that uses three hash functions: net_flowhash_jhash, net_flowhash_mh3_x64_128,
// and net_flowhash_mh3_x86_32. This is optimal for a 10% false positive rate.
// The optimal number of bits should be calculated as:
//      num_bits = ((2.3 * ELEMENT_COUNT) / 0.48)

struct net_bloom_filter {
	uint32_t b_table_num_bits;
	uint32_t b_table[0];
};

struct net_bloom_filter *
net_bloom_filter_create(uint32_t num_bits);

size_t
net_bloom_filter_get_size(uint32_t num_bits);

void
net_bloom_filter_destroy(struct net_bloom_filter *filter);

void
net_bloom_filter_insert(struct net_bloom_filter *filter,
    const void *buffer,
    uint32_t length);

bool
net_bloom_filter_contains(struct net_bloom_filter *filter,
    const void *buffer,
    uint32_t length);

#ifdef  __cplusplus
}
#endif

#endif /* _NET_BLOOM_FILTER_H_ */
