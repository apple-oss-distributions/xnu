/*
 * Copyright (c) 2020-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef log_mem_h
#define log_mem_h

#include <stddef.h>
#include <stdint.h>
#include <sys/param.h>

/*
 * A simple allocator on a top of a plain byte array. Primarily intended to
 * support OS kernel logging in order to avoid dependency to VM.
 */
typedef struct logmem_s {
	lck_spin_t  lm_lock;
	uint8_t     *lm_mem;
	uint8_t     *lm_mem_map;
	size_t      lm_mem_size;
	size_t      lm_cap_order;
	size_t      lm_min_order;
	size_t      lm_max_order;
	uint32_t    lm_cnt_allocations;
	uint32_t    lm_cnt_failed_size;
	uint32_t    lm_cnt_failed_full;
	uint32_t    lm_cnt_failed_lmoff;
	uint32_t    lm_cnt_free;
} logmem_t;

/*
 * Initializes dynamically allocated logmem. The caller is responsible for
 * allocating and providing backing memory for both data and the bitmap.
 * LOGMEM_SIZE and LOGMEM_MAP_SIZE provide a way to determine the right sizes.
 */
void logmem_init(logmem_t *, void *, size_t, size_t, size_t, size_t);

/*
 * Returns true if the logmem is initialized, false otherwise.
 */
bool logmem_ready(const logmem_t *);

/*
 * Allocates memory from a respective logmem. Returns a pointer to the beginning
 * of the allocated block. The resulting size of the allocated block is equal or
 * bigger than the size passed in during the call. The function comes in two
 * flavours, locking and non-locking. The caller is responsible for choosing the
 * right one based on where and how the logmem is used.
 */
void *logmem_alloc(logmem_t *, size_t *);
void *logmem_alloc_locked(logmem_t *, size_t *);

/*
 * Frees memory previously allocated by logmem_alloc*(). The caller must call
 * logmem_free*() with exact pointer and size value returned by logmem_alloc*().
 * The function comes in two flavours, locking and non-locking. The caller is
 * responsible for choosing the right one based on where and how the logmem is
 * used.
 */
void logmem_free(logmem_t *, void *, size_t);
void logmem_free_locked(logmem_t *, void *, size_t);

/*
 * Returns the maximum memory size allocatable by the logmem.
 */
size_t logmem_max_size(const logmem_t *);

/*
 * Returns true if logmem is empty, false otherwise.
 */
bool logmem_empty(const logmem_t *);

/*
 * Returns an amount of memory the logmem needs to be initialized with in order
 * to provide allocations and to maintain its internal state. The caller should
 * use this function to get the right amount, allocate the memory accodingly and
 * pass it to logmem_init().
 */
size_t logmem_required_size(size_t, size_t);

#endif /* log_mem_h */
