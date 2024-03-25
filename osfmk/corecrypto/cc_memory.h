/* Copyright (c) (2014-2023) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

#include "cc_config.h"
#include "cc_debug.h"
#include "ccn_internal.h"
#include <corecrypto/cc_error.h>
#include <corecrypto/cc_priv.h>

CC_PTRCHECK_CAPABLE_HEADER()

#ifndef _CORECRYPTO_CC_MEMORY_H_
#define _CORECRYPTO_CC_MEMORY_H_

#if CORECRYPTO_DEBUG && !defined(_WIN32) && !defined(_WIN64)
#define CC_ALLOC_DEBUG 1
#else
#define CC_ALLOC_DEBUG 0
#endif

struct cc_ws;
typedef struct cc_ws cc_ws, *cc_ws_t;

struct cc_ws {
	void *ctx;
	cc_size nunits;
	cc_size offset;
	cc_unit *(*CC_SPTR(cc_ws, alloc))(cc_ws_t ws, cc_size n);
	void(*CC_SPTR(cc_ws, free))(cc_ws_t ws);
};

/* Workspace debugging. */

#if CC_ALLOC_DEBUG
void cc_ws_alloc_debug(const void *p, const char *file, int line, const char *func);
void cc_ws_free_debug(const void *p);
#else
 #define cc_ws_alloc_debug(...)
 #define cc_ws_free_debug(...)
#endif

/* Generic heap malloc(). */
void *cc_malloc_clear(size_t s);
void cc_free(void *p, size_t size);

/* Generic workspace functions. */
cc_unit *cc_counted_by(n) cc_ws_alloc(cc_ws_t ws, cc_size n);
void cc_ws_free(cc_ws_t ws);

/* Stack-based workspace functions. */
void cc_ws_free_stack(cc_ws_t ws);

/* Null workspace functions. */
void cc_ws_free_null(cc_ws_t ws);

// Declare workspace with memory in HEAP. (FOR TESTING ONLY)
// This variant reserves a large workspace size in advance so
// we don't need to specify the exact requirement for tests.
#define CC_DECL_WORKSPACE_TEST(ws)                                \
    int ws##_rv;                                                  \
    CC_DECL_WORKSPACE_RV(ws, ccn_nof_size(1024 * 1024), ws##_rv); \
    cc_try_abort_if(ws##_rv != CCERR_OK, "alloc ws");

#define CC_DECL_WORKSPACE_NULL(ws)                                   \
    cc_ws ws##_ctx = { NULL, 0, 0, cc_ws_alloc, cc_ws_free_null };   \
    cc_ws_t ws = &ws##_ctx;                                          \
    cc_ws_alloc_debug(&ws, __FILE__, __LINE__, __func__);

#if CC_USE_HEAP_FOR_WORKSPACE

// Declare workspace with memory in HEAP.
// This should be the preference for large memory allocations but it requires
// to propagate error in case of allocation failure.
#define CC_DECL_WORKSPACE_RV(ws, n, rv)                                 \
    rv = CCERR_OK;                                                      \
    cc_unit *ws##_buf = (cc_unit *)cc_malloc_clear(ccn_sizeof_n(n));    \
    cc_ws ws##_ctx = { ws##_buf, n, 0, cc_ws_alloc, cc_ws_free };       \
    cc_ws_t ws = &ws##_ctx;                                             \
    if (NULL == ws->ctx)                                                \
	rv = CCERR_MEMORY_ALLOC_FAIL;                                   \
    else                                                                \
	cc_ws_alloc_debug(&ws, __FILE__, __LINE__, __func__);

#else // !CC_USE_HEAP_FOR_WORKSPACE

// Declare workspace with memory in STACK.
// This is the least preferred option since most corecrypto client have
// small stack.
#define CC_DECL_WORKSPACE_RV(ws, n, rv)                                 \
    rv = CCERR_OK;                                                      \
    _Pragma("GCC diagnostic push")                                      \
    _Pragma("GCC diagnostic ignored \"-Wvla\"")                         \
    cc_unit ws##_buf[CC_MAX_EVAL((n), 1U)];                             \
    _Pragma("GCC diagnostic pop")                                       \
    cc_ws ws##_ctx = { ws##_buf, n, 0, cc_ws_alloc, cc_ws_free_stack }; \
    cc_ws_t ws = &ws##_ctx;                                             \
    cc_ws_alloc_debug(&ws, __FILE__, __LINE__, __func__);

#endif // !CC_USE_HEAP_FOR_WORKSPACE

// =============================================================================
//   Common
// =============================================================================

#define CC_DECL_WORKSPACE_OR_FAIL(ws, n)  \
    int ws##_rv;                          \
    CC_DECL_WORKSPACE_RV(ws, n, ws##_rv); \
    if (ws##_rv != CCERR_OK)              \
	return ws##_rv;

#define CC_FREE_WORKSPACE(ws) \
    cc_ws_free_debug(&ws);    \
    ws->free(ws);

#define CC_CLEAR_AND_FREE_WORKSPACE CC_FREE_WORKSPACE

#define CC_DECL_BP_WS(ws, bp) cc_size _ws_offset = ws->offset;
#define CC_FREE_BP_WS(ws, bp) ws->offset = _ws_offset;

#define CC_CLEAR_BP_WS(ws, bp) \
    ccn_clear(ws->offset - _ws_offset, &((cc_unit *)ws->ctx)[_ws_offset]);

#define CC_ALLOC_WS(ws, n) ws->alloc(ws, n)

#if CC_KERNEL
#include <libkern/section_keywords.h>
#define CC_READ_ONLY_LATE(_t) SECURITY_READ_ONLY_LATE(_t)
#else
#define CC_READ_ONLY_LATE(_t) _t
#endif


#endif // _CORECRYPTO_CC_MEMORY_H_
