/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#pragma once

#include <mach/kern_return.h>
#include <kern/kern_types.h>
#include <kern/kern_cdata.h>
#include <kern/thread.h>
#include <sys/cdefs.h>


#if CONFIG_EXCLAVES

__BEGIN_DECLS

/*
 * Kick the collection thread to ensure it's running.
 */
extern void exclaves_inspection_begin_collecting(void);
/*
 * Wait for provided queue to drain.
 */
extern void exclaves_inspection_wait_complete(queue_t exclaves_inspection_queue);

extern void exclaves_inspection_check_ast(void);
extern bool exclaves_inspection_is_initialized(void);

extern lck_mtx_t exclaves_collect_mtx;
/*
 * These waitlists are protected by exclaves_collect_mtx and should not be
 * cleared other than by the dedicated `exclaves_collection_thread` thread.
 */
extern queue_head_t exclaves_inspection_queue_stackshot;
extern queue_head_t exclaves_inspection_queue_kperf;

static inline void
exclaves_inspection_queue_add(queue_t queue, queue_entry_t elm)
{
	assert(queue == &exclaves_inspection_queue_stackshot || queue == &exclaves_inspection_queue_kperf);
	lck_mtx_assert(&exclaves_collect_mtx, LCK_ASSERT_OWNED);

	enqueue_head(queue, elm);
}

__END_DECLS

#endif /* CONFIG_EXCLAVES */
