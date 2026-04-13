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

#pragma once

#include "fibers.h"

#define FIBERS_RWLOCK_ASSERT_SHARED    0x01
#define FIBERS_RWLOCK_ASSERT_EXCLUSIVE 0x02
#define FIBERS_RWLOCK_ASSERT_HELD      0x03
#define FIBERS_RWLOCK_ASSERT_NOTHELD   0x04
#define FIBERS_RWLOCK_ASSERT_NOT_OWNED 0x05

#define FIBERS_RWLOCK_WANT_UPGRADE     0x1

typedef struct fibers_rwlock fibers_rwlock_t;

struct fibers_rwlock {
	fiber_t writer_active;
	unsigned int reader_count;
	unsigned int flags;

	struct fibers_queue reader_wait_queue;
	struct fibers_queue writer_wait_queue;
};

extern void fibers_rwlock_init(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_rdlock(fibers_rwlock_t *rwlock, bool check_may_yield);
extern void fibers_rwlock_wrlock(fibers_rwlock_t *rwlock, bool check_may_yield);
extern int fibers_rwlock_try_rdlock(fibers_rwlock_t *rwlock);
extern int fibers_rwlock_try_wrlock(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_rdunlock(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_wrunlock(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_unlock(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_destroy(fibers_rwlock_t *rwlock);
extern bool fibers_rwlock_upgrade(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_downgrade(fibers_rwlock_t *rwlock);
extern void fibers_rwlock_assert(fibers_rwlock_t *rwlock, unsigned int type);
