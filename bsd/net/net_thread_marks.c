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

#include "kpi_interface.h"
#include <stddef.h>

#include <net/dlil.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/user.h>

#include <kern/assert.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <kern/zalloc.h>

struct net_thread_marks { };
static const struct net_thread_marks net_thread_marks_base = { };

__private_extern__ const net_thread_marks_t net_thread_marks_none =
    &net_thread_marks_base;

__private_extern__ net_thread_marks_t
net_thread_marks_push(u_int32_t push)
{
	static const char *__unsafe_indexable const base = (const void*__single)&net_thread_marks_base;
	u_int32_t pop = 0;

	if (push != 0) {
		struct uthread *uth = current_uthread();

		pop = push & ~uth->uu_network_marks;
		if (pop != 0) {
			uth->uu_network_marks |= pop;
		}
	}

	return __unsafe_forge_single(net_thread_marks_t, (base + pop));
}

__private_extern__ net_thread_marks_t
net_thread_unmarks_push(u_int32_t unpush)
{
	static const char *__unsafe_indexable const base = (const void*__single)&net_thread_marks_base;
	u_int32_t unpop = 0;

	if (unpush != 0) {
		struct uthread *uth = current_uthread();

		unpop = unpush & uth->uu_network_marks;
		if (unpop != 0) {
			uth->uu_network_marks &= ~unpop;
		}
	}

	return __unsafe_forge_single(net_thread_marks_t, (base + unpop));
}

__private_extern__ void
net_thread_marks_pop(net_thread_marks_t popx)
{
	static const char *__unsafe_indexable const base = (const void*__single)&net_thread_marks_base;
	const ptrdiff_t pop = (const char *)popx - (const char *)base;
	if (pop != 0) {
		static const ptrdiff_t ones = (ptrdiff_t)(u_int32_t)~0U;
		struct uthread *uth = current_uthread();

		VERIFY((pop & ones) == pop);
		VERIFY((ptrdiff_t)(uth->uu_network_marks & pop) == pop);
		uth->uu_network_marks &= ~pop;
	}
}

__private_extern__ void
net_thread_unmarks_pop(net_thread_marks_t unpopx)
{
	static const char *__unsafe_indexable const base = (const void*__single)&net_thread_marks_base;
	ptrdiff_t unpop = (const char *)unpopx - (const char *)base;

	if (unpop != 0) {
		static const ptrdiff_t ones = (ptrdiff_t)(u_int32_t)~0U;
		struct uthread *uth = current_uthread();

		VERIFY((unpop & ones) == unpop);
		VERIFY((ptrdiff_t)(uth->uu_network_marks & unpop) == 0);
		uth->uu_network_marks |= (u_int32_t)unpop;
	}
}


__private_extern__ u_int32_t
net_thread_is_marked(u_int32_t check)
{
	if (check != 0) {
		struct uthread *uth = current_uthread();
		return uth->uu_network_marks & check;
	} else {
		return 0;
	}
}

__private_extern__ u_int32_t
net_thread_is_unmarked(u_int32_t check)
{
	if (check != 0) {
		struct uthread *uth = current_uthread();
		return ~uth->uu_network_marks & check;
	} else {
		return 0;
	}
}
