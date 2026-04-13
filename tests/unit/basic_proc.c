/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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
#include "mocks/bsd/mock_proc.h"
#include <kern/task.h>
#include "mocks/osfmk/mock_thread.h"
#include <sys/reason.h>

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.proc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_OWNER("s_musaev")
	);


T_DECL(alloc_proc_task, "Allocating storage for task and proc")
{
	extern task_t proc_task(proc_t p);

	proc_t proc = fake_alloc_init_proc_and_task();

	T_ASSERT_EQ_PTR(proc, get_bsdtask_info(proc_task(proc)), "task and proc alignment check");
	fake_dealloc_proc_and_task(proc);

	T_PASS("First proc lifecycle test");
}
