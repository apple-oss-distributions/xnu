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
/*
 * Purgeable spelling rules
 * It is believed that the correct spelling is
 * { 'p', 'u', 'r', 'g', 'e', 'a', 'b', 'l', 'e' }.
 * However, there is one published API that likes to spell it without the
 * first 'e', vm_purgable_control(). Since we can't change that API,
 * here are the rules.
 * All qualifiers defined in vm_purgable.h are spelled without the e.
 * All other qualifiers are spelled with the e.
 * Right now, there are remains of the wrong spelling throughout the code,
 * vm_object_t.purgable for example. We expect to change these on occasion.
 */

#ifndef __VM_PURGEABLE_XNU__
#define __VM_PURGEABLE_XNU__

#ifdef XNU_KERNEL_PRIVATE

#include <kern/queue.h>

/* the object purger. purges the next eligible object from memory. */
/* returns TRUE if an object was purged, otherwise FALSE. */
boolean_t vm_purgeable_object_purge_one(int force_purge_below_group, int flags);

/* statistics for purgable objects in all queues */
void vm_purgeable_stats(vm_purgeable_info_t info, task_t target_task);

#if DEVELOPMENT || DEBUG
/* statistics for purgeable object usage in all queues for a task */
kern_return_t vm_purgeable_account(task_t task, pvm_account_info_t acnt_info);
#endif /* DEVELOPMENT || DEBUG */

uint64_t vm_purgeable_purge_task_owned(task_t task);


#endif /* XNU_KERNEL_PRIVATE */

#endif  /* __VM_PURGEABLE_XNU__ */
