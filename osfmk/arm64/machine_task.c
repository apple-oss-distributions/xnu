/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <kern/task.h>
#include <kern/thread.h>
#include <arm/misc_protos.h>

#include <IOKit/IOBSD.h>


extern zone_t ads_zone;

kern_return_t
machine_task_set_state(
	task_t task,
	int flavor,
	thread_state_t state,
	mach_msg_type_number_t state_count)
{
	switch (flavor) {
	case ARM_DEBUG_STATE:
	{
		arm_legacy_debug_state_t *tstate = (arm_legacy_debug_state_t *) state;
		if (task_has_64Bit_data(task) ||
		    (state_count != ARM_LEGACY_DEBUG_STATE_COUNT) ||
		    (!debug_legacy_state_is_valid(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc_flags(ads_zone,
			    Z_WAITOK | Z_NOFAIL);
		}

		copy_legacy_debug_state(tstate, (arm_legacy_debug_state_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE32:
	{
		arm_debug_state32_t *tstate = (arm_debug_state32_t *) state;
		if (task_has_64Bit_data(task) ||
		    (state_count != ARM_DEBUG_STATE32_COUNT) ||
		    (!debug_state_is_valid32(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc_flags(ads_zone,
			    Z_WAITOK | Z_NOFAIL);
		}

		copy_debug_state32(tstate, (arm_debug_state32_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE64:
	{
		arm_debug_state64_t *tstate = (arm_debug_state64_t *) state;

		if ((!task_has_64Bit_data(task)) ||
		    (state_count != ARM_DEBUG_STATE64_COUNT) ||
		    (!debug_state_is_valid64(tstate))) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			task->task_debug = zalloc_flags(ads_zone,
			    Z_WAITOK | Z_NOFAIL);
		}

		copy_debug_state64(tstate, (arm_debug_state64_t *) task->task_debug, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */

		return KERN_SUCCESS;
	}
	case THREAD_STATE_NONE:         /* Using this flavor to clear task_debug */
	{
		if (task->task_debug != NULL) {
			zfree(ads_zone, task->task_debug);
			task->task_debug = NULL;

			return KERN_SUCCESS;
		}
		return KERN_FAILURE;
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}

	return KERN_FAILURE;
}

kern_return_t
machine_task_get_state(task_t task,
    int flavor,
    thread_state_t state,
    mach_msg_type_number_t *state_count)
{
	switch (flavor) {
	case ARM_DEBUG_STATE:
	{
		arm_legacy_debug_state_t *tstate = (arm_legacy_debug_state_t *) state;

		if (task_has_64Bit_data(task) || (*state_count != ARM_LEGACY_DEBUG_STATE_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_legacy_debug_state((arm_legacy_debug_state_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE32:
	{
		arm_debug_state32_t *tstate = (arm_debug_state32_t *) state;

		if (task_has_64Bit_data(task) || (*state_count != ARM_DEBUG_STATE32_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state32((arm_debug_state32_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	case ARM_DEBUG_STATE64:
	{
		arm_debug_state64_t *tstate = (arm_debug_state64_t *) state;

		if ((!task_has_64Bit_data(task)) || (*state_count != ARM_DEBUG_STATE64_COUNT)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (task->task_debug == NULL) {
			bzero(state, sizeof(*tstate));
		} else {
			copy_debug_state64((arm_debug_state64_t*) task->task_debug, tstate, FALSE); /* FALSE OR TRUE doesn't matter since we are ignoring it for arm */
		}

		return KERN_SUCCESS;
	}
	default:
	{
		return KERN_INVALID_ARGUMENT;
	}
	}
	return KERN_FAILURE;
}

void
machine_task_terminate(task_t task)
{
	if (task) {
		void *task_debug;
		task_debug = task->task_debug;
		if (task_debug != NULL) {
			task->task_debug = NULL;
			zfree(ads_zone, task_debug);
		}
	}
}


kern_return_t
machine_thread_inherit_taskwide(
	thread_t thread,
	task_t parent_task)
{
	if (parent_task->task_debug) {
		int flavor;
		mach_msg_type_number_t count;

		flavor = task_has_64Bit_data(parent_task) ? ARM_DEBUG_STATE64 : ARM_DEBUG_STATE32;
		count = task_has_64Bit_data(parent_task) ? ARM_DEBUG_STATE64_COUNT : ARM_DEBUG_STATE32_COUNT;

		return machine_thread_set_state(thread, flavor, parent_task->task_debug, count);
	}

	return KERN_SUCCESS;
}


void
machine_task_init(__unused task_t new_task,
    __unused task_t parent_task,
    __unused boolean_t memory_inherit)
{
}

/*
 * machine_task_process_signature
 *
 * Called to allow code signature dependent adjustments to the task
 * state. It is not safe to assume that this function is only called
 * once per task, as a signature may be attached later.
 *
 * On error, this function should point error_msg to a static error
 * string (the caller will not free it).
 */
kern_return_t
machine_task_process_signature(
	task_t task,
	uint32_t const __unused platform,
	uint32_t const __unused sdk,
	char const ** __unused error_msg)
{
	assert(error_msg != NULL);

	kern_return_t kr = KERN_SUCCESS;

	bool const x18_entitled =
	    IOTaskHasEntitlement(task, "com.apple.private.custom-x18-abi") ||
	    IOTaskHasEntitlement(task, "com.apple.private.uexc");

#if !__ARM_KERNEL_PROTECT__
	task->preserve_x18 = x18_entitled;

	/*
	 * Temporary override for tasks before macOS 13.
	 * Those were allowed to use x18 for their purposes on Apple Silicon.
	 */

	if (platform == PLATFORM_MACOS && sdk < 0xd0000) {
		task->preserve_x18 = true;
	}
#else /* !__ARM_KERNEL_PROTECT__ */
	if (x18_entitled) {
		/*
		 * This *will* make you sad, because it means you are
		 * trying to use x18 on a device where that's just not
		 * possible. As these are private entitlements, we can
		 * prevent confusing damage now.
		 */

		*error_msg = "process has entitlement that indicates custom x18 ABI usage, not available on this device";
		kr = KERN_FAILURE;
	}
#endif /* !__ARM_KERNEL_PROTECT__ */

	return kr;
}
