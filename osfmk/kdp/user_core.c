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

#include <kdp/processor_core.h>
#include <kdp/kdp_core.h>
#include <kdp/core_notes.h>
#include <kdp/kdp_common.h>
#include <vm/vm_map.h>

kern_return_t
user_dump_init(void *refcon, void *context)
{
	kern_return_t err = KERN_NODE_DOWN;
	struct kern_userspace_coredump_context * uccontext = refcon;

	if (!uccontext) {
		kern_coredump_log(context, "%s: context allocation failure\n", __func__);
		goto finish;
	}

	if (!uccontext->task) {
		kern_coredump_log(context, "%s: no task is set\n", __func__);
		goto finish;
	}

	// Skip inactive tasks
	if (!uccontext->task->active) {
		kern_coredump_log(context, "%s: skipping inactive task\n", __func__);
		goto finish;
	}

	// If task is locked, it is unsafe to iterate over its threads
	if (kdp_task_is_locked(uccontext->task)) {
		kern_coredump_log(context, "%s: skipping locked task\n", __func__);
		goto finish;
	}

	// If vm map is locked exclusively, it is unsafe to traverse vm mappings
	if (kdp_vm_map_is_acquired_exclusive(uccontext->task->map)) {
		kern_coredump_log(context, "%s: skipping task with locked vm map\n", __func__);
		goto finish;
	}

	err = KERN_SUCCESS;

finish:
	return err;
}

struct user_dump_preflight_context {
	struct kern_userspace_coredump_context * uccontext;
	uint32_t region_count;
	uint64_t dumpable_bytes;
};

static kern_return_t
user_dump_map_traverse_preflight_callback(vm_offset_t start, vm_offset_t end, void *context)
{
	struct user_dump_preflight_context *udc_preflight = context;

	assert(start < end);

	udc_preflight->region_count++;
	udc_preflight->dumpable_bytes += (end - start);

	return KERN_SUCCESS;
}

kern_return_t
user_dump_save_summary(void *refcon, core_save_summary_cb callback, void *context)
{
	struct kern_userspace_coredump_context * uccontext = refcon;
	struct user_dump_preflight_context udc_preflight = {.uccontext = uccontext, .region_count = 0, .dumpable_bytes = 0};
	uint64_t thread_state_size = 0, thread_count = 0;
	kern_return_t ret;

	ret = kdp_traverse_mappings(uccontext->task,
	    KDP_FAULT_FLAGS_ENABLE_FAULTING,
	    KDP_TRAVERSE_MAPPINGS_FLAGS_NONE,
	    user_dump_map_traverse_preflight_callback,
	    &udc_preflight);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "%s: vm map traversal failed: %d\n", __func__, ret);
		return ret;
	}

	kern_collect_userth_state_size(uccontext->task, &thread_count, &thread_state_size);
	return callback(udc_preflight.region_count, udc_preflight.dumpable_bytes,
	           thread_count, thread_state_size, 0, context);
}

struct user_dump_send_seg_desc_context {
	core_save_segment_descriptions_cb callback;
	void *context;
};

static kern_return_t
user_dump_map_traverse_send_segdesc_callback(vm_offset_t start, vm_offset_t end, void *context)
{
	struct user_dump_send_seg_desc_context *uds_context = context;

	assert(start < end);

	uint64_t seg_start = (uint64_t) start;
	uint64_t seg_end = (uint64_t) end;

	return uds_context->callback(seg_start, seg_end, uds_context->context);
}

kern_return_t
user_dump_save_seg_descriptions(void *refcon, core_save_segment_descriptions_cb callback, void *context)
{
	struct kern_userspace_coredump_context * uccontext = refcon;
	struct user_dump_send_seg_desc_context uds_context;
	uds_context.callback = callback;
	uds_context.context = context;
	kern_return_t ret = kdp_traverse_mappings(uccontext->task,
	    KDP_FAULT_FLAGS_ENABLE_FAULTING,
	    KDP_TRAVERSE_MAPPINGS_FLAGS_NONE,
	    user_dump_map_traverse_send_segdesc_callback,
	    &uds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "%s: vm map traversal failed: %d\n", __func__, ret);
		return ret;
	}
	return KERN_SUCCESS;
}

kern_return_t
user_dump_save_thread_state(void *refcon, void *buf, core_save_thread_state_cb callback, void *context)
{
	struct kern_userspace_coredump_context * uccontext = refcon;
	uint64_t thread_state_size = 0, thread_count = 0;
	thread_t thread = THREAD_NULL;

	kern_collect_userth_state_size(uccontext->task, &thread_count, &thread_state_size);
	queue_iterate(&uccontext->task->threads, thread, thread_t, task_threads) {
		kern_collect_userth_state(uccontext->task, thread, buf, thread_state_size);

		kern_return_t ret = callback(buf, context);
		if (ret != KERN_SUCCESS) {
			return ret;
		}
	}

	return KERN_SUCCESS;
}

kern_return_t
user_dump_save_sw_vers_detail(void *refcon, core_save_sw_vers_detail_cb callback, void *context)
{
	struct kern_userspace_coredump_context * uccontext = refcon;
	uint64_t dyld_load_address;
	uuid_t dyld_uuid;
	size_t task_page_size;

	/*
	 * For user coredumps we want the dyld UUID to be stored in the main bin spec LC_NOTE
	 */
	kern_return_t ret = kdp_task_dyld_info(uccontext->task, KDP_FAULT_FLAGS_ENABLE_FAULTING, &dyld_load_address, dyld_uuid, &task_page_size);
	if (ret != KERN_SUCCESS) {
		return ret;
	}
	return callback(dyld_load_address, dyld_uuid, bit_log2(task_page_size), context);
}

struct user_dump_send_segdata_context {
	core_save_segment_data_cb callback;
	void *context;
};

static kern_return_t
user_dump_map_traverse_send_segdata_callback(vm_offset_t physstart, vm_offset_t physend, void * context)
{
	struct user_dump_send_segdata_context * uds_context = context;

	assert(physstart < physend);

	void * vphysstart = (void *) phystokv(physstart);
	return uds_context->callback(vphysstart, (uint64_t)((uintptr_t)physend - (uintptr_t)physstart), uds_context->context);
}

kern_return_t
user_dump_save_segment_data(void *refcon, core_save_segment_data_cb callback, void *context)
{
	struct kern_userspace_coredump_context * uccontext = refcon;
	struct user_dump_send_segdata_context uds_context = {.callback = callback, .context = context};
	kern_return_t ret = kdp_traverse_mappings(uccontext->task,
	    KDP_FAULT_FLAGS_ENABLE_FAULTING,
	    KDP_TRAVERSE_MAPPINGS_FLAGS_PHYSICAL,
	    user_dump_map_traverse_send_segdata_callback,
	    &uds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "%s: vm map traversal failed: %d\n", __func__, ret);
		return ret;
	}

	return KERN_SUCCESS;
}


/*
 * Add a LC_NOTE to the core to indicate that it was created during a kernel panic.
 */

extern char     kernel_uuid_string[];

kern_return_t
user_dump_save_note_summary(void *refcon __unused, core_save_note_summary_cb callback, void *context)
{
	return callback(2 /* two LC_NOTE */, sizeof(panic_context_note_t) + sizeof(addrable_bits_note_t), context);
}

kern_return_t
user_dump_save_note_descriptions(void *refcon __unused, core_save_note_descriptions_cb callback, void *context)
{
	callback(PANIC_CONTEXT_DATA_OWNER, sizeof(panic_context_note_t), context);
	return callback(ADDRABLE_BITS_DATA_OWNER, sizeof(addrable_bits_note_t), context);
}

kern_return_t
user_dump_save_note_data(void *refcon, core_save_note_data_cb callback, void *context)
{
	panic_context_note_t note;
	strlcpy(&note.kernel_uuid_string[0], kernel_uuid_string, sizeof(uuid_string_t));

	callback(&note, sizeof(panic_context_note_t), context);

	struct kern_userspace_coredump_context *ucontext = refcon;
	addrable_bits_note_t note_ab = {
		.version = ADDRABLE_BITS_VER,
		.addressing_bits = pmap_user_va_bits(get_task_pmap(ucontext->task)),
		.unused = 0
	};

	return callback(&note_ab, sizeof(addrable_bits_note_t), context);
}
