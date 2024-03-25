/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/kdebug_common.h>
#include <sys/kdebug_triage.h>

#define TRIAGE_KDCOPYBUF_COUNT 128
#define TRIAGE_KDCOPYBUF_SIZE  (TRIAGE_KDCOPYBUF_COUNT * sizeof(kd_buf))

struct kd_control kd_control_triage = {
	.kds_free_list = { .raw = KDS_PTR_NULL },
	.mode = KDEBUG_MODE_TRIAGE,
	.kdebug_events_per_storage_unit = TRIAGE_EVENTS_PER_STORAGE_UNIT,
	.kdebug_min_storage_units_per_cpu = TRIAGE_MIN_STORAGE_UNITS_PER_CPU,
	.kdebug_kdcopybuf_count = TRIAGE_KDCOPYBUF_COUNT,
	.kdebug_kdcopybuf_size = TRIAGE_KDCOPYBUF_SIZE,
	.kdc_flags = KDBG_DEBUGID_64,
	.kdc_emit = KDEMIT_DISABLE,
	.kdc_oldest_time = 0
};

struct kd_buffer kd_buffer_triage = {
	.kdb_event_count = 0,
	.kdb_storage_count = 0,
	.kdb_storage_threshold = 0,
	.kdb_region_count = 0,
	.kdb_info = NULL,
	.kd_bufs = NULL,
	.kdcopybuf = NULL
};


static LCK_GRP_DECLARE(ktriage_grp, "ktriage");
static LCK_MTX_DECLARE(ktriage_mtx, &ktriage_grp);

static void
ktriage_lock(void)
{
	lck_mtx_lock(&ktriage_mtx);
}

static void
ktriage_unlock(void)
{
	lck_mtx_unlock(&ktriage_mtx);
}

int
create_buffers_triage(void)
{
	int error = 0;
	int events_per_storage_unit, min_storage_units_per_cpu;

	if (kd_control_triage.kdc_flags & KDBG_BUFINIT) {
		panic("create_buffers_triage shouldn't be called once we have inited the triage system.");
	}

	events_per_storage_unit = kd_control_triage.kdebug_events_per_storage_unit;
	min_storage_units_per_cpu = kd_control_triage.kdebug_min_storage_units_per_cpu;

	kd_control_triage.kdebug_cpus = kdbg_cpu_count();
	kd_control_triage.alloc_cpus = kd_control_triage.kdebug_cpus;
	kd_control_triage.kdc_coprocs = NULL;

	if (kd_buffer_triage.kdb_event_count < (kd_control_triage.kdebug_cpus * events_per_storage_unit * min_storage_units_per_cpu)) {
		kd_buffer_triage.kdb_storage_count = kd_control_triage.kdebug_cpus * min_storage_units_per_cpu;
	} else {
		kd_buffer_triage.kdb_storage_count = kd_buffer_triage.kdb_event_count / events_per_storage_unit;
	}

	kd_buffer_triage.kdb_event_count = kd_buffer_triage.kdb_storage_count * events_per_storage_unit;

	kd_buffer_triage.kd_bufs = NULL;

	error = create_buffers(&kd_control_triage, &kd_buffer_triage, VM_KERN_MEMORY_TRIAGE);

	if (!error) {
		kd_control_triage.kdc_oldest_time = mach_continuous_time();
		kd_control_triage.enabled = 1;
		kd_buffer_triage.kdb_storage_threshold = kd_buffer_triage.kdb_storage_count / 2;
	}

	return error;
}

__attribute__((noreturn))
void
delete_buffers_triage(void)
{
	/*
	 * If create_buffers() for triage mode fails, it will call the generic delete_buffers() to
	 * free the resources. This specific call should never be invoked because we expect the
	 * triage system to always be ON.
	 */
	panic("delete_buffers_triage shouldn't be invoked");
}

ktriage_strings_t ktriage_subsystems_strings[KDBG_TRIAGE_SUBSYS_MAX + 1];

static void
ktriage_convert_to_string(uint64_t debugid, uintptr_t arg, char *buf, uint32_t bufsz)
{
	if (buf == NULL) {
		return;
	}

	uint8_t subsystem = KDBG_TRIAGE_EXTRACT_CLASS(debugid);

	/* zero subsystem means there is nothing to log */
	if (subsystem == 0) {
		return;
	}

	if (subsystem > KDBG_TRIAGE_SUBSYS_MAX) {
		snprintf(buf, bufsz, "KTriage Error: Subsystem code %u is invalid\n", subsystem);
		return;
	}

	int subsystem_num_strings = ktriage_subsystems_strings[subsystem].num_strings;
	const char **subsystem_strings = ktriage_subsystems_strings[subsystem].strings;
	uint16_t strindx = KDBG_TRIAGE_EXTRACT_CODE(debugid);

	/* fallback if ktriage doesn't know how to parse the given debugid */
	if (subsystem_num_strings < 1 || subsystem_strings == NULL || strindx >= subsystem_num_strings) {
		snprintf(buf, bufsz, "KTriage: Subsystem %d reported %u with argument 0x%lx\n", subsystem, strindx, arg);
		return;
	}

	snprintf(buf, bufsz, "%s(arg = 0x%lx) %s", subsystem_strings[0], arg, subsystem_strings[strindx]);

	return;
}

void
ktriage_record(
	uint64_t thread_id,
	uint64_t debugid,
	uintptr_t arg)
{
	struct kd_record kd_rec;

	if (thread_id == 0) {
		thread_id = thread_tid(current_thread());
	}

	kd_rec.cpu = -1;
	kd_rec.timestamp = -1;

	/*
	 * use 64-bit debugid per our flag KDBG_DEBUGID_64
	 * that is set in kd_control_triage (on LP64 only).
	 */
	assert(kd_control_triage.kdc_flags & KDBG_DEBUGID_64);

	kd_rec.debugid = 0;
	kd_rec.arg4 = (uintptr_t)debugid;

	kd_rec.arg1 = arg;
	kd_rec.arg2 = 0;
	kd_rec.arg3 = 0;
	kd_rec.arg5 = (uintptr_t)thread_id;

	kernel_debug_write(&kd_control_triage,
	    &kd_buffer_triage,
	    kd_rec);
}

void
ktriage_extract(
	uint64_t thread_id,
	void *buf,
	uint32_t bufsz)
{
	size_t i, record_bytes, record_cnt, record_bufsz;
	void *record_buf;
	void *local_buf;
	int ret;


	if (thread_id == 0 || buf == NULL || bufsz < KDBG_TRIAGE_MAX_STRLEN) {
		return;
	}

	local_buf = buf;
	bzero(local_buf, bufsz);

	record_bytes = record_bufsz = kd_buffer_triage.kdb_event_count * sizeof(kd_buf);
	record_buf = kalloc_data(record_bufsz, Z_WAITOK);

	if (record_buf == NULL) {
		ret = ENOMEM;
	} else {
		ktriage_lock();
		ret = kernel_debug_read(&kd_control_triage,
		    &kd_buffer_triage,
		    (user_addr_t) record_buf, &record_bytes, NULL, NULL, 0);
		ktriage_unlock();
	}

	if (ret) {
		printf("ktriage_extract: kernel_debug_read failed with %d\n", ret);
		kfree_data(record_buf, record_bufsz);
		return;
	}

	kd_buf *kd = (kd_buf*) record_buf;
	i = 0;
	record_cnt = record_bytes; /* kernel_debug_read() takes number of bytes that it
	                            * converts to kd_bufs. It processes a max of those and
	                            * returns number of kd_buf read/processed. We use a
	                            * different variable here to make our units clear.
	                            */

	while (i < record_cnt) {
		if (kd->arg5 == (uintptr_t)thread_id) {
			ktriage_convert_to_string(kd->arg4, kd->arg1, local_buf, KDBG_TRIAGE_MAX_STRLEN);
			local_buf = (void *)((uintptr_t)local_buf + KDBG_TRIAGE_MAX_STRLEN);
			bufsz -= KDBG_TRIAGE_MAX_STRLEN;
			if (bufsz < KDBG_TRIAGE_MAX_STRLEN) {
				break;
			}
		}
		i++;
		kd++;
	}

	kfree_data(record_buf, record_bufsz);
}

int
ktriage_register_subsystem_strings(uint8_t subsystem, ktriage_strings_t *subsystem_strings)
{
	if (subsystem == 0 || subsystem > KDBG_TRIAGE_SUBSYS_MAX || subsystem_strings == NULL) {
		return EINVAL;
	}

	ktriage_lock();

	ktriage_subsystems_strings[subsystem].num_strings = subsystem_strings->num_strings;
	ktriage_subsystems_strings[subsystem].strings = subsystem_strings->strings;
	printf("ktriage_register_subsystem_strings: set subsystem %u strings\n", subsystem);

	ktriage_unlock();

	return 0;
}

int
ktriage_unregister_subsystem_strings(uint8_t subsystem)
{
	if (subsystem == 0 || subsystem > KDBG_TRIAGE_SUBSYS_MAX) {
		return EINVAL;
	}

	ktriage_lock();

	if (ktriage_subsystems_strings[subsystem].num_strings == -1) {
		// already unregistered - nothing to do
		ktriage_unlock();
		return 0;
	}

	ktriage_subsystems_strings[subsystem].num_strings = -1;
	ktriage_subsystems_strings[subsystem].strings = NULL;

	ktriage_unlock();

	return 0;
}

/* KDBG_TRIAGE_CODE_* section */
/* VM begin */

const char *vm_triage_strings[] =
{
	[KDBG_TRIAGE_VM_PREFIX] = "VM - ",
	[KDBG_TRIAGE_VM_NO_DATA] = "Didn't get back data for this file\n",
	[KDBG_TRIAGE_VM_TEXT_CORRUPTION] = "A memory corruption was found in executable text\n",
	[KDBG_TRIAGE_VM_ADDRESS_NOT_FOUND] = "Found no valid range containing this address\n",
	[KDBG_TRIAGE_VM_PROTECTION_FAILURE] = "Fault hit protection failure\n",
	[KDBG_TRIAGE_VM_FAULT_MEMORY_SHORTAGE] = "VM Fault hit memory shortage\n",
	[KDBG_TRIAGE_VM_FAULT_COPY_MEMORY_SHORTAGE] = "vm_fault_copy hit memory shortage\n",
	[KDBG_TRIAGE_VM_FAULT_OBJCOPYSLOWLY_MEMORY_SHORTAGE] = "vm_object_copy_slowly fault hit memory shortage\n",
	[KDBG_TRIAGE_VM_FAULT_OBJIOPLREQ_MEMORY_SHORTAGE] = "vm_object_iopl_request fault hit memory shortage\n",
	[KDBG_TRIAGE_VM_FAULT_INTERRUPTED] = "Fault was interrupted\n",
	[KDBG_TRIAGE_VM_SUCCESS_NO_PAGE] = "Returned success with no page\n",
	[KDBG_TRIAGE_VM_GUARDPAGE_FAULT] = "Guard page fault\n",
	[KDBG_TRIAGE_VM_NONZERO_PREEMPTION_LEVEL] = "Fault entered with non-zero preemption level\n",
	[KDBG_TRIAGE_VM_BUSYPAGE_WAIT_INTERRUPTED] = "Waiting on busy page was interrupted\n",
	[KDBG_TRIAGE_VM_PURGEABLE_FAULT_ERROR] = "Purgeable object hit an error in fault\n",
	[KDBG_TRIAGE_VM_OBJECT_SHADOW_SEVERED] = "Object has a shadow severed\n",
	[KDBG_TRIAGE_VM_OBJECT_NOT_ALIVE] = "Object is not alive\n",
	[KDBG_TRIAGE_VM_OBJECT_NO_PAGER] = "Object has no pager\n",
	[KDBG_TRIAGE_VM_OBJECT_NO_PAGER_FORCED_UNMOUNT] = "Object has no pager because the backing vnode was force unmounted\n",
	[KDBG_TRIAGE_VM_OBJECT_NO_PAGER_UNGRAFT] = "Object has no pager because the backing vnode was ungrafted\n",
	[KDBG_TRIAGE_VM_PAGE_HAS_ERROR] = "Page has error bit set\n",
	[KDBG_TRIAGE_VM_PAGE_HAS_RESTART] = "Page has restart bit set\n",
	[KDBG_TRIAGE_VM_FAILED_IMMUTABLE_PAGE_WRITE] = "Failed a writable mapping of an immutable page\n",
	[KDBG_TRIAGE_VM_FAILED_NX_PAGE_EXEC_MAPPING] = "Failed an executable mapping of a nx page\n",
	[KDBG_TRIAGE_VM_PMAP_ENTER_RESOURCE_SHORTAGE] = "pmap_enter retried due to resource shortage\n",
	[KDBG_TRIAGE_VM_COMPRESSOR_GET_OUT_OF_RANGE] = "Compressor offset requested out of range\n",
	[KDBG_TRIAGE_VM_COMPRESSOR_GET_NO_PAGE] = "Compressor doesn't have this page\n",
	[KDBG_TRIAGE_VM_COMPRESSOR_DECOMPRESS_FAILED] = "Decompressor hit a failure\n",
	[KDBG_TRIAGE_VM_SUBMAP_NO_COW_ON_EXECUTABLE] = "Submap disallowed cow on executable range\n",
	[KDBG_TRIAGE_VM_SUBMAP_COPY_SLOWLY_FAILED] = "Submap object copy_slowly failed\n",
	[KDBG_TRIAGE_VM_SUBMAP_COPY_STRAT_FAILED] = "Submap object copy_strategically failed\n",
	[KDBG_TRIAGE_VM_VNODEPAGER_CLREAD_NO_UPL] = "vnode_pager_cluster_read couldn't create a UPL\n",
	[KDBG_TRIAGE_VM_VNODEPAGEIN_NO_UBCINFO] = "vnode_pagein got a vnode with no ubcinfo\n",
	[KDBG_TRIAGE_VM_VNODEPAGEIN_FSPAGEIN_FAIL] = "Filesystem pagein returned an error in vnode_pagein\n",
	[KDBG_TRIAGE_VM_VNODEPAGEIN_NO_UPL] = "vnode_pagein couldn't create a UPL\n",
	[KDBG_TRIAGE_VM_ECC_DIRTY] = "Accessed a page that has uncorrected ECC error\n",
	[KDBG_TRIAGE_VM_ECC_CLEAN] = "Clean page had an uncorrected ECC error\n",
	[KDBG_TRIAGE_VM_COPYOUTMAP_SAMEMAP_ERROR] = "vm_copyout_map failed with same src-dest map\n",
	[KDBG_TRIAGE_VM_COPYOUTMAP_DIFFERENTMAP_ERROR] = "vm_copyout_map failed with different src-dest map\n",
	[KDBG_TRIAGE_VM_COPYOVERWRITE_FULL_NESTED_ERROR] = "vm_map_copy_overwrite_nested failed when trying full copy\n",
	[KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_NESTED_ERROR] = "vm_map_copy_overwrite_nested failed when trying partial copy\n",
	[KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_HEAD_NESTED_ERROR] = "vm_map_copy_overwrite_nested failed when trying misaligned head copy\n",
	[KDBG_TRIAGE_VM_COPYOVERWRITE_PARTIAL_TAIL_NESTED_ERROR] = "vm_map_copy_overwrite_nested failed when trying misaligned tail copy\n",
	[KDBG_TRIAGE_VM_COPYOUT_INTERNAL_SIZE_ERROR] = "vm_map_copyout_internal failed due to bad size\n",
	[KDBG_TRIAGE_VM_COPYOUT_KERNEL_BUFFER_ERROR] = "vm_map_copyout_kernel_buffer failed\n",
	[KDBG_TRIAGE_VM_COPYOUT_INTERNAL_ADJUSTING_ERROR] = "vm_map_copyout_internal failed when trying to adjust src-dest params\n",
	[KDBG_TRIAGE_VM_COPYOUT_INTERNAL_SPACE_ERROR] = "vm_map_copyout_internal failed because we couldn't locate space\n",
	[KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADFLAGS_ERROR] = "mach_vm_allocate_kernel failed due to bad flags\n",
	[KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADMAP_ERROR] = "mach_vm_allocate_kernel failed due to bad map\n",
	[KDBG_TRIAGE_VM_ALLOCATE_KERNEL_BADSIZE_ERROR] = "mach_vm_allocate_kernel failed due to bad size\n",
	[KDBG_TRIAGE_VM_ALLOCATE_KERNEL_VMMAPENTER_ERROR] = "mach_vm_allocate_kernel failed within call to vm_map_enter\n",
};
/* VM end */

/* Cluster begin */

const char *cluster_triage_strings[] =
{
	[KDBG_TRIAGE_CL_PREFIX] = "CL - ",
	[KDBG_TRIAGE_CL_PGIN_PAST_EOF] = "cluster_pagein past EOF\n",
};
/* Cluster end */

/* Shared Region begin */

const char *shared_region_triage_strings[] =
{
	[KDBG_TRIAGE_SHARED_REGION_PREFIX] = "SR - ",
	[KDBG_TRIAGE_SHARED_REGION_NO_UPL] = "shared_region_pager_data_request couldn't create a upl\n",
	[KDBG_TRIAGE_SHARED_REGION_SLIDE_ERROR] = "shared_region_pager_data_request hit a page sliding error\n",
	[KDBG_TRIAGE_SHARED_REGION_PAGER_MEMORY_SHORTAGE] = "shared_region_pager_data_request hit memory shortage\n",
};
/* Shared Region end */

/* Dyld Pager begin */

const char *dyld_pager_triage_strings[] =
{
	[KDBG_TRIAGE_DYLD_PAGER_PREFIX] = "DP - ",
	[KDBG_TRIAGE_DYLD_PAGER_NO_UPL] = "dyld_pager_data_request couldn't create a upl\n",
	[KDBG_TRIAGE_DYLD_PAGER_MEMORY_SHORTAGE] = "dyld_pager_data_request hit memory shortage\n",
	[KDBG_TRIAGE_DYLD_PAGER_SLIDE_ERROR] = "dyld_pager_data_request hit a page sliding error\n",
	[KDBG_TRIAGE_DYLD_PAGER_CHAIN_OUT_OF_RANGE] = "dyld_pager_data_request chain out of range\n",
	[KDBG_TRIAGE_DYLD_PAGER_SEG_INFO_OUT_OF_RANGE] = "dyld_pager_data_request seg_info out of range\n",
	[KDBG_TRIAGE_DYLD_PAGER_SEG_SIZE_OUT_OF_RANGE] = "dyld_pager_data_request seg->size out of range\n",
	[KDBG_TRIAGE_DYLD_PAGER_SEG_PAGE_CNT_OUT_OF_RANGE] = "dyld_pager_data_request seg->page_count out of range\n",
	[KDBG_TRIAGE_DYLD_PAGER_NO_SEG_FOR_VA] = "dyld_pager_data_request no segment for VA\n",
	[KDBG_TRIAGE_DYLD_PAGER_RANGE_NOT_FOUND] = "dyld_pager_data_request no range for offset\n",
	[KDBG_TRIAGE_DYLD_PAGER_DELTA_TOO_LARGE] = "dyld_pager_data_request delta * 4 > PAGE_SIZE\n",
	[KDBG_TRIAGE_DYLD_PAGER_PAGE_START_OUT_OF_RANGE] = "dyld_pager_data_request segInfo page_start out of range\n",
	[KDBG_TRIAGE_DYLD_PAGER_BAD_POINTER_FMT] = "dyld_pager_data_request unkown pointer format\n",
	[KDBG_TRIAGE_DYLD_PAGER_INVALID_AUTH_KEY] = "dyld_pager_data_request unkown auth key\n",
	[KDBG_TRIAGE_DYLD_PAGER_BIND_ORDINAL] = "dyld_pager_data_request invalid bind ordinal\n",
};
/* Dyld Pager end */

/* Apple Protect Pager begin */

const char *apple_protect_pager_triage_strings[] =
{
	[KDBG_TRIAGE_APPLE_PROTECT_PAGER_PREFIX] = "APP - ",
	[KDBG_TRIAGE_APPLE_PROTECT_PAGER_MEMORY_SHORTAGE] = "apple_protect_pager_data_request hit memory shortage\n",
};
/* Apple Protect Pager end */

/* Fourk Pager begin */

const char *fourk_pager_triage_strings[] =
{
	[KDBG_TRIAGE_FOURK_PAGER_PREFIX] = "FP - ",
	[KDBG_TRIAGE_FOURK_PAGER_MEMORY_SHORTAGE] = "fourk_pager_data_request hit memory shortage\n",
};
/* Fourk Pager end */

/* Corpse section begin */

const char *corpse_triage_strings[] =
{
	[KDBG_TRIAGE_CORPSE_PREFIX] = "Corpse - ",
	[KDBG_TRIAGE_CORPSE_PROC_TOO_BIG] = "Process too big for corpse. Corpse disallowed.\n",
	[KDBG_TRIAGE_CORPSE_FAIL_LIBGMALLOC] = "Process linked against libgmalloc. Corpse disallowed.\n",
	[KDBG_TRIAGE_CORPSE_BLOCKED_JETSAM] = "Jetsams happening in higher bands. Corpse disallowed.\n",
	[KDBG_TRIAGE_CORPSE_LIMIT] = "Too many corpses in flight. Corpse disallowed.\n",
	[KDBG_TRIAGE_CORPSES_DISABLED] = "Corpse disabled on system.\n",
	[KDBG_TRIAGE_CORPSE_DISABLED_FOR_PROC] = "Corpse disabled for this process.\n",
};
/* Corpse section end */

/* subsystems starts at index 1 */
ktriage_strings_t ktriage_subsystems_strings[KDBG_TRIAGE_SUBSYS_MAX + 1] = {
	[KDBG_TRIAGE_SUBSYS_VM]            = {VM_MAX_TRIAGE_STRINGS, vm_triage_strings},
	[KDBG_TRIAGE_SUBSYS_CLUSTER]       = {CLUSTER_MAX_TRIAGE_STRINGS, cluster_triage_strings},
	[KDBG_TRIAGE_SUBSYS_SHARED_REGION] = {SHARED_REGION_MAX_TRIAGE_STRINGS, shared_region_triage_strings},
	[KDBG_TRIAGE_SUBSYS_DYLD_PAGER]    = {DYLD_PAGER_MAX_TRIAGE_STRINGS, dyld_pager_triage_strings},
	[KDBG_TRIAGE_SUBSYS_APPLE_PROTECT_PAGER]    = {APPLE_PROTECT_PAGER_MAX_TRIAGE_STRINGS, apple_protect_pager_triage_strings},
	[KDBG_TRIAGE_SUBSYS_FOURK_PAGER]    = {FOURK_PAGER_MAX_TRIAGE_STRINGS, fourk_pager_triage_strings},

	[KDBG_TRIAGE_SUBSYS_APFS]          = {-1, NULL},
	[KDBG_TRIAGE_SUBSYS_DECMPFS]       = {-1, NULL},
	[KDBG_TRIAGE_SUBSYS_CORPSE]        = {CORPSE_MAX_TRIAGE_STRINGS, corpse_triage_strings},
};

/* KDBG_TRIAGE_CODE_* section */
