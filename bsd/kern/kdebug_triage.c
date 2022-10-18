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

const char *ktriage_error_index_invalid_str = "Error descr index invalid\n";
const char *ktriage_error_subsyscode_invalid_str = "KTriage: Subsystem code invalid\n";
ktriage_strings_t subsystems_triage_strings[KDBG_TRIAGE_SUBSYS_MAX + 1];

static void
ktriage_convert_to_string(uint64_t debugid, char *buf, uint32_t bufsz)
{
	if (buf == NULL) {
		return;
	}

	int subsystem = KDBG_TRIAGE_EXTRACT_CLASS(debugid);

	/* zero subsystem means there is nothing to log */
	if (subsystem == 0) {
		return;
	}

	size_t prefixlen, msglen;
	if (subsystem <= KDBG_TRIAGE_SUBSYS_MAX) {
		int subsystem_num_strings = subsystems_triage_strings[subsystem].num_strings;
		const char **subsystem_strings = subsystems_triage_strings[subsystem].strings;

		prefixlen = strlen(subsystem_strings[0]);
		strlcpy(buf, (const char*)(subsystem_strings[0]), bufsz);

		int strindx = KDBG_TRIAGE_EXTRACT_CODE(debugid);
		if (strindx >= 1) { /* 0 is reserved for prefix */
			if (strindx < subsystem_num_strings) {
				msglen = MIN(bufsz - prefixlen, strlen(subsystem_strings[strindx]) + 1); /* incl. NULL termination */
				strlcpy(buf + prefixlen, (subsystem_strings[strindx]), msglen);
			} else {
				msglen = MIN(bufsz - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
				strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
			}
		} else {
			msglen = MIN(bufsz - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
			strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
		}
	} else {
		msglen = MIN(bufsz, strlen(ktriage_error_subsyscode_invalid_str) + 1);  /* incl. NULL termination */
		strlcpy(buf, ktriage_error_subsyscode_invalid_str, msglen);
	}

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
			ktriage_convert_to_string(kd->arg4, local_buf, KDBG_TRIAGE_MAX_STRLEN);
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
	[KDBG_TRIAGE_DYLD_PAGER_SLIDE_ERROR] = "dyld_pager_data_request hit a page sliding error\n",
	[KDBG_TRIAGE_DYLD_PAGER_MEMORY_SHORTAGE] = "dyld_pager_data_request hit memory shortage\n",
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

/* APFS begin */

const char *apfs_triage_strings[] =
{
	[KDBG_TRIAGE_APFS_PREFIX] = "APFS - ",
	[KDBG_TRIAGE_APFS_PAGEIN_NOT_ALLOWED] = "The inode's protection class does not allow page in\n",
	[KDBG_TRIAGE_APFS_INODE_DEAD] = "The inode has been deleted\n",
	[KDBG_TRIAGE_APFS_INODE_RAW_ENCRYPTED] = "The inode is raw encrypted, file page in is prohibited\n",
	[KDBG_TRIAGE_APFS_INODE_OF_RAW_DEVICE] = "The inode backing a raw device, file IO is prohibited\n",
	[KDBG_TRIAGE_APFS_DISALLOW_READS] = "The APFS_DISALLOW_READS flag is turned on (dataless snapshot mount)\n",
	[KDBG_TRIAGE_APFS_XATTR_GET_FAILED] = "Could not get namedstream xattr\n",
	[KDBG_TRIAGE_APFS_NO_NAMEDSTREAM_PARENT_INODE] = "Could not get namedstream parent inode\n",
	[KDBG_TRIAGE_APFS_INVALID_OFFSET] = "Invalid offset\n",
	[KDBG_TRIAGE_APFS_COLLECT_HASH_RECORDS] = "Failed collecting all hash records\n",
	[KDBG_TRIAGE_APFS_INVALID_FILE_INFO] = "Encountered an invalid file info\n",
	[KDBG_TRIAGE_APFS_NO_HASH_RECORD] = "Verification context for inode is empty\n",
	[KDBG_TRIAGE_APFS_DATA_HASH_MISMATCH] = "Encountered a data hash mismatch\n",
	[KDBG_TRIAGE_APFS_COMPRESSED_DATA_HASH_MISMATCH] = "Encountered a compressed data hash mismatch\n",
};
/* APFS end */

/* subsystems starts at index 1 */
ktriage_strings_t subsystems_triage_strings[KDBG_TRIAGE_SUBSYS_MAX + 1] = {
	[KDBG_TRIAGE_SUBSYS_VM]            = {VM_MAX_TRIAGE_STRINGS, vm_triage_strings},
	[KDBG_TRIAGE_SUBSYS_CLUSTER]       = {CLUSTER_MAX_TRIAGE_STRINGS, cluster_triage_strings},
	[KDBG_TRIAGE_SUBSYS_SHARED_REGION] = {SHARED_REGION_MAX_TRIAGE_STRINGS, shared_region_triage_strings},
	[KDBG_TRIAGE_SUBSYS_DYLD_PAGER]    = {DYLD_PAGER_MAX_TRIAGE_STRINGS, dyld_pager_triage_strings},
	[KDBG_TRIAGE_SUBSYS_APPLE_PROTECT_PAGER]    = {APPLE_PROTECT_PAGER_MAX_TRIAGE_STRINGS, apple_protect_pager_triage_strings},
	[KDBG_TRIAGE_SUBSYS_FOURK_PAGER]    = {FOURK_PAGER_MAX_TRIAGE_STRINGS, fourk_pager_triage_strings},
	[KDBG_TRIAGE_SUBSYS_APFS]          = {APFS_MAX_TRIAGE_STRINGS, apfs_triage_strings},
};
/* KDBG_TRIAGE_CODE_* section */
