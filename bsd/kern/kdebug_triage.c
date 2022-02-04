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

struct kd_ctrl_page_t kd_ctrl_page_triage = {
	.kds_free_list = {.raw = KDS_PTR_NULL},
	.mode = KDEBUG_MODE_TRIAGE,
	.kdebug_events_per_storage_unit = TRIAGE_EVENTS_PER_STORAGE_UNIT,
	.kdebug_min_storage_units_per_cpu = TRIAGE_MIN_STORAGE_UNITS_PER_CPU,
	.kdebug_kdcopybuf_count = TRIAGE_KDCOPYBUF_COUNT,
	.kdebug_kdcopybuf_size = TRIAGE_KDCOPYBUF_SIZE,
	.kdebug_flags = KDBG_DEBUGID_64,
	.kdebug_slowcheck = SLOW_NOLOG,
	.oldest_time = 0
};

struct kd_data_page_t kd_data_page_triage = {
	.nkdbufs = 0,
	.n_storage_units = 0,
	.n_storage_threshold = 0,
	.n_storage_buffer = 0,
	.kdbip = NULL,
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
create_buffers_triage(bool early_trace)
{
	int error = 0;
	int events_per_storage_unit, min_storage_units_per_cpu;

	if (kd_ctrl_page_triage.kdebug_flags & KDBG_BUFINIT) {
		panic("create_buffers_triage shouldn't be called once we have inited the triage system.");
	}

	events_per_storage_unit = kd_ctrl_page_triage.kdebug_events_per_storage_unit;
	min_storage_units_per_cpu = kd_ctrl_page_triage.kdebug_min_storage_units_per_cpu;

	kd_ctrl_page_triage.kdebug_cpus = kdbg_cpu_count(early_trace);
	kd_ctrl_page_triage.kdebug_iops = NULL;

	if (kd_data_page_triage.nkdbufs < (kd_ctrl_page_triage.kdebug_cpus * events_per_storage_unit * min_storage_units_per_cpu)) {
		kd_data_page_triage.n_storage_units = kd_ctrl_page_triage.kdebug_cpus * min_storage_units_per_cpu;
	} else {
		kd_data_page_triage.n_storage_units = kd_data_page_triage.nkdbufs / events_per_storage_unit;
	}

	kd_data_page_triage.nkdbufs = kd_data_page_triage.n_storage_units * events_per_storage_unit;

	kd_data_page_triage.kd_bufs = NULL;

	error = create_buffers(&kd_ctrl_page_triage, &kd_data_page_triage, VM_KERN_MEMORY_TRIAGE);

	if (!error) {
		kd_ctrl_page_triage.oldest_time = mach_continuous_time();
		kd_ctrl_page_triage.enabled = 1;
		kd_data_page_triage.n_storage_threshold = kd_data_page_triage.n_storage_units / 2;
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

static void
kernel_triage_convert_to_string(uint64_t debugid, char *buf)
{
	if (buf == NULL) {
		return;
	}

	int subsystem = KDBG_TRIAGE_EXTRACT_CLASS(debugid);
	size_t prefixlen, msglen;

	if (subsystem <= KDBG_TRIAGE_SUBSYS_MAX) {
		switch (subsystem) {
		case KDBG_TRIAGE_SUBSYS_VM:
		{
			prefixlen = strlen(*vm_triage_strings[0]);
			strlcpy(buf, (const char*)(*vm_triage_strings[0]), prefixlen + 1); /* we'll overwrite NULL with rest of string below */

			int strindx = KDBG_TRIAGE_EXTRACT_CODE(debugid);
			if (strindx >= 1) { /* 0 is reserved for prefix */
				if (strindx < VM_MAX_TRIAGE_STRINGS) {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(*vm_triage_strings[strindx]) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, (const char*)(*vm_triage_strings[strindx]), msglen);
				} else {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
				}
			} else {
				msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
				strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
			}
			break;
		}

		case KDBG_TRIAGE_SUBSYS_CLUSTER:
		{
			prefixlen = strlen(*cluster_triage_strings[0]);
			strlcpy(buf, (const char*)(*cluster_triage_strings[0]), prefixlen + 1); /* we'll overwrite NULL with rest of string below */

			int strindx = KDBG_TRIAGE_EXTRACT_CODE(debugid);
			if (strindx >= 1) { /* 0 is reserved for prefix */
				if (strindx < CLUSTER_MAX_TRIAGE_STRINGS) {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(*cluster_triage_strings[strindx]) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, (const char*)(*cluster_triage_strings[strindx]), msglen);
				} else {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
				}
			} else {
				msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
				strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
			}
			break;
		}
		case KDBG_TRIAGE_SUBSYS_SHARED_REGION:
		{
			prefixlen = strlen(*shared_region_triage_strings[0]);
			strlcpy(buf, (const char*)(*shared_region_triage_strings[0]), prefixlen + 1); /* we'll overwrite NULL with rest of string below */

			int strindx = KDBG_TRIAGE_EXTRACT_CODE(debugid);
			if (strindx >= 1) { /* 0 is reserved for prefix */
				if (strindx < SHARED_REGION_MAX_TRIAGE_STRINGS) {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(*shared_region_triage_strings[strindx]) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, (const char*)(*shared_region_triage_strings[strindx]), msglen);
				} else {
					msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
					strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
				}
			} else {
				msglen = MIN(KDBG_TRIAGE_MAX_STRLEN - prefixlen, strlen(ktriage_error_index_invalid_str) + 1); /* incl. NULL termination */
				strlcpy(buf + prefixlen, ktriage_error_index_invalid_str, msglen);
			}
			break;
		}
		default:
			break;
		}
		;
	} else {
		msglen = MIN(KDBG_TRIAGE_MAX_STRLEN, strlen(ktriage_error_subsyscode_invalid_str) + 1);  /* incl. NULL termination */
		strlcpy(buf, ktriage_error_subsyscode_invalid_str, msglen);
	}

	return;
}

void
kernel_triage_record(
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
	 * that is set in kd_ctrl_page_triage (on LP64 only).
	 */
	assert(kd_ctrl_page_triage.kdebug_flags & KDBG_DEBUGID_64);

	kd_rec.debugid = 0;
	kd_rec.arg4 = (uintptr_t)debugid;

	kd_rec.arg1 = arg;
	kd_rec.arg2 = 0;
	kd_rec.arg3 = 0;
	kd_rec.arg5 = (uintptr_t)thread_id;

	kernel_debug_write(&kd_ctrl_page_triage,
	    &kd_data_page_triage,
	    kd_rec);
}

void
kernel_triage_extract(
	uint64_t thread_id,
	void *buf,
	uint32_t bufsz)
{
	size_t i, record_bytes, record_cnt, record_bufsz;
	void *record_buf;
	void *local_buf;

	if (thread_id == 0 || buf == NULL || bufsz < KDBG_TRIAGE_MAX_STRLEN) {
		return;
	}

	local_buf = buf;
	bzero(local_buf, bufsz);

	record_bytes = record_bufsz = kd_data_page_triage.nkdbufs * sizeof(kd_buf);
	record_buf = kalloc_data(record_bufsz, Z_WAITOK);

	ktriage_lock();
	int ret = kernel_debug_read(&kd_ctrl_page_triage,
	    &kd_data_page_triage,
	    (user_addr_t) record_buf, &record_bytes, NULL, NULL, 0);
	ktriage_unlock();

	if (ret) {
		printf("kernel_triage_extract: kernel_debug_read failed with %d\n", ret);
		kfree_data(record_buf, record_bufsz);
		record_buf = NULL;
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
			kernel_triage_convert_to_string(kd->arg4, local_buf);
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
	record_buf = NULL;
}


/* KDBG_TRIAGE_CODE_* section */
/* VM begin */

const char *vm_triage_strings[VM_MAX_TRIAGE_STRINGS][KDBG_TRIAGE_MAX_STRLEN] =
{
	{"VM - "}, /* VM message prefix */
	{"Didn't get back data for this file\n"}, /* KDBG_TRIAGE_VM_NO_DATA */
	{"A memory corruption was found in executable text\n"}, /* KDBG_TRIAGE_VM_TEXT_CORRUPTION */
	{"Found no valid range containing this address\n"}, /* KDBG_TRIAGE_VM_ADDRESS_NOT_FOUND */
	{"Fault hit protection failure\n"}, /* KDBG_TRIAGE_VM_PROTECTION_FAILURE */
	{"Fault hit memory shortage\n"}, /* KDBG_TRIAGE_VM_MEMORY_SHORTAGE */
	{"Fault was interrupted\n"}, /* KDBG_TRIAGE_VM_FAULT_INTERRUPTED */
	{"Returned success with no page\n"}, /* KDBG_TRIAGE_VM_SUCCESS_NO_PAGE */
	{"Guard page fault\n"}, /* KDBG_TRIAGE_VM_GUARDPAGE_FAULT */
	{"Fault entered with non-zero preemption level\n"}, /* KDBG_TRIAGE_VM_NONZERO_PREEMPTION_LEVEL */
	{"Waiting on busy page was interrupted\n"}, /* KDBG_TRIAGE_VM_BUSYPAGE_WAIT_INTERRUPTED */
	{"Purgeable object hit an error in fault\n"}, /* KDBG_TRIAGE_VM_PURGEABLE_FAULT_ERROR */
	{"Object has a shadow severed\n"}, /* KDBG_TRIAGE_VM_OBJECT_SHADOW_SEVERED */
	{"Object is not alive\n"}, /* KDBG_TRIAGE_VM_OBJECT_NOT_ALIVE */
	{"Object has no pager\n"}, /* KDBG_TRIAGE_VM_OBJECT_NO_PAGER */
	{"Page has error bit set\n"}, /* KDBG_TRIAGE_VM_PAGE_HAS_ERROR */
	{"Page has restart bit set\n"}, /* KDBG_TRIAGE_VM_PAGE_HAS_RESTART */
	{"Failed a writable mapping of an immutable page\n"}, /* KDBG_TRIAGE_VM_FAILED_IMMUTABLE_PAGE_WRITE */
	{"Failed an executable mapping of a nx page\n"}, /* KDBG_TRIAGE_VM_FAILED_NX_PAGE_EXEC_MAPPING */
	{"pmap_enter failed with resource shortage\n"}, /* KDBG_TRIAGE_VM_PMAP_ENTER_RESOURCE_SHORTAGE */
	{"Compressor offset requested out of range\n"}, /* KDBG_TRIAGE_VM_COMPRESSOR_GET_OUT_OF_RANGE */
	{"Compressor doesn't have this page\n"}, /* KDBG_TRIAGE_VM_COMPRESSOR_GET_NO_PAGE */
	{"Decompressor hit a failure\n"}, /* KDBG_TRIAGE_VM_COMPRESSOR_DECOMPRESS_FAILED */
	{"Compressor failed a blocking pager_get\n"}, /* KDBG_TRIAGE_VM_COMPRESSOR_BLOCKING_OP_FAILED */
	{"Submap disallowed cow on executable range\n"}, /* KDBG_TRIAGE_VM_SUBMAP_NO_COW_ON_EXECUTABLE */
	{"Submap object copy_slowly failed\n"}, /* KDBG_TRIAGE_VM_SUBMAP_COPY_SLOWLY_FAILED */
	{"Submap object copy_strategically failed\n"}, /* KDBG_TRIAGE_VM_SUBMAP_COPY_STRAT_FAILED */
	{"vnode_pager_cluster_read couldn't create a UPL\n"}, /* KDBG_TRIAGE_VM_VNODEPAGER_CLREAD_NO_UPL */
	{"vnode_pagein got a vnode with no ubcinfo\n"}, /* KDBG_TRIAGE_VM_VNODEPAGEIN_NO_UBCINFO */
	{"Filesystem pagein returned an error in vnode_pagein\n"}, /* KDBG_TRIAGE_VM_VNODEPAGEIN_FSPAGEIN_FAIL */
	{"vnode_pagein couldn't create a UPL\n"} /* KDBG_TRIAGE_VM_VNODEPAGEIN_NO_UPL*/
};
/* VM end */

/* Cluster begin */

const char *cluster_triage_strings[CLUSTER_MAX_TRIAGE_STRINGS][KDBG_TRIAGE_MAX_STRLEN] =
{
	{"CL - "}, /* Cluster message prefix */
	{"cluster_pagein past EOF\n"} /* KDBG_TRIAGE_CL_PGIN_PAST_EOF */
};
/* Cluster end */

/* Shared Region begin */

const char *shared_region_triage_strings[SHARED_REGION_MAX_TRIAGE_STRINGS][KDBG_TRIAGE_MAX_STRLEN] =
{
	{"SR - "}, /* Shared region message prefix */
	{"shared_region_pager_data_request couldn't create a upl\n"}, /* KDBG_TRIAGE_SHARED_REGION_NO_UPL */
	{"shared_region_pager_data_request hit a page sliding error\n"} /* KDBG_TRIAGE_SHARED_REGION_SLIDE_ERROR */
};
/* Shared Region end */
/* KDBG_TRIAGE_CODE_* section */
