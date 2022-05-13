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

#if defined(CONFIG_KDP_INTERACTIVE_DEBUGGING) && (defined(__arm__) || defined(__arm64__))

#include <mach/mach_types.h>
#include <IOKit/IOTypes.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>
#include <arm/cpuid.h>
#include <arm/caches_internal.h>
#include <pexpert/arm/consistent_debug.h>

#if !defined(ROUNDUP)
#define ROUNDUP(a, b) (((a) + ((b) - 1)) & (~((b) - 1)))
#endif

#if !defined(ROUNDDOWN)
#define ROUNDDOWN(a, b) ((a) & ~((b) - 1))
#endif

#define KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS 2
#define KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE 64 * 1024
#define KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS 30

/*
 * Astris can read up to 4064 bytes at a time over
 * the probe, so we should try to make our buffer
 * size a multiple of this to make reads by astris
 * (the bottleneck) most efficient.
 */
#define OPTIMAL_ASTRIS_READSIZE 4064

/*
 * xnu shared memory hardware debugger support
 *
 * A hardware debugger can connect, read the consistent debug
 * header to determine the physical location of the handshake
 * structure and communicate using commands in the structure as
 * defined below.
 *
 * Currently used for sending compressed coredumps to
 * astris.
 */
struct xnu_hw_shmem_dbg_command_info {
	volatile uint32_t xhsdci_status;
	uint32_t xhsdci_seq_no;
	volatile uint64_t xhsdci_buf_phys_addr;
	volatile uint32_t xhsdci_buf_data_length;
	/* end of version 0 structure */
	uint64_t xhsdci_coredump_total_size_uncomp;
	uint64_t xhsdci_coredump_total_size_sent_uncomp;
	uint32_t xhsdci_page_size;
} __attribute__((packed));

#define CUR_XNU_HWSDCI_STRUCT_VERS 1

#define XHSDCI_STATUS_NONE              0 /* default status */
#define XHSDCI_STATUS_KERNEL_BUSY       1 /* kernel is busy with other procedure */
#define XHSDCI_STATUS_KERNEL_READY      2 /* kernel ready to begin command */
#define XHSDCI_COREDUMP_BEGIN           3 /* indicates hardware debugger is ready to begin consuming coredump info */
#define XHSDCI_COREDUMP_BUF_READY       4 /* indicates the kernel has populated the buffer */
#define XHSDCI_COREDUMP_BUF_EMPTY       5 /* indicates hardware debugger is done consuming the current data */
#define XHSDCI_COREDUMP_STATUS_DONE     6 /* indicates last compressed data is in buffer */
#define XHSDCI_COREDUMP_ERROR           7 /* indicates an error was encountered */
#define XHSDCI_COREDUMP_REMOTE_DONE     8 /* indicates that hardware debugger is done */

struct kdp_hw_shmem_dbg_buf_elm {
	vm_offset_t khsd_buf;
	uint32_t    khsd_data_length;
	STAILQ_ENTRY(kdp_hw_shmem_dbg_buf_elm) khsd_elms;
};

struct shmem_stage_data {
	uint32_t seq_no;
	uint64_t contact_deadline;
	uint64_t contact_deadline_interval;

	struct kdp_hw_shmem_dbg_buf_elm *currently_filling_buf;
	struct kdp_hw_shmem_dbg_buf_elm *currently_flushing_buf;
};

static uint32_t kdp_hw_shmem_dbg_bufsize;
static struct xnu_hw_shmem_dbg_command_info *hwsd_info = NULL;
static STAILQ_HEAD(, kdp_hw_shmem_dbg_buf_elm) free_hw_shmem_dbg_bufs =
    STAILQ_HEAD_INITIALIZER(free_hw_shmem_dbg_bufs);
static STAILQ_HEAD(, kdp_hw_shmem_dbg_buf_elm) hw_shmem_dbg_bufs_to_flush =
    STAILQ_HEAD_INITIALIZER(hw_shmem_dbg_bufs_to_flush);

/*
 * Whenever we start a coredump, make sure the buffers
 * are all on the free queue and the state is as expected.
 * The buffers may have been left in a different state if
 * a previous coredump attempt failed.
 */
static void
shmem_stage_reset(struct kdp_output_stage *stage)
{
	struct shmem_stage_data *data = (struct shmem_stage_data *) stage->kos_data;
	struct kdp_hw_shmem_dbg_buf_elm *cur_elm = NULL, *tmp_elm = NULL;

	STAILQ_FOREACH(cur_elm, &free_hw_shmem_dbg_bufs, khsd_elms) {
		cur_elm->khsd_data_length = 0;
	}

	if (data->currently_filling_buf != NULL) {
		data->currently_filling_buf->khsd_data_length = 0;

		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, data->currently_filling_buf, khsd_elms);
		data->currently_filling_buf = NULL;
	}

	if (data->currently_flushing_buf != NULL) {
		data->currently_flushing_buf->khsd_data_length = 0;

		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, data->currently_flushing_buf, khsd_elms);
		data->currently_flushing_buf = NULL;
	}

	STAILQ_FOREACH_SAFE(cur_elm, &hw_shmem_dbg_bufs_to_flush, khsd_elms, tmp_elm) {
		cur_elm->khsd_data_length = 0;

		STAILQ_REMOVE(&hw_shmem_dbg_bufs_to_flush, cur_elm, kdp_hw_shmem_dbg_buf_elm, khsd_elms);
		STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, cur_elm, khsd_elms);
	}

	hwsd_info->xhsdci_status = XHSDCI_COREDUMP_BUF_EMPTY;
	data->seq_no = 0;
	hwsd_info->xhsdci_buf_phys_addr = 0;
	hwsd_info->xhsdci_buf_data_length = 0;
	hwsd_info->xhsdci_coredump_total_size_uncomp = 0;
	hwsd_info->xhsdci_coredump_total_size_sent_uncomp = 0;
	hwsd_info->xhsdci_page_size = PAGE_SIZE;
	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

	data->contact_deadline = mach_absolute_time() + data->contact_deadline_interval;

	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

/*
 * Tries to move buffers forward in 'progress'. If
 * the hardware debugger is done consuming the current buffer, we
 * can put the next one on it and move the current
 * buffer back to the free queue.
 */
static kern_return_t
shmem_dbg_process_buffers(struct kdp_output_stage *stage)
{
	struct shmem_stage_data *data = (struct shmem_stage_data *) stage->kos_data;

	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
	if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_ERROR) {
		kern_coredump_log(NULL, "Detected remote error, terminating...\n");
		return kIOReturnError;
	} else if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_BUF_EMPTY) {
		if (hwsd_info->xhsdci_seq_no != (data->seq_no + 1)) {
			kern_coredump_log(NULL, "Detected stale/invalid seq num. Expected: %d, received %d\n",
			    (data->seq_no + 1), hwsd_info->xhsdci_seq_no);
			hwsd_info->xhsdci_status = XHSDCI_COREDUMP_ERROR;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
			return kIOReturnError;
		}

		data->seq_no = hwsd_info->xhsdci_seq_no;

		if (data->currently_flushing_buf != NULL) {
			data->currently_flushing_buf->khsd_data_length = 0;
			STAILQ_INSERT_TAIL(&free_hw_shmem_dbg_bufs, data->currently_flushing_buf, khsd_elms);
		}

		data->currently_flushing_buf = STAILQ_FIRST(&hw_shmem_dbg_bufs_to_flush);
		if (data->currently_flushing_buf != NULL) {
			STAILQ_REMOVE_HEAD(&hw_shmem_dbg_bufs_to_flush, khsd_elms);

			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
			hwsd_info->xhsdci_buf_phys_addr = kvtophys(data->currently_flushing_buf->khsd_buf);
			hwsd_info->xhsdci_buf_data_length = data->currently_flushing_buf->khsd_data_length;
			hwsd_info->xhsdci_coredump_total_size_uncomp = stage->kos_outstate->kcos_totalbytes;
			hwsd_info->xhsdci_coredump_total_size_sent_uncomp = stage->kos_outstate->kcos_bytes_written;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE);
			hwsd_info->xhsdci_seq_no = ++(data->seq_no);
			hwsd_info->xhsdci_status = XHSDCI_COREDUMP_BUF_READY;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		}

		data->contact_deadline = mach_absolute_time() + data->contact_deadline_interval;

		return KERN_SUCCESS;
	} else if (mach_absolute_time() > data->contact_deadline) {
		kern_coredump_log(NULL, "Kernel timed out waiting for hardware debugger to update handshake structure.");
		kern_coredump_log(NULL, "No contact in %d seconds\n", KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS);

		hwsd_info->xhsdci_status = XHSDCI_COREDUMP_ERROR;
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		return kIOReturnError;
	}

	return KERN_SUCCESS;
}

/*
 * Populates currently_filling_buf with a new buffer
 * once one becomes available. Returns 0 on success
 * or the value returned by shmem_dbg_process_buffers()
 * if it is non-zero (an error).
 */
static kern_return_t
shmem_dbg_get_buffer(struct kdp_output_stage *stage)
{
	kern_return_t ret = KERN_SUCCESS;
	struct shmem_stage_data *data = (struct shmem_stage_data *) stage->kos_data;

	assert(data->currently_filling_buf == NULL);

	while (STAILQ_EMPTY(&free_hw_shmem_dbg_bufs)) {
		ret = shmem_dbg_process_buffers(stage);
		if (ret) {
			return ret;
		}
	}

	data->currently_filling_buf = STAILQ_FIRST(&free_hw_shmem_dbg_bufs);
	STAILQ_REMOVE_HEAD(&free_hw_shmem_dbg_bufs, khsd_elms);

	assert(data->currently_filling_buf->khsd_data_length == 0);
	return ret;
}


/*
 * Output procedure for hardware shared memory core dumps
 *
 * Tries to fill up the buffer completely before flushing
 */
static kern_return_t
shmem_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    __unused char *corename, uint64_t length, void * panic_data)
{
	kern_return_t ret = KERN_SUCCESS;
	struct shmem_stage_data *data = (struct shmem_stage_data *) stage->kos_data;

	assert(STAILQ_NEXT(stage, kos_next) == NULL);
	assert(length < UINT32_MAX);
	uint32_t bytes_remaining =  (uint32_t) length;
	uint32_t bytes_to_copy;

	if (request == KDP_EOF) {
		assert(data->currently_filling_buf == NULL);

		/*
		 * Wait until we've flushed all the buffers
		 * before setting the connection status to done.
		 */
		while (!STAILQ_EMPTY(&hw_shmem_dbg_bufs_to_flush) ||
		    data->currently_flushing_buf != NULL) {
			ret = shmem_dbg_process_buffers(stage);
			if (ret) {
				return ret;
			}
		}

		/*
		 * If the last status we saw indicates that the buffer was
		 * empty and we didn't flush any new data since then, we expect
		 * the sequence number to still match the last we saw.
		 */
		if (hwsd_info->xhsdci_seq_no < data->seq_no) {
			kern_coredump_log(NULL, "EOF Flush: Detected stale/invalid seq num. Expected: %d, received %d\n",
			    data->seq_no, hwsd_info->xhsdci_seq_no);
			return -1;
		}

		data->seq_no = hwsd_info->xhsdci_seq_no;

		kern_coredump_log(NULL, "Setting coredump status as done!\n");
		hwsd_info->xhsdci_seq_no = ++(data->seq_no);
		hwsd_info->xhsdci_status = XHSDCI_COREDUMP_STATUS_DONE;
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

		return ret;
	}

	assert(request == KDP_DATA);

	/*
	 * The output procedure is called with length == 0 and panic_data == NULL
	 * to flush any remaining output at the end of the coredump before
	 * we call it a final time to mark the dump as done.
	 */
	if (length == 0) {
		assert(panic_data == NULL);

		if (data->currently_filling_buf != NULL) {
			STAILQ_INSERT_TAIL(&hw_shmem_dbg_bufs_to_flush, data->currently_filling_buf, khsd_elms);
			data->currently_filling_buf = NULL;
		}

		/*
		 * Move the current buffer along if possible.
		 */
		ret = shmem_dbg_process_buffers(stage);
		return ret;
	}

	while (bytes_remaining != 0) {
		/*
		 * Make sure we have a buffer to work with.
		 */
		while (data->currently_filling_buf == NULL) {
			ret = shmem_dbg_get_buffer(stage);
			if (ret) {
				return ret;
			}
		}

		assert(kdp_hw_shmem_dbg_bufsize >= data->currently_filling_buf->khsd_data_length);
		bytes_to_copy = MIN(bytes_remaining, kdp_hw_shmem_dbg_bufsize -
		    data->currently_filling_buf->khsd_data_length);
		bcopy(panic_data, (void *)(data->currently_filling_buf->khsd_buf + data->currently_filling_buf->khsd_data_length),
		    bytes_to_copy);

		data->currently_filling_buf->khsd_data_length += bytes_to_copy;

		if (data->currently_filling_buf->khsd_data_length == kdp_hw_shmem_dbg_bufsize) {
			STAILQ_INSERT_TAIL(&hw_shmem_dbg_bufs_to_flush, data->currently_filling_buf, khsd_elms);
			data->currently_filling_buf = NULL;

			/*
			 * Move it along if possible.
			 */
			ret = shmem_dbg_process_buffers(stage);
			if (ret) {
				return ret;
			}
		}

		stage->kos_bytes_written += bytes_to_copy;
		bytes_remaining -= bytes_to_copy;
		panic_data = (void *) ((uintptr_t)panic_data + bytes_to_copy);
	}

	return ret;
}

static void
shmem_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);

	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
shmem_stage_initialize(struct kdp_output_stage *stage)
{
	kern_return_t ret = KERN_SUCCESS;
	struct shmem_stage_data *data = NULL;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);

	if (!hwsd_info) {
		vm_offset_t kdp_core_hw_shmem_buf = 0;
		struct kdp_hw_shmem_dbg_buf_elm *cur_elm = NULL;
		cache_info_t   *cpuid_cache_info = NULL;

		/*
		 * We need to allocate physically contiguous memory since astris isn't capable
		 * of doing address translations while the CPUs are running.
		 */
		kdp_hw_shmem_dbg_bufsize = KDP_CORE_HW_SHMEM_DBG_TOTAL_BUF_SIZE;
		ret = kmem_alloc_contig(kernel_map, &kdp_core_hw_shmem_buf,
		    kdp_hw_shmem_dbg_bufsize, VM_MAP_PAGE_MASK(kernel_map),
		    0, 0, KMA_KOBJECT | KMA_DATA | KMA_PERMANENT,
		    VM_KERN_MEMORY_DIAG);
		assert(KERN_SUCCESS == ret);

		/*
		 * Put the connection info structure at the beginning of this buffer and adjust
		 * the buffer size accordingly.
		 */
		hwsd_info = (struct xnu_hw_shmem_dbg_command_info *) kdp_core_hw_shmem_buf;
		hwsd_info->xhsdci_status = XHSDCI_STATUS_NONE;
		hwsd_info->xhsdci_seq_no = 0;
		hwsd_info->xhsdci_buf_phys_addr = 0;
		hwsd_info->xhsdci_buf_data_length = 0;
		hwsd_info->xhsdci_coredump_total_size_uncomp = 0;
		hwsd_info->xhsdci_coredump_total_size_sent_uncomp = 0;
		hwsd_info->xhsdci_page_size = PAGE_SIZE;

		cpuid_cache_info = cache_info();
		assert(cpuid_cache_info != NULL);

		kdp_core_hw_shmem_buf += sizeof(*hwsd_info);
		/* Leave the handshake structure on its own cache line so buffer writes don't cause flushes of old handshake data */
		kdp_core_hw_shmem_buf = ROUNDUP(kdp_core_hw_shmem_buf, (vm_offset_t) cpuid_cache_info->c_linesz);
		kdp_hw_shmem_dbg_bufsize -= (uint32_t) (kdp_core_hw_shmem_buf - (vm_offset_t) hwsd_info);
		kdp_hw_shmem_dbg_bufsize /= KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS;
		/* The buffer size should be a cache-line length multiple */
		kdp_hw_shmem_dbg_bufsize -= (kdp_hw_shmem_dbg_bufsize % ROUNDDOWN(OPTIMAL_ASTRIS_READSIZE, cpuid_cache_info->c_linesz));

		STAILQ_INIT(&free_hw_shmem_dbg_bufs);
		STAILQ_INIT(&hw_shmem_dbg_bufs_to_flush);

		for (int i = 0; i < KDP_CORE_HW_SHMEM_DBG_NUM_BUFFERS; i++) {
			cur_elm = zalloc_permanent_type(typeof(*cur_elm));
			assert(cur_elm != NULL);

			cur_elm->khsd_buf = kdp_core_hw_shmem_buf;
			cur_elm->khsd_data_length = 0;

			kdp_core_hw_shmem_buf += kdp_hw_shmem_dbg_bufsize;

			STAILQ_INSERT_HEAD(&free_hw_shmem_dbg_bufs, cur_elm, khsd_elms);
		}

		PE_consistent_debug_register(kDbgIdAstrisConnection, kvtophys((vm_offset_t) hwsd_info), sizeof(pmap_paddr_t));
		PE_consistent_debug_register(kDbgIdAstrisConnectionVers, CUR_XNU_HWSDCI_STRUCT_VERS, sizeof(uint32_t));
	}

	stage->kos_data_size = sizeof(struct shmem_stage_data);

	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

	data = (struct shmem_stage_data*) stage->kos_data;
	data->seq_no = 0;
	data->contact_deadline = 0;
	nanoseconds_to_absolutetime(KDP_HW_SHMEM_DBG_TIMEOUT_DEADLINE_SECS * NSEC_PER_SEC, &(data->contact_deadline_interval));
	data->currently_filling_buf = NULL;
	data->currently_flushing_buf = NULL;

	stage->kos_funcs.kosf_reset = shmem_stage_reset;
	stage->kos_funcs.kosf_outproc = shmem_stage_outproc;
	stage->kos_funcs.kosf_free = shmem_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

void
shmem_mark_as_busy(void)
{
	if (hwsd_info != NULL) {
		hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_BUSY;
	}
}

void
panic_spin_shmcon(void)
{
	if (!PE_i_can_has_debugger(NULL)) {
		return;
	}

	if (hwsd_info == NULL) {
		kern_coredump_log(NULL, "handshake structure not initialized\n");
		return;
	}

	kern_coredump_log(NULL, "\nPlease go to https://panic.apple.com to report this panic\n");
	kern_coredump_log(NULL, "Waiting for hardware shared memory debugger, handshake structure is at virt: %p, phys %p\n",
	    hwsd_info, (void *)kvtophys((vm_offset_t)hwsd_info));

	hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_READY;
	hwsd_info->xhsdci_seq_no = 0;
	FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));

	for (;;) {
		FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		if (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_BEGIN) {
			kern_dump(KERN_DUMP_HW_SHMEM_DBG);
		}

		if ((hwsd_info->xhsdci_status == XHSDCI_COREDUMP_REMOTE_DONE) ||
		    (hwsd_info->xhsdci_status == XHSDCI_COREDUMP_ERROR)) {
			hwsd_info->xhsdci_status = XHSDCI_STATUS_KERNEL_READY;
			hwsd_info->xhsdci_seq_no = 0;
			FlushPoC_DcacheRegion((vm_offset_t) hwsd_info, sizeof(*hwsd_info));
		}
	}
}

#endif /* defined(CONFIG_KDP_INTERACTIVE_DEBUGGING) && (defined(__arm__) || defined(__arm64__)) */
