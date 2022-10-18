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

#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING

#include <mach/mach_types.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>
#include <IOKit/IOPolledInterface.h>
#include <IOKit/IOBSD.h>

struct disk_stage_data {
	bool last_operation_was_write;
	uint64_t current_offset;
	uint64_t furthest_written_offset;
	size_t alignment;
};

kern_return_t
disk_stage_write(struct kdp_output_stage *stage, uint64_t offset, uint64_t length, const void *data)
{
	kern_return_t err = KERN_SUCCESS;

	assert(stage != NULL);
	assert(stage->kos_initialized == true);

	struct disk_stage_data *stage_data = (struct disk_stage_data *) stage->kos_data;
	bool already_seeked_this_chunk = false;

	if ((offset < stage_data->furthest_written_offset) || (offset != stage_data->current_offset)) {
		// We need to seek to the proper offset and prefill the IOPolledInterface internal buffers
		uint64_t offset_misalignment = offset % stage_data->alignment;
		uint64_t aligned_offset = offset - offset_misalignment;
		err = disk_stage_read(stage, offset, 0, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "(disk_stage_write) disk_stage_read (during seek) returned 0x%x\n", err);
			return err;
		}

		// Now seek back to the aligned offset
		err = IOPolledFileSeek(gIOPolledCoreFileVars, aligned_offset);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "(disk_stage_write) IOPolledFileSeek(0x%llx) returned 0x%x\n", aligned_offset, err);
			return err;
		}

		// Adjust the position forward
		gIOPolledCoreFileVars->position += offset_misalignment;
		already_seeked_this_chunk = true;
	}

	while (KERN_SUCCESS == err && length != 0) {
		bool read_modify_write = false;
		uint64_t chunk = gIOPolledCoreFileVars->bufferLimit - gIOPolledCoreFileVars->bufferOffset;
		if (chunk > length) {
			chunk = length;

			// If we're about to write to a region that we've written to before,
			// we'll need to prefill the IOPolledInterface internal buffers with the contents
			// of that region
			if (offset + chunk < stage_data->furthest_written_offset) {
				read_modify_write = true;

				if (!already_seeked_this_chunk) {
					uint64_t offset_misalignment = offset % stage_data->alignment;
					uint64_t aligned_offset = offset - offset_misalignment;
					err = disk_stage_read(stage, offset, 0, NULL);
					if (kIOReturnSuccess != err) {
						kern_coredump_log(NULL, "(disk_stage_write) disk_stage_read (during final chunk seek) returned 0x%x\n", err);
						break;
					}

					// Now seek back to the aligned offset
					err = IOPolledFileSeek(gIOPolledCoreFileVars, aligned_offset);
					if (kIOReturnSuccess != err) {
						kern_coredump_log(NULL, "(disk_stage_write) IOPolledFileSeek(0x%llx) returned 0x%x\n", aligned_offset, err);
						break;
					}

					// Adjust the position forward
					gIOPolledCoreFileVars->position += offset_misalignment;
				}
			}
		}

		already_seeked_this_chunk = false;

		stage_data->last_operation_was_write = true;

		// Now write the chunk
		err = IOPolledFileWrite(gIOPolledCoreFileVars, data, (IOByteCount) chunk, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "(disk_stage_write) IOPolledFileWrite(gIOPolledCoreFileVars, %p, 0x%llx, NULL) returned 0x%x\n",
			    data, chunk, err);
			break;
		}

		if (read_modify_write) {
			// We flush the entirety of the IOPolledInterface buffer back to disk
			uint32_t remainder = gIOPolledCoreFileVars->bufferLimit - gIOPolledCoreFileVars->bufferOffset;
			gIOPolledCoreFileVars->bufferOffset += remainder;
			gIOPolledCoreFileVars->position += remainder;
			err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
			if (kIOReturnSuccess != err) {
				kern_coredump_log(NULL, "(disk_stage_write) IOPolledFileWrite (during final flush) returned 0x%x\n", err);
				break;
			}
		}

		data = (const void *) (((uintptr_t) data) + chunk);
		length -= chunk;
		offset += chunk;
		stage_data->current_offset += chunk;
		if (offset > stage_data->furthest_written_offset) {
			stage_data->furthest_written_offset = offset;
		}
	}

	return err;
}

kern_return_t
disk_stage_read(struct kdp_output_stage *stage, uint64_t offset, uint64_t length, void *data)
{
	kern_return_t err = KERN_SUCCESS;

	assert(stage != NULL);
	assert(stage->kos_initialized == true);

	struct disk_stage_data *stage_data = (struct disk_stage_data *) stage->kos_data;

	// Flush out any prior data
	if (stage_data->last_operation_was_write) {
		err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "(disk_stage_read) IOPolledFileWrite (during seek) returned 0x%x\n", err);
			return err;
		}
		stage_data->last_operation_was_write = false;
	}

	uint64_t offset_misalignment = offset % stage_data->alignment;
	uint64_t aligned_offset = offset - offset_misalignment;

	// First seek to the aligned position (this will update the position variable and whatnot)
	err = IOPolledFileSeek(gIOPolledCoreFileVars, aligned_offset);
	if (kIOReturnSuccess != err) {
		kern_coredump_log(NULL, "(disk_stage_read) IOPolledFileSeek(0x%llx) returned 0x%x\n", aligned_offset, err);
		return err;
	}

	// kick off the read ahead (this is mostly taken from IOHibernateIO.cpp)
	gIOPolledCoreFileVars->bufferHalf   = 0;
	gIOPolledCoreFileVars->bufferLimit  = 0;
	gIOPolledCoreFileVars->lastRead     = 0;
	gIOPolledCoreFileVars->readEnd      = roundup(gIOPolledCoreFileVars->fileSize, stage_data->alignment);
	gIOPolledCoreFileVars->bufferOffset = 0;

	err = IOPolledFileRead(gIOPolledCoreFileVars, NULL, 0, NULL);
	if (kIOReturnSuccess != err) {
		kern_coredump_log(NULL, "(disk_stage_read) Kickstarting IOPolledFileRead(0) returned 0x%x\n", err);
		return err;
	}

	// This read will (even if offset_misalignment is 0) wait for the previous read to actually complete
	err = IOPolledFileRead(gIOPolledCoreFileVars, NULL, (IOByteCount) offset_misalignment, NULL);
	if (kIOReturnSuccess != err) {
		kern_coredump_log(NULL, "(disk_stage_read) IOPolledFileRead(%llu) returned 0x%x\n", offset_misalignment, err);
		return err;
	}

	stage_data->current_offset = offset;

	err = IOPolledFileRead(gIOPolledCoreFileVars, (uint8_t *) data, (IOByteCount) length, NULL);
	if (kIOReturnSuccess != err) {
		kern_coredump_log(NULL, "(disk_stage_read) IOPolledFileRead(%llu) returned 0x%x\n", length, err);
		return err;
	}

	stage_data->current_offset += length;

	return err;
}

static void
disk_stage_reset(struct kdp_output_stage *stage)
{
	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

static kern_return_t
disk_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    __unused char *corename, uint64_t length, void * data)
{
	kern_return_t err = KERN_SUCCESS;
	struct disk_stage_data *stage_data = (struct disk_stage_data *) stage->kos_data;

	assert(STAILQ_NEXT(stage, kos_next) == NULL);

	switch (request) {
	case KDP_WRQ:
		err = IOPolledFileSeek(gIOPolledCoreFileVars, 0);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileSeek(gIOPolledCoreFileVars, 0) returned 0x%x\n", err);
			break;
		}
		err = IOPolledFilePollersOpen(gIOPolledCoreFileVars, kIOPolledBeforeSleepState, false);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFilePollersOpen returned 0x%x\n", err);
			break;
		}
		break;

	case KDP_SEEK:
	{
		uint64_t noffset = *((uint64_t *) data);
		err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileWrite (during seek) returned 0x%x\n", err);
			break;
		}
		err = IOPolledFileSeek(gIOPolledCoreFileVars, noffset);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileSeek(0x%llx) returned 0x%x\n", noffset, err);
		}
		stage_data->current_offset = noffset;
		break;
	}

	case KDP_DATA:
		err = IOPolledFileWrite(gIOPolledCoreFileVars, data, (IOByteCount) length, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileWrite(gIOPolledCoreFileVars, %p, 0x%llx, NULL) returned 0x%x\n",
			    data, length, err);
			break;
		}
		stage_data->last_operation_was_write = true;
		stage_data->current_offset += length;
		stage->kos_bytes_written += length;
		break;

#if defined(__arm64__)
	/* Only supported on embedded by the underlying polled mode driver */
	case KDP_FLUSH:
		err = IOPolledFileFlush(gIOPolledCoreFileVars);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileFlush() returned 0x%x\n", err);
			break;
		}
		break;
#endif /* defined(__arm64__) */

	case KDP_EOF:
		err = IOPolledFileWrite(gIOPolledCoreFileVars, 0, 0, NULL);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFileWrite (during EOF) returned 0x%x\n", err);
			break;
		}
		err = IOPolledFilePollersClose(gIOPolledCoreFileVars, kIOPolledBeforeSleepState);
		if (kIOReturnSuccess != err) {
			kern_coredump_log(NULL, "IOPolledFilePollersClose (during EOF) returned 0x%x\n", err);
			break;
		}
		break;
	}

	return err;
}

static void
disk_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);
	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
disk_stage_initialize(struct kdp_output_stage *stage)
{
	kern_return_t ret = KERN_SUCCESS;
	struct disk_stage_data *data = NULL;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);

	stage->kos_data_size = sizeof(struct disk_stage_data);
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

	data = (struct disk_stage_data *) stage->kos_data;
	data->last_operation_was_write = false;
	data->current_offset = 0;
	data->furthest_written_offset = 0;
	data->alignment = KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN;

	stage->kos_funcs.kosf_reset = disk_stage_reset;
	stage->kos_funcs.kosf_outproc = disk_stage_outproc;
	stage->kos_funcs.kosf_free = disk_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
