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

#if defined(CONFIG_KDP_INTERACTIVE_DEBUGGING)

#include <mach/kern_return.h>
#include <os/base.h>
#include <kern/assert.h>
#include <kern/kalloc.h>
#include <kern/misc_protos.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_out_stage.h>
#include <kdp/processor_core.h>
#include <kdp/output_stages/output_stages.h>
#include <libkern/compression/compression.h>

// One page seems to be a sweet-spot for both buffers; we tend to dump a page or less at a time so
// smaller sizes start incurring overhead for the loop, and larger sizes waste more memory without
// a noticable increase in throughput.
//
// Having a buffer full of zeroes wastes a bit of memory, but we need some way to pass zeroes to
// Compression when we are asked to pad the stream.
#define DST_BUF_SIZE PAGE_SIZE
#define ZERO_BUF_SIZE PAGE_SIZE

struct lz4_stage_data {
	compression_stream_t stream;
	compression_algorithm_t algorithm;
	uint8_t *dst_buf;
	const uint8_t *zero_buf;
	bool reset_failed;
};

static void
lz4_stage_reset(struct kdp_output_stage *stage)
{
	struct lz4_stage_data *data;
	compression_status_t status;

	assert(compression_ki_ptr);

	assert(stage);
	assert(stage->kos_initialized);

	data = stage->kos_data;
	assert(data);

	status = compression_ki_ptr->compression_stream_reinit(&data->stream,
	    COMPRESSION_STREAM_ENCODE, data->algorithm);
	if (COMPRESSION_STATUS_OK != status) {
		data->reset_failed = true;
	}

	data->stream.dst_ptr = data->dst_buf;
	data->stream.dst_size = DST_BUF_SIZE;

	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;
}

static kern_return_t
lz4_stage_stream(struct lz4_stage_data *data, struct kdp_output_stage *next_stage, char *corename,
    const uint8_t *src_buf, size_t src_buf_size, uint64_t *written)
{
	bool finalize;
	compression_status_t status;
	kern_return_t ret;
	size_t produced;

	assert(compression_ki_ptr);

	assert(data);
	assert(next_stage);
	assert(written);

	finalize = !src_buf && !src_buf_size;
	assert((src_buf && src_buf_size) || finalize);

	data->stream.src_ptr = src_buf;
	data->stream.src_size = src_buf_size;

	// Every time we process more bytes, the stream source and destination pointers
	// and sizes are adjusted.
	do {
		status = compression_ki_ptr->compression_stream_process(&data->stream,
		    finalize ? COMPRESSION_STREAM_FINALIZE : 0);
		if (COMPRESSION_STATUS_ERROR == status) {
			return KERN_FAILURE;
		}

		// The difference between the original destination buffer size and the size of the
		// remaining space tells us how many bytes were produced.
		produced = DST_BUF_SIZE - data->stream.dst_size;
		// Pass along those bytes to the next stage so that we empty the destination buffer.
		ret = next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, corename,
		    produced, data->dst_buf);
		if (KERN_SUCCESS != ret) {
			return ret;
		}
		*written += produced;
		data->stream.dst_ptr = data->dst_buf;
		data->stream.dst_size = DST_BUF_SIZE;
		// Continue processing while the source buffer is non-empty, or we are finalizing
		// and there are still bytes being produced in the destination buffer.
	} while (data->stream.src_size || (finalize && COMPRESSION_STATUS_END != status));

	if (finalize) {
		return next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, corename, 0, NULL);
	}

	return KERN_SUCCESS;
}

static kern_return_t
lz4_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void *panic_data)
{
	struct lz4_stage_data *data;
	struct kdp_output_stage *next_stage;
	kern_return_t ret;
	size_t pad_length;
	size_t zero_size;

	assert(stage);
	assert(stage->kos_initialized);

	data = stage->kos_data;
	assert(data);

	next_stage = STAILQ_NEXT(stage, kos_next);
	assert(next_stage);

	if (data->reset_failed) {
		return KERN_FAILURE;
	}

	if (KDP_SEEK == request) {
		stage->kos_bypass = true;
	}

	if (stage->kos_bypass || KDP_DATA != request) {
		return next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length,
		           panic_data);
	}

	if (panic_data) {
		// Write panic data to the stream.
		return lz4_stage_stream(data, next_stage, corename, panic_data, (size_t)length,
		           &stage->kos_bytes_written);
	} else {
		if (length) {
			// Pad the stream with zeroes.
			pad_length = (size_t)length;
			do {
				zero_size = MIN(pad_length, ZERO_BUF_SIZE);
				ret = lz4_stage_stream(data, next_stage, corename, data->zero_buf,
				    zero_size, &stage->kos_bytes_written);
				if (KERN_SUCCESS != ret) {
					return ret;
				}
				pad_length -= zero_size;
			} while (pad_length);
			return KERN_SUCCESS;
		} else {
			// Finalize the stream.
			return lz4_stage_stream(data, next_stage, corename, NULL, 0, &stage->kos_bytes_written);
		}
	}
}

static void
lz4_stage_free(struct kdp_output_stage *stage)
{
	struct lz4_stage_data *data;

	assert(compression_ki_ptr);

	assert(stage);
	assert(stage->kos_initialized);

	data = stage->kos_data;
	assert(data);

	kfree_data(data->dst_buf, DST_BUF_SIZE);

	compression_ki_ptr->compression_stream_destroy(&data->stream);

	kfree_type(typeof(*data), data);

	stage->kos_initialized = false;
}

kern_return_t
lz4_stage_initialize(struct kdp_output_stage *stage)
{
	struct lz4_stage_data *data;
	compression_status_t status;

	assert(compression_ki_ptr);

	assert(stage);
	assert(!stage->kos_initialized);
	assert(!stage->kos_data);

	data = kalloc_type(typeof(*data), Z_WAITOK);
	assert(data);

	data->algorithm = COMPRESSION_LZ4;

	data->dst_buf = kalloc_data(DST_BUF_SIZE, Z_WAITOK);
	assert(data->dst_buf);

	data->zero_buf = kalloc_data(ZERO_BUF_SIZE, Z_WAITOK | Z_ZERO);
	assert(data->zero_buf);

	data->reset_failed = false;

	status = compression_ki_ptr->compression_stream_init(&data->stream, COMPRESSION_STREAM_ENCODE,
	    data->algorithm);
	if (COMPRESSION_STATUS_ERROR == status) {
		return KERN_FAILURE;
	}
	data->stream.dst_ptr = data->dst_buf;
	data->stream.dst_size = DST_BUF_SIZE;

	stage->kos_data = data;
	stage->kos_data_size = sizeof(*data);

	stage->kos_funcs.kosf_reset = lz4_stage_reset;
	stage->kos_funcs.kosf_outproc = lz4_stage_outproc;
	stage->kos_funcs.kosf_free = lz4_stage_free;

	stage->kos_initialized = true;

	return KERN_SUCCESS;
}

static void
lz4_stage_registration_callback(void)
{
	kern_return_t ret = kdp_core_handle_lz4_available();
	if (KERN_SUCCESS != ret) {
		printf("(%s) Failed to handle availability of LZ4. Error 0x%x\n", __func__, ret);
	}
}

void
lz4_stage_monitor_availability(void)
{
	compression_interface_set_registration_callback(lz4_stage_registration_callback);
}

#endif /* defined(CONFIG_KDP_INTERACTIVE_DEBUGGING) */
