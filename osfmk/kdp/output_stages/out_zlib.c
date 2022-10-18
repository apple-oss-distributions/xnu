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
#include <IOKit/IOTypes.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <kdp/processor_core.h>
#include <libkern/zlib.h>

#define MAX_ZLIB_CHUNK (1024 * 1024 * 1024)

#if defined(__arm64__)
#define LEVEL Z_BEST_SPEED
#define NETBUF 0
#else
#define LEVEL Z_BEST_SPEED
#define NETBUF 1440
#endif

#define ROUND_32B(x) (~31UL & (31 + (x)))

struct zlib_stage_data {
	z_stream zs;
	size_t   allocation_offset;
};

static void *
zlib_alloc(void *opaque, u_int items, u_int size)
{
	struct kdp_output_stage *stage = (struct kdp_output_stage *) opaque;
	struct zlib_stage_data *data = (struct zlib_stage_data *) stage->kos_data;
	void * result;

	result = (void *) ((vm_offset_t) data + data->allocation_offset);
	data->allocation_offset += ROUND_32B(items * size); // 32b align for vector crc
	assert(data->allocation_offset <= stage->kos_data_size);

	return result;
}

static void
zlib_free(void * __unused ref, void * __unused ptr)
{
}

/*
 * flushes any data to the output proc immediately
 */
static int
zlib_zoutput(z_streamp strm, Bytef *buf, unsigned len)
{
	struct kdp_output_stage *stage = (typeof(stage))strm->opaque;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);
	IOReturn                 ret;

	if (stage->kos_outstate->kcos_error == kIOReturnSuccess) {
		ret = next_stage->kos_funcs.kosf_outproc(next_stage, KDP_DATA, NULL, len, buf);
		if (ret != kIOReturnSuccess) {
			kern_coredump_log(NULL, "(zlib_zoutput) outproc(KDP_DATA, NULL, 0x%x, %p) returned 0x%x\n",
			    len, buf, ret);
			stage->kos_outstate->kcos_error = ret;
		} else {
			stage->kos_bytes_written += len;
		}
	}

	return len;
}

static int
zlib_zinput(z_streamp strm, Bytef *buf, unsigned size)
{
	unsigned len;

	len = strm->avail_in;
	if (len > size) {
		len = size;
	}
	if (len == 0) {
		return 0;
	}

	if (strm->next_in != (Bytef *) strm) {
		memcpy(buf, strm->next_in, len);
	} else {
		bzero(buf, len);
	}
	strm->adler = z_crc32(strm->adler, buf, len);

	strm->avail_in -= len;
	strm->next_in  += len;
	strm->total_in += len;

	return (int)len;
}


static kern_return_t
zlib_stream_output_chunk(struct kdp_output_stage *stage, unsigned int length, void *data)
{
	struct zlib_stage_data *stage_data;
	z_stream * zs;
	int        zr;
	boolean_t  flush;

	stage_data = (struct zlib_stage_data *) stage->kos_data;
	zs = &(stage_data->zs);
	flush = (!length && !data);
	zr = Z_OK;

	assert(!zs->avail_in);

	while (zr >= 0) {
		if (!zs->avail_in && !flush) {
			if (!length) {
				break;
			}
			zs->next_in = data ? data : (Bytef *) zs /* zero marker */;
			zs->avail_in = length;
			length = 0;
		}
		if (!zs->avail_out) {
			zs->next_out  = (Bytef *) zs;
			zs->avail_out = UINT32_MAX;
		}
		zr = deflate(zs, flush ? Z_FINISH : Z_NO_FLUSH);
		if (Z_STREAM_END == zr) {
			break;
		}
		if (zr != Z_OK) {
			kern_coredump_log(NULL, "ZERR %d\n", zr);
			stage->kos_outstate->kcos_error = kIOReturnError;
		}
	}

	if (flush) {
		zlib_zoutput(zs, NULL, 0);
	}

	return stage->kos_outstate->kcos_error;
}

static void
zlib_stage_reset(struct kdp_output_stage *stage)
{
	struct zlib_stage_data *data = (struct zlib_stage_data *) stage->kos_data;

	stage->kos_bypass = false;
	stage->kos_bytes_written = 0;

	/* Re-initialize zstream variables */
	data->zs.avail_in  = 0;
	data->zs.next_in   = NULL;
	data->zs.avail_out = 0;
	data->zs.next_out  = NULL;

	deflateResetWithIO(&(data->zs), zlib_zinput, zlib_zoutput);
}

static kern_return_t
zlib_stage_outproc(struct kdp_output_stage *stage, unsigned int request,
    char *corename, uint64_t length, void *panic_data)
{
	kern_return_t            err = KERN_SUCCESS;
	struct kdp_output_stage *next_stage = STAILQ_NEXT(stage, kos_next);
	unsigned int             chunk;

	assert(next_stage != NULL);

	switch (request) {
	case KDP_SEEK:
		stage->kos_bypass = true;
		err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		break;
	case KDP_DATA:
		if (!stage->kos_bypass) {
			do{
				if (length <= MAX_ZLIB_CHUNK) {
					chunk = (typeof(chunk))length;
				} else {
					chunk = MAX_ZLIB_CHUNK;
				}

				err = zlib_stream_output_chunk(stage, chunk, panic_data);

				length -= chunk;

				if (panic_data) {
					panic_data = (void *) (((uintptr_t) panic_data) + chunk);
				}
			} while (length && (KERN_SUCCESS == err));
		} else {
			err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		}
		break;
	case KDP_WRQ:
		OS_FALLTHROUGH;
	case KDP_FLUSH:
		OS_FALLTHROUGH;
	case KDP_EOF:
		err = next_stage->kos_funcs.kosf_outproc(next_stage, request, corename, length, panic_data);
		break;
	default:
		break;
	}

	return err;
}

static void
zlib_stage_free(struct kdp_output_stage *stage)
{
	kmem_free(kernel_map, (vm_offset_t) stage->kos_data, stage->kos_data_size);
	stage->kos_data = NULL;
	stage->kos_data_size = 0;
	stage->kos_initialized = false;
}

kern_return_t
zlib_stage_initialize(struct kdp_output_stage *stage)
{
	const int wbits = 12;
	const int memlevel = 3;
	kern_return_t ret = KERN_SUCCESS;
	struct zlib_stage_data *data = NULL;

	assert(stage != NULL);
	assert(stage->kos_initialized == false);
	assert(stage->kos_data == NULL);

	stage->kos_data_size = round_page(sizeof(struct zlib_stage_data) + NETBUF + zlib_deflate_memory_size(wbits, memlevel));
	printf("kdp_core zlib memory 0x%lx\n", stage->kos_data_size);
	/*
	 * Note: KMA_DATA isn't right because we have pointers,
	 *       but it is assumed by the generic code that kos_data
	 *       is a linear buffer which requires more work to split.
	 *
	 *       We still want to use KMA_DATA for it as it has more
	 *       chances to have VA in catastrophic cases.
	 */
	ret = kmem_alloc(kernel_map, (vm_offset_t*) &stage->kos_data, stage->kos_data_size,
	    KMA_DATA, VM_KERN_MEMORY_DIAG);
	if (KERN_SUCCESS != ret) {
		printf("zlib_stage_initialize failed to allocate memory. Error 0x%x\n", ret);
		return ret;
	}

	data = (struct zlib_stage_data *)(stage->kos_data);
	data->allocation_offset = ROUND_32B(sizeof(struct zlib_stage_data)); // Start allocating from the end of the data struct
	data->zs.zalloc = zlib_alloc;
	data->zs.zfree = zlib_free;
	data->zs.opaque = (void*) stage;

	if (deflateInit2(&(data->zs), LEVEL, Z_DEFLATED, wbits + 16 /*gzip mode*/, memlevel, Z_DEFAULT_STRATEGY)) {
		/* Allocation failed */
		zlib_stage_free(stage);
		return kIOReturnError;
	}

	stage->kos_funcs.kosf_reset = zlib_stage_reset;
	stage->kos_funcs.kosf_outproc = zlib_stage_outproc;
	stage->kos_funcs.kosf_free = zlib_stage_free;

	stage->kos_initialized = true;

	return ret;
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
