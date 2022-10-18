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

#pragma once

#include <kdp/kdp_out_stage.h>

/*
 * A non-terminal output stage that merely buffers up any output data before
 * sending it over to the next stage. This is useful when a subsequent stage
 * expects data in specific chunks (e.g. the network stage expects chunks of
 * a specific size to send as packets).
 *
 * Note that the buffer is flushed before any operation other than KDP_DATA,
 * and is flushed when KDP_DATA is specified with an empty data buffer.
 */
kern_return_t buffer_stage_initialize(struct kdp_output_stage *stage, size_t buffer_size);

/*
 * A non-terminal output stage that compresses the output data with LZ4 before
 * sending it over to the next stage.
 */
kern_return_t lz4_stage_initialize(struct kdp_output_stage *stage);

/*
 * Instructs the LZ4 stage to start monitoring for the Compression kext.
 */
void lz4_stage_monitor_availability(void);

/*
 * A non-terminal output stage that compresses (using ZLib) the output data before
 * sending it over to the next stage.
 *
 * Note that compression is bypassed (until the stage is reset) if the caller performs
 * a KDP_SEEK operation.
 */
kern_return_t zlib_stage_initialize(struct kdp_output_stage *stage);

/*
 * A non-terminal output stage that encrypts the data through AppleEncryptedArchive
 * before sending it over to the next stage.
 *
 * Note that this stage requires that its subsequent stages be able to seek
 * backwards and read data
 *
 * Double Note that this stage will technically only work if the subsequent stage is
 * the disk stage.
 */
kern_return_t aea_stage_initialize(struct kdp_output_stage *stage, const void *recipient_public_key, size_t recipient_public_key_size);

/*
 * Instructs the AEA stage to start monitoring for the availability of the AEA functionality.
 */
void aea_stage_monitor_availability(void);

/*
 * Checks whether the AEA functionality is currently available.
 */
bool aea_stage_is_available(void);

/*
 * A terminal output stage that writes data out to the corefile.
 */
kern_return_t disk_stage_initialize(struct kdp_output_stage *stage);

/*
 * Write an arbitrary amount of data to an arbitrary offset in the on-disk corefile.
 */
kern_return_t disk_stage_write(struct kdp_output_stage *stage, uint64_t offset, uint64_t length, const void *data);

/*
 * Read an arbitrary amount of data from an arbitrary offset in the on-disk corefile.
 */
kern_return_t disk_stage_read(struct kdp_output_stage *stage, uint64_t offset, uint64_t length, void *data);

/*
 * A terminal output stage that streams the data out over the network.
 */
kern_return_t net_stage_initialize(struct kdp_output_stage *stage);

/*
 * A non-terminal output stage that notifies registered panic callouts about coredump progress periodically.
 */
kern_return_t progress_notify_stage_initialize(struct kdp_output_stage *stage);

#if defined(__arm64__)
/*
 * A non-terminal output stage that handles memory accesses to special device memory.
 */
kern_return_t memory_backing_aware_buffer_stage_initialize(struct kdp_output_stage *stage);
#endif /* defined(__arm64__) */

#if defined(__arm64__)
/*
 * A terminal output stage that streams the data out to an external
 * agent (a debugger) over a shared memory region.
 */
kern_return_t shmem_stage_initialize(struct kdp_output_stage *stage);
#endif /* defined(__arm64__) */
