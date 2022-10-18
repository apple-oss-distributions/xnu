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

#ifndef __COMPRESSION_H
#define __COMPRESSION_H

#include <stdint.h>
#include <stddef.h>
#include <os/base.h>

/*!
 *  @enum       compression_algorithm_t
 *  @abstract   Tag used to select a compression algorithm.
 *  @discussion Further details on the supported formats, and their implementation:
 *
 *              - LZ4 is an extremely high-performance compressor.  The open source version
 *              is already one of the fastest compressors of which we are aware, and we
 *              have optimized it still further in our implementation.  The encoded format
 *              we produce and consume is compatible with the open source version, except
 *              that we add a very simple frame to the raw stream to allow some additional
 *              validation and functionality.
 *
 *              The frame is documented here so that you can easily wrap another LZ4
 *              encoder/decoder to produce/consume the same data stream if necessary.  An
 *              LZ4 encoded buffer is a sequence of blocks, each of which begins with a
 *              header.  There are three possible headers:
 *
 *                   a "compressed block header" is (hex) 62 76 34 31, followed by the
 *                   size in bytes of the decoded (plaintext) data represented by the
 *                   block and the size (in bytes) of the encoded data stored in the
 *                   block.  Both size fields are stored as (possibly unaligned) 32-bit
 *                   little-endian values.  The compressed block header is followed
 *                   immediately by the actual lz4-encoded data stream.
 *
 *                   an "uncompressed block header" is (hex) 62 76 34 2d, followed by the
 *                   size of the data stored in the uncompressed block as a (possibly
 *                   unaligned) 32-bit little-endian value.  The uncompressed block header
 *                   is followed immediately by the uncompressed data buffer of the
 *                   specified size.
 *
 *                   an "end of stream header" is (hex) 62 76 34 24, and marks the end
 *                   of the lz4 frame.  No further data may be written or read beyond
 *                   this header.
 */
typedef enum{
	COMPRESSION_LZ4 = 0x100, // LZ4 + simple frame format
} compression_algorithm_t;

/* Return values for the compression_stream functions. */
typedef enum{
	COMPRESSION_STATUS_OK    =  0,
	COMPRESSION_STATUS_ERROR = -1,
	COMPRESSION_STATUS_END   =  1,
} compression_status_t;

typedef enum{
	COMPRESSION_STREAM_ENCODE = 0, /* Encode to a compressed stream */
	COMPRESSION_STREAM_DECODE = 1, /* Decode from a compressed stream */
} compression_stream_operation_t;

/* Bits for the flags in compression_stream_process. */
typedef enum{
	COMPRESSION_STREAM_FINALIZE = 0x0001,
} compression_stream_flags_t;

typedef struct{
	/*
	 *  You are partially responsible for management of the dst_ptr,
	 *  dst_size, src_ptr, and src_size fields.  You must initialize
	 *  them to describe valid memory buffers before making a call to
	 *  compression_stream_process. compression_stream_process will update
	 *  these fields before returning to account for the bytes of the src
	 *  and dst buffers that were successfully processed.
	 */
	uint8_t*       dst_ptr;
	size_t         dst_size;
	const uint8_t* src_ptr;
	size_t         src_size;

	/* The stream state object is managed by the compression_stream functions.
	 *  You should not ever directly access this field. */
	void*          state;
} compression_stream_t;

/*  There are two critical features of the stream interfaces:
 *
 *     - They allow encoding and decoding to be resumed from where it ended
 *       when the end of a source or destination block was reached.
 *
 *     - When resuming, the new source and destination blocks need not be
 *       contiguous with earlier blocks in the stream; all necessary state
 *       to resume compression is represented by the compression_stream_t object.
 *
 *   These two properties enable tasks like:
 *
 *     - Decoding a compressed stream into a buffer with the ability to grow
 *       the buffer and resume decoding if the expanded stream is too large
 *       to fit without repeating any work.
 *
 *     - Encoding a stream as pieces of it become available without ever needing
 *       to create an allocation large enough to hold all the uncompressed data.
 *
 *   The basic workflow for using the stream interface is as follows:
 *
 *       1. initialize the state of your compression_stream object by calling
 *       compression_stream_init with the operation parameter set to specify
 *       whether you will be encoding or decoding, and the chosen algorithm
 *       specified by the algorithm parameter. This will allocate storage
 *       for the state that allows encoding or decoding to be resumed
 *       across calls.
 *
 *       2. set the dst_buffer, dst_size, src_buffer, and src_size fields of
 *       the compression_stream object to point to the next blocks to be
 *       processed.
 *
 *       3. call compression_stream_process. If no further input will be added
 *       to the stream via subsequent calls, finalize should be non-zero.
 *       If compression_stream_process returns COMPRESSION_STATUS_END, there
 *       will be no further output from the stream.
 *
 *       4. repeat steps 2 and 3 as necessary to process the entire stream.
 *
 *       5. call compression_stream_destroy to free the state object in the
 *       compression_stream.
 */

/*!
 *  @abstract         Initialize a compression_stream for
 *                    encoding (if operation is COMPRESSION_STREAM_ENCODE) or
 *                    decoding (if operation is COMPRESSION_STREAM_DECODE).
 *  @param stream     Pointer to the compression_stream object to be initialized.
 *  @param operation  Specifies whether the stream is to initialized for encoding or decoding.
 *                    Must be either COMPRESSION_STREAM_ENCODE or COMPRESSION_STREAM_DECODE.
 *  @param algorithm  The compression algorithm to be used.  Must be one of the values specified
 *                    in the compression_algorithm enum.
 *  @discussion       This call initializes all fields of the compression_stream to zero, except for state;
 *                    this routine allocates storage to capture the internal state of the encoding or decoding
 *                    process so that it may be resumed. This storage is tracked via the state parameter.
 *  @return           COMPRESSION_STATUS_OK if the stream was successfully initialized, or
 *                    COMPRESSION_STATUS_ERROR if an error occurred.
 */
typedef compression_status_t (*compression_stream_init_proc)
(compression_stream_t* stream,
    compression_stream_operation_t operation,
    compression_algorithm_t algorithm);

/*!
 *  @abstract Functionally equivalent to compression_stream_destroy then compression_stream_init, but keeps the allocated state buffer.
 *  @return   Status of the virtual compression_stream_init call
 */
typedef compression_status_t (*compression_stream_reinit_proc)
(compression_stream_t* stream,
    compression_stream_operation_t operation,
    compression_algorithm_t algorithm);

/*!
 *  @abstract   Cleans up state information stored in a compression_stream object.
 *  @discussion Use this to free memory allocated by compression_stream_init.  After calling
 *              this function, you will need to re-init the compression_stream object before
 *              using it again.
 */
typedef compression_status_t (*compression_stream_destroy_proc)
(compression_stream_t* stream);

/*!
 *  @abstract     Encodes or decodes a block of the stream.
 *  @param stream Pointer to the compression_stream object to be operated on.  Before calling
 *                this function, you must initialize the stream object by calling
 *                compression_stream_init, and setting the user-managed fields to describe your
 *                input and output buffers. When compression_stream_process returns, those
 *                fields will have been updated to account for the bytes that were successfully
 *                encoded or decoded in the course of its operation.
 *  @param flags  Binary OR of zero or more compression_stream_flags:
 *                COMPRESSION_STREAM_FINALIZE
 *                  If set, indicates that no further input will be added to the stream, and
 *                  thus that the end of stream should be indicated if the input block is
 *                  completely processed.
 *  @discussion   Processes the buffers described by the stream object until the source buffer
 *                becomes empty, or the destination buffer becomes full, or the entire stream is
 *                processed, or an error is encountered.
 *  @return       When encoding COMPRESSION_STATUS_END is returned only if all input has been
 *                read from the source, all output (including an end-of-stream marker) has been
 *                written to the destination, and COMPRESSION_STREAM_FINALIZE bit is set.
 *
 *                When decoding COMPRESSION_STATUS_END is returned only if all input (including
 *                and end-of-stream marker) has been read from the source, and all output has
 *                been written to the destination.
 *
 *                COMPRESSION_STATUS_OK is returned if all data in the source buffer is consumed,
 *                or all space in the destination buffer is used. In that case, further calls
 *                to compression_stream_process are expected, providing more data in the source
 *                buffer, or more space in the destination buffer.
 *
 *                COMPRESSION_STATUS_ERROR is returned if an error is encountered (if the
 *                encoded data is corrupted, for example).
 *
 *                When decoding a valid stream, the end of stream will be detected from the contents
 *                of the input, and COMPRESSION_STATUS_END will be returned in that case, even if
 *                COMPRESSION_STREAM_FINALIZE is not set, or more input is provided.
 *
 *                When decoding a corrupted or truncated stream, if COMPRESSION_STREAM_FINALIZE is not
 *                set to notify the decoder that no more input is coming, the decoder will not consume
 *                or produce any data, and return COMPRESSION_STATUS_OK.  In that case, the client code
 *                will call compression_stream_process again with the same state, entering an infinite loop.
 *                To avoid this, it is strongly advised to always set COMPRESSION_STREAM_FINALIZE when
 *                no more input is expected, for both encoding and decoding.
 */
typedef compression_status_t (*compression_stream_process_proc)
(compression_stream_t* stream, int flags);

/*!
 *  @abstract   Identify the compression algorithm for the first 4 bytes of compressed data.
 *  @param data Points to 4 bytes at the beginning of the compressed data.
 *  @discussion This call identifies the compression algorithm used to generate the given data bytes.
 *  @return     A valid compression_algorithm on success, or -1 if the data bytes do not correspond to any supported algorithm.
 */
typedef int (*compression_stream_identify_algorithm_proc)
(const uint8_t* data);

typedef struct{
	compression_stream_init_proc               compression_stream_init;
	compression_stream_reinit_proc             compression_stream_reinit;
	compression_stream_destroy_proc            compression_stream_destroy;
	compression_stream_process_proc            compression_stream_process;
	compression_stream_identify_algorithm_proc compression_stream_identify_algorithm;
} compression_ki_t;

__BEGIN_DECLS

/**
 * @abstract The compression interface that was registered.
 */
extern const compression_ki_t* compression_ki_ptr;

/**
 * @abstract   Registers the compression kext interface for use within the kernel proper.
 * @param ki   The interface to register.
 * @discussion This routine may only be called once and must be called before late-const has been applied to kernel memory.
 */
OS_EXPORT OS_NONNULL1
void compression_interface_register(const compression_ki_t *ki);

#if PRIVATE

typedef void (*registration_callback_t)(void);

void compression_interface_set_registration_callback(registration_callback_t callback);

#endif /* PRIVATE */

__END_DECLS

#endif // __COMPRESSION_H
