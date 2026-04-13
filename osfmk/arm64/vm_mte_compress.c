/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef COMPRESSOR_TESTER
// this file is included by the tester but having these includes there conflicts with the SDK includes
#include <pexpert/arm64/board_config.h>

#include <sys/cdefs.h> // for __improbable()
#include <string.h>
#include <kern/assert.h>

#include <vm/vm_compressor_xnu.h>
#endif // COMPRESSOR_TESTER

#if HAS_MTE
#include <arm64/mte.h>
#include "vm_mte_compress.h"

// Run Length Encoding (RLE) algorithm for compressing MTE tags
// ======================================
// MTE tags are compressed using a simple one-pass RLE (run-length encoding) compression algorithm
// The input is a buffer of 512 bytes representing the MTE tags of a 16k page (tag = nibble = 4 bits)
// The output is the success status of the compression and the compressed data buffer.
// The compressed data is made of a byte-aligned stream of commands, each command encodes either
// - A sequence of non-repeating tags (commands 0-3)
// - or a repeating run of a single tag (commands 4-F).
// Most commands are encoded by a single byte, except commands 1,2,3 which are encoded by a span of more than 1 byte.
// The MSB bits of the (first) byte of a command encodes the meaning of the command. There are 16 commands as defined
// in the comment table below.
// Example:
//   RLE: "01 42"   encodes "21 22" - 1 time the tag '1' and 3 times the tag '2'
//
// Some lengths of tag runs need to be encoded by a sequence of several commands.
// For instance "22 22 22 22 22 22 22 22 22 22" - a run of 20 instances of the tag "2" will be
// encoded by a sequence of 2 commands: A2 (repeat 16 times tag '2') 52 (repeat 4 times tag '2')
// Similarly, a sequence of 4 non-repeating tags for instance "12 34" will be encoded by
// a sequence of 2 commands: "12 14 (emit the 3 tags 2,1,4) 03 (emit the single tag 3)"
// In commands that spam more than 1 byte, the tags in are consumed and emitted LSB 4 bits first, then MSB 4 bits.
// Non-repeating commands may also encode short sequences of actually repeating commands for instance
// the sequence "33 3" may be encoded as non-repeating: 13 33 or repeating: 43, depending on the
// internal state of the compression.
//
// Considerations for the selection of commands:
// - The number of non-repeating tags that commands 0,1,2,3 emit is odd so that the command
// would always make a whole number of bytes and no bits are wasted.
// - The counts of repeat in the tag-repeating commands were selected to handle the wide
// variety of sizes of blocks possible in the input.
//
// The compressed MTE tags data encoded here is saved in the compressor segments after the WKDM compressed page data.
// WKDM compressed data must start at 64 byte alignment, so the size that the compressed MTE
// tags effectively take is rounded up to a multiple of 64 bytes. This means that the maximum compression ratio
// is 64/512=12.5%. A main goal of this compression is that this would also be the typical compressed
// tags size.
//
// The WKDMd (decompress) instruction caches in the 512 bytes that follow the buffer it decompresses in expectation
// of reading the tags data, see instruction documentation.
//
//   0 - Emit the next 1 nibble            // commands 0..3 are groups of non-repeating nibbles
//   1 - Emit the next 3 nibbles           //    encoded by 2 bytes
//   2 - Emit the next 5 nibbles           //    encoded by 3 bytes
//   3 - Emit the next 7 nibbles           //    encoded by 4 bytes
//   4 - Emit the next nibble 3 times      // command 4..15 are runs of the same nibble by varying repetition counts.
//   5 - Emit the next nibble 4 times
//   6 - Emit the next nibble 5 times
//   7 - Emit the next nibble 6 times
//   8 - Emit the next nibble 7 times
//   9 - Emit the next nibble 8 times
//   A(10) - Emit the next nibble 16 times
//   B(11) - Emit the next nibble 32 times
//   C(12) - Emit the next nibble 64 times
//   D(13) - Emit the next nibble 128 times
//   E(14) - Emit the next nibble 256 times
//   F(15) - Emit the next nibble 512 times

#define CMTE_MAX_NON_REPEATING 7
#define CMTE_LAST_NON_REPEAT_COMMAND 3
#define CMTE_FIRST_REPEAT_COMMAND 4
#define CMTE_MIN_REPEAT_IN_ONE_COMMAND 3
#define CMTE_MAX_REPEAT_IN_ONE_COMMAND 512

// map command to the number of tags it emits to output
static const uint16_t cmd_to_count[16] = {
	1, 3, 5, 7, // commands 0,1,2,3 are non-repeat commands, must be odd numbers
	3, 4, 5, 6, 7, 8, // commands 4,5,6,7,8,9 handle incrementing sizes
	16, 32, 64, 128, 256, 512 // commands A to F have longer jumps
};

// For a given non-repeat sequence length, what command should we start to encode with
static const int8_t non_repeat_count_to_cmd[CMTE_MAX_NON_REPEATING + 1] = {
	-1, // 0 count is not valid
	0, 0, // sequence of 1,2 non-repeating tags, use command 0 which handles 1 nibble
	1, 1, // sequence of 3,4 non-repeating tags, use command 1 which handles 3 nibbles (4 non-repeating will be followed by command 0)
	2, 2, // sequence of 5,6 non-repeating tags, use command 2 which handles 5 nibbles (6 non-repeating will be followed by command 0)
	3 // sequence of 7 non-repeating tags, use command 3 which handles 7 nibbles
};
// For a given repeat count, from what command should we start to encode the sequence with
// index is tag repeat count, value is command
static const int8_t repeat_count_to_cmd[CMTE_MAX_REPEAT_IN_ONE_COMMAND + 1] = {
	-1, // 0 repeats is not valid
	-1, -1, // 1,2 repeated are handled by non-repeat commands
	4, 5, 6, 7, 8, 9, // 3-8 repeats handled by commands 4-9
	9, 9, 9, 9, 9, 9, 9, // 9-15 repeats handled by command 9 which does 8 repeats
	10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, // 16-31 repeats handled by command 10 which does 16 repeats
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, // (32-47)
	11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, // (48-63) 32-63 repeats handled by command 11 which does 32 repeats
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, // (64-79)
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, // (80-95)
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, // (96-111)
	12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, // (112-127) 64-127 repeats handled by command 12 which does 64 repeats
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, // (128-159)
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, // (160-191)
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, // (192-223)
	13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, // (224-255) 128-255 repeats handled by command 13 which does 128 repeats
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // ...
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // (256-319)
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // ...
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // (320-383)
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // ...
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // (384-447)
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // ...
	14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, // (448-511) 256-511 repeats handled by command 14 which does 256 repeats
	15 // 512 repeats and upwards are handled by command 15 which does 512 repeats
};

#define CMTE_INVALID_TAG 0xFF

// if the compress output is bigger than this, stop trying to compress and go for the memcpy option
// This is because in the compressed segments the WKDMc output is aligned to 64 byte so if we passed the (512-64) byte
// mark we might as well memcpy the entire 512 bytes and have easy time on decompress
#define CMTE_RESIGN_COMPRESS_SIZE (C_MTE_SIZE - C_SEG_OFFSET_ALIGNMENT_BOUNDARY)

struct run_length_state {
	// current run-length we're handling
	uint32_t cur_count; // 0 means we handled it all
	uint8_t cur_tag;

	// scratch-pad for non-repeating command
	uint8_t scratch[CMTE_MAX_NON_REPEATING];
	uint32_t scratch_len; // 0 means it's empty
	// offset of next byte to write to the output buffer
	uint32_t out_offset;
};

// return:
// - C_MTE_SIZE: if the input is incompressible, input copied to output
// - C_MTE_SIZE + 1 + tag: if the entire input has the same tag
// - size (lower than C_MTE_SIZE): input was compressed to size
uint32_t
vm_mte_rle_compress_tags(uint8_t *tags_in_buf, uint32_t in_size, uint8_t *out_buf, __assert_only uint32_t out_size)
{
	// worst case we're going to need this much size.
	// if it's uncompressible, we'll need at least the in size
	assert(out_size >= C_MTE_SIZE && out_size >= in_size);
	assert(in_size == C_MTE_SIZE);

	struct run_length_state s = {};
	struct run_length_state *s_ptr = &s; // avoid using __block which prevents some optimizations

#define OUTPUT_BYTE(b) do { \
	    if (__improbable(s_ptr->out_offset + 1 >= CMTE_RESIGN_COMPRESS_SIZE))  \
	        return false; \
	    out_buf[s_ptr->out_offset++] = (b); \
    } while(false)

	// this is done in a block since it needs to happen in the loop that goes over nibbles and at the end of the loop
	// return false if we ran out of output buffer
	bool (^process_tag)(bool) = ^bool (bool is_final) {
		// if it's the final call, we need to flush the scratch pad no matter what
		while (s_ptr->cur_count > 0 || (is_final && s_ptr->scratch_len > 0)) { // this will do at most 2 loops
			bool do_emit_scratch = false;
			// is it a run shorter than the shortest repeat command && we can add to cur to scratch without overflowing it?
			// for runs longer, always prefer to emit repeat command
			if (s_ptr->cur_count < CMTE_MIN_REPEAT_IN_ONE_COMMAND && s_ptr->scratch_len + s_ptr->cur_count <= CMTE_MAX_NON_REPEATING) {
				// adding to the scratch would not be above the maximum we can emit in one non-repeat command
				for (uint32_t i = 0; i < s_ptr->cur_count; ++i) {
					s_ptr->scratch[s_ptr->scratch_len++] = s_ptr->cur_tag;
				}
				s_ptr->cur_count = 0; // we just handled all of cur so reset it
				if (s_ptr->scratch_len == CMTE_MAX_NON_REPEATING || is_final) {
					// if it reached the size of scratch, need to emit scratch
					do_emit_scratch = true;
				}
			} else {
				// can't add to scratch because that would be beyond the allowed size in the scratch
				if (s_ptr->scratch_len > 0) {
					do_emit_scratch = true;
				}
			}

			if (do_emit_scratch) {
				// we may emit several non-repeat command, this keeps track of where we are in the scratch buffer
				uint32_t scratch_offset = 0;
				while (s_ptr->scratch_len > 0) {
					// scratch has at least 1. first byte is the (non-repeat) command and the first nibble
					int8_t cmd = non_repeat_count_to_cmd[s_ptr->scratch_len];
					assert(cmd >= 0 && cmd <= CMTE_LAST_NON_REPEAT_COMMAND);
					uint8_t out_byte = (uint8_t)((uint8_t)cmd << 4) | s_ptr->scratch[scratch_offset++];
					OUTPUT_BYTE(out_byte);
					uint32_t consume_count = cmd_to_count[cmd]; // how many more tags to output?
					assert(consume_count <= s_ptr->scratch_len);
					// next bytes are the additional nibbles for the non-repeat command
					uint32_t scratch_i = 1; // skip 0 which was already written
					for (; scratch_i < consume_count; scratch_i += 2) {
						out_byte = s_ptr->scratch[scratch_offset++];
						out_byte |= s_ptr->scratch[scratch_offset++] << 4;
						OUTPUT_BYTE(out_byte);
					}
					s_ptr->scratch_len -= consume_count;
				}
			}

			// now emit the cur as a series of repeating commands
			while (s_ptr->cur_count >= CMTE_MIN_REPEAT_IN_ONE_COMMAND) {
				int8_t cmd;
				if (s_ptr->cur_count > CMTE_MAX_REPEAT_IN_ONE_COMMAND) {
					cmd = repeat_count_to_cmd[CMTE_MAX_REPEAT_IN_ONE_COMMAND];
				} else {
					cmd = repeat_count_to_cmd[s_ptr->cur_count];
				}
				// reached a length that's not handled by a repeat command, shouldn't happen
				assert(cmd >= CMTE_FIRST_REPEAT_COMMAND);

				uint8_t out_byte = (uint8_t)((uint8_t)cmd << 4) | s_ptr->cur_tag;
				OUTPUT_BYTE(out_byte);

				// handled some of the length of the current run
				uint32_t consumed_count = cmd_to_count[cmd];
				assert(consumed_count <= s_ptr->cur_count); // consumed too much, shouldn't happen
				s_ptr->cur_count -= consumed_count;
			}
			// there might be still a few repeats left in cur, next iteration of the while loop will handle it via
			// the scratch path
		}
		return true;
	}; // process_tag()

	// first level goes over bytes
	for (uint32_t byte_i = 0; byte_i < in_size; ++byte_i) {
		uint8_t b = tags_in_buf[byte_i];
		uint8_t tag = b & 0xF;
		// second level iterates over 4 bit nibbles
		for (int nibble_i = 0; nibble_i < 2; ++nibble_i) {
			// third level counts the run length of equal nibbles
			if (tag == s.cur_tag) {
				// add to the current run-length
				++s.cur_count;
			} else {
				// previous run-length finished, process it
				// fourth level decides what to do with each run-length
				if (!process_tag(false)) {
					goto too_long;
				}

				// done handling the just-ended run, now create a new run in cur
				s.cur_tag = tag;
				s.cur_count = 1;
			}

			tag = b >> 4;
		}
	}

	if (s.out_offset == 0 && s.scratch_len == 0) {
		// the entire buffer was a single run of the same nibble value, return special value to indicate that along
		// with the repeating tag (single-tag optimization)
		return C_MTE_SIZE + 1 + s.cur_tag;
	}
	// process anything remaining in cur or in scratch
	if (!process_tag(true)) {
		goto too_long;
	}
	assert(s.scratch_len == 0);

	// normal case - return how many bytes were written to the compressed output
	return (uint32_t)s.out_offset;

too_long:
	memcpy(out_buf, tags_in_buf, in_size);
	return C_MTE_SIZE;
#undef OUTPUT_BYTE
}

// convert the return value of vm_mte_rle_compress_tags() to the actual size written to the buffer
uint32_t
vm_mte_compressed_tags_actual_size(uint32_t mte_size)
{
	if (mte_size <= C_MTE_SIZE) {
		return mte_size;
	}
	return 0;
}

// parse an RLE encoded compressed buffer and decompress it
// in_size is the return value of rle_compress_mte_tags()
// return true on success, false if input is malformed
bool
vm_mte_rle_decompress_tags(uint8_t *in_buf, uint32_t in_size, uint8_t *tags_out_buf, __assert_only uint32_t out_size)
{
	assert(out_size == C_MTE_SIZE);
	if (in_size == C_MTE_SIZE) {
		memcpy(tags_out_buf, in_buf, in_size);
		return true;
	}
	if (in_size > C_MTE_SIZE) { // same tag optimization
		assert(in_size <= C_SLOT_C_MTE_SIZE_MAX);
		uint8_t tag = (in_size & 0xF) - 1;
		uint8_t dbl_tag = tag | (uint8_t)(tag << 4);
		memset(tags_out_buf, dbl_tag, C_MTE_SIZE);
		// possible optimization: don't need to fill the buffer to do the eventual STGMs
		return true;
	}

	uint32_t out_offset = 0;
	uint8_t part_byte = CMTE_INVALID_TAG;
#define OUTPUT_TAG(t) do { \
	if (__improbable(out_offset >= C_MTE_SIZE)) \
	    return false; \
	if (part_byte == CMTE_INVALID_TAG) \
	    part_byte = (t); \
	else { \
	    tags_out_buf[out_offset++] = part_byte | (uint8_t)((t) << 4); \
	    part_byte = CMTE_INVALID_TAG; \
	} \
    } while(false)

	// process commands one by one
	uint32_t in_offset = 0;
	while (in_offset < in_size) {
		uint8_t in_byte = in_buf[in_offset++];
		uint8_t cmd = in_byte >> 4;
		if (cmd < CMTE_FIRST_REPEAT_COMMAND) {
			// it's a non-repeat command
			uint8_t first_tag = in_byte & 0xF;
			OUTPUT_TAG(first_tag);
			int32_t nonrpt_i = cmd_to_count[cmd] - 1; // number of tags we still need to read
			assert(nonrpt_i % 2 == 0); // sanity
			for (; nonrpt_i > 0; nonrpt_i -= 2) {
				if (__improbable(in_offset >= in_size)) {
					return false; // no more bytes to read (encoding error)
				}
				uint8_t in_byte2 = in_buf[in_offset++];
				OUTPUT_TAG(in_byte2 & 0xF);
				OUTPUT_TAG(in_byte2 >> 4);
			}
		} else {
			// it's a repeat command
			uint8_t tag = in_byte & 0xF;
			uint32_t repeat = cmd_to_count[cmd];
			// sanity check for cmd_to_count table
			assert(repeat >= CMTE_MIN_REPEAT_IN_ONE_COMMAND && repeat <= CMTE_MAX_REPEAT_IN_ONE_COMMAND);
			if (part_byte != CMTE_INVALID_TAG) {
				// we have a byte in progress, need emit one tag of this run to finish this byte before memset
				OUTPUT_TAG(tag);
				repeat -= 1;
			}
			uint32_t fill_sz = repeat / 2;
			if (__improbable(out_offset + fill_sz > C_MTE_SIZE)) {
				return false; // overflow
			}
			if (fill_sz > 0) {
				uint8_t dbl_tag = tag | (uint8_t)(tag << 4);
				memset(tags_out_buf + out_offset, dbl_tag, fill_sz);
				out_offset += fill_sz;
			}
			// do we need to add the extra one for an odd repeat count
			if ((repeat % 2) != 0) {
				OUTPUT_TAG(tag);
			}
		}
	}
	// make sure we output exactly the expected amount and no partial byte pending
	//   (first condition can't be reached since we would bail before so this is here for sanity)
	if (__improbable(out_offset != C_MTE_SIZE || part_byte != CMTE_INVALID_TAG)) {
		return false;
	}
	return true;
#undef OUTPUT_TAG
}

#if DEVELOPMENT || DEBUG
// parse an RLE encoded compressed buffer and increment a commands histogram
// this is used by the tester
bool
vm_mte_rle_comp_histogram(uint8_t *in_buf, uint32_t in_size, struct comp_histogram *hist)
{
	if (in_size > C_MTE_SIZE) { // same tag optimization
		assert(in_size <= C_SLOT_C_MTE_SIZE_MAX);
		hist->same_value_count++;
		return true;
	}
	assert(in_size > 0);
	hist->comp_size_bins[(in_size - 1) / C_SEG_OFFSET_ALIGNMENT_BOUNDARY]++;

	if (in_size == C_MTE_SIZE) { // not compressed
		return true;
	}

	// process commands one by one
	uint32_t in_offset = 0;
	while (in_offset < in_size) {
		uint8_t in_byte = in_buf[in_offset++];
		uint8_t cmd = in_byte >> 4;
		hist->cmd_bins[cmd]++;
		hist->cmd_total++;
		if (cmd < CMTE_FIRST_REPEAT_COMMAND) {
			// it's a non-repeat command
			int32_t nonrpt_i = cmd_to_count[cmd] - 1; // number of tags we still need to read
			assert(nonrpt_i % 2 == 0); // sanity
			for (; nonrpt_i > 0; nonrpt_i -= 2) {
				if (__improbable(in_offset >= in_size)) {
					return false; // no more bytes to read (encoding error)
				}
				in_offset++;
			}
		} else {
			// it's a repeat command, only 1 byte
		}
	}
	return true;
}

void
vm_mte_rle_runs_histogram(uint8_t *tags_in_buf, uint32_t in_size, struct runs_histogram *hist)
{
	assert(in_size == C_MTE_SIZE);

	struct run_length_state s = {};
	struct run_length_state *s_ptr = &s; // avoid using __block which prevents some optimizations

	// this is done in a block since it needs to happen in the loop that goes over nibbles and at the end of the loop
	// return false if we ran out of output buffer
	void (^process_tag)() = ^void () {
		if (s_ptr->cur_count == 0) {
			return; // first time
		}
		assert(s_ptr->cur_count <= VM_MTE_C_MAX_TAG_RUN);
		hist->rh_bins[s_ptr->cur_count]++;
	}; // process_tag()

	// first level goes over bytes
	for (uint32_t byte_i = 0; byte_i < in_size; ++byte_i) {
		uint8_t b = tags_in_buf[byte_i];
		uint8_t tag = b & 0xF;
		// second level iterates over 4 bit nibbles
		for (int nibble_i = 0; nibble_i < 2; ++nibble_i) {
			// third level counts the run length of equal nibbles
			if (tag == s.cur_tag) {
				// add to the current run-length
				++s.cur_count;
			} else {
				// previous run-length finished, process it
				// fourth level decides what to do with each run-length
				process_tag();

				// done handling the just-ended run, now create a new run in cur
				s.cur_tag = tag;
				s.cur_count = 1;
			}
			tag = b >> 4;
		}
	}

	// process anything remaining in cur or in scratch
	process_tag();
}


#endif /* DEVELOPMENT || DEBUG */

#ifndef COMPRESSOR_TESTER // compressor_tags_stats is not defined in the tester

SCALABLE_COUNTER_DEFINE(compressor_tagged_pages_compressed);
// different reasons why tagged pages were removed from the compressor
SCALABLE_COUNTER_DEFINE(compressor_tagged_pages_decompressed);
SCALABLE_COUNTER_DEFINE(compressor_tagged_pages_freed);
SCALABLE_COUNTER_DEFINE(compressor_tagged_pages_corrupted);
// current number of bytes taken by compressed tags in the compressor
SCALABLE_COUNTER_DEFINE(compressor_tags_overhead_bytes);
// current number of tagged pages that reside in the compressor
SCALABLE_COUNTER_DEFINE(compressor_tagged_pages);
// current number of tag storage pages composing the compressor pool
SCALABLE_COUNTER_DEFINE(compressor_tag_storage_pages_in_pool);
// current number of non-tag storage pages composing the compressor pool
SCALABLE_COUNTER_DEFINE(compressor_non_tag_storage_pages_in_pool);
// the following is a breakdown of tagged_pages_compressed
#if DEVELOPMENT || DEBUG
SCALABLE_COUNTER_DEFINE(compressor_tags_all_zero);
SCALABLE_COUNTER_DEFINE(compressor_tags_same_value);
SCALABLE_COUNTER_DEFINE(compressor_tags_below_align);
SCALABLE_COUNTER_DEFINE(compressor_tags_above_align);
SCALABLE_COUNTER_DEFINE(compressor_tags_incompressible);
#endif /* DEVELOPMENT || DEBUG */

#if DEVELOPMENT || DEBUG
// don't want to expose in release counters which may indirectly expose tag information
#define debug_counter_inc(c) counter_inc(c)
#else /* DEVELOPMENT || DEBUG */
#define debug_counter_inc(c)
#endif /* DEVELOPMENT || DEBUG */

void
vm_mte_tags_stats_compressed(uint32_t size_written)
{
	counter_inc(&compressor_tagged_pages_compressed);
	bool add_overhead = false;

	// 64 bytes is the minimum space compressed tags can take since that's the alignment requirement of wkdmc output
	// so even if the tags are compressed to 1 byte, it's still going to take 64 bytes in the segment
	if (size_written < C_SEG_OFFSET_ALIGNMENT_BOUNDARY) {
		debug_counter_inc(&compressor_tags_below_align);
		add_overhead = true;
	} else if (size_written == C_MTE_SIZE) {
		debug_counter_inc(&compressor_tags_incompressible);
		add_overhead = true;
	} else if (size_written == C_MTE_SIZE + 1) {
		// same-value indicator + tag == 0
		debug_counter_inc(&compressor_tags_all_zero);
	} else if (size_written > C_MTE_SIZE) {
		// just same-value indicator
		debug_counter_inc(&compressor_tags_same_value);
	} else {
		debug_counter_inc(&compressor_tags_above_align);
		add_overhead = true;
	}

	if (add_overhead) {
		uint64_t rounded = C_SEG_ROUND_TO_ALIGNMENT(size_written);
		counter_add(&compressor_tags_overhead_bytes, rounded);
	}
	counter_inc(&compressor_tagged_pages);
}

void
vm_mte_tags_stats_removed(uint32_t mte_size, vm_mte_c_tags_removal_reason_t reason)
{
	switch (reason) {
	case VM_MTE_C_TAGS_REMOVAL_DECOMPRESSED:
		counter_inc(&compressor_tagged_pages_decompressed);
		break;
	case VM_MTE_C_TAGS_REMOVAL_FREE:
		counter_inc(&compressor_tagged_pages_freed);
		break;
	case VM_MTE_C_TAGS_REMOVAL_CORRUPT:
		counter_inc(&compressor_tagged_pages_corrupted);
		break;
	default:
		panic("Unexpected compressor tags removal reason %u", reason);
	}

	if (mte_size <= C_MTE_SIZE) { // same-tag optimization doesn't take any buffer space
		uint64_t rounded = C_SEG_ROUND_TO_ALIGNMENT(mte_size);
		counter_add(&compressor_tags_overhead_bytes, -(uint64_t)rounded);
	}
	counter_dec(&compressor_tagged_pages);
}

#endif // COMPRESSOR_TESTER
#endif // HAS_MTE
