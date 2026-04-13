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

#include <arm_acle.h>
#include <libproc.h>
#include <signal.h>
#include <spawn_private.h>
#include <stddef.h>
#include <stdlib.h>

#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>

#include <darwintest.h>

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#define HAS_MTE 1

#include <vm/vm_compressor_info.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("s_shalom"),
	T_META_RUN_CONCURRENTLY(false) /* test is sampling global sysctls */
	);

/*
 * This test exercises internal functions that compress and decompress the MTE buffers
 * These functions are not accessible from outside the kernel, so we include them here verbatim.
 * In the future when user-land unit-test that runs kernel code we can move this there.
 */
#define COMPRESSOR_TESTER 1
#define DEVELOPMENT 1

// these need to be redefined since getting them from the XNU headers would create include conflicts
#define C_MTE_SIZE 512
#define C_SEG_OFFSET_ALIGNMENT_MASK (0x3FULL)
#define C_SEG_OFFSET_ALIGNMENT_BOUNDARY  (64)

#define C_SLOT_EXTRA_METADATA           16            /* 16 possible tags */
#define C_SLOT_C_MTE_SIZE_MAX           (C_MTE_SIZE + C_SLOT_EXTRA_METADATA + 1)

#define VM_MEMTAG_PTR_SIZE         56
#define VM_MEMTAG_TAG_SIZE          4
#define VM_MEMTAG_UPPER_SIZE        4
#define VM_MEMTAG_BYTES_PER_TAG    16

#define C_SEG_ROUND_TO_ALIGNMENT(offset) \
	(((offset) + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK)

#define __assert_only                   __unused

#include "../osfmk/arm64/vm_mte_compress.c"

// masks only the tags bits out of a pointer
#define TAG_MASK (((1UL << VM_MEMTAG_TAG_SIZE) - 1UL) << VM_MEMTAG_PTR_SIZE)


static void
show_buf_diff(const uint8_t* a, const uint8_t* b, size_t sz)
{
	for (uint32_t i = 0; i < sz; ++i) {
		if (a[i] != b[i]) {
			T_LOG("  byte diff at %u : %d != %d", i, (int)a[i], (int)b[i]);
			break;
		}
	}
}

// expected results of vm_mte_rle_compress_tags()
#define CASE_UNKNOWN 0
#define CASE_NON_COMP 1
#define CASE_SINGLE_TAG 2
#define CASE_NORMAL 3

static uint32_t
test_compress_decompress_eq(const uint8_t *buf, const char *desc, int expect_case)
{
	uint8_t compressed[C_MTE_SIZE] = {};
	uint32_t compressed_size = vm_mte_rle_compress_tags((uint8_t *)buf, C_MTE_SIZE, compressed, C_MTE_SIZE);
	if ((expect_case == CASE_NON_COMP && compressed_size != C_MTE_SIZE) ||
	    (expect_case == CASE_SINGLE_TAG && compressed_size <= C_MTE_SIZE) ||
	    (expect_case == CASE_NORMAL && compressed_size >= C_MTE_SIZE)) {
		T_ASSERT_FAIL("case %s", desc);
	}

	uint8_t decompressed[C_MTE_SIZE] = {};
	bool ret = vm_mte_rle_decompress_tags(compressed, compressed_size, decompressed, C_MTE_SIZE);
	if (!ret) {
		show_buf_diff(buf, decompressed, C_MTE_SIZE);
		T_ASSERT_FAIL("decompress return %s", desc);
	}

	if (memcmp((char*)buf, (char*)decompressed, C_MTE_SIZE) != 0) {
		show_buf_diff(buf, decompressed, C_MTE_SIZE);
		T_ASSERT_FAIL("decompress equal original %s", desc);
	} else {
		bool quiet = (desc[0] == '_'); // don't want to spam the console during the many random runs
		if (quiet) {
			T_QUIET;
		}
		T_PASS("OK %s  (size=%u)", desc, compressed_size);
	}

	return compressed_size;
}


static void
simple_tests(void)
{
	uint8_t buf[C_MTE_SIZE] = {};
	test_compress_decompress_eq(buf, "zeros", CASE_SINGLE_TAG);

	buf[0] = 0x01;
	test_compress_decompress_eq(buf, "simple 1", CASE_NORMAL);

	memset(buf, 0x22, C_MTE_SIZE);
	test_compress_decompress_eq(buf, "twos", CASE_SINGLE_TAG);

	buf[0] = 0x21;
	test_compress_decompress_eq(buf, "simple 2", CASE_NORMAL);

	buf[0] = 0x01;
	test_compress_decompress_eq(buf, "simple 3", CASE_NORMAL);

	buf[0] = 0x11;
	test_compress_decompress_eq(buf, "simple 4", CASE_NORMAL);

	buf[0] = 0x31;
	test_compress_decompress_eq(buf, "simple 5", CASE_NORMAL);

	buf[1] = 0x01;
	test_compress_decompress_eq(buf, "simple 6", CASE_NORMAL);

	buf[0] = 0x11;
	buf[1] = 0x11;
	test_compress_decompress_eq(buf, "simple 7", CASE_NORMAL);

	buf[2] = 0x01;
	test_compress_decompress_eq(buf, "simple 8", CASE_NORMAL);

	buf[2] = 0x11;
	test_compress_decompress_eq(buf, "simple 9", CASE_NORMAL);

	buf[3] = 0x01;
	test_compress_decompress_eq(buf, "simple 10", CASE_NORMAL);

	buf[3] = 0x11;
	test_compress_decompress_eq(buf, "simple 11", CASE_NORMAL);

	buf[3] = 0x21;
	test_compress_decompress_eq(buf, "simple 12", CASE_NORMAL);

	buf[3] = 0x12;
	test_compress_decompress_eq(buf, "simple 13", CASE_NORMAL);

	memset(buf, 0x22, C_MTE_SIZE);
	buf[255] = 0x01;
	test_compress_decompress_eq(buf, "simple 14", CASE_NORMAL);
	buf[255] = 0x21;
	test_compress_decompress_eq(buf, "simple 15", CASE_NORMAL);
	buf[255] = 0x12;
	test_compress_decompress_eq(buf, "simple 16", CASE_NORMAL);

	for (int i = 0; i < C_MTE_SIZE; ++i) {
		buf[i] = i % 16;
	}
	test_compress_decompress_eq(buf, "non-comp", CASE_NON_COMP);

	memset(buf, 0x22, C_MTE_SIZE);
	buf[0] = 0x11;
	buf[1] = 0x01;
	buf[2] = 0x10;
	buf[3] = 0x11;
	buf[4] = 0x01;
	buf[5] = 0x00;
	test_compress_decompress_eq(buf, "simple 17", CASE_NORMAL);
}

// run compress-decompress with input generated by the given callback
static void
gen_test(const char* name, int num_runs, int min_opt, int max_opt, void (^generate)(uint8_t *buf, int num_options))
{
	uint8_t buf[C_MTE_SIZE] = {};
	uint32_t count_incomp = 0, count_normal = 0, count_single = 0;
	uint64_t sum_normal = 0;

	for (int num_options = min_opt; num_options <= max_opt; ++num_options) {
		for (int run = 0; run < num_runs; ++run) {
			generate(buf, num_options);

			uint32_t sz = test_compress_decompress_eq(buf, name, CASE_UNKNOWN);
			if (sz == C_MTE_SIZE) {
				count_incomp++;
			} else if (sz < C_MTE_SIZE) {
				count_normal++;
				sum_normal += sz;
			} else {
				count_single++;
			}
		}
	}

	T_LOG("%s: incompressible:%u  normal:%u (avg=%llu) sv:%u", name, count_incomp, count_normal, sum_normal / count_normal, count_single);
}

static uint32_t rng_state = 0;
static void
my_srand(uint32_t seed)
{
	rng_state = seed;
}
static uint32_t
my_rand()
{
	rng_state = (rng_state * 1103515245) + 12345;
	uint32_t r = (rng_state >> 15);
	return r;
}


// fill a tags buffer with tags with values up to `num_options`
static void
random_tags_buf(uint8_t *buf, int num_options)
{
	T_QUIET; T_ASSERT_TRUE(num_options > 0 && num_options <= 16, "unexpected num_options");
	for (int i = 0; i < C_MTE_SIZE; ++i) {
		uint8_t tag1 = (uint8_t)(my_rand() % num_options);
		uint8_t tag2 = (uint8_t)(my_rand() % num_options);
		buf[i] = (uint8_t)((tag1 << 4) | tag2);
	}
}

// fill a tags buffer with runs of tags with values up to `num_options` and up to `max_run` long
static void
random_tag_runs_buf(uint8_t *buf, int num_options, int max_run)
{
	T_QUIET; T_ASSERT_GE(max_run, 1, "unexpected max_runs"); // sanity
	T_QUIET; T_ASSERT_TRUE(num_options > 0 && num_options <= 16, "unexpected num_options");

	uint8_t cur_tag = 0;
	int cur_run = 0;
	int cur_repeat = 0; // will be set on the first iteration
	for (int i = 0; i < C_MTE_SIZE; ++i) {
		uint8_t tags[2];
		for (int ti = 0; ti < 2; ++ti) {
			if (cur_run == cur_repeat) {
				cur_repeat = (my_rand() % max_run) + 1;
				cur_tag = (uint8_t)(my_rand() % num_options);
				cur_run = 0;
			}
			tags[ti] = cur_tag;
			++cur_run;
		}
		buf[i] = (uint8_t)((tags[1] << 4) | tags[0]);
	}
}

#define TAGS_IN_PAGE (C_MTE_SIZE * 2)

// fill a buffer with the tags of the same repeat count
static void
same_repeat_buf(uint8_t *buf, int num_repeat)
{
	T_QUIET; T_ASSERT_TRUE(num_repeat >= 1 && num_repeat <= TAGS_IN_PAGE, "unexpected num_options");
	uint8_t cur_tag = 0;
	int cur_run = 0;
	for (int i = 0; i < C_MTE_SIZE; ++i) {
		uint8_t tags[2];
		for (int ti = 0; ti < 2; ++ti) {
			if (cur_run == num_repeat) {
				cur_tag = (cur_tag + 1) % 0xf;
				cur_run = 0;
			}
			tags[ti] = cur_tag;
			++cur_run;
		}
		buf[i] = (uint8_t)((tags[1] << 4) | tags[0]);
	}
}

// fill a buffer with the same tag
static void
same_tag_buf(uint8_t *buf, int num_options)
{
	T_QUIET; T_ASSERT_TRUE(num_options >= 0 && num_options <= 16, "unexpected num_options");
	for (int i = 0; i < C_MTE_SIZE; ++i) {
		uint8_t tag = num_options;
		buf[i] = (uint8_t)((tag << 4) | tag);
	}
}

static void
random_bytes_test(void)
{
	my_srand(0);
	gen_test("_rand_bytes", 10000, 2, 16, ^void (uint8_t *buf, int num_options) {
		random_tags_buf(buf, num_options);
	});
}

static void
random_runs_test(int max_run)
{
	my_srand(0);
	gen_test("_rand_runs", 10000, 2, 16, ^void (uint8_t *buf, int num_options) {
		random_tag_runs_buf(buf, num_options, max_run);
	});
}

static void
same_tag_test(void)
{
	gen_test("_same_tag", 1, 0, 16, ^void (uint8_t *buf, int num_options) {
		same_tag_buf(buf, num_options);
	});
}

static void
every_repeat_len(void)
{
	gen_test("_every_repeat", 1, 1, TAGS_IN_PAGE, ^void (uint8_t *buf, int num_options) {
		same_repeat_buf(buf, num_options);
	});
}

T_DECL(mte_compress_tags,
    "Test the MTE tags buffer compression and decompression functions")
{
	simple_tests();
	random_bytes_test();
	random_runs_test(C_MTE_SIZE);
	random_runs_test(C_MTE_SIZE / 2);
	random_runs_test(20);
	random_runs_test(3);
	same_tag_test();
	every_repeat_len();
}


static void
test_malformed(const uint8_t* compressed, uint32_t compressed_size, bool expected, const char* desc, uint32_t desc_arg)
{
	char decompressed[C_MTE_SIZE] = {};
	bool ret = vm_mte_rle_decompress_tags((uint8_t*)compressed, compressed_size, (uint8_t*)decompressed, C_MTE_SIZE);
	T_QUIET; T_ASSERT_EQ(ret, expected, "malformed decompressed %s %d", desc, desc_arg);
	T_PASS("OK %s %d", desc, desc_arg);
}

static void
simple_malformed(void)
{
	uint8_t buf[C_MTE_SIZE] = {};

	buf[0] = 0x01;
	test_malformed(buf, 1, false, "underflow only 1 byte output", 0);

	buf[0] = 0xF1;
	buf[1] = 0xF2; // filled 1024 nibbles
	test_malformed(buf, 2, true, "no overflow at edge", 0);

	// filled all the output, but there's another command that would overflow
	buf[2] = 0x03;
	test_malformed(buf, 3, false, "overflow by 1 nibble", 0);

	for (uint32_t i = 1; i <= 0xF; ++i) {
		buf[2] = (uint8_t)(0x3 | (i << 4)); // every command should cause overflow
		test_malformed(buf, 3, false, "overflow at edge", i);
	}

	buf[0] = 0xF1; // 512
	buf[1] = 0xE2; // + 256
	buf[2] = 0xD3; // + 128
	buf[3] = 0xC4; // + 64
	buf[4] = 0xB5; // + 32
	buf[5] = 0xA6; // + 16
	buf[6] = 0x97; // + 8
	buf[7] = 0x78; // + 6 = filled 1022 nibbles
	test_malformed(buf, 8, false, "underflow missing 2 nibbles", 0);
	buf[7] = 0x88; // + 7 = filled 1023 nibbles
	test_malformed(buf, 8, false, "underflow missing 1 nibble", 0);
	buf[8] = 0x09; // + 1 = filled 1024 nibbles
	test_malformed(buf, 9, true, "no overflow from mid", 0);

	for (uint32_t i = 1; i <= 0xF; ++i) {
		buf[8] = (uint8_t)(0x9 | (i << 4));
		test_malformed(buf, 9, false, "overflow at mid", i);
	}
}

static void
random_malformed(int num_runs)
{
	uint8_t buf[C_MTE_SIZE] = {};
	int fail = 0, success = 0;
	my_srand(0);
	for (int run = 0; run < num_runs; ++run) {
		// fill buf with random bytes
		uint32_t sz = my_rand() % C_MTE_SIZE;
		for (uint32_t i = 0; i < sz; ++i) {
			buf[i] = my_rand() % 0xFF;
		}

		uint8_t decompressed[C_MTE_SIZE] = {};
		bool ret = vm_mte_rle_decompress_tags(buf, sz, decompressed, C_MTE_SIZE);
		// don't know if it's going to succeed or fail.
		// we're testing that it doesn't assert or hang
		if (ret) {
			++success;
		} else {
			++fail;
		}
	}
	T_QUIET; T_ASSERT_TRUE(fail > num_runs * 0.9 && fail < num_runs, "too many succeeded or failed %u,%u", success, fail);
	T_PASS("OK random %u success, %u fail", success, fail);
}

T_DECL(mte_decompress_malformed,
    "Test that tags decompress returns an error")
{
	simple_malformed();
	random_malformed(1000000);
}


// This test isn't really useful for automatic testing, so it is disabled. It is useful for on-desk testing
// while trying to optimize these functions. For full optimization add this to the Makefile:
//   arm_mte_compress: CFLAGS += -O3
T_DECL(mte_compress_tags_perf,
    "Test formance of MTE tags compression",
    T_META_ENABLED(false))
{
	my_srand(0);
	// compress worst case - random data of tags [0-F]
	uint8_t buf[C_MTE_SIZE] = {};
	random_tags_buf(buf, 16);
	uint8_t compressed[C_MTE_SIZE] = {};
	uint32_t compressed_size = 0;

	// warmup cache
	for (uint32_t i = 0; i < 50; ++i) {
		compressed_size = vm_mte_rle_compress_tags((uint8_t *) buf, C_MTE_SIZE, compressed, C_MTE_SIZE);
	}
	T_LOG("compressed_size=%u", compressed_size);

	uint64_t startns = clock_gettime_nsec_np(CLOCK_MONOTONIC);

	for (uint32_t i = 0; i < 300000; ++i) {
		compressed_size = vm_mte_rle_compress_tags((uint8_t *) buf, C_MTE_SIZE, compressed, C_MTE_SIZE);
	}
	uint64_t elapsed = clock_gettime_nsec_np(CLOCK_MONOTONIC) - startns;
	T_LOG("perf compress took: %llu msec", elapsed / NSEC_PER_MSEC);

	T_PASS("OK");
}

T_DECL(mte_decompress_tags_perf,
    "Test formance of MTE tags compression",
    T_META_ENABLED(false))
{
	my_srand(0);
	uint8_t buf[C_MTE_SIZE] = {};
	random_tag_runs_buf(buf, 16, 4);

	uint8_t compressed[C_MTE_SIZE] = {};
	uint32_t compressed_size = vm_mte_rle_compress_tags((uint8_t *) buf, C_MTE_SIZE, compressed, C_MTE_SIZE);
	T_LOG("compressed_size=%u", compressed_size);
	// verify it's doing a decent amount of work
	T_QUIET; T_ASSERT_TRUE(compressed_size < C_MTE_SIZE && compressed_size > C_MTE_SIZE / 5 * 4, "compressed to unexpected size %u", compressed_size);

	uint8_t decompressed[C_MTE_SIZE] = {};
	bool ret = 0;

	uint64_t startns = clock_gettime_nsec_np(CLOCK_MONOTONIC);
	for (uint32_t i = 0; i < 300000; ++i) {
		ret = vm_mte_rle_decompress_tags(compressed, compressed_size, (uint8_t*)decompressed, C_MTE_SIZE);
	}

	uint64_t elapsed = clock_gettime_nsec_np(CLOCK_MONOTONIC) - startns;
	T_QUIET; T_ASSERT_TRUE(ret, "decompress failed");
	T_LOG("perf decompress took: %llu msec", elapsed / NSEC_PER_MSEC);

	T_PASS("OK");
}

/****************************************************************************************
 *  Active compressor test
 *  This test runs creates different patterns of tags and data, triggers a page-out
 *  to the compressor, waits for the page to be compressed and then pages it back in
 */

#define countof(x) (sizeof(x) / sizeof(x[0]))

static void
zero_tags(uint8_t* buf, size_t bufsize)
{
	for (uint32_t offset = 0; offset < bufsize; offset += 16) {
		__arm_mte_set_tag(buf + offset);
	}
}

// state of single use case for convenient passing between functions
struct tag_pattern {
	uint8_t* buf_start;
	size_t buf_size;
	// a tagged pointer per every 16 bytes of the buffer
	uint8_t **tagged_ptrs;
	size_t ptrs_count;
	size_t ptrs_index;
};

static void
tag_pattern_init(struct tag_pattern *t, uint8_t *buf_start, size_t buf_size)
{
	t->buf_start = buf_start;
	t->buf_size = buf_size;
	t->ptrs_count = t->buf_size / VM_MEMTAG_BYTES_PER_TAG;
	T_LOG("  allocating %zu pointers", t->ptrs_count);
	t->tagged_ptrs = (uint8_t**)calloc(t->ptrs_count, sizeof(uint8_t *));
	t->ptrs_index = 0;
}

static void
tag_pattern_push_ptr(struct tag_pattern *t, uint8_t* tagged_ptr)
{
	T_QUIET; T_ASSERT_LT(t->ptrs_index, t->ptrs_count, "ptrs_index overflow"); // test sanity
	t->tagged_ptrs[t->ptrs_index++] = tagged_ptr;
}

static void
tag_pattern_destroy(struct tag_pattern *t)
{
	free(t->tagged_ptrs);
}

static uint8_t *
tag_pattern_get_ptr(struct tag_pattern *t, size_t offset)
{
	T_QUIET; T_ASSERT_LE(offset, t->buf_size, "offset overflow"); // test sanity
	uint8_t *chunk_p = t->tagged_ptrs[offset / VM_MEMTAG_BYTES_PER_TAG];
	if (chunk_p == NULL) {
		return t->buf_start + offset; // no tagged pointer filled in, return plain pointer
	}
	return chunk_p + (offset % VM_MEMTAG_BYTES_PER_TAG);
}

// test the correctness of the data, use the tagged pointers if they are populated
static uint64_t
tag_pattern_read_verify(struct tag_pattern *t, const uint8_t* orig_data)
{
	uint64_t sum = 0;
	for (size_t offset = 0; offset < t->buf_size; ++offset) {
		uint8_t *tagged_ptr = tag_pattern_get_ptr(t, offset);
		uint8_t c = *tagged_ptr;
		sum += c;
		T_QUIET; T_ASSERT_EQ(c, orig_data[offset], "failed data comparison %zu : %d != %d", offset, (int)c, (int)orig_data[offset]);
	}
	return sum;
}

// SV optimization that for sure ends up in the hash
static void
fill_zeros(uint8_t *buf, size_t bufsize)
{
	// do nothing, test function zeros buffer after allocation
}

// SV optimization
static void
fill_same(uint8_t *buf, size_t bufsize)
{
	memset((void*)buf, 'A', bufsize);
}

static void
fill_only_first_byte(uint8_t *buf, size_t bufsize)
{
	buf[0] = 'A';
}

// should be nicely compressible by wkdm
static void
fill_counter(uint8_t *buf, size_t bufsize)
{
	uint32_t *ibuf = (uint32_t *)buf; // this cast is ok since buf has page alignment
	for (size_t i = 0; i < bufsize / sizeof(uint32_t); ++i) {
		ibuf[i] = 0x11111111 + (uint32_t)i;
	}
}

// should be uncompressible by wkdm
static void
fill_rand(uint8_t *buf, size_t bufsize)
{
	for (size_t i = 0; i < bufsize; ++i) {
		buf[i] = my_rand() % 0xff;
	}
}

// increments vm.tags_below_align
static void
tag_pattern_single_at_start(struct tag_pattern *t)
{
	uint8_t *buf = t->buf_start;
	uint8_t *orig_tagged_ptr = __arm_mte_get_tag(buf);
	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	uint8_t *tagged_buf = __arm_mte_create_random_tag(buf, mask);
	__arm_mte_set_tag(tagged_buf);
	tag_pattern_push_ptr(t, tagged_buf);
	// the rest remain NULL
}

// every consecutive 16 bytes has a different tag (worst case for RLE algorithm)
// increments vm.tags_incompressible
static void
tag_pattern_max_mix(struct tag_pattern *t)
{
	uint8_t *prev_tagged_ptr = NULL;
	for (size_t offset = 0; offset < t->buf_size; offset += VM_MEMTAG_BYTES_PER_TAG) {
		uint8_t *ptr = t->buf_start + offset;
		uint8_t *orig_tagged_ptr = __arm_mte_get_tag(ptr);
		uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
		mask = __arm_mte_exclude_tag(prev_tagged_ptr, mask);  // don't want consecutive tags to be the same
		uint8_t *tagged_ptr = __arm_mte_create_random_tag(ptr, mask);
		__arm_mte_set_tag(tagged_ptr);
		tag_pattern_push_ptr(t, tagged_ptr);
		prev_tagged_ptr = tagged_ptr;
	}
	T_LOG("  got %zu pointers", t->ptrs_index);
}

static uint8_t *
tag_fill(struct tag_pattern *t, uint8_t* buf, size_t buf_size, uint8_t* prev_ptr)
{
	T_QUIET; T_ASSERT_EQ(buf_size % VM_MEMTAG_BYTES_PER_TAG, 0ul, "unexpected buf_size %zu", buf_size);
	uint8_t *orig_tagged_ptr = __arm_mte_get_tag(buf);
	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	mask = __arm_mte_exclude_tag(prev_ptr, mask); // new tag should be different from previous
	uint8_t *tagged_buf = __arm_mte_create_random_tag(buf, mask);
	uintptr_t only_tag = (uintptr_t)tagged_buf & TAG_MASK;

	for (size_t offset = 0; offset < buf_size; offset += VM_MEMTAG_BYTES_PER_TAG) {
		T_QUIET; T_ASSERT_LE(offset, t->buf_size, "fill_tag overflow"); // test sanity
		uint8_t *ptr = buf + offset;
		uint8_t *tagged_ptr = (uint8_t *)((uintptr_t)ptr | only_tag);
		__arm_mte_set_tag(tagged_ptr);
		tag_pattern_push_ptr(t, tagged_ptr);
	}
	return tagged_buf;
}

// the entire page has the same non-zero tag
static void
tag_pattern_all_same(struct tag_pattern *t)
{
	tag_fill(t, t->buf_start, t->buf_size, NULL);
}

static void
tag_patten_all_zero(struct tag_pattern *t)
{
	// do nothing, all tags are initialized to zero by the text function
}

// increments vm.tags_below_align
static void
tag_pattern_half_and_half(struct tag_pattern *t)
{
	size_t sz = t->buf_size / 2;
	uint8_t *prev = tag_fill(t, t->buf_start, sz, NULL);
	tag_fill(t, t->buf_start + sz, sz, prev);
}

// increments vm.tags_above_align
static void
tag_pattern_odd_chunks(struct tag_pattern *t)
{
	size_t sizes[] = {31, 31, 63, 63, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31}; // should sum to less than 1024
	size_t offset = 0;
	uint8_t *prev = NULL;
	for (size_t i = 0; i < countof(sizes); ++i) {
		size_t sz = sizes[i] * VM_MEMTAG_BYTES_PER_TAG;
		prev = tag_fill(t, t->buf_start + offset, sz, prev);
		offset += sz;
	}
	T_LOG("  reached offset %zu, got %zu pointers", offset, t->ptrs_index);
}

// --- the following functions uses the compressor sysctls to track that things are progressing as expected ---

// keeps the state of the compressor sysctls
struct tags_sysctls {
	uint64_t pages_compressed;

	uint64_t all_zero;
	uint64_t same_value;
	uint64_t below_align;
	uint64_t above_align;
	uint64_t incompressible;

	uint64_t pages_decompressed;
	uint64_t pages_freed;
	uint64_t pages_corrupted;

	int64_t overhead_bytes; // can be negative on diffs
	int64_t start_overhead_bytes; // for comparing the very start to the end
	int64_t tagged_pages;

	// unrelated to tagging, but interesting to see as well
	uint64_t wk_compressions;
};

// sample all the sysctls we're interested in
static void
tags_sysctls_sample(struct tags_sysctls *s)
{
	s->pages_compressed = sysctl_get_Q("vm.mte.compress_pages_compressed");
#if DEVELOPMENT || DEBUG
	s->all_zero = sysctl_get_Q("vm.mte.compress_all_zero");
	s->same_value = sysctl_get_Q("vm.mte.compress_same_value");
	s->below_align = sysctl_get_Q("vm.mte.compress_below_align");
	s->above_align = sysctl_get_Q("vm.mte.compress_above_align");
	s->incompressible = sysctl_get_Q("vm.mte.compress_incompressible");
#endif /* DEVELOPMENT || DEBUG */
	s->pages_decompressed = sysctl_get_Q("vm.mte.compress_pages_decompressed");
	s->pages_freed = sysctl_get_Q("vm.mte.compress_pages_freed");
	s->pages_corrupted = sysctl_get_Q("vm.mte.compress_pages_corrupted");
	s->overhead_bytes = (int64_t)sysctl_get_Q("vm.mte.compress_overhead_bytes");
	s->tagged_pages = (int64_t)sysctl_get_Q("vm.mte.compress_pages");
	s->wk_compressions = sysctl_get_Q("vm.wk_compressions");
}

static void
tags_sysctl_update(struct tags_sysctls *s, struct tags_sysctls *sample)
{ // update the sysctl state with the latest sample but preserve start_overhead_bytes
	int64_t start_bytes = s->start_overhead_bytes;
	*s = *sample;
	s->start_overhead_bytes = start_bytes;
}

// sample and diff with the previous sample
static void
tags_sysctls_sample_diff(const struct tags_sysctls *start, struct tags_sysctls *sample, struct tags_sysctls *d)
{
	tags_sysctls_sample(sample);
#define SUB_FIELD(field) d->field = sample->field - start->field
	SUB_FIELD(pages_compressed);
	SUB_FIELD(all_zero);
	SUB_FIELD(same_value);
	SUB_FIELD(below_align);
	SUB_FIELD(above_align);
	SUB_FIELD(incompressible);
	SUB_FIELD(pages_decompressed);
	SUB_FIELD(pages_freed);
	SUB_FIELD(pages_corrupted);
	SUB_FIELD(overhead_bytes);
	SUB_FIELD(tagged_pages);
	SUB_FIELD(wk_compressions);
#undef SUB_FIELD
}

static void
tags_sysctls_print(const struct tags_sysctls *s, const char* desc)
{
	T_LOG("  %s  comp: %llu | zero: %llu  same: %llu  below: %llu  above: %llu  incomp: %llu | decomp:%llu  freed:%llu  corrupt:%llu | bytes:%lld  pages:%lld | wk_comp:%llu",
	    desc, s->pages_compressed, s->all_zero, s->same_value, s->below_align, s->above_align, s->incompressible,
	    s->pages_decompressed, s->pages_freed, s->pages_corrupted, s->overhead_bytes, s->tagged_pages, s->wk_compressions);
}

// called before the compressor work
static void
tags_sysctl_start(struct tags_sysctls *s)
{
	tags_sysctls_sample(s);
	s->start_overhead_bytes = s->overhead_bytes;
	tags_sysctls_print(s, "START ");
}

#define SYSCTL_ALL_ZERO 1
#define SYSCTL_SAME_VALUE 2
#define SYSCTL_BELOW_ALIGN 3
#define SYSCTL_ABOVE_ALIGN 4
#define SYSCTL_INCOMPRESSIBLE 5

// uncomment this to make the asserts on the incremented statistics strict to the expected value. This assumes the
// tester is the only MTE enabled process not idle.
// This is undesirable if there are other MTE enabled processes which might page-out to the compressor
// while the test is running, which is the case in BATS.
// #define STRICT_STATS_EQ

#ifdef STRICT_STATS_EQ
#define ASSERT_STAT_ATLEAST T_ASSERT_EQ
#else
#define ASSERT_STAT_ATLEAST T_ASSERT_GE
#endif

static void
wait_compressed(struct tags_sysctls* start, uint32_t expected_increment)
{
	// start with a sleep to give it a first chance to settle
	usleep(10000);
	struct tags_sysctls sample, d;
	int iter = 1; // on account of the usleep above
	while (true) {
		tags_sysctls_sample_diff(start, &sample, &d);
		if (d.pages_compressed > 0) {
			T_QUIET; ASSERT_STAT_ATLEAST(d.pages_compressed, 1ull, "compressed more than 1 page, are you running something in parallel?");
			break;
		}
		usleep(10000);
		++iter;
		if (iter > 10) {
			T_ASSERT_FAIL("waiting too long for page-out. is MTE in the compressor enabled?");
			break;
		}
	}
	T_LOG("  waited for tags compression after %d msec", iter * 10);
	tags_sysctls_print(&d, "WAITED");

	// check the expected sysctl was incremented
#define CHECK_INC(field_name, field_num) \
	                T_QUIET; ASSERT_STAT_ATLEAST(d.field_name, (expected_increment == field_num) ? 1ull : 0ull, "unexpected increment value")
	CHECK_INC(all_zero, SYSCTL_ALL_ZERO);
	CHECK_INC(same_value, SYSCTL_SAME_VALUE);
	CHECK_INC(below_align, SYSCTL_BELOW_ALIGN);
	CHECK_INC(above_align, SYSCTL_ABOVE_ALIGN);
	CHECK_INC(incompressible, SYSCTL_INCOMPRESSIBLE);
#undef CHECK_INC
	tags_sysctl_update(start, &sample); // reset it for the next check
}

static void
check_sysctls_after_pagein(struct tags_sysctls* start)
{
	struct tags_sysctls sample, d;
	tags_sysctls_sample_diff(start, &sample, &d);
	tags_sysctls_print(&d, "PAGEIN");

	T_QUIET; ASSERT_STAT_ATLEAST(d.pages_decompressed, 1ull, "check counter");
	T_QUIET; ASSERT_STAT_ATLEAST(d.pages_freed, 0ull, "check counter");
	T_QUIET; ASSERT_STAT_ATLEAST(d.pages_corrupted, 0ull, "check counter");
	// after page-in overhead returns to 0
	T_QUIET; ASSERT_STAT_ATLEAST(start->start_overhead_bytes - sample.overhead_bytes, 0ll, "check overhead bytes");
	tags_sysctl_update(start, &sample);;
}

static void
check_sysctls_after_dealloc(struct tags_sysctls* start, bool did_pagein)
{
	struct tags_sysctls sample, d;
	tags_sysctls_sample_diff(start, &sample, &d);
	tags_sysctls_print(&d, "DEALLOC");

	if (!did_pagein) {
		T_QUIET; ASSERT_STAT_ATLEAST(d.pages_freed, 1ull, "check counter");
	} else {
		T_QUIET; ASSERT_STAT_ATLEAST(d.pages_freed, 0ull, "check counter");
	}
	T_QUIET; ASSERT_STAT_ATLEAST(d.pages_decompressed, 0ull, "check counter");
	T_QUIET; ASSERT_STAT_ATLEAST(d.pages_corrupted, 0ull, "check counter");
	T_QUIET; ASSERT_STAT_ATLEAST(start->start_overhead_bytes - sample.overhead_bytes, 0ll, "check overhead bytes");
	tags_sysctl_update(start, &sample);;
}

// --- main test function ---

typedef void (*fn_fill)(uint8_t *buf, size_t bufsize);
typedef void (*fn_do_tags)(struct tag_pattern *t);

struct tags_fill_t {
	fn_do_tags do_tags_func;
	const char *name;
	uint32_t expect_sysctl_increment;
};

struct data_fill_t {
	fn_fill fill_func;
	const char *name;
};

#define WAIT_INTERACTIVE 1
#define DONT_PAGEIN 2
#define PRELOAD_COMPRESSED_BYTES 4

static void
test_pattern(struct data_fill_t data_fill, struct tags_fill_t tags_fill, uint32_t flags)
{
	T_LOG("---------- Running: fill:%s tags:%s... ----------", data_fill.name, tags_fill.name);
	size_t bufsize = PAGE_SIZE;
	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, bufsize, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(VM_FLAGS_MTE)");

	uint8_t *buf = (uint8_t*)address;
	uint8_t *copy_buf = (uint8_t *)malloc(bufsize); // will hold a copy of the data for comparing after page-in

	memset((void*)buf, 0, bufsize);
	zero_tags(buf, bufsize);

	// fill page with data
	data_fill.fill_func(buf, bufsize);
	memcpy(copy_buf, buf, bufsize); // make a copy for later comparison

	struct tag_pattern t;
	tag_pattern_init(&t, buf, bufsize);
	T_LOG("  tagging");
	tags_fill.do_tags_func(&t);
	T_LOG("    verify-read");
	// verify we can indeed read all tags
	tag_pattern_read_verify(&t, copy_buf);

	struct tags_sysctls ts; // updated with the latest sysctl sample after each phase
	tags_sysctl_start(&ts);

	T_LOG("  paging-out");
	kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)buf, bufsize, VM_BEHAVIOR_PAGEOUT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed mach_vm_behavior_set() %p,%zu - %d", buf, bufsize, kr);

	wait_compressed(&ts, tags_fill.expect_sysctl_increment);

	if (flags & WAIT_INTERACTIVE) {
		getchar();
	}

	if (!(flags & DONT_PAGEIN)) {
		T_LOG("  paging-in");
		tag_pattern_read_verify(&t, copy_buf);
		check_sysctls_after_pagein(&ts);
	}
	T_LOG("  deallocating");
	kr = vm_deallocate(mach_task_self(), address, bufsize);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate");

	check_sysctls_after_dealloc(&ts, !(flags & DONT_PAGEIN));

	tag_pattern_destroy(&t);
	T_PASS("OK");
}

struct test_buf {
	vm_address_t address;
	size_t bufsize;
};
// this is just a simpler version of the above, split to two functions. This is meant so that there would be already
// something in the compressor while the test is running
static void
preload_compressed_bytes(struct test_buf *b)
{
	T_LOG("---- preloading the compressor ----");
	size_t bufsize = PAGE_SIZE;
	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, bufsize, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(VM_FLAGS_MTE)");

	uint8_t *buf = (uint8_t*)address;
	memset((void*)buf, 0, bufsize);
	zero_tags(buf, bufsize);

	// set non-zero tags
	struct tag_pattern t;
	tag_pattern_init(&t, buf, bufsize);
	tag_pattern_max_mix(&t);
	tag_pattern_destroy(&t); // don't need to verify it later

	struct tags_sysctls ts;
	tags_sysctl_start(&ts);

	T_LOG("  paging-out (preload)");
	kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)buf, bufsize, VM_BEHAVIOR_PAGEOUT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed mach_vm_behavior_set() %p,%zu - %d", buf, bufsize, kr);

	wait_compressed(&ts, SYSCTL_INCOMPRESSIBLE);
	b->address = address;
	b->bufsize = bufsize;
}

static void
un_preload_compressed_bytes(struct test_buf *b)
{
	T_LOG("---- un-preloading ----");
	kern_return_t kr = vm_deallocate(mach_task_self(), b->address, b->bufsize);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate");
}

static struct tags_fill_t tags_fills[] = {
	{ &tag_pattern_single_at_start, "single_at_start", SYSCTL_BELOW_ALIGN },
	{ &tag_pattern_max_mix, "max-mix", SYSCTL_INCOMPRESSIBLE },
	{ &tag_patten_all_zero, "all-zero", SYSCTL_ALL_ZERO },
	{ &tag_pattern_all_same, "all-same", SYSCTL_SAME_VALUE},
	{ &tag_pattern_half_and_half, "halfs", SYSCTL_BELOW_ALIGN },
	{ &tag_pattern_odd_chunks, "odd-chunks", SYSCTL_ABOVE_ALIGN }
};

static struct data_fill_t data_fills[] = {
	{ &fill_zeros, "zeros" },
	{ &fill_same, "same" },
	{ &fill_only_first_byte, "first-byte" },
	{ &fill_counter, "counter" },
	{ &fill_rand, "rand" }
};

void
run_all_patterns(int flags)
{
	my_srand(0);
	struct test_buf b;
	if (flags & PRELOAD_COMPRESSED_BYTES) {
		preload_compressed_bytes(&b);
	}
	if (flags & PRELOAD_COMPRESSED_BYTES) {
		preload_compressed_bytes(&b);
	}
	for (size_t fpi = 0; fpi < countof(data_fills); ++fpi) {
		for (size_t tpi = 0; tpi < countof(tags_fills); ++tpi) {
			test_pattern(data_fills[fpi], tags_fills[tpi], flags);
		}
	}
	if (flags & PRELOAD_COMPRESSED_BYTES) {
		un_preload_compressed_bytes(&b);
	}
}

T_DECL(mte_compressor_paging,
    "Test paging out to the compressor and paging in from the compressor of MTE pages",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	run_all_patterns(0);
	run_all_patterns(PRELOAD_COMPRESSED_BYTES);
}

T_DECL(mte_compressor_no_pageing,
    "Test what happens if the tagged memory is not paged-in before being deallocated",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	run_all_patterns(DONT_PAGEIN);
	run_all_patterns(DONT_PAGEIN | PRELOAD_COMPRESSED_BYTES);
}

static size_t
read_big_sysctl(const char *name, char **buf)
{
	size_t len = 0;
	int rc = sysctlbyname(name, NULL, &len, NULL, 0); // get the length of the needed buffer
	T_ASSERT_POSIX_SUCCESS(rc, "query size of sysctl `%s`", name);
	T_ASSERT_GT(len, (size_t)0, "sysctl got size 0");
	len += 4096; // allocate a bit extra in case the size changed between the two calls
	*buf = (char*)malloc(len);
	T_ASSERT_NE_PTR((void*)*buf, NULL, "allocation for sysctl %zu", len);
	rc = sysctlbyname(name, *buf, &len, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(rc, "query of sysctl `%s`", name);
	return len;
}

//#define CSEGS_VERBOSE
#ifdef CSEGS_VERBOSE
#define T_LOG_VERBOSE(...) T_LOG(__VA_ARGS__)
#else
#define T_LOG_VERBOSE(...)
#endif

// this uses the sysctl that dumps all the compressor metadata to calculate the MTE bytes overhead
static void
get_mte_size_from_csegs(uint64_t *bytes_overhead, uint64_t *tagged_pages)
{
	uint64_t compressed_bytes = 0; // before alignment
	*bytes_overhead = 0;
	*tagged_pages = 0;

	char *buf = NULL;
	size_t sz = read_big_sysctl("vm.compressor_segments", &buf);

	size_t offset = 0;
	T_QUIET; T_ASSERT_GE_ULONG(sz, sizeof(uint32_t), "got buffer shorter than the magic value");
	uint32_t hdr_magic = *((uint32_t*)buf);
	T_ASSERT_EQ_UINT(hdr_magic, VM_C_SEGMENT_INFO_MAGIC, "match magic value");
	offset += sizeof(uint32_t);
	while (offset < sz) {
		// read next c_segment
		T_QUIET; T_ASSERT_LE(offset + sizeof(struct c_segment_info), sz, "unexpected offset for c_segment_info");
		const struct c_segment_info* cseg = (const struct c_segment_info*)(buf + offset);
		offset += sizeof(struct c_segment_info);
		// read its slots
		bool logged_segment = false;
		T_QUIET; T_ASSERT_LE(offset + cseg->csi_slots_len * sizeof(struct c_slot_info), sz, "unexpected offset for c_slot_info");
		for (int i = 0; i < cseg->csi_slots_len; ++i) {
			const struct c_slot_info *slot = (const struct c_slot_info*)&cseg->csi_slots[i];
			if (slot->csi_mte_size == 0) {
				continue;
			}
			++(*tagged_pages);
			uint32_t actual_size = vm_mte_compressed_tags_actual_size(slot->csi_mte_size);
			if (actual_size > 0) {
				compressed_bytes += slot->csi_mte_size;
				*bytes_overhead += C_SEG_ROUND_TO_ALIGNMENT(slot->csi_mte_size);
			}
			T_QUIET; T_ASSERT_FALSE(slot->csi_mte_has_data, "unexpected has_data");

			if (!logged_segment) {
				T_LOG_VERBOSE("segment %u  bytes-used: %d", cseg->csi_mysegno, cseg->csi_bytes_used);
				logged_segment = true;
			}
			T_LOG_VERBOSE("   slot %d: size=%u  mte_size=%u", i, (uint32_t) slot->csi_size, (uint32_t) slot->csi_mte_size);
		}
		offset += cseg->csi_slots_len * sizeof(struct c_slot_info);
	}
	T_LOG("compressed_bytes=%llu  aligned=%llu  tagged_pages=%llu", compressed_bytes, *bytes_overhead, *tagged_pages);
}

static void
counters_verify()
{
	// this comparison may fail since it is inherently racy, getting the same number in 2 sligtly different times.
	T_MAYFAIL;
	uint64_t bytes_from_csegs = 0, pages_from_csegs = 0;
	get_mte_size_from_csegs(&bytes_from_csegs, &pages_from_csegs);
	uint64_t bytes_from_sysctl = sysctl_get_Q("vm.mte.compress_overhead_bytes");
	uint64_t pages_from_sysctl = sysctl_get_Q("vm.mte.compress_pages");
	T_ASSERT_EQ(bytes_from_csegs, bytes_from_sysctl, "overhead bytes count match");
	T_ASSERT_EQ(pages_from_csegs, pages_from_sysctl, "tagged pages count match");
}

static vm_address_t
make_rand_tagged_buf(size_t bufsize)
{
	my_srand(0);
	T_LOG("filling buffer size 0x%zx", bufsize);
	vm_address_t address;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, bufsize, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(VM_FLAGS_MTE)");

	uint8_t *buf = (uint8_t*)address;
	memset((void*)buf, 0, bufsize);
	zero_tags(buf, bufsize);

	// fill each page with different fill and tag patterns
	for (int i = 0; i < bufsize / PAGE_SIZE; ++i) {
		struct tag_pattern t;
		uint8_t *it_buf = buf + i * PAGE_SIZE;
		size_t it_size = PAGE_SIZE;
		tag_pattern_init(&t, it_buf, it_size);

		struct data_fill_t *df = &data_fills[(my_rand() >> 1) % countof(data_fills)];
		df->fill_func(it_buf, it_size);
		int tf_ind = (my_rand() >> 1) % countof(tags_fills);
		struct tags_fill_t *tf = &tags_fills[tf_ind];
		tf->do_tags_func(&t);

		tag_pattern_destroy(&t);
	}
	return address;
}

static void
page_out(vm_address_t address, size_t bufsize)
{
	T_LOG("paging-out");
	kern_return_t kr = mach_vm_behavior_set(mach_task_self(), (mach_vm_address_t)address, bufsize, VM_BEHAVIOR_PAGEOUT);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "failed mach_vm_behavior_set() %lx,%zu - %d", address, bufsize, kr);
}

static void
print_stats()
{
	struct tags_sysctls ts;
	tags_sysctls_sample(&ts);
	tags_sysctls_print(&ts, "STATS");
}

static void
dealloc(vm_address_t address, size_t bufsize)
{
	T_LOG("  deallocating");
	kern_return_t kr = vm_deallocate(mach_task_self(), address, bufsize);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "vm_deallocate");
}

// This test is useful for running after a some heavy MTE processes have ran and finished
// the make sure that the bytes number maintained in the sysctl is the same as the actual mte_sizes in the segments
T_DECL(mte_compressor_counters_verify,
    "Verify that the overhead bytes statistics match the size as it appears in the segments",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	counters_verify();
	print_stats();
}


T_DECL(mte_compressor_exercise_counters_verify,
    "Exericise the MTE tags compress, then verify that the overhead bytes statistics match the size as it appears in the segments",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	size_t bufsize = 100 * PAGE_SIZE;
	vm_address_t address = make_rand_tagged_buf(bufsize);
	page_out(address, bufsize);
	usleep(20000); // wait for the compressor to finish
	counters_verify();
	print_stats();
	dealloc(address, bufsize);
}

static void
dump_buffer(const char *path, const char *buf, size_t sz)
{
	FILE *f = fopen(path, "w");
	T_QUIET; T_ASSERT_NOTNULL(f, "Failed to open file %s", path);
	T_QUIET; T_ASSERT_EQ(fwrite(buf, 1, sz, f), sz, "Failed to write to file %s", path);
	T_QUIET; T_ASSERT_EQ(fclose(f), 0, "Failed to close file %s", path);
}

static size_t
read_file(const char *path, char **buf_ptr)
{
	FILE *f = fopen(path, "r");
	T_QUIET; T_ASSERT_NOTNULL(f, "Failed to open file %s", path);
	T_QUIET; T_ASSERT_EQ(fseek(f, 0, SEEK_END), 0, "Faile to seek in file %s", path);
	size_t sz = ftell(f);
	T_QUIET; T_ASSERT_GT(sz, (size_t)0, "Empty file %s", path);
	T_QUIET; T_ASSERT_EQ(fseek(f, 0, SEEK_SET), 0, "Faile to seek in file %s", path);
	*buf_ptr = (char *)malloc(sz);
	T_QUIET; T_ASSERT_EQ(fread(*buf_ptr, 1, sz, f), sz, "Failed to read from file %s", path);
	T_QUIET; T_ASSERT_EQ(fclose(f), 0, "Failed to close file %s", path);
	return sz;
}

static void
get_mte_compressed_tags(
	void (^process_cseg)(uint32_t state),
	void (^process_cslot)(int slot_idx, uint8_t *compressed_buf, uint32_t compressed_size, uint32_t actual_size),
	const char *load_from_file, const char *dump_to_file)
{
	char *buf = NULL;
	size_t sz = 0;
	if (load_from_file == NULL) {
		// if this buffer gets big reading it may fail when under memory pressure since it requires a big
		// memory allocation in the kernel
		T_MAYFAIL;
		sz = read_big_sysctl("vm.compressor_segments_data", &buf);
	} else {
		sz = read_file(load_from_file, &buf);
	}
	if (dump_to_file != NULL) {
		dump_buffer(dump_to_file, buf, sz);
	}

	size_t offset = 0;
	T_QUIET; T_ASSERT_GE_ULONG(sz, sizeof(uint32_t), "got buffer shorter than the magic value");
	uint32_t hdr_magic = *((uint32_t*)buf);
	T_ASSERT_EQ_UINT(hdr_magic, VM_C_SEGMENT_INFO_MAGIC_WITH_TAGS, "match magic value");
	offset += sizeof(uint32_t);
	while (offset < sz) {
		// read next c_segment
		T_QUIET; T_ASSERT_LE(offset + sizeof(struct c_segment_info), sz, "unexpected offset for c_segment_info");
		const struct c_segment_info* cseg = (const struct c_segment_info*)(buf + offset);
		process_cseg(cseg->csi_state);
		offset += sizeof(struct c_segment_info);
		// read its slots
		for (int si = 0; si < cseg->csi_slots_len; ++si) {
			T_QUIET; T_ASSERT_LE(offset + sizeof(struct c_slot_info), sz, "unexpected offset for c_slot_info");
			const struct c_slot_info *slot = (const struct c_slot_info*)(buf + offset);
			offset += sizeof(struct c_slot_info);
			if (slot->csi_mte_size == 0 || !slot->csi_mte_has_data) {
				continue;
			}
			uint32_t actual_size = vm_mte_compressed_tags_actual_size(slot->csi_mte_size);
			uint8_t *data_ptr = NULL;
			if (actual_size > 0) {
				T_QUIET; T_ASSERT_LE(offset + actual_size, sz, "unexpected offset for tags data");
				// compressed tag data is at the end of the c_slot_info
				data_ptr = (uint8_t *)slot + sizeof(struct c_slot_info);
			}
			process_cslot(si, data_ptr, slot->csi_mte_size, actual_size);
			offset += actual_size;
		}
	}
	free(buf);
}

static void
print_comp_hist(struct comp_histogram *comp_hist)
{
	T_LOG("RLE cmd histogram:");
	for (int i = 0; i < countof(comp_hist->cmd_bins); ++i) {
		T_LOG("|  %x,  %llu", i, comp_hist->cmd_bins[i]);
	}
	T_LOG("Total: %llu cmds", comp_hist->cmd_total);
	T_LOG("Compressed size histogram:");
	T_LOG("|  sv,  %llu", comp_hist->same_value_count);
	for (int i = 0; i < countof(comp_hist->comp_size_bins); ++i) {
		T_LOG("|  %d,  %llu", (i + 1) * C_SEG_OFFSET_ALIGNMENT_BOUNDARY, comp_hist->comp_size_bins[i]);
	}
}

#define C_STATE_COUNT 11

struct cseg_histogram {
	uint64_t csegs_per_state[C_STATE_COUNT + 1];
};

static void
analyse_rle_runs(const char* load_from_file, const char* dump_to_file, bool show_lens, bool show_recompress, bool show_cseg_state)
{
	struct comp_histogram comp_hist = {}, *comp_hist_ptr = &comp_hist;
	struct runs_histogram run_hist = {}, *run_hist_ptr = &run_hist;
	struct comp_histogram re_comp_hist = {}, *re_comp_hist_ptr = &re_comp_hist;
	struct cseg_histogram cseg_hist = {}, *cseg_hist_ptr = &cseg_hist;
	get_mte_compressed_tags(
		^void (uint32_t cseg_state) {
		cseg_hist_ptr->csegs_per_state[MIN(cseg_state, C_STATE_COUNT)]++;
	},
		^void (int slot_idx, uint8_t *compressed_buf, uint32_t compressed_size, uint32_t actual_size) {
		T_LOG_VERBOSE("    got compressed %d: %u(%x) bytes actual=%d", slot_idx, compressed_size, compressed_size, actual_size);
		// first verify that it decompresses to the correct size
		uint8_t decompressed[C_MTE_SIZE] = {};
		bool ret = vm_mte_rle_decompress_tags(compressed_buf, compressed_size, (uint8_t*)decompressed, C_MTE_SIZE);
		T_QUIET; T_ASSERT_TRUE(ret, "decompress failed");

		ret = vm_mte_rle_comp_histogram(compressed_buf, compressed_size, comp_hist_ptr);
		T_QUIET; T_ASSERT_TRUE(ret, "vm_mte_rle_cmd_histogram");
		vm_mte_rle_runs_histogram(decompressed, C_MTE_SIZE, run_hist_ptr);

		uint8_t re_compressed[C_MTE_SIZE] = {};
		uint32_t re_compress_sz = vm_mte_rle_compress_tags(decompressed, C_MTE_SIZE, re_compressed, C_MTE_SIZE);
		ret = vm_mte_rle_comp_histogram(re_compressed, re_compress_sz, re_comp_hist_ptr);
		T_QUIET; T_ASSERT_TRUE(ret, "re-vm_mte_rle_cmd_histogram");
	}, load_from_file, dump_to_file);

	print_comp_hist(&comp_hist);

	if (show_lens) {
		T_LOG("RLE run lengths histogram:");
		for (int i = 0; i < countof(run_hist.rh_bins); ++i) {
			T_LOG("|  %d,  %llu", i, run_hist.rh_bins[i]);
		}
	}
	if (show_recompress) {
		T_LOG("*** recompressed ***");
		print_comp_hist(&re_comp_hist);
	}
	if (show_cseg_state) {
		T_LOG("cseg-state histogram:");
		for (int i = 0; i < C_STATE_COUNT + 1; ++i) {
			T_LOG("|  %d,  %llu", i, cseg_hist.csegs_per_state[i]);
		}
	}
}

T_DECL(mte_compressor_analyze_rle,
    "Exercise the MTE tags compress, then read, verify and print the RLE commands stats and the runs stats",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	const char *dump_to_file = NULL, *load_from_file = NULL;
	bool show_lens = false, show_recompress = false, show_state = false;
	for (int i = 0; i < argc; ++i) {
		if (strcmp(argv[i], "--in") == 0) {
			load_from_file = argv[++i];
			T_LOG("Loading data from `%s`", load_from_file);
		} else if (strcmp(argv[i], "--out") == 0) {
			dump_to_file = argv[++i];
			T_LOG("Dumping data to `%s`", dump_to_file);
		} else if (strcmp(argv[i], "--show-lens") == 0) {
			show_lens = true;
		} else if (strcmp(argv[i], "--recompress") == 0) {
			// this option allows testing new changes in the compression algorithm compared to
			// what's loaded from the input file/sysctl
			show_recompress = true;
		} else if (strcmp(argv[i], "--state") == 0) {
			// useful for stats on how many segments are in the swap
			show_state = true;
		}
	}
	analyse_rle_runs(load_from_file, dump_to_file, show_lens, show_recompress, show_state);
	if (load_from_file) {
		return; // don't want to print irrelevant stats when processing data from file
	}
	print_stats();
}

T_DECL(mte_compressor_exercise_analyze_rle,
    "Exercise the MTE tags compress, then read, verify and print the RLE commands stats and the runs stats",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	size_t bufsize = 100 * PAGE_SIZE;
	vm_address_t address = make_rand_tagged_buf(bufsize);
	page_out(address, bufsize);
	usleep(20000); // wait for the compressor to finish
	analyse_rle_runs(NULL, NULL, false, false, false);
	print_stats();
	dealloc(address, bufsize);
}
