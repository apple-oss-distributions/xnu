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
/*
 * Compresor and swap benchmarks.
 */

#include <err.h>
#include <errno.h>
#include <mach/vm_page_size.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "benchmark/helpers.h"

/*
 * There are four different types of benchmarks
 * Each type can run on a variable size buffer
 * and with different types of data.
 */
typedef enum test_variant {
	VARIANT_COMPRESS,
	VARIANT_COMPRESS_AND_DECOMPRESS,
	VARIANT_SWAPOUT,
	VARIANT_SWAPOUT_AND_SWAPIN
} test_variant_t;

/*
 * Each benchmark supports buffers filled with different contents.
 */
typedef enum allocation_type {
	VARIANT_ZEROS,
	VARIANT_RANDOM,
	VARIANT_TYPICAL
} allocation_type_t;

/* Arguments parsed from the command line */
typedef struct test_args {
	uint64_t ta_duration_seconds;
	uint64_t ta_buffer_size;
	test_variant_t ta_variant;
	allocation_type_t ta_alloc_type;
	bool ta_verbose;
} test_args_t;

struct perf_compressor_data {
	user_addr_t buffer;
	size_t buffer_size;
	uint64_t benchmark_time;
	uint64_t bytes_processed;
	uint64_t compressor_growth;
};

/* Test Variants */
static const char *kCompressArgument = "compress";
static const char *kCompressAndDecompressArgument = "compress-and-decompress";

/* Allocation types */
static const char *kAllocZeroes = "zero";
static const char *kAllocRandom = "random";
static const char *kAllocTypical = "typical";

/*
 * Failure codes
 */
static int kInvalidArgument = 1;
static int kAllocationFailure = 2;
static int kCompressionFailure = 3;
static int kNYI = 4;

static void parse_arguments(int argc, const char **argv, test_args_t *args /* OUT */);
static void print_help(const char** argv);
static unsigned char *alloc_and_fill_buffer(size_t size, allocation_type_t alloc_type);
void fill_with_typical_data(unsigned char *buf, size_t size);
static void run_compress_benchmark(const test_args_t *args);
static uint64_t decompress_buffer(unsigned char *buf, size_t size);

int
main(int argc, const char **argv)
{
	test_args_t args = {0};
	parse_arguments(argc, argv, &args);
	switch (args.ta_variant) {
	case VARIANT_COMPRESS:
	case VARIANT_COMPRESS_AND_DECOMPRESS:
		run_compress_benchmark(&args);
		break;
	default:
		err(kNYI, "NYI: Test variant has not been implemented");
	}
}

static void
run_compress_benchmark(const test_args_t *args)
{
	uint64_t total_compressor_time = 0;
	uint64_t total_bytes_compressed = 0;
	uint64_t total_compressor_bytes_used = 0;
	uint64_t total_decompressor_time = 0;
	double compressor_throughput = 0, decompressor_throughput = 0, compression_ratio = 0;
	while (total_compressor_time < args->ta_duration_seconds * NSEC_PER_SEC) {
		unsigned char *buf;
		struct perf_compressor_data sysctl_data = {0};
		size_t len = sizeof(sysctl_data);

		benchmark_log(args->ta_verbose, "Start allocation\n");
		buf = alloc_and_fill_buffer(args->ta_buffer_size, args->ta_alloc_type);
		if (!buf) {
			err(kAllocationFailure, "Unable to allocate test buffer\n");
		}
		benchmark_log(args->ta_verbose, "Finished allocation\n");

		sysctl_data.buffer = (user_addr_t) buf;
		sysctl_data.buffer_size = args->ta_buffer_size;
		benchmark_log(args->ta_verbose, "Start compression\n");
		int ret = sysctlbyname("kern.perf_compressor", &sysctl_data, &len, &sysctl_data, sizeof(sysctl_data));
		if (ret < 0) {
			fprintf(stderr, "Failed to compress buffer: %s\n", strerror(errno));
			exit(kCompressionFailure);
		}
		if (sysctl_data.bytes_processed != args->ta_buffer_size) {
			fprintf(stderr, "WARNING: Failed to compress the whole buffer. Only compressed %llu bytes out of %llu bytes\n", sysctl_data.bytes_processed, args->ta_buffer_size);
		}
		total_bytes_compressed += sysctl_data.bytes_processed;
		total_compressor_time += sysctl_data.benchmark_time;
		total_compressor_bytes_used += sysctl_data.compressor_growth;
		benchmark_log(args->ta_verbose, "Finished compression\n");

		if (args->ta_variant == VARIANT_COMPRESS_AND_DECOMPRESS) {
			benchmark_log(args->ta_verbose, "Start decompression\n");
			total_decompressor_time += decompress_buffer(buf, args->ta_buffer_size);
			benchmark_log(args->ta_verbose, "Finished decompression\n");
		}
		munmap(buf, args->ta_buffer_size);
	}
	compressor_throughput = (double) total_bytes_compressed / total_compressor_time * NSEC_PER_SEC;
	printf("bytes_compressed=%llu, compressor_bytes_used=%llu\n", total_bytes_compressed, total_compressor_bytes_used);
	compression_ratio = (double) total_bytes_compressed / total_compressor_bytes_used;
	if (total_decompressor_time != 0) {
		decompressor_throughput = (double) total_bytes_compressed / total_decompressor_time * NSEC_PER_SEC;
	}
	printf("-----Results-----\n");
	printf("Compressor Throughput");
	if (args->ta_variant == VARIANT_COMPRESS_AND_DECOMPRESS) {
		printf(", Decompressor Throughput");
	}
	if (args->ta_alloc_type != VARIANT_ZEROS) {
		printf(", Compression Ratio\n");
	} else {
		printf("\n");
	}

	printf("%.0f", compressor_throughput);
	if (args->ta_variant == VARIANT_COMPRESS_AND_DECOMPRESS) {
		printf(", %.0f", decompressor_throughput);
	}
	if (args->ta_alloc_type != VARIANT_ZEROS) {
		printf(", %.2f\n", compression_ratio);
	} else {
		printf("\n");
	}
}

static unsigned char *
alloc_and_fill_buffer(size_t size, allocation_type_t alloc_type)
{
	unsigned char *buf = mmap_buffer(size);
	if (!buf) {
		return buf;
	}
	switch (alloc_type) {
	case VARIANT_ZEROS:
		bzero(buf, size);
		break;
	case VARIANT_RANDOM:
		arc4random_buf(buf, size);
		break;
	case VARIANT_TYPICAL:
		fill_with_typical_data(buf, size);
		break;
	default:
		err(kInvalidArgument, "Unknown allocation variant\n");
	}

	return buf;
}

static uint64_t
decompress_buffer(unsigned char *buf, size_t size)
{
	/*
	 * Fault in the compressed buffer to measure the decompression
	 * throughput.
	 */
	uint64_t start_time, end_time;
	start_time = current_timestamp_ns();
	volatile unsigned char val;
	for (unsigned char* ptr = buf; ptr < buf + size; ptr += vm_kernel_page_size) {
		val = *ptr;
	}
	end_time = current_timestamp_ns();
	return end_time - start_time;
}

/*
 * Gives us the compression ratio we see in the typical case (~2.5)
 */
void
fill_with_typical_data(unsigned char *buf, size_t size)
{
	for (size_t i = 0; i < size / vm_kernel_page_size; i++) {
		unsigned char val = 0;
		for (size_t j = 0; j < vm_kernel_page_size; j += 16) {
			memset(&buf[i * vm_kernel_page_size + j], val, 16);
			if (i < 3400 * (vm_kernel_page_size / 4096)) {
				val++;
			}
		}
	}
}

static void
parse_arguments(int argc, const char** argv, test_args_t *args)
{
	int current_positional_argument = 0;
	long duration = -1, size_mb = -1;
	memset(args, 0, sizeof(test_args_t));
	for (int current_argument = 1; current_argument < argc; current_argument++) {
		if (argv[current_argument][0] == '-') {
			if (strcmp(argv[current_argument], "-v") == 0) {
				args->ta_verbose = true;
			} else {
				fprintf(stderr, "Unknown argument %s\n", argv[current_argument]);
				print_help(argv);
				exit(kInvalidArgument);
			}
			if (current_argument >= argc) {
				print_help(argv);
				exit(kInvalidArgument);
			}
		} else {
			const char *curr = argv[current_argument];
			if (current_positional_argument == 0) {
				if (strcasecmp(curr, kCompressArgument) == 0) {
					args->ta_variant = VARIANT_COMPRESS;
				} else if (strcasecmp(curr, kCompressAndDecompressArgument) == 0) {
					args->ta_variant = VARIANT_COMPRESS_AND_DECOMPRESS;
				} else {
					print_help(argv);
					exit(kInvalidArgument);
				}
			} else if (current_positional_argument == 1) {
				if (strcasecmp(curr, kAllocZeroes) == 0) {
					args->ta_alloc_type = VARIANT_ZEROS;
				} else if (strcasecmp(curr, kAllocRandom) == 0) {
					args->ta_alloc_type = VARIANT_RANDOM;
				} else if (strcasecmp(curr, kAllocTypical) == 0) {
					args->ta_alloc_type = VARIANT_TYPICAL;
				} else {
					print_help(argv);
					exit(kInvalidArgument);
				}
			} else if (current_positional_argument == 2) {
				duration = strtol(argv[current_argument], NULL, 10);
				if (duration <= 0) {
					print_help(argv);
					exit(kInvalidArgument);
				}
			} else if (current_positional_argument == 3) {
				size_mb = strtol(argv[current_argument], NULL, 10);
				if (size_mb <= 0) {
					print_help(argv);
					exit(kInvalidArgument);
				}
			} else {
				print_help(argv);
				exit(kInvalidArgument);
			}
			current_positional_argument++;
		}
	}
	if (current_positional_argument != 4) {
		fprintf(stderr, "Expected 4 positional arguments. %d were supplied.\n", current_positional_argument);
		print_help(argv);
		exit(kInvalidArgument);
	}
	args->ta_duration_seconds = (uint64_t) duration;
	args->ta_buffer_size = ((uint64_t) size_mb * (1UL << 20));
}

static void
print_help(const char** argv)
{
	fprintf(stderr, "%s: [-v] <test-variant> allocation-type duration_seconds buffer_size_mb\n", argv[0]);
	fprintf(stderr, "\ntest variants:\n");
	fprintf(stderr, "	%s	Measure compressor throughput.\n", kCompressArgument);
	fprintf(stderr, "	%s	Measure compressor and decompressor throughput.\n", kCompressAndDecompressArgument);
	fprintf(stderr, "\n allocation types:\n");
	fprintf(stderr, "	%s	All zeros.\n", kAllocZeroes);
	fprintf(stderr, "	%s	Random bytes.\n", kAllocRandom);
	fprintf(stderr, "	%s	Typical compression ratio (~2.5:1).\n", kAllocTypical);
}
