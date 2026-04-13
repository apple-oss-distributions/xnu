/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#include "unit_test_utils.h"
#include "fibers/schedulers.h"
#include "fibers/random.h"

// Local min macro
#define _FDP_MIN(a, b) (((a) < (b)) ? (a) : (b))

// Do not instrument fdp functions with coverage
#define ATTR_NO_SANCOV __attribute__((no_sanitize("coverage")))

#ifndef MOCK_LIB_INCLUDE_UT_FUZZ
#ifndef __BUILDING_WITH_LIBFUZZER__
#pragma message("compiling a fuzz target without the libfuzzer instrumentation, add BUILD_LIBFUZZER=1 to the make arguments to get coverage feedback")
#endif
#endif

// advanced: to register custom coverage maps
extern void __sanitizer_cov_8bit_counters_init(char *start, char *end);

extern char ***_NSGetArgv(void);
extern int *_NSGetArgc(void);

extern int LLVMFuzzerRunDriver(int *argc, char ***argv, int (*callback)(const uint8_t *data, size_t size));
extern size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

extern void fibers_fuzzing_feedback_setup(void);
extern void fibers_fuzzing_feedback_reset(void);
extern void fibers_fuzzing_feedback_trace(void *pc, bool is_store, void *object);

#define T_FUZZ(name, description, ...)                                                \
	static int fuzztarget_##name(const uint8_t* data, size_t size);                   \
	T_DECL(name, description, ##__VA_ARGS__)                                          \
	{                                                                                 \
	        ut_fuzz_trampoline_to_libfuzzer(#name, fuzztarget_##name, argc, argv);    \
	}                                                                                 \
	static int fuzztarget_##name(const uint8_t* data, size_t size)

#define T_FUZZ_INIT(name)                                                 \
	static void ut_fuzz_init_##name(int *argc, char *const **argv);       \
	static struct ut_fuzz_init_data ut_fuzz_init_data_##name              \
	        __attribute__((used, section("__DATA,__ut_fuzz_init"))) = {   \
	                T_TOSTRING_(name), &ut_fuzz_init_##name               \
	        };                                                            \
	static void ut_fuzz_init_##name(int *argc, char *const **argv)

#define T_FUZZ_MUTATOR(name)                                                                              \
	static size_t ut_fuzz_mutate_##name(uint8_t *data, size_t size, size_t max_size, unsigned int seed);  \
	static struct ut_fuzz_mutate_data ut_fuzz_mutate_data_##name                                          \
	        __attribute__((used, section("__DATA,__ut_fuzz_mutate"))) = {                                 \
	                T_TOSTRING_(name), &ut_fuzz_mutate_##name                                             \
	        };                                                                                            \
	static size_t ut_fuzz_mutate_##name(uint8_t *data, size_t size, size_t max_size, unsigned int seed)

typedef void (*ut_fuzz_init_func_t)(int *argc, char *const **argv);

struct ut_fuzz_init_data {
	char *test_name;
	ut_fuzz_init_func_t func;
};

extern struct ut_fuzz_init_data _ut_fuzz_init_start[] __asm("section$start$__DATA$__ut_fuzz_init");
extern struct ut_fuzz_init_data _ut_fuzz_init_end __asm("section$end$__DATA$__ut_fuzz_init");

typedef size_t (*ut_fuzz_mutate_func_t)(uint8_t *data, size_t size, size_t max_size, unsigned int seed);

struct ut_fuzz_mutate_data {
	char *test_name;
	ut_fuzz_mutate_func_t func;
};

extern struct ut_fuzz_mutate_data _ut_fuzz_mutate_start[] __asm("section$start$__DATA$__ut_fuzz_mutate");
extern struct ut_fuzz_mutate_data _ut_fuzz_mutate_end __asm("section$end$__DATA$__ut_fuzz_mutate");

extern ut_fuzz_mutate_func_t ut_fuzz_current_mutator;

extern char* create_executable_tmpfile_with_content(char* buffer, size_t size);

// Here to access the test binary __ut_fuzz_mutate section
ATTR_NO_SANCOV static inline void
ut_fuzz_trampoline_to_libfuzzer(const char *name, int (*callback)(const uint8_t *, size_t), int argc, char *const *argv)
{
	const size_t ut_random_buffer_count = 1024;

	size_t i = 0;
	while (&_ut_fuzz_init_start[i] < &_ut_fuzz_init_end) {
		if (strcmp(_ut_fuzz_init_start[i].test_name, name) == 0) {
			(_ut_fuzz_init_start[i].func)(&argc, &argv);
			break;
		}
		++i;
	}

	i = 0;
	while (&_ut_fuzz_mutate_start[i] < &_ut_fuzz_mutate_end) {
		if (strcmp(_ut_fuzz_mutate_start[i].test_name, name) == 0) {
			ut_fuzz_current_mutator = _ut_fuzz_mutate_start[i].func;
			break;
		}
		++i;
	}

	const char *exec_path = (*_NSGetArgv())[0];
	if (argc == 0) {
		// ref. https://llvm.org/docs/LibFuzzer.html
		raw_printf(" ****************************************************************************** \n");
		raw_printf("WARNING: Unlike standard libfuzzer targets, this will act as a unit test if run without any command line argument.\n");
		raw_printf("WARNING: For additional info on args: %s -n %s -- -help=1\n", exec_path, name);
		raw_printf("WARNING: To run in fuzzing mode: %s -n %s -- /path/to/corpus/folder\n", exec_path, name);
		raw_printf(" ****************************************************************************** \n");
		uint64_t ut_random_buffer[ut_random_buffer_count];
		random_r_t rand;
		random_r_set_seed(&rand, 1234);
		for (size_t i = 0; i < ut_random_buffer_count; ++i) {
			ut_random_buffer[i] = random_r_next(&rand);
		}
		callback((const uint8_t *)ut_random_buffer, ut_random_buffer_count * sizeof(uint64_t));
	} else {
		char **new_argv = calloc(argc + 1, sizeof(char*));
		size_t command_alloc = strlen(exec_path) + strlen(name) + 64;
		char *command = calloc(command_alloc, 1);
		snprintf(command, command_alloc, "#!/bin/sh\n%s -n %s -- $@\n", exec_path, name);
		char *exec_file = create_executable_tmpfile_with_content(command, strlen(command));
		new_argv[0] = exec_file;

		int new_argc = argc + 1;
		for (int i = 0; argv != NULL && i < argc; ++i) {
			new_argv[i + 1] = argv[i];
		}
		LLVMFuzzerRunDriver(&new_argc, &new_argv, callback);

		free(new_argv);
	}
}

/*
 * This is an implementation in C of the LLVM FuzzedDataProvider class
 * see compiler-rt/include/fuzzer/FuzzedDataProvider.h for reference
 */

typedef struct {
	uint8_t *data;
	size_t size;
	size_t capacity;
} byte_vector_t;

typedef struct {
	const uint8_t *data_ptr;
	size_t remaining_bytes;
} fuzzed_data_provider_t;

// Byte vector functions

ATTR_NO_SANCOV static inline byte_vector_t *
byte_vector_create(size_t capacity)
{
	byte_vector_t *vector = (byte_vector_t *)malloc(sizeof(byte_vector_t));
	if (!vector) {
		abort();
	}
	vector->data = (uint8_t *)malloc(capacity * sizeof(uint8_t));
	if (!vector->data) {
		free(vector);
		abort();
	}
	vector->size = 0;
	vector->capacity = capacity;
	return vector;
}

ATTR_NO_SANCOV static inline void
byte_vector_destroy(byte_vector_t *vector)
{
	if (vector) {
		free(vector->data);
		free(vector);
	}
}

ATTR_NO_SANCOV static inline void
byte_vector_push_back(byte_vector_t *vector, uint8_t value)
{
	if (vector->size == vector->capacity) {
		vector->capacity *= 2;
		vector->data = (uint8_t *)realloc(vector->data, vector->capacity * sizeof(uint8_t));
		if (!vector->data) {
			abort();
		}
	}
	vector->data[vector->size++] = value;
}

ATTR_NO_SANCOV static inline void
byte_vector_shrink_to_fit(byte_vector_t *vector)
{
	if (vector->size < vector->capacity) {
		vector->capacity = vector->size;
		vector->data = (uint8_t *)realloc(vector->data, vector->capacity * sizeof(uint8_t));
		if (!vector->data && vector->capacity > 0) {
			abort();
		}
	}
}

// Helper functions

ATTR_NO_SANCOV static inline void
fuzzed_data_provider_advance(fuzzed_data_provider_t *provider, size_t num_bytes)
{
	if (num_bytes > provider->remaining_bytes) {
		abort();
	}

	provider->data_ptr += num_bytes;
	provider->remaining_bytes -= num_bytes;
}

ATTR_NO_SANCOV static inline void
fuzzed_data_provider_copy_and_advance(fuzzed_data_provider_t *provider, void *destination, size_t num_bytes)
{
	memcpy(destination, provider->data_ptr, num_bytes);
	fuzzed_data_provider_advance(provider, num_bytes);
}

ATTR_NO_SANCOV static inline byte_vector_t *
fuzzed_data_provider_consume_bytes_internal(fuzzed_data_provider_t *provider, size_t size, size_t num_bytes)
{
	byte_vector_t *result = byte_vector_create(size);
	if (!result) {
		abort();
	}

	fuzzed_data_provider_copy_and_advance(provider, result->data, num_bytes);
	result->size = num_bytes;
	byte_vector_shrink_to_fit(result);
	return result;
}

// API

ATTR_NO_SANCOV static inline void
fuzzed_data_provider_init(fuzzed_data_provider_t *provider, const uint8_t *data, size_t size)
{
	provider->data_ptr = data;
	provider->remaining_bytes = size;
}

ATTR_NO_SANCOV static inline uint8_t
fuzzed_data_provider_consume_byte(fuzzed_data_provider_t *provider)
{
	if (!provider->remaining_bytes) {
		return 0; // default value
	}
	uint8_t next = provider->data_ptr[0];
	fuzzed_data_provider_advance(provider, 1);
	return next;
}

ATTR_NO_SANCOV static inline byte_vector_t *
fuzzed_data_provider_consume_bytes(fuzzed_data_provider_t *provider, size_t num_bytes)
{
	num_bytes = _FDP_MIN(num_bytes, provider->remaining_bytes);
	return fuzzed_data_provider_consume_bytes_internal(provider, num_bytes, num_bytes);
}

ATTR_NO_SANCOV static inline byte_vector_t *
fuzzed_data_provider_consume_bytes_with_terminator(fuzzed_data_provider_t *provider, size_t num_bytes, uint8_t terminator)
{
	num_bytes = _FDP_MIN(num_bytes, provider->remaining_bytes);
	byte_vector_t *result = fuzzed_data_provider_consume_bytes_internal(provider, num_bytes + 1, num_bytes);
	if (result) {
		result->data[result->size - 1] = terminator; // replace last byte with terminator
	}
	return result;
}

ATTR_NO_SANCOV static inline byte_vector_t *
fuzzed_data_provider_consume_remaining_bytes(fuzzed_data_provider_t *provider)
{
	return fuzzed_data_provider_consume_bytes(provider, provider->remaining_bytes);
}

ATTR_NO_SANCOV static inline char *
fuzzed_data_provider_consume_bytes_as_string(fuzzed_data_provider_t *provider, size_t num_bytes)
{
	num_bytes = _FDP_MIN(num_bytes, provider->remaining_bytes);
	char *result = (char *)malloc((num_bytes + 1) * sizeof(char));
	if (!result) {
		abort();
	}
	fuzzed_data_provider_copy_and_advance(provider, result, num_bytes);
	result[num_bytes] = '\0'; // null-terminate
	return result;
}

ATTR_NO_SANCOV static inline char *
fuzzed_data_provider_consume_random_length_string(fuzzed_data_provider_t *provider, size_t max_length)
{
	size_t actual_length = 0;
	char *result = (char *)malloc((max_length + 1) * sizeof(char)); // allocate max possible
	if (!result) {
		abort();
	}
	result[0] = '\0';

	for (size_t i = 0; i < max_length && provider->remaining_bytes > 0; ++i) {
		char next = (char)fuzzed_data_provider_consume_byte(provider);

		if (next == '\\' && provider->remaining_bytes > 0) {
			next = (char)fuzzed_data_provider_consume_byte(provider);
			if (next != '\\') {
				break; // end string if not escaped backslash
			}
		}
		result[actual_length++] = next;
		if (next == 0) {
			// end string as we inserted a NUL to avoid keeping consuming bytes
			break;
		}
		result[actual_length] = '\0'; // keep null-terminated
	}

	char *final_result = (char *)realloc(result, (actual_length + 1) * sizeof(char));
	if (!final_result) {
		free(result);
		abort();
	}
	return final_result;
}

ATTR_NO_SANCOV static inline char *
fuzzed_data_provider_consume_random_length_string_no_max(fuzzed_data_provider_t *provider)
{
	return fuzzed_data_provider_consume_random_length_string(provider, provider->remaining_bytes);
}

ATTR_NO_SANCOV static inline char *
fuzzed_data_provider_consume_remaining_bytes_as_string(fuzzed_data_provider_t *provider)
{
	return fuzzed_data_provider_consume_bytes_as_string(provider, provider->remaining_bytes);
}

ATTR_NO_SANCOV static inline int64_t
fuzzed_data_provider_consume_integral_in_range(fuzzed_data_provider_t *provider, int64_t min, int64_t max)
{
	if (min > max) {
		abort();
	}

	uint64_t range = (uint64_t)(max - min);
	uint64_t result = 0;
	size_t offset = 0;

	while (offset < sizeof(int64_t) * 8 && (range >> offset) > 0 &&
	    provider->remaining_bytes > 0) {
		provider->remaining_bytes--;
		result = (result << 8) | provider->data_ptr[provider->remaining_bytes];
		offset += 8;
	}

	if (range != UINT64_MAX) {
		result = result % (range + 1);
	}

	return (int64_t)(min + result);
}

ATTR_NO_SANCOV static inline int64_t
fuzzed_data_provider_consume_integral(fuzzed_data_provider_t *provider)
{
	return fuzzed_data_provider_consume_integral_in_range(provider, INT64_MIN, INT64_MAX);
}

ATTR_NO_SANCOV static inline double
fuzzed_data_provider_consume_probability(fuzzed_data_provider_t *provider)
{
	uint64_t result = (uint64_t)fuzzed_data_provider_consume_integral(provider);
	return (double)result / (double)UINT64_MAX;
}

ATTR_NO_SANCOV static inline bool
fuzzed_data_provider_consume_bool(fuzzed_data_provider_t *provider)
{
	return 1 & fuzzed_data_provider_consume_integral(provider);
}

ATTR_NO_SANCOV static inline double
fuzzed_data_provider_consume_floating_point_in_range(fuzzed_data_provider_t *provider, double min, double max)
{
	if (min > max) {
		abort();
	}

	double range = 0.0;
	double result = min;
	if (max > 0.0 && min < 0.0 && max > min + __DBL_MAX__) {
		range = (max / 2.0) - (min / 2.0);
		if (fuzzed_data_provider_consume_bool(provider)) {
			result += range;
		}
	} else {
		range = max - min;
	}

	return result + range * fuzzed_data_provider_consume_probability(provider);
}

ATTR_NO_SANCOV static inline double
fuzzed_data_provider_consume_floating_point(fuzzed_data_provider_t *provider)
{
	return fuzzed_data_provider_consume_floating_point_in_range(provider, -__DBL_MAX__, __DBL_MAX__);
}

ATTR_NO_SANCOV static inline int64_t
fuzzed_data_provider_consume_enum(fuzzed_data_provider_t *provider, int64_t k_max_value)
{
	return fuzzed_data_provider_consume_integral_in_range(provider, 0, k_max_value);
}

ATTR_NO_SANCOV static inline int64_t
fuzzed_data_provider_pick_value_in_array(fuzzed_data_provider_t *provider, const int64_t *array, size_t size)
{
	if (size == 0) {
		abort();
	}
	size_t index = (size_t)fuzzed_data_provider_consume_integral_in_range(provider, 0, (int64_t)size - 1);
	return array[index];
}

ATTR_NO_SANCOV static inline size_t
fuzzed_data_provider_consume_data(fuzzed_data_provider_t *provider, void *destination, size_t num_bytes)
{
	num_bytes = _FDP_MIN(num_bytes, provider->remaining_bytes);
	fuzzed_data_provider_copy_and_advance(provider, destination, num_bytes);
	return num_bytes;
}

ATTR_NO_SANCOV static inline size_t
fuzzed_data_provider_remaining_bytes(fuzzed_data_provider_t *provider)
{
	return provider->remaining_bytes;
}
