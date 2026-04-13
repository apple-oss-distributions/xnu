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

// MOCK_LIB_INCLUDE_UT_FUZZ silences the warning related to __BUILDING_WITH_LIBFUZZER__ because libmocks is never built with libfuzzer instrumentation,
// even when BUILD_LIBFUZZER=1 is passed to make. We want the warning to appear only when building fuzz test files.
#define MOCK_LIB_INCLUDE_UT_FUZZ
#include "unit_test_fuzz.h"
#include "fibers/fibers.h"

ut_fuzz_mutate_func_t ut_fuzz_current_mutator = NULL;

typedef size_t (*llvm_fuzzer_mutate_t)(uint8_t *data, size_t size, size_t max_size);
static llvm_fuzzer_mutate_t llvm_fuzzer_mutate = NULL;

// Used by libfuzzer
size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed)
{
	if (ut_fuzz_current_mutator) {
		return (ut_fuzz_current_mutator)(data, size, max_size, seed);
	}
	if (llvm_fuzzer_mutate == NULL) {
		llvm_fuzzer_mutate = dlsym(RTLD_DEFAULT, "LLVMFuzzerMutate");
	}
	return llvm_fuzzer_mutate(data, size, max_size);
}

static char* ut_fuzz_tmp_filename;
static void
ut_fuzz_tmp_filename_cleanup(void)
{
	if (ut_fuzz_tmp_filename) {
		unlink(ut_fuzz_tmp_filename);
		free(ut_fuzz_tmp_filename);
	}
}

char*
create_executable_tmpfile_with_content(char* buffer, size_t size)
{
	char template[] = "/tmp/ut_fuzz_cmd.XXXXXX";
	int fd = mkstemp(template);
	if (fd == -1) {
		return NULL;
	}
	if (fchmod(fd, S_IRWXU) == -1) {
		close(fd);
		unlink(template);
		return NULL;
	}

	write(fd, buffer, size);

	// mkstemp modifies template
	char* path = strdup(template);
	if (path == NULL) {
		unlink(template);
		return NULL;
	}

	// unlink at exit so eventual subprocesses can use the file as executable
	ut_fuzz_tmp_filename = path;
	atexit(&ut_fuzz_tmp_filename_cleanup);

	return path;
}

/*
 * Here it lives the fibers interleaving feedback for Libfuzzer.
 * It is based on reads-from relationships on memory objects from different fibers.
 * The Libfuzzer 9-bit coverage map is extended to trace, for every memory read, the tuple (mem write location, mem read location)
 * where mem write location is the code location of the last memory write to that address if happened from another fiber.
 */

#define EVENTS_MAP_SIZE (65536 * 16)
#define FEEDBACK_MAP_SIZE (65536)

static size_t
locations_hash_index(uintptr_t read_loc, uintptr_t write_loc)
{
	return read_loc ^ (write_loc >> 1);
}

static size_t
object_hash_index(void *object)
{
	size_t x = (size_t)object;
	size_t z = (x += 0x9e3779b97f4a7c15);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
	return (z ^ (z >> 31)) % EVENTS_MAP_SIZE;
}

struct memop_event {
	void *object;
	uint32_t write_loc;
	int fiber_id;
};

typedef void (*sanitizer_cov_8bit_counters_init_t)(char *start, char *end);

struct memop_event *fibers_fuzzing_feedback_events_map;
char *fibers_fuzzing_feedback_map;

void
fibers_fuzzing_feedback_setup(void)
{
	if (fibers_fuzzing_feedback_events_map) {
		memset(fibers_fuzzing_feedback_events_map, 0, sizeof(struct memop_event) * EVENTS_MAP_SIZE);
	} else {
		fibers_fuzzing_feedback_events_map = calloc(sizeof(struct memop_event), EVENTS_MAP_SIZE);
	}

	if (fibers_fuzzing_feedback_map) {
		memset(fibers_fuzzing_feedback_map, 0, sizeof(char) * FEEDBACK_MAP_SIZE);
	} else {
		raw_printf("==== Initializating fibers feedback for fuzzing ====\n");
		fibers_fuzzing_feedback_map = calloc(sizeof(char), FEEDBACK_MAP_SIZE);

		sanitizer_cov_8bit_counters_init_t func = dlsym(RTLD_DEFAULT, "__sanitizer_cov_8bit_counters_init");
		if (func) {
			func(fibers_fuzzing_feedback_map, fibers_fuzzing_feedback_map + FEEDBACK_MAP_SIZE);
		}
	}
}

void
fibers_fuzzing_feedback_reset(void)
{
	if (!fibers_fuzzing_feedback_events_map || !fibers_fuzzing_feedback_map) {
		return;
	}

	memset(fibers_fuzzing_feedback_events_map, 0, sizeof(struct memop_event) * EVENTS_MAP_SIZE);
	// fibers_fuzzing_feedback_map is being reset by libfuzzer itself after each fuzz case
}

void
fibers_fuzzing_feedback_trace(void *pc, bool is_store, void *object)
{
	if (!fibers_fuzzing_feedback_events_map || !fibers_fuzzing_feedback_map) {
		return;
	}

	if (is_store) {
		uintptr_t write_loc = (uintptr_t)pc;
		write_loc = (write_loc >> 4) ^ (write_loc << 8);
		write_loc = write_loc % FEEDBACK_MAP_SIZE;

		size_t idx = object_hash_index(object);
		fibers_fuzzing_feedback_events_map[idx].object = object;
		fibers_fuzzing_feedback_events_map[idx].write_loc = (uint32_t)write_loc;
		fibers_fuzzing_feedback_events_map[idx].fiber_id = fibers_current->id;
	} else {
		size_t idx = object_hash_index(object);
		void *stored_object = fibers_fuzzing_feedback_events_map[idx].object;
		if (stored_object == object && fibers_fuzzing_feedback_events_map[idx].fiber_id != fibers_current->id) {
			uintptr_t read_loc = (uintptr_t)pc;
			read_loc = (read_loc >> 4) ^ (read_loc << 8);
			read_loc = read_loc % FEEDBACK_MAP_SIZE;

			uintptr_t write_loc = fibers_fuzzing_feedback_events_map[idx].write_loc;
			size_t feedback_idx = locations_hash_index(read_loc, write_loc);
			fibers_fuzzing_feedback_map[feedback_idx] = 1;
		}
	}
}
