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
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <mach-o/dyld.h>
#include <pthread.h>
#include <time.h>
#include <spawn.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm.mte"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_OWNER("n_sabo"),
	T_META_IGNORECRASHES(".*arm_mte.*")
	);

static int n_threads = 20;
static int n_procs = 30;
/* When run with full_test=true, the device needs to be opened
 * and connected to the internet. This doesn't fare well in BATS,
 * but is useful for when running this test on a properly set up
 * device at desk. */
bool full_test = false;

#if TARGET_OS_IOS
const char *terminate_safari = "killall -9 MobileSafari";
const char *safari_identifier = "com.apple.mobilesafari";
#elif TARGET_OS_OSX
const char *safari_path = "/Applications/Safari.app/Contents/MacOS/Safari";
const char *terminate_safari = "killall -9 Safari";
const char *safari_identifier = "com.apple.Safari";
#endif

typedef struct compressor_stats {
	uint64_t tag_compressions;
	uint64_t tag_decompressions;
} compressor_stats;

static void*
allocate_memory_and_wait(void *arg)
{
	T_SETUPBEGIN;
	static const size_t ALLOC_SIZE = KERNEL_BUFFER_COPY_THRESHOLD;
	long thread_num_for_proc = (long)arg;
	vm_address_t address = (vm_address_t)NULL;

	boolean_t is_tagged = thread_num_for_proc % 2;

	int flags = VM_FLAGS_ANYWHERE;
	if (is_tagged) {
		flags |= VM_FLAGS_MTE;
	}

	/* We want to allocate the max amount of memory we'll need for the test */
	kern_return_t kr = vm_allocate(mach_task_self(), &address, ALLOC_SIZE, flags);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");
	char *untagged_ptr = (char *)address;
	T_SETUPEND;

	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(orig_tag, 0U, "originally assigned tag is zero");

	if (is_tagged) {
		char *random_tagged_ptr = NULL;
		/*
		 * Generate the random tag. xnu automatically excludes 0 as a tag
		 * for userspace: ensure that it never shows up in the loop below.
		 */
		for (unsigned int i = 0; i < NUM_MTE_TAGS * 4; i++) {
			random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, 0);
			T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
			    "random tag was not taken from excluded tag set");

			ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
			T_QUIET; T_EXPECT_EQ_ULONG(diff, (ptrdiff_t)0, "untagged %p and tagged %p have identical address bits",
			    untagged_ptr, random_tagged_ptr);
		}

		/* Ensure that basic set/read/access operations work */

		/* Store the last generated random tag */
		__arm_mte_set_tag((void *)random_tagged_ptr);
		/* Read it back and ensure it matches */
		char *newly_tagged_ptr = __arm_mte_get_tag((void *)random_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_PTR(newly_tagged_ptr, random_tagged_ptr, "tag was committed to memory correctly");
		/* Ensure we can access */
		newly_tagged_ptr[0] = 'a';
		/* Reset the initial zero tag */
		__arm_mte_set_tag((void *)address);
	} else {
		for (uint64_t i = 0; i < ALLOC_SIZE; ++i) {
			orig_tagged_ptr[i] = 'a';
		}
	}

	T_QUIET; T_ASSERT_MACH_SUCCESS(vm_deallocate(mach_task_self(), address, ALLOC_SIZE), "Deallocated memory");
	return (void *)NULL;
}

T_HELPER_DECL(create_many_threads_helper, "A helper that creates n_threads threads and assert they exit successfully") {
	pthread_t thread[n_threads];
	void *status = NULL;

	/* the process should be mte enabled */
	T_QUIET; T_ASSERT_TRUE(validate_proc_pidinfo_mte_status(getpid(), true), "process is running with MTE");

	/* Create multiple threads */
	for (long thread_num = 0; thread_num < n_threads; thread_num++) {
		int return_code = pthread_create(&thread[thread_num], NULL, allocate_memory_and_wait, (void*) thread_num);
		T_QUIET; T_ASSERT_POSIX_ZERO(return_code, "Created thread %li", thread_num);
	}

	/* Wait for all threads to finish */
	for (int thread_num = 0; thread_num < n_threads; thread_num++) {
		int return_code = pthread_join(thread[thread_num], &status);
		T_QUIET; T_ASSERT_POSIX_ZERO(return_code, "Thread %d joined successfully", thread_num);
	}
	T_PASS("Process with pid %d exiting\n", getpid());
}

T_HELPER_DECL(app_helper, "A helper that launches and stimulates Safari and Notes") {
#if TARGET_OS_IOS
	int buffer_size = 256;
	char launch_safari[buffer_size] = {};
	snprintf(launch_safari, buffer_size, "xctitool launch %s", safari_identifier);
	/* For now, the running Safari process will not have MTE.
	 * Eventually, MTE will be enabled on Safari by default from the system's launchd plist. */
	T_ASSERT_POSIX_ZERO(system(launch_safari), "launchd Safari");

	/* Move past home screen to launch app in foreground */
	T_ASSERT_POSIX_ZERO(system("LaunchApp -unlock com.apple.springboard"), "open homescreen");

	/* Process 1: Safari, enabled with MTE, launched and we open a new tab */
	T_ASSERT_POSIX_ZERO(system("xctitool interact com.apple.mobilesafari -action \"tap\" -element \"NewTabButton\""), "new Safari tab");

	if (full_test) {
		T_ASSERT_POSIX_ZERO(system("xctitool interact com.apple.mobilesafari --element \"favoritesItemIdentifierContent\" --action tap"), "Safari internet search");
	}

	/* Process 2: Notes app (spawned without MTE), brought to foreground */
	T_ASSERT_POSIX_ZERO(system("xctitool launch com.apple.mobilenotes"), "launch notes app");

#elif TARGET_OS_OSX
	int buffer_size = 256;
	char launch_safari[buffer_size] = {};
	snprintf(launch_safari, buffer_size, "xctitool launch %s", safari_identifier);
	if (full_test) {
		/* Although these commands pass at desk, weird things happen in BATS */
		T_ASSERT_POSIX_ZERO(system(launch_safari), "launchd Safari");
		T_ASSERT_POSIX_ZERO(system("xctitool interact com.apple.Safari -action \"click\" -element \"NewTabButton\""), "new Safari tab");
		/* Since J7XX hardware in BATS can connect to WiFi, make a search.
		 * This action opens one of the recommended websites on the Safari homepage .*/
		T_ASSERT_POSIX_ZERO(system("xctitool interact com.apple.Safari --element \"linkRecommendationCollectionViewItem\" --action click"), "Safari internet search");
		T_ASSERT_POSIX_ZERO(system("xctitool launch com.apple.Notes"), "launch notes app");
	}
#endif
}

T_HELPER_DECL(arm_mte_stress_helper, "forks many multi-threaded processes that allocated tagged and untagged memory") {
	dt_helper_t helpers[n_procs + 1];
	/* Start the helper that spawns Safari with MTE and excercises it in interesting ways */
	helpers[0] = dt_fork_helper("app_helper");
	/* Start the helpers that allocate tagged memory from multiple threads, for multiple processes */
	for (int i = 1; i <= n_procs; ++i) {
		helpers[i] = dt_fork_helper("create_many_threads_helper");
	}
	dt_run_helpers(helpers, (unsigned long)n_procs + 1, 600);
}

void
run_munch(bool with_lim_resident)
{
	/* Use munch to wire down as much memory as possible. We want the memory to stay
	 * wired throughout the test, to make it easier to invoke the compressor. This is why
	 * we wire it at priority 98. However, we want the test process to proceed after wiring
	 * the memory, so wire it in the background, otherwise, the test blocks at this step. */
	T_QUIET; T_ASSERT_POSIX_ZERO(system("munch --lim-jetsam 98 --type=wired --cfg-background")
	    , "wired memory with munch");

	/*
	 * Start munch to increase memory pressure by creating as much page demand as possible,
	 * filling new pages with zeros, and creating the need for memory to be compressed or swapped.
	 * Spawn this with MTE, as malloc, in some cases, allocates tagged memory
	 */
	if (with_lim_resident) {
		char *munch_args[] = {"/usr/local/bin/munch", "--type=malloc", "--lim-resident", "--fill-zero", "--demand-pattern=exponential", "--demand-increment=unlimited", "--cfg-background", NULL};
		posix_spawn_then_perform_action_from_process(munch_args, MTE_SPAWN_USE_LEGACY_API, 0);
	}
}

static void
tear_down(void)
{
	/* Terminate munch */
	T_QUIET; T_EXPECT_POSIX_SUCCESS(system("killall -9 munch"), "terminated munch");
}

bool
should_run_munch_lim_resident(int argc, char *const *argv)
{
	if (argc == 2) {
		if (atoi(argv[1]) == 1) {
			T_LOG("Will run with munch lim-resident");
			return true;
		}
	}
	return false;
}

int
parse_num_cycles(int argc, char *const *argv)
{
	if (argc >= 1) {
		if (atoi(argv[0]) > 0) {
			T_LOG("Will run %d cycles", n_procs);
			return atoi(argv[0]);
		}
	}
	return 3;
}

void
set_test_mode(int argc, char *const *argv)
{
	if (argc >= 3) {
		if (atoi(argv[2]) == 1) {
			T_LOG("Will run the full test version. Requires internet and unlocked device.");
			full_test = true;
		}
	}
}

void
launch_helper(char *helper_name)
{
	char path[PATH_MAX] = {};
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *helper_args[] = { path, "-n", helper_name, NULL};
	int status = -1;
	pid_t child_pid = 0;

	/* Now, continuously allocate tagged memory on behalf of multiple, multi-threaded processes
	 * by spawning arm_mte_stress_helper repeatedly and launching Safari with MTE and Notes without MTE
	 * to provide some end-to-end system testing. */
	int ret = posix_spawn(&child_pid, helper_args[0], NULL, NULL, helper_args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_ASSERT_NE(child_pid, 0, "posix_spawn");

	/* Ensure the process from which tagged memory was allocated succeeded. */
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
	T_EXPECT_TRUE(WIFEXITED(status), "exited successfully");
	T_EXPECT_TRUE(WEXITSTATUS(status) == 0, "exited with status %d", WEXITSTATUS(status));
}

/*
 *  One can change the level of memory pressure applied and number of iterations
 *  via the cli as follows:
 *
 *  ./arm_mte_stress arm_mte_stress_cycler -- <num_cycles> <with_lim_resident> <test_mode>
 *
 *      <num_cycles>: number of cycles to repeat the test. Default is 3.
 *      <with_lim_resident>: should be 1 to specify running the test with extra pressure.
 *      <test_mode>: should be 1 specify running the test with Safari internet searches.
 */
T_DECL(arm_mte_stress_cycler,
    "Wires down as much memory as permitted using munch and allocates tagged memory "
    "from multiple multi-threaded processes to create memory pressure. Launches Safari "
    "with MTE and opens a new tab. Then launches Notes, which is not MTE enabled, to "
    "exercise the system in a more interesting way. This is repeated three times and then "
    "sysctls are used to ensure that the compressor is compressing and decompressing tag "
    "storage pages. Test can be enhanced to run more cycles, or add additional memory "
    "pressure when run at desk. ",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    /* For now, J8XX form-factor devices with WiFi are not available in BATS */
#if TARGET_OS_OSX
    T_META_REQUIRES_NETWORK(true),
#endif
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(false) /* rdar://147337971 */) {
	T_ATEND(tear_down);

	/* User override to add extra memory pressure by running munch --lim-resident.
	 * Default is without. */
	bool with_lim_resident = should_run_munch_lim_resident(argc, argv);
	/* User override of number of cycles to repeat the test. Default is 3. */
	int num_cycles = parse_num_cycles(argc, argv);
	/* User override to determine which mode to run the test in. A value of 1
	 * means making Safari searches and requires internet connectivity. */
	set_test_mode(argc, argv);

	/* Create memory pressure using munch. */
	run_munch(with_lim_resident);

	struct compressor_stats *compressor_data = malloc(num_cycles * sizeof(struct compressor_stats));

	for (int i = 0; i < num_cycles; ++i) {
		/* Verify that MTE compression is not disabled on the device */
		uint64_t no_compressor_pager_for_mte_count = sysctl_get_Q("vm.mte.no_compressor_pager_for_mte");
		if (no_compressor_pager_for_mte_count > 0) {
			T_SKIP("MTE compression is disabled on this device.");
		}

		compressor_data[i].tag_compressions = sysctl_get_Q("vm.mte.compress_pages_compressed");
		T_LOG("Compressed tags: %llu compressed tags", compressor_data[i].tag_compressions);
		compressor_data[i].tag_decompressions = sysctl_get_Q("vm.mte.compress_pages_decompressed");
		T_LOG("Decompressed tags: %llu decompressed tags", compressor_data[i].tag_decompressions);

		/* Now, continuously allocate tagged memory on behalf of multiple, multi-threaded processes
		 *  by spawning arm_mte_stress_helper repeatedly and launching Safari with MTE and Notes without MTE
		 *  to provide some end-to-end system testing. */
		launch_helper("arm_mte_stress_helper");

		/* When invoked with a larger number of cycles, ensure tag pages are compressed and
		 * decompressed throughout the test */
		if (i >= 40 && i >= (num_cycles / 3)) {
			/* Ensure the compressor is compressing and decompressing tag pages. */
			/* If after (num_cycles / 3) rounds, compressions and decompressions have not */
			/* increased, something is blocked */
			T_EXPECT_GT_(compressor_data[i].tag_compressions, compressor_data[i - (num_cycles / 3)].tag_compressions, "MTE tag pages are being compressed as expected");
			T_EXPECT_GT_(compressor_data[i].tag_decompressions, compressor_data[i - (num_cycles / 3)].tag_decompressions, "MTE tag pages are being decompressed as expected");
		}
	}

	/* Assert tag pages were compressed or decompressed since the beginning of the test. */
	T_EXPECT_TRUE((compressor_data[num_cycles - 1].tag_compressions > compressor_data[0].tag_compressions) ||
	    (compressor_data[num_cycles - 1].tag_decompressions > compressor_data[0].tag_decompressions),
	    "MTE tag pages are being compressed and/or decompressed as expected");

	/* Summarize compression / decompression growth over the duration of the test */
	T_LOG("Tag page compressions:");
	for (int i = 0; i < num_cycles; ++i) {
		/* T_LOG inserts a newline after each metric, after printing a timestamp.
		 * That makes these statistics difficult to transfer over to say, excel,
		 * for further analysis. Print the values in a single, comma delineated line.
		 */
		fprintf(stderr, "%llu, ", compressor_data[i].tag_compressions);
	}
	T_LOG("Tag page decompressions:");
	for (int i = 0; i < num_cycles; ++i) {
		fprintf(stderr, "%llu, ", compressor_data[i].tag_decompressions);
	}

	free(compressor_data);
}
