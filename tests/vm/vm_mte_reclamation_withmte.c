/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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
 * The only difference between this file and vm_mte_reclamation.c is that
 * this file runs with MTE turned on.
 */

#include <ctype.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

#if __arm64__
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm.mteinfo"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

static void
tear_down(void)
{
	/* Terminate munch */
	T_QUIET; T_EXPECT_POSIX_SUCCESS(system("killall -9 munch"),
	    "terminated munch");
}

void
run_munch(void)
{
	/*
	 * Allocates anonymous memory using the 'munch' tool to create
	 * memory pressure in the system, so that we can compress to free up
	 * some pages (triggers compressor)
	 */
	char *munch_args[] =
	{
		"/usr/local/bin/munch",
		"--lim-jetsam=idle",
		"--type=wired",
		"--cfg-background",
		NULL
	};
	posix_spawn_then_perform_action_from_process(munch_args,
	    MTE_SPAWN_USE_LEGACY_API, 0);
	sleep(30);/* Let the system stabilize */
}

void
run_munch_mte(void)
{
	/*
	 * Allocates tagged memory using the 'munch' tool
	 * to trigger tag storage page relocations
	 */

	pid_t pid = fork();
	if (pid == 0) {
		execl("/bin/sh",
		    "sh",
		    "-c",
		    "taskpolicy -S explicit-enable-inherit munch "
		    "--block=1 --type=malloc 10g",
		    (char*)NULL);
		perror("execl");
		exit(EXIT_FAILURE);
	} else if (pid < 0) {
		perror("fork");
		exit(EXIT_FAILURE);
	}
	sleep(30);
	kill(pid, SIGTERM);
	sleep(10);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

T_DECL(vm_mte_ts_for_tagged_malloc,
    "Make sure we don't use tag storage page for tagged malloc heap",
    T_META_BOOTARGS_SET("mte_ts_vm_tag=1_4,7_9,11_12"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	struct {
		uint32_t vm_tag;
		bool mte;
		bool expect_ts;
	} args = {VM_MEMORY_MALLOC_SMALL, true, false};
	T_EXPECT_EQ_INT(1,
	    (int)run_sysctl_test("vm_mte_tag_storage_for_vm_tag", (int64_t)(&args)),
	    "didn't get tag storage page for allocation");
}

T_DECL(test_mte_tag_storage_reclamation,
    "test verifies correct allocation and reclamation of tag storage pages"
    "in the compressor pool controlled by a boot-arg."
    "For test, we take initial readings of vm.mte.compress_ts_pages_used,"
    "vm.mte.cell.inactive,and vm.mte.tag_storage.compressor_relocations."
    "Then we allocate anonymous memory to trigger compressor via munch usage"
    "(vm.mte.compress_ts_pages_used  should increase;"
    "vm.mte.cell.inactive should decrease). Then we add tagged memory pressure"
    "to initiate the fill thread (vm.mte.tag_storage.compressor_relocations"
    "and vm.mte.cell.active should increase,"
    "vm.mte.compress_ts_pages_used should decrease ).",
    T_META_BOOTARGS_SET("mte_ts_vmtag=2,7,11"),
    T_META_BOOTARGS_SET("mte_ts_compressor=1"),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(!TARGET_OS_XR) /* rdar://165838166 */)
{
	T_ATEND(tear_down);
	/*
	 * Allocate a significant amount of wired memory to trigger compressor use,
	 * Check if the compressor is actively compressing pages,
	 * "vm.mte.compress_ts_pages_used" is increasing,
	 * vm.mte.cell.inactive" is decreasing
	 */
	int64_t compress_to_pages_used_initial =
	    sysctl_get_Q("vm.mte.compress_ts_pages_used");
	int64_t  inactive_pages_initial  = sysctl_get_Q("vm.mte.cell.inactive");
	int64_t  relocation_pages_initial =
	    sysctl_get_Q("vm.mte.tag_storage.compressor_relocations");

	run_munch();

	int64_t compress_to_pages_used_final_1 =
	    sysctl_get_Q("vm.mte.compress_ts_pages_used");
	T_QUIET; T_EXPECT_GT(compress_to_pages_used_final_1,
	    compress_to_pages_used_initial,
	    "vm.mte.compress_ts_pages_used is behaving as expected (increasing)");
	sleep(15);
	int64_t  inactive_pages_final = sysctl_get_Q("vm.mte.cell.inactive");
	T_QUIET; T_EXPECT_LT(inactive_pages_final, inactive_pages_initial,
	    "vm.mte.cell.inactive is behaving as expected (decreasing)");

	/*
	 * Track active page counts pre- and post-tagged allocation to
	 * compare for increase
	 */
	int64_t  active_pages_initial  = sysctl_get_Q("vm.mte.cell.active");

	/*
	 * Allocate heavy tagged memory to trigger fill thread,
	 * vm.mte.tag_storage.compressor_relocations to increase
	 */
	run_munch_mte();

	int64_t  relocation_pages_final =
	    sysctl_get_Q("vm.mte.tag_storage.compressor_relocations");
	T_QUIET; T_EXPECT_GT(relocation_pages_final, relocation_pages_initial,
	    "vm.mte.cell.relocation is behaving as expected (increasing)");
	int64_t  active_pages_final = sysctl_get_Q("vm.mte.cell.active");
	T_QUIET; T_EXPECT_GT(active_pages_final, active_pages_initial,
	    "vm.mte.cell.active is behaving as expected (increasing)");
}
#endif /* __arm64__ */
