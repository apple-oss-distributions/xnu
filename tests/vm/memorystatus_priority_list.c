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
 *
 */

#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>
#include <mach-o/dyld.h>
#include <mach/mach_vm.h>
#include <mach/vm_page_size.h>
#include <mach/shared_region.h>
#include <mach/mach.h>
#include <os/reason_private.h>
#include <TargetConditionals.h>
#include <darwintest.h>
#include <darwintest_utils.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.memorystatus"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(true),
	T_META_TAG_VM_PREFERRED
	);

#define SIZE_ESTIMATE_EXTRA_ENTRIES 5
#define MAX_TRIES 3

#define _STR(x) #x
#define STR(x) _STR(x)

memorystatus_priority_entry_v2_t*
get_priority_list(pid_t pid, int call, size_t entry_size, ssize_t* len)
{
	int i;
	ssize_t size;
	memorystatus_priority_entry_v2_t *list = NULL;

	for (i = 0; i < MAX_TRIES; i++) {
		T_LOG("Attempt %d", i + 1);

		size = memorystatus_control(call, pid, 0, NULL, 0);

		T_ASSERT_GT(size, 0l, "Priority list query size > 0");
		T_ASSERT_EQ(size % entry_size, 0ul, "Priority list size is multiple of struct size");

		if (size <= 0) {
			return NULL;
		}

		/* pad out the size just in case the list gets bigger */
		if (pid == 0) {
			size += SIZE_ESTIMATE_EXTRA_ENTRIES * entry_size;
		}

		list = malloc(size);
		T_QUIET; T_ASSERT_NOTNULL(list, "malloc");

		*len = memorystatus_control(call, pid, 0, list, size);

		if (*len <= 0) {
			T_LOG("Failed, maybe the list grew? Trying again...");
			free(list);
			continue;
		}

		T_ASSERT_GE(size, *len, "List fits in buffer");
		T_ASSERT_GT(size, 0l, "List size nonzero");
		return list;
	}

	T_FAIL("Tried more than MAX_TRIES=" STR(MAX_TRIES) " times");
	return NULL;
}

void
validate_entry(memorystatus_priority_entry_v2_t *entry, size_t entry_size, pid_t expect_pid)
{
	int i;
	if (expect_pid == -1) {
		T_QUIET; T_ASSERT_GE(entry->pid, 0, "PID valid");
		T_QUIET; T_ASSERT_NE(entry->pid, 0, "kernel_task not in list");
		T_QUIET; T_ASSERT_NE(entry->pid, 1, "launchd not in list");
	} else {
		T_QUIET; T_ASSERT_EQ(entry->pid, expect_pid, "PID correct");
	}

	if (entry->pid > 1) {
		T_QUIET; T_ASSERT_GE(
			entry->priority,
			0,
			"Entry priority >= 0");
		T_QUIET; T_ASSERT_LE(
			entry->priority,
			JETSAM_PRIORITY_MAX,
			"Entry priority <= JETSAM_PRIORITY_MAX (" STR(JETSAM_PRIORITY_MAX) ")");
	} else {
		T_QUIET; T_ASSERT_EQ(
			entry->priority,
			JETSAM_PRIORITY_INTERNAL,
			"Entry priority == JETSAM_PRIORITY_INTERNAL (" STR(JETSAM_PRIORITY_INTERNAL) ")");
	}

	if (entry_size == sizeof(memorystatus_priority_entry_v2_t)) {
		boolean_t found_nonzero = false;
		for (i = 0; i < sizeof(entry->_reserved) / sizeof(entry->_reserved[0]); i++) {
			if (entry->_reserved[i]) {
				found_nonzero = true;
				break;
			}
		}
		T_QUIET; T_ASSERT_FALSE(found_nonzero, "Entry reserved is empty");
	}
}

T_DECL(jetsam_priority_list_v2_list, "Jetsam priority list v2 - list")
{
	int i;
	ssize_t len;
	memorystatus_priority_entry_v2_t *list = get_priority_list(
		0,
		MEMORYSTATUS_CMD_GET_PRIORITY_LIST_V2,
		sizeof(*list),
		&len);

	T_ASSERT_NOTNULL(list, "Priority list not null");
	for (i = 0; i < len / sizeof(memorystatus_priority_entry_v2_t); i++) {
		validate_entry(&list[i], sizeof(*list), -1);
	}
	free(list);
	T_PASS("Entries valid");
}

void
validate_single(pid_t pid)
{
	ssize_t len;
	memorystatus_priority_entry_v2_t *list = get_priority_list(
		pid,
		MEMORYSTATUS_CMD_GET_PRIORITY_LIST_V2,
		sizeof(*list),
		&len);

	T_ASSERT_NOTNULL(list, "Getting self priority entry");
	T_ASSERT_EQ(len, sizeof(memorystatus_priority_entry_v2_t), "Single entry returned");
	validate_entry(list, sizeof(*list), pid);
	free(list);
}

T_DECL(jetsam_priority_list_v2_single, "Jetsam priority list v2 - single")
{
	T_LOG("Getting entry for self...");
	validate_single(getpid());

	T_LOG("Getting entry for launchd...");
	validate_single(1);

	T_PASS("Entries valid");
}

T_DECL(jetsam_priority_list_compat, "Jetsam priority list - v1 compat")
{
	int i;
	ssize_t len;

	memorystatus_priority_entry_t *list = (memorystatus_priority_entry_t*) get_priority_list(
		0,
		MEMORYSTATUS_CMD_GET_PRIORITY_LIST,
		sizeof(*list),
		&len);

	T_ASSERT_NOTNULL(list, "Priority list not null");

	for (i = 0; i < len / sizeof(memorystatus_priority_entry_v2_t); i++) {
		validate_entry((memorystatus_priority_entry_v2_t*) (&list[i]), sizeof(*list), -1);
	}

	free(list);
	T_PASS("Entries valid");
}
