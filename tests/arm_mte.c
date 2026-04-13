/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_map.h>
#include <mach-o/dyld.h>
#include <spawn_private.h>
#include <sys/aio.h>
#include <sys/spawn_internal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <signal.h>

#include "arm_mte_utilities.h"
#include "test_utils.h"

#if (TARGET_OS_OSX || TARGET_OS_IOS) && defined(__arm64__)
// TODO(PT): It'd be nice to have this as an allow list rather than the inverse,
// but I wasn't able to restrict based on TARGET_OS_[IPHONE|IOS] as this is sometimes set even for XR_OS.
// For now, to keep things moving, just restrict this from being set on platforms where
// we know it's not the case.
#if !(TARGET_OS_XR || TARGET_OS_TV || TARGET_OS_WATCH || TARGET_OS_BRIDGE)
	#define TARGET_SUPPORTS_MTE_EMULATION 1
#endif
#endif

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("ghackmann"),
	T_META_RUN_CONCURRENTLY(true),
	T_META_IGNORECRASHES(".*arm_mte.*"),
	T_META_CHECK_LEAKS(false));

static uint64_t
task_footprint(void)
{
	task_vm_info_data_t ti;
	kern_return_t kr;
	mach_msg_type_number_t count;

	count = TASK_VM_INFO_COUNT;
	kr = task_info(mach_task_self(),
	    TASK_VM_INFO,
	    (task_info_t) &ti,
	    &count);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "task_info()");
#if defined(__arm64__)
	T_QUIET;
	T_ASSERT_EQ(count, TASK_VM_INFO_COUNT, "task_info() count = %d (expected %d)",
	    count, TASK_VM_INFO_COUNT);
#endif /* defined(__arm64__) */
	return ti.phys_footprint;
}

static void
do_mte_tag_check(void)
{
	static const size_t ALLOC_SIZE = MTE_GRANULE_SIZE * 2;

	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, ALLOC_SIZE, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");
	char *untagged_ptr = (char *)address;

	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_ASSERT_EQ_UINT(orig_tag, 0U, "originally assigned tag is zero");

	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_EXPECT_EQ_LLONG(mask, (1LL << 0), "zero tag is excluded");

	char *random_tagged_ptr = NULL;
	/*
	 * Generate the random tag.  We've excluded the original tag, so it should never
	 * reappear no matter how many times we regenerate a new tag.
	 */
	for (unsigned int i = 0; i < NUM_MTE_TAGS * 4; i++) {
		random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
		T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
		    "random tag was not taken from excluded tag set");

		ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_ULONG(diff, (ptrdiff_t)0, "untagged %p and tagged %p have identical address bits",
		    untagged_ptr, random_tagged_ptr);
	}

	/* Time to make things real, commit the tag to memory */
	__arm_mte_set_tag(random_tagged_ptr);

	/* Ensure that we can read back the tag */
	char *read_back = __arm_mte_get_tag(untagged_ptr);
	T_EXPECT_EQ_PTR(read_back, random_tagged_ptr, "tag was committed to memory correctly");

	/* Verify that accessing memory actually works */
	random_tagged_ptr[0] = 't';
	random_tagged_ptr[1] = 'e';
	random_tagged_ptr[2] = 's';
	random_tagged_ptr[3] = 't';
	T_EXPECT_EQ_STR(random_tagged_ptr, "test", "read/write from tagged memory");

	/*
	 * Confirm that the next MTE granule still has the default tag, and then
	 * simulate an out-of-bounds access into that granule.
	 */
	void *next_granule_ptr = orig_tagged_ptr + MTE_GRANULE_SIZE;
	unsigned int next_granule_tag = extract_mte_tag(next_granule_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(next_granule_tag, 0U,
	    "next MTE granule still has its originally assigned tag");

	T_LOG("attempting out-of-bounds access to tagged memory");
	expect_sigkill(^{
		random_tagged_ptr[MTE_GRANULE_SIZE] = '!';
	}, "out-of-bounds access to tagged memory raises uncatchable exception");

	/*
	 * Simulate a use-after-free by accessing orig_tagged_ptr, which has an
	 * out-of-date tag.
	 */
	T_LOG("attempting use-after-free access to tagged memory");
	expect_sigkill(^{
		orig_tagged_ptr[0] = 'T';
	}, "use-after-free access to tagged memory raises uncatchable exception");

	__arm_mte_set_tag(orig_tagged_ptr);
	__arm_mte_set_tag(orig_tagged_ptr + MTE_GRANULE_SIZE);
	vm_deallocate(mach_task_self(), address, ALLOC_SIZE);
}

T_DECL(mte_tag_check,
    "Test MTE2 tag check fault handling",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	do_mte_tag_check();
#endif
}

T_DECL(mte_tag_check_child,
    "Test MTE2 tag check fault in a child process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	pid_t pid = fork();
	if (pid == 0) {
		/*
		 * Make sure the child process also has tag checks enabled.
		 */
		do_mte_tag_check();
	} else {
		T_ASSERT_TRUE(pid != -1, "Checking fork success in parent");

		int status = 0;
		T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
	}
#endif
}

T_DECL(mte_canonical_tag_check,
    "Test MTE4 Canonical Tag Check fault handling",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, MTE_GRANULE_SIZE, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "allocate a canonically-tagged page");
	char *ptr = (char *)address;

	T_LOG("attempting to set tag on canonically-tagged memory");
	char *tagged_ptr = __arm_mte_increment_tag(ptr, 1);
	expect_signal(SIGBUS, ^{
		__arm_mte_set_tag(tagged_ptr);
	}, "setting tag on canonically-tagged memory raises a canonical memory permission fault");

	T_LOG("attempting to access canonically-tagged memory with a tagged address");
	expect_sigkill(^{
		tagged_ptr[0] = '!';
	}, "accessing canonically-tagged memory with a tagged address raises a canonical tag check fault");

	vm_deallocate(mach_task_self(), address, MTE_GRANULE_SIZE);
#endif
}

static void
run_mte_copyio_tests(bool tag_check_faults_enabled)
{
	static_assert(MAXTHREADNAMESIZE >= MTE_GRANULE_SIZE * 2, "kern.threadname parameter can span multiple MTE granules");

	const size_t buf_size = MAXTHREADNAMESIZE;
	const size_t threadname_len = MTE_GRANULE_SIZE * 2;
	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, buf_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");

	char *untagged_ptr = (char *)address;
	/* n.b.: kern.threadname uses unterminated strings */
	memset(untagged_ptr, 'A', threadname_len);

	char *tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, 0);
	__arm_mte_set_tag(tagged_ptr);
	char *next_granule_ptr = tagged_ptr + MTE_GRANULE_SIZE;
	__arm_mte_set_tag(next_granule_ptr);

	int err = sysctlbyname("kern.threadname", NULL, NULL, tagged_ptr, threadname_len);
	T_ASSERT_POSIX_SUCCESS(err, "copyin using tagged pointer succeeds");

	/* Simulate use-after-free by passing in obsolete tag */
	if (tag_check_faults_enabled) {
		expect_sigkill(^{
			sysctlbyname("kern.threadname", NULL, NULL, untagged_ptr, threadname_len);
		}, "copyin using incorrectly-tagged pointer");
	} else {
		err = sysctlbyname("kern.threadname", NULL, NULL, untagged_ptr, threadname_len);
		T_ASSERT_POSIX_SUCCESS(err, "bypass: copyin using incorrectly-tagged pointer succeeds");
	}

	/* Simulate out-of-bounds access by giving the second MTE granule a different tag */
	char *different_tag_next_granule_ptr = __arm_mte_increment_tag(next_granule_ptr, 1);
	T_QUIET; T_ASSERT_NE(different_tag_next_granule_ptr, next_granule_ptr, "__arm_mte_increment_tag()");
	__arm_mte_set_tag(different_tag_next_granule_ptr);
	if (tag_check_faults_enabled) {
		expect_sigkill(^{
			sysctlbyname("kern.threadname", NULL, NULL, tagged_ptr, threadname_len);
		}, "copyin using inconsistently-tagged buffer");
	} else {
		err = sysctlbyname("kern.threadname", NULL, NULL, tagged_ptr, threadname_len);
		T_ASSERT_POSIX_SUCCESS(err, "bypass: copyin using inconsistently-tagged buffer succeeds");
	}
	__arm_mte_set_tag(next_granule_ptr);

	size_t oldlen = buf_size;
	err = sysctlbyname("kern.threadname", tagged_ptr, &oldlen, NULL, 0);
	T_EXPECT_POSIX_SUCCESS(err, "copyout using tagged pointer succeeds");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wshadow"

	if (tag_check_faults_enabled) {
		expect_sigkill(^{
			/* We need to repopulate kern.threadname since it isn't inherited across fork() */
			int err = sysctlbyname("kern.threadname", NULL, NULL, tagged_ptr, threadname_len);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname(kern.threadname)");

			size_t oldlen = buf_size;
			sysctlbyname("kern.threadname", untagged_ptr, &oldlen, NULL, 0);
		}, "copyout using incorrectly-tagged pointer");
	} else {
		size_t oldlen = buf_size;
		int err = sysctlbyname("kern.threadname", untagged_ptr, &oldlen, NULL, 0);
		T_EXPECT_POSIX_SUCCESS(err, "bypass: copyout using incorrectly-tagged pointer succeeds");
	}

	__arm_mte_set_tag(different_tag_next_granule_ptr);
	if (tag_check_faults_enabled) {
		expect_sigkill(^{
			int err = sysctlbyname("kern.threadname", NULL, NULL, tagged_ptr, threadname_len);
			T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname(kern.threadname)");

			size_t oldlen = buf_size;
			sysctlbyname("kern.threadname", tagged_ptr, &oldlen, NULL, 0);
		}, "copyout using inconsistently-tagged buffer");
	} else {
		size_t oldlen = buf_size;
		int err = sysctlbyname("kern.threadname", tagged_ptr, &oldlen, NULL, 0);
		T_EXPECT_POSIX_SUCCESS(err, "bypass: copyout using inconsistently-tagged buffer succeeds");
	}
	__arm_mte_set_tag(next_granule_ptr);

#pragma clang diagnostic pop

	vm_deallocate(mach_task_self(), address, buf_size);
}

T_DECL(mte_copyio,
    "Test MTE tag handling during copyin/copyout operations",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	run_mte_copyio_tests(true);
}

T_DECL(mte_malloc_footprint_test,
    "Test footprint across malloc() and free()",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(false) /* rdar://131390446 */)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	uint64_t count = 1024;
	uint64_t margin = 4;
	char* address[count];
	uint64_t size = PAGE_SIZE;

	for (unsigned int i = 0; i < count; i++) {
		address[i] = (char *) malloc(size);

		char *cp;
		for (cp = (char *) (address[i]); cp < (char *) (address[i] + size); cp += PAGE_SIZE) {
			*cp = 'x';
		}
	}

	uint64_t fp1 = task_footprint();
	T_LOG("Footprint after malloc(): %llu bytes", fp1);

	for (unsigned int i = 0; i < count; i++) {
		free(address[i]);
	}
	uint64_t fp2 = task_footprint();
	T_LOG("Footprint after free(): %llu bytes", fp2);

	T_EXPECT_TRUE(((fp2 + PAGE_SIZE * (count - margin)) <= fp1), "Footprint after free() is higher than expected.");
#endif
}

T_DECL(mte_tagged_memory_direct_io,
    "Test direct I/O on tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */

	uint64_t size = PAGE_SIZE;
	char* address = (char*) malloc(size);

	char *cp;
	for (cp = (char *) (address); cp < (char *) (address + size); cp += PAGE_SIZE) {
		*cp = 'x';
	}

	int fd = open("/tmp/file1", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	T_ASSERT_TRUE(fd > 0, "File open successful");
	T_ASSERT_TRUE(((fcntl(fd, F_NOCACHE, 1)) != -1), "Setting F_NOCACHE");
	ssize_t ret = pwrite(fd, address, size, 0);
	T_ASSERT_TRUE((uint64_t) ret == size, "pwrite() on tagged memory");

	char *incorrectly_tagged = __arm_mte_increment_tag(address, 1);
	ret = pwrite(fd, incorrectly_tagged, size, 0);
	T_ASSERT_TRUE((uint64_t) ret == size, "pwrite() on incorrectly tagged memory passes with direct I/O");

	free(address);
#endif
}

T_DECL(mte_tagged_memory_copy_io,
    "Test direct I/O on tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */

	uint64_t size = PAGE_SIZE;
	char* address = (char*) malloc(size);

	char *cp;
	for (cp = (char *) (address); cp < (char *) (address + size); cp += PAGE_SIZE) {
		*cp = 'x';
	}

	int fd = open("/tmp/file1", O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
	T_ASSERT_TRUE(fd > 0, "File open successful");
	ssize_t ret = pwrite(fd, address, size, 0);
	T_ASSERT_TRUE((uint64_t) ret == size, "pwrite() on tagged memory");

	char *incorrectly_tagged = __arm_mte_increment_tag(address, 1);
	expect_sigkill(^{
		(void)pwrite(fd, incorrectly_tagged, size, 0);
	}, "copy I/O on wrongly tagged memory");

	free(address);
#endif
}


static int FORK_TEST_CHILD_WRITES_FIRST = 0x1;
static int FORK_TEST_CHILD_FORKS = 0x2;
static int FORK_TEST_CHILD_RETAGS = 0x4;
static void
do_fork_test(vm_size_t vm_alloc_sz, int flags)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, vm_alloc_sz, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);

	T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");

	char *untagged_ptr = (char *)address;
	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);

	size_t count;
	size_t offset;
	const vm_size_t NUM_GRANULES = vm_alloc_sz / MTE_GRANULE_SIZE;
	char *tagged_ptrs[NUM_GRANULES];

	/*
	 * Tag the entire page
	 */
	for (count = 0; count < NUM_GRANULES; count++) {
		offset = count * MTE_GRANULE_SIZE;
		tagged_ptrs[count] = __arm_mte_create_random_tag(untagged_ptr + offset, mask);
		__arm_mte_set_tag(tagged_ptrs[count]);
	}

	if (!(flags & FORK_TEST_CHILD_WRITES_FIRST)) {
		for (count = 0; count < NUM_GRANULES; count++) {
			*(tagged_ptrs[count]) = 'a';
		}
	}

	pid_t pid = fork();
	if (pid == 0) {
		T_LOG("Child forked");

		if (flags & FORK_TEST_CHILD_RETAGS) {
			T_LOG("Child editing tags");
			/* re-tag the entire page */
			for (count = 0; count < NUM_GRANULES; count++) {
				tagged_ptrs[count] = __arm_mte_increment_tag(tagged_ptrs[count], 1);
				__arm_mte_set_tag(tagged_ptrs[count]);
			}
		}

		T_LOG("Accessing parent tagged memory");
		/*
		 * Make sure the child process also has tag checks enabled.
		 */
		for (count = 0; count < NUM_GRANULES; count++) {
			*(tagged_ptrs[count]) = 'a';
		}

		T_LOG("Child access to tagged memory success");

		expect_sigkill(^{
			*untagged_ptr = 'b';
		}, "Child access through untagged ptr");

		if (flags & FORK_TEST_CHILD_FORKS) {
			pid_t pid2 = fork();

			if (pid2 == 0) {
				T_LOG("Grandchild forked");

				T_LOG("Accessing grandparent's tagged memory");

				for (count = 0; count < NUM_GRANULES; count++) {
					*(tagged_ptrs[count]) = 'a';
				}

				T_LOG("Grandchild access to tagged memory success");

				pid_t pid3 = fork();

				if (pid3 == 0) {
					T_LOG("Great grandchild forked");

					T_LOG("Accessing great grandparent's tagged memory");

					for (count = 0; count < NUM_GRANULES; count++) {
						*(tagged_ptrs[count]) = 'a';
					}

					T_LOG("Great grandchild access to tagged memory success");

					kr = vm_deallocate(mach_task_self(), address, vm_alloc_sz);
					T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Great grandchild vm_deallocate");
					exit(0);
				} else {
					T_ASSERT_TRUE(pid3 != -1, "Checking fork success in grandchild");
					int status2 = 0;

					T_ASSERT_POSIX_SUCCESS(waitpid(pid3, &status2, 0), "waitpid");
					T_ASSERT_TRUE(WIFEXITED(status2) > 0, "Great grandchild exited normally");
				}

				kr = vm_deallocate(mach_task_self(), address, vm_alloc_sz);
				T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Grandchild vm_deallocate");
				exit(0);
			} else {
				T_ASSERT_TRUE(pid2 != -1, "Checking fork success in child");
				int status2 = 0;
				T_ASSERT_POSIX_SUCCESS(waitpid(pid2, &status2, 0), "waitpid");
				T_ASSERT_TRUE(WIFEXITED(status2) > 0, "Grandchild exited normally");
			}
		}

		kr = vm_deallocate(mach_task_self(), address, vm_alloc_sz);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Child vm_deallocate");
		exit(0);
	} else {
		T_ASSERT_TRUE(pid != -1, "Checking fork success in parent");

		int status = 0;
		T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");

		T_ASSERT_TRUE(WIFEXITED(status) > 0, "Child exited normally");

		/* Verify that accessing memory actually works */
		for (count = 0; count < NUM_GRANULES; count++) {
			*(tagged_ptrs[count]) = 'a';
		}

		T_LOG("Parent access to tagged memory sucessfull");

		expect_sigkill(^{
			*untagged_ptr = 'b';
		}, "Parent access through untagged ptr");
	}

	kr = vm_deallocate(mach_task_self(), address, vm_alloc_sz);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "Parent vm_deallocate");
#endif
}

T_DECL(mte_tag_check_fork_after_alloc_less_page_sz,
    "Test MTE2 tag check fault in a child process after vm_allocate(ALLOC_SIZE, MTE)",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	static const size_t ALLOC_SIZE = MTE_GRANULE_SIZE * 2;
	do_fork_test(ALLOC_SIZE, 0);
}

T_DECL(mte_tag_check_fork_after_alloc_page_sz,
    "Test MTE2 tag check fault in a child process after vm_allocate(PAGE_SIZE, MTE)",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, 0);
}

/* NOTE: These following tests matter for when we switch to MEMORY_OBJECT_COPY_DELAY_FORK */
T_DECL(mte_tag_check_fork_child_fault_write,
    "Test MTE2 tag check fault in a child process after vm_allocate(MTE) and child writes to tagged memory first",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, FORK_TEST_CHILD_WRITES_FIRST);
}

T_DECL(mte_tag_check_fork_child_double_fork,
    "Test MTE2 tag check fault in a child process after vm_allocate(MTE) and child writes to tagged memory first and then forks again",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, FORK_TEST_CHILD_WRITES_FIRST | FORK_TEST_CHILD_FORKS);
}

/*
 * These cases specifically test that tag setting instructions (STG) resolve CoW
 * on fork correctly, since the child doesn't fault in the mapping by writing first.
 */
T_DECL(mte_tag_check_fork_child_retag,
    "Test MTE2 tag check fault in a child process after vm_allocate(MTE) and child changes tags",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, FORK_TEST_CHILD_RETAGS);
}

T_DECL(mte_tag_check_fork_child_fault_write_retag,
    "Test MTE2 tag check fault in a child process after vm_allocate(MTE) and child changes tags and writes to tagged memory first",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, FORK_TEST_CHILD_WRITES_FIRST | FORK_TEST_CHILD_RETAGS);
}

T_DECL(mte_tag_check_fork_child_fault_write_retag_double_fork,
    "Test MTE2 tag check fault in a child process after vm_allocate(MTE) and child changes tags, writes to tagged memory first, and then forks again",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	do_fork_test(PAGE_SIZE, FORK_TEST_CHILD_WRITES_FIRST | FORK_TEST_CHILD_RETAGS | FORK_TEST_CHILD_FORKS);
}


T_DECL(mte_userland_uses_fake_kernel_pointer,
    "Test that VM correctly rejects kernel-looking pointer from userspace",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	/*
	 * When the VM is given a user address that looks like a kernel pointer,
	 * we want to make sure that it still gets canonicalized as a user address
	 * (rather than a valid kernel pointer).
	 * This should result in a nonsensical pointer that shouldn't exist in any
	 * VM map, so the memory access should fail.
	 */
	vm_address_t addr = 0;
	kern_return_t kr = vm_allocate(
		mach_task_self(),
		&addr,
		MTE_GRANULE_SIZE,
		VM_FLAGS_ANYWHERE);
	T_QUIET;
	T_ASSERT_MACH_SUCCESS(kr, "allocate an untagged page");
	T_LOG("Allocated untagged page at addr: 0x%lx", addr);

	/* Create a kernel-like pointer in userspace */
	char *tampered_ptr = (char *)(addr | VM_MIN_KERNEL_ADDRESS);
	T_LOG("Tampered ptr: %p", tampered_ptr);

	/* segfault is expected, since the pointer is not valid in the userspace map */
	expect_signal(SIGSEGV, ^{
		*tampered_ptr = 'a';
	}, "Accessing kernel-like pointer from userspace");
	vm_deallocate(mach_task_self(), addr, MTE_GRANULE_SIZE);
#endif /* __arm64__ */
}

/*
 * Allocates tagged memory, assigns the memory a tag, and attempts to
 * read the memory into its own address space via mach_vm_read().
 *
 * Also attempts to read the memory into its own address space with an untagged
 * pointer, which we expect to fail.
 */
static void
mte_mach_vm_read(mach_vm_size_t sz)
{
	T_SETUPBEGIN;
	__block mach_vm_address_t addr = 0;
	__block vm_offset_t read_addr = 0;
	__block mach_msg_type_number_t read_size = 0;

	mach_vm_size_t sz_rounded = (sz + (MTE_GRANULE_SIZE - 1)) & (unsigned)~((signed)(MTE_GRANULE_SIZE - 1));
	T_LOG("sz rounded: %llu", sz_rounded);
	/* Allocate some tagged memory */
	T_LOG("Allocate tagged memory");
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&addr,
		sz_rounded,
		VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "Allocated tagged page");
	T_QUIET; T_ASSERT_NE_ULLONG(0ULL, addr, "Allocated address is not null");

	uint64_t *untagged_ptr = (uint64_t *)addr;

	uint64_t *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(orig_tag, 0U, "Originally assigned tag is zero");

	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_QUIET; T_EXPECT_EQ_LLONG(mask, (1ULL << 0), "Zero tag is excluded");

	/* Generate random tag */
	uint64_t *tagged_ptr = NULL;
	tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
	T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, tagged_ptr,
	    "Random tag was not taken from excluded tag set");

	/* Time to make things real, commit the tag to memory */
	for (uintptr_t cur_ptr = (uintptr_t)tagged_ptr;
	    cur_ptr < (uintptr_t)tagged_ptr + sz_rounded;
	    cur_ptr += MTE_GRANULE_SIZE) {
		__arm_mte_set_tag((void *)cur_ptr);
	}
	T_LOG("Commited tagged pointer to memory: %p", tagged_ptr);

	/* Write to the memory */
	for (uint i = 0; i < sz_rounded / sizeof(uint64_t); ++i) {
		tagged_ptr[i] = addr;
	}
	T_LOG("Wrote to memory");
	T_SETUPEND;

	T_LOG("Reading %llu bytes from %p", sz, tagged_ptr);
	kr = mach_vm_read(
		mach_task_self(),
		(mach_vm_address_t)tagged_ptr,
		sz,
		&read_addr,
		&read_size);
	T_ASSERT_EQ(kr, KERN_SUCCESS,
	    "mach_vm_read %llu bytes from tagged ptr", sz);

	/* Make sure we get the same thing back */
	T_ASSERT_EQ_UINT((unsigned int)sz, read_size,
	    "sz:%llu == read_size:%d", sz, read_size);
	int result = memcmp(tagged_ptr, (void *)read_addr, sz);
	T_ASSERT_EQ(result, 0, "mach_vm_read back the same info");

	/* Now try with incorrectly tagged pointer (aka, no tag) */
	uint64_t *random_tagged_ptr = NULL;
	/* Exclude the previous tag */
	unsigned int previous_tag = extract_mte_tag(tagged_ptr);
	mask = __arm_mte_exclude_tag(tagged_ptr, previous_tag);
	random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
	T_LOG("random tagged ptr: %p", random_tagged_ptr);
	T_EXPECT_NE_PTR(tagged_ptr, random_tagged_ptr,
	    "Random tag was not taken from excluded tag set");

	T_LOG("Reading %llu bytes from %p", sz, random_tagged_ptr);
	expect_sigkill(^{
		T_LOG("tagged_ptr[0]: %llu", random_tagged_ptr[0]);
	}, "Accessing memory with the wrong tag, should fail");

	expect_sigkill(^{
		(void)mach_vm_read(
			mach_task_self(),
			(mach_vm_address_t)random_tagged_ptr,
			KERNEL_BUFFER_COPY_THRESHOLD,
			&read_addr,
			&read_size);
	}, "Untagged pointer access leads to tag check fault");

	/* Reset tags to 0 before freeing */
	for (uintptr_t cur_ptr = (uintptr_t)orig_tagged_ptr;
	    cur_ptr < (uintptr_t)orig_tagged_ptr + sz_rounded;
	    cur_ptr += MTE_GRANULE_SIZE) {
		__arm_mte_set_tag((void *)cur_ptr);
	}
	vm_deallocate(mach_task_self(), addr, sz_rounded);
}

T_DECL(mte_mach_vm_read_16b,
    "mach_vm_read 16 bytes of tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	mte_mach_vm_read(MTE_GRANULE_SIZE);
#endif /* __arm64__ */
}

T_DECL(mte_mach_vm_read_32k,
    "mach_vm_read 32k bytes of tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	mte_mach_vm_read(KERNEL_BUFFER_COPY_THRESHOLD);
#endif /* __arm64__ */
}

T_DECL(mte_mach_vm_read_over_32k,
    "mach_vm_read 32k + 1 bytes of tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	/* This will actually get rounded to 32K + 16 */
	mte_mach_vm_read(KERNEL_BUFFER_COPY_THRESHOLD + 1);
#endif /* __arm64__ */
}

T_DECL(mte_vm_map_copyinout_in_kernel,
    "Test that the VM handles vm_map_copyin correctly for kernel-to-kernel tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true),
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	T_SKIP("This test is expected to panic; comment this line to be able to run it at desk.");
	(void) run_sysctl_test("vm_map_copyio", 0);
#endif /* __arm64__ */
}

#if __arm64__
static void
do_remap_test(bool own_memory)
{
	mach_vm_address_t tagged_addr, untagged_addr;
	mach_vm_size_t size = PAGE_SIZE;

	T_LOG("Allocate tagged memory");
	tagged_addr = allocate_and_tag_range(size, TAG_RANDOM);
	char *tagged_ptr = (char*) tagged_addr;
	untagged_addr = tagged_addr & ~MTE_TAG_MASK;

	/* Write to the memory */
	for (unsigned int i = 0; i < size; i++) {
		tagged_ptr[i] = 'a';
	}

	T_LOG("Wrote to memory");

	expect_normal_exit(^{
		kern_return_t kr;
		mach_port_t port;
		if (own_memory) {
		        port = mach_task_self();
		} else {
		        /* note: expect_normal_exit forks, so the parent has the allocation as well */
		        kr = task_for_pid(mach_task_self(), getppid(), &port);
		        T_ASSERT_MACH_SUCCESS(kr, "task_for_pid");
		}

		mach_vm_address_t remap_addr = 0;
		vm_prot_t curprot = VM_PROT_WRITE | VM_PROT_READ;
		vm_prot_t maxprot = VM_PROT_WRITE | VM_PROT_READ;
		kr = mach_vm_remap_new(mach_task_self(), &remap_addr, size,
		/* mask = */ 0, VM_FLAGS_ANYWHERE, port, untagged_addr,
		/* copy = */ FALSE, &curprot, &maxprot, VM_INHERIT_DEFAULT);
		T_ASSERT_MACH_SUCCESS(kr, "successfully remapped tagged memory");

		T_ASSERT_EQ(remap_addr & MTE_TAG_MASK, 0ULL, "vm_remap returns an untagged pointer");

		char *untagged_remap_ptr = (char*) remap_addr;
		char *tagged_remap_ptr = __arm_mte_get_tag(untagged_remap_ptr);
		char *incorrectly_tagged_remap_ptr = __arm_mte_increment_tag(tagged_remap_ptr, 1);

		/* verify the data is correct; check every granule for speed */
		for (unsigned int i = 0; i < size; i += MTE_GRANULE_SIZE) {
		        T_QUIET; T_EXPECT_EQ(tagged_remap_ptr[i], 'a', "read value %u from array", i);
		}
		T_LOG("Verified data from child");

		/* make sure the new mapping is also tagged */
		expect_sigkill(^{
			*untagged_remap_ptr = 'b';
		}, "remapped MTE memory sends SIGKILL when accessed with canonical tag");
		expect_sigkill(^{
			*incorrectly_tagged_remap_ptr = 'b';
		}, "remapped MTE memory sends SIGKILL when accessed with incorrect tag");
		expect_normal_exit(^{
			*tagged_remap_ptr = 'b';
		}, "remapped MTE memory can be accessed with correct tag");

		if (!own_memory) {
		        kr = mach_port_deallocate(mach_task_self(), port);
		        T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate parent port");
		}
		kr = mach_vm_deallocate(mach_task_self(), remap_addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate remapped memory");
		kr = mach_vm_deallocate(mach_task_self(), untagged_addr, size);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate original memory from child");
	}, "remap tagged memory");
	kern_return_t kr = mach_vm_deallocate(mach_task_self(), untagged_addr, size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate original memory");
}

T_DECL(mte_vm_map_remap_self,
    "mach_vm_remap_new() on a tagged memory of the same process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
	do_remap_test(true);
}

T_DECL(mte_vm_map_remap_other,
    "mach_vm_remap_new() on a tagged memory of a different process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
	do_remap_test(false);
}

#endif /* __arm64__ */

T_DECL(vm_allocate_zero_tags,
    "Ensure tags are zeroed when tagged memory is allocated from userspace",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	/*
	 * Do a bunch of allocations and check that the returned tags are zeroed.
	 * We do NUM_ALLOCATIONS_PER_ITERATION allocations, check the tags,
	 * deallocate them, and then do it again for a total of NUM_ITERATIONS
	 * iterations.
	 * NUM_ALLOCATIONS_PER_ITERATION is equal to the array bound.
	 */
	vm_address_t addresses[1000];
	const unsigned int NUM_ALLOCATIONS_PER_ITERATION = sizeof(addresses) / sizeof(addresses[0]);
	const unsigned int NUM_ITERATIONS = 3;

	kern_return_t kr;
	for (size_t i = 0; i < NUM_ITERATIONS; i++) {
		unsigned int failures = 0;
		for (size_t j = 0; j < NUM_ALLOCATIONS_PER_ITERATION; j++) {
			kr = vm_allocate(mach_task_self(), &addresses[j], MTE_GRANULE_SIZE, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory (%zu, %zu)", i, j);

			/*
			 * This is the actual test - we get the correctly tagged pointer and
			 * verify that it is zero.
			 */
			char *tagged_ptr = __arm_mte_get_tag((char*) addresses[j]);
			unsigned int orig_tag = extract_mte_tag(tagged_ptr);
			T_QUIET; T_EXPECT_EQ(orig_tag, 0, "vm_allocate returns memory with zeroed tags (%zu, %zu)", i, j);
			failures += (orig_tag != 0);

			/* Assign an arbitrary nonzero tag and commit it to memory */
			tagged_ptr = __arm_mte_create_random_tag(tagged_ptr, 1);
			__arm_mte_set_tag(tagged_ptr);

			/* Fail early if a zero tag was somehow assigned */
			unsigned int new_tag = extract_mte_tag(tagged_ptr);
			T_QUIET; T_ASSERT_NE(new_tag, 0, "random tag is nonzero (%zu, %zu)", i, j);
		}

		for (size_t j = 0; j < NUM_ALLOCATIONS_PER_ITERATION; j++) {
			kr = vm_deallocate(mach_task_self(), addresses[j], MTE_GRANULE_SIZE);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate tagged memory (%zu, %zu)", i, j);
		}
		/* Aggregate results per iteration to avoid too much noise */
		T_EXPECT_EQ(failures, 0, "Iteration %zu success", i);
	}
#endif /* !__arm64__ */
}

/*
 * Policy (MTE_VMSEC_13): VM performed range-checks must be done with
 * canonicalized pointers, regardless of whether MTE is enabled
 *
 * Note that this specifically tests vm_map_copyin, vm_map_copy_overwrite,
 * since those kernel functions are intended to take tagged pointers.
 */
T_DECL(mte_copy_range_checks,
    "Test that VM range checks operate on canonicalized pointers",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	vm_address_t tagged_addr, incorrectly_tagged_addr;
	/*
	 * Test setup
	 */
	const mach_vm_size_t alloc_size = PAGE_SIZE;
	tagged_addr = allocate_and_tag_range(alloc_size, 1);
	incorrectly_tagged_addr = (tagged_addr & ~MTE_TAG_MASK) | (2LLU << MTE_TAG_SHIFT);

	/*
	 * mach_vm_copyin test:
	 * If mach_vm_copyin canonicalizes the tagged pointer for its range checks
	 * like it should, the range check will succeed and the actual "copy-in"
	 * operation will be allowed to go through. This will result in a tag check
	 * fault and the process being killed since the tag is incorrect.
	 *
	 * If, erroneously, the range check is done on tagged pointers, we expect
	 * to see a failure since the "incorrect" tag is larger than the "correct"
	 * one so it would be treated as out-of-bounds for the map.
	 */

	expect_sigkill(^{
		pointer_t read_address;
		mach_msg_type_number_t read_size;
		kern_return_t kr = mach_vm_read(mach_task_self(), incorrectly_tagged_addr,
		alloc_size, &read_address, &read_size);
		T_LOG("SIGKILL not received, kr was %d", kr);
	}, "mach_vm_read with incorrectly tagged pointer should cause a tag check fault");

	/*
	 * mach_vm_copy_overwrite test:
	 * Essentially the same logic using mach_vm_write instead of mach_vm_read.
	 * To be able to do a vm_map_write, we need to first set up a vm_map_copy_t,
	 * which we can get from a correctly-executed vm_map_read.
	 */
	T_SETUPBEGIN;
	pointer_t copy_address;
	mach_msg_type_number_t copy_size;
	kern_return_t kr = mach_vm_read(mach_task_self(), tagged_addr,
	    alloc_size, &copy_address, &copy_size);
	T_ASSERT_MACH_SUCCESS(kr, "set up vm_map_copy_t for mach_vm_write test");
	T_SETUPEND;
	expect_sigkill(^{
		kern_return_t kr2 = mach_vm_write(mach_task_self(), incorrectly_tagged_addr,
		copy_address, copy_size);
		T_LOG("SIGKILL not received, kr was %d", kr2);
	}, "mach_vm_write with incorrectly tagged pointer should cause a tag check fault");
#endif /* !__arm64__ */
}

/*
 * Policy (MTE_VMSEC_14): VM performed range math must be done using canonical
 * pointers, regardless of whether MTE is enabled.
 *
 * Note that this specifically tests vm_map_copyin, vm_map_copy_overwrite,
 * since those kernel functions are intended to take tagged pointers.
 */
T_DECL(mte_copy_range_math,
    "Test that pointer values are not canonicalized after range math",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	vm_address_t tagged_addr;
	kern_return_t kr;

	/*
	 * Test setup
	 */
	const mach_vm_size_t alloc_size = MTE_GRANULE_SIZE;
	tagged_addr = allocate_and_tag_range(alloc_size, TAG_RANDOM);

	vm_offset_t read_address;
	mach_msg_type_number_t read_size;
	mach_vm_size_t malformed_size;

	/*
	 * A size which extends into the MTE tag bits is too large to fit in
	 * memory and should be rejected. If range math is operating on tagged
	 * pointers (and the tag bits get stripped later), then this would
	 * be accepted.
	 */
	// Test vm_map_copyin using mach_vm_read
	malformed_size = (mach_vm_size_t) alloc_size | (7LLU << MTE_TAG_SHIFT);
	kr = mach_vm_read(mach_task_self(), tagged_addr, malformed_size,
	    &read_address, &read_size);
	T_EXPECT_MACH_ERROR_(kr, KERN_INVALID_ARGUMENT, "mach_vm_read should reject size which extends into tag bits");

	/*
	 * Cannot test vm_map_copy_overwrite from userspace. The only entry point
	 * that hits this function without first hitting mach_vm_read is
	 * mach_vm_write, which takes its size as a 32-bit mach_msg_type_number_t.
	 */
#endif /* !__arm64__ */
}

/*
 * Policy (MTE_VMSEC_16): if the parameter/target of a VM API is a range of
 * memory, VM APIs must ensure that the address is not tagged
 *
 * Corollary: to ease adoption in cases in which pointers obtained from
 * the memory allocator are directly passed to some of these functions,
 * we implement stripping at the kernel API entrypoint for APIs that do
 * not affect the VM state or that are safe and common enough to strip.
 * This helps also clearing/making deterministic
 * cases where addresses were passed along the VM subsystem just waiting
 * to eventually be rejected.
 *
 * note: this does not apply to APIs which lead to vm_map_copy{in,out}, since
 * these need tags to be able to read tagged memory.
 */
T_DECL(mte_vm_reject_tagged_pointers,
    "Test that most VM APIs reject tagged pointers",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true) /* to be able to get host_priv port for mach_vm_wire */)
{
#if !__arm64__
	T_SKIP("Running on non-arm64 target, skipping...");
#else /* !__arm64__ */
	vm_address_t untagged_addr, tagged_addr, tagged_addr_mprotect;
	void *untagged_ptr, *tagged_ptr, *tagged_ptr_mprotect;
	kern_return_t kr;
	int ret;

	/*
	 * Test setup
	 */
	const size_t alloc_size = PAGE_SIZE;
	tagged_addr = allocate_and_tag_range(alloc_size, TAG_RANDOM);
	tagged_addr_mprotect = allocate_and_tag_range(alloc_size, TAG_RANDOM);
	untagged_addr = tagged_addr & ~MTE_TAG_MASK;
	untagged_ptr = (void*) untagged_addr;
	tagged_ptr = (void*) tagged_addr;
	tagged_ptr_mprotect = (void *)tagged_addr_mprotect;

	T_QUIET; T_ASSERT_NE(tagged_addr & MTE_TAG_MASK, 0ULL, "validate tagged_addr");
	T_QUIET; T_ASSERT_EQ(untagged_addr & MTE_TAG_MASK, 0ULL, "validate untagged_addr");

	__block struct vm_region_submap_info_64 region_info;
	void (^get_region_info)(void) = ^{
		vm_address_t address = untagged_addr;
		unsigned int depth = 1;
		vm_size_t size;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t region_kr = vm_region_recurse_64(mach_task_self(), &address, &size,
		    &depth, (vm_region_info_t) &region_info, &count);
		T_QUIET; T_ASSERT_MACH_SUCCESS(region_kr, "get allocation region info");
	};

	/*
	 * Test various APIs with tagged pointers
	 */
	/* mprotect, mach_vm_protect are common enough, we strip implicitly. */
	ret = mprotect(tagged_ptr_mprotect, alloc_size, PROT_NONE);
	T_EXPECT_POSIX_SUCCESS(ret, "mprotect");
	kr = mach_vm_protect(mach_task_self(), tagged_addr_mprotect, alloc_size, false, PROT_NONE);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_protect");

	/*
	 * mincore: SUCCESS
	 */
	char vec[100] = {0};
	T_QUIET; T_ASSERT_LE(alloc_size, sizeof(vec) * PAGE_SIZE, "vec is large enough to fit mincore result");
	ret = mincore(tagged_ptr, alloc_size, vec);
	T_EXPECT_POSIX_SUCCESS(ret, "mincore: return value");

	/* msync, mach_vm_msync */
	ret = msync(tagged_ptr, alloc_size, MS_SYNC);
	T_EXPECT_POSIX_SUCCESS(ret, "msync");
	kr = mach_vm_msync(mach_task_self(), tagged_addr, alloc_size, VM_SYNC_SYNCHRONOUS | VM_SYNC_CONTIGUOUS);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_msync");

	/* madvise, mach_vm_behavior_set strip tagged addresses */
	ret = madvise(tagged_ptr, alloc_size, MADV_NORMAL);
	T_EXPECT_POSIX_SUCCESS(ret, "madvise");
	kr = mach_vm_behavior_set(mach_task_self(), tagged_addr, alloc_size,
	    VM_BEHAVIOR_DEFAULT);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_behavior_set");

	/*
	 * minherit, mach_vm_inherit:
	 * mach_vm_inherit would just silently succeed and do nothing if the range was tagged, so
	 * we strip addresses to have consistent behavior.
	 */
	const vm_inherit_t NEW_INHERIT = VM_INHERIT_NONE;
	ret = minherit(tagged_ptr, alloc_size, NEW_INHERIT);
	T_EXPECT_POSIX_SUCCESS(ret, "minherit");
	kr = mach_vm_inherit(mach_task_self(), tagged_addr, alloc_size, NEW_INHERIT);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_inherit");

	/*
	 * mlock, mach_vm_wire(prot != VM_PROT_NONE):
	 * Allow implicitly stripping to avoid no-op success that might confuse third parties.
	 */
	mach_port_t host_priv = HOST_PRIV_NULL;
	kr = host_get_host_priv_port(mach_host_self(), &host_priv); \
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "get host_priv port");

	ret = mlock(tagged_ptr, alloc_size);
	T_EXPECT_POSIX_SUCCESS(ret, "mlock");
	get_region_info();
	T_EXPECT_EQ(region_info.user_wired_count, (unsigned short) 1, "mlock on tagged pointer should wire memory");
	ret = munlock(tagged_ptr, alloc_size);
	T_EXPECT_POSIX_SUCCESS(ret, "munlock");
	get_region_info();
	T_EXPECT_EQ(region_info.user_wired_count, (unsigned short) 0, "munlock on tagged pointer should unwire memory");

	kr = mach_vm_wire(host_priv, mach_task_self(), tagged_addr,
	    alloc_size, VM_PROT_DEFAULT);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_wire (wire)");
	get_region_info();
	T_EXPECT_EQ(region_info.user_wired_count, (unsigned short) 1, "mach_vm_wire on tagged address should wire memory");
	ret = munlock(tagged_ptr, alloc_size);
	T_EXPECT_POSIX_SUCCESS(ret, "munlock");

	/* List of flags used to test vm_allocate, vm_map and vm_remap */
	const int ALLOCATE_FLAGS[] = {
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
		VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_FLAGS_MTE,
		VM_FLAGS_ANYWHERE,
		VM_FLAGS_ANYWHERE | VM_FLAGS_MTE
	};
	const size_t NUM_ALLOCATE_FLAGS = sizeof(ALLOCATE_FLAGS) / sizeof(*ALLOCATE_FLAGS);

	/* vm_allocate tests: */
	for (size_t i = 0; i < NUM_ALLOCATE_FLAGS; i++) {
		mach_vm_address_t new_addr = tagged_addr;
		kr = mach_vm_allocate(mach_task_self(), &new_addr, alloc_size, ALLOCATE_FLAGS[i]);
		if (ALLOCATE_FLAGS[i] & VM_FLAGS_ANYWHERE) {
			T_EXPECT_MACH_SUCCESS(kr, "mach_vm_allocate %zu (%#x)", i, ALLOCATE_FLAGS[i]);
			T_QUIET; T_EXPECT_EQ(new_addr & MTE_TAG_MASK, 0ull, "mach_vm_allocate should return untagged pointer");
			T_QUIET; T_EXPECT_NE((vm_address_t) new_addr, untagged_addr, "allocate anywhere should return a new range");

			/* clean up new allocation */
			if (kr == KERN_SUCCESS) {
				kr = mach_vm_deallocate(mach_task_self(), new_addr, alloc_size);
				T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "cleanup mach_vm_map");
			}
		} else {
			T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_vm_allocate %zu (%#x)", i, ALLOCATE_FLAGS[i]);
		}
	}

	/* mach_vm_machine_attribute: allow tagged addresses */
	vm_machine_attribute_val_t machine_attribute_val = MATTR_VAL_CACHE_FLUSH;
	kr = mach_vm_machine_attribute(mach_task_self(), tagged_addr, alloc_size,
	    MATTR_CACHE, &machine_attribute_val);
	T_EXPECT_MACH_SUCCESS(kr, "mach_vm_machine_attribute");

	/* mach_make_memory_entry_64: DO NOT allow tagged addresses */
	mach_port_t object_handle;
	memory_object_size_t object_size = alloc_size;
	kr = mach_make_memory_entry_64(mach_task_self(), &object_size, tagged_addr,
	    VM_PROT_DEFAULT, &object_handle, MACH_PORT_NULL);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_make_memory_entry_64");

	/* mach_vm_map: DO NOT allow tagged addresses */
	/* setup: get a memory entry to map in */
	kr = mach_make_memory_entry_64(mach_task_self(), &object_size, untagged_addr,
	    VM_PROT_DEFAULT | MAP_MEM_NAMED_CREATE, &object_handle, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(kr, "create memory entry for mach_vm_map");

	for (size_t i = 0; i < NUM_ALLOCATE_FLAGS; i++) {
		mach_vm_address_t new_addr = tagged_addr;
		kr = mach_vm_map(mach_task_self(), &new_addr, alloc_size, /* mask = */ 0,
		    ALLOCATE_FLAGS[i], object_handle, /* offset = */ 0, /* copy = */ true,
		    VM_PROT_DEFAULT, VM_PROT_DEFAULT, VM_INHERIT_DEFAULT);
		if (ALLOCATE_FLAGS[i] & VM_FLAGS_ANYWHERE) {
			/*
			 * VM_FLAGS_ANYWHERE uses the provided address as a location to start
			 * searching from. Since a tagged address is outside the map bounds,
			 * it won't be able to find any space for the allocation.
			 */
			T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE, "mach_vm_map %zu (%#x)", i, ALLOCATE_FLAGS[i]);
		} else {
			T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_vm_map %zu (%#x)", i, ALLOCATE_FLAGS[i]);
		}
	}

	/* clean up memory entry object handle */
	kr = mach_port_deallocate(mach_task_self(), object_handle);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_vm_map tests: clean up memory entry object handle");

	/* mach_vm_purgable_control */
	int purgable_state;
	kr = mach_vm_purgable_control(mach_task_self(), tagged_addr, VM_PURGABLE_GET_STATE, &purgable_state);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_vm_purgable_control");

	/* mach_vm_region: reject tagged addresses */
	mach_vm_address_t region_addr = tagged_addr;
	mach_vm_size_t region_size;
	vm_region_basic_info_data_64_t region_info_64;
	mach_msg_type_number_t region_info_cnt = VM_REGION_BASIC_INFO_COUNT_64;
	mach_port_t unused;

	kr = mach_vm_region(mach_task_self(), &region_addr, &region_size,
	    VM_REGION_BASIC_INFO_64, (vm_region_info_t) &region_info_64,
	    &region_info_cnt, &unused);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_vm_region");

	/* mach_vm_remap_new */
	mach_vm_address_t untagged_addr2, tagged_addr2;
	tagged_addr2 = allocate_and_tag_range(alloc_size, TAG_RANDOM);
	untagged_addr2 = tagged_addr2 & ~MTE_TAG_MASK;

	/* Test each flag value twice, once with source tagged and once with destination tagged */
	for (size_t i = 0; i < 2 * NUM_ALLOCATE_FLAGS; i++) {
		int flags = ALLOCATE_FLAGS[i % NUM_ALLOCATE_FLAGS];
		bool source_tagged = i < NUM_ALLOCATE_FLAGS;
		char *msg = source_tagged ? "source tagged" : "dest tagged";
		mach_vm_address_t src_addr = source_tagged ? tagged_addr : untagged_addr;
		mach_vm_address_t dest_addr = source_tagged ? untagged_addr2 : tagged_addr2;

		vm_prot_t cur_prot = VM_PROT_DEFAULT, max_prot = VM_PROT_DEFAULT;
		kr = mach_vm_remap_new(mach_task_self(), &dest_addr, alloc_size, /* mask = */ 0,
		    flags, mach_task_self(), src_addr, true, &cur_prot, &max_prot,
		    VM_INHERIT_DEFAULT);

		if (flags & VM_FLAGS_MTE) {
			/* VM_FLAGS_USER_REMAP does not include VM_FLAGS_MTE */
			T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_vm_remap_new %zu (%s, %#x)", i, msg, flags);
		} else if (!source_tagged && flags & VM_FLAGS_ANYWHERE) {
			/*
			 * In this case, we pass vm_map_remap_extract since the source
			 * address is untagged. When we try to find a space to insert it
			 * into the map, we fail since VM_FLAGS_ANYWHERE uses the destination
			 * passed in as a location to start searching from.
			 */
			T_EXPECT_MACH_ERROR(kr, KERN_NO_SPACE, "mach_vm_remap_new %zu (%s, %#x)", i, msg, flags);
		} else {
			T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "mach_vm_remap_new %zu (%s, %#x)", i, msg, flags);
		}

		if (kr == KERN_SUCCESS && (flags & VM_FLAGS_ANYWHERE)) {
			/* clean up the new allocation if we mistakenly suceeded */
			kr = mach_vm_deallocate(mach_task_self(), dest_addr, alloc_size);
			T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "cleanup mach_vm_remap_new %zu (%s, %#x)", i, msg, flags);
		}
	}

	/* clean up our second allocation */
	T_SETUPBEGIN;
	kr = vm_deallocate(mach_task_self(), untagged_addr2, alloc_size);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "clean up allocation for mach_vm_remap_new tests");
	T_SETUPEND;

	/* vm_deallocate: vm_allocate() will return a canonical address, so we mandate a canonical address here */
	T_SETUPBEGIN;
	kr = vm_deallocate(mach_task_self(), tagged_addr, alloc_size);
	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "vm_deallocate denies a non-canonical addresses");
	T_SETUPEND;

	/* test cleanup */
	T_SETUPBEGIN;
	kr = vm_deallocate(mach_task_self(), untagged_addr, alloc_size);
	T_ASSERT_MACH_SUCCESS(kr, "test region cleanup");
	T_SETUPEND;
#endif /* !__arm64__ */
}

T_DECL(mte_tagged_page_relocation,
    "Test that VM copies tags on page relocation for tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(__arm64__))
{
#if __arm64__
	T_SETUPBEGIN;
	mach_vm_address_t addr = 0;
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&addr,
		PAGE_SIZE,
		VM_FLAGS_ANYWHERE | VM_FLAGS_MTE
		);
	T_ASSERT_MACH_SUCCESS(kr,
	    "allocate 32 bytes of tagged memory at 0x%llx", addr);

	/* Verify originally assigned tags are zero */
	for (uint i = 0; i < PAGE_SIZE / MTE_GRANULE_SIZE; ++i) {
		char *untagged_ptr = (char *)((uintptr_t)addr + i * MTE_GRANULE_SIZE);
		char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
		unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
		T_QUIET; T_ASSERT_EQ_UINT(orig_tag, 0U, "originally assigned tag is zero");
	}

	/*
	 * Tag the first 16 bytes with non-zero tag, and
	 * leave the second 16 bytes as is
	 */
	char *untagged_ptr = (char *)addr;
	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_EXPECT_EQ_LLONG(mask, (1LL << 0), "zero tag is excluded");

	char *random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
	T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
	    "random tag was not taken from excluded tag set");

	ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
	T_QUIET; T_EXPECT_EQ_ULONG(diff, (ptrdiff_t)0, "untagged %p and tagged %p have identical address bits",
	    untagged_ptr, random_tagged_ptr);

	/* Time to make things real, commit the tag to memory */
	__arm_mte_set_tag(random_tagged_ptr);

	/* Ensure that we can read back the tag */
	char *read_back = __arm_mte_get_tag(untagged_ptr);
	T_EXPECT_EQ_PTR(read_back, random_tagged_ptr, "tag was committed to memory correctly");

	T_LOG("tagged pointer: %p", random_tagged_ptr);
	random_tagged_ptr[0] = 'a';
	untagged_ptr[MTE_GRANULE_SIZE] = 'b';
	T_SETUPEND;

	/*
	 * Relocate the page.
	 * The kernel will also write 'b' and 'c' to the memory.
	 */
	int64_t ret = run_sysctl_test("vm_page_relocate", (int64_t)random_tagged_ptr);
	T_EXPECT_EQ_LLONG(ret, 1LL, "sysctl: relocate page");

	T_EXPECT_EQ_CHAR(random_tagged_ptr[0], 'b',
	    "reading from tagged ptr after relocation");
	T_EXPECT_EQ_CHAR(untagged_ptr[MTE_GRANULE_SIZE], 'c',
	    "reading from untagged ptr after relocation");
#endif /* __arm64__ */
}

T_HELPER_DECL(mte_tag_violate, "child process to trigger an MTE violation")
{
	static const size_t ALLOC_SIZE = MTE_GRANULE_SIZE * 2;

	vm_address_t address = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &address, ALLOC_SIZE, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "allocate tagged memory");
	char *untagged_ptr = (char *) address;

	char *orig_tagged_ptr = __arm_mte_get_tag(untagged_ptr);
	unsigned int orig_tag = extract_mte_tag(orig_tagged_ptr);
	T_ASSERT_EQ_UINT(orig_tag, 0U, "originally assigned tag is zero");

	uint64_t mask = __arm_mte_exclude_tag(orig_tagged_ptr, 0);
	T_EXPECT_EQ_LLONG(mask, (1LL << 0), "zero tag is excluded");

	char *random_tagged_ptr = NULL;
	for (unsigned int i = 0; i < NUM_MTE_TAGS * 4; i++) {
		random_tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
		T_QUIET; T_EXPECT_NE_PTR(orig_tagged_ptr, random_tagged_ptr,
		    "random tag was not taken from excluded tag set");

		ptrdiff_t diff = __arm_mte_ptrdiff(untagged_ptr, random_tagged_ptr);
		T_QUIET; T_EXPECT_EQ_ULONG(diff, (ptrdiff_t)0, "untagged %p and tagged %p have identical address bits",
		    untagged_ptr, random_tagged_ptr);
	}

	__arm_mte_set_tag(random_tagged_ptr);

	char *read_back = __arm_mte_get_tag(untagged_ptr);
	T_EXPECT_EQ_PTR(read_back, random_tagged_ptr, "tag was committed to memory correctly");

	random_tagged_ptr[0] = 't';
	random_tagged_ptr[1] = 'e';
	random_tagged_ptr[2] = 's';
	random_tagged_ptr[3] = 't';
	T_EXPECT_EQ_STR(random_tagged_ptr, "test", "read/write from tagged memory");

	void *next_granule_ptr = orig_tagged_ptr + MTE_GRANULE_SIZE;
	unsigned int next_granule_tag = extract_mte_tag(next_granule_ptr);
	T_QUIET; T_ASSERT_EQ_UINT(next_granule_tag, 0U,
	    "next MTE granule still has its originally assigned tag");

	T_LOG("attempting out-of-bounds access to tagged memory");
	random_tagged_ptr[MTE_GRANULE_SIZE] = '!';
	T_LOG("bypass: survived OOB access");

	__arm_mte_set_tag(orig_tagged_ptr);
	__arm_mte_set_tag(orig_tagged_ptr + MTE_GRANULE_SIZE);
	vm_deallocate(mach_task_self(), address, ALLOC_SIZE);
	exit(0);
}

T_HELPER_DECL(mte_copyio_bypass_helper, "child process to test copyio in MTE tag check bypass mode")
{
	run_mte_copyio_tests(false);
}

static void
run_helper_with_sec_bypass(char *helper_name)
{
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	T_ASSERT_POSIX_ZERO(_NSGetExecutablePath(path, &path_size), "_NSGetExecutablePath");
	char *args[] = { path, "-n", helper_name, NULL };

	pid_t child_pid = 0;
	posix_spawnattr_t attr;
	errno_t ret = posix_spawnattr_init(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");

	ret = posix_spawnattr_set_use_sec_transition_shims_np(&attr, POSIX_SPAWN_SECFLAG_EXPLICIT_ENABLE | POSIX_SPAWN_SECFLAG_EXPLICIT_CHECK_BYPASS);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_use_sec_transition_shims_np");

	ret = posix_spawn(&child_pid, path, NULL, &attr, args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_ASSERT_NE(child_pid, 0, "posix_spawn");

	ret = posix_spawnattr_destroy(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");

	int status = 0;
	T_ASSERT_POSIX_SUCCESS(waitpid(child_pid, &status, 0), "waitpid");
	T_EXPECT_TRUE(WIFEXITED(status), "exited successfully");
	T_EXPECT_TRUE(WEXITSTATUS(status) == 0, "exited with status %d", WEXITSTATUS(status));
}

T_DECL(mte_tag_bypass,
    "Test MTE2 tag check bypass works with posix_spawnattr",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	run_helper_with_sec_bypass("mte_tag_violate");
}

T_DECL(mte_copyio_bypass,
    "Test MTE2 tag check bypass with copyio operations",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	run_helper_with_sec_bypass("mte_copyio_bypass_helper");
}

#ifdef __arm64__
T_DECL(mte_read_only,
    "Verify that setting tags on a read-only mapping results in SIGBUS",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	uint64_t mask;
	T_SETUPBEGIN;
	void* untagged_ptr = allocate_tagged_memory(MTE_GRANULE_SIZE, &mask);
	void *tagged_ptr = __arm_mte_create_random_tag(untagged_ptr, mask);
	T_SETUPEND;

	assert_normal_exit(^{
		__arm_mte_set_tag(tagged_ptr);
	}, "can set tags on writable memory");

	int ret = mprotect(untagged_ptr, MTE_GRANULE_SIZE, PROT_READ);
	T_ASSERT_POSIX_SUCCESS(ret, "mprotect");

	tagged_ptr = __arm_mte_increment_tag(tagged_ptr, 1);

	expect_signal(SIGBUS, ^{
		__arm_mte_set_tag(tagged_ptr);
	}, "set tag on read-only memory");

	T_SETUPBEGIN;
	kern_return_t kr = vm_deallocate(mach_task_self(), (vm_address_t) untagged_ptr, MTE_GRANULE_SIZE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "clean up tagged allocation");
	T_SETUPEND;
}

T_DECL(mte_inherit_share,
    "Verify that you can't set VM_INHERIT_SHARE on tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	const mach_vm_size_t ALLOC_SIZE = PAGE_SIZE;
	__block kern_return_t kr;

	T_SETUPBEGIN;
	vm_address_t tagged_addr = allocate_and_tag_range(ALLOC_SIZE, TAG_RANDOM);
	vm_address_t untagged_addr = tagged_addr & ~MTE_TAG_MASK;
	T_SETUPEND;

	expect_sigkill(^{
		int ret = minherit((void*) untagged_addr, ALLOC_SIZE, VM_INHERIT_SHARE);
		T_LOG("minherit: was not killed and returned %d", ret);
	}, "minherit(VM_INHERIT_SHARE) on tagged memory");

	expect_sigkill(^{
		kr = mach_vm_inherit(mach_task_self(), untagged_addr,
		ALLOC_SIZE, VM_INHERIT_SHARE);
		T_LOG("mach_vm_inherit: was not killed and returned %d", kr);
	}, "mach_vm_inherit(VM_INHERIT_SHARE) on tagged memory");

	T_SETUPBEGIN;
	kr = vm_deallocate(mach_task_self(), untagged_addr, ALLOC_SIZE);
	T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "clean up tagged allocation");
	T_SETUPEND;

	expect_sigkill(^{
		mach_vm_address_t addr = 0;
		kr = mach_vm_map(mach_task_self(), &addr, ALLOC_SIZE, /* mask = */ 0,
		VM_FLAGS_ANYWHERE | VM_FLAGS_MTE, MACH_PORT_NULL, /* offset = */ 0,
		/* copy = */ false, VM_PROT_DEFAULT, VM_PROT_ALL, VM_INHERIT_SHARE);
		T_LOG("mach_vm_map: was not killed and returned %d", kr);

		T_SETUPBEGIN;
		kr = vm_deallocate(mach_task_self(), addr, ALLOC_SIZE);
		T_QUIET; T_EXPECT_MACH_SUCCESS(kr, "clean up mach_vm_map allocation");
		T_SETUPEND;
	}, "mach_vm_map(VM_INHERIT_SHARE) to create new tagged memory");
}

static vm_object_id_t
get_object_id(mach_port_t task, vm_address_t addr)
{
	unsigned int depth = 1;
	vm_size_t size;
	struct vm_region_submap_info_64 info;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kern_return_t kr = vm_region_recurse_64(task, &addr, &size, &depth,
	    (vm_region_info_t) &info, &count);
	/*
	 * I'm not sure why it returns KERN_INVALID_ADDRESS in this case, but this
	 * can happen if the corpse task goes away. That happens if a jetsam event
	 * occurs (even on an unrelated process) while the test is running.
	 */
	if (task != mach_task_self() && kr == KERN_INVALID_ADDRESS) {
		T_SKIP("corpse port disappeared, bailing...");
	}
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "get_object_id: vm_region_recurse_64");
	return info.object_id_full;
}

T_DECL(mte_corpse_fork,
    "Verify that corpse-fork sharing paths work normally on tagged memory",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    /* rdar://138528295 (Provide a mechanism to guarantee availability of corpse slots for tests) */
    T_META_RUN_CONCURRENTLY(false))
{
	/*
	 * The corpse-fork path shares memory in two additional cases:
	 * (1) if the entry has INHERIT_NONE, and
	 * (2) if the memory is "owned" by the process for accounting purposes. This
	 * essentially means that it is purgeable & volatile.
	 * We want to ensure that these cases are unaffected by MTE restrictions on
	 * VM_INHERIT_SHARE.
	 */
	kern_return_t kr;
	mach_vm_size_t alloc_size = PAGE_SIZE;
	mach_vm_address_t inherit_none_addr, owned_addr, regular_addr;

	T_SETUPBEGIN;

	/* First up, expand the system's corpse pool size.
	 * Otherwise, this test sporadically can't secure the corpse slots it needs.
	 */
	int original_total_corpses_allowed;
	size_t original_total_corpses_allowed_sizeof = sizeof(original_total_corpses_allowed);
	int total_corpses_allowed = 20;
	int ret = sysctlbyname("kern.total_corpses_allowed",
	    &original_total_corpses_allowed, &original_total_corpses_allowed_sizeof,
	    &total_corpses_allowed, sizeof(total_corpses_allowed));
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "sysctl kern.total_corpses_allowed");

	/* set up regular MTE-tagged region */
	kr = mach_vm_allocate(mach_task_self(), &regular_addr, alloc_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate regular region");

	/* set up region for testing INHERIT_NONE */
	kr = mach_vm_allocate(mach_task_self(), &inherit_none_addr, alloc_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate INHERIT_NONE region");

	kr = mach_vm_inherit(mach_task_self(), inherit_none_addr, alloc_size,
	    VM_INHERIT_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_inherit(INHERIT_NONE)");

	/* set up region for testing "owned" memory */
	kr = mach_vm_allocate(mach_task_self(), &owned_addr, alloc_size,
	    VM_FLAGS_ANYWHERE | VM_FLAGS_MTE | VM_FLAGS_PURGABLE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate owned region");

	int purgable_state = VM_PURGABLE_VOLATILE;
	kr = mach_vm_purgable_control(mach_task_self(), owned_addr, VM_PURGABLE_SET_STATE,
	    &purgable_state);
	T_ASSERT_MACH_SUCCESS(kr, "vm_purgable_control(VM_PURGABLE_VOLATILE)");
	T_SETUPEND;

	/* Write in some data and tags */
	char *regular_ptr = __arm_mte_increment_tag((char*) regular_addr, 1);
	char *inherit_none_ptr = __arm_mte_increment_tag((char*) inherit_none_addr, 2);
	char *owned_ptr = __arm_mte_increment_tag((char*) owned_addr, 3);
	for (size_t i = 0; i < alloc_size; i++) {
		if (i % MTE_GRANULE_SIZE == 0) {
			__arm_mte_set_tag(&regular_ptr[i]);
			__arm_mte_set_tag(&inherit_none_ptr[i]);
			__arm_mte_set_tag(&owned_ptr[i]);
		}
		regular_ptr[i] = 'a';
		inherit_none_ptr[i] = 'b';
		owned_ptr[i] = 'c';
	}
	T_LOG("wrote data and tags");

	mach_port_t corpse_port;
	size_t NUM_RETRIES = 5;
	for (size_t i = 0;; i++) {
		kr = task_generate_corpse(mach_task_self(), &corpse_port);
		if (kr == KERN_RESOURCE_SHORTAGE) {
			T_LOG("hit system corpse limit");
			if (i == NUM_RETRIES) {
				T_SKIP("retried too many times, bailing...");
			} else {
				/* give ReportCrash some time to finish handling some corpses */
				sleep(2);
				/* ... then retry */
				T_LOG("retrying... (%lu/%lu)", i + 1, NUM_RETRIES);
				continue;
			}
		}
		T_ASSERT_MACH_SUCCESS(kr, "task_generate_corpse");
		break;
	}

	/*
	 * Make sure the "regular" region was not shared.
	 * Note: in the case of symmetric CoW, the object IDs may match even if
	 * there is no true sharing happening. However, since we only expect delayed
	 * CoW or eager copies for MTE objects, this isn't a concern here.
	 */
	vm_object_id_t regular_id = get_object_id(mach_task_self(), regular_addr);
	vm_object_id_t regular_corpse_id = get_object_id(corpse_port, regular_addr);
	T_EXPECT_NE(regular_id, regular_corpse_id, "regular region was not shared");

	/* Make sure the INHERIT_NONE region was shared */
	vm_object_id_t inherit_none_id = get_object_id(mach_task_self(), inherit_none_addr);
	vm_object_id_t inherit_none_corpse_id = get_object_id(corpse_port, inherit_none_addr);
	T_EXPECT_EQ(inherit_none_id, inherit_none_corpse_id, "INHERIT_NONE region was shared");

	/* Make sure the owned region was shared */
	vm_object_id_t owned_id = get_object_id(mach_task_self(), owned_addr);
	vm_object_id_t owned_corpse_id = get_object_id(corpse_port, owned_addr);
	T_EXPECT_EQ(owned_id, owned_corpse_id, "owned region was shared");

	/* Cleanup */
	T_SETUPBEGIN;
	kr = mach_vm_deallocate(mach_task_self(), regular_addr, alloc_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate regular allocation");
	kr = mach_vm_deallocate(mach_task_self(), inherit_none_addr, alloc_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate INHERIT_NONE allocation");
	kr = mach_vm_deallocate(mach_task_self(), owned_addr, alloc_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate owned allocation");
	kr = mach_port_deallocate(mach_task_self(), corpse_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "deallocate corpse port");

	/* Reduce the corpse pool size back to its original value */
	ret = sysctlbyname("kern.total_corpses_allowed",
	    NULL, 0,
	    &original_total_corpses_allowed, sizeof(original_total_corpses_allowed));
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "sysctl kern.total_corpses_allowed");

	T_SETUPEND;
}

T_DECL(mte_aio,
    "Test MTE asynchronous access faults when the kernel does copyio on behalf of a process",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ENABLED(false) /* rdar://154801490 */) {
	const mach_vm_size_t BUF_SIZE = MTE_GRANULE_SIZE;
	uint64_t mask;

	T_SETUPBEGIN;
	char *buf_untagged = allocate_tagged_memory(BUF_SIZE, &mask);
	char *buf_tagged = __arm_mte_create_random_tag(buf_untagged, mask);
	__arm_mte_set_tag(buf_tagged);
	strncpy(buf_tagged, "ABCDEFG", BUF_SIZE);

	char *buf_incorrectly_tagged = __arm_mte_increment_tag(buf_tagged, 1);
	int fd = fileno(tmpfile());

	T_SETUPEND;

	expect_sigkill(^{
		struct aiocb aiocb = {
		        .aio_fildes = fd,
		        .aio_offset = 0,
		        .aio_buf = buf_incorrectly_tagged,
		        .aio_nbytes = strlen(buf_tagged),
		};
		int ret = aio_write(&aiocb);
		T_ASSERT_POSIX_SUCCESS(ret, "aio_write");

		/* wait for the kernel to handle our async I/O */
		/* we should be killed at some point while this happens */
		const struct aiocb *aio_list[1] = { &aiocb };
		(void)aio_suspend(aio_list, 1, NULL);

		/* we were not killed: */
		close(fd);
		T_ASSERT_FAIL("aio write with untagged pointer completed successfully");
	}, "asynchronous I/O write from tagged buffer with incorrect MTE tags");

	char read_buf[BUF_SIZE];
	ssize_t bytes_read = read(fd, read_buf, sizeof(read_buf));
	T_ASSERT_POSIX_SUCCESS(bytes_read, "read from tmpfile");

	T_EXPECT_EQ(bytes_read, 0L, "no bytes sent over tmpfile");

	T_SETUPBEGIN;
	kern_return_t kr = vm_deallocate(mach_task_self(), (vm_address_t) buf_untagged, BUF_SIZE);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate tagged buffer");

	close(fd);
	T_SETUPEND;
}

T_HELPER_DECL(mte_tag_violate_aio, "child process to trigger an asynchronous MTE violation via AIO") {
	const mach_vm_size_t BUF_SIZE = MTE_GRANULE_SIZE;
	uint64_t mask;

	char *buf_untagged = allocate_tagged_memory(BUF_SIZE, &mask);
	char *buf_tagged = __arm_mte_create_random_tag(buf_untagged, mask);
	__arm_mte_set_tag(buf_tagged);

	strncpy(buf_tagged, "ABCDEFG", BUF_SIZE);
	size_t length = strlen(buf_tagged);

	char *buf_incorrectly_tagged = __arm_mte_increment_tag(buf_tagged, 1);
	int fd = fileno(tmpfile());

	struct aiocb aiocb = {
		.aio_fildes = fd,
		.aio_offset = 0,
		.aio_buf = buf_incorrectly_tagged,
		.aio_nbytes = length,
	};
	int ret = aio_write(&aiocb);
	T_ASSERT_POSIX_SUCCESS(ret, "aio_write");

	/* wait for the kernel to handle our async I/O */
	const struct aiocb *aio_list[1] = { &aiocb };
	ret = aio_suspend(aio_list, 1, NULL);
	T_ASSERT_POSIX_SUCCESS(ret, "aio_suspend");

	char read_buf[BUF_SIZE];
	ssize_t bytes_read = read(fd, read_buf, sizeof(read_buf));
	T_ASSERT_POSIX_SUCCESS(bytes_read, "read from tmpfile");

	/* these have to be "may fail" instead of "expect fail" due to rdar://136258500 */
	T_MAYFAIL_WITH_RADAR(136300841);
	T_EXPECT_EQ(bytes_read, (ssize_t)length, "bytes sent over tmpfile");

	for (size_t i = 0; i < length; i++) {
		T_MAYFAIL_WITH_RADAR(136300841);
		T_EXPECT_EQ(buf_tagged[i], read_buf[i], "character %lu matches", i);
	}

	kern_return_t kr = vm_deallocate(mach_task_self(), (vm_address_t) buf_untagged, BUF_SIZE);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate tagged buffer");

	close(fd);
}

T_DECL(mte_aio_tag_bypass,
    "Test nonfatal MTE asynchronous access faults with tag check bypass",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC) {
	run_helper_with_sec_bypass("mte_tag_violate_aio");
}
#endif /* __arm64__ */

static void
run_iokit_sysctl_test(int vector)
{
	int ret = sysctlbyname("kern.iokittest", NULL, 0, &vector, sizeof(vector));
	T_EXPECT_POSIX_ZERO(ret, "sysctl kern.iokittest(%d)", vector);
}

T_DECL(mte_iomd_cpu_map,
    "Test that IOMemoryDescriptor::map() of userspace memory is mapped as untagged in the kernel",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	run_iokit_sysctl_test(333);
}

T_DECL(mte_iomd_read_write_bytes,
    "Test that IOMemoryDescriptor::read/writeBytes() of tagged memory works",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	run_iokit_sysctl_test(334);
}

T_DECL(iomd_read_write_bytes_non_mte,
    "Test that IOMemoryDescriptor::read/writeBytes() of untagged memory works",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	run_iokit_sysctl_test(335);
}

T_DECL(iomd_read_bytes_with_tcf,
    "Test that tag mismatches during IOMemoryDescriptor::readBytes() get detected",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	/* The iokit test will generate an artificial tag check mismatch midway through the buffer */
	expect_sigkill(^{
		run_iokit_sysctl_test(336);
		T_ASSERT_FAIL("Expected this process to get killed");
	}, "asynchronous TCF in readBytes()");
}

T_DECL(iomd_write_bytes_with_tcf,
    "Test that tag mismatches during IOMemoryDescriptor::writeBytes() continue to work out of the box",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	/* The iokit test will generate an artificial tag check mismatch midway through the buffer */
	expect_sigkill(^{
		run_iokit_sysctl_test(337);
		T_ASSERT_FAIL("Expected this process to get killed");
	}, "asynchronous TCF in writeBytes()");
}

T_DECL(iomd_create_alias_mapping_in_this_map,
    "Test that IOMemoryDescriptor::createMappingInTask() of tagged memory in the current task works",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	run_iokit_sysctl_test(340);
}

T_DECL(iomd_create_alias_mapping_in_kernel_map,
    "Test that IOMemoryDescriptor::createMappingInTask() of tagged memory in the kernel is allowed",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC) {
	run_iokit_sysctl_test(342);
}

T_DECL(mte_cpu_map_pageout,
    "Test correct behavior of kernel CPU mapping after userspace mapping is paged out",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    T_META_ASROOT(true),
    XNU_T_META_SOC_SPECIFIC)
{
	mach_vm_size_t alloc_size = PAGE_SIZE;
	char *ptr = (char*)(allocate_and_tag_range(alloc_size, TAG_RANDOM_EXCLUDE(0xF)));
	char value = 'A';
	memset(ptr, value, alloc_size);

	struct {
		mach_vm_size_t size;
		char *ptr;
		char value;
	} args = { alloc_size, ptr, value };
	run_sysctl_test("vm_cpu_map_pageout", (int64_t)(&args));
}

T_DECL(vm_region_recurse_mte_info,
    "Ensure metadata returned by vm_region_recurse correct reflects MTE status",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	T_SETUPBEGIN;

	/* Given an MTE-enabled region */
	const mach_vm_size_t alloc_size = PAGE_SIZE;
	vm_address_t tagged_buffer_addr = allocate_and_tag_range(alloc_size, 0xa);
	vm_address_t untagged_handle_to_tagged_address = tagged_buffer_addr & ~MTE_TAG_MASK;

	/* And a non-MTE-enabled region */
	/* (Manually select an address to be sure we're placed in a new region from the tagged region) */
	mach_vm_address_t untagged_buffer_addr = untagged_handle_to_tagged_address + (32 * 1024);
	kern_return_t kr = mach_vm_allocate(
		mach_task_self(),
		&untagged_buffer_addr,
		alloc_size,
		VM_FLAGS_FIXED);
	if (kr == KERN_NO_SPACE) {
		/* Skip gracefully if we fail to grab the VA space we need. */
		T_SKIP("Cannot grab required VA space, skipping...");
	}
	T_ASSERT_MACH_SUCCESS(kr, "Allocated untagged page");
	/* (And write to it to be sure we populate a VM object) */
	memset((uint8_t*)untagged_buffer_addr, 0, alloc_size);

	T_SETUPEND;

	/* When we query the attributes of the region covering the MTE-enabled buffer */
	mach_vm_address_t addr = untagged_handle_to_tagged_address;
	mach_vm_size_t addr_size = alloc_size;
	uint32_t nesting_depth = UINT_MAX;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	vm_region_submap_info_data_64_t region_info;
	kr = vm_region_recurse_64(mach_task_self(), (vm_address_t*)&addr, (vm_size_t*)&addr_size, &nesting_depth, (vm_region_recurse_info_t)&region_info, &count);

	/* Then our metadata confirms that the region contains an MTE-mappable object */
	T_ASSERT_MACH_SUCCESS(kr, "Query MTE-enabled region");
	T_ASSERT_TRUE(region_info.flags & VM_REGION_FLAG_MTE_ENABLED, "Expected metadata to reflect an MTE mappable object");

	/* And when we query the same thing via the 'short' info */
	addr = untagged_handle_to_tagged_address;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	vm_region_submap_short_info_data_64_t short_info;
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region contains an MTE-mappable object */
	T_ASSERT_MACH_SUCCESS(kr, "Query MTE-enabled region");
	T_ASSERT_TRUE(short_info.flags & VM_REGION_FLAG_MTE_ENABLED, "Expected metadata to reflect an MTE mappable object");

	/* And when we query the attributes of the region covering the non-MTE-enabled buffer */
	addr = untagged_buffer_addr;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_INFO_V2_COUNT_64;
	memset(&region_info, 0, sizeof(region_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&region_info, &count);

	/* Then our metadata confirm that the region does not contain an MTE-mappable object */
	T_ASSERT_MACH_SUCCESS(kr, "Query MTE-disabled region");
	T_ASSERT_FALSE(region_info.flags & VM_REGION_FLAG_MTE_ENABLED, "Expected metadata to reflect no MTE mappable object");

	/* And when we query the same thing via the 'short' info */
	addr = untagged_buffer_addr;
	addr_size = alloc_size;
	nesting_depth = UINT_MAX;
	count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
	memset(&short_info, 0, sizeof(short_info));
	kr = mach_vm_region_recurse(mach_task_self(), (mach_vm_address_t*)&addr, (mach_vm_size_t*)&addr_size, &nesting_depth, (vm_region_info_t)&short_info, &count);

	/* Then the short metadata also confirms that the region does not contain an MTE-mappable object */
	T_ASSERT_MACH_SUCCESS(kr, "Query MTE-disabled region");
	T_ASSERT_FALSE(short_info.flags & VM_REGION_FLAG_MTE_ENABLED, "Expected metadata to reflect no MTE mappable object");

	/* Cleanup */
	kr = mach_vm_deallocate(mach_task_self(), untagged_handle_to_tagged_address, alloc_size);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate tagged memory");
	kr = mach_vm_deallocate(mach_task_self(), untagged_buffer_addr, alloc_size);
	T_ASSERT_MACH_SUCCESS(kr, "deallocate untagged memory");
}

T_DECL(mach_vm_read_of_remote_proc,
    "Verify that mach_vm_read of a remote MTE-enabled process works",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    /* rdar://151142487: gcore won't work on iOS without unrestricting task_read_for_pid */
    T_META_BOOTARGS_SET("amfi_unrestrict_task_for_pid=1"),
    T_META_ASROOT(true))
{
	/* Given a process that is launched as MTE-enabled */
	char* sleep_args[] = { "/bin/sleep", "5000", NULL};
	posix_spawnattr_t attr;
	errno_t ret = posix_spawnattr_init(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_init");
	ret = posix_spawnattr_set_use_sec_transition_shims_np(&attr, POSIX_SPAWN_SECFLAG_EXPLICIT_ENABLE);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_set_use_sec_transition_shims_np");
	pid_t child_pid = 0;
	ret = posix_spawn(&child_pid, sleep_args[0], NULL, &attr, sleep_args, NULL);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawn");
	T_ASSERT_NE(child_pid, 0, "posix_spawn");
	ret = posix_spawnattr_destroy(&attr);
	T_ASSERT_POSIX_ZERO(ret, "posix_spawnattr_destroy");

	/* And it's MTE-enabled as expected */
	validate_proc_pidinfo_mte_status(child_pid, true);

	/* And gcore attempts to mach_vm_read some of its memory */
	char pid_buf[64];
	snprintf(pid_buf, sizeof(pid_buf), "%d", child_pid);
	char* gcore_args[] = { "/usr/bin/gcore", pid_buf, NULL};
	/* Then gcore (and its implicit mach_vm_read()) succeeds */
	posix_spawn_with_flags_and_assert_successful_exit(gcore_args, POSIX_SPAWN_SECFLAG_EXPLICIT_DISABLE, false, false);

	kill_child(child_pid);
}

void
do_local_vm_copyin_with_invalid_tag_test(vm_size_t size)
{
	T_SETUPBEGIN;

	/* Given an MTE-enabled region */
	vm_address_t mte_region = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &mte_region, size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	memset((void *)mte_region, 0, size);

	/* And an MTE-disabled region */
	vm_address_t non_mte_region = 0;
	kr = vm_allocate(mach_task_self(), &non_mte_region, size, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(non-MTE)");

	/* And the MTE region has tag 0x4, but our pointer is incorrectly tagged 0x5 */
	mte_region |= 0x0400000000000000;
	__arm_mte_set_tag((void *)mte_region);
	mte_region |= 0x0500000000000000;

	T_SETUPEND;

	/* When we use `vm_read_overwrite` */
	/* Then the system terminates us due to our incorrectly tagged request */
	vm_size_t out_size;
	vm_read_overwrite(mach_task_self(), mte_region, size, non_mte_region, &out_size);
	T_FAIL("Expected to be SIGKILLED");
}

T_DECL(local_vm_copyin_with_invalid_tag,
    "Verify that copyin of local memory with an invalid tag is denied",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	/*
	 * We go down different code paths depending on the size,
	 * so test both and ensure they're handled consistently.
	 */
	expect_sigkill(^{
		do_local_vm_copyin_with_invalid_tag_test(PAGE_SIZE);
	}, "local_vm_copyin(PAGE_SIZE)");
	expect_sigkill(^{
		do_local_vm_copyin_with_invalid_tag_test(PAGE_SIZE * 10);
	}, "local_vm_copyin(PAGE_SIZE * 10)");
}

T_DECL(local_vm_copyin_with_large_non_mte_object_with_adjacent_mte_object,
    "Ensure a large copyin with a non-MTE object and adjacent MTE object fails",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	expect_sigkill(^{
		/* Given a non-MTE-enabled object */
		vm_address_t non_mte_object_address = 0;
		vm_size_t non_mte_object_size = PAGE_SIZE;
		kern_return_t kr = vm_allocate(mach_task_self(), &non_mte_object_address, non_mte_object_size, VM_FLAGS_ANYWHERE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(non-MTE)");
		/* And ensure it's present */
		memset((void *)non_mte_object_address, 0, non_mte_object_size);

		/* And an adjacent MTE object (which is large enough that the total region will definitely be above `msg_ool_size_small`) */
		vm_address_t mte_object_address = non_mte_object_address + non_mte_object_size;
		vm_size_t mte_object_size = PAGE_SIZE * 2;
		kr = vm_allocate(mach_task_self(), &mte_object_address, mte_object_size, VM_FLAGS_FIXED | VM_FLAGS_MTE);
		if (kr == KERN_NO_SPACE) {
		        /*
		         * Skip gracefully if we fail to grab the VA space we need.
		         * Note that we send ourselves a SIGKILL so the expect_sigkill() wrapper
		         * is happy. We can't use T_SKIP or the like because that would elide the
		         * SIGKILL.
		         */
		        T_LOG("Cannot grab required VA space, skipping...");
		        kill(getpid(), SIGKILL);
		        return;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(adjacent MTE)");
		/* And ensure it's present */
		memset((void *)mte_object_address, 0, mte_object_size);
		/* And the MTE object has a non-zero tag (so we TCF when crossing it) */
		mte_object_address |= 0x0400000000000000;
		for (mach_vm_size_t offset = 0; offset < mte_object_size; offset += MTE_GRANULE_SIZE) {
		        __arm_mte_set_tag(&((uint8_t*)mte_object_address)[offset]);
		}

		/* When we try to copyin the entire region, spanning both objects */
		vm_size_t total_region_size = mte_object_size + non_mte_object_size;
		vm_address_t region_to_overwrite = 0;
		kr = vm_allocate(mach_task_self(), &region_to_overwrite, total_region_size, VM_FLAGS_ANYWHERE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

		vm_size_t out_size;
		/* Then we take a TCF during the copyin */
		vm_read_overwrite(mach_task_self(), non_mte_object_address, total_region_size, region_to_overwrite, &out_size);
	}, "Trigger a TCF during copyin");
}

T_DECL(local_vm_copyin_with_large_mte_object_with_invalid_size,
    "Ensure a large copyin with a non-MTE object but an invalid size fails",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	/* Given an MTE-enabled object (which is large enough that it exceeds `msg_ool_size_small`) */
	vm_address_t mte_object_address = 0;
	vm_size_t mte_object_size = PAGE_SIZE * 3;
	kern_return_t kr = vm_allocate(mach_task_self(), &mte_object_address, mte_object_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE | VM_FLAGS_RANDOM_ADDR);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	/* And ensure it's present */
	memset((void *)mte_object_address, 0, mte_object_size);

	/* When we try to copyin the region, but specify a size that's too large */
	/* And we ensure this object is not coalesced with the above object */
	vm_size_t invalid_size = mte_object_size + PAGE_SIZE * 16;
	vm_address_t region_to_overwrite = mte_object_address + (PAGE_SIZE * 8);
	kr = vm_allocate(mach_task_self(), &region_to_overwrite, invalid_size, VM_FLAGS_FIXED);
	if (kr == KERN_NO_SPACE) {
		/* Skip gracefully if we fail to grab the VA space we need */
		T_SKIP("Cannot grab required VA space, skipping...");
		return;
	}
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

	vm_size_t out_size;
	kr = vm_read_overwrite(mach_task_self(), mte_object_address, invalid_size, region_to_overwrite, &out_size);
	/* Then it fails */
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "copyin fails");
}

T_DECL(local_vm_copyin_with_large_mte_object_with_hole_in_region,
    "Ensure a large copyin with an MTE object, but with a hole in the middle, is rejected",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	/* Given an MTE-enabled object (which is large enough that it exceeds `msg_ool_size_small`) */
	vm_address_t mte_object_address = 0;
	vm_size_t mte_object_size = PAGE_SIZE * 3;
	kern_return_t kr = vm_allocate(mach_task_self(), &mte_object_address, mte_object_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	/* And ensure it's present */
	memset((void *)mte_object_address, 0, mte_object_size);

	/* And a nearby non-MTE object, but we leave a hole in the middle */
	vm_size_t padding = PAGE_SIZE;
	vm_address_t non_mte_object_address = mte_object_address + mte_object_size + padding;
	vm_size_t non_mte_object_size = PAGE_SIZE;
	kr = vm_allocate(mach_task_self(), &non_mte_object_address, non_mte_object_size, VM_FLAGS_FIXED);
	if (kr == KERN_NO_SPACE) {
		/* Skip gracefully if we fail to grab the VA space we need */
		T_SKIP("Cannot grab required VA space, skipping...");
		return;
	}

	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(nearby non-MTE)");
	/* And ensure it's present */
	memset((void *)non_mte_object_address, 0, non_mte_object_size);

	/* When we try to copyin the whole region, including the hole */
	vm_size_t region_size = mte_object_size + padding + non_mte_object_size;
	vm_address_t region_to_overwrite = 0;
	kr = vm_allocate(mach_task_self(), &region_to_overwrite, region_size, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

	vm_size_t out_size;
	kr = vm_read_overwrite(mach_task_self(), mte_object_address, region_size, region_to_overwrite, &out_size);
	/* Then it fails */
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ADDRESS, "copyin fails");
}

T_DECL(local_vm_copyin_with_large_mte_object_with_adjacent_large_mte_object_same_tags,
    "Ensure a large copyin with two MTE objects with the same tag succeeds",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	/* Given an MTE-enabled object */
	vm_address_t mte_object1_address = 0;
	vm_size_t mte_object1_size = PAGE_SIZE;
	kern_return_t kr = vm_allocate(mach_task_self(), &mte_object1_address, mte_object1_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE | VM_FLAGS_RANDOM_ADDR);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	/* And ensure it's present */
	memset((void *)mte_object1_address, 0, mte_object1_size);

	/* And an adjacent MTE object (which is large enough that the total region will definitely be above `msg_ool_size_small`) */
	vm_address_t mte_object2_address = mte_object1_address + mte_object1_size;
	vm_size_t mte_object2_size = PAGE_SIZE * 2;
	kr = vm_allocate(mach_task_self(), &mte_object2_address, mte_object2_size, VM_FLAGS_FIXED | VM_FLAGS_MTE);
	if (kr == KERN_NO_SPACE) {
		/* Skip gracefully if we fail to grab the VA space we need */
		T_SKIP("Cannot grab required VA space, skipping...");
		return;
	}
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	/* And ensure it's present */
	memset((void *)mte_object2_address, 0, mte_object2_size);

	/* And both objects share the same tag */
	vm_size_t total_region_size = mte_object1_size + mte_object2_size;
	mte_object1_address |= 0x0400000000000000;
	for (mach_vm_size_t offset = 0; offset < total_region_size; offset += MTE_GRANULE_SIZE) {
		__arm_mte_set_tag(&((uint8_t*)mte_object1_address)[offset]);
	}

	/* When we try to copyin the entire region, spanning both objects */
	vm_address_t region_to_overwrite = 0;
	kr = vm_allocate(mach_task_self(), &region_to_overwrite, total_region_size, VM_FLAGS_ANYWHERE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

	vm_size_t out_size;
	kr = vm_read_overwrite(mach_task_self(), mte_object1_address, total_region_size, region_to_overwrite, &out_size);
	/* Then it succeeds */
	T_ASSERT_MACH_SUCCESS(kr, "copyin");
}

T_DECL(local_vm_copyin_with_large_mte_object_with_adjacent_large_mte_object_different_tags,
    "Ensure a large copyin with two MTE objects with a different tag in the second object fails",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	expect_sigkill(^{
		/* Given an MTE-enabled object */
		vm_address_t mte_object1_address = 0;
		vm_size_t mte_object1_size = PAGE_SIZE;
		kern_return_t kr = vm_allocate(mach_task_self(), &mte_object1_address, mte_object1_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
		/* And ensure it's present */
		memset((void *)mte_object1_address, 0, mte_object1_size);

		/* And an adjacent MTE object (which is large enough that the total region will definitely be above `msg_ool_size_small`) */
		vm_address_t mte_object2_address = mte_object1_address + mte_object1_size;
		vm_size_t mte_object2_size = PAGE_SIZE * 2;
		kr = vm_allocate(mach_task_self(), &mte_object2_address, mte_object2_size, VM_FLAGS_FIXED | VM_FLAGS_MTE);
		if (kr == KERN_NO_SPACE) {
		        /*
		         * Skip gracefully if we fail to grab the VA space we need.
		         * Note that we send ourselves a SIGKILL so the expect_sigkill() wrapper
		         * is happy. We can't use T_SKIP or the like because that would elide the
		         * SIGKILL.
		         */
		        T_LOG("Cannot grab required VA space, skipping...");
		        kill(getpid(), SIGKILL);
		        return;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(adjacent MTE)");
		/* And ensure it's present */
		memset((void *)mte_object2_address, 0, mte_object2_size);

		/* And the objects have different tags */
		mte_object1_address |= 0x0400000000000000;
		for (mach_vm_size_t offset = 0; offset < mte_object1_size; offset += MTE_GRANULE_SIZE) {
		        __arm_mte_set_tag(&((uint8_t*)mte_object1_address)[offset]);
		}
		mte_object2_address |= 0x0500000000000000;
		for (mach_vm_size_t offset = 0; offset < mte_object2_size; offset += MTE_GRANULE_SIZE) {
		        __arm_mte_set_tag(&((uint8_t*)mte_object2_address)[offset]);
		}

		/* When we try to copyin the entire region, spanning both objects */
		vm_address_t region_to_overwrite = 0;
		vm_size_t total_region_size = mte_object1_size + mte_object2_size;
		kr = vm_allocate(mach_task_self(), &region_to_overwrite, total_region_size, VM_FLAGS_ANYWHERE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

		/* And we use a pointer that only has a valid tag for the first object */
		/* Then we get a SIGKILL (because we take a TCF) */
		vm_size_t out_size;
		vm_read_overwrite(mach_task_self(), mte_object1_address, total_region_size, region_to_overwrite, &out_size);
	}, "Trigger a TCF during copyin");
}

T_DECL(local_vm_copyin_with_large_mte_object_with_adjacent_non_mte_object,
    "Ensure a large copyin with an MTE object and adjacent non-MTE object fails",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	expect_sigkill(^{
		/* Given an MTE-enabled object */
		vm_address_t mte_object_address = 0;
		vm_size_t mte_object_size = PAGE_SIZE;
		kern_return_t kr = vm_allocate(mach_task_self(), &mte_object_address, mte_object_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
		/* And ensure it's present */
		memset((void *)mte_object_address, 0, mte_object_size);
		/* And the MTE object has a non-zero tag (so we CTCF when crossing to an untagged region) */
		vm_address_t tagged_mte_object_address = mte_object_address | 0x0400000000000000;
		for (mach_vm_size_t offset = 0; offset < mte_object_size; offset += MTE_GRANULE_SIZE) {
		        __arm_mte_set_tag(&((uint8_t*)tagged_mte_object_address)[offset]);
		}

		/* And an adjacent non-MTE object (which is large enough that the total region will definitely be above `msg_ool_size_small`) */
		vm_address_t non_mte_object_address = mte_object_address + mte_object_size;
		vm_size_t non_mte_object_size = PAGE_SIZE * 2;
		kr = vm_allocate(mach_task_self(), &non_mte_object_address, non_mte_object_size, VM_FLAGS_FIXED);
		if (kr == KERN_NO_SPACE) {
		        /*
		         * Skip gracefully if we fail to grab the VA space we need.
		         * Note that we send ourselves a SIGKILL so the expect_sigkill() wrapper
		         * is happy. We can't use T_SKIP or the like because that would elide the
		         * SIGKILL.
		         */
		        T_LOG("Cannot grab required VA space, skipping...");
		        kill(getpid(), SIGKILL);
		        return;
		}
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(adjacent non-MTE)");
		/* And ensure it's present */
		memset((void *)non_mte_object_address, 0, non_mte_object_size);

		/* When we try to copyin the entire region, spanning both objects */
		vm_size_t total_region_size = mte_object_size + non_mte_object_size;
		vm_address_t region_to_overwrite = 0;
		kr = vm_allocate(mach_task_self(), &region_to_overwrite, total_region_size, VM_FLAGS_ANYWHERE);
		T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(scribble region)");

		vm_size_t out_size;
		vm_read_overwrite(mach_task_self(), mte_object_address, total_region_size, region_to_overwrite, &out_size);
		/* Then we're killed due to a CTCF */
	}, "Trigger a CTCF during copyin");
}

T_DECL(make_memory_entry_handles_kernel_buffers,
    "Ensure mach_make_memory_entry does not panic when handed an MTE copy",
    T_META_ENABLED(TARGET_CPU_ARM64),
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC,
    T_META_ASROOT(true))
{
	/* Given an MTE-enabled object */
	vm_address_t mte_object_address = 0;
	vm_size_t mte_object_size = PAGE_SIZE;
	kern_return_t kr = vm_allocate(mach_task_self(), &mte_object_address, mte_object_size, VM_FLAGS_ANYWHERE | VM_FLAGS_MTE);
	T_ASSERT_MACH_SUCCESS(kr, "vm_allocate(MTE)");
	/* And ensure it's present */
	memset((void *)mte_object_address, 0, mte_object_size);
	/* And assign a non-zero tag just for authenticity */
	vm_address_t tagged_mte_object_address = mte_object_address | 0x0400000000000000;
	for (mach_vm_size_t offset = 0; offset < mte_object_size; offset += MTE_GRANULE_SIZE) {
		__arm_mte_set_tag(&((uint8_t*)tagged_mte_object_address)[offset]);
	}

	/* When I use mach_make_memory_entry_64(MAP_MEM_VM_COPY) */
	mach_vm_size_t size = mte_object_size;
	mach_port_t memory_entry_port;
	kr = mach_make_memory_entry_64(mach_task_self(),
	    &size,
	    tagged_mte_object_address,
	    VM_PROT_DEFAULT | MAP_MEM_VM_COPY | MAP_MEM_USE_DATA_ADDR,
	    &memory_entry_port, MEMORY_OBJECT_NULL);
	/* Then the system does not panic... */
	T_ASSERT_MACH_SUCCESS(kr, "mach_make_memory_entry_64(MTE object)");
}
