/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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
#include <darwintest.h>
#include <sys/sysctl.h>
#include <assert.h>
#include <pthread.h>
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("jharmening"),
	T_META_RUN_CONCURRENTLY(true),
	XNU_T_META_SOC_SPECIFIC);

T_DECL(pmap_enter_disconnect,
    "Test that a physical page can be safely mapped concurrently with a disconnect of the same page", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_enter_disconnect_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_enter_disconnect_test, %d loops", num_loops);
}

T_DECL(pmap_exec_remove_test,
    "Test that an executable mapping can be created while another mapping of the same physical page is removed", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_exec_remove_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_exec_remove_test, %d loops", num_loops);
}

T_DECL(pmap_exec_remove_test_4k,
    "Test that an executable mapping can be created while another mapping of the same physical page is removed, in a 4K pmap", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_exec_remove_test_4k", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_exec_remove_test_4k, %d loops", num_loops);
}

T_DECL(pmap_enter_remove_test,
    "Test more than two threads concurrently entering and removing the same mapping", T_META_TAG_VM_NOT_ELIGIBLE)
{
	/**
	 * This test spawns a number of long-running and CPU-intensive kernel worker threads
	 * which inherit the main thread's priority.  Temporarily drop our priority down to
	 * the default (low) userspace priority to avoid producing a bunch of foreground-
	 * priority kernel threads that may starve other threads on smaller/slower devices.
	 */
	qos_class_t prev_qos;
	pthread_get_qos_class_np(pthread_self(), &prev_qos, NULL);
	pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);

	int num_loops = 100000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_enter_remove_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_enter_remove_test, %d loops", num_loops);

	pthread_set_qos_class_self_np(prev_qos, 0);
}

T_DECL(pmap_enter_remove_test_4k,
    "Test more than two threads concurrently entering and removing the same mapping, in a 4K pmap", T_META_TAG_VM_NOT_ELIGIBLE)
{
	/**
	 * This test spawns a number of long-running and CPU-intensive kernel worker threads
	 * which inherit the main thread's priority.  Temporarily drop our priority down to
	 * the default (low) userspace priority to avoid producing a bunch of foreground-
	 * priority kernel threads that may starve other threads on smaller/slower devices.
	 */
	qos_class_t prev_qos;
	pthread_get_qos_class_np(pthread_self(), &prev_qos, NULL);
	pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);

	int num_loops = 100000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_enter_remove_test_4k", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_enter_remove_test_4k, %d loops", num_loops);

	pthread_set_qos_class_self_np(prev_qos, 0);
}

T_DECL(pmap_compress_remove_test,
    "Test that a page can be disconnected for compression while concurrently unmapping the same page", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 1000000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_compress_remove_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_compress_remove_test, %d loops", num_loops);
}

T_DECL(pmap_protect_remove_test,
    "Test that a VA region can be concurrently unmapped while having its protection changed", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_protect_remove_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_protect_remove_test, %d loops", num_loops);
}

T_DECL(pmap_query_remove_test,
    "Test that a VA region can be concurrently unmapped while having its mapping state queried", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_query_remove_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_query_remove_test, %d loops", num_loops);
}

T_DECL(pmap_nesting_test,
    "Test that pmap_nest() and pmap_unnest() work reliably when concurrently invoked from multiple threads", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 5;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_nesting_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_nesting_test, %d loops", num_loops);
}

T_DECL(pmap_iommu_disconnect_test,
    "Test that CPU mappings of a physical page can safely be disconnected in the presence of IOMMU mappings", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int run = 1;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_iommu_disconnect_test", NULL, NULL, &run, sizeof(run)),
	    "kern.pmap_iommu_disconnect_test");
}

T_DECL(pmap_extended_test,
    "Test various pmap lifecycle calls in the presence of special configurations such as 4K and stage-2", T_META_TAG_VM_NOT_ELIGIBLE)
{
	int run = 1;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_extended_test", NULL, NULL, &run, sizeof(run)),
	    "kern.pmap_extended_test");
}

T_DECL(pmap_huge_pv_list_test,
    "Test that extremely large PV lists can be managed without spinlock timeouts or other panics",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2), T_META_TAG_VM_NOT_ELIGIBLE)
{
	struct {
		unsigned int num_loops;
		unsigned int num_mappings;
	} hugepv_in;
	hugepv_in.num_loops = 500;
	hugepv_in.num_mappings = 500000;

	/**
	 * This test spawns a number of long-running and CPU-intensive kernel worker threads
	 * which inherit the main thread's priority.  Temporarily drop our priority down to
	 * the default (low) userspace priority to avoid producing a bunch of foreground-
	 * priority kernel threads that may starve other threads on smaller/slower devices.
	 */
	qos_class_t prev_qos;
	pthread_get_qos_class_np(pthread_self(), &prev_qos, NULL);
	pthread_set_qos_class_self_np(QOS_CLASS_DEFAULT, 0);

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_huge_pv_list_test", NULL, NULL,
	    &hugepv_in, sizeof(hugepv_in)), "kern.pmap_huge_pv_list_test");

	pthread_set_qos_class_self_np(prev_qos, 0);
}

T_DECL(pmap_reentrance_test,
    "Test that the pmap can be reentered by an async exception handler",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2), T_META_TAG_VM_NOT_ELIGIBLE)
{
	int num_loops = 10000;
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.pmap_reentrance_test", NULL, NULL, &num_loops, sizeof(num_loops)),
	    "kern.pmap_reentrance_test, %d loops", num_loops);
}

T_DECL(surt_test,
    "Test that surt can handle a surge of SURT requests",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2),
    T_META_REQUIRES_SYSCTL_EQ("kern.surt_ready", 1),
    T_META_TAG_VM_NOT_ELIGIBLE)
{
	/* Use maxproc to get the theoretical upper bound on the sizeof a SURT request surge. */
	int maxproc;
	size_t maxproc_size = sizeof(maxproc);
	sysctlbyname("kern.maxproc", &maxproc, &maxproc_size, NULL, 0);

	int num_surts = maxproc;
	const int num_loops = 100;

	for (int i = 0; i < num_loops; i++) {
		T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.surt_test", NULL, NULL, &num_surts, sizeof(num_surts)),
		    "kern.surt_test, %d surts", num_surts);
	}
}
