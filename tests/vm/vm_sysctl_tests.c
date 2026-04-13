#include <sys/sysctl.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <ptrauth.h>
#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(YES),
	T_META_RUN_CONCURRENTLY(true),
	T_META_TAG_VM_PREFERRED);

static int64_t
run_sysctl_test(const char *t, int64_t value)
{
	char name[1024];
	int64_t result = 0;
	size_t s = sizeof(value);
	int rc;

	snprintf(name, sizeof(name), "debug.test.%s", t);
	rc = sysctlbyname(name, &result, &s, &value, s);
	T_ASSERT_POSIX_SUCCESS(rc, "sysctlbyname(%s)", t);
	return result;
}

T_DECL(vm_map_null,
    "Test that we can call vm_map functions with VM_MAP_NULL",
    T_META_TAG_VM_PREFERRED)
{
	int64_t result = run_sysctl_test("vm_map_null", 0);
	T_EXPECT_EQ(1ULL, result, "vm_map_null");
}

T_DECL(vm_map_copy_entry_subrange,
    "Test mapping a subrange of a copy entry")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_copy_entry_subrange", 0), "vm_map_copy_entry_subrange");
}

T_DECL(vm_memory_entry_map_size_null,
    "Test mach_memory_entry_map_size with NULL memory entry")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_memory_entry_map_size_null", 0), "vm_memory_entry_map_size_null");
}


T_DECL(vm_memory_entry_map_size_overflow,
    "Test overflow cases in mach_memory_entry_map_size sanitization")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_memory_entry_map_size_overflow", 0), "vm_memory_entry_map_size_overflow");
}

T_DECL(vm_memory_entry_map_size_copy,
    "Test mach_memory_entry_map_size with copy memory entries and 4k/16k combinations")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_memory_entry_map_size_copy", 0), "vm_memory_entry_map_size_copy");
}

T_DECL(vm_memory_entry_parent_submap,
    "Test mach_make_memory_entry cases where parent is a submap")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_memory_entry_parent_submap", 0), "vm_memory_entry_parent_submap");
}

T_DECL(memory_entry_share_kernel_tagged_address,
    "Verify that memory_entry_share can handle tagged kernel addresses")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("memory_entry_share_kernel_heap_test", 0),
	    "memory_entry_share_kernel_heap_test");
}

T_DECL(vm_lock_test, "test locks")
{
	int64_t result = run_sysctl_test("vm_range_lock_test", 0);
	T_EXPECT_EQ(1ULL, result, "vm_range_lock_test");
}

T_DECL(vm_lock_preflight_test, "test lock preflight")
{
	int64_t result = run_sysctl_test("vm_range_lock_preflight_test", 0);
	T_EXPECT_EQ(1ULL, result, "vm_range_lock_preflight_test");
}

T_DECL(flags_test, "flags_test")
{
	int64_t result = run_sysctl_test("vm_range_lock_flags_test", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_range_lock_flags_test");
}

#ifndef __x86_64__
T_DECL(vm_page_radix_verify, "verify the vm pages radix tree")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_page_radix_verify", 0), "vm_page_radix_verify");
}
#endif

T_DECL(vm_map_4k_16k_copyout,
    "Make sure vm_map_copyout from 4k->16k maps doesn't lead to address space holes")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_4k_16k", 0), "vm_map_4k_16k_copyout");
}

T_DECL(vm_map_4k_16k_copy_overwrite,
    "Make sure vm_map_copy_overwrite from 4k->16k maps doesn't lead to address space holes")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_4k_16k", 1), "vm_map_4k_16k_copy_overwrite");
}

T_DECL(vm_misc_tests,
    "vm_misc_tests")
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_misc_tests", 1), "vm_misc_tests");
}

T_DECL(vm_map_find_locked_entry_test, "vm_map_find_locked_entry_test")
{
	int64_t result = run_sysctl_test("vm_map_find_locked_entry_test", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_find_locked_entry_test");
}

T_DECL(vm_map_remove,
    "vm_map_remove tests")
{
	int64_t result = run_sysctl_test("vm_map_remove_test", 0);
	T_EXPECT_EQ(1ULL, result, "vm_map_remove_test");
}

T_DECL(vm_cs_obj_map,
    "Make sure chain including CS associated obj can be faulted in kernel map")
{
	/* pass cs associated addr, the text of this binary */

	int64_t func_addr = (int64_t) ptrauth_strip(&run_sysctl_test, ptrauth_key_function_pointer);
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_cs_associated_obj", func_addr), "vm_map_cs_associated_obj");
}

T_DECL(vm_map_range_configure,
    "vm_map_range_configure tests")
{
	int64_t result = run_sysctl_test("vm_map_range_configure_test", 0);
	T_EXPECT_EQ(1ULL, result, "vm_map_range_configure_test");
}


/* Slower multithreaded tests begin here, so we can run all the faster tests first */


/*
 * Wire vs delete race test
 */
static void *
vm_map_wire_race_test_thread_one_caller(void * args)
{
	int64_t result = run_sysctl_test("vm_map_wire_race_test_thread_one", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "1");
	return NULL;
}


static void *
vm_map_wire_race_test_thread_two_caller(void * args)
{
	int64_t result = run_sysctl_test("vm_map_wire_race_test_thread_two", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_wire_race_test_thread_two");
	return NULL;
}

T_DECL(wire_concurrent_deletion_test, "Test concurrent deletions against a kernel wiring", T_META_RUN_CONCURRENTLY(false))
{
	pthread_t th_one, th_two;
	int err;

	int64_t result = run_sysctl_test("vm_map_wire_race_test_setup", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "setup");

	err = pthread_create(&th_one, NULL, vm_map_wire_race_test_thread_one_caller, (void *) 0);
	T_QUIET; T_ASSERT_EQ(err, 0, "pthread_create");

	err = pthread_create(&th_two, NULL, vm_map_wire_race_test_thread_two_caller, (void *) 0);
	T_QUIET; T_ASSERT_EQ(err, 0, "pthread_create");

	sleep(10);

	int race_hits = run_sysctl_test("vm_map_wire_race_test_signal_end", 0);
	T_LOG("Hit the race we intend to hit: %i times\n", race_hits);
	T_PASS("Test didn't panic");


	pthread_join(th_one, NULL);
	pthread_join(th_two, NULL);

	run_sysctl_test("vm_map_wire_race_test_cleanup", 0);
}


/*
 * Copy overwrite vs wire race test
 */
static void *
vm_map_copy_overwrite_wire_race_copy_thread_caller(void * args)
{
	int64_t result = run_sysctl_test("vm_map_copy_overwrite_wire_race_copy_thread", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_copy_overwrite_wire_race_copy_thread");
	return NULL;
}


static void *
vm_map_copy_overwrite_wire_race_busy_thread_caller(void * args)
{
	int64_t result = run_sysctl_test("vm_map_copy_overwrite_wire_race_busy_thread", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "vm_map_copy_overwrite_wire_race_busy_thread");
	return NULL;
}

T_DECL(wire_copy_overwrite_tests, "Test copy_overwrite against wire's lock ordering", T_META_RUN_CONCURRENTLY(false))
{
	pthread_t th_one, th_two;
	int err;

	int64_t result = run_sysctl_test("vm_map_copy_overwrite_wire_race_setup", 0);
	T_QUIET; T_EXPECT_EQ(1ULL, result, "setup");

	err = pthread_create(&th_one, NULL, vm_map_copy_overwrite_wire_race_copy_thread_caller, (void *) 0);
	T_QUIET; T_ASSERT_EQ(err, 0, "pthread_create");

	err = pthread_create(&th_two, NULL, vm_map_copy_overwrite_wire_race_busy_thread_caller, (void *) 0);
	T_QUIET; T_ASSERT_EQ(err, 0, "pthread_create");

	sleep(5);

	run_sysctl_test("vm_map_copy_overwrite_wire_race_signal_end", 0);


	pthread_join(th_one, NULL);
	pthread_join(th_two, NULL);

	run_sysctl_test("vm_map_copy_overwrite_wire_race_cleanup", 0);

	T_PASS("Test didn't deadlock");
}

T_DECL(vm_map_protect_pmap_max,
    "test vm_map_protect on a region that hits the pmap->max boundary works",
    T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ULL,
	    run_sysctl_test("vm_map_protect_pmap_max", 0),
	    "vm_map_protect_at_max");
}
