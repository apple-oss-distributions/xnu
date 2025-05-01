#include <sys/sysctl.h>
#include <signal.h>
#include <darwintest.h>
#include <darwintest_utils.h>

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

T_DECL(vm_map_non_aligned,
    "Test that we can destroy map unaligned mappings (rdar://88969652)",
    T_META_TAG_VM_PREFERRED)
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_map_non_aligned", 0), "vm_map_non_aligned");
}

T_DECL(vm_map_null,
    "Test that we can call vm_map functions with VM_MAP_NULL",
    T_META_TAG_VM_PREFERRED)
{
	int64_t result = run_sysctl_test("vm_map_null", 0);
	T_EXPECT_EQ(1ull, result, "vm_map_null");
}

T_DECL(vm_memory_entry_pgz,
    "Test that we can make a memory entry of a pgz protected allocation (rdar://122836976)",
    T_META_TAG_VM_PREFERRED)
{
	int64_t result = run_sysctl_test("vm_memory_entry_pgz", 0);
	if (result == 2) {
		T_SKIP("Unable to pgz_protect allocation. Pgz slots might be full.");
	}
	T_EXPECT_EQ(1ull, result, "vm_memory_entry_pgz");
}

T_DECL(vm_map_copy_entry_subrange,
    "Test mapping a subrange of a copy entry")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_map_copy_entry_subrange", 0), "vm_map_copy_entry_subrange");
}

T_DECL(vm_memory_entry_map_size_null,
    "Test mach_memory_entry_map_size with NULL memory entry")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_memory_entry_map_size_null", 0), "vm_memory_entry_map_size_null");
}


T_DECL(vm_memory_entry_map_size_overflow,
    "Test overflow cases in mach_memory_entry_map_size sanitization")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_memory_entry_map_size_overflow", 0), "vm_memory_entry_map_size_overflow");
}

T_DECL(vm_memory_entry_map_size_copy,
    "Test mach_memory_entry_map_size with copy memory entries and 4k/16k combinations")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_memory_entry_map_size_copy", 0), "vm_memory_entry_map_size_copy");
}

T_DECL(vm_memory_entry_parent_submap,
    "Test mach_make_memory_entry cases where parent is a submap")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_memory_entry_parent_submap", 0), "vm_memory_entry_parent_submap");
}

#ifndef __x86_64__
T_DECL(vm_page_radix_verify, "verify the vm pages radix tree")
{
	T_EXPECT_EQ(1ull, run_sysctl_test("vm_page_radix_verify", 0), "vm_page_radix_verify");
}
#endif
