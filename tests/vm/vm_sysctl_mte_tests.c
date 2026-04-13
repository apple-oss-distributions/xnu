#include <sys/sysctl.h>
#include <darwintest.h>
#include <darwintest_utils.h>

#include "test_utils.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("VM"),
	T_META_ASROOT(YES),
	T_META_RUN_CONCURRENTLY(true));

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

T_DECL(vm_map_id_fork,
    "Ensure fork() maps witness a new ID",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_id_fork", 0), "vm_map_id_fork");
}

T_DECL(vm_map_alias_mte_mapping_in_other_non_mte_map,
    "Ensure an MTE mapping aliased into another non-MTE map is mapped as non-MTE, and roundtrips back to the originator are mapped as MTE",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_alias_mte_mapping_in_other_non_mte_map", 0), "vm_map_alias_mte_mapping_in_other_non_mte_map");
}

T_DECL(vm_map_alias_mte_mapping_in_other_mte_map,
    "Ensure an MTE mapping aliased into another MTE map is mapped as non-MTE, and roundtrips back to the originator are mapped as MTE",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_alias_mte_mapping_in_other_mte_map", 0), "vm_map_alias_mte_mapping_in_other_mte_map");
}

T_DECL(vm_map_alias_mte_mapping_in_fork_map,
    "Ensure MTE mappings shared across fork pairs are MTE enabled in every case",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_map_alias_mte_mapping_in_fork_map", 0), "vm_map_alias_mte_mapping_in_fork_map");
}

T_DECL(vm_transpose_provenance,
    "Ensure VM objects that are transposed have their serials transposed",
    T_META_REQUIRES_SYSCTL_EQ("kern.is_mte_enabled", 1),
    XNU_T_META_SOC_SPECIFIC)
{
	T_EXPECT_EQ(1ULL, run_sysctl_test("vm_object_transpose_provenance", 0), "vm_object_transpose_provenance");
}
