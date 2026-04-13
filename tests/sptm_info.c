#include <sys/sysctl.h>
#include <darwintest.h>
#include <perfdata/perfdata.h>
#include "test_utils.h"

#define KERNEL_PRIVATE 1

#include <sptm/sptm_xnu.h>

/**
 * @file
 * @brief Perfdata tests for SPTM I/O ranges.
 *
 * This test collects perfdata for the various SPTM I/O ranges exposed by
 * kernel sysctls. The collected data includes the index, address, length,
 * and frame type for each I/O range.
 *
 * This data is useful for security review and regression testing allowing
 * for tracking changes to these I/O ranges across different builds and
 * hardware platforms.
 */

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("sai_ranjan"),
	T_META_ASROOT(true),
	T_META_TAG_PERF);

/**
 * @brief Helper function to run a perfdata collection test for a given set of
 *        SPTM I/O range sysctls.
 *
 * @param count_sysctl The name of the sysctl that provides the count of ranges.
 * @param range_sysctl The name of the sysctl that provides a range by index.
 * @param pd_name The name to use for the perfdata file.
 * @param metric_name The name to use for the primary metric in the perfdata file.
 * @param log_prefix A short string to use in log messages (e.g., "Allowed", "Pmap").
 */
static void
run_sptm_perfdata_test(const char *count_sysctl, const char *range_sysctl,
    const char *pd_name, const char *metric_name, const char *log_prefix)
{
	int ret;
	unsigned int count = 0;
	size_t size = sizeof(count);

	ret = sysctlbyname(count_sysctl, &count, &size, NULL, 0);
	if (ret != 0) {
		T_SKIP("Sysctl '%s' not found", count_sysctl);
	}

	T_ASSERT_POSIX_SUCCESS(ret, "sysctlbyname %s", count_sysctl);
	T_LOG("Found %u SPTM %s I/O ranges", count, log_prefix);

	if (count == 0) {
		T_SKIP("No SPTM %s I/O ranges to report", log_prefix);
	}

	char pd_path[PATH_MAX] = "";
	pdwriter_t writer = pdwriter_open_tmp("xnu", pd_name, 0, 0, pd_path, sizeof(pd_path));
	T_ASSERT_NOTNULL(writer, "pdwriter_open_tmp");

	char addr_buf[32];
	for (unsigned int i = 0; i < count; i++) {
		sptm_io_range_t io_range;
		size_t range_size = sizeof(io_range);
		unsigned int index = i;

		ret = sysctlbyname(range_sysctl, &io_range, &range_size, &index, sizeof(index));
		if (ret != 0) {
			T_FAIL("sysctlbyname %s for index %u failed", range_sysctl, i);
		}

		T_LOG("SPTM %s IO Range %u: addr=0x%llx, len=0x%zx, frame_type=%u", log_prefix, i,
		    io_range.addr, io_range.len, io_range.type);

		/* Record the address as the primary metric. */
		pdwriter_new_value(writer, metric_name, PDUNIT_CUSTOM(phys_addr), (double)io_range.addr);

		/* Attach the other data as variables to this metric. */
		snprintf(addr_buf, sizeof(addr_buf), "0x%llx", io_range.addr);
		pdwriter_record_variable_str(writer, "addr", addr_buf);
		pdwriter_record_label_dbl(writer, "index", (double)i);
		pdwriter_record_variable_dbl(writer, "len", (double)io_range.len);
		pdwriter_record_variable_dbl(writer, "frame_type", (double)io_range.type);
	}

	pdwriter_close(writer);
	T_PASS("Successfully collected and wrote %u %s I/O ranges to %s", count, log_prefix, pd_path);
}

T_DECL(sptm_allowed_io_ranges_perfdata,
    "Collect SPTM Allowed I/O ranges into perfdata format",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1),
    XNU_T_META_SOC_SPECIFIC, T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_sptm_perfdata_test("kern.sptm_allowed_io_ranges_count",
	    "kern.sptm_allowed_io_ranges",
	    "sptm_allowed_io_ranges",
	    "allowed_io_range_addr",
	    "Allowed");
}

T_DECL(sptm_pmap_io_ranges_perfdata,
    "Collect SPTM Pmap I/O ranges into perfdata format",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1),
    XNU_T_META_SOC_SPECIFIC, T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_sptm_perfdata_test("kern.sptm_pmap_io_ranges_count",
	    "kern.sptm_pmap_io_ranges",
	    "sptm_pmap_io_ranges",
	    "pmap_io_range_addr",
	    "Pmap");
}

T_DECL(sptm_io_ranges_perfdata,
    "Collect SPTM Generic I/O ranges into perfdata format",
    T_META_REQUIRES_SYSCTL_EQ("kern.page_protection_type", 2),
    T_META_REQUIRES_SYSCTL_EQ("kern.development", 1),
    XNU_T_META_SOC_SPECIFIC, T_META_TAG_VM_NOT_ELIGIBLE)
{
	run_sptm_perfdata_test("kern.sptm_io_ranges_count",
	    "kern.sptm_io_ranges",
	    "sptm_io_ranges",
	    "io_range_addr",
	    "Generic");
}
