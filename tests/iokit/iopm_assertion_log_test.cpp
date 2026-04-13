/*
 * Copyright (c) 2025 Apple Computer, Inc. All rights reserved.
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
#include <darwintest_utils.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/pwr_mgt/IOPMPrivate.h>
#include <IOKit/pwr_mgt/IOPMLibDefs.h>
#include <unordered_map>
#include <unordered_set>

// Target property name that must be present
#define REQUIRED_PROPERTY_NAME "com.apple.conclave.AlwaysOnExclaves"

// Target property name for workload attribution test
#define WORKLOAD_ATTRIBUTION_PROPERTY_NAME "LPW(0, 0)"

// Use std::unordered_map for assertion name mappings
using AssertionNameMap = std::unordered_map<uint64_t, std::string>;
using AssertionNameSet = std::unordered_set<std::string>;

// Define ARRAY_LEN macro for calculating array sizes
#define ARRAY_LEN(x) (sizeof (x) / sizeof (x[0]))


// etrctl test constants
#define ETRCTL_PATH "/usr/appleinternal/bin/etrctl"
#define AOE_PRODUCER_TEST_COMPONENT "AlwaysOnExclavesProducerTestComponent"
#define EXCLAVE_PM_TEST_COMPONENT "ExclavePowerManagementTestComponent"

// launchctl constants
#define LAUNCHCTL_PATH "/bin/launchctl"
#define AOE_DAEMON_SERVICE "system/com.apple.alwaysonexclavesd"


T_GLOBAL_META(
	T_META_NAMESPACE("xnu.iokit"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IOKit")
	);

// Function to launch the alwaysonexclavesd daemon
static void
launch_aoe_daemon(void)
{
	pid_t child_pid = -1;
	char *launch_tool_args[] = {
		(char *)LAUNCHCTL_PATH,
		(char *)"kickstart",
		(char *)AOE_DAEMON_SERVICE,
		NULL
	};

	T_LOG("Launching alwaysonexclavesd daemon");
	int ret = dt_launch_tool(&child_pid, launch_tool_args, false, NULL, NULL);
	T_WITH_ERRNO; T_EXPECT_EQ(ret, 0, "dt_launch_tool(\"" LAUNCHCTL_PATH " kickstart " AOE_DAEMON_SERVICE "\") should succeed");

	int exit_status = 0, signum = 0;
	ret = dt_waitpid(child_pid, &exit_status, &signum, 30);
	T_QUIET; T_EXPECT_EQ(ret, 1, "dt_waitpid() on " LAUNCHCTL_PATH);
	T_EXPECT_EQ(exit_status, 0, "launchctl should successfully run");
	T_QUIET; T_EXPECT_EQ(signum, 0, "launchctl shouldn't get a signal");
}

// Function to run etrctl with specified component
static void
run_etrctl_test(const char *component, const char *description)
{
	pid_t child_pid = -1;
	char *launch_tool_args[] = {
		(char *)ETRCTL_PATH,
		(char *)"run",
		(char *)"-c",
		(char *)component,
		NULL
	};

	T_LOG("Running %s", description);
	int ret = dt_launch_tool(&child_pid, launch_tool_args, false, NULL, NULL);
	T_WITH_ERRNO; T_EXPECT_EQ(ret, 0, "dt_launch_tool(\"" ETRCTL_PATH " run -c %s\") should succeed", component);

	int exit_status = 0, signum = 0;
	ret = dt_waitpid(child_pid, &exit_status, &signum, 60);
	T_QUIET; T_EXPECT_EQ(ret, 1, "dt_waitpid() on " ETRCTL_PATH);
	T_EXPECT_EQ(exit_status, 0, "etrctl should successfully run");
	T_QUIET; T_EXPECT_EQ(signum, 0, "etrctl shouldn't get a signal");
}

// Function to retrieve power management assertion log data
static void
retrieve_assertion_log_data(IOPMAssertionLogData *log)
{
	// Find the power management service
	io_connect_t service = IOPMFindPowerManagement(MACH_PORT_NULL);
	T_ASSERT_NE(service, MACH_PORT_NULL, "IOPMFindPowerManagement should return valid service");

	size_t logSize = sizeof(*log);

	// Call the IOConnect method to get assertion log data
	kern_return_t kr = IOConnectCallStructMethod(service, kPMGetAssertionLog, NULL, 0, log, &logSize);
	T_ASSERT_EQ(kr, KERN_SUCCESS, "IOConnectCallStructMethod should succeed");

	// Determine dynamic array sizes
	const size_t props_array_len = ARRAY_LEN(log->props);
	const size_t intervals_array_len = ARRAY_LEN(log->intervals);

	T_LOG("Retrieved assertion log data:");
	T_LOG("Properties position: %llu, Properties array length: %zu", log->props_pos, props_array_len);
	T_LOG("Intervals position: %llu, Intervals array length: %zu", log->intervals_pos, intervals_array_len);

	// Clean up
	IOServiceClose(service);
}

// Function to process properties and build name mapping
static std::pair<AssertionNameMap, AssertionNameSet>
process_properties(const IOPMAssertionLogData *log)
{
	const size_t props_array_len = ARRAY_LEN(log->props);
	size_t props_pos_read = (log->props_pos > props_array_len) ? (log->props_pos - props_array_len) : 0;

	T_LOG("Reading properties from position %zu to %llu", props_pos_read, log->props_pos);

	AssertionNameMap nameMap;
	AssertionNameSet nameSet;
	for (; props_pos_read < log->props_pos; props_pos_read++) {
		size_t idx = props_pos_read % props_array_len;
		uint64_t id = log->props[idx].id;
		std::string name(log->props[idx].name);
		nameMap[id] = name;
		nameSet.insert(name);
		T_LOG("Property: ID=%llu, Name='%s'", id, name.c_str());
	}

	return std::make_pair(nameMap, nameSet);
}


// Function to process intervals and display timing information
static void
process_intervals(const IOPMAssertionLogData *log, const AssertionNameMap &nameMap)
{
	const size_t intervals_array_len = ARRAY_LEN(log->intervals);
	size_t intervals_pos_read = (log->intervals_pos > intervals_array_len) ? (log->intervals_pos - intervals_array_len) : 0;

	T_LOG("Reading intervals from position %zu to %llu", intervals_pos_read, log->intervals_pos);
	size_t interval_count = 0;

	for (; intervals_pos_read < log->intervals_pos; intervals_pos_read++) {
		size_t idx = intervals_pos_read % intervals_array_len;
		uint64_t interval_id = log->intervals[idx].id;
		uint64_t create_timestamp = log->intervals[idx].create_timestamp;
		uint64_t delete_timestamp = log->intervals[idx].delete_timestamp;

		// Look up the name for this assertion ID
		auto it = nameMap.find(interval_id);
		const char *name = (it != nameMap.end()) ? it->second.c_str() : "Unknown";

		// Calculate duration in milliseconds
		double duration_ms = (double)(delete_timestamp - create_timestamp) / 24.0e3;
		T_LOG("Interval %zu: ID=%llu (%s): %llu -> %llu (%.3f ms)",
		    interval_count, interval_id, name, create_timestamp, delete_timestamp, duration_ms);

		interval_count++;
	}

	T_LOG("Total intervals processed: %zu", interval_count);
}

// Function to validate assertion log data
static void
validate_assertion_log(const IOPMAssertionLogData *log, bool found_required_property, const AssertionNameMap &nameMap)
{
	const size_t props_array_len = ARRAY_LEN(log->props);
	const size_t intervals_array_len = ARRAY_LEN(log->intervals);

	T_LOG("Total properties processed: %zu", nameMap.size());

	// Basic validation tests
	T_ASSERT_GT(props_array_len, 0UL, "Properties array should have non-zero length");
	T_ASSERT_GT(intervals_array_len, 0UL, "Intervals array should have non-zero length");
	T_ASSERT_GE(log->props_pos, 0ULL, "Properties position should be non-negative");
	T_ASSERT_GE(log->intervals_pos, 0ULL, "Intervals position should be non-negative");

	// Fail the test if the required property is not found
	T_ASSERT_TRUE(found_required_property,
	    "Required property '%s' must be present in power management assertion log",
	    REQUIRED_PROPERTY_NAME);
}

T_DECL(iopm_assertion_log_test, "Test IOPMAssertionLogData retrieval and parsing AOE assertion",
    T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_status", 1),
    T_META_ENABLED(TARGET_OS_IOS)
    )
{
	// Launch the alwaysonexclavesd daemon first
	launch_aoe_daemon();

	// Run the AOE Producer test to trigger the AlwaysOnExclaves assertion
	run_etrctl_test(AOE_PRODUCER_TEST_COMPONENT, "AOE Producer test to trigger AlwaysOnExclaves assertion");

	// Retrieve power management assertion log data
	IOPMAssertionLogData log;
	retrieve_assertion_log_data(&log);

	// Process properties and build name mapping
	auto result = process_properties(&log);
	AssertionNameMap nameMap = result.first;
	AssertionNameSet nameSet = result.second;
	bool found_required_property = nameSet.count(REQUIRED_PROPERTY_NAME) != 0;

	// Process intervals and display timing information
	process_intervals(&log, nameMap);

	// Validate the assertion log data
	validate_assertion_log(&log, found_required_property, nameMap);

	T_PASS("IOPMAssertionLogData test completed successfully - found AlwaysOnExclaves assertion");
}

T_DECL(lpw_workload_attribution_test, "Test workload attribution with ExclavePowerManagementTestComponent",
    T_META_REQUIRES_SYSCTL_EQ("kern.exclaves_status", 1),
    T_META_ENABLED(TARGET_OS_IOS)
    )
{
	// Run the Exclave Power Management test
	run_etrctl_test(EXCLAVE_PM_TEST_COMPONENT, "Exclave Power Management test for workload attribution");

	// Retrieve power management assertion log data
	IOPMAssertionLogData log;
	retrieve_assertion_log_data(&log);

	// Process properties and build name mapping
	auto result = process_properties(&log);
	AssertionNameMap nameMap = result.first;
	AssertionNameSet nameSet = result.second;
	bool found_workload_attribution_property = nameSet.count(WORKLOAD_ATTRIBUTION_PROPERTY_NAME) != 0;

	T_LOG("Workload attribution test - Properties found:");
	for (const auto& pair : nameMap) {
		T_LOG("  ID=%llu, Name='%s'", pair.first, pair.second.c_str());
	}

	// Process intervals and display timing information
	process_intervals(&log, nameMap);

	// Validate that the workload attribution property was found
	T_ASSERT_TRUE(found_workload_attribution_property,
	    "Required workload attribution property '%s' must be present in power management assertion log",
	    WORKLOAD_ATTRIBUTION_PROPERTY_NAME);

	T_PASS("Workload attribution test completed successfully - found LPW property");
}
