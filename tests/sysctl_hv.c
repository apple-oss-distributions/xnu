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
#include <stdlib.h>
#include <sys/sysctl.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.arm"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("simon_ho"),
	T_META_RUN_CONCURRENTLY(true)
	);

/*
 * Helper function to read a signed integer value from a sysctl oid.
 * Returns the sentinel value if the sysctl is not found.
 * Note that many sysctls return a sentinel value (e.g. 0) on failures,
 * so caller can check if the return value matches the sentinel value to detect failures.
 *
 * @param name Sysctl name
 * @param sentinel_val Return this value if the sysctl value is not found.
 *
 * @return Return the sysctl value.
 */
static int
read_sysctl_int_with_default(const char *name, int sentinel_val)
{
	int val;
	size_t val_size = sizeof(val);
	if (sysctlbyname(name, &val, &val_size, NULL, 0) != 0) {
		return sentinel_val;
	}
	return val;
}

/*
 * Helper function to read a 32-bit unsigned integer value from a sysctl oid.
 * Returns the sentinel value if the sysctl is not found.
 * Note that many sysctls return a sentinel value (e.g. 0) on failures,
 * so caller can check if the return value matches the sentinel value to detect failures.
 *
 * @param name Sysctl name
 * @param sentinel_val Return this value if the sysctl value is not found.
 *
 * @return Return the sysctl value.
 */
static uint32_t
read_sysctl_u32_with_default(const char *name, uint32_t sentinel_val)
{
	uint32_t val;
	size_t val_size = sizeof(val);
	if (sysctlbyname(name, &val, &val_size, NULL, 0) != 0) {
		return sentinel_val;
	}
	return val;
}

/*
 * Helper function to read a 64-bit unsigned integer value from a sysctl oid.
 * Returns the sentinel value if the sysctl is not found.
 * Note that many sysctls return a sentinel value (e.g. 0) on failures,
 * so caller can check if the return value matches the sentinel value to detect failures.
 *
 * @param name Sysctl name
 * @param sentinel_val Return this value if the sysctl value is not found.
 *
 * @return Return the sysctl value.
 */
static uint64_t
read_sysctl_u64_with_default(const char *name, uint64_t sentinel_val)
{
	uint64_t val;
	size_t val_size = sizeof(val);
	if (sysctlbyname(name, &val, &val_size, NULL, 0) != 0) {
		return sentinel_val;
	}
	return val;
}

/*
 * Helper function to read a value from a sysctl oid and assert on failure.
 *
 * @param name Sysctl name
 * @param data Out pointer to sysctl data
 * @param data_size Syscal data size
 */
static void
read_sysctl_or_fail(const char *name, void *data, size_t data_size)
{
	int result = sysctlbyname(name, data, &data_size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(result, "Ensure %s can be read", name);
}

// Verify a number of hypervisor sysctls.
T_DECL(hv_sysctl, "Verify hypervisor sysctl")
{
	// Check for Hypervisor support using both old and new sysctl names.
	int hv_supported = read_sysctl_int_with_default("kern.hv.supported", 0);
	int hv_supported_alternate = read_sysctl_int_with_default("kern.hv_support", 0);
	T_ASSERT_EQ_INT(hv_supported, hv_supported_alternate,
	    "kern.hv.supported and kern.hv_support should be consistent");

	int vmm_present;
	read_sysctl_or_fail("kern.hv_vmm_present", &vmm_present, sizeof(vmm_present));

	if (hv_supported) {
		int hv_disable;
		read_sysctl_or_fail("kern.hv_disable", &hv_disable, sizeof(hv_disable));
		T_ASSERT_EQ_INT(hv_disable, 0, "Ensure hypervisor is not disabled.");

		uint32_t max_address_spaces;
		read_sysctl_or_fail("kern.hv.max_address_spaces", &max_address_spaces, sizeof(max_address_spaces));
		T_ASSERT_GE_UINT(max_address_spaces, 128, "Ensure max_address_spaces is valid");

		uint64_t ipa_size_16k;
		read_sysctl_or_fail("kern.hv.ipa_size_16k", &ipa_size_16k, sizeof(ipa_size_16k));
		T_ASSERT_GE_ULLONG(ipa_size_16k, 1ULL << 30, "Ensure ipa_size_16k is valid.");

		uint64_t ipa_size_4k;
		// 4K granule support is optional, so just check the sysctl exists.
		read_sysctl_or_fail("kern.hv.ipa_size_4k", &ipa_size_4k, sizeof(ipa_size_4k));
	} else {
		// These sysctls may or may not return valid values when hypervisor is supported.
		// These sysctls are exercised to ensure they do not crash.
		read_sysctl_int_with_default("kern.hv_disable", 0);
		read_sysctl_u32_with_default("kern.hv.max_address_spaces", 0);
		read_sysctl_u64_with_default("kern.hv.ipa_size_16k", 0);
		read_sysctl_u64_with_default("kern.hv.ipa_size_4k", 0);
	}

	const char *hypercall_sysctls[] = {
		"kern.hv.hc_get_bootsessionuuid",
		"kern.hv.hc_get_mabs_offset",
		"kern.hv.hc_vcpu_wfk",
		"kern.hv.hc_vcpu_kick",
	};
	for (size_t i = 0; i < sizeof(hypercall_sysctls) / sizeof(hypercall_sysctls[0]); ++i) {
		if (hv_supported & !vmm_present) {
			// These sysctls should succeed.
			int hc_val;
			read_sysctl_or_fail(hypercall_sysctls[i], &hc_val, sizeof(hc_val));
		} else {
			// These sysctls may or may not return valid values.
			// These sysctls are exercised to ensure they do not crash.
			read_sysctl_int_with_default(hypercall_sysctls[i], 0);
		}
	}

	if (vmm_present) {
		uint64_t guest_mabs_offset;
		read_sysctl_or_fail("kern.hvg.mabs_offset", &guest_mabs_offset, sizeof(guest_mabs_offset));
	} else {
		// This sysctl may or may not return a valid value.
		// This sysctl is exercised to ensure it does not crash.
		read_sysctl_u64_with_default("kern.hvg.mabs_offset", 0);
	}

	size_t host_bootsessionuuid_size;
	int result = sysctlbyname("kern.hvg.host_bootsessionuuid", NULL, &host_bootsessionuuid_size, NULL, 0);
	bool host_bootsessionuuid_is_valid = (result == 0 && host_bootsessionuuid_size > 0);
	if (vmm_present) {
		T_ASSERT_TRUE(host_bootsessionuuid_is_valid, "Ensure kern.hvg.host_bootsessionuuid is valid");
	}
}
