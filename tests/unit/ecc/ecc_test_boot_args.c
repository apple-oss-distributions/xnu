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

#include <darwintest.h>
#include <kern/ecc_init.h>
#include <kern/ecc.h>
#include <vm/vm_protos.h>

#include "ecc_utils.h"
#include "mocks/osfmk/mock_dt.h"
#include "mocks/osfmk/mock_internal.h"
#include "mocks/osfmk/unit_test_utils.h"

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.ecc_boot_args"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("arm"),
	T_META_OWNER("m_nitenko"),
	T_META_RUN_CONCURRENTLY(true)
	);

/**
 * Macro helper to set the value of "dram-ecc" property.
 *
 * @param dram_ecc_val 0 stands for "ecc not enabled" and 1 is "ecc enabled".
 */
#define SET_DRAM_ECC_DT_VAL(dram_ecc_val)                    \
	uint32_t dram_ecc = dram_ecc_val;                    \
	T_MOCK_SET_CALLBACK(SecureDTGetProperty, int, (const DTEntry entry, const char *propertyName, void const **propertyValue, unsigned int *propertySize), \
	{                                                    \
	        if (strcmp(propertyName, "dram-ecc") == 0) { \
	                *propertyValue = &dram_ecc;          \
	                *propertySize = sizeof(dram_ecc);    \
	                return kSuccess;                     \
	        } else {                                     \
	                return kError;                       \
	        }                                            \
	});

/* Acknowledge any lookup as successful, all tests expect that. */
T_MOCK_SET_PERM_RETVAL(SecureDTLookupEntry, int, kSuccess);

/* Set up our fake mem before every test. */
__attribute__((constructor)) void
ecc_test_init(void)
{
	setup_mem();
}

/**
 * Ensure that -restore ALWAYS disables ECC reporting.
 * It should take precedence over everything else.
 */
T_DECL(boot_arg_restore, "-restore override")
{
	SET_DRAM_ECC_DT_VAL(true);
	T_MOCK_SET_RETVAL(PE_boot_args, char *, "-restore vm_ecc_capable=1");

	T_ASSERT_FALSE(vm_ecc_capable(),
	    "-restore always disables ECC reporting");
}

/**
 * Ensure that vm_ecc_capable=1 marks the system as "ecc capable".
 */
T_DECL(boot_arg_true, "vm_ecc_capable overide")
{
	SET_DRAM_ECC_DT_VAL(false);
	T_MOCK_SET_RETVAL(PE_boot_args, char *, "vm_ecc_capable=1");

	T_ASSERT_TRUE(vm_ecc_capable(), "vm_ecc_capable override (for tests)");
}

/**
 * Ensure that vm_ecc_capable=0 disables ECC handling.
 */
T_DECL(boot_arg_false, "vm_ecc_capable negative overide")
{
	SET_DRAM_ECC_DT_VAL(true);
	T_MOCK_SET_RETVAL(PE_boot_args, char *, "vm_ecc_capable=0");

	T_ASSERT_FALSE(vm_ecc_capable(), "vm_ecc_capable negative override");
}

T_DECL(dt_true, "DT is ECC capable")
{
	SET_DRAM_ECC_DT_VAL(true);

	T_ASSERT_TRUE(vm_ecc_capable(), "DT indicates a capable system");
}

T_DECL(dt_false, "DT is NOT ECC capable")
{
	SET_DRAM_ECC_DT_VAL(false);

	T_ASSERT_FALSE(vm_ecc_capable(), "DT is explicitly not ECC capable");
}

/**
 * Ensure that a completely clean state is not capable.
 */
T_DECL(clean_state, "Clean state with no configuration")
{
	T_MOCK_SET_CALLBACK(SecureDTGetProperty, int, (const DTEntry entry, const char *propertyName, void const **propertyValue, unsigned int *propertySize),
	{
		/* No dram-ecc property */
		return kError;
	});
	/* No boot args */
	T_MOCK_SET_RETVAL(PE_boot_args, char *, "");

	T_ASSERT_FALSE(vm_ecc_capable(),
	    "Clean state should default to not capable");
}

T_DECL(ecc_log_memory_error, "Panic on ECC error reporting with a debug boot-arg set")
{
	T_SETUPBEGIN;
	SET_DRAM_ECC_DT_VAL(true);

	/* The debug boot arg is set. */
	debug_ecc_ue_panic = 1;

	const uint64_t out_of_dram_addr = PAGE_SIZE;
	const uint64_t addr = gDramBase + 5 * GIB;
	T_SETUPEND;

	/* Make sure that functions panic on out-of-DRAM addresses. */
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error(out_of_dram_addr, 0),
		"is out of bounds",
		"ecc_log_memory_error panic on an out-of-DRAM address");
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error_internal(out_of_dram_addr, 0),
		"is out of bounds",
		"ecc_log_memory_error_internal panic on an out-of-DRAM address");
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error_delayed(out_of_dram_addr, 0),
		"is out of bounds",
		"ecc_log_memory_error_delayed panic on an out-of-DRAM address");
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error_ce(out_of_dram_addr, ECC_IS_CORRECTABLE, 10),
		"is out of bounds",
		"ecc_log_memory_error_ce panic on an out-of-DRAM address");

	/* Make sure that functions force-panic on uncorrectable errors. */
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error(addr, 0),
		"ECC UE on physical address",
		"ecc_log_memory_error panic on an UE");
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error_internal(addr, 0),
		"ECC UE on physical address",
		"ecc_log_memory_error_internal panic on an UE");
	T_ASSERT_PANIC_CONTAINS(
		ecc_log_memory_error_delayed(addr, 0),
		"ECC UE on physical address",
		"ecc_log_memory_error_delayed panic on an UE");

	/* But not on corrected errors. */
	ecc_log_memory_error_ce(addr, ECC_IS_CORRECTABLE, 10);
	T_PASS("And corrected error reporting shouldn't panic");
}

T_DECL(zeroization_panic_if_needed, "Panic on zeroization errors with a debug boot-arg set")
{
	T_SETUPBEGIN;

	/* The debug boot arg is set. */
	debug_ecc_ue_panic = 1;

	ecc_carveout_t *carveout;
	size_t carveout_size = create_ecc_carveout(&carveout, 0UL, "");

	uint64_t zero_addrs[] = {
		gDramBase + 5 * GIB,
		gDramBase + 6 * GIB,
		gDramBase + 7 * GIB
	};
	const size_t zero_count = sizeof(zero_addrs) / sizeof(zero_addrs[0]);
	bad_memory_entry_t *zero_errors;
	size_t zero_size =
	    create_zero_errors(&zero_errors, zero_addrs, zero_count);
	T_SETUPEND;

	ecc_zeroization_panic_if_needed();
	T_PASS("No zeroization errors, no panic.");

	/* Now set up some zeroization errors. */
	setup_ecc_dt_mocks(NULL, 0UL, zero_errors, zero_size);

	T_ASSERT_PANIC_CONTAINS(ecc_zeroization_panic_if_needed(),
	    "ECC zeroization failure, zero_pages: 3, address[0]:",
	    "Panic if any zeroization failures are present");
}
