/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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
#include "mocks/osfmk/unit_test_utils.h"
#include "mocks/osfmk/mock_pmap.h"

#include <kdp/output_stages/output_stages.h>
#include <kdp/kdp_core.h>
#include <vm/pmap.h>
#include <arm/pmap_public.h>
#include <sys/queue.h>

#define UT_MODULE osfmk

kern_return_t
memory_backing_aware_buffer_stage_outproc(
	struct kdp_output_stage *stage,
	unsigned int request,
	char *corename,
	uint64_t length,
	void * panic_data);

static kern_return_t
kosf_outproc_mock(
	__unused struct kdp_output_stage *stage,
	__unused unsigned int request,
	__unused char *corename,
	__unused uint64_t length,
	__unused void *panic_data
	)
{
	return KERN_SUCCESS;
}

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.panic_path_test"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("debugging"),
	T_META_OWNER("e_zisman"),
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(xnu_osfmk_kdp_memory_backing_aware_buffer_stage_outproc, "memory_backing_aware_buffer_stage_outproc")
{
	// No need to actually fill with data.
	char panic_data[18 * 1024] __attribute__((aligned));

	STAILQ_HEAD(, kdp_output_stage) stages;
	struct kdp_output_stage stage1;
	struct kdp_output_stage stage2;
	char data1[32];
	char data2[32];

	stage1.kos_data = data1;
	stage2.kos_data = data2;
	stage1.kos_funcs.kosf_outproc = kosf_outproc_mock;
	stage2.kos_funcs.kosf_outproc = kosf_outproc_mock;

	STAILQ_INIT(&stages);
	STAILQ_INSERT_HEAD(&stages, &stage1, kos_next);
	STAILQ_INSERT_TAIL(&stages, &stage2, kos_next);

	struct {
		char *test_name;
		unsigned int pmap_cache_attributes_retval;
		size_t panic_data_length;
		kern_return_t expected;
	} test_cases[] = {
		{
			.test_name = "normal memory flow",
			.pmap_cache_attributes_retval = 0x02, // VM_WIMG_DEFAULT
			.panic_data_length = sizeof(panic_data),
			.expected = KERN_SUCCESS
		},
		{
			.test_name = "not-normal memory flow, 4-byte reads",
			.pmap_cache_attributes_retval = 0x00,
			.panic_data_length = sizeof(panic_data),
			.expected = KERN_SUCCESS
		},
		{
			.test_name = "not-normal memory flow, 1-byte reads",
			.pmap_cache_attributes_retval = 0x00,
			.panic_data_length = sizeof(panic_data) - 1, // ensure length of panic data is not aligned to 4 bytes.
			.expected = KERN_SUCCESS
		},
	};

	T_MOCK_SET_RETVAL(kvtophys, pmap_paddr_t, 0x12345678); // arbitrary value; isn't used anyways since we mock pmap_cache_attributes.

	for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
		T_MOCK_SET_RETVAL(pmap_cache_attributes, unsigned int, test_cases[i].pmap_cache_attributes_retval);

		T_EXPECT_EQ(
			test_cases[i].expected,
			memory_backing_aware_buffer_stage_outproc(&stage1, KDP_DATA, "corename", sizeof(panic_data), panic_data),
			"return value matches expectation"
			);
	}
}
