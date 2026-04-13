/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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
#include <kdp/processor_core_internal.h>
#include <kdp/processor_core.h>
#include <kdp/kdp_core.h>
#include <arm64/monotonic.h>

#include "mocks/osfmk/mock_kdp.h"

#define UT_MODULE osfmk
T_GLOBAL_META(
	T_META_NAMESPACE("xnu.unit.processor_core"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RUN_CONCURRENTLY(false)
	);


static int num_coredumps = 0;
static unsigned int coredump_type_counts[NUM_COREDUMP_TYPES] = {0};

kern_return_t
my_coredump_init(void *refcon, void *context)
{
	processor_core_context *core_context = (processor_core_context *)context;
	kern_coredump_type_t core_type = core_context->core_type;
	num_coredumps++;
	if (core_type < NUM_COREDUMP_TYPES) {
		coredump_type_counts[core_type]++;
	}
	return KERN_SUCCESS;
}

kern_return_t
my_coredump_init_fail(void *refcon, void *context)
{
	processor_core_context *core_context = (processor_core_context *)context;
	kern_coredump_type_t core_type = core_context->core_type;
	num_coredumps++;
	if (core_type < NUM_COREDUMP_TYPES) {
		coredump_type_counts[core_type]++;
	}
	return KERN_FAILURE;
}

kern_return_t
my_coredump_get_summary(void *refcon, core_save_summary_cb callback, void *context)
{
	processor_core_context *core_context = (processor_core_context *)context;
	core_context->core_should_be_skipped = TRUE;

	return KERN_SUCCESS;
}

kern_return_t
my_coredump_save_segment_descriptions(void *refcon, core_save_segment_descriptions_cb callback, void *context)
{
	return KERN_SUCCESS;
}
kern_return_t
my_coredump_save_thread_state(void *refcon, void *buf, core_save_thread_state_cb callback, void *context)
{
	return KERN_SUCCESS;
}

kern_return_t
my_coredump_save_sw_vers_detail(void *refcon, core_save_sw_vers_detail_cb callback, void *context)
{
	return KERN_SUCCESS;
}
kern_return_t
my_coredump_save_segment_data(void *refcon, core_save_segment_data_cb callback, void *context)
{
	return KERN_SUCCESS;
}
kern_return_t
my_coredump_save_note_summary(void *refcon, core_save_note_summary_cb callback, void *context)
{
	return KERN_SUCCESS;
}

kern_return_t
my_coredump_save_note_descriptions(void *refcon, core_save_note_descriptions_cb callback, void *context)
{
	return KERN_SUCCESS;
}

kern_return_t
my_coredump_save_note_data(void *refcon, core_save_note_data_cb callback, void *context)
{
	return KERN_SUCCESS;
}

void
init_core_config(kern_coredump_callback_config *core_config, bool fail_on_init)
{
	if (fail_on_init) {
		core_config->kcc_coredump_init = my_coredump_init_fail;
	} else {
		core_config->kcc_coredump_init = my_coredump_init;
	}
	core_config->kcc_coredump_get_summary = my_coredump_get_summary;
	core_config->kcc_coredump_save_segment_descriptions = my_coredump_save_segment_descriptions;
	core_config->kcc_coredump_save_thread_state = my_coredump_save_thread_state;
	core_config->kcc_coredump_save_sw_vers_detail = my_coredump_save_sw_vers_detail;
	core_config->kcc_coredump_save_segment_data = my_coredump_save_segment_data;
	core_config->kcc_coredump_save_note_summary = my_coredump_save_note_summary;
	core_config->kcc_coredump_save_note_descriptions = my_coredump_save_note_descriptions;
	core_config->kcc_coredump_save_note_data = my_coredump_save_note_data;
}

T_DECL(processor_core_failures, "Test continue-on-fail operation of kern_do_coredump()")
{
	T_MOCK_SET_RETVAL(kern_dump_seek_to_next_file, kern_return_t, KERN_SUCCESS);

	uint64_t last_file_offset = 0;
	not_in_kdp = 0;
	kern_coredump_callback_config core_config = {0};

	init_core_config(&core_config, false);
	kern_register_xnu_coredump_helper(&core_config);

	// Get the coprocessor + userspace cores to fail, and make sure we continue on fail, and return error.
	init_core_config(&core_config, true);

	struct kern_userspace_coredump_context user_ctx = {.task = NULL, .emergency_dump = false };
	kern_register_coredump_helper_internal(2, &core_config, &user_ctx, "coprocessor core", USERSPACE_COREDUMP, true, 0, 0, 0);
	kern_register_coredump_helper_internal(2, &core_config, NULL, "dext core", COPROCESSOR_COREDUMP, true, 0, 0, 0);

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	kern_return_t ret = kern_do_coredump(NULL, KCF_NONE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail");
	T_ASSERT_EQ(num_coredumps, 3, "Number of coredumps attempted (XNU + coprocessor + dext)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 1, "USERSPACE coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	ret = kern_do_coredump(NULL, KCF_ABORT_ON_FAILURE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail");
	T_ASSERT_EQ(num_coredumps, 2, "Number of coredumps attempted (XNU + coprocessor)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 0, "USERSPACE coredump count (should be 0 due to abort)");
}

T_DECL(processor_core_coprocessor_only_failure, "Test coprocessor core failure only")
{
	T_MOCK_SET_RETVAL(kern_dump_seek_to_next_file, kern_return_t, KERN_SUCCESS);

	uint64_t last_file_offset = 0;
	not_in_kdp = 0;
	kern_coredump_callback_config core_config = {0};

	// Register successful XNU core
	init_core_config(&core_config, false);
	kern_register_xnu_coredump_helper(&core_config);

	// Register successful dext core
	struct kern_userspace_coredump_context user_ctx = {.task = NULL, .emergency_dump = false };
	kern_register_coredump_helper_internal(2, &core_config, &user_ctx, "dext core", USERSPACE_COREDUMP, true, 0, 0, 0);

	// Register failing coprocessor core
	init_core_config(&core_config, true);
	kern_register_coredump_helper_internal(2, &core_config, NULL, "coprocessor core", COPROCESSOR_COREDUMP, true, 0, 0, 0);

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	kern_return_t ret = kern_do_coredump(NULL, KCF_NONE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail when coprocessor core fails");
	T_ASSERT_EQ(num_coredumps, 3, "Number of coredumps attempted (XNU + dext + coprocessor)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 1, "USERSPACE coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	ret = kern_do_coredump(NULL, KCF_ABORT_ON_FAILURE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail when coprocessor core fails with abort on failure");
	T_ASSERT_EQ(num_coredumps, 2, "Number of coredumps attempted before abort (XNU + coprocessor)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 0, "USERSPACE coredump count (should be 0 due to abort)");
}

T_DECL(processor_core_dext_only_failure, "Test dext core failure only")
{
	T_MOCK_SET_RETVAL(kern_dump_seek_to_next_file, kern_return_t, KERN_SUCCESS);

	uint64_t last_file_offset = 0;
	not_in_kdp = 0;
	kern_coredump_callback_config core_config = {0};

	// Register successful XNU core
	init_core_config(&core_config, false);
	kern_register_xnu_coredump_helper(&core_config);

	// Register successful coprocessor core
	kern_register_coredump_helper_internal(2, &core_config, NULL, "coprocessor core", COPROCESSOR_COREDUMP, true, 0, 0, 0);

	// Register failing dext core
	init_core_config(&core_config, true);
	struct kern_userspace_coredump_context user_ctx = {.task = NULL, .emergency_dump = false };
	kern_register_coredump_helper_internal(2, &core_config, &user_ctx, "dext core", USERSPACE_COREDUMP, true, 0, 0, 0);

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	kern_return_t ret = kern_do_coredump(NULL, KCF_NONE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail when dext core fails");
	T_ASSERT_EQ(num_coredumps, 3, "Number of coredumps attempted (XNU + coprocessor + dext)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 1, "USERSPACE coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");

	num_coredumps = 0;
	memset(coredump_type_counts, 0, sizeof(coredump_type_counts));
	ret = kern_do_coredump(NULL, KCF_ABORT_ON_FAILURE, 0, &last_file_offset, 0);
	T_ASSERT_NE(ret, KERN_SUCCESS, "kern_do_coredump() should fail when dext core fails with abort on failure");
	T_ASSERT_EQ(num_coredumps, 3, "Number of coredumps attempted (XNU + coprocessor + dext)");
	T_ASSERT_EQ(coredump_type_counts[XNU_COREDUMP], 1, "XNU coredump count");
	T_ASSERT_EQ(coredump_type_counts[USERSPACE_COREDUMP], 1, "USERSPACE coredump count");
	T_ASSERT_EQ(coredump_type_counts[COPROCESSOR_COREDUMP], 1, "COPROCESSOR coredump count");
}
