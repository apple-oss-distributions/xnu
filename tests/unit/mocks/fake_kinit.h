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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h> // for TAILQ macros
#include <kern/startup.h>

__BEGIN_DECLS

/**
 * fake_kinit() editing
 *
 * fake_kinit() contains the first code that run on a test-executable startup.
 * It runs before libdarwintest main() and before any XNU globals initialization.
 * The goal of this function is to bootstrap and initialize enough of XNU that the global
 * variables in XNU are able to initialize correctly.
 * A test can add its own code to be executed in fake_kinit and it can also edit and customize
 * its default behaviour.
 *
 * XNU initialization starts from arm_init() and occasionally calls
 * kernel_startup_initialize_upto() to run functions registered using the STARTUP() macro
 * fake_kinit() also needs to call some of these functions explicitly. These functions
 * are identified by their subsystem - STARTUP_SUB_* enum, and their name (char*)
 *
 * fake_kinit() follows 3 stages
 * 1. Create a default kinit plan.
 * 2. Allow the code in the test-executable to customize that plan.
 * 3. Execute the plan.
 *
 * The kinit plan is made of individual steps. A step can be either
 * - A call to a function. Such functions may end up calling kernel_startup_initialize_upto()
 *   to run STARTUP() functions.
 *   such steps are identified by their step_id.
 * - A call to kernel_startup_initialize_only() to run all the STARTUP() for a subsystem.
 *   such steps are identified by step_id == FKI_STARTUP_SUB and their subsys_id.
 *   A subsys_id can't appear more than once in the plan.
 * The kinit plan can also specify that some STARTUP() functions need to be skipped.
 * This is needed if we want just some of the functions that are registered for some subsystem.
 *
 * A test that wants to customize the kinit plan should use FAKE_KINIT_CUSTOMIZE_PLAN()
 * to define a function that uses the following fki_* API to make edits to the
 * default plan.
 * This would typically look like finding a step in the default plan, adding a step after
 * it or deleting it. It can also modify the STARTUP() functions that should be skipped.
 *
 * When making such edits, please refer to fake_kinit() for the default plan.
 * and arm_init() for the correct order initialization occur in.
 * This API should only be used in the kinit customization function, not in any T_DECL()
 *
 * Example:
 *     static void
 *     my_kinit_added_step(uint32_t step_id) {
 *         ...
 *     }
 *     FAKE_KINIT_CUSTOMIZE_PLAN() {
 *         fki_step_t bs_step = fki_plan_find_step(^bool(fki_step_t s) {
 *                              return s->fki_step_id == FKI_FUNC_BOOTSTRAP;
 *         });
 *         fki_plan_insert_after(bs_step, fki_plan_make_func_step(FKI_USER_STEP + 1, my_kinit_added_step));
 *
 *         fki_plan_set_startup_skip_func_names(STARTUP_SUB_MACH_IPC, NULL);
 *     }
 */

 #define FAKE_KINIT_CUSTOMIZE_PLAN() \
	void _fki_edit_plan_hook(void)

__enum_decl(fki_step_id_t, uint32_t, {
	FKI_FUNC_MOCK_MEM = 0,
	FKI_FUNC_BOOTARGS,
	FKI_FUNC_BOOTSTRAP,
	FKI_FUNC_IOKIT,
	FKI_STARTUP_SUB = 99,
	FKI_USER_STEP = 100  // test-specific steps should start from this value
});

typedef struct fki_step {
	fki_step_id_t fki_step_id;
	union {
		// in case step_id is FKI_FUNC_*, the step runs this function
		void (*fki_func)(uint32_t);
		// in case step_id is FKI_STARTUP_SUB, the step runs kernel_startup_initialize_only() with this argument
		startup_subsystem_id_t fki_subsys_id;
	};
	TAILQ_ENTRY(fki_step) fki_link;
} *fki_step_t;

extern void fki_plan_append(fki_step_t step);
extern void fki_plan_insert_after(fki_step_t after_step, fki_step_t new_step);
extern void fki_plan_insert_before(fki_step_t before_step, fki_step_t new_step);
extern void fki_plan_remove(fki_step_t step_to_remove);

extern fki_step_t fki_plan_make_func_step(fki_step_id_t step_id, void (*func)(uint32_t));
extern fki_step_t fki_plan_make_startup_step(startup_subsystem_id_t subsys_id);

// convenience functins for doing fki_plan_append(fki_plan_make_*(...))
extern void fki_plan_append_func_step(fki_step_id_t step_id, void (*func)(uint32_t));
extern void fki_plan_append_startup_step(startup_subsystem_id_t subsys_id);

extern void _fki_plan_set_startup_skip_func_names(startup_subsystem_id_t subsys_id, const char **skip_func_names);

// This macro give a convenient syntax for passing a list of strings
#define fki_plan_set_startup_skip_func_names(subsys_id, ...) \
	_fki_plan_set_startup_skip_func_names((subsys_id), (const char*[]){__VA_ARGS__ __VA_OPT__(,) NULL})

extern fki_step_t fki_plan_first_step(void);
extern fki_step_t fki_plan_find_step(bool (^predicate)(fki_step_t step));

extern bool fki_is_skipped_func_name(startup_subsystem_id_t subsys_id, const char* func_name);

__END_DECLS
