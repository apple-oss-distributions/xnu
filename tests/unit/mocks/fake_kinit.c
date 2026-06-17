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

#include "mocks/fake_kinit.h"
#include <arm/cpu_data_internal.h> // for BootArgs
#include <pexpert/pexpert.h>  // for PE_state
#include <pexpert/boot.h>  // for bootargs
#include <kern/startup.h>  // for kernel_startup_initialize_upto
#include <IOKit/IOLocks.h> // for IOLock
#include <vm/vm_page_internal.h> // for vm_set_page_size
#include <kern/clock.h> // for clock_config
#include <vm/pmap.h>
#include <sys/queue.h> // for TAILQ macros

#include "std_safe.h"
#include "mocks/mock_mem.h"
#include "mocks/osfmk/unit_test_utils.h"


// This define is supposed to come from the .CFLAGS parsing. if it's not, something is wrong with the Makefile
#ifndef __BUILDING_XNU_LIB_UNITTEST__
#error "not building unittest, something is wrong"
#endif


extern void kernel_startup_bootstrap(void);
extern void scale_setup(void);
extern void vm_mem_bootstrap(void);
extern void waitq_bootstrap(void);
// can't include IOKit/IOKitDebug.h since it's a C++ file
extern void IOTrackingInit(void);

extern void kernel_startup_initialize_only(startup_subsystem_id_t sysid);

extern lck_grp_t * IOLockGroup;
extern IOLock * sKextLoggingLock;
extern bitmap_t * asid_bitmap;
extern zone_t pmap_zone;
extern const struct page_table_attr * const native_pt_attr;

void
fake_pmap_init(void)
{
	pmap_zone = zone_create_ext("pmap", sizeof(struct pmap),
	    ZC_ZFREE_CLEARMEM, ZONE_ID_PMAP, NULL);

	static uint64_t asid_bits = 0;
	asid_bitmap = &asid_bits;

	// from pmap_bootstrap()
	kernel_pmap->pmap_pt_attr = native_pt_attr;
}


void
fake_init_bootargs(uint32_t __unused step_id)
{
	// see PE_boot_args()
	static boot_args ba;
	PE_state.bootArgs = &ba;
	PE_state.initialized = TRUE;
	BootArgs = &ba; // arm_init()
}

// This stands in for ml_parse_cpu_topology()
void
fake_cpu_topology(void)
{
	ml_topology_info_t *topo_info = (ml_topology_info_t *)ml_get_topology_info();
	for (int i = 0; i < MAX_CPUS; ++i) {
		topo_info->cpus[i].cluster_type = CLUSTER_TYPE_P;
	}
}

void
fake_kernel_bootstrap(uint32_t __unused step_id)
{
	fake_cpu_topology();
	kernel_startup_bootstrap(); // runs up to STARTUP_SUB_LOCKS

	mem_size = 0x0000000080000000ULL; // 2 GB
	max_mem = mem_size;
	scale_setup();

	vm_set_page_size(); // called from arm_init() -> arm_vm_init()
	vm_mem_bootstrap(); // runs up to STARTUP_SUB_ZALLOC
	// zalloc is now available to use
	fake_pmap_init();
	clock_config();
}


void
fake_iokit_init(uint32_t __unused step_id)
{
	// these are needed for static initializations in iokit to not crash
	IOLockGroup = lck_grp_alloc_init("IOKit", LCK_GRP_ATTR_NULL);
#if IOTRACKING
	IOTrackingInit();
#endif
	sKextLoggingLock = IOLockAlloc();
}

// -------------------- fake_kinit() test-facing API ---------------------

#define MAX_STARTUP_SUB (STARTUP_SUB_EARLY_BOOT + 1)
#define MAX_STEPS_COUNT (100)
struct {
	TAILQ_HEAD(, fki_step) fkp_steps;

	// for every STARTUP_* keep a null-terminated list of function names that should be skipped.
	// This is kept separately from the steps list so that it possible to control any STARTUP_* step.
	const char **fkp_startup_skip_func_names[MAX_STARTUP_SUB];
	bool fkp_edit_allowed;

	// pool of step objects so that we don't need to malloc them
	struct {
		struct fki_step fkpp_pool[MAX_STEPS_COUNT];
		uint32_t fkpp_next_avail;
	} fpk_steps_pool;
} g_fki_plan = {
	.fkp_steps = TAILQ_HEAD_INITIALIZER(g_fki_plan.fkp_steps),
	.fkp_startup_skip_func_names = {},
	.fkp_edit_allowed = true,
};

void
fki_plan_append(fki_step_t new_step)
{
	assert(g_fki_plan.fkp_edit_allowed);
	assert(new_step != NULL);
	TAILQ_INSERT_TAIL(&g_fki_plan.fkp_steps, new_step, fki_link);
}

void
fki_plan_insert_after(fki_step_t after_step, fki_step_t new_step)
{
	assert(g_fki_plan.fkp_edit_allowed);
	assert(new_step != NULL);
	assert(after_step != NULL);
	TAILQ_INSERT_AFTER(&g_fki_plan.fkp_steps, after_step, new_step, fki_link);
}

void
fki_plan_insert_before(fki_step_t before_step, fki_step_t new_step)
{
	assert(g_fki_plan.fkp_edit_allowed);
	assert(new_step != NULL);
	assert(before_step != NULL);
	TAILQ_INSERT_BEFORE(before_step, new_step, fki_link);
}

void
fki_plan_remove(fki_step_t step_to_remove)
{
	assert(g_fki_plan.fkp_edit_allowed);
	assert(step_to_remove != NULL);
	TAILQ_REMOVE(&g_fki_plan.fkp_steps, step_to_remove, fki_link);
}

static fki_step_t
fki_plan_alloc_step(void)
{
	assert3u(g_fki_plan.fpk_steps_pool.fkpp_next_avail, <, MAX_STEPS_COUNT - 1);
	return &g_fki_plan.fpk_steps_pool.fkpp_pool[g_fki_plan.fpk_steps_pool.fkpp_next_avail++];
}

fki_step_t
fki_plan_make_func_step(fki_step_id_t step_id, void (*func)(uint32_t))
{
	fki_step_t step = fki_plan_alloc_step();
	step->fki_step_id = step_id;
	step->fki_func = func;
	return step;
}

fki_step_t
fki_plan_make_startup_step(startup_subsystem_id_t subsys_id)
{
	fki_step_t step = fki_plan_alloc_step();
	step->fki_step_id = FKI_STARTUP_SUB;
	step->fki_subsys_id = subsys_id;
	return step;
}

void
fki_plan_append_func_step(fki_step_id_t step_id, void (*func)(uint32_t))
{
	fki_plan_append(fki_plan_make_func_step(step_id, func));
}

void
fki_plan_append_startup_step(startup_subsystem_id_t subsys_id)
{
	fki_plan_append(fki_plan_make_startup_step(subsys_id));
}

fki_step_t
fki_plan_first_step(void)
{
	return TAILQ_FIRST(&g_fki_plan.fkp_steps);
}

fki_step_t
fki_plan_find_step(bool (^predicate)(fki_step_t step))
{
	fki_step_t step;
	TAILQ_FOREACH(step, &g_fki_plan.fkp_steps, fki_link) {
		if (predicate(step)) {
			return step;
		}
	}
	// failure to find the expected plan step indicate something wrong about the assumptions made by the test
	raw_printf("fake_kinit step not found\n");
	abort();
}

void
_fki_plan_set_startup_skip_func_names(startup_subsystem_id_t subsys_id, const char **skip_func_names)
{
	assert(g_fki_plan.fkp_edit_allowed);
	assert(subsys_id >= 0 && subsys_id < MAX_STARTUP_SUB);
	g_fki_plan.fkp_startup_skip_func_names[subsys_id] = skip_func_names;
}

__attribute__((optnone, noinline)) bool
fki_is_skipped_func_name(startup_subsystem_id_t subsys_id, const char* func_name)
{
	if (subsys_id < 0 || subsys_id >= MAX_STARTUP_SUB) {
		return false;
	}
	const char **skip_funcs_names = g_fki_plan.fkp_startup_skip_func_names[subsys_id];
	if (skip_funcs_names == NULL) {
		return false;
	}
	for (int i = 0; skip_funcs_names[i] != NULL; ++i) {
		if (strcmp(func_name, skip_funcs_names[i]) == 0) {
			return true;
		}
	}
	return false;
}


__attribute__((weak)) void
_fki_edit_plan_hook(void)
{
	// Do nothing. test can override this using FAKE_KINIT_CUSTOMIZE_PLAN().
	// A non-weak symbol in the executable will override this weak symbol.
}

static void
fki_plan_run(void)
{
	fki_step_t step;
	TAILQ_FOREACH(step, &g_fki_plan.fkp_steps, fki_link) {
		if (step->fki_step_id != FKI_STARTUP_SUB) {
			step->fki_func(step->fki_step_id);
		} else {
			kernel_startup_initialize_only(step->fki_subsys_id);
		}
	}
}


// This is the first function that is called before any initialization in libkernel.
// It's made to be first by the order of object files in the linker command line in Makefile
// libdarwintest runs each test-case in a separate processes, so this function will be called
// for in every process started.
__attribute__((constructor)) void
fake_kinit(void)
{
	// setup default plan
	fki_plan_append_func_step(FKI_FUNC_MOCK_MEM, mock_mem_init_all);
	fki_plan_append_func_step(FKI_FUNC_BOOTARGS, fake_init_bootargs);
	fki_plan_append_func_step(FKI_FUNC_BOOTSTRAP, fake_kernel_bootstrap);

	fki_plan_append_func_step(FKI_FUNC_IOKIT, fake_iokit_init);

	fki_plan_append_startup_step(STARTUP_SUB_PERCPU);
	fki_plan_append_startup_step(STARTUP_SUB_MACH_IPC);
	fki_plan_append_startup_step(STARTUP_SUB_SYSCTL);

	// unittests don't support creating submaps in kernel_map
	fki_plan_set_startup_skip_func_names(STARTUP_SUB_MACH_IPC, "ipc_init");
	// kernel map is not maintained in unit-test
	fki_plan_set_startup_skip_func_names(STARTUP_SUB_KMEM, "kmem_range_init");
	// smr not supported in user-mode
	fki_plan_set_startup_skip_func_names(STARTUP_SUB_ZALLOC, "kauth_cred_init");

	// Allow the test code to customize the plan
	_fki_edit_plan_hook();
	g_fki_plan.fkp_edit_allowed = false;

	fki_plan_run();
}
