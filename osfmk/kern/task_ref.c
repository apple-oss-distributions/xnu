/*
 * C (c) 2000-2020 Apple Inc. All rights reserved.
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

#include <kern/task.h>
#include <kern/task_ref.h>
#include <libkern/OSKextLibPrivate.h>

#include <os/refcnt.h>

/*
 * Task references.
 *
 * Each task reference/deallocate pair has an associated reference group:
 *     TASK_GRP_INTERNAL This group is used exclusively to track long-term
 *                       references which are almost always present.
 *                       Specifically, the importance task reference, the owning
 *                       task reference and the thread references.
 *     TASK_GRP_EXTERNAL For kext references
 *     TASK_KERNEL       For at-large kernel references other than those tracked
 *                       by task_internal.
 *     TASK_GRP_MIG      For references from the MIG layer
 *
 * Depending on configuration (see task_refgrp_config) os_refgrps are used to
 * keep track of the context of the reference/deallocation.
 *
 * TASK_REF_CONFIG_OFF
 * No refgrps are used other than the single 'task' reference group.
 *
 * TASK_REF_CONFIG_DEFAULT
 * Global refgrps are used for 'kernel' and 'external' references. The
 * primary 'task' reference group is set as their parent. Each kext also gets
 * its own refgrp parented to the 'external' group.
 * Each task gets two reference groups - one for 'kernel' references parented to
 * the global 'kernel' group and as second which is dynamically assigned. All
 * references tagged with TASK_GRP_INTERNAL, TASK_GRP_KERNEL and TASK_GRP_MIG
 * use the task 'kernel' group. The dynamic group is initialized for the first
 * 'external' reference to a kext specific group parented to the matching global
 * kext group. For 'external' references not matching that group, the global
 * 'external' group is used.
 * This is the default configuration.
 *
 * TASK_REF_CONFIG_FULL
 * Global refgrps are used for 'kernel', 'external', 'internal' and 'mig'
 * references. The primary 'task' reference group is set as their parent. Each
 * kext also gets is own refgrp parented to the 'external' group.
 * Each task gets eight reference groups - one each mirroring the four global
 * reference groups and four dynamic groups which are assigned to kexts. For
 * 'external' references not matching any of the four dynamic groups, the global
 * 'external' group is used.
 *
 * Kext callers have the calls which take or release task references mapped
 * to '_external' equivalents  via the .exports file.
 *
 * At-large kernel callers see calls  redefined to call the '_kernel' variants
 * (see task_ref.h).
 *
 * The mig layer generates code which uses the '_mig' variants.
 *
 * Other groups are selected explicitly.
 *
 * Reference groups support recording of back traces via the rlog boot arg.
 * For example: rlog=task_external would keep a backtrace log of all external
 * references.
 */

#define TASK_REF_COUNT_INITIAL  (2u)

extern void task_deallocate_internal(task_t task, os_ref_count_t refs);

#if DEVELOPMENT || DEBUG

#include <stdbool.h>

#define DYNAMIC_COUNT 4

/*
 * Controlled by the boot arg 'task_refgrp=X'.
 *
 * Unspecified/default
 * There are two task reference groups. One kext specific reference group, the
 * other used for kernel/internal and mig references.
 *
 * "off"
 * No task specific reference groups are used.
 *
 * "full"
 * Each task gets its own set of kernel/internal/mig and external groups.
 * Additionally four dynamic reference groups are made available to identify kext
 * references.
 */
__attribute__((used))
static enum {
	TASK_REF_CONFIG_DEFAULT,
	TASK_REF_CONFIG_FULL,
	TASK_REF_CONFIG_OFF,
} task_refgrp_config = TASK_REF_CONFIG_DEFAULT;

/* Global reference groups. */
os_refgrp_decl(static, task_primary_refgrp, "task", NULL);
os_refgrp_decl(static, task_kernel_refgrp, "task_kernel", &task_primary_refgrp);
os_refgrp_decl(static, task_internal_refgrp, "task_internal", &task_primary_refgrp);
os_refgrp_decl(static, task_mig_refgrp, "task_mig", &task_primary_refgrp);
os_refgrp_decl(, task_external_refgrp, "task_external", &task_primary_refgrp);


/* 'task_refgrp' is used by lldb macros. */
__attribute__((used))
static struct os_refgrp * const task_refgrp[TASK_GRP_COUNT] = {
	[TASK_GRP_KERNEL]   = &task_kernel_refgrp,
	[TASK_GRP_INTERNAL] = &task_internal_refgrp,
	[TASK_GRP_MIG]      = &task_mig_refgrp,
	[TASK_GRP_EXTERNAL] = &task_external_refgrp,
};

/* Names used by local reference groups. */
static const char * const local_name[TASK_GRP_COUNT] = {
	[TASK_GRP_KERNEL]   = "task_local_kernel",
	[TASK_GRP_INTERNAL] = "task_local_internal",
	[TASK_GRP_MIG]      = "task_local_mig",
	[TASK_GRP_EXTERNAL] = "task_local_external",
};

/* Walk back the callstack calling cb for each address. */
static inline void
walk_kext_callstack(int (^cb)(uintptr_t))
{
	uintptr_t* frameptr;
	uintptr_t* frameptr_next;
	uintptr_t retaddr;
	uintptr_t kstackb, kstackt;
	thread_t cthread;

	cthread = current_thread();
	assert3p(cthread, !=, NULL);

	kstackb = thread_get_kernel_stack(cthread);
	kstackt = kstackb + kernel_stack_size;

	/* Load stack frame pointer (EBP on x86) into frameptr */
	frameptr = __builtin_frame_address(0);

	while (frameptr != NULL) {
		/* Verify thread stack bounds */
		if (((uintptr_t)(frameptr + 2) > kstackt) ||
		    ((uintptr_t)frameptr < kstackb)) {
			break;
		}

		/* Next frame pointer is pointed to by the previous one */
		frameptr_next = (uintptr_t*) *frameptr;

		/* Pull return address from one spot above the frame pointer */
		retaddr = *(frameptr + 1);

#if defined(HAS_APPLE_PAC)
		retaddr = (uintptr_t) ptrauth_strip((void *)retaddr,
		    ptrauth_key_return_address);
#endif

		if (((retaddr < vm_kernel_builtinkmod_text_end) &&
		    (retaddr >= vm_kernel_builtinkmod_text)) ||
		    (retaddr < vm_kernel_stext) || (retaddr > vm_kernel_top)) {
			if (cb(retaddr) != 0) {
				return;
			}
		}
		frameptr = frameptr_next;
	}

	return;
}

/* Return the reference group associated with the 'closest' kext. */
static struct os_refgrp *
lookup_kext_refgrp(void)
{
	__block struct os_refgrp *refgrp = NULL;

	/* Get the kext specific group based on the current stack. */
	walk_kext_callstack(^(uintptr_t retaddr) {
		OSKextGetRefGrpForCaller(retaddr, ^(struct os_refgrp *kext_grp) {
			assert(kext_grp != NULL);
			refgrp = kext_grp;
		});
		return 1;
	});
	return refgrp;
}


/*
 * Given an array of reference groups, find one that matches the specified kext
 * group. If there is no match and there is a empty slot, initialize a new
 * refgrp with the kext group as the parent (only when `can_allocate` is true).
 */
static struct os_refgrp *
lookup_dynamic_refgrp(struct os_refgrp *kext,
    struct os_refgrp *dynamic, int dynamic_count, bool can_allocate)
{
	/* First see if it exists. */
	for (int i = 0; i < dynamic_count; i++) {
		if (dynamic[i].grp_parent == kext) {
			return &dynamic[i];
		}
	}

	if (!can_allocate) {
		return NULL;
	}

	/* Grab an empty one, if available. */
	for (int i = 0; i < dynamic_count; i++) {
		if (dynamic[i].grp_name == NULL) {
			dynamic[i] = (struct os_refgrp)
			    os_refgrp_initializer(kext->grp_name, kext);
			return &dynamic[i];
		}
	}

	return NULL;
}

/*
 * Find the best external reference group.
 * - Task specific kext ref group
 *   else
 * - Kext ref group
 *   else
 * - Global external ref group
 */
static struct os_refgrp *
find_external_refgrp(struct os_refgrp *dynamic, int dynamic_count,
    bool can_allocate)
{
	struct os_refgrp *kext_refgrp = lookup_kext_refgrp();
	if (kext_refgrp == NULL) {
		return task_refgrp[TASK_GRP_EXTERNAL];
	}

	struct os_refgrp *refgrp = lookup_dynamic_refgrp(kext_refgrp, dynamic,
	    dynamic_count, can_allocate);
	if (refgrp == NULL) {
		return kext_refgrp;
	}

	return refgrp;
}

void
task_reference_grp(task_t task, task_grp_t grp)
{
	assert3u(grp, <, TASK_GRP_COUNT);
	assert(
		task_refgrp_config == TASK_REF_CONFIG_OFF ||
		task_refgrp_config == TASK_REF_CONFIG_DEFAULT ||
		task_refgrp_config == TASK_REF_CONFIG_FULL);

	struct os_refgrp *refgrp = NULL;

	if (task == TASK_NULL) {
		return;
	}

	task_require(task);

	/*
	 * External ref groups need to search and potentially allocate from the
	 * dynamic task ref groups. This must be protected by a lock.
	 */
	if (task_refgrp_config != TASK_REF_CONFIG_OFF &&
	    grp == TASK_GRP_EXTERNAL) {
		lck_spin_lock(&task->ref_group_lock);
	}

	switch (task_refgrp_config) {
	case TASK_REF_CONFIG_OFF:
		refgrp = NULL;
		break;

	case TASK_REF_CONFIG_DEFAULT:

		refgrp = (grp == TASK_GRP_EXTERNAL) ?
		    find_external_refgrp(&task->ref_group[1], 1, true) :
		    &task->ref_group[TASK_GRP_KERNEL];
		break;

	case TASK_REF_CONFIG_FULL:

		refgrp = (grp == TASK_GRP_EXTERNAL) ?
		    find_external_refgrp(&task->ref_group[TASK_GRP_COUNT], DYNAMIC_COUNT, true) :
		    &task->ref_group[grp];
		break;
	}

	os_ref_retain_raw(&task->ref_count.ref_count, refgrp);

	if (task_refgrp_config != TASK_REF_CONFIG_OFF &&
	    grp == TASK_GRP_EXTERNAL) {
		lck_spin_unlock(&task->ref_group_lock);
	}
}

void
task_deallocate_grp(task_t task, task_grp_t grp)
{
	assert3u(grp, <, TASK_GRP_COUNT);
	assert(
		task_refgrp_config == TASK_REF_CONFIG_OFF ||
		task_refgrp_config == TASK_REF_CONFIG_DEFAULT ||
		task_refgrp_config == TASK_REF_CONFIG_FULL);

	os_ref_count_t refs = -1;
	struct os_refgrp *refgrp = NULL;

	if (task == TASK_NULL) {
		return;
	}

	/*
	 * There is no need to take the ref_group_lock when de-allocating. The
	 * lock is only required when allocating a group.
	 */
	switch (task_refgrp_config) {
	case TASK_REF_CONFIG_OFF:
		refgrp = NULL;
		break;

	case TASK_REF_CONFIG_DEFAULT:
		refgrp = (grp == TASK_GRP_EXTERNAL) ?
		    find_external_refgrp(&task->ref_group[1], 1, false) :
		    &task->ref_group[TASK_GRP_KERNEL];
		break;

	case TASK_REF_CONFIG_FULL:
		refgrp = (grp == TASK_GRP_EXTERNAL) ?
		    find_external_refgrp(&task->ref_group[TASK_GRP_COUNT], DYNAMIC_COUNT, false) :
		    &task->ref_group[grp];
		break;
	}


	refs = os_ref_release_raw(&task->ref_count.ref_count, refgrp);
	/* Beware - the task may have been freed after this point. */

	task_deallocate_internal(task, refs);
}

void
task_reference_external(task_t task)
{
	task_reference_grp(task, TASK_GRP_EXTERNAL);
}

void
task_deallocate_external(task_t task)
{
	task_deallocate_grp(task, TASK_GRP_EXTERNAL);
}

static void
allocate_refgrp_default(task_t task)
{
	/* Just one static group and one dynamic group. */
	task->ref_group = kalloc_type(struct os_refgrp, 2,
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	task->ref_group[TASK_GRP_KERNEL] = (struct os_refgrp)
	    os_refgrp_initializer(local_name[TASK_GRP_KERNEL],
	    task_refgrp[TASK_GRP_KERNEL]);
	os_ref_log_init(&task->ref_group[TASK_GRP_KERNEL]);
}

static void
free_refgrp_default(task_t task)
{
	os_ref_log_fini(&task->ref_group[TASK_GRP_KERNEL]);
	/* Just one static group and one dynamic group. */
	kfree_type(struct os_refgrp, 2, task->ref_group);
}

static void
allocate_refgrp_full(task_t task)
{
	task->ref_group = kalloc_type(struct os_refgrp,
	    TASK_GRP_COUNT + DYNAMIC_COUNT, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	for (int i = 0; i < TASK_GRP_COUNT; i++) {
		task->ref_group[i] = (struct os_refgrp)
		    os_refgrp_initializer(local_name[i], task_refgrp[i]);
		os_ref_log_init(&task->ref_group[i]);
	}
}

static void
free_refgrp_full(task_t task)
{
	for (int i = 0; i < TASK_GRP_COUNT; i++) {
		os_ref_log_fini(&task->ref_group[i]);
	}
	kfree_type(struct os_refgrp, TASK_GRP_COUNT + DYNAMIC_COUNT, task->ref_group);
}

kern_return_t
task_ref_count_init(task_t task)
{
	assert(
		task_refgrp_config == TASK_REF_CONFIG_OFF ||
		task_refgrp_config == TASK_REF_CONFIG_DEFAULT ||
		task_refgrp_config == TASK_REF_CONFIG_FULL);

	switch (task_refgrp_config) {
	case TASK_REF_CONFIG_OFF:
		os_ref_init_count(&task->ref_count, &task_primary_refgrp,
		    TASK_REF_COUNT_INITIAL);
		return KERN_SUCCESS;


	case TASK_REF_CONFIG_DEFAULT:
		allocate_refgrp_default(task);
		lck_spin_init(&task->ref_group_lock, &task_lck_grp, LCK_ATTR_NULL);
		os_ref_init_count(&task->ref_count, &task->ref_group[TASK_GRP_KERNEL],
		    TASK_REF_COUNT_INITIAL);
		return KERN_SUCCESS;

	case TASK_REF_CONFIG_FULL:
		allocate_refgrp_full(task);
		lck_spin_init(&task->ref_group_lock, &task_lck_grp, LCK_ATTR_NULL);

		os_ref_init_count_internal(&task->ref_count.ref_count,
		    &task->ref_group[TASK_GRP_KERNEL], 1);

		task_reference_grp(task, TASK_GRP_INTERNAL);

		return KERN_SUCCESS;
	}
}

void
task_ref_count_fini(task_t task)
{
	assert(
		task_refgrp_config == TASK_REF_CONFIG_OFF ||
		task_refgrp_config == TASK_REF_CONFIG_DEFAULT ||
		task_refgrp_config == TASK_REF_CONFIG_FULL);

	switch (task_refgrp_config) {
	case TASK_REF_CONFIG_OFF:
		return;

	case TASK_REF_CONFIG_DEFAULT:
		lck_spin_destroy(&task->ref_group_lock, &task_lck_grp);
		free_refgrp_default(task);
		return;

	case TASK_REF_CONFIG_FULL:
		lck_spin_destroy(&task->ref_group_lock, &task_lck_grp);
		free_refgrp_full(task);
		return;
	}
}

void
task_ref_init(void)
{
	char config[16] = {0};

	/* Allow task reference group logging to be configured. */
	(void) PE_parse_boot_arg_str("task_refgrp", config,
	    sizeof(config));

	if (strncmp(config, "full", sizeof(config)) == 0) {
		task_refgrp_config = TASK_REF_CONFIG_FULL;
	}
	if (strncmp(config, "off", sizeof(config)) == 0) {
		task_refgrp_config = TASK_REF_CONFIG_OFF;
	}

	if (task_refgrp_config == TASK_REF_CONFIG_OFF) {
		return;
	}

	for (int i = 0; i < TASK_GRP_COUNT; i++) {
		os_ref_log_init(task_refgrp[i]);
	}
}

#else /* DEVELOPMENT || DEBUG */

kern_return_t
task_ref_count_init(task_t task)
{
	/* One ref for our caller, one for being alive. */
	os_ref_init_count(&task->ref_count, &task_primary_refgrp,
	    TASK_REF_COUNT_INITIAL);
	return KERN_SUCCESS;
}

void
task_reference_grp(task_t task, __attribute__((__unused__)) task_grp_t grp)
{
	if (task == TASK_NULL) {
		return;
	}

	task_require(task);
	os_ref_retain(&task->ref_count);
}

void
task_deallocate_grp(task_t task, __attribute__((__unused__)) task_grp_t grp)
{
	if (task == TASK_NULL) {
		return;
	}

	os_ref_count_t refs = os_ref_release(&task->ref_count);
	task_deallocate_internal(task, refs);
}

void
task_reference_external(task_t task)
{
	task_reference_grp(task, 0);
}

void
task_deallocate_external(task_t task)
{
	task_deallocate_grp(task, 0);
}

void
task_ref_count_fini(__attribute__((__unused__)) task_t task)
{
}

void
task_ref_init(void)
{
}

#endif /* DEVELOPMENT || DEBUG */
