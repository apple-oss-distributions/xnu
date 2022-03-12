/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef _SYS_PROC_RO_H_
#define _SYS_PROC_RO_H_

#include <stdint.h>
#include <sys/_types/_pid_t.h>
#include <sys/cdefs.h>

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN
#pragma GCC visibility push(hidden)

struct proc;
struct task;
struct ucred;

struct proc_platform_ro_data {
	uint32_t p_platform;
	uint32_t p_min_sdk;
	uint32_t p_sdk;
};

struct task_token_ro_data {
	security_token_t sec_token;
	audit_token_t audit_token;
};

struct task_filter_ro_data {
	uint8_t *__unsafe_indexable mach_trap_filter_mask; /* Mach trap filter bitmask (len: mach_trap_count bits) */
	uint8_t *__unsafe_indexable mach_kobj_filter_mask; /* Mach kobject filter bitmask (len: mach_kobj_count bits) */
};

struct proc_ro {
	struct proc *pr_proc;
	struct task *pr_task;

	__xnu_struct_group(proc_ro_data, proc_data, {
		uint64_t p_uniqueid;                               /* process unique ID - incremented on fork/spawn/vfork, remains same across exec. */
		int p_idversion;                                   /* version of process identity */
		uint32_t p_csflags;
		struct ucred *p_ucred;                             /* Process owner's identity. (PUCL) */
		uint8_t *__unsafe_indexable syscall_filter_mask;   /* syscall filter bitmask (length: nsysent bits) */
		struct proc_platform_ro_data p_platform_data;
	});

	__xnu_struct_group(task_ro_data, task_data, {
		/* Task security and audit tokens */
		struct task_token_ro_data task_tokens;
#ifdef CONFIG_MACF
		struct task_filter_ro_data task_filters;
#endif
	});
};

typedef const struct proc_ro_data *proc_ro_data_t;
typedef const struct task_ro_data *task_ro_data_t;
typedef struct proc_ro *proc_ro_t;

extern proc_ro_t proc_ro_alloc(struct proc *p, proc_ro_data_t p_data, struct task *t, task_ro_data_t t_data);
extern void proc_ro_free(proc_ro_t pr);
extern proc_ro_t proc_ro_ref_task(proc_ro_t pr, struct task *t, task_ro_data_t t_data);
extern void proc_switch_ro(struct proc *p, proc_ro_t new_ro);
extern proc_ro_t proc_ro_release_proc(proc_ro_t pr);
extern proc_ro_t proc_ro_release_task(proc_ro_t pr);

extern proc_ro_t proc_get_ro(struct proc *p) __pure2;
extern proc_ro_t current_proc_ro(void) __pure2;
extern proc_ro_t task_get_ro(struct task *t) __pure2;

extern struct proc *proc_ro_proc(proc_ro_t pr) __pure2;
extern struct task *proc_ro_task(proc_ro_t pr) __pure2;

#pragma GCC visibility pop
__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif /* _SYS_PROC_RO_H_ */
