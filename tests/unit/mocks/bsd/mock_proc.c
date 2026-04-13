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

#include "mock_proc.h"
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include "mocks/std_safe.h"
#include "sys/proc.h"
#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/vnode_internal.h>
#include <sys/conf.h>
#include <sys/buf_internal.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/systm.h>
#include <sys/mman.h>

/* this function simulates initialization of a random proc/task
 * that is going to be a child of init task
 * */
void
fake_proc_init(proc_t p)
{
	/* proc_ro needs to be properly set */
	p->p_proc_ro = calloc(sizeof(struct proc_ro), 1);
	p->p_proc_ro->pr_proc = p;
	/* needs to mark that proc has a task */
	p->p_lflag |= P_LHASTASK;
}

void
fake_dealloc_proc_and_task(proc_t proc)
{
	if (proc->p_proc_ro) {
		free(proc->p_proc_ro);
	}
	free(proc);
}

void
proc_user_faults_template(proc_t proc,
    int cross_limit_global,
    int cross_limit_security)
{
	proc->p_user_faults[PROC_P_USER_FAULTS_GLOBAL_IDX] = cross_limit_global ? 100 : 0;
	proc->p_user_faults[PROC_P_USER_FAULTS_SOFT_TRAPS_IDX] = cross_limit_security ? 100 : 0;
}
