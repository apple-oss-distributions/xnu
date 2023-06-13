/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)resourcevar.h	8.4 (Berkeley) 1/9/95
 */

#ifndef _SYS_RESOURCEVAR_H_
#define _SYS_RESOURCEVAR_H_

#include <sys/appleapiopts.h>
#include <sys/resource.h>
#include <sys/_types/_caddr_t.h>
#ifdef XNU_KERNEL_PRIVATE
#include <os/refcnt.h>
#endif

/*
 * Kernel per-process accounting / statistics
 * (not necessarily resident except when running).
 */
struct pstats {
	struct  rusage            p_ru;         /* stats for this proc */
	struct  rusage            p_cru;        /* (PL) sum of stats for reaped children */

	struct uprof {                  /* profile arguments */
		struct uprof *pr_next;  /* multiple prof buffers allowed */
		caddr_t pr_base;        /* buffer base */
		u_int32_t       pr_size;        /* buffer size */
		u_int32_t       pr_off;         /* pc offset */
		u_int32_t       pr_scale;       /* pc scaling */
		u_int32_t       pr_addr;        /* temp storage for addr until AST */
		u_int32_t       pr_ticks;       /* temp storage for ticks until AST */
	} p_prof;

	uint64_t ps_start;              /* starting time ; compat only */
#ifdef XNU_KERNEL_PRIVATE
	struct  rusage_info_child ri_child;     /* (PL) sum of additional stats for reaped children (proc_pid_rusage) */
	struct user_uprof {                         /* profile arguments */
		struct user_uprof *pr_next;  /* multiple prof buffers allowed */
		user_addr_t         pr_base;    /* buffer base */
		user_size_t         pr_size;    /* buffer size */
		user_ulong_t    pr_off;         /* pc offset */
		user_ulong_t    pr_scale;       /* pc scaling */
		user_ulong_t    pr_addr;        /* temp storage for addr until AST */
		user_ulong_t    pr_ticks;       /* temp storage for ticks until AST */
	} user_p_prof;
#endif // XNU_KERNEL_PRIVATE
};

#ifdef XNU_KERNEL_PRIVATE
#pragma GCC visibility push(hidden)
/*
 * Kernel shareable process resource limits:
 * Because this structure is moderately large but changed infrequently, it is normally
 * shared copy-on-write after a fork. The pl_refcnt variable records the number of
 * "processes" (NOT threads) currently sharing the plimit. A plimit is freed when the
 * last referencing process exits the system. The refcnt of the plimit is a race-free
 * _Atomic variable. We allocate new plimits in proc_limitupdate and free them
 * in proc_limitdrop/proc_limitupdate.
 */
struct plimit {
	struct  rlimit   pl_rlimit[RLIM_NLIMITS];
	os_refcnt_t      pl_refcnt;
};
struct proc;

void calcru(struct proc *p, struct timeval *up, struct timeval *sp, struct timeval *ip);
void ruadd(struct rusage *ru, struct rusage *ru2);
void update_rusage_info_child(struct rusage_info_child *ru, rusage_info_current *ru_current);
struct rlimit proc_limitget(struct proc *p, int which);
void proc_limitfork(struct proc *parent, struct proc *child);
void proc_limitdrop(struct proc *p);
rlim_t proc_limitgetcur(struct proc *p, int which);
void proc_limitsetcur_fsize(struct proc *p, rlim_t value);
int proc_limitgetcur_nofile(struct proc *p);

void gather_rusage_info(struct proc *p, rusage_info_current *ru, int flavor);
int proc_get_rusage(struct proc *proc, int flavor, user_addr_t buffer, int is_zombie);
int iopolicysys_vfs_materialize_dataless_files(struct proc *p, int cmd, int scope,
    int policy, struct _iopol_param_t *iop_param);

#pragma GCC visibility pop
#endif /* XNU_KERNEL_PRIVATE */
#endif  /* !_SYS_RESOURCEVAR_H_ */
