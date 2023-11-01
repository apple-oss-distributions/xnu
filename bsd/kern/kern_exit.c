/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
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
 *	@(#)kern_exit.c	8.7 (Berkeley) 2/12/94
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <machine/reg.h>
#include <machine/psl.h>
#include <stdatomic.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/tty.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/kernel.h>
#include <sys/wait.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/syslog.h>
#include <sys/malloc.h>
#include <sys/resourcevar.h>
#include <sys/ptrace.h>
#include <sys/proc_info.h>
#include <sys/reason.h>
#include <sys/_types/_timeval64.h>
#include <sys/user.h>
#include <sys/aio_kern.h>
#include <sys/sysproto.h>
#include <sys/signalvar.h>
#include <sys/kdebug.h>
#include <sys/kdebug_triage.h>
#include <sys/acct.h> /* acct_process */
#include <sys/codesign.h>
#include <sys/event.h> /* kevent_proc_copy_uptrs */
#include <sys/sdt.h>
#include <sys/bsdtask_info.h> /* bsd_getthreadname */
#include <sys/spawn.h>
#include <sys/ubc.h>
#include <sys/code_signing.h>

#include <security/audit/audit.h>
#include <bsm/audit_kevents.h>

#include <mach/mach_types.h>
#include <mach/task.h>
#include <mach/thread_act.h>

#include <kern/exc_resource.h>
#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <kern/task.h>
#include <corpses/task_corpse.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <kern/sched_prim.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/policy_internal.h>
#include <kern/exc_guard.h>
#include <kern/backtrace.h>

#include <vm/vm_protos.h>
#include <os/log.h>
#include <os/system_event_log.h>

#include <pexpert/pexpert.h>

#include <kdp/kdp_dyld.h>

#if SYSV_SHM
#include <sys/shm_internal.h>   /* shmexit */
#endif /* SYSV_SHM */
#if CONFIG_PERSONAS
#include <sys/persona.h>
#endif /* CONFIG_PERSONAS */
#if CONFIG_MEMORYSTATUS
#include <sys/kern_memorystatus.h>
#endif /* CONFIG_MEMORYSTATUS */
#if CONFIG_DTRACE
/* Do not include dtrace.h, it redefines kmem_[alloc/free] */
void dtrace_proc_exit(proc_t p);
#include <sys/dtrace_ptss.h>
#endif /* CONFIG_DTRACE */
#if CONFIG_MACF
#include <security/mac_framework.h>
#include <security/mac_mach_internal.h>
#include <sys/syscall.h>
#endif /* CONFIG_MACF */

#if CONFIG_MEMORYSTATUS
static void proc_memorystatus_remove(proc_t p);
#endif /* CONFIG_MEMORYSTATUS */
void proc_prepareexit(proc_t p, int rv, boolean_t perf_notify);
void gather_populate_corpse_crashinfo(proc_t p, task_t corpse_task,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode,
    uint64_t *udata_buffer, int num_udata, void *reason, exception_type_t etype);
mach_exception_data_type_t proc_encode_exit_exception_code(proc_t p);
exception_type_t get_exception_from_corpse_crashinfo(kcdata_descriptor_t corpse_info);
__private_extern__ void munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p);
__private_extern__ void munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p);
static void populate_corpse_crashinfo(proc_t p, task_t corpse_task,
    struct rusage_superset *rup, mach_exception_data_type_t code,
    mach_exception_data_type_t subcode, uint64_t *udata_buffer,
    int num_udata, os_reason_t reason, exception_type_t etype);
static void proc_update_corpse_exception_codes(proc_t p, mach_exception_data_type_t *code, mach_exception_data_type_t *subcode);
extern int proc_pidpathinfo_internal(proc_t p, uint64_t arg, char *buffer, uint32_t buffersize, int32_t *retval);
extern void proc_piduniqidentifierinfo(proc_t p, struct proc_uniqidentifierinfo *p_uniqidinfo);
extern void task_coalition_ids(task_t task, uint64_t ids[COALITION_NUM_TYPES]);
extern uint64_t get_task_phys_footprint_limit(task_t);
int proc_list_uptrs(void *p, uint64_t *udata_buffer, int size);
extern uint64_t task_corpse_get_crashed_thread_id(task_t corpse_task);

extern unsigned int exception_log_max_pid;

extern void IOUserServerRecordExitReason(task_t task, os_reason_t reason);

/*
 * Flags for `reap_child_locked`.
 */
__options_decl(reap_flags_t, uint32_t, {
	/*
	 * Parent is exiting, so the kernel is responsible for reaping children.
	 */
	REAP_DEAD_PARENT = 0x01,
	/*
	 * Childr process was re-parented to initproc.
	 */
	REAP_REPARENTED_TO_INIT = 0x02,
	/*
	 * `proc_list_lock` is held on entry.
	 */
	REAP_LOCKED = 0x04,
	/*
	 * Drop the `proc_list_lock` on return.  Note that the `proc_list_lock` will
	 * be dropped internally by the function regardless.
	 */
	REAP_DROP_LOCK = 0x08,
});
static void reap_child_locked(proc_t parent, proc_t child, reap_flags_t flags);

static KALLOC_TYPE_DEFINE(zombie_zone, struct rusage_superset, KT_DEFAULT);

/*
 * Things which should have prototypes in headers, but don't
 */
void    proc_exit(proc_t p);
int     wait1continue(int result);
int     waitidcontinue(int result);
kern_return_t sys_perf_notify(thread_t thread, int pid);
kern_return_t task_exception_notify(exception_type_t exception,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode, bool fatal);
void    delay(int);

#if __has_feature(ptrauth_calls)
int exit_with_pac_exception(proc_t p, exception_type_t exception, mach_exception_code_t code,
    mach_exception_subcode_t subcode);
#endif /* __has_feature(ptrauth_calls) */

int exit_with_guard_exception(proc_t p, mach_exception_data_type_t code,
    mach_exception_data_type_t subcode);
int exit_with_port_space_exception(proc_t p, mach_exception_data_type_t code,
    mach_exception_data_type_t subcode);
static int exit_with_mach_exception(proc_t p, os_reason_t reason, exception_type_t exception,
    mach_exception_code_t code, mach_exception_subcode_t subcode);

#if DEVELOPMENT || DEBUG
static LCK_GRP_DECLARE(proc_exit_lpexit_spin_lock_grp, "proc_exit_lpexit_spin");
static LCK_MTX_DECLARE(proc_exit_lpexit_spin_lock, &proc_exit_lpexit_spin_lock_grp);
static pid_t proc_exit_lpexit_spin_pid = -1;            /* wakeup point */
static int proc_exit_lpexit_spin_pos = -1;              /* point to block */
static int proc_exit_lpexit_spinning = 0;
enum {
	PELS_POS_START = 0,             /* beginning of proc_exit */
	PELS_POS_PRE_TASK_DETACH,       /* before task/proc detach */
	PELS_POS_POST_TASK_DETACH,      /* after task/proc detach */
	PELS_POS_END,                   /* end of proc_exit */
	PELS_NPOS                       /* # valid values */
};

/* Panic if matching processes (delimited by ',') exit on error. */
static TUNABLE_STR(panic_on_eexit_pcomms, 128, "panic_on_error_exit", "");

static int
proc_exit_lpexit_spin_pid_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	pid_t new_value;
	int changed;
	int error;

	if (!PE_parse_boot_argn("enable_proc_exit_lpexit_spin", NULL, 0)) {
		return ENOENT;
	}

	error = sysctl_io_number(req, proc_exit_lpexit_spin_pid,
	    sizeof(proc_exit_lpexit_spin_pid), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value < -1) {
			return EINVAL;
		}
		lck_mtx_lock(&proc_exit_lpexit_spin_lock);
		proc_exit_lpexit_spin_pid = new_value;
		wakeup(&proc_exit_lpexit_spin_pid);
		proc_exit_lpexit_spinning = 0;
		lck_mtx_unlock(&proc_exit_lpexit_spin_lock);
	}
	return error;
}

static int
proc_exit_lpexit_spin_pos_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int new_value;
	int changed;
	int error;

	if (!PE_parse_boot_argn("enable_proc_exit_lpexit_spin", NULL, 0)) {
		return ENOENT;
	}

	error = sysctl_io_number(req, proc_exit_lpexit_spin_pos,
	    sizeof(proc_exit_lpexit_spin_pos), &new_value, &changed);
	if (error == 0 && changed != 0) {
		if (new_value < -1 || new_value >= PELS_NPOS) {
			return EINVAL;
		}
		lck_mtx_lock(&proc_exit_lpexit_spin_lock);
		proc_exit_lpexit_spin_pos = new_value;
		wakeup(&proc_exit_lpexit_spin_pid);
		proc_exit_lpexit_spinning = 0;
		lck_mtx_unlock(&proc_exit_lpexit_spin_lock);
	}
	return error;
}

static int
proc_exit_lpexit_spinning_sysctl SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int new_value;
	int changed;
	int error;

	if (!PE_parse_boot_argn("enable_proc_exit_lpexit_spin", NULL, 0)) {
		return ENOENT;
	}

	error = sysctl_io_number(req, proc_exit_lpexit_spinning,
	    sizeof(proc_exit_lpexit_spinning), &new_value, &changed);
	if (error == 0 && changed != 0) {
		return EINVAL;
	}
	return error;
}

SYSCTL_PROC(_debug, OID_AUTO, proc_exit_lpexit_spin_pid,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    NULL, sizeof(pid_t),
    proc_exit_lpexit_spin_pid_sysctl, "I", "PID to hold in proc_exit");

SYSCTL_PROC(_debug, OID_AUTO, proc_exit_lpexit_spin_pos,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    NULL, sizeof(int),
    proc_exit_lpexit_spin_pos_sysctl, "I", "position to hold in proc_exit");

SYSCTL_PROC(_debug, OID_AUTO, proc_exit_lpexit_spinning,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    NULL, sizeof(int),
    proc_exit_lpexit_spinning_sysctl, "I", "is a thread at requested pid/pos");

static inline void
proc_exit_lpexit_check(pid_t pid, int pos)
{
	if (proc_exit_lpexit_spin_pid == pid) {
		bool slept = false;
		lck_mtx_lock(&proc_exit_lpexit_spin_lock);
		while (proc_exit_lpexit_spin_pid == pid &&
		    proc_exit_lpexit_spin_pos == pos) {
			if (!slept) {
				os_log(OS_LOG_DEFAULT,
				    "proc_exit_lpexit_check: Process[%d] waiting during proc_exit at pos %d as requested", pid, pos);
				slept = true;
			}
			proc_exit_lpexit_spinning = 1;
			msleep(&proc_exit_lpexit_spin_pid, &proc_exit_lpexit_spin_lock,
			    PWAIT, "proc_exit_lpexit_check", NULL);
			proc_exit_lpexit_spinning = 0;
		}
		lck_mtx_unlock(&proc_exit_lpexit_spin_lock);
		if (slept) {
			os_log(OS_LOG_DEFAULT,
			    "proc_exit_lpexit_check: Process[%d] driving on from pos %d", pid, pos);
		}
	}
}
#endif /* DEVELOPMENT || DEBUG */

/*
 * NOTE: Source and target may *NOT* overlap!
 * XXX Should share code with bsd/dev/ppc/unix_signal.c
 */
void
siginfo_user_to_user32(user_siginfo_t *in, user32_siginfo_t *out)
{
	out->si_signo   = in->si_signo;
	out->si_errno   = in->si_errno;
	out->si_code    = in->si_code;
	out->si_pid     = in->si_pid;
	out->si_uid     = in->si_uid;
	out->si_status  = in->si_status;
	out->si_addr    = CAST_DOWN_EXPLICIT(user32_addr_t, in->si_addr);
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr = CAST_DOWN_EXPLICIT(user32_addr_t, in->si_value.sival_ptr);
	out->si_band    = (user32_long_t)in->si_band;                  /* range reduction */
}

void
siginfo_user_to_user64(user_siginfo_t *in, user64_siginfo_t *out)
{
	out->si_signo   = in->si_signo;
	out->si_errno   = in->si_errno;
	out->si_code    = in->si_code;
	out->si_pid     = in->si_pid;
	out->si_uid     = in->si_uid;
	out->si_status  = in->si_status;
	out->si_addr    = in->si_addr;
	/* following cast works for sival_int because of padding */
	out->si_value.sival_ptr = in->si_value.sival_ptr;
	out->si_band    = in->si_band;                  /* range reduction */
}

static int
copyoutsiginfo(user_siginfo_t *native, boolean_t is64, user_addr_t uaddr)
{
	if (is64) {
		user64_siginfo_t sinfo64;

		bzero(&sinfo64, sizeof(sinfo64));
		siginfo_user_to_user64(native, &sinfo64);
		return copyout(&sinfo64, uaddr, sizeof(sinfo64));
	} else {
		user32_siginfo_t sinfo32;

		bzero(&sinfo32, sizeof(sinfo32));
		siginfo_user_to_user32(native, &sinfo32);
		return copyout(&sinfo32, uaddr, sizeof(sinfo32));
	}
}

void
gather_populate_corpse_crashinfo(proc_t p, task_t corpse_task,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode,
    uint64_t *udata_buffer, int num_udata, void *reason, exception_type_t etype)
{
	struct rusage_superset rup;

	gather_rusage_info(p, &rup.ri, RUSAGE_INFO_CURRENT);
	rup.ri.ri_phys_footprint = 0;
	populate_corpse_crashinfo(p, corpse_task, &rup, code, subcode,
	    udata_buffer, num_udata, reason, etype);
}

static void
proc_update_corpse_exception_codes(proc_t p, mach_exception_data_type_t *code, mach_exception_data_type_t *subcode)
{
	mach_exception_data_type_t code_update = *code;
	mach_exception_data_type_t subcode_update = *subcode;
	if (p->p_exit_reason == OS_REASON_NULL) {
		return;
	}

	switch (p->p_exit_reason->osr_namespace) {
	case OS_REASON_JETSAM:
		if (p->p_exit_reason->osr_code == JETSAM_REASON_MEMORY_PERPROCESSLIMIT) {
			/* Update the code with EXC_RESOURCE code for high memory watermark */
			EXC_RESOURCE_ENCODE_TYPE(code_update, RESOURCE_TYPE_MEMORY);
			EXC_RESOURCE_ENCODE_FLAVOR(code_update, FLAVOR_HIGH_WATERMARK);
			EXC_RESOURCE_HWM_ENCODE_LIMIT(code_update, ((get_task_phys_footprint_limit(proc_task(p))) >> 20));
			subcode_update = 0;
			break;
		}

		break;
	default:
		break;
	}

	*code = code_update;
	*subcode = subcode_update;
	return;
}

mach_exception_data_type_t
proc_encode_exit_exception_code(proc_t p)
{
	uint64_t subcode = 0;

	if (p->p_exit_reason == OS_REASON_NULL) {
		return 0;
	}

	/* Embed first 32 bits of osr_namespace and osr_code in exception code */
	ENCODE_OSR_NAMESPACE_TO_MACH_EXCEPTION_CODE(subcode, p->p_exit_reason->osr_namespace);
	ENCODE_OSR_CODE_TO_MACH_EXCEPTION_CODE(subcode, p->p_exit_reason->osr_code);
	return (mach_exception_data_type_t)subcode;
}

static void
populate_corpse_crashinfo(proc_t p, task_t corpse_task, struct rusage_superset *rup,
    mach_exception_data_type_t code, mach_exception_data_type_t subcode,
    uint64_t *udata_buffer, int num_udata, os_reason_t reason, exception_type_t etype)
{
	mach_vm_address_t uaddr = 0;
	mach_exception_data_type_t exc_codes[EXCEPTION_CODE_MAX];
	exc_codes[0] = code;
	exc_codes[1] = subcode;
	cpu_type_t cputype;
	struct proc_uniqidentifierinfo p_uniqidinfo;
	struct proc_workqueueinfo pwqinfo;
	int retval = 0;
	uint64_t crashed_threadid = task_corpse_get_crashed_thread_id(corpse_task);
	boolean_t is_corpse_fork;
	uint32_t csflags;
	unsigned int pflags = 0;
	uint64_t max_footprint_mb;
	uint64_t max_footprint;

	uint64_t ledger_internal;
	uint64_t ledger_internal_compressed;
	uint64_t ledger_iokit_mapped;
	uint64_t ledger_alternate_accounting;
	uint64_t ledger_alternate_accounting_compressed;
	uint64_t ledger_purgeable_nonvolatile;
	uint64_t ledger_purgeable_nonvolatile_compressed;
	uint64_t ledger_page_table;
	uint64_t ledger_phys_footprint;
	uint64_t ledger_phys_footprint_lifetime_max;
	uint64_t ledger_network_nonvolatile;
	uint64_t ledger_network_nonvolatile_compressed;
	uint64_t ledger_wired_mem;
	uint64_t ledger_tagged_footprint;
	uint64_t ledger_tagged_footprint_compressed;
	uint64_t ledger_media_footprint;
	uint64_t ledger_media_footprint_compressed;
	uint64_t ledger_graphics_footprint;
	uint64_t ledger_graphics_footprint_compressed;
	uint64_t ledger_neural_footprint;
	uint64_t ledger_neural_footprint_compressed;

	void *crash_info_ptr = task_get_corpseinfo(corpse_task);

#if CONFIG_MEMORYSTATUS
	int memstat_dirty_flags = 0;
#endif

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_EXCEPTION_CODES, sizeof(exc_codes), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, exc_codes, sizeof(exc_codes));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PID, sizeof(pid_t), &uaddr)) {
		pid_t pid = proc_getpid(p);
		kcdata_memcpy(crash_info_ptr, uaddr, &pid, sizeof(pid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PPID, sizeof(p->p_ppid), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_ppid, sizeof(p->p_ppid));
	}

	/* Don't include the crashed thread ID if there's an exit reason that indicates it's irrelevant */
	if ((p->p_exit_reason == OS_REASON_NULL) || !(p->p_exit_reason->osr_flags & OS_REASON_FLAG_NO_CRASHED_TID)) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CRASHED_THREADID, sizeof(uint64_t), &uaddr)) {
			kcdata_memcpy(crash_info_ptr, uaddr, &crashed_threadid, sizeof(uint64_t));
		}
	}

	static_assert(sizeof(struct proc_uniqidentifierinfo) == sizeof(struct crashinfo_proc_uniqidentifierinfo));
	if (KERN_SUCCESS ==
	    kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_BSDINFOWITHUNIQID, sizeof(struct proc_uniqidentifierinfo), &uaddr)) {
		proc_piduniqidentifierinfo(p, &p_uniqidinfo);
		kcdata_memcpy(crash_info_ptr, uaddr, &p_uniqidinfo, sizeof(struct proc_uniqidentifierinfo));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_RUSAGE_INFO, sizeof(rusage_info_current), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &rup->ri, sizeof(rusage_info_current));
	}

	csflags = (uint32_t)proc_getcsflags(p);
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_CSFLAGS, sizeof(csflags), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &csflags, sizeof(csflags));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_NAME, sizeof(p->p_comm), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_comm, sizeof(p->p_comm));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_STARTTIME, sizeof(p->p_start), &uaddr)) {
		struct timeval64 t64;
		t64.tv_sec = (int64_t)p->p_start.tv_sec;
		t64.tv_usec = (int64_t)p->p_start.tv_usec;
		kcdata_memcpy(crash_info_ptr, uaddr, &t64, sizeof(t64));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_USERSTACK, sizeof(p->user_stack), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->user_stack, sizeof(p->user_stack));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_ARGSLEN, sizeof(p->p_argslen), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_argslen, sizeof(p->p_argslen));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_ARGC, sizeof(p->p_argc), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_argc, sizeof(p->p_argc));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_PATH, MAXPATHLEN, &uaddr)) {
		char *buf = zalloc_flags(ZV_NAMEI, Z_WAITOK | Z_ZERO);
		proc_pidpathinfo_internal(p, 0, buf, MAXPATHLEN, &retval);
		kcdata_memcpy(crash_info_ptr, uaddr, buf, MAXPATHLEN);
		zfree(ZV_NAMEI, buf);
	}

	pflags = p->p_flag & (P_LP64 | P_SUGID | P_TRANSLATED);
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_FLAGS, sizeof(pflags), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &pflags, sizeof(pflags));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_UID, sizeof(p->p_uid), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_uid, sizeof(p->p_uid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_GID, sizeof(p->p_gid), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_gid, sizeof(p->p_gid));
	}

	cputype = cpu_type() & ~CPU_ARCH_MASK;
	if (IS_64BIT_PROCESS(p)) {
		cputype |= CPU_ARCH_ABI64;
	} else if (proc_is64bit_data(p)) {
		cputype |= CPU_ARCH_ABI64_32;
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CPUTYPE, sizeof(cpu_type_t), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &cputype, sizeof(cpu_type_t));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_CPUTYPE, sizeof(cpu_type_t), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_cputype, sizeof(cpu_type_t));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_MEMORY_LIMIT, sizeof(max_footprint_mb), &uaddr)) {
		max_footprint = get_task_phys_footprint_limit(proc_task(p));
		max_footprint_mb = max_footprint >> 20;
		kcdata_memcpy(crash_info_ptr, uaddr, &max_footprint_mb, sizeof(max_footprint_mb));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX, sizeof(ledger_phys_footprint_lifetime_max), &uaddr)) {
		ledger_phys_footprint_lifetime_max = get_task_phys_footprint_lifetime_max(proc_task(p));
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_phys_footprint_lifetime_max, sizeof(ledger_phys_footprint_lifetime_max));
	}

	// In the forking case, the current ledger info is copied into the corpse while the original task is suspended for consistency
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_INTERNAL, sizeof(ledger_internal), &uaddr)) {
		ledger_internal = get_task_internal(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_internal, sizeof(ledger_internal));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_INTERNAL_COMPRESSED, sizeof(ledger_internal_compressed), &uaddr)) {
		ledger_internal_compressed = get_task_internal_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_internal_compressed, sizeof(ledger_internal_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_IOKIT_MAPPED, sizeof(ledger_iokit_mapped), &uaddr)) {
		ledger_iokit_mapped = get_task_iokit_mapped(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_iokit_mapped, sizeof(ledger_iokit_mapped));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_ALTERNATE_ACCOUNTING, sizeof(ledger_alternate_accounting), &uaddr)) {
		ledger_alternate_accounting = get_task_alternate_accounting(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_alternate_accounting, sizeof(ledger_alternate_accounting));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED, sizeof(ledger_alternate_accounting_compressed), &uaddr)) {
		ledger_alternate_accounting_compressed = get_task_alternate_accounting_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_alternate_accounting_compressed, sizeof(ledger_alternate_accounting_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_PURGEABLE_NONVOLATILE, sizeof(ledger_purgeable_nonvolatile), &uaddr)) {
		ledger_purgeable_nonvolatile = get_task_purgeable_nonvolatile(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_purgeable_nonvolatile, sizeof(ledger_purgeable_nonvolatile));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED, sizeof(ledger_purgeable_nonvolatile_compressed), &uaddr)) {
		ledger_purgeable_nonvolatile_compressed = get_task_purgeable_nonvolatile_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_purgeable_nonvolatile_compressed, sizeof(ledger_purgeable_nonvolatile_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_PAGE_TABLE, sizeof(ledger_page_table), &uaddr)) {
		ledger_page_table = get_task_page_table(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_page_table, sizeof(ledger_page_table));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_PHYS_FOOTPRINT, sizeof(ledger_phys_footprint), &uaddr)) {
		ledger_phys_footprint = get_task_phys_footprint(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_phys_footprint, sizeof(ledger_phys_footprint));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_NETWORK_NONVOLATILE, sizeof(ledger_network_nonvolatile), &uaddr)) {
		ledger_network_nonvolatile = get_task_network_nonvolatile(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_network_nonvolatile, sizeof(ledger_network_nonvolatile));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_NETWORK_NONVOLATILE_COMPRESSED, sizeof(ledger_network_nonvolatile_compressed), &uaddr)) {
		ledger_network_nonvolatile_compressed = get_task_network_nonvolatile_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_network_nonvolatile_compressed, sizeof(ledger_network_nonvolatile_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_WIRED_MEM, sizeof(ledger_wired_mem), &uaddr)) {
		ledger_wired_mem = get_task_wired_mem(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_wired_mem, sizeof(ledger_wired_mem));
	}

	bzero(&pwqinfo, sizeof(struct proc_workqueueinfo));
	retval = fill_procworkqueue(p, &pwqinfo);
	if (retval == 0) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_WORKQUEUEINFO, sizeof(struct proc_workqueueinfo), &uaddr)) {
			kcdata_memcpy(crash_info_ptr, uaddr, &pwqinfo, sizeof(struct proc_workqueueinfo));
		}
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_RESPONSIBLE_PID, sizeof(p->p_responsible_pid), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_responsible_pid, sizeof(p->p_responsible_pid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_PROC_PERSONA_ID, sizeof(uid_t), &uaddr)) {
		uid_t persona_id = proc_persona_id(p);
		kcdata_memcpy(crash_info_ptr, uaddr, &persona_id, sizeof(persona_id));
	}

#if CONFIG_COALITIONS
	if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(crash_info_ptr, TASK_CRASHINFO_COALITION_ID, sizeof(uint64_t), COALITION_NUM_TYPES, &uaddr)) {
		uint64_t coalition_ids[COALITION_NUM_TYPES];
		task_coalition_ids(proc_task(p), coalition_ids);
		kcdata_memcpy(crash_info_ptr, uaddr, coalition_ids, sizeof(coalition_ids));
	}
#endif /* CONFIG_COALITIONS */

#if CONFIG_MEMORYSTATUS
	memstat_dirty_flags = memorystatus_dirty_get(p, FALSE);
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_DIRTY_FLAGS, sizeof(memstat_dirty_flags), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &memstat_dirty_flags, sizeof(memstat_dirty_flags));
	}
#endif

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_MEMORY_LIMIT_INCREASE, sizeof(p->p_memlimit_increase), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_memlimit_increase, sizeof(p->p_memlimit_increase));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_TAGGED_FOOTPRINT, sizeof(ledger_tagged_footprint), &uaddr)) {
		ledger_tagged_footprint = get_task_tagged_footprint(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_tagged_footprint, sizeof(ledger_tagged_footprint));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_TAGGED_FOOTPRINT_COMPRESSED, sizeof(ledger_tagged_footprint_compressed), &uaddr)) {
		ledger_tagged_footprint_compressed = get_task_tagged_footprint_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_tagged_footprint_compressed, sizeof(ledger_tagged_footprint_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_MEDIA_FOOTPRINT, sizeof(ledger_media_footprint), &uaddr)) {
		ledger_media_footprint = get_task_media_footprint(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_media_footprint, sizeof(ledger_media_footprint));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_MEDIA_FOOTPRINT_COMPRESSED, sizeof(ledger_media_footprint_compressed), &uaddr)) {
		ledger_media_footprint_compressed = get_task_media_footprint_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_media_footprint_compressed, sizeof(ledger_media_footprint_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_GRAPHICS_FOOTPRINT, sizeof(ledger_graphics_footprint), &uaddr)) {
		ledger_graphics_footprint = get_task_graphics_footprint(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_graphics_footprint, sizeof(ledger_graphics_footprint));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED, sizeof(ledger_graphics_footprint_compressed), &uaddr)) {
		ledger_graphics_footprint_compressed = get_task_graphics_footprint_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_graphics_footprint_compressed, sizeof(ledger_graphics_footprint_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_NEURAL_FOOTPRINT, sizeof(ledger_neural_footprint), &uaddr)) {
		ledger_neural_footprint = get_task_neural_footprint(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_neural_footprint, sizeof(ledger_neural_footprint));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_LEDGER_NEURAL_FOOTPRINT_COMPRESSED, sizeof(ledger_neural_footprint_compressed), &uaddr)) {
		ledger_neural_footprint_compressed = get_task_neural_footprint_compressed(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &ledger_neural_footprint_compressed, sizeof(ledger_neural_footprint_compressed));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_MEMORYSTATUS_EFFECTIVE_PRIORITY, sizeof(p->p_memstat_effectivepriority), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_memstat_effectivepriority, sizeof(p->p_memstat_effectivepriority));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_KERNEL_TRIAGE_INFO_V1, sizeof(struct kernel_triage_info_v1), &uaddr)) {
		char triage_strings[KDBG_TRIAGE_MAX_STRINGS][KDBG_TRIAGE_MAX_STRLEN];
		ktriage_extract(thread_tid(current_thread()), triage_strings, KDBG_TRIAGE_MAX_STRINGS * KDBG_TRIAGE_MAX_STRLEN);
		kcdata_memcpy(crash_info_ptr, uaddr, (void*) triage_strings, sizeof(struct kernel_triage_info_v1));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_TASK_IS_CORPSE_FORK, sizeof(is_corpse_fork), &uaddr)) {
		is_corpse_fork = is_corpsefork(corpse_task);
		kcdata_memcpy(crash_info_ptr, uaddr, &is_corpse_fork, sizeof(is_corpse_fork));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_EXCEPTION_TYPE, sizeof(etype), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &etype, sizeof(etype));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CRASH_COUNT, sizeof(int), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_crash_count, sizeof(int));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_THROTTLE_TIMEOUT, sizeof(int), &uaddr)) {
		kcdata_memcpy(crash_info_ptr, uaddr, &p->p_throttle_timeout, sizeof(int));
	}

	char signing_id[MAX_CRASHINFO_SIGNING_ID_LEN] = {};
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CS_SIGNING_ID, sizeof(signing_id), &uaddr)) {
		const char * id = cs_identity_get(p);
		if (id) {
			strlcpy(signing_id, id, sizeof(signing_id));
		}
		kcdata_memcpy(crash_info_ptr, uaddr, &signing_id, sizeof(signing_id));
	}
	char team_id[MAX_CRASHINFO_TEAM_ID_LEN] = {};
	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CS_TEAM_ID, sizeof(team_id), &uaddr)) {
		const char * id = csproc_get_teamid(p);
		if (id) {
			strlcpy(team_id, id, sizeof(team_id));
		}
		kcdata_memcpy(crash_info_ptr, uaddr, &team_id, sizeof(team_id));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CS_VALIDATION_CATEGORY, sizeof(uint32_t), &uaddr)) {
		uint32_t category = 0;
		if (csproc_get_validation_category(p, &category) != KERN_SUCCESS) {
			category = CS_VALIDATION_CATEGORY_INVALID;
		}
		kcdata_memcpy(crash_info_ptr, uaddr, &category, sizeof(category));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, TASK_CRASHINFO_CS_TRUST_LEVEL, sizeof(uint32_t), &uaddr)) {
		uint32_t trust = 0;
		kern_return_t ret = get_trust_level_kdp(get_task_pmap(corpse_task), &trust);
		if (ret != KERN_SUCCESS) {
			trust = KCDATA_INVALID_CS_TRUST_LEVEL;
		}
		kcdata_memcpy(crash_info_ptr, uaddr, &trust, sizeof(trust));
	}


	if (p->p_exit_reason != OS_REASON_NULL && reason == OS_REASON_NULL) {
		reason = p->p_exit_reason;
	}
	if (reason != OS_REASON_NULL) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, EXIT_REASON_SNAPSHOT, sizeof(struct exit_reason_snapshot), &uaddr)) {
			struct exit_reason_snapshot ers = {
				.ers_namespace = reason->osr_namespace,
				.ers_code = reason->osr_code,
				.ers_flags = reason->osr_flags
			};

			kcdata_memcpy(crash_info_ptr, uaddr, &ers, sizeof(ers));
		}

		if (reason->osr_kcd_buf != 0) {
			uint32_t reason_buf_size = (uint32_t)kcdata_memory_get_used_bytes(&reason->osr_kcd_descriptor);
			assert(reason_buf_size != 0);

			if (KERN_SUCCESS == kcdata_get_memory_addr(crash_info_ptr, KCDATA_TYPE_NESTED_KCDATA, reason_buf_size, &uaddr)) {
				kcdata_memcpy(crash_info_ptr, uaddr, reason->osr_kcd_buf, reason_buf_size);
			}
		}
	}

	if (num_udata > 0) {
		if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(crash_info_ptr, TASK_CRASHINFO_UDATA_PTRS,
		    sizeof(uint64_t), num_udata, &uaddr)) {
			kcdata_memcpy(crash_info_ptr, uaddr, udata_buffer, sizeof(uint64_t) * num_udata);
		}
	}
}

exception_type_t
get_exception_from_corpse_crashinfo(kcdata_descriptor_t corpse_info)
{
	kcdata_iter_t iter = kcdata_iter((void *)corpse_info->kcd_addr_begin,
	    corpse_info->kcd_length);
	__assert_only uint32_t type = kcdata_iter_type(iter);
	assert(type == KCDATA_BUFFER_BEGIN_CRASHINFO);

	iter = kcdata_iter_find_type(iter, TASK_CRASHINFO_EXCEPTION_TYPE);
	exception_type_t *etype = kcdata_iter_payload(iter);
	return *etype;
}

/*
 * Collect information required for generating lightwight corpse for current
 * task, which can be terminating.
 */
kern_return_t
current_thread_collect_backtrace_info(
	kcdata_descriptor_t *new_desc,
	exception_type_t etype,
	mach_exception_data_t code,
	mach_msg_type_number_t codeCnt,
	void *reasonp)
{
	kcdata_descriptor_t kcdata;
	kern_return_t kr;
	int frame_count = 0, max_frames = 100;
	mach_vm_address_t uuid_info_addr = 0;
	uint32_t uuid_info_count         = 0;
	uint32_t btinfo_flag             = 0;
	mach_vm_address_t btinfo_flag_addr = 0, kaddr = 0;
	natural_t alloc_size = BTINFO_ALLOCATION_SIZE;
	mach_msg_type_number_t th_info_count = THREAD_IDENTIFIER_INFO_COUNT;
	thread_identifier_info_data_t th_info;
	char threadname[MAXTHREADNAMESIZE];
	void *btdata_kernel = NULL;
	typedef uintptr_t user_btframe_t __kernel_data_semantics;
	user_btframe_t *btframes = NULL;
	os_reason_t reason = (os_reason_t)reasonp;
	struct backtrace_user_info info = BTUINFO_INIT;
	struct rusage_superset rup;
	uint32_t platform;

	task_t task = current_task();
	proc_t p = current_proc();

	bool has_64bit_addr = task_get_64bit_addr(current_task());
	bool has_64bit_data = task_get_64bit_data(current_task());

	if (new_desc == NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	/* First, collect backtrace frames */
	btframes = kalloc_data(max_frames * sizeof(btframes[0]), Z_WAITOK | Z_ZERO);
	if (!btframes) {
		return KERN_RESOURCE_SHORTAGE;
	}

	frame_count = backtrace_user(btframes, max_frames, NULL, &info);
	if (info.btui_error || frame_count == 0) {
		kfree_data(btframes, max_frames * sizeof(btframes[0]));
		return KERN_FAILURE;
	}

	if ((info.btui_info & BTI_TRUNCATED) != 0) {
		btinfo_flag |= TASK_BTINFO_FLAG_BT_TRUNCATED;
	}

	/* Captured in kcdata descriptor below */
	btdata_kernel = kalloc_data(alloc_size, Z_WAITOK | Z_ZERO);
	if (!btdata_kernel) {
		kfree_data(btframes, max_frames * sizeof(btframes[0]));
		return KERN_RESOURCE_SHORTAGE;
	}

	kcdata = task_btinfo_alloc_init((mach_vm_address_t)btdata_kernel, alloc_size);
	if (!kcdata) {
		kfree_data(btdata_kernel, alloc_size);
		kfree_data(btframes, max_frames * sizeof(btframes[0]));
		return KERN_RESOURCE_SHORTAGE;
	}

	/* First reserve space in kcdata blob for the btinfo flag fields */
	if (KERN_SUCCESS != kcdata_get_memory_addr(kcdata, TASK_BTINFO_FLAGS,
	    sizeof(uint32_t), &btinfo_flag_addr)) {
		kfree_data(btdata_kernel, alloc_size);
		kfree_data(btframes, max_frames * sizeof(btframes[0]));
		kcdata_memory_destroy(kcdata);
		return KERN_RESOURCE_SHORTAGE;
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(kcdata,
	    (has_64bit_addr ? TASK_BTINFO_BACKTRACE64 : TASK_BTINFO_BACKTRACE),
	    sizeof(uintptr_t), frame_count, &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, btframes, sizeof(uintptr_t) * frame_count);
	}

#if __LP64__
	/* We only support async stacks on 64-bit kernels */
	frame_count = 0;

	if (info.btui_async_frame_addr != 0) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_ASYNC_START_INDEX,
		    sizeof(uint32_t), &kaddr)) {
			uint32_t idx = info.btui_async_start_index;
			kcdata_memcpy(kcdata, kaddr, &idx, sizeof(uint32_t));
		}
		struct backtrace_control ctl = {
			.btc_frame_addr = info.btui_async_frame_addr,
			.btc_addr_offset = BTCTL_ASYNC_ADDR_OFFSET,
		};

		info = BTUINFO_INIT;
		frame_count = backtrace_user(btframes, max_frames, &ctl, &info);
		if (info.btui_error == 0 && frame_count > 0) {
			if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(kcdata,
			    TASK_BTINFO_ASYNC_BACKTRACE64,
			    sizeof(uintptr_t), frame_count, &kaddr)) {
				kcdata_memcpy(kcdata, kaddr, btframes, sizeof(uintptr_t) * frame_count);
			}
		}

		if ((info.btui_info & BTI_TRUNCATED) != 0) {
			btinfo_flag |= TASK_BTINFO_FLAG_ASYNC_BT_TRUNCATED;
		}
	}
#endif

	/* Backtrace collection done, free the frames buffer */
	kfree_data(btframes, max_frames * sizeof(btframes[0]));
	btframes = NULL;

	thread_set_exec_promotion(current_thread());
	/* Next, suspend the task briefly and collect image load infos */
	task_suspend_internal(task);

	/* all_image_info struct is ABI, in agreement with address width */
	if (has_64bit_addr) {
		struct user64_dyld_all_image_infos task_image_infos = {};
		struct btinfo_sc_load_info64 sc_info;
		(void)copyin((user_addr_t)task_get_all_image_info_addr(task), &task_image_infos,
		    sizeof(struct user64_dyld_all_image_infos));
		uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
		uuid_info_addr = task_image_infos.uuidArray;

		sc_info.sharedCacheSlide = task_image_infos.sharedCacheSlide;
		sc_info.sharedCacheBaseAddress = task_image_infos.sharedCacheBaseAddress;
		memcpy(&sc_info.sharedCacheUUID, &task_image_infos.sharedCacheUUID,
		    sizeof(task_image_infos.sharedCacheUUID));

		if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata,
		    TASK_BTINFO_SC_LOADINFO64, sizeof(sc_info), &kaddr)) {
			kcdata_memcpy(kcdata, kaddr, &sc_info, sizeof(sc_info));
		}
	} else {
		struct user32_dyld_all_image_infos task_image_infos = {};
		struct btinfo_sc_load_info sc_info;
		(void)copyin((user_addr_t)task_get_all_image_info_addr(task), &task_image_infos,
		    sizeof(struct user32_dyld_all_image_infos));
		uuid_info_count = task_image_infos.uuidArrayCount;
		uuid_info_addr = task_image_infos.uuidArray;

		sc_info.sharedCacheSlide = task_image_infos.sharedCacheSlide;
		sc_info.sharedCacheBaseAddress = task_image_infos.sharedCacheBaseAddress;
		memcpy(&sc_info.sharedCacheUUID, &task_image_infos.sharedCacheUUID,
		    sizeof(task_image_infos.sharedCacheUUID));

		if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata,
		    TASK_BTINFO_SC_LOADINFO, sizeof(sc_info), &kaddr)) {
			kcdata_memcpy(kcdata, kaddr, &sc_info, sizeof(sc_info));
		}
	}

	if (!uuid_info_addr) {
		/*
		 * Can happen when we catch dyld in the middle of updating
		 * this data structure, or copyin of all_image_info struct failed.
		 */
		task_resume_internal(task);
		thread_clear_exec_promotion(current_thread());
		kfree_data(btdata_kernel, alloc_size);
		kcdata_memory_destroy(kcdata);
		return KERN_MEMORY_ERROR;
	}

	if (uuid_info_count > 0) {
		uint32_t uuid_info_size = (uint32_t)(has_64bit_addr ?
		    sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));

		if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(kcdata,
		    (has_64bit_addr ? TASK_BTINFO_DYLD_LOADINFO64 : TASK_BTINFO_DYLD_LOADINFO),
		    uuid_info_size, uuid_info_count, &kaddr)) {
			if (copyin((user_addr_t)uuid_info_addr, (void *)kaddr, uuid_info_size * uuid_info_count)) {
				task_resume_internal(task);
				thread_clear_exec_promotion(current_thread());
				kfree_data(btdata_kernel, alloc_size);
				kcdata_memory_destroy(kcdata);
				return KERN_MEMORY_ERROR;
			}
		}
	}

	task_resume_internal(task);
	thread_clear_exec_promotion(current_thread());

	/* Next, collect all other information */
	thread_flavor_t tsflavor;
	mach_msg_type_number_t tscount;

#if defined(__x86_64__) || defined(__i386__)
	tsflavor = x86_THREAD_STATE;      /* unified */
	tscount  = x86_THREAD_STATE_COUNT;
#else
	tsflavor = ARM_THREAD_STATE;      /* unified */
	tscount  = ARM_UNIFIED_THREAD_STATE_COUNT;
#endif

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_THREAD_STATE,
	    sizeof(struct btinfo_thread_state_data_t) + sizeof(int) * tscount, &kaddr)) {
		struct btinfo_thread_state_data_t *bt_thread_state = (struct btinfo_thread_state_data_t *)kaddr;
		bt_thread_state->flavor = tsflavor;
		bt_thread_state->count = tscount;
		/* variable-sized tstate array follows */

		kr = thread_getstatus_to_user(current_thread(), bt_thread_state->flavor,
		    (thread_state_t)&bt_thread_state->tstate, &bt_thread_state->count, TSSF_FLAGS_NONE);
		if (kr != KERN_SUCCESS) {
			bzero((void *)kaddr, sizeof(struct btinfo_thread_state_data_t) + sizeof(int) * tscount);
			if (kr == KERN_TERMINATED) {
				btinfo_flag |= TASK_BTINFO_FLAG_TASK_TERMINATED;
			}
		}
	}

#if defined(__x86_64__) || defined(__i386__)
	tsflavor = x86_EXCEPTION_STATE;       /* unified */
	tscount  = x86_EXCEPTION_STATE_COUNT;
#else
#if defined(__arm64__)
	if (has_64bit_data) {
		tsflavor = ARM_EXCEPTION_STATE64;
		tscount  = ARM_EXCEPTION_STATE64_COUNT;
	} else
#endif /* defined(__arm64__) */
	{
		tsflavor = ARM_EXCEPTION_STATE;
		tscount  = ARM_EXCEPTION_STATE_COUNT;
	}
#endif /* defined(__x86_64__) || defined(__i386__) */

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_THREAD_EXCEPTION_STATE,
	    sizeof(struct btinfo_thread_state_data_t) + sizeof(int) * tscount, &kaddr)) {
		struct btinfo_thread_state_data_t *bt_thread_state = (struct btinfo_thread_state_data_t *)kaddr;
		bt_thread_state->flavor = tsflavor;
		bt_thread_state->count = tscount;
		/* variable-sized tstate array follows */

		kr = thread_getstatus_to_user(current_thread(), bt_thread_state->flavor,
		    (thread_state_t)&bt_thread_state->tstate, &bt_thread_state->count, TSSF_FLAGS_NONE);
		if (kr != KERN_SUCCESS) {
			bzero((void *)kaddr, sizeof(struct btinfo_thread_state_data_t) + sizeof(int) * tscount);
			if (kr == KERN_TERMINATED) {
				btinfo_flag |= TASK_BTINFO_FLAG_TASK_TERMINATED;
			}
		}
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PID, sizeof(pid_t), &kaddr)) {
		pid_t pid = proc_getpid(p);
		kcdata_memcpy(kcdata, kaddr, &pid, sizeof(pid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PPID, sizeof(p->p_ppid), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_ppid, sizeof(p->p_ppid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PROC_NAME, sizeof(p->p_comm), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_comm, sizeof(p->p_comm));
	}

#if CONFIG_COALITIONS
	if (KERN_SUCCESS == kcdata_get_memory_addr_for_array(kcdata, TASK_BTINFO_COALITION_ID, sizeof(uint64_t), COALITION_NUM_TYPES, &kaddr)) {
		uint64_t coalition_ids[COALITION_NUM_TYPES];
		task_coalition_ids(proc_task(p), coalition_ids);
		kcdata_memcpy(kcdata, kaddr, coalition_ids, sizeof(coalition_ids));
	}
#endif /* CONFIG_COALITIONS */

	/* V0 is sufficient for ReportCrash */
	gather_rusage_info(current_proc(), &rup.ri, RUSAGE_INFO_V0);
	rup.ri.ri_phys_footprint = 0;
	/* Soft crash, proc did not exit */
	rup.ri.ri_proc_exit_abstime = 0;
	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_RUSAGE_INFO, sizeof(struct rusage_info_v0), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &rup.ri, sizeof(struct rusage_info_v0));
	}

	platform = proc_platform(current_proc());
	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PLATFORM, sizeof(platform), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &platform, sizeof(platform));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PROC_PATH, MAXPATHLEN, &kaddr)) {
		char *buf = zalloc_flags(ZV_NAMEI, Z_WAITOK | Z_ZERO);
		proc_pidpathinfo_internal(p, 0, buf, MAXPATHLEN, NULL);
		kcdata_memcpy(kcdata, kaddr, buf, MAXPATHLEN);
		zfree(ZV_NAMEI, buf);
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_UID, sizeof(p->p_uid), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_uid, sizeof(p->p_uid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_GID, sizeof(p->p_gid), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_gid, sizeof(p->p_gid));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_PROC_FLAGS, sizeof(unsigned int), &kaddr)) {
		unsigned int pflags = p->p_flag & (P_LP64 | P_SUGID | P_TRANSLATED);
		kcdata_memcpy(kcdata, kaddr, &pflags, sizeof(pflags));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_CPUTYPE, sizeof(cpu_type_t), &kaddr)) {
		cpu_type_t cputype = cpu_type() & ~CPU_ARCH_MASK;
		if (has_64bit_addr) {
			cputype |= CPU_ARCH_ABI64;
		} else if (has_64bit_data) {
			cputype |= CPU_ARCH_ABI64_32;
		}
		kcdata_memcpy(kcdata, kaddr, &cputype, sizeof(cpu_type_t));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_EXCEPTION_TYPE, sizeof(etype), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &etype, sizeof(etype));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_CRASH_COUNT, sizeof(int), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_crash_count, sizeof(int));
	}

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_THROTTLE_TIMEOUT, sizeof(int), &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, &p->p_throttle_timeout, sizeof(int));
	}

	assert(codeCnt <= EXCEPTION_CODE_MAX);

	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_EXCEPTION_CODES,
	    sizeof(mach_exception_code_t) * codeCnt, &kaddr)) {
		kcdata_memcpy(kcdata, kaddr, code, sizeof(mach_exception_code_t) * codeCnt);
	}

	if (reason != OS_REASON_NULL) {
		if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, EXIT_REASON_SNAPSHOT, sizeof(struct exit_reason_snapshot), &kaddr)) {
			struct exit_reason_snapshot ers = {
				.ers_namespace = reason->osr_namespace,
				.ers_code = reason->osr_code,
				.ers_flags = reason->osr_flags
			};

			kcdata_memcpy(kcdata, kaddr, &ers, sizeof(ers));
		}

		if (reason->osr_kcd_buf != 0) {
			uint32_t reason_buf_size = (uint32_t)kcdata_memory_get_used_bytes(&reason->osr_kcd_descriptor);
			assert(reason_buf_size != 0);

			if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, KCDATA_TYPE_NESTED_KCDATA, reason_buf_size, &kaddr)) {
				kcdata_memcpy(kcdata, kaddr, reason->osr_kcd_buf, reason_buf_size);
			}
		}
	}

	threadname[0] = '\0';
	if (KERN_SUCCESS == kcdata_get_memory_addr(kcdata, TASK_BTINFO_THREAD_NAME,
	    sizeof(threadname), &kaddr)) {
		bsd_getthreadname(get_bsdthread_info(current_thread()), threadname);
		kcdata_memcpy(kcdata, kaddr, threadname, sizeof(threadname));
	}

	kr = thread_info(current_thread(), THREAD_IDENTIFIER_INFO, (thread_info_t)&th_info, &th_info_count);
	if (kr == KERN_TERMINATED) {
		btinfo_flag |= TASK_BTINFO_FLAG_TASK_TERMINATED;
	}


	kern_return_t last_kr = kcdata_get_memory_addr(kcdata, TASK_BTINFO_THREAD_ID,
	    sizeof(uint64_t), &kaddr);

	/*
	 * If the last kcdata_get_memory_addr() failed (unlikely), signal to exception
	 * handler (ReportCrash) that lw corpse collection ran out of space and the
	 * result is incomplete.
	 */
	if (last_kr != KERN_SUCCESS) {
		btinfo_flag |= TASK_BTINFO_FLAG_KCDATA_INCOMPLETE;
	}

	if (KERN_SUCCESS == kr && KERN_SUCCESS == last_kr) {
		kcdata_memcpy(kcdata, kaddr, &th_info.thread_id, sizeof(uint64_t));
	}

	/* Lastly, copy the flags to the address we reserved at the beginning. */
	kcdata_memcpy(kcdata, btinfo_flag_addr, &btinfo_flag, sizeof(uint32_t));

	*new_desc = kcdata;

	return KERN_SUCCESS;
}

/*
 * We only parse exit reason kcdata blobs for critical process before they die
 * and we're going to panic or for opt-in, limited diagnostic tools.
 *
 * Meant to be called immediately before panicking or limited diagnostic
 * scenarios.
 */
char *
exit_reason_get_string_desc(os_reason_t exit_reason)
{
	kcdata_iter_t iter;

	if (exit_reason == OS_REASON_NULL || exit_reason->osr_kcd_buf == NULL ||
	    exit_reason->osr_bufsize == 0) {
		return NULL;
	}

	iter = kcdata_iter(exit_reason->osr_kcd_buf, exit_reason->osr_bufsize);
	if (!kcdata_iter_valid(iter)) {
#if DEBUG || DEVELOPMENT
		printf("exit reason has invalid exit reason buffer\n");
#endif
		return NULL;
	}

	if (kcdata_iter_type(iter) != KCDATA_BUFFER_BEGIN_OS_REASON) {
#if DEBUG || DEVELOPMENT
		printf("exit reason buffer type mismatch, expected %d got %d\n",
		    KCDATA_BUFFER_BEGIN_OS_REASON, kcdata_iter_type(iter));
#endif
		return NULL;
	}

	iter = kcdata_iter_find_type(iter, EXIT_REASON_USER_DESC);
	if (!kcdata_iter_valid(iter)) {
		return NULL;
	}

	return (char *)kcdata_iter_payload(iter);
}

static int initproc_spawned = 0;

static int
sysctl_initproc_spawned(struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	if (req->newptr != 0 && (proc_getpid(req->p) != 1 || initproc_spawned != 0)) {
		// Can only ever be set by launchd, and only once at boot
		return EPERM;
	}
	return sysctl_handle_int(oidp, &initproc_spawned, 0, req);
}

SYSCTL_PROC(_kern, OID_AUTO, initproc_spawned,
    CTLFLAG_RW | CTLFLAG_KERN | CTLTYPE_INT | CTLFLAG_LOCKED, 0, 0,
    sysctl_initproc_spawned, "I", "Boolean indicator that launchd has reached main");

#if DEVELOPMENT || DEBUG

/* disable user faults */
static TUNABLE(bool, bootarg_disable_user_faults, "-disable_user_faults", false);
#endif /* DEVELOPMENT || DEBUG */

#define OS_REASON_IFLAG_USER_FAULT 0x1

#define OS_REASON_TOTAL_USER_FAULTS_PER_PROC  5

static int
abort_with_payload_internal(proc_t p,
    uint32_t reason_namespace, uint64_t reason_code,
    user_addr_t payload, uint32_t payload_size,
    user_addr_t reason_string, uint64_t reason_flags,
    uint32_t internal_flags)
{
	os_reason_t exit_reason = OS_REASON_NULL;
	kern_return_t kr = KERN_SUCCESS;

	if (internal_flags & OS_REASON_IFLAG_USER_FAULT) {
		uint32_t old_value = atomic_load_explicit(&p->p_user_faults,
		    memory_order_relaxed);

#if DEVELOPMENT || DEBUG
		if (bootarg_disable_user_faults) {
			return EQFULL;
		}
#endif /* DEVELOPMENT || DEBUG */

		for (;;) {
			if (old_value >= OS_REASON_TOTAL_USER_FAULTS_PER_PROC) {
				return EQFULL;
			}
			// this reloads the value in old_value
			if (atomic_compare_exchange_strong_explicit(&p->p_user_faults,
			    &old_value, old_value + 1, memory_order_relaxed,
			    memory_order_relaxed)) {
				break;
			}
		}
	}

	KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_CREATE) | DBG_FUNC_NONE,
	    proc_getpid(p), reason_namespace,
	    reason_code, 0, 0);

	exit_reason = build_userspace_exit_reason(reason_namespace, reason_code,
	    payload, payload_size, reason_string, reason_flags | OS_REASON_FLAG_ABORT);

	if (internal_flags & OS_REASON_IFLAG_USER_FAULT) {
		mach_exception_code_t code = 0;

		EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_USER); /* simulated EXC_GUARD */
		EXC_GUARD_ENCODE_FLAVOR(code, 0);
		EXC_GUARD_ENCODE_TARGET(code, reason_namespace);

		if (exit_reason == OS_REASON_NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
		} else {
			kr = task_violated_guard(code, reason_code, exit_reason, TRUE);
		}
		os_reason_free(exit_reason);
	} else {
		/*
		 * We use SIGABRT (rather than calling exit directly from here) so that
		 * the debugger can catch abort_with_{reason,payload} calls.
		 */
		psignal_try_thread_with_reason(p, current_thread(), SIGABRT, exit_reason);
	}

	switch (kr) {
	case KERN_SUCCESS:
		return 0;
	case KERN_NOT_SUPPORTED:
		return ENOTSUP;
	case KERN_INVALID_ARGUMENT:
		return EINVAL;
	case KERN_RESOURCE_SHORTAGE:
	default:
		return EBUSY;
	}
}

int
abort_with_payload(struct proc *cur_proc, struct abort_with_payload_args *args,
    __unused void *retval)
{
	abort_with_payload_internal(cur_proc, args->reason_namespace,
	    args->reason_code, args->payload, args->payload_size,
	    args->reason_string, args->reason_flags, 0);

	return 0;
}

int
os_fault_with_payload(struct proc *cur_proc,
    struct os_fault_with_payload_args *args, __unused int *retval)
{
	return abort_with_payload_internal(cur_proc, args->reason_namespace,
	           args->reason_code, args->payload, args->payload_size,
	           args->reason_string, args->reason_flags, OS_REASON_IFLAG_USER_FAULT);
}


/*
 * exit --
 *	Death of process.
 */
__attribute__((noreturn))
void
exit(proc_t p, struct exit_args *uap, int *retval)
{
	p->p_xhighbits = ((uint32_t)(uap->rval) & 0xFF000000) >> 24;
	exit1(p, W_EXITCODE((uint32_t)uap->rval, 0), retval);

	thread_exception_return();
	/* NOTREACHED */
	while (TRUE) {
		thread_block(THREAD_CONTINUE_NULL);
	}
	/* NOTREACHED */
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */
int
exit1(proc_t p, int rv, int *retval)
{
	return exit1_internal(p, rv, retval, FALSE, TRUE, 0);
}

int
exit1_internal(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,
    int jetsam_flags)
{
	return exit_with_reason(p, rv, retval, thread_can_terminate, perf_notify, jetsam_flags, OS_REASON_NULL);
}

/*
 * NOTE: exit_with_reason drops a reference on the passed exit_reason
 */
int
exit_with_reason(proc_t p, int rv, int *retval, boolean_t thread_can_terminate, boolean_t perf_notify,
    int jetsam_flags, struct os_reason *exit_reason)
{
	thread_t self = current_thread();
	struct task *task = proc_task(p);
	struct uthread *ut;
	int error = 0;
	bool proc_exiting = false;

#if DEVELOPMENT || DEBUG
	/*
	 * Debug boot-arg: panic here if matching process is exiting with non-zero code.
	 * Example usage: panic_on_error_exit=launchd,logd,watchdogd
	 */
	if (rv && strnstr(panic_on_eexit_pcomms, p->p_comm, sizeof(panic_on_eexit_pcomms))) {
		panic("%s: Process %s with pid %d exited on error with code 0x%x.",
		    __FUNCTION__, p->p_comm, proc_getpid(p), rv);
	}
#endif

	/*
	 * If a thread in this task has already
	 * called exit(), then halt any others
	 * right here.
	 */

	ut = get_bsdthread_info(self);
	(void)retval;

	/*
	 * The parameter list of audit_syscall_exit() was augmented to
	 * take the Darwin syscall number as the first parameter,
	 * which is currently required by mac_audit_postselect().
	 */

	/*
	 * The BSM token contains two components: an exit status as passed
	 * to exit(), and a return value to indicate what sort of exit it
	 * was.  The exit status is WEXITSTATUS(rv), but it's not clear
	 * what the return value is.
	 */
	AUDIT_ARG(exit, WEXITSTATUS(rv), 0);
	/*
	 * TODO: what to audit here when jetsam calls exit and the uthread,
	 * 'ut' does not belong to the proc, 'p'.
	 */
	AUDIT_SYSCALL_EXIT(SYS_exit, p, ut, 0); /* Exit is always successfull */

	DTRACE_PROC1(exit, int, CLD_EXITED);

	/* mark process is going to exit and pull out of DBG/disk throttle */
	/* TODO: This should be done after becoming exit thread */
	proc_set_task_policy(proc_task(p), TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

	proc_lock(p);
	error = proc_transstart(p, 1, (jetsam_flags ? 1 : 0));
	if (error == EDEADLK) {
		/*
		 * If proc_transstart() returns EDEADLK, then another thread
		 * is either exec'ing or exiting. Return an error and allow
		 * the other thread to continue.
		 */
		proc_unlock(p);
		os_reason_free(exit_reason);
		if (current_proc() == p) {
			if (p->exit_thread == self) {
				panic("exit_thread failed to exit");
			}

			if (thread_can_terminate) {
				thread_exception_return();
			}
		}

		return error;
	}

	proc_exiting = !!(p->p_lflag & P_LEXIT);

	while (proc_exiting || p->exit_thread != self) {
		if (proc_exiting || sig_try_locked(p) <= 0) {
			proc_transend(p, 1);
			os_reason_free(exit_reason);

			if (get_threadtask(self) != task) {
				proc_unlock(p);
				return 0;
			}
			proc_unlock(p);

			thread_terminate(self);
			if (!thread_can_terminate) {
				return 0;
			}

			thread_exception_return();
			/* NOTREACHED */
		}
		sig_lock_to_exit(p);
	}

	if (exit_reason != OS_REASON_NULL) {
		KERNEL_DEBUG_CONSTANT(BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXITREASON_COMMIT) | DBG_FUNC_NONE,
		    proc_getpid(p), exit_reason->osr_namespace,
		    exit_reason->osr_code, 0, 0);
	}

	assert(p->p_exit_reason == OS_REASON_NULL);
	p->p_exit_reason = exit_reason;

	p->p_lflag |= P_LEXIT;
	p->p_xstat = rv;
	p->p_lflag |= jetsam_flags;

	proc_transend(p, 1);
	proc_unlock(p);

	proc_prepareexit(p, rv, perf_notify);

	/* Last thread to terminate will call proc_exit() */
	task_terminate_internal(task);

	return 0;
}

#if CONFIG_MEMORYSTATUS
/*
 * Remove this process from jetsam bands for freezing or exiting. Note this will block, if the process
 * is currently being frozen.
 * The proc_list_lock is held by the caller.
 * NB: If the process should be ineligible for future freezing or jetsaming the caller should first set
 * the p_refcount P_REF_DEAD bit.
 */
static void
proc_memorystatus_remove(proc_t p)
{
	LCK_MTX_ASSERT(&proc_list_mlock, LCK_MTX_ASSERT_OWNED);
	while (memorystatus_remove(p) == EAGAIN) {
		os_log(OS_LOG_DEFAULT, "memorystatus_remove: Process[%d] tried to exit while being frozen. Blocking exit until freeze completes.", proc_getpid(p));
		msleep(&p->p_memstat_state, &proc_list_mlock, PWAIT, "proc_memorystatus_remove", NULL);
	}
}
#endif

#if DEVELOPMENT
boolean_t crash_behavior_test_mode = FALSE;
boolean_t crash_behavior_test_would_panic = FALSE;
SYSCTL_UINT(_kern, OID_AUTO, crash_behavior_test_mode, CTLFLAG_RW, &crash_behavior_test_mode, 0, "");
SYSCTL_UINT(_kern, OID_AUTO, crash_behavior_test_would_panic, CTLFLAG_RW, &crash_behavior_test_would_panic, 0, "");
#endif /* DEVELOPMENT */

static bool
_proc_is_crashing_signal(int sig)
{
	bool result = false;
	switch (sig) {
	case SIGILL:
	case SIGABRT:
	case SIGFPE:
	case SIGBUS:
	case SIGSEGV:
	case SIGSYS:
	/*
	 * If SIGTRAP is the terminating signal, then we can safely assume the
	 * process crashed. (On iOS, SIGTRAP will be the terminating signal when
	 * a process calls __builtin_trap(), which will abort.)
	 */
	case SIGTRAP:
		result = true;
	}

	return result;
}

static bool
_proc_is_fatal_reason(os_reason_t reason)
{
	if ((reason->osr_flags & OS_REASON_FLAG_ABORT) != 0) {
		/* Abort is always fatal even if there is no crash report generated */
		return true;
	}
	if ((reason->osr_flags & OS_REASON_FLAG_NO_CRASH_REPORT) != 0) {
		/*
		 * No crash report means this reason shouldn't be considered fatal
		 * unless we are in test mode
		 */
#if DEVELOPMENT
		if (crash_behavior_test_mode) {
			return true;
		}
#endif /* DEVELOPMENT */
		return false;
	}
	// By default all OS_REASON are fatal
	return true;
}

static TUNABLE(bool, panic_on_crash_disabled, "panic_on_crash_disabled", false);

static bool
proc_should_trigger_panic(proc_t p, int rv)
{
	if (p == initproc) {
		/* Always panic for launchd */
		return true;
	}

	if (panic_on_crash_disabled) {
		printf("panic-on-crash disabled via boot-arg\n");
		return false;
	}

	if ((p->p_crash_behavior & POSIX_SPAWN_PANIC_ON_EXIT) != 0) {
		return true;
	}

	if ((p->p_crash_behavior & POSIX_SPAWN_PANIC_ON_SPAWN_FAIL) != 0) {
		return true;
	}

	if (p->p_posix_spawn_failed) {
		/* posix_spawn failures normally don't qualify for panics */
		return false;
	}

	bool deadline_expired = (mach_continuous_time() > p->p_crash_behavior_deadline);
	if (p->p_crash_behavior_deadline != 0 && deadline_expired) {
		return false;
	}

	if (WIFEXITED(rv)) {
		int code = WEXITSTATUS(rv);

		if ((p->p_crash_behavior & POSIX_SPAWN_PANIC_ON_NON_ZERO_EXIT) != 0) {
			if (code == 0) {
				/* No panic if we exit 0 */
				return false;
			} else {
				/* Panic on non-zero exit */
				return true;
			}
		} else {
			/* No panic on normal exit if the process doesn't have the non-zero flag set */
			return false;
		}
	} else if (WIFSIGNALED(rv)) {
		int signal = WTERMSIG(rv);
		/* This is a crash (non-normal exit) */
		if ((p->p_crash_behavior & POSIX_SPAWN_PANIC_ON_CRASH) != 0) {
			os_reason_t reason = p->p_exit_reason;
			if (reason != OS_REASON_NULL) {
				if (!_proc_is_fatal_reason(reason)) {
					// Skip non-fatal terminate_with_reason
					return false;
				}
				if (reason->osr_namespace == OS_REASON_SIGNAL) {
					/*
					 * OS_REASON_SIGNAL delivers as a SIGKILL with the actual signal
					 * in osr_code, so we should check that signal here
					 */
					return _proc_is_crashing_signal((int)reason->osr_code);
				} else {
					/*
					 * This branch covers the case of terminate_with_reason which
					 * delivers a SIGTERM which is still considered a crash even
					 * thought the signal is not considered a crashing signal
					 */
					return true;
				}
			}
			return _proc_is_crashing_signal(signal);
		} else {
			return false;
		}
	} else {
		/*
		 * This branch implies that we didn't exit normally nor did we receive
		 * a signal. This should be unreachable.
		 */
		return true;
	}
}

static void
proc_crash_coredump(proc_t p)
{
	(void)p;
#if (DEVELOPMENT || DEBUG) && CONFIG_COREDUMP
	/*
	 * For debugging purposes, generate a core file of initproc before
	 * panicking. Leave at least 300 MB free on the root volume, and ignore
	 * the process's corefile ulimit. fsync() the file to ensure it lands on disk
	 * before the panic hits.
	 */

	int             err;
	uint64_t        coredump_start = mach_absolute_time();
	uint64_t        coredump_end;
	clock_sec_t     tv_sec;
	clock_usec_t    tv_usec;
	uint32_t        tv_msec;


	err = coredump(p, 300, COREDUMP_IGNORE_ULIMIT | COREDUMP_FULLFSYNC);

	coredump_end = mach_absolute_time();

	absolutetime_to_microtime(coredump_end - coredump_start, &tv_sec, &tv_usec);

	tv_msec = tv_usec / 1000;

	if (err != 0) {
		printf("Failed to generate core file for pid: %d: error %d, took %d.%03d seconds\n",
		    proc_getpid(p), err, (uint32_t)tv_sec, tv_msec);
	} else {
		printf("Generated core file for pid: %d in %d.%03d seconds\n",
		    proc_getpid(p), (uint32_t)tv_sec, tv_msec);
	}
#endif /* (DEVELOPMENT || DEBUG) && CONFIG_COREDUMP */
}

static void
proc_handle_critical_exit(proc_t p, int rv)
{
	if (!proc_should_trigger_panic(p, rv)) {
		// No panic, bail out
		return;
	}

#if DEVELOPMENT
	if (crash_behavior_test_mode) {
		crash_behavior_test_would_panic = TRUE;
		// Force test mode off after hitting a panic
		crash_behavior_test_mode = FALSE;
		return;
	}
#endif /* DEVELOPMENT */

	char *exit_reason_desc = exit_reason_get_string_desc(p->p_exit_reason);

	if (p->p_exit_reason == OS_REASON_NULL) {
		printf("pid %d exited -- no exit reason available -- (signal %d, exit %d)\n",
		    proc_getpid(p), WTERMSIG(rv), WEXITSTATUS(rv));
	} else {
		printf("pid %d exited -- exit reason namespace %d subcode 0x%llx, description %s\n", proc_getpid(p),
		    p->p_exit_reason->osr_namespace, p->p_exit_reason->osr_code, exit_reason_desc ?
		    exit_reason_desc : "none");
	}

	const char *prefix_str;
	char prefix_str_buf[128];

	if (p == initproc) {
		if (strnstr(p->p_name, "preinit", sizeof(p->p_name))) {
			prefix_str = "LTE preinit process exited";
		} else if (initproc_spawned) {
			prefix_str = "initproc exited";
		} else {
			prefix_str = "initproc failed to start";
		}
	} else {
		/* For processes that aren't launchd, just use the process name and pid */
		snprintf(prefix_str_buf, sizeof(prefix_str_buf), "%s[%d] exited", p->p_name, proc_getpid(p));
		prefix_str = prefix_str_buf;
	}

	proc_crash_coredump(p);

	sync(p, (void *)NULL, (int *)NULL);

	if (p->p_exit_reason == OS_REASON_NULL) {
		panic_with_options(0, NULL, DEBUGGER_OPTION_INITPROC_PANIC, "%s -- no exit reason available -- (signal %d, exit status %d %s)",
		    prefix_str, WTERMSIG(rv), WEXITSTATUS(rv), ((proc_getcsflags(p) & CS_KILLED) ? "CS_KILLED" : ""));
	} else {
		panic_with_options(0, NULL, DEBUGGER_OPTION_INITPROC_PANIC, "%s %s -- exit reason namespace %d subcode 0x%llx description: %." LAUNCHD_PANIC_REASON_STRING_MAXLEN "s",
		    ((proc_getcsflags(p) & CS_KILLED) ? "CS_KILLED" : ""),
		    prefix_str, p->p_exit_reason->osr_namespace, p->p_exit_reason->osr_code,
		    exit_reason_desc ? exit_reason_desc : "none");
	}
}

void
proc_prepareexit(proc_t p, int rv, boolean_t perf_notify)
{
	mach_exception_data_type_t code = 0, subcode = 0;
	exception_type_t etype;

	struct uthread *ut;
	thread_t self = current_thread();
	ut = get_bsdthread_info(self);
	struct rusage_superset *rup;
	int kr = 0;
	int create_corpse = FALSE;
	bool corpse_source = false;
	task_t task = proc_task(p);


	if (p->p_crash_behavior != 0 || p == initproc) {
		proc_handle_critical_exit(p, rv);
	}

	if (task) {
		corpse_source = vm_map_is_corpse_source(get_task_map(task));
	}

	/*
	 * Generate a corefile/crashlog if:
	 *      The process doesn't have an exit reason that indicates no crash report should be created
	 *      AND any of the following are true:
	 *	- The process was terminated due to a fatal signal that generates a core
	 *	- The process was killed due to a code signing violation
	 *	- The process has an exit reason that indicates we should generate a crash report
	 *
	 * The first condition is necessary because abort_with_reason()/payload() use SIGABRT
	 * (which normally triggers a core) but may indicate that no crash report should be created.
	 */
	if (!(PROC_HAS_EXITREASON(p) && (PROC_EXITREASON_FLAGS(p) & OS_REASON_FLAG_NO_CRASH_REPORT)) &&
	    (hassigprop(WTERMSIG(rv), SA_CORE) || ((proc_getcsflags(p) & CS_KILLED) != 0) ||
	    (PROC_HAS_EXITREASON(p) && (PROC_EXITREASON_FLAGS(p) &
	    OS_REASON_FLAG_GENERATE_CRASH_REPORT)))) {
		/*
		 * Workaround for processes checking up on PT_DENY_ATTACH:
		 * should be backed out post-Leopard (details in 5431025).
		 */
		if ((SIGSEGV == WTERMSIG(rv)) &&
		    (p->p_pptr->p_lflag & P_LNOATTACH)) {
			goto skipcheck;
		}

		/*
		 * Crash Reporter looks for the signal value, original exception
		 * type, and low 20 bits of the original code in code[0]
		 * (8, 4, and 20 bits respectively). code[1] is unmodified.
		 */
		code = ((WTERMSIG(rv) & 0xff) << 24) |
		    ((ut->uu_exception & 0x0f) << 20) |
		    ((int)ut->uu_code & 0xfffff);
		subcode = ut->uu_subcode;
		etype = ut->uu_exception;

		/* Defualt to EXC_CRASH if the exception is not an EXC_RESOURCE or EXC_GUARD */
		if (etype != EXC_RESOURCE || etype != EXC_GUARD) {
			etype = EXC_CRASH;
		}

#if (DEVELOPMENT || DEBUG)
		if (p->p_pid <= exception_log_max_pid) {
			char *proc_name = proc_best_name(p);
			if (PROC_HAS_EXITREASON(p)) {
				record_system_event(SYSTEM_EVENT_TYPE_INFO, SYSTEM_EVENT_SUBSYSTEM_PROCESS, "process exit",
				    "pid: %d -- process name: %s -- exit reason namespace: %d -- subcode: 0x%llx -- description: %s",
				    proc_getpid(p), proc_name, p->p_exit_reason->osr_namespace, p->p_exit_reason->osr_code,
				    exit_reason_get_string_desc(p->p_exit_reason));
			} else {
				record_system_event(SYSTEM_EVENT_TYPE_INFO, SYSTEM_EVENT_SUBSYSTEM_PROCESS, "process exit",
				    "pid: %d -- process name: %s -- exit status %d",
				    proc_getpid(p), proc_name, WEXITSTATUS(rv));
			}
		}
#endif
		const bool fatal = false;
		kr = task_exception_notify(EXC_CRASH, code, subcode, fatal);
		/* Nobody handled EXC_CRASH?? remember to make corpse */
		if ((kr != 0 || corpse_source) && p == current_proc()) {
			/*
			 * Do not create corpse when exit is called from jetsam thread.
			 * Corpse creation code requires that proc_prepareexit is
			 * called by the exiting proc and not the kernel_proc.
			 */
			create_corpse = TRUE;
		}

		/*
		 * Revalidate the code signing of the text pages around current PC.
		 * This is an attempt to detect and repair faults due to memory
		 * corruption of text pages.
		 *
		 * The goal here is to fixup infrequent memory corruptions due to
		 * things like aging RAM bit flips. So the approach is to only expect
		 * to have to fixup one thing per crash. This also limits the amount
		 * of extra work we cause in case this is a development kernel with an
		 * active memory stomp happening.
		 */
		uintptr_t bt[2];
		struct backtrace_user_info btinfo = BTUINFO_INIT;
		unsigned int frame_count = backtrace_user(bt, 2, NULL, &btinfo);
		int bt_err = btinfo.btui_error;
		if (bt_err == 0 && frame_count >= 1) {
			/*
			 * First check at the page containing the current PC.
			 * This passes if the page code signs -or- if we can't figure out
			 * what is at that address. The latter action is so we continue checking
			 * previous pages which may be corrupt and caused a wild branch.
			 */
			kr = revalidate_text_page(task, bt[0]);

			/* No corruption found, check the previous sequential page */
			if (kr == KERN_SUCCESS) {
				kr = revalidate_text_page(task, bt[0] - get_task_page_size(task));
			}

			/* Still no corruption found, check the current function's caller */
			if (kr == KERN_SUCCESS) {
				if (frame_count > 1 &&
				    atop(bt[0]) != atop(bt[1]) &&           /* don't recheck PC page */
				    atop(bt[0]) - 1 != atop(bt[1])) {       /* don't recheck page before */
					kr = revalidate_text_page(task, (vm_map_offset_t)bt[1]);
				}
			}

			/*
			 * Log that we found a corruption.
			 */
			if (kr != KERN_SUCCESS) {
				os_log(OS_LOG_DEFAULT,
				    "Text page corruption detected in dying process %d\n", proc_getpid(p));
			}
		}
	}

skipcheck:
	if (task_is_driver(task) && PROC_HAS_EXITREASON(p)) {
		IOUserServerRecordExitReason(task, p->p_exit_reason);
	}

	/* Notify the perf server? */
	if (perf_notify) {
		(void)sys_perf_notify(self, proc_getpid(p));
	}


	/* stash the usage into corpse data if making_corpse == true */
	if (create_corpse == TRUE) {
		kr = task_mark_corpse(task);
		if (kr != KERN_SUCCESS) {
			if (kr == KERN_NO_SPACE) {
				printf("Process[%d] has no vm space for corpse info.\n", proc_getpid(p));
			} else if (kr == KERN_NOT_SUPPORTED) {
				printf("Process[%d] was destined to be corpse. But corpse is disabled by config.\n", proc_getpid(p));
			} else if (kr == KERN_TERMINATED) {
				printf("Process[%d] has been terminated before it could be converted to a corpse.\n", proc_getpid(p));
			} else {
				printf("Process[%d] crashed: %s. Too many corpses being created.\n", proc_getpid(p), p->p_comm);
			}
			create_corpse = FALSE;
		}
	}

	if (corpse_source && !create_corpse) {
		/* vm_map was marked for corpse, but we decided to not create one, unmark the vmmap */
		vm_map_unset_corpse_source(get_task_map(task));
	}

	if (!proc_is_shadow(p)) {
		/*
		 * Before this process becomes a zombie, stash resource usage
		 * stats in the proc for external observers to query
		 * via proc_pid_rusage().
		 *
		 * If the zombie allocation fails, just punt the stats.
		 */
		rup = zalloc(zombie_zone);
		gather_rusage_info(p, &rup->ri, RUSAGE_INFO_CURRENT);
		rup->ri.ri_phys_footprint = 0;
		rup->ri.ri_proc_exit_abstime = mach_absolute_time();
		/*
		 * Make the rusage_info visible to external observers
		 * only after it has been completely filled in.
		 */
		p->p_ru = rup;
	}

	if (create_corpse) {
		int est_knotes = 0, num_knotes = 0;
		uint64_t *buffer = NULL;
		uint32_t buf_size = 0;

		/* Get all the udata pointers from kqueue */
		est_knotes = kevent_proc_copy_uptrs(p, NULL, 0);
		if (est_knotes > 0) {
			buf_size = (uint32_t)((est_knotes + 32) * sizeof(uint64_t));
			buffer = kalloc_data(buf_size, Z_WAITOK);
			if (buffer) {
				num_knotes = kevent_proc_copy_uptrs(p, buffer, buf_size);
				if (num_knotes > est_knotes + 32) {
					num_knotes = est_knotes + 32;
				}
			}
		}

		/* Update the code, subcode based on exit reason */
		proc_update_corpse_exception_codes(p, &code, &subcode);
		populate_corpse_crashinfo(p, task, rup,
		    code, subcode, buffer, num_knotes, NULL, etype);
		kfree_data(buffer, buf_size);
	}
	/*
	 * Remove proc from allproc queue and from pidhash chain.
	 * Need to do this before we do anything that can block.
	 * Not doing causes things like mount() find this on allproc
	 * in partially cleaned state.
	 */

	proc_list_lock();

#if CONFIG_MEMORYSTATUS
	proc_memorystatus_remove(p);
#endif

	LIST_REMOVE(p, p_list);
	LIST_INSERT_HEAD(&zombproc, p, p_list); /* Place onto zombproc. */
	/* will not be visible via proc_find */
	os_atomic_or(&p->p_refcount, P_REF_DEAD, relaxed);

	proc_list_unlock();

	/*
	 * If parent is waiting for us to exit or exec,
	 * P_LPPWAIT is set; we will wakeup the parent below.
	 */
	proc_lock(p);
	p->p_lflag &= ~(P_LTRACED | P_LPPWAIT);
	p->p_sigignore = ~(sigcantmask);

	/*
	 * If a thread is already waiting for us in proc_exit,
	 * P_LTERM is set, wakeup the thread.
	 */
	if (p->p_lflag & P_LTERM) {
		wakeup(&p->exit_thread);
	} else {
		p->p_lflag |= P_LTERM;
	}

	/* If current proc is exiting, ignore signals on the exit thread */
	if (p == current_proc()) {
		ut->uu_siglist = 0;
	}
	proc_unlock(p);
}

void
proc_exit(proc_t p)
{
	proc_t q;
	proc_t pp;
	struct task *task = proc_task(p);
	vnode_t tvp = NULLVP;
	struct pgrp * pg;
	struct session *sessp;
	struct uthread * uth;
	pid_t pid;
	int exitval;
	int knote_hint;

	uth = current_uthread();

	proc_lock(p);
	proc_transstart(p, 1, 0);
	if (!(p->p_lflag & P_LEXIT)) {
		/*
		 * This can happen if a thread_terminate() occurs
		 * in a single-threaded process.
		 */
		p->p_lflag |= P_LEXIT;
		proc_transend(p, 1);
		proc_unlock(p);
		proc_prepareexit(p, 0, TRUE);
		(void) task_terminate_internal(task);
		proc_lock(p);
	} else if (!(p->p_lflag & P_LTERM)) {
		proc_transend(p, 1);
		/* Jetsam is in middle of calling proc_prepareexit, wait for it */
		p->p_lflag |= P_LTERM;
		msleep(&p->exit_thread, &p->p_mlock, PWAIT, "proc_prepareexit_wait", NULL);
	} else {
		proc_transend(p, 1);
	}

	p->p_lflag |= P_LPEXIT;

	/*
	 * Other kernel threads may be in the middle of signalling this process.
	 * Wait for those threads to wrap it up before making the process
	 * disappear on them.
	 */
	if ((p->p_lflag & P_LINSIGNAL) || (p->p_sigwaitcnt > 0)) {
		p->p_sigwaitcnt++;
		while ((p->p_lflag & P_LINSIGNAL) || (p->p_sigwaitcnt > 1)) {
			msleep(&p->p_sigmask, &p->p_mlock, PWAIT, "proc_sigdrain", NULL);
		}
		p->p_sigwaitcnt--;
	}

	proc_unlock(p);
	pid = proc_getpid(p);
	exitval = p->p_xstat;
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON,
	    BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_START,
	    pid, exitval, 0, 0, 0);

#if DEVELOPMENT || DEBUG
	proc_exit_lpexit_check(pid, PELS_POS_START);
#endif

#if CONFIG_DTRACE
	dtrace_proc_exit(p);
#endif

	proc_refdrain(p);
	/* We now have unique ref to the proc */

	/* if any pending cpu limits action, clear it */
	task_clear_cpuusage(proc_task(p), TRUE);

	workq_mark_exiting(p);

	/*
	 * need to cancel async IO requests that can be cancelled and wait for those
	 * already active.  MAY BLOCK!
	 */
	_aio_exit( p );

	/*
	 * Close open files and release open-file table.
	 * This may block!
	 */
	fdt_invalidate(p);

	/*
	 * Once all the knotes, kqueues & workloops are destroyed, get rid of the
	 * workqueue.
	 */
	workq_exit(p);

	if (uth->uu_lowpri_window) {
		/*
		 * task is marked as a low priority I/O type
		 * and the I/O we issued while in flushing files on close
		 * collided with normal I/O operations...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 */
		throttle_lowpri_io(0);
	}

	if (p->p_lflag & P_LNSPACE_RESOLVER) {
		/*
		 * The namespace resolver is exiting; there may be
		 * outstanding materialization requests to clean up.
		 */
		nspace_resolver_exited(p);
	}

#if SYSV_SHM
	/* Close ref SYSV Shared memory*/
	if (p->vm_shm) {
		shmexit(p);
	}
#endif
#if SYSV_SEM
	/* Release SYSV semaphores */
	semexit(p);
#endif

#if PSYNCH
	pth_proc_hashdelete(p);
#endif /* PSYNCH */

	pg = proc_pgrp(p, &sessp);
	if (SESS_LEADER(p, sessp)) {
		if (sessp->s_ttyvp != NULLVP) {
			struct vnode *ttyvp;
			int ttyvid;
			int cttyflag = 0;
			struct vfs_context context;
			struct tty *tp;
			struct pgrp *tpgrp = PGRP_NULL;

			/*
			 * Controlling process.
			 * Signal foreground pgrp,
			 * drain controlling terminal
			 * and revoke access to controlling terminal.
			 */

			proc_list_lock(); /* prevent any t_pgrp from changing */
			session_lock(sessp);
			if (sessp->s_ttyp && sessp->s_ttyp->t_session == sessp) {
				tpgrp = tty_pgrp_locked(sessp->s_ttyp);
			}
			proc_list_unlock();

			if (tpgrp != PGRP_NULL) {
				session_unlock(sessp);
				pgsignal(tpgrp, SIGHUP, 1);
				pgrp_rele(tpgrp);
				session_lock(sessp);
			}

			cttyflag = (os_atomic_andnot_orig(&sessp->s_refcount,
			    S_CTTYREF, relaxed) & S_CTTYREF);
			ttyvp = sessp->s_ttyvp;
			ttyvid = sessp->s_ttyvid;
			tp = session_clear_tty_locked(sessp);
			if (ttyvp) {
				vnode_hold(ttyvp);
			}
			session_unlock(sessp);

			if ((ttyvp != NULLVP) && (vnode_getwithvid(ttyvp, ttyvid) == 0)) {
				if (tp != TTY_NULL) {
					tty_lock(tp);
					(void) ttywait(tp);
					tty_unlock(tp);
				}

				context.vc_thread = NULL;
				context.vc_ucred = kauth_cred_proc_ref(p);
				VNOP_REVOKE(ttyvp, REVOKEALL, &context);
				if (cttyflag) {
					/*
					 * Release the extra usecount taken in cttyopen.
					 * usecount should be released after VNOP_REVOKE is called.
					 * This usecount was taken to ensure that
					 * the VNOP_REVOKE results in a close to
					 * the tty since cttyclose is a no-op.
					 */
					vnode_rele(ttyvp);
				}
				vnode_put(ttyvp);
				kauth_cred_unref(&context.vc_ucred);
				vnode_drop(ttyvp);
				ttyvp = NULLVP;
			}
			if (ttyvp) {
				vnode_drop(ttyvp);
			}
			if (tp) {
				ttyfree(tp);
			}
		}
		session_lock(sessp);
		sessp->s_leader = NULL;
		session_unlock(sessp);
	}

	if (!proc_is_shadow(p)) {
		fixjobc(p, pg, 0);
	}
	pgrp_rele(pg);

	/*
	 * Change RLIMIT_FSIZE for accounting/debugging.
	 */
	proc_limitsetcur_fsize(p, RLIM_INFINITY);

	(void)acct_process(p);

	proc_list_lock();

	if ((p->p_listflag & P_LIST_EXITCOUNT) == P_LIST_EXITCOUNT) {
		p->p_listflag &= ~P_LIST_EXITCOUNT;
		proc_shutdown_exitcount--;
		if (proc_shutdown_exitcount == 0) {
			wakeup(&proc_shutdown_exitcount);
		}
	}

	/* wait till parentrefs are dropped and grant no more */
	proc_childdrainstart(p);
	while ((q = p->p_children.lh_first) != NULL) {
		if (q->p_stat == SZOMB) {
			if (p != q->p_pptr) {
				panic("parent child linkage broken");
			}
			/* check for sysctl zomb lookup */
			while ((q->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
				msleep(&q->p_stat, &proc_list_mlock, PWAIT, "waitcoll", 0);
			}
			q->p_listflag |= P_LIST_WAITING;
			/*
			 * This is a named reference and it is not granted
			 * if the reap is already in progress. So we get
			 * the reference here exclusively and their can be
			 * no waiters. So there is no need for a wakeup
			 * after we are done.  Also the reap frees the structure
			 * and the proc struct cannot be used for wakeups as well.
			 * It is safe to use q here as this is system reap
			 */
			reap_flags_t reparent_flags = (q->p_listflag & P_LIST_DEADPARENT) ?
			    REAP_REPARENTED_TO_INIT : 0;
			reap_child_locked(p, q,
			    REAP_DEAD_PARENT | REAP_LOCKED | reparent_flags);
		} else {
			/*
			 * Traced processes are killed
			 * since their existence means someone is messing up.
			 */
			if (q->p_lflag & P_LTRACED) {
				struct proc *opp;

				/*
				 * Take a reference on the child process to
				 * ensure it doesn't exit and disappear between
				 * the time we drop the list_lock and attempt
				 * to acquire its proc_lock.
				 */
				if (proc_ref(q, true) != q) {
					continue;
				}

				proc_list_unlock();

				opp = proc_find(q->p_oppid);
				if (opp != PROC_NULL) {
					proc_list_lock();
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, opp, 0, 0);
					proc_rele(opp);
				} else {
					/* original parent exited while traced */
					proc_list_lock();
					q->p_listflag |= P_LIST_DEADPARENT;
					q->p_oppid = 0;
					proc_list_unlock();
					proc_reparentlocked(q, initproc, 0, 0);
				}

				proc_lock(q);
				q->p_lflag &= ~P_LTRACED;

				if (q->sigwait_thread) {
					thread_t thread = q->sigwait_thread;

					proc_unlock(q);
					/*
					 * The sigwait_thread could be stopped at a
					 * breakpoint. Wake it up to kill.
					 * Need to do this as it could be a thread which is not
					 * the first thread in the task. So any attempts to kill
					 * the process would result into a deadlock on q->sigwait.
					 */
					thread_resume(thread);
					clear_wait(thread, THREAD_INTERRUPTED);
					threadsignal(thread, SIGKILL, 0, TRUE);
				} else {
					proc_unlock(q);
				}

				psignal(q, SIGKILL);
				proc_list_lock();
				proc_rele(q);
			} else {
				q->p_listflag |= P_LIST_DEADPARENT;
				proc_reparentlocked(q, initproc, 0, 1);
			}
		}
	}

	proc_childdrainend(p);
	proc_list_unlock();

#if CONFIG_MACF
	if (!proc_is_shadow(p)) {
		/*
		 * Notify MAC policies that proc is dead.
		 * This should be replaced with proper label management
		 * (rdar://problem/32126399).
		 */
		mac_proc_notify_exit(p);
	}
#endif

	/*
	 * Release reference to text vnode
	 */
	tvp = p->p_textvp;
	p->p_textvp = NULL;
	if (tvp != NULLVP) {
		vnode_rele(tvp);
	}

	/*
	 * Save exit status and final rusage info, adding in child rusage
	 * info and self times.  If we were unable to allocate a zombie
	 * structure, this information is lost.
	 */
	if (p->p_ru != NULL) {
		calcru(p, &p->p_stats->p_ru.ru_utime, &p->p_stats->p_ru.ru_stime, NULL);
		p->p_ru->ru = p->p_stats->p_ru;

		ruadd(&(p->p_ru->ru), &p->p_stats->p_cru);
	}

	/*
	 * Free up profiling buffers.
	 */
	{
		struct uprof *p0 = &p->p_stats->p_prof, *p1, *pn;

		p1 = p0->pr_next;
		p0->pr_next = NULL;
		p0->pr_scale = 0;

		for (; p1 != NULL; p1 = pn) {
			pn = p1->pr_next;
			kfree_type(struct uprof, p1);
		}
	}

	proc_free_realitimer(p);

	/*
	 * Other substructures are freed from wait().
	 */
	zfree(proc_stats_zone, p->p_stats);
	p->p_stats = NULL;

	if (p->p_subsystem_root_path) {
		zfree(ZV_NAMEI, p->p_subsystem_root_path);
		p->p_subsystem_root_path = NULL;
	}

	proc_limitdrop(p);

#if DEVELOPMENT || DEBUG
	proc_exit_lpexit_check(pid, PELS_POS_PRE_TASK_DETACH);
#endif

	/*
	 * Finish up by terminating the task
	 * and halt this thread (only if a
	 * member of the task exiting).
	 */
	proc_set_task(p, TASK_NULL);
	set_bsdtask_info(task, NULL);
	clear_thread_ro_proc(get_machthread(uth));

#if DEVELOPMENT || DEBUG
	proc_exit_lpexit_check(pid, PELS_POS_POST_TASK_DETACH);
#endif

	knote_hint = NOTE_EXIT | (p->p_xstat & 0xffff);
	proc_knote(p, knote_hint);

	/* mark the thread as the one that is doing proc_exit
	 * no need to hold proc lock in uthread_free
	 */
	uth->uu_flag |= UT_PROCEXIT;
	/*
	 * Notify parent that we're gone.
	 */
	pp = proc_parent(p);
	if (proc_is_shadow(p)) {
		/* kernel can reap this one, no need to move it to launchd */
		proc_list_lock();
		p->p_listflag |= P_LIST_DEADPARENT;
		proc_list_unlock();
	} else if (pp->p_flag & P_NOCLDWAIT) {
		if (p->p_ru != NULL) {
			proc_lock(pp);
#if 3839178
			/*
			 * If the parent is ignoring SIGCHLD, then POSIX requires
			 * us to not add the resource usage to the parent process -
			 * we are only going to hand it off to init to get reaped.
			 * We should contest the standard in this case on the basis
			 * of RLIMIT_CPU.
			 */
#else   /* !3839178 */
			/*
			 * Add child resource usage to parent before giving
			 * zombie to init.  If we were unable to allocate a
			 * zombie structure, this information is lost.
			 */
			ruadd(&pp->p_stats->p_cru, &p->p_ru->ru);
#endif  /* !3839178 */
			update_rusage_info_child(&pp->p_stats->ri_child, &p->p_ru->ri);
			proc_unlock(pp);
		}

		/* kernel can reap this one, no need to move it to launchd */
		proc_list_lock();
		p->p_listflag |= P_LIST_DEADPARENT;
		proc_list_unlock();
	}
	if (!proc_is_shadow(p) &&
	    ((p->p_listflag & P_LIST_DEADPARENT) == 0 || p->p_oppid)) {
		if (pp != initproc) {
			proc_lock(pp);
			pp->si_pid = proc_getpid(p);
			pp->p_xhighbits = p->p_xhighbits;
			p->p_xhighbits = 0;
			pp->si_status = p->p_xstat;
			pp->si_code = CLD_EXITED;
			/*
			 * p_ucred usage is safe as it is an exiting process
			 * and reference is dropped in reap
			 */
			pp->si_uid = kauth_cred_getruid(proc_ucred_unsafe(p));
			proc_unlock(pp);
		}
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		DTRACE_PROC2(exited, proc_t, p, int, exitval);
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON,
		    BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END,
		    pid, exitval, 0, 0, 0);
		p->p_stat = SZOMB;
		/*
		 * The current process can be reaped so, no one
		 * can depend on this
		 */

		psignal(pp, SIGCHLD);

		/* and now wakeup the parent */
		proc_list_lock();
		wakeup((caddr_t)pp);
		proc_list_unlock();
	} else {
		/* should be fine as parent proc would be initproc */
		/* mark as a zombie */
		/* No need to take proc lock as all refs are drained and
		 * no one except parent (reaping ) can look at this.
		 * The write is to an int and is coherent. Also parent is
		 *  keyed off of list lock for reaping
		 */
		DTRACE_PROC2(exited, proc_t, p, int, exitval);
		proc_list_lock();
		KERNEL_DEBUG_CONSTANT_IST(KDEBUG_COMMON,
		    BSDDBG_CODE(DBG_BSD_PROC, BSD_PROC_EXIT) | DBG_FUNC_END,
		    pid, exitval, 0, 0, 0);
		/* check for sysctl zomb lookup */
		while ((p->p_listflag & P_LIST_WAITING) == P_LIST_WAITING) {
			msleep(&p->p_stat, &proc_list_mlock, PWAIT, "waitcoll", 0);
		}
		/* safe to use p as this is a system reap */
		p->p_stat = SZOMB;
		p->p_listflag |= P_LIST_WAITING;

		/*
		 * This is a named reference and it is not granted
		 * if the reap is already in progress. So we get
		 * the reference here exclusively and their can be
		 * no waiters. So there is no need for a wakeup
		 * after we are done. AlsO  the reap frees the structure
		 * and the proc struct cannot be used for wakeups as well.
		 * It is safe to use p here as this is system reap
		 */
		reap_child_locked(pp, p,
		    REAP_DEAD_PARENT | REAP_LOCKED | REAP_DROP_LOCK);
	}
	if (uth->uu_lowpri_window) {
		/*
		 * task is marked as a low priority I/O type and we've
		 * somehow picked up another throttle during exit processing...
		 * no need to throttle this thread since its going away
		 * but we do need to update our bookeeping w/r to throttled threads
		 */
		throttle_lowpri_io(0);
	}

	proc_rele(pp);
#if DEVELOPMENT || DEBUG
	proc_exit_lpexit_check(pid, PELS_POS_END);
#endif
}


/*
 * reap_child_locked
 *
 * Finalize a child exit once its status has been saved.
 *
 * If ptrace has attached, detach it and return it to its real parent.  Free any
 * remaining resources.
 *
 * Parameters:
 * - proc_t parent      Parent of process being reaped
 * - proc_t child       Process to reap
 * - reap_flags_t flags Control locking and re-parenting behavior
 */
static void
reap_child_locked(proc_t parent, proc_t child, reap_flags_t flags)
{
	struct pgrp *pg;
	boolean_t shadow_proc = proc_is_shadow(child);

	if (flags & REAP_LOCKED) {
		proc_list_unlock();
	}

	/*
	 * Under ptrace, the child should now be re-parented back to its original
	 * parent, unless that parent was initproc or it didn't come to initproc
	 * through re-parenting.
	 */
	bool child_ptraced = child->p_oppid != 0;
	if (!shadow_proc && child_ptraced) {
		int knote_hint;
		pid_t orig_ppid = 0;
		proc_t orig_parent = PROC_NULL;

		proc_lock(child);
		orig_ppid = child->p_oppid;
		child->p_oppid = 0;
		knote_hint = NOTE_EXIT | (child->p_xstat & 0xffff);
		proc_unlock(child);

		orig_parent = proc_find(orig_ppid);
		if (orig_parent) {
			/*
			 * Only re-parent the process if its original parent was not
			 * initproc and it did not come to initproc from re-parenting.
			 */
			bool reparenting = orig_parent != initproc ||
			    (flags & REAP_REPARENTED_TO_INIT) == 0;
			if (reparenting) {
				if (orig_parent != initproc) {
					/*
					 * Internal fields should be safe to access here because the
					 * child is exited and not reaped or re-parented yet.
					 */
					proc_lock(orig_parent);
					orig_parent->si_pid = proc_getpid(child);
					orig_parent->si_status = child->p_xstat;
					orig_parent->si_code = CLD_CONTINUED;
					orig_parent->si_uid = kauth_cred_getruid(proc_ucred_unsafe(child));
					proc_unlock(orig_parent);
				}
				proc_reparentlocked(child, orig_parent, 1, 0);

				/*
				 * After re-parenting, re-send the child's NOTE_EXIT to the
				 * original parent.
				 */
				proc_knote(child, knote_hint);
				psignal(orig_parent, SIGCHLD);

				proc_list_lock();
				wakeup((caddr_t)orig_parent);
				child->p_listflag &= ~P_LIST_WAITING;
				wakeup(&child->p_stat);
				proc_list_unlock();

				proc_rele(orig_parent);
				if ((flags & REAP_LOCKED) && !(flags & REAP_DROP_LOCK)) {
					proc_list_lock();
				}
				return;
			} else {
				/*
				 * Satisfy the knote lifecycle because ptraced processes don't
				 * broadcast NOTE_EXIT during initial child termination.
				 */
				proc_knote(child, knote_hint);
				proc_rele(orig_parent);
			}
		}
	}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
	proc_knote(child, NOTE_REAP);
#pragma clang diagnostic pop

	proc_knote_drain(child);

	child->p_xstat = 0;
	if (!shadow_proc && child->p_ru) {
		/*
		 * Roll up the rusage statistics to the parent, unless the parent is
		 * ignoring SIGCHLD.  POSIX requires the children's resources of such a
		 * parent to not be included in the parent's usage (seems odd given
		 * RLIMIT_CPU, though).
		 */
		proc_lock(parent);
		bool rollup_child = (parent->p_flag & P_NOCLDWAIT) == 0;
		if (rollup_child) {
			ruadd(&parent->p_stats->p_cru, &child->p_ru->ru);
		}
		update_rusage_info_child(&parent->p_stats->ri_child, &child->p_ru->ri);
		proc_unlock(parent);
		zfree(zombie_zone, child->p_ru);
		child->p_ru = NULL;
	} else if (!shadow_proc) {
		printf("Warning : lost p_ru for %s\n", child->p_comm);
	} else {
		assert(child->p_ru == NULL);
	}

	AUDIT_SESSION_PROCEXIT(child);

#if CONFIG_PERSONAS
	persona_proc_drop(child);
#endif /* CONFIG_PERSONAS */
	/* proc_ucred_unsafe is safe, because child is not running */
	(void)chgproccnt(kauth_cred_getruid(proc_ucred_unsafe(child)), -1);

	os_reason_free(child->p_exit_reason);

	proc_list_lock();

	pg = pgrp_leave_locked(child);
	LIST_REMOVE(child, p_list);
	parent->p_childrencnt--;
	LIST_REMOVE(child, p_sibling);
	bool no_more_children = (flags & REAP_DEAD_PARENT) &&
	    LIST_EMPTY(&parent->p_children);
	if (no_more_children) {
		wakeup((caddr_t)parent);
	}
	child->p_listflag &= ~P_LIST_WAITING;
	wakeup(&child->p_stat);

	/* Take it out of process hash */
	if (!shadow_proc) {
		phash_remove_locked(child);
	}
	proc_checkdeadrefs(child);
	nprocs--;
	if (flags & REAP_DEAD_PARENT) {
		child->p_listflag |= P_LIST_DEADPARENT;
	}

	proc_list_unlock();

	pgrp_rele(pg);
	fdt_destroy(child);
	lck_mtx_destroy(&child->p_mlock, &proc_mlock_grp);
	lck_mtx_destroy(&child->p_ucred_mlock, &proc_ucred_mlock_grp);
#if CONFIG_AUDIT
	lck_mtx_destroy(&child->p_audit_mlock, &proc_ucred_mlock_grp);
#endif /* CONFIG_AUDIT */
#if CONFIG_DTRACE
	lck_mtx_destroy(&child->p_dtrace_sprlock, &proc_lck_grp);
#endif
	lck_spin_destroy(&child->p_slock, &proc_slock_grp);
	proc_wait_release(child);

	if ((flags & REAP_LOCKED) && (flags & REAP_DROP_LOCK) == 0) {
		proc_list_lock();
	}
}

int
wait1continue(int result)
{
	proc_t p;
	thread_t thread;
	uthread_t uth;
	struct _wait4_data *wait4_data;
	struct wait4_nocancel_args *uap;
	int *retval;

	if (result) {
		return result;
	}

	p = current_proc();
	thread = current_thread();
	uth = (struct uthread *)get_bsdthread_info(thread);

	wait4_data = &uth->uu_save.uus_wait4_data;
	uap = wait4_data->args;
	retval = wait4_data->retval;
	return wait4_nocancel(p, uap, retval);
}

int
wait4(proc_t q, struct wait4_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return wait4_nocancel(q, (struct wait4_nocancel_args *)uap, retval);
}

int
wait4_nocancel(proc_t q, struct wait4_nocancel_args *uap, int32_t *retval)
{
	int nfound;
	int sibling_count;
	proc_t p;
	int status, error;
	uthread_t uth;
	struct _wait4_data *wait4_data;

	AUDIT_ARG(pid, uap->pid);

	if (uap->pid == 0) {
		uap->pid = -q->p_pgrpid;
	}

	if (uap->pid == INT_MIN) {
		return EINVAL;
	}

loop:
	proc_list_lock();
loop1:
	nfound = 0;
	sibling_count = 0;

	PCHILDREN_FOREACH(q, p) {
		if (p->p_sibling.le_next != 0) {
			sibling_count++;
		}
		if (uap->pid != WAIT_ANY &&
		    proc_getpid(p) != uap->pid &&
		    p->p_pgrpid != -(uap->pid)) {
			continue;
		}

		if (proc_is_shadow(p)) {
			continue;
		}

		nfound++;

		/* XXX This is racy because we don't get the lock!!!! */

		if (p->p_listflag & P_LIST_WAITING) {
			/* we're not using a continuation here but we still need to stash
			 * the args for stackshot. */
			uth = current_uthread();
			wait4_data = &uth->uu_save.uus_wait4_data;
			wait4_data->args = uap;
			thread_set_pending_block_hint(current_thread(), kThreadWaitOnProcess);

			(void)msleep(&p->p_stat, &proc_list_mlock, PWAIT, "waitcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;   /* only allow single thread to wait() */


		if (p->p_stat == SZOMB) {
			reap_flags_t reap_flags = (p->p_listflag & P_LIST_DEADPARENT) ?
			    REAP_REPARENTED_TO_INIT : 0;

			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif
			retval[0] = proc_getpid(p);
			if (uap->status) {
				/* Legacy apps expect only 8 bits of status */
				status = 0xffff & p->p_xstat;   /* convert to int */
				error = copyout((caddr_t)&status,
				    uap->status,
				    sizeof(status));
				if (error) {
					goto out;
				}
			}
			if (uap->rusage) {
				if (p->p_ru == NULL) {
					error = ENOMEM;
				} else {
					if (IS_64BIT_PROCESS(q)) {
						struct user64_rusage    my_rusage = {};
						munge_user64_rusage(&p->p_ru->ru, &my_rusage);
						error = copyout((caddr_t)&my_rusage,
						    uap->rusage,
						    sizeof(my_rusage));
					} else {
						struct user32_rusage    my_rusage = {};
						munge_user32_rusage(&p->p_ru->ru, &my_rusage);
						error = copyout((caddr_t)&my_rusage,
						    uap->rusage,
						    sizeof(my_rusage));
					}
				}
				/* information unavailable? */
				if (error) {
					goto out;
				}
			}

			/* Conformance change for 6577252.
			 * When SIGCHLD is blocked and wait() returns because the status
			 * of a child process is available and there are no other
			 * children processes, then any pending SIGCHLD signal is cleared.
			 */
			if (sibling_count == 0) {
				int mask = sigmask(SIGCHLD);
				uth = current_uthread();

				if ((uth->uu_sigmask & mask) != 0) {
					/* we are blocking SIGCHLD signals.  clear any pending SIGCHLD.
					 * This locking looks funny but it is protecting access to the
					 * thread via p_uthlist.
					 */
					proc_lock(q);
					uth->uu_siglist &= ~mask;       /* clear pending signal */
					proc_unlock(q);
				}
			}

			/* Clean up */
			(void)reap_child_locked(q, p, reap_flags);

			return 0;
		}
		if (p->p_stat == SSTOP && (p->p_lflag & P_LWAITED) == 0 &&
		    (p->p_lflag & P_LTRACED || uap->options & WUNTRACED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif
			proc_lock(p);
			p->p_lflag |= P_LWAITED;
			proc_unlock(p);
			retval[0] = proc_getpid(p);
			if (uap->status) {
				status = W_STOPCODE(p->p_xstat);
				error = copyout((caddr_t)&status,
				    uap->status,
				    sizeof(status));
			} else {
				error = 0;
			}
			goto out;
		}
		/*
		 * If we are waiting for continued processses, and this
		 * process was continued
		 */
		if ((uap->options & WCONTINUED) &&
		    (p->p_flag & P_CONTINUED)) {
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif

			/* Prevent other process for waiting for this event */
			OSBitAndAtomic(~((uint32_t)P_CONTINUED), &p->p_flag);
			retval[0] = proc_getpid(p);
			if (uap->status) {
				status = W_STOPCODE(SIGCONT);
				error = copyout((caddr_t)&status,
				    uap->status,
				    sizeof(status));
			} else {
				error = 0;
			}
			goto out;
		}
		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	/* list lock is held when we get here any which way */
	if (nfound == 0) {
		proc_list_unlock();
		return ECHILD;
	}

	if (uap->options & WNOHANG) {
		retval[0] = 0;
		proc_list_unlock();
		return 0;
	}

	/* Save arguments for continuation. Backing storage is in uthread->uu_arg, and will not be deallocated */
	uth = current_uthread();
	wait4_data = &uth->uu_save.uus_wait4_data;
	wait4_data->args = uap;
	wait4_data->retval = retval;

	thread_set_pending_block_hint(current_thread(), kThreadWaitOnProcess);
	if ((error = msleep0((caddr_t)q, &proc_list_mlock, PWAIT | PCATCH | PDROP, "wait", 0, wait1continue))) {
		return error;
	}

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return error;
}

#if DEBUG
#define ASSERT_LCK_MTX_OWNED(lock)      \
	                        lck_mtx_assert(lock, LCK_MTX_ASSERT_OWNED)
#else
#define ASSERT_LCK_MTX_OWNED(lock)      /* nothing */
#endif

int
waitidcontinue(int result)
{
	proc_t p;
	thread_t thread;
	uthread_t uth;
	struct _waitid_data *waitid_data;
	struct waitid_nocancel_args *uap;
	int *retval;

	if (result) {
		return result;
	}

	p = current_proc();
	thread = current_thread();
	uth = (struct uthread *)get_bsdthread_info(thread);

	waitid_data = &uth->uu_save.uus_waitid_data;
	uap = waitid_data->args;
	retval = waitid_data->retval;
	return waitid_nocancel(p, uap, retval);
}

/*
 * Description:	Suspend the calling thread until one child of the process
 *		containing the calling thread changes state.
 *
 * Parameters:	uap->idtype		one of P_PID, P_PGID, P_ALL
 *		uap->id			pid_t or gid_t or ignored
 *		uap->infop		Address of siginfo_t struct in
 *					user space into which to return status
 *		uap->options		flag values
 *
 * Returns:	0			Success
 *		!0			Error returning status to user space
 */
int
waitid(proc_t q, struct waitid_args *uap, int32_t *retval)
{
	__pthread_testcancel(1);
	return waitid_nocancel(q, (struct waitid_nocancel_args *)uap, retval);
}

int
waitid_nocancel(proc_t q, struct waitid_nocancel_args *uap,
    __unused int32_t *retval)
{
	user_siginfo_t  siginfo;        /* siginfo data to return to caller */
	boolean_t caller64 = IS_64BIT_PROCESS(q);
	int nfound;
	proc_t p;
	int error;
	uthread_t uth;
	struct _waitid_data *waitid_data;

	if (uap->options == 0 ||
	    (uap->options & ~(WNOHANG | WNOWAIT | WCONTINUED | WSTOPPED | WEXITED))) {
		return EINVAL;        /* bits set that aren't recognized */
	}
	switch (uap->idtype) {
	case P_PID:     /* child with process ID equal to... */
	case P_PGID:    /* child with process group ID equal to... */
		if (((int)uap->id) < 0) {
			return EINVAL;
		}
		break;
	case P_ALL:     /* any child */
		break;
	}

loop:
	proc_list_lock();
loop1:
	nfound = 0;

	PCHILDREN_FOREACH(q, p) {
		switch (uap->idtype) {
		case P_PID:     /* child with process ID equal to... */
			if (proc_getpid(p) != (pid_t)uap->id) {
				continue;
			}
			break;
		case P_PGID:    /* child with process group ID equal to... */
			if (p->p_pgrpid != (pid_t)uap->id) {
				continue;
			}
			break;
		case P_ALL:     /* any child */
			break;
		}

		if (proc_is_shadow(p)) {
			continue;
		}
		/* XXX This is racy because we don't get the lock!!!! */

		/*
		 * Wait collision; go to sleep and restart; used to maintain
		 * the single return for waited process guarantee.
		 */
		if (p->p_listflag & P_LIST_WAITING) {
			(void) msleep(&p->p_stat, &proc_list_mlock,
			    PWAIT, "waitidcoll", 0);
			goto loop1;
		}
		p->p_listflag |= P_LIST_WAITING;                /* mark busy */

		nfound++;

		bzero(&siginfo, sizeof(siginfo));

		switch (p->p_stat) {
		case SZOMB:             /* Exited */
			if (!(uap->options & WEXITED)) {
				break;
			}
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_pid = proc_getpid(p);

			/* If the child terminated abnormally due to a signal, the signum
			 * needs to be preserved in the exit status.
			 */
			if (WIFSIGNALED(p->p_xstat)) {
				siginfo.si_code = WCOREDUMP(p->p_xstat) ?
				    CLD_DUMPED : CLD_KILLED;
				siginfo.si_status = WTERMSIG(p->p_xstat);
			} else {
				siginfo.si_code = CLD_EXITED;
				siginfo.si_status = WEXITSTATUS(p->p_xstat) & 0x00FFFFFF;
			}
			siginfo.si_status |= (((uint32_t)(p->p_xhighbits) << 24) & 0xFF000000);
			p->p_xhighbits = 0;

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0) {
				goto out;
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				reap_child_locked(q, p, 0);
				return 0;
			}
			goto out;

		case SSTOP:             /* Stopped */
			/*
			 * If we are not interested in stopped processes, then
			 * ignore this one.
			 */
			if (!(uap->options & WSTOPPED)) {
				break;
			}

			/*
			 * If someone has already waited it, we lost a race
			 * to be the one to return status.
			 */
			if ((p->p_lflag & P_LWAITED) != 0) {
				break;
			}
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_pid = proc_getpid(p);
			siginfo.si_status = p->p_xstat; /* signal number */
			siginfo.si_code = CLD_STOPPED;

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0) {
				goto out;
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				proc_lock(p);
				p->p_lflag |= P_LWAITED;
				proc_unlock(p);
			}
			goto out;

		default:                /* All other states => Continued */
			if (!(uap->options & WCONTINUED)) {
				break;
			}

			/*
			 * If the flag isn't set, then this process has not
			 * been stopped and continued, or the status has
			 * already been reaped by another caller of waitid().
			 */
			if ((p->p_flag & P_CONTINUED) == 0) {
				break;
			}
			proc_list_unlock();
#if CONFIG_MACF
			if ((error = mac_proc_check_wait(q, p)) != 0) {
				goto out;
			}
#endif
			siginfo.si_signo = SIGCHLD;
			siginfo.si_code = CLD_CONTINUED;
			proc_lock(p);
			siginfo.si_pid = p->p_contproc;
			siginfo.si_status = p->p_xstat;
			proc_unlock(p);

			if ((error = copyoutsiginfo(&siginfo,
			    caller64, uap->infop)) != 0) {
				goto out;
			}

			/* Prevent other process for waiting for this event? */
			if (!(uap->options & WNOWAIT)) {
				OSBitAndAtomic(~((uint32_t)P_CONTINUED),
				    &p->p_flag);
			}
			goto out;
		}
		ASSERT_LCK_MTX_OWNED(&proc_list_mlock);

		/* Not a process we are interested in; go on to next child */

		p->p_listflag &= ~P_LIST_WAITING;
		wakeup(&p->p_stat);
	}
	ASSERT_LCK_MTX_OWNED(&proc_list_mlock);

	/* No child processes that could possibly satisfy the request? */

	if (nfound == 0) {
		proc_list_unlock();
		return ECHILD;
	}

	if (uap->options & WNOHANG) {
		proc_list_unlock();
#if CONFIG_MACF
		if ((error = mac_proc_check_wait(q, p)) != 0) {
			return error;
		}
#endif
		/*
		 * The state of the siginfo structure in this case
		 * is undefined.  Some implementations bzero it, some
		 * (like here) leave it untouched for efficiency.
		 *
		 * Thus the most portable check for "no matching pid with
		 * WNOHANG" is to store a zero into si_pid before
		 * invocation, then check for a non-zero value afterwards.
		 */
		return 0;
	}

	/* Save arguments for continuation. Backing storage is in uthread->uu_arg, and will not be deallocated */
	uth = current_uthread();
	waitid_data = &uth->uu_save.uus_waitid_data;
	waitid_data->args = uap;
	waitid_data->retval = retval;

	if ((error = msleep0(q, &proc_list_mlock,
	    PWAIT | PCATCH | PDROP, "waitid", 0, waitidcontinue)) != 0) {
		return error;
	}

	goto loop;
out:
	proc_list_lock();
	p->p_listflag &= ~P_LIST_WAITING;
	wakeup(&p->p_stat);
	proc_list_unlock();
	return error;
}

/*
 * make process 'parent' the new parent of process 'child'.
 */
void
proc_reparentlocked(proc_t child, proc_t parent, int signallable, int locked)
{
	proc_t oldparent = PROC_NULL;

	if (child->p_pptr == parent) {
		return;
	}

	if (locked == 0) {
		proc_list_lock();
	}

	oldparent = child->p_pptr;
#if __PROC_INTERNAL_DEBUG
	if (oldparent == PROC_NULL) {
		panic("proc_reparent: process %p does not have a parent", child);
	}
#endif

	LIST_REMOVE(child, p_sibling);
#if __PROC_INTERNAL_DEBUG
	if (oldparent->p_childrencnt == 0) {
		panic("process children count already 0");
	}
#endif
	oldparent->p_childrencnt--;
#if __PROC_INTERNAL_DEBUG
	if (oldparent->p_childrencnt < 0) {
		panic("process children count -ve");
	}
#endif
	LIST_INSERT_HEAD(&parent->p_children, child, p_sibling);
	parent->p_childrencnt++;
	child->p_pptr = parent;
	child->p_ppid = proc_getpid(parent);

	proc_list_unlock();

	if ((signallable != 0) && (initproc == parent) && (child->p_stat == SZOMB)) {
		psignal(initproc, SIGCHLD);
	}
	if (locked == 1) {
		proc_list_lock();
	}
}

/*
 * Exit: deallocate address space and other resources, change proc state
 * to zombie, and unlink proc from allproc and parent's lists.  Save exit
 * status and rusage for wait().  Check for child processes and orphan them.
 */


/*
 * munge_rusage
 *	LP64 support - long is 64 bits if we are dealing with a 64 bit user
 *	process.  We munge the kernel version of rusage into the
 *	64 bit version.
 */
__private_extern__  void
munge_user64_rusage(struct rusage *a_rusage_p, struct user64_rusage *a_user_rusage_p)
{
	/* Zero-out struct so that padding is cleared */
	bzero(a_user_rusage_p, sizeof(struct user64_rusage));

	/* timeval changes size, so utime and stime need special handling */
	a_user_rusage_p->ru_utime.tv_sec = a_rusage_p->ru_utime.tv_sec;
	a_user_rusage_p->ru_utime.tv_usec = a_rusage_p->ru_utime.tv_usec;
	a_user_rusage_p->ru_stime.tv_sec = a_rusage_p->ru_stime.tv_sec;
	a_user_rusage_p->ru_stime.tv_usec = a_rusage_p->ru_stime.tv_usec;
	/*
	 * everything else can be a direct assign, since there is no loss
	 * of precision implied boing 32->64.
	 */
	a_user_rusage_p->ru_maxrss = a_rusage_p->ru_maxrss;
	a_user_rusage_p->ru_ixrss = a_rusage_p->ru_ixrss;
	a_user_rusage_p->ru_idrss = a_rusage_p->ru_idrss;
	a_user_rusage_p->ru_isrss = a_rusage_p->ru_isrss;
	a_user_rusage_p->ru_minflt = a_rusage_p->ru_minflt;
	a_user_rusage_p->ru_majflt = a_rusage_p->ru_majflt;
	a_user_rusage_p->ru_nswap = a_rusage_p->ru_nswap;
	a_user_rusage_p->ru_inblock = a_rusage_p->ru_inblock;
	a_user_rusage_p->ru_oublock = a_rusage_p->ru_oublock;
	a_user_rusage_p->ru_msgsnd = a_rusage_p->ru_msgsnd;
	a_user_rusage_p->ru_msgrcv = a_rusage_p->ru_msgrcv;
	a_user_rusage_p->ru_nsignals = a_rusage_p->ru_nsignals;
	a_user_rusage_p->ru_nvcsw = a_rusage_p->ru_nvcsw;
	a_user_rusage_p->ru_nivcsw = a_rusage_p->ru_nivcsw;
}

/* For a 64-bit kernel and 32-bit userspace, munging may be needed */
__private_extern__  void
munge_user32_rusage(struct rusage *a_rusage_p, struct user32_rusage *a_user_rusage_p)
{
	bzero(a_user_rusage_p, sizeof(struct user32_rusage));

	/* timeval changes size, so utime and stime need special handling */
	a_user_rusage_p->ru_utime.tv_sec = (user32_time_t)a_rusage_p->ru_utime.tv_sec;
	a_user_rusage_p->ru_utime.tv_usec = a_rusage_p->ru_utime.tv_usec;
	a_user_rusage_p->ru_stime.tv_sec = (user32_time_t)a_rusage_p->ru_stime.tv_sec;
	a_user_rusage_p->ru_stime.tv_usec = a_rusage_p->ru_stime.tv_usec;
	/*
	 * everything else can be a direct assign. We currently ignore
	 * the loss of precision
	 */
	a_user_rusage_p->ru_maxrss = (user32_long_t)a_rusage_p->ru_maxrss;
	a_user_rusage_p->ru_ixrss = (user32_long_t)a_rusage_p->ru_ixrss;
	a_user_rusage_p->ru_idrss = (user32_long_t)a_rusage_p->ru_idrss;
	a_user_rusage_p->ru_isrss = (user32_long_t)a_rusage_p->ru_isrss;
	a_user_rusage_p->ru_minflt = (user32_long_t)a_rusage_p->ru_minflt;
	a_user_rusage_p->ru_majflt = (user32_long_t)a_rusage_p->ru_majflt;
	a_user_rusage_p->ru_nswap = (user32_long_t)a_rusage_p->ru_nswap;
	a_user_rusage_p->ru_inblock = (user32_long_t)a_rusage_p->ru_inblock;
	a_user_rusage_p->ru_oublock = (user32_long_t)a_rusage_p->ru_oublock;
	a_user_rusage_p->ru_msgsnd = (user32_long_t)a_rusage_p->ru_msgsnd;
	a_user_rusage_p->ru_msgrcv = (user32_long_t)a_rusage_p->ru_msgrcv;
	a_user_rusage_p->ru_nsignals = (user32_long_t)a_rusage_p->ru_nsignals;
	a_user_rusage_p->ru_nvcsw = (user32_long_t)a_rusage_p->ru_nvcsw;
	a_user_rusage_p->ru_nivcsw = (user32_long_t)a_rusage_p->ru_nivcsw;
}

void
kdp_wait4_find_process(thread_t thread, __unused event64_t wait_event, thread_waitinfo_t *waitinfo)
{
	assert(thread != NULL);
	assert(waitinfo != NULL);

	struct uthread *ut = get_bsdthread_info(thread);
	waitinfo->context = 0;
	// ensure wmesg is consistent with a thread waiting in wait4
	assert(!strcmp(ut->uu_wmesg, "waitcoll") || !strcmp(ut->uu_wmesg, "wait"));
	struct wait4_nocancel_args *args = ut->uu_save.uus_wait4_data.args;
	// May not actually contain a pid; this is just the argument to wait4.
	// See man wait4 for other valid wait4 arguments.
	waitinfo->owner = args->pid;
}

int
exit_with_guard_exception(
	proc_t p,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode)
{
	os_reason_t reason = os_reason_create(OS_REASON_GUARD, (uint64_t)code);
	assert(reason != OS_REASON_NULL);

	return exit_with_mach_exception(p, reason, EXC_GUARD, code, subcode);
}

#if __has_feature(ptrauth_calls)
int
exit_with_pac_exception(proc_t p, exception_type_t exception, mach_exception_code_t code,
    mach_exception_subcode_t subcode)
{
	os_reason_t reason = os_reason_create(OS_REASON_PAC_EXCEPTION, (uint64_t)code);
	assert(reason != OS_REASON_NULL);

	return exit_with_mach_exception(p, reason, exception, code, subcode);
}
#endif /* __has_feature(ptrauth_calls) */

int
exit_with_port_space_exception(proc_t p, mach_exception_data_type_t code,
    mach_exception_data_type_t subcode)
{
	os_reason_t reason = os_reason_create(OS_REASON_PORT_SPACE, (uint64_t)code);
	assert(reason != OS_REASON_NULL);

	return exit_with_mach_exception(p, reason, EXC_RESOURCE, code, subcode);
}

static int
exit_with_mach_exception(proc_t p, os_reason_t reason, exception_type_t exception, mach_exception_code_t code,
    mach_exception_subcode_t subcode)
{
	thread_t self = current_thread();
	struct uthread *ut = get_bsdthread_info(self);

	ut->uu_exception = exception;
	ut->uu_code = code;
	ut->uu_subcode = subcode;

	reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
	return exit_with_reason(p, W_EXITCODE(0, SIGKILL), NULL,
	           TRUE, FALSE, 0, reason);
}
