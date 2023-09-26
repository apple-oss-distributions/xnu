/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1986, 1989, 1991, 1993
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
 *	@(#)proc_internal.h	8.15 (Berkeley) 5/19/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef _SYS_PROC_INTERNAL_H_
#define _SYS_PROC_INTERNAL_H_

#include <kern/smr.h>
#include <kern/kalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/cdefs.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/proc_ro.h>
#include <sys/signalvar.h>
#include <mach/resource_monitors.h>     // command/proc_name_t

__BEGIN_DECLS
#include <kern/locks.h>
#if PSYNCH
#include <kern/thread_call.h>
#endif /* PSYNCH */
__END_DECLS

#if DEBUG
#define __PROC_INTERNAL_DEBUG 1
#endif

/*
 * The short form for various locks that protect fields in the data structures.
 * PL   = Process Lock
 * PGL  = Process Group Lock
 * PUCL = Process User Credentials Lock
 * PSL  = Process Spin Lock
 * LL   = List Lock
 * SL   = Session Lock
 * TTYL = TTY Lock
 *
 * C    = constant/static
 */
struct label;

/*
 * Flags kept in the low bits of `struct session::s_refcount`
 */
__options_decl(session_ref_bits_t, uint32_t, {
	S_DEFAULT        = 0x00,
	S_NOCTTY         = 0x01,      /* Do not associate controlling tty */
	S_CTTYREF        = 0x02,      /* vnode ref taken by cttyopen      */
});
#define SESSION_REF_BITS  4           /* 2 is enough, 4 is easier in hex  */
#define SESSION_REF_MASK  ((1u << PGRP_REF_BITS) - 1)

#define SESSION_NULL ((struct session *)NULL)

/*!
 * @struct session
 *
 * @brief
 * Structure to keep track of process sessions
 *
 * @discussion
 * Sessions hang (with +1's) from:
 * - process groups (@c pgrp::pg_session)
 * - ttys (@c tty::t_session)
 *
 * Lock ordering: TTYL > LL > SL
 */
struct session {
	lck_mtx_t               s_mlock;             /* session lock          */
	LIST_ENTRY(session)     s_hash;              /* (LL) hash linkage     */
	struct proc            *s_leader;            /* (C)  session leader   */
	struct vnode           *s_ttyvp;             /* (SL) Vnode of controlling terminal */
	struct tty             *s_ttyp;              /* (SL) Controlling terminal */
	uint32_t                s_ttyvid;            /* (SL) Vnode id of the controlling terminal */
	pid_t                   s_ttypgrpid;         /* (SL) tty's pgrp id    */
	dev_t _Atomic           s_ttydev;            /* (SL) tty's device     */
	pid_t                   s_sid;               /* (C)  Session ID       */
	os_ref_atomic_t         s_refcount;
	char                    s_login[MAXLOGNAME]; /* (SL) Setlogin() name  */
};


/*
 * Flags for pg_refcnt
 */
__options_decl(pggrp_ref_bits_t, uint32_t, {
	PGRP_REF_NONE    = 0x00,
	PGRP_REF_EMPTY   = 0x01, /* the process group has no members */
});
#define PGRP_REF_BITS  1
#define PGRP_REF_MASK  ((1u << PGRP_REF_BITS) - 1)

#define PGRP_NULL ((struct pgrp *)NULL)

/*!
 * @struct pgrp
 *
 * @abstract
 * Describes a process group membership.
 *
 * @discussion
 * <b>locking rules</b>
 *
 * Process groups have a static ID (@c pg_id) and session (@c pg_session),
 * and groups hold a reference on their session.
 *
 * Process group membership is protected by the @c pgrp_lock().
 *
 * Lock ordering: TTYL > LL > PGL
 *
 * <b>lifetime</b>
 * Process groups are refcounted, with a packed bit that tracks whether
 * the group is orphaned (has no members), which prevents it
 * from being looked up.
 *
 * Process groups are retired through @c smr_proc_task_call().
 *
 * Process groups are hashed in a global hash table that can be consulted
 * while holding the @c proc_list_lock() with @c pghash_find_locked()
 * or using hazard pointers with @c pgrp_find().
 */
struct pgrp {
	union {
		lck_mtx_t       pg_mlock;       /* process group lock   (PGL) */
		struct smr_node pg_smr_node;
	};
	struct smrq_slink       pg_hash;        /* hash chain           (PLL) */
	LIST_HEAD(, proc)       pg_members;     /* group members        (PGL) */
	struct session         *pg_session;     /* session           (static) */
	pid_t                   pg_id;          /* group ID          (static) */
	int                     pg_jobc;        /* # procs qualifying pgrp for job control (PGL) */
	os_ref_atomic_t         pg_refcount;
	os_ref_atomic_t         pg_hashref;
};


__options_decl(proc_ref_bits_t, uint32_t, {
	P_REF_NONE       = 0x00u,
	P_REF_NEW        = 0x01u, /* the proc is being initialized */
	P_REF_DEAD       = 0x02u, /* the proc is becoming a zombie */
	P_REF_WILL_EXEC  = 0x04u, /* see proc_refdrain_will_exec() */
	P_REF_IN_EXEC    = 0x08u, /* see proc_refdrain_will_exec() */
	P_REF_DRAINING   = 0x10u, /* someone is in proc_refdrain() */
	P_REF_SHADOW     = 0x20u, /* the proc is shadow proc in exec */
	P_REF_PROC_HOLD  = 0x40u, /* the proc has ref on the proc task combined struct */
	P_REF_TASK_HOLD  = 0x80u, /* the task has ref on the proc task combined struct */
});
#define P_REF_BITS   8
#define P_REF_MASK   ((1u << P_REF_BITS) - 1)

/*
 * Kernel signal definitions and data structures,
 * not exported to user programs.
 */
struct sigacts;

/*
 * Process signal actions and state, needed only within the process
 * (not necessarily resident).
 */
struct  sigacts {
	user_addr_t ps_sigact[NSIG];    /* disposition of signals */
	user_addr_t ps_trampact[NSIG];  /* disposition of signals */
	sigset_t ps_catchmask[NSIG];    /* signals to be blocked */
	sigset_t ps_sigonstack;         /* signals to take on sigstack */
	sigset_t ps_sigintr;            /* signals that interrupt syscalls */
	sigset_t ps_sigreset;           /* signals that reset when caught */
	sigset_t ps_signodefer;         /* signals not masked while handled */
	sigset_t ps_siginfo;            /* signals that want SA_SIGINFO args */
	sigset_t ps_oldmask;            /* saved mask from before sigpause */
	_Atomic uint32_t ps_sigreturn_validation; /* sigreturn argument validation state */
	int     ps_flags;               /* signal flags, below */
	int     ps_sig;                 /* for core dump/debugger XXX */
	int     ps_code;                /* for core dump/debugger XXX */
	int     ps_addr;                /* for core dump/debugger XXX */
};

#define PROC_NULL ((struct proc *)NULL)

/*
 * Description of a process.
 *
 * This structure contains the information needed to manage a thread of
 * control, known in UN*X as a process; it has references to substructures
 * containing descriptions of things that the process uses, but may share
 * with related processes.  The process structure and the substructures
 * are always addressible except for those marked "(PROC ONLY)" below,
 * which might be addressible only on a processor on which the process
 * is running.
 */
struct proc {
	union {
		LIST_ENTRY(proc) p_list;                /* List of all processes. */
		struct smr_node  p_smr_node;
	};
	struct  proc *  XNU_PTRAUTH_SIGNED_PTR("proc.p_pptr") p_pptr;   /* Pointer to parent process.(LL) */
	proc_ro_t       p_proc_ro;
	pid_t           p_ppid;                 /* process's parent pid number */
	pid_t           p_original_ppid;        /* process's original parent pid number, doesn't change if reparented */
	pid_t           p_pgrpid;               /* process group id of the process (LL)*/
	uid_t           p_uid;
	gid_t           p_gid;
	uid_t           p_ruid;
	gid_t           p_rgid;
	uid_t           p_svuid;
	gid_t           p_svgid;
	pid_t           p_sessionid;
	uint64_t        p_puniqueid;            /* parent's unique ID - set on fork/spawn, doesn't change if reparented. */

	lck_mtx_t       p_mlock;                /* mutex lock for proc */
	pid_t           p_pid;                  /* Process identifier for proc_find. (static)*/
	char            p_stat;                 /* S* process status. (PL)*/
	char            p_shutdownstate;
	char            p_kdebug;               /* P_KDEBUG eq (CC)*/
	char            p_btrace;               /* P_BTRACE eq (CC)*/

	LIST_ENTRY(proc) p_pglist;              /* List of processes in pgrp (PGL) */
	LIST_ENTRY(proc) p_sibling;             /* List of sibling processes (LL)*/
	LIST_HEAD(, proc) p_children;           /* Pointer to list of children (LL)*/
	TAILQ_HEAD(, uthread) p_uthlist;        /* List of uthreads (PL) */

	struct smrq_slink p_hash;               /* Hash chain (LL)*/

#if CONFIG_PERSONAS
	struct persona  *p_persona;
	LIST_ENTRY(proc) p_persona_list;
#endif

	lck_mtx_t       p_ucred_mlock;          /* mutex lock to protect p_ucred */
#if CONFIG_AUDIT
	lck_mtx_t       p_audit_mlock;          /* mutex lock to protect audit sessions */
#endif /* CONFIG_AUDIT */

	/* substructures: */
	struct  filedesc p_fd;                  /* open files structure */
	struct  pstats *p_stats;                /* Accounting/statistics (PL) */
	SMR_POINTER(struct plimit *) p_limit;/* Process limits (PL) */
	SMR_POINTER(struct pgrp *XNU_PTRAUTH_SIGNED_PTR("proc.p_pgrp")) p_pgrp; /* Pointer to process group. (LL) */

	struct sigacts  p_sigacts;
	lck_spin_t      p_slock;                /* spin lock for itimer/profil protection */

	int             p_siglist;              /* signals captured back from threads */
	unsigned int    p_flag;                 /* P_* flags. (atomic bit ops) */
	unsigned int    p_lflag;                /* local flags  (PL) */
	unsigned int    p_listflag;             /* list flags (LL) */
	unsigned int    p_ladvflag;             /* local adv flags (atomic) */
	os_ref_atomic_t p_refcount;             /* number of outstanding users */
	os_ref_atomic_t p_waitref;              /* number of users pending transition */
	int             p_childrencnt;          /* children holding ref on parent (LL) */
	int             p_parentref;            /* children lookup ref on parent (LL) */
	pid_t           p_oppid;                /* Save parent pid during ptrace. XXX */
	u_int           p_xstat;                /* Exit status for wait; also stop signal. */
	int             p_aio_total_count;              /* all allocated AIO requests for this proc */

#ifdef _PROC_HAS_SCHEDINFO_
	/* may need cleanup, not used */
	u_int           p_estcpu;               /* Time averaged value of p_cpticks.(used by aio and proc_comapre) */
	fixpt_t         p_pctcpu;               /* %cpu for this process during p_swtime (used by aio)*/
	u_int           p_slptime;              /* used by proc_compare */
#endif /* _PROC_HAS_SCHEDINFO_ */

	struct  itimerval p_realtimer;          /* Alarm timer. (PSL) */
	struct  timeval p_rtime;                /* Real time.(PSL)  */
	struct  itimerval p_vtimer_user;        /* Virtual timers.(PSL)  */
	struct  itimerval p_vtimer_prof;        /* (PSL) */

	struct  timeval p_rlim_cpu;             /* Remaining rlim cpu value.(PSL) */
	int             p_debugger;             /*  NU 1: can exec set-bit programs if suser */
	boolean_t       sigwait;        /* indication to suspend (PL) */
	void    *sigwait_thread;        /* 'thread' holding sigwait(PL)  */
	void    *exit_thread;           /* Which thread is exiting(PL)  */
	/* Following fields are info from SIGCHLD (PL) */
	pid_t   si_pid;                 /* (PL) */
	u_int   si_status;              /* (PL) */
	u_int   si_code;                /* (PL) */
	uid_t   si_uid;                 /* (PL) */

	void * vm_shm;                  /* (SYSV SHM Lock) for sysV shared memory */
	int             p_ractive;
	/* cached proc-specific data required for corpse inspection */
	pid_t             p_responsible_pid;    /* pid resonsible for this process */

#if CONFIG_DTRACE
	int                             p_dtrace_probes;                /* (PL) are there probes for this proc? */
	u_int                           p_dtrace_count;                 /* (sprlock) number of DTrace tracepoints */
	uint8_t                         p_dtrace_stop;                  /* indicates a DTrace-desired stop */
	user_addr_t                     p_dtrace_argv;                  /* (write once, read only after that) */
	user_addr_t                     p_dtrace_envp;                  /* (write once, read only after that) */
	lck_mtx_t                       p_dtrace_sprlock;               /* sun proc lock emulation */
	struct dtrace_ptss_page*        p_dtrace_ptss_pages;            /* (sprlock) list of user ptss pages */
	struct dtrace_ptss_page_entry*  p_dtrace_ptss_free_list;        /* (atomic) list of individual ptss entries */
	struct dtrace_helpers*          p_dtrace_helpers;               /* (dtrace_lock) DTrace per-proc private */
	struct dof_ioctl_data*          p_dtrace_lazy_dofs;             /* (sprlock) unloaded dof_helper_t's */
#endif /* CONFIG_DTRACE */

	__xnu_struct_group(proc_forkcopy_data, p_forkcopy, {
		u_int   p_argslen;       /* Length of process arguments. */
		int     p_argc;                 /* saved argc for sysctl_procargs() */
		user_addr_t user_stack;         /* where user stack was allocated */
		struct  vnode * XNU_PTRAUTH_SIGNED_PTR("proc.p_textvp") p_textvp;       /* Vnode of executable. */
		off_t   p_textoff;              /* offset in executable vnode */

		sigset_t p_sigmask;             /* DEPRECATED */
		sigset_t p_sigignore;   /* Signals being ignored. (PL) */
		sigset_t p_sigcatch;    /* Signals being caught by user.(PL)  */

		u_char  p_priority;     /* (NU) Process priority. */
		u_char  p_resv0;        /* (NU) User-priority based on p_cpu and p_nice. */
		char    p_nice;         /* Process "nice" value.(PL) */
		u_char  p_resv1;        /* (NU) User-priority based on p_cpu and p_nice. */

		// types currently in sys/param.h
		command_t   p_comm;
		proc_name_t p_name;     /* can be changed by the process */
		uint8_t p_xhighbits;    /* Stores the top byte of exit status to avoid truncation*/
		pid_t   p_contproc;     /* last PID to send us a SIGCONT (PL) */

		uint32_t        p_pcaction;     /* action  for process control on starvation */
		uint8_t p_uuid[16];                                /* from LC_UUID load command */

		/*
		 * CPU type and subtype of binary slice executed in
		 * this process.  Protected by proc lock.
		 */
		cpu_type_t      p_cputype;
		cpu_subtype_t   p_cpusubtype;
	});

	TAILQ_HEAD(, aio_workq_entry ) p_aio_activeq;   /* active async IO requests */
	TAILQ_HEAD(, aio_workq_entry ) p_aio_doneq;     /* completed async IO requests */

	struct klist p_klist;  /* knote list (PL ?)*/

	struct  rusage_superset *p_ru;  /* Exit information. (PL) */
	thread_t        p_signalholder;
	thread_t        p_transholder;
	int             p_sigwaitcnt;
	/* DEPRECATE following field  */
	u_short p_acflag;       /* Accounting flags. */
	volatile u_short p_vfs_iopolicy;        /* VFS iopolicy flags. (atomic bit ops) */

	user_addr_t     p_threadstart;          /* pthread start fn */
	user_addr_t     p_wqthread;             /* pthread workqueue fn */
	int     p_pthsize;                      /* pthread size */
	uint32_t        p_pth_tsd_offset;       /* offset from pthread_t to TSD for new threads */
	user_addr_t     p_stack_addr_hint;      /* stack allocation hint for wq threads */
	struct workqueue *_Atomic p_wqptr;                      /* workq ptr */

	struct  timeval p_start;                /* starting time */
	void *  p_rcall;
	void *  p_pthhash;                      /* pthread waitqueue hash */
	volatile uint64_t was_throttled __attribute__((aligned(8))); /* Counter for number of throttled I/Os */
	volatile uint64_t did_throttle __attribute__((aligned(8)));  /* Counter for number of I/Os this proc throttled */

#if DIAGNOSTIC
	unsigned int p_fdlock_pc[4];
	unsigned int p_fdunlock_pc[4];
#if SIGNAL_DEBUG
	unsigned int lockpc[8];
	unsigned int unlockpc[8];
#endif /* SIGNAL_DEBUG */
#endif /* DIAGNOSTIC */
	uint64_t        p_dispatchqueue_offset;
	uint64_t        p_dispatchqueue_serialno_offset;
	uint64_t        p_dispatchqueue_label_offset;
	uint64_t        p_return_to_kernel_offset;
	uint64_t        p_mach_thread_self_offset;
	/* The offset is set to 0 if userspace is not requesting for this feature */
	uint64_t        p_pthread_wq_quantum_offset;
#if VM_PRESSURE_EVENTS
	struct timeval  vm_pressure_last_notify_tstamp;
#endif
	uint8_t p_crash_behavior;  /* bit fields to control behavior on crash. See spawn.h POSIX_SPAWN_PANIC* */
	bool p_posix_spawn_failed; /* indicates that a posix_spawn failed */
	bool p_disallow_map_with_linking; /* used to prevent dyld's map_with_linking() usage after startup */

#if CONFIG_MEMORYSTATUS
#if CONFIG_FREEZE
	uint8_t           p_memstat_freeze_skip_reason; /* memorystaus_freeze_skipped_reason_t. Protected by the freezer mutex. */
#endif /* CONFIG_FREEZE */
	/* Fields protected by proc list lock */
	uint32_t          p_memstat_state;              /* state. Also used as a wakeup channel when the memstat's LOCKED bit changes */
	int32_t           p_memstat_effectivepriority;  /* priority after transaction state accounted for */
	int32_t           p_memstat_requestedpriority;  /* active priority */
	int32_t           p_memstat_assertionpriority;  /* assertion driven priority */
	uint32_t          p_memstat_dirty;              /* dirty state */
	TAILQ_ENTRY(proc) p_memstat_list;               /* priority bucket link */
	uint64_t          p_memstat_userdata;           /* user state */
	uint64_t          p_memstat_idledeadline;       /* time at which process became clean */
	uint64_t          p_memstat_idle_start;         /* abstime process transitions into the idle band */
	uint64_t          p_memstat_idle_delta;         /* abstime delta spent in idle band */
	int32_t           p_memstat_memlimit;           /* cached memory limit, toggles between active and inactive limits */
	int32_t           p_memstat_memlimit_active;    /* memory limit enforced when process is in active jetsam state */
	int32_t           p_memstat_memlimit_inactive;  /* memory limit enforced when process is in inactive jetsam state */
	int32_t           p_memstat_relaunch_flags;     /* flags indicating relaunch behavior for the process */
#if CONFIG_FREEZE
	uint32_t          p_memstat_freeze_sharedanon_pages; /* shared pages left behind after freeze */
	uint32_t          p_memstat_frozen_count;
	uint32_t          p_memstat_thaw_count;
	uint32_t          p_memstat_last_thaw_interval; /* In which freezer interval was this last thawed? */
#endif /* CONFIG_FREEZE */
#endif /* CONFIG_MEMORYSTATUS */

	_Atomic uint32_t  p_user_faults; /* count the number of user faults generated */

	uint32_t          p_memlimit_increase; /* byte increase for memory limit for dyld SPI rdar://problem/49950264, structure packing 32-bit and 64-bit */

	uint64_t p_crash_behavior_deadline; /* mach_continuous_time deadline. After this timestamp p_crash_behavior is invalid */

	uint32_t          p_crash_count;      /* Consecutive crash count threshold */
	uint32_t          p_throttle_timeout; /* Exponential backoff throttle */

	struct os_reason     *p_exit_reason;

#if CONFIG_PROC_UDATA_STORAGE
	uint64_t        p_user_data;                    /* general-purpose storage for userland-provided data */
#endif /* CONFIG_PROC_UDATA_STORAGE */

	char * p_subsystem_root_path;
};

/*
 * Identify a process uniquely.
 * proc_ident's fields match 1-1 with those in struct proc.
 */
struct proc_ident {
	uint64_t        p_uniqueid;
	pid_t           p_pid;
	int             p_idversion;
};

#define PGRPID_DEAD 0xdeaddead

/* p_listflag */
#define P_LIST_WAITING          0x00000010
#define P_LIST_CHILDDRSTART     0x00000080
#define P_LIST_CHILDDRAINED     0x00000100
#define P_LIST_CHILDDRWAIT      0x00000200
#define P_LIST_CHILDLKWAIT      0x00000400
#define P_LIST_DEADPARENT       0x00000800
#define P_LIST_PARENTREFWAIT    0x00001000
#define P_LIST_EXITCOUNT        0x00100000      /* counted for process exit */

/* local flags */
#define P_LDELAYTERM    0x00000001      /* */
#define P_LHASTASK      0x00000002      /* process points to a task */
#define P_LTERM         0x00000004      /* */
#define P_LEXIT         0x00000008      /* */
#define P_LPEXIT        0x00000010
#define P_LTRANSCOMMIT  0x00000020      /* process is committed to trans */
#define P_LINTRANSIT    0x00000040      /* process in exec or in creation */
#define P_LTRANSWAIT    0x00000080      /* waiting for trans to complete */
#define P_LTRACED       0x00000400      /* */
#define P_LSIGEXC       0x00000800      /* */
#define P_LNOATTACH     0x00001000      /* */
#define P_LPPWAIT       0x00002000      /* */
#define P_LPTHREADJITALLOWLIST  0x00004000      /* process has pthread JIT write function allowlist */
#define P_LPTHREADJITFREEZELATE 0x00008000      /* process JIT function allowlist is frozen late */
#define P_LTRACE_WAIT   0x00010000      /* wait for flag to be cleared before starting ptrace */
#define P_LLIMCHANGE    0x00020000      /* process is changing its plimit (rlim_cur, rlim_max) */
#define P_LLIMWAIT      0x00040000
#define P_LWAITED       0x00080000
#define P_LINSIGNAL     0x00100000
#define P_LCUSTOM_STACK 0x00200000      /* process is using custom stack size */
#define P_LRAGE_VNODES  0x00400000
#define P_LREGISTER     0x00800000      /* thread start fns registered  */
#define P_LVMRSRCOWNER  0x01000000      /* can handle the resource ownership of  */
#define P_LTERM_DECRYPTFAIL     0x04000000      /* process terminating due to key failure to decrypt */
#define P_LTERM_JETSAM          0x08000000      /* process is being jetsam'd */

#define P_JETSAM_VMPAGESHORTAGE 0x00000000      /* jetsam: lowest jetsam priority proc, killed due to vm page shortage */
#define P_JETSAM_VMTHRASHING    0x10000000      /* jetsam: lowest jetsam priority proc, killed due to vm thrashing */
#define P_JETSAM_HIWAT          0x20000000      /* jetsam: high water mark */
#define P_JETSAM_PID            0x30000000      /* jetsam: pid */
#define P_JETSAM_IDLEEXIT       0x40000000      /* jetsam: idle exit */
#define P_JETSAM_VNODE          0x50000000      /* jetsam: vnode kill */
#define P_JETSAM_FCTHRASHING    0x60000000      /* jetsam: lowest jetsam priority proc, killed due to filecache thrashing */
#define P_JETSAM_MASK           0x70000000      /* jetsam type mask */
#define P_LNSPACE_RESOLVER      0x80000000      /* process is the namespace resolver */

/* Process control state for resource starvation */
#define P_PCTHROTTLE    1
#define P_PCSUSP        2
#define P_PCKILL        3
#define P_PCMAX         3

/* Process control action state on resrouce starvation */
#define PROC_ACTION_MASK 0xffff0000;
#define PROC_CONTROL_STATE(p) (p->p_pcaction & P_PCMAX)
#define PROC_ACTION_STATE(p) ((p->p_pcaction >> 16) & P_PCMAX)
#define PROC_SETACTION_STATE(p) (p->p_pcaction = (PROC_CONTROL_STATE(p) | (PROC_CONTROL_STATE(p) << 16)))
#define PROC_RESETACTION_STATE(p) (p->p_pcaction = PROC_CONTROL_STATE(p))

/* Process exit reason macros */
#define PROC_HAS_EXITREASON(p) (p->p_exit_reason != OS_REASON_NULL)
#define PROC_EXITREASON_FLAGS(p) p->p_exit_reason->osr_flags

/* additional process flags */
#define P_LADVLOCK              0x01
#define P_LXBKIDLEINPROG        0x02
#define P_RSR                   0x04

/* p_vfs_iopolicy flags */
#define P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY       0x0001
#define P_VFS_IOPOLICY_ATIME_UPDATES                    0x0002
#define P_VFS_IOPOLICY_MATERIALIZE_DATALESS_FILES       0x0004
#define P_VFS_IOPOLICY_STATFS_NO_DATA_VOLUME            0x0008
#define P_VFS_IOPOLICY_TRIGGER_RESOLVE_DISABLE          0x0010
#define P_VFS_IOPOLICY_IGNORE_CONTENT_PROTECTION        0x0020
#define P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS          0x0040
#define P_VFS_IOPOLICY_SKIP_MTIME_UPDATE                0x0080
#define P_VFS_IOPOLICY_ALLOW_LOW_SPACE_WRITES           0x0100
#define P_VFS_IOPOLICY_DISALLOW_RW_FOR_O_EVTONLY        0x0200
#define P_VFS_IOPOLICY_ALTLINK                          0x0400
#define P_VFS_IOPOLICY_NOCACHE_WRITE_FS_BLKSIZE         0x0800

#define P_VFS_IOPOLICY_INHERITED_MASK                   \
	(P_VFS_IOPOLICY_FORCE_HFS_CASE_SENSITIVITY | \
	P_VFS_IOPOLICY_ATIME_UPDATES | \
	P_VFS_IOPOLICY_MATERIALIZE_DATALESS_FILES | \
	P_VFS_IOPOLICY_STATFS_NO_DATA_VOLUME | \
	P_VFS_IOPOLICY_TRIGGER_RESOLVE_DISABLE | \
	P_VFS_IOPOLICY_IGNORE_CONTENT_PROTECTION | \
	P_VFS_IOPOLICY_IGNORE_NODE_PERMISSIONS | \
	P_VFS_IOPOLICY_SKIP_MTIME_UPDATE | \
	P_VFS_IOPOLICY_DISALLOW_RW_FOR_O_EVTONLY | \
	P_VFS_IOPOLICY_ALTLINK | \
	P_VFS_IOPOLICY_NOCACHE_WRITE_FS_BLKSIZE)

#define P_VFS_IOPOLICY_VALID_MASK                       \
	(P_VFS_IOPOLICY_INHERITED_MASK | \
	P_VFS_IOPOLICY_ALLOW_LOW_SPACE_WRITES)

/* process creation arguments */
#define PROC_CREATE_FORK        0       /* independent child (running) */
#define PROC_CREATE_SPAWN       1       /* independent child (suspended) */

/* LP64 version of extern_proc.  all pointers
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with extern_proc
 * but use native alignment of 64-bit process.
 */

#ifdef KERNEL
#include <sys/time.h>   /* user_timeval, user_itimerval */

/*
 * This packing is required to ensure symmetry between userspace and kernelspace
 * when the kernel is 64-bit and the user application is 32-bit. All currently
 * supported ARM slices (arm64/armv7k/arm64_32) contain the same struct
 * alignment ABI so this packing isn't needed for ARM.
 */
#if defined(__x86_64__)
#pragma pack(4)
#endif
struct user32_extern_proc {
	union {
		struct {
			uint32_t __p_forw;      /* Doubly-linked run/sleep queue. */
			uint32_t __p_back;
		} p_st1;
		struct user32_timeval __p_starttime;    /* process start time */
	} p_un;
	uint32_t        p_vmspace;      /* Address space. */
	uint32_t        p_sigacts;      /* Signal actions, state (PROC ONLY). */
	int             p_flag;                 /* P_* flags. */
	char    p_stat;                 /* S* process status. */
	pid_t   p_pid;                  /* Process identifier. */
	pid_t   p_oppid;                /* Save parent pid during ptrace. XXX */
	int             p_dupfd;                /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	uint32_t user_stack;    /* where user stack was allocated */
	uint32_t exit_thread;  /* XXX Which thread is exiting? */
	int             p_debugger;             /* allow to debug */
	boolean_t       sigwait;        /* indication to suspend */
	/* scheduling */
	u_int   p_estcpu;        /* Time averaged value of p_cpticks. */
	int             p_cpticks;       /* Ticks of cpu time. */
	fixpt_t p_pctcpu;        /* %cpu for this process during p_swtime */
	uint32_t        p_wchan;         /* Sleep address. */
	uint32_t        p_wmesg;         /* Reason for sleep. */
	u_int   p_swtime;        /* Time swapped in or out. */
	u_int   p_slptime;       /* Time since last blocked. */
	struct  user32_itimerval p_realtimer;   /* Alarm timer. */
	struct  user32_timeval p_rtime; /* Real time. */
	u_quad_t p_uticks;              /* Statclock hits in user mode. */
	u_quad_t p_sticks;              /* Statclock hits in system mode. */
	u_quad_t p_iticks;              /* Statclock hits processing intr. */
	int             p_traceflag;            /* Kernel trace points. */
	uint32_t        p_tracep;       /* Trace to vnode. */
	int             p_siglist;              /* DEPRECATED */
	uint32_t        p_textvp;       /* Vnode of executable. */
	int             p_holdcnt;              /* If non-zero, don't swap. */
	sigset_t p_sigmask;     /* DEPRECATED. */
	sigset_t p_sigignore;   /* Signals being ignored. */
	sigset_t p_sigcatch;    /* Signals being caught by user. */
	u_char  p_priority;     /* Process priority. */
	u_char  p_usrpri;       /* User-priority based on p_cpu and p_nice. */
	char    p_nice;         /* Process "nice" value. */
	char    p_comm[MAXCOMLEN + 1];
	uint32_t        p_pgrp; /* Pointer to process group. */
	uint32_t        p_addr; /* Kernel virtual addr of u-area (PROC ONLY). */
	u_short p_xstat;        /* Exit status for wait; also stop signal. */
	u_short p_acflag;       /* Accounting flags. */
	uint32_t        p_ru;   /* Exit information. XXX */
};
#pragma pack()
struct user64_extern_proc {
	union {
		struct {
			user_addr_t __p_forw;   /* Doubly-linked run/sleep queue. */
			user_addr_t __p_back;
		} p_st1;
		struct user64_timeval __p_starttime;    /* process start time */
	} p_un;
	user_addr_t     p_vmspace;      /* Address space. */
	user_addr_t             p_sigacts;      /* Signal actions, state (PROC ONLY). */
	int             p_flag;                 /* P_* flags. */
	char    p_stat;                 /* S* process status. */
	pid_t   p_pid;                  /* Process identifier. */
	pid_t   p_oppid;                /* Save parent pid during ptrace. XXX */
	int             p_dupfd;                /* Sideways return value from fdopen. XXX */
	/* Mach related  */
	user_addr_t user_stack __attribute((aligned(8)));       /* where user stack was allocated */
	user_addr_t exit_thread;  /* XXX Which thread is exiting? */
	int             p_debugger;             /* allow to debug */
	boolean_t       sigwait;        /* indication to suspend */
	/* scheduling */
	u_int   p_estcpu;        /* Time averaged value of p_cpticks. */
	int             p_cpticks;       /* Ticks of cpu time. */
	fixpt_t p_pctcpu;        /* %cpu for this process during p_swtime */
	user_addr_t     p_wchan __attribute((aligned(8)));       /* Sleep address. */
	user_addr_t     p_wmesg;         /* Reason for sleep. */
	u_int   p_swtime;        /* Time swapped in or out. */
	u_int   p_slptime;       /* Time since last blocked. */
	struct  user64_itimerval p_realtimer;   /* Alarm timer. */
	struct  user64_timeval p_rtime; /* Real time. */
	u_quad_t p_uticks;              /* Statclock hits in user mode. */
	u_quad_t p_sticks;              /* Statclock hits in system mode. */
	u_quad_t p_iticks;              /* Statclock hits processing intr. */
	int             p_traceflag;            /* Kernel trace points. */
	user_addr_t     p_tracep __attribute((aligned(8)));     /* Trace to vnode. */
	int             p_siglist;              /* DEPRECATED */
	user_addr_t     p_textvp __attribute((aligned(8)));     /* Vnode of executable. */
	int             p_holdcnt;              /* If non-zero, don't swap. */
	sigset_t p_sigmask;     /* DEPRECATED. */
	sigset_t p_sigignore;   /* Signals being ignored. */
	sigset_t p_sigcatch;    /* Signals being caught by user. */
	u_char  p_priority;     /* Process priority. */
	u_char  p_usrpri;       /* User-priority based on p_cpu and p_nice. */
	char    p_nice;         /* Process "nice" value. */
	char    p_comm[MAXCOMLEN + 1];
	user_addr_t     p_pgrp __attribute((aligned(8)));       /* Pointer to process group. */
	user_addr_t     p_addr; /* Kernel virtual addr of u-area (PROC ONLY). */
	u_short p_xstat;        /* Exit status for wait; also stop signal. */
	u_short p_acflag;       /* Accounting flags. */
	user_addr_t     p_ru __attribute((aligned(8))); /* Exit information. XXX */
};
#endif  /* KERNEL */

#pragma GCC visibility push(hidden)

extern struct vfs_context vfs_context0;

/*
 * We use process IDs <= PID_MAX; PID_MAX + 1 must also fit in a pid_t,
 * as it is used to represent "no process group".
 */
extern int nprocs, maxproc;             /* Current and max number of procs. */
extern int maxprocperuid;               /* Current number of procs per uid */
extern int hard_maxproc;        /* hard limit */
extern unsigned int proc_shutdown_exitcount;

#define PID_MAX         99999
#define NO_PID          100000
extern lck_mtx_t proc_list_mlock;

#define BSD_SIMUL_EXECS         33 /* 32 , allow for rounding */
#define BSD_PAGEABLE_SIZE_PER_EXEC      (NCARGS + PAGE_SIZE + PAGE_SIZE) /* page for apple vars, page for executable header */
extern int execargs_cache_size;
extern int execargs_free_count;
extern vm_offset_t * execargs_cache;

#define SESS_LEADER(p, sessp)   ((sessp)->s_leader == (p))

#define SESSHASH(sessid) (&sesshashtbl[(sessid) & sesshash])
extern LIST_HEAD(sesshashhead, session) * sesshashtbl;
extern u_long sesshash;

extern lck_attr_t proc_lck_attr;
extern lck_grp_t proc_fdmlock_grp;
extern lck_grp_t proc_lck_grp;
extern lck_grp_t proc_kqhashlock_grp;
extern lck_grp_t proc_knhashlock_grp;
extern lck_grp_t proc_slock_grp;
extern lck_grp_t proc_mlock_grp;
extern lck_grp_t proc_ucred_mlock_grp;
extern lck_grp_t proc_dirslock_grp;

LIST_HEAD(proclist, proc);
extern struct proclist allproc;         /* List of all processes. */
extern struct proclist zombproc;        /* List of zombie processes. */

#if CONFIG_COREDUMP
extern const char * defaultcorefiledir;
extern const char * defaultdrivercorefiledir;
extern char corefilename[MAXPATHLEN + 1];
extern char drivercorefilename[MAXPATHLEN + 1];
extern int do_coredump;
extern int sugid_coredump;
#endif

__options_decl(cloneproc_flags_t, uint32_t, {
	CLONEPROC_FLAGS_NONE             = 0,
	CLONEPROC_FLAGS_INHERIT_MEMORY   = 0x0001,
	CLONEPROC_FLAGS_MEMSTAT_INTERNAL = 0x0002,
	CLONEPROC_FLAGS_FOR_EXEC         = 0x0004,
});

extern thread_t cloneproc(task_t, coalition_t *, proc_t, cloneproc_flags_t);
extern struct proc * XNU_PTRAUTH_SIGNED_PTR("initproc") initproc;
extern void proc_lock(struct proc *);
extern void proc_unlock(struct proc *);
extern void proc_spinlock(struct proc *);
extern void proc_spinunlock(struct proc *);
extern void proc_list_lock(void);
extern void proc_list_unlock(void);
extern void proc_klist_lock(void);
extern void proc_klist_unlock(void);
extern void proc_fdlock(struct proc *);
extern void proc_fdlock_spin(struct proc *);
extern void proc_fdunlock(struct proc *);
extern void proc_fdlock_assert(proc_t p, int assertflags);
extern void proc_dirs_lock_shared(struct proc *);
extern void proc_dirs_unlock_shared(struct proc *);
extern void proc_dirs_lock_exclusive(struct proc *);
extern void proc_dirs_unlock_exclusive(struct proc *);
extern void proc_ucred_lock(struct proc *);
extern void proc_ucred_unlock(struct proc *);
extern void proc_update_creds_onproc(struct proc *, kauth_cred_t cred);
extern kauth_cred_t proc_ucred_locked(proc_t p);
extern kauth_cred_t proc_ucred_smr(proc_t p);
extern kauth_cred_t proc_ucred_unsafe(proc_t p) __exported;
#if CONFIG_COREDUMP
__private_extern__ int proc_core_name(const char *format, const char *name, uid_t uid, pid_t pid,
    char *cr_name, size_t cr_name_len);
#endif
extern int isinferior(struct proc *, struct proc *);
__private_extern__ struct proc *pzfind(pid_t);  /* Find zombie by id. */
__private_extern__ struct proc *proc_find_zombref(pid_t);       /* Find zombie by id. */
__private_extern__ void proc_drop_zombref(struct proc * p);     /* Find zombie by id. */

extern size_t   chgproccnt(uid_t uid, int diff);
extern void     pinsertchild(struct proc *parent, struct proc *child, bool in_exec);
extern void     p_reparentallchildren(proc_t old_proc, proc_t new_proc);
extern int      setsid_internal(struct proc *p);
#ifndef __cplusplus
extern void     setlogin_internal(proc_t p, const char login[static MAXLOGNAME]);
#endif // __cplusplus
extern int      setgroups_internal(proc_t p, u_int gidsetsize, gid_t *gidset, uid_t gmuid);
extern int      enterpgrp(struct proc *p, pid_t pgid, int mksess);
extern void     fixjobc(struct proc *p, struct pgrp *pgrp, int entering);
extern int      inferior(struct proc *p);
extern void     resetpriority(struct proc *);
extern void     setrunnable(struct proc *);
extern void     setrunqueue(struct proc *);
extern int      sleep(void *chan, int pri) __exported;
extern int      tsleep0(void *chan, int pri, const char *wmesg, int timo, int (*continuation)(int));
extern int      tsleep1(void *chan, int pri, const char *wmesg, u_int64_t abstime, int (*continuation)(int));
extern int      exit1(struct proc *, int, int *);
extern int      exit1_internal(struct proc *, int, int *, boolean_t, boolean_t, int);
extern int      exit_with_reason(struct proc *, int, int *, boolean_t, boolean_t, int, struct os_reason *);
extern int      fork1(proc_t, thread_t *, int, coalition_t *);
extern void proc_reparentlocked(struct proc *child, struct proc * newparent, int cansignal, int locked);

extern bool   proc_list_exited(proc_t p);
extern proc_t proc_find_locked(int pid);
extern bool proc_is_shadow(proc_t p);
extern proc_t proc_findthread(thread_t thread);
extern void proc_refdrain(proc_t);
extern proc_t proc_refdrain_will_exec(proc_t p);
extern void proc_refwake_did_exec(proc_t p);
extern void proc_childdrainlocked(proc_t);
extern void proc_childdrainstart(proc_t);
extern void proc_childdrainend(proc_t);
extern void  proc_checkdeadrefs(proc_t);
struct proc *phash_find_locked(pid_t);
extern void phash_insert_locked(struct proc *);
extern void phash_remove_locked(struct proc *);
extern void phash_replace_locked(struct proc *old_proc, struct proc *new_proc);
extern bool pghash_exists_locked(pid_t);
extern void pghash_insert_locked(struct pgrp *);
extern struct pgrp *pgrp_find(pid_t);
extern void pgrp_rele(struct pgrp * pgrp);
extern struct session * session_find_internal(pid_t sessid);
extern struct pgrp *proc_pgrp(proc_t, struct session **);
extern struct pgrp *pgrp_leave_locked(struct proc *p);
extern struct pgrp *pgrp_enter_locked(struct proc *parent, struct proc *p);
extern struct pgrp *tty_pgrp_locked(struct tty * tp);
struct pgrp *pgrp_alloc(pid_t pgid, pggrp_ref_bits_t bits);
extern void pgrp_lock(struct pgrp * pgrp);
extern void pgrp_unlock(struct pgrp * pgrp);
extern struct session *session_find_locked(pid_t sessid);
extern void session_replace_leader(struct proc *old_proc, struct proc *new_proc);
extern struct session *session_alloc(struct proc *leader);
extern void session_lock(struct session * sess);
extern void session_unlock(struct session * sess);
extern struct session *session_ref(struct session *sess);
extern void session_rele(struct session *sess);
extern struct tty *session_set_tty_locked(struct session *sessp, struct tty *);
extern struct tty *session_clear_tty_locked(struct session *sess);
extern struct tty *session_tty(struct session *sess);
extern proc_t proc_parentholdref(proc_t);
extern int proc_parentdropref(proc_t, int);
int  itimerfix(struct timeval *tv);
int  itimerdecr(struct proc * p, struct itimerval *itp, int usec);
void proc_free_realitimer(proc_t proc);
void proc_inherit_itimers(struct proc *old_proc, struct proc *new_proc);
int  timespec_is_valid(const struct timespec *);
void proc_signalstart(struct proc *, int locked);
void proc_signalend(struct proc *, int locked);
int  proc_transstart(struct proc *, int locked, int non_blocking);
void proc_transcommit(struct proc *, int locked);
void proc_transend(struct proc *, int locked);
int  proc_transwait(struct proc *, int locked);
struct proc *proc_ref(struct proc *p, int locked);
void proc_wait_release(struct proc *p);
void proc_knote(struct proc * p, long hint);
void proc_transfer_knotes(struct proc *old_proc, struct proc *new_proc);
void proc_knote_drain(struct proc *p);
void proc_setregister(proc_t p);
void proc_resetregister(proc_t p);
bool proc_get_pthread_jit_allowlist(proc_t p, bool *late_out);
void proc_set_pthread_jit_allowlist(proc_t p, bool late);
/* returns the first thread_t in the process, or NULL XXX for NFS, DO NOT USE */
thread_t proc_thread(proc_t);
extern int proc_pendingsignals(proc_t, sigset_t);
int proc_getpcontrol(int pid, int * pcontrolp);
int proc_dopcontrol(proc_t p);
int proc_resetpcontrol(int pid);
#if PSYNCH
void pth_proc_hashinit(proc_t);
void pth_proc_hashdelete(proc_t);
void pth_global_hashinit(void);
extern thread_call_t psynch_thcall;
void psynch_wq_cleanup(__unused void *  param, __unused void * param1);
extern lck_mtx_t * pthread_list_mlock;
#endif /* PSYNCH */
struct uthread *current_uthread(void) __pure2;

extern void proc_set_task(proc_t, task_t);
extern task_t proc_get_task_raw(proc_t proc);
extern proc_t task_get_proc_raw(task_t task);
extern void proc_ref_hold_proc_task_struct(proc_t proc);
extern void proc_release_proc_task_struct(proc_t proc);
extern void task_ref_hold_proc_task_struct(task_t task);
extern void task_release_proc_task_struct(task_t task);
extern void proc_setpidversion(proc_t, int);
extern uint64_t proc_getcsflags(proc_t);
extern void proc_csflags_update(proc_t, uint64_t);
extern void proc_csflags_set(proc_t, uint64_t);
extern void proc_csflags_clear(proc_t, uint64_t);
extern uint8_t *proc_syscall_filter_mask(proc_t);
extern void proc_syscall_filter_mask_set(proc_t, uint8_t *);
extern pid_t proc_getpid(proc_t);
extern void proc_setplatformdata(proc_t, uint32_t, uint32_t, uint32_t);
extern void proc_set_sigact(proc_t, int, user_addr_t);
extern void proc_set_trampact(proc_t, int, user_addr_t);
extern void proc_set_sigact_trampact(proc_t, int, user_addr_t, user_addr_t);
extern void proc_reset_sigact(proc_t, sigset_t);
extern void proc_setexecutableuuid(proc_t, const uuid_t);
extern const unsigned char *proc_executableuuid_addr(proc_t);


#pragma mark - process iteration

/*
 * ALLPROC_FOREACH cannot be used to access the task, as the field may be
 * swapped out during exec.  With `proc_iterate`, find threads by iterating the
 * `p_uthlist` field of the proc, under the `proc_lock`.
 */

#define ALLPROC_FOREACH(var) \
	LIST_FOREACH((var), &allproc, p_list)

#define ZOMBPROC_FOREACH(var) \
	LIST_FOREACH((var), &zombproc, p_list)

#define PGMEMBERS_FOREACH(group, var) \
	LIST_FOREACH((var), &((struct pgrp *)(group))->pg_members, p_pglist)

#define PCHILDREN_FOREACH(parent, var) \
	LIST_FOREACH((var), &(((struct proc *)(parent))->p_children), p_sibling)

typedef int (*proc_iterate_fn_t)(proc_t, void *);

/*
 * These are the only valid return values of `callout` functions provided to
 * process iterators.
 *
 * CLAIMED returns expect the caller to call proc_rele on the proc.  DONE
 * returns stop iterating processes early.
 */
#define PROC_RETURNED      (0)
#define PROC_RETURNED_DONE (1)
#define PROC_CLAIMED       (2)
#define PROC_CLAIMED_DONE  (3)

/*
 * pgrp_iterate walks the provided process group, calling `filterfn` with
 * `filterarg` for each process.  For processes where `filterfn` returned
 * non-zero, `callout` is called with `arg`.
 *
 * `PGMEMBERS_FOREACH` might also be used under the pgrp_lock to achieve a
 * similar effect.
 */

extern void pgrp_iterate(struct pgrp *pgrp, proc_iterate_fn_t callout,
    void *arg, bool (^filterfn)(proc_t));

/*
 * proc_iterate walks the `allproc` and/or `zombproc` lists, calling `filterfn`
 * with `filterarg` for each process.  For processes where `filterfn` returned
 * non-zero, `callout` is called with `arg`.  If the `PROC_NOWAITTRANS` flag is
 * unset, this function waits for transitions.
 *
 * `ALLPROC_FOREACH` or `ZOMBPROC_FOREACH` might also be used under the
 * `proc_list_lock` to achieve a similar effect.
 */
#define PROC_ALLPROCLIST  (1U << 0) /* walk the allproc list (processes not yet exited) */
#define PROC_ZOMBPROCLIST (1U << 1) /* walk the zombie list */
#define PROC_NOWAITTRANS  (1U << 2) /* do not wait for transitions (checkdirs only) */

extern void proc_iterate(unsigned int flags, proc_iterate_fn_t callout,
    void *arg, proc_iterate_fn_t filterfn, void *filterarg);

/*
 * proc_childrenwalk walks the children of process `p`, calling `callout` for
 * each one.
 *
 * `PCHILDREN_FOREACH` might also be used under the `proc_list_lock` to achieve
 * a similar effect.
 */
extern void proc_childrenwalk(proc_t p, proc_iterate_fn_t callout, void *arg);

/*
 * proc_rebootscan should only be used by kern_shutdown.c
 */
extern void proc_rebootscan(proc_iterate_fn_t callout, void *arg,
    proc_iterate_fn_t filterfn, void *filterarg);

pid_t dtrace_proc_selfpid(void);
pid_t dtrace_proc_selfppid(void);
uid_t dtrace_proc_selfruid(void);

os_refgrp_decl_extern(p_refgrp);
KALLOC_TYPE_DECLARE(proc_stats_zone);
ZONE_DECLARE_ID(ZONE_ID_PROC_TASK, struct proc);
extern zone_t proc_task_zone;

extern struct proc_ident proc_ident(proc_t p);

#if CONFIG_PROC_RESOURCE_LIMITS
int proc_set_filedesc_limits(proc_t p, int soft_limit, int hard_limit);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

/*
 * True if the process ignores file permissions in case it owns the
 * file/directory
 */
bool proc_ignores_node_permissions(proc_t proc);

#pragma GCC visibility pop
#endif  /* !_SYS_PROC_INTERNAL_H_ */
