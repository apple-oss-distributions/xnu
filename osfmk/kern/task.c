/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 *	File:	kern/task.c
 *	Author:	Avadis Tevanian, Jr., Michael Wayne Young, David Golub,
 *		David Black
 *
 *	Task management primitives implementation.
 */
/*
 * Copyright (c) 1993 The University of Utah and
 * the Computer Systems Laboratory (CSL).  All rights reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * THE UNIVERSITY OF UTAH AND CSL ALLOW FREE USE OF THIS SOFTWARE IN ITS "AS
 * IS" CONDITION.  THE UNIVERSITY OF UTAH AND CSL DISCLAIM ANY LIABILITY OF
 * ANY KIND FOR ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * CSL requests users of this software to return to csl-dist@cs.utah.edu any
 * improvements that they make and grant CSL redistribution rights.
 *
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 * Copyright (c) 2005 SPARTA, Inc.
 */

#include <mach/mach_types.h>
#include <mach/boolean.h>
#include <mach/host_priv.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_param.h>
#include <mach/mach_vm.h>
#include <mach/semaphore.h>
#include <mach/task_info.h>
#include <mach/task_inspect.h>
#include <mach/task_special_ports.h>
#include <mach/sdt.h>
#include <mach/mach_test_upcall.h>

#include <ipc/ipc_importance.h>
#include <ipc/ipc_types.h>
#include <ipc/ipc_space.h>
#include <ipc/ipc_entry.h>
#include <ipc/ipc_hash.h>
#include <ipc/ipc_policy.h>

#include <kern/kern_types.h>
#include <kern/mach_param.h>
#include <kern/misc_protos.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/coalition.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/kern_cdata.h>
#include <kern/processor.h>
#include <kern/recount.h>
#include <kern/sched_prim.h>    /* for thread_wakeup */
#include <kern/ipc_tt.h>
#include <kern/host.h>
#include <kern/clock.h>
#include <kern/timer.h>
#include <kern/assert.h>
#include <kern/affinity.h>
#include <kern/exc_resource.h>
#include <kern/exc_guard.h>
#include <kern/machine.h>
#include <kern/policy_internal.h>
#include <kern/restartable.h>
#include <kern/ipc_kobject.h>

#include <corpses/task_corpse.h>
#if CONFIG_TELEMETRY
#include <kern/telemetry.h>
#endif

#if CONFIG_PERVASIVE_CPI
#include <kern/monotonic.h>
#include <machine/monotonic.h>
#endif /* CONFIG_PERVASIVE_CPI */

#if CONFIG_EXCLAVES
#include "exclaves_boot.h"
#include "exclaves_resource.h"
#include "exclaves_boot.h"
#include "exclaves_inspection.h"
#include "exclaves_conclave.h"
#endif /* CONFIG_EXCLAVES */

#include <os/log.h>

#include <vm/pmap.h>
#include <vm/vm_map_lock_internal.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_kern_xnu.h>         /* for kernel_map, ipc_kernel_map */
#include <vm/vm_pageout_xnu.h>
#include <vm/vm_protos.h>
#include <vm/vm_purgeable_xnu.h>
#include <vm/vm_compressor_backing_store_xnu.h>
#include <vm/vm_compressor_pager_xnu.h>
#include <vm/vm_reclaim_xnu.h>
#include <vm/vm_compressor_xnu.h>

#include <sys/kdebug.h>
#include <sys/proc_ro.h>
#include <sys/resource.h>
#include <sys/signalvar.h> /* for coredump */
#include <sys/bsdtask_info.h>
#include <sys/kdebug_triage.h>
#include <sys/code_signing.h> /* for is_address_space_debugged */
#include <sys/reason.h>
/*
 * Exported interfaces
 */

#include <mach/task_server.h>
#include <mach/mach_host_server.h>
#include <mach/mach_port_server.h>

#include <vm/vm_shared_region_xnu.h>

#include <libkern/OSDebug.h>
#include <libkern/OSAtomic.h>
#include <libkern/section_keywords.h>

#include <mach-o/loader.h>
#include <kdp/kdp_dyld.h>

#include <kern/sfi.h>           /* picks up ledger.h */

#if CONFIG_MACF
#include <security/mac_mach_internal.h>
#endif

#include <IOKit/IOBSD.h>
#include <kdp/processor_core.h>

#if defined (__arm64__)
#include <pexpert/arm64/board_config.h>
#endif

#include <string.h>

static KALLOC_TYPE_DEFINE(task_tokens_zone, struct task_token_data, KT_DEFAULT);

#if KPERF
extern int kpc_force_all_ctrs(task_t, int);
#endif

SECURITY_READ_ONLY_LATE(task_t) kernel_task;

int64_t         next_taskuniqueid = 0;
const size_t task_alignment = _Alignof(struct task);
extern const size_t proc_alignment;
extern size_t proc_struct_size;
extern size_t proc_and_task_size;
size_t task_struct_size;

extern int large_corpse_count;

extern boolean_t proc_send_synchronous_EXC_RESOURCE(void *p);
extern boolean_t proc_is_simulated(const proc_t);

static void task_port_no_senders(ipc_port_t, mach_msg_type_number_t);
static void task_port_with_flavor_no_senders(ipc_port_t, mach_msg_type_number_t);
static void task_suspension_no_senders(ipc_port_t, mach_msg_type_number_t);
static inline void task_zone_init(void);

static void task_store_owned_vmobject_info(task_t to_task, task_t from_task);
static void task_set_control_port_options(task_t task, task_control_port_options_t opts);

#if CONFIG_EXCLAVES
static bool task_should_panic_on_exit_due_to_conclave_taint(task_t task);
static bool task_is_conclave_tainted(task_t task);
static void task_set_conclave_taint(task_t task);
kern_return_t task_crash_info_conclave_upcall(task_t task,
    const struct conclave_sharedbuffer_t *shared_buf, uint32_t length);
#endif /* CONFIG_EXCLAVES */

IPC_KOBJECT_DEFINE(IKOT_TASK_NAME,
    .iko_op_movable_send = true);
IPC_KOBJECT_DEFINE(IKOT_TASK_CONTROL,
    .iko_op_no_senders = task_port_no_senders,
    .iko_op_movable_send = true, /* see ipc_should_mark_immovable_send */
    .iko_op_label_free = ipc_kobject_label_free);
IPC_KOBJECT_DEFINE(IKOT_TASK_READ,
    .iko_op_no_senders = task_port_with_flavor_no_senders,
    .iko_op_label_free = ipc_kobject_label_free);
IPC_KOBJECT_DEFINE(IKOT_TASK_INSPECT,
    .iko_op_no_senders = task_port_with_flavor_no_senders);
IPC_KOBJECT_DEFINE(IKOT_TASK_RESUME,
    .iko_op_movable_send = true,
    .iko_op_no_senders = task_suspension_no_senders);

#if CONFIG_PROC_RESOURCE_LIMITS
static void task_fatal_port_no_senders(ipc_port_t, mach_msg_type_number_t);
static mach_port_t task_allocate_fatal_port(void);

IPC_KOBJECT_DEFINE(IKOT_TASK_FATAL,
    .iko_op_movable_send = true,
    .iko_op_stable     = true,
    .iko_op_no_senders = task_fatal_port_no_senders);

extern void task_id_token_set_port(task_id_token_t token, ipc_port_t port);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

/* Flag set by core audio when audio is playing. Used to stifle EXC_RESOURCE generation when active. */
int audio_active = 0;

/*
 *	structure for tracking zone usage
 *	Used either one per task/thread for all zones or <per-task,per-zone>.
 */
typedef struct zinfo_usage_store_t {
	/* These fields may be updated atomically, and so must be 8 byte aligned */
	uint64_t        alloc __attribute__((aligned(8)));              /* allocation counter */
	uint64_t        free __attribute__((aligned(8)));               /* free counter */
} zinfo_usage_store_t;

/**
 * Return codes related to diag threshold and memory limit
 */
__options_decl(diagthreshold_check_return, int, {
	THRESHOLD_IS_SAME_AS_LIMIT_FLAG_DISABLED        = 0,
	THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED         = 1,
	THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED    = 2,
	THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_ENABLED     = 3,
});

/**
 * Return codes related to diag threshold and memory limit
 */
__options_decl(current_, int, {
	THRESHOLD_IS_SAME_AS_LIMIT      = 0,
	THRESHOLD_IS_NOT_SAME_AS_LIMIT  = 1
});

zinfo_usage_store_t tasks_tkm_private;
zinfo_usage_store_t tasks_tkm_shared;

/* A container to accumulate statistics for expired tasks */
expired_task_statistics_t               dead_task_statistics;
LCK_SPIN_DECLARE_ATTR(dead_task_statistics_lock, &task_lck_grp, &task_lck_attr);

/* global lock for task_dyld_process_info_notify_{register, deregister, get_trap} */
LCK_GRP_DECLARE(g_dyldinfo_mtx_grp, "g_dyldinfo");
LCK_MTX_DECLARE(g_dyldinfo_mtx, &g_dyldinfo_mtx_grp);

static void task_io_rate_exceeded(ledger_warning_t warning, const void *param0)
asm("_SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MUCH_IO");
static void task_wakeups_rate_exceeded(ledger_warning_t warning, const void *param0)
asm("_SENDING_NOTIFICATION__THIS_PROCESS_IS_CAUSING_TOO_MANY_WAKEUPS");
static void task_footprint_exceeded(ledger_warning_t warning, const void *param0);
static void task_conclave_mem_limit_exceeded(ledger_warning_t warning, const void *param0);

SECURITY_READ_ONLY_LATE(struct _task_ledger_indices) task_ledgers;

static SECURITY_READ_ONLY_LATE(struct ledger_entry_template) task_ledger_entries[] =
{ LEDGER_ENTRY("cpu_time", "sched", "ns", LFEAT_DEBIT | LFEAT_REFILL),

  LEDGER_ENTRY("tkm_private", "physmem", "bytes", LFEAT_SCALABLE),
  LEDGER_ENTRY("tkm_shared", "physmem", "bytes", LFEAT_SCALABLE),
  LEDGER_ENTRY("phys_mem", "physmem", "bytes", LFEAT_SCALABLE | LFEAT_MAXIMUM),
  LEDGER_ENTRY("wired_mem", "physmem", "bytes", LFEAT_SCALABLE),

  LEDGER_ENTRY("internal", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM),
  LEDGER_ENTRY("external", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM),
  LEDGER_ENTRY("reusable", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM),
  LEDGER_ENTRY("internal_compressed", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM),

  LEDGER_ENTRY("iokit_mapped", "mappings", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("alternate_accounting", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("alternate_accounting_compressed", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY_CALLBACK("conclave_mem", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM,
#if CONFIG_MEMORYSTATUS
    task_conclave_mem_limit_exceeded,
#else
    NULL,
#endif
    NULL),
  LEDGER_ENTRY_CALLBACK("phys_footprint", "physmem", "bytes",
    LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE | LFEAT_DEBIT | LFEAT_MAXIMUM | LFEAT_DIAG,
#if CONFIG_MEMORYSTATUS
    task_footprint_exceeded,
#else
    NULL,
#endif
    NULL),
#if CONFIG_MEMORYSTATUS
  LEDGER_ENTRY("memorystatus_dirty_time", "physmem", "ns", LFEAT_NONE),
#endif /* CONFIG_MEMORYSTATUS */
  LEDGER_ENTRY("page_table", "physmem", "bytes", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("pages_grabbed", "physmem", "count", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("pages_grabbed_kern", "physmem", "count", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("pages_grabbed_iopl", "physmem", "count", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("pages_grabbed_upl", "physmem", "count", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("purgeable_volatile", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("purgeable_nonvolatile", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("purgeable_volatile_compress", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("purgeable_nonvolatile_compress", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("tagged_nofootprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("tagged_footprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("tagged_nofootprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("tagged_footprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("network_volatile", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("network_nonvolatile", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("network_volatile_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("network_nonvolatile_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("media_nofootprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("media_footprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("media_nofootprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("media_footprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("graphics_nofootprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("graphics_footprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("graphics_nofootprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("graphics_footprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),

  LEDGER_ENTRY("neural_nofootprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("neural_footprint", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("neural_nofootprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("neural_footprint_compressed", "physmem", "bytes", LFEAT_ASSERT_POSITIVE),
  LEDGER_ENTRY("neural_nofootprint_total", "physmem", "bytes", LFEAT_ASSERT_POSITIVE | LFEAT_MAXIMUM),

  LEDGER_ENTRY("swapins", "physmem", "bytes", LFEAT_SCALABLE | LFEAT_ASSERT_POSITIVE),
#if CONFIG_FREEZE
  LEDGER_ENTRY("frozen_to_swap", "physmem", "bytes", LFEAT_NONE),
#endif /* CONFIG_FREEZE */
#if CONFIG_DEFERRED_RECLAIM
  LEDGER_ENTRY("est_reclaimable", "virtmem", "bytes", LFEAT_ASSERT_POSITIVE),
#endif /* CONFIG_DEFERRED_RECLAIM */

  LEDGER_ENTRY("platform_idle_wakeups", "power", "count", LFEAT_NONE),
  LEDGER_ENTRY_CALLBACK("interrupt_wakeups", "power", "count",
    LFEAT_DEBIT | LFEAT_REFILL,
    task_wakeups_rate_exceeded, NULL),

#if CONFIG_SCHED_SFI
  SFI_LEDGER_ENTRY(APP_NAP),
  SFI_LEDGER_ENTRY(DARWIN_BG),
  SFI_LEDGER_ENTRY(DEFAULT),
  SFI_LEDGER_ENTRY(LEGACY),
  SFI_LEDGER_ENTRY(MAINTENANCE),
  SFI_LEDGER_ENTRY(MANAGED),
  SFI_LEDGER_ENTRY(OPTED_OUT),
  SFI_LEDGER_ENTRY(USER_INITIATED),
  SFI_LEDGER_ENTRY(USER_INTERACTIVE),
  SFI_LEDGER_ENTRY(UTILITY),
  SFI_LEDGER_ENTRY(RUNAWAY_MITIGATION),
#endif /* CONFIG_SCHED_SFI */

  LEDGER_ENTRY("cpu_time_billed_to_me", "sched", "ns", LFEAT_NONE),
  LEDGER_ENTRY("cpu_time_billed_to_others", "sched", "ns", LFEAT_NONE),
  LEDGER_ENTRY("energy_billed_to_me", "power", "nj", LFEAT_NONE),
  LEDGER_ENTRY("energy_billed_to_others", "power", "nj", LFEAT_NONE),

  LEDGER_ENTRY_CALLBACK("physical_writes", "res", "bytes",
    LFEAT_DEBIT | LFEAT_REFILL,
    task_io_rate_exceeded, (void *)FLAVOR_IO_PHYSICAL_WRITES),
  LEDGER_ENTRY("logical_writes", "res", "bytes", LFEAT_DEBIT),
  LEDGER_ENTRY("logical_writes_to_external", "res", "bytes", LFEAT_DEBIT),
#if CONFIG_PHYS_WRITE_ACCT
  LEDGER_ENTRY("fs_metadata_writes", "res", "bytes", LFEAT_DEBIT),
#endif /* CONFIG_PHYS_WRITE_ACCT */
};

LEDGER_TEMPLATE_DEFINE(task_ledger_template, "Per-task ledger", task_ledger_entries);

/* System sleep state */
boolean_t tasks_suspend_state;

__options_decl(send_exec_resource_options_t, uint8_t, {
	EXC_RESOURCE_FATAL      = 0x01,
	EXC_RESOURCE_DIAGNOSTIC = 0x02,
	EXC_RESOURCE_WARNING    = 0x04,
	EXC_RESOURCE_CONCLAVE   = 0x08, // A side memory limit independent of the main footprint.
	EXC_RESOURCE_IS_ACTIVE  = 0x10
});

/**
 * Actions to take when a process has reached the memory limit or the diagnostics threshold limits
 */
void init_task_ledgers(void);
void __attribute__((noinline)) PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb, send_exec_resource_options_t exception_options);
#if CONFIG_PROC_RESOURCE_LIMITS
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_FILE_DESCRIPTORS(task_t task, int current_size, int soft_limit, int hard_limit);
mach_port_name_t current_task_get_fatal_port_name(void);
void __attribute__((noinline)) SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_KQWORKLOOPS(task_t task, int current_size, int soft_limit, int hard_limit);
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

kern_return_t task_suspend_internal(task_t);
kern_return_t task_resume_internal(task_t);
static kern_return_t task_start_halt_locked(task_t task, boolean_t should_mark_corpse);

extern kern_return_t iokit_task_terminate(task_t task, int phase);
extern void          iokit_task_app_suspended_changed(task_t task);

extern kern_return_t exception_deliver(thread_t, exception_type_t, mach_exception_data_t, mach_msg_type_number_t, struct exception_action *, lck_mtx_t *);
extern void bsd_copythreadname(void *dst_uth, void *src_uth);
extern kern_return_t thread_resume(thread_t thread);

// Condition to include diag footprints
#define RESETTABLE_DIAG_FOOTPRINT_LIMITS ((DEBUG || DEVELOPMENT) && CONFIG_MEMORYSTATUS)

// Warn tasks when they hit 80% of their memory limit.
#define PHYS_FOOTPRINT_WARNING_LEVEL 80

#define TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT              150 /* wakeups per second */
#define TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL   300 /* in seconds. */

int task_wakeups_monitor_interval; /* In seconds. Time period over which wakeups rate is observed */
int task_wakeups_monitor_rate;     /* In hz. Maximum allowable wakeups per task before EXC_RESOURCE is sent */

TUNABLE(bool, disable_exc_resource, "disable_exc_resource", false); /* Global override to suppress EXC_RESOURCE for resource monitor violations. */
TUNABLE(bool, disable_exc_resource_during_audio, "disable_exc_resource_during_audio", true); /* Global override to suppress EXC_RESOURCE while audio is active */

ledger_amount_t max_task_footprint = 0;  /* Per-task limit on physical memory consumption in bytes     */
unsigned int max_task_footprint_warning_level = 0;  /* Per-task limit warning percentage */

/*
 * Configure per-task memory limit.
 * The boot-arg is interpreted as Megabytes,
 * and takes precedence over the device tree.
 * Setting the boot-arg to 0 disables task limits.
 */
TUNABLE_DT_WRITEABLE(int, max_task_footprint_mb, "/defaults", "kern.max_task_pmem", "max_task_pmem", 0, TUNABLE_DT_NONE);

/* I/O Monitor Limits */
#define IOMON_DEFAULT_LIMIT                     (20480ull)      /* MB of logical/physical I/O */
#define IOMON_DEFAULT_INTERVAL                  (86400ull)      /* in seconds */

uint64_t task_iomon_limit_mb;           /* Per-task I/O monitor limit in MBs */
uint64_t task_iomon_interval_secs;      /* Per-task I/O monitor interval in secs */

#define IO_TELEMETRY_DEFAULT_LIMIT              (10ll * 1024ll * 1024ll)
int64_t io_telemetry_limit;                     /* Threshold to take a microstackshot (0 indicated I/O telemetry is turned off) */
int64_t global_logical_writes_count = 0;        /* Global count for logical writes */
int64_t global_logical_writes_to_external_count = 0;        /* Global count for logical writes to external storage*/
static boolean_t global_update_logical_writes(int64_t, int64_t*);

#if DEBUG || DEVELOPMENT
static diagthreshold_check_return task_check_memorythreshold_is_valid(task_t task, uint64_t new_limit, bool is_diagnostics_value);
#endif
#define TASK_MAX_THREAD_LIMIT 256

int task_max = CONFIG_TASK_MAX; /* Max number of tasks */

#if CONFIG_COREDUMP
int hwm_user_cores = 0; /* high watermark violations generate user core files */
#endif

#ifdef MACH_BSD
extern uint32_t proc_platform(const struct proc *);
extern uint32_t proc_sdk(struct proc *);
extern void     proc_getexecutableuuid(void *, unsigned char *, unsigned long);
extern int      proc_pid(struct proc *p);
extern int      proc_selfpid(void);
extern struct proc *current_proc(void);
extern char     *proc_name_address(struct proc *p);
extern uint64_t get_dispatchqueue_offset_from_proc(void *);
extern int kevent_proc_copy_uptrs(void *proc, uint64_t *buf, uint32_t bufsize);
extern void workq_proc_suspended(struct proc *p);
extern void workq_proc_resumed(struct proc *p);
extern struct proc *kernproc;
extern void * XNU_PTRAUTH_SIGNED_PTR("initproc") initproc;

#if CONFIG_MEMORYSTATUS
extern void     proc_memstat_skip(struct proc* p, boolean_t set);
extern void     memorystatus_on_ledger_footprint_exceeded(int warning, bool memlimit_is_active, bool memlimit_is_fatal);
extern void     memorystatus_log_exception(const int max_footprint_mb, bool memlimit_is_active, bool memlimit_is_fatal);
extern void     memorystatus_log_diag_threshold_exception(const int diag_threshold_value);
extern void     memorystatus_on_conclave_limit_exceeded(const int max_footprint_mb);
extern boolean_t memorystatus_allowed_vm_map_fork(task_t task, bool *is_large);
extern uint64_t  memorystatus_available_memory_internal(struct proc *p);

#if DEVELOPMENT || DEBUG
extern void memorystatus_abort_vm_map_fork(task_t);
#endif

#endif /* CONFIG_MEMORYSTATUS */

#endif /* MACH_BSD */

/* Boot-arg that turns on fatal pac exception delivery for all first-party apps */
static TUNABLE(bool, enable_pac_exception, "enable_pac_exception", false);

/*
 * Defaults for controllable EXC_GUARD behaviors
 *
 * Internal builds are fatal by default (except BRIDGE).
 * Create an alternate set of defaults for special processes by name.
 */
struct task_exc_guard_named_default {
	char *name;
	uint32_t behavior;
};
#define _TASK_EXC_GUARD_MP_CORPSE  (TASK_EXC_GUARD_MP_DELIVER | TASK_EXC_GUARD_MP_CORPSE)
#define _TASK_EXC_GUARD_MP_ONCE    (_TASK_EXC_GUARD_MP_CORPSE | TASK_EXC_GUARD_MP_ONCE)
#define _TASK_EXC_GUARD_MP_FATAL   (TASK_EXC_GUARD_MP_DELIVER | TASK_EXC_GUARD_MP_FATAL)

#define _TASK_EXC_GUARD_VM_CORPSE  (TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_VM_CORPSE)
#define _TASK_EXC_GUARD_VM_ONCE    (_TASK_EXC_GUARD_VM_CORPSE | TASK_EXC_GUARD_VM_ONCE)
#define _TASK_EXC_GUARD_VM_FATAL   (TASK_EXC_GUARD_VM_DELIVER | TASK_EXC_GUARD_VM_FATAL)

#define _TASK_EXC_GUARD_ALL_CORPSE (_TASK_EXC_GUARD_MP_CORPSE | _TASK_EXC_GUARD_VM_CORPSE)
#define _TASK_EXC_GUARD_ALL_ONCE   (_TASK_EXC_GUARD_MP_ONCE | _TASK_EXC_GUARD_VM_ONCE)
#define _TASK_EXC_GUARD_ALL_FATAL  (_TASK_EXC_GUARD_MP_FATAL | _TASK_EXC_GUARD_VM_FATAL)

/* cannot turn off FATAL and DELIVER bit if set */
uint32_t task_exc_guard_no_unset_mask = TASK_EXC_GUARD_MP_FATAL | TASK_EXC_GUARD_VM_FATAL |
    TASK_EXC_GUARD_MP_DELIVER | TASK_EXC_GUARD_VM_DELIVER;
/* cannot turn on ONCE bit if unset */
uint32_t task_exc_guard_no_set_mask = TASK_EXC_GUARD_MP_ONCE | TASK_EXC_GUARD_VM_ONCE;

#if !defined(XNU_TARGET_OS_BRIDGE)

uint32_t task_exc_guard_default = _TASK_EXC_GUARD_ALL_FATAL;
uint32_t task_exc_guard_config_mask = TASK_EXC_GUARD_MP_ALL | TASK_EXC_GUARD_VM_ALL;
/*
 * These "by-process-name" default overrides are intended to be a short-term fix to
 * quickly get over races between changes introducing new EXC_GUARD raising behaviors
 * in some process and a change in default behavior for same. We should ship with
 * these lists empty (by fixing the bugs, or explicitly changing the task's EXC_GUARD
 * exception behavior via task_set_exc_guard_behavior()).
 *
 * XXX Remember to add/remove TASK_EXC_GUARD_HONOR_NAMED_DEFAULTS back to
 * task_exc_guard_default when transitioning this list between empty and
 * non-empty.
 */
static struct task_exc_guard_named_default task_exc_guard_named_defaults[] = {};

#else /* !defined(XNU_TARGET_OS_BRIDGE) */

uint32_t task_exc_guard_default = _TASK_EXC_GUARD_ALL_ONCE;
uint32_t task_exc_guard_config_mask = TASK_EXC_GUARD_MP_ALL | TASK_EXC_GUARD_VM_ALL;
static struct task_exc_guard_named_default task_exc_guard_named_defaults[] = {};

#endif /* !defined(XNU_TARGET_OS_BRIDGE) */

/* Forwards */

static bool task_hold_locked(task_t task);
static void task_wait_locked(task_t task, boolean_t until_not_runnable);
static void task_release_locked(task_t task);
extern task_t proc_get_task_raw(void *proc);
extern void task_ref_hold_proc_task_struct(task_t task);
extern void task_release_proc_task_struct(task_t task, proc_ro_t proc_ro);

static void task_synchronizer_destroy_all(task_t task);
static os_ref_count_t
task_add_turnstile_watchports_locked(
	task_t                      task,
	struct task_watchports      *watchports,
	struct task_watchport_elem  **previous_elem_array,
	ipc_port_t                  *portwatch_ports,
	uint32_t                    portwatch_count);

static os_ref_count_t
task_remove_turnstile_watchports_locked(
	task_t                 task,
	struct task_watchports *watchports,
	ipc_port_t             *port_freelist);

static struct task_watchports *
task_watchports_alloc_init(
	task_t        task,
	thread_t      thread,
	uint32_t      count);

static void
task_watchports_deallocate(
	struct task_watchports *watchports);

void
task_set_64bit(
	task_t task,
	boolean_t is_64bit,
	boolean_t is_64bit_data)
{
#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)
	thread_t thread;
#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm64__) */

	task_lock(task);

	/*
	 * Switching to/from 64-bit address spaces
	 */
	if (is_64bit) {
		if (!task_has_64Bit_addr(task)) {
			task_set_64Bit_addr(task);
		}
	} else {
		if (task_has_64Bit_addr(task)) {
			task_clear_64Bit_addr(task);
		}
	}

	/*
	 * Switching to/from 64-bit register state.
	 */
	if (is_64bit_data) {
		if (task_has_64Bit_data(task)) {
			goto out;
		}

		task_set_64Bit_data(task);
	} else {
		if (!task_has_64Bit_data(task)) {
			goto out;
		}

		task_clear_64Bit_data(task);
	}

	/* FIXME: On x86, the thread save state flavor can diverge from the
	 * task's 64-bit feature flag due to the 32-bit/64-bit register save
	 * state dichotomy. Since we can be pre-empted in this interval,
	 * certain routines may observe the thread as being in an inconsistent
	 * state with respect to its task's 64-bitness.
	 */

#if defined(__x86_64__) || defined(__arm64__)
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		machine_thread_switch_addrmode(thread);
		thread_mtx_unlock(thread);
	}
#endif /* defined(__x86_64__) || defined(__arm64__) */

out:
	task_unlock(task);
}

bool
task_get_64bit_addr(task_t task)
{
	return task_has_64Bit_addr(task);
}

bool
task_get_64bit_data(task_t task)
{
	return task_has_64Bit_data(task);
}

void
task_set_platform_binary(
	task_t task,
	boolean_t is_platform)
{
	if (is_platform) {
		task_ro_flags_set(task, TFRO_PLATFORM);
	} else {
		task_ro_flags_clear(task, TFRO_PLATFORM);
	}
	assert(task->map);
	if (task->map) {
		vm_map_ilk_lock(task->map);
		vm_map_set_platform_binary(task->map, (bool)is_platform);
		vm_map_ilk_unlock(task->map);
	}
}

#if XNU_TARGET_OS_OSX
#if DEVELOPMENT || DEBUG
SECURITY_READ_ONLY_LATE(bool) AMFI_bootarg_disable_mach_hardening = false;
#endif /* DEVELOPMENT || DEBUG */

void
task_disable_mach_hardening(task_t task)
{
	task_ro_flags_set(task, TFRO_MACH_HARDENING_OPT_OUT);
}

bool
task_opted_out_mach_hardening(task_t task)
{
	return task_ro_flags_get(task) & TFRO_MACH_HARDENING_OPT_OUT;
}
#endif /* XNU_TARGET_OS_OSX */

boolean_t
task_get_platform_binary(task_t task)
{
	return (task_ro_flags_get(task) & TFRO_PLATFORM) != 0;
}

boolean_t
task_is_a_corpse(task_t task)
{
	return (task_ro_flags_get(task) & TFRO_CORPSE) != 0;
}

boolean_t
task_is_ipc_active(task_t task)
{
	return task->ipc_active;
}

bool
task_is_immovable_no_assert(task_t task)
{
	task_control_port_options_t opt = task_get_control_port_options(task);
	return !!(opt & TASK_CONTROL_PORT_IMMOVABLE_MASK);
}

bool
task_is_immovable(task_t task)
{
	task_control_port_options_t opt = task_get_control_port_options(task);
	assert(opt != TASK_CONTROL_PORT_OPTIONS_INVALID);
	return !!(opt & TASK_CONTROL_PORT_IMMOVABLE_MASK);
}

void
task_set_corpse(task_t task)
{
	return task_ro_flags_set(task, TFRO_CORPSE);
}

/*
 * Set or clear per-task TF_CA_CLIENT_WI flag according to specified argument.
 * Returns "false" if flag is already set, and "true" in other cases.
 */
bool
task_set_ca_client_wi(
	task_t task,
	boolean_t set_or_clear)
{
	bool ret = true;
	task_lock(task);
	if (set_or_clear) {
		/* Tasks can have only one CA_CLIENT work interval */
		if (task->t_flags & TF_CA_CLIENT_WI) {
			ret = false;
		} else {
			task->t_flags |= TF_CA_CLIENT_WI;
		}
	} else {
		task->t_flags &= ~TF_CA_CLIENT_WI;
	}
	task_unlock(task);
	return ret;
}

/*
 * task_set_dyld_info() is called at most three times.
 * 1) at task struct creation to set addr/size to zero.
 * 2) in mach_loader.c to set location of __all_image_info section in loaded dyld
 * 3) is from dyld itself to update location of all_image_info
 * For security any calls after that are ignored.  The TF_DYLD_ALL_IMAGE_SET bit is used to determine state.
 */
kern_return_t
task_set_dyld_info(
	task_t            task,
	mach_vm_address_t addr,
	mach_vm_size_t    size,
	bool              finalize_value)
{
	mach_vm_address_t end;
	if (os_add_overflow(addr, size, &end)) {
		return KERN_FAILURE;
	}

	task_lock(task);
	/* don't accept updates if all_image_info_addr is final */
	if ((task->t_flags & TF_DYLD_ALL_IMAGE_FINAL) == 0) {
		bool inputNonZero   = ((addr != 0) || (size != 0));
		bool currentNonZero = ((task->all_image_info_addr != 0) || (task->all_image_info_size != 0));
		task->all_image_info_addr = addr;
		task->all_image_info_size = size;
		/* can only change from a non-zero value to another non-zero once */
		if ((inputNonZero && currentNonZero) || finalize_value) {
			task->t_flags |= TF_DYLD_ALL_IMAGE_FINAL;
		}
		task_unlock(task);
		return KERN_SUCCESS;
	} else {
		task_unlock(task);
		return KERN_FAILURE;
	}
}

bool
task_donates_own_pages(
	task_t task)
{
	return task->donates_own_pages;
}

void
task_set_mach_header_address(
	task_t task,
	mach_vm_address_t addr)
{
	task_lock(task);
	task->mach_header_vm_address = addr;
	task_unlock(task);
}

void
task_bank_reset(__unused task_t task)
{
	if (task->bank_context != NULL) {
		bank_task_destroy(task);
	}
}

/*
 * NOTE: This should only be called when the P_LINTRANSIT
 *	 flag is set (the proc_trans lock is held) on the
 *	 proc associated with the task.
 */
void
task_bank_init(__unused task_t task)
{
	if (task->bank_context != NULL) {
		panic("Task bank init called with non null bank context for task: %p and bank_context: %p", task, task->bank_context);
	}
	bank_task_initialize(task);
}

void
task_set_did_exec_flag(task_t task)
{
	task->t_procflags |= TPF_DID_EXEC;
}

void
task_clear_exec_copy_flag(task_t task)
{
	task->t_procflags &= ~TPF_EXEC_COPY;
}

event_t
task_get_return_wait_event(task_t task)
{
	return (event_t)&task->returnwait_inheritor;
}

void
task_clear_return_wait(task_t task, uint32_t flags)
{
	if (flags & TCRW_CLEAR_INITIAL_WAIT) {
		thread_wakeup(task_get_return_wait_event(task));
	}

	if (flags & TCRW_CLEAR_FINAL_WAIT) {
		is_write_lock(task->itk_space);

		task->t_returnwaitflags &= ~TRW_LRETURNWAIT;
		task->returnwait_inheritor = NULL;

		if (flags & TCRW_CLEAR_EXEC_COMPLETE) {
			task->t_returnwaitflags &= ~TRW_LEXEC_COMPLETE;
		}

		if (task->t_returnwaitflags & TRW_LRETURNWAITER) {
			struct turnstile *turnstile = turnstile_prepare_hash((uintptr_t) task_get_return_wait_event(task),
			    TURNSTILE_ULOCK);

			waitq_wakeup64_all(&turnstile->ts_waitq,
			    CAST_EVENT64_T(task_get_return_wait_event(task)),
			    THREAD_AWAKENED, WAITQ_UPDATE_INHERITOR);

			turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_HELD);

			turnstile_complete_hash((uintptr_t) task_get_return_wait_event(task), TURNSTILE_ULOCK);
			turnstile_cleanup();
			task->t_returnwaitflags &= ~TRW_LRETURNWAITER;
		}
		is_write_unlock(task->itk_space);
	}
}

/*
 *  Set default behavior for a task's control ports
 *
 *  Nothing locked. This is safe because it is called before
 *  ipc_task_enable, so no one has access to the task yet.
 */
void
task_set_ctrl_port_default(
	task_t         task,
	thread_t       thread)
{
	ipc_space_policy_t pol = ipc_policy_for_task(task);
	bool movable_allowed = mac_task_check_get_movable_control_port_during_spawn(task) == 0;
	bool is_simulated = pol & IPC_SPACE_POLICY_SIMULATED;
	bool is_translated = false;
	task_control_port_options_t opts = TASK_CONTROL_PORT_OPTIONS_NONE;

	/* verify it is call before ipc_task_enable */
	assert(!task->ipc_active);

	if (movable_allowed || is_simulated || is_translated) {
		/* Disable control port hardening for entitled||simulated binaries */
		opts = TASK_CONTROL_PORT_OPTIONS_NONE;
	} else if (ipc_should_apply_policy(pol, IPC_POLICY_ENHANCED_V1)) {
		/* set control port options for 1p code, inherited from parent task by default */
		if (ipc_control_port_options & ICP_OPTIONS_IMMOVABLE_1P_HARD) {
			opts |= TASK_CONTROL_PORT_IMMOVABLE_HARD;
		}
	} else {
		/* set control port options for 3p code, inherited from parent task by default */
		if (ipc_control_port_options & ICP_OPTIONS_IMMOVABLE_3P_HARD) {
			opts |= TASK_CONTROL_PORT_IMMOVABLE_HARD;
		}
	}

	/* see `ipc_should_mark_immovable_send`, which consumes these flags */
	task_set_control_port_options(task, opts);

	/*
	 * now that we have marked the task as immovable, copyout the task/thread ports
	 * again so that they get marked as immovable on copyout
	 */
	ipc_task_copyout_control_port(task);
	/* consumed by ipc_thread_set_immovable_pinned */
	thread_reference(thread);
	ipc_thread_set_immovable_pinned(thread);
}

void __attribute__((noreturn))
task_wait_to_return(void)
{
	task_t task = current_task();
	uint8_t returnwaitflags;

	is_write_lock(task->itk_space);

	if (task->t_returnwaitflags & TRW_LRETURNWAIT) {
		struct turnstile *turnstile = turnstile_prepare_hash((uintptr_t) task_get_return_wait_event(task),
		    TURNSTILE_ULOCK);

		do {
			task->t_returnwaitflags |= TRW_LRETURNWAITER;
			turnstile_update_inheritor(turnstile, task->returnwait_inheritor,
			    (TURNSTILE_DELAYED_UPDATE | TURNSTILE_INHERITOR_THREAD));

			waitq_assert_wait64(&turnstile->ts_waitq,
			    CAST_EVENT64_T(task_get_return_wait_event(task)),
			    THREAD_UNINT, TIMEOUT_WAIT_FOREVER);

			is_write_unlock(task->itk_space);

			turnstile_update_inheritor_complete(turnstile, TURNSTILE_INTERLOCK_NOT_HELD);

			thread_block(THREAD_CONTINUE_NULL);

			is_write_lock(task->itk_space);
		} while (task->t_returnwaitflags & TRW_LRETURNWAIT);

		turnstile_complete_hash((uintptr_t) task_get_return_wait_event(task), TURNSTILE_ULOCK);
	}

	returnwaitflags = task->t_returnwaitflags;
	is_write_unlock(task->itk_space);
	turnstile_cleanup();

	/**
	 * In posix_spawn() path, process_signature() is guaranteed to complete
	 * when the "second wait" is cleared. Call out to execute whatever depends
	 * on the result of that before we return to EL0.
	 */
	task_post_signature_processing_hook(task);
#if CONFIG_MACF
	/*
	 * Before jumping to userspace and allowing this process
	 * to execute any code, make sure its credentials are cached,
	 * and notify any interested parties.
	 */
	extern void current_cached_proc_cred_update(void);

	current_cached_proc_cred_update();
	if (returnwaitflags & TRW_LEXEC_COMPLETE) {
		mac_proc_notify_exec_complete(current_proc());
	}
#endif

	thread_bootstrap_return();
}

/**
 * A callout by task_wait_to_return on the main thread of a newly spawned task
 * after process_signature() is completed by the parent task.
 *
 * @param task The newly spawned task
 */
void
task_post_signature_processing_hook(task_t task)
{
	ml_task_post_signature_processing_hook(task);
}

bool
task_is_initproc(task_t task)
{
	return get_bsdtask_info(task) == initproc;
}

boolean_t
task_is_exec_copy(task_t task)
{
	return task_is_exec_copy_internal(task);
}

boolean_t
task_did_exec(task_t task)
{
	return task_did_exec_internal(task);
}

boolean_t
task_is_active(task_t task)
{
	return task->active;
}

boolean_t
task_is_halting(task_t task)
{
	return task->halting;
}

void
task_init(void)
{
	if (max_task_footprint_mb != 0) {
#if CONFIG_MEMORYSTATUS
		if (max_task_footprint_mb < 50) {
			printf("Warning: max_task_pmem %d below minimum.\n",
			    max_task_footprint_mb);
			max_task_footprint_mb = 50;
		}
		printf("Limiting task physical memory footprint to %d MB\n",
		    max_task_footprint_mb);

		max_task_footprint = (ledger_amount_t)max_task_footprint_mb * 1024 * 1024;         // Convert MB to bytes

		/*
		 * Configure the per-task memory limit warning level.
		 * This is computed as a percentage.
		 */
		max_task_footprint_warning_level = 0;

		if (max_mem < 0x40000000) {
			/*
			 * On devices with < 1GB of memory:
			 *    -- set warnings to 50MB below the per-task limit.
			 */
			if (max_task_footprint_mb > 50) {
				max_task_footprint_warning_level = ((max_task_footprint_mb - 50) * 100) / max_task_footprint_mb;
			}
		} else {
			/*
			 * On devices with >= 1GB of memory:
			 *    -- set warnings to 100MB below the per-task limit.
			 */
			if (max_task_footprint_mb > 100) {
				max_task_footprint_warning_level = ((max_task_footprint_mb - 100) * 100) / max_task_footprint_mb;
			}
		}

		/*
		 * Never allow warning level to land below the default.
		 */
		if (max_task_footprint_warning_level < PHYS_FOOTPRINT_WARNING_LEVEL) {
			max_task_footprint_warning_level = PHYS_FOOTPRINT_WARNING_LEVEL;
		}

		printf("Limiting task physical memory warning to %d%%\n", max_task_footprint_warning_level);

#else
		printf("Warning: max_task_pmem specified, but jetsam not configured; ignoring.\n");
#endif /* CONFIG_MEMORYSTATUS */
	}

#if DEVELOPMENT || DEBUG
	PE_parse_boot_argn("task_exc_guard_default",
	    &task_exc_guard_default,
	    sizeof(task_exc_guard_default));
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_COREDUMP
	if (!PE_parse_boot_argn("hwm_user_cores", &hwm_user_cores,
	    sizeof(hwm_user_cores))) {
		hwm_user_cores = 0;
	}
#endif

	proc_init_cpumon_params();

	if (!PE_parse_boot_argn("task_wakeups_monitor_rate", &task_wakeups_monitor_rate, sizeof(task_wakeups_monitor_rate))) {
		task_wakeups_monitor_rate = TASK_WAKEUPS_MONITOR_DEFAULT_LIMIT;
	}

	if (!PE_parse_boot_argn("task_wakeups_monitor_interval", &task_wakeups_monitor_interval, sizeof(task_wakeups_monitor_interval))) {
		task_wakeups_monitor_interval = TASK_WAKEUPS_MONITOR_DEFAULT_INTERVAL;
	}

	if (!PE_parse_boot_argn("task_iomon_limit_mb", &task_iomon_limit_mb, sizeof(task_iomon_limit_mb))) {
		task_iomon_limit_mb = IOMON_DEFAULT_LIMIT;
	}

	if (!PE_parse_boot_argn("task_iomon_interval_secs", &task_iomon_interval_secs, sizeof(task_iomon_interval_secs))) {
		task_iomon_interval_secs = IOMON_DEFAULT_INTERVAL;
	}

	if (!PE_parse_boot_argn("io_telemetry_limit", &io_telemetry_limit, sizeof(io_telemetry_limit))) {
		io_telemetry_limit = IO_TELEMETRY_DEFAULT_LIMIT;
	}

/*
 * If we have coalitions, coalition_init() will call init_task_ledgers() as it
 * sets up the ledgers for the default coalition. If we don't have coalitions,
 * then we have to call it now.
 */
#if CONFIG_COALITIONS
	assert(task_ledger_template.lt_size);
#else /* CONFIG_COALITIONS */
	init_task_ledgers();
#endif /* CONFIG_COALITIONS */

	task_ref_init();
	task_zone_init();

#ifdef __LP64__
	boolean_t is_64bit = TRUE;
#else
	boolean_t is_64bit = FALSE;
#endif

	kernproc = (struct proc *)zalloc_flags(proc_task_zone, Z_WAITOK | Z_ZERO);
	kernel_task = proc_get_task_raw(kernproc);

	/*
	 * Create the kernel task as the first task.
	 */
	if (task_create_internal(TASK_NULL, NULL, NULL, FALSE, is_64bit,
	    is_64bit, TF_NONE, TF_NONE, TPF_NONE, TWF_NONE, kernel_task) != KERN_SUCCESS) {
		panic("task_init");
	}

#if HAS_MTE && CONFIG_KERNEL_TAGGING
	task_set_sec(kernel_task);
#endif /* HAS_MTE && CONFIG_KERNEL_TAGGING */


	vm_map_setup(get_task_map(kernel_task), kernel_task);

	ipc_task_enable(kernel_task);

#if defined(HAS_APPLE_PAC)
	kernel_task->rop_pid = ml_default_rop_pid();
	kernel_task->jop_pid = ml_default_jop_pid();
	// kernel_task never runs at EL0, but machine_thread_state_convert_from/to_user() relies on
	// disable_user_jop to be false for kernel threads (e.g. in exception delivery on thread_exception_daemon)
	ml_task_set_disable_user_jop(kernel_task, FALSE);
#endif

	vm_map_deallocate(kernel_task->map);
	kernel_task->map = kernel_map;
}

static inline void
task_zone_init(void)
{
	proc_struct_size = roundup(proc_struct_size, task_alignment);
	task_struct_size = roundup(sizeof(struct task), proc_alignment);
	proc_and_task_size = proc_struct_size + task_struct_size;

	proc_task_zone = zone_create_ext("proc_task", proc_and_task_size,
	    ZC_ZFREE_CLEARMEM | ZC_SEQUESTER, ZONE_ID_PROC_TASK, NULL); /* sequester is needed for proc_rele() */
}

/*
 * Task ledgers
 * ------------
 *
 * phys_footprint
 *   Physical footprint: This is the sum of:
 *     + (internal - alternate_accounting)
 *     + (internal_compressed - alternate_accounting_compressed)
 *     + iokit_mapped
 *     + purgeable_nonvolatile
 *     + purgeable_nonvolatile_compressed
 *     + page_table
 *
 * internal
 *   The task's anonymous memory, which on iOS is always resident.
 *
 * internal_compressed
 *   Amount of this task's internal memory which is held by the compressor.
 *   Such memory is no longer actually resident for the task [i.e., resident in its pmap],
 *   and could be either decompressed back into memory, or paged out to storage, depending
 *   on our implementation.
 *
 * iokit_mapped
 *   IOKit mappings: The total size of all IOKit mappings in this task, regardless of
 *    clean/dirty or internal/external state].
 *
 * alternate_accounting
 *   The number of internal dirty pages which are part of IOKit mappings. By definition, these pages
 *   are counted in both internal *and* iokit_mapped, so we must subtract them from the total to avoid
 *   double counting.
 *
 * pages_grabbed
 *   pages_grabbed counts all page grabs in a task.  It is also broken out into three subtypes
 *   which track UPL, IOPL and Kernel page grabs.
 */
void
init_task_ledgers(void)
{
	ledger_template_t t = &task_ledger_template;

	ledger_template_finalize(t,
	    LEDGER_TPL_SCALABLE | LEDGER_TPL_SECURE_ALLOC);

	LEDGER_KEY_MEMOIZE(t, task_ledgers, cpu_time);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tkm_private);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tkm_shared);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, phys_mem);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, wired_mem);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, conclave_mem);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, internal);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, iokit_mapped);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, alternate_accounting);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, alternate_accounting_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, page_table);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, phys_footprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, internal_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, reusable);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, external);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, purgeable_volatile);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, purgeable_nonvolatile);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, purgeable_volatile_compress);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, purgeable_nonvolatile_compress);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, pages_grabbed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, pages_grabbed_kern);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, pages_grabbed_iopl);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, pages_grabbed_upl);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tagged_nofootprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tagged_footprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tagged_nofootprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, tagged_footprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, network_volatile);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, network_nonvolatile);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, network_volatile_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, network_nonvolatile_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, media_nofootprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, media_footprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, media_nofootprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, media_footprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, graphics_nofootprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, graphics_footprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, graphics_nofootprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, graphics_footprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, neural_nofootprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, neural_footprint);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, neural_nofootprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, neural_footprint_compressed);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, neural_nofootprint_total);
#if CONFIG_FREEZE
	LEDGER_KEY_MEMOIZE(t, task_ledgers, frozen_to_swap);
#endif /* CONFIG_FREEZE */
#if CONFIG_DEFERRED_RECLAIM
	LEDGER_KEY_MEMOIZE(t, task_ledgers, est_reclaimable);
#endif /* CONFIG_DEFERRED_RECLAIM */
	LEDGER_KEY_MEMOIZE(t, task_ledgers, platform_idle_wakeups);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, interrupt_wakeups);

#if CONFIG_SCHED_SFI
	/* don't account for UNSPECIFIED */
	for (sfi_class_id_t class_id = SFI_CLASS_UNSPECIFIED + 1; class_id < MAX_SFI_CLASS_ID; class_id++) {
		task_ledgers.sfi_wait_times[class_id] = ledger_key_lookup(t,
		    sfi_class_ledger_name(class_id), true);
	}
#endif /* CONFIG_SCHED_SFI */

	LEDGER_KEY_MEMOIZE(t, task_ledgers, cpu_time_billed_to_me);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, cpu_time_billed_to_others);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, physical_writes);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, logical_writes);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, logical_writes_to_external);
#if CONFIG_PHYS_WRITE_ACCT
	LEDGER_KEY_MEMOIZE(t, task_ledgers, fs_metadata_writes);
#endif /* CONFIG_PHYS_WRITE_ACCT */
	LEDGER_KEY_MEMOIZE(t, task_ledgers, energy_billed_to_me);
	LEDGER_KEY_MEMOIZE(t, task_ledgers, energy_billed_to_others);
#if CONFIG_MEMORYSTATUS
	LEDGER_KEY_MEMOIZE(t, task_ledgers, memorystatus_dirty_time);
#endif /* CONFIG_MEMORYSTATUS */
	LEDGER_KEY_MEMOIZE(t, task_ledgers, swapins);
}

/* Create a task, but leave the task ports disabled */
kern_return_t
task_create_internal(
	task_t             parent_task,            /* Null-able */
	proc_ro_t          proc_ro,
	coalition_t        *parent_coalitions __unused,
	boolean_t          inherit_memory,
	boolean_t          is_64bit,
	boolean_t          is_64bit_data,
	uint32_t           t_flags,
	uint32_t           t_flags_ro,
	uint32_t           t_procflags,
	uint8_t            t_returnwaitflags,
	task_t             child_task)
{
	task_t                  new_task;
	vm_shared_region_t      shared_region;
	ledger_t                ledger = NULL;
	struct task_ro_data     task_ro_data = {};
	uint32_t                parent_t_flags_ro = 0;

	new_task = child_task;

	if (task_ref_count_init(new_task) != KERN_SUCCESS) {
		return KERN_RESOURCE_SHORTAGE;
	}

	/* allocate with active entries */
	ledger = ledger_instantiate(&task_ledger_template);

	counter_alloc(&(new_task->faults));

#if defined(HAS_APPLE_PAC)
	const uint8_t disable_user_jop = inherit_memory ? parent_task->disable_user_jop : FALSE;
	ml_task_set_rop_pid(new_task, parent_task, inherit_memory);
	ml_task_set_jop_pid(new_task, parent_task, inherit_memory, disable_user_jop);
	ml_task_set_disable_user_jop(new_task, disable_user_jop);
#endif


	new_task->ledger = ledger;

	/* if inherit_memory is true, parent_task MUST not be NULL */
	if (!(t_flags & TF_CORPSE_FORK) && inherit_memory) {
#if CONFIG_DEFERRED_RECLAIM
		if (parent_task->deferred_reclamation_metadata) {
			/*
			 * Prevent concurrent reclaims while we're forking the parent_task's map,
			 * so that the child's map is in sync with the forked reclamation
			 * metadata.
			 */
			vm_deferred_reclamation_ring_own(
				parent_task->deferred_reclamation_metadata);
		}
#endif /* CONFIG_DEFERRED_RECLAIM */
		new_task->map = vm_map_fork(ledger, parent_task->map, 0);
#if CONFIG_DEFERRED_RECLAIM
		if (new_task->map != NULL &&
		    parent_task->deferred_reclamation_metadata) {
			new_task->deferred_reclamation_metadata =
			    vm_deferred_reclamation_task_fork(new_task,
			    parent_task->deferred_reclamation_metadata);
		}
		if (parent_task->deferred_reclamation_metadata) {
			vm_deferred_reclamation_ring_disown(
				parent_task->deferred_reclamation_metadata);
		}
#endif /* CONFIG_DEFERRED_RECLAIM */
	} else {
		unsigned int pmap_flags = is_64bit ? PMAP_CREATE_64BIT : 0;
		pmap_t pmap = pmap_create_options(ledger, 0, pmap_flags);
		vm_map_t new_map;

		if (pmap == NULL) {
			counter_free(&new_task->faults);
			ledger_dereference(ledger);
			task_ref_count_fini(new_task);
			return KERN_RESOURCE_SHORTAGE;
		}
		new_map = vm_map_create_options(pmap,
		    (vm_map_offset_t)(VM_MIN_ADDRESS),
		    (vm_map_offset_t)(VM_MAX_ADDRESS),
		    VM_MAP_CREATE_DEFAULT);
		if (parent_task) {
			vm_map_inherit_limits(new_map, parent_task->map);
		}
		new_task->map = new_map;
	}

	if (new_task->map == NULL) {
		counter_free(&new_task->faults);
		ledger_dereference(ledger);
		task_ref_count_fini(new_task);
		return KERN_RESOURCE_SHORTAGE;
	}

	lck_mtx_init(&new_task->lock, &task_lck_grp, &task_lck_attr);
	queue_init(&new_task->threads);
	new_task->suspend_count = 0;
	new_task->thread_count = 0;
	new_task->active_thread_count = 0;
	new_task->user_stop_count = 0;
	new_task->legacy_stop_count = 0;
	new_task->active = TRUE;
	new_task->halting = FALSE;
	new_task->priv_flags = 0;
	new_task->t_flags = t_flags;
	task_ro_data.t_flags_ro = t_flags_ro;
	new_task->t_procflags = t_procflags;
	new_task->t_returnwaitflags = t_returnwaitflags;
	new_task->returnwait_inheritor = current_thread();
	new_task->importance = 0;
	new_task->crashed_thread_id = 0;
	new_task->watchports = NULL;
	new_task->t_rr_ranges = NULL;

	new_task->bank_context = NULL;

	if (parent_task) {
		parent_t_flags_ro = task_ro_flags_get(parent_task);
	}

	if (parent_task && inherit_memory) {
#if __has_feature(ptrauth_calls)
		/* Inherit the pac exception flags from parent if in fork */
		task_ro_data.t_flags_ro |= (parent_t_flags_ro & (TFRO_PAC_ENFORCE_USER_STATE |
		    TFRO_PAC_EXC_FATAL));
#endif /* __has_feature(ptrauth_calls) */
		/* Inherit the platform restrictions flags from parent if in fork */
		task_ro_data.t_flags_ro |= parent_t_flags_ro & (TFRO_PLATFORM | TFRO_JIT_EXC_FATAL);
#if XNU_TARGET_OS_OSX
		task_ro_data.t_flags_ro |= parent_t_flags_ro & TFRO_MACH_HARDENING_OPT_OUT;
#endif /* XNU_TARGET_OS_OSX */

		/* task_security_config options are always inherited on fork */
		new_task->security_config = parent_task->security_config;
	}

#ifdef MACH_BSD
	new_task->corpse_info = NULL;
#endif /* MACH_BSD */

	/* kern_task not created by this function has unique id 0, start with 1 here. */
	task_set_uniqueid(new_task);

#if CONFIG_MACF
	set_task_crash_label(new_task, NULL);

	task_ro_data.task_filters.mach_trap_filter_mask = NULL;
	task_ro_data.task_filters.mach_kobj_filter_mask = NULL;
#endif

#if CONFIG_MEMORYSTATUS
	if (max_task_footprint != 0) {
		ledger_set_limit(ledger, task_ledgers.phys_footprint, max_task_footprint, PHYS_FOOTPRINT_WARNING_LEVEL);
	}
#endif /* CONFIG_MEMORYSTATUS */

	if (task_wakeups_monitor_rate != 0) {
		uint32_t flags = WAKEMON_ENABLE | WAKEMON_SET_DEFAULTS;
		int32_t  rate;        // Ignored because of WAKEMON_SET_DEFAULTS
		task_wakeups_monitor_ctl(new_task, &flags, &rate);
	}

#if CONFIG_IO_ACCOUNTING
	uint32_t flags = IOMON_ENABLE;
	task_io_monitor_ctl(new_task, &flags);
#endif /* CONFIG_IO_ACCOUNTING */

	machine_task_init(new_task, parent_task, inherit_memory);

	new_task->task_debug = NULL;

#if DEVELOPMENT || DEBUG
	new_task->task_unnested = FALSE;
	new_task->task_disconnected_count = 0;
#endif
	queue_init(&new_task->semaphore_list);
	new_task->semaphores_owned = 0;

	new_task->vtimers = 0;

	new_task->shared_region = NULL;

	new_task->affinity_space = NULL;

#if CONFIG_CPU_COUNTERS
	new_task->t_cpc = (struct cpc_task){ 0 };
#endif /* CONFIG_CPU_COUNTERS */

	new_task->pidsuspended = FALSE;
	new_task->frozen = FALSE;
	new_task->changing_freeze_state = FALSE;
	new_task->rusage_cpu_flags = 0;
	new_task->rusage_cpu_percentage = 0;
	new_task->rusage_cpu_interval = 0;
	new_task->rusage_cpu_deadline = 0;
	new_task->rusage_cpu_callt = NULL;
#if MACH_ASSERT
	new_task->suspends_outstanding = 0;
#endif
	recount_task_init(&new_task->tk_recount);

#if HYPERVISOR
	new_task->hv_task_target = NULL;
#endif /* HYPERVISOR */

#if CONFIG_TASKWATCH
	queue_init(&new_task->task_watchers);
	new_task->num_taskwatchers  = 0;
	new_task->watchapplying  = 0;
#endif /* CONFIG_TASKWATCH */

	new_task->mem_notify_reserved = 0;

	new_task->requested_policy = default_task_requested_policy;
	new_task->effective_policy = default_task_effective_policy;

	new_task->task_shared_region_slide = -1;

	/*
	 * Allocate and initialize task tokens.
	 */
	struct task_token_data *tokens;
	security_token_t sec_token;
	audit_token_t audit_token;

	tokens = kalloc_type(struct task_token_data,
	    Z_WAITOK | Z_NOFAIL);

	if (parent_task != NULL) {
		task_get_tokens(parent_task, &sec_token, &audit_token);
	} else {
		sec_token = KERNEL_SECURITY_TOKEN;
		audit_token = KERNEL_AUDIT_TOKEN;
	}

	os_atomic_init(&tokens->tc_uids,
	    task_token_pack(sec_token.val[0], audit_token.val[3]));
	os_atomic_init(&tokens->tc_gids,
	    task_token_pack(sec_token.val[1], audit_token.val[4]));
	os_atomic_init(&tokens->tc_auid, audit_token.val[0]);
	os_atomic_init(&tokens->tc_asid, audit_token.val[6]);
	os_atomic_init(&tokens->tc_pid, audit_token.val[5]);
	os_atomic_init(&tokens->tc_pidversion, audit_token.val[7]);
	new_task->task_tokens = tokens;

	if (parent_task != NULL) {
		task_ro_data.t_flags_ro |= parent_t_flags_ro & TFRO_FILTER_MSG;
#if CONFIG_MACF
		if (!(t_flags & TF_CORPSE_FORK)) {
			task_ro_data.task_filters.mach_trap_filter_mask = task_get_mach_trap_filter_mask(parent_task);
			task_ro_data.task_filters.mach_kobj_filter_mask = task_get_mach_kobj_filter_mask(parent_task);
		}
#endif
	}
	/* set in task_set_ctrl_port_default */
	task_ro_data.task_control_port_options = TASK_CONTROL_PORT_OPTIONS_INVALID;

	/* must set before task_importance_init_from_parent: */
	if (proc_ro != NULL) {
		new_task->bsd_info_ro = proc_ro_ref_task(proc_ro, new_task, &task_ro_data);
	} else {
		new_task->bsd_info_ro = proc_ro_alloc(NULL, NULL, new_task, &task_ro_data);
	}

	ipc_task_init(new_task, parent_task);

	task_importance_init_from_parent(new_task, parent_task);

	new_task->corpse_vmobject_list = NULL;

	if (parent_task != TASK_NULL) {
		/* inherit the parent's shared region */
		shared_region = vm_shared_region_get(parent_task);
		if (shared_region != NULL) {
			vm_shared_region_set(new_task, shared_region);
		}

#if __has_feature(ptrauth_calls)
		/* use parent's shared_region_id */
		char *shared_region_id = task_get_vm_shared_region_id_and_jop_pid(parent_task, NULL);
		if (shared_region_id != NULL) {
			shared_region_key_alloc(shared_region_id, FALSE, 0);         /* get a reference */
		}
		task_set_shared_region_id(new_task, shared_region_id);
#endif /* __has_feature(ptrauth_calls) */

		if (task_has_64Bit_addr(parent_task)) {
			task_set_64Bit_addr(new_task);
		}

		if (task_has_64Bit_data(parent_task)) {
			task_set_64Bit_data(new_task);
		}

		if (inherit_memory) {
			new_task->all_image_info_addr = parent_task->all_image_info_addr;
			new_task->all_image_info_size = parent_task->all_image_info_size;
			if (parent_task->t_flags & TF_DYLD_ALL_IMAGE_FINAL) {
				new_task->t_flags |= TF_DYLD_ALL_IMAGE_FINAL;
			}
		}
		new_task->mach_header_vm_address = 0;

		if (inherit_memory && parent_task->affinity_space) {
			task_affinity_create(parent_task, new_task);
		}

		new_task->pset_hint = parent_task->pset_hint = task_choose_pset(parent_task);

		new_task->task_exc_guard = parent_task->task_exc_guard;
		if (parent_task->t_flags & TF_NO_SMT) {
			new_task->t_flags |= TF_NO_SMT;
		}

		if (parent_task->t_flags & TF_USE_PSET_HINT_CLUSTER_TYPE) {
			new_task->t_flags |= TF_USE_PSET_HINT_CLUSTER_TYPE;
		}

		if (parent_task->t_flags & TF_TECS) {
			new_task->t_flags |= TF_TECS;
		}

#if defined(__x86_64__)
		if (parent_task->t_flags & TF_INSN_COPY_OPTOUT) {
			new_task->t_flags |= TF_INSN_COPY_OPTOUT;
		}
#endif

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
		/*
		 * On inherit_memory inherit sec-enabled and sec-inherit,
		 * and enable it on the address space. The fork() case
		 * is independent from the inheritance rules, as we must
		 * support a parent duplicating the VA space and accessing
		 * tagged memory in the child.
		 */
		if (inherit_memory) {
			if (task_has_sec(parent_task)) {
				task_set_sec(new_task);
				vm_map_set_sec_enabled(get_task_map(new_task));
			}
			if (task_has_sec_user_data(parent_task)) {
				task_set_sec_user_data(new_task);
			}
			if (task_has_sec_soft_mode(parent_task)) {
				task_set_sec_soft_mode(new_task);
			}
#if DEVELOPMENT || DEBUG
			/*
			 * The following configuration options are only
			 * available for debugging.
			 */
			if (task_has_sec_inherit(parent_task)) {
				task_set_sec_inherit(new_task);
			}
			if (task_has_sec_never_check(parent_task)) {
				task_set_sec_never_check(new_task);
				vm_map_set_sec_disabled(get_task_map(new_task));
			}
#endif /* DEVELOPMENT || DEBUG */
		}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

		new_task->priority = BASEPRI_DEFAULT;
		new_task->max_priority = MAXPRI_USER;
	} else {
#ifdef __LP64__
		if (is_64bit) {
			task_set_64Bit_addr(new_task);
		}
#endif

		if (is_64bit_data) {
			task_set_64Bit_data(new_task);
		}

		new_task->all_image_info_addr = (mach_vm_address_t)0;
		new_task->all_image_info_size = (mach_vm_size_t)0;

		new_task->pset_hint = PROCESSOR_SET_NULL;

		new_task->task_exc_guard = TASK_EXC_GUARD_NONE;

		if (new_task == kernel_task) {
			new_task->priority = BASEPRI_KERNEL;
			new_task->max_priority = MAXPRI_KERNEL;
		} else {
			new_task->priority = BASEPRI_DEFAULT;
			new_task->max_priority = MAXPRI_USER;
		}
	}

	bzero(new_task->coalition, sizeof(new_task->coalition));
	for (int i = 0; i < COALITION_NUM_TYPES; i++) {
		queue_chain_init(new_task->task_coalition[i]);
	}

	/* Allocate I/O Statistics */
	new_task->task_io_stats = kalloc_data(sizeof(struct io_stat_info),
	    Z_WAITOK | Z_ZERO | Z_NOFAIL);

	bzero(&(new_task->cpu_time_eqos_stats), sizeof(new_task->cpu_time_eqos_stats));
	bzero(&(new_task->cpu_time_rqos_stats), sizeof(new_task->cpu_time_rqos_stats));

	bzero(&new_task->extmod_statistics, sizeof(new_task->extmod_statistics));

	counter_alloc(&(new_task->pageins));
	counter_alloc(&(new_task->cow_faults));
	counter_alloc(&(new_task->messages_sent));
	counter_alloc(&(new_task->messages_received));

	/* Copy resource acc. info from Parent for Corpe Forked task. */
	if (parent_task != NULL && (t_flags & TF_CORPSE_FORK)) {
		task_rollup_accounting_info(new_task, parent_task);
		task_store_owned_vmobject_info(new_task, parent_task);
	} else {
		/* Initialize to zero for standard fork/spawn case */
		new_task->total_runnable_time = 0;
		new_task->syscalls_mach = 0;
		new_task->syscalls_unix = 0;
		new_task->c_switch = 0;
		new_task->p_switch = 0;
		new_task->ps_switch = 0;
		new_task->decompressions = 0;
		new_task->low_mem_notified_warn = 0;
		new_task->low_mem_notified_critical = 0;
		new_task->purged_memory_warn = 0;
		new_task->purged_memory_critical = 0;
		new_task->low_mem_privileged_listener = 0;
		os_atomic_store(&new_task->memlimit_flags, 0, relaxed);
		new_task->task_timer_wakeups_bin_1 = 0;
		new_task->task_timer_wakeups_bin_2 = 0;
		new_task->task_gpu_ns = 0;
		new_task->task_writes_counters_internal.task_immediate_writes = 0;
		new_task->task_writes_counters_internal.task_deferred_writes = 0;
		new_task->task_writes_counters_internal.task_invalidated_writes = 0;
		new_task->task_writes_counters_internal.task_metadata_writes = 0;
		new_task->task_writes_counters_external.task_immediate_writes = 0;
		new_task->task_writes_counters_external.task_deferred_writes = 0;
		new_task->task_writes_counters_external.task_invalidated_writes = 0;
		new_task->task_writes_counters_external.task_metadata_writes = 0;
#if CONFIG_PHYS_WRITE_ACCT
		new_task->task_fs_metadata_writes = 0;
#endif /* CONFIG_PHYS_WRITE_ACCT */
	}


	new_task->donates_own_pages = FALSE;
#if CONFIG_COALITIONS
	if (!(t_flags & TF_CORPSE_FORK)) {
		/* TODO: there is no graceful failure path here... */
		if (parent_coalitions && parent_coalitions[COALITION_TYPE_RESOURCE]) {
			coalitions_adopt_task(parent_coalitions, new_task);
			if (parent_coalitions[COALITION_TYPE_JETSAM]) {
				new_task->donates_own_pages = coalition_is_swappable(parent_coalitions[COALITION_TYPE_JETSAM]);
			}
		} else if (parent_task && parent_task->coalition[COALITION_TYPE_RESOURCE]) {
			/*
			 * all tasks at least have a resource coalition, so
			 * if the parent has one then inherit all coalitions
			 * the parent is a part of
			 */
			coalitions_adopt_task(parent_task->coalition, new_task);
			if (parent_task->coalition[COALITION_TYPE_JETSAM]) {
				new_task->donates_own_pages = coalition_is_swappable(parent_task->coalition[COALITION_TYPE_JETSAM]);
			}
		} else {
			/* TODO: assert that new_task will be PID 1 (launchd) */
			coalitions_adopt_init_task(new_task);
		}
		/*
		 * on exec, we need to transfer the coalition roles from the
		 * parent task to the exec copy task.
		 */
		if (parent_task && (t_procflags & TPF_EXEC_COPY)) {
			int coal_roles[COALITION_NUM_TYPES];
			task_coalition_roles(parent_task, coal_roles);
			(void)coalitions_set_roles(new_task->coalition, new_task, coal_roles);
		}
	} else {
		coalitions_adopt_corpse_task(new_task);
	}

	if (new_task->coalition[COALITION_TYPE_RESOURCE] == COALITION_NULL) {
		panic("created task is not a member of a resource coalition");
	}
	task_set_coalition_member(new_task);
#endif /* CONFIG_COALITIONS */

	if (parent_task != TASK_NULL) {
		/* task_policy_create queries the adopted coalition */
		task_policy_create(new_task, parent_task);
	}

	new_task->dispatchqueue_offset = 0;
	if (parent_task != NULL) {
		new_task->dispatchqueue_offset = parent_task->dispatchqueue_offset;
	}

	new_task->task_can_transfer_memory_ownership = FALSE;
	new_task->task_volatile_objects = 0;
	new_task->task_nonvolatile_objects = 0;
	new_task->task_objects_disowning = FALSE;
	new_task->task_objects_disowned = FALSE;
	new_task->task_owned_objects = 0;
	queue_init(&new_task->task_objq);

#if CONFIG_FREEZE
	queue_init(&new_task->task_frozen_cseg_q);
#endif /* CONFIG_FREEZE */

	task_objq_lock_init(new_task);

#if __arm64__
	new_task->task_legacy_footprint = FALSE;
	new_task->task_extra_footprint_limit = FALSE;
	new_task->task_ios13extended_footprint_limit = FALSE;
#endif /* __arm64__ */
	new_task->task_region_footprint = FALSE;
	new_task->task_has_crossed_thread_limit = FALSE;
	new_task->task_thread_limit = 0;
#if CONFIG_SECLUDED_MEMORY
	new_task->task_can_use_secluded_mem = FALSE;
	new_task->task_could_use_secluded_mem = FALSE;
	new_task->task_could_also_use_secluded_mem = FALSE;
	new_task->task_suppressed_secluded = FALSE;
#endif /* CONFIG_SECLUDED_MEMORY */


	/*
	 * t_flags is set up above. But since we don't
	 * support darkwake mode being set that way
	 * currently, we clear it out here explicitly.
	 */
	new_task->t_flags &= ~(TF_DARKWAKE_MODE);

	queue_init(&new_task->io_user_clients);
	new_task->loadTag = 0;

	lck_mtx_lock(&tasks_threads_lock);
	queue_enter(&tasks, new_task, task_t, tasks);
	tasks_count++;
	if (tasks_suspend_state) {
		task_suspend_internal(new_task);
	}
	lck_mtx_unlock(&tasks_threads_lock);
	task_ref_hold_proc_task_struct(new_task);

	return KERN_SUCCESS;
}

/*
 *	task_rollup_accounting_info
 *
 *	Roll up accounting stats. Used to rollup stats
 *	for exec copy task and corpse fork.
 */
void
task_rollup_accounting_info(task_t to_task, task_t from_task)
{
	assert(from_task != to_task);

	recount_task_copy(&to_task->tk_recount, &from_task->tk_recount);
	to_task->total_runnable_time = from_task->total_runnable_time;
	counter_add(&to_task->faults, counter_load(&from_task->faults));
	counter_add(&to_task->pageins, counter_load(&from_task->pageins));
	counter_add(&to_task->cow_faults, counter_load(&from_task->cow_faults));
	counter_add(&to_task->messages_sent, counter_load(&from_task->messages_sent));
	counter_add(&to_task->messages_received, counter_load(&from_task->messages_received));
	to_task->decompressions = from_task->decompressions;
	to_task->syscalls_mach = from_task->syscalls_mach;
	to_task->syscalls_unix = from_task->syscalls_unix;
	to_task->c_switch = from_task->c_switch;
	to_task->p_switch = from_task->p_switch;
	to_task->ps_switch = from_task->ps_switch;
	to_task->extmod_statistics = from_task->extmod_statistics;
	to_task->low_mem_notified_warn = from_task->low_mem_notified_warn;
	to_task->low_mem_notified_critical = from_task->low_mem_notified_critical;
	to_task->purged_memory_warn = from_task->purged_memory_warn;
	to_task->purged_memory_critical = from_task->purged_memory_critical;
	to_task->low_mem_privileged_listener = from_task->low_mem_privileged_listener;
	*to_task->task_io_stats = *from_task->task_io_stats;
	to_task->cpu_time_eqos_stats = from_task->cpu_time_eqos_stats;
	to_task->cpu_time_rqos_stats = from_task->cpu_time_rqos_stats;
	to_task->task_timer_wakeups_bin_1 = from_task->task_timer_wakeups_bin_1;
	to_task->task_timer_wakeups_bin_2 = from_task->task_timer_wakeups_bin_2;
	to_task->task_gpu_ns = from_task->task_gpu_ns;
	to_task->task_writes_counters_internal.task_immediate_writes = from_task->task_writes_counters_internal.task_immediate_writes;
	to_task->task_writes_counters_internal.task_deferred_writes = from_task->task_writes_counters_internal.task_deferred_writes;
	to_task->task_writes_counters_internal.task_invalidated_writes = from_task->task_writes_counters_internal.task_invalidated_writes;
	to_task->task_writes_counters_internal.task_metadata_writes = from_task->task_writes_counters_internal.task_metadata_writes;
	to_task->task_writes_counters_external.task_immediate_writes = from_task->task_writes_counters_external.task_immediate_writes;
	to_task->task_writes_counters_external.task_deferred_writes = from_task->task_writes_counters_external.task_deferred_writes;
	to_task->task_writes_counters_external.task_invalidated_writes = from_task->task_writes_counters_external.task_invalidated_writes;
	to_task->task_writes_counters_external.task_metadata_writes = from_task->task_writes_counters_external.task_metadata_writes;
#if CONFIG_PHYS_WRITE_ACCT
	to_task->task_fs_metadata_writes = from_task->task_fs_metadata_writes;
#endif /* CONFIG_PHYS_WRITE_ACCT */

#if CONFIG_MEMORYSTATUS
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.memorystatus_dirty_time);
#endif /* CONFIG_MEMORYSTATUS */

	/* Skip ledger roll up for memory accounting entries */
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.platform_idle_wakeups);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.interrupt_wakeups);
#if CONFIG_SCHED_SFI
	for (sfi_class_id_t class_id = SFI_CLASS_UNSPECIFIED + 1; class_id < MAX_SFI_CLASS_ID; class_id++) {
		ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.sfi_wait_times[class_id]);
	}
#endif
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time_billed_to_me);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.cpu_time_billed_to_others);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.physical_writes);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.logical_writes);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.energy_billed_to_me);
	ledger_rollup_entry(to_task->ledger, from_task->ledger, task_ledgers.energy_billed_to_others);
}

/*
 *	task_deallocate_internal:
 *
 *	Drop a reference on a task.
 *	Don't call this directly.
 */
extern void task_deallocate_internal(task_t task, os_ref_count_t refs);
void
task_deallocate_internal(
	task_t          task,
	os_ref_count_t  refs)
{
	ledger_amount_t credit, debit, interrupt_wakeups, platform_idle_wakeups;

	if (task == TASK_NULL) {
		return;
	}

#if IMPORTANCE_INHERITANCE
	if (refs == 1) {
		/*
		 * If last ref potentially comes from the task's importance,
		 * disconnect it.  But more task refs may be added before
		 * that completes, so wait for the reference to go to zero
		 * naturally (it may happen on a recursive task_deallocate()
		 * from the ipc_importance_disconnect_task() call).
		 */
		if (IIT_NULL != task->task_imp_base) {
			ipc_importance_disconnect_task(task);
		}
		return;
	}
#endif /* IMPORTANCE_INHERITANCE */

	if (refs > 0) {
		return;
	}

	/*
	 * The task should be dead at this point. Ensure other resources
	 * like threads, are gone before we trash the world.
	 */
	assert(queue_empty(&task->threads));
	assert(get_bsdtask_info(task) == NULL);
	assert(!is_active(task->itk_space));
	assert(!task->active);
	assert(task->active_thread_count == 0);
	assert(!task_get_game_mode(task));
	assert(!task_get_carplay_mode(task));

	lck_mtx_lock(&tasks_threads_lock);
	assert(terminated_tasks_count > 0);
	queue_remove(&terminated_tasks, task, task_t, tasks);
	terminated_tasks_count--;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * remove the reference on bank context
	 */
	task_bank_reset(task);

	kfree_data(task->task_io_stats, sizeof(struct io_stat_info));

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup before ripping apart
	 *	the task.
	 */
	machine_task_terminate(task);

	ipc_task_terminate(task);

	/* let iokit know 2 */
	iokit_task_terminate(task, 2);

	/* Unregister task from userspace coredumps on panic */
	kern_unregister_userspace_coredump(task);

	if (task->affinity_space) {
		task_affinity_deallocate(task);
	}

#if MACH_ASSERT
	if (task->ledger != NULL &&
	    task->map != NULL &&
	    task->map->pmap != NULL &&
	    task->map->pmap->ledger != NULL) {
		assert(task->ledger == task->map->pmap->ledger);
	}
#endif /* MACH_ASSERT */

	vm_owned_objects_disown(task);
	assert(task->task_objects_disowned);
	if (task->task_owned_objects != 0) {
		panic("task_deallocate(%p): "
		    "volatile_objects=%d nonvolatile_objects=%d owned=%d\n",
		    task,
		    task->task_volatile_objects,
		    task->task_nonvolatile_objects,
		    task->task_owned_objects);
	}

#if CONFIG_DEFERRED_RECLAIM
	/*
	 * Remove this tasks reclaim buffer from global queues.
	 */
	if (task->deferred_reclamation_metadata != NULL) {
		vm_deferred_reclamation_buffer_deallocate(task->deferred_reclamation_metadata);
		task->deferred_reclamation_metadata = NULL;
	}
#endif /* CONFIG_DEFERRED_RECLAIM */

	vm_map_deallocate(task->map);
	if (task->is_large_corpse) {
		assert(large_corpse_count > 0);
		OSDecrementAtomic(&large_corpse_count);
		task->is_large_corpse = false;
	}
	is_release(task->itk_space);

	if (task->t_rr_ranges) {
		restartable_ranges_release(task->t_rr_ranges);
	}

	ledger_tab_settle(&task_ledger_template, task->ledger);
	ledger_get_entries(task->ledger, task_ledgers.interrupt_wakeups,
	    LEO_NO_SETTLE, &interrupt_wakeups, &debit);
	ledger_get_entries(task->ledger, task_ledgers.platform_idle_wakeups,
	    LEO_NO_SETTLE, &platform_idle_wakeups, &debit);

	struct recount_times_mach sum = { 0 };
	struct recount_times_mach p_only = { 0 };
	recount_task_times_perf_only(task, &sum, &p_only);
#if CONFIG_PERVASIVE_ENERGY
	uint64_t energy = recount_task_energy_nj(task);
#endif /* CONFIG_PERVASIVE_ENERGY */
	recount_task_deinit(&task->tk_recount);

	/* Accumulate statistics for dead tasks */
	lck_spin_lock(&dead_task_statistics_lock);
	dead_task_statistics.total_user_time += sum.rtm_user;
	dead_task_statistics.total_system_time += sum.rtm_system;

	dead_task_statistics.task_interrupt_wakeups += interrupt_wakeups;
	dead_task_statistics.task_platform_idle_wakeups += platform_idle_wakeups;

	dead_task_statistics.task_timer_wakeups_bin_1 += task->task_timer_wakeups_bin_1;
	dead_task_statistics.task_timer_wakeups_bin_2 += task->task_timer_wakeups_bin_2;
	dead_task_statistics.total_ptime += p_only.rtm_user + p_only.rtm_system;
	dead_task_statistics.total_pset_switches += task->ps_switch;
	dead_task_statistics.task_gpu_ns += task->task_gpu_ns;
#if CONFIG_PERVASIVE_ENERGY
	dead_task_statistics.task_energy += energy;
#endif /* CONFIG_PERVASIVE_ENERGY */

	lck_spin_unlock(&dead_task_statistics_lock);
	lck_mtx_destroy(&task->lock, &task_lck_grp);

	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_private,
	    LEO_NO_SETTLE, &credit, &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_private.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_private.free);
	}
	if (!ledger_get_entries(task->ledger, task_ledgers.tkm_shared,
	    LEO_NO_SETTLE, &credit, &debit)) {
		OSAddAtomic64(credit, (int64_t *)&tasks_tkm_shared.alloc);
		OSAddAtomic64(debit, (int64_t *)&tasks_tkm_shared.free);
	}
	ledger_dereference(task->ledger);

	counter_free(&task->faults);
	counter_free(&task->pageins);
	counter_free(&task->cow_faults);
	counter_free(&task->messages_sent);
	counter_free(&task->messages_received);

#if CONFIG_COALITIONS
	task_release_coalitions(task);
#endif /* CONFIG_COALITIONS */

	bzero(task->coalition, sizeof(task->coalition));

#if MACH_BSD
	/* clean up collected information since last reference to task is gone */
	if (task->corpse_info) {
		void *corpse_info_kernel = kcdata_memory_get_begin_addr(task->corpse_info);
		task_crashinfo_destroy(task->corpse_info);
		task->corpse_info = NULL;
		kfree_data(corpse_info_kernel, CORPSEINFO_ALLOCATION_SIZE);
	}
#endif

#if CONFIG_MACF
	if (get_task_crash_label(task)) {
		mac_exc_free_label(get_task_crash_label(task));
		set_task_crash_label(task, NULL);
	}
#endif

	assert(queue_empty(&task->task_objq));
	task_objq_lock_destroy(task);

	if (task->corpse_vmobject_list) {
		kfree_data(task->corpse_vmobject_list,
		    (vm_size_t)task->corpse_vmobject_list_size);
	}

	task_ref_count_fini(task);
	kfree_type(struct task_token_data, task->task_tokens);
	proc_ro_erase_task(task->bsd_info_ro);
	task_release_proc_task_struct(task, task->bsd_info_ro);
}

/*
 *	task_name_deallocate_mig:
 *
 *	Drop a reference on a task name.
 */
void
task_name_deallocate_mig(
	task_name_t             task_name)
{
	return task_deallocate_grp((task_t)task_name, TASK_GRP_MIG);
}

/*
 *	task_policy_set_deallocate_mig:
 *
 *	Drop a reference on a task type.
 */
void
task_policy_set_deallocate_mig(task_policy_set_t task_policy_set)
{
	return task_deallocate_grp((task_t)task_policy_set, TASK_GRP_MIG);
}

/*
 *	task_policy_get_deallocate_mig:
 *
 *	Drop a reference on a task type.
 */
void
task_policy_get_deallocate_mig(task_policy_get_t task_policy_get)
{
	return task_deallocate_grp((task_t)task_policy_get, TASK_GRP_MIG);
}

/*
 *	task_inspect_deallocate_mig:
 *
 *	Drop a task inspection reference.
 */
void
task_inspect_deallocate_mig(
	task_inspect_t          task_inspect)
{
	return task_deallocate_grp((task_t)task_inspect, TASK_GRP_MIG);
}

/*
 *	task_read_deallocate_mig:
 *
 *	Drop a reference on task read port.
 */
void
task_read_deallocate_mig(
	task_read_t          task_read)
{
	return task_deallocate_grp((task_t)task_read, TASK_GRP_MIG);
}

/*
 *	task_suspension_token_deallocate:
 *
 *	Drop a reference on a task suspension token.
 */
void
task_suspension_token_deallocate(
	task_suspension_token_t         token)
{
	return task_deallocate((task_t)token);
}

void
task_suspension_token_deallocate_grp(
	task_suspension_token_t         token,
	task_grp_t                      grp)
{
	return task_deallocate_grp((task_t)token, grp);
}

/*
 * task_collect_crash_info:
 *
 * collect crash info from bsd and mach based data
 */
kern_return_t
task_collect_crash_info(
	task_t task,
#ifdef CONFIG_MACF
	struct label *crash_label,
#endif
	int is_corpse_fork)
{
	kern_return_t kr = KERN_SUCCESS;

	kcdata_descriptor_t crash_data = NULL;
	kcdata_descriptor_t crash_data_release = NULL;
	mach_msg_type_number_t size = CORPSEINFO_ALLOCATION_SIZE;
	mach_vm_offset_t crash_data_ptr = 0;
	void *crash_data_kernel = NULL;
	void *crash_data_kernel_release = NULL;
#if CONFIG_MACF
	struct label *label, *free_label;
#endif

	if (!corpses_enabled()) {
		return KERN_NOT_SUPPORTED;
	}

#if CONFIG_MACF
	free_label = label = mac_exc_create_label(NULL);
#endif

	task_lock(task);

	assert(is_corpse_fork || get_bsdtask_info(task) != NULL);
	if (task->corpse_info == NULL && (is_corpse_fork || get_bsdtask_info(task) != NULL)) {
#if CONFIG_MACF
		/* Set the crash label, used by the exception delivery mac hook */
		free_label = get_task_crash_label(task);         // Most likely NULL.
		set_task_crash_label(task, label);
		mac_exc_update_task_crash_label(task, crash_label);
#endif
		task_unlock(task);

		crash_data_kernel = kalloc_data(CORPSEINFO_ALLOCATION_SIZE,
		    Z_WAITOK | Z_ZERO);
		if (crash_data_kernel == NULL) {
			kr = KERN_RESOURCE_SHORTAGE;
			goto out_no_lock;
		}
		crash_data_ptr = (mach_vm_offset_t) crash_data_kernel;

		/* Do not get a corpse ref for corpse fork */
		crash_data = task_crashinfo_alloc_init((mach_vm_address_t)crash_data_ptr, size,
		    is_corpse_fork ? 0 : CORPSE_CRASHINFO_HAS_REF,
		    KCFLAG_USE_MEMCOPY);
		if (crash_data) {
			task_lock(task);
			crash_data_release = task->corpse_info;
			crash_data_kernel_release = kcdata_memory_get_begin_addr(crash_data_release);
			task->corpse_info = crash_data;

			task_unlock(task);
			kr = KERN_SUCCESS;
		} else {
			kfree_data(crash_data_kernel,
			    CORPSEINFO_ALLOCATION_SIZE);
			kr = KERN_FAILURE;
		}

		if (crash_data_release != NULL) {
			task_crashinfo_destroy(crash_data_release);
		}
		kfree_data(crash_data_kernel_release, CORPSEINFO_ALLOCATION_SIZE);
	} else {
		task_unlock(task);
	}

out_no_lock:
#if CONFIG_MACF
	if (free_label != NULL) {
		mac_exc_free_label(free_label);
	}
#endif
	return kr;
}

/*
 * task_deliver_crash_notification:
 *
 * Makes outcall to registered host port for a corpse.
 */
kern_return_t
task_deliver_crash_notification(
	task_t corpse, /* corpse or corpse fork */
	thread_t thread,
	exception_type_t etype,
	mach_exception_subcode_t subcode)
{
	kcdata_descriptor_t crash_info = corpse->corpse_info;
	thread_t th_iter = NULL;
	kern_return_t kr = KERN_SUCCESS;
	wait_interrupt_t wsave;
	mach_exception_data_type_t code[EXCEPTION_CODE_MAX];
	ipc_port_t corpse_port;

	if (crash_info == NULL) {
		return KERN_FAILURE;
	}

	assert(task_is_a_corpse(corpse));

	task_lock(corpse);

	/*
	 * Always populate code[0] as the effective exception type for EXC_CORPSE_NOTIFY.
	 * Crash reporters should derive whether it's fatal from corpse blob.
	 */
	code[0] = etype;
	code[1] = subcode;

	queue_iterate(&corpse->threads, th_iter, thread_t, task_threads)
	{
		if (th_iter->corpse_dup == FALSE) {
			ipc_thread_reset(th_iter);
		}
	}
	task_unlock(corpse);

	/* Arm the no-sender notification for taskport */
	task_reference(corpse);
	corpse_port = convert_corpse_to_port_and_nsrequest(corpse);

	wsave = thread_interrupt_level(THREAD_UNINT);
	kr = exception_triage_thread(EXC_CORPSE_NOTIFY, code, EXCEPTION_CODE_MAX, thread);
	if (kr != KERN_SUCCESS) {
		printf("Failed to send exception EXC_CORPSE_NOTIFY. error code: %d for pid %d\n", kr, task_pid(corpse));
	}

	(void)thread_interrupt_level(wsave);

	/*
	 * Drop the send right on corpse port, will fire the
	 * no-sender notification if exception deliver failed.
	 */
	ipc_port_release_send(corpse_port);
	return kr;
}

/*
 *	task_terminate:
 *
 *	Terminate the specified task.  See comments on thread_terminate
 *	(kern/thread.c) about problems with terminating the "current task."
 */

kern_return_t
task_terminate(
	task_t          task)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	if (get_bsdtask_info(task)) {
		return KERN_FAILURE;
	}

	return task_terminate_internal(task);
}

#if MACH_ASSERT
extern int proc_pid(struct proc *);
extern void proc_name_kdp(struct proc *p, char *buf, int size);
#endif /* MACH_ASSERT */

/*
 * task_mark_corpse:
 *
 * Mark the task as a corpse. Called by crashing thread.
 */
kern_return_t
task_mark_corpse(task_t task)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t self_thread;
	(void) self_thread;
	wait_interrupt_t wsave;
#if CONFIG_MACF
	struct label *crash_label = NULL;
#endif

	assert(task != kernel_task);
	assert(task == current_task());
	assert(!task_is_a_corpse(task));

#if CONFIG_MACF
	crash_label = mac_exc_create_label_for_proc((struct proc*)get_bsdtask_info(task));
#endif

	kr = task_collect_crash_info(task,
#if CONFIG_MACF
	    crash_label,
#endif
	    FALSE);
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	/* Store owned vmobjects so we can access them after being marked as corpse */
	task_store_owned_vmobject_info(task, task);

	self_thread = current_thread();

	wsave = thread_interrupt_level(THREAD_UNINT);
	task_lock(task);

	/*
	 * Check if any other thread called task_terminate_internal
	 * and made the task inactive before we could mark it for
	 * corpse pending report. Bail out if the task is inactive.
	 */
	if (!task->active) {
		kcdata_descriptor_t crash_data_release = task->corpse_info;;
		void *crash_data_kernel_release = kcdata_memory_get_begin_addr(crash_data_release);;

		task->corpse_info = NULL;
		task_unlock(task);

		if (crash_data_release != NULL) {
			task_crashinfo_destroy(crash_data_release);
		}
		kfree_data(crash_data_kernel_release, CORPSEINFO_ALLOCATION_SIZE);
		return KERN_TERMINATED;
	}

	/*
	 * ipc_task_reset() moved to last thread_terminate_self(): rdar://75737960.
	 * disable old ports here instead.
	 *
	 * The vm_map and ipc_space must exist until this function returns,
	 * convert_port_to_{map,space}_with_flavor relies on this behavior.
	 *
	 * Note this must be done before we mark the port as a corpse,
	 * so that task_port_no_senders() can determine if the no-senders
	 * is for a real corpse or not.
	 */
	ipc_task_disable(task);

	task_set_corpse_pending_report(task);
	task_set_corpse(task);
	task->crashed_thread_id = thread_tid(self_thread);

	kr = task_start_halt_locked(task, TRUE);
	assert(kr == KERN_SUCCESS);

	task_set_uniqueid(task);

	task_unlock(task);

	/* let iokit know 1 */
	iokit_task_terminate(task, 1);

	/* terminate the ipc space */
	ipc_space_terminate(task->itk_space);

	/* Add it to global corpse task list */
	task_add_to_corpse_task_list(task);

	thread_terminate_internal(self_thread);

	(void) thread_interrupt_level(wsave);
	assert(task->halting == TRUE);

out:
#if CONFIG_MACF
	mac_exc_free_label(crash_label);
#endif
	return kr;
}

/*
 *	task_set_uniqueid
 *
 *	Set task uniqueid to systemwide unique 64 bit value
 */
void
task_set_uniqueid(task_t task)
{
	task->task_uniqueid = OSIncrementAtomic64(&next_taskuniqueid);
}

/*
 *	task_clear_corpse
 *
 *	Clears the corpse pending bit on task.
 *	Removes inspection bit on the threads.
 */
void
task_clear_corpse(task_t task)
{
	thread_t th_iter = NULL;

	task_lock(task);
	queue_iterate(&task->threads, th_iter, thread_t, task_threads)
	{
		thread_mtx_lock(th_iter);
		th_iter->inspection = FALSE;
		ipc_thread_disable(th_iter);
		thread_mtx_unlock(th_iter);
	}

	thread_terminate_crashed_threads();
	/* remove the pending corpse report flag */
	task_clear_corpse_pending_report(task);

	task_unlock(task);
}

/*
 *	task_port_no_senders
 *
 *	Called whenever the Mach port system detects no-senders on
 *	a control task port.
 *
 *	Only task ports for corpses need to take action on it,
 *	and each notification that comes in should terminate
 *	the task (corpse).
 */
static void
task_port_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	task_t task;

	ip_mq_lock(port);
	task = ipc_kobject_get_locked(port, IKOT_TASK_CONTROL);
	if (task == TASK_NULL ||
	    !task_is_a_corpse(task) ||
	    /* this is the extra check, that is not har drequired for correctness
	     * but was added for performance (earlier bail out)
	     */
	    !ipc_kobject_is_mscount_current_locked(port, mscount)) {
		task = TASK_NULL;
	} else {
		task_reference_mig(task);
	}
	ip_mq_unlock(port);

	/*
	 * Task might be a corpse, we must inspect this under
	 * the task_corpse_lock to make sure that it is a registered corpse.
	 *
	 * TODO: we should really make corpses use their own IKOT_TASK_CORPSE
	 *       port type instead of these hacks.
	 */
	if (task) {
		bool corpse_destr_required = false;

		/*
		 * There can be a concurrent request to mint new send right via
		 * `task_identity_token_get_task_port`, which will call the
		 * `convert_task_to_port_with_flavor`. Normally on that path the
		 * `ipc_kobject_make_send` is called to mint the send right.
		 * This call must be done under itk lock, hence we are disabling
		 * the kobject (a) on the task port under itk lock to prevent it.
		 *
		 * All concurrent requests that has already been created before we take
		 * the port lock - are guaranteed to fail check of mscount (b)
		 */
		itk_lock(task);
		ip_mq_lock(port);

		if (ipc_kobject_get_locked(port, IKOT_TASK_CONTROL) &&
		    /* (b) Unlike previous check - this one is absolutely required here;
		     * In case if mscount doesn't match - it means that another
		     * send right was created concurrently, hence we are skipping the
		     * corpse destruction cycle;
		     */
		    ipc_kobject_is_mscount_current_locked(port, mscount)) {
			assert(task_is_a_corpse(task));
			/* (a) to make sure that concurrent check will fail */
			ipc_kobject_disable_locked(port, IKOT_TASK_CONTROL);
			corpse_destr_required = true;
		}

		ip_mq_unlock(port);
		itk_unlock(task);
		if (corpse_destr_required) {
			task_remove_from_corpse_task_list(task);
			task_clear_corpse(task);
			vm_map_unset_corpse_source(task->map);
			task_terminate_internal(task);
		}

		task_deallocate_mig(task);
	}
}

/*
 *	task_port_with_flavor_no_senders
 *
 *	Called whenever the Mach port system detects no-senders on
 *	the task inspect or read port. These ports are allocated lazily and
 *	should be deallocated here when there are no senders remaining.
 */
static void
task_port_with_flavor_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	task_t task;
	mach_task_flavor_t flavor;
	ipc_kobject_type_t kotype;

	ip_mq_lock(port);
	if (!ipc_kobject_is_mscount_current_locked(port, mscount)) {
		ip_mq_unlock(port);
		return;
	}

	kotype = ip_type(port);
	assert((IKOT_TASK_READ == kotype) || (IKOT_TASK_INSPECT == kotype));
	task = ipc_kobject_get_locked(port, kotype);
	if (task != TASK_NULL) {
		task_reference(task);
	}
	ip_mq_unlock(port);

	if (task == TASK_NULL) {
		/* The task is exiting or disabled; it will eventually deallocate the port */
		return;
	}

	if (kotype == IKOT_TASK_READ) {
		flavor = TASK_FLAVOR_READ;
	} else {
		flavor = TASK_FLAVOR_INSPECT;
	}

	itk_lock(task);
	ip_mq_lock(port);

	/*
	 * If the port is no longer active, then ipc_task_terminate() ran
	 * and destroyed the kobject already. Just deallocate the task
	 * ref we took and go away.
	 *
	 * It is also possible that several nsrequests are in flight,
	 * only one shall NULL-out the port entry, and this is the one
	 * that gets to dealloc the port.
	 *
	 * Check for a stale no-senders notification. A call to any function
	 * that vends out send rights to this port could resurrect it between
	 * this notification being generated and actually being handled here.
	 */
	if (task->itk_task_ports[flavor] != port ||
	    !ipc_kobject_is_mscount_current_locked(port, mscount)) {
		ip_mq_unlock(port);
		itk_unlock(task);
		task_deallocate(task);
		return;
	}

	task->itk_task_ports[flavor] = IP_NULL;
	itk_unlock(task);

	ipc_kobject_dealloc_port_and_unlock(port, mscount, kotype);

	task_deallocate(task);
}

/*
 *	task_wait_till_threads_terminate_locked
 *
 *	Wait till all the threads in the task are terminated.
 *	Might release the task lock and re-acquire it.
 */
void
task_wait_till_threads_terminate_locked(task_t task)
{
	/* wait for all the threads in the task to terminate */
	while (task->active_thread_count != 0) {
		assert_wait((event_t)&task->active_thread_count, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
}

/*
 *	task_duplicate_map_and_threads
 *
 *	Copy vmmap of source task.
 *	Copy active threads from source task to destination task.
 *	Source task would be suspended during the copy.
 */
kern_return_t
task_duplicate_map_and_threads(
	task_t task,
	void *p,
	task_t new_task,
	thread_t *thread_ret,
	uint64_t **udata_buffer,
	int *size,
	int *num_udata,
	bool for_exception)
{
	kern_return_t kr = KERN_SUCCESS;
	int active;
	thread_t thread, self, thread_return = THREAD_NULL;
	thread_t new_thread = THREAD_NULL, first_thread = THREAD_NULL;
	thread_t *thread_array;
	uint32_t active_thread_count = 0, array_count = 0, i;
	vm_map_t oldmap;
	uint64_t *buffer = NULL;
	int buf_size = 0;
	int est_knotes = 0, num_knotes = 0;

	self = current_thread();

	/*
	 * Suspend the task to copy thread state, use the internal
	 * variant so that no user-space process can resume
	 * the task from under us
	 */
	kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (task->map->disable_vmentry_reuse == TRUE) {
		/*
		 * Quite likely GuardMalloc (or some debugging tool)
		 * is being used on this task. And it has gone through
		 * its limit. Making a corpse will likely encounter
		 * a lot of VM entries that will need COW.
		 *
		 * Skip it.
		 */
#if DEVELOPMENT || DEBUG
		memorystatus_abort_vm_map_fork(task);
#endif
		ktriage_record(thread_tid(self), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_CORPSE, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_CORPSE_FAIL_LIBGMALLOC), 0 /* arg */);
		task_resume_internal(task);
		return KERN_FAILURE;
	}

	/* Check with VM if vm_map_fork is allowed for this task */
	bool is_large = false;
	if (memorystatus_allowed_vm_map_fork(task, &is_large)) {
		/* Setup new task's vmmap, switch from parent task's map to it COW map */
		oldmap = new_task->map;
		new_task->map = vm_map_fork(new_task->ledger,
		    task->map,
		    (VM_MAP_FORK_SHARE_IF_INHERIT_NONE |
		    VM_MAP_FORK_PRESERVE_PURGEABLE |
		    VM_MAP_FORK_CORPSE_FOOTPRINT |
		    VM_MAP_FORK_SHARE_IF_OWNED));
		if (new_task->map) {
			new_task->is_large_corpse = is_large;
			vm_map_deallocate(oldmap);

			/* copy ledgers that impact the memory footprint */
			vm_map_copy_footprint_ledgers(task, new_task);

			/* Get all the udata pointers from kqueue */
			est_knotes = kevent_proc_copy_uptrs(p, NULL, 0);
			if (est_knotes > 0) {
				buf_size = (est_knotes + 32) * sizeof(uint64_t);
				buffer = kalloc_data(buf_size, Z_WAITOK);
				num_knotes = kevent_proc_copy_uptrs(p, buffer, buf_size);
				if (num_knotes > est_knotes + 32) {
					num_knotes = est_knotes + 32;
				}
			}
		} else {
			if (is_large) {
				assert(large_corpse_count > 0);
				OSDecrementAtomic(&large_corpse_count);
			}
			new_task->map = oldmap;
#if DEVELOPMENT || DEBUG
			memorystatus_abort_vm_map_fork(task);
#endif
			task_resume_internal(task);
			return KERN_NO_SPACE;
		}
	} else if (!for_exception) {
#if DEVELOPMENT || DEBUG
		memorystatus_abort_vm_map_fork(task);
#endif
		task_resume_internal(task);
		return KERN_NO_SPACE;
	}

	active_thread_count = task->active_thread_count;
	if (active_thread_count == 0) {
		kfree_data(buffer, buf_size);
		task_resume_internal(task);
		return KERN_FAILURE;
	}

	thread_array = kalloc_type(thread_t, active_thread_count, Z_WAITOK);

	/* Iterate all the threads and drop the task lock before calling thread_create_with_continuation */
	task_lock(task);
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		/* Skip inactive threads */
		active = thread->active;
		if (!active) {
			continue;
		}

		if (array_count >= active_thread_count) {
			break;
		}

		thread_array[array_count++] = thread;
		thread_reference(thread);
	}
	task_unlock(task);

	for (i = 0; i < array_count; i++) {
		kr = thread_create_with_continuation(new_task, &new_thread, (thread_continue_t)thread_corpse_continue);
		if (kr != KERN_SUCCESS) {
			break;
		}

		/* Equivalent of current thread in corpse */
		if (thread_array[i] == self) {
			thread_return = new_thread;
			new_task->crashed_thread_id = thread_tid(new_thread);
		} else if (first_thread == NULL) {
			first_thread = new_thread;
		} else {
			/* drop the extra ref returned by thread_create_with_continuation */
			thread_deallocate(new_thread);
		}

		kr = thread_dup2(thread_array[i], new_thread);
		if (kr != KERN_SUCCESS) {
			thread_mtx_lock(new_thread);
			new_thread->corpse_dup = TRUE;
			thread_mtx_unlock(new_thread);
			continue;
		}

		/* Copy thread name */
		bsd_copythreadname(get_bsdthread_info(new_thread),
		    get_bsdthread_info(thread_array[i]));
		new_thread->thread_tag = thread_array[i]->thread_tag &
		    ~THREAD_TAG_USER_JOIN;
		thread_copy_resource_info(new_thread, thread_array[i]);
	}

	/* return the first thread if we couldn't find the equivalent of current */
	if (thread_return == THREAD_NULL) {
		thread_return = first_thread;
	} else if (first_thread != THREAD_NULL) {
		/* drop the extra ref returned by thread_create_with_continuation */
		thread_deallocate(first_thread);
	}

	task_resume_internal(task);

	for (i = 0; i < array_count; i++) {
		thread_deallocate(thread_array[i]);
	}
	kfree_type(thread_t, active_thread_count, thread_array);

	if (kr == KERN_SUCCESS) {
		*thread_ret = thread_return;
		*udata_buffer = buffer;
		*size = buf_size;
		*num_udata = num_knotes;
	} else {
		if (thread_return != THREAD_NULL) {
			thread_deallocate(thread_return);
		}
		kfree_data(buffer, buf_size);
	}

	return kr;
}

#if CONFIG_SECLUDED_MEMORY
extern void task_set_can_use_secluded_mem_locked(
	task_t          task,
	boolean_t       can_use_secluded_mem);
#endif /* CONFIG_SECLUDED_MEMORY */

#if MACH_ASSERT
int debug4k_panic_on_terminate = 0;
#endif /* MACH_ASSERT */
kern_return_t
task_terminate_internal(
	task_t                  task)
{
	thread_t                        thread, self;
	task_t                          self_task;
	boolean_t                       interrupt_save;
	int                             pid = 0;

	assert(task != kernel_task);

	self = current_thread();
	self_task = current_task();

	/*
	 *	Get the task locked and make sure that we are not racing
	 *	with someone else trying to terminate us.
	 */
	if (task == self_task) {
		task_lock(task);
	} else if (task < self_task) {
		task_lock(task);
		task_lock(self_task);
	} else {
		task_lock(self_task);
		task_lock(task);
	}

#if CONFIG_SECLUDED_MEMORY
	if (task->task_can_use_secluded_mem) {
		task_set_can_use_secluded_mem_locked(task, FALSE);
	}
	task->task_could_use_secluded_mem = FALSE;
	task->task_could_also_use_secluded_mem = FALSE;

	if (task->task_suppressed_secluded) {
		stop_secluded_suppression(task);
	}
#endif /* CONFIG_SECLUDED_MEMORY */

	if (!task->active) {
		/*
		 *	Task is already being terminated.
		 *	Just return an error. If we are dying, this will
		 *	just get us to our AST special handler and that
		 *	will get us to finalize the termination of ourselves.
		 */
		task_unlock(task);
		if (self_task != task) {
			task_unlock(self_task);
		}

		return KERN_FAILURE;
	}

	if (task_corpse_pending_report(task)) {
		/*
		 *	Task is marked for reporting as corpse.
		 *	Just return an error. This will
		 *	just get us to our AST special handler and that
		 *	will get us to finish the path to death
		 */
		task_unlock(task);
		if (self_task != task) {
			task_unlock(self_task);
		}

		return KERN_FAILURE;
	}

	if (self_task != task) {
		task_unlock(self_task);
	}

	/*
	 * Make sure the current thread does not get aborted out of
	 * the waits inside these operations.
	 */
	interrupt_save = thread_interrupt_level(THREAD_UNINT);

	/*
	 *	Indicate that we want all the threads to stop executing
	 *	at user space by holding the task (we would have held
	 *	each thread independently in thread_terminate_internal -
	 *	but this way we may be more likely to already find it
	 *	held there).  Mark the task inactive, and prevent
	 *	further task operations via the task port.
	 *
	 *	The vm_map and ipc_space must exist until this function returns,
	 *	convert_port_to_{map,space}_with_flavor relies on this behavior.
	 */
	bool first_suspension __unused = task_hold_locked(task);
	task->active = FALSE;
	ipc_task_disable(task);

#if CONFIG_EXCLAVES
	/* before conclave can be suspended */
	exclaves_conclave_prepare_teardown(task);

	//rdar://139307390, first suspension might not have done conclave suspend.
	first_suspension = true;
	if (first_suspension) {
		task_unlock(task);
		task_suspend_conclave(task);
		task_lock(task);
	}
#endif /* CONFIG_EXCLAVES */


	/*
	 *	Terminate each thread in the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_terminate_internal(thread);
	}

#ifdef MACH_BSD
	void *bsd_info = get_bsdtask_info(task);
	if (bsd_info != NULL) {
		pid = proc_pid(bsd_info);
	}
#endif /* MACH_BSD */

	task_unlock(task);

#if CONFIG_EXCLAVES
	task_stop_conclave(task, false);
#endif /* CONFIG_EXCLAVES */

	proc_set_task_policy(task, TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

	/* Early object reap phase */

#if CONFIG_TASKWATCH
	/*
	 * remove all task watchers
	 */
	task_removewatchers(task);

#endif /* CONFIG_TASKWATCH */

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/*
	 *	Clear the watchport boost on the task.
	 */
	task_remove_turnstile_watchports(task);

	/* let iokit know 1 */
	iokit_task_terminate(task, 1);

	/*
	 *	Destroy the IPC space, leaving just a reference for it.
	 */
	ipc_space_terminate(task->itk_space);

#if 00
	/* if some ledgers go negative on tear-down again... */
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
	    task_ledgers.phys_footprint);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
	    task_ledgers.internal);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
	    task_ledgers.iokit_mapped);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
	    task_ledgers.alternate_accounting);
	ledger_disable_panic_on_negative(task->map->pmap->ledger,
	    task_ledgers.alternate_accounting_compressed);
#endif

	/*
	 * If the current thread is a member of the task
	 * being terminated, then the last reference to
	 * the task will not be dropped until the thread
	 * is finally reaped.  To avoid incurring the
	 * expense of removing the address space regions
	 * at reap time, we do it explictly here.
	 */

#if MACH_ASSERT
	/*
	 * Identify the pmap's process, in case the pmap ledgers drift
	 * and we have to report it.
	 */
	char procname[17];
	void *proc = get_bsdtask_info(task);
	if (proc) {
		pid = proc_pid(proc);
		proc_name_kdp(proc, procname, sizeof(procname));
	} else {
		pid = 0;
		strlcpy(procname, "<unknown>", sizeof(procname));
	}
	pmap_set_process(task->map->pmap, pid, procname);
	if (vm_map_page_shift(task->map) < (int)PAGE_SHIFT) {
		DEBUG4K_LIFE("map %p procname: %s\n", task->map, procname);
		if (debug4k_panic_on_terminate) {
			panic("DEBUG4K: %s:%d %d[%s] map %p", __FUNCTION__, __LINE__, pid, procname, task->map);
		}
	}
#endif /* MACH_ASSERT */

	vm_map_terminate(task->map);

	/* release our shared region */
	vm_shared_region_set(task, NULL);

#if __has_feature(ptrauth_calls)
	task_set_shared_region_id(task, NULL);
#endif /* __has_feature(ptrauth_calls) */

	lck_mtx_lock(&tasks_threads_lock);
	queue_remove(&tasks, task, task_t, tasks);
	queue_enter(&terminated_tasks, task, task_t, tasks);
	tasks_count--;
	terminated_tasks_count++;
	lck_mtx_unlock(&tasks_threads_lock);

	/*
	 * We no longer need to guard against being aborted, so restore
	 * the previous interruptible state.
	 */
	thread_interrupt_level(interrupt_save);

#if CONFIG_CPU_COUNTERS
	cpc_task_terminate(&task->t_cpc);
#endif /* CONFIG_CPU_COUNTERS */

#if CONFIG_COALITIONS
	/*
	 * Leave the coalition for corpse task or task that
	 * never had any active threads (e.g. fork, exec failure).
	 * For task with active threads, the task will be removed
	 * from coalition by last terminating thread.
	 */
	if (task->active_thread_count == 0) {
		coalitions_remove_task(task);
	}
#endif

#if CONFIG_FREEZE
	extern int      vm_compressor_available;
	if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE && vm_compressor_available) {
		task_disown_frozen_csegs(task);
		assert(queue_empty(&task->task_frozen_cseg_q));
	}
#endif /* CONFIG_FREEZE */


	/*
	 * Get rid of the task active reference on itself.
	 */
	task_deallocate_grp(task, TASK_GRP_INTERNAL);

	return KERN_SUCCESS;
}

void
tasks_system_suspend(boolean_t suspend)
{
	task_t task;

	KDBG(MACHDBG_CODE(DBG_MACH_SCHED, MACH_SUSPEND_USERSPACE) |
	    (suspend ? DBG_FUNC_START : DBG_FUNC_END));

	lck_mtx_lock(&tasks_threads_lock);
	assert(tasks_suspend_state != suspend);
	tasks_suspend_state = suspend;
	queue_iterate(&tasks, task, task_t, tasks) {
		if (task == kernel_task) {
			continue;
		}
		if (task_is_driver(task)) {
			continue;
		}
		suspend ? task_suspend_internal(task) : task_resume_internal(task);
	}
	lck_mtx_unlock(&tasks_threads_lock);
}

/*
 * task_start_halt:
 *
 *      Shut the current task down (except for the current thread) in
 *	preparation for dramatic changes to the task (probably exec).
 *	We hold the task and mark all other threads in the task for
 *	termination.
 */
kern_return_t
task_start_halt(task_t task)
{
	kern_return_t kr = KERN_SUCCESS;
	task_lock(task);
	kr = task_start_halt_locked(task, FALSE);
	task_unlock(task);
	return kr;
}

static kern_return_t
task_start_halt_locked(task_t task, boolean_t should_mark_corpse)
{
	thread_t thread, self;
	uint64_t dispatchqueue_offset;

	assert(task != kernel_task);

	self = current_thread();

	if (task != get_threadtask(self) && !task_is_a_corpse_fork(task)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (!should_mark_corpse &&
	    (task->halting || !task->active || !self->active)) {
		/*
		 * Task or current thread is already being terminated.
		 * Hurry up and return out of the current kernel context
		 * so that we run our AST special handler to terminate
		 * ourselves. If should_mark_corpse is set, the corpse
		 * creation might have raced with exec, let the corpse
		 * creation continue, once the current thread reaches AST
		 * thread in exec will be woken up from task_complete_halt.
		 * Exec will fail cause the proc was marked for exit.
		 * Once the thread in exec reaches AST, it will call proc_exit
		 * and deliver the EXC_CORPSE_NOTIFY.
		 */
		return KERN_FAILURE;
	}

	/* Thread creation will fail after this point of no return. */
	task->halting = TRUE;

	/*
	 * Mark all the threads to keep them from starting any more
	 * user-level execution. The thread_terminate_internal code
	 * would do this on a thread by thread basis anyway, but this
	 * gives us a better chance of not having to wait there.
	 */
	bool first_suspension __unused = task_hold_locked(task);

#if CONFIG_EXCLAVES
	if (should_mark_corpse) {
		void *crash_info_ptr = task_get_corpseinfo(task);
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (crash_info_ptr != NULL && thread->th_exclaves_ipc_ctx.ipcb != NULL) {
				struct thread_crash_exclaves_info info = { 0 };

				info.tcei_flags = kExclaveRPCActive;
				info.tcei_scid = thread->th_exclaves_ipc_ctx.scid;
				info.tcei_thread_id = thread->thread_id;

				kcdata_push_data(crash_info_ptr,
				    STACKSHOT_KCTYPE_KERN_EXCLAVES_CRASH_THREADINFO,
				    sizeof(struct thread_crash_exclaves_info), &info);
			}
		}
	}
	//rdar://139307390, first suspension might not have done conclave suspend.
	first_suspension = true;
	if (first_suspension || should_mark_corpse) {
		task_unlock(task);

		/* before we can teardown the conclave */
		exclaves_conclave_prepare_teardown(task);

		if (first_suspension) {
			task_suspend_conclave(task);
		}

		if (should_mark_corpse) {
			task_stop_conclave(task, true);
		}
		task_lock(task);
	}
#endif /* CONFIG_EXCLAVES */

	dispatchqueue_offset = get_dispatchqueue_offset_from_proc(get_bsdtask_info(task));
	/*
	 * Terminate all the other threads in the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads)
	{
		/*
		 * Remove priority throttles for threads to terminate timely. This has
		 * to be done after task_hold_locked() traps all threads to AST, but before
		 * threads are marked inactive in thread_terminate_internal(). Takes thread
		 * mutex lock.
		 *
		 * We need task_is_a_corpse() check so that we don't accidently update policy
		 * for tasks that are doing posix_spawn().
		 *
		 * See: thread_policy_update_tasklocked().
		 */
		if (task_is_a_corpse(task)) {
			proc_set_thread_policy(thread, TASK_POLICY_ATTRIBUTE,
			    TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);
		}

		if (should_mark_corpse) {
			thread_mtx_lock(thread);
			thread->inspection = TRUE;
			thread_mtx_unlock(thread);
		}
		if (thread != self) {
			thread_terminate_internal(thread);
		}
	}
	task->dispatchqueue_offset = dispatchqueue_offset;

	task_release_locked(task);

	return KERN_SUCCESS;
}


/*
 * task_complete_halt:
 *
 *	Complete task halt by waiting for threads to terminate, then clean
 *	up task resources (VM, port namespace, etc...) and then let the
 *	current thread go in the (practically empty) task context.
 *
 *	Note: task->halting flag is not cleared in order to avoid creation
 *	of new thread in old exec'ed task.
 */
void
task_complete_halt(task_t task)
{
	task_lock(task);
	assert(task->halting);
	assert(task == current_task());

	/*
	 *	Wait for the other threads to get shut down.
	 *      When the last other thread is reaped, we'll be
	 *	woken up.
	 */
	if (task->thread_count > 1) {
		assert_wait((event_t)&task->halting, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);
	} else {
		task_unlock(task);
	}

#if CONFIG_DEFERRED_RECLAIM
	if (task->deferred_reclamation_metadata) {
		vm_deferred_reclamation_buffer_deallocate(
			task->deferred_reclamation_metadata);
		task->deferred_reclamation_metadata = NULL;
	}
#endif /* CONFIG_DEFERRED_RECLAIM */

	/*
	 *	Give the machine dependent code a chance
	 *	to perform cleanup of task-level resources
	 *	associated with the current thread before
	 *	ripping apart the task.
	 */
	machine_task_terminate(task);

	/*
	 *	Destroy all synchronizers owned by the task.
	 */
	task_synchronizer_destroy_all(task);

	/* let iokit know 1 */
	iokit_task_terminate(task, 1);

	/*
	 *	Terminate the IPC space.  A long time ago,
	 *	this used to be ipc_space_clean() which would
	 *	keep the space active but hollow it.
	 *
	 *	We really do not need this semantics given
	 *	tasks die with exec now.
	 */
	ipc_space_terminate(task->itk_space);

	/*
	 * Clean out the address space, as we are going to be
	 * getting a new one.
	 */
	vm_map_terminate(task->map);

	/*
	 * Kick out any IOKitUser handles to the task. At best they're stale,
	 * at worst someone is racing a SUID exec.
	 */
	/* let iokit know 2 */
	iokit_task_terminate(task, 2);
}

#ifdef CONFIG_TASK_SUSPEND_STATS

static void
_task_mark_suspend_source(task_t task)
{
	int idx;
	task_suspend_stats_t stats;
	task_suspend_source_t source;
	task_lock_assert_owned(task);
	stats = &task->t_suspend_stats;

	idx = stats->tss_count % TASK_SUSPEND_SOURCES_MAX;
	source = &task->t_suspend_sources[idx];
	bzero(source, sizeof(*source));

	source->tss_time = mach_absolute_time();
	source->tss_tid = current_thread()->thread_id;
	source->tss_pid = task_pid(current_task());
	strlcpy(source->tss_procname, task_best_name(current_task()),
	    sizeof(source->tss_procname));

	stats->tss_count++;
}

static inline void
_task_mark_suspend_start(task_t task)
{
	task_lock_assert_owned(task);
	task->t_suspend_stats.tss_last_start = mach_absolute_time();
}

static inline void
_task_mark_suspend_end(task_t task)
{
	task_lock_assert_owned(task);
	task->t_suspend_stats.tss_last_end = mach_absolute_time();
	task->t_suspend_stats.tss_duration += (task->t_suspend_stats.tss_last_end -
	    task->t_suspend_stats.tss_last_start);
}

static kern_return_t
_task_get_suspend_stats_locked(task_t task, task_suspend_stats_t stats)
{
	if (task == TASK_NULL || stats == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	task_lock_assert_owned(task);
	memcpy(stats, &task->t_suspend_stats, sizeof(task->t_suspend_stats));
	return KERN_SUCCESS;
}

static kern_return_t
_task_get_suspend_sources_locked(task_t task, task_suspend_source_t sources)
{
	if (task == TASK_NULL || sources == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	task_lock_assert_owned(task);
	memcpy(sources, task->t_suspend_sources,
	    sizeof(struct task_suspend_source_s) * TASK_SUSPEND_SOURCES_MAX);
	return KERN_SUCCESS;
}

#endif /* CONFIG_TASK_SUSPEND_STATS */

kern_return_t
task_get_suspend_stats(task_t task, task_suspend_stats_t stats)
{
#ifdef CONFIG_TASK_SUSPEND_STATS
	kern_return_t kr;
	if (task == TASK_NULL || stats == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	task_lock(task);
	kr = _task_get_suspend_stats_locked(task, stats);
	task_unlock(task);
	return kr;
#else /* CONFIG_TASK_SUSPEND_STATS */
	(void)task;
	(void)stats;
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
task_get_suspend_stats_kdp(task_t task, task_suspend_stats_t stats)
{
#ifdef CONFIG_TASK_SUSPEND_STATS
	if (task == TASK_NULL || stats == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	memcpy(stats, &task->t_suspend_stats, sizeof(task->t_suspend_stats));
	return KERN_SUCCESS;
#else /* CONFIG_TASK_SUSPEND_STATS */
#pragma unused(task, stats)
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_TASK_SUSPEND_STATS */
}

kern_return_t
task_get_suspend_sources(task_t task, task_suspend_source_array_t sources)
{
#ifdef CONFIG_TASK_SUSPEND_STATS
	kern_return_t kr;
	if (task == TASK_NULL || sources == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	task_lock(task);
	kr = _task_get_suspend_sources_locked(task, sources);
	task_unlock(task);
	return kr;
#else /* CONFIG_TASK_SUSPEND_STATS */
	(void)task;
	(void)sources;
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
task_get_suspend_sources_kdp(task_t task, task_suspend_source_array_t sources)
{
#ifdef CONFIG_TASK_SUSPEND_STATS
	if (task == TASK_NULL || sources == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	memcpy(sources, task->t_suspend_sources,
	    sizeof(struct task_suspend_source_s) * TASK_SUSPEND_SOURCES_MAX);
	return KERN_SUCCESS;
#else /* CONFIG_TASK_SUSPEND_STATS */
#pragma unused(task, sources)
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
task_set_cs_auxiliary_info(task_t task, uint64_t info)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task->task_cs_auxiliary_info = info;
	return KERN_SUCCESS;
}

uint64_t
task_get_cs_auxiliary_info_kdp(task_t task)
{
	if (task == TASK_NULL) {
		return 0;
	}
	return task->task_cs_auxiliary_info;
}

/*
 *	task_hold_locked:
 *
 *	Suspend execution of the specified task.
 *	This is a recursive-style suspension of the task, a count of
 *	suspends is maintained.
 *
 *	CONDITIONS: the task is locked and active.
 *	Returns true if this was first suspension
 */
bool
task_hold_locked(
	task_t          task)
{
	thread_t        thread;
	void *bsd_info = get_bsdtask_info(task);

	assert(task->active);

	if (task->suspend_count++ > 0) {
		return false;
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SUSPENSION, MACH_TASK_SUSPEND),
	    task_pid(task), task->user_stop_count, task->pidsuspended);

	if (bsd_info) {
		workq_proc_suspended(bsd_info);
	}

	/*
	 *	Iterate through all the threads and hold them.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_hold(thread);
		thread_mtx_unlock(thread);
	}

#ifdef CONFIG_TASK_SUSPEND_STATS
	_task_mark_suspend_start(task);
#endif
	return true;
}

/*
 *	task_hold_and_wait
 *
 *	Same as the internal routine above, except that is must lock
 *	and verify that the task is active.  This differs from task_suspend
 *	in that it places a kernel hold on the task rather than just a
 *	user-level hold.  This keeps users from over resuming and setting
 *	it running out from under the kernel.
 *
 *      CONDITIONS: the caller holds a reference on the task
 */
kern_return_t
task_hold_and_wait(
	task_t          task,
	bool            suspend_conclave __unused)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

#ifdef CONFIG_TASK_SUSPEND_STATS
	_task_mark_suspend_source(task);
#endif /* CONFIG_TASK_SUSPEND_STATS */

	bool first_suspension __unused = task_hold_locked(task);

#if CONFIG_EXCLAVES
	//rdar://139307390, first suspension might not have done conclave suspend.
	first_suspension = true;
	if (suspend_conclave && first_suspension) {
		/* before we can teardown the conclave */
		exclaves_conclave_prepare_teardown(task);

		task_unlock(task);
		task_suspend_conclave(task);
		task_lock(task);
		/*
		 * If task terminated/resumed before we could wait on threads, then
		 * it is a race we lost and we could treat that as termination/resume
		 * happened after the wait and return SUCCESS.
		 */
		if (!task->active || task->suspend_count <= 0) {
			task_unlock(task);
			return KERN_SUCCESS;
		}
	}
#endif /* CONFIG_EXCLAVES */

	task_wait_locked(task, FALSE);
	task_unlock(task);

	return KERN_SUCCESS;
}

/*
 *	task_wait_locked:
 *
 *	Wait for all threads in task to stop.
 *
 * Conditions:
 *	Called with task locked, active, and held.
 */
void
task_wait_locked(
	task_t          task,
	boolean_t               until_not_runnable)
{
	thread_t        thread, self;

	assert(task->active);
	assert(task->suspend_count > 0);

	self = current_thread();

	/*
	 *	Iterate through all the threads and wait for them to
	 *	stop.  Do not wait for the current thread if it is within
	 *	the task.
	 */
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread != self) {
			thread_wait(thread, until_not_runnable);
		}
	}
}

boolean_t
task_is_app_suspended(task_t task)
{
	return task->pidsuspended;
}

/*
 *	task_release_locked:
 *
 *	Release a kernel hold on a task.
 *
 *      CONDITIONS: the task is locked and active
 */
void
task_release_locked(
	task_t          task)
{
	thread_t        thread;
	void *bsd_info = get_bsdtask_info(task);

	assert(task->active);
	assert(task->suspend_count > 0);

	if (--task->suspend_count > 0) {
		return;
	}

	if (bsd_info) {
		workq_proc_resumed(bsd_info);
	}

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		thread_mtx_lock(thread);
		thread_release(thread);
		thread_mtx_unlock(thread);
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_SUSPENSION, MACH_TASK_RESUME) | DBG_FUNC_NONE, task_pid(task));

#if CONFIG_TASK_SUSPEND_STATS
	_task_mark_suspend_end(task);
#endif

//rdar://139307390.
#if 0
#if CONFIG_EXCLAVES
	task_unlock(task);
	task_resume_conclave(task);
	task_lock(task);
#endif /* CONFIG_EXCLAVES */
#endif
}

/*
 *	task_release:
 *
 *	Same as the internal routine above, except that it must lock
 *	and verify that the task is active.
 *
 *      CONDITIONS: The caller holds a reference to the task
 */
kern_return_t
task_release(
	task_t          task)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);

		return KERN_FAILURE;
	}

	task_release_locked(task);
	task_unlock(task);

	return KERN_SUCCESS;
}

static kern_return_t
task_threads_internal(
	task_t                  task,
	thread_act_array_t     *threads_out,
	mach_msg_type_number_t *countp,
	mach_thread_flavor_t    flavor)
{
	mach_msg_type_number_t  actual, count, count_needed;
	thread_act_array_t      thread_list;
	thread_t                thread;
	unsigned int            i;

	count = 0;
	thread_list = NULL;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	assert(flavor <= THREAD_FLAVOR_INSPECT);

	for (;;) {
		task_lock(task);
		if (!task->active) {
			task_unlock(task);

			mach_port_array_free(thread_list, count);
			return KERN_FAILURE;
		}

		count_needed = actual = task->thread_count;
		if (count_needed <= count) {
			break;
		}

		/* unlock the task and allocate more memory */
		task_unlock(task);

		mach_port_array_free(thread_list, count);
		count = count_needed;
		thread_list = mach_port_array_alloc(count, Z_WAITOK);

		if (thread_list == NULL) {
			return KERN_RESOURCE_SHORTAGE;
		}
	}

	i = 0;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		assert(i < actual);
		thread_reference(thread);
		((thread_t *)thread_list)[i++] = thread;
	}

	count_needed = actual;

	/* can unlock task now that we've got the thread refs */
	task_unlock(task);

	if (actual == 0) {
		/* no threads, so return null pointer and deallocate memory */

		mach_port_array_free(thread_list, count);

		*threads_out = NULL;
		*countp = 0;
	} else {
		/* if we allocated too much, must copy */
		if (count_needed < count) {
			mach_port_array_t newaddr;

			newaddr = mach_port_array_alloc(count_needed, Z_WAITOK);
			if (newaddr == NULL) {
				for (i = 0; i < actual; ++i) {
					thread_deallocate(((thread_t *)thread_list)[i]);
				}
				mach_port_array_free(thread_list, count);
				return KERN_RESOURCE_SHORTAGE;
			}

			bcopy(thread_list, newaddr, count_needed * sizeof(thread_t));
			mach_port_array_free(thread_list, count);
			thread_list = newaddr;
		}

		/* do the conversion that Mig should handle */
		convert_thread_array_to_ports(thread_list, actual, flavor);

		*threads_out = thread_list;
		*countp = actual;
	}

	return KERN_SUCCESS;
}


kern_return_t
task_threads_from_user(
	mach_port_t                 port,
	thread_act_array_t         *threads_out,
	mach_msg_type_number_t     *count)
{
	ipc_kobject_type_t kotype;
	kern_return_t kr;

	task_t task = convert_port_to_task_inspect_no_eval(port);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	kotype = ip_type(port);

	switch (kotype) {
	case IKOT_TASK_CONTROL:
		kr = task_threads_internal(task, threads_out, count, THREAD_FLAVOR_CONTROL);
		break;
	case IKOT_TASK_READ:
		kr = task_threads_internal(task, threads_out, count, THREAD_FLAVOR_READ);
		break;
	case IKOT_TASK_INSPECT:
		kr = task_threads_internal(task, threads_out, count, THREAD_FLAVOR_INSPECT);
		break;
	default:
		panic("strange kobject type");
		break;
	}

	task_deallocate(task);
	return kr;
}

#define TASK_HOLD_NORMAL        0
#define TASK_HOLD_PIDSUSPEND    1
#define TASK_HOLD_LEGACY        2
#define TASK_HOLD_LEGACY_ALL    3

static kern_return_t
place_task_hold(
	task_t task,
	int mode)
{
	if (!task->active && !task_is_a_corpse(task)) {
		return KERN_FAILURE;
	}

	/* Return success for corpse task */
	if (task_is_a_corpse(task)) {
		return KERN_SUCCESS;
	}

#if MACH_ASSERT
	current_task()->suspends_outstanding++;
#endif

	if (mode == TASK_HOLD_LEGACY) {
		task->legacy_stop_count++;
	}

#ifdef CONFIG_TASK_SUSPEND_STATS
	_task_mark_suspend_source(task);
#endif /* CONFIG_TASK_SUSPEND_STATS */

	if (task->user_stop_count++ > 0) {
		/*
		 *	If the stop count was positive, the task is
		 *	already stopped and we can exit.
		 */
		return KERN_SUCCESS;
	}

	/*
	 * Put a kernel-level hold on the threads in the task (all
	 * user-level task suspensions added together represent a
	 * single kernel-level hold).  We then wait for the threads
	 * to stop executing user code.
	 */
	bool first_suspension __unused = task_hold_locked(task);

//rdar://139307390, do not suspend conclave on task suspend.
#if 0
#if CONFIG_EXCLAVES
	if (first_suspension) {
		task_unlock(task);
		task_suspend_conclave(task);

		/*
		 * If task terminated/resumed before we could wait on threads, then
		 * it is a race we lost and we could treat that as termination/resume
		 * happened after the wait and return SUCCESS.
		 */
		task_lock(task);
		if (!task->active || task->suspend_count <= 0) {
			return KERN_SUCCESS;
		}
	}
#endif /* CONFIG_EXCLAVES */
#endif

	task_wait_locked(task, FALSE);

	return KERN_SUCCESS;
}

static kern_return_t
release_task_hold(
	task_t          task,
	int                     mode)
{
	boolean_t release = FALSE;

	if (!task->active && !task_is_a_corpse(task)) {
		return KERN_FAILURE;
	}

	/* Return success for corpse task */
	if (task_is_a_corpse(task)) {
		return KERN_SUCCESS;
	}

	if (mode == TASK_HOLD_PIDSUSPEND) {
		if (task->pidsuspended == FALSE) {
			return KERN_FAILURE;
		}
		task->pidsuspended = FALSE;
	}

	if (task->user_stop_count > (task->pidsuspended ? 1 : 0)) {
#if MACH_ASSERT
		/*
		 * This is obviously not robust; if we suspend one task and then resume a different one,
		 * we'll fly under the radar. This is only meant to catch the common case of a crashed
		 * or buggy suspender.
		 */
		current_task()->suspends_outstanding--;
#endif

		if (mode == TASK_HOLD_LEGACY_ALL) {
			if (task->legacy_stop_count >= task->user_stop_count) {
				task->user_stop_count = 0;
				release = TRUE;
			} else {
				task->user_stop_count -= task->legacy_stop_count;
			}
			task->legacy_stop_count = 0;
		} else {
			if (mode == TASK_HOLD_LEGACY && task->legacy_stop_count > 0) {
				task->legacy_stop_count--;
			}
			if (--task->user_stop_count == 0) {
				release = TRUE;
			}
		}
	} else {
		return KERN_FAILURE;
	}

	/*
	 *	Release the task if necessary.
	 */
	if (release) {
		task_release_locked(task);
	}

	return KERN_SUCCESS;
}

boolean_t
get_task_suspended(task_t task)
{
	return 0 != task->user_stop_count;
}

/*
 *	task_suspend:
 *
 *	Implement an (old-fashioned) user-level suspension on a task.
 *
 *	Because the user isn't expecting to have to manage a suspension
 *	token, we'll track it for them in the kernel in the form of a naked
 *	send right to the task's resume port.  All such send rights
 *	account for a single suspension against the task (unlike task_suspend2()
 *	where each caller gets a unique suspension count represented by a
 *	unique send-once right).
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
kern_return_t
task_suspend(
	task_t          task)
{
	kern_return_t           kr;
	mach_port_t             port;
	mach_port_name_t        name;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * place a legacy hold on the task.
	 */
	task_lock(task);
	kr = place_task_hold(task, TASK_HOLD_LEGACY);
	task_unlock(task);

	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/*
	 * Claim a send right on the task resume port, and request a no-senders
	 * notification on that port (if none outstanding).
	 */
	itk_lock(task);
	port = task->itk_resume;
	if (port == IP_NULL) {
		port = ipc_kobject_alloc_port(task, IKOT_TASK_RESUME,
		    IPC_KOBJECT_ALLOC_MAKE_SEND);
		task->itk_resume = port;
	} else {
		(void)ipc_kobject_make_send(port, task, IKOT_TASK_RESUME);
	}
	itk_unlock(task);

	/*
	 * Copyout the send right into the calling task's IPC space.  It won't know it is there,
	 * but we'll look it up when calling a traditional resume.  Any IPC operations that
	 * deallocate the send right will auto-release the suspension.
	 */
	if (IP_VALID(port)) {
		kr = ipc_object_copyout(current_space(), port,
		    MACH_MSG_TYPE_MOVE_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
		    NULL, &name);
		if (__improbable(kr != KERN_SUCCESS)) {
			printf("warning: %s(%d) failed to copyout suspension "
			    "token for pid %d with error: %d\n",
			    proc_name_address(get_bsdtask_info(current_task())),
			    proc_pid(get_bsdtask_info(current_task())),
			    task_pid(task), kr);
		}
	}

	return kr;
}

/*
 *	task_resume:
 *		Release a user hold on a task.
 *
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t
task_resume(
	task_t  task)
{
	kern_return_t    kr;
	mach_port_name_t resume_port_name;
	ipc_entry_t              resume_port_entry;
	ipc_space_t              space = current_task()->itk_space;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	/* release a legacy task hold */
	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_LEGACY);
	task_unlock(task);

	itk_lock(task); /* for itk_resume */
	is_write_lock(space); /* spin lock */
	if (is_active(space) && IP_VALID(task->itk_resume) &&
	    ipc_hash_lookup(space, ip_to_object(task->itk_resume), &resume_port_name, &resume_port_entry) == TRUE) {
		/*
		 * We found a suspension token in the caller's IPC space. Release a send right to indicate that
		 * we are holding one less legacy hold on the task from this caller.  If the release failed,
		 * go ahead and drop all the rights, as someone either already released our holds or the task
		 * is gone.
		 */
		itk_unlock(task);
		if (kr == KERN_SUCCESS) {
			ipc_right_dealloc(space, resume_port_name, resume_port_entry);
		} else {
			ipc_right_destroy(space, resume_port_name, resume_port_entry);
		}
		/* space unlocked */
	} else {
		itk_unlock(task);
		is_write_unlock(space);
		if (kr == KERN_SUCCESS) {
			printf("warning: %s(%d) performed out-of-band resume on pid %d\n",
			    proc_name_address(get_bsdtask_info(current_task())), proc_pid(get_bsdtask_info(current_task())),
			    task_pid(task));
		}
	}

	return kr;
}

/*
 * Suspend the target task.
 * Making/holding a token/reference/port is the callers responsibility.
 */
kern_return_t
task_suspend_internal(task_t task)
{
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	kr = place_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return kr;
}

/*
 * Suspend the target task, and return a suspension token. The token
 * represents a reference on the suspended task.
 */
static kern_return_t
task_suspend2_grp(
	task_t                  task,
	task_suspension_token_t *suspend_token,
	task_grp_t              grp)
{
	kern_return_t    kr;

	kr = task_suspend_internal(task);
	if (kr != KERN_SUCCESS) {
		*suspend_token = TASK_NULL;
		return kr;
	}

	/*
	 * Take a reference on the target task and return that to the caller
	 * as a "suspension token," which can be converted into an SO right to
	 * the now-suspended task's resume port.
	 */
	task_reference_grp(task, grp);
	*suspend_token = task;

	return KERN_SUCCESS;
}

kern_return_t
task_suspend2_mig(
	task_t                  task,
	task_suspension_token_t *suspend_token)
{
	return task_suspend2_grp(task, suspend_token, TASK_GRP_MIG);
}

kern_return_t
task_suspend2_external(
	task_t                  task,
	task_suspension_token_t *suspend_token)
{
	return task_suspend2_grp(task, suspend_token, TASK_GRP_EXTERNAL);
}

/*
 * Resume the task
 * (reference/token/port management is caller's responsibility).
 */
kern_return_t
task_resume_internal(
	task_suspension_token_t         task)
{
	kern_return_t kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	kr = release_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);
	return kr;
}

/*
 * Resume the task using a suspension token. Consumes the token's ref.
 */
static kern_return_t
task_resume2_grp(
	task_suspension_token_t         task,
	task_grp_t                      grp)
{
	kern_return_t kr;

	kr = task_resume_internal(task);
	task_suspension_token_deallocate_grp(task, grp);

	return kr;
}

kern_return_t
task_resume2_mig(
	task_suspension_token_t         task)
{
	return task_resume2_grp(task, TASK_GRP_MIG);
}

kern_return_t
task_resume2_external(
	task_suspension_token_t         task)
{
	return task_resume2_grp(task, TASK_GRP_EXTERNAL);
}

static void
task_suspension_no_senders(ipc_port_t port, mach_port_mscount_t mscount)
{
	task_t task = convert_port_to_task_suspension_token(port);

	assert(task != kernel_task);

	if (task == TASK_NULL) {
		return;
	}

	task_lock(task);

	if (ipc_kobject_is_mscount_current(port, mscount)) {
		/* release all the [remaining] outstanding legacy holds */
		release_task_hold(task, TASK_HOLD_LEGACY_ALL);
	}

	task_unlock(task);

	task_suspension_token_deallocate(task); /* drop token reference */
}

/*
 * Fires when a send once made
 * by convert_task_suspension_token_to_port() dies.
 */
void
task_suspension_send_once(ipc_port_t port)
{
	task_t task = convert_port_to_task_suspension_token(port);

	if (task == TASK_NULL || task == kernel_task) {
		return; /* nothing to do */
	}

	/* release the hold held by this specific send-once right */
	task_lock(task);
	release_task_hold(task, TASK_HOLD_NORMAL);
	task_unlock(task);

	task_suspension_token_deallocate(task);         /* drop token reference */
}

static kern_return_t
task_pidsuspend_locked(task_t task)
{
	kern_return_t kr;

	if (task->pidsuspended) {
		kr = KERN_FAILURE;
		goto out;
	}

	task->pidsuspended = TRUE;

	kr = place_task_hold(task, TASK_HOLD_PIDSUSPEND);
	if (kr != KERN_SUCCESS) {
		task->pidsuspended = FALSE;
	}
out:
	return kr;
}


/*
 *	task_pidsuspend:
 *
 *	Suspends a task by placing a hold on its threads.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
kern_return_t
task_pidsuspend(
	task_t          task)
{
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	kr = task_pidsuspend_locked(task);

	task_unlock(task);

	if ((KERN_SUCCESS == kr) && task->message_app_suspended) {
		iokit_task_app_suspended_changed(task);
		vm_deferred_reclamation_task_suspend(task);
	}

	return kr;
}

/*
 *	task_pidresume:
 *		Resumes a previously suspended task.
 *
 * Conditions:
 *		The caller holds a reference to the task
 */
kern_return_t
task_pidresume(
	task_t  task)
{
	kern_return_t    kr;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

#if CONFIG_FREEZE

	while (task->changing_freeze_state) {
		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	task->changing_freeze_state = TRUE;
#endif

	kr = release_task_hold(task, TASK_HOLD_PIDSUSPEND);

	task_unlock(task);

	if ((KERN_SUCCESS == kr) && task->message_app_suspended) {
		iokit_task_app_suspended_changed(task);
	}

#if CONFIG_FREEZE

	task_lock(task);

	if (kr == KERN_SUCCESS) {
		os_atomic_store(&task->frozen, FALSE, release);
	}
	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);

	task_unlock(task);
#endif

	return kr;
}

os_refgrp_decl(static, task_watchports_refgrp, "task_watchports", NULL);

/*
 *	task_add_turnstile_watchports:
 *		Setup watchports to boost the main thread of the task.
 *
 *	Arguments:
 *		task: task being spawned
 *		thread: main thread of task
 *		portwatch_ports: array of watchports
 *		portwatch_count: number of watchports
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_add_turnstile_watchports(
	task_t          task,
	thread_t        thread,
	ipc_port_t      *portwatch_ports,
	uint32_t        portwatch_count)
{
	struct task_watchports *watchports = NULL;
	struct task_watchport_elem *previous_elem_array[TASK_MAX_WATCHPORT_COUNT] = {};
	os_ref_count_t refs;

	/* Check if the task has terminated */
	if (!task->active) {
		return;
	}

	assert(portwatch_count <= TASK_MAX_WATCHPORT_COUNT);

	watchports = task_watchports_alloc_init(task, thread, portwatch_count);

	/* Lock the ipc space */
	is_write_lock(task->itk_space);

	/* Setup watchports to boost the main thread */
	refs = task_add_turnstile_watchports_locked(task,
	    watchports, previous_elem_array, portwatch_ports,
	    portwatch_count);

	/* Drop the space lock */
	is_write_unlock(task->itk_space);

	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}

	/* Drop the ref on previous_elem_array */
	for (uint32_t i = 0; i < portwatch_count && previous_elem_array[i] != NULL; i++) {
		task_watchport_elem_deallocate(previous_elem_array[i]);
	}
}

/*
 *	task_remove_turnstile_watchports:
 *		Clear all turnstile boost on the task from watchports.
 *
 *	Arguments:
 *		task: task being terminated
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_remove_turnstile_watchports(
	task_t          task)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;
	struct task_watchports *watchports = NULL;
	ipc_port_t port_freelist[TASK_MAX_WATCHPORT_COUNT] = {};
	uint32_t portwatch_count;

	/* Lock the ipc space */
	is_write_lock(task->itk_space);

	/* Check if watchport boost exist */
	if (task->watchports == NULL) {
		is_write_unlock(task->itk_space);
		return;
	}
	watchports = task->watchports;
	portwatch_count = watchports->tw_elem_array_count;

	refs = task_remove_turnstile_watchports_locked(task, watchports,
	    port_freelist);

	is_write_unlock(task->itk_space);

	/* Drop all the port references */
	for (uint32_t i = 0; i < portwatch_count && port_freelist[i] != NULL; i++) {
		ip_release(port_freelist[i]);
	}

	/* Clear the task and thread references for task_watchport */
	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}
}

/*
 *	task_transfer_turnstile_watchports:
 *		Transfer all watchport turnstile boost from old task to new task.
 *
 *	Arguments:
 *		old_task: task calling exec
 *		new_task: new exec'ed task
 *		thread: main thread of new task
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_transfer_turnstile_watchports(
	task_t   old_task,
	task_t   new_task,
	thread_t new_thread)
{
	struct task_watchports *old_watchports = NULL;
	struct task_watchports *new_watchports = NULL;
	os_ref_count_t old_refs = TASK_MAX_WATCHPORT_COUNT;
	os_ref_count_t new_refs = TASK_MAX_WATCHPORT_COUNT;
	uint32_t portwatch_count;

	if (old_task->watchports == NULL || !new_task->active) {
		return;
	}

	/* Get the watch port count from the old task */
	is_write_lock(old_task->itk_space);
	if (old_task->watchports == NULL) {
		is_write_unlock(old_task->itk_space);
		return;
	}

	portwatch_count = old_task->watchports->tw_elem_array_count;
	is_write_unlock(old_task->itk_space);

	new_watchports = task_watchports_alloc_init(new_task, new_thread, portwatch_count);

	/* Lock the ipc space for old task */
	is_write_lock(old_task->itk_space);

	/* Lock the ipc space for new task */
	is_write_lock(new_task->itk_space);

	/* Check if watchport boost exist */
	if (old_task->watchports == NULL || !new_task->active) {
		is_write_unlock(new_task->itk_space);
		is_write_unlock(old_task->itk_space);
		(void)task_watchports_release(new_watchports);
		task_watchports_deallocate(new_watchports);
		return;
	}

	old_watchports = old_task->watchports;
	assert(portwatch_count == old_task->watchports->tw_elem_array_count);

	/* Setup new task watchports */
	new_task->watchports = new_watchports;

	for (uint32_t i = 0; i < portwatch_count; i++) {
		ipc_port_t port = old_watchports->tw_elem[i].twe_port;

		if (port == NULL) {
			task_watchport_elem_clear(&new_watchports->tw_elem[i]);
			continue;
		}

		/* Lock the port and check if it has the entry */
		ip_mq_lock(port);

		task_watchport_elem_init(&new_watchports->tw_elem[i], new_task, port);

		if (ipc_port_replace_watchport_elem_conditional_locked(port,
		    &old_watchports->tw_elem[i], &new_watchports->tw_elem[i]) == KERN_SUCCESS) {
			task_watchport_elem_clear(&old_watchports->tw_elem[i]);

			task_watchports_retain(new_watchports);
			old_refs = task_watchports_release(old_watchports);

			/* Check if all ports are cleaned */
			if (old_refs == 0) {
				old_task->watchports = NULL;
			}
		} else {
			task_watchport_elem_clear(&new_watchports->tw_elem[i]);
		}
		/* port unlocked by ipc_port_replace_watchport_elem_conditional_locked */
	}

	/* Drop the reference on new task_watchports struct returned by task_watchports_alloc_init */
	new_refs = task_watchports_release(new_watchports);
	if (new_refs == 0) {
		new_task->watchports = NULL;
	}

	is_write_unlock(new_task->itk_space);
	is_write_unlock(old_task->itk_space);

	/* Clear the task and thread references for old_watchport */
	if (old_refs == 0) {
		task_watchports_deallocate(old_watchports);
	}

	/* Clear the task and thread references for new_watchport */
	if (new_refs == 0) {
		task_watchports_deallocate(new_watchports);
	}
}

/*
 *	task_add_turnstile_watchports_locked:
 *		Setup watchports to boost the main thread of the task.
 *
 *	Arguments:
 *		task: task to boost
 *		watchports: watchport structure to be attached to the task
 *		previous_elem_array: an array of old watchport_elem to be returned to caller
 *		portwatch_ports: array of watchports
 *		portwatch_count: number of watchports
 *
 *	Conditions:
 *		ipc space of the task locked.
 *		returns array of old watchport_elem in previous_elem_array
 */
static os_ref_count_t
task_add_turnstile_watchports_locked(
	task_t                      task,
	struct task_watchports      *watchports,
	struct task_watchport_elem  **previous_elem_array,
	ipc_port_t                  *portwatch_ports,
	uint32_t                    portwatch_count)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;

	/* Check if the task is still active */
	if (!task->active) {
		refs = task_watchports_release(watchports);
		return refs;
	}

	assert(task->watchports == NULL);
	task->watchports = watchports;

	for (uint32_t i = 0, j = 0; i < portwatch_count; i++) {
		ipc_port_t port = portwatch_ports[i];

		task_watchport_elem_init(&watchports->tw_elem[i], task, port);
		if (port == NULL) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			continue;
		}

		ip_mq_lock(port);

		/* Check if port is in valid state to be setup as watchport */
		if (ipc_port_add_watchport_elem_locked(port, &watchports->tw_elem[i],
		    &previous_elem_array[j]) != KERN_SUCCESS) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			continue;
		}
		/* port unlocked on return */

		ip_reference(port);
		task_watchports_retain(watchports);
		if (previous_elem_array[j] != NULL) {
			j++;
		}
	}

	/* Drop the reference on task_watchport struct returned by os_ref_init */
	refs = task_watchports_release(watchports);
	if (refs == 0) {
		task->watchports = NULL;
	}

	return refs;
}

/*
 *	task_remove_turnstile_watchports_locked:
 *		Clear all turnstile boost on the task from watchports.
 *
 *	Arguments:
 *		task: task to remove watchports from
 *		watchports: watchports structure for the task
 *		port_freelist: array of ports returned with ref to caller
 *
 *
 *	Conditions:
 *		ipc space of the task locked.
 *		array of ports with refs are returned in port_freelist
 */
static os_ref_count_t
task_remove_turnstile_watchports_locked(
	task_t                 task,
	struct task_watchports *watchports,
	ipc_port_t             *port_freelist)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;

	for (uint32_t i = 0, j = 0; i < watchports->tw_elem_array_count; i++) {
		ipc_port_t port = watchports->tw_elem[i].twe_port;
		if (port == NULL) {
			continue;
		}

		/* Lock the port and check if it has the entry */
		ip_mq_lock(port);
		if (ipc_port_clear_watchport_elem_internal_conditional_locked(port,
		    &watchports->tw_elem[i]) == KERN_SUCCESS) {
			task_watchport_elem_clear(&watchports->tw_elem[i]);
			port_freelist[j++] = port;
			refs = task_watchports_release(watchports);

			/* Check if all ports are cleaned */
			if (refs == 0) {
				task->watchports = NULL;
				break;
			}
		}
		/* mqueue and port unlocked by ipc_port_clear_watchport_elem_internal_conditional_locked */
	}
	return refs;
}

/*
 *	task_watchports_alloc_init:
 *		Allocate and initialize task watchport struct.
 *
 *	Conditions:
 *		Nothing locked.
 */
static struct task_watchports *
task_watchports_alloc_init(
	task_t        task,
	thread_t      thread,
	uint32_t      count)
{
	struct task_watchports *watchports = kalloc_type(struct task_watchports,
	    struct task_watchport_elem, count, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	task_reference(task);
	thread_reference(thread);
	watchports->tw_task = task;
	watchports->tw_thread = thread;
	watchports->tw_elem_array_count = count;
	os_ref_init(&watchports->tw_refcount, &task_watchports_refgrp);

	return watchports;
}

/*
 *	task_watchports_deallocate:
 *		Deallocate task watchport struct.
 *
 *	Conditions:
 *		Nothing locked.
 */
static void
task_watchports_deallocate(
	struct task_watchports *watchports)
{
	uint32_t portwatch_count = watchports->tw_elem_array_count;

	task_deallocate(watchports->tw_task);
	thread_deallocate(watchports->tw_thread);
	kfree_type(struct task_watchports, struct task_watchport_elem,
	    portwatch_count, watchports);
}

/*
 *	task_watchport_elem_deallocate:
 *		Deallocate task watchport element and release its ref on task_watchport.
 *
 *	Conditions:
 *		Nothing locked.
 */
void
task_watchport_elem_deallocate(
	struct task_watchport_elem *watchport_elem)
{
	os_ref_count_t refs = TASK_MAX_WATCHPORT_COUNT;
	task_t task = watchport_elem->twe_task;
	struct task_watchports *watchports = NULL;
	ipc_port_t port = NULL;

	assert(task != NULL);

	/* Take the space lock to modify the elememt */
	is_write_lock(task->itk_space);

	watchports = task->watchports;
	assert(watchports != NULL);

	port = watchport_elem->twe_port;
	assert(port != NULL);

	task_watchport_elem_clear(watchport_elem);
	refs = task_watchports_release(watchports);

	if (refs == 0) {
		task->watchports = NULL;
	}

	is_write_unlock(task->itk_space);

	ip_release(port);
	if (refs == 0) {
		task_watchports_deallocate(watchports);
	}
}

/*
 *	task_has_watchports:
 *		Return TRUE if task has watchport boosts.
 *
 *	Conditions:
 *		Nothing locked.
 */
boolean_t
task_has_watchports(task_t task)
{
	return task->watchports != NULL;
}

#if DEVELOPMENT || DEBUG

extern void IOSleep(int);

kern_return_t
task_disconnect_page_mappings(task_t task)
{
	int     n;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * this function is used to strip all of the mappings from
	 * the pmap for the specified task to force the task to
	 * re-fault all of the pages it is actively using... this
	 * allows us to approximate the true working set of the
	 * specified task.  We only engage if at least 1 of the
	 * threads in the task is runnable, but we want to continuously
	 * sweep (at least for a while - I've arbitrarily set the limit at
	 * 100 sweeps to be re-looked at as we gain experience) to get a better
	 * view into what areas within a page are being visited (as opposed to only
	 * seeing the first fault of a page after the task becomes
	 * runnable)...  in the future I may
	 * try to block until awakened by a thread in this task
	 * being made runnable, but for now we'll periodically poll from the
	 * user level debug tool driving the sysctl
	 */
	for (n = 0; n < 100; n++) {
		thread_t        thread;
		boolean_t       runnable;
		boolean_t       do_unnest;
		int             page_count;

		runnable = FALSE;
		do_unnest = FALSE;

		task_lock(task);

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if (thread->state & TH_RUN) {
				runnable = TRUE;
				break;
			}
		}
		if (n == 0) {
			task->task_disconnected_count++;
		}

		if (task->task_unnested == FALSE) {
			if (runnable == TRUE) {
				task->task_unnested = TRUE;
				do_unnest = TRUE;
			}
		}
		task_unlock(task);

		if (runnable == FALSE) {
			break;
		}

		KDBG_RELEASE((MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_TASK_PAGE_MAPPINGS)) | DBG_FUNC_START,
		    task, do_unnest, task->task_disconnected_count);

		page_count = vm_map_disconnect_page_mappings(task->map, do_unnest);

		KDBG_RELEASE((MACHDBG_CODE(DBG_MACH_WORKINGSET, VM_DISCONNECT_TASK_PAGE_MAPPINGS)) | DBG_FUNC_END,
		    task, page_count);

		if ((n % 5) == 4) {
			IOSleep(1);
		}
	}
	return KERN_SUCCESS;
}

#endif


#if CONFIG_FREEZE

/*
 *	task_freeze:
 *
 *	Freeze a task.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
extern struct freezer_context freezer_context_global;

kern_return_t
task_freeze(
	task_t    task,
	uint32_t           *purgeable_count,
	uint32_t           *wired_count,
	uint32_t           *clean_count,
	uint32_t           *dirty_count,
	uint32_t           dirty_budget,
	uint32_t           *shared_count,
	int                *freezer_error_code,
	int                 opts)
{
	kern_return_t kr = KERN_SUCCESS;
	bool eval_only = opts & FREEZE_EVAL_ONLY;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	while (task->changing_freeze_state) {
		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (task->frozen) {
		task_unlock(task);
		return KERN_FAILURE;
	}
	task->changing_freeze_state = TRUE;

	freezer_context_global.freezer_ctx_task = task;

	task_unlock(task);

#if CONFIG_DEFERRED_RECLAIM
	if (vm_deferred_reclamation_task_has_ring(task)) {
		kr = vm_deferred_reclamation_task_drain(task, RECLAIM_OPTIONS_NONE);
		if (kr != KERN_SUCCESS) {
			os_log_error(OS_LOG_DEFAULT, "Failed to drain reclamation ring prior to freezing (%d)\n", kr);
		}
	}
#endif /* CONFIG_DEFERRED_RECLAIM */

	kr = vm_map_freeze(task,
	    purgeable_count,
	    wired_count,
	    clean_count,
	    dirty_count,
	    dirty_budget,
	    shared_count,
	    freezer_error_code,
	    opts);

	task_lock(task);

	if ((kr == KERN_SUCCESS) && !eval_only) {
		os_atomic_store(&task->frozen, TRUE, release);

		freezer_context_global.freezer_ctx_task = NULL;
		freezer_context_global.freezer_ctx_uncompressed_pages = 0;

		if (VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
			/*
			 * reset the counter tracking the # of swapped compressed pages
			 * because we are now done with this freeze session and task.
			 */

			*dirty_count = (uint32_t) (freezer_context_global.freezer_ctx_swapped_bytes / PAGE_SIZE_64);         /*used to track pageouts*/
		}

		freezer_context_global.freezer_ctx_swapped_bytes = 0;
	}

	task->changing_freeze_state = FALSE;
	thread_wakeup(&task->changing_freeze_state);

	task_unlock(task);

	if (VM_CONFIG_COMPRESSOR_IS_PRESENT &&
	    (kr == KERN_SUCCESS) &&
	    !eval_only) {
		vm_wake_compactor_swapper();
		/*
		 * We do an explicit wakeup of the swapout thread here
		 * because the compact_and_swap routines don't have
		 * knowledge about these kind of "per-task packed c_segs"
		 * and so will not be evaluating whether we need to do
		 * a wakeup there.
		 */
		vm_swapout_wakeup();
	}

	return kr;
}

/*
 *	task_thaw:
 *
 *	Thaw a currently frozen task.
 *
 * Conditions:
 *      The caller holds a reference to the task
 */
kern_return_t
task_thaw(
	task_t          task)
{
	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	while (task->changing_freeze_state) {
		assert_wait((event_t)&task->changing_freeze_state, THREAD_UNINT);
		task_unlock(task);
		thread_block(THREAD_CONTINUE_NULL);

		task_lock(task);
	}
	if (!task->frozen) {
		task_unlock(task);
		return KERN_FAILURE;
	}
	os_atomic_store(&task->frozen, FALSE, release);

	task_unlock(task);

	return KERN_SUCCESS;
}

void
task_update_frozen_to_swap_acct(task_t task, int64_t amount, freezer_acct_op_t op)
{
	/*
	 * We don't assert that the task lock is held because we call this
	 * routine from the decompression path and we won't be holding the
	 * task lock. However, since we are in the context of the task we are
	 * safe.
	 * In the case of the task_freeze path, we call it from behind the task
	 * lock but we don't need to because we have a reference on the proc
	 * being frozen.
	 */

	assert(task);
	if (amount == 0) {
		return;
	}

	if (op == CREDIT_TO_SWAP) {
		ledger_credit(task->ledger, task_ledgers.frozen_to_swap, amount);
	} else if (op == DEBIT_FROM_SWAP) {
		ledger_debit(task->ledger, task_ledgers.frozen_to_swap, amount);
	} else {
		panic("task_update_frozen_to_swap_acct: Invalid ledger op");
	}
}
#endif /* CONFIG_FREEZE */

kern_return_t
task_set_security_tokens(
	task_t           task,
	security_token_t sec_token,
	audit_token_t    audit_token,
	host_priv_t      host_priv)
{
	ipc_port_t       host_port = IP_NULL;
	kern_return_t    kr;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);
	task_set_tokens(task, &sec_token, &audit_token);
	task_unlock(task);

	if (host_priv != HOST_PRIV_NULL) {
		kr = host_get_host_priv_port(host_priv, &host_port);
	} else {
		kr = host_get_host_port(host_priv_self(), &host_port);
	}
	assert(kr == KERN_SUCCESS);

	kr = task_set_special_port_internal(task, TASK_HOST_PORT, host_port);
	return kr;
}

kern_return_t
task_send_trace_memory(
	__unused task_t   target_task,
	__unused uint32_t pid,
	__unused uint64_t uniqueid)
{
	return KERN_INVALID_ARGUMENT;
}

/*
 * This routine was added, pretty much exclusively, for registering the
 * RPC glue vector for in-kernel short circuited tasks.  Rather than
 * removing it completely, I have only disabled that feature (which was
 * the only feature at the time).  It just appears that we are going to
 * want to add some user data to tasks in the future (i.e. bsd info,
 * task names, etc...), so I left it in the formal task interface.
 */
kern_return_t
task_set_info(
	task_t          task,
	task_flavor_t   flavor,
	__unused task_info_t    task_info_in,           /* pointer to IN array */
	__unused mach_msg_type_number_t task_info_count)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	switch (flavor) {
#if CONFIG_ATM
	case TASK_TRACE_MEMORY_INFO:
		return KERN_NOT_SUPPORTED;
#endif // CONFIG_ATM
	default:
		return KERN_INVALID_ARGUMENT;
	}
}

static void
_task_fill_times(task_t task, time_value_t *user_time, time_value_t *sys_time)
{
	clock_sec_t sec;
	clock_usec_t usec;

	struct recount_times_mach times = recount_task_terminated_times(task);
	absolutetime_to_microtime(times.rtm_user, &sec, &usec);
	user_time->seconds = (typeof(user_time->seconds))sec;
	user_time->microseconds = usec;
	absolutetime_to_microtime(times.rtm_system, &sec, &usec);
	sys_time->seconds = (typeof(sys_time->seconds))sec;
	sys_time->microseconds = usec;
}

int radar_20146450 = 1;
kern_return_t
task_info(
	task_t                  task,
	task_flavor_t           flavor,
	task_info_t             task_info_out,
	mach_msg_type_number_t  *task_info_count)
{
	kern_return_t error = KERN_SUCCESS;
	mach_msg_type_number_t  original_task_info_count;
	bool is_kernel_task = (task == kernel_task);

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	original_task_info_count = *task_info_count;
	task_lock(task);

	if (task != current_task() && !task->active) {
		task_unlock(task);
		return KERN_INVALID_ARGUMENT;
	}


	switch (flavor) {
	case TASK_BASIC_INFO_32:
	case TASK_BASIC2_INFO_32:
#if defined(__arm64__)
	case TASK_BASIC_INFO_64:
#endif
		{
			task_basic_info_32_t basic_info;
			ledger_amount_t      tmp;

			if (*task_info_count < TASK_BASIC_INFO_32_COUNT) {
				error = KERN_INVALID_ARGUMENT;
				break;
			}

			basic_info = (task_basic_info_32_t)task_info_out;

			basic_info->virtual_size = (typeof(basic_info->virtual_size))
			    vm_map_adjusted_size(is_kernel_task ? kernel_map : task->map);
			if (flavor == TASK_BASIC2_INFO_32) {
				/*
				 * The "BASIC2" flavor gets the maximum resident
				 * size instead of the current resident size...
				 */
				ledger_get_lifetime_max(task->ledger,
				    task_ledgers.phys_mem, LEO_SETTLE, &tmp);
			} else {
				ledger_get_balance(task->ledger,
				    task_ledgers.phys_mem, LEO_SETTLE, &tmp);
			}
			basic_info->resident_size = (natural_t) MIN((ledger_amount_t) UINT32_MAX, tmp);

			_task_fill_times(task, &basic_info->user_time,
			    &basic_info->system_time);

			basic_info->policy = is_kernel_task ? POLICY_RR : POLICY_TIMESHARE;
			basic_info->suspend_count = task->user_stop_count;

			*task_info_count = TASK_BASIC_INFO_32_COUNT;
			break;
		}

#if defined(__arm64__)
	case TASK_BASIC_INFO_64_2:
	{
		task_basic_info_64_2_t  basic_info;

		if (*task_info_count < TASK_BASIC_INFO_64_2_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		basic_info = (task_basic_info_64_2_t)task_info_out;

		basic_info->virtual_size  = vm_map_adjusted_size(is_kernel_task ?
		    kernel_map : task->map);
		ledger_get_balance(task->ledger, task_ledgers.phys_mem,
		    LEO_SETTLE, (ledger_amount_t *)&basic_info->resident_size);
		basic_info->policy = is_kernel_task ? POLICY_RR : POLICY_TIMESHARE;
		basic_info->suspend_count = task->user_stop_count;
		_task_fill_times(task, &basic_info->user_time,
		    &basic_info->system_time);

		*task_info_count = TASK_BASIC_INFO_64_2_COUNT;
		break;
	}

#else /* defined(__arm64__) */
	case TASK_BASIC_INFO_64:
	{
		task_basic_info_64_t basic_info;

		if (*task_info_count < TASK_BASIC_INFO_64_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		basic_info = (task_basic_info_64_t)task_info_out;

		basic_info->virtual_size = vm_map_adjusted_size(is_kernel_task ?
		    kernel_map : task->map);
		ledger_get_balance(task->ledger, task_ledgers.phys_mem,
		    LEO_SETTLE, (ledger_amount_t *)&basic_info->resident_size);
		basic_info->policy = is_kernel_task ? POLICY_RR : POLICY_TIMESHARE;
		basic_info->suspend_count = task->user_stop_count;
		_task_fill_times(task, &basic_info->user_time,
		    &basic_info->system_time);

		*task_info_count = TASK_BASIC_INFO_64_COUNT;
		break;
	}
#endif /* defined(__arm64__) */

	case MACH_TASK_BASIC_INFO:
	{
		mach_task_basic_info_t  basic_info;

		if (*task_info_count < MACH_TASK_BASIC_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		basic_info = (mach_task_basic_info_t)task_info_out;

		basic_info->virtual_size = vm_map_adjusted_size(is_kernel_task ?
		    kernel_map : task->map);
		ledger_get_balance(task->ledger, task_ledgers.phys_mem,
		    LEO_SETTLE, (ledger_amount_t *) &basic_info->resident_size);
		ledger_get_lifetime_max(task->ledger, task_ledgers.phys_mem,
		    LEO_NO_SETTLE, (ledger_amount_t *) &basic_info->resident_size_max);
		basic_info->policy = is_kernel_task ? POLICY_RR : POLICY_TIMESHARE;
		basic_info->suspend_count = task->user_stop_count;
		_task_fill_times(task, &basic_info->user_time,
		    &basic_info->system_time);

		*task_info_count = MACH_TASK_BASIC_INFO_COUNT;
		break;
	}

	case TASK_THREAD_TIMES_INFO:
	{
		task_thread_times_info_t times_info;
		thread_t                 thread;

		if (*task_info_count < TASK_THREAD_TIMES_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		times_info = (task_thread_times_info_t)task_info_out;
		times_info->user_time = (time_value_t){ 0 };
		times_info->system_time = (time_value_t){ 0 };

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			if ((thread->options & TH_OPT_IDLE_THREAD) == 0) {
				time_value_t user_time, system_time;

				thread_read_times(thread, &user_time, &system_time, NULL);
				time_value_add(&times_info->user_time, &user_time);
				time_value_add(&times_info->system_time, &system_time);
			}
		}

		*task_info_count = TASK_THREAD_TIMES_INFO_COUNT;
		break;
	}

	case TASK_ABSOLUTETIME_INFO:
	{
		task_absolutetime_info_t        info;

		if (*task_info_count < TASK_ABSOLUTETIME_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_absolutetime_info_t)task_info_out;

		struct recount_times_mach term_times =
		    recount_task_terminated_times(task);
		struct recount_times_mach total_times = recount_task_times(task);

		info->total_user = total_times.rtm_user;
		info->total_system = total_times.rtm_system;
		info->threads_user = total_times.rtm_user - term_times.rtm_user;
		info->threads_system += total_times.rtm_system - term_times.rtm_system;

		*task_info_count = TASK_ABSOLUTETIME_INFO_COUNT;
		break;
	}

	case TASK_DYLD_INFO:
	{
		task_dyld_info_t info;

		/*
		 * We added the format field to TASK_DYLD_INFO output.  For
		 * temporary backward compatibility, accept the fact that
		 * clients may ask for the old version - distinquished by the
		 * size of the expected result structure.
		 */
#define TASK_LEGACY_DYLD_INFO_COUNT \
	        offsetof(struct task_dyld_info, all_image_info_format)/sizeof(natural_t)

		if (*task_info_count < TASK_LEGACY_DYLD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_dyld_info_t)task_info_out;
		info->all_image_info_addr = task->all_image_info_addr;
		info->all_image_info_size = task->all_image_info_size;

		/* only set format on output for those expecting it */
		if (*task_info_count >= TASK_DYLD_INFO_COUNT) {
			info->all_image_info_format = task_has_64Bit_addr(task) ?
			    TASK_DYLD_ALL_IMAGE_INFO_64 :
			    TASK_DYLD_ALL_IMAGE_INFO_32;
			*task_info_count = TASK_DYLD_INFO_COUNT;
		} else {
			*task_info_count = TASK_LEGACY_DYLD_INFO_COUNT;
		}
		break;
	}

	case TASK_EXTMOD_INFO:
	{
		task_extmod_info_t info;
		void *p;

		if (*task_info_count < TASK_EXTMOD_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		info = (task_extmod_info_t)task_info_out;

		p = get_bsdtask_info(task);
		if (p) {
			proc_getexecutableuuid(p, info->task_uuid, sizeof(info->task_uuid));
		} else {
			bzero(info->task_uuid, sizeof(info->task_uuid));
		}
		info->extmod_statistics = task->extmod_statistics;
		*task_info_count = TASK_EXTMOD_INFO_COUNT;

		break;
	}

	case TASK_KERNELMEMORY_INFO:
	{
		task_kernelmemory_info_t        tkm_info;
		ledger_amount_t                 credit, debit;

		if (*task_info_count < TASK_KERNELMEMORY_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		tkm_info = (task_kernelmemory_info_t) task_info_out;
		tkm_info->total_palloc = 0;
		tkm_info->total_pfree = 0;
		tkm_info->total_salloc = 0;
		tkm_info->total_sfree = 0;

		ledger_tab_settle_all(&task_ledger_template);

		if (task == kernel_task) {
			/*
			 * All shared allocs/frees from other tasks count against
			 * the kernel private memory usage.  If we are looking up
			 * info for the kernel task, gather from everywhere.
			 */
			task_unlock(task);

			/* start by accounting for all the terminated tasks against the kernel */
			tkm_info->total_palloc = tasks_tkm_private.alloc + tasks_tkm_shared.alloc;
			tkm_info->total_pfree = tasks_tkm_private.free + tasks_tkm_shared.free;

			/* count all other task/thread shared alloc/free against the kernel */
			lck_mtx_lock(&tasks_threads_lock);

			/* XXX this really shouldn't be using the function parameter 'task' as a local var! */
			queue_iterate(&tasks, task, task_t, tasks) {
				if (task == kernel_task) {
					if (ledger_get_entries(task->ledger,
					    task_ledgers.tkm_private, LEO_NO_SETTLE,
					    &credit, &debit) == KERN_SUCCESS) {
						tkm_info->total_palloc += credit;
						tkm_info->total_pfree += debit;
					}
				}
				if (!ledger_get_entries(task->ledger,
				    task_ledgers.tkm_shared, LEO_NO_SETTLE,
				    &credit, &debit)) {
					tkm_info->total_palloc += credit;
					tkm_info->total_pfree += debit;
				}
			}
			lck_mtx_unlock(&tasks_threads_lock);
		} else {
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_private, LEO_NO_SETTLE,
			    &credit, &debit)) {
				tkm_info->total_palloc = credit;
				tkm_info->total_pfree = debit;
			}
			if (!ledger_get_entries(task->ledger,
			    task_ledgers.tkm_shared, LEO_NO_SETTLE,
			    &credit, &debit)) {
				tkm_info->total_salloc = credit;
				tkm_info->total_sfree = debit;
			}
			task_unlock(task);
		}

		*task_info_count = TASK_KERNELMEMORY_INFO_COUNT;
		return KERN_SUCCESS;
	}

	/* OBSOLETE */
	case TASK_SCHED_FIFO_INFO:
	{
		if (*task_info_count < POLICY_FIFO_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		error = KERN_INVALID_POLICY;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_RR_INFO:
	{
		policy_rr_base_t        rr_base;
		uint32_t quantum_time;
		uint64_t quantum_ns;

		if (*task_info_count < POLICY_RR_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		rr_base = (policy_rr_base_t) task_info_out;

		if (task != kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		rr_base->base_priority = task->priority;

		quantum_time = SCHED(initial_quantum_size)(THREAD_NULL);
		absolutetime_to_nanoseconds(quantum_time, &quantum_ns);

		rr_base->quantum = (uint32_t)(quantum_ns / 1000 / 1000);

		*task_info_count = POLICY_RR_BASE_COUNT;
		break;
	}

	/* OBSOLETE */
	case TASK_SCHED_TIMESHARE_INFO:
	{
		policy_timeshare_base_t ts_base;

		if (*task_info_count < POLICY_TIMESHARE_BASE_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		ts_base = (policy_timeshare_base_t) task_info_out;

		if (task == kernel_task) {
			error = KERN_INVALID_POLICY;
			break;
		}

		ts_base->base_priority = task->priority;

		*task_info_count = POLICY_TIMESHARE_BASE_COUNT;
		break;
	}

	case TASK_SECURITY_TOKEN:
	{
		security_token_t        *sec_token_p;

		if (*task_info_count < TASK_SECURITY_TOKEN_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		sec_token_p = (security_token_t *) task_info_out;

		task_get_sec_token(task, sec_token_p);

		*task_info_count = TASK_SECURITY_TOKEN_COUNT;
		break;
	}

	case TASK_AUDIT_TOKEN:
	{
		audit_token_t   *audit_token_p;

		if (*task_info_count < TASK_AUDIT_TOKEN_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		audit_token_p = (audit_token_t *) task_info_out;

		task_get_audit_token(task, audit_token_p);

		*task_info_count = TASK_AUDIT_TOKEN_COUNT;
		break;
	}

	case TASK_SCHED_INFO:
		error = KERN_INVALID_ARGUMENT;
		break;

	case TASK_EVENTS_INFO:
	{
		task_events_info_t      events_info;
		thread_t                thread;
		uint64_t                n_syscalls_mach, n_syscalls_unix, n_csw;

		if (*task_info_count < TASK_EVENTS_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		events_info = (task_events_info_t) task_info_out;


		events_info->faults = (int32_t) MIN(counter_load(&task->faults), INT32_MAX);
		events_info->pageins = (int32_t) MIN(counter_load(&task->pageins), INT32_MAX);
		events_info->cow_faults = (int32_t) MIN(counter_load(&task->cow_faults), INT32_MAX);
		events_info->messages_sent = (int32_t) MIN(counter_load(&task->messages_sent), INT32_MAX);
		events_info->messages_received = (int32_t) MIN(counter_load(&task->messages_received), INT32_MAX);

		n_syscalls_mach = task->syscalls_mach;
		n_syscalls_unix = task->syscalls_unix;
		n_csw = task->c_switch;

		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			n_csw           += thread->c_switch;
			n_syscalls_mach += thread->syscalls_mach;
			n_syscalls_unix += thread->syscalls_unix;
		}

		events_info->syscalls_mach = (int32_t) MIN(n_syscalls_mach, INT32_MAX);
		events_info->syscalls_unix = (int32_t) MIN(n_syscalls_unix, INT32_MAX);
		events_info->csw = (int32_t) MIN(n_csw, INT32_MAX);

		*task_info_count = TASK_EVENTS_INFO_COUNT;
		break;
	}
	case TASK_AFFINITY_TAG_INFO:
	{
		if (*task_info_count < TASK_AFFINITY_TAG_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		error = task_affinity_info(task, task_info_out, task_info_count);
		break;
	}
	case TASK_POWER_INFO:
	{
		if (*task_info_count < TASK_POWER_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		task_power_info_locked(task, (task_power_info_t)task_info_out, NULL, NULL, NULL);
		break;
	}

	case TASK_POWER_INFO_V2:
	{
		if (*task_info_count < TASK_POWER_INFO_V2_COUNT_OLD) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		task_power_info_v2_t tpiv2 = (task_power_info_v2_t) task_info_out;
		task_power_info_locked(task, &tpiv2->cpu_energy, &tpiv2->gpu_energy, tpiv2, NULL);
		break;
	}

	case TASK_VM_INFO:
	case TASK_VM_INFO_PURGEABLE:
	{
		task_vm_info_t          vm_info;
		vm_map_t                map;
		ledger_amount_t         tmp_amount;

		struct proc *p;
		uint32_t platform, sdk;

		vmlp_api_start(TASK_INFO); /* this is the only case that is relevant to the lock */

		p = current_proc();
		platform = proc_platform(p);
		sdk = proc_sdk(p);
		if (original_task_info_count > TASK_VM_INFO_COUNT) {
			/*
			 * Some iOS apps pass an incorrect value for
			 * task_info_count, expressed in number of bytes
			 * instead of number of "natural_t" elements, which
			 * can lead to binary compatibility issues (including
			 * stack corruption) when the data structure is
			 * expanded in the future.
			 * Let's make this potential issue visible by
			 * logging about it...
			 */
			if (!proc_is_simulated(p)) {
				os_log(OS_LOG_DEFAULT, "%s[%d] task_info: possibly invalid "
				    "task_info_count %d > TASK_VM_INFO_COUNT=%d on platform %d sdk "
				    "%d.%d.%d - please use TASK_VM_INFO_COUNT",
				    proc_name_address(p), proc_pid(p),
				    original_task_info_count, TASK_VM_INFO_COUNT,
				    platform, (sdk >> 16), ((sdk >> 8) & 0xff), (sdk & 0xff));
			}
			DTRACE_VM4(suspicious_task_vm_info_count,
			    mach_msg_type_number_t, original_task_info_count,
			    mach_msg_type_number_t, TASK_VM_INFO_COUNT,
			    uint32_t, platform,
			    uint32_t, sdk);
		}
#if __arm64__
		if (original_task_info_count > TASK_VM_INFO_REV2_COUNT &&
		    platform == PLATFORM_IOS &&
		    sdk != 0 &&
		    (sdk >> 16) <= 12) {
			/*
			 * Some iOS apps pass an incorrect value for
			 * task_info_count, expressed in number of bytes
			 * instead of number of "natural_t" elements.
			 * For the sake of backwards binary compatibility
			 * for apps built with an iOS12 or older SDK and using
			 * the "rev2" data structure, let's fix task_info_count
			 * for them, to avoid stomping past the actual end
			 * of their buffer.
			 */
#if DEVELOPMENT || DEBUG
			printf("%s:%d %d[%s] rdar://49484582 task_info_count %d -> %d "
			    "platform %d sdk %d.%d.%d\n", __FUNCTION__, __LINE__, proc_pid(p),
			    proc_name_address(p), original_task_info_count,
			    TASK_VM_INFO_REV2_COUNT, platform, (sdk >> 16),
			    ((sdk >> 8) & 0xff), (sdk & 0xff));
#endif /* DEVELOPMENT || DEBUG */
			DTRACE_VM4(workaround_task_vm_info_count,
			    mach_msg_type_number_t, original_task_info_count,
			    mach_msg_type_number_t, TASK_VM_INFO_REV2_COUNT,
			    uint32_t, platform,
			    uint32_t, sdk);
			original_task_info_count = TASK_VM_INFO_REV2_COUNT;
			*task_info_count = original_task_info_count;
		}
		if (original_task_info_count > TASK_VM_INFO_REV5_COUNT &&
		    platform == PLATFORM_IOS &&
		    sdk != 0 &&
		    (sdk >> 16) <= 15) {
			/*
			 * Some iOS apps pass an incorrect value for
			 * task_info_count, expressed in number of bytes
			 * instead of number of "natural_t" elements.
			 */
			printf("%s:%d %d[%s] task_info_count=%d > TASK_VM_INFO_COUNT=%d "
			    "platform %d sdk %d.%d.%d\n", __FUNCTION__, __LINE__, proc_pid(p),
			    proc_name_address(p), original_task_info_count,
			    TASK_VM_INFO_REV5_COUNT, platform, (sdk >> 16),
			    ((sdk >> 8) & 0xff), (sdk & 0xff));
			DTRACE_VM4(workaround_task_vm_info_count,
			    mach_msg_type_number_t, original_task_info_count,
			    mach_msg_type_number_t, TASK_VM_INFO_REV5_COUNT,
			    uint32_t, platform,
			    uint32_t, sdk);
#if DEVELOPMENT || DEBUG
			/*
			 * For the sake of internal builds livability,
			 * work around this user-space bug by capping the
			 * buffer's size to what it was with the iOS15 SDK.
			 */
			original_task_info_count = TASK_VM_INFO_REV5_COUNT;
			*task_info_count = original_task_info_count;
#endif /* DEVELOPMENT || DEBUG */
		}

		if (original_task_info_count > TASK_VM_INFO_REV7_COUNT &&
		    platform == PLATFORM_IOS &&
		    sdk != 0 &&
		    (sdk >> 16) == 17) {
			/*
			 * Some iOS apps still pass an incorrect value for
			 * task_info_count, expressed in number of bytes
			 * instead of number of "natural_t" elements.
			 */
			printf("%s:%d %d[%s] task_info_count=%d > TASK_VM_INFO_COUNT=%d "
			    "platform %d sdk %d.%d.%d\n", __FUNCTION__, __LINE__, proc_pid(p),
			    proc_name_address(p), original_task_info_count,
			    TASK_VM_INFO_REV7_COUNT, platform, (sdk >> 16),
			    ((sdk >> 8) & 0xff), (sdk & 0xff));
			DTRACE_VM4(workaround_task_vm_info_count,
			    mach_msg_type_number_t, original_task_info_count,
			    mach_msg_type_number_t, TASK_VM_INFO_REV6_COUNT,
			    uint32_t, platform,
			    uint32_t, sdk);
#if DEVELOPMENT || DEBUG
			/*
			 * For the sake of internal builds livability,
			 * work around this user-space bug by capping the
			 * buffer's size to what it was with the iOS15 and iOS16 SDKs.
			 */
			original_task_info_count = TASK_VM_INFO_REV6_COUNT;
			*task_info_count = original_task_info_count;
#endif /* DEVELOPMENT || DEBUG */
		}
#endif /* __arm64__ */

		if (*task_info_count < TASK_VM_INFO_REV0_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			vmlp_api_end(TASK_INFO, error);
			break;
		}

		vm_info = (task_vm_info_t)task_info_out;

		/*
		 * Do not hold both the task and map locks,
		 * so convert the task lock into a map reference,
		 * drop the task lock, then take the interlock on the map.
		 */
		if (is_kernel_task) {
			map = kernel_map;
			task_unlock(task);
			/* no reference */
		} else {
			map = task->map;
			vm_map_reference(map);
			task_unlock(task);
		}

		vm_map_ilk_lock(map);

		vmlp_range_event_all(map);

		vm_info->virtual_size = (typeof(vm_info->virtual_size))vm_map_adjusted_size(map);
		vm_info->region_count = map->hdr.nentries;
		vm_info->page_size = vm_map_page_size(map);

		if (original_task_info_count >= TASK_VM_INFO_REV2_COUNT) {
			vm_info->min_address = map->min_offset;
			vm_info->max_address = map->max_offset;
		}

		if (is_kernel_task) {
			/*
			 * We have recorded every info we needed from the map in this case.
			 * Drop the interlock early to limit contention on the kernel map.
			 */
			vm_map_ilk_unlock(map);
		}

		/*
		 * In the kernel task case we no longer hold the interlock and should
		 * not read map fields after this point.
		 * The userspace task case still has the interlock.
		 */

		ledger_tab_settle(&task_ledger_template, task->ledger);
		ledger_get_balance(task->ledger, task_ledgers.phys_mem,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->resident_size);
		ledger_get_lifetime_max(task->ledger, task_ledgers.phys_mem,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->resident_size_peak);

		vm_info->device = 0;
		vm_info->device_peak = 0;
		ledger_get_balance(task->ledger, task_ledgers.external,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->external);
		ledger_get_lifetime_max(task->ledger, task_ledgers.external,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->external_peak);
		ledger_get_balance(task->ledger, task_ledgers.internal,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->internal);
		ledger_get_lifetime_max(task->ledger, task_ledgers.internal,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->internal_peak);
		ledger_get_balance(task->ledger, task_ledgers.reusable,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->reusable);
		ledger_get_lifetime_max(task->ledger, task_ledgers.reusable,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->reusable_peak);
		ledger_get_balance(task->ledger, task_ledgers.internal_compressed,
		    LEO_NO_SETTLE, (ledger_amount_t*) &vm_info->compressed);
		ledger_get_lifetime_max(task->ledger, task_ledgers.internal_compressed,
		    LEO_NO_SETTLE, (ledger_amount_t*) &vm_info->compressed_peak);
		ledger_get_entries(task->ledger, task_ledgers.internal_compressed,
		    LEO_NO_SETTLE, (ledger_amount_t*) &vm_info->compressed_lifetime, &tmp_amount);
		ledger_get_balance(task->ledger, task_ledgers.neural_nofootprint_total,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->ledger_tag_neural_nofootprint_total);
		ledger_get_lifetime_max(task->ledger, task_ledgers.neural_nofootprint_total,
		    LEO_NO_SETTLE, (ledger_amount_t *) &vm_info->ledger_tag_neural_nofootprint_peak);

		vm_info->purgeable_volatile_pmap = 0;
		vm_info->purgeable_volatile_resident = 0;
		vm_info->purgeable_volatile_virtual = 0;

		*task_info_count = TASK_VM_INFO_REV0_COUNT;

		if (is_kernel_task) {
			/*
			 * We do not maintain the detailed stats for the
			 * kernel_pmap, so just count everything as
			 * "internal"...
			 */
			vm_info->internal = vm_info->resident_size;
			/*
			 * ... but since the memory held by the VM compressor
			 * in the kernel address space ought to be attributed
			 * to user-space tasks, we subtract it from "internal"
			 * to give memory reporting tools a more accurate idea
			 * of what the kernel itself is actually using, instead
			 * of making it look like the kernel is leaking memory
			 * when the system is under memory pressure.
			 */
			vm_info->internal -= (VM_PAGE_COMPRESSOR_COUNT *
			    PAGE_SIZE);
		} else {
			mach_vm_size_t  volatile_virtual_size;
			mach_vm_size_t  volatile_resident_size;
			mach_vm_size_t  volatile_compressed_size;
			mach_vm_size_t  volatile_pmap_size;
			mach_vm_size_t  volatile_compressed_pmap_size;
			kern_return_t   kr;

			if (flavor == TASK_VM_INFO_PURGEABLE) {
				kr = vm_map_query_volatile_and_iunlock(
					map,
					&volatile_virtual_size,
					&volatile_resident_size,
					&volatile_compressed_size,
					&volatile_pmap_size,
					&volatile_compressed_pmap_size);
				if (kr == KERN_SUCCESS) {
					vm_info->purgeable_volatile_pmap =
					    volatile_pmap_size;
					if (radar_20146450) {
						vm_info->compressed -=
						    volatile_compressed_pmap_size;
					}
					vm_info->purgeable_volatile_resident =
					    volatile_resident_size;
					vm_info->purgeable_volatile_virtual =
					    volatile_virtual_size;
				}
			} else {
				vm_map_ilk_unlock(map);
			}
		}

		/*
		 * Done with vm map things, the interlock was dropped in all paths
		 * above. Can drop the map reference, and take the task lock back.
		 *
		 * Re-validate that the task didn't die on us.
		 */
		if (!is_kernel_task) {
			vm_map_deallocate(map);
		}
		map = VM_MAP_NULL;

		task_lock(task);

		if ((task != current_task()) && (!task->active)) {
			error = KERN_INVALID_ARGUMENT;
			vmlp_api_end(TASK_INFO, error);
			break;
		}

		if (original_task_info_count >= TASK_VM_INFO_REV1_COUNT) {
			vm_info->phys_footprint =
			    (mach_vm_size_t) get_task_phys_footprint(task);
			*task_info_count = TASK_VM_INFO_REV1_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV2_COUNT) {
			/* data was captured above */
			*task_info_count = TASK_VM_INFO_REV2_COUNT;
		}

		if (original_task_info_count >= TASK_VM_INFO_REV3_COUNT) {
			ledger_get_lifetime_max(task->ledger,
			    task_ledgers.phys_footprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_phys_footprint_peak);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_nonvolatile,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_purgeable_nonvolatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_nonvolatile_compress,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_purgeable_novolatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_volatile,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_purgeable_volatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.purgeable_volatile_compress,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_purgeable_volatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_nonvolatile,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_network_nonvolatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_nonvolatile_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_network_nonvolatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_volatile,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_network_volatile);
			ledger_get_balance(task->ledger,
			    task_ledgers.network_volatile_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_network_volatile_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_footprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_media_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_footprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_media_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_nofootprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_media_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.media_nofootprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_media_nofootprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_footprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_graphics_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_footprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_graphics_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_nofootprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_graphics_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.graphics_nofootprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_graphics_nofootprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_footprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_footprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_footprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_footprint_compressed);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_nofootprint,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_nofootprint);
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_nofootprint_compressed,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_nofootprint_compressed);
			*task_info_count = TASK_VM_INFO_REV3_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV4_COUNT) {
			if (get_bsdtask_info(task)) {
				vm_info->limit_bytes_remaining =
				    memorystatus_available_memory_internal(get_bsdtask_info(task));
			} else {
				vm_info->limit_bytes_remaining = 0;
			}
			*task_info_count = TASK_VM_INFO_REV4_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV5_COUNT) {
			thread_t thread;
			uint64_t total = task->decompressions;
			queue_iterate(&task->threads, thread, thread_t, task_threads) {
				total += thread->decompressions;
			}
			vm_info->decompressions = (int32_t) MIN(total, INT32_MAX);
			*task_info_count = TASK_VM_INFO_REV5_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV6_COUNT) {
			ledger_get_balance(task->ledger, task_ledgers.swapins,
			    LEO_NO_SETTLE, &vm_info->ledger_swapins);
			*task_info_count = TASK_VM_INFO_REV6_COUNT;
		}
		if (original_task_info_count >= TASK_VM_INFO_REV7_COUNT) {
			ledger_get_balance(task->ledger,
			    task_ledgers.neural_nofootprint_total,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_nofootprint_total);
			ledger_get_lifetime_max(task->ledger,
			    task_ledgers.neural_nofootprint_total,
			    LEO_NO_SETTLE,
			    &vm_info->ledger_tag_neural_nofootprint_peak);
			*task_info_count = TASK_VM_INFO_REV7_COUNT;
		}

		vmlp_api_end(TASK_INFO, error);
		break;
	}

	case TASK_WAIT_STATE_INFO:
	{
		/*
		 * Deprecated flavor. Currently allowing some results until all users
		 * stop calling it. The results may not be accurate.
		 */
		task_wait_state_info_t  wait_state_info;
		uint64_t total_sfi_ledger_val = 0;

		if (*task_info_count < TASK_WAIT_STATE_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		wait_state_info = (task_wait_state_info_t) task_info_out;

		wait_state_info->total_wait_state_time = 0;
		bzero(wait_state_info->_reserved, sizeof(wait_state_info->_reserved));

#if CONFIG_SCHED_SFI
		int prev_lentry = -1;
		int64_t  val_credit, val_debit;

		for (sfi_class_id_t i = SFI_CLASS_UNSPECIFIED + 1; i < MAX_SFI_CLASS_ID; i++) {
			val_credit = 0;
			/*
			 * checking with prev_lentry != entry ensures adjacent classes
			 * which share the same ledger do not add wait times twice.
			 * Note: Use ledger() call to get data for each individual sfi class.
			 */
			if (prev_lentry != task_ledgers.sfi_wait_times[i] &&
			    KERN_SUCCESS == ledger_get_entries(task->ledger,
			    task_ledgers.sfi_wait_times[i], LEO_SETTLE,
			    &val_credit, &val_debit)) {
				total_sfi_ledger_val += val_credit;
			}
			prev_lentry = task_ledgers.sfi_wait_times[i];
		}

#endif /* CONFIG_SCHED_SFI */
		wait_state_info->total_wait_sfi_state_time = total_sfi_ledger_val;
		*task_info_count = TASK_WAIT_STATE_INFO_COUNT;

		break;
	}
	case TASK_VM_INFO_PURGEABLE_ACCOUNT:
	{
#if DEVELOPMENT || DEBUG
		pvm_account_info_t      acnt_info;

		if (*task_info_count < PVM_ACCOUNT_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		if (task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		acnt_info = (pvm_account_info_t) task_info_out;

		error = vm_purgeable_account(task, acnt_info);

		*task_info_count = PVM_ACCOUNT_INFO_COUNT;

		break;
#else /* DEVELOPMENT || DEBUG */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* DEVELOPMENT || DEBUG */
	}
	case TASK_FLAGS_INFO:
	{
		task_flags_info_t               flags_info;

		if (*task_info_count < TASK_FLAGS_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		flags_info = (task_flags_info_t)task_info_out;

		/* only publish the 64-bit flag of the task */
		flags_info->flags = task->t_flags & (TF_64B_ADDR | TF_64B_DATA);

		*task_info_count = TASK_FLAGS_INFO_COUNT;
		break;
	}

	case TASK_DEBUG_INFO_INTERNAL:
	{
#if DEVELOPMENT || DEBUG
		task_debug_info_internal_t dbg_info;
		ipc_space_t space = task->itk_space;
		if (*task_info_count < TASK_DEBUG_INFO_INTERNAL_COUNT) {
			error = KERN_NOT_SUPPORTED;
			break;
		}

		if (task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		dbg_info = (task_debug_info_internal_t) task_info_out;
		dbg_info->ipc_space_size = 0;

		if (space) {
			smr_ipc_enter();
			ipc_entry_table_t table = smr_entered_load(&space->is_table);
			if (table) {
				dbg_info->ipc_space_size =
				    ipc_entry_table_count(table);
			}
			smr_ipc_leave();
		}

		dbg_info->suspend_count = task->suspend_count;

		error = KERN_SUCCESS;
		*task_info_count = TASK_DEBUG_INFO_INTERNAL_COUNT;
		break;
#else /* DEVELOPMENT || DEBUG */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* DEVELOPMENT || DEBUG */
	}
	case TASK_SUSPEND_STATS_INFO:
	{
#if CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG)
		if (*task_info_count < TASK_SUSPEND_STATS_INFO_COUNT || task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		error = _task_get_suspend_stats_locked(task, (task_suspend_stats_t)task_info_out);
		*task_info_count = TASK_SUSPEND_STATS_INFO_COUNT;
		break;
#else /* CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG) */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG) */
	}
	case TASK_SUSPEND_SOURCES_INFO:
	{
#if CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG)
		if (*task_info_count < TASK_SUSPEND_SOURCES_INFO_COUNT || task_info_out == NULL) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		error = _task_get_suspend_sources_locked(task, (task_suspend_source_t)task_info_out);
		*task_info_count = TASK_SUSPEND_SOURCES_INFO_COUNT;
		break;
#else /* CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG) */
		error = KERN_NOT_SUPPORTED;
		break;
#endif /* CONFIG_TASK_SUSPEND_STATS && (DEVELOPMENT || DEBUG) */
	}
	case TASK_SECURITY_CONFIG_INFO:
	{
		task_security_config_info_t             security_config;

		if (*task_info_count < TASK_SECURITY_CONFIG_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		security_config = (task_security_config_info_t)task_info_out;
		security_config->config = (uint32_t)task->security_config.value;

		*task_info_count = TASK_SECURITY_CONFIG_INFO_COUNT;
		break;
	}
	case TASK_IPC_SPACE_POLICY_INFO:
	{
		task_ipc_space_policy_info_t             ipc_space_config;

		if (*task_info_count < TASK_IPC_SPACE_POLICY_INFO_COUNT) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		ipc_space_config = (task_ipc_space_policy_info_t)task_info_out;
		struct ipc_space *space = task->itk_space;
		if (space) {
			ipc_space_config->space_policy = (uint32_t)space->is_policy;
			*task_info_count = TASK_IPC_SPACE_POLICY_INFO_COUNT;
		}
		break;
	}
	default:
		error = KERN_INVALID_ARGUMENT;
	}

	task_unlock(task);
	return error;
}

/*
 * task_info_from_user
 *
 * When calling task_info from user space,
 * this function will be executed as mig server side
 * instead of calling directly into task_info.
 * This gives the possibility to perform more security
 * checks on task_port.
 *
 * In the case of TASK_DYLD_INFO, we require the more
 * privileged task_read_port not the less-privileged task_name_port.
 *
 */
kern_return_t
task_info_from_user(
	mach_port_t             task_port,
	task_flavor_t           flavor,
	task_info_t             task_info_out,
	mach_msg_type_number_t  *task_info_count)
{
	task_t task;
	kern_return_t ret;

	if (flavor == TASK_DYLD_INFO) {
		task = convert_port_to_task_read(task_port);
	} else {
		task = convert_port_to_task_name(task_port);
	}

	ret = task_info(task, flavor, task_info_out, task_info_count);

	task_deallocate(task);

	return ret;
}

/*
 * Routine: task_dyld_process_info_update_helper
 *
 * Release send rights in release_ports.
 *
 * If no active ports found in task's dyld notifier array, unset the magic value
 * in user space to indicate so.
 *
 * Condition:
 *      task's itk_lock is locked, and is unlocked upon return.
 *      Global g_dyldinfo_mtx is locked, and is unlocked upon return.
 */
void
task_dyld_process_info_update_helper(
	task_t                  task,
	size_t                  active_count,
	vm_map_address_t        magic_addr,    /* a userspace address */
	ipc_port_t             *release_ports,
	size_t                  release_count)
{
	void *notifiers_ptr = NULL;

	assert(release_count <= DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT);

	if (active_count == 0) {
		assert(task->itk_dyld_notify != NULL);
		notifiers_ptr = task->itk_dyld_notify;
		task->itk_dyld_notify = NULL;
		itk_unlock(task);

		kfree_type(ipc_port_t, DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT, notifiers_ptr);
		(void)copyoutmap_atomic32(task->map, MACH_PORT_NULL, magic_addr); /* unset magic */
	} else {
		itk_unlock(task);
		(void)copyoutmap_atomic32(task->map, (mach_port_name_t)DYLD_PROCESS_INFO_NOTIFY_MAGIC,
		    magic_addr);     /* reset magic */
	}

	lck_mtx_unlock(&g_dyldinfo_mtx);

	for (size_t i = 0; i < release_count; i++) {
		ipc_port_release_send(release_ports[i]);
	}
}

/*
 * Routine: task_dyld_process_info_notify_register
 *
 * Insert a send right to target task's itk_dyld_notify array. Allocate kernel
 * memory for the array if it's the first port to be registered. Also cleanup
 * any dead rights found in the array.
 *
 * Consumes sright if returns KERN_SUCCESS, otherwise MIG will destroy it.
 *
 * Args:
 *     task:   Target task for the registration.
 *     sright: A send right.
 *
 * Returns:
 *     KERN_SUCCESS: Registration succeeded.
 *     KERN_INVALID_TASK: task is invalid.
 *     KERN_INVALID_RIGHT: sright is invalid.
 *     KERN_DENIED: Security policy denied this call.
 *     KERN_RESOURCE_SHORTAGE: Kernel memory allocation failed.
 *     KERN_NO_SPACE: No available notifier port slot left for this task.
 *     KERN_RIGHT_EXISTS: The notifier port is already registered and active.
 *
 *     Other error code see task_info().
 *
 * See Also:
 *     task_dyld_process_info_notify_get_trap() in mach_kernelrpc.c
 */
kern_return_t
task_dyld_process_info_notify_register(
	task_t                  task,
	ipc_port_t              sright)
{
	struct task_dyld_info dyld_info;
	mach_msg_type_number_t info_count = TASK_DYLD_INFO_COUNT;
	ipc_port_t release_ports[DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
	uint32_t release_count = 0, active_count = 0;
	mach_vm_address_t ports_addr; /* a user space address */
	kern_return_t kr;
	boolean_t right_exists = false;
	ipc_port_t *notifiers_ptr = NULL;
	ipc_port_t *portp;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_TASK;
	}

	if (!ipc_can_stash_naked_send(sright)) {
		return KERN_INVALID_RIGHT;
	}

	if (!IP_VALID(sright)) {
		return KERN_INVALID_RIGHT;
	}

#if CONFIG_MACF
	if (mac_task_check_dyld_process_info_notify_register()) {
		return KERN_DENIED;
	}
#endif

	kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &info_count);
	if (kr) {
		return kr;
	}

	if (dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32) {
		ports_addr = (mach_vm_address_t)(dyld_info.all_image_info_addr +
		    offsetof(struct user32_dyld_all_image_infos, notifyMachPorts));
	} else {
		ports_addr = (mach_vm_address_t)(dyld_info.all_image_info_addr +
		    offsetof(struct user64_dyld_all_image_infos, notifyMachPorts));
	}

retry:
	if (task->itk_dyld_notify == NULL) {
		notifiers_ptr = kalloc_type(ipc_port_t,
		    DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT,
		    Z_WAITOK | Z_ZERO | Z_NOFAIL);
	}

	lck_mtx_lock(&g_dyldinfo_mtx);
	itk_lock(task);

	if (task->itk_dyld_notify == NULL) {
		if (notifiers_ptr == NULL) {
			itk_unlock(task);
			lck_mtx_unlock(&g_dyldinfo_mtx);
			goto retry;
		}
		task->itk_dyld_notify = notifiers_ptr;
		notifiers_ptr = NULL;
	}

	assert(task->itk_dyld_notify != NULL);
	/* First pass: clear dead names and check for duplicate registration */
	for (int slot = 0; slot < DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT; slot++) {
		portp = &task->itk_dyld_notify[slot];
		if (*portp != IPC_PORT_NULL && !ip_active(*portp)) {
			release_ports[release_count++] = *portp;
			*portp = IPC_PORT_NULL;
		} else if (*portp == sright) {
			/* the port is already registered and is active */
			right_exists = true;
		}

		if (*portp != IPC_PORT_NULL) {
			active_count++;
		}
	}

	if (right_exists) {
		/* skip second pass */
		kr = KERN_RIGHT_EXISTS;
		goto out;
	}

	/* Second pass: register the port */
	kr = KERN_NO_SPACE;
	for (int slot = 0; slot < DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT; slot++) {
		portp = &task->itk_dyld_notify[slot];
		if (*portp == IPC_PORT_NULL) {
			*portp = sright;
			active_count++;
			kr = KERN_SUCCESS;
			break;
		}
	}

out:
	assert(active_count > 0);

	task_dyld_process_info_update_helper(task, active_count,
	    (vm_map_address_t)ports_addr, release_ports, release_count);
	/* itk_lock, g_dyldinfo_mtx are unlocked upon return */

	kfree_type(ipc_port_t, DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT, notifiers_ptr);

	return kr;
}

/*
 * Routine: task_dyld_process_info_notify_deregister
 *
 * Remove a send right in target task's itk_dyld_notify array matching the receive
 * right name passed in. Deallocate kernel memory for the array if it's the last port to
 * be deregistered, or all ports have died. Also cleanup any dead rights found in the array.
 *
 * Does not consume any reference.
 *
 * Args:
 *     task: Target task for the deregistration.
 *     rcv_name: The name denoting the receive right in caller's space.
 *
 * Returns:
 *     KERN_SUCCESS: A matching entry found and degistration succeeded.
 *     KERN_INVALID_TASK: task is invalid.
 *     KERN_INVALID_NAME: name is invalid.
 *     KERN_DENIED: Security policy denied this call.
 *     KERN_FAILURE: A matching entry is not found.
 *     KERN_INVALID_RIGHT: The name passed in does not represent a valid rcv right.
 *
 *     Other error code see task_info().
 *
 * See Also:
 *     task_dyld_process_info_notify_get_trap() in mach_kernelrpc.c
 */
kern_return_t
task_dyld_process_info_notify_deregister(
	task_t                  task,
	mach_port_name_t        rcv_name)
{
	struct task_dyld_info dyld_info;
	mach_msg_type_number_t info_count = TASK_DYLD_INFO_COUNT;
	ipc_port_t release_ports[DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT];
	uint32_t release_count = 0, active_count = 0;
	boolean_t port_found = false;
	mach_vm_address_t ports_addr; /* a user space address */
	ipc_port_t sright;
	kern_return_t kr;
	ipc_port_t *portp;

	if (task == TASK_NULL || task == kernel_task) {
		return KERN_INVALID_TASK;
	}

	if (!MACH_PORT_VALID(rcv_name)) {
		return KERN_INVALID_NAME;
	}

#if CONFIG_MACF
	if (mac_task_check_dyld_process_info_notify_register()) {
		return KERN_DENIED;
	}
#endif

	kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &info_count);
	if (kr) {
		return kr;
	}

	if (dyld_info.all_image_info_format == TASK_DYLD_ALL_IMAGE_INFO_32) {
		ports_addr = (mach_vm_address_t)(dyld_info.all_image_info_addr +
		    offsetof(struct user32_dyld_all_image_infos, notifyMachPorts));
	} else {
		ports_addr = (mach_vm_address_t)(dyld_info.all_image_info_addr +
		    offsetof(struct user64_dyld_all_image_infos, notifyMachPorts));
	}

	kr = ipc_port_translate_receive(current_space(), rcv_name, &sright); /* does not produce port ref */
	if (kr) {
		return KERN_INVALID_RIGHT;
	}

	ip_reference(sright);
	ip_mq_unlock(sright);

	assert(sright != IPC_PORT_NULL);

	lck_mtx_lock(&g_dyldinfo_mtx);
	itk_lock(task);

	if (task->itk_dyld_notify == NULL) {
		itk_unlock(task);
		lck_mtx_unlock(&g_dyldinfo_mtx);
		ip_release(sright);
		return KERN_FAILURE;
	}

	for (int slot = 0; slot < DYLD_MAX_PROCESS_INFO_NOTIFY_COUNT; slot++) {
		portp = &task->itk_dyld_notify[slot];
		if (*portp == sright) {
			release_ports[release_count++] = *portp;
			*portp = IPC_PORT_NULL;
			port_found = true;
		} else if ((*portp != IPC_PORT_NULL && !ip_active(*portp))) {
			release_ports[release_count++] = *portp;
			*portp = IPC_PORT_NULL;
		}

		if (*portp != IPC_PORT_NULL) {
			active_count++;
		}
	}

	task_dyld_process_info_update_helper(task, active_count,
	    (vm_map_address_t)ports_addr, release_ports, release_count);
	/* itk_lock, g_dyldinfo_mtx are unlocked upon return */

	ip_release(sright);

	return port_found ? KERN_SUCCESS : KERN_FAILURE;
}

/*
 *	task_power_info
 *
 *	Returns power stats for the task.
 *	Note: Called with task locked.
 */
void
task_power_info_locked(
	task_t                        task,
	task_power_info_t             info,
	gpu_energy_data_t             ginfo,
	task_power_info_v2_t          infov2,
	struct task_power_info_extra *extra_info)
{
	thread_t                thread;
	ledger_amount_t         tmp;

	uint64_t                runnable_time_sum = 0;

	task_lock_assert_owned(task);

	ledger_tab_settle(&task_ledger_template, task->ledger);
	ledger_get_entries(task->ledger, task_ledgers.interrupt_wakeups,
	    LEO_NO_SETTLE, (ledger_amount_t *)&info->task_interrupt_wakeups, &tmp);
	ledger_get_entries(task->ledger, task_ledgers.platform_idle_wakeups,
	    LEO_NO_SETTLE, (ledger_amount_t *)&info->task_platform_idle_wakeups, &tmp);

	info->task_timer_wakeups_bin_1 = task->task_timer_wakeups_bin_1;
	info->task_timer_wakeups_bin_2 = task->task_timer_wakeups_bin_2;

	struct recount_usage usage = { 0 };
	struct recount_usage usage_perf = { 0 };
	recount_task_usage_cpu_kinds(task, &usage, &usage_perf, NULL);

	info->total_user = usage.ru_metrics[RCT_LVL_USER].rm_time_mach;
	info->total_system = recount_usage_system_time_mach(&usage);
	runnable_time_sum = task->total_runnable_time;

	if (ginfo) {
		ginfo->task_gpu_utilisation = task->task_gpu_ns;
	}

	if (infov2) {
		infov2->task_ptime = recount_usage_time_mach(&usage_perf);
		infov2->task_pset_switches = task->ps_switch;
#if CONFIG_PERVASIVE_ENERGY
		infov2->task_energy = usage.ru_energy_nj;
#endif /* CONFIG_PERVASIVE_ENERGY */
	}

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		spl_t x;

		if (thread->options & TH_OPT_IDLE_THREAD) {
			continue;
		}

		x = splsched();
		thread_lock(thread);

		info->task_timer_wakeups_bin_1 += thread->thread_timer_wakeups_bin_1;
		info->task_timer_wakeups_bin_2 += thread->thread_timer_wakeups_bin_2;

		if (infov2) {
			infov2->task_pset_switches += thread->ps_switch;
		}

		runnable_time_sum += timer_grab(&thread->runnable_timer);

		if (ginfo) {
			ginfo->task_gpu_utilisation += ml_gpu_stat(thread);
		}
		thread_unlock(thread);
		splx(x);
	}

	if (extra_info) {
		extra_info->runnable_time = runnable_time_sum;
#if CONFIG_PERVASIVE_CPI
		extra_info->cycles = recount_usage_cycles(&usage);
		extra_info->instructions = recount_usage_instructions(&usage);
		extra_info->pcycles = recount_usage_cycles(&usage_perf);
		extra_info->pinstructions = recount_usage_instructions(&usage_perf);
		extra_info->user_ptime = usage_perf.ru_metrics[RCT_LVL_USER].rm_time_mach;
		extra_info->system_ptime = recount_usage_system_time_mach(&usage_perf);
#endif // CONFIG_PERVASIVE_CPI
#if CONFIG_PERVASIVE_ENERGY
		extra_info->energy = usage.ru_energy_nj;
		extra_info->penergy = usage_perf.ru_energy_nj;
#endif // CONFIG_PERVASIVE_ENERGY
#if RECOUNT_SECURE_METRICS
		if (PE_i_can_has_debugger(NULL)) {
			extra_info->secure_time = usage.ru_metrics[RCT_LVL_SECURE].rm_time_mach;
			extra_info->secure_ptime = usage_perf.ru_metrics[RCT_LVL_SECURE].rm_time_mach;
		}
#endif // RECOUNT_SECURE_METRICS
	}
}

/*
 *	task_gpu_utilisation
 *
 *	Returns the total gpu time used by the all the threads of the task
 *  (both dead and alive)
 */
uint64_t
task_gpu_utilisation(
	task_t  task)
{
	uint64_t gpu_time = 0;
#if defined(__x86_64__)
	thread_t thread;

	task_lock(task);
	gpu_time += task->task_gpu_ns;

	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		spl_t x;
		x = splsched();
		thread_lock(thread);
		gpu_time += ml_gpu_stat(thread);
		thread_unlock(thread);
		splx(x);
	}

	task_unlock(task);
#else /* defined(__x86_64__) */
	/* silence compiler warning */
	(void)task;
#endif /* defined(__x86_64__) */
	return gpu_time;
}

/* This function updates the cpu time in the arrays for each
 * effective and requested QoS class
 */
void
task_update_cpu_time_qos_stats(
	task_t  task,
	uint64_t *eqos_stats,
	uint64_t *rqos_stats)
{
	if (!eqos_stats && !rqos_stats) {
		return;
	}

	task_lock(task);
	thread_t thread;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread->options & TH_OPT_IDLE_THREAD) {
			continue;
		}

		thread_update_qos_cpu_time(thread);
	}

	if (eqos_stats) {
		eqos_stats[THREAD_QOS_DEFAULT] += task->cpu_time_eqos_stats.cpu_time_qos_default;
		eqos_stats[THREAD_QOS_MAINTENANCE] += task->cpu_time_eqos_stats.cpu_time_qos_maintenance;
		eqos_stats[THREAD_QOS_BACKGROUND] += task->cpu_time_eqos_stats.cpu_time_qos_background;
		eqos_stats[THREAD_QOS_UTILITY] += task->cpu_time_eqos_stats.cpu_time_qos_utility;
		eqos_stats[THREAD_QOS_LEGACY] += task->cpu_time_eqos_stats.cpu_time_qos_legacy;
		eqos_stats[THREAD_QOS_USER_INITIATED] += task->cpu_time_eqos_stats.cpu_time_qos_user_initiated;
		eqos_stats[THREAD_QOS_USER_INTERACTIVE] += task->cpu_time_eqos_stats.cpu_time_qos_user_interactive;
	}

	if (rqos_stats) {
		rqos_stats[THREAD_QOS_DEFAULT] += task->cpu_time_rqos_stats.cpu_time_qos_default;
		rqos_stats[THREAD_QOS_MAINTENANCE] += task->cpu_time_rqos_stats.cpu_time_qos_maintenance;
		rqos_stats[THREAD_QOS_BACKGROUND] += task->cpu_time_rqos_stats.cpu_time_qos_background;
		rqos_stats[THREAD_QOS_UTILITY] += task->cpu_time_rqos_stats.cpu_time_qos_utility;
		rqos_stats[THREAD_QOS_LEGACY] += task->cpu_time_rqos_stats.cpu_time_qos_legacy;
		rqos_stats[THREAD_QOS_USER_INITIATED] += task->cpu_time_rqos_stats.cpu_time_qos_user_initiated;
		rqos_stats[THREAD_QOS_USER_INTERACTIVE] += task->cpu_time_rqos_stats.cpu_time_qos_user_interactive;
	}

	task_unlock(task);
}

kern_return_t
task_purgable_info(
	task_t                  task,
	task_purgable_info_t    *stats)
{
	if (task == TASK_NULL || stats == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	/* Take task reference */
	task_reference(task);
	vm_purgeable_stats((vm_purgeable_info_t)stats, task);
	/* Drop task reference */
	task_deallocate(task);
	return KERN_SUCCESS;
}

void
task_vtimer_set(
	task_t          task,
	integer_t       which)
{
	thread_t        thread;
	spl_t           x;

	task_lock(task);

	task->vtimers |= which;

	switch (which) {
	case TASK_VTIMER_USER:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			struct recount_times_mach times = recount_thread_times(thread);
			thread->vtimer_user_save = times.rtm_user;
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_PROF:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_prof_save = recount_thread_time_mach(thread);
			thread_unlock(thread);
			splx(x);
		}
		break;

	case TASK_VTIMER_RLIM:
		queue_iterate(&task->threads, thread, thread_t, task_threads) {
			x = splsched();
			thread_lock(thread);
			thread->vtimer_rlim_save = recount_thread_time_mach(thread);
			thread_unlock(thread);
			splx(x);
		}
		break;
	}

	task_unlock(task);
}

void
task_vtimer_clear(
	task_t          task,
	integer_t       which)
{
	task_lock(task);

	task->vtimers &= ~which;

	task_unlock(task);
}

void
task_vtimer_update(
	__unused
	task_t          task,
	integer_t       which,
	uint32_t        *microsecs)
{
	thread_t        thread = current_thread();
	uint32_t        tdelt = 0;
	clock_sec_t     secs = 0;
	uint64_t        tsum;

	assert(task == current_task());

	spl_t s = splsched();
	thread_lock(thread);

	if ((task->vtimers & which) != (uint32_t)which) {
		thread_unlock(thread);
		splx(s);
		return;
	}

	switch (which) {
	case TASK_VTIMER_USER:;
		struct recount_times_mach times = recount_thread_times(thread);
		tsum = times.rtm_user;
		tdelt = (uint32_t)(tsum - thread->vtimer_user_save);
		thread->vtimer_user_save = tsum;
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;

	case TASK_VTIMER_PROF:
		tsum = recount_current_thread_time_mach();
		tdelt = (uint32_t)(tsum - thread->vtimer_prof_save);
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		/* if the time delta is smaller than a usec, ignore */
		if (*microsecs != 0) {
			thread->vtimer_prof_save = tsum;
		}
		break;

	case TASK_VTIMER_RLIM:
		tsum = recount_current_thread_time_mach();
		tdelt = (uint32_t)(tsum - thread->vtimer_rlim_save);
		thread->vtimer_rlim_save = tsum;
		absolutetime_to_microtime(tdelt, &secs, microsecs);
		break;
	}

	thread_unlock(thread);
	splx(s);
}

uint64_t
get_task_dispatchqueue_offset(
	task_t          task)
{
	return task->dispatchqueue_offset;
}

void
task_synchronizer_destroy_all(task_t task)
{
	/*
	 *  Destroy owned semaphores
	 */
	semaphore_destroy_all(task);
}

/*
 * Install default (machine-dependent) initial thread state
 * on the task.  Subsequent thread creation will have this initial
 * state set on the thread by machine_thread_inherit_taskwide().
 * Flavors and structures are exactly the same as those to thread_set_state()
 */
kern_return_t
task_set_state(
	task_t task,
	int flavor,
	thread_state_t state,
	mach_msg_type_number_t state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

	ret = machine_task_set_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}

/*
 * Examine the default (machine-dependent) initial thread state
 * on the task, as set by task_set_state().  Flavors and structures
 * are exactly the same as those passed to thread_get_state().
 */
kern_return_t
task_get_state(
	task_t  task,
	int     flavor,
	thread_state_t state,
	mach_msg_type_number_t *state_count)
{
	kern_return_t ret;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return KERN_FAILURE;
	}

	ret = machine_task_get_state(task, flavor, state, state_count);

	task_unlock(task);
	return ret;
}


static kern_return_t __attribute__((noinline, not_tail_called))
PROC_VIOLATED_GUARD__SEND_EXC_GUARD(
	mach_exception_code_t code,
	mach_exception_subcode_t subcode,
	void *reason,
	boolean_t backtrace_only)
{
#ifdef MACH_BSD
	if (1 == proc_selfpid()) {
		return KERN_NOT_SUPPORTED;              // initproc is immune
	}
#endif
	mach_exception_data_type_t codes[EXCEPTION_CODE_MAX] = {
		[0] = code,
		[1] = subcode,
	};
	task_t task = current_task();
	kern_return_t kr;
	void *bsd_info = get_bsdtask_info(task);

	/* (See jetsam-related comments below) */

	proc_memstat_skip(bsd_info, TRUE);
	kr = task_enqueue_exception_with_corpse(task, EXC_GUARD, codes, 2, reason, backtrace_only);
	proc_memstat_skip(bsd_info, FALSE);
	return kr;
}

kern_return_t
task_violated_guard(
	mach_exception_code_t code,
	mach_exception_subcode_t subcode,
	void *reason,
	bool backtrace_only)
{
	return PROC_VIOLATED_GUARD__SEND_EXC_GUARD(code, subcode, reason, backtrace_only);
}


#if CONFIG_MEMORYSTATUS

bool
task_get_memlimit_is_active(task_t task)
{
	assert(task != NULL);

	return os_atomic_load(&task->memlimit_flags, relaxed) & TASK_MEMLIMIT_IS_ACTIVE;
}

void
task_set_memlimit_is_active(task_t task, bool memlimit_is_active)
{
	assert(task != NULL);

	if (memlimit_is_active) {
		os_atomic_or(&task->memlimit_flags, TASK_MEMLIMIT_IS_ACTIVE, relaxed);
	} else {
		os_atomic_andnot(&task->memlimit_flags, TASK_MEMLIMIT_IS_ACTIVE, relaxed);
	}
}

bool
task_get_memlimit_is_fatal(task_t task)
{
	assert(task != NULL);

	return os_atomic_load(&task->memlimit_flags, relaxed) & TASK_MEMLIMIT_IS_FATAL;
}

void
task_set_memlimit_is_fatal(task_t task, bool memlimit_is_fatal)
{
	assert(task != NULL);

	if (memlimit_is_fatal) {
		os_atomic_or(&task->memlimit_flags, TASK_MEMLIMIT_IS_FATAL, relaxed);
	} else {
		os_atomic_andnot(&task->memlimit_flags, TASK_MEMLIMIT_IS_FATAL, relaxed);
	}
}

uint64_t
task_get_dirty_start(task_t task)
{
	return task->memstat_dirty_start;
}

void
task_set_dirty_start(task_t task, uint64_t start)
{
	task_lock(task);
	task->memstat_dirty_start = start;
	task_unlock(task);
}

bool
task_set_exc_resource_bit(task_t task, bool memlimit_is_active)
{
	/*
	 * Sets the specified EXC_RESOURCE bit if not set already, and returns
	 * true if the bit was changed (i.e. it was 0 before).
	 */

	task_memlimit_flags_t memlimit_orig;
	task_memlimit_flags_t bit =
	    memlimit_is_active ?
	    TASK_MEMLIMIT_ACTIVE_EXC_RESOURCE :
	    TASK_MEMLIMIT_INACTIVE_EXC_RESOURCE;

	memlimit_orig = os_atomic_or_orig(&task->memlimit_flags, bit, acquire);

	return !(memlimit_orig & bit);
}

void
task_reset_triggered_exc_resource(task_t task, bool memlimit_is_active)
{
	task_memlimit_flags_t bit =
	    memlimit_is_active ?
	    TASK_MEMLIMIT_ACTIVE_EXC_RESOURCE :
	    TASK_MEMLIMIT_INACTIVE_EXC_RESOURCE;

	os_atomic_andnot(&task->memlimit_flags, bit, relaxed);
}

bool
task_get_jetsam_realtime_audio(task_t task)
{
	return task->task_jetsam_realtime_audio;
}

void
task_set_jetsam_realtime_audio(task_t task, bool realtime_audio)
{
	task_lock(task);
	task->task_jetsam_realtime_audio = realtime_audio;
	task_unlock(task);
}

#define HWM_USERCORE_MINSPACE 250 // free space (in MB) required *after* core file creation

void __attribute__((noinline))
PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND(int max_footprint_mb, send_exec_resource_options_t exception_options)
{
	task_t                                          task            = current_task();
	int                                                     pid         = 0;
	const char                                      *procname       = "unknown";
	const char                                      *reason         = "high watermark";
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
	boolean_t send_sync_exc_resource = FALSE;
	void *cur_bsd_info = get_bsdtask_info(current_task());
	int flavor = FLAVOR_HIGH_WATERMARK;

#ifdef MACH_BSD
	pid = proc_selfpid();

	if (pid == 1) {
		/*
		 * Cannot have ReportCrash analyzing
		 * a suspended initproc.
		 */
		return;
	}

	if (cur_bsd_info != NULL) {
		procname = proc_name_address(cur_bsd_info);
		send_sync_exc_resource = proc_send_synchronous_EXC_RESOURCE(cur_bsd_info);
	}
#endif
#if CONFIG_COREDUMP
	if (hwm_user_cores) {
		int                             error;
		uint64_t                starttime, end;
		clock_sec_t             secs = 0;
		uint32_t                microsecs = 0;

		starttime = mach_absolute_time();
		/*
		 * Trigger a coredump of this process. Don't proceed unless we know we won't
		 * be filling up the disk; and ignore the core size resource limit for this
		 * core file.
		 */
		if ((error = coredump(cur_bsd_info, HWM_USERCORE_MINSPACE, COREDUMP_IGNORE_ULIMIT)) != 0) {
			printf("couldn't take coredump of %s[%d]: %d\n", procname, pid, error);
		}
		/*
		 * coredump() leaves the task suspended.
		 */
		task_resume_internal(current_task());

		end = mach_absolute_time();
		absolutetime_to_microtime(end - starttime, &secs, &microsecs);
		printf("coredump of %s[%d] taken in %d secs %d microsecs\n",
		    proc_name_address(cur_bsd_info), pid, (int)secs, microsecs);
	}
#endif /* CONFIG_COREDUMP */

	if (disable_exc_resource) {
		printf("process %s[%d] crossed memory high watermark (%d MB); EXC_RESOURCE "
		    "suppressed by a boot-arg.\n", procname, pid, max_footprint_mb);
		return;
	}

	/*
	 * For the reason string, diagnostic limit is prioritized over fatal limit,
	 * but for the EXC_RESOURCE flavor it's the other way round.
	 */
	if (exception_options & EXC_RESOURCE_DIAGNOSTIC) {
		reason = "diagnostics limit";
		if (!(exception_options & EXC_RESOURCE_FATAL)) {
			flavor = FLAVOR_DIAG_MEMLIMIT;
		}
	} else if (exception_options & EXC_RESOURCE_CONCLAVE) {
		reason = "conclave limit";
		flavor = FLAVOR_CONCLAVE_LIMIT;
	}

	printf("process %s [%d] crossed memory %s (%d MB); EXC_RESOURCE "
	    "\n", procname, pid, reason, max_footprint_mb);

	/*
	 * A task that has triggered an EXC_RESOURCE, should not be
	 * jetsammed when the device is under memory pressure.  Here
	 * we set the P_MEMSTAT_SKIP flag so that the process
	 * will be skipped if the memorystatus_thread wakes up.
	 *
	 * This is a debugging aid to ensure we can get a corpse before
	 * the jetsam thread kills the process.
	 * Note that proc_memstat_skip is a no-op on release kernels.
	 */
	proc_memstat_skip(cur_bsd_info, TRUE);

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_MEMORY);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], flavor);
	EXC_RESOURCE_HWM_ENCODE_LIMIT(code[0], max_footprint_mb);
	if (exception_options & EXC_RESOURCE_IS_ACTIVE) {
		code[0] |= EXC_RESOURCE_HWM_ACTIVE_BIT;
	}

	/*
	 * Do not generate a corpse fork if the violation is a fatal one
	 * or the process wants synchronous EXC_RESOURCE exceptions.
	 */
	if ((exception_options & EXC_RESOURCE_FATAL) || send_sync_exc_resource || !exc_via_corpse_forking) {
		if (exception_options & EXC_RESOURCE_FATAL) {
			vm_map_set_corpse_source(task->map);
		}

		/* Do not send a EXC_RESOURCE if corpse_for_fatal_memkill is set */
		if (send_sync_exc_resource || !corpse_for_fatal_memkill) {
			/*
			 * Use the _internal_ variant so that no user-space
			 * process can resume our task from under us.
			 */
			task_suspend_internal(task);
			exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
			task_resume_internal(task);
		}
	} else {
		if (disable_exc_resource_during_audio && audio_active && task->task_jetsam_realtime_audio) {
			printf("process %s[%d] crossed memory high watermark (%d MB); EXC_RESOURCE "
			    "suppressed due to audio playback.\n", procname, pid, max_footprint_mb);
		} else {
			task_enqueue_exception_with_corpse(task, EXC_RESOURCE,
			    code, EXCEPTION_CODE_MAX, NULL, FALSE);
		}
	}

	/*
	 * After the EXC_RESOURCE has been handled, we must clear the
	 * P_MEMSTAT_SKIP flag so that the process can again be
	 * considered for jetsam if the memorystatus_thread wakes up.
	 */
	proc_memstat_skip(cur_bsd_info, FALSE);         /* clear the flag */
}
/*
 * Callback invoked when a task exceeds its physical footprint limit.
 */
static void
task_footprint_exceeded(ledger_warning_t warning, __unused const void *param0)
{
	ledger_amount_t enforced_limit_mb = 0;
	ledger_amount_t enforced_limit = 0;
#if CONFIG_DEFERRED_RECLAIM
	ledger_amount_t current_footprint;
#endif /* CONFIG_DEFERRED_RECLAIM */
	task_t task;
	bool is_active, is_fatal;
	bool is_warning = false;
#if DEBUG || DEVELOPMENT
	bool is_diag = false;
#endif /* DEBUG || DEVELOPMENT */


	/* Determine if this is the diag, warning, or regular limit */
	switch (warning) {
#if DEBUG || DEVELOPMENT
	case LEDGER_WARNING_LEVEL_DIAG:
		is_diag = true;
		OS_FALLTHROUGH;
#endif /* DEBUG || DEVELOPMENT */
	case LEDGER_WARNING_LEVEL_WARNING:
		is_warning = true;
		break;
	default:
		break;
	}

	task = current_task();

	/* Get the relevant limit value */
	task_lock(task);
#if DEBUG || DEVELOPMENT
	if (is_diag) {
		ledger_get_diag_mem_threshold(task->ledger, task_ledgers.phys_footprint, &enforced_limit);
	} else {
		ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &enforced_limit);
	}
#else /* DEBUG || DEVELOPMENT */
	ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &enforced_limit);
#endif /* !(DEBUG || DEVELOPMENT) */
	enforced_limit_mb = enforced_limit >> 20;
	is_active = task_get_memlimit_is_active(task);
	is_fatal = task_get_memlimit_is_fatal(task);
	task_unlock(task);

	/* If this is not a warning, try draining the reclaim ring first */
#if CONFIG_DEFERRED_RECLAIM
	if (!is_warning && vm_deferred_reclamation_task_has_ring(task)) {
		/*
		 * Task is enrolled in deferred reclamation.
		 * Do a reclaim to ensure it's really over its limit.
		 */
		vm_deferred_reclamation_task_drain(task, RECLAIM_OPTIONS_NONE);
		ledger_get_balance(task->ledger, task_ledgers.phys_footprint,
		    LEO_NO_SETTLE, &current_footprint);
		if (current_footprint < enforced_limit) {
			return;
		}
	}
#endif /* CONFIG_DEFERRED_RECLAIM */

	send_exec_resource_options_t exception_options = 0;

	/* If we can't encode the limit in EXC_RESOURCE, log a warning */
	if ((enforced_limit_mb & EXC_RESOURCE_HWM_LIMIT_MASK) != enforced_limit_mb) {
		os_log_error(OS_LOG_DEFAULT, "EXC_RESOURCE limit %d above maximum-encodable limit %d; logs may be inaccurate\n",
		    (int) enforced_limit_mb, (int) EXC_RESOURCE_HWM_LIMIT_MASK);
	}

	if (is_active) {
		exception_options |= EXC_RESOURCE_IS_ACTIVE;
	}

#if DEBUG || DEVELOPMENT
	if (is_diag) {
		exception_options |= EXC_RESOURCE_DIAGNOSTIC;
		PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND((int) enforced_limit_mb, exception_options);
		memorystatus_log_diag_threshold_exception((int) enforced_limit_mb);
		return;
	}
#endif /* DEBUG || DEVELOPMENT */

	if (is_fatal) {
		exception_options |= EXC_RESOURCE_FATAL;
	}

	if (!is_warning && task_set_exc_resource_bit(task, is_active)) {
		PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND((int) enforced_limit_mb, exception_options);
		memorystatus_log_exception((int) enforced_limit_mb, is_active, is_fatal);
	}

	memorystatus_on_ledger_footprint_exceeded(is_warning, is_active, is_fatal);
}

/*
 * Callback invoked when a task exceeds its conclave memory limit.
 */
static void
task_conclave_mem_limit_exceeded(ledger_warning_t warning, const void *param0)
{
#pragma unused(warning, param0)
	ledger_amount_t max_footprint = 0;
	ledger_amount_t max_footprint_mb = 0;
	task_t task = current_task();

	/* no warn level is ever set */
	assert(warning == LEDGER_WARNING_LEVEL_CRITICAL);

	ledger_get_limit(task->ledger, task_ledgers.conclave_mem, &max_footprint);
	max_footprint_mb = max_footprint >> 20;

	/*
	 * The conclave memory limit is always fatal.
	 * For the moment, we assume conclave memory isn't tied to process memory
	 * and so this doesn't participate in the once-per-process rule above.
	 */
	PROC_CROSSED_HIGH_WATERMARK__SEND_EXC_RESOURCE_AND_SUSPEND((int)max_footprint_mb,
	    EXC_RESOURCE_FATAL | EXC_RESOURCE_CONCLAVE);

	memorystatus_on_conclave_limit_exceeded((int)max_footprint_mb);
}

extern int proc_check_footprint_priv(void);

kern_return_t
task_set_phys_footprint_limit(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb)
{
	kern_return_t error;

	boolean_t memlimit_is_active;
	boolean_t memlimit_is_fatal;

	if ((error = proc_check_footprint_priv())) {
		return KERN_NO_ACCESS;
	}

	/*
	 * This call should probably be obsoleted.
	 * But for now, we default to current state.
	 */
	memlimit_is_active = task_get_memlimit_is_active(task);
	memlimit_is_fatal = task_get_memlimit_is_fatal(task);

	return task_set_phys_footprint_limit_internal(task, new_limit_mb, old_limit_mb, memlimit_is_active, memlimit_is_fatal);
}

/*
 * Set the limit of diagnostics memory consumption for a concrete task
 */
#if CONFIG_MEMORYSTATUS
#if DEVELOPMENT || DEBUG
kern_return_t
task_set_diag_footprint_limit(
	task_t task,
	uint64_t new_limit_mb,
	uint64_t *old_limit_mb)
{
	kern_return_t error;

	if ((error = proc_check_footprint_priv())) {
		return KERN_NO_ACCESS;
	}

	return task_set_diag_footprint_limit_internal(task, new_limit_mb, old_limit_mb);
}

#endif // DEVELOPMENT || DEBUG
#endif // CONFIG_MEMORYSTATUS

kern_return_t
task_convert_phys_footprint_limit(
	int limit_mb,
	int *converted_limit_mb)
{
	if (limit_mb == -1) {
		/*
		 * No limit
		 */
		if (max_task_footprint != 0) {
			*converted_limit_mb = (int)(max_task_footprint / 1024 / 1024);         /* bytes to MB */
		} else {
			*converted_limit_mb = (int)(LEDGER_LIMIT_INFINITY >> 20);
		}
	} else {
		/* nothing to convert */
		*converted_limit_mb = limit_mb;
	}
	return KERN_SUCCESS;
}

kern_return_t
task_set_phys_footprint_limit_internal(
	task_t task,
	int new_limit_mb,
	int *old_limit_mb,
	boolean_t memlimit_is_active,
	boolean_t memlimit_is_fatal)
{
	ledger_amount_t old;
	kern_return_t ret;
#if DEVELOPMENT || DEBUG
	diagthreshold_check_return diag_threshold_validity;
#endif
	ret = ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &old);
	if (ret != KERN_SUCCESS) {
		return ret;
	}
	/**
	 * Maybe we will need to re-enable the diag threshold, lets get the value
	 * and the current status
	 */
#if DEVELOPMENT || DEBUG
	diag_threshold_validity = task_check_memorythreshold_is_valid( task, new_limit_mb, false);
	/**
	 * If the footprint and diagnostics threshold are going to be same, lets disable the threshold
	 */
	if (diag_threshold_validity == THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED) {
		ledger_set_diag_mem_threshold_disabled(task->ledger, task_ledgers.phys_footprint);
	} else if (diag_threshold_validity == THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED) {
		ledger_set_diag_mem_threshold_enabled(task->ledger, task_ledgers.phys_footprint);
	}
#endif

	/*
	 * Check that limit >> 20 will not give an "unexpected" 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	assert(((old & 0xFFF0000000000000LL) == 0) || (old == LEDGER_LIMIT_INFINITY));

	if (old_limit_mb) {
		*old_limit_mb = (int)(old >> 20);
	}

	if (new_limit_mb == -1) {
		/*
		 * Caller wishes to remove the limit.
		 */
		ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
		    max_task_footprint ? max_task_footprint : LEDGER_LIMIT_INFINITY,
		    max_task_footprint ? (uint8_t)max_task_footprint_warning_level : 0);

		task_lock(task);
		task_set_memlimit_is_active(task, memlimit_is_active);
		task_set_memlimit_is_fatal(task, memlimit_is_fatal);
		task_unlock(task);
		/**
		 * If the diagnostics were disabled, and now we have a new limit, we have to re-enable it.
		 */
#if DEVELOPMENT || DEBUG
		if (diag_threshold_validity == THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED) {
			ledger_set_diag_mem_threshold_disabled(task->ledger, task_ledgers.phys_footprint);
		} else if (diag_threshold_validity == THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED) {
			ledger_set_diag_mem_threshold_enabled(task->ledger, task_ledgers.phys_footprint);
		}
	#endif
		return KERN_SUCCESS;
	}

#ifdef CONFIG_NOMONITORS
	return KERN_SUCCESS;
#endif /* CONFIG_NOMONITORS */

	task_lock(task);

	if ((memlimit_is_active == task_get_memlimit_is_active(task)) &&
	    (memlimit_is_fatal == task_get_memlimit_is_fatal(task)) &&
	    (((ledger_amount_t)new_limit_mb << 20) == old)) {
		/*
		 * memlimit state is not changing
		 */
		task_unlock(task);
		return KERN_SUCCESS;
	}

	task_set_memlimit_is_active(task, memlimit_is_active);
	task_set_memlimit_is_fatal(task, memlimit_is_fatal);

	ledger_set_limit(task->ledger, task_ledgers.phys_footprint,
	    (ledger_amount_t)new_limit_mb << 20, PHYS_FOOTPRINT_WARNING_LEVEL);

	if (task == current_task()) {
		ledger_check_new_balance(task->ledger, task_ledgers.phys_footprint);
	}

	task_unlock(task);
#if DEVELOPMENT || DEBUG
	if (diag_threshold_validity == THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED) {
		ledger_set_diag_mem_threshold_enabled(task->ledger, task_ledgers.phys_footprint);
	}
	#endif

	return KERN_SUCCESS;
}

#if RESETTABLE_DIAG_FOOTPRINT_LIMITS
kern_return_t
task_set_diag_footprint_limit_internal(
	task_t task,
	uint64_t new_limit_bytes,
	uint64_t *old_limit_bytes)
{
	ledger_amount_t old = 0;
	kern_return_t ret = KERN_SUCCESS;
	diagthreshold_check_return diag_threshold_validity;
	ret = ledger_get_diag_mem_threshold(task->ledger, task_ledgers.phys_footprint, &old);

	if (ret != KERN_SUCCESS) {
		return ret;
	}
	/**
	 * Maybe we will need to re-enable the diag threshold, lets get the value
	 * and the current status
	 */
	diag_threshold_validity = task_check_memorythreshold_is_valid( task, new_limit_bytes >> 20, true);
	/**
	 * If the footprint and diagnostics threshold are going to be same, lets disable the threshold
	 */
	if (diag_threshold_validity == THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED) {
		ledger_set_diag_mem_threshold_disabled(task->ledger, task_ledgers.phys_footprint);
	}

	/*
	 * Check that limit >> 20 will not give an "unexpected" 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	if (old_limit_bytes) {
		*old_limit_bytes = old;
	}

	if (new_limit_bytes == -1) {
		/*
		 * Caller wishes to remove the limit.
		 */
		ledger_set_diag_mem_threshold(task->ledger, task_ledgers.phys_footprint,
		    LEDGER_LIMIT_INFINITY);
		/*
		 * If the memory diagnostics flag was disabled, lets enable it again
		 */
		ledger_set_diag_mem_threshold_enabled(task->ledger, task_ledgers.phys_footprint);
		return KERN_SUCCESS;
	}

#ifdef CONFIG_NOMONITORS
	return KERN_SUCCESS;
#else

	task_lock(task);
	ledger_set_diag_mem_threshold(task->ledger, task_ledgers.phys_footprint,
	    (ledger_amount_t)new_limit_bytes );
	if (task == current_task()) {
		ledger_check_new_balance(task->ledger, task_ledgers.phys_footprint);
	}

	task_unlock(task);
	if (diag_threshold_validity == THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED) {
		ledger_set_diag_mem_threshold_disabled(task->ledger, task_ledgers.phys_footprint);
	} else if (diag_threshold_validity == THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED) {
		ledger_set_diag_mem_threshold_enabled(task->ledger, task_ledgers.phys_footprint);
	}

	return KERN_SUCCESS;
#endif /* CONFIG_NOMONITORS */
}

kern_return_t
task_get_diag_footprint_limit_internal(
	task_t task,
	uint64_t *new_limit_bytes,
	bool *threshold_disabled)
{
	ledger_amount_t ledger_limit;
	kern_return_t ret = KERN_SUCCESS;
	if (new_limit_bytes == NULL || threshold_disabled == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
	ret = ledger_get_diag_mem_threshold(task->ledger, task_ledgers.phys_footprint, &ledger_limit);
	if (ledger_limit == LEDGER_LIMIT_INFINITY) {
		ledger_limit = -1;
	}
	if (ret == KERN_SUCCESS) {
		*new_limit_bytes = ledger_limit;
		ret = ledger_is_diag_threshold_enabled(task->ledger, task_ledgers.phys_footprint, threshold_disabled);
	}
	return ret;
}
#endif /* RESETTABLE_DIAG_FOOTPRINT_LIMITS */


kern_return_t
task_get_phys_footprint_limit(
	task_t task,
	int *limit_mb)
{
	ledger_amount_t limit;
	kern_return_t ret;

	ret = ledger_get_limit(task->ledger, task_ledgers.phys_footprint, &limit);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/*
	 * Check that limit >> 20 will not give an "unexpected" signed, 32-bit
	 * result. There are, however, implicit assumptions that -1 mb limit
	 * equates to LEDGER_LIMIT_INFINITY.
	 */
	assert(((limit & 0xFFF0000000000000LL) == 0) || (limit == LEDGER_LIMIT_INFINITY));
	*limit_mb = (int)(limit >> 20);

	return KERN_SUCCESS;
}
#else /* CONFIG_MEMORYSTATUS */
kern_return_t
task_set_phys_footprint_limit(
	__unused task_t task,
	__unused int new_limit_mb,
	__unused int *old_limit_mb)
{
	return KERN_FAILURE;
}

kern_return_t
task_get_phys_footprint_limit(
	__unused task_t task,
	__unused int *limit_mb)
{
	return KERN_FAILURE;
}
#endif /* CONFIG_MEMORYSTATUS */

static void
task_fill_sec_token(uint64_t uids, uint64_t gids, security_token_t *out)
{
	out->val[0] = task_token_effective(uids);
	out->val[1] = task_token_effective(gids);
}

static void
task_fill_audit_token(const struct task_token_data *tokens,
    uint64_t uids, uint64_t gids, audit_token_t *out)
{
	out->val[0] = os_atomic_load(&tokens->tc_auid, relaxed);
	out->val[1] = task_token_effective(uids);
	out->val[2] = task_token_effective(gids);
	out->val[3] = task_token_real(uids);
	out->val[4] = task_token_real(gids);
	out->val[5] = os_atomic_load(&tokens->tc_pid, relaxed);
	out->val[6] = os_atomic_load(&tokens->tc_asid, relaxed);
	out->val[7] = os_atomic_load(&tokens->tc_pidversion, relaxed);
}

void
task_get_sec_token(task_t task, security_token_t *out)
{
	const struct task_token_data *tokens = task->task_tokens;
	uint64_t uids = os_atomic_load(&tokens->tc_uids, relaxed);
	uint64_t gids = os_atomic_load(&tokens->tc_gids, relaxed);

	task_fill_sec_token(uids, gids, out);
}

void
task_get_audit_token(task_t task, audit_token_t *out)
{
	const struct task_token_data *tokens = task->task_tokens;
	uint64_t uids = os_atomic_load(&tokens->tc_uids, relaxed);
	uint64_t gids = os_atomic_load(&tokens->tc_gids, relaxed);

	task_fill_audit_token(tokens, uids, gids, out);
}

void
task_get_tokens(task_t task, security_token_t *sec_out, audit_token_t *audit_out)
{
	const struct task_token_data *tokens = task->task_tokens;
	uint64_t uids = os_atomic_load(&tokens->tc_uids, relaxed);
	uint64_t gids = os_atomic_load(&tokens->tc_gids, relaxed);

	if (sec_out) {
		task_fill_sec_token(uids, gids, sec_out);
	}
	if (audit_out) {
		task_fill_audit_token(tokens, uids, gids, audit_out);
	}
}

void
task_set_tokens(task_t task, security_token_t *sec_token, audit_token_t *audit_token)
{
	struct task_token_data *tokens = task->task_tokens;

	task_lock_assert_owned(task);

	os_atomic_store(&tokens->tc_uids, task_token_pack(sec_token->val[0],
	    audit_token->val[3]), relaxed);
	os_atomic_store(&tokens->tc_gids, task_token_pack(sec_token->val[1],
	    audit_token->val[4]), relaxed);
	os_atomic_store(&tokens->tc_auid, audit_token->val[0], relaxed);
	os_atomic_store(&tokens->tc_asid, audit_token->val[6], relaxed);
	os_atomic_store(&tokens->tc_pid, audit_token->val[5], relaxed);
	os_atomic_store(&tokens->tc_pidversion, audit_token->val[7], relaxed);
}

boolean_t
task_is_privileged(task_t task)
{
	uint64_t uids = os_atomic_load(&task->task_tokens->tc_uids, relaxed);
	return task_token_effective(uids) == 0;
}

#ifdef CONFIG_MACF
uint8_t *
task_get_mach_trap_filter_mask(task_t task)
{
	return task_get_ro(task)->task_filters.mach_trap_filter_mask;
}

void
task_set_mach_trap_filter_mask(task_t task, uint8_t *mask)
{
	zalloc_ro_update_field(ZONE_ID_PROC_RO, task_get_ro(task),
	    task_filters.mach_trap_filter_mask, &mask);
}

uint8_t *
task_get_mach_kobj_filter_mask(task_t task)
{
	return task_get_ro(task)->task_filters.mach_kobj_filter_mask;
}

mach_vm_address_t
task_get_all_image_info_addr(task_t task)
{
	return task->all_image_info_addr;
}

void
task_set_mach_kobj_filter_mask(task_t task, uint8_t *mask)
{
	zalloc_ro_update_field(ZONE_ID_PROC_RO, task_get_ro(task),
	    task_filters.mach_kobj_filter_mask, &mask);
}

#endif /* CONFIG_MACF */

void
task_set_thread_limit(task_t task, uint16_t thread_limit)
{
	assert(task != kernel_task);
	if (thread_limit <= TASK_MAX_THREAD_LIMIT) {
		task_lock(task);
		task->task_thread_limit = thread_limit;
		task_unlock(task);
	}
}

kern_return_t
task_get_conclave_mem_limit(task_t task, uint64_t *conclave_limit)
{
	kern_return_t ret;
	ledger_amount_t max;

	ret = ledger_get_limit(task->ledger, task_ledgers.conclave_mem, &max);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	*conclave_limit = max;

	return KERN_SUCCESS;
}

kern_return_t
task_set_conclave_mem_limit_internal(task_t task, uint64_t conclave_limit)
{
	kern_return_t ret;
	task_lock(task);

	ret = ledger_set_limit(task->ledger, task_ledgers.conclave_mem,
	    (ledger_amount_t)conclave_limit << 20, 0);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	if (task == current_task()) {
		ledger_check_new_balance(task->ledger, task_ledgers.conclave_mem);
	}

	task_unlock(task);

	return KERN_SUCCESS;
}

#if CONFIG_PROC_RESOURCE_LIMITS
kern_return_t
task_set_port_space_limits(task_t task, uint32_t soft_limit, uint32_t hard_limit)
{
	return ipc_space_set_table_size_limits(task->itk_space, soft_limit, hard_limit);
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

#if XNU_TARGET_OS_OSX
boolean_t
task_has_system_version_compat_enabled(task_t task)
{
	boolean_t enabled = FALSE;

	task_lock(task);
	enabled = (task->t_flags & TF_SYS_VERSION_COMPAT);
	task_unlock(task);

	return enabled;
}

void
task_set_system_version_compat_enabled(task_t task, boolean_t enable_system_version_compat)
{
	assert(task == current_task());
	assert(task != kernel_task);

	task_lock(task);
	if (enable_system_version_compat) {
		task->t_flags |= TF_SYS_VERSION_COMPAT;
	} else {
		task->t_flags &= ~TF_SYS_VERSION_COMPAT;
	}
	task_unlock(task);
}
#endif /* XNU_TARGET_OS_OSX */

/*
 * We need to export some functions to other components that
 * are currently implemented in macros within the osfmk
 * component.  Just export them as functions of the same name.
 */
boolean_t
is_kerneltask(task_t t)
{
	if (t == kernel_task) {
		return TRUE;
	}

	return FALSE;
}

boolean_t
is_corpsefork(task_t t)
{
	return task_is_a_corpse_fork(t);
}

task_t
current_task_early(void)
{
	if (__improbable(startup_phase < STARTUP_SUB_EARLY_BOOT)) {
		if (current_thread()->t_tro == NULL) {
			return TASK_NULL;
		}
	}
	return get_threadtask(current_thread());
}

task_t
current_task(void)
{
	return get_threadtask(current_thread());
}

__mockable int
task_pid(task_t task)
{
	if (task) {
		return (int)os_atomic_load(&task->task_tokens->tc_pid, relaxed);
	}
	return -1;
}

#if __has_feature(ptrauth_calls)
/*
 * Get the shared region id and jop signing key for the task.
 * The function will allocate a kalloc buffer and return
 * it to caller, the caller needs to free it. This is used
 * for getting the information via task port.
 */
char *
task_get_vm_shared_region_id_and_jop_pid(task_t task, uint64_t *jop_pid)
{
	size_t len;
	char *shared_region_id = NULL;

	task_lock(task);
	if (task->shared_region_id == NULL) {
		task_unlock(task);
		return NULL;
	}
	len = strlen(task->shared_region_id) + 1;

	/* don't hold task lock while allocating */
	task_unlock(task);
	shared_region_id = kalloc_data(len, Z_WAITOK);
	task_lock(task);

	if (task->shared_region_id == NULL) {
		task_unlock(task);
		kfree_data(shared_region_id, len);
		return NULL;
	}
	assert(len == strlen(task->shared_region_id) + 1);         /* should never change */
	strlcpy(shared_region_id, task->shared_region_id, len);
	task_unlock(task);

	/* find key from its auth pager */
	if (jop_pid != NULL) {
		*jop_pid = shared_region_find_key(shared_region_id);
	}

	return shared_region_id;
}

/*
 * set the shared region id for a task
 */
void
task_set_shared_region_id(task_t task, char *id)
{
	char *old_id;

	task_lock(task);
	old_id = task->shared_region_id;
	task->shared_region_id = id;
	task->shared_region_auth_remapped = FALSE;
	task_unlock(task);

	/* free any pre-existing shared region id */
	if (old_id != NULL) {
		shared_region_key_dealloc(old_id);
		kfree_data(old_id, strlen(old_id) + 1);
	}
}
#endif /* __has_feature(ptrauth_calls) */

/*
 * This routine finds a thread in a task by its unique id
 * Returns a referenced thread or THREAD_NULL if the thread was not found
 *
 * TODO: This is super inefficient - it's an O(threads in task) list walk!
 *       We should make a tid hash, or transition all tid clients to thread ports
 *
 * Precondition: No locks held (will take task lock)
 */
thread_t
task_findtid(task_t task, uint64_t tid)
{
	thread_t self           = current_thread();
	thread_t found_thread   = THREAD_NULL;
	thread_t iter_thread    = THREAD_NULL;

	/* Short-circuit the lookup if we're looking up ourselves */
	if (tid == self->thread_id || tid == TID_NULL) {
		assert(get_threadtask(self) == task);

		thread_reference(self);

		return self;
	}

	task_lock(task);

	queue_iterate(&task->threads, iter_thread, thread_t, task_threads) {
		if (iter_thread->thread_id == tid) {
			found_thread = iter_thread;
			thread_reference(found_thread);
			break;
		}
	}

	task_unlock(task);

	return found_thread;
}

int
pid_from_task(task_t task)
{
	int pid = -1;
	void *bsd_info = get_bsdtask_info(task);

	if (bsd_info) {
		pid = proc_pid(bsd_info);
	} else {
		pid = task_pid(task);
	}

	return pid;
}

/*
 * Control the CPU usage monitor for a task.
 */
kern_return_t
task_cpu_usage_monitor_ctl(task_t task, uint32_t *flags)
{
	int error = KERN_SUCCESS;

	if (*flags & CPUMON_MAKE_FATAL) {
		task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_FATAL_CPUMON;
	} else {
		error = KERN_INVALID_ARGUMENT;
	}

	return error;
}

/*
 * Control the wakeups monitor for a task.
 */
kern_return_t
task_wakeups_monitor_ctl(task_t task, uint32_t *flags, int32_t *rate_hz)
{
	ledger_t ledger = task->ledger;

	task_lock(task);
	if (*flags & WAKEMON_GET_PARAMS) {
		ledger_amount_t limit;
		uint64_t                period;

		ledger_get_limit(ledger, task_ledgers.interrupt_wakeups, &limit);
		ledger_get_period(ledger, task_ledgers.interrupt_wakeups, &period);

		if (limit != LEDGER_LIMIT_INFINITY) {
			/*
			 * An active limit means the wakeups monitor is enabled.
			 */
			*rate_hz = (int32_t)(limit / (int64_t)(period / NSEC_PER_SEC));
			*flags = WAKEMON_ENABLE;
			if (task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON) {
				*flags |= WAKEMON_MAKE_FATAL;
			}
		} else {
			*flags = WAKEMON_DISABLE;
			*rate_hz = -1;
		}

		/*
		 * If WAKEMON_GET_PARAMS is present in flags, all other flags are ignored.
		 */
		task_unlock(task);
		return KERN_SUCCESS;
	}

	if (*flags & WAKEMON_ENABLE) {
		if (*flags & WAKEMON_SET_DEFAULTS) {
			*rate_hz = task_wakeups_monitor_rate;
		}

#ifndef CONFIG_NOMONITORS
		if (*flags & WAKEMON_MAKE_FATAL) {
			task->rusage_cpu_flags |= TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON;
		}
#endif /* CONFIG_NOMONITORS */

		if (*rate_hz <= 0) {
			task_unlock(task);
			return KERN_INVALID_ARGUMENT;
		}

#ifndef CONFIG_NOMONITORS
		ledger_set_limit(ledger, task_ledgers.interrupt_wakeups, *rate_hz * task_wakeups_monitor_interval, 0);
		ledger_set_period(ledger, task_ledgers.interrupt_wakeups, task_wakeups_monitor_interval * NSEC_PER_SEC);
		ledger_enable_callback(ledger, task_ledgers.interrupt_wakeups);
#endif /* CONFIG_NOMONITORS */
	} else if (*flags & WAKEMON_DISABLE) {
		/*
		 * Caller wishes to disable wakeups monitor on the task.
		 *
		 * Remove the limit & callback on the wakeups ledger entry.
		 */
		ledger_disable_refill(ledger, task_ledgers.interrupt_wakeups);
		ledger_disable_callback(ledger, task_ledgers.interrupt_wakeups);
	}

	task_unlock(task);
	return KERN_SUCCESS;
}

TUNABLE(bool, enable_wakeup_reports, "enable_wakeup_reports", false); /* Enable wakeup reports. */

static void
task_wakeups_rate_exceeded(ledger_warning_t warning, const void *param0)
{
#pragma unused(warning, param0)
	task_t                      task        = current_task();
	int                         pid         = 0;
	const char                  *procname   = "unknown";
	boolean_t                   fatal;
	kern_return_t               kr;
#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t  code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info    lei;

	/* we never set a warning percentage */
	assert(warning == LEDGER_WARNING_LEVEL_CRITICAL);

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (get_bsdtask_info(task) != NULL) {
		procname = proc_name_address(get_bsdtask_info(current_task()));
	}
#endif

	ledger_get_entry_info(task->ledger, task_ledgers.interrupt_wakeups, &lei);

	/*
	 * Disable the exception notification so we don't overwhelm
	 * the listener with an endless stream of redundant exceptions.
	 * TODO: detect whether another thread is already reporting the violation.
	 */
	uint32_t flags = WAKEMON_DISABLE;
	task_wakeups_monitor_ctl(task, &flags, NULL);

	fatal = task->rusage_cpu_flags & TASK_RUSECPU_FLAGS_FATAL_WAKEUPSMON;
	trace_resource_violation(RMON_CPUWAKES_VIOLATED, &lei);
	os_log(OS_LOG_DEFAULT, "process %s[%d] caught waking the CPU %llu times "
	    "over ~%llu seconds, averaging %llu wakes / second and "
	    "violating a %slimit of %llu wakes over %llu seconds.\n",
	    procname, pid,
	    lei.lei_balance, lei.lei_last_refill / NSEC_PER_SEC,
	    lei.lei_last_refill == 0 ? 0 :
	    (NSEC_PER_SEC * lei.lei_balance / lei.lei_last_refill),
	    fatal ? "FATAL " : "",
	    lei.lei_limit, lei.lei_refill_period / NSEC_PER_SEC);

	if (enable_wakeup_reports) {
		kr = send_resource_violation(send_cpu_wakes_violation, task, &lei,
		    fatal ? kRNFatalLimitFlag : 0);
		if (kr) {
			printf("send_resource_violation(CPU wakes, ...): error %#x\n", kr);
		}
	}

#ifdef EXC_RESOURCE_MONITORS
	if (disable_exc_resource) {
		printf("process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "suppressed by a boot-arg\n", procname, pid);
		return;
	}
	if (disable_exc_resource_during_audio && audio_active && task->task_jetsam_realtime_audio) {
		os_log(OS_LOG_DEFAULT, "process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "suppressed due to audio playback\n", procname, pid);
		return;
	}
	if (lei.lei_last_refill == 0) {
		os_log(OS_LOG_DEFAULT, "process %s[%d] caught causing excessive wakeups. EXC_RESOURCE "
		    "suppressed due to lei.lei_last_refill = 0 \n", procname, pid);
	}

	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_WAKEUPS);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_WAKEUPS_MONITOR);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_PERMITTED(code[0],
	    NSEC_PER_SEC * lei.lei_limit / lei.lei_refill_period);
	EXC_RESOURCE_CPUMONITOR_ENCODE_OBSERVATION_INTERVAL(code[0],
	    lei.lei_last_refill);
	EXC_RESOURCE_CPUMONITOR_ENCODE_WAKEUPS_OBSERVED(code[1],
	    NSEC_PER_SEC * lei.lei_balance / lei.lei_last_refill);
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
#endif /* EXC_RESOURCE_MONITORS */

	if (fatal) {
		task_terminate_internal(task);
	}
}

static boolean_t
global_update_logical_writes(int64_t io_delta, int64_t *global_write_count)
{
	int64_t old_count, new_count;
	boolean_t needs_telemetry;

	do {
		new_count = old_count = *global_write_count;
		new_count += io_delta;
		if (new_count >= io_telemetry_limit) {
			new_count = 0;
			needs_telemetry = TRUE;
		} else {
			needs_telemetry = FALSE;
		}
	} while (!OSCompareAndSwap64(old_count, new_count, global_write_count));
	return needs_telemetry;
}

void
task_update_physical_writes(__unused task_t task, __unused task_physical_write_flavor_t flavor, __unused uint64_t io_size, __unused task_balance_flags_t flags)
{
#if CONFIG_PHYS_WRITE_ACCT
	if (!io_size) {
		return;
	}

	/*
	 * task == NULL means that we have to update kernel_task ledgers
	 */
	if (!task) {
		task = kernel_task;
	}

	KDBG((VMDBG_CODE(DBG_VM_PHYS_WRITE_ACCT)) | DBG_FUNC_NONE,
	    task_pid(task), flavor, io_size, flags);
	DTRACE_IO4(physical_writes, struct task *, task, task_physical_write_flavor_t, flavor, uint64_t, io_size, task_balance_flags_t, flags);

	if (flags & TASK_BALANCE_CREDIT) {
		if (flavor == TASK_PHYSICAL_WRITE_METADATA) {
			OSAddAtomic64(io_size, (SInt64 *)&(task->task_fs_metadata_writes));
			ledger_credit(task->ledger, task_ledgers.fs_metadata_writes, io_size);
		}
	} else if (flags & TASK_BALANCE_DEBIT) {
		if (flavor == TASK_PHYSICAL_WRITE_METADATA) {
			OSAddAtomic64(-1 * io_size, (SInt64 *)&(task->task_fs_metadata_writes));
			ledger_debit(task->ledger, task_ledgers.fs_metadata_writes, io_size);
		}
	}
#endif /* CONFIG_PHYS_WRITE_ACCT */
}

void
task_update_logical_writes(task_t task, uint32_t io_size, int flags, void *vp)
{
	int64_t io_delta = 0;
	int64_t * global_counter_to_update;
	boolean_t needs_telemetry = FALSE;
	boolean_t is_external_device = FALSE;
	int ledger_to_update = 0;
	struct task_writes_counters * writes_counters_to_update;

	if ((!task) || (!io_size) || (!vp)) {
		return;
	}

	KDBG((VMDBG_CODE(DBG_VM_DATA_WRITE)) | DBG_FUNC_NONE,
	    task_pid(task), io_size, flags, (uintptr_t)VM_KERNEL_ADDRPERM(vp));
	DTRACE_IO4(logical_writes, struct task *, task, uint32_t, io_size, int, flags, vnode *, vp);

	// Is the drive backing this vnode internal or external to the system?
	if (vnode_isonexternalstorage(vp) == false) {
		global_counter_to_update = &global_logical_writes_count;
		ledger_to_update = task_ledgers.logical_writes;
		writes_counters_to_update = &task->task_writes_counters_internal;
		is_external_device = FALSE;
	} else {
		global_counter_to_update = &global_logical_writes_to_external_count;
		ledger_to_update = task_ledgers.logical_writes_to_external;
		writes_counters_to_update = &task->task_writes_counters_external;
		is_external_device = TRUE;
	}

	switch (flags) {
	case TASK_WRITE_IMMEDIATE:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_immediate_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	case TASK_WRITE_DEFERRED:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_deferred_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	case TASK_WRITE_INVALIDATED:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_invalidated_writes));
		ledger_debit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, FALSE, io_size);
		}
		break;
	case TASK_WRITE_METADATA:
		OSAddAtomic64(io_size, (SInt64 *)&(writes_counters_to_update->task_metadata_writes));
		ledger_credit(task->ledger, ledger_to_update, io_size);
		if (!is_external_device) {
			coalition_io_ledger_update(task, FLAVOR_IO_LOGICAL_WRITES, TRUE, io_size);
		}
		break;
	}

	io_delta = (flags == TASK_WRITE_INVALIDATED) ? ((int64_t)io_size * -1ll) : ((int64_t)io_size);
	if (io_telemetry_limit != 0) {
		/* If io_telemetry_limit is 0, disable global updates and I/O telemetry */
		needs_telemetry = global_update_logical_writes(io_delta, global_counter_to_update);
		if (needs_telemetry && !is_external_device) {
			act_set_telemetry_ast(current_thread(), TELEMETRY_AST_IO);
		}
	}
}

/*
 * Control the I/O monitor for a task.
 */
kern_return_t
task_io_monitor_ctl(task_t task, uint32_t *flags)
{
	ledger_t ledger = task->ledger;

	task_lock(task);
	if (*flags & IOMON_ENABLE) {
		/* Configure the physical I/O ledger */
		ledger_set_limit(ledger, task_ledgers.physical_writes, (task_iomon_limit_mb * 1024 * 1024), 0);
		ledger_set_period(ledger, task_ledgers.physical_writes, (task_iomon_interval_secs * NSEC_PER_SEC));
	} else if (*flags & IOMON_DISABLE) {
		/*
		 * Caller wishes to disable I/O monitor on the task.
		 */
		ledger_disable_refill(ledger, task_ledgers.physical_writes);
		ledger_disable_callback(ledger, task_ledgers.physical_writes);
	}

	task_unlock(task);
	return KERN_SUCCESS;
}

static void
task_io_rate_exceeded(ledger_warning_t warning __unused, const void *param0)
{
	int                             pid = 0;
	long                            flavor = (long)param0;
	task_t                          task = current_task();
#ifdef EXC_RESOURCE_MONITORS
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];
#endif /* EXC_RESOURCE_MONITORS */
	struct ledger_entry_info        lei = {};
	kern_return_t                   kr;

	/* we never set a percentage for the limit */
	assert(warning == LEDGER_WARNING_LEVEL_CRITICAL);

#ifdef MACH_BSD
	pid = proc_selfpid();
#endif
	/*
	 * Get the ledger entry info. We need to do this before disabling the exception
	 * to get correct values for all fields.
	 */
	switch (flavor) {
	case FLAVOR_IO_PHYSICAL_WRITES:
		ledger_get_entry_info(task->ledger, task_ledgers.physical_writes, &lei);
		break;
	default:
		return;
	}


	/*
	 * Disable the exception notification so we don't overwhelm
	 * the listener with an endless stream of redundant exceptions.
	 * TODO: detect whether another thread is already reporting the violation.
	 */
	uint32_t flags = IOMON_DISABLE;
	task_io_monitor_ctl(task, &flags);

	if (flavor == FLAVOR_IO_LOGICAL_WRITES) {
		trace_resource_violation(RMON_LOGWRITES_VIOLATED, &lei);
	}
	os_log(OS_LOG_DEFAULT, "process [%d] caught causing excessive I/O (flavor: %ld). "
	    "Task I/O: %lld MB. [Limit : %lld MB per %lld secs]\n", pid, flavor,
	    lei.lei_balance / (1024 * 1024), lei.lei_limit / (1024 * 1024),
	    lei.lei_refill_period / NSEC_PER_SEC);

	kr = send_resource_violation(send_disk_writes_violation, task, &lei, kRNFlagsNone);
	if (kr) {
		printf("send_resource_violation(disk_writes, ...): error %#x\n", kr);
	}

#ifdef EXC_RESOURCE_MONITORS
	code[0] = code[1] = 0;
	EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_IO);
	EXC_RESOURCE_ENCODE_FLAVOR(code[0], flavor);
	EXC_RESOURCE_IO_ENCODE_INTERVAL(code[0], (lei.lei_refill_period / NSEC_PER_SEC));
	EXC_RESOURCE_IO_ENCODE_LIMIT(code[0], (lei.lei_limit / (1024 * 1024)));
	EXC_RESOURCE_IO_ENCODE_OBSERVED(code[1], (lei.lei_balance / (1024 * 1024)));
	exception_triage(EXC_RESOURCE, code, EXCEPTION_CODE_MAX);
#endif /* EXC_RESOURCE_MONITORS */
}

void
task_port_space_ast(__unused task_t task)
{
	uint32_t current_size, soft_limit, hard_limit;
	assert(task == current_task());
	bool should_notify = ipc_space_check_table_size_limit(task->itk_space,
	    &current_size, &soft_limit, &hard_limit);
	if (should_notify) {
		SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_MACH_PORTS(task, current_size, soft_limit, hard_limit);
	}
}

#if CONFIG_PROC_RESOURCE_LIMITS
static mach_port_t
task_allocate_fatal_port(void)
{
	mach_port_t task_fatal_port = MACH_PORT_NULL;
	task_id_token_t token;

	kern_return_t kr = task_create_identity_token(current_task(), &token); /* Takes a reference on the token */
	if (kr) {
		return MACH_PORT_NULL;
	}
	task_fatal_port = ipc_kobject_alloc_port(token, IKOT_TASK_FATAL,
	    IPC_KOBJECT_ALLOC_MAKE_SEND);

	task_id_token_set_port(token, task_fatal_port);

	return task_fatal_port;
}

static void
task_fatal_port_no_senders(ipc_port_t port, __unused mach_port_mscount_t mscount)
{
	kern_return_t kr;

	task_id_token_t token = ipc_kobject_get_stable(port, IKOT_TASK_FATAL);

	assert(token != NULL);
	if (token) {
		kr = task_identity_token_try_sigkill(token); /* takes a reference on task */
		task_id_token_release(token); /* consumes ref given by notification */
	}
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_MACH_PORTS(task_t task, uint32_t current_size, uint32_t soft_limit, uint32_t hard_limit)
{
	int pid = 0;
	char *procname = (char *) "unknown";
	__unused kern_return_t kr;
	__unused resource_notify_flags_t flags = kRNFlagsNone;
	__unused uint32_t limit;
	__unused mach_port_t task_fatal_port = MACH_PORT_NULL;
	mach_exception_data_type_t      code[EXCEPTION_CODE_MAX];

	pid = proc_selfpid();
	if (get_bsdtask_info(task) != NULL) {
		procname = proc_name_address(get_bsdtask_info(task));
	}

	/*
	 * Only kernel_task and launchd may be allowed to
	 * have really large ipc space.
	 */
	if (pid == 0 || pid == 1) {
		return;
	}

	os_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many mach ports. \
	    Num of ports allocated %u; \n", procname, pid, current_size);

	/* Abort the process if it has hit the system-wide limit for ipc port table size */
	if (!hard_limit && !soft_limit) {
		code[0] = code[1] = 0;
		EXC_RESOURCE_ENCODE_TYPE(code[0], RESOURCE_TYPE_PORTS);
		EXC_RESOURCE_ENCODE_FLAVOR(code[0], FLAVOR_PORT_SPACE_FULL);
		EXC_RESOURCE_PORTS_ENCODE_PORTS(code[0], current_size);

		/* Perform fatal exception logic. */
		exit_with_fatal_exception_and_notify(current_proc(), OS_REASON_PORT_SPACE,
		    EXC_RESOURCE, code[0], code[1], PX_FLAGS_NONE);
		return;
	}

#if CONFIG_PROC_RESOURCE_LIMITS
	if (hard_limit > 0) {
		flags |= kRNHardLimitFlag;
		limit = hard_limit;
		task_fatal_port = task_allocate_fatal_port();
		if (!task_fatal_port) {
			os_log(OS_LOG_DEFAULT, "process %s[%d] Unable to create task token ident object", procname, pid);
			task_self_sigkill(os_reason_create(OS_REASON_RESOURCES, RESOURCES_LIMIT_MACH_PORTS_EXHAUSTION));
		}
	} else {
		flags |= kRNSoftLimitFlag;
		limit = soft_limit;
	}

	kr = send_resource_violation_with_fatal_port(send_port_space_violation, task, (int64_t)current_size, (int64_t)limit, task_fatal_port, flags);
	if (kr) {
		os_log(OS_LOG_DEFAULT, "send_resource_violation(ports, ...): error %#x\n", kr);
	}
	if (task_fatal_port) {
		ipc_port_release_send(task_fatal_port);
	}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */
}

#if CONFIG_PROC_RESOURCE_LIMITS
void
task_kqworkloop_ast(task_t task, int current_size, int soft_limit, int hard_limit)
{
	assert(task == current_task());
	return SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_KQWORKLOOPS(task, current_size, soft_limit, hard_limit);
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_KQWORKLOOPS(task_t task, int current_size, int soft_limit, int hard_limit)
{
	int pid = 0;
	char *procname = (char *) "unknown";
#ifdef MACH_BSD
	pid = proc_selfpid();
	if (get_bsdtask_info(task) != NULL) {
		procname = proc_name_address(get_bsdtask_info(task));
	}
#endif
	if (pid == 0 || pid == 1) {
		return;
	}

	os_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many kqworkloops. \
	    Num of kqworkloops allocated %u; \n", procname, pid, current_size);

	int limit = 0;
	resource_notify_flags_t flags = kRNFlagsNone;
	mach_port_t task_fatal_port = MACH_PORT_NULL;
	if (hard_limit) {
		flags |= kRNHardLimitFlag;
		limit = hard_limit;

		task_fatal_port = task_allocate_fatal_port();
		if (task_fatal_port == MACH_PORT_NULL) {
			os_log(OS_LOG_DEFAULT, "process %s[%d] Unable to create task token ident object", procname, pid);
			task_self_sigkill(os_reason_create(OS_REASON_RESOURCES, RESOURCES_LIMIT_KQWORKLOOPS_EXHAUSTION));
		}
	} else {
		flags |= kRNSoftLimitFlag;
		limit = soft_limit;
	}

	kern_return_t kr;
	kr = send_resource_violation_with_fatal_port(send_kqworkloops_violation, task, (int64_t)current_size, (int64_t)limit, task_fatal_port, flags);
	if (kr) {
		os_log(OS_LOG_DEFAULT, "send_resource_violation_with_fatal_port(kqworkloops, ...): error %#x\n", kr);
	}
	if (task_fatal_port) {
		ipc_port_release_send(task_fatal_port);
	}
}


void
task_filedesc_ast(__unused task_t task, __unused int current_size, __unused int soft_limit, __unused int hard_limit)
{
	assert(task == current_task());
	SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_FILE_DESCRIPTORS(task, current_size, soft_limit, hard_limit);
}

void __attribute__((noinline))
SENDING_NOTIFICATION__THIS_PROCESS_HAS_TOO_MANY_FILE_DESCRIPTORS(task_t task, int current_size, int soft_limit, int hard_limit)
{
	int pid = 0;
	char *procname = (char *) "unknown";
	kern_return_t kr;
	resource_notify_flags_t flags = kRNFlagsNone;
	int limit;
	mach_port_t task_fatal_port = MACH_PORT_NULL;

#ifdef MACH_BSD
	pid = proc_selfpid();
	if (get_bsdtask_info(task) != NULL) {
		procname = proc_name_address(get_bsdtask_info(task));
	}
#endif
	/*
	 * Only kernel_task and launchd may be allowed to
	 * have really large ipc space.
	 */
	if (pid == 0 || pid == 1) {
		return;
	}

	os_log(OS_LOG_DEFAULT, "process %s[%d] caught allocating too many file descriptors. \
	    Num of fds allocated %u; \n", procname, pid, current_size);

	if (hard_limit > 0) {
		flags |= kRNHardLimitFlag;
		limit = hard_limit;
		task_fatal_port = task_allocate_fatal_port();
		if (!task_fatal_port) {
			os_log(OS_LOG_DEFAULT, "process %s[%d] Unable to create task token ident object", procname, pid);
			task_self_sigkill(os_reason_create(OS_REASON_RESOURCES, RESOURCES_LIMIT_FILE_DESCRIPTORS_EXHAUSTION));
		}
	} else {
		flags |= kRNSoftLimitFlag;
		limit = soft_limit;
	}

	kr = send_resource_violation_with_fatal_port(send_file_descriptors_violation, task, (int64_t)current_size, (int64_t)limit, task_fatal_port, flags);
	if (kr) {
		os_log(OS_LOG_DEFAULT, "send_resource_violation_with_fatal_port(filedesc, ...): error %#x\n", kr);
	}
	if (task_fatal_port) {
		ipc_port_release_send(task_fatal_port);
	}
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

/* Placeholders for the task set/get voucher interfaces */
kern_return_t
task_get_mach_voucher(
	task_t                  task,
	mach_voucher_selector_t __unused which,
	ipc_voucher_t           *voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	*voucher = NULL;
	return KERN_SUCCESS;
}

kern_return_t
task_set_mach_voucher(
	task_t                  task,
	ipc_voucher_t           __unused voucher)
{
	if (TASK_NULL == task) {
		return KERN_INVALID_TASK;
	}

	return KERN_SUCCESS;
}

kern_return_t
task_swap_mach_voucher(
	__unused task_t         task,
	__unused ipc_voucher_t  new_voucher,
	ipc_voucher_t          *in_out_old_voucher)
{
	/*
	 * Currently this function is only called from a MIG generated
	 * routine which doesn't release the reference on the voucher
	 * addressed by in_out_old_voucher. To avoid leaking this reference,
	 * a call to release it has been added here.
	 */
	ipc_voucher_release(*in_out_old_voucher);
	OS_ANALYZER_SUPPRESS("81787115") return KERN_NOT_SUPPORTED;
}

void
task_set_gpu_role(task_t task, darwin_gpu_role_t gpu_role)
{
	task_lock(task);

	os_atomic_store(&task->t_gpu_role, gpu_role, relaxed);

	KDBG(IMPORTANCE_CODE(IMP_SET_GPU_ROLE, 0), gpu_role);

	task_unlock(task);
}

darwin_gpu_role_t
task_get_gpu_role(task_t task)
{
	return os_atomic_load(&task->t_gpu_role, relaxed);
}

boolean_t
task_is_gpu_denied(task_t task)
{
	return (os_atomic_load(&task->t_gpu_role, relaxed) == PRIO_DARWIN_GPU_DENY) ? TRUE : FALSE;
}

/*
 * Task policy termination uses this path to clear the bit the final time
 * during the termination flow, and the TASK_POLICY_TERMINATED bit guarantees
 * that it won't be changed again on a terminated task.
 */
bool
task_set_game_mode_locked(task_t task, bool enabled)
{
	task_lock_assert_owned(task);

	if (enabled) {
		assert(proc_get_effective_task_policy(task, TASK_POLICY_TERMINATED) == 0);
	}

	bool previously_enabled = task_get_game_mode(task);
	bool needs_update = false;
	uint32_t new_count = 0;

	if (enabled) {
		task->t_flags |= TF_GAME_MODE;
	} else {
		task->t_flags &= ~TF_GAME_MODE;
	}

	if (enabled && !previously_enabled) {
		if (task_coalition_adjust_game_mode_count(task, 1, &new_count) && (new_count == 1)) {
			needs_update = true;
		}
	} else if (!enabled && previously_enabled) {
		if (task_coalition_adjust_game_mode_count(task, -1, &new_count) && (new_count == 0)) {
			needs_update = true;
		}
	}

	return needs_update;
}

void
task_set_game_mode(task_t task, bool enabled)
{
	bool needs_update = false;

	task_lock(task);

	/* After termination, further updates are no longer effective */
	if (proc_get_effective_task_policy(task, TASK_POLICY_TERMINATED) == 0) {
		needs_update = task_set_game_mode_locked(task, enabled);
	}

	task_unlock(task);

#if CONFIG_THREAD_GROUPS
	if (needs_update) {
		task_coalition_thread_group_game_mode_update(task);
	}
#endif /* CONFIG_THREAD_GROUPS */
}

bool
task_get_game_mode(task_t task)
{
	/* We don't need the lock to read this flag */
	return task->t_flags & TF_GAME_MODE;
}

bool
task_set_carplay_mode_locked(task_t task, bool enabled)
{
	task_lock_assert_owned(task);

	if (enabled) {
		assert(proc_get_effective_task_policy(task, TASK_POLICY_TERMINATED) == 0);
	}

	bool previously_enabled = task_get_carplay_mode(task);
	bool needs_update = false;
	uint32_t new_count = 0;

	if (enabled) {
		task->t_flags |= TF_CARPLAY_MODE;
	} else {
		task->t_flags &= ~TF_CARPLAY_MODE;
	}

	if (enabled && !previously_enabled) {
		if (task_coalition_adjust_carplay_mode_count(task, 1, &new_count) && (new_count == 1)) {
			needs_update = true;
		}
	} else if (!enabled && previously_enabled) {
		if (task_coalition_adjust_carplay_mode_count(task, -1, &new_count) && (new_count == 0)) {
			needs_update = true;
		}
	}
	return needs_update;
}

void
task_set_carplay_mode(task_t task, bool enabled)
{
	bool needs_update = false;

	task_lock(task);

	/* After termination, further updates are no longer effective */
	if (proc_get_effective_task_policy(task, TASK_POLICY_TERMINATED) == 0) {
		needs_update = task_set_carplay_mode_locked(task, enabled);
	}

	task_unlock(task);

#if CONFIG_THREAD_GROUPS
	if (needs_update) {
		task_coalition_thread_group_carplay_mode_update(task);
	}
#endif /* CONFIG_THREAD_GROUPS */
}

bool
task_get_carplay_mode(task_t task)
{
	/* We don't need the lock to read this flag */
	return task->t_flags & TF_CARPLAY_MODE;
}

uint64_t
get_task_memory_region_count(task_t task)
{
	vm_map_t map;
	map = (task == kernel_task) ? kernel_map: task->map;
	return (uint64_t)get_map_nentries(map);
}

static void
kdebug_trace_dyld_internal(uint32_t base_code,
    struct dyld_kernel_image_info *info)
{
	static_assert(sizeof(info->uuid) >= 16);

#if defined(__LP64__)
	uint64_t *uuid = (uint64_t *)&(info->uuid);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code), uuid[0],
	    uuid[1], info->load_addr,
	    (uint64_t)info->fsid.val[0] | ((uint64_t)info->fsid.val[1] << 32),
	    0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 1),
	    (uint64_t)info->fsobjid.fid_objno |
	    ((uint64_t)info->fsobjid.fid_generation << 32),
	    0, 0, 0, 0);
#else /* defined(__LP64__) */
	uint32_t *uuid = (uint32_t *)&(info->uuid);

	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 2), uuid[0],
	    uuid[1], uuid[2], uuid[3], 0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 3),
	    (uint32_t)info->load_addr, info->fsid.val[0], info->fsid.val[1],
	    info->fsobjid.fid_objno, 0);
	KERNEL_DEBUG_CONSTANT_IST(KDEBUG_TRACE,
	    KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, base_code + 4),
	    info->fsobjid.fid_generation, 0, 0, 0, 0);
#endif /* !defined(__LP64__) */
}

static kern_return_t
kdebug_trace_dyld(task_t task, uint32_t base_code,
    vm_map_copy_t infos_copy, mach_msg_type_number_t infos_len)
{
	kern_return_t kr;
	dyld_kernel_image_info_array_t infos;
	vm_map_offset_t map_data;
	vm_offset_t data;

	if (!infos_copy) {
		return KERN_INVALID_ADDRESS;
	}

	if (!kdebug_enable ||
	    !kdebug_debugid_enabled(KDBG_EVENTID(DBG_DYLD, DBG_DYLD_UUID, 0))) {
		vm_map_copy_discard(infos_copy);
		return KERN_SUCCESS;
	}

	if (task == NULL || task != current_task()) {
		return KERN_INVALID_TASK;
	}

	kr = vm_map_copyout(ipc_kernel_map, &map_data, (vm_map_copy_t)infos_copy);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	infos = CAST_DOWN(dyld_kernel_image_info_array_t, map_data);

	for (mach_msg_type_number_t i = 0; i < infos_len; i++) {
		kdebug_trace_dyld_internal(base_code, &(infos[i]));
	}

	data = CAST_DOWN(vm_offset_t, map_data);
	mach_vm_deallocate_kernel(ipc_kernel_map, data, infos_len * sizeof(infos[0]));
	return KERN_SUCCESS;
}

kern_return_t
task_register_dyld_image_infos(task_t task,
    dyld_kernel_image_info_array_t infos_copy,
    mach_msg_type_number_t infos_len)
{
	return kdebug_trace_dyld(task, DBG_DYLD_UUID_MAP_A,
	           (vm_map_copy_t)infos_copy, infos_len);
}

kern_return_t
task_unregister_dyld_image_infos(task_t task,
    dyld_kernel_image_info_array_t infos_copy,
    mach_msg_type_number_t infos_len)
{
	return kdebug_trace_dyld(task, DBG_DYLD_UUID_UNMAP_A,
	           (vm_map_copy_t)infos_copy, infos_len);
}

kern_return_t
task_get_dyld_image_infos(__unused task_t task,
    __unused dyld_kernel_image_info_array_t * dyld_images,
    __unused mach_msg_type_number_t * dyld_imagesCnt)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_register_dyld_shared_cache_image_info(task_t task,
    dyld_kernel_image_info_t cache_img,
    __unused boolean_t no_cache,
    __unused boolean_t private_cache)
{
	if (task == NULL || task != current_task()) {
		return KERN_INVALID_TASK;
	}

	kdebug_trace_dyld_internal(DBG_DYLD_UUID_SHARED_CACHE_A, &cache_img);
	return KERN_SUCCESS;
}

kern_return_t
task_register_dyld_set_dyld_state(__unused task_t task,
    __unused uint8_t dyld_state)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_register_dyld_get_process_state(__unused task_t task,
    __unused dyld_kernel_process_info_t * dyld_process_state)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
task_inspect(task_inspect_t task_insp, task_inspect_flavor_t flavor,
    task_inspect_info_t info_out, mach_msg_type_number_t *size_in_out)
{
#if CONFIG_PERVASIVE_CPI
	task_t task = (task_t)task_insp;
	kern_return_t kr = KERN_SUCCESS;
	mach_msg_type_number_t size;

	if (task == TASK_NULL) {
		return KERN_INVALID_ARGUMENT;
	}

	size = *size_in_out;

	switch (flavor) {
	case TASK_INSPECT_BASIC_COUNTS: {
		struct task_inspect_basic_counts *bc =
		    (struct task_inspect_basic_counts *)info_out;
		struct recount_usage stats = { 0 };
		if (size < TASK_INSPECT_BASIC_COUNTS_COUNT) {
			kr = KERN_INVALID_ARGUMENT;
			break;
		}

		recount_sum(&recount_task_plan, task->tk_recount.rtk_lifetime, &stats);
		bc->instructions = recount_usage_instructions(&stats);
		bc->cycles = recount_usage_cycles(&stats);
		size = TASK_INSPECT_BASIC_COUNTS_COUNT;
		break;
	}
	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	if (kr == KERN_SUCCESS) {
		*size_in_out = size;
	}
	return kr;
#else /* CONFIG_PERVASIVE_CPI */
#pragma unused(task_insp, flavor, info_out, size_in_out)
	return KERN_NOT_SUPPORTED;
#endif /* !CONFIG_PERVASIVE_CPI */
}

#if CONFIG_SECLUDED_MEMORY
int num_tasks_can_use_secluded_mem = 0;

void
task_set_can_use_secluded_mem(
	task_t          task,
	boolean_t       can_use_secluded_mem)
{
	if (!task->task_could_use_secluded_mem) {
		return;
	}
	task_lock(task);
	task_set_can_use_secluded_mem_locked(task, can_use_secluded_mem);
	task_unlock(task);
}

void
task_set_can_use_secluded_mem_locked(
	task_t          task,
	boolean_t       can_use_secluded_mem)
{
	assert(task->task_could_use_secluded_mem);
	if (can_use_secluded_mem &&
	    secluded_for_apps &&         /* global boot-arg */
	    !task->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem >= 0);
		OSAddAtomic(+1,
		    (volatile SInt32 *)&num_tasks_can_use_secluded_mem);
		task->task_can_use_secluded_mem = TRUE;
	} else if (!can_use_secluded_mem &&
	    task->task_can_use_secluded_mem) {
		assert(num_tasks_can_use_secluded_mem > 0);
		OSAddAtomic(-1,
		    (volatile SInt32 *)&num_tasks_can_use_secluded_mem);
		task->task_can_use_secluded_mem = FALSE;
	}
}

void
task_set_could_use_secluded_mem(
	task_t          task,
	boolean_t       could_use_secluded_mem)
{
	task->task_could_use_secluded_mem = !!could_use_secluded_mem;
}

void
task_set_could_also_use_secluded_mem(
	task_t          task,
	boolean_t       could_also_use_secluded_mem)
{
	task->task_could_also_use_secluded_mem = !!could_also_use_secluded_mem;
}

boolean_t
task_can_use_secluded_mem(
	task_t          task,
	boolean_t       is_alloc)
{
	if (task->task_can_use_secluded_mem) {
		assert(task->task_could_use_secluded_mem);
		assert(num_tasks_can_use_secluded_mem > 0);
		return TRUE;
	}
	if (task->task_could_also_use_secluded_mem &&
	    num_tasks_can_use_secluded_mem > 0) {
		assert(num_tasks_can_use_secluded_mem > 0);
		return TRUE;
	}

	/*
	 * If a single task is using more than some large amount of
	 * memory (i.e. secluded_shutoff_trigger) and is approaching
	 * its task limit, allow it to dip into secluded and begin
	 * suppression of rebuilding secluded memory until that task exits.
	 */
	if (is_alloc && secluded_shutoff_trigger != 0) {
		uint64_t phys_used = get_task_phys_footprint(task);
		uint64_t limit = get_task_phys_footprint_limit(task);
		if (phys_used > secluded_shutoff_trigger &&
		    limit > secluded_shutoff_trigger &&
		    phys_used > limit - secluded_shutoff_headroom) {
			start_secluded_suppression(task);
			return TRUE;
		}
	}

	return FALSE;
}

boolean_t
task_could_use_secluded_mem(
	task_t  task)
{
	return task->task_could_use_secluded_mem;
}

boolean_t
task_could_also_use_secluded_mem(
	task_t  task)
{
	return task->task_could_also_use_secluded_mem;
}
#endif /* CONFIG_SECLUDED_MEMORY */

queue_head_t *
task_io_user_clients(task_t task)
{
	return &task->io_user_clients;
}

void
task_set_message_app_suspended(task_t task, boolean_t enable)
{
	task->message_app_suspended = enable;
}

void
task_copy_fields_for_exec(task_t dst_task, task_t src_task)
{
	dst_task->vtimers = src_task->vtimers;
}

#if DEVELOPMENT || DEBUG
int vm_region_footprint = 0;
#endif /* DEVELOPMENT || DEBUG */

boolean_t
task_self_region_footprint(void)
{
#if DEVELOPMENT || DEBUG
	if (vm_region_footprint) {
		/* system-wide override */
		return TRUE;
	}
#endif /* DEVELOPMENT || DEBUG */
	return current_task()->task_region_footprint;
}

void
task_self_region_footprint_set(
	boolean_t newval)
{
	task_t  curtask;

	curtask = current_task();
	task_lock(curtask);
	if (newval) {
		curtask->task_region_footprint = TRUE;
	} else {
		curtask->task_region_footprint = FALSE;
	}
	task_unlock(curtask);
}

int
task_self_region_info_flags(void)
{
	return current_task()->task_region_info_flags;
}

kern_return_t
task_self_region_info_flags_set(
	int newval)
{
	task_t  curtask;
	kern_return_t err = KERN_SUCCESS;

	curtask = current_task();
	task_lock(curtask);
	curtask->task_region_info_flags = newval;
	/* check for overflow (flag added without increasing bitfield size?) */
	if (curtask->task_region_info_flags != newval) {
		err = KERN_INVALID_ARGUMENT;
	}
	task_unlock(curtask);

	return err;
}

void
task_set_darkwake_mode(task_t task, boolean_t set_mode)
{
	assert(task);

	task_lock(task);

	if (set_mode) {
		task->t_flags |= TF_DARKWAKE_MODE;
	} else {
		task->t_flags &= ~(TF_DARKWAKE_MODE);
	}

	task_unlock(task);
}

boolean_t
task_get_darkwake_mode(task_t task)
{
	assert(task);
	return (task->t_flags & TF_DARKWAKE_MODE) != 0;
}

/*
 * Set task default behavior for EXC_GUARD variants that have settable behavior.
 *
 * Platform binaries typically have one behavior, third parties another -
 * but there are special exception we may need to account for.
 */
void
task_set_exc_guard_default(
	task_t task,
	const char *name,
	unsigned long namelen,
	boolean_t is_simulated,
	uint32_t platform,
	uint32_t sdk)
{
	if (task_get_platform_restrictions_version(task) >= 1) {
		/* set exc guard default behavior for platform restrictions binaries */
		task->task_exc_guard = (task_exc_guard_default & TASK_EXC_GUARD_ALL);

		if (1 == task_pid(task)) {
			/*
			 * special configuration for inittask: mp error as
			 * corpses, VM guards as fatal.
			 */
			task->task_exc_guard = _TASK_EXC_GUARD_MP_CORPSE |
			    _TASK_EXC_GUARD_VM_FATAL;
		} else if (task_has_guard_objects(task)) {
			/*
			 * rdar://168990820: guard objects, which are
			 * a task_get_platform_restrictions_version() >= 2 feature,
			 * require fatal guard exceptions, otherwise this can lead
			 * to inconsistencies in the vm map store
			 */
			task->task_exc_guard &= ~TASK_EXC_GUARD_VM_ALL;
			task->task_exc_guard |= _TASK_EXC_GUARD_VM_FATAL;
		}

		if (task_exc_guard_default & TASK_EXC_GUARD_HONOR_NAMED_DEFAULTS) {
			/* honor by-name default setting overrides */

			int count = sizeof(task_exc_guard_named_defaults) / sizeof(struct task_exc_guard_named_default);

			for (int i = 0; i < count; i++) {
				const struct task_exc_guard_named_default *named_default =
				    &task_exc_guard_named_defaults[i];
				if (strncmp(named_default->name, name, namelen) == 0 &&
				    strlen(named_default->name) == namelen) {
					task->task_exc_guard = named_default->behavior;
					break;
				}
			}
		}
	} else {
		/* set exc guard default behavior for third-party code */
		task->task_exc_guard = ((task_exc_guard_default >> TASK_EXC_GUARD_THIRD_PARTY_DEFAULT_SHIFT) & TASK_EXC_GUARD_ALL);
	}

	if (is_simulated) {
		/* If simulated and built against pre-iOS 15 SDK, disable all EXC_GUARD */
		if ((platform == PLATFORM_IOSSIMULATOR && sdk < 0xf0000) ||
		    (platform == PLATFORM_TVOSSIMULATOR && sdk < 0xf0000) ||
		    (platform == PLATFORM_WATCHOSSIMULATOR && sdk < 0x80000)) {
			task->task_exc_guard = TASK_EXC_GUARD_NONE;
		}
	}
}

kern_return_t
task_get_exc_guard_behavior(
	task_t task,
	task_exc_guard_behavior_t *behaviorp)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	*behaviorp = task->task_exc_guard;
	return KERN_SUCCESS;
}

kern_return_t
task_set_exc_guard_behavior(
	task_t task,
	task_exc_guard_behavior_t new_behavior)
{
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}
	if (new_behavior & ~TASK_EXC_GUARD_ALL) {
		return KERN_INVALID_VALUE;
	}

	/* limit setting to that allowed for this config */
	new_behavior = new_behavior & task_exc_guard_config_mask;

#if !defined (DEBUG) && !defined (DEVELOPMENT)
	/* On release kernels, only allow _upgrading_ exc guard behavior */
	task_exc_guard_behavior_t cur_behavior;

	os_atomic_rmw_loop(&task->task_exc_guard, cur_behavior, new_behavior, relaxed, {
		if ((cur_behavior & task_exc_guard_no_unset_mask) & ~(new_behavior & task_exc_guard_no_unset_mask)) {
		        os_atomic_rmw_loop_give_up(return KERN_DENIED);
		}

		if ((new_behavior & task_exc_guard_no_set_mask) & ~(cur_behavior & task_exc_guard_no_set_mask)) {
		        os_atomic_rmw_loop_give_up(return KERN_DENIED);
		}

		/* no restrictions on CORPSE bit */
	});
#else
	task->task_exc_guard = new_behavior;
#endif
	return KERN_SUCCESS;
}

kern_return_t
task_set_corpse_forking_behavior(task_t task, task_corpse_forking_behavior_t behavior)
{
#if DEVELOPMENT || DEBUG
	if (task == TASK_NULL) {
		return KERN_INVALID_TASK;
	}

	task_lock(task);
	if (behavior & TASK_CORPSE_FORKING_DISABLED_MEM_DIAG) {
		task->t_flags |= TF_NO_CORPSE_FORKING;
	} else {
		task->t_flags &= ~TF_NO_CORPSE_FORKING;
	}
	task_unlock(task);

	return KERN_SUCCESS;
#else
	(void)task;
	(void)behavior;
	return KERN_NOT_SUPPORTED;
#endif
}

boolean_t
task_corpse_forking_disabled(task_t task)
{
	boolean_t disabled = FALSE;

	task_lock(task);
	disabled = (task->t_flags & TF_NO_CORPSE_FORKING);
	task_unlock(task);

	return disabled;
}

#if __arm64__
extern int legacy_footprint_entitlement_mode;
extern void memorystatus_act_on_legacy_footprint_entitlement(struct proc *, boolean_t);
extern void memorystatus_act_on_ios13extended_footprint_entitlement(struct proc *);


void
task_set_legacy_footprint(
	task_t task)
{
	task_lock(task);
	task->task_legacy_footprint = TRUE;
	task_unlock(task);
}

void
task_set_extra_footprint_limit(
	task_t task)
{
	if (task->task_extra_footprint_limit) {
		return;
	}
	task_lock(task);
	if (task->task_extra_footprint_limit) {
		task_unlock(task);
		return;
	}
	task->task_extra_footprint_limit = TRUE;
	task_unlock(task);
	memorystatus_act_on_legacy_footprint_entitlement(get_bsdtask_info(task), TRUE);
}

void
task_set_ios13extended_footprint_limit(
	task_t task)
{
	if (task->task_ios13extended_footprint_limit) {
		return;
	}
	task_lock(task);
	if (task->task_ios13extended_footprint_limit) {
		task_unlock(task);
		return;
	}
	task->task_ios13extended_footprint_limit = TRUE;
	task_unlock(task);
	memorystatus_act_on_ios13extended_footprint_entitlement(get_bsdtask_info(task));
}
#endif /* __arm64__ */

static inline ledger_amount_t
task_ledger_get_balance(
	ledger_t        ledger,
	int             ledger_idx)
{
	ledger_amount_t amount;
	amount = 0;
	ledger_get_balance(ledger, ledger_idx, LEO_NO_SETTLE, &amount);
	return amount;
}

/*
 * Gather the amount of memory counted in a task's footprint due to
 * being in a specific set of ledgers.
 */
void
task_ledgers_footprint(
	ledger_t        ledger,
	ledger_amount_t *ledger_resident,
	ledger_amount_t *ledger_compressed)
{
	*ledger_resident = 0;
	*ledger_compressed = 0;

	ledger_tab_settle(&task_ledger_template, ledger);

	/* purgeable non-volatile memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.purgeable_nonvolatile);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.purgeable_nonvolatile_compress);

	/* "default" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.tagged_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.tagged_footprint_compressed);

	/* "network" currently never counts in the footprint... */

	/* "media" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.media_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.media_footprint_compressed);

	/* "graphics" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.graphics_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.graphics_footprint_compressed);

	/* "neural" tagged memory */
	*ledger_resident += task_ledger_get_balance(ledger, task_ledgers.neural_footprint);
	*ledger_compressed += task_ledger_get_balance(ledger, task_ledgers.neural_footprint_compressed);
}

#if CONFIG_MEMORYSTATUS
/*
 * Credit any outstanding task dirty time to the ledger.
 * memstat_dirty_start is pushed forward to prevent any possibility of double
 * counting, making it safe to call this as often as necessary to ensure that
 * anyone reading the ledger gets up-to-date information.
 */
void
task_ledger_settle_dirty_time(task_t t)
{
	uint64_t start;

	task_lock(t);

	start = t->memstat_dirty_start;
	if (start) {
		uint64_t now = mach_absolute_time();

		uint64_t duration;
		absolutetime_to_nanoseconds(now - start, &duration);

		ledger_t ledger = get_task_ledger(t);
		ledger_credit(ledger, task_ledgers.memorystatus_dirty_time, duration);

		t->memstat_dirty_start = now;
	}

	task_unlock(t);
}
#endif /* CONFIG_MEMORYSTATUS */

void
task_ledger_settle(task_t t)
{
#if CONFIG_MEMORYSTATUS
	task_ledger_settle_dirty_time(t);
#endif
	ledger_tab_settle(&task_ledger_template, t->ledger);
#if CONFIG_DEFERRED_RECLAIM
	vm_deferred_reclamation_settle_ledger(t);
#endif /* CONFIG_DEFERRED_RECLAIM */
}

void
task_set_memory_ownership_transfer(
	task_t    task,
	boolean_t value)
{
	task_lock(task);
	task->task_can_transfer_memory_ownership = !!value;
	task_unlock(task);
}

#if DEVELOPMENT || DEBUG

void
task_set_no_footprint_for_debug(task_t task, boolean_t value)
{
	task_lock(task);
	task->task_no_footprint_for_debug = !!value;
	task_unlock(task);
}

int
task_get_no_footprint_for_debug(task_t task)
{
	return task->task_no_footprint_for_debug;
}

#endif /* DEVELOPMENT || DEBUG */

void
task_copy_vmobjects(task_t task, vm_object_query_t query, size_t len, size_t *num)
{
	vm_object_t find_vmo;
	size_t size = 0;

	/*
	 * Allocate a save area for FP state before taking task_objq lock,
	 * if necessary, to ensure that VM_KERNEL_ADDRHASH() doesn't cause
	 * an FP state allocation while holding VM locks.
	 */
	ml_fp_save_area_prealloc();

	task_objq_lock(task);
	if (query != NULL) {
		queue_iterate(&task->task_objq, find_vmo, vm_object_t, task_objq)
		{
			vm_object_query_t p = &query[size++];

			/* make sure to not overrun */
			if (size * sizeof(vm_object_query_data_t) > len) {
				--size;
				break;
			}

			bzero(p, sizeof(*p));
			p->object_id = (vm_object_id_t) VM_KERNEL_ADDRHASH(find_vmo);
			p->virtual_size = find_vmo->internal ? find_vmo->vo_size : 0;
			p->resident_size = find_vmo->resident_page_count * PAGE_SIZE;
			p->wired_size = find_vmo->wired_page_count * PAGE_SIZE;
			p->reusable_size = find_vmo->reusable_page_count * PAGE_SIZE;
			p->vo_no_footprint = find_vmo->vo_no_footprint;
			p->vo_ledger_tag = find_vmo->vo_ledger_tag;
			p->purgable = find_vmo->purgable;

			if (find_vmo->internal && find_vmo->pager_created && find_vmo->pager != NULL) {
				p->compressed_size = vm_compressor_pager_get_count(find_vmo->pager) * PAGE_SIZE;
			} else {
				p->compressed_size = 0;
			}
		}
	} else {
		size = (size_t)task->task_owned_objects;
	}
	task_objq_unlock(task);

	*num = size;
}

void
task_get_owned_vmobjects(task_t task, size_t buffer_size, vmobject_list_output_t buffer, size_t* output_size, size_t* entries)
{
	assert(output_size);
	assert(entries);

	/* copy the vmobjects and vmobject data out of the task */
	if (buffer_size == 0) {
		task_copy_vmobjects(task, NULL, 0, entries);
		*output_size = (*entries > 0) ? *entries * sizeof(vm_object_query_data_t) + sizeof(*buffer) : 0;
	} else {
		assert(buffer);
		task_copy_vmobjects(task, &buffer->data[0], buffer_size - sizeof(*buffer), entries);
		buffer->entries = (uint64_t)*entries;
		*output_size = *entries * sizeof(vm_object_query_data_t) + sizeof(*buffer);
	}
}

static void
task_store_owned_vmobject_info(task_t to_task, task_t from_task)
{
	size_t buffer_size;
	vmobject_list_output_t buffer;
	size_t output_size;
	size_t entries;

	/* get the size, allocate a buffer, and populate */
	entries = 0;
	output_size = 0;
	task_get_owned_vmobjects(from_task, 0, NULL, &output_size, &entries);

	if (output_size) {
		buffer_size = output_size;
		buffer = kalloc_data(buffer_size, Z_WAITOK);

		if (buffer) {
			entries = 0;
			output_size = 0;

			task_get_owned_vmobjects(from_task, buffer_size, buffer, &output_size, &entries);

			task_lock(to_task);

			if (!entries || (to_task->corpse_vmobject_list != NULL)) {
				kfree_data(buffer, buffer_size);
				task_unlock(to_task);
				return;
			}

			to_task->corpse_vmobject_list = buffer;
			to_task->corpse_vmobject_list_size = buffer_size;

			task_unlock(to_task);
		}
	}
}

void
task_set_filter_msg_flag(
	task_t task,
	boolean_t flag)
{
	assert(task != TASK_NULL);

	if (flag) {
		task_ro_flags_set(task, TFRO_FILTER_MSG);
	} else {
		task_ro_flags_clear(task, TFRO_FILTER_MSG);
	}
}

boolean_t
task_get_filter_msg_flag(
	task_t task)
{
	if (!task) {
		return false;
	}

	return (task_ro_flags_get(task) & TFRO_FILTER_MSG) ? TRUE : FALSE;
}
bool
task_is_exotic(
	task_t task)
{
	if (task == TASK_NULL) {
		return false;
	}
	return vm_map_is_exotic(get_task_map(task));
}

bool
task_is_alien(
	task_t task)
{
	if (task == TASK_NULL) {
		return false;
	}
	return vm_map_is_alien(get_task_map(task));
}



#if CONFIG_MACF
uint8_t *
mac_task_get_mach_filter_mask(task_t task)
{
	assert(task);
	return task_get_mach_trap_filter_mask(task);
}

uint8_t *
mac_task_get_kobj_filter_mask(task_t task)
{
	assert(task);
	return task_get_mach_kobj_filter_mask(task);
}

/* Set the filter mask for Mach traps. */
void
mac_task_set_mach_filter_mask(task_t task, uint8_t *maskptr)
{
	assert(task);

	task_set_mach_trap_filter_mask(task, maskptr);
}

/* Set the filter mask for kobject msgs. */
void
mac_task_set_kobj_filter_mask(task_t task, uint8_t *maskptr)
{
	assert(task);

	task_set_mach_kobj_filter_mask(task, maskptr);
}

/* Hook for mach trap/sc filter evaluation policy. */
SECURITY_READ_ONLY_LATE(mac_task_mach_filter_cbfunc_t) mac_task_mach_trap_evaluate = NULL;

/* Hook for kobj message filter evaluation policy. */
SECURITY_READ_ONLY_LATE(mac_task_kobj_filter_cbfunc_t) mac_task_kobj_msg_evaluate = NULL;

/* Set the callback hooks for the filtering policy. */
int
mac_task_register_filter_callbacks(
	const mac_task_mach_filter_cbfunc_t mach_cbfunc,
	const mac_task_kobj_filter_cbfunc_t kobj_cbfunc)
{
	if (mach_cbfunc != NULL) {
		if (mac_task_mach_trap_evaluate != NULL) {
			return KERN_FAILURE;
		}
		mac_task_mach_trap_evaluate = mach_cbfunc;
	}
	if (kobj_cbfunc != NULL) {
		if (mac_task_kobj_msg_evaluate != NULL) {
			return KERN_FAILURE;
		}
		mac_task_kobj_msg_evaluate = kobj_cbfunc;
	}

	return KERN_SUCCESS;
}
#endif /* CONFIG_MACF */

#if CONFIG_ROSETTA
bool
task_is_translated(task_t task)
{
	extern boolean_t proc_is_translated(struct proc* p);
	return task && proc_is_translated(get_bsdtask_info(task));
}
#endif

/* Task runtime security mitigations configuration. */
#define TASK_SECURITY_CONFIG_HELPER_DEFINE(suffix) \
	bool task_has_##suffix(task_t task) \
	{ \
	        assert(task);   \
	        return (task->security_config. suffix); \
	} \
        \
	void task_set_##suffix(task_t task) \
	{ \
	        assert(task);\
	        task->security_config. suffix = true; \
	} \
        \
	void task_clear_##suffix(task_t task) \
	{ \
	        assert(task);\
	        task->security_config. suffix = false; \
	}

uint32_t
task_get_security_config(task_t task)
{
	assert(task);
	return (uint32_t)(task->security_config.value);
}

bool
task_has_fatal_vm_guards(task_t task)
{
	return task->task_exc_guard & _TASK_EXC_GUARD_VM_FATAL;
}

TASK_SECURITY_CONFIG_HELPER_DEFINE(hardened_heap)
TASK_SECURITY_CONFIG_HELPER_DEFINE(tpro)
TASK_SECURITY_CONFIG_HELPER_DEFINE(script_restrictions)
TASK_SECURITY_CONFIG_HELPER_DEFINE(ipc_containment_vessel)
TASK_SECURITY_CONFIG_HELPER_DEFINE(guard_objects)

uint8_t
task_get_platform_restrictions_version(task_t task)
{
	assert(task);
	return task->security_config.platform_restrictions_version;
}

void
task_set_platform_restrictions_version(task_t task, uint64_t version)
{
	assert(task);
	/* platform_restrictions_version is a 3-bit field */
	if (version < 8) {
		task->security_config.platform_restrictions_version = (uint8_t)version;
	}
}

uint8_t
task_get_hardened_process_version(task_t task)
{
	assert(task);
	return task->security_config.hardened_process_version;
}
void
task_set_hardened_process_version(task_t task, uint64_t version)
{
	assert(task);
	task->security_config.hardened_process_version = (uint8_t)version;
}

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
/*
 * task_has_sec() (really: task_has_mte()) means:
 *
 * 1. task->map allows vm_allocate(VM_FLAGS_MTE); i.e., you can create *new*
 *    tagged memory in that map.
 * 2. When this task is running, MTE tag checking is enabled (SCTLR.ATA0=1).
 * 3. task is subject to VM restriction policies.
 */
TASK_SECURITY_CONFIG_HELPER_DEFINE(sec)

#define TASK_MTE_POLICY_HELPER_DEFINE(suffix, policy)   \
    bool task_has_sec_##suffix(task_t task) \
	{ \
	        if (__improbable(!task)) { \
	                panic("NULL task in %s", __func__); \
	} \
	if (__improbable(task == kernel_task)) { \
	        return false; \
	} \
	if (__improbable(!task_has_sec(task))) { \
	                return false; \
	} \
	        return ((os_atomic_load(&task->task_sec_policy, relaxed)) & policy) != 0; \
	} \
	void task_set_sec_##suffix(task_t task) \
	{ \
	        os_atomic_or(&task->task_sec_policy, policy, relaxed); \
	}

TASK_MTE_POLICY_HELPER_DEFINE(soft_mode, TASK_SEC_POLICY_SOFT_MODE);
TASK_MTE_POLICY_HELPER_DEFINE(user_data, TASK_SEC_POLICY_USER_DATA);
TASK_MTE_POLICY_HELPER_DEFINE(inherit, TASK_SEC_POLICY_INHERIT);
TASK_MTE_POLICY_HELPER_DEFINE(never_check, TASK_SEC_POLICY_NEVER_CHECK);
TASK_MTE_POLICY_HELPER_DEFINE(restrict_receiving_aliases_to_tagged_memory, TASK_SEC_POLICY_RESTRICT_RECEIVING_ALIASES_TO_TAGGED_MEMORY);

uint32_t
task_get_sec_policy(task_t task)
{
	assert(task);
	return (uint32_t)(task->task_sec_policy);
}

void
task_clear_sec_policy(task_t task)
{
	os_atomic_store(&task->task_sec_policy, TASK_SEC_POLICY_NONE, relaxed);
}

void
task_clear_sec_soft_mode(task_t task)
{
	os_atomic_andnot(&task->task_sec_policy, TASK_SEC_POLICY_SOFT_MODE, relaxed);
}

bool
current_task_has_sec_enabled(void)
{
	task_t task = current_task_early();
	if (!task) {
		/* an early boot thread is always a kernel thread */
#if CONFIG_KERNEL_TAGGING
		return true;
#else /* !CONFIG_KERNEL_TAGGING */
		return false;
#endif /* !CONFIG_KERNEL_TAGGING */
	}
	return task_has_sec(task);
}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */


#if __has_feature(ptrauth_calls)
/* On FPAC, we want to deliver all PAC violations as fatal exceptions, regardless
 * of the enable_pac_exception boot-arg value or any other entitlements.
 * The only case where we allow non-fatal PAC exceptions on FPAC is for debugging,
 * which requires Developer Mode enabled.
 *
 * On non-FPAC hardware, we gate the decision behind entitlements and the
 * enable_pac_exception boot-arg.
 */
extern int gARM_FEAT_FPAC;
/*
 * Having the PAC_EXCEPTION_ENTITLEMENT entitlement means we always enforce all
 * of the PAC exception hardening: fatal exceptions and signed user state.
 */
#define PAC_EXCEPTION_ENTITLEMENT "com.apple.private.pac.exception"
/*
 * On non-FPAC hardware, when enable_pac_exception boot-arg is set to true,
 * processes can choose to get non-fatal PAC exception delivery by setting
 * the SKIP_PAC_EXCEPTION_ENTITLEMENT entitlement.
 */
#define SKIP_PAC_EXCEPTION_ENTITLEMENT "com.apple.private.skip.pac.exception"

void
task_set_pac_exception_fatal_flag(
	task_t task)
{
	assert(task != TASK_NULL);
	bool pac_hardened_task = false;
	uint32_t set_flags = 0;

	/*
	 * We must not apply this security policy on tasks which have opted out of mach hardening to
	 * avoid regressions in third party plugins and third party apps when using AMFI boot-args
	 */
	ipc_space_policy_t pol = ipc_policy_for_task(task);
	bool platform_binary = pol & IPC_SPACE_POLICY_PLATFORM;
#if XNU_TARGET_OS_OSX
	platform_binary &= !(pol & IPC_SPACE_POLICY_OPTED_OUT);
#endif /* XNU_TARGET_OS_OSX */

	/*
	 * On non-FPAC hardware, we allow gating PAC exceptions behind
	 * SKIP_PAC_EXCEPTION_ENTITLEMENT and the boot-arg.
	 */
	if (!gARM_FEAT_FPAC && enable_pac_exception &&
	    IOTaskHasEntitlement(task, SKIP_PAC_EXCEPTION_ENTITLEMENT)) {
		return;
	}

	if (IOTaskHasEntitlement(task, PAC_EXCEPTION_ENTITLEMENT) ||
	    (task_get_platform_restrictions_version(task) >= 1)) {
		pac_hardened_task = true;
		set_flags |= TFRO_PAC_ENFORCE_USER_STATE;
	}

	/* On non-FPAC hardware, gate the fatal property behind entitlements and boot-arg. */
	if (pac_hardened_task ||
	    ((enable_pac_exception || gARM_FEAT_FPAC) && platform_binary)) {
		set_flags |= TFRO_PAC_EXC_FATAL;
	}

	if (set_flags != 0) {
		task_ro_flags_set(task, set_flags);
	}
}

bool
task_is_pac_exception_fatal(
	task_t task)
{
	assert(task != TASK_NULL);
	return !!(task_ro_flags_get(task) & TFRO_PAC_EXC_FATAL);
}
#endif /* __has_feature(ptrauth_calls) */

/*
 * FATAL_EXCEPTION_ENTITLEMENT, if present, will contain a list of
 * conditions for which access violations should deliver SIGKILL rather than
 * SIGSEGV.  This is a hardening measure intended for use by applications
 * that are able to handle the stricter error handling behavior.  Currently
 * this supports FATAL_EXCEPTION_ENTITLEMENT_JIT, which is documented in
 * user_fault_in_self_restrict_mode().
 */
#define FATAL_EXCEPTION_ENTITLEMENT "com.apple.security.fatal-exceptions"
#define FATAL_EXCEPTION_ENTITLEMENT_JIT "jit"


void
task_set_jit_flags(
	task_t task)
{
	assert(task != TASK_NULL);
	if (IOTaskHasStringEntitlement(task, FATAL_EXCEPTION_ENTITLEMENT, FATAL_EXCEPTION_ENTITLEMENT_JIT)) {
		task_ro_flags_set(task, TFRO_JIT_EXC_FATAL);
	}

}

bool
task_is_jit_exception_fatal(
	__unused task_t task)
{
#if !defined(XNU_PLATFORM_MacOSX)
	return true;
#else
	assert(task != TASK_NULL);
	return !!(task_ro_flags_get(task) & TFRO_JIT_EXC_FATAL);
#endif
}

bool
task_needs_user_signed_thread_state(
	task_t task)
{
	assert(task != TASK_NULL);
	return !!(task_ro_flags_get(task) & TFRO_PAC_ENFORCE_USER_STATE);
}

void
task_set_tecs(task_t task)
{
	if (task == TASK_NULL) {
		task = current_task();
	}

	if (!machine_csv(CPUVN_CI)) {
		return;
	}

	LCK_MTX_ASSERT(&task->lock, LCK_MTX_ASSERT_NOTOWNED);

	task_lock(task);

	task->t_flags |= TF_TECS;

	thread_t thread;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		machine_tecs(thread);
	}
	task_unlock(task);
}

kern_return_t
task_test_sync_upcall(
	task_t     task,
	ipc_port_t send_port)
{
#if DEVELOPMENT || DEBUG
	if (task != current_task() || !IPC_PORT_VALID(send_port)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* Block on sync kernel upcall on the given send port */
	mach_test_sync_upcall(send_port);

	ipc_port_release_send(send_port);
	return KERN_SUCCESS;
#else
	(void)task;
	(void)send_port;
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
task_test_async_upcall_propagation(
	task_t      task,
	ipc_port_t  send_port,
	int         qos,
	int         iotier)
{
#if DEVELOPMENT || DEBUG
	kern_return_t kr;

	if (task != current_task() || !IPC_PORT_VALID(send_port)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (qos < THREAD_QOS_DEFAULT || qos > THREAD_QOS_USER_INTERACTIVE ||
	    iotier < THROTTLE_LEVEL_START || iotier > THROTTLE_LEVEL_END) {
		return KERN_INVALID_ARGUMENT;
	}

	struct thread_attr_for_ipc_propagation attr = {
		.tafip_iotier = iotier,
		.tafip_qos = qos
	};

	/* Apply propagate attr to port */
	kr = ipc_port_propagate_thread_attr(send_port, attr);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	thread_enable_send_importance(current_thread(), TRUE);

	/* Perform an async kernel upcall on the given send port */
	mach_test_async_upcall(send_port);
	thread_enable_send_importance(current_thread(), FALSE);

	ipc_port_release_send(send_port);
	return KERN_SUCCESS;
#else
	(void)task;
	(void)send_port;
	(void)qos;
	(void)iotier;
	return KERN_NOT_SUPPORTED;
#endif
}

#if CONFIG_PROC_RESOURCE_LIMITS
mach_port_name_t
current_task_get_fatal_port_name(void)
{
	mach_port_t task_fatal_port = MACH_PORT_NULL;
	mach_port_name_t port_name = 0;

	task_fatal_port = task_allocate_fatal_port();

	if (task_fatal_port) {
		ipc_object_copyout(current_space(), task_fatal_port,
		    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
		    NULL, &port_name);
	}

	return port_name;
}
#endif /* CONFIG_PROC_RESOURCE_LIMITS */

#if defined(__x86_64__)
bool
curtask_get_insn_copy_optout(void)
{
	bool optout;
	task_t cur_task = current_task();

	task_lock(cur_task);
	optout = (cur_task->t_flags & TF_INSN_COPY_OPTOUT) ? true : false;
	task_unlock(cur_task);

	return optout;
}

void
curtask_set_insn_copy_optout(void)
{
	task_t cur_task = current_task();

	task_lock(cur_task);

	cur_task->t_flags |= TF_INSN_COPY_OPTOUT;

	thread_t thread;
	queue_iterate(&cur_task->threads, thread, thread_t, task_threads) {
		machine_thread_set_insn_copy_optout(thread);
	}
	task_unlock(cur_task);
}
#endif /* defined(__x86_64__) */

void
task_get_corpse_vmobject_list(task_t task, vmobject_list_output_t* list, size_t* list_size)
{
	assert(task);
	assert(list_size);

	*list = task->corpse_vmobject_list;
	*list_size = (size_t)task->corpse_vmobject_list_size;
}

__abortlike
static void
panic_proc_ro_task_backref_mismatch(task_t t, proc_ro_t ro)
{
	panic("proc_ro->task backref mismatch: t=%p, ro=%p, "
	    "proc_ro_task(ro)=%p", t, ro, proc_ro_task(ro));
}

proc_ro_t
task_get_ro(task_t t)
{
	proc_ro_t ro = (proc_ro_t)t->bsd_info_ro;

	zone_require_ro(ZONE_ID_PROC_RO, sizeof(struct proc_ro), ro);
	if (__improbable(proc_ro_task(ro) != t)) {
		panic_proc_ro_task_backref_mismatch(t, ro);
	}

	return ro;
}

uint32_t
task_ro_flags_get(task_t task)
{
	return task_get_ro(task)->t_flags_ro;
}

void
task_ro_flags_set(task_t task, uint32_t flags)
{
	zalloc_ro_update_field_atomic(ZONE_ID_PROC_RO, task_get_ro(task),
	    t_flags_ro, ZRO_ATOMIC_OR_32, flags);
}

void
task_ro_flags_clear(task_t task, uint32_t flags)
{
	zalloc_ro_update_field_atomic(ZONE_ID_PROC_RO, task_get_ro(task),
	    t_flags_ro, ZRO_ATOMIC_AND_32, ~flags);
}

task_control_port_options_t
task_get_control_port_options(task_t task)
{
	return task_get_ro(task)->task_control_port_options;
}

/*
 * intentionally static, as calling this after the task has been started
 * will have no affect, control ports cannot go from immovable back to movable
 */
static void
task_set_control_port_options(task_t task, task_control_port_options_t opts)
{
	zalloc_ro_update_field(ZONE_ID_PROC_RO, task_get_ro(task),
	    task_control_port_options, &opts);
}

/*!
 * @function kdp_task_is_locked
 *
 * @abstract
 * Checks if task is locked.
 *
 * @discussion
 * NOT SAFE: To be used only by kernel debugger.
 *
 * @param task task to check
 *
 * @returns TRUE if the task is locked.
 */
boolean_t
kdp_task_is_locked(task_t task)
{
	return kdp_lck_mtx_lock_spin_is_acquired(&task->lock);
}

#if DEBUG || DEVELOPMENT
/**
 *
 * Check if a threshold limit is valid based on the actual phys memory
 * limit. If they are same, race conditions may arise, so we have to prevent
 * it to happen.
 */
static diagthreshold_check_return
task_check_memorythreshold_is_valid(task_t task, uint64_t new_limit, bool is_diagnostics_value)
{
	int phys_limit_mb;
	kern_return_t ret_value;
	bool threshold_enabled;
	bool dummy;
	ret_value = ledger_is_diag_threshold_enabled(task->ledger, task_ledgers.phys_footprint, &threshold_enabled);
	if (ret_value != KERN_SUCCESS) {
		return ret_value;
	}
	if (is_diagnostics_value == true) {
		ret_value = task_get_phys_footprint_limit(task, &phys_limit_mb);
	} else {
		uint64_t diag_limit;
		ret_value = task_get_diag_footprint_limit_internal(task, &diag_limit, &dummy);
		phys_limit_mb = (int)(diag_limit >> 20);
	}
	if (ret_value != KERN_SUCCESS) {
		return ret_value;
	}
	if (phys_limit_mb == (int)  new_limit) {
		if (threshold_enabled == false) {
			return THRESHOLD_IS_SAME_AS_LIMIT_FLAG_DISABLED;
		} else {
			return THRESHOLD_IS_SAME_AS_LIMIT_FLAG_ENABLED;
		}
	}
	if (threshold_enabled == false) {
		return THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_DISABLED;
	} else {
		return THRESHOLD_IS_NOT_SAME_AS_LIMIT_FLAG_ENABLED;
	}
}
#endif

#if CONFIG_EXCLAVES
kern_return_t
task_add_conclave(task_t task, void *vnode, int64_t off, const char *task_conclave_id)
{
	/*
	 * Only launchd or properly entitled tasks can attach tasks to
	 * conclaves.
	 */
	if (!exclaves_has_priv(current_task(), EXCLAVES_PRIV_CONCLAVE_SPAWN)) {
		return KERN_DENIED;
	}

	/*
	 * Only entitled tasks can have conclaves attached.
	 * Allow tasks which have the SPAWN privilege to also host conclaves.
	 * This allows xpc proxy to add a conclave before execing a daemon.
	 */
	if (!exclaves_has_priv_vnode(vnode, off, EXCLAVES_PRIV_CONCLAVE_HOST) &&
	    !exclaves_has_priv_vnode(vnode, off, EXCLAVES_PRIV_CONCLAVE_SPAWN)) {
		return KERN_DENIED;
	}

	return exclaves_conclave_attach(task_conclave_id, task);
}

kern_return_t
task_launch_conclave(mach_port_name_t port __unused)
{
	kern_return_t kr = KERN_FAILURE;
	assert3u(port, ==, MACH_PORT_NULL);
	exclaves_resource_t *conclave = task_get_conclave(current_task());
	if (conclave == NULL || exclaves_is_forwarding_resource(conclave)) {
		return kr;
	}

	kr = exclaves_conclave_launch(conclave);
	if (kr != KERN_SUCCESS) {
		return kr;
	}
	task_set_conclave_taint(current_task());

	return KERN_SUCCESS;
}

kern_return_t
task_inherit_conclave(task_t old_task, task_t new_task, void *vnode, int64_t off)
{
	if (old_task->conclave == NULL ||
	    !exclaves_conclave_is_attached(old_task->conclave)) {
		return KERN_SUCCESS;
	}

	/*
	 * Only launchd or properly entitled tasks can attach tasks to
	 * conclaves.
	 */
	if (!exclaves_has_priv(current_task(), EXCLAVES_PRIV_CONCLAVE_SPAWN)) {
		return KERN_DENIED;
	}

	/*
	 * Only entitled tasks can have conclaves attached.
	 */
	if (!exclaves_has_priv_vnode(vnode, off, EXCLAVES_PRIV_CONCLAVE_HOST)) {
		return KERN_DENIED;
	}

	return exclaves_conclave_inherit(old_task->conclave, old_task, new_task);
}

void
task_clear_conclave(task_t task)
{
	if (task->exclave_crash_info) {
		kfree_data(task->exclave_crash_info, CONCLAVE_CRASH_BUFFER_PAGECOUNT * PAGE_SIZE);
		task->exclave_crash_info = NULL;
	}

	if (task->conclave == NULL) {
		return;
	}

	/*
	 * XXX
	 * This should only fail if either the conclave is in an unexpected
	 * state (i.e. not ATTACHED) or if the wrong port is supplied.
	 * We should re-visit this and make sure we guarantee the above
	 * constraints.
	 */
	__assert_only kern_return_t ret =
	    exclaves_conclave_detach(task->conclave, task);
	assert3u(ret, ==, KERN_SUCCESS);
}

void
task_stop_conclave(task_t task, bool gather_crash_bt)
{
	thread_t thread = current_thread();

	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return;
	}

	if (task_should_panic_on_exit_due_to_conclave_taint(task)) {
		panic("Conclave tainted task %p terminated\n", task);
	}

	/* Stash the task on current thread for conclave teardown */
	thread->conclave_stop_task = task;

	__assert_only kern_return_t ret =
	    exclaves_conclave_stop(task->conclave, gather_crash_bt);

	thread->conclave_stop_task = TASK_NULL;

	assert3u(ret, ==, KERN_SUCCESS);
}

void
task_suspend_conclave(task_t task)
{
	thread_t thread = current_thread();

	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return;
	}

	/* Stash the task on current thread for conclave teardown */
	thread->conclave_stop_task = task;

	__assert_only kern_return_t ret =
	    exclaves_conclave_suspend(task->conclave);

	thread->conclave_stop_task = TASK_NULL;

	assert3u(ret, ==, KERN_SUCCESS);
}

void
task_resume_conclave(task_t task)
{
	thread_t thread = current_thread();

	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return;
	}

	/* Stash the task on current thread for conclave teardown */
	thread->conclave_stop_task = task;

	__assert_only kern_return_t ret =
	    exclaves_conclave_resume(task->conclave);

	thread->conclave_stop_task = TASK_NULL;

	assert3u(ret, ==, KERN_SUCCESS);
}

kern_return_t
task_stop_conclave_upcall(void)
{
	task_t task = current_task();
	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return KERN_INVALID_TASK;
	}

	return exclaves_conclave_stop_upcall(task->conclave);
}

kern_return_t
task_stop_conclave_upcall_complete(void)
{
	task_t task = current_task();
	thread_t thread = current_thread();

	if (!(thread->th_exclaves_state & TH_EXCLAVES_STOP_UPCALL_PENDING)) {
		return KERN_SUCCESS;
	}

	assert3p(task->conclave, !=, NULL);

	return exclaves_conclave_stop_upcall_complete(task->conclave, task);
}

kern_return_t
task_suspend_conclave_upcall(uint64_t *scid_list, size_t scid_list_count)
{
	task_t task = current_task();
	thread_t thread;
	int scid_count = 0;
	kern_return_t kr;
	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return KERN_INVALID_TASK;
	}

	kr = task_hold_and_wait(task, false);

	task_lock(task);
	queue_iterate(&task->threads, thread, thread_t, task_threads)
	{
		if (thread->th_exclaves_state & TH_EXCLAVES_RPC) {
			scid_list[scid_count++] = thread->th_exclaves_ipc_ctx.scid;
			if (scid_count >= scid_list_count) {
				break;
			}
		}
	}

	task_unlock(task);
	return kr;
}

kern_return_t
task_crash_info_conclave_upcall(task_t task, const struct conclave_sharedbuffer_t *shared_buf,
    uint32_t length)
{
	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return KERN_INVALID_TASK;
	}

	/* Allocate the buffer and memcpy it */
	int task_crash_info_buffer_size = 0;
	uint8_t * task_crash_info_buffer;

	if (!length) {
		printf("Conclave upcall: task_crash_info_conclave_upcall did not return any page addresses\n");
		return KERN_INVALID_ARGUMENT;
	}

	task_crash_info_buffer_size = CONCLAVE_CRASH_BUFFER_PAGECOUNT * PAGE_SIZE;
	assert3u(task_crash_info_buffer_size, >=, length);

	task_crash_info_buffer = kalloc_data(task_crash_info_buffer_size, Z_WAITOK);
	if (!task_crash_info_buffer) {
		panic("task_crash_info_conclave_upcall: cannot allocate buffer for task_info shared memory");
		return KERN_INVALID_ARGUMENT;
	}

	uint8_t * dst = task_crash_info_buffer;
	uint32_t remaining = length;
	for (size_t i = 0; i < CONCLAVE_CRASH_BUFFER_PAGECOUNT; i++) {
		if (remaining) {
			memcpy(dst, (uint8_t*)phystokv((pmap_paddr_t)shared_buf->physaddr[i]), PAGE_SIZE);
			remaining = (remaining >= PAGE_SIZE) ? remaining - PAGE_SIZE : 0;
			dst += PAGE_SIZE;
		}
	}

	task_lock(task);
	if (task->exclave_crash_info == NULL && task->active) {
		task->exclave_crash_info = task_crash_info_buffer;
		task->exclave_crash_info_length = length;
		task_crash_info_buffer = NULL;
	}
	task_unlock(task);

	if (task_crash_info_buffer) {
		kfree_data(task_crash_info_buffer, task_crash_info_buffer_size);
	}

	return KERN_SUCCESS;
}

exclaves_resource_t *
task_get_conclave(task_t task)
{
	return task->conclave;
}

extern boolean_t IOPMRootDomainGetWillShutdown(void);

TUNABLE(bool, disable_conclave_taint, "disable_conclave_taint", true); /* Do not taint processes when they talk to conclave, so system does not panic when exit. */

static bool
task_should_panic_on_exit_due_to_conclave_taint(task_t task)
{
	/* Check if boot-arg to disable conclave taint is set */
	if (disable_conclave_taint) {
		return false;
	}

	/* Check if the system is shutting down */
	if (IOPMRootDomainGetWillShutdown()) {
		return false;
	}

	return task_is_conclave_tainted(task);
}

static bool
task_is_conclave_tainted(task_t task)
{
	return (task->t_exclave_state & TES_CONCLAVE_TAINTED) != 0 &&
	       !(task->t_exclave_state & TES_CONCLAVE_UNTAINTABLE);
}

static void
task_set_conclave_taint(task_t task)
{
	os_atomic_or(&task->t_exclave_state, TES_CONCLAVE_TAINTED, relaxed);
}

void
task_set_conclave_untaintable(task_t task)
{
	os_atomic_or(&task->t_exclave_state, TES_CONCLAVE_UNTAINTABLE, relaxed);
}

void
task_add_conclave_crash_info(task_t task, void *crash_info_ptr)
{
	__block kern_return_t error = KERN_SUCCESS;
	tb_error_t tberr = TB_ERROR_SUCCESS;
	void *crash_info;
	uint32_t crash_info_length = 0;

	if (task->conclave == NULL || exclaves_is_forwarding_resource(task->conclave)) {
		return;
	}

	if (task->exclave_crash_info_length == 0) {
		return;
	}

	error = kcdata_add_container_marker(crash_info_ptr, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVES, 0);
	if (error != KERN_SUCCESS) {
		return;
	}

	crash_info = task->exclave_crash_info;
	crash_info_length = task->exclave_crash_info_length;

	tberr = stackshot_stackshotresult__unmarshal(crash_info,
	    (uint64_t)crash_info_length, ^(stackshot_stackshotresult_s result){
		error = stackshot_exclaves_process_stackshot(&result, crash_info_ptr, false);
		if (error != KERN_SUCCESS) {
		        printf("task_add_conclave_crash_info: error processing stackshot result %d\n", error);
		}
	});
	if (tberr != TB_ERROR_SUCCESS) {
		printf("task_conclave_crash: task_add_conclave_crash_info could not unmarshal stackshot data 0x%x\n", tberr);
		error = KERN_FAILURE;
		goto error_exit;
	}

error_exit:
	kcdata_add_container_marker(crash_info_ptr, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVES, 0);

	return;
}

#endif /* CONFIG_EXCLAVES */

/* defined in bsd/kern/kern_proc.c */
extern void proc_name(int pid, char *buf, int size);
extern const char *proc_best_name(struct proc *p);

void
task_procname(task_t task, char *buf, int size)
{
	proc_name(task_pid(task), buf, size);
}

const char *
task_best_name(task_t task)
{
	return proc_best_name(task_get_proc_raw(task));
}


/*
 * Set a AST_SYNTHESIZE_MACH exception on the task.
 * This AST will consult the saved address in the vm_map and create a proper
 * MTE mach exception out of thin air.
 */
void
task_set_ast_synthesize_async_fault_mach_exception(task_t task)
{
	task_lock(task);

	if (!task->active) {
		task_unlock(task);
		return;
	}

	spl_t s = splsched();
	/* Set an AST on each of the task's threads, sending IPIs if needed */
	thread_t thread;
	queue_iterate(&task->threads, thread, thread_t, task_threads) {
		if (thread == current_thread()) {
			thread_ast_set(thread, AST_SYNTHESIZE_MACH);
			ast_propagate(thread);
		} else {
			processor_t processor;

			thread_lock(thread);
			thread_ast_set(thread, AST_SYNTHESIZE_MACH);
			processor = thread->last_processor;
			if (processor != PROCESSOR_NULL &&
			    processor->state == PROCESSOR_RUNNING &&
			    processor->active_thread == thread) {
				cause_ast_check(processor);
			}
			thread_unlock(thread);
		}
	};
	splx(s);

	task_unlock(task);
}
