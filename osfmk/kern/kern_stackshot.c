/*
 * Copyright (c) 2013-2020 Apple Inc. All rights reserved.
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


#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <mach/mach_vm.h>
#include <mach/clock_types.h>
#include <sys/code_signing.h>
#include <sys/errno.h>
#include <sys/stackshot.h>
#if defined(__arm64__)
#include <arm/cpu_internal.h>
#endif /* __arm64__ */
#ifdef IMPORTANCE_INHERITANCE
#include <ipc/ipc_importance.h>
#endif
#include <sys/appleapiopts.h>
#include <kern/debug.h>
#include <kern/block_hint.h>
#include <uuid/uuid.h>

#include <kdp/kdp_dyld.h>
#include <kdp/kdp_en_debugger.h>
#include <kdp/processor_core.h>
#include <kdp/kdp_common.h>

#include <libsa/types.h>
#include <libkern/version.h>
#include <libkern/section_keywords.h>

#include <string.h> /* bcopy */

#include <kern/kern_stackshot.h>
#include <kern/backtrace.h>
#include <kern/coalition.h>
#include <kern/epoch_sync.h>
#include <kern/exclaves_stackshot.h>
#include <kern/exclaves_inspection.h>
#include <kern/processor.h>
#include <kern/host_statistics.h>
#include <kern/counter.h>
#include <kern/thread.h>
#include <kern/thread_group.h>
#include <kern/task.h>
#include <kern/telemetry.h>
#include <kern/clock.h>
#include <kern/policy_internal.h>
#include <kern/socd_client.h>
#include <kern/startup.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_kern_xnu.h>
#include <vm/vm_pageout.h>
#include <vm/vm_fault.h>
#include <vm/vm_shared_region_xnu.h>
#include <vm/vm_compressor_xnu.h>
#include <libkern/OSKextLibPrivate.h>
#include <os/log.h>

#ifdef CONFIG_EXCLAVES
#include <kern/exclaves.tightbeam.h>
#endif /* CONFIG_EXCLAVES */

#include <kern/exclaves_test_stackshot.h>

#include <libkern/coreanalytics/coreanalytics.h>

#if defined(__x86_64__)
#include <i386/mp.h>
#include <i386/cpu_threads.h>
#endif

#include <pexpert/pexpert.h>

#if CONFIG_PERVASIVE_CPI
#include <kern/monotonic.h>
#endif /* CONFIG_PERVASIVE_CPI */

#include <san/kasan.h>

#if DEBUG || DEVELOPMENT
#define STACKSHOT_COLLECTS_DIAGNOSTICS 1
#define STACKSHOT_COLLECTS_LATENCY_INFO 1
#else
#define STACKSHOT_COLLECTS_DIAGNOSTICS 0
#define STACKSHOT_COLLECTS_LATENCY_INFO 0
#endif /* DEBUG || DEVELOPMENT */

#define STACKSHOT_COLLECTS_RDAR_126582377_DATA 0

#if defined(__AMP__)
#define STACKSHOT_NUM_WORKQUEUES 2
#else /* __AMP__ */
#define STACKSHOT_NUM_WORKQUEUES 1
#endif

#if defined(__arm64__)
#define STACKSHOT_NUM_BUFFERS MAX_CPU_CLUSTERS
#else /* __arm64__ */
#define STACKSHOT_NUM_BUFFERS 1
#endif /* __arm64__ */

/* The number of threads which will land a task in the hardest workqueue. */
#define STACKSHOT_HARDEST_THREADCOUNT 10

TUNABLE_DEV_WRITEABLE(unsigned int, stackshot_single_thread, "stackshot_single_thread", 0);

extern unsigned int not_in_kdp;

/* indicate to the compiler that some accesses are unaligned */
typedef uint64_t unaligned_u64 __attribute__((aligned(1)));

int kdp_snapshot                            = 0;

#pragma mark ---Stackshot Struct Definitions---

typedef struct linked_kcdata_descriptor {
	struct kcdata_descriptor          kcdata;
	struct linked_kcdata_descriptor  *next;
} * linked_kcdata_descriptor_t;

struct stackshot_workitem {
	task_t                        sswi_task;
	linked_kcdata_descriptor_t    sswi_data; /* The kcdata for this task. */
	int                           sswi_idx;  /* The index of this job, used for ordering kcdata across multiple queues. */
};

struct stackshot_workqueue {
	uint32_t _Atomic              sswq_num_items; /* Only modified by main CPU */
	uint32_t _Atomic              sswq_cur_item; /* Modified by all CPUs */
	size_t                        sswq_capacity; /* Constant after preflight */
	bool _Atomic                  sswq_populated; /* Only modified by main CPU */
	struct stackshot_workitem    *__counted_by(capacity) sswq_items;
};

struct freelist_entry {
	struct freelist_entry        *fl_next; /* Next entry in the freelist */
	size_t                        fl_size; /* Size of the entry (must be >= sizeof(struct freelist_entry)) */
};

struct stackshot_buffer {
	void                         *ssb_ptr; /* Base of buffer */
	size_t                        ssb_size;
	size_t _Atomic                ssb_used;
	struct freelist_entry        *ssb_freelist; /* First freelist entry */
	int _Atomic                   ssb_freelist_lock;
	size_t _Atomic                ssb_overhead; /* Total amount ever freed (even if re-allocated from freelist) */
};

struct kdp_snapshot_args {
	int                           pid;
	void                         *buffer;
	struct kcdata_descriptor     *descriptor;
	uint32_t                      buffer_size;
	uint64_t                      flags;
	uint64_t                      since_timestamp;
	uint32_t                      pagetable_mask;
};

/*
 * Keep a simple cache of the most recent validation done at a page granularity
 * to avoid the expensive software KVA-to-phys translation in the VM.
 */

struct _stackshot_validation_state {
	vm_offset_t last_valid_page_kva;
	size_t last_valid_size;
};

/* CPU-local generation counts for PLH */
struct _stackshot_plh_gen_state {
	uint8_t                *pgs_gen;       /* last 'gen #' seen in */
	int16_t                 pgs_curgen_min; /* min idx seen for this gen */
	int16_t                 pgs_curgen_max; /* max idx seen for this gen */
	uint8_t                 pgs_curgen;     /* current gen */
};

/*
 * For port labels, we have a small hash table we use to track the
 * struct ipc_service_port_label pointers we see along the way.
 * This structure encapsulates the global state.
 *
 * The hash table is insert-only, similar to "intern"ing strings.  It's
 * only used an manipulated in during the stackshot collection.  We use
 * seperate chaining, with the hash elements and chains being int16_ts
 * indexes into the parallel arrays, with -1 ending the chain.  Array indices are
 * allocated using a bump allocator.
 *
 * The parallel arrays contain:
 *      - plh_array[idx]	the pointer entered
 *      - plh_chains[idx]	the hash chain
 *      - plh_gen[idx]		the last 'generation #' seen
 *
 * Generation IDs are used to track entries looked up in the current
 * task; 0 is never used, and the plh_gen array is cleared to 0 on
 * rollover.
 *
 * The portlabel_ids we report externally are just the index in the array,
 * plus 1 to avoid 0 as a value.  0 is NONE, -1 is UNKNOWN (e.g. there is
 * one, but we ran out of space)
 */
struct port_label_hash {
	int _Atomic             plh_lock;       /* lock for concurrent modifications to this plh */
	uint16_t                plh_size;       /* size of allocations; 0 disables tracking */
	uint16_t                plh_count;      /* count of used entries in plh_array */
	struct ipc_service_port_label **plh_array; /* _size allocated, _count used */
	int16_t                *plh_chains;    /* _size allocated */
	int16_t                *plh_hash;      /* (1 << STACKSHOT_PLH_SHIFT) entry hash table: hash(ptr) -> array index */
#if DEVELOPMENT || DEBUG
	/* statistics */
	uint32_t _Atomic        plh_lookups;    /* # lookups or inserts */
	uint32_t _Atomic        plh_found;
	uint32_t _Atomic        plh_found_depth;
	uint32_t _Atomic        plh_insert;
	uint32_t _Atomic        plh_insert_depth;
	uint32_t _Atomic        plh_bad;
	uint32_t _Atomic        plh_bad_depth;
	uint32_t _Atomic        plh_lookup_send;
	uint32_t _Atomic        plh_lookup_receive;
#define PLH_STAT_OP(...)    (void)(__VA_ARGS__)
#else /* DEVELOPMENT || DEBUG */
#define PLH_STAT_OP(...)    (void)(0)
#endif /* DEVELOPMENT || DEBUG */
};

#define plh_lock(plh) while(!os_atomic_cmpxchg(&(plh)->plh_lock, 0, 1, acquire)) { loop_wait(); }
#define plh_unlock(plh) os_atomic_store(&(plh)->plh_lock, 0, release);

#define STACKSHOT_PLH_SHIFT    7
#define STACKSHOT_PLH_SIZE_MAX ((kdp_ipc_have_splabel)? 1024 : 0)
size_t stackshot_port_label_size = (2 * (1u << STACKSHOT_PLH_SHIFT));
#define STASKSHOT_PLH_SIZE(x) MIN((x), STACKSHOT_PLH_SIZE_MAX)

struct stackshot_cpu_context {
	bool                               scc_can_work; /* Whether the CPU can do more stackshot work */
	bool                               scc_did_work; /* Whether the CPU actually did any stackshot work */
	linked_kcdata_descriptor_t         scc_kcdata_head; /* See `linked_kcdata_alloc_callback */
	linked_kcdata_descriptor_t         scc_kcdata_tail; /* See `linked_kcdata_alloc_callback */
	uintptr_t                         *scc_stack_buffer; /* A buffer for stacktraces. */
	struct stackshot_fault_stats       scc_fault_stats;
	struct _stackshot_validation_state scc_validation_state;
	struct _stackshot_plh_gen_state    scc_plh_gen;
};

/*
 * When directly modifying the stackshot state, always use the macros below to
 * work wth this enum - the higher order bits are used to store an error code
 * in the case of SS_ERRORED.
 *
 *        +------------------------------------+-------------------+
 *        |                                    |                   |
 *        v                                    |                   |
 * +-------------+     +----------+     +------------+     +------------+
 * | SS_INACTIVE |---->| SS_SETUP |---->| SS_RUNNING |---->| SS_ERRORED |
 * +-------------+     +----------+     +------------+     +------------+
 *                         |  |                |                ^  |
 *                         |  +----------------|----------------+  |
 * +-------------+         |                   |                   |
 * | SS_PANICKED |<--------+-------------------+                   |
 * +-------------+                                                 |
 *        ^                                                        |
 *        |                                                        |
 *        +--------------------------------------------------------+
 */
__enum_closed_decl(stackshot_state_t, uint, {
	SS_INACTIVE = 0x0, /* -> SS_SETUP */
	SS_SETUP    = 0x1, /* -> SS_RUNNING, SS_ERRORED, SS_PANICKED */
	SS_RUNNING  = 0x2, /* -> SS_ERRORED, SS_PANICKED, SS_INACTIVE */
	SS_ERRORED  = 0x3, /* -> SS_INACTIVE, SS_PANICKED */
	SS_PANICKED = 0x4, /* -> N/A */
	_SS_COUNT
});

static_assert(_SS_COUNT <= 0x5);
/* Get the stackshot state ID from a stackshot_state_t. */
#define SS_STATE(state) ((state) & 0x7u)
/* Get the error code from a stackshot_state_t. */
#define SS_ERRCODE(state) ((state) >> 3)
/* Make a stackshot error state with a given code. */
#define SS_MKERR(code) (((code) << 3) | SS_ERRORED)

struct stackshot_context {
	/* Constants & Arguments */
	struct kdp_snapshot_args      sc_args;
	int                           sc_calling_cpuid;
	int                           sc_main_cpuid;
	bool                          sc_enable_faulting;
	uint64_t                      sc_microsecs; /* Timestamp */
	bool                          sc_panic_stackshot;
	size_t                        sc_min_kcdata_size;
	bool                          sc_is_singlethreaded;

	/* State & Errors */
	stackshot_state_t _Atomic     sc_state; /* Only modified by calling CPU, main CPU, or panicking CPU. See comment above type definition for details. */
	kern_return_t                 sc_retval; /* The return value of the main thread */
	uint32_t _Atomic              sc_cpus_working;

	/* KCData */
	linked_kcdata_descriptor_t    sc_pretask_kcdata;
	linked_kcdata_descriptor_t    sc_posttask_kcdata;
	kcdata_descriptor_t           sc_finalized_kcdata;

	/* Buffers & Queues */
	struct stackshot_buffer       __counted_by(num_buffers) sc_buffers[STACKSHOT_NUM_BUFFERS];
	size_t                        sc_num_buffers;
	struct stackshot_workqueue    __counted_by(STACKSHOT_NUM_WORKQUEUES) sc_workqueues[STACKSHOT_NUM_WORKQUEUES];
	struct port_label_hash        sc_plh;

	/* Statistics */
	struct stackshot_duration_v2  sc_duration;
	uint32_t                      sc_bytes_traced;
	uint32_t                      sc_bytes_uncompressed;
#if STACKSHOT_COLLECTS_LATENCY_INFO
	struct stackshot_latency_collection_v2 sc_latency;
#endif
};

#define STACKSHOT_DEBUG_TRACEBUF_SIZE 16

struct stackshot_trace_entry {
	int               sste_line_no;
	uint64_t          sste_timestamp;
	mach_vm_address_t sste_data;
};

struct stackshot_trace_buffer {
	uint64_t                     sstb_last_trace_timestamp;
	size_t                       sstb_tail_idx;
	size_t                       sstb_size;
	struct stackshot_trace_entry __counted_by(STACKSHOT_DEBUG_TRACEBUF_SIZE) sstb_entries[STACKSHOT_DEBUG_TRACEBUF_SIZE];
};

#pragma mark ---Stackshot State and Data---

/*
 * Two stackshot states, one for panic and one for normal.
 * That way, we can take a stackshot during a panic without clobbering state.
 */
#define STACKSHOT_CTX_IDX_NORMAL 0
#define STACKSHOT_CTX_IDX_PANIC  1
size_t cur_stackshot_ctx_idx   = STACKSHOT_CTX_IDX_NORMAL;
struct stackshot_context stackshot_contexts[2] = {{0}, {0}};
#define stackshot_ctx (stackshot_contexts[cur_stackshot_ctx_idx])
#define stackshot_args (stackshot_ctx.sc_args)
#define stackshot_flags (stackshot_args.flags)

static struct {
	uint64_t last_abs_start;      /* start time of last stackshot */
	uint64_t last_abs_end;        /* end time of last stackshot */
	uint64_t stackshots_taken;    /* total stackshots taken since boot */
	uint64_t stackshots_duration; /* total abs time spent in stackshot_trap() since boot */
} stackshot_stats = { 0 };

#if STACKSHOT_COLLECTS_LATENCY_INFO
static struct stackshot_latency_cpu PERCPU_DATA(stackshot_cpu_latency_percpu);
#define stackshot_cpu_latency (*PERCPU_GET(stackshot_cpu_latency_percpu))
#endif

static struct stackshot_cpu_context PERCPU_DATA(stackshot_cpu_ctx_percpu);
#define stackshot_cpu_ctx (*PERCPU_GET(stackshot_cpu_ctx_percpu))

static struct kcdata_descriptor PERCPU_DATA(stackshot_kcdata_percpu);
#define stackshot_kcdata_p (PERCPU_GET(stackshot_kcdata_percpu))

#if STACKSHOT_COLLECTS_LATENCY_INFO
static bool collect_latency_info = true;
#endif

static uint64_t stackshot_max_fault_time;

#if STACKSHOT_COLLECTS_DIAGNOSTICS
static struct stackshot_trace_buffer PERCPU_DATA(stackshot_trace_buffer);
#endif

#pragma mark ---Stackshot Global State---

uint32_t stackshot_estimate_adj = 25; /* experiment factor: 0-100, adjust our estimate up by this amount */

static uint32_t stackshot_initial_estimate;
static uint32_t stackshot_initial_estimate_adj;
static uint64_t stackshot_duration_prior_abs;   /* prior attempts, abs */
static unaligned_u64 * stackshot_duration_outer;
static uint64_t stackshot_tries;

void * kernel_stackshot_buf   = NULL; /* Pointer to buffer for stackshots triggered from the kernel and retrieved later */
int kernel_stackshot_buf_size = 0;

void * stackshot_snapbuf = NULL; /* Used by stack_snapshot2 (to be removed) */

#if CONFIG_EXCLAVES
static ctid_t *stackshot_exclave_inspect_ctids = NULL;
static size_t stackshot_exclave_inspect_ctid_count = 0;
static size_t stackshot_exclave_inspect_ctid_capacity = 0;

static kern_return_t stackshot_exclave_kr = KERN_SUCCESS;
#endif /* CONFIG_EXCLAVES */

#if DEBUG || DEVELOPMENT
TUNABLE(bool, disable_exclave_stackshot, "-disable_exclave_stackshot", false);
#else
const bool disable_exclave_stackshot = false;
#endif

#pragma mark ---Stackshot Static Function Declarations---

__private_extern__ void stackshot_init( void );
static boolean_t        memory_iszero(void *addr, size_t size);
static void             stackshot_cpu_do_work(void);
static kern_return_t    stackshot_finalize_kcdata(void);
static kern_return_t    stackshot_finalize_singlethreaded_kcdata(void);
static kern_return_t    stackshot_collect_kcdata(void);
static int              kdp_stackshot_kcdata_format();
static void             kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap);
static vm_offset_t      stackshot_find_phys(vm_map_t map, vm_offset_t target_addr, kdp_fault_flags_t fault_flags, uint32_t *kdp_fault_result_flags);
static boolean_t        stackshot_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, boolean_t try_fault, uint32_t *kdp_fault_result);
static int              stackshot_copyin_string(task_t task, uint64_t addr, char *buf, int buf_sz, boolean_t try_fault, uint32_t *kdp_fault_results);
static boolean_t        stackshot_copyin_word(task_t task, uint64_t addr, uint64_t *result, boolean_t try_fault, uint32_t *kdp_fault_results);
static uint64_t         proc_was_throttled_from_task(task_t task);
static void             stackshot_thread_wait_owner_info(thread_t thread, thread_waitinfo_v2_t * waitinfo);
static int              stackshot_thread_has_valid_waitinfo(thread_t thread);
static void             stackshot_thread_turnstileinfo(thread_t thread, thread_turnstileinfo_v2_t *tsinfo);
static int              stackshot_thread_has_valid_turnstileinfo(thread_t thread);
static uint32_t         get_stackshot_estsize(uint32_t prev_size_hint, uint32_t adj, uint64_t trace_flags, pid_t target_pid);
static kern_return_t    kdp_snapshot_preflight_internal(struct kdp_snapshot_args args);

#if CONFIG_COALITIONS
static void             stackshot_coalition_jetsam_count(void *arg, int i, coalition_t coal);
static void             stackshot_coalition_jetsam_snapshot(void *arg, int i, coalition_t coal);
#endif /* CONFIG_COALITIONS */

#if CONFIG_THREAD_GROUPS
static void             stackshot_thread_group_count(void *arg, int i, struct thread_group *tg);
static void             stackshot_thread_group_snapshot(void *arg, int i, struct thread_group *tg);
#endif /* CONFIG_THREAD_GROUPS */

extern uint64_t         workqueue_get_task_ss_flags_from_pwq_state_kdp(void *proc);

static kcdata_descriptor_t linked_kcdata_alloc_callback(kcdata_descriptor_t descriptor, size_t min_size);

#pragma mark ---Stackshot Externs---

struct proc;
extern int              proc_pid(struct proc *p);
extern uint64_t         proc_uniqueid(void *p);
extern uint64_t         proc_was_throttled(void *p);
extern uint64_t         proc_did_throttle(void *p);
extern int              proc_exiting(void *p);
extern int              proc_in_teardown(void *p);
static uint64_t         proc_did_throttle_from_task(task_t task);
extern void             proc_name_kdp(struct proc *p, char * buf, int size);
extern int              proc_threadname_kdp(void * uth, char * buf, size_t size);
extern void             proc_starttime_kdp(void * p, uint64_t * tv_sec, uint64_t * tv_usec, uint64_t * abstime);
extern void             proc_archinfo_kdp(void* p, cpu_type_t* cputype, cpu_subtype_t* cpusubtype);
extern uint64_t         proc_getcsflags_kdp(void * p);
extern boolean_t        proc_binary_uuid_kdp(task_t task, uuid_t uuid);
extern int              memorystatus_get_pressure_status_kdp(void);
extern void             memorystatus_proc_flags_unsafe(void * v, boolean_t *is_dirty, boolean_t *is_dirty_tracked, boolean_t *allow_idle_exit);
extern void             panic_stackshot_release_lock(void);

extern int count_busy_buffers(void); /* must track with declaration in bsd/sys/buf_internal.h */

#if CONFIG_TELEMETRY
extern kern_return_t stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif /* CONFIG_TELEMETRY */

extern kern_return_t kern_stack_snapshot_with_reason(char* reason);
extern kern_return_t kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user);

static size_t stackshot_plh_est_size(void);

#if CONFIG_EXCLAVES
static kern_return_t collect_exclave_threads(uint64_t);
static kern_return_t stackshot_setup_exclave_waitlist(void);
#endif

/*
 * Validates that the given address for a word is both a valid page and has
 * default caching attributes for the current map.
 */
bool machine_trace_thread_validate_kva(vm_offset_t);
/*
 * Validates a region that stackshot will potentially inspect.
 */
static bool _stackshot_validate_kva(vm_offset_t, size_t);
/*
 * Must be called whenever stackshot is re-driven.
 */
static void _stackshot_validation_reset(void);
/*
 * A kdp-safe strlen() call.  Returns:
 *      -1 if we reach maxlen or a bad address before the end of the string, or
 *      strlen(s)
 */
static long _stackshot_strlen(const char *s, size_t maxlen);

#define MAX_FRAMES 1000
#define STACKSHOT_PAGETABLE_BUFSZ 4000
#define MAX_LOADINFOS 500
#define MAX_DYLD_COMPACTINFO (20 * 1024)  // max bytes of compactinfo to include per proc/shared region
#define TASK_IMP_WALK_LIMIT 20

typedef struct thread_snapshot *thread_snapshot_t;
typedef struct task_snapshot *task_snapshot_t;

#if CONFIG_KDP_INTERACTIVE_DEBUGGING
extern kdp_send_t    kdp_en_send_pkt;
#endif

/*
 * Stackshot locking and other defines.
 */
LCK_GRP_DECLARE(stackshot_subsys_lck_grp, "stackshot_subsys_lock");
LCK_MTX_DECLARE(stackshot_subsys_mutex, &stackshot_subsys_lck_grp);

#define STACKSHOT_SUBSYS_LOCK() lck_mtx_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_TRY_LOCK() lck_mtx_try_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_UNLOCK() lck_mtx_unlock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_ASSERT_LOCKED() lck_mtx_assert(&stackshot_subsys_mutex, LCK_MTX_ASSERT_OWNED);

#define SANE_BOOTPROFILE_TRACEBUF_SIZE (64ULL * 1024ULL * 1024ULL)
#define SANE_TRACEBUF_SIZE (8ULL * 1024ULL * 1024ULL)

#define TRACEBUF_SIZE_PER_GB (1024ULL * 1024ULL)
#define GIGABYTES (1024ULL * 1024ULL * 1024ULL)

SECURITY_READ_ONLY_LATE(static uint32_t) max_tracebuf_size = SANE_TRACEBUF_SIZE;

/*
 * We currently set a ceiling of 3 milliseconds spent in the kdp fault path
 * for non-panic stackshots where faulting is requested.
 */
#define KDP_FAULT_PATH_MAX_TIME_PER_STACKSHOT_NSECS (3 * NSEC_PER_MSEC)


#ifndef ROUNDUP
#define ROUNDUP(x, y)            ((((x)+(y)-1)/(y))*(y))
#endif

#define STACKSHOT_QUEUE_LABEL_MAXSIZE  64

#pragma mark ---Stackshot Useful Macros---

#define kcd_end_address(kcd) ((void *)((uint64_t)((kcd)->kcd_addr_begin) + kcdata_memory_get_used_bytes((kcd))))
#define kcd_max_address(kcd) ((void *)((kcd)->kcd_addr_begin + (kcd)->kcd_length))
/*
 * Use of the kcd_exit_on_error(action) macro requires a local
 * 'kern_return_t error' variable and 'error_exit' label.
 */
#define kcd_exit_on_error(action)                      \
	do {                                               \
	    if (KERN_SUCCESS != (error = (action))) {      \
	        STACKSHOT_TRACE(error);                    \
	        if (error == KERN_RESOURCE_SHORTAGE) {     \
	            error = KERN_INSUFFICIENT_BUFFER_SIZE; \
	        }                                          \
	        goto error_exit;                           \
	    }                                              \
	} while (0); /* end kcd_exit_on_error */

#if defined(__arm64__)
#define loop_wait_noguard() __builtin_arm_wfe()
#elif defined(__x86_64__)
#define loop_wait_noguard() __builtin_ia32_pause()
#else
#define loop_wait_noguard()
#endif /* __x86_64__ */

#define loop_wait() { loop_wait_noguard(); stackshot_panic_guard(); }

static inline void stackshot_panic_guard(void);

static __attribute__((noreturn, noinline)) void
stackshot_panic_spin(void)
{
	if (stackshot_cpu_ctx.scc_can_work) {
		stackshot_cpu_ctx.scc_can_work = false;
		os_atomic_dec(&stackshot_ctx.sc_cpus_working, acquire);
	}
	if (stackshot_ctx.sc_calling_cpuid == cpu_number()) {
		while (os_atomic_load(&stackshot_ctx.sc_cpus_working, acquire) != 0) {
			loop_wait_noguard();
		}
		panic_stackshot_release_lock();
	}
	while (1) {
		loop_wait_noguard();
	}
}

/**
 * Immediately aborts if another CPU panicked during the stackshot.
 */
static inline void
stackshot_panic_guard(void)
{
	if (__improbable(os_atomic_load(&stackshot_ctx.sc_state, relaxed) == SS_PANICKED)) {
		stackshot_panic_spin();
	}
}

/*
 * Signal that we panicked during a stackshot by setting an atomic flag and
 * waiting for others to coalesce before continuing the panic. Other CPUs will
 * spin on this as soon as they see it set in order to prevent multiple
 * concurrent panics. The calling CPU (i.e. the one holding the debugger lock)
 * will release it for us in `stackshot_panic_spin` so we can continue
 * panicking.
 *
 * This is called from panic_trap_to_debugger.
 */
void
stackshot_cpu_signal_panic(void)
{
	stackshot_state_t o_state;
	if (stackshot_active()) {
		/* Check if someone else panicked before we did. */
		o_state = os_atomic_xchg(&stackshot_ctx.sc_state, SS_PANICKED, seq_cst);
		if (o_state == SS_PANICKED) {
			stackshot_panic_spin();
		}

		/* We're the first CPU to panic - wait for everyone to coalesce. */
		if (stackshot_cpu_ctx.scc_can_work) {
			stackshot_cpu_ctx.scc_can_work = false;
			os_atomic_dec(&stackshot_ctx.sc_cpus_working, acquire);
		}
		while (os_atomic_load(&stackshot_ctx.sc_cpus_working, seq_cst) != 0) {
			loop_wait_noguard();
		}
	}
}

/*
 * Sets the stackshot state to SS_ERRORED along with the error code.
 * Only works if the current state is SS_RUNNING or SS_SETUP.
 */
static inline void
stackshot_set_error(kern_return_t error)
{
	stackshot_state_t cur_state;
	stackshot_state_t err_state = SS_MKERR(error);
	if (__improbable(!os_atomic_cmpxchgv(&stackshot_ctx.sc_state, SS_RUNNING, err_state, &cur_state, seq_cst))) {
		if (cur_state == SS_SETUP) {
			os_atomic_cmpxchg(&stackshot_ctx.sc_state, SS_SETUP, err_state, seq_cst);
		} else {
			/* Our state is something other than SS_RUNNING or SS_SETUP... Check for panic. */
			stackshot_panic_guard();
		}
	}
}

/* Returns an error code if the current stackshot context has errored out.
 * Also functions as a panic guard.
 */
__result_use_check
static inline kern_return_t
stackshot_status_check(void)
{
	stackshot_state_t state = os_atomic_load(&stackshot_ctx.sc_state, relaxed);

	/* Check for panic */
	if (__improbable(SS_STATE(state) == SS_PANICKED)) {
		stackshot_panic_spin();
	}

	/* Check for error */
	if (__improbable(SS_STATE(state) == SS_ERRORED)) {
		kern_return_t err = SS_ERRCODE(state);
		assert(err != KERN_SUCCESS); /* SS_ERRORED should always store an associated error code. */
		return err;
	}

	return KERN_SUCCESS;
}

#pragma mark ---Stackshot Tracing---

#if STACKSHOT_COLLECTS_DIAGNOSTICS
static void
stackshot_trace(int line_no, mach_vm_address_t data)
{
	struct stackshot_trace_buffer *buffer = PERCPU_GET(stackshot_trace_buffer);
	buffer->sstb_entries[buffer->sstb_tail_idx] = (struct stackshot_trace_entry) {
		.sste_line_no = line_no,
		.sste_timestamp = mach_continuous_time(),
		.sste_data = data
	};
	buffer->sstb_tail_idx = (buffer->sstb_tail_idx + 1) % STACKSHOT_DEBUG_TRACEBUF_SIZE;
	buffer->sstb_size = MIN(buffer->sstb_size + 1, STACKSHOT_DEBUG_TRACEBUF_SIZE);
}
#define STACKSHOT_TRACE(data) stackshot_trace(__LINE__, (mach_vm_address_t) (data))

#else /* STACKSHOT_COLLECTS_DIAGNOSTICS */
#define STACKSHOT_TRACE(data) ((void) data)
#endif /* !STACKSHOT_COLLECTS_DIAGNOSTICS */

#pragma mark ---Stackshot Buffer Management---

#define freelist_lock(buffer) while(!os_atomic_cmpxchg(&buffer->ssb_freelist_lock, 0, 1, acquire)) { loop_wait(); }
#define freelist_unlock(buffer) os_atomic_store(&buffer->ssb_freelist_lock, 0, release);

/**
 * Allocates some data from the shared stackshot buffer freelist.
 * This should not be used directly, it is a last resort if we run out of space.
 */
static void *
stackshot_freelist_alloc(
	size_t size,
	struct stackshot_buffer *buffer,
	kern_return_t *error)
{
	struct freelist_entry **cur_freelist, **best_freelist = NULL, *ret = NULL;

	freelist_lock(buffer);

	cur_freelist = &buffer->ssb_freelist;

	while (*cur_freelist != NULL) {
		if (((*cur_freelist)->fl_size >= size) && ((best_freelist == NULL) || ((*best_freelist)->fl_size > (*cur_freelist)->fl_size))) {
			best_freelist = cur_freelist;
			if ((*best_freelist)->fl_size == size) {
				break;
			}
		}
		cur_freelist = &((*cur_freelist)->fl_next);
	}

	/* If we found a freelist entry, update the freelist */
	if (best_freelist != NULL) {
		os_atomic_sub(&buffer->ssb_overhead, size, relaxed);
		ret = *best_freelist;

		/* If there's enough unused space at the end of this entry, we should make a new one */
		if (((*best_freelist)->fl_size - size) > sizeof(struct freelist_entry)) {
			struct freelist_entry *new_freelist = (struct freelist_entry*) ((mach_vm_address_t) *best_freelist + size);
			*new_freelist = (struct freelist_entry) {
				.fl_next = (*best_freelist)->fl_next,
				.fl_size = (*best_freelist)->fl_size - size
			};
			(*best_freelist)->fl_next = new_freelist;
		}

		/* Update previous entry with next or new entry */
		*best_freelist = (*best_freelist)->fl_next;
	}

	freelist_unlock(buffer);

	if (error != NULL) {
		if (ret == NULL) {
			*error = KERN_INSUFFICIENT_BUFFER_SIZE;
		} else {
			*error = KERN_SUCCESS;
		}
	}

	return ret;
}

/**
 * Allocates some data from the shared stackshot buffer.
 * Should not be used directly - see the `stackshot_alloc` and
 * `stackshot_alloc_arr` macros.
 */
static void *
stackshot_buffer_alloc(
	size_t size,
	struct stackshot_buffer *buffer,
	kern_return_t *error)
{
	size_t o_used, new_used;

	stackshot_panic_guard();
	assert(!stackshot_ctx.sc_is_singlethreaded);

	os_atomic_rmw_loop(&buffer->ssb_used, o_used, new_used, relaxed, {
		new_used = o_used + size;
		if (new_used > buffer->ssb_size) {
		        os_atomic_rmw_loop_give_up(return stackshot_freelist_alloc(size, buffer, error));
		}
	});

	if (error != NULL) {
		*error = KERN_SUCCESS;
	}

	return (void*) ((mach_vm_address_t) buffer->ssb_ptr + o_used);
}

/**
 * Finds the best stackshot buffer to use (prefer our cluster's buffer)
 * and allocates from it.
 * Should not be used directly - see the `stackshot_alloc` and
 * `stackshot_alloc_arr` macros.
 */
__result_use_check
static void *
stackshot_best_buffer_alloc(size_t size, kern_return_t *error)
{
#if defined(__AMP__)
	kern_return_t err;
	int           my_cluster;
	void         *ret = NULL;
#endif /* __AMP__ */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_cpu_latency.total_buf += size;
#endif

#if defined(__AMP__)
	/* First, try our cluster's buffer */
	my_cluster = cpu_cluster_id();
	ret = stackshot_buffer_alloc(size, &stackshot_ctx.sc_buffers[my_cluster], &err);

	/* Try other buffers now. */
	if (err != KERN_SUCCESS) {
		for (size_t buf_idx = 0; buf_idx < stackshot_ctx.sc_num_buffers; buf_idx++) {
			if (buf_idx == my_cluster) {
				continue;
			}

			ret = stackshot_buffer_alloc(size, &stackshot_ctx.sc_buffers[buf_idx], &err);
			if (err == KERN_SUCCESS) {
#if STACKSHOT_COLLECTS_LATENCY_INFO
				stackshot_cpu_latency.intercluster_buf_used += size;
#endif
				break;
			}
		}
	}

	if (error != NULL) {
		*error = err;
	}

	return ret;
#else /* __AMP__ */
	return stackshot_buffer_alloc(size, &stackshot_ctx.sc_buffers[0], error);
#endif /* !__AMP__ */
}

/**
 * Frees some data from the shared stackshot buffer and adds it to the freelist.
 */
static void
stackshot_buffer_free(
	void *ptr,
	struct stackshot_buffer *buffer,
	size_t size)
{
	stackshot_panic_guard();

	/* This should never be called during a singlethreaded stackshot. */
	assert(!stackshot_ctx.sc_is_singlethreaded);

	os_atomic_add(&buffer->ssb_overhead, size, relaxed);

	/* Make sure we have enough space for the freelist entry */
	if (size < sizeof(struct freelist_entry)) {
		return;
	}

	freelist_lock(buffer);

	/* Create new freelist entry and push it to the front of the list */
	*((struct freelist_entry*) ptr) = (struct freelist_entry) {
		.fl_size = size,
		.fl_next = buffer->ssb_freelist
	};
	buffer->ssb_freelist = ptr;

	freelist_unlock(buffer);
}

/**
 * Allocates some data from the stackshot buffer. Uses the bump allocator in
 * multithreaded mode and endalloc in singlethreaded.
 * err must ALWAYS be nonnull.
 * Should not be used directly - see the macros in kern_stackshot.h.
 */
void *
stackshot_alloc_with_size(size_t size, kern_return_t *err)
{
	void *ptr;
	assert(err != NULL);
	assert(stackshot_active());

	stackshot_panic_guard();

	if (stackshot_ctx.sc_is_singlethreaded) {
		ptr = kcdata_endalloc(stackshot_kcdata_p, size);
		if (ptr == NULL) {
			*err = KERN_INSUFFICIENT_BUFFER_SIZE;
		}
	} else {
		ptr = stackshot_best_buffer_alloc(size, err);
		if (ptr == NULL) {
			/* We should always return an error if we return a null ptr */
			assert3u(*err, !=, KERN_SUCCESS);
		}
	}

	return ptr;
}

/**
 * Initializes a new kcdata buffer somewhere in a linked kcdata list.
 * Allocates a buffer for the kcdata from the shared stackshot buffer.
 *
 * See `linked_kcdata_alloc_callback` for the implementation details of
 * linked kcdata for stackshot.
 */
__result_use_check
static kern_return_t
linked_kcdata_init(
	linked_kcdata_descriptor_t descriptor,
	size_t min_size,
	unsigned int data_type,
	unsigned int flags)
{
	void              *buf_ptr;
	kern_return_t      error;
	size_t             buf_size = MAX(min_size, stackshot_ctx.sc_min_kcdata_size);

	buf_ptr = stackshot_alloc_arr(uint8_t, buf_size, &error);
	if (error != KERN_SUCCESS) {
		return error;
	}

	error = kcdata_memory_static_init(&descriptor->kcdata, (mach_vm_address_t) buf_ptr, data_type, buf_size, flags);
	if (error != KERN_SUCCESS) {
		return error;
	}

	descriptor->kcdata.kcd_alloc_callback = linked_kcdata_alloc_callback;

	return KERN_SUCCESS;
}

static void
stackshot_kcdata_free_unused(kcdata_descriptor_t descriptor)
{
	/*
	 * If we have free space at the end of the kcdata, we can add it to the
	 * freelist. We always add to *our* cluster's freelist, no matter where
	 * the data was originally allocated.
	 *
	 * Important Note: We do not use kcdata_memory_get_used_bytes here because
	 * that includes extra space for the end tag (which we do not care about).
	 */
	int    buffer;
	size_t used_size = descriptor->kcd_addr_end - descriptor->kcd_addr_begin;
	size_t free_size = (descriptor->kcd_length - used_size);
	if (free_size > 0) {
#if defined(__arm64__)
		buffer = cpu_cluster_id();
#else /* __arm64__ */
		buffer = 0;
#endif /* !__arm64__ */
		stackshot_buffer_free((void*) descriptor->kcd_addr_end, &stackshot_ctx.sc_buffers[buffer], free_size);
		descriptor->kcd_length = used_size;
	}
}

/**
 * The callback for linked kcdata, which is called when one of the kcdata
 * buffers runs out of space. This allocates a new kcdata descriptor &
 * buffer in the linked list and sets it up.
 *
 * When kcdata calls this callback, it takes the returned descriptor
 * and copies it to its own descriptor (which will be the per-cpu kcdata
 * descriptor, in the case of stackshot).
 *
 * --- Stackshot linked kcdata details ---
 * The way stackshot allocates kcdata buffers (in a non-panic context) is via
 * a basic bump allocator (see `stackshot_buffer_alloc`) and a linked list of
 * kcdata structures. The kcdata are allocated with a reasonable size based on
 * some system heuristics (or more if whatever is being pushed into the buffer
 * is larger). When the current kcdata buffer runs out of space, it calls this
 * callback, which allocates a new linked kcdata object at the tail of the
 * current list.
 *
 * The per-cpu `stackshot_kcdata_p` descriptor is the "tail" of the list, but
 * is not actually part of the linked list (this simplified implementation,
 * since it didn't require changing every kcdata call & a bunch of
 * kcdata code, since the current in-use descriptor is always in the same place
 * this way). When it is filled up and this callback is called, the
 * `stackshot_kcdata_p` descriptor is copied to the *actual* tail of the list
 * (in stackshot_cpu_ctx.scc_kcdata_tail), and a new linked kcdata struct is
 * allocated at the tail.
 */
static kcdata_descriptor_t
linked_kcdata_alloc_callback(kcdata_descriptor_t descriptor, size_t min_size)
{
	kern_return_t error;
	linked_kcdata_descriptor_t new_kcdata = NULL;

	/* This callback should ALWAYS be coming from our per-cpu kcdata. If not, something has gone horribly wrong.*/
	stackshot_panic_guard();
	assert(descriptor == stackshot_kcdata_p);

	/* Free the unused space in the buffer and copy it to the tail of the linked kcdata list. */
	stackshot_kcdata_free_unused(descriptor);
	stackshot_cpu_ctx.scc_kcdata_tail->kcdata = *descriptor;

	/* Allocate another linked_kcdata and initialize it. */
	new_kcdata = stackshot_alloc(struct linked_kcdata_descriptor, &error);
	if (error != KERN_SUCCESS) {
		return NULL;
	}

	/* It doesn't matter what we mark the data type as - we're throwing it away when weave the data together anyway. */
	error = linked_kcdata_init(new_kcdata, min_size, KCDATA_BUFFER_BEGIN_STACKSHOT, descriptor->kcd_flags);
	if (error != KERN_SUCCESS) {
		return NULL;
	}

	bzero(descriptor, sizeof(struct kcdata_descriptor));
	stackshot_cpu_ctx.scc_kcdata_tail->next = new_kcdata;
	stackshot_cpu_ctx.scc_kcdata_tail = new_kcdata;

	return &new_kcdata->kcdata;
}

/**
 * Allocates a new linked kcdata list for the current CPU and sets it up.
 * If there was a previous linked kcdata descriptor, you should call
 * `stackshot_finalize_linked_kcdata` first, or otherwise save it somewhere.
 */
__result_use_check
static kern_return_t
stackshot_new_linked_kcdata(void)
{
	kern_return_t error;

	stackshot_panic_guard();
	assert(!stackshot_ctx.sc_panic_stackshot);

	stackshot_cpu_ctx.scc_kcdata_head = stackshot_alloc(struct linked_kcdata_descriptor, &error);
	if (error != KERN_SUCCESS) {
		return error;
	}

	kcd_exit_on_error(linked_kcdata_init(stackshot_cpu_ctx.scc_kcdata_head, 0,
	    KCDATA_BUFFER_BEGIN_STACKSHOT,
	    KCFLAG_USE_MEMCOPY | KCFLAG_NO_AUTO_ENDBUFFER | KCFLAG_ALLOC_CALLBACK));

	stackshot_cpu_ctx.scc_kcdata_tail = stackshot_cpu_ctx.scc_kcdata_head;
	*stackshot_kcdata_p = stackshot_cpu_ctx.scc_kcdata_head->kcdata;

error_exit:
	return error;
}

/**
 * Finalizes the current linked kcdata structure for the CPU by updating the
 * tail of the list with the per-cpu kcdata descriptor.
 */
static void
stackshot_finalize_linked_kcdata(void)
{
	stackshot_panic_guard();
	assert(!stackshot_ctx.sc_panic_stackshot);
	stackshot_kcdata_free_unused(stackshot_kcdata_p);
	if (stackshot_cpu_ctx.scc_kcdata_tail != NULL) {
		stackshot_cpu_ctx.scc_kcdata_tail->kcdata = *stackshot_kcdata_p;
	}
	*stackshot_kcdata_p = (struct kcdata_descriptor){};
}

/*
 * Initialize the mutex governing access to the stack snapshot subsystem
 * and other stackshot related bits.
 */
__private_extern__ void
stackshot_init(void)
{
	mach_timebase_info_data_t timebase;

	clock_timebase_info(&timebase);
	stackshot_max_fault_time = ((KDP_FAULT_PATH_MAX_TIME_PER_STACKSHOT_NSECS * timebase.denom) / timebase.numer);

	max_tracebuf_size = MAX(max_tracebuf_size, ((ROUNDUP(max_mem, GIGABYTES) / GIGABYTES) * TRACEBUF_SIZE_PER_GB));

	PE_parse_boot_argn("stackshot_maxsz", &max_tracebuf_size, sizeof(max_tracebuf_size));
}

/*
 * Called with interrupts disabled after stackshot context has been
 * initialized.
 */
static kern_return_t
stackshot_trap(void)
{
	kern_return_t   rv;

#if defined(__x86_64__)
	/*
	 * Since mp_rendezvous and stackshot both attempt to capture cpus then perform an
	 * operation, it's essential to apply mutual exclusion to the other when one
	 * mechanism is in operation, lest there be a deadlock as the mechanisms race to
	 * capture CPUs.
	 *
	 * Further, we assert that invoking stackshot from mp_rendezvous*() is not
	 * allowed, so we check to ensure there there is no rendezvous in progress before
	 * trying to grab the lock (if there is, a deadlock will occur when we try to
	 * grab the lock).  This is accomplished by setting cpu_rendezvous_in_progress to
	 * TRUE in the mp rendezvous action function.  If stackshot_trap() is called by
	 * a subordinate of the call chain within the mp rendezvous action, this flag will
	 * be set and can be used to detect the inevitable deadlock that would occur
	 * if this thread tried to grab the rendezvous lock.
	 */

	if (current_cpu_datap()->cpu_rendezvous_in_progress == TRUE) {
		panic("Calling stackshot from a rendezvous is not allowed!");
	}

	mp_rendezvous_lock();
#endif

	stackshot_stats.last_abs_start = mach_absolute_time();
	stackshot_stats.last_abs_end = 0;

	rv = DebuggerTrapWithState(DBOP_STACKSHOT, NULL, NULL, NULL, 0, NULL, FALSE, 0, NULL);

	stackshot_stats.last_abs_end = mach_absolute_time();
	stackshot_stats.stackshots_taken++;
	stackshot_stats.stackshots_duration += (stackshot_stats.last_abs_end - stackshot_stats.last_abs_start);

#if defined(__x86_64__)
	mp_rendezvous_unlock();
#endif
	return rv;
}

extern void stackshot_get_timing(uint64_t *last_abs_start, uint64_t *last_abs_end, uint64_t *count, uint64_t *total_duration);
void
stackshot_get_timing(uint64_t *last_abs_start, uint64_t *last_abs_end, uint64_t *count, uint64_t *total_duration)
{
	STACKSHOT_SUBSYS_LOCK();
	*last_abs_start = stackshot_stats.last_abs_start;
	*last_abs_end = stackshot_stats.last_abs_end;
	*count = stackshot_stats.stackshots_taken;
	*total_duration = stackshot_stats.stackshots_duration;
	STACKSHOT_SUBSYS_UNLOCK();
}

kern_return_t
stack_snapshot_from_kernel(int pid, void *buf, uint32_t size, uint64_t flags, uint64_t delta_since_timestamp, uint32_t pagetable_mask, unsigned *bytes_traced)
{
	kern_return_t error = KERN_SUCCESS;
	boolean_t istate;
	struct kdp_snapshot_args args;

	args = (struct kdp_snapshot_args) {
		.pid =               pid,
		.buffer =            buf,
		.buffer_size =       size,
		.flags =             flags,
		.since_timestamp =   delta_since_timestamp,
		.pagetable_mask =    pagetable_mask
	};

#if DEVELOPMENT || DEBUG
	if (kern_feature_override(KF_STACKSHOT_OVRD) == TRUE) {
		return KERN_NOT_SUPPORTED;
	}
#endif
	if ((buf == NULL) || (size <= 0) || (bytes_traced == NULL)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* zero caller's buffer to match KMA_ZERO in other path */
	bzero(buf, size);

	/* cap in individual stackshot to max_tracebuf_size */
	if (size > max_tracebuf_size) {
		size = max_tracebuf_size;
	}

	/* Serialize tracing */
	if (flags & STACKSHOT_TRYLOCK) {
		if (!STACKSHOT_SUBSYS_TRY_LOCK()) {
			return KERN_LOCK_OWNED;
		}
	} else {
		STACKSHOT_SUBSYS_LOCK();
	}

#if CONFIG_EXCLAVES
	assert(!stackshot_exclave_inspect_ctids);
#endif

	stackshot_initial_estimate = 0;
	stackshot_duration_prior_abs = 0;
	stackshot_duration_outer = NULL;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_STACKSHOT, STACKSHOT_KERN_RECORD) | DBG_FUNC_START,
	    flags, size, pid, delta_since_timestamp);

	/* Prepare the compressor for a stackshot */
	error = vm_compressor_kdp_init();
	if (error != KERN_SUCCESS) {
		return error;
	}

#if STACKSHOT_COLLECTS_RDAR_126582377_DATA
	// Opportunistically collect reports of the rdar://126582377 failure.
	// If the allocation doesn't succeed, or if another CPU "steals" the
	// allocated event first, that is acceptable.
	ca_event_t new_event = CA_EVENT_ALLOCATE_FLAGS(bad_stackshot_upper16, Z_NOWAIT);
	if (new_event) {
		if (os_atomic_cmpxchg(&rdar_126582377_event, NULL, new_event, relaxed) == 0) {
			// Already set up, so free it
			CA_EVENT_DEALLOCATE(new_event);
		}
	}
#endif

	istate = ml_set_interrupts_enabled(FALSE);
	uint64_t time_start      = mach_absolute_time();

	/* Emit a SOCD tracepoint that we are initiating a stackshot */
	SOCD_TRACE_XNU_START(STACKSHOT);

	/* Preload trace parameters*/
	error = kdp_snapshot_preflight_internal(args);

	/*
	 * Trap to the debugger to obtain a coherent stack snapshot; this populates
	 * the trace buffer
	 */
	if (error == KERN_SUCCESS) {
		error = stackshot_trap();
	}

	uint64_t time_end = mach_absolute_time();

	/* Emit a SOCD tracepoint that we have completed the stackshot */
	SOCD_TRACE_XNU_END(STACKSHOT);

	ml_set_interrupts_enabled(istate);

#if CONFIG_EXCLAVES
	/* stackshot trap should only finish successfully or with no pending Exclave threads */
	assert(error == KERN_SUCCESS || stackshot_exclave_inspect_ctids == NULL);
#endif

	/*
	 * Stackshot is no longer active.
	 * (We have to do this here for the special interrupt disable timeout case to work)
	 */
	os_atomic_store(&stackshot_ctx.sc_state, SS_INACTIVE, release);

	/* Release kdp compressor buffers */
	vm_compressor_kdp_teardown();

	/* Collect multithreaded kcdata into one finalized buffer */
	if (error == KERN_SUCCESS && !stackshot_ctx.sc_is_singlethreaded) {
		error = stackshot_collect_kcdata();
	}

#if CONFIG_EXCLAVES
	if (error == KERN_SUCCESS && stackshot_exclave_inspect_ctids) {
		error = collect_exclave_threads(flags);
	}
#endif /* CONFIG_EXCLAVES */

	if (error == KERN_SUCCESS) {
		if (!stackshot_ctx.sc_is_singlethreaded) {
			error = stackshot_finalize_kcdata();
		} else {
			error = stackshot_finalize_singlethreaded_kcdata();
		}
	}

	if (stackshot_duration_outer) {
		*stackshot_duration_outer = time_end - time_start;
	}
	*bytes_traced = kdp_stack_snapshot_bytes_traced();

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_STACKSHOT, STACKSHOT_KERN_RECORD) | DBG_FUNC_END,
	    error, (time_end - time_start), size, *bytes_traced);

	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}

#if CONFIG_TELEMETRY
kern_return_t
stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval)
{
	int error = KERN_FAILURE;
	uint32_t bytes_traced = 0;

	/*
	 * "Flags" is actually treated as an enumeration, make sure only one value
	 * is passed at a time.
	 */
	bool set_mark = flags & STACKSHOT_SET_MICROSTACKSHOT_MARK;
	flags &= ~STACKSHOT_SET_MICROSTACKSHOT_MARK;
	if (__builtin_popcount(flags) != 1) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Ensure that there's space to copyout to.
	 */
	if (tracebuf == USER_ADDR_NULL || tracebuf_size == 0) {
		return KERN_INVALID_ARGUMENT;
	}

	STACKSHOT_SUBSYS_LOCK();

	switch (flags) {
	case STACKSHOT_GET_KERNEL_MICROSTACKSHOT:
		/*
		 * Kernel samples consume from their buffer, so using a mark is the only
		 * allowed option.
		 */
		if (!set_mark) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}
		bytes_traced = tracebuf_size;
		error = telemetry_kernel_gather(tracebuf, &bytes_traced);
		*retval = (int)bytes_traced;
		break;
	case STACKSHOT_GET_MICROSTACKSHOT: {
		if (tracebuf_size > max_tracebuf_size) {
			error = KERN_INVALID_ARGUMENT;
			break;
		}

		bytes_traced = tracebuf_size;
		error = telemetry_gather(tracebuf, &bytes_traced, set_mark);
		*retval = (int)bytes_traced;
		break;
	}
	default:
		error = KERN_NOT_SUPPORTED;
		break;
	}

	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}
#endif /* CONFIG_TELEMETRY */

/**
 * Grabs the next work item from the stackshot work queue.
 */
static struct stackshot_workitem *
stackshot_get_workitem(struct stackshot_workqueue *queue)
{
	uint32_t old_count, new_count;

	/* note: this relies on give_up not performing the write, just bailing out immediately */
	os_atomic_rmw_loop(&queue->sswq_cur_item, old_count, new_count, acq_rel, {
		if (old_count >= os_atomic_load(&queue->sswq_num_items, relaxed)) {
		        os_atomic_rmw_loop_give_up(return NULL);
		}
		new_count = old_count + 1;
	});

	return &queue->sswq_items[old_count];
};

/**
 * Puts an item on the appropriate stackshot work queue.
 * We don't need the lock for this, but only because it's
 * only called by one writer..
 *
 * @returns
 * true if the item fit in the queue, false if not.
 */
static kern_return_t
stackshot_put_workitem(struct stackshot_workitem item)
{
	struct stackshot_workqueue *queue;

	/* Put in higher queue if task has more threads, with highest queue having >= STACKSHOT_HARDEST_THREADCOUNT threads */
	size_t queue_idx = ((item.sswi_task->thread_count * (STACKSHOT_NUM_WORKQUEUES - 1)) / STACKSHOT_HARDEST_THREADCOUNT);
	queue_idx = MIN(queue_idx, STACKSHOT_NUM_WORKQUEUES - 1);

	queue = &stackshot_ctx.sc_workqueues[queue_idx];

	size_t num_items = os_atomic_load(&queue->sswq_num_items, relaxed);

	if (num_items >= queue->sswq_capacity) {
		return KERN_INSUFFICIENT_BUFFER_SIZE;
	}

	queue->sswq_items[num_items] = item;
	os_atomic_inc(&queue->sswq_num_items, release);

	return KERN_SUCCESS;
}

#define calc_num_linked_kcdata_frames(size, kcdata_size) (1 + ((size) - 1) / (kcdata_size))
#define calc_linked_kcdata_size(size, kcdata_size) (calc_num_linked_kcdata_frames((size), (kcdata_size)) * ((kcdata_size) + sizeof(struct linked_kcdata_descriptor)))

#define TASK_UUID_AVG_SIZE (16 * sizeof(uuid_t)) /* Average space consumed by UUIDs/task */
#define TASK_SHARED_CACHE_AVG_SIZE (128) /* Average space consumed by task shared cache info */
#define sizeof_if_traceflag(a, flag) (((trace_flags & (flag)) != 0) ? sizeof(a) : 0)

#define FUDGED_SIZE(size, adj) (((size) * ((adj) + 100)) / 100)

/*
 * Return the estimated size of a single task (including threads)
 * in a stackshot with the given flags.
 */
static uint32_t
get_stackshot_est_tasksize(uint64_t trace_flags)
{
	size_t total_size;
	size_t threads_per_task = (((threads_count + terminated_threads_count) - 1) / (tasks_count + terminated_tasks_count)) + 1;
	size_t est_thread_size = sizeof(struct thread_snapshot_v4) + 42 * sizeof(uintptr_t);
	size_t est_task_size = sizeof(struct task_snapshot_v2) +
	    TASK_UUID_AVG_SIZE +
	    TASK_SHARED_CACHE_AVG_SIZE +
	    sizeof_if_traceflag(struct io_stats_snapshot, STACKSHOT_INSTRS_CYCLES) +
	    sizeof_if_traceflag(uint32_t, STACKSHOT_ASID) +
	    sizeof_if_traceflag(sizeof(uintptr_t) * STACKSHOT_PAGETABLE_BUFSZ, STACKSHOT_PAGE_TABLES) +
	    sizeof_if_traceflag(struct instrs_cycles_snapshot_v2, STACKSHOT_INSTRS_CYCLES) +
	    sizeof(struct stackshot_cpu_architecture) +
	    sizeof(struct stackshot_task_codesigning_info);

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if (collect_latency_info) {
		est_thread_size += sizeof(struct stackshot_latency_thread);
		est_task_size += sizeof(struct stackshot_latency_task);
	}
#endif

	total_size = est_task_size + threads_per_task * est_thread_size;

	return total_size;
}

/*
 * Return the estimated size of a stackshot based on the
 * number of currently running threads and tasks.
 *
 * adj is an adjustment in units of percentage
 */
static uint32_t
get_stackshot_estsize(
	uint32_t prev_size_hint,
	uint32_t adj,
	uint64_t trace_flags,
	pid_t target_pid)
{
	vm_size_t thread_and_task_total;
	uint64_t  size;
	uint32_t  estimated_size;
	bool      process_scoped = ((target_pid != -1) && ((trace_flags & STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL) == 0));

	/*
	 * We use the estimated task size (with a fudge factor) as the default
	 * linked kcdata buffer size in an effort to reduce overhead (ideally, we want
	 * each task to only need a single kcdata buffer.)
	 */
	uint32_t est_task_size = get_stackshot_est_tasksize(trace_flags);
	uint32_t est_kcdata_size = FUDGED_SIZE(est_task_size, adj);
	uint64_t est_preamble_size = calc_linked_kcdata_size(8192 * 4, est_kcdata_size);
	uint64_t est_postamble_size = calc_linked_kcdata_size(8192 * 2, est_kcdata_size);
	uint64_t est_extra_size = 0;

	adj = MIN(adj, 100u);   /* no more than double our estimate */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	est_extra_size += real_ncpus * sizeof(struct stackshot_latency_cpu);
	est_extra_size += sizeof(struct stackshot_latency_collection_v2);
#endif

	est_extra_size += real_ncpus * MAX_FRAMES * sizeof(uintptr_t); /* Stacktrace buffers */
	est_extra_size += FUDGED_SIZE(tasks_count, 10) * sizeof(uintptr_t) * STACKSHOT_NUM_WORKQUEUES; /* Work queues */
	est_extra_size += sizeof_if_traceflag(sizeof(uintptr_t) * STACKSHOT_PAGETABLE_BUFSZ * real_ncpus, STACKSHOT_PAGE_TABLES);

	thread_and_task_total = calc_linked_kcdata_size(est_task_size, est_kcdata_size);
	if (!process_scoped) {
		thread_and_task_total *= tasks_count;
	}
	size = thread_and_task_total + est_preamble_size + est_postamble_size + est_extra_size; /* estimate */
	size = FUDGED_SIZE(size, adj); /* add adj */
	size = MAX(size, prev_size_hint); /* allow hint to increase */
	size += stackshot_plh_est_size(); /* add space for the port label hash */
	size = MIN(size, VM_MAP_TRUNC_PAGE(UINT32_MAX, PAGE_MASK)); /* avoid overflow */
	estimated_size = (uint32_t) VM_MAP_ROUND_PAGE(size, PAGE_MASK); /* round to pagesize */

	return estimated_size;
}

/**
 * Copies a linked list of kcdata structures into a final kcdata structure.
 * Only used from stackshot_finalize_kcdata.
 */
__result_use_check
static kern_return_t
stackshot_copy_linked_kcdata(kcdata_descriptor_t final_kcdata, linked_kcdata_descriptor_t linked_kcdata)
{
	kern_return_t error = KERN_SUCCESS;

	while (linked_kcdata) {
		/* Walk linked kcdata list */
		kcdata_descriptor_t cur_kcdata = &linked_kcdata->kcdata;
		if ((cur_kcdata->kcd_addr_end - cur_kcdata->kcd_addr_begin) == 0) {
			linked_kcdata = linked_kcdata->next;
			continue;
		}

		/* Every item in the linked kcdata should have a header tag of type KCDATA_BUFFER_BEGIN_STACKSHOT. */
		assert(((struct kcdata_item*) cur_kcdata->kcd_addr_begin)->type == KCDATA_BUFFER_BEGIN_STACKSHOT);
		assert((final_kcdata->kcd_addr_begin + final_kcdata->kcd_length) > final_kcdata->kcd_addr_end);
		size_t header_size = sizeof(kcdata_item_t) + kcdata_calc_padding(sizeof(kcdata_item_t));
		size_t size = cur_kcdata->kcd_addr_end - cur_kcdata->kcd_addr_begin - header_size;
		size_t free = (final_kcdata->kcd_length + final_kcdata->kcd_addr_begin) - final_kcdata->kcd_addr_end;
		if (free < size) {
			error = KERN_INSUFFICIENT_BUFFER_SIZE;
			goto error_exit;
		}

		/* Just memcpy the data over (and compress if we need to.) */
		kcdata_compression_window_open(final_kcdata);
		error = kcdata_memcpy(final_kcdata, final_kcdata->kcd_addr_end, (void*) (cur_kcdata->kcd_addr_begin + header_size), size);
		if (error != KERN_SUCCESS) {
			goto error_exit;
		}
		final_kcdata->kcd_addr_end += size;
		kcdata_compression_window_close(final_kcdata);

		linked_kcdata = linked_kcdata->next;
	}

error_exit:
	return error;
}

/**
 * Copies the duration, latency, and diagnostic info into a final kcdata buffer.
 * Only used by stackshot_finalize_kcdata and stackshot_finalize_singlethreaded_kcdata.
 */
__result_use_check
static kern_return_t
stackshot_push_duration_and_latency(kcdata_descriptor_t kcdata)
{
	kern_return_t error;
	mach_vm_address_t out_addr;
	bool use_fault_path = ((stackshot_flags & (STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_ENABLE_BT_FAULTING)) != 0);
#if STACKSHOT_COLLECTS_LATENCY_INFO
	size_t            buffer_used = 0;
	size_t            buffer_overhead = 0;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	if (use_fault_path) {
		struct stackshot_fault_stats stats = (struct stackshot_fault_stats) {
			.sfs_pages_faulted_in = 0,
			.sfs_time_spent_faulting = 0,
			.sfs_system_max_fault_time = stackshot_max_fault_time,
			.sfs_stopped_faulting = false
		};
		percpu_foreach_base(base) {
			struct stackshot_cpu_context *cpu_ctx = PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu);
			if (!cpu_ctx->scc_did_work) {
				continue;
			}
			stats.sfs_pages_faulted_in += cpu_ctx->scc_fault_stats.sfs_pages_faulted_in;
			stats.sfs_time_spent_faulting += cpu_ctx->scc_fault_stats.sfs_time_spent_faulting;
			stats.sfs_stopped_faulting = stats.sfs_stopped_faulting || cpu_ctx->scc_fault_stats.sfs_stopped_faulting;
		}
		kcdata_push_data(kcdata, STACKSHOT_KCTYPE_STACKSHOT_FAULT_STATS,
		    sizeof(struct stackshot_fault_stats), &stats);
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	int num_working_cpus = 0;
	if (collect_latency_info) {
		/* Add per-CPU latency info */
		percpu_foreach(cpu_ctx, stackshot_cpu_ctx_percpu) {
			if (cpu_ctx->scc_did_work) {
				num_working_cpus++;
			}
		}
		kcdata_compression_window_open(kcdata);
		kcd_exit_on_error(kcdata_get_memory_addr_for_array(
			    kcdata, STACKSHOT_KCTYPE_LATENCY_INFO_CPU, sizeof(struct stackshot_latency_cpu), num_working_cpus, &out_addr));
		percpu_foreach_base(base) {
			if (PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu)->scc_did_work) {
				kcdata_memcpy(kcdata, out_addr, PERCPU_GET_WITH_BASE(base, stackshot_cpu_latency_percpu),
				    sizeof(struct stackshot_latency_cpu));
				out_addr += sizeof(struct stackshot_latency_cpu);
			}
		}
		kcd_exit_on_error(kcdata_compression_window_close(kcdata));

		/* Add up buffer info */
		for (size_t buf_idx = 0; buf_idx < stackshot_ctx.sc_num_buffers; buf_idx++) {
			struct stackshot_buffer *buf = &stackshot_ctx.sc_buffers[buf_idx];
			buffer_used += os_atomic_load(&buf->ssb_used, relaxed);
			buffer_overhead += os_atomic_load(&buf->ssb_overhead, relaxed);
		}
		stackshot_ctx.sc_latency.buffer_size = stackshot_ctx.sc_args.buffer_size;
		stackshot_ctx.sc_latency.buffer_overhead = buffer_overhead;
		stackshot_ctx.sc_latency.buffer_used = buffer_used;
		stackshot_ctx.sc_latency.buffer_count = stackshot_ctx.sc_num_buffers;

		/* Add overall latency info */
		kcd_exit_on_error(kcdata_push_data(
			    kcdata, STACKSHOT_KCTYPE_LATENCY_INFO,
			    sizeof(stackshot_ctx.sc_latency), &stackshot_ctx.sc_latency));
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	if ((stackshot_flags & STACKSHOT_DO_COMPRESS) == 0) {
		assert(!stackshot_ctx.sc_panic_stackshot);
		kcd_exit_on_error(kcdata_get_memory_addr(kcdata, STACKSHOT_KCTYPE_STACKSHOT_DURATION,
		    sizeof(struct stackshot_duration_v2), &out_addr));
		struct stackshot_duration_v2 *duration_p = (void *) out_addr;
		memcpy(duration_p, &stackshot_ctx.sc_duration, sizeof(*duration_p));
		stackshot_duration_outer = (unaligned_u64 *) &duration_p->stackshot_duration_outer;
		kcd_exit_on_error(kcdata_add_uint64_with_description(kcdata, stackshot_tries, "stackshot_tries"));
	} else {
		kcd_exit_on_error(kcdata_push_data(kcdata, STACKSHOT_KCTYPE_STACKSHOT_DURATION, sizeof(stackshot_ctx.sc_duration), &stackshot_ctx.sc_duration));
		stackshot_duration_outer = NULL;
	}

error_exit:
	return error;
}

/**
 * Allocates the final kcdata buffer for a mulitithreaded stackshot,
 * where all of the per-task kcdata (and exclave kcdata) will end up.
 */
__result_use_check
static kern_return_t
stackshot_alloc_final_kcdata(void)
{
	vm_offset_t   final_kcdata_buffer = 0;
	kern_return_t error = KERN_SUCCESS;
	uint32_t hdr_tag = (stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
	    : (stackshot_flags & STACKSHOT_DO_COMPRESS) ? KCDATA_BUFFER_BEGIN_COMPRESSED
	    : KCDATA_BUFFER_BEGIN_STACKSHOT;

	if (stackshot_ctx.sc_is_singlethreaded) {
		return KERN_SUCCESS;
	}

	if ((error = kmem_alloc(kernel_map, &final_kcdata_buffer, stackshot_args.buffer_size,
	    KMA_ZERO | KMA_DATA, VM_KERN_MEMORY_DIAG)) != KERN_SUCCESS) {
		os_log_error(OS_LOG_DEFAULT, "stackshot: final allocation failed: %d, allocating %u bytes of %u max, try %llu\n", (int)error, stackshot_args.buffer_size, max_tracebuf_size, stackshot_tries);
		return KERN_RESOURCE_SHORTAGE;
	}

	stackshot_ctx.sc_finalized_kcdata = kcdata_memory_alloc_init(final_kcdata_buffer, hdr_tag,
	    stackshot_args.buffer_size, KCFLAG_USE_MEMCOPY | KCFLAG_NO_AUTO_ENDBUFFER);

	if (stackshot_ctx.sc_finalized_kcdata == NULL) {
		kmem_free(kernel_map, final_kcdata_buffer, stackshot_args.buffer_size);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

/**
 * Frees the final kcdata buffer.
 */
static void
stackshot_free_final_kcdata(void)
{
	if (stackshot_ctx.sc_is_singlethreaded || (stackshot_ctx.sc_finalized_kcdata == NULL)) {
		return;
	}

	kmem_free(kernel_map, stackshot_ctx.sc_finalized_kcdata->kcd_addr_begin, stackshot_args.buffer_size);
	kcdata_memory_destroy(stackshot_ctx.sc_finalized_kcdata);
	stackshot_ctx.sc_finalized_kcdata = NULL;
}

/**
 * Called once we exit the debugger trap to collate all of the separate linked
 * kcdata lists into one kcdata buffer. The calling thread will run this, and
 * it is guaranteed that nobody else is touching any stackshot state at this
 * point. In the case of a panic stackshot, this is never called since we only
 * use one thread.
 *
 * Called with interrupts enabled, stackshot subsys lock held.
 */
__result_use_check
static kern_return_t
stackshot_collect_kcdata(void)
{
	kern_return_t error = 0;
	uint32_t      hdr_tag;

	assert(!stackshot_ctx.sc_panic_stackshot && !stackshot_ctx.sc_is_singlethreaded);
	LCK_MTX_ASSERT(&stackshot_subsys_mutex, LCK_MTX_ASSERT_OWNED);

	/* Allocate our final kcdata buffer. */
	kcd_exit_on_error(stackshot_alloc_final_kcdata());
	assert(stackshot_ctx.sc_finalized_kcdata != NULL);

	/* Setup compression if we need it. */
	if (stackshot_flags & STACKSHOT_DO_COMPRESS) {
		hdr_tag = (stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
		    : KCDATA_BUFFER_BEGIN_STACKSHOT;
		kcd_exit_on_error(kcdata_init_compress(stackshot_ctx.sc_finalized_kcdata, hdr_tag, kdp_memcpy, KCDCT_ZLIB));
	}

	/* Copy over all of the pre task-iteration kcdata (to preserve order as if it were single-threaded) */
	kcd_exit_on_error(stackshot_copy_linked_kcdata(stackshot_ctx.sc_finalized_kcdata, stackshot_ctx.sc_pretask_kcdata));

	/* Set each queue's cur_item to 0. */
	for (size_t i = 0; i < STACKSHOT_NUM_WORKQUEUES; i++) {
		os_atomic_store(&stackshot_ctx.sc_workqueues[i].sswq_cur_item, 0, relaxed);
	}

	/*
	 * Iterate over work queue(s) and copy the kcdata in.
	 */
	while (true) {
		struct stackshot_workitem  *next_item = NULL;
		struct stackshot_workqueue *next_queue = NULL;
		for (size_t i = 0; i < STACKSHOT_NUM_WORKQUEUES; i++) {
			struct stackshot_workqueue *queue = &stackshot_ctx.sc_workqueues[i];
			size_t cur_item = os_atomic_load(&queue->sswq_cur_item, relaxed);

			/* Check if we're done with this queue */
			if (cur_item >= os_atomic_load(&queue->sswq_num_items, relaxed)) {
				continue;
			}

			/* Check if this workitem should come next */
			struct stackshot_workitem *item = &queue->sswq_items[cur_item];
			if ((next_item == NULL) || (next_item->sswi_idx > item->sswi_idx)) {
				next_item = item;
				next_queue = queue;
			}
		}

		/* Queues are empty. */
		if (next_item == NULL) {
			break;
		}

		assert(next_queue);
		assert(next_item->sswi_data != NULL);

		os_atomic_inc(&next_queue->sswq_cur_item, relaxed);
		kcd_exit_on_error(stackshot_copy_linked_kcdata(stackshot_ctx.sc_finalized_kcdata, next_item->sswi_data));
	}

	/* Write post-task kcdata */
	kcd_exit_on_error(stackshot_copy_linked_kcdata(stackshot_ctx.sc_finalized_kcdata, stackshot_ctx.sc_posttask_kcdata));
error_exit:
	if (error != KERN_SUCCESS) {
		stackshot_free_final_kcdata();
	}
	return error;
}


/**
 * Called at the very end of stackshot data generation, to write final timing
 * data to the kcdata structure and close compression. Only called for
 * multi-threaded stackshots; see stackshot_finalize_singlethreaded_kcata for
 * single-threaded variant.
 *
 * Called with interrupts enabled, stackshot subsys lock held.
 */
__result_use_check
static kern_return_t
stackshot_finalize_kcdata(void)
{
	kern_return_t error = 0;

	assert(!stackshot_ctx.sc_panic_stackshot && !stackshot_ctx.sc_is_singlethreaded);
	LCK_MTX_ASSERT(&stackshot_subsys_mutex, LCK_MTX_ASSERT_OWNED);

	assert(stackshot_ctx.sc_finalized_kcdata != NULL);

	/* Write stackshot timing info */
	kcd_exit_on_error(stackshot_push_duration_and_latency(stackshot_ctx.sc_finalized_kcdata));

	/* Note: exactly 0 or 1 call to something pushing more data can be called after kcd_finalize_compression */
	kcd_finalize_compression(stackshot_ctx.sc_finalized_kcdata);
	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_ctx.sc_finalized_kcdata, stackshot_flags, "stackshot_out_flags"));
	kcd_exit_on_error(kcdata_write_buffer_end(stackshot_ctx.sc_finalized_kcdata));

	stackshot_ctx.sc_bytes_traced = (uint32_t) kcdata_memory_get_used_bytes(stackshot_ctx.sc_finalized_kcdata);
	stackshot_ctx.sc_bytes_uncompressed = (uint32_t) kcdata_memory_get_uncompressed_bytes(stackshot_ctx.sc_finalized_kcdata);

	if (os_atomic_load(&stackshot_ctx.sc_retval, relaxed) == KERN_SUCCESS) {
		/* releases and zeros done */
		kcd_exit_on_error(kcdata_finish(stackshot_ctx.sc_finalized_kcdata));
	}

	memcpy(stackshot_args.buffer, (void*) stackshot_ctx.sc_finalized_kcdata->kcd_addr_begin, stackshot_args.buffer_size);

	/* Fix duration_outer offset */
	if (stackshot_duration_outer != NULL) {
		stackshot_duration_outer = (unaligned_u64*) ((mach_vm_address_t) stackshot_args.buffer + ((mach_vm_address_t) stackshot_duration_outer - stackshot_ctx.sc_finalized_kcdata->kcd_addr_begin));
	}

error_exit:
	stackshot_free_final_kcdata();
	return error;
}

/**
 * Finalizes the kcdata for a singlethreaded stackshot.
 *
 * May be called from interrupt/panic context.
 */
__result_use_check
static kern_return_t
stackshot_finalize_singlethreaded_kcdata(void)
{
	kern_return_t error;

	assert(stackshot_ctx.sc_is_singlethreaded);

	kcd_exit_on_error(stackshot_push_duration_and_latency(stackshot_ctx.sc_finalized_kcdata));
	/* Note: exactly 0 or 1 call to something pushing more data can be called after kcd_finalize_compression */
	kcd_finalize_compression(stackshot_ctx.sc_finalized_kcdata);
	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_ctx.sc_finalized_kcdata, stackshot_flags, "stackshot_out_flags"));
	kcd_exit_on_error(kcdata_write_buffer_end(stackshot_ctx.sc_finalized_kcdata));

	stackshot_ctx.sc_bytes_traced = (uint32_t) kcdata_memory_get_used_bytes(stackshot_ctx.sc_finalized_kcdata);
	stackshot_ctx.sc_bytes_uncompressed = (uint32_t) kcdata_memory_get_uncompressed_bytes(stackshot_ctx.sc_finalized_kcdata);

	kcd_exit_on_error(kcdata_finish(stackshot_ctx.sc_finalized_kcdata));

	if (stackshot_ctx.sc_panic_stackshot) {
		*stackshot_args.descriptor = *stackshot_ctx.sc_finalized_kcdata;
	}

error_exit:
	return error;
}

/*
 * stackshot_remap_buffer:	Utility function to remap bytes_traced bytes starting at stackshotbuf
 *				into the current task's user space and subsequently copy out the address
 *				at which the buffer has been mapped in user space to out_buffer_addr.
 *
 * Inputs:			stackshotbuf - pointer to the original buffer in the kernel's address space
 *				bytes_traced - length of the buffer to remap starting from stackshotbuf
 *				out_buffer_addr - pointer to placeholder where newly mapped buffer will be mapped.
 *				out_size_addr - pointer to be filled in with the size of the buffer
 *
 * Outputs:			ENOSPC if there is not enough free space in the task's address space to remap the buffer
 *				EINVAL for all other errors returned by task_remap_buffer/mach_vm_remap
 *				an error from copyout
 */
static kern_return_t
stackshot_remap_buffer(void *stackshotbuf, uint32_t bytes_traced, uint64_t out_buffer_addr, uint64_t out_size_addr)
{
	int                     error = 0;
	mach_vm_offset_t        stackshotbuf_user_addr = (mach_vm_offset_t)NULL;
	vm_prot_t               cur_prot = VM_PROT_NONE, max_prot = VM_PROT_NONE;

	error = mach_vm_remap(current_map(), &stackshotbuf_user_addr, bytes_traced, 0,
	    VM_FLAGS_ANYWHERE, kernel_map, (mach_vm_offset_t)stackshotbuf, FALSE,
	    &cur_prot, &max_prot, VM_INHERIT_DEFAULT);
	/*
	 * If the call to mach_vm_remap fails, we return the appropriate converted error
	 */
	if (error == KERN_SUCCESS) {
		/* If the user addr somehow didn't get set, we should make sure that we fail, and (eventually)
		 * panic on development kernels to find out why
		 */
		if (stackshotbuf_user_addr == (mach_vm_offset_t)NULL) {
#if DEVELOPMENT || DEBUG
			os_log_error(OS_LOG_DEFAULT, "stackshot: mach_vm_remap succeeded with NULL\n");
#endif // DEVELOPMENT || DEBUG
			return KERN_FAILURE;
		}

		/*
		 * If we fail to copy out the address or size of the new buffer, we remove the buffer mapping that
		 * we just made in the task's user space.
		 */
		error = copyout(CAST_DOWN(void *, &stackshotbuf_user_addr), (user_addr_t)out_buffer_addr, sizeof(stackshotbuf_user_addr));
		if (error != KERN_SUCCESS) {
			mach_vm_deallocate(get_task_map(current_task()), stackshotbuf_user_addr, (mach_vm_size_t)bytes_traced);
			return error;
		}
		error = copyout(&bytes_traced, (user_addr_t)out_size_addr, sizeof(bytes_traced));
		if (error != KERN_SUCCESS) {
			mach_vm_deallocate(get_task_map(current_task()), stackshotbuf_user_addr, (mach_vm_size_t)bytes_traced);
			return error;
		}
	}
	return error;
}

#if CONFIG_EXCLAVES

static kern_return_t
stackshot_setup_exclave_waitlist(void)
{
	kern_return_t error = KERN_SUCCESS;
	size_t exclave_threads_max = exclaves_ipc_buffer_count();
	size_t waitlist_size = 0;

	assert(!stackshot_exclave_inspect_ctids);

	if (exclaves_inspection_is_initialized() && exclave_threads_max) {
		if (os_mul_overflow(exclave_threads_max, sizeof(ctid_t), &waitlist_size)) {
			error = KERN_INVALID_ARGUMENT;
			goto error;
		}
		stackshot_exclave_inspect_ctids = stackshot_alloc_with_size(waitlist_size, &error);
		if (!stackshot_exclave_inspect_ctids) {
			goto error;
		}
		stackshot_exclave_inspect_ctid_count = 0;
		stackshot_exclave_inspect_ctid_capacity = exclave_threads_max;
	}

error:
	return error;
}

static kern_return_t
collect_exclave_threads(uint64_t ss_flags)
{
	size_t i;
	ctid_t ctid;
	thread_t thread;
	kern_return_t kr = KERN_SUCCESS;
	STACKSHOT_SUBSYS_ASSERT_LOCKED();

	lck_mtx_lock(&exclaves_collect_mtx);

	if (stackshot_exclave_inspect_ctid_count == 0) {
		/* Nothing to do */
		goto out;
	}

	// When asking for ASIDs, make sure we get all exclaves asids and mappings as well
	exclaves_stackshot_raw_addresses = (ss_flags & STACKSHOT_ASID);
	exclaves_stackshot_all_address_spaces = (ss_flags & (STACKSHOT_ASID | STACKSHOT_EXCLAVES));

	/* This error is intentionally ignored: we are now committed to collecting
	 * these threads, or at least properly waking them. If this fails, the first
	 * collected thread should also fail to append to the kcdata, and will abort
	 * further collection, properly clearing the AST and waking these threads.
	 */
	kcdata_add_container_marker(stackshot_ctx.sc_finalized_kcdata, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVES, 0);

	for (i = 0; i < stackshot_exclave_inspect_ctid_count; ++i) {
		ctid = stackshot_exclave_inspect_ctids[i];
		thread = ctid_get_thread(ctid);
		assert(thread);
		exclaves_inspection_queue_add(&exclaves_inspection_queue_stackshot, &thread->th_exclaves_inspection_queue_stackshot);
	}
	exclaves_inspection_begin_collecting();
	exclaves_inspection_wait_complete(&exclaves_inspection_queue_stackshot);
	kr = stackshot_exclave_kr; /* Read the result of work done on our behalf, by collection thread */
	if (kr != KERN_SUCCESS) {
		goto out;
	}

	kr = kcdata_add_container_marker(stackshot_ctx.sc_finalized_kcdata, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVES, 0);
	if (kr != KERN_SUCCESS) {
		goto out;
	}
out:
	/* clear Exclave buffer now that it's been used */
	stackshot_exclave_inspect_ctids = NULL;
	stackshot_exclave_inspect_ctid_capacity = 0;
	stackshot_exclave_inspect_ctid_count = 0;

	lck_mtx_unlock(&exclaves_collect_mtx);
	return kr;
}

static kern_return_t
stackshot_exclaves_process_stacktrace(const address_v__opt_s *_Nonnull st, void *kcdata_ptr)
{
	kern_return_t error = KERN_SUCCESS;
	exclave_ecstackentry_addr_t * addr = NULL;
	__block size_t count = 0;

	if (!st->has_value) {
		goto error_exit;
	}

	address__v_visit(&st->value, ^(size_t __unused i, const stackshottypes_address_s __unused item) {
		count++;
	});

	kcdata_compression_window_open(kcdata_ptr);
	kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_ECSTACK,
	    sizeof(exclave_ecstackentry_addr_t), count, (mach_vm_address_t*)&addr));

	address__v_visit(&st->value, ^(size_t i, const stackshottypes_address_s item) {
		addr[i] = (exclave_ecstackentry_addr_t)item;
	});

	kcd_exit_on_error(kcdata_compression_window_close(kcdata_ptr));

error_exit:
	return error;
}

static kern_return_t
stackshot_exclaves_process_ipcstackentry(uint64_t index, const stackshottypes_ipcstackentry_s *_Nonnull ise, void *kcdata_ptr)
{
	kern_return_t error = KERN_SUCCESS;

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY, index));

	struct exclave_ipcstackentry_info info = { 0 };
	info.eise_asid = ise->asid;

	info.eise_tnid = ise->tnid;

	if (ise->invocationid.has_value) {
		info.eise_flags |= kExclaveIpcStackEntryHaveInvocationID;
		info.eise_invocationid = ise->invocationid.value;
	} else {
		info.eise_invocationid = 0;
	}

	info.eise_flags |= (ise->stacktrace.has_value ? kExclaveIpcStackEntryHaveStack : 0);

	kcd_exit_on_error(kcdata_push_data(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_IPCSTACKENTRY_INFO, sizeof(struct exclave_ipcstackentry_info), &info));

	if (ise->stacktrace.has_value) {
		kcd_exit_on_error(stackshot_exclaves_process_stacktrace(&ise->stacktrace, kcdata_ptr));
	}

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVE_IPCSTACKENTRY, index));

error_exit:
	return error;
}

static kern_return_t
stackshot_exclaves_process_ipcstack(const stackshottypes_ipcstackentry_v__opt_s *_Nonnull ipcstack, void *kcdata_ptr)
{
	__block kern_return_t kr = KERN_SUCCESS;

	if (!ipcstack->has_value) {
		goto error_exit;
	}

	stackshottypes_ipcstackentry__v_visit(&ipcstack->value, ^(size_t i, const stackshottypes_ipcstackentry_s *_Nonnull item) {
		if (kr == KERN_SUCCESS) {
		        kr = stackshot_exclaves_process_ipcstackentry(i, item, kcdata_ptr);
		}
	});

error_exit:
	return kr;
}

static kern_return_t
stackshot_exclaves_process_stackshotentry(const stackshot_stackshotentry_s *_Nonnull se, void *kcdata_ptr)
{
	kern_return_t error = KERN_SUCCESS;

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT, se->scid));

	struct exclave_scresult_info info = { 0 };
	info.esc_id = se->scid;
	info.esc_flags = se->ipcstack.has_value ? kExclaveScresultHaveIPCStack : 0;

	kcd_exit_on_error(kcdata_push_data(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_SCRESULT_INFO, sizeof(struct exclave_scresult_info), &info));

	if (se->ipcstack.has_value) {
		kcd_exit_on_error(stackshot_exclaves_process_ipcstack(&se->ipcstack, kcdata_ptr));
	}

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVE_SCRESULT, se->scid));

error_exit:
	return error;
}

static kern_return_t
stackshot_exclaves_process_textlayout_segments(const stackshottypes_textlayout_s *_Nonnull tl, void *kcdata_ptr, bool want_raw_addresses)
{
	kern_return_t error = KERN_SUCCESS;
	__block struct exclave_textlayout_segment_v2 * info = NULL;

	__block size_t count = 0;
	stackshottypes_textsegment__v_visit(&tl->textsegments, ^(size_t __unused i, const stackshottypes_textsegment_s __unused *_Nonnull item) {
		count++;
	});

	if (!count) {
		goto error_exit;
	}

	kcdata_compression_window_open(kcdata_ptr);
	kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_SEGMENTS,
	    sizeof(struct exclave_textlayout_segment_v2), count, (mach_vm_address_t*)&info));

	stackshottypes_textsegment__v_visit(&tl->textsegments, ^(size_t __unused i, const stackshottypes_textsegment_s *_Nonnull item) {
		memcpy(&info->layoutSegment_uuid, item->uuid, sizeof(uuid_t));
		info->layoutSegment_loadAddress = item->loadaddress;
		if (want_raw_addresses) {
		        info->layoutSegment_rawLoadAddress = item->rawloadaddress.has_value ? item->rawloadaddress.value: 0;
		} else {
		        info->layoutSegment_rawLoadAddress = 0;
		}
		info++;
	});

	kcd_exit_on_error(kcdata_compression_window_close(kcdata_ptr));

error_exit:
	return error;
}

static kern_return_t
stackshot_exclaves_process_textlayout(const stackshottypes_textlayout_s *_Nonnull tl, void *kcdata_ptr, bool want_raw_addresses)
{
	kern_return_t error = KERN_SUCCESS;
	__block struct exclave_textlayout_info info = { 0 };

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT, tl->textlayoutid));

	// tightbeam optional interfaced don't have enough const.
	u32__opt_s sharedcacheindex_opt = tl->sharedcacheindex;
	const uint32_t *sharedcache_index = u32__opt_get(&sharedcacheindex_opt);

	info.layout_id = tl->textlayoutid;

	info.etl_flags =
	    (want_raw_addresses ? 0 : kExclaveTextLayoutLoadAddressesUnslid) |
	    (sharedcache_index == NULL ? 0 : kExclaveTextLayoutHasSharedCache);
	info.sharedcache_index = (sharedcache_index == NULL) ? UINT32_MAX : *sharedcache_index;

	kcd_exit_on_error(kcdata_push_data(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_TEXTLAYOUT_INFO, sizeof(struct exclave_textlayout_info), &info));
	kcd_exit_on_error(stackshot_exclaves_process_textlayout_segments(tl, kcdata_ptr, want_raw_addresses));
	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVE_TEXTLAYOUT, tl->textlayoutid));
error_exit:
	return error;
}

static kern_return_t
stackshot_exclaves_process_addressspace(const stackshottypes_addressspace_s *_Nonnull as, void *kcdata_ptr, bool want_raw_addresses)
{
	kern_return_t error = KERN_SUCCESS;
	struct exclave_addressspace_info info = { 0 };
	__block size_t name_len = 0;
	uint8_t * name = NULL;

	u8__v_visit(&as->name, ^(size_t __unused i, const uint8_t __unused item) {
		name_len++;
	});

	info.eas_id = as->asid;

	if (want_raw_addresses && as->rawaddressslide.has_value) {
		info.eas_flags = kExclaveAddressSpaceHaveSlide;
		info.eas_slide = as->rawaddressslide.value;
	} else {
		info.eas_flags = 0;
		info.eas_slide = UINT64_MAX;
	}

	info.eas_layoutid = as->textlayoutid; // text layout for this address space
	info.eas_asroot = as->asroot.has_value ? as->asroot.value : 0;

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_BEGIN,
	    STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE, as->asid));
	kcd_exit_on_error(kcdata_push_data(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_INFO, sizeof(struct exclave_addressspace_info), &info));

	if (name_len > 0) {
		kcdata_compression_window_open(kcdata_ptr);
		kcd_exit_on_error(kcdata_get_memory_addr(kcdata_ptr, STACKSHOT_KCTYPE_EXCLAVE_ADDRESSSPACE_NAME, name_len + 1, (mach_vm_address_t*)&name));

		u8__v_visit(&as->name, ^(size_t i, const uint8_t item) {
			name[i] = item;
		});
		name[name_len] = 0;

		kcd_exit_on_error(kcdata_compression_window_close(kcdata_ptr));
	}

	kcd_exit_on_error(kcdata_add_container_marker(kcdata_ptr, KCDATA_TYPE_CONTAINER_END,
	    STACKSHOT_KCCONTAINER_EXCLAVE_ADDRESSSPACE, as->asid));
error_exit:
	return error;
}

kern_return_t
stackshot_exclaves_process_stackshot(const stackshot_stackshotresult_s *result, void *kcdata_ptr, bool want_raw_addresses);

kern_return_t
stackshot_exclaves_process_stackshot(const stackshot_stackshotresult_s *result, void *kcdata_ptr, bool want_raw_addresses)
{
	__block kern_return_t kr = KERN_SUCCESS;

	stackshot_stackshotentry__v_visit(&result->stackshotentries, ^(size_t __unused i, const stackshot_stackshotentry_s *_Nonnull item) {
		if (kr == KERN_SUCCESS) {
		        kr = stackshot_exclaves_process_stackshotentry(item, kcdata_ptr);
		}
	});

	stackshottypes_addressspace__v_visit(&result->addressspaces, ^(size_t __unused i, const stackshottypes_addressspace_s *_Nonnull item) {
		if (kr == KERN_SUCCESS) {
		        kr = stackshot_exclaves_process_addressspace(item, kcdata_ptr, want_raw_addresses);
		}
	});

	stackshottypes_textlayout__v_visit(&result->textlayouts, ^(size_t __unused i, const stackshottypes_textlayout_s *_Nonnull item) {
		if (kr == KERN_SUCCESS) {
		        kr = stackshot_exclaves_process_textlayout(item, kcdata_ptr, want_raw_addresses);
		}
	});

	return kr;
}

kern_return_t
stackshot_exclaves_process_result(kern_return_t collect_kr, const stackshot_stackshotresult_s *result, bool want_raw_addresses);

kern_return_t
stackshot_exclaves_process_result(kern_return_t collect_kr, const stackshot_stackshotresult_s *result, bool want_raw_addresses)
{
	kern_return_t kr = KERN_SUCCESS;
	if (result == NULL) {
		return collect_kr;
	}

	kr = stackshot_exclaves_process_stackshot(result, stackshot_ctx.sc_finalized_kcdata, want_raw_addresses);

	stackshot_exclave_kr = kr;

	return kr;
}


static void
commit_exclaves_ast(void)
{
	size_t i = 0;
	thread_t thread = NULL;
	size_t count;

	assert(debug_mode_active());

	count = os_atomic_load(&stackshot_exclave_inspect_ctid_count, acquire);

	if (stackshot_exclave_inspect_ctids) {
		for (i = 0; i < count; ++i) {
			thread = ctid_get_thread(stackshot_exclave_inspect_ctids[i]);
			assert(thread);
			thread_reference(thread);
			os_atomic_or(&thread->th_exclaves_inspection_state, TH_EXCLAVES_INSPECTION_STACKSHOT, relaxed);
		}
	}
}

#endif /* CONFIG_EXCLAVES */

kern_return_t
kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user)
{
	int error = 0;
	boolean_t prev_interrupt_state;
	bool did_copyout = false;
	uint32_t bytes_traced = 0;
	uint32_t stackshot_estimate = 0;
	struct kdp_snapshot_args snapshot_args;

	void * buf_to_free = NULL;
	int size_to_free = 0;
	bool is_traced = false;    /* has FUNC_START tracepoint fired? */
	uint64_t tot_interrupts_off_abs = 0; /* sum(time with interrupts off) */

	/* Parsed arguments */
	uint64_t                out_buffer_addr;
	uint64_t                out_size_addr;
	uint32_t                size_hint = 0;

	snapshot_args.pagetable_mask = STACKSHOT_PAGETABLES_MASK_ALL;

	if (stackshot_config == NULL) {
		return KERN_INVALID_ARGUMENT;
	}
#if DEVELOPMENT || DEBUG
	/* TBD: ask stackshot clients to avoid issuing stackshots in this
	 * configuration in lieu of the kernel feature override.
	 */
	if (kern_feature_override(KF_STACKSHOT_OVRD) == TRUE) {
		return KERN_NOT_SUPPORTED;
	}
#endif

	switch (stackshot_config_version) {
	case STACKSHOT_CONFIG_TYPE:
		if (stackshot_config_size != sizeof(stackshot_config_t)) {
			return KERN_INVALID_ARGUMENT;
		}
		stackshot_config_t *config = (stackshot_config_t *) stackshot_config;
		out_buffer_addr = config->sc_out_buffer_addr;
		out_size_addr = config->sc_out_size_addr;
		snapshot_args.pid = config->sc_pid;
		snapshot_args.flags = config->sc_flags;
		snapshot_args.since_timestamp = config->sc_delta_timestamp;
		if (config->sc_size <= max_tracebuf_size) {
			size_hint = config->sc_size;
		}
		/*
		 * Retain the pre-sc_pagetable_mask behavior of STACKSHOT_PAGE_TABLES,
		 * dump every level if the pagetable_mask is not set
		 */
		if (snapshot_args.flags & STACKSHOT_PAGE_TABLES && config->sc_pagetable_mask) {
			snapshot_args.pagetable_mask = config->sc_pagetable_mask;
		}
		break;
	default:
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * Currently saving a kernel buffer and trylock are only supported from the
	 * internal/KEXT API.
	 */
	if (stackshot_from_user) {
		if (snapshot_args.flags & (STACKSHOT_TRYLOCK | STACKSHOT_SAVE_IN_KERNEL_BUFFER | STACKSHOT_FROM_PANIC)) {
			return KERN_NO_ACCESS;
		}
#if !DEVELOPMENT && !DEBUG
		if (snapshot_args.flags & (STACKSHOT_DO_COMPRESS)) {
			return KERN_NO_ACCESS;
		}
#endif
	} else {
		if (!(snapshot_args.flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
			return KERN_NOT_SUPPORTED;
		}
	}

	if (!((snapshot_args.flags & STACKSHOT_KCDATA_FORMAT) || (snapshot_args.flags & STACKSHOT_RETRIEVE_EXISTING_BUFFER))) {
		return KERN_NOT_SUPPORTED;
	}

	/* Compresssed delta stackshots or page dumps are not yet supported */
	if (((snapshot_args.flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) || (snapshot_args.flags & STACKSHOT_PAGE_TABLES))
	    && (snapshot_args.flags & STACKSHOT_DO_COMPRESS)) {
		return KERN_NOT_SUPPORTED;
	}

	/*
	 * If we're not saving the buffer in the kernel pointer, we need a place to copy into.
	 */
	if ((!out_buffer_addr || !out_size_addr) && !(snapshot_args.flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
		return KERN_INVALID_ARGUMENT;
	}

	if (snapshot_args.since_timestamp != 0 && ((snapshot_args.flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) == 0)) {
		return KERN_INVALID_ARGUMENT;
	}

	/* EXCLAVES and SKIP_EXCLAVES conflict */
	if ((snapshot_args.flags & (STACKSHOT_EXCLAVES | STACKSHOT_SKIP_EXCLAVES)) == (STACKSHOT_EXCLAVES | STACKSHOT_SKIP_EXCLAVES)) {
		return KERN_INVALID_ARGUMENT;
	}

#if CONFIG_PERVASIVE_CPI && CONFIG_CPU_COUNTERS
	if (!mt_core_supported) {
		snapshot_args.flags &= ~STACKSHOT_INSTRS_CYCLES;
	}
#else /* CONFIG_PERVASIVE_CPI && CONFIG_CPU_COUNTERS */
	snapshot_args.flags &= ~STACKSHOT_INSTRS_CYCLES;
#endif /* !CONFIG_PERVASIVE_CPI || !CONFIG_CPU_COUNTERS */

	STACKSHOT_TESTPOINT(TP_WAIT_START_STACKSHOT);
	STACKSHOT_SUBSYS_LOCK();

	stackshot_tries = 0;

	if (snapshot_args.flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER) {
		/*
		 * Don't overwrite an existing stackshot
		 */
		if (kernel_stackshot_buf != NULL) {
			error = KERN_MEMORY_PRESENT;
			goto error_early_exit;
		}
	} else if (snapshot_args.flags & STACKSHOT_RETRIEVE_EXISTING_BUFFER) {
		if ((kernel_stackshot_buf == NULL) || (kernel_stackshot_buf_size <= 0)) {
			error = KERN_NOT_IN_SET;
			goto error_early_exit;
		}
		error = stackshot_remap_buffer(kernel_stackshot_buf, kernel_stackshot_buf_size,
		    out_buffer_addr, out_size_addr);
		/*
		 * If we successfully remapped the buffer into the user's address space, we
		 * set buf_to_free and size_to_free so the prior kernel mapping will be removed
		 * and then clear the kernel stackshot pointer and associated size.
		 */
		if (error == KERN_SUCCESS) {
			did_copyout = true;
			buf_to_free = kernel_stackshot_buf;
			size_to_free = (int) VM_MAP_ROUND_PAGE(kernel_stackshot_buf_size, PAGE_MASK);
			kernel_stackshot_buf = NULL;
			kernel_stackshot_buf_size = 0;
		}

		goto error_early_exit;
	}

	if (snapshot_args.flags & STACKSHOT_GET_BOOT_PROFILE) {
		void *bootprofile = NULL;
		uint32_t len = 0;
#if CONFIG_TELEMETRY
		bootprofile_get(&bootprofile, &len);
#endif
		if (!bootprofile || !len) {
			error = KERN_NOT_IN_SET;
			goto error_early_exit;
		}
		error = stackshot_remap_buffer(bootprofile, len, out_buffer_addr, out_size_addr);
		if (error == KERN_SUCCESS) {
			did_copyout = true;
		}
		goto error_early_exit;
	}

	stackshot_duration_prior_abs = 0;
	stackshot_initial_estimate_adj = os_atomic_load(&stackshot_estimate_adj, relaxed);
	snapshot_args.buffer_size = stackshot_estimate =
	    get_stackshot_estsize(size_hint, stackshot_initial_estimate_adj, snapshot_args.flags, snapshot_args.pid);
	stackshot_initial_estimate = stackshot_estimate;

	// ensure at least one attempt, even if the initial size from estimate was too big
	snapshot_args.buffer_size = MIN(snapshot_args.buffer_size, max_tracebuf_size);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_STACKSHOT, STACKSHOT_RECORD) | DBG_FUNC_START,
	    snapshot_args.flags, snapshot_args.buffer_size, snapshot_args.pid, snapshot_args.since_timestamp);
	is_traced = true;

#if CONFIG_EXCLAVES
	assert(!stackshot_exclave_inspect_ctids);
#endif

	for (; snapshot_args.buffer_size <= max_tracebuf_size; snapshot_args.buffer_size = MIN(snapshot_args.buffer_size << 1, max_tracebuf_size)) {
		stackshot_tries++;
		if ((error = kmem_alloc(kernel_map, (vm_offset_t *)&snapshot_args.buffer, snapshot_args.buffer_size,
		    KMA_ZERO | KMA_DATA, VM_KERN_MEMORY_DIAG)) != KERN_SUCCESS) {
			os_log_error(OS_LOG_DEFAULT, "stackshot: initial allocation failed: %d, allocating %u bytes of %u max, try %llu\n", (int)error, snapshot_args.buffer_size, max_tracebuf_size, stackshot_tries);
			error = KERN_RESOURCE_SHORTAGE;
			goto error_exit;
		}

		uint32_t hdr_tag = (snapshot_args.flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
		    : (snapshot_args.flags & STACKSHOT_DO_COMPRESS) ? KCDATA_BUFFER_BEGIN_COMPRESSED
		    : KCDATA_BUFFER_BEGIN_STACKSHOT;
		#pragma unused(hdr_tag)

		stackshot_duration_outer = NULL;

		/* if compression was requested, allocate the extra zlib scratch area */
		if (snapshot_args.flags & STACKSHOT_DO_COMPRESS) {
			hdr_tag = (snapshot_args.flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
			    : KCDATA_BUFFER_BEGIN_STACKSHOT;
			if (error != KERN_SUCCESS) {
				os_log_error(OS_LOG_DEFAULT, "failed to initialize compression: %d!\n",
				    (int) error);
				goto error_exit;
			}
		}

		/* Prepare the compressor for a stackshot */
		error = vm_compressor_kdp_init();
		if (error != KERN_SUCCESS) {
			goto error_exit;
		}

		/*
		 * Disable interrupts and save the current interrupt state.
		 */
		prev_interrupt_state = ml_set_interrupts_enabled(FALSE);
		uint64_t time_start  = mach_absolute_time();

		/* Emit a SOCD tracepoint that we are initiating a stackshot */
		SOCD_TRACE_XNU_START(STACKSHOT);

		/*
		 * Load stackshot parameters.
		 */
		error = kdp_snapshot_preflight_internal(snapshot_args);

		if (error == KERN_SUCCESS) {
			error = stackshot_trap();
		}

		/* Emit a SOCD tracepoint that we have completed the stackshot */
		SOCD_TRACE_XNU_END(STACKSHOT);
		ml_set_interrupts_enabled(prev_interrupt_state);

#if CONFIG_EXCLAVES
		/* stackshot trap should only finish successfully or with no pending Exclave threads */
		assert(error == KERN_SUCCESS || stackshot_exclave_inspect_ctids == NULL);
#endif

		/*
		 * Stackshot is no longer active.
		 * (We have to do this here for the special interrupt disable timeout case to work)
		 */
		os_atomic_store(&stackshot_ctx.sc_state, SS_INACTIVE, release);

		/* Release compressor kdp buffers */
		vm_compressor_kdp_teardown();

		/* Record duration that interrupts were disabled */
		uint64_t time_end = mach_absolute_time();
		tot_interrupts_off_abs += (time_end - time_start);

		/* Collect multithreaded kcdata into one finalized buffer */
		if (error == KERN_SUCCESS && !stackshot_ctx.sc_is_singlethreaded) {
			error = stackshot_collect_kcdata();
		}

#if CONFIG_EXCLAVES
		if (error == KERN_SUCCESS && stackshot_exclave_inspect_ctids) {
			if (stackshot_exclave_inspect_ctid_count > 0) {
				STACKSHOT_TESTPOINT(TP_START_COLLECTION);
			}
			error = collect_exclave_threads(snapshot_args.flags);
		}
#endif /* CONFIG_EXCLAVES */

		if (error == KERN_SUCCESS) {
			if (stackshot_ctx.sc_is_singlethreaded) {
				error = stackshot_finalize_singlethreaded_kcdata();
			} else {
				error = stackshot_finalize_kcdata();
			}

			if ((error != KERN_SUCCESS) && (error != KERN_INSUFFICIENT_BUFFER_SIZE)) {
				goto error_exit;
			}
			if (error == KERN_INSUFFICIENT_BUFFER_SIZE && snapshot_args.buffer_size == max_tracebuf_size) {
				os_log_error(OS_LOG_DEFAULT, "stackshot: final buffer size was insufficient at maximum size\n");
				error = KERN_RESOURCE_SHORTAGE;
				goto error_exit;
			}
		}

		/* record the duration that interupts were disabled + kcdata was being finalized */
		if (stackshot_duration_outer) {
			*stackshot_duration_outer = mach_absolute_time() - time_start;
		}

		if (error != KERN_SUCCESS) {
			os_log_error(OS_LOG_DEFAULT, "stackshot: debugger call failed: %d, try %llu, buffer %u estimate %u\n", (int)error, stackshot_tries, snapshot_args.buffer_size, stackshot_estimate);
			kmem_free(kernel_map, (vm_offset_t)snapshot_args.buffer, snapshot_args.buffer_size);
			snapshot_args.buffer = NULL;
			if (error == KERN_INSUFFICIENT_BUFFER_SIZE) {
				/*
				 * If we didn't allocate a big enough buffer, deallocate and try again.
				 */
				KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_STACKSHOT, STACKSHOT_RECORD_SHORT) | DBG_FUNC_NONE,
				    time_end - time_start, stackshot_estimate, snapshot_args.buffer_size);
				stackshot_duration_prior_abs += (time_end - time_start);
				if (snapshot_args.buffer_size == max_tracebuf_size) {
					os_log_error(OS_LOG_DEFAULT, "stackshot: initial buffer size was insufficient at maximum size\n");
					error = KERN_RESOURCE_SHORTAGE;
					goto error_exit;
				}
				continue;
			} else {
				goto error_exit;
			}
		}

		bytes_traced = kdp_stack_snapshot_bytes_traced();
		if (bytes_traced <= 0) {
			error = KERN_ABORTED;
			goto error_exit;
		}

		if (!(snapshot_args.flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER)) {
			error = stackshot_remap_buffer(snapshot_args.buffer, bytes_traced, out_buffer_addr, out_size_addr);
			if (error == KERN_SUCCESS) {
				did_copyout = true;
			}
			goto error_exit;
		}

		if (!(snapshot_args.flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT)) {
			os_log_info(OS_LOG_DEFAULT, "stackshot: succeeded, traced %u bytes to %u buffer (estimate %u) try %llu\n", bytes_traced, snapshot_args.buffer_size, stackshot_estimate, stackshot_tries);
		}

		/*
		 * Save the stackshot in the kernel buffer.
		 */
		kernel_stackshot_buf = snapshot_args.buffer;
		kernel_stackshot_buf_size =  bytes_traced;
		/*
		 * Figure out if we didn't use all the pages in the buffer. If so, we set buf_to_free to the beginning of
		 * the next page after the end of the stackshot in the buffer so that the kmem_free clips the buffer and
		 * update size_to_free for kmem_free accordingly.
		 */
		size_to_free = snapshot_args.buffer_size - (int) VM_MAP_ROUND_PAGE(bytes_traced, PAGE_MASK);

		assert(size_to_free >= 0);

		if (size_to_free != 0) {
			buf_to_free = (void *)((uint64_t)snapshot_args.buffer + snapshot_args.buffer_size - size_to_free);
		}

		snapshot_args.buffer = NULL;
		snapshot_args.buffer_size = 0;
		goto error_exit;
	}

error_exit:
	if (is_traced) {
		KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_STACKSHOT, STACKSHOT_RECORD) | DBG_FUNC_END,
		    error, tot_interrupts_off_abs, snapshot_args.buffer_size, bytes_traced);
	}

error_early_exit:
	if (snapshot_args.buffer != NULL) {
		kmem_free(kernel_map, (vm_offset_t)snapshot_args.buffer, snapshot_args.buffer_size);
	}
	if (buf_to_free != NULL) {
		kmem_free(kernel_map, (vm_offset_t)buf_to_free, size_to_free);
	}

	if (error == KERN_SUCCESS && !(snapshot_args.flags & STACKSHOT_SAVE_IN_KERNEL_BUFFER) && !did_copyout) {
		/* If we return success, we must have done the copyout to userspace. If
		 * we somehow did not, we need to indicate failure instead.
		 */
#if DEVELOPMENT || DEBUG
		os_log_error(OS_LOG_DEFAULT, "stackshot: reached end without doing copyout\n");
#endif // DEVELOPMENT || DEBUG
		error = KERN_FAILURE;
	}

	STACKSHOT_SUBSYS_UNLOCK();
	STACKSHOT_TESTPOINT(TP_STACKSHOT_DONE);

	return error;
}

/*
 * Set up state and parameters for a stackshot.
 * (This runs on the calling CPU before other CPUs enter the debugger trap.)
 * Called when interrupts are disabled, but we're not in the debugger trap yet.
 */
__result_use_check
static kern_return_t
kdp_snapshot_preflight_internal(struct kdp_snapshot_args args)
{
	kern_return_t error = KERN_SUCCESS;
	uint64_t microsecs = 0, secs = 0;
	bool is_panic = ((args.flags & STACKSHOT_FROM_PANIC) != 0);
	bool process_scoped = (args.pid != -1) &&
	    ((args.flags & STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL) == 0);
	bool is_singlethreaded = stackshot_single_thread || (process_scoped || is_panic || ((args.flags & STACKSHOT_PAGE_TABLES) != 0));
	clock_get_calendar_microtime((clock_sec_t *)&secs, (clock_usec_t *)&microsecs);

	cur_stackshot_ctx_idx = (is_panic ? STACKSHOT_CTX_IDX_PANIC : STACKSHOT_CTX_IDX_NORMAL);

	/* Setup overall state */
	stackshot_ctx = (struct stackshot_context) {
		.sc_args               = args,
		.sc_state              = SS_SETUP,
		.sc_bytes_traced       = 0,
		.sc_bytes_uncompressed = 0,
		.sc_microsecs          = microsecs + (secs * USEC_PER_SEC),
		.sc_panic_stackshot    = is_panic,
		.sc_is_singlethreaded  = is_singlethreaded,
		.sc_cpus_working       = 0,
		.sc_retval             = 0,
		.sc_calling_cpuid      = cpu_number(),
		.sc_main_cpuid         = is_singlethreaded ? cpu_number() : -1,
		.sc_min_kcdata_size    = get_stackshot_est_tasksize(args.flags),
		.sc_enable_faulting    = false,
	};

	if (!stackshot_ctx.sc_panic_stackshot) {
#if defined(__AMP__)
		/* On AMP systems, we want to split the buffers up by cluster to avoid cache line effects. */
		stackshot_ctx.sc_num_buffers = is_singlethreaded ? 1 : ml_get_cluster_count();
#else /* __AMP__ */
		stackshot_ctx.sc_num_buffers = 1;
#endif /* !__AMP__ */
		size_t bufsz = args.buffer_size / stackshot_ctx.sc_num_buffers;
		for (int buf_idx = 0; buf_idx < stackshot_ctx.sc_num_buffers; buf_idx++) {
			stackshot_ctx.sc_buffers[buf_idx] = (struct stackshot_buffer) {
				.ssb_ptr = (void*) ((mach_vm_address_t) args.buffer + (bufsz * buf_idx)),
				.ssb_size = bufsz,
				.ssb_used = 0,
				.ssb_freelist = NULL,
				.ssb_freelist_lock = 0,
				.ssb_overhead = 0
			};
		}

		/* Setup per-cpu state */
		percpu_foreach_base(base) {
			*PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu) = (struct stackshot_cpu_context) { 0 };
		}

		if (is_singlethreaded) {
			/* If the stackshot is singlethreaded, set up the kcdata - we don't bother with linked-list kcdata in singlethreaded mode. */
			uint32_t hdr_tag = (stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
			    : (stackshot_flags & STACKSHOT_DO_COMPRESS) ? KCDATA_BUFFER_BEGIN_COMPRESSED
			    : KCDATA_BUFFER_BEGIN_STACKSHOT;
			kcdata_memory_static_init(stackshot_kcdata_p, (mach_vm_address_t) stackshot_args.buffer, hdr_tag,
			    stackshot_args.buffer_size, KCFLAG_USE_MEMCOPY | KCFLAG_NO_AUTO_ENDBUFFER);
			if (stackshot_flags & STACKSHOT_DO_COMPRESS) {
				hdr_tag = (stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) ? KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT
				    : KCDATA_BUFFER_BEGIN_STACKSHOT;
				kcd_exit_on_error(kcdata_init_compress(stackshot_kcdata_p, hdr_tag, kdp_memcpy, KCDCT_ZLIB));
			}
			stackshot_cpu_ctx.scc_stack_buffer = kcdata_endalloc(stackshot_kcdata_p, sizeof(uintptr_t) * MAX_FRAMES);
		}
	} else {
		/*
		 * If this is a panic stackshot, we need to handle things differently.
		 * The panic code hands us a kcdata descriptor to work with instead of
		 * us making one ourselves.
		 */
		*stackshot_kcdata_p = *stackshot_args.descriptor;
		stackshot_cpu_ctx = (struct stackshot_cpu_context) {
			.scc_can_work = true,
			.scc_stack_buffer = kcdata_endalloc(stackshot_kcdata_p, sizeof(uintptr_t) * MAX_FRAMES)
		};
#if STACKSHOT_COLLECTS_LATENCY_INFO
		*(PERCPU_GET(stackshot_trace_buffer)) = (struct stackshot_trace_buffer) {};
#endif
	}

	/* Set up our cpu state */
	stackshot_cpu_preflight();

error_exit:
	return error;
}

/*
 * The old function signature for kdp_snapshot_preflight, used in the panic path.
 * Called when interrupts are disabled, but we're not in the debugger trap yet.
 */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint64_t flags,
    kcdata_descriptor_t data_p, uint64_t since_timestamp, uint32_t pagetable_mask)
{
	__assert_only kern_return_t err;
	err = kdp_snapshot_preflight_internal((struct kdp_snapshot_args) {
		.pid = pid,
		.buffer = tracebuf,
		.buffer_size = tracebuf_size,
		.flags = flags,
		.descriptor = data_p,
		.since_timestamp = since_timestamp,
		.pagetable_mask = pagetable_mask
	});


	/* This shouldn't ever return an error in the panic path. */
	assert(err == KERN_SUCCESS);
}

static void
stackshot_reset_state(void)
{
	stackshot_ctx = (struct stackshot_context) { 0 };
}

void
panic_stackshot_reset_state(void)
{
	stackshot_reset_state();
}

boolean_t
stackshot_active(void)
{
	return os_atomic_load(&stackshot_ctx.sc_state, relaxed) != SS_INACTIVE;
}

boolean_t
panic_stackshot_active(void)
{
	return os_atomic_load(&stackshot_contexts[STACKSHOT_CTX_IDX_PANIC].sc_state, relaxed) != SS_INACTIVE;
}

uint32_t
kdp_stack_snapshot_bytes_traced(void)
{
	return stackshot_ctx.sc_bytes_traced;
}

uint32_t
kdp_stack_snapshot_bytes_uncompressed(void)
{
	return stackshot_ctx.sc_bytes_uncompressed;
}

static boolean_t
memory_iszero(void *addr, size_t size)
{
	char *data = (char *)addr;
	for (size_t i = 0; i < size; i++) {
		if (data[i] != 0) {
			return FALSE;
		}
	}
	return TRUE;
}

static void
_stackshot_validation_reset(void)
{
	percpu_foreach_base(base) {
		struct stackshot_cpu_context *cpu_ctx = PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu);
		cpu_ctx->scc_validation_state.last_valid_page_kva = -1;
		cpu_ctx->scc_validation_state.last_valid_size = 0;
	}
}

static bool
_stackshot_validate_kva(vm_offset_t addr, size_t size)
{
	vm_offset_t page_addr = atop_kernel(addr);
	if (stackshot_cpu_ctx.scc_validation_state.last_valid_page_kva == page_addr &&
	    stackshot_cpu_ctx.scc_validation_state.last_valid_size <= size) {
		return true;
	}

	if (ml_validate_nofault(addr, size)) {
		stackshot_cpu_ctx.scc_validation_state.last_valid_page_kva = page_addr;
		stackshot_cpu_ctx.scc_validation_state.last_valid_size = size;
		return true;
	}
	return false;
}

static long
_stackshot_strlen(const char *s, size_t maxlen)
{
	size_t len = 0;
	for (len = 0; _stackshot_validate_kva((vm_offset_t)s, 1); len++, s++) {
		if (*s == 0) {
			return len;
		}
		if (len >= maxlen) {
			return -1;
		}
	}
	return -1; /* failed before end of string */
}


static size_t
stackshot_plh_est_size(void)
{
	struct port_label_hash *plh = &stackshot_ctx.sc_plh;
	size_t size = STASKSHOT_PLH_SIZE(stackshot_port_label_size);

	if (size == 0) {
		return 0;
	}
#define SIZE_EST(x) ROUNDUP((x), sizeof (uintptr_t))
	return SIZE_EST(size * sizeof(*plh->plh_array)) +
	       SIZE_EST(size * sizeof(*plh->plh_chains)) +
	       SIZE_EST(size * sizeof(*stackshot_cpu_ctx.scc_plh_gen.pgs_gen) * real_ncpus) +
	       SIZE_EST((1ul << STACKSHOT_PLH_SHIFT) * sizeof(*plh->plh_hash));
#undef SIZE_EST
}

static void
stackshot_plh_reset(void)
{
	stackshot_ctx.sc_plh = (struct port_label_hash){.plh_size = 0};  /* structure assignment */
}

static kern_return_t
stackshot_plh_setup(void)
{
	kern_return_t error;
	size_t size;
	bool percpu_alloc_failed = false;
	struct port_label_hash plh = {
		.plh_size = STASKSHOT_PLH_SIZE(stackshot_port_label_size),
		.plh_count = 0,
	};

	stackshot_plh_reset();

	percpu_foreach_base(base) {
		struct stackshot_cpu_context *cpu_ctx = PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu);
		cpu_ctx->scc_plh_gen = (struct _stackshot_plh_gen_state){
			.pgs_gen = NULL,
			.pgs_curgen = 1,
			.pgs_curgen_min = STACKSHOT_PLH_SIZE_MAX,
			.pgs_curgen_max = 0,
		};
	}

	size = plh.plh_size;
	if (size == 0) {
		return KERN_SUCCESS;
	}
	plh.plh_array = stackshot_alloc_with_size(size * sizeof(*plh.plh_array), &error);
	plh.plh_chains = stackshot_alloc_with_size(size * sizeof(*plh.plh_chains), &error);
	percpu_foreach_base(base) {
		struct stackshot_cpu_context *cpu_ctx = PERCPU_GET_WITH_BASE(base, stackshot_cpu_ctx_percpu);
		cpu_ctx->scc_plh_gen.pgs_gen = stackshot_alloc_with_size(size * sizeof(*cpu_ctx->scc_plh_gen.pgs_gen), &error);
		if (cpu_ctx->scc_plh_gen.pgs_gen == NULL) {
			percpu_alloc_failed = true;
			break;
		}
		for (int x = 0; x < size; x++) {
			cpu_ctx->scc_plh_gen.pgs_gen[x] = 0;
		}
	}
	plh.plh_hash = stackshot_alloc_with_size((1ul << STACKSHOT_PLH_SHIFT) * sizeof(*plh.plh_hash), &error);
	if (error != KERN_SUCCESS) {
		return error;
	}
	if (plh.plh_array == NULL || plh.plh_chains == NULL || percpu_alloc_failed || plh.plh_hash == NULL) {
		PLH_STAT_OP(os_atomic_inc(&stackshot_ctx.sc_plh.plh_bad, relaxed));
		return KERN_SUCCESS;
	}
	for (int x = 0; x < size; x++) {
		plh.plh_array[x] = NULL;
		plh.plh_chains[x] = -1;
	}
	for (int x = 0; x < (1ul << STACKSHOT_PLH_SHIFT); x++) {
		plh.plh_hash[x] = -1;
	}
	stackshot_ctx.sc_plh = plh;  /* structure assignment */
	return KERN_SUCCESS;
}

static int16_t
stackshot_plh_hash(struct ipc_service_port_label *ispl)
{
	uintptr_t ptr = (uintptr_t)ispl;
	static_assert(STACKSHOT_PLH_SHIFT < 16, "plh_hash must fit in 15 bits");
#define PLH_HASH_STEP(ptr, x) \
	    ((((x) * STACKSHOT_PLH_SHIFT) < (sizeof(ispl) * CHAR_BIT)) ? ((ptr) >> ((x) * STACKSHOT_PLH_SHIFT)) : 0)
	ptr ^= PLH_HASH_STEP(ptr, 16);
	ptr ^= PLH_HASH_STEP(ptr, 8);
	ptr ^= PLH_HASH_STEP(ptr, 4);
	ptr ^= PLH_HASH_STEP(ptr, 2);
	ptr ^= PLH_HASH_STEP(ptr, 1);
#undef PLH_HASH_STEP
	return (int16_t)(ptr & ((1ul << STACKSHOT_PLH_SHIFT) - 1));
}

enum stackshot_plh_lookup_type {
	STACKSHOT_PLH_LOOKUP_UNKNOWN,
	STACKSHOT_PLH_LOOKUP_SEND,
	STACKSHOT_PLH_LOOKUP_RECEIVE,
};

static void
stackshot_plh_resetgen(void)
{
	struct _stackshot_plh_gen_state *pgs = &stackshot_cpu_ctx.scc_plh_gen;
	uint16_t plh_size = stackshot_ctx.sc_plh.plh_size;

	if (pgs->pgs_curgen_min == STACKSHOT_PLH_SIZE_MAX && pgs->pgs_curgen_max == 0) {
		return;  // no lookups, nothing using the current generation
	}
	pgs->pgs_curgen++;
	pgs->pgs_curgen_min = STACKSHOT_PLH_SIZE_MAX;
	pgs->pgs_curgen_max = 0;
	if (pgs->pgs_curgen == 0) { // wrapped, zero the array and increment the generation
		for (int x = 0; x < plh_size; x++) {
			pgs->pgs_gen[x] = 0;
		}
		pgs->pgs_curgen = 1;
	}
}

static int16_t
stackshot_plh_lookup_locked(struct ipc_service_port_label *ispl, enum stackshot_plh_lookup_type type)
{
	struct port_label_hash *plh = &stackshot_ctx.sc_plh;
	int depth;
	int16_t cur;
	if (ispl == NULL) {
		return STACKSHOT_PORTLABELID_NONE;
	}
	switch (type) {
	case STACKSHOT_PLH_LOOKUP_SEND:
		PLH_STAT_OP(os_atomic_inc(&plh->plh_lookup_send, relaxed));
		break;
	case STACKSHOT_PLH_LOOKUP_RECEIVE:
		PLH_STAT_OP(os_atomic_inc(&plh->plh_lookup_receive, relaxed));
		break;
	default:
		break;
	}
	PLH_STAT_OP(os_atomic_inc(&plh->plh_lookups, relaxed));
	if (plh->plh_size == 0) {
		return STACKSHOT_PORTLABELID_MISSING;
	}
	int16_t hash = stackshot_plh_hash(ispl);
	assert(hash >= 0 && hash < (1ul << STACKSHOT_PLH_SHIFT));
	depth = 0;
	for (cur = plh->plh_hash[hash]; cur >= 0; cur = plh->plh_chains[cur]) {
		/* cur must be in-range, and chain depth can never be above our # allocated */
		if (cur >= plh->plh_count || depth > plh->plh_count || depth > plh->plh_size) {
			PLH_STAT_OP(os_atomic_inc(&plh->plh_bad, relaxed));
			PLH_STAT_OP(os_atomic_add(&plh->plh_bad_depth, depth, relaxed));
			return STACKSHOT_PORTLABELID_MISSING;
		}
		assert(cur < plh->plh_count);
		if (plh->plh_array[cur] == ispl) {
			PLH_STAT_OP(os_atomic_inc(&plh->plh_found, relaxed));
			PLH_STAT_OP(os_atomic_add(&plh->plh_found_depth, depth, relaxed));
			goto found;
		}
		depth++;
	}
	/* not found in hash table, so alloc and insert it */
	if (cur != -1) {
		PLH_STAT_OP(os_atomic_inc(&plh->plh_bad, relaxed));
		PLH_STAT_OP(os_atomic_add(&plh->plh_bad_depth, depth, relaxed));
		return STACKSHOT_PORTLABELID_MISSING; /* bad end of chain */
	}
	PLH_STAT_OP(os_atomic_inc(&plh->plh_insert, relaxed));
	PLH_STAT_OP(os_atomic_add(&plh->plh_insert_depth, depth, relaxed));
	if (plh->plh_count >= plh->plh_size) {
		return STACKSHOT_PORTLABELID_MISSING; /* no space */
	}
	cur = plh->plh_count;
	plh->plh_count++;
	plh->plh_array[cur] = ispl;
	plh->plh_chains[cur] = plh->plh_hash[hash];
	plh->plh_hash[hash] = cur;
found:  ;
	struct _stackshot_plh_gen_state *pgs = &stackshot_cpu_ctx.scc_plh_gen;
	pgs->pgs_gen[cur] = pgs->pgs_curgen;
	if (pgs->pgs_curgen_min > cur) {
		pgs->pgs_curgen_min = cur;
	}
	if (pgs->pgs_curgen_max < cur) {
		pgs->pgs_curgen_max = cur;
	}
	return cur + 1;   /* offset to avoid 0 */
}

static kern_return_t
kdp_stackshot_plh_record_locked(void)
{
	kern_return_t error = KERN_SUCCESS;
	struct port_label_hash *plh = &stackshot_ctx.sc_plh;
	struct _stackshot_plh_gen_state *pgs = &stackshot_cpu_ctx.scc_plh_gen;
	uint16_t count = plh->plh_count;
	uint8_t curgen = pgs->pgs_curgen;
	int16_t curgen_min = pgs->pgs_curgen_min;
	int16_t curgen_max = pgs->pgs_curgen_max;
	if (curgen_min <= curgen_max && curgen_max < count &&
	    count <= plh->plh_size && plh->plh_size <= STACKSHOT_PLH_SIZE_MAX) {
		struct ipc_service_port_label **arr = plh->plh_array;
		size_t ispl_size, max_namelen;
		kdp_ipc_splabel_size(&ispl_size, &max_namelen);
		for (int idx = curgen_min; idx <= curgen_max; idx++) {
			struct ipc_service_port_label *ispl = arr[idx];
			struct portlabel_info spl = {
				.portlabel_id = (idx + 1),
			};
			const char *name = NULL;
			long name_sz = 0;
			if (pgs->pgs_gen[idx] != curgen) {
				continue;
			}
			if (_stackshot_validate_kva((vm_offset_t)ispl, ispl_size)) {
				kdp_ipc_fill_splabel(ispl, &spl, &name);
#if STACKSHOT_COLLECTS_RDAR_126582377_DATA
			} else {
				if (ispl != NULL && (vm_offset_t)ispl >> 48 == 0x0000) {
					ca_event_t event_to_send = os_atomic_xchg(&rdar_126582377_event, NULL, relaxed);
					if (event_to_send) {
						CA_EVENT_SEND(event_to_send);
					}
				}
#endif
			}

			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
			    STACKSHOT_KCCONTAINER_PORTLABEL, idx + 1));
			if (name != NULL && (name_sz = _stackshot_strlen(name, max_namelen)) > 0) {   /* validates the kva */
				kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_PORTLABEL_NAME, name_sz + 1, name));
			} else {
				spl.portlabel_flags |= STACKSHOT_PORTLABEL_READFAILED;
			}
			kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_PORTLABEL, sizeof(spl), &spl));
			kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END,
			    STACKSHOT_KCCONTAINER_PORTLABEL, idx + 1));
		}
	}

error_exit:
	return error;
}

// record any PLH referenced since the last stackshot_plh_resetgen() call
static kern_return_t
kdp_stackshot_plh_record(void)
{
	kern_return_t error;
	plh_lock(&stackshot_ctx.sc_plh);
	error = kdp_stackshot_plh_record_locked();
	plh_unlock(&stackshot_ctx.sc_plh);
	return error;
}

static int16_t
stackshot_plh_lookup(struct ipc_service_port_label *ispl, enum stackshot_plh_lookup_type type)
{
	int16_t result;
	plh_lock(&stackshot_ctx.sc_plh);
	result = stackshot_plh_lookup_locked(ispl, type);
	plh_unlock(&stackshot_ctx.sc_plh);
	return result;
}

#if DEVELOPMENT || DEBUG
static kern_return_t
kdp_stackshot_plh_stats(void)
{
	kern_return_t error = KERN_SUCCESS;
	struct port_label_hash *plh = &stackshot_ctx.sc_plh;

#define PLH_STAT(x) do { if (os_atomic_load(&plh->x, relaxed) != 0) { \
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, os_atomic_load(&plh->x, relaxed), "stackshot_" #x)); \
} } while (0)
	PLH_STAT(plh_size);
	PLH_STAT(plh_lookups);
	PLH_STAT(plh_found);
	PLH_STAT(plh_found_depth);
	PLH_STAT(plh_insert);
	PLH_STAT(plh_insert_depth);
	PLH_STAT(plh_bad);
	PLH_STAT(plh_bad_depth);
	PLH_STAT(plh_lookup_send);
	PLH_STAT(plh_lookup_receive);
#undef PLH_STAT

error_exit:
	return error;
}
#endif /* DEVELOPMENT || DEBUG */

static uint64_t
kcdata_get_task_ss_flags(task_t task)
{
	uint64_t ss_flags = 0;
	boolean_t task_64bit_addr = task_has_64Bit_addr(task);
	void *bsd_info = get_bsdtask_info(task);

	if (task_64bit_addr) {
		ss_flags |= kUser64_p;
	}
	if (!task->active || task_is_a_corpse(task) || proc_exiting(bsd_info)) {
		ss_flags |= kTerminatedSnapshot;
	}
	if (task->pidsuspended) {
		ss_flags |= kPidSuspended;
	}
	if (task->frozen) {
		ss_flags |= kFrozen;
	}
	if (task->effective_policy.tep_darwinbg == 1) {
		ss_flags |= kTaskDarwinBG;
	}
	if (task->requested_policy.trp_role == TASK_FOREGROUND_APPLICATION) {
		ss_flags |= kTaskIsForeground;
	}
	if (task->requested_policy.trp_boosted == 1) {
		ss_flags |= kTaskIsBoosted;
	}
	if (task->effective_policy.tep_sup_active == 1) {
		ss_flags |= kTaskIsSuppressed;
	}
#if CONFIG_MEMORYSTATUS

	boolean_t dirty = FALSE, dirty_tracked = FALSE, allow_idle_exit = FALSE;
	memorystatus_proc_flags_unsafe(bsd_info, &dirty, &dirty_tracked, &allow_idle_exit);
	if (dirty) {
		ss_flags |= kTaskIsDirty;
	}
	if (dirty_tracked) {
		ss_flags |= kTaskIsDirtyTracked;
	}
	if (allow_idle_exit) {
		ss_flags |= kTaskAllowIdleExit;
	}

#endif
	if (task->effective_policy.tep_tal_engaged) {
		ss_flags |= kTaskTALEngaged;
	}

	ss_flags |= workqueue_get_task_ss_flags_from_pwq_state_kdp(bsd_info);

#if IMPORTANCE_INHERITANCE
	if (task->task_imp_base) {
		if (task->task_imp_base->iit_donor) {
			ss_flags |= kTaskIsImpDonor;
		}
		if (task->task_imp_base->iit_live_donor) {
			ss_flags |= kTaskIsLiveImpDonor;
		}
	}
#endif
	return ss_flags;
}

static kern_return_t
kcdata_record_shared_cache_info(kcdata_descriptor_t kcd, task_t task, unaligned_u64 *task_snap_ss_flags)
{
	kern_return_t error = KERN_SUCCESS;

	uint64_t shared_cache_slide = 0;
	uint64_t shared_cache_first_mapping = 0;
	uint32_t kdp_fault_results = 0;
	uint32_t shared_cache_id = 0;
	struct dyld_shared_cache_loadinfo shared_cache_data = {0};


	assert(task_snap_ss_flags != NULL);

	/* Get basic info about the shared region pointer, regardless of any failures */
	if (task->shared_region == NULL) {
		*task_snap_ss_flags |= kTaskSharedRegionNone;
	} else if (task->shared_region == primary_system_shared_region) {
		*task_snap_ss_flags |= kTaskSharedRegionSystem;
	} else {
		*task_snap_ss_flags |= kTaskSharedRegionOther;
	}

	if (task->shared_region && _stackshot_validate_kva((vm_offset_t)task->shared_region, sizeof(struct vm_shared_region))) {
		struct vm_shared_region *sr = task->shared_region;
		shared_cache_first_mapping = sr->sr_base_address + sr->sr_first_mapping;

		shared_cache_id = sr->sr_id;
	} else {
		*task_snap_ss_flags |= kTaskSharedRegionInfoUnavailable;
		goto error_exit;
	}

	/* We haven't copied in the shared region UUID yet as part of setup */
	if (!shared_cache_first_mapping || !task->shared_region->sr_uuid_copied) {
		goto error_exit;
	}


	/*
	 * No refcounting here, but we are in debugger context, so that should be safe.
	 */
	shared_cache_slide = task->shared_region->sr_slide;

	if (task->shared_region == primary_system_shared_region) {
		/* skip adding shared cache info -- it's the same as the system level one */
		goto error_exit;
	}
	/*
	 * New-style shared cache reference: for non-primary shared regions,
	 * just include the ID of the shared cache we're attached to.  Consumers
	 * should use the following info from the task's ts_ss_flags as well:
	 *
	 * kTaskSharedRegionNone - task is not attached to a shared region
	 * kTaskSharedRegionSystem - task is attached to the shared region
	 *     with kSharedCacheSystemPrimary set in sharedCacheFlags.
	 * kTaskSharedRegionOther - task is attached to the shared region with
	 *     sharedCacheID matching the STACKSHOT_KCTYPE_SHAREDCACHE_ID entry.
	 */
	kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_SHAREDCACHE_ID, sizeof(shared_cache_id), &shared_cache_id));

	/*
	 * For backwards compatibility; this should eventually be removed.
	 *
	 * Historically, this data was in a dyld_uuid_info_64 structure, but the
	 * naming of both the structure and fields for this use wasn't great.  The
	 * dyld_shared_cache_loadinfo structure has better names, but the same
	 * layout and content as the original.
	 *
	 * The imageSlidBaseAddress/sharedCacheUnreliableSlidBaseAddress field
	 * has been used inconsistently for STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT
	 * entries; here, it's the slid first mapping, and we leave it that way
	 * for backwards compatibility.
	 */
	shared_cache_data.sharedCacheSlide = shared_cache_slide;
	kdp_memcpy(&shared_cache_data.sharedCacheUUID, task->shared_region->sr_uuid, sizeof(task->shared_region->sr_uuid));
	shared_cache_data.sharedCacheUnreliableSlidBaseAddress = shared_cache_first_mapping;
	shared_cache_data.sharedCacheSlidFirstMapping = shared_cache_first_mapping;
	kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO, sizeof(shared_cache_data), &shared_cache_data));

error_exit:
	if (kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
		*task_snap_ss_flags |= kTaskUUIDInfoMissing;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
		*task_snap_ss_flags |= kTaskUUIDInfoTriedFault;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
		*task_snap_ss_flags |= kTaskUUIDInfoFaultedIn;
	}

	return error;
}

static kern_return_t
kcdata_record_uuid_info(kcdata_descriptor_t kcd, task_t task, uint64_t trace_flags, boolean_t have_pmap, unaligned_u64 *task_snap_ss_flags)
{
	bool save_loadinfo_p         = ((trace_flags & STACKSHOT_SAVE_LOADINFO) != 0);
	bool save_kextloadinfo_p     = ((trace_flags & STACKSHOT_SAVE_KEXT_LOADINFO) != 0);
	bool save_compactinfo_p      = ((trace_flags & STACKSHOT_SAVE_DYLD_COMPACTINFO) != 0);
	bool should_fault            = (trace_flags & STACKSHOT_ENABLE_UUID_FAULTING);

	kern_return_t error        = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	mach_vm_address_t dyld_compactinfo_addr = 0;
	uint32_t dyld_compactinfo_size = 0;

	uint32_t uuid_info_count         = 0;
	mach_vm_address_t uuid_info_addr = 0;
	uint64_t uuid_info_timestamp     = 0;
	#pragma unused(uuid_info_timestamp)
	kdp_fault_result_flags_t kdp_fault_results = 0;


	assert(task_snap_ss_flags != NULL);

	int task_pid     = pid_from_task(task);
	boolean_t task_64bit_addr = task_has_64Bit_addr(task);

	if ((save_loadinfo_p || save_compactinfo_p) && have_pmap && task->active && task_pid > 0) {
		/* Read the dyld_all_image_infos struct from the task memory to get UUID array count and location */
		if (task_64bit_addr) {
			struct user64_dyld_all_image_infos task_image_infos;
			if (stackshot_copyin(task->map, task->all_image_info_addr, &task_image_infos,
			    sizeof(struct user64_dyld_all_image_infos), should_fault, &kdp_fault_results)) {
				uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
				uuid_info_addr = task_image_infos.uuidArray;
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_TIMESTAMP_MINIMUM_VERSION) {
					uuid_info_timestamp = task_image_infos.timestamp;
				}
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_COMPACTINFO_MINIMUM_VERSION) {
					dyld_compactinfo_addr = task_image_infos.compact_dyld_image_info_addr;
					dyld_compactinfo_size = task_image_infos.compact_dyld_image_info_size;
				}

			}
		} else {
			struct user32_dyld_all_image_infos task_image_infos;
			if (stackshot_copyin(task->map, task->all_image_info_addr, &task_image_infos,
			    sizeof(struct user32_dyld_all_image_infos), should_fault, &kdp_fault_results)) {
				uuid_info_count = task_image_infos.uuidArrayCount;
				uuid_info_addr = task_image_infos.uuidArray;
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_TIMESTAMP_MINIMUM_VERSION) {
					uuid_info_timestamp = task_image_infos.timestamp;
				}
				if (task_image_infos.version >= DYLD_ALL_IMAGE_INFOS_COMPACTINFO_MINIMUM_VERSION) {
					dyld_compactinfo_addr = task_image_infos.compact_dyld_image_info_addr;
					dyld_compactinfo_size = task_image_infos.compact_dyld_image_info_size;
				}
			}
		}

		/*
		 * If we get a NULL uuid_info_addr (which can happen when we catch dyld in the middle of updating
		 * this data structure), we zero the uuid_info_count so that we won't even try to save load info
		 * for this task.
		 */
		if (!uuid_info_addr) {
			uuid_info_count = 0;
		}

		if (!dyld_compactinfo_addr) {
			dyld_compactinfo_size = 0;
		}

	}

	if (have_pmap && task_pid == 0) {
		if (save_kextloadinfo_p && _stackshot_validate_kva((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader))) {
			uuid_info_count = gLoadedKextSummaries->numSummaries + 1; /* include main kernel UUID */
		} else {
			uuid_info_count = 1; /* include kernelcache UUID (embedded) or kernel UUID (desktop) */
		}
	}

	if (save_compactinfo_p && task_pid > 0) {
		if (dyld_compactinfo_size == 0) {
			*task_snap_ss_flags |= kTaskDyldCompactInfoNone;
		} else if (dyld_compactinfo_size > MAX_DYLD_COMPACTINFO) {
			*task_snap_ss_flags |= kTaskDyldCompactInfoTooBig;
		} else {
			kdp_fault_result_flags_t ci_kdp_fault_results = 0;

			/* Open a compression window to avoid overflowing the stack */
			kcdata_compression_window_open(kcd);
			kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_DYLD_COMPACTINFO,
			    dyld_compactinfo_size, &out_addr));

			if (!stackshot_copyin(task->map, dyld_compactinfo_addr, (void *)out_addr,
			    dyld_compactinfo_size, should_fault, &ci_kdp_fault_results)) {
				bzero((void *)out_addr, dyld_compactinfo_size);
			}
			if (ci_kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
				*task_snap_ss_flags |= kTaskDyldCompactInfoMissing;
			}

			if (ci_kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
				*task_snap_ss_flags |= kTaskDyldCompactInfoTriedFault;
			}

			if (ci_kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
				*task_snap_ss_flags |= kTaskDyldCompactInfoFaultedIn;
			}

			kcd_exit_on_error(kcdata_compression_window_close(kcd));
		}
	}
	if (save_loadinfo_p && task_pid > 0 && (uuid_info_count < MAX_LOADINFOS)) {
		uint32_t copied_uuid_count = 0;
		uint32_t uuid_info_size = (uint32_t)(task_64bit_addr ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
		uint32_t uuid_info_array_size = 0;

		/* Open a compression window to avoid overflowing the stack */
		kcdata_compression_window_open(kcd);

		/* If we found some UUID information, first try to copy it in -- this will only be non-zero if we had a pmap above */
		if (uuid_info_count > 0) {
			uuid_info_array_size = uuid_info_count * uuid_info_size;

			kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, (task_64bit_addr ? KCDATA_TYPE_LIBRARY_LOADINFO64 : KCDATA_TYPE_LIBRARY_LOADINFO),
			    uuid_info_size, uuid_info_count, &out_addr));

			if (!stackshot_copyin(task->map, uuid_info_addr, (void *)out_addr, uuid_info_array_size, should_fault, &kdp_fault_results)) {
				bzero((void *)out_addr, uuid_info_array_size);
			} else {
				copied_uuid_count = uuid_info_count;
			}
		}

		uuid_t binary_uuid;
		if (!copied_uuid_count && proc_binary_uuid_kdp(task, binary_uuid)) {
			/* We failed to copyin the UUID information, try to store the UUID of the main binary we have in the proc */
			if (uuid_info_array_size == 0) {
				/* We just need to store one UUID */
				uuid_info_array_size = uuid_info_size;
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, (task_64bit_addr ? KCDATA_TYPE_LIBRARY_LOADINFO64 : KCDATA_TYPE_LIBRARY_LOADINFO),
				    uuid_info_size, 1, &out_addr));
			}

			if (task_64bit_addr) {
				struct user64_dyld_uuid_info *uuid_info = (struct user64_dyld_uuid_info *)out_addr;
				uint64_t image_load_address = task->mach_header_vm_address;

				kdp_memcpy(&uuid_info->imageUUID, binary_uuid, sizeof(uuid_t));
				kdp_memcpy(&uuid_info->imageLoadAddress, &image_load_address, sizeof(image_load_address));
			} else {
				struct user32_dyld_uuid_info *uuid_info = (struct user32_dyld_uuid_info *)out_addr;
				uint32_t image_load_address = (uint32_t) task->mach_header_vm_address;

				kdp_memcpy(&uuid_info->imageUUID, binary_uuid, sizeof(uuid_t));
				kdp_memcpy(&uuid_info->imageLoadAddress, &image_load_address, sizeof(image_load_address));
			}
		}

		kcd_exit_on_error(kcdata_compression_window_close(kcd));
	} else if (task_pid == 0 && uuid_info_count > 0 && uuid_info_count < MAX_LOADINFOS) {
		uintptr_t image_load_address;

		do {
#if defined(__arm64__)
			if (kernelcache_uuid_valid && !save_kextloadinfo_p) {
				struct dyld_uuid_info_64 kc_uuid = {0};
				kc_uuid.imageLoadAddress = VM_MIN_KERNEL_AND_KEXT_ADDRESS;
				kdp_memcpy(&kc_uuid.imageUUID, &kernelcache_uuid, sizeof(uuid_t));
				kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_KERNELCACHE_LOADINFO, sizeof(struct dyld_uuid_info_64), &kc_uuid));
				break;
			}
#endif /* defined(__arm64__) */

			if (!kernel_uuid || !_stackshot_validate_kva((vm_offset_t)kernel_uuid, sizeof(uuid_t))) {
				/* Kernel UUID not found or inaccessible */
				break;
			}

			uint32_t uuid_type = KCDATA_TYPE_LIBRARY_LOADINFO;
			if ((sizeof(kernel_uuid_info) == sizeof(struct user64_dyld_uuid_info))) {
				uuid_type = KCDATA_TYPE_LIBRARY_LOADINFO64;
#if  defined(__arm64__)
				kc_format_t primary_kc_type = KCFormatUnknown;
				if (PE_get_primary_kc_format(&primary_kc_type) && (primary_kc_type == KCFormatFileset)) {
					/* return TEXT_EXEC based load information on arm devices running with fileset kernelcaches */
					uuid_type = STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC;
				}
#endif
			}

			/*
			 * The element count of the array can vary - avoid overflowing the
			 * stack by opening a window.
			 */
			kcdata_compression_window_open(kcd);
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, uuid_type,
			    sizeof(kernel_uuid_info), uuid_info_count, &out_addr));
			kernel_uuid_info *uuid_info_array = (kernel_uuid_info *)out_addr;

			image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(vm_kernel_stext);
#if defined(__arm64__)
			if (uuid_type == STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC) {
				/* If we're reporting TEXT_EXEC load info, populate the TEXT_EXEC base instead */
				extern vm_offset_t segTEXTEXECB;
				image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(segTEXTEXECB);
			}
#endif
			uuid_info_array[0].imageLoadAddress = image_load_address;
			kdp_memcpy(&uuid_info_array[0].imageUUID, kernel_uuid, sizeof(uuid_t));

			if (save_kextloadinfo_p &&
			    _stackshot_validate_kva((vm_offset_t)(gLoadedKextSummaries), sizeof(OSKextLoadedKextSummaryHeader)) &&
			    _stackshot_validate_kva((vm_offset_t)(&gLoadedKextSummaries->summaries[0]),
			    gLoadedKextSummaries->entry_size * gLoadedKextSummaries->numSummaries)) {
				uint32_t kexti;
				for (kexti = 0; kexti < gLoadedKextSummaries->numSummaries; kexti++) {
					image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].address);
#if defined(__arm64__)
					if (uuid_type == STACKSHOT_KCTYPE_LOADINFO64_TEXT_EXEC) {
						/* If we're reporting TEXT_EXEC load info, populate the TEXT_EXEC base instead */
						image_load_address = (uintptr_t)VM_KERNEL_UNSLIDE(gLoadedKextSummaries->summaries[kexti].text_exec_address);
					}
#endif
					uuid_info_array[kexti + 1].imageLoadAddress = image_load_address;
					kdp_memcpy(&uuid_info_array[kexti + 1].imageUUID, &gLoadedKextSummaries->summaries[kexti].uuid, sizeof(uuid_t));
				}
			}
			kcd_exit_on_error(kcdata_compression_window_close(kcd));
		} while (0);
	}

error_exit:
	if (kdp_fault_results & KDP_FAULT_RESULT_PAGED_OUT) {
		*task_snap_ss_flags |= kTaskUUIDInfoMissing;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_TRIED_FAULT) {
		*task_snap_ss_flags |= kTaskUUIDInfoTriedFault;
	}

	if (kdp_fault_results & KDP_FAULT_RESULT_FAULTED_IN) {
		*task_snap_ss_flags |= kTaskUUIDInfoFaultedIn;
	}

	return error;
}

static kern_return_t
kcdata_record_task_iostats(kcdata_descriptor_t kcd, task_t task)
{
	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	/* I/O Statistics if any counters are non zero */
	assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
	if (task->task_io_stats && !memory_iszero(task->task_io_stats, sizeof(struct io_stat_info))) {
		/* struct io_stats_snapshot is quite large - avoid overflowing the stack. */
		kcdata_compression_window_open(kcd);
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
		struct io_stats_snapshot *_iostat = (struct io_stats_snapshot *)out_addr;
		_iostat->ss_disk_reads_count = task->task_io_stats->disk_reads.count;
		_iostat->ss_disk_reads_size = task->task_io_stats->disk_reads.size;
		_iostat->ss_disk_writes_count = (task->task_io_stats->total_io.count - task->task_io_stats->disk_reads.count);
		_iostat->ss_disk_writes_size = (task->task_io_stats->total_io.size - task->task_io_stats->disk_reads.size);
		_iostat->ss_paging_count = task->task_io_stats->paging.count;
		_iostat->ss_paging_size = task->task_io_stats->paging.size;
		_iostat->ss_non_paging_count = (task->task_io_stats->total_io.count - task->task_io_stats->paging.count);
		_iostat->ss_non_paging_size = (task->task_io_stats->total_io.size - task->task_io_stats->paging.size);
		_iostat->ss_metadata_count = task->task_io_stats->metadata.count;
		_iostat->ss_metadata_size = task->task_io_stats->metadata.size;
		_iostat->ss_data_count = (task->task_io_stats->total_io.count - task->task_io_stats->metadata.count);
		_iostat->ss_data_size = (task->task_io_stats->total_io.size - task->task_io_stats->metadata.size);
		for (int i = 0; i < IO_NUM_PRIORITIES; i++) {
			_iostat->ss_io_priority_count[i] = task->task_io_stats->io_priority[i].count;
			_iostat->ss_io_priority_size[i] = task->task_io_stats->io_priority[i].size;
		}
		kcd_exit_on_error(kcdata_compression_window_close(kcd));
	}


error_exit:
	return error;
}

#if CONFIG_PERVASIVE_CPI
static kern_return_t
kcdata_record_task_instrs_cycles(kcdata_descriptor_t kcd, task_t task)
{
	struct instrs_cycles_snapshot_v2 instrs_cycles = { 0 };
	struct recount_usage usage = { 0 };
	struct recount_usage perf_only = { 0 };
	recount_task_terminated_usage_perf_only(task, &usage, &perf_only);
	instrs_cycles.ics_instructions = recount_usage_instructions(&usage);
	instrs_cycles.ics_cycles = recount_usage_cycles(&usage);
	instrs_cycles.ics_p_instructions = recount_usage_instructions(&perf_only);
	instrs_cycles.ics_p_cycles = recount_usage_cycles(&perf_only);

	return kcdata_push_data(kcd, STACKSHOT_KCTYPE_INSTRS_CYCLES, sizeof(instrs_cycles), &instrs_cycles);
}
#endif /* CONFIG_PERVASIVE_CPI */

static kern_return_t
kcdata_record_task_cpu_architecture(kcdata_descriptor_t kcd, task_t task)
{
	struct stackshot_cpu_architecture cpu_architecture = {0};
	int32_t cputype;
	int32_t cpusubtype;

	proc_archinfo_kdp(get_bsdtask_info(task), &cputype, &cpusubtype);
	cpu_architecture.cputype = cputype;
	cpu_architecture.cpusubtype = cpusubtype;

	return kcdata_push_data(kcd, STACKSHOT_KCTYPE_TASK_CPU_ARCHITECTURE, sizeof(struct stackshot_cpu_architecture), &cpu_architecture);
}

static kern_return_t
kcdata_record_task_codesigning_info(kcdata_descriptor_t kcd, task_t task)
{
	struct stackshot_task_codesigning_info codesigning_info = {};
	void * bsdtask_info = NULL;
	uint32_t trust = 0;
	kern_return_t ret = 0;
	pmap_t pmap = get_task_pmap(task);
	uint64_t cs_auxiliary_info = 0;
	if (task != kernel_task) {
		bsdtask_info = get_bsdtask_info(task);
		codesigning_info.csflags = proc_getcsflags_kdp(bsdtask_info);
		ret = get_trust_level_kdp(pmap, &trust);
		if (ret != KERN_SUCCESS) {
			trust = KCDATA_INVALID_CS_TRUST_LEVEL;
		}
		codesigning_info.cs_trust_level = trust;
		cs_auxiliary_info = task_get_cs_auxiliary_info_kdp(task);
	} else {
		return KERN_SUCCESS;
	}
	ret = kcdata_push_data(kcd, STACKSHOT_KCTYPE_CODESIGNING_INFO, sizeof(struct stackshot_task_codesigning_info), &codesigning_info);
	if (ret != KERN_SUCCESS) {
		return ret;
	}
	return kcdata_push_data(kcd, TASK_CRASHINFO_CS_AUXILIARY_INFO, sizeof(cs_auxiliary_info), &cs_auxiliary_info);
}

static kern_return_t
kcdata_record_task_jit_address_range(kcdata_descriptor_t kcd, task_t task)
{
	uint64_t jit_start_addr = 0;
	uint64_t jit_end_addr = 0;
	struct crashinfo_jit_address_range range = {};
	kern_return_t ret = 0;
	pmap_t pmap = get_task_pmap(task);
	if (task == kernel_task || NULL == pmap) {
		return KERN_SUCCESS;
	}
	ret = get_jit_address_range_kdp(pmap, (uintptr_t*)&jit_start_addr, (uintptr_t*)&jit_end_addr);
	if (KERN_SUCCESS == ret) {
		range.start_address = jit_start_addr;
		range.end_address = jit_end_addr;
		return kcdata_push_data(kcd, TASK_CRASHINFO_JIT_ADDRESS_RANGE, sizeof(struct crashinfo_jit_address_range), &range);
	} else {
		return KERN_SUCCESS;
	}
}

#if CONFIG_TASK_SUSPEND_STATS
static kern_return_t
kcdata_record_task_suspension_info(kcdata_descriptor_t kcd, task_t task)
{
	kern_return_t ret = KERN_SUCCESS;
	struct stackshot_suspension_info suspension_info = {};
	task_suspend_stats_data_t suspend_stats;
	task_suspend_source_array_t suspend_sources;
	struct stackshot_suspension_source suspension_sources[TASK_SUSPEND_SOURCES_MAX];
	int i;

	if (task == kernel_task) {
		return KERN_SUCCESS;
	}

	ret = task_get_suspend_stats_kdp(task, &suspend_stats);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	suspension_info.tss_count = suspend_stats.tss_count;
	suspension_info.tss_duration = suspend_stats.tss_duration;
	suspension_info.tss_last_end = suspend_stats.tss_last_end;
	suspension_info.tss_last_start = suspend_stats.tss_last_start;
	ret = kcdata_push_data(kcd, STACKSHOT_KCTYPE_SUSPENSION_INFO, sizeof(suspension_info), &suspension_info);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	ret = task_get_suspend_sources_kdp(task, suspend_sources);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	for (i = 0; i < TASK_SUSPEND_SOURCES_MAX; ++i) {
		suspension_sources[i].tss_pid = suspend_sources[i].tss_pid;
		strlcpy(suspension_sources[i].tss_procname, suspend_sources[i].tss_procname, sizeof(suspend_sources[i].tss_procname));
		suspension_sources[i].tss_tid = suspend_sources[i].tss_tid;
		suspension_sources[i].tss_time = suspend_sources[i].tss_time;
	}
	return kcdata_push_array(kcd, STACKSHOT_KCTYPE_SUSPENSION_SOURCE, sizeof(suspension_sources[0]), TASK_SUSPEND_SOURCES_MAX, &suspension_sources);
}
#endif /* CONFIG_TASK_SUSPEND_STATS */

static kern_return_t
kcdata_record_transitioning_task_snapshot(kcdata_descriptor_t kcd, task_t task, unaligned_u64 task_snap_ss_flags, uint64_t transition_type)
{
	kern_return_t error                 = KERN_SUCCESS;
	mach_vm_address_t out_addr          = 0;
	struct transitioning_task_snapshot * cur_tsnap = NULL;

	int task_pid           = pid_from_task(task);
	/* Is returning -1 ok for terminating task ok ??? */
	uint64_t task_uniqueid = get_task_uniqueid(task);

	if (task_pid && (task_did_exec_internal(task) || task_is_exec_copy_internal(task))) {
		/*
		 * if this task is a transit task from another one, show the pid as
		 * negative
		 */
		task_pid = 0 - task_pid;
	}

	/* the task_snapshot_v2 struct is large - avoid overflowing the stack */
	kcdata_compression_window_open(kcd);
	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_TRANSITIONING_TASK_SNAPSHOT, sizeof(struct transitioning_task_snapshot), &out_addr));
	cur_tsnap = (struct transitioning_task_snapshot *)out_addr;
	bzero(cur_tsnap, sizeof(*cur_tsnap));

	cur_tsnap->tts_unique_pid = task_uniqueid;
	cur_tsnap->tts_ss_flags = kcdata_get_task_ss_flags(task);
	cur_tsnap->tts_ss_flags |= task_snap_ss_flags;
	cur_tsnap->tts_transition_type = transition_type;
	cur_tsnap->tts_pid = task_pid;

	/* Add the BSD process identifiers */
	if (task_pid != -1 && get_bsdtask_info(task) != NULL) {
		proc_name_kdp(get_bsdtask_info(task), cur_tsnap->tts_p_comm, sizeof(cur_tsnap->tts_p_comm));
	} else {
		cur_tsnap->tts_p_comm[0] = '\0';
	}

	kcd_exit_on_error(kcdata_compression_window_close(kcd));

error_exit:
	return error;
}

static kern_return_t
#if STACKSHOT_COLLECTS_LATENCY_INFO
kcdata_record_task_snapshot(kcdata_descriptor_t kcd, task_t task, uint64_t trace_flags, boolean_t have_pmap, unaligned_u64 task_snap_ss_flags, struct stackshot_latency_task *latency_info)
#else
kcdata_record_task_snapshot(kcdata_descriptor_t kcd, task_t task, uint64_t trace_flags, boolean_t have_pmap, unaligned_u64 task_snap_ss_flags)
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */
{
	bool collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	bool collect_iostats         = !collect_delta_stackshot && !(trace_flags & STACKSHOT_NO_IO_STATS);
#if CONFIG_PERVASIVE_CPI
	bool collect_instrs_cycles   = ((trace_flags & STACKSHOT_INSTRS_CYCLES) != 0);
#endif /* CONFIG_PERVASIVE_CPI */
#if __arm64__
	bool collect_asid            = ((trace_flags & STACKSHOT_ASID) != 0);
#endif
	bool collect_pagetables      = ((trace_flags & STACKSHOT_PAGE_TABLES) != 0);


	kern_return_t error                 = KERN_SUCCESS;
	mach_vm_address_t out_addr          = 0;
	struct task_snapshot_v2 * cur_tsnap = NULL;
#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info->cur_tsnap_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	int task_pid           = pid_from_task(task);
	uint64_t task_uniqueid = get_task_uniqueid(task);
	void *bsd_info = get_bsdtask_info(task);
	uint64_t proc_starttime_secs = 0;

	if (task_pid && (task_did_exec_internal(task) || task_is_exec_copy_internal(task))) {
		/*
		 * if this task is a transit task from another one, show the pid as
		 * negative
		 */
		task_pid = 0 - task_pid;
	}

	/* the task_snapshot_v2 struct is large - avoid overflowing the stack */
	kcdata_compression_window_open(kcd);
	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_TASK_SNAPSHOT, sizeof(struct task_snapshot_v2), &out_addr));
	cur_tsnap = (struct task_snapshot_v2 *)out_addr;
	bzero(cur_tsnap, sizeof(*cur_tsnap));

	cur_tsnap->ts_unique_pid = task_uniqueid;
	cur_tsnap->ts_ss_flags = kcdata_get_task_ss_flags(task);
	cur_tsnap->ts_ss_flags |= task_snap_ss_flags;

	struct recount_usage term_usage = { 0 };
	recount_task_terminated_usage(task, &term_usage);
	struct recount_times_mach term_times = recount_usage_times_mach(&term_usage);
	cur_tsnap->ts_user_time_in_terminated_threads = term_times.rtm_user;
	cur_tsnap->ts_system_time_in_terminated_threads = term_times.rtm_system;

	proc_starttime_kdp(bsd_info, &proc_starttime_secs, NULL, NULL);
	cur_tsnap->ts_p_start_sec = proc_starttime_secs;
	cur_tsnap->ts_task_size = have_pmap ? get_task_phys_footprint(task) : 0;
	cur_tsnap->ts_max_resident_size = get_task_resident_max(task);
	cur_tsnap->ts_was_throttled = (uint32_t) proc_was_throttled_from_task(task);
	cur_tsnap->ts_did_throttle = (uint32_t) proc_did_throttle_from_task(task);

	cur_tsnap->ts_suspend_count = task->suspend_count;
	cur_tsnap->ts_faults = counter_load(&task->faults);
	cur_tsnap->ts_pageins = counter_load(&task->pageins);
	cur_tsnap->ts_cow_faults = counter_load(&task->cow_faults);
	cur_tsnap->ts_latency_qos = (task->effective_policy.tep_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED) ?
	    LATENCY_QOS_TIER_UNSPECIFIED : ((0xFF << 16) | task->effective_policy.tep_latency_qos);
	cur_tsnap->ts_pid = task_pid;

	/* Add the BSD process identifiers */
	if (task_pid != -1 && bsd_info != NULL) {
		proc_name_kdp(bsd_info, cur_tsnap->ts_p_comm, sizeof(cur_tsnap->ts_p_comm));
	} else {
		cur_tsnap->ts_p_comm[0] = '\0';
#if IMPORTANCE_INHERITANCE && (DEVELOPMENT || DEBUG)
		if (task->task_imp_base != NULL) {
			kdp_strlcpy(cur_tsnap->ts_p_comm, &task->task_imp_base->iit_procname[0],
			    MIN((int)sizeof(task->task_imp_base->iit_procname), (int)sizeof(cur_tsnap->ts_p_comm)));
		}
#endif /* IMPORTANCE_INHERITANCE && (DEVELOPMENT || DEBUG) */
	}

	kcd_exit_on_error(kcdata_compression_window_close(kcd));

#if CONFIG_COALITIONS
	if (task_pid != -1 && bsd_info != NULL &&
	    (task->coalition[COALITION_TYPE_JETSAM] != NULL)) {
		/*
		 * The jetsam coalition ID is always saved, even if
		 * STACKSHOT_SAVE_JETSAM_COALITIONS is not set.
		 */
		uint64_t jetsam_coal_id = coalition_id(task->coalition[COALITION_TYPE_JETSAM]);
		kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_JETSAM_COALITION, sizeof(jetsam_coal_id), &jetsam_coal_id));
	}
#endif /* CONFIG_COALITIONS */

#if __arm64__
	if (collect_asid && have_pmap) {
		uint32_t asid = PMAP_VASID(task->map->pmap);
		kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_ASID, sizeof(asid), &asid));
	}
#endif

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info->cur_tsnap_latency = mach_absolute_time() - latency_info->cur_tsnap_latency;
	latency_info->pmap_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	if (collect_pagetables && have_pmap) {
#if SCHED_HYGIENE_DEBUG
		// pagetable dumps can be large; reset the interrupt timeout to avoid a panic
		ml_spin_debug_clear_self();
#endif
		assert(stackshot_ctx.sc_is_singlethreaded);
		size_t bytes_dumped = 0;
		error = pmap_dump_page_tables(task->map->pmap, kcd_end_address(kcd), kcd_max_address(kcd), stackshot_args.pagetable_mask, &bytes_dumped);
		if (error != KERN_SUCCESS) {
			goto error_exit;
		} else {
			/* Variable size array - better not have it on the stack. */
			kcdata_compression_window_open(kcd);
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(kcd, STACKSHOT_KCTYPE_PAGE_TABLES,
			    sizeof(uint64_t), (uint32_t)(bytes_dumped / sizeof(uint64_t)), &out_addr));
			kcd_exit_on_error(kcdata_compression_window_close(kcd));
		}
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info->pmap_latency = mach_absolute_time() - latency_info->pmap_latency;
	latency_info->bsd_proc_ids_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info->bsd_proc_ids_latency = mach_absolute_time() - latency_info->bsd_proc_ids_latency;
	latency_info->end_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	if (collect_iostats) {
		kcd_exit_on_error(kcdata_record_task_iostats(kcd, task));
	}

#if CONFIG_PERVASIVE_CPI
	if (collect_instrs_cycles) {
		kcd_exit_on_error(kcdata_record_task_instrs_cycles(kcd, task));
	}
#endif /* CONFIG_PERVASIVE_CPI */

	kcd_exit_on_error(kcdata_record_task_cpu_architecture(kcd, task));
	kcd_exit_on_error(kcdata_record_task_codesigning_info(kcd, task));
	kcd_exit_on_error(kcdata_record_task_jit_address_range(kcd, task));

#if CONFIG_TASK_SUSPEND_STATS
	kcd_exit_on_error(kcdata_record_task_suspension_info(kcd, task));
#endif /* CONFIG_TASK_SUSPEND_STATS */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info->end_latency = mach_absolute_time() - latency_info->end_latency;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

error_exit:
	return error;
}

static kern_return_t
kcdata_record_task_delta_snapshot(kcdata_descriptor_t kcd, task_t task, uint64_t trace_flags, boolean_t have_pmap, unaligned_u64 task_snap_ss_flags)
{
#if !CONFIG_PERVASIVE_CPI
#pragma unused(trace_flags)
#endif /* !CONFIG_PERVASIVE_CPI */
	kern_return_t error                       = KERN_SUCCESS;
	struct task_delta_snapshot_v2 * cur_tsnap = NULL;
	mach_vm_address_t out_addr                = 0;
	(void) trace_flags;
#if __arm64__
	boolean_t collect_asid                    = ((trace_flags & STACKSHOT_ASID) != 0);
#endif
#if CONFIG_PERVASIVE_CPI
	boolean_t collect_instrs_cycles           = ((trace_flags & STACKSHOT_INSTRS_CYCLES) != 0);
#endif /* CONFIG_PERVASIVE_CPI */

	uint64_t task_uniqueid = get_task_uniqueid(task);

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_TASK_DELTA_SNAPSHOT, sizeof(struct task_delta_snapshot_v2), &out_addr));

	cur_tsnap = (struct task_delta_snapshot_v2 *)out_addr;

	cur_tsnap->tds_unique_pid = task_uniqueid;
	cur_tsnap->tds_ss_flags = kcdata_get_task_ss_flags(task);
	cur_tsnap->tds_ss_flags |= task_snap_ss_flags;

	struct recount_usage usage = { 0 };
	recount_task_terminated_usage(task, &usage);
	struct recount_times_mach term_times = recount_usage_times_mach(&usage);

	cur_tsnap->tds_user_time_in_terminated_threads = term_times.rtm_user;
	cur_tsnap->tds_system_time_in_terminated_threads = term_times.rtm_system;

	cur_tsnap->tds_task_size = have_pmap ? get_task_phys_footprint(task) : 0;

	cur_tsnap->tds_max_resident_size = get_task_resident_max(task);
	cur_tsnap->tds_suspend_count = task->suspend_count;
	cur_tsnap->tds_faults            = counter_load(&task->faults);
	cur_tsnap->tds_pageins           = counter_load(&task->pageins);
	cur_tsnap->tds_cow_faults        = counter_load(&task->cow_faults);
	cur_tsnap->tds_was_throttled     = (uint32_t)proc_was_throttled_from_task(task);
	cur_tsnap->tds_did_throttle      = (uint32_t)proc_did_throttle_from_task(task);
	cur_tsnap->tds_latency_qos       = (task->effective_policy.tep_latency_qos == LATENCY_QOS_TIER_UNSPECIFIED)
	    ? LATENCY_QOS_TIER_UNSPECIFIED
	    : ((0xFF << 16) | task->effective_policy.tep_latency_qos);

#if __arm64__
	if (collect_asid && have_pmap) {
		uint32_t asid = PMAP_VASID(task->map->pmap);
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_ASID, sizeof(uint32_t), &out_addr));
		kdp_memcpy((void*)out_addr, &asid, sizeof(asid));
	}
#endif

#if CONFIG_PERVASIVE_CPI
	if (collect_instrs_cycles) {
		kcd_exit_on_error(kcdata_record_task_instrs_cycles(kcd, task));
	}
#endif /* CONFIG_PERVASIVE_CPI */

error_exit:
	return error;
}

static kern_return_t
kcdata_record_thread_iostats(kcdata_descriptor_t kcd, thread_t thread)
{
	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;

	/* I/O Statistics */
	assert(IO_NUM_PRIORITIES == STACKSHOT_IO_NUM_PRIORITIES);
	if (thread->thread_io_stats && !memory_iszero(thread->thread_io_stats, sizeof(struct io_stat_info))) {
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_IOSTATS, sizeof(struct io_stats_snapshot), &out_addr));
		struct io_stats_snapshot *_iostat = (struct io_stats_snapshot *)out_addr;
		_iostat->ss_disk_reads_count = thread->thread_io_stats->disk_reads.count;
		_iostat->ss_disk_reads_size = thread->thread_io_stats->disk_reads.size;
		_iostat->ss_disk_writes_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->disk_reads.count);
		_iostat->ss_disk_writes_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->disk_reads.size);
		_iostat->ss_paging_count = thread->thread_io_stats->paging.count;
		_iostat->ss_paging_size = thread->thread_io_stats->paging.size;
		_iostat->ss_non_paging_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->paging.count);
		_iostat->ss_non_paging_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->paging.size);
		_iostat->ss_metadata_count = thread->thread_io_stats->metadata.count;
		_iostat->ss_metadata_size = thread->thread_io_stats->metadata.size;
		_iostat->ss_data_count = (thread->thread_io_stats->total_io.count - thread->thread_io_stats->metadata.count);
		_iostat->ss_data_size = (thread->thread_io_stats->total_io.size - thread->thread_io_stats->metadata.size);
		for (int i = 0; i < IO_NUM_PRIORITIES; i++) {
			_iostat->ss_io_priority_count[i] = thread->thread_io_stats->io_priority[i].count;
			_iostat->ss_io_priority_size[i] = thread->thread_io_stats->io_priority[i].size;
		}
	}

error_exit:
	return error;
}

bool
machine_trace_thread_validate_kva(vm_offset_t addr)
{
	return _stackshot_validate_kva(addr, sizeof(uintptr_t));
}

struct _stackshot_backtrace_context {
	vm_map_t sbc_map;
	vm_offset_t sbc_prev_page;
	vm_offset_t sbc_prev_kva;
	uint32_t sbc_flags;
	bool sbc_allow_faulting;
};

static errno_t
_stackshot_backtrace_copy(void *vctx, void *dst, user_addr_t src, size_t size)
{
	struct _stackshot_backtrace_context *ctx = vctx;
	size_t map_page_mask = 0;
	size_t __assert_only map_page_size = kdp_vm_map_get_page_size(ctx->sbc_map,
	    &map_page_mask);
	assert(size < map_page_size);
	if (src & (size - 1)) {
		// The source should be aligned to the size passed in, like a stack
		// frame or word.
		return EINVAL;
	}

	vm_offset_t src_page = src & ~map_page_mask;
	vm_offset_t src_kva = 0;

	if (src_page != ctx->sbc_prev_page) {
		uint32_t res = 0;
		uint32_t flags = 0;
		vm_offset_t src_pa = stackshot_find_phys(ctx->sbc_map, src,
		    ctx->sbc_allow_faulting, &res);

		flags |= (res & KDP_FAULT_RESULT_PAGED_OUT) ? kThreadTruncatedBT : 0;
		flags |= (res & KDP_FAULT_RESULT_TRIED_FAULT) ? kThreadTriedFaultBT : 0;
		flags |= (res & KDP_FAULT_RESULT_FAULTED_IN) ? kThreadFaultedBT : 0;
		ctx->sbc_flags |= flags;
		if (src_pa == 0) {
			return EFAULT;
		}

		src_kva = phystokv(src_pa);
		ctx->sbc_prev_page = src_page;
		ctx->sbc_prev_kva = (src_kva & ~map_page_mask);
	} else {
		src_kva = ctx->sbc_prev_kva + (src & map_page_mask);
	}

#if KASAN
	/*
	 * KASan does not monitor accesses to userspace pages. Therefore, it is
	 * pointless to maintain a shadow map for them. Instead, they are all
	 * mapped to a single, always valid shadow map page. This approach saves
	 * a considerable amount of shadow map pages which are limited and
	 * precious.
	 */
	kasan_notify_address_nopoison(src_kva, size);
#endif
	memcpy(dst, (const void *)src_kva, size);

	return 0;
}

static kern_return_t
kcdata_record_thread_snapshot(kcdata_descriptor_t kcd, thread_t thread, task_t task, uint64_t trace_flags, boolean_t have_pmap, boolean_t thread_on_core)
{
	boolean_t dispatch_p              = ((trace_flags & STACKSHOT_GET_DQ) != 0);
	boolean_t active_kthreads_only_p  = ((trace_flags & STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY) != 0);
	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t collect_iostats         = !collect_delta_stackshot && !(trace_flags & STACKSHOT_NO_IO_STATS);
#if CONFIG_PERVASIVE_CPI
	boolean_t collect_instrs_cycles   = ((trace_flags & STACKSHOT_INSTRS_CYCLES) != 0);
#endif /* CONFIG_PERVASIVE_CPI */
	kern_return_t error        = KERN_SUCCESS;

#if STACKSHOT_COLLECTS_LATENCY_INFO
	struct stackshot_latency_thread latency_info;
	latency_info.cur_thsnap1_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	mach_vm_address_t out_addr = 0;
	int saved_count            = 0;

	struct thread_snapshot_v4 * cur_thread_snap = NULL;
	char cur_thread_name[STACKSHOT_MAX_THREAD_NAME_SIZE];

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_SNAPSHOT, sizeof(struct thread_snapshot_v4), &out_addr));
	cur_thread_snap = (struct thread_snapshot_v4 *)out_addr;

	/* Populate the thread snapshot header */
	cur_thread_snap->ths_ss_flags = 0;
	cur_thread_snap->ths_thread_id = thread_tid(thread);
	cur_thread_snap->ths_wait_event = VM_KERNEL_UNSLIDE_OR_PERM(thread->wait_event);
	cur_thread_snap->ths_continuation = VM_KERNEL_UNSLIDE(thread->continuation);
	cur_thread_snap->ths_total_syscalls = thread->syscalls_mach + thread->syscalls_unix;

	if (IPC_VOUCHER_NULL != thread->ith_voucher) {
		cur_thread_snap->ths_voucher_identifier = VM_KERNEL_ADDRPERM(thread->ith_voucher);
	} else {
		cur_thread_snap->ths_voucher_identifier = 0;
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.cur_thsnap1_latency = mach_absolute_time() - latency_info.cur_thsnap1_latency;
	latency_info.dispatch_serial_latency = mach_absolute_time();
	latency_info.dispatch_label_latency = 0;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	cur_thread_snap->ths_dqserialnum = 0;
	if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
		uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
		if (dqkeyaddr != 0) {
			uint64_t dqaddr = 0;
			boolean_t copyin_ok = stackshot_copyin_word(task, dqkeyaddr, &dqaddr, FALSE, NULL);
			if (copyin_ok && dqaddr != 0) {
				uint64_t dqserialnumaddr = dqaddr + get_task_dispatchqueue_serialno_offset(task);
				uint64_t dqserialnum = 0;
				copyin_ok = stackshot_copyin_word(task, dqserialnumaddr, &dqserialnum, FALSE, NULL);
				if (copyin_ok) {
					cur_thread_snap->ths_ss_flags |= kHasDispatchSerial;
					cur_thread_snap->ths_dqserialnum = dqserialnum;
				}

#if STACKSHOT_COLLECTS_LATENCY_INFO
				latency_info.dispatch_serial_latency = mach_absolute_time() - latency_info.dispatch_serial_latency;
				latency_info.dispatch_label_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

				/* try copying in the queue label */
				uint64_t label_offs = get_task_dispatchqueue_label_offset(task);
				if (label_offs) {
					uint64_t dqlabeladdr = dqaddr + label_offs;
					uint64_t actual_dqlabeladdr = 0;

					copyin_ok = stackshot_copyin_word(task, dqlabeladdr, &actual_dqlabeladdr, FALSE, NULL);
					if (copyin_ok && actual_dqlabeladdr != 0) {
						char label_buf[STACKSHOT_QUEUE_LABEL_MAXSIZE];
						int len;

						bzero(label_buf, STACKSHOT_QUEUE_LABEL_MAXSIZE * sizeof(char));
						len = stackshot_copyin_string(task, actual_dqlabeladdr, label_buf, STACKSHOT_QUEUE_LABEL_MAXSIZE, FALSE, NULL);
						if (len > 0) {
							mach_vm_address_t label_addr = 0;
							kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_DISPATCH_QUEUE_LABEL, len, &label_addr));
							kdp_strlcpy((char*)label_addr, &label_buf[0], len);
						}
					}
				}
#if STACKSHOT_COLLECTS_LATENCY_INFO
				latency_info.dispatch_label_latency = mach_absolute_time() - latency_info.dispatch_label_latency;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */
			}
		}
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if ((cur_thread_snap->ths_ss_flags & kHasDispatchSerial) == 0) {
		latency_info.dispatch_serial_latency = 0;
	}
	latency_info.cur_thsnap2_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	struct recount_times_mach times = recount_thread_times(thread);
	cur_thread_snap->ths_user_time = times.rtm_user;
	cur_thread_snap->ths_sys_time = times.rtm_system;

	if (thread->thread_tag & THREAD_TAG_MAINTHREAD) {
		cur_thread_snap->ths_ss_flags |= kThreadMain;
	}
	if (thread->effective_policy.thep_darwinbg) {
		cur_thread_snap->ths_ss_flags |= kThreadDarwinBG;
	}
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO)) {
		cur_thread_snap->ths_ss_flags |= kThreadIOPassive;
	}
	if (thread->suspend_count > 0) {
		cur_thread_snap->ths_ss_flags |= kThreadSuspended;
	}
	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
		cur_thread_snap->ths_ss_flags |= kGlobalForcedIdle;
	}
#if CONFIG_EXCLAVES
	/* save exclave thread for later collection */
	if ((thread->th_exclaves_state & TH_EXCLAVES_RPC) && stackshot_exclave_inspect_ctids && !stackshot_ctx.sc_panic_stackshot) {
		/* certain threads, like the collector, must never be inspected */
		if ((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & TH_EXCLAVES_INSPECTION_NOINSPECT) == 0) {
			uint32_t ctid_index = os_atomic_inc_orig(&stackshot_exclave_inspect_ctid_count, acq_rel);
			if (ctid_index < stackshot_exclave_inspect_ctid_capacity) {
				stackshot_exclave_inspect_ctids[ctid_index] = thread_get_ctid(thread);
			} else {
				os_atomic_store(&stackshot_exclave_inspect_ctid_count, stackshot_exclave_inspect_ctid_capacity, release);
			}
			if ((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & TH_EXCLAVES_INSPECTION_STACKSHOT) != 0) {
				panic("stackshot: trying to inspect already-queued thread");
			}
		}
	}
#endif /* CONFIG_EXCLAVES */
	if (thread_on_core) {
		cur_thread_snap->ths_ss_flags |= kThreadOnCore;
	}
	if (stackshot_thread_is_idle_worker_unsafe(thread)) {
		cur_thread_snap->ths_ss_flags |= kThreadIdleWorker;
	}

	/* make sure state flags defined in kcdata.h still match internal flags */
	static_assert(SS_TH_WAIT == TH_WAIT);
	static_assert(SS_TH_SUSP == TH_SUSP);
	static_assert(SS_TH_RUN == TH_RUN);
	static_assert(SS_TH_UNINT == TH_UNINT);
	static_assert(SS_TH_TERMINATE == TH_TERMINATE);
	static_assert(SS_TH_TERMINATE2 == TH_TERMINATE2);
	static_assert(SS_TH_IDLE == TH_IDLE);

	cur_thread_snap->ths_last_run_time           = thread->last_run_time;
	cur_thread_snap->ths_last_made_runnable_time = thread->last_made_runnable_time;
	cur_thread_snap->ths_state                   = thread->state;
	cur_thread_snap->ths_sched_flags             = thread->sched_flags;
	cur_thread_snap->ths_base_priority = thread->base_pri;
	cur_thread_snap->ths_sched_priority = thread->sched_pri;
	cur_thread_snap->ths_eqos = thread->effective_policy.thep_qos;
	cur_thread_snap->ths_rqos = thread->requested_policy.thrp_qos;
	cur_thread_snap->ths_rqos_override = MAX(thread->requested_policy.thrp_qos_override,
	    thread->requested_policy.thrp_qos_workq_override);
	cur_thread_snap->ths_io_tier = (uint8_t) proc_get_effective_thread_policy(thread, TASK_POLICY_IO);
	cur_thread_snap->ths_thread_t = VM_KERNEL_UNSLIDE_OR_PERM(thread);

	static_assert(sizeof(thread->effective_policy) == sizeof(uint64_t));
	static_assert(sizeof(thread->requested_policy) == sizeof(uint64_t));
	cur_thread_snap->ths_requested_policy = *(unaligned_u64 *) &thread->requested_policy;
	cur_thread_snap->ths_effective_policy = *(unaligned_u64 *) &thread->effective_policy;

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.cur_thsnap2_latency = mach_absolute_time()  - latency_info.cur_thsnap2_latency;
	latency_info.thread_name_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* if there is thread name then add to buffer */
	cur_thread_name[0] = '\0';
	proc_threadname_kdp(get_bsdthread_info(thread), cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE);
	if (strnlen(cur_thread_name, STACKSHOT_MAX_THREAD_NAME_SIZE) > 0) {
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_NAME, sizeof(cur_thread_name), &out_addr));
		kdp_memcpy((void *)out_addr, (void *)cur_thread_name, sizeof(cur_thread_name));
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.thread_name_latency = mach_absolute_time()  - latency_info.thread_name_latency;
	latency_info.sur_times_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* record system, user, and runnable times */
	time_value_t runnable_time;
	thread_read_times(thread, NULL, NULL, &runnable_time);
	clock_sec_t user_sec = 0, system_sec = 0;
	clock_usec_t user_usec = 0, system_usec = 0;
	absolutetime_to_microtime(times.rtm_user, &user_sec, &user_usec);
	absolutetime_to_microtime(times.rtm_system, &system_sec, &system_usec);

	kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_CPU_TIMES, sizeof(struct stackshot_cpu_times_v2), &out_addr));
	struct stackshot_cpu_times_v2 *stackshot_cpu_times = (struct stackshot_cpu_times_v2 *)out_addr;
	*stackshot_cpu_times = (struct stackshot_cpu_times_v2){
		.user_usec = user_sec * USEC_PER_SEC + user_usec,
		.system_usec = system_sec * USEC_PER_SEC + system_usec,
		.runnable_usec = (uint64_t)runnable_time.seconds * USEC_PER_SEC + runnable_time.microseconds,
	};

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.sur_times_latency = mach_absolute_time()  - latency_info.sur_times_latency;
	latency_info.user_stack_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* Trace user stack, if any */
	if (!active_kthreads_only_p && task->active && task->map != kernel_map) {
		uint32_t user_ths_ss_flags = 0;

		/*
		 * We don't know how big the stacktrace will be, so read it into our
		 * per-cpu buffer, then copy it to the kcdata.
		 */
		struct _stackshot_backtrace_context ctx = {
			.sbc_map = task->map,
			.sbc_allow_faulting = stackshot_ctx.sc_enable_faulting,
			.sbc_prev_page = -1,
			.sbc_prev_kva = -1,
		};
		struct backtrace_control ctl = {
			.btc_user_thread = thread,
			.btc_user_copy = _stackshot_backtrace_copy,
			.btc_user_copy_context = &ctx,
		};
		struct backtrace_user_info info = BTUINFO_INIT;

		saved_count = backtrace_user(stackshot_cpu_ctx.scc_stack_buffer, MAX_FRAMES, &ctl,
		    &info);
		if (saved_count > 0) {
#if __LP64__
#define STACKLR_WORDS STACKSHOT_KCTYPE_USER_STACKLR64
#else // __LP64__
#define STACKLR_WORDS STACKSHOT_KCTYPE_USER_STACKLR
#endif // !__LP64__
			/* Now, copy the stacktrace into kcdata. */
			kcd_exit_on_error(kcdata_push_array(kcd, STACKLR_WORDS, sizeof(uintptr_t),
			    saved_count, stackshot_cpu_ctx.scc_stack_buffer));
			if (info.btui_info & BTI_64_BIT) {
				user_ths_ss_flags |= kUser64_p;
			}
			if ((info.btui_info & BTI_TRUNCATED) ||
			    (ctx.sbc_flags & kThreadTruncatedBT)) {
				user_ths_ss_flags |= kThreadTruncatedBT;
				user_ths_ss_flags |= kThreadTruncUserBT;
			}
			user_ths_ss_flags |= ctx.sbc_flags;
			ctx.sbc_flags = 0;
#if __LP64__
			/* We only support async stacks on 64-bit kernels */
			if (info.btui_async_frame_addr != 0) {
				uint32_t async_start_offset = info.btui_async_start_index;
				kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_USER_ASYNC_START_INDEX,
				    sizeof(async_start_offset), &async_start_offset));
				ctl.btc_frame_addr = info.btui_async_frame_addr;
				ctl.btc_addr_offset = BTCTL_ASYNC_ADDR_OFFSET;
				info = BTUINFO_INIT;
				unsigned int async_count = backtrace_user(stackshot_cpu_ctx.scc_stack_buffer, MAX_FRAMES, &ctl,
				    &info);
				if (async_count > 0) {
					kcd_exit_on_error(kcdata_push_array(kcd, STACKSHOT_KCTYPE_USER_ASYNC_STACKLR64,
					    sizeof(uintptr_t), async_count, stackshot_cpu_ctx.scc_stack_buffer));
					if ((info.btui_info & BTI_TRUNCATED) ||
					    (ctx.sbc_flags & kThreadTruncatedBT)) {
						user_ths_ss_flags |= kThreadTruncatedBT;
						user_ths_ss_flags |= kThreadTruncUserAsyncBT;
					}
					user_ths_ss_flags |= ctx.sbc_flags;
				}
			}
#endif /* _LP64 */
		}
		if (user_ths_ss_flags != 0) {
			cur_thread_snap->ths_ss_flags |= user_ths_ss_flags;
		}
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.user_stack_latency = mach_absolute_time()  - latency_info.user_stack_latency;
	latency_info.kernel_stack_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* Call through to the machine specific trace routines
	 * Frames are added past the snapshot header.
	 */
	if (thread->kernel_stack != 0) {
		uint32_t kern_ths_ss_flags = 0;
#if defined(__LP64__)
		uint32_t stack_kcdata_type = STACKSHOT_KCTYPE_KERN_STACKLR64;
		extern int machine_trace_thread64(thread_t thread, char *tracepos,
		    char *tracebound, int nframes, uint32_t *thread_trace_flags);
		saved_count = machine_trace_thread64(
#else
		uint32_t stack_kcdata_type = STACKSHOT_KCTYPE_KERN_STACKLR;
		extern int machine_trace_thread(thread_t thread, char *tracepos,
		    char *tracebound, int nframes, uint32_t *thread_trace_flags);
		saved_count = machine_trace_thread(
#endif
			thread, (char*) stackshot_cpu_ctx.scc_stack_buffer,
			(char *) (stackshot_cpu_ctx.scc_stack_buffer + MAX_FRAMES), MAX_FRAMES,
			&kern_ths_ss_flags);
		if (saved_count > 0) {
			int frame_size = sizeof(uintptr_t);
#if defined(__LP64__)
			cur_thread_snap->ths_ss_flags |= kKernel64_p;
#endif
#if CONFIG_EXCLAVES
			if (thread->th_exclaves_state & TH_EXCLAVES_RPC) {
				struct thread_exclaves_info info = { 0 };

				info.tei_flags = kExclaveRPCActive;
				if (thread->th_exclaves_state & TH_EXCLAVES_SCHEDULER_REQUEST) {
					info.tei_flags |= kExclaveSchedulerRequest;
				}
				if (thread->th_exclaves_state & TH_EXCLAVES_UPCALL) {
					info.tei_flags |= kExclaveUpcallActive;
				}
				info.tei_scid = thread->th_exclaves_ipc_ctx.scid;
				info.tei_thread_offset = exclaves_stack_offset(stackshot_cpu_ctx.scc_stack_buffer, saved_count / frame_size, false);

				kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_KERN_EXCLAVES_THREADINFO, sizeof(struct thread_exclaves_info), &info));
			}
#endif /* CONFIG_EXCLAVES */
			kcd_exit_on_error(kcdata_push_array(kcd, stack_kcdata_type,
			    frame_size, saved_count / frame_size, stackshot_cpu_ctx.scc_stack_buffer));
		}
		if (kern_ths_ss_flags & kThreadTruncatedBT) {
			kern_ths_ss_flags |= kThreadTruncKernBT;
		}
		if (kern_ths_ss_flags != 0) {
			cur_thread_snap->ths_ss_flags |= kern_ths_ss_flags;
		}
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.kernel_stack_latency = mach_absolute_time()  - latency_info.kernel_stack_latency;
	latency_info.misc_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if CONFIG_THREAD_GROUPS
	if (trace_flags & STACKSHOT_THREAD_GROUP) {
		uint64_t thread_group_id = thread->thread_group ? thread_group_get_id(thread->thread_group) : 0;
		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_THREAD_GROUP, sizeof(thread_group_id), &out_addr));
		kdp_memcpy((void*)out_addr, &thread_group_id, sizeof(uint64_t));
	}
#endif /* CONFIG_THREAD_GROUPS */

	if (collect_iostats) {
		kcd_exit_on_error(kcdata_record_thread_iostats(kcd, thread));
	}

#if CONFIG_PERVASIVE_CPI
	if (collect_instrs_cycles) {
		struct recount_usage usage = { 0 };
		recount_sum_unsafe(&recount_thread_plan, thread->th_recount.rth_lifetime,
		    &usage);

		kcd_exit_on_error(kcdata_get_memory_addr(kcd, STACKSHOT_KCTYPE_INSTRS_CYCLES, sizeof(struct instrs_cycles_snapshot), &out_addr));
		struct instrs_cycles_snapshot *instrs_cycles = (struct instrs_cycles_snapshot *)out_addr;
		    instrs_cycles->ics_instructions = recount_usage_instructions(&usage);
		    instrs_cycles->ics_cycles = recount_usage_cycles(&usage);
	}
#endif /* CONFIG_PERVASIVE_CPI */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.misc_latency = mach_absolute_time() - latency_info.misc_latency;
	if (collect_latency_info) {
		kcd_exit_on_error(kcdata_push_data(kcd, STACKSHOT_KCTYPE_LATENCY_INFO_THREAD, sizeof(latency_info), &latency_info));
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

error_exit:
	return error;
}

static int
kcdata_record_thread_delta_snapshot(struct thread_delta_snapshot_v3 * cur_thread_snap, thread_t thread, boolean_t thread_on_core)
{
	cur_thread_snap->tds_thread_id = thread_tid(thread);
	if (IPC_VOUCHER_NULL != thread->ith_voucher) {
		cur_thread_snap->tds_voucher_identifier  = VM_KERNEL_ADDRPERM(thread->ith_voucher);
	} else {
		cur_thread_snap->tds_voucher_identifier = 0;
	}

	cur_thread_snap->tds_ss_flags = 0;
	if (thread->effective_policy.thep_darwinbg) {
		cur_thread_snap->tds_ss_flags |= kThreadDarwinBG;
	}
	if (proc_get_effective_thread_policy(thread, TASK_POLICY_PASSIVE_IO)) {
		cur_thread_snap->tds_ss_flags |= kThreadIOPassive;
	}
	if (thread->suspend_count > 0) {
		cur_thread_snap->tds_ss_flags |= kThreadSuspended;
	}
	if (thread->options & TH_OPT_GLOBAL_FORCED_IDLE) {
		cur_thread_snap->tds_ss_flags |= kGlobalForcedIdle;
	}
	if (thread_on_core) {
		cur_thread_snap->tds_ss_flags |= kThreadOnCore;
	}
	if (stackshot_thread_is_idle_worker_unsafe(thread)) {
		cur_thread_snap->tds_ss_flags |= kThreadIdleWorker;
	}

	cur_thread_snap->tds_last_made_runnable_time = thread->last_made_runnable_time;
	cur_thread_snap->tds_state                   = thread->state;
	cur_thread_snap->tds_sched_flags             = thread->sched_flags;
	cur_thread_snap->tds_base_priority           = thread->base_pri;
	cur_thread_snap->tds_sched_priority          = thread->sched_pri;
	cur_thread_snap->tds_eqos                    = thread->effective_policy.thep_qos;
	cur_thread_snap->tds_rqos                    = thread->requested_policy.thrp_qos;
	cur_thread_snap->tds_rqos_override           = MAX(thread->requested_policy.thrp_qos_override,
	    thread->requested_policy.thrp_qos_workq_override);
	cur_thread_snap->tds_io_tier                 = (uint8_t) proc_get_effective_thread_policy(thread, TASK_POLICY_IO);

	static_assert(sizeof(thread->effective_policy) == sizeof(uint64_t));
	static_assert(sizeof(thread->requested_policy) == sizeof(uint64_t));
	cur_thread_snap->tds_requested_policy = *(unaligned_u64 *) &thread->requested_policy;
	cur_thread_snap->tds_effective_policy = *(unaligned_u64 *) &thread->effective_policy;

	return 0;
}

/*
 * Why 12?  12 strikes a decent balance between allocating a large array on
 * the stack and having large kcdata item overheads for recording nonrunable
 * tasks.
 */
#define UNIQUEIDSPERFLUSH 12

struct saved_uniqueids {
	uint64_t ids[UNIQUEIDSPERFLUSH];
	unsigned count;
};

enum thread_classification {
	tc_full_snapshot,  /* take a full snapshot */
	tc_delta_snapshot, /* take a delta snapshot */
};

static enum thread_classification
classify_thread(thread_t thread, boolean_t * thread_on_core_p, boolean_t collect_delta_stackshot)
{
	processor_t last_processor = thread->last_processor;

	boolean_t thread_on_core = FALSE;
	if (last_processor != PROCESSOR_NULL) {
		/* Idle threads are always treated as on-core, since the processor state can change while they are running. */
		thread_on_core = (thread == last_processor->idle_thread) ||
		    (last_processor->state == PROCESSOR_RUNNING &&
		    last_processor->active_thread == thread);
	}

	*thread_on_core_p = thread_on_core;

	/* Capture the full thread snapshot if this is not a delta stackshot or if the thread has run subsequent to the
	 * previous full stackshot */
	if (!collect_delta_stackshot || thread_on_core || (thread->last_run_time > stackshot_args.since_timestamp)) {
		return tc_full_snapshot;
	} else {
		return tc_delta_snapshot;
	}
}


static kern_return_t
kdp_stackshot_record_task(task_t task)
{
	boolean_t active_kthreads_only_p  = ((stackshot_flags & STACKSHOT_ACTIVE_KERNEL_THREADS_ONLY) != 0);
	boolean_t save_donating_pids_p    = ((stackshot_flags & STACKSHOT_SAVE_IMP_DONATION_PIDS) != 0);
	boolean_t collect_delta_stackshot = ((stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	boolean_t save_owner_info         = ((stackshot_flags & STACKSHOT_THREAD_WAITINFO) != 0);
	boolean_t include_drivers         = ((stackshot_flags & STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL) != 0);

	kern_return_t error = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;
	int saved_count = 0;

	int task_pid                   = 0;
	uint64_t task_uniqueid         = 0;
	int num_delta_thread_snapshots = 0;
	int num_waitinfo_threads       = 0;
	int num_turnstileinfo_threads  = 0;

	uint64_t task_start_abstime    = 0;
	boolean_t have_map = FALSE, have_pmap = FALSE;
	boolean_t some_thread_ran = FALSE;
	unaligned_u64 task_snap_ss_flags = 0;
#if STACKSHOT_COLLECTS_LATENCY_INFO
	struct stackshot_latency_task latency_info;
	latency_info.setup_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
	uint64_t task_begin_cpu_cycle_count = 0;
	if (!stackshot_ctx.sc_panic_stackshot) {
		task_begin_cpu_cycle_count = mt_cur_cpu_cycles();
	}
#endif

	if ((task == NULL) || !_stackshot_validate_kva((vm_offset_t)task, sizeof(struct task))) {
		error = KERN_FAILURE;
		goto error_exit;
	}

	void *bsd_info = get_bsdtask_info(task);
	boolean_t task_in_teardown        = (bsd_info == NULL) || proc_in_teardown(bsd_info);// has P_LPEXIT set during proc_exit()
	boolean_t task_in_transition      = task_in_teardown;         // here we can add other types of transition.
	uint32_t  container_type          = (task_in_transition) ? STACKSHOT_KCCONTAINER_TRANSITIONING_TASK : STACKSHOT_KCCONTAINER_TASK;
	uint32_t  transition_type         = (task_in_teardown) ? kTaskIsTerminated : 0;

	if (task_in_transition) {
		collect_delta_stackshot = FALSE;
	}

	have_map = (task->map != NULL) && (_stackshot_validate_kva((vm_offset_t)(task->map), sizeof(struct _vm_map)));
	have_pmap = have_map && (task->map->pmap != NULL) && (_stackshot_validate_kva((vm_offset_t)(task->map->pmap), sizeof(struct pmap)));

	task_pid = pid_from_task(task);
	/* Is returning -1 ok for terminating task ok ??? */
	task_uniqueid = get_task_uniqueid(task);

	if (!task->active || task_is_a_corpse(task) || task_is_a_corpse_fork(task)) {
		/*
		 * Not interested in terminated tasks without threads.
		 */
		if (queue_empty(&task->threads) || task_pid == -1) {
			return KERN_SUCCESS;
		}
	}

	/* All PIDs should have the MSB unset */
	assert((task_pid & (1ULL << 31)) == 0);

#if STACKSHOT_COLLECTS_LATENCY_INFO
	latency_info.setup_latency = mach_absolute_time() - latency_info.setup_latency;
	latency_info.task_uniqueid = task_uniqueid;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* Trace everything, unless a process was specified. Add in driver tasks if requested. */
	if ((stackshot_args.pid == -1) || (stackshot_args.pid == task_pid) || (include_drivers && task_is_driver(task))) {
#if STACKSHOT_COLLECTS_LATENCY_INFO
		stackshot_cpu_latency.tasks_processed++;
#endif

		/* add task snapshot marker */
		kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
		    container_type, task_uniqueid));

		if (collect_delta_stackshot) {
			/*
			 * For delta stackshots we need to know if a thread from this task has run since the
			 * previous timestamp to decide whether we're going to record a full snapshot and UUID info.
			 */
			thread_t thread = THREAD_NULL;
			queue_iterate(&task->threads, thread, thread_t, task_threads)
			{
				if ((thread == NULL) || !_stackshot_validate_kva((vm_offset_t)thread, sizeof(struct thread))) {
					error = KERN_FAILURE;
					goto error_exit;
				}

				if (active_kthreads_only_p && thread->kernel_stack == 0) {
					continue;
				}

				boolean_t thread_on_core;
				enum thread_classification thread_classification = classify_thread(thread, &thread_on_core, collect_delta_stackshot);

				switch (thread_classification) {
				case tc_full_snapshot:
					some_thread_ran = TRUE;
					break;
				case tc_delta_snapshot:
					num_delta_thread_snapshots++;
					break;
				}
			}
		}

		if (collect_delta_stackshot) {
			proc_starttime_kdp(get_bsdtask_info(task), NULL, NULL, &task_start_abstime);
		}

		/* Next record any relevant UUID info and store the task snapshot */
		if (task_in_transition ||
		    !collect_delta_stackshot ||
		    (task_start_abstime == 0) ||
		    (task_start_abstime > stackshot_args.since_timestamp) ||
		    some_thread_ran) {
			/*
			 * Collect full task information in these scenarios:
			 *
			 * 1) a full stackshot or the task is in transition
			 * 2) a delta stackshot where the task started after the previous full stackshot
			 * 3) a delta stackshot where any thread from the task has run since the previous full stackshot
			 *
			 * because the task may have exec'ed, changing its name, architecture, load info, etc
			 */

			kcd_exit_on_error(kcdata_record_shared_cache_info(stackshot_kcdata_p, task, &task_snap_ss_flags));
			kcd_exit_on_error(kcdata_record_uuid_info(stackshot_kcdata_p, task, stackshot_flags, have_pmap, &task_snap_ss_flags));
#if STACKSHOT_COLLECTS_LATENCY_INFO
			if (!task_in_transition) {
				kcd_exit_on_error(kcdata_record_task_snapshot(stackshot_kcdata_p, task, stackshot_flags, have_pmap, task_snap_ss_flags, &latency_info));
			} else {
				kcd_exit_on_error(kcdata_record_transitioning_task_snapshot(stackshot_kcdata_p, task, task_snap_ss_flags, transition_type));
			}
#else
			if (!task_in_transition) {
				kcd_exit_on_error(kcdata_record_task_snapshot(stackshot_kcdata_p, task, stackshot_flags, have_pmap, task_snap_ss_flags));
			} else {
				kcd_exit_on_error(kcdata_record_transitioning_task_snapshot(stackshot_kcdata_p, task, task_snap_ss_flags, transition_type));
			}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */
		} else {
			kcd_exit_on_error(kcdata_record_task_delta_snapshot(stackshot_kcdata_p, task, stackshot_flags, have_pmap, task_snap_ss_flags));
		}

#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.misc_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

		struct thread_delta_snapshot_v3 * delta_snapshots = NULL;
		int current_delta_snapshot_index                  = 0;
		if (num_delta_thread_snapshots > 0) {
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_DELTA_SNAPSHOT,
			    sizeof(struct thread_delta_snapshot_v3),
			    num_delta_thread_snapshots, &out_addr));
			delta_snapshots = (struct thread_delta_snapshot_v3 *)out_addr;
		}


#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.task_thread_count_loop_latency = mach_absolute_time();
#endif
		/*
		 * Iterate over the task threads to save thread snapshots and determine
		 * how much space we need for waitinfo and turnstile info
		 */
		thread_t thread = THREAD_NULL;
		queue_iterate(&task->threads, thread, thread_t, task_threads)
		{
			if ((thread == NULL) || !_stackshot_validate_kva((vm_offset_t)thread, sizeof(struct thread))) {
				error = KERN_FAILURE;
				goto error_exit;
			}

			uint64_t thread_uniqueid;
			if (active_kthreads_only_p && thread->kernel_stack == 0) {
				continue;
			}
			thread_uniqueid = thread_tid(thread);

			boolean_t thread_on_core;
			enum thread_classification thread_classification = classify_thread(thread, &thread_on_core, collect_delta_stackshot);

#if STACKSHOT_COLLECTS_LATENCY_INFO
			stackshot_cpu_latency.threads_processed++;
#endif

			switch (thread_classification) {
			case tc_full_snapshot:
				/* add thread marker */
				kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
				    STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));

				/* thread snapshot can be large, including strings, avoid overflowing the stack. */
				kcdata_compression_window_open(stackshot_kcdata_p);

				kcd_exit_on_error(kcdata_record_thread_snapshot(stackshot_kcdata_p, thread, task, stackshot_flags, have_pmap, thread_on_core));

				kcd_exit_on_error(kcdata_compression_window_close(stackshot_kcdata_p));

				/* mark end of thread snapshot data */
				kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END,
				    STACKSHOT_KCCONTAINER_THREAD, thread_uniqueid));
				break;
			case tc_delta_snapshot:
				kcd_exit_on_error(kcdata_record_thread_delta_snapshot(&delta_snapshots[current_delta_snapshot_index++], thread, thread_on_core));
				break;
			}

			/*
			 * We want to report owner information regardless of whether a thread
			 * has changed since the last delta, whether it's a normal stackshot,
			 * or whether it's nonrunnable
			 */
			if (save_owner_info) {
				if (stackshot_thread_has_valid_waitinfo(thread)) {
					num_waitinfo_threads++;
				}

				if (stackshot_thread_has_valid_turnstileinfo(thread)) {
					num_turnstileinfo_threads++;
				}
			}
		}
#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.task_thread_count_loop_latency = mach_absolute_time() - latency_info.task_thread_count_loop_latency;
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

		thread_waitinfo_v2_t *thread_waitinfo           = NULL;
		thread_turnstileinfo_v2_t *thread_turnstileinfo = NULL;
		int current_waitinfo_index              = 0;
		int current_turnstileinfo_index         = 0;
		/* allocate space for the wait and turnstil info */
		if (num_waitinfo_threads > 0 || num_turnstileinfo_threads > 0) {
			/* thread waitinfo and turnstileinfo can be quite large, avoid overflowing the stack */
			kcdata_compression_window_open(stackshot_kcdata_p);

			if (num_waitinfo_threads > 0) {
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_WAITINFO,
				    sizeof(thread_waitinfo_v2_t), num_waitinfo_threads, &out_addr));
				thread_waitinfo = (thread_waitinfo_v2_t *)out_addr;
			}

			if (num_turnstileinfo_threads > 0) {
				/* get space for the turnstile info */
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_TURNSTILEINFO,
				    sizeof(thread_turnstileinfo_v2_t), num_turnstileinfo_threads, &out_addr));
				thread_turnstileinfo = (thread_turnstileinfo_v2_t *)out_addr;
			}

			stackshot_plh_resetgen();  // so we know which portlabel_ids are referenced
		}

#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.misc_latency = mach_absolute_time() - latency_info.misc_latency;
		latency_info.task_thread_data_loop_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

		/* Iterate over the task's threads to save the wait and turnstile info */
		queue_iterate(&task->threads, thread, thread_t, task_threads)
		{
			uint64_t thread_uniqueid;
			#pragma unused(thread_uniqueid)

			if (active_kthreads_only_p && thread->kernel_stack == 0) {
				continue;
			}

			thread_uniqueid = thread_tid(thread);

			/* If we want owner info, we should capture it regardless of its classification */
			if (save_owner_info) {
				if (stackshot_thread_has_valid_waitinfo(thread)) {
					stackshot_thread_wait_owner_info(
						thread,
						&thread_waitinfo[current_waitinfo_index++]);
				}

				if (stackshot_thread_has_valid_turnstileinfo(thread)) {
					stackshot_thread_turnstileinfo(
						thread,
						&thread_turnstileinfo[current_turnstileinfo_index++]);
				}
			}
		}

#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.task_thread_data_loop_latency = mach_absolute_time() - latency_info.task_thread_data_loop_latency;
		latency_info.misc2_latency = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if DEBUG || DEVELOPMENT
		if (current_delta_snapshot_index != num_delta_thread_snapshots) {
			panic("delta thread snapshot count mismatch while capturing snapshots for task %p. expected %d, found %d", task,
			    num_delta_thread_snapshots, current_delta_snapshot_index);
		}
		if (current_waitinfo_index != num_waitinfo_threads) {
			panic("thread wait info count mismatch while capturing snapshots for task %p. expected %d, found %d", task,
			    num_waitinfo_threads, current_waitinfo_index);
		}
#endif

		if (num_waitinfo_threads > 0 || num_turnstileinfo_threads > 0) {
			kcd_exit_on_error(kcdata_compression_window_close(stackshot_kcdata_p));
			// now, record the portlabel hashes.
			kcd_exit_on_error(kdp_stackshot_plh_record());
		}

#if IMPORTANCE_INHERITANCE
		if (save_donating_pids_p) {
			/* Ensure the buffer is big enough, since we're using the stack buffer for this. */
			static_assert(TASK_IMP_WALK_LIMIT * sizeof(int32_t) <= MAX_FRAMES * sizeof(uintptr_t));
			saved_count = task_importance_list_pids(task, TASK_IMP_LIST_DONATING_PIDS,
			    (char*) stackshot_cpu_ctx.scc_stack_buffer, TASK_IMP_WALK_LIMIT);
			if (saved_count > 0) {
				/* Variable size array - better not have it on the stack. */
				kcdata_compression_window_open(stackshot_kcdata_p);
				kcd_exit_on_error(kcdata_push_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_DONATING_PIDS,
				    sizeof(int32_t), saved_count, stackshot_cpu_ctx.scc_stack_buffer));
				kcd_exit_on_error(kcdata_compression_window_close(stackshot_kcdata_p));
			}
		}
#endif

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
		if (!stackshot_ctx.sc_panic_stackshot) {
			kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, (mt_cur_cpu_cycles() - task_begin_cpu_cycle_count),
			    "task_cpu_cycle_count"));
		}
#endif

#if STACKSHOT_COLLECTS_LATENCY_INFO
		latency_info.misc2_latency = mach_absolute_time() - latency_info.misc2_latency;
		if (collect_latency_info) {
			kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_LATENCY_INFO_TASK, sizeof(latency_info), &latency_info));
		}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

		/* mark end of task snapshot data */
		kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END, container_type,
		    task_uniqueid));
	}


error_exit:
	return error;
}

/* Record global shared regions */
static kern_return_t
kdp_stackshot_shared_regions(uint64_t trace_flags)
{
	kern_return_t error        = KERN_SUCCESS;

	boolean_t collect_delta_stackshot = ((trace_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	extern queue_head_t vm_shared_region_queue;
	vm_shared_region_t sr;

	extern queue_head_t vm_shared_region_queue;
	queue_iterate(&vm_shared_region_queue,
	    sr,
	    vm_shared_region_t,
	    sr_q) {
		struct dyld_shared_cache_loadinfo_v2 scinfo = {0};
		if (!_stackshot_validate_kva((vm_offset_t)sr, sizeof(*sr))) {
			break;
		}
		if (collect_delta_stackshot && sr->sr_install_time < stackshot_args.since_timestamp) {
			continue; // only include new shared caches in delta stackshots
		}
		uint32_t sharedCacheFlags = ((sr == primary_system_shared_region) ? kSharedCacheSystemPrimary : 0) |
		    (sr->sr_driverkit ? kSharedCacheDriverkit : 0);
		kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
		    STACKSHOT_KCCONTAINER_SHAREDCACHE, sr->sr_id));
		kdp_memcpy(scinfo.sharedCacheUUID, sr->sr_uuid, sizeof(sr->sr_uuid));
		scinfo.sharedCacheSlide = sr->sr_slide;
		scinfo.sharedCacheUnreliableSlidBaseAddress = sr->sr_base_address + sr->sr_first_mapping;
		scinfo.sharedCacheSlidFirstMapping = sr->sr_base_address + sr->sr_first_mapping;
		scinfo.sharedCacheID = sr->sr_id;
		scinfo.sharedCacheFlags = sharedCacheFlags;

		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_SHAREDCACHE_INFO,
		    sizeof(scinfo), &scinfo));

		if ((trace_flags & STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT) && sr->sr_images != NULL &&
		    _stackshot_validate_kva((vm_offset_t)sr->sr_images, sr->sr_images_count * sizeof(struct dyld_uuid_info_64))) {
			assert(sr->sr_images_count != 0);
			kcd_exit_on_error(kcdata_push_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT, sizeof(struct dyld_uuid_info_64), sr->sr_images_count, sr->sr_images));
		}
		kcd_exit_on_error(kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END,
		    STACKSHOT_KCCONTAINER_SHAREDCACHE, sr->sr_id));
	}

	/*
	 * For backwards compatibility; this will eventually be removed.
	 * Another copy of the Primary System Shared Region, for older readers.
	 */
	sr = primary_system_shared_region;
	/* record system level shared cache load info (if available) */
	if (!collect_delta_stackshot && sr &&
	    _stackshot_validate_kva((vm_offset_t)sr, sizeof(struct vm_shared_region))) {
		struct dyld_shared_cache_loadinfo scinfo = {0};

		/*
		 * Historically, this data was in a dyld_uuid_info_64 structure, but the
		 * naming of both the structure and fields for this use isn't great.  The
		 * dyld_shared_cache_loadinfo structure has better names, but the same
		 * layout and content as the original.
		 *
		 * The imageSlidBaseAddress/sharedCacheUnreliableSlidBaseAddress field
		 * has been used inconsistently for STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT
		 * entries; here, it's the slid base address, and we leave it that way
		 * for backwards compatibility.
		 */
		kdp_memcpy(scinfo.sharedCacheUUID, &sr->sr_uuid, sizeof(sr->sr_uuid));
		scinfo.sharedCacheSlide = sr->sr_slide;
		scinfo.sharedCacheUnreliableSlidBaseAddress = sr->sr_slide + sr->sr_base_address;
		scinfo.sharedCacheSlidFirstMapping = sr->sr_base_address + sr->sr_first_mapping;

		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_SHAREDCACHE_LOADINFO,
		    sizeof(scinfo), &scinfo));

		if (trace_flags & STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT) {
			/*
			 * Include a map of the system shared cache layout if it has been populated
			 * (which is only when the system is using a custom shared cache).
			 */
			if (sr->sr_images && _stackshot_validate_kva((vm_offset_t)sr->sr_images,
			    (sr->sr_images_count * sizeof(struct dyld_uuid_info_64)))) {
				assert(sr->sr_images_count != 0);
				kcd_exit_on_error(kcdata_push_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_SYS_SHAREDCACHE_LAYOUT, sizeof(struct dyld_uuid_info_64), sr->sr_images_count, sr->sr_images));
			}
		}
	}

error_exit:
	return error;
}

static kern_return_t
kdp_stackshot_kcdata_format(void)
{
	kern_return_t error        = KERN_SUCCESS;
	mach_vm_address_t out_addr = 0;
	uint64_t abs_time = 0;
	uint64_t system_state_flags = 0;
	task_t task = TASK_NULL;
	mach_timebase_info_data_t timebase = {0, 0};
	uint32_t length_to_copy = 0, tmp32 = 0;
	abs_time = mach_absolute_time();
	uint64_t last_task_start_time = 0;
	int cur_workitem_index = 0;
	uint64_t tasks_in_stackshot = 0;
	uint64_t threads_in_stackshot = 0;

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
	uint64_t stackshot_begin_cpu_cycle_count = 0;

	if (!stackshot_ctx.sc_panic_stackshot) {
		stackshot_begin_cpu_cycle_count = mt_cur_cpu_cycles();
	}
#endif

	/* the CPU entering here is participating in the stackshot */
	stackshot_cpu_ctx.scc_did_work = true;

#if STACKSHOT_COLLECTS_LATENCY_INFO
	collect_latency_info = stackshot_flags & STACKSHOT_DISABLE_LATENCY_INFO ? false : true;
#endif
	/* process the flags */
	bool collect_delta_stackshot = ((stackshot_flags & STACKSHOT_COLLECT_DELTA_SNAPSHOT) != 0);
	bool collect_exclaves        = !disable_exclave_stackshot && ((stackshot_flags & STACKSHOT_SKIP_EXCLAVES) == 0);
	stackshot_ctx.sc_enable_faulting = (stackshot_flags & (STACKSHOT_ENABLE_BT_FAULTING));

	/* Currently we only support returning explicit KEXT load info on fileset kernels */
	kc_format_t primary_kc_type = KCFormatUnknown;
	if (PE_get_primary_kc_format(&primary_kc_type) && (primary_kc_type != KCFormatFileset)) {
		stackshot_flags &= ~(STACKSHOT_SAVE_KEXT_LOADINFO);
	}

	if (sizeof(void *) == 8) {
		system_state_flags |= kKernel64_p;
	}

#if CONFIG_EXCLAVES
	if (!stackshot_ctx.sc_panic_stackshot && collect_exclaves) {
		kcd_exit_on_error(stackshot_setup_exclave_waitlist()); /* Allocate list of exclave threads */
	}
#else
#pragma unused(collect_exclaves)
#endif /* CONFIG_EXCLAVES */

	/* setup mach_absolute_time and timebase info -- copy out in some cases and needed to convert since_timestamp to seconds for proc start time */
	clock_timebase_info(&timebase);

	/* begin saving data into the buffer */
	if (stackshot_ctx.sc_bytes_uncompressed) {
		stackshot_ctx.sc_bytes_uncompressed = 0;
	}

	/*
	 * Setup pre-task linked kcdata buffer.
	 * The idea here is that we want the kcdata to be in (roughly) the same order as it was
	 * before we made this multithreaded, so we have separate buffers for pre and post task-iteration,
	 * since that's the parallelized part.
	 */
	if (!stackshot_ctx.sc_is_singlethreaded) {
		kcd_exit_on_error(stackshot_new_linked_kcdata());
		stackshot_ctx.sc_pretask_kcdata = stackshot_cpu_ctx.scc_kcdata_head;
	}

	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, stackshot_flags, "stackshot_in_flags"));
	kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, (uint32_t)stackshot_flags, "stackshot_in_pid"));
	kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, system_state_flags, "system_state_flags"));
	if (stackshot_flags & STACKSHOT_PAGE_TABLES) {
		kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, stackshot_args.pagetable_mask, "stackshot_pagetable_mask"));
	}
	if (stackshot_initial_estimate != 0) {
		kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, stackshot_initial_estimate, "stackshot_size_estimate"));
		kcd_exit_on_error(kcdata_add_uint32_with_description(stackshot_kcdata_p, stackshot_initial_estimate_adj, "stackshot_size_estimate_adj"));
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_ctx.sc_latency.setup_latency_mt = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if CONFIG_JETSAM
	tmp32 = memorystatus_get_pressure_status_kdp();
	kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_JETSAM_LEVEL, sizeof(uint32_t), &tmp32));
#endif

	if (!collect_delta_stackshot) {
		tmp32 = THREAD_POLICY_INTERNAL_STRUCT_VERSION;
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_POLICY_VERSION, sizeof(uint32_t), &tmp32));

		tmp32 = PAGE_SIZE;
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_KERN_PAGE_SIZE, sizeof(uint32_t), &tmp32));

		/* save boot-args and osversion string */
		length_to_copy =  MIN((uint32_t)(strlen(version) + 1), OSVERSIZE);
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_OSVERSION, length_to_copy, (const void *)version));
		length_to_copy = MIN((uint32_t)(strlen(osversion) + 1), OSVERSIZE);
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_OS_BUILD_VERSION, length_to_copy, (void *)osversion));


		length_to_copy =  MIN((uint32_t)(strlen(PE_boot_args()) + 1), BOOT_LINE_LENGTH);
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_BOOTARGS, length_to_copy, PE_boot_args()));

		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, KCDATA_TYPE_TIMEBASE, sizeof(timebase), &timebase));
	} else {
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_DELTA_SINCE_TIMESTAMP, sizeof(uint64_t), &stackshot_args.since_timestamp));
	}

	kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, KCDATA_TYPE_MACH_ABSOLUTE_TIME, sizeof(uint64_t), &abs_time));

	kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, KCDATA_TYPE_USECS_SINCE_EPOCH, sizeof(uint64_t), &stackshot_ctx.sc_microsecs));

	kcd_exit_on_error(kdp_stackshot_shared_regions(stackshot_flags));

	/* Add requested information first */
	if (stackshot_flags & STACKSHOT_GET_GLOBAL_MEM_STATS) {
		struct mem_and_io_snapshot mais = {0};
		kdp_mem_and_io_snapshot(&mais);
		kcd_exit_on_error(kcdata_push_data(stackshot_kcdata_p, STACKSHOT_KCTYPE_GLOBAL_MEM_STATS, sizeof(mais), &mais));
	}

#if CONFIG_THREAD_GROUPS
	struct thread_group_snapshot_v3 *thread_groups = NULL;
	int num_thread_groups = 0;

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
	uint64_t thread_group_begin_cpu_cycle_count = 0;

	if (!stackshot_ctx.sc_is_singlethreaded && (stackshot_flags & STACKSHOT_THREAD_GROUP)) {
		thread_group_begin_cpu_cycle_count = mt_cur_cpu_cycles();
	}
#endif

	/* Iterate over thread group names */
	if (stackshot_flags & STACKSHOT_THREAD_GROUP) {
		/* Variable size array - better not have it on the stack. */
		kcdata_compression_window_open(stackshot_kcdata_p);

		if (thread_group_iterate_stackshot(stackshot_thread_group_count, &num_thread_groups) != KERN_SUCCESS) {
			stackshot_flags &= ~(STACKSHOT_THREAD_GROUP);
		}

		if (num_thread_groups > 0) {
			kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT, sizeof(struct thread_group_snapshot_v3), num_thread_groups, &out_addr));
			thread_groups = (struct thread_group_snapshot_v3 *)out_addr;
		}

		if (thread_group_iterate_stackshot(stackshot_thread_group_snapshot, thread_groups) != KERN_SUCCESS) {
			error = KERN_FAILURE;
			goto error_exit;
		}

		kcd_exit_on_error(kcdata_compression_window_close(stackshot_kcdata_p));
	}

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
	if (!stackshot_ctx.sc_panic_stackshot && (thread_group_begin_cpu_cycle_count != 0)) {
		kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, (mt_cur_cpu_cycles() - thread_group_begin_cpu_cycle_count),
		    "thread_groups_cpu_cycle_count"));
	}
#endif
#else
	stackshot_flags &= ~(STACKSHOT_THREAD_GROUP);
#endif /* CONFIG_THREAD_GROUPS */


#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_ctx.sc_latency.setup_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.setup_latency_mt;
	if (stackshot_ctx.sc_is_singlethreaded) {
		stackshot_ctx.sc_latency.total_task_iteration_latency_mt = mach_absolute_time();
	} else {
		stackshot_ctx.sc_latency.task_queue_building_latency_mt = mach_absolute_time();
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	bool const process_scoped = (stackshot_args.pid != -1) &&
	    ((stackshot_flags & STACKSHOT_INCLUDE_DRIVER_THREADS_IN_KERNEL) == 0);

	/* Iterate over tasks */
	queue_iterate(&tasks, task, task_t, tasks)
	{
		stackshot_panic_guard();

		if (collect_delta_stackshot) {
			uint64_t abstime;
			proc_starttime_kdp(get_bsdtask_info(task), NULL, NULL, &abstime);

			if (abstime > last_task_start_time) {
				last_task_start_time = abstime;
			}
		}

		pid_t task_pid = pid_from_task(task);

		if (process_scoped && (task_pid != stackshot_args.pid)) {
			continue;
		}

		if ((task->active && !task_is_a_corpse(task) && !task_is_a_corpse_fork(task)) ||
		    (!queue_empty(&task->threads) && task_pid != -1)) {
			tasks_in_stackshot++;
			threads_in_stackshot += task->thread_count;
		}

		/* If this is a singlethreaded stackshot, don't use the work queues. */
		if (stackshot_ctx.sc_is_singlethreaded) {
			kcd_exit_on_error(kdp_stackshot_record_task(task));
		} else {
			kcd_exit_on_error(stackshot_put_workitem((struct stackshot_workitem) {
				.sswi_task = task,
				.sswi_data = NULL,
				.sswi_idx = cur_workitem_index++
			}));
		}

		if (process_scoped) {
			/* Only targeting one process, we're done now. */
			break;
		}
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if (stackshot_ctx.sc_is_singlethreaded) {
		stackshot_ctx.sc_latency.total_task_iteration_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.total_task_iteration_latency_mt;
	} else {
		stackshot_ctx.sc_latency.task_queue_building_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.task_queue_building_latency_mt;
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/* Setup post-task kcdata buffer */
	if (!stackshot_ctx.sc_is_singlethreaded) {
		stackshot_finalize_linked_kcdata();
		kcd_exit_on_error(stackshot_new_linked_kcdata());
		stackshot_ctx.sc_posttask_kcdata = stackshot_cpu_ctx.scc_kcdata_head;
	}

#if CONFIG_COALITIONS
	/* Don't collect jetsam coalition snapshots in delta stackshots - these don't change */
	if (!collect_delta_stackshot || (last_task_start_time > stackshot_args.since_timestamp)) {
		int num_coalitions = 0;
		struct jetsam_coalition_snapshot *coalitions = NULL;

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
		uint64_t coalition_begin_cpu_cycle_count = 0;

		if (!stackshot_ctx.sc_panic_stackshot && (stackshot_flags & STACKSHOT_SAVE_JETSAM_COALITIONS)) {
			coalition_begin_cpu_cycle_count = mt_cur_cpu_cycles();
		}
#endif /* SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI */

		/* Iterate over coalitions */
		if (stackshot_flags & STACKSHOT_SAVE_JETSAM_COALITIONS) {
			if (coalition_iterate_stackshot(stackshot_coalition_jetsam_count, &num_coalitions, COALITION_TYPE_JETSAM) != KERN_SUCCESS) {
				stackshot_flags &= ~(STACKSHOT_SAVE_JETSAM_COALITIONS);
			}
		}
		if (stackshot_flags & STACKSHOT_SAVE_JETSAM_COALITIONS) {
			if (num_coalitions > 0) {
				/* Variable size array - better not have it on the stack. */
				kcdata_compression_window_open(stackshot_kcdata_p);
				kcd_exit_on_error(kcdata_get_memory_addr_for_array(stackshot_kcdata_p, STACKSHOT_KCTYPE_JETSAM_COALITION_SNAPSHOT, sizeof(struct jetsam_coalition_snapshot), num_coalitions, &out_addr));
				coalitions = (struct jetsam_coalition_snapshot*)out_addr;

				if (coalition_iterate_stackshot(stackshot_coalition_jetsam_snapshot, coalitions, COALITION_TYPE_JETSAM) != KERN_SUCCESS) {
					error = KERN_FAILURE;
					goto error_exit;
				}

				kcd_exit_on_error(kcdata_compression_window_close(stackshot_kcdata_p));
			}
		}
#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
		if (!stackshot_ctx.sc_panic_stackshot && (coalition_begin_cpu_cycle_count != 0)) {
			kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, (mt_cur_cpu_cycles() - coalition_begin_cpu_cycle_count),
			    "coalitions_cpu_cycle_count"));
		}
#endif /* SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI */
	}
#else
	stackshot_flags &= ~(STACKSHOT_SAVE_JETSAM_COALITIONS);
#endif /* CONFIG_COALITIONS */

	stackshot_panic_guard();

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if (stackshot_ctx.sc_is_singlethreaded) {
		stackshot_ctx.sc_latency.total_terminated_task_iteration_latency_mt = mach_absolute_time();
	} else {
		stackshot_ctx.sc_latency.terminated_task_queue_building_latency_mt = mach_absolute_time();
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	/*
	 * Iterate over the tasks in the terminated tasks list. We only inspect
	 * tasks that have a valid bsd_info pointer. The check for task transition
	 * like past P_LPEXIT during proc_exit() is now checked for inside the
	 * kdp_stackshot_record_task(), and then a safer and minimal
	 * transitioning_task_snapshot struct is collected via
	 * kcdata_record_transitioning_task_snapshot()
	 */
	queue_iterate(&terminated_tasks, task, task_t, tasks)
	{
		stackshot_panic_guard();

		if ((task->active && !task_is_a_corpse(task) && !task_is_a_corpse_fork(task)) ||
		    (!queue_empty(&task->threads) && pid_from_task(task) != -1)) {
			tasks_in_stackshot++;
			threads_in_stackshot += task->thread_count;
		}

		/* Only use workqueues on non-panic and non-scoped stackshots. */
		if (stackshot_ctx.sc_is_singlethreaded) {
			kcd_exit_on_error(kdp_stackshot_record_task(task));
		} else {
			kcd_exit_on_error(stackshot_put_workitem((struct stackshot_workitem) {
				.sswi_task = task,
				.sswi_data = NULL,
				.sswi_idx = cur_workitem_index++
			}));
		}
	}

	/* Mark the queue(s) as populated. */
	for (size_t i = 0; i < STACKSHOT_NUM_WORKQUEUES; i++) {
		os_atomic_store(&stackshot_ctx.sc_workqueues[i].sswq_populated, true, release);
	}

#if DEVELOPMENT || DEBUG
	kcd_exit_on_error(kdp_stackshot_plh_stats());
#endif /* DEVELOPMENT || DEBUG */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if (stackshot_ctx.sc_is_singlethreaded) {
		stackshot_ctx.sc_latency.total_terminated_task_iteration_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.total_terminated_task_iteration_latency_mt;
	} else {
		stackshot_ctx.sc_latency.terminated_task_queue_building_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.terminated_task_queue_building_latency_mt;
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if STACKSHOT_COLLECTS_LATENCY_INFO
	if (collect_latency_info) {
		stackshot_ctx.sc_latency.latency_version = 2;
		stackshot_ctx.sc_latency.main_cpu_number = stackshot_ctx.sc_main_cpuid;
		stackshot_ctx.sc_latency.calling_cpu_number = stackshot_ctx.sc_calling_cpuid;
	}
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

#if SCHED_HYGIENE_DEBUG && CONFIG_PERVASIVE_CPI
	if (!stackshot_ctx.sc_panic_stackshot) {
		kcd_exit_on_error(kcdata_add_uint64_with_description(stackshot_kcdata_p, (mt_cur_cpu_cycles() - stackshot_begin_cpu_cycle_count),
		    "stackshot_total_cpu_cycle_cnt"));
	}
#endif

	kcdata_add_uint64_with_description(stackshot_kcdata_p, tasks_in_stackshot, "stackshot_tasks_count");
	kcdata_add_uint64_with_description(stackshot_kcdata_p, threads_in_stackshot, "stackshot_threads_count");

	stackshot_panic_guard();

	if (!stackshot_ctx.sc_is_singlethreaded) {
		/* Chip away at the queue. */
		stackshot_finalize_linked_kcdata();
		stackshot_cpu_do_work();
		*stackshot_kcdata_p = stackshot_cpu_ctx.scc_kcdata_tail->kcdata;
	}

#if CONFIG_EXCLAVES
	/* If this is the panic stackshot, check if Exclaves panic left its stackshot in the shared region */
	if (stackshot_ctx.sc_panic_stackshot) {
		struct exclaves_panic_stackshot excl_ss;
		kdp_read_panic_exclaves_stackshot(&excl_ss);

		if (excl_ss.stackshot_buffer != NULL && excl_ss.stackshot_buffer_size != 0) {
			tb_error_t tberr = TB_ERROR_SUCCESS;
			exclaves_panic_ss_status = EXCLAVES_PANIC_STACKSHOT_FOUND;

			/* this block does not escape, so this is okay... */
			kern_return_t *error_in_block = &error;
			kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_BEGIN,
			    STACKSHOT_KCCONTAINER_EXCLAVES, 0);
			tberr = stackshot_stackshotresult__unmarshal(excl_ss.stackshot_buffer, excl_ss.stackshot_buffer_size, ^(stackshot_stackshotresult_s result){
				*error_in_block = stackshot_exclaves_process_stackshot(&result, stackshot_kcdata_p, false);
			});
			kcdata_add_container_marker(stackshot_kcdata_p, KCDATA_TYPE_CONTAINER_END,
			    STACKSHOT_KCCONTAINER_EXCLAVES, 0);
			if (tberr != TB_ERROR_SUCCESS) {
				exclaves_panic_ss_status = EXCLAVES_PANIC_STACKSHOT_DECODE_FAILED;
			}
		} else {
			exclaves_panic_ss_status = EXCLAVES_PANIC_STACKSHOT_NOT_FOUND;
		}

		/* check error from the block */
		kcd_exit_on_error(error);
	}
#endif

	/*  === END of populating stackshot data === */
error_exit:;
	if (error != KERN_SUCCESS) {
		stackshot_set_error(error);
	}

	stackshot_panic_guard();

	return error;
}

static uint64_t
proc_was_throttled_from_task(task_t task)
{
	uint64_t was_throttled = 0;
	void *bsd_info = get_bsdtask_info(task);

	if (bsd_info) {
		was_throttled = proc_was_throttled(bsd_info);
	}

	return was_throttled;
}

static uint64_t
proc_did_throttle_from_task(task_t task)
{
	uint64_t did_throttle = 0;
	void *bsd_info = get_bsdtask_info(task);

	if (bsd_info) {
		did_throttle = proc_did_throttle(bsd_info);
	}

	return did_throttle;
}

static void
kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap)
{
	unsigned int pages_reclaimed;
	unsigned int pages_wanted;
	kern_return_t kErr;

	uint64_t compressions = 0;
	uint64_t decompressions = 0;

	compressions = counter_load(&vm_statistics_compressions);
	decompressions = counter_load(&vm_statistics_decompressions);

	memio_snap->snapshot_magic = STACKSHOT_MEM_AND_IO_SNAPSHOT_MAGIC;
	memio_snap->free_pages = vm_page_free_count;
	memio_snap->active_pages = vm_page_active_count;
	memio_snap->inactive_pages = vm_page_inactive_count;
	memio_snap->purgeable_pages = vm_page_purgeable_count;
	memio_snap->wired_pages = vm_page_wire_count;
	memio_snap->speculative_pages = vm_page_speculative_count;
	memio_snap->throttled_pages = vm_page_throttled_count;
	memio_snap->busy_buffer_count = count_busy_buffers();
	memio_snap->filebacked_pages = vm_page_pageable_external_count;
	memio_snap->compressions = (uint32_t)compressions;
	memio_snap->decompressions = (uint32_t)decompressions;
	memio_snap->compressor_size = VM_PAGE_COMPRESSOR_COUNT;
	kErr = mach_vm_pressure_monitor(FALSE, VM_PRESSURE_TIME_WINDOW, &pages_reclaimed, &pages_wanted);

	if (!kErr) {
		memio_snap->pages_wanted = (uint32_t)pages_wanted;
		memio_snap->pages_reclaimed = (uint32_t)pages_reclaimed;
		memio_snap->pages_wanted_reclaimed_valid = 1;
	} else {
		memio_snap->pages_wanted = 0;
		memio_snap->pages_reclaimed = 0;
		memio_snap->pages_wanted_reclaimed_valid = 0;
	}
}

static vm_offset_t
stackshot_find_phys(vm_map_t map, vm_offset_t target_addr, kdp_fault_flags_t fault_flags, uint32_t *kdp_fault_result_flags)
{
	vm_offset_t result;
	struct kdp_fault_result fault_results = {0};
	if (stackshot_cpu_ctx.scc_fault_stats.sfs_stopped_faulting) {
		fault_flags &= ~KDP_FAULT_FLAGS_ENABLE_FAULTING;
	}
	if (!stackshot_ctx.sc_panic_stackshot) {
		fault_flags |= KDP_FAULT_FLAGS_MULTICPU;
	}

	result = kdp_find_phys(map, target_addr, fault_flags, &fault_results);

	if ((fault_results.flags & KDP_FAULT_RESULT_TRIED_FAULT) || (fault_results.flags & KDP_FAULT_RESULT_FAULTED_IN)) {
		stackshot_cpu_ctx.scc_fault_stats.sfs_time_spent_faulting += fault_results.time_spent_faulting;

#if STACKSHOT_COLLECTS_LATENCY_INFO
		stackshot_cpu_latency.faulting_time_mt += fault_results.time_spent_faulting;
#endif

		if ((stackshot_cpu_ctx.scc_fault_stats.sfs_time_spent_faulting >= stackshot_max_fault_time) && !stackshot_ctx.sc_panic_stackshot) {
			stackshot_cpu_ctx.scc_fault_stats.sfs_stopped_faulting = (uint8_t) TRUE;
		}
	}

	if (fault_results.flags & KDP_FAULT_RESULT_FAULTED_IN) {
		stackshot_cpu_ctx.scc_fault_stats.sfs_pages_faulted_in++;
	}

	if (kdp_fault_result_flags) {
		*kdp_fault_result_flags = fault_results.flags;
	}

	return result;
}

/*
 * Wrappers around kdp_generic_copyin, kdp_generic_copyin_word, kdp_generic_copyin_string that use stackshot_find_phys
 * in order to:
 *   1. collect statistics on the number of pages faulted in
 *   2. stop faulting if the time spent faulting has exceeded the limit.
 */
static boolean_t
stackshot_copyin(vm_map_t map, uint64_t uaddr, void *dest, size_t size, boolean_t try_fault, kdp_fault_result_flags_t *kdp_fault_result_flags)
{
	kdp_fault_flags_t fault_flags = KDP_FAULT_FLAGS_NONE;
	if (try_fault) {
		fault_flags |= KDP_FAULT_FLAGS_ENABLE_FAULTING;
	}
	return kdp_generic_copyin(map, uaddr, dest, size, fault_flags, (find_phys_fn_t)stackshot_find_phys, kdp_fault_result_flags) == KERN_SUCCESS;
}
static boolean_t
stackshot_copyin_word(task_t task, uint64_t addr, uint64_t *result, boolean_t try_fault, kdp_fault_result_flags_t *kdp_fault_result_flags)
{
	kdp_fault_flags_t fault_flags = KDP_FAULT_FLAGS_NONE;
	if (try_fault) {
		fault_flags |= KDP_FAULT_FLAGS_ENABLE_FAULTING;
	}
	return kdp_generic_copyin_word(task, addr, result, fault_flags, (find_phys_fn_t)stackshot_find_phys, kdp_fault_result_flags) == KERN_SUCCESS;
}
static int
stackshot_copyin_string(task_t task, uint64_t addr, char *buf, int buf_sz, boolean_t try_fault, kdp_fault_result_flags_t *kdp_fault_result_flags)
{
	kdp_fault_flags_t fault_flags = KDP_FAULT_FLAGS_NONE;
	if (try_fault) {
		fault_flags |= KDP_FAULT_FLAGS_ENABLE_FAULTING;
	}
	return kdp_generic_copyin_string(task, addr, buf, buf_sz, fault_flags, (find_phys_fn_t)stackshot_find_phys, kdp_fault_result_flags);
}

kern_return_t
do_stackshot(void *context)
{
#pragma unused(context)
	kern_return_t error;
	size_t queue_size;
	uint64_t abs_time = mach_absolute_time(), abs_time_end = 0;
	kdp_snapshot++;

	_stackshot_validation_reset();
	error = stackshot_plh_setup(); /* set up port label hash */

	if (!stackshot_ctx.sc_is_singlethreaded) {
		/* Set up queues. These numbers shouldn't change, but slightly fudge queue size just in case. */
		queue_size = FUDGED_SIZE(tasks_count + terminated_tasks_count, 10);
		for (size_t i = 0; i < STACKSHOT_NUM_WORKQUEUES; i++) {
			stackshot_ctx.sc_workqueues[i] = (struct stackshot_workqueue) {
				.sswq_items     = stackshot_alloc_arr(struct stackshot_workitem, queue_size, &error),
				.sswq_capacity  = queue_size,
				.sswq_num_items = 0,
				.sswq_cur_item  = 0,
				.sswq_populated = false
			};
			if (error != KERN_SUCCESS) {
				break;
			}
		}
	}

	if (error != KERN_SUCCESS) {
		stackshot_set_error(error);
		return error;
	}

	/*
	 * If no main CPU has been selected at this point, (since every CPU has
	 * called stackshot_cpu_preflight by now), then there was no CLPC
	 * recommended P-core available. In that case, we should volunteer ourself
	 * to be the main CPU, because someone has to do it.
	 */
	if (stackshot_ctx.sc_main_cpuid == -1) {
		os_atomic_cmpxchg(&stackshot_ctx.sc_main_cpuid, -1, cpu_number(), acquire);
		stackshot_cpu_ctx.scc_can_work = true;
	}

	/* After this, auxiliary CPUs can begin work. */
	os_atomic_store(&stackshot_ctx.sc_state, SS_RUNNING, release);

	/* If we are the main CPU, populate the queues / do other main CPU work. */
	if (stackshot_ctx.sc_panic_stackshot || (stackshot_ctx.sc_main_cpuid == cpu_number())) {
		stackshot_ctx.sc_retval = kdp_stackshot_kcdata_format();
	} else if (stackshot_cpu_ctx.scc_can_work) {
		stackshot_cpu_do_work();
	}

	/* Wait for every CPU to finish. */
#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_ctx.sc_latency.cpu_wait_latency_mt = mach_absolute_time();
#endif
	if (stackshot_cpu_ctx.scc_can_work) {
		os_atomic_dec(&stackshot_ctx.sc_cpus_working, seq_cst);
		stackshot_cpu_ctx.scc_can_work = false;
	}
	while (os_atomic_load(&stackshot_ctx.sc_cpus_working, seq_cst) != 0) {
		loop_wait();
	}
	stackshot_panic_guard();
#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_ctx.sc_latency.cpu_wait_latency_mt = mach_absolute_time() - stackshot_ctx.sc_latency.cpu_wait_latency_mt;
#endif

	/* update timestamp of the stackshot */
	abs_time_end = mach_absolute_time();
	stackshot_ctx.sc_duration = (struct stackshot_duration_v2) {
		.stackshot_duration       = (abs_time_end - abs_time),
		.stackshot_duration_outer = 0,
		.stackshot_duration_prior = stackshot_duration_prior_abs,
	};

	stackshot_plh_reset();

	/* Check interrupts disabled time. */
#if SCHED_HYGIENE_DEBUG
	bool disable_interrupts_masked_check = kern_feature_override(
		KF_INTERRUPT_MASKED_DEBUG_STACKSHOT_OVRD) ||
	    (stackshot_flags & STACKSHOT_DO_COMPRESS) != 0;

#if STACKSHOT_INTERRUPTS_MASKED_CHECK_DISABLED
	disable_interrupts_masked_check = true;
#endif /* STACKSHOT_INTERRUPTS_MASKED_CHECK_DISABLED */

	if (disable_interrupts_masked_check) {
		ml_spin_debug_clear_self();
	}

	if (!stackshot_ctx.sc_panic_stackshot && interrupt_masked_debug_mode) {
		/*
		 * Try to catch instances where stackshot takes too long BEFORE returning from
		 * the debugger
		 */
		ml_handle_stackshot_interrupt_disabled_duration(current_thread());
	}
#endif /* SCHED_HYGIENE_DEBUG */

	kdp_snapshot--;

	/* If any other CPU had an error, make sure we return it */
	if (stackshot_ctx.sc_retval == KERN_SUCCESS) {
		stackshot_ctx.sc_retval = stackshot_status_check();
	}

#if CONFIG_EXCLAVES
	/* Avoid setting AST until as late as possible, in case the stackshot fails */
	if (!stackshot_ctx.sc_panic_stackshot && stackshot_ctx.sc_retval == KERN_SUCCESS) {
		commit_exclaves_ast();
	}
	if (stackshot_ctx.sc_retval != KERN_SUCCESS && stackshot_exclave_inspect_ctids) {
		/* Clear inspection CTID list: no need to wait for these threads */
		stackshot_exclave_inspect_ctid_count = 0;
		stackshot_exclave_inspect_ctid_capacity = 0;
		stackshot_exclave_inspect_ctids = NULL;
	}
#endif

	/* If this is a singlethreaded stackshot, the "final" kcdata buffer is just our CPU's kcdata buffer */
	if (stackshot_ctx.sc_is_singlethreaded) {
		stackshot_ctx.sc_finalized_kcdata = stackshot_kcdata_p;
	}

	return stackshot_ctx.sc_retval;
}

kern_return_t
do_panic_stackshot(void *context)
{
	kern_return_t ret = do_stackshot(context);
	if (ret != KERN_SUCCESS) {
		goto out;
	}

	ret = stackshot_finalize_singlethreaded_kcdata();

out:
	return ret;
}

/*
 * Set up needed state for this CPU before participating in a stackshot.
 * Namely, we want to signal that we're available to do work.
 * Called while interrupts are disabled & in the debugger trap.
 */
void
stackshot_cpu_preflight(void)
{
	bool is_recommended, is_calling_cpu;
	int my_cpu_no = cpu_number();

#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_cpu_latency = (typeof(stackshot_cpu_latency)) {
		.cpu_number            =  cpu_number(),
#if defined(__AMP__)
		.cluster_type          =  current_cpu_datap()->cpu_cluster_type,
#else /* __AMP__ */
		.cluster_type = CLUSTER_TYPE_SMP,
#endif /* __AMP__ */
		.faulting_time_mt      = 0,
		.total_buf             = 0,
		.intercluster_buf_used = 0
	};
#if CONFIG_PERVASIVE_CPI
	mt_cur_cpu_cycles_instrs_speculative(&stackshot_cpu_latency.total_cycles, &stackshot_cpu_latency.total_instrs);
#endif /* CONFIG_PERVASIVE_CPI */
	stackshot_cpu_latency.init_latency_mt = stackshot_cpu_latency.total_latency_mt = mach_absolute_time();
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

	is_recommended = current_processor()->is_recommended;

	/* If this is a recommended P-core (or SMP), try making it the main CPU */
	if (is_recommended
#if defined(__AMP__)
	    && current_cpu_datap()->cpu_cluster_type == CLUSTER_TYPE_P
#endif /* __AMP__ */
	    ) {
		os_atomic_cmpxchg(&stackshot_ctx.sc_main_cpuid, -1, my_cpu_no, acquire);
	}

	is_calling_cpu = stackshot_ctx.sc_calling_cpuid == my_cpu_no;

	stackshot_cpu_ctx.scc_did_work = false;
	stackshot_cpu_ctx.scc_can_work = is_calling_cpu || (is_recommended && !stackshot_ctx.sc_is_singlethreaded);

	if (stackshot_cpu_ctx.scc_can_work) {
		os_atomic_inc(&stackshot_ctx.sc_cpus_working, relaxed);
	}
}

__result_use_check
static kern_return_t
stackshot_cpu_work_on_queue(struct stackshot_workqueue *queue)
{
	struct stackshot_workitem     *cur_workitemp;
	kern_return_t                  error = KERN_SUCCESS;

	while (((cur_workitemp = stackshot_get_workitem(queue)) != NULL || !os_atomic_load(&queue->sswq_populated, acquire))) {
		/* Check to make sure someone hasn't errored out or panicked. */
		if (__improbable(stackshot_status_check() != KERN_SUCCESS)) {
			return KERN_ABORTED;
		}

		if (cur_workitemp) {
			kcd_exit_on_error(stackshot_new_linked_kcdata());
			cur_workitemp->sswi_data = stackshot_cpu_ctx.scc_kcdata_head;
			kcd_exit_on_error(kdp_stackshot_record_task(cur_workitemp->sswi_task));
			stackshot_finalize_linked_kcdata();
		} else {
#if STACKSHOT_COLLECTS_LATENCY_INFO
			uint64_t time_begin = mach_absolute_time();
#endif
			loop_wait();
#if STACKSHOT_COLLECTS_LATENCY_INFO
			stackshot_cpu_latency.workqueue_latency_mt += mach_absolute_time() - time_begin;
#endif
		}
	}

error_exit:
	return error;
}

static void
stackshot_cpu_do_work(void)
{
	kern_return_t                  error;

	stackshot_cpu_ctx.scc_stack_buffer = stackshot_alloc_arr(uintptr_t, MAX_FRAMES, &error);
	if (error != KERN_SUCCESS) {
		goto error_exit;
	}

#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_cpu_latency.init_latency_mt = mach_absolute_time() - stackshot_cpu_latency.init_latency_mt;
#endif

	bool high_perf = true;

#if defined(__AMP__)
	if (current_cpu_datap()->cpu_cluster_type == CLUSTER_TYPE_E) {
		high_perf = false;
	}
#endif /* __AMP__ */

	if (high_perf) {
		/* Non-E cores: Work from most difficult to least difficult */
		for (size_t i = STACKSHOT_NUM_WORKQUEUES; i > 0; i--) {
			kcd_exit_on_error(stackshot_cpu_work_on_queue(&stackshot_ctx.sc_workqueues[i - 1]));
		}
	} else {
		/* E: Work from least difficult to most difficult */
		for (size_t i = 0; i < STACKSHOT_NUM_WORKQUEUES; i++) {
			kcd_exit_on_error(stackshot_cpu_work_on_queue(&stackshot_ctx.sc_workqueues[i]));
		}
	}
#if STACKSHOT_COLLECTS_LATENCY_INFO
	stackshot_cpu_latency.total_latency_mt = mach_absolute_time() - stackshot_cpu_latency.total_latency_mt;
#if CONFIG_PERVASIVE_CPI
	uint64_t cycles, instrs;
	mt_cur_cpu_cycles_instrs_speculative(&cycles, &instrs);
	stackshot_cpu_latency.total_cycles = cycles - stackshot_cpu_latency.total_cycles;
	stackshot_cpu_latency.total_instrs = instrs - stackshot_cpu_latency.total_instrs;
#endif /* CONFIG_PERVASIVE_CPI */
#endif /* STACKSHOT_COLLECTS_LATENCY_INFO */

error_exit:
	if (error != KERN_SUCCESS) {
		stackshot_set_error(error);
	}
	stackshot_panic_guard();
}

/*
 * This is where the other CPUs will end up when we take a stackshot.
 * If they're available to do work, they'll do so here.
 * Called with interrupts disabled & from the debugger trap.
 */
void
stackshot_aux_cpu_entry(void)
{
	/*
	 * This is where the other CPUs will end up when we take a stackshot.
	 * Also, the main CPU will call this in the middle of its work to chip
	 * away at the queue.
	 */

	/* Don't do work if we said we couldn't... */
	if (!stackshot_cpu_ctx.scc_can_work) {
		return;
	}

	/* Spin until we're ready to run. */
	while (os_atomic_load(&stackshot_ctx.sc_state, acquire) == SS_SETUP) {
		loop_wait();
	}

	/* Check to make sure the setup didn't error out or panic. */
	if (stackshot_status_check() != KERN_SUCCESS) {
		goto exit;
	}

	/* the CPU entering here is participating in the stackshot */
	stackshot_cpu_ctx.scc_did_work = true;

	if (stackshot_ctx.sc_main_cpuid == cpu_number()) {
		stackshot_ctx.sc_retval = kdp_stackshot_kcdata_format();
	} else {
		stackshot_cpu_do_work();
	}

exit:
	os_atomic_dec(&stackshot_ctx.sc_cpus_working, release);
}

boolean_t
stackshot_thread_is_idle_worker_unsafe(thread_t thread)
{
	/* When the pthread kext puts a worker thread to sleep, it will
	 * set kThreadWaitParkedWorkQueue in the block_hint of the thread
	 * struct. See parkit() in kern/kern_support.c in libpthread.
	 */
	return (thread->state & TH_WAIT) &&
	       (thread->block_hint == kThreadWaitParkedWorkQueue);
}

#if CONFIG_COALITIONS
static void
stackshot_coalition_jetsam_count(void *arg, int i, coalition_t coal)
{
#pragma unused(i, coal)
	unsigned int *coalition_count = (unsigned int*)arg;
	(*coalition_count)++;
}

static void
stackshot_coalition_jetsam_snapshot(void *arg, int i, coalition_t coal)
{
	if (coalition_type(coal) != COALITION_TYPE_JETSAM) {
		return;
	}

	struct jetsam_coalition_snapshot *coalitions = (struct jetsam_coalition_snapshot*)arg;
	struct jetsam_coalition_snapshot *jcs = &coalitions[i];
	task_t leader = TASK_NULL;
	jcs->jcs_id = coalition_id(coal);
	jcs->jcs_flags = 0;
	jcs->jcs_thread_group = 0;

	if (coalition_term_requested(coal)) {
		jcs->jcs_flags |= kCoalitionTermRequested;
	}
	if (coalition_is_terminated(coal)) {
		jcs->jcs_flags |= kCoalitionTerminated;
	}
	if (coalition_is_reaped(coal)) {
		jcs->jcs_flags |= kCoalitionReaped;
	}
	if (coalition_is_privileged(coal)) {
		jcs->jcs_flags |= kCoalitionPrivileged;
	}

#if CONFIG_THREAD_GROUPS
	struct thread_group *thread_group = kdp_coalition_get_thread_group(coal);
	if (thread_group) {
		jcs->jcs_thread_group = thread_group_get_id(thread_group);
	}
#endif /* CONFIG_THREAD_GROUPS */

	leader = kdp_coalition_get_leader(coal);
	if (leader) {
		jcs->jcs_leader_task_uniqueid = get_task_uniqueid(leader);
	} else {
		jcs->jcs_leader_task_uniqueid = 0;
	}
}
#endif /* CONFIG_COALITIONS */

#if CONFIG_THREAD_GROUPS
static void
stackshot_thread_group_count(void *arg, int i, struct thread_group *tg)
{
#pragma unused(i, tg)
	unsigned int *n = (unsigned int*)arg;
	(*n)++;
}

static void
stackshot_thread_group_snapshot(void *arg, int i, struct thread_group *tg)
{
	struct thread_group_snapshot_v3 *thread_groups = arg;
	struct thread_group_snapshot_v3 *tgs = &thread_groups[i];
	const char *name = thread_group_get_name(tg);
	uint32_t flags = thread_group_get_flags(tg);
	tgs->tgs_id = thread_group_get_id(tg);
	static_assert(THREAD_GROUP_MAXNAME > sizeof(tgs->tgs_name));
	kdp_memcpy(tgs->tgs_name, name, sizeof(tgs->tgs_name));
	kdp_memcpy(tgs->tgs_name_cont, name + sizeof(tgs->tgs_name),
	    sizeof(tgs->tgs_name_cont));
	tgs->tgs_flags =
	    ((flags & THREAD_GROUP_FLAGS_EFFICIENT)     ? kThreadGroupEfficient     : 0) |
	    ((flags & THREAD_GROUP_FLAGS_APPLICATION)   ? kThreadGroupApplication   : 0) |
	    ((flags & THREAD_GROUP_FLAGS_CRITICAL)      ? kThreadGroupCritical      : 0) |
	    ((flags & THREAD_GROUP_FLAGS_BEST_EFFORT)   ? kThreadGroupBestEffort    : 0) |
	    ((flags & THREAD_GROUP_FLAGS_UI_APP)        ? kThreadGroupUIApplication : 0) |
	    ((flags & THREAD_GROUP_FLAGS_MANAGED)       ? kThreadGroupManaged       : 0) |
	    ((flags & THREAD_GROUP_FLAGS_STRICT_TIMERS) ? kThreadGroupStrictTimers  : 0) |
	    0;
}
#endif /* CONFIG_THREAD_GROUPS */

/* Determine if a thread has waitinfo that stackshot can provide */
static int
stackshot_thread_has_valid_waitinfo(thread_t thread)
{
	if (!(thread->state & TH_WAIT)) {
		return 0;
	}

	switch (thread->block_hint) {
	// If set to None or is a parked work queue, ignore it
	case kThreadWaitParkedWorkQueue:
	case kThreadWaitNone:
		return 0;
	// There is a short window where the pthread kext removes a thread
	// from its ksyn wait queue before waking the thread up
	case kThreadWaitPThreadMutex:
	case kThreadWaitPThreadRWLockRead:
	case kThreadWaitPThreadRWLockWrite:
	case kThreadWaitPThreadCondVar:
		return kdp_pthread_get_thread_kwq(thread) != NULL;
	// All other cases are valid block hints if in a wait state
	default:
		return 1;
	}
}

/* Determine if a thread has turnstileinfo that stackshot can provide */
static int
stackshot_thread_has_valid_turnstileinfo(thread_t thread)
{
	struct turnstile *ts = thread_get_waiting_turnstile(thread);

	return stackshot_thread_has_valid_waitinfo(thread) &&
	       ts != TURNSTILE_NULL;
}

static void
stackshot_thread_turnstileinfo(thread_t thread, thread_turnstileinfo_v2_t *tsinfo)
{
	struct turnstile *ts;
	struct ipc_service_port_label *ispl = NULL;

	/* acquire turnstile information and store it in the stackshot */
	ts = thread_get_waiting_turnstile(thread);
	tsinfo->waiter = thread_tid(thread);
	kdp_turnstile_fill_tsinfo(ts, tsinfo, &ispl);
	tsinfo->portlabel_id = stackshot_plh_lookup(ispl,
	    (tsinfo->turnstile_flags & STACKSHOT_TURNSTILE_STATUS_SENDPORT) ? STACKSHOT_PLH_LOOKUP_SEND :
	    (tsinfo->turnstile_flags & STACKSHOT_TURNSTILE_STATUS_RECEIVEPORT) ? STACKSHOT_PLH_LOOKUP_RECEIVE :
	    STACKSHOT_PLH_LOOKUP_UNKNOWN);
}

static void
stackshot_thread_wait_owner_info(thread_t thread, thread_waitinfo_v2_t *waitinfo)
{
	thread_waitinfo_t *waitinfo_v1 = (thread_waitinfo_t *)waitinfo;
	struct ipc_service_port_label *ispl = NULL;

	waitinfo->waiter        = thread_tid(thread);
	waitinfo->wait_type     = thread->block_hint;
	waitinfo->wait_flags    = 0;

	switch (waitinfo->wait_type) {
	case kThreadWaitKernelMutex:
		kdp_lck_mtx_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitPortReceive:
		kdp_mqueue_recv_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo, &ispl);
		waitinfo->portlabel_id  = stackshot_plh_lookup(ispl, STACKSHOT_PLH_LOOKUP_RECEIVE);
		break;
	case kThreadWaitPortSend:
		kdp_mqueue_send_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo, &ispl);
		waitinfo->portlabel_id  = stackshot_plh_lookup(ispl, STACKSHOT_PLH_LOOKUP_SEND);
		break;
	case kThreadWaitSemaphore:
		kdp_sema_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitUserLock:
		kdp_ulock_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitKernelRWLockRead:
	case kThreadWaitKernelRWLockWrite:
	case kThreadWaitKernelRWLockUpgrade:
		kdp_rwlck_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitPThreadMutex:
	case kThreadWaitPThreadRWLockRead:
	case kThreadWaitPThreadRWLockWrite:
	case kThreadWaitPThreadCondVar:
		kdp_pthread_find_owner(thread, waitinfo_v1);
		break;
	case kThreadWaitWorkloopSyncWait:
		kdp_workloop_sync_wait_find_owner(thread, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitOnProcess:
		kdp_wait4_find_process(thread, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitSleepWithInheritor:
		kdp_sleep_with_inheritor_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitEventlink:
		kdp_eventlink_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitCompressor:
		kdp_compressor_busy_find_owner(thread->wait_event, waitinfo_v1);
		break;
#ifdef CONFIG_EXCLAVES
	case kThreadWaitExclaveCore:
	case kThreadWaitExclaveKit:
		kdp_esync_find_owner(thread->waitq.wq_q, thread->wait_event, waitinfo_v1);
		break;
#endif /* CONFIG_EXCLAVES */
	case kThreadWaitPageBusy:
		kdp_vm_page_sleep_find_owner(thread->wait_event, waitinfo_v1);
		break;
	case kThreadWaitPagingInProgress:
	case kThreadWaitPagingActivity:
	case kThreadWaitPagerInit:
	case kThreadWaitPagerReady:
	case kThreadWaitMemoryBlocked:
	case kThreadWaitPageInThrottle:
		kdp_vm_object_sleep_find_owner(thread->wait_event, waitinfo->wait_type, waitinfo_v1);
		break;
	default:
		waitinfo->owner = 0;
		waitinfo->context = 0;
		break;
	}
}
