// Copyright (c) 2024 Apple Inc.  All rights reserved.

#include <mach/mach_time.h>

#ifndef MIN
#define MIN(a, b) (((a)<(b))?(a):(b))
#endif /* MIN */
#ifndef MAX
#define MAX(a, b) (((a)>(b))?(a):(b))
#endif  /* MAX */

/* Panicking and asserting */
__attribute__((noreturn))
void
panic(char *msg, ...)
{
	printf("\n🚨🚨🚨 Panicking (FAIL) 😱😱😱: ");
	va_list args;
	va_start(args, msg);
	vprintf(msg, args);
	va_end(args);
	printf("\n");
	abort();
}

#define assert(expression) { \
	if ((expression) == false) { \
	    panic("%s:%d Assert failed: %s", __FILE__, __LINE__, #expression); \
	} \
    }

#define assert3f(arg1, op, arg2, arg_fmt, cast_type) { \
	if ((arg1 op arg2) == false) { \
	    panic("%s:%d Assert failed: %s(%"arg_fmt") %s %s(%"arg_fmt")", \
	        __FILE__, __LINE__, #arg1, (cast_type)arg1, #op, #arg2, (cast_type)arg2); \
	} \
    }
#define assert3u(arg1, op, arg2) assert3f(arg1, op, arg2, "llu", uint64_t)
#define assert3s(arg1, op, arg2) assert3f(arg1, op, arg2, "lld", int64_t)
#define assert3p(arg1, op, arg2) assert3f(arg1, op, arg2, "p", void *)

/* Overrides necessary for userspace code */
#define KDBG(a1, a2, a3, a4, a5) clutch_impl_log_tracepoint(a1, a2, a3, a4, a5)
#define KDBG_RELEASE(...) (void)0
#define kalloc_type(x, y, z) calloc((size_t)y, sizeof(x))
#define kfree_type(x, y, z) do { free(z); (void)(y); } while (0)
#define PE_parse_boot_argn(x, y, z) FALSE
#define kprintf(...) printf(__VA_ARGS__)
#define ml_get_interrupts_enabled() (true)

/* Mock locks */
typedef void *lck_ticket_t;
#define LCK_SPIN_DECLARE(var, name)        int var
#define LCK_GRP_DECLARE(var, name)         int var
#define SIMPLE_LOCK_DECLARE(var, name)     int var
#define LCK_ATTR_DECLARE(var, a, b)        int var
#define LCK_MTX_DECLARE_ATTR(var, a, b)    int var
#define LCK_MTX_DECLARE(var, a)            int var
#define decl_lck_mtx_data(class, name)     class int name
#define decl_simple_lock_data(class, name) class int name
#define pset_lock_init(x) (void)x
#define pset_lock(x) (void)x
#define pset_unlock(x) (void)x
#define change_locked_pset(x, y) y
#define pset_assert_locked(x) (void)x
#define thread_lock(x) (void)x
#define thread_unlock(x) (void)x
#define simple_lock(...)
#define simple_unlock(...)
#define simple_lock_assert(...)
#define simple_lock_init(...)
#define lck_spin_lock(...)
#define lck_spin_unlock(...)

/* Processor-related */
#define PERCPU_DECL(type_t, name) type_t name
#include <kern/processor.h>

/* SMR-related */
#define smr_cpu_init(a) (void)0
#define IP_NULL 0

/* Allocating-related */
#define zalloc_permanent_type(type) malloc(sizeof(type))

#define sched_processor_change_mode_locked(...) (void)0

static struct processor master_processor_backing;
processor_t master_processor = &master_processor_backing;

/* Expected global(s) */
static task_t kernel_task = NULL;

/* Time conversion to mock the implementation in osfmk/arm/rtclock.c */
static mach_timebase_info_data_t timebase_info;
void
clock_interval_to_absolutetime_interval(uint32_t   interval,
    uint32_t   scale_factor,
    uint64_t * result)
{
	mach_timebase_info(&timebase_info);
	uint64_t nanosecs = (uint64_t) interval * scale_factor;
	*result = nanosecs * timebase_info.denom / timebase_info.numer;
}

void
absolutetime_to_nanoseconds(uint64_t   abstime,
    uint64_t * result)
{
	mach_timebase_info(&timebase_info);
	*result = abstime * timebase_info.numer / timebase_info.denom;
}

/*
 * thread struct from osfmk/kern/thread.h containing only fields needed by
 * the Clutch runqueue logic, followed by needed functions from osfmk/kern/thread.c
 * for operating on the __runq field
 */
struct thread {
	int id;
	sched_mode_t sched_mode;
	int16_t                 sched_pri;              /* scheduled (current) priority */
	int16_t                 base_pri;               /* effective base priority (equal to req_base_pri unless TH_SFLAG_BASE_PRI_FROZEN) */
	queue_chain_t                   runq_links;             /* run queue links */
	struct { processor_t    runq; } __runq; /* internally managed run queue assignment, see above comment */
	sched_bucket_t          th_sched_bucket;
	processor_t             bound_processor;        /* bound to a processor? */
	processor_t             last_processor;         /* processor last dispatched on */
	ast_t                   reason;         /* why we blocked */
	int                     state;
#define TH_WAIT                 0x01            /* queued for waiting */
#define TH_RUN                  0x04            /* running or on runq */
#define TH_IDLE                 0x80            /* idling processor */
#define TH_SFLAG_DEPRESS                0x0040          /* normal depress yield */
#define TH_SFLAG_POLLDEPRESS            0x0080          /* polled depress yield */
#define TH_SFLAG_DEPRESSED_MASK         (TH_SFLAG_DEPRESS | TH_SFLAG_POLLDEPRESS)
#define TH_SFLAG_BOUND_SOFT             0x20000         /* thread is soft bound to a cluster; can run anywhere if bound cluster unavailable */
	uint64_t                thread_id;             /* system wide unique thread-id */
	struct {
		uint64_t user_time;
		uint64_t system_time;
	} mock_recount_time;
	uint64_t sched_time_save;
	natural_t               sched_usage;            /* timesharing cpu usage [sched] */
	natural_t               pri_shift;              /* usage -> priority from pset */
	natural_t               cpu_usage;              /* instrumented cpu usage [%cpu] */
	natural_t               cpu_delta;              /* accumulated cpu_usage delta */
	struct thread_group     *thread_group;
	struct priority_queue_entry_stable      th_clutch_runq_link;
	struct priority_queue_entry_sched       th_clutch_pri_link;
	queue_chain_t                           th_clutch_timeshare_link;
	uint32_t                sched_flags;            /* current flag bits */
#define THREAD_BOUND_PSET_NONE       PSET_ID_INVALID
	pset_id_t                 th_bound_pset_id;
#if CONFIG_SCHED_EDGE
	bool            th_bound_pset_enqueued;
	bool            th_shared_rsrc_enqueued[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	bool            th_shared_rsrc_heavy_user[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	bool            th_shared_rsrc_heavy_perf_control[CLUSTER_SHARED_RSRC_TYPE_COUNT];
	bool            th_expired_quantum_on_lower_core;
	bool            th_expired_quantum_on_higher_core;
#endif /* CONFIG_SCHED_EDGE */
	sfi_class_id_t          sfi_class;      /* SFI class (XXX Updated on CSW/QE/AST) */

	/* real-time parameters */
	struct {                                        /* see mach/thread_policy.h */
		uint32_t            period;
		uint32_t            computation;
		uint32_t            constraint;
		bool                preemptible;
		uint8_t             priority_offset;   /* base_pri = BASEPRI_RTQUEUES + priority_offset */
		uint64_t            deadline;
	}                       realtime;

	uint64_t                last_made_runnable_time;        /* time when thread was unblocked or preempted */
};

void
thread_assert_runq_null(__assert_only thread_t thread)
{
	assert(thread->__runq.runq == PROCESSOR_NULL);
}

void
thread_assert_runq_nonnull(thread_t thread)
{
	assert(thread->__runq.runq != PROCESSOR_NULL);
}

void
thread_clear_runq(thread_t thread)
{
	thread_assert_runq_nonnull(thread);
	thread->__runq.runq = PROCESSOR_NULL;
}

void
thread_set_runq_locked(thread_t thread, processor_t new_runq)
{
	thread_assert_runq_null(thread);
	thread->__runq.runq = new_runq;
}

processor_t
thread_get_runq_locked(thread_t thread)
{
	return thread->__runq.runq;
}

uint64_t
thread_tid(
	thread_t        thread)
{
	return thread != THREAD_NULL? thread->thread_id: 0;
}

void
thread_clear_runq_locked(thread_t thread)
{
	thread->__runq.runq = PROCESSOR_NULL;
}

/* Satisfy recount dependency needed by osfmk/kern/sched.h */
#define recount_thread_time_mach(thread) (thread->mock_recount_time.user_time + thread->mock_recount_time.system_time)

/*
 * thread_group struct from osfmk/kern/thread_group.c containing only fields
 * needed by the Clutch runqueue logic, followed by needed functions from
 * osfmk/kern/thread_group.c
 */
struct thread_group {
	uint64_t                tg_id;
	struct sched_clutch     tg_sched_clutch;
};

sched_clutch_t
sched_clutch_for_thread(thread_t thread)
{
	assert(thread->thread_group != NULL);
	return &(thread->thread_group->tg_sched_clutch);
}

sched_clutch_t
sched_clutch_for_thread_group(struct thread_group *thread_group)
{
	return &(thread_group->tg_sched_clutch);
}

uint64_t
thread_group_get_id(struct thread_group *tg)
{
	return tg->tg_id;
}

/*
 * Get thread's current thread group
 */
inline struct thread_group *
thread_group_get(thread_t t)
{
	return t->thread_group;
}

inline boolean_t
thread_group_uses_immediate_ipi(struct thread_group *tg)
{
	return FALSE;
}

#if CONFIG_SCHED_EDGE

bool
thread_shared_rsrc_policy_get(thread_t thread, cluster_shared_rsrc_type_t type)
{
	return thread->th_shared_rsrc_heavy_user[type] || thread->th_shared_rsrc_heavy_perf_control[type];
}

#endif /* CONFIG_SCHED_EDGE */

/* From osfmk/arm64/machine_routines.c */
bool cpu_config_modified = false;
