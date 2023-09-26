/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <libkern/libkern.h>
#include <libkern/coreanalytics/coreanalytics.h>
#include <mach/mach_types.h>
#include <sys/errno.h>
#include <sys/kauth.h>
#include <sys/proc_internal.h>
#include <sys/stackshot.h>
#include <sys/sysproto.h>
#include <sys/sysctl.h>
#include <pexpert/device_tree.h>
#include <pexpert/pexpert.h>
#include <os/log.h>
#include <IOKit/IOBSD.h>

extern uint32_t stackshot_estimate_adj;
EXPERIMENT_FACTOR_UINT(_kern, stackshot_estimate_adj, &stackshot_estimate_adj, 0, 100,
    "adjust stackshot estimates up by this percentage");

#define SSHOT_ANALYTICS_PERIOD_HOURS       1

enum stackshot_report_setting {
	STACKSHOT_REPORT_NONE = 0,
	STACKSHOT_REPORT_NO_ENT = 1,    /* report if missing entitlement */
	STACKSHOT_REPORT_ALL = 2,       /* always report */
};

#define STACKSHOT_ENTITLEMENT_REPORT STACKSHOT_REPORT_ALL
#define STACKSHOT_ENTITLEMENT_REFUSE false
/*
 * Controls for Stackshot entitlement; changable with boot args
 *    stackshot_entitlement_report=0 or 1 or 2  (send CoreAnalytics when called without entitlement(1) or always(2))
 *    stackshot_entitlement_fail=0 or 1    (fail call without entitlement)
 * This only effects requests from userspace.
 *
 * For reporting, we only report a given command once.
 */
SECURITY_READ_ONLY_LATE(uint8_t) stackshot_entitlement_report = STACKSHOT_ENTITLEMENT_REPORT;
SECURITY_READ_ONLY_LATE(bool) stackshot_entitlement_refuse = STACKSHOT_ENTITLEMENT_REFUSE;

#define STACKSHOT_ENTITLEMENT "com.apple.private.stackshot"
#define STACKSHOT_STATS_ENTITLEMENT "com.apple.private.stackshot.stats"
#define SSHOT_ENTITLEMENT_BOOTARG_REPORT "sshot-entitlement-report"
#define SSHOT_ENTITLEMENT_BOOTARG_FAIL "sshot-entitlement-refuse"

/* use single printable characters; these are in order of the stackshot syscall's checks */
enum stackshot_progress {
	STACKSHOT_NOT_ROOT = 'R',
	STACKSHOT_NOT_ENTITLED = 'E',
	STACKSHOT_PERMITTED = 'P',
	STACKSHOT_ATTEMPTED = 'A',
	STACKSHOT_SUCCEEDED = 'S',
};

CA_EVENT(stackshot_entitlement_report,
    CA_INT, sshot_count,
    CA_BOOL, sshot_refused,
    CA_BOOL, sshot_have_entitlement,
    CA_BOOL, sshot_fromtest,
    CA_STATIC_STRING(2), sshot_progress,
    CA_STATIC_STRING(CA_PROCNAME_LEN), sshot_pcomm,
    CA_STATIC_STRING(33), sshot_pname);

static thread_call_t sshot_entitlement_thread_call;

#define SSHOT_ENTITLEMENT_RECENT 16     /* track 16 recent violators */
struct stackshot_entitlement_report {
	uint64_t ser_lastev;
	uint32_t ser_count;
	command_t ser_pcomm;
	proc_name_t ser_pname;
	bool ser_have_entitlement;
	char ser_progress; /* from enum stackshot_progress */
#if DEVELOPMENT || DEBUG
	bool ser_test;
#endif
};
static LCK_GRP_DECLARE(sshot_report_lck_grp, "stackshot_entitlement_repot");
static LCK_MTX_DECLARE(sshot_report_lck, &sshot_report_lck_grp);
static struct stackshot_entitlement_report *sshot_report_recent[SSHOT_ENTITLEMENT_RECENT];
static bool sshot_report_batch_scheduled = false;
#if DEVELOPMENT || DEBUG
static uint32_t sshot_report_test_events = 0;
static uint64_t sshot_report_test_counts = 0;
#endif

static void
stackshot_entitlement_send_report(const struct stackshot_entitlement_report *ser)
{
	ca_event_t ca_event = CA_EVENT_ALLOCATE(stackshot_entitlement_report);
	CA_EVENT_TYPE(stackshot_entitlement_report) * ser_event = ca_event->data;
	ser_event->sshot_count = ser->ser_count;
	ser_event->sshot_refused = stackshot_entitlement_refuse;
#if DEVELOPMENT || DEBUG
	ser_event->sshot_fromtest = ser->ser_test;
#else
	ser_event->sshot_fromtest = false;
#endif
	ser_event->sshot_have_entitlement = ser->ser_have_entitlement;
	ser_event->sshot_progress[0] = ser->ser_progress;
	ser_event->sshot_progress[1] = '\0';
	static_assert(sizeof(ser_event->sshot_pcomm) == sizeof(ser->ser_pcomm), "correct sshot_pcomm/ser_pcomm sizing");
	strlcpy(ser_event->sshot_pcomm, ser->ser_pcomm, sizeof(ser->ser_pcomm));
	static_assert(sizeof(ser_event->sshot_pname) == sizeof(ser->ser_pname), "correct sshot_pcomm/ser_pcomm sizing");
	strlcpy(ser_event->sshot_pname, ser->ser_pname, sizeof(ser->ser_pname));
	CA_EVENT_SEND(ca_event);
}

static void
sshot_entitlement_schedule_batch(void)
{
	static const uint64_t analytics_period_ns = SSHOT_ANALYTICS_PERIOD_HOURS * 60 * 60 * NSEC_PER_SEC;
	uint64_t analytics_period_absolutetime;
	nanoseconds_to_absolutetime(analytics_period_ns, &analytics_period_absolutetime);

	thread_call_enter_delayed(sshot_entitlement_thread_call, analytics_period_absolutetime + mach_absolute_time());
}

__attribute__((always_inline))
static void
sshot_entitlement_copy_for_send(const struct stackshot_entitlement_report *src,
    struct stackshot_entitlement_report *dst)
{
	bcopy(src, dst, sizeof(*src));
#if DEVELOPMENT || DEBUG
	if (src->ser_test) {
		sshot_report_test_events++;
		sshot_report_test_counts += src->ser_count;
	}
#endif
}

#define SSHOT_ENTITLEMENT_REPORT_NORMAL       0
#define SSHOT_ENTITLEMENT_REPORT_TEST(x) ((int)((x) ?: 1)) // always non-zero
#define SSHOT_ENTITLEMENT_REPORT_TEST_OVERFLOW SSHOT_ENTITLEMENT_REPORT_TEST(-1)

static void
stackshot_entitlement_do_report(bool have_entitlement, enum stackshot_progress progress, int testval)
{
#pragma unused(testval)
#if DEVELOPMENT || DEBUG
	const bool from_test = (testval != SSHOT_ENTITLEMENT_REPORT_NORMAL);
#endif
	const struct proc *p = current_proc();
	struct stackshot_entitlement_report *ser = kalloc_data(sizeof(*ser), Z_WAITOK | Z_NOFAIL);
	struct stackshot_entitlement_report *tofree = NULL;
	struct stackshot_entitlement_report myser = {0};
	struct stackshot_entitlement_report oldser = {0};
	bool send_myser = false;
	bool send_oldser = false;

	myser.ser_count = 0;
	myser.ser_have_entitlement = have_entitlement;
	myser.ser_progress = (uint8_t)progress;
	static_assert(sizeof(p->p_comm) == sizeof(myser.ser_pcomm), "correct p_comm/ser_pcomm sizing");
	strlcpy(myser.ser_pcomm, p->p_comm, sizeof(myser.ser_pcomm));
	static_assert(sizeof(p->p_name) == sizeof(myser.ser_pname), "correct p_name/ser_pname sizing");
	strlcpy(myser.ser_pname, p->p_name, sizeof(myser.ser_pname));
#if DEVELOPMENT || DEBUG
	myser.ser_test = from_test;
	if (testval && (myser.ser_pcomm[0] != 0)) {
		myser.ser_pcomm[0] += (testval - 1);
	}
#endif
	lck_mtx_lock(&sshot_report_lck);
	// Search the table, looking for a match or a NULL slot.  While we search, track
	// the slot with the oldest use time as an eviction candidate, for LRU behavior

	struct stackshot_entitlement_report **tslot = NULL;
	bool match = false;
	for (int i = 0; i < SSHOT_ENTITLEMENT_RECENT; i++) {
		struct stackshot_entitlement_report **curp = &sshot_report_recent[i];
		struct stackshot_entitlement_report *cur = *curp;

		if (cur == NULL) {
			tslot = curp;
			break;
		}
		if (cur->ser_have_entitlement == myser.ser_have_entitlement &&
		    cur->ser_progress == myser.ser_progress &&
		    strncmp(cur->ser_pcomm, myser.ser_pcomm, sizeof(cur->ser_pcomm)) == 0 &&
		    strncmp(cur->ser_pname, myser.ser_pname, sizeof(cur->ser_pname)) == 0) {
			match = true;
			tslot = curp;
			break;
		}
		// not a match; track the slot with the oldest event to evict
		if (tslot == NULL ||
		    ((*tslot)->ser_lastev > cur->ser_lastev)) {
			tslot = curp;
		}
	}
	// Either we have:
	//   a match,
	//   no match and an empty (NULL) slot, or
	//   no match, a full table, and tslot points at the entry with the lowest count
	struct stackshot_entitlement_report *cur = NULL; // the entry to bump the count of
	if (match) {
		cur = *tslot;
		tofree = ser;
	} else {
		struct stackshot_entitlement_report *old = *tslot;
		if (old != NULL && old->ser_count > 0) {
			sshot_entitlement_copy_for_send(old, &oldser);
			send_oldser = true;
		}
		// fill it in and install it
		bcopy(&myser, ser, sizeof(*cur));
		cur = *tslot = ser;
		tofree = old;  // if there's an old one, free it after we drop the lock
	}
	// Now we have an installed structure, bump the count
	uint32_t ncount;
	uint32_t toadd = 1;
#if DEVELOPMENT || DEBUG
	if (testval == SSHOT_ENTITLEMENT_REPORT_TEST_OVERFLOW) {
		toadd = UINT32_MAX;
	}
#endif
	if (os_add_overflow(cur->ser_count, toadd, &ncount)) {
		// overflow; send the existing structure
		sshot_entitlement_copy_for_send(cur, &myser);
		send_myser = true;
		ncount = toadd;
	}
	cur->ser_lastev = mach_absolute_time();
	cur->ser_count = ncount;
#if DEVELOPMENT || DEBUG
	cur->ser_test = from_test;
#endif
	// see if we need to schedule the background task
	const bool batch_is_scheduled = sshot_report_batch_scheduled;
	if (!batch_is_scheduled) {
		sshot_report_batch_scheduled = true;
	}
	lck_mtx_unlock(&sshot_report_lck);
	//
	// we just bumped a counter in the structure, so schedule an analytics
	// dump in an hour if one isn't already scheduled.
	//
	// The flag gets cleared when the batch clears out the data, making the
	// next event reschedule immediately.
	if (!batch_is_scheduled) {
		sshot_entitlement_schedule_batch();
	}

	if (tofree != NULL) {
		kfree_data(tofree, sizeof(*tofree));
	}
	if (send_myser) {
		stackshot_entitlement_send_report(&myser);
	}
	if (send_oldser) {
		stackshot_entitlement_send_report(&oldser);
	}
}

static void
sshot_entitlement_send_batch(void *arg0, void *arg1)
{
#pragma unused(arg0, arg1)
	struct stackshot_entitlement_report *ser = kalloc_data(sizeof(*ser) * SSHOT_ENTITLEMENT_RECENT, Z_WAITOK | Z_NOFAIL);
	size_t count = 0;
	// Walk through the array, find non-zero counts and:
	//   * copy them into our local array for reporting, and
	//   * zeroing the counts.
	lck_mtx_lock(&sshot_report_lck);
	for (size_t i = 0; i < SSHOT_ENTITLEMENT_RECENT; i++) {
		struct stackshot_entitlement_report *cur = sshot_report_recent[i];
		if (cur == NULL || cur->ser_count == 0) {
			continue;
		}
		sshot_entitlement_copy_for_send(cur, &ser[count]);
		count++;
		cur->ser_count = 0;
	}
	sshot_report_batch_scheduled = false;
	lck_mtx_unlock(&sshot_report_lck);
	for (size_t i = 0; i < count; i++) {
		stackshot_entitlement_send_report(&ser[i]);
	}
}

#if DEVELOPMENT || DEBUG
/*
 * Manual trigger of a set of entitlement reports and the associated batch
 * processing for testing on dev/debug kernel.
 */
static int
sysctl_stackshot_entitlement_test SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int error, val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr) {
		return error;
	}
	static LCK_MTX_DECLARE(sshot_report_test_lck, &sshot_report_lck_grp);
	static bool sshot_report_test_active;
	// avoid multiple active tests
	lck_mtx_lock(&sshot_report_test_lck);
	if (sshot_report_test_active) {
		lck_mtx_unlock(&sshot_report_test_lck);
		return EBUSY;
	}
	sshot_report_test_active = true;
	lck_mtx_unlock(&sshot_report_test_lck);

	sshot_entitlement_send_batch(NULL, NULL); // flush out existing data
	sshot_report_test_events = 0;
	sshot_report_test_counts = 0;

	// fill with test events
	for (int idx = 0; idx < SSHOT_ENTITLEMENT_RECENT; idx++) {
		stackshot_entitlement_do_report(false, STACKSHOT_NOT_ENTITLED, SSHOT_ENTITLEMENT_REPORT_TEST(idx + 1));
	}
	sshot_entitlement_send_batch(NULL, NULL);
	const uint32_t post_batch = sshot_report_test_events;
	const uint64_t post_batch_counts = sshot_report_test_counts;

	// overflow test
	stackshot_entitlement_do_report(false, STACKSHOT_NOT_ENTITLED, SSHOT_ENTITLEMENT_REPORT_TEST_OVERFLOW);
	stackshot_entitlement_do_report(false, STACKSHOT_NOT_ENTITLED, SSHOT_ENTITLEMENT_REPORT_TEST_OVERFLOW);
	sshot_entitlement_send_batch(NULL, NULL);
	const uint32_t post_overflow = sshot_report_test_events - post_batch;
	const uint64_t post_overflow_counts = sshot_report_test_counts - post_batch_counts;

	os_log_error(OS_LOG_DEFAULT, "sysctl_stackshot_entitlement_test: made %d events, %d events sent, %d counts (both should == events)",
	    SSHOT_ENTITLEMENT_RECENT, post_batch, (int)post_batch_counts);
	os_log_error(OS_LOG_DEFAULT, "sysctl_stackshot_entitlement_test: overflow, %d events sent (expect 2), %llx counts (expect %llx)",
	    post_overflow, (long long)post_overflow_counts, 2 * (long long)UINT32_MAX);

	lck_mtx_lock(&sshot_report_test_lck);
	sshot_report_test_active = false;
	lck_mtx_unlock(&sshot_report_test_lck);

	if (post_batch != SSHOT_ENTITLEMENT_RECENT ||
	    post_batch_counts != SSHOT_ENTITLEMENT_RECENT ||
	    post_overflow != 2 ||
	    post_overflow_counts != 2 * (long long)UINT32_MAX) {
		os_log_error(OS_LOG_DEFAULT, "sysctl_stackshot_entitlement_test: failed");
		return EDEVERR;
	}

	os_log_error(OS_LOG_DEFAULT, "sysctl_stackshot_entitlement_test: success");
	return 0;
}
SYSCTL_PROC(_debug, OID_AUTO, stackshot_entitlement_send_batch,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0,
    &sysctl_stackshot_entitlement_test, "I", "");

/* Return current entitlement enforcement state. */
static int
sysctl_stackshot_entitlement_status SYSCTL_HANDLER_ARGS
{
	int return_value = ((stackshot_entitlement_report & 0xf) | (stackshot_entitlement_refuse ? 0x10 : 0));
	return SYSCTL_OUT(req, &return_value, sizeof(return_value));
}
SYSCTL_PROC(_kern, OID_AUTO, stackshot_entitlement_status,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED, 0, 0,
    &sysctl_stackshot_entitlement_status, "I", "");

#endif /* DEVELOPMENT || DEBUG */

__startup_func
static void
atboot_stackshot_entitlement(void)
{
	uint32_t boot_arg;
	if (PE_parse_boot_argn(SSHOT_ENTITLEMENT_BOOTARG_REPORT, &boot_arg, sizeof(boot_arg))) {
		/* clamp to valid values */
		boot_arg = (boot_arg <= STACKSHOT_REPORT_ALL ? boot_arg : STACKSHOT_REPORT_ALL);
		stackshot_entitlement_report = (uint8_t)boot_arg;
	}
	if (PE_parse_boot_argn(SSHOT_ENTITLEMENT_BOOTARG_FAIL, &boot_arg, sizeof(boot_arg))) {
		stackshot_entitlement_refuse = (boot_arg != 0);
	}
	sshot_entitlement_thread_call = thread_call_allocate_with_options(
		sshot_entitlement_send_batch, NULL, THREAD_CALL_PRIORITY_LOW, THREAD_CALL_OPTIONS_ONCE);
}
STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, atboot_stackshot_entitlement);


static int
sysctl_stackshot_stats SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	stackshot_stats_t stats;
	proc_t self = current_proc();

	/* root processes and non-root processes with the STATS entitlement can read this */
	if (suser(kauth_cred_get(), &self->p_acflag) != 0 &&
	    !IOCurrentTaskHasEntitlement(STACKSHOT_STATS_ENTITLEMENT)) {
		return EPERM;
	}

	if (req->newptr != USER_ADDR_NULL) {
		return EPERM;
	}
	if (req->oldptr == USER_ADDR_NULL) {
		req->oldidx = sizeof(stats);
		return 0;
	}
	extern void stackshot_get_timing(uint64_t *last_abs_start, uint64_t *last_abs_end, uint64_t *count, uint64_t *total_duration);
	stackshot_get_timing(&stats.ss_last_start, &stats.ss_last_end, &stats.ss_count, &stats.ss_duration);

	return SYSCTL_OUT(req, &stats, MIN(sizeof(stats), req->oldlen));
}

SYSCTL_PROC(_kern, OID_AUTO, stackshot_stats,
    CTLTYPE_STRUCT | CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_MASKED |
    CTLFLAG_KERN,
    NULL, 0, sysctl_stackshot_stats, "S,stackshot_stats",
    "Get stackshot statistics");

/*
 * Stackshot system calls
 */

#if CONFIG_TELEMETRY
extern kern_return_t stack_microstackshot(user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, int32_t *retval);
#endif /* CONFIG_TELEMETRY */
extern kern_return_t kern_stack_snapshot_with_reason(char* reason);
extern kern_return_t kern_stack_snapshot_internal(int stackshot_config_version, void *stackshot_config, size_t stackshot_config_size, boolean_t stackshot_from_user);

static int
stackshot_kern_return_to_bsd_error(kern_return_t kr)
{
	switch (kr) {
	case KERN_SUCCESS:
		return 0;
	case KERN_RESOURCE_SHORTAGE:
		/* could not allocate memory, or stackshot is actually bigger than
		 * SANE_TRACEBUF_SIZE */
		return ENOMEM;
	case KERN_INSUFFICIENT_BUFFER_SIZE:
	case KERN_NO_SPACE:
		/* ran out of buffer to write the stackshot.  Normally this error
		 * causes a larger buffer to be allocated in-kernel, rather than
		 * being returned to the user. */
		return ENOSPC;
	case KERN_NO_ACCESS:
		return EPERM;
	case KERN_MEMORY_PRESENT:
		return EEXIST;
	case KERN_NOT_SUPPORTED:
		return ENOTSUP;
	case KERN_NOT_IN_SET:
		/* requested existing buffer, but there isn't one. */
		return ENOENT;
	case KERN_ABORTED:
		/* kdp did not report an error, but also did not produce any data */
		return EINTR;
	case KERN_FAILURE:
		/* stackshot came across inconsistent data and needed to bail out */
		return EBUSY;
	case KERN_OPERATION_TIMED_OUT:
		/* debugger synchronization timed out */
		return ETIMEDOUT;
	default:
		return EINVAL;
	}
}

/*
 * stack_snapshot_with_config:	Obtains a coherent set of stack traces for specified threads on the sysem,
 *				tracing both kernel and user stacks where available. Allocates a buffer from the
 *				kernel and maps the buffer into the calling task's address space.
 *
 * Inputs:                      uap->stackshot_config_version - version of the stackshot config that is being passed
 *				uap->stackshot_config - pointer to the stackshot config
 *				uap->stackshot_config_size- size of the stackshot config being passed
 * Outputs:			EINVAL if there is a problem with the arguments
 *				EFAULT if we failed to copy in the arguments succesfully
 *				EPERM if the caller is not privileged
 *				ENOTSUP if the caller is passing a version of arguments that is not supported by the kernel
 *				(indicates libsyscall:kernel mismatch) or if the caller is requesting unsupported flags
 *				ENOENT if the caller is requesting an existing buffer that doesn't exist or if the
 *				requested PID isn't found
 *				ENOMEM if the kernel is unable to allocate enough memory to serve the request
 *				ENOSPC if there isn't enough space in the caller's address space to remap the buffer
 *				ESRCH if the target PID isn't found
 *				returns KERN_SUCCESS on success
 */
int
stack_snapshot_with_config(struct proc *p, struct stack_snapshot_with_config_args *uap, __unused int *retval)
{
	int error = 0;
	kern_return_t kr;
	const uint8_t report = stackshot_entitlement_report;
	const bool refuse = stackshot_entitlement_refuse;
	enum stackshot_progress progress = STACKSHOT_NOT_ROOT;
	bool has_entitlement = true;

	if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
		goto err;
	}
	progress = STACKSHOT_NOT_ENTITLED;

	if ((report != STACKSHOT_REPORT_NONE || refuse) &&
	    !IOCurrentTaskHasEntitlement(STACKSHOT_ENTITLEMENT)) {
		has_entitlement = false;
		if (refuse) {
			error = EPERM;
			goto err;
		}
	}
	progress = STACKSHOT_PERMITTED;

	if ((void*)uap->stackshot_config == NULL) {
		error = EINVAL;
		goto err;
	}

	switch (uap->stackshot_config_version) {
	case STACKSHOT_CONFIG_TYPE:
		if (uap->stackshot_config_size != sizeof(stackshot_config_t)) {
			error = EINVAL;
			break;
		}
		stackshot_config_t config;
		error = copyin(uap->stackshot_config, &config, sizeof(stackshot_config_t));
		if (error != KERN_SUCCESS) {
			error = EFAULT;
			break;
		}
		kr = kern_stack_snapshot_internal(uap->stackshot_config_version, &config, sizeof(stackshot_config_t), TRUE);
		error = stackshot_kern_return_to_bsd_error(kr);
		progress = (error == 0) ? STACKSHOT_SUCCEEDED : STACKSHOT_ATTEMPTED;
		break;
	default:
		error = ENOTSUP;
		break;
	}
err:
	if (report == STACKSHOT_REPORT_ALL || (report == STACKSHOT_REPORT_NO_ENT && !has_entitlement)) {
		stackshot_entitlement_do_report(has_entitlement, progress, SSHOT_ENTITLEMENT_REPORT_NORMAL);
	}
	return error;
}

#if CONFIG_TELEMETRY
/*
 * microstackshot:	Catch all system call for microstackshot related operations, including
 *			enabling/disabling both global and windowed microstackshots as well
 *			as retrieving windowed or global stackshots and the boot profile.
 * Inputs:              uap->tracebuf - address of the user space destination
 *			buffer
 *			uap->tracebuf_size - size of the user space trace buffer
 *			uap->flags - various flags
 * Outputs:		EPERM if the caller is not privileged
 *			EINVAL if the supplied mss_args is NULL, mss_args.tracebuf is NULL or mss_args.tracebuf_size is not sane
 *			ENOMEM if we don't have enough memory to satisfy the request
 *			*retval contains the number of bytes traced, if successful
 *			and -1 otherwise.
 */
int
microstackshot(struct proc *p, struct microstackshot_args *uap, int32_t *retval)
{
	int error = 0;
	kern_return_t kr;

	if ((error = suser(kauth_cred_get(), &p->p_acflag))) {
		return error;
	}

	kr = stack_microstackshot(uap->tracebuf, uap->tracebuf_size, uap->flags, retval);
	return stackshot_kern_return_to_bsd_error(kr);
}
#endif /* CONFIG_TELEMETRY */

/*
 * kern_stack_snapshot_with_reason:	Obtains a coherent set of stack traces for specified threads on the sysem,
 *					tracing both kernel and user stacks where available. Allocates a buffer from the
 *					kernel and stores the address of this buffer.
 *
 * Inputs:                              reason - the reason for triggering a stackshot (unused at the moment, but in the
 *						future will be saved in the stackshot)
 * Outputs:				EINVAL/ENOTSUP if there is a problem with the arguments
 *					EPERM if the caller doesn't pass at least one KERNEL stackshot flag
 *					ENOMEM if the kernel is unable to allocate enough memory to serve the request
 *					ESRCH if the target PID isn't found
 *					returns KERN_SUCCESS on success
 */
int
kern_stack_snapshot_with_reason(__unused char *reason)
{
	stackshot_config_t config;
	kern_return_t kr;

	config.sc_pid = -1;
	config.sc_flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS | STACKSHOT_SAVE_IN_KERNEL_BUFFER |
	    STACKSHOT_KCDATA_FORMAT | STACKSHOT_ENABLE_UUID_FAULTING | STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_THREAD_WAITINFO |
	    STACKSHOT_NO_IO_STATS | STACKSHOT_COLLECT_SHAREDCACHE_LAYOUT);
	config.sc_delta_timestamp = 0;
	config.sc_out_buffer_addr = 0;
	config.sc_out_size_addr = 0;

	kr = kern_stack_snapshot_internal(STACKSHOT_CONFIG_TYPE, &config, sizeof(stackshot_config_t), FALSE);
	return stackshot_kern_return_to_bsd_error(kr);
}
