/*-
 * Copyright (c) 2008-2010 Apple Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>

#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <kern/host.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>

#include <libkern/OSAtomic.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>

#include <security/audit/audit_bsd.h>
#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

#include <mach/host_priv.h>
#include <mach/host_special_ports.h>
#include <mach/audit_triggers_server.h>
#include <mach/audit_triggers_types.h>

#include <os/overflow.h>

extern void ipc_port_release_send(ipc_port_t port);

#if CONFIG_AUDIT
struct mhdr {
	size_t                   mh_size;
	au_malloc_type_t        *mh_type;
	u_long                   mh_magic;
	char                     mh_data[0];
};

/*
 * The lock group for the audit subsystem.
 */
static LCK_GRP_DECLARE(audit_lck_grp, "Audit");

#define AUDIT_MHMAGIC   0x4D656C53

/*
 * Initialize a condition variable.  Must be called before use.
 */
void
_audit_cv_init(struct cv *cvp, const char *desc)
{
	if (desc == NULL) {
		cvp->cv_description = "UNKNOWN";
	} else {
		cvp->cv_description = desc;
	}
	cvp->cv_waiters = 0;
}

/*
 *  Destory a condition variable.
 */
void
_audit_cv_destroy(struct cv *cvp)
{
	cvp->cv_description = NULL;
	cvp->cv_waiters = 0;
}

/*
 * Signal a condition variable, wakes up one waiting thread.
 */
void
_audit_cv_signal(struct cv *cvp)
{
	if (cvp->cv_waiters > 0) {
		wakeup_one((caddr_t)cvp);
		cvp->cv_waiters--;
	}
}

/*
 * Broadcast a signal to a condition variable.
 */
void
_audit_cv_broadcast(struct cv *cvp)
{
	if (cvp->cv_waiters > 0) {
		wakeup((caddr_t)cvp);
		cvp->cv_waiters = 0;
	}
}

/*
 * Wait on a condition variable. A cv_signal or cv_broadcast on the same
 * condition variable will resume the thread. It is recommended that the mutex
 * be held when cv_signal or cv_broadcast are called.
 */
void
_audit_cv_wait(struct cv *cvp, lck_mtx_t *mp, const char *desc)
{
	cvp->cv_waiters++;
	(void) msleep(cvp, mp, PZERO, desc, 0);
}

/*
 * Wait on a condition variable, allowing interruption by signals.  Return 0
 * if the thread was resumed with cv_signal or cv_broadcast, EINTR or
 * ERESTART if a signal was caught.  If ERESTART is returned the system call
 * should be restarted if possible.
 */
int
_audit_cv_wait_sig(struct cv *cvp, lck_mtx_t *mp, const char *desc)
{
	cvp->cv_waiters++;
	return msleep(cvp, mp, PSOCK | PCATCH, desc, 0);
}

/*
 * BSD Mutexes.
 */
void
#if DIAGNOSTIC
_audit_mtx_init(struct mtx *mp, const char *lckname)
#else
_audit_mtx_init(struct mtx *mp, __unused const char *lckname)
#endif
{
	mp->mtx_lock = lck_mtx_alloc_init(&audit_lck_grp, LCK_ATTR_NULL);
	KASSERT(mp->mtx_lock != NULL,
	    ("_audit_mtx_init: Could not allocate a mutex."));
#if DIAGNOSTIC
	strlcpy(mp->mtx_name, lckname, AU_MAX_LCK_NAME);
#endif
}

void
_audit_mtx_destroy(struct mtx *mp)
{
	if (mp->mtx_lock) {
		lck_mtx_free(mp->mtx_lock, &audit_lck_grp);
		mp->mtx_lock = NULL;
	}
}

/*
 * BSD rw locks.
 */
void
#if DIAGNOSTIC
_audit_rw_init(struct rwlock *lp, const char *lckname)
#else
_audit_rw_init(struct rwlock *lp, __unused const char *lckname)
#endif
{
	lp->rw_lock = lck_rw_alloc_init(&audit_lck_grp, LCK_ATTR_NULL);
	KASSERT(lp->rw_lock != NULL,
	    ("_audit_rw_init: Could not allocate a rw lock."));
#if DIAGNOSTIC
	strlcpy(lp->rw_name, lckname, AU_MAX_LCK_NAME);
#endif
}

void
_audit_rw_destroy(struct rwlock *lp)
{
	if (lp->rw_lock) {
		lck_rw_free(lp->rw_lock, &audit_lck_grp);
		lp->rw_lock = NULL;
	}
}
/*
 * Wait on a condition variable in a continuation (i.e. yield kernel stack).
 * A cv_signal or cv_broadcast on the same condition variable will cause
 * the thread to be scheduled.
 */
int
_audit_cv_wait_continuation(struct cv *cvp, lck_mtx_t *mp, thread_continue_t function)
{
	int status = KERN_SUCCESS;

	cvp->cv_waiters++;
	assert_wait(cvp, THREAD_UNINT);
	lck_mtx_unlock(mp);

	status = thread_block(function);

	/* should not be reached, but just in case, re-lock */
	lck_mtx_lock(mp);

	return status;
}

/*
 * Simple recursive lock.
 */
void
#if DIAGNOSTIC
_audit_rlck_init(struct rlck *lp, const char *lckname)
#else
_audit_rlck_init(struct rlck *lp, __unused const char *lckname)
#endif
{
	lp->rl_mtx = lck_mtx_alloc_init(&audit_lck_grp, LCK_ATTR_NULL);
	KASSERT(lp->rl_mtx != NULL,
	    ("_audit_rlck_init: Could not allocate a recursive lock."));
#if DIAGNOSTIC
	strlcpy(lp->rl_name, lckname, AU_MAX_LCK_NAME);
#endif
	lp->rl_thread = 0;
	lp->rl_recurse = 0;
}

/*
 * Recursive lock.  Allow same thread to recursively lock the same lock.
 */
void
_audit_rlck_lock(struct rlck *lp)
{
	if (lp->rl_thread == current_thread()) {
		OSAddAtomic(1, &lp->rl_recurse);
		KASSERT(lp->rl_recurse < 10000,
		    ("_audit_rlck_lock: lock nested too deep."));
	} else {
		lck_mtx_lock(lp->rl_mtx);
		lp->rl_thread = current_thread();
		lp->rl_recurse = 1;
	}
}

/*
 * Recursive unlock.  It should be the same thread that does the unlock.
 */
void
_audit_rlck_unlock(struct rlck *lp)
{
	KASSERT(lp->rl_thread == current_thread(),
	    ("_audit_rlck_unlock(): Don't own lock."));

	/* Note: OSAddAtomic returns old value. */
	if (OSAddAtomic(-1, &lp->rl_recurse) == 1) {
		lp->rl_thread = 0;
		lck_mtx_unlock(lp->rl_mtx);
	}
}

void
_audit_rlck_destroy(struct rlck *lp)
{
	if (lp->rl_mtx) {
		lck_mtx_free(lp->rl_mtx, &audit_lck_grp);
		lp->rl_mtx = NULL;
	}
}

/*
 * Recursive lock assert.
 */
void
_audit_rlck_assert(struct rlck *lp, u_int assert)
{
	thread_t cthd = current_thread();

	if (assert == LCK_MTX_ASSERT_OWNED && lp->rl_thread == cthd) {
		panic("recursive lock (%p) not held by this thread (%p).",
		    lp, cthd);
	}
	if (assert == LCK_MTX_ASSERT_NOTOWNED && lp->rl_thread != 0) {
		panic("recursive lock (%p) held by thread (%p).",
		    lp, cthd);
	}
}

/*
 * Simple sleep lock.
 */
void
#if DIAGNOSTIC
_audit_slck_init(struct slck *lp, const char *lckname)
#else
_audit_slck_init(struct slck *lp, __unused const char *lckname)
#endif
{
	lp->sl_mtx = lck_mtx_alloc_init(&audit_lck_grp, LCK_ATTR_NULL);
	KASSERT(lp->sl_mtx != NULL,
	    ("_audit_slck_init: Could not allocate a sleep lock."));
#if DIAGNOSTIC
	strlcpy(lp->sl_name, lckname, AU_MAX_LCK_NAME);
#endif
	lp->sl_locked = 0;
	lp->sl_waiting = 0;
}

/*
 * Sleep lock lock.  The 'intr' flag determines if the lock is interruptible.
 * If 'intr' is true then signals or other events can interrupt the sleep lock.
 */
wait_result_t
_audit_slck_lock(struct slck *lp, int intr)
{
	wait_result_t res = THREAD_AWAKENED;

	lck_mtx_lock(lp->sl_mtx);
	while (lp->sl_locked && res == THREAD_AWAKENED) {
		lp->sl_waiting = 1;
		res = lck_mtx_sleep(lp->sl_mtx, LCK_SLEEP_DEFAULT,
		    (event_t) lp, (intr) ? THREAD_INTERRUPTIBLE : THREAD_UNINT);
	}
	if (res == THREAD_AWAKENED) {
		lp->sl_locked = 1;
	}
	lck_mtx_unlock(lp->sl_mtx);

	return res;
}

/*
 * Sleep lock unlock.  Wake up all the threads waiting for this lock.
 */
void
_audit_slck_unlock(struct slck *lp)
{
	lck_mtx_lock(lp->sl_mtx);
	lp->sl_locked = 0;
	if (lp->sl_waiting) {
		lp->sl_waiting = 0;

		/* Wake up *all* sleeping threads. */
		wakeup((event_t) lp);
	}
	lck_mtx_unlock(lp->sl_mtx);
}

/*
 * Sleep lock try.  Don't sleep if it doesn't get the lock.
 */
int
_audit_slck_trylock(struct slck *lp)
{
	int result;

	lck_mtx_lock(lp->sl_mtx);
	result = !lp->sl_locked;
	if (result) {
		lp->sl_locked = 1;
	}
	lck_mtx_unlock(lp->sl_mtx);

	return result;
}

/*
 * Sleep lock assert.
 */
void
_audit_slck_assert(struct slck *lp, u_int assert)
{
	if (assert == LCK_MTX_ASSERT_OWNED && lp->sl_locked == 0) {
		panic("sleep lock (%p) not held.", lp);
	}
	if (assert == LCK_MTX_ASSERT_NOTOWNED && lp->sl_locked == 1) {
		panic("sleep lock (%p) held.", lp);
	}
}

void
_audit_slck_destroy(struct slck *lp)
{
	if (lp->sl_mtx) {
		lck_mtx_free(lp->sl_mtx, &audit_lck_grp);
		lp->sl_mtx = NULL;
	}
}

/*
 * XXXss - This code was taken from bsd/netinet6/icmp6.c.  Maybe ppsratecheck()
 * should be made global in icmp6.c.
 */
#ifndef timersub
#define timersub(tvp, uvp, vvp)                                         \
	do {                                                            \
	        (vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;          \
	        (vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;       \
	        if ((vvp)->tv_usec < 0) {                               \
	                (vvp)->tv_sec--;                                \
	                (vvp)->tv_usec += 1000000;                      \
	        }                                                       \
	} while (0)
#endif

/*
 * Packets (or events) per second limitation.
 */
int
_audit_ppsratecheck(struct timeval *lasttime, int *curpps, int maxpps)
{
	struct timeval tv, delta;
	int rv;

	microtime(&tv);

	timersub(&tv, lasttime, &delta);

	/*
	 * Check for 0,0 so that the message will be seen at least once.
	 * If more than one second has passed since the last update of
	 * lasttime, reset the counter.
	 *
	 * we do increment *curpps even in *curpps < maxpps case, as some may
	 * try to use *curpps for stat purposes as well.
	 */
	if ((lasttime->tv_sec == 0 && lasttime->tv_usec == 0) ||
	    delta.tv_sec >= 1) {
		*lasttime = tv;
		*curpps = 0;
		rv = 1;
	} else if (maxpps < 0) {
		rv = 1;
	} else if (*curpps < maxpps) {
		rv = 1;
	} else {
		rv = 0;
	}
	if (*curpps + 1 > 0) {
		*curpps = *curpps + 1;
	}

	return rv;
}

int
audit_send_trigger(unsigned int trigger)
{
	mach_port_t audit_port;
	int error;

	error = host_get_audit_control_port(host_priv_self(), &audit_port);
	if (error == KERN_SUCCESS && audit_port != MACH_PORT_NULL) {
		(void)audit_triggers(audit_port, trigger);
		ipc_port_release_send(audit_port);
		return 0;
	} else {
		printf("Cannot get audit control port\n");
		return error;
	}
}

int
audit_send_analytics(char* signing_id, char* process_name)
{
	mach_port_t audit_port;
	int error;

	error = host_get_audit_control_port(host_priv_self(), &audit_port);
	if (error == KERN_SUCCESS && audit_port != MACH_PORT_NULL) {
		(void)audit_analytics(audit_port, signing_id, process_name);
		ipc_port_release_send(audit_port);
		return 0;
	} else {
		printf("Cannot get audit control port for analytics \n");
		return error;
	}
}

#endif /* CONFIG_AUDIT */
