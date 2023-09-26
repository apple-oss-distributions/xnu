/*
 * Copyright (c) 2015-2022 Apple Inc. All rights reserved.
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

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <sys/kdebug.h>
#include <mach/thread_act.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>

extern kern_return_t thread_terminate(thread_t);

static void nx_netif_mit_reset_interval(struct nx_netif_mit *);
static void nx_netif_mit_set_start_interval(struct nx_netif_mit *);
static uint32_t nx_netif_mit_update_interval(struct nx_netif_mit *, boolean_t);
static void nx_netif_mit_thread_func(void *, wait_result_t);
static void nx_netif_mit_thread_cont(void *, wait_result_t);
static void nx_netif_mit_s_thread_cont(void *, wait_result_t);
static void nx_netif_mit_stats(struct __kern_channel_ring *, uint64_t,
    uint64_t);

/* mitigation intervals in micro seconds */
#define NETIF_BUSY_MIT_DELAY    (100)

static uint32_t netif_busy_mit_delay = NETIF_BUSY_MIT_DELAY;

#define MIT_EWMA(old, new, gdecay, sdecay) do {                         \
	uint32_t _avg;                                                  \
	if ((_avg = (old)) > 0) {                                       \
	        uint32_t _d = ((new) > _avg) ? gdecay : sdecay;         \
	        _avg = (((_avg << (_d)) - _avg) + (new)) >> (_d);       \
	} else {                                                        \
	        _avg = (new);                                           \
	}                                                               \
	(old) = _avg;                                                   \
} while (0)

/*
 * Larger decay factor results in slower reaction.  Each value is ilog2
 * of EWMA decay rate; one for growth and another for shrink.  The two
 * decay factors chosen are such that we reach quickly to shrink, and
 * slowly to grow.  Growth and shrink are relevant to the mitigation
 * delay interval.
 */
#define NETIF_AD_MIT_GDECAY     3       /* ilog2(8) */
static uint32_t netif_ad_mit_gdecay = NETIF_AD_MIT_GDECAY;

#define NETIF_AD_MIT_SDECAY     2       /* ilog2(4) */
static uint32_t netif_ad_mit_sdecay = NETIF_AD_MIT_SDECAY;

#define NETIF_MIT_MODE_HOLDTIME_MIN     (1ULL * 1000 * 1000)    /* 1 ms */
#define NETIF_MIT_MODE_HOLDTIME         (1000ULL * 1000 * 1000) /* 1 sec */
static uint64_t netif_mit_mode_holdtime = NETIF_MIT_MODE_HOLDTIME;

#define NETIF_MIT_SAMPLETIME_MIN        (1ULL * 1000 * 1000)    /* 1 ms */
#define NETIF_MIT_SAMPLETIME            (10ULL * 1000 * 1000)   /* 10 ms */
static uint64_t netif_mit_sample_holdtime = NETIF_MIT_SAMPLETIME;

/*
 * These numbers are based off 10ms netif_mit_sample_holdtime;
 * changing the hold time will require recomputing them.
 */
#if (DEVELOPMENT || DEBUG)
static struct mit_cfg_tbl mit_cfg_tbl_native[] = {
#else /* !DEVELOPMENT && !DEBUG */
static const struct mit_cfg_tbl mit_cfg_tbl_native[] = {
#endif /* !DEVELOPMENT && !DEBUG */
	{ .cfg_plowat = 10, .cfg_phiwat = 60, .cfg_blowat = 4000,
	  .cfg_bhiwat = 6000, .cfg_ival = 100 },
	{ .cfg_plowat = 40, .cfg_phiwat = 100, .cfg_blowat = 5000,
	  .cfg_bhiwat = 300000, .cfg_ival = 300 },
	{ .cfg_plowat = 80, .cfg_phiwat = 200, .cfg_blowat = 100000,
	  .cfg_bhiwat = 300000, .cfg_ival = 500 },
	{ .cfg_plowat = 220, .cfg_phiwat = 240, .cfg_blowat = 330000,
	  .cfg_bhiwat = 375000, .cfg_ival = 1000 },
	{ .cfg_plowat = 250, .cfg_phiwat = 2000, .cfg_blowat = 450000,
	  .cfg_bhiwat = 30000000, .cfg_ival = 200 },
};

#if (DEVELOPMENT || DEBUG)
static struct mit_cfg_tbl mit_cfg_tbl_compat[] = {
#else /* !DEVELOPMENT && !DEBUG */
static const struct mit_cfg_tbl mit_cfg_tbl_compat[] = {
#endif /* !DEVELOPMENT && !DEBUG */
	{ .cfg_plowat = 10, .cfg_phiwat = 60, .cfg_blowat = 4000,
	  .cfg_bhiwat = 6000, .cfg_ival = 100 },
	{ .cfg_plowat = 40, .cfg_phiwat = 100, .cfg_blowat = 5000,
	  .cfg_bhiwat = 300000, .cfg_ival = 300 },
	{ .cfg_plowat = 80, .cfg_phiwat = 200, .cfg_blowat = 100000,
	  .cfg_bhiwat = 300000, .cfg_ival = 500 },
	{ .cfg_plowat = 220, .cfg_phiwat = 240, .cfg_blowat = 330000,
	  .cfg_bhiwat = 375000, .cfg_ival = 1000 },
	{ .cfg_plowat = 250, .cfg_phiwat = 2000, .cfg_blowat = 450000,
	  .cfg_bhiwat = 3000000, .cfg_ival = 200 },
};

#if (DEVELOPMENT || DEBUG)
static struct mit_cfg_tbl mit_cfg_tbl_native_cellular[] = {
#else /* !DEVELOPMENT && !DEBUG */
static const struct mit_cfg_tbl mit_cfg_tbl_native_cellular[] = {
#endif /* !DEVELOPMENT && !DEBUG */
	{ .cfg_plowat = 10, .cfg_phiwat = 40, .cfg_blowat = 4000,
	  .cfg_bhiwat = 6000, .cfg_ival = 300 },
	{ .cfg_plowat = 20, .cfg_phiwat = 60, .cfg_blowat = 5000,
	  .cfg_bhiwat = 150000, .cfg_ival = 500 },
	{ .cfg_plowat = 40, .cfg_phiwat = 80, .cfg_blowat = 80000,
	  .cfg_bhiwat = 200000, .cfg_ival = 700 },
	{ .cfg_plowat = 60, .cfg_phiwat = 250, .cfg_blowat = 150000,
	  .cfg_bhiwat = 375000, .cfg_ival = 1500 },
	{ .cfg_plowat = 260, .cfg_phiwat = 2000, .cfg_blowat = 450000,
	  .cfg_bhiwat = 3000000, .cfg_ival = 400 },
};

#if (DEVELOPMENT || DEBUG)
static int sysctl_mit_mode_holdtime SYSCTL_HANDLER_ARGS;
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, busy_mit_delay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_busy_mit_delay,
    NETIF_BUSY_MIT_DELAY, "");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, ad_mit_gdecay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_ad_mit_gdecay, NETIF_AD_MIT_GDECAY, "");
SYSCTL_UINT(_kern_skywalk_netif, OID_AUTO, ad_mit_sdecay,
    CTLFLAG_RW | CTLFLAG_LOCKED, &netif_ad_mit_sdecay, NETIF_AD_MIT_SDECAY, "");
SYSCTL_PROC(_kern_skywalk_netif, OID_AUTO, ad_mit_freeze,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED, &netif_mit_mode_holdtime,
    NETIF_MIT_MODE_HOLDTIME, sysctl_mit_mode_holdtime, "Q", "");
#endif /* !DEVELOPMENT && !DEBUG */

void
nx_netif_mit_init(struct nx_netif *nif, const struct ifnet *ifp,
    struct nx_netif_mit *mit, struct __kern_channel_ring *kr,
    boolean_t simple)
{
#pragma unused(nif)
	thread_precedence_policy_data_t info;
	__unused kern_return_t kret;
	char oid_name[24];

	_CASSERT(sizeof(mit_cfg_tbl_native_cellular) <=
	    sizeof(((struct nx_netif_mit *)0)->mit_tbl));

	lck_spin_init(&mit->mit_lock, kr->ckr_qlock_group, &channel_lock_attr);

	if (kr->ckr_tx == NR_TX) {
		if (simple) {
			(void) snprintf(mit->mit_name, sizeof(mit->mit_name),
			    "skywalk_%s_tx_%u", ifp->if_xname, kr->ckr_ring_id);
		} else {
			(void) snprintf(mit->mit_name, sizeof(mit->mit_name),
			    "skywalk_mit_%s_tx_%u", ifp->if_xname,
			    kr->ckr_ring_id);
		}
		(void) snprintf(oid_name, sizeof(oid_name),
		    "tx_%u", kr->ckr_ring_id);
	} else {
		if (simple) {
			(void) snprintf(mit->mit_name, sizeof(mit->mit_name),
			    "skywalk_%s_rx_%u", ifp->if_xname, kr->ckr_ring_id);
		} else {
			(void) snprintf(mit->mit_name, sizeof(mit->mit_name),
			    "skywalk_mit_%s_rx_%u", ifp->if_xname,
			    kr->ckr_ring_id);
		}
		(void) snprintf(oid_name, sizeof(oid_name),
		    "rx_%u", kr->ckr_ring_id);
	}

	mit->mit_ckr = kr;
	mit->mit_ckr->ckr_mit = mit;
	mit->mit_interval = 0;
	mit->mit_netif_ifp = ifp;

	if ((ifp->if_eflags & IFEF_SKYWALK_NATIVE) && (ifp->if_family ==
	    IFNET_FAMILY_CELLULAR)) {
		bcopy(mit_cfg_tbl_native_cellular,
		    (void *)__DECONST(struct mit_cfg_tbl *, mit->mit_tbl),
		    sizeof(mit_cfg_tbl_native_cellular));
		mit->mit_cfg_idx_max = sizeof(mit_cfg_tbl_native_cellular) /
		    sizeof(*mit->mit_cfg);
	} else if (ifp->if_eflags & IFEF_SKYWALK_NATIVE) {
		bcopy(mit_cfg_tbl_native,
		    (void *)__DECONST(struct mit_cfg_tbl *, mit->mit_tbl),
		    sizeof(mit->mit_tbl));
		mit->mit_cfg_idx_max = sizeof(mit_cfg_tbl_native) /
		    sizeof(*mit->mit_cfg);
	} else {
		bcopy(mit_cfg_tbl_compat,
		    (void *)__DECONST(struct mit_cfg_tbl *, mit->mit_tbl),
		    sizeof(mit->mit_tbl));
		mit->mit_cfg_idx_max = sizeof(mit_cfg_tbl_compat) /
		    sizeof(*mit->mit_cfg);
	}
	VERIFY(mit->mit_cfg_idx_max > 0);
	VERIFY(mit->mit_cfg_idx_max <= NETIF_MIT_CFG_TBL_MAX_CFG);

	if (ifp->if_rx_mit_ival != 0) {
		mit->mit_tbl[0].cfg_ival = ifp->if_rx_mit_ival;
		SK_D("mit interval updated: %s cfg %u ival %u",
		    mit->mit_name, 0, mit->mit_tbl[0].cfg_ival);
	}

	net_timerclear(&mit->mit_mode_holdtime);
	net_timerclear(&mit->mit_mode_lasttime);
	net_timerclear(&mit->mit_sample_time);
	net_timerclear(&mit->mit_sample_lasttime);
	net_timerclear(&mit->mit_start_time);

	net_nsectimer(&netif_mit_mode_holdtime, &mit->mit_mode_holdtime);
	net_nsectimer(&netif_mit_sample_holdtime, &mit->mit_sample_time);

	/* initialize mode and params */
	nx_netif_mit_reset_interval(mit);
	VERIFY(mit->mit_cfg != NULL && mit->mit_cfg_idx < mit->mit_cfg_idx_max);
	mit->mit_flags = NETIF_MITF_INITIALIZED;
	if (simple) {
		/*
		 * Simple mitigation where we don't collect any statistics
		 * at all, and therefore don't want to register the ring's
		 * ckr_netif_mit_stats() callback.
		 */
		mit->mit_flags |= NETIF_MITF_SIMPLE;
		ASSERT(kr->ckr_netif_mit_stats == NULL);
	} else {
		/*
		 * Regular mitigation where we collect stats and use them
		 * for determining the delay between wakeups; initialize
		 * the ring's ckr_netif_mit_stats() callback.
		 */
		kr->ckr_netif_mit_stats = nx_netif_mit_stats;
	}

	if (kernel_thread_start(nx_netif_mit_thread_func, mit,
	    &mit->mit_thread) != KERN_SUCCESS) {
		panic_plain("%s: can't create thread", mit->mit_name);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	/* this must not fail */
	VERIFY(mit->mit_thread != NULL);

	/* wait until nx_netif_mit_thread_func() is ready */
	MIT_SPIN_LOCK(mit);
	while (!(mit->mit_flags & NETIF_MITF_READY)) {
		(void) assert_wait(&mit->mit_thread, THREAD_UNINT);
		MIT_SPIN_UNLOCK(mit);
		(void) thread_block(THREAD_CONTINUE_NULL);
		MIT_SPIN_LOCK(mit);
	}
	MIT_SPIN_UNLOCK(mit);

	bzero(&info, sizeof(info));
	info.importance = 0;
	kret = thread_policy_set(mit->mit_thread, THREAD_PRECEDENCE_POLICY,
	    (thread_policy_t)&info, THREAD_PRECEDENCE_POLICY_COUNT);
	ASSERT(kret == KERN_SUCCESS);

#if (DEVELOPMENT || DEBUG)
	/* register mit sysctl skoid */
	skoid_create(&mit->mit_skoid, SKOID_DNODE(nif->nif_skoid), oid_name, 0);
	skoid_add_uint(&mit->mit_skoid, "interval", CTLFLAG_RW,
	    &mit->mit_interval);
	struct skoid *skoid = &mit->mit_skoid;
	struct mit_cfg_tbl *t;
#define MIT_ADD_SKOID(_i)       \
	t = &mit->mit_tbl[_i];  \
	skoid_add_uint(skoid, #_i"_plowat", CTLFLAG_RW, &t->cfg_plowat); \
	skoid_add_uint(skoid, #_i"_phiwat", CTLFLAG_RW, &t->cfg_phiwat);  \
	skoid_add_uint(skoid, #_i"_blowat", CTLFLAG_RW, &t->cfg_blowat);  \
	skoid_add_uint(skoid, #_i"_bhiwat", CTLFLAG_RW, &t->cfg_bhiwat);\
	skoid_add_uint(skoid, #_i"_ival", CTLFLAG_RW, &t->cfg_ival);
	MIT_ADD_SKOID(0);
	MIT_ADD_SKOID(1);
	MIT_ADD_SKOID(2);
	MIT_ADD_SKOID(3);
	MIT_ADD_SKOID(4);
	_CASSERT(NETIF_MIT_CFG_TBL_MAX_CFG == 5);
#endif /* !DEVELOPMENT && !DEBUG */
}

__attribute__((always_inline))
static inline void
nx_netif_mit_reset_interval(struct nx_netif_mit *mit)
{
	(void) nx_netif_mit_update_interval(mit, TRUE);
}

__attribute__((always_inline))
static inline void
nx_netif_mit_set_start_interval(struct nx_netif_mit *mit)
{
	nanouptime(&mit->mit_start_time);
}

__attribute__((always_inline))
static inline uint32_t
nx_netif_mit_update_interval(struct nx_netif_mit *mit, boolean_t reset)
{
	struct timespec now, delta;
	uint64_t r;
	uint32_t i;

	nanouptime(&now);
	net_timersub(&now, &mit->mit_sample_lasttime, &delta);

	/* CSTYLED */
	if ((net_timercmp(&delta, &mit->mit_mode_holdtime, >)) || reset) {
		mit_mode_t mode = (mit->mit_flags & NETIF_MITF_SIMPLE) ?
		    MIT_MODE_SIMPLE : MIT_MODE_ADVANCED_STATIC;

		/* if we haven't updated stats in a while, reset it back */
		SK_DF(SK_VERB_NETIF_MIT, "%s: resetting [mode %u->%u]",
		    mit->mit_name, mit->mit_mode, mode);

		mit->mit_mode = mode;
		mit->mit_cfg_idx = 0;
		mit->mit_cfg = &mit->mit_tbl[mit->mit_cfg_idx];
		mit->mit_packets_avg = 0;
		mit->mit_bytes_avg = 0;
	}

	/* calculate work duration (since last start work time) */
	if (net_timerisset(&mit->mit_start_time)) {
		net_timersub(&now, &mit->mit_start_time, &delta);
		net_timerusec(&delta, &r);
	} else {
		r = 0;
	}

	switch (mit->mit_mode) {
	case MIT_MODE_SIMPLE:
		i = 0;
		break;

	case MIT_MODE_ADVANCED_STATIC:
		i = mit->mit_interval;
		break;

	case MIT_MODE_ADVANCED_DYNAMIC:
		i = mit->mit_cfg->cfg_ival;
		break;
	}

	/*
	 * The idea here is to return the effective delay interval that
	 * causes each work phase to begin at the desired cadence, at
	 * the minimum.
	 */
	if (__probable(r != 0)) {
		if (__probable(i > r)) {
			i -= r;
		} else {
			/* bump up cfg_idx perhaps? */
			i = 0;
		}
	}

	return i;
}

void
nx_netif_mit_cleanup(struct nx_netif_mit *mit)
{
	if (mit->mit_thread != THREAD_NULL) {
		ASSERT(mit->mit_flags & NETIF_MITF_INITIALIZED);

		/* signal thread to begin self-termination */
		MIT_SPIN_LOCK(mit);
		mit->mit_flags |= NETIF_MITF_TERMINATING;
		(void) thread_wakeup_thread((caddr_t)&mit->mit_flags,
		    mit->mit_thread);
		MIT_SPIN_UNLOCK(mit);

		/* and wait for thread to terminate */
		MIT_SPIN_LOCK(mit);
		while (!(mit->mit_flags & NETIF_MITF_TERMINATED)) {
			(void) assert_wait(&mit->mit_flags, THREAD_UNINT);
			MIT_SPIN_UNLOCK(mit);
			(void) thread_block(THREAD_CONTINUE_NULL);
			MIT_SPIN_LOCK(mit);
		}
		ASSERT(mit->mit_flags & NETIF_MITF_TERMINATED);
		MIT_SPIN_UNLOCK(mit);
		mit->mit_thread = THREAD_NULL;
	}
	ASSERT(mit->mit_thread == THREAD_NULL);
	lck_spin_destroy(&mit->mit_lock, mit->mit_ckr->ckr_qlock_group);

	mit->mit_ckr->ckr_mit = NULL;
	mit->mit_ckr = NULL;
	mit->mit_netif_ifp = NULL;
	mit->mit_flags &= ~NETIF_MITF_INITIALIZED;

	net_timerclear(&mit->mit_mode_holdtime);
	net_timerclear(&mit->mit_mode_lasttime);
	net_timerclear(&mit->mit_sample_time);
	net_timerclear(&mit->mit_sample_lasttime);
	net_timerclear(&mit->mit_start_time);

#if (DEVELOPMENT || DEBUG)
	skoid_destroy(&mit->mit_skoid);
#endif /* !DEVELOPMENT && !DEBUG */
}

int
nx_netif_mit_tx_intr(struct __kern_channel_ring *kr, struct proc *p,
    uint32_t flags, uint32_t *work_done)
{
	struct nexus_netif_adapter *nifna =
	    (struct nexus_netif_adapter *)KRNA(kr);
	struct netif_stats *nifs =
	    &NX_NETIF_PRIVATE(KRNA(kr)->na_nx)->nif_stats;

	ASSERT(kr->ckr_tx == NR_TX);
	STATS_INC(nifs, NETIF_STATS_TX_IRQ);

	/*
	 * If mitigation is not enabled for this kring, we're done; otherwise,
	 * signal the thread that there is work to do, unless it's terminating.
	 */
	if (__probable(nifna->nifna_tx_mit == NULL)) {
		(void) nx_netif_common_intr(kr, p, flags, work_done);
	} else {
		struct nx_netif_mit *mit =
		    &nifna->nifna_tx_mit[kr->ckr_ring_id];
		ASSERT(mit->mit_flags & NETIF_MITF_INITIALIZED);
		MIT_SPIN_LOCK(mit);
		mit->mit_requests++;
		if (!(mit->mit_flags & (NETIF_MITF_RUNNING |
		    NETIF_MITF_TERMINATING | NETIF_MITF_TERMINATED))) {
			(void) thread_wakeup_thread((caddr_t)&mit->mit_flags,
			    mit->mit_thread);
		}
		MIT_SPIN_UNLOCK(mit);
	}

	return 0;
}

int
nx_netif_mit_rx_intr(struct __kern_channel_ring *kr, struct proc *p,
    uint32_t flags, uint32_t *work_done)
{
	struct nexus_netif_adapter *nifna =
	    (struct nexus_netif_adapter *)KRNA(kr);
	struct netif_stats *nifs =
	    &NX_NETIF_PRIVATE(KRNA(kr)->na_nx)->nif_stats;

	KDBG((SK_KTRACE_NETIF_MIT_RX_INTR | DBG_FUNC_START), SK_KVA(kr));

	ASSERT(kr->ckr_tx == NR_RX);
	STATS_INC(nifs, NETIF_STATS_RX_IRQ);

	/*
	 * If mitigation is enabled for this kring, signal the thread that there
	 * is work to do, unless it's terminating.  Otherwise, we're done.
	 */
	if (__improbable(nifna->nifna_rx_mit != NULL)) {
		struct nx_netif_mit *mit =
		    &nifna->nifna_rx_mit[kr->ckr_ring_id];
		ASSERT(mit->mit_flags & NETIF_MITF_INITIALIZED);
		MIT_SPIN_LOCK(mit);
		mit->mit_requests++;
		if (!(mit->mit_flags & (NETIF_MITF_RUNNING |
		    NETIF_MITF_TERMINATING | NETIF_MITF_TERMINATED))) {
			(void) thread_wakeup_thread((caddr_t)&mit->mit_flags,
			    mit->mit_thread);
		}
		MIT_SPIN_UNLOCK(mit);
	} else {
		(void) nx_netif_common_intr(kr, p, flags, work_done);
	}

	KDBG((SK_KTRACE_NETIF_MIT_RX_INTR | DBG_FUNC_END), SK_KVA(kr));

	return 0;
}

__attribute__((noreturn))
static void
nx_netif_mit_thread_func(void *v, wait_result_t w)
{
#pragma unused(w)
	struct nx_netif_mit *mit = v;

	ASSERT(mit->mit_thread == current_thread());
	thread_set_thread_name(current_thread(), mit->mit_name);

	MIT_SPIN_LOCK(mit);
	VERIFY(!(mit->mit_flags & (NETIF_MITF_READY | NETIF_MITF_RUNNING)));
	/* tell nx_netif_mit_init() to proceed */
	mit->mit_flags |= NETIF_MITF_READY;
	wakeup((caddr_t)&mit->mit_thread);
	(void) assert_wait(&mit->mit_flags, THREAD_UNINT);
	MIT_SPIN_UNLOCK(mit);
	if (mit->mit_flags & NETIF_MITF_SIMPLE) {
		(void) thread_block_parameter(nx_netif_mit_s_thread_cont, mit);
	} else {
		(void) thread_block_parameter(nx_netif_mit_thread_cont, mit);
	}
	/* NOTREACHED */
	__builtin_unreachable();
}

/*
 * Simple variant.
 */
__attribute__((noreturn))
static void
nx_netif_mit_s_thread_cont(void *v, wait_result_t wres)
{
	struct __kern_channel_ring *kr;
	struct nx_netif_mit *mit = v;
	struct netif_stats *nifs;
	int irq_stat, error;

	ASSERT(mit->mit_flags & NETIF_MITF_SIMPLE);
	kr = __DEVOLATILE(struct __kern_channel_ring *, mit->mit_ckr);
	nifs = &NX_NETIF_PRIVATE(KRNA(kr)->na_nx)->nif_stats;
	irq_stat = (kr->ckr_tx == NR_TX) ? NETIF_STATS_TX_IRQ_MIT :
	    NETIF_STATS_RX_IRQ_MIT;

	MIT_SPIN_LOCK(mit);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (mit->mit_flags & NETIF_MITF_TERMINATING))) {
		goto terminate;
	}

	ASSERT(!(mit->mit_flags & NETIF_MITF_TERMINATED));
	mit->mit_flags |= NETIF_MITF_RUNNING;

	/*
	 * Keep on servicing the ring until no more request.
	 */
	for (;;) {
		uint32_t requests = mit->mit_requests;

		STATS_INC(nifs, irq_stat);
		MIT_SPIN_UNLOCK(mit);

		error = nx_netif_common_intr(kr, kernproc, 0, NULL);

		/*
		 * We could get EBUSY here due to netif_inject_rx() holding
		 * the kring lock. EBUSY means the rx notify callback (which
		 * does the rx syncs..etc) wasn't called. If we don't retry
		 * nx_netif_common_intr() the driver will eventually stop
		 * notifying due to its queues being full.
		 */
		if (error == EBUSY) {
			uint32_t ival =
			    MAX(netif_busy_mit_delay, NETIF_BUSY_MIT_DELAY);

			MIT_SPIN_LOCK(mit);
			mit->mit_requests++;
			MIT_SPIN_UNLOCK(mit);
			delay(ival);
		}

		MIT_SPIN_LOCK(mit);

		if ((mit->mit_flags & NETIF_MITF_TERMINATING) != 0 ||
		    requests == mit->mit_requests) {
			mit->mit_requests = 0;
			break;
		}
	}

	if (__probable((mit->mit_flags & NETIF_MITF_TERMINATING) == 0)) {
		uint64_t deadline = TIMEOUT_WAIT_FOREVER;

		MIT_SPIN_LOCK_ASSERT_HELD(mit);

		if (kr->ckr_rate_limited) {
			SK_DF(SK_VERB_NETIF_MIT,
			    "%s: posting wait deadline for MIT",
			    mit->mit_name);
			clock_interval_to_deadline(1, NSEC_PER_MSEC,
			    &deadline);
		}
		mit->mit_flags &= ~NETIF_MITF_RUNNING;
		(void) assert_wait_deadline(&mit->mit_flags,
		    THREAD_UNINT, deadline);
		MIT_SPIN_UNLOCK(mit);
		(void) thread_block_parameter(nx_netif_mit_s_thread_cont, mit);
		/* NOTREACHED */
	} else {
terminate:
		MIT_SPIN_LOCK_ASSERT_HELD(mit);

		VERIFY(mit->mit_thread == current_thread());
		VERIFY((mit->mit_flags & NETIF_MITF_TERMINATING) != 0);
		mit->mit_flags &= ~(NETIF_MITF_READY | NETIF_MITF_RUNNING |
		    NETIF_MITF_TERMINATING);
		mit->mit_flags |= NETIF_MITF_TERMINATED;
		wakeup((caddr_t)&mit->mit_flags);
		MIT_SPIN_UNLOCK(mit);

		/* for the extra refcnt from kernel_thread_start() */
		thread_deallocate(current_thread());
		/* this is the end */
		thread_terminate(current_thread());
		/* NOTREACHED */
	}

	/* must never get here */
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

/*
 * Advanced variant.
 */
__attribute__((noreturn))
static void
nx_netif_mit_thread_cont(void *v, wait_result_t wres)
{
	struct __kern_channel_ring *kr;
	struct nx_netif_mit *mit = v;
	struct netif_stats *nifs;
	int irq_stat;

	ASSERT(!(mit->mit_flags & NETIF_MITF_SIMPLE));
	kr = __DEVOLATILE(struct __kern_channel_ring *, mit->mit_ckr);
	nifs = &NX_NETIF_PRIVATE(KRNA(kr)->na_nx)->nif_stats;
	irq_stat = (kr->ckr_tx == NR_TX) ? NETIF_STATS_TX_IRQ_MIT :
	    NETIF_STATS_RX_IRQ_MIT;

	MIT_SPIN_LOCK(mit);
	if (__improbable(wres == THREAD_INTERRUPTED ||
	    (mit->mit_flags & NETIF_MITF_TERMINATING))) {
		goto terminate;
	}

	ASSERT(!(mit->mit_flags & NETIF_MITF_TERMINATED));
	mit->mit_flags |= NETIF_MITF_RUNNING;

	/*
	 * Keep on servicing the ring until no more request.
	 */
	for (;;) {
		uint32_t requests = mit->mit_requests;
		uint32_t ival;
		int error = 0;

		STATS_INC(nifs, irq_stat);
		MIT_SPIN_UNLOCK(mit);

		/*
		 * Notify the ring and trigger packets fan-out;
		 * bracket the call with timestamps to compute
		 * our effective mitigation/delay interval below.
		 */
		nx_netif_mit_set_start_interval(mit);
		error = nx_netif_common_intr(kr, kernproc, 0, NULL);
		ival = nx_netif_mit_update_interval(mit, FALSE);

		/*
		 * If mitigation interval is non-zero (for TX/RX)
		 * then we always introduce an artificial delay
		 * for that amount of time.  Otherwise, if we get
		 * EBUSY, then kr_enter() has another thread that
		 * is working on it, and so we should wait a bit.
		 */
		if (ival != 0 || error == EBUSY) {
			if (error == EBUSY) {
				ival = MAX(netif_busy_mit_delay,
				    NETIF_BUSY_MIT_DELAY);
				MIT_SPIN_LOCK(mit);
				mit->mit_requests++;
				MIT_SPIN_UNLOCK(mit);
			}
			delay(ival);
		}

		MIT_SPIN_LOCK(mit);

		if ((mit->mit_flags & NETIF_MITF_TERMINATING) != 0 ||
		    requests == mit->mit_requests) {
			mit->mit_requests = 0;
			break;
		}
	}

	if (__probable((mit->mit_flags & NETIF_MITF_TERMINATING) == 0)) {
		uint64_t deadline = TIMEOUT_WAIT_FOREVER;

		MIT_SPIN_LOCK_ASSERT_HELD(mit);

		if (kr->ckr_rate_limited) {
			SK_DF(SK_VERB_NETIF_MIT,
			    "%s: posting wait deadline for MIT",
			    mit->mit_name);
			clock_interval_to_deadline(1, NSEC_PER_MSEC,
			    &deadline);
		}
		mit->mit_flags &= ~NETIF_MITF_RUNNING;
		(void) assert_wait_deadline(&mit->mit_flags,
		    THREAD_UNINT, deadline);
		MIT_SPIN_UNLOCK(mit);
		(void) thread_block_parameter(nx_netif_mit_thread_cont, mit);
		/* NOTREACHED */
	} else {
terminate:
		MIT_SPIN_LOCK_ASSERT_HELD(mit);

		VERIFY(mit->mit_thread == current_thread());
		VERIFY((mit->mit_flags & NETIF_MITF_TERMINATING) != 0);
		mit->mit_flags &= ~(NETIF_MITF_READY | NETIF_MITF_RUNNING |
		    NETIF_MITF_TERMINATING);
		mit->mit_flags |= NETIF_MITF_TERMINATED;
		wakeup((caddr_t)&mit->mit_flags);
		MIT_SPIN_UNLOCK(mit);

		/* for the extra refcnt from kernel_thread_start() */
		thread_deallocate(current_thread());
		/* this is the end */
		thread_terminate(current_thread());
		/* NOTREACHED */
	}

	/* must never get here */
	VERIFY(0);
	/* NOTREACHED */
	__builtin_unreachable();
}

static void
nx_netif_mit_stats(struct __kern_channel_ring *kr, uint64_t pkts,
    uint64_t bytes)
{
	struct nx_netif_mit *mit = kr->ckr_mit;
	struct timespec now, delta;
	mit_mode_t mode;
	uint32_t cfg_idx;

	ASSERT(mit != NULL && !(mit->mit_flags & NETIF_MITF_SIMPLE));

	if ((os_atomic_or_orig(&mit->mit_flags, NETIF_MITF_SAMPLING, relaxed) &
	    NETIF_MITF_SAMPLING) != 0) {
		return;
	}

	mode = mit->mit_mode;
	cfg_idx = mit->mit_cfg_idx;

	nanouptime(&now);
	if (!net_timerisset(&mit->mit_sample_lasttime)) {
		*(&mit->mit_sample_lasttime) = *(&now);
	}

	net_timersub(&now, &mit->mit_sample_lasttime, &delta);
	if (net_timerisset(&mit->mit_sample_time)) {
		uint32_t ptot, btot;

		/* accumulate statistics for current sampling */
		PKTCNTR_ADD(&mit->mit_sstats, pkts, bytes);

		/* CSTYLED */
		if (net_timercmp(&delta, &mit->mit_sample_time, <)) {
			goto done;
		}

		*(&mit->mit_sample_lasttime) = *(&now);

		/* calculate min/max of bytes */
		btot = (uint32_t)mit->mit_sstats.bytes;
		if (mit->mit_bytes_min == 0 || mit->mit_bytes_min > btot) {
			mit->mit_bytes_min = btot;
		}
		if (btot > mit->mit_bytes_max) {
			mit->mit_bytes_max = btot;
		}

		/* calculate EWMA of bytes */
		MIT_EWMA(mit->mit_bytes_avg, btot,
		    netif_ad_mit_gdecay, netif_ad_mit_sdecay);

		/* calculate min/max of packets */
		ptot = (uint32_t)mit->mit_sstats.packets;
		if (mit->mit_packets_min == 0 || mit->mit_packets_min > ptot) {
			mit->mit_packets_min = ptot;
		}
		if (ptot > mit->mit_packets_max) {
			mit->mit_packets_max = ptot;
		}

		/* calculate EWMA of packets */
		MIT_EWMA(mit->mit_packets_avg, ptot,
		    netif_ad_mit_gdecay, netif_ad_mit_sdecay);

		/* reset sampling statistics */
		PKTCNTR_CLEAR(&mit->mit_sstats);

		/* Perform mode transition, if necessary */
		if (!net_timerisset(&mit->mit_mode_lasttime)) {
			*(&mit->mit_mode_lasttime) = *(&now);
		}

		net_timersub(&now, &mit->mit_mode_lasttime, &delta);
		/* CSTYLED */
		if (net_timercmp(&delta, &mit->mit_mode_holdtime, <)) {
			goto done;
		}

		SK_RDF(SK_VERB_NETIF_MIT, 2, "%s [%u]: pavg %u bavg %u "
		    "delay %llu usec", mit->mit_name, mit->mit_cfg_idx,
		    mit->mit_packets_avg, mit->mit_bytes_avg,
		    (mode == MIT_MODE_ADVANCED_STATIC ? 0 :
		    (mit->mit_tbl[mit->mit_cfg_idx].cfg_ival)));

		if (mit->mit_packets_avg <= mit->mit_cfg->cfg_plowat &&
		    mit->mit_bytes_avg <= mit->mit_cfg->cfg_blowat) {
			if (cfg_idx == 0) {
				mode = MIT_MODE_ADVANCED_STATIC;
			} else {
				ASSERT(mode == MIT_MODE_ADVANCED_DYNAMIC);
				--cfg_idx;
			}
		} else if (mit->mit_packets_avg >= mit->mit_cfg->cfg_phiwat &&
		    mit->mit_bytes_avg >= mit->mit_cfg->cfg_bhiwat) {
			mode = MIT_MODE_ADVANCED_DYNAMIC;
			if (cfg_idx < (mit->mit_cfg_idx_max - 1)) {
				++cfg_idx;
			}
		}

		if (mode != mit->mit_mode || cfg_idx != mit->mit_cfg_idx) {
			ASSERT(cfg_idx < mit->mit_cfg_idx_max);

			SK_DF(SK_VERB_NETIF_MIT, "%s [%u->%u]: pavg %u "
			    "bavg %u [mode %u->%u, delay %llu->%llu usec]",
			    mit->mit_name, mit->mit_cfg_idx, cfg_idx,
			    mit->mit_packets_avg, mit->mit_bytes_avg,
			    mit->mit_mode, mode,
			    (mit->mit_mode == MIT_MODE_ADVANCED_STATIC ? 0 :
			    (mit->mit_cfg->cfg_ival)),
			    (mode == MIT_MODE_ADVANCED_STATIC ? 0 :
			    (mit->mit_tbl[cfg_idx].cfg_ival)));

			mit->mit_mode = mode;
			mit->mit_cfg_idx = cfg_idx;
			mit->mit_cfg = &mit->mit_tbl[mit->mit_cfg_idx];
			*(&mit->mit_mode_lasttime) = *(&now);
		}
	}

done:
	os_atomic_andnot(&mit->mit_flags, NETIF_MITF_SAMPLING, relaxed);
}

#if (DEVELOPMENT || DEBUG)
static int
sysctl_mit_mode_holdtime SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	uint64_t q;
	int err;

	q = netif_mit_mode_holdtime;

	err = sysctl_handle_quad(oidp, &q, 0, req);
	if (err != 0 || req->newptr == USER_ADDR_NULL) {
		return err;
	}

	if (q < NETIF_MIT_MODE_HOLDTIME_MIN) {
		q = NETIF_MIT_MODE_HOLDTIME_MIN;
	}

	netif_mit_mode_holdtime = q;

	return err;
}
#endif /* !DEVELOPMENT && !DEBUG */
