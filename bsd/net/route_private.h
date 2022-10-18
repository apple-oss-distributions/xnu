/*
 * Copyright (c) 2000-2022 Apple Inc. All rights reserved.
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
 * Copyright (c) 1980, 1986, 1993
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
 *	@(#)route.h	8.3 (Berkeley) 4/19/94
 * $FreeBSD: src/sys/net/route.h,v 1.36.2.1 2000/08/16 06:14:23 jayanth Exp $
 */

#ifndef _NET_ROUTE_PRIVATE_H_
#define _NET_ROUTE_PRIVATE_H_
#include <net/route.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <uuid/uuid.h>

struct route_old {
	void            *ro_rt;
	uint32_t        ro_flags;
	struct sockaddr ro_dst;
};

#ifdef BSD_KERNEL_PRIVATE
#include <kern/locks.h>
#include <net/radix.h>
#include <net/if_llatbl.h>
#include <sys/eventhandler.h>
#include <net/if_dl.h>

extern boolean_t trigger_v6_defrtr_select;
/*
 * Kernel resident routing tables.
 *
 * The routing tables are initialized when interface addresses
 * are set by making entries for all directly connected interfaces.
 */

/* forward declarations */
struct ifnet_llreach_info;
struct rt_reach_info;

/*
 * IP route structure
 *
 * A route consists of a destination address and a reference
 * to a routing entry.  These are often held by protocols
 * in their control blocks, e.g. inpcb.
 */
struct route {
	/*
	 * N.B: struct route must begin with ro_{rt, lle, srcia, flags}
	 * because the code does some casts of a 'struct route_in6 *'
	 * to a 'struct route *'.
	 */
	struct rtentry        *ro_rt;
	struct llentry        *ro_lle;

	struct ifaddr         *ro_srcia;
	uint32_t              ro_flags;       /* route flags (see below) */
#if __has_ptrcheck
	struct sockaddr_in    ro_dst;
#else
	struct sockaddr       ro_dst;
#endif
};

#define ROF_SRCIF_SELECTED      0x0001  /* source interface was selected */
#if 0
/* XXX These will be used in the changes coming in later */
#define        ROF_NORTREF             0x0002  /* doesn't hold reference on ro_rt */
#define        ROF_L2_ME               0x0004  /* dst L2 addr is our address */
#define        ROF_MAY_LOOP            0x0008  /* dst may require loop copy */
#define        ROF_HAS_HEADER          0x0010  /* mbuf already have its header prepended */
#define        ROF_REJECT              0x0020  /* Destination is reject */
#define        ROF_BLACKHOLE           0x0040  /* Destination is blackhole */
#define        ROF_HAS_GW              0x0080  /* Destination has GW  */
#endif
#define ROF_LLE_CACHE   0x0100  /* Cache link layer  */

#define ROUTE_UNUSABLE(_ro)                                             \
	((_ro)->ro_rt == NULL ||                                        \
	((_ro)->ro_rt->rt_flags & (RTF_UP|RTF_CONDEMNED)) != RTF_UP ||  \
	RT_GENID_OUTOFSYNC((_ro)->ro_rt))

#define _ROUTE_RELEASE_COMMON(_ro, _rnh_locked) do {                    \
	if ((_ro)->ro_rt != NULL) {                                     \
	        RT_LOCK_ASSERT_NOTHELD((_ro)->ro_rt);                   \
	        if (_rnh_locked)                                        \
	                rtfree_locked((_ro)->ro_rt);                    \
	        else                                                    \
	                rtfree((_ro)->ro_rt);                           \
	        (_ro)->ro_rt = NULL;                                    \
	}                                                               \
	if ((_ro)->ro_srcia != NULL) {                                  \
	        IFA_REMREF((_ro)->ro_srcia);                            \
	        (_ro)->ro_srcia = NULL;                                 \
	        (_ro)->ro_flags &= ~ROF_SRCIF_SELECTED;                 \
	}                                                               \
	if ((_ro)->ro_lle != NULL) {                                    \
	        LLE_REMREF((_ro)->ro_lle);                              \
	        (_ro)->ro_lle = NULL;                                   \
	        (_ro)->ro_flags &= ~ROF_LLE_CACHE;                      \
	}                                                               \
} while (0)

#define ROUTE_RELEASE_LOCKED(_ro)       _ROUTE_RELEASE_COMMON(_ro, TRUE)
#define ROUTE_RELEASE(_ro)              _ROUTE_RELEASE_COMMON(_ro, FALSE)

/*
 * We distinguish between routes to hosts and routes to networks,
 * preferring the former if available.  For each route we infer
 * the interface to use from the gateway address supplied when
 * the route was entered.  Routes that forward packets through
 * gateways are marked so that the output routines know to address the
 * gateway rather than the ultimate destination.
 */

#define NRTT_HIST       10
/*
 * Kernel routing entry structure.
 */
struct rtentry {
	struct  radix_node rt_nodes[2]; /* tree glue, and other values */
#define rt_key(r)       (SA((r)->rt_nodes->rn_key))
#define rt_mask(r)      (SA((r)->rt_nodes->rn_mask))
	/*
	 * See bsd/net/route.c for synchronization notes.
	 */
	decl_lck_mtx_data(, rt_lock);   /* lock for routing entry */
	uint32_t rt_refcnt;             /* # held references */
	uint32_t rt_flags;              /* up/down?, host/net */
	uint32_t rt_genid;              /* route generation id */
	struct sockaddr *rt_gateway;    /* value */
	struct ifnet *rt_ifp;           /* the answer: interface to use */
	struct ifaddr *rt_ifa;          /* the answer: interface addr to use */
	struct sockaddr *rt_genmask;    /* for generation of cloned routes */
	void *rt_llinfo;                /* pointer to link level info cache */
	void (*rt_llinfo_get_ri)        /* llinfo get reachability info fn */
	(struct rtentry *, struct rt_reach_info *);
	void (*rt_llinfo_get_iflri)     /* ifnet llinfo get reach. info fn */
	(struct rtentry *, struct ifnet_llreach_info *);
	void (*rt_llinfo_purge)(struct rtentry *); /* llinfo purge fn */
	void (*rt_llinfo_free)(void *); /* link level info free function */
	void (*rt_llinfo_refresh) (struct rtentry *); /* expedite llinfo refresh */
	struct rt_metrics rt_rmx;       /* metrics used by rx'ing protocols */
#define rt_use rt_rmx.rmx_pksent
	struct rtentry *rt_gwroute;     /* implied entry for gatewayed routes */
	struct rtentry *rt_parent;      /* cloning parent of this route */
	struct nstat_counts *rt_stats;  /* route stats */
	void (*rt_if_ref_fn)(struct ifnet *, int); /* interface ref func */

	uint32_t *rt_tree_genid;        /* ptr to per-tree route_genid */
	uint64_t rt_expire;             /* expiration time in uptime seconds */
	uint64_t base_calendartime;     /* calendar time upon entry creation */
	uint64_t base_uptime;           /* uptime upon entry creation */
	u_int32_t rtt_hist[NRTT_HIST];  /* RTT history sample by TCP connections */
	u_int32_t rtt_min;              /* minimum RTT computed from history */
	u_int32_t rtt_expire_ts;        /* RTT history expire timestamp */
	u_int8_t rtt_index;             /* Index into RTT history */
	/* Event handler context for the rtentrt */
	struct eventhandler_lists_ctxt rt_evhdlr_ctxt;
};

#define rt_key_free(r) ({ \
	void *__r = rt_key(r); \
	kheap_free_addr(KHEAP_DATA_BUFFERS, __r); \
})

enum {
	ROUTE_STATUS_UPDATE = 1,
	ROUTE_ENTRY_REFRESH,
	ROUTE_ENTRY_DELETED,
	ROUTE_LLENTRY_RESOLVED,
	ROUTE_LLENTRY_UNREACH,
	ROUTE_LLENTRY_CHANGED,
	ROUTE_LLENTRY_STALE,
	ROUTE_LLENTRY_TIMEDOUT,
	ROUTE_LLENTRY_DELETED,
	ROUTE_LLENTRY_EXPIRED,
	ROUTE_LLENTRY_PROBED,
	ROUTE_EVHDLR_DEREGISTER,
};

extern const char * route_event2str(int route_event);

typedef void (*route_event_fn) (struct eventhandler_entry_arg,
    struct sockaddr *, int, struct sockaddr *, int);
EVENTHANDLER_DECLARE(route_event, route_event_fn);

/*
 * Synchronize route entry's generation ID with the tree's.
 */
#define RT_GENID_SYNC(_rt) do {                                         \
	if ((_rt)->rt_tree_genid != NULL)                               \
	        (_rt)->rt_genid = *(_rt)->rt_tree_genid;                \
} while (0)

/*
 * Indicates whether or not the route entry's generation ID is stale.
 */
#define RT_GENID_OUTOFSYNC(_rt)                                         \
	((_rt)->rt_tree_genid != NULL &&                                \
	*(_rt)->rt_tree_genid != (_rt)->rt_genid)

enum {
	ROUTE_OP_READ,
	ROUTE_OP_WRITE,
};

extern int route_op_entitlement_check(struct socket *, kauth_cred_t, int, boolean_t);
#endif /* BSD_KERNEL_PRIVATE */

struct kev_netevent_apnfallbk_data {
	pid_t           epid;           /* effective PID */
	uuid_t          euuid;          /* effective UUID */
};

/*
 * Route reachability info.
 */
struct rt_reach_info {
	u_int32_t       ri_refcnt;      /* reference count */
	u_int32_t       ri_probes;      /* total # of probes */
	u_int64_t       ri_snd_expire;  /* tx expiration (calendar) time */
	u_int64_t       ri_rcv_expire;  /* rx expiration (calendar) time */
	int32_t         ri_rssi;        /* received signal strength */
	int32_t         ri_lqm;         /* link quality metric */
	int32_t         ri_npm;         /* node proximity metric */
};

/*
 * Extended routing message header (private).
 */
struct rt_msghdr_ext {
	u_short rtm_msglen;     /* to skip over non-understood messages */
	u_char  rtm_version;    /* future binary compatibility */
	u_char  rtm_type;       /* message type */
	u_int32_t rtm_index;    /* index for associated ifp */
	u_int32_t rtm_flags;    /* flags, incl. kern & message, e.g. DONE */
	u_int32_t rtm_reserved; /* for future use */
	u_int32_t rtm_addrs;    /* bitmask identifying sockaddrs in msg */
	pid_t   rtm_pid;        /* identify sender */
	int     rtm_seq;        /* for sender to identify action */
	int     rtm_errno;      /* why failed */
	u_int32_t rtm_use;      /* from rtentry */
	u_int32_t rtm_inits;    /* which metrics we are initializing */
	struct rt_metrics rtm_rmx;      /* metrics themselves */
	struct rt_reach_info rtm_ri;    /* route reachability info */
};

/*
 * Message types.
 */
#define RTM_GET_SILENT  0x11
#define RTM_GET_EXT     0x15

/*
 * Bitmask values for rtm_inits and rmx_locks.
 */
#define RTV_REFRESH_HOST        0x100   /* init host route to expedite refresh */

/*
 * For scoped routing; a zero interface scope value means nil/no scope.
 */
#define IFSCOPE_NONE    0
#define IFSCOPE_UNKNOWN IFSCOPE_NONE

#ifdef BSD_KERNEL_PRIVATE
/*
 * Generic call trace used by some subsystems (e.g. route, ifaddr)
 */
#define CTRACE_STACK_SIZE       8               /* depth of stack trace */
#define CTRACE_HIST_SIZE        4               /* refcnt history size */
typedef struct ctrace {
	void    *th;                            /* thread ptr */
	void    *pc[CTRACE_STACK_SIZE];         /* PC stack trace */
} ctrace_t;

extern void ctrace_record(ctrace_t *);

#define RT_LOCK_ASSERT_HELD(_rt)                                        \
	LCK_MTX_ASSERT(&(_rt)->rt_lock, LCK_MTX_ASSERT_OWNED)

#define RT_LOCK_ASSERT_NOTHELD(_rt)                                     \
	LCK_MTX_ASSERT(&(_rt)->rt_lock, LCK_MTX_ASSERT_NOTOWNED)

#define RT_LOCK(_rt) do {                                               \
	rt_lock(_rt, FALSE);                                            \
} while (0)

#define RT_LOCK_SPIN(_rt) do {                                          \
	rt_lock(_rt, TRUE);                                             \
} while (0)

#define RT_CONVERT_LOCK(_rt) do {                                       \
	RT_LOCK_ASSERT_HELD(_rt);                                       \
	lck_mtx_convert_spin(&(_rt)->rt_lock);                          \
} while (0)

#define RT_UNLOCK(_rt) do {                                             \
	rt_unlock(_rt);                                                 \
} while (0)

#define RT_ADDREF_LOCKED(_rt) do {                                      \
	rtref(_rt);                                                     \
} while (0)

/*
 * Spin variant mutex is used here; caller is responsible for
 * converting any previously-held similar lock to full mutex.
 */
#define RT_ADDREF(_rt) do {                                             \
	RT_LOCK_SPIN(_rt);                                              \
	RT_ADDREF_LOCKED(_rt);                                          \
	RT_UNLOCK(_rt);                                                 \
} while (0)

#define RT_REMREF_LOCKED(_rt) do {                                      \
	(void) rtunref(_rt);                                            \
} while (0)

/*
 * Spin variant mutex is used here; caller is responsible for
 * converting any previously-held similar lock to full mutex.
 */
#define RT_REMREF(_rt) do {                                             \
	RT_LOCK_SPIN(_rt);                                              \
	RT_REMREF_LOCKED(_rt);                                          \
	RT_UNLOCK(_rt);                                                 \
} while (0)

/*
 * This macro calculates skew in wall clock, just in case the user changes the
 * system time. This skew adjustment is required because we now keep the
 * expiration times in uptime terms in the kernel, but the userland still
 * expects expiration times in terms of calendar times.  This is used when
 * reporting rt_expire, ln_expire, etc. values to user space.
 */
#define NET_CALCULATE_CLOCKSKEW(cc, ic, cu, iu)                         \
	((cc.tv_sec - ic) - (cu - iu))

extern unsigned int rt_verbose;
extern struct radix_node_head *rt_tables[AF_MAX + 1];
extern lck_mtx_t rnh_lock_data;
#define rnh_lock (&rnh_lock_data)
extern uint32_t route_genid_inet;       /* INET route generation count */
extern uint32_t route_genid_inet6;      /* INET6 route generation count */
extern int rttrash;
extern unsigned int rte_debug;

struct ifmultiaddr;
struct proc;

extern void route_init(void);
extern void routegenid_update(void);
extern void routegenid_inet_update(void);
extern void routegenid_inet6_update(void);
extern void rt_ifmsg(struct ifnet *);
extern void rt_missmsg(u_char, struct rt_addrinfo *, int, int);
extern void rt_newaddrmsg(u_char, struct ifaddr *, int, struct rtentry *);
extern void rt_newmaddrmsg(u_char, struct ifmultiaddr *);
extern int rt_setgate(struct rtentry *, struct sockaddr *, struct sockaddr *);
extern void set_primary_ifscope(int, unsigned int);
extern unsigned int get_primary_ifscope(int);
extern boolean_t rt_primary_default(struct rtentry *, struct sockaddr *);
extern struct rtentry *rt_lookup(boolean_t, struct sockaddr *,
    struct sockaddr *, struct radix_node_head *, unsigned int);
extern struct rtentry *rt_lookup_coarse(boolean_t, struct sockaddr *,
    struct sockaddr *, struct radix_node_head *);
extern void rtalloc(struct route *);
extern void rtalloc_scoped(struct route *, unsigned int);
extern void rtalloc_ign(struct route *, uint32_t);
extern void rtalloc_scoped_ign(struct route *, uint32_t, unsigned int);
extern struct rtentry *rtalloc1(struct sockaddr *, int, uint32_t);
extern struct rtentry *rtalloc1_scoped(struct sockaddr *, int, uint32_t,
    unsigned int);
extern struct rtentry *rtalloc1_scoped_locked(struct sockaddr *, int,
    uint32_t, unsigned int);
extern void rtfree_locked(struct rtentry *);
extern void rtfree(struct rtentry *);
extern void rtref(struct rtentry *);
/*
 * rtunref will decrement the refcount, rtfree will decrement and free if
 * the refcount has reached zero and the route is not up.
 * Unless you have good reason to do otherwise, use rtfree.
 */
extern int rtunref(struct rtentry *);
extern void rtsetifa(struct rtentry *, struct ifaddr *);
extern int rtinit(struct ifaddr *, uint8_t, int);
extern int rtinit_locked(struct ifaddr *, uint8_t, int);
extern int rtioctl(unsigned long, caddr_t, struct proc *);
extern void rtredirect(struct ifnet *, struct sockaddr *, struct sockaddr *,
    struct sockaddr *, int, struct sockaddr *, struct rtentry **);
extern int rtrequest(int, struct sockaddr *,
    struct sockaddr *, struct sockaddr *, int, struct rtentry **);
extern int rtrequest_scoped(int, struct sockaddr *, struct sockaddr *,
    struct sockaddr *, int, struct rtentry **, unsigned int);
extern int rtrequest_locked(int, struct sockaddr *,
    struct sockaddr *, struct sockaddr *, int, struct rtentry **);
extern int rtrequest_scoped_locked(int, struct sockaddr *, struct sockaddr *,
    struct sockaddr *, int, struct rtentry **, unsigned int);
extern void sin_set_ifscope(struct sockaddr *, unsigned int);
extern unsigned int sin_get_ifscope(struct sockaddr *);
extern unsigned int sin6_get_ifscope(struct sockaddr *);
extern void rt_lock(struct rtentry *, boolean_t);
extern void rt_unlock(struct rtentry *);
extern struct sockaddr *rtm_scrub(int, int, struct sockaddr *,
    struct sockaddr *, void *, uint32_t, kauth_cred_t *);
extern boolean_t rt_validate(struct rtentry *);
extern void rt_set_proxy(struct rtentry *, boolean_t);
extern void rt_set_gwroute(struct rtentry *, struct sockaddr *,
    struct rtentry *);
extern void rt_revalidate_gwroute(struct rtentry *, struct rtentry *);
extern errno_t route_to_gwroute(const struct sockaddr *, struct rtentry *,
    struct rtentry **);
extern void rt_setexpire(struct rtentry *, uint64_t);
extern void rt_str(struct rtentry *, char *, uint32_t, char *, uint32_t);
extern const char *rtm2str(int);
extern void route_clear(struct route *);
extern void route_copyin(struct route *, struct route *, size_t);
extern void route_copyout(struct route *, const struct route *, size_t);
extern boolean_t rt_ifa_is_dst(struct sockaddr *, struct ifaddr *);
extern struct sockaddr *sa_copy(struct sockaddr *, struct sockaddr_storage *,
    unsigned int *);

/*
 * The following is used to enqueue work items for route events
 * and also used to pass route event while walking the tree
 */
struct route_event {
	struct rtentry *rt;
	/*
	 * There's no reference taken on gwrt.
	 * We only use it to check whether we should
	 * point to rt_gateway or the embedded rt_addr
	 * structure.
	 */
	struct rtentry *gwrt;
	union {
		union sockaddr_in_4_6 _rtev_ipaddr;
		char _rtev_addr_bytes[DLIL_SDLMAXLEN];
	} rt_addr;
	uint32_t route_event_code;
	eventhandler_tag evtag;
};

#define rtev_ipaddr     rt_addr._rtev_ipaddr
#define rtev_addr_bytes rt_addr._rtev_addr_bytes

extern void route_event_init(struct route_event *p_route_ev, struct rtentry *rt,
    struct rtentry *gwrt, int route_ev_code);
extern int route_event_walktree(struct radix_node *rn, void *arg);
extern void route_event_enqueue_nwk_wq_entry(struct rtentry *, struct rtentry *,
    uint32_t, eventhandler_tag, boolean_t);
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _NET_ROUTE_PRIVATE_H_ */
