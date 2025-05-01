/*
 * Copyright (c) 1999-2024 Apple Inc. All rights reserved.
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
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
#ifndef DLIL_VAR_PRIVATE_H
#define DLIL_VAR_PRIVATE_H

#include "kern/kern_types.h"
#include <sys/kernel_types.h>


#include <stddef.h>
#include <ptrauth.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/domain.h>
#include <sys/user.h>
#include <sys/random.h>
#include <sys/socketvar.h>
#include <net/if_dl.h>
#include <net/if.h>
#include <net/route.h>
#include <net/if_var.h>
#include <net/dlil.h>
#include <net/if_arp.h>
#include <net/iptap.h>
#include <net/pktap.h>
#include <net/droptap.h>
#include <net/nwk_wq.h>
#include <sys/kern_event.h>
#include <sys/kdebug.h>
#include <sys/mcache.h>
#include <sys/syslog.h>
#include <sys/protosw.h>
#include <sys/priv.h>

#include <kern/assert.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/sched_prim.h>
#include <kern/locks.h>
#include <kern/kalloc.h>
#include <kern/zalloc.h>

#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <net/if_types.h>
#include <net/if_ipsec.h>
#include <net/if_llreach.h>
#include <net/if_utun.h>
#include <net/kpi_interfacefilter.h>
#include <net/classq/classq.h>
#include <net/classq/classq_sfb.h>
#include <net/flowhash.h>
#include <net/ntstat.h>

#include <net/net_api_stats.h>
#include <net/if_ports_used.h>
#include <net/if_vlan_var.h>
#include <netinet/in.h>
#if INET
#include <netinet/in_var.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_pcb.h>
#include <netinet/in_tclass.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#endif /* INET */

#include <net/nat464_utils.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <netinet6/mld6_var.h>
#include <netinet6/scope6_var.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/pf_pbuf.h>
#include <libkern/OSAtomic.h>
#include <libkern/tree.h>

#include <dev/random/randomdev.h>
#include <machine/machine_routines.h>

#include <mach/thread_act.h>
#include <mach/sdt.h>

#if CONFIG_MACF
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <net/ethernet.h>
#include <net/firewire.h>
#endif

#if PF
#include <net/pfvar.h>
#endif /* PF */
#include <net/pktsched/pktsched.h>
#include <net/pktsched/pktsched_netem.h>

#if NECP
#include <net/necp.h>
#endif /* NECP */

#if SKYWALK
#include <skywalk/packet/packet_queue.h>
#include <skywalk/nexus/netif/nx_netif.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#endif /* SKYWALK */

#include <net/sockaddr_utils.h>

#include <os/log.h>

#ifndef BSD_KERNEL_PRIVATE
#error __FILE__ ## " can only be privately included"
#endif /* BSD_KERNEL_PRIVATE */


#define DBG_LAYER_BEG           DLILDBG_CODE(DBG_DLIL_STATIC, 0)
#define DBG_LAYER_END           DLILDBG_CODE(DBG_DLIL_STATIC, 2)
#define DBG_FNC_DLIL_INPUT      DLILDBG_CODE(DBG_DLIL_STATIC, (1 << 8))
#define DBG_FNC_DLIL_OUTPUT     DLILDBG_CODE(DBG_DLIL_STATIC, (2 << 8))
#define DBG_FNC_DLIL_IFOUT      DLILDBG_CODE(DBG_DLIL_STATIC, (3 << 8))

#define IF_DATA_REQUIRE_ALIGNED_64(f)   \
	_CASSERT(!(offsetof(struct if_data_internal, f) % sizeof (u_int64_t)))

#define IFNET_IF_DATA_REQUIRE_ALIGNED_64(f)     \
	_CASSERT(!(offsetof(struct ifnet, if_data.f) % sizeof (u_int64_t)))

enum {
	kProtoKPI_v1    = 1,
	kProtoKPI_v2    = 2
};

#if 1
#define DLIL_PRINTF     printf
#else
#define DLIL_PRINTF     kprintf
#endif

extern unsigned int ifnet_debug;


extern unsigned int net_rxpoll;
extern unsigned int net_affinity;
extern unsigned int net_async;     /* 0: synchronous, 1: asynchronous */

#if SKYWALK
/*
 * Skywalk ifnet attachment modes.
 */
extern uint32_t if_attach_nx;
extern uint32_t if_enable_fsw_ip_netagent;
extern uint32_t if_enable_fsw_transport_netagent;
extern uint32_t if_netif_all;
#endif /* SKYWALK */

#define DLIL_SDLDATALEN \
	(DLIL_SDLMAXLEN - offsetof(struct sockaddr_dl, sdl_data[0]))


/*
 * In the common case, the LL address is stored in the
 * `dl_if_lladdr' member of the `dlil_ifnet'. This is sufficient
 * for LL addresses that do not exceed the `DLIL_SDLMAXLEN' constant.
 */
struct dl_if_lladdr_std {
	struct ifaddr   ifa;
	u_int8_t        addr_sdl_bytes[DLIL_SDLMAXLEN];
	u_int8_t        mask_sdl_bytes[DLIL_SDLMAXLEN];
};

/*
 * However, in some rare cases we encounter LL addresses which
 * would not fit in the `DLIL_SDLMAXLEN' limitation. In such cases
 * we allocate the storage in the permanent arena, using this memory layout.
 */
struct dl_if_lladdr_xtra_space {
	struct ifaddr   ifa;
	u_int8_t        addr_sdl_bytes[SOCK_MAXADDRLEN];
	u_int8_t        mask_sdl_bytes[SOCK_MAXADDRLEN];
};

struct dlil_ifnet {
	struct ifnet    dl_if;                  /* public ifnet */
	/*
	 * DLIL private fields, protected by dl_if_lock
	 */
	decl_lck_mtx_data(, dl_if_lock);
	TAILQ_ENTRY(dlil_ifnet) dl_if_link;     /* dlil_ifnet link */
	u_int32_t dl_if_flags;                  /* flags (below) */
	u_int32_t dl_if_refcnt;                 /* refcnt */
	void (*dl_if_trace)(struct dlil_ifnet *, int); /* ref trace callback */
	void    *dl_if_uniqueid __sized_by_or_null(dl_if_uniqueid_len);                /* unique interface id */
	size_t  dl_if_uniqueid_len;             /* length of the unique id */
	char    dl_if_namestorage[IFNAMSIZ];    /* interface name storage */
	char    dl_if_xnamestorage[IFXNAMSIZ];  /* external name storage */
	struct dl_if_lladdr_std dl_if_lladdr;   /* link-level address storage*/
	u_int8_t dl_if_descstorage[IF_DESCSIZE]; /* desc storage */
	u_int8_t dl_if_permanent_ether[ETHER_ADDR_LEN]; /* permanent address */
	u_int8_t dl_if_permanent_ether_is_set;
	u_int8_t dl_if_unused;
	struct dlil_threading_info dl_if_inpstorage; /* input thread storage */
	ctrace_t        dl_if_attach;           /* attach PC stacktrace */
	ctrace_t        dl_if_detach;           /* detach PC stacktrace */
};


/* Values for dl_if_flags (private to DLIL) */
#define DLIF_INUSE      0x1     /* DLIL ifnet recycler, ifnet in use */
#define DLIF_REUSE      0x2     /* DLIL ifnet recycles, ifnet is not new */
#define DLIF_DEBUG      0x4     /* has debugging info */

#define IF_REF_TRACE_HIST_SIZE  8       /* size of ref trace history */

/* For gdb */
extern unsigned int if_ref_trace_hist_size;

struct dlil_ifnet_dbg {
	struct dlil_ifnet       dldbg_dlif;             /* dlil_ifnet */
	u_int16_t               dldbg_if_refhold_cnt;   /* # ifnet references */
	u_int16_t               dldbg_if_refrele_cnt;   /* # ifnet releases */
	/*
	 * Circular lists of ifnet_{reference,release} callers.
	 */
	ctrace_t                dldbg_if_refhold[IF_REF_TRACE_HIST_SIZE];
	ctrace_t                dldbg_if_refrele[IF_REF_TRACE_HIST_SIZE];
};

#define DLIL_TO_IFP(s)  (&s->dl_if)
#define IFP_TO_DLIL(s)  ((struct dlil_ifnet *)s)

struct ifnet_filter {
	TAILQ_ENTRY(ifnet_filter)       filt_next;
	u_int32_t                       filt_skip;
	u_int32_t                       filt_flags;
	ifnet_t                         filt_ifp;
	const char                      *filt_name;
	void                            *filt_cookie;
	protocol_family_t               filt_protocol;
	iff_input_func                  filt_input;
	iff_output_func                 filt_output;
	iff_event_func                  filt_event;
	iff_ioctl_func                  filt_ioctl;
	iff_detached_func               filt_detached;
};


/* Mbuf queue used for freeing the excessive mbufs */
typedef MBUFQ_HEAD(dlil_freeq) dlil_freeq_t;

typedef TAILQ_HEAD(, dlil_ifnet) dlil_ifnet_queue_t;

extern dlil_ifnet_queue_t dlil_ifnet_head;

struct proto_input_entry;

/*
 * Utility routines
 */
extern kern_return_t dlil_affinity_set(struct thread *, u_int32_t);
extern boolean_t packet_has_vlan_tag(struct mbuf * m);
void log_hexdump(void *__sized_by(len) data, size_t len);

/*
 * Monitor routines.
 */
extern void if_flt_monitor_busy(struct ifnet *);
extern void if_flt_monitor_unbusy(struct ifnet *);
extern void if_flt_monitor_enter(struct ifnet *);
extern void if_flt_monitor_leave(struct ifnet *);

/*
 * Allocation routines
 */
extern void dlil_allocation_zones_init(void);

extern struct dlil_ifnet * dlif_ifnet_alloc(void);
extern void dlif_ifnet_free(struct dlil_ifnet *);

extern struct ifnet_filter * dlif_filt_alloc(void);
extern void dlif_filt_free(struct ifnet_filter *);

extern struct if_proto * dlif_proto_alloc(void);
extern void dlif_proto_free(struct if_proto * );

extern struct tcpstat_local * dlif_tcpstat_alloc(void);
extern void dlif_tcpstat_free(struct tcpstat_local *);

extern struct udpstat_local * dlif_udpstat_alloc(void);
extern void dlif_udpstat_free(struct udpstat_local *);

extern void if_proto_ref(struct if_proto *);
extern void if_proto_free(struct if_proto *);

/*
 * Prepare the storage for the first/permanent link address, which must
 * must have the same lifetime as the ifnet itself.  Although the link
 * address gets removed from if_addrhead and ifnet_addrs[] at detach time,
 * its location in memory must never change as it may still be referred
 * to by some parts of the system afterwards (unfortunate implementation
 * artifacts inherited from BSD.)
 *
 * Caller must hold ifnet lock as writer.
 */
extern struct ifaddr * dlil_alloc_lladdr(struct ifnet *ifp, const struct sockaddr_dl *ll_addr);


/*
 * dlil_ifp_protolist
 * - get the list of protocols attached to the interface, or just the number
 *   of attached protocols
 * - if the number returned is greater than 'list_count', truncation occurred
 *
 * Note:
 * - caller must already be holding ifnet lock.
 */
extern u_int32_t dlil_ifp_protolist(struct ifnet *ifp, protocol_family_t *list __counted_by(list_count),
    u_int32_t list_count);

extern uint64_t if_creation_generation_count;


/*
 * Interface management functions
 */
extern void dlil_if_trace(struct dlil_ifnet *, int);

extern void _dlil_if_release(ifnet_t ifp, bool clear_in_use);

/*
 * Stats management
 */
void dlil_input_stats_add(const struct ifnet_stat_increment_param *,
    struct dlil_threading_info *, struct ifnet *, boolean_t);

boolean_t dlil_input_stats_sync(struct ifnet *,
    struct dlil_threading_info *);

/*
 * Thread management
 */
extern uint32_t dlil_pending_thread_cnt;


/* DLIL data threshold thread call */
extern void dlil_dt_tcall_fn(thread_call_param_t, thread_call_param_t);

extern void dlil_clean_threading_info(struct dlil_threading_info *inp);

int dlil_create_input_thread(ifnet_t, struct dlil_threading_info *,
    thread_continue_t *);

void dlil_terminate_input_thread(struct dlil_threading_info *);

extern boolean_t dlil_is_rxpoll_input(thread_continue_t func);
boolean_t dlil_is_native_netif_nexus(ifnet_t ifp);

void dlil_incr_pending_thread_count(void);
void dlil_decr_pending_thread_count(void);

struct if_proto * find_attached_proto(struct ifnet *ifp, u_int32_t protocol_family);

int dlil_is_clat_needed(protocol_family_t proto_family, mbuf_t m);
errno_t dlil_clat46(ifnet_t ifp, protocol_family_t *proto_family, mbuf_t *m);
errno_t dlil_clat64(ifnet_t ifp, protocol_family_t *proto_family, mbuf_t *m);

/*
 * Lock management functions
 */
extern lck_attr_t dlil_lck_attributes;
extern lck_rw_t ifnet_head_lock;
extern lck_mtx_t dlil_ifnet_lock;
extern lck_grp_t dlil_lock_group;
extern lck_grp_t ifnet_head_lock_group;
extern lck_grp_t ifnet_snd_lock_group;
extern lck_grp_t ifnet_rcv_lock_group;
extern lck_mtx_t dlil_thread_sync_lock;

extern void dlil_if_lock(void);

extern void dlil_if_unlock(void);

extern void dlil_if_lock_assert(void);

extern void ifnet_head_lock_assert(ifnet_lock_assert_t what);

extern void ifnet_lock_assert(struct ifnet *ifp, ifnet_lock_assert_t what);

extern void ifnet_lock_shared(struct ifnet *ifp);

extern void ifnet_lock_exclusive(struct ifnet *ifp);

extern void ifnet_lock_done(struct ifnet *ifp);

#if INET
extern void if_inetdata_lock_shared(struct ifnet *ifp);

extern void if_inetdata_lock_exclusive(struct ifnet *ifp);

extern void if_inetdata_lock_done(struct ifnet *ifp);

#endif /* INET */

extern void if_inet6data_lock_shared(struct ifnet *ifp);

extern void if_inet6data_lock_exclusive(struct ifnet *ifp);

extern void if_inet6data_lock_done(struct ifnet *ifp);

extern void ifnet_head_lock_shared(void);

extern void ifnet_head_lock_exclusive(void);

extern void ifnet_head_done(void);

extern void ifnet_head_assert_exclusive(void);

/*
 * mcasts
 */
errno_t if_mcasts_update_async(struct ifnet *);


#endif /* DLIL_VAR_PRIVATE_H */
