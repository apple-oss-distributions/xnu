/*
 * Copyright (c) 2015-2021 Apple Inc. All rights reserved.
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
 * Copyright (C) 2011-2014 Matteo Landi, Luigi Rizzo. All rights reserved.
 * Copyright (C) 2013-2014 Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SKYWALK_NEXUS_FLOWSWITCH_H_
#define _SKYWALK_NEXUS_FLOWSWITCH_H_

#include <skywalk/os_skywalk_private.h>
#include <net/ethernet.h>
#include <net/if_vlan_var.h>
#include <netinet/ip6.h>

#include <skywalk/nexus/flowswitch/flow/flow_var.h>

#if CONFIG_NEXUS_FLOWSWITCH
/* Shared declarations for the flow switch. */
#define NX_FSW_NAME             "fsw"   /* prefix for flow switch port name */

#define NX_FSW_MAXRINGS         NX_MAX_NUM_RING_PAIR
#define NX_FSW_TXRINGSIZE       256     /* default TX ring size */
#define NX_FSW_RXRINGSIZE       1024    /* default RX ring size */
#define NX_FSW_AFRINGSIZE       256     /* default Alloc/Free ring size */

#define NX_FSW_CHUNK            64      /* port chunk */
#define NX_FSW_CHUNK_FREE       0xffffffffffffffff /* entire chunk is free */

#define NX_FSW_VP_MIN           NX_FSW_CHUNK
#define NX_FSW_VP_MAX           4096    /* up to 4k ports */
#define NX_FSW_VP_NOPORT        (NX_FSW_VP_MAX+1)
#define NX_FSW_VP_BROADCAST     NX_FSW_VP_MAX

#define NX_FSW_MINSLOTS         2       /* XXX unclear how many */
#define NX_FSW_MAXSLOTS         NX_MAX_NUM_SLOT_PER_RING /* max # of slots */

#define NX_FSW_TXBATCH          64      /* default TX batch size */
#if !XNU_TARGET_OS_OSX
#define NX_FSW_RXBATCH          64      /* default RX batch size */
#else /* XNU_TARGET_OS_OSX */
#define NX_FSW_RXBATCH          32      /* default RX batch size */
#endif /* XNU_TARGET_OS_OSX */

#define NX_FSW_BUFSIZE          (2 * 1024)  /* default buffer size */

#define NX_FSW_MINBUFSIZE       512  /* min buffer size */
#define NX_FSW_MAXBUFSIZE       (16 * 1024) /* max buffer size */
#define NX_FSW_MAXBUFFERS       (4 * 1024) /* max number of buffers */
/* max number of buffers for memory constrained device */
#define NX_FSW_MAXBUFFERS_MEM_CONSTRAINED (2 * 1024)
/* default user buffer segment size for non memory-constrained device */
#define NX_FSW_BUF_SEG_SIZE     (32 * 1024)

/*
 * TODO: adi@apple.com -- minimum buflets for now; we will need to
 * have a way to adjust this based on the underlying interface's
 * parameters, e.g. jumbo MTU, large segment offload, etc.
 */
#define NX_FSW_UMD_SIZE _USER_PACKET_SIZE(BUFLETS_MIN)
#define NX_FSW_KMD_SIZE _KERN_PACKET_SIZE(BUFLETS_MIN)

struct nx_flowswitch;

/*
 * Virtual port nexus adapter
 */
struct nexus_vp_adapter {
	/*
	 * This is an overlay structure on nexus_adapter;
	 * make sure it contains 'up' as the first member.
	 */
	struct nexus_adapter vpna_up;

	/*
	 * Flow switch support:
	 *
	 * If the adapter is associated with a nexus port, vpna_fsw points
	 * to the flow switch this NA is attached to; vpna_nx_port is the
	 * port number used in the flow switch.  Otherwise, vpna_fsw would
	 * be NULL and vpna_nx_port would be NEXUS_PORT_ANY.
	 */
	struct nx_flowswitch *vpna_fsw;
	nexus_port_t    vpna_nx_port;
	boolean_t       vpna_retry;
	boolean_t       vpna_pid_bound;
	boolean_t       vpna_defunct;
	pid_t           vpna_pid;
};

#define VPNA(_na)       ((struct nexus_vp_adapter *)(_na))

#define NEXUS_PROVIDER_FLOW_SWITCH      "com.apple.nexus.flowswitch"

/* fsw_state_flags */
#define FSW_STATEF_QUIESCED             0x0001
#define FSW_STATEF_NETAGENT_ADDED       0x0002
#define FSW_STATEF_NETAGENT_ENABLED     0x0004

#define FSW_QUIESCED(_fsw) \
    (((_fsw)->fsw_state_flags & FSW_STATEF_QUIESCED) != 0)

#define FSW_NETAGENT_ADDED(_fsw) \
    (((_fsw)->fsw_state_flags & FSW_STATEF_NETAGENT_ADDED) != 0)

#define FSW_NETAGENT_ENABLED(_fsw)                                      \
    (((_fsw)->fsw_state_flags & FSW_STATEF_NETAGENT_ENABLED) != 0)

/*
 * nx_flowswitch is a descriptor for a flow switch instance.
 * Interfaces for a flow switch are all in fsw_ports[].
 * The array has fixed size, an empty entry does not terminate
 * the search, but lookups only occur on attach/detach so we
 * don't mind if they are slow.
 *
 * The flow switch is non blocking on the transmit ports: excess
 * packets are dropped if there is no room on the output port.
 *
 * fsw_lock protects accesses to the fsw_ports array.
 * This is a rw lock (or equivalent).
 */
struct nx_flowswitch {
	decl_lck_rw_data(, fsw_lock);
	uint32_t                fsw_tx_rings;
	uint32_t                fsw_rx_rings;

	struct kern_nexus       *fsw_nx;

	/* packet type enqueued by the class queues */
	classq_pkt_type_t       fsw_classq_enq_ptype;
	boolean_t               fsw_classq_enabled;

	/* packet copy routines */
	pkt_copy_from_pkt_t     *fsw_pkt_copy_from_pkt;
	pkt_copy_from_mbuf_t    *fsw_pkt_copy_from_mbuf;
	pkt_copy_to_mbuf_t      *fsw_pkt_copy_to_mbuf;

	uint8_t                 fsw_frame_headroom;
	uint32_t                fsw_src_lla_gencnt;
	uint32_t                fsw_pending_nonviable;
	uint32_t                fsw_low_power_gencnt;

	/* The following are protected by fsw_lock. */
	struct flow_mgr         *fsw_flow_mgr;
	netagent_session_t      fsw_agent_session;
	uuid_t                  fsw_agent_uuid;
	struct ifnet            *fsw_ifp;        /* host interface */
	struct nexus_adapter    *fsw_nifna;      /* netif adapter */
	uint32_t                fsw_state_flags; /* FSW_STATEF_* */

	union {
		uint64_t _buf[1];
		uint8_t _eth_src[ETHER_ADDR_LEN];
	} __fsw_slladdr __attribute((aligned(sizeof(uint64_t))));

#define fsw_slla                 __fsw_slladdr._buf
#define fsw_ether_shost          __fsw_slladdr._eth_src

	int (*fsw_resolve)(struct nx_flowswitch *, struct flow_route *,
	    struct __kern_packet *);
	void (*fsw_frame)(struct nx_flowswitch *, struct flow_route *,
	    struct __kern_packet *);
	sa_family_t (*fsw_demux)(struct nx_flowswitch *,
	    struct __kern_packet *);

	struct fsw_stats        fsw_stats;

	/*
	 * The host interface attachment to the flowswitch (fsw_ifp), as well
	 * as the netagent registration, are guarded by the flowswitch's RW
	 * lock.  During fsw_flow_bind() time, we need to make sure they are
	 * valid before proceeding forward, but holding that RW lock across
	 * the routine is not possible since the thread may block if there
	 * are other threads performing fsw_flow_{bind,unbind} on the same
	 * flow owner bucket.  To prevent fsw_dtor() from happening while
	 * fsw_flow_bind() is in progress, we need to have it wait until all
	 * pending flow binds are done.  To do this we add a busy counter
	 * incremented at flow bind time, and use the lock for synchronization.
	 */
	decl_lck_mtx_data(, fsw_detach_barrier_lock);
	uint32_t                fsw_detach_flags;        /* see fsw_DETACHF_* */
	uint32_t                fsw_detach_barriers;
	uint32_t                fsw_detach_waiters;

	u_int                   fsw_ifp_dlt;

	void (*fsw_ctor)(struct nx_flowswitch *, struct flow_route *);

	/* store stats from na that is going to be deactivated */
	struct __nx_stats_fsw   *fsw_closed_na_stats;

	/* ip fragments manager */
	struct fsw_ip_frag_mgr  *fsw_ipfm;

	struct skoid            fsw_skoid;

	/* input network emulator */
	struct netem            *fsw_input_netem;

	struct kern_channel     *fsw_dev_ch;
	struct kern_channel     *fsw_host_ch;

	/*
	 * The reaper thread gets scheduled on-demand, whenever there
	 * is any lingering flow entry needing to be freed or becoming
	 * nonviable.  Access is protected by fsw_reap_lock.
	 */
	decl_lck_mtx_data(, fsw_reap_lock);
	uint32_t                fsw_reap_flags;  /* see fsw_REAPF_* */
	uint32_t                fsw_reap_requests;
	struct thread           *fsw_reap_thread;
	char                    fsw_reap_name[MAXTHREADNAMESIZE];

	uint64_t                fsw_reap_last;
	uint64_t                fsw_drain_channel_chk_last;
	uint64_t                fsw_drain_netif_chk_last;

	decl_lck_mtx_data(, fsw_linger_lock);
	struct flow_entry_linger_head fsw_linger_head;
	uint32_t                fsw_linger_cnt;
};

#define NX_FSW_PRIVATE(_nx) ((struct nx_flowswitch *)(_nx)->nx_arg)

#define FSW_RWINIT(_fsw)                \
	lck_rw_init(&(_fsw)->fsw_lock, &nexus_lock_group, &nexus_lock_attr)
#define FSW_WLOCK(_fsw)                 \
	lck_rw_lock_exclusive(&(_fsw)->fsw_lock)
#define FSW_WUNLOCK(_fsw)               \
	lck_rw_unlock_exclusive(&(_fsw)->fsw_lock)
#define FSW_WLOCKTORLOCK(_fsw)          \
	lck_rw_lock_exclusive_to_shared(&(_fsw)->fsw_lock)
#define FSW_RLOCK(_fsw)                 \
	lck_rw_lock_shared(&(_fsw)->fsw_lock)
#define FSW_RLOCKTOWLOCK(_fsw)          \
	lck_rw_lock_shared_to_exclusive(&(_fsw)->fsw_lock)
#define FSW_RTRYLOCK(_fsw)              \
	lck_rw_try_lock(&(_fsw)->fsw_lock, LCK_RW_TYPE_SHARED)
#define FSW_RUNLOCK(_fsw)               \
	lck_rw_unlock_shared(&(_fsw)->fsw_lock)
#define FSW_UNLOCK(_fsw)                \
	lck_rw_done(&(_fsw)->fsw_lock)
#define FSW_RWDESTROY(_fsw)             \
	lck_rw_destroy(&(_fsw)->fsw_lock, &nexus_lock_group)
#define FSW_WLOCK_ASSERT_HELD(_fsw)     \
	LCK_RW_ASSERT(&(_fsw)->fsw_lock, LCK_RW_ASSERT_EXCLUSIVE)
#define FSW_RLOCK_ASSERT_HELD(_fsw)     \
	LCK_RW_ASSERT(&(_fsw)->fsw_lock, LCK_RW_ASSERT_SHARED)
#define FSW_LOCK_ASSERT_HELD(_fsw)      \
	LCK_RW_ASSERT(&(_fsw)->fsw_lock, LCK_RW_ASSERT_HELD)

extern struct nxdom nx_flowswitch_dom_s;
extern struct kern_nexus_domain_provider nx_fsw_prov_s;

SYSCTL_DECL(_kern_skywalk_flowswitch);

/* functions used by external modules to interface with flow switch */
__BEGIN_DECLS
extern int nx_fsw_na_find(struct kern_nexus *, struct kern_channel *,
    struct chreq *, struct nxbind *, struct proc *, struct nexus_adapter **,
    boolean_t);
extern boolean_t nx_fsw_dom_port_is_reserved(struct kern_nexus *nx,
    nexus_port_t nx_port);
extern int nx_fsw_netagent_add(struct kern_nexus *nx);
extern int nx_fsw_netagent_remove(struct kern_nexus *nx);
extern void nx_fsw_netagent_update(struct kern_nexus *nx);
extern void fsw_devna_rx(struct nexus_adapter *, struct __kern_packet *,
    struct nexus_pkt_stats *);
extern struct nx_flowswitch *fsw_ifp_to_fsw(struct ifnet *);

__END_DECLS
#endif /* CONFIG_NEXUS_FLOWSWITCH */
#endif /* _SKYWALK_NEXUS_FLOWSWITCH_H_ */
