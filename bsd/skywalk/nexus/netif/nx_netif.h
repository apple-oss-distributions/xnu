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

#ifndef _SKYWALK_NEXUS_NETIF_H_
#define _SKYWALK_NEXUS_NETIF_H_

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/nexus_pktq.h>

#if CONFIG_NEXUS_NETIF

#define NEXUS_PROVIDER_NET_IF           "com.apple.nexus.netif"

#define NX_NETIF_MAXPORTS       128
#define NX_NETIF_EVENT_RING_NUM      1     /* number of event rings */
#define NX_NETIF_EVENT_RING_SIZE     32    /* default event ring size */

struct netif_filter {
	STAILQ_ENTRY(netif_filter) nf_link;
	nexus_port_t            nf_port;
	uint32_t                nf_refcnt;
	void                    *nf_cb_arg;
	errno_t                 (*nf_cb_func)(void *,
	    struct __kern_packet *, uint32_t);
};
STAILQ_HEAD(netif_filter_head, netif_filter);

struct netif_flow_desc {
	uint16_t        fd_ethertype;
	struct in6_addr fd_laddr;
	struct in6_addr fd_raddr;
};

struct netif_port_info {
	struct nx_port_info_header npi_hdr;
	struct netif_flow_desc  npi_fd;
};

struct netif_flow {
	SLIST_ENTRY(netif_flow) nf_link;
	SLIST_ENTRY(netif_flow) nf_table_link;
	nexus_port_t            nf_port;
	uint32_t                nf_refcnt;
	struct netif_flow_desc  nf_desc;
	void                    *nf_cb_arg;
	errno_t                 (*nf_cb_func)(void *,
	    void *, uint32_t);
};

typedef enum {
	FT_TYPE_ETHERTYPE,
	FT_TYPE_IPV6_ULA
} netif_flowtable_type_t;

struct netif_flowtable {
	struct netif_flowtable_ops      *ft_ops;
	void                            *ft_internal;
};

typedef int netif_flow_lookup_t(struct netif_flowtable *,
    struct __kern_packet *, uint32_t, struct netif_flow **);
typedef boolean_t netif_flow_match_t(struct netif_flow_desc *,
    struct netif_flow_desc *);
typedef int netif_flow_info_t(struct __kern_packet *,
    struct netif_flow_desc *, uint32_t);
typedef int netif_flow_insert_t(struct netif_flowtable *,
    struct netif_flow *);
typedef void netif_flow_remove_t(struct netif_flowtable *,
    struct netif_flow *);
typedef struct netif_flowtable *netif_flow_table_alloc_t(
	struct netif_flowtable_ops *);
typedef void netif_flow_table_free_t(struct netif_flowtable *);

struct netif_flowtable_ops {
	netif_flow_lookup_t           *nfo_lookup;
	netif_flow_match_t            *nfo_match;
	netif_flow_info_t             *nfo_info;
	netif_flow_insert_t           *nfo_insert;
	netif_flow_remove_t           *nfo_remove;
	netif_flow_table_alloc_t      *nfo_table_alloc;
	netif_flow_table_free_t       *nfo_table_free;
};

SLIST_HEAD(netif_flow_head, netif_flow);
struct nexus_netif_adapter {
	/*
	 * This is an overlay structure on nexus_adapter;
	 * make sure it contains 'up' as the first member.
	 */
	struct nexus_adapter      nifna_up;
	struct nx_netif           *nifna_netif;

	struct nx_netif_mit       *nifna_tx_mit;
	struct nx_netif_mit       *nifna_rx_mit;

	/*
	 * XXX For filter or vpna only
	 */
	union {
		struct netif_filter     *nifna_filter;
		struct netif_flow       *nifna_flow;
	};
};

struct netif_queue {
	decl_lck_mtx_data(, nq_lock);
	struct netif_qset    *nq_qset; /* backpointer to parent netif qset */
	struct pktq          nq_pktq;
	void                 *nq_ctx;
	kern_packet_svc_class_t nq_svc; /* service class of TX queue */
	uint16_t             nq_flags;
}__attribute__((aligned(sizeof(uint64_t))));

/* values for nq_flags */
#define NETIF_QUEUE_EXT_INITED   0x0001 /* nxnpi_queue_init() succeeded */
#define NETIF_QUEUE_IS_RX        0x0002 /* RX queue, else TX */

#define _NETIF_QSET_QUEUE(_p, _n)    \
    (struct netif_queue *)(void *)((uint8_t *)((_p)->nqs_driver_queues) + \
    ((_n) * sizeof(struct netif_queue)))
#define NETIF_QSET_RX_QUEUE(_p, _n)    _NETIF_QSET_QUEUE(_p, _n)
#define NETIF_QSET_TX_QUEUE(_p, _n)    \
    _NETIF_QSET_QUEUE(_p, (_p)->nqs_num_rx_queues + (_n))

/* the top 32 bits are unused for now */
#define NETIF_QSET_ID_ENCODE(llink_id_internal, qset_idx) \
    ((((llink_id_internal) << 16) | (qset_idx)) & 0xffffffff)

struct netif_qset {
	struct netif_llink         *nqs_llink; /* backpointer to parent logical link */
	struct ifclassq            *nqs_ifcq;
	SLIST_ENTRY(netif_qset)    nqs_list;
	void                       *nqs_ctx; /* context provided by driver */
	uint64_t                   nqs_id;  /* queue set identifier */
	uint8_t                    nqs_idx; /* queue set index */
	uint16_t                   nqs_flags;
	uint8_t                    nqs_num_rx_queues;
	uint8_t                    nqs_num_tx_queues;
	/*
	 * nq_queues will be organized as:
	 * nq_queues[0..nq_num_rx_queues-1] will hold RX queues.
	 * nq_queues[nq_num_rx_queues..nq_num_tx_queues-1] will hold TX queues.
	 */
	struct netif_queue         nqs_driver_queues[0]
	__attribute__((aligned(sizeof(uint64_t))));
};

/* values for nqs_flags */
#define NETIF_QSET_FLAG_DEFAULT     0x0001 /* default queue set of the logical link */
#define NETIF_QSET_FLAG_AQM         0x0002 /* provides AQM */
#define NETIF_QSET_FLAG_LOW_LATENCY 0x0004 /* provides low latency service */
#define NETIF_QSET_FLAG_EXT_INITED  0x0008 /* nxnpi_qset_init() succeeded */

#define NETIF_DEFAULT_QSET(_qs)    ((_qs)->nqs_flags & NETIF_QSET_FLAG_DEFAULT)

struct netif_llink {
	struct nx_netif             *nll_nif; /* backpointer to parent netif instance */
	STAILQ_ENTRY(netif_llink)   nll_link;
	SLIST_HEAD(, netif_qset)    nll_qset_list;
	struct netif_qset           *nll_default_qset;
	struct os_refcnt            nll_refcnt;
#define NETIF_LLINK_ID_DEFAULT    0
	kern_nexus_netif_llink_id_t nll_link_id;
	uint16_t                    nll_link_id_internal;
	uint16_t                    nll_qset_cnt;
	uint8_t                     nll_state;
	uint8_t                     nll_flags;
	void                        *nll_ctx; /* context provided by driver */
};
STAILQ_HEAD(netif_llink_head, netif_llink);

/* values for nll_flags */
#define NETIF_LLINK_FLAG_DEFAULT    0x1 /* default logical link */

/* values for nll_state */
#define NETIF_LLINK_STATE_INIT         0x1 /* Intialized and ready for use */
#define NETIF_LLINK_STATE_DESTROYED    0x2 /* not available for use */

#define NETIF_DEFAULT_LLINK(_ll)  ((_ll)->nll_flags & NETIF_LLINK_FLAG_DEFAULT)

SLIST_HEAD(netif_agent_flow_head, netif_agent_flow);
struct netif_agent_flow {
	SLIST_ENTRY(netif_agent_flow) naf_link;
	uuid_t                  naf_flow_uuid;
	uuid_t                  naf_bind_key;
	nexus_port_t            naf_nx_port;
	uint16_t                naf_flags;
	pid_t                   naf_pid;
	union sockaddr_in_4_6   naf_daddr;
	union sockaddr_in_4_6   naf_saddr;
};

#define NIFNA(_na)       ((struct nexus_netif_adapter *)(_na))

/* nif_flags */
/*
 * This is named differently from the flow classification rule
 * (IPV6 ULA) because this gives us the flexibility of using
 * different types of classification in the future.
 */
#define NETIF_FLAG_LOW_LATENCY          0x00000001
#define NETIF_FLAG_COMPAT               0x00000002
#define NETIF_FLAG_LLINK_INITIALIZED    0x00000004
#define NETIF_IS_LOW_LATENCY(n) \
    (((n)->nif_flags & NETIF_FLAG_LOW_LATENCY) != 0)
#define NETIF_IS_COMPAT(n) \
    (((n)->nif_flags & NETIF_FLAG_COMPAT) != 0)
#define NETIF_LLINK_ENABLED(n) \
    (((n)->nif_flags & NETIF_FLAG_LLINK_INITIALIZED) != 0)
#define NETIF_DEFAULT_DROP_ENABLED(n) \
    (nx_netif_filter_default_drop != 0 && \
    (((n)->nif_filter_flags & NETIF_FILTER_FLAG_INITIALIZED) != 0))

/* nif_agent_flags */
#define NETIF_AGENT_FLAG_REGISTERED     0x00000001
#define NETIF_AGENT_FLAG_ADDED          0x00000002

/* nif_filter_flags */
#define NETIF_FILTER_FLAG_INITIALIZED   0x00000001
#define NETIF_FILTER_FLAG_ENABLED       0x00000002

/* nif_flow_flags */
#define NETIF_FLOW_FLAG_INITIALIZED     0x00000001
#define NETIF_FLOW_FLAG_ENABLED         0x00000002

/* nif_llink_flags */
#define NETIF_LLINK_FLAG_INITIALIZED    0x00000001

/* Used by netif_hwna_set_mode() */
typedef enum {
	NETIF_MODE_NONE,
	NETIF_MODE_FSW,
	NETIF_MODE_LLW
} netif_mode_t;

/*
 * nx_netif is a descriptor for a netif nexus instance.
 */
struct nx_netif {
	decl_lck_rw_data(, nif_lock);
	struct kern_nexus       *nif_nx;

	struct nxbind           *nif_dev_nxb;
	struct nxbind           *nif_host_nxb;
	uuid_t                  nif_uuid;       /* attachment UUID */
	struct netif_stats      nif_stats;
	uint32_t                nif_flags;
	struct os_refcnt        nif_refcnt;

	decl_lck_mtx_data(, nif_agent_lock);
	struct netif_agent_flow_head nif_agent_flow_list;
	uint32_t                nif_agent_flow_cnt;
	uint32_t                nif_agent_flags;
	netagent_session_t      nif_agent_session;
	uuid_t                  nif_agent_uuid;

	uint32_t                nif_hwassist;
	uint32_t                nif_capabilities;
	uint32_t                nif_capenable;
	uint64_t                nif_input_rate; /* device input rate limit */

	struct ifnet            *nif_ifp;
	struct nx_flowswitch    *nif_fsw;       /* attached flowswitch nexus */
	struct sk_nexusadv      *nif_fsw_nxadv; /* flowswitch nexus advisory */
	struct netif_nexus_advisory *nif_netif_nxadv; /* netif nexus advisory */

	/* packet-mbuf copy routines */
	pkt_copy_from_mbuf_t    *nif_pkt_copy_from_mbuf;
	pkt_copy_to_mbuf_t      *nif_pkt_copy_to_mbuf;
	pkt_copy_from_pkt_t     *nif_pkt_copy_from_pkt;

	/* packet filtering */
	decl_lck_mtx_data(, nif_filter_lock);
	uint32_t                nif_filter_flags;
	uint32_t                nif_filter_vp_cnt;
	uint32_t                nif_filter_cnt;
	struct kern_pbufpool    *nif_filter_pp;
	struct netif_filter_head nif_filter_list;
	union {
		struct nx_mbq   nif_tx_processed_mbq[MBUF_TC_MAX];
		struct nx_pktq  nif_tx_processed_pktq[KPKT_TC_MAX];
	};

	/* virtual port */
	decl_lck_mtx_data(, nif_flow_lock);
	uint32_t                nif_vp_cnt;
	uint32_t                nif_flow_flags;
	uint32_t                nif_flow_cnt;
	struct netif_flow_head  nif_flow_list;
	struct netif_flowtable  *nif_flow_table;
	struct kern_channel     *nif_hw_ch;
	uint32_t                nif_hw_ch_refcnt;

	/* logical link */
	decl_lck_rw_data(, nif_llink_lock);
	struct kern_nexus_netif_llink_init *nif_default_llink_params;
	struct netif_llink         *nif_default_llink;
	STAILQ_HEAD(, netif_llink) nif_llink_list;
	uint16_t                   nif_llink_cnt;

	/* capability configuration callback function and context */
	kern_nexus_capab_interface_advisory_config_fn_t nif_intf_adv_config;
	void *nif_intf_adv_prov_ctx;

#if (DEVELOPMENT || DEBUG)
	struct skoid            nif_skoid;
#endif /* !DEVELOPMENT && !DEBUG */
};

#define NX_NETIF_PRIVATE(_nx) ((struct nx_netif *)(_nx)->nx_arg)

#define NETIF_RWINIT(_nif)                \
	lck_rw_init(&(_nif)->nif_lock, &nexus_lock_group, &nexus_lock_attr)
#define NETIF_WLOCK(_nif)                 \
	lck_rw_lock_exclusive(&(_nif)->nif_lock)
#define NETIF_WUNLOCK(_nif)               \
	lck_rw_unlock_exclusive(&(_nif)->nif_lock)
#define NETIF_WLOCKTORLOCK(_nif)          \
	lck_rw_lock_exclusive_to_shared(&(_nif)->nif_lock)
#define NETIF_RLOCK(_nif)                 \
	lck_rw_lock_shared(&(_nif)->nif_lock)
#define NETIF_RLOCKTOWLOCK(_nif)          \
	lck_rw_lock_shared_to_exclusive(&(_nif)->nif_lock)
#define NETIF_RTRYLOCK(_nif)              \
	lck_rw_try_lock(&(_nif)->nif_lock, LCK_RW_TYPE_SHARED)
#define NETIF_RUNLOCK(_nif)               \
	lck_rw_unlock_shared(&(_nif)->nif_lock)
#define NETIF_UNLOCK(_nif)                \
	lck_rw_done(&(_nif)->nif_lock)
#define NETIF_RWDESTROY(_nif)             \
	lck_rw_destroy(&(_nif)->nif_lock, &nexus_lock_group)
#define NETIF_WLOCK_ASSERT_HELD(_nif)     \
	LCK_RW_ASSERT(&(_nif)->nif_lock, LCK_RW_ASSERT_EXCLUSIVE)
#define NETIF_RLOCK_ASSERT_HELD(_nif)     \
	LCK_RW_ASSERT(&(_nif)->nif_lock, LCK_RW_ASSERT_SHARED)
#define NETIF_LOCK_ASSERT_HELD(_nif)      \
	LCK_RW_ASSERT(&(_nif)->nif_lock, LCK_RW_ASSERT_HELD)

SYSCTL_DECL(_kern_skywalk_netif);

/*
 * Macros to determine if an interface is skywalk capable or skywalk enabled.
 * See the magic field in struct nexus_adapter.
 */
#define SKYWALK_CAPABLE(ifp)                                            \
	(NA(ifp) != NULL && (ifnet_capabilities_supported(ifp) & IFCAP_SKYWALK))

#define SKYWALK_SET_CAPABLE(ifp) do {                                   \
	ifnet_lock_exclusive(ifp);                                      \
	(ifp)->if_capabilities |= IFCAP_SKYWALK;                        \
	(ifp)->if_capenable |= IFCAP_SKYWALK;                           \
	ifnet_lock_done(ifp);                                           \
} while (0)

#define SKYWALK_CLEAR_CAPABLE(ifp) do {                                 \
	ifnet_lock_exclusive(ifp);                                      \
	(ifp)->if_capabilities &= ~IFCAP_SKYWALK;                       \
	(ifp)->if_capenable &= ~IFCAP_SKYWALK;                          \
	ifnet_lock_done(ifp);                                           \
} while (0)

#define SKYWALK_NATIVE(ifp)                                             \
	((ifp)->if_eflags & IFEF_SKYWALK_NATIVE)

typedef enum {
	MIT_MODE_SIMPLE,
	MIT_MODE_ADVANCED_STATIC,
	MIT_MODE_ADVANCED_DYNAMIC,
} mit_mode_t;

/*
 * Mitigation support.
 */
struct mit_cfg_tbl {
	uint32_t cfg_plowat;            /* packets low watermark */
	uint32_t cfg_phiwat;            /* packets high watermark */
	uint32_t cfg_blowat;            /* bytes low watermark */
	uint32_t cfg_bhiwat;            /* bytes high watermark */
	uint32_t cfg_ival;              /* delay interval (in microsecond) */
};

#define NETIF_MIT_CFG_TBL_MAX_CFG       5

struct nx_netif_mit {
	decl_lck_spin_data(, mit_lock);
	volatile struct __kern_channel_ring *mit_ckr;  /* kring backpointer */
	uint32_t        mit_flags;
	uint32_t        mit_requests;
	uint32_t        mit_interval;

	/*
	 * Adaptive mitigation.
	 */
	uint32_t        mit_cfg_idx_max;        /* highest config selector */
	uint32_t        mit_cfg_idx;            /* current config selector */
	const struct mit_cfg_tbl *mit_cfg;      /* current config mapping */
	mit_mode_t      mit_mode;               /* current mode */
	uint32_t        mit_packets_avg;        /* average # of packets */
	uint32_t        mit_packets_min;        /* smallest # of packets */
	uint32_t        mit_packets_max;        /* largest # of packets */
	uint32_t        mit_bytes_avg;          /* average # of bytes */
	uint32_t        mit_bytes_min;          /* smallest # of bytes */
	uint32_t        mit_bytes_max;          /* largest # of bytes */

	struct pktcntr  mit_sstats;             /* pkts & bytes per sampling */
	struct timespec mit_mode_holdtime;      /* mode holdtime in nsec */
	struct timespec mit_mode_lasttime;      /* last mode change time nsec */
	struct timespec mit_sample_time;        /* sampling holdtime in nsec */
	struct timespec mit_sample_lasttime;    /* last sampling time in nsec */
	struct timespec mit_start_time;         /* time of start work in nsec */

	struct thread   *mit_thread;
	char            mit_name[MAXTHREADNAMESIZE];

	const struct ifnet      *mit_netif_ifp;
	/* interface-specific mitigation table */
	struct mit_cfg_tbl mit_tbl[NETIF_MIT_CFG_TBL_MAX_CFG];

#if (DEVELOPMENT || DEBUG)
	struct skoid    mit_skoid;
#endif /* !DEVELOPMENT && !DEBUG */
};

#define NETIF_MITF_INITIALIZED  0x00000001      /* has been initialized */
#define NETIF_MITF_SAMPLING     0x00000002      /* busy sampling stats */
#define NETIF_MITF_SIMPLE       0x00000004      /* no stats, no delay */
#define NETIF_MITF_READY        0x10000000      /* thread is ready */
#define NETIF_MITF_RUNNING      0x20000000      /* thread is running */
#define NETIF_MITF_TERMINATING  0x40000000      /* thread is terminating */
#define NETIF_MITF_TERMINATED   0x80000000      /* thread is terminated */

#define MIT_SPIN_LOCK(_mit)                     \
	lck_spin_lock(&(_mit)->mit_lock)
#define MIT_SPIN_LOCK_ASSERT_HELD(_mit)         \
	LCK_SPIN_ASSERT(&(_mit)->mit_lock, LCK_ASSERT_OWNED)
#define MIT_SPIN_LOCK_ASSERT_NOTHELD(_mit)      \
	LCK_SPIN_ASSERT(&(_mit)->mit_lock, LCK_ASSERT_NOTOWNED)
#define MIT_SPIN_UNLOCK(_mit)                   \
	lck_spin_unlock(&(_mit)->mit_lock)

extern kern_allocation_name_t skmem_tag_netif_filter;
extern kern_allocation_name_t skmem_tag_netif_flow;
extern kern_allocation_name_t skmem_tag_netif_agent_flow;
extern kern_allocation_name_t skmem_tag_netif_llink;
extern kern_allocation_name_t skmem_tag_netif_qset;

__BEGIN_DECLS
extern struct nxdom nx_netif_dom_s;
extern struct kern_nexus_domain_provider nx_netif_prov_s;

extern struct nx_netif *nx_netif_alloc(zalloc_flags_t);
extern void nx_netif_free(struct nx_netif *);
extern void nx_netif_retain(struct nx_netif *);
extern void nx_netif_release(struct nx_netif *);

extern int nx_netif_dev_krings_create(struct nexus_adapter *,
    struct kern_channel *);
extern void nx_netif_dev_krings_delete(struct nexus_adapter *,
    struct kern_channel *, boolean_t);
extern int nx_netif_na_find(struct kern_nexus *, struct kern_channel *,
    struct chreq *, struct nxbind *, struct proc *, struct nexus_adapter **,
    boolean_t create);
extern int nx_netif_na_special(struct nexus_adapter *,
    struct kern_channel *, struct chreq *, nxspec_cmd_t);
extern int nx_netif_na_special_common(struct nexus_adapter *,
    struct kern_channel *, struct chreq *, nxspec_cmd_t);
extern int nx_netif_common_intr(struct __kern_channel_ring *, struct proc *,
    uint32_t, uint32_t *);

extern int nx_netif_prov_init(struct kern_nexus_domain_provider *);
extern int nx_netif_prov_params(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS]);
extern int nx_netif_prov_mem_new(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nexus_adapter *);
extern void nx_netif_prov_fini(struct kern_nexus_domain_provider *);
extern int nx_netif_prov_config(struct kern_nexus_domain_provider *,
    struct kern_nexus *, struct nx_cfg_req *, int, struct proc *,
    kauth_cred_t);
extern int nx_netif_prov_nx_ctor(struct kern_nexus *);
extern void nx_netif_prov_nx_dtor(struct kern_nexus *);
extern int nx_netif_prov_nx_mem_info(struct kern_nexus *,
    struct kern_pbufpool **, struct kern_pbufpool **);
extern size_t nx_netif_prov_nx_mib_get(struct kern_nexus *nx,
    struct nexus_mib_filter *, void *, size_t, struct proc *);
extern int nx_netif_prov_nx_stop(struct kern_nexus *);

extern void nx_netif_reap(struct nexus_netif_adapter *, struct ifnet *,
    uint32_t, boolean_t);

extern void nx_netif_copy_stats(struct nexus_netif_adapter *,
    struct if_netif_stats *);
extern struct nexus_netif_adapter * na_netif_alloc(zalloc_flags_t);
extern void na_netif_free(struct nexus_adapter *);
extern void na_netif_finalize(struct nexus_netif_adapter *, struct ifnet *);
extern int nx_netif_interface_advisory_report(struct nexus_adapter *,
    const struct ifnet_interface_advisory *);
extern void nx_netif_config_interface_advisory(struct kern_nexus *, bool);

/*
 * netif netagent API
 */
extern void nx_netif_agent_init(struct nx_netif *);
extern void nx_netif_agent_fini(struct nx_netif *);
extern int nx_netif_netagent_flow_add(struct nx_netif *, struct nx_flow_req *);
extern int nx_netif_netagent_flow_del(struct nx_netif *, struct nx_flow_req *);

/*
 * "Interrupt" mitigation API. This is used by the netif adapter to reduce
 * the number of "interrupt" requests/wakeup to clients on incoming packets.
 */
extern void nx_netif_mit_init(struct nx_netif *, const struct ifnet *,
    struct nx_netif_mit *, struct __kern_channel_ring *, boolean_t);
extern void nx_netif_mit_cleanup(struct nx_netif_mit *);
extern int nx_netif_mit_tx_intr(struct __kern_channel_ring *, struct proc *,
    uint32_t, uint32_t *);
extern int nx_netif_mit_rx_intr(struct __kern_channel_ring *, struct proc *,
    uint32_t, uint32_t *);

/*
 * Interface filter API
 */
#define NETIF_FILTER_RX         0x0001
#define NETIF_FILTER_TX         0x0002
#define NETIF_FILTER_SOURCE     0x0004
#define NETIF_FILTER_INJECT     0x0008
extern errno_t nx_netif_filter_inject(struct nexus_netif_adapter *,
    struct netif_filter *, struct __kern_packet *, uint32_t);
extern errno_t nx_netif_filter_add(struct nx_netif *, nexus_port_t, void *,
    errno_t (*)(void *, struct __kern_packet *, uint32_t),
    struct netif_filter **);
extern errno_t nx_netif_filter_remove(struct nx_netif *, struct netif_filter *);
extern void nx_netif_filter_init(struct nx_netif *);
extern void nx_netif_filter_fini(struct nx_netif *);
extern void nx_netif_filter_enable(struct nx_netif *);
extern void nx_netif_filter_disable(struct nx_netif *);

/*
 * These callbacks are invoked when a packet chain has traversed the full
 * filter chain.
 */
extern errno_t nx_netif_filter_rx_cb(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);
extern errno_t nx_netif_filter_tx_cb(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);

/*
 * These are called by nx_netif_filter_tx_cb() to feed filtered packets
 * back to driver.
 */
extern errno_t
    nx_netif_filter_tx_processed_mbuf_enqueue(struct nexus_netif_adapter *,
    mbuf_svc_class_t, struct mbuf *);
extern errno_t
    nx_netif_filter_tx_processed_pkt_enqueue(struct nexus_netif_adapter *,
    kern_packet_svc_class_t, struct __kern_packet *);

/*
 * Called by nx_netif_na_find() to create a filter nexus adapter.
 */
extern int netif_filter_na_create(struct kern_nexus *, struct chreq *,
    struct nexus_adapter **);

/*
 * Callbacks from ifnet
 */
extern errno_t nx_netif_native_tx_dequeue(struct nexus_netif_adapter *,
    uint32_t, uint32_t, uint32_t, classq_pkt_t *, classq_pkt_t *,
    uint32_t *, uint32_t *, boolean_t, errno_t);
extern errno_t nx_netif_native_tx_get_len(struct nexus_netif_adapter *,
    uint32_t, uint32_t *, uint32_t *, errno_t);
extern errno_t nx_netif_compat_tx_dequeue(struct nexus_netif_adapter *,
    uint32_t, uint32_t, uint32_t, classq_pkt_t *, classq_pkt_t *,
    uint32_t *, uint32_t *, boolean_t, errno_t);
extern errno_t nx_netif_compat_tx_get_len(struct nexus_netif_adapter *,
    uint32_t, uint32_t *, uint32_t *, errno_t);

/*
 * doorbell dequeue tunable
 */
extern uint32_t nx_netif_doorbell_max_dequeue;

/*
 * Default drop tunable
 */
extern uint32_t nx_netif_filter_default_drop;

/*
 * Flow API
 */
#define NETIF_FLOW_SOURCE       0x0001
#define NETIF_FLOW_INJECT       0x0002
#define NETIF_FLOW_OUTBOUND     0x0004 /* Assumes inbound if flag is missing */

extern errno_t nx_netif_demux(struct nexus_netif_adapter *,
    struct __kern_packet *, struct __kern_packet **, uint32_t);
extern errno_t nx_netif_flow_add(struct nx_netif *, nexus_port_t,
    struct netif_flow_desc *, void *, errno_t (*)(void *, void *, uint32_t),
    struct netif_flow **);
extern errno_t nx_netif_flow_remove(struct nx_netif *, struct netif_flow *);
extern void nx_netif_flow_init(struct nx_netif *);
extern void nx_netif_flow_fini(struct nx_netif *);
extern void nx_netif_flow_enable(struct nx_netif *);
extern void nx_netif_flow_disable(struct nx_netif *);
extern void nx_netif_snoop(struct nx_netif *, struct __kern_packet *,
    boolean_t);
extern boolean_t nx_netif_validate_macaddr(struct nx_netif *,
    struct __kern_packet *, uint32_t);
extern boolean_t nx_netif_flow_match(struct nx_netif *, struct __kern_packet *,
    struct netif_flow *, uint32_t);
extern struct netif_flow * nx_netif_flow_classify(struct nx_netif *,
    struct __kern_packet *, uint32_t);
extern void nx_netif_flow_release(struct nx_netif *, struct netif_flow *);
extern int netif_vp_na_create(struct kern_nexus *, struct chreq *,
    struct nexus_adapter **);

/*
 * Disable all checks on inbound/outbound packets on VP adapters
 */
extern uint32_t nx_netif_vp_accept_all;

/*
 * Utility functions
 */
extern struct __kern_packet *nx_netif_alloc_packet(struct kern_pbufpool *,
    uint32_t, kern_packet_t *);
extern void nx_netif_free_packet(struct __kern_packet *);
extern void nx_netif_free_packet_chain(struct __kern_packet *, int *);

#define NETIF_CONVERT_RX        0x0001
#define NETIF_CONVERT_TX        0x0002

extern struct __kern_packet *
    nx_netif_mbuf_to_filter_pkt_chain(struct nexus_netif_adapter *,
    struct mbuf *, uint32_t);
extern struct mbuf *
    nx_netif_filter_pkt_to_mbuf_chain(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);

extern struct __kern_packet *
    nx_netif_pkt_to_filter_pkt(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);
extern struct __kern_packet *
    nx_netif_pkt_to_filter_pkt_chain(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);
extern struct __kern_packet *
    nx_netif_filter_pkt_to_pkt_chain(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);

extern struct mbuf *
    nx_netif_pkt_to_mbuf(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);
extern struct __kern_packet *
    nx_netif_pkt_to_pkt(struct nexus_netif_adapter *,
    struct __kern_packet *, uint32_t);

extern void nx_netif_mbuf_chain_info(struct mbuf *,
    struct mbuf **, uint32_t *, uint32_t *);
extern void nx_netif_pkt_chain_info(struct __kern_packet *,
    struct __kern_packet **, uint32_t *, uint32_t *);
extern int nx_netif_get_max_mtu(ifnet_t, uint32_t *);

extern void nx_netif_mit_config(struct nexus_netif_adapter *,
    boolean_t *, boolean_t *, boolean_t *, boolean_t *);

extern void nx_netif_vp_region_params_adjust(struct nexus_adapter *,
    struct skmem_region_params *);

extern void nx_netif_pktap_output(ifnet_t, int, struct __kern_packet *);

extern int netif_rx_notify_default(struct __kern_channel_ring *,
    struct proc *p, uint32_t);
extern int netif_rx_notify_fast(struct __kern_channel_ring *,
    struct proc *p, uint32_t);
extern int netif_llw_rx_notify_default(struct __kern_channel_ring *,
    struct proc *p, uint32_t);
extern int netif_llw_rx_notify_fast(struct __kern_channel_ring *,
    struct proc *p, uint32_t);
extern void netif_receive(struct nexus_netif_adapter *,
    struct __kern_packet *, struct nexus_pkt_stats *);

#define NETIF_XMIT_FLAG_CHANNEL 0x0001
#define NETIF_XMIT_FLAG_HOST    0x0002
extern void netif_transmit(struct ifnet *, uint32_t);
extern int netif_ring_tx_refill(const kern_channel_ring_t,
    uint32_t, uint32_t, boolean_t, boolean_t *, boolean_t);
extern void netif_hwna_set_mode(struct nexus_adapter *, netif_mode_t,
    void (*)(struct nexus_adapter *, struct __kern_packet *,
    struct nexus_pkt_stats *));
extern void netif_hwna_clear_mode(struct nexus_adapter *);

/*
 * rxpoll functions
 */
extern errno_t netif_rxpoll_set_params(struct ifnet *,
    struct ifnet_poll_params *, boolean_t locked);
extern void netif_rxpoll_compat_thread_func(void *, wait_result_t);

/*
 * GSO functions
 */
extern int netif_gso_dispatch(struct ifnet *ifp, struct mbuf *m);
extern void netif_gso_init(void);
extern void netif_gso_fini(void);

/*
 * Logical link functions
 */
extern void nx_netif_llink_module_init(void);
extern void nx_netif_llink_module_fini(void);
extern void nx_netif_llink_retain(struct netif_llink *);
extern void nx_netif_llink_release(struct netif_llink **);
extern void nx_netif_qset_retain(struct netif_qset *);
extern void nx_netif_qset_release(struct netif_qset **);
extern void nx_netif_llink_init(struct nx_netif *);
extern void nx_netif_llink_fini(struct nx_netif *);
extern struct netif_qset * nx_netif_find_qset(struct nx_netif *, uint64_t);
extern struct netif_qset * nx_netif_get_default_qset_noref(struct nx_netif *);
extern int netif_qset_enqueue(struct netif_qset *, struct __kern_packet *,
    struct __kern_packet *, uint32_t, uint32_t, uint32_t *, uint32_t *);
extern int nx_netif_default_llink_config(struct nx_netif *,
    struct kern_nexus_netif_llink_init *);
extern void nx_netif_llink_config_free(struct nx_netif *);
extern int nx_netif_llink_ext_init_default_queues(struct kern_nexus *);
extern void nx_netif_llink_ext_fini_default_queues(struct kern_nexus *);
extern int nx_netif_validate_llink_config(struct kern_nexus_netif_llink_init *,
    bool);
extern int nx_netif_llink_add(struct nx_netif *,
    struct kern_nexus_netif_llink_init *, struct netif_llink **);
extern int nx_netif_llink_remove(struct nx_netif *,
    kern_nexus_netif_llink_id_t);

__END_DECLS
#endif /* CONFIG_NEXUS_NETIF */
#include <skywalk/nexus/netif/nx_netif_compat.h>
#include <skywalk/nexus/netif/nx_netif_host.h>
#endif /* _SKYWALK_NEXUS_NETIF_H_ */
