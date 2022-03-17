/*
 * Copyright (c) 2016-2021 Apple Inc. All rights reserved.
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
 * Once a packet is classified, it goes through checks to see if there
 * is a matching flow entry in the flow table.  The key used to search
 * the entry is composed of the fields contained in struct flow_ptrs.
 *
 * Flow entry insertion and deletion to the flow table, on behalf of
 * the owning client process, requires the use of the rule ID (UUID)
 * as the search key.
 *
 * Because of the above, each flow entry simultaneously exists in two
 * respective trees: flow_entry_tree and flow_entry_id_tree.
 *
 * Using a single RW lock to protect the two trees is simple, but the
 * data path performance is impacted during flow insertion and deletion,
 * especially as the number of client processes and flows grow.
 *
 * To solve that, we deploy the following scheme:
 *
 * Given that the flow_entry_tree is searched on a per-packet basis,
 * we break it down into a series of trees, each one contained within
 * a flow_bucket structure.  The hash from flow_ptrs determines the
 * index of the flow_bucket to search the flow_entry_tree from.
 *
 * The flow_entry_id_tree is searched on each flow insertion and
 * deletion, and similarly we break it down into a series of trees,
 * each contained within a flow_owner_bucket structure. We use the
 * client process ID (pid_t) to determine the bucket index.
 *
 * Each flow_bucket and flow_owner_bucket structure is dynamically
 * created, and is aligned on the CPU cache boundary.  The amount
 * of those buckets is determined by client module at the time the
 * flow manager context is initialized.  This is done to avoid false
 * sharing, especially given that each bucket has its own RW lock.
 */

#ifndef _SKYWALK_NEXUS_FLOWSIWTCH_FLOW_FLOWVAR_H_
#define _SKYWALK_NEXUS_FLOWSIWTCH_FLOW_FLOWVAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/lib/cuckoo_hashtable.h>
#include <skywalk/namespace/netns.h>
#include <skywalk/namespace/protons.h>
#include <skywalk/packet/packet_var.h>
#include <net/flowhash.h>
#include <netinet/ip.h>
#include <netinet/in_stat.h>
#include <netinet/ip6.h>
#include <sys/eventhandler.h>

RB_HEAD(flow_owner_tree, flow_owner);

struct flow_owner_bucket {
	decl_lck_mtx_data(, fob_lock);
	struct flow_owner_tree  fob_owner_head;
	uint16_t                fob_busy_flags;
	uint16_t                fob_open_waiters;
	uint16_t                fob_close_waiters;
	uint16_t                fob_dtor_waiters;
	const size_t            fob_idx;
};

#define FOBF_OPEN_BUSY          0x1     /* flow open monitor */
#define FOBF_CLOSE_BUSY         0x2     /* flow close monitor */
#define FOBF_DEAD               0x4     /* no longer usable */

#define FOB_LOCK(_fob)                  \
	lck_mtx_lock(&(_fob)->fob_lock)
#define FOB_LOCK_SPIN(_fob)             \
	lck_mtx_lock_spin(&(_fob)->fob_lock)
#define FOB_LOCK_CONVERT(_fob)          \
	lck_mtx_convert_spin(&(_fob)->fob_lock)
#define FOB_TRY_LOCK(_fob)              \
	lck_mtx_try_lock(&(_fob)->fob_lock)
#define FOB_LOCK_ASSERT_HELD(_fob)      \
	LCK_MTX_ASSERT(&(_fob)->fob_lock, LCK_MTX_ASSERT_OWNED)
#define FOB_LOCK_ASSERT_NOTHELD(_fob)   \
	LCK_MTX_ASSERT(&(_fob)->fob_lock, LCK_MTX_ASSERT_NOTOWNED)
#define FOB_UNLOCK(_fob)                \
	lck_mtx_unlock(&(_fob)->fob_lock)

RB_HEAD(flow_entry_id_tree, flow_entry);

#define FLOW_PROCESS_NAME_LENGTH        24

struct flow_owner {
	RB_ENTRY(flow_owner)    fo_link;
	struct flow_entry_id_tree fo_flow_entry_id_head;
	const struct flow_owner_bucket *fo_bucket;
	void                    *fo_context;
	pid_t                   fo_pid;
	bool                    fo_nx_port_pid_bound;
	bool                    fo_nx_port_destroyed;
	bool                    fo_low_latency;
	nexus_port_t            fo_nx_port;
	uuid_t                  fo_key;

	struct nexus_adapter *  const fo_nx_port_na;
	struct nx_flowswitch *  const fo_fsw;

	/*
	 * Array of bitmaps to manage the flow advisory table indices.
	 * Currently we are restricting a flow owner to a single nexus
	 * port, so this structure is effectively managing the flow advisory
	 * indices for a port.
	 */
	bitmap_t                *fo_flowadv_bmap;
	uint32_t                fo_flowadv_max;
	uint32_t                fo_num_flowadv;

	/* for debugging */
	char                    fo_name[FLOW_PROCESS_NAME_LENGTH];
};

#define FO_BUCKET(_fo)  \
	__DECONST(struct flow_owner_bucket *, (_fo)->fo_bucket)

RB_PROTOTYPE_SC_PREV(__private_extern__, flow_owner_tree, flow_owner,
    fo_link, fo_cmp);
RB_PROTOTYPE_SC_PREV(__private_extern__, flow_entry_id_tree, flow_entry,
    fe_id_link, fe_id_cmp);

typedef enum {
	/*
	 * TCP states.
	 */
	FT_STATE_CLOSED = 0,            /* closed */
	FT_STATE_LISTEN,                /* listening for connection */
	FT_STATE_SYN_SENT,              /* active, have sent SYN */
	FT_STATE_SYN_RECEIVED,          /* have sent and rcvd SYN */
	FT_STATE_ESTABLISHED,           /* established */
	FT_STATE_CLOSE_WAIT,            /* rcvd FIN, waiting close */
	FT_STATE_FIN_WAIT_1,            /* have sent FIN */
	FT_STATE_CLOSING,               /* exchanged FINs, waiting FIN|ACK */
	FT_STATE_LAST_ACK,              /* rcvd FIN, closed, waiting FIN|ACK */
	FT_STATE_FIN_WAIT_2,            /* closed, FIN is ACK'd */
	FT_STATE_TIME_WAIT,             /* quiet wait after close */

	/*
	 * UDP states.
	 */
	FT_STATE_NO_TRAFFIC = 20,       /* no packet observed */
	FT_STATE_SINGLE,                /* single packet */
	FT_STATE_MULTIPLE,              /* multiple packets */

	FT_STATE_MAX = 255
} flow_track_state_t;

struct flow_track_rtt {
	uint64_t        frtt_timestamp; /* tracked segment timestamp */
	uint64_t        frtt_last;      /* previous net_uptime(rate limiting) */
	uint32_t        frtt_seg_begin; /* tracked segment begin SEQ */
	uint32_t        frtt_seg_end;   /* tracked segment end SEQ */
	uint32_t        frtt_usec;      /* avg RTT in usec */
};

#define FLOWTRACK_RTT_SAMPLE_INTERVAL   2       /* sample ACK RTT every 2 sec */

struct flow_track {
	/*
	 * TCP specific tracking info.
	 */
	uint32_t fse_seqlo;     /* max sequence number sent */
	uint32_t fse_seqhi;     /* max the other end ACKd + win	*/
	uint32_t fse_seqlast;   /* last sequence number (FIN) */
	uint16_t fse_max_win;   /* largest window (pre scaling)	*/
	uint16_t fse_mss;       /* maximum segment size option */
	uint8_t fse_state;      /* active state level (FT_STATE_*) */
	uint8_t fse_wscale;     /* window scaling factor */
	uint16_t fse_flags;     /* FLOWSTATEF_* */
	uint32_t fse_syn_ts;    /* SYN timestamp */
	uint32_t fse_syn_cnt;   /* # of SYNs per second */

	struct flow_track_rtt   fse_rtt;        /* ACK RTT tracking */
#define fse_rtt_usec    fse_rtt.frtt_usec
} __sk_aligned(8);

/* valid values for fse_flags */
#define FLOWSTATEF_WSCALE       0x1     /* fse_wscale is valid */

struct flow_llhdr {
	uint32_t                flh_gencnt;     /* link-layer address gencnt */

	const uint8_t           flh_off;
	const uint8_t           flh_len;
	uint16_t                flh_pad;        /* for future */

	union _flh_u {
		uint64_t        _buf[2];
		struct {
			uint16_t _eth_pad;
			struct ether_header _eth;
		} _eth_padded;
	}  __sk_aligned(8)      _flh;
#define flh_eth_padded          _flh._eth_padded
#define flh_eth                 _flh._eth_padded._eth
};


TAILQ_HEAD(flow_entry_list, flow_entry);

typedef void (*flow_action_t)(struct nx_flowswitch *fsw, struct flow_entry *fe);

struct flow_entry {
	/**** Common Group ****/
	os_refcnt_t             fe_refcnt;
	struct flow_key         fe_key;
	uint32_t                fe_flags;
	uint32_t                fe_key_hash;
	struct cuckoo_node      fe_cnode;

	uuid_t                  fe_uuid __sk_aligned(8);
	nexus_port_t            fe_nx_port;
	uint32_t                fe_laddr_gencnt;
	uint32_t                fe_want_nonviable;
	uint32_t                fe_want_withdraw;
	uint8_t                 fe_transport_protocol;

	/**** Rx Group ****/
	uint16_t                fe_rx_frag_count;
	uint32_t                fe_rx_pktq_bytes;
	struct pktq             fe_rx_pktq;
	TAILQ_ENTRY(flow_entry) fe_rx_link;
	flow_action_t           fe_rx_process;
	uint32_t                fe_rx_largest_msize; /* used for mbuf batch allocation */
	bool                    fe_rx_nodelay;

	/**** Tx Group ****/
	bool                    fe_tx_is_cont_frag;
	uint32_t                fe_tx_frag_id;
	struct pktq             fe_tx_pktq;
	TAILQ_ENTRY(flow_entry) fe_tx_link;
	flow_action_t           fe_tx_process;

	uuid_t                  fe_eproc_uuid __sk_aligned(8);
	flowadv_idx_t           fe_adv_idx;
	kern_packet_svc_class_t fe_svc_class;
	uint32_t                fe_policy_id;   /* policy id matched to flow */

	/**** Misc Group ****/
	struct nx_flowswitch *  const fe_fsw;
	struct ns_token         *fe_port_reservation;
	struct protons_token    *fe_proto_reservation;
	void                    *fe_ipsec_reservation;

	struct flow_track       fe_ltrack;      /* local endpoint state */
	struct flow_track       fe_rtrack;      /* remote endpoint state */

	/*
	 * Flow stats are kept externally stand-alone, refcnt'ed by various
	 * users (e.g. flow_entry, necp_client_flow, etc.)
	 */
	struct flow_stats       *fe_stats;
	struct flow_route       *fe_route;

	RB_ENTRY(flow_entry)    fe_id_link;

	TAILQ_ENTRY(flow_entry) fe_linger_link;
	uint64_t                fe_linger_expire; /* expiration deadline */
	uint32_t                fe_linger_wait;   /* linger time (seconds) */

	pid_t                   fe_pid;
	pid_t                   fe_epid;
	char                    fe_proc_name[FLOW_PROCESS_NAME_LENGTH];
	char                    fe_eproc_name[FLOW_PROCESS_NAME_LENGTH];

	uint32_t                fe_inp_flowhash; /* flowhash for looking up inpcb */

	/* Logical link related information */
	struct netif_qset      *fe_qset;
};

/* valid values for fe_flags */
#define FLOWENTF_INITED         0x00000001 /* {src,dst} states initialized */
#define FLOWENTF_TRACK          0x00000010 /* enable state tracking */
#define FLOWENTF_CONNECTED      0x00000020 /* connected mode */
#define FLOWENTF_LISTENER       0x00000040 /* listener mode */
#define FLOWENTF_QOS_MARKING    0x00000100 /* flow can have qos marking */
#define FLOWENTF_LOW_LATENCY    0x00000200 /* low latency flow */
#define FLOWENTF_WAIT_CLOSE     0x00001000 /* defer free after close */
#define FLOWENTF_CLOSE_NOTIFY   0x00002000 /* notify NECP upon tear down */
#define FLOWENTF_EXTRL_PORT     0x00004000 /* port reservation is held externally */
#define FLOWENTF_EXTRL_PROTO    0x00008000 /* proto reservation is held externally */
#define FLOWENTF_ABORTED        0x01000000 /* has sent RST to peer */
#define FLOWENTF_NONVIABLE      0x02000000 /* disabled; awaiting tear down */
#define FLOWENTF_WITHDRAWN      0x04000000 /* flow has been withdrawn */
#define FLOWENTF_TORN_DOWN      0x08000000 /* torn down and awaiting destroy */
#define FLOWENTF_HALF_CLOSED    0x10000000 /* flow is half closed */
#define FLOWENTF_DESTROYED      0x40000000 /* not in RB trees anymore */
#define FLOWENTF_LINGERING      0x80000000 /* destroyed and in linger list */

#define FLOWENTF_BITS                                            \
    "\020\01INITED\05TRACK\06CONNECTED\07LISTNER\011QOS_MARKING" \
    "\012LOW_LATENCY\015WAIT_CLOSE\016CLOSE_NOTIFY\017EXT_PORT"  \
    "\020EXT_PROTO\031ABORTED\032NONVIABLE\033WITHDRAWN\034TORN_DOWN" \
    "\035HALF_CLOSED\037DESTROYED\40LINGERING"

TAILQ_HEAD(flow_entry_linger_head, flow_entry);

struct flow_entry_dead {
	LIST_ENTRY(flow_entry_dead)     fed_link;

	boolean_t               fed_want_nonviable;
	boolean_t               fed_want_clonotify;

	/* rule (flow) UUID */
	union {
		uint64_t        fed_uuid_64[2];
		uint32_t        fed_uuid_32[4];
		uuid_t          fed_uuid;
	} __sk_aligned(8);
};

/*
 * Minimum refcnt for a flow route entry to be considered as idle.
 */
#define FLOW_ROUTE_MINREF       2       /* for the 2 RB trees */

struct flow_route {
	RB_ENTRY(flow_route)    fr_link;
	RB_ENTRY(flow_route)    fr_id_link;

	/*
	 * fr_laddr represents the local address that the system chooses
	 * for the foreign destination in fr_faddr.  The flow entry that
	 * is referring to this flow route object may choose a different
	 * local address if it wishes.
	 *
	 * fr_gaddr represents the gateway address to reach the final
	 * foreign destination fr_faddr, valid only if the destination is
	 * not directly attached (FLOWRTF_GATEWAY is set).
	 *
	 * The use of sockaddr for storage is for convenience; the port
	 * value is not applicable for this object, as this is shared
	 * among flow entries.
	 */
	union sockaddr_in_4_6   fr_laddr;       /* local IP address */
	union sockaddr_in_4_6   fr_faddr;       /* remote IP address */
#define fr_af                   fr_faddr.sa.sa_family
	union sockaddr_in_4_6   fr_gaddr;       /* gateway IP address */

	struct flow_llhdr       fr_llhdr;
#define fr_eth_padded           fr_llhdr.flh_eth_padded
#define fr_eth                  fr_llhdr.flh_eth

	/*
	 * In flow_route_tree, we use the destination address as key.
	 * To speed up searches, we initialize fr_addr_key to the address
	 * portion of fr_faddr depending on the address family.
	 */
	void                    *fr_addr_key;

	/* flow route UUID */
	uuid_t                  fr_uuid __sk_aligned(8);

	/*
	 * fr_usecnt is updated atomically; incremented when a flow entry
	 * refers to this object and decremented otherwise.  Periodically,
	 * the flowswitch instance garbage collects flow_route objects
	 * that aren't being referred to by any flow entries.
	 *
	 * fr_expire is set when fr_usecnt reaches its minimum count, and
	 * is cleared when it goes above the minimum count.
	 *
	 * The spin lock fr_reflock is used to serialize both.
	 */
	decl_lck_spin_data(, fr_reflock);
	uint64_t                fr_expire;
	volatile uint32_t       fr_usecnt;

	uint32_t                fr_flags;
	uint32_t                fr_laddr_gencnt; /* local IP gencnt */
	uint32_t                fr_addr_len;     /* sizeof {in,in6}_addr */

	volatile uint32_t       fr_want_configure;
	volatile uint32_t       fr_want_probe;

	/* lock to serialize resolver */
	decl_lck_mtx_data(, fr_lock);

	/*
	 * fr_rt_dst is the route to final destination, and along with
	 * fr_rt_evhdlr_tag, they are used in route event registration.
	 *
	 * fr_rt_gw is valid only if FLOWRTF_GATEWAY is set.
	 */
	eventhandler_tag        fr_rt_evhdlr_tag;
	struct rtentry          *fr_rt_dst;
	struct rtentry          *fr_rt_gw;

	/* nexus UUID */
	uuid_t                  fr_nx_uuid __sk_aligned(8);

	const struct flow_mgr   *fr_mgr;
	const struct flow_route_bucket  *fr_frb;
	const struct flow_route_id_bucket *fr_frib;
};

/* valid values for fr_flags */
#define FLOWRTF_ATTACHED        0x00000001 /* attached to RB trees */
#define FLOWRTF_ONLINK          0x00000010 /* dst directly on the link */
#define FLOWRTF_GATEWAY         0x00000020 /* gw IP address is valid */
#define FLOWRTF_RESOLVED        0x00000040 /* flow route is resolved */
#define FLOWRTF_HAS_LLINFO      0x00000080 /* has dst link-layer address */
#define FLOWRTF_DELETED         0x00000100 /* route has been deleted */
#define FLOWRTF_DST_LL_MCAST    0x00000200 /* dst is link layer multicast */
#define FLOWRTF_DST_LL_BCAST    0x00000400 /* dst is link layer broadcast */
#define FLOWRTF_STABLE_ADDR     0x00000800 /* local address prefers stable */

#define FR_LOCK(_fr)                    \
	lck_mtx_lock(&(_fr)->fr_lock)
#define FR_TRY_LOCK(_fr)                \
	lck_mtx_try_lock(&(_fr)->fr_lock)
#define FR_LOCK_ASSERT_HELD(_fr)        \
	LCK_MTX_ASSERT(&(_fr)->fr_lock, LCK_MTX_ASSERT_OWNED)
#define FR_LOCK_ASSERT_NOTHELD(_fr)     \
	LCK_MTX_ASSERT(&(_fr)->fr_lock, LCK_MTX_ASSERT_NOTOWNED)
#define FR_UNLOCK(_fr)                  \
	lck_mtx_unlock(&(_fr)->fr_lock)

#define FLOWRT_UPD_ETH_DST(_fr, _addr)  do {                            \
	bcopy((_addr), (_fr)->fr_eth.ether_dhost, ETHER_ADDR_LEN);      \
	(_fr)->fr_flags &= ~(FLOWRTF_DST_LL_MCAST|FLOWRTF_DST_LL_BCAST);\
	if (ETHER_IS_MULTICAST(_addr)) {                                \
	        if (_ether_cmp(etherbroadcastaddr, (_addr)) == 0)       \
	                (_fr)->fr_flags |= FLOWRTF_DST_LL_BCAST;        \
	        else                                                    \
	                (_fr)->fr_flags |= FLOWRTF_DST_LL_MCAST;        \
	}                                                               \
} while (0)

RB_HEAD(flow_route_tree, flow_route);
RB_PROTOTYPE_SC_PREV(__private_extern__, flow_route_tree, flow_route,
    fr_link, fr_cmp);

struct flow_route_bucket {
	decl_lck_rw_data(, frb_lock);
	struct flow_route_tree  frb_head;
	const uint32_t          frb_idx;
};

#define FRB_WLOCK(_frb)                 \
	lck_rw_lock_exclusive(&(_frb)->frb_lock)
#define FRB_WLOCKTORLOCK(_frb)          \
	lck_rw_lock_exclusive_to_shared(&(_frb)->frb_lock)
#define FRB_WTRYLOCK(_frb)              \
	lck_rw_try_lock_exclusive(&(_frb)->frb_lock)
#define FRB_WUNLOCK(_frb)               \
	lck_rw_unlock_exclusive(&(_frb)->frb_lock)
#define FRB_RLOCK(_frb)                 \
	lck_rw_lock_shared(&(_frb)->frb_lock)
#define FRB_RLOCKTOWLOCK(_frb)          \
	lck_rw_lock_shared_to_exclusive(&(_frb)->frb_lock)
#define FRB_RTRYLOCK(_frb)              \
	lck_rw_try_lock_shared(&(_frb)->frb_lock)
#define FRB_RUNLOCK(_frb)               \
	lck_rw_unlock_shared(&(_frb)->frb_lock)
#define FRB_UNLOCK(_frb)                \
	lck_rw_done(&(_frb)->frb_lock)
#define FRB_WLOCK_ASSERT_HELD(_frb)     \
	LCK_RW_ASSERT(&(_frb)->frb_lock, LCK_RW_ASSERT_EXCLUSIVE)
#define FRB_RLOCK_ASSERT_HELD(_frb)     \
	LCK_RW_ASSERT(&(_frb)->frb_lock, LCK_RW_ASSERT_SHARED)
#define FRB_LOCK_ASSERT_HELD(_frb)      \
	LCK_RW_ASSERT(&(_frb)->frb_lock, LCK_RW_ASSERT_HELD)

RB_HEAD(flow_route_id_tree, flow_route);
RB_PROTOTYPE_SC_PREV(__private_extern__, flow_route_id_tree, flow_route,
    fr_id_link, fr_id_cmp);

struct flow_route_id_bucket {
	decl_lck_rw_data(, frib_lock);
	struct flow_route_id_tree       frib_head;
	const uint32_t                  frib_idx;
};

#define FRIB_WLOCK(_frib)               \
	lck_rw_lock_exclusive(&(_frib)->frib_lock)
#define FRIB_WLOCKTORLOCK(_frib)        \
	lck_rw_lock_exclusive_to_shared(&(_frib)->frib_lock)
#define FRIB_WTRYLOCK(_frib)            \
	lck_rw_try_lock_exclusive(&(_frib)->frib_lock)
#define FRIB_WUNLOCK(_frib)             \
	lck_rw_unlock_exclusive(&(_frib)->frib_lock)
#define FRIB_RLOCK(_frib)               \
	lck_rw_lock_shared(&(_frib)->frib_lock)
#define FRIB_RLOCKTOWLOCK(_frib)        \
	lck_rw_lock_shared_to_exclusive(&(_frib)->frib_lock)
#define FRIB_RTRYLOCK(_frib)            \
	lck_rw_try_lock_shared(&(_frib)->frib_lock)
#define FRIB_RUNLOCK(_frib)             \
	lck_rw_unlock_shared(&(_frib)->frib_lock)
#define FRIB_UNLOCK(_frib)              \
	lck_rw_done(&(_frib)->frib_lock)
#define FRIB_WLOCK_ASSERT_HELD(_frib)   \
	LCK_RW_ASSERT(&(_frib)->frib_lock, LCK_RW_ASSERT_EXCLUSIVE)
#define FRIB_RLOCK_ASSERT_HELD(_frib)   \
	LCK_RW_ASSERT(&(_frib)->frib_lock, LCK_RW_ASSERT_SHARED)
#define FRIB_LOCK_ASSERT_HELD(_frib)    \
	LCK_RW_ASSERT(&(_frib)->frib_lock, LCK_RW_ASSERT_HELD)

struct flow_mgr {
	char            fm_name[IFNAMSIZ];
	uuid_t          fm_uuid;
	RB_ENTRY(flow_mgr) fm_link;

	struct cuckoo_hashtable *fm_flow_table;
	size_t   fm_flow_hash_count[FKMASK_IDX_MAX]; /* # of flows with mask */
	uint16_t fm_flow_hash_masks[FKMASK_IDX_MAX];

	void            *fm_owner_buckets;     /* cache-aligned fob */
	const size_t    fm_owner_buckets_cnt;  /* total # of fobs */
	const size_t    fm_owner_bucket_sz;    /* size of each fob */
	const size_t    fm_owner_bucket_tot_sz; /* allocated size of each fob */

	void            *fm_route_buckets;     /* cache-aligned frb */
	const size_t    fm_route_buckets_cnt;  /* total # of frb */
	const size_t    fm_route_bucket_sz;    /* size of each frb */
	const size_t    fm_route_bucket_tot_sz; /* allocated size of each frb */

	void            *fm_route_id_buckets;    /* cache-aligned frib */
	const size_t    fm_route_id_buckets_cnt; /* total # of frib */
	const size_t    fm_route_id_bucket_sz;   /* size of each frib */
	const size_t    fm_route_id_bucket_tot_sz; /* allocated size of each frib */

	struct flow_entry *fm_host_fe;
};

/*
 * this func compare match with key;
 * return values:
 * 0 as long as @key(exact) matches what @match(wildcard) wants to match on.
 * 1 when it doesn't match
 */
static inline int
flow_key_cmp(const struct flow_key *match, const struct flow_key *key)
{
#define FK_CMP(field, mask)     \
	if ((match->fk_mask & mask) != 0) {     \
	        if ((key->fk_mask & mask) == 0) {       \
	                return 1;       \
	        }       \
	        int d = memcmp(&match->field, &key->field, sizeof(match->field));       \
	        if (d != 0) {   \
	                return d;       \
	        }       \
	}

	FK_CMP(fk_ipver, FKMASK_IPVER);
	FK_CMP(fk_proto, FKMASK_PROTO);
	FK_CMP(fk_src, FKMASK_SRC);
	FK_CMP(fk_dst, FKMASK_DST);
	FK_CMP(fk_sport, FKMASK_SPORT);
	FK_CMP(fk_dport, FKMASK_DPORT);

	return 0;
}

/*
 * Similar to flow_key_cmp() except using memory compare with mask,
 * done with SIMD instructions, if available for the platform.
 */
static inline int
flow_key_cmp_mask(const struct flow_key *match,
    const struct flow_key *key, const struct flow_key *mask)
{
	_CASSERT(FLOW_KEY_LEN == 48);
	_CASSERT(FLOW_KEY_LEN == sizeof(struct flow_key));
	_CASSERT((sizeof(struct flow_entry) % 16) == 0);
	_CASSERT((offsetof(struct flow_entry, fe_key) % 16) == 0);

	return sk_memcmp_mask_48B((const uint8_t *)match,
	           (const uint8_t *)key, (const uint8_t *)mask);
}

static inline uint32_t
flow_key_hash(const struct flow_key *key)
{
	uint32_t hash = FK_HASH_SEED;
#define FK_HASH(field, mask)    \
	if ((key->fk_mask & mask) != 0) {       \
	        hash = net_flowhash(&key->field, sizeof(key->field), hash);     \
	}

	FK_HASH(fk_ipver, FKMASK_IPVER);
	FK_HASH(fk_proto, FKMASK_PROTO);
	FK_HASH(fk_src, FKMASK_SRC);
	FK_HASH(fk_dst, FKMASK_DST);
	FK_HASH(fk_sport, FKMASK_SPORT);
	FK_HASH(fk_dport, FKMASK_DPORT);

	return hash;
}

__attribute__((always_inline))
static inline void
flow_key_unpack(const struct flow_key *key, union sockaddr_in_4_6 *laddr,
    union sockaddr_in_4_6 *faddr, uint8_t *protocol)
{
	*protocol = key->fk_proto;
	if (key->fk_ipver == IPVERSION) {
		laddr->sa.sa_family = AF_INET;
		laddr->sin.sin_addr = key->fk_src4;
		laddr->sin.sin_port = key->fk_sport;
		faddr->sa.sa_family = AF_INET;
		faddr->sin.sin_addr = key->fk_dst4;
		faddr->sin.sin_port = key->fk_dport;
	} else if (key->fk_ipver == IPV6_VERSION) {
		laddr->sa.sa_family = AF_INET6;
		laddr->sin6.sin6_addr = key->fk_src6;
		laddr->sin6.sin6_port = key->fk_sport;
		faddr->sa.sa_family = AF_INET6;
		faddr->sin6.sin6_addr = key->fk_dst6;
		faddr->sin6.sin6_port = key->fk_dport;
	}
}

__attribute__((always_inline))
static inline int
flow_req2key(struct nx_flow_req *req, struct flow_key *key)
{
	FLOW_KEY_CLEAR(key);

	if (req->nfr_saddr.sa.sa_family == AF_INET) {
		key->fk_ipver = IPVERSION;
		key->fk_proto = req->nfr_ip_protocol;
		key->fk_mask |= FKMASK_PROTO;
		if (sk_sa_has_addr(SA(&req->nfr_saddr))) {
			key->fk_src4 = req->nfr_saddr.sin.sin_addr;
			key->fk_mask |= (FKMASK_IPVER | FKMASK_SRC);
		}
		if (sk_sa_has_addr(SA(&req->nfr_daddr))) {
			key->fk_dst4 = req->nfr_daddr.sin.sin_addr;
			key->fk_mask |= (FKMASK_IPVER | FKMASK_DST);
		}
		if (sk_sa_has_port(SA(&req->nfr_saddr))) {
			key->fk_sport = req->nfr_saddr.sin.sin_port;
			key->fk_mask |= FKMASK_SPORT;
		}
		if (sk_sa_has_port(SA(&req->nfr_daddr))) {
			key->fk_dport = req->nfr_daddr.sin.sin_port;
			key->fk_mask |= FKMASK_DPORT;
		}
	} else if (req->nfr_saddr.sa.sa_family == AF_INET6) {
		key->fk_ipver = IPV6_VERSION;
		key->fk_proto = req->nfr_ip_protocol;
		key->fk_mask |= FKMASK_PROTO;
		if (sk_sa_has_addr(SA(&req->nfr_saddr))) {
			key->fk_src6 = req->nfr_saddr.sin6.sin6_addr;
			key->fk_mask |= (FKMASK_IPVER | FKMASK_SRC);
		}
		if (sk_sa_has_addr(SA(&req->nfr_daddr))) {
			key->fk_dst6 = req->nfr_daddr.sin6.sin6_addr;
			key->fk_mask |= (FKMASK_IPVER | FKMASK_DST);
		}
		if (sk_sa_has_port(SA(&req->nfr_saddr))) {
			key->fk_sport = req->nfr_saddr.sin6.sin6_port;
			key->fk_mask |= FKMASK_SPORT;
		}
		if (sk_sa_has_port(SA(&req->nfr_daddr))) {
			key->fk_dport = req->nfr_daddr.sin6.sin6_port;
			key->fk_mask |= FKMASK_DPORT;
		}
	} else {
		SK_ERR("unknown AF %d", req->nfr_saddr.sa.sa_family);
		return ENOTSUP;
	}

	switch (key->fk_mask) {
	case FKMASK_5TUPLE:
	case FKMASK_4TUPLE:
	case FKMASK_3TUPLE:
	case FKMASK_2TUPLE:
	case FKMASK_IPFLOW3:
	case FKMASK_IPFLOW2:
	case FKMASK_IPFLOW1:
		break;
	default:
		SK_ERR("unknown flow key mask 0x%04x", key->fk_mask);
		return ENOTSUP;
	}

	return 0;
}

__attribute__((always_inline))
static inline void
flow_pkt2key(struct __kern_packet *pkt, boolean_t input,
    struct flow_key *key)
{
	struct __flow *flow = pkt->pkt_flow;

	FLOW_KEY_CLEAR(key);

	if (__improbable((pkt->pkt_qum_qflags & QUM_F_FLOW_CLASSIFIED) == 0)) {
		return;
	}

	ASSERT(flow->flow_l3._l3_ip_ver != 0);

	key->fk_ipver = flow->flow_l3._l3_ip_ver;
	key->fk_proto = flow->flow_ip_proto;
	if (input) {
		if (flow->flow_ip_ver == IPVERSION) {
			key->fk_src4 = flow->flow_ipv4_dst;
			key->fk_sport = flow->flow_tcp_dst;
			key->fk_dst4 = flow->flow_ipv4_src;
			key->fk_dport = flow->flow_tcp_src;
		} else {
			key->fk_src6 = flow->flow_ipv6_dst;
			key->fk_sport = flow->flow_tcp_dst;
			key->fk_dst6 = flow->flow_ipv6_src;
			key->fk_dport = flow->flow_tcp_src;
		}
	} else {
		if (flow->flow_ip_ver == IPVERSION) {
			key->fk_src4 = flow->flow_ipv4_src;
			key->fk_sport = flow->flow_tcp_src;
			key->fk_dst4 = flow->flow_ipv4_dst;
			key->fk_dport = flow->flow_tcp_dst;
		} else {
			key->fk_src6 = flow->flow_ipv6_src;
			key->fk_sport = flow->flow_tcp_src;
			key->fk_dst6 = flow->flow_ipv6_dst;
			key->fk_dport = flow->flow_tcp_dst;
		}
	}
}

__attribute__((always_inline))
static inline int
flow_ip_cmp(const void *a0, const void *b0, size_t alen)
{
	struct flow_ip_addr *a = __DECONST(struct flow_ip_addr *, a0),
	    *b = __DECONST(struct flow_ip_addr *, b0);

	switch (alen) {
	case sizeof(struct in_addr):
		if (a->_addr32[0] > b->_addr32[0]) {
			return 1;
		}
		if (a->_addr32[0] < b->_addr32[0]) {
			return -1;
		}
		break;

	case sizeof(struct in6_addr):
		if (a->_addr64[1] > b->_addr64[1]) {
			return 1;
		}
		if (a->_addr64[1] < b->_addr64[1]) {
			return -1;
		}
		if (a->_addr64[0] > b->_addr64[0]) {
			return 1;
		}
		if (a->_addr64[0] < b->_addr64[0]) {
			return -1;
		}
		break;

	default:
		VERIFY(0);
		/* NOTREACHED */
		__builtin_unreachable();
	}
	return 0;
}

__attribute__((always_inline))
static inline struct flow_owner_bucket *
flow_mgr_get_fob_at_idx(struct flow_mgr *fm, uint32_t idx)
{
	return (struct flow_owner_bucket *)(void *)
	       ((intptr_t)fm->fm_owner_buckets +
	       (idx * fm->fm_owner_bucket_sz));
}

__attribute__((always_inline))
static inline struct flow_route_bucket *
flow_mgr_get_frb_at_idx(struct flow_mgr *fm, uint32_t idx)
{
	return (struct flow_route_bucket *)(void *)
	       ((intptr_t)fm->fm_route_buckets +
	       (idx * fm->fm_route_bucket_sz));
}

__attribute__((always_inline))
static inline struct flow_route_id_bucket *
flow_mgr_get_frib_at_idx(struct flow_mgr *fm, uint32_t idx)
{
	return (struct flow_route_id_bucket *)(void *)
	       ((intptr_t)fm->fm_route_id_buckets +
	       (idx * fm->fm_route_id_bucket_sz));
}

__attribute__((always_inline))
static inline uint32_t
flow_mgr_get_fob_idx(struct flow_mgr *fm,
    struct flow_owner_bucket *bkt)
{
	ASSERT(((intptr_t)bkt - (intptr_t)fm->fm_owner_buckets) %
	    fm->fm_owner_bucket_sz == 0);
	return (uint32_t)(((intptr_t)bkt - (intptr_t)fm->fm_owner_buckets) /
	       fm->fm_owner_bucket_sz);
}

extern unsigned int sk_fo_size;
extern struct skmem_cache *sk_fo_cache;

extern unsigned int sk_fe_size;
extern struct skmem_cache *sk_fe_cache;

extern unsigned int sk_fab_size;
extern struct skmem_cache *sk_fab_cache;

extern uint32_t flow_seed;

extern struct skmem_cache *flow_route_cache;
extern struct skmem_cache *flow_stats_cache;

__BEGIN_DECLS

typedef void (*flow_route_ctor_fn_t)(void *arg, struct flow_route *);
typedef int (*flow_route_resolve_fn_t)(void *arg, struct flow_route *,
    struct __kern_packet *);

extern int flow_init(void);
extern void flow_fini(void);

extern void flow_mgr_init(void);
extern void flow_mgr_fini(void);
extern struct flow_mgr *flow_mgr_find_lock(uuid_t);
extern void flow_mgr_unlock(void);
extern struct flow_mgr * flow_mgr_create(size_t, size_t, size_t, size_t);
extern void flow_mgr_destroy(struct flow_mgr *);
extern void flow_mgr_terminate(struct flow_mgr *);
extern int flow_mgr_flow_add(struct kern_nexus *nx, struct flow_mgr *fm,
    struct flow_owner *fo, struct ifnet *ifp, struct nx_flow_req *req,
    flow_route_ctor_fn_t fr_ctor, flow_route_resolve_fn_t fr_resolve, void *fr_arg);
extern struct flow_owner_bucket *flow_mgr_get_fob_by_pid(
	struct flow_mgr *, pid_t);
extern struct flow_entry *flow_mgr_get_fe_by_uuid_rlock(
	struct flow_mgr *, uuid_t);
extern struct flow_route_bucket *flow_mgr_get_frb_by_addr(
	struct flow_mgr *, union sockaddr_in_4_6 *);
extern struct flow_route_id_bucket *flow_mgr_get_frib_by_uuid(
	struct flow_mgr *, uuid_t);
extern int flow_mgr_flow_hash_mask_add(struct flow_mgr *fm, uint32_t mask);
extern int flow_mgr_flow_hash_mask_del(struct flow_mgr *fm, uint32_t mask);

extern struct flow_entry * fe_alloc(boolean_t can_block);
extern void flow_mgr_setup_host_flow(struct flow_mgr *fm, struct nx_flowswitch *fsw);
extern void flow_mgr_teardown_host_flow(struct flow_mgr *fm);

extern int flow_namespace_create(union sockaddr_in_4_6 *, uint8_t protocol,
    netns_token *, boolean_t, struct ns_flow_info *);
extern void flow_namespace_half_close(netns_token *token);
extern void flow_namespace_withdraw(netns_token *);
extern void flow_namespace_destroy(netns_token *);

extern struct flow_owner_bucket *flow_owner_buckets_alloc(size_t, size_t *, size_t *);
extern void flow_owner_buckets_free(struct flow_owner_bucket *, size_t);
extern void flow_owner_bucket_init(struct flow_owner_bucket *);
extern void flow_owner_bucket_destroy(struct flow_owner_bucket *);
extern void flow_owner_bucket_purge_all(struct flow_owner_bucket *);
extern void flow_owner_attach_nexus_port(struct flow_mgr *, boolean_t,
    pid_t, nexus_port_t);
extern uint32_t flow_owner_detach_nexus_port(struct flow_mgr *,
    boolean_t, pid_t, nexus_port_t, boolean_t);
extern struct flow_owner *flow_owner_alloc(struct flow_owner_bucket *,
    struct proc *, nexus_port_t, bool, bool, struct nx_flowswitch*,
    struct nexus_adapter *, void *, bool);
extern void flow_owner_free(struct flow_owner_bucket *, struct flow_owner *);
extern struct flow_entry *flow_owner_create_entry(struct flow_owner *,
    struct nx_flow_req *, boolean_t, uint32_t, boolean_t,
    struct flow_route *, int *);
extern int flow_owner_destroy_entry(struct flow_owner *, uuid_t, bool, void *);
extern struct flow_owner *flow_owner_find_by_pid(struct flow_owner_bucket *,
    pid_t, void *, bool);
extern int flow_owner_flowadv_index_alloc(struct flow_owner *, flowadv_idx_t *);
extern void flow_owner_flowadv_index_free(struct flow_owner *, flowadv_idx_t);
extern uint32_t flow_owner_activate_nexus_port(struct flow_mgr *,
    boolean_t, pid_t, nexus_port_t, struct nexus_adapter *,
    na_activate_mode_t);

extern struct flow_entry *flow_mgr_find_fe_by_key(struct flow_mgr *,
    struct flow_key *);
extern struct flow_entry * flow_mgr_find_conflicting_fe(struct flow_mgr *fm,
    struct flow_key *fe_key);
extern void flow_mgr_foreach_flow(struct flow_mgr *fm,
    void (^flow_handler)(struct flow_entry *fe));
extern struct flow_entry * flow_mgr_get_host_fe(struct flow_mgr *fm);
extern struct flow_entry *flow_entry_find_by_uuid(struct flow_owner *,
    uuid_t);
extern struct flow_entry * flow_entry_alloc(struct flow_owner *fo,
    struct nx_flow_req *req, int *perr);
extern void flow_entry_teardown(struct flow_owner *, struct flow_entry *);
extern void flow_entry_destroy(struct flow_owner *, struct flow_entry *, bool,
    void *);
extern void flow_entry_retain(struct flow_entry *fe);
extern void flow_entry_release(struct flow_entry **pfe);
extern uint32_t flow_entry_refcnt(struct flow_entry *fe);

extern struct flow_entry_dead *flow_entry_dead_alloc(zalloc_flags_t);
extern void flow_entry_dead_free(struct flow_entry_dead *);

extern void flow_entry_stats_get(struct flow_entry *, struct sk_stats_flow *);

extern int flow_pkt_classify(struct __kern_packet *pkt, struct ifnet *ifp,
    sa_family_t af, bool input);

extern void flow_track_stats(struct flow_entry *, uint64_t, uint64_t,
    bool, bool);
extern int flow_pkt_track(struct flow_entry *, struct __kern_packet *, bool);
extern boolean_t flow_track_tcp_want_abort(struct flow_entry *);
extern void fsw_host_rx(struct nx_flowswitch *, struct flow_entry *);
extern void fsw_host_sendup(struct ifnet *, struct mbuf *, struct mbuf *,
    uint32_t, uint32_t);

extern void flow_rx_agg_tcp(struct nx_flowswitch *fsw, struct flow_entry *fe);

extern void flow_route_init(void);
extern void flow_route_fini(void);
extern struct flow_route_bucket *flow_route_buckets_alloc(size_t, size_t *, size_t *);
extern void flow_route_buckets_free(struct flow_route_bucket *, size_t);
extern void flow_route_bucket_init(struct flow_route_bucket *);
extern void flow_route_bucket_destroy(struct flow_route_bucket *);
extern void flow_route_bucket_purge_all(struct flow_route_bucket *);
extern struct flow_route_id_bucket *flow_route_id_buckets_alloc(size_t,
    size_t *, size_t *);
extern void flow_route_id_buckets_free(struct flow_route_id_bucket *, size_t);
extern void flow_route_id_bucket_init(struct flow_route_id_bucket *);
extern void flow_route_id_bucket_destroy(struct flow_route_id_bucket *);

extern int flow_route_select_laddr(union sockaddr_in_4_6 *,
    union sockaddr_in_4_6 *, struct ifnet *, struct rtentry *, uint32_t *, int);
extern int flow_route_find(struct kern_nexus *, struct flow_mgr *,
    struct ifnet *, struct nx_flow_req *, flow_route_ctor_fn_t,
    flow_route_resolve_fn_t, void *, struct flow_route **);
extern int flow_route_configure(struct flow_route *, struct ifnet *, struct nx_flow_req *);
extern void flow_route_retain(struct flow_route *);
extern void flow_route_release(struct flow_route *);
extern uint32_t flow_route_prune(struct flow_mgr *, struct ifnet *,
    uint32_t *);
extern void flow_route_cleanup(struct flow_route *);
extern boolean_t flow_route_laddr_validate(union sockaddr_in_4_6 *,
    struct ifnet *, uint32_t *);
extern boolean_t flow_route_key_validate(struct flow_key *, struct ifnet *,
    uint32_t *);

extern void flow_stats_init(void);
extern void flow_stats_fini(void);
extern struct flow_stats *flow_stats_alloc(boolean_t cansleep);

#if SK_LOG
#define FLOWKEY_DBGBUF_SIZE   256
#define FLOWENTRY_DBGBUF_SIZE   512
extern char *fk_as_string(const struct flow_key *fk, char *, size_t);
extern char *fe_as_string(const struct flow_entry *fe, char *, size_t);
#endif /* SK_LOG */
__END_DECLS
#endif /* BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_NEXUS_FLOWSIWTCH_FLOW_FLOWVAR_H_ */
