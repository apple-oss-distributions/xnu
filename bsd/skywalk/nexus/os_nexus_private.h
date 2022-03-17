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

#ifndef _SKYWALK_OS_NEXUS_PRIVATE_H_
#define _SKYWALK_OS_NEXUS_PRIVATE_H_

#if defined(PRIVATE) || defined(BSD_KERNEL_PRIVATE)
#include <sys/guarded.h>
#include <skywalk/os_channel.h>
#include <skywalk/os_nexus.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

/*
 * Ephemeral port, for NEXUSDOMCAPF_EPHEMERAL capable nexus.
 */
#define NEXUS_PORT_ANY  ((nexus_port_t)-1)

#define NEXUSCTL_INIT_VERSION_1         1
#define NEXUSCTL_INIT_CURRENT_VERSION   NEXUSCTL_INIT_VERSION_1

/*
 * Nexus controller init parameters.
 */
struct nxctl_init {
	uint32_t        ni_version;     /* in: NEXUSCTL_INIT_CURRENT_VERSION */
	uint32_t        __ni_align;     /* reserved */
	guardid_t       ni_guard;       /* out: guard ID */
};

/*
 * Nexus metadata type.
 *
 * Be mindful that due to the use of tagged pointers for packets, this
 * type gets encoded along with the subtype, with the requirement that the
 * object addresses are aligned on 64-byte boundary at the minimum.  That
 * leaves a total of 4 bits: 2 for type and another 2 for subtype, therefore
 * limiting the maximum enum value to 3.
 */
typedef enum {
	NEXUS_META_TYPE_INVALID = 0,    /* invalid type */
	NEXUS_META_TYPE_QUANTUM,        /* struct __quantum */
	NEXUS_META_TYPE_PACKET,         /* struct __packet */
	NEXUS_META_TYPE_RESERVED,       /* for future */
	NEXUS_META_TYPE_MAX = NEXUS_META_TYPE_RESERVED
} nexus_meta_type_t;

typedef enum {
	NEXUS_META_SUBTYPE_INVALID = 0, /* invalid subtype */
	NEXUS_META_SUBTYPE_PAYLOAD,     /* normal payload mode */
	NEXUS_META_SUBTYPE_RAW,         /* raw (link layer) mode */
	NEXUS_META_SUBTYPE_RESERVED,    /* for future */
	NEXUS_META_SUBTYPE_MAX = NEXUS_META_SUBTYPE_RESERVED
} nexus_meta_subtype_t;

/*
 * Nexus provider parameters.
 */
struct nxprov_params {
	nexus_name_t    nxp_name;       /* name */
	uint32_t        nxp_namelen;    /* length of name */
	nexus_type_t    nxp_type;       /* NEXUS_TYPE_* */
	nexus_meta_type_t nxp_md_type;  /* NEXUS_META_TYPE_* */
	nexus_meta_subtype_t nxp_md_subtype; /* NEXUS_META_SUBTYPE_* */
	uint32_t        nxp_flags;      /* NXPF_* */
	uint32_t        nxp_format;     /* provider-defined */
	uint32_t        nxp_tx_rings;   /* # of channel transmit rings */
	uint32_t        nxp_rx_rings;   /* # of channel receive rings */
	uint32_t        nxp_tx_slots;   /* # of slots per channel TX ring */
	uint32_t        nxp_rx_slots;   /* # of slots per channel RX ring */
	uint32_t        nxp_buf_size;   /* size of each buffer */
	uint32_t        nxp_meta_size;  /* size of metadata per slot */
	uint32_t        nxp_stats_size; /* size of statistics region */
	uint32_t        nxp_pipes;      /* number of pipes */
	nexus_extension_t nxp_extensions;  /* extension specific parameter(s) */
	uint32_t        nxp_mhints;        /* memory usage hints */
	uint32_t        nxp_ifindex;       /* network interface index */
	uint32_t        nxp_flowadv_max;   /* max flow advisory entries */
	nexus_qmap_type_t nxp_qmap;        /* queue mapping type */
	uint32_t        nxp_capabilities;  /* nexus capabilities */
	uint32_t        nxp_nexusadv_size; /* nexus advisory region size */
	uint32_t        nxp_max_frags;     /* max fragments per packet */
	/*
	 * reject channel operations if the peer has closed the channel.
	 * Only valid for user-pipe nexus.
	 */
	boolean_t       nxp_reject_on_close;
} __attribute__((aligned(64)));

/* valid values for nxp_flags */
#define NXPF_ANONYMOUS          0x1     /* allow anonymous channel clients */
#define NXPF_USER_CHANNEL       0x2     /* allow user channel open */
#define NXPF_NETIF_LLINK        0x4     /* use netif logical link */
#ifdef KERNEL
#define NXPF_MASK    (NXPF_ANONYMOUS | NXPF_USER_CHANNEL | NXPF_NETIF_LLINK)
#endif /* KERNEL */

#define NXPF_BITS               \
	"\020\01ANONYMOUS\02USER_CHANNEL"

/* valid values for nxp_capabilities */
#define NXPCAP_CHECKSUM_PARTIAL 0x1     /* partial checksum */
#define NXPCAP_USER_PACKET_POOL 0x2     /* user packet pool */
#define NXPCAP_USER_CHANNEL     0x4     /* allow user channel access */

#define NXPCAP_BITS             \
	"\020\01CHECKSUM_PARTIAL\02USER_PKT_POOL\03USER_CHANNEL"

#define NXPROV_REG_VERSION_1            1
#define NXPROV_REG_CURRENT_VERSION      NXPROV_REG_VERSION_1

/*
 * Nexus provider registration parameters.
 */
struct nxprov_reg {
	uint32_t        nxpreg_version;         /* NXPROV_REG_CURRENT_VERSION */
	uint32_t        nxpreg_requested;       /* customized attributes */
	struct nxprov_params nxpreg_params;     /* Nexus provider parameters */
};

/*
 * Flags for nxpreq_requested; keep in sync with NXA_REQ_* flags.
 * Note that these are 32-bit, whereas nxa_requested is 64-bit
 * wide; for now this won't matter.
 */
#define NXPREQ_TX_RINGS         (1U << 0)       /* 0x00000001 */
#define NXPREQ_RX_RINGS         (1U << 1)       /* 0x00000002 */
#define NXPREQ_TX_SLOTS         (1U << 2)       /* 0x00000004 */
#define NXPREQ_RX_SLOTS         (1U << 3)       /* 0x00000008 */
#define NXPREQ_BUF_SIZE         (1U << 4)       /* 0x00000010 */
#define NXPREQ_META_SIZE        (1U << 5)       /* 0x00000020 */
#define NXPREQ_STATS_SIZE       (1U << 6)       /* 0x00000040 */
#define NXPREQ_ANONYMOUS        (1U << 7)       /* 0x00000080 */
#define NXPREQ_PIPES            (1U << 8)       /* 0x00000100 */
#define NXPREQ_EXTENSIONS       (1U << 9)       /* 0x00000200 */
#define NXPREQ_MHINTS           (1U << 10)      /* 0x00000400 */
#define NXPREQ_FLOWADV_MAX      (1U << 11)      /* 0x00000800 */
#define NXPREQ_QMAP             (1U << 12)      /* 0x00001000 */
#define NXPREQ_CHECKSUM_OFFLOAD (1U << 13)      /* 0x00002000 */
#define NXPREQ_USER_PACKET_POOL (1U << 14)      /* 0x00004000 */
#define NXPREQ_CAPABILITIES     (1U << 15)      /* 0x00008000 */
#define NXPREQ_NEXUSADV_SIZE    (1U << 16)      /* 0x00010000 */
#define NXPREQ_IFINDEX          (1U << 17)      /* 0x00020000 */
#define NXPREQ_USER_CHANNEL     (1U << 18)      /* 0x00040000 */
#define NXPREQ_MAX_FRAGS        (1U << 19)      /* 0x00080000 */
#define NXPREQ_REJECT_ON_CLOSE  (1U << 20)      /* 0x00100000 */

#define NXPREQ_BITS                                                     \
	"\020\01TX_RINGS\02RX_RINGS\03TX_SLOTS\04RX_SLOTS\05BUF_SIZE"   \
	"\06META_SIZE\07STATS_SIZE\010ANONYMOUS\011EXTRA_BUFS\012PIPES" \
	"\013EXTENSIONS\014MHINTS\015FLOWADV_MAX\016QMAP"               \
	"\017CKSUM_OFFLOAD\020USER_PKT_POOL\021CAPABS\022NEXUSADV_SIZE" \
	"\023IFINDEX\024USER_CHANNEL\025MAX_FRAGS\026REJ_CLOSE"

/*
 * Nexus provider registration entry.  Also argument for NXOPT_NEXUS_PROV_ENTRY.
 */
struct nxprov_reg_ent {
	uuid_t          npre_prov_uuid;         /* Nexus provider UUID */
	struct nxprov_params npre_prov_params;  /* Nexus provider parameters */
};

/*
 * Nexus options.
 */
#define NXOPT_NEXUS_PROV_LIST   1       /* (get) list all provider UUIDS */
#define NXOPT_NEXUS_PROV_ENTRY  2       /* (get) get params of a provider */
#define NXOPT_NEXUS_LIST        20      /* (get) list all Nexus instances */
#define NXOPT_NEXUS_BIND        21      /* (set) bind a Nexus port */
#define NXOPT_NEXUS_UNBIND      22      /* (set) unbind a Nexus port */
#define NXOPT_CHANNEL_LIST      30      /* (get) list all Channel instances */
#define NXOPT_NEXUS_CONFIG      40      /* (set) nexus specific config */

/*
 * Argument structure for NXOPT_NEXUS_PROV_LIST.
 */
struct nxprov_list_req {
	uint32_t                nrl_num_regs;   /* array count */
	uint32_t                __nrl_align;    /* reserved */
	user_addr_t             nrl_regs;       /* array of nexus_reg_ent */
};

/*
 * Argument structure for NXOPT_NEXUS_LIST.
 */
struct nx_list_req {
	uuid_t                  nl_prov_uuid;   /* nexus provider UUID */
	uint32_t                nl_num_nx_uuids; /* array count */
	uint32_t                __nl_align;     /* reserved */
	user_addr_t             nl_nx_uuids;    /* array of nexus UUIDs */
};

/*
 * Argument structure for NXOPT_NEXUS_BIND.
 */
struct nx_bind_req {
	uuid_t                  nb_nx_uuid;     /* nexus instance UUID */
	nexus_port_t            nb_port;        /* nexus instance port */
	uint32_t                nb_flags;       /* NBR_* match flags */
	uuid_t                  nb_exec_uuid;   /* executable UUID */
	user_addr_t             nb_key;         /* key blob */
	uint32_t                nb_key_len;     /* key blob length */
	pid_t                   nb_pid;         /* client PID */
};

#define NBR_MATCH_PID           0x1             /* match against PID */
#define NBR_MATCH_EXEC_UUID     0x2             /* match executable's UUID */
#define NBR_MATCH_KEY           0x4             /* match key blob */
#ifdef KERNEL
#define NBR_MATCH_MASK          \
	(NBR_MATCH_PID | NBR_MATCH_EXEC_UUID | NBR_MATCH_KEY)
#endif /* KERNEL */

/*
 * Argument structure for NXOPT_NEXUS_UNBIND.
 */
struct nx_unbind_req {
	uuid_t                  nu_nx_uuid;     /* nexus instance UUID */
	nexus_port_t            nu_port;        /* nexus instance port */
};

/*
 * Argument structure for NXOPT_CHANNEL_LIST.
 */
struct ch_list_req {
	uuid_t                  cl_nx_uuid;     /* nexus instance UUID */
	uint32_t                cl_num_ch_uuids; /* array count */
	uint32_t                __cl_align;     /* reserved */
	user_addr_t             cl_ch_uuids;    /* array of channel UUIDs */
};

/*
 * Skywalk Nexus MIB
 *
 * We will use the name MIB now to refer to things that we expose to outside
 * world for management/telemetry purpose.
 *
 * General rule of thumb of this MIB structure is to keep it simple.
 * Try to avoid variable length field and hierarchical representation wherever
 * possible. Simple retrieval would return either a single object (simple type
 * or fixed length compound type) or an object array of same type. This makes
 * parsing the retrieved information a lot easier.
 *
 * For now, we use sysctl as the way MIB interface is exposed. Additional
 * interfaces could be syscall (e.g. via a nexus controller), etc.
 */
#define NXMIB_NETIF_STATS       (((uint32_t)1) << 1)
#define NXMIB_FSW_STATS         (((uint32_t)1) << 2)
#define NXMIB_FLOW              (((uint32_t)1) << 3)
#define NXMIB_FLOW_ADV          (((uint32_t)1) << 4)
#define NXMIB_FLOW_OWNER        (((uint32_t)1) << 5)
#define NXMIB_FLOW_ROUTE        (((uint32_t)1) << 6)
#define NXMIB_LLINK_LIST        (((uint32_t)1) << 7)

#define NXMIB_QUIC_STATS        (((uint32_t)1) << 27)
#define NXMIB_UDP_STATS         (((uint32_t)1) << 28)
#define NXMIB_TCP_STATS         (((uint32_t)1) << 29)
#define NXMIB_IP6_STATS         (((uint32_t)1) << 30)
#define NXMIB_IP_STATS          (((uint32_t)1) << 31)

#define NXMIB_USERSTACK_STATS   (NXMIB_IP_STATS | NXMIB_IP6_STATS \
	                        | NXMIB_TCP_STATS | NXMIB_UDP_STATS \
	                        | NXMIB_QUIC_STATS)

#define NXMIB_FILTER_NX_UUID    (((uint64_t)1) << 0)
#define NXMIB_FILTER_FLOW_ID    (((uint64_t)1) << 1)
#define NXMIB_FILTER_PID        (((uint64_t)1) << 2)
#define NXMIB_FILTER_INFO_TUPLE (((uint64_t)1) << 3)

/*
 * Nexus MIB filter: used to retrieve only those matching the filter value.
 */
struct nexus_mib_filter {
	uint32_t                nmf_type;       /* MIB type */
	uint64_t                nmf_bitmap;     /* bitmap of following fields */

	uuid_t                  nmf_nx_uuid;    /* nexus instance uuid */
	uuid_t                  nmf_flow_id;    /* flow rule id */
	pid_t                   nmf_pid;        /* owner pid */
	struct info_tuple       nmf_info_tuple; /* flow tuple */
};

/*
 * Nexus-specific config commands.
 */
typedef enum {
	NXCFG_CMD_ATTACH =      0,      /* attach an object to a nexus */
	NXCFG_CMD_DETACH =      1,      /* detach an object from a nexus */
	NXCFG_CMD_FLOW_ADD =    20,     /* bind namespace to a nexus port */
	NXCFG_CMD_FLOW_DEL =    21,     /* unbind namespace from a nexus port */
	NXCFG_CMD_NETEM =       30,     /* config packet scheduler */
	NXCFG_CMD_GET_LLINK_INFO = 40,  /* collect llink info */
} nxcfg_cmd_t;

#define NX_SPEC_IF_NAMELEN      64

/*
 * Argument struture for NXOPT_NEXUS_CONFIG.
 */
struct nx_cfg_req {
	uuid_t                  nc_nx_uuid;     /* nexus instance UUID */
	nxcfg_cmd_t             nc_cmd;         /* NXCFG_CMD_* */
	uint32_t                nc_req_len;     /* size of request struct */
	user_addr_t             nc_req;         /* address of request struct */
};

/*
 * Argument structure for NXCFG_CMD_{ATTACH,DETACH}
 */
struct nx_spec_req {
	union {
		char            nsru_name[NX_SPEC_IF_NAMELEN];
		uuid_t          nsru_uuid;
#ifdef KERNEL
		struct ifnet    *nsru_ifp;
#endif /* KERNEL */
	} nsr_u __attribute__((aligned(sizeof(uint64_t))));     /* in */
	uint32_t                nsr_flags;                      /* in */
	uuid_t                  nsr_if_uuid;    /* attach: out, detach: in */
};
#define nsr_name        nsr_u.nsru_name
#define nsr_uuid        nsr_u.nsru_uuid
#ifdef KERNEL
#define nsr_ifp         nsr_u.nsru_ifp
#endif /* KERNEL */

#define NXSPECREQ_UUID          0x1     /* nsr_name is uuid_t else ifname */
#define NXSPECREQ_HOST          0x2     /* attach to host port */
#ifdef KERNEL
/* mask off userland-settable bits */
#define NXSPECREQ_MASK          (NXSPECREQ_UUID | NXSPECREQ_HOST)
#define NXSPECREQ_IFP           0x1000  /* (embryonic) ifnet */
#endif /* KERNEL */

/*
 * Argument structure for NXCFG_CMD_FLOW_{BIND,UNBIND}
 */
struct nx_flow_req {
	nexus_port_t            nfr_nx_port;
	uint16_t                nfr_ethertype;
	ether_addr_t            nfr_etheraddr;
	union sockaddr_in_4_6   nfr_saddr;
	union sockaddr_in_4_6   nfr_daddr;
	uint8_t                 nfr_ip_protocol;
	uint8_t                 nfr_transport_protocol;
	uint16_t                nfr_flags;
	uuid_t                  nfr_flow_uuid;
	packet_svc_class_t      nfr_svc_class;
	uuid_t                  nfr_euuid;
	uint32_t                nfr_policy_id;
	pid_t                   nfr_epid;
	flowadv_idx_t           nfr_flowadv_idx;
	uuid_t                  nfr_bind_key;
	uint64_t                nfr_qset_id;
	// below is reserved kernel-only fields
	union {
#ifdef KERNEL
		struct {
			char                    _nfr_kernel_field_start[0];
			void                    *nfr_context;
			struct proc             *nfr_proc;
			struct ifnet            *nfr_ifp;
			struct flow_route       *nfr_route;
			struct ns_token         *nfr_port_reservation;
			struct protons_token    *nfr_proto_reservation;
			struct flow_stats       *nfr_flow_stats;
			pid_t                   nfr_pid;
			uint32_t                nfr_saddr_gencnt;
			void                    *nfr_ipsec_reservation;
			uint32_t                nfr_inp_flowhash;
#if defined(__LP64__)
			uint8_t                 _nfr_kernel_pad[4];
#else  /* !__LP64__ */
			uint8_t                 _nfr_kernel_pad[36];
#endif /* !__LP64__ */
			char                    _nfr_kernel_field_end[0];
		};
#endif  /* KERNEL */
		struct {
			uint8_t                 _nfr_opaque[80];
			/* should be at the same offset as _nfr_kernel_field_end above */
			char                    _nfr_common_field_end[0];
		};
	};
};

/* valid flags for nfr_flags */
#define NXFLOWREQF_TRACK          0x0001  /* enable state tracking */
#define NXFLOWREQF_QOS_MARKING    0x0002  /* allow qos marking */
#define NXFLOWREQF_FILTER         0x0004  /* interpose filter */
#define NXFLOWREQF_CUSTOM_ETHER   0x0008  /* custom ethertype */
#define NXFLOWREQF_IPV6_ULA       0x0010  /* ipv6 ula */
#define NXFLOWREQF_LISTENER       0x0020  /* listener */
#define NXFLOWREQF_OVERRIDE_ADDRESS_SELECTION 0x0040  /* override system address selection */
#define NXFLOWREQF_USE_STABLE_ADDRESS     0x0080  /* if override local, use stable address */
#define NXFLOWREQF_FLOWADV        0x0100  /* allocate flow advisory */
#define NXFLOWREQF_ASIS           0x0200  /* create flow as is in nfr */
#define NXFLOWREQF_LOW_LATENCY    0x0400  /* low latency flow */

#define NXFLOWREQF_BITS                                                   \
	"\020\01TRACK\02QOS_MARKING\03FILTER\04CUSTOM_ETHER\05IPV6_ULA" \
	"\06LISTENER\07OVERRIDE_ADDRESS_SELECTION\010USE_STABLE_ADDRESS" \
	"\011ALLOC_FLOWADV\012ASIS\013LOW_LATENCY"

struct flow_ip_addr {
	union {
		struct in_addr  _v4;
		struct in6_addr _v6;
		uint8_t         _addr8[16];
		uint16_t        _addr16[8];
		uint32_t        _addr32[4];
		uint64_t        _addr64[2];
	};
};

struct flow_key {
	uint16_t                fk_mask;
	uint8_t                 fk_ipver;
	uint8_t                 fk_proto;
	uint16_t                fk_sport;
	uint16_t                fk_dport;
	struct flow_ip_addr     fk_src;
	struct flow_ip_addr     fk_dst;
	uint64_t                fk_pad[1];      /* pad to 48 bytes */
} __attribute__((__aligned__(16)));

#define fk_src4                 fk_src._v4
#define fk_dst4                 fk_dst._v4
#define fk_src6                 fk_src._v6
#define fk_dst6                 fk_dst._v6

#define FLOW_KEY_LEN            sizeof(struct flow_key)
#define FK_HASH_SEED            0xabcd

#define FKMASK_IPVER            (((uint16_t)1) << 0)
#define FKMASK_PROTO            (((uint16_t)1) << 1)
#define FKMASK_SRC              (((uint16_t)1) << 2)
#define FKMASK_SPORT            (((uint16_t)1) << 3)
#define FKMASK_DST              (((uint16_t)1) << 4)
#define FKMASK_DPORT            (((uint16_t)1) << 5)

#define FKMASK_2TUPLE           (FKMASK_PROTO | FKMASK_SPORT)
#define FKMASK_3TUPLE           (FKMASK_2TUPLE | FKMASK_IPVER | FKMASK_SRC)
#define FKMASK_4TUPLE           (FKMASK_3TUPLE | FKMASK_DPORT)
#define FKMASK_5TUPLE           (FKMASK_4TUPLE | FKMASK_DST)
#define FKMASK_IPFLOW1          FKMASK_PROTO
#define FKMASK_IPFLOW2          (FKMASK_IPFLOW1 | FKMASK_IPVER | FKMASK_SRC)
#define FKMASK_IPFLOW3          (FKMASK_IPFLOW2 | FKMASK_DST)
#define FKMASK_IDX_MAX          7

extern const struct flow_key fk_mask_2tuple;
extern const struct flow_key fk_mask_3tuple;
extern const struct flow_key fk_mask_4tuple;
extern const struct flow_key fk_mask_5tuple;
extern const struct flow_key fk_mask_ipflow1;
extern const struct flow_key fk_mask_ipflow2;
extern const struct flow_key fk_mask_ipflow3;

#define FLOW_KEY_CLEAR(_fk) do {                                        \
	_CASSERT(FLOW_KEY_LEN == 48);                                   \
	_CASSERT(FLOW_KEY_LEN == sizeof(struct flow_key));              \
	sk_zero_48(_fk);                                                \
} while (0)

#ifdef KERNEL
/* mask off userland-settable bits */
#define NXFLOWREQF_MASK \
    (NXFLOWREQF_TRACK | NXFLOWREQF_QOS_MARKING | NXFLOWREQF_FILTER | \
    NXFLOWREQF_CUSTOM_ETHER | NXFLOWREQF_IPV6_ULA | NXFLOWREQF_LISTENER | \
    NXFLOWREQF_OVERRIDE_ADDRESS_SELECTION | NXFLOWREQF_USE_STABLE_ADDRESS | \
    NXFLOWREQF_FLOWADV | NXFLOWREQF_LOW_LATENCY)

#define NXFLOWREQF_EXT_PORT_RSV   0x1000  /* external port reservation */
#define NXFLOWREQF_EXT_PROTO_RSV  0x2000  /* external proto reservation */

static inline void
nx_flow_req_internalize(struct nx_flow_req *req)
{
	/* init kernel only fields */
	bzero(&req->_nfr_opaque, sizeof(req->_nfr_opaque));
	req->nfr_flags &= NXFLOWREQF_MASK;
	req->nfr_context = NULL;
	req->nfr_flow_stats = NULL;
	req->nfr_port_reservation = NULL;
}

static inline void
nx_flow_req_externalize(struct nx_flow_req *req)
{
	/* neutralize kernel only fields */
	bzero(&req->_nfr_opaque, sizeof(req->_nfr_opaque));
	req->nfr_flags &= NXFLOWREQF_MASK;
}
#endif /* KERNEL */

struct nx_qset_info {
	uint64_t        nqi_id;
	uint16_t        nqi_flags;
	uint8_t         nqi_num_rx_queues;
	uint8_t         nqi_num_tx_queues;
};

#define NETIF_LLINK_MAX_QSETS 256
struct nx_llink_info {
	uuid_t          nli_netif_uuid;            /* nexus netif instance uuid */
	uint64_t        nli_link_id;
	uint16_t        nli_link_id_internal;
	uint8_t         nli_state;
	uint8_t         nli_flags;
	uint16_t        nli_qset_cnt;
	struct nx_qset_info nli_qset[NETIF_LLINK_MAX_QSETS];
};

#define NETIF_LLINK_INFO_VERSION  0x01
struct nx_llink_info_req {
	uint16_t        nlir_version;
	uint16_t        nlir_llink_cnt;
	struct nx_llink_info nlir_llink[0];
};

/*
 * Nexus controller descriptor.
 */
struct nexus_controller {
#ifndef KERNEL
	int             ncd_fd;
	guardid_t       ncd_guard;
#else /* KERNEL */
	struct nxctl    *ncd_nxctl;
#endif /* KERNEL */
};

/*
 * Nexus attributes.
 */
struct nexus_attr {
	uint64_t        nxa_requested;  /* customized attributes */
	uint64_t        nxa_tx_rings;   /* # of channel transmit rings */
	uint64_t        nxa_rx_rings;   /* # of channel receive rings */
	uint64_t        nxa_tx_slots;   /* # of slots per channel TX ring */
	uint64_t        nxa_rx_slots;   /* # of slots per channel RX ring */
	uint64_t        nxa_buf_size;   /* size of each buffer */
	uint64_t        nxa_meta_size;  /* size of metadata per buffer */
	uint64_t        nxa_stats_size; /* size of statistics region */
	uint64_t        nxa_anonymous;  /* bool: allow anonymous clients */
	uint64_t        nxa_pipes;      /* number of pipes */
	uint64_t        nxa_extensions; /* extension-specific attribute */
	uint64_t        nxa_mhints;     /* memory usage hints */
	uint64_t        nxa_ifindex;    /* network interface index */
	uint64_t        nxa_flowadv_max; /* max flow advisory entries */
	uint64_t        nxa_qmap;       /* queue mapping type */
	uint64_t        nxa_checksum_offload;   /* partial checksum offload */
	uint64_t        nxa_user_packet_pool;   /* user packet pool */
	uint64_t        nxa_nexusadv_size;      /* size of advisory region */
	uint64_t        nxa_user_channel;       /* user channel open allowed */
	uint64_t        nxa_max_frags;  /* max fragments per packet */
	/*
	 * reject channel operations if the nexus peer has closed the channel.
	 * valid only for user-pipe nexus.
	 */
	uint64_t        nxa_reject_on_close;
};

/*
 * Flags for nxa_requested; keep in sync with NXPREQ_* flags.
 * Note that these are 64-bit, whereas nxpreq_requested is
 * 32-bit wide; for not this won't matter.
 */
#define NXA_REQ_TX_RINGS        (1ULL << 0)     /* 0x0000000000000001 */
#define NXA_REQ_RX_RINGS        (1ULL << 1)     /* 0x0000000000000002 */
#define NXA_REQ_TX_SLOTS        (1ULL << 2)     /* 0x0000000000000004 */
#define NXA_REQ_RX_SLOTS        (1ULL << 3)     /* 0x0000000000000008 */
#define NXA_REQ_BUF_SIZE        (1ULL << 4)     /* 0x0000000000000010 */
#define NXA_REQ_META_SIZE       (1ULL << 5)     /* 0x0000000000000020 */
#define NXA_REQ_STATS_SIZE      (1ULL << 6)     /* 0x0000000000000040 */
#define NXA_REQ_ANONYMOUS       (1ULL << 7)     /* 0x0000000000000080 */
#define NXA_REQ_PIPES           (1ULL << 8)     /* 0x0000000000000100 */
#define NXA_REQ_EXTENSIONS      (1ULL << 9)     /* 0x0000000000000200 */
#define NXA_REQ_MHINTS          (1ULL << 10)    /* 0x0000000000000400 */
#define NXA_REQ_FLOWADV_MAX     (1ULL << 11)    /* 0x0000000000000800 */
#define NXA_REQ_QMAP            (1ULL << 12)    /* 0x0000000000001000 */
#define NXA_REQ_CHECKSUM_OFFLOAD (1ULL << 13)   /* 0x0000000000002000 */
#define NXA_REQ_USER_PACKET_POOL (1ULL << 14)   /* 0x0000000000004000 */
#define NXA_REQ_CAPABILITIES    (1ULL << 15)    /* 0x0000000000008000 */
#define NXA_REQ_NEXUSADV_SIZE   (1ULL << 16)    /* 0x0000000000010000 */
#define NXA_REQ_IFINDEX         (1ULL << 17)    /* 0x0000000000020000 */
#define NXA_REQ_USER_CHANNEL    (1ULL << 18)    /* 0x0000000000040000 */
#define NXA_REQ_MAX_FRAGS       (1ULL << 19)    /* 0x0000000000080000 */
#define NXA_REQ_REJECT_ON_CLOSE (1ULL << 20)    /* 0x0000000000100000 */

#ifndef KERNEL
#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)
__BEGIN_DECLS
/* system calls */
extern int __nexus_open(struct nxctl_init *init, const uint32_t init_len);
extern int __nexus_register(int ctl, struct nxprov_reg *reg,
    const uint32_t reg_len, uuid_t *prov_uuid, const uint32_t prov_uuid_len);
extern int __nexus_deregister(int ctl, const uuid_t prov_uuid,
    const uint32_t prov_uuid_len);
extern int __nexus_create(int ctl, const uuid_t prov_uuid,
    const uint32_t prov_uuid_len, uuid_t *nx_uuid, const uint32_t nx_uuid_len);
extern int __nexus_destroy(int ctl, const uuid_t nx_uuid,
    const uint32_t nx_uuid_len);
extern int __nexus_get_opt(int ctl, const uint32_t opt, void *aoptval,
    uint32_t *aoptlen);
extern int __nexus_set_opt(int ctl, const uint32_t opt, const void *aoptval,
    const uint32_t optlen);

/* private nexus controller APIs */
extern int __os_nexus_ifattach(const nexus_controller_t ctl,
    const uuid_t nx_uuid, const char *ifname, const uuid_t netif_uuid,
    boolean_t host, uuid_t *nx_if_uuid);
extern int __os_nexus_ifdetach(const nexus_controller_t ctl,
    const uuid_t nx_uuid, const uuid_t nx_if_uuid);

/* private flow APIs */
extern int __os_nexus_flow_add(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const struct nx_flow_req *nfr);
extern int __os_nexus_flow_del(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const struct nx_flow_req *nfr);
extern int __os_nexus_get_llink_info(const nexus_controller_t ncd,
    const uuid_t nx_uuid, const struct nx_llink_info_req *nlir, size_t len);

__END_DECLS
#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */
#endif /* !KERNEL */
#if defined(LIBSYSCALL_INTERFACE) || defined(BSD_KERNEL_PRIVATE)
#include <skywalk/nexus_common.h>
#endif /* LIBSYSCALL_INTERFACE || BSD_KERNEL_PRIVATE */
#endif /* PRIVATE || BSD_KERNEL_PRIVATE */
#endif /* !_SKYWALK_OS_NEXUS_PRIVATE_H_ */
