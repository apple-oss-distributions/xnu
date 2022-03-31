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
 * Copyright (C) 2012-2014 Matteo Landi, Luigi Rizzo, Giuseppe Lettieri.
 * All rights reserved.
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

#ifndef _SKYWALK_NEXUS_NEXUSVAR_H_
#define _SKYWALK_NEXUS_NEXUSVAR_H_

#ifdef BSD_KERNEL_PRIVATE
#include <skywalk/core/skywalk_var.h>
#include <skywalk/os_nexus_private.h>

struct chreq;
struct nxdom;
struct kern_channel;
struct kern_nexus_domain_provider;

/*
 * Nexus controller instance.
 */
struct nxctl {
	decl_lck_mtx_data(, nxctl_lock);
	uint32_t                nxctl_refcnt;
	uint32_t                nxctl_flags;
	uuid_t                  nxctl_uuid;
	uuid_t                  nxctl_proc_uuid;
	uint64_t                nxctl_proc_uniqueid;
	STAILQ_ENTRY(nxctl)     nxctl_link;
	struct fileproc         *nxctl_fp;
	kauth_cred_t            nxctl_cred;
};

#define NEXUSCTLF_ATTACHED      0x1
#define NEXUSCTLF_NOFDREF       0x2
#define NEXUSCTLF_KERNEL        0x4

#define NEXUSCTLF_BITS  \
	"\020\01ATTACHED\02NOFDREF\03KERNEL"

/*
 * Nexus port binding structure.
 */
struct nxbind {
	uint32_t                nxb_flags;
	pid_t                   nxb_pid;
	uint64_t                nxb_uniqueid;
	uuid_t                  nxb_exec_uuid;
	uint32_t                nxb_key_len;
	void                    *nxb_key;
};

#define NXBF_MATCH_UNIQUEID     0x1     /* match against process's unique ID */
#define NXBF_MATCH_EXEC_UUID    0x2     /* match against executable's UUID */
#define NXBF_MATCH_KEY          0x4     /* match against key blob */

#define NXBF_BITS       \
	"\020\01UNIQUEID\02EXEC_UUID\03KEY"

/*
 * Nexus port info structure.
 */
struct nx_port_info {
	/*
	 * We need to store some states on the nexus port info,
	 * e.g. defunct.  The states are encoded in the tagged
	 * pointer handle npi_nah.
	 */
	uintptr_t               npi_nah;
	struct nxbind           *npi_nxb;
	void                    *npi_info;
};

/*
 * Used for indicating what type is attached to npi_info
 * The type enum is defined here. One namespace for all nexus types.
 * The actual structure is defined in nexus specific headers.
 */
typedef enum {
	NX_PORT_INFO_TYPE_NETIF = 0x10000001
} nx_port_info_type_t;

/*
 * Header of nexus specific structure npi_info
 */
struct nx_port_info_header {
	nx_port_info_type_t     ih_type;
	size_t                  ih_size;
};

#define NX_PORT_CHUNK      64
#define NX_PORT_CHUNK_FREE 0xffffffffffffffff /* entire chunk is free */

/*
 * Nexus port state type.
 *
 * Be mindful that due to the use of tagger pointer for nexus adapter in the
 * nexus port info structure, this type gets encoded with the requirement
 * that the object addresses are aligned on 4-bytes boundary at the minimum.
 * That leaves 2 bits for the states, therefore limiting the maximum enum
 * value to 3.
 */
typedef enum {
	NEXUS_PORT_STATE_WORKING = 0,           /* fully operational */
	NEXUS_PORT_STATE_DEFUNCT,               /* no longer in service */
	NEXUS_PORT_STATE_RESERVED_1,            /* for future use */
	NEXUS_PORT_STATE_RESERVED_2,            /* for future use */
	NEXUS_PORT_STATE_MAX = NEXUS_PORT_STATE_RESERVED_2
} nexus_port_state_t;

#define NPI_NA_STATE_MASK       ((uintptr_t)0x3)        /* 11 */
#define NPI_NA_TAG_MASK         ((uintptr_t)0x3)        /* 11 */

#define NPI_NA_TAG(_p)          ((uintptr_t)(_p) & NPI_NA_TAG_MASK)
#define NPI_NA_ADDR_MASK        (~NPI_NA_TAG_MASK)

#define NPI_NA_STATE(_p)        ((uintptr_t)(_p) & NPI_NA_STATE_MASK)
#define NPI_NA_STATE_ENC(_s)    ((uintptr_t)(_s) & NPI_NA_STATE_MASK)

#define NPI_NA_ADDR(_p)         ((uintptr_t)(_p) & NPI_NA_ADDR_MASK)
#define NPI_NA_ADDR_ENC(_p)     ((uintptr_t)(_p) & NPI_NA_ADDR_MASK)

#define NPI_NA_ENCODE(_p, _s)   (NPI_NA_ADDR_ENC(_p) | NPI_NA_STATE_ENC(_s))

#define NPI_NA(_npi)            \
	((struct nexus_adapter *)NPI_NA_ADDR((_npi)->npi_nah))
#define NPI_IS_DEFUNCT(_npi)    \
	(NPI_NA_STATE((_npi)->npi_nah) == NEXUS_PORT_STATE_DEFUNCT)

/*
 * Nexus-wide advisory region and object.
 */
struct kern_nexus_advisory {
	struct skmem_region     *nxv_reg;
	void                    *nxv_adv;
	nexus_advisory_type_t   nxv_adv_type;
	union {
		struct sk_nexusadv             *flowswitch_nxv_adv;
		struct netif_nexus_advisory    *netif_nxv_adv;
	};
};

/*
 * Nexus instance.
 *
 * At present most fields are protected by sk_lock.  The exception is
 * the nx_ch_if_adv_head list which uses nx_ch_if_adv_lock instead.
 *
 * In cases where sk_lock, nx_ch_if_adv_lock and ch_lock must be held,
 * the following ordering needs to be followed:
 *
 *   sk_lock -> nx_ch_if_adv_lock -> ch_lock
 */
struct kern_nexus {
	uint32_t                nx_refcnt;
	volatile uint32_t       nx_flags;
	void                    *nx_ctx;
	nexus_ctx_release_fn_t  nx_ctx_release;
	struct kern_nexus_provider *nx_prov;
	uint64_t                nx_id;
	uuid_t                  nx_uuid;
	STAILQ_ENTRY(kern_nexus) nx_prov_link;
	RB_ENTRY(kern_nexus)    nx_link;
	STAILQ_HEAD(, kern_channel) nx_ch_head;
	uint32_t                nx_ch_count;
	STAILQ_HEAD(, kern_channel) nx_ch_nonxref_head;
	decl_lck_rw_data(, nx_ch_if_adv_lock);
	STAILQ_HEAD(, kern_channel) nx_ch_if_adv_head;
	void                    *nx_arg;
	struct kern_pbufpool    *nx_rx_pp;
	struct kern_pbufpool    *nx_tx_pp;
	struct kern_nexus_advisory nx_adv;

	/* nexus port */
	struct nx_port_info     *nx_ports;
	bitmap_t                *nx_ports_bmap;
	uint32_t                nx_active_ports;
	uint32_t                nx_num_ports;
};

#define NXF_ATTACHED    0x1
#define NXF_CLOSED      0x2             /* attached but closed */
#define NXF_REJECT      (1U << 31)      /* not accepting channel activities */

#define NXF_BITS        \
	"\020\01ATTACHED\02CLOSED\040REJECT"

#define NX_PROV(_nx)            ((_nx)->nx_prov)
#define NX_DOM_PROV(_nx)        (NX_PROV(_nx)->nxprov_dom_prov)
#define NX_DOM(_nx)             (NX_DOM_PROV(_nx)->nxdom_prov_dom)

#define NX_REJECT_ACT(_nx)      (((_nx)->nx_flags & NXF_REJECT) != 0)

/*
 * Nexus provider.
 */
struct kern_nexus_provider {
	uint32_t                        nxprov_refcnt;
	uint32_t                        nxprov_flags;
	STAILQ_ENTRY(kern_nexus_provider) nxprov_link;
	STAILQ_HEAD(, kern_nexus)       nxprov_nx_head;
	uint32_t                        nxprov_nx_count;
	struct nxctl                    *nxprov_ctl;
	uuid_t                          nxprov_uuid;
	struct kern_nexus_domain_provider *nxprov_dom_prov;
	union {
		struct kern_nexus_provider_init nxprov_ext;
		struct kern_nexus_netif_provider_init nxprov_netif_ext;
	};
	struct nxprov_params            *nxprov_params;
	struct skmem_region_params      nxprov_region_params[SKMEM_REGIONS];
};

/* valid flags for nxprov_flags */
#define NXPROVF_ATTACHED        0x1     /* attached to global list */
#define NXPROVF_CLOSED          0x2     /* attached but closed */
#define NXPROVF_EXTERNAL        0x4     /* external nexus provider */
#define NXPROVF_VIRTUAL_DEVICE  0x8     /* device is virtual (no DMA) */

#define NXPROV_LLINK(_nxp) \
	((_nxp)->nxprov_params->nxp_flags & NXPF_NETIF_LLINK)

#define NXPROVF_BITS    \
	"\020\01ATTACHED\02CLOSED\03EXTERNAL\04VIRTUALDEV"

#define NX_ANONYMOUS_PROV(_nx)  \
	(NX_PROV(_nx)->nxprov_params->nxp_flags & NXPF_ANONYMOUS)
#define NX_USER_CHANNEL_PROV(_nx) \
	(NX_PROV(_nx)->nxprov_params->nxp_flags & NXPF_USER_CHANNEL)
#define NX_LLINK_PROV(_nx)    NXPROV_LLINK(NX_PROV(_nx))

/*
 * Nexus domain provider.
 */
struct kern_nexus_domain_provider {
	STAILQ_ENTRY(kern_nexus_domain_provider) nxdom_prov_link;
	STAILQ_ENTRY(kern_nexus_domain_provider) nxdom_prov_detaching_link;
	char                    nxdom_prov_name[64];
	uuid_t                  nxdom_prov_uuid;
	uint64_t                nxdom_prov_gencnt;
	uint32_t                nxdom_prov_refcnt;
	uint32_t                nxdom_prov_flags;
	struct nxdom            *nxdom_prov_dom;
	struct kern_nexus_domain_provider_init nxdom_prov_ext;
	/*
	 * The callbacks are grouped together to simplify the
	 * initialization of external domain providers; see
	 * kern_nexus_register_domain_provider() for details.
	 */
	struct nxdom_prov_cb {
		int (*dp_cb_init)(struct kern_nexus_domain_provider *);
		void (*dp_cb_fini)(struct kern_nexus_domain_provider *);
		int (*dp_cb_params)(struct kern_nexus_domain_provider *,
		    const uint32_t, const struct nxprov_params *,
		    struct nxprov_params *,
		    struct skmem_region_params[SKMEM_REGIONS]);
		int (*dp_cb_mem_new)(struct kern_nexus_domain_provider *,
		    struct kern_nexus *, struct nexus_adapter *);
		int (*dp_cb_config)(struct kern_nexus_domain_provider *,
		    struct kern_nexus *, struct nx_cfg_req *, int,
		    struct proc *, kauth_cred_t);
		int (*dp_cb_nx_ctor)(struct kern_nexus *);
		void (*dp_cb_nx_dtor)(struct kern_nexus *);
		int (*dp_cb_nx_mem_info)(struct kern_nexus *,
		    struct kern_pbufpool **, struct kern_pbufpool **);
		size_t (*dp_cb_nx_mib_get)(struct kern_nexus *,
		    struct nexus_mib_filter *, void *, size_t, struct proc *);
		int (*dp_cb_nx_stop)(struct kern_nexus *);
	} nxdom_prov_cb;
#define nxdom_prov_init         nxdom_prov_cb.dp_cb_init
#define nxdom_prov_fini         nxdom_prov_cb.dp_cb_fini
#define nxdom_prov_params       nxdom_prov_cb.dp_cb_params
#define nxdom_prov_mem_new      nxdom_prov_cb.dp_cb_mem_new
#define nxdom_prov_config       nxdom_prov_cb.dp_cb_config
#define nxdom_prov_nx_ctor      nxdom_prov_cb.dp_cb_nx_ctor
#define nxdom_prov_nx_dtor      nxdom_prov_cb.dp_cb_nx_dtor
#define nxdom_prov_nx_mem_info  nxdom_prov_cb.dp_cb_nx_mem_info
#define nxdom_prov_nx_mib_get   nxdom_prov_cb.dp_cb_nx_mib_get
#define nxdom_prov_nx_stop      nxdom_prov_cb.dp_cb_nx_stop
};

#define NXDOMPROVF_INITIALIZED  0x1     /* provider has been initialized */
#define NXDOMPROVF_ATTACHED     0x2     /* provider is attached to a domain */
#define NXDOMPROVF_DETACHING    0x4     /* provider is being detached */
#define NXDOMPROVF_EXT          0x8     /* external provider */
#define NXDOMPROVF_EXT_INITED   0x10    /* nxpi_init() succeeded */
#define NXDOMPROVF_DEFAULT      0x20    /* default provider for domain */

struct nxp_bounds {
	uint32_t        nb_def;
	uint32_t        nb_min;
	uint32_t        nb_max;
};

/*
 * Nexus domain.
 *
 * Each Nexus type is represented by a Nexus domain; there can
 * be more than one providers for a given domain.
 */
struct nxdom {
	STAILQ_ENTRY(nxdom) nxdom_link;
	STAILQ_HEAD(, kern_nexus_domain_provider) nxdom_prov_head;
	nexus_type_t    nxdom_type;
	nexus_meta_type_t nxdom_md_type;
	nexus_meta_subtype_t nxdom_md_subtype;
	uint32_t        nxdom_flags;
	struct nxp_bounds nxdom_ports;
	struct nxp_bounds nxdom_tx_rings;
	struct nxp_bounds nxdom_rx_rings;
	struct nxp_bounds nxdom_tx_slots;
	struct nxp_bounds nxdom_rx_slots;
	struct nxp_bounds nxdom_buf_size;
	struct nxp_bounds nxdom_meta_size;
	struct nxp_bounds nxdom_stats_size;
	struct nxp_bounds nxdom_pipes;
	struct nxp_bounds nxdom_extensions;
	struct nxp_bounds nxdom_mhints;
	struct nxp_bounds nxdom_flowadv_max;
	struct nxp_bounds nxdom_nexusadv_size;
	struct nxp_bounds nxdom_capabilities;
	struct nxp_bounds nxdom_qmap;
	struct nxp_bounds nxdom_max_frags;
	struct skmem_region_params nxdom_region_params[SKMEM_REGIONS];
	const char      *nxdom_name;

	/*
	 * Nexus domain callbacks.
	 */
	void (*nxdom_init)(struct nxdom *);             /* optional */
	void (*nxdom_terminate)(struct nxdom *);        /* optional */
	void (*nxdom_fini)(struct nxdom *);             /* optional */
	int (*nxdom_find_port)                          /* optional */
	(struct kern_nexus *, boolean_t, nexus_port_t *);
	boolean_t (*nxdom_port_is_reserved)             /* optional */
	(struct kern_nexus *, nexus_port_t);
	int (*nxdom_bind_port)                          /* required */
	(struct kern_nexus *, nexus_port_t *, struct nxbind *, void *);
	int (*nxdom_unbind_port)                        /* required */
	(struct kern_nexus *, nexus_port_t);
	int (*nxdom_connect)                            /* required */
	(struct kern_nexus_domain_provider *, struct kern_nexus *,
	struct kern_channel *, struct chreq *, struct kern_channel *,
	struct nxbind *, struct proc *);
	void (*nxdom_disconnect)                        /* required */
	(struct kern_nexus_domain_provider *, struct kern_nexus *,
	struct kern_channel *);
	void (*nxdom_defunct)                           /* required */
	(struct kern_nexus_domain_provider *, struct kern_nexus *,
	struct kern_channel *, struct proc *);
	void (*nxdom_defunct_finalize)                  /* required */
	(struct kern_nexus_domain_provider *, struct kern_nexus *,
	struct kern_channel *, boolean_t);
};

#define NEXUSDOMF_INITIALIZED   0x1     /* domain has been initialized */
#define NEXUSDOMF_ATTACHED      0x2     /* domain is globally attached */
#define NEXUSDOMF_TERMINATED    0x4     /* domain has been terminated */

#define NXDOM_DEF(_dom, var)    ((_dom)->nxdom_##var.nb_def)
#define NXDOM_MIN(_dom, var)    ((_dom)->nxdom_##var.nb_min)
#define NXDOM_MAX(_dom, var)    ((_dom)->nxdom_##var.nb_max)

extern struct nexus_controller kernnxctl;
extern lck_grp_t nexus_lock_group;
extern lck_grp_t nexus_mbq_lock_group;
extern lck_grp_t nexus_pktq_lock_group;
extern lck_attr_t nexus_lock_attr;
extern kern_allocation_name_t skmem_tag_nx_key;
extern kern_allocation_name_t skmem_tag_nx_port_info;

extern struct kern_nexus_domain_provider *nxdom_prov_default[NEXUS_TYPE_MAX];

#define NX_SHARED_NXCTL_INSTANCE(_nxctl)        \
    ((_nxctl) == kernnxctl.ncd_nxctl)

#define NXCTL_LOCK(_nxctl)      do {                    \
	if (!NX_SHARED_NXCTL_INSTANCE((_nxctl))) {      \
	        lck_mtx_lock(&((_nxctl)->nxctl_lock));  \
	} else {                                        \
	        LCK_MTX_ASSERT(&((_nxctl)->nxctl_lock), \
	            LCK_MTX_ASSERT_NOTOWNED);           \
	}                                               \
} while (0)

#define NXCTL_UNLOCK(_nxctl)    do {                    \
	if (!NX_SHARED_NXCTL_INSTANCE((_nxctl))) {      \
	        lck_mtx_unlock(&((_nxctl)->nxctl_lock));\
	}                                               \
	LCK_MTX_ASSERT(&((_nxctl)->nxctl_lock),         \
	    LCK_MTX_ASSERT_NOTOWNED);                   \
} while (0)

#define NXCTL_LOCK_ASSERT_HELD(_nxctl)  do {            \
	if (!NX_SHARED_NXCTL_INSTANCE((_nxctl))) {      \
	        LCK_MTX_ASSERT(&((_nxctl)->nxctl_lock), \
	            LCK_MTX_ASSERT_OWNED);              \
	} else {                                        \
	        LCK_MTX_ASSERT(&((_nxctl)->nxctl_lock), \
	            LCK_MTX_ASSERT_NOTOWNED);           \
	}                                               \
} while (0)

__BEGIN_DECLS
extern int nexus_init(void);
extern void nexus_fini(void);

extern struct kern_nexus *nx_create(struct nxctl *, const uuid_t,
    const nexus_type_t, const void *, nexus_ctx_release_fn_t,
    struct kern_pbufpool *, struct kern_pbufpool *, int *);
extern void nx_retain(struct kern_nexus *);
extern void nx_retain_locked(struct kern_nexus *);
extern int nx_release(struct kern_nexus *);
extern int nx_release_locked(struct kern_nexus *);
extern void nx_detach(struct kern_nexus *);
extern void nx_stop(struct kern_nexus *nx);
extern int nx_close(struct kern_nexus *, boolean_t);
extern int nx_destroy(struct nxctl *, const uuid_t);
extern struct kern_nexus *nx_find(const uuid_t, boolean_t);
extern int nx_advisory_alloc(struct kern_nexus *, const char *,
    struct skmem_region_params *, nexus_advisory_type_t);
extern void nx_advisory_free(struct kern_nexus *);
extern int nx_port_find(struct kern_nexus *, nexus_port_t,
    nexus_port_t, nexus_port_t *);
extern int nx_port_alloc(struct kern_nexus *, nexus_port_t,
    struct nxbind *, struct nexus_adapter **, struct proc *);
extern int nx_port_bind(struct kern_nexus *, nexus_port_t,
    struct nxbind *);
extern int nx_port_bind_info(struct kern_nexus *, nexus_port_t,
    struct nxbind *, void *);
extern int nx_port_unbind(struct kern_nexus *, nexus_port_t);
extern struct nexus_adapter *nx_port_get_na(struct kern_nexus *,
    nexus_port_t);
extern int nx_port_get_info(struct kern_nexus *, nexus_port_t,
    nx_port_info_type_t, void *, uint32_t);
extern void nx_port_defunct(struct kern_nexus *, nexus_port_t);
extern void nx_port_free(struct kern_nexus *, nexus_port_t);
extern void nx_port_free_all(struct kern_nexus *);
extern bool nx_port_is_valid(struct kern_nexus *, nexus_port_t);
extern bool nx_port_is_defunct(struct kern_nexus *, nexus_port_t);
extern void nx_port_foreach(struct kern_nexus *, void (^)(nexus_port_t));
extern void nx_interface_advisory_notify(struct kern_nexus *);

extern struct nxctl *nxctl_create(struct proc *, struct fileproc *,
    const uuid_t, int *);
extern void nxctl_close(struct nxctl *nxctl);
extern int nxctl_get_opt(struct nxctl *, struct sockopt *);
extern int nxctl_set_opt(struct nxctl *, struct sockopt *);
extern void nxctl_retain(struct nxctl *);
extern int nxctl_release(struct nxctl *);
extern void nxctl_dtor(void *);

extern int nxprov_advise_connect(struct kern_nexus *, struct kern_channel *,
    struct proc *p);
extern void nxprov_advise_disconnect(struct kern_nexus *,
    struct kern_channel *);
extern struct kern_nexus_provider *nxprov_create(struct proc *,
    struct nxctl *, struct nxprov_reg *, int *);
extern struct kern_nexus_provider *nxprov_create_kern(struct nxctl *,
    struct kern_nexus_domain_provider *, struct nxprov_reg *,
    const struct kern_nexus_provider_init *init, int *err);
extern int nxprov_close(struct kern_nexus_provider *, boolean_t);
extern int nxprov_destroy(struct nxctl *, const uuid_t);
extern void nxprov_retain(struct kern_nexus_provider *);
extern int nxprov_release(struct kern_nexus_provider *);
extern struct nxprov_params *nxprov_params_alloc(zalloc_flags_t);
extern void nxprov_params_free(struct nxprov_params *);

struct nxprov_adjusted_params {
	nexus_meta_subtype_t *adj_md_subtype;
	boolean_t *adj_md_magazines;
	uint32_t *adj_stats_size;
	uint32_t *adj_flowadv_max;
	uint32_t *adj_nexusadv_size;
	uint32_t *adj_caps;
	uint32_t *adj_tx_rings;
	uint32_t *adj_rx_rings;
	uint32_t *adj_tx_slots;
	uint32_t *adj_rx_slots;
	uint32_t *adj_alloc_rings;
	uint32_t *adj_free_rings;
	uint32_t *adj_alloc_slots;
	uint32_t *adj_free_slots;
	uint32_t *adj_buf_size;
	struct skmem_region_params *adj_buf_srp;
	uint32_t *adj_max_frags;
	uint32_t *adj_event_rings;
	uint32_t *adj_event_slots;
	uint32_t *adj_max_buffers;
};

extern int nxprov_params_adjust(struct kern_nexus_domain_provider *,
    const uint32_t, const struct nxprov_params *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS], const struct nxdom *,
    const struct nxdom *, const struct nxdom *,
    int (*adjust_fn)(const struct kern_nexus_domain_provider *,
    const struct nxprov_params *, struct nxprov_adjusted_params *));

extern void nxdom_attach_all(void);
extern void nxdom_detach_all(void);
extern struct nxdom *nxdom_find(nexus_type_t);

extern struct kern_nexus_domain_provider *nxdom_prov_find(
	const struct nxdom *, const char *);
extern struct kern_nexus_domain_provider *nxdom_prov_find_uuid(const uuid_t);
extern int nxdom_prov_add(struct nxdom *, struct kern_nexus_domain_provider *);
extern void nxdom_prov_del(struct kern_nexus_domain_provider *);
extern void nxdom_prov_retain_locked(struct kern_nexus_domain_provider *);
extern void nxdom_prov_retain(struct kern_nexus_domain_provider *);
extern boolean_t nxdom_prov_release_locked(struct kern_nexus_domain_provider *);
extern boolean_t nxdom_prov_release(struct kern_nexus_domain_provider *);
extern int nxdom_prov_validate_params(struct kern_nexus_domain_provider *,
    const struct nxprov_reg *, struct nxprov_params *,
    struct skmem_region_params[SKMEM_REGIONS], const uint32_t);

extern struct nxbind *nxb_alloc(zalloc_flags_t);
extern void nxb_free(struct nxbind *);
extern boolean_t nxb_is_equal(struct nxbind *, struct nxbind *);
extern void nxb_move(struct nxbind *, struct nxbind *);

typedef void kern_nexus_walktree_f_t(struct kern_nexus *, void *);
extern void kern_nexus_walktree(kern_nexus_walktree_f_t *, void *, boolean_t);

extern int kern_nexus_get_pbufpool_info(const uuid_t nx_uuid,
    struct kern_pbufpool_memory_info *rx_pool,
    struct kern_pbufpool_memory_info *tx_pool);
__END_DECLS

#include <skywalk/nexus/nexus_adapter.h>

__attribute__((always_inline))
static inline int
nx_sync_tx(struct __kern_channel_ring *kring, boolean_t commit)
{
	struct kern_nexus_provider *nxprov = NX_PROV(KRNA(kring)->na_nx);

	ASSERT(kring->ckr_tx == NR_TX);
	if (nxprov->nxprov_ext.nxpi_sync_tx != NULL) {
		return nxprov->nxprov_ext.nxpi_sync_tx(nxprov,
		           KRNA(kring)->na_nx, kring,
		           (commit ? KERN_NEXUS_SYNCF_COMMIT : 0));
	} else {
		return 0;
	}
}

__attribute__((always_inline))
static inline int
nx_sync_rx(struct __kern_channel_ring *kring, boolean_t commit)
{
	struct kern_nexus_provider *nxprov = NX_PROV(KRNA(kring)->na_nx);

	ASSERT(kring->ckr_tx == NR_RX);
	if (nxprov->nxprov_ext.nxpi_sync_rx != NULL) {
		return nxprov->nxprov_ext.nxpi_sync_rx(nxprov,
		           KRNA(kring)->na_nx, kring,
		           (commit ? KERN_NEXUS_SYNCF_COMMIT : 0));
	} else {
		return 0;
	}
}

__attribute__((always_inline))
static __inline__ void
nx_tx_doorbell(struct __kern_channel_ring *kring, boolean_t async)
{
	struct kern_nexus_provider *nxprov = NX_PROV(KRNA(kring)->na_nx);

	ASSERT(kring->ckr_tx == NR_TX);
	ASSERT(nxprov->nxprov_ext.nxpi_tx_doorbell != NULL);
	nxprov->nxprov_ext.nxpi_tx_doorbell(nxprov, KRNA(kring)->na_nx,
	    kring, (async ? KERN_NEXUS_TXDOORBELLF_ASYNC_REFILL: 0));
}

__attribute__((always_inline))
static inline int
nx_rx_sync_packets(struct __kern_channel_ring *kring, uint64_t packets[],
    uint32_t *count)
{
	struct kern_nexus_provider *nxprov = NX_PROV(KRNA(kring)->na_nx);

	ASSERT(kring->ckr_tx == NR_RX);
	if (nxprov->nxprov_ext.nxpi_rx_sync_packets != NULL) {
		return nxprov->nxprov_ext.nxpi_rx_sync_packets(nxprov,
		           KRNA(kring)->na_nx, kring, packets, count, 0);
	} else {
		return 0;
	}
}

__attribute__((always_inline))
static inline boolean_t
nx_has_rx_sync_packets(struct __kern_channel_ring *kring)
{
	struct kern_nexus_provider *nxprov = NX_PROV(KRNA(kring)->na_nx);

	ASSERT(kring->ckr_tx == NR_RX);
	return nxprov->nxprov_ext.nxpi_rx_sync_packets != NULL;
}

__attribute__((always_inline))
static __inline__ errno_t
nx_tx_qset_notify(struct kern_nexus *nx, struct netif_qset *qset)
{
	struct kern_nexus_provider *nxprov = NX_PROV(nx);
	sk_protect_t protect;
	errno_t err;

	ASSERT(nxprov->nxprov_netif_ext.nxnpi_tx_qset_notify != NULL);
	protect = sk_tx_notify_protect();
	err = nxprov->nxprov_netif_ext.nxnpi_tx_qset_notify(nxprov, nx, qset, 0);
	sk_tx_notify_unprotect(protect);
	return err;
}
#endif /* BSD_KERNEL_PRIVATE */
#endif /* _SKYWALK_NEXUS_NEXUSVAR_H_ */
