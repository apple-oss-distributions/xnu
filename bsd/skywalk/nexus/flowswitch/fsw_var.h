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

#ifndef _SKYWALK_NEXUS_FLOWSWITCH_FSWVAR_H_
#define _SKYWALK_NEXUS_FLOWSWITCH_FSWVAR_H_

#include <skywalk/os_skywalk_private.h>
#include <skywalk/nexus/flowswitch/nx_flowswitch.h>
#include <skywalk/nexus/flowswitch/flow/flow_var.h>

#include <net/if_var.h>
#include <net/network_agent.h>
#include <net/necp.h>
#include <net/pktap.h>

#define FSW_VP_DEV               0               /* device port */
#define FSW_VP_HOST              1               /* host port (MS) */
#define FSW_VP_USER_MIN          2               /* start of user vp port num */
#define FSW_VP_USER_MAX          NX_FSW_VP_MAX   /* end of user vp port num */
/* max flush batch size for device port */
#if !XNU_TARGET_OS_OSX
#define FSW_VP_DEV_BATCH_MAX             16
#else /* XNU_TARGET_OS_OSX */
#define FSW_VP_DEV_BATCH_MAX             32
#endif /* XNU_TARGET_OS_OSX */

#define FSW_REAP_THREADNAME "skywalk_fsw_reap_%s%s"

struct fsw_ip_frag_mgr;  /* forward declaration */
extern uint32_t fsw_ip_reass;
struct pktq;

#define FSW_DETACHF_DETACHING    0x10000000      /* detach in progress */
#define FSW_DETACHF_DETACHED     0x20000000      /* detached */

#define FSW_REAPF_RUNNING        0x00000001      /* thread is running */
#define FSW_REAPF_TERMINATEBLOCK 0x20000000      /* blocked waiting terminate */
#define FSW_REAPF_TERMINATING    0x40000000      /* thread is terminating */
#define FSW_REAPF_TERMINATED     0x80000000      /* thread is terminated */

extern kern_allocation_name_t skmem_tag_fsw_ports;
extern kern_allocation_name_t skmem_tag_fsw_ft;
extern kern_allocation_name_t skmem_tag_fsw_fb_hash;
extern kern_allocation_name_t skmem_tag_fsw_fob_hash;
extern kern_allocation_name_t skmem_tag_fsw_frb_hash;
extern kern_allocation_name_t skmem_tag_fsw_frib_hash;
extern kern_allocation_name_t skmem_tag_fsw_frag_mgr;

__BEGIN_DECLS

// generic
extern void fsw_init(void);
extern void fsw_uninit(void);
extern struct nx_flowswitch * fsw_alloc(zalloc_flags_t);
extern void fsw_free(struct nx_flowswitch *fsw);
extern int fsw_grow(struct nx_flowswitch *fsw, uint32_t grow);
extern int fsw_port_find(struct nx_flowswitch *fsw, nexus_port_t first,
    nexus_port_t last, nexus_port_t *nx_port);
extern int fsw_port_bind(struct nx_flowswitch *fsw, nexus_port_t nx_port,
    struct nxbind *nxb0);
extern int fsw_port_unbind(struct nx_flowswitch *fsw, nexus_port_t nx_port);
extern int fsw_port_na_defunct(struct nx_flowswitch *fsw,
    struct nexus_vp_adapter *vpna);
extern size_t fsw_mib_get(struct nx_flowswitch *fsw,
    struct nexus_mib_filter *filter, void *out, size_t len, struct proc *p);
extern int fsw_attach_vp(struct kern_nexus *nx, struct kern_channel *ch,
    struct chreq *chr, struct nxbind *nxb, struct proc *p,
    struct nexus_vp_adapter **vpna);
extern int fsw_ctl(struct kern_nexus *nx, nxcfg_cmd_t nc_cmd, struct proc *p,
    void *data);
extern int fsw_ctl_detach(struct kern_nexus *nx, struct proc *p,
    struct nx_spec_req *nsr);
extern boolean_t fsw_should_drop_packet(boolean_t is_input, sa_family_t af,
    uint8_t proto, const char *ifname);
extern int fsw_port_alloc(struct nx_flowswitch *fsw, struct nxbind *nxb,
    struct nexus_vp_adapter **vpna, nexus_port_t nx_port, struct proc *p,
    boolean_t ifattach, boolean_t host);
extern void fsw_port_free(struct nx_flowswitch *fsw,
    struct nexus_vp_adapter *vpna, nexus_port_t nx_port, boolean_t defunct);
extern int fsw_port_grow(struct nx_flowswitch *fsw, uint32_t num_ports);
extern int fsw_port_na_activate(struct nx_flowswitch *fsw,
    struct nexus_vp_adapter *vpna, na_activate_mode_t mode);
extern boolean_t fsw_detach_barrier_add(struct nx_flowswitch *fsw);
extern void fsw_detach_barrier_remove(struct nx_flowswitch *fsw);

// vp related
extern int fsw_vp_na_activate(struct nexus_adapter *na,
    na_activate_mode_t mode);
extern int fsw_vp_na_krings_create(struct nexus_adapter *na,
    struct kern_channel *ch);
extern void fsw_vp_na_krings_delete(struct nexus_adapter *na,
    struct kern_channel *ch, boolean_t defunct);
extern int fsw_vp_na_txsync(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags);
extern int fsw_vp_na_rxsync(struct __kern_channel_ring *kring,
    struct proc *p, uint32_t flags);
extern int fsw_vp_na_attach(struct kern_nexus *nx, const char *cr_name,
    struct nexus_adapter *na);
extern int fsw_vp_na_create(struct kern_nexus *nx, struct chreq *chr,
    struct nexus_vp_adapter **ret);
extern void fsw_vp_channel_error_stats_fold(struct fsw_stats *fs,
    struct __nx_stats_channel_errors *es);

// classq related
extern void fsw_classq_setup(struct nx_flowswitch *fsw,
    struct nexus_adapter *hostna);
extern void fsw_classq_teardown(struct nx_flowswitch *fsw,
    struct nexus_adapter *hostna);
extern struct mbuf * fsw_classq_kpkt_to_mbuf(struct nx_flowswitch *fsw,
    struct __kern_packet *pkt);

// routing related
extern int fsw_generic_resolve(struct nx_flowswitch *fsw, struct flow_route *fr,
    struct __kern_packet *pkt);

// data plane related
extern int fsw_dp_init(void);
extern void fsw_dp_uninit(void);
extern int fsw_dp_ctor(struct nx_flowswitch *fsw);
extern void fsw_dp_dtor(struct nx_flowswitch *fsw);
extern void fsw_ring_flush(struct nx_flowswitch *fsw,
    struct __kern_channel_ring *skring, struct proc *p);
extern void fsw_ring_enqueue_tail_drop(struct nx_flowswitch *fsw,
    struct __kern_channel_ring *ring, struct pktq *pktq);
extern boolean_t fsw_detach_barrier_add(struct nx_flowswitch *fsw);
extern void fsw_detach_barrier_remove(struct nx_flowswitch *fsw);
extern void fsw_linger_insert(struct flow_entry *fsw);
extern void fsw_linger_purge(struct nx_flowswitch *fsw);
extern void fsw_reap_sched(struct nx_flowswitch *fsw);

extern int fsw_dev_input_netem_dequeue(void *handle, pktsched_pkt_t *pkts,
    uint32_t n_pkts);
extern void fsw_snoop(struct nx_flowswitch *fsw, struct flow_entry *fe,
    bool input);

extern void dp_flow_tx_process(struct nx_flowswitch *fsw,
    struct flow_entry *fe);
extern void dp_flow_rx_process(struct nx_flowswitch *fsw,
    struct flow_entry *fe);

extern uint32_t fsw_tx_batch;
extern uint32_t fsw_rx_batch;
extern uint32_t fsw_chain_enqueue;

// flow related
extern struct flow_owner * fsw_flow_add(struct nx_flowswitch *fsw,
    struct nx_flow_req *req0, int *error);
extern int fsw_flow_del(struct nx_flowswitch *fsw, struct nx_flow_req *req,
    bool nolinger, void *params);
extern void fsw_flow_abort_tcp(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct __kern_packet *pkt);
extern void fsw_flow_abort_quic(struct flow_entry *fe, uint8_t *token);
extern struct __kern_channel_ring * fsw_flow_get_rx_ring(struct nx_flowswitch *fsw,
    struct flow_entry *fe);
extern bool dp_flow_rx_route_process(struct nx_flowswitch *fsw,
    struct flow_entry *fe);
// stats related
extern void fsw_fold_stats(struct nx_flowswitch *fsw, void *data,
    nexus_stats_type_t type);

// netagent related
extern int fsw_netagent_add_remove(struct kern_nexus *nx, boolean_t add);
extern void fsw_netagent_update(struct kern_nexus *nx);
extern int fsw_netagent_register(struct nx_flowswitch *fsw, struct ifnet *ifp);
extern void fsw_netagent_unregister(struct nx_flowswitch *fsw,
    struct ifnet *ifp);

// interface related
extern int fsw_ip_setup(struct nx_flowswitch *fsw, struct ifnet *ifp);
extern int fsw_cellular_setup(struct nx_flowswitch *fsw, struct ifnet *ifp);
extern int fsw_ethernet_setup(struct nx_flowswitch *fsw, struct ifnet *ifp);
extern void fsw_classq_setup(struct nx_flowswitch *fsw,
    struct nexus_adapter *hostna);
extern void fsw_classq_teardown(struct nx_flowswitch *fsw,
    struct nexus_adapter *hostna);
extern void fsw_qos_mark(struct nx_flowswitch *fsw, struct flow_entry *fe,
    struct __kern_packet *pkt);
extern boolean_t fsw_qos_default_restricted(void);
extern struct mbuf * fsw_classq_kpkt_to_mbuf(struct nx_flowswitch *fsw,
    struct __kern_packet *pkt);
extern sa_family_t fsw_ip_demux(struct nx_flowswitch *, struct __kern_packet *);

// fragment reassembly related
extern struct fsw_ip_frag_mgr * fsw_ip_frag_mgr_create(
	struct nx_flowswitch *fsw, struct ifnet *ifp, size_t f_limit);
extern void fsw_ip_frag_mgr_destroy(struct fsw_ip_frag_mgr *mgr);
extern int fsw_ip_frag_reass_v4(struct fsw_ip_frag_mgr *mgr,
    struct __kern_packet **pkt, struct ip *ip4, uint16_t *nfrags,
    uint16_t *tlen);
extern int fsw_ip_frag_reass_v6(struct fsw_ip_frag_mgr *mgr,
    struct __kern_packet **pkt, struct ip6_hdr *ip6, struct ip6_frag *ip6f,
    uint16_t *nfrags, uint16_t *tlen);

__END_DECLS

__attribute__((always_inline))
static inline void
fsw_snoop_and_dequeue(struct flow_entry *fe, struct pktq *target, bool input)
{
	if (pktap_total_tap_count != 0) {
		fsw_snoop(fe->fe_fsw, fe, input);
	}
	KPKTQ_CONCAT(target, input ? &fe->fe_rx_pktq : &fe->fe_tx_pktq);
}

#endif /* _SKYWALK_NEXUS_FLOWSWITCH_FSWVAR_H_ */
