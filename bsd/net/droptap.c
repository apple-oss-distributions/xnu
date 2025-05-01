/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#include <sys/queue.h>
#include <sys/socketvar.h>
#include <net/bpf.h>
#include <net/droptap.h>
#include <net/if_var_private.h>
#include <net/kpi_interface.h>
#include <net/pktap.h>


struct droptap_softc {
	LIST_ENTRY(droptap_softc)         dtap_link;
	uint32_t                          dtap_unit;
	uint32_t                          dtap_dlt_pktap_count;
	struct ifnet                      *dtap_ifp;
};

static int droptap_inited = 0;

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, OID_AUTO, droptap,
    CTLFLAG_RW  | CTLFLAG_LOCKED, 0, "droptap virtual interface");

uint32_t droptap_total_tap_count = 0;
SYSCTL_UINT(_net_link_droptap, OID_AUTO, total_tap_count,
    CTLFLAG_RD | CTLFLAG_LOCKED, &droptap_total_tap_count, 0, "");

uint32_t droptap_verbose = 0;
SYSCTL_UINT(_net_link_droptap, OID_AUTO, verbose,
    CTLFLAG_RW | CTLFLAG_LOCKED, &droptap_verbose, 0, "");

static LCK_GRP_DECLARE(droptap_lck_grp, "droptap");
static LCK_ATTR_DECLARE(droptap_lck_attr, 0, 0);
static LCK_RW_DECLARE_ATTR(droptap_lck_rw, &droptap_lck_grp, &droptap_lck_attr);


static LIST_HEAD(droptap_list, droptap_softc) droptap_list =
    LIST_HEAD_INITIALIZER(droptap_list);

int droptap_clone_create(struct if_clone *, u_int32_t, void *);
int droptap_clone_destroy(struct ifnet *);

#define DROPTAP_MAXUNIT IF_MAXUNIT

static struct if_clone droptap_cloner =
    IF_CLONE_INITIALIZER(DROPTAP_IFNAME,
    droptap_clone_create,
    droptap_clone_destroy,
    0,
    DROPTAP_MAXUNIT);

errno_t droptap_if_output(ifnet_t, mbuf_t);
errno_t droptap_add_proto(ifnet_t, protocol_family_t,
    const struct ifnet_demux_desc *, u_int32_t);
errno_t droptap_del_proto(ifnet_t, protocol_family_t);
errno_t droptap_tap_callback(ifnet_t, u_int32_t, bpf_tap_mode);
void droptap_detach(ifnet_t);
static void droptap_bpf_tap_packet(kern_packet_t, uint32_t,
    struct droptap_header *, uint32_t, struct ifnet *, pid_t,
    const char *, pid_t, const char *, uint8_t, uint32_t);
static void droptap_bpf_tap_mbuf(struct mbuf *, uint16_t,
    struct droptap_header *, struct ifnet *);


void
droptap_init(void)
{
	int error = 0;

	VERIFY(droptap_inited == 0);
	droptap_inited = 1;

	LIST_INIT(&droptap_list);

	error = if_clone_attach(&droptap_cloner);
	if (error != 0) {
		panic("%s: if_clone_attach() failed, error %d",
		    __func__, error);
	}
}

int
droptap_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int error = 0;
	struct droptap_softc *droptap = NULL;
	struct ifnet_init_eparams if_init;

	droptap = kalloc_type(struct droptap_softc, Z_WAITOK_ZERO_NOFAIL);
	droptap->dtap_unit = unit;

	bzero(&if_init, sizeof(if_init));
	if_init.ver = IFNET_INIT_CURRENT_VERSION;
	if_init.len = sizeof(if_init);
	if_init.flags = IFNET_INIT_LEGACY;
	if_init.name = __unsafe_null_terminated_from_indexable(ifc->ifc_name);
	if_init.unit = unit;
	if_init.type = IFT_OTHER;
	if_init.family = IFNET_FAMILY_LOOPBACK;
	if_init.output = droptap_if_output;
	if_init.add_proto = droptap_add_proto;
	if_init.del_proto = droptap_del_proto;
	if_init.softc = droptap;
	if_init.detach = droptap_detach;

	error = ifnet_allocate_extended(&if_init, &droptap->dtap_ifp);
	if (error != 0) {
		printf("%s: ifnet_allocate_extended failed, error: %d\n",
		    __func__, error);
		goto done;
	}

	ifnet_set_flags(droptap->dtap_ifp, IFF_UP, IFF_UP);

	error = ifnet_attach(droptap->dtap_ifp, NULL);
	if (error != 0) {
		printf("%s: ifnet_attach failed, error: %d\n", __func__, error);
		ifnet_release(droptap->dtap_ifp);
		goto done;
	}

	/* We use DLT_PKTAP for droptap as well. */
	bpf_attach(droptap->dtap_ifp, DLT_PKTAP, sizeof(struct droptap_header),
	    NULL, droptap_tap_callback);

	ifnet_reference(droptap->dtap_ifp);
	lck_rw_lock_exclusive(&droptap_lck_rw);
	LIST_INSERT_HEAD(&droptap_list, droptap, dtap_link);
	lck_rw_done(&droptap_lck_rw);
done:
	if (error != 0 && droptap != NULL) {
		kfree_type(struct droptap_softc, droptap);
	}
	return error;
}

int
droptap_clone_destroy(struct ifnet *ifp)
{
	int error = 0;

	(void) ifnet_detach(ifp);
	return error;
}

errno_t
droptap_tap_callback(ifnet_t ifp, u_int32_t dlt, bpf_tap_mode direction)
{
	struct droptap_softc *__single droptap;

	droptap = ifp->if_softc;
	switch (dlt) {
	case DLT_PKTAP:
		if (direction == BPF_MODE_DISABLED) {
			if (droptap->dtap_dlt_pktap_count > 0) {
				droptap->dtap_dlt_pktap_count--;
				OSAddAtomic(-1, &droptap_total_tap_count);
			}
		} else {
			droptap->dtap_dlt_pktap_count++;
			OSAddAtomic(1, &droptap_total_tap_count);
		}
		break;
	}
	return 0;
}

errno_t
droptap_if_output(ifnet_t __unused ifp, mbuf_t __unused m)
{
	return ENOTSUP;
}

errno_t
droptap_add_proto(__unused ifnet_t ifp, __unused protocol_family_t pf,
    __unused const struct ifnet_demux_desc *dmx, __unused u_int32_t cnt)
{
	return 0;
}

errno_t
droptap_del_proto(__unused ifnet_t ifp, __unused protocol_family_t pf)
{
	return 0;
}

void
droptap_detach(ifnet_t ifp)
{
	struct droptap_softc *__single droptap;

	lck_rw_lock_exclusive(&droptap_lck_rw);

	droptap = ifp->if_softc;
	ifp->if_softc = NULL;
	LIST_REMOVE(droptap, dtap_link);

	lck_rw_done(&droptap_lck_rw);

	/* Drop reference as it's no more on the global list */
	ifnet_release(ifp);

	kfree_type(struct droptap_softc, droptap);
	/* This is for the reference taken by ifnet_attach() */
	(void) ifnet_release(ifp);
}

void
droptap_input_packet(kern_packet_t pkt, drop_reason_t reason,
    const char *funcname, uint16_t linenum, uint16_t flags, struct ifnet *ifp,
    pid_t pid, const char *pname, pid_t epid, const char *epname,
    uint8_t ipproto, uint32_t flowid)
{
	struct droptap_header     dtaphdr;
	uint32_t                  dlt;

	if (flags & DROPTAP_FLAG_L2_MISSING) {
		dlt = DLT_RAW;
	} else {
		dlt = DLT_EN10MB;
	}
	bzero(&dtaphdr, sizeof(struct droptap_header));
	dtaphdr.dth_dropreason = reason;
	if (funcname != NULL) {
		dtaphdr.dth_dropline = linenum;
		snprintf(dtaphdr.dth_dropfunc, sizeof(dtaphdr.dth_dropfunc), "%s", funcname);
		dtaphdr.dth_dropfunc_size = (uint8_t)strbuflen(dtaphdr.dth_dropfunc);
	}

	droptap_bpf_tap_packet(pkt, DROPTAP_FLAG_DIR_IN | PTH_FLAG_NEXUS_CHAN,
	    &dtaphdr, dlt, ifp, pid, pname, epid, epname, ipproto, flowid);
}

void
droptap_output_packet(kern_packet_t pkt, drop_reason_t reason,
    const char *funcname, uint16_t linenum, uint16_t flags, struct ifnet *ifp,
    pid_t pid, const char *pname, pid_t epid, const char *epname,
    uint8_t ipproto, uint32_t flowid)
{
	struct droptap_header     dtaphdr;
	uint32_t                  dlt;

	if (flags & DROPTAP_FLAG_L2_MISSING) {
		dlt = DLT_RAW;
	} else {
		dlt = DLT_EN10MB;
	}
	bzero(&dtaphdr, sizeof(struct droptap_header));
	dtaphdr.dth_dropreason = reason;
	if (funcname != NULL) {
		dtaphdr.dth_dropline = linenum;
		snprintf(dtaphdr.dth_dropfunc, sizeof(dtaphdr.dth_dropfunc), "%s", funcname);
		dtaphdr.dth_dropfunc_size = (uint8_t)strbuflen(dtaphdr.dth_dropfunc);
	}

	droptap_bpf_tap_packet(pkt, DROPTAP_FLAG_DIR_OUT | PTH_FLAG_NEXUS_CHAN,
	    &dtaphdr, dlt, ifp, pid, pname, epid, epname, ipproto, flowid);
}

static void
droptap_bpf_tap_packet(kern_packet_t pkt, uint32_t flags,
    struct droptap_header *dtaphdr, uint32_t dlt, struct ifnet *ifp, pid_t pid,
    const char *pname, pid_t epid, const char *epname, uint8_t ipproto,
    uint32_t flowid)
{
	struct droptap_softc *droptap;
	struct pktap_header *hdr;
	size_t hdr_size;
	void (*tap_packet_func)(ifnet_t, u_int32_t, kern_packet_t, void *, size_t) =
	    flags & DROPTAP_FLAG_DIR_OUT ? bpf_tap_packet_out : bpf_tap_packet_in;

	hdr_size = DROPTAP_HDR_SIZE(dtaphdr);

	hdr = (struct pktap_header *)dtaphdr;
	hdr->pth_length = sizeof(struct pktap_header);
	hdr->pth_type_next = PTH_TYPE_DROP;
	hdr->pth_dlt = dlt;
	hdr->pth_pid = pid;
	if (pid != epid) {
		hdr->pth_epid = epid;
	} else {
		hdr->pth_epid = -1;
	}
	if (pname != NULL) {
		strlcpy(hdr->pth_comm, pname, sizeof(hdr->pth_comm));
	}
	if (epname != NULL) {
		strlcpy(hdr->pth_ecomm, epname, sizeof(hdr->pth_ecomm));
	}
	if (ifp) {
		strlcpy(hdr->pth_ifname, ifp->if_xname, sizeof(hdr->pth_ifname));
		hdr->pth_iftype = ifp->if_type;
		hdr->pth_ifunit = ifp->if_unit;
	}
	hdr->pth_flags |= flags;
	hdr->pth_ipproto = ipproto;
	hdr->pth_flowid = flowid;

	hdr->pth_flags |= flags & DROPTAP_FLAG_DIR_OUT ? PTH_FLAG_DIR_OUT : PTH_FLAG_DIR_IN;
	if ((flags & PTH_FLAG_SOCKET) != 0 && ipproto != 0 && flowid != 0) {
		hdr->pth_flags |= PTH_FLAG_DELAY_PKTAP;
	}
	if (kern_packet_get_wake_flag(pkt)) {
		hdr->pth_flags |= PTH_FLAG_WAKE_PKT;
	}
	hdr->pth_trace_tag = kern_packet_get_trace_tag(pkt);
	hdr->pth_svc = so_svc2tc((mbuf_svc_class_t)
	    kern_packet_get_service_class(pkt));

	lck_rw_lock_shared(&droptap_lck_rw);
	LIST_FOREACH(droptap, &droptap_list, dtap_link) {
		if (droptap->dtap_dlt_pktap_count > 0) {
			tap_packet_func(droptap->dtap_ifp, DLT_PKTAP,
			    pkt, hdr, hdr_size);
		}
	}
	lck_rw_done(&droptap_lck_rw);
}

void
droptap_input_mbuf(struct mbuf *m, drop_reason_t reason, const char *funcname,
    uint16_t linenum, uint16_t flags, struct ifnet *ifp, char *frame_header)
{
	struct droptap_header    dtaphdr;
	char *hdr;
	char *start;

	bzero(&dtaphdr, sizeof(struct droptap_header));
	dtaphdr.dth_dropreason = reason;
	if (funcname != NULL) {
		dtaphdr.dth_dropline = linenum;
		snprintf(dtaphdr.dth_dropfunc, sizeof(dtaphdr.dth_dropfunc), "%s", funcname);
		dtaphdr.dth_dropfunc_size = (uint8_t)strbuflen(dtaphdr.dth_dropfunc);
	}

	hdr = mtod(m, char *);
	start = (char *)m_mtod_lower_bound(m);
	if (frame_header != NULL && frame_header >= start && frame_header <= hdr) {
		size_t o_len = m->m_len;
		u_int32_t pre = (u_int32_t)(hdr - frame_header);

		if (mbuf_setdata(m, frame_header, o_len + pre) == 0) {
			droptap_bpf_tap_mbuf(m, DROPTAP_FLAG_DIR_IN | flags, &dtaphdr, ifp);
			mbuf_setdata(m, hdr, o_len);
		}
	} else {
		droptap_bpf_tap_mbuf(m, DROPTAP_FLAG_DIR_IN | flags, &dtaphdr, ifp);
	}
}

void
droptap_output_mbuf(struct mbuf *m, drop_reason_t reason, const char *funcname,
    uint16_t linenum, uint16_t flags, struct ifnet *ifp)
{
	struct droptap_header    dtaphdr;

	bzero(&dtaphdr, sizeof(struct droptap_header));
	dtaphdr.dth_dropreason = reason;
	if (funcname != NULL) {
		dtaphdr.dth_dropline = linenum;
		snprintf(dtaphdr.dth_dropfunc, sizeof(dtaphdr.dth_dropfunc), "%s", funcname);
		dtaphdr.dth_dropfunc_size = (uint8_t)strbuflen(dtaphdr.dth_dropfunc);
	}

	droptap_bpf_tap_mbuf(m, DROPTAP_FLAG_DIR_OUT | flags, &dtaphdr, ifp);
}

static void
droptap_bpf_tap_mbuf(struct mbuf *m, uint16_t flags,
    struct droptap_header *dtaphdr, struct ifnet *ifp)
{
	struct droptap_softc *droptap;
	struct pktap_header *hdr;
	size_t hdr_size;
	void (*bpf_tap_func)(ifnet_t, u_int32_t, mbuf_t, void *, size_t ) =
	    flags & DROPTAP_FLAG_DIR_OUT ? bpf_tap_out : bpf_tap_in;

	hdr_size = DROPTAP_HDR_SIZE(dtaphdr);

	hdr = (struct pktap_header *)dtaphdr;
	hdr->pth_length = sizeof(struct pktap_header);
	hdr->pth_type_next = PTH_TYPE_DROP;

	/* Use DLT_RAW if L2 frame header is NULL */
	if (flags & DROPTAP_FLAG_L2_MISSING) {
		hdr->pth_dlt = DLT_RAW;
	} else {
		hdr->pth_dlt = DLT_EN10MB;
	}

	hdr->pth_flags |= flags & DROPTAP_FLAG_DIR_OUT ? PTH_FLAG_DIR_OUT : PTH_FLAG_DIR_IN;
	if (ifp) {
		strlcpy(hdr->pth_ifname, ifp->if_xname, sizeof(hdr->pth_ifname));
		hdr->pth_iftype = ifp->if_type;
		hdr->pth_ifunit = ifp->if_unit;
	}

	if (m->m_pkthdr.pkt_flags & PKTF_KEEPALIVE) {
		hdr->pth_flags |= PTH_FLAG_KEEP_ALIVE;
	}
	if (m->m_pkthdr.pkt_flags & PKTF_TCP_REXMT) {
		hdr->pth_flags |= PTH_FLAG_REXMIT;
	}
	if (m->m_pkthdr.pkt_flags & PKTF_WAKE_PKT) {
		hdr->pth_flags |= PTH_FLAG_WAKE_PKT;
	}

	hdr->pth_svc = so_svc2tc(m->m_pkthdr.pkt_svc);

	lck_rw_lock_exclusive(&droptap_lck_rw);
	LIST_FOREACH(droptap, &droptap_list, dtap_link) {
		if (droptap->dtap_dlt_pktap_count > 0) {
			bpf_tap_func(droptap->dtap_ifp, DLT_PKTAP,
			    m, hdr, hdr_size);
		}
	}
	lck_rw_done(&droptap_lck_rw);
}
