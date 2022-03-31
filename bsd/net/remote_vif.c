/*
 * Copyright (c) 2010-2021 Apple Inc. All rights reserved.
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

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <mach/mach_types.h>

#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/debug.h>

#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/cdefs.h>
#include <sys/kern_control.h>
#include <sys/mbuf.h>
#include <sys/sysctl.h>

#include <net/if_types.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <net/bpf.h>
#include <net/remote_vif.h>

#include <libkern/libkern.h>
#include <libkern/OSAtomic.h>

#include <os/log.h>

#define RVI_IF_NAME            "rvi"

#define RVI_DIR_IN              IFF_LINK0
#define RVI_DIR_OUT             IFF_LINK1
#define RVI_DIR_INOUT           (RVI_DIR_IN | RVI_DIR_OUT)

#define RVI_IF_FAMILY           IFNET_FAMILY_LOOPBACK
#define RVI_IF_TYPE             IFT_OTHER
#define RVI_IF_FLAGS            (IFF_UP | IFF_DEBUG | RVI_DIR_INOUT)

struct rvi_client_t {
	LIST_ENTRY(rvi_client_t)        _cle;
	ifnet_t                         _ifp;
	uint32_t                        _unit;
	uint32_t                        _vif;
	uint32_t                        _raw_count;
	uint32_t                        _pktap_count;
};

static LIST_HEAD(, rvi_client_t)        _s_rvi_clients;

static LCK_GRP_DECLARE(rvi_grp, "remote virtual interface lock");
static LCK_RW_DECLARE(rvi_mtx, &rvi_grp);

static kern_ctl_ref     rvi_kernctl = NULL;

kern_return_t           rvi_start(kmod_info_t *, void *);
kern_return_t           rvi_stop(kmod_info_t *, void *);

static void             rvi_insert_client(struct rvi_client_t *);
static errno_t          rvi_create_if(struct rvi_client_t *);
static errno_t          rvi_destroy_if(struct rvi_client_t *);

static inline void      rvi_lock_shared(lck_rw_t *);
static inline void      rvi_lock_exclusive(lck_rw_t *);
static inline void      rvi_lock_done_shared(lck_rw_t *);
static inline void      rvi_lock_done_exclusive(lck_rw_t *);

static errno_t          rvi_output(ifnet_t, mbuf_t);
static errno_t          rvi_demux(ifnet_t, mbuf_t, char *, protocol_family_t *);
static errno_t          rvi_ioctl(ifnet_t, unsigned long, void *);
static errno_t          rvi_add_proto(ifnet_t, protocol_family_t, const struct ifnet_demux_desc *, uint32_t);
static errno_t          rvi_del_proto(ifnet_t, protocol_family_t);
static errno_t          rvi_set_bpf_tap(ifnet_t, uint32_t, bpf_tap_mode);
static void             rvi_detach(ifnet_t);

static errno_t          rvi_bpf_tap(ifnet_t, mbuf_t, int, struct rvi_client_t *, struct pktap_header *);

static errno_t          rvi_register_control(void);
static errno_t          rvi_ctl_connect(kern_ctl_ref, struct sockaddr_ctl *, void **);
static errno_t          rvi_ctl_send(kern_ctl_ref, uint32_t, void *, mbuf_t, int);
static errno_t          rvi_ctl_disconnect(kern_ctl_ref, uint32_t, void *);
static errno_t          rvi_ctl_getopt(kern_ctl_ref, uint32_t, void *, int, void *, size_t *);

int
rvi_init()
{
	int error = 0;

	if ((error = rvi_register_control()) != 0) {
		os_log(OS_LOG_DEFAULT, "rvi_start failed: rvi_register_control failure");
		return error;
	}

	return 0;
}

static inline void
rvi_lock_shared(lck_rw_t *mtx)
{
	lck_rw_lock_shared(mtx);
}

static inline void
rvi_lock_exclusive(lck_rw_t *mtx)
{
	lck_rw_lock_exclusive(mtx);
}

static inline void
rvi_lock_done_shared(lck_rw_t *mtx)
{
	lck_rw_unlock_shared(mtx);
}

static inline void
rvi_lock_done_exclusive(lck_rw_t *mtx)
{
	lck_rw_unlock_exclusive(mtx);
}

static errno_t
rvi_create_if(struct rvi_client_t *client)
{
	errno_t err = 0;
	struct ifnet_init_params rvi_ifinit;

	memset(&rvi_ifinit, 0x0, sizeof(rvi_ifinit));
	rvi_ifinit.name = RVI_IF_NAME;
	rvi_ifinit.unit = client->_vif;
	rvi_ifinit.type = RVI_IF_TYPE;
	rvi_ifinit.family = RVI_IF_FAMILY;
	rvi_ifinit.output = rvi_output;
	rvi_ifinit.demux = rvi_demux;
	rvi_ifinit.add_proto = rvi_add_proto;
	rvi_ifinit.del_proto = rvi_del_proto;
	rvi_ifinit.ioctl = rvi_ioctl;
	rvi_ifinit.detach = rvi_detach;
	rvi_ifinit.softc = client;

	err = ifnet_allocate(&rvi_ifinit, &client->_ifp);
	if (err != 0) {
		os_log(OS_LOG_DEFAULT, "%s: ifnet_allocate for %s%d failed - %d",
		    __func__, RVI_IF_NAME, client->_vif, err);
		goto done;
	}

	ifnet_set_flags(client->_ifp, RVI_IF_FLAGS, RVI_IF_FLAGS);

	err = ifnet_attach(client->_ifp, NULL);
	if (err != 0) {
		os_log(OS_LOG_DEFAULT, "%s: ifnet_attach for %s%d failed - %d",
		    __func__, RVI_IF_NAME, client->_vif, err);
		ifnet_release(client->_ifp);
		goto done;
	}

	bpf_attach(client->_ifp, DLT_PKTAP, sizeof(struct pktap_header), NULL,
	    rvi_set_bpf_tap);
	bpf_attach(client->_ifp, DLT_RAW, 0, NULL, rvi_set_bpf_tap);
done:
	return err;
}

static errno_t
rvi_destroy_if(struct rvi_client_t *client)
{
	errno_t err = 0;

	if (client == NULL) {
		goto done;
	}

	err = ifnet_detach(client->_ifp);
	if (err != 0) {
		os_log(OS_LOG_DEFAULT, "%s: ifnet_detach for %s%d failed - %d",
		    __func__, RVI_IF_NAME, client->_vif, err);
	}
done:
	return err;
}

static void
rvi_detach(ifnet_t ifp)
{
	struct rvi_client_t *client;

	rvi_lock_exclusive(&rvi_mtx);

	client = ifnet_softc(ifp);
	LIST_REMOVE(client, _cle);

	ifnet_release(ifp);

	rvi_lock_done_exclusive(&rvi_mtx);

	kfree_type(struct rvi_client_t, client);
}

static void
rvi_insert_client(struct rvi_client_t *client)
{
	struct rvi_client_t *itr = NULL;
	uint32_t ph = 0;

	rvi_lock_exclusive(&rvi_mtx);

	if (LIST_EMPTY(&_s_rvi_clients)) {
		LIST_INSERT_HEAD(&_s_rvi_clients, client, _cle);
	} else {
		LIST_FOREACH(itr, &_s_rvi_clients, _cle) {
			if (ph != itr->_vif) {
				LIST_INSERT_BEFORE(itr, client, _cle);
				break;
			}

			ph++;

			if (LIST_NEXT(itr, _cle) == NULL) {
				LIST_INSERT_AFTER(itr, client, _cle);
				break;
			}
		}
	}

	rvi_lock_done_exclusive(&rvi_mtx);

	client->_vif = ph;
}

static void
rvi_remove_client(uint32_t unit)
{
	struct rvi_client_t *client = NULL;

	rvi_lock_shared(&rvi_mtx);

	LIST_FOREACH(client, &_s_rvi_clients, _cle) {
		if (client->_unit == unit) {
			break;
		}
	}

	rvi_lock_done_shared(&rvi_mtx);

	if (client == NULL) {
		panic("rvi_ctl_disconnect: received a disconnect notification without a cache entry");
	}

	(void)rvi_destroy_if(client);
}


static errno_t
rvi_register_control(void)
{
	errno_t err = 0;
	struct kern_ctl_reg kern_ctl;

	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, RVI_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED;
	kern_ctl.ctl_sendsize = RVI_BUFFERSZ;
	kern_ctl.ctl_recvsize = RVI_BUFFERSZ;
	kern_ctl.ctl_connect = rvi_ctl_connect;
	kern_ctl.ctl_disconnect = rvi_ctl_disconnect;
	kern_ctl.ctl_send = rvi_ctl_send;
	kern_ctl.ctl_setopt = NULL;
	kern_ctl.ctl_getopt = rvi_ctl_getopt;

	err = ctl_register(&kern_ctl, &rvi_kernctl);

	return err;
}

static errno_t
rvi_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
#pragma unused(kctlref)
	errno_t err = 0;
	struct rvi_client_t *client = NULL;

	client = kalloc_type(struct rvi_client_t, Z_WAITOK | Z_ZERO | Z_NOFAIL);

	client->_unit = sac->sc_unit;
	rvi_insert_client(client);

	err = rvi_create_if(client);
	if (err != 0) {
		os_log(OS_LOG_DEFAULT, "%s: failure to create virtual interface %d",
		    __func__, err);
	}
	*unitinfo = client;

	return err;
}

static errno_t
rvi_ctl_disconnect(kern_ctl_ref kctlref, uint32_t unit, void *unitinfo)
{
#pragma unused(kctlref)
#pragma unused(unitinfo)
	errno_t err = 0;

	rvi_remove_client(unit);

	return err;
}

static errno_t
rvi_ctl_getopt(kern_ctl_ref kctlref, uint32_t unit, void *unitinfo,
    int opt, void *data, size_t *len)
{
#pragma unused(kctlref)
#pragma unused(unit)
	errno_t err = 0;
	int n;
	struct rvi_client_t *client = (struct rvi_client_t *)unitinfo;

	rvi_lock_shared(&rvi_mtx);

	switch (opt) {
	case RVI_COMMAND_GET_INTERFACE:
		if (data == NULL || len == NULL) {
			err = EINVAL;
			break;
		}
		n = snprintf(data, sizeof(*len), "%s%u", ifnet_name(client->_ifp),
		    ifnet_unit(client->_ifp));
		*len = n + 1;
		break;

	case RVI_COMMAND_VERSION:
		if (data == NULL || len == NULL || *len < sizeof(int)) {
			err = EINVAL;
			break;
		}
		*(int *)data = RVI_VERSION_CURRENT;
		*len = sizeof(int);
		break;

	default:
		err = ENOPROTOOPT;
		break;
	}

	rvi_lock_done_shared(&rvi_mtx);

	return err;
}

static errno_t
rvi_ctl_send(kern_ctl_ref kctlref, uint32_t unit, void *unitinfo, mbuf_t m, int flags)
{
#pragma unused(kctlref)
#pragma unused(unit)
#pragma unused(flags)
	errno_t err = 0;
	struct rvi_client_t *client = (struct rvi_client_t *)unitinfo;
	struct pktap_header pktap_hdr;
	uint32_t hdr_length;

	err = mbuf_copydata(m, 0, sizeof(struct pktap_header), (void *)&pktap_hdr);
	if (err != 0) {
		os_log(OS_LOG_DEFAULT, "%s: mbuf_copydata failed %d", __func__, err);
		goto done;
	}
	hdr_length = pktap_hdr.pth_length;

	mbuf_adj(m, hdr_length);

	rvi_lock_shared(&rvi_mtx);

	err = rvi_bpf_tap(client->_ifp, m,
	    pktap_hdr.pth_flags & PTH_FLAG_DIR_OUT ? 1 : 0,
	    client, &pktap_hdr);

	rvi_lock_done_shared(&rvi_mtx);
done:
	mbuf_freem(m);
	return err;
}

static errno_t
rvi_output(ifnet_t ifp, mbuf_t m)
{
#pragma unused(ifp)

	mbuf_freem(m);
	return 0;
}

static errno_t
rvi_demux(ifnet_t ifp, mbuf_t m, char *header, protocol_family_t *ppf)
{
#pragma unused(ifp)
#pragma unused(m)
#pragma unused(header)
#pragma unused(ppf)

	return ENOTSUP;
}

static errno_t
rvi_add_proto( ifnet_t ifp, protocol_family_t pf,
    const struct ifnet_demux_desc *dmx, uint32_t cnt)
{
#pragma unused(ifp)
#pragma unused(pf)
#pragma unused(dmx)
#pragma unused(cnt)

	return EINVAL;
}

static errno_t
rvi_del_proto(ifnet_t ifp, protocol_family_t pf)
{
#pragma unused(ifp)
#pragma unused(pf)

	return EINVAL;
}

static errno_t
rvi_ioctl(ifnet_t ifp, unsigned long cmd, void *data)
{
#pragma unused(ifp)
#pragma unused(cmd)
#pragma unused(data)

	return ENOTSUP;
}

static errno_t
rvi_set_bpf_tap(ifnet_t ifp, uint32_t dlt, bpf_tap_mode mode)
{
	struct rvi_client_t *client;

	rvi_lock_shared(&rvi_mtx);

	client = ifnet_softc(ifp);
	if (client == NULL) {
		os_log(OS_LOG_DEFAULT, "%s: ifnet_softc is NULL for ifp %p", __func__, ifp);
		goto done;
	}
	switch (dlt) {
	case DLT_RAW:
		if (mode == 0) {
			if (client->_raw_count > 0) {
				client->_raw_count--;
			}
		} else {
			client->_raw_count++;
		}
		break;
	case DLT_PKTAP:
		if (mode == 0) {
			if (client->_pktap_count > 0) {
				client->_pktap_count--;
			}
		} else {
			client->_pktap_count++;
		}
		break;
	}
done:
	rvi_lock_done_shared(&rvi_mtx);

	return 0;
}

/*
 * Note: called with the rvi lock taken as shared
 */
static errno_t
rvi_bpf_tap(ifnet_t ifp, mbuf_t m, int outgoing, struct rvi_client_t *client,
    struct pktap_header *pktap_hdr)
{
#pragma unused(ifp)
	errno_t err = 0;
	void (*bpf_tap_fn)(ifnet_t, uint32_t, mbuf_t, void *, size_t ) =
	    outgoing ? bpf_tap_out : bpf_tap_in;

	if (client->_pktap_count > 0) {
		bpf_tap_fn(client->_ifp, DLT_PKTAP, m, pktap_hdr,
		    sizeof(struct pktap_header));
	}

	if (client->_raw_count > 0 &&
	    (pktap_hdr->pth_protocol_family == AF_INET ||
	    pktap_hdr->pth_protocol_family == AF_INET6)) {
		/*
		 * We can play just with the length of the first mbuf in the
		 * chain because bpf_tap_imp() disregard the packet length
		 * of the mbuf packet header.
		 */
		if (pktap_hdr->pth_frame_pre_length > mbuf_len(m)) {
			err = mbuf_pullup(&m, pktap_hdr->pth_frame_pre_length);
			if (err != 0) {
				os_log(OS_LOG_DEFAULT, "%s mbuf_pullup failed", __func__);
				return 0;
			}
		}

		if (mbuf_setdata(m, m->m_data + pktap_hdr->pth_frame_pre_length,
		    m->m_len - pktap_hdr->pth_frame_pre_length) == 0) {
			bpf_tap_fn(client->_ifp, DLT_RAW, m, NULL, 0);
			mbuf_setdata(m, m->m_data  - pktap_hdr->pth_frame_pre_length,
			    m->m_len  + pktap_hdr->pth_frame_pre_length);
		}
	}

	return err;
}
