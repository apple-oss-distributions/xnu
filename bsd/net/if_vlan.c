/*
 * Copyright (c) 2003-2024 Apple Inc. All rights reserved.
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
 * Copyright 1998 Massachusetts Institute of Technology
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby
 * granted, provided that both the above copyright notice and this
 * permission notice appear in all copies, that both the above
 * copyright notice and this permission notice appear in all
 * supporting documentation, and that the name of M.I.T. not be used
 * in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  M.I.T. makes
 * no representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied
 * warranty.
 *
 * THIS SOFTWARE IS PROVIDED BY M.I.T. ``AS IS''.  M.I.T. DISCLAIMS
 * ALL EXPRESS OR IMPLIED WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT
 * SHALL M.I.T. BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/net/if_vlan.c,v 1.54 2003/10/31 18:32:08 brooks Exp $
 */

/*
 * if_vlan.c - pseudo-device driver for IEEE 802.1Q virtual LANs.
 * Might be extended some day to also handle IEEE 802.1p priority
 * tagging.  This is sort of sneaky in the implementation, since
 * we need to pretend to be enough of an Ethernet implementation
 * to make arp work.  The way we do this is by telling everyone
 * that we are an Ethernet, and then catch the packets that
 * ether_output() left on our output queue when it calls
 * if_start(), rewrite them for use by the real outgoing interface,
 * and ask it to send them.
 */


#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/kern_event.h>
#include <sys/mcache.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_ether.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>
#include <libkern/OSAtomic.h>

#include <net/dlil.h>

#include <net/kpi_interface.h>
#include <net/kpi_protocol.h>

#include <kern/locks.h>
#include <kern/zalloc.h>

#ifdef INET
#include <netinet/in.h>
#include <netinet/if_ether.h>
#endif

#include <net/if_media.h>
#include <net/multicast_list.h>
#include <net/ether_if_module.h>

#include <os/log.h>

#if !XNU_TARGET_OS_OSX
#if (DEVELOPMENT || DEBUG)
#include <pexpert/pexpert.h>
#endif
#endif /* !XNU_TARGET_OS_OSX */

#include <net/mblist.h>

#define VLANNAME        "vlan"

/*
 * if_vlan_debug, VL_DBGF_*
 * - 'if_vlan_debug' is a bitmask of VL_DBGF_* flags that can be set
 *   to enable additional logs for the corresponding vlan function
 * - "sysctl net.link.vlan.debug" controls the value of
 *   'if_vlan_debug'
 */
static uint32_t if_vlan_debug = 0;

#define VL_DBGF_LIFECYCLE             0x0001
#define VL_DBGF_INPUT                 0x0002
#define VL_DBGF_OUTPUT                0x0004
#define VL_DBGF_CONTROL               0x0008
#define VL_DBGF_MISC                  0x0010

/*
 * if_vlan_log_level
 * - 'if_vlan_log_level' ensures that by default important logs are
 *   logged regardless of if_vlan_debug by comparing the log level
 *   in VLAN_LOG to if_vlan_log_level
 * - use "sysctl net.link.vlan.log_level" controls the value of
 *   'if_vlan_log_level'
 * - the default value of 'if_vlan_log_level' is LOG_NOTICE; important
 *   logs must use LOG_NOTICE to ensure they appear by default
 */
#define VL_DBGF_ENABLED(__flag)     ((if_vlan_debug & __flag) != 0)

/*
 * VLAN_LOG
 * - macro to generate the specified log conditionally based on
 *   the specified log level and debug flags
 */
#define VLAN_LOG(__level, __dbgf, __string, ...)              \
	do {                                                            \
	        if (__level <= if_vlan_log_level ||                   \
	            VL_DBGF_ENABLED(__dbgf)) {                      \
	                os_log(OS_LOG_DEFAULT, "%s: " __string, \
	                       __func__, ## __VA_ARGS__);       \
	        }                                                       \
	} while (0)


/**
** vlan locks
**/

static LCK_GRP_DECLARE(vlan_lck_grp, "if_vlan");
static LCK_MTX_DECLARE(vlan_lck_mtx, &vlan_lck_grp);

static inline void
vlan_assert_lock_held(void)
{
	LCK_MTX_ASSERT(&vlan_lck_mtx, LCK_MTX_ASSERT_OWNED);
}

static inline void
vlan_assert_lock_not_held(void)
{
	LCK_MTX_ASSERT(&vlan_lck_mtx, LCK_MTX_ASSERT_NOTOWNED);
}

static inline void
vlan_lock(void)
{
	lck_mtx_lock(&vlan_lck_mtx);
}

static inline void
vlan_unlock(void)
{
	lck_mtx_unlock(&vlan_lck_mtx);
}

/**
** vlan structures, types
**/
struct vlan_parent;
LIST_HEAD(vlan_parent_list, vlan_parent);
struct ifvlan;
LIST_HEAD(ifvlan_list, ifvlan);

typedef LIST_ENTRY(vlan_parent)
vlan_parent_entry;
typedef LIST_ENTRY(ifvlan)
ifvlan_entry;

#define VLP_SIGNATURE           0xfaceface
typedef struct vlan_parent {
	vlan_parent_entry           vlp_parent_list;/* list of parents */
	struct ifnet *              vlp_ifp;    /* interface */
	struct ifvlan_list          vlp_vlan_list;/* list of VLAN's */
#define VLPF_SUPPORTS_VLAN_MTU          0x00000001
#define VLPF_CHANGE_IN_PROGRESS         0x00000002
#define VLPF_DETACHING                  0x00000004
#define VLPF_INVALIDATED                0x00000008
#define VLPF_LINK_EVENT_REQUIRED        0x00000010
	u_int32_t                   vlp_flags;
	u_int32_t                   vlp_event_code;
	struct ifdevmtu             vlp_devmtu;
	int32_t                     vlp_retain_count;
	u_int32_t                   vlp_signature;/* VLP_SIGNATURE */
} vlan_parent, * __single vlan_parent_ref;

#define IFV_SIGNATURE           0xbeefbeef
struct ifvlan {
	ifvlan_entry                ifv_vlan_list;
	char                        ifv_name[IFNAMSIZ];/* our unique id */
	struct ifnet *              ifv_ifp;    /* our interface */
	vlan_parent_ref             ifv_vlp;    /* parent information */
	u_int16_t                   ifv_mtufudge;/* MTU fudged by this much */
	u_int16_t                   ifv_tag;     /* VLAN tag */
	struct multicast_list       ifv_multicast;
#define IFVF_PROMISC            0x1             /* promiscuous mode enabled */
#define IFVF_DETACHING          0x2             /* interface is detaching */
#define IFVF_READY              0x4             /* interface is ready */
	u_int32_t                   ifv_flags;
	int32_t                     ifv_retain_count;
	u_int32_t                   ifv_signature;/* IFV_SIGNATURE */
};

typedef struct ifvlan * ifvlan_ref;

typedef struct vlan_globals_s {
	struct vlan_parent_list     parent_list;
} * vlan_globals_ref;

static vlan_globals_ref g_vlan;

#define VLAN_PARENT_WAIT(vlp)   vlan_parent_wait(vlp, __func__)
#define VLAN_PARENT_SIGNAL(vlp) vlan_parent_signal(vlp, __func__)

static void
vlan_parent_retain(vlan_parent_ref vlp);

static void
vlan_parent_release(vlan_parent_ref vlp);

static inline bool
vlan_parent_flags_are_set(vlan_parent_ref vlp, u_int32_t flags)
{
	return (vlp->vlp_flags & flags) != 0;
}

static inline void
vlan_parent_flags_set(vlan_parent_ref vlp, u_int32_t flags)
{
	vlp->vlp_flags |= flags;
}

static inline void
vlan_parent_flags_clear(vlan_parent_ref vlp, u_int32_t flags)
{
	vlp->vlp_flags &= ~flags;
}

/**
** ifvlan_flags in-lines routines
**/
static inline bool
ifvlan_flags_are_set(ifvlan_ref ifv, u_int32_t flags)
{
	return (ifv->ifv_flags & flags) != 0;
}

static inline void
ifvlan_flags_set(ifvlan_ref ifv, u_int32_t flags)
{
	ifv->ifv_flags |= flags;
}

static inline void
ifvlan_flags_clear(ifvlan_ref ifv, u_int32_t flags)
{
	ifv->ifv_flags &= ~flags;
}

static inline bool
ifvlan_is_invalid(ifvlan_ref ifv)
{
	return ifv == NULL || ifvlan_flags_are_set(ifv, IFVF_DETACHING);
}

SYSCTL_DECL(_net_link);
SYSCTL_NODE(_net_link, IFT_L2VLAN, vlan, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
    "IEEE 802.1Q VLAN");

static int if_vlan_log_level = LOG_NOTICE;
SYSCTL_INT(_net_link_vlan, OID_AUTO, log_level, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_vlan_log_level, 0, "VLAN interface log level");

SYSCTL_UINT(_net_link_vlan, OID_AUTO, debug, CTLFLAG_RW | CTLFLAG_LOCKED,
    &if_vlan_debug, 0, "VLAN debug flags");

#if !XNU_TARGET_OS_OSX
static unsigned int vlan_enabled;

#if (DEVELOPMENT || DEBUG)

SYSCTL_UINT(_net_link_vlan, OID_AUTO, enabled,
    CTLFLAG_RD | CTLFLAG_LOCKED,
    &vlan_enabled, 0,
    "VLAN interface support enabled");

#endif /* DEVELOPMENT || DEBUG */
#endif /* !XNU_TARGET_OS_OSX */

#if 0
SYSCTL_NODE(_net_link_vlan, PF_LINK, link, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "for consistency");
#endif

#define VLAN_UNITMAX    IF_MAXUNIT
#define VLAN_ZONE_MAX_ELEM      MIN(IFNETS_MAX, VLAN_UNITMAX)

static  int vlan_clone_create(struct if_clone *, u_int32_t, void *);
static  int vlan_clone_destroy(struct ifnet *);
static  int vlan_input(ifnet_t ifp, protocol_family_t protocol, mbuf_t m);
static  int vlan_output(struct ifnet *ifp, struct mbuf *m);
static  int vlan_ioctl(ifnet_t ifp, u_long cmd, void * addr);
static  int vlan_attach_protocol(struct ifnet *ifp);
static  int vlan_detach_protocol(struct ifnet *ifp);
static  int vlan_setmulti(struct ifnet *ifp);
static  int vlan_unconfig(ifvlan_ref ifv, int need_to_wait);
static  int vlan_config(struct ifnet * ifp, struct ifnet * p, int tag);
static  void vlan_if_free(struct ifnet * ifp);
static  int vlan_remove(ifvlan_ref ifv, int need_to_wait);

static struct if_clone vlan_cloner = IF_CLONE_INITIALIZER(VLANNAME,
    vlan_clone_create,
    vlan_clone_destroy,
    0,
    VLAN_UNITMAX);
static  void interface_link_event(struct ifnet * ifp, u_int32_t event_code);
static  void vlan_parent_link_event(struct ifnet * p,
    u_int32_t event_code);

static  int ifvlan_new_mtu(ifvlan_ref ifv, int mtu);

/**
** ifvlan_ref routines
**/
static void
ifvlan_retain(ifvlan_ref ifv)
{
	if (ifv->ifv_signature != IFV_SIGNATURE) {
		panic("ifvlan_retain: bad signature");
	}
	if (ifv->ifv_retain_count == 0) {
		panic("ifvlan_retain: retain count is 0");
	}
	OSIncrementAtomic(&ifv->ifv_retain_count);
}

static void
ifvlan_release(ifvlan_ref ifv)
{
	u_int32_t           old_retain_count;

	if (ifv->ifv_signature != IFV_SIGNATURE) {
		panic("ifvlan_release: bad signature");
	}
	old_retain_count = OSDecrementAtomic(&ifv->ifv_retain_count);
	switch (old_retain_count) {
	case 0:
		panic("ifvlan_release: retain count is 0");
		break;
	case 1:
		VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE, "%s", ifv->ifv_name);
		ifv->ifv_signature = 0;
		kfree_type(struct ifvlan, ifv);
		break;
	default:
		break;
	}
	return;
}

static vlan_parent_ref
ifvlan_get_vlan_parent_retained(ifvlan_ref ifv)
{
	vlan_parent_ref     vlp = ifv->ifv_vlp;

	if (vlp == NULL || vlan_parent_flags_are_set(vlp, VLPF_DETACHING)) {
		return NULL;
	}
	vlan_parent_retain(vlp);
	return vlp;
}

/**
** ifnet_* routines
**/

static ifvlan_ref
ifnet_get_ifvlan(struct ifnet * ifp)
{
	ifvlan_ref          ifv;

	ifv = (ifvlan_ref)ifnet_softc(ifp);
	return ifv;
}

static ifvlan_ref
ifnet_get_ifvlan_retained(struct ifnet * ifp)
{
	ifvlan_ref          ifv;

	ifv = ifnet_get_ifvlan(ifp);
	if (ifvlan_is_invalid(ifv)) {
		return NULL;
	}
	ifvlan_retain(ifv);
	return ifv;
}

static int
ifnet_ifvlan_vlan_parent_ok(struct ifnet * ifp, ifvlan_ref ifv,
    vlan_parent_ref vlp)
{
	ifvlan_ref          check_ifv;

	check_ifv = ifnet_get_ifvlan(ifp);
	if (check_ifv != ifv || ifvlan_flags_are_set(ifv, IFVF_DETACHING)) {
		/* ifvlan_ref no longer valid */
		return FALSE;
	}
	if (ifv->ifv_vlp != vlp) {
		/* vlan_parent no longer valid */
		return FALSE;
	}
	if (vlan_parent_flags_are_set(vlp, VLPF_DETACHING)) {
		/* parent is detaching */
		return FALSE;
	}
	return TRUE;
}

/**
** vlan, etc. routines
**/

static int
vlan_globals_init(void)
{
	vlan_globals_ref    v;

	vlan_assert_lock_not_held();

	if (g_vlan != NULL) {
		return 0;
	}
	v = kalloc_type(struct vlan_globals_s, Z_WAITOK | Z_NOFAIL);
	LIST_INIT(&v->parent_list);
	vlan_lock();
	if (g_vlan != NULL) {
		vlan_unlock();
		if (v != NULL) {
			kfree_type(struct vlan_globals_s, v);
		}
		return 0;
	}
	g_vlan = v;
	vlan_unlock();
	if (v == NULL) {
		return ENOMEM;
	}
	return 0;
}

static int
siocgifdevmtu(struct ifnet * ifp, struct ifdevmtu * ifdm_p)
{
	struct ifreq        ifr;
	int                 error;

	bzero(&ifr, sizeof(ifr));
	error = ifnet_ioctl(ifp, 0, SIOCGIFDEVMTU, &ifr);
	if (error == 0) {
		*ifdm_p = ifr.ifr_devmtu;
	}
	return error;
}

static int
siocsifaltmtu(struct ifnet * ifp, int mtu)
{
	struct ifreq        ifr;

	bzero(&ifr, sizeof(ifr));
	ifr.ifr_mtu = mtu;
	return ifnet_ioctl(ifp, 0, SIOCSIFALTMTU, &ifr);
}

/**
** vlan_parent synchronization routines
**/
static void
vlan_parent_retain(vlan_parent_ref vlp)
{
	if (vlp->vlp_signature != VLP_SIGNATURE) {
		panic("vlan_parent_retain: signature is bad");
	}
	if (vlp->vlp_retain_count == 0) {
		panic("vlan_parent_retain: retain count is 0");
	}
	OSIncrementAtomic(&vlp->vlp_retain_count);
}

static void
vlan_parent_release(vlan_parent_ref vlp)
{
	struct ifnet *  ifp = vlp->vlp_ifp;
	u_int32_t       old_retain_count;

	if (vlp->vlp_signature != VLP_SIGNATURE) {
		panic("vlan_parent_release: signature is bad");
	}
	old_retain_count = OSDecrementAtomic(&vlp->vlp_retain_count);
	switch (old_retain_count) {
	case 0:
		panic("vlan_parent_release: retain count is 0");
		break;
	case 1:
		VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE,
		    "%s", ifp->if_xname);
		vlp->vlp_signature = 0;
		kfree_type(struct vlan_parent, vlp);
		break;
	default:
		break;
	}
	return;
}

/*
 * Function: vlan_parent_wait
 * Purpose:
 *   Allows a single thread to gain exclusive access to the vlan_parent
 *   data structure.  Some operations take a long time to complete,
 *   and some have side-effects that we can't predict.  Holding the
 *   vlan_lock() across such operations is not possible.
 *
 * Notes:
 *   Before calling, you must be holding the vlan_lock and have taken
 *   a reference on the vlan_parent_ref.
 */
static void
vlan_parent_wait(vlan_parent_ref vlp, const char * msg)
{
	struct ifnet *  ifp = vlp->vlp_ifp;
	int             waited = 0;

	/* other add/remove/multicast-change in progress */
	while (vlan_parent_flags_are_set(vlp, VLPF_CHANGE_IN_PROGRESS)) {
		VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE, "%s: %s msleep",
		    ifp->if_xname, msg);
		waited = 1;
		(void)msleep(vlp, &vlan_lck_mtx, PZERO, msg, 0);
	}
	/* prevent other vlan parent remove/add from taking place */
	vlan_parent_flags_set(vlp, VLPF_CHANGE_IN_PROGRESS);
	if (waited) {
		VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE, "%s: %s woke up",
		    ifp->if_xname, msg);
	}
	return;
}

/*
 * Function: vlan_parent_signal
 * Purpose:
 *   Allows the thread that previously invoked vlan_parent_wait() to
 *   give up exclusive access to the vlan_parent data structure, and wake up
 *   any other threads waiting to access
 * Notes:
 *   Before calling, you must be holding the vlan_lock and have taken
 *   a reference on the vlan_parent_ref.
 */
static void
vlan_parent_signal(vlan_parent_ref vlp, const char * msg)
{
	struct ifnet * vlp_ifp = vlp->vlp_ifp;

	if (vlan_parent_flags_are_set(vlp, VLPF_LINK_EVENT_REQUIRED)) {
		vlan_parent_flags_clear(vlp, VLPF_LINK_EVENT_REQUIRED);
		if (!vlan_parent_flags_are_set(vlp, VLPF_DETACHING)) {
			u_int32_t           event_code = vlp->vlp_event_code;
			ifvlan_ref          ifv;

			vlan_unlock();

			/* we can safely walk the list unlocked */
			LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
				struct ifnet *  ifp = ifv->ifv_ifp;

				interface_link_event(ifp, event_code);
			}
			VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE,
			    "%s: propagated link event to vlans",
			    vlp_ifp->if_xname);
			vlan_lock();
		}
	}
	vlan_parent_flags_clear(vlp, VLPF_CHANGE_IN_PROGRESS);
	wakeup((caddr_t)vlp);
	VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE,
	    "%s: %s wakeup", vlp_ifp->if_xname, msg);
	return;
}

/*
 * Program our multicast filter. What we're actually doing is
 * programming the multicast filter of the parent. This has the
 * side effect of causing the parent interface to receive multicast
 * traffic that it doesn't really want, which ends up being discarded
 * later by the upper protocol layers. Unfortunately, there's no way
 * to avoid this: there really is only one physical interface.
 */
static int
vlan_setmulti(struct ifnet * ifp)
{
	int                 error = 0;
	ifvlan_ref          ifv;
	struct ifnet *      p;
	vlan_parent_ref     vlp = NULL;

	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL) {
		goto unlock_done;
	}
	vlp = ifvlan_get_vlan_parent_retained(ifv);
	if (vlp == NULL) {
		/* no parent, no need to program the multicast filter */
		goto unlock_done;
	}
	VLAN_PARENT_WAIT(vlp);

	/* check again, things could have changed */
	if (ifnet_ifvlan_vlan_parent_ok(ifp, ifv, vlp) == FALSE) {
		goto signal_done;
	}
	p = vlp->vlp_ifp;
	vlan_unlock();

	/* update parent interface with our multicast addresses */
	error = multicast_list_program(&ifv->ifv_multicast, ifp, p);

	vlan_lock();

signal_done:
	VLAN_PARENT_SIGNAL(vlp);

unlock_done:
	vlan_unlock();
	if (ifv != NULL) {
		ifvlan_release(ifv);
	}
	if (vlp != NULL) {
		vlan_parent_release(vlp);
	}
	return error;
}

/**
** vlan_parent list manipulation/lookup routines
**/
static vlan_parent_ref
parent_list_lookup(struct ifnet * p)
{
	vlan_parent_ref     vlp;

	LIST_FOREACH(vlp, &g_vlan->parent_list, vlp_parent_list) {
		if (vlp->vlp_ifp == p) {
			return vlp;
		}
	}
	return NULL;
}

static ifvlan_ref
vlan_parent_lookup_tag(vlan_parent_ref vlp, int tag)
{
	ifvlan_ref          ifv;

	LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
		if (tag == ifv->ifv_tag) {
			return ifv;
		}
	}
	return NULL;
}

static ifvlan_ref
vlan_lookup_parent_and_tag(struct ifnet * p, int tag)
{
	vlan_parent_ref     vlp;

	vlp = parent_list_lookup(p);
	if (vlp != NULL) {
		return vlan_parent_lookup_tag(vlp, tag);
	}
	return NULL;
}

static int
vlan_parent_find_max_mtu(vlan_parent_ref vlp, ifvlan_ref exclude_ifv)
{
	int                 max_mtu = 0;
	ifvlan_ref          ifv;

	LIST_FOREACH(ifv, &vlp->vlp_vlan_list, ifv_vlan_list) {
		int     req_mtu;

		if (exclude_ifv == ifv) {
			continue;
		}
		req_mtu = ifnet_mtu(ifv->ifv_ifp) + ifv->ifv_mtufudge;
		if (req_mtu > max_mtu) {
			max_mtu = req_mtu;
		}
	}
	return max_mtu;
}

/*
 * Function: vlan_parent_create
 * Purpose:
 *   Create a vlan_parent structure to hold the VLAN's for the given
 *   interface.  Add it to the list of VLAN parents.
 */
static int
vlan_parent_create(struct ifnet * p, vlan_parent_ref * ret_vlp)
{
	int                 error;
	vlan_parent_ref     vlp;

	*ret_vlp = NULL;
	vlp = kalloc_type(struct vlan_parent, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	error = siocgifdevmtu(p, &vlp->vlp_devmtu);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, VL_DBGF_LIFECYCLE,
		    "%s: siocgifdevmtu failed, %d",
		    p->if_xname, error);
		kfree_type(struct vlan_parent, vlp);
		return error;
	}
	LIST_INIT(&vlp->vlp_vlan_list);
	vlp->vlp_ifp = p;
	vlp->vlp_retain_count = 1;
	vlp->vlp_signature = VLP_SIGNATURE;
	if (ifnet_offload(p)
	    & (IF_HWASSIST_VLAN_MTU | IF_HWASSIST_VLAN_TAGGING)) {
		vlan_parent_flags_set(vlp, VLPF_SUPPORTS_VLAN_MTU);
	}
	*ret_vlp = vlp;
	return 0;
}

static void
vlan_parent_remove_all_vlans(struct ifnet * p)
{
	ifvlan_ref          ifv;
	int                 need_vlp_release = 0;
	ifvlan_ref          next;
	vlan_parent_ref     vlp;

	vlan_lock();
	vlp = parent_list_lookup(p);
	if (vlp == NULL ||
	    vlan_parent_flags_are_set(vlp, VLPF_DETACHING | VLPF_INVALIDATED)) {
		/* parent has no VLANs or is detaching/invalidated */
		vlan_unlock();
		return;
	}
	vlan_parent_flags_set(vlp, VLPF_DETACHING);
	vlan_parent_retain(vlp);
	VLAN_PARENT_WAIT(vlp);
	need_vlp_release++;

	/* check again */
	if (parent_list_lookup(p) != vlp) {
		goto signal_done;
	}

	for (ifv = LIST_FIRST(&vlp->vlp_vlan_list); ifv != NULL; ifv = next) {
		struct ifnet *  ifp = ifv->ifv_ifp;
		int             removed;

		next = LIST_NEXT(ifv, ifv_vlan_list);
		removed = vlan_remove(ifv, FALSE);
		if (removed) {
			vlan_unlock();
			ifnet_detach(ifp);
			vlan_lock();
		}
	}

	/* the vlan parent has no more VLAN's */
	if_clear_eflags(p, IFEF_VLAN); /* clear IFEF_VLAN */

	LIST_REMOVE(vlp, vlp_parent_list);
	need_vlp_release++; /* one for being in the list */
	need_vlp_release++; /* final reference */

signal_done:
	VLAN_PARENT_SIGNAL(vlp);
	vlan_unlock();

	while (need_vlp_release--) {
		vlan_parent_release(vlp);
	}
	return;
}

static inline int
vlan_parent_no_vlans(vlan_parent_ref vlp)
{
	return LIST_EMPTY(&vlp->vlp_vlan_list);
}

static void
vlan_parent_add_vlan(vlan_parent_ref vlp, ifvlan_ref ifv, int tag)
{
	LIST_INSERT_HEAD(&vlp->vlp_vlan_list, ifv, ifv_vlan_list);
	ifv->ifv_vlp = vlp;
	ifv->ifv_tag = tag;
	return;
}

static void
vlan_parent_remove_vlan(__unused vlan_parent_ref vlp, ifvlan_ref ifv)
{
	ifv->ifv_vlp = NULL;
	LIST_REMOVE(ifv, ifv_vlan_list);
	return;
}

static int
vlan_clone_attach(void)
{
	return if_clone_attach(&vlan_cloner);
}

#if !XNU_TARGET_OS_OSX
static inline bool
vlan_is_enabled(void)
{
	if (vlan_enabled != 0) {
		return true;
	}
	if (kern_osreleasetype_matches("Darwin") ||
	    kern_osreleasetype_matches("Restore") ||
	    kern_osreleasetype_matches("NonUI")) {
		vlan_enabled = 1;
	}
	return vlan_enabled != 0;
}
#endif /* !XNU_TARGET_OS_OSX */

static int
vlan_clone_create(struct if_clone *ifc, u_int32_t unit, __unused void *params)
{
	int                                                     error;
	ifvlan_ref                                      ifv;
	ifnet_ref_t                               ifp;
	struct ifnet_init_eparams       vlan_init;

#if !XNU_TARGET_OS_OSX
	if (!vlan_is_enabled()) {
		return EOPNOTSUPP;
	}
#endif /* !XNU_TARGET_OS_OSX */

	error = vlan_globals_init();
	if (error != 0) {
		return error;
	}
	ifv = kalloc_type(struct ifvlan, Z_WAITOK_ZERO_NOFAIL);
	ifv->ifv_retain_count = 1;
	ifv->ifv_signature = IFV_SIGNATURE;
	multicast_list_init(&ifv->ifv_multicast);

	/* use the interface name as the unique id for ifp recycle */
	if ((unsigned int)
	    snprintf(ifv->ifv_name, sizeof(ifv->ifv_name), "%s%d",
	    ifc->ifc_name, unit) >= sizeof(ifv->ifv_name)) {
		ifvlan_release(ifv);
		return EINVAL;
	}

	bzero(&vlan_init, sizeof(vlan_init));
	vlan_init.ver = IFNET_INIT_CURRENT_VERSION;
	vlan_init.len = sizeof(vlan_init);
	vlan_init.flags = IFNET_INIT_LEGACY;
	vlan_init.uniqueid_len = strbuflen(ifv->ifv_name);
	vlan_init.uniqueid = ifv->ifv_name;
	vlan_init.name = __unsafe_null_terminated_from_indexable(ifc->ifc_name);
	vlan_init.unit = unit;
	vlan_init.family = IFNET_FAMILY_VLAN;
	vlan_init.type = IFT_L2VLAN;
	vlan_init.output = vlan_output;
	vlan_init.demux = ether_demux;
	vlan_init.add_proto = ether_add_proto;
	vlan_init.del_proto = ether_del_proto;
	vlan_init.check_multi = ether_check_multi;
	vlan_init.framer_extended = ether_frameout_extended;
	vlan_init.softc = ifv;
	vlan_init.ioctl = vlan_ioctl;
	vlan_init.set_bpf_tap = NULL;
	vlan_init.detach = vlan_if_free;
	vlan_init.broadcast_addr = etherbroadcastaddr;
	vlan_init.broadcast_len = ETHER_ADDR_LEN;
	error = ifnet_allocate_extended(&vlan_init, &ifp);

	if (error) {
		ifvlan_release(ifv);
		return error;
	}

	ifnet_set_offload(ifp, 0);
	ifnet_set_addrlen(ifp, ETHER_ADDR_LEN);
	ifnet_set_baudrate(ifp, 0);
	ifnet_set_hdrlen(ifp, ETHER_HDR_LEN);
	ifnet_set_mtu(ifp, ETHERMTU);

	error = ifnet_attach(ifp, NULL);
	if (error) {
		ifnet_release(ifp);
		ifvlan_release(ifv);
		return error;
	}
	ifv->ifv_ifp = ifp;

	/* attach as ethernet */
	bpfattach(ifp, DLT_EN10MB, sizeof(struct ether_header));
	return 0;
}

static int
vlan_remove(ifvlan_ref ifv, int need_to_wait)
{
	vlan_assert_lock_held();
	if (ifvlan_flags_are_set(ifv, IFVF_DETACHING)) {
		return 0;
	}
	ifvlan_flags_set(ifv, IFVF_DETACHING);
	vlan_unconfig(ifv, need_to_wait);
	return 1;
}


static int
vlan_clone_destroy(struct ifnet *ifp)
{
	ifvlan_ref ifv;

	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL) {
		vlan_unlock();
		return 0;
	}
	if (vlan_remove(ifv, TRUE) == 0) {
		vlan_unlock();
		ifvlan_release(ifv);
		return 0;
	}
	vlan_unlock();
	ifvlan_release(ifv);
	ifnet_detach(ifp);

	return 0;
}

static int
vlan_output(struct ifnet * ifp, struct mbuf * m)
{
	struct ether_vlan_header *  evl;
	ifvlan_ref                  ifv;
	struct ifnet *              p;
	int                         soft_vlan;
	u_short                     tag;
	vlan_parent_ref             vlp = NULL;
	int                         err;
	struct flowadv              adv = { .code = FADV_SUCCESS };

	if (m == 0) {
		return 0;
	}
	if ((m->m_flags & M_PKTHDR) == 0) {
		m_freem_list(m);
		return 0;
	}
	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL || !ifvlan_flags_are_set(ifv, IFVF_READY)) {
		goto unlock_done;
	}
	vlp = ifvlan_get_vlan_parent_retained(ifv);
	if (vlp == NULL) {
		goto unlock_done;
	}
	p = vlp->vlp_ifp;
	(void)ifnet_stat_increment_out(ifp, 1, m->m_pkthdr.len, 0);
	soft_vlan = (ifnet_offload(p) & IF_HWASSIST_VLAN_TAGGING) == 0;
	tag = ifv->ifv_tag;
	vlan_unlock();

	ifvlan_release(ifv);
	vlan_parent_release(vlp);

	bpf_tap_out(ifp, DLT_EN10MB, m, NULL, 0);

	/* do not run parent's if_output() if the parent is not up */
	if ((ifnet_flags(p) & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) {
		m_freem(m);
		os_atomic_inc(&ifp->if_collisions, relaxed);
		return 0;
	}
	/*
	 * If underlying interface can do VLAN tag insertion itself,
	 * just pass the packet along. However, we need some way to
	 * tell the interface where the packet came from so that it
	 * knows how to find the VLAN tag to use.  We use a field in
	 * the mbuf header to store the VLAN tag, and a bit in the
	 * csum_flags field to mark the field as valid.
	 */
	if (soft_vlan == 0) {
		m->m_pkthdr.csum_flags |= CSUM_VLAN_TAG_VALID;
		m->m_pkthdr.vlan_tag = tag;
	} else {
		M_PREPEND(m, ETHER_VLAN_ENCAP_LEN, M_DONTWAIT, 0);
		if (m == NULL) {
			VLAN_LOG(LOG_DEBUG, VL_DBGF_OUTPUT,
			    "%s: unable to prepend VLAN header",
			    ifp->if_xname);
			os_atomic_inc(&ifp->if_oerrors, relaxed);
			return 0;
		}
		/* M_PREPEND takes care of m_len, m_pkthdr.len for us */
		if (m->m_len < (int)sizeof(*evl)) {
			m = m_pullup(m, sizeof(*evl));
			if (m == NULL) {
				VLAN_LOG(LOG_NOTICE, VL_DBGF_OUTPUT,
				    "%s: m_pullup VLAN header failed",
				    ifp->if_xname);
				os_atomic_inc(&ifp->if_oerrors, relaxed);
				return 0;
			}
			VLAN_LOG(LOG_DEBUG, VL_DBGF_OUTPUT,
			    "%s: needed to m_pullup VLAN header",
			    ifp->if_xname);
		}

		/*
		 * Transform the Ethernet header into an Ethernet header
		 * with 802.1Q encapsulation.
		 */
		bcopy(mtod(m, char *) + ETHER_VLAN_ENCAP_LEN,
		    mtod(m, char *), ETHER_HDR_LEN);
		evl = mtod(m, struct ether_vlan_header *);
		evl->evl_proto = evl->evl_encap_proto;
		evl->evl_encap_proto = htons(ETHERTYPE_VLAN);
		evl->evl_tag = htons(tag);

		/* adjust partial checksum offload offsets */
		if ((m->m_pkthdr.csum_flags & (CSUM_DATA_VALID |
		    CSUM_PARTIAL)) == (CSUM_DATA_VALID | CSUM_PARTIAL)) {
			m->m_pkthdr.csum_tx_start += ETHER_VLAN_ENCAP_LEN;
			m->m_pkthdr.csum_tx_stuff += ETHER_VLAN_ENCAP_LEN;
		}
		m->m_pkthdr.csum_flags |= CSUM_VLAN_ENCAP_PRESENT;
	}
	VLAN_LOG(LOG_DEBUG, VL_DBGF_OUTPUT,
	    "%s: %s tag %d bytes %d (%s)", ifp->if_xname, p->if_xname, tag,
	    m->m_pkthdr.len, soft_vlan ? "soft" : "hard");
	err = dlil_output(p, PF_VLAN, m, NULL, NULL,
	    DLIL_OUTPUT_FLAGS_RAW, &adv);
	if (err == 0) {
		if (adv.code == FADV_FLOW_CONTROLLED) {
			err = EQFULL;
		} else if (adv.code == FADV_SUSPENDED) {
			err = EQSUSPENDED;
		}
	}

	return err;

unlock_done:
	vlan_unlock();
	if (ifv != NULL) {
		ifvlan_release(ifv);
	}
	if (vlp != NULL) {
		vlan_parent_release(vlp);
	}
	m_freem_list(m);
	return 0;
}

static void
vlan_input_packet_list(ifnet_t vlan_ifp, mbuf_t list)
{
	struct ifnet_stat_increment_param       s;

	bzero(&s, sizeof(s));
	for (mbuf_t scan = list; scan != NULL; scan = scan->m_nextpkt) {
		struct ether_header *   eh_p;

		/* clear hardware VLAN */
		scan->m_pkthdr.csum_flags &= ~CSUM_VLAN_TAG_VALID;
		scan->m_pkthdr.vlan_tag = 0;
		scan->m_pkthdr.rcvif = vlan_ifp;
		eh_p = (struct ether_header *)scan->m_pkthdr.pkt_hdr;
		bpf_tap_in(vlan_ifp, DLT_EN10MB, scan, eh_p, ETHER_HDR_LEN);
		s.packets_in++;
		s.bytes_in += scan->m_pkthdr.len + ETHER_HDR_LEN;
	}
	ifnet_stat_increment(vlan_ifp, &s);
	VLAN_LOG(LOG_DEBUG, VL_DBGF_INPUT, "%s: packets %d bytes %d",
	    vlan_ifp->if_xname, s.packets_in, s.bytes_in);
	dlil_input_packet_list(vlan_ifp, list);
}

static void
vlan_input_tag(ifnet_t p, mbuf_t list, u_int tag)
{
	ifvlan_ref              ifv;
	struct ifnet *          vlan_ifp = NULL;

	/* find a matching VLAN */
	vlan_lock();
	ifv = vlan_lookup_parent_and_tag(p, tag);
	if (ifv != NULL && ifvlan_flags_are_set(ifv, IFVF_READY)) {
		vlan_ifp = ifv->ifv_ifp;
		if ((ifnet_flags(vlan_ifp) & IFF_UP) == 0) {
			vlan_ifp = NULL;
		}
	}
	vlan_unlock();
	if (vlan_ifp == NULL) {
		/* no such VLAN */
		VLAN_LOG(LOG_DEBUG, VL_DBGF_INPUT,
		    "%s VLAN tag %d (dropped)", p->if_xname, tag);
		m_freem_list(list);
	} else {
		/* send packet list up */
		vlan_input_packet_list(vlan_ifp, list);
	}
	return;
}


static int
vlan_input(ifnet_t p, __unused protocol_family_t protocol, mbuf_t m)
{
	mblist                      list;
	u_int                       list_tag = 0;
	mbuf_t                      next_packet = NULL;
	mbuf_t                      scan;
	u_int                       tag;

	if ((ifnet_eflags(p) & IFEF_VLAN) == 0) {
		/* don't bother looking through the VLAN list */
		m_freem_list(m);
		goto done;
	}
	mblist_init(&list);
	for (scan = m; scan != NULL; scan = next_packet) {
		next_packet = scan->m_nextpkt;
		scan->m_nextpkt = NULL;

		VERIFY((scan->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) != 0);
		tag = EVL_VLANOFTAG(scan->m_pkthdr.vlan_tag);
		/* ether_demux() handles priority-tagged pkts */
		VERIFY(tag != 0);
		VLAN_LOG(LOG_DEBUG, VL_DBGF_INPUT,
		    "%s tag %d", p->if_xname, tag);
		if (scan == NULL) {
			/* discarded above */
		} else if (list.head == NULL) {
			/* start a new list */
			mblist_append(&list, scan);
			list_tag = tag;
		} else if (tag != list_tag) {
			/* send up the previous chain */
			vlan_input_tag(p, list.head, list_tag);

			/* start a new list */
			mblist_init(&list);
			mblist_append(&list, scan);
			list_tag = tag;
		} else {
			mblist_append(&list, scan);
		}
		if (next_packet == NULL) {
			/* end of the list */
			if (list.head != NULL) {
				vlan_input_tag(p, list.head, list_tag);
			}
		}
	}
done:
	return 0;
}

static int
vlan_config(struct ifnet * ifp, struct ifnet * p, int tag)
{
	u_int32_t           eflags;
	int                 error;
	int                 first_vlan = FALSE;
	ifvlan_ref          ifv = NULL;
	int                 ifv_added = FALSE;
	int                 need_vlp_release = 0;
	vlan_parent_ref     new_vlp = NULL;
	ifnet_offload_t     offload;
	u_int16_t           parent_flags;
	vlan_parent_ref     vlp = NULL;

	/* pre-allocate space for vlan_parent, in case we're first */
	error = vlan_parent_create(p, &new_vlp);
	if (error != 0) {
		return error;
	}

	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL || ifv->ifv_vlp != NULL) {
		vlan_unlock();
		if (ifv != NULL) {
			ifvlan_release(ifv);
		}
		vlan_parent_release(new_vlp);
		return EBUSY;
	}
	vlp = parent_list_lookup(p);
	if (vlp != NULL) {
		vlan_parent_retain(vlp);
		need_vlp_release++;
		if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
			/* already a VLAN with that tag on this interface */
			error = EADDRINUSE;
			goto unlock_done;
		}
	} else {
		/* one for being in the list */
		vlan_parent_retain(new_vlp);

		/* we're the first VLAN on this interface */
		LIST_INSERT_HEAD(&g_vlan->parent_list, new_vlp, vlp_parent_list);
		vlp = new_vlp;

		vlan_parent_retain(vlp);
		need_vlp_release++;
	}

	/* need to wait to ensure no one else is trying to add/remove */
	VLAN_PARENT_WAIT(vlp);

	if (ifnet_get_ifvlan(ifp) != ifv) {
		error = EINVAL;
		goto signal_done;
	}

	/* check again because someone might have gotten in */
	if (parent_list_lookup(p) != vlp) {
		error = EBUSY;
		goto signal_done;
	}

	if (vlan_parent_flags_are_set(vlp, VLPF_DETACHING) ||
	    ifvlan_flags_are_set(ifv, IFVF_DETACHING) || ifv->ifv_vlp != NULL) {
		error = EBUSY;
		goto signal_done;
	}

	/* check again because someone might have gotten the tag */
	if (vlan_parent_lookup_tag(vlp, tag) != NULL) {
		/* already a VLAN with that tag on this interface */
		error = EADDRINUSE;
		goto signal_done;
	}

	if (vlan_parent_no_vlans(vlp)) {
		first_vlan = TRUE;
	}
	vlan_parent_add_vlan(vlp, ifv, tag);
	ifvlan_retain(ifv); /* parent references ifv */
	ifv_added = TRUE;

	/* don't allow VLAN on interface that's part of a bond */
	if ((ifnet_eflags(p) & IFEF_BOND) != 0) {
		error = EBUSY;
		goto signal_done;
	}
	/* mark it as in use by VLAN */
	eflags = if_set_eflags(p, IFEF_VLAN);
	if ((eflags & IFEF_BOND) != 0) {
		/* bond got in ahead of us */
		if_clear_eflags(p, IFEF_VLAN);
		error = EBUSY;
		goto signal_done;
	}
	vlan_unlock();

	if (first_vlan) {
		/* attach our VLAN "protocol" to the interface */
		error = vlan_attach_protocol(p);
		if (error) {
			vlan_lock();
			goto signal_done;
		}
	}

	/* inherit management restriction from parent by default */
	if (IFNET_IS_MANAGEMENT(p)) {
		ifnet_set_management(ifp, true);
	}

	/* configure parent to receive our multicast addresses */
	error = multicast_list_program(&ifv->ifv_multicast, ifp, p);
	if (error != 0) {
		if (first_vlan) {
			(void)vlan_detach_protocol(p);
		}
		vlan_lock();
		goto signal_done;
	}

	/* set our ethernet address to that of the parent */
	ifnet_set_lladdr_and_type(ifp, IF_LLADDR(p), ETHER_ADDR_LEN, IFT_ETHER);

	/* no failures past this point */
	vlan_lock();

	ifv->ifv_flags = 0;
	if (vlan_parent_flags_are_set(vlp, VLPF_SUPPORTS_VLAN_MTU)) {
		ifv->ifv_mtufudge = 0;
	} else {
		/*
		 * Fudge the MTU by the encapsulation size.  This
		 * makes us incompatible with strictly compliant
		 * 802.1Q implementations, but allows us to use
		 * the feature with other NetBSD implementations,
		 * which might still be useful.
		 */
		ifv->ifv_mtufudge = ETHER_VLAN_ENCAP_LEN;
	}
	ifnet_set_mtu(ifp, ETHERMTU - ifv->ifv_mtufudge);

	/*
	 * Copy only a selected subset of flags from the parent.
	 * Other flags are none of our business.
	 */
	parent_flags = ifnet_flags(p)
	    & (IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);
	ifnet_set_flags(ifp, parent_flags,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX);

	/* use hwassist bits from parent interface, but exclude VLAN bits */
	offload = ifnet_offload(p) & ~(IFNET_VLAN_TAGGING | IFNET_VLAN_MTU);
	ifnet_set_offload(ifp, offload);

	ifnet_set_flags(ifp, IFF_RUNNING, IFF_RUNNING);
	ifvlan_flags_set(ifv, IFVF_READY);
	VLAN_PARENT_SIGNAL(vlp);
	vlan_unlock();
	if (new_vlp != vlp) {
		/* throw it away, it wasn't needed */
		vlan_parent_release(new_vlp);
	}
	if (ifv != NULL) {
		ifvlan_release(ifv);
	}
	if (first_vlan) {
		/* mark the parent interface up */
		ifnet_set_flags(p, IFF_UP, IFF_UP);
		(void)ifnet_ioctl(p, 0, SIOCSIFFLAGS, (caddr_t)NULL);
	}
	return 0;

signal_done:
	vlan_assert_lock_held();

	if (ifv_added) {
		vlan_parent_remove_vlan(vlp, ifv);
		if (!vlan_parent_flags_are_set(vlp, VLPF_DETACHING) &&
		    vlan_parent_no_vlans(vlp)) {
			/* the vlan parent has no more VLAN's */
			if_clear_eflags(p, IFEF_VLAN);
			LIST_REMOVE(vlp, vlp_parent_list);
			/* release outside of the lock below */
			need_vlp_release++;

			/* one for being in the list */
			need_vlp_release++;
		}
	}
	VLAN_PARENT_SIGNAL(vlp);

unlock_done:
	vlan_unlock();

	while (need_vlp_release--) {
		vlan_parent_release(vlp);
	}
	if (new_vlp != vlp) {
		vlan_parent_release(new_vlp);
	}
	if (ifv != NULL) {
		if (ifv_added) {
			ifvlan_release(ifv);
		}
		ifvlan_release(ifv);
	}
	return error;
}

static void
vlan_link_event(struct ifnet * ifp, struct ifnet * p)
{
	struct ifmediareq ifmr;

	/* generate link event based on the state of the underlying interface */
	bzero(&ifmr, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, p->if_xname, sizeof(ifmr.ifm_name));
	if (ifnet_ioctl(p, 0, SIOCGIFMEDIA, &ifmr) == 0
	    && ifmr.ifm_count > 0 && ifmr.ifm_status & IFM_AVALID) {
		u_int32_t       event;

		event = (ifmr.ifm_status & IFM_ACTIVE)
		    ? KEV_DL_LINK_ON : KEV_DL_LINK_OFF;
		interface_link_event(ifp, event);
	}
	return;
}

static int
vlan_unconfig(ifvlan_ref ifv, int need_to_wait)
{
	struct ifnet *      ifp = ifv->ifv_ifp;
	int                 last_vlan = FALSE;
	int                 need_ifv_release = 0;
	int                 need_vlp_release = 0;
	struct ifnet *      p;
	vlan_parent_ref     vlp;

	vlan_assert_lock_held();
	vlp = ifv->ifv_vlp;
	if (vlp == NULL) {
		return 0;
	}
	if (need_to_wait) {
		need_vlp_release++;
		vlan_parent_retain(vlp);
		VLAN_PARENT_WAIT(vlp);

		/* check again because another thread could be in vlan_unconfig */
		if (ifv != ifnet_get_ifvlan(ifp)) {
			goto signal_done;
		}
		if (ifv->ifv_vlp != vlp) {
			/* vlan parent changed */
			goto signal_done;
		}
	}

	/* ifv has a reference on vlp, need to remove it */
	need_vlp_release++;
	p = vlp->vlp_ifp;

	/* remember whether we're the last VLAN on the parent */
	if (LIST_NEXT(LIST_FIRST(&vlp->vlp_vlan_list), ifv_vlan_list) == NULL) {
		VLAN_LOG(LOG_DEBUG, VL_DBGF_LIFECYCLE,
		    "last vlan on %s", p->if_xname);
		last_vlan = TRUE;
		/* avoid deadlock with vlan_parent_remove_vlans() */
		vlan_parent_flags_set(vlp, VLPF_INVALIDATED);
	}

	/* back-out any effect our mtu might have had on the parent */
	(void)ifvlan_new_mtu(ifv, ETHERMTU - ifv->ifv_mtufudge);

	vlan_unlock();

	/* un-join multicast on parent interface */
	(void)multicast_list_remove(&ifv->ifv_multicast);

	/* Clear our MAC address. */
	ifnet_set_lladdr_and_type(ifp, NULL, 0, IFT_L2VLAN);

	/* if we enabled promiscuous mode, disable it */
	if (ifvlan_flags_are_set(ifv, IFVF_PROMISC)) {
		(void)ifnet_set_promiscuous(p, 0);
	}

	/* detach VLAN "protocol" */
	if (last_vlan) {
		(void)vlan_detach_protocol(p);
	}

	vlan_lock();

	/* return to the state we were in before SIFVLAN */
	ifnet_set_mtu(ifp, ETHERMTU);
	ifnet_set_flags(ifp, 0,
	    IFF_BROADCAST | IFF_MULTICAST | IFF_SIMPLEX | IFF_RUNNING);
	ifnet_set_offload(ifp, 0);
	ifv->ifv_mtufudge = 0;

	/* Disconnect from parent. */
	vlan_parent_remove_vlan(vlp, ifv);
	ifv->ifv_flags = 0; /* clears IFVF_READY */

	/* vlan_parent has reference to ifv, remove it */
	need_ifv_release++;

	/* from this point on, no more referencing ifv */
	if (last_vlan && !vlan_parent_flags_are_set(vlp, VLPF_DETACHING)) {
		/* the vlan parent has no more VLAN's */
		if_clear_eflags(p, IFEF_VLAN);
		LIST_REMOVE(vlp, vlp_parent_list);

		/* one for being in the list */
		need_vlp_release++;

		/* release outside of the lock below */
		need_vlp_release++;
	}

signal_done:
	if (need_to_wait) {
		VLAN_PARENT_SIGNAL(vlp);
	}
	vlan_unlock();
	while (need_ifv_release--) {
		ifvlan_release(ifv);
	}
	while (need_vlp_release--) {    /* references to vlp */
		vlan_parent_release(vlp);
	}
	vlan_lock();
	return 0;
}

static int
vlan_set_promisc(struct ifnet * ifp)
{
	int                         error = 0;
	ifvlan_ref                  ifv;
	bool                        is_promisc;
	int                         val;
	vlan_parent_ref             vlp;
	struct ifnet *              vlp_ifp = NULL;

	is_promisc = (ifnet_flags(ifp) & IFF_PROMISC) != 0;

	/* determine whether promiscuous state needs to be changed */
	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL) {
		error = EBUSY;
		goto done;
	}
	vlp = ifv->ifv_vlp;
	if (vlp != NULL) {
		vlp_ifp = vlp->vlp_ifp;
	}
	if (vlp_ifp == NULL) {
		goto done;
	}
	if (is_promisc == ifvlan_flags_are_set(ifv, IFVF_PROMISC)) {
		/* already in the right state */
		goto done;
	}
	vlan_unlock();

	/* state needs to be changed, set promiscuous state on parent */
	val = is_promisc ? 1 : 0;
	error = ifnet_set_promiscuous(vlp_ifp, val);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, VL_DBGF_CONTROL,
		    "%s: ifnet_set_promiscuous(%s, %d) failed %d",
		    ifp->if_xname, vlp_ifp->if_xname, val, error);
		goto unlocked_done;
	}
	VLAN_LOG(LOG_NOTICE, VL_DBGF_CONTROL,
	    "%s: ifnet_set_promiscuous(%s, %d) succeeded",
	    ifp->if_xname, vlp_ifp->if_xname, val);

	/* update our internal state */
	vlan_lock();
	if (is_promisc) {
		ifvlan_flags_set(ifv, IFVF_PROMISC);
	} else {
		ifvlan_flags_clear(ifv, IFVF_PROMISC);
	}

done:
	vlan_unlock();
unlocked_done:
	if (ifv != NULL) {
		ifvlan_release(ifv);
	}
	return error;
}

static int
ifvlan_new_mtu(ifvlan_ref ifv, int mtu)
{
	struct ifdevmtu *   devmtu_p;
	int                 error = 0;
	struct ifnet *      ifp = ifv->ifv_ifp;
	int                 max_mtu;
	int                 new_mtu = 0;
	int                 req_mtu;
	vlan_parent_ref     vlp;

	vlan_assert_lock_held();
	vlp = ifv->ifv_vlp;
	devmtu_p = &vlp->vlp_devmtu;
	req_mtu = mtu + ifv->ifv_mtufudge;
	if (req_mtu > devmtu_p->ifdm_max || req_mtu < devmtu_p->ifdm_min) {
		return EINVAL;
	}
	max_mtu = vlan_parent_find_max_mtu(vlp, ifv);
	if (req_mtu > max_mtu) {
		new_mtu = req_mtu;
	} else if (max_mtu < devmtu_p->ifdm_current) {
		new_mtu = max_mtu;
	}
	if (new_mtu != 0) {
		struct ifnet *  p = vlp->vlp_ifp;
		vlan_unlock();
		error = siocsifaltmtu(p, new_mtu);
		vlan_lock();
	}
	if (error == 0) {
		if (new_mtu != 0) {
			devmtu_p->ifdm_current = new_mtu;
		}
		ifnet_set_mtu(ifp, mtu);
	}
	return error;
}

static int
vlan_set_mtu(struct ifnet * ifp, int mtu)
{
	int                 error = 0;
	ifvlan_ref          ifv;
	vlan_parent_ref     vlp;

	if (mtu < IF_MINMTU) {
		return EINVAL;
	}
	vlan_lock();
	ifv = ifnet_get_ifvlan_retained(ifp);
	if (ifv == NULL) {
		vlan_unlock();
		return EBUSY;
	}
	vlp = ifvlan_get_vlan_parent_retained(ifv);
	if (vlp == NULL) {
		vlan_unlock();
		ifvlan_release(ifv);
		if (mtu != 0) {
			return EINVAL;
		}
		return 0;
	}
	VLAN_PARENT_WAIT(vlp);

	/* check again, something might have changed */
	if (ifnet_get_ifvlan(ifp) != ifv ||
	    ifvlan_flags_are_set(ifv, IFVF_DETACHING)) {
		error = EBUSY;
		goto signal_done;
	}
	if (ifv->ifv_vlp != vlp) {
		/* vlan parent changed */
		goto signal_done;
	}
	if (vlan_parent_flags_are_set(vlp, VLPF_DETACHING)) {
		if (mtu != 0) {
			error = EINVAL;
		}
		goto signal_done;
	}
	error = ifvlan_new_mtu(ifv, mtu);

signal_done:
	VLAN_PARENT_SIGNAL(vlp);
	vlan_unlock();
	vlan_parent_release(vlp);
	ifvlan_release(ifv);

	return error;
}

static int
vlan_ioctl(ifnet_t ifp, u_long cmd, void * data)
{
	struct ifdevmtu *   devmtu_p;
	int                 error = 0;
	struct ifaddr *     ifa;
	struct ifmediareq32 * ifmr;
	struct ifreq *      ifr;
	ifvlan_ref          ifv;
	struct ifnet *      p;
	u_int16_t           tag;
	user_addr_t         user_addr;
	vlan_parent_ref     vlp;
	struct vlanreq      vlr;

	if (ifnet_type(ifp) != IFT_L2VLAN) {
		return EOPNOTSUPP;
	}
	ifr = (struct ifreq *)data;
	ifa = (struct ifaddr *)data;

	switch (cmd) {
	case SIOCSIFADDR:
		ifnet_set_flags(ifp, IFF_UP, IFF_UP);
		break;

	case SIOCGIFMEDIA32:
	case SIOCGIFMEDIA64:
		vlan_lock();
		ifv = (ifvlan_ref)ifnet_softc(ifp);
		if (ifvlan_is_invalid(ifv)) {
			vlan_unlock();
			return ifv == NULL ? EOPNOTSUPP : EBUSY;
		}
		p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
		vlan_unlock();
		ifmr = (struct ifmediareq32 *)data;
		user_addr =  (cmd == SIOCGIFMEDIA64) ?
		    ((struct ifmediareq64 *)data)->ifmu_ulist :
		    CAST_USER_ADDR_T(((struct ifmediareq32 *)data)->ifmu_ulist);
		if (p != NULL) {
			struct ifmediareq p_ifmr;

			bzero(&p_ifmr, sizeof(p_ifmr));
			error = ifnet_ioctl(p, 0, SIOCGIFMEDIA, &p_ifmr);
			if (error == 0) {
				ifmr->ifm_active = p_ifmr.ifm_active;
				ifmr->ifm_current = p_ifmr.ifm_current;
				ifmr->ifm_mask = p_ifmr.ifm_mask;
				ifmr->ifm_status = p_ifmr.ifm_status;
				ifmr->ifm_count = p_ifmr.ifm_count;
				/* Limit the result to the parent's current config. */
				if (ifmr->ifm_count >= 1 && user_addr != USER_ADDR_NULL) {
					ifmr->ifm_count = 1;
					error = copyout(&ifmr->ifm_current, user_addr,
					    sizeof(int));
				}
			}
		} else {
			ifmr->ifm_active = ifmr->ifm_current = IFM_NONE;
			ifmr->ifm_mask = 0;
			ifmr->ifm_status = IFM_AVALID;
			ifmr->ifm_count = 1;
			if (user_addr != USER_ADDR_NULL) {
				error = copyout(&ifmr->ifm_current, user_addr, sizeof(int));
			}
		}
		break;

	case SIOCSIFMEDIA:
		error = EOPNOTSUPP;
		break;

	case SIOCGIFDEVMTU:
		vlan_lock();
		ifv = (ifvlan_ref)ifnet_softc(ifp);
		if (ifvlan_is_invalid(ifv)) {
			vlan_unlock();
			return ifv == NULL ? EOPNOTSUPP : EBUSY;
		}
		vlp = ifv->ifv_vlp;
		if (vlp != NULL) {
			int         min_mtu = vlp->vlp_devmtu.ifdm_min - ifv->ifv_mtufudge;
			devmtu_p = &ifr->ifr_devmtu;
			devmtu_p->ifdm_current = ifnet_mtu(ifp);
			devmtu_p->ifdm_min = max(min_mtu, IF_MINMTU);
			devmtu_p->ifdm_max = vlp->vlp_devmtu.ifdm_max - ifv->ifv_mtufudge;
		} else {
			devmtu_p = &ifr->ifr_devmtu;
			devmtu_p->ifdm_current = 0;
			devmtu_p->ifdm_min = 0;
			devmtu_p->ifdm_max = 0;
		}
		vlan_unlock();
		break;

	case SIOCSIFMTU:
		error = vlan_set_mtu(ifp, ifr->ifr_mtu);
		break;

	case SIOCSIFVLAN:
		user_addr = proc_is64bit(current_proc())
		    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
		error = copyin(user_addr, &vlr, sizeof(vlr));
		if (error) {
			break;
		}
		p = NULL;
		/* ensure nul termination */
		vlr.vlr_parent[IFNAMSIZ - 1] = '\0';
		if (vlr.vlr_parent[0] != '\0') {
			if (vlr.vlr_tag & ~EVL_VLID_MASK) {
				/*
				 * Don't let the caller set up a VLAN tag with
				 * anything except VLID bits.
				 */
				error = EINVAL;
				break;
			}
			p = ifunit(__unsafe_null_terminated_from_indexable(vlr.vlr_parent));
			if (p == NULL) {
				error = ENXIO;
				break;
			}
			if (IFNET_IS_INTCOPROC(p)) {
				error = EINVAL;
				break;
			}

			/* can't do VLAN over anything but ethernet or ethernet aggregate */
			if (ifnet_type(p) != IFT_ETHER
			    && ifnet_type(p) != IFT_IEEE8023ADLAG) {
				error = EPROTONOSUPPORT;
				break;
			}
			error = vlan_config(ifp, p, vlr.vlr_tag);
			if (error) {
				break;
			}

			/* Update promiscuous mode, if necessary. */
			(void)vlan_set_promisc(ifp);

			/* generate a link event based on the state of the parent */
			vlan_link_event(ifp, p);
		} else {
			int         need_link_event = FALSE;

			vlan_lock();
			ifv = (ifvlan_ref)ifnet_softc(ifp);
			if (ifvlan_is_invalid(ifv)) {
				vlan_unlock();
				error = (ifv == NULL ? EOPNOTSUPP : EBUSY);
				break;
			}
			need_link_event = (ifv->ifv_vlp != NULL);
			vlan_unconfig(ifv, TRUE);
			vlan_unlock();
			if (need_link_event) {
				interface_link_event(ifp, KEV_DL_LINK_OFF);
			}
		}
		break;

	case SIOCGIFVLAN:
		bzero(&vlr, sizeof vlr);
		vlan_lock();
		ifv = (ifvlan_ref)ifnet_softc(ifp);
		if (ifvlan_is_invalid(ifv)) {
			vlan_unlock();
			return ifv == NULL ? EOPNOTSUPP : EBUSY;
		}
		p = (ifv->ifv_vlp == NULL) ? NULL : ifv->ifv_vlp->vlp_ifp;
		tag = ifv->ifv_tag;
		vlan_unlock();
		if (p != NULL) {
			strlcpy(vlr.vlr_parent, p->if_xname,
			    sizeof(vlr.vlr_parent));
			vlr.vlr_tag = tag;
		}
		user_addr = proc_is64bit(current_proc())
		    ? ifr->ifr_data64 : CAST_USER_ADDR_T(ifr->ifr_data);
		error = copyout(&vlr, user_addr, sizeof(vlr));
		break;

	case SIOCSIFFLAGS:
		/*
		 * For promiscuous mode, we enable promiscuous mode on
		 * the parent if we need promiscuous on the VLAN interface.
		 */
		error = vlan_set_promisc(ifp);
		break;

	case SIOCADDMULTI:
	case SIOCDELMULTI:
		error = vlan_setmulti(ifp);
		break;
	default:
		error = EOPNOTSUPP;
	}
	return error;
}

static void
vlan_if_free(struct ifnet * ifp)
{
	ifvlan_ref  ifv;

	if (ifp == NULL) {
		return;
	}
	ifv = (ifvlan_ref)ifnet_softc(ifp);
	if (ifv == NULL) {
		return;
	}
	ifvlan_release(ifv);
	ifnet_release(ifp);
	return;
}

static void
vlan_event(struct ifnet * p, __unused protocol_family_t protocol,
    const struct kev_msg * event)
{
	int                 event_code;

	/* Check if the interface we are attached to is being detached */
	if (event->vendor_code != KEV_VENDOR_APPLE
	    || event->kev_class != KEV_NETWORK_CLASS
	    || event->kev_subclass != KEV_DL_SUBCLASS) {
		return;
	}
	event_code = event->event_code;
	switch (event_code) {
	case KEV_DL_LINK_OFF:
	case KEV_DL_LINK_ON:
		vlan_parent_link_event(p, event_code);
		break;
	default:
		return;
	}
	return;
}

static errno_t
vlan_detached(ifnet_t p, __unused protocol_family_t protocol)
{
	if (ifnet_is_attached(p, 0) == 0) {
		/* if the parent isn't attached, remove all VLANs */
		vlan_parent_remove_all_vlans(p);
	}
	return 0;
}

static void
interface_link_event(struct ifnet * ifp, u_int32_t event_code)
{
	struct event {
		u_int32_t ifnet_family;
		u_int32_t unit;
		char if_name[IFNAMSIZ];
	};
	_Alignas(struct kern_event_msg) char message[sizeof(struct kern_event_msg) + sizeof(struct event)] = { 0 };
	struct kern_event_msg *header = (struct kern_event_msg*)message;

	struct event *data = (struct event *)(message + KEV_MSG_HEADER_SIZE);

	header->total_size   = sizeof(message);
	header->vendor_code  = KEV_VENDOR_APPLE;
	header->kev_class    = KEV_NETWORK_CLASS;
	header->kev_subclass = KEV_DL_SUBCLASS;
	header->event_code   = event_code;
	data->ifnet_family   = ifnet_family(ifp);
	data->unit           = (u_int32_t)ifnet_unit(ifp);
	strlcpy(data->if_name, ifnet_name(ifp), sizeof(data->if_name));
	ifnet_event(ifp, header);
}

static void
vlan_parent_link_event(struct ifnet * p, u_int32_t event_code)
{
	vlan_parent_ref     vlp;

	vlan_lock();
	if ((ifnet_eflags(p) & IFEF_VLAN) == 0) {
		vlan_unlock();
		/* no VLAN's */
		return;
	}
	vlp = parent_list_lookup(p);
	if (vlp == NULL) {
		/* no VLAN's */
		vlan_unlock();
		return;
	}
	vlan_parent_flags_set(vlp, VLPF_LINK_EVENT_REQUIRED);
	vlp->vlp_event_code = event_code;

	if (vlan_parent_flags_are_set(vlp, VLPF_CHANGE_IN_PROGRESS)) {
		/* don't block waiting to generate an event */
		vlan_unlock();
		return;
	}
	vlan_parent_retain(vlp);
	VLAN_PARENT_WAIT(vlp);
	/* vlan_parent_signal() generates the link event */
	VLAN_PARENT_SIGNAL(vlp);
	vlan_unlock();
	vlan_parent_release(vlp);
	return;
}

/*
 * Function: vlan_attach_protocol
 * Purpose:
 *   Attach a DLIL protocol to the interface, using the ETHERTYPE_VLAN
 *   demux ether type.
 *
 *	 The ethernet demux actually special cases VLAN to support hardware.
 *	 The demux here isn't used. The demux will return PF_VLAN for the
 *	 appropriate packets and our vlan_input function will be called.
 */
static int
vlan_attach_protocol(struct ifnet *ifp)
{
	int                                 error;
	struct ifnet_attach_proto_param_v2  reg;

	bzero(&reg, sizeof(reg));
	reg.input            = vlan_input;
	reg.event            = vlan_event;
	reg.detached         = vlan_detached;
	error = ifnet_attach_protocol_v2(ifp, PF_VLAN, &reg);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, VL_DBGF_LIFECYCLE,
		    "%s: ifnet_attach_protocol failed, %d",
		    ifp->if_xname, error);
	}
	return error;
}

/*
 * Function: vlan_detach_protocol
 * Purpose:
 *   Detach our DLIL protocol from an interface
 */
static int
vlan_detach_protocol(struct ifnet *ifp)
{
	int         error;

	error = ifnet_detach_protocol(ifp, PF_VLAN);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, VL_DBGF_LIFECYCLE,
		    "%s: ifnet_detach_protocol failed, %d",
		    ifp->if_xname, error);
	}
	return error;
}

/*
 * DLIL interface family functions
 *   We use the ethernet plumb functions, since that's all we support.
 *   If we wanted to handle multiple LAN types (tokenring, etc.), we'd
 *   call the appropriate routines for that LAN type instead of hard-coding
 *   ethernet.
 */
static errno_t
vlan_attach_inet(struct ifnet *ifp, protocol_family_t protocol_family)
{
	return ether_attach_inet(ifp, protocol_family);
}

static void
vlan_detach_inet(struct ifnet *ifp, protocol_family_t protocol_family)
{
	ether_detach_inet(ifp, protocol_family);
}

static errno_t
vlan_attach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
	return ether_attach_inet6(ifp, protocol_family);
}

static void
vlan_detach_inet6(struct ifnet *ifp, protocol_family_t protocol_family)
{
	ether_detach_inet6(ifp, protocol_family);
}

__private_extern__ int
vlan_family_init(void)
{
	int error = 0;

#if !XNU_TARGET_OS_OSX
#if (DEVELOPMENT || DEBUG)
	/* check whether "vlan" boot-arg is enabled */
	(void)PE_parse_boot_argn("vlan", &vlan_enabled, sizeof(vlan_enabled));
#endif /* DEVELOPMENT || DEBUG */
#endif /* !XNU_TARGET_OS_OSX */

	error = proto_register_plumber(PF_INET, IFNET_FAMILY_VLAN,
	    vlan_attach_inet, vlan_detach_inet);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, 0,
		    "proto_register_plumber failed for AF_INET error=%d",
		    error);
		goto done;
	}
	error = proto_register_plumber(PF_INET6, IFNET_FAMILY_VLAN,
	    vlan_attach_inet6, vlan_detach_inet6);
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, 0,
		    "proto_register_plumber failed for AF_INET6 error=%d",
		    error);
		goto done;
	}
	error = vlan_clone_attach();
	if (error != 0) {
		VLAN_LOG(LOG_NOTICE, 0,
		    "proto_register_plumber failed vlan_clone_attach error=%d",
		    error);
		goto done;
	}


done:
	return error;
}
