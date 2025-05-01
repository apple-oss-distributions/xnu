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

#include "net/if_var.h"
#include <net/dlil_var_private.h>


LCK_ATTR_DECLARE(dlil_lck_attributes, 0, 0);

LCK_GRP_DECLARE(dlil_lock_group, "DLIL internal locks");
LCK_GRP_DECLARE(ifnet_lock_group, "ifnet locks");
LCK_GRP_DECLARE(ifnet_head_lock_group, "ifnet head lock");
LCK_GRP_DECLARE(ifnet_snd_lock_group, "ifnet snd locks");
LCK_GRP_DECLARE(ifnet_rcv_lock_group, "ifnet rcv locks");

LCK_ATTR_DECLARE(ifnet_lock_attr, 0, 0);
LCK_RW_DECLARE_ATTR(ifnet_head_lock, &ifnet_head_lock_group,
    &dlil_lck_attributes);
LCK_MTX_DECLARE_ATTR(dlil_ifnet_lock, &dlil_lock_group,
    &dlil_lck_attributes);


LCK_MTX_DECLARE_ATTR(dlil_thread_sync_lock, &dlil_lock_group,
    &dlil_lck_attributes);

uint32_t dlil_pending_thread_cnt = 0;


/*
 * Forward declarations.
 */
__private_extern__ void link_rtrequest(int, struct rtentry *, struct sockaddr *);
__private_extern__ void if_rtproto_del(struct ifnet *ifp, int protocol);


/*
 * Allocation zones
 */
unsigned int dlif_size;          /* size of dlil_ifnet to allocate */
unsigned int dlif_bufsize;       /* size of dlif_size + headroom */
ZONE_DECLARE(dlif_zone, struct dlil_ifnet);
#define DLIF_ZONE_NAME          "ifnet" /* zone name */
zone_t dlif_zone;                       /* zone for dlil_ifnet */

unsigned int dlif_tcpstat_size;  /* size of tcpstat_local to allocate */
unsigned int dlif_tcpstat_bufsize; /* size of dlif_tcpstat_size + headroom */
ZONE_DECLARE(dlif_tcpstat_zone, struct ifnet_tcpstat);
#define DLIF_TCPSTAT_ZONE_NAME  "ifnet_tcpstat" /* zone name */
zone_t dlif_tcpstat_zone;                       /* zone for tcpstat_local */

unsigned int dlif_udpstat_size;  /* size of udpstat_local to allocate */
unsigned int dlif_udpstat_bufsize;       /* size of dlif_udpstat_size + headroom */
ZONE_DECLARE(dlif_udpstat_zone, struct ifnet_udpstat);
#define DLIF_UDPSTAT_ZONE_NAME  "ifnet_udpstat" /* zone name */
zone_t dlif_udpstat_zone;                       /* zone for udpstat_local */

KALLOC_TYPE_DEFINE(dlif_filt_zone, struct ifnet_filter, NET_KT_DEFAULT);

KALLOC_TYPE_DEFINE(dlif_proto_zone, struct if_proto, NET_KT_DEFAULT);

/*
 * Utility routines
 */
kern_return_t
dlil_affinity_set(struct thread *tp, u_int32_t tag)
{
	thread_affinity_policy_data_t policy;

	bzero(&policy, sizeof(policy));
	policy.affinity_tag = tag;
	return thread_policy_set(tp, THREAD_AFFINITY_POLICY,
	           (thread_policy_t)&policy, THREAD_AFFINITY_POLICY_COUNT);
}

void
dlil_incr_pending_thread_count(void)
{
	LCK_MTX_ASSERT(&dlil_thread_sync_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(&dlil_thread_sync_lock);
	dlil_pending_thread_cnt++;
	lck_mtx_unlock(&dlil_thread_sync_lock);
}

void
dlil_decr_pending_thread_count(void)
{
	LCK_MTX_ASSERT(&dlil_thread_sync_lock, LCK_MTX_ASSERT_NOTOWNED);
	lck_mtx_lock(&dlil_thread_sync_lock);
	VERIFY(dlil_pending_thread_cnt > 0);
	dlil_pending_thread_cnt--;
	if (dlil_pending_thread_cnt == 0) {
		wakeup(&dlil_pending_thread_cnt);
	}
	lck_mtx_unlock(&dlil_thread_sync_lock);
}

boolean_t
packet_has_vlan_tag(struct mbuf * m)
{
	u_int   tag = 0;

	if ((m->m_pkthdr.csum_flags & CSUM_VLAN_TAG_VALID) != 0) {
		tag = EVL_VLANOFTAG(m->m_pkthdr.vlan_tag);
		if (tag == 0) {
			/* the packet is just priority-tagged, clear the bit */
			m->m_pkthdr.csum_flags &= ~CSUM_VLAN_TAG_VALID;
		}
	}
	return tag != 0;
}

void
log_hexdump(void *__sized_by(len) data, size_t len)
{
	size_t i, j, k;
	unsigned char *ptr = (unsigned char *)data;
#define MAX_DUMP_BUF 32
	unsigned char buf[3 * MAX_DUMP_BUF + 1];

	for (i = 0; i < len; i += MAX_DUMP_BUF) {
		for (j = i, k = 0; j < i + MAX_DUMP_BUF && j < len; j++) {
			unsigned char msnbl = ptr[j] >> 4;
			unsigned char lsnbl = ptr[j] & 0x0f;

			buf[k++] = msnbl < 10 ? msnbl + '0' : msnbl + 'a' - 10;
			buf[k++] = lsnbl < 10 ? lsnbl + '0' : lsnbl + 'a' - 10;

			if ((j % 2) == 1) {
				buf[k++] = ' ';
			}
			if ((j % MAX_DUMP_BUF) == MAX_DUMP_BUF - 1) {
				buf[k++] = ' ';
			}
		}
		buf[k] = 0;
		os_log(OS_LOG_DEFAULT, "%3lu: %s", i, buf);
	}
}

/*
 * Monitor functions.
 */
void
if_flt_monitor_busy(struct ifnet *ifp)
{
	LCK_MTX_ASSERT(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	++ifp->if_flt_busy;
	VERIFY(ifp->if_flt_busy != 0);
}

void
if_flt_monitor_unbusy(struct ifnet *ifp)
{
	if_flt_monitor_leave(ifp);
}

void
if_flt_monitor_enter(struct ifnet *ifp)
{
	LCK_MTX_ASSERT(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	while (ifp->if_flt_busy) {
		++ifp->if_flt_waiters;
		(void) msleep(&ifp->if_flt_head, &ifp->if_flt_lock,
		    (PZERO - 1), "if_flt_monitor", NULL);
	}
	if_flt_monitor_busy(ifp);
}

void
if_flt_monitor_leave(struct ifnet *ifp)
{
	LCK_MTX_ASSERT(&ifp->if_flt_lock, LCK_MTX_ASSERT_OWNED);

	VERIFY(ifp->if_flt_busy != 0);
	--ifp->if_flt_busy;

	if (ifp->if_flt_busy == 0 && ifp->if_flt_waiters > 0) {
		ifp->if_flt_waiters = 0;
		wakeup(&ifp->if_flt_head);
	}
}

/*
 * Allocation routines
 */
void
dlil_allocation_zones_init(void)
{
	dlif_size = (ifnet_debug == 0) ? sizeof(struct dlil_ifnet) :
	    sizeof(struct dlil_ifnet_dbg);
	/* Enforce 64-bit alignment for dlil_ifnet structure */
	dlif_bufsize = dlif_size + sizeof(void *) + sizeof(u_int64_t);
	dlif_bufsize = (uint32_t)P2ROUNDUP(dlif_bufsize, sizeof(u_int64_t));
	dlif_zone = zone_create(DLIF_ZONE_NAME, dlif_bufsize, ZC_ZFREE_CLEARMEM);

	dlif_tcpstat_size = sizeof(struct tcpstat_local);
	/* Enforce 64-bit alignment for tcpstat_local structure */
	dlif_tcpstat_bufsize =
	    dlif_tcpstat_size + sizeof(void *) + sizeof(u_int64_t);
	dlif_tcpstat_bufsize = (uint32_t)
	    P2ROUNDUP(dlif_tcpstat_bufsize, sizeof(u_int64_t));
	dlif_tcpstat_zone = zone_create(DLIF_TCPSTAT_ZONE_NAME,
	    dlif_tcpstat_bufsize, ZC_ZFREE_CLEARMEM);

	dlif_udpstat_size = sizeof(struct udpstat_local);
	/* Enforce 64-bit alignment for udpstat_local structure */
	dlif_udpstat_bufsize =
	    dlif_udpstat_size + sizeof(void *) + sizeof(u_int64_t);
	dlif_udpstat_bufsize = (uint32_t)
	    P2ROUNDUP(dlif_udpstat_bufsize, sizeof(u_int64_t));
	dlif_udpstat_zone = zone_create(DLIF_UDPSTAT_ZONE_NAME,
	    dlif_udpstat_bufsize, ZC_ZFREE_CLEARMEM);
}

static void
_dlil_alloc_aligned_object(struct zone *zone,
    size_t buffer_size, void *__indexable *__single pbuffer,
    size_t object_size, void *__indexable *__single pobject)
{
	void *base, *buf, **pbuf;

	void *__unsafe_indexable addr = __zalloc_flags(zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	__builtin_assume(addr != NULL);
	buf = __unsafe_forge_bidi_indexable(void*, addr, buffer_size);

	/* Get the 64-bit aligned base address for this object */
	base = (void*)((char*)buf + (P2ROUNDUP((intptr_t)buf + sizeof(u_int64_t), sizeof(u_int64_t)) - (intptr_t)buf));
	VERIFY(((intptr_t)base + object_size) <=
	    ((intptr_t)buf + buffer_size));

	/*
	 * Wind back a pointer size from the aligned base and
	 * save the original address so we can free it later.
	 */
	pbuf = __unsafe_forge_bidi_indexable(void**, (intptr_t)base - sizeof(void *), sizeof(void *));
	*pbuf = buf;
	*pbuffer = buf;
	*pobject = base;
}

static void
_dlil_free_aligned_object(struct zone *zone, void *pobject)
{
	if (pobject != NULL) {
		void *__single *pbuf;
		pbuf = __unsafe_forge_single(void**, ((intptr_t)pobject - sizeof(void*)));
		zfree(zone, *pbuf);
	}
}

struct dlil_ifnet *
dlif_ifnet_alloc(void)
{
	void *__indexable base, *__indexable buf;
	_dlil_alloc_aligned_object(dlif_zone,
	    dlif_bufsize, &buf,
	    dlif_size, &base);

	return base;
}

void
dlif_ifnet_free(struct dlil_ifnet *ifnet)
{
	_dlil_free_aligned_object(dlif_zone, ifnet);
}

struct ifnet_filter *
dlif_filt_alloc(void)
{
	return zalloc_flags(dlif_filt_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
}

void
dlif_filt_free(struct ifnet_filter *filt)
{
	if (filt != NULL) {
		zfree(dlif_filt_zone, filt);
	}
}

struct if_proto *
dlif_proto_alloc(void)
{
	return zalloc_flags(dlif_proto_zone, Z_WAITOK | Z_ZERO | Z_NOFAIL);
}

void
dlif_proto_free(struct if_proto *ifproto)
{
	if (ifproto != NULL) {
		zfree(dlif_proto_zone, ifproto);
	}
}

struct tcpstat_local *
dlif_tcpstat_alloc(void)
{
	void *__indexable base, *__indexable buf;
	_dlil_alloc_aligned_object(dlif_tcpstat_zone,
	    dlif_tcpstat_bufsize, &buf,
	    dlif_tcpstat_size, &base);
	return base;
}

void
dlif_tcpstat_free(struct tcpstat_local *if_tcp_stat)
{
	_dlil_free_aligned_object(dlif_tcpstat_zone, if_tcp_stat);
}

struct udpstat_local *
dlif_udpstat_alloc(void)
{
	void *__indexable base, *__indexable buf;
	_dlil_alloc_aligned_object(dlif_udpstat_zone,
	    dlif_udpstat_bufsize, &buf,
	    dlif_udpstat_size, &base);
	return base;
}

void
dlif_udpstat_free(struct udpstat_local *if_udp_stat)
{
	_dlil_free_aligned_object(dlif_tcpstat_zone, if_udp_stat);
}

struct ifaddr *
dlil_alloc_lladdr(struct ifnet *ifp, const struct sockaddr_dl *ll_addr)
{
	struct ifaddr *ifa, *oifa = NULL;
	struct sockaddr_dl *addr_sdl, *mask_sdl;
	char workbuf[IFNAMSIZ * 2];
	int namelen, masklen, socksize;
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_EXCLUSIVE);
	VERIFY(ll_addr == NULL || ll_addr->sdl_alen == ifp->if_addrlen);

	namelen = scnprintf(workbuf, sizeof(workbuf), "%s",
	    if_name(ifp));
	masklen = offsetof(struct sockaddr_dl, sdl_data[0])
	    + ((namelen > 0) ? namelen : 0);
	socksize = masklen + ifp->if_addrlen;
#define ROUNDUP(a) (1 + (((a) - 1) | (sizeof (u_int32_t) - 1)))
	if ((u_int32_t)socksize < sizeof(struct sockaddr_dl)) {
		socksize = sizeof(struct sockaddr_dl);
	}
	socksize = ROUNDUP(socksize);
#undef ROUNDUP

	ifa = ifp->if_lladdr;
	if (socksize > DLIL_SDLMAXLEN ||
	    (ifa != NULL && ifa != &dl_if->dl_if_lladdr.ifa)) {
		/*
		 * Rare, but in the event that the link address requires
		 * more storage space than DLIL_SDLMAXLEN, allocate the
		 * largest possible storages for address and mask, such
		 * that we can reuse the same space when if_addrlen grows.
		 * This same space will be used when if_addrlen shrinks.
		 */
		struct dl_if_lladdr_xtra_space *__single dl_if_lladdr_ext;

		if (ifa == NULL || ifa == &dl_if->dl_if_lladdr.ifa) {
			dl_if_lladdr_ext = zalloc_permanent(
				sizeof(*dl_if_lladdr_ext), ZALIGN(struct ifaddr));

			ifa = &dl_if_lladdr_ext->ifa;
			ifa_lock_init(ifa);
			ifa_initref(ifa);
			/* Don't set IFD_ALLOC, as this is permanent */
			ifa->ifa_debug = IFD_LINK;
		} else {
			dl_if_lladdr_ext = __unsafe_forge_single(
				struct dl_if_lladdr_xtra_space*, ifa);
			ifa = &dl_if_lladdr_ext->ifa;
		}

		IFA_LOCK(ifa);
		/* address and mask sockaddr_dl locations */
		bzero(dl_if_lladdr_ext->addr_sdl_bytes,
		    sizeof(dl_if_lladdr_ext->addr_sdl_bytes));
		bzero(dl_if_lladdr_ext->mask_sdl_bytes,
		    sizeof(dl_if_lladdr_ext->mask_sdl_bytes));
		addr_sdl = SDL(dl_if_lladdr_ext->addr_sdl_bytes);
		mask_sdl = SDL(dl_if_lladdr_ext->mask_sdl_bytes);
	} else {
		VERIFY(ifa == NULL || ifa == &dl_if->dl_if_lladdr.ifa);
		/*
		 * Use the storage areas for address and mask within the
		 * dlil_ifnet structure.  This is the most common case.
		 */
		if (ifa == NULL) {
			ifa = &dl_if->dl_if_lladdr.ifa;
			ifa_lock_init(ifa);
			ifa_initref(ifa);
			/* Don't set IFD_ALLOC, as this is permanent */
			ifa->ifa_debug = IFD_LINK;
		}
		IFA_LOCK(ifa);
		/* address and mask sockaddr_dl locations */
		bzero(dl_if->dl_if_lladdr.addr_sdl_bytes,
		    sizeof(dl_if->dl_if_lladdr.addr_sdl_bytes));
		bzero(dl_if->dl_if_lladdr.mask_sdl_bytes,
		    sizeof(dl_if->dl_if_lladdr.mask_sdl_bytes));
		addr_sdl = SDL(dl_if->dl_if_lladdr.addr_sdl_bytes);
		mask_sdl = SDL(dl_if->dl_if_lladdr.mask_sdl_bytes);
	}

	if (ifp->if_lladdr != ifa) {
		oifa = ifp->if_lladdr;
		ifp->if_lladdr = ifa;
	}

	VERIFY(ifa->ifa_debug == IFD_LINK);
	ifa->ifa_ifp = ifp;
	ifa->ifa_rtrequest = link_rtrequest;
	ifa->ifa_addr = SA(addr_sdl);
	addr_sdl->sdl_len = (u_char)socksize;
	addr_sdl->sdl_family = AF_LINK;
	if (namelen > 0) {
		bcopy(workbuf, addr_sdl->sdl_data, min(namelen,
		    sizeof(addr_sdl->sdl_data)));
		addr_sdl->sdl_nlen = (u_char)namelen;
	} else {
		addr_sdl->sdl_nlen = 0;
	}
	addr_sdl->sdl_index = ifp->if_index;
	addr_sdl->sdl_type = ifp->if_type;
	if (ll_addr != NULL) {
		addr_sdl->sdl_alen = ll_addr->sdl_alen;
		bcopy(CONST_LLADDR(ll_addr), LLADDR(addr_sdl), addr_sdl->sdl_alen);
	} else {
		addr_sdl->sdl_alen = 0;
	}
	ifa->ifa_netmask = SA(mask_sdl);
	mask_sdl->sdl_len = (u_char)masklen;
	while (namelen > 0) {
		mask_sdl->sdl_data[--namelen] = 0xff;
	}
	IFA_UNLOCK(ifa);

	if (oifa != NULL) {
		ifa_remref(oifa);
	}

	return ifa;
}


__private_extern__ int
dlil_alloc_local_stats(struct ifnet *ifp)
{
	int ret = EINVAL;

	if (ifp == NULL) {
		goto end;
	}

	if (ifp->if_tcp_stat == NULL && ifp->if_udp_stat == NULL) {
		ifp->if_tcp_stat = dlif_tcpstat_alloc();
		ifp->if_udp_stat = dlif_udpstat_alloc();

		VERIFY(IS_P2ALIGNED(ifp->if_tcp_stat, sizeof(u_int64_t)) &&
		    IS_P2ALIGNED(ifp->if_udp_stat, sizeof(u_int64_t)));

		ret = 0;
	}

	if (ifp->if_ipv4_stat == NULL) {
		ifp->if_ipv4_stat = kalloc_type(struct if_tcp_ecn_stat, Z_WAITOK | Z_ZERO);
	}

	if (ifp->if_ipv6_stat == NULL) {
		ifp->if_ipv6_stat = kalloc_type(struct if_tcp_ecn_stat, Z_WAITOK | Z_ZERO);
	}
end:
	if (ifp != NULL && ret != 0) {
		if (ifp->if_tcp_stat != NULL) {
			dlif_tcpstat_free(ifp->if_tcp_stat);
			ifp->if_tcp_stat = NULL;
		}
		if (ifp->if_udp_stat != NULL) {
			dlif_udpstat_free(ifp->if_udp_stat);
			ifp->if_udp_stat = NULL;
		}
		/* The macro kfree_type sets the passed pointer to NULL */
		if (ifp->if_ipv4_stat != NULL) {
			kfree_type(struct if_tcp_ecn_stat, ifp->if_ipv4_stat);
		}
		if (ifp->if_ipv6_stat != NULL) {
			kfree_type(struct if_tcp_ecn_stat, ifp->if_ipv6_stat);
		}
	}

	return ret;
}

errno_t
dlil_if_ref(struct ifnet *ifp)
{
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;

	if (dl_if == NULL) {
		return EINVAL;
	}

	lck_mtx_lock_spin(&dl_if->dl_if_lock);
	++dl_if->dl_if_refcnt;
	if (dl_if->dl_if_refcnt == 0) {
		panic("%s: wraparound refcnt for ifp=%p", __func__, ifp);
		/* NOTREACHED */
	}
	if (dl_if->dl_if_trace != NULL) {
		(*dl_if->dl_if_trace)(dl_if, TRUE);
	}
	lck_mtx_unlock(&dl_if->dl_if_lock);

	return 0;
}

errno_t
dlil_if_free(struct ifnet *ifp)
{
	struct dlil_ifnet *dl_if = (struct dlil_ifnet *)ifp;
	bool need_release = FALSE;

	if (dl_if == NULL) {
		return EINVAL;
	}

	lck_mtx_lock_spin(&dl_if->dl_if_lock);
	switch (dl_if->dl_if_refcnt) {
	case 0:
		panic("%s: negative refcnt for ifp=%p", __func__, ifp);
		/* NOTREACHED */
		break;
	case 1:
		if ((ifp->if_refflags & IFRF_EMBRYONIC) != 0) {
			need_release = TRUE;
		}
		break;
	default:
		break;
	}
	--dl_if->dl_if_refcnt;
	if (dl_if->dl_if_trace != NULL) {
		(*dl_if->dl_if_trace)(dl_if, FALSE);
	}
	lck_mtx_unlock(&dl_if->dl_if_lock);
	if (need_release) {
		_dlil_if_release(ifp, true);
	}
	return 0;
}

void
_dlil_if_release(ifnet_t ifp, bool clear_in_use)
{
	struct dlil_ifnet *dlifp = (struct dlil_ifnet *)ifp;

	VERIFY(OSDecrementAtomic64(&net_api_stats.nas_ifnet_alloc_count) > 0);
	if (!(ifp->if_xflags & IFXF_ALLOC_KPI)) {
		VERIFY(OSDecrementAtomic64(&net_api_stats.nas_ifnet_alloc_os_count) > 0);
	}

	ifnet_lock_exclusive(ifp);
	kfree_data_counted_by(ifp->if_broadcast.ptr, ifp->if_broadcast.length);
	lck_mtx_lock(&dlifp->dl_if_lock);
	/* Copy the if name to the dedicated storage */
	ifp->if_name = tsnprintf(dlifp->dl_if_namestorage, sizeof(dlifp->dl_if_namestorage),
	    "%s", ifp->if_name);
	/* Reset external name (name + unit) */
	ifp->if_xname = tsnprintf(dlifp->dl_if_xnamestorage, sizeof(dlifp->dl_if_xnamestorage),
	    "%s?", ifp->if_name);
	if (clear_in_use) {
		ASSERT((dlifp->dl_if_flags & DLIF_INUSE) != 0);
		dlifp->dl_if_flags &= ~DLIF_INUSE;
	}
	lck_mtx_unlock(&dlifp->dl_if_lock);
	ifnet_lock_done(ifp);
}

__private_extern__ void
dlil_if_release(ifnet_t ifp)
{
	_dlil_if_release(ifp, false);
}

void
if_proto_ref(struct if_proto *proto)
{
	os_atomic_inc(&proto->refcount, relaxed);
}

void
if_proto_free(struct if_proto *proto)
{
	u_int32_t oldval;
	struct ifnet *ifp = proto->ifp;
	u_int32_t proto_family = proto->protocol_family;
	struct kev_dl_proto_data ev_pr_data;

	oldval = os_atomic_dec_orig(&proto->refcount, relaxed);
	if (oldval > 1) {
		return;
	}

	if (proto->proto_kpi == kProtoKPI_v1) {
		if (proto->kpi.v1.detached) {
			proto->kpi.v1.detached(ifp, proto->protocol_family);
		}
	}
	if (proto->proto_kpi == kProtoKPI_v2) {
		if (proto->kpi.v2.detached) {
			proto->kpi.v2.detached(ifp, proto->protocol_family);
		}
	}

	/*
	 * Cleanup routes that may still be in the routing table for that
	 * interface/protocol pair.
	 */
	if_rtproto_del(ifp, proto_family);

	ifnet_lock_shared(ifp);

	/* No more reference on this, protocol must have been detached */
	VERIFY(proto->detached);

	/*
	 * The reserved field carries the number of protocol still attached
	 * (subject to change)
	 */
	ev_pr_data.proto_family = proto_family;
	ev_pr_data.proto_remaining_count = dlil_ifp_protolist(ifp, NULL, 0);

	ifnet_lock_done(ifp);

	dlil_post_msg(ifp, KEV_DL_SUBCLASS, KEV_DL_PROTO_DETACHED,
	    (struct net_event_data *)&ev_pr_data,
	    sizeof(struct kev_dl_proto_data), FALSE);

	if (ev_pr_data.proto_remaining_count == 0) {
		/*
		 * The protocol count has gone to zero, mark the interface down.
		 * This used to be done by configd.KernelEventMonitor, but that
		 * is inherently prone to races (rdar://problem/30810208).
		 */
		(void) ifnet_set_flags(ifp, 0, IFF_UP);
		(void) ifnet_ioctl(ifp, 0, SIOCSIFFLAGS, NULL);
		dlil_post_sifflags_msg(ifp);
	}

	dlif_proto_free(proto);
}

__private_extern__ u_int32_t
dlil_ifp_protolist(struct ifnet *ifp, protocol_family_t *list __counted_by(list_count),
    u_int32_t list_count)
{
	u_int32_t       count = 0;
	int             i;

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	if (ifp->if_proto_hash == NULL) {
		goto done;
	}

	for (i = 0; i < PROTO_HASH_SLOTS; i++) {
		if_proto_ref_t proto;
		SLIST_FOREACH(proto, &ifp->if_proto_hash[i], next_hash) {
			if (list != NULL && count < list_count) {
				list[count] = proto->protocol_family;
			}
			count++;
		}
	}
done:
	return count;
}

__private_extern__ u_int32_t
if_get_protolist(struct ifnet * ifp, u_int32_t *__counted_by(count) protolist, u_int32_t count)
{
	u_int32_t actual_count;
	ifnet_lock_shared(ifp);
	actual_count = dlil_ifp_protolist(ifp, protolist, count);
	ifnet_lock_done(ifp);
	return actual_count;
}

__private_extern__ void
if_free_protolist(u_int32_t *list)
{
	kfree_data_addr(list);
}

boolean_t
dlil_is_native_netif_nexus(ifnet_t ifp)
{
	return (ifp->if_eflags & IFEF_SKYWALK_NATIVE) && ifp->if_na != NULL;
}


/*
 * Caller must already be holding ifnet lock.
 */
struct if_proto *
find_attached_proto(struct ifnet *ifp, u_int32_t protocol_family)
{
	struct if_proto *proto = NULL;
	u_int32_t i = proto_hash_value(protocol_family);

	ifnet_lock_assert(ifp, IFNET_LCK_ASSERT_OWNED);

	if (ifp->if_proto_hash != NULL) {
		proto = SLIST_FIRST(&ifp->if_proto_hash[i]);
	}

	while (proto != NULL && proto->protocol_family != protocol_family) {
		proto = SLIST_NEXT(proto, next_hash);
	}

	if (proto != NULL) {
		if_proto_ref(proto);
	}

	return proto;
}

/*
 * Clat routines.
 */

/*
 * This routine checks if the destination address is not a loopback, link-local,
 * multicast or broadcast address.
 */
int
dlil_is_clat_needed(protocol_family_t proto_family, mbuf_t m)
{
	int ret = 0;
	switch (proto_family) {
	case PF_INET: {
		struct ip *iph = mtod(m, struct ip *);
		if (CLAT46_NEEDED(ntohl(iph->ip_dst.s_addr))) {
			ret = 1;
		}
		break;
	}
	case PF_INET6: {
		struct ip6_hdr *ip6h = mtod(m, struct ip6_hdr *);
		if ((size_t)m_pktlen(m) >= sizeof(struct ip6_hdr) &&
		    CLAT64_NEEDED(&ip6h->ip6_dst)) {
			ret = 1;
		}
		break;
	}
	}

	return ret;
}

/*
 * @brief This routine translates IPv4 packet to IPv6 packet,
 *     updates protocol checksum and also translates ICMP for code
 *     along with inner header translation.
 *
 * @param ifp Pointer to the interface
 * @param proto_family pointer to protocol family. It is updated if function
 *     performs the translation successfully.
 * @param m Pointer to the pointer pointing to the packet. Needed because this
 *     routine can end up changing the mbuf to a different one.
 *
 * @return 0 on success or else a negative value.
 */
errno_t
dlil_clat46(ifnet_t ifp, protocol_family_t *proto_family, mbuf_t *m)
{
	VERIFY(*proto_family == PF_INET);
	VERIFY(IS_INTF_CLAT46(ifp));

	pbuf_t pbuf_store, *pbuf = NULL;
	struct ip *iph = NULL;
	struct in_addr osrc, odst;
	uint8_t proto = 0;
	struct in6_addr src_storage = {};
	struct in6_addr *src = NULL;
	struct sockaddr_in6 dstsock = {};
	int error = 0;
	uint16_t off = 0;
	uint16_t tot_len = 0;
	uint16_t ip_id_val = 0;
	uint16_t ip_frag_off = 0;

	boolean_t is_frag = FALSE;
	boolean_t is_first_frag = TRUE;
	boolean_t is_last_frag = TRUE;

	pbuf_init_mbuf(&pbuf_store, *m, ifp);
	pbuf = &pbuf_store;
	iph = pbuf->pb_data;

	osrc = iph->ip_src;
	odst = iph->ip_dst;
	proto = iph->ip_p;
	off = (uint16_t)(iph->ip_hl << 2);
	ip_id_val = iph->ip_id;
	ip_frag_off = ntohs(iph->ip_off) & IP_OFFMASK;

	tot_len = ntohs(iph->ip_len);

	/*
	 * For packets that are not first frags
	 * we only need to adjust CSUM.
	 * For 4 to 6, Fragmentation header gets appended
	 * after proto translation.
	 */
	if (ntohs(iph->ip_off) & ~(IP_DF | IP_RF)) {
		is_frag = TRUE;

		/* If the offset is not zero, it is not first frag */
		if (ip_frag_off != 0) {
			is_first_frag = FALSE;
		}

		/* If IP_MF is set, then it is not last frag */
		if (ntohs(iph->ip_off) & IP_MF) {
			is_last_frag = FALSE;
		}
	}

	/*
	 * Translate IPv4 destination to IPv6 destination by using the
	 * prefixes learned through prior PLAT discovery.
	 */
	if ((error = nat464_synthesize_ipv6(ifp, &odst, &dstsock.sin6_addr)) != 0) {
		ip6stat.ip6s_clat464_out_v6synthfail_drop++;
		goto cleanup;
	}

	dstsock.sin6_len = sizeof(struct sockaddr_in6);
	dstsock.sin6_family = AF_INET6;

	/*
	 * Retrive the local IPv6 CLAT46 address reserved for stateless
	 * translation.
	 */
	src = in6_selectsrc_core(&dstsock, 0, ifp, 0, &src_storage, NULL, &error,
	    NULL, NULL, TRUE);

	if (src == NULL) {
		ip6stat.ip6s_clat464_out_nov6addr_drop++;
		error = -1;
		goto cleanup;
	}


	/* Translate the IP header part first */
	error = (nat464_translate_46(pbuf, off, iph->ip_tos, iph->ip_p,
	    iph->ip_ttl, src_storage, dstsock.sin6_addr, tot_len) == NT_NAT64) ? 0 : -1;

	iph = NULL;     /* Invalidate iph as pbuf has been modified */

	if (error != 0) {
		ip6stat.ip6s_clat464_out_46transfail_drop++;
		goto cleanup;
	}

	/*
	 * Translate protocol header, update checksum, checksum flags
	 * and related fields.
	 */
	error = (nat464_translate_proto(pbuf, (struct nat464_addr *)&osrc, (struct nat464_addr *)&odst,
	    proto, PF_INET, PF_INET6, NT_OUT, !is_first_frag) == NT_NAT64) ? 0 : -1;

	if (error != 0) {
		ip6stat.ip6s_clat464_out_46proto_transfail_drop++;
		goto cleanup;
	}

	/* Now insert the IPv6 fragment header */
	if (is_frag) {
		error = nat464_insert_frag46(pbuf, ip_id_val, ip_frag_off, is_last_frag);

		if (error != 0) {
			ip6stat.ip6s_clat464_out_46frag_transfail_drop++;
			goto cleanup;
		}
	}

cleanup:
	if (pbuf_is_valid(pbuf)) {
		*m = pbuf->pb_mbuf;
		pbuf->pb_mbuf = NULL;
		pbuf_destroy(pbuf);
	} else {
		error = -1;
		*m = NULL;
		ip6stat.ip6s_clat464_out_invalpbuf_drop++;
	}

	if (error == 0) {
		*proto_family = PF_INET6;
		ip6stat.ip6s_clat464_out_success++;
	}

	return error;
}

/*
 * @brief This routine translates incoming IPv6 to IPv4 packet,
 *     updates protocol checksum and also translates ICMPv6 outer
 *     and inner headers
 *
 * @return 0 on success or else a negative value.
 */
errno_t
dlil_clat64(ifnet_t ifp, protocol_family_t *proto_family, mbuf_t *m)
{
	VERIFY(*proto_family == PF_INET6);
	VERIFY(IS_INTF_CLAT46(ifp));

	struct ip6_hdr *ip6h = NULL;
	struct in6_addr osrc, odst;
	uint8_t proto = 0;
	struct in6_ifaddr *ia6_clat_dst = NULL;
	struct in_ifaddr *ia4_clat_dst = NULL;
	struct in_addr *dst = NULL;
	struct in_addr src;
	int error = 0;
	uint32_t off = 0;
	u_int64_t tot_len = 0;
	uint8_t tos = 0;
	boolean_t is_first_frag = TRUE;

	/* Incoming mbuf does not contain valid IP6 header */
	if ((size_t)(*m)->m_pkthdr.len < sizeof(struct ip6_hdr) ||
	    ((size_t)(*m)->m_len < sizeof(struct ip6_hdr) &&
	    (*m = m_pullup(*m, sizeof(struct ip6_hdr))) == NULL)) {
		ip6stat.ip6s_clat464_in_tooshort_drop++;
		return -1;
	}

	ip6h = mtod(*m, struct ip6_hdr *);
	/* Validate that mbuf contains IP payload equal to ip6_plen  */
	if ((size_t)(*m)->m_pkthdr.len < ntohs(ip6h->ip6_plen) + sizeof(struct ip6_hdr)) {
		ip6stat.ip6s_clat464_in_tooshort_drop++;
		return -1;
	}

	osrc = ip6h->ip6_src;
	odst = ip6h->ip6_dst;

	/*
	 * Retrieve the local CLAT46 reserved IPv6 address.
	 * Let the packet pass if we don't find one, as the flag
	 * may get set before IPv6 configuration has taken place.
	 */
	ia6_clat_dst = in6ifa_ifpwithflag(ifp, IN6_IFF_CLAT46);
	if (ia6_clat_dst == NULL) {
		goto done;
	}

	/*
	 * Check if the original dest in the packet is same as the reserved
	 * CLAT46 IPv6 address
	 */
	if (IN6_ARE_ADDR_EQUAL(&odst, &ia6_clat_dst->ia_addr.sin6_addr)) {
		pbuf_t pbuf_store, *pbuf = NULL;
		pbuf_init_mbuf(&pbuf_store, *m, ifp);
		pbuf = &pbuf_store;

		/*
		 * Retrive the local CLAT46 IPv4 address reserved for stateless
		 * translation.
		 */
		ia4_clat_dst = inifa_ifpclatv4(ifp);
		if (ia4_clat_dst == NULL) {
			ifa_remref(&ia6_clat_dst->ia_ifa);
			ip6stat.ip6s_clat464_in_nov4addr_drop++;
			error = -1;
			goto cleanup;
		}
		ifa_remref(&ia6_clat_dst->ia_ifa);

		/* Translate IPv6 src to IPv4 src by removing the NAT64 prefix */
		dst = &ia4_clat_dst->ia_addr.sin_addr;
		if ((error = nat464_synthesize_ipv4(ifp, &osrc, &src)) != 0) {
			ip6stat.ip6s_clat464_in_v4synthfail_drop++;
			error = -1;
			goto cleanup;
		}

		ip6h = pbuf->pb_data;
		off = sizeof(struct ip6_hdr);
		proto = ip6h->ip6_nxt;
		tos = (ntohl(ip6h->ip6_flow) >> 20) & 0xff;
		tot_len = ntohs(ip6h->ip6_plen) + sizeof(struct ip6_hdr);

		/*
		 * Translate the IP header and update the fragmentation
		 * header if needed
		 */
		error = (nat464_translate_64(pbuf, off, tos, &proto,
		    ip6h->ip6_hlim, src, *dst, tot_len, &is_first_frag) == NT_NAT64) ?
		    0 : -1;

		ip6h = NULL; /* Invalidate ip6h as pbuf has been changed */

		if (error != 0) {
			ip6stat.ip6s_clat464_in_64transfail_drop++;
			goto cleanup;
		}

		/*
		 * Translate protocol header, update checksum, checksum flags
		 * and related fields.
		 */
		error = (nat464_translate_proto(pbuf, (struct nat464_addr *)&osrc,
		    (struct nat464_addr *)&odst, proto, PF_INET6, PF_INET,
		    NT_IN, !is_first_frag) == NT_NAT64) ? 0 : -1;

		if (error != 0) {
			ip6stat.ip6s_clat464_in_64proto_transfail_drop++;
			goto cleanup;
		}

cleanup:
		if (ia4_clat_dst != NULL) {
			ifa_remref(&ia4_clat_dst->ia_ifa);
		}

		if (pbuf_is_valid(pbuf)) {
			*m = pbuf->pb_mbuf;
			pbuf->pb_mbuf = NULL;
			pbuf_destroy(pbuf);
		} else {
			error = -1;
			ip6stat.ip6s_clat464_in_invalpbuf_drop++;
		}

		if (error == 0) {
			*proto_family = PF_INET;
			ip6stat.ip6s_clat464_in_success++;
		}
	} /* CLAT traffic */

done:
	return error;
}

/*
 * Thread management
 */
void
dlil_clean_threading_info(struct dlil_threading_info *inp)
{
	lck_mtx_destroy(&inp->dlth_lock, inp->dlth_lock_grp);
	lck_grp_free(inp->dlth_lock_grp);
	inp->dlth_lock_grp = NULL;

	inp->dlth_flags = 0;
	inp->dlth_wtot = 0;
	bzero(inp->dlth_name_storage, sizeof(inp->dlth_name_storage));
	inp->dlth_name = NULL;
	inp->dlth_ifp = NULL;
	VERIFY(qhead(&inp->dlth_pkts) == NULL && qempty(&inp->dlth_pkts));
	qlimit(&inp->dlth_pkts) = 0;
	bzero(&inp->dlth_stats, sizeof(inp->dlth_stats));

	VERIFY(!inp->dlth_affinity);
	inp->dlth_thread = THREAD_NULL;
	inp->dlth_strategy = NULL;
	VERIFY(inp->dlth_driver_thread == THREAD_NULL);
	VERIFY(inp->dlth_poller_thread == THREAD_NULL);
	VERIFY(inp->dlth_affinity_tag == 0);
#if IFNET_INPUT_SANITY_CHK
	inp->dlth_pkts_cnt = 0;
#endif /* IFNET_INPUT_SANITY_CHK */
}

/*
 * Lock management
 */
static errno_t
_dlil_get_lock_assertion_type(ifnet_lock_assert_t what, unsigned int *type)
{
	switch (what) {
	case IFNET_LCK_ASSERT_EXCLUSIVE:
		*type = LCK_RW_ASSERT_EXCLUSIVE;
		return 0;

	case IFNET_LCK_ASSERT_SHARED:
		*type = LCK_RW_ASSERT_SHARED;
		return 0;

	case IFNET_LCK_ASSERT_OWNED:
		*type = LCK_RW_ASSERT_HELD;
		return 0;

	case IFNET_LCK_ASSERT_NOTOWNED:
		/* nothing to do here for RW lock; bypass assert */
		return ENOENT;

	default:
		panic("bad ifnet assert type: %d", what);
		/* NOTREACHED */
	}
}

__private_extern__ void
dlil_if_lock(void)
{
	lck_mtx_lock(&dlil_ifnet_lock);
}

__private_extern__ void
dlil_if_unlock(void)
{
	lck_mtx_unlock(&dlil_ifnet_lock);
}

__private_extern__ void
dlil_if_lock_assert(void)
{
	LCK_MTX_ASSERT(&dlil_ifnet_lock, LCK_MTX_ASSERT_OWNED);
}

__private_extern__ void
ifnet_head_lock_assert(ifnet_lock_assert_t what)
{
	unsigned int type = 0;

	if (_dlil_get_lock_assertion_type(what, &type) == 0) {
		LCK_RW_ASSERT(&ifnet_head_lock, type);
	}
}

__private_extern__ void
ifnet_lock_assert(struct ifnet *ifp, ifnet_lock_assert_t what)
{
#if !MACH_ASSERT
#pragma unused(ifp)
#endif
	unsigned int type = 0;

	if (_dlil_get_lock_assertion_type(what, &type) == 0) {
		LCK_RW_ASSERT(&ifp->if_lock, type);
	}
}

__private_extern__ void
ifnet_lock_shared(struct ifnet *ifp)
{
	lck_rw_lock_shared(&ifp->if_lock);
}

__private_extern__ void
ifnet_lock_exclusive(struct ifnet *ifp)
{
	lck_rw_lock_exclusive(&ifp->if_lock);
}

__private_extern__ void
ifnet_lock_done(struct ifnet *ifp)
{
	lck_rw_done(&ifp->if_lock);
}

#if INET
__private_extern__ void
if_inetdata_lock_shared(struct ifnet *ifp)
{
	lck_rw_lock_shared(&ifp->if_inetdata_lock);
}

__private_extern__ void
if_inetdata_lock_exclusive(struct ifnet *ifp)
{
	lck_rw_lock_exclusive(&ifp->if_inetdata_lock);
}

__private_extern__ void
if_inetdata_lock_done(struct ifnet *ifp)
{
	lck_rw_done(&ifp->if_inetdata_lock);
}
#endif /* INET */

__private_extern__ void
if_inet6data_lock_shared(struct ifnet *ifp)
{
	lck_rw_lock_shared(&ifp->if_inet6data_lock);
}

__private_extern__ void
if_inet6data_lock_exclusive(struct ifnet *ifp)
{
	lck_rw_lock_exclusive(&ifp->if_inet6data_lock);
}

__private_extern__ void
if_inet6data_lock_done(struct ifnet *ifp)
{
	lck_rw_done(&ifp->if_inet6data_lock);
}

__private_extern__ void
ifnet_head_lock_shared(void)
{
	lck_rw_lock_shared(&ifnet_head_lock);
}

__private_extern__ void
ifnet_head_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&ifnet_head_lock);
}

__private_extern__ void
ifnet_head_done(void)
{
	lck_rw_done(&ifnet_head_lock);
}

__private_extern__ void
ifnet_head_assert_exclusive(void)
{
	LCK_RW_ASSERT(&ifnet_head_lock, LCK_RW_ASSERT_EXCLUSIVE);
}

static errno_t
if_mcasts_update_common(struct ifnet * ifp, bool sync)
{
	errno_t err;

	if (sync) {
		err = ifnet_ioctl(ifp, 0, SIOCADDMULTI, NULL);
		if (err == EAFNOSUPPORT) {
			err = 0;
		}
	} else {
		ifnet_ioctl_async(ifp, SIOCADDMULTI);
		err = 0;
	}
	DLIL_PRINTF("%s: %s %d suspended link-layer multicast membership(s) "
	    "(err=%d)\n", if_name(ifp),
	    (err == 0 ? "successfully restored" : "failed to restore"),
	    ifp->if_updatemcasts, err);

	/* just return success */
	return 0;
}

errno_t
if_mcasts_update_async(struct ifnet *ifp)
{
	return if_mcasts_update_common(ifp, false);
}

errno_t
if_mcasts_update(struct ifnet *ifp)
{
	return if_mcasts_update_common(ifp, true);
}
