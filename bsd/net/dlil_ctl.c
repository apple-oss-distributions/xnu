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

#include <stddef.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/mcache.h>
#include <libkern/OSAtomic.h>

#include <kern/zalloc.h>

#include <net/dlil_var_private.h>
#include <net/if_var_private.h>

/*
 * DLIL device management
 */
int
dlil_if_acquire(uint32_t family, const void *uniqueid __sized_by(uniqueid_len),
    size_t uniqueid_len, const char *ifxname0 __null_terminated, struct ifnet **ifp)
{
	struct ifnet *ifp1 = NULL;
	struct dlil_ifnet *dlifp1 = NULL;
	struct dlil_ifnet *dlifp1_saved = NULL;
	int ret = 0;
	size_t ifxname_len = strlen(ifxname0);
	const char *ifxname = __unsafe_forge_bidi_indexable(const char *, ifxname0, ifxname_len);
	size_t ifp_name_len;

	VERIFY(*ifp == NULL);
	dlil_if_lock();
	/*
	 * We absolutely can't have an interface with the same name
	 * in in-use state.
	 * To make sure of that list has to be traversed completely
	 */
	TAILQ_FOREACH(dlifp1, &dlil_ifnet_head, dl_if_link) {
		ifp1 = (struct ifnet *)dlifp1;
		ifp_name_len = strlen(ifp1->if_name);
		if (IFXNAMSIZ < ifp_name_len) {
			ifp_name_len = IFXNAMSIZ;
		}

		if (ifp1->if_family != family) {
			continue;
		}

		/*
		 * If interface is in use, return EBUSY if either unique id
		 * or interface extended names are the same
		 */
		lck_mtx_lock(&dlifp1->dl_if_lock);
		/*
		 * Note: compare the lengths to avoid least prefix match.
		 */
		if (ifxname_len == ifp_name_len &&
		    strlcmp(ifxname, ifp1->if_xname, ifxname_len) == 0 &&
		    (dlifp1->dl_if_flags & DLIF_INUSE) != 0) {
			lck_mtx_unlock(&dlifp1->dl_if_lock);
			ret = EBUSY;
			goto end;
		}

		if (uniqueid_len != 0 &&
		    uniqueid_len == dlifp1->dl_if_uniqueid_len &&
		    bcmp(uniqueid, dlifp1->dl_if_uniqueid, uniqueid_len) == 0) {
			if ((dlifp1->dl_if_flags & DLIF_INUSE) != 0) {
				lck_mtx_unlock(&dlifp1->dl_if_lock);
				ret = EBUSY;
				goto end;
			}
			if (dlifp1_saved == NULL) {
				/* cache the first match */
				dlifp1_saved = dlifp1;
			}
			/*
			 * Do not break or jump to end as we have to traverse
			 * the whole list to ensure there are no name collisions
			 */
		}
		lck_mtx_unlock(&dlifp1->dl_if_lock);
	}

	/* If there's an interface that can be recycled, use that */
	if (dlifp1_saved != NULL) {
		lck_mtx_lock(&dlifp1_saved->dl_if_lock);
		if ((dlifp1_saved->dl_if_flags & DLIF_INUSE) != 0) {
			/* some other thread got in ahead of us */
			lck_mtx_unlock(&dlifp1_saved->dl_if_lock);
			ret = EBUSY;
			goto end;
		}
		dlifp1_saved->dl_if_flags |= (DLIF_INUSE | DLIF_REUSE);
		lck_mtx_unlock(&dlifp1_saved->dl_if_lock);
		*ifp = (struct ifnet *)dlifp1_saved;
		dlil_if_ref(*ifp);
		goto end;
	}

	/* no interface found, allocate a new one */
	dlifp1 = dlif_ifnet_alloc();

	if (uniqueid_len) {
		void *new_uniqueid = kalloc_data(uniqueid_len,
		    Z_WAITOK);
		if (new_uniqueid == NULL) {
			dlif_ifnet_free(dlifp1);
			ret = ENOMEM;
			goto end;
		}
		dlifp1->dl_if_uniqueid_len = uniqueid_len;
		dlifp1->dl_if_uniqueid = new_uniqueid;

		bcopy(uniqueid, dlifp1->dl_if_uniqueid, uniqueid_len);
	}

	ifp1 = (struct ifnet *)dlifp1;
	dlifp1->dl_if_flags = DLIF_INUSE;
	if (ifnet_debug) {
		dlifp1->dl_if_flags |= DLIF_DEBUG;
		dlifp1->dl_if_trace = dlil_if_trace;
	}
	ifp1->if_name = tsnprintf(dlifp1->dl_if_namestorage, sizeof(dlifp1->dl_if_namestorage), "");
	ifp1->if_xname = tsnprintf(dlifp1->dl_if_xnamestorage, sizeof(dlifp1->dl_if_xnamestorage), "");

	/* initialize interface description */
	ifp1->if_desc.ifd_maxlen = IF_DESCSIZE;
	ifp1->if_desc.ifd_len = 0;
	ifp1->if_desc.ifd_desc = dlifp1->dl_if_descstorage;

#if SKYWALK
	LIST_INIT(&ifp1->if_netns_tokens);
#endif /* SKYWALK */

	if ((ret = dlil_alloc_local_stats(ifp1)) != 0) {
		DLIL_PRINTF("%s: failed to allocate if local stats, "
		    "error: %d\n", __func__, ret);
		/* This probably shouldn't be fatal */
		ret = 0;
	}

	lck_mtx_init(&dlifp1->dl_if_lock, &ifnet_lock_group, &ifnet_lock_attr);
	lck_rw_init(&ifp1->if_lock, &ifnet_lock_group, &ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_ref_lock, &ifnet_lock_group, &ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_flt_lock, &ifnet_lock_group, &ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_addrconfig_lock, &ifnet_lock_group,
	    &ifnet_lock_attr);
	lck_rw_init(&ifp1->if_llreach_lock, &ifnet_lock_group, &ifnet_lock_attr);
#if INET
	lck_rw_init(&ifp1->if_inetdata_lock, &ifnet_lock_group,
	    &ifnet_lock_attr);
	ifp1->if_inetdata = NULL;
#endif
	lck_mtx_init(&ifp1->if_inet6_ioctl_lock, &ifnet_lock_group, &ifnet_lock_attr);
	ifp1->if_inet6_ioctl_busy = FALSE;
	lck_rw_init(&ifp1->if_inet6data_lock, &ifnet_lock_group,
	    &ifnet_lock_attr);
	ifp1->if_inet6data = NULL;
	lck_rw_init(&ifp1->if_link_status_lock, &ifnet_lock_group,
	    &ifnet_lock_attr);
	ifp1->if_link_status = NULL;
	lck_mtx_init(&ifp1->if_delegate_lock, &ifnet_lock_group, &ifnet_lock_attr);

	/* for send data paths */
	lck_mtx_init(&ifp1->if_start_lock, &ifnet_snd_lock_group,
	    &ifnet_lock_attr);
	lck_mtx_init(&ifp1->if_cached_route_lock, &ifnet_snd_lock_group,
	    &ifnet_lock_attr);

	/* for receive data paths */
	lck_mtx_init(&ifp1->if_poll_lock, &ifnet_rcv_lock_group,
	    &ifnet_lock_attr);

	/* thread call allocation is done with sleeping zalloc */
	ifp1->if_dt_tcall = thread_call_allocate_with_options(dlil_dt_tcall_fn,
	    ifp1, THREAD_CALL_PRIORITY_KERNEL, THREAD_CALL_OPTIONS_ONCE);
	if (ifp1->if_dt_tcall == NULL) {
		panic_plain("%s: couldn't create if_dt_tcall", __func__);
		/* NOTREACHED */
	}

	TAILQ_INSERT_TAIL(&dlil_ifnet_head, dlifp1, dl_if_link);

	*ifp = ifp1;
	dlil_if_ref(*ifp);

end:
	dlil_if_unlock();

	VERIFY(dlifp1 == NULL || (IS_P2ALIGNED(dlifp1, sizeof(u_int64_t)) &&
	    IS_P2ALIGNED(&ifp1->if_data, sizeof(u_int64_t))));

	return ret;
}

void
dlil_if_trace(struct dlil_ifnet *dl_if, int refhold)
{
	struct dlil_ifnet_dbg *dl_if_dbg = (struct dlil_ifnet_dbg *)dl_if;
	ctrace_t *tr;
	u_int32_t idx;
	u_int16_t *cnt;

	if (!(dl_if->dl_if_flags & DLIF_DEBUG)) {
		panic("%s: dl_if %p has no debug structure", __func__, dl_if);
		/* NOTREACHED */
	}

	if (refhold) {
		cnt = &dl_if_dbg->dldbg_if_refhold_cnt;
		tr = dl_if_dbg->dldbg_if_refhold;
	} else {
		cnt = &dl_if_dbg->dldbg_if_refrele_cnt;
		tr = dl_if_dbg->dldbg_if_refrele;
	}

	idx = os_atomic_inc_orig(cnt, relaxed) % IF_REF_TRACE_HIST_SIZE;
	ctrace_record(&tr[idx]);
}

/*
 * Stats management.
 */
void
dlil_input_stats_add(const struct ifnet_stat_increment_param *s,
    struct dlil_threading_info *inp, struct ifnet *ifp, boolean_t poll)
{
	struct ifnet_stat_increment_param *d = &inp->dlth_stats;

	if (s->packets_in != 0) {
		d->packets_in += s->packets_in;
	}
	if (s->bytes_in != 0) {
		d->bytes_in += s->bytes_in;
	}
	if (s->errors_in != 0) {
		d->errors_in += s->errors_in;
	}

	if (s->packets_out != 0) {
		d->packets_out += s->packets_out;
	}
	if (s->bytes_out != 0) {
		d->bytes_out += s->bytes_out;
	}
	if (s->errors_out != 0) {
		d->errors_out += s->errors_out;
	}

	if (s->collisions != 0) {
		d->collisions += s->collisions;
	}
	if (s->dropped != 0) {
		d->dropped += s->dropped;
	}

	if (poll) {
		PKTCNTR_ADD(&ifp->if_poll_tstats, s->packets_in, s->bytes_in);
	}
}

boolean_t
dlil_input_stats_sync(struct ifnet *ifp, struct dlil_threading_info *inp)
{
	struct ifnet_stat_increment_param *s = &inp->dlth_stats;

	/*
	 * Use of atomic operations is unavoidable here because
	 * these stats may also be incremented elsewhere via KPIs.
	 */
	if (s->packets_in != 0) {
		os_atomic_add(&ifp->if_data.ifi_ipackets, s->packets_in, relaxed);
		s->packets_in = 0;
	}
	if (s->bytes_in != 0) {
		os_atomic_add(&ifp->if_data.ifi_ibytes, s->bytes_in, relaxed);
		s->bytes_in = 0;
	}
	if (s->errors_in != 0) {
		os_atomic_add(&ifp->if_data.ifi_ierrors, s->errors_in, relaxed);
		s->errors_in = 0;
	}

	if (s->packets_out != 0) {
		os_atomic_add(&ifp->if_data.ifi_opackets, s->packets_out, relaxed);
		s->packets_out = 0;
	}
	if (s->bytes_out != 0) {
		os_atomic_add(&ifp->if_data.ifi_obytes, s->bytes_out, relaxed);
		s->bytes_out = 0;
	}
	if (s->errors_out != 0) {
		os_atomic_add(&ifp->if_data.ifi_oerrors, s->errors_out, relaxed);
		s->errors_out = 0;
	}

	if (s->collisions != 0) {
		os_atomic_add(&ifp->if_data.ifi_collisions, s->collisions, relaxed);
		s->collisions = 0;
	}
	if (s->dropped != 0) {
		os_atomic_add(&ifp->if_data.ifi_iqdrops, s->dropped, relaxed);
		s->dropped = 0;
	}

	/*
	 * No need for atomic operations as they are modified here
	 * only from within the DLIL input thread context.
	 */
	if (ifp->if_poll_tstats.packets != 0) {
		ifp->if_poll_pstats.ifi_poll_packets += ifp->if_poll_tstats.packets;
		ifp->if_poll_tstats.packets = 0;
	}
	if (ifp->if_poll_tstats.bytes != 0) {
		ifp->if_poll_pstats.ifi_poll_bytes += ifp->if_poll_tstats.bytes;
		ifp->if_poll_tstats.bytes = 0;
	}

	return ifp->if_data_threshold != 0;
}


#if SKYWALK
errno_t
dlil_set_input_handler(struct ifnet *ifp, dlil_input_func fn)
{
	return os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_input_dlil),
	           ptrauth_nop_cast(void *, &dlil_input_handler),
	           ptrauth_nop_cast(void *, fn), acq_rel) ? 0 : EBUSY;
}

void
dlil_reset_input_handler(struct ifnet *ifp)
{
	while (!os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_input_dlil),
	    ptrauth_nop_cast(void *, ifp->if_input_dlil),
	    ptrauth_nop_cast(void *, &dlil_input_handler), acq_rel)) {
		;
	}
}

errno_t
dlil_set_output_handler(struct ifnet *ifp, dlil_output_func fn)
{
	return os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_output_dlil),
	           ptrauth_nop_cast(void *, &dlil_output_handler),
	           ptrauth_nop_cast(void *, fn), acq_rel) ? 0 : EBUSY;
}

void
dlil_reset_output_handler(struct ifnet *ifp)
{
	while (!os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_output_dlil),
	    ptrauth_nop_cast(void *, ifp->if_output_dlil),
	    ptrauth_nop_cast(void *, &dlil_output_handler), acq_rel)) {
		;
	}
}
#endif /* SKYWALK */

errno_t
dlil_output_handler(struct ifnet *ifp, struct mbuf *m)
{
	return ifp->if_output(ifp, m);
}

#define MAX_KNOWN_MBUF_CLASS 8


#if SKYWALK
errno_t
ifnet_set_output_handler(struct ifnet *ifp, ifnet_output_func fn)
{
	return os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_output),
	           ptrauth_nop_cast(void *, ifp->if_save_output),
	           ptrauth_nop_cast(void *, fn), acq_rel) ? 0 : EBUSY;
}

void
ifnet_reset_output_handler(struct ifnet *ifp)
{
	while (!os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_output),
	    ptrauth_nop_cast(void *, ifp->if_output),
	    ptrauth_nop_cast(void *, ifp->if_save_output), acq_rel)) {
		;
	}
}

errno_t
ifnet_set_start_handler(struct ifnet *ifp, ifnet_start_func fn)
{
	return os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_start),
	           ptrauth_nop_cast(void *, ifp->if_save_start),
	           ptrauth_nop_cast(void *, fn), acq_rel) ? 0 : EBUSY;
}

void
ifnet_reset_start_handler(struct ifnet *ifp)
{
	while (!os_atomic_cmpxchg(__unsafe_forge_single(void * volatile *, &ifp->if_start),
	    ptrauth_nop_cast(void *, ifp->if_start),
	    ptrauth_nop_cast(void *, ifp->if_save_start), acq_rel)) {
		;
	}
}
#endif /* SKYWALK */
