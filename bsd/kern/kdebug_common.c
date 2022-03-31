/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <sys/kdebug_common.h>

LCK_GRP_DECLARE(kdebug_lck_grp, "kdebug");
int kdbg_debug = 0;

extern struct kd_ctrl_page_t kd_ctrl_page_trace, kd_ctrl_page_triage;

void
kdebug_lck_init(void)
{
	lck_spin_init(&kd_ctrl_page_trace.kds_spin_lock, &kdebug_lck_grp, LCK_ATTR_NULL);
	lck_spin_init(&kd_ctrl_page_triage.kds_spin_lock, &kdebug_lck_grp, LCK_ATTR_NULL);
}

int
kdebug_storage_lock(struct kd_ctrl_page_t *kd_ctrl_page)
{
	int intrs_en = ml_set_interrupts_enabled(false);
	lck_spin_lock_grp(&kd_ctrl_page->kds_spin_lock, &kdebug_lck_grp);
	return intrs_en;
}

void
kdebug_storage_unlock(struct kd_ctrl_page_t *kd_ctrl_page, int intrs_en)
{
	lck_spin_unlock(&kd_ctrl_page->kds_spin_lock);
	ml_set_interrupts_enabled(intrs_en);
}

extern int kernel_debug_trace_write_to_file(user_addr_t *buffer, size_t *number, size_t *count, size_t tempbuf_number, vnode_t vp, vfs_context_t ctx, uint32_t file_version);

uint32_t
kdbg_cpu_count(bool early_trace)
{
	if (early_trace) {
#if defined(__x86_64__)
		return max_ncpus;
#else /* defined(__x86_64__) */
		return ml_get_cpu_count();
#endif /* !defined(__x86_64__) */
	}

#if defined(__x86_64__)
	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
	host_info((host_t)1 /* BSD_HOST */, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	assert(hinfo.logical_cpu_max > 0);
	return hinfo.logical_cpu_max;
#else /* defined(__x86_64__) */
	return ml_get_topology_info()->max_cpu_id + 1;
#endif /* !defined(__x86_64__) */
}

/*
 * Both kdebug_timestamp and kdebug_using_continuous_time are known
 * to kexts. And going forward we always want to use mach_continuous_time().
 * So we keep these 2 routines as-is to keep the TRACE mode use outside
 * the kernel intact. TRIAGE mode will explicitly only use mach_continuous_time()
 * for its timestamp.
 */
bool
kdebug_using_continuous_time(void)
{
	return kd_ctrl_page_trace.kdebug_flags & KDBG_CONTINUOUS_TIME;
}

uint64_t
kdebug_timestamp(void)
{
	if (kdebug_using_continuous_time()) {
		return mach_continuous_time();
	} else {
		return mach_absolute_time();
	}
}

int
create_buffers(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, vm_tag_t tag)
{
	unsigned int i;
	unsigned int p_buffer_size;
	unsigned int f_buffer_size;
	unsigned int f_buffers;
	int error = 0;
	int ncpus, count_storage_units = 0;
	vm_size_t kd_buf_size;

	struct kd_bufinfo *kdbip = NULL;
	struct kd_storage_buffers *kd_bufs = NULL;
	int n_storage_units = kd_data_page->n_storage_units;

	ncpus = kd_ctrl_page->kdebug_cpus;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_data_page->kdbip, sizeof(struct kd_bufinfo) * ncpus, tag) != KERN_SUCCESS) {
		error = ENOSPC;
		goto out;
	}
	kdbip = kd_data_page->kdbip;

	f_buffers = n_storage_units / N_STORAGE_UNITS_PER_BUFFER;
	kd_data_page->n_storage_buffer = f_buffers;

	f_buffer_size = N_STORAGE_UNITS_PER_BUFFER * sizeof(struct kd_storage);
	p_buffer_size = (n_storage_units % N_STORAGE_UNITS_PER_BUFFER) * sizeof(struct kd_storage);

	if (p_buffer_size) {
		kd_data_page->n_storage_buffer++;
	}

	if (kd_data_page->kdcopybuf == 0) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_data_page->kdcopybuf, (vm_size_t) kd_ctrl_page->kdebug_kdcopybuf_size, tag) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
	}

	kd_buf_size = (vm_size_t) (kd_data_page->n_storage_buffer * sizeof(struct kd_storage_buffers));
	if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_data_page->kd_bufs, kd_buf_size, tag) != KERN_SUCCESS) {
		error = ENOSPC;
		goto out;
	}
	kd_bufs = kd_data_page->kd_bufs;
	bzero(kd_bufs, kd_buf_size);

	for (i = 0; i < f_buffers; i++) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)f_buffer_size, tag) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		bzero(kd_bufs[i].kdsb_addr, f_buffer_size);

		kd_bufs[i].kdsb_size = f_buffer_size;
	}
	if (p_buffer_size) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)p_buffer_size, tag) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		bzero(kd_bufs[i].kdsb_addr, p_buffer_size);

		kd_bufs[i].kdsb_size = p_buffer_size;
	}

	count_storage_units = 0;
	for (i = 0; i < kd_data_page->n_storage_buffer; i++) {
		struct kd_storage *kds;
		uint16_t n_elements;
		static_assert(N_STORAGE_UNITS_PER_BUFFER <= UINT16_MAX);
		assert(kd_bufs[i].kdsb_size <= N_STORAGE_UNITS_PER_BUFFER *
		    sizeof(struct kd_storage));

		n_elements = kd_bufs[i].kdsb_size / sizeof(struct kd_storage);
		kds = kd_bufs[i].kdsb_addr;

		for (uint16_t n = 0; n < n_elements; n++) {
			kds[n].kds_next.buffer_index = kd_ctrl_page->kds_free_list.buffer_index;
			kds[n].kds_next.offset = kd_ctrl_page->kds_free_list.offset;

			kd_ctrl_page->kds_free_list.buffer_index = i;
			kd_ctrl_page->kds_free_list.offset = n;
		}
		count_storage_units += n_elements;
	}

	kd_data_page->n_storage_units = count_storage_units;

	bzero((char *)kdbip, sizeof(struct kd_bufinfo) * ncpus);

	for (i = 0; i < ncpus; i++) {
		kdbip[i].kd_list_head.raw = KDS_PTR_NULL;
		kdbip[i].kd_list_tail.raw = KDS_PTR_NULL;
		kdbip[i].kd_lostevents = false;
		kdbip[i].num_bufs = 0;
	}

	kd_ctrl_page->kdebug_flags |= KDBG_BUFINIT;

	kd_ctrl_page->kds_inuse_count = 0;
out:
	if (error) {
		delete_buffers(kd_ctrl_page, kd_data_page);
	}

	return error;
}

void
delete_buffers(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page)
{
	unsigned int i;
	int n_storage_buffer = kd_data_page->n_storage_buffer;

	struct kd_bufinfo *kdbip = kd_data_page->kdbip;
	struct kd_storage_buffers *kd_bufs = kd_data_page->kd_bufs;

	if (kd_bufs) {
		for (i = 0; i < n_storage_buffer; i++) {
			if (kd_bufs[i].kdsb_addr) {
				kmem_free(kernel_map, (vm_offset_t)kd_bufs[i].kdsb_addr, (vm_size_t)kd_bufs[i].kdsb_size);
			}
		}
		kmem_free(kernel_map, (vm_offset_t)kd_bufs, (vm_size_t)(n_storage_buffer * sizeof(struct kd_storage_buffers)));

		kd_data_page->kd_bufs = NULL;
		kd_data_page->n_storage_buffer = 0;
	}
	if (kd_data_page->kdcopybuf) {
		kmem_free(kernel_map, (vm_offset_t)kd_data_page->kdcopybuf, kd_ctrl_page->kdebug_kdcopybuf_size);

		kd_data_page->kdcopybuf = NULL;
	}
	kd_ctrl_page->kds_free_list.raw = KDS_PTR_NULL;

	if (kdbip) {
		kmem_free(kernel_map, (vm_offset_t)kdbip, sizeof(struct kd_bufinfo) * kd_ctrl_page->kdebug_cpus);

		kd_data_page->kdbip = NULL;
	}
	kd_ctrl_page->kdebug_iops = NULL;
	kd_ctrl_page->kdebug_cpus = 0;
	kd_ctrl_page->kdebug_flags &= ~KDBG_BUFINIT;
}

bool
allocate_storage_unit(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, int cpu)
{
	union kds_ptr kdsp;
	struct kd_storage *kdsp_actual, *kdsp_next_actual;
	struct kd_bufinfo *kdbip, *kdbp, *kdbp_vict, *kdbp_try;
	uint64_t oldest_ts, ts;
	bool retval = true;
	struct kd_storage_buffers *kd_bufs;

	int intrs_en = kdebug_storage_lock(kd_ctrl_page);

	kdbp = &kd_data_page->kdbip[cpu];
	kd_bufs = kd_data_page->kd_bufs;
	kdbip = kd_data_page->kdbip;

	/* If someone beat us to the allocate, return success */
	if (kdbp->kd_list_tail.raw != KDS_PTR_NULL) {
		kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdbp->kd_list_tail);

		if (kdsp_actual->kds_bufindx < kd_ctrl_page->kdebug_events_per_storage_unit) {
			goto out;
		}
	}

	if ((kdsp = kd_ctrl_page->kds_free_list).raw != KDS_PTR_NULL) {
		/*
		 * If there's a free page, grab it from the free list.
		 */
		kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);
		kd_ctrl_page->kds_free_list = kdsp_actual->kds_next;

		kd_ctrl_page->kds_inuse_count++;
	} else {
		/*
		 * Otherwise, we're going to lose events and repurpose the oldest
		 * storage unit we can find.
		 */
		if (kd_ctrl_page->kdebug_flags & KDBG_NOWRAP) {
			kd_ctrl_page->kdebug_slowcheck |= SLOW_NOLOG;
			kdbp->kd_lostevents = true;
			retval = false;
			goto out;
		}
		kdbp_vict = NULL;
		oldest_ts = UINT64_MAX;

		for (kdbp_try = &kdbip[0]; kdbp_try < &kdbip[kd_ctrl_page->kdebug_cpus]; kdbp_try++) {
			if (kdbp_try->kd_list_head.raw == KDS_PTR_NULL) {
				/*
				 * no storage unit to steal
				 */
				continue;
			}

			kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdbp_try->kd_list_head);

			if (kdsp_actual->kds_bufcnt < kd_ctrl_page->kdebug_events_per_storage_unit) {
				/*
				 * make sure we don't steal the storage unit
				 * being actively recorded to...  need to
				 * move on because we don't want an out-of-order
				 * set of events showing up later
				 */
				continue;
			}

			/*
			 * When wrapping, steal the storage unit with the
			 * earliest timestamp on its last event, instead of the
			 * earliest timestamp on the first event.  This allows a
			 * storage unit with more recent events to be preserved,
			 * even if the storage unit contains events that are
			 * older than those found in other CPUs.
			 */
			ts = kdbg_get_timestamp(&kdsp_actual->kds_records[kd_ctrl_page->kdebug_events_per_storage_unit - 1]);
			if (ts < oldest_ts) {
				oldest_ts = ts;
				kdbp_vict = kdbp_try;
			}
		}
		if (kdbp_vict == NULL && kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
			kdebug_enable = 0;
			kd_ctrl_page->enabled = 0;
			commpage_update_kdebug_state();
			retval = false;
			goto out;
		}
		kdsp = kdbp_vict->kd_list_head;
		kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);
		kdbp_vict->kd_list_head = kdsp_actual->kds_next;

		if (kdbp_vict->kd_list_head.raw != KDS_PTR_NULL) {
			kdsp_next_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdbp_vict->kd_list_head);
			kdsp_next_actual->kds_lostevents = true;
		} else {
			kdbp_vict->kd_lostevents = true;
		}

		if (kd_ctrl_page->oldest_time < oldest_ts) {
			kd_ctrl_page->oldest_time = oldest_ts;
		}
		kd_ctrl_page->kdebug_flags |= KDBG_WRAPPED;
	}

	if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
		kdsp_actual->kds_timestamp = kdebug_timestamp();
	} else {
		kdsp_actual->kds_timestamp = mach_continuous_time();
	}

	kdsp_actual->kds_next.raw = KDS_PTR_NULL;
	kdsp_actual->kds_bufcnt   = 0;
	kdsp_actual->kds_readlast = 0;

	kdsp_actual->kds_lostevents = kdbp->kd_lostevents;
	kdbp->kd_lostevents = false;
	kdsp_actual->kds_bufindx = 0;

	if (kdbp->kd_list_head.raw == KDS_PTR_NULL) {
		kdbp->kd_list_head = kdsp;
	} else {
		POINTER_FROM_KDS_PTR(kd_bufs, kdbp->kd_list_tail)->kds_next = kdsp;
	}
	kdbp->kd_list_tail = kdsp;
out:
	kdebug_storage_unlock(kd_ctrl_page, intrs_en);

	return retval;
}

void
release_storage_unit(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, int cpu, uint32_t kdsp_raw)
{
	struct  kd_storage *kdsp_actual;
	struct kd_bufinfo *kdbp;
	union kds_ptr kdsp;

	kdbp = &kd_data_page->kdbip[cpu];

	kdsp.raw = kdsp_raw;

	int intrs_en = kdebug_storage_lock(kd_ctrl_page);

	if (kdsp.raw == kdbp->kd_list_head.raw) {
		/*
		 * it's possible for the storage unit pointed to
		 * by kdsp to have already been stolen... so
		 * check to see if it's still the head of the list
		 * now that we're behind the lock that protects
		 * adding and removing from the queue...
		 * since we only ever release and steal units from
		 * that position, if it's no longer the head
		 * we having nothing to do in this context
		 */
		kdsp_actual = POINTER_FROM_KDS_PTR(kd_data_page->kd_bufs, kdsp);
		kdbp->kd_list_head = kdsp_actual->kds_next;

		kdsp_actual->kds_next = kd_ctrl_page->kds_free_list;
		kd_ctrl_page->kds_free_list = kdsp;

		kd_ctrl_page->kds_inuse_count--;
	}

	kdebug_storage_unlock(kd_ctrl_page, intrs_en);
}


/*
 * Disable wrapping and return true if trace wrapped, false otherwise.
 */
bool
disable_wrap(struct kd_ctrl_page_t *kd_ctrl_page, uint32_t *old_slowcheck, uint32_t *old_flags)
{
	bool wrapped;
	int intrs_en = kdebug_storage_lock(kd_ctrl_page);

	*old_slowcheck = kd_ctrl_page->kdebug_slowcheck;
	*old_flags = kd_ctrl_page->kdebug_flags;

	wrapped = kd_ctrl_page->kdebug_flags & KDBG_WRAPPED;
	kd_ctrl_page->kdebug_flags &= ~KDBG_WRAPPED;
	kd_ctrl_page->kdebug_flags |= KDBG_NOWRAP;

	kdebug_storage_unlock(kd_ctrl_page, intrs_en);

	return wrapped;
}

void
enable_wrap(struct kd_ctrl_page_t *kd_ctrl_page, uint32_t old_slowcheck)
{
	int intrs_en = kdebug_storage_lock(kd_ctrl_page);

	kd_ctrl_page->kdebug_flags &= ~KDBG_NOWRAP;

	if (!(old_slowcheck & SLOW_NOLOG)) {
		kd_ctrl_page->kdebug_slowcheck &= ~SLOW_NOLOG;
	}
	kdebug_storage_unlock(kd_ctrl_page, intrs_en);
}

__attribute__((always_inline))
void
kernel_debug_write(struct kd_ctrl_page_t *kd_ctrl_page,
    struct kd_data_page_t *kd_data_page,
    struct kd_record      kd_rec)
{
	uint64_t now = 0;
	uint32_t bindx;
	kd_buf *kd;
	int cpu;
	struct kd_bufinfo *kdbp;
	struct kd_storage *kdsp_actual;
	union kds_ptr kds_raw;

	disable_preemption();

	if (kd_ctrl_page->enabled == 0) {
		goto out;
	}

	if (kd_rec.cpu == -1) {
		cpu = cpu_number();
	} else {
		cpu = kd_rec.cpu;
	}

	kdbp = &kd_data_page->kdbip[cpu];

	bool timestamp_is_continuous = kdbp->continuous_timestamps;

	if (kd_rec.timestamp != -1) {
		if (kdebug_using_continuous_time()) {
			if (!timestamp_is_continuous) {
				kd_rec.timestamp = absolutetime_to_continuoustime(kd_rec.timestamp);
			}
		} else {
			if (timestamp_is_continuous) {
				kd_rec.timestamp = continuoustime_to_absolutetime(kd_rec.timestamp);
			}
		}

		if (kd_rec.timestamp < kd_ctrl_page->oldest_time) {
			goto out;
		}

		kd_rec.timestamp &= KDBG_TIMESTAMP_MASK;
	}

retry_q:
	kds_raw = kdbp->kd_list_tail;

	if (kds_raw.raw != KDS_PTR_NULL) {
		kdsp_actual = POINTER_FROM_KDS_PTR(kd_data_page->kd_bufs, kds_raw);
		bindx = kdsp_actual->kds_bufindx;
	} else {
		kdsp_actual = NULL;
		bindx = kd_ctrl_page->kdebug_events_per_storage_unit;
	}

	if (kdsp_actual == NULL || bindx >= kd_ctrl_page->kdebug_events_per_storage_unit) {
		if (allocate_storage_unit(kd_ctrl_page, kd_data_page, cpu) == false) {
			/*
			 * this can only happen if wrapping
			 * has been disabled
			 */
			goto out;
		}
		goto retry_q;
	}

	if (kd_rec.timestamp != -1) {
		/*
		 * IOP entries can be allocated before xnu allocates and inits the buffer
		 * And, Intel uses a special 0 value as a early tracing timestamp sentinel
		 * to set the start of trace-time-start-of-interest.
		 */
		if (kd_rec.timestamp < kdsp_actual->kds_timestamp) {
			kdsp_actual->kds_timestamp = kd_rec.timestamp;
		}
		now = kd_rec.timestamp;
	} else {
		if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
			now = kdebug_timestamp() & KDBG_TIMESTAMP_MASK;
		} else {
			now = mach_continuous_time() & KDBG_TIMESTAMP_MASK;
		}
	}

	if (!OSCompareAndSwap(bindx, bindx + 1, &kdsp_actual->kds_bufindx)) {
		goto retry_q;
	}

	kd = &kdsp_actual->kds_records[bindx];

	if (kd_ctrl_page->kdebug_flags & KDBG_DEBUGID_64) {
		/*DebugID has been passed in arg 4*/
		kd->debugid = 0;
	} else {
		kd->debugid = kd_rec.debugid;
	}

	kd->arg1 = kd_rec.arg1;
	kd->arg2 = kd_rec.arg2;
	kd->arg3 = kd_rec.arg3;
	kd->arg4 = kd_rec.arg4;
	kd->arg5 = kd_rec.arg5; /* thread ID */

	kdbg_set_timestamp_and_cpu(kd, now, cpu);

	OSAddAtomic(1, &kdsp_actual->kds_bufcnt);

out:
	enable_preemption();
}

/*
 * This is a general purpose routine to read the kd_bufs from the storage units.
 * So it is the responsibility of the caller to make sure they have acquired
 * the right synchronization primitive so they can retrieve the data in the correct
 * way.
 */
int
kernel_debug_read(struct kd_ctrl_page_t *kd_ctrl_page, struct kd_data_page_t *kd_data_page, user_addr_t buffer, size_t *number, vnode_t vp, vfs_context_t ctx, uint32_t file_version)
{
	size_t count;
	unsigned int cpu, min_cpu;
	uint64_t barrier_min = 0, barrier_max = 0, t, earliest_time;
	int error = 0;
	kd_buf *tempbuf;
	uint32_t rcursor;
	kd_buf lostevent;
	union kds_ptr kdsp;
	bool traced_retrograde = false;
	struct kd_storage *kdsp_actual;
	struct kd_bufinfo *kdbp;
	struct kd_bufinfo *min_kdbp;
	size_t tempbuf_count;
	uint32_t tempbuf_number;
	uint32_t old_kdebug_flags;
	uint32_t old_kdebug_slowcheck;
	bool out_of_events = false;
	bool wrapped = false;
	bool set_preempt = true;
	bool should_disable = false;

	struct kd_bufinfo *kdbip = kd_data_page->kdbip;
	struct kd_storage_buffers *kd_bufs = kd_data_page->kd_bufs;

	assert(number != NULL);
	count = *number / sizeof(kd_buf);
	*number = 0;

	if (count == 0 || !(kd_ctrl_page->kdebug_flags & KDBG_BUFINIT) || kd_data_page->kdcopybuf == 0) {
		return EINVAL;
	}

	if (kd_ctrl_page->mode == KDEBUG_MODE_TRIAGE) {
		/*
		 * A corpse can be created due to 'TASK_HAS_TOO_MANY_THREADS'
		 * and that can be handled by a callout thread that already
		 * has the eager-preemption set.
		 * So check to see if we are dealing with one such thread.
		 */
		set_preempt = !(thread_is_eager_preempt(current_thread()));
	}

	if (set_preempt) {
		thread_set_eager_preempt(current_thread());
	}

	memset(&lostevent, 0, sizeof(lostevent));
	lostevent.debugid = TRACE_LOST_EVENTS;

	/*
	 * Capture the current time.  Only sort events that have occured
	 * before now.  Since the IOPs are being flushed here, it is possible
	 * that events occur on the AP while running live tracing.
	 */
	if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
		barrier_max = kdebug_timestamp() & KDBG_TIMESTAMP_MASK;
	} else {
		barrier_max = mach_continuous_time() & KDBG_TIMESTAMP_MASK;
	}

	/*
	 * Disable wrap so storage units cannot be stolen out from underneath us
	 * while merging events.
	 *
	 * Because we hold ktrace_lock, no other control threads can be playing
	 * with kdebug_flags.  The code that emits new events could be running,
	 * but it grabs kds_spin_lock if it needs to acquire a new storage
	 * chunk, which is where it examines kdebug_flags.  If it is adding to
	 * the same chunk we're reading from, check for that below.
	 */
	wrapped = disable_wrap(kd_ctrl_page, &old_kdebug_slowcheck, &old_kdebug_flags);

	if (count > kd_data_page->nkdbufs) {
		count = kd_data_page->nkdbufs;
	}

	if ((tempbuf_count = count) > kd_ctrl_page->kdebug_kdcopybuf_count) {
		tempbuf_count = kd_ctrl_page->kdebug_kdcopybuf_count;
	}

	/*
	 * If the buffers have wrapped, do not emit additional lost events for the
	 * oldest storage units.
	 */
	if (wrapped) {
		kd_ctrl_page->kdebug_flags &= ~KDBG_WRAPPED;

		for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_ctrl_page->kdebug_cpus; cpu++, kdbp++) {
			if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
				continue;
			}
			kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);
			kdsp_actual->kds_lostevents = false;
		}
	}

	if (kd_ctrl_page->mode == KDEBUG_MODE_TRIAGE) {
		/*
		 * In TRIAGE mode we want to extract all the current
		 * records regardless of where we stopped reading last
		 * time so that we have the best shot at getting older
		 * records for threads before the buffers are wrapped.
		 * So set readlast to 0 to initiate the search from the
		 * 1st record.
		 */
		for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_ctrl_page->kdebug_cpus; cpu++, kdbp++) {
			if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
				continue;
			}
			kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);
			kdsp_actual->kds_readlast = 0;
		}
	}

	/*
	 * Capture the earliest time where there are events for all CPUs and don't
	 * emit events with timestamps prior.
	 */
	barrier_min = kd_ctrl_page->oldest_time;

	while (count) {
		tempbuf = kd_data_page->kdcopybuf;
		tempbuf_number = 0;

		if (wrapped) {
			/*
			 * Emit a lost events tracepoint to indicate that previous events
			 * were lost -- the thread map cannot be trusted.  A new one must
			 * be taken so tools can analyze the trace in a backwards-facing
			 * fashion.
			 */
			kdbg_set_timestamp_and_cpu(&lostevent, barrier_min, 0);
			*tempbuf = lostevent;
			wrapped = false;
			goto nextevent;
		}

		/* While space left in merged events scratch buffer. */
		while (tempbuf_count) {
			bool lostevents = false;
			int lostcpu = 0;
			earliest_time = UINT64_MAX;
			min_kdbp = NULL;
			min_cpu = 0;

			/* Check each CPU's buffers for the earliest event. */
			for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_ctrl_page->kdebug_cpus; cpu++, kdbp++) {
				/* Skip CPUs without data in their oldest storage unit. */
				if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
next_cpu:
					continue;
				}
				/* From CPU data to buffer header to buffer. */
				kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);

next_event:
				/* The next event to be read from this buffer. */
				rcursor = kdsp_actual->kds_readlast;

				/* Skip this buffer if there are no events left. */
				if (rcursor == kdsp_actual->kds_bufindx) {
					continue;
				}

				if (kd_ctrl_page->mode == KDEBUG_MODE_TRIAGE) {
					/*
					 * TRIAGE mode record keeping doesn't (currently)
					 * use lostevent markers. It also doesn't want to
					 * call release_storage_unit() in this read call.
					 * It expects the buffers to wrap and records reclaimed
					 * in that way solely.
					 */
					t = kdbg_get_timestamp(&kdsp_actual->kds_records[rcursor]);
					goto skip_record_checks;
				}

				/*
				 * Check that this storage unit wasn't stolen and events were
				 * lost.  This must have happened while wrapping was disabled
				 * in this function.
				 */
				if (kdsp_actual->kds_lostevents) {
					lostevents = true;
					kdsp_actual->kds_lostevents = false;

					/*
					 * The earliest event we can trust is the first one in this
					 * stolen storage unit.
					 */
					uint64_t lost_time =
					    kdbg_get_timestamp(&kdsp_actual->kds_records[0]);
					if (kd_ctrl_page->oldest_time < lost_time) {
						/*
						 * If this is the first time we've seen lost events for
						 * this gap, record its timestamp as the oldest
						 * timestamp we're willing to merge for the lost events
						 * tracepoint.
						 */
						kd_ctrl_page->oldest_time = barrier_min = lost_time;
						lostcpu = cpu;
					}
				}

				t = kdbg_get_timestamp(&kdsp_actual->kds_records[rcursor]);

				if (t > barrier_max) {
					if (kdbg_debug) {
						printf("kdebug: FUTURE EVENT: debugid %#8x: "
						    "time %lld from CPU %u "
						    "(barrier at time %lld, read %lu events)\n",
						    kdsp_actual->kds_records[rcursor].debugid,
						    t, cpu, barrier_max, *number + tempbuf_number);
					}
					goto next_cpu;
				}
				if (t < kdsp_actual->kds_timestamp) {
					/*
					 * This indicates the event emitter hasn't completed
					 * filling in the event (becuase we're looking at the
					 * buffer that the record head is using).  The max barrier
					 * timestamp should have saved us from seeing these kinds
					 * of things, but other CPUs might be slow on the up-take.
					 *
					 * Bail out so we don't get out-of-order events by
					 * continuing to read events from other CPUs' events.
					 */
					out_of_events = true;
					break;
				}

				/*
				 * Ignore events that have aged out due to wrapping or storage
				 * unit exhaustion while merging events.
				 */
				if (t < barrier_min) {
					kdsp_actual->kds_readlast++;
					if (kdbg_debug) {
						printf("kdebug: PAST EVENT: debugid %#8x: "
						    "time %lld from CPU %u "
						    "(barrier at time %lld)\n",
						    kdsp_actual->kds_records[rcursor].debugid,
						    t, cpu, barrier_min);
					}

					if (kdsp_actual->kds_readlast >= kd_ctrl_page->kdebug_events_per_storage_unit) {
						release_storage_unit(kd_ctrl_page, kd_data_page, cpu, kdsp.raw);

						if ((kdsp = kdbp->kd_list_head).raw == KDS_PTR_NULL) {
							goto next_cpu;
						}
						kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);
					}
					goto next_event;
				}

				/*
				 * Don't worry about merging any events -- just walk through
				 * the CPUs and find the latest timestamp of lost events.
				 */
				if (lostevents) {
					continue;
				}
skip_record_checks:
				if (t < earliest_time) {
					earliest_time = t;
					min_kdbp = kdbp;
					min_cpu = cpu;
				}
			}
			if (lostevents) {
				/*
				 * If any lost events were hit in the buffers, emit an event
				 * with the latest timestamp.
				 */
				kdbg_set_timestamp_and_cpu(&lostevent, barrier_min, lostcpu);
				*tempbuf = lostevent;
				tempbuf->arg1 = 1;
				goto nextevent;
			}
			if (min_kdbp == NULL) {
				/* All buffers ran empty. */
				out_of_events = true;
			}
			if (out_of_events) {
				break;
			}

			kdsp = min_kdbp->kd_list_head;
			kdsp_actual = POINTER_FROM_KDS_PTR(kd_bufs, kdsp);

			/* Copy earliest event into merged events scratch buffer. */
			*tempbuf = kdsp_actual->kds_records[kdsp_actual->kds_readlast++];
			kd_buf *earliest_event = tempbuf;
			if (kd_ctrl_page_trace.kdebug_flags & KDBG_MATCH_DISABLE) {
				kd_event_matcher *match = &kd_ctrl_page_trace.disable_event_match;
				kd_event_matcher *mask = &kd_ctrl_page_trace.disable_event_mask;
				if ((earliest_event->debugid & mask->kem_debugid) == match->kem_debugid &&
				    (earliest_event->arg1 & mask->kem_args[0]) == match->kem_args[0] &&
				    (earliest_event->arg2 & mask->kem_args[1]) == match->kem_args[1] &&
				    (earliest_event->arg3 & mask->kem_args[2]) == match->kem_args[2] &&
				    (earliest_event->arg4 & mask->kem_args[3]) == match->kem_args[3]) {
					should_disable = true;
				}
			}

			if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
				if (kdsp_actual->kds_readlast == kd_ctrl_page->kdebug_events_per_storage_unit) {
					release_storage_unit(kd_ctrl_page, kd_data_page, min_cpu, kdsp.raw);
				}
			}

			/*
			 * Watch for out of order timestamps (from IOPs).
			 */
			if (earliest_time < min_kdbp->kd_prev_timebase) {
				/*
				 * If we haven't already, emit a retrograde events event.
				 * Otherwise, ignore this event.
				 */
				if (traced_retrograde) {
					continue;
				}
				if (kdbg_debug) {
					printf("kdebug: RETRO EVENT: debugid %#8x: "
					    "time %lld from CPU %u "
					    "(barrier at time %lld)\n",
					    kdsp_actual->kds_records[rcursor].debugid,
					    t, cpu, barrier_min);
				}

				kdbg_set_timestamp_and_cpu(tempbuf, min_kdbp->kd_prev_timebase, kdbg_get_cpu(tempbuf));
				tempbuf->arg1 = tempbuf->debugid;
				tempbuf->arg2 = (kd_buf_argtype)earliest_time;
				tempbuf->arg3 = 0;
				tempbuf->arg4 = 0;
				tempbuf->debugid = TRACE_RETROGRADE_EVENTS;
				traced_retrograde = true;
			} else {
				min_kdbp->kd_prev_timebase = earliest_time;
			}
nextevent:
			tempbuf_count--;
			tempbuf_number++;
			tempbuf++;

			if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE && (RAW_file_written += sizeof(kd_buf)) >= RAW_FLUSH_SIZE) {
				break;
			}
		}

		if (tempbuf_number) {
			/*
			 * Remember the latest timestamp of events that we've merged so we
			 * don't think we've lost events later.
			 */
			uint64_t latest_time = kdbg_get_timestamp(tempbuf - 1);
			if (kd_ctrl_page->oldest_time < latest_time) {
				kd_ctrl_page->oldest_time = latest_time;
			}

			if (kd_ctrl_page->mode == KDEBUG_MODE_TRACE) {
				error = kernel_debug_trace_write_to_file(&buffer, number, &count, tempbuf_number, vp, ctx, file_version);
				if (error) {
					goto check_error;
				}
			} else if (kd_ctrl_page->mode == KDEBUG_MODE_TRIAGE) {
				memcpy((void*)buffer, kd_data_page->kdcopybuf, tempbuf_number * sizeof(kd_buf));

				buffer += (tempbuf_number * sizeof(kd_buf));
			} else {
				panic("kernel_debug_read: Invalid Mode");
			}
check_error:
			if (error) {
				*number = 0;
				error = EINVAL;
				break;
			}
			count   -= tempbuf_number;
			*number += tempbuf_number;
		}
		if (out_of_events) {
			/*
			 * all trace buffers are empty
			 */
			break;
		}

		if ((tempbuf_count = count) > kd_ctrl_page->kdebug_kdcopybuf_count) {
			tempbuf_count = kd_ctrl_page->kdebug_kdcopybuf_count;
		}
	}
	if (!(old_kdebug_flags & KDBG_NOWRAP)) {
		enable_wrap(kd_ctrl_page, old_kdebug_slowcheck);
	}

	if (set_preempt) {
		thread_clear_eager_preempt(current_thread());
	}

	if (should_disable) {
		kernel_debug_disable();
	}

	return error;
}
