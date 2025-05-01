/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_PAGEOUT_XNU_H_
#define _VM_VM_PAGEOUT_XNU_H_

#include <sys/cdefs.h>

__BEGIN_DECLS
#include <vm/vm_pageout.h>

#ifdef XNU_KERNEL_PRIVATE

extern void memoryshot(unsigned int event, unsigned int control);

extern void update_vm_info(void);



#if CONFIG_IOSCHED
extern int upl_get_cached_tier(
	upl_t                   upl);
#endif

extern void upl_set_iodone(upl_t, void *);
extern void upl_set_iodone_error(upl_t, int);
extern void upl_callout_iodone(upl_t);

extern ppnum_t upl_get_highest_page(
	upl_t                   upl);

extern upl_t upl_associated_upl(upl_t upl);
extern void upl_set_associated_upl(upl_t upl, upl_t associated_upl);
extern void upl_set_map_exclusive(upl_t upl);
extern void upl_clear_map_exclusive(upl_t upl);


#include <vm/vm_kern_xnu.h>


extern upl_size_t upl_adjusted_size(
	upl_t upl,
	vm_map_offset_t page_mask);
extern vm_object_offset_t upl_adjusted_offset(
	upl_t upl,
	vm_map_offset_t page_mask);
extern vm_object_offset_t upl_get_data_offset(
	upl_t upl);

extern kern_return_t vm_map_create_upl(
	vm_map_t                map,
	vm_map_address_t        offset,
	upl_size_t              *upl_size,
	upl_t                   *upl,
	upl_page_info_array_t   page_list,
	unsigned int            *count,
	upl_control_flags_t     *flags,
	vm_tag_t            tag);

extern void               vm_page_free_list(
	vm_page_t   mem,
	boolean_t   prepare_object);

extern kern_return_t vm_page_alloc_list(
	vm_size_t   page_count,
	kma_flags_t flags,
	vm_page_t  *list);
#if XNU_TARGET_OS_OSX
extern kern_return_t    vm_pageout_wait(uint64_t deadline);
#endif /* XNU_TARGET_OS_OSX */


#ifdef  MACH_KERNEL_PRIVATE

#include <vm/vm_page.h>

extern unsigned int     vm_pageout_scan_event_counter;
extern unsigned int     vm_page_anonymous_count;
extern thread_t         vm_pageout_scan_thread;
extern thread_t         vm_pageout_gc_thread;
extern sched_cond_atomic_t vm_pageout_gc_cond;

/*
 * must hold the page queues lock to
 * manipulate this structure
 */
struct vm_pageout_queue {
	vm_page_queue_head_t pgo_pending;  /* laundry pages to be processed by pager's iothread */
	unsigned int    pgo_laundry;       /* current count of laundry pages on queue or in flight */
	unsigned int    pgo_maxlaundry;

	uint32_t
	    pgo_busy:1,        /* iothread is currently processing request from pgo_pending */
	    pgo_throttled:1,   /* vm_pageout_scan thread needs a wakeup when pgo_laundry drops */
	    pgo_lowpriority:1, /* iothread is set to use low priority I/O */
	    pgo_draining:1,
	    pgo_inited:1,
	    pgo_unused_bits:26;
};

#define VM_PAGE_Q_THROTTLED(q)          \
	((q)->pgo_laundry >= (q)->pgo_maxlaundry)

extern struct   vm_pageout_queue        vm_pageout_queue_internal;
extern struct   vm_pageout_queue        vm_pageout_queue_external;

/*
 * This function is redeclared with slightly different parameter types in vfs_cluster.c
 * This should be fixed at a later time.
 */
extern void vector_upl_set_iostate(upl_t, upl_t, upl_offset_t, upl_size_t);

/*
 *	Routines exported to Mach.
 */
extern void             vm_pageout(void);

__startup_func extern void             vm_config_init(void);

extern kern_return_t    vm_pageout_internal_start(void);

extern void             vm_pageout_object_terminate(
	vm_object_t     object);

extern void             vm_pageout_cluster(
	vm_page_t       m);

extern void             vm_pageout_initialize_page(
	vm_page_t       m);


struct _vector_upl_iostates {
	upl_offset_t offset;
	upl_size_t   size;
};

typedef struct _vector_upl_iostates vector_upl_iostates_t;

struct _vector_upl {
	upl_size_t              size;
	uint32_t                num_upls;
	uint32_t                invalid_upls;
	uint32_t                max_upls;
	vm_map_t                submap;
	vm_offset_t             submap_dst_addr;
	vm_object_offset_t      offset;
	upl_page_info_array_t   pagelist;
	struct {
		upl_t                   elem;
		vector_upl_iostates_t   iostate;
	} upls[];
};

typedef struct _vector_upl* vector_upl_t;

/* universal page list structure */

#if UPL_DEBUG
#define UPL_DEBUG_COMMIT_RECORDS 4

struct ucd {
	upl_offset_t    c_beg;
	upl_offset_t    c_end;
	int             c_aborted;
	uint32_t        c_btref; /* btref_t */
};
#endif

struct upl_io_completion {
	void     *io_context;
	void     (*io_done)(void *, int);

	int      io_error;
};


struct upl {
	decl_lck_mtx_data(, Lock);      /* Synchronization */
	int             ref_count;
	int             ext_ref_count;
	int             flags;
	ctid_t          map_addr_owner; /* owning thread for upl_map_range */
	/*
	 * XXX CAUTION: to accomodate devices with "mixed page sizes",
	 * u_offset and u_size are now byte-aligned and no longer
	 * page-aligned, on all devices.
	 */
	vm_object_offset_t u_offset;
	upl_size_t      u_size;       /* size in bytes of the address space */
	upl_size_t      u_mapped_size;       /* size in bytes of the UPL that is mapped */
	vm_offset_t     kaddr;      /* secondary mapping in kernel */
	vm_object_t     map_object;
	vector_upl_t    vector_upl;
	upl_t           associated_upl;
	struct upl_io_completion *upl_iodone;
	ppnum_t         highest_page;
#if CONFIG_IOSCHED
	int             upl_priority;
	uint64_t        *upl_reprio_info;
	void            *decmp_io_upl;
#endif
#if CONFIG_IOSCHED || UPL_DEBUG
	thread_t        upl_creator;
	queue_chain_t   uplq;       /* List of outstanding upls on an obj */
#endif
#if     UPL_DEBUG
	uintptr_t       ubc_alias1;
	uintptr_t       ubc_alias2;

	uint32_t        upl_state;
	uint32_t        upl_commit_index;
	uint32_t        upl_create_btref; /* btref_t */

	struct  ucd     upl_commit_records[UPL_DEBUG_COMMIT_RECORDS];
#endif  /* UPL_DEBUG */

	bitmap_t       *lite_list;
	struct upl_page_info page_list[];
};

/* upl struct flags */
#define UPL_PAGE_LIST_MAPPED    0x1
#define UPL_KERNEL_MAPPED       0x2
#define UPL_CLEAR_DIRTY         0x4
#define UPL_COMPOSITE_LIST      0x8
#define UPL_INTERNAL            0x10
#define UPL_PAGE_SYNC_DONE      0x20
#define UPL_DEVICE_MEMORY       0x40
#define UPL_PAGEOUT             0x80
#define UPL_LITE                0x100
#define UPL_IO_WIRE             0x200
#define UPL_ACCESS_BLOCKED      0x400
#define UPL_SHADOWED            0x1000
#define UPL_KERNEL_OBJECT       0x2000
#define UPL_VECTOR              0x4000
#define UPL_SET_DIRTY           0x8000
#define UPL_HAS_BUSY            0x10000
#define UPL_TRACKED_BY_OBJECT   0x20000
#define UPL_EXPEDITE_SUPPORTED  0x40000
#define UPL_DECMP_REQ           0x80000
#define UPL_DECMP_REAL_IO       0x100000
#define UPL_MAP_EXCLUSIVE_WAIT  0x200000
#define UPL_HAS_WIRED           0x400000

/* flags for upl_create flags parameter */
#define UPL_CREATE_EXTERNAL     0
#define UPL_CREATE_INTERNAL     0x1
#define UPL_CREATE_LITE         0x2
#define UPL_CREATE_IO_TRACKING  0x4
#define UPL_CREATE_EXPEDITE_SUP 0x8

extern void vector_upl_deallocate(upl_t);
extern void vector_upl_set_submap(upl_t, vm_map_t, vm_offset_t);
extern void vector_upl_get_submap(upl_t, vm_map_t*, vm_offset_t*);
extern void vector_upl_get_iostate(upl_t, upl_t, upl_offset_t*, upl_size_t*);
extern void vector_upl_get_iostate_byindex(upl_t, uint32_t, upl_offset_t*, upl_size_t*);
extern upl_t vector_upl_subupl_byindex(upl_t, uint32_t);
extern upl_t vector_upl_subupl_byoffset(upl_t, upl_offset_t*, upl_size_t*);


extern void vm_page_free_reserve(int pages);

#endif  /* MACH_KERNEL_PRIVATE */


struct vm_pageout_state {
	boolean_t vm_pressure_thread_running;
	boolean_t vm_pressure_changed;
	boolean_t vm_restricted_to_single_processor;
	int vm_compressor_thread_count;

	unsigned int vm_page_speculative_q_age_ms;
	unsigned int vm_page_speculative_percentage;
	unsigned int vm_page_speculative_target;

	unsigned int vm_pageout_swap_wait;
	unsigned int vm_pageout_idle_wait;      /* milliseconds */
	unsigned int vm_pageout_empty_wait;     /* milliseconds */
	unsigned int vm_pageout_burst_wait;     /* milliseconds */
	unsigned int vm_pageout_deadlock_wait;  /* milliseconds */
	unsigned int vm_pageout_deadlock_relief;
	unsigned int vm_pageout_burst_inactive_throttle;

	unsigned int vm_pageout_inactive;
	unsigned int vm_pageout_inactive_used;  /* debugging */
	unsigned int vm_pageout_inactive_clean; /* debugging */

	uint32_t vm_page_filecache_min;
	uint32_t vm_page_filecache_min_divisor;
	uint32_t vm_page_xpmapped_min;
	uint32_t vm_page_xpmapped_min_divisor;
	uint64_t vm_pageout_considered_page_last;

	int vm_page_free_count_init;

	unsigned int vm_memory_pressure;

	int memorystatus_purge_on_critical;
	int memorystatus_purge_on_warning;
	int memorystatus_purge_on_urgent;

	thread_t vm_pageout_early_swapout_iothread;
};

extern struct vm_pageout_state vm_pageout_state;

/*
 * This structure is used to track the VM_INFO instrumentation
 */
struct vm_pageout_vminfo {
	unsigned long vm_pageout_considered_page;
	unsigned long vm_pageout_considered_bq_internal;
	unsigned long vm_pageout_considered_bq_external;
	unsigned long vm_pageout_skipped_external;
	unsigned long vm_pageout_skipped_internal;

	unsigned long vm_pageout_pages_evicted;
	unsigned long vm_pageout_pages_purged;
	unsigned long vm_pageout_freed_cleaned;
	unsigned long vm_pageout_freed_speculative;
	unsigned long vm_pageout_freed_external;
	unsigned long vm_pageout_freed_internal;
	unsigned long vm_pageout_inactive_dirty_internal;
	unsigned long vm_pageout_inactive_dirty_external;
	unsigned long vm_pageout_inactive_referenced;
	unsigned long vm_pageout_reactivation_limit_exceeded;
	unsigned long vm_pageout_inactive_force_reclaim;
	unsigned long vm_pageout_inactive_nolock;
	unsigned long vm_pageout_filecache_min_reactivated;
	unsigned long vm_pageout_scan_inactive_throttled_internal;
	unsigned long vm_pageout_scan_inactive_throttled_external;

	uint64_t      vm_pageout_compressions;
	uint64_t      vm_compressor_pages_grabbed;
	unsigned long vm_compressor_failed;

	unsigned long vm_page_pages_freed;

	unsigned long vm_phantom_cache_found_ghost;
	unsigned long vm_phantom_cache_added_ghost;

	unsigned long vm_pageout_protected_sharedcache;
	unsigned long vm_pageout_forcereclaimed_sharedcache;
	unsigned long vm_pageout_protected_realtime;
	unsigned long vm_pageout_forcereclaimed_realtime;

};

extern struct vm_pageout_vminfo vm_pageout_vminfo;

extern void vm_swapout_thread(void);

#if DEVELOPMENT || DEBUG

/*
 *	This structure records the pageout daemon's actions:
 *	how many pages it looks at and what happens to those pages.
 *	No locking needed because only one thread modifies the fields.
 */
struct vm_pageout_debug {
	uint32_t vm_pageout_balanced;
	uint32_t vm_pageout_scan_event_counter;
	uint32_t vm_pageout_speculative_dirty;

	uint32_t vm_pageout_inactive_busy;
	uint32_t vm_pageout_inactive_absent;
	uint32_t vm_pageout_inactive_notalive;
	uint32_t vm_pageout_inactive_error;
	uint32_t vm_pageout_inactive_deactivated;

	uint32_t vm_pageout_enqueued_cleaned;

	uint32_t vm_pageout_cleaned_busy;
	uint32_t vm_pageout_cleaned_nolock;
	uint32_t vm_pageout_cleaned_reference_reactivated;
	uint32_t vm_pageout_cleaned_volatile_reactivated;
	uint32_t vm_pageout_cleaned_reactivated;  /* debugging; how many cleaned pages are found to be referenced on pageout (and are therefore reactivated) */
	uint32_t vm_pageout_cleaned_fault_reactivated;

	uint32_t vm_pageout_dirty_no_pager;
	uint32_t vm_pageout_purged_objects;

	uint32_t vm_pageout_scan_throttle;
	uint32_t vm_pageout_scan_reclaimed_throttled;
	uint32_t vm_pageout_scan_burst_throttle;
	uint32_t vm_pageout_scan_empty_throttle;
	uint32_t vm_pageout_scan_swap_throttle;
	uint32_t vm_pageout_scan_deadlock_detected;
	uint32_t vm_pageout_scan_inactive_throttle_success;
	uint32_t vm_pageout_scan_throttle_deferred;

	uint32_t vm_pageout_inactive_external_forced_jetsam_count;

	uint32_t vm_grab_anon_overrides;
	uint32_t vm_grab_anon_nops;

	uint32_t vm_pageout_no_victim;
	uint32_t vm_pageout_yield_for_free_pages;
	unsigned long vm_pageout_throttle_up_count;
	uint32_t vm_page_steal_pageout_page;

	uint32_t vm_cs_validated_resets;
	uint32_t vm_object_iopl_request_sleep_for_cleaning;
	uint32_t vm_page_slide_counter;
	uint32_t vm_page_slide_errors;
	uint32_t vm_page_throttle_count;
	/*
	 * Statistics about UPL enforcement of copy-on-write obligations.
	 */
	unsigned long upl_cow;
	unsigned long upl_cow_again;
	unsigned long upl_cow_pages;
	unsigned long upl_cow_again_pages;
	unsigned long iopl_cow;
	unsigned long iopl_cow_pages;
};

extern struct vm_pageout_debug vm_pageout_debug;

#define VM_PAGEOUT_DEBUG(member, value)                 \
	MACRO_BEGIN                                     \
	        vm_pageout_debug.member += value;       \
	MACRO_END
#else /* DEVELOPMENT || DEBUG */
#define VM_PAGEOUT_DEBUG(member, value)
#endif /* DEVELOPMENT || DEBUG */

#define MAX_COMPRESSOR_THREAD_COUNT      8

/*
 * Forward declarations for internal routines.
 */

/*
 * Contains relevant state for pageout iothreads. Some state is unused by
 * external (file-backed) thread.
 */
struct pgo_iothread_state {
	struct vm_pageout_queue *q;
	// cheads unused by external thread
	void                    *current_early_swapout_chead;
	void                    *current_regular_swapout_chead;
	void                    *current_late_swapout_chead;
	char                    *scratch_buf;
	int                     id;
	thread_t                pgo_iothread; // holds a +1 ref
	sched_cond_atomic_t     pgo_wakeup;
#if DEVELOPMENT || DEBUG
	// for perf_compressor benchmark
	struct vm_pageout_queue *benchmark_q;
#endif /* DEVELOPMENT || DEBUG */
};

extern struct pgo_iothread_state pgo_iothread_internal_state[MAX_COMPRESSOR_THREAD_COUNT];

extern struct pgo_iothread_state pgo_iothread_external_state;

struct vm_compressor_swapper_stats {
	uint64_t unripe_under_30s;
	uint64_t unripe_under_60s;
	uint64_t unripe_under_300s;
	uint64_t reclaim_swapins;
	uint64_t defrag_swapins;
	uint64_t compressor_swap_threshold_exceeded;
	uint64_t external_q_throttled;
	uint64_t free_count_below_reserve;
	uint64_t thrashing_detected;
	uint64_t fragmentation_detected;
};
extern struct vm_compressor_swapper_stats vmcs_stats;

#if DEVELOPMENT || DEBUG
typedef struct vmct_stats_s {
	uint64_t vmct_runtimes[MAX_COMPRESSOR_THREAD_COUNT];
	uint64_t vmct_pages[MAX_COMPRESSOR_THREAD_COUNT];
	uint64_t vmct_iterations[MAX_COMPRESSOR_THREAD_COUNT];
	// total mach absolute time that compressor threads has been running
	uint64_t vmct_cthreads_total;
	int32_t vmct_minpages[MAX_COMPRESSOR_THREAD_COUNT];
	int32_t vmct_maxpages[MAX_COMPRESSOR_THREAD_COUNT];
} vmct_stats_t;

kern_return_t
run_compressor_perf_test(
	user_addr_t buf,
	size_t buffer_size,
	uint64_t *time,
	uint64_t *bytes_compressed,
	uint64_t *compressor_growth);

#endif /* DEVELOPMENT || DEBUG */

#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS

#endif  /* _VM_VM_PAGEOUT_XNU_H_ */
