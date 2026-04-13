/*
 * Copyright (c) 2000-2016 Apple Inc. All rights reserved.
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
#ifndef _VM_VM_COMPRESSOR_XNU_H_
#define _VM_VM_COMPRESSOR_XNU_H_
#include <stdbool.h>
#include <stdint.h>

#if MACH_KERNEL_PRIVATE

#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_protos.h>
#include <vm/WKdm_new.h>
#include <vm/vm_object_xnu.h>
#include <vm/vm_map.h>
#include <machine/pmap.h>
#include <kern/locks.h>

#include <sys/kdebug.h>

#if defined(__arm64__)
#include <arm64/proc_reg.h>
#endif

#if HAS_MTE
#include <arm64/mte_xnu.h>
#endif

#define C_SEG_OFFSET_BITS       16

#define C_SEG_MAX_POPULATE_SIZE (4 * PAGE_SIZE)

#if defined(__arm64__) && (DEVELOPMENT || DEBUG)

#if defined(XNU_PLATFORM_WatchOS)
#define VALIDATE_C_SEGMENTS (1)
#endif
#endif /* defined(__arm64__) && (DEVELOPMENT || DEBUG) */


#if DEBUG || COMPRESSOR_INTEGRITY_CHECKS
#define ENABLE_SWAP_CHECKS 1
#define ENABLE_COMPRESSOR_CHECKS 1
#define POPCOUNT_THE_COMPRESSED_DATA (1)
#else
#define ENABLE_SWAP_CHECKS 0
#define ENABLE_COMPRESSOR_CHECKS 0
#endif

#define CHECKSUM_THE_SWAP               ENABLE_SWAP_CHECKS              /* Debug swap data */
#define CHECKSUM_THE_DATA               ENABLE_COMPRESSOR_CHECKS        /* Debug compressor/decompressor data */
#define CHECKSUM_THE_COMPRESSED_DATA    ENABLE_COMPRESSOR_CHECKS        /* Debug compressor/decompressor compressed data */

#ifndef VALIDATE_C_SEGMENTS
#define VALIDATE_C_SEGMENTS             ENABLE_COMPRESSOR_CHECKS        /* Debug compaction */
#endif

#define RECORD_THE_COMPRESSED_DATA      0
#define TRACK_C_SEGMENT_UTILIZATION     0

/*
 * The c_slot structure embeds a packed pointer to a c_slot_mapping
 * (32bits) which we ideally want to span as much VA space as possible
 * to not limit zalloc in how it sets itself up.
 */
#if !defined(__LP64__)                  /* no packing */
#define C_SLOT_PACKED_PTR_BITS          32
#define C_SLOT_PACKED_PTR_SHIFT         0
#define C_SLOT_PACKED_PTR_BASE          0

#define C_SLOT_C_SIZE_BITS              12
#define C_SLOT_C_CODEC_BITS             1
#define C_SLOT_C_POPCOUNT_BITS          0
#define C_SLOT_C_PADDING_BITS           3

#elif defined(__arm64__)                /* 32G from the heap start */

#if HAS_MTE
#define C_MTE_SIZE                      MTE_SIZE_TO_ATAG_STORAGE(PAGE_SIZE)
#define C_SLOT_EXTRA_METADATA           16            /* 16 possible tags */
#define C_SLOT_C_MTE_SIZE_BITS          10            /* ceil(log2(C_MTE_SIZE + C_SLOT_EXTRA_METADATA))  */
#define C_SLOT_C_MTE_SIZE_MAX           (C_MTE_SIZE + C_SLOT_EXTRA_METADATA + 1)
#define C_SLOT_C_PADDING_BITS           22
#else /* !HAS_MTE */
#define C_SLOT_C_PADDING_BITS           0
#endif /* HAS_MTE */

#define C_SLOT_PACKED_PTR_BITS          33
#define C_SLOT_PACKED_PTR_SHIFT         2
#define C_SLOT_PACKED_PTR_BASE          ((uintptr_t)KERNEL_PMAP_HEAP_RANGE_START)

#define C_SLOT_C_SIZE_BITS              14
#define C_SLOT_C_CODEC_BITS             1
#define C_SLOT_C_POPCOUNT_BITS          0

#elif defined(__x86_64__)               /* 256G from the heap start */
#define C_SLOT_PACKED_PTR_BITS          36
#define C_SLOT_PACKED_PTR_SHIFT         2
#define C_SLOT_PACKED_PTR_BASE          ((uintptr_t)KERNEL_PMAP_HEAP_RANGE_START)

#define C_SLOT_C_SIZE_BITS              12
#define C_SLOT_C_CODEC_BITS             0 /* not used */
#define C_SLOT_C_POPCOUNT_BITS          0
#define C_SLOT_C_PADDING_BITS           0

#else
#error vm_compressor parameters undefined for this architecture
#endif

/*
 * Popcounts needs to represent both 0 and full which requires
 * (8 ^ C_SLOT_C_SIZE_BITS) + 1 values and (C_SLOT_C_SIZE_BITS + 4) bits.
 *
 * We us the (2 * (8 ^ C_SLOT_C_SIZE_BITS) - 1) value to mean "unknown".
 */
#define C_SLOT_NO_POPCOUNT              ((16u << C_SLOT_C_SIZE_BITS) - 1)

static_assert((C_SEG_OFFSET_BITS + C_SLOT_C_SIZE_BITS +
#if HAS_MTE
    C_SLOT_C_MTE_SIZE_BITS +
#endif
    C_SLOT_C_CODEC_BITS + C_SLOT_C_POPCOUNT_BITS +
    C_SLOT_C_PADDING_BITS + C_SLOT_PACKED_PTR_BITS) % 32 == 0);

struct c_slot {
	uint64_t        c_offset:C_SEG_OFFSET_BITS __kernel_ptr_semantics;
	/* 0 means it's an empty slot
	 * 4 means it's a short-value that did not fit in the hash
	 * [5 : PAGE_SIZE-1] means it is normally compressed
	 * PAGE_SIZE means it was incompressible (see tag:WK-INCOMPRESSIBLE) */
	uint64_t        c_size:C_SLOT_C_SIZE_BITS;
#if HAS_MTE
	/* 0 means there are no MTE
	 * [1 : C_MTE_SIZE-1] means normally compressed tags
	 * C_MTE_SIZE means incompressible tags
	 * [C_MTE_SIZE + 1 : C_SLOT_C_MTE_SIZE_MAX] means single-tag and encodes the tag */
	uint64_t        c_mte_size:C_SLOT_C_MTE_SIZE_BITS;
#endif /* HAS_MTE */
#if C_SLOT_C_CODEC_BITS
	uint64_t        c_codec:C_SLOT_C_CODEC_BITS;
#endif
#if C_SLOT_C_POPCOUNT_BITS
	/*
	 * This value may not agree with c_pop_cdata, as it may be the
	 * population count of the uncompressed data.
	 *
	 * This value must be C_SLOT_NO_POPCOUNT when the compression algorithm
	 * cannot provide it.
	 */
	uint32_t        c_inline_popcount:C_SLOT_C_POPCOUNT_BITS;
#endif
#if C_SLOT_C_PADDING_BITS
	uint64_t        c_padding:C_SLOT_C_PADDING_BITS;
#endif
	uint64_t        c_packed_ptr:C_SLOT_PACKED_PTR_BITS __kernel_ptr_semantics; /* points back to the c_slot_mapping_t in the pager */

	/* debugging fields, typically not present on release kernels */
#if CHECKSUM_THE_DATA
	unsigned int    c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	unsigned int    c_hash_compressed_data;
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
	unsigned int    c_pop_cdata;
#endif
} __attribute__((packed, aligned(4)));

__enum_closed_decl(c_state_t, uint8_t, {
	C_IS_EMPTY = 0,  /* segment was just allocated and is going to start filling */
	C_IS_FREE = 1,  /* segment is unused, went to the free-list, unallocated */
	C_IS_FILLING = 2,
	C_ON_AGE_Q = 3,
	C_ON_SWAPOUT_Q = 4,
	C_ON_SWAPPEDOUT_Q = 5,
	C_ON_SWAPPEDOUTSPARSE_Q = 6,  /* segment is swapped-out but some of its slots were freed */
	C_ON_SWAPPEDIN_Q = 7,
	C_ON_MAJORCOMPACT_Q = 8,  /* we just did major compaction on this segment */
	C_ON_BAD_Q = 9,
	C_ON_SWAPIO_Q = 10,
	C_STATE_MAX = C_ON_SWAPIO_Q,
});

static_assert(C_STATE_MAX < 0x10, "segment state must fit in c_state bits");

struct c_segment {
	lck_mtx_t       c_lock;
	queue_chain_t   c_age_list;  /* chain of the main queue this c_segment is in */
	queue_chain_t   c_list;      /* chain of c_minor_list_head, if c_on_minorcompact_q==1 */

#if CONFIG_FREEZE
	queue_chain_t   c_task_list_next_cseg;
	task_t          c_task_owner;
#endif /* CONFIG_FREEZE */

#define C_SEG_MAX_LIMIT         (UINT_MAX)       /* this needs to track the size of c_mysegno */
	uint32_t        c_mysegno;  /* my index in c_segments */

	uint32_t        c_creation_ts;  /* time (in seconds) filling the segment has finished, used for checking if segment reached ripe age */
	uint64_t        c_generation_id;  /* a unique id of a single lifetime of a segment */

	int32_t         c_bytes_used;
	int32_t         c_bytes_unused;
	uint32_t        c_slots_used;

	uint16_t        c_firstemptyslot;  /* index of lowest empty slot. used for instance in minor compaction to not have to start from 0 */
	uint16_t        c_nextslot;        /* index of the next available slot in either c_slot_fixed_array or c_slot_var_array */
	uint32_t        c_nextoffset;      /* next available position in the buffer space pointed by c_store.c_buffer */
	uint32_t        c_populated_offset; /* how much of the segment is populated from it's beginning */
	/* c_nextoffset and c_populated_offset count ints, not bytes
	 * Invariants: - (c_nextoffset <= c_populated_offset) always
	 *             - c_nextoffset is rounded to WKDM alignment
	 *             - c_populated_offset is in quanta of PAGE_SIZE/sizeof(int) */

	union {
		int32_t *c_buffer;
		uint64_t c_swap_handle;  /* this is populated if C_SEG_IS_ONDISK()  */
	} c_store;

#if     VALIDATE_C_SEGMENTS
	uint32_t        c_was_minor_compacted;
	uint32_t        c_was_major_compacted;
	uint32_t        c_was_major_donor;
#endif
#if CHECKSUM_THE_SWAP
	unsigned int    cseg_hash;
	unsigned int    cseg_swap_size;
#endif /* CHECKSUM_THE_SWAP */

	thread_t        c_busy_for_thread;
	uint32_t        c_agedin_ts;  /* time (in sec) the seg got to age_q after being swapped in. used for stats*/
	uint32_t        c_swappedin_ts; /* time (in sec) the seg was swapped in */
	bool            c_swappedin;
#if TRACK_C_SEGMENT_UTILIZATION
	uint32_t        c_decompressions_since_swapin;
#endif /* TRACK_C_SEGMENT_UTILIZATION */
	/*
	 * Do not pull c_swappedin above into the bitfield below.
	 * We update it without always taking the segment
	 * lock and rely on the segment being busy instead.
	 * The bitfield needs the segment lock. So updating
	 * this state, if in the bitfield, without the lock
	 * will race with the updates to the other fields and
	 * result in a mess.
	 */
	uint32_t        c_busy:1,
	    c_busy_swapping:1,
	    c_wanted:1,
	    c_on_minorcompact_q:1,              /* can also be on the age_q, the majorcompact_q or the swappedin_q */

	    c_state:4,                          /* what state is the segment in which dictates which q to find it on */
	    c_overage_swap:1,
	    c_has_donated_pages:1,
	    c_swapout_reason:3,                 /* c_swapout_reason_t */
#if CONFIG_FREEZE
	    c_has_freezer_pages:1,
	    c_reserved:18;
#else /* CONFIG_FREEZE */
	c_reserved:19;
#endif /* CONFIG_FREEZE */

	int             c_slot_var_array_len;  /* length of the allocated c_slot_var_array */
	struct  c_slot  *c_slot_var_array;     /* see C_SEG_SLOT_FROM_INDEX() */
	struct  c_slot  c_slot_fixed_array[0];
};

/*
 * the pager holds a buffer of this 32 bit sized object, one for each page in the vm_object,
 * to refer to a specific slot in a specific segment in the compressor
 */
struct  c_slot_mapping {
#if !CONFIG_TRACK_UNMODIFIED_ANON_PAGES
	uint32_t        s_cseg:22,      /* segment number + 1 */
	    s_cindx:10;                 /* index of slot in the segment, see also C_SLOT_MAX_INDEX */
	/* in the case of a single-value (sv) page, s_cseg==C_SV_CSEG_ID and s_cindx is the
	 * index into c_segment_sv_hash_table
	 */
#else /* !CONFIG_TRACK_UNMODIFIED_ANON_PAGES */
	uint32_t        s_cseg:21,      /* segment number + 1 */
	    s_cindx:10,                 /* index in the segment */
	    s_uncompressed:1;           /* This bit indicates that the page resides uncompressed in a swapfile.
	                                 * This can happen in 2 ways:-
	                                 * 1) Page used to be in the compressor, got decompressed, was not
	                                 * modified, and so was pushed uncompressed to a different swapfile on disk.
	                                 * 2) Page was in its uncompressed form in a swapfile on disk. It got swapped in
	                                 * but was not modified. As we are about to reclaim it, we notice that this bit
	                                 * is set in its current slot. And so we can safely toss this clean anonymous page
	                                 * because its copy exists on disk.
	                                 */
#endif /* !CONFIG_TRACK_UNMODIFIED_ANON_PAGES */
};
#define C_SLOT_MAX_INDEX        (1 << 10)

typedef struct c_slot_mapping *c_slot_mapping_t;


extern  int             c_seg_fixed_array_len;
extern  vm_offset_t     c_buffers;
extern _Atomic uint64_t c_segment_compressed_bytes;

#ifndef __PLATFORM_WKDM_ALIGNMENT_MASK__
#define C_SEG_OFFSET_ALIGNMENT_MASK     0x3ULL
#define C_SEG_OFFSET_ALIGNMENT_BOUNDARY 0x4
#else
#define C_SEG_OFFSET_ALIGNMENT_MASK     __PLATFORM_WKDM_ALIGNMENT_MASK__
#define C_SEG_OFFSET_ALIGNMENT_BOUNDARY __PLATFORM_WKDM_ALIGNMENT_BOUNDARY__
#endif

/* round an offset/size up to the next multiple the wkdm write alignment (64 byte) */
#define C_SEG_ROUND_TO_ALIGNMENT(offset) \
	(((offset) + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK)

extern vm_map_t compressor_map;

#if CONFIG_CSEG_MPROTECT
extern bool write_protect_c_segs;
extern int vm_compressor_test_seg_wp;

#define C_SEG_MAKE_WRITEABLE(cseg)                      \
	MACRO_BEGIN                                     \
	if (write_protect_c_segs) {                     \
	        kern_return_t krprot = vm_map_protect(compressor_map,                  \
	                       (vm_map_offset_t)cseg->c_store.c_buffer,         \
	                       (vm_map_offset_t)&cseg->c_store.c_buffer[C_SEG_BYTES_TO_OFFSET(c_seg_allocsize)],\
	                       0, VM_PROT_READ | VM_PROT_WRITE);    \
	        assert3u(krprot, ==, KERN_SUCCESS);          \
	}                               \
	MACRO_END

#define C_SEG_WRITE_PROTECT(cseg)                       \
	MACRO_BEGIN                                     \
	if (write_protect_c_segs) {                     \
	        kern_return_t krprot = vm_map_protect(compressor_map,                  \
	                       (vm_map_offset_t)cseg->c_store.c_buffer,         \
	                       (vm_map_offset_t)&cseg->c_store.c_buffer[C_SEG_BYTES_TO_OFFSET(c_seg_allocsize)],\
	                       0, VM_PROT_READ);                    \
	        assert3u(krprot, ==, KERN_SUCCESS);          \
	}                                                       \
	if (vm_compressor_test_seg_wp) {                                \
	        volatile uint32_t vmtstmp = *(volatile uint32_t *)cseg->c_store.c_buffer; \
	        *(volatile uint32_t *)cseg->c_store.c_buffer = 0xDEADABCD; \
	        (void) vmtstmp;                                         \
	}                                                               \
	MACRO_END
#else /* !CONFIG_CSEG_MPROTECT */
#define C_SEG_MAKE_WRITEABLE(cseg)
#define C_SEG_WRITE_PROTECT(cseg)
#endif /* CONFIG_CSEG_MPROTECT */

typedef struct c_segment *c_segment_t;
typedef struct c_slot   *c_slot_t;

void vm_decompressor_lock(void);
void vm_decompressor_unlock(void);
void vm_compressor_delay_trim(void);
void vm_compressor_do_warmup(void);

extern uint32_t vm_compressor_minorcompact_threshold_divisor;
extern uint32_t vm_compressor_majorcompact_threshold_divisor;
extern uint32_t vm_compressor_unthrottle_threshold_divisor;
extern uint32_t vm_compressor_catchup_threshold_divisor;

extern uint32_t vm_compressor_minorcompact_threshold_divisor_overridden;
extern uint32_t vm_compressor_majorcompact_threshold_divisor_overridden;
extern uint32_t vm_compressor_unthrottle_threshold_divisor_overridden;
extern uint32_t vm_compressor_catchup_threshold_divisor_overridden;

struct vm_compressor_kdp_state {
	char           *kc_scratch_bufs;
	char           *kc_decompressed_pages;
	addr64_t       *kc_decompressed_pages_paddr;
	ppnum_t        *kc_decompressed_pages_ppnum;
	char           *kc_panic_scratch_buf;
	char           *kc_panic_decompressed_page;
	addr64_t        kc_panic_decompressed_page_paddr;
	ppnum_t         kc_panic_decompressed_page_ppnum;
};
extern struct vm_compressor_kdp_state vm_compressor_kdp_state;

extern void kdp_compressor_busy_find_owner(event64_t wait_event, thread_waitinfo_t *waitinfo);
extern kern_return_t vm_compressor_kdp_init(void);
extern void vm_compressor_kdp_teardown(void);

/*
 * TODO, there may be a minor optimisation opportunity to replace these divisions
 * with multiplies and shifts
 *
 * By multiplying by 10, the divisors can have more precision w/o resorting to floating point... a divisor specified as 25 is in reality a divide by 2.5
 * By multiplying by 9, you get a number ~11% smaller which allows us to have another limit point derived from the same base
 * By multiplying by 11, you get a number ~10% bigger which allows us to generate a reset limit derived from the same base which is useful for hysteresis
 */

#define VM_PAGE_COMPRESSOR_COMPACT_THRESHOLD            (((AVAILABLE_MEMORY) * 10) / (vm_compressor_minorcompact_threshold_divisor ? vm_compressor_minorcompact_threshold_divisor : 10))
#define VM_PAGE_COMPRESSOR_SWAP_THRESHOLD               (((AVAILABLE_MEMORY) * 10) / (vm_compressor_majorcompact_threshold_divisor ? vm_compressor_majorcompact_threshold_divisor : 10))

#define VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD    (((AVAILABLE_MEMORY) * 10) / (vm_compressor_unthrottle_threshold_divisor ? vm_compressor_unthrottle_threshold_divisor : 10))
#define VM_PAGE_COMPRESSOR_SWAP_RETHROTTLE_THRESHOLD    (((AVAILABLE_MEMORY) * 11) / (vm_compressor_unthrottle_threshold_divisor ? vm_compressor_unthrottle_threshold_divisor : 11))

#define VM_PAGE_COMPRESSOR_SWAP_HAS_CAUGHTUP_THRESHOLD  (((AVAILABLE_MEMORY) * 11) / (vm_compressor_catchup_threshold_divisor ? vm_compressor_catchup_threshold_divisor : 11))
#define VM_PAGE_COMPRESSOR_SWAP_CATCHUP_THRESHOLD       (((AVAILABLE_MEMORY) * 10) / (vm_compressor_catchup_threshold_divisor ? vm_compressor_catchup_threshold_divisor : 10))
#define VM_PAGE_COMPRESSOR_HARD_THROTTLE_THRESHOLD      (((AVAILABLE_MEMORY) * 9) / (vm_compressor_catchup_threshold_divisor ? vm_compressor_catchup_threshold_divisor : 9))

#if !XNU_TARGET_OS_OSX
#define AVAILABLE_NON_COMPRESSED_MIN                    20000
#define COMPRESSOR_NEEDS_TO_SWAP()              (((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_THRESHOLD) || \
	                                          (AVAILABLE_NON_COMPRESSED_MEMORY < AVAILABLE_NON_COMPRESSED_MIN)) ? 1 : 0)
#else /* !XNU_TARGET_OS_OSX */
#define COMPRESSOR_NEEDS_TO_SWAP()              ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_THRESHOLD) ? 1 : 0)
#endif /* !XNU_TARGET_OS_OSX */

#define HARD_THROTTLE_LIMIT_REACHED()           ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_HARD_THROTTLE_THRESHOLD) ? 1 : 0)
#define SWAPPER_NEEDS_TO_UNTHROTTLE()           ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_UNTHROTTLE_THRESHOLD) ? 1 : 0)
#define SWAPPER_NEEDS_TO_RETHROTTLE()           ((AVAILABLE_NON_COMPRESSED_MEMORY > VM_PAGE_COMPRESSOR_SWAP_RETHROTTLE_THRESHOLD) ? 1 : 0)
#define SWAPPER_NEEDS_TO_CATCHUP()              ((AVAILABLE_NON_COMPRESSED_MEMORY < VM_PAGE_COMPRESSOR_SWAP_CATCHUP_THRESHOLD) ? 1 : 0)
#define SWAPPER_HAS_CAUGHTUP()                  ((AVAILABLE_NON_COMPRESSED_MEMORY > VM_PAGE_COMPRESSOR_SWAP_HAS_CAUGHTUP_THRESHOLD) ? 1 : 0)


#if !XNU_TARGET_OS_OSX
#define COMPRESSOR_FREE_RESERVED_LIMIT          28
#else /* !XNU_TARGET_OS_OSX */
#define COMPRESSOR_FREE_RESERVED_LIMIT          128
#endif /* !XNU_TARGET_OS_OSX */

#define COMPRESSOR_SCRATCH_BUF_SIZE vm_compressor_get_encode_scratch_size()

extern lck_mtx_t c_list_lock_storage;
#define          c_list_lock (&c_list_lock_storage)

#if DEVELOPMENT || DEBUG
extern uint32_t vm_ktrace_enabled;

#define VMKDBG(x, ...)          \
MACRO_BEGIN                     \
if (vm_ktrace_enabled) {        \
	KDBG(x, ## __VA_ARGS__);\
}                               \
MACRO_END

extern bool compressor_running_perf_test;
extern uint64_t compressor_perf_test_pages_processed;
#endif /* DEVELOPMENT || DEBUG */

#endif /* MACH_KERNEL_PRIVATE */

__enum_closed_decl(c_swapout_reason_t, uint8_t, {
	C_SWAPOUT_NONE     = 0x0,
	C_SWAPOUT_FREEZER  = 0x1,
	C_SWAPOUT_DONATE   = 0x2,
	C_SWAPOUT_RIPE     = 0x3,
	C_SWAPOUT_REG      = 0x4,
	C_SWAPOUT_DARKWAKE = 0x5,
	C_SWAPOUT_REASON_MAX = C_SWAPOUT_DARKWAKE,
});

static_assert(C_SWAPOUT_REASON_MAX < 0x8, "Swapout reason must fit in c_swapout_reason bits");

extern atomic_counter_t c_pages_swapped_by_reason[C_SWAPOUT_REASON_MAX + 1];
extern atomic_counter_t c_pages_swap_by_reason[C_SWAPOUT_REASON_MAX + 1];

extern _Atomic uint64_t compressor_bytes_used;
extern uint64_t swapout_target_age;
extern uint64_t c_segment_ripeness_age_s;

/*
 * @func vm_swap_low_on_space
 *
 * @brief Return true if the system is running low on swap space
 *
 * @discussion
 * Returns true if the number of free swapfile segments is low and we aren't
 * likely to be able to create another swapfile (e.g. because the swapfile
 * creation thread has failed to create a new swapfile).
 */
extern bool vm_swap_low_on_space(void);

/*
 * @func vm_swap_out_of_space
 *
 * @brief Return true if the system has totally exhausted it's swap space
 *
 * @discussion
 * Returns true iff all free swapfile segments have been exhausted and we aren't
 * able to create another swapfile (because we've reached the configured limit).
 * Unlike @c vm_swap_low_on_space(), @c vm_swap_out_of_space() will not return
 * true if the swapfile creation thread has failed in the recent past -- even
 * if we've run out of swapfile segments. This is because conditions may change
 * and allow for future creation of new swapfiles.
 */
extern bool vm_swap_out_of_space(void);

/*
 * @func vm_swapout_wakeup
 *
 * @brief Issue a wakeup to the VM_swapout thread.
 */
extern void vm_swapout_wakeup(void);

/*
 * @func vm_swapout_is_running
 *
 * @brief Return true iff the VM_swapout thread is already running or has
 * been issued a wakeup.
 */
extern bool vm_swapout_is_running(void);

#define HIBERNATE_FLUSHING_SECS_TO_COMPLETE     120

#if DEVELOPMENT || DEBUG
int do_cseg_wedge_setup(void);
int do_cseg_wedge_thread(void);
int do_cseg_unwedge_thread(void);
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
void task_disown_frozen_csegs(task_t owner_task);
#endif /* CONFIG_FREEZE */

void vm_wake_compactor_swapper(void);
extern void             vm_swap_consider_defragmenting(int);
void vm_run_compactor(void);
void vm_thrashing_jetsam_done(void);

uint32_t vm_compression_ratio(void);
uint32_t vm_compressor_pool_size(void);
uint32_t vm_compressor_fragmentation_level(void);
uint32_t vm_compressor_incore_fragmentation_wasted_pages(void);
bool vm_compressor_is_thrashing(void);
bool vm_compressor_swapout_is_ripe(void);
void vm_compressor_process_special_swapped_in_segments(void);
uint32_t vm_compressor_get_swapped_segment_count(void);

/*
 * Return the number of virtual pages which have been compressed. On systems
 * with the freezer, this includes only in-core pages.
 */
extern uint32_t vm_compressor_pages_compressed(void);

/*
 * Return the number of virtual pages whose data has been swapped to disk.
 */
extern uint32_t vm_compressor_pages_swapped(void);

#if DEVELOPMENT || DEBUG
__enum_closed_decl(vm_c_serialize_add_data_t, uint32_t, {
	VM_C_SERIALIZE_DATA_NONE,
#if HAS_MTE
	VM_C_SERIALIZE_DATA_TAGS,
#endif /* HAS_MTE */
});
kern_return_t vm_compressor_serialize_segment_debug_info(int segno, char *buf, size_t *size, vm_c_serialize_add_data_t with_data);
#endif /* DEVELOPMENT || DEBUG */

/*
 * @func vm_compressor_swapout_conditions_met
 * @brief Evaluate whether memory conditions are such that the system should
 * begin swapping to disk
 * @returns true iff the system should begin swapping
 */
extern bool vm_compressor_swapout_conditions_met(void);

extern bool vm_compressor_low_on_space(void);
extern bool vm_compressor_compressed_pages_nearing_limit(void);
extern bool vm_compressor_out_of_space(void);

#if HAS_MTE
// number of tagged pages ever sent to the compressor
SCALABLE_COUNTER_DECLARE(compressor_tagged_pages_compressed);
// different reasons why tagged pages were removed from the compressor
SCALABLE_COUNTER_DECLARE(compressor_tagged_pages_decompressed);
SCALABLE_COUNTER_DECLARE(compressor_tagged_pages_freed);
SCALABLE_COUNTER_DECLARE(compressor_tagged_pages_corrupted);
// current number of bytes taken by compressed tags in the compressor
SCALABLE_COUNTER_DECLARE(compressor_tags_overhead_bytes);
// current number of tagged pages that reside in the compressor
SCALABLE_COUNTER_DECLARE(compressor_tagged_pages);
// current number of tag storage pages composing the compressor pool
SCALABLE_COUNTER_DECLARE(compressor_tag_storage_pages_in_pool);
// current number of non-tag storage pages composing the compressor pool
SCALABLE_COUNTER_DECLARE(compressor_non_tag_storage_pages_in_pool);
// the following is a breakdown of tagged_pages_compressed
#if DEVELOPMENT || DEBUG
SCALABLE_COUNTER_DECLARE(compressor_tags_all_zero);
SCALABLE_COUNTER_DECLARE(compressor_tags_same_value);
SCALABLE_COUNTER_DECLARE(compressor_tags_below_align);
SCALABLE_COUNTER_DECLARE(compressor_tags_above_align);
SCALABLE_COUNTER_DECLARE(compressor_tags_incompressible);
#endif /* DEVELOPMENT || DEBUG */
#endif /* HAS_MTE */

#endif /* _VM_VM_COMPRESSOR_XNU_H_ */
