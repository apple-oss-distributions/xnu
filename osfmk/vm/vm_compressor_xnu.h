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

#ifdef MACH_KERNEL_PRIVATE

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
#define C_SLOT_PACKED_PTR_BITS          33
#define C_SLOT_PACKED_PTR_SHIFT         2
#define C_SLOT_PACKED_PTR_BASE          ((uintptr_t)KERNEL_PMAP_HEAP_RANGE_START)

#define C_SLOT_C_SIZE_BITS              14
#define C_SLOT_C_CODEC_BITS             1
#define C_SLOT_C_POPCOUNT_BITS          0
#define C_SLOT_C_PADDING_BITS           0

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
    C_SLOT_C_CODEC_BITS + C_SLOT_C_POPCOUNT_BITS +
    C_SLOT_C_PADDING_BITS + C_SLOT_PACKED_PTR_BITS) % 32 == 0);

struct c_slot {
	uint64_t        c_offset:C_SEG_OFFSET_BITS __kernel_ptr_semantics;
	/* 0 means it's an empty slot
	 * 4 means it's a short-value that did not fit in the hash
	 * [5 : PAGE_SIZE-1] means it is normally compressed
	 * PAGE_SIZE means it was incompressible (see tag:WK-INCOMPRESSIBLE) */
	uint64_t        c_size:C_SLOT_C_SIZE_BITS;
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

#define C_IS_EMPTY              0  /* segment was just allocated and is going to start filling */
#define C_IS_FREE               1  /* segment is unused, went to the free-list, unallocated */
#define C_IS_FILLING            2
#define C_ON_AGE_Q              3
#define C_ON_SWAPOUT_Q          4
#define C_ON_SWAPPEDOUT_Q       5
#define C_ON_SWAPPEDOUTSPARSE_Q 6  /* segment is swapped-out but some of its slots were freed */
#define C_ON_SWAPPEDIN_Q        7
#define C_ON_MAJORCOMPACT_Q     8  /* we just did major compaction on this segment */
#define C_ON_BAD_Q              9
#define C_ON_SWAPIO_Q          10


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

	uint32_t        c_creation_ts;  /* time filling the segment has finished, used for checking if segment reached ripe age */
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
	uint32_t        c_agedin_ts;  /* time the seg got to age_q after being swapped in. used for stats*/
	uint32_t        c_swappedin_ts;
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
#if CONFIG_FREEZE
	    c_has_freezer_pages:1,
	    c_reserved:21;
#else /* CONFIG_FREEZE */
	c_reserved:22;
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

#define C_SEG_BUFFER_ADDRESS(c_segno)   ((c_buffers + ((uint64_t)c_segno * (uint64_t)c_seg_allocsize)))

#define C_SEG_SLOT_FROM_INDEX(cseg, index)      (index < c_seg_fixed_array_len ? &(cseg->c_slot_fixed_array[index]) : &(cseg->c_slot_var_array[index - c_seg_fixed_array_len]))

#define C_SEG_OFFSET_TO_BYTES(off)      ((off) * (int) sizeof(int32_t))
#define C_SEG_BYTES_TO_OFFSET(bytes)    ((bytes) / (int) sizeof(int32_t))

#define C_SEG_UNUSED_BYTES(cseg)        (cseg->c_bytes_unused + (C_SEG_OFFSET_TO_BYTES(cseg->c_populated_offset - cseg->c_nextoffset)))

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

#define C_SEG_SHOULD_MINORCOMPACT_NOW(cseg)     ((C_SEG_UNUSED_BYTES(cseg) >= (c_seg_bufsize / 4)) ? 1 : 0)

/*
 * the decsion to force a c_seg to be major compacted is based on 2 criteria
 * 1) is the c_seg buffer almost empty (i.e. we have a chance to merge it with another c_seg)
 * 2) are there at least a minimum number of slots unoccupied so that we have a chance
 *    of combining this c_seg with another one.
 */
#define C_SEG_SHOULD_MAJORCOMPACT_NOW(cseg)                                                                                     \
	((((cseg->c_bytes_unused + (c_seg_bufsize - C_SEG_OFFSET_TO_BYTES(c_seg->c_nextoffset))) >= (c_seg_bufsize / 8)) &&     \
	  ((C_SLOT_MAX_INDEX - cseg->c_slots_used) > (c_seg_bufsize / PAGE_SIZE))) \
	? 1 : 0)

#define C_SEG_ONDISK_IS_SPARSE(cseg)    ((cseg->c_bytes_used < cseg->c_bytes_unused) ? 1 : 0)
#define C_SEG_IS_ONDISK(cseg)           ((cseg->c_state == C_ON_SWAPPEDOUT_Q || cseg->c_state == C_ON_SWAPPEDOUTSPARSE_Q))
#define C_SEG_IS_ON_DISK_OR_SOQ(cseg)   ((cseg->c_state == C_ON_SWAPPEDOUT_Q || \
	                                  cseg->c_state == C_ON_SWAPPEDOUTSPARSE_Q || \
	                                  cseg->c_state == C_ON_SWAPOUT_Q || \
	                                  cseg->c_state == C_ON_SWAPIO_Q))


#define C_SEG_WAKEUP_DONE(cseg)                         \
	MACRO_BEGIN                                     \
	assert((cseg)->c_busy);                         \
	(cseg)->c_busy = 0;                             \
	assert((cseg)->c_busy_for_thread != NULL);      \
	(cseg)->c_busy_for_thread = NULL;               \
	if ((cseg)->c_wanted) {                         \
	        (cseg)->c_wanted = 0;                   \
	        thread_wakeup((event_t) (cseg));        \
	}                                               \
	MACRO_END

#define C_SEG_BUSY(cseg)                                \
	MACRO_BEGIN                                     \
	assert((cseg)->c_busy == 0);                    \
	(cseg)->c_busy = 1;                             \
	assert((cseg)->c_busy_for_thread == NULL);      \
	(cseg)->c_busy_for_thread = current_thread();   \
	MACRO_END


extern vm_map_t compressor_map;

#if DEVELOPMENT || DEBUG
extern boolean_t write_protect_c_segs;
extern int vm_compressor_test_seg_wp;

#define C_SEG_MAKE_WRITEABLE(cseg)                      \
	MACRO_BEGIN                                     \
	if (write_protect_c_segs) {                     \
	        vm_map_protect(compressor_map,                  \
	                       (vm_map_offset_t)cseg->c_store.c_buffer,         \
	                       (vm_map_offset_t)&cseg->c_store.c_buffer[C_SEG_BYTES_TO_OFFSET(c_seg_allocsize)],\
	                       0, VM_PROT_READ | VM_PROT_WRITE);    \
	}                               \
	MACRO_END

#define C_SEG_WRITE_PROTECT(cseg)                       \
	MACRO_BEGIN                                     \
	if (write_protect_c_segs) {                     \
	        vm_map_protect(compressor_map,                  \
	                       (vm_map_offset_t)cseg->c_store.c_buffer,         \
	                       (vm_map_offset_t)&cseg->c_store.c_buffer[C_SEG_BYTES_TO_OFFSET(c_seg_allocsize)],\
	                       0, VM_PROT_READ);                    \
	}                                                       \
	if (vm_compressor_test_seg_wp) {                                \
	        volatile uint32_t vmtstmp = *(volatile uint32_t *)cseg->c_store.c_buffer; \
	        *(volatile uint32_t *)cseg->c_store.c_buffer = 0xDEADABCD; \
	        (void) vmtstmp;                                         \
	}                                                               \
	MACRO_END
#endif /* DEVELOPMENT || DEBUG */

typedef struct c_segment *c_segment_t;
typedef struct c_slot   *c_slot_t;

void vm_decompressor_lock(void);
void vm_decompressor_unlock(void);
void vm_compressor_delay_trim(void);
void vm_compressor_do_warmup(void);

extern kern_return_t    vm_swap_get(c_segment_t, uint64_t, uint64_t);

extern uint32_t         c_age_count;
extern uint32_t         c_early_swapout_count, c_regular_swapout_count, c_late_swapout_count;
extern uint32_t         c_swappedout_count;
extern uint32_t         c_swappedout_sparse_count;

extern _Atomic uint64_t compressor_bytes_used;
extern uint32_t         swapout_target_age;

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

extern bool vm_swap_low_on_space(void);
extern bool vm_swap_out_of_space(void);

#define HIBERNATE_FLUSHING_SECS_TO_COMPLETE     120

#if DEVELOPMENT || DEBUG
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
uint32_t vm_compressor_pages_compressed(void);
void vm_compressor_process_special_swapped_in_segments(void);

#if DEVELOPMENT || DEBUG
__enum_closed_decl(vm_c_serialize_add_data_t, uint32_t, {
	VM_C_SERIALIZE_DATA_NONE,
});
kern_return_t vm_compressor_serialize_segment_debug_info(int segno, char *buf, size_t *size, vm_c_serialize_add_data_t with_data);
#endif /* DEVELOPMENT || DEBUG */

extern bool vm_compressor_low_on_space(void);
extern bool vm_compressor_compressed_pages_nearing_limit(void);
extern bool vm_compressor_out_of_space(void);


#endif /* _VM_VM_COMPRESSOR_XNU_H_ */
