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

#ifndef _VM_VM_COMPRESSOR_INTERNAL_H_
#define _VM_VM_COMPRESSOR_INTERNAL_H_

#include <stdbool.h>
#include <stdint.h>
#include <kern/locks.h>
#include <kern/thread.h>
#include <mach/boolean.h>
#include <sys/cdefs.h>
#include <vm/vm_compressor_xnu.h>

__BEGIN_DECLS
#if XNU_KERNEL_PRIVATE

#pragma mark Compressor Globals

__enum_decl(vm_compressor_config_t, uint32_t, {
	VM_PAGER_NOT_CONFIGURED       = 0x00, /* No compressor or swap */
	VM_PAGER_DEFAULT              = 0x01, /* Deprecated */
	VM_PAGER_COMPRESSOR_NO_SWAP   = 0x02, /* In-core compressor with no swap */
	VM_PAGER_COMPRESSOR_WITH_SWAP = 0x04, /* In-core compressor with swap-to-file */
	VM_PAGER_FREEZER_DEFAULT      = 0x08, /* Deprecated */
	VM_PAGER_FREEZER_NO_SWAP      = 0x10, /* Freezer backed by in-core compression */
	VM_PAGER_FREEZER_WITH_SWAP    = 0x20 /* Freezer backed by in-core compression + swap-to-file */
});

extern vm_compressor_config_t vm_compressor_mode;
extern boolean_t        vm_compressor_is_active;
extern boolean_t        vm_compressor_available;

extern boolean_t        fastwake_recording_in_progress;
extern int              compaction_swapper_inited;
extern int              compaction_swapper_running;
extern uint64_t         vm_swap_put_failures;

extern int              c_overage_swapped_count;
extern int              c_overage_swapped_limit;

extern queue_head_t     c_minor_list_head;
extern queue_head_t     c_age_list_head;
extern queue_head_t     c_major_list_head;
extern queue_head_t     c_early_swapout_list_head;
extern queue_head_t     c_regular_swapout_list_head;
extern queue_head_t     c_late_swapout_list_head;
extern queue_head_t     c_swappedout_list_head;
extern queue_head_t     c_swappedout_sparse_list_head;

extern uint64_t         first_c_segment_to_warm_generation_id;
extern uint64_t         last_c_segment_to_warm_generation_id;
extern boolean_t        hibernate_flushing;
extern boolean_t        hibernate_no_swapspace;
extern boolean_t        hibernate_in_progress_with_pinned_swap;
extern boolean_t        hibernate_flush_timed_out;

extern uint32_t        c_age_count;
extern uint32_t        c_early_swappedin_count, c_regular_swappedin_count, c_late_swappedin_count;
extern uint32_t        c_early_swapout_count, c_regular_swapout_count, c_late_swapout_count;
extern uint32_t        c_swappedout_count;
extern uint32_t        c_swappedout_sparse_count;
extern uint32_t        c_swapio_count;
extern uint32_t        c_minor_count;
extern uint32_t        c_major_count;
extern uint32_t        c_bad_count;
extern uint32_t        c_empty_count;
extern uint32_t        c_filling_count;
extern uint32_t        c_segment_count;
extern uint32_t        c_segments_nearing_limit;
extern uint32_t        c_segments_limit;

extern uint32_t        c_segment_pages_compressed;
extern uint32_t        c_segment_pages_compressed_nearing_limit;
extern uint32_t        c_segment_pages_compressed_limit;
#if CONFIG_FREEZE
extern bool            freezer_incore_cseg_acct;
#endif
extern int32_t         c_segment_pages_compressed_incore;
extern int32_t         c_segment_pages_compressed_incore_late_swapout;

extern uint32_t        c_segment_svp_in_hash;
extern uint32_t        c_segment_svp_hash_succeeded;
extern uint32_t        c_segment_svp_hash_failed;
extern uint32_t        c_segment_svp_zero_compressions;
extern uint32_t        c_segment_svp_nonzero_compressions;
extern uint32_t        c_segment_svp_zero_decompressions;
extern uint32_t        c_segment_svp_nonzero_decompressions;

extern bool            c_debug_events;

#if DEVELOPMENT || DEBUG
extern void vm_compressor_age_all_segments(uint64_t age_ns);
#endif /* DEVELOPMENT || DEBUG */

#if MACH_KERNEL_PRIVATE

#pragma mark Internal Compressor Functions

void vm_consider_waking_compactor_swapper(void);
void vm_consider_swapping(void);
void vm_compressor_flush(void);
void c_seg_free(c_segment_t);
void c_seg_free_locked(c_segment_t);
void c_seg_need_delayed_compaction(c_segment_t, boolean_t);
void c_seg_update_task_owner(c_segment_t, task_t);
void vm_compressor_record_warmup_start(void);
void vm_compressor_record_warmup_end(void);

int                     vm_wants_task_throttled(task_t);

extern void             vm_compaction_swapper_do_init(void);
extern void             vm_compressor_swap_init(void);
extern lck_rw_t         c_page_replacement_lock;

#if ENCRYPTED_SWAP
extern void             vm_swap_decrypt(c_segment_t, bool);
#endif /* ENCRYPTED_SWAP */

extern void             vm_swap_free(uint64_t);

extern void             c_seg_swapin_requeue(c_segment_t, boolean_t, boolean_t, boolean_t);
extern int              c_seg_swapin(c_segment_t, boolean_t, boolean_t);
extern void             c_seg_trim_tail(c_segment_t);
extern void             c_seg_switch_state(c_segment_t, int, boolean_t);

extern void c_seg_insert_into_q(queue_head_t *, c_segment_t);

__options_closed_decl(c_compact_options_t, uint32_t, {
	C_COMPACT_CLEAR_BUSY    = 0x01, /* Drop the busy bit on the segment before unlocking */
	C_COMPACT_LOCK_LIST     = 0x02, /* Re-lock the segment list before returning */
	C_COMPACT_NO_PG_REPLACE = 0x04, /* Disallow page replacement during compaction */
	C_COMPACT_NO_REQUEUE    = 0x08, /* Don't requeue major segments */
});

/*
 * @func c_seg_do_minor_comapction_and_unlock
 *
 * @brief Consolidates a segment's data, remove it from the minor compaction
 * queue, and unlock it.
 *
 * @param segment
 * The segment to compact
 *
 * @param opt
 * Options for compaction
 *
 * @returns true iff the segment was freed as a result of compaction.
 *
 * @discussion
 * By default, the segment and the segment list lock are dropped after
 * compaction is finished. If the caller needs to hold the list lock, it can
 * be reacquired by passing @c C_COMPACT_LOCK_LIST. The caller must hold both
 * the segment and the segment list locked as a precondition.
 *
 * It is assumed that the caller also has page replacement disabled, unless the
 * @c C_COMPACT_NO_PG_REPLACE flag is passed, in which case page replacement
 * is disabled for the duration of the compaction.
 *
 * If the caller wishes to drop the segment's busy bit before dropping the
 * segment lock, the @c C_COMPACT_CLEAR_BUSY flag may be passed.
 *
 * By default, the segment is re-queued for major compaction if it is on the
 * major queue and needs major compaction. This behavior can be bypassed by
 * passing the @c C_COMPACT_NO_REQUEUE flag.
 */
extern bool c_seg_do_minor_compaction_and_unlock(
	c_segment_t segment,
	c_compact_options_t opt);

uint32_t vm_compressor_get_encode_scratch_size(void) __pure2;
uint32_t vm_compressor_get_decode_scratch_size(void) __pure2;

#if RECORD_THE_COMPRESSED_DATA
extern void      c_compressed_record_init(void);
extern void      c_compressed_record_write(char *, int);
#endif

/*
 * @function c_seg_sleep
 *
 * @brief Sleep on a busy compressor segment
 *
 * @discussion
 * Caller must hold segment locked. @c c_seg_sleep() will drop the lock and
 * return with the segment unlocked. Scheduling priority is propagated to
 * the segment's owner via turnstile.
 *
 * @param segment
 * A busy compressor segment to wait for.
 */
extern void             c_seg_sleep(c_segment_t segment);

#pragma mark Compressor Macros

#define C_SEG_BUFFER_ADDRESS(c_segno)   ((c_buffers + ((uint64_t)c_segno * (uint64_t)c_seg_allocsize)))

#define C_SEG_SLOT_FROM_INDEX(cseg, index)      (index < c_seg_fixed_array_len ? &(cseg->c_slot_fixed_array[index]) : &(cseg->c_slot_var_array[index - c_seg_fixed_array_len]))

#define C_SEG_OFFSET_TO_BYTES(off)      ((off) * (int) sizeof(int32_t))
#define C_SEG_BYTES_TO_OFFSET(bytes)    ((bytes) / (int) sizeof(int32_t))

#define C_SEG_UNUSED_BYTES(cseg)        (cseg->c_bytes_unused + (C_SEG_OFFSET_TO_BYTES(cseg->c_populated_offset - cseg->c_nextoffset)))

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

#define CDBG(event_id, ...) \
MACRO_BEGIN \
	if (__improbable(c_debug_events)) { \
	        KDBG(event_id, __VA_ARGS__); \
	} \
MACRO_END

#pragma mark Inline Helpers

/*
 * @function c_seg_wakeup_done
 *
 * @brief Clear the busy bit on @c segment.
 *
 * @discussion
 * If segment is wanted by another thread, issue a wakeup and drop the
 * turnstile push.
 *
 * @param segment
 * The segment to un-busy.
 */
OS_INLINE
void
c_seg_wakeup_done(c_segment_t segment)
{
	LCK_MTX_ASSERT(&segment->c_lock, LCK_MTX_ASSERT_OWNED);
	assert(segment->c_busy);
	assert3p(segment->c_busy_for_thread, ==, current_thread());
	segment->c_busy = 0;
	segment->c_busy_for_thread = THREAD_NULL;
	bool wanted = segment->c_wanted;
	if (wanted) {
		segment->c_wanted = 0;
		wakeup_all_with_inheritor((event_t)segment, THREAD_AWAKENED);
	}
	KDBG(VM_COMPRESSOR_EVENTID(DBG_CSEG_BUSY) | DBG_FUNC_END,
	    VM_KERNEL_ADDRHIDE(segment), wanted);
}

/*
 * @function c_seg_mark_busy
 *
 * @brief Set the busy bit on @c segment.
 *
 * @discussion
 * Segments undergoing compaction or swap in/out must be marked busy to provide
 * mutual exclusion between these operations. Marking the segment as busy will
 * set the current thread as the owner of the segment so as to receive pushes
 * if other threads want the same segment. Segments should be un-busied via @c
 * c_seg_wakeup_done() once the busying operation is completed.
 *
 * @param segment
 * The segment to mark as busy.
 */
OS_INLINE
void
c_seg_mark_busy(c_segment_t segment)
{
	LCK_MTX_ASSERT(&segment->c_lock, LCK_MTX_ASSERT_OWNED);
	assert(segment->c_busy == 0);
	assert3p(segment->c_busy_for_thread, ==, THREAD_NULL);
	segment->c_busy = 1;
	segment->c_busy_for_thread = current_thread();
	KDBG(VM_COMPRESSOR_EVENTID(DBG_CSEG_BUSY) | DBG_FUNC_START,
	    VM_KERNEL_ADDRHIDE(segment));
}

/*
 * @function c_page_replacement_allowed_start
 *
 * @brief Acquire c_page_replacement_lock in exclusive mode.
 *
 * @discussion
 * Gives caller exclusive access to modify pages held by the compressor until
 * c_page_replacement_allowed_end() is called.
 */
OS_INLINE
void
c_page_replacement_allowed_start(void)
{
	lck_rw_lock_exclusive(&c_page_replacement_lock);
}

/*
 * @function c_page_replacement_allowed_end
 *
 * @brief Release c_page_replacement_lock.
 */
OS_INLINE
void
c_page_replacement_allowed_end(void)
{
	lck_rw_done(&c_page_replacement_lock);
}

/*
 * @function c_page_replacement_disallowed_start
 *
 * @brief Acquire c_page_replacement_lock in shared mode.
 *
 * @discussion
 * Guarantees that pages held by the compressor will not be modified until
 * c_page_replacement_disallowed_end() has been called.
 */
OS_INLINE
void
c_page_replacement_disallowed_start(void)
{
	lck_rw_lock_shared(&c_page_replacement_lock);
}

/*
 * @function c_page_replacement_disallowed_end
 *
 * @brief Release c_page_replacement_lock.
 */
OS_INLINE
void
c_page_replacement_disallowed_end(void)
{
	lck_rw_done(&c_page_replacement_lock);
}

#endif /* MACH_KERNEL_PRIVATE */
#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS
#endif /* _VM_VM_COMPRESSOR_INTERNAL_H_ */
