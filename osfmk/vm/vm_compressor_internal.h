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

#include <sys/cdefs.h>
#include <vm/vm_compressor_xnu.h>

__BEGIN_DECLS
#ifdef XNU_KERNEL_PRIVATE


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
extern lck_rw_t         c_master_lock;

#define PAGE_REPLACEMENT_DISALLOWED(enable)     (enable == TRUE ? lck_rw_lock_shared(&c_master_lock) : lck_rw_done(&c_master_lock))
#define PAGE_REPLACEMENT_ALLOWED(enable)        (enable == TRUE ? lck_rw_lock_exclusive(&c_master_lock) : lck_rw_done(&c_master_lock))

#if ENCRYPTED_SWAP
extern void             vm_swap_decrypt(c_segment_t);
#endif /* ENCRYPTED_SWAP */

extern void             vm_swap_free(uint64_t);

extern void             c_seg_swapin_requeue(c_segment_t, boolean_t, boolean_t, boolean_t);
extern int              c_seg_swapin(c_segment_t, boolean_t, boolean_t);
extern void             c_seg_wait_on_busy(c_segment_t);
extern void             c_seg_trim_tail(c_segment_t);
extern void             c_seg_switch_state(c_segment_t, int, boolean_t);


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

extern void c_seg_insert_into_q(queue_head_t *, c_segment_t);

extern uint64_t vm_compressor_compute_elapsed_msecs(clock_sec_t, clock_nsec_t, clock_sec_t, clock_nsec_t);

uint32_t vm_compressor_get_encode_scratch_size(void) __pure2;
uint32_t vm_compressor_get_decode_scratch_size(void) __pure2;

#if RECORD_THE_COMPRESSED_DATA
extern void      c_compressed_record_init(void);
extern void      c_compressed_record_write(char *, int);
#endif


#endif /* XNU_KERNEL_PRIVATE */
__END_DECLS
#endif /* _VM_VM_COMPRESSOR_INTERNAL_H_ */
