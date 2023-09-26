/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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

#include <vm/vm_compressor.h>

#if CONFIG_PHANTOM_CACHE
#include <vm/vm_phantom_cache.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_pageout.h>
#include <vm/memory_object.h>
#include <vm/vm_compressor_algorithms.h>
#include <vm/vm_compressor_backing_store.h>
#include <vm/vm_fault.h>
#include <vm/vm_protos.h>
#include <mach/mach_host.h>             /* for host_info() */
#if DEVELOPMENT || DEBUG
#include <kern/hvg_hypercall.h>
#endif
#include <kern/ledger.h>
#include <kern/policy_internal.h>
#include <kern/thread_group.h>
#include <san/kasan.h>
#include <os/log.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>

#if defined(__x86_64__)
#include <i386/misc_protos.h>
#endif
#if defined(__arm64__)
#include <arm/machine_routines.h>
#endif

#include <IOKit/IOHibernatePrivate.h>

/*
 * The segment buffer size is a tradeoff.
 * A larger buffer leads to faster I/O throughput, better compression ratios
 * (since fewer bytes are wasted at the end of the segment),
 * and less overhead (both in time and space).
 * However, a smaller buffer causes less swap when the system is overcommited
 * b/c a higher percentage of the swapped-in segment is definitely accessed
 * before it goes back out to storage.
 *
 * So on systems without swap, a larger segment is a clear win.
 * On systems with swap, the choice is murkier. Empirically, we've
 * found that a 64KB segment provides a better tradeoff both in terms of
 * performance and swap writes than a 256KB segment on systems with fast SSDs
 * and a HW compression block.
 */
#define C_SEG_BUFSIZE_ARM_SWAP (1024 * 64)
#if XNU_TARGET_OS_OSX && defined(__arm64__)
#define C_SEG_BUFSIZE_DEFAULT C_SEG_BUFSIZE_ARM_SWAP
#else
#define C_SEG_BUFSIZE_DEFAULT (1024 * 256)
#endif /* TARGET_OS_OSX && defined(__arm64__) */
uint32_t c_seg_bufsize;

uint32_t c_seg_max_pages, c_seg_off_limit, c_seg_allocsize, c_seg_slot_var_array_min_len;

extern boolean_t vm_darkwake_mode;
extern zone_t vm_page_zone;

#if DEVELOPMENT || DEBUG
/* sysctl defined in bsd/dev/arm64/sysctl.c */
int do_cseg_wedge_thread(void);
int do_cseg_unwedge_thread(void);
static event_t debug_cseg_wait_event = NULL;
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
bool freezer_incore_cseg_acct = TRUE; /* Only count incore compressed memory for jetsams. */
void task_disown_frozen_csegs(task_t owner_task);
#endif /* CONFIG_FREEZE */

#if POPCOUNT_THE_COMPRESSED_DATA
boolean_t popcount_c_segs = TRUE;

static inline uint32_t
vmc_pop(uintptr_t ins, int sz)
{
	uint32_t rv = 0;

	if (__probable(popcount_c_segs == FALSE)) {
		return 0xDEAD707C;
	}

	while (sz >= 16) {
		uint32_t rv1, rv2;
		uint64_t *ins64 = (uint64_t *) ins;
		uint64_t *ins642 = (uint64_t *) (ins + 8);
		rv1 = __builtin_popcountll(*ins64);
		rv2 = __builtin_popcountll(*ins642);
		rv += rv1 + rv2;
		sz -= 16;
		ins += 16;
	}

	while (sz >= 4) {
		uint32_t *ins32 = (uint32_t *) ins;
		rv += __builtin_popcount(*ins32);
		sz -= 4;
		ins += 4;
	}

	while (sz > 0) {
		char *ins8 = (char *)ins;
		rv += __builtin_popcount(*ins8);
		sz--;
		ins++;
	}
	return rv;
}
#endif

#if VALIDATE_C_SEGMENTS
boolean_t validate_c_segs = TRUE;
#endif
/*
 * vm_compressor_mode has a hierarchy of control to set its value.
 * boot-args are checked first, then device-tree, and finally
 * the default value that is defined below. See vm_fault_init() for
 * the boot-arg & device-tree code.
 */

#if !XNU_TARGET_OS_OSX

#if CONFIG_FREEZE
int     vm_compressor_mode = VM_PAGER_FREEZER_DEFAULT;
struct  freezer_context freezer_context_global;
#else /* CONFIG_FREEZE */
int     vm_compressor_mode = VM_PAGER_NOT_CONFIGURED;
#endif /* CONFIG_FREEZE */

#else /* !XNU_TARGET_OS_OSX */
int             vm_compressor_mode = VM_PAGER_COMPRESSOR_WITH_SWAP;

#endif /* !XNU_TARGET_OS_OSX */

TUNABLE(uint32_t, vm_compression_limit, "vm_compression_limit", 0);
int             vm_compressor_is_active = 0;
int             vm_compressor_available = 0;

extern uint64_t vm_swap_get_max_configured_space(void);
extern void     vm_pageout_io_throttle(void);
bool vm_compressor_swapout_is_ripe(void);

#if CHECKSUM_THE_DATA || CHECKSUM_THE_SWAP || CHECKSUM_THE_COMPRESSED_DATA
extern unsigned int hash_string(char *cp, int len);
static unsigned int vmc_hash(char *, int);
boolean_t checksum_c_segs = TRUE;

unsigned int
vmc_hash(char *cp, int len)
{
	if (__probable(checksum_c_segs == FALSE)) {
		return 0xDEAD7A37;
	}
	return hash_string(cp, len);
}
#endif

#define UNPACK_C_SIZE(cs)       ((cs->c_size == (PAGE_SIZE-1)) ? PAGE_SIZE : cs->c_size)
#define PACK_C_SIZE(cs, size)   (cs->c_size = ((size == PAGE_SIZE) ? PAGE_SIZE - 1 : size))


struct c_sv_hash_entry {
	union {
		struct  {
			uint32_t        c_sv_he_ref;
			uint32_t        c_sv_he_data;
		} c_sv_he;
		uint64_t        c_sv_he_record;
	} c_sv_he_un;
};

#define he_ref  c_sv_he_un.c_sv_he.c_sv_he_ref
#define he_data c_sv_he_un.c_sv_he.c_sv_he_data
#define he_record c_sv_he_un.c_sv_he_record

#define C_SV_HASH_MAX_MISS      32
#define C_SV_HASH_SIZE          ((1 << 10))
#define C_SV_HASH_MASK          ((1 << 10) - 1)

#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
#define C_SV_CSEG_ID            ((1 << 21) - 1)
#else /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */
#define C_SV_CSEG_ID            ((1 << 22) - 1)
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */


union c_segu {
	c_segment_t     c_seg;
	uintptr_t       c_segno;
};

#define C_SLOT_ASSERT_PACKABLE(ptr) \
	VM_ASSERT_POINTER_PACKABLE((vm_offset_t)(ptr), C_SLOT_PACKED_PTR);

#define C_SLOT_PACK_PTR(ptr) \
	VM_PACK_POINTER((vm_offset_t)(ptr), C_SLOT_PACKED_PTR)

#define C_SLOT_UNPACK_PTR(cslot) \
	(c_slot_mapping_t)VM_UNPACK_POINTER((cslot)->c_packed_ptr, C_SLOT_PACKED_PTR)

/* for debugging purposes */
SECURITY_READ_ONLY_EARLY(vm_packing_params_t) c_slot_packing_params =
    VM_PACKING_PARAMS(C_SLOT_PACKED_PTR);

uint32_t        c_segment_count = 0;
uint32_t        c_segment_count_max = 0;

uint64_t        c_generation_id = 0;
uint64_t        c_generation_id_flush_barrier;


#define         HIBERNATE_FLUSHING_SECS_TO_COMPLETE     120

boolean_t       hibernate_no_swapspace = FALSE;
boolean_t       hibernate_flush_timed_out = FALSE;
clock_sec_t     hibernate_flushing_deadline = 0;

#if RECORD_THE_COMPRESSED_DATA
char    *c_compressed_record_sbuf;
char    *c_compressed_record_ebuf;
char    *c_compressed_record_cptr;
#endif


queue_head_t    c_age_list_head;
queue_head_t    c_early_swappedin_list_head, c_regular_swappedin_list_head, c_late_swappedin_list_head;
queue_head_t    c_early_swapout_list_head, c_regular_swapout_list_head, c_late_swapout_list_head;
queue_head_t    c_swapio_list_head;
queue_head_t    c_swappedout_list_head;
queue_head_t    c_swappedout_sparse_list_head;
queue_head_t    c_major_list_head;
queue_head_t    c_filling_list_head;
queue_head_t    c_bad_list_head;

uint32_t        c_age_count = 0;
uint32_t        c_early_swappedin_count = 0, c_regular_swappedin_count = 0, c_late_swappedin_count = 0;
uint32_t        c_early_swapout_count = 0, c_regular_swapout_count = 0, c_late_swapout_count = 0;
uint32_t        c_swapio_count = 0;
uint32_t        c_swappedout_count = 0;
uint32_t        c_swappedout_sparse_count = 0;
uint32_t        c_major_count = 0;
uint32_t        c_filling_count = 0;
uint32_t        c_empty_count = 0;
uint32_t        c_bad_count = 0;


queue_head_t    c_minor_list_head;
uint32_t        c_minor_count = 0;

int             c_overage_swapped_count = 0;
int             c_overage_swapped_limit = 0;

int             c_seg_fixed_array_len;
union  c_segu   *c_segments;
vm_offset_t     c_buffers;
vm_size_t       c_buffers_size;
caddr_t         c_segments_next_page;
boolean_t       c_segments_busy;
uint32_t        c_segments_available;
uint32_t        c_segments_limit;
uint32_t        c_segments_nearing_limit;

uint32_t        c_segment_svp_in_hash;
uint32_t        c_segment_svp_hash_succeeded;
uint32_t        c_segment_svp_hash_failed;
uint32_t        c_segment_svp_zero_compressions;
uint32_t        c_segment_svp_nonzero_compressions;
uint32_t        c_segment_svp_zero_decompressions;
uint32_t        c_segment_svp_nonzero_decompressions;

uint32_t        c_segment_noncompressible_pages;

uint32_t        c_segment_pages_compressed = 0; /* Tracks # of uncompressed pages fed into the compressor */
#if CONFIG_FREEZE
int32_t         c_segment_pages_compressed_incore = 0; /* Tracks # of uncompressed pages fed into the compressor that are in memory */
int32_t         c_segment_pages_compressed_incore_late_swapout = 0; /* Tracks # of uncompressed pages fed into the compressor that are in memory and tagged for swapout */
uint32_t        c_segments_incore_limit = 0; /* Tracks # of segments allowed to be in-core. Based on compressor pool size */
#endif /* CONFIG_FREEZE */

uint32_t        c_segment_pages_compressed_limit;
uint32_t        c_segment_pages_compressed_nearing_limit;
uint32_t        c_free_segno_head = (uint32_t)-1;

uint32_t        vm_compressor_minorcompact_threshold_divisor = 10;
uint32_t        vm_compressor_majorcompact_threshold_divisor = 10;
uint32_t        vm_compressor_unthrottle_threshold_divisor = 10;
uint32_t        vm_compressor_catchup_threshold_divisor = 10;

uint32_t        vm_compressor_minorcompact_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_majorcompact_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_unthrottle_threshold_divisor_overridden = 0;
uint32_t        vm_compressor_catchup_threshold_divisor_overridden = 0;

#define         C_SEGMENTS_PER_PAGE     (PAGE_SIZE / sizeof(union c_segu))

LCK_GRP_DECLARE(vm_compressor_lck_grp, "vm_compressor");
LCK_RW_DECLARE(c_master_lock, &vm_compressor_lck_grp);
LCK_MTX_DECLARE(c_list_lock_storage, &vm_compressor_lck_grp);

boolean_t       decompressions_blocked = FALSE;

zone_t          compressor_segment_zone;
int             c_compressor_swap_trigger = 0;

uint32_t        compressor_cpus;
char            *compressor_scratch_bufs;
char            *kdp_compressor_scratch_buf;
char            *kdp_compressor_decompressed_page;
addr64_t        kdp_compressor_decompressed_page_paddr;
ppnum_t         kdp_compressor_decompressed_page_ppnum;

clock_sec_t     start_of_sample_period_sec = 0;
clock_nsec_t    start_of_sample_period_nsec = 0;
clock_sec_t     start_of_eval_period_sec = 0;
clock_nsec_t    start_of_eval_period_nsec = 0;
uint32_t        sample_period_decompression_count = 0;
uint32_t        sample_period_compression_count = 0;
uint32_t        last_eval_decompression_count = 0;
uint32_t        last_eval_compression_count = 0;

#define         DECOMPRESSION_SAMPLE_MAX_AGE            (60 * 30)

boolean_t       vm_swapout_ripe_segments = FALSE;
uint32_t        vm_ripe_target_age = (60 * 60 * 48);

uint32_t        swapout_target_age = 0;
uint32_t        age_of_decompressions_during_sample_period[DECOMPRESSION_SAMPLE_MAX_AGE];
uint32_t        overage_decompressions_during_sample_period = 0;


void            do_fastwake_warmup(queue_head_t *, boolean_t);
boolean_t       fastwake_warmup = FALSE;
boolean_t       fastwake_recording_in_progress = FALSE;
clock_sec_t     dont_trim_until_ts = 0;

uint64_t        c_segment_warmup_count;
uint64_t        first_c_segment_to_warm_generation_id = 0;
uint64_t        last_c_segment_to_warm_generation_id = 0;
boolean_t       hibernate_flushing = FALSE;

int64_t         c_segment_input_bytes __attribute__((aligned(8))) = 0;
int64_t         c_segment_compressed_bytes __attribute__((aligned(8))) = 0;
int64_t         compressor_bytes_used __attribute__((aligned(8))) = 0;

/* Keeps track of the most recent timestamp for when major compaction finished. */
mach_timespec_t major_compact_ts;

struct c_sv_hash_entry c_segment_sv_hash_table[C_SV_HASH_SIZE]  __attribute__ ((aligned(8)));

static void vm_compressor_swap_trigger_thread(void);
static void vm_compressor_do_delayed_compactions(boolean_t);
static void vm_compressor_compact_and_swap(boolean_t);
static void vm_compressor_process_regular_swapped_in_segments(boolean_t);
void vm_compressor_process_special_swapped_in_segments(void);
static void vm_compressor_process_special_swapped_in_segments_locked(void);

struct vm_compressor_swapper_stats vmcs_stats;

static void vm_compressor_process_major_segments(bool);
#if XNU_TARGET_OS_OSX
static void vm_compressor_take_paging_space_action(void);
#endif /* XNU_TARGET_OS_OSX */

void compute_swapout_target_age(void);

boolean_t c_seg_major_compact(c_segment_t, c_segment_t);
boolean_t c_seg_major_compact_ok(c_segment_t, c_segment_t);

int  c_seg_minor_compaction_and_unlock(c_segment_t, boolean_t);
int  c_seg_do_minor_compaction_and_unlock(c_segment_t, boolean_t, boolean_t, boolean_t);
void c_seg_try_minor_compaction_and_unlock(c_segment_t c_seg);

void c_seg_move_to_sparse_list(c_segment_t);
void c_seg_insert_into_q(queue_head_t *, c_segment_t);

uint64_t vm_available_memory(void);
uint64_t vm_compressor_pages_compressed(void);
uint32_t vm_compressor_pool_size(void);
uint32_t vm_compressor_fragmentation_level(void);
uint32_t vm_compression_ratio(void);

/*
 * indicate the need to do a major compaction if
 * the overall set of in-use compression segments
 * becomes sparse... on systems that support pressure
 * driven swapping, this will also cause swapouts to
 * be initiated.
 */
static inline bool
vm_compressor_needs_to_major_compact()
{
	uint32_t        incore_seg_count;

	incore_seg_count = c_segment_count - c_swappedout_count - c_swappedout_sparse_count;

	if ((c_segment_count >= (c_segments_nearing_limit / 8)) &&
	    ((incore_seg_count * c_seg_max_pages) - VM_PAGE_COMPRESSOR_COUNT) >
	    ((incore_seg_count / 8) * c_seg_max_pages)) {
		return true;
	}
	return false;
}


uint64_t
vm_available_memory(void)
{
	return ((uint64_t)AVAILABLE_NON_COMPRESSED_MEMORY) * PAGE_SIZE_64;
}


uint32_t
vm_compressor_pool_size(void)
{
	return VM_PAGE_COMPRESSOR_COUNT;
}

uint32_t
vm_compressor_fragmentation_level(void)
{
	const uint32_t incore_seg_count = c_segment_count - c_swappedout_count - c_swappedout_sparse_count;
	if ((incore_seg_count == 0) || (c_seg_max_pages == 0)) {
		return 0;
	}
	return 100 - (vm_compressor_pool_size() * 100 / (incore_seg_count * c_seg_max_pages));
}

uint32_t
vm_compression_ratio(void)
{
	if (vm_compressor_pool_size() == 0) {
		return UINT32_MAX;
	}
	return c_segment_pages_compressed / vm_compressor_pool_size();
}

uint64_t
vm_compressor_pages_compressed(void)
{
	return c_segment_pages_compressed * PAGE_SIZE_64;
}

bool
vm_compressor_compressed_pages_nearing_limit(void)
{
	uint32_t pages = 0;

#if CONFIG_FREEZE
	pages = os_atomic_load(&c_segment_pages_compressed_incore, relaxed);
#else /* CONFIG_FREEZE */
	pages = c_segment_pages_compressed;
#endif /* CONFIG_FREEZE */

	return pages > c_segment_pages_compressed_nearing_limit;
}

static bool
vm_compressor_segments_nearing_limit(void)
{
	uint64_t segments;

#if CONFIG_FREEZE
	if (freezer_incore_cseg_acct) {
		if (os_sub_overflow(c_segment_count, c_swappedout_count, &segments)) {
			segments = 0;
		}
		if (os_sub_overflow(segments, c_swappedout_sparse_count, &segments)) {
			segments = 0;
		}
	} else {
		segments = os_atomic_load(&c_segment_count, relaxed);
	}
#else /* CONFIG_FREEZE */
	segments = c_segment_count;
#endif /* CONFIG_FREEZE */

	return segments > c_segments_nearing_limit;
}

boolean_t
vm_compressor_low_on_space(void)
{
	return vm_compressor_compressed_pages_nearing_limit() ||
	       vm_compressor_segments_nearing_limit();
}


boolean_t
vm_compressor_out_of_space(void)
{
#if CONFIG_FREEZE
	uint64_t incore_seg_count;
	uint32_t incore_compressed_pages;
	if (freezer_incore_cseg_acct) {
		if (os_sub_overflow(c_segment_count, c_swappedout_count, &incore_seg_count)) {
			incore_seg_count = 0;
		}
		if (os_sub_overflow(incore_seg_count, c_swappedout_sparse_count, &incore_seg_count)) {
			incore_seg_count = 0;
		}
		incore_compressed_pages = os_atomic_load(&c_segment_pages_compressed_incore, relaxed);
	} else {
		incore_seg_count = os_atomic_load(&c_segment_count, relaxed);
		incore_compressed_pages = os_atomic_load(&c_segment_pages_compressed_incore, relaxed);
	}

	if ((incore_compressed_pages >= c_segment_pages_compressed_limit) ||
	    (incore_seg_count > c_segments_incore_limit)) {
		return TRUE;
	}
#else /* CONFIG_FREEZE */
	if ((c_segment_pages_compressed >= c_segment_pages_compressed_limit) ||
	    (c_segment_count >= c_segments_limit)) {
		return TRUE;
	}
#endif /* CONFIG_FREEZE */
	return FALSE;
}

bool
vm_compressor_is_thrashing()
{
	compute_swapout_target_age();

	if (swapout_target_age) {
		c_segment_t     c_seg;

		lck_mtx_lock_spin_always(c_list_lock);

		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t) queue_first(&c_age_list_head);

			if (c_seg->c_creation_ts > swapout_target_age) {
				swapout_target_age = 0;
			}
		}
		lck_mtx_unlock_always(c_list_lock);
	}

	return swapout_target_age != 0;
}


int
vm_wants_task_throttled(task_t task)
{
	ledger_amount_t compressed;
	if (task == kernel_task) {
		return 0;
	}

	if (VM_CONFIG_SWAP_IS_ACTIVE) {
		if ((vm_compressor_low_on_space() || HARD_THROTTLE_LIMIT_REACHED())) {
			ledger_get_balance(task->ledger, task_ledgers.internal_compressed, &compressed);
			compressed >>= VM_MAP_PAGE_SHIFT(task->map);
			if ((unsigned int)compressed > (c_segment_pages_compressed / 4)) {
				return 1;
			}
		}
	}
	return 0;
}


#if DEVELOPMENT || DEBUG
/*
 * On compressor/swap exhaustion, kill the largest process regardless of
 * its chosen process policy.
 */
TUNABLE(bool, kill_on_no_paging_space, "-kill_on_no_paging_space", false);
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_JETSAM
boolean_t       memorystatus_kill_on_VM_compressor_space_shortage(boolean_t);
void            memorystatus_thread_wake(void);
extern uint32_t jetsam_kill_on_low_swap;
bool            memorystatus_disable_swap(void);
#if CONFIG_PHANTOM_CACHE
extern bool memorystatus_phantom_cache_pressure;
#endif /* CONFIG_PHANTOM_CACHE */
int             compressor_thrashing_induced_jetsam = 0;
int             filecache_thrashing_induced_jetsam = 0;
static boolean_t        vm_compressor_thrashing_detected = FALSE;
#else  /* CONFIG_JETSAM */
static uint32_t no_paging_space_action_in_progress = 0;
extern void memorystatus_send_low_swap_note(void);
#endif /* CONFIG_JETSAM */

static void
vm_compressor_take_paging_space_action(void)
{
#if CONFIG_JETSAM
	/*
	 * On systems with both swap and jetsam,
	 * just wake up the jetsam thread and have it handle the low swap condition
	 * by killing apps.
	 */
	if (jetsam_kill_on_low_swap) {
		memorystatus_thread_wake();
	}
#else /* CONFIG_JETSAM */
	if (no_paging_space_action_in_progress == 0) {
		if (OSCompareAndSwap(0, 1, (UInt32 *)&no_paging_space_action_in_progress)) {
			if (no_paging_space_action()) {
#if DEVELOPMENT || DEBUG
				if (kill_on_no_paging_space) {
					/*
					 * Since we are choosing to always kill a process, we don't need the
					 * "out of application memory" dialog box in this mode. And, hence we won't
					 * send the knote.
					 */
					no_paging_space_action_in_progress = 0;
					return;
				}
#endif /* DEVELOPMENT || DEBUG */
				memorystatus_send_low_swap_note();
			}

			no_paging_space_action_in_progress = 0;
		}
	}
#endif /* !CONFIG_JETSAM */
}


void
vm_decompressor_lock(void)
{
	PAGE_REPLACEMENT_ALLOWED(TRUE);

	decompressions_blocked = TRUE;

	PAGE_REPLACEMENT_ALLOWED(FALSE);
}

void
vm_decompressor_unlock(void)
{
	PAGE_REPLACEMENT_ALLOWED(TRUE);

	decompressions_blocked = FALSE;

	PAGE_REPLACEMENT_ALLOWED(FALSE);

	thread_wakeup((event_t)&decompressions_blocked);
}

static inline void
cslot_copy(c_slot_t cdst, c_slot_t csrc)
{
#if CHECKSUM_THE_DATA
	cdst->c_hash_data = csrc->c_hash_data;
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	cdst->c_hash_compressed_data = csrc->c_hash_compressed_data;
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
	cdst->c_pop_cdata = csrc->c_pop_cdata;
#endif
	cdst->c_size = csrc->c_size;
	cdst->c_packed_ptr = csrc->c_packed_ptr;
#if defined(__arm64__)
	cdst->c_codec = csrc->c_codec;
#endif
}

#if XNU_TARGET_OS_OSX
#define VM_COMPRESSOR_MAX_POOL_SIZE (192UL << 30)
#else
#define VM_COMPRESSOR_MAX_POOL_SIZE (0)
#endif

static vm_map_size_t compressor_size;
static SECURITY_READ_ONLY_LATE(struct mach_vm_range) compressor_range;
vm_map_t compressor_map;
uint64_t compressor_pool_max_size;
uint64_t compressor_pool_size;
uint32_t compressor_pool_multiplier;

#if DEVELOPMENT || DEBUG
/*
 * Compressor segments are write-protected in development/debug
 * kernels to help debug memory corruption.
 * In cases where performance is a concern, this can be disabled
 * via the boot-arg "-disable_cseg_write_protection".
 */
boolean_t write_protect_c_segs = TRUE;
int vm_compressor_test_seg_wp;
uint32_t vm_ktrace_enabled;
#endif /* DEVELOPMENT || DEBUG */

#if (XNU_TARGET_OS_OSX && __arm64__)

#include <IOKit/IOPlatformExpert.h>
#include <sys/random.h>

static const char *csegbufsizeExperimentProperty = "_csegbufsz_experiment";
static thread_call_t csegbufsz_experiment_thread_call;

extern boolean_t IOServiceWaitForMatchingResource(const char * property, uint64_t timeout);
static void
erase_csegbufsz_experiment_property(__unused void *param0, __unused void *param1)
{
	// Wait for NVRAM to be writable
	if (!IOServiceWaitForMatchingResource("IONVRAM", UINT64_MAX)) {
		printf("csegbufsz_experiment_property: Failed to wait for IONVRAM.");
	}

	if (!PERemoveNVRAMProperty(csegbufsizeExperimentProperty)) {
		printf("csegbufsize_experiment_property: Failed to remove %s from NVRAM.", csegbufsizeExperimentProperty);
	}
	thread_call_free(csegbufsz_experiment_thread_call);
}

static void
erase_csegbufsz_experiment_property_async()
{
	csegbufsz_experiment_thread_call = thread_call_allocate_with_priority(
		erase_csegbufsz_experiment_property,
		NULL,
		THREAD_CALL_PRIORITY_LOW
		);
	if (csegbufsz_experiment_thread_call == NULL) {
		printf("csegbufsize_experiment_property: Unable to allocate thread call.");
	} else {
		thread_call_enter(csegbufsz_experiment_thread_call);
	}
}

static void
cleanup_csegbufsz_experiment(__unused void *arg0)
{
	char nvram = 0;
	unsigned int len = sizeof(nvram);
	if (PEReadNVRAMProperty(csegbufsizeExperimentProperty, &nvram, &len)) {
		erase_csegbufsz_experiment_property_async();
	}
}

STARTUP_ARG(EARLY_BOOT, STARTUP_RANK_FIRST, cleanup_csegbufsz_experiment, NULL);
#endif /* XNU_TARGET_OS_OSX && __arm64__ */

#if CONFIG_JETSAM
extern unsigned int memorystatus_swap_all_apps;
#endif /* CONFIG_JETSAM */

TUNABLE_DT(uint64_t, swap_vol_min_capacity, "/defaults", "kern.swap_min_capacity", "kern.swap_min_capacity", 0, TUNABLE_DT_NONE);

static void
vm_compressor_set_size(void)
{
	/*
	 * Note that this function may be called multiple times on systems with app swap
	 * because the value of vm_swap_get_max_configured_space() and memorystatus_swap_all_apps
	 * can change based the size of the swap volume. On these systems, we'll call
	 * this function once early in boot to reserve the maximum amount of VA required
	 * for the compressor submap and then one more time in vm_compressor_init after
	 * determining the swap volume size. We must not return a larger value the second
	 * time around.
	 */
	vm_size_t       c_segments_arr_size = 0;
	struct c_slot_mapping tmp_slot_ptr;

	/* The segment size can be overwritten by a boot-arg */
	if (!PE_parse_boot_argn("vm_compressor_segment_buffer_size", &c_seg_bufsize, sizeof(c_seg_bufsize))) {
#if CONFIG_JETSAM
		if (memorystatus_swap_all_apps) {
			c_seg_bufsize = C_SEG_BUFSIZE_ARM_SWAP;
		} else {
			c_seg_bufsize = C_SEG_BUFSIZE_DEFAULT;
		}
#else
		c_seg_bufsize = C_SEG_BUFSIZE_DEFAULT;
#endif /* CONFIG_JETSAM */
	}

	vm_compressor_swap_init_swap_file_limit();
	if (vm_compression_limit) {
		compressor_pool_size = ptoa_64(vm_compression_limit);
	}

	compressor_pool_max_size = C_SEG_MAX_LIMIT;
	compressor_pool_max_size *= c_seg_bufsize;

#if XNU_TARGET_OS_OSX

	if (vm_compression_limit == 0) {
		if (max_mem <= (4ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 16ULL * max_mem;
		} else if (max_mem <= (8ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 8ULL * max_mem;
		} else if (max_mem <= (32ULL * 1024ULL * 1024ULL * 1024ULL)) {
			compressor_pool_size = 4ULL * max_mem;
		} else {
			compressor_pool_size = 2ULL * max_mem;
		}
	}
	/*
	 * Cap the compressor pool size to a max of 192G
	 */
	if (compressor_pool_size > VM_COMPRESSOR_MAX_POOL_SIZE) {
		compressor_pool_size = VM_COMPRESSOR_MAX_POOL_SIZE;
	}
	if (max_mem <= (8ULL * 1024ULL * 1024ULL * 1024ULL)) {
		compressor_pool_multiplier = 1;
	} else if (max_mem <= (32ULL * 1024ULL * 1024ULL * 1024ULL)) {
		compressor_pool_multiplier = 2;
	} else {
		compressor_pool_multiplier = 4;
	}

#else

	if (compressor_pool_max_size > max_mem) {
		compressor_pool_max_size = max_mem;
	}

	if (vm_compression_limit == 0) {
		compressor_pool_size = max_mem;
	}

#if XNU_TARGET_OS_WATCH
	compressor_pool_multiplier = 2;
#elif XNU_TARGET_OS_IOS
	if (max_mem <= (2ULL * 1024ULL * 1024ULL * 1024ULL)) {
		compressor_pool_multiplier = 2;
	} else {
		compressor_pool_multiplier = 1;
	}
#else
	compressor_pool_multiplier = 1;
#endif

#endif

	PE_parse_boot_argn("kern.compressor_pool_multiplier", &compressor_pool_multiplier, sizeof(compressor_pool_multiplier));
	if (compressor_pool_multiplier < 1) {
		compressor_pool_multiplier = 1;
	}

	if (compressor_pool_size > compressor_pool_max_size) {
		compressor_pool_size = compressor_pool_max_size;
	}

	c_seg_max_pages = (c_seg_bufsize / PAGE_SIZE);
	c_seg_slot_var_array_min_len = c_seg_max_pages;

#if !defined(__x86_64__)
	c_seg_off_limit = (C_SEG_BYTES_TO_OFFSET((c_seg_bufsize - 512)));
	c_seg_allocsize = (c_seg_bufsize + PAGE_SIZE);
#else
	c_seg_off_limit = (C_SEG_BYTES_TO_OFFSET((c_seg_bufsize - 128)));
	c_seg_allocsize = c_seg_bufsize;
#endif /* !defined(__x86_64__) */

	c_segments_limit = (uint32_t)(compressor_pool_size / (vm_size_t)(c_seg_allocsize));
	tmp_slot_ptr.s_cseg = c_segments_limit;
	/* Panic on internal configs*/
	assertf((tmp_slot_ptr.s_cseg == c_segments_limit), "vm_compressor_init: overflowed s_cseg field in c_slot_mapping with c_segno: %d", c_segments_limit);

	if (tmp_slot_ptr.s_cseg != c_segments_limit) {
		tmp_slot_ptr.s_cseg = -1;
		c_segments_limit = tmp_slot_ptr.s_cseg - 1; /*limited by segment idx bits in c_slot_mapping*/
		compressor_pool_size = (c_segments_limit * (vm_size_t)(c_seg_allocsize));
	}

	c_segments_nearing_limit = (uint32_t)(((uint64_t)c_segments_limit * 98ULL) / 100ULL);

	c_segment_pages_compressed_limit = (c_segments_limit * (c_seg_bufsize / PAGE_SIZE) * compressor_pool_multiplier);

	if (c_segment_pages_compressed_limit < (uint32_t)(max_mem / PAGE_SIZE)) {
#if defined(XNU_TARGET_OS_WATCH)
		c_segment_pages_compressed_limit = (uint32_t)(max_mem / PAGE_SIZE);
#else
		if (!vm_compression_limit) {
			c_segment_pages_compressed_limit = (uint32_t)(max_mem / PAGE_SIZE);
		}
#endif
	}

	c_segment_pages_compressed_nearing_limit = (uint32_t)(((uint64_t)c_segment_pages_compressed_limit * 98ULL) / 100ULL);

#if CONFIG_FREEZE
	/*
	 * Our in-core limits are based on the size of the compressor pool.
	 * The c_segments_nearing_limit is also based on the compressor pool
	 * size and calculated above.
	 */
	c_segments_incore_limit = c_segments_limit;

	if (freezer_incore_cseg_acct) {
		/*
		 * Add enough segments to track all frozen c_segs that can be stored in swap.
		 */
		c_segments_limit += (uint32_t)(vm_swap_get_max_configured_space() / (vm_size_t)(c_seg_allocsize));
		tmp_slot_ptr.s_cseg = c_segments_limit;
		/* Panic on internal configs*/
		assertf((tmp_slot_ptr.s_cseg == c_segments_limit), "vm_compressor_init: freezer reserve overflowed s_cseg field in c_slot_mapping with c_segno: %d", c_segments_limit);
	}
#endif
	/*
	 * Submap needs space for:
	 * - c_segments
	 * - c_buffers
	 * - swap reclaimations -- c_seg_bufsize
	 */
	c_segments_arr_size = vm_map_round_page((sizeof(union c_segu) * c_segments_limit), VM_MAP_PAGE_MASK(kernel_map));
	c_buffers_size = vm_map_round_page(((vm_size_t)c_seg_allocsize * (vm_size_t)c_segments_limit), VM_MAP_PAGE_MASK(kernel_map));

	compressor_size = c_segments_arr_size + c_buffers_size + c_seg_bufsize;

#if RECORD_THE_COMPRESSED_DATA
	c_compressed_record_sbuf_size = (vm_size_t)c_seg_allocsize + (PAGE_SIZE * 2);
	compressor_size += c_compressed_record_sbuf_size;
#endif /* RECORD_THE_COMPRESSED_DATA */
}
STARTUP(KMEM, STARTUP_RANK_FIRST, vm_compressor_set_size);

KMEM_RANGE_REGISTER_DYNAMIC(compressor, &compressor_range, ^() {
	return compressor_size;
});

bool
osenvironment_is_diagnostics(void)
{
	DTEntry chosen;
	const char *osenvironment;
	unsigned int size;
	if (kSuccess == SecureDTLookupEntry(0, "/chosen", &chosen)) {
		if (kSuccess == SecureDTGetProperty(chosen, "osenvironment", (void const **) &osenvironment, &size)) {
			return strcmp(osenvironment, "diagnostics") == 0;
		}
	}
	return false;
}

void
vm_compressor_init(void)
{
	thread_t        thread;
#if RECORD_THE_COMPRESSED_DATA
	vm_size_t       c_compressed_record_sbuf_size = 0;
#endif /* RECORD_THE_COMPRESSED_DATA */

#if DEVELOPMENT || DEBUG || CONFIG_FREEZE
	char bootarg_name[32];
#endif /* DEVELOPMENT || DEBUG || CONFIG_FREEZE */
	__unused uint64_t early_boot_compressor_size = compressor_size;

#if CONFIG_JETSAM
	if (memorystatus_swap_all_apps && osenvironment_is_diagnostics()) {
		printf("osenvironment == \"diagnostics\". Disabling app swap.\n");
		memorystatus_disable_swap();
	}

	if (memorystatus_swap_all_apps) {
		/*
		 * App swap is disabled on devices with small NANDs.
		 * Now that we're no longer in early boot, we can get
		 * the NAND size and re-run vm_compressor_set_size.
		 */
		int error = vm_swap_vol_get_capacity(SWAP_VOLUME_NAME, &vm_swap_volume_capacity);
#if DEVELOPMENT || DEBUG
		if (error != 0) {
			panic("vm_compressor_init: Unable to get swap volume capacity. error=%d\n", error);
		}
#else
		if (error != 0) {
			os_log_with_startup_serial(OS_LOG_DEFAULT, "vm_compressor_init: Unable to get swap volume capacity. error=%d\n", error);
		}
#endif /* DEVELOPMENT || DEBUG */
		if (vm_swap_volume_capacity < swap_vol_min_capacity) {
			memorystatus_disable_swap();
		}
		/*
		 * Resize the compressor and swap now that we know the capacity
		 * of the swap volume.
		 */
		vm_compressor_set_size();
		/*
		 * We reserved a chunk of VA early in boot for the compressor submap.
		 * We can't allocate more than that.
		 */
		assert(compressor_size <= early_boot_compressor_size);
	}
#endif /* CONFIG_JETSAM */

#if DEVELOPMENT || DEBUG
	if (PE_parse_boot_argn("-disable_cseg_write_protection", bootarg_name, sizeof(bootarg_name))) {
		write_protect_c_segs = FALSE;
	}

	int vmcval = 1;
#if defined(XNU_TARGET_OS_WATCH)
	vmcval = 0;
#endif /* XNU_TARGET_OS_WATCH */
	PE_parse_boot_argn("vm_compressor_validation", &vmcval, sizeof(vmcval));

	if (kern_feature_override(KF_COMPRSV_OVRD)) {
		vmcval = 0;
	}

	if (vmcval == 0) {
#if POPCOUNT_THE_COMPRESSED_DATA
		popcount_c_segs = FALSE;
#endif
#if CHECKSUM_THE_DATA || CHECKSUM_THE_COMPRESSED_DATA
		checksum_c_segs = FALSE;
#endif
#if VALIDATE_C_SEGMENTS
		validate_c_segs = FALSE;
#endif
		write_protect_c_segs = FALSE;
	}
#endif /* DEVELOPMENT || DEBUG */

#if CONFIG_FREEZE
	if (PE_parse_boot_argn("-disable_freezer_cseg_acct", bootarg_name, sizeof(bootarg_name))) {
		freezer_incore_cseg_acct = FALSE;
	}
#endif /* CONFIG_FREEZE */

	assert((C_SEGMENTS_PER_PAGE * sizeof(union c_segu)) == PAGE_SIZE);

#if !XNU_TARGET_OS_OSX
	vm_compressor_minorcompact_threshold_divisor = 20;
	vm_compressor_majorcompact_threshold_divisor = 30;
	vm_compressor_unthrottle_threshold_divisor = 40;
	vm_compressor_catchup_threshold_divisor = 60;
#else /* !XNU_TARGET_OS_OSX */
	if (max_mem <= (3ULL * 1024ULL * 1024ULL * 1024ULL)) {
		vm_compressor_minorcompact_threshold_divisor = 11;
		vm_compressor_majorcompact_threshold_divisor = 13;
		vm_compressor_unthrottle_threshold_divisor = 20;
		vm_compressor_catchup_threshold_divisor = 35;
	} else {
		vm_compressor_minorcompact_threshold_divisor = 20;
		vm_compressor_majorcompact_threshold_divisor = 25;
		vm_compressor_unthrottle_threshold_divisor = 35;
		vm_compressor_catchup_threshold_divisor = 50;
	}
#endif /* !XNU_TARGET_OS_OSX */

	queue_init(&c_bad_list_head);
	queue_init(&c_age_list_head);
	queue_init(&c_minor_list_head);
	queue_init(&c_major_list_head);
	queue_init(&c_filling_list_head);
	queue_init(&c_early_swapout_list_head);
	queue_init(&c_regular_swapout_list_head);
	queue_init(&c_late_swapout_list_head);
	queue_init(&c_swapio_list_head);
	queue_init(&c_early_swappedin_list_head);
	queue_init(&c_regular_swappedin_list_head);
	queue_init(&c_late_swappedin_list_head);
	queue_init(&c_swappedout_list_head);
	queue_init(&c_swappedout_sparse_list_head);

	c_free_segno_head = -1;
	c_segments_available = 0;

	compressor_map = kmem_suballoc(kernel_map, &compressor_range.min_address,
	    compressor_size, VM_MAP_CREATE_NEVER_FAULTS,
	    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, KMS_NOFAIL | KMS_PERMANENT,
	    VM_KERN_MEMORY_COMPRESSOR).kmr_submap;

	kmem_alloc(compressor_map, (vm_offset_t *)(&c_segments),
	    (sizeof(union c_segu) * c_segments_limit),
	    KMA_NOFAIL | KMA_KOBJECT | KMA_VAONLY | KMA_PERMANENT,
	    VM_KERN_MEMORY_COMPRESSOR);
	kmem_alloc(compressor_map, &c_buffers, c_buffers_size,
	    KMA_NOFAIL | KMA_COMPRESSOR | KMA_VAONLY | KMA_PERMANENT,
	    VM_KERN_MEMORY_COMPRESSOR);

#if DEVELOPMENT || DEBUG
	if (hvg_is_hcall_available(HVG_HCALL_SET_COREDUMP_DATA)) {
		hvg_hcall_set_coredump_data();
	}
#endif

	/*
	 * Pick a good size that will minimize fragmentation in zalloc
	 * by minimizing the fragmentation in a 16k run.
	 *
	 * c_seg_slot_var_array_min_len is larger on 4k systems than 16k ones,
	 * making the fragmentation in a 4k page terrible. Using 16k for all
	 * systems matches zalloc() and will minimize fragmentation.
	 */
	uint32_t c_segment_size = sizeof(struct c_segment) + (c_seg_slot_var_array_min_len * sizeof(struct c_slot));
	uint32_t cnt  = (16 << 10) / c_segment_size;
	uint32_t frag = (16 << 10) % c_segment_size;

	c_seg_fixed_array_len = c_seg_slot_var_array_min_len;

	while (cnt * sizeof(struct c_slot) < frag) {
		c_segment_size += sizeof(struct c_slot);
		c_seg_fixed_array_len++;
		frag -= cnt * sizeof(struct c_slot);
	}

	compressor_segment_zone = zone_create("compressor_segment",
	    c_segment_size, ZC_PGZ_USE_GUARDS | ZC_NOENCRYPT | ZC_ZFREE_CLEARMEM);

	c_segments_busy = FALSE;

	c_segments_next_page = (caddr_t)c_segments;
	vm_compressor_algorithm_init();

	{
		host_basic_info_data_t hinfo;
		mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
		size_t bufsize;
		char *buf;

#define BSD_HOST 1
		host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);

		compressor_cpus = hinfo.max_cpus;

		bufsize = PAGE_SIZE;
		bufsize += compressor_cpus * vm_compressor_get_decode_scratch_size();
		/* For the KDP path */
		bufsize += vm_compressor_get_decode_scratch_size();
#if CONFIG_FREEZE
		bufsize += vm_compressor_get_encode_scratch_size();
#endif
#if RECORD_THE_COMPRESSED_DATA
		bufsize += c_compressed_record_sbuf_size;
#endif

		kmem_alloc(kernel_map, (vm_offset_t *)&buf, bufsize,
		    KMA_DATA | KMA_NOFAIL | KMA_KOBJECT | KMA_PERMANENT,
		    VM_KERN_MEMORY_COMPRESSOR);

		/*
		 * kdp_compressor_decompressed_page must be page aligned because we access
		 * it through the physical aperture by page number.
		 */
		kdp_compressor_decompressed_page = buf;
		kdp_compressor_decompressed_page_paddr = kvtophys((vm_offset_t)kdp_compressor_decompressed_page);
		kdp_compressor_decompressed_page_ppnum = (ppnum_t) atop(kdp_compressor_decompressed_page_paddr);
		buf += PAGE_SIZE;
		bufsize -= PAGE_SIZE;

		compressor_scratch_bufs = buf;
		buf += compressor_cpus * vm_compressor_get_decode_scratch_size();
		bufsize -= compressor_cpus * vm_compressor_get_decode_scratch_size();

		kdp_compressor_scratch_buf = buf;
		buf += vm_compressor_get_decode_scratch_size();
		bufsize -= vm_compressor_get_decode_scratch_size();

#if CONFIG_FREEZE
		freezer_context_global.freezer_ctx_compressor_scratch_buf = buf;
		buf += vm_compressor_get_encode_scratch_size();
		bufsize -= vm_compressor_get_encode_scratch_size();
#endif

#if RECORD_THE_COMPRESSED_DATA
		c_compressed_record_sbuf = buf;
		c_compressed_record_cptr = buf;
		c_compressed_record_ebuf = c_compressed_record_sbuf + c_compressed_record_sbuf_size;
		buf += c_compressed_record_sbuf_size;
		bufsize -= c_compressed_record_sbuf_size;
#endif
		assert(bufsize == 0);
	}

	if (kernel_thread_start_priority((thread_continue_t)vm_compressor_swap_trigger_thread, NULL,
	    BASEPRI_VM, &thread) != KERN_SUCCESS) {
		panic("vm_compressor_swap_trigger_thread: create failed");
	}
	thread_deallocate(thread);

	if (vm_pageout_internal_start() != KERN_SUCCESS) {
		panic("vm_compressor_init: Failed to start the internal pageout thread.");
	}
	if (VM_CONFIG_SWAP_IS_PRESENT) {
		vm_compressor_swap_init();
	}

	if (VM_CONFIG_COMPRESSOR_IS_ACTIVE) {
		vm_compressor_is_active = 1;
	}

#if CONFIG_FREEZE
	memorystatus_freeze_enabled = TRUE;
#endif /* CONFIG_FREEZE */

	vm_compressor_available = 1;

	vm_page_reactivate_all_throttled();

	bzero(&vmcs_stats, sizeof(struct vm_compressor_swapper_stats));
}


#if VALIDATE_C_SEGMENTS

static void
c_seg_validate(c_segment_t c_seg, boolean_t must_be_compact)
{
	uint16_t        c_indx;
	int32_t         bytes_used;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	c_slot_t        cs;

	if (__probable(validate_c_segs == FALSE)) {
		return;
	}
	if (c_seg->c_firstemptyslot < c_seg->c_nextslot) {
		c_indx = c_seg->c_firstemptyslot;
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		if (cs == NULL) {
			panic("c_seg_validate:  no slot backing c_firstemptyslot");
		}

		if (cs->c_size) {
			panic("c_seg_validate:  c_firstemptyslot has non-zero size (%d)", cs->c_size);
		}
	}
	bytes_used = 0;

	for (c_indx = 0; c_indx < c_seg->c_nextslot; c_indx++) {
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

		c_size = UNPACK_C_SIZE(cs);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		bytes_used += c_rounded_size;

#if CHECKSUM_THE_COMPRESSED_DATA
		unsigned csvhash;
		if (c_size && cs->c_hash_compressed_data != (csvhash = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))) {
			addr64_t csvphys = kvtophys((vm_offset_t)&c_seg->c_store.c_buffer[cs->c_offset]);
			panic("Compressed data doesn't match original %p phys: 0x%llx %d %p %d %d 0x%x 0x%x", c_seg, csvphys, cs->c_offset, cs, c_indx, c_size, cs->c_hash_compressed_data, csvhash);
		}
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
		unsigned csvpop;
		if (c_size) {
			uintptr_t csvaddr = (uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset];
			if (cs->c_pop_cdata != (csvpop = vmc_pop(csvaddr, c_size))) {
				panic("Compressed data popcount doesn't match original, bit distance: %d %p (phys: %p) %p %p 0x%llx 0x%x 0x%x 0x%x", (csvpop - cs->c_pop_cdata), (void *)csvaddr, (void *) kvtophys(csvaddr), c_seg, cs, (uint64_t)cs->c_offset, c_size, csvpop, cs->c_pop_cdata);
			}
		}
#endif
	}

	if (bytes_used != c_seg->c_bytes_used) {
		panic("c_seg_validate: bytes_used mismatch - found %d, segment has %d", bytes_used, c_seg->c_bytes_used);
	}

	if (c_seg->c_bytes_used > C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset)) {
		panic("c_seg_validate: c_bytes_used > c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d",
		    (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);
	}

	if (must_be_compact) {
		if (c_seg->c_bytes_used != C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset)) {
			panic("c_seg_validate: c_bytes_used doesn't match c_nextoffset - c_nextoffset = %d,  c_bytes_used = %d",
			    (int32_t)C_SEG_OFFSET_TO_BYTES((int32_t)c_seg->c_nextoffset), c_seg->c_bytes_used);
		}
	}
}

#endif


void
c_seg_need_delayed_compaction(c_segment_t c_seg, boolean_t c_list_lock_held)
{
	boolean_t       clear_busy = FALSE;

	if (c_list_lock_held == FALSE) {
		if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
			C_SEG_BUSY(c_seg);

			lck_mtx_unlock_always(&c_seg->c_lock);
			lck_mtx_lock_spin_always(c_list_lock);
			lck_mtx_lock_spin_always(&c_seg->c_lock);

			clear_busy = TRUE;
		}
	}
	assert(c_seg->c_state != C_IS_FILLING);

	if (!c_seg->c_on_minorcompact_q && !(C_SEG_IS_ON_DISK_OR_SOQ(c_seg)) && !c_seg->c_has_donated_pages) {
		queue_enter(&c_minor_list_head, c_seg, c_segment_t, c_list);
		c_seg->c_on_minorcompact_q = 1;
		c_minor_count++;
	}
	if (c_list_lock_held == FALSE) {
		lck_mtx_unlock_always(c_list_lock);
	}

	if (clear_busy == TRUE) {
		C_SEG_WAKEUP_DONE(c_seg);
	}
}


unsigned int c_seg_moved_to_sparse_list = 0;

void
c_seg_move_to_sparse_list(c_segment_t c_seg)
{
	boolean_t       clear_busy = FALSE;

	if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
		C_SEG_BUSY(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);
		lck_mtx_lock_spin_always(c_list_lock);
		lck_mtx_lock_spin_always(&c_seg->c_lock);

		clear_busy = TRUE;
	}
	c_seg_switch_state(c_seg, C_ON_SWAPPEDOUTSPARSE_Q, FALSE);

	c_seg_moved_to_sparse_list++;

	lck_mtx_unlock_always(c_list_lock);

	if (clear_busy == TRUE) {
		C_SEG_WAKEUP_DONE(c_seg);
	}
}


void
c_seg_insert_into_q(queue_head_t *qhead, c_segment_t c_seg)
{
	c_segment_t c_seg_next;

	if (queue_empty(qhead)) {
		queue_enter(qhead, c_seg, c_segment_t, c_age_list);
	} else {
		c_seg_next = (c_segment_t)queue_first(qhead);

		while (TRUE) {
			if (c_seg->c_generation_id < c_seg_next->c_generation_id) {
				queue_insert_before(qhead, c_seg, c_seg_next, c_segment_t, c_age_list);
				break;
			}
			c_seg_next = (c_segment_t) queue_next(&c_seg_next->c_age_list);

			if (queue_end(qhead, (queue_entry_t) c_seg_next)) {
				queue_enter(qhead, c_seg, c_segment_t, c_age_list);
				break;
			}
		}
	}
}


int try_minor_compaction_failed = 0;
int try_minor_compaction_succeeded = 0;

void
c_seg_try_minor_compaction_and_unlock(c_segment_t c_seg)
{
	assert(c_seg->c_on_minorcompact_q);
	/*
	 * c_seg is currently on the delayed minor compaction
	 * queue and we have c_seg locked... if we can get the
	 * c_list_lock w/o blocking (if we blocked we could deadlock
	 * because the lock order is c_list_lock then c_seg's lock)
	 * we'll pull it from the delayed list and free it directly
	 */
	if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
		/*
		 * c_list_lock is held, we need to bail
		 */
		try_minor_compaction_failed++;

		lck_mtx_unlock_always(&c_seg->c_lock);
	} else {
		try_minor_compaction_succeeded++;

		C_SEG_BUSY(c_seg);
		c_seg_do_minor_compaction_and_unlock(c_seg, TRUE, FALSE, FALSE);
	}
}


int
c_seg_do_minor_compaction_and_unlock(c_segment_t c_seg, boolean_t clear_busy, boolean_t need_list_lock, boolean_t disallow_page_replacement)
{
	int     c_seg_freed;

	assert(c_seg->c_busy);
	assert(!C_SEG_IS_ON_DISK_OR_SOQ(c_seg));

	/*
	 * check for the case that can occur when we are not swapping
	 * and this segment has been major compacted in the past
	 * and moved to the majorcompact q to remove it from further
	 * consideration... if the occupancy falls too low we need
	 * to put it back on the age_q so that it will be considered
	 * in the next major compaction sweep... if we don't do this
	 * we will eventually run into the c_segments_limit
	 */
	if (c_seg->c_state == C_ON_MAJORCOMPACT_Q && C_SEG_SHOULD_MAJORCOMPACT_NOW(c_seg)) {
		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
	}
	if (!c_seg->c_on_minorcompact_q) {
		if (clear_busy == TRUE) {
			C_SEG_WAKEUP_DONE(c_seg);
		}

		lck_mtx_unlock_always(&c_seg->c_lock);

		return 0;
	}
	queue_remove(&c_minor_list_head, c_seg, c_segment_t, c_list);
	c_seg->c_on_minorcompact_q = 0;
	c_minor_count--;

	lck_mtx_unlock_always(c_list_lock);

	if (disallow_page_replacement == TRUE) {
		lck_mtx_unlock_always(&c_seg->c_lock);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg->c_lock);
	}
	c_seg_freed = c_seg_minor_compaction_and_unlock(c_seg, clear_busy);

	if (disallow_page_replacement == TRUE) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
	}

	if (need_list_lock == TRUE) {
		lck_mtx_lock_spin_always(c_list_lock);
	}

	return c_seg_freed;
}

void
kdp_compressor_busy_find_owner(event64_t wait_event, thread_waitinfo_t *waitinfo)
{
	c_segment_t c_seg = (c_segment_t) wait_event;

	waitinfo->owner = thread_tid(c_seg->c_busy_for_thread);
	waitinfo->context = VM_KERNEL_UNSLIDE_OR_PERM(c_seg);
}

#if DEVELOPMENT || DEBUG
int
do_cseg_wedge_thread(void)
{
	struct c_segment c_seg;
	c_seg.c_busy_for_thread = current_thread();

	debug_cseg_wait_event = (event_t) &c_seg;

	thread_set_pending_block_hint(current_thread(), kThreadWaitCompressor);
	assert_wait((event_t) (&c_seg), THREAD_INTERRUPTIBLE);

	thread_block(THREAD_CONTINUE_NULL);

	return 0;
}

int
do_cseg_unwedge_thread(void)
{
	thread_wakeup(debug_cseg_wait_event);
	debug_cseg_wait_event = NULL;

	return 0;
}
#endif /* DEVELOPMENT || DEBUG */

void
c_seg_wait_on_busy(c_segment_t c_seg)
{
	c_seg->c_wanted = 1;

	thread_set_pending_block_hint(current_thread(), kThreadWaitCompressor);
	assert_wait((event_t) (c_seg), THREAD_UNINT);

	lck_mtx_unlock_always(&c_seg->c_lock);
	thread_block(THREAD_CONTINUE_NULL);
}

#if CONFIG_FREEZE
/*
 * We don't have the task lock held while updating the task's
 * c_seg queues. We can do that because of the following restrictions:
 *
 * - SINGLE FREEZER CONTEXT:
 *   We 'insert' c_segs into the task list on the task_freeze path.
 *   There can only be one such freeze in progress and the task
 *   isn't disappearing because we have the VM map lock held throughout
 *   and we have a reference on the proc too.
 *
 * - SINGLE TASK DISOWN CONTEXT:
 *   We 'disown' c_segs of a task ONLY from the task_terminate context. So
 *   we don't need the task lock but we need the c_list_lock and the
 *   compressor master lock (shared). We also hold the individual
 *   c_seg locks (exclusive).
 *
 *   If we either:
 *   - can't get the c_seg lock on a try, then we start again because maybe
 *   the c_seg is part of a compaction and might get freed. So we can't trust
 *   that linkage and need to restart our queue traversal.
 *   - OR, we run into a busy c_seg (say being swapped in or free-ing) we
 *   drop all locks again and wait and restart our queue traversal.
 *
 * - The new_owner_task below is currently only the kernel or NULL.
 *
 */
void
c_seg_update_task_owner(c_segment_t c_seg, task_t new_owner_task)
{
	task_t          owner_task = c_seg->c_task_owner;
	uint64_t        uncompressed_bytes = ((c_seg->c_slots_used) * PAGE_SIZE_64);

	LCK_MTX_ASSERT(c_list_lock, LCK_MTX_ASSERT_OWNED);
	LCK_MTX_ASSERT(&c_seg->c_lock, LCK_MTX_ASSERT_OWNED);

	if (owner_task) {
		task_update_frozen_to_swap_acct(owner_task, uncompressed_bytes, DEBIT_FROM_SWAP);
		queue_remove(&owner_task->task_frozen_cseg_q, c_seg,
		    c_segment_t, c_task_list_next_cseg);
	}

	if (new_owner_task) {
		queue_enter(&new_owner_task->task_frozen_cseg_q, c_seg,
		    c_segment_t, c_task_list_next_cseg);
		task_update_frozen_to_swap_acct(new_owner_task, uncompressed_bytes, CREDIT_TO_SWAP);
	}

	c_seg->c_task_owner = new_owner_task;
}

void
task_disown_frozen_csegs(task_t owner_task)
{
	c_segment_t c_seg = NULL, next_cseg = NULL;

again:
	PAGE_REPLACEMENT_DISALLOWED(TRUE);
	lck_mtx_lock_spin_always(c_list_lock);

	for (c_seg = (c_segment_t) queue_first(&owner_task->task_frozen_cseg_q);
	    !queue_end(&owner_task->task_frozen_cseg_q, (queue_entry_t) c_seg);
	    c_seg = next_cseg) {
		next_cseg = (c_segment_t) queue_next(&c_seg->c_task_list_next_cseg);

		if (!lck_mtx_try_lock_spin_always(&c_seg->c_lock)) {
			lck_mtx_unlock(c_list_lock);
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			goto again;
		}

		if (c_seg->c_busy) {
			lck_mtx_unlock(c_list_lock);
			PAGE_REPLACEMENT_DISALLOWED(FALSE);

			c_seg_wait_on_busy(c_seg);

			goto again;
		}
		assert(c_seg->c_task_owner == owner_task);
		c_seg_update_task_owner(c_seg, kernel_task);
		lck_mtx_unlock_always(&c_seg->c_lock);
	}

	lck_mtx_unlock(c_list_lock);
	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}
#endif /* CONFIG_FREEZE */

void
c_seg_switch_state(c_segment_t c_seg, int new_state, boolean_t insert_head)
{
	int     old_state = c_seg->c_state;
	queue_head_t *donate_swapout_list_head, *donate_swappedin_list_head;
	uint32_t     *donate_swapout_count, *donate_swappedin_count;

	/*
	 * On macOS the donate queue is swapped first ie the c_early_swapout queue.
	 * On other swap-capable platforms, we want to swap those out last. So we
	 * use the c_late_swapout queue.
	 */
#if XNU_TARGET_OS_OSX
#if (DEVELOPMENT || DEBUG)
	if (new_state != C_IS_FILLING) {
		LCK_MTX_ASSERT(&c_seg->c_lock, LCK_MTX_ASSERT_OWNED);
	}
	LCK_MTX_ASSERT(c_list_lock, LCK_MTX_ASSERT_OWNED);
#endif /* DEVELOPMENT || DEBUG */

	donate_swapout_list_head = &c_early_swapout_list_head;
	donate_swapout_count = &c_early_swapout_count;
	donate_swappedin_list_head = &c_early_swappedin_list_head;
	donate_swappedin_count = &c_early_swappedin_count;
#else /* XNU_TARGET_OS_OSX */
	donate_swapout_list_head = &c_late_swapout_list_head;
	donate_swapout_count = &c_late_swapout_count;
	donate_swappedin_list_head = &c_late_swappedin_list_head;
	donate_swappedin_count = &c_late_swappedin_count;
#endif /* XNU_TARGET_OS_OSX */

	switch (old_state) {
	case C_IS_EMPTY:
		assert(new_state == C_IS_FILLING || new_state == C_IS_FREE);

		c_empty_count--;
		break;

	case C_IS_FILLING:
		assert(new_state == C_ON_AGE_Q || new_state == C_ON_SWAPOUT_Q);

		queue_remove(&c_filling_list_head, c_seg, c_segment_t, c_age_list);
		c_filling_count--;
		break;

	case C_ON_AGE_Q:
		assert(new_state == C_ON_SWAPOUT_Q || new_state == C_ON_MAJORCOMPACT_Q ||
		    new_state == C_IS_FREE);

		queue_remove(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		c_age_count--;
		break;

	case C_ON_SWAPPEDIN_Q:
		if (c_seg->c_has_donated_pages) {
			assert(new_state == C_ON_SWAPOUT_Q || new_state == C_IS_FREE);
			queue_remove(donate_swappedin_list_head, c_seg, c_segment_t, c_age_list);
			*donate_swappedin_count -= 1;
		} else {
			assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE);
#if CONFIG_FREEZE
			assert(c_seg->c_has_freezer_pages);
			queue_remove(&c_early_swappedin_list_head, c_seg, c_segment_t, c_age_list);
			c_early_swappedin_count--;
#else /* CONFIG_FREEZE */
			queue_remove(&c_regular_swappedin_list_head, c_seg, c_segment_t, c_age_list);
			c_regular_swappedin_count--;
#endif /* CONFIG_FREEZE */
		}
		break;

	case C_ON_SWAPOUT_Q:
		assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE || new_state == C_IS_EMPTY || new_state == C_ON_SWAPIO_Q);

#if CONFIG_FREEZE
		if (c_seg->c_has_freezer_pages) {
			if (c_seg->c_task_owner && (new_state != C_ON_SWAPIO_Q)) {
				c_seg_update_task_owner(c_seg, NULL);
			}
			queue_remove(&c_early_swapout_list_head, c_seg, c_segment_t, c_age_list);
			c_early_swapout_count--;
		} else
#endif /* CONFIG_FREEZE */
		{
			if (c_seg->c_has_donated_pages) {
				queue_remove(donate_swapout_list_head, c_seg, c_segment_t, c_age_list);
				*donate_swapout_count -= 1;
			} else {
				queue_remove(&c_regular_swapout_list_head, c_seg, c_segment_t, c_age_list);
				c_regular_swapout_count--;
			}
		}

		if (new_state == C_ON_AGE_Q) {
			c_seg->c_has_donated_pages = 0;
		}
		thread_wakeup((event_t)&compaction_swapper_running);
		break;

	case C_ON_SWAPIO_Q:
#if CONFIG_FREEZE
		if (c_seg->c_has_freezer_pages) {
			assert(new_state == C_ON_SWAPPEDOUT_Q || new_state == C_ON_SWAPPEDOUTSPARSE_Q || new_state == C_ON_AGE_Q);
		} else
#endif /* CONFIG_FREEZE */
		{
			if (c_seg->c_has_donated_pages) {
				assert(new_state == C_ON_SWAPPEDOUT_Q || new_state == C_ON_SWAPPEDOUTSPARSE_Q || new_state == C_ON_SWAPPEDIN_Q);
			} else {
				assert(new_state == C_ON_SWAPPEDOUT_Q || new_state == C_ON_SWAPPEDOUTSPARSE_Q || new_state == C_ON_AGE_Q);
			}
		}

		queue_remove(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		c_swapio_count--;
		break;

	case C_ON_SWAPPEDOUT_Q:
		assert(new_state == C_ON_SWAPPEDIN_Q || new_state == C_ON_AGE_Q ||
		    new_state == C_ON_SWAPPEDOUTSPARSE_Q ||
		    new_state == C_ON_BAD_Q || new_state == C_IS_EMPTY || new_state == C_IS_FREE);

		queue_remove(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		c_swappedout_count--;
		break;

	case C_ON_SWAPPEDOUTSPARSE_Q:
		assert(new_state == C_ON_SWAPPEDIN_Q || new_state == C_ON_AGE_Q ||
		    new_state == C_ON_BAD_Q || new_state == C_IS_EMPTY || new_state == C_IS_FREE);

		queue_remove(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		c_swappedout_sparse_count--;
		break;

	case C_ON_MAJORCOMPACT_Q:
		assert(new_state == C_ON_AGE_Q || new_state == C_IS_FREE);

		queue_remove(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		c_major_count--;
		break;

	case C_ON_BAD_Q:
		assert(new_state == C_IS_FREE);

		queue_remove(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		c_bad_count--;
		break;

	default:
		panic("c_seg %p has bad c_state = %d", c_seg, old_state);
	}

	switch (new_state) {
	case C_IS_FREE:
		assert(old_state != C_IS_FILLING);

		break;

	case C_IS_EMPTY:
		assert(old_state == C_ON_SWAPOUT_Q || old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		c_empty_count++;
		break;

	case C_IS_FILLING:
		assert(old_state == C_IS_EMPTY);

		queue_enter(&c_filling_list_head, c_seg, c_segment_t, c_age_list);
		c_filling_count++;
		break;

	case C_ON_AGE_Q:
		assert(old_state == C_IS_FILLING || old_state == C_ON_SWAPPEDIN_Q ||
		    old_state == C_ON_SWAPOUT_Q || old_state == C_ON_SWAPIO_Q ||
		    old_state == C_ON_MAJORCOMPACT_Q || old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		assert(!c_seg->c_has_donated_pages);
		if (old_state == C_IS_FILLING) {
			queue_enter(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			if (!queue_empty(&c_age_list_head)) {
				c_segment_t     c_first;

				c_first = (c_segment_t)queue_first(&c_age_list_head);
				c_seg->c_creation_ts = c_first->c_creation_ts;
			}
			queue_enter_first(&c_age_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_age_count++;
		break;

	case C_ON_SWAPPEDIN_Q:
	{
		queue_head_t *list_head;

		assert(old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q || old_state == C_ON_SWAPIO_Q);
		if (c_seg->c_has_donated_pages) {
			/* Error in swapouts could happen while the c_seg is still on the swapio queue */
			list_head = donate_swappedin_list_head;
			*donate_swappedin_count += 1;
		} else {
#if CONFIG_FREEZE
			assert(c_seg->c_has_freezer_pages);
			list_head = &c_early_swappedin_list_head;
			c_early_swappedin_count++;
#else /* CONFIG_FREEZE */
			list_head = &c_regular_swappedin_list_head;
			c_regular_swappedin_count++;
#endif /* CONFIG_FREEZE */
		}

		if (insert_head == TRUE) {
			queue_enter_first(list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(list_head, c_seg, c_segment_t, c_age_list);
		}
		break;
	}

	case C_ON_SWAPOUT_Q:
	{
		queue_head_t *list_head;

#if CONFIG_FREEZE
		/*
		 * A segment with both identities of frozen + donated pages
		 * will be put on early swapout Q ie the frozen identity wins.
		 * This is because when both identities are set, the donation bit
		 * is added on after in the c_current_seg_filled path for accounting
		 * purposes.
		 */
		if (c_seg->c_has_freezer_pages) {
			assert(old_state == C_ON_AGE_Q || old_state == C_IS_FILLING);
			list_head = &c_early_swapout_list_head;
			c_early_swapout_count++;
		} else
#endif
		{
			if (c_seg->c_has_donated_pages) {
				assert(old_state == C_ON_SWAPPEDIN_Q || old_state == C_IS_FILLING);
				list_head = donate_swapout_list_head;
				*donate_swapout_count += 1;
			} else {
				assert(old_state == C_ON_AGE_Q || old_state == C_IS_FILLING);
				list_head = &c_regular_swapout_list_head;
				c_regular_swapout_count++;
			}
		}

		if (insert_head == TRUE) {
			queue_enter_first(list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(list_head, c_seg, c_segment_t, c_age_list);
		}
		break;
	}

	case C_ON_SWAPIO_Q:
		assert(old_state == C_ON_SWAPOUT_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swapio_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swapio_count++;
		break;

	case C_ON_SWAPPEDOUT_Q:
		assert(old_state == C_ON_SWAPIO_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swappedout_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_swappedout_count++;
		break;

	case C_ON_SWAPPEDOUTSPARSE_Q:
		assert(old_state == C_ON_SWAPIO_Q || old_state == C_ON_SWAPPEDOUT_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_swappedout_sparse_list_head, c_seg, c_segment_t, c_age_list);
		}

		c_swappedout_sparse_count++;
		break;

	case C_ON_MAJORCOMPACT_Q:
		assert(old_state == C_ON_AGE_Q);
		assert(!c_seg->c_has_donated_pages);

		if (insert_head == TRUE) {
			queue_enter_first(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_major_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_major_count++;
		break;

	case C_ON_BAD_Q:
		assert(old_state == C_ON_SWAPPEDOUT_Q || old_state == C_ON_SWAPPEDOUTSPARSE_Q);

		if (insert_head == TRUE) {
			queue_enter_first(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		} else {
			queue_enter(&c_bad_list_head, c_seg, c_segment_t, c_age_list);
		}
		c_bad_count++;
		break;

	default:
		panic("c_seg %p requesting bad c_state = %d", c_seg, new_state);
	}
	c_seg->c_state = new_state;
}



void
c_seg_free(c_segment_t c_seg)
{
	assert(c_seg->c_busy);

	lck_mtx_unlock_always(&c_seg->c_lock);
	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	c_seg_free_locked(c_seg);
}


void
c_seg_free_locked(c_segment_t c_seg)
{
	int             segno;
	int             pages_populated = 0;
	int32_t         *c_buffer = NULL;
	uint64_t        c_swap_handle = 0;

	assert(c_seg->c_busy);
	assert(c_seg->c_slots_used == 0);
	assert(!c_seg->c_on_minorcompact_q);
	assert(!c_seg->c_busy_swapping);

	if (c_seg->c_overage_swap == TRUE) {
		c_overage_swapped_count--;
		c_seg->c_overage_swap = FALSE;
	}
	if (!(C_SEG_IS_ONDISK(c_seg))) {
		c_buffer = c_seg->c_store.c_buffer;
	} else {
		c_swap_handle = c_seg->c_store.c_swap_handle;
	}

	c_seg_switch_state(c_seg, C_IS_FREE, FALSE);

	if (c_buffer) {
		pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;
		c_seg->c_store.c_buffer = NULL;
	} else {
#if CONFIG_FREEZE
		c_seg_update_task_owner(c_seg, NULL);
#endif /* CONFIG_FREEZE */

		c_seg->c_store.c_swap_handle = (uint64_t)-1;
	}

	lck_mtx_unlock_always(&c_seg->c_lock);

	lck_mtx_unlock_always(c_list_lock);

	if (c_buffer) {
		if (pages_populated) {
			kernel_memory_depopulate((vm_offset_t)c_buffer,
			    ptoa(pages_populated), KMA_COMPRESSOR,
			    VM_KERN_MEMORY_COMPRESSOR);
		}
	} else if (c_swap_handle) {
		/*
		 * Free swap space on disk.
		 */
		vm_swap_free(c_swap_handle);
	}
	lck_mtx_lock_spin_always(&c_seg->c_lock);
	/*
	 * c_seg must remain busy until
	 * after the call to vm_swap_free
	 */
	C_SEG_WAKEUP_DONE(c_seg);
	lck_mtx_unlock_always(&c_seg->c_lock);

	segno = c_seg->c_mysegno;

	lck_mtx_lock_spin_always(c_list_lock);
	/*
	 * because the c_buffer is now associated with the segno,
	 * we can't put the segno back on the free list until
	 * after we have depopulated the c_buffer range, or
	 * we run the risk of depopulating a range that is
	 * now being used in one of the compressor heads
	 */
	c_segments[segno].c_segno = c_free_segno_head;
	c_free_segno_head = segno;
	c_segment_count--;

	lck_mtx_unlock_always(c_list_lock);

	lck_mtx_destroy(&c_seg->c_lock, &vm_compressor_lck_grp);

	if (c_seg->c_slot_var_array_len) {
		kfree_type(struct c_slot, c_seg->c_slot_var_array_len,
		    c_seg->c_slot_var_array);
	}

	zfree(compressor_segment_zone, c_seg);
}

#if DEVELOPMENT || DEBUG
int c_seg_trim_page_count = 0;
#endif

void
c_seg_trim_tail(c_segment_t c_seg)
{
	c_slot_t        cs;
	uint32_t        c_size;
	uint32_t        c_offset;
	uint32_t        c_rounded_size;
	uint16_t        current_nextslot;
	uint32_t        current_populated_offset;

	if (c_seg->c_bytes_used == 0) {
		return;
	}
	current_nextslot = c_seg->c_nextslot;
	current_populated_offset = c_seg->c_populated_offset;

	while (c_seg->c_nextslot) {
		cs = C_SEG_SLOT_FROM_INDEX(c_seg, (c_seg->c_nextslot - 1));

		c_size = UNPACK_C_SIZE(cs);

		if (c_size) {
			if (current_nextslot != c_seg->c_nextslot) {
				c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;
				c_offset = cs->c_offset + C_SEG_BYTES_TO_OFFSET(c_rounded_size);

				c_seg->c_nextoffset = c_offset;
				c_seg->c_populated_offset = (c_offset + (C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1)) &
				    ~(C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1);

				if (c_seg->c_firstemptyslot > c_seg->c_nextslot) {
					c_seg->c_firstemptyslot = c_seg->c_nextslot;
				}
#if DEVELOPMENT || DEBUG
				c_seg_trim_page_count += ((round_page_32(C_SEG_OFFSET_TO_BYTES(current_populated_offset)) -
				    round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) /
				    PAGE_SIZE);
#endif
			}
			break;
		}
		c_seg->c_nextslot--;
	}
	assert(c_seg->c_nextslot);
}


int
c_seg_minor_compaction_and_unlock(c_segment_t c_seg, boolean_t clear_busy)
{
	c_slot_mapping_t slot_ptr;
	uint32_t        c_offset = 0;
	uint32_t        old_populated_offset;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	uint16_t        c_indx = 0;
	int             i;
	c_slot_t        c_dst;
	c_slot_t        c_src;

	assert(c_seg->c_busy);

#if VALIDATE_C_SEGMENTS
	c_seg_validate(c_seg, FALSE);
#endif
	if (c_seg->c_bytes_used == 0) {
		c_seg_free(c_seg);
		return 1;
	}
	lck_mtx_unlock_always(&c_seg->c_lock);

	if (c_seg->c_firstemptyslot >= c_seg->c_nextslot || C_SEG_UNUSED_BYTES(c_seg) < PAGE_SIZE) {
		goto done;
	}

/* TODO: assert first emptyslot's c_size is actually 0 */

#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg);
#endif

#if VALIDATE_C_SEGMENTS
	c_seg->c_was_minor_compacted++;
#endif
	c_indx = c_seg->c_firstemptyslot;
	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

	old_populated_offset = c_seg->c_populated_offset;
	c_offset = c_dst->c_offset;

	for (i = c_indx + 1; i < c_seg->c_nextslot && c_offset < c_seg->c_nextoffset; i++) {
		c_src = C_SEG_SLOT_FROM_INDEX(c_seg, i);

		c_size = UNPACK_C_SIZE(c_src);

		if (c_size == 0) {
			continue;
		}

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;
/* N.B.: This memcpy may be an overlapping copy */
		memcpy(&c_seg->c_store.c_buffer[c_offset], &c_seg->c_store.c_buffer[c_src->c_offset], c_rounded_size);

		cslot_copy(c_dst, c_src);
		c_dst->c_offset = c_offset;

		slot_ptr = C_SLOT_UNPACK_PTR(c_dst);
		slot_ptr->s_cindx = c_indx;

		c_offset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);
		PACK_C_SIZE(c_src, 0);
		c_indx++;

		c_dst = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
	}
	c_seg->c_firstemptyslot = c_indx;
	c_seg->c_nextslot = c_indx;
	c_seg->c_nextoffset = c_offset;
	c_seg->c_populated_offset = (c_offset + (C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1)) & ~(C_SEG_BYTES_TO_OFFSET(PAGE_SIZE) - 1);
	c_seg->c_bytes_unused = 0;

#if VALIDATE_C_SEGMENTS
	c_seg_validate(c_seg, TRUE);
#endif
	if (old_populated_offset > c_seg->c_populated_offset) {
		uint32_t        gc_size;
		int32_t         *gc_ptr;

		gc_size = C_SEG_OFFSET_TO_BYTES(old_populated_offset - c_seg->c_populated_offset);
		gc_ptr = &c_seg->c_store.c_buffer[c_seg->c_populated_offset];

		kernel_memory_depopulate((vm_offset_t)gc_ptr, gc_size,
		    KMA_COMPRESSOR, VM_KERN_MEMORY_COMPRESSOR);
	}

#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg);
#endif

done:
	if (clear_busy == TRUE) {
		lck_mtx_lock_spin_always(&c_seg->c_lock);
		C_SEG_WAKEUP_DONE(c_seg);
		lck_mtx_unlock_always(&c_seg->c_lock);
	}
	return 0;
}


static void
c_seg_alloc_nextslot(c_segment_t c_seg)
{
	struct c_slot   *old_slot_array = NULL;
	struct c_slot   *new_slot_array = NULL;
	int             newlen;
	int             oldlen;

	if (c_seg->c_nextslot < c_seg_fixed_array_len) {
		return;
	}

	if ((c_seg->c_nextslot - c_seg_fixed_array_len) >= c_seg->c_slot_var_array_len) {
		oldlen = c_seg->c_slot_var_array_len;
		old_slot_array = c_seg->c_slot_var_array;

		if (oldlen == 0) {
			newlen = c_seg_slot_var_array_min_len;
		} else {
			newlen = oldlen * 2;
		}

		new_slot_array = kalloc_type(struct c_slot, newlen, Z_WAITOK);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (old_slot_array) {
			memcpy(new_slot_array, old_slot_array,
			    sizeof(struct c_slot) * oldlen);
		}

		c_seg->c_slot_var_array_len = newlen;
		c_seg->c_slot_var_array = new_slot_array;

		lck_mtx_unlock_always(&c_seg->c_lock);

		kfree_type(struct c_slot, oldlen, old_slot_array);
	}
}


#define C_SEG_MAJOR_COMPACT_STATS_MAX   (30)

struct {
	uint64_t asked_permission;
	uint64_t compactions;
	uint64_t moved_slots;
	uint64_t moved_bytes;
	uint64_t wasted_space_in_swapouts;
	uint64_t count_of_swapouts;
	uint64_t count_of_freed_segs;
	uint64_t bailed_compactions;
	uint64_t bytes_freed_rate_us;
} c_seg_major_compact_stats[C_SEG_MAJOR_COMPACT_STATS_MAX];

int c_seg_major_compact_stats_now = 0;


#define C_MAJOR_COMPACTION_SIZE_APPROPRIATE     ((c_seg_bufsize * 90) / 100)


boolean_t
c_seg_major_compact_ok(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{
	c_seg_major_compact_stats[c_seg_major_compact_stats_now].asked_permission++;

	if (c_seg_src->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE &&
	    c_seg_dst->c_bytes_used >= C_MAJOR_COMPACTION_SIZE_APPROPRIATE) {
		return FALSE;
	}

	if (c_seg_dst->c_nextoffset >= c_seg_off_limit || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
		/*
		 * destination segment is full... can't compact
		 */
		return FALSE;
	}

	return TRUE;
}


boolean_t
c_seg_major_compact(
	c_segment_t c_seg_dst,
	c_segment_t c_seg_src)
{
	c_slot_mapping_t slot_ptr;
	uint32_t        c_rounded_size;
	uint32_t        c_size;
	uint16_t        dst_slot;
	int             i;
	c_slot_t        c_dst;
	c_slot_t        c_src;
	boolean_t       keep_compacting = TRUE;

	/*
	 * segments are not locked but they are both marked c_busy
	 * which keeps c_decompress from working on them...
	 * we can safely allocate new pages, move compressed data
	 * from c_seg_src to c_seg_dst and update both c_segment's
	 * state w/o holding the master lock
	 */
#if DEVELOPMENT || DEBUG
	C_SEG_MAKE_WRITEABLE(c_seg_dst);
#endif

#if VALIDATE_C_SEGMENTS
	c_seg_dst->c_was_major_compacted++;
	c_seg_src->c_was_major_donor++;
#endif
	assertf(c_seg_dst->c_has_donated_pages == c_seg_src->c_has_donated_pages, "Mismatched donation status Dst: %p, Src: %p\n", c_seg_dst, c_seg_src);
	c_seg_major_compact_stats[c_seg_major_compact_stats_now].compactions++;

	dst_slot = c_seg_dst->c_nextslot;

	for (i = 0; i < c_seg_src->c_nextslot; i++) {
		c_src = C_SEG_SLOT_FROM_INDEX(c_seg_src, i);

		c_size = UNPACK_C_SIZE(c_src);

		if (c_size == 0) {
			/* BATCH: move what we have so far; */
			continue;
		}

		if (C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset - c_seg_dst->c_nextoffset) < (unsigned) c_size) {
			int     size_to_populate;

			/* doesn't fit */
			size_to_populate = c_seg_bufsize - C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset);

			if (size_to_populate == 0) {
				/* can't fit */
				keep_compacting = FALSE;
				break;
			}
			if (size_to_populate > C_SEG_MAX_POPULATE_SIZE) {
				size_to_populate = C_SEG_MAX_POPULATE_SIZE;
			}

			kernel_memory_populate(
				(vm_offset_t) &c_seg_dst->c_store.c_buffer[c_seg_dst->c_populated_offset],
				size_to_populate,
				KMA_NOFAIL | KMA_COMPRESSOR,
				VM_KERN_MEMORY_COMPRESSOR);

			c_seg_dst->c_populated_offset += C_SEG_BYTES_TO_OFFSET(size_to_populate);
			assert(C_SEG_OFFSET_TO_BYTES(c_seg_dst->c_populated_offset) <= c_seg_bufsize);
		}
		c_seg_alloc_nextslot(c_seg_dst);

		c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

		memcpy(&c_seg_dst->c_store.c_buffer[c_seg_dst->c_nextoffset], &c_seg_src->c_store.c_buffer[c_src->c_offset], c_size);

		c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

		c_seg_major_compact_stats[c_seg_major_compact_stats_now].moved_slots++;
		c_seg_major_compact_stats[c_seg_major_compact_stats_now].moved_bytes += c_size;

		cslot_copy(c_dst, c_src);
		c_dst->c_offset = c_seg_dst->c_nextoffset;

		if (c_seg_dst->c_firstemptyslot == c_seg_dst->c_nextslot) {
			c_seg_dst->c_firstemptyslot++;
		}
		c_seg_dst->c_slots_used++;
		c_seg_dst->c_nextslot++;
		c_seg_dst->c_bytes_used += c_rounded_size;
		c_seg_dst->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);

		PACK_C_SIZE(c_src, 0);

		c_seg_src->c_bytes_used -= c_rounded_size;
		c_seg_src->c_bytes_unused += c_rounded_size;
		c_seg_src->c_firstemptyslot = 0;

		assert(c_seg_src->c_slots_used);
		c_seg_src->c_slots_used--;

		if (!c_seg_src->c_swappedin) {
			/* Pessimistically lose swappedin status when non-swappedin pages are added. */
			c_seg_dst->c_swappedin = false;
		}

		if (c_seg_dst->c_nextoffset >= c_seg_off_limit || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
			/* dest segment is now full */
			keep_compacting = FALSE;
			break;
		}
	}
#if DEVELOPMENT || DEBUG
	C_SEG_WRITE_PROTECT(c_seg_dst);
#endif
	if (dst_slot < c_seg_dst->c_nextslot) {
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		/*
		 * we've now locked out c_decompress from
		 * converting the slot passed into it into
		 * a c_segment_t which allows us to use
		 * the backptr to change which c_segment and
		 * index the slot points to
		 */
		while (dst_slot < c_seg_dst->c_nextslot) {
			c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, dst_slot);

			slot_ptr = C_SLOT_UNPACK_PTR(c_dst);
			/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
			slot_ptr->s_cseg = c_seg_dst->c_mysegno + 1;
			slot_ptr->s_cindx = dst_slot++;
		}
		PAGE_REPLACEMENT_ALLOWED(FALSE);
	}
	return keep_compacting;
}


uint64_t
vm_compressor_compute_elapsed_msecs(clock_sec_t end_sec, clock_nsec_t end_nsec, clock_sec_t start_sec, clock_nsec_t start_nsec)
{
	uint64_t end_msecs;
	uint64_t start_msecs;

	end_msecs = (end_sec * 1000) + end_nsec / 1000000;
	start_msecs = (start_sec * 1000) + start_nsec / 1000000;

	return end_msecs - start_msecs;
}



uint32_t compressor_eval_period_in_msecs = 250;
uint32_t compressor_sample_min_in_msecs = 500;
uint32_t compressor_sample_max_in_msecs = 10000;
uint32_t compressor_thrashing_threshold_per_10msecs = 50;
uint32_t compressor_thrashing_min_per_10msecs = 20;

/* When true, reset sample data next chance we get. */
static boolean_t        compressor_need_sample_reset = FALSE;


void
compute_swapout_target_age(void)
{
	clock_sec_t     cur_ts_sec;
	clock_nsec_t    cur_ts_nsec;
	uint32_t        min_operations_needed_in_this_sample;
	uint64_t        elapsed_msecs_in_eval;
	uint64_t        elapsed_msecs_in_sample;
	boolean_t       need_eval_reset = FALSE;

	clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

	elapsed_msecs_in_sample = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_sample_period_sec, start_of_sample_period_nsec);

	if (compressor_need_sample_reset ||
	    elapsed_msecs_in_sample >= compressor_sample_max_in_msecs) {
		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
		goto done;
	}
	elapsed_msecs_in_eval = vm_compressor_compute_elapsed_msecs(cur_ts_sec, cur_ts_nsec, start_of_eval_period_sec, start_of_eval_period_nsec);

	if (elapsed_msecs_in_eval < compressor_eval_period_in_msecs) {
		goto done;
	}
	need_eval_reset = TRUE;

	KERNEL_DEBUG(0xe0400020 | DBG_FUNC_START, elapsed_msecs_in_eval, sample_period_compression_count, sample_period_decompression_count, 0, 0);

	min_operations_needed_in_this_sample = (compressor_thrashing_min_per_10msecs * (uint32_t)elapsed_msecs_in_eval) / 10;

	if ((sample_period_compression_count - last_eval_compression_count) < min_operations_needed_in_this_sample ||
	    (sample_period_decompression_count - last_eval_decompression_count) < min_operations_needed_in_this_sample) {
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, sample_period_compression_count - last_eval_compression_count,
		    sample_period_decompression_count - last_eval_decompression_count, 0, 1, 0);

		swapout_target_age = 0;

		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
		goto done;
	}
	last_eval_compression_count = sample_period_compression_count;
	last_eval_decompression_count = sample_period_decompression_count;

	if (elapsed_msecs_in_sample < compressor_sample_min_in_msecs) {
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, swapout_target_age, 0, 0, 5, 0);
		goto done;
	}
	if (sample_period_decompression_count > ((compressor_thrashing_threshold_per_10msecs * elapsed_msecs_in_sample) / 10)) {
		uint64_t        running_total;
		uint64_t        working_target;
		uint64_t        aging_target;
		uint32_t        oldest_age_of_csegs_sampled = 0;
		uint64_t        working_set_approximation = 0;

		swapout_target_age = 0;

		working_target = (sample_period_decompression_count / 100) * 95;                /* 95 percent */
		aging_target = (sample_period_decompression_count / 100) * 1;                   /* 1 percent */
		running_total = 0;

		for (oldest_age_of_csegs_sampled = 0; oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE; oldest_age_of_csegs_sampled++) {
			running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			working_set_approximation += oldest_age_of_csegs_sampled * age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

			if (running_total >= working_target) {
				break;
			}
		}
		if (oldest_age_of_csegs_sampled < DECOMPRESSION_SAMPLE_MAX_AGE) {
			working_set_approximation = (working_set_approximation * 1000) / elapsed_msecs_in_sample;

			if (working_set_approximation < VM_PAGE_COMPRESSOR_COUNT) {
				running_total = overage_decompressions_during_sample_period;

				for (oldest_age_of_csegs_sampled = DECOMPRESSION_SAMPLE_MAX_AGE - 1; oldest_age_of_csegs_sampled; oldest_age_of_csegs_sampled--) {
					running_total += age_of_decompressions_during_sample_period[oldest_age_of_csegs_sampled];

					if (running_total >= aging_target) {
						break;
					}
				}
				swapout_target_age = (uint32_t)cur_ts_sec - oldest_age_of_csegs_sampled;

				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, swapout_target_age, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 2, 0);
			} else {
				KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_set_approximation, VM_PAGE_COMPRESSOR_COUNT, 0, 3, 0);
			}
		} else {
			KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, working_target, running_total, 0, 4, 0);
		}

		compressor_need_sample_reset = TRUE;
		need_eval_reset = TRUE;
	} else {
		KERNEL_DEBUG(0xe0400020 | DBG_FUNC_END, sample_period_decompression_count, (compressor_thrashing_threshold_per_10msecs * elapsed_msecs_in_sample) / 10, 0, 6, 0);
	}
done:
	if (compressor_need_sample_reset == TRUE) {
		bzero(age_of_decompressions_during_sample_period, sizeof(age_of_decompressions_during_sample_period));
		overage_decompressions_during_sample_period = 0;

		start_of_sample_period_sec = cur_ts_sec;
		start_of_sample_period_nsec = cur_ts_nsec;
		sample_period_decompression_count = 0;
		sample_period_compression_count = 0;
		last_eval_decompression_count = 0;
		last_eval_compression_count = 0;
		compressor_need_sample_reset = FALSE;
	}
	if (need_eval_reset == TRUE) {
		start_of_eval_period_sec = cur_ts_sec;
		start_of_eval_period_nsec = cur_ts_nsec;
	}
}


int             compaction_swapper_init_now = 0;
int             compaction_swapper_running = 0;
int             compaction_swapper_awakened = 0;
int             compaction_swapper_abort = 0;

bool
vm_compressor_swapout_is_ripe()
{
	bool is_ripe = false;
	if (vm_swapout_ripe_segments == TRUE && c_overage_swapped_count < c_overage_swapped_limit) {
		c_segment_t     c_seg;
		clock_sec_t     now;
		clock_sec_t     age;
		clock_nsec_t    nsec;

		clock_get_system_nanotime(&now, &nsec);
		age = 0;

		lck_mtx_lock_spin_always(c_list_lock);

		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t) queue_first(&c_age_list_head);

			age = now - c_seg->c_creation_ts;
		}
		lck_mtx_unlock_always(c_list_lock);

		if (age >= vm_ripe_target_age) {
			is_ripe = true;
		}
	}
	return is_ripe;
}

static bool
compressor_swapout_conditions_met(void)
{
	bool should_swap = false;
	if (COMPRESSOR_NEEDS_TO_SWAP()) {
		should_swap = true;
		vmcs_stats.compressor_swap_threshold_exceeded++;
	}
	if (VM_PAGE_Q_THROTTLED(&vm_pageout_queue_external) && vm_page_anonymous_count < (vm_page_inactive_count / 20)) {
		should_swap = true;
		vmcs_stats.external_q_throttled++;
	}
	if (vm_page_free_count < (vm_page_free_reserved - (COMPRESSOR_FREE_RESERVED_LIMIT * 2))) {
		should_swap = true;
		vmcs_stats.free_count_below_reserve++;
	}
	return should_swap;
}

static bool
compressor_needs_to_swap()
{
	bool should_swap = false;
	if (vm_compressor_swapout_is_ripe()) {
		should_swap = true;
		goto check_if_low_space;
	}

	if (VM_CONFIG_SWAP_IS_ACTIVE) {
		should_swap =  compressor_swapout_conditions_met();
		if (should_swap) {
			goto check_if_low_space;
		}
	}

#if (XNU_TARGET_OS_OSX && __arm64__)
	/*
	 * Thrashing detection disabled.
	 */
#else /* (XNU_TARGET_OS_OSX && __arm64__) */

	if (vm_compressor_is_thrashing()) {
		should_swap = true;
		vmcs_stats.thrashing_detected++;
	}

#if CONFIG_PHANTOM_CACHE
	if (vm_phantom_cache_check_pressure()) {
		os_atomic_store(&memorystatus_phantom_cache_pressure, true, release);
		should_swap = true;
	}
#endif
	if (swapout_target_age) {
		should_swap = true;
	}
#endif /* (XNU_TARGET_OS_OSX && __arm64__) */

check_if_low_space:

#if CONFIG_JETSAM
	if (should_swap || vm_compressor_low_on_space() == TRUE) {
		if (vm_compressor_thrashing_detected == FALSE) {
			vm_compressor_thrashing_detected = TRUE;

			if (swapout_target_age) {
				compressor_thrashing_induced_jetsam++;
			} else if (vm_compressor_low_on_space() == TRUE) {
				compressor_thrashing_induced_jetsam++;
			} else {
				filecache_thrashing_induced_jetsam++;
			}
			/*
			 * Wake up the memorystatus thread so that it can return
			 * the system to a healthy state (by killing processes).
			 */
			memorystatus_thread_wake();
		}
		/*
		 * let the jetsam take precedence over
		 * any major compactions we might have
		 * been able to do... otherwise we run
		 * the risk of doing major compactions
		 * on segments we're about to free up
		 * due to the jetsam activity.
		 */
		should_swap = false;
		if (memorystatus_swap_all_apps && vm_swap_low_on_space()) {
			vm_compressor_take_paging_space_action();
		}
	}

#else /* CONFIG_JETSAM */
	if (should_swap && vm_swap_low_on_space()) {
		vm_compressor_take_paging_space_action();
	}
#endif /* CONFIG_JETSAM */

	if (should_swap == false) {
		/*
		 * vm_compressor_needs_to_major_compact returns true only if we're
		 * about to run out of available compressor segments... in this
		 * case, we absolutely need to run a major compaction even if
		 * we've just kicked off a jetsam or we don't otherwise need to
		 * swap... terminating objects releases
		 * pages back to the uncompressed cache, but does not guarantee
		 * that we will free up even a single compression segment
		 */
		should_swap = vm_compressor_needs_to_major_compact();
		if (should_swap) {
			vmcs_stats.fragmentation_detected++;
		}
	}

	/*
	 * returning TRUE when swap_supported == FALSE
	 * will cause the major compaction engine to
	 * run, but will not trigger any swapping...
	 * segments that have been major compacted
	 * will be moved to the majorcompact queue
	 */
	return should_swap;
}

#if CONFIG_JETSAM
/*
 * This function is called from the jetsam thread after killing something to
 * mitigate thrashing.
 *
 * We need to restart our thrashing detection heuristics since memory pressure
 * has potentially changed significantly, and we don't want to detect on old
 * data from before the jetsam.
 */
void
vm_thrashing_jetsam_done(void)
{
	vm_compressor_thrashing_detected = FALSE;

	/* Were we compressor-thrashing or filecache-thrashing? */
	if (swapout_target_age) {
		swapout_target_age = 0;
		compressor_need_sample_reset = TRUE;
	}
#if CONFIG_PHANTOM_CACHE
	else {
		vm_phantom_cache_restart_sample();
	}
#endif
}
#endif /* CONFIG_JETSAM */

uint32_t vm_wake_compactor_swapper_calls = 0;
uint32_t vm_run_compactor_already_running = 0;
uint32_t vm_run_compactor_empty_minor_q = 0;
uint32_t vm_run_compactor_did_compact = 0;
uint32_t vm_run_compactor_waited = 0;

void
vm_run_compactor(void)
{
	if (c_segment_count == 0) {
		return;
	}

	lck_mtx_lock_spin_always(c_list_lock);

	if (c_minor_count == 0) {
		vm_run_compactor_empty_minor_q++;

		lck_mtx_unlock_always(c_list_lock);
		return;
	}
	if (compaction_swapper_running) {
		if (vm_pageout_state.vm_restricted_to_single_processor == FALSE) {
			vm_run_compactor_already_running++;

			lck_mtx_unlock_always(c_list_lock);
			return;
		}
		vm_run_compactor_waited++;

		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);

		thread_block(THREAD_CONTINUE_NULL);

		return;
	}
	vm_run_compactor_did_compact++;

	fastwake_warmup = FALSE;
	compaction_swapper_running = 1;

	vm_compressor_do_delayed_compactions(FALSE);

	compaction_swapper_running = 0;

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);
}


void
vm_wake_compactor_swapper(void)
{
	if (compaction_swapper_running || compaction_swapper_awakened || c_segment_count == 0) {
		return;
	}

	if (c_minor_count || vm_compressor_needs_to_major_compact()) {
		lck_mtx_lock_spin_always(c_list_lock);

		fastwake_warmup = FALSE;

		if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
			vm_wake_compactor_swapper_calls++;

			compaction_swapper_awakened = 1;
			thread_wakeup((event_t)&c_compressor_swap_trigger);
		}
		lck_mtx_unlock_always(c_list_lock);
	}
}


void
vm_consider_swapping()
{
	assert(VM_CONFIG_SWAP_IS_PRESENT);

	lck_mtx_lock_spin_always(c_list_lock);

	compaction_swapper_abort = 1;

	while (compaction_swapper_running) {
		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);

		thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);
	}
	compaction_swapper_abort = 0;
	compaction_swapper_running = 1;

	vm_swapout_ripe_segments = TRUE;

	vm_compressor_process_major_segments(vm_swapout_ripe_segments);

	vm_compressor_compact_and_swap(FALSE);

	compaction_swapper_running = 0;

	vm_swapout_ripe_segments = FALSE;

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);
}


void
vm_consider_waking_compactor_swapper(void)
{
	boolean_t       need_wakeup = FALSE;

	if (c_segment_count == 0) {
		return;
	}

	if (compaction_swapper_running || compaction_swapper_awakened) {
		return;
	}

	if (!compaction_swapper_inited && !compaction_swapper_init_now) {
		compaction_swapper_init_now = 1;
		need_wakeup = TRUE;
	}

	if (c_minor_count && (COMPRESSOR_NEEDS_TO_MINOR_COMPACT())) {
		need_wakeup = TRUE;
	} else if (compressor_needs_to_swap()) {
		need_wakeup = TRUE;
	} else if (c_minor_count) {
		uint64_t        total_bytes;

		total_bytes = compressor_object->resident_page_count * PAGE_SIZE_64;

		if ((total_bytes - compressor_bytes_used) > total_bytes / 10) {
			need_wakeup = TRUE;
		}
	}
	if (need_wakeup == TRUE) {
		lck_mtx_lock_spin_always(c_list_lock);

		fastwake_warmup = FALSE;

		if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
			memoryshot(VM_WAKEUP_COMPACTOR_SWAPPER, DBG_FUNC_NONE);

			compaction_swapper_awakened = 1;
			thread_wakeup((event_t)&c_compressor_swap_trigger);
		}
		lck_mtx_unlock_always(c_list_lock);
	}
}


#define C_SWAPOUT_LIMIT                 4
#define DELAYED_COMPACTIONS_PER_PASS    30

void
vm_compressor_do_delayed_compactions(boolean_t flush_all)
{
	c_segment_t     c_seg;
	int             number_compacted = 0;
	boolean_t       needs_to_swap = FALSE;
	uint32_t        c_swapout_count = 0;


	VM_DEBUG_CONSTANT_EVENT(vm_compressor_do_delayed_compactions, VM_COMPRESSOR_DO_DELAYED_COMPACTIONS, DBG_FUNC_START, c_minor_count, flush_all, 0, 0);

#if XNU_TARGET_OS_OSX
	LCK_MTX_ASSERT(c_list_lock, LCK_MTX_ASSERT_OWNED);
#endif /* XNU_TARGET_OS_OSX */

	while (!queue_empty(&c_minor_list_head) && needs_to_swap == FALSE) {
		c_seg = (c_segment_t)queue_first(&c_minor_list_head);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {
			lck_mtx_unlock_always(c_list_lock);
			c_seg_wait_on_busy(c_seg);
			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		C_SEG_BUSY(c_seg);

		c_seg_do_minor_compaction_and_unlock(c_seg, TRUE, FALSE, TRUE);

		c_swapout_count = c_early_swapout_count + c_regular_swapout_count + c_late_swapout_count;
		if (VM_CONFIG_SWAP_IS_ACTIVE && (number_compacted++ > DELAYED_COMPACTIONS_PER_PASS)) {
			if ((flush_all == TRUE || compressor_needs_to_swap()) && c_swapout_count < C_SWAPOUT_LIMIT) {
				needs_to_swap = TRUE;
			}

			number_compacted = 0;
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}

	VM_DEBUG_CONSTANT_EVENT(vm_compressor_do_delayed_compactions, VM_COMPRESSOR_DO_DELAYED_COMPACTIONS, DBG_FUNC_END, c_minor_count, number_compacted, needs_to_swap, 0);
}

int min_csegs_per_major_compaction = DELAYED_COMPACTIONS_PER_PASS;

static bool
vm_compressor_major_compact_cseg(c_segment_t c_seg, uint32_t* c_seg_considered, bool* bail_wanted_cseg, uint64_t* total_bytes_freed)
{
	/*
	 * Major compaction
	 */
	bool keep_compacting = true, fully_compacted = true;
	queue_head_t *list_head = NULL;
	c_segment_t c_seg_next;
	uint64_t        bytes_to_free = 0, bytes_freed = 0;
	uint32_t        number_considered = 0;

	if (c_seg->c_state == C_ON_AGE_Q) {
		assert(!c_seg->c_has_donated_pages);
		list_head = &c_age_list_head;
	} else if (c_seg->c_state == C_ON_SWAPPEDIN_Q) {
		assert(c_seg->c_has_donated_pages);
		list_head = &c_late_swappedin_list_head;
	}

	while (keep_compacting == TRUE) {
		assert(c_seg->c_busy);

		/* look for another segment to consolidate */

		c_seg_next = (c_segment_t) queue_next(&c_seg->c_age_list);

		if (queue_end(list_head, (queue_entry_t)c_seg_next)) {
			break;
		}

		assert(c_seg_next->c_state == c_seg->c_state);

		number_considered++;

		if (c_seg_major_compact_ok(c_seg, c_seg_next) == FALSE) {
			break;
		}

		lck_mtx_lock_spin_always(&c_seg_next->c_lock);

		if (c_seg_next->c_busy) {
			/*
			 * We are going to block for our neighbor.
			 * If our c_seg is wanted, we should unbusy
			 * it because we don't know how long we might
			 * have to block here.
			 */
			if (c_seg->c_wanted) {
				lck_mtx_unlock_always(&c_seg_next->c_lock);
				fully_compacted = false;
				c_seg_major_compact_stats[c_seg_major_compact_stats_now].bailed_compactions++;
				*bail_wanted_cseg = true;
				break;
			}

			lck_mtx_unlock_always(c_list_lock);

			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 8, (void*) VM_KERNEL_ADDRPERM(c_seg_next), 0, 0);

			c_seg_wait_on_busy(c_seg_next);
			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		/* grab that segment */
		C_SEG_BUSY(c_seg_next);

		bytes_to_free = C_SEG_OFFSET_TO_BYTES(c_seg_next->c_populated_offset);
		if (c_seg_do_minor_compaction_and_unlock(c_seg_next, FALSE, TRUE, TRUE)) {
			/*
			 * found an empty c_segment and freed it
			 * so we can't continue to use c_seg_next
			 */
			bytes_freed += bytes_to_free;
			c_seg_major_compact_stats[c_seg_major_compact_stats_now].count_of_freed_segs++;
			continue;
		}

		/* unlock the list ... */
		lck_mtx_unlock_always(c_list_lock);

		/* do the major compaction */

		keep_compacting = c_seg_major_compact(c_seg, c_seg_next);

		VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 9, keep_compacting, 0, 0);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg_next->c_lock);
		/*
		 * run a minor compaction on the donor segment
		 * since we pulled at least some of it's
		 * data into our target...  if we've emptied
		 * it, now is a good time to free it which
		 * c_seg_minor_compaction_and_unlock also takes care of
		 *
		 * by passing TRUE, we ask for c_busy to be cleared
		 * and c_wanted to be taken care of
		 */
		bytes_to_free = C_SEG_OFFSET_TO_BYTES(c_seg_next->c_populated_offset);
		if (c_seg_minor_compaction_and_unlock(c_seg_next, TRUE)) {
			bytes_freed += bytes_to_free;
			c_seg_major_compact_stats[c_seg_major_compact_stats_now].count_of_freed_segs++;
		} else {
			bytes_to_free -= C_SEG_OFFSET_TO_BYTES(c_seg_next->c_populated_offset);
			bytes_freed += bytes_to_free;
		}

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		/* relock the list */
		lck_mtx_lock_spin_always(c_list_lock);

		if (c_seg->c_wanted) {
			/*
			 * Our c_seg is in demand. Let's
			 * unbusy it and wakeup the waiters
			 * instead of continuing the compaction
			 * because we could be in this loop
			 * for a while.
			 */
			fully_compacted = false;
			*bail_wanted_cseg = true;
			c_seg_major_compact_stats[c_seg_major_compact_stats_now].bailed_compactions++;
			break;
		}
	} /* major compaction */

	VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 10, number_considered, *bail_wanted_cseg, 0);

	*c_seg_considered += number_considered;
	*total_bytes_freed += bytes_freed;

	lck_mtx_lock_spin_always(&c_seg->c_lock);
	return fully_compacted;
}

#define TIME_SUB(rsecs, secs, rfrac, frac, unit)                        \
	MACRO_BEGIN                                                     \
	if ((int)((rfrac) -= (frac)) < 0) {                             \
	        (rfrac) += (unit);                                      \
	        (rsecs) -= 1;                                           \
	}                                                               \
	(rsecs) -= (secs);                                              \
	MACRO_END

clock_nsec_t c_process_major_report_over_ms = 9; /* report if over 9 ms */
int c_process_major_yield_after = 1000; /* yield after moving 1,000 segments */
uint64_t c_process_major_reports = 0;
clock_sec_t c_process_major_max_sec = 0;
clock_nsec_t c_process_major_max_nsec = 0;
uint32_t c_process_major_peak_segcount = 0;
static void
vm_compressor_process_major_segments(bool ripe_age_only)
{
	c_segment_t c_seg = NULL;
	int count = 0, total = 0, breaks = 0;
	clock_sec_t start_sec, end_sec;
	clock_nsec_t start_nsec, end_nsec;
	clock_nsec_t report_over_ns;

	if (queue_empty(&c_major_list_head)) {
		return;
	}

	// printf("%s: starting to move segments from MAJORQ to AGEQ\n", __FUNCTION__);
	if (c_process_major_report_over_ms != 0) {
		report_over_ns = c_process_major_report_over_ms * NSEC_PER_MSEC;
	} else {
		report_over_ns = (clock_nsec_t)-1;
	}

	if (ripe_age_only) {
		if (c_overage_swapped_count >= c_overage_swapped_limit) {
			/*
			 * Return while we wait for the overage segments
			 * in our queue to get pushed out first.
			 */
			return;
		}
	}

	clock_get_system_nanotime(&start_sec, &start_nsec);
	while (!queue_empty(&c_major_list_head)) {
		if (!ripe_age_only) {
			/*
			 * Start from the end to preserve aging order. The newer
			 * segments are at the tail and so need to be inserted in
			 * the aging queue in this way so we have the older segments
			 * at the end of the AGE_Q.
			 */
			c_seg = (c_segment_t)queue_last(&c_major_list_head);
		} else {
			c_seg = (c_segment_t)queue_first(&c_major_list_head);
			if ((start_sec - c_seg->c_creation_ts) < vm_ripe_target_age) {
				/*
				 * We have found the first segment in our queue that is not ripe. Segments after it
				 * will be the same. So let's bail here. Return with c_list_lock held.
				 */
				break;
			}
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);
		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
		lck_mtx_unlock_always(&c_seg->c_lock);

		count++;
		if (count == c_process_major_yield_after ||
		    queue_empty(&c_major_list_head)) {
			/* done or time to take a break */
		} else {
			/* keep going */
			continue;
		}

		total += count;
		clock_get_system_nanotime(&end_sec, &end_nsec);
		TIME_SUB(end_sec, start_sec, end_nsec, start_nsec, NSEC_PER_SEC);
		if (end_sec > c_process_major_max_sec) {
			c_process_major_max_sec = end_sec;
			c_process_major_max_nsec = end_nsec;
		} else if (end_sec == c_process_major_max_sec &&
		    end_nsec > c_process_major_max_nsec) {
			c_process_major_max_nsec = end_nsec;
		}
		if (total > c_process_major_peak_segcount) {
			c_process_major_peak_segcount = total;
		}
		if (end_sec > 0 ||
		    end_nsec >= report_over_ns) {
			/* we used more than expected */
			c_process_major_reports++;
			printf("%s: moved %d/%d segments from MAJORQ to AGEQ in %lu.%09u seconds and %d breaks\n",
			    __FUNCTION__, count, total,
			    end_sec, end_nsec, breaks);
		}
		if (queue_empty(&c_major_list_head)) {
			/* done */
			break;
		}
		/* take a break to allow someone else to grab the lock */
		lck_mtx_unlock_always(c_list_lock);
		mutex_pause(0); /* 10 microseconds */
		lck_mtx_lock_spin_always(c_list_lock);
		/* start again */
		clock_get_system_nanotime(&start_sec, &start_nsec);
		count = 0;
		breaks++;
	}
}

/*
 * macOS special swappable csegs -> early_swapin queue
 * non-macOS special swappable+non-freezer csegs -> late_swapin queue
 * Processing special csegs means minor compacting each cseg and then
 * major compacting it and putting them on the early or late
 * (depending on platform) swapout queue.
 */
static void
vm_compressor_process_special_swapped_in_segments_locked(void)
{
	c_segment_t c_seg = NULL;
	bool            switch_state = true, bail_wanted_cseg = false;
	unsigned int    number_considered = 0, yield_after_considered_per_pass = 0;
	uint64_t        bytes_freed = 0;
	queue_head_t    *special_swappedin_list_head;

#if XNU_TARGET_OS_OSX
	special_swappedin_list_head = &c_early_swappedin_list_head;
#else /* XNU_TARGET_OS_OSX */
	if (memorystatus_swap_all_apps) {
		special_swappedin_list_head = &c_late_swappedin_list_head;
	} else {
		/* called on unsupported config*/
		return;
	}
#endif /* XNU_TARGET_OS_OSX */

	yield_after_considered_per_pass = MAX(min_csegs_per_major_compaction, DELAYED_COMPACTIONS_PER_PASS);
	while (!queue_empty(special_swappedin_list_head)) {
		c_seg = (c_segment_t)queue_first(special_swappedin_list_head);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {
			lck_mtx_unlock_always(c_list_lock);
			c_seg_wait_on_busy(c_seg);
			lck_mtx_lock_spin_always(c_list_lock);
			continue;
		}

		C_SEG_BUSY(c_seg);
		lck_mtx_unlock_always(&c_seg->c_lock);
		lck_mtx_unlock_always(c_list_lock);

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg_minor_compaction_and_unlock(c_seg, FALSE /*clear busy?*/)) {
			/*
			 * found an empty c_segment and freed it
			 * so go grab the next guy in the queue
			 */
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			lck_mtx_lock_spin_always(c_list_lock);
			continue;
		}

		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		lck_mtx_lock_spin_always(c_list_lock);

		switch_state = vm_compressor_major_compact_cseg(c_seg, &number_considered, &bail_wanted_cseg, &bytes_freed);
		assert(c_seg->c_busy);
		assert(!c_seg->c_on_minorcompact_q);

		if (switch_state) {
			if (VM_CONFIG_SWAP_IS_ACTIVE || VM_CONFIG_FREEZER_SWAP_IS_ACTIVE) {
				/*
				 * Ordinarily we let swapped in segments age out + get
				 * major compacted with the rest of the c_segs on the ageQ.
				 * But the early donated c_segs, if well compacted, should be
				 * kept ready to be swapped out if needed. These are typically
				 * describing memory belonging to a leaky app (macOS) or a swap-
				 * capable app (iPadOS) and for the latter we can keep these
				 * around longer because we control the triggers in the memorystatus
				 * subsystem
				 */
				c_seg_switch_state(c_seg, C_ON_SWAPOUT_Q, FALSE);
			}
		}

		C_SEG_WAKEUP_DONE(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);

		if (number_considered >= yield_after_considered_per_pass) {
			if (bail_wanted_cseg) {
				/*
				 * We stopped major compactions on a c_seg
				 * that is wanted. We don't know the priority
				 * of the waiter unfortunately but we are at
				 * a very high priority and so, just in case
				 * the waiter is a critical system daemon or
				 * UI thread, let's give up the CPU in case
				 * the system is running a few CPU intensive
				 * tasks.
				 */
				bail_wanted_cseg = false;
				lck_mtx_unlock_always(c_list_lock);

				mutex_pause(2); /* 100us yield */

				lck_mtx_lock_spin_always(c_list_lock);
			}

			number_considered = 0;
		}
	}
}

void
vm_compressor_process_special_swapped_in_segments(void)
{
	lck_mtx_lock_spin_always(c_list_lock);
	vm_compressor_process_special_swapped_in_segments_locked();
	lck_mtx_unlock_always(c_list_lock);
}

#define C_SEGMENT_SWAPPEDIN_AGE_LIMIT   10
/*
 * Processing regular csegs means aging them.
 */
static void
vm_compressor_process_regular_swapped_in_segments(boolean_t flush_all)
{
	c_segment_t     c_seg;
	clock_sec_t     now;
	clock_nsec_t    nsec;

	clock_get_system_nanotime(&now, &nsec);

	while (!queue_empty(&c_regular_swappedin_list_head)) {
		c_seg = (c_segment_t)queue_first(&c_regular_swappedin_list_head);

		if (flush_all == FALSE && (now - c_seg->c_swappedin_ts) < C_SEGMENT_SWAPPEDIN_AGE_LIMIT) {
			break;
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
		c_seg->c_agedin_ts = (uint32_t) now;

		lck_mtx_unlock_always(&c_seg->c_lock);
	}
}


extern  int     vm_num_swap_files;
extern  int     vm_num_pinned_swap_files;
extern  int     vm_swappin_enabled;

extern  unsigned int    vm_swapfile_total_segs_used;
extern  unsigned int    vm_swapfile_total_segs_alloced;


void
vm_compressor_flush(void)
{
	uint64_t        vm_swap_put_failures_at_start;
	wait_result_t   wait_result = 0;
	AbsoluteTime    startTime, endTime;
	clock_sec_t     now_sec;
	clock_nsec_t    now_nsec;
	uint64_t        nsec;
	c_segment_t     c_seg, c_seg_next;

	HIBLOG("vm_compressor_flush - starting\n");

	clock_get_uptime(&startTime);

	lck_mtx_lock_spin_always(c_list_lock);

	fastwake_warmup = FALSE;
	compaction_swapper_abort = 1;

	while (compaction_swapper_running) {
		assert_wait((event_t)&compaction_swapper_running, THREAD_UNINT);

		lck_mtx_unlock_always(c_list_lock);

		thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);
	}
	compaction_swapper_abort = 0;
	compaction_swapper_running = 1;

	hibernate_flushing = TRUE;
	hibernate_no_swapspace = FALSE;
	hibernate_flush_timed_out = FALSE;
	c_generation_id_flush_barrier = c_generation_id + 1000;

	clock_get_system_nanotime(&now_sec, &now_nsec);
	hibernate_flushing_deadline = now_sec + HIBERNATE_FLUSHING_SECS_TO_COMPLETE;

	vm_swap_put_failures_at_start = vm_swap_put_failures;

	/*
	 * We are about to hibernate and so we want all segments flushed to disk.
	 * Segments that are on the major compaction queue won't be considered in
	 * the vm_compressor_compact_and_swap() pass. So we need to bring them to
	 * the ageQ for consideration.
	 */
	if (!queue_empty(&c_major_list_head)) {
		c_seg = (c_segment_t)queue_first(&c_major_list_head);

		while (!queue_end(&c_major_list_head, (queue_entry_t)c_seg)) {
			c_seg_next = (c_segment_t) queue_next(&c_seg->c_age_list);
			lck_mtx_lock_spin_always(&c_seg->c_lock);
			c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
			lck_mtx_unlock_always(&c_seg->c_lock);
			c_seg = c_seg_next;
		}
	}
	vm_compressor_compact_and_swap(TRUE);

	while (!queue_empty(&c_early_swapout_list_head) || !queue_empty(&c_regular_swapout_list_head) || !queue_empty(&c_late_swapout_list_head)) {
		assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 5000, 1000 * NSEC_PER_USEC);

		lck_mtx_unlock_always(c_list_lock);

		wait_result = thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin_always(c_list_lock);

		if (wait_result == THREAD_TIMED_OUT) {
			break;
		}
	}
	hibernate_flushing = FALSE;
	compaction_swapper_running = 0;

	if (vm_swap_put_failures > vm_swap_put_failures_at_start) {
		HIBLOG("vm_compressor_flush failed to clean %llu segments - vm_page_compressor_count(%d)\n",
		    vm_swap_put_failures - vm_swap_put_failures_at_start, VM_PAGE_COMPRESSOR_COUNT);
	}

	lck_mtx_unlock_always(c_list_lock);

	thread_wakeup((event_t)&compaction_swapper_running);

	clock_get_uptime(&endTime);
	SUB_ABSOLUTETIME(&endTime, &startTime);
	absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_flush completed - took %qd msecs - vm_num_swap_files = %d, vm_num_pinned_swap_files = %d, vm_swappin_enabled = %d\n",
	    nsec / 1000000ULL, vm_num_swap_files, vm_num_pinned_swap_files, vm_swappin_enabled);
}


int             compaction_swap_trigger_thread_awakened = 0;

static void
vm_compressor_swap_trigger_thread(void)
{
	current_thread()->options |= TH_OPT_VMPRIV;

	/*
	 * compaction_swapper_init_now is set when the first call to
	 * vm_consider_waking_compactor_swapper is made from
	 * vm_pageout_scan... since this function is called upon
	 * thread creation, we want to make sure to delay adjusting
	 * the tuneables until we are awakened via vm_pageout_scan
	 * so that we are at a point where the vm_swapfile_open will
	 * be operating on the correct directory (in case the default
	 * of using the VM volume is overridden by the dynamic_pager)
	 */
	if (compaction_swapper_init_now) {
		vm_compaction_swapper_do_init();

		if (vm_pageout_state.vm_restricted_to_single_processor == TRUE) {
			thread_vm_bind_group_add();
		}
#if CONFIG_THREAD_GROUPS
		thread_group_vm_add();
#endif
		thread_set_thread_name(current_thread(), "VM_cswap_trigger");
		compaction_swapper_init_now = 0;
	}
	lck_mtx_lock_spin_always(c_list_lock);

	compaction_swap_trigger_thread_awakened++;
	compaction_swapper_awakened = 0;

	if (compaction_swapper_running == 0) {
		compaction_swapper_running = 1;

		vm_compressor_compact_and_swap(FALSE);

		compaction_swapper_running = 0;
	}
	assert_wait((event_t)&c_compressor_swap_trigger, THREAD_UNINT);

	if (compaction_swapper_running == 0) {
		thread_wakeup((event_t)&compaction_swapper_running);
	}

	lck_mtx_unlock_always(c_list_lock);

	thread_block((thread_continue_t)vm_compressor_swap_trigger_thread);

	/* NOTREACHED */
}


void
vm_compressor_record_warmup_start(void)
{
	c_segment_t     c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (first_c_segment_to_warm_generation_id == 0) {
		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			first_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else {
			first_c_segment_to_warm_generation_id = 0;
		}

		fastwake_recording_in_progress = TRUE;
	}
	lck_mtx_unlock_always(c_list_lock);
}


void
vm_compressor_record_warmup_end(void)
{
	c_segment_t     c_seg;

	lck_mtx_lock_spin_always(c_list_lock);

	if (fastwake_recording_in_progress == TRUE) {
		if (!queue_empty(&c_age_list_head)) {
			c_seg = (c_segment_t)queue_last(&c_age_list_head);

			last_c_segment_to_warm_generation_id = c_seg->c_generation_id;
		} else {
			last_c_segment_to_warm_generation_id = first_c_segment_to_warm_generation_id;
		}

		fastwake_recording_in_progress = FALSE;

		HIBLOG("vm_compressor_record_warmup (%qd - %qd)\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);
	}
	lck_mtx_unlock_always(c_list_lock);
}


#define DELAY_TRIM_ON_WAKE_SECS         25

void
vm_compressor_delay_trim(void)
{
	clock_sec_t     sec;
	clock_nsec_t    nsec;

	clock_get_system_nanotime(&sec, &nsec);
	dont_trim_until_ts = sec + DELAY_TRIM_ON_WAKE_SECS;
}


void
vm_compressor_do_warmup(void)
{
	lck_mtx_lock_spin_always(c_list_lock);

	if (first_c_segment_to_warm_generation_id == last_c_segment_to_warm_generation_id) {
		first_c_segment_to_warm_generation_id = last_c_segment_to_warm_generation_id = 0;

		lck_mtx_unlock_always(c_list_lock);
		return;
	}

	if (compaction_swapper_running == 0 && compaction_swapper_awakened == 0) {
		fastwake_warmup = TRUE;

		compaction_swapper_awakened = 1;
		thread_wakeup((event_t)&c_compressor_swap_trigger);
	}
	lck_mtx_unlock_always(c_list_lock);
}

void
do_fastwake_warmup_all(void)
{
	lck_mtx_lock_spin_always(c_list_lock);

	if (queue_empty(&c_swappedout_list_head) && queue_empty(&c_swappedout_sparse_list_head)) {
		lck_mtx_unlock_always(c_list_lock);
		return;
	}

	fastwake_warmup = TRUE;

	do_fastwake_warmup(&c_swappedout_list_head, TRUE);

	do_fastwake_warmup(&c_swappedout_sparse_list_head, TRUE);

	fastwake_warmup = FALSE;

	lck_mtx_unlock_always(c_list_lock);
}

void
do_fastwake_warmup(queue_head_t *c_queue, boolean_t consider_all_cseg)
{
	c_segment_t     c_seg = NULL;
	AbsoluteTime    startTime, endTime;
	uint64_t        nsec;


	HIBLOG("vm_compressor_fastwake_warmup (%qd - %qd) - starting\n", first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id);

	clock_get_uptime(&startTime);

	lck_mtx_unlock_always(c_list_lock);

	proc_set_thread_policy(current_thread(),
	    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER2);

	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(c_list_lock);

	while (!queue_empty(c_queue) && fastwake_warmup == TRUE) {
		c_seg = (c_segment_t) queue_first(c_queue);

		if (consider_all_cseg == FALSE) {
			if (c_seg->c_generation_id < first_c_segment_to_warm_generation_id ||
			    c_seg->c_generation_id > last_c_segment_to_warm_generation_id) {
				break;
			}

			if (vm_page_free_count < (AVAILABLE_MEMORY / 4)) {
				break;
			}
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);
		lck_mtx_unlock_always(c_list_lock);

		if (c_seg->c_busy) {
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			c_seg_wait_on_busy(c_seg);
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		} else {
			if (c_seg_swapin(c_seg, TRUE, FALSE) == 0) {
				lck_mtx_unlock_always(&c_seg->c_lock);
			}
			c_segment_warmup_count++;

			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			vm_pageout_io_throttle();
			PAGE_REPLACEMENT_DISALLOWED(TRUE);
		}
		lck_mtx_lock_spin_always(c_list_lock);
	}
	lck_mtx_unlock_always(c_list_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	proc_set_thread_policy(current_thread(),
	    TASK_POLICY_INTERNAL, TASK_POLICY_IO, THROTTLE_LEVEL_COMPRESSOR_TIER0);

	clock_get_uptime(&endTime);
	SUB_ABSOLUTETIME(&endTime, &startTime);
	absolutetime_to_nanoseconds(endTime, &nsec);

	HIBLOG("vm_compressor_fastwake_warmup completed - took %qd msecs\n", nsec / 1000000ULL);

	lck_mtx_lock_spin_always(c_list_lock);

	if (consider_all_cseg == FALSE) {
		first_c_segment_to_warm_generation_id = last_c_segment_to_warm_generation_id = 0;
	}
}

extern bool     vm_swapout_thread_running;
extern boolean_t        compressor_store_stop_compaction;

void
vm_compressor_compact_and_swap(boolean_t flush_all)
{
	c_segment_t     c_seg;
	bool            switch_state, bail_wanted_cseg = false;
	clock_sec_t     now;
	clock_nsec_t    nsec;
	mach_timespec_t start_ts, end_ts;
	unsigned int    number_considered, wanted_cseg_found, yield_after_considered_per_pass, number_yields;
	uint64_t        bytes_freed, delta_usec;
	uint32_t        c_swapout_count = 0;

	VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_START, c_age_count, c_minor_count, c_major_count, vm_page_free_count);

	if (fastwake_warmup == TRUE) {
		uint64_t        starting_warmup_count;

		starting_warmup_count = c_segment_warmup_count;

		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 11) | DBG_FUNC_START, c_segment_warmup_count,
		    first_c_segment_to_warm_generation_id, last_c_segment_to_warm_generation_id, 0, 0);
		do_fastwake_warmup(&c_swappedout_list_head, FALSE);
		KERNEL_DEBUG_CONSTANT(IOKDBG_CODE(DBG_HIBERNATE, 11) | DBG_FUNC_END, c_segment_warmup_count, c_segment_warmup_count - starting_warmup_count, 0, 0, 0);

		fastwake_warmup = FALSE;
	}

#if (XNU_TARGET_OS_OSX && __arm64__)
	/*
	 * Re-considering major csegs showed benefits on all platforms by
	 * significantly reducing fragmentation and getting back memory.
	 * However, on smaller devices, eg watch, there was increased power
	 * use for the additional compactions. And the turnover in csegs on
	 * those smaller platforms is high enough in the decompression/free
	 * path that we can skip reconsidering them here because we already
	 * consider them for major compaction in those paths.
	 */
	vm_compressor_process_major_segments(false /*all segments and not just the ripe-aged ones*/);
#endif /* (XNU_TARGET_OS_OSX && __arm64__) */

	/*
	 * it's possible for the c_age_list_head to be empty if we
	 * hit our limits for growing the compressor pool and we subsequently
	 * hibernated... on the next hibernation we could see the queue as
	 * empty and not proceeed even though we have a bunch of segments on
	 * the swapped in queue that need to be dealt with.
	 */
	vm_compressor_do_delayed_compactions(flush_all);
	vm_compressor_process_special_swapped_in_segments_locked();
	vm_compressor_process_regular_swapped_in_segments(flush_all);

	/*
	 * we only need to grab the timestamp once per
	 * invocation of this function since the
	 * timescale we're interested in is measured
	 * in days
	 */
	clock_get_system_nanotime(&now, &nsec);

	start_ts.tv_sec = (int) now;
	start_ts.tv_nsec = nsec;
	delta_usec = 0;
	number_considered = 0;
	wanted_cseg_found = 0;
	number_yields = 0;
	bytes_freed = 0;
	yield_after_considered_per_pass = MAX(min_csegs_per_major_compaction, DELAYED_COMPACTIONS_PER_PASS);

#if 0
	/**
	 * SW: Need to figure out how to properly rate limit this log because it is currently way too
	 * noisy. rdar://99379414 (Figure out how to rate limit the fragmentation level logging)
	 */
	os_log(OS_LOG_DEFAULT, "memorystatus: before compaction fragmentation level %u\n", vm_compressor_fragmentation_level());
#endif

	while (!queue_empty(&c_age_list_head) && !compaction_swapper_abort && !compressor_store_stop_compaction) {
		if (hibernate_flushing == TRUE) {
			clock_sec_t     sec;

			if (hibernate_should_abort()) {
				HIBLOG("vm_compressor_flush - hibernate_should_abort returned TRUE\n");
				break;
			}
			if (hibernate_no_swapspace == TRUE) {
				HIBLOG("vm_compressor_flush - out of swap space\n");
				break;
			}
			if (vm_swap_files_pinned() == FALSE) {
				HIBLOG("vm_compressor_flush - unpinned swap files\n");
				break;
			}
			if (hibernate_in_progress_with_pinned_swap == TRUE &&
			    (vm_swapfile_total_segs_alloced == vm_swapfile_total_segs_used)) {
				HIBLOG("vm_compressor_flush - out of pinned swap space\n");
				break;
			}
			clock_get_system_nanotime(&sec, &nsec);

			if (sec > hibernate_flushing_deadline) {
				hibernate_flush_timed_out = TRUE;
				HIBLOG("vm_compressor_flush - failed to finish before deadline\n");
				break;
			}
		}

		c_swapout_count = c_early_swapout_count + c_regular_swapout_count + c_late_swapout_count;
		if (VM_CONFIG_SWAP_IS_ACTIVE && !vm_swap_out_of_space() && c_swapout_count >= C_SWAPOUT_LIMIT) {
			assert_wait_timeout((event_t) &compaction_swapper_running, THREAD_INTERRUPTIBLE, 100, 1000 * NSEC_PER_USEC);

			if (!vm_swapout_thread_running) {
				thread_wakeup((event_t)&vm_swapout_thread);
			}

			lck_mtx_unlock_always(c_list_lock);

			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 1, c_swapout_count, 0, 0);

			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock_spin_always(c_list_lock);
		}
		/*
		 * Minor compactions
		 */
		vm_compressor_do_delayed_compactions(flush_all);

		/*
		 * vm_compressor_process_early_swapped_in_segments()
		 * might be too aggressive. So OFF for now.
		 */
		vm_compressor_process_regular_swapped_in_segments(flush_all);

		/* Recompute because we dropped the c_list_lock above*/
		c_swapout_count = c_early_swapout_count + c_regular_swapout_count + c_late_swapout_count;
		if (VM_CONFIG_SWAP_IS_ACTIVE && !vm_swap_out_of_space() && c_swapout_count >= C_SWAPOUT_LIMIT) {
			/*
			 * we timed out on the above thread_block
			 * let's loop around and try again
			 * the timeout allows us to continue
			 * to do minor compactions to make
			 * more memory available
			 */
			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 2, c_swapout_count, 0, 0);

			continue;
		}

		/*
		 * Swap out segments?
		 */
		if (flush_all == FALSE) {
			bool needs_to_swap;

			lck_mtx_unlock_always(c_list_lock);

			needs_to_swap = compressor_needs_to_swap();

			lck_mtx_lock_spin_always(c_list_lock);

			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 3, needs_to_swap, 0, 0);

			if (!needs_to_swap) {
				break;
			}
		}
		if (queue_empty(&c_age_list_head)) {
			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 4, c_age_count, 0, 0);
			break;
		}
		c_seg = (c_segment_t) queue_first(&c_age_list_head);

		assert(c_seg->c_state == C_ON_AGE_Q);

		if (flush_all == TRUE && c_seg->c_generation_id > c_generation_id_flush_barrier) {
			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 5, 0, 0, 0);
			break;
		}

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg->c_busy) {
			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 6, (void*) VM_KERNEL_ADDRPERM(c_seg), 0, 0);

			lck_mtx_unlock_always(c_list_lock);
			c_seg_wait_on_busy(c_seg);
			lck_mtx_lock_spin_always(c_list_lock);

			continue;
		}
		C_SEG_BUSY(c_seg);

		if (c_seg_do_minor_compaction_and_unlock(c_seg, FALSE, TRUE, TRUE)) {
			/*
			 * found an empty c_segment and freed it
			 * so go grab the next guy in the queue
			 */
			VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 7, 0, 0, 0);
			c_seg_major_compact_stats[c_seg_major_compact_stats_now].count_of_freed_segs++;
			continue;
		}

		switch_state = vm_compressor_major_compact_cseg(c_seg, &number_considered, &bail_wanted_cseg, &bytes_freed);
		if (bail_wanted_cseg) {
			wanted_cseg_found++;
			bail_wanted_cseg = false;
		}

		assert(c_seg->c_busy);
		assert(!c_seg->c_on_minorcompact_q);

		if (switch_state) {
			if (VM_CONFIG_SWAP_IS_ACTIVE) {
				int new_state = C_ON_SWAPOUT_Q;
#if (XNU_TARGET_OS_OSX && __arm64__)
				if (flush_all == false && compressor_swapout_conditions_met() == false) {
					new_state = C_ON_MAJORCOMPACT_Q;
				}
#endif /* (XNU_TARGET_OS_OSX && __arm64__) */

				if (new_state == C_ON_SWAPOUT_Q) {
					/*
					 * This mode of putting a generic c_seg on the swapout list is
					 * only supported when we have general swapping enabled
					 */
					clock_sec_t lnow;
					clock_nsec_t lnsec;
					clock_get_system_nanotime(&lnow, &lnsec);
					if (c_seg->c_agedin_ts && (lnow - c_seg->c_agedin_ts) < 30) {
						vmcs_stats.unripe_under_30s++;
					} else if (c_seg->c_agedin_ts && (lnow - c_seg->c_agedin_ts) < 60) {
						vmcs_stats.unripe_under_60s++;
					} else if (c_seg->c_agedin_ts && (lnow - c_seg->c_agedin_ts) < 300) {
						vmcs_stats.unripe_under_300s++;
					}
				}

				c_seg_switch_state(c_seg, new_state, FALSE);
			} else {
				if ((vm_swapout_ripe_segments == TRUE && c_overage_swapped_count < c_overage_swapped_limit)) {
					assert(VM_CONFIG_SWAP_IS_PRESENT);
					/*
					 * we are running compressor sweeps with swap-behind
					 * make sure the c_seg has aged enough before swapping it
					 * out...
					 */
					if ((now - c_seg->c_creation_ts) >= vm_ripe_target_age) {
						c_seg->c_overage_swap = TRUE;
						c_overage_swapped_count++;
						c_seg_switch_state(c_seg, C_ON_SWAPOUT_Q, FALSE);
					}
				}
			}
			if (c_seg->c_state == C_ON_AGE_Q) {
				/*
				 * this c_seg didn't get moved to the swapout queue
				 * so we need to move it out of the way...
				 * we just did a major compaction on it so put it
				 * on that queue
				 */
				c_seg_switch_state(c_seg, C_ON_MAJORCOMPACT_Q, FALSE);
			} else {
				c_seg_major_compact_stats[c_seg_major_compact_stats_now].wasted_space_in_swapouts += c_seg_bufsize - c_seg->c_bytes_used;
				c_seg_major_compact_stats[c_seg_major_compact_stats_now].count_of_swapouts++;
			}
		}

		C_SEG_WAKEUP_DONE(c_seg);

		lck_mtx_unlock_always(&c_seg->c_lock);

		/*
		 * On systems _with_ general swap, regardless of jetsam, we wake up the swapout thread here.
		 * On systems _without_ general swap, it's the responsibility of the memorystatus
		 * subsystem to wake up the swapper.
		 * TODO: When we have full jetsam support on a swap enabled system, we will need to revisit
		 * this policy.
		 */
		if (VM_CONFIG_SWAP_IS_ACTIVE && c_swapout_count) {
			/*
			 * We don't pause/yield here because we will either
			 * yield below or at the top of the loop with the
			 * assert_wait_timeout.
			 */
			if (!vm_swapout_thread_running) {
				thread_wakeup((event_t)&vm_swapout_thread);
			}
		}

		if (number_considered >= yield_after_considered_per_pass) {
			if (wanted_cseg_found) {
				/*
				 * We stopped major compactions on a c_seg
				 * that is wanted. We don't know the priority
				 * of the waiter unfortunately but we are at
				 * a very high priority and so, just in case
				 * the waiter is a critical system daemon or
				 * UI thread, let's give up the CPU in case
				 * the system is running a few CPU intensive
				 * tasks.
				 */
				lck_mtx_unlock_always(c_list_lock);

				mutex_pause(2); /* 100us yield */

				number_yields++;

				VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_NONE, 11, number_considered, number_yields, 0);

				lck_mtx_lock_spin_always(c_list_lock);
			}

			number_considered = 0;
			wanted_cseg_found = 0;
		}
	}
	clock_get_system_nanotime(&now, &nsec);

	end_ts = major_compact_ts = (mach_timespec_t){.tv_sec = (int)now, .tv_nsec = nsec};

	SUB_MACH_TIMESPEC(&end_ts, &start_ts);

	delta_usec = (end_ts.tv_sec * USEC_PER_SEC) + (end_ts.tv_nsec / NSEC_PER_USEC) - (number_yields * 100);

	delta_usec = MAX(1, delta_usec); /* we could have 0 usec run if conditions weren't right */

	c_seg_major_compact_stats[c_seg_major_compact_stats_now].bytes_freed_rate_us = (bytes_freed / delta_usec);

	if ((c_seg_major_compact_stats_now + 1) == C_SEG_MAJOR_COMPACT_STATS_MAX) {
		c_seg_major_compact_stats_now = 0;
	} else {
		c_seg_major_compact_stats_now++;
	}

	assert(c_seg_major_compact_stats_now < C_SEG_MAJOR_COMPACT_STATS_MAX);

	VM_DEBUG_CONSTANT_EVENT(vm_compressor_compact_and_swap, VM_COMPRESSOR_COMPACT_AND_SWAP, DBG_FUNC_END, c_age_count, c_minor_count, c_major_count, vm_page_free_count);
}


static c_segment_t
c_seg_allocate(c_segment_t *current_chead)
{
	c_segment_t     c_seg;
	int             min_needed;
	int             size_to_populate;
	c_segment_t     *donate_queue_head;

#if XNU_TARGET_OS_OSX
	if (vm_compressor_low_on_space()) {
		vm_compressor_take_paging_space_action();
	}
#endif /* XNU_TARGET_OS_OSX */

	if ((c_seg = *current_chead) == NULL) {
		uint32_t        c_segno;

		lck_mtx_lock_spin_always(c_list_lock);

		while (c_segments_busy == TRUE) {
			assert_wait((event_t) (&c_segments_busy), THREAD_UNINT);

			lck_mtx_unlock_always(c_list_lock);

			thread_block(THREAD_CONTINUE_NULL);

			lck_mtx_lock_spin_always(c_list_lock);
		}
		if (c_free_segno_head == (uint32_t)-1) {
			uint32_t        c_segments_available_new;
			uint32_t        compressed_pages;

#if CONFIG_FREEZE
			if (freezer_incore_cseg_acct) {
				compressed_pages = c_segment_pages_compressed_incore;
			} else {
				compressed_pages = c_segment_pages_compressed;
			}
#else
			compressed_pages = c_segment_pages_compressed;
#endif /* CONFIG_FREEZE */

			if (c_segments_available >= c_segments_limit || compressed_pages >= c_segment_pages_compressed_limit) {
				lck_mtx_unlock_always(c_list_lock);

				return NULL;
			}
			c_segments_busy = TRUE;
			lck_mtx_unlock_always(c_list_lock);

			kernel_memory_populate((vm_offset_t)c_segments_next_page,
			    PAGE_SIZE, KMA_NOFAIL | KMA_KOBJECT,
			    VM_KERN_MEMORY_COMPRESSOR);
			c_segments_next_page += PAGE_SIZE;

			c_segments_available_new = c_segments_available + C_SEGMENTS_PER_PAGE;

			if (c_segments_available_new > c_segments_limit) {
				c_segments_available_new = c_segments_limit;
			}

			for (c_segno = c_segments_available + 1; c_segno < c_segments_available_new; c_segno++) {
				c_segments[c_segno - 1].c_segno = c_segno;
			}

			lck_mtx_lock_spin_always(c_list_lock);

			c_segments[c_segno - 1].c_segno = c_free_segno_head;
			c_free_segno_head = c_segments_available;
			c_segments_available = c_segments_available_new;

			c_segments_busy = FALSE;
			thread_wakeup((event_t) (&c_segments_busy));
		}
		c_segno = c_free_segno_head;
		assert(c_segno >= 0 && c_segno < c_segments_limit);

		c_free_segno_head = (uint32_t)c_segments[c_segno].c_segno;

		/*
		 * do the rest of the bookkeeping now while we're still behind
		 * the list lock and grab our generation id now into a local
		 * so that we can install it once we have the c_seg allocated
		 */
		c_segment_count++;
		if (c_segment_count > c_segment_count_max) {
			c_segment_count_max = c_segment_count;
		}

		lck_mtx_unlock_always(c_list_lock);

		c_seg = zalloc_flags(compressor_segment_zone, Z_WAITOK | Z_ZERO);

		c_seg->c_store.c_buffer = (int32_t *)C_SEG_BUFFER_ADDRESS(c_segno);

		lck_mtx_init(&c_seg->c_lock, &vm_compressor_lck_grp, LCK_ATTR_NULL);

		c_seg->c_state = C_IS_EMPTY;
		c_seg->c_firstemptyslot = C_SLOT_MAX_INDEX;
		c_seg->c_mysegno = c_segno;

		lck_mtx_lock_spin_always(c_list_lock);
		c_empty_count++;
		c_seg_switch_state(c_seg, C_IS_FILLING, FALSE);
		c_segments[c_segno].c_seg = c_seg;
		assert(c_segments[c_segno].c_segno > c_segments_available);
		lck_mtx_unlock_always(c_list_lock);

		for (int i = 0; i < vm_pageout_state.vm_compressor_thread_count; i++) {
#if XNU_TARGET_OS_OSX
			donate_queue_head = (c_segment_t*) &(pgo_iothread_internal_state[i].current_early_swapout_chead);
#else /* XNU_TARGET_OS_OSX */
			if (memorystatus_swap_all_apps) {
				donate_queue_head = (c_segment_t*) &(pgo_iothread_internal_state[i].current_late_swapout_chead);
			} else {
				donate_queue_head = NULL;
			}
#endif /* XNU_TARGET_OS_OSX */

			if (current_chead == donate_queue_head) {
				c_seg->c_has_donated_pages = 1;
				break;
			}
		}

		*current_chead = c_seg;

#if DEVELOPMENT || DEBUG
		C_SEG_MAKE_WRITEABLE(c_seg);
#endif
	}
	c_seg_alloc_nextslot(c_seg);

	size_to_populate = c_seg_allocsize - C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset);

	if (size_to_populate) {
		min_needed = PAGE_SIZE + (c_seg_allocsize - c_seg_bufsize);

		if (C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset - c_seg->c_nextoffset) < (unsigned) min_needed) {
			if (size_to_populate > C_SEG_MAX_POPULATE_SIZE) {
				size_to_populate = C_SEG_MAX_POPULATE_SIZE;
			}

			OSAddAtomic64(size_to_populate / PAGE_SIZE, &vm_pageout_vminfo.vm_compressor_pages_grabbed);

			kernel_memory_populate(
				(vm_offset_t) &c_seg->c_store.c_buffer[c_seg->c_populated_offset],
				size_to_populate,
				KMA_NOFAIL | KMA_COMPRESSOR,
				VM_KERN_MEMORY_COMPRESSOR);
		} else {
			size_to_populate = 0;
		}
	}
	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	if (size_to_populate) {
		c_seg->c_populated_offset += C_SEG_BYTES_TO_OFFSET(size_to_populate);
	}

	return c_seg;
}

#if DEVELOPMENT || DEBUG
#if CONFIG_FREEZE
extern boolean_t memorystatus_freeze_to_memory;
#endif /* CONFIG_FREEZE */
#endif /* DEVELOPMENT || DEBUG */
uint64_t c_seg_total_donated_bytes = 0; /* For testing/debugging only for now. Remove and add new counters for vm_stat.*/

uint64_t c_seg_filled_no_contention = 0;
uint64_t c_seg_filled_contention = 0;
clock_sec_t c_seg_filled_contention_sec_max = 0;
clock_nsec_t c_seg_filled_contention_nsec_max = 0;

static void
c_current_seg_filled(c_segment_t c_seg, c_segment_t *current_chead)
{
	uint32_t        unused_bytes;
	uint32_t        offset_to_depopulate;
	int             new_state = C_ON_AGE_Q;
	clock_sec_t     sec;
	clock_nsec_t    nsec;
	bool            head_insert = false, wakeup_swapout_thread = false;

	unused_bytes = trunc_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset - c_seg->c_nextoffset));

	if (unused_bytes) {
		offset_to_depopulate = C_SEG_BYTES_TO_OFFSET(round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_nextoffset)));

		/*
		 *  release the extra physical page(s) at the end of the segment
		 */
		lck_mtx_unlock_always(&c_seg->c_lock);

		kernel_memory_depopulate(
			(vm_offset_t) &c_seg->c_store.c_buffer[offset_to_depopulate],
			unused_bytes,
			KMA_COMPRESSOR,
			VM_KERN_MEMORY_COMPRESSOR);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		c_seg->c_populated_offset = offset_to_depopulate;
	}
	assert(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset) <= c_seg_bufsize);

#if DEVELOPMENT || DEBUG
	{
		boolean_t       c_seg_was_busy = FALSE;

		if (!c_seg->c_busy) {
			C_SEG_BUSY(c_seg);
		} else {
			c_seg_was_busy = TRUE;
		}

		lck_mtx_unlock_always(&c_seg->c_lock);

		C_SEG_WRITE_PROTECT(c_seg);

		lck_mtx_lock_spin_always(&c_seg->c_lock);

		if (c_seg_was_busy == FALSE) {
			C_SEG_WAKEUP_DONE(c_seg);
		}
	}
#endif

#if CONFIG_FREEZE
	if (current_chead == (c_segment_t*) &(freezer_context_global.freezer_ctx_chead) &&
	    VM_CONFIG_SWAP_IS_PRESENT &&
	    VM_CONFIG_FREEZER_SWAP_IS_ACTIVE
#if DEVELOPMENT || DEBUG
	    && !memorystatus_freeze_to_memory
#endif /* DEVELOPMENT || DEBUG */
	    ) {
		new_state = C_ON_SWAPOUT_Q;
		wakeup_swapout_thread = true;
	}
#endif /* CONFIG_FREEZE */

	if (vm_darkwake_mode == TRUE) {
		new_state = C_ON_SWAPOUT_Q;
		head_insert = true;
		wakeup_swapout_thread = true;
	} else {
		c_segment_t *donate_queue_head;
		for (int i = 0; i < vm_pageout_state.vm_compressor_thread_count; i++) {
#if XNU_TARGET_OS_OSX
			donate_queue_head = (c_segment_t*) &(pgo_iothread_internal_state[i].current_early_swapout_chead);
#else /* XNU_TARGET_OS_OSX */
			donate_queue_head = (c_segment_t*) &(pgo_iothread_internal_state[i].current_late_swapout_chead);
#endif /* XNU_TARGET_OS_OSX */

			if (current_chead == donate_queue_head) {
				assert(c_seg->c_has_donated_pages);
				new_state = C_ON_SWAPOUT_Q;
				c_seg_total_donated_bytes += c_seg->c_bytes_used;
				break;
			}
		}
	}

	clock_get_system_nanotime(&sec, &nsec);
	c_seg->c_creation_ts = (uint32_t)sec;

	if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
		clock_sec_t     sec2;
		clock_nsec_t    nsec2;

		lck_mtx_lock_spin_always(c_list_lock);
		clock_get_system_nanotime(&sec2, &nsec2);
		TIME_SUB(sec2, sec, nsec2, nsec, NSEC_PER_SEC);
		// printf("FBDP %s: head %p waited for c_list_lock for %lu.%09u seconds\n", __FUNCTION__, current_chead, sec2, nsec2);
		if (sec2 > c_seg_filled_contention_sec_max) {
			c_seg_filled_contention_sec_max = sec2;
			c_seg_filled_contention_nsec_max = nsec2;
		} else if (sec2 == c_seg_filled_contention_sec_max &&
		    nsec2 > c_seg_filled_contention_nsec_max) {
			c_seg_filled_contention_nsec_max = nsec2;
		}
		c_seg_filled_contention++;
	} else {
		c_seg_filled_no_contention++;
	}

#if CONFIG_FREEZE
	if (current_chead == (c_segment_t*) &(freezer_context_global.freezer_ctx_chead)) {
		if (freezer_context_global.freezer_ctx_task->donates_own_pages) {
			assert(!c_seg->c_has_donated_pages);
			c_seg->c_has_donated_pages = 1;
			OSAddAtomic(c_seg->c_slots_used, &c_segment_pages_compressed_incore_late_swapout);
		}
		c_seg->c_has_freezer_pages = 1;
	}
#endif /* CONFIG_FREEZE */

	c_seg->c_generation_id = c_generation_id++;
	c_seg_switch_state(c_seg, new_state, head_insert);

#if CONFIG_FREEZE
	/*
	 * Donated segments count as frozen to swap if we go through the freezer.
	 * TODO: What we need is a new ledger and cseg state that can describe
	 * a frozen cseg from a donated task so we can accurately decrement it on
	 * swapins.
	 */
	if (current_chead == (c_segment_t*) &(freezer_context_global.freezer_ctx_chead) && (c_seg->c_state == C_ON_SWAPOUT_Q)) {
		/*
		 * darkwake and freezer can't co-exist together
		 * We'll need to fix this accounting as a start.
		 * And early donation c_segs are separate from frozen c_segs.
		 */
		assert(vm_darkwake_mode == FALSE);
		c_seg_update_task_owner(c_seg, freezer_context_global.freezer_ctx_task);
		freezer_context_global.freezer_ctx_swapped_bytes += c_seg->c_bytes_used;
	}
#endif /* CONFIG_FREEZE */

	if (c_seg->c_state == C_ON_AGE_Q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
#if CONFIG_FREEZE
		assert(c_seg->c_task_owner == NULL);
#endif /* CONFIG_FREEZE */
		c_seg_need_delayed_compaction(c_seg, TRUE);
	}

	lck_mtx_unlock_always(c_list_lock);

	if (wakeup_swapout_thread) {
		/*
		 * Darkwake and Freeze configs always
		 * wake up the swapout thread because
		 * the compactor thread that normally handles
		 * it may not be running as much in these
		 * configs.
		 */
		thread_wakeup((event_t)&vm_swapout_thread);
	}

	*current_chead = NULL;
}

/*
 * returns with c_seg locked
 */
void
c_seg_swapin_requeue(c_segment_t c_seg, boolean_t has_data, boolean_t minor_compact_ok, boolean_t age_on_swapin_q)
{
	clock_sec_t     sec;
	clock_nsec_t    nsec;

	clock_get_system_nanotime(&sec, &nsec);

	lck_mtx_lock_spin_always(c_list_lock);
	lck_mtx_lock_spin_always(&c_seg->c_lock);

	assert(c_seg->c_busy_swapping);
	assert(c_seg->c_busy);

	c_seg->c_busy_swapping = 0;

	if (c_seg->c_overage_swap == TRUE) {
		c_overage_swapped_count--;
		c_seg->c_overage_swap = FALSE;
	}
	if (has_data == TRUE) {
		if (age_on_swapin_q == TRUE || c_seg->c_has_donated_pages) {
#if CONFIG_FREEZE
			/*
			 * If a segment has both identities, frozen and donated bits set, the donated
			 * bit wins on the swapin path. This is because the segment is being swapped back
			 * in and so is in demand and should be given more time to spend in memory before
			 * being swapped back out under pressure.
			 */
			if (c_seg->c_has_donated_pages) {
				c_seg->c_has_freezer_pages = 0;
			}
#endif /* CONFIG_FREEZE */
			c_seg_switch_state(c_seg, C_ON_SWAPPEDIN_Q, FALSE);
		} else {
			c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
		}

		if (minor_compact_ok == TRUE && !c_seg->c_on_minorcompact_q && C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
			c_seg_need_delayed_compaction(c_seg, TRUE);
		}
	} else {
		c_seg->c_store.c_buffer = (int32_t*) NULL;
		c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);

		c_seg_switch_state(c_seg, C_ON_BAD_Q, FALSE);
	}
	c_seg->c_swappedin_ts = (uint32_t)sec;
	c_seg->c_swappedin = true;

	lck_mtx_unlock_always(c_list_lock);
}



/*
 * c_seg has to be locked and is returned locked if the c_seg isn't freed
 * PAGE_REPLACMENT_DISALLOWED has to be TRUE on entry and is returned TRUE
 * c_seg_swapin returns 1 if the c_seg was freed, 0 otherwise
 */

int
c_seg_swapin(c_segment_t c_seg, boolean_t force_minor_compaction, boolean_t age_on_swapin_q)
{
	vm_offset_t     addr = 0;
	uint32_t        io_size = 0;
	uint64_t        f_offset;
	thread_pri_floor_t token;

	assert(C_SEG_IS_ONDISK(c_seg));

#if !CHECKSUM_THE_SWAP
	c_seg_trim_tail(c_seg);
#endif
	io_size = round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset));
	f_offset = c_seg->c_store.c_swap_handle;

	C_SEG_BUSY(c_seg);
	c_seg->c_busy_swapping = 1;

	/*
	 * This thread is likely going to block for I/O.
	 * Make sure it is ready to run when the I/O completes because
	 * it needs to clear the busy bit on the c_seg so that other
	 * waiting threads can make progress too.
	 */
	token = thread_priority_floor_start();
	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	addr = (vm_offset_t)C_SEG_BUFFER_ADDRESS(c_seg->c_mysegno);
	c_seg->c_store.c_buffer = (int32_t*) addr;

	kernel_memory_populate(addr, io_size, KMA_NOFAIL | KMA_COMPRESSOR,
	    VM_KERN_MEMORY_COMPRESSOR);

	if (vm_swap_get(c_seg, f_offset, io_size) != KERN_SUCCESS) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		kernel_memory_depopulate(addr, io_size, KMA_COMPRESSOR,
		    VM_KERN_MEMORY_COMPRESSOR);

		c_seg_swapin_requeue(c_seg, FALSE, TRUE, age_on_swapin_q);
	} else {
#if ENCRYPTED_SWAP
		vm_swap_decrypt(c_seg);
#endif /* ENCRYPTED_SWAP */

#if CHECKSUM_THE_SWAP
		if (c_seg->cseg_swap_size != io_size) {
			panic("swapin size doesn't match swapout size");
		}

		if (c_seg->cseg_hash != vmc_hash((char*) c_seg->c_store.c_buffer, (int)io_size)) {
			panic("c_seg_swapin - Swap hash mismatch");
		}
#endif /* CHECKSUM_THE_SWAP */

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		c_seg_swapin_requeue(c_seg, TRUE, force_minor_compaction == TRUE ? FALSE : TRUE, age_on_swapin_q);

#if CONFIG_FREEZE
		/*
		 * c_seg_swapin_requeue() returns with the c_seg lock held.
		 */
		if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
			assert(c_seg->c_busy);

			lck_mtx_unlock_always(&c_seg->c_lock);
			lck_mtx_lock_spin_always(c_list_lock);
			lck_mtx_lock_spin_always(&c_seg->c_lock);
		}

		if (c_seg->c_task_owner) {
			c_seg_update_task_owner(c_seg, NULL);
		}

		lck_mtx_unlock_always(c_list_lock);

		OSAddAtomic(c_seg->c_slots_used, &c_segment_pages_compressed_incore);
		if (c_seg->c_has_donated_pages) {
			OSAddAtomic(c_seg->c_slots_used, &c_segment_pages_compressed_incore_late_swapout);
		}
#endif /* CONFIG_FREEZE */

		OSAddAtomic64(c_seg->c_bytes_used, &compressor_bytes_used);

		if (force_minor_compaction == TRUE) {
			if (c_seg_minor_compaction_and_unlock(c_seg, FALSE)) {
				/*
				 * c_seg was completely empty so it was freed,
				 * so be careful not to reference it again
				 *
				 * Drop the boost so that the thread priority
				 * is returned back to where it is supposed to be.
				 */
				thread_priority_floor_end(&token);
				return 1;
			}

			lck_mtx_lock_spin_always(&c_seg->c_lock);
		}
	}
	C_SEG_WAKEUP_DONE(c_seg);

	/*
	 * Drop the boost so that the thread priority
	 * is returned back to where it is supposed to be.
	 */
	thread_priority_floor_end(&token);

	return 0;
}


static void
c_segment_sv_hash_drop_ref(int hash_indx)
{
	struct c_sv_hash_entry o_sv_he, n_sv_he;

	while (1) {
		o_sv_he.he_record = c_segment_sv_hash_table[hash_indx].he_record;

		n_sv_he.he_ref = o_sv_he.he_ref - 1;
		n_sv_he.he_data = o_sv_he.he_data;

		if (OSCompareAndSwap64((UInt64)o_sv_he.he_record, (UInt64)n_sv_he.he_record, (UInt64 *) &c_segment_sv_hash_table[hash_indx].he_record) == TRUE) {
			if (n_sv_he.he_ref == 0) {
				OSAddAtomic(-1, &c_segment_svp_in_hash);
			}
			break;
		}
	}
}


static int
c_segment_sv_hash_insert(uint32_t data)
{
	int             hash_sindx;
	int             misses;
	struct c_sv_hash_entry o_sv_he, n_sv_he;
	boolean_t       got_ref = FALSE;

	if (data == 0) {
		OSAddAtomic(1, &c_segment_svp_zero_compressions);
	} else {
		OSAddAtomic(1, &c_segment_svp_nonzero_compressions);
	}

	hash_sindx = data & C_SV_HASH_MASK;

	for (misses = 0; misses < C_SV_HASH_MAX_MISS; misses++) {
		o_sv_he.he_record = c_segment_sv_hash_table[hash_sindx].he_record;

		while (o_sv_he.he_data == data || o_sv_he.he_ref == 0) {
			n_sv_he.he_ref = o_sv_he.he_ref + 1;
			n_sv_he.he_data = data;

			if (OSCompareAndSwap64((UInt64)o_sv_he.he_record, (UInt64)n_sv_he.he_record, (UInt64 *) &c_segment_sv_hash_table[hash_sindx].he_record) == TRUE) {
				if (n_sv_he.he_ref == 1) {
					OSAddAtomic(1, &c_segment_svp_in_hash);
				}
				got_ref = TRUE;
				break;
			}
			o_sv_he.he_record = c_segment_sv_hash_table[hash_sindx].he_record;
		}
		if (got_ref == TRUE) {
			break;
		}
		hash_sindx++;

		if (hash_sindx == C_SV_HASH_SIZE) {
			hash_sindx = 0;
		}
	}
	if (got_ref == FALSE) {
		return -1;
	}

	return hash_sindx;
}


#if RECORD_THE_COMPRESSED_DATA

static void
c_compressed_record_data(char *src, int c_size)
{
	if ((c_compressed_record_cptr + c_size + 4) >= c_compressed_record_ebuf) {
		panic("c_compressed_record_cptr >= c_compressed_record_ebuf");
	}

	*(int *)((void *)c_compressed_record_cptr) = c_size;

	c_compressed_record_cptr += 4;

	memcpy(c_compressed_record_cptr, src, c_size);
	c_compressed_record_cptr += c_size;
}
#endif


static int
c_compress_page(char *src, c_slot_mapping_t slot_ptr, c_segment_t *current_chead, char *scratch_buf)
{
	int             c_size = -1;
	int             c_rounded_size = 0;
	int             max_csize;
	c_slot_t        cs;
	c_segment_t     c_seg;
	bool            single_value = false;

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_START, *current_chead, 0, 0, 0, 0);
retry:
	if ((c_seg = c_seg_allocate(current_chead)) == NULL) {
		return 1;
	}
	/*
	 * returns with c_seg lock held
	 * and PAGE_REPLACEMENT_DISALLOWED(TRUE)...
	 * c_nextslot has been allocated and
	 * c_store.c_buffer populated
	 */
	assert(c_seg->c_state == C_IS_FILLING);

	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_seg->c_nextslot);

	C_SLOT_ASSERT_PACKABLE(slot_ptr);
	cs->c_packed_ptr = C_SLOT_PACK_PTR(slot_ptr);

	cs->c_offset = c_seg->c_nextoffset;

	max_csize = c_seg_bufsize - C_SEG_OFFSET_TO_BYTES((int32_t)cs->c_offset);

	if (max_csize > PAGE_SIZE) {
		max_csize = PAGE_SIZE;
	}

#if CHECKSUM_THE_DATA
	cs->c_hash_data = vmc_hash(src, PAGE_SIZE);
#endif
	boolean_t incomp_copy = FALSE;
	int max_csize_adj = (max_csize - 4);

	if (vm_compressor_algorithm() != VM_COMPRESSOR_DEFAULT_CODEC) {
#if defined(__arm64__)
		uint16_t ccodec = CINVALID;
		uint32_t inline_popcount;
		if (max_csize >= C_SEG_OFFSET_ALIGNMENT_BOUNDARY) {
			c_size = metacompressor((const uint8_t *) src,
			    (uint8_t *) &c_seg->c_store.c_buffer[cs->c_offset],
			    max_csize_adj, &ccodec,
			    scratch_buf, &incomp_copy, &inline_popcount);
			assert(inline_popcount == C_SLOT_NO_POPCOUNT);

#if C_SEG_OFFSET_ALIGNMENT_BOUNDARY > 4
			if (c_size > max_csize_adj) {
				c_size = -1;
			}
#endif
		} else {
			c_size = -1;
		}
		assert(ccodec == CCWK || ccodec == CCLZ4);
		cs->c_codec = ccodec;
#endif
	} else {
#if defined(__arm64__)
		cs->c_codec = CCWK;
		__unreachable_ok_push
		if (PAGE_SIZE == 4096) {
			c_size = WKdm_compress_4k((WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
			    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
		} else {
			c_size = WKdm_compress_16k((WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
			    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
		}
		__unreachable_ok_pop
#else
		c_size = WKdm_compress_new((const WK_word *)(uintptr_t)src, (WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
		    (WK_word *)(uintptr_t)scratch_buf, max_csize_adj);
#endif
	}
	assertf(((c_size <= max_csize_adj) && (c_size >= -1)),
	    "c_size invalid (%d, %d), cur compressions: %d", c_size, max_csize_adj, c_segment_pages_compressed);

	if (c_size == -1) {
		if (max_csize < PAGE_SIZE) {
			c_current_seg_filled(c_seg, current_chead);
			assert(*current_chead == NULL);

			lck_mtx_unlock_always(&c_seg->c_lock);
			/* TODO: it may be worth requiring codecs to distinguish
			 * between incompressible inputs and failures due to
			 * budget exhaustion.
			 */
			PAGE_REPLACEMENT_DISALLOWED(FALSE);
			goto retry;
		}
		c_size = PAGE_SIZE;

		if (incomp_copy == FALSE) {
			memcpy(&c_seg->c_store.c_buffer[cs->c_offset], src, c_size);
		}

		OSAddAtomic(1, &c_segment_noncompressible_pages);
	} else if (c_size == 0) {
		int             hash_index;

		/*
		 * special case - this is a page completely full of a single 32 bit value
		 */
		single_value = true;
		hash_index = c_segment_sv_hash_insert(*(uint32_t *)(uintptr_t)src);

		if (hash_index != -1) {
			slot_ptr->s_cindx = hash_index;
			slot_ptr->s_cseg = C_SV_CSEG_ID;
#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
			slot_ptr->s_uncompressed = 0;
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

			OSAddAtomic(1, &c_segment_svp_hash_succeeded);
#if RECORD_THE_COMPRESSED_DATA
			c_compressed_record_data(src, 4);
#endif
			goto sv_compression;
		}
		c_size = 4;

		memcpy(&c_seg->c_store.c_buffer[cs->c_offset], src, c_size);

		OSAddAtomic(1, &c_segment_svp_hash_failed);
	}

#if RECORD_THE_COMPRESSED_DATA
	c_compressed_record_data((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
#if CHECKSUM_THE_COMPRESSED_DATA
	cs->c_hash_compressed_data = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
#if POPCOUNT_THE_COMPRESSED_DATA
	cs->c_pop_cdata = vmc_pop((uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset], c_size);
#endif
	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	PACK_C_SIZE(cs, c_size);
	c_seg->c_bytes_used += c_rounded_size;
	c_seg->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);
	c_seg->c_slots_used++;

#if CONFIG_FREEZE
	/* TODO: should c_segment_pages_compressed be up here too? See 88598046 for details */
	OSAddAtomic(1, &c_segment_pages_compressed_incore);
	if (c_seg->c_has_donated_pages) {
		OSAddAtomic(1, &c_segment_pages_compressed_incore_late_swapout);
	}
#endif /* CONFIG_FREEZE */

	slot_ptr->s_cindx = c_seg->c_nextslot++;
	/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
	slot_ptr->s_cseg = c_seg->c_mysegno + 1;

#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
	slot_ptr->s_uncompressed = 0;
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

sv_compression:
	if (c_seg->c_nextoffset >= c_seg_off_limit || c_seg->c_nextslot >= C_SLOT_MAX_INDEX) {
		c_current_seg_filled(c_seg, current_chead);
		assert(*current_chead == NULL);
	}

	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

#if RECORD_THE_COMPRESSED_DATA
	if ((c_compressed_record_cptr - c_compressed_record_sbuf) >= c_seg_allocsize) {
		c_compressed_record_write(c_compressed_record_sbuf, (int)(c_compressed_record_cptr - c_compressed_record_sbuf));
		c_compressed_record_cptr = c_compressed_record_sbuf;
	}
#endif
	if (c_size) {
		OSAddAtomic64(c_size, &c_segment_compressed_bytes);
		OSAddAtomic64(c_rounded_size, &compressor_bytes_used);
	}
	OSAddAtomic64(PAGE_SIZE, &c_segment_input_bytes);

	OSAddAtomic(1, &c_segment_pages_compressed);
#if DEVELOPMENT || DEBUG
	if (!compressor_running_perf_test) {
		/*
		 * The perf_compressor benchmark should not be able to trigger
		 * compressor thrashing jetsams.
		 */
		OSAddAtomic(1, &sample_period_compression_count);
	}
#else /* DEVELOPMENT || DEBUG */
	OSAddAtomic(1, &sample_period_compression_count);
#endif /* DEVELOPMENT || DEBUG */

	KERNEL_DEBUG(0xe0400000 | DBG_FUNC_END, *current_chead, c_size, c_segment_input_bytes, c_segment_compressed_bytes, 0);

	return 0;
}

static inline void
sv_decompress(int32_t *ddst, int32_t pattern)
{
//	assert(__builtin_constant_p(PAGE_SIZE) != 0);
#if defined(__x86_64__)
	memset_word(ddst, pattern, PAGE_SIZE / sizeof(int32_t));
#elif defined(__arm64__)
	assert((PAGE_SIZE % 128) == 0);
	if (pattern == 0) {
		fill32_dczva((addr64_t)ddst, PAGE_SIZE);
	} else {
		fill32_nt((addr64_t)ddst, PAGE_SIZE, pattern);
	}
#else
	size_t          i;

	/* Unroll the pattern fill loop 4x to encourage the
	 * compiler to emit NEON stores, cf.
	 * <rdar://problem/25839866> Loop autovectorization
	 * anomalies.
	 */
	/* * We use separate loops for each PAGE_SIZE
	 * to allow the autovectorizer to engage, as PAGE_SIZE
	 * may not be a constant.
	 */

	__unreachable_ok_push
	if (PAGE_SIZE == 4096) {
		for (i = 0; i < (4096U / sizeof(int32_t)); i += 4) {
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
		}
	} else {
		assert(PAGE_SIZE == 16384);
		for (i = 0; i < (int)(16384U / sizeof(int32_t)); i += 4) {
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
			*ddst++ = pattern;
		}
	}
	__unreachable_ok_pop
#endif
}

static int
c_decompress_page(char *dst, volatile c_slot_mapping_t slot_ptr, vm_compressor_options_t flags, int *zeroslot)
{
	c_slot_t        cs;
	c_segment_t     c_seg;
	uint32_t        c_segno;
	uint16_t        c_indx;
	int             c_rounded_size;
	uint32_t        c_size;
	int             retval = 0;
	boolean_t       need_unlock = TRUE;
	boolean_t       consider_defragmenting = FALSE;
	boolean_t       kdp_mode = FALSE;

	if (__improbable(flags & C_KDP)) {
		if (not_in_kdp) {
			panic("C_KDP passed to decompress page from outside of debugger context");
		}

		assert((flags & C_KEEP) == C_KEEP);
		assert((flags & C_DONT_BLOCK) == C_DONT_BLOCK);

		if ((flags & (C_DONT_BLOCK | C_KEEP)) != (C_DONT_BLOCK | C_KEEP)) {
			return -2;
		}

		kdp_mode = TRUE;
		*zeroslot = 0;
	}

ReTry:
	if (__probable(!kdp_mode)) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);
	} else {
		if (kdp_lck_rw_lock_is_acquired_exclusive(&c_master_lock)) {
			return -2;
		}
	}

#if HIBERNATION
	/*
	 * if hibernation is enabled, it indicates (via a call
	 * to 'vm_decompressor_lock' that no further
	 * decompressions are allowed once it reaches
	 * the point of flushing all of the currently dirty
	 * anonymous memory through the compressor and out
	 * to disk... in this state we allow freeing of compressed
	 * pages and must honor the C_DONT_BLOCK case
	 */
	if (__improbable(dst && decompressions_blocked == TRUE)) {
		if (flags & C_DONT_BLOCK) {
			if (__probable(!kdp_mode)) {
				PAGE_REPLACEMENT_DISALLOWED(FALSE);
			}

			*zeroslot = 0;
			return -2;
		}
		/*
		 * it's safe to atomically assert and block behind the
		 * lock held in shared mode because "decompressions_blocked" is
		 * only set and cleared and the thread_wakeup done when the lock
		 * is held exclusively
		 */
		assert_wait((event_t)&decompressions_blocked, THREAD_UNINT);

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		thread_block(THREAD_CONTINUE_NULL);

		goto ReTry;
	}
#endif
	/* s_cseg is actually "segno+1" */
	c_segno = slot_ptr->s_cseg - 1;

	if (__improbable(c_segno >= c_segments_available)) {
		panic("c_decompress_page: c_segno %d >= c_segments_available %d, slot_ptr(%p), slot_data(%x)",
		    c_segno, c_segments_available, slot_ptr, *(int *)((void *)slot_ptr));
	}

	if (__improbable(c_segments[c_segno].c_segno < c_segments_available)) {
		panic("c_decompress_page: c_segno %d is free, slot_ptr(%p), slot_data(%x)",
		    c_segno, slot_ptr, *(int *)((void *)slot_ptr));
	}

	c_seg = c_segments[c_segno].c_seg;

	if (__probable(!kdp_mode)) {
		lck_mtx_lock_spin_always(&c_seg->c_lock);
	} else {
		if (kdp_lck_mtx_lock_spin_is_acquired(&c_seg->c_lock)) {
			return -2;
		}
	}

	assert(c_seg->c_state != C_IS_EMPTY && c_seg->c_state != C_IS_FREE);

	if (dst == NULL && c_seg->c_busy_swapping) {
		assert(c_seg->c_busy);

		goto bypass_busy_check;
	}
	if (flags & C_DONT_BLOCK) {
		if (c_seg->c_busy || (C_SEG_IS_ONDISK(c_seg) && dst)) {
			*zeroslot = 0;

			retval = -2;
			goto done;
		}
	}
	if (c_seg->c_busy) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		c_seg_wait_on_busy(c_seg);

		goto ReTry;
	}
bypass_busy_check:

	c_indx = slot_ptr->s_cindx;

	if (__improbable(c_indx >= c_seg->c_nextslot)) {
		panic("c_decompress_page: c_indx %d >= c_nextslot %d, c_seg(%p), slot_ptr(%p), slot_data(%x)",
		    c_indx, c_seg->c_nextslot, c_seg, slot_ptr, *(int *)((void *)slot_ptr));
	}

	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);

	c_size = UNPACK_C_SIZE(cs);

	if (__improbable(c_size == 0)) {
		panic("c_decompress_page: c_size == 0, c_seg(%p), slot_ptr(%p), slot_data(%x)",
		    c_seg, slot_ptr, *(int *)((void *)slot_ptr));
	}

	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	if (dst) {
		uint32_t        age_of_cseg;
		clock_sec_t     cur_ts_sec;
		clock_nsec_t    cur_ts_nsec;

		if (C_SEG_IS_ONDISK(c_seg)) {
#if CONFIG_FREEZE
			if (freezer_incore_cseg_acct) {
				if ((c_seg->c_slots_used + c_segment_pages_compressed_incore) >= c_segment_pages_compressed_nearing_limit) {
					PAGE_REPLACEMENT_DISALLOWED(FALSE);
					lck_mtx_unlock_always(&c_seg->c_lock);

					memorystatus_kill_on_VM_compressor_space_shortage(FALSE /* async */);

					goto ReTry;
				}

				uint32_t incore_seg_count = c_segment_count - c_swappedout_count - c_swappedout_sparse_count;
				if ((incore_seg_count + 1) >= c_segments_nearing_limit) {
					PAGE_REPLACEMENT_DISALLOWED(FALSE);
					lck_mtx_unlock_always(&c_seg->c_lock);

					memorystatus_kill_on_VM_compressor_space_shortage(FALSE /* async */);

					goto ReTry;
				}
			}
#endif /* CONFIG_FREEZE */
			assert(kdp_mode == FALSE);
			retval = c_seg_swapin(c_seg, FALSE, TRUE);
			assert(retval == 0);

			retval = 1;
		}
		if (c_seg->c_state == C_ON_BAD_Q) {
			assert(c_seg->c_store.c_buffer == NULL);
			*zeroslot = 0;

			retval = -1;
			goto done;
		}

#if POPCOUNT_THE_COMPRESSED_DATA
		unsigned csvpop;
		uintptr_t csvaddr = (uintptr_t) &c_seg->c_store.c_buffer[cs->c_offset];
		if (cs->c_pop_cdata != (csvpop = vmc_pop(csvaddr, c_size))) {
			panic("Compressed data popcount doesn't match original, bit distance: %d %p (phys: %p) %p %p 0x%x 0x%x 0x%x 0x%x", (csvpop - cs->c_pop_cdata), (void *)csvaddr, (void *) kvtophys(csvaddr), c_seg, cs, cs->c_offset, c_size, csvpop, cs->c_pop_cdata);
		}
#endif

#if CHECKSUM_THE_COMPRESSED_DATA
		unsigned csvhash;
		if (cs->c_hash_compressed_data != (csvhash = vmc_hash((char *)&c_seg->c_store.c_buffer[cs->c_offset], c_size))) {
			panic("Compressed data doesn't match original %p %p %u %u %u", c_seg, cs, c_size, cs->c_hash_compressed_data, csvhash);
		}
#endif
		if (c_rounded_size == PAGE_SIZE) {
			/*
			 * page wasn't compressible... just copy it out
			 */
			memcpy(dst, &c_seg->c_store.c_buffer[cs->c_offset], PAGE_SIZE);
		} else if (c_size == 4) {
			int32_t         data;
			int32_t         *dptr;

			/*
			 * page was populated with a single value
			 * that didn't fit into our fast hash
			 * so we packed it in as a single non-compressed value
			 * that we need to populate the page with
			 */
			dptr = (int32_t *)(uintptr_t)dst;
			data = *(int32_t *)(&c_seg->c_store.c_buffer[cs->c_offset]);
			sv_decompress(dptr, data);
		} else {
			uint32_t        my_cpu_no;
			char            *scratch_buf;

			if (__probable(!kdp_mode)) {
				/*
				 * we're behind the c_seg lock held in spin mode
				 * which means pre-emption is disabled... therefore
				 * the following sequence is atomic and safe
				 */
				my_cpu_no = cpu_number();

				assert(my_cpu_no < compressor_cpus);

				scratch_buf = &compressor_scratch_bufs[my_cpu_no * vm_compressor_get_decode_scratch_size()];
			} else {
				scratch_buf = kdp_compressor_scratch_buf;
			}

			if (vm_compressor_algorithm() != VM_COMPRESSOR_DEFAULT_CODEC) {
#if defined(__arm64__)
				uint16_t c_codec = cs->c_codec;
				uint32_t inline_popcount;
				if (!metadecompressor((const uint8_t *) &c_seg->c_store.c_buffer[cs->c_offset],
				    (uint8_t *)dst, c_size, c_codec, (void *)scratch_buf, &inline_popcount)) {
					retval = -1;
				} else {
					assert(inline_popcount == C_SLOT_NO_POPCOUNT);
				}
#endif
			} else {
#if defined(__arm64__)
				__unreachable_ok_push
				if (PAGE_SIZE == 4096) {
					WKdm_decompress_4k((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
					    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
				} else {
					WKdm_decompress_16k((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
					    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
				}
				__unreachable_ok_pop
#else
				WKdm_decompress_new((WK_word *)(uintptr_t)&c_seg->c_store.c_buffer[cs->c_offset],
				    (WK_word *)(uintptr_t)dst, (WK_word *)(uintptr_t)scratch_buf, c_size);
#endif
			}
		}

#if CHECKSUM_THE_DATA
		if (cs->c_hash_data != vmc_hash(dst, PAGE_SIZE)) {
#if defined(__arm64__)
			int32_t *dinput = &c_seg->c_store.c_buffer[cs->c_offset];
			panic("decompressed data doesn't match original cs: %p, hash: 0x%x, offset: %d, c_size: %d, c_rounded_size: %d, codec: %d, header: 0x%x 0x%x 0x%x", cs, cs->c_hash_data, cs->c_offset, c_size, c_rounded_size, cs->c_codec, *dinput, *(dinput + 1), *(dinput + 2));
#else
			panic("decompressed data doesn't match original cs: %p, hash: %d, offset: 0x%x, c_size: %d", cs, cs->c_hash_data, cs->c_offset, c_size);
#endif
		}
#endif
		if (c_seg->c_swappedin_ts == 0 && !kdp_mode) {
			clock_get_system_nanotime(&cur_ts_sec, &cur_ts_nsec);

			age_of_cseg = (uint32_t)cur_ts_sec - c_seg->c_creation_ts;
			if (age_of_cseg < DECOMPRESSION_SAMPLE_MAX_AGE) {
				OSAddAtomic(1, &age_of_decompressions_during_sample_period[age_of_cseg]);
			} else {
				OSAddAtomic(1, &overage_decompressions_during_sample_period);
			}

			OSAddAtomic(1, &sample_period_decompression_count);
		}
	}
#if CONFIG_FREEZE
	else {
		/*
		 * We are freeing an uncompressed page from this c_seg and so balance the ledgers.
		 */
		if (C_SEG_IS_ONDISK(c_seg)) {
			/*
			 * The compression sweep feature will push out anonymous pages to disk
			 * without going through the freezer path and so those c_segs, while
			 * swapped out, won't have an owner.
			 */
			if (c_seg->c_task_owner) {
				task_update_frozen_to_swap_acct(c_seg->c_task_owner, PAGE_SIZE_64, DEBIT_FROM_SWAP);
			}

			/*
			 * We are freeing a page in swap without swapping it in. We bump the in-core
			 * count here to simulate a swapin of a page so that we can accurately
			 * decrement it below.
			 */
			OSAddAtomic(1, &c_segment_pages_compressed_incore);
			if (c_seg->c_has_donated_pages) {
				OSAddAtomic(1, &c_segment_pages_compressed_incore_late_swapout);
			}
		} else if (c_seg->c_state == C_ON_BAD_Q) {
			assert(c_seg->c_store.c_buffer == NULL);
			*zeroslot = 0;

			retval = -1;
			goto done;
		}
	}
#endif /* CONFIG_FREEZE */

	if (flags & C_KEEP) {
		*zeroslot = 0;
		goto done;
	}
	assert(kdp_mode == FALSE);

	c_seg->c_bytes_unused += c_rounded_size;
	c_seg->c_bytes_used -= c_rounded_size;

	assert(c_seg->c_slots_used);
	c_seg->c_slots_used--;
	if (dst && c_seg->c_swappedin) {
		task_t task = current_task();
		if (task) {
			ledger_credit(task->ledger, task_ledgers.swapins, PAGE_SIZE);
		}
	}

	PACK_C_SIZE(cs, 0);

	if (c_indx < c_seg->c_firstemptyslot) {
		c_seg->c_firstemptyslot = c_indx;
	}

	OSAddAtomic(-1, &c_segment_pages_compressed);
#if CONFIG_FREEZE
	OSAddAtomic(-1, &c_segment_pages_compressed_incore);
	assertf(c_segment_pages_compressed_incore >= 0, "-ve incore count %p 0x%x", c_seg, c_segment_pages_compressed_incore);
	if (c_seg->c_has_donated_pages) {
		OSAddAtomic(-1, &c_segment_pages_compressed_incore_late_swapout);
		assertf(c_segment_pages_compressed_incore_late_swapout >= 0, "-ve lateswapout count %p 0x%x", c_seg, c_segment_pages_compressed_incore_late_swapout);
	}
#endif /* CONFIG_FREEZE */

	if (c_seg->c_state != C_ON_BAD_Q && !(C_SEG_IS_ONDISK(c_seg))) {
		/*
		 * C_SEG_IS_ONDISK == TRUE can occur when we're doing a
		 * free of a compressed page (i.e. dst == NULL)
		 */
		OSAddAtomic64(-c_rounded_size, &compressor_bytes_used);
	}
	if (c_seg->c_busy_swapping) {
		/*
		 * bypass case for c_busy_swapping...
		 * let the swapin/swapout paths deal with putting
		 * the c_seg on the minor compaction queue if needed
		 */
		assert(c_seg->c_busy);
		goto done;
	}
	assert(!c_seg->c_busy);

	if (c_seg->c_state != C_IS_FILLING) {
		if (c_seg->c_bytes_used == 0) {
			if (!(C_SEG_IS_ONDISK(c_seg))) {
				int     pages_populated;

				pages_populated = (round_page_32(C_SEG_OFFSET_TO_BYTES(c_seg->c_populated_offset))) / PAGE_SIZE;
				c_seg->c_populated_offset = C_SEG_BYTES_TO_OFFSET(0);

				if (pages_populated) {
					assert(c_seg->c_state != C_ON_BAD_Q);
					assert(c_seg->c_store.c_buffer != NULL);

					C_SEG_BUSY(c_seg);
					lck_mtx_unlock_always(&c_seg->c_lock);

					kernel_memory_depopulate(
						(vm_offset_t) c_seg->c_store.c_buffer,
						ptoa(pages_populated),
						KMA_COMPRESSOR, VM_KERN_MEMORY_COMPRESSOR);

					lck_mtx_lock_spin_always(&c_seg->c_lock);
					C_SEG_WAKEUP_DONE(c_seg);
				}
				if (!c_seg->c_on_minorcompact_q && c_seg->c_state != C_ON_SWAPIO_Q) {
					if (c_seg->c_state == C_ON_SWAPOUT_Q) {
						bool clear_busy = false;
						if (!lck_mtx_try_lock_spin_always(c_list_lock)) {
							C_SEG_BUSY(c_seg);

							lck_mtx_unlock_always(&c_seg->c_lock);
							lck_mtx_lock_spin_always(c_list_lock);
							lck_mtx_lock_spin_always(&c_seg->c_lock);
							clear_busy = true;
						}
						c_seg_switch_state(c_seg, C_ON_AGE_Q, FALSE);
						if (clear_busy) {
							C_SEG_WAKEUP_DONE(c_seg);
							clear_busy = false;
						}
						lck_mtx_unlock_always(c_list_lock);
					}
					c_seg_need_delayed_compaction(c_seg, FALSE);
				}
			} else {
				if (c_seg->c_state != C_ON_SWAPPEDOUTSPARSE_Q) {
					c_seg_move_to_sparse_list(c_seg);
					consider_defragmenting = TRUE;
				}
			}
		} else if (c_seg->c_on_minorcompact_q) {
			assert(c_seg->c_state != C_ON_BAD_Q);
			assert(!C_SEG_IS_ON_DISK_OR_SOQ(c_seg));

			if (C_SEG_SHOULD_MINORCOMPACT_NOW(c_seg)) {
				c_seg_try_minor_compaction_and_unlock(c_seg);
				need_unlock = FALSE;
			}
		} else if (!(C_SEG_IS_ONDISK(c_seg))) {
			if (c_seg->c_state != C_ON_BAD_Q && c_seg->c_state != C_ON_SWAPOUT_Q && c_seg->c_state != C_ON_SWAPIO_Q &&
			    C_SEG_UNUSED_BYTES(c_seg) >= PAGE_SIZE) {
				c_seg_need_delayed_compaction(c_seg, FALSE);
			}
		} else if (c_seg->c_state != C_ON_SWAPPEDOUTSPARSE_Q && C_SEG_ONDISK_IS_SPARSE(c_seg)) {
			c_seg_move_to_sparse_list(c_seg);
			consider_defragmenting = TRUE;
		}
	}
done:
	if (__improbable(kdp_mode)) {
		return retval;
	}

	if (need_unlock == TRUE) {
		lck_mtx_unlock_always(&c_seg->c_lock);
	}

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	if (consider_defragmenting == TRUE) {
		vm_swap_consider_defragmenting(VM_SWAP_FLAGS_NONE);
	}

#if !XNU_TARGET_OS_OSX
	if ((c_minor_count && COMPRESSOR_NEEDS_TO_MINOR_COMPACT()) || vm_compressor_needs_to_major_compact()) {
		vm_wake_compactor_swapper();
	}
#endif /* !XNU_TARGET_OS_OSX */

	return retval;
}


inline bool
vm_compressor_is_slot_compressed(int *slot)
{
#if !CONFIG_TRACK_UNMODIFIED_ANON_PAGES
#pragma unused(slot)
	return true;
#else /* !CONFIG_TRACK_UNMODIFIED_ANON_PAGES*/
	c_slot_mapping_t slot_ptr = (c_slot_mapping_t)slot;
	return !slot_ptr->s_uncompressed;
#endif /* !CONFIG_TRACK_UNMODIFIED_ANON_PAGES*/
}

int
vm_compressor_get(ppnum_t pn, int *slot, vm_compressor_options_t flags)
{
	c_slot_mapping_t  slot_ptr;
	char    *dst;
	int     zeroslot = 1;
	int     retval;

#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
	if (flags & C_PAGE_UNMODIFIED) {
		retval = vm_uncompressed_get(pn, slot, flags | C_KEEP);
		if (retval == 0) {
			os_atomic_inc(&compressor_ro_uncompressed_get, relaxed);
		}

		return retval;
	}
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

	dst = pmap_map_compressor_page(pn);
	slot_ptr = (c_slot_mapping_t)slot;

	assert(dst != NULL);

	if (slot_ptr->s_cseg == C_SV_CSEG_ID) {
		int32_t         data;
		int32_t         *dptr;

		/*
		 * page was populated with a single value
		 * that found a home in our hash table
		 * grab that value from the hash and populate the page
		 * that we need to populate the page with
		 */
		dptr = (int32_t *)(uintptr_t)dst;
		data = c_segment_sv_hash_table[slot_ptr->s_cindx].he_data;
		sv_decompress(dptr, data);
		if (!(flags & C_KEEP)) {
			c_segment_sv_hash_drop_ref(slot_ptr->s_cindx);

			OSAddAtomic(-1, &c_segment_pages_compressed);
			*slot = 0;
		}
		if (data) {
			OSAddAtomic(1, &c_segment_svp_nonzero_decompressions);
		} else {
			OSAddAtomic(1, &c_segment_svp_zero_decompressions);
		}

		pmap_unmap_compressor_page(pn, dst);
		return 0;
	}

	retval = c_decompress_page(dst, slot_ptr, flags, &zeroslot);

	/*
	 * zeroslot will be set to 0 by c_decompress_page if (flags & C_KEEP)
	 * or (flags & C_DONT_BLOCK) and we found 'c_busy' or 'C_SEG_IS_ONDISK' to be TRUE
	 */
	if (zeroslot) {
		*slot = 0;
	}

	pmap_unmap_compressor_page(pn, dst);

	/*
	 * returns 0 if we successfully decompressed a page from a segment already in memory
	 * returns 1 if we had to first swap in the segment, before successfully decompressing the page
	 * returns -1 if we encountered an error swapping in the segment - decompression failed
	 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' or 'C_SEG_IS_ONDISK' to be true
	 */
	return retval;
}

int
vm_compressor_free(int *slot, vm_compressor_options_t flags)
{
	bool slot_is_compressed = vm_compressor_is_slot_compressed(slot);

	if (slot_is_compressed) {
		c_slot_mapping_t  slot_ptr;
		int     zeroslot = 1;
		int     retval = 0;

		assert(flags == 0 || flags == C_DONT_BLOCK);

		slot_ptr = (c_slot_mapping_t)slot;

		if (slot_ptr->s_cseg == C_SV_CSEG_ID) {
			c_segment_sv_hash_drop_ref(slot_ptr->s_cindx);
			OSAddAtomic(-1, &c_segment_pages_compressed);

			*slot = 0;
			return 0;
		}
		retval = c_decompress_page(NULL, slot_ptr, flags, &zeroslot);
		/*
		 * returns 0 if we successfully freed the specified compressed page
		 * returns -1 if we encountered an error swapping in the segment - decompression failed
		 * returns -2 if (flags & C_DONT_BLOCK) and we found 'c_busy' set
		 */

		if (retval == 0) {
			*slot = 0;
		}

		return retval;
	}
#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
	else {
		if ((flags & C_PAGE_UNMODIFIED) == 0) {
			/* moving from uncompressed state to compressed. Free it.*/
			vm_uncompressed_free(slot, 0);
			assert(*slot == 0);
		}
	}
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */
	return KERN_SUCCESS;
}

int
vm_compressor_put(ppnum_t pn, int *slot, void  **current_chead, char *scratch_buf, bool unmodified)
{
	char    *src;
	int     retval = 0;

#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES
	if (unmodified) {
		if (*slot) {
			os_atomic_inc(&compressor_ro_uncompressed_skip_returned, relaxed);
			return retval;
		} else {
			retval = vm_uncompressed_put(pn, slot);
			if (retval == KERN_SUCCESS) {
				os_atomic_inc(&compressor_ro_uncompressed_put, relaxed);
				return retval;
			}
		}
	}
#else /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */
#pragma unused(unmodified)
#endif /* CONFIG_TRACK_UNMODIFIED_ANON_PAGES */

	src = pmap_map_compressor_page(pn);
	assert(src != NULL);

	retval = c_compress_page(src, (c_slot_mapping_t)slot, (c_segment_t *)current_chead, scratch_buf);
	pmap_unmap_compressor_page(pn, src);

	return retval;
}

void
vm_compressor_transfer(
	int     *dst_slot_p,
	int     *src_slot_p)
{
	c_slot_mapping_t        dst_slot, src_slot;
	c_segment_t             c_seg;
	uint16_t                c_indx;
	c_slot_t                cs;

	src_slot = (c_slot_mapping_t) src_slot_p;

	if (src_slot->s_cseg == C_SV_CSEG_ID || !vm_compressor_is_slot_compressed(src_slot_p)) {
		*dst_slot_p = *src_slot_p;
		*src_slot_p = 0;
		return;
	}
	dst_slot = (c_slot_mapping_t) dst_slot_p;
Retry:
	PAGE_REPLACEMENT_DISALLOWED(TRUE);
	/* get segment for src_slot */
	c_seg = c_segments[src_slot->s_cseg - 1].c_seg;
	/* lock segment */
	lck_mtx_lock_spin_always(&c_seg->c_lock);
	/* wait if it's busy */
	if (c_seg->c_busy && !c_seg->c_busy_swapping) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		c_seg_wait_on_busy(c_seg);
		goto Retry;
	}
	/* find the c_slot */
	c_indx = src_slot->s_cindx;
	cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
	/* point the c_slot back to dst_slot instead of src_slot */
	C_SLOT_ASSERT_PACKABLE(dst_slot);
	cs->c_packed_ptr = C_SLOT_PACK_PTR(dst_slot);
	/* transfer */
	*dst_slot_p = *src_slot_p;
	*src_slot_p = 0;
	lck_mtx_unlock_always(&c_seg->c_lock);
	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}

#if defined(__arm64__)
extern clock_sec_t             vm_swapfile_last_failed_to_create_ts;
__attribute__((noreturn))
void
vm_panic_hibernate_write_image_failed(int err)
{
	panic("hibernate_write_image encountered error 0x%x - %u, %u, %d, %d, %d, %d, %d, %d, %d, %d, %llu, %d, %d, %d\n",
	    err,
	    VM_PAGE_COMPRESSOR_COUNT, vm_page_wire_count,
	    c_age_count, c_major_count, c_minor_count, (c_early_swapout_count + c_regular_swapout_count + c_late_swapout_count), c_swappedout_sparse_count,
	    vm_num_swap_files, vm_num_pinned_swap_files, vm_swappin_enabled, vm_swap_put_failures,
	    (vm_swapfile_last_failed_to_create_ts ? 1:0), hibernate_no_swapspace, hibernate_flush_timed_out);
}
#endif /*(__arm64__)*/

#if CONFIG_FREEZE

int     freezer_finished_filling = 0;

void
vm_compressor_finished_filling(
	void    **current_chead)
{
	c_segment_t     c_seg;

	if ((c_seg = *(c_segment_t *)current_chead) == NULL) {
		return;
	}

	assert(c_seg->c_state == C_IS_FILLING);

	lck_mtx_lock_spin_always(&c_seg->c_lock);

	c_current_seg_filled(c_seg, (c_segment_t *)current_chead);

	lck_mtx_unlock_always(&c_seg->c_lock);

	freezer_finished_filling++;
}


/*
 * This routine is used to transfer the compressed chunks from
 * the c_seg/cindx pointed to by slot_p into a new c_seg headed
 * by the current_chead and a new cindx within that c_seg.
 *
 * Currently, this routine is only used by the "freezer backed by
 * compressor with swap" mode to create a series of c_segs that
 * only contain compressed data belonging to one task. So, we
 * move a task's previously compressed data into a set of new
 * c_segs which will also hold the task's yet to be compressed data.
 */

kern_return_t
vm_compressor_relocate(
	void            **current_chead,
	int             *slot_p)
{
	c_slot_mapping_t        slot_ptr;
	c_slot_mapping_t        src_slot;
	uint32_t                c_rounded_size;
	uint32_t                c_size;
	uint16_t                dst_slot;
	c_slot_t                c_dst;
	c_slot_t                c_src;
	uint16_t                c_indx;
	c_segment_t             c_seg_dst = NULL;
	c_segment_t             c_seg_src = NULL;
	kern_return_t           kr = KERN_SUCCESS;


	src_slot = (c_slot_mapping_t) slot_p;

	if (src_slot->s_cseg == C_SV_CSEG_ID) {
		/*
		 * no need to relocate... this is a page full of a single
		 * value which is hashed to a single entry not contained
		 * in a c_segment_t
		 */
		return kr;
	}

	if (vm_compressor_is_slot_compressed((int *)src_slot) == false) {
		/*
		 * Unmodified anonymous pages are sitting uncompressed on disk.
		 * So don't pull them back in again.
		 */
		return kr;
	}

Relookup_dst:
	c_seg_dst = c_seg_allocate((c_segment_t *)current_chead);
	/*
	 * returns with c_seg lock held
	 * and PAGE_REPLACEMENT_DISALLOWED(TRUE)...
	 * c_nextslot has been allocated and
	 * c_store.c_buffer populated
	 */
	if (c_seg_dst == NULL) {
		/*
		 * Out of compression segments?
		 */
		kr = KERN_RESOURCE_SHORTAGE;
		goto out;
	}

	assert(c_seg_dst->c_busy == 0);

	C_SEG_BUSY(c_seg_dst);

	dst_slot = c_seg_dst->c_nextslot;

	lck_mtx_unlock_always(&c_seg_dst->c_lock);

Relookup_src:
	c_seg_src = c_segments[src_slot->s_cseg - 1].c_seg;

	assert(c_seg_dst != c_seg_src);

	lck_mtx_lock_spin_always(&c_seg_src->c_lock);

	if (C_SEG_IS_ON_DISK_OR_SOQ(c_seg_src) ||
	    c_seg_src->c_state == C_IS_FILLING) {
		/*
		 * Skip this page if :-
		 * a) the src c_seg is already on-disk (or on its way there)
		 *    A "thaw" can mark a process as eligible for
		 * another freeze cycle without bringing any of
		 * its swapped out c_segs back from disk (because
		 * that is done on-demand).
		 *    Or, this page may be mapped elsewhere in the task's map,
		 * and we may have marked it for swap already.
		 *
		 * b) Or, the src c_seg is being filled by the compressor
		 * thread. We don't want the added latency of waiting for
		 * this c_seg in the freeze path and so we skip it.
		 */

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		lck_mtx_unlock_always(&c_seg_src->c_lock);

		c_seg_src = NULL;

		goto out;
	}

	if (c_seg_src->c_busy) {
		PAGE_REPLACEMENT_DISALLOWED(FALSE);
		c_seg_wait_on_busy(c_seg_src);

		c_seg_src = NULL;

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		goto Relookup_src;
	}

	C_SEG_BUSY(c_seg_src);

	lck_mtx_unlock_always(&c_seg_src->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);

	/* find the c_slot */
	c_indx = src_slot->s_cindx;

	c_src = C_SEG_SLOT_FROM_INDEX(c_seg_src, c_indx);

	c_size = UNPACK_C_SIZE(c_src);

	assert(c_size);

	if (c_size > (uint32_t)(c_seg_bufsize - C_SEG_OFFSET_TO_BYTES((int32_t)c_seg_dst->c_nextoffset))) {
		/*
		 * This segment is full. We need a new one.
		 */

		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg_src->c_lock);
		C_SEG_WAKEUP_DONE(c_seg_src);
		lck_mtx_unlock_always(&c_seg_src->c_lock);

		c_seg_src = NULL;

		lck_mtx_lock_spin_always(&c_seg_dst->c_lock);

		assert(c_seg_dst->c_busy);
		assert(c_seg_dst->c_state == C_IS_FILLING);
		assert(!c_seg_dst->c_on_minorcompact_q);

		c_current_seg_filled(c_seg_dst, (c_segment_t *)current_chead);
		assert(*current_chead == NULL);

		C_SEG_WAKEUP_DONE(c_seg_dst);

		lck_mtx_unlock_always(&c_seg_dst->c_lock);

		c_seg_dst = NULL;

		PAGE_REPLACEMENT_DISALLOWED(FALSE);

		goto Relookup_dst;
	}

	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, c_seg_dst->c_nextslot);

	memcpy(&c_seg_dst->c_store.c_buffer[c_seg_dst->c_nextoffset], &c_seg_src->c_store.c_buffer[c_src->c_offset], c_size);
	/*
	 * Is platform alignment actually necessary since wkdm aligns its output?
	 */
	c_rounded_size = (c_size + C_SEG_OFFSET_ALIGNMENT_MASK) & ~C_SEG_OFFSET_ALIGNMENT_MASK;

	cslot_copy(c_dst, c_src);
	c_dst->c_offset = c_seg_dst->c_nextoffset;

	if (c_seg_dst->c_firstemptyslot == c_seg_dst->c_nextslot) {
		c_seg_dst->c_firstemptyslot++;
	}

	c_seg_dst->c_slots_used++;
	c_seg_dst->c_nextslot++;
	c_seg_dst->c_bytes_used += c_rounded_size;
	c_seg_dst->c_nextoffset += C_SEG_BYTES_TO_OFFSET(c_rounded_size);


	PACK_C_SIZE(c_src, 0);

	c_seg_src->c_bytes_used -= c_rounded_size;
	c_seg_src->c_bytes_unused += c_rounded_size;

	assert(c_seg_src->c_slots_used);
	c_seg_src->c_slots_used--;

	if (!c_seg_src->c_swappedin) {
		/* Pessimistically lose swappedin status when non-swappedin pages are added. */
		c_seg_dst->c_swappedin = false;
	}

	if (c_indx < c_seg_src->c_firstemptyslot) {
		c_seg_src->c_firstemptyslot = c_indx;
	}

	c_dst = C_SEG_SLOT_FROM_INDEX(c_seg_dst, dst_slot);

	PAGE_REPLACEMENT_ALLOWED(TRUE);
	slot_ptr = C_SLOT_UNPACK_PTR(c_dst);
	/* <csegno=0,indx=0> would mean "empty slot", so use csegno+1 */
	slot_ptr->s_cseg = c_seg_dst->c_mysegno + 1;
	slot_ptr->s_cindx = dst_slot;

	PAGE_REPLACEMENT_ALLOWED(FALSE);

out:
	if (c_seg_src) {
		lck_mtx_lock_spin_always(&c_seg_src->c_lock);

		C_SEG_WAKEUP_DONE(c_seg_src);

		if (c_seg_src->c_bytes_used == 0 && c_seg_src->c_state != C_IS_FILLING) {
			if (!c_seg_src->c_on_minorcompact_q) {
				c_seg_need_delayed_compaction(c_seg_src, FALSE);
			}
		}

		lck_mtx_unlock_always(&c_seg_src->c_lock);
	}

	if (c_seg_dst) {
		PAGE_REPLACEMENT_DISALLOWED(TRUE);

		lck_mtx_lock_spin_always(&c_seg_dst->c_lock);

		if (c_seg_dst->c_nextoffset >= c_seg_off_limit || c_seg_dst->c_nextslot >= C_SLOT_MAX_INDEX) {
			/*
			 * Nearing or exceeded maximum slot and offset capacity.
			 */
			assert(c_seg_dst->c_busy);
			assert(c_seg_dst->c_state == C_IS_FILLING);
			assert(!c_seg_dst->c_on_minorcompact_q);

			c_current_seg_filled(c_seg_dst, (c_segment_t *)current_chead);
			assert(*current_chead == NULL);
		}

		C_SEG_WAKEUP_DONE(c_seg_dst);

		lck_mtx_unlock_always(&c_seg_dst->c_lock);

		c_seg_dst = NULL;

		PAGE_REPLACEMENT_DISALLOWED(FALSE);
	}

	return kr;
}
#endif /* CONFIG_FREEZE */

#if DEVELOPMENT || DEBUG

void
vm_compressor_inject_error(int *slot)
{
	c_slot_mapping_t slot_ptr = (c_slot_mapping_t)slot;

	/* No error detection for single-value compression. */
	if (slot_ptr->s_cseg == C_SV_CSEG_ID) {
		printf("%s(): cannot inject errors in SV-compressed pages\n", __func__ );
		return;
	}

	/* s_cseg is actually "segno+1" */
	const uint32_t c_segno = slot_ptr->s_cseg - 1;

	assert(c_segno < c_segments_available);
	assert(c_segments[c_segno].c_segno >= c_segments_available);

	const c_segment_t c_seg = c_segments[c_segno].c_seg;

	PAGE_REPLACEMENT_DISALLOWED(TRUE);

	lck_mtx_lock_spin_always(&c_seg->c_lock);
	assert(c_seg->c_state != C_IS_EMPTY && c_seg->c_state != C_IS_FREE);

	const uint16_t c_indx = slot_ptr->s_cindx;
	assert(c_indx < c_seg->c_nextslot);

	/*
	 * To safely make this segment temporarily writable, we need to mark
	 * the segment busy, which allows us to release the segment lock.
	 */
	while (c_seg->c_busy) {
		c_seg_wait_on_busy(c_seg);
		lck_mtx_lock_spin_always(&c_seg->c_lock);
	}
	C_SEG_BUSY(c_seg);

	bool already_writable = (c_seg->c_state == C_IS_FILLING);
	if (!already_writable) {
		/*
		 * Protection update must be performed preemptibly, so temporarily drop
		 * the lock. Having set c_busy will prevent most other concurrent
		 * operations.
		 */
		lck_mtx_unlock_always(&c_seg->c_lock);
		C_SEG_MAKE_WRITEABLE(c_seg);
		lck_mtx_lock_spin_always(&c_seg->c_lock);
	}

	/*
	 * Once we've released the lock following our c_state == C_IS_FILLING check,
	 * c_current_seg_filled() can (re-)write-protect the segment. However, it
	 * will transition from C_IS_FILLING before releasing the c_seg lock, so we
	 * can detect this by re-checking after we've reobtained the lock.
	 */
	if (already_writable && c_seg->c_state != C_IS_FILLING) {
		lck_mtx_unlock_always(&c_seg->c_lock);
		C_SEG_MAKE_WRITEABLE(c_seg);
		lck_mtx_lock_spin_always(&c_seg->c_lock);
		already_writable = false;
		/* Segment can't be freed while c_busy is set. */
		assert(c_seg->c_state != C_IS_FILLING);
	}

	/*
	 * Skip if the segment is on disk. This check can only be performed after
	 * the final acquisition of the segment lock before we attempt to write to
	 * the segment.
	 */
	if (!C_SEG_IS_ON_DISK_OR_SOQ(c_seg)) {
		c_slot_t cs = C_SEG_SLOT_FROM_INDEX(c_seg, c_indx);
		int32_t *data = &c_seg->c_store.c_buffer[cs->c_offset];
		/* assume that the compressed data holds at least one int32_t */
		assert(UNPACK_C_SIZE(cs) > sizeof(*data));
		/*
		 * This bit is known to be in the payload of a MISS packet resulting from
		 * the pattern used in the test pattern from decompression_failure.c.
		 * Flipping it should result in many corrupted bits in the test page.
		 */
		data[0] ^= 0x00000100;
	}

	if (!already_writable) {
		lck_mtx_unlock_always(&c_seg->c_lock);
		C_SEG_WRITE_PROTECT(c_seg);
		lck_mtx_lock_spin_always(&c_seg->c_lock);
	}

	C_SEG_WAKEUP_DONE(c_seg);
	lck_mtx_unlock_always(&c_seg->c_lock);

	PAGE_REPLACEMENT_DISALLOWED(FALSE);
}

#endif /* DEVELOPMENT || DEBUG */


#if CONFIG_TRACK_UNMODIFIED_ANON_PAGES

struct vnode;
extern void vm_swapfile_open(const char *path, struct vnode **vp);
extern int vm_swapfile_preallocate(struct vnode *vp, uint64_t *size, boolean_t *pin);

struct vnode *uncompressed_vp0 = NULL;
struct vnode *uncompressed_vp1 = NULL;
uint32_t uncompressed_file0_free_pages = 0, uncompressed_file1_free_pages = 0;
uint64_t uncompressed_file0_free_offset = 0, uncompressed_file1_free_offset = 0;

uint64_t compressor_ro_uncompressed = 0;
uint64_t compressor_ro_uncompressed_total_returned = 0;
uint64_t compressor_ro_uncompressed_skip_returned = 0;
uint64_t compressor_ro_uncompressed_get = 0;
uint64_t compressor_ro_uncompressed_put = 0;
uint64_t compressor_ro_uncompressed_swap_usage = 0;

extern void vnode_put(struct vnode* vp);
extern int vnode_getwithref(struct vnode* vp);
extern int vm_swapfile_io(struct vnode *vp, uint64_t offset, uint64_t start, int npages, int flags, void *upl_ctx);

#define MAX_OFFSET_PAGES        (255)
uint64_t uncompressed_file0_space_bitmap[MAX_OFFSET_PAGES];
uint64_t uncompressed_file1_space_bitmap[MAX_OFFSET_PAGES];

#define UNCOMPRESSED_FILEIDX_OFFSET_MASK (((uint32_t)1<<31ull) - 1)
#define UNCOMPRESSED_FILEIDX_SHIFT (29)
#define UNCOMPRESSED_FILEIDX_MASK (3)
#define UNCOMPRESSED_OFFSET_SHIFT (29)
#define UNCOMPRESSED_OFFSET_MASK (7)

static uint32_t
vm_uncompressed_extract_swap_file(int slot)
{
	uint32_t fileidx = (((uint32_t)slot & UNCOMPRESSED_FILEIDX_OFFSET_MASK) >> UNCOMPRESSED_FILEIDX_SHIFT) & UNCOMPRESSED_FILEIDX_MASK;
	return fileidx;
}

static uint32_t
vm_uncompressed_extract_swap_offset(int slot)
{
	return slot & (uint32_t)(~(UNCOMPRESSED_OFFSET_MASK << UNCOMPRESSED_OFFSET_SHIFT));
}

static void
vm_uncompressed_return_space_to_swap(int slot)
{
	PAGE_REPLACEMENT_ALLOWED(TRUE);
	uint32_t fileidx = vm_uncompressed_extract_swap_file(slot);
	if (fileidx == 1) {
		uint32_t free_offset = vm_uncompressed_extract_swap_offset(slot);
		uint64_t pgidx = free_offset / PAGE_SIZE_64;
		uint64_t chunkidx = pgidx / 64;
		uint64_t chunkoffset = pgidx % 64;
#if DEVELOPMENT || DEBUG
		uint64_t vaddr = (uint64_t)&uncompressed_file0_space_bitmap[chunkidx];
		uint64_t maxvaddr = (uint64_t)&uncompressed_file0_space_bitmap[MAX_OFFSET_PAGES];
		assertf(vaddr < maxvaddr, "0x%llx 0x%llx", vaddr, maxvaddr);
#endif /*DEVELOPMENT || DEBUG*/
		assertf((uncompressed_file0_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)),
		    "0x%x %llu %llu", slot, chunkidx, chunkoffset);
		uncompressed_file0_space_bitmap[chunkidx] &= ~((uint64_t)1 << chunkoffset);
		assertf(!(uncompressed_file0_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)),
		    "0x%x %llu %llu", slot, chunkidx, chunkoffset);

		uncompressed_file0_free_pages++;
	} else {
		uint32_t free_offset = vm_uncompressed_extract_swap_offset(slot);
		uint64_t pgidx = free_offset / PAGE_SIZE_64;
		uint64_t chunkidx = pgidx / 64;
		uint64_t chunkoffset = pgidx % 64;
		assertf((uncompressed_file1_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)),
		    "%llu %llu", chunkidx, chunkoffset);
		uncompressed_file1_space_bitmap[chunkidx] &= ~((uint64_t)1 << chunkoffset);

		uncompressed_file1_free_pages++;
	}
	compressor_ro_uncompressed_swap_usage--;
	PAGE_REPLACEMENT_ALLOWED(FALSE);
}

static int
vm_uncompressed_reserve_space_in_swap()
{
	int slot = 0;
	if (uncompressed_file0_free_pages == 0 && uncompressed_file1_free_pages == 0) {
		return -1;
	}

	PAGE_REPLACEMENT_ALLOWED(TRUE);
	if (uncompressed_file0_free_pages) {
		uint64_t chunkidx = 0;
		uint64_t chunkoffset = 0;
		while (uncompressed_file0_space_bitmap[chunkidx] == 0xffffffffffffffff) {
			chunkidx++;
		}
		while (uncompressed_file0_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)) {
			chunkoffset++;
		}

		assertf((uncompressed_file0_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)) == 0,
		    "%llu %llu", chunkidx, chunkoffset);
#if DEVELOPMENT || DEBUG
		uint64_t vaddr = (uint64_t)&uncompressed_file0_space_bitmap[chunkidx];
		uint64_t maxvaddr = (uint64_t)&uncompressed_file0_space_bitmap[MAX_OFFSET_PAGES];
		assertf(vaddr < maxvaddr, "0x%llx 0x%llx", vaddr, maxvaddr);
#endif /*DEVELOPMENT || DEBUG*/
		uncompressed_file0_space_bitmap[chunkidx] |= ((uint64_t)1 << chunkoffset);
		uncompressed_file0_free_offset = ((chunkidx * 64) + chunkoffset) * PAGE_SIZE_64;
		assertf((uncompressed_file0_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)),
		    "%llu %llu", chunkidx, chunkoffset);

		assert(uncompressed_file0_free_offset <= (1 << UNCOMPRESSED_OFFSET_SHIFT));
		slot = (int)((1 << UNCOMPRESSED_FILEIDX_SHIFT) + uncompressed_file0_free_offset);
		uncompressed_file0_free_pages--;
	} else {
		uint64_t chunkidx = 0;
		uint64_t chunkoffset = 0;
		while (uncompressed_file1_space_bitmap[chunkidx] == 0xFFFFFFFFFFFFFFFF) {
			chunkidx++;
		}
		while (uncompressed_file1_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)) {
			chunkoffset++;
		}
		assert((uncompressed_file1_space_bitmap[chunkidx] & ((uint64_t)1 << chunkoffset)) == 0);
		uncompressed_file1_space_bitmap[chunkidx] |= ((uint64_t)1 << chunkoffset);
		uncompressed_file1_free_offset = ((chunkidx * 64) + chunkoffset) * PAGE_SIZE_64;
		slot = (int)((2 << UNCOMPRESSED_FILEIDX_SHIFT) + uncompressed_file1_free_offset);
		uncompressed_file1_free_pages--;
	}
	compressor_ro_uncompressed_swap_usage++;
	PAGE_REPLACEMENT_ALLOWED(FALSE);
	return slot;
}

#define MAX_IO_REQ (16)
struct _uncompressor_io_req {
	uint64_t addr;
	bool inuse;
} uncompressor_io_req[MAX_IO_REQ];

int
vm_uncompressed_put(ppnum_t pn, int *slot)
{
	int retval = 0;
	struct vnode *uncompressed_vp = NULL;
	uint64_t uncompress_offset = 0;

again:
	if (uncompressed_vp0 == NULL) {
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		if (uncompressed_vp0 == NULL) {
			uint64_t size = (MAX_OFFSET_PAGES * 1024 * 1024ULL);
			vm_swapfile_open("/private/var/vm/uncompressedswap0", &uncompressed_vp0);
			if (uncompressed_vp0 == NULL) {
				PAGE_REPLACEMENT_ALLOWED(FALSE);
				return KERN_NO_ACCESS;
			}
			vm_swapfile_preallocate(uncompressed_vp0, &size, NULL);
			uncompressed_file0_free_pages = (uint32_t)atop(size);
			bzero(uncompressed_file0_space_bitmap, sizeof(uint64_t) * MAX_OFFSET_PAGES);

			int i = 0;
			for (; i < MAX_IO_REQ; i++) {
				kmem_alloc(kernel_map, (vm_offset_t*)&uncompressor_io_req[i].addr, PAGE_SIZE_64, KMA_NOFAIL | KMA_KOBJECT, VM_KERN_MEMORY_COMPRESSOR);
				uncompressor_io_req[i].inuse = false;
			}

			vm_swapfile_open("/private/var/vm/uncompressedswap1", &uncompressed_vp1);
			assert(uncompressed_vp1);
			vm_swapfile_preallocate(uncompressed_vp1, &size, NULL);
			uncompressed_file1_free_pages = (uint32_t)atop(size);
			bzero(uncompressed_file1_space_bitmap, sizeof(uint64_t) * MAX_OFFSET_PAGES);
			PAGE_REPLACEMENT_ALLOWED(FALSE);
		} else {
			PAGE_REPLACEMENT_ALLOWED(FALSE);
			delay(100);
			goto again;
		}
	}

	int swapinfo = vm_uncompressed_reserve_space_in_swap();
	if (swapinfo == -1) {
		*slot = 0;
		return KERN_RESOURCE_SHORTAGE;
	}

	if (vm_uncompressed_extract_swap_file(swapinfo) == 1) {
		uncompressed_vp = uncompressed_vp0;
	} else {
		uncompressed_vp = uncompressed_vp1;
	}
	uncompress_offset = vm_uncompressed_extract_swap_offset(swapinfo);
	if ((retval = vnode_getwithref(uncompressed_vp)) != 0) {
		os_log_error_with_startup_serial(OS_LOG_DEFAULT, "vm_uncompressed_put: vnode_getwithref on swapfile failed with %d\n", retval);
	} else {
		int i = 0;
retry:
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		for (i = 0; i < MAX_IO_REQ; i++) {
			if (uncompressor_io_req[i].inuse == false) {
				uncompressor_io_req[i].inuse = true;
				break;
			}
		}
		if (i == MAX_IO_REQ) {
			assert_wait((event_t)&uncompressor_io_req, THREAD_UNINT);
			PAGE_REPLACEMENT_ALLOWED(FALSE);
			thread_block(THREAD_CONTINUE_NULL);
			goto retry;
		}
		PAGE_REPLACEMENT_ALLOWED(FALSE);
		void *addr = pmap_map_compressor_page(pn);
		memcpy((void*)uncompressor_io_req[i].addr, addr, PAGE_SIZE_64);
		pmap_unmap_compressor_page(pn, addr);

		retval = vm_swapfile_io(uncompressed_vp, uncompress_offset, (uint64_t)uncompressor_io_req[i].addr, 1, SWAP_WRITE, NULL);
		if (retval) {
			*slot = 0;
		} else {
			*slot = (int)swapinfo;
			((c_slot_mapping_t)(slot))->s_uncompressed = 1;
		}
		vnode_put(uncompressed_vp);
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		uncompressor_io_req[i].inuse = false;
		thread_wakeup((event_t)&uncompressor_io_req);
		PAGE_REPLACEMENT_ALLOWED(FALSE);
	}
	return retval;
}

int
vm_uncompressed_get(ppnum_t pn, int *slot, __unused vm_compressor_options_t flags)
{
	int retval = 0;
	struct vnode *uncompressed_vp = NULL;
	uint32_t fileidx = vm_uncompressed_extract_swap_file(*slot);
	uint64_t uncompress_offset = vm_uncompressed_extract_swap_offset(*slot);

	if (__improbable(flags & C_KDP)) {
		return -2;
	}

	if (fileidx == 1) {
		uncompressed_vp = uncompressed_vp0;
	} else {
		uncompressed_vp = uncompressed_vp1;
	}

	if ((retval = vnode_getwithref(uncompressed_vp)) != 0) {
		os_log_error_with_startup_serial(OS_LOG_DEFAULT, "vm_uncompressed_put: vnode_getwithref on swapfile failed with %d\n", retval);
	} else {
		int i = 0;
retry:
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		for (i = 0; i < MAX_IO_REQ; i++) {
			if (uncompressor_io_req[i].inuse == false) {
				uncompressor_io_req[i].inuse = true;
				break;
			}
		}
		if (i == MAX_IO_REQ) {
			assert_wait((event_t)&uncompressor_io_req, THREAD_UNINT);
			PAGE_REPLACEMENT_ALLOWED(FALSE);
			thread_block(THREAD_CONTINUE_NULL);
			goto retry;
		}
		PAGE_REPLACEMENT_ALLOWED(FALSE);
		retval = vm_swapfile_io(uncompressed_vp, uncompress_offset, (uint64_t)uncompressor_io_req[i].addr, 1, SWAP_READ, NULL);
		vnode_put(uncompressed_vp);
		void *addr = pmap_map_compressor_page(pn);
		memcpy(addr, (void*)uncompressor_io_req[i].addr, PAGE_SIZE_64);
		pmap_unmap_compressor_page(pn, addr);
		PAGE_REPLACEMENT_ALLOWED(TRUE);
		uncompressor_io_req[i].inuse = false;
		thread_wakeup((event_t)&uncompressor_io_req);
		PAGE_REPLACEMENT_ALLOWED(FALSE);
	}
	return retval;
}

int
vm_uncompressed_free(int *slot, __unused vm_compressor_options_t flags)
{
	vm_uncompressed_return_space_to_swap(*slot);
	*slot = 0;
	return 0;
}

#endif /*CONFIG_TRACK_UNMODIFIED_ANON_PAGES*/
