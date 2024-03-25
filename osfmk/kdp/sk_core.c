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

/*
 * Secure kernel coredump support.
 *
 * Actual coredump is a physical memory footprint of secure kernel's memory.
 * The whole macho is written by using PA == VA mappings for its segments.
 * It is required to use cL4's scripted process plugin to reconstruct VA address
 * spaces back.
 */

#include <kdp/processor_core.h>
#include <kdp/kdp_core.h>
#include <kdp/core_notes.h>
#include <kdp/sk_core.h>

#include <machine/machine_routines.h>
#include <pexpert/boot.h>
#include <arm64/sptm/sptm.h>
#include <arm64/proc_reg.h>
#include <vm/pmap.h>

#if EXCLAVES_COREDUMP

#pragma mark secure coredump data structures


/* Secure coredump reference constant type. */
struct secure_core_context {
	uuid_t *scc_uuid;           /* UUID to be added to coredump. */
	uint64_t scc_segments;      /* Total amount of segments. */
	uint64_t scc_total;         /* Total amount of bytes. */
};

/*
 * cL4's debug signpost structure required to identify UUID of a cL4.
 *
 * Keep in sync with cL4's debug signpost.
 * From: cL4/kernel/src/plat/common/lib/debug/signpost/signpost.h
 */

/* Older structure magic/version. */
#define ASTRIS_UUID_MAGIC 'diuu'
#define ASTRIS_UUID_VERSION 5

/*
 * Both old and new structures are identical up to uuid field.
 * XNU does not need to read anything else, so the structure below
 * defines only common fields up to uuid itself.
 */
struct astris_uuid {
	uint32_t magic;
	uint32_t version;
	uint32_t _reserved_0[2];
	uuid_t   uuid;
	uint32_t _reserved_1[4];
} __attribute__((packed));

/* Current structure magic/version. */
#define DEBUG_SIGNPOST_MAGIC 'cL4D'
#define DEBUG_SIGNPOST_VERSION 0

struct debug_signpost {
	uint32_t magic;
	uint32_t version;
	uuid_t   uuid;
	/* remaining fields are not interesting */
} __attribute__((packed));

/*
 * Debug kernel header of cL4 kernel.
 *
 * Keep in sync with cL4's dbg_kernel_header
 * From: kernel/src/plat/common/lib/dbgreg/internal.h
 */

/* debug registry secure kernel record header version */
#define DBGREG_KERNEL_HEADER_VERSION 2

/* debug registry secure kernel record header */
struct dbg_kernel_header {
	uint32_t version;       /* header version */
	uint32_t reserved;      /* reserved */
	uint64_t tcr;           /* kernel tcr_el1 register value */
	uint64_t ttbr1;         /* kernel ttbr1_el1 register value */
	uint64_t vbar;          /* kernel vbar_el1 register value */
};

static SECURITY_READ_ONLY_LATE(struct dbg_kernel_header *sk_dbg_header) = NULL;

/*
 * Artificial segment that will hold copy of 'seckern' LC_NOTE. This copy can be
 * removed when LLDB allows access to LC_NOTEs to the scripted process.
 *
 * The actucal VA has to be kept in sync with cL4's scripted process plug-in.
 *
 * Removal tracked in rdar://116107495
 */
static const uint64_t sk_dbg_header_seg_va = 0xFFFFFFFFFFFFC000;

/* coredumping mode */
__enum_closed_decl(secure_coredump_mode_t, unsigned int, {
	SC_MODE_DISABLED,               /* Coredump support disabled. */
	SC_MODE_CDBG                    /* Use consistent debug entries. */
});

/* Referenced from kern_sysctl.c */
SECURITY_READ_ONLY_LATE(secure_coredump_mode_t sc_dump_mode) = SC_MODE_DISABLED;


#pragma mark Coredump configuration (consistent debug)


/*
 * A dev-fused device should have a SECKERN entry in consistent debug records.
 * It is used to find location of cL4 debug header.
 *
 * Consistent debug entry holds pointer into cL4's address space.
 * It is not possible to access contents of the debug header until SPTM grants
 * access to secure kernel's memory.
 */

#define kDbgIdSecKernInfo    (DEBUG_RECORD_ID_LONG('S','E','C','K','E','R','N', 0))

static kern_return_t
sc_init_cdbg(void)
{
	uint64_t sk_debug_phys, sk_debug_len;

	if (!PE_consistent_debug_enabled()) {
		printf("secure_core: Consistent debug disabled.\n");
		return KERN_FAILURE;
	}

	if (!PE_consistent_debug_lookup_entry(kDbgIdSecKernInfo, &sk_debug_phys, &sk_debug_len)) {
		printf("secure_core: secure kernel entry missing in consistent debug.\n");
		return KERN_FAILURE;
	}

	/* Configure consistent debug mode. */
	sk_dbg_header = (struct dbg_kernel_header *)phystokv(sk_debug_phys);
	sc_dump_mode = SC_MODE_CDBG;

	return KERN_SUCCESS;
}


#pragma mark Address translation support


/*
 * All structures required for dump live in cL4's VA space. It is required
 * To perform translaction between cL4 VA into XNU VA so coredumper can
 * access required data from XNU side.
 */


/* Taken from pmap code - configuration for 4 levels page table walk. */
static const struct page_level_config {
	const uint64_t size;
	const uint64_t offmask;
	const uint64_t shift;
	const uint64_t index_mask;
	const uint64_t valid_mask;
	const uint64_t type_mask;
	const uint64_t type_block;
} page_config[] = {
	[0] = {
		.size       = ARM_16K_TT_L0_SIZE,
		.offmask    = ARM_16K_TT_L0_OFFMASK,
		.shift      = ARM_16K_TT_L0_SHIFT,
		.index_mask = ARM_16K_TT_L0_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[1] = {
		.size       = ARM_16K_TT_L1_SIZE,
		.offmask    = ARM_16K_TT_L1_OFFMASK,
		.shift      = ARM_16K_TT_L1_SHIFT,
		.index_mask = ARM_16K_TT_L1_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[2] = {
		.size       = ARM_16K_TT_L2_SIZE,
		.offmask    = ARM_16K_TT_L2_OFFMASK,
		.shift      = ARM_16K_TT_L2_SHIFT,
		.index_mask = ARM_16K_TT_L2_INDEX_MASK,
		.valid_mask = ARM_TTE_VALID,
		.type_mask  = ARM_TTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_BLOCK
	},
	[3] = {
		.size       = ARM_16K_TT_L3_SIZE,
		.offmask    = ARM_16K_TT_L3_OFFMASK,
		.shift      = ARM_16K_TT_L3_SHIFT,
		.index_mask = ARM_16K_TT_L3_INDEX_MASK,
		.valid_mask = ARM_PTE_TYPE_VALID,
		.type_mask  = ARM_PTE_TYPE_MASK,
		.type_block = ARM_TTE_TYPE_L3BLOCK
	}
};

/* Return kernel's VA size from TCR. */
static inline uint64_t
sc_va_size(uint64_t tcr)
{
	return (tcr >> 16) & 0x3f;
}

/* Return page size in bits based on TCR. */
static inline uint64_t
sc_va_page_size(uint64_t tcr)
{
	const uint64_t tg1 = (tcr >> 30) & 0x3;

	switch (tg1) {
	case 1:
		return 16;
	case 2:
		return 4;
	case 3:
		return 64;
	}

	return 0;
}

/* Page table walk configuration. */
static uint64_t sc_vaddr_mask = 0;
static int sc_page_levels = 0;

static kern_return_t
sc_boostrap_va(struct dbg_kernel_header *hdrp)
{
	/* validate and set VA bit mask */
	const uint64_t va_size_bits = sc_va_size(hdrp->tcr);
	if (va_size_bits == 0) {
		kern_coredump_log(NULL, "secure_core: Invalid VA bit size");
		return KERN_FAILURE;
	}

	sc_vaddr_mask = (1UL << va_size_bits) - 1;

	/* validate and set page size / levels */
	const uint64_t page_size_bits = sc_va_page_size(hdrp->tcr);
	if (page_size_bits == 0) {
		kern_coredump_log(NULL, "secure_core: Invalid page size bits");
		return KERN_FAILURE;
	}

	sc_page_levels = (int)(((va_size_bits - page_size_bits) + ((page_size_bits - 3) - 1)) / (page_size_bits - 3));
	return KERN_SUCCESS;
}

/*
 * Converts cL4 kernel VA to XNU VA.
 *
 * The translation starts with cL4's TTBR1 and maps a cL4 virtual address to
 * physical address. A physical address is then mapped back to XNU's PAPT virtual
 * address.
 *
 * Note: panics if SPTM has not unlocked SK_DOMAIN memory access.
 */
static vm_map_address_t
sc_cL4_kvtov(vm_map_address_t vaddr)
{
	tt_entry_t *ttp = (tt_entry_t *)phystokv(sk_dbg_header->ttbr1 & ARM_TTE_PA_MASK);
	tt_entry_t *ttep = NULL;
	tt_entry_t tte = ARM_TTE_EMPTY;
	pmap_paddr_t paddr = 0;

	vaddr = vaddr & sc_vaddr_mask;

	for (int cur_level = 4 - sc_page_levels; cur_level <= 3; cur_level++) {
		const uint64_t idx = vaddr & page_config[cur_level].index_mask;
		const uint64_t valid_mask = page_config[cur_level].valid_mask;
		const uint64_t type_mask = page_config[cur_level].type_mask;
		const uint64_t type_block = page_config[cur_level].type_block;
		const uint64_t offmask = page_config[cur_level].offmask;

		/* Find TTE index for current level. */
		ttep = &ttp[idx >> page_config[cur_level].shift];
		tte = *ttep;

		/* Check if we have valid tte */
		if ((tte & valid_mask) != valid_mask) {
			return 0;
		}

		/* Detect a leaf entry/block address. */
		if ((tte & type_mask) == type_block) {
			paddr = ((tte & ARM_TTE_PA_MASK & ~offmask) | (vaddr & offmask));
			break;
		}

		/* Find next TTE through PAPT */
		ttp = (tt_entry_t *)phystokv(tte & ARM_TTE_TABLE_MASK);
	}

	/* Translate physical address back to XNU VA. */
	return phystokv(paddr);
}

/*
 * Locates cL4 debug signpost per agreed algorithm:
 *    1. Find stepping stone at VBAR + 0x800
 *    2. Construct final VA as VBAR + stepping stone
 *
 * Note: Requires access to SK_DOMAIN pages to avoid panic.
 */
static uuid_t *
sc_find_uuid_cdbg(void)
{
	uuid_t *uuid = NULL;

	/* Return PAPT VA of a stepping stone. */
	vm_map_address_t vbar = sc_cL4_kvtov(sk_dbg_header->vbar);
	if (vbar == 0) {
		kern_coredump_log(NULL, "secure_core: Can't translate VBAR address\n");
		return NULL;
	}

	/* Construct final debug singpost address. */
	uint64_t offs = *(int64_t *)(vbar + 0x800);

	/* Use structure based on magic. */
	const vm_map_address_t signpostva = sc_cL4_kvtov(sk_dbg_header->vbar + offs);

	/* Determine header based on magic and version */
	const uint32_t magic = *(uint32_t *)signpostva;

	switch (magic) {
	case ASTRIS_UUID_MAGIC: {
		struct astris_uuid *signpost = (struct astris_uuid *)signpostva;

		if (signpost->version != ASTRIS_UUID_VERSION) {
			kern_coredump_log(NULL, "secure_core: unsupported astris signpost version 0x%x\n", signpost->version);
			break;
		}

		uuid = &signpost->uuid;
		break;
	}
	case DEBUG_SIGNPOST_MAGIC: {
		struct debug_signpost *signpost = (struct debug_signpost *)signpostva;

		if (signpost->version != DEBUG_SIGNPOST_VERSION) {
			kern_coredump_log(NULL, "secure_core: unsupported debug signpost version 0x%x\n", signpost->version);
			break;
		}

		uuid = &signpost->uuid;
		break;
	}
	default:
		kern_coredump_log(NULL, "secure_core: unknwon signpost magic 0x%x\n", magic);
	}

	return uuid;
}


#pragma mark secure coredump memory dump


/* Pages to be walked. */
extern const vm_map_address_t physmap_base;
extern const vm_map_address_t physmap_end;

typedef kern_return_t (*papt_walk_callback)(pmap_paddr_t start, pmap_paddr_t end, void *context);

/*
 * Returns wheter a PAPT page belongs to SK_DOMAIN.
 *
 * I/O pages are not collect as a part of secure coredump.
 */
static inline bool
is_sk_type(int type)
{
	return type == SK_DEFAULT || type == SK_SHARED_RO || type == SK_SHARED_RW;
}

/*
 * Walks XNU's PAPT and finds all physical pages from SK_DOMAIN.
 * Contiguous ranges of physical pages are reported as single segment.
 */
static kern_return_t
papt_walk(papt_walk_callback cb, void *context)
{
	pmap_paddr_t seg_start = 0;
	pmap_paddr_t seg_end = 0;
	pmap_paddr_t last_paddr = 0;
	kern_return_t kr = KERN_SUCCESS;

	for (vm_map_address_t vaddr = physmap_base; vaddr < physmap_end; vaddr += PAGE_SIZE_64) {
		pmap_paddr_t paddr = kvtophys(vaddr);

		/* Skip non secure domain pages. */
		if (!is_sk_type(sptm_get_frame_type(paddr))) {
			continue;
		}

		/* Open new segment if we don't have one already. */
		if (seg_start == 0) {
			seg_start = paddr;
			seg_end = paddr + PAGE_SIZE_64;
			last_paddr = paddr;
			continue;
		}

		/* Prolong currently opened segment if PA is contiguous. */
		if (paddr == last_paddr + PAGE_SIZE_64) {
			seg_end = paddr + PAGE_SIZE_64;
			last_paddr = paddr;
			continue;
		}

		/* Close the segment and send it out to callback. */
		kr = cb(seg_start, seg_end, context);
		if (kr != KERN_SUCCESS) {
			kern_coredump_log(NULL, "secure_core: PAPT walk callback failed with %d\n", kr);
			return kr;
		}

		/* Open new segment. */
		seg_start = paddr;
		seg_end = paddr + PAGE_SIZE_64;
		last_paddr = paddr;
	}

	/* report last segment */
	if (seg_start != 0) {
		kr = cb(seg_start, seg_end, context);
		if (kr != KERN_SUCCESS) {
			kern_coredump_log(NULL, "secure_core: PAPT walk callback failed with %d\n", kr);
		}
	}

	return kr;
}


#pragma mark secure coredump helper callbacks


/*
 * It is not possible to allocate a memory on panic path. Thus this code has
 * to scan cL4's memory multiple times. First a preflight identifies how many
 * segments and total size we are about to dump. Remaining rounds are for
 * actuall data extraction.
 *
 * Getting totals ahead of the actual dump is not only required to show progress
 * but also to periodically prolong panic watchdog.
 */


static kern_return_t
secure_summary(pmap_paddr_t start, pmap_paddr_t end, void *refcon)
{
	struct secure_core_context *scc = refcon;

	scc->scc_segments++;
	scc->scc_total += (end - start);

	return KERN_SUCCESS;
}

static kern_return_t
sk_dump_init(void *refcon, void *context)
{
	/* Core dump disabled for some reason. */
	if (sc_dump_mode == SC_MODE_DISABLED) {
		kern_coredump_log(context, "secure_core: Disabled\n");
		return KERN_NODE_DOWN;
	}

	if (sk_dbg_header == NULL) {
		kern_coredump_log(context, "secure_core: No debug header\n");
		return KERN_NODE_DOWN;
	}

	/* Unlock access to secure domain pages. */
	sptm_map_sk_domain();

	/* Bootstrap secure kernel page table translation. */
	if (sc_boostrap_va(sk_dbg_header) != KERN_SUCCESS) {
		kern_coredump_log(context, "secure_core: Invalid debug header contents.\n");
		return KERN_NODE_DOWN;
	}

	/* validate debug header */
	if (sk_dbg_header->version != DBGREG_KERNEL_HEADER_VERSION) {
		kern_coredump_log(context, "secure_core: Debug header version (%d) mismatch\n",
		    sk_dbg_header->version);
		return KERN_NODE_DOWN;
	}

	/* validate debug signpost and discover UUID. */
	struct secure_core_context *scc = (struct secure_core_context *)refcon;
	scc->scc_uuid = sc_find_uuid_cdbg();

	if (scc->scc_uuid == NULL) {
		kern_coredump_log(context, "secure_core: No UUID found\n");
		return KERN_NODE_DOWN;
	}

	return KERN_SUCCESS;
}

static kern_return_t
sk_dump_get_summary(void *refcon, core_save_summary_cb callback, void *context)
{
	kern_return_t ret;

	ret = papt_walk(secure_summary, refcon);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "secure_core: Unable to get summary: %d\n", ret);
		return ret;
	}

	/* Account for extra segment with debug header for LLDB's scripted process. */
	struct secure_core_context *scc = refcon;
	scc->scc_segments++;
	scc->scc_total += sizeof(struct dbg_kernel_header);

	return callback(scc->scc_segments, scc->scc_total, 0, 0, 0, context);
}

typedef struct secure_segment_desc {
	core_save_segment_descriptions_cb ssd_callback;
	void *                            ssd_context;
} secure_segment_desc_t;

static kern_return_t
secure_seg_desc(pmap_paddr_t start, pmap_paddr_t end, void *context)
{
	secure_segment_desc_t *ssd = context;

	return ssd->ssd_callback(start, end, ssd->ssd_context);
}

static kern_return_t
sk_dump_save_seg_desc(void *refcon __unused, core_save_segment_descriptions_cb callback,
    void *context)
{
	kern_return_t ret;
	secure_segment_desc_t ssd = {
		.ssd_callback = callback,
		.ssd_context = context
	};

	ret = papt_walk(secure_seg_desc, &ssd);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "secure_core: Unable to save segment description: %d\n", ret);
		return ret;
	}

	/* Save cL4's debug header as a special segment. */
	return callback(sk_dbg_header_seg_va, sk_dbg_header_seg_va + sizeof(struct dbg_kernel_header), context);
}


typedef struct secure_segment_data {
	core_save_segment_data_cb ssd_callback;
	void *                    ssd_context;
} secure_segment_data_t;

static kern_return_t
secure_seg_data(pmap_paddr_t start, pmap_paddr_t end, void *context)
{
	secure_segment_data_t *ssd = context;

	return ssd->ssd_callback((void *)phystokv(start), end - start, ssd->ssd_context);
}

static kern_return_t
sk_dump_save_seg_data(void *refcon __unused, core_save_segment_data_cb callback,
    void *context)
{
	kern_return_t ret;
	secure_segment_data_t ssd = {
		.ssd_callback = callback,
		.ssd_context = context
	};

	ret = papt_walk(secure_seg_data, &ssd);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "secure_core: Unable to save segment data: %d\n", ret);
		return ret;
	}

	/* Save cL4 debug header as a last segment. */
	return callback(sk_dbg_header, sizeof(struct dbg_kernel_header), context);
}

static kern_return_t
sk_dump_save_thread_state(void *refcon __unused, void *buf __unused,
    core_save_thread_state_cb callback __unused, void *context __unused)
{
	/* All threads are parked on XNU side so there is no cL4 thread state. */
	return KERN_FAILURE;
}

static kern_return_t
sk_dump_save_sw_vers_detail(void *refcon,
    core_save_sw_vers_detail_cb callback, void *context)
{
	struct secure_core_context *scc = refcon;
	return callback(0, *(scc->scc_uuid), 0, context);
}

/*
 * LC_NOTE from consistent debug.
 *
 * Contains snapshot of consistent debug region from cL4.
 * The note uses its own versioning to support further extension.
 */

#define SECKERN_DATA_OWNER "seckern"

typedef struct seckern_note {
	uint32_t                    version;       /* currently 1 */
	struct dbg_kernel_header    header;
} __attribute__((packed)) seckern_note_t;

#define SECKERN_VER 1

static kern_return_t
sk_dump_save_note_summary(void *refcon __unused, core_save_note_summary_cb callback, void *context)
{
	return callback(1, sizeof(seckern_note_t), context);
}

static kern_return_t
sk_dump_save_note_desc(void *refcon __unused, core_save_note_descriptions_cb callback, void *context)
{
	return callback(SECKERN_DATA_OWNER, sizeof(seckern_note_t), context);
}

static kern_return_t
sk_dump_save_note_data(void *refcon __unused, core_save_note_data_cb callback, void *context)
{
	seckern_note_t seckern_note = {
		.version = SECKERN_VER,
		.header  = *sk_dbg_header
	};

	return callback(&seckern_note, sizeof(seckern_note), context);
}


#pragma mark secure coredump handler registration


/* Static refconst is fine as secure coredump has only single instance. */
static struct secure_core_context sc_context;

bool
sk_core_enabled(void)
{
	return SPTMArgs->sk_bootstrapped;
}

uint64_t
sk_core_size(void)
{
	static const uint64_t one_mb = 1024ULL * 1024ULL;
	return (sk_core_enabled()) ? 750 * one_mb : 0;
}

/*
 * Initialize secure kernel coredump.
 *
 * Registers a coredump helper only if secure kernel's cL4 is able to provide
 * all requried debugging information to XNU:
 *
 *     - debug header for TTBR1 page table unwinding
 *     - debug signpost for UUID
 *
 * It is not possible to validate any contents of the structures as XNU does
 * not have access to cL4's memory at this point. The access will be granted
 * later from panic context.
 */
void
sk_core_init(void)
{
	kern_coredump_callback_config sk_config = { };
	kern_return_t kr;

	/*
	 * User can disable secure kernel coredump by adding following boot-arg:
	 *     secure_coredump=0
	 */
	unsigned int barg;
	if (PE_parse_boot_argn("secure_coredump", &barg, sizeof(barg)) &&
	    barg == SC_MODE_DISABLED) {
		printf("secure_core: disabled by boot-arg\n");
		return;
	}

	if (sc_init_cdbg() != KERN_SUCCESS) {
		printf("secure_core: not supported\n");
		return;
	}

	if (SPTMArgs->sptm_variant != SPTM_VARIANT_DEVELOPMENT) {
		printf("secure_core: requires development sptm\n");
		return;
	}

	if (!sk_core_enabled()) {
		printf("secure_core: no secure kernel present\n");
		return;
	}

	printf("secure_core: mode = %d\n", sc_dump_mode);

	/* Register coredump handler. */
	sk_config.kcc_coredump_init = sk_dump_init;
	sk_config.kcc_coredump_get_summary = sk_dump_get_summary;
	sk_config.kcc_coredump_save_segment_descriptions = sk_dump_save_seg_desc;
	sk_config.kcc_coredump_save_segment_data = sk_dump_save_seg_data;
	sk_config.kcc_coredump_save_thread_state = sk_dump_save_thread_state;
	sk_config.kcc_coredump_save_sw_vers_detail = sk_dump_save_sw_vers_detail;
	sk_config.kcc_coredump_save_note_summary = sk_dump_save_note_summary;
	sk_config.kcc_coredump_save_note_descriptions = sk_dump_save_note_desc;
	sk_config.kcc_coredump_save_note_data = sk_dump_save_note_data;

	kr = kern_register_sk_coredump_helper(&sk_config, &sc_context);
	assert3u(kr, ==, KERN_SUCCESS);
}

#else /* EXCLAVES_COREDUMP */

bool
sk_core_enabled(void)
{
	return false;
}

void
sk_core_init(void)
{
}

uint64_t
sk_core_size(void)
{
	return 0;
}

#endif /* EXCLAVES_COREDUMP */
