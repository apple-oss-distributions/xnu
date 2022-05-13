/*
 * Copyright (c) 2015-2019 Apple Inc. All rights reserved.
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
 * The main orchestrator for kernel (and co-processor) coredumps. Here's a very simplistic view of
 * the flow:
 *
 * At kernel initialization time (kdp_core_init):
 * ----------------------------------------------
 *
 * - kdp_core_init() takes care of allocating all necessary data structures and initializes the
 *   coredump output stages
 *
 * At coredump time (do_kern_dump):
 * --------------------------------
 *
 * - Depending on the coredump variant, we chain the necessary output stages together in chain_output_stages()
 * - [Disk only] We initialize the corefile header
 * - [Disk only] We stream the stackshot out through the output stages and update the corefile header
 * - We perform the kernel coredump, streaming it out through the output stages
 * - [Disk only] We update the corefile header
 * - [Disk only] We perform the co-processor coredumps (driven by kern_do_coredump), streaming each out
 *               through the output stages and updating the corefile header.
 * - [Disk only] We save the coredump log to the corefile
 */

#ifdef CONFIG_KDP_INTERACTIVE_DEBUGGING

#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <mach/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <machine/cpu_capabilities.h>
#include <libsa/types.h>
#include <libkern/kernel_mach_header.h>
#include <kern/locks.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_core.h>
#include <kdp/output_stages/output_stages.h>
#include <kdp/processor_core.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOBSD.h>
#include <sys/errno.h>
#include <sys/msgbuf.h>
#include <san/kasan.h>
#include <kern/debug.h>
#include <pexpert/pexpert.h>

#if defined(__x86_64__)
#include <i386/pmap_internal.h>
#include <kdp/ml/i386/kdp_x86_common.h>
#include <kern/debug.h>
#endif /* defined(__x86_64__) */

kern_return_t kdp_core_polled_io_polled_file_available(IOCoreFileAccessCallback access_data, void *access_context, void *recipient_context);
kern_return_t kdp_core_polled_io_polled_file_unavailable(void);

typedef int (*pmap_traverse_callback)(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context);

extern int pmap_traverse_present_mappings(pmap_t pmap,
    vm_map_offset_t start,
    vm_map_offset_t end,
    pmap_traverse_callback callback,
    void *context);

static int kern_dump_save_summary(void *refcon, core_save_summary_cb callback, void *context);
static int kern_dump_save_seg_descriptions(void *refcon, core_save_segment_descriptions_cb callback, void *context);
static int kern_dump_save_thread_state(void *refcon, void *buf, core_save_thread_state_cb callback, void *context);
static int kern_dump_save_sw_vers_detail(void *refcon, core_save_sw_vers_detail_cb callback, void *context);
static int kern_dump_save_segment_data(void *refcon, core_save_segment_data_cb callback, void *context);

static int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context);
static int
kern_dump_pmap_traverse_send_segdesc_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context);

static int
kern_dump_pmap_traverse_send_segdata_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context);

static struct kdp_output_stage disk_output_stage = {};
static struct kdp_output_stage zlib_output_stage = {};
static struct kdp_output_stage buffer_output_stage = {};
static struct kdp_output_stage net_output_stage = {};
static struct kdp_output_stage progress_notify_output_stage = {};
#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
static struct kdp_output_stage aea_output_stage = {};
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION
#if defined(__arm__) || defined(__arm64__)
static struct kdp_output_stage shmem_output_stage = {};
#endif /* defined(__arm__) || defined(__arm64__) */
#if defined(__arm64__)
static struct kdp_output_stage memory_backing_aware_buffer_output_stage = {};
#endif /* defined(__arm64__) */

extern uint32_t kdp_crashdump_pkt_size;

static boolean_t kern_dump_successful = FALSE;

static const size_t kdp_core_header_size = sizeof(struct mach_core_fileheader_v2) + (KERN_COREDUMP_MAX_CORES * sizeof(struct mach_core_details_v2));
static struct mach_core_fileheader_v2 *kdp_core_header = NULL;

static lck_grp_t *kdp_core_initialization_lock_group = NULL;
static lck_mtx_t *kdp_core_disk_stage_lock = NULL;
static bool kdp_core_is_initializing_disk_stage = false;

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
static const size_t PUBLIC_KEY_RESERVED_LENGTH = roundup(4096, KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
static void *kdp_core_public_key = NULL;
static lck_mtx_t *kdp_core_encryption_stage_lock = NULL;
static bool kdp_core_is_initializing_encryption_stage = false;

static bool kern_dump_should_enforce_encryption(void);
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

/*
 * These variables will be modified by the BSD layer if the root device is
 * a RAMDisk.
 */
uint64_t kdp_core_ramdisk_addr = 0;
uint64_t kdp_core_ramdisk_size = 0;

#define COREDUMP_ENCRYPTION_OVERRIDES_AVAILABILITY (1 << 0)
#define COREDUMP_ENCRYPTION_OVERRIDES_ENFORCEMENT  (1 << 1)

boolean_t
kdp_has_polled_corefile(void)
{
	return NULL != gIOPolledCoreFileVars;
}

kern_return_t
kdp_polled_corefile_error(void)
{
	return gIOPolledCoreFileOpenRet;
}

kern_return_t
kdp_core_output(void *kdp_core_out_state, uint64_t length, void * data)
{
	kern_return_t              err = KERN_SUCCESS;
	uint64_t                   percent;
	struct kdp_core_out_state *vars = (struct kdp_core_out_state *)kdp_core_out_state;
	struct kdp_output_stage   *first_stage = STAILQ_FIRST(&vars->kcos_out_stage);

	if (vars->kcos_error == KERN_SUCCESS) {
		if ((err = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_DATA, NULL, length, data)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "(kdp_core_output) outproc(KDP_DATA, NULL, 0x%llx, %p) returned 0x%x\n",
			    length, data, err);
			vars->kcos_error = err;
		}
		if (!data && !length) {
			kern_coredump_log(NULL, "100..");
		} else {
			vars->kcos_bytes_written += length;
			percent = (vars->kcos_bytes_written * 100) / vars->kcos_totalbytes;
			if ((percent - vars->kcos_lastpercent) >= 10) {
				vars->kcos_lastpercent = percent;
				kern_coredump_log(NULL, "%lld..\n", percent);
			}
		}
	}
	return err;
}

#if defined(__arm__) || defined(__arm64__)
extern pmap_paddr_t avail_start, avail_end;
extern struct vm_object pmap_object_store;
#endif
extern vm_offset_t c_buffers;
extern vm_size_t   c_buffers_size;

static bool
kernel_vaddr_in_coredump_stage(const struct kdp_output_stage *stage, uint64_t vaddr, uint64_t *vincr)
{
	uint64_t start_addr = (uint64_t)stage->kos_data;
	uint64_t end_addr = start_addr + stage->kos_data_size;

	if (!stage->kos_data) {
		return false;
	}

	if (vaddr >= start_addr && vaddr < end_addr) {
		*vincr = stage->kos_data_size - (vaddr - start_addr);
		return true;
	}

	return false;
}

static bool
kernel_vaddr_in_coredump_stages(uint64_t vaddr, uint64_t *vincr)
{
	if (kernel_vaddr_in_coredump_stage(&disk_output_stage, vaddr, vincr)) {
		return true;
	}

	if (kernel_vaddr_in_coredump_stage(&zlib_output_stage, vaddr, vincr)) {
		return true;
	}

	if (kernel_vaddr_in_coredump_stage(&buffer_output_stage, vaddr, vincr)) {
		return true;
	}

	if (kernel_vaddr_in_coredump_stage(&net_output_stage, vaddr, vincr)) {
		return true;
	}

	if (kernel_vaddr_in_coredump_stage(&progress_notify_output_stage, vaddr, vincr)) {
		return true;
	}

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
	if (kernel_vaddr_in_coredump_stage(&aea_output_stage, vaddr, vincr)) {
		return true;
	}
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

#if defined(__arm__) || defined(__arm64__)
	if (kernel_vaddr_in_coredump_stage(&shmem_output_stage, vaddr, vincr)) {
		return true;
	}
#endif /* defined(__arm__) || defined(__arm64__) */

#if defined(__arm64__)
	if (kernel_vaddr_in_coredump_stage(&memory_backing_aware_buffer_output_stage, vaddr, vincr)) {
		return true;
	}
#endif /* defined(__arm64__) */

	return false;
}

ppnum_t
kernel_pmap_present_mapping(uint64_t vaddr, uint64_t * pvincr, uintptr_t * pvphysaddr)
{
	ppnum_t ppn = 0;
	uint64_t vincr = PAGE_SIZE_64;

	assert(!(vaddr & PAGE_MASK_64));

	/* VA ranges to exclude */
	if (vaddr == c_buffers) {
		/* compressor data */
		ppn = 0;
		vincr = c_buffers_size;
	} else if (kernel_vaddr_in_coredump_stages(vaddr, &vincr)) {
		/* coredump output stage working memory */
		ppn = 0;
	} else if ((kdp_core_ramdisk_addr != 0) && (vaddr == kdp_core_ramdisk_addr)) {
		ppn = 0;
		vincr = kdp_core_ramdisk_size;
	} else
#if defined(__arm__) || defined(__arm64__)
	if (vaddr == phystokv(avail_start)) {
		/* physical memory map */
		ppn = 0;
		vincr = (avail_end - avail_start);
	} else
#endif /* defined(__arm__) || defined(__arm64__) */
	{
		ppn = (pvphysaddr != NULL ?
		    pmap_find_phys(kernel_pmap, vaddr) :
		    pmap_find_phys_nofault(kernel_pmap, vaddr));
	}

	*pvincr = round_page_64(vincr);

	if (ppn && pvphysaddr) {
		uint64_t phys = ptoa_64(ppn);
		if (physmap_enclosed(phys)) {
			*pvphysaddr = phystokv(phys);
		} else {
			ppn = 0;
		}
	}

	return ppn;
}

int
pmap_traverse_present_mappings(pmap_t __unused pmap,
    vm_map_offset_t start,
    vm_map_offset_t end,
    pmap_traverse_callback callback,
    void *context)
{
	IOReturn        ret;
	vm_map_offset_t vcurstart, vcur;
	uint64_t        vincr = 0;
	vm_map_offset_t debug_start = trunc_page((vm_map_offset_t) debug_buf_base);
	vm_map_offset_t debug_end = round_page((vm_map_offset_t) (debug_buf_base + debug_buf_size));
#if defined(XNU_TARGET_OS_BRIDGE)
	vm_map_offset_t macos_panic_start = trunc_page((vm_map_offset_t) macos_panic_base);
	vm_map_offset_t macos_panic_end = round_page((vm_map_offset_t) (macos_panic_base + macos_panic_size));
#endif

	boolean_t       lastvavalid;
#if defined(__arm__) || defined(__arm64__)
	vm_page_t m = VM_PAGE_NULL;
#endif

#if defined(__x86_64__)
	assert(!is_ept_pmap(pmap));
#endif

	/* Assumes pmap is locked, or being called from the kernel debugger */

	if (start > end) {
		return KERN_INVALID_ARGUMENT;
	}

	ret = KERN_SUCCESS;
	lastvavalid = FALSE;
	for (vcur = vcurstart = start; (ret == KERN_SUCCESS) && (vcur < end);) {
		ppnum_t ppn = 0;

#if defined(__arm__) || defined(__arm64__)
		/* We're at the start of the physmap, so pull out the pagetable pages that
		 * are accessed through that region.*/
		if (vcur == phystokv(avail_start) && vm_object_lock_try_shared(&pmap_object_store)) {
			m = (vm_page_t)vm_page_queue_first(&pmap_object_store.memq);
		}

		if (m != VM_PAGE_NULL) {
			vm_map_offset_t vprev = vcur;
			ppn = (ppnum_t)atop(avail_end);
			while (!vm_page_queue_end(&pmap_object_store.memq, (vm_page_queue_entry_t)m)) {
				/* Ignore pages that come from the static region and have already been dumped.*/
				if (VM_PAGE_GET_PHYS_PAGE(m) >= atop(avail_start)) {
					ppn = VM_PAGE_GET_PHYS_PAGE(m);
					break;
				}
				m = (vm_page_t)vm_page_queue_next(&m->vmp_listq);
			}
			vincr = PAGE_SIZE_64;
			if (ppn == atop(avail_end)) {
				vm_object_unlock(&pmap_object_store);
				m = VM_PAGE_NULL;
				// avail_end is not a valid physical address,
				// so phystokv(avail_end) may not produce the expected result.
				vcur = phystokv(avail_start) + (avail_end - avail_start);
			} else {
				m = (vm_page_t)vm_page_queue_next(&m->vmp_listq);
				vcur = phystokv(ptoa(ppn));
			}
			if (vcur != vprev) {
				ret = callback(vcurstart, vprev, context);
				lastvavalid = FALSE;
			}
		}
		if (m == VM_PAGE_NULL) {
			ppn = kernel_pmap_present_mapping(vcur, &vincr, NULL);
		}
#else /* defined(__arm__) || defined(__arm64__) */
		ppn = kernel_pmap_present_mapping(vcur, &vincr, NULL);
#endif
		if (ppn != 0) {
			if (((vcur < debug_start) || (vcur >= debug_end))
			    && !(pmap_valid_page(ppn) || bootloader_valid_page(ppn))
#if defined(XNU_TARGET_OS_BRIDGE)
			    // include the macOS panic region if it's mapped
			    && ((vcur < macos_panic_start) || (vcur >= macos_panic_end))
#endif
			    ) {
				/* not something we want */
				ppn = 0;
			}
			/* include the phys carveout only if explictly marked */
			if ((debug_is_in_phys_carveout(vcur) || debug_is_in_phys_carveout_metadata(vcur)) &&
			    !debug_can_coredump_phys_carveout()) {
				ppn = 0;
			}
		}

		if (ppn != 0) {
			if (!lastvavalid) {
				/* Start of a new virtual region */
				vcurstart = vcur;
				lastvavalid = TRUE;
			}
		} else {
			if (lastvavalid) {
				/* end of a virtual region */
				ret = callback(vcurstart, vcur, context);
				lastvavalid = FALSE;
			}

#if defined(__x86_64__)
			/* Try to skip by 2MB if possible */
			if ((vcur & PDMASK) == 0) {
				pd_entry_t *pde;
				pde = pmap_pde(pmap, vcur);
				if (0 == pde || ((*pde & INTEL_PTE_VALID) == 0)) {
					/* Make sure we wouldn't overflow */
					if (vcur < (end - NBPD)) {
						vincr = NBPD;
					}
				}
			}
#endif /* defined(__x86_64__) */
		}
		vcur += vincr;
	}

	if ((ret == KERN_SUCCESS) && lastvavalid) {
		/* send previous run */
		ret = callback(vcurstart, vcur, context);
	}

#if KASAN
	if (ret == KERN_SUCCESS) {
		ret = kasan_traverse_mappings(callback, context);
	}
#endif

	return ret;
}

struct kern_dump_preflight_context {
	uint32_t region_count;
	uint64_t dumpable_bytes;
};

int
kern_dump_pmap_traverse_preflight_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context)
{
	struct kern_dump_preflight_context *kdc = (struct kern_dump_preflight_context *)context;
	IOReturn ret = KERN_SUCCESS;

	kdc->region_count++;
	kdc->dumpable_bytes += (end - start);

	return ret;
}


struct kern_dump_send_seg_desc_context {
	core_save_segment_descriptions_cb callback;
	void *context;
};

int
kern_dump_pmap_traverse_send_segdesc_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context)
{
	struct kern_dump_send_seg_desc_context *kds_context = (struct kern_dump_send_seg_desc_context *)context;
	uint64_t seg_start = (uint64_t) start;
	uint64_t seg_end = (uint64_t) end;

	return kds_context->callback(seg_start, seg_end, kds_context->context);
}

struct kern_dump_send_segdata_context {
	core_save_segment_data_cb callback;
	void *context;
};

int
kern_dump_pmap_traverse_send_segdata_callback(vm_map_offset_t start,
    vm_map_offset_t end,
    void *context)
{
	struct kern_dump_send_segdata_context *kds_context = (struct kern_dump_send_segdata_context *)context;

	return kds_context->callback((void *)start, (uint64_t)(end - start), kds_context->context);
}

static int
kern_dump_save_summary(__unused void *refcon, core_save_summary_cb callback, void *context)
{
	struct kern_dump_preflight_context kdc_preflight = { };
	uint64_t thread_state_size = 0, thread_count = 0;
	vm_map_offset_t vstart = kdp_core_start_addr();
	kern_return_t ret;

	ret = pmap_traverse_present_mappings(kernel_pmap,
	    vstart,
	    VM_MAX_KERNEL_ADDRESS,
	    kern_dump_pmap_traverse_preflight_callback,
	    &kdc_preflight);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_summary: pmap traversal failed: %d\n", ret);
		return ret;
	}

	kern_collectth_state_size(&thread_count, &thread_state_size);

	ret = callback(kdc_preflight.region_count, kdc_preflight.dumpable_bytes,
	    thread_count, thread_state_size, 0, context);
	return ret;
}

static int
kern_dump_save_seg_descriptions(__unused void *refcon, core_save_segment_descriptions_cb callback, void *context)
{
	vm_map_offset_t vstart = kdp_core_start_addr();
	kern_return_t ret;
	struct kern_dump_send_seg_desc_context kds_context;

	kds_context.callback = callback;
	kds_context.context = context;

	ret = pmap_traverse_present_mappings(kernel_pmap,
	    vstart,
	    VM_MAX_KERNEL_ADDRESS,
	    kern_dump_pmap_traverse_send_segdesc_callback,
	    &kds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_seg_desc: pmap traversal failed: %d\n", ret);
		return ret;
	}

	return KERN_SUCCESS;
}

static int
kern_dump_save_thread_state(__unused void *refcon, void *buf, core_save_thread_state_cb callback, void *context)
{
	kern_return_t ret;
	uint64_t thread_state_size = 0, thread_count = 0;

	kern_collectth_state_size(&thread_count, &thread_state_size);

	if (thread_state_size > 0) {
		void * iter = NULL;
		do {
			kern_collectth_state(current_thread(), buf, thread_state_size, &iter);

			ret = callback(buf, context);
			if (ret != KERN_SUCCESS) {
				return ret;
			}
		} while (iter);
	}

	return KERN_SUCCESS;
}


static int
kern_dump_save_sw_vers_detail(__unused void *refcon, core_save_sw_vers_detail_cb callback, void *context)
{
	return callback(vm_kernel_stext, kernel_uuid, 0, context);
}

static int
kern_dump_save_segment_data(__unused void *refcon, core_save_segment_data_cb callback, void *context)
{
	vm_map_offset_t vstart = kdp_core_start_addr();
	kern_return_t ret;
	struct kern_dump_send_segdata_context kds_context;

	kds_context.callback = callback;
	kds_context.context = context;

	ret = pmap_traverse_present_mappings(kernel_pmap,
	    vstart,
	    VM_MAX_KERNEL_ADDRESS, kern_dump_pmap_traverse_send_segdata_callback, &kds_context);
	if (ret != KERN_SUCCESS) {
		kern_coredump_log(context, "save_seg_data: pmap traversal failed: %d\n", ret);
		return ret;
	}

	return KERN_SUCCESS;
}

kern_return_t
kdp_reset_output_vars(void *kdp_core_out_state, uint64_t totalbytes, bool encrypt_core, bool *out_should_skip_coredump)
{
	struct kdp_core_out_state *outstate = (struct kdp_core_out_state *)kdp_core_out_state;
	struct kdp_output_stage *current_stage = NULL;

	/* Re-initialize kdp_outstate */
	outstate->kcos_totalbytes = totalbytes;
	outstate->kcos_bytes_written = 0;
	outstate->kcos_lastpercent = 0;
	outstate->kcos_error = KERN_SUCCESS;

	/* Reset the output stages */
	STAILQ_FOREACH(current_stage, &outstate->kcos_out_stage, kos_next) {
		current_stage->kos_funcs.kosf_reset(current_stage);
	}

	*out_should_skip_coredump = false;
	if (encrypt_core) {
		if (outstate->kcos_enforce_encryption && !outstate->kcos_encryption_stage) {
			*out_should_skip_coredump = true;
#if defined(__arm__) || defined(__arm64__)
			panic_info->eph_panic_flags |= EMBEDDED_PANIC_HEADER_FLAG_ENCRYPTED_COREDUMP_SKIPPED;
#else
			panic_info->mph_panic_flags |= MACOS_PANIC_HEADER_FLAG_ENCRYPTED_COREDUMP_SKIPPED;
#endif
			kern_coredump_log(NULL, "(kdp_reset_output_vars) Encryption requested, is unavailable, and enforcement is active. Skipping current core.\n");
		}
	} else if (outstate->kcos_encryption_stage) {
		outstate->kcos_encryption_stage->kos_bypass = true;
	}

	return KERN_SUCCESS;
}

static kern_return_t
kern_dump_update_header(struct kdp_core_out_state *outstate)
{
	struct kdp_output_stage *first_stage = STAILQ_FIRST(&outstate->kcos_out_stage);
	uint64_t foffset;
	kern_return_t ret;

	/* Write the file header -- first seek to the beginning of the file */
	foffset = 0;
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_SEEK, NULL, sizeof(foffset), &foffset)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
		    sizeof(foffset), &foffset, foffset, ret);
		return ret;
	}

	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, kdp_core_header_size, kdp_core_header)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
		    kdp_core_header_size, kdp_core_header, ret);
		return ret;
	}

	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, 0, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc data flush returned 0x%x\n", ret);
		return ret;
	}

#if defined(__arm__) || defined(__arm64__)
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_FLUSH, NULL, 0, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_update_header) outproc explicit flush returned 0x%x\n", ret);
		return ret;
	}
#endif /* defined(__arm__) || defined(__arm64__) */

	return ret;
}

kern_return_t
kern_dump_record_file(void *kdp_core_out_state, const char *filename, uint64_t file_offset, uint64_t *out_file_length)
{
	kern_return_t ret = KERN_SUCCESS;
	uint64_t bytes_written = 0;
	struct mach_core_details_v2 *core_details = NULL;
	struct kdp_output_stage *last_stage;
	struct kdp_core_out_state *outstate = (struct kdp_core_out_state *)kdp_core_out_state;

	assert(kdp_core_header->num_files < KERN_COREDUMP_MAX_CORES);
	assert(out_file_length != NULL);
	*out_file_length = 0;

	last_stage = STAILQ_LAST(&outstate->kcos_out_stage, kdp_output_stage, kos_next);
	bytes_written = last_stage->kos_bytes_written;

	core_details = &(kdp_core_header->files[kdp_core_header->num_files]);
	core_details->flags = MACH_CORE_DETAILS_V2_FLAG_COMPRESSED_ZLIB;
	if (outstate->kcos_encryption_stage && outstate->kcos_encryption_stage->kos_bypass == false) {
		core_details->flags |= MACH_CORE_DETAILS_V2_FLAG_ENCRYPTED_AEA;
	}
	core_details->offset = file_offset;
	core_details->length = bytes_written;
	strncpy((char *)&core_details->core_name, filename,
	    MACH_CORE_FILEHEADER_NAMELEN);
	core_details->core_name[MACH_CORE_FILEHEADER_NAMELEN - 1] = '\0';

	kdp_core_header->num_files++;

	ret = kern_dump_update_header(outstate);
	if (ret == KERN_SUCCESS) {
		*out_file_length = bytes_written;
	}

	return ret;
}

kern_return_t
kern_dump_seek_to_next_file(void *kdp_core_out_state, uint64_t next_file_offset)
{
	struct kdp_core_out_state *outstate = (struct kdp_core_out_state *)kdp_core_out_state;
	struct kdp_output_stage *first_stage = STAILQ_FIRST(&outstate->kcos_out_stage);
	kern_return_t ret;

	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_SEEK, NULL, sizeof(next_file_offset), &next_file_offset)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_seek_to_next_file) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
		    sizeof(next_file_offset), &next_file_offset, next_file_offset, ret);
	}

	return ret;
}

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION

static kern_return_t
kern_dump_write_public_key(struct kdp_core_out_state *outstate)
{
	struct kdp_output_stage *first_stage = STAILQ_FIRST(&outstate->kcos_out_stage);
	uint64_t foffset;
	uint64_t remainder = PUBLIC_KEY_RESERVED_LENGTH - kdp_core_header->pub_key_length;
	kern_return_t ret;

	if (kdp_core_header->pub_key_offset == 0 || kdp_core_header->pub_key_length == 0) {
		// Nothing to do
		return KERN_SUCCESS;
	}

	/* Write the public key -- first seek to the appropriate offset */
	foffset = kdp_core_header->pub_key_offset;
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_SEEK, NULL, sizeof(foffset), &foffset)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
		    sizeof(foffset), &foffset, foffset, ret);
		return ret;
	}

	// Write the public key
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, kdp_core_header->pub_key_length, kdp_core_public_key)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc(KDP_DATA, NULL, %u, %p) returned 0x%x\n",
		    kdp_core_header->pub_key_length, kdp_core_public_key, ret);
		return ret;
	}

	// Fill out the remainder of the block with zeroes
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, remainder, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc(KDP_DATA, NULL, %llu, NULL) returned 0x%x\n",
		    remainder, ret);
		return ret;
	}

	// Do it once more to write the "next" public key
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, kdp_core_header->pub_key_length, kdp_core_public_key)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc(KDP_DATA, NULL, %u, %p) returned 0x%x\n",
		    kdp_core_header->pub_key_length, kdp_core_public_key, ret);
		return ret;
	}

	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, remainder, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc(KDP_DATA, NULL, %llu, NULL) returned 0x%x\n",
		    remainder, ret);
		return ret;
	}

	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_DATA, NULL, 0, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc data flush returned 0x%x\n", ret);
		return ret;
	}

#if defined(__arm__) || defined(__arm64__)
	if ((ret = (first_stage->kos_funcs.kosf_outproc)(first_stage, KDP_FLUSH, NULL, 0, NULL)) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(kern_dump_write_public_key) outproc explicit flush returned 0x%x\n", ret);
		return ret;
	}
#endif /* defined(__arm__) || defined(__arm64__) */

	return ret;
}

#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

static kern_return_t
chain_output_stages(enum kern_dump_type kd_variant, struct kdp_core_out_state *outstate)
{
	struct kdp_output_stage *current = NULL;

	switch (kd_variant) {
	case KERN_DUMP_STACKSHOT_DISK:
		OS_FALLTHROUGH;
	case KERN_DUMP_DISK:
#if defined(__arm64__)
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &memory_backing_aware_buffer_output_stage, kos_next);
#endif
		if (!kdp_corezip_disabled) {
			STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &zlib_output_stage, kos_next);
		}
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &progress_notify_output_stage, kos_next);
#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
		if (kdp_core_is_initializing_encryption_stage) {
			kern_coredump_log(NULL, "We were in the middle of initializing encryption. Marking it as unavailable\n");
		} else if (aea_output_stage.kos_initialized) {
			STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &aea_output_stage, kos_next);
			outstate->kcos_encryption_stage = &aea_output_stage;
		}
		outstate->kcos_enforce_encryption = kern_dump_should_enforce_encryption();
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION
		if (kdp_core_is_initializing_disk_stage) {
			kern_coredump_log(NULL, "We were in the middle of initializing the disk stage. Cannot write a coredump to disk\n");
			return KERN_FAILURE;
		} else if (disk_output_stage.kos_initialized == false) {
			kern_coredump_log(NULL, "Corefile is not yet initialized. Cannot write a coredump to disk\n");
			return KERN_FAILURE;
		}
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &disk_output_stage, kos_next);
		break;
	case KERN_DUMP_NET:
		if (!kdp_corezip_disabled) {
			STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &zlib_output_stage, kos_next);
		}
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &progress_notify_output_stage, kos_next);
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &buffer_output_stage, kos_next);
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &net_output_stage, kos_next);
		break;
#if defined(__arm__) || defined(__arm64__)
	case KERN_DUMP_HW_SHMEM_DBG:
		if (!kdp_corezip_disabled) {
			STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &zlib_output_stage, kos_next);
		}
		STAILQ_INSERT_TAIL(&outstate->kcos_out_stage, &shmem_output_stage, kos_next);
		break;
#endif /* defined(__arm__) || defined(__arm64__) */
	}

	STAILQ_FOREACH(current, &outstate->kcos_out_stage, kos_next) {
		current->kos_outstate = outstate;
	}

	return KERN_SUCCESS;
}

static int
do_kern_dump(enum kern_dump_type kd_variant)
{
	struct kdp_core_out_state outstate = { };
	struct kdp_output_stage *first_stage = NULL;
	char *coredump_log_start = NULL, *buf = NULL;
	size_t reserved_debug_logsize = 0, prior_debug_logsize = 0;
	uint64_t foffset = 0;
	kern_return_t ret = KERN_SUCCESS;
	boolean_t output_opened = FALSE, dump_succeeded = TRUE;

	/* Initialize output context */

	bzero(&outstate, sizeof(outstate));
	STAILQ_INIT(&outstate.kcos_out_stage);
	ret = chain_output_stages(kd_variant, &outstate);
	if (KERN_SUCCESS != ret) {
		dump_succeeded = FALSE;
		goto exit;
	}
	first_stage = STAILQ_FIRST(&outstate.kcos_out_stage);

	/*
	 * Record the initial panic log buffer length so we can dump the coredump log
	 * and panic log to disk
	 */
	coredump_log_start = debug_buf_ptr;
#if defined(__arm__) || defined(__arm64__)
	assert(panic_info->eph_other_log_offset != 0);
	assert(panic_info->eph_panic_log_len != 0);
	/* Include any data from before the panic log as well */
	prior_debug_logsize = (panic_info->eph_panic_log_offset - sizeof(struct embedded_panic_header)) +
	    panic_info->eph_panic_log_len + panic_info->eph_other_log_len;
#else /* defined(__arm__) || defined(__arm64__) */
	if (panic_info->mph_panic_log_offset != 0) {
		prior_debug_logsize = (panic_info->mph_panic_log_offset - sizeof(struct macos_panic_header)) +
		    panic_info->mph_panic_log_len + panic_info->mph_other_log_len;
	}
#endif /* defined(__arm__) || defined(__arm64__) */

	assert(prior_debug_logsize <= debug_buf_size);

	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		/* Open the file for output */
		if ((ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_WRQ, NULL, 0, NULL)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "outproc(KDP_WRQ, NULL, 0, NULL) returned 0x%x\n", ret);
			dump_succeeded = FALSE;
			goto exit;
		}
	}
	output_opened = true;

	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		const size_t aligned_corefile_header_size = roundup(kdp_core_header_size, KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
		const size_t aligned_public_key_size = PUBLIC_KEY_RESERVED_LENGTH * 2;
#else
		const size_t aligned_public_key_size = 0;
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

		reserved_debug_logsize = prior_debug_logsize + KERN_COREDUMP_MAXDEBUGLOGSIZE;

		/* Space for file header, public key, panic log, core log */
		foffset = roundup(aligned_corefile_header_size + aligned_public_key_size + reserved_debug_logsize, KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
		kdp_core_header->log_offset = aligned_corefile_header_size + aligned_public_key_size;

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
		/* Write the public key */
		ret = kern_dump_write_public_key(&outstate);
		if (KERN_SUCCESS != ret) {
			kern_coredump_log(NULL, "(do_kern_dump write public key) returned 0x%x\n", ret);
			dump_succeeded = FALSE;
			goto exit;
		}
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

		/* Seek the calculated offset (we'll scrollback later to flush the logs and header) */
		if ((ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_SEEK, NULL, sizeof(foffset), &foffset)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "(do_kern_dump seek begin) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
			    sizeof(foffset), &foffset, foffset, ret);
			dump_succeeded = FALSE;
			goto exit;
		}
	}

#if defined(__arm__) || defined(__arm64__)
	flush_mmu_tlb();
#endif

	kern_coredump_log(NULL, "%s", (kd_variant == KERN_DUMP_DISK) ? "Writing local cores...\n" :
	    "Transmitting kernel state, please wait:\n");


#if defined(__x86_64__)
	if (((kd_variant == KERN_DUMP_STACKSHOT_DISK) || (kd_variant == KERN_DUMP_DISK)) && ((panic_stackshot_buf != 0) && (panic_stackshot_len != 0))) {
		bool should_skip = false;

		kern_coredump_log(NULL, "\nBeginning dump of kernel stackshot\n");

		ret = kdp_reset_output_vars(&outstate, panic_stackshot_len, true, &should_skip);

		if (ret != KERN_SUCCESS) {
			kern_coredump_log(NULL, "Failed to reset outstate for stackshot with len 0x%zx, returned 0x%x\n", panic_stackshot_len, ret);
			dump_succeeded = FALSE;
		} else if (!should_skip) {
			uint64_t compressed_stackshot_len = 0;
			if ((ret = kdp_core_output(&outstate, panic_stackshot_len, (void *)panic_stackshot_buf)) != KERN_SUCCESS) {
				kern_coredump_log(NULL, "Failed to write panic stackshot to file, kdp_coreoutput(outstate, %lu, %p) returned 0x%x\n",
				    panic_stackshot_len, (void *) panic_stackshot_buf, ret);
				dump_succeeded = FALSE;
			} else if ((ret = kdp_core_output(&outstate, 0, NULL)) != KERN_SUCCESS) {
				kern_coredump_log(NULL, "Failed to flush stackshot data : kdp_core_output(%p, 0, NULL) returned 0x%x\n", &outstate, ret);
				dump_succeeded = FALSE;
			} else if ((ret = kern_dump_record_file(&outstate, "panic_stackshot.kcdata", foffset, &compressed_stackshot_len)) != KERN_SUCCESS) {
				kern_coredump_log(NULL, "Failed to record panic stackshot in corefile header, kern_dump_record_file returned 0x%x\n", ret);
				dump_succeeded = FALSE;
			} else {
				kern_coredump_log(NULL, "Recorded panic stackshot in corefile at offset 0x%llx, compressed to %llu bytes\n", foffset, compressed_stackshot_len);
				foffset = roundup((foffset + compressed_stackshot_len), KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
				if ((ret = kern_dump_seek_to_next_file(&outstate, foffset)) != KERN_SUCCESS) {
					kern_coredump_log(NULL, "Failed to seek to stackshot file offset 0x%llx, kern_dump_seek_to_next_file returned 0x%x\n", foffset, ret);
					dump_succeeded = FALSE;
				}
			}
		} else {
			kern_coredump_log(NULL, "Skipping stackshot dump\n");
		}
	}
#endif

	if (kd_variant == KERN_DUMP_DISK) {
		/*
		 * Dump co-processors as well, foffset will be overwritten with the
		 * offset of the next location in the file to be written to.
		 */
		if (kern_do_coredump(&outstate, FALSE, foffset, &foffset) != 0) {
			dump_succeeded = FALSE;
		}
	} else if (kd_variant != KERN_DUMP_STACKSHOT_DISK) {
		/* Only the kernel */
		if (kern_do_coredump(&outstate, TRUE, foffset, &foffset) != 0) {
			dump_succeeded = FALSE;
		}
	}

	if (kd_variant == KERN_DUMP_DISK) {
		assert(reserved_debug_logsize != 0);
		size_t remaining_debug_logspace = reserved_debug_logsize;

		/* Write the debug log -- first seek to the end of the corefile header */
		foffset = kdp_core_header->log_offset;
		if ((ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_SEEK, NULL, sizeof(foffset), &foffset)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "(do_kern_dump seek logfile) outproc(KDP_SEEK, NULL, %lu, %p) foffset = 0x%llx returned 0x%x\n",
			    sizeof(foffset), &foffset, foffset, ret);
			dump_succeeded = FALSE;
			goto exit;
		}

		/* First flush the data from just the paniclog */
		size_t initial_log_length = 0;
#if defined(__arm__) || defined(__arm64__)
		initial_log_length = (panic_info->eph_panic_log_offset - sizeof(struct embedded_panic_header)) +
		    panic_info->eph_panic_log_len;
#else
		if (panic_info->mph_panic_log_offset != 0) {
			initial_log_length = (panic_info->mph_panic_log_offset - sizeof(struct macos_panic_header)) +
			    panic_info->mph_panic_log_len;
		}
#endif

		buf = debug_buf_base;
		if ((ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_DATA, NULL, initial_log_length, buf)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "(do_kern_dump paniclog) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
			    initial_log_length, buf, ret);
			dump_succeeded = FALSE;
			goto exit;
		}

		remaining_debug_logspace -= initial_log_length;

		/* Next include any log data from after the stackshot (the beginning of the 'other' log). */
#if defined(__arm__) || defined(__arm64__)
		buf = (char *)(((char *)panic_info) + (uintptr_t) panic_info->eph_other_log_offset);
#else
		/*
		 * There may be no paniclog if we're doing a coredump after a call to Debugger() on x86 if debugger_is_panic was
		 * configured to FALSE based on the boot-args. In that case just start from where the debug buffer was when
		 * we began taking a coredump.
		 */
		if (panic_info->mph_other_log_offset != 0) {
			buf = (char *)(((char *)panic_info) + (uintptr_t) panic_info->mph_other_log_offset);
		} else {
			buf = coredump_log_start;
		}
#endif
		assert(debug_buf_ptr >= buf);

		size_t other_log_length = debug_buf_ptr - buf;
		if (other_log_length > remaining_debug_logspace) {
			other_log_length = remaining_debug_logspace;
		}

		/* Write the coredump log */
		if ((ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_DATA, NULL, other_log_length, buf)) != KERN_SUCCESS) {
			kern_coredump_log(NULL, "(do_kern_dump coredump log) outproc(KDP_DATA, NULL, %lu, %p) returned 0x%x\n",
			    other_log_length, buf, ret);
			dump_succeeded = FALSE;
			goto exit;
		}

		kdp_core_header->log_length = initial_log_length + other_log_length;
		kern_dump_update_header(&outstate);
	}

exit:
	/* close / last packet */
	if (output_opened && (ret = first_stage->kos_funcs.kosf_outproc(first_stage, KDP_EOF, NULL, 0, ((void *) 0))) != KERN_SUCCESS) {
		kern_coredump_log(NULL, "(do_kern_dump close) outproc(KDP_EOF, NULL, 0, 0) returned 0x%x\n", ret);
		dump_succeeded = FALSE;
	}

	/* If applicable, update the panic header and flush it so we update the CRC */
#if defined(__arm__) || defined(__arm64__)
	panic_info->eph_panic_flags |= (dump_succeeded ? EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_COMPLETE :
	    EMBEDDED_PANIC_HEADER_FLAG_COREDUMP_FAILED);
	paniclog_flush();
#else
	if (panic_info->mph_panic_log_offset != 0) {
		panic_info->mph_panic_flags |= (dump_succeeded ? MACOS_PANIC_HEADER_FLAG_COREDUMP_COMPLETE :
		    MACOS_PANIC_HEADER_FLAG_COREDUMP_FAILED);
		paniclog_flush();
	}
#endif

	return dump_succeeded ? 0 : -1;
}

boolean_t
dumped_kernel_core(void)
{
	return kern_dump_successful;
}

int
kern_dump(enum kern_dump_type kd_variant)
{
	static boolean_t local_dump_in_progress = FALSE, dumped_local = FALSE;
	int ret = -1;
#if KASAN
	kasan_kdp_disable();
#endif
	if ((kd_variant == KERN_DUMP_DISK) || (kd_variant == KERN_DUMP_STACKSHOT_DISK)) {
		if (dumped_local) {
			return 0;
		}
		if (local_dump_in_progress) {
			return -1;
		}
		local_dump_in_progress = TRUE;
#if defined(__arm__) || defined(__arm64__)
		shmem_mark_as_busy();
#endif
		ret = do_kern_dump(kd_variant);
		if (ret == 0) {
			dumped_local = TRUE;
			kern_dump_successful = TRUE;
			local_dump_in_progress = FALSE;
		}

		return ret;
#if defined(__arm__) || defined(__arm64__)
	} else if (kd_variant == KERN_DUMP_HW_SHMEM_DBG) {
		ret = do_kern_dump(kd_variant);
		if (ret == 0) {
			kern_dump_successful = TRUE;
		}
		return ret;
#endif
	} else {
		ret = do_kern_dump(kd_variant);
		if (ret == 0) {
			kern_dump_successful = TRUE;
		}
		return ret;
	}
}

static kern_return_t
kdp_core_init_output_stages(void)
{
	kern_return_t ret = KERN_SUCCESS;

	// We only zero-out the disk stage. It will be initialized
	// later on when the corefile is initialized
	bzero(&disk_output_stage, sizeof(disk_output_stage));

	bzero(&zlib_output_stage, sizeof(zlib_output_stage));
	ret = zlib_stage_initialize(&zlib_output_stage);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

	bzero(&buffer_output_stage, sizeof(buffer_output_stage));
	ret = buffer_stage_initialize(&buffer_output_stage, kdp_crashdump_pkt_size);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

	bzero(&net_output_stage, sizeof(net_output_stage));
	ret = net_stage_initialize(&net_output_stage);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

	bzero(&progress_notify_output_stage, sizeof(progress_notify_output_stage));
	ret = progress_notify_stage_initialize(&progress_notify_output_stage);
	if (KERN_SUCCESS != ret) {
		return ret;
	}

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
	// We only zero-out the AEA stage. It will be initialized
	// later on, if it's supported and needed
	bzero(&aea_output_stage, sizeof(aea_output_stage));
	aea_stage_monitor_availability();
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

#if defined(__arm__) || defined(__arm64__)
	bzero(&shmem_output_stage, sizeof(shmem_output_stage));
	if (PE_consistent_debug_enabled() && PE_i_can_has_debugger(NULL)) {
		ret = shmem_stage_initialize(&shmem_output_stage);
		if (KERN_SUCCESS != ret) {
			return ret;
		}
	}
#endif /* defined(__arm__) || defined(__arm64__) */

#if defined(__arm64__)
	bzero(&memory_backing_aware_buffer_output_stage, sizeof(memory_backing_aware_buffer_output_stage));
	ret = memory_backing_aware_buffer_stage_initialize(&memory_backing_aware_buffer_output_stage);
	if (KERN_SUCCESS != ret) {
		return ret;
	}
#endif /* defined(__arm64__) */

	return ret;
}

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION

static bool
kern_dump_should_enforce_encryption(void)
{
	static int enforce_encryption = -1;

	// Only check once
	if (enforce_encryption == -1) {
		uint32_t coredump_encryption_flags = 0;

		// When set, the boot-arg is the sole decider
		if (!kernel_debugging_restricted() &&
		    PE_parse_boot_argn("coredump_encryption", &coredump_encryption_flags, sizeof(coredump_encryption_flags))) {
			enforce_encryption = (coredump_encryption_flags & COREDUMP_ENCRYPTION_OVERRIDES_ENFORCEMENT) != 0 ? 1 : 0;
		} else {
			enforce_encryption = 0;
		}
	}

	return enforce_encryption != 0;
}

static bool
kern_dump_is_encryption_available(void)
{
	// Default to feature enabled unless boot-arg says otherwise
	uint32_t coredump_encryption_flags = COREDUMP_ENCRYPTION_OVERRIDES_AVAILABILITY;

	if (!kernel_debugging_restricted()) {
		PE_parse_boot_argn("coredump_encryption", &coredump_encryption_flags, sizeof(coredump_encryption_flags));
	}

	if ((coredump_encryption_flags & COREDUMP_ENCRYPTION_OVERRIDES_AVAILABILITY) == 0) {
		return false;
	}

	return aea_stage_is_available();
}

/*
 * Initialize (or de-initialize) the encryption stage. This is done in a way such that if initializing the
 * encryption stage with a new key fails, then the existing encryption stage is left untouched. Once
 * the new stage is initialized, the old stage is uninitialized.
 *
 * This function is called whenever we have a new public key (whether from someone calling our sysctl, or because
 * we read it out of a corefile), or when encryption becomes available.
 *
 * Parameters:
 *  - public_key:      The public key to use when initializing the encryption stage. Can be NULL to indicate that
 *                     the encryption stage should be de-initialized.
 *  - public_key_size: The size of the given public key.
 */
static kern_return_t
kdp_core_init_encryption_stage(void *public_key, size_t public_key_size)
{
	kern_return_t ret = KERN_SUCCESS;
	struct kdp_output_stage new_encryption_stage = {};
	struct kdp_output_stage old_encryption_stage = {};

	lck_mtx_assert(kdp_core_encryption_stage_lock, LCK_MTX_ASSERT_OWNED);

	bzero(&new_encryption_stage, sizeof(new_encryption_stage));

	if (public_key && kern_dump_is_encryption_available()) {
		ret = aea_stage_initialize(&new_encryption_stage, public_key, public_key_size);
		if (KERN_SUCCESS != ret) {
			printf("(kdp_core_init_encryption_stage) Failed to initialize the encryption stage. Error 0x%x\n", ret);
			return ret;
		}
	}

	bcopy(&aea_output_stage, &old_encryption_stage, sizeof(aea_output_stage));

	bcopy(&new_encryption_stage, &aea_output_stage, sizeof(new_encryption_stage));

	if (old_encryption_stage.kos_initialized && old_encryption_stage.kos_funcs.kosf_free) {
		old_encryption_stage.kos_funcs.kosf_free(&old_encryption_stage);
	}

	return KERN_SUCCESS;
}

kern_return_t
kdp_core_handle_new_encryption_key(IOCoreFileAccessCallback access_data, void *access_context, void *recipient_context)
{
	kern_return_t ret = KERN_SUCCESS;
	struct kdp_core_encryption_key_descriptor *key_descriptor = (struct kdp_core_encryption_key_descriptor *) recipient_context;
	void *old_public_key = NULL;
	size_t old_public_key_size = 0;

	if (!key_descriptor) {
		return kIOReturnBadArgument;
	}

	lck_mtx_lock(kdp_core_encryption_stage_lock);
	kdp_core_is_initializing_encryption_stage = true;

	do {
		// Do the risky part first, and bail out cleanly if it fails
		ret = kdp_core_init_encryption_stage(key_descriptor->kcekd_key, key_descriptor->kcekd_size);
		if (ret != KERN_SUCCESS) {
			printf("kdp_core_handle_new_encryption_key failed to re-initialize encryption stage. Error 0x%x\n", ret);
			break;
		}

		// The rest of this function should technically never fail

		old_public_key = kdp_core_public_key;
		old_public_key_size = kdp_core_header->pub_key_length;

		kdp_core_public_key = key_descriptor->kcekd_key;
		kdp_core_header->flags &= ~MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK;
		kdp_core_header->flags &= ~MACH_CORE_FILEHEADER_V2_FLAGS_EXISTING_COREFILE_KEY_FORMAT_MASK;
		if (key_descriptor->kcekd_key) {
			kdp_core_header->flags |= key_descriptor->kcekd_format & MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK;
			kdp_core_header->flags |= MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_KEY_FORMAT_TO_KEY_FORMAT(key_descriptor->kcekd_format);
			kdp_core_header->pub_key_offset = roundup(kdp_core_header_size, KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
			kdp_core_header->pub_key_length = key_descriptor->kcekd_size;
		} else {
			kdp_core_header->pub_key_offset = 0;
			kdp_core_header->pub_key_length = 0;
		}

		/*
		 * Return the old key to the caller to free
		 */
		key_descriptor->kcekd_key = old_public_key;
		key_descriptor->kcekd_size = (uint16_t)old_public_key_size;

		// If this stuff fails, we have bigger problems
		struct mach_core_fileheader_v2 existing_header;
		bool used_existing_header = false;
		ret = access_data(access_context, FALSE, 0, sizeof(existing_header), &existing_header);
		if (ret != KERN_SUCCESS) {
			printf("kdp_core_handle_new_encryption_key failed to read the existing corefile header. Error 0x%x\n", ret);
			break;
		}

		if (existing_header.signature == MACH_CORE_FILEHEADER_V2_SIGNATURE
		    && existing_header.version == 2
		    && (existing_header.pub_key_length == 0
		    || kdp_core_header->pub_key_length == 0
		    || existing_header.pub_key_length == kdp_core_header->pub_key_length)) {
			used_existing_header = true;
			existing_header.flags &= ~MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK;

			if (kdp_core_public_key) {
				existing_header.flags |= key_descriptor->kcekd_format & MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK;

				if (existing_header.pub_key_offset == 0) {
					existing_header.pub_key_offset = kdp_core_header->pub_key_offset;
					existing_header.pub_key_length = kdp_core_header->pub_key_length;
				}
			}

			ret = access_data(access_context, TRUE, 0, sizeof(existing_header), &existing_header);
			if (ret != KERN_SUCCESS) {
				printf("kdp_core_handle_new_encryption_key failed to update the existing corefile header. Error 0x%x\n", ret);
				break;
			}
		} else {
			ret = access_data(access_context, TRUE, 0, sizeof(struct mach_core_fileheader_v2), kdp_core_header);
			if (ret != KERN_SUCCESS) {
				printf("kdp_core_handle_new_encryption_key failed to write the corefile header. Error 0x%x\n", ret);
				break;
			}
		}

		if (kdp_core_header->pub_key_length) {
			uint64_t offset = used_existing_header ? existing_header.pub_key_offset : kdp_core_header->pub_key_offset;
			ret = access_data(access_context, TRUE, offset + PUBLIC_KEY_RESERVED_LENGTH, kdp_core_header->pub_key_length, kdp_core_public_key);
			if (ret != KERN_SUCCESS) {
				printf("kdp_core_handle_new_encryption_key failed to write the next public key. Error 0x%x\n", ret);
				break;
			}

			if (!used_existing_header) {
				// Everything that happens here is optional. It's not the end of the world if this stuff fails, so we don't return
				// any errors
				// Since we're writing out a completely new header, we make sure to zero-out the region that's reserved for the public key.
				// This allows us consumers of the corefile to know for sure that this corefile is not encrypted (yet). Once we actually
				// write out a corefile, we'll overwrite this region with the key that we ended up using at the time.
				// If we fail to zero-out this region, consumers would read garbage data and properly fail to interpret it as a public key,
				// which is why it is OK for us to fail here (it's hard to interpret garbage data as a valid key, and even then, they wouldn't
				// find a matching private key anyway)
				void *empty_key = NULL;
				kern_return_t temp_ret = KERN_SUCCESS;

				empty_key = kalloc_data(PUBLIC_KEY_RESERVED_LENGTH,
				    Z_WAITOK | Z_ZERO | Z_NOFAIL);

				temp_ret = access_data(access_context, TRUE, offset, PUBLIC_KEY_RESERVED_LENGTH, empty_key);
				kfree_data(empty_key, PUBLIC_KEY_RESERVED_LENGTH);

				if (temp_ret != KERN_SUCCESS) {
					printf("kdp_core_handle_new_encryption_key failed to zero-out the public key region. Error 0x%x\n", temp_ret);
					break;
				}
			}
		}
	} while (0);

	kdp_core_is_initializing_encryption_stage = false;
	lck_mtx_unlock(kdp_core_encryption_stage_lock);

	return ret;
}

kern_return_t
kdp_core_handle_encryption_available(void)
{
	kern_return_t ret;

	lck_mtx_lock(kdp_core_encryption_stage_lock);
	kdp_core_is_initializing_encryption_stage = true;

	ret = kdp_core_init_encryption_stage(kdp_core_public_key, kdp_core_header->pub_key_length);

	kdp_core_is_initializing_encryption_stage = false;
	lck_mtx_unlock(kdp_core_encryption_stage_lock);

	return ret;
}

#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

kern_return_t
kdp_core_polled_io_polled_file_available(IOCoreFileAccessCallback access_data, void *access_context, __unused void *recipient_context)
{
	kern_return_t ret = KERN_SUCCESS;

	lck_mtx_lock(kdp_core_disk_stage_lock);
	kdp_core_is_initializing_disk_stage = true;

	ret = disk_stage_initialize(&disk_output_stage);

	kdp_core_is_initializing_disk_stage = false;
	lck_mtx_unlock(kdp_core_disk_stage_lock);

	if (KERN_SUCCESS != ret) {
		return ret;
	}

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
	// If someone has already provided a new public key,
	// there's no sense in reading the old one from the corefile.
	if (kdp_core_public_key != NULL) {
		return KERN_SUCCESS;
	}

	// The kernel corefile is now available. Let's try to retrieve the public key from its
	// header (if available and supported).

	// First let's read the corefile header itself
	struct mach_core_fileheader_v2 temp_header = {};
	ret = access_data(access_context, FALSE, 0, sizeof(temp_header), &temp_header);
	if (KERN_SUCCESS != ret) {
		printf("kdp_core_polled_io_polled_file_available failed to read corefile header. Error 0x%x\n", ret);
		return ret;
	}

	// Check if the corefile header is initialized, and whether it's initialized to values that we support
	// (for backwards and forwards) compatibility, and check whether the header indicates that the corefile has
	// has a public key stashed inside of it.
	if (temp_header.signature == MACH_CORE_FILEHEADER_V2_SIGNATURE
	    && temp_header.version == 2
	    && temp_header.pub_key_offset != 0
	    && temp_header.pub_key_length != 0
	    /* Future-proofing: make sure it's the key format that we support */
	    && (temp_header.flags & MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK) == MACH_CORE_FILEHEADER_V2_FLAG_NEXT_COREFILE_KEY_FORMAT_NIST_P256
	    /* Add some extra sanity checks. These are not necessary */
	    && temp_header.pub_key_length <= 4096
	    && temp_header.pub_key_offset < 65535) {
		// The corefile header is properly initialized, is supported, and contains a public key.
		// Let's adopt that public key for our encryption needs
		void *public_key = NULL;

		public_key = kalloc_data(temp_header.pub_key_length,
		    Z_ZERO | Z_WAITOK | Z_NOFAIL);

		// Read the public key from the corefile. Note that the key we're trying to adopt is the "next" key, which is
		// PUBLIC_KEY_RESERVED_LENGTH bytes after the public key.
		ret = access_data(access_context, FALSE, temp_header.pub_key_offset + PUBLIC_KEY_RESERVED_LENGTH, temp_header.pub_key_length, public_key);
		if (KERN_SUCCESS != ret) {
			printf("kdp_core_polled_io_polled_file_available failed to read the public key. Error 0x%x\n", ret);
			kfree_data(public_key, temp_header.pub_key_length);
			return ret;
		}

		lck_mtx_lock(kdp_core_encryption_stage_lock);
		kdp_core_is_initializing_encryption_stage = true;

		ret = kdp_core_init_encryption_stage(public_key, temp_header.pub_key_length);
		if (KERN_SUCCESS == ret) {
			kdp_core_header->flags |= temp_header.flags & MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK;
			kdp_core_header->flags |= MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_KEY_FORMAT_TO_KEY_FORMAT(temp_header.flags);
			kdp_core_header->pub_key_offset = roundup(kdp_core_header_size, KERN_COREDUMP_BEGIN_FILEBYTES_ALIGN);
			kdp_core_header->pub_key_length = temp_header.pub_key_length;
			kdp_core_public_key = public_key;
		}

		kdp_core_is_initializing_encryption_stage = false;
		lck_mtx_unlock(kdp_core_encryption_stage_lock);
	}
#else
#pragma unused(access_data, access_context)
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

	return ret;
}

kern_return_t
kdp_core_polled_io_polled_file_unavailable(void)
{
	lck_mtx_lock(kdp_core_disk_stage_lock);
	kdp_core_is_initializing_disk_stage = true;

	if (disk_output_stage.kos_initialized && disk_output_stage.kos_funcs.kosf_free) {
		disk_output_stage.kos_funcs.kosf_free(&disk_output_stage);
	}

	kdp_core_is_initializing_disk_stage = false;
	lck_mtx_unlock(kdp_core_disk_stage_lock);

	return KERN_SUCCESS;
}

void
kdp_core_init(void)
{
	kern_return_t kr;
	kern_coredump_callback_config core_config = { };

	/* Initialize output stages */
	kr = kdp_core_init_output_stages();
	assert(KERN_SUCCESS == kr);

	kmem_alloc(kernel_map, (vm_offset_t*)&kdp_core_header,
	    kdp_core_header_size,
	    KMA_NOFAIL | KMA_ZERO | KMA_PERMANENT | KMA_KOBJECT | KMA_DATA,
	    VM_KERN_MEMORY_DIAG);

	kdp_core_header->signature = MACH_CORE_FILEHEADER_V2_SIGNATURE;
	kdp_core_header->version = 2;

	kdp_core_initialization_lock_group = lck_grp_alloc_init("KDPCoreStageInit", LCK_GRP_ATTR_NULL);
	kdp_core_disk_stage_lock = lck_mtx_alloc_init(kdp_core_initialization_lock_group, LCK_ATTR_NULL);

#ifdef CONFIG_KDP_COREDUMP_ENCRYPTION
	kdp_core_encryption_stage_lock = lck_mtx_alloc_init(kdp_core_initialization_lock_group, LCK_ATTR_NULL);

	(void) kern_dump_should_enforce_encryption();
#endif // CONFIG_KDP_COREDUMP_ENCRYPTION

	core_config.kcc_coredump_init = NULL; /* TODO: consider doing mmu flush from an init function */
	core_config.kcc_coredump_get_summary = kern_dump_save_summary;
	core_config.kcc_coredump_save_segment_descriptions = kern_dump_save_seg_descriptions;
	core_config.kcc_coredump_save_thread_state = kern_dump_save_thread_state;
	core_config.kcc_coredump_save_sw_vers_detail = kern_dump_save_sw_vers_detail;
	core_config.kcc_coredump_save_segment_data = kern_dump_save_segment_data;

	kr = kern_register_xnu_coredump_helper(&core_config);
	assert(KERN_SUCCESS == kr);
}

#endif /* CONFIG_KDP_INTERACTIVE_DEBUGGING */
