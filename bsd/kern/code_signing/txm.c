/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdarg.h>
#include <stdatomic.h>
#include <os/overflow.h>
#include <machine/atomic.h>
#include <mach/vm_param.h>
#include <mach/vm_map.h>
#include <mach/shared_region.h>
#include <vm/vm_kern.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/recount.h>
#include <kern/sched_prim.h>
#include <kern/lock_rw.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/coretrust/coretrust.h>
#include <libkern/amfi/amfi.h>
#include <pexpert/pexpert.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <uuid/uuid.h>
#include <IOKit/IOBSD.h>

#if CONFIG_SPTM
/*
 * The TrustedExecutionMonitor environment works in tandem with the SPTM to provide code
 * signing and memory isolation enforcement for data structures critical to ensuring that
 * all code executed on the system is authorized to do so.
 *
 * Unless the data is managed by TXM itself, XNU needs to page-align everything, make the
 * relevant type transfer, and then reference the memory as read-only.
 *
 * TXM enforces concurrency on its side, but through the use of try-locks. Upon a failure
 * in acquiring the lock, TXM will panic. As a result, in order to ensure single-threaded
 * behavior, the kernel also has to take some locks on its side befor calling into TXM.
 */
#include <sys/trusted_execution_monitor.h>
#include <pexpert/arm64/board_config.h>

/* Lock group used for all locks within the kernel for TXM */
LCK_GRP_DECLARE(txm_lck_grp, "txm_code_signing_lck_grp");

#pragma mark Utilities

/* Number of thread stacks is known at build-time */
#define NUM_TXM_THREAD_STACKS (MAX_CPUS)
txm_thread_stack_t thread_stacks[NUM_TXM_THREAD_STACKS] = {0};

/* Singly-linked-list head for thread stacks */
SLIST_HEAD(thread_stack_head, _txm_thread_stack) thread_stacks_head =
    SLIST_HEAD_INITIALIZER(thread_stacks_head);

static decl_lck_mtx_data(, thread_stacks_lock);
static void *thread_stack_event = NULL;

static void
setup_thread_stacks(void)
{
	extern const sptm_bootstrap_args_xnu_t *SPTMArgs;
	txm_thread_stack_t *thread_stack = NULL;

	/* Initialize each thread stack and add it to the list */
	for (uint32_t i = 0; i < NUM_TXM_THREAD_STACKS; i++) {
		thread_stack = &thread_stacks[i];

		/* Acquire the thread stack virtual mapping */
		thread_stack->thread_stack_papt = SPTMArgs->txm_thread_stacks[i];

		/* Acquire the thread stack physical page */
		thread_stack->thread_stack_phys = (uintptr_t)kvtophys_nofail(
			thread_stack->thread_stack_papt);

		/* Resolve the pointer to the thread stack data */
		thread_stack->thread_stack_data =
		    (TXMThreadStack_t*)(thread_stack->thread_stack_papt + (PAGE_SIZE - 1024));

		/* Add thread stack to the list head */
		SLIST_INSERT_HEAD(&thread_stacks_head, thread_stack, link);
	}

	/* Initialize the thread stacks lock */
	lck_mtx_init(&thread_stacks_lock, &txm_lck_grp, 0);
}

static txm_thread_stack_t*
acquire_thread_stack(void)
{
	txm_thread_stack_t *thread_stack = NULL;

	/* Lock the thread stack list */
	lck_mtx_lock(&thread_stacks_lock);

	while (SLIST_EMPTY(&thread_stacks_head) == true) {
		lck_mtx_sleep(
			&thread_stacks_lock,
			LCK_SLEEP_DEFAULT,
			&thread_stack_event,
			THREAD_UNINT);
	}

	if (SLIST_EMPTY(&thread_stacks_head) == true) {
		panic("unable to acquire a thread stack for TXM");
	}

	/* Use the first available thread stack */
	thread_stack = SLIST_FIRST(&thread_stacks_head);

	/* Remove the thread stack from the list */
	SLIST_REMOVE_HEAD(&thread_stacks_head, link);

	/* Unlock the thread stack list */
	lck_mtx_unlock(&thread_stacks_lock);

	/* Associate the thread stack with the current thread */
	thread_associate_txm_thread_stack(thread_stack->thread_stack_phys);

	return thread_stack;
}

static void
release_thread_stack(
	txm_thread_stack_t* thread_stack)
{
	/* Remove the TXM thread stack association with the current thread */
	thread_disassociate_txm_thread_stack(thread_stack->thread_stack_phys);

	/* Lock the thread stack list */
	lck_mtx_lock(&thread_stacks_lock);

	/* Add the thread stack at the list head */
	SLIST_INSERT_HEAD(&thread_stacks_head, thread_stack, link);

	/* Unlock the thread stack list */
	lck_mtx_unlock(&thread_stacks_lock);

	/* Wake up any threads waiting to acquire a thread stack */
	thread_wakeup(&thread_stack_event);
}

static kern_return_t
txm_parse_return(
	TXMReturn_t txm_ret)
{
	switch (txm_ret.returnCode) {
	case kTXMSuccess:
		return KERN_SUCCESS;

	case kTXMReturnOutOfMemory:
		return KERN_RESOURCE_SHORTAGE;

	case kTXMReturnNotFound:
		return KERN_NOT_FOUND;

	default:
		return KERN_FAILURE;
	}
}

static void
txm_print_return(
	TXMKernelSelector_t selector,
	TXMReturn_t txm_ret)
{
	if (txm_ret.returnCode == kTXMSuccess) {
		return;
	} else if (txm_ret.returnCode == kTXMReturnTrustCache) {
		printf("TXM [Error]: TrustCache: selector: %u | 0x%02X | 0x%02X | %u\n",
		    selector, txm_ret.tcRet.component, txm_ret.tcRet.error, txm_ret.tcRet.uniqueError);
	} else if (txm_ret.returnCode == kTXMReturnCodeSignature) {
		printf("TXM [Error]: CodeSignature: selector: %u | 0x%02X | 0x%02X | %u\n",
		    selector, txm_ret.csRet.component, txm_ret.csRet.error, txm_ret.csRet.uniqueError);
	} else if (txm_ret.returnCode == kTXMReturnCodeErrno) {
		printf("TXM [Error]: Errno: selector: %u | %d\n",
		    selector, txm_ret.errnoRet);
	} else {
		printf("TXM [Error]: selector: %u | %u\n",
		    selector, txm_ret.returnCode);
	}
}

#pragma mark Page Allocation

static void
txm_add_page(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAddFreeListPage,
		.failure_fatal = true,
		.num_input_args = 1
	};

	/* Allocate a page from the VM -- transfers page to TXM internally */
	vm_map_address_t phys_addr = pmap_txm_allocate_page();

	/* Add this page to the TXM free list */
	txm_kernel_call(&txm_call, phys_addr);
}

#pragma mark Calls

static void
txm_kernel_call_registers_setup(
	txm_call_t *parameters,
	sptm_call_regs_t *registers,
	va_list args)
{
	/*
	 * We are only ever allowed a maximum of 7 arguments for calling into TXM.
	 * This is because the SPTM dispatch only sets up registers x0-x7 for the
	 * call, and x0 is always reserved for passing in a thread stack for TXM
	 * to operate on.
	 */

	switch (parameters->num_input_args) {
	case 7:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		registers->x3 = va_arg(args, uintptr_t);
		registers->x4 = va_arg(args, uintptr_t);
		registers->x5 = va_arg(args, uintptr_t);
		registers->x6 = va_arg(args, uintptr_t);
		registers->x7 = va_arg(args, uintptr_t);
		break;

	case 6:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		registers->x3 = va_arg(args, uintptr_t);
		registers->x4 = va_arg(args, uintptr_t);
		registers->x5 = va_arg(args, uintptr_t);
		registers->x6 = va_arg(args, uintptr_t);
		break;

	case 5:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		registers->x3 = va_arg(args, uintptr_t);
		registers->x4 = va_arg(args, uintptr_t);
		registers->x5 = va_arg(args, uintptr_t);
		break;

	case 4:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		registers->x3 = va_arg(args, uintptr_t);
		registers->x4 = va_arg(args, uintptr_t);
		break;

	case 3:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		registers->x3 = va_arg(args, uintptr_t);
		break;

	case 2:
		registers->x1 = va_arg(args, uintptr_t);
		registers->x2 = va_arg(args, uintptr_t);
		break;

	case 1:
		registers->x1 = va_arg(args, uintptr_t);
		break;

	case 0:
		break;

	default:
		panic("invalid number of arguments to TXM: selector: %u | %u",
		    parameters->selector, parameters->num_input_args);
	}
}

static TXMReturn_t
txm_kernel_call_internal(
	txm_call_t *parameters,
	va_list args)
{
	TXMReturn_t txm_ret = (TXMReturn_t){.returnCode = kTXMReturnGeneric};
	sptm_call_regs_t txm_registers = {0};
	txm_thread_stack_t *thread_stack = NULL;
	const TXMThreadStack_t *thread_stack_data = NULL;
	const TXMSharedContextData_t *shared_context_data = NULL;

	/* Obtain a stack for this call */
	thread_stack = acquire_thread_stack();
	thread_stack_data = thread_stack->thread_stack_data;
	shared_context_data = &thread_stack_data->sharedData;

	/* Setup argument registers */
	txm_registers.x0 = thread_stack->thread_stack_phys;
	txm_kernel_call_registers_setup(parameters, &txm_registers, args);

	/* Track resource usage */
	recount_enter_secure();

	/* Call into TXM */
	txm_enter(parameters->selector, &txm_registers);

	recount_leave_secure();

	txm_ret = (TXMReturn_t){.rawValue = shared_context_data->txmReturnCode};
	parameters->txm_ret = txm_ret;

	if (parameters->txm_ret.returnCode == kTXMSuccess) {
		parameters->num_return_words = shared_context_data->txmNumReturnWords;
		if (parameters->num_return_words > kTXMStackReturnWords) {
			panic("received excessive return words from TXM: selector: %u | %llu",
			    parameters->selector, parameters->num_return_words);
		}

		for (uint64_t i = 0; i < parameters->num_return_words; i++) {
			parameters->return_words[i] = shared_context_data->txmReturnWords[i];
		}
	}

	/* Release the thread stack as it is no longer needed */
	release_thread_stack(thread_stack);
	thread_stack_data = NULL;
	shared_context_data = NULL;

	return txm_ret;
}

kern_return_t
txm_kernel_call(
	txm_call_t *parameters, ...)
{
	TXMReturn_t txm_ret = (TXMReturn_t){.returnCode = kTXMReturnGeneric};
	kern_return_t ret = KERN_DENIED;
	va_list args;

	/* Start the variadic arguments list */
	va_start(args, parameters);

	do {
		txm_ret = txm_kernel_call_internal(parameters, args);
		if (txm_ret.returnCode == kTXMReturnOutOfMemory) {
			if (parameters->selector == kTXMKernelSelectorAddFreeListPage) {
				panic("received out-of-memory error when adding a free page to TXM");
			}
			txm_add_page();
		}
	} while (txm_ret.returnCode == kTXMReturnOutOfMemory);

	/* Clean up the variadic arguments list */
	va_end(args);

	/* Print all TXM logs from the log buffer */
	if (parameters->skip_logs == false) {
		txm_print_logs();
	}

	/* Print the return code from TXM -- only prints for an error */
	if (parameters->failure_silent != true) {
		if (parameters->failure_code_silent != txm_ret.returnCode) {
			txm_print_return(parameters->selector, txm_ret);
		}
	}

	/*
	 * To ease the process of calling into TXM, and to also reduce the number of
	 * lines of code for each call site, the txm_call_t offers some properties
	 * we can enforce over here. Go through these, and panic in case they aren't
	 * honored.
	 *
	 * NOTE: We check for "<" instead of "!=" for the number of return words we
	 * get back from TXM since this helps in forward development. If the kernel
	 * and TXM are proceeding at different project cadences, we do not want to
	 * gate adding more return words from TXM on the kernel first adopting the
	 * new number of return words.
	 */
	ret = txm_parse_return(txm_ret);

	if (parameters->failure_fatal && (ret != KERN_SUCCESS)) {
		panic("received fatal error for a selector from TXM: selector: %u | 0x%0llX",
		    parameters->selector, txm_ret.rawValue);
	} else if (parameters->num_return_words < parameters->num_output_args) {
		/* Only panic if return was a success */
		if (ret == KERN_SUCCESS) {
			panic("received fewer than expected return words from TXM: selector: %u | %llu",
			    parameters->selector, parameters->num_return_words);
		}
	}

	return ret;
}

void
txm_transfer_region(
	vm_address_t addr,
	vm_size_t size)
{
	vm_address_t addr_end = 0;
	vm_size_t size_aligned = round_page(size);

	if ((addr & PAGE_MASK) != 0) {
		panic("attempted to transfer non-page-aligned memory to TXM: %p", (void*)addr);
	} else if (os_add_overflow(addr, size_aligned, &addr_end)) {
		panic("overflow on range to be transferred to TXM: %p | %lu",
		    (void*)addr, size);
	}

	/* Make the memory read-only first (transfer will panic otherwise) */
	vm_protect(kernel_map, addr, size_aligned, false, VM_PROT_READ);

	/* Transfer each physical page to be TXM_DEFAULT */
	for (vm_address_t page = addr; page < addr_end; page += PAGE_SIZE) {
		pmap_txm_transfer_page(page);
	}
}

void
txm_reclaim_region(
	vm_address_t addr,
	vm_size_t size)
{
	vm_address_t addr_end = 0;
	vm_size_t size_aligned = round_page(size);

	if ((addr & PAGE_MASK) != 0) {
		panic("attempted to reclaim non-page-aligned memory from TXM: %p", (void*)addr);
	} else if (os_add_overflow(addr, size_aligned, &addr_end)) {
		panic("overflow on range to be reclaimed from TXM: %p | %lu",
		    (void*)addr, size);
	}

	/*
	 * We can only reclaim once TXM has transferred the memory range back to the
	 * kernel. Hence, we simply try and switch permissions to read-write. If TXM
	 * hasn't transferred pages, this then should panic.
	 */
	vm_protect(kernel_map, addr, size_aligned, false, VM_PROT_READ | VM_PROT_WRITE);
}

static SECURITY_READ_ONLY_LATE(const char*) txm_log_page = NULL;
static SECURITY_READ_ONLY_LATE(const uint32_t*) txm_log_head = NULL;
static SECURITY_READ_ONLY_LATE(const uint32_t*) txm_log_sync = NULL;

static decl_lck_mtx_data(, log_lock);
static uint32_t log_head = 0;

void
txm_print_logs(void)
{
	uint32_t start_index = 0;
	uint32_t end_index = 0;

	/*
	 * The design here is very simple. TXM keeps adding slots to its circular buffer
	 * and the kernel attempts to read each one and print it, maintaining its own head
	 * for the log.
	 *
	 * This design is by nature lazy. TXM doesn't know or care if the kernel has gone
	 * through and printed any of the logs, so it'll just keep writing into its buffer
	 * and then circle around when it becomes full.
	 *
	 * This is fine most of the time since there are a decent amount of slots in the
	 * log buffer. We mostly have an issue when TXM is adding so many logs so quickly
	 * such that it wraps around and starts overwriting logs which haven't been seen
	 * by the kernel. If this were to happen, TXM's log head may circle around the
	 * head maintained by the kernel, causing a lot of logs to be missed, since the
	 * kernel only attempts the number of logs in-between the two heads.
	 *
	 * The fix for that is complicated, and until we see an actual impact, we're going
	 * to keep the simpler design in place.
	 */

	/* Return if the logging hasn't been setup yet */
	if (txm_log_sync == NULL) {
		return;
	}

	/*
	 * Holding the log lock and printing can cause lots of issues since printing can
	 * be rather slow. While we make it a point to keep the logging buffer quiet, some
	 * actions (such as loading trust caches) are still very chatty.
	 *
	 * As a result, we optimize this routine to ensure that the lock itself isn't held
	 * for very long. All we need to do within the critical section is calculate the
	 * starting and ending index of the log buffer. The actual printing doesn't need
	 * to be done with the lock held.
	 */
	lck_mtx_lock(&log_lock);

	start_index = log_head;
	end_index = os_atomic_load(txm_log_head, relaxed) % kTXMLogSlots;

	/* Update the log head with the new index */
	log_head = end_index;

	/* Release the log lock */
	lck_mtx_unlock(&log_lock);

	if (start_index != end_index) {
		/* Use load acquire here to sync up with all writes to the buffer */
		os_atomic_load(txm_log_sync, acquire);

		while (start_index != end_index) {
			const char *slot = txm_log_page + (start_index * kTXMLogSlotSize);

			/* We add newlines after each log statement since TXM does not */
			printf("%s\n", slot);

			start_index = (start_index + 1) % kTXMLogSlots;
		}
	}
}

#pragma mark Initialization

SECURITY_READ_ONLY_LATE(const TXMReadOnlyData_t*) txm_ro_data = NULL;
SECURITY_READ_ONLY_LATE(const TXMStatistics_t*) txm_stats = NULL;
SECURITY_READ_ONLY_LATE(const CSConfig_t*) txm_cs_config = NULL;

SECURITY_READ_ONLY_LATE(bool*) developer_mode_enabled = NULL;
static SECURITY_READ_ONLY_LATE(bool) code_signing_enabled = true;
static SECURITY_READ_ONLY_LATE(uint32_t) managed_signature_size = 0;

static decl_lck_mtx_data(, compilation_service_lock);
static decl_lck_mtx_data(, unregister_sync_lock);

static void
get_logging_info(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorGetLogInfo,
		.failure_fatal = true,
		.num_output_args = 3
	};
	txm_kernel_call(&txm_call);

	txm_log_page = (const char*)txm_call.return_words[0];
	txm_log_head = (const uint32_t*)txm_call.return_words[1];
	txm_log_sync = (const uint32_t*)txm_call.return_words[2];
}

static void
get_code_signing_info(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorGetCodeSigningInfo,
		.failure_fatal = true,
		.num_output_args = 6
	};
	txm_kernel_call(&txm_call);

	/*
	 * Not using txm_call.return_words[0] for now. This was previously the
	 * code_signing_enabled field, but we've since switched to acquiring that
	 * value from TXM's read-only data.
	 *
	 * Not using txm_call.return_words[4] for now. This was previously the
	 * txm_cs_config field, but we've since switched to acquiring that value
	 * from TXM's read-only data.
	 */

	developer_mode_enabled = (bool*)txm_call.return_words[1];
	txm_stats = (TXMStatistics_t*)txm_call.return_words[2];
	managed_signature_size = (uint32_t)txm_call.return_words[3];
	txm_ro_data = (TXMReadOnlyData_t*)txm_call.return_words[5];

	/* Set code_signing_disabled based on read-only data */
	code_signing_enabled = txm_ro_data->codeSigningDisabled == false;

	/* Set txm_cs_config based on read-only data */
	txm_cs_config = &txm_ro_data->CSConfiguration;
}

static void
set_shared_region_base_address(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorSetSharedRegionBaseAddress,
		.failure_fatal = true,
		.num_input_args = 2,
	};

	txm_kernel_call(&txm_call,
	    SHARED_REGION_BASE,
	    SHARED_REGION_SIZE);
}

void
code_signing_init(void)
{
	/* Setup the thread stacks used by TXM */
	setup_thread_stacks();

	/* Setup the logging lock */
	lck_mtx_init(&log_lock, &txm_lck_grp, 0);

	/* Setup TXM logging information */
	get_logging_info();

	/* Setup code signing configuration */
	get_code_signing_info();

	/* Setup all the other locks we need */
	lck_mtx_init(&compilation_service_lock, &txm_lck_grp, 0);
	lck_mtx_init(&unregister_sync_lock, &txm_lck_grp, 0);

	/*
	 * We need to let TXM know what the shared region base address is going
	 * to be for this boot.
	 */
	set_shared_region_base_address();

	/* Require signed code when monitor is enabled */
	if (code_signing_enabled == true) {
		cs_debug_fail_on_unsigned_code = 1;
	}
}

void
txm_enter_lockdown_mode(void)
{
#if kTXMKernelAPIVersion >= 3
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorEnterLockdownMode,
		.failure_fatal = true,
	};

	txm_kernel_call(&txm_call);
#endif
}

#pragma mark Developer Mode

void
txm_toggle_developer_mode(bool state)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorDeveloperModeToggle,
		.failure_fatal = true,
		.num_input_args = 1
	};

	txm_kernel_call(&txm_call, state);
}

#pragma mark Code Signing and Provisioning Profiles

bool
txm_code_signing_enabled(void)
{
	return code_signing_enabled;
}

vm_size_t
txm_managed_code_signature_size(void)
{
	return managed_signature_size;
}

kern_return_t
txm_register_provisioning_profile(
	const void *profile_blob,
	const size_t profile_blob_size,
	void **profile_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorRegisterProvisioningProfile,
		.num_input_args = 2,
		.num_output_args = 1
	};
	vm_address_t payload_addr = 0;
	kern_return_t ret = KERN_DENIED;

	/* We need to allocate page-wise in order to transfer the range to TXM */
	ret = kmem_alloc(kernel_map, &payload_addr, profile_blob_size,
	    KMA_KOBJECT | KMA_DATA, VM_KERN_MEMORY_SECURITY);
	if (ret != KERN_SUCCESS) {
		printf("unable to allocate memory for profile payload: %d\n", ret);
		goto exit;
	}

	/* Copy the contents into the allocation */
	memcpy((void*)payload_addr, profile_blob, profile_blob_size);

	/* Transfer the memory range to TXM */
	txm_transfer_region(payload_addr, profile_blob_size);

	ret = txm_kernel_call(&txm_call, payload_addr, profile_blob_size);
	if (ret == KERN_SUCCESS) {
		*profile_obj = (void*)txm_call.return_words[0];
	}

exit:
	if ((ret != KERN_SUCCESS) && (payload_addr != 0)) {
		/* Reclaim this memory range */
		txm_reclaim_region(payload_addr, profile_blob_size);

		/* Free the memory range */
		kmem_free(kernel_map, payload_addr, profile_blob_size);
		payload_addr = 0;
	}

	return ret;
}

kern_return_t
txm_unregister_provisioning_profile(
	void *profile_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorUnregisterProvisioningProfile,
		.num_input_args = 1,
		.num_output_args = 2
	};
	vm_address_t profile_addr = 0;
	vm_size_t profile_size = 0;
	kern_return_t ret = KERN_DENIED;

	ret = txm_kernel_call(&txm_call, profile_obj);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	profile_addr = txm_call.return_words[0];
	profile_size = txm_call.return_words[1];

	/* Reclaim this memory range */
	txm_reclaim_region(profile_addr, profile_size);

	/* Free the memory range */
	kmem_free(kernel_map, profile_addr, profile_size);

	return KERN_SUCCESS;
}

kern_return_t
txm_associate_provisioning_profile(
	void *sig_obj,
	void *profile_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAssociateProvisioningProfile,
		.num_input_args = 2,
	};

	return txm_kernel_call(&txm_call, sig_obj, profile_obj);
}

kern_return_t
txm_disassociate_provisioning_profile(
	void *sig_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorDisassociateProvisioningProfile,
		.num_input_args = 1,
	};

	/*
	 * Take the unregistration sync lock.
	 * For more information: rdar://99205627.
	 */
	lck_mtx_lock(&unregister_sync_lock);

	/* Disassociate the profile from the signature */
	kern_return_t ret = txm_kernel_call(&txm_call, sig_obj);

	/* Release the unregistration sync lock */
	lck_mtx_unlock(&unregister_sync_lock);

	return ret;
}

void
txm_set_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAuthorizeCompilationServiceCDHash,
		.num_input_args = 1,
	};

	lck_mtx_lock(&compilation_service_lock);
	txm_kernel_call(&txm_call, cdhash);
	lck_mtx_unlock(&compilation_service_lock);
}

bool
txm_match_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorMatchCompilationServiceCDHash,
		.failure_silent = true,
		.num_input_args = 1,
		.num_output_args = 1,
	};
	kern_return_t ret = KERN_DENIED;

	/* Be safe and take the lock (avoid thread collisions) */
	lck_mtx_lock(&compilation_service_lock);
	ret = txm_kernel_call(&txm_call, cdhash);
	lck_mtx_unlock(&compilation_service_lock);

	if (ret == KERN_SUCCESS) {
		return true;
	}
	return false;
}

void
txm_set_local_signing_public_key(
	const uint8_t public_key[XNU_LOCAL_SIGNING_KEY_SIZE])
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorSetLocalSigningPublicKey,
		.num_input_args = 1,
	};

	txm_kernel_call(&txm_call, public_key);
}

uint8_t*
txm_get_local_signing_public_key(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorGetLocalSigningPublicKey,
		.num_output_args = 1,
	};
	kern_return_t ret = KERN_DENIED;

	ret = txm_kernel_call(&txm_call);
	if (ret != KERN_SUCCESS) {
		return NULL;
	}

	return (uint8_t*)txm_call.return_words[0];
}

void
txm_unrestrict_local_signing_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAuthorizeLocalSigningCDHash,
		.num_input_args = 1,
	};

	txm_kernel_call(&txm_call, cdhash);
}

kern_return_t
txm_register_code_signature(
	const vm_address_t signature_addr,
	const vm_size_t signature_size,
	const vm_offset_t code_directory_offset,
	const char *signature_path,
	void **sig_obj,
	vm_address_t *txm_signature_addr)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorRegisterCodeSignature,
		.num_input_args = 3,
		.num_output_args = 2,
	};
	kern_return_t ret = KERN_DENIED;

	/*
	 * TXM performs more exhaustive validation of the code signature and figures
	 * out the best code directory to use on its own. As a result, this offset here
	 * is not used.
	 */
	(void)code_directory_offset;

	/*
	 * If the signature is large enough to not fit within TXM's managed signature
	 * size, then we need to transfer it over so it is owned by TXM.
	 */
	if (signature_size > txm_managed_code_signature_size()) {
		txm_transfer_region(signature_addr, signature_size);
	}

	ret = txm_kernel_call(
		&txm_call,
		signature_addr,
		signature_size,
		signature_path);

	if (ret != KERN_SUCCESS) {
		goto exit;
	}

	*sig_obj = (void*)txm_call.return_words[0];
	*txm_signature_addr = txm_call.return_words[1];

exit:
	if ((ret != KERN_SUCCESS) && (signature_size > txm_managed_code_signature_size())) {
		txm_reclaim_region(signature_addr, signature_size);
	}

	return ret;
}

kern_return_t
txm_unregister_code_signature(
	void *sig_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorUnregisterCodeSignature,
		.failure_fatal = true,
		.num_input_args = 1,
		.num_output_args = 2,
	};
	TXMCodeSignature_t *cs_obj = sig_obj;
	vm_address_t signature_addr = 0;
	vm_size_t signature_size = 0;
	bool txm_managed = false;

	/* Check if the signature memory is TXM managed */
	txm_managed = cs_obj->sptmType != TXM_BULK_DATA;

	/*
	 * Take the unregistration sync lock.
	 * For more information: rdar://99205627.
	 */
	lck_mtx_lock(&unregister_sync_lock);

	/* Unregister the signature from TXM -- cannot fail */
	txm_kernel_call(&txm_call, sig_obj);

	/* Release the unregistration sync lock */
	lck_mtx_unlock(&unregister_sync_lock);

	signature_addr = txm_call.return_words[0];
	signature_size = txm_call.return_words[1];

	/* Reclaim the memory range in case we need to */
	if (txm_managed == false) {
		txm_reclaim_region(signature_addr, signature_size);
	}

	return KERN_SUCCESS;
}

kern_return_t
txm_verify_code_signature(
	void *sig_obj)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorValidateCodeSignature,
		.num_input_args = 1,
	};
	kern_return_t ret = KERN_DENIED;

	/*
	 * Verification of the code signature may perform a trust cache look up.
	 * In order to avoid any collisions with threads which may be loading a
	 * trust cache, we take a reader lock on the trust cache runtime.
	 */

	lck_rw_lock_shared(&txm_trust_cache_lck);
	ret = txm_kernel_call(&txm_call, sig_obj);
	lck_rw_unlock_shared(&txm_trust_cache_lck);

	return ret;
}

kern_return_t
txm_reconstitute_code_signature(
	void *sig_obj,
	vm_address_t *unneeded_addr,
	vm_size_t *unneeded_size)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorReconstituteCodeSignature,
		.failure_fatal = true,
		.num_input_args = 1,
		.num_output_args = 2,
	};
	vm_address_t return_addr = 0;
	vm_size_t return_size = 0;

	/* Reconstitute the code signature -- cannot fail */
	txm_kernel_call(&txm_call, sig_obj);

	return_addr = txm_call.return_words[0];
	return_size = txm_call.return_words[1];

	/* Reclaim the memory region if we need to */
	if ((return_addr != 0) && (return_size != 0)) {
		txm_reclaim_region(return_addr, return_size);
	}

	*unneeded_addr = return_addr;
	*unneeded_size = return_size;

	return KERN_SUCCESS;
}

#pragma mark Address Spaces

kern_return_t
txm_register_address_space(
	pmap_t pmap,
	uint16_t addr_space_id,
	TXMAddressSpaceFlags_t flags)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorRegisterAddressSpace,
		.failure_fatal = true,
		.num_input_args = 2,
		.num_output_args = 1,
	};
	TXMAddressSpace_t *txm_addr_space = NULL;

	/* Register the address space -- cannot fail */
	txm_kernel_call(&txm_call, addr_space_id, flags);

	/* Set the address space object within the PMAP */
	txm_addr_space = (TXMAddressSpace_t*)txm_call.return_words[0];
	pmap_txm_set_addr_space(pmap, txm_addr_space);

	return KERN_SUCCESS;
}

kern_return_t
txm_unregister_address_space(
	pmap_t pmap)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorUnregisterAddressSpace,
		.failure_fatal = true,
		.num_input_args = 1,
	};
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);

	/*
	 * Take the unregistration sync lock.
	 * For more information: rdar://99205627.
	 */
	lck_mtx_lock(&unregister_sync_lock);

	/* Unregister the address space -- cannot fail */
	txm_kernel_call(&txm_call, txm_addr_space);

	/* Release the unregistration sync lock */
	lck_mtx_unlock(&unregister_sync_lock);

	/* Remove the address space from the pmap */
	pmap_txm_set_addr_space(pmap, NULL);

	return KERN_SUCCESS;
}

kern_return_t
txm_associate_code_signature(
	pmap_t pmap,
	void *sig_obj,
	const vm_address_t region_addr,
	const vm_size_t region_size,
	const vm_offset_t region_offset)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAssociateCodeSignature,
		.num_input_args = 5,
	};
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);
	kern_return_t ret = KERN_DENIED;

	/*
	 * Associating a code signature may require exclusive access to the TXM address
	 * space lock within TXM.
	 */
	pmap_txm_acquire_exclusive_lock(pmap);

	/*
	 * If the address space in question is a nested address space, then all associations
	 * need to go into the shared region base range. The VM layer is inconsistent with
	 * how it makes associations with TXM vs. how it maps pages into the shared region.
	 *
	 * For TXM, the associations are made without taking the base range into account,
	 * but when mappings are entered into the shared region, the base range is taken
	 * into account. To normalize this, we add the base range address here.
	 */
	vm_address_t adjusted_region_addr = region_addr;
	if (txm_addr_space->addrSpaceID.type == kTXMAddressSpaceIDTypeSharedRegion) {
		adjusted_region_addr += SHARED_REGION_BASE;
	}

	/*
	 * The VM tries a bunch of weird mappings within launchd for some platform code
	 * which isn't mapped contiguously. These mappings don't succeed, but the failure
	 * is fairly harmless since everything seems to work. However, since the call to
	 * TXM fails, we make a series of logs. Hence, for launchd, we suppress failure
	 * logs.
	 */
	if (txm_addr_space->addrSpaceID.type == kTXMAddressSpaceIDTypeAddressSpace) {
		/* TXMTODO: Scope this to launchd better */
		txm_call.failure_code_silent = kTXMReturnPlatformCodeMapping;
	}

	/* Check if the main region has been set on the address space */
	bool main_region_set = txm_addr_space->mainRegion != NULL;
	bool main_region_set_after = false;

	ret = txm_kernel_call(
		&txm_call,
		txm_addr_space,
		sig_obj,
		adjusted_region_addr,
		region_size,
		region_offset);

	/*
	 * If the main region wasn't set on the address space before hand, but this new
	 * call into TXM was successful and sets the main region, it means this signature
	 * object is associated with the main region on the address space. With this, we
	 * can now set the appropriate trust level on the PMAP.
	 */
	if (ret == KERN_SUCCESS) {
		main_region_set_after = txm_addr_space->mainRegion != NULL;
	}

	/* Unlock the TXM address space lock */
	pmap_txm_release_exclusive_lock(pmap);

	/* Check if we should set the trust level on the PMAP */
	if (!main_region_set && main_region_set_after) {
		const TXMCodeSignature_t *cs_obj = sig_obj;
		const SignatureValidation_t *sig = &cs_obj->sig;

		/*
		 * This is gross, as we're dereferencing into a private data structure type.
		 * There are 2 ways to clean this up in the future:
		 * 1. Import libCodeSignature, so we can use "codeSignatureGetTrustLevel".
		 * 2. Cache the trust level on the address space within TXM and then use it.
		 */
		pmap_txm_set_trust_level(pmap, sig->trustLevel);
	}

	return ret;
}

kern_return_t
txm_allow_jit_region(
	pmap_t pmap)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAllowJITRegion,
		.num_input_args = 1,
	};
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);
	kern_return_t ret = KERN_DENIED;

	pmap_txm_acquire_shared_lock(pmap);
	ret = txm_kernel_call(&txm_call, txm_addr_space);
	pmap_txm_release_shared_lock(pmap);

	return ret;
}

kern_return_t
txm_associate_jit_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAssociateJITRegion,
		.num_input_args = 3,
	};
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);
	kern_return_t ret = KERN_DENIED;

	/*
	 * Associating a JIT region may require exclusive access to the TXM address
	 * space lock within TXM.
	 */
	pmap_txm_acquire_exclusive_lock(pmap);

	ret = txm_kernel_call(
		&txm_call,
		txm_addr_space,
		region_addr,
		region_size);

	/* Unlock the TXM address space lock */
	pmap_txm_release_exclusive_lock(pmap);

	return ret;
}

kern_return_t
txm_address_space_debugged(
	pmap_t pmap)
{
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);
	bool debug_regions_allowed = false;

	/*
	 * We do not actually need to trap into the monitor for this function for
	 * now. It might be a tad bit more secure to actually trap into the monitor
	 * as it implicitly verifies all of our pointers, but since this is a simple
	 * state check against the address space, the real policy around it lies
	 * within the kernel still, in which case entering the monitor doesn't
	 * really provide much more security.
	 */

	pmap_txm_acquire_shared_lock(pmap);
	debug_regions_allowed = os_atomic_load(&txm_addr_space->allowsInvalidCode, relaxed);
	pmap_txm_release_shared_lock(pmap);

	if (debug_regions_allowed == true) {
		return KERN_SUCCESS;
	}
	return KERN_DENIED;
}

kern_return_t
txm_associate_debug_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	/*
	 * This function is an interesting one. There is no need for us to make
	 * a call into TXM for this one and instead, all we need to do here is
	 * to verify that the TXM address space actually allows debug regions to
	 * be mapped in or not.
	 */
	(void)region_addr;
	(void)region_size;

	kern_return_t ret = txm_address_space_debugged(pmap);
	if (ret != KERN_SUCCESS) {
		printf("address space does not allow creating debug regions\n");
	}

	return ret;
}

kern_return_t
txm_allow_invalid_code(
	pmap_t pmap)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAllowInvalidCode,
		.num_input_args = 1,
	};
	TXMAddressSpace_t *txm_addr_space = pmap_txm_addr_space(pmap);
	kern_return_t ret = KERN_DENIED;

	/*
	 * Allowing invalid code may require exclusive access to the TXM address
	 * space lock within TXM.
	 */

	pmap_txm_acquire_exclusive_lock(pmap);
	ret = txm_kernel_call(&txm_call, txm_addr_space);
	pmap_txm_release_exclusive_lock(pmap);

	return ret;
}

kern_return_t
txm_get_trust_level_kdp(
	pmap_t pmap,
	uint32_t *trust_level)
{
	CSTrust_t txm_trust_level = kCSTrustUntrusted;

	kern_return_t ret = pmap_txm_get_trust_level_kdp(pmap, &txm_trust_level);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	if (trust_level != NULL) {
		*trust_level = txm_trust_level;
	}
	return KERN_SUCCESS;
}

kern_return_t
txm_address_space_exempt(
	const pmap_t pmap)
{
	if (pmap_performs_stage2_translations(pmap) == true) {
		return KERN_SUCCESS;
	}

	return KERN_DENIED;
}

kern_return_t
txm_fork_prepare(
	pmap_t old_pmap,
	pmap_t new_pmap)
{
	/*
	 * We'll add support for this as the need for it becomes more important.
	 * TXMTODO: Complete this implementation.
	 */
	(void)old_pmap;
	(void)new_pmap;

	return KERN_SUCCESS;
}

kern_return_t
txm_acquire_signing_identifier(
	const void *sig_obj,
	const char **signing_id)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAcquireSigningIdentifier,
		.num_input_args = 1,
		.num_output_args = 1,
		.failure_fatal = true,
	};

	/* Get the signing ID -- should not fail */
	txm_kernel_call(&txm_call, sig_obj);

	if (signing_id != NULL) {
		*signing_id = (const char*)txm_call.return_words[0];
	}
	return KERN_SUCCESS;
}

#pragma mark Entitlements

kern_return_t
txm_associate_kernel_entitlements(
	void *sig_obj,
	const void *kernel_entitlements)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAssociateKernelEntitlements,
		.num_input_args = 2,
		.failure_fatal = true,
	};

	/* Associate the kernel entitlements -- should not fail */
	txm_kernel_call(&txm_call, sig_obj, kernel_entitlements);

	return KERN_SUCCESS;
}

kern_return_t
txm_resolve_kernel_entitlements(
	pmap_t pmap,
	const void **kernel_entitlements)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorResolveKernelEntitlementsAddressSpace,
		.skip_logs = true,
		.num_input_args = 1,
		.num_output_args = 1,
		.failure_silent = true,
	};
	TXMAddressSpace_t *txm_addr_space = NULL;
	kern_return_t ret = KERN_DENIED;

	if (pmap == pmap_txm_kernel_pmap()) {
		return KERN_NOT_FOUND;
	}
	txm_addr_space = pmap_txm_addr_space(pmap);

	pmap_txm_acquire_shared_lock(pmap);
	ret = txm_kernel_call(&txm_call, txm_addr_space);
	pmap_txm_release_shared_lock(pmap);

	if ((ret == KERN_SUCCESS) && (kernel_entitlements != NULL)) {
		*kernel_entitlements = (const void*)txm_call.return_words[0];
	}
	return ret;
}

kern_return_t
txm_accelerate_entitlements(
	void *sig_obj,
	CEQueryContext_t *ce_ctx)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorAccelerateEntitlements,
		.num_input_args = 1,
		.num_output_args = 1,
	};
	kern_return_t ret = KERN_DENIED;

	ret = txm_kernel_call(&txm_call, sig_obj);
	if ((ret == KERN_SUCCESS) && (ce_ctx != NULL)) {
		*ce_ctx = (CEQueryContext_t)txm_call.return_words[0];
	}

	return ret;
}

#pragma mark Image4

void*
txm_image4_storage_data(
	__unused size_t *allocated_size)
{
	/*
	 * AppleImage4 builds a variant of TXM which TXM should link against statically
	 * thereby removing the need for the kernel to allocate some data on behalf of
	 * the kernel extension.
	 */
	panic("unsupported AppleImage4 interface");
}

void
txm_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4SetNonce,
		.failure_fatal = true,
		.num_input_args = 2,
	};

	txm_kernel_call(&txm_call, ndi, nonce);
}

void
txm_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4RollNonce,
		.failure_fatal = true,
		.num_input_args = 1,
	};

	txm_kernel_call(&txm_call, ndi);
}

errno_t
txm_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4GetNonce,
		.num_input_args = 1,
		.num_output_args = 1,
	};
	const img4_nonce_t *nonce = NULL;
	TXMReturn_t txm_ret = {0};
	kern_return_t ret = KERN_DENIED;

	ret = txm_kernel_call(&txm_call, ndi);
	if (ret != KERN_SUCCESS) {
		txm_ret = txm_call.txm_ret;
		if (txm_ret.returnCode != kTXMReturnCodeErrno) {
			return EPERM;
		}
		return txm_ret.errnoRet;
	}

	/* Acquire a pointer to the nonce from TXM */
	nonce = (const img4_nonce_t*)txm_call.return_words[0];

	if (nonce_out) {
		*nonce_out = *nonce;
	}
	return 0;
}

errno_t
txm_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest)
{
	/* Not supported within TXM yet */
	(void)obj_spec_index;
	(void)payload;
	(void)manifest;

	printf("image4 object execution isn't supported by TXM\n");
	return ENOSYS;
}

errno_t
txm_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length)
{
	/* Not supported within TXM yet */
	(void)obj_spec_index;
	(void)object_out;
	(void)object_length;

	printf("image4 object copying isn't supported by TXM\n");
	return ENOSYS;
}

const void*
txm_image4_get_monitor_exports(void)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4GetExports,
		.failure_fatal = true,
		.num_output_args = 1,
	};

	txm_kernel_call(&txm_call);
	return (const void*)txm_call.return_words[0];
}

errno_t
txm_image4_set_release_type(
	const char *release_type)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4SetReleaseType,
		.failure_fatal = true,
		.num_input_args = 1,
	};

	/* Set the release type -- cannot fail */
	txm_kernel_call(&txm_call, release_type);

	return 0;
}

errno_t
txm_image4_set_bnch_shadow(
	const img4_nonce_domain_index_t ndi)
{
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4SetBootNonceShadow,
		.failure_fatal = true,
		.num_input_args = 1,
	};

	/* Set the release type -- cannot fail */
	txm_kernel_call(&txm_call, ndi);

	return 0;
}

#pragma mark Image4 - New

static inline bool
_txm_image4_monitor_trap_supported(
	image4_cs_trap_t selector)
{
	switch (selector) {
#if kTXMImage4APIVersion >= 1
	case IMAGE4_CS_TRAP_KMOD_SET_RELEASE_TYPE:
	case IMAGE4_CS_TRAP_KMOD_PIN_ROOT:
	case IMAGE4_CS_TRAP_KMOD_EVALUATE_TRUST:
	case IMAGE4_CS_TRAP_NONCE_SET:
	case IMAGE4_CS_TRAP_NONCE_ROLL:
	case IMAGE4_CS_TRAP_IMAGE_ACTIVATE:
		return true;
#endif

	default:
		return false;
	}
}

kern_return_t
txm_image4_transfer_region(
	image4_cs_trap_t selector,
	vm_address_t region_addr,
	vm_size_t region_size)
{
	if (_txm_image4_monitor_trap_supported(selector) == true) {
		txm_transfer_region(region_addr, region_size);
	}
	return KERN_SUCCESS;
}

kern_return_t
txm_image4_reclaim_region(
	image4_cs_trap_t selector,
	vm_address_t region_addr,
	vm_size_t region_size)
{
	if (_txm_image4_monitor_trap_supported(selector) == true) {
		txm_reclaim_region(region_addr, region_size);
	}
	return KERN_SUCCESS;
}

errno_t
txm_image4_monitor_trap(
	image4_cs_trap_t selector,
	__unused const void *input_data,
	__unused size_t input_size)
{
#if kTXMKernelAPIVersion >= 2
	txm_call_t txm_call = {
		.selector = kTXMKernelSelectorImage4Dispatch,
		.num_input_args = 5,
	};

	kern_return_t ret = txm_kernel_call(
		&txm_call, selector,
		input_data, input_size,
		NULL, NULL);

	/* Return 0 for success */
	if (ret == KERN_SUCCESS) {
		return 0;
	}

	/* Check for an errno_t return */
	if (txm_call.txm_ret.returnCode == kTXMReturnCodeErrno) {
		if (txm_call.txm_ret.errnoRet == 0) {
			panic("image4 dispatch: unexpected success errno_t: %llu", selector);
		}
		return txm_call.txm_ret.errnoRet;
	}

	/* Return a generic error */
	return EPERM;
#else
	printf("image4 dispatch: traps not supported: %llu\n", selector);
	return ENOSYS;
#endif
}

#endif /* CONFIG_SPTM */
