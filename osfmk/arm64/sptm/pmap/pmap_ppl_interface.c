/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
/**
 * This file is meant to contain all of the PPL entry points and PPL-specific
 * functionality.
 *
 * Every single function in the pmap that chooses between running a "*_ppl()" or
 * "*_internal()" function variant will be placed into this file. This file also
 * contains the ppl_handler_table, as well as a few PPL-only entry/exit helper
 * functions.
 *
 * See doc/ppl.md for more information about how these PPL entry points work.
 */
#include <kern/ledger.h>

#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>

#include <arm64/sptm/pmap/pmap_internal.h>

/**
 * PMAP_SUPPORT_PROTOTYPES() will automatically create prototypes for the
 * _internal() and _ppl() variants of a PPL entry point. It also automatically
 * generates the code for the _ppl() variant which is what is used to jump into
 * the PPL.
 *
 * See doc/ppl.md for more information about how these PPL entry points work.
 */

PMAP_SUPPORT_PROTOTYPES(
	kern_return_t,
	mapping_free_prime, (void), MAPPING_FREE_PRIME_INDEX);

/**
 * See pmap_cpu_data_init_internal()'s function header for more info.
 */
void
pmap_cpu_data_init(void)
{
	pmap_cpu_data_init_internal(cpu_number());
}

/**
 * Prime the pv_entry_t free lists with a healthy amount of objects first thing
 * during boot. These objects will be used to keep track of physical-to-virtual
 * mappings.
 */
void
mapping_free_prime(void)
{
	kern_return_t kr = KERN_FAILURE;

	kr = mapping_free_prime_internal();

	if (kr != KERN_SUCCESS) {
		panic("%s: failed, no pages available? kr=%d", __func__, kr);
	}
}

/**
 * SPTM TODO: delete this function once the SPTM pmap becomes the sole pmap implementation.
 * See pmap_ledger_verify_size_internal()'s function header for more information.
 */
__attribute__((noreturn))
void
pmap_ledger_verify_size(size_t size)
{
	panic("%s: unsupported on non-PPL systems, size=%lu", __func__, size);
	__builtin_unreachable();
}

/**
 * SPTM TODO: delete this function once the SPTM pmap becomes the sole pmap implementation.
 * See pmap_ledger_alloc_internal()'s function header for more information.
 */
ledger_t
pmap_ledger_alloc(void)
{
	panic("%s: unsupported on non-PPL systems", __func__);
	__builtin_unreachable();
}

/**
 * SPTM TODO: delete this function once the SPTM pmap becomes the sole pmap implementation.
 * See pmap_ledger_free_internal()'s function header for more information.
 */
__attribute__((noreturn))
void
pmap_ledger_free(ledger_t ledger)
{
	panic("%s: unsupported on non-PPL systems, ledger=%p", __func__, ledger);
	__builtin_unreachable();
}
