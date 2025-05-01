/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#pragma once

#include <stdint.h>
#include <mach/kern_return.h>

#include "kern/exclaves.tightbeam.h"

/* The maximum number of pages in a memory request. */
#define EXCLAVES_MEMORY_MAX_REQUEST (64)

typedef enum : uint32_t {
	EXCLAVES_MEMORY_PAGEKIND_ROOTDOMAIN = 1,
	EXCLAVES_MEMORY_PAGEKIND_CONCLAVE = 2,
} exclaves_memory_pagekind_t;

typedef enum __enum_closed __enum_options : uint32_t {
	EXCLAVES_MEMORY_PAGE_FLAGS_NONE = 0,
} exclaves_memory_page_flags_t;

__BEGIN_DECLS

extern void
exclaves_memory_alloc(uint32_t npages, uint32_t * _Nonnull pages, const exclaves_memory_pagekind_t kind, const exclaves_memory_page_flags_t flags);

extern void
exclaves_memory_free(uint32_t npages, const uint32_t * _Nonnull pages, const exclaves_memory_pagekind_t kind, const exclaves_memory_page_flags_t flags);

extern kern_return_t
exclaves_memory_map(uint32_t npages, const uint32_t * _Nonnull pages, vm_prot_t prot,
    char * _Nullable * _Nonnull address);

extern kern_return_t
exclaves_memory_unmap(char * _Nonnull address, size_t size);

/* BEGIN IGNORE CODESTYLE */

/* Legacy upcall handlers */

extern tb_error_t
exclaves_memory_upcall_legacy_alloc(uint32_t npages, xnuupcalls_pagekind_s kind,
    tb_error_t (^_Nonnull completion)(xnuupcalls_pagelist_s));

extern tb_error_t
exclaves_memory_upcall_legacy_alloc_ext(uint32_t npages, xnuupcalls_pageallocflags_s flags,
    tb_error_t (^_Nonnull completion)(xnuupcalls_pagelist_s));

extern tb_error_t
exclaves_memory_upcall_legacy_free(const uint32_t pages[_Nonnull EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, const xnuupcalls_pagekind_s kind,
    tb_error_t (^_Nonnull completion)(void));

extern tb_error_t
exclaves_memory_upcall_legacy_free_ext(const uint32_t pages[_Nonnull EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, xnuupcalls_pagefreeflags_s flags,
    tb_error_t (^_Nonnull completion)(void));

/* Upcall handlers */

extern tb_error_t
exclaves_memory_upcall_alloc(uint32_t npages, xnuupcallsv2_pagekind_s kind,
    tb_error_t (^_Nonnull completion)(xnuupcallsv2_pagelist_s));

extern tb_error_t
exclaves_memory_upcall_alloc_ext(uint32_t npages, xnuupcallsv2_pageallocflagsv2_s flags,
    tb_error_t (^_Nonnull completion)(xnuupcallsv2_pagelist_s));

extern tb_error_t
exclaves_memory_upcall_free(const xnuupcallsv2_pagelist_s pages,
    const xnuupcallsv2_pagekind_s kind, tb_error_t (^_Nonnull completion)(void));

extern tb_error_t
exclaves_memory_upcall_free_ext(const xnuupcallsv2_pagelist_s pages,
    const xnuupcallsv2_pagefreeflagsv2_s kind, tb_error_t (^_Nonnull completion)(void));

/* END IGNORE CODESTYLE */

extern void
exclaves_memory_report_accounting(void);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
