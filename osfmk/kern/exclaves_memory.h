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

__BEGIN_DECLS

extern void
exclaves_memory_alloc(uint32_t npages, uint32_t *pages, const xnuupcalls_pagekind_s kind);

extern void
exclaves_memory_free(uint32_t npages, const uint32_t *pages, const xnuupcalls_pagekind_s kind);

/* BEGIN IGNORE CODESTYLE */
extern tb_error_t
exclaves_memory_upcall_alloc(uint32_t npages, xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(xnuupcalls_pagelist_s));
/* END IGNORE CODESTYLE */

/* BEGIN IGNORE CODESTYLE */
extern tb_error_t
exclaves_memory_upcall_free(const uint32_t pages[EXCLAVES_MEMORY_MAX_REQUEST],
    uint32_t npages, const xnuupcalls_pagekind_s kind,
    tb_error_t (^completion)(void));
/* END IGNORE CODESTYLE */

extern void
exclaves_memory_report_accounting(void);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
