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
#include <mach/exclaves_l4.h>

#include "exclaves_internal.h"

#include "kern/exclaves.tightbeam.h"

__BEGIN_DECLS

extern kern_return_t
exclaves_xnuproxy_pmm_usage(void);

extern kern_return_t
exclaves_xnuproxy_ctx_alloc(exclaves_ctx_t *ctx);

extern kern_return_t
exclaves_xnuproxy_ctx_free(exclaves_ctx_t *ctx);

extern kern_return_t
exclaves_xnuproxy_init(uint64_t bootinfo_pa);

/* BEGIN IGNORE CODESTYLE */
/*
 * Note: strings passed to callback are not valid outside of the context of the
 * callback.
 */
extern kern_return_t
exclaves_xnuproxy_resource_info(void (^cb)(const char *name, const char *domain,
    xnuproxy_resourcetype_s, uint64_t id, bool));
/* END IGNORE CODESTYLE */

extern kern_return_t
exclaves_xnuproxy_audio_buffer_copyout(uint64_t id,
    uint64_t size1, uint64_t offset1, uint64_t size2, uint64_t offset2);

extern kern_return_t
exclaves_xnuproxy_audio_buffer_delete(uint64_t id);

extern kern_return_t
exclaves_xnuproxy_audio_buffer_map(uint64_t id, size_t size, bool *read_only);

/* BEGIN IGNORE CODESTYLE */
extern kern_return_t
exclaves_xnuproxy_audio_buffer_layout(uint64_t id, uint32_t start,
    uint32_t npages, kern_return_t (^cb)(uint64_t base, uint32_t npages));
/* ENDIGNORE CODESTYLE */

extern kern_return_t
exclaves_xnuproxy_named_buffer_delete(uint64_t id);

extern kern_return_t
exclaves_xnuproxy_named_buffer_map(uint64_t id, size_t size, bool *read_only);

/* BEGIN IGNORE CODESTYLE */
extern kern_return_t
exclaves_xnuproxy_named_buffer_layout(uint64_t id, uint32_t start,
    uint32_t npages, kern_return_t (^cb)(uint64_t base, uint32_t npages));
/* END IGNORE CODESTYLE */

extern kern_return_t
exclaves_xnuproxy_endpoint_call(Exclaves_L4_Word_t endpoint_id);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
