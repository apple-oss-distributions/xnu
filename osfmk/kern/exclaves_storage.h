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

#pragma once

#if CONFIG_EXCLAVES

#if __has_include(<Tightbeam/tightbeam.h>)

#include <stdint.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>

#include "kern/exclaves.tightbeam.h"

#include "exclaves_resource.h"

__BEGIN_DECLS

extern tb_error_t
    exclaves_storage_upcall_root(const uint8_t exclaveid[_Nonnull 32],
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_root__result_s));

extern tb_error_t
    exclaves_storage_upcall_open(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_open__result_s));

extern tb_error_t
    exclaves_storage_upcall_close(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_close__result_s));

extern tb_error_t
    exclaves_storage_upcall_create(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_create__result_s));

extern tb_error_t
    exclaves_storage_upcall_read(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s * _Nonnull descriptor,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_read__result_s));

extern tb_error_t
    exclaves_storage_upcall_write(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s * _Nonnull descriptor,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_write__result_s));

extern tb_error_t
    exclaves_storage_upcall_remove(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_remove__result_s));

extern tb_error_t
    exclaves_storage_upcall_sync(const enum xnuupcalls_fstag_s fstag,
    const enum xnuupcalls_syncop_s op,
    const uint64_t fileid,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_sync__result_s));

extern tb_error_t
    exclaves_storage_upcall_readdir(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const uint64_t buf,
    const uint32_t length,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_readdir__result_s));

extern tb_error_t
    exclaves_storage_upcall_getsize(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid,
    tb_error_t (^_Nonnull completion)(xnuupcalls_xnuupcalls_getsize__result_s));

__END_DECLS

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

#endif /* CONFIG_EXCLAVES */
