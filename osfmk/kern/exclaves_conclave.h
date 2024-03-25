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

#if CONFIG_EXCLAVES

#pragma once

#include <Tightbeam/tightbeam.h>
#include <mach/kern_return.h>
#include <stdint.h>

#include "kern/exclaves.tightbeam.h"

__BEGIN_DECLS

extern kern_return_t
exclaves_conclave_launcher_init(uint64_t id, tb_client_connection_t *connection);

extern kern_return_t
exclaves_conclave_launcher_launch(const tb_client_connection_t connection);

extern kern_return_t
exclaves_conclave_launcher_stop(const tb_client_connection_t connection,
    uint32_t stop_reason);

extern tb_error_t
    exclaves_conclave_upcall_suspend(const uint32_t flags,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_suspend__result_s));

extern tb_error_t
    exclaves_conclave_upcall_stop(const uint32_t flags,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_stop__result_s));

extern tb_error_t
    exclaves_conclave_upcall_crash_info(const xnuupcalls_conclavesharedbuffer_s * shared_buf,
    const uint32_t length,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_conclave_crash_info__result_s));

__END_DECLS

#endif /* CONFIG_EXCLAVES */
