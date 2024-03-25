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

#include <stdint.h>
#include <mach/kern_return.h>

#include "kern/exclaves.tightbeam.h"

__BEGIN_DECLS


/*!
 * @function exclaves_shared_memory_init
 *
 * @abstract
 * Initialize a tightbeam connection to a shared memory segment.
 *
 * @param endpoint
 * Endpoint ID of the shared memory
 *
 * @param sm_client
 * Out paramater holding the connection.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_shared_memory_init(const uint64_t endpoint,
    sharedmemorybase_segxnuaccess_s *sm_client);

/*!
 * @function exclaves_shared_memory_setup
 *
 * @abstract
 * Initialize access to the shared memory segment and setup a mapping.
 *
 * @param sm_client
 * Connection to shared memory segment.
 *
 * @param perm
 * Permissions associated with the access (RO, RW).
 *
 * @param startpage
 * The start page of the mapping.
 *
 * @param endpage
 * The end page of the mapping.
 *
 * @param mapping
 * Out parameter respresenting the mapping.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_shared_memory_setup(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_perms_s perm, uint64_t startpage, uint64_t endpage,
    sharedmemorybase_mapping_s *mapping);

/*!
 * @function exclaves_shared_memory_teardown
 *
 * @abstract
 * Teardown access to the shared memory segment and unmap.
 *
 * @param sm_client
 * Connection to shared memory segment.
 *
 * @param mapping
 * Pointer to the mapping.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_shared_memory_teardown(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping);

/*!
 * @function exclaves_shared_memory_map
 *
 * @abstract
 * Map a range of memory into xnu.
 *
 * @param sm_client
 * Connection to shared memory segment.
 *
 * @param mapping
 * Pointer to the mapping.
 *
 * @param startpage
 * The start page of the mapping.
 *
 * @param endpage
 * The end page of the mapping.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_shared_memory_map(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping, const uint64_t startpage,
    const uint64_t endpage);

/*!
 * @function exclaves_shared_memory_unmap
 *
 * @abstract
 * Unmap a range of memory already mapped in xnu.
 *
 * @param sm_client
 * Connection to shared memory segment.
 *
 * @param mapping
 * Pointer to the mapping.
 *
 * @param startpage
 * The start page of the mapping.
 *
 * @param endpage
 * The end page of the mapping.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_shared_memory_unmap(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping, const uint64_t startpage,
    const uint64_t endpage);

/*!
 * @function exclaves_shared_memory_iterate
 *
 * @abstract
 * Iterate over the physical pages of a mapping
 *
 * @param sm_client
 * Connection to shared memory segment.
 *
 * @param mapping
 * Pointer to the mapping.
 *
 * @param startpage
 * The start page of range to iterate over..
 *
 * @param endpage
 * The end page of range to iterate over.
 *
 * @param cb
 * The callback to call for each physical page.
 *
 * @return
 * The KERN_SUCCESS or error code on failure.
 */
/* BEGIN IGNORE CODESTYLE */
extern kern_return_t
exclaves_shared_memory_iterate(const sharedmemorybase_segxnuaccess_s * sm_client,
    const sharedmemorybase_mapping_s *mapping, uint64_t startpage, uint64_t endpage,
    void (^cb)(uint64_t physical_address));
/* END IGNORE CODESTYLE*/

__END_DECLS

#endif /* CONFIG_EXCLAVES */
