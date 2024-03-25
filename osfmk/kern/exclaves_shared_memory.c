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

#include <stdint.h>
#include <mach/kern_return.h>
#include <kern/assert.h>
#include <kern/misc_protos.h>

#include "exclaves_shared_memory.h"
#include "kern/exclaves.tightbeam.h"

kern_return_t
exclaves_shared_memory_init(const uint64_t endpoint,
    sharedmemorybase_segxnuaccess_s *sm_client)
{
	assert3p(sm_client, !=, NULL);

	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, endpoint, TB_ENDPOINT_OPTIONS_NONE);
	tb_error_t ret = sharedmemorybase_segxnuaccess__init(sm_client, ep);

	return ret == TB_ERROR_SUCCESS ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t
exclaves_shared_memory_access_check(
	const sharedmemorybase_segxnuaccess_s *sm_client,
	const sharedmemorybase_perms_s perm, const uint64_t endpage,
	bool *access_allowed)
{
	assert3p(sm_client, !=, NULL);
	assert3p(access_allowed, !=, NULL);

	tb_error_t ret = TB_ERROR_SUCCESS;

	__block bool allowed = true;
	ret = sharedmemorybase_segxnuaccess_xnuaccessstatus(sm_client,
	    ^(sharedmemorybase_accessstatus_s result) {
		/*
		 * Check permissions.
		 * For the moment just check for writable
		 * access (if relevant).
		 */
		if (perm == SHAREDMEMORYBASE_PERMS_READWRITE) {
		        allowed = allowed && perm == result.permissions;
		}

		/* Check that it's xnu mappable. */
		allowed = allowed && result.xnu;

		/* Check that there are enough pages. */
		allowed = allowed && endpage <= result.segmentstatus.npages;
	});

	if (ret != TB_ERROR_SUCCESS) {
		return KERN_FAILURE;
	}

	*access_allowed = allowed;
	return KERN_SUCCESS;
}

kern_return_t
exclaves_shared_memory_setup(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_perms_s perm, const uint64_t startpage,
    const uint64_t endpage, sharedmemorybase_mapping_s *mapping)
{
	assert3p(sm_client, !=, NULL);
	assert3p(mapping, !=, NULL);
	assert3u(startpage, <, endpage);
	assert(perm == SHAREDMEMORYBASE_PERMS_READWRITE ||
	    perm == SHAREDMEMORYBASE_PERMS_READONLY);

	tb_error_t ret = TB_ERROR_SUCCESS;

	/* Do a quick sanity check that this access is allowed. */
	bool allowed = false;
	kern_return_t kret = exclaves_shared_memory_access_check(sm_client, perm, endpage, &allowed);
	if (kret != KERN_SUCCESS) {
		return kret;
	}

	sharedmemorybase_pagerange__opt_s opt_range = {};

	sharedmemorybase_pagerange_s range = {
		.startpage = startpage,
		.endpage = endpage,
	};
	sharedmemorybase_pagerange__opt_init(&opt_range, &range);

	*mapping = 0;
	ret = sharedmemorybase_segxnuaccess_createxnumapping(sm_client, perm,
	    &opt_range,
	    ^(sharedmemorybase_segxnuaccess_createxnumapping__result_s result) {
		sharedmemorybase_accesserror_s *error = NULL;
		error = sharedmemorybase_segxnuaccess_createxnumapping__result_get_failure(&result);
		if (error != NULL) {
		        (void) printf("%s: failed to create mapping: %u",
		        __func__, *error);
		        return;
		}

		sharedmemorybase_mappingresult_s *sm_result = NULL;
		sm_result = sharedmemorybase_segxnuaccess_createxnumapping__result_get_success(&result);
		assert3p(sm_result, !=, NULL);

		*mapping = sm_result->mappinginfo.mapping;
		assert3u(*mapping, !=, 0);
	});

	if (ret != TB_ERROR_SUCCESS || *mapping == 0) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

/*
 * Currently unused as the setup process can provide an initial mapping.
 */
kern_return_t
exclaves_shared_memory_teardown(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping)
{
	assert3p(sm_client, !=, NULL);
	assert3p(mapping, !=, NULL);

	tb_error_t ret = TB_ERROR_SUCCESS;
	__block bool success = false;

	ret = sharedmemorybase_segxnuaccess_mappingdestroy(sm_client, *mapping,
	    ^(sharedmemorybase_segaccessbase_mappingdestroy__result_s result) {
		sharedmemorybase_accesserror_s *error;
		error = sharedmemorybase_segaccessbase_mappingdestroy__result_get_failure(&result);
		if (error != NULL) {
		        (void) printf("%s: failed to destroy mapping: %u\n",
		        __func__, *error);
		        return;
		}

		assert(sharedmemorybase_segaccessbase_mappingdestroy__result_get_success(&result));
		success = true;
	});

	if (ret != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

/*
 * Currently unused as the teardown process unmaps.
 */
kern_return_t
exclaves_shared_memory_map(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping, const uint64_t startpage,
    const uint64_t endpage)
{
	assert3p(sm_client, !=, NULL);
	assert3p(mapping, !=, NULL);
	assert3u(startpage, <, endpage);

	tb_error_t ret = TB_ERROR_SUCCESS;
	__block bool success = false;

	const sharedmemorybase_pagerange_s range = {
		.startpage = startpage,
		.endpage = endpage,
	};

	ret = sharedmemorybase_segxnuaccess_mappingmap(sm_client, *mapping,
	    &range, ^(sharedmemorybase_segaccessbase_mappingmap__result_s result) {
		sharedmemorybase_accesserror_s *error;
		error = sharedmemorybase_segaccessbase_mappingmap__result_get_failure(&result);
		if (error != NULL) {
		        (void) printf("%s: failed to map: %u\n",
		        __func__, *error);
		        return;
		}

		assert(sharedmemorybase_segaccessbase_mappingmap__result_get_success(&result));
		success = true;
	});

	if (ret != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}


kern_return_t
exclaves_shared_memory_unmap(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping, const uint64_t startpage,
    const uint64_t endpage)
{
	assert3p(sm_client, !=, NULL);
	assert3p(mapping, !=, NULL);
	assert3u(startpage, <, endpage);

	tb_error_t ret = TB_ERROR_SUCCESS;
	__block bool success = false;

	const sharedmemorybase_pagerange_s range = {
		.startpage = startpage,
		.endpage = endpage,
	};

	ret = sharedmemorybase_segxnuaccess_mappingunmap(sm_client, *mapping,
	    &range, ^(sharedmemorybase_segaccessbase_mappingunmap__result_s result) {
		sharedmemorybase_accesserror_s *error;
		error = sharedmemorybase_segaccessbase_mappingunmap__result_get_failure(&result);
		if (error != NULL) {
		        (void) printf("%s: failed to unmap: %u\n",
		        __func__, *error);
		        return;
		}

		assert(sharedmemorybase_segaccessbase_mappingunmap__result_get_success(&result));
		success = true;
	});

	if (ret != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

kern_return_t
exclaves_shared_memory_iterate(const sharedmemorybase_segxnuaccess_s *sm_client,
    const sharedmemorybase_mapping_s *mapping, uint64_t startpage, uint64_t endpage,
    void (^cb)(uint64_t))
{
	assert3p(sm_client, !=, NULL);
	assert3p(mapping, !=, NULL);
	assert3u(startpage, <, endpage);

	tb_error_t ret = TB_ERROR_SUCCESS;
	__block bool success = false;

	sharedmemorybase_pagerange_s full_range = {
		.startpage = startpage,
		.endpage = endpage,
	};

	ret = sharedmemorybase_segxnuaccess_mappinggetphysicaladdresses(sm_client,
	    *mapping, &full_range,
	    ^(sharedmemorybase_segaccessbase_mappinggetphysicaladdresses__result_s result) {
		sharedmemorybase_accesserror_s *error = NULL;
		error = sharedmemorybase_segaccessbase_mappinggetphysicaladdresses__result_get_failure(&result);
		if (error != NULL) {
		        (void) printf("%s: failed to get physical address: %u",
		        __func__, *error);
		        return;
		}

		physicaladdress_v_s *phys_addr = NULL;
		phys_addr = sharedmemorybase_segaccessbase_mappinggetphysicaladdresses__result_get_success(&result);
		assert3p(phys_addr, !=, NULL);

		physicaladdress__v_visit(phys_addr,
		^(__unused size_t i, const sharedmemorybase_physicaladdress_s item) {
			cb(item);
		});

		success = true;
	});

	if (ret != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

#endif /* CONFIG_EXCLAVES */
