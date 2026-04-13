/*
 * Copyright (c) 2025 Apple Inc. All rights reserved.
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

#include <arm64/sptm/pmap/pmap.h>

#include "fake_libsptm.h"

/*
 * Other functions that are not defined here are stubbed out in mock_unimpl.c
 */

libsptm_error_t
sptm_get_cpu_state(uint64_t sptm_logical_cpu_id, libsptm_cpu_state_t state_type,
    bool *state)
{
	if (state == NULL) {
		return LIBSPTM_INVALID_ARG;
	}

	*state = false;

	return LIBSPTM_SUCCESS;
}

static libsptm_error_t sptm_type_is_ecc_retireable_ret = LIBSPTM_SUCCESS;
void
sptm_type_is_ecc_retireable_set_ret(const libsptm_error_t ret)
{
	sptm_type_is_ecc_retireable_ret = ret;
}
libsptm_error_t
sptm_type_is_ecc_retireable(sptm_frame_type_t frame_type,
    bool *is_ecc_retirable)
{
	/* Mock return override. */
	if (sptm_type_is_ecc_retireable_ret != LIBSPTM_SUCCESS) {
		return sptm_type_is_ecc_retireable_ret;
	}

	if (is_ecc_retirable == NULL) {
		return LIBSPTM_INVALID_ARG;
	}

	if (is_ecc_retirable) {
		switch (frame_type) {
		case XNU_DEFAULT:
			*is_ecc_retirable = true;
			break;
		case SPTM_DEFAULT:
		case SPTM_CODE:
			*is_ecc_retirable = false;
			break;
		default:
			panic("Unexpected frame_type %u in %s mock.",
			    frame_type, __func__);
			break;
		}
	}

	return LIBSPTM_SUCCESS;
}

static sptm_return_t sptm_condemn_leaf_table_ret = SPTM_SUCCESS;
void
sptm_condemn_leaf_table_set_ret(const sptm_return_t ret)
{
	sptm_condemn_leaf_table_ret = ret;
}

/* Can return SPTM_TABLE_NOT_PRESENT or SPTM_SUCCESS. */
sptm_return_t
sptm_condemn_leaf_table(sptm_paddr_t root_pt_paddr, sptm_vaddr_t vaddr)
{
	return sptm_condemn_leaf_table_ret;
}

libsptm_error_t
sptm_phystokv(sptm_paddr_t paddr, sptm_papt_t *vaddrp)
{
	*vaddrp = paddr;
	return LIBSPTM_SUCCESS;
}

static sptm_frame_type_t sptm_get_paddr_type_mocked_type = XNU_DEFAULT;
void
sptm_get_paddr_type_set_type(const sptm_frame_type_t frame_typep)
{
	sptm_get_paddr_type_mocked_type = frame_typep;
}

libsptm_error_t
sptm_get_paddr_type(sptm_paddr_t paddr, sptm_frame_type_t *frame_typep)
{
	if (frame_typep == NULL) {
		return LIBSPTM_INVALID_ARG;
	}

	*frame_typep = sptm_get_paddr_type_mocked_type;
	return LIBSPTM_SUCCESS;
}

static sptm_frame_type_t sptm_retype_last_type = -1;
sptm_frame_type_t
sptm_retype_get_type(void)
{
	const sptm_frame_type_t ret = sptm_retype_last_type;

	/* Reset after reading (to distinguish multiple calls to the mock). */
	sptm_retype_last_type = -1;

	return ret;
}
void
sptm_retype(sptm_paddr_t paddr,
    sptm_frame_type_t current_type,
    sptm_frame_type_t new_type,
    sptm_retype_params_t retype_params)
{
	/*
	 * Explicitly define some transitions, everything else will be consider
	 * "unexpected".
	 */
	if ((current_type == XNU_DEFAULT && new_type == XNU_DEFAULT) ||
	    (current_type == XNU_DEFAULT && new_type == SPTM_UNUSED)) {
		sptm_retype_last_type = new_type;
		return;
	}
	if (current_type == SPTM_CODE && new_type == XNU_DEFAULT) {
		panic("%s: Invalid retype (Mock SPTM violation)", __func__);
	}

	panic("Unexpected transition in %s mock (type %u -> type %u)", __func__,
	    current_type, new_type);
}
