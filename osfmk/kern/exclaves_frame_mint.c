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
#include <mach/exclaves.h>
#include <mach/kern_return.h>

#include "kern/exclaves.tightbeam.h"

#include "exclaves_boot.h"
#include "exclaves_frame_mint.h"
#include "exclaves_resource.h"
#include "exclaves_debug.h"

/* -------------------------------------------------------------------------- */
#pragma mark Frame Mint

#define EXCLAVES_FRAME_MINT "com.apple.service.FrameMint"

static framemint_framemint_s frame_mint_client;

/*
 * As this only happens once, in theory this could be done as part of the
 * populate call. As we can't cleanup tightbeam connections anyway it doesn't
 * make much difference to just do it up-front and keep it around. If we ever
 * need to make any other calls to FrameMint, having it separate makes that
 * easier.
 */
static kern_return_t
exclaves_frame_mint_init(void)
{
	exclaves_id_t id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL,
	    EXCLAVES_FRAME_MINT);
	if (id == UINT64_C(~0)) {
		exclaves_debug_printf(show_errors,
		    "frame mint init: no frame mint service found \n");
		return KERN_NOT_FOUND;
	}

	tb_endpoint_t ep = tb_endpoint_create_with_value(
		TB_TRANSPORT_TYPE_XNU, id, TB_ENDPOINT_OPTIONS_NONE);

	tb_error_t tb_result = framemint_framemint__init(&frame_mint_client, ep);

	if (tb_result != TB_ERROR_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "frame mint init: failure %u\n", tb_result);
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

EXCLAVES_BOOT_TASK(exclaves_frame_mint_init, EXCLAVES_BOOT_RANK_ANY);

kern_return_t
exclaves_frame_mint_populate(void)
{
	__block bool success = false;
	tb_error_t tb_result = TB_ERROR_SUCCESS;

	/* BEGIN IGNORE CODESTYLE */
	tb_result = framemint_framemint_populate(&frame_mint_client,
	    ^(framemint_framemint_populate__result_s result) {
		if (framemint_framemint_populate__result_get_success(&result)) {
			success = true;
			return;
		}

		framemint_frameminterror_s *error = NULL;
		error = framemint_framemint_populate__result_get_failure(&result);

		assert3p(error, !=, NULL);
		exclaves_debug_printf(show_errors,
		    "frame mint failure: failure %u\n", *error);
	});
	/* END IGNORE CODESTYLE */

	if (tb_result != TB_ERROR_SUCCESS || !success) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

#endif /* CONFIG_EXCLAVES */
