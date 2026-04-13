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

#include <kern/ecc.h>
#include <libkern/libkern.h>
#include <machine/machine_routines.h>
#include <pexpert/pexpert.h>
#include <sys/sysctl.h>
#include <vm/vm_protos.h>

#ifdef HAS_MTE
#include <arm64/mte_xnu.h>
#include <sys/ubc.h>                    /* for kr to bsd error conversion */
#endif

#if DEBUG || DEVELOPMENT
/*
 * Sysctl to check if the platform is supposed to support error injection.
 */
static int
dram_ecc_error_injection_capable SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2, req)
	int capable = 0;

/* T6041 does not support error injection. */

	return SYSCTL_OUT(req, &capable, sizeof(capable));
}
SYSCTL_PROC(_vm, OID_AUTO, dram_ecc_error_injection_capable,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
    0, 0, &dram_ecc_error_injection_capable, "I", "");
#endif /* DEBUG || DEVELOPMENT */

