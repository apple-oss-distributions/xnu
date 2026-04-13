/*
 * Copyright (c) 2020-2025 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_EXEC_INTERNAL_H_
#define _KERN_EXEC_INTERNAL_H_

#include <sys/imgact.h>
#include <sys/kernel_types.h>
#include <kern/mach_loader.h>

/*
 * Set p->p_comm and p->p_name to the name passed to exec
 */
extern void
set_proc_name(struct image_params *imgp, proc_t p);

/*
 * Runtime security mitigations in production are primarily controlled by
 * entitlements. Third party processes/daemons on MacOS aren't allowed to use
 * the com.apple.developer entitlement without a profile, whereby a special carve out
 * exists for com.apple.security.
 *
 * Progressively we expect internal first party software to shift towards the com.apple.security
 * format, but until then we support both cases, with a strict rule that only one can
 * be present.
 */
__enum_decl(exec_security_mitigation_entitlement_t, uint8_t, {
/*
 * Hardened-process.
 *
 * Security mitigations follow the notion of "hardened-process": binaries that we
 * have identified as being security critical. They are identified by the
 * com.apple.{developer|security}.hardened-process entitlement, which is required to further
 * configure the other security mitigations.
 */
	HARDENED_PROCESS = 0,
/*
 * Hardened-Heap.
 *
 * This mitigation extends libmalloc xzone with a number of security features,
 * most notably increasing the number of buckets and adding guard pages.
 * The presence of the entitlement opts the binary into the feature.
 */
	HARDENED_HEAP,
/*
 * TPRO - Trusted-Path Read-Only
 *
 * The TPRO mitigation allows to create memory regions that are read-only
 * but that can be rapidly, locally, modified by trusted-paths to be temporarily
 * read-write. TPRO is "enabled by default" (with the caveats in the exec_setup_tpro())
 * starting with the SDK versions below.
 */
	TPRO,
#if HAS_MTE
	CHECKED_ALLOCATIONS,
/*
 * We provide a negative entitlement for 1P binaries to opt out from the default
 * enablement of data tagging enablement.
 */
	CHECKED_ALLOCATIONS_DISABLE_PURE_DATA,
/*
 * Certain first-party actors (such as WCP and BlastDoor) are modeled untrustworthy, and should never
 * be allowed to receive untagged aliases to tagged memory from other actors. This entitlement (and a
 *  corresponding hard-coded bundle ID list in AMFI, for secrecy) expresses this constraint.
 */
	CHECKED_ALLOCATIONS_NO_TAGGED_RECEIVE,
/*
 * First and third party processes may want to have a form of "soaking time" where their process
 * is battle-tested with MTE without crashing on tag check faults. We call this mode soft-mode.
 * Note that after the first tag check fault, tag checking is completely disabled on the process.
 */
	CHECKED_ALLOCATIONS_SOFT_MODE,
#endif /* HAS_MTE */
/*
 * Script-Restrictions.
 *
 * This mitigation indicates we should restrict script usage in this process. This currently implies
 * preventing JavaScriptCore from being used, but could be adapted for other use cases.
 */
	SCRIPT_RESTRICTIONS,
/*
 * Containment Vessels (IPC restrictions)
 *
 * Certain first-party sandboxed processes on the system, such as BlastDoors and WCP, represent sensitive
 * attack surface. We therefore apply specific, stricter security policy to these processes in
 * various contexts. This entitlement serves for such binaries to self-identify for the specific
 * use case of stricter IPC security policies.
 */
	IPC_CONTAINMENT_VESSEL,
/*
 * Guard objects.
 *
 * This mitigation indicates that userland and kernel VM allocations may not be replaced with guard
 * objects on deallocation.
 */
	NO_GUARD_OBJECTS,
});

/*
 * Version number for enhanced security.
 * Currently stored with 3 bits in `hardened_process_version`
 *
 * The following entitlements set the hardened process version.
 *
 * First, we look for the string entitlement, and use that if it exists.
 * If it is not, we look for the integer entitlement.
 */
#define HARDENED_PROCESS_VERSION "com.apple.security.hardened-process.enhanced-security-version"
#define HARDENED_PROCESS_VERSION_STRING "com.apple.security.hardened-process.enhanced-security-version-string"

__enum_decl(hardened_process_version_t, uint8_t, {
	/* Not hardened process */
	HARDENED_PROCESS_DISABLED = 0,
	/* Initial version */
	HARDENED_PROCESS_VERSION_ONE = 1,
	/* Implies guard objects */
	HARDENED_PROCESS_VERSION_TWO = 2,
	/* Must be set to latest version */
	HARDENED_PROCESS_VERSION_LATEST = HARDENED_PROCESS_VERSION_TWO,
});

/*
 * exec_check_security_entitlement verifies whether a given entitlement is
 * associated to the to-be-run process. It verifies both legacy and current
 * format and returns:
 *   EXEC_SECURITY_NOT_ENTITLED   - if no entitlement is present
 *   EXEC_SECURITY_ENTITLED       - if the entitlement is present
 *   EXEC_SECURITY_INVALID_CONFIG - if _both_ entitlements are present (fatal condition)
 */
__enum_decl(exec_security_err_t, uint8_t, {
	EXEC_SECURITY_NOT_ENTITLED,
	EXEC_SECURITY_ENTITLED,
	EXEC_SECURITY_INVALID_CONFIG
});

extern exec_security_err_t exec_check_security_entitlement(struct image_params *imgp,
    exec_security_mitigation_entitlement_t entitlement);

#endif /* _KERN_EXEC_INTERNAL_H_ */
