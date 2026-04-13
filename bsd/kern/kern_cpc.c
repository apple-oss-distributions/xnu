// Copyright (c) 2023 Apple Inc. All rights reserved.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_START@
//
// This file contains Original Code and/or Modifications of Original Code
// as defined in and that are subject to the Apple Public Source License
// Version 2.0 (the 'License'). You may not use this file except in
// compliance with the License. The rights granted to you under the License
// may not be used to create, or enable the creation or redistribution of,
// unlawful or unlicensed copies of an Apple operating system, or to
// circumvent, violate, or enable the circumvention or violation of, any
// terms of an Apple operating system software license agreement.
//
// Please obtain a copy of the License at
// http://www.opensource.apple.com/apsl/ and read it before using this file.
//
// The Original Code and all software distributed under the License are
// distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
// EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
// Please see the License for the specific language governing rights and
// limitations under the License.
//
// @APPLE_OSREFERENCE_LICENSE_HEADER_END@

#include <kern/cpc.h>
#include <sys/sysctl.h>

SYSCTL_NODE(_kern, OID_AUTO, cpc, CTLFLAG_RD, 0,
    "CPU Performance Counters subsystem");

static int
_cpc_sysctl_secure SYSCTL_HANDLER_ARGS
{
	int enforced = cpc_is_secure();
	int changed = 0;
	int error = sysctl_io_number(req, enforced, sizeof(enforced), &enforced,
	    &changed);
	if (error != 0) {
		return error;
	}
	if (changed) {
#if CPC_INSECURE
		cpc_change_security(enforced);
#else // CPC_INSECURE
		return EPERM;
#endif // !CPC_INSECURE
	}
	return 0;
}

#if CPC_INSECURE
#define CPC_SYSCTL_SECURE_PROT CTLFLAG_RW
#else // CPC_INSECURE
#define CPC_SYSCTL_SECURE_PROT CTLFLAG_RD
#endif // !CPC_INSECURE

SYSCTL_PROC(_kern_cpc, OID_AUTO, secure, CPC_SYSCTL_SECURE_PROT | CTLTYPE_INT,
    0, 0, _cpc_sysctl_secure, "I",
    "Whether the CPU Performance Counters system is operating securely.");

#if DEVELOPMENT || DEBUG

bool cpc_logging = false;

static int
_cpc_sysctl_log SYSCTL_HANDLER_ARGS
{
	int changed = 0;
	int logging = cpc_logging;
	int error = sysctl_io_number(req, logging, sizeof(logging), &logging,
	    &changed);
	if (error != 0) {
		return error;
	}
	if (changed) {
		cpc_logging = logging;
	}
	return 0;
}

SYSCTL_PROC(_kern_cpc, OID_AUTO, log, CTLFLAG_RW | CTLTYPE_INT,
    0, 0, _cpc_sysctl_log, "I",
    "Log updates to the CPU Performance Counters system.");

static int
_cpc_sysctl_state SYSCTL_HANDLER_ARGS
{
	size_t size = 0;
	char *state = cpc_state_create(false, &size);
	int error = ENOBUFS;
	if (state) {
		int changed = 0;
		error = sysctl_io_string(req, state, strlen(state), 0, &changed);
		cpc_state_destroy(state, size);
	}
	return error;
}

SYSCTL_PROC(_kern_cpc, OID_AUTO, state,
    CTLFLAG_RD | CTLTYPE_STRING | CTLFLAG_MASKED,
    0, 0, _cpc_sysctl_state, "S",
    "Describe the state of the CPU Performance Counters system.");

#endif // DEVELOPMENT || DEBUG
