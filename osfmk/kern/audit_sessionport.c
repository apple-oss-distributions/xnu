/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/notify.h>
#include <ipc/ipc_port.h>
#include <kern/ipc_kobject.h>
#include <kern/audit_sessionport.h>
#include <libkern/OSAtomic.h>

#if CONFIG_AUDIT
/*
 * audit_session_mksend
 *
 * Description: Obtain a send right for given audit session.
 *
 * Parameters:	*aia_p		Audit session information to assosiate with
 *                              the new port.
 *              *sessionport	Pointer to the current session port.  This may
 *                              actually be set to IPC_PORT_NULL.
 *
 * Returns:	!NULL		Resulting send right.
 *              NULL		Failed to allocate port (due to lack of memory
 *                              resources).
 *
 * Assumptions: Caller holds a reference on the session during the call.
 *		If there were no outstanding send rights against the port,
 *		hold a reference on the session and arm a new no-senders
 *		notification to determine when to release that reference.
 *		Otherwise, by creating an additional send right, we share
 *		the port's reference until all send rights go away.
 */
ipc_port_t
audit_session_mksend(struct auditinfo_addr *aia_p, ipc_port_t *sessionport)
{
	audit_session_aiaref(aia_p);
	if (!ipc_kobject_make_send_lazy_alloc_port(sessionport,
	    aia_p, IKOT_AU_SESSIONPORT, IPC_KOBJECT_ALLOC_NONE)) {
		audit_session_aiaunref(aia_p);
	}

	return *sessionport;
}


/*
 * audit_session_porttoaia
 *
 * Description: Obtain the audit session info associated with the given port.
 *
 * Parameters: port		A Mach port.
 *
 * Returns:    NULL		The given Mach port did not reference audit
 *                              session info.
 *	       !NULL		The audit session info that is associated with
 *				the Mach port.
 *
 * Notes: The caller must hold an outstanding send-right on the sessionport.
 */
struct auditinfo_addr *
audit_session_porttoaia(ipc_port_t port)
{
	struct auditinfo_addr *aia_p = NULL;

	if (IP_VALID(port)) {
		aia_p = ipc_kobject_get_stable(port, IKOT_AU_SESSIONPORT);
	}

	return aia_p;
}


/*
 * audit_session_no_senders
 *
 * Description: Handle a no-senders notification for a sessionport.
 *
 * Notes: It is possible that new send rights are created after a
 *	  no-senders notification has been sent, but they will be protected
 *	  by another aia reference.
 */
static void
audit_session_no_senders(ipc_port_t port, __unused mach_port_mscount_t mscount)
{
	struct auditinfo_addr *aia_p = NULL;

	aia_p = ipc_kobject_get_stable(port, IKOT_AU_SESSIONPORT);
	assert(NULL != aia_p);

	audit_session_aiaunref(aia_p);
}

/*
 * audit_session_portdestroy
 *
 * Description: Destroy the kobject associated with the audit_session
 *
 * Notes: It is called when there is no outstanding references on the aia
 *        anymore (it also won't have any outstanding send rights)
 */
void
audit_session_portdestroy(ipc_port_t *sessionport)
{
	ipc_port_t port = *sessionport;

	*sessionport = IP_NULL;
	if (IP_VALID(port)) {
		ipc_kobject_dealloc_port(port, 0, IKOT_AU_SESSIONPORT);
	}
}

IPC_KOBJECT_DEFINE(IKOT_AU_SESSIONPORT,
    .iko_op_stable     = true,
    .iko_op_no_senders = audit_session_no_senders);

#endif /* CONFIG_AUDIT */
