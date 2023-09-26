/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include <stdbool.h>

#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/sbuf.h>
#include <sys/types.h>
#include <sys/mcache.h>
#include <sys/malloc.h>

#include <os/log.h>

#include <net/nwk_wq.h>
#include <skywalk/lib/net_filter_event.h>

static uint32_t net_filter_event_state;
static bool net_filter_event_initialized;
static struct eventhandler_lists_ctxt net_filter_evhdlr_ctxt;

EVENTHANDLER_DECLARE(net_filter_event, net_filter_event_callback_t);

static struct sbuf *
net_filter_event_description(uint32_t state)
{
	struct sbuf *sbuf;

	sbuf = sbuf_new(NULL, NULL, 128, SBUF_AUTOEXTEND);
	if (state & NET_FILTER_EVENT_PF) {
		sbuf_cat(sbuf, "pf ");
	}
	if (state & NET_FILTER_EVENT_SOCKET) {
		sbuf_cat(sbuf, "socket ");
	}
	if (state & NET_FILTER_EVENT_INTERFACE) {
		sbuf_cat(sbuf, "interface ");
	}
	if (state & NET_FILTER_EVENT_IP) {
		sbuf_cat(sbuf, "ip ");
	}
	if (state & NET_FILTER_EVENT_ALF) {
		sbuf_cat(sbuf, "application-firewall ");
	}
	if (state & NET_FILTER_EVENT_PARENTAL_CONTROLS) {
		sbuf_cat(sbuf, "parental-controls ");
	}
	sbuf_trim(sbuf);
	sbuf_finish(sbuf);

	return sbuf;
}


static void
net_filter_event_callback(struct eventhandler_entry_arg arg0 __unused,
    enum net_filter_event_subsystems state)
{
	struct sbuf *sbuf = net_filter_event_description(state);

	os_log(OS_LOG_DEFAULT, "net_filter_event: new state (0x%x) %s",
	    state, sbuf_data(sbuf));
	sbuf_delete(sbuf);
}

static void
net_filter_event_init(void)
{
	if (net_filter_event_initialized) {
		return;
	}
	net_filter_event_initialized = true;
	eventhandler_lists_ctxt_init(&net_filter_evhdlr_ctxt);
	net_filter_event_register(net_filter_event_callback);
}

static void
net_filter_event_enqueue_callback(struct nwk_wq_entry *nwk_kwqe)
{
	EVENTHANDLER_INVOKE(&net_filter_evhdlr_ctxt, net_filter_event,
	    net_filter_event_state);
	kfree_type(struct nwk_wq_entry, nwk_kwqe);
}

static void
net_filter_event_enqueue(void)
{
	struct nwk_wq_entry *nwk_wqe;

	nwk_wqe = kalloc_type(struct nwk_wq_entry, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	nwk_wqe->func = net_filter_event_enqueue_callback;
	nwk_wq_enqueue(nwk_wqe);
}

void
net_filter_event_mark(enum net_filter_event_subsystems subsystem, bool compatible)
{
	uint32_t old_state = net_filter_event_state;

	net_filter_event_init();
	if (!compatible) {
		os_atomic_or(&net_filter_event_state, subsystem, relaxed);
	} else {
		os_atomic_andnot(&net_filter_event_state, subsystem, relaxed);
	}
	if (old_state != net_filter_event_state) {
		net_filter_event_enqueue();
	}
}

enum net_filter_event_subsystems
net_filter_event_get_state(void)
{
	return net_filter_event_state;
}

void
net_filter_event_register(net_filter_event_callback_t callback)
{
	net_filter_event_init();
	eventhandler_register(&net_filter_evhdlr_ctxt, NULL,
	    "net_filter_event",
	    ptrauth_nop_cast(void *, callback),
	    eventhandler_entry_dummy_arg,
	    EVENTHANDLER_PRI_ANY);
}


static int
net_filter_event_sysctl(struct sysctl_oid *oidp, void *arg1, int arg2,
    struct sysctl_req *req)
{
#pragma unused(oidp, arg1, arg2)
	struct sbuf *sbuf = net_filter_event_description(net_filter_event_state);

	int error = sysctl_io_string(req, sbuf_data(sbuf), 0, 0, NULL);
	sbuf_delete(sbuf);

	return error;
}

SYSCTL_PROC(_net, OID_AUTO, filter_state,
    CTLTYPE_STRING | CTLFLAG_LOCKED, NULL, 0,
    net_filter_event_sysctl, "A", "State of the network filters");
