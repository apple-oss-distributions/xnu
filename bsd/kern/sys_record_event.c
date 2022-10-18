/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <os/system_event_log.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <IOKit/IOBSD.h>

int
sys_record_system_event(__unused struct proc *p, struct record_system_event_args *uap, __unused int *retval)
{
	int error = 0;

	boolean_t entitled = FALSE;
	entitled = IOCurrentTaskHasEntitlement(SYSTEM_EVENT_ENTITLEMENT);
	if (!entitled) {
		error = EPERM;
		goto done;
	}

	char event[SYSTEM_EVENT_EVENT_MAX] = {0};
	char payload[SYSTEM_EVENT_PAYLOAD_MAX] = {0};
	size_t bytes_copied;

	error = copyinstr(uap->event, event, sizeof(event), &bytes_copied);
	if (error) {
		goto done;
	}
	error = copyinstr(uap->payload, payload, sizeof(payload), &bytes_copied);
	if (error) {
		goto done;
	}

	record_system_event_no_varargs((uint8_t)(uap->type), (uint8_t)(uap->subsystem), event, payload);

done:
	return error;
}
