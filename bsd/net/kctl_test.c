/*
 * Copyright (c) 2023 Apple Computer, Inc. All rights reserved.
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

#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/errno.h>
#include <netinet/in.h>

#include <sys/kern_control.h>
#include <libkern/libkern.h>
#include <os/log.h>

#include <net/kctl_test.h>

static errno_t kctl_test_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t kctl_test_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo);
static errno_t kctl_test_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags);
static errno_t kctl_test_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
static errno_t kctl_test_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
static errno_t kctl_test_send_list(kern_ctl_ref kctlref, u_int32_t unit,
    void *unitinfo, mbuf_t m, int flags);

static struct kern_ctl_reg kctl_test_reg = {
	.ctl_name = KCTL_TEST_CONTROL_NAME,
	.ctl_id = 0,
	.ctl_unit = 0,
	.ctl_flags = CTL_FLAG_PRIVILEGED | CTL_FLAG_REG_EXTENDED,
	.ctl_sendsize = 256 * 1024, /* 256 KiB */
	.ctl_recvsize = 2 * 1024 * 1024, /* 2 MiB */
	.ctl_connect = kctl_test_connect,
	.ctl_disconnect = kctl_test_disconnect,
	.ctl_send = kctl_test_send,
	.ctl_setopt = kctl_test_setopt,
	.ctl_getopt = kctl_test_getopt,
	.ctl_send_list = kctl_test_send_list
};
static kern_ctl_ref kctl_test_ref;
static u_int32_t kctl_test_id;


static errno_t
kctl_test_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
#pragma unused(unitinfo)
	errno_t error = 0;
	size_t space;

	os_log(OS_LOG_DEFAULT, "kctl_test_connect: ref %p id %u port %u",
	    kctlref, sac->sc_id, sac->sc_unit);

	error = ctl_getenqueuespace(kctlref, sac->sc_unit, &space);
	if (error != 0) {
		os_log(OS_LOG_DEFAULT, "kctl_test_connect; ctl_getenqueuespace failed %d", error);
		goto out;
	}
	os_log(OS_LOG_DEFAULT, "kctl_test_connect: ctl_getenqueuespace %ld", space);
out:
	return error;
}

static errno_t
kctl_test_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
#pragma unused(unitinfo)
	errno_t error = 0;
	size_t space;

	os_log(OS_LOG_DEFAULT, "kctl_test_disconnect: ref %p", kctlref);

	error = ctl_getenqueuespace(kctlref, unit, &space);
	if (error != 0) {
		os_log(OS_LOG_DEFAULT, "kctl_test_disconnect; ctl_getenqueuespace failed %d", error);
		goto out;
	}
	os_log(OS_LOG_DEFAULT, "kctl_test_disconnect: ctl_getenqueuespace %ld", space);
out:

	return error;
}

static errno_t
kctl_test_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags)
{
#pragma unused(unitinfo, flags)
	errno_t error = 0;

	error = ctl_enqueuembuf(kctlref, unit, m, CTL_DATA_EOR);
	if (error != 0) {
		os_log(OS_LOG_DEFAULT, "kctl_test_send: ctl_enqueuembuf() failed %d", error);
		mbuf_freem(m);
	}

	return error;
}

static int optval = 0;

static errno_t
kctl_test_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
#pragma unused(unit, unitinfo)
	errno_t error = 0;

	os_log(OS_LOG_DEFAULT, "kctl_test_setopt: ref %p", kctlref);

	switch (opt) {
	case 0:
		if (len < sizeof(int)) {
			error = EINVAL;
		} else {
			optval = *(int*)data;
		}
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}

	return error;
}

static errno_t
kctl_test_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
#pragma unused(unitinfo, unit)
	errno_t error = 0;

	os_log(OS_LOG_DEFAULT, "kctl_test_getopt: ref %p", kctlref);

	switch (opt) {
	case 0:
		if (*len < sizeof(int)) {
			error = EINVAL;
		} else {
			*(int*)data = optval;
			*len = sizeof(int);
		}
		break;
	default:
		error = ENOPROTOOPT;
		break;
	}

	return error;
}

static errno_t
kctl_test_send_list(kern_ctl_ref kctlref, u_int32_t unit,
    void *unitinfo, mbuf_t m, int flags)
{
#pragma unused(unitinfo)
	errno_t error = 0;
	mbuf_t m_remain = NULL;
	uint32_t unsent_count = 0;

	error = ctl_enqueuembuf_list(kctlref, unit, m, flags, &m_remain);
	if (m_remain != NULL) {
		mbuf_t tmp = m_remain;

		while (tmp != NULL) {
			unsent_count += 1;
			tmp = mbuf_next(tmp);
		}

		mbuf_freem_list(m_remain);
	}
	if (error != 0) {
		os_log(OS_LOG_DEFAULT, "kctl_test_send_list: ctl_enqueuembuf_list() error %d unsent packets %u",
		    error, unsent_count);
	}
	return error;
}

int
kctl_test_init(void)
{
	errno_t error = 0;
	struct kern_ctl_reg kern_ctl_reg = kctl_test_reg;

	os_log(OS_LOG_DEFAULT, "kctl_test_init ctl_sendsize %u ctl_recvsize %u",
	    kctl_test_reg.ctl_sendsize, kctl_test_reg.ctl_recvsize);

	error = ctl_register(&kern_ctl_reg, &kctl_test_ref);
	if (error == 0) {
		kctl_test_id = kern_ctl_reg.ctl_id;
		os_log(OS_LOG_DEFAULT, "kctl_test_register: OK kctlref %p kctlid %x ctl_sendsize %u ctl_recvsize %u",
		    kctl_test_ref, kctl_test_id, kern_ctl_reg.ctl_sendsize, kern_ctl_reg.ctl_recvsize);
	} else {
		os_log(OS_LOG_DEFAULT, "kctl_test_register: error %d", error);
	}
	return (error == 0) ? KERN_SUCCESS : KERN_FAILURE;
}
