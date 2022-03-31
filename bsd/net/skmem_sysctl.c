/*
 * Copyright (c) 2017-2021 Apple Inc. All rights reserved.
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

#include <sys/sysctl.h>

__private_extern__ void
skmem_sysctl_init(void)
{
	// TCP values
	skmem_sysctl *sysctls = skmem_get_sysctls_obj(NULL);
	if (sysctls) {
		sysctls->version = SKMEM_SYSCTL_VERSION;
#define X(type, field, default_value) \
	        extern struct sysctl_oid sysctl__net_inet_tcp_##field;                          \
	        sysctls->tcp.field = *(type*)sysctl__net_inet_tcp_##field.oid_arg1;
		SKMEM_SYSCTL_TCP_LIST
#undef  X
	}
}

__private_extern__ int
skmem_sysctl_handle_int(__unused struct sysctl_oid *oidp, void *arg1,
    int arg2, struct sysctl_req *req)
{
	int changed = 0;
	int result = sysctl_io_number(req, *(int*)arg1, sizeof(int), arg1,
	    &changed);
	if (changed) {
		SYSCTL_SKMEM_UPDATE_AT_OFFSET(arg2, *(int*)arg1);
	}
	return result;
}
