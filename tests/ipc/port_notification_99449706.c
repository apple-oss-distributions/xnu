/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#include <unistd.h>
#include <darwintest.h>
#include <mach/mach.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("IPC"),
	T_META_RUN_CONCURRENTLY(true));

static mach_port_t
create_voucher(void)
{
	mach_voucher_attr_recipe_data_t dummy_voucher = {
		.key                = MACH_VOUCHER_ATTR_KEY_IMPORTANCE,
		.command            = MACH_VOUCHER_ATTR_IMPORTANCE_SELF,
		.previous_voucher   = MACH_VOUCHER_NULL,
		.content_size       = 0,
	};

	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr = host_create_mach_voucher(mach_host_self(),
	    (mach_voucher_attr_raw_recipe_array_t)&dummy_voucher,
	    sizeof(dummy_voucher), &port);
	T_ASSERT_MACH_SUCCESS(kr, "alloc voucher");

	return port;
}


T_DECL(mach_port_notification_dead_name_double_free, "Test mach_port_request_notification with a dead name port")
{
	kern_return_t kr;
	mach_port_t dead_port;
	mach_port_t voucher_port;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_DEAD_NAME, &dead_port);
	T_ASSERT_MACH_SUCCESS(kr, "alloc dead port");

	voucher_port = create_voucher();
	T_ASSERT_NE(voucher_port, MACH_PORT_NULL, "voucher not null");

	/* trigger crash via double-free: see rdar://99779706 */
	mach_port_request_notification(mach_task_self(),
	    voucher_port,
	    MACH_NOTIFY_PORT_DESTROYED,
	    0, dead_port, MACH_MSG_TYPE_PORT_SEND_ONCE, 0);

	T_PASS("Kernel didn't crash!");
}
