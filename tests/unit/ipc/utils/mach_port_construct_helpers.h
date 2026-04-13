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

#pragma once

#include <darwintest.h>
#include <mach/mach.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/mk_timer.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/code_signing.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <kern/ipc_kobject.h>

#include "mocks/mock_dynamic.h"

/*
 * Common IPC utilities for XNU tests
 *
 * This header provides standardized message structures and utilities
 * for common IPC patterns used across multiple test files.
 */


/* Additional helper macros for test assertions */
#define T_ASSERT_PORT_VALID(port, msg, ...) \
	T_EXPECT_NE_PTR(port, IPC_PORT_NULL, msg, ##__VA_ARGS__); \
	T_QUIET; T_EXPECT_NE_PTR(port, IPC_PORT_DEAD, msg, ##__VA_ARGS__)

/*
 * Security and Code Signing Utilities
 */

/* XPC domain types - in xpc/launch_private.h */
#define XPC_DOMAIN_SYSTEM 1
#define XPC_DOMAIN_PORT 7

/*
 * Port Type Testing Infrastructure
 */

/* Enum to identify port types during testing */
typedef enum {
	TEST_IOT_PORT = 0,
	TEST_IOT_REPLY_PORT,
	TEST_IOT_WEAK_REPLY_PORT,
	TEST_IOT_CONNECTION_PORT,
	TEST_IOT_EXCEPTION_PORT,
	TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	TEST_IOT_NOTIFICATION_PORT,
	// /* TODO: need to get kobjects working rdar://164033836 */
	// TEST_IOT_TIMER_PORT,
	TEST_IOT_SPECIAL_REPLY_PORT,
	TEST_IOT_SERVICE_PORT,
	TEST_IOT_WEAK_SERVICE_PORT,
	TEST_IOT_BOOTSTRAP_PORT,
	TEST_IKOT_PORT,
	TEST_PORT_TYPE_COUNT
} ipc_test_port_type_t;

/*
 * Kobject for testing
 * note: can't use a stable type because deallocating it will panic
 */
#define IPC_IKOT_TEST_TYPE IKOT_TASK_NAME

/* Port type descriptor for testing different port types */
typedef struct {
	mach_port_t (*port_ctor)(mach_port_name_t *name);
	void (*port_dtor)(mach_port_t port, mach_port_name_t name);
	char *port_type_name;
} port_type_desc_t;

/*
 * Implementation of common IPC utilities for XNU unit tests
 */

/*
 * Port Management Function helpers
 */

static inline mach_port_t
ipc_translate_and_unlock_port_name(mach_port_name_t port_name)
{
	ipc_port_t port;
	kern_return_t kr;

	kr = ipc_port_translate_receive(current_space(), port_name, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_port_translate_receive");
	ip_mq_unlock(port);

	return port;
}

static inline mach_port_t
ipc_create_receive_port_with_full_options(mach_port_options_t *opts, mach_port_name_t *out_port_name)
{
	mach_port_name_t port_name;
	kern_return_t kr;

	kr = mach_port_construct(current_space(), opts, 0, &port_name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_create_receive_port_with_full_options");

	if (out_port_name) {
		*out_port_name = port_name;
	}

	return ipc_translate_and_unlock_port_name(port_name);
}

static inline mach_port_t
ipc_create_receive_port_with_options(uint32_t mpo_flags)
{
	mach_port_options_t opts = {
		.flags = mpo_flags,
	};
	return ipc_create_receive_port_with_full_options(&opts, NULL);
}

static inline mach_port_t
ipc_create_receive_port(void)
{
	return ipc_create_receive_port_with_options(MPO_INSERT_SEND_RIGHT);
}

/*
 * Port Type Testing Infrastructure
 */

/* Port constructor implementations */
static inline mach_port_t
get_send_receive_right(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_reply_port(mach_port_name_t *port_name)
{
	mach_port_t port;
	kern_return_t kr;
	mach_port_options_t opts = {
		.flags = MPO_REPLY_PORT,
	};
	port = ipc_create_receive_port_with_full_options(&opts, port_name);
	return port;
}

static inline mach_port_t
create_connection_port(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_CONNECTION_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_name = MPO_ANONYMOUS_SERVICE,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_exception_port(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_EXCEPTION_PORT | MPO_INSERT_SEND_RIGHT,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_weak_reply_port(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_WEAK_REPLY_PORT,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_conn_with_port_array_port(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_CONNECTION_PORT_WITH_PORT_ARRAY | MPO_INSERT_SEND_RIGHT,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_notification_port(mach_port_name_t *port_name)
{
	mach_port_options_t opts = {
		.flags = MPO_NOTIFICATION_PORT | MPO_INSERT_SEND_RIGHT,
	};
	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

/* TODO: need to add support for kobjects and enable rdar://164033836 */
/*
 *  static inline mach_port_t
 *  mk_timer_create_unit(mach_port_name_t *port_name)
 *  {
 *    kern_return_t kr;
 *    ipc_port_t port;
 *
 * port_name = mk_timer_create_trap(NULL);
 *    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mk_timer_create");
 *
 *   ipc_port_translate_send(current_space(), *port_name, &port);
 *    T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_port_translate_send");
 *
 *    return port;
 *  }
 */

static inline mach_port_t
thread_get_special_reply_port_unit(mach_port_name_t *port_name)
{
	*port_name = thread_get_special_reply_port(NULL);
	return ipc_translate_and_unlock_port_name(*port_name);
}

static inline mach_port_t
create_strict_service_port(mach_port_name_t *port_name)
{
	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info64 = (user_addr_t)&sp_info,
	};

	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_weak_service_port(mach_port_name_t *port_name)
{
	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice.weak",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info64 = (user_addr_t)&sp_info,
	};

	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static inline mach_port_t
create_bootstrap_port(mach_port_name_t *port_name)
{
	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_PORT,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info64 = (user_addr_t)&sp_info,
	};

	return ipc_create_receive_port_with_full_options(&opts, port_name);
}

static mach_port_t
create_kobject_port(mach_port_name_t *port_name)
{
	kern_return_t kr;
	ipc_port_t kobject_port;

	kobject_port = ipc_kobject_alloc_port(IKO_NULL,
	    IPC_IKOT_TEST_TYPE, IPC_KOBJECT_ALLOC_MAKE_SEND);
	T_QUIET; T_EXPECT_NE_PTR(kobject_port, IP_NULL, "ipc_kobject_alloc_port");

	kr = ipc_object_copyout(current_space(), kobject_port,
	    MACH_MSG_TYPE_PORT_SEND, IPC_OBJECT_COPYOUT_FLAGS_NONE,
	    NULL, port_name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "kobject ipc_object_copyout");
	return kobject_port;
}

/* Port destructor implementations */

static void
destroy_send_recv_port(
	mach_port_t __unused port,
	mach_port_name_t port_name)
{
	kern_return_t kr;
	uint16_t srdelta = 1;
	kr = mach_port_destruct(current_space(), port_name, -srdelta, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "destroy_send_recv_port");
}

/*
 * Regular and weak reply port are not allocated with send rights by
 * default in the utils frameworks to avoid the annoying process of
 * hand-holding send-once vs. send rights.
 * This does not apply to special reply port because
 * thread_get_special_reply_port() allocates a send right.
 */
static void
destroy_recv_port(
	mach_port_t __unused port,
	mach_port_name_t port_name)
{
	kern_return_t kr;
	uint16_t srdelta = 0;
	kr = mach_port_destruct(current_space(), port_name, -srdelta, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "destroy_send_recv_port");
}

static void
destroy_kobject_port(
	mach_port_t port,
	mach_port_name_t port_name)
{
	kern_return_t kr;
	/* deallocate one send right */
	kr = mach_port_deallocate(current_space(), port_name);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "destroy_kobject_port");

	(void)ipc_kobject_dealloc_port(port, IPC_KOBJECT_NO_MSCOUNT, IPC_IKOT_TEST_TYPE);
}

/* Global port type descriptor array */
static const port_type_desc_t g_port_type_descs[] = {
	[TEST_IOT_PORT] = {
		.port_ctor = get_send_receive_right,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_PORT",
	},
	[TEST_IOT_REPLY_PORT] = {
		.port_ctor = create_reply_port,
		.port_dtor = destroy_recv_port,
		.port_type_name = "IOT_REPLY_PORT",
	},
	[TEST_IOT_WEAK_REPLY_PORT] = {
		.port_ctor = create_weak_reply_port,
		.port_dtor = destroy_recv_port,
		.port_type_name = "IOT_WEAK_REPLY_PORT",
	},
	[TEST_IOT_CONNECTION_PORT] = {
		.port_ctor = create_connection_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_CONNECTION_PORT",
	},
	[TEST_IOT_EXCEPTION_PORT] = {
		.port_ctor = create_exception_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_EXCEPTION_PORT",
	},
	[TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY] = {
		.port_ctor = create_conn_with_port_array_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_CONNECTION_PORT_WITH_PORT_ARRAY",
	},
	[TEST_IOT_NOTIFICATION_PORT] = {
		.port_ctor = create_notification_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_NOTIFICATION_PORT",
	},
	/* TODO: need to add support for kobjects and enable rdar://164033836 */
	/*
	 *  [TEST_IOT_TIMER_PORT] = {
	 *    .port_ctor = mk_timer_create_unit,
	 *    .port_type_name = "IOT_TIMER_PORT",
	 *  },
	 */
	[TEST_IOT_SPECIAL_REPLY_PORT] = {
		.port_ctor = thread_get_special_reply_port_unit,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_SPECIAL_REPLY_PORT",
	},
	[TEST_IOT_SERVICE_PORT] = {
		.port_ctor = create_strict_service_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_SERVICE_PORT",
	},
	[TEST_IOT_WEAK_SERVICE_PORT] = {
		.port_ctor = create_weak_service_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_WEAK_SERVICE_PORT",
	},
	[TEST_IOT_BOOTSTRAP_PORT] = {
		.port_ctor = create_bootstrap_port,
		.port_dtor = destroy_send_recv_port,
		.port_type_name = "IOT_BOOTSTRAP_PORT",
	},
	[TEST_IKOT_PORT] = {
		.port_ctor = create_kobject_port,
		.port_dtor = destroy_kobject_port,
		.port_type_name = "IKOT_PORT",
	},
};

static inline const port_type_desc_t *
ipc_get_all_port_types(void)
{
	return g_port_type_descs;
}

static inline size_t
ipc_get_port_type_count(void)
{
	return sizeof(g_port_type_descs) / sizeof(g_port_type_descs[0]);
}

static inline const port_type_desc_t *
ipc_get_port_type_desc(ipc_test_port_type_t type)
{
	assert(type < TEST_PORT_TYPE_COUNT);
	return &g_port_type_descs[type];
}

static inline mach_port_t
ipc_create_port_with_type(ipc_test_port_type_t type, mach_port_name_t *name)
{
	const port_type_desc_t *desc = ipc_get_port_type_desc(type);
	mach_port_t port = desc->port_ctor(name);
	T_QUIET; T_ASSERT_NE_PTR(port, (mach_port_t)MACH_PORT_NULL,
	    "port of type %s should be non-null", desc->port_type_name);
	return port;
}

void
ipc_deallocate_port(
	ipc_test_port_type_t type,
	mach_port_t port,
	mach_port_name_t name)
{
	const port_type_desc_t *desc = ipc_get_port_type_desc(type);
	desc->port_dtor(port, name);
}
