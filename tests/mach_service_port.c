#include <darwintest.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <err.h>
#include <sysexits.h>

#include "notifyServer.h"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_NAMESPACE("xnu.ipc"),
    T_META_RADAR_COMPONENT_NAME("xnu"),
    T_META_RADAR_COMPONENT_VERSION("IPC"));

static mach_port_t service_port = MACH_PORT_NULL;

#define SP_CONTEXT (0x1803)
#define NEW_SP_CONTEXT (0x0318)
#define SERVICE_NAME "com.apple.testservice"
#define SERVICE_DOMAIN (1)

T_DECL(mach_service_port, "Create a port with a service port label", T_META_CHECK_LEAKS(false)) {
	mach_port_t connection_port;
	mach_port_t notify_port;
	mach_port_t previous;
	uint64_t fpid = 0;

	struct mach_service_port_info sp_info = {};

	strcpy(sp_info.mspi_string_name, SERVICE_NAME);
	sp_info.mspi_domain_type = (uint8_t)SERVICE_DOMAIN;
	kern_return_t kr;

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD | MPO_STRICT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, SP_CONTEXT, &service_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct %u", service_port);

	mach_port_options_t opts2 = {
		.flags = MPO_CONNECTION_PORT,
		.service_port_name = service_port,
	};

	kr = mach_port_construct(mach_task_self(), &opts2, 0x0, &connection_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct %u", connection_port);

	kr = mach_port_is_connection_for_service(mach_task_self(), connection_port, service_port, &fpid);
	if (kr != KERN_SUCCESS || kr != KERN_NOT_SUPPORTED) {
		T_LOG("mach_port_is_connection_for_service kr = %d, fpid = %llu", kr, fpid);
	}

	// notification port for the service port to come back on
	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &notify_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate notify_port");

	kr = mach_port_insert_right(mach_task_self(), notify_port, notify_port, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right notify_port");

	T_LOG("service port: 0x%x, notify port: 0x%x\n", service_port, notify_port);

	kr = mach_port_request_notification(mach_task_self(), service_port, MACH_NOTIFY_PORT_DESTROYED, 0, notify_port,
	    MACH_MSG_TYPE_MAKE_SEND_ONCE, &previous);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_request_notification service_port");
	T_ASSERT_EQ(previous, MACH_PORT_NULL, "previous null");

	/* Attempt to destroy port */
	kr = mach_port_destruct(mach_task_self(), service_port, 0, SP_CONTEXT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_destruct service_port");

	/*
	 * Recover the service port because the port must have been destroyed and sent the notification by now
	 */
	kr = mach_msg_server_once(notify_server, MACH_MSG_SIZE_RELIABLE, notify_port, MACH_RCV_TIMEOUT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_msg_server_once notify_port");

	T_LOG("done");
}

kern_return_t
do_mach_notify_port_destroyed(mach_port_t notify, mach_port_t name)
{
	kern_return_t kr;

	T_LOG("Received a service port destroyed notification notify = 0x%x name = 0x%x", notify, name);
	if (name == MACH_PORT_NULL) {
		T_FAIL("do_mach_notify_port_destroyed: MACH_PORT_NULL?");
	}

	if (name != service_port) {
		T_FAIL("do_mach_notify_port_destroyed: name 0x%x != service_port: 0x%x", name, service_port);
	}

	struct mach_service_port_info sp_info = {};
	kr = mach_port_get_service_port_info(mach_task_self(), service_port, &sp_info);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_get_service_port_info");

	if (strcmp(sp_info.mspi_string_name, SERVICE_NAME)) {
		T_FAIL("Service port name = %s is incorrect", sp_info.mspi_string_name);
	}
	T_ASSERT_EQ(sp_info.mspi_domain_type, SERVICE_DOMAIN, "Service domain = %u", sp_info.mspi_domain_type);

	mach_port_guard_info_t mpgi = {SP_CONTEXT};
	kr = mach_port_assert_attributes(mach_task_self(), service_port, MACH_PORT_GUARD_INFO, (mach_port_info_t)&mpgi, MACH_PORT_GUARD_INFO_COUNT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_assert_attributes");

	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_port_deleted(__unused mach_port_t notify, __unused mach_port_name_t name)
{
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_no_senders(__unused mach_port_t notify, __unused mach_port_mscount_t mscount)
{
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_send_once(__unused mach_port_t notify)
{
	return KERN_SUCCESS;
}

kern_return_t
do_mach_notify_dead_name(__unused mach_port_t notify, __unused mach_port_name_t name)
{
	return KERN_SUCCESS;
}

#define SERVICE_NAME_2 "com.apple.testservice2"
#define SERVICE_DOMAIN_2 (2)

T_DECL(mach_fake_service_port, "Create a connection port with a fake service port", T_META_CHECK_LEAKS(false))
{
	mach_port_t connection_port;
	mach_port_t fake_service_port;
	mach_port_t service_port_2;

	kern_return_t kr;

	struct mach_service_port_info sp_info = {};

	strcpy(sp_info.mspi_string_name, SERVICE_NAME_2);
	sp_info.mspi_domain_type = (uint8_t)SERVICE_DOMAIN_2;

	mach_port_options_t opts = {
		.flags = MPO_CONNECTION_PORT | MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, SP_CONTEXT, &service_port_2);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_port_construct with extra flags %u", service_port_2);

	mach_port_options_t opts2 = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD,
		.service_port_info = NULL,
	};

	kr = mach_port_construct(mach_task_self(), &opts2, SP_CONTEXT, &service_port_2);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_port_construct with missing service port info %u", service_port_2);

	mach_port_options_t opts3 = {
		.flags = MPO_INSERT_SEND_RIGHT | MPO_CONTEXT_AS_GUARD,
	};

	kr = mach_port_construct(mach_task_self(), &opts3, SP_CONTEXT, &fake_service_port);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct with missing flag %u", fake_service_port);

	struct mach_service_port_info sp_info3 = {};
	kr = mach_port_get_service_port_info(mach_task_self(), fake_service_port, &sp_info3);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_CAPABILITY, "mach_port_get_service_port_info");

	mach_port_options_t opts4 = {
		.flags = MPO_CONNECTION_PORT,
		.service_port_name = fake_service_port,
	};

	kr = mach_port_construct(mach_task_self(), &opts4, 0x0, &connection_port);
	T_ASSERT_MACH_ERROR(kr, KERN_INVALID_CAPABILITY, "mach_port_construct connection port %u", connection_port);

	T_LOG("done");
}

T_DECL(mach_dead_service_port, "Create a connection port with a dead service port", T_META_CHECK_LEAKS(false))
{
	mach_port_t connection_port;
	mach_port_t service_port_2;

	kern_return_t kr;

	struct mach_service_port_info sp_info = {};

	strcpy(sp_info.mspi_string_name, SERVICE_NAME_2);
	sp_info.mspi_domain_type = (uint8_t)SERVICE_DOMAIN_2;

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0, &service_port_2);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct %u", service_port_2);

	kr = mach_port_mod_refs(mach_task_self(), service_port_2, MACH_PORT_RIGHT_RECEIVE, -1);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs");

	mach_port_options_t opts3 = {
		.flags = MPO_CONNECTION_PORT,
		.service_port_name = service_port_2,
	};

	kr = mach_port_construct(mach_task_self(), &opts3, 0x0, &connection_port);
	T_LOG("mach_port_construct connection port kr = %d", kr);

	if (kr == KERN_INVALID_RIGHT || kr == KERN_INVALID_NAME) {
		T_PASS("Invalid service port");
	} else {
		T_FAIL("mach_port_construct incorrect return value");
	}

	T_LOG("done");
}
