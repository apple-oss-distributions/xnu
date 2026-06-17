#include "ipc_utils.h"
#include <darwintest.h>
#include <sys/csr.h>
#include <sys/types.h>
#include <sys/unistd.h>
#include <sys/sysctl.h>
#include <mach/mk_timer.h>

/*
 * Implementation of common IPC utilities for XNU tests
 *
 * Note: This implementation is designed specifically for test environments
 * and uses darwintest T_QUIET macros for internal validations.
 */

/*
 * Port Management Functions
 */

mach_port_t
ipc_create_receive_port(void)
{
	return ipc_create_receive_port_with_options(MPO_INSERT_SEND_RIGHT);
}

mach_port_t
ipc_create_receive_port_with_options(uint32_t mpo_flags)
{
	mach_port_options_t opts = {
		.flags = mpo_flags,
	};
	mach_port_name_t port;
	kern_return_t kr;

	kr = mach_port_construct(mach_task_self(), &opts, 0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_create_receive_port_with_options");

	return port;
}

void
ipc_deallocate_port(mach_port_t port)
{
	if (port != MACH_PORT_NULL) {
		kern_return_t kr = mach_port_deallocate(mach_task_self(), port);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "ipc_deallocate_port");
	}
}

kern_return_t
ipc_insert_send_right(mach_port_t receive_port)
{
	kern_return_t kr = mach_port_insert_right(mach_task_self(), receive_port,
	    receive_port, MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(kr, "ipc_insert_send_right");
	return kr;
}

/*
 * Single Port Messaging Functions
 */

kern_return_t
ipc_send_port(mach_port_t destination, mach_port_t port, mach_msg_type_name_t disposition)
{
	ipc_single_port_msg_t msg = {
		.header = {
			.msgh_remote_port = destination,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX,
			.msgh_size = sizeof(ipc_single_port_msg_t),
			.msgh_id = 0x1001  /* Single port message ID */
		},
		.body = {
			.msgh_descriptor_count = 1
		},
		.port = {
			.name = port,
			.disposition = disposition,
			.type = MACH_MSG_PORT_DESCRIPTOR
		}
	};

	return ipc_send_message(&msg.header);
}

kern_return_t
ipc_receive_port(mach_port_t destination, mach_port_t *port)
{
	ipc_receive_msg_t msg;
	kern_return_t kr;

	kr = ipc_receive_message(destination, &msg, sizeof(ipc_receive_msg_t));
	if (kr == KERN_SUCCESS) {
		if (msg.header.msgh_id == 0x1001 && msg.body.msgh_descriptor_count == 1) {
			*port = msg.data.single.port.name;
		} else {
			kr = KERN_INVALID_ARGUMENT;
		}
	}

	return kr;
}


/*
 * Port Array Messaging Functions
 */

kern_return_t
ipc_send_port_array(mach_port_t destination,
    mach_port_t *ports, mach_msg_type_number_t count,
    mach_msg_type_name_t disposition)
{
	ipc_port_array_msg_t msg = {
		.header = {
			.msgh_remote_port = destination,
			.msgh_local_port = MACH_PORT_NULL,
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX,
			.msgh_size = sizeof(ipc_port_array_msg_t),
			.msgh_id = 0x1004  /* Port array message ID */
		},
		.body = {
			.msgh_descriptor_count = 1
		},
		.ports_descriptor = {
			.address = (void*)ports,
			.count = count,
			.deallocate = FALSE,
			.disposition = disposition,
			.type = MACH_MSG_OOL_PORTS_DESCRIPTOR
		}
	};

	return ipc_send_message(&msg.header);
}

kern_return_t
ipc_receive_port_array(mach_port_t destination,
    mach_port_t **ports, mach_msg_type_number_t *count)
{
	ipc_receive_msg_t msg;
	kern_return_t kr;

	kr = ipc_receive_message(destination, &msg, sizeof(ipc_receive_msg_t));
	if (kr == KERN_SUCCESS) {
		if (msg.header.msgh_id == 0x1004 && msg.body.msgh_descriptor_count == 1) {
			*ports = (mach_port_t*)msg.data.array.ports_descriptor.address;
			*count = msg.data.array.ports_descriptor.count;
		} else {
			kr = KERN_INVALID_ARGUMENT;
		}
	}

	return kr;
}

/*
 * Generic Messaging Functions
 */

kern_return_t
ipc_send_message(mach_msg_header_t *msg)
{
	kern_return_t kr = mach_msg(msg, MACH_SEND_MSG, msg->msgh_size, 0,
	    MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	return kr;
}

kern_return_t
ipc_receive_message(mach_port_t destination, ipc_receive_msg_t *msg, mach_msg_size_t max_size)
{
	kern_return_t kr = mach_msg(&msg->header, MACH_RCV_MSG, 0, max_size,
	    destination, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	return kr;
}


/*
 * Security and Code Signing Utilities
 */

bool
ipc_hardening_disabled(void)
{
#if TARGET_OS_OSX || TARGET_OS_BRIDGE
	/*
	 * CS_CONFIG_GET_OUT_OF_MY_WAY (enabled via AMFI boot-args)
	 * disables IPC security features. Unfortunately,
	 * BATS runs with this boot-arg enabled very frequently.
	 */
	code_signing_config_t cur_cs_config = 0;
	size_t cs_config_size = sizeof(cur_cs_config);
	int result = sysctlbyname("security.codesigning.config", &cur_cs_config,
	    &cs_config_size, NULL, 0);
	if (result != 0) {
		T_QUIET; T_LOG("ipc_hardening_disabled: failed to get codesigning config, assuming not disabled");
		return false;
	}
	return (cur_cs_config & CS_CONFIG_GET_OUT_OF_MY_WAY) != 0;
#else /* TARGET_OS_OSX || TARGET_OS_BRIDGE */
	/* mach hardening is only disabled by boot-args on macOS */
	return false;
#endif
}

bool
ipc_sip_disabled(void)
{
#if TARGET_OS_OSX
	/* SIP can only be disabled on macOS, see SIP_is_enabled() */
	bool sip_disabled = (csr_check(CSR_ALLOW_UNRESTRICTED_FS) == 0);
	if (sip_disabled) {
		T_LOG("SIP DISABLED");
	}
	return sip_disabled;
#else
	return false;
#endif /* TARGET_OS_OSX */
}

/*
 * Port Type Testing Infrastructure
 */

/* Port constructor implementations */
static mach_port_t
get_send_receive_right(void)
{
	kern_return_t kr;
	mach_port_t port;

	kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_insert_right");

	return port;
}

static mach_port_t
create_reply_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	mach_port_options_t opts = {
		.flags = MPO_REPLY_PORT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct reply_port");

	return port;
}

static mach_port_t
create_connection_port(void)
{
	kern_return_t kr;
	mach_port_t conn_port;

	mach_port_options_t opts = {
		.flags = MPO_CONNECTION_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_name = MPO_ANONYMOUS_SERVICE,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct connection_port");

	return conn_port;
}

static mach_port_t
create_exception_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	mach_port_options_t opts = {
		.flags = MPO_EXCEPTION_PORT | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct exception_port");

	return port;
}

static mach_port_t
create_weak_reply_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	mach_port_options_t opts = {
		.flags = MPO_WEAK_REPLY_PORT | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct weak_reply_port");

	return port;
}

static mach_port_t
create_conn_with_port_array_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	mach_port_options_t opts = {
		.flags =
	    MPO_CONNECTION_PORT_WITH_PORT_ARRAY | MPO_INSERT_SEND_RIGHT,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct conn_with_port_array");

	return port;
}

static mach_port_t
create_notification_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	mach_port_options_t opts = { .flags = MPO_NOTIFICATION_PORT | MPO_INSERT_SEND_RIGHT };

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct notification_port");

	return port;
}

static mach_port_t
create_strict_service_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct strict_service_port");

	return port;
}

static mach_port_t
create_weak_service_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice.weak",
		.mspi_domain_type = XPC_DOMAIN_SYSTEM,
	};

	mach_port_options_t opts = {
		.flags = MPO_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct weak_service_port");

	return port;
}

static mach_port_t
create_bootstrap_port(void)
{
	kern_return_t kr;
	mach_port_t port;

	struct mach_service_port_info sp_info = {
		.mspi_string_name = "com.apple.testservice",
		.mspi_domain_type = XPC_DOMAIN_PORT,
	};

	mach_port_options_t opts = {
		.flags = MPO_STRICT_SERVICE_PORT | MPO_INSERT_SEND_RIGHT,
		.service_port_info = &sp_info,
	};

	kr = mach_port_construct(mach_task_self(), &opts, 0x0, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct bootstrap_port");

	return port;
}

/* Global port type descriptor array */
static const port_type_desc_t g_port_type_descs[] = {
	[TEST_IOT_PORT] = {
		.port_ctor = get_send_receive_right,
		.port_type_name = "IOT_PORT",
	},
	[TEST_IOT_REPLY_PORT] = {
		.port_ctor = create_reply_port,
		.port_type_name = "IOT_REPLY_PORT",
	},
	[TEST_IOT_CONNECTION_PORT] = {
		.port_ctor = create_connection_port,
		.port_type_name = "IOT_CONNECTION_PORT",
	},
	[TEST_IOT_EXCEPTION_PORT] = {
		.port_ctor = create_exception_port,
		.port_type_name = "IOT_EXCEPTION_PORT",
	},
	[TEST_IOT_WEAK_REPLY_PORT] = {
		.port_ctor = create_weak_reply_port,
		.port_type_name = "IOT_WEAK_REPLY_PORT",
	},
	[TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY] = {
		.port_ctor = create_conn_with_port_array_port,
		.port_type_name = "IOT_CONNECTION_PORT_WITH_PORT_ARRAY",
	},
	[TEST_IOT_NOTIFICATION_PORT] = {
		.port_ctor = create_notification_port,
		.port_type_name = "IOT_NOTIFICATION_PORT",
	},
	[TEST_IOT_TIMER_PORT] = {
		.port_ctor = mk_timer_create,
		.port_type_name = "IOT_TIMER_PORT",
	},
	[TEST_IOT_SPECIAL_REPLY_PORT] = {
		.port_ctor = thread_get_special_reply_port,
		.port_type_name = "IOT_SPECIAL_REPLY_PORT",
	},
	[TEST_IOT_SERVICE_PORT] = {
		.port_ctor = create_strict_service_port,
		.port_type_name = "IOT_SERVICE_PORT",
	},
	[TEST_IOT_WEAK_SERVICE_PORT] = {
		.port_ctor = create_weak_service_port,
		.port_type_name = "IOT_WEAK_SERVICE_PORT",
	},
	[TEST_IOT_BOOTSTRAP_PORT] = {
		.port_ctor = create_bootstrap_port,
		.port_type_name = "IOT_BOOTSTRAP_PORT",
	}
};

const port_type_desc_t *
ipc_get_all_port_types(void)
{
	return g_port_type_descs;
}

size_t
ipc_get_port_type_count(void)
{
	return sizeof(g_port_type_descs) / sizeof(g_port_type_descs[0]);
}

const port_type_desc_t *
ipc_get_port_type_desc(ipc_test_port_type_t type)
{
	if (type >= TEST_PORT_TYPE_COUNT) {
		return NULL;
	}
	return &g_port_type_descs[type];
}

mach_port_t
ipc_create_port_with_type(ipc_test_port_type_t type)
{
	const port_type_desc_t *desc = ipc_get_port_type_desc(type);
	mach_port_t port = desc->port_ctor();
	T_QUIET; T_ASSERT_NE(port, (mach_port_t)MACH_PORT_NULL,
	    "Failed to create port of type %s", desc->port_type_name);
	return port;
}

/*
 * Test Setup Utilities
 */

void
ipc_ensure_mach_port_guard_fatal(void)
{
#if TARGET_OS_BRIDGE
	kern_return_t kr;
	task_exc_guard_behavior_t behavior;

	/* Get current exception guard behavior */
	kr = task_get_exc_guard_behavior(mach_task_self(), &behavior);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_get_exc_guard_behavior");

	/* Clear existing MP flags and set DELIVER + FATAL */
	behavior &= ~TASK_EXC_GUARD_MP_ALL;
	behavior |= TASK_EXC_GUARD_MP_DELIVER | TASK_EXC_GUARD_MP_FATAL;

	/* Apply the new behavior */
	kr = task_set_exc_guard_behavior(mach_task_self(), behavior);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "task_set_exc_guard_behavior");
#endif /* TARGET_OS_BRIDGE */
}

/*
 * Fork and Expect SIGKILL Testing
 */

void
expect_sigkill(void (^fn)(void), const char *format_description, ...)
{
	char description[0x100];

	va_list args;
	va_start(args, format_description);
	vsnprintf(description, sizeof(description), format_description, args);
	va_end(args);

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		exit(0);
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		T_EXPECT_EQ(WTERMSIG(status), SIGKILL,
		    "%s exited with %d, expect SIGKILL", description, WTERMSIG(status));
	}
}

void
ipc_expect_exc_guard(unsigned int expected_guard_code, void (^fn)(void),
    const char *format_description, ...)
{
	char description[0x100];

	va_list args;
	va_start(args, format_description);
	vsnprintf(description, sizeof(description), format_description, args);
	va_end(args);

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		exit(0);
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");

		/* EXC_GUARD exceptions result in SIGKILL */
		T_QUIET; T_EXPECT_EQ(WTERMSIG(status), SIGKILL,
		    "%s exited with %d, expect SIGKILL", description, WTERMSIG(status));

		/* Check the exit code contains the EXC_GUARD flavor */
		unsigned int exit_code = WEXITSTATUS(status);
		unsigned int guard_flavor = (exit_code >> 0) & 0x1fffffff;  /* bits [28:0] of exit code */

		T_EXPECT_EQ(guard_flavor, expected_guard_code,
		    "%s: expected guard code 0x%x, got 0x%x",
		    description, expected_guard_code, guard_flavor);
	}
}

void
assert_normal_exit(void (^fn)(void), const char *format_description, ...)
{
	char description[0x100];

	va_list args;
	va_start(args, format_description);
	vsnprintf(description, sizeof(description), format_description, args);
	va_end(args);

	pid_t pid = fork();
	T_QUIET; T_ASSERT_POSIX_SUCCESS(pid, "fork");

	if (pid == 0) {
		fn();
		exit(0);
	} else {
		int status = 0;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(waitpid(pid, &status, 0), "waitpid");
		T_EXPECT_FALSE(WIFSIGNALED(status), "%s: should exit normally, sig=%d", description, WTERMSIG(status));
		T_QUIET; T_EXPECT_EQ(WEXITSTATUS(status), 0, "%s: should exit with 0 status=%d", description, WEXITSTATUS(status));
	}
}

/*
 * Port Policy Helpers
 */

bool
ipc_port_type_can_receive_notifications(ipc_test_port_type_t type)
{
	switch (type) {
	case TEST_IOT_PORT:
	case TEST_IOT_SERVICE_PORT:
	case TEST_IOT_BOOTSTRAP_PORT:
	case TEST_IOT_WEAK_SERVICE_PORT:
	case TEST_IOT_CONNECTION_PORT:
	case TEST_IOT_NOTIFICATION_PORT:
		return true;
	case TEST_IOT_TIMER_PORT:
	case TEST_IOT_SPECIAL_REPLY_PORT:
		return false;
	case TEST_IOT_REPLY_PORT:
		return ipc_hardening_disabled();
	default:
		/* TODO: telemetry only for now, update after enforcement */
		return true;
	}
}

bool
ipc_reply_port_causes_sigkill_as_exception_port(ipc_test_port_type_t type)
{
	/* Only reply ports are checked by this function */
	if (type != TEST_IOT_REPLY_PORT && type != TEST_IOT_SPECIAL_REPLY_PORT) {
		return false;
	}

	/*
	 * TEST_IOT_SPECIAL_REPLY_PORT always causes SIGKILL when used as
	 * an exception port, regardless of hardening status.
	 */
	if (type == TEST_IOT_SPECIAL_REPLY_PORT) {
		return true;
	}

	/*
	 * TEST_IOT_REPLY_PORT behavior depends on hardening:
	 * - With hardening disabled (macOS/Bridge with AMFI boot-args),
	 *   it acts as a "weak reply port" and succeeds.
	 * - With hardening enabled, it causes SIGKILL.
	 */
	return !ipc_hardening_disabled();
}

bool
ipc_containment_notification_causes_sigkill(ipc_test_port_type_t type)
{
	/*
	 * Containment processes should only send to IOT_NOTIFICATION_PORT
	 */
	switch (type) {
	/* reply ports cause sigkill due to reply port semantics */
	case TEST_IOT_REPLY_PORT:
		return !ipc_hardening_disabled();
	case TEST_IOT_SPECIAL_REPLY_PORT:
		return true;
	case TEST_IOT_NOTIFICATION_PORT:
		return false;
	default:
		/* telemetry only for now */
		return false;
	}
}
