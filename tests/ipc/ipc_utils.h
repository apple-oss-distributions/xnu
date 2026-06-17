#ifndef IPC_UTILS_H
#define IPC_UTILS_H

#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_error.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/code_signing.h>

/*
 * Common IPC utilities for XNU tests
 *
 * This header provides standardized message structures and utilities
 * for common IPC patterns used across multiple test files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#if __arm64e__
#define TARGET_CPU_ARM64E true
#else
#define TARGET_CPU_ARM64E false
#endif

#define countof(arr) (sizeof(arr) / sizeof((arr)[0]))

/* Message structure for sending a single port */
typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port;
} ipc_single_port_msg_t;

/* Message structure for sending multiple ports in an array */
typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_ool_ports_descriptor_t ports_descriptor;
} ipc_port_array_msg_t;

/* Generic message structure with trailer for receiving */
typedef struct {
	mach_msg_header_t header;
	mach_msg_body_t body;
	union {
		/* Single port descriptor */
		struct {
			mach_msg_port_descriptor_t port;
		} single;

		/* Port array descriptor */
		struct {
			mach_msg_ool_ports_descriptor_t ports_descriptor;
		} array;
	} data;
	mach_msg_max_trailer_t trailer;
} ipc_receive_msg_t;

/*
 * Port Management Functions
 */

/* Create a new receive port with send right */
mach_port_t ipc_create_receive_port(void);

/* Create a receive port with specific options */
mach_port_t ipc_create_receive_port_with_options(uint32_t mpo_flags);

/* Safely deallocate a port */
void ipc_deallocate_port(mach_port_t port);

/* Insert a send right to a receive right */
kern_return_t ipc_insert_send_right(mach_port_t receive_port);

/*
 * Single Port Messaging Functions
 */

/* Send a single port to destination */
kern_return_t ipc_send_port(mach_port_t destination, mach_port_t port,
    mach_msg_type_name_t disposition);

/* Receive a single port from destination */
kern_return_t ipc_receive_port(mach_port_t destination, mach_port_t *port);

/*
 * Port Array Messaging Functions
 */

/* Send an array of ports to destination */
kern_return_t ipc_send_port_array(mach_port_t destination,
    mach_port_t *ports, mach_msg_type_number_t count,
    mach_msg_type_name_t disposition);

/* Receive an array of ports from destination */
kern_return_t ipc_receive_port_array(mach_port_t destination,
    mach_port_t **ports, mach_msg_type_number_t *count);

/*
 * Generic Messaging Functions
 */

/* Send a pre-constructed message */
kern_return_t ipc_send_message(mach_msg_header_t *msg);

/* Receive a message into a pre-allocated buffer */
kern_return_t ipc_receive_message(mach_port_t destination, ipc_receive_msg_t *msg,
    mach_msg_size_t max_size);

/*
 * Security and Code Signing Utilities
 */

/* Check if IPC hardening is disabled (CS_CONFIG_GET_OUT_OF_MY_WAY) */
bool ipc_hardening_disabled(void);

/* Check if SIP is disabled (CSR_ALLOW_UNRESTRICTED_FS) */
bool ipc_sip_disabled(void);

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
	TEST_IOT_CONNECTION_PORT,
	TEST_IOT_EXCEPTION_PORT,
	TEST_IOT_WEAK_REPLY_PORT,
	TEST_IOT_CONNECTION_PORT_WITH_PORT_ARRAY,
	TEST_IOT_NOTIFICATION_PORT,
	TEST_IOT_TIMER_PORT,
	TEST_IOT_SPECIAL_REPLY_PORT,
	TEST_IOT_SERVICE_PORT,
	TEST_IOT_WEAK_SERVICE_PORT,
	TEST_IOT_BOOTSTRAP_PORT,
	TEST_PORT_TYPE_COUNT
} ipc_test_port_type_t;

/* Port type descriptor for testing different port types */
typedef struct {
	mach_port_t (*port_ctor)(void);
	char *port_type_name;
} port_type_desc_t;

/* Get the array of all port type descriptors */
const port_type_desc_t *ipc_get_all_port_types(void);

/* Get the count of port types in the array */
size_t ipc_get_port_type_count(void);

/* Get a specific port type descriptor by enum */
const port_type_desc_t *ipc_get_port_type_desc(ipc_test_port_type_t type);

/* Create a port of the specified type with null assertion */
mach_port_t ipc_create_port_with_type(ipc_test_port_type_t type);

/*
 * Port Policy Helpers
 */

/*
 * Encode if a port type can receive notifications based on
 * pol_can_receive_notifications in ipc_policy.c
 */
bool ipc_port_type_can_receive_notifications(ipc_test_port_type_t type);

/*
 * Determine if a reply port type will cause SIGKILL when used as
 * an exception port. Returns true if SIGKILL is expected, false if
 * the port is weak (due to hardening being disabled) and will succeed.
 */
bool ipc_reply_port_causes_sigkill_as_exception_port(ipc_test_port_type_t type);

/*
 * Determine if a port type will cause SIGKILL for containment processes
 * when attempting to register for notifications. Containment processes have
 * restricted IPC capabilities, so all notification registration attempts
 * should result in SIGKILL.
 */
bool ipc_containment_notification_causes_sigkill(ipc_test_port_type_t type);

/*
 * Test Setup Utilities
 */

/*
 * Ensure mach port guard exceptions are fatal on bridgeOS.
 * On bridgeOS, TASK_EXC_GUARD_MP_FATAL is not set by default, so we need to
 * override it to ensure tests work correctly.
 */
void ipc_ensure_mach_port_guard_fatal(void);

/*
 * Fork and Expect SIGKILL Testing
 */

/* Fork and expect a block to be killed with SIGKILL */
void expect_sigkill(void (^fn)(void), const char *format_description, ...);

/* Fork and expect a block to be killed with a specific EXC_GUARD code */
void ipc_expect_exc_guard(unsigned int expected_guard_code, void (^fn)(void),
    const char *format_description, ...);

/* Fork and expect a block to exit normally (status 0, no signal) */
void assert_normal_exit(void (^fn)(void), const char *format_description, ...);

#ifdef __cplusplus
}
#endif

#endif /* IPC_UTILS_H */
