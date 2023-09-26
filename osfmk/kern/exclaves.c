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

#include <mach/exclaves.h>
#include <mach/mach_traps.h>
#include <kern/misc_protos.h>
#include <kern/assert.h>
#include <kern/startup.h>


/* -------------------------------------------------------------------------- */
#pragma mark userspace entry point

kern_return_t
_exclaves_ctl_trap(struct exclaves_ctl_trap_args *uap)
{
#pragma unused(uap)
	return KERN_NOT_SUPPORTED;
}

/* -------------------------------------------------------------------------- */
#pragma mark kernel entry points

kern_return_t
exclaves_endpoint_call(ipc_port_t port, exclaves_id_t endpoint_id,
    exclaves_tag_t *tag, exclaves_error_t *error)
{
#pragma unused(port, endpoint_id, tag, error)
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_allocate_ipc_buffer(void **out_ipc_buffer)
{
#pragma unused(out_ipc_buffer)
	return KERN_NOT_SUPPORTED;
}


kern_return_t
exclaves_free_ipc_buffer(void)
{
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_thread_terminate(__unused thread_t thread)
{
	kern_return_t kr = KERN_SUCCESS;

#pragma unused(thread)

	return kr;
}

OS_CONST
void*
exclaves_get_ipc_buffer(void)
{
	return NULL;
}

kern_return_t
exclaves_register_upcall_handler(exclaves_id_t upcall_id, void *upcall_context,
    exclaves_upcall_handler_t upcall_handler)
{
#pragma unused(upcall_id, upcall_context, upcall_handler)
	return KERN_NOT_SUPPORTED;
}


kern_return_t
exclaves_boot(__unused ipc_port_t port, uint64_t flags)
{
	assert(flags == 0);
#pragma unused(flags)
#pragma unused(port)
	return KERN_NOT_SUPPORTED;
}

exclaves_status_t
exclaves_get_status(void)
{
	return EXCLAVES_STATUS_NOT_SUPPORTED;
}


void
exclaves_register_xrt_hosted_callbacks(struct XrtHosted_Callbacks *callbacks)
{
#pragma unused(callbacks)
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves ipc internals


/* -------------------------------------------------------------------------- */

#pragma mark tests


#if EXCLAVES_XNU_LOOPBACK_TESTING

static int
exclaves_loopback_ipc_test(__unused int64_t in, int64_t *out)
{
	printf("%s: SKIPPED\n", __func__);
	*out = -1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_loopback_ipc_test, exclaves_loopback_ipc_test);

static int
exclaves_loopback_tightbeam_test(__unused int64_t in, int64_t *out)
{
#pragma unused(in, out)
	printf("%s: SKIPPED\n", __func__);
	*out = -1;
	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_loopback_tightbeam_test,
    exclaves_loopback_tightbeam_test);
#endif /* EXCLAVES_XNU_LOOPBACK_TESTING */

/* Disable test code in release kernel, SYSCTL_TEST_REGISTER is not available */
#if DEVELOPMENT || DEBUG

#define EXCLAVES_ID_HELLO_EXCLAVE_EP \
    ((exclaves_id_t)EXCLAVES_XNUPROXY_EXCLAVE_HELLOEXCLAVE)

static int
exclaves_hello_exclave_test(__unused int64_t in, int64_t *out)
{
	printf("%s: SKIPPED\n", __func__);
	*out = -1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_hello_exclave_test, exclaves_hello_exclave_test);

#if EXCLAVES_XNU_UPCALL_TESTING
static int
exclaves_hello_upcall_test(__unused int64_t in, int64_t *out)
{
	printf("%s: SKIPPED\n", __func__);
	*out = -1;

	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_hello_upcall_test, exclaves_hello_upcall_test);
#endif /* EXCLAVES_XNU_UPCALL_TESTING */



#define EXCLAVES_ID_SWIFT_HELLO_EXCLAVE_EP \
    ((exclaves_id_t)EXCLAVES_XNUPROXY_EXCLAVE_HELLOTIGHTBEAM)

static int
exclaves_hello_tightbeam(bool upcall, int64_t *out)
{
#pragma unused(upcall, out)
	printf("%s: SKIPPED\n", __func__);
	*out = -1;
	return 0;
}

#define EXCLAVES_HELLO_DRIVER_INTERRUPTS_INDEX 0
#define EXCLAVES_HELLO_DRIVER_INTERRUPTS_CHECK_RET(test) if (test) { break; }

static int
exclaves_hello_driver_interrupts(uint64_t registryID, int64_t *out)
{
#pragma unused(registryID)
	printf("%s: SKIPPED\n", __func__);
	*out = -1;
	return 0;
}

static int
exclaves_hello_drivers_test(int64_t in __unused, int64_t *out)
{
	printf("%s: SKIPPED\n", __func__);
	*out = -1;
	return 0;
}
SYSCTL_TEST_REGISTER(exclaves_hello_drivers_test,
    exclaves_hello_drivers_test);

static int
exclaves_hello_tightbeam_test(__unused int64_t in, int64_t *out)
{
	return exclaves_hello_tightbeam(false, out);
}
SYSCTL_TEST_REGISTER(exclaves_hello_tightbeam_test,
    exclaves_hello_tightbeam_test);

#if EXCLAVES_XNU_TIGHTBEAM_UPCALL_TESTING
static int
exclaves_hello_tightbeam_upcall_test(__unused int64_t in, int64_t *out)
{
	return exclaves_hello_tightbeam(true, out);
}
SYSCTL_TEST_REGISTER(exclaves_hello_tightbeam_upcall_test,
    exclaves_hello_tightbeam_upcall_test);
#endif /* EXCLAVES_XNU_TIGHTBEAM_UPCALL_TESTING */

static int
exclaves_hello_driver_interrupts_test(int64_t in, int64_t *out)
{
	// in should be AppleExclaveExampleKext's registry ID
	return exclaves_hello_driver_interrupts((uint64_t)in, out);
}
SYSCTL_TEST_REGISTER(exclaves_hello_driver_interrupts_test,
    exclaves_hello_driver_interrupts_test);



static TUNABLE(bool, enable_hello_conclaves, "enable_hello_conclaves", false);

static int
exclaves_hello_conclaves_test(int64_t in, int64_t *out)
{
#pragma unused(in)
	printf("%s: SKIPPED\n", __func__);
	*out = -1;
	return KERN_SUCCESS;
}
SYSCTL_TEST_REGISTER(exclaves_hello_conclaves_test,
    exclaves_hello_conclaves_test);



#endif /* DEVELOPMENT || DEBUG */
