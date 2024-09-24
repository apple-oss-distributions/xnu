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
#include <kern/recount.h>
#include <kern/startup.h>

#if CONFIG_EXCLAVES

#if CONFIG_SPTM
#include <arm64/sptm/sptm.h>
#include <arm64/hv/hv_vm.h>
#include <arm64/hv/hv_vcpu.h>
#else
#error Invalid configuration
#endif /* CONFIG_SPTM */

#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <kern/epoch_sync.h>
#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/percpu.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <kern/zalloc.h>
#include <kern/exclaves_stackshot.h>
#include <kern/exclaves_test_stackshot.h>
#include <vm/pmap.h>
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>

#include <mach/exclaves_l4.h>
#include <mach/mach_port.h>

#include <Exclaves/Exclaves.h>

#include <IOKit/IOBSD.h>

#include <xnuproxy/messages.h>

#include "exclaves_debug.h"
#include "exclaves_panic.h"
#include "exclaves_xnuproxy.h"

/* External & generated headers */
#include <xrt_hosted_types/types.h>

#if __has_include(<Tightbeam/tightbeam.h>)
#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>
#endif

#include "exclaves_resource.h"
#include "exclaves_upcalls.h"
#include "exclaves_boot.h"
#include "exclaves_inspection.h"
#include "exclaves_memory.h"
#include "exclaves_internal.h"

LCK_GRP_DECLARE(exclaves_lck_grp, "exclaves");

/* Boot lock - only used here for assertions. */
extern lck_mtx_t exclaves_boot_lock;

/*
 * Control access to exclaves. Multicore support is learned at runtime.
 */
static LCK_MTX_DECLARE(exclaves_scheduler_lock, &exclaves_lck_grp);
static bool exclaves_multicore;
#if DEVELOPMENT || DEBUG
/* boot-arg to control use of the exclaves_scheduler_lock independently of
 * whether exclaves multicore support is enabled */
static TUNABLE(bool, exclaves_smp_enabled, "exclaves_smp", true);
#else
#define exclaves_smp_enabled true
#endif

/*
 * Sent/latest offset for updating exclaves clocks
 */
typedef struct {
	union {
		/* atomic fields are used via atomic primitives */
		struct { _Atomic uint64_t sent_offset, latest_offset; } a_u64;
		_Atomic unsigned __int128 a_u128;
		/* non-atomic fields are used via local variable. this is needed to
		 * avoid undefined behavior with an atomic struct or accessing atomic
		 * fields non-atomically */
		struct { uint64_t sent_offset, latest_offset; } u64;
		unsigned __int128 u128;
	};
} exclaves_clock_t;

static exclaves_clock_t exclaves_absolute_clock, exclaves_continuous_clock;

static kern_return_t
exclaves_endpoint_call_internal(ipc_port_t port, exclaves_id_t endpoint_id);

static kern_return_t
exclaves_enter(void);
static kern_return_t
exclaves_bootinfo(uint64_t *out_boot_info, bool *early_enter);

static kern_return_t
exclaves_scheduler_init(uint64_t boot_info, uint64_t *xnuproxy_boot_info);
OS_NORETURN OS_NOINLINE
static void
exclaves_wait_for_panic(void);

static bool
exclaves_clock_needs_update(const exclaves_clock_t *clock);
static kern_return_t
exclaves_clock_update(exclaves_clock_t *clock, XrtHosted_Buffer_t *save_out_ptr, XrtHosted_Buffer_t *save_in_ptr);

static kern_return_t
exclaves_scheduler_boot(void);

static kern_return_t
exclaves_hosted_error(bool success, XrtHosted_Error_t *error);

/*
 * A static set of exclave epoch counters.
 */
static os_atomic(uint64_t) epoch_counter[XrtHosted_Counter_limit] = {};

static inline os_atomic(uint64_t) *
exclaves_get_queue_counter(const uint64_t id)
{
	return &epoch_counter[XrtHosted_Counter_fromQueueId(id)];
}

static inline os_atomic(uint64_t) *
exclaves_get_thread_counter(const uint64_t id)
{
	return &epoch_counter[XrtHosted_Counter_fromThreadId(id)];
}


/* -------------------------------------------------------------------------- */
#pragma mark exclaves debug configuration

#if DEVELOPMENT || DEBUG
TUNABLE_WRITEABLE(unsigned int, exclaves_debug, "exclaves_debug",
    exclaves_debug_show_errors);

TUNABLE_DT(exclaves_requirement_t, exclaves_relaxed_requirements, "/defaults",
    "kern.exclaves_relaxed_reqs", "exclaves_relaxed_requirements", 0,
    TUNABLE_DT_NONE);
#else
const exclaves_requirement_t exclaves_relaxed_requirements = 0;
#endif

#endif /* CONFIG_EXCLAVES */

/* -------------------------------------------------------------------------- */
#pragma mark userspace entry point

#if CONFIG_EXCLAVES
static kern_return_t
operation_boot(mach_port_name_t name, exclaves_boot_stage_t stage)
{
	if (name != MACH_PORT_NULL) {
		/* Only accept MACH_PORT_NULL for now */
		return KERN_INVALID_CAPABILITY;
	}

	/*
	 * As the boot operation itself happens outside the context of any
	 * conclave, it requires special privilege.
	 */
	if (!exclaves_has_priv(current_task(), EXCLAVES_PRIV_BOOT)) {
		return KERN_DENIED;
	}

	return exclaves_boot(stage);
}
#endif /* CONFIG_EXCLAVES */

kern_return_t
_exclaves_ctl_trap(struct exclaves_ctl_trap_args *uap)
{
#if CONFIG_EXCLAVES
	kern_return_t kr = KERN_SUCCESS;
	int error = 0;

	mach_port_name_t name = uap->name;
	exclaves_id_t identifier = uap->identifier;
	mach_vm_address_t ubuffer = uap->buffer;
	mach_vm_size_t usize = uap->size;
	mach_vm_size_t uoffset = (mach_vm_size_t)uap->identifier;
	mach_vm_size_t usize2 = uap->size2;
	mach_vm_size_t uoffset2 = uap->offset;
	task_t task = current_task();

	/*
	 * EXCLAVES_XNU_PROXY_CR_RETVAL comes from ExclavePlatform and is shared
	 * with xnu. That header is not shared with userspace. Make sure that
	 * the retval userspace picks up is the same as the one
	 * xnu/ExclavePlatform thinks it is.
	 */
	assert3p(&EXCLAVES_XNU_PROXY_CR_RETVAL((Exclaves_L4_IpcBuffer_t *)0), ==,
	    &XNUPROXY_CR_RETVAL((Exclaves_L4_IpcBuffer_t *)0));

	uint8_t operation = EXCLAVES_CTL_OP(uap->operation_and_flags);
	uint32_t flags = EXCLAVES_CTL_FLAGS(uap->operation_and_flags);
	if (flags != 0) {
		return KERN_INVALID_ARGUMENT;
	}

	/*
	 * Deal with OP_BOOT up-front as it has slightly different restrictions
	 * than the other operations.
	 */
	if (operation == EXCLAVES_CTL_OP_BOOT) {
		return operation_boot(name, (uint32_t)identifier);
	}

	/*
	 * All other operations are restricted to properly entitled tasks which
	 * can operate in the kernel domain, or those which have joined
	 * conclaves (which has its own entitlement check).
	 * If requirements are relaxed during development, tasks with no
	 * conclaves are also allowed.
	 */
	if (task_get_conclave(task) == NULL &&
	    !exclaves_has_priv(task, EXCLAVES_PRIV_KERNEL_DOMAIN) &&
	    !exclaves_requirement_is_relaxed(EXCLAVES_R_CONCLAVE_RESOURCES)) {
		return KERN_DENIED;
	}

	/*
	 * Wait for STAGE_2 boot to complete. If exclaves are unsupported,
	 * return immediately,.
	 */
	kr = exclaves_boot_wait(EXCLAVES_BOOT_STAGE_2);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (task_get_conclave(task) != NULL) {
		/*
		 * For calls from tasks that have joined conclaves, now wait until
		 * booted up to EXCLAVEKIT. If EXCLAVEKIT boot fails for some reason,
		 * KERN_NOT_SUPPORTED will be returned (on RELEASE this would panic).
		 * For testing purposes, continue even if EXCLAVEKIT fails. This is a
		 * separate call to the one above because we need to distinguish
		 * STAGE_2 NOT SUPPORTED and still wait for EXCLAVEKIT to boot if it
		 * *is* supported.
		 */
		(void) exclaves_boot_wait(EXCLAVES_BOOT_STAGE_EXCLAVEKIT);
	}

	switch (operation) {
	case EXCLAVES_CTL_OP_ENDPOINT_CALL: {
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		if (ubuffer == USER_ADDR_NULL || usize == 0 ||
		    usize != Exclaves_L4_IpcBuffer_Size) {
			return KERN_INVALID_ARGUMENT;
		}


		Exclaves_L4_IpcBuffer_t *ipcb = exclaves_get_ipc_buffer();
		/* TODO (rdar://123728529) - IPC buffer isn't freed until thread exit */
		if (!ipcb && (error = exclaves_allocate_ipc_buffer((void**)&ipcb))) {
			return error;
		}
		assert(ipcb != NULL);
		if ((error = copyin(ubuffer, ipcb, usize))) {
			return error;
		}

		if (identifier >= CONCLAVE_SERVICE_MAX) {
			return KERN_INVALID_ARGUMENT;
		}

		/*
		 * Verify that the service actually exists in the current
		 * domain.
		 */
		if (!exclaves_conclave_has_service(task_get_conclave(task),
		    identifier)) {
			return KERN_INVALID_ARGUMENT;
		}

		kr = exclaves_endpoint_call_internal(IPC_PORT_NULL, identifier);
		error = copyout(ipcb, ubuffer, usize);
		/*
		 * Endpoint call to conclave may have trigger a stop upcall,
		 * check if stop upcall completion handler needs to run.
		 */
		task_stop_conclave_upcall_complete();
		if (error) {
			return error;
		}
		break;
	}

	case EXCLAVES_CTL_OP_NAMED_BUFFER_CREATE: {
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}

		size_t len = 0;
		char id_name[EXCLAVES_RESOURCE_NAME_MAX] = "";
		if (copyinstr(identifier, id_name, EXCLAVES_RESOURCE_NAME_MAX,
		    &len) != 0 || id_name[0] == '\0') {
			return KERN_INVALID_ARGUMENT;
		}

		exclaves_buffer_perm_t perm = (exclaves_buffer_perm_t)usize2;
		const exclaves_buffer_perm_t supported =
		    EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE;
		if ((perm & supported) == 0 || (perm & ~supported) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		const char *domain = exclaves_conclave_get_domain(task_get_conclave(task));
		const bool new_api =
		    (perm == EXCLAVES_BUFFER_PERM_READ) ||
		    (perm == EXCLAVES_BUFFER_PERM_WRITE);
		const bool shared_mem_available =
		    exclaves_resource_lookup_by_name(domain, id_name,
		    XNUPROXY_RESOURCETYPE_SHAREDMEMORY) != NULL;
		const bool use_shared_mem = new_api && shared_mem_available;

		exclaves_resource_t *resource = NULL;
		kr = use_shared_mem ?
		    exclaves_resource_shared_memory_map(domain, id_name, usize, perm, &resource) :
		    exclaves_named_buffer_map(domain, id_name, usize, perm, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = exclaves_resource_create_port_name(resource,
		    current_space(), &name);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&name, ubuffer, sizeof(mach_port_name_t));
		if (kr != KERN_SUCCESS) {
			mach_port_deallocate(current_space(), name);
			return kr;
		}

		break;
	}

	case EXCLAVES_CTL_OP_NAMED_BUFFER_COPYIN: {
		exclaves_resource_t *resource = NULL;
		kr = exclaves_resource_from_port_name(current_space(), name,
		    &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		switch (resource->r_type) {
		case XNUPROXY_RESOURCETYPE_NAMEDBUFFER:
			kr = exclaves_named_buffer_copyin(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCETYPE_SHAREDMEMORY:
			kr = exclaves_resource_shared_memory_copyin(resource,
			    ubuffer, usize, uoffset, usize2, uoffset2);
			break;

		default:
			exclaves_resource_release(resource);
			return KERN_INVALID_CAPABILITY;
		}

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}
		break;
	}

	case EXCLAVES_CTL_OP_NAMED_BUFFER_COPYOUT: {
		exclaves_resource_t *resource = NULL;
		kr = exclaves_resource_from_port_name(current_space(), name,
		    &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		switch (resource->r_type) {
		case XNUPROXY_RESOURCETYPE_NAMEDBUFFER:
			kr = exclaves_named_buffer_copyout(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCETYPE_SHAREDMEMORY:
			kr = exclaves_resource_shared_memory_copyout(resource,
			    ubuffer, usize, uoffset, usize2, uoffset2);
			break;

		default:
			exclaves_resource_release(resource);
			return KERN_INVALID_CAPABILITY;
		}

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}
		break;
	}

	case EXCLAVES_CTL_OP_LAUNCH_CONCLAVE:
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		kr = task_launch_conclave(name);

		/*
		 * Conclave launch call to may have trigger a stop upcall,
		 * check if stop upcall completion handler needs to run.
		 */
		task_stop_conclave_upcall_complete();
		break;

	case EXCLAVES_CTL_OP_LOOKUP_SERVICES: {
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		struct exclaves_resource_user uresource = {};

		if (usize > (MAX_CONCLAVE_RESOURCE_NUM * sizeof(struct exclaves_resource_user)) ||
		    (usize % sizeof(struct exclaves_resource_user) != 0)) {
			return KERN_INVALID_ARGUMENT;
		}

		if ((ubuffer == USER_ADDR_NULL && usize != 0) ||
		    (usize == 0 && ubuffer != USER_ADDR_NULL)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (ubuffer == USER_ADDR_NULL) {
			return KERN_INVALID_ARGUMENT;
		}

		/* For the moment we only ever have to deal with one request. */
		if (usize != sizeof(struct exclaves_resource_user)) {
			return KERN_INVALID_ARGUMENT;
		}
		error = copyin(ubuffer, &uresource, usize);
		if (error) {
			return KERN_INVALID_ARGUMENT;
		}

		const size_t name_buf_len = sizeof(uresource.r_name);
		if (strnlen(uresource.r_name, name_buf_len) == name_buf_len) {
			return KERN_INVALID_ARGUMENT;
		}

		/*
		 * Do the regular lookup first. If that fails, fallback to the
		 * DARWIN domain, finally fallback to the KERNEL domain.
		 */
		const char *domain = exclaves_conclave_get_domain(task_get_conclave(task));
		uint64_t id = exclaves_service_lookup(domain, uresource.r_name);

		if (exclaves_requirement_is_relaxed(EXCLAVES_R_CONCLAVE_RESOURCES) ||
		    exclaves_has_priv(task, EXCLAVES_PRIV_KERNEL_DOMAIN)) {
			if (id == EXCLAVES_INVALID_ID) {
				id = exclaves_service_lookup(EXCLAVES_DOMAIN_DARWIN,
				    uresource.r_name);
			}
			if (id == EXCLAVES_INVALID_ID) {
				id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL,
				    uresource.r_name);
			}
		}

		if (id == EXCLAVES_INVALID_ID) {
			return KERN_NOT_FOUND;
		}

		uresource.r_id = id;
		uresource.r_port = MACH_PORT_NULL;

		error = copyout(&uresource, ubuffer, usize);
		if (error) {
			return KERN_INVALID_ADDRESS;
		}

		kr = KERN_SUCCESS;
		break;
	}

	case EXCLAVES_CTL_OP_AUDIO_BUFFER_CREATE: {
		if (identifier == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/* copy in string name */
		char id_name[EXCLAVES_RESOURCE_NAME_MAX] = "";
		size_t done = 0;
		if (copyinstr(identifier, id_name, EXCLAVES_RESOURCE_NAME_MAX, &done) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		const char *domain = exclaves_conclave_get_domain(task_get_conclave(task));
		const bool use_audio_memory =
		    exclaves_resource_lookup_by_name(domain, id_name,
		    XNUPROXY_RESOURCETYPE_ARBITRATEDAUDIOMEMORY) != NULL;
		exclaves_resource_t *resource = NULL;
		kr = use_audio_memory ?
		    exclaves_resource_audio_memory_map(domain, id_name, usize, &resource) :
		    exclaves_audio_buffer_map(domain, id_name, usize, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = exclaves_resource_create_port_name(resource, current_space(),
		    &name);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&name, ubuffer, sizeof(mach_port_name_t));
		if (kr != KERN_SUCCESS) {
			mach_port_deallocate(current_space(), name);
			return kr;
		}

		break;
	}

	case EXCLAVES_CTL_OP_AUDIO_BUFFER_COPYOUT: {
		exclaves_resource_t *resource;

		kr = exclaves_resource_from_port_name(current_space(), name, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		switch (resource->r_type) {
		case XNUPROXY_RESOURCETYPE_ARBITRATEDAUDIOBUFFER:
			kr = exclaves_audio_buffer_copyout(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCETYPE_ARBITRATEDAUDIOMEMORY:
			kr = exclaves_resource_audio_memory_copyout(resource,
			    ubuffer, usize, uoffset, usize2, uoffset2);
			break;

		default:
			exclaves_resource_release(resource);
			return KERN_INVALID_CAPABILITY;
		}

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		break;
	}

	case EXCLAVES_CTL_OP_SENSOR_CREATE: {
		if (identifier == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/* copy in string name */
		char id_name[EXCLAVES_RESOURCE_NAME_MAX] = "";
		size_t done = 0;
		if (copyinstr(identifier, id_name, EXCLAVES_RESOURCE_NAME_MAX, &done) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		const char *domain = exclaves_conclave_get_domain(task_get_conclave(task));
		exclaves_resource_t *resource = NULL;
		kr = exclaves_resource_sensor_open(domain, id_name, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = exclaves_resource_create_port_name(resource, current_space(),
		    &name);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&name, ubuffer, sizeof(mach_port_name_t));
		if (kr != KERN_SUCCESS) {
			/* No senders drops the reference. */
			mach_port_deallocate(current_space(), name);
			return kr;
		}

		break;
	}

	case EXCLAVES_CTL_OP_SENSOR_START: {
		exclaves_resource_t *resource;
		kr = exclaves_resource_from_port_name(current_space(), name, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (resource->r_type != XNUPROXY_RESOURCETYPE_SENSOR) {
			exclaves_resource_release(resource);
			return KERN_FAILURE;
		}

		exclaves_sensor_status_t status;
		kr = exclaves_resource_sensor_start(resource, identifier, &status);

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&status, ubuffer, sizeof(exclaves_sensor_status_t));

		break;
	}
	case EXCLAVES_CTL_OP_SENSOR_STOP: {
		exclaves_resource_t *resource;
		kr = exclaves_resource_from_port_name(current_space(), name, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (resource->r_type != XNUPROXY_RESOURCETYPE_SENSOR) {
			exclaves_resource_release(resource);
			return KERN_FAILURE;
		}

		exclaves_sensor_status_t status;
		kr = exclaves_resource_sensor_stop(resource, identifier, &status);

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&status, ubuffer, sizeof(exclaves_sensor_status_t));

		break;
	}
	case EXCLAVES_CTL_OP_SENSOR_STATUS: {
		exclaves_resource_t *resource;
		kr = exclaves_resource_from_port_name(current_space(), name, &resource);
		if (kr != KERN_SUCCESS) {
			return kr;
		}

		if (resource->r_type != XNUPROXY_RESOURCETYPE_SENSOR) {
			exclaves_resource_release(resource);
			return KERN_FAILURE;
		}


		exclaves_sensor_status_t status;
		kr = exclaves_resource_sensor_status(resource, identifier, &status);

		exclaves_resource_release(resource);

		if (kr != KERN_SUCCESS) {
			return kr;
		}

		kr = copyout(&status, ubuffer, sizeof(exclaves_sensor_status_t));
		break;
	}
	case EXCLAVES_CTL_OP_NOTIFICATION_RESOURCE_LOOKUP: {
		exclaves_resource_t *notification_resource = NULL;
		mach_port_name_t port_name = MACH_PORT_NULL;

		struct exclaves_resource_user *notification_resource_user = NULL;
		if (usize != sizeof(struct exclaves_resource_user)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (ubuffer == USER_ADDR_NULL) {
			return KERN_INVALID_ARGUMENT;
		}

		notification_resource_user = (struct exclaves_resource_user *)
		    kalloc_data(usize, Z_WAITOK | Z_ZERO | Z_NOFAIL);

		error = copyin(ubuffer, notification_resource_user, usize);
		if (error) {
			kr = KERN_INVALID_ARGUMENT;
			goto notification_resource_lookup_out;
		}

		const size_t name_buf_len = sizeof(notification_resource_user->r_name);
		if (strnlen(notification_resource_user->r_name, name_buf_len)
		    == name_buf_len) {
			kr = KERN_INVALID_ARGUMENT;
			goto notification_resource_lookup_out;
		}

		const char *domain = exclaves_conclave_get_domain(task_get_conclave(task));
		kr = exclaves_notification_create(domain,
		    notification_resource_user->r_name, &notification_resource);
		if (kr != KERN_SUCCESS) {
			goto notification_resource_lookup_out;
		}

		kr = exclaves_resource_create_port_name(notification_resource,
		    current_space(), &port_name);
		if (kr != KERN_SUCCESS) {
			goto notification_resource_lookup_out;
		}
		notification_resource_user->r_type = notification_resource->r_type;
		notification_resource_user->r_id = notification_resource->r_id;
		notification_resource_user->r_port = port_name;
		error = copyout(notification_resource_user, ubuffer, usize);
		if (error) {
			kr = KERN_INVALID_ADDRESS;
			goto notification_resource_lookup_out;
		}

notification_resource_lookup_out:
		if (notification_resource_user != NULL) {
			kfree_data(notification_resource_user, usize);
		}
		if (kr != KERN_SUCCESS && port_name != MACH_PORT_NULL) {
			mach_port_deallocate(current_space(), port_name);
		}
		break;
	}

	default:
		kr = KERN_INVALID_ARGUMENT;
		break;
	}

	return kr;
#else /* CONFIG_EXCLAVES */
#pragma unused(uap)
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_EXCLAVES */
}

/* -------------------------------------------------------------------------- */
#pragma mark kernel entry points

kern_return_t
exclaves_endpoint_call(ipc_port_t port, exclaves_id_t endpoint_id,
    exclaves_tag_t *tag, exclaves_error_t *error)
{
#if CONFIG_EXCLAVES
	kern_return_t kr = KERN_SUCCESS;
	assert(port == IPC_PORT_NULL);

	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();
	assert(ipcb != NULL);

	exclaves_debug_printf(show_progress,
	    "exclaves: endpoint call:\tendpoint id %lld tag 0x%llx\n",
	    endpoint_id, *tag);

	ipcb->mr[Exclaves_L4_Ipc_Mr_Tag] = *tag;
	kr = exclaves_endpoint_call_internal(port, endpoint_id);
	*tag = ipcb->mr[Exclaves_L4_Ipc_Mr_Tag];
	*error = XNUPROXY_CR_RETVAL(ipcb);

	exclaves_debug_printf(show_progress,
	    "exclaves: endpoint call return:\tendpoint id %lld tag 0x%llx "
	    "error 0x%llx\n", endpoint_id, *tag, *error);

	return kr;
#else /* CONFIG_EXCLAVES */
#pragma unused(port, endpoint_id, tag, error)
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_EXCLAVES */
}

kern_return_t
exclaves_allocate_ipc_buffer(void **out_ipc_buffer)
{
#if CONFIG_EXCLAVES
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();

	if (thread->th_exclaves_ipc_ctx.ipcb == NULL) {
		assert(thread->th_exclaves_ipc_ctx.usecnt == 0);
		kr = exclaves_xnuproxy_ctx_alloc(&thread->th_exclaves_ipc_ctx);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
		assert(thread->th_exclaves_ipc_ctx.usecnt == 0);
	}
	thread->th_exclaves_ipc_ctx.usecnt++;

	if (out_ipc_buffer != NULL) {
		*out_ipc_buffer = thread->th_exclaves_ipc_ctx.ipcb;
	}
	return KERN_SUCCESS;
#else /* CONFIG_EXCLAVES */
#pragma unused(out_ipc_buffer)
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_EXCLAVES */
}

kern_return_t
exclaves_free_ipc_buffer(void)
{
#if CONFIG_EXCLAVES

	/* The inspection thread's cached buffer should never be freed */
	thread_t thread = current_thread();

	/* Don't try to free unallocated contexts. */
	if (thread->th_exclaves_ipc_ctx.ipcb == NULL) {
		return KERN_SUCCESS;
	}

	const thread_exclaves_inspection_flags_t iflags =
	    os_atomic_load(&thread->th_exclaves_inspection_state, relaxed);
	if ((iflags & TH_EXCLAVES_INSPECTION_NOINSPECT) != 0) {
		return KERN_SUCCESS;
	}

	assert(thread->th_exclaves_ipc_ctx.usecnt > 0);
	if (--thread->th_exclaves_ipc_ctx.usecnt > 0) {
		return KERN_SUCCESS;
	}

	return exclaves_xnuproxy_ctx_free(&thread->th_exclaves_ipc_ctx);
#else /* CONFIG_EXCLAVES */
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_EXCLAVES */
}

kern_return_t
exclaves_thread_terminate(__unused thread_t thread)
{
	kern_return_t kr = KERN_SUCCESS;

#if CONFIG_EXCLAVES
	assert(thread == current_thread());
	assert(thread->th_exclaves_intstate == 0);
	assert(thread->th_exclaves_state == 0);
	if (thread->th_exclaves_ipc_ctx.ipcb != NULL) {
		exclaves_debug_printf(show_progress,
		    "exclaves: thread_terminate freeing abandoned exclaves "
		    "ipc buffer\n");
		/* Unconditionally free context irrespective of usecount */
		thread->th_exclaves_ipc_ctx.usecnt = 0;
		kr = exclaves_xnuproxy_ctx_free(&thread->th_exclaves_ipc_ctx);
		assert(kr == KERN_SUCCESS);
	}
#else
#pragma unused(thread)
#endif /* CONFIG_EXCLAVES */

	return kr;
}

OS_CONST
void*
exclaves_get_ipc_buffer(void)
{
#if CONFIG_EXCLAVES
	thread_t thread = current_thread();
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_ctx.ipcb;

	return ipcb;
#else /* CONFIG_EXCLAVES */
	return NULL;
#endif /* CONFIG_EXCLAVES */
}

#if CONFIG_EXCLAVES

static void
bind_to_boot_core(void)
{
	/*
	 * First ensure the boot cluster isn't powered down preventing the
	 * thread from running at all.
	 */
	suspend_cluster_powerdown();
	const int cpu = ml_get_boot_cpu_number();
	processor_t processor = cpu_to_processor(cpu);
	assert3p(processor, !=, NULL);
	__assert_only processor_t old = thread_bind(processor);
	assert3p(old, ==, PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);
}

static void
unbind_from_boot_core(void)
{
	/* Unbind the thread from the boot CPU. */
	thread_bind(PROCESSOR_NULL);
	thread_block(THREAD_CONTINUE_NULL);
	resume_cluster_powerdown();
}

extern kern_return_t exclaves_boot_early(void);
kern_return_t
exclaves_boot_early(void)
{
	kern_return_t kr = KERN_FAILURE;
	uint64_t boot_info = 0;
	bool early_enter = false;

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	kr = exclaves_bootinfo(&boot_info, &early_enter);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Get bootinfo failed\n");
		return kr;
	}

	if (early_enter) {
		thread_t thread = current_thread();
		assert3u(thread->th_exclaves_state & TH_EXCLAVES_STATE_ANY, ==, 0);

		bind_to_boot_core();

		disable_preemption_without_measurements();
		thread->th_exclaves_state |= TH_EXCLAVES_SCHEDULER_CALL;

		kr = exclaves_enter();

		thread->th_exclaves_state &= ~TH_EXCLAVES_SCHEDULER_CALL;
		enable_preemption();

		unbind_from_boot_core();

		if (kr != KERN_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "exclaves: early exclaves enter failed\n");
			if (kr == KERN_ABORTED) {
				panic("Unexpected ringgate panic status");
			}
			return kr;
		}
	}

	uint64_t xnuproxy_boot_info = 0;
	kr = exclaves_scheduler_init(boot_info, &xnuproxy_boot_info);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Init scheduler failed\n");
		return kr;
	}

	kr = exclaves_xnuproxy_init(xnuproxy_boot_info);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "XNU proxy setup failed\n");
		return KERN_FAILURE;
	}

	kr = exclaves_panic_thread_setup();
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "XNU proxy panic thread setup failed\n");
		return KERN_FAILURE;
	}

	kr = exclaves_resource_init();
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: failed to initialize resources\n");
		return kr;
	}

	return KERN_SUCCESS;
}
#endif /* CONFIG_EXCLAVES */

#if CONFIG_EXCLAVES
static struct XrtHosted_Callbacks *exclaves_callbacks = NULL;
#endif /* CONFIG_EXCLAVES */

void
exclaves_register_xrt_hosted_callbacks(struct XrtHosted_Callbacks *callbacks)
{
#if CONFIG_EXCLAVES
	if (exclaves_callbacks == NULL) {
		exclaves_callbacks = callbacks;
	}
#else /* CONFIG_EXCLAVES */
#pragma unused(callbacks)
#endif /* CONFIG_EXCLAVES */
}

void
exclaves_update_timebase(exclaves_clock_type_t type, uint64_t offset)
{
#if CONFIG_EXCLAVES
	exclaves_clock_t *clock = (type == EXCLAVES_CLOCK_ABSOLUTE ?
	    &exclaves_absolute_clock : &exclaves_continuous_clock);
	uint64_t latest_offset = os_atomic_load(&clock->a_u64.latest_offset, relaxed);
	while (latest_offset < offset) {
		/* Update the latest offset with the new offset. If this fails, then a
		 * concurrent update occurred and our offset may be stale. */
		if (os_atomic_cmpxchgv(&clock->a_u64.latest_offset, latest_offset,
		    offset, &latest_offset, relaxed)) {
			break;
		}
	}
#else
#pragma unused(type, offset)
#endif /* CONFIG_EXCLAVES */
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves ipc internals

#if CONFIG_EXCLAVES

static kern_return_t
exclaves_endpoint_call_internal(__unused ipc_port_t port,
    exclaves_id_t endpoint_id)
{
	kern_return_t kr = KERN_SUCCESS;

	assert(port == IPC_PORT_NULL);

	kr = exclaves_xnuproxy_endpoint_call(endpoint_id);

	return kr;
}

/* -------------------------------------------------------------------------- */
#pragma mark secure kernel communication

/* ringgate entry endpoints */
enum {
	RINGGATE_EP_ENTER,
	RINGGATE_EP_INFO
};

/* ringgate entry status codes */
enum {
	RINGGATE_STATUS_SUCCESS,
	RINGGATE_STATUS_ERROR,
	RINGGATE_STATUS_PANIC, /* RINGGATE_EP_ENTER: Another core paniced */
};

OS_NOINLINE
static kern_return_t
exclaves_enter(void)
{
	uint32_t endpoint = RINGGATE_EP_ENTER;
	uint64_t result = RINGGATE_STATUS_ERROR;

	sptm_call_regs_t regs = { };

	__assert_only thread_t thread = current_thread();

	/*
	 * Should never re-enter exclaves.
	 */
	if ((thread->th_exclaves_state & TH_EXCLAVES_UPCALL) != 0 ||
	    (thread->th_exclaves_state & TH_EXCLAVES_SCHEDULER_REQUEST) != 0) {
		panic("attempt to re-enter exclaves");
	}

	/*
	 * Must have one (and only one) of the flags set to enter exclaves.
	 */
	__assert_only const thread_exclaves_state_flags_t mask = (
		TH_EXCLAVES_RPC |
		TH_EXCLAVES_XNUPROXY |
		TH_EXCLAVES_SCHEDULER_CALL);
	assert3u(thread->th_exclaves_state & mask, !=, 0);
	assert3u(thread->th_exclaves_intstate & TH_EXCLAVES_EXECUTION, ==, 0);

#if MACH_ASSERT
	/*
	 * Set the ast to check that the thread doesn't return to userspace
	 * while in an RPC or XNUPROXY call.
	 */
	act_set_debug_assert();
#endif /* MACH_ASSERT */

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_SWITCH)
	    | DBG_FUNC_START);

	recount_enter_secure();

	/* xnu_return_to_gl2 relies on this flag being present to correctly return
	 * to SK from interrupts xnu handles on behalf of SK. */
	thread->th_exclaves_intstate |= TH_EXCLAVES_EXECUTION;

	/*
	 * Bracket with labels so stackshot can determine where exclaves are
	 * entered from xnu.
	 */
	__asm__ volatile (
            "EXCLAVES_ENTRY_START: nop\n\t"
        );
	result = sk_enter(endpoint, &regs);
	__asm__ volatile (
            "EXCLAVES_ENTRY_END: nop\n\t"
        );

	thread->th_exclaves_intstate &= ~TH_EXCLAVES_EXECUTION;

	recount_leave_secure();

#if CONFIG_SPTM
	/**
	 * SPTM will return here with debug exceptions disabled (MDSCR_{KDE,MDE} == {0,0})
	 * but SK might have clobbered individual breakpoints, etc. Invalidate the current CPU
	 * debug state forcing a reload on the next return to user mode.
	 */
	if (__improbable(getCpuDatap()->cpu_user_debug != NULL)) {
		arm_debug_set(NULL);
	}
#endif /* CONFIG_SPTM */

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_SWITCH)
	    | DBG_FUNC_END);

	switch (result) {
	case RINGGATE_STATUS_SUCCESS:
		return KERN_SUCCESS;
	case RINGGATE_STATUS_ERROR:
		return KERN_FAILURE;
	case RINGGATE_STATUS_PANIC:
		return KERN_ABORTED;
	default:
		assertf(false, "Unknown ringgate status %llu", result);
		__builtin_trap();
	}
}


/*
 * A bit in the lower byte of the value returned by RINGGATE_EP_INFO. If set,
 * it in indicates that we should immediately enter the ringgate once in order
 * to allow the scheduler to perform early boot initialisation.
 */
#define EARLY_RINGGATE_ENTER 2

OS_NOINLINE
static kern_return_t
exclaves_bootinfo(uint64_t *out_boot_info, bool *early_enter)
{
	uint32_t endpoint = RINGGATE_EP_INFO;
	uint64_t result = RINGGATE_STATUS_ERROR;

	sptm_call_regs_t regs = { };

	recount_enter_secure();
	result = sk_enter(endpoint, &regs);
	recount_leave_secure();
	if (result == RINGGATE_STATUS_ERROR) {
		return KERN_FAILURE;
	}

	*early_enter = (result & EARLY_RINGGATE_ENTER) != 0;
	*out_boot_info = result & ~EARLY_RINGGATE_ENTER;

	return KERN_SUCCESS;
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves scheduler communication

static XrtHosted_Buffer_t * PERCPU_DATA(exclaves_request);
static XrtHosted_Buffer_t * PERCPU_DATA(exclaves_response);

static void
exclaves_init_multicore(void)
{
	assert(exclaves_multicore);

	XrtHosted_Buffer_t **req, **res;

	exclaves_wait_for_cpu_init();

	DTEntry entry, child;
	OpaqueDTEntryIterator iter;
	int err = SecureDTLookupEntry(NULL, "/cpus", &entry);
	assert(err == kSuccess);
	err = SecureDTInitEntryIterator(entry, &iter);
	assert(err == kSuccess);

	bool exclaves_uses_mpidr = (exclaves_callbacks->v1.global()->v2.smpStatus == XrtHosted_SmpStatus_MulticoreMpidr);
	if (exclaves_uses_mpidr) {
		exclaves_debug_printf(show_progress, "Using MPIDR for exclave scheduler core IDs\n");
	} else {
		// TODO(rdar://120679733) - clean up non-MPIDR identification logic.
		exclaves_debug_printf(show_progress, "Not using MPIDR for exclave scheduler core IDs\n");
	}

	/*
	 * Match the hardwareID to the physical ID and stash the pointers to the
	 * request/response buffers in per-cpu data for quick access.
	 */
	size_t core_count = exclaves_callbacks->v1.cores();
	for (size_t i = 0; i < core_count; i++) {
		const XrtHosted_Core_t *core = exclaves_callbacks->v1.core(i);
		uint32_t dt_phys_id = 0;
		if (exclaves_uses_mpidr) {
			dt_phys_id = (uint32_t)core->v2.hardwareId;
		} else {
			/* Find the physical ID of the entry at position hardwareId in the
			 * DeviceTree "cpus" array */
			uint32_t dt_index = 0;
			bool dt_entry_found = false;
			err = SecureDTRestartEntryIteration(&iter);
			assert(err == kSuccess);
			while (kSuccess == SecureDTIterateEntries(&iter, &child)) {
				if (core->v2.hardwareId == dt_index) {
					void const *dt_prop;
					unsigned int dt_prop_sz;
					err = SecureDTGetProperty(child, "reg", &dt_prop, &dt_prop_sz);
					assert(err == kSuccess);
					assert(dt_prop_sz == sizeof(uint32_t));
					dt_phys_id = *((uint32_t const *)dt_prop);
					dt_entry_found = true;
					break;
				}
				dt_index++;
			}
			if (!dt_entry_found) {
				continue;
			}
		}
		percpu_foreach(cpu_data, cpu_data) {
			if (cpu_data->cpu_phys_id != dt_phys_id) {
				continue;
			}
			req = PERCPU_GET_RELATIVE(exclaves_request, cpu_data, cpu_data);
			*req = exclaves_callbacks->v1.Core.request(i);

			res = PERCPU_GET_RELATIVE(exclaves_response, cpu_data, cpu_data);
			*res = exclaves_callbacks->v1.Core.response(i);

			break;
		}
	}
}

static void
exclaves_init_unicore(void)
{
	assert(!exclaves_multicore);

	XrtHosted_Buffer_t *breq, *bres, **req, **res;

	exclaves_wait_for_cpu_init();

	breq = exclaves_callbacks->v1.Core.request(XrtHosted_Core_bootIndex);
	bres = exclaves_callbacks->v1.Core.response(XrtHosted_Core_bootIndex);

	/* Always use the boot request/response buffers. */
	percpu_foreach(cpu_data, cpu_data) {
		req = PERCPU_GET_RELATIVE(exclaves_request, cpu_data, cpu_data);
		*req = breq;

		res = PERCPU_GET_RELATIVE(exclaves_response, cpu_data, cpu_data);
		*res = bres;
	}
}

static kern_return_t
exclaves_scheduler_init(uint64_t boot_info, uint64_t *xnuproxy_boot_info)
{
	kern_return_t kr = KERN_SUCCESS;
	XrtHosted_Error_t hosted_error;

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	if (!pmap_valid_address(boot_info)) {
		exclaves_debug_printf(show_errors,
		    "exclaves: %s: 0x%012llx\n",
		    "Invalid root physical address",
		    boot_info);
		return KERN_FAILURE;
	}

	if (exclaves_callbacks == NULL) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Callbacks not registered\n");
		return KERN_FAILURE;
	}

	/* Initialise XrtHostedXnu kext */
	kr = exclaves_hosted_error(
		exclaves_callbacks->v1.init(
			XrtHosted_Version_current,
			phystokv(boot_info),
			&hosted_error),
		&hosted_error);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	/* Record aperture addresses in buffer */
	size_t frames = exclaves_callbacks->v1.frames();
	XrtHosted_Mapped_t **pages = zalloc_permanent(
		frames * sizeof(XrtHosted_Mapped_t *),
		ZALIGN(XrtHosted_Mapped_t *));
	size_t index = 0;
	uint64_t phys = boot_info;
	while (index < frames) {
		if (!pmap_valid_address(phys)) {
			exclaves_debug_printf(show_errors,
			    "exclaves: %s: 0x%012llx\n",
			    "Invalid shared physical address",
			    phys);
			return KERN_FAILURE;
		}
		pages[index] = (XrtHosted_Mapped_t *)phystokv(phys);
		kr = exclaves_hosted_error(
			exclaves_callbacks->v1.nextPhys(
				pages[index],
				&index,
				&phys,
				&hosted_error),
			&hosted_error);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	}

	/* Initialise the mapped region */
	exclaves_callbacks->v1.setMapping(
		XrtHosted_Region_scattered(frames, pages));

	/* Boot the scheduler. */
	kr = exclaves_scheduler_boot();
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	XrtHosted_Global_t *global = exclaves_callbacks->v1.global();

	exclaves_multicore = (global->v2.smpStatus ==
	    XrtHosted_SmpStatus_Multicore ||
	    global->v2.smpStatus == XrtHosted_SmpStatus_MulticoreMpidr);
	exclaves_multicore ? exclaves_init_multicore() : exclaves_init_unicore();

	/* Initialise the XNU proxy */
	if (!pmap_valid_address(global->v1.proxyInit)) {
		exclaves_debug_printf(show_errors,
		    "exclaves: %s: 0x%012llx\n",
		    "Invalid xnu prpoxy physical address",
		    phys);
		return KERN_FAILURE;
	}
	*xnuproxy_boot_info = global->v1.proxyInit;

	return kr;
}

#if EXCLAVES_ENABLE_SHOW_SCHEDULER_REQUEST_RESPONSE
#define exclaves_scheduler_debug_save_buffer(_buf_in, _buf_out) \
	*(_buf_out) = *(_buf_in)
#define exclaves_scheduler_debug_show_request_response(_request_buf, \
	    _response_buf) ({ \
	if (exclaves_debug_enabled(show_scheduler_request_response)) { \
	        printf("exclaves: Scheduler request = %p\n", _request_buf); \
	        printf("exclaves: Scheduler request.tag = 0x%04llx\n", \
	            (_request_buf)->tag); \
	        for (size_t arg = 0; arg < XrtHosted_Buffer_args; arg += 1) { \
	                printf("exclaves: Scheduler request.arguments[%02zu] = " \
	                    "0x%04llx\n", arg, \
	                    (_request_buf)->arguments[arg]); \
	        } \
	        printf("exclaves: Scheduler response = %p\n", _response_buf); \
	        printf("exclaves: Scheduler response.tag = 0x%04llx\n", \
	                (_response_buf)->tag); \
	        for (size_t arg = 0; arg < XrtHosted_Buffer_args; arg += 1) { \
	                printf("exclaves: Scheduler response.arguments[%02zu] = " \
	                    "0x%04llx\n", arg, \
	                    (_response_buf)->arguments[arg]); \
	        } \
	}})
#else // EXCLAVES_SHOW_SCHEDULER_REQUEST_RESPONSE
#define exclaves_scheduler_debug_save_buffer(_buf_in, _buf_out) (void)_buf_out
#define exclaves_scheduler_debug_show_request_response(_request_buf, \
	    _response_buf) ({ })
#endif // EXCLAVES_SHOW_SCHEDULER_REQUEST_RESPONSE

__attribute__((always_inline))
static kern_return_t
exclaves_scheduler_send(const XrtHosted_Request_t *request,
    XrtHosted_Response_t *response, XrtHosted_Buffer_t *save_out_ptr, XrtHosted_Buffer_t *save_in_ptr)
{
	/* Must be called with preemption and interrupts disabled */
	kern_return_t kr;

	XrtHosted_Buffer_t *request_buf = *PERCPU_GET(exclaves_request);
	assert3p(request_buf, !=, NULL);

	exclaves_callbacks->v1.Request.encode(request_buf, request);
	exclaves_scheduler_debug_save_buffer(request_buf, save_out_ptr);

	kr = exclaves_enter();

	/* The response may have come back on a different core. */
	XrtHosted_Buffer_t *response_buf = *PERCPU_GET(exclaves_response);
	assert3p(response_buf, !=, NULL);

	exclaves_scheduler_debug_save_buffer(response_buf, save_in_ptr);
	exclaves_callbacks->v1.Response.decode(response_buf, response);

	return kr;
}

__attribute__((always_inline))
static kern_return_t
exclaves_scheduler_request(const XrtHosted_Request_t *request,
    XrtHosted_Response_t *response)
{
#if EXCLAVES_ENABLE_SHOW_SCHEDULER_REQUEST_RESPONSE
	XrtHosted_Buffer_t save_in[3], save_out[3] = {{ .tag = XrtHosted_Message_Invalid }, { .tag = XrtHosted_Message_Invalid }, { .tag = XrtHosted_Message_Invalid }};
	XrtHosted_Buffer_t *save_out_ptr = save_out, *save_in_ptr = save_in;
#else
	XrtHosted_Buffer_t *save_out_ptr = NULL, *save_in_ptr = NULL;
#endif // EXCLAVES_SHOW_SCHEDULER_REQUEST_RESPONSE

	assert3u(request->tag, >, XrtHosted_Request_Invalid);
	assert3u(request->tag, <, XrtHosted_Request_Limit);

	kern_return_t kr = KERN_SUCCESS;
	bool istate;

	if (!exclaves_multicore || !exclaves_smp_enabled) {
		lck_mtx_lock(&exclaves_scheduler_lock);
	}

	/*
	 * Disable preemption and interrupts as the xrt hosted scheduler data
	 * structures are per-core.
	 * Preemption disabled and interrupt disabled timeouts are disabled for
	 * now until we can co-ordinate the measurements with the exclaves side of
	 * things.
	 */
	istate = ml_set_interrupts_enabled_with_debug(false, false);

	/*
	 * This needs to be done with interrupts disabled, otherwise stackshot could
	 * mark the thread blocked just after this function exits and a thread marked
	 * as AST blocked would go into exclaves.
	 */

	while ((os_atomic_load(&current_thread()->th_exclaves_inspection_state, relaxed) & ~TH_EXCLAVES_INSPECTION_NOINSPECT) != 0) {
		/* Enable interrupts */
		(void) ml_set_interrupts_enabled_with_debug(true, false);

		if (!exclaves_multicore || !exclaves_smp_enabled) {
			lck_mtx_unlock(&exclaves_scheduler_lock);
		}

		/* Wait until the thread is collected on exclaves side */
		exclaves_inspection_check_ast();

		if (!exclaves_multicore || !exclaves_smp_enabled) {
			lck_mtx_lock(&exclaves_scheduler_lock);
		}

		/* Disable interrupts and preemption before next AST check */
		ml_set_interrupts_enabled_with_debug(false, false);
	}
	/* Interrupts are disabled and exclaves_stackshot_ast is clean */

	disable_preemption_without_measurements();

	/* Update clock offsets before any other scheduler operation */
	exclaves_clock_t *clocks[] = { &exclaves_absolute_clock,
		                       &exclaves_continuous_clock };
	for (unsigned i = 0; i < ARRAY_COUNT(clocks); ++i) {
		if (exclaves_clock_needs_update(clocks[i])) {
			kr = exclaves_clock_update(clocks[i], &save_out_ptr[i], &save_in_ptr[i]);
			if (kr != KERN_SUCCESS) {
				break;
			}
		}
	}

	if (kr == KERN_SUCCESS) {
		kr = exclaves_scheduler_send(request, response, &save_out_ptr[2], &save_in_ptr[2]);
	}

	enable_preemption();
	(void) ml_set_interrupts_enabled_with_debug(istate, false);

#if EXCLAVES_ENABLE_SHOW_SCHEDULER_REQUEST_RESPONSE
	for (unsigned i = 0; i < ARRAY_COUNT(save_out); ++i) {
		if (save_out_ptr[i].tag != XrtHosted_Message_Invalid) {
			exclaves_scheduler_debug_show_request_response(&save_out_ptr[i], &save_in_ptr[i]);
		}
	}
#endif // EXCLAVES_ENABLE_SHOW_SCHEDULER_REQUEST_RESPONSE

	if (!exclaves_multicore || !exclaves_smp_enabled) {
		lck_mtx_unlock(&exclaves_scheduler_lock);
	}

	if (kr == KERN_ABORTED) {
		/* RINGGATE_EP_ENTER returned RINGGATE_STATUS_PANIC indicating that
		 * another core has paniced in exclaves and is on the way to call xnu
		 * panic() via SPTM, so wait here for that to happen. */
		exclaves_wait_for_panic();
	}

	return kr;
}

OS_NORETURN OS_NOINLINE
static void
exclaves_wait_for_panic(void)
{
	assert_wait_timeout((event_t)exclaves_wait_for_panic, THREAD_UNINT, 1,
	    NSEC_PER_SEC);
	wait_result_t wr = thread_block(THREAD_CONTINUE_NULL);
	panic("Unexpected wait for panic result: %d", wr);
}

static kern_return_t
handle_response_yield(bool early, __assert_only Exclaves_L4_Word_t scid,
    const XrtHosted_Yield_t *yield)
{
	Exclaves_L4_Word_t responding_scid = yield->thread;
	Exclaves_L4_Word_t yielded_to_scid = yield->yieldTo;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: %s scid 0x%lx yielded to scid 0x%lx\n",
	    early ? "(early yield)" : "", responding_scid, yielded_to_scid);
	/* TODO: 1. remember yielding scid if it isn't the xnu proxy's
	 * th_exclaves_scheduling_context_id so we know to resume it later
	 * 2. translate yield_to to thread_switch()-style handoff.
	 */
	if (!early) {
		assert3u(responding_scid, ==, scid);
		assert3u(yield->threadHostId, ==, ctid);
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_YIELD), yielded_to_scid, early);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_spawned(__assert_only Exclaves_L4_Word_t scid,
    const XrtHosted_Spawned_t *spawned)
{
	Exclaves_L4_Word_t responding_scid = spawned->thread;
	thread_t thread = current_thread();
	__assert_only ctid_t ctid = thread_get_ctid(thread);

	/*
	 * There are only a few places an exclaves thread is expected to be
	 * spawned. Any other cases are considered errors.
	 */
	if ((thread->th_exclaves_state & TH_EXCLAVES_SPAWN_EXPECTED) == 0) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Scheduler: Unexpected thread spawn: "
		    "scid 0x%lx spawned scid 0x%llx\n",
		    responding_scid, spawned->spawned);
		return KERN_FAILURE;
	}

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: scid 0x%lx spawned scid 0x%lx\n",
	    responding_scid, (unsigned long)spawned->spawned);
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_SPAWNED), spawned->spawned);

	assert3u(responding_scid, ==, scid);
	assert3u(spawned->threadHostId, ==, ctid);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_terminated(const XrtHosted_Terminated_t *terminated)
{
	Exclaves_L4_Word_t responding_scid = terminated->thread;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_errors,
	    "exclaves: Scheduler: Unexpected thread terminate: "
	    "scid 0x%lx terminated scid 0x%llx\n", responding_scid,
	    terminated->terminated);
	assert3u(terminated->threadHostId, ==, ctid);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_TERMINATED),
	    terminated->terminated);

	return KERN_TERMINATED;
}

static kern_return_t
handle_response_wait(const XrtHosted_Wait_t *wait)
{
	Exclaves_L4_Word_t responding_scid = wait->waiter;
	thread_t thread = current_thread();
	__assert_only ctid_t ctid = thread_get_ctid(thread);

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Wait: "
	    "scid 0x%lx wait on owner scid 0x%llx, queue id 0x%llx, "
	    "epoch 0x%llx\n", responding_scid, wait->owner,
	    wait->queueId, wait->epoch);
	assert3u(wait->waiterHostId, ==, ctid);

	/* The exclaves inspection thread should never wait. */
	if ((thread->th_exclaves_state & TH_EXCLAVES_INSPECTION_NOINSPECT) != 0) {
		panic("Exclaves inspection thread tried to wait\n");
	}

	/*
	 * Note, "owner" may not be safe to access directly, for example
	 * the thread may have exited and been freed. esync_wait will
	 * only access it under a lock if the epoch is fresh thus
	 * ensuring safety.
	 */
	const ctid_t owner = (ctid_t)wait->ownerHostId;
	const XrtHosted_Word_t id = wait->queueId;
	const uint64_t epoch = wait->epoch;

	wait_interrupt_t interruptible;
	esync_policy_t policy;

	switch (wait->interruptible) {
	case XrtHosted_Interruptibility_None:
		interruptible = THREAD_UNINT;
		policy = ESYNC_POLICY_KERNEL;
		break;

	case XrtHosted_Interruptibility_Voluntary:
		interruptible = THREAD_INTERRUPTIBLE;
		policy = ESYNC_POLICY_KERNEL;
		break;

	case XrtHosted_Interruptibility_DynamicQueue:
		interruptible = THREAD_INTERRUPTIBLE;
		policy = ESYNC_POLICY_USER;
		break;

	default:
		panic("Unknown exclaves interruptibility: %llu",
		    wait->interruptible);
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAIT) | DBG_FUNC_START, id, epoch, owner,
	    wait->interruptible);
	const wait_result_t wr = esync_wait(ESYNC_SPACE_EXCLAVES_Q, id, epoch,
	    exclaves_get_queue_counter(id), owner, policy, interruptible);
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAIT) | DBG_FUNC_END, wr);

	switch (wr) {
	case THREAD_INTERRUPTED:
		return KERN_ABORTED;

	case THREAD_NOT_WAITING:
	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	default:
		panic("Unexpected wait result from esync_wait: %d", wr);
	}
}

static kern_return_t
handle_response_wake(const XrtHosted_Wake_t *wake)
{
	Exclaves_L4_Word_t responding_scid = wake->waker;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Wake: "
	    "scid 0x%lx wake of queue id 0x%llx, "
	    "epoch 0x%llx, all 0x%llx\n", responding_scid,
	    wake->queueId, wake->epoch, wake->all);
	assert3u(wake->wakerHostId, ==, ctid);

	const XrtHosted_Word_t id = wake->queueId;
	const uint64_t epoch = wake->epoch;
	const esync_wake_mode_t mode = wake->all != 0 ?
	    ESYNC_WAKE_ALL : ESYNC_WAKE_ONE;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAKE) | DBG_FUNC_START, id, epoch, 0, mode);

	kern_return_t kr = esync_wake(ESYNC_SPACE_EXCLAVES_Q, id, epoch,
	    exclaves_get_queue_counter(id), mode, 0);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAKE) | DBG_FUNC_END,
	    kr == KERN_SUCCESS ? THREAD_AWAKENED : THREAD_NOT_WAITING);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_wake_with_owner(const XrtHosted_WakeWithOwner_t *wake)
{
	Exclaves_L4_Word_t responding_scid = wake->waker;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: WakeWithOwner: "
	    "scid 0x%lx wake of queue id 0x%llx, "
	    "epoch 0x%llx, owner 0x%llx\n", responding_scid,
	    wake->queueId, wake->epoch,
	    wake->owner);

	assert3u(wake->wakerHostId, ==, ctid);

	const ctid_t owner = (ctid_t)wake->ownerHostId;
	const XrtHosted_Word_t id = wake->queueId;
	const uint64_t epoch = wake->epoch;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAKE) | DBG_FUNC_START, id, epoch, owner,
	    ESYNC_WAKE_ONE_WITH_OWNER);

	kern_return_t kr = esync_wake(ESYNC_SPACE_EXCLAVES_Q, id, epoch,
	    exclaves_get_queue_counter(id), ESYNC_WAKE_ONE_WITH_OWNER, owner);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_WAKE) | DBG_FUNC_END,
	    kr == KERN_SUCCESS ? THREAD_AWAKENED : THREAD_NOT_WAITING);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_panic_wait(const XrtHosted_PanicWait_t *panic_wait)
{
	Exclaves_L4_Word_t panic_thread_scid = panic_wait->handler;
	__assert_only thread_t thread = current_thread();

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: PanicWait: "
	    "Panic thread SCID %lx\n",
	    panic_thread_scid);

	assert3u(panic_thread_scid, ==, thread->th_exclaves_ipc_ctx.scid);

	exclaves_panic_thread_wait();

	/* NOT REACHABLE */
	return KERN_SUCCESS;
}

static kern_return_t
handle_response_suspended(const XrtHosted_Suspended_t *suspended)
{
	Exclaves_L4_Word_t responding_scid = suspended->suspended;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Suspended: "
	    "scid 0x%lx epoch 0x%llx\n", responding_scid, suspended->epoch);
	assert3u(suspended->suspendedHostId, ==, ctid);

	const uint64_t id = suspended->suspended;
	const uint64_t epoch = suspended->epoch;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_SUSPENDED) | DBG_FUNC_START, id, epoch);

	const wait_result_t wr = esync_wait(ESYNC_SPACE_EXCLAVES_T, id, epoch,
	    exclaves_get_thread_counter(id), 0, ESYNC_POLICY_KERNEL, THREAD_UNINT);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_SUSPENDED) | DBG_FUNC_END, wr);

	switch (wr) {
	case THREAD_INTERRUPTED:
		return KERN_ABORTED;

	case THREAD_NOT_WAITING:
	case THREAD_AWAKENED:
		return KERN_SUCCESS;

	default:
		panic("Unexpected wait result from esync_wait: %d", wr);
	}
}

static kern_return_t
handle_response_resumed(const XrtHosted_Resumed_t *resumed)
{
	Exclaves_L4_Word_t responding_scid = resumed->thread;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Resumed: scid 0x%lx resume of scid 0x%llx "
	    "(ctid: 0x%llx), epoch 0x%llx\n", responding_scid, resumed->resumed,
	    resumed->resumedHostId, resumed->epoch);
	assert3u(resumed->threadHostId, ==, ctid);

	const ctid_t target = (ctid_t)resumed->resumedHostId;
	const XrtHosted_Word_t id = resumed->resumed;
	const uint64_t epoch = resumed->epoch;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_RESUMED) | DBG_FUNC_START, id, epoch,
	    target);

	kern_return_t kr = esync_wake(ESYNC_SPACE_EXCLAVES_T, id, epoch,
	    exclaves_get_thread_counter(id), ESYNC_WAKE_THREAD, target);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_RESUMED) | DBG_FUNC_END,
	    kr == KERN_SUCCESS ? THREAD_AWAKENED : THREAD_NOT_WAITING);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_interrupted(const XrtHosted_Interrupted_t *interrupted)
{
	Exclaves_L4_Word_t responding_scid = interrupted->thread;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Interrupted: "
	    "scid 0x%lx interrupt on queue id 0x%llx, "
	    "epoch 0x%llx, target 0x%llx\n", responding_scid,
	    interrupted->queueId, interrupted->epoch,
	    interrupted->interruptedHostId);
	assert3u(interrupted->threadHostId, ==, ctid);

	const ctid_t target = (ctid_t)interrupted->interruptedHostId;
	const XrtHosted_Word_t id = interrupted->queueId;
	const uint64_t epoch = interrupted->epoch;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_INTERRUPTED) | DBG_FUNC_START, id, epoch,
	    target);

	kern_return_t kr = esync_wake(ESYNC_SPACE_EXCLAVES_Q, id, epoch,
	    exclaves_get_queue_counter(id), ESYNC_WAKE_THREAD, target);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_INTERRUPTED) | DBG_FUNC_END,
	    kr == KERN_SUCCESS ? THREAD_AWAKENED : THREAD_NOT_WAITING);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_nothing_scheduled(
	__unused const XrtHosted_NothingScheduled_t *nothing_scheduled)
{
	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: nothing scheduled\n");

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_NOTHING_SCHEDULED));

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_all_exclaves_booted(
	__unused const XrtHosted_AllExclavesBooted_t *all_exclaves_booted)
{
	exclaves_debug_printf(show_progress,
	    "exclaves: scheduler: all exclaves booted\n");

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_ALL_EXCLAVES_BOOTED));

	return KERN_SUCCESS;
}

/*
 * The Early Alloc response asks for npages to be allocated. The list of
 * allocated pages is written into the first allocated page in the form of 32bit
 * page numbers. The physical address of the first page is passed back to the
 * exclaves scheduler as part of the next request.
 */
static kern_return_t
handle_response_pmm_early_alloc(const XrtHosted_PmmEarlyAlloc_t *pmm_early_alloc,
    uint64_t *pagelist_pa)
{
	const uint32_t npages = (uint32_t)pmm_early_alloc->a;
	const uint64_t flags = pmm_early_alloc->b;

	exclaves_debug_printf(show_progress,
	    "exclaves: scheduler: pmm early alloc, npages: %u, flags: %llu\n",
	    npages, flags);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_EARLY_ALLOC), npages, flags);

	if (npages == 0) {
		return KERN_SUCCESS;
	}

	if (npages > EXCLAVES_MEMORY_MAX_REQUEST) {
		exclaves_debug_printf(show_errors,
		    "exclaves: request to allocate too many pages: %u\n",
		    npages);
		return KERN_NO_SPACE;
	}

	/*
	 * As npages must be relatively small (<= EXCLAVES_MEMORY_MAX_REQUEST),
	 * stack allocation is sufficient and fast. If
	 * EXCLAVES_MEMORY_MAX_REQUEST gets large, this should probably be moved
	 * to the heap.
	 */
	uint32_t page[EXCLAVES_MEMORY_MAX_REQUEST];
	exclaves_memory_alloc(npages, page, XNUUPCALLS_PAGEKIND_ROOTDOMAIN);

	/* Now copy the list of pages into the first page. */
	uint64_t first_page_pa = ptoa(page[0]);
#if 0
	// move to before sptm retype
	uint32_t *first_page = (uint32_t *)phystokv(first_page_pa);
	for (int i = 0; i < npages; i++) {
		first_page[i] = page[i];
	}
#endif

	*pagelist_pa = first_page_pa;
	return KERN_SUCCESS;
}

static inline bool
exclaves_clock_needs_update(const exclaves_clock_t *clock)
{
	exclaves_clock_t local = {
		.u128 = os_atomic_load(&clock->a_u128, relaxed),
	};

	return local.u64.sent_offset != local.u64.latest_offset;
}

OS_NOINLINE
static kern_return_t
exclaves_clock_update(exclaves_clock_t *clock, XrtHosted_Buffer_t *save_out_ptr, XrtHosted_Buffer_t *save_in_ptr)
{
	XrtHosted_Response_t response = { .tag = XrtHosted_Response_NothingScheduled, };
	kern_return_t kr = KERN_SUCCESS;
	exclaves_clock_t local;

	local.u128 = os_atomic_load(&clock->a_u128, relaxed);
	while (local.u64.sent_offset != local.u64.latest_offset) {
		XrtHosted_Request_t request = XrtHosted_Request_UpdateTimerOffsetMsg(
			.timer =
			(clock == &exclaves_absolute_clock ?
			XrtHosted_Timer_Absolute : XrtHosted_Timer_Continuous),
			.offset = local.u64.latest_offset,
			);

		kr = exclaves_scheduler_send(&request, &response, save_out_ptr, save_in_ptr);
		if (kr) {
			return kr;
		}

		/* Swap the sent offset with the local latest offset. If it fails,
		 * the sent offset will be reloaded. */
		os_atomic_cmpxchgv(&clock->a_u64.sent_offset, local.u64.sent_offset,
		    local.u64.latest_offset, &local.u64.sent_offset, relaxed);

		/* Fetch the latest offset again, in case we are stale. */
		local.u64.latest_offset = os_atomic_load(&clock->a_u64.latest_offset,
		    relaxed);
	}

	if (response.tag != XrtHosted_Response_NothingScheduled) {
		kr = KERN_FAILURE;
	}

	return kr;
}

static kern_return_t
exclaves_scheduler_boot(void)
{
	kern_return_t kr = KERN_FAILURE;
	thread_t thread = current_thread();

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Request to boot exclave\n");

	/* This must happen on the boot CPU - bind the thread. */
	bind_to_boot_core();

	assert3u(thread->th_exclaves_state & TH_EXCLAVES_STATE_ANY, ==, 0);
	thread->th_exclaves_state |= TH_EXCLAVES_SCHEDULER_CALL;

	/*
	 * Set the request/response buffers. These may be overriden later when
	 * doing multicore setup.
	 */
	*PERCPU_GET(exclaves_request) =
	    exclaves_callbacks->v1.Core.request(XrtHosted_Core_bootIndex);
	*PERCPU_GET(exclaves_response) =
	    exclaves_callbacks->v1.Core.response(XrtHosted_Core_bootIndex);

	XrtHosted_Response_t response = {.tag = XrtHosted_Response_Invalid};
	uint64_t pagelist_pa = 0;

	while (response.tag != XrtHosted_Response_AllExclavesBooted) {
		const XrtHosted_Request_t request = pagelist_pa != 0 ?
		    XrtHosted_Request_PmmEarlyAllocResponseMsg(.a = pagelist_pa):
		    XrtHosted_Request_BootExclavesMsg();
		pagelist_pa = 0;

		kr = exclaves_scheduler_request(&request, &response);
		if (kr != KERN_SUCCESS) {
			exclaves_debug_printf(show_errors,
			    "exclaves: Enter failed\n");
			break;
		}

		thread->th_exclaves_state |= TH_EXCLAVES_SCHEDULER_REQUEST;

		switch (response.tag) {
		case XrtHosted_Response_Yield:
			kr = handle_response_yield(true, 0, &response.Yield);
			break;

		case XrtHosted_Response_NothingScheduled:
			kr = handle_response_nothing_scheduled(&response.NothingScheduled);
			break;

		case XrtHosted_Response_AllExclavesBooted:
			kr = handle_response_all_exclaves_booted(&response.AllExclavesBooted);
			break;

		case XrtHosted_Response_PmmEarlyAlloc:
			kr = handle_response_pmm_early_alloc(&response.PmmEarlyAlloc, &pagelist_pa);
			break;

		case XrtHosted_Response_PanicBufferAddress:
			handle_response_panic_buffer_address(response.PanicBufferAddress.physical);
			break;

		default:
			exclaves_debug_printf(show_errors,
			    "exclaves: Scheduler: Unexpected response: tag 0x%x\n",
			    response.tag);
			kr = KERN_FAILURE;
			break;
		}

		thread->th_exclaves_state &= ~TH_EXCLAVES_SCHEDULER_REQUEST;

		/* Bail out if an error is hit. */
		if (kr != KERN_SUCCESS) {
			break;
		}
	}

	thread->th_exclaves_state &= ~TH_EXCLAVES_SCHEDULER_CALL;

	unbind_from_boot_core();

	return kr;
}

kern_return_t
exclaves_scheduler_resume_scheduling_context(const exclaves_ctx_t *ctx,
    bool interrupted)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();
	const ctid_t ctid = thread_get_ctid(thread);

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Request to resume scid 0x%lx\n", ctx->scid);

	XrtHosted_Response_t response = {};
	const XrtHosted_Request_t request = interrupted ?
	    XrtHosted_Request_InterruptWithHostIdMsg(
		.thread = ctx->scid,
		.hostId = ctid,
		) :
	    XrtHosted_Request_ResumeWithHostIdMsg(
		.thread = ctx->scid,
		.hostId = ctid,
		);
	kr = exclaves_scheduler_request(&request, &response);
	if (kr) {
		exclaves_debug_printf(show_errors, "exclaves: Enter failed\n");
		return kr;
	}

	thread->th_exclaves_state |= TH_EXCLAVES_SCHEDULER_REQUEST;

	switch (response.tag) {
	case XrtHosted_Response_Wait:
		kr = handle_response_wait(&response.Wait);
		goto out;

	case XrtHosted_Response_Wake:
		kr = handle_response_wake(&response.Wake);
		goto out;

	case XrtHosted_Response_Yield:
		kr = handle_response_yield(false, ctx->scid, &response.Yield);
		goto out;

	case XrtHosted_Response_Spawned:
		kr = handle_response_spawned(ctx->scid, &response.Spawned);
		goto out;

	case XrtHosted_Response_Terminated:
		kr = handle_response_terminated(&response.Terminated);
		goto out;

	case XrtHosted_Response_WakeWithOwner:
		kr = handle_response_wake_with_owner(&response.WakeWithOwner);
		goto out;

	case XrtHosted_Response_PanicWait:
		kr = handle_response_panic_wait(&response.PanicWait);
		goto out;

	case XrtHosted_Response_Suspended:
		kr = handle_response_suspended(&response.Suspended);
		goto out;

	case XrtHosted_Response_Resumed:
		kr = handle_response_resumed(&response.Resumed);
		goto out;

	case XrtHosted_Response_Interrupted:
		kr = handle_response_interrupted(&response.Interrupted);
		goto out;

	case XrtHosted_Response_Invalid:
	case XrtHosted_Response_Failure:
	case XrtHosted_Response_Pong:
	case XrtHosted_Response_SleepUntil:
	case XrtHosted_Response_Awaken:
	default:
		exclaves_debug_printf(show_errors,
		    "exclaves: Scheduler: Unexpected response: tag 0x%x\n",
		    response.tag);
		kr = KERN_FAILURE;
		goto out;
	}

out:
	thread->th_exclaves_state &= ~TH_EXCLAVES_SCHEDULER_REQUEST;
	return kr;
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves xnu proxy communication

static kern_return_t
exclaves_hosted_error(bool success, XrtHosted_Error_t *error)
{
	if (success) {
		return KERN_SUCCESS;
	} else {
		exclaves_debug_printf(show_errors,
		    "exclaves: XrtHosted: %s[%d] (%s): %s\n",
		    error->file,
		    error->line,
		    error->function,
		    error->expression
		    );
		return KERN_FAILURE;
	}
}


#pragma mark exclaves privilege management

/*
 * All entitlement checking enabled by default.
 */
#define DEFAULT_ENTITLEMENT_FLAGS (~0)

/*
 * boot-arg to control the use of entitlements.
 * Eventually this should be removed and entitlement checking should be gated on
 * the EXCLAVES_R_ENTITLEMENTS requirement.
 * This will be addressed with rdar://125153460.
 */
TUNABLE(unsigned int, exclaves_entitlement_flags,
    "exclaves_entitlement_flags", DEFAULT_ENTITLEMENT_FLAGS);

static bool
has_entitlement(task_t task, const exclaves_priv_t priv,
    const char *entitlement)
{
	/* Skip the entitlement if not enabled. */
	if ((exclaves_entitlement_flags & priv) == 0) {
		return true;
	}

	return IOTaskHasEntitlement(task, entitlement);
}

static bool
has_entitlement_vnode(void *vnode, const int64_t off,
    const exclaves_priv_t priv, const char *entitlement)
{
	/* Skip the entitlement if not enabled. */
	if ((exclaves_entitlement_flags & priv) == 0) {
		return true;
	}

	return IOVnodeHasEntitlement(vnode, off, entitlement);
}

bool
exclaves_has_priv(task_t task, exclaves_priv_t priv)
{
	const bool is_kernel = task == kernel_task;
	const bool is_launchd = task_pid(task) == 1;

	switch (priv) {
	case EXCLAVES_PRIV_CONCLAVE_SPAWN:
		/* Both launchd and entitled tasks can spawn new conclaves. */
		if (is_launchd) {
			return true;
		}
		return has_entitlement(task, priv,
		           "com.apple.private.exclaves.conclave-spawn");

	case EXCLAVES_PRIV_KERNEL_DOMAIN:
		/*
		 * Both the kernel itself and user tasks with the right
		 * privilege can access exclaves resources in the kernel domain.
		 */
		if (is_kernel) {
			return true;
		}

		/*
		 * If the task was entitled and has been through this path
		 * before, it will have set the TFRO_HAS_KD_ACCESS flag.
		 */
		if ((task_ro_flags_get(task) & TFRO_HAS_KD_ACCESS) != 0) {
			return true;
		}

		if (has_entitlement(task, priv,
		    "com.apple.private.exclaves.kernel-domain")) {
			task_ro_flags_set(task, TFRO_HAS_KD_ACCESS);
			return true;
		}

		return false;

	case EXCLAVES_PRIV_BOOT:
		/* Both launchd and entitled tasks can boot exclaves. */
		if (is_launchd) {
			return true;
		}
		/* BEGIN IGNORE CODESTYLE */
		return has_entitlement(task, priv,
		    "com.apple.private.exclaves.boot");
		/* END IGNORE CODESTYLE */

	/* The CONCLAVE HOST priv is always checked by vnode. */
	case EXCLAVES_PRIV_CONCLAVE_HOST:
	default:
		panic("bad exclaves privilege (%u)", priv);
	}
}

bool
exclaves_has_priv_vnode(void *vnode, int64_t off, exclaves_priv_t priv)
{
	switch (priv) {
	case EXCLAVES_PRIV_CONCLAVE_HOST: {
		const bool has_conclave_host = has_entitlement_vnode(vnode,
		    off, priv, "com.apple.private.exclaves.conclave-host");

		/*
		 * Tasks should never have both EXCLAVES_PRIV_CONCLAVE_HOST
		 * *and* EXCLAVES_PRIV_KERNEL_DOMAIN.
		 */

		/* Don't check if neither entitlemenent is being enforced.*/
		if ((exclaves_entitlement_flags & EXCLAVES_PRIV_CONCLAVE_HOST) == 0 ||
		    (exclaves_entitlement_flags & EXCLAVES_PRIV_KERNEL_DOMAIN) == 0) {
			return has_conclave_host;
		}

		const bool has_domain_kernel = has_entitlement_vnode(vnode, off,
		    EXCLAVES_PRIV_KERNEL_DOMAIN,
		    "com.apple.private.exclaves.kernel-domain");

		/* See if it has both. */
		if (has_conclave_host && has_domain_kernel) {
			exclaves_debug_printf(show_errors,
			    "exclaves: task has both conclave-host and "
			    "kernel-domain entitlements which is forbidden\n");
			return false;
		}

		return has_conclave_host;
	}

	case EXCLAVES_PRIV_CONCLAVE_SPAWN:
		return has_entitlement_vnode(vnode, off, priv,
		           "com.apple.private.exclaves.conclave-spawn");

	default:
		panic("bad exclaves privilege (%u)", priv);
	}
}


#pragma mark exclaves stackshot range

/* Unslid pointers defining the range of code which switches threads into
 * secure world */
uintptr_t exclaves_enter_range_start;
uintptr_t exclaves_enter_range_end;


__startup_func
static void
initialize_exclaves_enter_range(void)
{
	exclaves_enter_range_start = VM_KERNEL_UNSLIDE(&exclaves_enter_start_label);
	assert3u(exclaves_enter_range_start, !=, 0);
	exclaves_enter_range_end = VM_KERNEL_UNSLIDE(&exclaves_enter_end_label);
	assert3u(exclaves_enter_range_end, !=, 0);
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, initialize_exclaves_enter_range);

/*
 * Return true if the specified address is in exclaves_enter.
 */
static bool
exclaves_enter_in_range(uintptr_t addr, bool slid)
{
	return slid ?
	       exclaves_in_range(addr, (uintptr_t)&exclaves_enter_start_label, (uintptr_t)&exclaves_enter_end_label) :
	       exclaves_in_range(addr, exclaves_enter_range_start, exclaves_enter_range_end);
}

uint32_t
exclaves_stack_offset(const uintptr_t *addr, size_t nframes, bool slid)
{
	size_t i = 0;

	// Check for a frame matching upcall code range
	for (i = 0; i < nframes; i++) {
		if (exclaves_upcall_in_range(addr[i], slid)) {
			break;
		}
	}

	// Insert exclaves stacks before the upcall frame when found
	if (i < nframes) {
		return (uint32_t)(i + 1);
	}

	// Check for a frame matching exclaves enter range
	for (i = 0; i < nframes; i++) {
		if (exclaves_enter_in_range(addr[i], slid)) {
			break;
		}
	}

	// Put exclaves stacks on top of kernel stacks by default
	if (i == nframes) {
		i = 0;
	}
	return (uint32_t)i;
}

#endif /* CONFIG_EXCLAVES */


#ifndef CONFIG_EXCLAVES
/* stubs for sensor functions which are not compiled in from exclaves.c when
 * CONFIG_EXCLAVE is disabled */

kern_return_t
exclaves_sensor_start(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_sensor_stop(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

kern_return_t
exclaves_sensor_status(exclaves_sensor_type_t sensor_type, uint64_t flags,
    exclaves_sensor_status_t *status)
{
#pragma unused(sensor_type, flags, status)
	return KERN_NOT_SUPPORTED;
}

#endif /* ! CONFIG_EXCLAVES */
