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
#else
#error Invalid configuration
#endif /* CONFIG_SPTM */

#include <arm/cpu_data_internal.h>
#include <kern/epoch_sync.h>
#include <kern/ipc_kobject.h>
#include <kern/kalloc.h>
#include <kern/locks.h>
#include <kern/percpu.h>
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

#include "exclaves_debug.h"
#include "exclaves_panic.h"

/* External & generated headers */
#include <xrt_hosted_types/types.h>
#include <xnuproxy/messages.h>

/* Use the new version of xnuproxy_msg_t. */
#define xnuproxy_msg_t xnuproxy_msg_new_t

#if __has_include(<Tightbeam/tightbeam.h>)
#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>
#endif

#include "exclaves_resource.h"
#include "exclaves_upcalls.h"
#include "exclaves_boot.h"
#include "exclaves_inspection.h"


/* Unslid pointers defining the range of code which switches threads into
 * secure world */
uintptr_t exclaves_enter_range_start;
uintptr_t exclaves_enter_range_end;

/* Unslid pointers defining the range of code which triggers upcall handlers */
uintptr_t exclaves_upcall_range_start;
uintptr_t exclaves_upcall_range_end;

/* Number of allocated ipcb buffers, estimate of active exclave threads */
static _Atomic size_t exclaves_ipcb_cnt;

LCK_GRP_DECLARE(exclaves_lck_grp, "exclaves");

/* Lock around communication with singleton xnu proxy server thread */
LCK_MTX_DECLARE(exclaves_xnu_proxy_lock, &exclaves_lck_grp);

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

static kern_return_t
exclaves_acquire_ipc_buffer(Exclaves_L4_IpcBuffer_t **ipcb_out,
    Exclaves_L4_Word_t *scid_out);
static kern_return_t
exclaves_relinquish_ipc_buffer(Exclaves_L4_IpcBuffer_t *ipcb,
    Exclaves_L4_Word_t scid);
static kern_return_t
exclaves_endpoint_call_internal(ipc_port_t port, exclaves_id_t endpoint_id);

static kern_return_t
exclaves_enter(void);
static kern_return_t
exclaves_bootinfo(uint64_t *out_boot_info);

static kern_return_t
exclaves_scheduler_init(uint64_t boot_info);

kern_return_t
exclaves_scheduler_resume_scheduling_context(Exclaves_L4_Word_t scid,
    Exclaves_L4_Word_t *spawned_scid, bool interrupted);

static kern_return_t
exclaves_xnu_proxy_init(uint64_t xnu_proxy_boot_info);
static kern_return_t
exclaves_xnu_proxy_allocate_context(Exclaves_L4_Word_t *out_scid,
    Exclaves_L4_IpcBuffer_t **out_ipcb);
static kern_return_t
exclaves_xnu_proxy_free_context(Exclaves_L4_Word_t scid);
static kern_return_t
exclaves_xnu_proxy_endpoint_call(Exclaves_L4_Word_t endpoint_id);
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

/*
 * A (simple, for now...) cache of IPC buffers for communicating with XNU-Proxy.
 * Limited in size by the same value as XNU-Proxy's EC limit.
 * Must be realtime-safe.
 */

static kern_return_t
exclaves_ipc_buffer_cache_init(void);

/* Intrusive linked list within the unused IPC buffer */
struct exclaves_ipc_buffer_cache_item {
	struct exclaves_ipc_buffer_cache_item *next;
	Exclaves_L4_Word_t scid;
} __attribute__((__packed__));

_Static_assert(Exclaves_L4_IpcBuffer_Size >= sizeof(struct exclaves_ipc_buffer_cache_item),
    "Invalid Exclaves_L4_IpcBuffer_Size");

LCK_SPIN_DECLARE(exclaves_ipc_buffer_cache_lock, &exclaves_lck_grp);
static struct exclaves_ipc_buffer_cache_item *exclaves_ipc_buffer_cache;

/* -------------------------------------------------------------------------- */
#pragma mark exclaves debug configuration

#if DEVELOPMENT || DEBUG
TUNABLE_WRITEABLE(unsigned int, exclaves_debug, "exclaves_debug", 0);
#endif /* DEVELOPMENT || DEBUG */

#if DEVELOPMENT || DEBUG
TUNABLE_WRITEABLE(unsigned int, exclaves_ipc_buffer_cache_enabled, "exclaves_ipcb_cache", 1);
#else
#define exclaves_ipc_buffer_cache_enabled 1
#endif
#endif /* CONFIG_EXCLAVES */

/* -------------------------------------------------------------------------- */
#pragma mark userspace entry point

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
	bool start_conclave = false;

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
	 * The only valid operation if exclaves are not booted to
	 * EXCLAVES_BOOT_STAGE_EXCLAVEKIT, is the BOOT op.
	 */
	if (operation != EXCLAVES_CTL_OP_BOOT) {
		/*
		 * Make this EXCLAVES_BOOT_STAGE_2 until userspace is actually
		 * triggering the EXCLAVESKIT boot stage.
		 */
		kr = exclaves_boot_wait(EXCLAVES_BOOT_STAGE_2);
		if (kr != KERN_SUCCESS) {
			return kr;
		}
	}

	switch (operation) {
	case EXCLAVES_CTL_OP_ENDPOINT_CALL:
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		if (ubuffer == USER_ADDR_NULL || usize == 0 ||
		    usize != Exclaves_L4_IpcBuffer_Size) {
			return KERN_INVALID_ARGUMENT;
		}

		Exclaves_L4_IpcBuffer_t *ipcb;
		if ((error = exclaves_allocate_ipc_buffer((void**)&ipcb))) {
			return error;
		}
		assert(ipcb != NULL);
		if ((error = copyin(ubuffer, ipcb, usize))) {
			return error;
		}
		kr = exclaves_endpoint_call_internal(IPC_PORT_NULL, identifier);
		if ((error = copyout(ipcb, ubuffer, usize))) {
			return error;
		}
		break;

	case EXCLAVES_CTL_OP_NAMED_BUFFER_CREATE: {
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}

		size_t len = 0;
		char id_name[XNUPROXY_RESOURCE_NAME_MAX] = "";
		if (copyinstr(identifier, id_name, XNUPROXY_RESOURCE_NAME_MAX,
		    &len) != 0 || id_name[0] == '\0') {
			return KERN_INVALID_ARGUMENT;
		}

		exclaves_buffer_perm_t perm = (exclaves_buffer_perm_t)usize2;
		const exclaves_buffer_perm_t supported =
		    EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE;
		if ((perm & supported) == 0 || (perm & ~supported) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/*
		 * Fallback to the kernel domain for now if the conclave can't
		 * be found.
		 */
		exclaves_resource_t *resource = task_get_conclave(current_task());
		const char *domain = resource != NULL ?
		    resource->r_name : EXCLAVES_DOMAIN_KERNEL;
		const bool new_api =
		    (perm == EXCLAVES_BUFFER_PERM_READ) ||
		    (perm == EXCLAVES_BUFFER_PERM_WRITE);
		const bool shared_mem_available =
		    exclaves_resource_lookup_by_name(domain, id_name,
		    XNUPROXY_RESOURCE_SHARED_MEMORY) != NULL;
		const bool use_shared_mem = new_api && shared_mem_available;

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
		case XNUPROXY_RESOURCE_NAMED_BUFFER:
			kr = exclaves_named_buffer_copyin(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCE_SHARED_MEMORY:
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
		case XNUPROXY_RESOURCE_NAMED_BUFFER:
			kr = exclaves_named_buffer_copyout(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCE_SHARED_MEMORY:
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

	case EXCLAVES_CTL_OP_BOOT:
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		kr = exclaves_boot((uint32_t)identifier);
		break;

	case EXCLAVES_CTL_OP_LAUNCH_CONCLAVE:
		start_conclave = true;
		OS_FALLTHROUGH;
	case EXCLAVES_CTL_OP_LOOKUP_RESOURCES:
		if (name != MACH_PORT_NULL) {
			/* Only accept MACH_PORT_NULL for now */
			return KERN_INVALID_CAPABILITY;
		}
		struct exclaves_resource_user *conclave_resource_user = NULL;
		int resource_count = 0;

		if (usize > (MAX_CONCLAVE_RESOURCE_NUM * sizeof(struct exclaves_resource_user)) ||
		    (usize % sizeof(struct exclaves_resource_user) != 0)) {
			return KERN_INVALID_ARGUMENT;
		}

		if ((ubuffer == USER_ADDR_NULL && usize != 0) ||
		    (usize == 0 && ubuffer != USER_ADDR_NULL)) {
			return KERN_INVALID_ARGUMENT;
		}

		if (ubuffer != USER_ADDR_NULL) {
			conclave_resource_user = (struct exclaves_resource_user *)
			    kalloc_data(usize, Z_WAITOK | Z_ZERO | Z_NOFAIL);
			error = copyin(ubuffer, conclave_resource_user, usize);
			if (error) {
				kfree_data(conclave_resource_user, usize);
				return KERN_INVALID_ARGUMENT;
			}
			resource_count = (int)usize / sizeof(struct exclaves_resource_user);

			const size_t name_buf_len = sizeof(conclave_resource_user->r_name);
			for (int i = 0; i < resource_count; i++) {
				if (strnlen(conclave_resource_user[i].r_name,
				    name_buf_len) == name_buf_len) {
					kfree_data(conclave_resource_user, usize);
					return KERN_INVALID_ARGUMENT;
				}
			}
		}
		kr = task_start_conclave_and_lookup_resources(MACH_PORT_NULL,
		    start_conclave, conclave_resource_user, resource_count);
		if (kr == KERN_SUCCESS && conclave_resource_user != NULL) {
			error = copyout(conclave_resource_user, ubuffer, usize);
			if (error) {
				kr = KERN_INVALID_ADDRESS;
			}
		}

		if (conclave_resource_user) {
			kfree_data(conclave_resource_user, usize);
		}
		break;

	case EXCLAVES_CTL_OP_AUDIO_BUFFER_CREATE: {
		if (identifier == 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/* copy in string name */
		char id_name[XNUPROXY_RESOURCE_NAME_MAX] = "";
		size_t done = 0;
		if (copyinstr(identifier, id_name, XNUPROXY_RESOURCE_NAME_MAX, &done) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/*
		 * Fallback to the kernel domain for now if the conclave can't
		 * be found.
		 */
		exclaves_resource_t *resource = task_get_conclave(current_task());
		const char *domain = resource != NULL ?
		    resource->r_name : EXCLAVES_DOMAIN_KERNEL;
		const bool use_audio_memory =
		    exclaves_resource_lookup_by_name(domain, id_name,
		    XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY) != NULL;

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
		case XNUPROXY_RESOURCE_ARBITRATED_AUDIO_BUFFER:
			kr = exclaves_audio_buffer_copyout(resource, ubuffer,
			    usize, uoffset, usize2, uoffset2);
			break;

		case XNUPROXY_RESOURCE_ARBITRATED_AUDIO_MEMORY:
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
		char id_name[XNUPROXY_RESOURCE_NAME_MAX] = "";
		size_t done = 0;
		if (copyinstr(identifier, id_name, XNUPROXY_RESOURCE_NAME_MAX, &done) != 0) {
			return KERN_INVALID_ARGUMENT;
		}

		/*
		 * Fallback to the kernel domain for now if the conclave can't
		 * be found.
		 */
		exclaves_resource_t *resource = task_get_conclave(current_task());
		const char *domain = resource != NULL ?
		    resource->r_name : EXCLAVES_DOMAIN_KERNEL;

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

		if (resource->r_type != XNUPROXY_RESOURCE_SENSOR) {
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

		if (resource->r_type != XNUPROXY_RESOURCE_SENSOR) {
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

		if (resource->r_type != XNUPROXY_RESOURCE_SENSOR) {
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

		/*
		 * Fallback to the kernel domain for now if the conclave can't
		 * be found.
		 */
		exclaves_resource_t *resource = task_get_conclave(current_task());
		const char *domain = resource != NULL ?
		    resource->r_name : EXCLAVES_DOMAIN_KERNEL;

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

/* Realtime-safe acquisition of an IPC buffer */
kern_return_t
exclaves_allocate_ipc_buffer(void **out_ipc_buffer)
{
#if CONFIG_EXCLAVES
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_buffer;
	Exclaves_L4_Word_t scid = thread->th_exclaves_scheduling_context_id;

	if (ipcb == NULL) {
		assert(scid == 0);
		if ((kr = exclaves_acquire_ipc_buffer(&ipcb, &scid))) {
			return kr;
		}
		thread->th_exclaves_ipc_buffer = ipcb;
		thread->th_exclaves_scheduling_context_id = scid;
	}
	if (out_ipc_buffer) {
		*out_ipc_buffer = (void*)ipcb;
	}

	return kr;
#else /* CONFIG_EXCLAVES */
#pragma unused(out_ipc_buffer)
	return KERN_NOT_SUPPORTED;
#endif /* CONFIG_EXCLAVES */
}

#if CONFIG_EXCLAVES
static kern_return_t
exclaves_thread_free_ipc_buffer(thread_t thread)
{
	kern_return_t kr = KERN_SUCCESS;
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_buffer;
	Exclaves_L4_Word_t scid = thread->th_exclaves_scheduling_context_id;

	if (ipcb != NULL) {
		assert(scid != 0);
		thread->th_exclaves_ipc_buffer = NULL;
		thread->th_exclaves_scheduling_context_id = 0;

		kr = exclaves_relinquish_ipc_buffer(ipcb, scid);
	} else {
		assert(scid == 0);
	}

	return kr;
}
#endif /* CONFIG_EXCLAVES */

kern_return_t
exclaves_free_ipc_buffer(void)
{
#if CONFIG_EXCLAVES
	return exclaves_thread_free_ipc_buffer(current_thread());
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
	if (thread->th_exclaves_ipc_buffer) {
		exclaves_debug_printf(show_progress,
		    "exclaves: thread_terminate freeing abandoned exclaves "
		    "ipc buffer\n");
		kr = exclaves_thread_free_ipc_buffer(thread);
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
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_buffer;
	assert(ipcb != NULL);

	return ipcb;
#else /* CONFIG_EXCLAVES */
	return NULL;
#endif /* CONFIG_EXCLAVES */
}

#if CONFIG_EXCLAVES

__startup_func
static void
initialize_exclaves_call_range(void)
{
	exclaves_enter_range_start = VM_KERNEL_UNSLIDE(&exclaves_enter_start_label);
	assert3u(exclaves_enter_range_start, !=, 0);
	exclaves_enter_range_end = VM_KERNEL_UNSLIDE(&exclaves_enter_end_label);
	assert3u(exclaves_enter_range_end, !=, 0);
	exclaves_upcall_range_start = VM_KERNEL_UNSLIDE(&exclaves_upcall_start_label);
	assert3u(exclaves_upcall_range_start, !=, 0);
	exclaves_upcall_range_end = VM_KERNEL_UNSLIDE(&exclaves_upcall_end_label);
	assert3u(exclaves_upcall_range_end, !=, 0);
}
STARTUP(EARLY_BOOT, STARTUP_RANK_MIDDLE, initialize_exclaves_call_range);

extern kern_return_t exclaves_boot_early(void);
kern_return_t
exclaves_boot_early(void)
{
	kern_return_t kr = KERN_FAILURE;
	uint64_t boot_info = 0;

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	kr = exclaves_bootinfo(&boot_info);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Get bootinfo failed\n");
		return kr;
	}

	kr = exclaves_scheduler_init(boot_info);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Init scheduler failed\n");
		return kr;
	}

	kr = exclaves_ipc_buffer_cache_init();
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "exclaves: failed to initialize IPC buffer cache\n");
		return kr;
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

/* -------------------------------------------------------------------------- */

#pragma mark exclaves ipc internals

#if CONFIG_EXCLAVES

static kern_return_t
exclaves_acquire_ipc_buffer(Exclaves_L4_IpcBuffer_t **out_ipcb,
    Exclaves_L4_Word_t *out_scid)
{
	kern_return_t kr = KERN_SUCCESS;
	Exclaves_L4_IpcBuffer_t *ipcb = NULL;
	Exclaves_L4_Word_t scid = 0;
	struct exclaves_ipc_buffer_cache_item *cached_buffer = NULL;


	_Static_assert(Exclaves_L4_IpcBuffer_Size < PAGE_SIZE,
	    "Invalid Exclaves_L4_IpcBuffer_Size");

	if (exclaves_ipc_buffer_cache_enabled) {
		lck_spin_lock(&exclaves_ipc_buffer_cache_lock);
		if (exclaves_ipc_buffer_cache != NULL) {
			cached_buffer = exclaves_ipc_buffer_cache;
			exclaves_ipc_buffer_cache = cached_buffer->next;
		}
		lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);
	}

	if (cached_buffer) {
		scid = cached_buffer->scid;

		/* zero out this usage of the buffer to avoid any confusion in xnuproxy */
		cached_buffer->next = NULL;
		cached_buffer->scid = 0;

		ipcb = (Exclaves_L4_IpcBuffer_t*)cached_buffer;
	} else {
		kr = exclaves_xnu_proxy_allocate_context(&scid, &ipcb);
		if (kr == KERN_NO_SPACE) {
			panic("Exclaves IPC buffer allocation failed");
		}
	}

	*out_ipcb = ipcb;
	*out_scid = scid;

	return kr;
}

size_t
exclaves_ipc_buffer_count(void)
{
	return os_atomic_load(&exclaves_ipcb_cnt, relaxed);
}

static kern_return_t
exclaves_relinquish_ipc_buffer(Exclaves_L4_IpcBuffer_t *ipcb,
    Exclaves_L4_Word_t scid)
{
	kern_return_t kr = KERN_SUCCESS;
	struct exclaves_ipc_buffer_cache_item *cached_buffer;

	if (!exclaves_ipc_buffer_cache_enabled) {
		kr = exclaves_xnu_proxy_free_context(scid);
	} else {
		cached_buffer = (struct exclaves_ipc_buffer_cache_item*)ipcb;
		cached_buffer->scid = scid;

		lck_spin_lock(&exclaves_ipc_buffer_cache_lock);
		cached_buffer->next = exclaves_ipc_buffer_cache;
		exclaves_ipc_buffer_cache = cached_buffer;
		lck_spin_unlock(&exclaves_ipc_buffer_cache_lock);
	}

	return kr;
}

static kern_return_t
exclaves_endpoint_call_internal(__unused ipc_port_t port,
    exclaves_id_t endpoint_id)
{
	kern_return_t kr = KERN_SUCCESS;

	assert(port == IPC_PORT_NULL);

	kr = exclaves_xnu_proxy_endpoint_call(endpoint_id);

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
	RINGGATE_STATUS_ERROR
};

OS_NOINLINE
static kern_return_t
exclaves_enter(void)
{
	uint32_t endpoint = RINGGATE_EP_ENTER;
	uint64_t result = RINGGATE_STATUS_ERROR;

	sptm_call_regs_t regs = { };

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_SWITCH)
	    | DBG_FUNC_START);
	recount_enter_secure();
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
	recount_leave_secure();
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_SWITCH)
	    | DBG_FUNC_END);


	if (result == RINGGATE_STATUS_ERROR) {
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

OS_NOINLINE
static kern_return_t
exclaves_bootinfo(uint64_t *out_boot_info)
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
	*out_boot_info = result;

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

	/*
	 * Match the hardwareID to the physical ID and stash the pointers to the
	 * request/response buffers in per-cpu data for quick access.
	 */
	size_t core_count = exclaves_callbacks->v1.cores();
	for (size_t i = 0; i < core_count; i++) {
		const XrtHosted_Core_t *core = exclaves_callbacks->v1.core(i);

		/* Find the physical ID of the entry at position hardwareId in the
		 * DeviceTree "cpus" array */
		uint32_t dt_phys_id = 0, dt_index = 0;
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
exclaves_scheduler_init(uint64_t boot_info)
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

	/* Initialise the XNU proxy */
	XrtHosted_Global_t *global = exclaves_callbacks->v1.global();

	exclaves_multicore = global->v2.smpStatus == XrtHosted_SmpStatus_Multicore;
	exclaves_multicore ?
	exclaves_init_multicore() :
	exclaves_init_unicore();

	uint64_t xnu_proxy_boot_info = global->v1.proxyInit;
	kr = exclaves_xnu_proxy_init(xnu_proxy_boot_info);

	return kr;
}

#if EXCLAVES_ENABLE_SHOW_SCHEDULER_REQUEST_RESPONSE
#define exclaves_scheduler_debug_save_buffer(_buf) \
	XrtHosted_Buffer_t _buf##_copy = *(_buf)
#define exclaves_scheduler_debug_show_request_response(_request_buf, \
	    _response_buf) ({ \
	if (exclaves_debug_enabled(show_scheduler_request_response)) { \
	        printf("exclaves: Scheduler request = %p\n", _request_buf); \
	        printf("exclaves: Scheduler request.tag = 0x%04llx\n", \
	            _request_buf##_copy.tag); \
	        for (size_t arg = 0; arg < XrtHosted_Buffer_args; arg += 1) { \
	                printf("exclaves: Scheduler request.arguments[%02zu] = " \
	                    "0x%04llx\n", arg, \
	                    _request_buf##_copy.arguments[arg]); \
	        } \
	        printf("exclaves: Scheduler response = %p\n", _response_buf); \
	        printf("exclaves: Scheduler response.tag = 0x%04llx\n", \
	                _response_buf##_copy.tag); \
	        for (size_t arg = 0; arg < XrtHosted_Buffer_args; arg += 1) { \
	                printf("exclaves: Scheduler response.arguments[%02zu] = " \
	                    "0x%04llx\n", arg, \
	                    _response_buf##_copy.arguments[arg]); \
	        } \
	}})
#else // EXCLAVES_SHOW_SCHEDULER_REQUEST_RESPONSE
#define exclaves_scheduler_debug_save_buffer(_buf) ({ })
#define exclaves_scheduler_debug_show_request_response(_request_buf, \
	    _response_buf) ({ })
#endif // EXCLAVES_SHOW_SCHEDULER_REQUEST_RESPONSE

__attribute__((always_inline))
static kern_return_t
exclaves_scheduler_request(const XrtHosted_Request_t *request, XrtHosted_Response_t *response)
{
	assert3u(request->tag, >, XrtHosted_Request_Invalid);
	assert3u(request->tag, <, XrtHosted_Request_Limit);

	kern_return_t kr = KERN_FAILURE;
	bool istate;
	thread_t thread = current_thread();

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

	while ((os_atomic_load(&thread->th_exclaves_inspection_state, relaxed) & ~TH_EXCLAVES_INSPECTION_NOINSPECT) != 0) {
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

	assert((thread->th_exclaves_intstate & TH_EXCLAVES_EXECUTION) == 0);
	thread->th_exclaves_intstate |= TH_EXCLAVES_EXECUTION;

	XrtHosted_Buffer_t *request_buf = *PERCPU_GET(exclaves_request);
	assert3p(request_buf, !=, NULL);

	exclaves_callbacks->v1.Request.encode(request_buf, request);
	exclaves_scheduler_debug_save_buffer(request_buf);

	kr = exclaves_enter();

	/* The response may have come back on a different core. */
	XrtHosted_Buffer_t *response_buf = *PERCPU_GET(exclaves_response);
	assert3p(response_buf, !=, NULL);

	exclaves_scheduler_debug_save_buffer(response_buf);
	exclaves_callbacks->v1.Response.decode(response_buf, response);

	thread->th_exclaves_intstate &= ~TH_EXCLAVES_EXECUTION;
	enable_preemption();
	(void) ml_set_interrupts_enabled_with_debug(istate, false);

	exclaves_scheduler_debug_show_request_response(request_buf, response_buf);

	if (!exclaves_multicore || !exclaves_smp_enabled) {
		lck_mtx_unlock(&exclaves_scheduler_lock);
	}

	return kr;
}

static kern_return_t
handle_response_yield(__assert_only Exclaves_L4_Word_t scid,
    const XrtHosted_Yield_t *yield)
{
	Exclaves_L4_Word_t responding_scid = yield->thread;
	Exclaves_L4_Word_t yielded_to_scid = yield->yieldTo;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: scid 0x%lx yielded to scid 0x%lx\n",
	    responding_scid, yielded_to_scid);
	/* TODO: 1. remember yielding scid if it isn't the xnu proxy's
	 * th_exclaves_scheduling_context_id so we know to resume it later
	 * 2. translate yield_to to thread_switch()-style handoff.
	 */
	assert3u(responding_scid, ==, scid);
	assert3u(yield->threadHostId, ==, ctid);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_YIELD), yielded_to_scid);

	return KERN_SUCCESS;
}

static kern_return_t
handle_response_spawned(__assert_only Exclaves_L4_Word_t scid,
    const XrtHosted_Spawned_t *spawned, Exclaves_L4_Word_t *spawned_scid)
{
	Exclaves_L4_Word_t responding_scid = spawned->thread;
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	if (spawned_scid == NULL) {
		exclaves_debug_printf(show_errors,
		    "exclaves: Scheduler: Unexpected thread spawn: "
		    "scid 0x%lx spawned scid 0x%llx\n",
		    responding_scid, spawned->spawned);
		return KERN_FAILURE;
	}

	*spawned_scid = spawned->spawned;
	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: scid 0x%lx spawned scid 0x%lx\n",
	    responding_scid, *spawned_scid);
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES_SCHEDULER,
	    MACH_EXCLAVES_SCHEDULER_SPAWNED), *spawned_scid);

	/* TODO: remember yielding scid if it isn't the xnu proxy's
	 * th_exclaves_scheduling_context_id so we know to resume it later
	 */
	if (0) {
		// FIXME: reenable when exclaves scheduler is fixed
		assert3u(responding_scid, ==, scid);
		assert3u(spawned->threadHostId, ==, ctid);
	}

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
	__assert_only ctid_t ctid = thread_get_ctid(current_thread());

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Wait: "
	    "scid 0x%lx wait on owner scid 0x%llx, queue id 0x%llx, "
	    "epoch 0x%llx\n", responding_scid, wait->owner,
	    wait->queueId, wait->epoch);
	assert3u(wait->waiterHostId, ==, ctid);

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
	const wait_result_t wr = esync_wait(&esync_queue_ht, id, epoch,
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

	kern_return_t kr = esync_wake(&esync_queue_ht, id, epoch,
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
	    ESYNC_WAKE_ONE);

	kern_return_t kr = esync_wake(&esync_queue_ht, id, epoch,
	    exclaves_get_queue_counter(id), ESYNC_WAKE_ONE_WITH_OWNER, owner);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES,
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

	assert3u(panic_thread_scid, ==, thread->th_exclaves_scheduling_context_id);

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

	const wait_result_t wr = esync_wait(&esync_thread_ht, id, epoch,
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

	kern_return_t kr = esync_wake(&esync_thread_ht, id, epoch,
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

	kern_return_t kr = esync_wake(&esync_queue_ht, id, epoch,
	    exclaves_get_queue_counter(id), ESYNC_WAKE_THREAD, target);

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES,
	    MACH_EXCLAVES_SCHEDULER_INTERRUPTED) | DBG_FUNC_END,
	    kr == KERN_SUCCESS ? THREAD_AWAKENED : THREAD_NOT_WAITING);

	return KERN_SUCCESS;
}

kern_return_t
exclaves_scheduler_resume_scheduling_context(Exclaves_L4_Word_t scid,
    Exclaves_L4_Word_t *spawned_scid, bool interrupted)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();
	const ctid_t ctid = thread_get_ctid(thread);

	exclaves_debug_printf(show_progress,
	    "exclaves: Scheduler: Request to resume scid 0x%lx\n", scid);

	XrtHosted_Response_t response = {};
	const XrtHosted_Request_t request = interrupted ?
	    XrtHosted_Request_InterruptWithHostIdMsg(
		.thread = scid,
		.hostId = ctid,
		) :
	    XrtHosted_Request_ResumeWithHostIdMsg(
		.thread = scid,
		.hostId = ctid,
		);
	kr = exclaves_scheduler_request(&request, &response);

	if (kr) {
		exclaves_debug_printf(show_errors, "exclaves: Enter failed\n");
		return kr;
	}

	switch (response.tag) {
	case XrtHosted_Response_Wait:
		return handle_response_wait(&response.Wait);

	case XrtHosted_Response_Wake:
		return handle_response_wake(&response.Wake);

	case XrtHosted_Response_Yield:
		return handle_response_yield(scid, &response.Yield);

	case XrtHosted_Response_Spawned:
		return handle_response_spawned(scid, &response.Spawned, spawned_scid);

	case XrtHosted_Response_Terminated:
		return handle_response_terminated(&response.Terminated);

	case XrtHosted_Response_WakeWithOwner:
		return handle_response_wake_with_owner(&response.WakeWithOwner);

	case XrtHosted_Response_PanicWait:
		return handle_response_panic_wait(&response.PanicWait);

	case XrtHosted_Response_Suspended:
		return handle_response_suspended(&response.Suspended);

	case XrtHosted_Response_Resumed:
		return handle_response_resumed(&response.Resumed);

	case XrtHosted_Response_Interrupted:
		return handle_response_interrupted(&response.Interrupted);

	case XrtHosted_Response_Invalid:
	case XrtHosted_Response_Failure:
	case XrtHosted_Response_Pong:
	case XrtHosted_Response_SleepUntil:
	case XrtHosted_Response_Awaken:
	default:
		exclaves_debug_printf(show_errors,
		    "exclaves: Scheduler: Unexpected response: tag 0x%x\n",
		    response.tag);
		return KERN_FAILURE;
	}
}

/* -------------------------------------------------------------------------- */

#pragma mark exclaves xnu proxy communication
static const char *
cmd_to_str(xnuproxy_cmd_t cmd)
{
	switch (cmd) {
	case XNUPROXY_CMD_UNDEFINED:           return "undefined";
	case XNUPROXY_CMD_SETUP:               return "setup";
	case XNUPROXY_CMD_CONTEXT_ALLOCATE:    return "allocate context";
	case XNUPROXY_CMD_CONTEXT_FREE:        return "free context";
	case XNUPROXY_CMD_NAMED_BUFFER_CREATE: return "named buffer create";
	case XNUPROXY_CMD_NAMED_BUFFER_DELETE: return "named buffer delete";
	case XNUPROXY_CMD_RESOURCE_INFO:       return "resource info";
	case XNUPROXY_CMD_AUDIO_BUFFER_CREATE: return "audio buffer create";
	case XNUPROXY_CMD_AUDIO_BUFFER_COPYOUT: return "audio buffer copyout";
	case XNUPROXY_CMD_AUDIO_BUFFER_DELETE: return "audio buffer delete";
	case XNUPROXY_CMD_SENSOR_START:        return "sensor start";
	case XNUPROXY_CMD_SENSOR_STOP:         return "sensor stop";
	case XNUPROXY_CMD_SENSOR_STATUS:       return "sensor status";
	case XNUPROXY_CMD_DISPLAY_HEALTHCHECK_RATE: return "display healthcheck rate";
	case XNUPROXY_CMD_NAMED_BUFFER_MAP:    return "named buffer map";
	case XNUPROXY_CMD_NAMED_BUFFER_LAYOUT: return "named buffer layout";
	case XNUPROXY_CMD_AUDIO_BUFFER_MAP:    return "audio buffer map";
	case XNUPROXY_CMD_AUDIO_BUFFER_LAYOUT: return "audio buffer layout";
	default:                               return "<unknown>";
	}
}
#define exclaves_xnu_proxy_debug(flag, step, msg) \
	exclaves_debug_printf(flag, \
	    "exclaves: xnu proxy %s " #step ":\t" \
	    "msg %p server_id 0x%lx cmd %u status %u\n", \
	    cmd_to_str((msg)->cmd), (msg), (msg)->server_id, (msg)->cmd, \
	    os_atomic_load(&(msg)->status, relaxed))
#define exclaves_xnu_proxy_show_progress(step, msg) \
	exclaves_xnu_proxy_debug(show_progress, step, msg)
#define exclaves_xnu_proxy_show_error(msg) \
	exclaves_xnu_proxy_debug(show_errors, failed, msg)
#define exclaves_xnu_proxy_endpoint_call_show_progress(operation, step, \
	    eid, scid, status) \
	exclaves_debug_printf(show_progress, \
	    "exclaves: xnu proxy endpoint " #operation " " #step ":\t" \
	    "endpoint id %ld scid 0x%lx status %u\n", \
	    (eid), (scid), (status))

static xnuproxy_msg_t *exclaves_xnu_proxy_msg_buffer;
static uint64_t exclaves_xnu_proxy_scid;

extern kern_return_t exclaves_xnu_proxy_send(xnuproxy_msg_t *, Exclaves_L4_Word_t *);
kern_return_t
exclaves_xnu_proxy_send(xnuproxy_msg_t *_msg, Exclaves_L4_Word_t *spawned)
{
	assert3p(_msg, !=, NULL);

	if (exclaves_xnu_proxy_msg_buffer == NULL) {
		return KERN_FAILURE;
	}

	kern_return_t kr = KERN_SUCCESS;
	xnuproxy_msg_t *msg = exclaves_xnu_proxy_msg_buffer;
	bool interrupted = false;

	lck_mtx_lock(&exclaves_xnu_proxy_lock);
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_XNUPROXY)
	    | DBG_FUNC_START, exclaves_xnu_proxy_scid, _msg->cmd);

	*msg = *_msg;
	msg->server_id = exclaves_xnu_proxy_scid;

	os_atomic_store(&msg->status, XNUPROXY_MSG_STATUS_PROCESSING,
	    release);

	while (os_atomic_load(&msg->status, relaxed) ==
	    XNUPROXY_MSG_STATUS_PROCESSING) {
		exclaves_xnu_proxy_show_progress(in progress, msg);
		kr = exclaves_scheduler_resume_scheduling_context(msg->server_id,
		    spawned, interrupted);
		assert(kr == KERN_SUCCESS || kr == KERN_ABORTED);

		/* A wait was interrupted. */
		interrupted = kr == KERN_ABORTED;
	}
	if (os_atomic_load(&msg->status, acquire) ==
	    XNUPROXY_MSG_STATUS_NONE) {
		exclaves_xnu_proxy_show_progress(complete, msg);
	} else {
		kr = KERN_FAILURE;
		exclaves_xnu_proxy_show_error(msg);
	}

	*_msg = *msg;

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_XNUPROXY)
	    | DBG_FUNC_END);
	lck_mtx_unlock(&exclaves_xnu_proxy_lock);

	return kr;
}

static kern_return_t
exclaves_xnu_proxy_init(uint64_t xnu_proxy_boot_info)
{
	kern_return_t kr = KERN_SUCCESS;
	pmap_paddr_t msg_buffer_paddr = xnu_proxy_boot_info;

	lck_mtx_assert(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);

	if (msg_buffer_paddr && pmap_valid_address(msg_buffer_paddr)) {
		lck_mtx_lock(&exclaves_xnu_proxy_lock);
		exclaves_xnu_proxy_msg_buffer =
		    (xnuproxy_msg_t*)phystokv(msg_buffer_paddr);
		exclaves_xnu_proxy_scid =
		    exclaves_xnu_proxy_msg_buffer->server_id;
		lck_mtx_unlock(&exclaves_xnu_proxy_lock);
	} else {
		exclaves_debug_printf(show_errors,
		    "exclaves: %s: 0x%012llx\n",
		    "Invalid xnu proxy boot info physical address",
		    xnu_proxy_boot_info);
		return KERN_FAILURE;
	}

	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_SETUP,
	};

	kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (msg.cmd_setup.response.version != XNUPROXY_MSG_VERSION) {
		exclaves_debug_printf(show_errors,
		    "exclaves: mismatched xnuproxy message version, "
		    "xnuproxy: %u, xnu: %u  ", msg.cmd_setup.response.version,
		    XNUPROXY_MSG_VERSION);
		return KERN_FAILURE;
	}

	exclaves_debug_printf(show_progress,
	    "exclaves: xnuproxy message version: 0x%u\n", XNUPROXY_MSG_VERSION);

	kr = exclaves_panic_thread_setup();
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "XNU proxy panic thread setup failed\n");
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

static kern_return_t
exclaves_xnu_proxy_allocate_context(Exclaves_L4_Word_t *scid,
    Exclaves_L4_IpcBuffer_t **ipcb)
{
	kern_return_t kr = KERN_FAILURE;
	Exclaves_L4_Word_t spawned_scid = 0;

	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_CONTEXT_ALLOCATE,
	};

	kr = exclaves_xnu_proxy_send(&msg, &spawned_scid);
	if (kr != KERN_SUCCESS) {
		return kr;
	}

	if (msg.cmd_ctx_alloc.response.ipc_paddr == 0) {
		return KERN_NO_SPACE;
	}

	if (spawned_scid != 0) {
		assert3u(msg.cmd_ctx_alloc.response.sched_id, ==, spawned_scid);
	}

	*scid = msg.cmd_ctx_alloc.response.sched_id;
	*ipcb = (Exclaves_L4_IpcBuffer_t *)
	    phystokv(msg.cmd_ctx_alloc.response.ipc_paddr);
	os_atomic_inc(&exclaves_ipcb_cnt, relaxed);

	return KERN_SUCCESS;
}

static kern_return_t
exclaves_xnu_proxy_free_context(Exclaves_L4_Word_t scid)
{
	kern_return_t kr = KERN_FAILURE;
	xnuproxy_msg_t msg = {
		.cmd = XNUPROXY_CMD_CONTEXT_FREE,
		.cmd_ctx_free = (xnuproxy_cmd_ctx_free_t) {
			.request.sched_id = scid,
			.request.destroy = false,
		},
	};

	kr = exclaves_xnu_proxy_send(&msg, NULL);
	if (kr == KERN_SUCCESS) {
		size_t orig_ipcb_cnt = os_atomic_dec_orig(&exclaves_ipcb_cnt, relaxed);
		assert3u(orig_ipcb_cnt, >=, 1);
		if (orig_ipcb_cnt == 0) { /* This is just to avoid unused variable warning */
			kr = KERN_FAILURE;
		}
	}
	return kr;
}

OS_NOINLINE
static kern_return_t
exclaves_xnu_proxy_endpoint_call(Exclaves_L4_Word_t endpoint_id)
{
	kern_return_t kr = KERN_SUCCESS;
	thread_t thread = current_thread();
	bool interrupted = false;

	Exclaves_L4_Word_t scid = thread->th_exclaves_scheduling_context_id;
	Exclaves_L4_IpcBuffer_t *ipcb = thread->th_exclaves_ipc_buffer;
	xnuproxy_msg_status_t status =
	    XNUPROXY_MSG_STATUS_PROCESSING;

	XNUPROXY_CR_ENDPOINT_ID(ipcb) = endpoint_id;
	XNUPROXY_CR_STATUS(ipcb) = status;

	exclaves_xnu_proxy_endpoint_call_show_progress(call, entry,
	    endpoint_id, scid, status);

	assert((thread->th_exclaves_state &
	    (TH_EXCLAVES_RPC | TH_EXCLAVES_UPCALL)) == 0);
	thread->th_exclaves_state |= TH_EXCLAVES_RPC;
	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_RPC)
	    | DBG_FUNC_START, scid, endpoint_id);

	while (1) {
		kr = exclaves_scheduler_resume_scheduling_context(scid, NULL,
		    interrupted);
		assert(kr == KERN_SUCCESS || kr == KERN_ABORTED);

		/* A wait was interrupted. */
		interrupted = kr == KERN_ABORTED;

		status = (xnuproxy_msg_status_t)
		    XNUPROXY_CR_STATUS(ipcb);

		switch (status) {
		case XNUPROXY_MSG_STATUS_PROCESSING:
			exclaves_xnu_proxy_endpoint_call_show_progress(call, yielded,
			    endpoint_id, scid, status);
			continue;

		case XNUPROXY_MSG_STATUS_REPLY:
			exclaves_xnu_proxy_endpoint_call_show_progress(call, returned,
			    endpoint_id, scid, status);
			kr = KERN_SUCCESS;
			break;

		case XNUPROXY_MSG_STATUS_UPCALL:
			thread->th_exclaves_state |= TH_EXCLAVES_UPCALL;
			endpoint_id = XNUPROXY_CR_ENDPOINT_ID(ipcb);
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_UPCALL)
			    | DBG_FUNC_START, scid, endpoint_id);
			exclaves_xnu_proxy_endpoint_call_show_progress(upcall, entry,
			    endpoint_id, scid, status);
			__asm__ volatile (
                                "EXCLAVES_UPCALL_START: nop\n\t"
                        );
			kr = exclaves_call_upcall_handler(endpoint_id);
			__asm__ volatile (
                                "EXCLAVES_UPCALL_END: nop\n\t"
                        );
			XNUPROXY_CR_STATUS(ipcb) =
			    XNUPROXY_MSG_STATUS_PROCESSING;
			/* TODO: More state returned than Success or OperationInvalid? */
			XNUPROXY_CR_RETVAL(ipcb) =
			    (kr == KERN_SUCCESS) ? Exclaves_L4_Success :
			    Exclaves_L4_ErrorOperationInvalid;
			KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_UPCALL)
			    | DBG_FUNC_END);
			thread->th_exclaves_state &= ~TH_EXCLAVES_UPCALL;
			exclaves_xnu_proxy_endpoint_call_show_progress(upcall, returned,
			    endpoint_id, scid,
			    (unsigned int)XNUPROXY_CR_RETVAL(ipcb));
			continue;

		default:
			// Should we have an assert(valid return) here?
			exclaves_xnu_proxy_endpoint_call_show_progress(call, failed,
			    endpoint_id, scid, status);
			kr = KERN_FAILURE;
			break;
		}
		break;
	}

	KDBG_RELEASE(MACHDBG_CODE(DBG_MACH_EXCLAVES, MACH_EXCLAVES_RPC)
	    | DBG_FUNC_END);
	thread->th_exclaves_state &= ~TH_EXCLAVES_RPC;

	return kr;
}

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

kern_return_t
exclaves_ipc_buffer_cache_init(void)
{
	kern_return_t kr = KERN_SUCCESS;
	Exclaves_L4_IpcBuffer_t *ipcb = NULL;
	Exclaves_L4_Word_t scid = 0;

	LCK_MTX_ASSERT(&exclaves_boot_lock, LCK_MTX_ASSERT_OWNED);
	assert(exclaves_ipc_buffer_cache == NULL);

	if (exclaves_ipc_buffer_cache_enabled) {
		if ((kr = exclaves_xnu_proxy_allocate_context(&scid, &ipcb))) {
			return kr;
		}

		/* relinquish the new buffer into the cache */
		exclaves_relinquish_ipc_buffer(ipcb, scid);
	}
	return kr;
}

exclaves_id_t
exclaves_endpoint_lookup(const char *name)
{
	exclaves_id_t id;

	/*
	 * First look-up in the kernel domain, fallback to the darwin domain if
	 * not found.
	 */
	id = exclaves_service_lookup(EXCLAVES_DOMAIN_KERNEL, name);
	if (id == UINT64_C(~0)) {
		id = exclaves_service_lookup(EXCLAVES_DOMAIN_DARWIN, name);
	}

	assert3u(id, !=, UINT64_C(~0));

	return id;
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
