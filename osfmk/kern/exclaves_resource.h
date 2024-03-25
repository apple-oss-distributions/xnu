/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#pragma once

#include <kern/locks.h>
#include <kern/queue.h>
#include <mach/exclaves.h>
#include <mach/kern_return.h>
#include <sys/event.h>

#include <stdint.h>
#include <os/base.h>

#include <libxnuproxy/messages.h>

#include "kern/exclaves.tightbeam.h"

__BEGIN_DECLS


/* -------------------------------------------------------------------------- */
#pragma mark Exclaves Resources

#define EXCLAVES_DOMAIN_KERNEL "com.apple.kernel"
#define EXCLAVES_DOMAIN_DARWIN "com.apple.darwin"

/*
 * Data associated with a conclave.
 */

/*
 * Conclave State Machine:
 *
 *                 Launch Syscall
 *       +---------+         +--------------+
 *       |Attached | ------->|  Launching   |
 *       |         |         |              |
 *       +---------+         +--------------+
 *          ^ |                 |       |
 *    Spawn | |proc_exit   Exit |       |   Start IPC
 *          | |                 |       |  to Conclave Manager
 *          | v                 v       v
 *      +---------+   +-----------+   +----------+
 * *--> |  None   |   |    Stop   |   | Launched |
 *      |         |   | Requested |   |          |
 *      +---------+   +-----------+   +----------+
 *           ^                  |       |
 *  proc_exit|          Launch  |       |  Exit
 *           |        Completion|       |
 *           |                  v       v
 *         +---------+       +------------+
 *         | Stopped |<------|  Stopping  |
 *         |         |       |            |
 *         +---------+       +------------+
 *                    Stop IPC
 *                   to Conclave Manager
 */
typedef enum  {
	CONCLAVE_S_NONE = 0,
	CONCLAVE_S_ATTACHED,
	CONCLAVE_S_LAUNCHING,
	CONCLAVE_S_LAUNCHED,
	CONCLAVE_S_STOP_REQUESTED,
	CONCLAVE_S_STOPPING,
	CONCLAVE_S_STOPPED,
} conclave_state_t;

typedef struct {
	conclave_state_t       c_state;
	tb_client_connection_t c_control;
	task_t                 c_task;
} conclave_resource_t;

#define EXCLAVES_SHARED_BUFFER_MAX_RANGES 64

typedef struct {
	char *address;
	size_t npages;
} named_buffer_range_t;

typedef struct {
	size_t nb_size;
	exclaves_buffer_perm_t nb_perm;
	size_t nb_nranges;
	named_buffer_range_t nb_range[EXCLAVES_SHARED_BUFFER_MAX_RANGES];
} named_buffer_resource_t;

typedef struct {
	size_t sm_size;
	exclaves_buffer_perm_t sm_perm;
	size_t sm_nranges;
	named_buffer_range_t sm_range[EXCLAVES_SHARED_BUFFER_MAX_RANGES];
	sharedmemorybase_mapping_s sm_mapping;
	sharedmemorybase_segxnuaccess_s sm_client;
} shared_memory_resource_t;

typedef struct {
	/* how many times *this* sensor resource handle has been
	 * used to call sensor_start */
	uint64_t s_startcount;
} sensor_resource_t;

typedef struct {
	struct klist notification_klist;
} exclaves_notification_t;

/*
 * Every resource has an associated name and some other common state.
 * Additionally there may be type specific data associated with the resource.
 */
typedef struct exclaves_resource {
	char                r_name[XNUPROXY_RESOURCE_NAME_MAX];
	xnuproxy_resource_t r_type;
	uint64_t            r_id;
	_Atomic uint32_t    r_usecnt;
	ipc_port_t          r_port;
	lck_mtx_t           r_mutex;
	bool                r_active;

	union {
		conclave_resource_t     r_conclave;
		named_buffer_resource_t r_named_buffer;
		sensor_resource_t       r_sensor;
		exclaves_notification_t r_notification;
		shared_memory_resource_t r_shared_memory;
	};
} exclaves_resource_t;

/*!
 * @function exclaves_resource_init
 *
 * @abstract
 * Called during exclaves_boot to dump the resource information from xnu proxy
 * and build the xnu-side tables.
 *
 * @return
 * KERN_SUCCESS on success otherwise an error code.
 */
extern kern_return_t
exclaves_resource_init(void);

/*!
 * @function exclaves_resource_name
 *
 * @abstract
 * Return the name associated with a resource.
 *
 * @param resource
 * Conclave manager resource.
 *
 * @return
 * The name of the resource or NULL.
 */
extern const char *
exclaves_resource_name(const exclaves_resource_t *resource);

/*!
 * @function exclaves_resource_retain
 *
 * @abstract
 * Grab a reference to the specified resource
 *
 * @param resource
 * The resource to retain.
 *
 * @return
 * The value of the use count before the retain
 */
extern uint32_t
exclaves_resource_retain(exclaves_resource_t *resource);

/*!
 * @function exclaves_resource_release
 *
 * @abstract
 * Drop a reference to the specified resource
 *
 * @param resource
 * The resource to release.
 *
 * @discussion
 * This may result in a resource type specific release function being called
 * which can grab locks, free memory etc.
 * After this function has been called, the resource should not be accessed as
 * it may be in an uninitialized state.
 */
extern void
exclaves_resource_release(exclaves_resource_t *resource);

/*!
 * @function exclaves_resource_from_port_name
 *
 * @abstract
 * Find the resource associated with a port name in the specified space.
 *
 * @param space
 * IPC space to search
 *
 * @param name
 * Port name of the resource.
 *
 * @param resource
 * Out parameter holding a pointer to the resource.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_resource_from_port_name(ipc_space_t space, mach_port_name_t name,
    exclaves_resource_t **resource);


/*!
 * @function exclaves_resource_create_port_name
 *
 * @abstract
 * Create a port name for the given resource in the specified space.
 *
 * @param name
 * Our parameter for holding a pointer to the port name.
 *
 * @param space
 * IPC space in which to create the name
 *
 * @param resource
 * Resource for which to create a port name for.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which is associated with the life
 * of the newly created send right.
 */
extern kern_return_t
exclaves_resource_create_port_name(exclaves_resource_t *resource, ipc_space_t space,
    mach_port_name_t *name);




/* -------------------------------------------------------------------------- */
#pragma mark Named Buffers

/*!
 * @function exclaves_named_buffer_map
 *
 * @abstract
 * Map a named buffer resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of the named buffer resource.
 *
 * @param size
 * Size of named buffer region to map.
 *
 * @param perm
 * The permissions of the named buffer.
 *
 * @param resource
 * Out parameter which holds the resource on success.
 *
 * @return
 * KERN_SUCCESS or an error code.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_named_buffer_map(const char *domain, const char *name, size_t size,
    exclaves_buffer_perm_t perm, exclaves_resource_t **resource);

/*!
 * @function exclaves_named_buffer_copyin
 *
 * @abstract
 * Copy user data into a named buffer.
 *
 * @param resource
 * Named buffer resource.
 *
 * @param ubuffer
 * Source of data to copy.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the named buffer.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the named buffer.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_named_buffer_copyin(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);

/*!
 * @function exclaves_named_buffer_copyout
 *
 * @abstract
 * Copy user data into a named buffer.
 *
 * @param resource
 * Named buffer resource.
 *
 * @param ubuffer
 * Destination to copy data to.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the named buffer.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the named buffer.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_named_buffer_copyout(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);


/*!
 * @function exclaves_named_buffer_io
 *
 * @abstract
 * Perform IO on a named buffer
 *
 * @param resource
 * Named buffer resource.
 *
 * @param offset
 * Offset into the named buffer
 *
 * @param len
 * Size of the IO
 *
 * @param cb
 * A block which is called (potentially) multiple times to perform the IO.
 *
 * @return
 * 0 on success. If cb returns a non-zero value, exclaves_named_buffer_io()
 * immediately returns with that non-zero value.
 */
extern int
    exclaves_named_buffer_io(exclaves_resource_t * resource, off_t offset,
    size_t len, int (^cb)(char *buffer, size_t size));

/* -------------------------------------------------------------------------- */
#pragma mark Audio buffers

/*!
 * @function exclaves_audio_buffer_map
 *
 * @abstract
 * Map an audio buffer resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of audio buffer resource.
 *
 * @param size
 * Size of named buffer region to map.
 *
 * @param resource
 * Out parameter which holds the resource on success.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_audio_buffer_map(const char *domain, const char *name, size_t size,
    exclaves_resource_t **resource);

/*!
 * @function exclaves_audio_buffer_copyout
 *
 * @abstract
 * Copy user data into a audio buffer.
 *
 * @param resource
 * audio buffer resource.
 *
 * @param ubuffer
 * Destination to copy data to.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the audio buffer.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the audio buffer.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_audio_buffer_copyout(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);




/* -------------------------------------------------------------------------- */
#pragma mark Conclaves

/*!
 * @function exclaves_conclave_attach
 *
 * @abstract
 * Attach a conclave to a task. The conclave must not already be attached to any
 * task. Once attached, this conclave is exclusively associated with the task.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of conclave resource.
 *
 * @param task
 * Task to attach the conclave to.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t
exclaves_conclave_attach(const char *domain, const char *name, task_t task);

/*!
 * @function exclaves_conclave_detach
 *
 * @abstract
 * Detach a conclave from a task. The conclave must already be attached to the
 * task and stopped. Once detached, this conclave is available for other tasks.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @param task
 * Task to detach the conclave from.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t
exclaves_conclave_detach(exclaves_resource_t *resource, task_t task);

/*!
 * @function exclaves_conclave_inherit
 *
 * @abstract
 * Pass an attached conclave from one task to another.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @param old_task
 * Task with attached conclave.
 *
 * @param new_task
 * Task which will inherit the conclave.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t
exclaves_conclave_inherit(exclaves_resource_t *resource, task_t old_task,
    task_t new_task);

/*!
 * @function exclaves_conclave_launch
 *
 * @abstract
 * Launch a conclave. The conclave must be attached to a task and not already
 * launched.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t exclaves_conclave_launch(exclaves_resource_t *resource);

/*!
 * @function exclaves_conclave_lookup_resources
 *
 * @abstract
 * Lookup conclave resource. The conclave must be attached to a task and
 * launched.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @param conclave_resource_user
 * Array to fill user resources for Conclave
 *
 * @param resource_count
 * Number of resources in array
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t exclaves_conclave_lookup_resources(exclaves_resource_t *resource,
    struct exclaves_resource_user *conclave_resource_user, int resource_count);

/*!
 * @function exclaves_conclave_stop
 *
 * @abstract
 * Stop a conclave. The conclave must be launched and attached.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @param gather_crash_bt
 * Conclave Manager needs to gather backtraces
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t exclaves_conclave_stop(exclaves_resource_t *resource, bool gather_crash_bt);

/*!
 * @function exclaves_conclave_stop_upcall
 *
 * @abstract
 * Stop a conclave. The conclave must be launched and attached.
 *
 * @param resource
 * Conclave Manager resource.
 *
 * @param task
 * Conclave Host task
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t exclaves_conclave_stop_upcall(exclaves_resource_t *resource, task_t task);

/* -------------------------------------------------------------------------- */
#pragma mark Sensors

/*!
 * @function exclaves_resource_sensor_open
 *
 * @abstract
 * Open a sensor resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of the sensor resource.
 *
 * @param resource
 * Out parameter which holds the resource on success.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_resource_sensor_open(const char *domain, const char *name,
    exclaves_resource_t **resource);

/*!
 * @function exclaves_resource_sensor_start
 *
 * @abstract
 * Start accessing a sensor.
 *
 * @param resource
 * Sensor resource.
 *
 * @param flags
 * Flags to pass to implementation.
 *
 * @param status
 * output parameter for status of sensor after this operation.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
kern_return_t
exclaves_resource_sensor_start(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status);

/*!
 * @function exclaves_resource_sensor_stop
 *
 * @abstract
 * Stop accessing a sensor.
 *
 * @param resource
 * Sensor resource.
 *
 * @param flags
 * Flags to pass to implementation.
 *
 * @param status
 * output parameter for status of sensor after this operation.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
kern_return_t
exclaves_resource_sensor_stop(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status);

/*!
 * @function exclaves_resource_sensor_status
 *
 * @abstract
 * Query the status of access to a sensor.
 *
 * @param resource
 * Sensor resource.
 *
 * @param flags
 * Flags to pass to implementation.
 *
 * @param status
 * output parameter for status of sensor after this operation.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
kern_return_t
exclaves_resource_sensor_status(exclaves_resource_t *resource, uint64_t flags,
    exclaves_sensor_status_t *status);

/* -------------------------------------------------------------------------- */
#pragma mark Notifications

/*!
 * @function exclaves_notification_create
 *
 * @abstract
 * Set up an exclave notification from the specified resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of the notification resource.
 *
 * @return
 * A notification resource or NULL.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_notification_create(const char *domain, const char *name,
    exclaves_resource_t **resource);

/*!
 * @function exclaves_notification_signal
 *
 * @abstract
 * To be called from upcall context when the specified notification resource is signaled.
 *
 * @param resource
 * Notification resource.
 *
 * @param event_mask
 * Bit mask of events for the notification.
 *
 * @return
 * KERN_SUCCESS on success, error code otherwise.
 */
extern kern_return_t
exclaves_notification_signal(exclaves_resource_t *resource, long event_mask);


/*!
 * @function exclaves_notificatione_lookup_by_id
 *
 * @abstract
 * Find an exclave notification  by ID.
 *
 * @param id
 * The resource ID.
 *
 * @param domain
 * The domain to search.
 *
 * @return
 * Pointer to the resource
 */
exclaves_resource_t *
exclaves_notification_lookup_by_id(const char *domain, uint64_t id);


/* -------------------------------------------------------------------------- */
#pragma mark Services

/*!
 * @function exclaves_service_lookup
 *
 * @abstract
 * Look up a service resource
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of the service resource.
 *
 * @return
 * ID of service or -1 if the service cannot be found.
 */
extern uint64_t
exclaves_service_lookup(const char *domain, const char *name);


/* -------------------------------------------------------------------------- */
#pragma mark Shared Memory

/*!
 * @function exclaves_resource_shared_memory_map
 *
 * @abstract
 * Map a shared memory resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of the shared memory resource.
 *
 * @param size
 * Size of shared memory region to map.
 *
 * @param perm
 * The permissions of the shared memory.
 *
 * @param resource
 * Out parameter which holds the resource on success.
 *
 * @return
 * KERN_SUCCESS or an error code.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_resource_shared_memory_map(const char *domain, const char *name,
    size_t size, exclaves_buffer_perm_t perm, exclaves_resource_t **resource);

/*!
 * @function exclaves_resource_shared_memory_copyin
 *
 * @abstract
 * Copy user data into a shared memory.
 *
 * @param resource
 * Named buffer resource.
 *
 * @param ubuffer
 * Source of data to copy.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the shared memory.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the shared memory.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_resource_shared_memory_copyin(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);

/*!
 * @function exclaves_resource_shared_memory_copyout
 *
 * @abstract
 * Copy user data into a shared memory.
 *
 * @param resource
 * Named buffer resource.
 *
 * @param ubuffer
 * Destination to copy data to.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the shared memory.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the shared memory.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_resource_shared_memory_copyout(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);


/*!
 * @function exclaves_resource_shared_memory_io
 *
 * @abstract
 * Perform IO on a shared memory
 *
 * @param resource
 * Named buffer resource.
 *
 * @param offset
 * Offset into the shared memory
 *
 * @param len
 * Size of the IO
 *
 * @param cb
 * A block which is called (potentially) multiple times to perform the IO.
 *
 * @return
 * 0 on success. If cb returns a non-zero value, exclaves_resource_shared_memory_io()
 * immediately returns with that non-zero value.
 */
extern int
    exclaves_resource_shared_memory_io(exclaves_resource_t * resource, off_t offset,
    size_t len, int (^cb)(char *buffer, size_t size));


/* -------------------------------------------------------------------------- */
#pragma mark Arbitrated Audio Memory

/*!
 * @function exclaves_resource_audio_memory_map
 *
 * @abstract
 * Map an audio memory resource.
 *
 * @param domain
 * The domain to search.
 *
 * @param name
 * The name of audio memory resource.
 *
 * @param size
 * Size of named buffer region to map.
 *
 * @param resource
 * Out parameter which holds the resource on success.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 *
 * @discussion
 * Returns with a +1 use-count on the resource which must be dropped with
 * exclaves_resource_release().
 */
extern kern_return_t
exclaves_resource_audio_memory_map(const char *domain, const char *name, size_t size,
    exclaves_resource_t **resource);

/*!
 * @function exclaves_resource_audio_memory_copyout
 *
 * @abstract
 * Copy user data into a audio memory.
 *
 * @param resource
 * audio memory resource.
 *
 * @param ubuffer
 * Destination to copy data to.
 *
 * @param usize1
 * Size of data to copy.
 *
 * @param uoffset1
 * Offset into the audio memory.
 *
 * @param usize2
 * Size of 2nd range of data to copy (can be 0).
 *
 * @param uoffset2
 * Offset of 2nd range into the audio memory.
 *
 * @return
 * KERN_SUCCESS or error code on failure.
 */
extern kern_return_t
exclaves_resource_audio_memory_copyout(exclaves_resource_t *resource,
    user_addr_t ubuffer, mach_vm_size_t usize1, mach_vm_size_t uoffset1,
    mach_vm_size_t usize2, mach_vm_size_t uoffset2);

extern exclaves_resource_t *
exclaves_resource_lookup_by_name(const char *domain_name, const char *name,
    xnuproxy_resource_t type);

kern_return_t
exclaves_xnu_proxy_check_mem_usage(void);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
