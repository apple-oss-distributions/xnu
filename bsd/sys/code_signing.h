/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#ifndef _SYS_CODE_SIGNING_H_
#define _SYS_CODE_SIGNING_H_

#include <sys/cdefs.h>
__BEGIN_DECLS

#ifdef KERNEL_PRIVATE
/* All definitions for XNU and kernel extensions */

#ifdef XNU_KERNEL_PRIVATE
/* All definitions for XNU only */

#include <vm/pmap_cs.h>

#if   PMAP_CS_PPL_MONITOR
#define CODE_SIGNING_MONITOR 1
#else
#define CODE_SIGNING_MONITOR 0
#endif

#if CODE_SIGNING_MONITOR
/* All definitions which are only required for monitor-specific code */

/**
 * This function is used to initialize the state of the locks for managing provisioning
 * profiles on the system. It should be called by the kernel bootstrap thread during the
 * early kernel initialization.
 */
void
initialize_provisioning_profiles(void);

/**
 * Register a provisioning profile with the monitor environment available on the
 * system. This function will allocate its own memory for managing the profile and
 * the caller is allowed to free their own allocation.
 */
kern_return_t
register_provisioning_profile(
	const uuid_t profile_uuid,
	const void *profile, const size_t profile_size);

/**
 * Associate a registered profile with a code signature object which is managed by
 * the monitor environment. This incrementes the reference count on the profile object
 * managed by the monitor, preventing the profile from being unregistered.
 */
kern_return_t
associate_provisioning_profile(
	void *monitor_sig_obj,
	const uuid_t profile_uuid);

/**
 * Disassociate an associated profile with a code signature object which is managed by
 * the monitor environment. This decrements the refernce count on the profile object
 * managed by the monitor, potentially allowing it to be unregistered in case no other
 * signatures hold a reference count to it.
 */
kern_return_t
disassociate_provisioning_profile(
	void *monitor_sig_obj);

/**
 * Trigger the provisioning profile garbage collector to go through each registered
 * profile on the system and unregister it in case it isn't being used.
 */
void
free_provisioning_profiles(void);

#endif /* CODE_SIGNING_MONITOR */

#endif /* XNU_KERNEL_PRIVATE */

#include <mach/boolean.h>
#include <mach/kern_return.h>

/* Availability macros for KPI functions */
#define XNU_SUPPORTS_PROFILE_GARBAGE_COLLECTION 1

/**
 * Enable developer mode on the system. When the system contains a monitor environment,
 * developer mode is turned on by trapping into the appropriate monitor environment.
 */
void
enable_developer_mode(void);

/**
 * Disable developer mode on the system. When the system contains a monitor environment,
 * developer mode is turned off by trapping into the appropriate monitor environment.
 */
void
disable_developer_mode(void);

/**
 * Query the current state of developer mode on the system. This call never traps into
 * the monitor environment because XNU can directly read the monitors memory.
 */
bool
developer_mode_state(void);

/**
 * Wrapper function which is exposed to kernel extensions. This can be used to trigger
 * a call to the garbage collector for going through and unregistring all unused profiles
 * on the system.
 */
void
garbage_collect_provisioning_profiles(void);

#endif /* KERNEL_PRIVATE */

__END_DECLS
#endif /* _SYS_CODE_SIGNING_H_ */
