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

typedef uint32_t code_signing_monitor_type_t;
enum {
	CS_MONITOR_TYPE_NONE = 0,
	CS_MONITOR_TYPE_PPL = 1,

};

typedef uint32_t code_signing_config_t;
enum {
	CS_CONFIG_UNRESTRICTED_DEBUGGING = (1 << 0),
	CS_CONFIG_ALLOW_ANY_SIGNATURE = (1 << 1),
	CS_CONFIG_ENFORCEMENT_DISABLED = (1 << 2),
	CS_CONFIG_GET_OUT_OF_MY_WAY = (1 << 3),
	CS_CONFIG_CSM_ENABLED = (1 << 31),
};

#ifdef KERNEL_PRIVATE
/* All definitions for XNU and kernel extensions */

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <img4/firmware.h>

/* Availability macros for KPI functions */
#define XNU_SUPPORTS_CSM_TYPE 1
#define XNU_SUPPORTS_CSM_APPLE_IMAGE4 1
#define XNU_SUPPORTS_PROFILE_GARBAGE_COLLECTION 1
#define XNU_SUPPORTS_COMPILATION_SERVICE 1
#define XNU_SUPPORTS_LOCAL_SIGNING 1
#define XNU_SUPPORTS_CE_ACCELERATION 1

/* Local signing public key size */
#define XNU_LOCAL_SIGNING_KEY_SIZE 97

#if XNU_KERNEL_PRIVATE

#include <sys/code_signing_internal.h>
#include <libkern/img4/interface.h>

#if PMAP_CS_INCLUDE_CODE_SIGNING
#if XNU_LOCAL_SIGNING_KEY_SIZE != PMAP_CS_LOCAL_SIGNING_KEY_SIZE
#error "XNU local signing key size and PMAP_CS local signing key size differ!"
#endif
#endif /* PMAP_CS_INCLUDE_CODE_SIGNING */

/* Common developer mode state variable */
extern bool *developer_mode_enabled;

/**
 * AppleImage4 does not provide an API to convert an object specification index to an
 * actual object specification. Since this particular function is used across different
 * places, it makes sense to keep it in a shared header file.
 *
 * This function may be called in contexts where printing is not possible, so do NOT
 * leave a print statement here under any ciscumstances.
 */
static inline const img4_runtime_object_spec_t*
image4_get_object_spec_from_index(
	img4_runtime_object_spec_index_t obj_spec_index)
{
	const img4_runtime_object_spec_t *obj_spec = NULL;

	switch (obj_spec_index) {
	case IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT:
		obj_spec = IMG4_RUNTIME_OBJECT_SPEC_SUPPLEMENTAL_ROOT;
		break;

	case IMG4_RUNTIME_OBJECT_SPEC_INDEX_LOCAL_POLICY:
		obj_spec = IMG4_RUNTIME_OBJECT_SPEC_LOCAL_POLICY;
		break;

	default:
		break;
	}

	return obj_spec;
}

/**
 * Perform any initialization required for managing code signing state on the system.
 * This is called within XNU itself and doesn't need to be exported to anything external.
 */
void
code_signing_init(void);

#endif /* XNU_KERNEL_PRIVATE */

/**
 * Query the system to understand the code signing configuration of the system. This
 * includes information on what monitor environment is available on the system as well
 * as what the state of the system looks like with the provided boot-args.
 */
void
code_signing_configuration(
	code_signing_monitor_type_t *monitor_type,
	code_signing_config_t *config);

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

/**
 * Set the CDHash which is currently being used by the compilation service. This CDHash
 * is compared against when validating the signature of a compilation service library.
 */
void
set_compilation_service_cdhash(
	const uint8_t *cdhash);

/**
 * Match a CDHash against the currently stored CDHash for the compilation service.
 */
bool
match_compilation_service_cdhash(
	const uint8_t *cdhash);

/**
 * Set the local signing key which is currently being used on the system. This key is used
 * to validate any signatures which are signed on device.
 */
void
set_local_signing_public_key(
	const uint8_t public_key[XNU_LOCAL_SIGNING_KEY_SIZE]);

/**
 * Get the local signing key which is currently being used on the system. This API is
 * mostly used by kernel extensions which validate code signatures on the platform.
 */
uint8_t*
get_local_signing_public_key(void);

/**
 * Unrestrict a particular CDHash for local signing, allowing it to be loaded and run on
 * the system. This is only required to be done for main binaries, since libraries do not
 * need to be unrestricted.
 */
void
unrestrict_local_signing_cdhash(
	const uint8_t *cdhash);

/**
 * The kernel or the monitor environments allocate some data which is used by AppleImage4
 * for storing critical system information such as nonces. AppleImage4 uses this API to
 * get access to this data while abstracting the implementation underneath.
 */
void*
kernel_image4_storage_data(
	size_t *allocated_size);

/**
 * AppleImage4 uses this API to store the specified nonce into the nonce storage. This API
 * abstracts away the kernel or monitor implementation used.
 */
void
kernel_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce);

/**
 * AppleImage4 uses this API to roll a specified nonce on the next boot. This API abstracts
 * away the kernel or monitor implementation used.
 */
void
kernel_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi);

/**
 * AppleImage4 uses this API to copy a specified nonce from the nonce storage. This API
 * abstracts away the kernel or monitor implementation used.
 *
 * We need this API since the nonces use a lock to protect against concurrency, and the
 * lock can only be taken within the monitor environment, if any.
 */
errno_t
kernel_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out);

/**
 * AppleImage4 uses this API to perform object execution on a particular object type. This
 * API abstracts away the kernel or monitor implementation used.
 */
errno_t
kernel_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest);

/**
 * AppleImage4 uses this API to copy the contents of an executed object. This API abstracts
 * away the kernel or monitor implementation used.
 */
errno_t
kernel_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length);

/**
 * AppleImage4 uses this API to get a pointer to the structure which is used for exporting
 * monitor locked down data to the rest of the system.
 */
const void*
kernel_image4_get_monitor_exports(void);

/**
 * AppleImage4 uses this API to let the monitor environment know the release type for the
 * the current boot. Under some circumstances, the monitor isn't able to gauge this on its
 * own.
 */
errno_t
kernel_image4_set_release_type(
	const char *release_type);

/**
 * AppleImage4 uses this API to let the monitor know when a nonce domain is shadowing the
 * AP boot nonce. Since this information is queried from the NVRAM, the monitor cant know
 * this on its own.
 */
errno_t
kernel_image4_set_bnch_shadow(
	const img4_nonce_domain_index_t ndi);

/**
 * AMFI uses this API to obtain the OSEntitlements object which is associated with the
 * main binary mapped in for a process.
 *
 * This API is considered safer for resolving the OSEntitlements than through the cred
 * structure on the process because the system maintains a strong binding in the linkage
 * chain from the process structure through the pmap, which ultimately contains the
 * code signing monitors address space information for the process.
 */
kern_return_t
csm_resolve_os_entitlements_from_proc(
	const proc_t process,
	const void **os_entitlements);

#if CODE_SIGNING_MONITOR

/**
 * Check to see if the monitor is currently enforcing code signing protections or
 * not. Even when this is disabled, certains artifacts are still protected by the
 * monitor environment.
 */
bool
csm_enabled(void);

/**
 * This function is used to initialize the state of the locks for managing provisioning
 * profiles on the system. It should be called by the kernel bootstrap thread during the
 * early kernel initialization.
 */
void
csm_initialize_provisioning_profiles(void);

/**
 * Register a provisioning profile with the monitor environment available on the
 * system. This function will allocate its own memory for managing the profile and
 * the caller is allowed to free their own allocation.
 */
kern_return_t
csm_register_provisioning_profile(
	const uuid_t profile_uuid,
	const void *profile,
	const size_t profile_size);

/**
 * Associate a registered profile with a code signature object which is managed by
 * the monitor environment. This incrementes the reference count on the profile object
 * managed by the monitor, preventing the profile from being unregistered.
 */
kern_return_t
csm_associate_provisioning_profile(
	void *monitor_sig_obj,
	const uuid_t profile_uuid);

/**
 * Disassociate an associated profile with a code signature object which is managed by
 * the monitor environment. This decrements the refernce count on the profile object
 * managed by the monitor, potentially allowing it to be unregistered in case no other
 * signatures hold a reference count to it.
 */
kern_return_t
csm_disassociate_provisioning_profile(
	void *monitor_sig_obj);

/**
 * Trigger the provisioning profile garbage collector to go through each registered
 * profile on the system and unregister it in case it isn't being used.
 */
void
csm_free_provisioning_profiles(void);

/**
 * Acquire the largest size for a code signature which the monitor will allocate on
 * its own. Anything larger than this size needs to be page-allocated and aligned and
 * will be locked down by the monitor upon registration.
 */
vm_size_t
csm_signature_size_limit(void);

/**
 * Register a code signature with the monitor environment. The monitor will either
 * allocate its own memory for the code signature, or it will lockdown the memory which
 * is given to it. In either case, the signature will be read-only for the kernel.
 *
 * If the monitor doesn't enforce code signing, then this function will return the
 * KERN_SUCCESS condition.
 */
kern_return_t
csm_register_code_signature(
	const vm_address_t signature_addr,
	const vm_size_t signature_size,
	const vm_offset_t code_directory_offset,
	const char *signature_path,
	void **monitor_sig_obj,
	vm_address_t *monitor_signature_addr);

/**
 * Unregister a code signature previously registered with the monitor environment.
 * This will free (or unlock) the signature memory held by the monitor.
 *
 * If the monitor doesn't enforce code signing, then this function will return the
 * error KERN_NOT_SUPPORTED.
 */
kern_return_t
csm_unregister_code_signature(
	void *monitor_sig_obj);

/**
 * Verify a code signature previously registered with the monitor. After verification,
 * the signature can be used for making code signature associations with address spaces.
 *
 * If the monitor doesn't enforce code signing, then this function will return the
 * KERN_SUCCESS condition.
 */
kern_return_t
csm_verify_code_signature(
	void *monitor_sig_obj);

/**
 * Perform 2nd stage reconstitution through the monitor. This unlocks any unused parts
 * of the code signature, which can then be freed by the kernel. This isn't strictly
 * required, but it helps in conserving system memory.
 *
 * If the monitor doesn't enforce code signing, then this function will return the
 * error KERN_NOT_SUPPORTED.
 */
kern_return_t
csm_reconstitute_code_signature(
	void *monitor_sig_obj,
	vm_address_t *unneeded_addr,
	vm_size_t *unneeded_size);

/**
 * Associate a code signature with an address space for a specified region with the
 * monitor environment. The code signature can only be associated if it has been
 * verified before.
 */
kern_return_t
csm_associate_code_signature(
	pmap_t pmap,
	void *monitor_sig_obj,
	const vm_address_t region_addr,
	const vm_size_t region_size,
	const vm_offset_t region_offset);

/**
 * Associate a JIT region with an address space in the monitor environment. An address
 * space can only have a JIT region if it has the appropriate JIT entitlement.
 */
kern_return_t
csm_associate_jit_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size);

/**
 * Associate a debug region with an address space in the monitor environment. An address
 * space can only have a debug region if it is currently being debugged.
 */
kern_return_t
csm_associate_debug_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size);

/**
 * Call out to the monitor to inform it that the address space needs to be debugged. The
 * monitor will only allow the address space to be debugged if it has the appropriate
 * entitlements.
 */
kern_return_t
csm_allow_invalid_code(
	pmap_t pmap);

/**
 * Certain address spaces are exempt from code signing enforcement. This function can be
 * used to check if the specified address space is such or not.
 */
kern_return_t
csm_address_space_exempt(
	const pmap_t pmap);

/**
 * Instruct the monitor that an address space is about to be forked. The monitor can then
 * do whatever it needs to do in order to prepare for the fork.
 */
kern_return_t
csm_fork_prepare(
	pmap_t old_pmap,
	pmap_t new_pmap);

/**
 * Get the signing identifier which is embedded within the code directory using the
 * code signing monitor's abstract signature object.
 */
kern_return_t
csm_acquire_signing_identifier(
	const void *monitor_sig_obj,
	const char **signing_id);

/**
 * This API to associate an OSEntitlements objects with the code signing monitor's
 * signature object. This binding is useful as it can be used to resolve the entitlement
 * object which is used by the kernel for performing queries.
 */
kern_return_t
csm_associate_os_entitlements(
	void *monitor_sig_obj,
	const void *os_entitlements);

/**
 * Accelerate the CoreEntitlements context within the code signing monitor's memory
 * in order to speed up all queries for entitlements going through CoreEntitlements.
 */
kern_return_t
csm_accelerate_entitlements(
	void *monitor_sig_obj,
	CEQueryContext_t *ce_ctx);

kern_return_t
vm_map_entry_cs_associate(
	vm_map_t map,
	struct vm_map_entry *entry,
	vm_map_kernel_flags_t vmk_flags);

kern_return_t
cs_associate_blob_with_mapping(
	void *pmap,
	vm_map_offset_t start,
	vm_map_size_t size,
	vm_object_offset_t offset,
	void *blobs_p);

#endif /* CODE_SIGNING_MONITOR */

#endif /* KERNEL_PRIVATE */

__END_DECLS
#endif /* _SYS_CODE_SIGNING_H_ */
