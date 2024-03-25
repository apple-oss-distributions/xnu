/*
 * Copyright (c) 2021 Apple Computer, Inc. All rights reserved.
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

#include <os/overflow.h>
#include <machine/atomic.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <vm/pmap_cs.h>
#include <vm/vm_map.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/lock_rw.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/coretrust/coretrust.h>
#include <pexpert/pexpert.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/proc_require.h>
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <sys/lockdown_mode.h>
#include <sys/reason.h>
#include <sys/kdebug_kernel.h>
#include <sys/kdebug_triage.h>
#include <sys/sysctl.h>
#include <uuid/uuid.h>
#include <IOKit/IOBSD.h>

#if CONFIG_SPTM
#include <sys/trusted_execution_monitor.h>
#endif

#if XNU_KERNEL_PRIVATE
vm_address_t
code_signing_allocate(
	size_t alloc_size)
{
	vm_address_t alloc_addr = 0;

	if (alloc_size == 0) {
		panic("%s: zero allocation size", __FUNCTION__);
	}
	size_t aligned_size = round_page(alloc_size);

	kern_return_t ret = kmem_alloc(
		kernel_map,
		&alloc_addr, aligned_size,
		KMA_KOBJECT | KMA_DATA | KMA_ZERO,
		VM_KERN_MEMORY_SECURITY);

	if (ret != KERN_SUCCESS) {
		printf("%s: unable to allocate %lu bytes\n", __FUNCTION__, aligned_size);
	} else if (alloc_addr == 0) {
		printf("%s: invalid allocation\n", __FUNCTION__);
	}

	return alloc_addr;
}

void
code_signing_deallocate(
	vm_address_t *alloc_addr,
	size_t alloc_size)
{
	if (alloc_addr == NULL) {
		panic("%s: invalid pointer provided", __FUNCTION__);
	} else if ((*alloc_addr == 0) || ((*alloc_addr & PAGE_MASK) != 0)) {
		panic("%s: address provided: %p", __FUNCTION__, (void*)(*alloc_addr));
	} else if (alloc_size == 0) {
		panic("%s: zero allocation size", __FUNCTION__);
	}
	size_t aligned_size = round_page(alloc_size);

	/* Free the allocation */
	kmem_free(kernel_map, *alloc_addr, aligned_size);

	/* Clear the address */
	*alloc_addr = 0;
}
#endif /* XNU_KERNEL_PRIVATE */

SYSCTL_DECL(_security);
SYSCTL_DECL(_security_codesigning);
SYSCTL_NODE(_security, OID_AUTO, codesigning, CTLFLAG_RD, 0, "XNU Code Signing");

static SECURITY_READ_ONLY_LATE(bool) cs_config_set = false;
static SECURITY_READ_ONLY_LATE(code_signing_monitor_type_t) cs_monitor = CS_MONITOR_TYPE_NONE;
static SECURITY_READ_ONLY_LATE(code_signing_config_t) cs_config = 0;

SYSCTL_UINT(_security_codesigning, OID_AUTO, monitor, CTLFLAG_RD, &cs_monitor, 0, "code signing monitor type");
SYSCTL_UINT(_security_codesigning, OID_AUTO, config, CTLFLAG_RD, &cs_config, 0, "code signing configuration");

void
code_signing_configuration(
	code_signing_monitor_type_t *monitor_type_out,
	code_signing_config_t *config_out)
{
	code_signing_monitor_type_t monitor_type = CS_MONITOR_TYPE_NONE;
	code_signing_config_t config = 0;

	/*
	 * Since we read this variable with load-acquire semantics, if we observe a value
	 * of true, it means we should be able to observe writes to cs_monitor and also
	 * cs_config.
	 */
	if (os_atomic_load(&cs_config_set, acquire) == true) {
		goto config_set;
	}

	/*
	 * Add support for all the code signing features. This function is called very
	 * early in the system boot, much before kernel extensions such as Apple Mobile
	 * File Integrity come online. As a result, this function assumes that all the
	 * code signing features are enabled, and later on, different components can
	 * disable support for different features using disable_code_signing_feature().
	 */
	config |= CS_CONFIG_MAP_JIT;
	config |= CS_CONFIG_DEVELOPER_MODE_SUPPORTED;
	config |= CS_CONFIG_COMPILATION_SERVICE;
	config |= CS_CONFIG_LOCAL_SIGNING;
	config |= CS_CONFIG_OOP_JIT;

#if CODE_SIGNING_MONITOR
	/* Mark the code signing monitor as enabled if required */
	if (csm_enabled() == true) {
		config |= CS_CONFIG_CSM_ENABLED;
	}

#if CONFIG_SPTM
	/*
	 * Since TrustedExecutionMonitor cannot call into any function within XNU, we
	 * query it's code signing configuration even before this function is called.
	 * Using that, we modify the state of the code signing features available.
	 */
	if (csm_enabled() == true) {
#if kTXMKernelAPIVersion >= 3
		bool platform_code_only = txm_cs_config->systemPolicy->platformCodeOnly;
#else
		bool platform_code_only = txm_ro_data->platformCodeOnly;
#endif

		/* Disable unsupported features when enforcing platform-code-only */
		if (platform_code_only == true) {
			config &= ~CS_CONFIG_MAP_JIT;
			config &= ~CS_CONFIG_COMPILATION_SERVICE;
			config &= ~CS_CONFIG_LOCAL_SIGNING;
			config &= ~CS_CONFIG_OOP_JIT;
		}

#if kTXMKernelAPIVersion >= 3
		/* MAP_JIT support */
		if (txm_cs_config->systemPolicy->featureSet.JIT == false) {
			config &= ~CS_CONFIG_MAP_JIT;
		}
#endif

		/* Developer mode support */
		if (txm_cs_config->systemPolicy->featureSet.developerMode == false) {
			config &= ~CS_CONFIG_DEVELOPER_MODE_SUPPORTED;
		}

		/* Compilation service support */
		if (txm_cs_config->systemPolicy->featureSet.compilationService == false) {
			config &= ~CS_CONFIG_COMPILATION_SERVICE;
		}

		/* Local signing support */
		if (txm_cs_config->systemPolicy->featureSet.localSigning == false) {
			config &= ~CS_CONFIG_LOCAL_SIGNING;
		}

		/* OOP-JIT support */
		if (txm_cs_config->systemPolicy->featureSet.OOPJit == false) {
			config &= ~CS_CONFIG_OOP_JIT;
		}
	}
	monitor_type = CS_MONITOR_TYPE_TXM;
#elif PMAP_CS_PPL_MONITOR
	monitor_type = CS_MONITOR_TYPE_PPL;
#endif /* CONFIG_SPTM */
#endif /* CODE_SIGNING_MONITOR */

#if DEVELOPMENT || DEBUG
	/*
	 * We only ever need to parse for boot-args based exemption state on DEVELOPMENT
	 * or DEBUG builds as this state is not respected by any code signing component
	 * on RELEASE builds.
	 */

#define CS_AMFI_MASK_UNRESTRICT_TASK_FOR_PID 0x01
#define CS_AMFI_MASK_ALLOW_ANY_SIGNATURE 0x02
#define CS_AMFI_MASK_GET_OUT_OF_MY_WAY 0x80

	int amfi_mask = 0;
	int amfi_allow_any_signature = 0;
	int amfi_unrestrict_task_for_pid = 0;
	int amfi_get_out_of_my_way = 0;
	int cs_enforcement_disabled = 0;
	int cs_integrity_skip = 0;

	/* Parse the AMFI mask */
	PE_parse_boot_argn("amfi", &amfi_mask, sizeof(amfi_mask));

	/* Parse the AMFI soft-bypass */
	PE_parse_boot_argn(
		"amfi_allow_any_signature",
		&amfi_allow_any_signature,
		sizeof(amfi_allow_any_signature));

	/* Parse the AMFI debug-bypass */
	PE_parse_boot_argn(
		"amfi_unrestrict_task_for_pid",
		&amfi_unrestrict_task_for_pid,
		sizeof(amfi_unrestrict_task_for_pid));

	/* Parse the AMFI hard-bypass */
	PE_parse_boot_argn(
		"amfi_get_out_of_my_way",
		&amfi_get_out_of_my_way,
		sizeof(amfi_get_out_of_my_way));

	/* Parse the system code signing hard-bypass */
	PE_parse_boot_argn(
		"cs_enforcement_disable",
		&cs_enforcement_disabled,
		sizeof(cs_enforcement_disabled));

	/* Parse the system code signing integrity-check bypass */
	PE_parse_boot_argn(
		"cs_integrity_skip",
		&cs_integrity_skip,
		sizeof(cs_integrity_skip));

	/* CS_CONFIG_UNRESTRICTED_DEBUGGING */
	if (amfi_mask & CS_AMFI_MASK_UNRESTRICT_TASK_FOR_PID) {
		config |= CS_CONFIG_UNRESTRICTED_DEBUGGING;
	} else if (amfi_unrestrict_task_for_pid) {
		config |= CS_CONFIG_UNRESTRICTED_DEBUGGING;
	}

	/* CS_CONFIG_ALLOW_ANY_SIGNATURE */
	if (amfi_mask & CS_AMFI_MASK_ALLOW_ANY_SIGNATURE) {
		config |= CS_CONFIG_ALLOW_ANY_SIGNATURE;
	} else if (amfi_mask & CS_AMFI_MASK_GET_OUT_OF_MY_WAY) {
		config |= CS_CONFIG_ALLOW_ANY_SIGNATURE;
	} else if (amfi_allow_any_signature) {
		config |= CS_CONFIG_ALLOW_ANY_SIGNATURE;
	} else if (amfi_get_out_of_my_way) {
		config |= CS_CONFIG_ALLOW_ANY_SIGNATURE;
	} else if (cs_enforcement_disabled) {
		config |= CS_CONFIG_ALLOW_ANY_SIGNATURE;
	}

	/* CS_CONFIG_ENFORCEMENT_DISABLED */
	if (cs_enforcement_disabled) {
		config |= CS_CONFIG_ENFORCEMENT_DISABLED;
	}

	/* CS_CONFIG_GET_OUT_OF_MY_WAY */
	if (amfi_mask & CS_AMFI_MASK_GET_OUT_OF_MY_WAY) {
		config |= CS_CONFIG_GET_OUT_OF_MY_WAY;
	} else if (amfi_get_out_of_my_way) {
		config |= CS_CONFIG_GET_OUT_OF_MY_WAY;
	} else if (cs_enforcement_disabled) {
		config |= CS_CONFIG_GET_OUT_OF_MY_WAY;
	}

	/* CS_CONFIG_INTEGRITY_SKIP */
	if (cs_integrity_skip) {
		config |= CS_CONFIG_INTEGRITY_SKIP;
	}

#if CONFIG_SPTM

	if (csm_enabled() == true) {
		/* allow_any_signature */
		if (txm_cs_config->exemptions.allowAnySignature == false) {
			config &= ~CS_CONFIG_ALLOW_ANY_SIGNATURE;
		}

		/* unrestrict_task_for_pid */
		if (txm_ro_data && !txm_ro_data->exemptions.allowUnrestrictedDebugging) {
			config &= ~CS_CONFIG_UNRESTRICTED_DEBUGGING;
		}

		/* cs_enforcement_disable */
		if (txm_ro_data && !txm_ro_data->exemptions.allowModifiedCode) {
			config &= ~CS_CONFIG_ENFORCEMENT_DISABLED;
		}

		/* get_out_of_my_way (skip_trust_evaluation) */
		if (txm_cs_config->exemptions.skipTrustEvaluation == false) {
			config &= ~CS_CONFIG_GET_OUT_OF_MY_WAY;
		}
	}

#elif PMAP_CS_PPL_MONITOR

	if (csm_enabled() == true) {
		int pmap_cs_allow_any_signature = 0;
		bool override = PE_parse_boot_argn(
			"pmap_cs_allow_any_signature",
			&pmap_cs_allow_any_signature,
			sizeof(pmap_cs_allow_any_signature));

		if (!pmap_cs_allow_any_signature && override) {
			config &= ~CS_CONFIG_ALLOW_ANY_SIGNATURE;
		}

		int pmap_cs_unrestrict_task_for_pid = 0;
		override = PE_parse_boot_argn(
			"pmap_cs_unrestrict_pmap_cs_disable",
			&pmap_cs_unrestrict_task_for_pid,
			sizeof(pmap_cs_unrestrict_task_for_pid));

		if (!pmap_cs_unrestrict_task_for_pid && override) {
			config &= ~CS_CONFIG_UNRESTRICTED_DEBUGGING;
		}

		int pmap_cs_enforcement_disable = 0;
		override = PE_parse_boot_argn(
			"pmap_cs_allow_modified_code_pages",
			&pmap_cs_enforcement_disable,
			sizeof(pmap_cs_enforcement_disable));

		if (!pmap_cs_enforcement_disable && override) {
			config &= ~CS_CONFIG_ENFORCEMENT_DISABLED;
		}
	}

#endif /* CONFIG_SPTM */
#endif /* DEVELOPMENT || DEBUG */

	os_atomic_store(&cs_monitor, monitor_type, relaxed);
	os_atomic_store(&cs_config, config, relaxed);

	/*
	 * We write the cs_config_set variable with store-release semantics which means
	 * no writes before this call will be re-ordered to after this call. Hence, if
	 * someone reads this variable with load-acquire semantics, and they observe a
	 * value of true, then they will be able to observe the correct values of the
	 * cs_monitor and the cs_config variables as well.
	 */
	os_atomic_store(&cs_config_set, true, release);

config_set:
	/* Ensure configuration has been set */
	assert(os_atomic_load(&cs_config_set, relaxed) == true);

	/* Set the monitor type */
	if (monitor_type_out) {
		*monitor_type_out = os_atomic_load(&cs_monitor, relaxed);
	}

	/* Set the configuration */
	if (config_out) {
		*config_out = os_atomic_load(&cs_config, relaxed);
	}
}

void
disable_code_signing_feature(
	code_signing_config_t feature)
{
	/*
	 * We require that this function be called only after the code signing config
	 * has been setup initially with a call to code_signing_configuration.
	 */
	if (os_atomic_load(&cs_config_set, acquire) == false) {
		panic("attempted to disable code signing feature without init: %u", feature);
	}

	/*
	 * We require that only a single feature be disabled through a single call to this
	 * function. Moreover, we ensure that only valid features are being disabled.
	 */
	switch (feature) {
	case CS_CONFIG_DEVELOPER_MODE_SUPPORTED:
		cs_config &= ~CS_CONFIG_DEVELOPER_MODE_SUPPORTED;
		break;

	case CS_CONFIG_COMPILATION_SERVICE:
		cs_config &= ~CS_CONFIG_COMPILATION_SERVICE;
		break;

	case CS_CONFIG_LOCAL_SIGNING:
		cs_config &= ~CS_CONFIG_LOCAL_SIGNING;
		break;

	case CS_CONFIG_OOP_JIT:
		cs_config &= ~CS_CONFIG_OOP_JIT;
		break;

	case CS_CONFIG_MAP_JIT:
		cs_config &= ~CS_CONFIG_MAP_JIT;
		break;

	default:
		panic("attempted to disable a code signing feature invalidly: %u", feature);
	}

	/* Ensure all readers can observe the latest data */
#if defined(__arm64__)
	__asm__ volatile ("dmb ish" ::: "memory");
#elif defined(__x86_64__)
	__asm__ volatile ("mfence" ::: "memory");
#else
#error "Unknown platform -- fence instruction unavailable"
#endif
}

#pragma mark Developer Mode

void
enable_developer_mode(void)
{
	CSM_PREFIX(toggle_developer_mode)(true);
}

void
disable_developer_mode(void)
{
	CSM_PREFIX(toggle_developer_mode)(false);
}

bool
developer_mode_state(void)
{
	/* Assume false if the pointer isn't setup */
	if (developer_mode_enabled == NULL) {
		return false;
	}

	return os_atomic_load(developer_mode_enabled, relaxed);
}

#pragma mark Provisioning Profiles
/*
 * AMFI performs full profile validation by itself. XNU only needs to manage provisioning
 * profiles when we have a monitor since the monitor needs to independently verify the
 * profile data as well.
 */

void
garbage_collect_provisioning_profiles(void)
{
#if CODE_SIGNING_MONITOR
	csm_free_provisioning_profiles();
#endif
}

#if CODE_SIGNING_MONITOR

/* Structure used to maintain the set of registered profiles on the system */
typedef struct _cs_profile {
	/* The UUID of the registered profile */
	uuid_t profile_uuid;

	/* The profile validation object from the monitor */
	void *profile_obj;

	/*
	 * In order to minimize the number of times the same profile would need to be
	 * registered, we allow frequently used profiles to skip the garbage collector
	 * for one pass.
	 */
	bool skip_collector;

	/* Linked list linkage */
	SLIST_ENTRY(_cs_profile) link;
} cs_profile_t;

/* Linked list head for registered profiles */
static SLIST_HEAD(, _cs_profile) all_profiles = SLIST_HEAD_INITIALIZER(all_profiles);

/* Lock for the provisioning profiles */
LCK_GRP_DECLARE(profiles_lck_grp, "profiles_lck_grp");
decl_lck_rw_data(, profiles_lock);

void
csm_initialize_provisioning_profiles(void)
{
	/* Ensure the CoreTrust kernel extension has loaded */
	if (coretrust == NULL) {
		panic("coretrust interface not available");
	}

	/* Initialize the provisoning profiles lock */
	lck_rw_init(&profiles_lock, &profiles_lck_grp, 0);
	printf("initialized XNU provisioning profile data\n");

#if PMAP_CS_PPL_MONITOR
	pmap_initialize_provisioning_profiles();
#endif
}

static cs_profile_t*
search_for_profile_uuid(
	const uuid_t profile_uuid)
{
	cs_profile_t *profile = NULL;

	/* Caller is required to acquire the lock */
	lck_rw_assert(&profiles_lock, LCK_RW_ASSERT_HELD);

	SLIST_FOREACH(profile, &all_profiles, link) {
		if (uuid_compare(profile_uuid, profile->profile_uuid) == 0) {
			return profile;
		}
	}

	return NULL;
}

kern_return_t
csm_register_provisioning_profile(
	const uuid_t profile_uuid,
	const void *profile_blob,
	const size_t profile_blob_size)
{
	cs_profile_t *profile = NULL;
	void *monitor_profile_obj = NULL;
	kern_return_t ret = KERN_DENIED;

	/* Allocate storage for the profile wrapper object */
	profile = kalloc_type(cs_profile_t, Z_WAITOK_ZERO);
	assert(profile != NULL);

	/* Lock the profile set exclusively */
	lck_rw_lock_exclusive(&profiles_lock);

	/* Check to make sure this isn't a duplicate UUID */
	cs_profile_t *dup_profile = search_for_profile_uuid(profile_uuid);
	if (dup_profile != NULL) {
		/* This profile might be used soon -- skip garbage collector */
		dup_profile->skip_collector = true;

		ret = KERN_ALREADY_IN_SET;
		goto exit;
	}

	ret = CSM_PREFIX(register_provisioning_profile)(
		profile_blob,
		profile_blob_size,
		&monitor_profile_obj);

	if (ret == KERN_SUCCESS) {
		/* Copy in the profile UUID */
		uuid_copy(profile->profile_uuid, profile_uuid);

		/* Setup the monitor's profile object */
		profile->profile_obj = monitor_profile_obj;

		/* This profile might be used soon -- skip garbage collector */
		profile->skip_collector = true;

		/* Insert at the head of the profile set */
		SLIST_INSERT_HEAD(&all_profiles, profile, link);
	}

exit:
	/* Unlock the profile set */
	lck_rw_unlock_exclusive(&profiles_lock);

	if (ret != KERN_SUCCESS) {
		/* Free the profile wrapper object */
		kfree_type(cs_profile_t, profile);
		profile = NULL;

		if (ret != KERN_ALREADY_IN_SET) {
			printf("unable to register profile with monitor: %d\n", ret);
		}
	}

	return ret;
}

kern_return_t
csm_associate_provisioning_profile(
	void *monitor_sig_obj,
	const uuid_t profile_uuid)
{
	cs_profile_t *profile = NULL;
	kern_return_t ret = KERN_DENIED;

	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	/* Lock the profile set as shared */
	lck_rw_lock_shared(&profiles_lock);

	/* Search for the provisioning profile */
	profile = search_for_profile_uuid(profile_uuid);
	if (profile == NULL) {
		ret = KERN_NOT_FOUND;
		goto exit;
	}

	ret = CSM_PREFIX(associate_provisioning_profile)(
		monitor_sig_obj,
		profile->profile_obj);

	if (ret == KERN_SUCCESS) {
		/*
		 * This seems like an active profile -- let it skip the garbage collector on
		 * the next pass. We can modify this field even though we've only taken a shared
		 * lock as in this case we're always setting it to a fixed value.
		 */
		profile->skip_collector = true;
	}

exit:
	/* Unlock the profile set */
	lck_rw_unlock_shared(&profiles_lock);

	if (ret != KERN_SUCCESS) {
		printf("unable to associate profile: %d\n", ret);
	}
	return ret;
}

kern_return_t
csm_disassociate_provisioning_profile(
	void *monitor_sig_obj)
{
	kern_return_t ret = KERN_DENIED;

	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	/* Call out to the monitor */
	ret = CSM_PREFIX(disassociate_provisioning_profile)(monitor_sig_obj);

	if ((ret != KERN_SUCCESS) && (ret != KERN_NOT_FOUND)) {
		printf("unable to disassociate profile: %d\n", ret);
	}
	return ret;
}

static kern_return_t
unregister_provisioning_profile(
	cs_profile_t *profile)
{
	kern_return_t ret = KERN_DENIED;

	/* Call out to the monitor */
	ret = CSM_PREFIX(unregister_provisioning_profile)(profile->profile_obj);

	/*
	 * KERN_FAILURE represents the case when the unregistration failed because the
	 * monitor noted that the profile was still being used. Other than that, there
	 * is no other error expected out of this interface. In fact, there is no easy
	 * way to deal with other errors, as the profile state may be corrupted. If we
	 * see a different error, then we panic.
	 */
	if ((ret != KERN_SUCCESS) && (ret != KERN_FAILURE)) {
		panic("unable to unregister profile from monitor: %d | %p\n", ret, profile);
	}

	return ret;
}

void
csm_free_provisioning_profiles(void)
{
	kern_return_t ret = KERN_DENIED;
	cs_profile_t *profile = NULL;
	cs_profile_t *temp_profile = NULL;

	/* Lock the profile set exclusively */
	lck_rw_lock_exclusive(&profiles_lock);

	SLIST_FOREACH_SAFE(profile, &all_profiles, link, temp_profile) {
		if (profile->skip_collector == true) {
			profile->skip_collector = false;
			continue;
		}

		/* Attempt to unregister this profile from the system */
		ret = unregister_provisioning_profile(profile);
		if (ret == KERN_SUCCESS) {
			/* Remove the profile from the profile set */
			SLIST_REMOVE(&all_profiles, profile, _cs_profile, link);

			/* Free the memory consumed for the profile wrapper object */
			kfree_type(cs_profile_t, profile);
			profile = NULL;
		}
	}

	/* Unlock the profile set */
	lck_rw_unlock_exclusive(&profiles_lock);
}

#endif /* CODE_SIGNING_MONITOR */

#pragma mark Code Signing
/*
 * AMFI performs full signature validation by itself. For some things, AMFI uses XNU in
 * order to abstract away the underlying implementation for data storage, but for most of
 * these, AMFI doesn't directly interact with them, and they're only required when we have
 * a code signing monitor on the system.
 */

void
set_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	CSM_PREFIX(set_compilation_service_cdhash)(cdhash);
}

bool
match_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	return CSM_PREFIX(match_compilation_service_cdhash)(cdhash);
}

void
set_local_signing_public_key(
	const uint8_t public_key[XNU_LOCAL_SIGNING_KEY_SIZE])
{
	CSM_PREFIX(set_local_signing_public_key)(public_key);
}

uint8_t*
get_local_signing_public_key(void)
{
	return CSM_PREFIX(get_local_signing_public_key)();
}

void
unrestrict_local_signing_cdhash(
	__unused const uint8_t cdhash[CS_CDHASH_LEN])
{
	/*
	 * Since AMFI manages code signing on its own, we only need to unrestrict the
	 * local signing cdhash when we have a monitor environment.
	 */

#if CODE_SIGNING_MONITOR
	CSM_PREFIX(unrestrict_local_signing_cdhash)(cdhash);
#endif
}

kern_return_t
get_trust_level_kdp(
	__unused pmap_t pmap,
	__unused uint32_t *trust_level)
{
#if CODE_SIGNING_MONITOR
	return csm_get_trust_level_kdp(pmap, trust_level);
#else
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
csm_resolve_os_entitlements_from_proc(
	__unused const proc_t process,
	__unused const void **os_entitlements)
{
#if CODE_SIGNING_MONITOR
	task_t task = NULL;
	vm_map_t task_map = NULL;
	pmap_t task_pmap = NULL;
	kern_return_t ret = KERN_DENIED;

	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	/* Ensure the process comes from the proc_task zone */
	proc_require(process, PROC_REQUIRE_ALLOW_ALL);

	/* Acquire the task from the proc */
	task = proc_task(process);
	if (task == NULL) {
		return KERN_NOT_FOUND;
	}

	/* Acquire the virtual memory map from the task -- takes a reference on it */
	task_map = get_task_map_reference(task);
	if (task_map == NULL) {
		return KERN_NOT_FOUND;
	}

	/* Acquire the pmap from the virtual memory map */
	task_pmap = vm_map_get_pmap(task_map);
	assert(task_pmap != NULL);

	/* Call into the monitor to resolve the entitlements */
	ret = CSM_PREFIX(resolve_kernel_entitlements)(task_pmap, os_entitlements);

	/* Release the reference on the virtual memory map */
	vm_map_deallocate(task_map);

	return ret;
#else
	return KERN_NOT_SUPPORTED;
#endif
}

kern_return_t
address_space_debugged(
	const proc_t process)
{
	/* Must pass in a valid proc_t */
	if (process == NULL) {
		printf("%s: provided a NULL process\n", __FUNCTION__);
		return KERN_DENIED;
	}
	proc_require(process, PROC_REQUIRE_ALLOW_ALL);

	/* Developer mode must always be enabled for this to return successfully */
	if (developer_mode_state() == false) {
		return KERN_DENIED;
	}

#if CODE_SIGNING_MONITOR
	task_t task = NULL;
	vm_map_t task_map = NULL;
	pmap_t task_pmap = NULL;

	if (csm_enabled() == true) {
		/* Acquire the task from the proc */
		task = proc_task(process);
		if (task == NULL) {
			return KERN_NOT_FOUND;
		}

		/* Acquire the virtual memory map from the task -- takes a reference on it */
		task_map = get_task_map_reference(task);
		if (task_map == NULL) {
			return KERN_NOT_FOUND;
		}

		/* Acquire the pmap from the virtual memory map */
		task_pmap = vm_map_get_pmap(task_map);
		assert(task_pmap != NULL);

		/* Acquire the state from the monitor */
		kern_return_t ret = CSM_PREFIX(address_space_debugged)(task_pmap);

		/* Release the reference on the virtual memory map */
		vm_map_deallocate(task_map);

		return ret;
	}
#endif /* CODE_SIGNING_MONITOR */

	/* Check read-only process flags for state */
	if (proc_getcsflags(process) & CS_DEBUGGED) {
		return KERN_SUCCESS;
	}

	return KERN_DENIED;
}

#if CODE_SIGNING_MONITOR

bool
csm_enabled(void)
{
	return CSM_PREFIX(code_signing_enabled)();
}

vm_size_t
csm_signature_size_limit(void)
{
	return CSM_PREFIX(managed_code_signature_size)();
}

void
csm_check_lockdown_mode(void)
{
	if (get_lockdown_mode_state() == 0) {
		return;
	}

	/* Inform the code signing monitor about lockdown mode */
	CSM_PREFIX(enter_lockdown_mode)();

#if CONFIG_SPTM
#if kTXMKernelAPIVersion >= 3
	/* MAP_JIT lockdown */
	if (txm_cs_config->systemPolicy->featureSet.JIT == false) {
		disable_code_signing_feature(CS_CONFIG_MAP_JIT);
	}
#endif

	/* Compilation service lockdown */
	if (txm_cs_config->systemPolicy->featureSet.compilationService == false) {
		disable_code_signing_feature(CS_CONFIG_COMPILATION_SERVICE);
	}

	/* Local signing lockdown */
	if (txm_cs_config->systemPolicy->featureSet.localSigning == false) {
		disable_code_signing_feature(CS_CONFIG_LOCAL_SIGNING);
	}

	/* OOP-JIT lockdown */
	if (txm_cs_config->systemPolicy->featureSet.OOPJit == false) {
		disable_code_signing_feature(CS_CONFIG_OOP_JIT);
	}
#else
	/*
	 * Lockdown mode is supposed to disable all forms of JIT on the system. For now,
	 * we leave JIT enabled by default until some blockers are resolved. The way this
	 * code is written, we don't need to change anything once we enforce MAP_JIT to
	 * be disabled for lockdown mode.
	 */
	if (ppl_lockdown_mode_enforce_jit == true) {
		disable_code_signing_feature(CS_CONFIG_MAP_JIT);
	}
	disable_code_signing_feature(CS_CONFIG_OOP_JIT);
	disable_code_signing_feature(CS_CONFIG_LOCAL_SIGNING);
	disable_code_signing_feature(CS_CONFIG_COMPILATION_SERVICE);
#endif /* CONFIG_SPTM */
}

void
csm_code_signing_violation(
	proc_t proc,
	vm_offset_t addr)
{
	os_reason_t kill_reason = OS_REASON_NULL;

	/* No enforcement if code-signing-monitor is disabled */
	if (csm_enabled() == false) {
		return;
	} else if (proc == PROC_NULL) {
		panic("code-signing violation without a valid proc");
	}

	/*
	 * If the address space is being debugged, then we expect this task to undergo
	 * some code signing violations. In this case, we return without killing the
	 * task.
	 */
	if (address_space_debugged(proc) == KERN_SUCCESS) {
		return;
	}

	/* Leave a ktriage record */
	ktriage_record(
		thread_tid(current_thread()),
		KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_VM, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_VM_CODE_SIGNING),
		0);

	/* Leave a log for triage purposes */
	printf("[%s: killed] code-signing-violation at %p\n", proc_best_name(proc), (void*)addr);

	/*
	 * Create a reason for the SIGKILL and set it to allow generating crash reports,
	 * which is critical for better triaging these issues.
	 */
	kill_reason = os_reason_create(OS_REASON_CODESIGNING, CODESIGNING_EXIT_REASON_INVALID_PAGE);
	if (kill_reason != NULL) {
		kill_reason->osr_flags |= OS_REASON_FLAG_GENERATE_CRASH_REPORT;
	}

	/*
	 * Send a SIGKILL to the process. This function will consume the kill_reason, so
	 * we do not need to manually free it here.
	 */
	psignal_with_reason(proc, SIGKILL, kill_reason);
}

kern_return_t
csm_register_code_signature(
	const vm_address_t signature_addr,
	const vm_size_t signature_size,
	const vm_offset_t code_directory_offset,
	const char *signature_path,
	void **monitor_sig_obj,
	vm_address_t *monitor_signature_addr)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(register_code_signature)(
		signature_addr,
		signature_size,
		code_directory_offset,
		signature_path,
		monitor_sig_obj,
		monitor_signature_addr);
}

kern_return_t
csm_unregister_code_signature(
	void *monitor_sig_obj)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(unregister_code_signature)(monitor_sig_obj);
}

kern_return_t
csm_verify_code_signature(
	void *monitor_sig_obj)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(verify_code_signature)(monitor_sig_obj);
}

kern_return_t
csm_reconstitute_code_signature(
	void *monitor_sig_obj,
	vm_address_t *unneeded_addr,
	vm_size_t *unneeded_size)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(reconstitute_code_signature)(
		monitor_sig_obj,
		unneeded_addr,
		unneeded_size);
}

kern_return_t
csm_associate_code_signature(
	pmap_t monitor_pmap,
	void *monitor_sig_obj,
	const vm_address_t region_addr,
	const vm_size_t region_size,
	const vm_offset_t region_offset)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(associate_code_signature)(
		monitor_pmap,
		monitor_sig_obj,
		region_addr,
		region_size,
		region_offset);
}

kern_return_t
csm_allow_jit_region(
	pmap_t monitor_pmap)
{
	if (csm_enabled() == false) {
		return KERN_SUCCESS;
	} else if (monitor_pmap == NULL) {
		return KERN_DENIED;
	}

	kern_return_t ret = CSM_PREFIX(allow_jit_region)(monitor_pmap);
	if (ret == KERN_NOT_SUPPORTED) {
		/*
		 * Some monitor environments do not support this API and as a result will
		 * return KERN_NOT_SUPPORTED. The caller here should not interpret that as
		 * a failure.
		 */
		ret = KERN_SUCCESS;
	}

	return ret;
}

kern_return_t
csm_associate_jit_region(
	pmap_t monitor_pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(associate_jit_region)(
		monitor_pmap,
		region_addr,
		region_size);
}

kern_return_t
csm_associate_debug_region(
	pmap_t monitor_pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(associate_debug_region)(
		monitor_pmap,
		region_addr,
		region_size);
}

kern_return_t
csm_allow_invalid_code(
	pmap_t pmap)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(allow_invalid_code)(pmap);
}

kern_return_t
csm_get_trust_level_kdp(
	pmap_t pmap,
	uint32_t *trust_level)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(get_trust_level_kdp)(pmap, trust_level);
}

kern_return_t
csm_address_space_exempt(
	const pmap_t pmap)
{
	/*
	 * These exemptions are actually orthogonal to the code signing enforcement. As
	 * a result, we let each monitor explicitly decide how to deal with the exemption
	 * in case code signing enforcement is disabled.
	 */

	return CSM_PREFIX(address_space_exempt)(pmap);
}

kern_return_t
csm_fork_prepare(
	pmap_t old_pmap,
	pmap_t new_pmap)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(fork_prepare)(old_pmap, new_pmap);
}

kern_return_t
csm_acquire_signing_identifier(
	const void *monitor_sig_obj,
	const char **signing_id)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(acquire_signing_identifier)(monitor_sig_obj, signing_id);
}

kern_return_t
csm_associate_os_entitlements(
	void *monitor_sig_obj,
	const void *os_entitlements)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	} else if (os_entitlements == NULL) {
		/* Not every signature has entitlements */
		return KERN_SUCCESS;
	}

	return CSM_PREFIX(associate_kernel_entitlements)(monitor_sig_obj, os_entitlements);
}

kern_return_t
csm_accelerate_entitlements(
	void *monitor_sig_obj,
	CEQueryContext_t *ce_ctx)
{
	if (csm_enabled() == false) {
		return KERN_NOT_SUPPORTED;
	}

	return CSM_PREFIX(accelerate_entitlements)(monitor_sig_obj, ce_ctx);
}

#endif /* CODE_SIGNING_MONITOR */

#pragma mark AppleImage4
/*
 * AppleImage4 uses the monitor environment to safeguard critical security data.
 * In order to ease the implementation specific, AppleImage4 always depends on these
 * abstracted APIs, regardless of whether the system has a monitor environment or
 * not.
 */

void*
kernel_image4_storage_data(
	size_t *allocated_size)
{
	return CSM_PREFIX(image4_storage_data)(allocated_size);
}

void
kernel_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce)
{
	return CSM_PREFIX(image4_set_nonce)(ndi, nonce);
}

void
kernel_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi)
{
	return CSM_PREFIX(image4_roll_nonce)(ndi);
}

errno_t
kernel_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out)
{
	return CSM_PREFIX(image4_copy_nonce)(ndi, nonce_out);
}

errno_t
kernel_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest)
{
	return CSM_PREFIX(image4_execute_object)(
		obj_spec_index,
		payload,
		manifest);
}

errno_t
kernel_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length)
{
	return CSM_PREFIX(image4_copy_object)(
		obj_spec_index,
		object_out,
		object_length);
}

const void*
kernel_image4_get_monitor_exports(void)
{
	return CSM_PREFIX(image4_get_monitor_exports)();
}

errno_t
kernel_image4_set_release_type(
	const char *release_type)
{
	return CSM_PREFIX(image4_set_release_type)(release_type);
}

errno_t
kernel_image4_set_bnch_shadow(
	const img4_nonce_domain_index_t ndi)
{
	return CSM_PREFIX(image4_set_bnch_shadow)(ndi);
}

#pragma mark Image4 - New



static errno_t
_kernel_image4_monitor_trap_image_activate(
	image4_cs_trap_t selector,
	const void *input_data)
{
	/*
	 * csmx_payload (csmx_payload_len) --> __cs_xfer
	 * csmx_manifest (csmx_manifest_len) --> __cs_borrow
	 */
	image4_cs_trap_argv(image_activate) input = {0};
	vm_address_t payload_addr = 0;
	vm_address_t manifest_addr = 0;
	errno_t err = EPERM;

	/* Copy the input data */
	memcpy(&input, input_data, sizeof(input));

	payload_addr = code_signing_allocate(input.csmx_payload_len);
	if (payload_addr == 0) {
		goto out;
	}
	memcpy((void*)payload_addr, (void*)input.csmx_payload, input.csmx_payload_len);

	manifest_addr = code_signing_allocate(input.csmx_manifest_len);
	if (manifest_addr == 0) {
		goto out;
	}
	memcpy((void*)manifest_addr, (void*)input.csmx_manifest, input.csmx_manifest_len);

	/* Transfer both regions to the monitor */
	CSM_PREFIX(image4_transfer_region)(selector, payload_addr, input.csmx_payload_len);
	CSM_PREFIX(image4_transfer_region)(selector, manifest_addr, input.csmx_manifest_len);

	/* Setup the input with new addresses */
	input.csmx_payload = payload_addr;
	input.csmx_manifest = manifest_addr;

	/* Trap into the monitor for this selector */
	err = CSM_PREFIX(image4_monitor_trap)(selector, &input, sizeof(input));

out:
	if ((err != 0) && (payload_addr != 0)) {
		/* Retyping only happens after allocating the manifest */
		if (manifest_addr != 0) {
			CSM_PREFIX(image4_reclaim_region)(
				selector, payload_addr, input.csmx_payload_len);
		}
		code_signing_deallocate(&payload_addr, input.csmx_payload_len);
	}

	if (manifest_addr != 0) {
		/* Reclaim the manifest region -- will be retyped if not NULL */
		CSM_PREFIX(image4_reclaim_region)(
			selector, manifest_addr, input.csmx_manifest_len);

		/* Deallocate the manifest region */
		code_signing_deallocate(&manifest_addr, input.csmx_manifest_len);
	}

	return err;
}

static errno_t
_kernel_image4_monitor_trap(
	image4_cs_trap_t selector,
	const void *input_data,
	size_t input_size)
{
	/* Validate input size for the selector */
	if (input_size != image4_cs_trap_vector_size(selector)) {
		printf("image4 dispatch: invalid input: %llu | %lu\n", selector, input_size);
		return EINVAL;
	}

	switch (selector) {
	case IMAGE4_CS_TRAP_IMAGE_ACTIVATE:
		return _kernel_image4_monitor_trap_image_activate(selector, input_data);

	default:
		return CSM_PREFIX(image4_monitor_trap)(selector, input_data, input_size);
	}
}

errno_t
kernel_image4_monitor_trap(
	image4_cs_trap_t selector,
	const void *input_data,
	size_t input_size,
	__unused void *output_data,
	__unused size_t *output_size)
{
	size_t length_check = 0;

	/* Input data is always required */
	if ((input_data == NULL) || (input_size == 0)) {
		printf("image4 dispatch: no input data: %llu\n", selector);
		return EINVAL;
	} else if (os_add_overflow((vm_address_t)input_data, input_size, &length_check)) {
		panic("image4_ dispatch: overflow on input: %p | %lu", input_data, input_size);
	}

	return _kernel_image4_monitor_trap(selector, input_data, input_size);
}
