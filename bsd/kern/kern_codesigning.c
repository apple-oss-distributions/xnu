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
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/lock_rw.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/coretrust/coretrust.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <uuid/uuid.h>
#include <IOKit/IOBSD.h>

#if CODE_SIGNING_MONITOR
/*
 * Any set of definitions and functions which are only needed when we have a monitor
 * environment available should go under this if-guard.
 */

#if   PMAP_CS_PPL_MONITOR
/* All good */
#else
#error "CODE_SIGNING_MONITOR defined without an available monitor"
#endif

typedef uint64_t pmap_paddr_t;
extern vm_map_address_t phystokv(pmap_paddr_t pa);
extern pmap_paddr_t kvtophys_nofail(vm_offset_t va);

#endif /* CODE_SIGNING_MONITOR */

#if   PMAP_CS_PPL_MONITOR
/*
 * We have the Page Protection Layer environment available. All of our artifacts
 * need to be page-aligned. The PPL will lockdown the artifacts before it begins
 * the validation.
 */

SECURITY_READ_ONLY_EARLY(static bool*) developer_mode_enabled = &ppl_developer_mode_storage;

static void
ppl_toggle_developer_mode(
	bool state)
{
	pmap_toggle_developer_mode(state);
}

static kern_return_t
ppl_register_provisioning_profile(
	const void *profile_blob,
	const size_t profile_blob_size,
	void **profile_obj)
{
	pmap_profile_payload_t *pmap_payload = NULL;
	vm_address_t payload_addr = 0;
	vm_size_t payload_size = 0;
	vm_size_t payload_size_aligned = 0;
	kern_return_t ret = KERN_DENIED;

	if (os_add_overflow(sizeof(*pmap_payload), profile_blob_size, &payload_size)) {
		panic("attempted to load a too-large profile: %lu bytes", profile_blob_size);
	}
	payload_size_aligned = round_page(payload_size);

	ret = kmem_alloc(kernel_map, &payload_addr, payload_size_aligned,
	    KMA_KOBJECT | KMA_DATA | KMA_ZERO, VM_KERN_MEMORY_SECURITY);
	if (ret != KERN_SUCCESS) {
		printf("unable to allocate memory for pmap profile payload: %d\n", ret);
		goto exit;
	}

	/* We need to setup the payload before we send it to the PPL */
	pmap_payload = (pmap_profile_payload_t*)payload_addr;

	pmap_payload->profile_blob_size = profile_blob_size;
	memcpy(pmap_payload->profile_blob, profile_blob, profile_blob_size);

	ret = pmap_register_provisioning_profile(payload_addr, payload_size_aligned);
	if (ret == KERN_SUCCESS) {
		*profile_obj = &pmap_payload->profile_obj_storage;
		*profile_obj = (pmap_cs_profile_t*)phystokv(kvtophys_nofail((vm_offset_t)*profile_obj));
	}

exit:
	if ((ret != KERN_SUCCESS) && (payload_addr != 0)) {
		kmem_free(kernel_map, payload_addr, payload_size_aligned);
		payload_addr = 0;
		payload_size_aligned = 0;
	}

	return ret;
}

static kern_return_t
ppl_unregister_provisioning_profile(
	pmap_cs_profile_t *profile_obj)
{
	kern_return_t ret = KERN_DENIED;

	ret = pmap_unregister_provisioning_profile(profile_obj);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* Get the original payload address */
	const pmap_profile_payload_t *pmap_payload = profile_obj->original_payload;
	const vm_address_t payload_addr = (const vm_address_t)pmap_payload;

	/* Get the original payload size */
	vm_size_t payload_size = pmap_payload->profile_blob_size + sizeof(*pmap_payload);
	payload_size = round_page(payload_size);

	/* Free the payload */
	kmem_free(kernel_map, payload_addr, payload_size);
	pmap_payload = NULL;

	return KERN_SUCCESS;
}

static kern_return_t
ppl_associate_provisioning_profile(
	pmap_cs_code_directory_t *sig_obj,
	pmap_cs_profile_t *profile_obj)
{
	if (pmap_cs_enabled() == false) {
		return KERN_SUCCESS;
	}

	return pmap_associate_provisioning_profile(sig_obj, profile_obj);
}

static kern_return_t
ppl_disassociate_provisioning_profile(
	pmap_cs_code_directory_t *sig_obj)
{
	if (pmap_cs_enabled() == false) {
		return KERN_SUCCESS;
	}

	return pmap_disassociate_provisioning_profile(sig_obj);
}

#else
/*
 * We don't have a monitor environment available. This means someone with a kernel
 * memory exploit will be able to corrupt code signing state. There is not much we
 * can do here, since this is older HW.
 */

static bool developer_mode_storage = true;
SECURITY_READ_ONLY_EARLY(static bool*) developer_mode_enabled = &developer_mode_storage;

static void
xnu_toggle_developer_mode(
	bool state)
{
	/* No extra validation needed within XNU */
	os_atomic_store(developer_mode_enabled, state, release);
}

#endif /* */

#pragma mark Developer Mode
/*
 * AMFI always depends on XNU to extract the state of developer mode on the system. In
 * cases when we have a monitor, the state is stored within protected monitor memory.
 */

void
enable_developer_mode(void)
{
#if   PMAP_CS_PPL_MONITOR
	ppl_toggle_developer_mode(true);
#else
	xnu_toggle_developer_mode(true);
#endif
}

void
disable_developer_mode(void)
{
#if   PMAP_CS_PPL_MONITOR
	ppl_toggle_developer_mode(false);
#else
	xnu_toggle_developer_mode(false);
#endif
}

bool
developer_mode_state(void)
{
	/* Assume true if the pointer isn't setup */
	if (developer_mode_enabled == NULL) {
		return true;
	}

	return os_atomic_load(developer_mode_enabled, acquire);
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
	free_provisioning_profiles();
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
initialize_provisioning_profiles(void)
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
register_provisioning_profile(
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

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_register_provisioning_profile(profile_blob, profile_blob_size, &monitor_profile_obj);
#endif

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
associate_provisioning_profile(
	void *monitor_sig_obj,
	const uuid_t profile_uuid)
{
	cs_profile_t *profile = NULL;
	kern_return_t ret = KERN_DENIED;

	/* Lock the profile set as shared */
	lck_rw_lock_shared(&profiles_lock);

	/* Search for the provisioning profile */
	profile = search_for_profile_uuid(profile_uuid);
	if (profile == NULL) {
		ret = KERN_NOT_FOUND;
		goto exit;
	}

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_associate_provisioning_profile(monitor_sig_obj, profile->profile_obj);
#endif

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
disassociate_provisioning_profile(
	void *monitor_sig_obj)
{
	kern_return_t ret = KERN_DENIED;

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_disassociate_provisioning_profile(monitor_sig_obj);
#endif

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

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_unregister_provisioning_profile(profile->profile_obj);
#endif

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
free_provisioning_profiles(void)
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
