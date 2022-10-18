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
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>
#include <mach/boolean.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/pmap_cs.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/lock_rw.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/img4/interface.h>
#include <libkern/amfi/amfi.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/trust_caches.h>
#include <IOKit/IOBSD.h>
#include <img4/firmware.h>
#include <TrustCache/API.h>

static bool boot_os_tc_loaded = false;
static bool boot_app_tc_loaded = false;

#if   PMAP_CS_PPL_MONITOR
/*
 * We have the Page Protection Layer environment available. All of our artifacts
 * need to be page-aligned. The PPL will lockdown the artifacts before it begins
 * the validation.
 *
 * Even though the runtimes are PPL owned, we expect the runtime init function
 * to be called before the PPL has been locked down, which allows us to write
 * to them.
 */

/* Immutable part of the runtime */
SECURITY_READ_ONLY_LATE(TrustCacheRuntime_t*) trust_cache_rt = &ppl_trust_cache_rt;

/* Mutable part of the runtime */
SECURITY_READ_ONLY_LATE(TrustCacheMutableRuntime_t*) trust_cache_mut_rt = &ppl_trust_cache_mut_rt;

void
trust_cache_runtime_init(void)
{
	bool allow_second_static_cache = false;
	bool allow_engineering_caches = false;

#if CONFIG_SECOND_STATIC_TRUST_CACHE
	allow_second_static_cache = true;
#endif

#if PMAP_CS_INCLUDE_INTERNAL_CODE
	allow_engineering_caches = true;
#endif

	/* Image4 interface needs to be available */
	if (img4if == NULL) {
		panic("image4 interface not available");
	}

	trustCacheInitializeRuntime(
		trust_cache_rt,
		trust_cache_mut_rt,
		allow_second_static_cache,
		allow_engineering_caches,
		false,
		IMG4_RUNTIME_PMAP_CS);

	/* Locks are initialized in "pmap_bootstrap()" */
}

static kern_return_t
ppl_load_trust_cache(
	TCType_t type,
	const uint8_t *img4_payload, const size_t img4_payload_len,
	const uint8_t *img4_manifest, const size_t img4_manifest_len,
	const uint8_t *img4_aux_manifest, const size_t img4_aux_manifest_len)
{
	kern_return_t ret = KERN_DENIED;
	vm_address_t payload_addr = 0;
	vm_size_t payload_len = 0;
	vm_size_t payload_len_aligned = 0;
	vm_address_t manifest_addr = 0;
	vm_size_t manifest_len_aligned = 0;
	vm_address_t aux_manifest_addr = 0;
	vm_size_t aux_manifest_len_aligned = 0;

	/* The trust cache data structure is bundled with the img4 payload */
	if (os_add_overflow(img4_payload_len, sizeof(pmap_img4_payload_t), &payload_len)) {
		panic("overflow on pmap img4 payload: %lu", img4_payload_len);
	}
	payload_len_aligned = round_page(payload_len);
	manifest_len_aligned = round_page(img4_manifest_len);
	aux_manifest_len_aligned = round_page(img4_aux_manifest_len);

	ret = kmem_alloc(kernel_map, &payload_addr, payload_len_aligned,
	    KMA_KOBJECT | KMA_ZERO, VM_KERN_MEMORY_SECURITY);
	if (ret != KERN_SUCCESS) {
		printf("unable to allocate memory for pmap image4 payload: %d\n", ret);
		goto out;
	}

	pmap_img4_payload_t *pmap_payload = (pmap_img4_payload_t*)payload_addr;
	memcpy(pmap_payload->img4_payload, img4_payload, img4_payload_len);

	/* Allocate storage for the manifest */
	ret = kmem_alloc(kernel_map, &manifest_addr, manifest_len_aligned,
	    KMA_KOBJECT | KMA_DATA | KMA_ZERO, VM_KERN_MEMORY_SECURITY);
	if (ret != KERN_SUCCESS) {
		printf("unable to allocate memory for image4 manifest: %d\n", ret);
		goto out;
	}
	memcpy((void*)manifest_addr, img4_manifest, img4_manifest_len);

	if (aux_manifest_len_aligned != 0) {
		/* Allocate storage for the auxiliary manifest */
		ret = kmem_alloc(kernel_map, &aux_manifest_addr, aux_manifest_len_aligned,
		    KMA_KOBJECT | KMA_DATA | KMA_ZERO, VM_KERN_MEMORY_SECURITY);
		if (ret != KERN_SUCCESS) {
			printf("unable to allocate memory for auxiliary image4 manifest: %d\n", ret);
			goto out;
		}
		memcpy((void*)aux_manifest_addr, img4_aux_manifest, img4_aux_manifest_len);
	}

	/* The PPL will round up the length to page size itself */
	ret = pmap_load_trust_cache_with_type(
		type,
		payload_addr, payload_len,
		manifest_addr, img4_manifest_len,
		aux_manifest_addr, img4_aux_manifest_len);

out:
	if (aux_manifest_addr != 0) {
		kmem_free(kernel_map, aux_manifest_addr, aux_manifest_len_aligned);
		aux_manifest_addr = 0;
		aux_manifest_len_aligned = 0;
	}

	if (manifest_addr != 0) {
		kmem_free(kernel_map, manifest_addr, manifest_len_aligned);
		manifest_addr = 0;
		manifest_len_aligned = 0;
	}

	if ((ret != KERN_SUCCESS) && (payload_addr != 0)) {
		kmem_free(kernel_map, payload_addr, payload_len_aligned);
		payload_addr = 0;
		payload_len_aligned = 0;
	}

	return ret;
}

static kern_return_t
ppl_load_legacy_trust_cache(
	__unused const uint8_t *module_data, __unused const size_t module_size)
{
	panic("legacy trust caches are not supported on this platform");
}

static kern_return_t
ppl_query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	/*
	 * We need to query by trapping into the PPL since the PPL trust cache runtime
	 * lock needs to be held. We cannot hold the lock from outside the PPL.
	 */
	return pmap_query_trust_cache(query_type, cdhash, query_token);
}

#else
/*
 * We don't have a monitor environment available. This means someone with a kernel
 * memory exploit will be able to inject a trust cache into the system. There is
 * not much we can do here, since this is older HW.
 */

/* Lock for the runtime */
LCK_GRP_DECLARE(trust_cache_lck_grp, "trust_cache_lck_grp");
decl_lck_rw_data(, trust_cache_rt_lock);

/* Immutable part of the runtime */
SECURITY_READ_ONLY_LATE(TrustCacheRuntime_t) trust_cache_rt_storage;
SECURITY_READ_ONLY_LATE(TrustCacheRuntime_t*) trust_cache_rt = &trust_cache_rt_storage;

/* Mutable part of the runtime */
TrustCacheMutableRuntime_t trust_cache_mut_rt_storage;
SECURITY_READ_ONLY_LATE(TrustCacheMutableRuntime_t*) trust_cache_mut_rt = &trust_cache_mut_rt_storage;

void
trust_cache_runtime_init(void)
{
	bool allow_second_static_cache = false;
	bool allow_engineering_caches = false;
	bool allow_legacy_caches = false;

#if CONFIG_SECOND_STATIC_TRUST_CACHE
	allow_second_static_cache = true;
#endif

#if TRUST_CACHE_INCLUDE_INTERNAL_CODE
	allow_engineering_caches = true;
#endif

#ifdef XNU_PLATFORM_BridgeOS
	allow_legacy_caches = true;
#endif

	/* Image4 interface needs to be available */
	if (img4if == NULL) {
		panic("image4 interface not available");
	}

	trustCacheInitializeRuntime(
		trust_cache_rt,
		trust_cache_mut_rt,
		allow_second_static_cache,
		allow_engineering_caches,
		allow_legacy_caches,
		IMG4_RUNTIME_DEFAULT);

	/* Initialize the read-write lock */
	lck_rw_init(&trust_cache_rt_lock, &trust_cache_lck_grp, 0);
}

static kern_return_t
xnu_load_trust_cache(
	TCType_t type,
	const uint8_t *img4_payload, const size_t img4_payload_len,
	const uint8_t *img4_manifest, const size_t img4_manifest_len,
	const uint8_t *img4_aux_manifest, const size_t img4_aux_manifest_len)
{
	kern_return_t ret = KERN_DENIED;

	/* Ignore the auxiliary manifest until we add support for it */
	(void)img4_aux_manifest;
	(void)img4_aux_manifest_len;

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		printf("unable to load trust cache (type: %u): interface not supported\n", type);
		return KERN_NOT_SUPPORTED;
	}

	/* Allocate the trust cache data structure -- Z_WAITOK_ZERO means this can't fail */
	TrustCache_t *trust_cache = kalloc_type(TrustCache_t, Z_WAITOK_ZERO);
	assert(trust_cache != NULL);

	/*
	 * The manifests aren't needed after the validation is complete, but the payload needs
	 * to persist. The caller of this API expects us to make our own allocations. Since we
	 * don't need the manifests after validation, we can use the manifests passed in to us
	 * but we need to make a new allocation for the payload, since that needs to persist.
	 *
	 * Z_WAITOK implies that this allocation can never fail.
	 */
	uint8_t *payload = (uint8_t*)kalloc_data(img4_payload_len, Z_WAITOK);
	assert(payload != NULL);

	/* Copy the payload into our allocation */
	memcpy(payload, img4_payload, img4_payload_len);

	/* Exclusively lock the runtime */
	lck_rw_lock_exclusive(&trust_cache_rt_lock);

	TCReturn_t tc_ret = interface->load(
		trust_cache_rt,
		type,
		trust_cache,
		(const uintptr_t)payload, img4_payload_len,
		(const uintptr_t)img4_manifest, img4_manifest_len);

	/* Unlock the runtime */
	lck_rw_unlock_exclusive(&trust_cache_rt_lock);

	if (tc_ret.error == kTCReturnSuccess) {
		ret = KERN_SUCCESS;
	} else if (tc_ret.error == kTCReturnDuplicate) {
		ret = KERN_ALREADY_IN_SET;
	} else {
		printf("unable to load trust cache (TCReturn: 0x%02X | 0x%02X | %u)\n",
		    tc_ret.component, tc_ret.error, tc_ret.uniqueError);

		ret = KERN_FAILURE;
	}

	if (ret != KERN_SUCCESS) {
		kfree_data(payload, img4_payload_len);
		payload = NULL;

		kfree_type(TrustCache_t, trust_cache);
		trust_cache = NULL;
	}
	return ret;
}

static kern_return_t
xnu_load_legacy_trust_cache(
	__unused const uint8_t *module_data, __unused const size_t module_size)
{
#if XNU_HAS_LEGACY_TRUST_CACHE_LOADING
	kern_return_t ret = KERN_DENIED;

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		printf("unable to load legacy trust cache: interface not supported\n");
		return KERN_NOT_SUPPORTED;
	}

	/* Allocate the trust cache data structure -- Z_WAITOK_ZERO means this can't fail */
	TrustCache_t *trust_cache = kalloc_type(TrustCache_t, Z_WAITOK_ZERO);
	assert(trust_cache != NULL);

	/* Allocate storage for the module -- Z_WAITOK means this can't fail */
	uint8_t *module = (uint8_t*)kalloc_data(module_size, Z_WAITOK);
	assert(module != NULL);

	/* Copy the module into our allocation */
	memcpy(module, module_data, module_size);

	/* Exclusively lock the runtime */
	lck_rw_lock_exclusive(&trust_cache_rt_lock);

	TCReturn_t tc_ret = interface->loadModule(
		trust_cache_rt,
		kTCTypeLegacy,
		trust_cache,
		(const uintptr_t)module, module_size);

	/* Unlock the runtime */
	lck_rw_unlock_exclusive(&trust_cache_rt_lock);

	if (tc_ret.error == kTCReturnSuccess) {
		ret = KERN_SUCCESS;
	} else if (tc_ret.error == kTCReturnDuplicate) {
		ret = KERN_ALREADY_IN_SET;
	} else {
		printf("unable to load legacy trust cache (TCReturn: 0x%02X | 0x%02X | %u)\n",
		    tc_ret.component, tc_ret.error, tc_ret.uniqueError);

		ret = KERN_FAILURE;
	}

	if (ret != KERN_SUCCESS) {
		kfree_data(module, module_size);
		module = NULL;

		kfree_type(TrustCache_t, trust_cache);
		trust_cache = NULL;
	}
	return ret;
#else
	panic("legacy trust caches are not supported on this platform");
#endif /* XNU_HAS_LEGACY_TRUST_CACHE_LOADING */
}

static kern_return_t
xnu_query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	kern_return_t ret = KERN_NOT_FOUND;

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		printf("unable to query trust cache: interface not supported\n");
		return KERN_NOT_SUPPORTED;
	}

	/* Validate the query type preemptively */
	if (query_type >= kTCQueryTypeTotal) {
		printf("unable to query trust cache: invalid query type: %u\n", query_type);
		return KERN_INVALID_ARGUMENT;
	}

	/* Lock the runtime as shared */
	lck_rw_lock_shared(&trust_cache_rt_lock);

	TCReturn_t tc_ret = interface->query(
		trust_cache_rt,
		query_type,
		cdhash,
		query_token);

	/* Unlock the runtime */
	lck_rw_unlock_shared(&trust_cache_rt_lock);

	if (tc_ret.error == kTCReturnSuccess) {
		ret = KERN_SUCCESS;
	} else if (tc_ret.error == kTCReturnNotFound) {
		ret = KERN_NOT_FOUND;
	} else {
		ret = KERN_FAILURE;
		printf("trust cache query failed (TCReturn: 0x%02X | 0x%02X | %u)\n",
		    tc_ret.component, tc_ret.error, tc_ret.uniqueError);
	}

	return ret;
}

#endif /* */

kern_return_t
load_trust_cache(
	const uint8_t *img4_object, const size_t img4_object_len,
	const uint8_t *img4_ext_manifest, const size_t img4_ext_manifest_len)
{
	TCType_t type = kTCTypeInvalid;
	kern_return_t ret = KERN_DENIED;

	/* Start from the first valid type and attempt to validate through each */
	for (type = kTCTypeLTRS; type < kTCTypeTotal; type += 1) {
		ret = load_trust_cache_with_type(
			type,
			img4_object, img4_object_len,
			img4_ext_manifest, img4_ext_manifest_len,
			NULL, 0);

		if ((ret == KERN_SUCCESS) || (ret == KERN_ALREADY_IN_SET)) {
			return ret;
		}
	}

#if TRUST_CACHE_INCLUDE_INTERNAL_CODE
	/* Attempt to load as an engineering root */
	ret = load_trust_cache_with_type(
		kTCTypeDTRS,
		img4_object, img4_object_len,
		img4_ext_manifest, img4_ext_manifest_len,
		NULL, 0);
#endif

	return ret;
}

kern_return_t
load_trust_cache_with_type(
	TCType_t type,
	const uint8_t *img4_object, const size_t img4_object_len,
	const uint8_t *img4_ext_manifest, const size_t img4_ext_manifest_len,
	const uint8_t *img4_aux_manifest, const size_t img4_aux_manifest_len)
{
	kern_return_t ret = KERN_DENIED;
	uintptr_t length_check = 0;
	const uint8_t *img4_payload = NULL;
	size_t img4_payload_len = 0;
	const uint8_t *img4_manifest = NULL;
	size_t img4_manifest_len = 0;

	/* Image4 interface needs to be available */
	if (img4if == NULL) {
		panic("image4 interface not available");
	}

	/* img4_object is required */
	if (!img4_object || (img4_object_len == 0)) {
		printf("unable to load trust cache (type: %u): no img4_object provided\n", type);
		return KERN_INVALID_ARGUMENT;
	} else if (os_add_overflow((uintptr_t)img4_object, img4_object_len, &length_check)) {
		panic("overflow on the img4 object: %p | %lu", img4_object, img4_object_len);
	}

	/* img4_ext_manifest is optional */
	if (img4_ext_manifest_len != 0) {
		if (!img4_ext_manifest) {
			printf("unable to load trust cache (type: %u): img4_ext_manifest expected\n", type);
			return KERN_INVALID_ARGUMENT;
		} else if (os_add_overflow((uintptr_t)img4_ext_manifest, img4_ext_manifest_len, &length_check)) {
			panic("overflow on the ext manifest: %p | %lu", img4_ext_manifest, img4_ext_manifest_len);
		}
	}

	/* img4_aux_manifest is optional */
	if (img4_aux_manifest_len != 0) {
		if (!img4_aux_manifest) {
			printf("unable to load trust cache (type: %u): img4_aux_manifest expected\n", type);
			return KERN_INVALID_ARGUMENT;
		} else if (os_add_overflow((uintptr_t)img4_aux_manifest, img4_aux_manifest_len, &length_check)) {
			panic("overflow on the ext manifest: %p | %lu", img4_aux_manifest, img4_aux_manifest_len);
		}
	}

	/*
	 * If we don't have an external manifest provided, we expect the img4_object to have
	 * the manifest embedded. In this case, we need to extract the different artifacts
	 * out of the object.
	 */
	if (img4_ext_manifest_len != 0) {
		img4_payload = img4_object;
		img4_payload_len = img4_object_len;
		img4_manifest = img4_ext_manifest;
		img4_manifest_len = img4_ext_manifest_len;
	} else {
		if (img4if->i4if_version < 15) {
			/* AppleImage4 change hasn't landed in the build */
			printf("unable to extract payload and manifest from object\n");
			return KERN_NOT_SUPPORTED;
		}
		img4_buff_t img4_buff = IMG4_BUFF_INIT;

		/* Extract the payload */
		if (img4_get_payload(img4_object, img4_object_len, &img4_buff) == NULL) {
			printf("unable to find payload within img4 object\n");
			return KERN_NOT_FOUND;
		}
		img4_payload = img4_buff.i4b_bytes;
		img4_payload_len = img4_buff.i4b_len;

		/* Extract the manifest */
		if (img4_get_manifest(img4_object, img4_object_len, &img4_buff) == NULL) {
			printf("unable to find manifest within img4 object\n");
			return KERN_NOT_FOUND;
		}
		img4_manifest = img4_buff.i4b_bytes;
		img4_manifest_len = img4_buff.i4b_len;
	}

	if ((type == kTCTypeStatic) || (type == kTCTypeEngineering) || (type == kTCTypeLegacy)) {
		printf("unable to load trust cache: invalid type: %u\n", type);
		return KERN_INVALID_ARGUMENT;
	} else if (type >= kTCTypeTotal) {
		printf("unable to load trust cache: unknown type: %u\n", type);
		return KERN_INVALID_ARGUMENT;
	}

	/* Validate entitlement for the calling process */
	if (TCTypeConfig[type].entitlementValue != NULL) {
		const bool entitlement_satisfied = IOCurrentTaskHasStringEntitlement(
			"com.apple.private.pmap.load-trust-cache",
			TCTypeConfig[type].entitlementValue);

		if (entitlement_satisfied == false) {
			printf("unable to load trust cache (type: %u): unsatisfied entitlement\n", type);
			return KERN_DENIED;
		}
	}

	if ((type == kTCTypeCryptex1BootOS) && boot_os_tc_loaded) {
		printf("disallowed to load multiple kTCTypeCryptex1BootOS trust caches\n");
		return KERN_DENIED;
	} else if ((type == kTCTypeCryptex1BootApp) && boot_app_tc_loaded) {
		printf("disallowed to load multiple kTCTypeCryptex1BootApp trust caches\n");
		return KERN_DENIED;
	}

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_load_trust_cache(
		type,
		img4_payload, img4_payload_len,
		img4_manifest, img4_manifest_len,
		img4_aux_manifest, img4_aux_manifest_len);
#else
	ret = xnu_load_trust_cache(
		type,
		img4_payload, img4_payload_len,
		img4_manifest, img4_manifest_len,
		img4_aux_manifest, img4_aux_manifest_len);
#endif

	if (ret != KERN_SUCCESS) {
		printf("unable to load trust cache (type: %u): %d\n", type, ret);
	} else {
		if (type == kTCTypeCryptex1BootOS) {
			boot_os_tc_loaded = true;
		} else if (type == kTCTypeCryptex1BootApp) {
			boot_app_tc_loaded = true;
		}
		printf("successfully loaded trust cache of type: %u\n", type);
	}

	return ret;
}

kern_return_t
load_legacy_trust_cache(
	const uint8_t *module_data, const size_t module_size)
{
	kern_return_t ret = KERN_DENIED;
	uintptr_t length_check = 0;

	/* Module is required */
	if (!module_data || (module_size == 0)) {
		printf("unable to load legacy trust cache: no module provided\n");
		return KERN_INVALID_ARGUMENT;
	} else if (os_add_overflow((uintptr_t)module_data, module_size, &length_check)) {
		panic("overflow on the module: %p | %lu", module_data, module_size);
	}

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_load_legacy_trust_cache(module_data, module_size);
#else
	ret = xnu_load_legacy_trust_cache(module_data, module_size);
#endif

	if (ret != KERN_SUCCESS) {
		printf("unable to load legacy trust cache: %d\n", ret);
	} else {
		printf("successfully loaded legacy trust cache\n");
	}

	return ret;
}

kern_return_t
query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token)
{
	kern_return_t ret = KERN_NOT_FOUND;

	if (cdhash == NULL) {
		printf("unable to query trust caches: no cdhash provided\n");
		return KERN_INVALID_ARGUMENT;
	}

#if   PMAP_CS_PPL_MONITOR
	ret = ppl_query_trust_cache(query_type, cdhash, query_token);
#else
	ret = xnu_query_trust_cache(query_type, cdhash, query_token);
#endif

	return ret;
}

/*
 * The trust cache management library uses a wrapper data structure to manage each
 * of the trust cache modules. We know the exact number of static trust caches we
 * expect, so we keep around a read-only-late allocation of the data structure for
 * use.
 *
 * Since engineering trust caches are only ever allowed on development builds, they
 * are not protected through the read-only-late property, and instead allocated
 * dynamically.
 */

SECURITY_READ_ONLY_LATE(bool) trust_cache_static_init = false;
SECURITY_READ_ONLY_LATE(bool) trust_cache_static_loaded = true;
SECURITY_READ_ONLY_LATE(TrustCache_t) trust_cache_static0 = {0};

#if CONFIG_SECOND_STATIC_TRUST_CACHE
SECURITY_READ_ONLY_LATE(TrustCache_t) trust_cache_static1 = {0};
#endif

#if defined(__arm64__)

/*
 * On arm platforms, the static and engineering trust caches are part of the EXTRADATA
 * segment. The device tree is also a part of the same segment. When building for this
 * platform, we ensure the format of the EXTRADATA segment is how we expect it to be.
 */
extern vm_offset_t segEXTRADATA;
extern unsigned long segSizeEXTRADATA;

typedef uint64_t pmap_paddr_t;
extern vm_map_address_t phystokv(pmap_paddr_t pa);

#else /* x86_64 */
/*
 * We need this duplicate definition because it is hidden behind the MACH_KERNEL_PRIVATE
 * macro definition, which makes it inaccessible to this part of the code base.
 */
extern uint64_t physmap_base, physmap_max;

static inline void*
PHYSMAP_PTOV_check(void *paddr)
{
	uint64_t pvaddr = (uint64_t)paddr + physmap_base;

	if (__improbable(pvaddr >= physmap_max)) {
		panic("PHYSMAP_PTOV bounds exceeded, 0x%qx, 0x%qx, 0x%qx",
		    pvaddr, physmap_base, physmap_max);
	}

	return (void*)pvaddr;
}

#define PHYSMAP_PTOV(x) (PHYSMAP_PTOV_check((void*) (x)))
#define phystokv(x) ((vm_offset_t)(PHYSMAP_PTOV(x)))

#endif /* defined(__arm__) || defined(__arm64__) */

void
load_static_trust_cache(void)
{
	DTEntry memory_map = {0};
	const DTTrustCacheRange *tc_range = NULL;
	trust_cache_offsets_t *tc_offsets = NULL;
	unsigned int tc_dt_prop_length = 0;
	size_t tc_segment_length = 0;

	/* Mark this function as having been called */
	trust_cache_static_init = true;

	/* Nothing to do when the runtime isn't set */
	if (trust_cache_rt == NULL) {
		return;
	}

	/* AMFI interface needs to be available */
	if (amfi == NULL) {
		panic("amfi interface not available");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 1) {
		/* AMFI change hasn't landed in the build */
		printf("unable to load static trust cache: interface not supported\n");
		return;
	}

	int err = SecureDTLookupEntry(NULL, "chosen/memory-map", &memory_map);
	if (err != kSuccess) {
		printf("unable to find chosen/memory-map in the device tree: %d\n", err);
		return;
	}

	err = SecureDTGetProperty(memory_map, "TrustCache", (const void **)&tc_range, &tc_dt_prop_length);
	if (err == kSuccess) {
		if (tc_dt_prop_length != sizeof(DTTrustCacheRange)) {
			panic("unexpected size for TrustCache property: %u != %zu",
			    tc_dt_prop_length, sizeof(DTTrustCacheRange));
		}

		tc_offsets = (void*)phystokv(tc_range->paddr);
		tc_segment_length = tc_range->length;
	}

	/* x86_64 devices aren't expected to have trust caches */
	if (tc_segment_length == 0) {
		if (tc_offsets && tc_offsets->num_caches != 0) {
			panic("trust cache segment is zero length but trust caches are available: %u",
			    tc_offsets->num_caches);
		}

		printf("no external trust caches found (segment length is zero)\n");
		return;
	} else if (tc_offsets->num_caches == 0) {
		panic("trust cache segment isn't zero but no trust caches available: %lu",
		    (unsigned long)tc_segment_length);
	}

	size_t offsets_length = 0;
	size_t struct_length = 0;
	if (os_mul_overflow(tc_offsets->num_caches, sizeof(uint32_t), &offsets_length)) {
		panic("overflow on the number of trust caches provided: %u", tc_offsets->num_caches);
	} else if (os_add_overflow(offsets_length, sizeof(trust_cache_offsets_t), &struct_length)) {
		panic("overflow on length of the trust cache offsets: %lu",
		    (unsigned long)offsets_length);
	} else if (tc_segment_length < struct_length) {
		panic("trust cache segment length smaller than required: %lu | %lu",
		    (unsigned long)tc_segment_length, (unsigned long)struct_length);
	}
	const uintptr_t tc_region_end = (uintptr_t)tc_offsets + tc_segment_length;

	printf("attempting to load %u external trust cache modules\n", tc_offsets->num_caches);

	for (uint32_t i = 0; i < tc_offsets->num_caches; i++) {
		TCReturn_t tc_ret = (TCReturn_t){.error = kTCReturnError};
		TCType_t tc_type = kTCTypeEngineering;
		TrustCache_t *trust_cache = NULL;

		uintptr_t tc_module = 0;
		if (os_add_overflow((uintptr_t)tc_offsets, tc_offsets->offsets[i], &tc_module)) {
			panic("trust cache module start overflows: %u | %lu | %u",
			    i, (unsigned long)tc_offsets, tc_offsets->offsets[i]);
		} else if (tc_module >= tc_region_end) {
			panic("trust cache module begins after segment ends: %u | %lx | %lx",
			    i, (unsigned long)tc_module, tc_region_end);
		}

		/* Should be safe for underflow */
		const size_t buffer_length = tc_region_end - tc_module;

		/* The first module is always the static trust cache */
		if (i == 0) {
			tc_type = kTCTypeStatic;
			trust_cache = &trust_cache_static0;
		}

#if CONFIG_SECOND_STATIC_TRUST_CACHE
		if (trust_cache_rt->allowSecondStaticTC && (i == 1)) {
			tc_type = kTCTypeStatic;
			trust_cache = &trust_cache_static1;
		}
#endif

		if (tc_type == kTCTypeEngineering) {
			if (trust_cache_rt->allowEngineeringTC == false) {
				printf("skipping engineering trust cache module: %u\n", i);
				continue;
			}

			/* Allocate the trust cache data structure -- Z_WAITOK_ZERO means this can't fail */
			trust_cache = kalloc_type(TrustCache_t, Z_WAITOK_ZERO);
			assert(trust_cache != NULL);
		}

		tc_ret = interface->loadModule(
			trust_cache_rt,
			tc_type,
			trust_cache,
			tc_module, buffer_length);

		if (tc_ret.error != kTCReturnSuccess) {
			printf("unable to load trust cache module: %u (TCReturn: 0x%02X | 0x%02X | %u)\n",
			    i, tc_ret.component, tc_ret.error, tc_ret.uniqueError);

			if (tc_type == kTCTypeStatic) {
				panic("failed to load static trust cache module: %u", i);
			}
			continue;
		}
		printf("loaded external trust cache module: %u\n", i);

		/*
		 * The first module is always loaded as a static trust cache. If loading it failed,
		 * then this function would've panicked. If we reach here, it means we've loaded a
		 * static trust cache on the system.
		 */
		trust_cache_static_loaded = true;
	}

	printf("completed loading external trust cache modules\n");
}

kern_return_t
static_trust_cache_capabilities(
	uint32_t *num_static_trust_caches,
	TCCapabilities_t *capabilities0,
	TCCapabilities_t *capabilities1)
{
	TCReturn_t tcRet = {.error = kTCReturnError};

	*num_static_trust_caches = 0;
	*capabilities0 = kTCCapabilityNone;
	*capabilities1 = kTCCapabilityNone;

	/* Ensure static trust caches have been initialized */
	if (trust_cache_static_init == false) {
		panic("attempted to query static trust cache capabilities without init");
	}

	const TrustCacheInterface_t *interface = &amfi->TrustCache;
	if (interface->version < 2) {
		/* AMFI change hasn't landed in the build */
		printf("unable to get static trust cache capabilities: interface not supported\n");
		return KERN_NOT_SUPPORTED;
	} else if (trust_cache_static_loaded == false) {
		/* Return arguments already set */
		return KERN_SUCCESS;
	}

	tcRet = interface->getCapabilities(&trust_cache_static0, capabilities0);
	assert(tcRet.error == kTCReturnSuccess);
	*num_static_trust_caches += 1;

#if CONFIG_SECOND_STATIC_TRUST_CACHE
	tcRet = interface->getCapabilities(&trust_cache_static1, capabilities1);
	assert(tcRet.error == kTCReturnSuccess);
	*num_static_trust_caches += 1;
#endif

	return KERN_SUCCESS;
}
