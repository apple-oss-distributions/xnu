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

#include <os/overflow.h>
#include <machine/atomic.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
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
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <uuid/uuid.h>
#include <IOKit/IOBSD.h>

#if PMAP_CS_PPL_MONITOR
/*
 * The Page Protection Layer layer implements the PMAP_CS monitor environment which
 * provides code signing and memory isolation enforcements for data structures which
 * are critical to ensuring that all code executed on the system is authorized to do
 * so.
 *
 * Unless the data is managed by the PPL itself, XNU needs to page-align everything,
 * and then reference the memory as read-only.
 */

typedef uint64_t pmap_paddr_t __kernel_ptr_semantics;
extern vm_map_address_t phystokv(pmap_paddr_t pa);
extern pmap_paddr_t kvtophys_nofail(vm_offset_t va);

#pragma mark Initialization

void
code_signing_init()
{
	/* Does nothing */
}

#pragma mark Developer Mode

SECURITY_READ_ONLY_LATE(bool*) developer_mode_enabled = &ppl_developer_mode_storage;

void
ppl_toggle_developer_mode(
	bool state)
{
	pmap_toggle_developer_mode(state);
}

#pragma mark Code Signing and Provisioning Profiles

bool
ppl_code_signing_enabled(void)
{
	return pmap_cs_enabled();
}

kern_return_t
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

kern_return_t
ppl_unregister_provisioning_profile(
	void *profile_obj)
{
	pmap_cs_profile_t *ppl_profile_obj = profile_obj;
	kern_return_t ret = KERN_DENIED;

	ret = pmap_unregister_provisioning_profile(ppl_profile_obj);
	if (ret != KERN_SUCCESS) {
		return ret;
	}

	/* Get the original payload address */
	const pmap_profile_payload_t *pmap_payload = ppl_profile_obj->original_payload;
	const vm_address_t payload_addr = (const vm_address_t)pmap_payload;

	/* Get the original payload size */
	vm_size_t payload_size = pmap_payload->profile_blob_size + sizeof(*pmap_payload);
	payload_size = round_page(payload_size);

	/* Free the payload */
	kmem_free(kernel_map, payload_addr, payload_size);
	pmap_payload = NULL;

	return KERN_SUCCESS;
}

kern_return_t
ppl_associate_provisioning_profile(
	void *sig_obj,
	void *profile_obj)
{
	return pmap_associate_provisioning_profile(sig_obj, profile_obj);
}

kern_return_t
ppl_disassociate_provisioning_profile(
	void *sig_obj)
{
	return pmap_disassociate_provisioning_profile(sig_obj);
}

void
ppl_set_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	pmap_set_compilation_service_cdhash(cdhash);
}

bool
ppl_match_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	return pmap_match_compilation_service_cdhash(cdhash);
}

void
ppl_set_local_signing_public_key(
	const uint8_t public_key[XNU_LOCAL_SIGNING_KEY_SIZE])
{
	return pmap_set_local_signing_public_key(public_key);
}

uint8_t*
ppl_get_local_signing_public_key(void)
{
	return pmap_get_local_signing_public_key();
}

void
ppl_unrestrict_local_signing_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	pmap_unrestrict_local_signing(cdhash);
}

vm_size_t
ppl_managed_code_signature_size(void)
{
	return pmap_cs_blob_limit;
}

kern_return_t
ppl_register_code_signature(
	const vm_address_t signature_addr,
	const vm_size_t signature_size,
	const vm_offset_t code_directory_offset,
	const char *signature_path,
	void **sig_obj,
	vm_address_t *ppl_signature_addr)
{
	pmap_cs_code_directory_t *cd_entry = NULL;

	/* PPL doesn't care about the signature path */
	(void)signature_path;

	kern_return_t ret = pmap_cs_register_code_signature_blob(
		signature_addr,
		signature_size,
		code_directory_offset,
		(pmap_cs_code_directory_t**)sig_obj);

	if (ret != KERN_SUCCESS) {
		return ret;
	}
	cd_entry = *((pmap_cs_code_directory_t**)sig_obj);

	if (ppl_signature_addr) {
		*ppl_signature_addr = (vm_address_t)cd_entry->superblob;
	}

	return KERN_SUCCESS;
}

kern_return_t
ppl_unregister_code_signature(
	void *sig_obj)
{
	return pmap_cs_unregister_code_signature_blob(sig_obj);
}

kern_return_t
ppl_verify_code_signature(
	void *sig_obj)
{
	return pmap_cs_verify_code_signature_blob(sig_obj);
}

kern_return_t
ppl_reconstitute_code_signature(
	void *sig_obj,
	vm_address_t *unneeded_addr,
	vm_size_t *unneeded_size)
{
	return pmap_cs_unlock_unneeded_code_signature(
		sig_obj,
		unneeded_addr,
		unneeded_size);
}

#pragma mark Address Spaces

kern_return_t
ppl_associate_code_signature(
	pmap_t pmap,
	void *sig_obj,
	const vm_address_t region_addr,
	const vm_size_t region_size,
	const vm_offset_t region_offset)
{
	return pmap_cs_associate(
		pmap,
		sig_obj,
		region_addr,
		region_size,
		region_offset);
}

kern_return_t
ppl_allow_jit_region(
	__unused pmap_t pmap)
{
	/* PPL does not support this API */
	return KERN_NOT_SUPPORTED;
}

kern_return_t
ppl_associate_jit_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	return pmap_cs_associate(
		pmap,
		PMAP_CS_ASSOCIATE_JIT,
		region_addr,
		region_size,
		0);
}

kern_return_t
ppl_associate_debug_region(
	pmap_t pmap,
	const vm_address_t region_addr,
	const vm_size_t region_size)
{
	return pmap_cs_associate(
		pmap,
		PMAP_CS_ASSOCIATE_COW,
		region_addr,
		region_size,
		0);
}

kern_return_t
ppl_address_space_debugged(
	pmap_t pmap)
{
	/*
	 * ppl_associate_debug_region is a fairly idempotent function which simply
	 * checks if an address space is already debugged or not and returns a value
	 * based on that. The actual memory region is not inserted into the address
	 * space, so we can pass whatever in this case. The only caveat here though
	 * is that the memory region needs to be page-aligned and cannot be NULL.
	 */
	return ppl_associate_debug_region(pmap, PAGE_SIZE, PAGE_SIZE);
}

kern_return_t
ppl_allow_invalid_code(
	pmap_t pmap)
{
	return pmap_cs_allow_invalid(pmap);
}

kern_return_t
ppl_get_trust_level_kdp(
	pmap_t pmap,
	uint32_t *trust_level)
{
	return pmap_get_trust_level_kdp(pmap, trust_level);
}

kern_return_t
ppl_address_space_exempt(
	const pmap_t pmap)
{
	if (pmap_performs_stage2_translations(pmap) == true) {
		return KERN_SUCCESS;
	}

	return KERN_DENIED;
}

kern_return_t
ppl_fork_prepare(
	pmap_t old_pmap,
	pmap_t new_pmap)
{
	return pmap_cs_fork_prepare(old_pmap, new_pmap);
}

kern_return_t
ppl_acquire_signing_identifier(
	const void *sig_obj,
	const char **signing_id)
{
	const pmap_cs_code_directory_t *cd_entry = sig_obj;

	/* If we reach here, the identifier must have been setup */
	assert(cd_entry->identifier != NULL);

	if (signing_id) {
		*signing_id = cd_entry->identifier;
	}

	return KERN_SUCCESS;
}

#pragma mark Entitlements

kern_return_t
ppl_associate_kernel_entitlements(
	void *sig_obj,
	const void *kernel_entitlements)
{
	pmap_cs_code_directory_t *cd_entry = sig_obj;
	return pmap_associate_kernel_entitlements(cd_entry, kernel_entitlements);
}

kern_return_t
ppl_resolve_kernel_entitlements(
	pmap_t pmap,
	const void **kernel_entitlements)
{
	kern_return_t ret = KERN_DENIED;
	const void *entitlements = NULL;

	ret = pmap_resolve_kernel_entitlements(pmap, &entitlements);
	if ((ret == KERN_SUCCESS) && (kernel_entitlements != NULL)) {
		*kernel_entitlements = entitlements;
	}

	return ret;
}

kern_return_t
ppl_accelerate_entitlements(
	void *sig_obj,
	CEQueryContext_t *ce_ctx)
{
	pmap_cs_code_directory_t *cd_entry = sig_obj;
	kern_return_t ret = KERN_DENIED;

	ret = pmap_accelerate_entitlements(cd_entry);

	/*
	 * We only ever get KERN_ABORTED when we cannot accelerate the entitlements
	 * because it would consume too much memory. In this case, we still want to
	 * return the ce_ctx since we don't want the system to fall-back to non-PPL
	 * locked down memory, so we switch this to a success case.
	 */
	if (ret == KERN_ABORTED) {
		ret = KERN_SUCCESS;
	}

	/* Return the accelerated context to the caller */
	if ((ret == KERN_SUCCESS) && (ce_ctx != NULL)) {
		*ce_ctx = cd_entry->ce_ctx;
	}

	return ret;
}

#pragma mark Image4

void*
ppl_image4_storage_data(
	size_t *allocated_size)
{
	return pmap_image4_pmap_data(allocated_size);
}

void
ppl_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce)
{
	return pmap_image4_set_nonce(ndi, nonce);
}

void
ppl_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi)
{
	return pmap_image4_roll_nonce(ndi);
}

errno_t
ppl_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out)
{
	return pmap_image4_copy_nonce(ndi, nonce_out);
}

errno_t
ppl_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest)
{
	errno_t err = EINVAL;
	kern_return_t kr = KERN_DENIED;
	img4_buff_t payload_aligned = IMG4_BUFF_INIT;
	img4_buff_t manifest_aligned = IMG4_BUFF_INIT;
	vm_address_t payload_addr = 0;
	vm_size_t payload_len_aligned = 0;
	vm_address_t manifest_addr = 0;
	vm_size_t manifest_len_aligned = 0;

	if (payload == NULL) {
		printf("invalid object execution request: no payload\n");
		goto out;
	}

	/*
	 * The PPL will attempt to lockdown both the payload and the manifest before executing
	 * the object. In order for that to happen, both the artifacts need to be page-aligned.
	 */
	payload_len_aligned = round_page(payload->i4b_len);
	if (manifest != NULL) {
		manifest_len_aligned = round_page(manifest->i4b_len);
	}

	kr = kmem_alloc(
		kernel_map,
		&payload_addr,
		payload_len_aligned,
		KMA_KOBJECT,
		VM_KERN_MEMORY_SECURITY);

	if (kr != KERN_SUCCESS) {
		printf("unable to allocate memory for image4 payload: %d\n", kr);
		err = ENOMEM;
		goto out;
	}

	/* Copy in the payload */
	memcpy((uint8_t*)payload_addr, payload->i4b_bytes, payload->i4b_len);

	/* Construct the aligned payload buffer */
	payload_aligned.i4b_bytes = (uint8_t*)payload_addr;
	payload_aligned.i4b_len = payload->i4b_len;

	if (manifest != NULL) {
		kr = kmem_alloc(
			kernel_map,
			&manifest_addr,
			manifest_len_aligned,
			KMA_KOBJECT,
			VM_KERN_MEMORY_SECURITY);

		if (kr != KERN_SUCCESS) {
			printf("unable to allocate memory for image4 manifest: %d\n", kr);
			err = ENOMEM;
			goto out;
		}

		/* Construct the aligned manifest buffer */
		manifest_aligned.i4b_bytes = (uint8_t*)manifest_addr;
		manifest_aligned.i4b_len = manifest->i4b_len;

		/* Copy in the manifest */
		memcpy((uint8_t*)manifest_addr, manifest->i4b_bytes, manifest->i4b_len);
	}

	err = pmap_image4_execute_object(obj_spec_index, &payload_aligned, &manifest_aligned);
	if (err != 0) {
		printf("unable to execute image4 object: %d\n", err);
		goto out;
	}

out:
	/* We always free the manifest as it isn't required anymore */
	if (manifest_addr != 0) {
		kmem_free(kernel_map, manifest_addr, manifest_len_aligned);
		manifest_addr = 0;
		manifest_len_aligned = 0;
	}

	/* If we encountered an error -- free the allocated payload */
	if ((err != 0) && (payload_addr != 0)) {
		kmem_free(kernel_map, payload_addr, payload_len_aligned);
		payload_addr = 0;
		payload_len_aligned = 0;
	}

	return err;
}

errno_t
ppl_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length)
{
	errno_t err = EINVAL;
	kern_return_t kr = KERN_DENIED;
	vm_address_t object_addr = 0;
	vm_size_t object_len_aligned = 0;

	if (object_out == 0) {
		printf("invalid object copy request: no object input buffer\n");
		goto out;
	} else if (object_length == NULL) {
		printf("invalid object copy request: no object input length\n");
		goto out;
	}

	/*
	 * The PPL will attempt to pin the input buffer in order to ensure that the kernel
	 * didn't pass in PPL-owned buffers. The PPL cannot pin the same page more than once,
	 * and attempting to do so will panic the system. Hence, we allocate fresh pages for
	 * for the PPL to pin.
	 *
	 * We can send in the address for the length pointer since that is allocated on the
	 * stack, so the PPL can pin our stack for the duration of the call as no other
	 * thread can be using our stack, meaning the PPL will never attempt to double-pin
	 * the page.
	 */
	object_len_aligned = round_page(*object_length);

	kr = kmem_alloc(
		kernel_map,
		&object_addr,
		object_len_aligned,
		KMA_KOBJECT,
		VM_KERN_MEMORY_SECURITY);

	if (kr != KERN_SUCCESS) {
		printf("unable to allocate memory for image4 object: %d\n", kr);
		err = ENOMEM;
		goto out;
	}

	err = pmap_image4_copy_object(obj_spec_index, object_addr, object_length);
	if (err != 0) {
		printf("unable to copy image4 object: %d\n", err);
		goto out;
	}

	/* Copy the data back into the caller passed buffer */
	memcpy((void*)object_out, (void*)object_addr, *object_length);

out:
	/* We don't ever need to keep around our page-aligned buffer */
	if (object_addr != 0) {
		kmem_free(kernel_map, object_addr, object_len_aligned);
		object_addr = 0;
		object_len_aligned = 0;
	}

	return err;
}

const void*
ppl_image4_get_monitor_exports(void)
{
	/*
	 * AppleImage4 can query the PMAP_CS runtime on its own since the PMAP_CS
	 * runtime is compiled within the kernel extension itself. As a result, we
	 * never expect this KPI to be called when the system uses the PPL monitor.
	 */

	printf("explicit monitor-exports-get not required for the PPL\n");
	return NULL;
}

errno_t
ppl_image4_set_release_type(
	__unused const char *release_type)
{
	/*
	 * AppleImage4 stores the release type in the CTRR protected memory region
	 * of its kernel extension. This is accessible by the PMAP_CS runtime as the
	 * runtime is compiled alongside the kernel extension. As a result, we never
	 * expect this KPI to be called when the system uses the PPL monitor.
	 */

	printf("explicit release-type-set set not required for the PPL\n");
	return ENOTSUP;
}

errno_t
ppl_image4_set_bnch_shadow(
	__unused const img4_nonce_domain_index_t ndi)
{
	/*
	 * AppleImage4 stores the BNCH shadow in the CTRR protected memory region
	 * of its kernel extension. This is accessible by the PMAP_CS runtime as the
	 * runtime is compiled alongside the kernel extension. As a result, we never
	 * expect this KPI to be called when the system uses the PPL monitor.
	 */

	printf("explicit BNCH-shadow-set not required for the PPL\n");
	return ENOTSUP;
}

#endif /* PMAP_CS_PPL_MONITOR */
