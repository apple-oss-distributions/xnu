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

#if !CODE_SIGNING_MONITOR
/*
 * We don't have a monitor environment available. This means someone with a kernel
 * memory exploit will be able to corrupt code signing state. There is not much we
 * can do here, since this is older HW.
 */
LCK_GRP_DECLARE(xnu_codesigning_lck_grp, "xnu_codesigning_lck_grp");

#pragma mark Initialization

static decl_lck_mtx_data(, compilation_service_lock);

void
code_signing_init()
{
	/* Initialize compilation service lock */
	lck_mtx_init(&compilation_service_lock, &xnu_codesigning_lck_grp, 0);
}

#pragma mark Developer Mode

static bool developer_mode_storage = true;
SECURITY_READ_ONLY_LATE(bool*) developer_mode_enabled = &developer_mode_storage;

void
xnu_toggle_developer_mode(
	bool state)
{
	/* No extra validation needed within XNU */
	os_atomic_store(developer_mode_enabled, state, relaxed);
}

#pragma mark Code Signing

static uint8_t compilation_service_cdhash[CS_CDHASH_LEN] = {0};

void
xnu_set_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	lck_mtx_lock(&compilation_service_lock);
	memcpy(compilation_service_cdhash, cdhash, CS_CDHASH_LEN);
	lck_mtx_unlock(&compilation_service_lock);
}

bool
xnu_match_compilation_service_cdhash(
	const uint8_t cdhash[CS_CDHASH_LEN])
{
	bool match = false;

	lck_mtx_lock(&compilation_service_lock);
	if (bcmp(compilation_service_cdhash, cdhash, CS_CDHASH_LEN) == 0) {
		match = true;
	}
	lck_mtx_unlock(&compilation_service_lock);

	return match;
}

static bool local_signing_key_set = false;
static uint8_t local_signing_public_key[XNU_LOCAL_SIGNING_KEY_SIZE] = {0};

void
xnu_set_local_signing_public_key(
	const uint8_t public_key[XNU_LOCAL_SIGNING_KEY_SIZE])
{
	bool key_set = false;

	/*
	 * os_atomic_cmpxchg returns true in case the exchange was successful. For us,
	 * a successful exchange means that the local signing public key has _not_ been
	 * set. In case the key has been set, we panic as we would never expect the
	 * kernel to attempt to set the key more than once.
	 */
	key_set = !os_atomic_cmpxchg(&local_signing_key_set, false, true, relaxed);

	if (key_set) {
		panic("attempted to set the local signing public key multiple times");
	}

	memcpy(local_signing_public_key, public_key, sizeof(local_signing_public_key));
}

uint8_t*
xnu_get_local_signing_public_key(void)
{
	bool key_set = os_atomic_load(&local_signing_key_set, relaxed);

	if (key_set) {
		return local_signing_public_key;
	}

	return NULL;
}

#pragma mark Image4

static uint8_t __attribute__((aligned(8)))
_xnu_image4_storage[IMG4_PMAP_DATA_SIZE_RECOMMENDED] = {0};

void*
xnu_image4_storage_data(
	size_t *allocated_size)
{
	if (allocated_size) {
		*allocated_size = sizeof(_xnu_image4_storage);
	}
	return _xnu_image4_storage;
}

void
xnu_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce)
{
	/*
	 * As a hold over from legacy code, AppleImage4 only ever manages nonces
	 * from the kernel interface through the PMAP_CS runtime. So even though
	 * we don't have a PMAP_CS monitor, we still pass in the PMAP_CS runtime.
	 */

	IMG4_RUNTIME_PMAP_CS->i4rt_set_nonce(
		IMG4_RUNTIME_PMAP_CS,
		ndi,
		nonce);
}

void
xnu_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi)
{
	/*
	 * As a hold over from legacy code, AppleImage4 only ever manages nonces
	 * from the kernel interface through the PMAP_CS runtime. So even though
	 * we don't have a PMAP_CS monitor, we still pass in the PMAP_CS runtime.
	 */

	IMG4_RUNTIME_PMAP_CS->i4rt_roll_nonce(
		IMG4_RUNTIME_PMAP_CS,
		ndi);
}

errno_t
xnu_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out)
{
	errno_t ret = EPERM;

	/*
	 * As a hold over from legacy code, AppleImage4 only ever manages nonces
	 * from the kernel interface through the PMAP_CS runtime. So even though
	 * we don't have a PMAP_CS monitor, we still pass in the PMAP_CS runtime.
	 */

	ret = IMG4_RUNTIME_PMAP_CS->i4rt_copy_nonce(
		IMG4_RUNTIME_PMAP_CS,
		ndi,
		nonce_out);

	if (ret != 0) {
		printf("unable to copy image4 nonce: %llu | %d\n", ndi, ret);
	}

	return ret;
}

errno_t
xnu_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest)
{
	errno_t ret = EPERM;
	const img4_runtime_object_spec_t *obj_spec = NULL;

	obj_spec = image4_get_object_spec_from_index(obj_spec_index);
	if (obj_spec == NULL) {
		return ENOENT;
	}

	/*
	 * As a hold over from legacy code, AppleImage4 only ever executes objects
	 * through the kernel interface through the PMAP_CS runtime. So even though
	 * we don't have a PMAP_CS monitor, we still pass in the PMAP_CS runtime.
	 */

	ret = img4_runtime_execute_object(
		IMG4_RUNTIME_PMAP_CS,
		obj_spec,
		payload,
		manifest);

	if (ret != 0) {
		printf("unable to execute image4 object: %d\n", ret);
	}

	return ret;
}

errno_t
xnu_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length)
{
	errno_t ret = EPERM;
	img4_buff_t object_payload = IMG4_BUFF_INIT;
	size_t object_payload_length = 0;
	const img4_runtime_object_spec_t *obj_spec = NULL;

	obj_spec = image4_get_object_spec_from_index(obj_spec_index);
	if (obj_spec == NULL) {
		return ENOENT;
	}

	/*
	 * The object length is used as an in/out parameter, so we require that this parameter
	 * is used to specify the length of the buffer.
	 */
	object_payload_length = *object_length;

	object_payload.i4b_bytes = (void*)object_out;
	object_payload.i4b_len = object_payload_length;

	/*
	 * As a hold over from legacy code, AppleImage4 only ever copies objects
	 * through the kernel interface through the PMAP_CS runtime. So even though
	 * we don't have a PMAP_CS monitor, we still pass in the PMAP_CS runtime.
	 */

	ret = img4_runtime_copy_object(
		IMG4_RUNTIME_PMAP_CS,
		obj_spec,
		&object_payload,
		&object_payload_length);
	if (ret != 0) {
		printf("unable to copy image4 object: %d\n", ret);
	}

	/* Update the length with what we received from the image4 runtime */
	*object_length = object_payload_length;

	return ret;
}

const void*
xnu_image4_get_monitor_exports(void)
{
	printf("monitor exports not supported without a monitor\n");
	return NULL;
}

errno_t
xnu_image4_set_release_type(
	__unused const char *release_type)
{
	/*
	 * We don't need to inform the monitor about the release type when there
	 * is no monitor environment available.
	 */

	printf("explicit release-type-set not supported without a monitor\n");
	return ENOTSUP;
}

errno_t
xnu_image4_set_bnch_shadow(
	__unused const img4_nonce_domain_index_t ndi)
{
	/*
	 * We don't need to inform the monitor about the BNCH shadow when there
	 * is no monitor environment available.
	 */

	printf("explicit BNCH-shadow-set not supported without a monitor\n");
	return ENOTSUP;
}

#pragma mark Image4 - New

kern_return_t
xnu_image4_transfer_region(
	image4_cs_trap_t selector,
	__unused vm_address_t region_addr,
	__unused vm_size_t region_size)
{
	panic("image4 dispatch: transfer without code signing monitor: %llu", selector);
}

kern_return_t
xnu_image4_reclaim_region(
	image4_cs_trap_t selector,
	__unused vm_address_t region_addr,
	__unused vm_size_t region_size)
{
	panic("image4 dispatch: reclaim without code signing monitor: %llu", selector);
}

errno_t
xnu_image4_monitor_trap(
	image4_cs_trap_t selector,
	__unused const void *input_data,
	__unused size_t input_size)
{
	panic("image4 dispatch: trap without code signing monitor: %llu", selector);
}

#endif /* !CODE_SIGNING_MONITOR */
