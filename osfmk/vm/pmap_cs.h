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

#ifndef _VM_PMAP_CS_H_
#define _VM_PMAP_CS_H_

#ifdef KERNEL_PRIVATE
/*
 * All of PMAP_CS definitions are private and should remain accessible only within XNU
 * and Apple internal kernel extensions.
 */

#include <mach/kern_return.h>
#include <mach/vm_param.h>
#include <mach/vm_types.h>
#include <mach/boolean.h>

#ifdef MACH_KERNEL_PRIVATE
#if defined(__arm64__)
#include <pexpert/arm64/board_config.h>
#endif
#endif


/* To cover situations where we want something on RESEARCH builds as well */


/*
 * All APIs which are relevant for AppleImage4.
 */

#if defined(__arm__) || defined(__arm64__)
#define PMAP_SUPPORTS_IMAGE4_NONCE 1
#define PMAP_SUPPORTS_IMAGE4_OBJECT_EXECUTION 1
#endif

/* These are needed to complete the img4_* types */
#include <img4/firmware.h>
#include <img4/nonce.h>

/**
 * The PPl allocates some space for AppleImage4 to store some of its data. It needs to
 * allocate this space since this region needs to be PPL protected, and the macro which
 * makes a region PPL protected isn't available to kernel extensions.
 *
 * This function can be used to acquire the memory region which is PPL protected.
 */
extern void* pmap_image4_pmap_data(
	size_t *allocated_size);

/**
 * Use the AppleImage4 API to set a nonce value based on a particular nonce index.
 * AppleImage4 ensures that a particular nonce domain value can only be set once
 * during the boot of the system.
 */
extern void pmap_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce);

/**
 * Use the AppleImage4 API to roll the nonce associated with a particular domain to
 * make the nonce invalid.
 */
extern void pmap_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi);

/**
 * Use the AppleImage4 API to copy the nonce value associated with a particular domain.
 *
 * The PPL will attempt to "pin" the nonce_out parameter before writing to it.
 */
extern errno_t pmap_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out);

/**
 * Use the AppleImage4 API to perform object execution of a particular known object type.
 *
 * These are the supported object types:
 * - IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT
 */
extern errno_t pmap_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest);

/**
 * Use the AppleImage4 API to copy an executed objects contents into provided memroy.
 *
 * The PPL will attempt to "pin" the object_out parameter before writing to it.
 */
extern errno_t pmap_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length);

#endif /* KERNEL_PRIVATE */

#endif /* _VM_PMAP_CS_H_ */
