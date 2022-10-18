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
#include <img4/firmware.h>
#include <img4/nonce.h>

__BEGIN_DECLS

#if XNU_KERNEL_PRIVATE
/*
 * Any declarations for types or functions which don't need to be exported to kernel
 * extensions should go here. Naturally, this means this section can also include
 * headers which may not be available to kernel extensions.
 */

#if defined(__arm64__)
#include <pexpert/arm64/board_config.h>
#endif

#include <kern/lock_rw.h>
#include <TrustCache/API.h>


#if PMAP_CS
#define PMAP_CS_INCLUDE_CODE_SIGNING 1
#endif

#if   XNU_MONITOR
#define PMAP_CS_PPL_MONITOR 1
#else
#define PMAP_CS_PPL_MONITOR 0
#endif

#if PMAP_CS_PPL_MONITOR

/*
 * XNU_MONITOR and PMAP_CS are both defined for the same targets in board_config.h.
 * As a result, whenever XNU_MONITOR is defined, so is PMAP_CS. In an ideal world, we
 * can remove the use of PMAP_CS macro and simply use XNU_MONITOR, but that would
 * require a lot of changes throughout the codebase.
 *
 * PMAP_CS_PPL_MONITOR is defined when we have XNU_MONITOR _and_ we explicitly don't
 * have . This effectively means that whenever we have PMAP_CS_PPL_MONITOR,
 * we should also always have PMAP_CS_INCLUDE_CODE_SIGNING. Lets enforce this with a
 * build check.
 */
#if !PMAP_CS_INCLUDE_CODE_SIGNING
#error "PMAP_CS_INCLUDE_CODE_SIGNING not defined when under PMAP_CS_PPL_MONITOR"
#endif

/* Immutable part of the trust cache runtime */
extern TrustCacheRuntime_t ppl_trust_cache_rt;

/* Mutable part of the trust cache runtime */
extern TrustCacheMutableRuntime_t ppl_trust_cache_mut_rt;

/* Lock for the trust cache runtime */
extern lck_rw_t ppl_trust_cache_rt_lock;

typedef struct _pmap_img4_payload {
	/* The trust cache data structure which wraps the payload */
	TrustCache_t trust_cache;

	/* The actual image4 trust cache payload */
	uint8_t img4_payload[0];
} pmap_img4_payload_t;

/* State for whether developer mode has been set or not */
extern bool ppl_developer_mode_set;

/* State of developer mode on the system */
extern bool ppl_developer_mode_storage;

/**
 * Load an image4 trust cache of a particular type into the PPL. If validation succeeds,
 * the payload will remain locked, but the other artifacts will be unlocked. If validation
 * fails, all artifacts will be unlocked.
 *
 * All the lengths passed in will first be rounded up to page-size, so it is expected that
 * the caller allocates page-aligned data.
 *
 * Upon successful validation, the trust cache is added to the runtime maintained by the
 * PPL.
 */
kern_return_t
pmap_load_trust_cache_with_type(
	TCType_t type,
	const vm_address_t pmap_img4_payload, const vm_size_t pmap_img4_payload_len,
	const vm_address_t img4_manifest, const vm_size_t img4_manifest_len,
	const vm_address_t img4_aux_manifest, const vm_size_t img4_aux_manifest_len);

/*
 * Query a trust cache from within the PPL. This function can only be called when within
 * the PPL and does not pin the query_token passed in.
 */
kern_return_t
pmap_query_trust_cache_safe(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token);

/**
 * Query a trust cache of a particular type from the PPL. The query_token passed in will
 * be pinned by the PPL runtime when the PPL is attempting to write to it. This is an API
 * which can be used for callers external to the PPL.
 */
kern_return_t
pmap_query_trust_cache(
	TCQueryType_t query_type,
	const uint8_t cdhash[kTCEntryHashSize],
	TrustCacheQueryToken_t *query_token);

/**
 * Toggle the state of developer mode on the system. This function can only be called with
 * a true value once in the lifecycle of a boot.
 *
 * Until this function is called once to set the state, the PPL will block non-platform
 * code and JIT on the system.
 */
void
pmap_toggle_developer_mode(
	bool state);

#endif /* PMAP_CS_PPL_MONITOR */

#if PMAP_CS_INCLUDE_CODE_SIGNING

#define CORE_ENTITLEMENTS_I_KNOW_WHAT_IM_DOING

#include <CoreEntitlements/CoreEntitlementsPriv.h>
#include <kern/cs_blobs.h>
#include <libkern/tree.h>
#include <libkern/crypto/sha1.h>
#include <libkern/crypto/sha2.h>
#include <libkern/coretrust/coretrust.h>

/* Validation data for a provisioning profile */
typedef struct _pmap_cs_profile {
	/*
	 * The PPL uses the physical aperture mapping to write to this structure. But
	 * we need to save a pointer to the original mapping for when we are going to
	 * unregister this profile from the PPL.
	 */
	void *original_payload;

	/* A CoreEntitlements context for querying the profile */
	der_vm_context_t profile_ctx_storage;
	const der_vm_context_t *profile_ctx;

	/*
	 * Critical information regarding the profile. If a profile has not been verified,
	 * it cannot be associated with a code signature. Development profiles are only
	 * allowed under certain circumstances.
	 */
	bool profile_validated;
	bool development_profile;

	/*
	 * Reference count for the number of code signatures which are currently using
	 * this provisioning profile for their constraint validation.
	 */
	uint32_t reference_count;

	/*
	 * The list of entitlements which are provisioned by this provisioning profile.
	 * If this list allows the debuggee entitlements, then this profile is considered
	 * a development profile.
	 */
	struct CEQueryContext entitlements_ctx_storage;
	struct CEQueryContext *entitlements_ctx;

	/* Red-black tree linkage */
	RB_ENTRY(_pmap_cs_profile) link;
} pmap_cs_profile_t;

/* This is how we expect the kernel to hand us provisioning profiles */
typedef struct _pmap_profile_payload {
	/* Storage for the provisioning profile */
	pmap_cs_profile_t profile_obj_storage;

	/* Size of the signed profile blob */
	vm_size_t profile_blob_size;

	/* The signed profile blob itself */
	uint8_t profile_blob[0];
} pmap_profile_payload_t;

/* Trust levels are ordered, i.e. higher is more trust */
typedef enum {
	PMAP_CS_UNTRUSTED = 0,

	/*
	 * Trust level given to code directory entries which have been retired and are
	 * no longer valid to be used for any purpose. These code directores are freed
	 * when their reference count touches 0.
	 */
	PMAP_CS_RETIRED,

	/*
	 * This trust level signifies that an application has been verified through the
	 * profile based certificate chain, but the profile in question itself has not
	 * been verified. Code directories with this trust aren't allowed to be run
	 * or mapped.
	 */
	PMAP_CS_PROFILE_PREFLIGHT,

	/*
	 * Signatures provided through the compilation service. These signatures are meant
	 * to only apply to loadable libraries, and therefore have the lowest acceptable trust.
	 */
	PMAP_CS_COMPILATION_SERVICE,

	/*
	 * Signature for out-of-process JIT. These can only be loaded by an entitled process
	 * and have a special library validation policy for being mapped within other processes.
	 * These represent a safer version of JIT.
	 */
	PMAP_CS_OOP_JIT,

	/*
	 * These signatures are those which are trusted because they have been signed by the
	 * device local signing key.
	 */
	PMAP_CS_LOCAL_SIGNING,

	/*
	 * These signatures belong to applications which are profile validated, and for those
	 * whose profiles have also been verified.
	 */
	PMAP_CS_PROFILE_VALIDATED,

	/*
	 * These signatures are those belonging to the app store.
	 */
	PMAP_CS_APP_STORE,

#if PMAP_CS_INCLUDE_INTERNAL_CODE
	/*
	 * Engineering roots which are still Apple signed. These don't need to be platform
	 * because they are backed by a CMS signature and therefore would've never been
	 * platform anyways.
	 */
	PMAP_CS_ENGINEERING_SIGNED_WITH_CMS,
#endif

	/*
	 * These signatures represent platform binaries which have the highest trust level.
	 */
	PMAP_CS_IN_LOADED_TRUST_CACHE,
	PMAP_CS_IN_STATIC_TRUST_CACHE,

#if PMAP_CS_INCLUDE_INTERNAL_CODE
	/*
	 * Engineering roots installed by engineers for development. These are given the
	 * highest trust level.
	 */
	PMAP_CS_ENGINEERING_SIGNED,
#endif
} pmap_cs_trust_t;

/* Everything with greater or equal trust is a platform binary */
#define PMAP_CS_LOWEST_PLATFORM_BINARY_TRUST PMAP_CS_IN_LOADED_TRUST_CACHE

/* Minimum trust level of a code signature to be run/mapped */
#define PMAP_CS_LOWEST_ACCEPTABLE_TRUST PMAP_CS_COMPILATION_SERVICE

typedef struct pmap_cs_code_directory {
	union {
		struct {
			/* red-black tree linkage */
			RB_ENTRY(pmap_cs_code_directory) link;

			/*
			 * Blobs which are small enough are allocated and managed by the PPL. This field
			 * is NULL for large blobs.
			 */
			struct pmap_cs_blob *managed_blob;
			bool managed;

			/*
			 * The superblob of the code signature. The length we store here is the length of the
			 * memory allocated by the kernel itself, which may be greater than the actual length
			 * of the code signature.
			 */
			CS_SuperBlob *superblob;
			vm_size_t superblob_size;
			bool superblob_validated;

			/*
			 * Code directories can be arbitrarily large, and hashing them can take a long time. We
			 * usually hash code directories in a continuable way, yielding our execution context
			 * after hashing some amount of the bytes.
			 */
			union {
				SHA384_CTX sha384_ctx;
				SHA256_CTX sha256_ctx;
				SHA1_CTX sha1_ctx;
			};
			uint32_t cd_length_hashed;

			/*
			 * The best code directory is just an offset away from the superblob. This code directory
			 * is extensively validated for all of its fields.
			 */
			const CS_CodeDirectory *cd;
			bool cd_offset_matched;

			/*
			 * The first code directory is used when validating the CMS blob attached to a code signature
			 * and is often not the best code directory.
			 */
			bool first_cd_initialized;
			bool first_cd_hashed;
			uint8_t first_cdhash[CS_HASH_MAX_SIZE];
			const uint8_t *first_cd;
			size_t first_cd_length;
			const uint8_t *cms_blob;
			size_t cms_blob_length;
			CoreTrustDigestType ct_digest_type;

			/*
			 * Frequently accessed information from the code directory kept here as a cache.
			 */
			const char *identifier;
			const char *teamid;
			bool main_binary;

			/*
			 * The DER entitlements blob and CoreEntitlements context for querying this code
			 * signature for entitlements.
			 */
			struct CEQueryContext core_entitlements_ctx;
			struct CEQueryContext *ce_ctx;
			const CS_GenericBlob *der_entitlements;
			uint32_t der_entitlements_size;

			/*
			 * This is parhaps the most important field in this structure. It signifies what
			 * level of confidence we have in this code directory and this trust level
			 * defines execution/mapping policies for this code directory.
			 */
			pmap_cs_trust_t trust;

			/*
			 * Reference count of how many regions this code directory is associated with through
			 * pmap_cs_associate.
			 */
			uint32_t reference_count;

			/*
			 * We maintain this field as it allows us to quickly index into a bucket of supported
			 * hash types, and choose the correct hashing algorithm for this code directory.
			 */
			unsigned int hash_type;

			/* Lock on this code directory */
			decl_lck_rw_data(, rwlock);

			/*
			 * The PPL may transform the code directory (e.g. for multilevel hashing),
			 * which changes its cdhash. We retain the cdhash of the original, canonical
			 * code directory here.
			 */
			uint8_t cdhash[CS_CDHASH_LEN];

			/*
			 * For performing provisioning profile validation in the PPL, we store the profile as
			 * PPL owned data so it cannot be changed during the validation time period.
			 *
			 * This interface for profile validation is deprecated.
			 */
			struct {
				/* The provisioning profile and its size */
				const uint8_t *profile;
				vm_size_t profile_size;

				/* Size of memory allocated to hold the profile */
				vm_size_t allocation_size;
			} profile_data;

			/*
			 * The provisioning profile object used for validating constrainst for profile validates
			 * signatures. This is the newer interface the PPL uses.
			 */
			pmap_cs_profile_t *profile_obj;

			/*
			 * The leaf certificate for CMS blobs as returned to us by CoreTrust. This is used when
			 * verifying a signature against a provisioning profile.
			 */
			const uint8_t *cms_leaf;
			vm_size_t cms_leaf_size;

			/*
			 * The UBC layer may request the PPL to unlock the unneeded part of the code signature.
			 * We hold this boolean to track whether we have unlocked those unneeded bits already or
			 * not.
			 */
			bool unneeded_code_signature_unlocked;
		};

		/* Free list linkage */
		struct pmap_cs_code_directory *pmap_cs_code_directory_next;
	};
} pmap_cs_code_directory_t;

/**
 * Initialize the red-black tree and the locks for managing provisioning profiles within
 * the PPL.
 *
 * This function doesn't trap into the PPL but writes to PPL protected data. Hence, this
 * function needs to be called before the PPL is locked down, asn otherwise it will cause
 * a system panic.
 */
void
pmap_initialize_provisioning_profiles(void);

/**
 * Register a provisioning profile with the PPL. The payload address and size are both
 * expected to be page aligned. The PPL will attempt to lockdown the address range before
 * the profile validation.
 *
 * After validation, the profile will be added to an internal red-black tree, allowing
 * the PPL to safely enumerate all registered profiles.
 */
kern_return_t
pmap_register_provisioning_profile(
	const vm_address_t payload_addr,
	const vm_size_t payload_size);

/**
 * Unregister a provisioning profile from the PPL. The payload which was registered is
 * unlocked, and the caller is free to do whatever they want with it. Unregistration is
 * only successful when there are no reference counts on the profile object.
 */
kern_return_t
pmap_unregister_provisioning_profile(
	pmap_cs_profile_t *profile_obj);

/**
 * Associate a PPL profile object with a PPL code signature object. A code signature
 * object can only have a single profile associated with it, and a successful association
 * increments the reference count on the profile object.
 */
kern_return_t
pmap_associate_provisioning_profile(
	pmap_cs_code_directory_t *cd_entry,
	pmap_cs_profile_t *profile_obj);

/**
 * Disassociate a PPL profile object from a PPL code signature object. Disassociation
 * through this code path is only successful when the code signature object has been
 * verified.
 *
 * This decrements the reference count on the profile object, potentially allowing it
 * to be unregistered if the reference count hits zero.
 */
kern_return_t
pmap_disassociate_provisioning_profile(
	pmap_cs_code_directory_t *cd_entry);

#endif /* PMAP_CS_INCLUDE_CODE_SIGNING */

#endif /* XNU_KERNEL_PRIVATE */

/* Availability macros for AppleImage4 */
#if defined(__arm__) || defined(__arm64__)
#define PMAP_SUPPORTS_IMAGE4_NONCE 1
#define PMAP_SUPPORTS_IMAGE4_OBJECT_EXECUTION 1
#endif

/* Availability macros for developer mode */
#define PMAP_SUPPORTS_DEVELOPER_MODE 1

/**
 * The PPl allocates some space for AppleImage4 to store some of its data. It needs to
 * allocate this space since this region needs to be PPL protected, and the macro which
 * makes a region PPL protected isn't available to kernel extensions.
 *
 * This function can be used to acquire the memory region which is PPL protected.
 */
void*
pmap_image4_pmap_data(
	size_t *allocated_size);

/**
 * Use the AppleImage4 API to set a nonce value based on a particular nonce index.
 * AppleImage4 ensures that a particular nonce domain value can only be set once
 * during the boot of the system.
 */
void
pmap_image4_set_nonce(
	const img4_nonce_domain_index_t ndi,
	const img4_nonce_t *nonce);

/**
 * Use the AppleImage4 API to roll the nonce associated with a particular domain to
 * make the nonce invalid.
 */
void
pmap_image4_roll_nonce(
	const img4_nonce_domain_index_t ndi);

/**
 * Use the AppleImage4 API to copy the nonce value associated with a particular domain.
 *
 * The PPL will attempt to "pin" the nonce_out parameter before writing to it.
 */
errno_t
pmap_image4_copy_nonce(
	const img4_nonce_domain_index_t ndi,
	img4_nonce_t *nonce_out);

/**
 * Use the AppleImage4 API to perform object execution of a particular known object type.
 *
 * These are the supported object types:
 * - IMG4_RUNTIME_OBJECT_SPEC_INDEX_SUPPLEMENTAL_ROOT
 */
errno_t
pmap_image4_execute_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	const img4_buff_t *payload,
	const img4_buff_t *manifest);

/**
 * Use the AppleImage4 API to copy an executed objects contents into provided memroy.
 *
 * The PPL will attempt to "pin" the object_out parameter before writing to it.
 */
errno_t
pmap_image4_copy_object(
	img4_runtime_object_spec_index_t obj_spec_index,
	vm_address_t object_out,
	size_t *object_length);

__END_DECLS

#endif /* KERNEL_PRIVATE */
#endif /* _VM_PMAP_CS_H_ */
