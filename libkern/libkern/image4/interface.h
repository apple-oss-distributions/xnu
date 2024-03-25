/*
 * Copyright © 2017-2024 Apple Inc. All rights reserved.
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
/*!
 * @header
 * Interface structure for the upward-exported AppleImage4 API.
 *
 * This header relies entirely on transitive inclusion from dlxk.h to satisfy
 * its dependencies.
 */
#ifndef __IMAGE4_DLXK_INTERFACE_H
#define __IMAGE4_DLXK_INTERFACE_H

#if !defined(__IMAGE4_XNU_INDIRECT)
#error "Please include <libkern/image4/dlxk.h> instead of this file"
#endif

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma mark Macros
#define image4_xnu_dlxk_type(_s) _image4_ ## _s ## _dlxk_t
#define image4_xnu_dlxk_fld(_s) dlxk_ ## _s
#define image4_xnu_dlxk_fld_decl(_s) \
	image4_xnu_dlxk_type(_s) image4_xnu_dlxk_fld(_s)

#pragma mark Types
typedef struct _image4_dlxk_interface {
	image4_struct_version_t dlxk_version;
	image4_xnu_dlxk_fld_decl(coprocessor_host);
	image4_xnu_dlxk_fld_decl(coprocessor_ap);
	image4_xnu_dlxk_fld_decl(coprocessor_ap_local);
	image4_xnu_dlxk_fld_decl(coprocessor_cryptex1);
	image4_xnu_dlxk_fld_decl(coprocessor_sep);
	image4_xnu_dlxk_fld_decl(coprocessor_x86);
	image4_xnu_dlxk_fld_decl(environment_init);
	image4_xnu_dlxk_fld_decl(environment_new);
	image4_xnu_dlxk_fld_decl(environment_set_secure_boot);
	image4_xnu_dlxk_fld_decl(environment_set_callbacks);
	image4_xnu_dlxk_fld_decl(environment_copy_nonce_digest);
	image4_xnu_dlxk_fld_decl(environment_roll_nonce);
	image4_xnu_dlxk_fld_decl(environment_generate_nonce_proposal);
	image4_xnu_dlxk_fld_decl(environment_commit_nonce_proposal);
	image4_xnu_dlxk_fld_decl(environment_get_nonce_handle);
	image4_xnu_dlxk_fld_decl(environment_destroy);
	image4_xnu_dlxk_fld_decl(trust_init);
	image4_xnu_dlxk_fld_decl(trust_new);
	image4_xnu_dlxk_fld_decl(trust_set_payload);
	image4_xnu_dlxk_fld_decl(trust_set_booter);
	image4_xnu_dlxk_fld_decl(trust_record_property_bool);
	image4_xnu_dlxk_fld_decl(trust_record_property_integer);
	image4_xnu_dlxk_fld_decl(trust_record_property_data);
	image4_xnu_dlxk_fld_decl(trust_evaluate);
	image4_xnu_dlxk_fld_decl(trust_destroy);
	image4_xnu_dlxk_fld_decl(trust_evaluation_exec);
	image4_xnu_dlxk_fld_decl(trust_evaluation_preflight);
	image4_xnu_dlxk_fld_decl(trust_evaluation_sign);
	image4_xnu_dlxk_fld_decl(trust_evaluation_boot);
	image4_xnu_dlxk_fld_decl(cs_trap_resolve_handler);
	image4_xnu_dlxk_fld_decl(cs_trap_vector_size);
} image4_dlxk_interface_t;

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_DLXK_INTERFACE_H
