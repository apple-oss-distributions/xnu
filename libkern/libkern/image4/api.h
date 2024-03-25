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
 * Trampolines for the APIs which are useable by the kernel-proper. These take
 * the form of macros which override the symbol names and redirect them to the
 * interface structure that gets registered at runtime in order to preserve most
 * source compatibility.
 *
 * The exception to this is when referencing API constants. Because API constant
 * macros get indirected through an expression that cannot be evaluated at
 * compile-time, you cannot statically initialize a variable to e.g.
 * IMAGE4_COPROCESSOR_HOST in xnu. Nor can you statically initialize pointers to
 * API functions.
 *
 * This header relies entirely on transitive inclusion from dlxk.h to satisfy
 * its dependencies.
 */
#ifndef __IMAGE4_DLXK_API_H
#define __IMAGE4_DLXK_API_H

#if !defined(__IMAGE4_XNU_INDIRECT)
#error "Please include <libkern/image4/dlxk.h> instead of this file"
#endif


#pragma mark Macros
#define image4_xnu_callable(_f, _v, _rv, ...) ({ \
	const image4_dlxk_interface_t *dlxk = NULL; \
	dlxk = image4_dlxk_get(_v); \
	dlxk ? (dlxk->dlxk_ ## _f(__VA_ARGS__)) : (_rv); \
})

#define image4_xnu_callable_ptr(_f, _v, ...) \
	image4_xnu_callable(_f, _v, NULL, ## __VA_ARGS__)

#define image4_xnu_callable_posix(_f, _v, ...) \
	image4_xnu_callable(_f, _v, ENOSYS, ## __VA_ARGS__)

#define image4_xnu_callable_void(_f, _v, ...) ({ \
	const image4_dlxk_interface_t *dlxk = NULL; \
	dlxk = image4_dlxk_get(_v); \
	if (dlxk) { \
	    dlxk->dlxk_ ## _f(__VA_ARGS__); \
	} \
})

#define image4_xnu_const(_s, _v) ({ \
	const image4_dlxk_interface_t *dlxk = NULL; \
	dlxk = image4_dlxk_get(_v); \
	dlxk ? (dlxk->dlxk_ ## _s) : NULL; \
})

#pragma mark Coprocessors
#undef IMAGE4_COPROCESSOR_HOST
#define IMAGE4_COPROCESSOR_HOST image4_xnu_const(coprocessor_host, 0)

#undef IMAGE4_COPROCESSOR_AP
#define IMAGE4_COPROCESSOR_AP image4_xnu_const(coprocessor_ap, 0)

#undef IMAGE4_COPROCESSOR_AP_LOCAL
#define IMAGE4_COPROCESSOR_AP_LOCAL image4_xnu_const(coprocessor_ap_local, 0)

#undef IMAGE4_COPROCESSOR_CRYPTEX1
#define IMAGE4_COPROCESSOR_CRYPTEX1 image4_xnu_const(coprocessor_cryptex1, 0)

#undef IMAGE4_COPROCESSOR_SEP
#define IMAGE4_COPROCESSOR_SEP image4_xnu_const(coprocessor_sep, 0)

#undef IMAGE4_COPROCESSOR_X86
#define IMAGE4_COPROCESSOR_X86 image4_xnu_const(coprocessor_x86, 0)

#pragma mark Trust Evaluations
#undef IMAGE4_TRUST_EVALUATION_EXEC
#define IMAGE4_TRUST_EVALUATION_EXEC \
	image4_xnu_const(trust_evaluation_exec, 0)

#undef IMAGE4_TRUST_EVALUATION_PREFLIGHT
#define IMAGE4_TRUST_EVALUATION_PREFLIGHT \
	image4_xnu_const(trust_evaluation_preflight, 0)

#undef IMAGE4_TRUST_EVALUATION_SIGN
#define IMAGE4_TRUST_EVALUATION_SIGN \
	image4_xnu_const(trust_evaluation_sign, 0)

#undef IMAGE4_TRUST_EVALUATION_BOOT
#define IMAGE4_TRUST_EVALUATION_BOOT \
	image4_xnu_const(trust_evaluation_boot, 0)

#pragma mark Environment
#define _image4_environment_init(...) \
	image4_xnu_callable_ptr(environment_init, 0, ## __VA_ARGS__)
#define image4_environment_new(...) \
	image4_xnu_callable_ptr(environment_new, 0, ## __VA_ARGS__)
#define image4_environment_set_secure_boot(...) \
	image4_xnu_callable_void(environment_set_secure_boot, 0, ## __VA_ARGS__)
#define image4_environment_set_callbacks(...) \
	image4_xnu_callable_void(environment_set_callbacks, 0, ## __VA_ARGS__)
#define image4_environment_copy_nonce_digest(...) \
	image4_xnu_callable_posix(environment_copy_nonce_digest, 0, ## __VA_ARGS__)
#define image4_environment_roll_nonce(...) \
	image4_xnu_callable_posix(environment_roll_nonce, 0, ## __VA_ARGS__)
#define image4_environment_generate_nonce_proposal(...) \
	image4_xnu_callable_posix(environment_generate_nonce_proposal, \
	    0, ## __VA_ARGS__)
#define image4_environment_commit_nonce_proposal(...) \
	image4_xnu_callable_posix(environment_commit_nonce_proposal, \
	    0, ## __VA_ARGS__)
#define image4_environment_get_nonce_handle(...) \
	image4_xnu_callable_posix(environment_get_nonce_handle, 0, ## __VA_ARGS__)
#define image4_environment_destroy(...) \
	image4_xnu_callable_void(environment_destroy, 0, ## __VA_ARGS__)

#pragma mark Trust
#define _image4_trust_init(...) \
	image4_xnu_callable_ptr(trust_init, 0, ## __VA_ARGS__)
#define image4_trust_new(...) \
	image4_xnu_callable_ptr(trust_new, 0, ## __VA_ARGS__)
#define image4_trust_set_payload(...) \
	image4_xnu_callable_void(trust_set_payload, 0, ## __VA_ARGS__)
#define image4_trust_set_booter(...) \
	image4_xnu_callable_void(trust_set_booter, 0, ## __VA_ARGS__)
#define image4_trust_record_property_bool(...) \
	image4_xnu_callable_void(trust_record_property_bool, 0, ## __VA_ARGS__)
#define image4_trust_record_property_integer(...) \
	image4_xnu_callable_void(trust_record_property_integer, 0, ## __VA_ARGS__)
#define image4_trust_record_property_data(...) \
	image4_xnu_callable_void(trust_record_property_data, 0, ## __VA_ARGS__)
#define image4_trust_evaluate(...) \
	image4_xnu_callable_void(trust_evaluate, 0, ## __VA_ARGS__)
#define image4_trust_destroy(...) \
	image4_xnu_callable_void(trust_destroy, 0, ## __VA_ARGS__)

#pragma mark Kernel-Specific
#define image4_cs_trap_resolve_handler(...) \
	image4_xnu_callable_ptr(cs_trap_resolve_handler, 0, ## __VA_ARGS__)
#define image4_cs_trap_vector_size(...) \
	image4_xnu_callable(cs_trap_vector_size, 0, -1, ## __VA_ARGS__)

#endif // __IMAGE4_DLXK_API_H
