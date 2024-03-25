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
 * Structures and trap handler declarations for use in the kernel's code signing
 * monitor. On targets which have a PPL, these mediate traps between the EL2 and
 * GL2 experts. On targets which have a TXM, these mediate traps from EL2 to
 * GL0, which uses libimage4_TXM and not the kernel implementation.
 */
#ifndef __IMAGE4_CS_TRAPS_H
#define __IMAGE4_CS_TRAPS_H

#include <os/base.h>
#include <stdint.h>
#include <sys/types.h>
#include <image4/image4.h>

#if XNU_KERNEL_PRIVATE
#include <sys/_types/_ssize_t.h>

#if !defined(IMAGE4_DIAGNOSTIC_TRAP_LEVEL)
#if DEBUG || KASAN
#define IMAGE4_DIAGNOSTIC_TRAP_LEVEL 2
#elif DEVELOPMENT
#define IMAGE4_DIAGNOSTIC_TRAP_LEVEL 1
#elif RELEASE
#define IMAGE4_DIAGNOSTIC_TRAP_LEVEL 0
#else
#define IMAGE4_DIAGNOSTIC_TRAP_LEVEL 0
#endif
#endif // !defined(IMAGE4_DIAGNOSTIC_TRAP_LEVEL)
#endif // XNU_KERNEL_PRIVATE

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN
OS_ASSUME_PTR_ABI_SINGLE_BEGIN

/*!
 * @const IMAGE4_CS_API_VERSION
 * The version of the trap API which is supported by the current implementation.
 * Successive versions will only introduce new traps. If a trap's ABI has to
 * change, a new trap will be introduced, and the old one retired.
 */
#define IMAGE4_CS_API_VERSION (0u)

#pragma mark Parameter Attributes
/*!
 * @const __cs_copy
 * The trap vector parameter is fixed-size and should be copied into the
 * supervisor's address space.
 */
#define __cs_copy

/*!
 * @const __cs_xfer
 * The trap vector parameter is a pointer with an associated length, and control
 * of the subject memory should be transferred to the supervisor permanently.
 */
#define __cs_xfer

/*!
 * @const __cs_borrow
 * The trap vector parameter is a pointer with an associated length, and control
 * of the subject memory should be temporarily transferred to the supervisor,
 * being returned at the conclusion of the trap.
 */
#define __cs_borrow

/*!
 * @const __cs_nullable
 * The trap vector parameter is a pointer which may be NULL.
 */
#define __cs_nullable

/*!
 * @const __cs_diagnostic
 * Indicates that the trap vector is for a trap which is only implemented in
 * DEBUG build variants.
 */
#define __cs_diagnostic

#pragma mark Types
/*!
 * @typedef image4_cs_addr_t
 * A type representing an address used in a trap argument vector.
 */
typedef uintptr_t image4_cs_addr_t;

/*!
 * @enum image4_cs_trap_t
 * An enumeration describing all supported traps from the EL2 expert to its
 * code signing supervisor.
 *
 * @const IMAGE4_CS_TRAP_KMOD_SET_RELEASE_TYPE
 * Set the OS release type to inform the availability of the research cryptex
 * nonce. Can only be called once.
 *
 * @const IMAGE4_CS_TRAP_NONCE_SET
 * Sets the active nonce for a nonce domain. Both the cleartext nonce and its
 * encrypted form are set.
 *
 * @const IMAGE4_CS_TRAP_NONCE_ROLL
 * Marks a nonce as rolled such that it new trust evaluations using the nonce
 * will fail. The nonce will be re-generated at the next boot.
 *
 * @const IMAGE4_CS_TRAP_IMAGE_ACTIVATE
 * Activates an image in the GL2 context.
 *
 * @const IMAGE4_CS_TRAP_SET_BOOT_UUID
 * Set the boot session UUID to inform nonce choices for MobileAsset.
 */
OS_CLOSED_ENUM(image4_cs_trap, uint64_t,
	IMAGE4_CS_TRAP_KMOD_SET_RELEASE_TYPE,
	IMAGE4_CS_TRAP_NONCE_SET,
	IMAGE4_CS_TRAP_NONCE_ROLL,
	IMAGE4_CS_TRAP_IMAGE_ACTIVATE,
	IMAGE4_CS_TRAP_KMOD_SET_BOOT_UUID,
	_IMAGE4_CS_TRAP_CNT,
);

/*!
 * @typedef image4_cs_trap_handler_t
 * A handler for a GL2 or GL0 trap.
 *
 * @param csmx
 * The trap code.
 *
 * @param argv
 * The input argument structure.
 *
 * @param argv_len
 * The length of {@link argv}.
 *
 * @param argv_out
 * The output argument structure. Upon successful return, this structure will be
 * populated. Otherwise, the implementation will not modify this memory.
 *
 * @param argv_out_len
 * The length of {@link argv_out}.
 *
 * @result
 * Upon success, zero is returned. Upon failure, a POSIX error code describing
 * the failure condition.
 */
typedef errno_t (*image4_cs_trap_handler_t)(
	image4_cs_trap_t csmx,
	const void *argv,
	size_t argv_len,
	void *_Nullable argv_out,
	size_t *_Nullable argv_out_len
);

/*!
 * @function image4_cs_trap_handler
 * Macro which expands to a function name suitable for a trap handler.
 *
 * @param _el
 * The execution level in which the trap resides.
 *
 * @param _where
 * The subsystem of the trap.
 *
 * @param _which
 * The name of the trap.
 */
#define image4_cs_trap_handler(_el, _where, _which) \
	_image4_ ## _el ## _cs_trap_ ## _where ## _ ## _which

#pragma mark Trap Arguments
#define image4_cs_trap_argv(_which) \
	image4_cs_trap_argv_ ## _which ## _t

#define image4_cs_trap_argv_decl(_which) \
	typedef struct _image4_cs_trap_argv_ ## _which \
			image4_cs_trap_argv(_which); \
	struct __attribute__((packed)) _image4_cs_trap_argv_ ## _which

image4_cs_trap_argv_decl(kmod_set_release_type) {
	char __cs_copy csmx_release_type[64];
};

image4_cs_trap_argv_decl(kmod_set_boot_uuid) {
	uint8_t __cs_copy csmx_uuid[16];
};



image4_cs_trap_argv_decl(nonce_set) {
	uint64_t csmx_handle;
	uint32_t csmx_flags;
	uint8_t __cs_copy csmx_clear[16];
	uint8_t __cs_copy csmx_cipher[16];
};

image4_cs_trap_argv_decl(nonce_roll) {
	uint64_t csmx_handle;
};

image4_cs_trap_argv_decl(image_activate) {
	uint64_t csmx_handle;
	image4_cs_addr_t __cs_xfer csmx_payload;
	uint32_t csmx_payload_len;
	image4_cs_addr_t __cs_xfer csmx_manifest;
	uint32_t csmx_manifest_len;
};

#pragma mark API
/*!
 * @function image4_cs_trap_resolve_handler
 * Resolves a trap code to a handler function.
 *
 * @param trap
 * The trap code to resolve.
 *
 * @result
 * A function pointer corresponding to the entry point for the given trap code.
 * If the given trap is not implemented, NULL is returned.
 */
OS_EXPORT OS_WARN_RESULT
image4_cs_trap_handler_t _Nullable
image4_cs_trap_resolve_handler(image4_cs_trap_t trap);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_cs_trap_resolve_handler);

/*!
 * @function image4_cs_trap_vector_size
 * Returns the expected size of the argument vector for the provided trap.
 *
 * @param trap
 * The trap code for which to obtain the size.
 *
 * @result
 * The size of the argument vector in bytes of the provided trap. If the trap
 * number is invalid or not supported by the implementation, -1 is returned.
 */
OS_EXPORT OS_WARN_RESULT
ssize_t
image4_cs_trap_vector_size(image4_cs_trap_t trap);
IMAGE4_XNU_AVAILABLE_DIRECT(image4_cs_trap_vector_size);

OS_ASSUME_PTR_ABI_SINGLE_END
OS_ASSUME_NONNULL_END
__END_DECLS

#endif // __IMAGE4_CS_TRAPS_H
