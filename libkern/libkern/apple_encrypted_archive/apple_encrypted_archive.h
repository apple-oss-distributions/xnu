/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef __APPLE_ENCRYPTED_ARCHIVE_H
#define __APPLE_ENCRYPTED_ARCHIVE_H

#include <stdint.h>
#include <os/base.h>
#include <sys/cdefs.h>
#include <sys/_types/_ssize_t.h>

/* Callbacks used to write/read data to/from the encrypted stream */
typedef ssize_t (*apple_encrypted_archive_pwrite_proc)(
	void *arg,
	const void *buf,
	size_t nbyte,
	off_t offset);

typedef ssize_t (*apple_encrypted_archive_pread_proc)(
	void *arg,
	void *buf,
	size_t nbyte,
	off_t offset);

/**
 * @abstract Get state size
 *
 * @return State size (bytes)
 */
typedef size_t (*apple_encrypted_archive_get_state_size)(void);

/**
 * @abstract Initialize state
 *
 * @param state Encryption state buffer, \p state_size bytes
 * @param state_size Size allocated in \p state, must be at least apple_encrypted_archive_get_state_size()
 * @param recipient_public_key x9.63 encoded public key, must be on the P256 elliptic curve
 * @param recipient_public_key_size bytes stored in \p public_key (must be 65)
 *
 * @return 0 on success, and a negative error code on failure
 */
typedef int (*apple_encrypted_archive_initialize_state)(
	void *state,
	size_t state_size,
	const uint8_t *recipient_public_key,
	size_t recipient_public_key_size);

/**
 * @abstract Open encryption stream
 *
 * @discussion State must have been initialized with apple_encrypted_archive_initialize_state()
 *
 * @param state Encryption state buffer, \p state_size bytes
 * @param state_size Size allocated in \p state, must be at least apple_encrypted_archive_get_state_size()
 * @param callback_arg Value passed as first argument to the pwrite/pread callbacks
 * @param pwrite_callback Function used to write data to the encrypted stream
 * @param pread_callback Function used to read data from the encrypted stream
 *
 * @return 0 on success, and a negative error code on failure
 */
typedef int (*apple_encrypted_archive_open)(
	void *state,
	size_t state_size,
	void *callback_arg,
	apple_encrypted_archive_pwrite_proc pwrite_callback,
	apple_encrypted_archive_pread_proc pread_callback);

/**
 * @abstract Write data to encryption stream
 *
 * @discussion Stream must have been opened with apple_encrypted_archive_open()
 *
 * @param state Encryption state buffer, \p state_size bytes
 * @param state_size Size allocated in \p state, must be at least apple_encrypted_archive_get_state_size()
 * @param buf Data to write, \p nbyte bytes
 * @param nbyte Number of bytes to write from \p buf
 *
 * @return Number of bytes written on success, and a negative error code on failure
 */
typedef ssize_t (*apple_encrypted_archive_write)(
	void *state,
	size_t state_size,
	const void *buf,
	size_t nbyte);

/**
 * @abstract Close encryption stream
 *
 * @discussion Stream must have been opened with apple_encrypted_archive_open()
 *
 * @param state Encryption state buffer, \p state_size bytes
 * @param state_size Size allocated in \p state, must be at least apple_encrypted_archive_get_state_size()
 *
 * @return 0 on success, and a negative error code on failure
 */
typedef int (*apple_encrypted_archive_close)(
	void *state,
	size_t state_size);

typedef struct _apple_encrypted_archive {
	apple_encrypted_archive_get_state_size   aea_get_state_size;
	apple_encrypted_archive_initialize_state aea_initialize_state;
	apple_encrypted_archive_open             aea_open;
	apple_encrypted_archive_write            aea_write;
	apple_encrypted_archive_close            aea_close;
} apple_encrypted_archive_t;

__BEGIN_DECLS

/**
 * @abstract The AppleEncryptedArchive interface that was registered.
 */
extern const apple_encrypted_archive_t *apple_encrypted_archive;

/**
 * @abstract Registers the AppleEncryptedArchive kext interface for use within the kernel proper.
 *
 * @param aea The interface to register.
 *
 * @discussion
 * This routine may only be called once and must be called before late-const has
 * been applied to kernel memory.
 */
OS_EXPORT OS_NONNULL1
void apple_encrypted_archive_interface_register(const apple_encrypted_archive_t *aea);

#if PRIVATE

typedef void (*registration_callback_t)(void);

void apple_encrypted_archive_interface_set_registration_callback(registration_callback_t callback);

#endif /* PRIVATE */

__END_DECLS

#endif // __APPLE_ENCRYPTED_ARCHIVE_H
