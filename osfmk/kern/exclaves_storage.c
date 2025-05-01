/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#if __has_include(<Tightbeam/tightbeam.h>)

#include <stdint.h>
#include <vm/pmap.h>

#include <Tightbeam/tightbeam.h>
#include <Tightbeam/tightbeam_private.h>

#include <mach/exclaves.h>
#include <sys/errno.h>
#include <vfs/vfs_exclave_fs.h>
#include <kern/kalloc.h>

#include "kern/exclaves.tightbeam.h"
#include "exclaves_debug.h"
#include "exclaves_storage.h"
#include "exclaves_boot.h"

#define STORAGE_EXCLAVE_BUF_SIZE (4 * 1024 * 1024)

static int
verify_string_length(const char *str, size_t size)
{
	return (strnlen(str, size) < size) ? 0 : ERANGE;
}

static int
verify_storage_buf_offset(uint64_t buf, uint64_t length)
{
	uint64_t off;
	if (__builtin_add_overflow(buf, length, &off)) {
		return ERANGE;
	}

	if (off > STORAGE_EXCLAVE_BUF_SIZE) {
		return ERANGE;
	}

	return 0;
}

static int
consolidate_storage_error(int error)
{
	switch (error) {
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_PERMISSIONDENIED:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_NOSUCHFILE:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_IOERROR:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_OUTOFMEMORY:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_ACCESSERROR:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_FILEEXISTS:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_NOTADIRECTORY:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_ISADIRECTORY:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_INVALIDARG:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_NOSPACELEFT:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_READONLYFILESYSTEM:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_RESULTTOOLARGE:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_RESOURCETEMPORARILYUNAVAILABLE:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_NOTSUPPORTED:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_BUFFERTOOSMALL:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_NAMETOOLONG:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_STALEFILEHANDLE:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_AUTHENTICATIONERROR:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_VALUETOOSMALL:
	case XNUUPCALLSV2_STORAGEUPCALLSERROR_INTERNALERROR:
		return error;
	default:
		return XNUUPCALLSV2_STORAGEUPCALLSERROR_UNKNOWN;
	}
}

/* -------------------------------------------------------------------------- */
#pragma mark Upcalls

/* Legacy upcall handlers */

tb_error_t
exclaves_storage_upcall_legacy_root(const uint8_t exclaveid[_Nonnull 32],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_root__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] root %s\n", exclaveid);

	int error;
	uint64_t rootid;
	xnuupcalls_xnuupcalls_root__result_s result = {};

	if ((error = verify_string_length((const char *)&exclaveid[0], 32))) {
		xnuupcalls_xnuupcalls_root__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_root((const char *)&exclaveid[0], &rootid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_root failed with %d\n",
		    error);
		xnuupcalls_xnuupcalls_root__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_root return "
		    "rootId %lld\n", rootid);
		xnuupcalls_xnuupcalls_root__result_init_success(&result, rootid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_open(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_open__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "open %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcalls_xnuupcalls_open__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_open__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_open((uint32_t)fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_open failed with %d\n",
		    error);
		xnuupcalls_xnuupcalls_open__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_open return "
		    "fileId %lld\n", fileid);
		xnuupcalls_xnuupcalls_open__result_init_success(&result, fileid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_close(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, tb_error_t (^completion)(xnuupcalls_xnuupcalls_close__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "close %d %lld\n", fstag, fileid);
	int error;
	xnuupcalls_xnuupcalls_close__result_s result = {};

	error = vfs_exclave_fs_close((uint32_t)fstag, fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_close failed with "
		    "%d\n", error);
		xnuupcalls_xnuupcalls_close__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_close succeeded\n");
		xnuupcalls_xnuupcalls_close__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_create(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_create__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server]"
	    " create %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcalls_xnuupcalls_create__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_create__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_create((uint32_t)fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_create failed with"
		    " %d\n", error);
		xnuupcalls_xnuupcalls_create__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_create return "
		    "fileId %lld\n", fileid);
		xnuupcalls_xnuupcalls_create__result_init_success(&result, fileid);
	}

	return completion(result);
}

// Borrowed from bsd_init.c
extern bool bsd_rooted_ramdisk(void);

static bool
is_restore(void)
{
	bool is_restore = false;
	(void) PE_parse_boot_argn("-restore", &is_restore, sizeof(is_restore));
	return is_restore;
}

static bool
dt_string_is_equal(DTEntry *entry, const char *name, const char *str)
{
	const void       *value;
	unsigned         size;
	size_t           str_size;

	str_size = strlen(str) + 1;
	return entry != NULL &&
	       SecureDTGetProperty(*entry, name, &value, &size) == kSuccess &&
	       value != NULL &&
	       size == str_size &&
	       strncmp(str, value, str_size) == 0;
}

static bool
is_recovery_environment(void)
{
	DTEntry chosen;

#if defined(XNU_TARGET_OS_OSX)
	const char * environment = "recoveryos";
#else
	const char * environment = "recovery";
#endif

	return SecureDTLookupEntry(0, "/chosen", &chosen) == kSuccess &&
	       dt_string_is_equal(&chosen, "osenvironment", environment);
}

static char *storage_buffer = NULL;

static kern_return_t
exclaves_storage_init(void)
{
	const char *v2_seg_name = "com.apple.storage.backend";
	exclaves_resource_t *storage_resource = NULL;

	kern_return_t kr = exclaves_resource_shared_memory_map(
		EXCLAVES_DOMAIN_KERNEL, v2_seg_name,
		STORAGE_EXCLAVE_BUF_SIZE,
		EXCLAVES_BUFFER_PERM_WRITE,
		&storage_resource);

	if (kr == KERN_SUCCESS) {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls] Using SharedMemory V2 segment for IO");
		storage_buffer =
		    exclaves_resource_shared_memory_get_buffer(storage_resource,
		    NULL);
		return kr;
	}

	if (kr != KERN_NOT_FOUND) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] Cannot map shared memory segment '%s': failed with %d\n",
		    v2_seg_name, kr);
	}

	if (is_restore() || bsd_rooted_ramdisk() || is_recovery_environment() ||
	    exclaves_requirement_is_relaxed(EXCLAVES_R_STORAGE)) {
		// Set the relaxed bit so the rest of the system can know that
		// it's expected that storage is not available.
		exclaves_requirement_relax(EXCLAVES_R_STORAGE);

		// Don't fail boot here. Fail the upcalls that try to use the
		// storage buffer instead.
		storage_resource = NULL;
		kr = KERN_SUCCESS;
	}

	return kr;
}
EXCLAVES_BOOT_TASK(exclaves_storage_init, EXCLAVES_BOOT_RANK_SECOND);

tb_error_t
exclaves_storage_upcall_legacy_read(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_read__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "read %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->buf,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcalls_xnuupcalls_read__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcalls_xnuupcalls_read__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	error = verify_storage_buf_offset(descriptor->buf, descriptor->length);
	if (error != 0) {
		xnuupcalls_xnuupcalls_read__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	error = vfs_exclave_fs_read((uint32_t)fstag, fileid,
	    descriptor->fileoffset, descriptor->length,
	    storage_buffer + descriptor->buf);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "read %d %lld %lld %lld %lld failed with errno %d",
		    fstag, fileid, descriptor->buf,
		    descriptor->fileoffset, descriptor->length, error);
		xnuupcalls_xnuupcalls_read__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_read succeeded\n");
		xnuupcalls_xnuupcalls_read__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_write(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_write__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "write %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->buf,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcalls_xnuupcalls_write__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcalls_xnuupcalls_write__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	error = verify_storage_buf_offset(descriptor->buf, descriptor->length);
	if (error != 0) {
		xnuupcalls_xnuupcalls_write__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	error = vfs_exclave_fs_write((uint32_t)fstag, fileid,
	    descriptor->fileoffset, descriptor->length,
	    storage_buffer + descriptor->buf);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "write %d %lld %lld %lld %lld failed with errno %d\n",
		    fstag, fileid, descriptor->buf, descriptor->fileoffset,
		    descriptor->length, error);
		xnuupcalls_xnuupcalls_write__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_write succeeded\n");
		xnuupcalls_xnuupcalls_write__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_remove(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_remove__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "remove %d %lld %s\n", fstag, rootid, name);
	int error;
	xnuupcalls_xnuupcalls_remove__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_remove__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_remove((uint32_t)fstag, rootid,
	    (const char *)&name[0]);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_remove failed with "
		    "%d\n", error);
		xnuupcalls_xnuupcalls_remove__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_remove succeeded\n");
		xnuupcalls_xnuupcalls_remove__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_sync(const enum xnuupcalls_fstag_s fstag,
    const enum xnuupcalls_syncop_s op,
    const uint64_t fileid, tb_error_t (^completion)(xnuupcalls_xnuupcalls_sync__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "sync %d %lld %d\n", fstag, fileid, (int)op);
	int error;
	xnuupcalls_xnuupcalls_sync__result_s result = {};

	error = vfs_exclave_fs_sync((uint32_t)fstag, fileid, op);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_sync failed with %d\n",
		    error);
		xnuupcalls_xnuupcalls_sync__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_sync succeeded\n");
		xnuupcalls_xnuupcalls_sync__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_readdir(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const uint64_t buf,
    const uint32_t length, tb_error_t (^completion)(xnuupcalls_xnuupcalls_readdir__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] readdir %d %lld %lld %d\n",
	    fstag, fileid, buf, length);
	int error;
	int32_t count;

	xnuupcalls_xnuupcalls_readdir__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcalls_xnuupcalls_readdir__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	if ((error = verify_storage_buf_offset(buf, length))) {
		xnuupcalls_xnuupcalls_readdir__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	error = vfs_exclave_fs_readdir((uint32_t)fstag, fileid,
	    storage_buffer, length, &count);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "vfs_exclave_fs_readdir %d %lld %lld %d failed with errno %d\n",
		    fstag, fileid, buf, length, error);
		xnuupcalls_xnuupcalls_readdir__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] readdir succeeded\n");
	xnuupcalls_xnuupcalls_readdir__result_init_success(&result, count);

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_getsize(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_getsize__result_s result))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] getsize %d %lld\n",
	    fstag, fileid);
	int error;
	uint64_t size;
	xnuupcalls_xnuupcalls_getsize__result_s result = {};

	error = vfs_exclave_fs_getsize((uint32_t)fstag, fileid, &size);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_getsize(%d, %lld) "
		    "failed with %d\n", fstag, fileid, error);
		xnuupcalls_xnuupcalls_getsize__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_getsize succeeded\n");
		xnuupcalls_xnuupcalls_getsize__result_init_success(&result, size);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_legacy_sealstate(const enum xnuupcalls_fstag_s fstag,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_sealstate__result_s result))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] sealstate %d\n",
	    fstag);
	int error;
	bool sealed;
	xnuupcalls_xnuupcalls_sealstate__result_s result = {};

	error = vfs_exclave_fs_sealstate((uint32_t)fstag, &sealed);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_sealstate(%d) "
		    "failed with %d\n", fstag, error);
		xnuupcalls_xnuupcalls_sealstate__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_sealstate succeeded\n");
		xnuupcalls_xnuupcalls_sealstate__result_init_success(&result, sealed);
	}

	return completion(result);
}

/* Upcall handlers */

tb_error_t
exclaves_storage_upcall_root(const uint8_t exclaveid[_Nonnull 32],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_root__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] root %s\n", exclaveid);

	int error;
	uint64_t rootid;
	xnuupcallsv2_storageupcallsprivate_root__result_s result = {};

	if ((error = verify_string_length((const char *)&exclaveid[0], 32))) {
		xnuupcallsv2_storageupcallsprivate_root__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_root((const char *)&exclaveid[0], &rootid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_root failed with %d\n",
		    error);
		xnuupcallsv2_storageupcallsprivate_root__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_root return "
		    "rootId %lld\n", rootid);
		xnuupcallsv2_storageupcallsprivate_root__result_init_success(&result, rootid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_rootex(const uint32_t fstag,
    const uint8_t exclaveid[_Nonnull 32],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_rootex__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] rootex tag %u exclaveid %s\n", fstag, exclaveid);

	int error;
	uint64_t rootid;
	xnuupcallsv2_storageupcallsprivate_rootex__result_s result = {};

	if ((error = verify_string_length((const char *)&exclaveid[0], 32))) {
		xnuupcallsv2_storageupcallsprivate_rootex__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_root_ex(fstag, (const char *)&exclaveid[0], &rootid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_rootex failed with %d\n",
		    error);
		xnuupcallsv2_storageupcallsprivate_rootex__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_rootex return "
		    "rootId %lld\n", rootid);
		xnuupcallsv2_storageupcallsprivate_rootex__result_init_success(&result, rootid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_open(const uint32_t fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_open__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "open %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcallsv2_storageupcallsprivate_open__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcallsv2_storageupcallsprivate_open__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_open(fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_open failed with %d\n",
		    error);
		xnuupcallsv2_storageupcallsprivate_open__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_open return "
		    "fileId %lld\n", fileid);
		xnuupcallsv2_storageupcallsprivate_open__result_init_success(&result, fileid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_close(const uint32_t fstag,
    const uint64_t fileid, tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_close__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "close %d %lld\n", fstag, fileid);
	int error;
	xnuupcallsv2_storageupcallsprivate_close__result_s result = {};

	error = vfs_exclave_fs_close(fstag, fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_close failed with "
		    "%d\n", error);
		xnuupcallsv2_storageupcallsprivate_close__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_close succeeded\n");
		xnuupcallsv2_storageupcallsprivate_close__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_create(const uint32_t fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_create__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server]"
	    " create %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcallsv2_storageupcallsprivate_create__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcallsv2_storageupcallsprivate_create__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_create(fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_create failed with"
		    " %d\n", error);
		xnuupcallsv2_storageupcallsprivate_create__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_create return "
		    "fileId %lld\n", fileid);
		xnuupcallsv2_storageupcallsprivate_create__result_init_success(&result, fileid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_read(const uint32_t fstag,
    const uint64_t fileid, const struct xnuupcallsv2_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_read__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "read %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->bufferoffset,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcallsv2_storageupcallsprivate_read__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcallsv2_storageupcallsprivate_read__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	error = verify_storage_buf_offset(descriptor->bufferoffset, descriptor->length);
	if (error != 0) {
		xnuupcallsv2_storageupcallsprivate_read__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	error = vfs_exclave_fs_read((uint32_t)fstag, fileid,
	    descriptor->fileoffset, descriptor->length,
	    storage_buffer + descriptor->bufferoffset);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "read %d %lld %lld %lld %lld failed with errno %d",
		    fstag, fileid, descriptor->bufferoffset,
		    descriptor->fileoffset, descriptor->length, error);
		xnuupcallsv2_storageupcallsprivate_read__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_read succeeded\n");
		xnuupcallsv2_storageupcallsprivate_read__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_write(const uint32_t fstag,
    const uint64_t fileid, const struct xnuupcallsv2_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_write__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "write %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->bufferoffset,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcallsv2_storageupcallsprivate_write__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcallsv2_storageupcallsprivate_write__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	error = verify_storage_buf_offset(descriptor->bufferoffset, descriptor->length);
	if (error != 0) {
		xnuupcallsv2_storageupcallsprivate_write__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}


	error = vfs_exclave_fs_write((uint32_t)fstag, fileid,
	    descriptor->fileoffset, descriptor->length,
	    storage_buffer + descriptor->bufferoffset);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "write %d %lld %lld %lld %lld failed with errno %d\n",
		    fstag, fileid, descriptor->bufferoffset, descriptor->fileoffset,
		    descriptor->length, error);
		xnuupcallsv2_storageupcallsprivate_write__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_write succeeded\n");
		xnuupcallsv2_storageupcallsprivate_write__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_remove(const uint32_t fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_remove__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "remove %d %lld %s\n", fstag, rootid, name);
	int error;
	xnuupcallsv2_storageupcallsprivate_remove__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcallsv2_storageupcallsprivate_remove__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}
	error = vfs_exclave_fs_remove(fstag, rootid,
	    (const char *)&name[0]);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_remove failed with "
		    "%d\n", error);
		xnuupcallsv2_storageupcallsprivate_remove__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_remove succeeded\n");
		xnuupcallsv2_storageupcallsprivate_remove__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_sync(const uint32_t fstag,
    const xnuupcallsv2_syncop_s *op,
    const uint64_t fileid, tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_sync__result_s))
{
	int error;
	uint64_t _op;
	xnuupcallsv2_storageupcallsprivate_sync__result_s result = {};

	switch (op->tag) {
	case XNUUPCALLSV2_SYNCOP__BARRIER:
		_op = EXCLAVE_FS_SYNC_OP_BARRIER;
		break;
	case XNUUPCALLSV2_SYNCOP__FULL:
		_op = EXCLAVE_FS_SYNC_OP_FULL;
		break;
	case XNUUPCALLSV2_SYNCOP__UBC:
		_op = EXCLAVE_FS_SYNC_OP_UBC;
		break;
	default:
		// unknown op, set to selector value for debug
		_op = op->tag;
	}

	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "sync %d %lld %llu\n", fstag, fileid, _op);

	error = vfs_exclave_fs_sync(fstag, fileid, _op);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_sync (op: %llu) failed with %d\n",
		    _op, error);
		xnuupcallsv2_storageupcallsprivate_sync__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_sync succeeded\n");
		xnuupcallsv2_storageupcallsprivate_sync__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_readdir(const uint32_t fstag,
    const uint64_t fileid, const uint64_t buf,
    const uint32_t length, tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_readdir__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] readdir %d %lld %lld %d\n",
	    fstag, fileid, buf, length);
	int error;
	int32_t count;

	xnuupcallsv2_storageupcallsprivate_readdir__result_s result = {};

	if (!storage_buffer) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] shared memory buffer not initialized\n");
		xnuupcallsv2_storageupcallsprivate_readdir__result_init_failure(&result, ENOMEM);
		return completion(result);
	}

	if ((error = verify_storage_buf_offset(buf, length))) {
		xnuupcallsv2_storageupcallsprivate_readdir__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	error = vfs_exclave_fs_readdir((uint32_t)fstag, fileid, storage_buffer,
	    length, &count);
	if (error) {
		exclaves_debug_printf(show_errors, "[storage_upcalls_server] "
		    "vfs_exclave_fs_readdir %d %lld %lld %d failed with errno %d\n",
		    fstag, fileid, buf, length, error);
		xnuupcallsv2_storageupcallsprivate_readdir__result_init_failure(&result, consolidate_storage_error(error));
		return completion(result);
	}

	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] readdir succeeded\n");
	xnuupcallsv2_storageupcallsprivate_readdir__result_init_success(&result, count);

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_getsize(const uint32_t fstag,
    const uint64_t fileid,
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_getsize__result_s result))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] getsize %d %lld\n",
	    fstag, fileid);
	int error;
	uint64_t size;
	xnuupcallsv2_storageupcallsprivate_getsize__result_s result = {};

	error = vfs_exclave_fs_getsize(fstag, fileid, &size);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_getsize(%d, %lld) "
		    "failed with %d\n", fstag, fileid, error);
		xnuupcallsv2_storageupcallsprivate_getsize__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_getsize succeeded\n");
		xnuupcallsv2_storageupcallsprivate_getsize__result_init_success(&result, size);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_sealstate(const uint32_t fstag,
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_sealstate__result_s result))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] sealstate %d\n",
	    fstag);
	int error;
	bool sealed;
	xnuupcallsv2_storageupcallsprivate_sealstate__result_s result = {};

	error = vfs_exclave_fs_sealstate(fstag, &sealed);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_sealstate(%d) "
		    "failed with %d\n", fstag, error);
		xnuupcallsv2_storageupcallsprivate_sealstate__result_init_failure(&result, consolidate_storage_error(error));
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_sealstate succeeded\n");
		xnuupcallsv2_storageupcallsprivate_sealstate__result_init_success(&result, sealed);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_queryvolumegroup(const uint8_t vguuid[_Nonnull 37],
    tb_error_t (^completion)(xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] queryvolumegroup exclaveid %s\n", vguuid);

	int error;
	bool exists;
	xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_s result = {};

	if ((error = verify_string_length((const char *)vguuid, 37))) {
		xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_query_volume_group((const char *)&vguuid[0], &exists);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_queryvolumegroup failed with %d\n",
		    error);
		xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_queryvolumegroup return "
		    "exists %d\n", exists);
		xnuupcallsv2_storageupcallsprivate_queryvolumegroup__result_init_success(&result, exists);
	}

	return completion(result);
}

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

#endif /* CONFIG_EXCLAVES */
