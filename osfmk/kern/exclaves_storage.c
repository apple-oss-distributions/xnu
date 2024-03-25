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

static const char *STORAGE_EXCLAVE_BUF_ID = "com.apple.named_buffer.6";
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


/* -------------------------------------------------------------------------- */
#pragma mark Upcalls

tb_error_t
exclaves_storage_upcall_root(const uint8_t exclaveid[_Nonnull 32],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_root__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] root %s\n", exclaveid);

	int error;
	uint64_t rootid;
	xnuupcalls_xnuupcalls_root__result_s result = {};

	if ((error = verify_string_length((const char *)&exclaveid[0], 32))) {
		xnuupcalls_xnuupcalls_root__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_root((const char *)&exclaveid[0], &rootid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_root failed with %d\n",
		    error);
		xnuupcalls_xnuupcalls_root__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_root return "
		    "rootId %lld\n", rootid);
		xnuupcalls_xnuupcalls_root__result_init_success(&result, rootid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_open(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_open__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "open %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcalls_xnuupcalls_open__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_open__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_open((uint32_t)fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_open failed with %d\n",
		    error);
		xnuupcalls_xnuupcalls_open__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_open return "
		    "fileId %lld\n", fileid);
		xnuupcalls_xnuupcalls_open__result_init_success(&result, fileid);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_close(const enum xnuupcalls_fstag_s fstag,
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
		xnuupcalls_xnuupcalls_close__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_close succeeded\n");
		xnuupcalls_xnuupcalls_close__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_create(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_create__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server]"
	    " create %d %lld %s\n", fstag, rootid, name);
	int error;
	uint64_t fileid;
	xnuupcalls_xnuupcalls_create__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_create__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_create((uint32_t)fstag, rootid,
	    (const char *)&name[0], &fileid);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_create failed with"
		    " %d\n", error);
		xnuupcalls_xnuupcalls_create__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_create return "
		    "fileId %lld\n", fileid);
		xnuupcalls_xnuupcalls_create__result_init_success(&result, fileid);
	}

	return completion(result);
}

static exclaves_resource_t *storage_resource = NULL;
static kern_return_t
exclaves_storage_init(void)
{
	kern_return_t kr = exclaves_named_buffer_map(
		EXCLAVES_DOMAIN_KERNEL, STORAGE_EXCLAVE_BUF_ID,
		STORAGE_EXCLAVE_BUF_SIZE,
		EXCLAVES_BUFFER_PERM_READ | EXCLAVES_BUFFER_PERM_WRITE,
		&storage_resource);
	if (kr != KERN_SUCCESS) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls] exclaves_named_buffer_map failed with %d\n", kr);
		return kr;
	}
	return KERN_SUCCESS;
}
EXCLAVES_BOOT_TASK(exclaves_storage_init, EXCLAVES_BOOT_RANK_SECOND);

tb_error_t
exclaves_storage_upcall_read(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_read__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "read %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->buf,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcalls_xnuupcalls_read__result_s result = {};

	error = verify_storage_buf_offset(descriptor->buf, descriptor->length);
	if (error != 0) {
		xnuupcalls_xnuupcalls_read__result_init_failure(&result, error);
		return completion(result);
	}

	__block uint64_t off = descriptor->fileoffset;
	error = exclaves_named_buffer_io(storage_resource, descriptor->buf,
	    descriptor->length, ^(char *buffer, size_t size) {
		int ret = vfs_exclave_fs_read((uint32_t)fstag,
		fileid, off, size, buffer);
		off += size;
		return ret;
	});

	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_read "
		    "failed with %d\n", error);
		xnuupcalls_xnuupcalls_read__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_read succeeded\n");
		xnuupcalls_xnuupcalls_read__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_write(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const struct xnuupcalls_iodesc_s *descriptor,
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_write__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "write %d %lld %lld %lld %lld\n", fstag, fileid, descriptor->buf,
	    descriptor->fileoffset, descriptor->length);
	int error;

	xnuupcalls_xnuupcalls_write__result_s result = {};

	error = verify_storage_buf_offset(descriptor->buf, descriptor->length);
	if (error != 0) {
		xnuupcalls_xnuupcalls_write__result_init_failure(&result, error);
		return completion(result);
	}


	__block uint64_t off = descriptor->fileoffset;
	error = exclaves_named_buffer_io(storage_resource, descriptor->buf,
	    descriptor->length, ^(char *buffer, size_t size) {
		int ret = vfs_exclave_fs_write((uint32_t)fstag,
		fileid, off, size, buffer);
		off += size;
		return ret;
	});

	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_write "
		    "failed with %d\n", error);
		xnuupcalls_xnuupcalls_write__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_write succeeded\n");
		xnuupcalls_xnuupcalls_write__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_remove(const enum xnuupcalls_fstag_s fstag,
    const uint64_t rootid, const uint8_t name[_Nonnull 256],
    tb_error_t (^completion)(xnuupcalls_xnuupcalls_remove__result_s))
{
	exclaves_debug_printf(show_storage_upcalls, "[storage_upcalls_server] "
	    "remove %d %lld %s\n", fstag, rootid, name);
	int error;
	xnuupcalls_xnuupcalls_remove__result_s result = {};

	if ((error = verify_string_length((const char *)&name[0], 256))) {
		xnuupcalls_xnuupcalls_remove__result_init_failure(&result, error);
		return completion(result);
	}
	error = vfs_exclave_fs_remove((uint32_t)fstag, rootid,
	    (const char *)&name[0]);
	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_remove failed with "
		    "%d\n", error);
		xnuupcalls_xnuupcalls_remove__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_remove succeeded\n");
		xnuupcalls_xnuupcalls_remove__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_sync(const enum xnuupcalls_fstag_s fstag,
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
		xnuupcalls_xnuupcalls_sync__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_sync succeeded\n");
		xnuupcalls_xnuupcalls_sync__result_init_success(&result);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_readdir(const enum xnuupcalls_fstag_s fstag,
    const uint64_t fileid, const uint64_t buf,
    const uint32_t length, tb_error_t (^completion)(xnuupcalls_xnuupcalls_readdir__result_s))
{
	exclaves_debug_printf(show_storage_upcalls,
	    "[storage_upcalls_server] readdir %d %lld %lld %d\n",
	    fstag, fileid, buf, length);
	int error;
	int32_t count;

	xnuupcalls_xnuupcalls_readdir__result_s result = {};

	if ((error = verify_storage_buf_offset(buf, length))) {
		xnuupcalls_xnuupcalls_readdir__result_init_failure(&result, error);
		return completion(result);
	}

	/*
	 * When we are able to map exclaves shared memory into kernel
	 * virtual address space, this temporary buffer will no longer
	 * be required.
	 */
	char *tmpbuf = kalloc_data(length, Z_WAITOK | Z_ZERO | Z_NOFAIL);
	error = vfs_exclave_fs_readdir((uint32_t)fstag, fileid,
	    tmpbuf, length, &count);
	assert3u(error, ==, 0);

	__block char *p = tmpbuf;
	error = exclaves_named_buffer_io(storage_resource, buf, length,
	    ^(char *buffer, size_t size) {
		memcpy(buffer, p, size);
		p += size;
		return 0;
	});
	assert3u(error, ==, 0);
	kfree_data(tmpbuf, length);

	if (error) {
		exclaves_debug_printf(show_errors,
		    "[storage_upcalls_server] vfs_exclave_fs_readdir "
		    "failed with %d\n", error);
		xnuupcalls_xnuupcalls_readdir__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_readdir succeeded\n");
		xnuupcalls_xnuupcalls_readdir__result_init_success(&result, count);
	}

	return completion(result);
}

tb_error_t
exclaves_storage_upcall_getsize(const enum xnuupcalls_fstag_s fstag,
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
		xnuupcalls_xnuupcalls_getsize__result_init_failure(&result, error);
	} else {
		exclaves_debug_printf(show_storage_upcalls,
		    "[storage_upcalls_server] vfs_exclave_fs_getsize succeeded\n");
		xnuupcalls_xnuupcalls_getsize__result_init_success(&result, size);
	}

	return completion(result);
}

#endif /* __has_include(<Tightbeam/tightbeam.h>) */

#endif /* CONFIG_EXCLAVES */
