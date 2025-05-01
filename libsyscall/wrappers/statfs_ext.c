/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/attr.h>
#include <sys/param.h>
#include <sys/mount.h>

static int
__statfs_ext_default(const char *path, int fd, struct statfs *buf)
{
	int ret = 0;

	if (path) {
		ret = statfs(path, buf);
	} else {
		ret = fstatfs(fd, buf);
	}

	return ret;
}

static int
__statfs_ext_noblock(const char *path, int fd, struct statfs *buf)
{
	int ret = 0;
	char *ptr;

	struct {
		uint32_t        size;
		attribute_set_t f_attrs;
		fsid_t          f_fsid;
		uint32_t        f_type;
		attrreference_t f_mntonname;
		uint32_t        f_flags;
		attrreference_t f_mntfromname;
		uint32_t        f_flags_ext;
		attrreference_t f_fstypename;
		uint32_t        f_fssubtype;
		uid_t           f_owner;
		char            f_mntonname_buf[MAXPATHLEN];
		char            f_mntfromname_buf[MAXPATHLEN];
		char            f_fstypename_buf[MFSTYPENAMELEN];
	} __attribute__((aligned(4), packed)) *attrbuf;

	struct attrlist al = {
		.bitmapcount = ATTR_BIT_MAP_COUNT,
		.commonattr = ATTR_CMN_FSID | ATTR_CMN_RETURNED_ATTRS,
		.volattr =  ATTR_VOL_INFO | ATTR_VOL_FSTYPE | ATTR_VOL_MOUNTPOINT |
	    ATTR_VOL_MOUNTFLAGS | ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_FSTYPENAME |
	    ATTR_VOL_FSSUBTYPE | ATTR_VOL_MOUNTEXTFLAGS | ATTR_VOL_OWNER,
	};

	attrbuf = malloc(sizeof(*attrbuf));
	if (attrbuf == NULL) {
		errno = ENOMEM;
		return -1;
	}
	bzero(attrbuf, sizeof(*attrbuf));

	if (path) {
		ret = getattrlist(path, &al, attrbuf, sizeof(*attrbuf), FSOPT_NOFOLLOW | FSOPT_RETURN_REALDEV);
	} else {
		ret = fgetattrlist(fd, &al, attrbuf, sizeof(*attrbuf), FSOPT_RETURN_REALDEV);
	}

	if (ret < 0) {
		goto out;
	}

	/* Update user structure */
	if (attrbuf->f_attrs.commonattr & ATTR_CMN_FSID) {
		buf->f_fsid = attrbuf->f_fsid;
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_OWNER) {
		buf->f_owner = attrbuf->f_owner;
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_FSTYPE) {
		buf->f_type = attrbuf->f_type;
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_MOUNTFLAGS) {
		buf->f_flags = attrbuf->f_flags;
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_FSSUBTYPE) {
		buf->f_fssubtype = attrbuf->f_fssubtype;
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_FSTYPENAME) {
		ptr = (char *)&attrbuf->f_fstypename + attrbuf->f_fstypename.attr_dataoffset;
		strlcpy(buf->f_fstypename, ptr, sizeof(buf->f_fstypename));
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_MOUNTPOINT) {
		ptr = (char *)&attrbuf->f_mntonname + attrbuf->f_mntonname.attr_dataoffset;
		strlcpy(buf->f_mntonname, ptr, sizeof(buf->f_mntonname));
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_MOUNTEDDEVICE) {
		ptr = (char *)&attrbuf->f_mntfromname + attrbuf->f_mntfromname.attr_dataoffset;
		strlcpy(buf->f_mntfromname, ptr, sizeof(buf->f_mntfromname));
	}
	if (attrbuf->f_attrs.volattr & ATTR_VOL_MOUNTEXTFLAGS) {
		buf->f_flags_ext = attrbuf->f_flags_ext;
	}

out:
	free(attrbuf);
	return ret;
}

static int
__statfs_ext_impl(const char *path, int fd, struct statfs *buf, int flags)
{
	int ret = 0;

	bzero(buf, sizeof(struct statfs));

	/* Check for invalid flags */
	if (flags & ~(STATFS_EXT_NOBLOCK)) {
		errno = EINVAL;
		return -1;
	}

	/* Simply wrap statfs() or fstatfs() if no option is provided */
	if (flags == 0) {
		return __statfs_ext_default(path, fd, buf);
	}

	/* Retrieve filesystem statistics with extended options */
	if (flags & STATFS_EXT_NOBLOCK) {
		ret = __statfs_ext_noblock(path, fd, buf);
	}

	return ret;
}

int
fstatfs_ext(int fd, struct statfs *buf, int flags)
{
	/* fstatfs() sanity checks */
	if (fd < 0) {
		errno = EBADF;
		return -1;
	}
	if (buf == NULL) {
		errno = EFAULT;
		return -1;
	}

	return __statfs_ext_impl(NULL, fd, buf, flags);
}

int
statfs_ext(const char *path, struct statfs *buf, int flags)
{
	/* statfs() sanity checks */
	if (path == NULL) {
		errno = EFAULT;
		return -1;
	}
	if (buf == NULL) {
		errno = EFAULT;
		return -1;
	}

	return __statfs_ext_impl(path, -1, buf, flags);
}
