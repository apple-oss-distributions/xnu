/*
 * Copyright (c) 2006, 2017 Apple Computer, Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/attr.h>
#include <sys/time.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <strings.h>

extern int __gettimeofday(struct timeval *, struct timezone *);
extern int __commpage_gettimeofday(struct timeval *);

static struct timespec times_now[2] = {
	{ .tv_nsec = UTIME_NOW },
	{ .tv_nsec = UTIME_NOW }
};

/*
 * Resolve any UTIME_NOW or UTIME_OMIT and return the attributes buffer and
 * attributes to pass.  Assumes times_in is writable.
 */
static int
prepare_times_array_and_attrs(struct timespec times_in[2],
    struct timespec times_out[2], size_t *times_out_size, int *flags)
{
	if (times_in[0].tv_nsec == UTIME_OMIT &&
	    times_in[1].tv_nsec == UTIME_OMIT) {
		return 0;
	}

	if (times_in[0].tv_nsec == UTIME_NOW ||
	    times_in[1].tv_nsec == UTIME_NOW) {
		*flags |= FSOPT_UTIMES_NULL;
		struct timespec now = {};
		{
			/*
			 * TODO: Replace with nanosecond time when available
			 */
			struct timeval tv;
			if (__commpage_gettimeofday(&tv) != 0) {
				__gettimeofday(&tv, NULL);
			}
			TIMEVAL_TO_TIMESPEC(&tv, &now);
		}

		if (times_in[0].tv_nsec == UTIME_NOW) {
			times_in[0] = now;
		}
		if (times_in[1].tv_nsec == UTIME_NOW) {
			times_in[1] = now;
		}
	}

	int attrs = 0;
	*times_out_size = 0;
	struct timespec *times_cursor = times_out;
	if (times_in[1].tv_nsec != UTIME_OMIT) {
		attrs |= ATTR_CMN_MODTIME;
		*times_cursor++ = times_in[1];
		*times_out_size += sizeof(struct timespec);
	}
	if (times_in[0].tv_nsec != UTIME_OMIT) {
		attrs |= ATTR_CMN_ACCTIME;
		*times_cursor = times_in[0];
		*times_out_size += sizeof(struct timespec);
	}
	return attrs;
}

int
futimens(int fd, const struct timespec _times_in[2])
{
	struct timespec times_in[2];
	int flags_out;

	if (_times_in != NULL) {
		memcpy(&times_in, _times_in, sizeof(times_in));
	} else {
		memcpy(&times_in, times_now, sizeof(times_in));
	}

	size_t attrbuf_size = 0;
	struct timespec times_out[2] = {};
	struct attrlist a = {
		.bitmapcount = ATTR_BIT_MAP_COUNT
	};
	a.commonattr = prepare_times_array_and_attrs(times_in, times_out, &attrbuf_size, &flags_out);

	return fsetattrlist(fd, &a, &times_out, attrbuf_size, 0);
}

int
utimensat(int fd, const char *path, const struct timespec _times_in[2], int flags)
{
	struct timespec times_in[2];
	int flags_out = 0;

	if (_times_in != NULL) {
		memcpy(&times_in, _times_in, sizeof(times_in));
	} else {
		memcpy(&times_in, times_now, sizeof(times_in));
	}

	size_t attrbuf_size = 0;
	struct timespec times_out[2] = {};
	struct attrlist a = {
		.bitmapcount = ATTR_BIT_MAP_COUNT
	};
	a.commonattr = prepare_times_array_and_attrs(times_in, times_out, &attrbuf_size, &flags_out);

	if (flags & AT_SYMLINK_NOFOLLOW) {
		flags_out |= FSOPT_NOFOLLOW;
	}
	if (flags & AT_SYMLINK_NOFOLLOW_ANY) {
		flags_out |= FSOPT_NOFOLLOW_ANY;
	}

	return setattrlistat(fd, path, &a, &times_out, attrbuf_size, flags_out);
}
