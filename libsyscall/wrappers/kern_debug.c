/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#include <stdbool.h>

#include <sys/errno.h>

#include <sys/kern_debug.h>

/* Syscall entry points */
int __debug_syscall_reject(uint64_t packed_selectors);

static bool supported = true;

int
debug_syscall_reject(const syscall_rejection_selector_t *selectors, size_t len)
{
	_Static_assert(sizeof(syscall_rejection_selector_t) == 1, "selector size is not 1 byte");

	if (!supported) {
		/* Gracefully ignored if unsupported (e.g. if compiled out of RELEASE). */
		return 0;
	}

	if (len > 8) {
		/* selectors are packed one per byte into an uint64_t */
		errno = E2BIG;
		return -1;
	}

	/*
	 * The masks to apply are passed to the kernel as packed selectors,
	 * which are just however many of the selector data type fit into one
	 * (or more) fields of the natural word size (i.e. a register). This
	 * avoids copying from user space.
	 *
	 * More specifically, at the time of this writing, a selector is 1
	 * byte wide, and there is only one uint64_t argument
	 * (args->packed_selectors), so up to 8 selectors can be specified,
	 * which are then stuffed into the 64 bits of the argument. If less
	 * than 8 masks are requested to be applied, the remaining selectors
	 * will just be left as 0, which naturally resolves as the "empty" or
	 * "NULL" mask that changes nothing.
	 *
	 * This libsyscall wrapper provides a more convenient interface where
	 * an array (up to 8 elements long) and its length are passed in,
	 * which the wrapper then packs into packed_selectors of the actual
	 * system call.
	 */


	uint64_t packed_selectors = 0;
	int shift = 0;

	for (int i = 0; i < len; i++, shift += 8) {
		packed_selectors |= ((uint64_t)(selectors[i]) & 0xff) << shift;
	}

	int ret = __debug_syscall_reject(packed_selectors);

	if (ret == -1 && errno == ENOTSUP) {
		errno = 0;
		supported = false;
		return 0;
	}

	return ret;
}
