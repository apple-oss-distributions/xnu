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
int __debug_syscall_reject_config(uint64_t packed_selectors1, uint64_t packed_selectors2, uint64_t flags);

static bool supported = true;

typedef uint64_t packed_selector_t;

int
debug_syscall_reject_config(const syscall_rejection_selector_t *selectors, size_t len, uint64_t flags)
{
	_Static_assert(sizeof(syscall_rejection_selector_t) == 1, "selector size is not 1 byte");

	if (!supported) {
		/* Gracefully ignored if unsupported (e.g. if compiled out of RELEASE). */
		return 0;
	}

	if (len > (2 * 8 * sizeof(packed_selector_t)) / SYSCALL_REJECTION_SELECTOR_BITS) {
		/* selectors are packed one per 7 bits into two uint64_ts */
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

	uint64_t packed_selectors[2] = { 0 };
	int shift = 0;

#define s_left_shift(x, n) ((n) < 0 ? ((x) >> -(n)) : ((x) << (n)))

	for (int i = 0; i < len; i++, shift += SYSCALL_REJECTION_SELECTOR_BITS) {
		int const second_shift = shift - 64;

		if (shift < 8 * sizeof(packed_selector_t)) {
			packed_selectors[0] |= ((uint64_t)(selectors[i]) & SYSCALL_REJECTION_SELECTOR_MASK) << shift;
		}
		if (second_shift > -SYSCALL_REJECTION_SELECTOR_BITS) {
			packed_selectors[1] |= s_left_shift((uint64_t)(selectors[i] & SYSCALL_REJECTION_SELECTOR_MASK), second_shift);
		}
	}

	int ret = __debug_syscall_reject_config(packed_selectors[0], packed_selectors[1], flags);

	if (ret == -1 && errno == ENOTSUP) {
		errno = 0;
		supported = false;
		return 0;
	}

	return ret;
}

/* Compatibility to old system call. */
int
debug_syscall_reject(const syscall_rejection_selector_t *selectors, size_t len)
{
	return debug_syscall_reject_config(selectors, len, SYSCALL_REJECTION_FLAGS_DEFAULT);
}
