/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#if CONFIG_DEBUG_SYSCALL_REJECTION

#include <kern/bits.h>
#include <kern/exc_guard.h>
#include <kern/exception.h>
#include <kern/kalloc.h>
#include <kern/simple_lock.h>
#include <kern/startup.h>
#include <kern/syscall_sw.h>

#include <pexpert/pexpert.h>

#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/user.h>

#include <sys/kern_debug.h>

#define SYSCALL_REJECTION_MODE_IGNORE   0
#define SYSCALL_REJECTION_MODE_GUARD    1
#define SYSCALL_REJECTION_MODE_CRASH    2

int debug_syscall_rejection_mode = 0;
SYSCTL_INT(_kern, OID_AUTO, debug_syscall_rejection_mode, CTLFLAG_RW | CTLFLAG_LOCKED,
    &debug_syscall_rejection_mode, 0, "0: ignore, 1: non-fatal, 2: crash");

static size_t const predefined_masks = 2; // 0: null mask (all 0), 1: all mask (all 1)

/*
 * The number of masks is derived from the mask selector data type:
 *
 * A selector is just made of an index into syscall_rejection_masks,
 * with the exception of the highest bit, which indicates whether the
 * mask is to be added as an "allow" mask or a "deny" mask.
 * Additionally, predefined masks don't actually have storage and are
 * handled specially, so syscall_rejection_masks starts with the first
 * non-predefined mask (and is sized appropriately).
 */
static size_t const syscall_rejection_mask_count =
    (1 << (8 * sizeof(syscall_rejection_selector_t) - predefined_masks)) - 1;
static syscall_rejection_mask_t syscall_rejection_masks[syscall_rejection_mask_count];

#define SR_MASK_SIZE (BITMAP_SIZE(mach_trap_count + nsysent))

static LCK_GRP_DECLARE(syscall_rejection_lck_grp, "syscall rejection lock");
static LCK_MTX_DECLARE(syscall_rejection_mtx, &syscall_rejection_lck_grp);

extern kern_return_t task_violated_guard(mach_exception_code_t, mach_exception_subcode_t, void *);

bool
debug_syscall_rejection_handle(int syscall_mach_trap_number)
{
	bool fatal = false;

	switch (debug_syscall_rejection_mode) {
	case SYSCALL_REJECTION_MODE_CRASH:
		fatal = true;
		OS_FALLTHROUGH;
	case SYSCALL_REJECTION_MODE_GUARD: {
		mach_exception_code_t code = 0;
		EXC_GUARD_ENCODE_TYPE(code, GUARD_TYPE_REJECTED_SC);
		EXC_GUARD_ENCODE_FLAVOR(code, 0);
		EXC_GUARD_ENCODE_TARGET(code, syscall_mach_trap_number < 0);
		mach_exception_subcode_t subcode =
		    syscall_mach_trap_number < 0 ? -syscall_mach_trap_number : syscall_mach_trap_number;

		if (!fatal) {
			task_violated_guard(code, subcode, NULL);
		} else {
			thread_guard_violation(current_thread(), code, subcode, fatal);
		}
		break;
	};
	default:
		/* ignore */
		;
	}
	return fatal;
}

void
rejected_syscall_guard_ast(
	thread_t __unused t,
	mach_exception_data_type_t code,
	mach_exception_data_type_t subcode)
{
	task_exception_notify(EXC_GUARD, code, subcode);
	proc_t p = current_proc();
	psignal(p, SIGSYS);
}


static void
_syscall_rejection_apply_mask(syscall_rejection_mask_t dest, const syscall_rejection_mask_t src, bool apply_as_allow)
{
	assert(dest != NULL);
	assert(src != NULL);

	if (apply_as_allow) {
		bitmap_or(dest, dest, src, mach_trap_count + nsysent);
	} else {
		bitmap_and_not(dest, dest, src, mach_trap_count + nsysent);
	}
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
 * The libsyscall wrapper provides a more convenient interface where
 * an array (up to 8 elements long) and its length are passed in,
 * which the wrapper then packs into packed_selectors of the actual
 * system call.
 */

int
debug_syscall_reject(struct proc *p __unused, struct debug_syscall_reject_args *args, int *retval)
{
	int error = 0;

	*retval = 0;

	if (debug_syscall_rejection_mode == SYSCALL_REJECTION_MODE_IGNORE) {
		return 0;
	}

	uthread_t ut = current_uthread();

	bitmap_t mask[SR_MASK_SIZE / sizeof(bitmap_t)];
	// syscall rejection masks are always reset to "deny all"
	memset(mask, 0, SR_MASK_SIZE);

	lck_mtx_lock(&syscall_rejection_mtx);

	for (int i = 0; i < sizeof(args->packed_selectors) / sizeof(syscall_rejection_selector_t); i++) {
		syscall_rejection_selector_t selector = ((syscall_rejection_selector_t const *)&(args->packed_selectors))[i];
		bool const is_allow_mask = selector & SYSCALL_REJECTION_IS_ALLOW_MASK;
		int const mask_index = selector & SYSCALL_REJECTION_INDEX_MASK;

		if (mask_index == SYSCALL_REJECTION_NULL) {
			// mask 0 is always empty (nothing to apply)
			continue;
		}

		if (mask_index == SYSCALL_REJECTION_ALL) {
			// mask 1 is always full (overrides everything)
			memset(mask, is_allow_mask ? 0xff : 0x00, SR_MASK_SIZE);
			continue;
		}

		syscall_rejection_mask_t mask_to_apply = syscall_rejection_masks[mask_index - predefined_masks];

		if (mask_to_apply == NULL) {
			error = ENOENT;
			goto out_locked;
		}

		_syscall_rejection_apply_mask(mask, mask_to_apply, is_allow_mask);
	}

	if (ut->syscall_rejection_mask == NULL) {
		/* Not RT-safe, but only necessary once. */

		ut->syscall_rejection_mask = kalloc_data(SR_MASK_SIZE, Z_WAITOK);

		if (ut->syscall_rejection_mask == NULL) {
			error = ENOMEM;
			goto out_locked;
		}
	}

	memcpy(ut->syscall_rejection_mask, mask, SR_MASK_SIZE);

out_locked:
	lck_mtx_unlock(&syscall_rejection_mtx);

	return error;
}

static bool
_syscall_rejection_add(syscall_rejection_mask_t dst, char const *name)
{
	/*
	 * Yes, this function is O(n+m), making the whole act of setting a
	 * mask O(l*(n+m)), but defining masks is done rarely enough (and
	 * i, n and m small enough) for this to not matter.
	 */

	for (int i = 0; i < mach_trap_count; i++) {
		if (strcmp(mach_syscall_name_table[i], name) == 0) {
			bitmap_set(dst, i);
			return true;
		}
	}

	extern char const *syscallnames[];

	for (int i = 0; i < nsysent; i++) {
		if (strcmp(syscallnames[i], name) == 0) {
			bitmap_set(dst, i + mach_trap_count);
			return true;
		}
	}

	printf("%s: trying to add non-existing syscall/mach trap '%s'\n", __func__, name);
	return false;
}

/* Pretty much arbitrary, we just don't want userspace to pass
 * unreasonably large buffers to parse. */
static size_t const max_input_size = 16 * PAGE_MAX_SIZE;

static int
_sysctl_debug_syscall_rejection_masks(struct sysctl_oid __unused *oidp, void * __unused arg1, int __unused arg2,
    struct sysctl_req *req)
{
	if (req->newptr == 0) {
		return 0;
	}

	if (req->newlen > max_input_size) {
		return E2BIG;
	}

	size_t const len = req->newlen;
	char *buf = kalloc_data(len + 1, Z_WAITOK);

	if (buf == NULL) {
		return ENOMEM;
	}

	/*
	 * sysctl_io_string always copies out the given buffer as the
	 * "old" value if requested.  We could construct a text
	 * representation of existing masks, but this is not particularly
	 * interesting, so we just return the dummy string "<masks>".
	 */
	strlcpy(buf, "<masks>", len + 1);
	int changed = 0;
	int error = sysctl_io_string(req, buf, len + 1, 0, &changed);

	if (error != 0 || !changed) {
		goto out;
	}

	char const *p = buf;

	int id = 0;
	int l = 0;
	int n = sscanf(p, "%i: %n", &id, &l);

	if (n != 1 || id < predefined_masks || id > syscall_rejection_mask_count + predefined_masks) {
		printf("%s: invalid mask id %i (or conversion failed)\n", __FUNCTION__, id);
		error = EINVAL;
		goto out;
	}

	p += l;

	syscall_rejection_mask_t new_mask = kalloc_data(SR_MASK_SIZE,
	    Z_WAITOK | Z_ZERO);
	if (new_mask == NULL) {
		printf("%s: allocating new mask for id %i failed\n", __FUNCTION__, id);
		error = ENOMEM;
		goto out;
	}

	size_t const max_name_len = 128;
	char name[max_name_len];

	error = 0;

	while (p < buf + len && *p != 0) {
		name[0] = 0;
		n = sscanf(p, "%127s %n", name, &l);
		if (n != 1 || name[0] == 0) {
			error = EINVAL;
			kfree_data(new_mask, SR_MASK_SIZE);
			goto out;
		}

		if (!_syscall_rejection_add(new_mask, name)) {
			error = ENOENT;
			kfree_data(new_mask, SR_MASK_SIZE);
			goto out;
		}

		p += l;
	}


	syscall_rejection_mask_t to_free = NULL;

	lck_mtx_lock(&syscall_rejection_mtx);

	syscall_rejection_mask_t *target_mask = &syscall_rejection_masks[id - predefined_masks];

	to_free = *target_mask;
	*target_mask = new_mask;

	lck_mtx_unlock(&syscall_rejection_mtx);

	kfree_data(to_free, SR_MASK_SIZE);
out:

	kfree_data(buf, len);
	return error;
}

SYSCTL_PROC(_kern, OID_AUTO, syscall_rejection_masks, CTLTYPE_STRING | CTLFLAG_WR | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, _sysctl_debug_syscall_rejection_masks, "A", "system call rejection masks");

#else /* CONFIG_DEBUG_SYSCALL_REJECTION */

#include <sys/kern_debug.h>

int
debug_syscall_reject(struct proc *p __unused, struct debug_syscall_reject_args * __unused args, int __unused *ret)
{
	/* not supported. */
	return ENOTSUP;
}

#endif /* CONFIG_DEBUG_SYSCALL_REJECTION */
