/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
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

#include <machine/machine_routines.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/pgo.h>
#include <sys/kauth.h>
#include <security/mac_framework.h>
#include <libkern/OSKextLib.h>

#ifdef PROFILE

static uint64_t
get_size_for_buffer(int flags)
{
	/* These __llvm functions are defined in InstrProfiling.h in compiler_rt.  That
	 * is a internal header, so we need to re-prototype them here.  */
	extern uint64_t __llvm_profile_get_size_for_buffer(void);

	return __llvm_profile_get_size_for_buffer();
}


static int
write_buffer(int flags, char *buffer)
{
	extern int __llvm_profile_write_buffer(char *Buffer);

	return __llvm_profile_write_buffer(buffer);
}

#endif /* PROFILE */

/* this variable is used to signal to the debugger that we'd like it to reset
 * the counters */
int kdp_pgo_reset_counters = 0;

/* called in debugger context */
kern_return_t
do_pgo_reset_counters(void)
{
	OSKextResetPgoCounters();
	kdp_pgo_reset_counters = 0;
	return KERN_SUCCESS;
}

static kern_return_t
kextpgo_trap(void)
{
	return DebuggerTrapWithState(DBOP_RESET_PGO_COUNTERS, NULL, NULL, NULL, 0, NULL, FALSE, 0, NULL);
}

static kern_return_t
pgo_reset_counters(void)
{
	kern_return_t r;
	boolean_t istate;

	OSKextResetPgoCountersLock();

	istate = ml_set_interrupts_enabled(FALSE);

	kdp_pgo_reset_counters = 1;
	r = kextpgo_trap();

	ml_set_interrupts_enabled(istate);

	OSKextResetPgoCountersUnlock();
	return r;
}

/*
 * returns:
 *   EPERM  unless you are root
 *   EINVAL for invalid args.
 *   ENOSYS for not implemented
 *   ERANGE for integer overflow
 *   ENOENT if kext not found
 *   ENOTSUP kext does not support PGO
 *   EIO llvm returned an error.  shouldn't ever happen.
 */

int
grab_pgo_data(struct proc *p,
    struct grab_pgo_data_args *uap,
    register_t *retval)
{
	char *buffer = NULL;
	uint64_t size64 = 0;
	int err = 0;

	(void) p;

	if (!kauth_cred_issuser(kauth_cred_get())) {
		err = EPERM;
		goto out;
	}

#if CONFIG_MACF
	err = mac_system_check_info(kauth_cred_get(), "kern.profiling_data");
	if (err) {
		goto out;
	}
#endif /* CONFIG_MACF */

	if (uap->flags & ~PGO_ALL_FLAGS ||
	    uap->size < 0 ||
	    (uap->size > 0 && uap->buffer == 0)) {
		err = EINVAL;
		goto out;
	}

	if (uap->flags & PGO_HIB) {
		err = ENOTSUP;
		goto out;
	}

	if (uap->flags & PGO_RESET_ALL) {
		if (uap->flags != PGO_RESET_ALL || uap->uuid || uap->buffer || uap->size) {
			err = EINVAL;
		} else {
			kern_return_t r = pgo_reset_counters();
			switch (r) {
			case KERN_SUCCESS:
				err = 0;
				break;
			case KERN_OPERATION_TIMED_OUT:
				err = ETIMEDOUT;
				break;
			default:
				err = EIO;
				break;
			}
		}
		goto out;
	}

	*retval = 0;

	if (uap->uuid) {
		uuid_t uuid;
		err = copyin(uap->uuid, &uuid, sizeof(uuid));
		if (err) {
			goto out;
		}

		if (uap->buffer == 0 && uap->size == 0) {
			if (uap->flags & PGO_WAIT_FOR_UNLOAD) {
				err = EINVAL;
				goto out;
			}

			err = OSKextGrabPgoData(uuid, &size64, NULL, 0, 0, !!(uap->flags & PGO_METADATA));
			if (size64 == 0 && err == 0) {
				err = EIO;
			}
			if (err) {
				goto out;
			}

			ssize_t size = size64;
			if (((uint64_t) size) != size64 ||
			    size < 0) {
				err = ERANGE;
				goto out;
			}

			*retval = size;
			err = 0;
			goto out;
		} else if (!uap->buffer || uap->size <= 0) {
			err = EINVAL;
			goto out;
		} else {
			err = OSKextGrabPgoData(uuid, &size64, NULL, 0,
			    false,
			    !!(uap->flags & PGO_METADATA));

			if (size64 == 0 && err == 0) {
				err = EIO;
			}
			if (err) {
				goto out;
			}

			if (uap->size < 0 || (uint64_t)uap->size < size64) {
				err = EINVAL;
				goto out;
			}

			buffer = kalloc_data(size64, Z_WAITOK | Z_ZERO);
			if (!buffer) {
				err = ENOMEM;
				goto out;
			}

			err = OSKextGrabPgoData(uuid, &size64, buffer, size64,
			    !!(uap->flags & PGO_WAIT_FOR_UNLOAD),
			    !!(uap->flags & PGO_METADATA));
			if (err) {
				goto out;
			}

			ssize_t size = size64;
			if (((uint64_t) size) != size64 ||
			    size < 0) {
				err = ERANGE;
				goto out;
			}

			err = copyout(buffer, uap->buffer, size);
			if (err) {
				goto out;
			}

			*retval = size;
			goto out;
		}
	}


#ifdef PROFILE

	size64 = get_size_for_buffer(uap->flags);
	ssize_t size = size64;

	if (uap->flags & (PGO_WAIT_FOR_UNLOAD | PGO_METADATA)) {
		err = EINVAL;
		goto out;
	}

	if (((uint64_t) size) != size64 ||
	    size < 0) {
		err = ERANGE;
		goto out;
	}


	if (uap->buffer == 0 && uap->size == 0) {
		*retval = size;
		err = 0;
		goto out;
	} else if (uap->size < size) {
		err = EINVAL;
		goto out;
	} else {
		buffer = kalloc_data(size, Z_WAITOK | Z_ZERO);
		if (!buffer) {
			err = ENOMEM;
			goto out;
		}

		err = write_buffer(uap->flags, buffer);
		if (err) {
			err = EIO;
			goto out;
		}

		err = copyout(buffer, uap->buffer, size);
		if (err) {
			goto out;
		}

		*retval = size;
		goto out;
	}

#else /* PROFILE */

	*retval = -1;
	err = ENOSYS;
	goto out;

#endif /* !PROFILE */

out:
	if (buffer) {
		kfree_data(buffer, size64);
	}
	if (err) {
		*retval = -1;
	}
	return err;
}
