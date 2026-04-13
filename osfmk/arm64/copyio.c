/*
 * Copyright (c) 2012-2024 Apple Inc. All rights reserved.
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

#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>
#include <kern/thread.h>
#include <kern/zalloc_internal.h>
#include <sys/errno.h>
#include <vm/pmap.h>
#include <vm/vm_map_xnu.h>
#include <vm/vm_memtag.h>
#include <san/kasan.h>
#include <arm/pmap.h>
#include <arm64/speculation.h>

#undef copyin
#undef copyout

extern int _bcopyin(const user_addr_t src, char *dst, vm_size_t len);
extern int _bcopyinstr(const user_addr_t src, char *dst, vm_size_t max, vm_size_t *actual);
extern int _bcopyout(const char *src, user_addr_t dst, vm_size_t len);
extern int _copyin_atomic32(const user_addr_t src, uint32_t *dst);
extern int _copyin_atomic32_wait_if_equals(const user_addr_t src, uint32_t value);
extern int _copyin_atomic64(const user_addr_t src, uint64_t *dst);
extern int _copyout_atomic32(uint32_t u32, user_addr_t dst);
extern int _copyout_atomic64(uint64_t u64, user_addr_t dst);

#if HAS_MTE
extern int _unprivileged_bcopyin(const user_addr_t src, char *dst, vm_size_t len);
extern int _unprivileged_bcopyinstr(const user_addr_t src, char *dst, vm_size_t max, vm_size_t *actual);
extern int _unprivileged_bcopyout(const char *src, user_addr_t dst, vm_size_t len);
extern int _unprivileged_copyin_atomic32(const user_addr_t src, uint32_t *dst);
extern int _copyin_atomic32_wait_if_equals_unchecked(const user_addr_t src, uint32_t value);
extern int _unprivileged_copyin_atomic64(const user_addr_t src, uint64_t *dst);
extern int _unprivileged_copyout_atomic32(uint32_t u32, user_addr_t dst);
extern int _unprivileged_copyout_atomic64(uint64_t u64, user_addr_t dst);

extern int _copyin_mte_load_tag(const user_addr_t src, user_addr_t* out);
#endif /* HAS_MTE */

extern int copyoutstr_prevalidate(const void *kaddr, user_addr_t uaddr, size_t len);

extern const vm_map_address_t physmap_base;
extern const vm_map_address_t physmap_end;

/*!
 * @typedef copyio_flags_t
 *
 * @const COPYIO_IN
 * The copy is user -> kernel.
 * One of COPYIO_IN or COPYIO_OUT should always be specified.
 *
 * @const COPYIO_OUT
 * The copy is kernel -> user
 * One of COPYIO_IN or COPYIO_OUT should always be specified.
 *
 * @const COPYIO_ALLOW_KERNEL_TO_KERNEL
 * The "user_address" is allowed to be in the VA space of the kernel.
 *
 * @const COPYIO_VALIDATE_USER_ONLY
 * There isn't really a kernel address used, and only the user address
 * needs to be validated.
 *
 * @const COPYIO_ATOMIC
 * The copyio operation is atomic, ensure that it is properly aligned.
 */
__options_decl(copyio_flags_t, uint32_t, {
	COPYIO_IN                       = 0x0001,
	COPYIO_OUT                      = 0x0002,
	COPYIO_ALLOW_KERNEL_TO_KERNEL   = 0x0004,
	COPYIO_VALIDATE_USER_ONLY       = 0x0008,
	COPYIO_ATOMIC                   = 0x0010,
});

typedef enum {
	USER_ACCESS_READ,
	USER_ACCESS_WRITE
} user_access_direction_t;

#if HAS_MTE
static inline void
unprivileged_user_access_enable(__unused user_access_direction_t user_access_direction,
    pmap_t __unused pmap)
{
}

static inline void
unprivileged_user_access_disable(__unused user_access_direction_t user_access_direction,
    pmap_t __unused pmap)
{
	current_thread()->machine.in_unprivileged_access = false;
}
#endif /* HAS_MTE */

static inline void
user_access_enable(__unused user_access_direction_t user_access_direction, pmap_t __unused pmap)
{
#if __ARM_PAN_AVAILABLE__
	assert(__builtin_arm_rsr("pan") != 0);
	__builtin_arm_wsr("pan", 0);
#endif  /* __ARM_PAN_AVAILABLE__ */

}

static inline void
user_access_disable(__unused user_access_direction_t user_access_direction, pmap_t __unused pmap)
{
#if __ARM_PAN_AVAILABLE__
	__builtin_arm_wsr("pan", 1);
#endif  /* __ARM_PAN_AVAILABLE__ */

}

#if HAS_MTE
static inline bool
userspace_access_is_tagged(vm_map_t map)
{
	if (task_has_sec_never_check(current_task())) {
		return false;
	}
	if (ml_thread_get_sec_override(current_thread())) {
		return false;
	}
	return current_task_has_sec_enabled() || !vm_map_has_sec_access(map);
}

#define WRAP_COPYIO_UNPRIVILEGED(_dir, _map, _op)                           \
	({                                                                      \
	        int _ret;                                                       \
	        unprivileged_user_access_enable(_dir, (_map)->pmap);            \
	        _ret = _op;                                                     \
	        unprivileged_user_access_disable(_dir, (_map)->pmap);           \
	        _ret;                                                           \
	})
#endif /* HAS_MTE */

#define WRAP_COPYIO_PAN(_dir, _map, _op)                                    \
	({                                                                      \
	        int _ret;                                                       \
	        user_access_enable(_dir, (_map)->pmap);                         \
	        _ret = _op;                                                     \
	        user_access_disable(_dir, (_map)->pmap);                        \
	        _ret;                                                           \
	})

#if HAS_MTE
/* BEGIN IGNORE CODESTYLE */
/**
 * Wraps a low-level assembly copyio handler.
 *
 * Depending on how the target address space is configured, this macro will
 * choose between a "privileged" handler (ldr/str + PAN=0) and an unprivileged
 * equivalent (ldtr/sttr).  Privileged handler calls are wrapped with
 * user_access_{enable,disable} as needed.
 *
 * @param _dir USER_ACCESS_READ if this handler reads from userspace memory, or
 *             USER_ACCESS_WRITE if it writes to userspace memory
 * @param _map the VM map to read from
 * @param _op the copyio handler to invoke, including parameters
 */
#define WRAP_COPYIO(_dir, _map, _op)                                                            \
	({                                                                                          \
	        int _ret2;                                                                          \
	        if (userspace_access_is_tagged(_map)) {                                             \
	                _ret2 = WRAP_COPYIO_PAN(_dir, _map, _op);                                   \
	                if (_ret2 == EAGAIN) {                                                      \
	                        /*                                                                  \
	                         * The exception handler enabled MTE soft mode.                     \
	                         * Try again with a handler that respects ATA0/TCF0.                \
	                         */                                                                 \
	                        _ret2 = WRAP_COPYIO_UNPRIVILEGED(_dir, _map, _unprivileged ## _op); \
	                }                                                                           \
	        } else {                                                                            \
	                _ret2 = WRAP_COPYIO_UNPRIVILEGED(_dir, _map, _unprivileged ## _op);         \
	        }                                                                                   \
	        _ret2;                                                                              \
	})
/* END IGNORE CODESTYLE */
#else
#define WRAP_COPYIO(_dir, _map, _op) WRAP_COPYIO_PAN(_dir, _map, _op)
#endif

/*
 * Copy sizes bigger than this value will cause a kernel panic.
 *
 * Yes, this is an arbitrary fixed limit, but it's almost certainly
 * a programming error to be copying more than this amount between
 * user and wired kernel memory in a single invocation on this
 * platform.
 */
const int copysize_limit_panic = (64 * 1024 * 1024);

static inline bool
is_kernel_to_kernel_copy(pmap_t pmap)
{
	return pmap == kernel_pmap;
}

/**
 * In order to prevent copies from speculatively targeting the wrong address
 * space, force kernel-to-kernel copies to target the kernel address space
 * (TTBR1) and non-kernel copies to target the user address space (TTBR0).
 *
 * This should have no non-speculative effect as any address which passes
 * validation should already have bit 55 (the address space select bit) set
 * appropriately. If the address would change (i.e. addr is invalid for the copy
 * type), this function panics and so it must only be called after all other
 * verification has completed.
 */
static user_addr_t
copy_ensure_address_space_spec(vm_map_t map, const user_addr_t addr)
{
	user_addr_t new_addr = 0;
	user_addr_t kaddr = addr | BIT(55);
	user_addr_t uaddr = addr & (~BIT(55));

	/*
	 * new_addr = is_kernel_to_kernel_copy(...) ? kaddr : uaddr
	 *
	 * The check must be performed explicitly as the compiler lowering of the
	 * actual call may be subject to prediction.
	 */
	SPECULATION_GUARD_SELECT_XXX(
		/* out */ new_addr,
		/* cmp_1  */ map->pmap, /* cmp_2 */ kernel_pmap,
		/* cc   */ "eq", /* sel_1 */ kaddr,
		/* n_cc */ "ne", /* sel_2 */ uaddr);

	/*
	 * Since we're modifying the address past the validation point, let's be
	 * sure we didn't erroneously change address spaces.
	 *
	 * We have to be careful to hide this check from the optimizer as if it
	 * learns that new_addr == addr, then it is free to (and, indeed, does) use
	 * addr everywhere that new_addr is referenced, which breaks our hardening.
	 */
	user_addr_t new_addr_opt_hidden = new_addr;
	__compiler_materialize_and_prevent_reordering_on(new_addr_opt_hidden);
	if (new_addr_opt_hidden != addr) {
		panic("copy_ensure_address_space_spec changed address: 0x%llx->0x%llx",
		    addr, new_addr);
	}

	return new_addr;
}

static int
copy_validate_user_addr(vm_map_t map, const user_addr_t user_addr, vm_size_t nbytes)
{
	user_addr_t canonicalized_user_addr = user_addr;
	user_addr_t user_addr_last;
	bool is_kernel_to_kernel = is_kernel_to_kernel_copy(map->pmap);

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	/*
	 *  `user_addr` could be tagged. Canonicalize the address so we perform
	 *  range checks with canonical addresses.
	 *
	 *  Emulated processes are allowed to pass tagged pointers into the kernel.
	 *  Though we do not currently check tags for emulated processes, on real
	 *  silicon, copyio will check tags, so we want to propagate them here
	 *  for testing purposes. This works because TCR.TBI0 is set, which
	 *  enables TBI for access to TTBR0 at all ELx.
	 *
	 *  We use vm_memtag_canonicalize() here, rather than vm_map_strip_addr()
	 *  as TBI-tagged addresses are explicitly banned from copyio.
	 */
	if (current_task_has_sec_enabled()) {
		canonicalized_user_addr = (user_addr_t)vm_memtag_canonicalize(map, user_addr);
	}
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

	if (__improbable(canonicalized_user_addr < vm_map_min(map) ||
	    os_add_overflow(canonicalized_user_addr, nbytes, &user_addr_last) ||
	    user_addr_last > vm_map_max(map))) {
		return EFAULT;
	}


	if (!is_kernel_to_kernel) {
		if (__improbable(canonicalized_user_addr & ARM_TBI_USER_MASK)) {
			return EINVAL;
		}
	}

	return 0;
}

static void
copy_validate_kernel_addr(uintptr_t kernel_addr, vm_size_t nbytes)
{
	uintptr_t kernel_addr_last;

	if (__improbable(os_add_overflow(kernel_addr, nbytes, &kernel_addr_last))) {
		panic("%s(%p, %lu) - kaddr not in kernel", __func__,
		    (void *)kernel_addr, nbytes);
	}

	bool in_kva = (VM_KERNEL_STRIP_PTR(kernel_addr) >= VM_MIN_KERNEL_ADDRESS) &&
	    (VM_KERNEL_STRIP_PTR(kernel_addr_last) <= VM_MAX_KERNEL_ADDRESS);
	bool in_physmap = (VM_KERNEL_STRIP_PTR(kernel_addr) >= physmap_base) &&
	    (VM_KERNEL_STRIP_PTR(kernel_addr_last) <= physmap_end);

	if (__improbable(!(in_kva || in_physmap))) {
		panic("%s(%p, %lu) - kaddr not in kernel", __func__,
		    (void *)kernel_addr, nbytes);
	}

	zone_element_bounds_check(kernel_addr, nbytes);
}

/*
 * Validate the arguments to copy{in,out} on this platform.
 *
 * Returns EXDEV when the current thread pmap is the kernel's
 * which is non fatal for certain routines.
 */
static inline __attribute__((always_inline)) int
copy_validate(vm_map_t map, const user_addr_t user_addr, uintptr_t kernel_addr,
    vm_size_t nbytes, copyio_flags_t flags)
{
	int ret;

	if (__improbable(nbytes > copysize_limit_panic)) {
		return EINVAL;
	}

	ret = copy_validate_user_addr(map, user_addr, nbytes);
	if (__improbable(ret)) {
		return ret;
	}

	if (flags & COPYIO_ATOMIC) {
		if (__improbable(user_addr & (nbytes - 1))) {
			return EINVAL;
		}
	}

	if ((flags & COPYIO_VALIDATE_USER_ONLY) == 0) {
		copy_validate_kernel_addr(kernel_addr, nbytes);
#if KASAN
		/* For user copies, asan-check the kernel-side buffer */
		if (flags & COPYIO_IN) {
			__asan_storeN(kernel_addr, nbytes);
		} else {
			__asan_loadN(kernel_addr, nbytes);
		}
#endif
	}

	if (is_kernel_to_kernel_copy(map->pmap)) {
		if (__improbable((flags & COPYIO_ALLOW_KERNEL_TO_KERNEL) == 0)) {
			return EFAULT;
		}
		return EXDEV;
	}

	return 0;
}

int
copyin_kern(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes)
{
	bcopy((const char*)(uintptr_t)user_addr, kernel_addr, nbytes);

	return 0;
}

int
copyout_kern(const char *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	bcopy(kernel_addr, (char *)(uintptr_t)user_addr, nbytes);

	return 0;
}

__mockable int
copyin(const user_addr_t user_addr, void *kernel_addr, vm_size_t nbytes)
{
	vm_map_t map = current_thread()->map;
	user_addr_t guarded_user_addr;
	int result;

	if (__improbable(nbytes == 0)) {
		return 0;
	}

	result = copy_validate(map, user_addr, (uintptr_t)kernel_addr, nbytes,
	    COPYIO_IN | COPYIO_ALLOW_KERNEL_TO_KERNEL);
	if (result == EXDEV) {
		guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);
		return copyin_kern(guarded_user_addr, kernel_addr, nbytes);
	}
	if (__improbable(result)) {
		return result;
	}

	guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_READ, map,
	           _bcopyin(guarded_user_addr, kernel_addr, nbytes));
}

/*
 * copy{in,out}_atomic{32,64}
 * Read or store an aligned value from userspace as a single memory transaction.
 * These functions support userspace synchronization features
 */
int
copyin_atomic32(const user_addr_t user_addr, uint32_t *kernel_addr)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, (uintptr_t)kernel_addr, 4,
	    COPYIO_IN | COPYIO_ATOMIC);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_READ, map,
	           _copyin_atomic32(guarded_user_addr, kernel_addr));
}

#if HAS_MTE
static inline int
_unprivileged_copyin_atomic32_wait_if_equals(const user_addr_t user_addr, uint32_t value)
{
	vm_map_t map = current_thread()->map;

	assert(__builtin_arm_rsr64("TCO") == 0);
	return WRAP_COPYIO_PAN(USER_ACCESS_READ, map,
	           _copyin_atomic32_wait_if_equals_unchecked(user_addr, value));
}


/*
 * Retrieves the associated MTE tag, if any, for a user space address.
 * Returns the input pointer with any associated MTE tag merged to the
 * architecturally specified bitfield in `out`.
 */
int
copyin_mte_load_tag(const user_addr_t user_addr, user_addr_t* out)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, (uintptr_t)out, sizeof(user_addr_t),
	    COPYIO_IN | COPYIO_ATOMIC);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	int ret = WRAP_COPYIO_PAN(USER_ACCESS_READ, map,
	    _copyin_mte_load_tag(guarded_user_addr, out));
	return ret;
}

#endif /* HAS_MTE */

int
copyin_atomic32_wait_if_equals(const user_addr_t user_addr, uint32_t value)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, 0, 4,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_READ, map,
	           _copyin_atomic32_wait_if_equals(guarded_user_addr, value));
}

int
copyin_atomic64(const user_addr_t user_addr, uint64_t *kernel_addr)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, (uintptr_t)kernel_addr, 8,
	    COPYIO_IN | COPYIO_ATOMIC);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_READ, map,
	           _copyin_atomic64(guarded_user_addr, kernel_addr));
}

int
copyout_atomic32(uint32_t value, user_addr_t user_addr)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, 0, 4,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_WRITE, map,
	           _copyout_atomic32(value, guarded_user_addr));
}

int
copyout_atomic64(uint64_t value, user_addr_t user_addr)
{
	vm_map_t map = current_thread()->map;
	int result = copy_validate(map, user_addr, 0, 8,
	    COPYIO_OUT | COPYIO_ATOMIC | COPYIO_VALIDATE_USER_ONLY);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_WRITE, map,
	           _copyout_atomic64(value, guarded_user_addr));
}

int
copyinstr(const user_addr_t user_addr, char *kernel_addr, vm_size_t nbytes, vm_size_t *lencopied)
{
	vm_map_t map = current_thread()->map;
	int result;
	vm_size_t bytes_copied = 0;

	*lencopied = 0;
	if (__improbable(nbytes == 0)) {
		return ENAMETOOLONG;
	}

	result = copy_validate(map, user_addr, (uintptr_t)kernel_addr, nbytes, COPYIO_IN);
	if (__improbable(result)) {
		return result;
	}

	user_addr_t guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	result = WRAP_COPYIO(USER_ACCESS_READ, map,
	    _bcopyinstr(guarded_user_addr, kernel_addr, nbytes, &bytes_copied));

	if (result != EFAULT) {
		*lencopied = bytes_copied;
	}
	return result;
}

__mockable int
copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes)
{
	vm_map_t map = current_thread()->map;
	int result;
	user_addr_t guarded_user_addr;

	if (nbytes == 0) {
		return 0;
	}

	result = copy_validate(map, user_addr, (uintptr_t)kernel_addr, nbytes,
	    COPYIO_OUT | COPYIO_ALLOW_KERNEL_TO_KERNEL);
	if (result == EXDEV) {
		guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);
		return copyout_kern(kernel_addr, guarded_user_addr, nbytes);
	}
	if (__improbable(result)) {
		return result;
	}

	guarded_user_addr = copy_ensure_address_space_spec(map, user_addr);

	return WRAP_COPYIO(USER_ACCESS_WRITE, map,
	           _bcopyout(kernel_addr, guarded_user_addr, nbytes));
}

int
copyoutstr_prevalidate(const void *__unused kaddr, user_addr_t __unused uaddr, size_t __unused len)
{
	vm_map_t map = current_thread()->map;

	if (__improbable(is_kernel_to_kernel_copy(map->pmap))) {
		return EFAULT;
	}

	return 0;
}

#if (DEBUG || DEVELOPMENT)
int
verify_write(const void *source, void *dst, size_t size)
{
	int rc;
	disable_preemption();
	rc = _bcopyout((const char*)source, (user_addr_t)dst, size);
	enable_preemption();
	return rc;
}
#endif
