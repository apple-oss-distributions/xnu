/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef _ARM64_MTE_XNU_H_
#define _ARM64_MTE_XNU_H_

#if HAS_MTE

#if XNU_KERNEL_PRIVATE

#include <machine/static_if.h>

__BEGIN_DECLS

#if DEVELOPMENT || DEBUG || KASAN
/*
 * Boot-args.
 *
 * - -disable_mte: legacy big hammer that disables MTE entirely. It is understood and
 *                 honored by both iBoot and SPTM.
 *
 * - mte_config:   allows to setup an explicit MTE configuration for XNU. The configuration
 *                 allows to toggle USER/KERNEL DEFAULT/PURE_DATA configurations.
 *                 The bitmask is an _explicit_ configuration that overrides the
 *                 default one. E.g. mte_config=0x0004 will boot the kernel with only
 *                 userspace MTE enabled.
 *
 * - mte_debug:    set of tunables that can be turned on to test either experimental
 *                 features or further debugging features.
 */

/*
 * mte_config=xxx boot-arg allows to set a specific MTE enablement configuration.
 * It allows to toggle whether user/kernel default/data tagging is enabled.
 */
__options_closed_decl(mte_config_t, uint16_t, {
	MTE_ENABLE_KERNEL                 = 0x0001,         /* Enable MTE tag checking in the kernel */
	MTE_ENABLE_KERNEL_PURE_DATA       = 0x0002,         /* Extend MTE tag checking to pure data in the kernel */
	MTE_ENABLE_USER                   = 0x0004,         /* Enable MTE tag checking in userspace */
	MTE_ENABLE_USER_PURE_DATA         = 0x0008          /* Enable MTE tag checking to pure data in userspace */
});

#define MTE_CONFIG_DEFAULT                      (MTE_ENABLE_KERNEL | MTE_ENABLE_USER | MTE_ENABLE_KERNEL_PURE_DATA | MTE_ENABLE_USER_PURE_DATA)
#define MTE_CONFIG_DISABLE_ALL                  (0)

/* Default configuration for both DEVELOPMENT and RELEASE */
STATIC_IF_KEY_DECLARE_TRUE(mte_config_kern_enabled);
STATIC_IF_KEY_DECLARE_TRUE(mte_config_kern_data_enabled);
STATIC_IF_KEY_DECLARE_TRUE(mte_config_user_enabled);
STATIC_IF_KEY_DECLARE_TRUE(mte_config_user_data_enabled);

#define mte_kern_enabled()                      probable_static_if(mte_config_kern_enabled)
#define mte_kern_data_enabled()                 probable_static_if(mte_config_kern_data_enabled)
#define mte_user_enabled()                      probable_static_if(mte_config_user_enabled)
#define mte_user_data_enabled()                 probable_static_if(mte_config_user_data_enabled)

/*
 * mte_debug=xxx boot-arg allows to enable a number of runtime debugging
 * options for MTE.
 */
__options_closed_decl(mte_debug_config_t, uint16_t, {
	MTE_USER_FORCE_ENABLE_ALL         = 0x0001,         /* Force enable MTE on every userland process */
	MTE_DEBUG_TCO_STATE               = 0x0002,         /* Enable TCO debugging */
	MTE_PANIC_ON_NON_CANONICAL_PARAM  = 0x0004,         /* Panic whenever a non canonical address is passed to APIs expecting otherwise */
	MTE_PANIC_ON_ASYNC_FAULT          = 0x0008,         /* Panic whenever a tag check fault is detected in an async path */
});

#define MTE_DEBUG_DEFAULT               (0)
#define MTE_DEBUG_DISABLE_ALL           (0)

STATIC_IF_KEY_DECLARE_FALSE(mte_config_force_all_enabled);
STATIC_IF_KEY_DECLARE_FALSE(mte_debug_tco_state);
STATIC_IF_KEY_DECLARE_FALSE(mte_panic_on_non_canonical);
STATIC_IF_KEY_DECLARE_FALSE(mte_panic_on_async_fault);

#define mte_force_all_enabled()          improbable_static_if(mte_config_force_all_enabled)
/*
 * PSTATE.TCO sounds mellow, but can be evil. Tag Check Override is meant to be
 * a way to briefly disable tag checking during a trusted path. It must not extend
 * past the path, into unexpected callee/callers. For this reason, we should not incentivize
 * its use. This option adds some enforcing that TCO is at the state we expect
 * whenever we try to manipulate it. We intentionally do not implement any form of
 * save and restore of its state. We don't enable this on release as reading TCO is
 * a slow operation and would impact performance.
 */
#define mte_debug_tco_state()            improbable_static_if(mte_debug_tco_state)
/*
 * Internal VM state is maintained in canonical form, therefore any non load/store
 * operation (e.g. locate an entry within a vm_map) must happen in canonical form.
 * For a selected number of user/kernel VM API, we strip addresses of metadata on
 * behalf of the user. These are APIs that are normally called by consumers on the
 * result of e.g. malloc()'ed addresses (which would now be tagged under MTE) and
 * therefore we strip the address on behalf of the consumer. "Destructive" APIs
 * and internal VM APIs, though, should never receive a tagged address. This option
 * turns on panic'ing (rather than graciously failing) for this scenario, to help
 * squash away bugs.
 */
#define mte_panic_on_non_canonical()     improbable_static_if(mte_panic_on_non_canonical)
/*
 * Software asynchronous tag check faults can be a nightmare to triage. Until we
 * get better telemetry, allow to trigger a panic rather than just killing the
 * victim task.
 */
#define mte_panic_on_async_fault()        improbable_static_if(mte_panic_on_async_fault)

#else /* DEVELOPMENT || DEBUG */
#define MTE_CONFIG_ON_RELEASE(name, state)              \
	static inline bool                          \
	name(void) {                                \
	    return (state);                         \
	}

MTE_CONFIG_ON_RELEASE(mte_kern_enabled, true)
MTE_CONFIG_ON_RELEASE(mte_kern_data_enabled, true)
MTE_CONFIG_ON_RELEASE(mte_user_enabled, true)
MTE_CONFIG_ON_RELEASE(mte_user_data_enabled, true)

#endif /* DEVELOPMENT || DEBUG || KASAN */

/*
 * While we could theoretically boot with user MTE enabled and kernel MTE (tagging)
 * disabled, we are never really going to, so let's save some distasteful codegen across
 * the board.
 */
#define mte_enabled()                           (mte_kern_enabled())

#ifndef MTE_EXCLUDE_MASK_T
#define MTE_EXCLUDE_MASK_T
typedef uint64_t mte_exclude_mask_t;
#endif /* MTE_EXCLUDE_MASK_T */

/*
 * Generate a random tag out of default best effort exclude mask.
 * Assign the generated tag to both pointer and backing storage.
 */
extern caddr_t mte_generate_and_store_tag(caddr_t target, size_t size) __attribute__((overloadable));

/*
 * Generate a random tag out of a caller supplied exclude mask.
 * Assign the generated tag to both pointer and backing storage.
 */
extern caddr_t mte_generate_and_store_tag(caddr_t target, size_t size, mte_exclude_mask_t mask) __attribute__((overloadable));

/*
 * Disable tag checking over a user task, in order to support MTE soft mode.
 */
extern void mte_disable_user_checking(task_t);

/*
 * MTE bulk operations.
 * These function allow to read and set (potentially) non-identical sequences
 * of tags from a given range. They leverage STGM/LDGM, therefore require
 * 256 bytes alignment.
 *
 * They take as parameter the va the operation should start from, the amount of memory
 * to cover, the source/destination of tags in units of mte_bulk_taglist_t and
 * the size of the source/destination buffer. Buffer is expected to be exactly matched
 * to the amount of tags that need to be read/written.
 */
typedef uint64_t mte_bulk_taglist_t;

/* LDGM and STGM are privileged instructions. */
static inline void
mte_store_tag_256(caddr_t addr, mte_bulk_taglist_t tag_list)
{
	__asm__ __volatile__ ("stgm %0, [%1]" : "+r" (tag_list) : "r" (addr) : "memory");
}

static inline mte_bulk_taglist_t
mte_load_tag_256(caddr_t addr)
{
	mte_bulk_taglist_t tag_list = 0;
	__asm__ __volatile__ ("ldgm %0, [%1]" : "+r" (tag_list) : "r" (addr) : "memory");

	return tag_list;
}

#define MTE_BULK_TAGLIST_BUF_SIZE(size)         MTE_SIZE_TO_ATAG_STORAGE(size) / sizeof (mte_bulk_taglist_t)
#define MTE_BULK_DECLARE_TAGLIST(name, size)    mte_bulk_taglist_t name[MTE_BULK_TAGLIST_BUF_SIZE(size)]

extern void mte_bulk_read_tags(caddr_t va, size_t va_size, mte_bulk_taglist_t * buffer, size_t buf_size);
extern void mte_bulk_write_tags(caddr_t va, size_t va_size, mte_bulk_taglist_t * buffer, size_t buf_size);

/* Copy tags from one va to the other. Mappings are expected to target different physical addresses */
extern void mte_copy_tags(caddr_t dest, caddr_t source, vm_size_t size);

/* If panic_on_canonical is enabled, report a detected non-canonical address where unexpected */
extern void mte_report_non_canonical_address(caddr_t address, vm_map_t map, const char *location);

/* MTE exceptions */
extern void mte_guard_ast(thread_t thread, mach_exception_data_type_t code, mach_exception_data_type_t subcode);


#endif /* XNU_KERNEL_PRIVATE */

__END_DECLS

#endif /* HAS_MTE */

#endif /* _ARM64_MTE_XNU_H_ */
