/*
 * Copyright (c) 2000-2020 Apple Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */

#ifdef  XNU_KERNEL_PRIVATE

#ifndef _KERN_STARTUP_H_
#define _KERN_STARTUP_H_

#include <stdbool.h>
#include <stdint.h>

#include <libkern/section_keywords.h>

__BEGIN_DECLS

#pragma GCC visibility push(hidden)

/*!
 * @enum startup_subsystem_id_t
 *
 * @abstract
 * Represents a stage of kernel intialization, ubnd allows for subsystems
 * to register initializers for a specific stage.
 *
 * @discussion
 * Documentation of each subsystem initialization sequence exists in
 * @file doc/startup.md.
 */
__enum_decl(startup_subsystem_id_t, uint32_t, {
	STARTUP_SUB_NONE = 0,         /**< reserved for the startup subsystem  */

	STARTUP_SUB_TUNABLES,         /**< support for the tunables subsystem  */
	STARTUP_SUB_TIMEOUTS,         /**< configurable machine timeouts       */
	STARTUP_SUB_LOCKS_EARLY,      /**< early locking, before zalloc        */
	STARTUP_SUB_KPRINTF,          /**< kprintf initialization              */

	STARTUP_SUB_PMAP_STEAL,       /**< to perform various pmap carveouts   */
	STARTUP_SUB_VM_KERNEL,        /**< once the kernel VM is ready         */
	STARTUP_SUB_KMEM,             /**< once kmem is ready                  */
	STARTUP_SUB_KMEM_ALLOC,       /**< once kmem_alloc is ready            */
	STARTUP_SUB_ZALLOC,           /**< initialize zalloc and kalloc        */
	STARTUP_SUB_PERCPU,           /**< initialize the percpu subsystem     */
	STARTUP_SUB_LOCKS,            /**< various subsystem locks             */

	STARTUP_SUB_CODESIGNING,      /**< codesigning subsystem               */
	STARTUP_SUB_OSLOG,            /**< oslog and kernel loggging           */
	STARTUP_SUB_MACH_IPC,         /**< Mach IPC                            */
	STARTUP_SUB_THREAD_CALL,      /**< Thread calls                        */
	STARTUP_SUB_SYSCTL,           /**< registers sysctls                   */
	STARTUP_SUB_EARLY_BOOT,       /**< interrupts/premption are turned on  */

	STARTUP_SUB_LOCKDOWN = ~0u,   /**< reserved for the startup subsystem  */
});

/*!
 * Stores the last subsystem to have been fully initialized;
 */
extern startup_subsystem_id_t startup_phase;

/*!
 * @enum startup_debug_t
 *
 * @abstract
 * Flags set in the @c startup_debug global to configure startup debugging.
 */
__options_decl(startup_debug_t, uint32_t, {
	STARTUP_DEBUG_NONE    = 0x00000000,
	STARTUP_DEBUG_VERBOSE = 0x00000001,
});

extern startup_debug_t startup_debug;

/*!
 * @enum startup_rank
 *
 * @abstract
 * Specifies in which rank a given initializer runs within a given section
 * to register initializers for a specific rank within the subsystem.
 *
 * @description
 * A startup function, declared with @c STARTUP or @c STARTUP_ARG, can specify
 * an rank within the subsystem they initialize.
 *
 * @c STARTUP_RANK_NTH(n) will let callbacks be run at stage @c n (0-based).
 *
 * @c STARTUP_RANK_FIRST, @c STARTUP_RANK_SECOND, @c STARTUP_RANK_THIRD and
 * @c STARTUP_RANK_FOURTH are given as conveniency names for these.
 *
 * @c STARTUP_RANK_MIDDLE is a reserved value that will let startup functions
 * run after all the @c STARTUP_RANK_NTH(n) ones have.
 *
 * @c STARTUP_RANK_NTH_LATE_NTH(n) will let callbacks be run then in @c n rank
 * after the @c STARTUP_RANK_MIDDLE ones (0-based).
 *
 * @c STARTUP_RANK_LAST callbacks will run absolutely last after everything
 * else did for this subsystem.
 */
__enum_decl(startup_rank_t, uint32_t, {
#define STARTUP_RANK_NTH(n) \
	(enum startup_rank)(n)
	STARTUP_RANK_FIRST          = 0,
	STARTUP_RANK_SECOND         = 1,
	STARTUP_RANK_THIRD          = 2,
	STARTUP_RANK_FOURTH         = 3,

	STARTUP_RANK_MIDDLE         = 0x7fffffff,

#define STARTUP_RANK_LATE_NTH(n) \
	(enum startup_rank)(STARTUP_RANK_MIDDLE + 1 + (n))

	STARTUP_RANK_LAST           = 0xffffffff,
});

#if KASAN
/*
 * The use of weird sections that get unmapped confuse the hell out of kasan,
 * so for KASAN leave things in regular __TEXT/__DATA segments
 */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__DATA,__init"
#define STARTUP_HOOK_SEGMENT "__DATA"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#elif defined(__x86_64__)
/* Intel doesn't have a __BOOTDATA but doesn't protect __KLD */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__KLDDATA,__init"
#define STARTUP_HOOK_SEGMENT "__KLDDATA"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#else
/* arm protects __KLD early, so use __BOOTDATA for data */
#define STARTUP_CODE_SEGSECT "__TEXT,__text"
#define STARTUP_DATA_SEGSECT "__BOOTDATA,__init"
#define STARTUP_HOOK_SEGMENT "__BOOTDATA"
#define STARTUP_HOOK_SECTION "__init_entry_set"
#endif

/*!
 * @macro __startup_func
 *
 * @abstract
 * Attribute to place on functions used only during the kernel startup phase.
 *
 * @description
 * Code marked with this attribute will be unmapped after kernel lockdown.
 */
#define __startup_func \
	__PLACE_IN_SECTION(STARTUP_CODE_SEGSECT) \
	__attribute__((cold, visibility("hidden")))

/*!
 * @macro __startup_data
 *
 * @abstract
 * Attribute to place on globals used during the kernel startup phase.
 *
 * @description
 * Data marked with this attribute will be unmapped after kernel lockdown.
 */
#define __startup_data \
	__PLACE_IN_SECTION(STARTUP_DATA_SEGSECT)

/*!
 * @macro STARTUP
 *
 * @abstract
 * Declares a kernel startup callback.
 */
#define STARTUP(subsystem, rank, func) \
	__STARTUP(func, __LINE__, subsystem, rank, func)

/*!
 * @macro STARTUP_ARG
 *
 * @abstract
 * Declares a kernel startup callback that takes an argument.
 */
#define STARTUP_ARG(subsystem, rank, func, arg) \
	__STARTUP_ARG(func, __LINE__, subsystem, rank, func, arg)

/*!
 * @macro TUNABLE
 *
 * @abstract
 * Declares a read-only kernel tunable that is read from a boot-arg with
 * a default value, without further processing.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param boot_arg
 * The name of the boot-arg to parse for initialization
 *
 * @param default_value
 * The default value for the tunable if the boot-arg is absent.
 */
#define TUNABLE(type_t, var, boot_arg, default_value) \
	SECURITY_READ_ONLY_LATE(type_t) var = default_value; \
	__TUNABLE(type_t, var, boot_arg)

/*!
 * @macro TUNABLE_WRITEABLE
 *
 * @abstract
 * Declares a writeable kernel tunable that is read from a boot-arg with
 * a default value, without further processing.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param boot_arg
 * The name of the boot-arg to parse for initialization
 *
 * @param default_value
 * The default value for the tunable if the boot-arg is absent.
 */
#define TUNABLE_WRITEABLE(type_t, var, boot_arg, default_value) \
	type_t var = default_value; \
	__TUNABLE(type_t, var, boot_arg)

#if DEBUG || DEVELOPMENT
#define TUNABLE_DEV_WRITEABLE(type_t, var, boot_arg, default_value) \
	TUNABLE_WRITEABLE(type_t, var, boot_arg, default_value)
#else
#define TUNABLE_DEV_WRITEABLE(type_t, var, boot_arg, default_value) \
	TUNABLE(type_t, var, boot_arg, default_value)
#endif

/*!
 * @macro TUNABLE_STR
 *
 * @abstract
 * Declares a read-only kernel tunable that is read from a boot-arg with
 * a default value, without further processing.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param count
 * The number of bytes in the buffer.
 *
 * @param boot_arg
 * The name of the boot-arg to parse for initialization
 *
 * @param default_value
 * The default value for the tunable if the boot-arg is absent.
 */
#define TUNABLE_STR(var, count, boot_arg, default_value) \
	char __security_const_late var[count] = default_value; \
	__TUNABLE_STR(var, boot_arg)

/*!
 * @enum tunable_dt_flags_t
 *
 * @abstract
 * Flags used with the @c TUNABLE_DT* macros.
 *
 * @description
 * If TUNABLE_DT_CHECK_CHOSEN is set, a value in
 * /chosen/<dt_base>/<dt_name> takes precedence over any value in
 * /<dt_base>/<dt_name>. /chosen is by convention the area where
 * synthesized values not coming from the serialized device tree are
 * being added, so this provides a way for e.g. the boot-loader to
 * set/override tunables.
 */
__options_decl(tunable_dt_flags_t, uint32_t, {
	TUNABLE_DT_NONE         = 0x00000000,
	TUNABLE_DT_CHECK_CHOSEN = 0x00000001,
});

/*!
 * @macro TUNABLE_DT
 *
 * @abstract
 * Like TUNABLE, but gets the initial value from both Device Tree and
 * boot-args. The order in which the initial value is resolved is as
 * follows, with later steps overriding previous ones (if they are
 * specified):
 *
 * 1. Device Tree Entry "/<dt_base>/<dt_name>",
 * 2. If TUNABLE_DT_CHECK_CHOSEN is set, Device Tree Entry
 *    "/chosen/<dt_base>/<dt_name>" (see the description for
 *    @c tunable_dt_flags_t),
 * 3. boot-args.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param dt_base
 * The name of the DT node containing the property.
 *
 * @param dt_name
 * The name of the DT property containing the default value.
 *
 * @param boot_arg
 * The name of the boot-arg overriding the initial value from the DT.
 *
 * @param default_value
 * The default value for the tunable if both DT entry and boot-arg are
 * absent.
 *
 * @param flags
 * See the description for @c tunable_dt_flags_t.
 */
#define TUNABLE_DT(type_t, var, dt_base, dt_name, boot_arg, default_value, flags) \
	SECURITY_READ_ONLY_LATE(type_t) var = default_value; \
	__TUNABLE_DT(type_t, var, dt_base, dt_name, boot_arg, flags)

/*!
 * @macro TUNABLE_DT_WRITEABLE
 *
 * @abstract
 * Like TUNABLE_WRITEABLE, but gets the initial value from both Device
 * Tree and boot-args. The order in which the initial value is
 * resolved is as follows, with later steps overriding previous ones
 * (if they are specified):
 *
 * 1. Device Tree Entry "/<dt_base>/<dt_name>",
 * 2. If TUNABLE_DT_CHECK_CHOSEN is set, Device Tree Entry
 *    "/chosen/<dt_base>/<dt_name>" (see the description for
 *    @c tunable_dt_flags_t),
 * 3. boot-args.
 *
 * @param type_t
 * Should be an integer type or bool.
 *
 * @param var
 * The name of the C variable to use for storage.
 *
 * @param dt_base
 * The name of the DT node containing the property.
 *
 * @param dt_name
 * The name of the DT property containing the default value.
 *
 * @param boot_arg
 * The name of the boot-arg overriding the initial value from the DT.
 *
 * @param default_value
 * The default value for the tunable if both DT entry and boot-arg are
 * absent.
 *
 * @param flags
 * See the description for @c tunable_dt_flags_t.
 */
#define TUNABLE_DT_WRITEABLE(type_t, var, dt_base, dt_name, boot_arg, default_value, flags) \
	type_t var = default_value; \
	__TUNABLE_DT(type_t, var, dt_base, dt_name, boot_arg, flags)

/*
 * Machine Timeouts
 *
 * Machine Timeouts are timeouts for low level kernel code manifesting
 * as _Atomic uint64_t variables, whose default value can be
 * overridden and scaled via the device tree and boot-args.
 *
 * Each timeout has a name, looked up directly as the property name in
 * the device tree in both the "/machine-timeouts" and
 * "/chosen/machine-timeouts" nodes. The "chosen" property always
 * overrides the other one. This allows fixed per-device timeouts in
 * the device tree to be overridden by iBoot in "chosen".
 *
 * Additionally, the same name with "-scale" appended is looked up as
 * properties for optional scale factors. Scale factors are not
 * overridden by chosen, instead all scale factors (including global
 * and/or boot-arg scale factors) combine by multiplication.
 *
 * The special name "global-scale" provides a scale that applies to
 * every timeout.
 *
 * All property names can be used as boot-args by prefixing
 * "ml-timeout-", e.g. th global scale is available as the
 * "ml-timeout-global-scale" boot-arg.
 *
 * By convention, if the timeout value resolves to 0, the timeout
 * should be disabled.
 */

/*
 * Machine Timeouts types. See the next section for what unit
 * they are in.
 *
 * We use _Atomic, but only with relaxed ordering: This is just to
 * make sure all devices see consistent values all the time.  Since
 * the actual timeout value will be seen as 0 before initializaton,
 * relaxed ordering means that code that runs concurrently with
 * initialization only risks to see a disabled timeout during early
 * boot.
 *
 * On 64bit devices, _Atomic with relaxed should have no effect.  On
 * 32bit devices, _Atomic uint64_t will incur synchronization, so it
 * might be better to use machine_timeout32_t instead.
 */
typedef _Atomic uint64_t machine_timeout_t;
typedef _Atomic uint32_t machine_timeout32_t;

/*
 * Units
 *
 * Machine Timeouts are ALWAYS in picoseconds in the device tree or
 * boot-args, to avoid confusion when changing or comparing timeouts
 * as a user, but the actual storage value might contain the same
 * duration in another unit, calculated by the initialization code.
 *
 * This is done because otherwise we would likely introduce another
 * multiplication in potentially hot code paths, given that code that
 * actually uses the timeout storage variable is unlikely to work with
 * picosecond values when comparing against the timeout deadline.
 *
 * This unit scale is *only* applied during initialization at early
 * boot, and only if the timeout's default value was overridden
 * through the device tree or a boot-arg.
 */
#define MACHINE_TIMEOUT_UNIT_PSEC 1
#define MACHINE_TIMEOUT_UNIT_NSEC 1000
#define MACHINE_TIMEOUT_UNIT_USEC (1000*1000)
#define MACHINE_TIMEOUT_UNIT_MSEC (1000*1000*1000)
// Special unit for timebase ticks (usually 1/24MHz)
#define MACHINE_TIMEOUT_UNIT_TIMEBASE 0

// DT property names are limited to 31 chars, minus "-global" suffix
#define MACHINE_TIMEOUT_MAX_NAME_LEN 25
struct machine_timeout_spec {
	void *ptr;
	uint64_t default_value;
	uint64_t unit_scale;
	bool is32;
	char name[MACHINE_TIMEOUT_MAX_NAME_LEN + 1];
	bool (*skip_predicate)(struct machine_timeout_spec const *);
};

extern void
machine_timeout_init_with_suffix(const struct machine_timeout_spec *spec, char const *phase_suffix);

extern void
machine_timeout_init(const struct machine_timeout_spec *spec);

// Late timeout (re-)initialization, at the end of bsd_init()
extern void
machine_timeout_bsd_init(void);

/*!
 * @macro MACHINE_TIMEOUT and MACHINE_TIMEOUT_WRITEABLE
 *
 * @abstract
 * Defines a Machine Timeout that can be overridden and
 * scaled through the device tree and boot-args.
 *
 * The variant with the _WRITEABLE suffix does not mark the timeout as
 * SECURITY_READ_ONLY_LATE, so that e.g. machine_timeout_init_with_suffix
 * or sysctls can change it after lockdown.
 *
 * @param var
 * The name of the C variable to use for storage. If the storage value
 * contains 0, the timeout is considered disabled by convention.
 *
 * @param timeout_name
 * The name of the timeout, used for property and boot-arg names. See
 * the general description of Machine Timeouts above for how this name
 * ends up being used.
 *
 * @param timeout_default
 * The default value for the timeout if not specified through device
 * tree or boot-arg. Will still be scaled if a scale factor exists.
 *
 * @param var_unit
 * The unit that the storage variable is in. Note that timeout values
 * must always be specified as picoseconds in the device tree and
 * boot-args, but timeout initialization will convert the value to the
 * unit specified here before writing it to the storage variable.
 *
 * @param skip_predicate
 * Optionally, a function to call to decide whether the timeout should
 * be set or not.  If NULL, the timeout will always be set (if
 * specified anywhere). A predicate has the following signature:
 *     bool skip_predicate (struct machine_timeout_spec const *)
 */

#define _MACHINE_TIMEOUT(var, timeout_name, timeout_default, var_unit, var_is32, skip_pred) \
	struct machine_timeout_spec \
	__machine_timeout_spec_ ## var = { \
	        .ptr = &var, \
	        .default_value = timeout_default, \
	        .unit_scale = var_unit, \
	        .is32 = var_is32, \
	        .name = timeout_name, \
	        .skip_predicate = skip_pred, \
	}; \
	__STARTUP_ARG(var, __LINE__, TIMEOUTS, STARTUP_RANK_FIRST, \
	    machine_timeout_init, &__machine_timeout_spec_ ## var)

#define MACHINE_TIMEOUT(var, name, default, unit, skip_predicate)       \
	SECURITY_READ_ONLY_LATE(machine_timeout_t) var = 0;                                     \
	_MACHINE_TIMEOUT(var, name, default, unit, false, skip_predicate)

#define MACHINE_TIMEOUT32(var, name, default, unit, skip_predicate)     \
	SECURITY_READ_ONLY_LATE(machine_timeout32_t) var = 0;                           \
	_MACHINE_TIMEOUT(var, name, default, unit, true, skip_predicate)

#define MACHINE_TIMEOUT_WRITEABLE(var, name, default, unit, skip_predicate)       \
	machine_timeout_t var = 0; \
	_MACHINE_TIMEOUT(var, name, default, unit, false, skip_predicate)

#define MACHINE_TIMEOUT32_WRITEABLE(var, name, default, unit, skip_predicate)     \
	machine_timeout32_t var = 0; \
	_MACHINE_TIMEOUT(var, name, default, unit, true, skip_predicate)

/*!
 * @macro MACHINE_TIMEOUT_SPEC_REF
 *
 * @abstract
 * References a previously defined MACHINE_TIMEOUT or
 * MACHINE_TIMEOUT32.  This is primarily useful for overriding
 * individual timeouts at arbitrary times (even after boot), by
 * manually calling machine_timeout_init_with_suffix() with this macro
 * as first argument, and a suffix to apply to both device tree and
 * boot-arg as second argument.
 *
 * @param var
 * The name of the C variable used for storage, as it was specified
 * in MACHINE_TIMEOUT or MACHINE_TIMEOUT32.
 */
#define MACHINE_TIMEOUT_SPEC_REF(var) (&__machine_timeout_spec_ ## var)

/*!
 * @macro MACHINE_TIMEOUT_SPEC_DECL
 *
 * @abstract
 * Declaration of machine timeout spec, mostly useful to make it known
 * for MACHINE_TIMEOUT_SPEC_REF.
 *
 * @param var
 * The name of the C variable used for storage, as it was specified
 * in MACHINE_TIMEOUT or MACHINE_TIMEOUT32.
 */
#define MACHINE_TIMEOUT_SPEC_DECL(var) extern struct machine_timeout_spec __machine_timeout_spec_ ## var

#if DEBUG || DEVELOPMENT

/*!
 * @macro SYSCTL_TEST_REGISTER
 *
 * @abstract
 * Declares a test that will appear under @c debug.test.${name}.
 *
 * @param name
 * An indentifier that will be stringified to form the sysctl test name.
 *
 * @param cb
 * The callback to run, of type:
 * <code>
 *     int (callback *)(int64_t value, int64_t *);
 * </code>
 */
#define SYSCTL_TEST_REGISTER(name, cb) \
	static __startup_data struct sysctl_test_setup_spec \
	__startup_SYSCTL_TEST_ ## name = { \
	        .st_name = #name, \
	        .st_func = &cb, \
	}; \
	STARTUP_ARG(SYSCTL, STARTUP_RANK_MIDDLE, \
	    sysctl_register_test_startup, &__startup_SYSCTL_TEST_ ## name)

#endif /* DEBUG || DEVELOPMENT */
#pragma mark - internals

__END_DECLS

#ifdef __cplusplus
template <typename T>
struct __startup_tunable {
	static const bool value  = false;
};

template <>
struct __startup_tunable <bool>{
	static const bool value = true;
};
#define __startup_type_is_bool(type_t) __startup_tunable<type_t>::value
#else
#define __startup_type_is_bool(type_t) __builtin_types_compatible_p(bool, type_t)
#endif

__BEGIN_DECLS

#define __TUNABLE(type_t, var, key) \
	static __startup_data char __startup_TUNABLES_name_ ## var[] = key; \
	static __startup_data struct startup_tunable_spec \
	__startup_TUNABLES_spec_ ## var = { \
	        .name = __startup_TUNABLES_name_ ## var, \
	        .var_addr = (void *)&var, \
	        .var_len = sizeof(type_t), \
	        .var_is_bool = __startup_type_is_bool(type_t), \
	}; \
	__STARTUP_ARG(var, __LINE__, TUNABLES, STARTUP_RANK_FIRST, \
	    kernel_startup_tunable_init, &__startup_TUNABLES_spec_ ## var)

#define __TUNABLE_STR(var, key) \
	static __startup_data char __startup_TUNABLES_name_ ## var[] = key; \
	static __startup_data struct startup_tunable_spec \
	__startup_TUNABLES_spec_ ## var = { \
	        .name = __startup_TUNABLES_name_ ## var, \
	        .var_addr = (void *)&var, \
	        .var_len = sizeof(var), \
	        .var_is_str = true, \
	}; \
	__STARTUP_ARG(var, __LINE__, TUNABLES, STARTUP_RANK_FIRST, \
	    kernel_startup_tunable_init, &__startup_TUNABLES_spec_ ## var)

#define __TUNABLE_DT(type_t, var, dt_base_key, dt_name_key, boot_arg_key, flags) \
	static __startup_data char __startup_TUNABLES_dt_base_ ## var[] = dt_base_key; \
	static __startup_data char __startup_TUNABLES_dt_name_ ## var[] = dt_name_key; \
	static __startup_data char __startup_TUNABLES_name_ ## var[] = boot_arg_key; \
	static __startup_data struct startup_tunable_dt_spec \
	__startup_TUNABLES_DT_spec_ ## var = { \
	        .dt_base = __startup_TUNABLES_dt_base_ ## var, \
	        .dt_name = __startup_TUNABLES_dt_name_ ## var, \
	        .dt_chosen_override = (bool)((flags) & TUNABLE_DT_CHECK_CHOSEN), \
	        .boot_arg_name = __startup_TUNABLES_name_ ## var, \
	        .var_addr = (void *)&var, \
	        .var_len = sizeof(type_t), \
	        .var_is_bool = __startup_type_is_bool(type_t), \
	}; \
	__STARTUP_ARG(var, __LINE__, TUNABLES, STARTUP_RANK_FIRST, \
	    kernel_startup_tunable_dt_init, &__startup_TUNABLES_DT_spec_ ## var)

#ifdef __cplusplus
#define __STARTUP_FUNC_CAST(func, a) \
	    (void(*)(const void *))func
#else
#define __STARTUP_FUNC_CAST(func, a) \
	    (typeof(func(a))(*)(const void *))func
#endif


#define __STARTUP1(name, line, subsystem, rank, func, a, b) \
	__PLACE_IN_SECTION(STARTUP_HOOK_SEGMENT "," STARTUP_HOOK_SECTION) \
	static const struct startup_entry \
	__startup_ ## subsystem ## _entry_ ## name ## _ ## line = { \
	    STARTUP_SUB_ ## subsystem, \
	    rank, __STARTUP_FUNC_CAST(func, a), b, \
	}

#define __STARTUP(name, line, subsystem, rank, func) \
	__STARTUP1(name, line, subsystem, rank, func, , NULL)

#define __STARTUP_ARG(name, line, subsystem, rank, func, arg) \
	__STARTUP1(name, line, subsystem, rank, func, arg, arg)

struct startup_entry {
	startup_subsystem_id_t subsystem;
	startup_rank_t         rank;
	void                 (*func)(const void *);
	const void            *arg;
};

struct startup_tunable_spec {
	const char *name;
	void       *var_addr;
	int         var_len;
	bool        var_is_bool;
	bool        var_is_str;
};

struct startup_tunable_dt_spec {
	const char *dt_base;
	const char *dt_name;
	bool        dt_chosen_override;
	const char *boot_arg_name;
	void       *var_addr;
	int         var_len;
	bool        var_is_bool;
};

#if DEBUG || DEVELOPMENT
struct sysctl_test_setup_spec {
	const char *st_name;
	int (*st_func)(int64_t, int64_t *);
};

extern void sysctl_register_test_startup(
	struct sysctl_test_setup_spec *spec);
#endif /* DEBUG || DEVELOPMENT */

/*
 * Kernel and machine startup declarations
 */

/* Initialize kernel */
extern void kernel_startup_bootstrap(void);
extern void kernel_startup_initialize_upto(startup_subsystem_id_t upto);
extern void kernel_startup_tunable_init(const struct startup_tunable_spec *);
extern void kernel_startup_tunable_dt_init(const struct startup_tunable_dt_spec *);
extern void kernel_bootstrap(void);

/* Initialize machine dependent stuff */
extern void machine_init(void);

extern void slave_main(void *machine_param);

/*
 * The following must be implemented in machine dependent code.
 */

/* Slave cpu initialization */
extern void slave_machine_init(void *machine_param);

/* Device subystem initialization */
extern void device_service_create(void);

#ifdef  MACH_BSD

/* BSD subsystem initialization */
extern void bsd_init(void);

#endif  /* MACH_BSD */

#pragma GCC visibility pop

__END_DECLS

#endif  /* _KERN_STARTUP_H_ */

#endif  /* XNU_KERNEL_PRIVATE */
