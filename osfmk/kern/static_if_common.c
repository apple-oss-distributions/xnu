/* * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef STATIC_IF_TEST
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/startup.h>
#include <machine/static_if.h>
#include <machine/machine_routines.h>


extern struct static_if_entry __static_if_entries[]
__SECTION_START_SYM(STATIC_IF_SEGMENT, STATIC_IF_SECTION);

extern struct static_if_entry __static_if_entries_end[]
__SECTION_END_SYM(STATIC_IF_SEGMENT, STATIC_IF_SECTION);

extern static_if_initializer __static_if_initializer_entries[]
__SECTION_START_SYM(STATIC_IF_SEGMENT, STATIC_IFINIT_SECTION);

extern static_if_initializer __static_if_initializer_entries_end[]
__SECTION_END_SYM(STATIC_IF_SEGMENT, STATIC_IFINIT_SECTION);


#endif /* STATIC_IF_TEST */
#pragma mark boot-arg parsing

/*
 * On SPTM targets we can't use PE_parse_boot_argn() because it isn't part
 * of __BOOT_TEXT, so we need to roll our own.
 *
 * We can't use TUNABLES() yet either because they won't have been initialized.
 */

__attribute__((always_inline))
static inline bool
isargsep(char c)
{
	return c == ' ' || c == '\0' || c == '\t';
}

__attribute__((always_inline))
static const char *
skip_seps(const char *s)
{
	while (*s && isargsep(*s)) {
		s++;
	}
	return s;
}

__attribute__((always_inline))
static const char *
skip_to_sep(const char *s)
{
	while (!isargsep(*s)) {
		s++;
	}
	return s;
}

__attribute__((always_inline))
static inline bool
skip_prefix(const char *args, const char *key, const char **argsout)
{
	while (*key) {
		if (*args != *key) {
			return false;
		}
		args++;
		key++;
	}

	*argsout = args;
	return true;
}

__attribute__((always_inline))
static inline const char *
get_val(const char *s, uint64_t *val)
{
	uint64_t radix = 10;
	uint64_t v;
	int sign = 1;

	if (isargsep(*s)) {
		/* "... key ..." is the same as "... key=1 ..." */
		*val = 1;
		return s;
	}

	if (*s != '=') {
		/* if not followed by a = then this is garbage */
		return s;
	}
	s++;

	if (*s == '-') {
		sign = -1;
		s++;
	}

	if (isargsep(*s)) {
		/* "... key=- ..." is malfomed */
		return s;
	}

	v = (*s++ - '0');
	if (v == 0) {
		switch (*s) {
		case 'x':
			radix = 16;
			s++;
			break;

		case 'b':
			radix = 2;
			s++;
			break;

		case '0' ... '7':
			radix = 8;
			break;

		default:
			if (!isargsep(*s)) {
				return s;
			}
			break;
		}
	} else if (v > radix) {
		return s;
	}

	for (;;) {
		if (*s >= '0' && *s <= '9' - (10 - radix)) {
			v = v * radix + *s - '0';
		} else if (radix == 16 && *s >= 'a' && *s <= 'f') {
			v = v * radix + 10 + *s - 'a';
		} else if (radix == 16 && *s >= 'A' && *s <= 'F') {
			v = v * radix + 10 + *s - 'A';
		} else {
			if (isargsep(*s)) {
				*val = v * sign;
			}
			return s;
		}

		s++;
	}
}

MARK_AS_FIXUP_TEXT uint64_t
static_if_boot_arg_uint64(const char *args, const char *key, uint64_t defval)
{
	uint64_t ret = defval;

	args = skip_seps(args);

	while (*args) {
		if (*args == '-' && skip_prefix(args + 1, key, &args)) {
			if (isargsep(*args)) {
				ret = TRUE;
			}
		} else if (skip_prefix(args, key, &args)) {
			args = get_val(args, &ret);
		}

		args = skip_to_sep(args);
		args = skip_seps(args);
	}

	return ret;
}


#pragma mark patching
#ifndef STATIC_IF_TEST

/*
 * static_if() is implemented using keys, which are data structures
 * of type `struct static_if_key`.
 *
 * These come in two concrete variants:
 * - struct static_if_key_true, for which the key starts enabled/true,
 * - struct static_if_key_false, for which the key starts disabled/false.
 *
 * Usage of static_if() and its variants use the following pattern:
 * (a) a result variable is initialized to 0 (resp 1),
 * (b) an asm goto() statement might jump to a label or fall through depending on
 *     the state of the key (implemented with STATIC_IF_{NOP,JUMP}),
 * (c) in the fall through code, the variable is set to 1 (resp 0).
 *
 * As a result these macros implement a boolean return that depend on whether
 * their assembly is currently a nop (in which case it will return the value
 * from (c)) or a branch (in which case it will return the value from (a)).
 *
 * STATIC_IF_NOP() and STATIC_IF_ENTRY() are machine dependent macros that emit
 * either a nop or a branch instruction, and generate a `struct static_if_entry`
 * which denote where this patchable instruction lives, and for which key.
 *
 * static_if_init() will run early and chain all these entries onto their key,
 * in order to enable static_if_key_{enable,disable} to be able to quickly patch
 * these instructions between nops and jumps.
 */

__attribute__((always_inline))
static inline void *
__static_if_entry_next(static_if_entry_t sie)
{
	return (void *)(sie->sie_link & ~3ul);
}

__attribute__((always_inline))
static inline bool
__static_if_is_jump(static_if_entry_t sie)
{
	return sie->sie_link & 1;
}


MARK_AS_FIXUP_TEXT void
static_if_init(const char *args)
{
	struct static_if_entry *sie = __static_if_entries_end;
	unsigned long sie_flags;
	static_if_key_t sie_key;

	while (--sie >= __static_if_entries) {
		sie_flags = sie->sie_link & 3ul;
		sie_key   = __static_if_entry_next(sie);
		sie->sie_link = (vm_offset_t)sie_key->sik_entries_head | sie_flags;

		sie_key->sik_entries_head = sie;
		sie_key->sik_entries_count++;
	}

	for (static_if_initializer *f = __static_if_initializer_entries;
	    f < __static_if_initializer_entries_end; f++) {
		(*f)(args);
	}

	ml_static_if_flush_icache();
}

MARK_AS_FIXUP_TEXT void
__static_if_key_delta(static_if_key_t key, int delta)
{
	/*
	 * On SPTM configuration, static_if_init() is called by
	 * arm_static_if_init() during the XNU fixup phase,
	 * before the XNU kernel text is retyped to SPTM_XNU_CODE
	 * and can't be modified anymore.
	 *
	 * For other platforms, this is called from kernel_startup_bootstrap()
	 */
	if (startup_phase >= STARTUP_SUB_TUNABLES) {
		panic("static_if_key_{enable,disable} called too late");
	}

	bool was_enabled = (key->sik_enable_count >= 0);

	key->sik_enable_count += delta;
	if (was_enabled != (key->sik_enable_count >= 0)) {
		static_if_entry_t sie = key->sik_entries_head;
		bool init_enabled = key->sik_init_value >= 0;

		while (sie) {
			ml_static_if_entry_patch(sie,
			    (was_enabled == init_enabled) ^
			    __static_if_is_jump(sie));
			sie = __static_if_entry_next(sie);
		}
	}
}

#endif /* STATIC_IF_TEST */
