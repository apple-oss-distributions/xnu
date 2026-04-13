/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
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

#include "mocks/std_safe.h"
#include "mocks/dt_proxy.h"

// The normal XNU executable links to libsptm_xnu.a and libTightbeam.a for platforms that require it.
// The unit-test environment however isn't supposed to call into these libraries
// and can't link to them anyway because they are built for arch arm64.kernel, not arm64.
// Instead, the missing required symbols are discovered at build time and
// defined in this translation unit. It is also possible to create custom
// definitions for those functions (as it's done in fake_libsptm.c).
// This is done to satisfy the linker and to show an error if one of these function
// ends up being called.
// These definitions ignore the real return value and arguments of
// the functions to keep it simple, and the linker doesn't care.


#define UNIMPLEMENTED(name) void name(void) { PT_FAIL("unimplemented: " #name); }
#include "func_unimpl.inc"
#undef UNIMPLEMENTED
