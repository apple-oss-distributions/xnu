/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
#ifndef _PEXPERT_ARM64_PLATFORM_H_
#define _PEXPERT_ARM64_PLATFORM_H_

/*
 * EmbeddedHeaders defines required: SPDS_ENABLE_STRUCTS and SPDS_ENABLE_ENUMS.
 */

#ifndef SPDS_ENABLE_STRUCTS
#define SPDS_ENABLE_STRUCTS                     1       // Enable structure definitions
#endif /* SPDS_ENABLE_STRUCTS */
#ifndef SPDS_ENABLE_ENUMS
#define SPDS_ENABLE_ENUMS                       1       // Enable enumeration definitions
#endif /* SPDS_ENABLE_ENUMS */

#pragma mark EmbeddedHeaders include macros
/*
 * Define a macro to construct an include path for a sub-platform file.
 * Example: #include SUB_PLATFORM_SPDS_HEADER(p_acc)
 * where ARM64_SOC_NAME is txxxx, and where SPDS_CHIP_REV_LC is a0
 * Expands: #include <soc/txxxx/a0/module/p_acc.h>
 * Lifted and adapted from iBoot/platform.h.
 */
#define NOQUOTE(x) x
#define COMBINE3(a, b, c)                       NOQUOTE(a)NOQUOTE(b)NOQUOTE(c)
#define COMBINE5(a, b, c, d, e)                 NOQUOTE(a)NOQUOTE(b)NOQUOTE(c)NOQUOTE(d)NOQUOTE(e)
#define COMBINE7(a, b, c, d, e, f, g)           NOQUOTE(a)NOQUOTE(b)NOQUOTE(c)NOQUOTE(d)NOQUOTE(e)NOQUOTE(f)NOQUOTE(g)

#define SUB_PLATFORM_HEADER(x)                  <COMBINE5(platform/,x,_,ARM64_SOC_NAME,.h)>
#define SUB_PLATFORM_SOC_HEADER(x)              <COMBINE5(platform/soc/,x,_,ARM64_SOC_NAME,.h)>
#define SUB_PLATFORM_NONMODULE_HEADER(x)        <COMBINE5(soc/,PLATFORM_SPDS_CHIP_REV_LC,/,x,.h)>
#define SUB_PLATFORM_SPDS_HEADER(x)             <COMBINE5(soc/,PLATFORM_SPDS_CHIP_REV_LC,/module/,x,.h)>
#define SUB_PLATFORM_TARGET_HEADER(x)           <COMBINE5(target/,x,_,ARM64_SOC_NAME,.h)>
#define SUB_PLATFORM_TUNABLE_HEADER(r, x)       <COMBINE7(platform/soc/tunables/,ARM64_SOC_NAME,/,r,/,x,.h)>
#define SUB_TARGET_TUNABLE_HEADER(r, t, x)      <COMBINE7(target/tunables/,t,/,r,/,x,.h)>

#ifndef ARM64_SOC_NAME
#ifndef CURRENT_MACHINE_CONFIG_LC
#error CURRENT_MACHINE_CONFIG_LC must be defined in makedefs/MakeInc.def
#endif
#define ARM64_SOC_NAME CURRENT_MACHINE_CONFIG_LC
#endif /* ARM64_SOC_NAME */

// rdar://72605444 (EmbeddedHeaders per SoC symlink to newest chip revision: <soc/txxxx/latest>)
#define SPDS_CHIP_REV_LC a0 // default
#define PLATFORM_SPDS_CHIP_REV_LC ARM64_SOC_NAME/SPDS_CHIP_REV_LC

#endif /* !_PEXPERT_ARM64_PLATFORM_H_ */
