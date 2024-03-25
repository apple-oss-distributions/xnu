/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#if CONFIG_EXCLAVES

#pragma once

#include <mach/exclaves.h>

#include <libkern/section_keywords.h>
#include <mach/kern_return.h>

#define EXCLAVES_BOOT_TASK_SEGMENT "__DATA_CONST"
#define EXCLAVES_BOOT_TASK_SECTION "__exclaves_bt"

__BEGIN_DECLS

__enum_decl(exclaves_boot_task_rank_t, uint32_t, {
	EXCLAVES_BOOT_RANK_FIRST          = 0,
	EXCLAVES_BOOT_RANK_SECOND         = 1,
	EXCLAVES_BOOT_RANK_THIRD          = 2,
	EXCLAVES_BOOT_RANK_FOURTH         = 3,

	EXCLAVES_BOOT_RANK_ANY            = 0x7fffffff,

	EXCLAVES_BOOT_RANK_LAST           = 0xffffffff,
});

typedef struct exclaves_boot_task_entry {
	kern_return_t (*ebt_func)(void);
	exclaves_boot_task_rank_t ebt_rank;
	const char *ebt_name;
} exclaves_boot_task_entry_t;

/* BEGIN IGNORE CODESTYLE */
#define __EXCLAVES_BOOT_TASK(name, line, rank, func)              \
	__PLACE_IN_SECTION(EXCLAVES_BOOT_TASK_SEGMENT ","         \
	    EXCLAVES_BOOT_TASK_SECTION)                           \
	static const exclaves_boot_task_entry_t                   \
	__exclaves_boot_task_entry_ ## name ## _ ## line = {      \
	    .ebt_func = func,                                     \
	    .ebt_rank = rank,                                     \
	    /* Used for  panic string. */                         \
	    .ebt_name = #name,                                    \
	}
/* END IGNORE CODESTYLE */

#define EXCLAVES_BOOT_TASK(func, rank)                            \
	__EXCLAVES_BOOT_TASK(func, __LINE__, rank, func)

/* Boot the requested boot stage. */
extern kern_return_t exclaves_boot(exclaves_boot_stage_t);

/*
 * Wait until the specified boot stage has been reached (or return
 * KERN_NOT_SUPPORTED immediately if exclaves are not supported)
 */
extern kern_return_t exclaves_boot_wait(exclaves_boot_stage_t);

__END_DECLS

#endif /* CONFIG_EXCLAVES */
