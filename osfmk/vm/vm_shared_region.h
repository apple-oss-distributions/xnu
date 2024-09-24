/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*
 *
 *	File: vm/vm_shared_region.h
 *
 *      protos and struct definitions for shared region
 */

#ifndef _VM_SHARED_REGION_H_
#define _VM_SHARED_REGION_H_

#ifdef  KERNEL_PRIVATE

#include <mach/vm_prot.h>
#include <mach/mach_types.h>
#include <mach/shared_region.h>

#include <kern/kern_types.h>
#include <kern/macro_help.h>

#include <vm/vm_map.h>

extern int shared_region_version;
extern int shared_region_persistence;

#if DEBUG
extern int shared_region_debug;
#define SHARED_REGION_DEBUG(args)               \
	MACRO_BEGIN                             \
	if (shared_region_debug) {              \
	        kprintf args;                   \
	}                                       \
	MACRO_END
#else /* DEBUG */
#define SHARED_REGION_DEBUG(args)
#endif /* DEBUG */

extern int shared_region_trace_level;

extern struct vm_shared_region *primary_system_shared_region;

#define SHARED_REGION_TRACE_NONE_LVL            0 /* no trace */
#define SHARED_REGION_TRACE_ERROR_LVL           1 /* trace abnormal events */
#define SHARED_REGION_TRACE_INFO_LVL            2 /* trace all events */
#define SHARED_REGION_TRACE_DEBUG_LVL           3 /* extra traces for debug */
#define SHARED_REGION_TRACE(level, args)                \
	MACRO_BEGIN                                     \
	if (shared_region_trace_level >= level) {       \
	        printf args;                            \
	}                                               \
	MACRO_END
#define SHARED_REGION_TRACE_NONE(args)
#define SHARED_REGION_TRACE_ERROR(args)                         \
	MACRO_BEGIN                                             \
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_ERROR_LVL,      \
	                    args);                              \
	MACRO_END
#define SHARED_REGION_TRACE_INFO(args)                          \
	MACRO_BEGIN                                             \
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_INFO_LVL,       \
	                    args);                              \
	MACRO_END
#define SHARED_REGION_TRACE_DEBUG(args)                         \
	MACRO_BEGIN                                             \
	SHARED_REGION_TRACE(SHARED_REGION_TRACE_DEBUG_LVL,      \
	                    args);                              \
	MACRO_END

typedef struct vm_shared_region *vm_shared_region_t;

#ifndef MACH_KERNEL_PRIVATE
struct vm_shared_region;
struct vm_shared_region_slide_info;
struct vm_shared_region_slide_info_entry;
struct slide_info_entry_toc;
#endif /* MACH_KERNEL_PRIVATE */

struct _sr_file_mappings {
	int                     fd;
	uint32_t                mappings_count;
	struct shared_file_mapping_slide_np *mappings;
	uint32_t                slide;
	struct fileproc         *fp;
	struct vnode            *vp;
	memory_object_size_t    file_size;
	memory_object_control_t file_control;
};


#endif /* KERNEL_PRIVATE */

#endif  /* _VM_SHARED_REGION_H_ */
