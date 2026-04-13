/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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
 * Make sure we don't accidentally include the external definitions of
 * the routines we're interposing on below.
 */
#define _vm_map_user_
#define _mach_vm_user_
#include <mach/mach.h>
#include <mach/mach_traps.h>
#undef _vm_map_user_
#include <mach/vm_map_internal.h>
#undef _mach_vm_user_
#include <mach/mach_vm_internal.h>
#include <mach/vm_statistics.h>
#include <mach/vm_region_private.h>

#include "stack_logging_internal.h"

malloc_logger_t *__syscall_logger = NULL;   // This may get set by Libc's malloc stack logging initialization code.

kern_return_t
mach_vm_allocate(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	int flags)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_allocate_trap(target, address, size, flags);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_allocate(target, address, size, flags);
	}

	int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
	if (__syscall_logger && rv == KERN_SUCCESS && (userTagFlags != VM_MAKE_TAG(VM_MEMORY_STACK))) {
		__syscall_logger(stack_logging_type_vm_allocate | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
mach_vm_deallocate(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size)
{
	kern_return_t rv;

	if (__syscall_logger) {
		__syscall_logger(stack_logging_type_vm_deallocate, (uintptr_t)target, (uintptr_t)address, (uintptr_t)size, 0, 0);
	}

	rv = _kernelrpc_mach_vm_deallocate_trap(target, address, size);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_deallocate(target, address, size);
	}

	return rv;
}

kern_return_t
mach_vm_protect(
	mach_port_name_t task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum,
	    new_protection);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_protect(task, address, size,
		    set_maximum, new_protection);
	}

	return rv;
}

kern_return_t
vm_allocate(
	mach_port_name_t task,
	vm_address_t *address,
	vm_size_t size,
	int flags)
{
	kern_return_t rv;
	mach_vm_address_t mach_addr;

	mach_addr = (mach_vm_address_t)*address;
	rv = mach_vm_allocate(task, &mach_addr, size, flags);
#if defined(__LP64__)
	*address = mach_addr;
#else
	*address = (vm_address_t)(mach_addr & ((vm_address_t)-1));
#endif

	return rv;
}

kern_return_t
vm_deallocate(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size)
{
	kern_return_t rv;

	rv = mach_vm_deallocate(task, address, size);

	return rv;
}

kern_return_t
vm_protect(
	mach_port_name_t task,
	vm_address_t address,
	vm_size_t size,
	boolean_t set_maximum,
	vm_prot_t new_protection)
{
	kern_return_t rv;

	rv = mach_vm_protect(task, address, size, set_maximum, new_protection);

	return rv;
}

kern_return_t
mach_vm_map(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mem_entry_name_port_t object,
	memory_object_offset_t offset,
	boolean_t copy,
	vm_prot_t cur_protection,
	vm_prot_t max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv = MACH_SEND_INVALID_DEST;

	if (object == MEMORY_OBJECT_NULL && max_protection == VM_PROT_ALL &&
	    inheritance == VM_INHERIT_DEFAULT) {
		rv = _kernelrpc_mach_vm_map_trap(target, address, size, mask, flags,
		    cur_protection);
	}

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_map(target, address, size, mask, flags, object,
		    offset, copy, cur_protection, max_protection, inheritance);
	}

	int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
	if (__syscall_logger && rv == KERN_SUCCESS && (userTagFlags != VM_MAKE_TAG(VM_MEMORY_STACK))) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
mach_vm_remap(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	mach_vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_remap(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
mach_vm_remap_new(
	mach_port_name_t target,
	mach_vm_address_t *address,
	mach_vm_size_t size,
	mach_vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	mach_vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	/* {max,cur}_protection is inout */
	rv = _kernelrpc_mach_vm_remap_new(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
mach_vm_read(
	mach_port_name_t target,
	mach_vm_address_t address,
	mach_vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_read(target, address, size, data, dataCnt);

	if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		// The target argument is the remote task from which data is being read,
		// so pass mach_task_self() as the destination task receiving the allocation.
		__syscall_logger(eventTypeFlags, (uintptr_t)mach_task_self(), (uintptr_t)*dataCnt, 0, *data, 0);
	}

	return rv;
}

kern_return_t
vm_map(
	mach_port_name_t target,
	vm_address_t *address,
	vm_size_t size,
	vm_offset_t mask,
	int flags,
	mem_entry_name_port_t object,
	vm_offset_t offset,
	boolean_t copy,
	vm_prot_t cur_protection,
	vm_prot_t max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_map(target, address, size, mask, flags, object,
	    offset, copy, cur_protection, max_protection, inheritance);

	if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
vm_remap(
	mach_port_name_t target,
	vm_address_t *address,
	vm_size_t size,
	vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_remap(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	if (__syscall_logger) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
vm_remap_new(
	mach_port_name_t target,
	vm_address_t *address,
	vm_size_t size,
	vm_offset_t mask,
	int flags,
	mach_port_name_t src_task,
	vm_address_t src_address,
	boolean_t copy,
	vm_prot_t *cur_protection,
	vm_prot_t *max_protection,
	vm_inherit_t inheritance)
{
	kern_return_t rv;

	/* {max,cur}_protection is inout */
	rv = _kernelrpc_vm_remap_new(target, address, size, mask, flags,
	    src_task, src_address, copy, cur_protection, max_protection,
	    inheritance);

	if (__syscall_logger) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		int userTagFlags = flags & VM_FLAGS_ALIAS_MASK;
		__syscall_logger(eventTypeFlags | userTagFlags, (uintptr_t)target, (uintptr_t)size, 0, (uintptr_t)*address, 0);
	}

	return rv;
}

kern_return_t
vm_read(
	mach_port_name_t target,
	vm_address_t address,
	vm_size_t size,
	vm_offset_t *data,
	mach_msg_type_number_t *dataCnt)
{
	kern_return_t rv;

	rv = _kernelrpc_vm_read(target, address, size, data, dataCnt);

	if (__syscall_logger && rv == KERN_SUCCESS) {
		int eventTypeFlags = stack_logging_type_vm_allocate | stack_logging_type_mapped_file_or_shared_mem;
		// The target argument is the remote task from which data is being read,
		// so pass mach_task_self() as the destination task receiving the allocation.
		__syscall_logger(eventTypeFlags, (uintptr_t)mach_task_self(), (uintptr_t)*dataCnt, 0, *data, 0);
	}

	return rv;
}

kern_return_t
mach_vm_purgable_control(
	mach_port_name_t        target,
	mach_vm_offset_t        address,
	vm_purgable_t           control,
	int                     *state)
{
	kern_return_t rv;

	rv = _kernelrpc_mach_vm_purgable_control_trap(target, address, control, state);

	if (rv == MACH_SEND_INVALID_DEST) {
		rv = _kernelrpc_mach_vm_purgable_control(target, address, control, state);
	}

	return rv;
}

kern_return_t
vm_purgable_control(
	mach_port_name_t        task,
	vm_offset_t             address,
	vm_purgable_t           control,
	int                     *state)
{
	return mach_vm_purgable_control(task,
	           (mach_vm_offset_t) address,
	           control,
	           state);
}

kern_return_t
mach_vm_update_pointers_with_remote_tags(
	mach_port_name_t        target,
	mach_vm_offset_list_t in_pointer_list,
	mach_msg_type_number_t in_pointer_listCnt,
	mach_vm_offset_list_t out_pointer_list,
	mach_msg_type_number_t *out_pointer_listCnt)
{
	return _kernelrpc_mach_vm_update_pointers_with_remote_tags(target, in_pointer_list, in_pointer_listCnt, out_pointer_list, out_pointer_listCnt);
}

/*
 * The tag descriptions provided here are primarily exposed via vmmap(1)
 * and footprint(1). The tag descriptions displayed by these tools must be
 * human-readable and conform to a maximum length of 24 characters in order
 * to fit within vmmap(1)'s type name column. i.e. 123456789012345678901234
 */
static const char *vm_tag_descriptions[VM_MEMORY_COUNT] = {
	/* vmmap also uses "shared memory" */
	/* maximum width indicator                         123456789012345678901234 */
	[0]                                             = "Untagged",
	[VM_MEMORY_MALLOC]                              = "Malloc Metadata",
	[VM_MEMORY_MALLOC_SMALL]                        = "Malloc Small",
	[VM_MEMORY_MALLOC_LARGE]                        = "Malloc Large",
	[VM_MEMORY_MALLOC_HUGE]                         = "Malloc Huge",
	[VM_MEMORY_SBRK]                                = "SBRK",
	[VM_MEMORY_REALLOC]                             = "Malloc Realloc",
	[VM_MEMORY_MALLOC_TINY]                         = "Malloc Tiny",
	[VM_MEMORY_MALLOC_LARGE_REUSABLE]               = "Malloc Large (Reusable)",
	[VM_MEMORY_MALLOC_LARGE_REUSED]                 = "Malloc Large (Reused)",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_ANALYSIS_TOOL]                       = "Performance Tool Data",
	[VM_MEMORY_MALLOC_NANO]                         = "Malloc Nano",
	[VM_MEMORY_MALLOC_MEDIUM]                       = "Malloc Medium",
	[VM_MEMORY_MALLOC_PROB_GUARD]                   = "Malloc Prob. Guard",
	[14]                                            = "VM_MEMORY_14",
	[15]                                            = "VM_MEMORY_15",
	[16]                                            = "VM_MEMORY_16",
	[17]                                            = "VM_MEMORY_17",
	[18]                                            = "VM_MEMORY_18",
	[19]                                            = "VM_MEMORY_19",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_MACH_MSG]                            = "Mach Message",
	[VM_MEMORY_IOKIT]                               = "IOKit",
	[VM_MEMORY_VM_RECLAIM]                          = "Deferred Reclaim",
	[23]                                            = "VM_MEMORY_23",
	[24]                                            = "VM_MEMORY_24",
	[25]                                            = "VM_MEMORY_25",
	[26]                                            = "VM_MEMORY_26",
	[27]                                            = "VM_MEMORY_27",
	[28]                                            = "VM_MEMORY_28",
	[29]                                            = "VM_MEMORY_29",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_STACK]                               = "Stack",
	[VM_MEMORY_GUARD]                               = "Guard",
	[VM_MEMORY_SHARED_PMAP]                         = "Shared Pmap",
	[VM_MEMORY_DYLIB]                               = "Dylib",
	[VM_MEMORY_OBJC_DISPATCHERS]                    = "ObjC Dispatching Code",
	[VM_MEMORY_UNSHARED_PMAP]                       = "Unshared Pmap",
	[VM_MEMORY_LIBCHANNEL]                          = "Channel Library",
	[37]                                            = "VM_MEMORY_37",
	[38]                                            = "VM_MEMORY_38",
	[39]                                            = "VM_MEMORY_39",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_APPKIT]                              = "AppKit",
	[VM_MEMORY_FOUNDATION]                          = "Foundation",
	[VM_MEMORY_COREGRAPHICS]                        = "CoreGraphics",
	[VM_MEMORY_CORESERVICES]                        = "CoreServices",
	[VM_MEMORY_JAVA]                                = "Java",
	[VM_MEMORY_COREDATA]                            = "CoreData",
	[VM_MEMORY_COREDATA_OBJECTIDS]                  = "CoreData Object IDs",
	[47]                                            = "VM_MEMORY_47",
	[48]                                            = "VM_MEMORY_48",
	[49]                                            = "VM_MEMORY_49",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_ATS]                                 = "ATS (Font Support)",
	[VM_MEMORY_LAYERKIT]                            = "CoreAnimation",
	[VM_MEMORY_CGIMAGE]                             = "CG Image",
	[VM_MEMORY_TCMALLOC]                            = "WebKit Malloc",
	[VM_MEMORY_COREGRAPHICS_DATA]                   = "CG Raster Data",
	[VM_MEMORY_COREGRAPHICS_SHARED]                 = "CG Shared Images",
	[VM_MEMORY_COREGRAPHICS_FRAMEBUFFERS]           = "CG Frame Buffers",
	[VM_MEMORY_COREGRAPHICS_BACKINGSTORES]          = "CG Backing Stores",
	[VM_MEMORY_COREGRAPHICS_XALLOC]                 = "CG Xalloc",
	[59]                                            = "VM_MEMORY_59",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_DYLD]                                = "Dyld Private Memory",
	[VM_MEMORY_DYLD_MALLOC]                         = "Dyld Malloc Memory",
	[VM_MEMORY_SQLITE]                              = "SQLite Page Cache",
	[VM_MEMORY_WEBASSEMBLY]                         = "WebAssembly Memory",
	[VM_MEMORY_JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR] = "JS JIT Generated Code",
	[VM_MEMORY_JAVASCRIPT_JIT_REGISTER_FILE]        = "JS VM Register File",
	[VM_MEMORY_GLSL]                                = "OpenGL GLSL",
	[VM_MEMORY_OPENCL]                              = "OpenCL",
	[VM_MEMORY_COREIMAGE]                           = "CoreImage",
	[VM_MEMORY_WEBCORE_PURGEABLE_BUFFERS]           = "WebCore Purgeable Data",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_IMAGEIO]                             = "Image IO",
	[VM_MEMORY_COREPROFILE]                         = "CoreProfile",
	[VM_MEMORY_ASSETSD]                             = "Assets Library",
	[VM_MEMORY_OS_ALLOC_ONCE]                       = "OS Alloc Once",
	[VM_MEMORY_LIBDISPATCH]                         = "Dispatch Continuations",
	[VM_MEMORY_ACCELERATE]                          = "Accelerate Framework",
	[VM_MEMORY_COREUI]                              = "CoreUI Image Data",
	[VM_MEMORY_COREUIFILE]                          = "CoreUI Image File",
	[VM_MEMORY_GENEALOGY]                           = "Activity Tracing",
	[VM_MEMORY_RAWCAMERA]                           = "RawCamera",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_CORPSEINFO]                          = "Process Corpse Info",
	[VM_MEMORY_ASL]                                 = "Apple System Log",
	[VM_MEMORY_SWIFT_RUNTIME]                       = "Swift Runtime",
	[VM_MEMORY_SWIFT_METADATA]                      = "Swift Metadata",
	[VM_MEMORY_DHMM]                                = "DHMM",
	[VM_MEMORY_DFR]                                 = "DFR",
	[VM_MEMORY_SCENEKIT]                            = "SceneKit",
	[VM_MEMORY_SKYWALK]                             = "Skywalk Networking",
	[VM_MEMORY_IOSURFACE]                           = "IOSurface",
	[VM_MEMORY_LIBNETWORK]                          = "Libnetwork",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_AUDIO]                               = "Audio",
	[VM_MEMORY_VIDEOBITSTREAM]                      = "Video Bitstream",
	[VM_MEMORY_CM_XPC]                              = "CoreMedia XPC",
	[VM_MEMORY_CM_RPC]                              = "CoreMedia RPC",
	[VM_MEMORY_CM_MEMORYPOOL]                       = "CoreMedia Memory Pool",
	[VM_MEMORY_CM_READCACHE]                        = "CoreMedia Read Cache",
	[VM_MEMORY_CM_CRABS]                            = "CoreMedia HTTP Cache",
	[VM_MEMORY_QUICKLOOK_THUMBNAILS]                = "QuickLook Thumbnails",
	[VM_MEMORY_ACCOUNTS]                            = "Accounts Framework",
	[VM_MEMORY_SANITIZER]                           = "Sanitizer",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_IOACCELERATOR]                       = "IOAccelerator",
	[VM_MEMORY_CM_REGWARP]                          = "CoreMedia Capture Data",
	[VM_MEMORY_EAR_DECODER]                         = "EAR Speech Decoder",
	[VM_MEMORY_COREUI_CACHED_IMAGE_DATA]            = "CoreUI Cache Image Data",
	[VM_MEMORY_COLORSYNC]                           = "ColorSync",
	[VM_MEMORY_BTINFO]                              = "Simulated Crash Data",
	[VM_MEMORY_CM_HLS]                              = "CoreMedia HLS",
	[107]                                           = "VM_MEMORY_107",
	[108]                                           = "VM_MEMORY_108",
	[109]                                           = "VM_MEMORY_109",
	/* maximum width indicator                         123456789012345678901234 */
	[110]                                           = "VM_MEMORY_110",
	[111]                                           = "VM_MEMORY_111",
	[112]                                           = "VM_MEMORY_112",
	[113]                                           = "VM_MEMORY_113",
	[114]                                           = "VM_MEMORY_114",
	[115]                                           = "VM_MEMORY_115",
	[116]                                           = "VM_MEMORY_116",
	[117]                                           = "VM_MEMORY_117",
	[118]                                           = "VM_MEMORY_118",
	[119]                                           = "VM_MEMORY_119",
	/* maximum width indicator                         123456789012345678901234 */
	[120]                                           = "VM_MEMORY_120",
	[121]                                           = "VM_MEMORY_121",
	[122]                                           = "VM_MEMORY_122",
	[123]                                           = "VM_MEMORY_123",
	[124]                                           = "VM_MEMORY_124",
	[125]                                           = "VM_MEMORY_125",
	[126]                                           = "VM_MEMORY_126",
	[127]                                           = "VM_MEMORY_127",
	[128]                                           = "VM_MEMORY_128",
	[129]                                           = "VM_MEMORY_129",
	/* maximum width indicator                         123456789012345678901234 */
	[130]                                           = "VM_MEMORY_130",
	[131]                                           = "VM_MEMORY_131",
	[132]                                           = "VM_MEMORY_132",
	[133]                                           = "VM_MEMORY_133",
	[134]                                           = "VM_MEMORY_134",
	[135]                                           = "VM_MEMORY_135",
	[136]                                           = "VM_MEMORY_136",
	[137]                                           = "VM_MEMORY_137",
	[138]                                           = "VM_MEMORY_138",
	[139]                                           = "VM_MEMORY_139",
	/* maximum width indicator                         123456789012345678901234 */
	[140]                                           = "VM_MEMORY_140",
	[141]                                           = "VM_MEMORY_141",
	[142]                                           = "VM_MEMORY_142",
	[143]                                           = "VM_MEMORY_143",
	[144]                                           = "VM_MEMORY_144",
	[145]                                           = "VM_MEMORY_145",
	[146]                                           = "VM_MEMORY_146",
	[147]                                           = "VM_MEMORY_147",
	[148]                                           = "VM_MEMORY_148",
	[149]                                           = "VM_MEMORY_149",
	/* maximum width indicator                         123456789012345678901234 */
	[150]                                           = "VM_MEMORY_150",
	[151]                                           = "VM_MEMORY_151",
	[152]                                           = "VM_MEMORY_152",
	[153]                                           = "VM_MEMORY_153",
	[154]                                           = "VM_MEMORY_154",
	[155]                                           = "VM_MEMORY_155",
	[156]                                           = "VM_MEMORY_156",
	[157]                                           = "VM_MEMORY_157",
	[158]                                           = "VM_MEMORY_158",
	[159]                                           = "VM_MEMORY_159",
	/* maximum width indicator                         123456789012345678901234 */
	[160]                                           = "VM_MEMORY_160",
	[161]                                           = "VM_MEMORY_161",
	[162]                                           = "VM_MEMORY_162",
	[163]                                           = "VM_MEMORY_163",
	[164]                                           = "VM_MEMORY_164",
	[165]                                           = "VM_MEMORY_165",
	[166]                                           = "VM_MEMORY_166",
	[167]                                           = "VM_MEMORY_167",
	[168]                                           = "VM_MEMORY_168",
	[169]                                           = "VM_MEMORY_169",
	/* maximum width indicator                         123456789012345678901234 */
	[170]                                           = "VM_MEMORY_170",
	[171]                                           = "VM_MEMORY_171",
	[172]                                           = "VM_MEMORY_172",
	[173]                                           = "VM_MEMORY_173",
	[174]                                           = "VM_MEMORY_174",
	[175]                                           = "VM_MEMORY_175",
	[176]                                           = "VM_MEMORY_176",
	[177]                                           = "VM_MEMORY_177",
	[178]                                           = "VM_MEMORY_178",
	[179]                                           = "VM_MEMORY_179",
	/* maximum width indicator                         123456789012345678901234 */
	[180]                                           = "VM_MEMORY_180",
	[181]                                           = "VM_MEMORY_181",
	[182]                                           = "VM_MEMORY_182",
	[183]                                           = "VM_MEMORY_183",
	[184]                                           = "VM_MEMORY_184",
	[185]                                           = "VM_MEMORY_185",
	[186]                                           = "VM_MEMORY_186",
	[187]                                           = "VM_MEMORY_187",
	[188]                                           = "VM_MEMORY_188",
	[189]                                           = "VM_MEMORY_189",
	/* maximum width indicator                         123456789012345678901234 */
	[190]                                           = "VM_MEMORY_190",
	[191]                                           = "VM_MEMORY_191",
	[192]                                           = "VM_MEMORY_192",
	[193]                                           = "VM_MEMORY_193",
	[194]                                           = "VM_MEMORY_194",
	[195]                                           = "VM_MEMORY_195",
	[196]                                           = "VM_MEMORY_196",
	[197]                                           = "VM_MEMORY_197",
	[198]                                           = "VM_MEMORY_198",
	[199]                                           = "VM_MEMORY_199",
	/* maximum width indicator                         123456789012345678901234 */
	[200]                                           = "VM_MEMORY_200",
	[201]                                           = "VM_MEMORY_201",
	[202]                                           = "VM_MEMORY_202",
	[203]                                           = "VM_MEMORY_203",
	[204]                                           = "VM_MEMORY_204",
	[205]                                           = "VM_MEMORY_205",
	[206]                                           = "VM_MEMORY_206",
	[207]                                           = "VM_MEMORY_207",
	[208]                                           = "VM_MEMORY_208",
	[209]                                           = "VM_MEMORY_209",
	/* maximum width indicator                         123456789012345678901234 */
	[210]                                           = "VM_MEMORY_210",
	[211]                                           = "VM_MEMORY_211",
	[212]                                           = "VM_MEMORY_212",
	[213]                                           = "VM_MEMORY_213",
	[214]                                           = "VM_MEMORY_214",
	[215]                                           = "VM_MEMORY_215",
	[216]                                           = "VM_MEMORY_216",
	[217]                                           = "VM_MEMORY_217",
	[218]                                           = "VM_MEMORY_218",
	[219]                                           = "VM_MEMORY_219",
	/* maximum width indicator                         123456789012345678901234 */
	[220]                                           = "VM_MEMORY_220",
	[221]                                           = "VM_MEMORY_221",
	[222]                                           = "VM_MEMORY_222",
	[223]                                           = "VM_MEMORY_223",
	[224]                                           = "VM_MEMORY_224",
	[225]                                           = "VM_MEMORY_225",
	[226]                                           = "VM_MEMORY_226",
	[227]                                           = "VM_MEMORY_227",
	[228]                                           = "VM_MEMORY_228",
	[229]                                           = "VM_MEMORY_229",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_ROSETTA]                             = "Rosetta Generic",
	[VM_MEMORY_ROSETTA_THREAD_CONTEXT]              = "Rosetta Thread Context",
	[VM_MEMORY_ROSETTA_INDIRECT_BRANCH_MAP]         = "Rosetta IndirectBranch",
	[VM_MEMORY_ROSETTA_RETURN_STACK]                = "Rosetta Return Stack",
	[VM_MEMORY_ROSETTA_EXECUTABLE_HEAP]             = "Rosetta JIT",
	[VM_MEMORY_ROSETTA_USER_LDT]                    = "Rosetta User LDT",
	[VM_MEMORY_ROSETTA_ARENA]                       = "Rosetta Arena",
	[237]                                           = "VM_MEMORY_237",
	[238]                                           = "VM_MEMORY_238",
	[VM_MEMORY_ROSETTA_10]                          = "Rosetta Tag 10",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_APPLICATION_SPECIFIC_1]              = "App-Specific Tag 1",
	[VM_MEMORY_APPLICATION_SPECIFIC_2]              = "App-Specific Tag 2",
	[VM_MEMORY_APPLICATION_SPECIFIC_3]              = "App-Specific Tag 3",
	[VM_MEMORY_APPLICATION_SPECIFIC_4]              = "App-Specific Tag 4",
	[VM_MEMORY_APPLICATION_SPECIFIC_5]              = "App-Specific Tag 5",
	[VM_MEMORY_APPLICATION_SPECIFIC_6]              = "App-Specific Tag 6",
	[VM_MEMORY_APPLICATION_SPECIFIC_7]              = "App-Specific Tag 7",
	[VM_MEMORY_APPLICATION_SPECIFIC_8]              = "App-Specific Tag 8",
	[VM_MEMORY_APPLICATION_SPECIFIC_9]              = "App-Specific Tag 9",
	/* maximum width indicator                         123456789012345678901234 */
	[VM_MEMORY_APPLICATION_SPECIFIC_10]             = "App-Specific Tag 10",
	[VM_MEMORY_APPLICATION_SPECIFIC_11]             = "App-Specific Tag 11",
	[VM_MEMORY_APPLICATION_SPECIFIC_12]             = "App-Specific Tag 12",
	[VM_MEMORY_APPLICATION_SPECIFIC_13]             = "App-Specific Tag 13",
	[VM_MEMORY_APPLICATION_SPECIFIC_14]             = "App-Specific Tag 14",
	[VM_MEMORY_APPLICATION_SPECIFIC_15]             = "App-Specific Tag 15",
	[VM_MEMORY_APPLICATION_SPECIFIC_16]             = "App-Specific Tag 16",
};

const char *
mach_vm_tag_describe(unsigned int tag)
{
	if (tag < VM_MEMORY_COUNT) {
		return vm_tag_descriptions[tag];
	}
	return "Invalid Tag (?)";
}

kern_return_t
mach_vm_reallocate(
	mach_port_name_t        task,
	mach_vm_address_t       src,
	mach_vm_size_t          src_size,
	mach_vm_address_t      *dst_inout,
	mach_vm_size_t          dst_size,
	mach_vm_offset_t        align_mask,
	int                     options,
	int                     flags)
{
	kern_return_t kr;

	kr = _kernelrpc_mach_vm_reallocate(task, src, src_size, dst_inout, dst_size, align_mask, options, flags);
	if (__syscall_logger && kr == KERN_SUCCESS) {
		__syscall_logger(stack_logging_type_vm_deallocate, (uintptr_t)task, (uintptr_t)src, (uintptr_t)src_size, 0, 0);
		__syscall_logger(stack_logging_type_vm_allocate, (uintptr_t)task, (uintptr_t)dst_size, 0, (uintptr_t)*dst_inout, 0);
	}

	return kr;
}

kern_return_t
vm_reallocate(
	mach_port_name_t        task,
	vm_address_t            src,
	vm_size_t               src_size,
	vm_address_t           *dst_inout,
	vm_size_t               dst_size,
	vm_offset_t             align_mask,
	int                     options,
	int                     flags)
{
	kern_return_t kr;
	mach_vm_address_t mach_addr;

	mach_addr = (mach_vm_address_t)(*dst_inout);
	kr = mach_vm_reallocate(task, src, src_size, &mach_addr, dst_size, align_mask, options, flags);
#if defined(__LP64__)
	*dst_inout = mach_addr;
#else
	*dst_inout = (vm_address_t)(mach_addr & ((vm_address_t)-1));
#endif /* __LP64__ */

	return kr;
}
