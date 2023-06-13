/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
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

/* Common LC_NOTE defintions for core files. */
#ifndef _CORE_NOTES_H_
#define _CORE_NOTES_H_

/*
 * Format of the "main bin spec" LC_NOTE payload as expected by LLDB
 */
#define MAIN_BIN_SPEC_DATA_OWNER "main bin spec"

typedef struct main_bin_spec_note {
	uint32_t version;       // currently 1
	uint32_t type;          // 0 == unspecified, 1 == kernel, 2 == user process, 3 == standalone (ie FW)
	uint64_t address;       // UINT64_MAX if address not specified
	uuid_t   uuid;          // all zeros if uuid not specified
	uint32_t log2_pagesize; // process page size in log base 2, e.g. 4k pages are 12. 0 for unspecified
	uint32_t unused;        // leave set to 0
} __attribute__((packed)) main_bin_spec_note_t;

#define MAIN_BIN_SPEC_VERSION 1
#define MAIN_BIN_SPEC_TYPE_KERNEL 1
#define MAIN_BIN_SPEC_TYPE_USER 2
#define MAIN_BIN_SPEC_TYPE_STANDALONE 3


/*
 * Format of the "load binary" LC_NOTE payload as expected by LLDB
 */
#define LOAD_BINARY_SPEC_DATA_OWNER "load binary"

#define LOAD_BINARY_NAME_BUF_SIZE 32
typedef struct load_binary_spec_note {
	uint32_t version;    // currently 1
	uuid_t   uuid;       // all zeroes if uuid not specified
	uint64_t address;    // virtual address where the macho is loaded, UINT64_MAX if unavail
	uint64_t slide;      // UINT64_MAX if slide not specified/unknown
	                     // 0 if there is no slide (the binary loaded at
	                     // the vmaddr in the file)
	/*
	 * name_cstring must be a NUL terminated C string, or empty ('\0')
	 * if unavailable.  NOTE: lldb's spec does not specify a length
	 * for the name, it just wants a NUL terminated string. But we
	 * specify a (maximum) length to avoid notes with dynamic length.
	 */
	char     name_cstring[LOAD_BINARY_NAME_BUF_SIZE];
} __attribute__((packed)) load_binary_spec_note_t;

#define LOAD_BINARY_SPEC_VERSION 1

/*
 * Format of the "addrable bits" LC_NOTE payload as expected by LLDB.
 */
#define ADDRABLE_BITS_DATA_OWNER "addrable bits"

typedef struct addrable_bits_note {
	uint32_t version;            // CURRENTLY 3
	uint32_t addressing_bits;    // # of bits in use for addressing
	uint64_t unused;             // zeroed
} __attribute__((packed)) addrable_bits_note_t;

#define ADDRABLE_BITS_VER 3


#define PANIC_CONTEXT_DATA_OWNER "panic context"

typedef struct panic_context_note {
	uuid_string_t kernel_uuid_string;
} __attribute__((packed)) panic_context_note_t;

#endif /* _CORE_NOTES_H_ */
