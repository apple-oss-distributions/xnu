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

#ifndef _MACHINE_STATIC_IF_H
#error "do not include this file directly, use <machine/static_if.h>"
#else

#define STATIC_IF_RELATIVE      0
#define STATIC_IF_INSN_SIZE     5

typedef long static_if_offset_t;

struct static_if_entry {
	static_if_offset_t      sie_base;
	static_if_offset_t      sie_target;
	unsigned long           sie_link;
};

/* generates a struct static_if_entry */
#define STATIC_IF_ENTRY(n) \
	".pushsection " STATIC_IF_SEGSECT ",regular,live_support"       "\n\t" \
	".align 3"                                                      "\n\t" \
	".quad 1b"                                                      "\n\t" \
	".quad %l1"                                                     "\n\t" \
	".quad _" #n "_jump_key + %c0"                                  "\n\t" \
	".popsection"

/* From "Recommended Multi-Byte Sequence of NOP Instruction" */
#define STATIC_IF_NOP(n, label) \
	asm goto("1: .byte 0x0F,0x1F,0x44,0x00,0x00"                    "\n\t" \
	    STATIC_IF_ENTRY(n) : : "i"(0) : : label)

/* 32-bit jump */
#define STATIC_IF_BRANCH(n, label) \
	asm goto("1: .byte 0xE9; .long %l1 - 2f; 2:"                    "\n\t" \
	    STATIC_IF_ENTRY(n) : : "i"(1) : : label)

#endif /* _MACHINE_STATIC_IF_H */
