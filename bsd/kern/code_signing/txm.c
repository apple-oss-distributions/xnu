/*
 * Copyright (c) 2022 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdarg.h>
#include <stdatomic.h>
#include <os/overflow.h>
#include <machine/atomic.h>
#include <mach/vm_param.h>
#include <mach/vm_map.h>
#include <mach/shared_region.h>
#include <vm/vm_kern.h>
#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/locks.h>
#include <kern/sched_prim.h>
#include <kern/lock_rw.h>
#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/coretrust/coretrust.h>
#include <libkern/amfi/amfi.h>
#include <pexpert/pexpert.h>
#include <sys/vm.h>
#include <sys/proc.h>
#include <sys/codesign.h>
#include <sys/code_signing.h>
#include <uuid/uuid.h>
#include <IOKit/IOBSD.h>

