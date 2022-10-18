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
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1987, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_malloc.c	8.4 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <kern/zalloc.h>
#include <kern/kalloc.h>
#include <sys/ubc.h> /* mach_to_bsd_errno */

#include <sys/malloc.h>
#include <sys/sysctl.h>

#include <libkern/libkern.h>

ZONE_VIEW_DEFINE(ZV_NAMEI, "vfs.namei", KHEAP_ID_DATA_BUFFERS, MAXPATHLEN);
KALLOC_HEAP_DEFINE(KERN_OS_MALLOC, "kern_os_malloc", KHEAP_ID_DEFAULT);

/*
 * macOS Only deprecated interfaces, here only for legacy reasons.
 * There is no internal variant of any of these symbols on purpose.
 */
#if XNU_PLATFORM_MacOSX

#define OSMallocDeprecatedMsg(msg)
#include <libkern/OSMalloc.h>

void *
_MALLOC_external(size_t size, int type, int flags);
void *
_MALLOC_external(size_t size, int type, int flags)
{
	kalloc_heap_t heap = KHEAP_DEFAULT;
	void    *addr = NULL;

	if (type == M_SONAME) {
#if !XNU_TARGET_OS_OSX
		assert3u(size, <=, UINT8_MAX);
#endif /* XNU_TARGET_OS_OSX */
		heap = KHEAP_SONAME;
	}

	if (size == 0) {
		return NULL;
	}

	static_assert(sizeof(vm_size_t) == sizeof(size_t));
	static_assert(M_WAITOK == Z_WAITOK);
	static_assert(M_NOWAIT == Z_NOWAIT);
	static_assert(M_ZERO == Z_ZERO);

	flags = Z_VM_TAG_BT(flags & Z_KPI_MASK, VM_KERN_MEMORY_KALLOC);
	addr = kalloc_ext(heap, size, flags, NULL).addr;
	if (__probable(addr)) {
		return addr;
	}

	if (flags & (M_NOWAIT | M_NULL)) {
		return NULL;
	}

	/*
	 * We get here when the caller told us to block waiting for memory, but
	 * kalloc said there's no memory left to get.  Generally, this means there's a
	 * leak or the caller asked for an impossibly large amount of memory. If the caller
	 * is expecting a NULL return code then it should explicitly set the flag M_NULL.
	 * If the caller isn't expecting a NULL return code, we just panic. This is less
	 * than ideal, but returning NULL when the caller isn't expecting it doesn't help
	 * since the majority of callers don't check the return value and will just
	 * dereference the pointer and trap anyway.  We may as well get a more
	 * descriptive message out while we can.
	 */
	panic("_MALLOC: kalloc returned NULL (potential leak), size %llu", (uint64_t) size);
}

void
_FREE_external(void *addr, int type);
void
_FREE_external(void *addr, int type __unused)
{
	kheap_free_addr(KHEAP_DEFAULT, addr);
}

void
_FREE_ZONE_external(void *elem, size_t size, int type);
void
_FREE_ZONE_external(void *elem, size_t size, int type __unused)
{
	kheap_free(KHEAP_DEFAULT, elem, size);
}

char *
STRDUP_external(const char *string, int type);
char *
STRDUP_external(const char *string, int type __unused)
{
	size_t len;
	char *copy;

	len = strlen(string) + 1;
	copy = kheap_alloc(KHEAP_DEFAULT, len, Z_WAITOK);
	if (copy) {
		memcpy(copy, string, len);
	}
	return copy;
}

static queue_head_t OSMalloc_tag_list = QUEUE_HEAD_INITIALIZER(OSMalloc_tag_list);
static LCK_GRP_DECLARE(OSMalloc_tag_lck_grp, "OSMalloc_tag");
static LCK_SPIN_DECLARE(OSMalloc_tag_lock, &OSMalloc_tag_lck_grp);

#define OSMalloc_tag_spin_lock()        lck_spin_lock(&OSMalloc_tag_lock)
#define OSMalloc_tag_unlock()           lck_spin_unlock(&OSMalloc_tag_lock)

extern typeof(OSMalloc_Tagalloc) OSMalloc_Tagalloc_external;
OSMallocTag
OSMalloc_Tagalloc_external(const char *str, uint32_t flags)
{
	OSMallocTag OSMTag;

	OSMTag = kalloc_type(struct _OSMallocTag_, Z_WAITOK | Z_ZERO);

	if (flags & OSMT_PAGEABLE) {
		OSMTag->OSMT_attr = OSMT_ATTR_PAGEABLE;
	}

	OSMTag->OSMT_refcnt = 1;

	strlcpy(OSMTag->OSMT_name, str, OSMT_MAX_NAME);

	OSMalloc_tag_spin_lock();
	enqueue_tail(&OSMalloc_tag_list, (queue_entry_t)OSMTag);
	OSMalloc_tag_unlock();
	OSMTag->OSMT_state = OSMT_VALID;
	return OSMTag;
}

static void
OSMalloc_Tagref(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	os_atomic_inc(&tag->OSMT_refcnt, relaxed);
}

static void
OSMalloc_Tagrele(OSMallocTag tag)
{
	if (!((tag->OSMT_state & OSMT_VALID_MASK) == OSMT_VALID)) {
		panic("OSMalloc_Tagref():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) != 0) {
		return;
	}

	if (os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID | OSMT_RELEASED, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kfree_type(struct _OSMallocTag_, tag);
	} else {
		panic("OSMalloc_Tagrele():'%s' has refcnt 0", tag->OSMT_name);
	}
}

extern typeof(OSMalloc_Tagfree) OSMalloc_Tagfree_external;
void
OSMalloc_Tagfree_external(OSMallocTag tag)
{
	if (!os_atomic_cmpxchg(&tag->OSMT_state,
	    OSMT_VALID, OSMT_VALID | OSMT_RELEASED, acq_rel)) {
		panic("OSMalloc_Tagfree():'%s' has bad state 0x%08X",
		    tag->OSMT_name, tag->OSMT_state);
	}

	if (os_atomic_dec(&tag->OSMT_refcnt, relaxed) == 0) {
		OSMalloc_tag_spin_lock();
		(void)remque((queue_entry_t)tag);
		OSMalloc_tag_unlock();
		kfree_type(struct _OSMallocTag_, tag);
	}
}

extern typeof(OSMalloc) OSMalloc_external;
void *
OSMalloc_external(uint32_t size, OSMallocTag tag)
{
	void           *addr = NULL;
	kern_return_t   kr;

	OSMalloc_Tagref(tag);
	if ((tag->OSMT_attr & OSMT_PAGEABLE) && (size & ~PAGE_MASK)) {
		if ((kr = kmem_alloc(kernel_map, (vm_offset_t *)&addr, size,
		    KMA_PAGEABLE | KMA_DATA, vm_tag_bt())) != KERN_SUCCESS) {
			addr = NULL;
		}
	} else {
		addr = kheap_alloc(KERN_OS_MALLOC, size,
		    Z_VM_TAG_BT(Z_WAITOK, VM_KERN_MEMORY_KALLOC));
	}

	if (!addr) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSMalloc_noblock) OSMalloc_noblock_external;
void *
OSMalloc_noblock_external(uint32_t size, OSMallocTag tag)
{
	void    *addr = NULL;

	if (tag->OSMT_attr & OSMT_PAGEABLE) {
		return NULL;
	}

	OSMalloc_Tagref(tag);
	addr = kheap_alloc(KERN_OS_MALLOC, (vm_size_t)size,
	    Z_VM_TAG_BT(Z_NOWAIT, VM_KERN_MEMORY_KALLOC));
	if (addr == NULL) {
		OSMalloc_Tagrele(tag);
	}

	return addr;
}

extern typeof(OSFree) OSFree_external;
void
OSFree_external(void *addr, uint32_t size, OSMallocTag tag)
{
	if ((tag->OSMT_attr & OSMT_PAGEABLE)
	    && (size & ~PAGE_MASK)) {
		kmem_free(kernel_map, (vm_offset_t)addr, size);
	} else {
		kheap_free(KERN_OS_MALLOC, addr, size);
	}

	OSMalloc_Tagrele(tag);
}

#endif /* XNU_PLATFORM_MacOSX */
#if DEBUG || DEVELOPMENT

static int
sysctl_zone_map_jetsam_limit SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int oldval = 0, val = 0, error = 0;

	oldval = zone_map_jetsam_limit;
	error = sysctl_io_number(req, oldval, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
		return error;
	}

	return mach_to_bsd_errno(zone_map_jetsam_set_limit(val));
}
SYSCTL_PROC(_kern, OID_AUTO, zone_map_jetsam_limit,
    CTLTYPE_INT | CTLFLAG_RW, 0, 0, sysctl_zone_map_jetsam_limit, "I",
    "Zone map jetsam limit");


extern void get_zone_map_size(uint64_t *current_size, uint64_t *capacity);

static int
sysctl_zone_map_size_and_capacity SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t zstats[2];
	get_zone_map_size(&zstats[0], &zstats[1]);

	return SYSCTL_OUT(req, &zstats, sizeof(zstats));
}

SYSCTL_PROC(_kern, OID_AUTO, zone_map_size_and_capacity,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED, 0, 0,
    &sysctl_zone_map_size_and_capacity, "Q",
    "Current size and capacity of the zone map");

SYSCTL_LONG(_kern, OID_AUTO, zone_wired_pages,
    CTLFLAG_RD | CTLFLAG_LOCKED, &zone_pages_wired,
    "number of wired pages in zones");

SYSCTL_LONG(_kern, OID_AUTO, zone_guard_pages,
    CTLFLAG_RD | CTLFLAG_LOCKED, &zone_guard_pages,
    "number of guard pages in zones");

#endif /* DEBUG || DEVELOPMENT */
#if CONFIG_ZLEAKS

SYSCTL_DECL(_kern_zleak);
SYSCTL_NODE(_kern, OID_AUTO, zleak, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "zleak");

SYSCTL_INT(_kern_zleak, OID_AUTO, active, CTLFLAG_RD,
    &zleak_active, 0, "zleak activity");

/*
 * kern.zleak.max_zonemap_size
 *
 * Read the value of the maximum zonemap size in bytes; useful
 * as the maximum size that zleak.global_threshold and
 * zleak.zone_threshold should be set to.
 */
SYSCTL_LONG(_kern_zleak, OID_AUTO, max_zonemap_size,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED, &zleak_max_zonemap_size,
    "zleak max zonemap size");


static int
sysctl_zleak_threshold SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error;
	uint64_t value = *(vm_size_t *)arg1;

	error = sysctl_io_number(req, value, sizeof(value), &value, NULL);

	if (error || !req->newptr) {
		return error;
	}

	return mach_to_bsd_errno(zleak_update_threshold(arg1, value));
}

/*
 * kern.zleak.global_threshold
 *
 * Set the global zleak threshold size (in bytes).  If the zone map
 * grows larger than this value, zleaks are automatically activated.
 *
 * The default value is set in zleak_init().
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, global_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_global_tracking_threshold, 0, sysctl_zleak_threshold, "Q",
    "zleak global threshold");

/*
 * kern.zleak.zone_threshold
 *
 * Set the per-zone threshold size (in bytes) above which any
 * zone will automatically start zleak tracking.
 *
 * The default value is set in zleak_init().
 *
 * Setting this variable will have no effect until zleak tracking is
 * activated (See above.)
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, zone_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_per_zone_tracking_threshold, 0, sysctl_zleak_threshold, "Q",
    "zleak per-zone threshold");

#endif  /* CONFIG_ZLEAKS */

extern uint64_t get_zones_collectable_bytes(void);

static int
sysctl_zones_collectable_bytes SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t zones_free_mem = get_zones_collectable_bytes();

	return SYSCTL_OUT(req, &zones_free_mem, sizeof(zones_free_mem));
}

SYSCTL_PROC(_kern, OID_AUTO, zones_collectable_bytes,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
    0, 0, &sysctl_zones_collectable_bytes, "Q",
    "Collectable memory in zones");
