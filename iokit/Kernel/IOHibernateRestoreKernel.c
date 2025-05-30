/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <sys/param.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <IOKit/IOHibernatePrivate.h>
#include <IOKit/IOLib.h>
#include <pexpert/boot.h>
#include <libkern/libkern.h>

#include "IOHibernateInternal.h"

#include <machine/pal_hibernate.h>

/*
 *  This code is linked into the kernel but part of the "__HIB" section, which means
 *  its used by code running in the special context of restoring the kernel text and data
 *  from the hibernation image read by the booter. hibernate_kernel_entrypoint() and everything
 *  it calls or references needs to be careful to only touch memory also in the "__HIB" section.
 */

#define HIB_ROUND_PAGE(x) (((x) + PAGE_MASK) & ~PAGE_MASK)

uint32_t gIOHibernateState;

uint32_t gIOHibernateDebugFlags;

static IOHibernateImageHeader _hibernateHeader;
IOHibernateImageHeader * gIOHibernateCurrentHeader = &_hibernateHeader;

ppnum_t gIOHibernateHandoffPages[64];
const uint32_t gIOHibernateHandoffPageCount = sizeof(gIOHibernateHandoffPages)
    / sizeof(gIOHibernateHandoffPages[0]);

#if CONFIG_DEBUG
#if defined(__arm64__)
extern void serial_hibernation_init(void);
#endif /* defined(__arm64__) */
void hibprintf(const char *fmt, ...);
#else
#define hibprintf(x...)
#endif


#if CONFIG_SLEEP
#if defined(__i386__) || defined(__x86_64__)
extern void acpi_wake_prot_entry(void);
#endif
#endif

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#if defined(__i386__) || defined(__x86_64__)
#include <i386/proc_reg.h>
#else

static inline uint64_t
rdtsc64(void)
{
	return 0;
}

#endif /* defined(__i386__) || defined(__x86_64__) */

#if defined(__i386__) || defined(__x86_64__)

#define DBGLOG  1

#include <architecture/i386/pio.h>

/* standard port addresses */
enum {
	COM1_PORT_ADDR = 0x3f8,
	COM2_PORT_ADDR = 0x2f8
};

/* UART register offsets */
enum {
	UART_RBR = 0, /* receive buffer Register   (R) */
	UART_THR = 0, /* transmit holding register (W) */
	UART_DLL = 0, /* DLAB = 1, divisor latch (LSB) */
	UART_IER = 1, /* interrupt enable register     */
	UART_DLM = 1, /* DLAB = 1, divisor latch (MSB) */
	UART_IIR = 2, /* interrupt ident register (R)  */
	UART_FCR = 2, /* fifo control register (W)     */
	UART_LCR = 3, /* line control register         */
	UART_MCR = 4, /* modem control register        */
	UART_LSR = 5, /* line status register          */
	UART_MSR = 6, /* modem status register         */
	UART_SCR = 7 /* scratch register              */
};

enum {
	UART_LCR_8BITS = 0x03,
	UART_LCR_DLAB  = 0x80
};

enum {
	UART_MCR_DTR   = 0x01,
	UART_MCR_RTS   = 0x02,
	UART_MCR_OUT1  = 0x04,
	UART_MCR_OUT2  = 0x08,
	UART_MCR_LOOP  = 0x10
};

enum {
	UART_LSR_DR    = 0x01,
	UART_LSR_OE    = 0x02,
	UART_LSR_PE    = 0x04,
	UART_LSR_FE    = 0x08,
	UART_LSR_THRE  = 0x20
};

static void
hib_uart_putc(char c)
{
	while (!(inb(COM1_PORT_ADDR + UART_LSR) & UART_LSR_THRE)) {
	}
	outb(COM1_PORT_ADDR + UART_THR, c);
}

static int
debug_probe( void )
{
	/* Verify that the Scratch Register is accessible */
	outb(COM1_PORT_ADDR + UART_SCR, 0x5a);
	if (inb(COM1_PORT_ADDR + UART_SCR) != 0x5a) {
		return false;
	}
	outb(COM1_PORT_ADDR + UART_SCR, 0xa5);
	if (inb(COM1_PORT_ADDR + UART_SCR) != 0xa5) {
		return false;
	}
	hib_uart_putc('\n');
	return true;
}

#elif defined(__arm64__)

#define DBGLOG  1

static void
hib_uart_putc(char c)
{
	uart_putc(c);
}

static int
debug_probe( void )
{
	// todo
	return false;
}

#endif /* defined(__arm64__) */

#if defined(__i386__) || defined(__x86_64__) || defined(__arm64__)

static void
uart_putstring(const char *str)
{
	while (*str) {
		hib_uart_putc(*str++);
	}
}

static void
uart_putdec(uint64_t num)
{
	bool leading = true;
	for (uint64_t pos = 10000000000000000000ull; pos != 0; pos /= 10) {
		char c = (char) (num / pos);
		if (c) {
			leading = false;
			num -= c * pos;
		} else if (leading && (pos != 1)) {
			continue;
		}
		hib_uart_putc(c + '0');
	}
}

static void
uart_puthex(uint64_t num)
{
	int bit;
	char c;
	bool leading = true;

	for (bit = 60; bit >= 0; bit -= 4) {
		c = 0xf & (num >> bit);
		if (c) {
			leading = false;
		} else if (leading && bit) {
			continue;
		}
		if (c <= 9) {
			c += '0';
		} else {
			c += 'a' - 10;
		}
		hib_uart_putc(c);
	}
}

static void
debug_code(uint32_t code, uint64_t value)
{
	int bit;
	char c;

	if (!(kIOHibernateDebugRestoreLogs & gIOHibernateDebugFlags)) {
		return;
	}

	for (bit = 24; bit >= 0; bit -= 8) {
		c = 0xFF & (code >> bit);
		if (c) {
			hib_uart_putc(c);
		}
	}
	hib_uart_putc('=');
	uart_puthex(value);
	hib_uart_putc('\n');
	hib_uart_putc('\r');
}

#endif /* defined(__i386__) || defined(__x86_64__) || defined(__arm64__) */

#if !defined(DBGLOG)
#define debug_probe()       (false)
#define debug_code(c, v)    {}
#endif

enum{
	kIOHibernateRestoreCodeImageStart       = 'imgS',
	kIOHibernateRestoreCodeImageEnd         = 'imgE',
	kIOHibernateRestoreCodePageIndexStart   = 'pgiS',
	kIOHibernateRestoreCodePageIndexEnd     = 'pgiE',
	kIOHibernateRestoreCodeMapStart         = 'mapS',
	kIOHibernateRestoreCodeMapEnd           = 'mapE',
	kIOHibernateRestoreCodeWakeMapSize      = 'wkms',
	kIOHibernateRestoreCodeConflictPage     = 'cfpg',
	kIOHibernateRestoreCodeConflictSource   = 'cfsr',
	kIOHibernateRestoreCodeNoMemory         = 'nomm',
	kIOHibernateRestoreCodeTag              = 'tag ',
	kIOHibernateRestoreCodeSignature        = 'sign',
	kIOHibernateRestoreCodeMapVirt          = 'mapV',
	kIOHibernateRestoreCodeHandoffPages     = 'hand',
	kIOHibernateRestoreCodeHandoffCount     = 'hndc',
};

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


void
__hib_assert(const char *file, int line, const char *expression)
{
	uart_putstring(file);
	hib_uart_putc(':');
	uart_putdec(line);
	uart_putstring(" Assertion failed: ");
	uart_putstring(expression);
	hib_uart_putc('\n');
#if defined(__i386__) || defined(__x86_64__)
	outb(0xcf9, 6);
#endif /* defined(__i386__) || defined(__x86_64__) */
	while (true) {
	}
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

uint32_t
hibernate_sum_page(uint8_t *buf, uint32_t ppnum)
{
	return ((uint32_t *)buf)[((PAGE_SIZE >> 2) - 1) & ppnum];
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static hibernate_bitmap_t *
hibernate_page_bitmap(hibernate_page_list_t * list, uint32_t page)
{
	uint32_t             bank;
	hibernate_bitmap_t * bitmap = &list->bank_bitmap[0];

	for (bank = 0; bank < list->bank_count; bank++) {
		if ((page >= bitmap->first_page) && (page <= bitmap->last_page)) {
			break;
		}
		bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
	}
	if (bank == list->bank_count) {
		bitmap = NULL;
	}

	return bitmap;
}

hibernate_bitmap_t *
hibernate_page_bitmap_pin(hibernate_page_list_t * list, uint32_t * pPage)
{
	uint32_t             bank, page = *pPage;
	hibernate_bitmap_t * bitmap = &list->bank_bitmap[0];

	for (bank = 0; bank < list->bank_count; bank++) {
		if (page <= bitmap->first_page) {
			*pPage = bitmap->first_page;
			break;
		}
		if (page <= bitmap->last_page) {
			break;
		}
		bitmap = (hibernate_bitmap_t *) &bitmap->bitmap[bitmap->bitmapwords];
	}
	if (bank == list->bank_count) {
		bitmap = NULL;
	}

	return bitmap;
}

void
hibernate_page_bitset(hibernate_page_list_t * list, boolean_t set, uint32_t page)
{
	hibernate_bitmap_t * bitmap;

	bitmap = hibernate_page_bitmap(list, page);
	if (bitmap) {
		page -= bitmap->first_page;
		if (set) {
			bitmap->bitmap[page >> 5] |= (0x80000000 >> (page & 31));
		}
		//setbit(page - bitmap->first_page, (int *) &bitmap->bitmap[0]);
		else {
			bitmap->bitmap[page >> 5] &= ~(0x80000000 >> (page & 31));
		}
		//clrbit(page - bitmap->first_page, (int *) &bitmap->bitmap[0]);
	}
}

boolean_t
hibernate_page_bittst(hibernate_page_list_t * list, uint32_t page)
{
	boolean_t            result = TRUE;
	hibernate_bitmap_t * bitmap;

	bitmap = hibernate_page_bitmap(list, page);
	if (bitmap) {
		page -= bitmap->first_page;
		result = (0 != (bitmap->bitmap[page >> 5] & (0x80000000 >> (page & 31))));
	}
	return result;
}

// count bits clear or set (set == TRUE) starting at page.
uint32_t
hibernate_page_bitmap_count(hibernate_bitmap_t * bitmap, uint32_t set, uint32_t page)
{
	uint32_t index, bit, bits;
	uint32_t count;

	count = 0;

	index = (page - bitmap->first_page) >> 5;
	bit = (page - bitmap->first_page) & 31;

	bits = bitmap->bitmap[index];
	if (set) {
		bits = ~bits;
	}
	bits = (bits << bit);
	if (bits) {
		count += __builtin_clz(bits);
	} else {
		count += 32 - bit;
		while (++index < bitmap->bitmapwords) {
			bits = bitmap->bitmap[index];
			if (set) {
				bits = ~bits;
			}
			if (bits) {
				count += __builtin_clz(bits);
				break;
			}
			count += 32;
		}
	}

	if ((page + count) > (bitmap->last_page + 1)) {
		count = (bitmap->last_page + 1) - page;
	}

	return count;
}

ppnum_t
hibernate_page_list_grab(hibernate_page_list_t * list, uint32_t * pNextFree)
{
	uint32_t             nextFree = *pNextFree;
	uint32_t             nextFreeInBank;
	hibernate_bitmap_t * bitmap;

	nextFreeInBank = nextFree + 1;
	while ((bitmap = hibernate_page_bitmap_pin(list, &nextFreeInBank))) {
		nextFreeInBank += hibernate_page_bitmap_count(bitmap, FALSE, nextFreeInBank);
		if (nextFreeInBank <= bitmap->last_page) {
			*pNextFree = nextFreeInBank;
			break;
		}
	}

	if (!bitmap) {
		debug_code(kIOHibernateRestoreCodeNoMemory, nextFree);
		HIB_ASSERT(0);
	}

	return nextFree;
}

#pragma mark -
#pragma mark hibernate_scratch

void
hibernate_scratch_init(hibernate_scratch_t * scratch, hibernate_page_list_t * map, uint32_t * nextFree)
{
	// initialize "scratch" so we can start writing into it
	__nosan_bzero(scratch, sizeof(*scratch));
	scratch->map = map;
	scratch->nextFree = nextFree;
	scratch->headPage = hibernate_page_list_grab(scratch->map, scratch->nextFree);
	scratch->curPage = (uint8_t *)pal_hib_map(SCRATCH_AREA, ptoa_64(scratch->headPage));
}

void
hibernate_scratch_start_read(hibernate_scratch_t * scratch)
{
	// re-initialize "scratch" so we can start reading from it it
	hibernate_scratch_t result;
	__nosan_bzero(&result, sizeof(result));
	result.headPage = scratch->headPage;
	result.curPage = (uint8_t *)pal_hib_map(SCRATCH_AREA, ptoa_64(result.headPage));
	result.totalLength = scratch->curPos;
	*scratch = result;
}

static void
hibernate_scratch_io(hibernate_scratch_t * scratch, void * buffer, size_t size, bool write)
{
	// copy data to or from "scratch" based on the value of "write"
	if (!write) {
		// check that we are in bounds
		HIB_ASSERT(scratch->curPos + size <= scratch->totalLength);
	}
	while (size) {
		// if we got to the end of a page (leaving room for our chain pointer), advance to the next page
		if (scratch->curPagePos == PAGE_SIZE - sizeof(ppnum_t)) {
			ppnum_t *nextPage = (ppnum_t *)(scratch->curPage + scratch->curPagePos);
			if (write) {
				// allocate the next page and store the page number
				*nextPage = hibernate_page_list_grab(scratch->map, scratch->nextFree);
			}
			scratch->curPage = (uint8_t *)pal_hib_map(SCRATCH_AREA, ptoa_64(*nextPage));
			scratch->curPagePos = 0;
		}
		size_t curPageRemaining = PAGE_SIZE - sizeof(ppnum_t) - scratch->curPagePos;
		size_t toCopy = MIN(size, curPageRemaining);
		if (write) {
			// copy from "buffer" into "scratch"
			__nosan_memcpy(scratch->curPage + scratch->curPagePos, buffer, toCopy);
		} else {
			// copy from "scratch" into "buffer"
			__nosan_memcpy(buffer, scratch->curPage + scratch->curPagePos, toCopy);
		}
		scratch->curPos += toCopy;
		scratch->curPagePos += toCopy;
		buffer = (void *)((uintptr_t)buffer + toCopy);
		size -= toCopy;
	}
}

void
hibernate_scratch_write(hibernate_scratch_t * scratch, const void * buffer, size_t size)
{
	hibernate_scratch_io(scratch, (void *)(uintptr_t)buffer, size, true);
}

void
hibernate_scratch_read(hibernate_scratch_t * scratch, void * buffer, size_t size)
{
	hibernate_scratch_io(scratch, buffer, size, false);
}

#pragma mark -

static uint32_t
store_one_page(uint32_t procFlags, uint32_t * src, uint32_t compressedSize,
    uint8_t * scratch, uint32_t ppnum)
{
	uint64_t dst = ptoa_64(ppnum);

	if (compressedSize != PAGE_SIZE) {
		dst = pal_hib_map(DEST_COPY_AREA, dst);
		if (compressedSize != 4) {
			pal_hib_decompress_page(src, (void *)dst, scratch, compressedSize);
		} else {
			size_t i;
			uint32_t s, *d;

			s = *src;
			d = (uint32_t *)(uintptr_t)dst;
			if (!s) {
				__nosan_bzero((void *) dst, PAGE_SIZE);
			} else {
				for (i = 0; i < (PAGE_SIZE / sizeof(int32_t)); i++) {
					*d++ = s;
				}
			}
		}
	} else {
		dst = hibernate_restore_phys_page((uint64_t) (uintptr_t) src, dst, PAGE_SIZE, procFlags);
	}

	return hibernate_sum_page((uint8_t *)(uintptr_t)dst, ppnum);
}

void
hibernate_reserve_restore_pages(uint64_t headerPhys, IOHibernateImageHeader *header, hibernate_page_list_t * map)
{
	uint32_t lastImagePage    = atop_64_ppnum(HIB_ROUND_PAGE(headerPhys + header->image1Size));
	uint32_t handoffPages     = header->handoffPages;
	uint32_t handoffPageCount = header->handoffPageCount;
	uint32_t ppnum;

	// knock all the image pages to be used out of free map
	for (ppnum = atop_64_ppnum(headerPhys); ppnum <= lastImagePage; ppnum++) {
		hibernate_page_bitset(map, FALSE, ppnum);
	}
	// knock all the handoff pages to be used out of free map
	for (ppnum = handoffPages; ppnum < (handoffPages + handoffPageCount); ppnum++) {
		hibernate_page_bitset(map, FALSE, ppnum);
	}
}

long
hibernate_kernel_entrypoint(uint32_t p1,
    uint32_t p2, uint32_t p3, uint32_t p4)
{
	uint64_t headerPhys;
	uint64_t mapPhys;
	uint64_t srcPhys;
	uint64_t imageReadPhys;
	uint64_t pageIndexPhys;
	uint32_t * pageIndexSource;
	hibernate_page_list_t * map;
	pal_hib_restore_stage_t stage;
	uint32_t count;
	uint32_t ppnum;
	uint32_t page;
	uint32_t conflictCount;
	uint32_t compressedSize;
	uint32_t uncompressedPages;
	uint32_t * src;
	uint32_t sum;
	uint32_t pageSum;
	uint32_t nextFree;
	uint32_t lastImagePage;
	uint32_t lastMapPage;
	uint32_t lastPageIndexPage;
	uint32_t handoffPages;
	uint32_t handoffPageCount;
	uint8_t * wkdmScratch;
	hibernate_scratch_t conflictList = {};
	pal_hib_ctx_t palHibCtx;

	uint64_t timeStart;
	timeStart = rdtsc64();

#if defined(__arm64__)
	serial_hibernation_init();
#endif /* defined(__arm64__) */

#if !defined(__arm64__)
	static_assert(sizeof(IOHibernateImageHeader) == 512);
#endif /* !defined(__arm64__) */

	headerPhys = ptoa_64(p1);

	if ((kIOHibernateDebugRestoreLogs & gIOHibernateDebugFlags) && !debug_probe()) {
		gIOHibernateDebugFlags &= ~kIOHibernateDebugRestoreLogs;
	}

	debug_code(kIOHibernateRestoreCodeImageStart, headerPhys);

	__nosan_memcpy(gIOHibernateCurrentHeader,
	    (void *) pal_hib_map(IMAGE_AREA, headerPhys),
	    sizeof(IOHibernateImageHeader));

	debug_code(kIOHibernateRestoreCodeSignature, gIOHibernateCurrentHeader->signature);

	mapPhys = headerPhys
	    + (offsetof(IOHibernateImageHeader, fileExtentMap)
	    + gIOHibernateCurrentHeader->fileExtentMapSize
	    + ptoa_32(gIOHibernateCurrentHeader->restore1PageCount)
	    + gIOHibernateCurrentHeader->previewSize);

	map = (hibernate_page_list_t *) pal_hib_map(BITMAP_AREA, mapPhys);


	// make the rest of the image is safe for atop()
	uint64_t imageEnd;
	if (os_add_overflow(headerPhys, gIOHibernateCurrentHeader->image1Size, &imageEnd) || (imageEnd > IO_MAX_PAGE_ADDR)) {
		HIB_ASSERT(0);
	}

	lastImagePage = atop_64_ppnum(HIB_ROUND_PAGE(headerPhys + gIOHibernateCurrentHeader->image1Size));
	lastMapPage = atop_64_ppnum(HIB_ROUND_PAGE(mapPhys + gIOHibernateCurrentHeader->bitmapSize));

	handoffPages     = gIOHibernateCurrentHeader->handoffPages;
	handoffPageCount = gIOHibernateCurrentHeader->handoffPageCount;

	debug_code(kIOHibernateRestoreCodeImageEnd, ptoa_64(lastImagePage));
	debug_code(kIOHibernateRestoreCodeMapStart, mapPhys);
	debug_code(kIOHibernateRestoreCodeMapEnd, ptoa_64(lastMapPage));

	debug_code(kIOHibernateRestoreCodeMapVirt, (uintptr_t) map);
	debug_code(kIOHibernateRestoreCodeHandoffPages, ptoa_64(handoffPages));
	debug_code(kIOHibernateRestoreCodeHandoffCount, handoffPageCount);

#if defined(__arm64__)
	// on arm64 we've already done this in pal_hib_resume_tramp
#else /* !defined(__arm64__) */
	hibernate_reserve_restore_pages(headerPhys, gIOHibernateCurrentHeader, map);
#endif /* !defined(__arm64__) */

	nextFree = 0;
	hibernate_page_list_grab(map, &nextFree);

	pal_hib_resume_init(&palHibCtx, map, &nextFree);

	// allocate scratch space for wkdm
	wkdmScratch = (uint8_t *)pal_hib_map(WKDM_AREA, ptoa_64(hibernate_page_list_grab(map, &nextFree)));

	sum = gIOHibernateCurrentHeader->actualRestore1Sum;
	gIOHibernateCurrentHeader->diag[0] = atop_64_ppnum(headerPhys);
	gIOHibernateCurrentHeader->diag[1] = sum;
	gIOHibernateCurrentHeader->trampolineTime = 0;

	uncompressedPages    = 0;
	conflictCount        = 0;

	compressedSize       = PAGE_SIZE;
	stage                = pal_hib_restore_stage_handoff_data;
	count                = 0;
	srcPhys              = 0;

	if (gIOHibernateCurrentHeader->previewSize) {
		pageIndexPhys     = headerPhys
		    + (offsetof(IOHibernateImageHeader, fileExtentMap)
		    + gIOHibernateCurrentHeader->fileExtentMapSize
		    + ptoa_32(gIOHibernateCurrentHeader->restore1PageCount));
		imageReadPhys     = (pageIndexPhys + gIOHibernateCurrentHeader->previewPageListSize);
		lastPageIndexPage = atop_64_ppnum(HIB_ROUND_PAGE(imageReadPhys));
		pageIndexSource   = (uint32_t *) pal_hib_map(IMAGE2_AREA, pageIndexPhys);
	} else {
		pageIndexPhys     = 0;
		lastPageIndexPage = 0;
		imageReadPhys     = (mapPhys + gIOHibernateCurrentHeader->bitmapSize);
	}

	debug_code(kIOHibernateRestoreCodePageIndexStart, pageIndexPhys);
	debug_code(kIOHibernateRestoreCodePageIndexEnd, ptoa_64(lastPageIndexPage));

	while (1) {
		switch (stage) {
		case pal_hib_restore_stage_handoff_data:
			// copy handoff data
			count = srcPhys ? 0 : handoffPageCount;
			if (!count) {
				break;
			}
			if (count > gIOHibernateHandoffPageCount) {
				count = gIOHibernateHandoffPageCount;
			}
			srcPhys = ptoa_64(handoffPages);
			break;

		case pal_hib_restore_stage_preview_pages:
			// copy pageIndexSource pages == preview image data
			if (!srcPhys) {
				if (!pageIndexPhys) {
					break;
				}
				srcPhys = imageReadPhys;
			}
			ppnum = pageIndexSource[0];
			count = pageIndexSource[1];
			pageIndexSource += 2;
			pageIndexPhys   += 2 * sizeof(pageIndexSource[0]);
			imageReadPhys = srcPhys;
			break;

		case pal_hib_restore_stage_dram_pages:
			// copy pages
			if (!srcPhys) {
				srcPhys = (mapPhys + gIOHibernateCurrentHeader->bitmapSize);
			}
			src = (uint32_t *) pal_hib_map(IMAGE_AREA, srcPhys);
			ppnum = src[0];
			count = src[1];
			srcPhys += 2 * sizeof(*src);
			imageReadPhys = srcPhys;
			break;
		}


		if (!count) {
			if (stage == pal_hib_restore_stage_dram_pages) {
				break;
			}
			stage--;
			srcPhys = 0;
			continue;
		}

		for (page = 0; page < count; page++, ppnum++) {
			uint32_t tag;
			int conflicts;

			src = (uint32_t *) pal_hib_map(IMAGE_AREA, srcPhys);

			if (stage == pal_hib_restore_stage_handoff_data) {
				ppnum = gIOHibernateHandoffPages[page];
			} else if (stage == pal_hib_restore_stage_dram_pages) {
				tag = *src++;
				HIB_ASSERT((tag & kIOHibernateTagSigMask) == kIOHibernateTagSignature);
//		debug_code(kIOHibernateRestoreCodeTag, (uintptr_t) tag);
				srcPhys += sizeof(*src);
				compressedSize = kIOHibernateTagLength & tag;
				HIB_ASSERT(compressedSize <= PAGE_SIZE);
			}

			conflicts = (ppnum >= atop_64_ppnum(mapPhys)) && (ppnum <= lastMapPage);

			conflicts |= ((ppnum >= atop_64_ppnum(imageReadPhys)) && (ppnum <= lastImagePage));

			if (stage >= pal_hib_restore_stage_handoff_data) {
				conflicts |= ((ppnum >= atop_64_ppnum(srcPhys)) && (ppnum <= (handoffPages + handoffPageCount - 1)));
			}

			if (stage >= pal_hib_restore_stage_preview_pages) {
				conflicts |= ((ppnum >= atop_64_ppnum(pageIndexPhys)) && (ppnum <= lastPageIndexPage));
			}

			if (!conflicts) {
				pageSum = store_one_page(gIOHibernateCurrentHeader->processorFlags,
				    src, compressedSize, wkdmScratch, ppnum);
				if (stage != pal_hib_restore_stage_handoff_data) {
					sum += pageSum;
				}
				uncompressedPages++;
			} else {
//		debug_code(kIOHibernateRestoreCodeConflictPage,   ppnum);
//		debug_code(kIOHibernateRestoreCodeConflictSource, (uintptr_t) src);
				conflictCount++;
				if (!conflictList.headPage) {
					hibernate_scratch_init(&conflictList, map, &nextFree);
				}
				hibernate_scratch_write(&conflictList, &ppnum, sizeof(ppnum));
				hibernate_scratch_write(&conflictList, &compressedSize, sizeof(compressedSize));
				hibernate_scratch_write(&conflictList, &stage, sizeof(stage));
				hibernate_scratch_write(&conflictList, src, compressedSize);
			}
			srcPhys += ((compressedSize + 3) & ~3);
			src     += ((compressedSize + 3) >> 2);
			pal_hib_restored_page(&palHibCtx, stage, ppnum);
		}
	}

	/* src points to the last page restored, so we need to skip over that */
	pal_hib_restore_pal_state(src);

	// -- copy back conflicts

	if (conflictCount) {
		src = (uint32_t *)pal_hib_map(COPY_PAGE_AREA, ptoa_64(hibernate_page_list_grab(map, &nextFree)));
		hibernate_scratch_start_read(&conflictList);
		for (uint32_t i = 0; i < conflictCount; i++) {
			hibernate_scratch_read(&conflictList, &ppnum, sizeof(ppnum));
			hibernate_scratch_read(&conflictList, &compressedSize, sizeof(compressedSize));
			hibernate_scratch_read(&conflictList, &stage, sizeof(stage));
			HIB_ASSERT(compressedSize <= PAGE_SIZE);
			hibernate_scratch_read(&conflictList, src, compressedSize);
			pageSum        = store_one_page(gIOHibernateCurrentHeader->processorFlags,
			    src, compressedSize, wkdmScratch, ppnum);
			if (stage != pal_hib_restore_stage_handoff_data) {
				sum += pageSum;
			}
			uncompressedPages++;
		}
	}

	pal_hib_patchup(&palHibCtx);

	// -- image has been destroyed...

	gIOHibernateCurrentHeader->actualImage1Sum         = sum;
	gIOHibernateCurrentHeader->actualUncompressedPages = uncompressedPages;
	gIOHibernateCurrentHeader->conflictCount           = conflictCount;
	gIOHibernateCurrentHeader->nextFree                = nextFree;

	gIOHibernateState = kIOHibernateStateWakingFromHibernate;

	gIOHibernateCurrentHeader->trampolineTime = ((uint32_t) (((rdtsc64() - timeStart)) >> 8));

//  debug_code('done', 0);

#if CONFIG_SLEEP
#if defined(__i386__) || defined(__x86_64__)
	typedef void (*ResetProc)(void);
	ResetProc proc;
	proc = HIB_ENTRYPOINT;
	// flush caches
	__asm__("wbinvd");
	proc();
	return -1;
#elif defined(__arm64__)
	// return control to hibernate_machine_entrypoint
	return 0;
#else
// implement me
#endif
#endif
}

#if CONFIG_DEBUG
/* standalone printf implementation */
/*-
 * Copyright (c) 1986, 1988, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *	@(#)subr_prf.c	8.3 (Berkeley) 1/21/94
 */

typedef long ptrdiff_t;
char const hibhex2ascii_data[] = "0123456789abcdefghijklmnopqrstuvwxyz";
#define hibhex2ascii(hex)  (hibhex2ascii_data[hex])
#define toupper(c)      ((c) - 0x20 * (((c) >= 'a') && ((c) <= 'z')))
static size_t
hibstrlen(const char *s)
{
	size_t l = 0;
	while (*s++) {
		l++;
	}
	return l;
}

/* Max number conversion buffer length: a u_quad_t in base 2, plus NUL byte. */
#define MAXNBUF (sizeof(intmax_t) * NBBY + 1)

/*
 * Put a NUL-terminated ASCII number (base <= 36) in a buffer in reverse
 * order; return an optional length and a pointer to the last character
 * written in the buffer (i.e., the first character of the string).
 * The buffer pointed to by `nbuf' must have length >= MAXNBUF.
 */
static char *
ksprintn(char *nbuf, uintmax_t num, int base, int *lenp, int upper)
{
	char *p, c;

	/* Truncate so we don't call umoddi3, which isn't in __HIB */
#if !defined(__LP64__)
	uint32_t num2 = (uint32_t) num;
#else
	uintmax_t num2 = num;
#endif

	p = nbuf;
	*p = '\0';
	do {
		c = hibhex2ascii(num2 % base);
		*++p = upper ? toupper(c) : c;
	} while (num2 /= base);
	if (lenp) {
		*lenp = (int)(p - nbuf);
	}
	return p;
}

/*
 * Scaled down version of printf(3).
 *
 * Two additional formats:
 *
 * The format %b is supported to decode error registers.
 * Its usage is:
 *
 *	printf("reg=%b\n", regval, "<base><arg>*");
 *
 * where <base> is the output base expressed as a control character, e.g.
 * \10 gives octal; \20 gives hex.  Each arg is a sequence of characters,
 * the first of which gives the bit number to be inspected (origin 1), and
 * the next characters (up to a control character, i.e. a character <= 32),
 * give the name of the register.  Thus:
 *
 *	kvprintf("reg=%b\n", 3, "\10\2BITTWO\1BITONE");
 *
 * would produce output:
 *
 *	reg=3<BITTWO,BITONE>
 *
 * XXX:  %D  -- Hexdump, takes pointer and separator string:
 *		("%6D", ptr, ":")   -> XX:XX:XX:XX:XX:XX
 *		("%*D", len, ptr, " " -> XX XX XX XX ...
 */
static int
hibkvprintf(char const *fmt, void (*func)(int, void*), void *arg, int radix, va_list ap)
{
#define PCHAR(c) {int cc=(c); if (func) (*func)(cc,arg); else *d++ = (char)cc; retval++; }
	char nbuf[MAXNBUF];
	char *d;
	const char *p, *percent, *q;
	u_char *up;
	int ch, n;
	uintmax_t num;
	int base, lflag, qflag, tmp, width, ladjust, sharpflag, neg, sign, dot;
	int cflag, hflag, jflag, tflag, zflag;
	int dwidth, upper;
	char padc;
	int stop = 0, retval = 0;

	num = 0;
	if (!func) {
		d = (char *) arg;
	} else {
		d = NULL;
	}

	if (fmt == NULL) {
		fmt = "(fmt null)\n";
	}

	if (radix < 2 || radix > 36) {
		radix = 10;
	}

	for (;;) {
		padc = ' ';
		width = 0;
		while ((ch = (u_char) * fmt++) != '%' || stop) {
			if (ch == '\0') {
				return retval;
			}
			PCHAR(ch);
		}
		percent = fmt - 1;
		qflag = 0; lflag = 0; ladjust = 0; sharpflag = 0; neg = 0;
		sign = 0; dot = 0; dwidth = 0; upper = 0;
		cflag = 0; hflag = 0; jflag = 0; tflag = 0; zflag = 0;
reswitch:       switch (ch = (u_char) * fmt++) {
		case '.':
			dot = 1;
			goto reswitch;
		case '#':
			sharpflag = 1;
			goto reswitch;
		case '+':
			sign = 1;
			goto reswitch;
		case '-':
			ladjust = 1;
			goto reswitch;
		case '%':
			PCHAR(ch);
			break;
		case '*':
			if (!dot) {
				width = va_arg(ap, int);
				if (width < 0) {
					ladjust = !ladjust;
					width = -width;
				}
			} else {
				dwidth = va_arg(ap, int);
			}
			goto reswitch;
		case '0':
			if (!dot) {
				padc = '0';
				goto reswitch;
			}
		case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			for (n = 0;; ++fmt) {
				n = n * 10 + ch - '0';
				ch = *fmt;
				if (ch < '0' || ch > '9') {
					break;
				}
			}
			if (dot) {
				dwidth = n;
			} else {
				width = n;
			}
			goto reswitch;
		case 'b':
			num = (u_int)va_arg(ap, int);
			p = va_arg(ap, char *);
			for (q = ksprintn(nbuf, num, *p++, NULL, 0); *q;) {
				PCHAR(*q--);
			}

			if (num == 0) {
				break;
			}

			for (tmp = 0; *p;) {
				n = *p++;
				if (num & (1 << (n - 1))) {
					PCHAR(tmp ? ',' : '<');
					for (; (n = *p) > ' '; ++p) {
						PCHAR(n);
					}
					tmp = 1;
				} else {
					for (; *p > ' '; ++p) {
						continue;
					}
				}
			}
			if (tmp) {
				PCHAR('>');
			}
			break;
		case 'c':
			PCHAR(va_arg(ap, int));
			break;
		case 'D':
			up = va_arg(ap, u_char *);
			p = va_arg(ap, char *);
			if (!width) {
				width = 16;
			}
			while (width--) {
				PCHAR(hibhex2ascii(*up >> 4));
				PCHAR(hibhex2ascii(*up & 0x0f));
				up++;
				if (width) {
					for (q = p; *q; q++) {
						PCHAR(*q);
					}
				}
			}
			break;
		case 'd':
		case 'i':
			base = 10;
			sign = 1;
			goto handle_sign;
		case 'h':
			if (hflag) {
				hflag = 0;
				cflag = 1;
			} else {
				hflag = 1;
			}
			goto reswitch;
		case 'j':
			jflag = 1;
			goto reswitch;
		case 'l':
			if (lflag) {
				lflag = 0;
				qflag = 1;
			} else {
				lflag = 1;
			}
			goto reswitch;
		case 'n':
			if (jflag) {
				*(va_arg(ap, intmax_t *)) = retval;
			} else if (qflag) {
				*(va_arg(ap, quad_t *)) = retval;
			} else if (lflag) {
				*(va_arg(ap, long *)) = retval;
			} else if (zflag) {
				*(va_arg(ap, size_t *)) = retval;
			} else if (hflag) {
				*(va_arg(ap, short *)) = (short)retval;
			} else if (cflag) {
				*(va_arg(ap, char *)) = (char)retval;
			} else {
				*(va_arg(ap, int *)) = retval;
			}
			break;
		case 'o':
			base = 8;
			goto handle_nosign;
		case 'p':
			base = 16;
			sharpflag = (width == 0);
			sign = 0;
			num = (uintptr_t)va_arg(ap, void *);
			goto number;
		case 'q':
			qflag = 1;
			goto reswitch;
		case 'r':
			base = radix;
			if (sign) {
				goto handle_sign;
			}
			goto handle_nosign;
		case 's':
			p = va_arg(ap, char *);
			if (p == NULL) {
				p = "(null)";
			}
			if (!dot) {
				n = (typeof(n))hibstrlen(p);
			} else {
				for (n = 0; n < dwidth && p[n]; n++) {
					continue;
				}
			}

			width -= n;

			if (!ladjust && width > 0) {
				while (width--) {
					PCHAR(padc);
				}
			}
			while (n--) {
				PCHAR(*p++);
			}
			if (ladjust && width > 0) {
				while (width--) {
					PCHAR(padc);
				}
			}
			break;
		case 't':
			tflag = 1;
			goto reswitch;
		case 'u':
			base = 10;
			goto handle_nosign;
		case 'X':
			upper = 1;
		case 'x':
			base = 16;
			goto handle_nosign;
		case 'y':
			base = 16;
			sign = 1;
			goto handle_sign;
		case 'z':
			zflag = 1;
			goto reswitch;
handle_nosign:
			sign = 0;
			if (jflag) {
				num = va_arg(ap, uintmax_t);
			} else if (qflag) {
				num = va_arg(ap, u_quad_t);
			} else if (tflag) {
				num = va_arg(ap, ptrdiff_t);
			} else if (lflag) {
				num = va_arg(ap, u_long);
			} else if (zflag) {
				num = va_arg(ap, size_t);
			} else if (hflag) {
				num = (u_short)va_arg(ap, int);
			} else if (cflag) {
				num = (u_char)va_arg(ap, int);
			} else {
				num = va_arg(ap, u_int);
			}
			goto number;
handle_sign:
			if (jflag) {
				num = va_arg(ap, intmax_t);
			} else if (qflag) {
				num = va_arg(ap, quad_t);
			} else if (tflag) {
				num = va_arg(ap, ptrdiff_t);
			} else if (lflag) {
				num = va_arg(ap, long);
			} else if (zflag) {
				num = va_arg(ap, ssize_t);
			} else if (hflag) {
				num = (short)va_arg(ap, int);
			} else if (cflag) {
				num = (char)va_arg(ap, int);
			} else {
				num = va_arg(ap, int);
			}
number:
			if (sign && (intmax_t)num < 0) {
				neg = 1;
				num = -(intmax_t)num;
			}
			p = ksprintn(nbuf, num, base, &tmp, upper);
			if (sharpflag && num != 0) {
				if (base == 8) {
					tmp++;
				} else if (base == 16) {
					tmp += 2;
				}
			}
			if (neg) {
				tmp++;
			}

			if (!ladjust && padc != '0' && width
			    && (width -= tmp) > 0) {
				while (width--) {
					PCHAR(padc);
				}
			}
			if (neg) {
				PCHAR('-');
			}
			if (sharpflag && num != 0) {
				if (base == 8) {
					PCHAR('0');
				} else if (base == 16) {
					PCHAR('0');
					PCHAR('x');
				}
			}
			if (!ladjust && width && (width -= tmp) > 0) {
				while (width--) {
					PCHAR(padc);
				}
			}

			while (*p) {
				PCHAR(*p--);
			}

			if (ladjust && width && (width -= tmp) > 0) {
				while (width--) {
					PCHAR(padc);
				}
			}

			break;
		default:
			while (percent < fmt) {
				PCHAR(*percent++);
			}
			/*
			 * Since we ignore a formatting argument it is no
			 * longer safe to obey the remaining formatting
			 * arguments as the arguments will no longer match
			 * the format specs.
			 */
			stop = 1;
			break;
		}
	}
#undef PCHAR
}


static void
putchar(int c, void *arg)
{
	(void)arg;
	hib_uart_putc((char)c);
}

void
hibprintf(const char *fmt, ...)
{
	/* http://www.pagetable.com/?p=298 */
	va_list ap;

	va_start(ap, fmt);
	hibkvprintf(fmt, putchar, NULL, 10, ap);
	va_end(ap);
}
#endif /* CONFIG_DEBUG */

#if __arm64__ && HIBERNATE_TRAP_HANDLER
void
hibernate_trap(__unused arm_context_t *context, __unused uint64_t trap_addr)
__attribute__((optnone))
{
	// enable logging
	gIOHibernateDebugFlags |= kIOHibernateDebugRestoreLogs;

	// dump some interesting registers
	for (int i = 0; i < 29; i++) {
		debug_code(' r00' + (i / 10 * 256) + (i % 10), context->ss.ss_64.x[i]);
	}
	debug_code('  fp', context->ss.ss_64.fp);
	debug_code('  lr', context->ss.ss_64.lr);
	debug_code('  sp', context->ss.ss_64.sp);
	debug_code('  pc', context->ss.ss_64.pc);
	debug_code('cpsr', context->ss.ss_64.cpsr);
	debug_code(' far', context->ss.ss_64.far);
	debug_code(' esr', context->ss.ss_64.esr);

	// dump the trap_addr
	debug_code('trap', trap_addr);

	// dump the kernel slide
	debug_code('slid', _hibernateHeader.kernVirtSlide);

	// loop forever
	while (true) {
		;
	}
}
#endif /* __arm64__ && HIBERNATE_TRAP_HANDLER */
