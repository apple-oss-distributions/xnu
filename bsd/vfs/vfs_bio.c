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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1994 Christopher G. Demetriou
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)vfs_bio.c	8.6 (Berkeley) 1/11/94
 */

/*
 * Some references:
 *	Bach: The Design of the UNIX Operating System (Prentice Hall, 1986)
 *	Leffler, et al.: The Design and Implementation of the 4.3BSD
 *		UNIX Operating System (Addison Welley, 1989)
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/buf_internal.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/trace.h>
#include <kern/kalloc.h>
#include <sys/resourcevar.h>
#include <miscfs/specfs/specdev.h>
#include <sys/ubc.h>
#include <sys/kauth.h>
#if DIAGNOSTIC
#include <kern/assert.h>
#endif /* DIAGNOSTIC */
#include <kern/task.h>
#include <kern/zalloc.h>
#include <kern/locks.h>
#include <kern/thread.h>

#include <sys/fslog.h>          /* fslog_io_error() */
#include <sys/disk.h>           /* dk_error_description_t */

#include <mach/mach_types.h>
#include <mach/memory_object_types.h>
#include <kern/sched_prim.h>    /* thread_block() */

#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

#include <sys/kdebug.h>

#include <libkern/OSAtomic.h>
#include <libkern/OSDebug.h>
#include <sys/ubc_internal.h>

#include <sys/sdt.h>

int     bcleanbuf(buf_t bp, boolean_t discard);
static int      brecover_data(buf_t bp);
static boolean_t incore(vnode_t vp, daddr64_t blkno);
/* timeout is in msecs */
static buf_t    getnewbuf(int slpflag, int slptimeo, int *queue);
static void     bremfree_locked(buf_t bp);
static void     buf_reassign(buf_t bp, vnode_t newvp);
static errno_t  buf_acquire_locked(buf_t bp, int flags, int slpflag, int slptimeo);
static int      buf_iterprepare(vnode_t vp, struct buflists *, int flags);
static void     buf_itercomplete(vnode_t vp, struct buflists *, int flags);
static boolean_t buffer_cache_gc(int);
static buf_t    buf_brelse_shadow(buf_t bp);
static void     buf_free_meta_store(buf_t bp);

static buf_t    buf_create_shadow_internal(buf_t bp, boolean_t force_copy,
    uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg, int priv);


int  bdwrite_internal(buf_t, int);

extern void disk_conditioner_delay(buf_t, int, int, uint64_t);

/* zone allocated buffer headers */
static void     bcleanbuf_thread_init(void);
static void     bcleanbuf_thread(void);

static ZONE_DEFINE_TYPE(buf_hdr_zone, "buf headers", struct buf, ZC_NONE);
static int      buf_hdr_count;


/*
 * Definitions for the buffer hash lists.
 */
#define BUFHASH(dvp, lbn)       \
	(&bufhashtbl[((long)(dvp) / sizeof(*(dvp)) + (int)(lbn)) & bufhash])
LIST_HEAD(bufhashhdr, buf) * bufhashtbl, invalhash;
u_long  bufhash;

static buf_t    incore_locked(vnode_t vp, daddr64_t blkno, struct bufhashhdr *dp);

/* Definitions for the buffer stats. */
struct bufstats bufstats;

/* Number of delayed write buffers */
long nbdwrite = 0;
int blaundrycnt = 0;
static int boot_nbuf_headers = 0;

static TAILQ_HEAD(delayqueue, buf) delaybufqueue;

static TAILQ_HEAD(ioqueue, buf) iobufqueue;
static TAILQ_HEAD(bqueues, buf) bufqueues[BQUEUES];
static int needbuffer;
static int need_iobuffer;

static LCK_GRP_DECLARE(buf_mtx_grp, "buffer cache");
static LCK_ATTR_DECLARE(buf_mtx_attr, 0, 0);
static LCK_MTX_DECLARE_ATTR(iobuffer_mtxp, &buf_mtx_grp, &buf_mtx_attr);
static LCK_MTX_DECLARE_ATTR(buf_mtx, &buf_mtx_grp, &buf_mtx_attr);
static LCK_MTX_DECLARE_ATTR(buf_gc_callout, &buf_mtx_grp, &buf_mtx_attr);

static uint32_t buf_busycount;

#define FS_BUFFER_CACHE_GC_CALLOUTS_MAX_SIZE 16
typedef struct {
	void (* callout)(int, void *);
	void *context;
} fs_buffer_cache_gc_callout_t;

fs_buffer_cache_gc_callout_t fs_callouts[FS_BUFFER_CACHE_GC_CALLOUTS_MAX_SIZE] = { {NULL, NULL} };

static __inline__ int
buf_timestamp(void)
{
	struct  timeval         t;
	microuptime(&t);
	return (int)t.tv_sec;
}

/*
 * Insq/Remq for the buffer free lists.
 */
#define binsheadfree(bp, dp, whichq)    do { \
	                            TAILQ_INSERT_HEAD(dp, bp, b_freelist); \
	                        } while (0)

#define binstailfree(bp, dp, whichq)    do { \
	                            TAILQ_INSERT_TAIL(dp, bp, b_freelist); \
	                        } while (0)

#define BHASHENTCHECK(bp)       \
	if ((bp)->b_hash.le_prev != (struct buf **)0xdeadbeef)  \
	        panic("%p: b_hash.le_prev is not deadbeef", (bp));

#define BLISTNONE(bp)   \
	(bp)->b_hash.le_next = (struct buf *)0; \
	(bp)->b_hash.le_prev = (struct buf **)0xdeadbeef;

/*
 * Insq/Remq for the vnode usage lists.
 */
#define bufinsvn(bp, dp)        LIST_INSERT_HEAD(dp, bp, b_vnbufs)
#define bufremvn(bp) {                                                  \
	LIST_REMOVE(bp, b_vnbufs);                                      \
	(bp)->b_vnbufs.le_next = NOLIST;                                \
}

/*
 * Time in seconds before a buffer on a list is
 * considered as a stale buffer
 */
#define LRU_IS_STALE 120 /* default value for the LRU */
#define AGE_IS_STALE 60  /* default value for the AGE */
#define META_IS_STALE 180 /* default value for the BQ_META */

int lru_is_stale = LRU_IS_STALE;
int age_is_stale = AGE_IS_STALE;
int meta_is_stale = META_IS_STALE;

#define MAXLAUNDRY      10

/* LIST_INSERT_HEAD() with assertions */
static __inline__ void
blistenterhead(struct bufhashhdr * head, buf_t bp)
{
	if ((bp->b_hash.le_next = (head)->lh_first) != NULL) {
		(head)->lh_first->b_hash.le_prev = &(bp)->b_hash.le_next;
	}
	(head)->lh_first = bp;
	bp->b_hash.le_prev = &(head)->lh_first;
	if (bp->b_hash.le_prev == (struct buf **)0xdeadbeef) {
		panic("blistenterhead: le_prev is deadbeef");
	}
}

static __inline__ void
binshash(buf_t bp, struct bufhashhdr *dp)
{
#if DIAGNOSTIC
	buf_t   nbp;
#endif /* DIAGNOSTIC */

	BHASHENTCHECK(bp);

#if DIAGNOSTIC
	nbp = dp->lh_first;
	for (; nbp != NULL; nbp = nbp->b_hash.le_next) {
		if (nbp == bp) {
			panic("buf already in hashlist");
		}
	}
#endif /* DIAGNOSTIC */

	blistenterhead(dp, bp);
}

static __inline__ void
bremhash(buf_t  bp)
{
	if (bp->b_hash.le_prev == (struct buf **)0xdeadbeef) {
		panic("bremhash le_prev is deadbeef");
	}
	if (bp->b_hash.le_next == bp) {
		panic("bremhash: next points to self");
	}

	if (bp->b_hash.le_next != NULL) {
		bp->b_hash.le_next->b_hash.le_prev = bp->b_hash.le_prev;
	}
	*bp->b_hash.le_prev = (bp)->b_hash.le_next;
}

/*
 * buf_mtx held.
 */
static __inline__ void
bmovelaundry(buf_t bp)
{
	bp->b_whichq = BQ_LAUNDRY;
	bp->b_timestamp = buf_timestamp();
	binstailfree(bp, &bufqueues[BQ_LAUNDRY], BQ_LAUNDRY);
	blaundrycnt++;
}

static __inline__ void
buf_release_credentials(buf_t bp)
{
	if (IS_VALID_CRED(bp->b_rcred)) {
		kauth_cred_unref(&bp->b_rcred);
	}
	if (IS_VALID_CRED(bp->b_wcred)) {
		kauth_cred_unref(&bp->b_wcred);
	}
}


int
buf_valid(buf_t bp)
{
	if ((bp->b_flags & (B_DONE | B_DELWRI))) {
		return 1;
	}
	return 0;
}

int
buf_fromcache(buf_t bp)
{
	if ((bp->b_flags & B_CACHE)) {
		return 1;
	}
	return 0;
}

void
buf_markinvalid(buf_t bp)
{
	SET(bp->b_flags, B_INVAL);
}

void
buf_markdelayed(buf_t bp)
{
	if (!ISSET(bp->b_flags, B_DELWRI)) {
		SET(bp->b_flags, B_DELWRI);

		OSAddAtomicLong(1, &nbdwrite);
		buf_reassign(bp, bp->b_vp);
	}
	SET(bp->b_flags, B_DONE);
}

void
buf_markclean(buf_t bp)
{
	if (ISSET(bp->b_flags, B_DELWRI)) {
		CLR(bp->b_flags, B_DELWRI);

		OSAddAtomicLong(-1, &nbdwrite);
		buf_reassign(bp, bp->b_vp);
	}
}

void
buf_markeintr(buf_t bp)
{
	SET(bp->b_flags, B_EINTR);
}


void
buf_markaged(buf_t bp)
{
	SET(bp->b_flags, B_AGE);
}

int
buf_fua(buf_t bp)
{
	if ((bp->b_flags & B_FUA) == B_FUA) {
		return 1;
	}
	return 0;
}

void
buf_markfua(buf_t bp)
{
	SET(bp->b_flags, B_FUA);
}

#if CONFIG_PROTECT
cpx_t
bufattr_cpx(bufattr_t bap)
{
	return bap->ba_cpx;
}

void
bufattr_setcpx(bufattr_t bap, cpx_t cpx)
{
	bap->ba_cpx = cpx;
}

void
buf_setcpoff(buf_t bp, uint64_t foffset)
{
	bp->b_attr.ba_cp_file_off = foffset;
}

uint64_t
bufattr_cpoff(bufattr_t bap)
{
	return bap->ba_cp_file_off;
}

void
bufattr_setcpoff(bufattr_t bap, uint64_t foffset)
{
	bap->ba_cp_file_off = foffset;
}

#else // !CONTECT_PROTECT

uint64_t
bufattr_cpoff(bufattr_t bap __unused)
{
	return 0;
}

void
bufattr_setcpoff(__unused bufattr_t bap, __unused uint64_t foffset)
{
	return;
}

struct cpx *
bufattr_cpx(__unused bufattr_t bap)
{
	return NULL;
}

void
bufattr_setcpx(__unused bufattr_t bap, __unused struct cpx *cpx)
{
}

#endif /* !CONFIG_PROTECT */

bufattr_t
bufattr_alloc(void)
{
	return kalloc_type(struct bufattr, Z_WAITOK | Z_ZERO);
}

void
bufattr_free(bufattr_t bap)
{
	kfree_type(struct bufattr, bap);
}

bufattr_t
bufattr_dup(bufattr_t bap)
{
	bufattr_t new_bufattr;
	new_bufattr = kalloc_type(struct bufattr, Z_WAITOK | Z_NOFAIL);

	/* Copy the provided one into the new copy */
	memcpy(new_bufattr, bap, sizeof(struct bufattr));
	return new_bufattr;
}

int
bufattr_rawencrypted(bufattr_t bap)
{
	if ((bap->ba_flags & BA_RAW_ENCRYPTED_IO)) {
		return 1;
	}
	return 0;
}

int
bufattr_throttled(bufattr_t bap)
{
	return GET_BUFATTR_IO_TIER(bap);
}

int
bufattr_passive(bufattr_t bap)
{
	if ((bap->ba_flags & BA_PASSIVE)) {
		return 1;
	}
	return 0;
}

int
bufattr_nocache(bufattr_t bap)
{
	if ((bap->ba_flags & BA_NOCACHE)) {
		return 1;
	}
	return 0;
}

int
bufattr_meta(bufattr_t bap)
{
	if ((bap->ba_flags & BA_META)) {
		return 1;
	}
	return 0;
}

void
bufattr_markmeta(bufattr_t bap)
{
	SET(bap->ba_flags, BA_META);
}

int
bufattr_delayidlesleep(bufattr_t bap)
{
	if ((bap->ba_flags & BA_DELAYIDLESLEEP)) {
		return 1;
	}
	return 0;
}

bufattr_t
buf_attr(buf_t bp)
{
	return &bp->b_attr;
}

void
buf_markstatic(buf_t bp __unused)
{
	SET(bp->b_flags, B_STATICCONTENT);
}

int
buf_static(buf_t bp)
{
	if ((bp->b_flags & B_STATICCONTENT)) {
		return 1;
	}
	return 0;
}

void
bufattr_markgreedymode(bufattr_t bap)
{
	SET(bap->ba_flags, BA_GREEDY_MODE);
}

int
bufattr_greedymode(bufattr_t bap)
{
	if ((bap->ba_flags & BA_GREEDY_MODE)) {
		return 1;
	}
	return 0;
}

void
bufattr_markisochronous(bufattr_t bap)
{
	SET(bap->ba_flags, BA_ISOCHRONOUS);
}

int
bufattr_isochronous(bufattr_t bap)
{
	if ((bap->ba_flags & BA_ISOCHRONOUS)) {
		return 1;
	}
	return 0;
}

void
bufattr_markquickcomplete(bufattr_t bap)
{
	SET(bap->ba_flags, BA_QUICK_COMPLETE);
}

int
bufattr_quickcomplete(bufattr_t bap)
{
	if ((bap->ba_flags & BA_QUICK_COMPLETE)) {
		return 1;
	}
	return 0;
}

void
bufattr_markioscheduled(bufattr_t bap)
{
	SET(bap->ba_flags, BA_IO_SCHEDULED);
}


int
bufattr_ioscheduled(bufattr_t bap)
{
	if ((bap->ba_flags & BA_IO_SCHEDULED)) {
		return 1;
	}
	return 0;
}

void
bufattr_markexpeditedmeta(bufattr_t bap)
{
	SET(bap->ba_flags, BA_EXPEDITED_META_IO);
}

int
bufattr_expeditedmeta(bufattr_t bap)
{
	if ((bap->ba_flags & BA_EXPEDITED_META_IO)) {
		return 1;
	}
	return 0;
}

int
bufattr_willverify(bufattr_t bap)
{
	if ((bap->ba_flags & BA_WILL_VERIFY)) {
		return 1;
	}
	return 0;
}

errno_t
buf_error(buf_t bp)
{
	return bp->b_error;
}

void
buf_seterror(buf_t bp, errno_t error)
{
	if ((bp->b_error = error)) {
		SET(bp->b_flags, B_ERROR);
	} else {
		CLR(bp->b_flags, B_ERROR);
	}
}

void
buf_setflags(buf_t bp, int32_t flags)
{
	SET(bp->b_flags, (flags & BUF_X_WRFLAGS));
}

void
buf_clearflags(buf_t bp, int32_t flags)
{
	CLR(bp->b_flags, (flags & BUF_X_WRFLAGS));
}

int32_t
buf_flags(buf_t bp)
{
	return bp->b_flags & BUF_X_RDFLAGS;
}

void
buf_reset(buf_t bp, int32_t io_flags)
{
	CLR(bp->b_flags, (B_READ | B_WRITE | B_ERROR | B_DONE | B_INVAL | B_ASYNC | B_NOCACHE | B_FUA));
	SET(bp->b_flags, (io_flags & (B_ASYNC | B_READ | B_WRITE | B_NOCACHE)));

	bp->b_error = 0;
}

uint32_t
buf_count(buf_t bp)
{
	return bp->b_bcount;
}

void
buf_setcount(buf_t bp, uint32_t bcount)
{
	bp->b_bcount = bcount;
}

uint32_t
buf_size(buf_t bp)
{
	return bp->b_bufsize;
}

void
buf_setsize(buf_t bp, uint32_t bufsize)
{
	bp->b_bufsize = bufsize;
}

uint32_t
buf_resid(buf_t bp)
{
	return bp->b_resid;
}

void
buf_setresid(buf_t bp, uint32_t resid)
{
	bp->b_resid = resid;
}

uint32_t
buf_dirtyoff(buf_t bp)
{
	return bp->b_dirtyoff;
}

uint32_t
buf_dirtyend(buf_t bp)
{
	return bp->b_dirtyend;
}

void
buf_setdirtyoff(buf_t bp, uint32_t dirtyoff)
{
	bp->b_dirtyoff = dirtyoff;
}

void
buf_setdirtyend(buf_t bp, uint32_t dirtyend)
{
	bp->b_dirtyend = dirtyend;
}

uintptr_t
buf_dataptr(buf_t bp)
{
	return bp->b_datap;
}

void
buf_setdataptr(buf_t bp, uintptr_t data)
{
	bp->b_datap = data;
}

vnode_t
buf_vnode(buf_t bp)
{
	return bp->b_vp;
}

void
buf_setvnode(buf_t bp, vnode_t vp)
{
	bp->b_vp = vp;
}


void *
buf_callback(buf_t bp)
{
	if (!(bp->b_flags & B_CALL)) {
		return (void *) NULL;
	}

	return (void *)bp->b_iodone;
}


errno_t
buf_setcallback(buf_t bp, void (*callback)(buf_t, void *), void *transaction)
{
	assert(!ISSET(bp->b_flags, B_FILTER) && ISSET(bp->b_lflags, BL_BUSY));

	if (callback) {
		bp->b_flags |= (B_CALL | B_ASYNC);
	} else {
		bp->b_flags &= ~B_CALL;
	}
	bp->b_transaction = transaction;
	bp->b_iodone = callback;

	return 0;
}

errno_t
buf_setupl(buf_t bp, upl_t upl, uint32_t offset)
{
	if (!(bp->b_lflags & BL_IOBUF)) {
		return EINVAL;
	}

	if (upl) {
		bp->b_flags |= B_CLUSTER;
	} else {
		bp->b_flags &= ~B_CLUSTER;
	}
	bp->b_upl = upl;
	bp->b_uploffset = offset;

	return 0;
}

buf_t
buf_clone(buf_t bp, int io_offset, int io_size, void (*iodone)(buf_t, void *), void *arg)
{
	buf_t   io_bp;
	int add1, add2;

	if (io_offset < 0 || io_size < 0) {
		return NULL;
	}

	if ((unsigned)(io_offset + io_size) > (unsigned)bp->b_bcount) {
		return NULL;
	}

	if (bp->b_flags & B_CLUSTER) {
		if (io_offset && ((bp->b_uploffset + io_offset) & PAGE_MASK)) {
			return NULL;
		}

		if (os_add_overflow(io_offset, io_size, &add1) || os_add_overflow(add1, bp->b_uploffset, &add2)) {
			return NULL;
		}
		if ((add2 & PAGE_MASK) && ((uint32_t)add1 < (uint32_t)bp->b_bcount)) {
			return NULL;
		}
	}
	io_bp = alloc_io_buf(bp->b_vp, 0);

	io_bp->b_flags = bp->b_flags & (B_COMMIT_UPL | B_META | B_PAGEIO | B_CLUSTER | B_PHYS | B_RAW | B_ASYNC | B_READ | B_FUA);

	if (iodone) {
		io_bp->b_transaction = arg;
		io_bp->b_iodone = iodone;
		io_bp->b_flags |= B_CALL;
	}
	if (bp->b_flags & B_CLUSTER) {
		io_bp->b_upl = bp->b_upl;
		io_bp->b_uploffset = bp->b_uploffset + io_offset;
	} else {
		io_bp->b_datap  = (uintptr_t)(((char *)bp->b_datap) + io_offset);
	}
	io_bp->b_bcount = io_size;

	return io_bp;
}


int
buf_shadow(buf_t bp)
{
	if (bp->b_lflags & BL_SHADOW) {
		return 1;
	}
	return 0;
}


buf_t
buf_create_shadow_priv(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg)
{
	return buf_create_shadow_internal(bp, force_copy, external_storage, iodone, arg, 1);
}

buf_t
buf_create_shadow(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg)
{
	return buf_create_shadow_internal(bp, force_copy, external_storage, iodone, arg, 0);
}


static buf_t
buf_create_shadow_internal(buf_t bp, boolean_t force_copy, uintptr_t external_storage, void (*iodone)(buf_t, void *), void *arg, int priv)
{
	buf_t   io_bp;

	KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_START, bp, 0, 0, 0, 0);

	if (!(bp->b_flags & B_META) || (bp->b_lflags & BL_IOBUF)) {
		KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_END, bp, 0, 0, 0, 0);
		return NULL;
	}
#ifdef BUF_MAKE_PRIVATE
	if (bp->b_shadow_ref && bp->b_data_ref == 0 && external_storage == 0) {
		panic("buf_create_shadow: %p is in the private state (%d, %d)", bp, bp->b_shadow_ref, bp->b_data_ref);
	}
#endif
	io_bp = alloc_io_buf(bp->b_vp, priv);

	io_bp->b_flags = bp->b_flags & (B_META | B_ZALLOC | B_ASYNC | B_READ | B_FUA);
	io_bp->b_blkno = bp->b_blkno;
	io_bp->b_lblkno = bp->b_lblkno;
	io_bp->b_lblksize = bp->b_lblksize;

	if (iodone) {
		io_bp->b_transaction = arg;
		io_bp->b_iodone = iodone;
		io_bp->b_flags |= B_CALL;
	}
	if (force_copy == FALSE) {
		io_bp->b_bcount = bp->b_bcount;
		io_bp->b_bufsize = bp->b_bufsize;

		if (external_storage) {
			io_bp->b_datap = external_storage;
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_data_store = NULL;
#endif
		} else {
			io_bp->b_datap = bp->b_datap;
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_data_store = bp;
#endif
		}
		*(buf_t *)(&io_bp->b_orig) = bp;

		lck_mtx_lock_spin(&buf_mtx);

		io_bp->b_lflags |= BL_SHADOW;
		io_bp->b_shadow = bp->b_shadow;
		bp->b_shadow = io_bp;
		bp->b_shadow_ref++;

#ifdef BUF_MAKE_PRIVATE
		if (external_storage) {
			io_bp->b_lflags |= BL_EXTERNAL;
		} else {
			bp->b_data_ref++;
		}
#endif
		lck_mtx_unlock(&buf_mtx);
	} else {
		if (external_storage) {
#ifdef BUF_MAKE_PRIVATE
			io_bp->b_lflags |= BL_EXTERNAL;
#endif
			io_bp->b_bcount = bp->b_bcount;
			io_bp->b_bufsize = bp->b_bufsize;
			io_bp->b_datap = external_storage;
		} else {
			allocbuf(io_bp, bp->b_bcount);

			io_bp->b_lflags |= BL_IOBUF_ALLOC;
		}
		bcopy((caddr_t)bp->b_datap, (caddr_t)io_bp->b_datap, bp->b_bcount);

#ifdef BUF_MAKE_PRIVATE
		io_bp->b_data_store = NULL;
#endif
	}
	KERNEL_DEBUG(0xbbbbc000 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, io_bp, 0);

	return io_bp;
}


#ifdef BUF_MAKE_PRIVATE
errno_t
buf_make_private(buf_t bp)
{
	buf_t   ds_bp;
	buf_t   t_bp;
	struct buf my_buf;

	KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_START, bp, bp->b_shadow_ref, 0, 0, 0);

	if (bp->b_shadow_ref == 0 || bp->b_data_ref == 0 || ISSET(bp->b_lflags, BL_SHADOW)) {
		KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, EINVAL, 0);
		return EINVAL;
	}
	my_buf.b_flags = B_META;
	my_buf.b_datap = (uintptr_t)NULL;
	allocbuf(&my_buf, bp->b_bcount);

	bcopy((caddr_t)bp->b_datap, (caddr_t)my_buf.b_datap, bp->b_bcount);

	lck_mtx_lock_spin(&buf_mtx);

	for (t_bp = bp->b_shadow; t_bp; t_bp = t_bp->b_shadow) {
		if (!ISSET(bp->b_lflags, BL_EXTERNAL)) {
			break;
		}
	}
	ds_bp = t_bp;

	if (ds_bp == NULL && bp->b_data_ref) {
		panic("buf_make_private: b_data_ref != 0 && ds_bp == NULL");
	}

	if (ds_bp && (bp->b_data_ref == 0 || bp->b_shadow_ref == 0)) {
		panic("buf_make_private: ref_count == 0 && ds_bp != NULL");
	}

	if (ds_bp == NULL) {
		lck_mtx_unlock(&buf_mtx);

		buf_free_meta_store(&my_buf);

		KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, EINVAL, 0);
		return EINVAL;
	}
	for (t_bp = bp->b_shadow; t_bp; t_bp = t_bp->b_shadow) {
		if (!ISSET(t_bp->b_lflags, BL_EXTERNAL)) {
			t_bp->b_data_store = ds_bp;
		}
	}
	ds_bp->b_data_ref = bp->b_data_ref;

	bp->b_data_ref = 0;
	bp->b_datap = my_buf.b_datap;

	lck_mtx_unlock(&buf_mtx);

	KERNEL_DEBUG(0xbbbbc004 | DBG_FUNC_END, bp, bp->b_shadow_ref, 0, 0, 0);
	return 0;
}
#endif


void
buf_setfilter(buf_t bp, void (*filter)(buf_t, void *), void *transaction,
    void(**old_iodone)(buf_t, void *), void **old_transaction)
{
	assert(ISSET(bp->b_lflags, BL_BUSY));

	if (old_iodone) {
		*old_iodone = bp->b_iodone;
	}
	if (old_transaction) {
		*old_transaction = bp->b_transaction;
	}

	bp->b_transaction = transaction;
	bp->b_iodone = filter;
	if (filter) {
		bp->b_flags |= B_FILTER;
	} else {
		bp->b_flags &= ~B_FILTER;
	}
}


daddr64_t
buf_blkno(buf_t bp)
{
	return bp->b_blkno;
}

daddr64_t
buf_lblkno(buf_t bp)
{
	return bp->b_lblkno;
}

uint32_t
buf_lblksize(buf_t bp)
{
	return bp->b_lblksize;
}

void
buf_setblkno(buf_t bp, daddr64_t blkno)
{
	bp->b_blkno = blkno;
}

void
buf_setlblkno(buf_t bp, daddr64_t lblkno)
{
	bp->b_lblkno = lblkno;
}

void
buf_setlblksize(buf_t bp, uint32_t lblksize)
{
	bp->b_lblksize = lblksize;
}

dev_t
buf_device(buf_t bp)
{
	return bp->b_dev;
}

errno_t
buf_setdevice(buf_t bp, vnode_t vp)
{
	if ((vp->v_type != VBLK) && (vp->v_type != VCHR)) {
		return EINVAL;
	}
	bp->b_dev = vp->v_rdev;

	return 0;
}


void *
buf_drvdata(buf_t bp)
{
	return bp->b_drvdata;
}

void
buf_setdrvdata(buf_t bp, void *drvdata)
{
	bp->b_drvdata = drvdata;
}

void *
buf_fsprivate(buf_t bp)
{
	return bp->b_fsprivate;
}

// if NULL callback is passed, it's ignored
void
buf_setfsprivate(buf_t bp, void *fsprivate, (*release_callback)(void *))
{
	bp->b_fsprivate = fsprivate;
	if (release_callback != NULL){
		bp->b_fsprivate_done = release_callback;
	}
}

kauth_cred_t
buf_rcred(buf_t bp)
{
	return bp->b_rcred;
}

kauth_cred_t
buf_wcred(buf_t bp)
{
	return bp->b_wcred;
}

void *
buf_upl(buf_t bp)
{
	return bp->b_upl;
}

uint32_t
buf_uploffset(buf_t bp)
{
	return (uint32_t)(bp->b_uploffset);
}

proc_t
buf_proc(buf_t bp)
{
	return bp->b_proc;
}


static errno_t
buf_map_range_internal(buf_t bp, caddr_t *io_addr, boolean_t legacymode)
{
	buf_t           real_bp;
	vm_offset_t     vaddr;
	kern_return_t   kret;

	if (!(bp->b_flags & B_CLUSTER)) {
		*io_addr = (caddr_t)bp->b_datap;
		return 0;
	}
	real_bp = (buf_t)(bp->b_real_bp);

	if (real_bp && real_bp->b_datap) {
		/*
		 * b_real_bp is only valid if B_CLUSTER is SET
		 * if it's non-zero, than someone did a cluster_bp call
		 * if the backing physical pages were already mapped
		 * in before the call to cluster_bp (non-zero b_datap),
		 * than we just use that mapping
		 */
		*io_addr = (caddr_t)real_bp->b_datap;
		return 0;
	}

	if (legacymode) {
		kret = ubc_upl_map(bp->b_upl, &vaddr);    /* Map it in */
		if (kret == KERN_SUCCESS) {
			vaddr += bp->b_uploffset;
		}
	} else {
		kret = ubc_upl_map_range(bp->b_upl, bp->b_uploffset, bp->b_bcount, VM_PROT_DEFAULT, &vaddr);    /* Map it in */
	}

	if (kret != KERN_SUCCESS) {
		*io_addr = NULL;

		return ENOMEM;
	}

	*io_addr = (caddr_t)vaddr;

	return 0;
}

errno_t
buf_map_range(buf_t bp, caddr_t *io_addr)
{
	return buf_map_range_internal(bp, io_addr, false);
}

errno_t
buf_map(buf_t bp, caddr_t *io_addr)
{
	return buf_map_range_internal(bp, io_addr, true);
}

static errno_t
buf_unmap_range_internal(buf_t bp, boolean_t legacymode)
{
	buf_t           real_bp;
	kern_return_t   kret;

	if (!(bp->b_flags & B_CLUSTER)) {
		return 0;
	}
	/*
	 * see buf_map for the explanation
	 */
	real_bp = (buf_t)(bp->b_real_bp);

	if (real_bp && real_bp->b_datap) {
		return 0;
	}

	if ((bp->b_lflags & BL_IOBUF) &&
	    ((bp->b_flags & (B_PAGEIO | B_READ)) != (B_PAGEIO | B_READ))) {
		/*
		 * ignore pageins... the 'right' thing will
		 * happen due to the way we handle speculative
		 * clusters...
		 *
		 * when we commit these pages, we'll hit
		 * it with UPL_COMMIT_INACTIVE which
		 * will clear the reference bit that got
		 * turned on when we touched the mapping
		 */
		bp->b_flags |= B_AGE;
	}

	if (legacymode) {
		kret = ubc_upl_unmap(bp->b_upl);
	} else {
		kret = ubc_upl_unmap_range(bp->b_upl, bp->b_uploffset, bp->b_bcount);
	}

	if (kret != KERN_SUCCESS) {
		return EINVAL;
	}
	return 0;
}

errno_t
buf_unmap_range(buf_t bp)
{
	return buf_unmap_range_internal(bp, false);
}

errno_t
buf_unmap(buf_t bp)
{
	return buf_unmap_range_internal(bp, true);
}


void
buf_clear(buf_t bp)
{
	caddr_t baddr;

	if (buf_map(bp, &baddr) == 0) {
		bzero(baddr, bp->b_bcount);
		buf_unmap(bp);
	}
	bp->b_resid = 0;
}

/*
 * Read or write a buffer that is not contiguous on disk.
 * buffer is marked done/error at the conclusion
 */
static int
buf_strategy_fragmented(vnode_t devvp, buf_t bp, off_t f_offset, size_t contig_bytes)
{
	vnode_t vp = buf_vnode(bp);
	buf_t   io_bp;                   /* For reading or writing a single block */
	int     io_direction;
	int     io_resid;
	size_t  io_contig_bytes;
	daddr64_t io_blkno;
	int     error = 0;
	int     bmap_flags;

	/*
	 * save our starting point... the bp was already mapped
	 * in buf_strategy before we got called
	 * no sense doing it again.
	 */
	io_blkno = bp->b_blkno;
	/*
	 * Make sure we redo this mapping for the next I/O
	 * i.e. this can never be a 'permanent' mapping
	 */
	bp->b_blkno = bp->b_lblkno;

	/*
	 * Get an io buffer to do the deblocking
	 */
	io_bp = alloc_io_buf(devvp, 0);

	io_bp->b_lblkno = bp->b_lblkno;
	io_bp->b_lblksize = bp->b_lblksize;
	io_bp->b_datap  = bp->b_datap;
	io_resid        = bp->b_bcount;
	io_direction    = bp->b_flags & B_READ;
	io_contig_bytes = contig_bytes;

	if (bp->b_flags & B_READ) {
		bmap_flags = VNODE_READ;
	} else {
		bmap_flags = VNODE_WRITE;
	}

	for (;;) {
		if (io_blkno == -1) {
			/*
			 * this is unexepected, but we'll allow for it
			 */
			bzero((caddr_t)io_bp->b_datap, (int)io_contig_bytes);
		} else {
			io_bp->b_bcount  = (uint32_t)io_contig_bytes;
			io_bp->b_bufsize = (uint32_t)io_contig_bytes;
			io_bp->b_resid   = (uint32_t)io_contig_bytes;
			io_bp->b_blkno   = io_blkno;

			buf_reset(io_bp, io_direction);

			/*
			 * Call the device to do the I/O and wait for it.  Make sure the appropriate party is charged for write
			 */

			if (!ISSET(bp->b_flags, B_READ)) {
				OSAddAtomic(1, &devvp->v_numoutput);
			}

			if ((error = VNOP_STRATEGY(io_bp))) {
				break;
			}
			if ((error = (int)buf_biowait(io_bp))) {
				break;
			}
			if (io_bp->b_resid) {
				io_resid -= (io_contig_bytes - io_bp->b_resid);
				break;
			}
		}
		if ((io_resid -= io_contig_bytes) == 0) {
			break;
		}
		f_offset       += io_contig_bytes;
		io_bp->b_datap += io_contig_bytes;

		/*
		 * Map the current position to a physical block number
		 */
		if ((error = VNOP_BLOCKMAP(vp, f_offset, io_resid, &io_blkno, &io_contig_bytes, NULL, bmap_flags, NULL))) {
			break;
		}
	}
	buf_free(io_bp);

	if (error) {
		buf_seterror(bp, error);
	}
	bp->b_resid = io_resid;
	/*
	 * This I/O is now complete
	 */
	buf_biodone(bp);

	return error;
}


/*
 * struct vnop_strategy_args {
 *      struct buf *a_bp;
 * } *ap;
 */
errno_t
buf_strategy(vnode_t devvp, void *ap)
{
	buf_t   bp = ((struct vnop_strategy_args *)ap)->a_bp;
	vnode_t vp = bp->b_vp;
	int     bmap_flags;
	errno_t error;
#if CONFIG_DTRACE
	int dtrace_io_start_flag = 0;    /* We only want to trip the io:::start
	                                  * probe once, with the true physical
	                                  * block in place (b_blkno)
	                                  */

#endif

	if (vp == NULL || vp->v_type == VCHR || vp->v_type == VBLK) {
		panic("buf_strategy: b_vp == NULL || vtype == VCHR | VBLK");
	}
	/*
	 * associate the physical device with
	 * with this buf_t even if we don't
	 * end up issuing the I/O...
	 */
	bp->b_dev = devvp->v_rdev;

	if (bp->b_flags & B_READ) {
		bmap_flags = VNODE_READ;
	} else {
		bmap_flags = VNODE_WRITE;
	}

	if (!(bp->b_flags & B_CLUSTER)) {
		if ((bp->b_upl)) {
			/*
			 * we have a UPL associated with this bp
			 * go through cluster_bp which knows how
			 * to deal with filesystem block sizes
			 * that aren't equal to the page size
			 */
			DTRACE_IO1(start, buf_t, bp);
			return cluster_bp(bp);
		}
		if (bp->b_blkno == bp->b_lblkno) {
			off_t       f_offset;
			size_t  contig_bytes;

			if (bp->b_lblksize && bp->b_lblkno >= 0) {
				f_offset = bp->b_lblkno * bp->b_lblksize;
			} else if ((error = VNOP_BLKTOOFF(vp, bp->b_lblkno, &f_offset))) {
				DTRACE_IO1(start, buf_t, bp);
				buf_seterror(bp, error);
				buf_biodone(bp);

				return error;
			}

			if ((error = VNOP_BLOCKMAP(vp, f_offset, bp->b_bcount, &bp->b_blkno, &contig_bytes, NULL, bmap_flags, NULL))) {
				DTRACE_IO1(start, buf_t, bp);
				buf_seterror(bp, error);
				buf_biodone(bp);

				return error;
			}

			DTRACE_IO1(start, buf_t, bp);
#if CONFIG_DTRACE
			dtrace_io_start_flag = 1;
#endif /* CONFIG_DTRACE */

			if ((bp->b_blkno == -1) || (contig_bytes == 0)) {
				/* Set block number to force biodone later */
				bp->b_blkno = -1;
				buf_clear(bp);
			} else if (contig_bytes < (size_t)bp->b_bcount) {
				return buf_strategy_fragmented(devvp, bp, f_offset, contig_bytes);
			}
		}

#if CONFIG_DTRACE
		if (dtrace_io_start_flag == 0) {
			DTRACE_IO1(start, buf_t, bp);
			dtrace_io_start_flag = 1;
		}
#endif /* CONFIG_DTRACE */

		if (bp->b_blkno == -1) {
			buf_biodone(bp);
			return 0;
		}
	}

#if CONFIG_DTRACE
	if (dtrace_io_start_flag == 0) {
		DTRACE_IO1(start, buf_t, bp);
	}
#endif /* CONFIG_DTRACE */

#if CONFIG_PROTECT
	/* Capture f_offset in the bufattr*/
	cpx_t cpx = bufattr_cpx(buf_attr(bp));
	if (cpx) {
		/* No need to go here for older EAs */
		if (cpx_use_offset_for_iv(cpx) && !cpx_synthetic_offset_for_iv(cpx)) {
			off_t f_offset;

			/*
			 * this assert should be changed if cluster_io  ever
			 * changes its logical block size.
			 */
			assert((bp->b_lblksize == CLUSTER_IO_BLOCK_SIZE) || !(bp->b_flags & B_CLUSTER));

			if (bp->b_lblksize && bp->b_lblkno >= 0) {
				f_offset = bp->b_lblkno * bp->b_lblksize;
			} else if ((error = VNOP_BLKTOOFF(bp->b_vp, bp->b_lblkno, &f_offset))) {
				return error;
			}

			/*
			 * Attach the file offset to this buffer.  The
			 * bufattr attributes will be passed down the stack
			 * until they reach the storage driver (whether
			 * IOFlashStorage, ASP, or IONVMe). The driver
			 * will retain the offset in a local variable when it
			 * issues its I/Os to the NAND controller.
			 *
			 * Note that LwVM may end up splitting this I/O
			 * into sub-I/Os if it crosses a chunk boundary.  In this
			 * case, LwVM will update this field when it dispatches
			 * each I/O to IOFlashStorage.  But from our perspective
			 * we have only issued a single I/O.
			 *
			 * In the case of APFS we do not bounce through another
			 * intermediate layer (such as CoreStorage). APFS will
			 * issue the I/Os directly to the block device / IOMedia
			 * via buf_strategy on the specfs node.
			 */
			buf_setcpoff(bp, f_offset);
			CP_DEBUG((CPDBG_OFFSET_IO | DBG_FUNC_NONE), (uint32_t) f_offset, (uint32_t) bp->b_lblkno, (uint32_t) bp->b_blkno, (uint32_t) bp->b_bcount, 0);
		}
	}
#endif

	/*
	 * we can issue the I/O because...
	 * either B_CLUSTER is set which
	 * means that the I/O is properly set
	 * up to be a multiple of the page size, or
	 * we were able to successfully set up the
	 * physical block mapping
	 */
	error = VOCALL(devvp->v_op, VOFFSET(vnop_strategy), ap);
	DTRACE_FSINFO(strategy, vnode_t, vp);
	return error;
}



buf_t
buf_alloc(vnode_t vp)
{
	return alloc_io_buf(vp, is_vm_privileged());
}

void
buf_free(buf_t bp)
{
	free_io_buf(bp);
}


/*
 * iterate buffers for the specified vp.
 *   if BUF_SCAN_DIRTY is set, do the dirty list
 *   if BUF_SCAN_CLEAN is set, do the clean list
 *   if neither flag is set, default to BUF_SCAN_DIRTY
 *   if BUF_NOTIFY_BUSY is set, call the callout function using a NULL bp for busy pages
 */

struct buf_iterate_info_t {
	int flag;
	struct buflists *listhead;
};

void
buf_iterate(vnode_t vp, int (*callout)(buf_t, void *), int flags, void *arg)
{
	buf_t   bp;
	int     retval;
	struct  buflists local_iterblkhd;
	int     lock_flags = BAC_NOWAIT | BAC_REMOVE;
	int     notify_busy = flags & BUF_NOTIFY_BUSY;
	struct buf_iterate_info_t list[2];
	int     num_lists, i;

	if (flags & BUF_SKIP_LOCKED) {
		lock_flags |= BAC_SKIP_LOCKED;
	}
	if (flags & BUF_SKIP_NONLOCKED) {
		lock_flags |= BAC_SKIP_NONLOCKED;
	}

	if (!(flags & (BUF_SCAN_DIRTY | BUF_SCAN_CLEAN))) {
		flags |= BUF_SCAN_DIRTY;
	}

	num_lists = 0;

	if (flags & BUF_SCAN_DIRTY) {
		list[num_lists].flag = VBI_DIRTY;
		list[num_lists].listhead = &vp->v_dirtyblkhd;
		num_lists++;
	}
	if (flags & BUF_SCAN_CLEAN) {
		list[num_lists].flag = VBI_CLEAN;
		list[num_lists].listhead = &vp->v_cleanblkhd;
		num_lists++;
	}

	for (i = 0; i < num_lists; i++) {
		lck_mtx_lock(&buf_mtx);

		if (buf_iterprepare(vp, &local_iterblkhd, list[i].flag)) {
			lck_mtx_unlock(&buf_mtx);
			continue;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);
			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(list[i].listhead, bp, b_vnbufs);

			if (buf_acquire_locked(bp, lock_flags, 0, 0)) {
				if (notify_busy) {
					bp = NULL;
				} else {
					continue;
				}
			}

			lck_mtx_unlock(&buf_mtx);

			retval = callout(bp, arg);

			switch (retval) {
			case BUF_RETURNED:
				if (bp) {
					buf_brelse(bp);
				}
				break;
			case BUF_CLAIMED:
				break;
			case BUF_RETURNED_DONE:
				if (bp) {
					buf_brelse(bp);
				}
				lck_mtx_lock(&buf_mtx);
				goto out;
			case BUF_CLAIMED_DONE:
				lck_mtx_lock(&buf_mtx);
				goto out;
			}
			lck_mtx_lock(&buf_mtx);
		} /* while list has more nodes */
out:
		buf_itercomplete(vp, &local_iterblkhd, list[i].flag);
		lck_mtx_unlock(&buf_mtx);
	} /* for each list */
} /* buf_iterate */


/*
 * Flush out and invalidate all buffers associated with a vnode.
 */
int
buf_invalidateblks(vnode_t vp, int flags, int slpflag, int slptimeo)
{
	buf_t   bp;
	int     aflags;
	int     error = 0;
	int     must_rescan = 1;
	struct  buflists local_iterblkhd;


	if (LIST_EMPTY(&vp->v_cleanblkhd) && LIST_EMPTY(&vp->v_dirtyblkhd)) {
		return 0;
	}

	lck_mtx_lock(&buf_mtx);

	for (;;) {
		if (must_rescan == 0) {
			/*
			 * the lists may not be empty, but all that's left at this
			 * point are metadata or B_LOCKED buffers which are being
			 * skipped... we know this because we made it through both
			 * the clean and dirty lists without dropping buf_mtx...
			 * each time we drop buf_mtx we bump "must_rescan"
			 */
			break;
		}
		if (LIST_EMPTY(&vp->v_cleanblkhd) && LIST_EMPTY(&vp->v_dirtyblkhd)) {
			break;
		}
		must_rescan = 0;
		/*
		 * iterate the clean list
		 */
		if (buf_iterprepare(vp, &local_iterblkhd, VBI_CLEAN)) {
			goto try_dirty_list;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);

			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_cleanblkhd, bp, b_vnbufs);

			/*
			 * some filesystems distinguish meta data blocks with a negative logical block #
			 */
			if ((flags & BUF_SKIP_META) && (bp->b_lblkno < 0 || ISSET(bp->b_flags, B_META))) {
				continue;
			}

			aflags = BAC_REMOVE;

			if (!(flags & BUF_INVALIDATE_LOCKED)) {
				aflags |= BAC_SKIP_LOCKED;
			}

			if ((error = (int)buf_acquire_locked(bp, aflags, slpflag, slptimeo))) {
				if (error == EDEADLK) {
					/*
					 * this buffer was marked B_LOCKED...
					 * we didn't drop buf_mtx, so we
					 * we don't need to rescan
					 */
					continue;
				}
				if (error == EAGAIN) {
					/*
					 * found a busy buffer... we blocked and
					 * dropped buf_mtx, so we're going to
					 * need to rescan after this pass is completed
					 */
					must_rescan++;
					continue;
				}
				/*
				 * got some kind of 'real' error out of the msleep
				 * in buf_acquire_locked, terminate the scan and return the error
				 */
				buf_itercomplete(vp, &local_iterblkhd, VBI_CLEAN);

				lck_mtx_unlock(&buf_mtx);
				return error;
			}
			lck_mtx_unlock(&buf_mtx);

			if (bp->b_flags & B_LOCKED) {
				KERNEL_DEBUG(0xbbbbc038, bp, 0, 0, 0, 0);
			}

			CLR(bp->b_flags, B_LOCKED);
			SET(bp->b_flags, B_INVAL);
			buf_brelse(bp);

			lck_mtx_lock(&buf_mtx);

			/*
			 * by dropping buf_mtx, we allow new
			 * buffers to be added to the vnode list(s)
			 * we'll have to rescan at least once more
			 * if the queues aren't empty
			 */
			must_rescan++;
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_CLEAN);

try_dirty_list:
		/*
		 * Now iterate on dirty blks
		 */
		if (buf_iterprepare(vp, &local_iterblkhd, VBI_DIRTY)) {
			continue;
		}
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);

			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_dirtyblkhd, bp, b_vnbufs);

			/*
			 * some filesystems distinguish meta data blocks with a negative logical block #
			 */
			if ((flags & BUF_SKIP_META) && (bp->b_lblkno < 0 || ISSET(bp->b_flags, B_META))) {
				continue;
			}

			aflags = BAC_REMOVE;

			if (!(flags & BUF_INVALIDATE_LOCKED)) {
				aflags |= BAC_SKIP_LOCKED;
			}

			if ((error = (int)buf_acquire_locked(bp, aflags, slpflag, slptimeo))) {
				if (error == EDEADLK) {
					/*
					 * this buffer was marked B_LOCKED...
					 * we didn't drop buf_mtx, so we
					 * we don't need to rescan
					 */
					continue;
				}
				if (error == EAGAIN) {
					/*
					 * found a busy buffer... we blocked and
					 * dropped buf_mtx, so we're going to
					 * need to rescan after this pass is completed
					 */
					must_rescan++;
					continue;
				}
				/*
				 * got some kind of 'real' error out of the msleep
				 * in buf_acquire_locked, terminate the scan and return the error
				 */
				buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);

				lck_mtx_unlock(&buf_mtx);
				return error;
			}
			lck_mtx_unlock(&buf_mtx);

			if (bp->b_flags & B_LOCKED) {
				KERNEL_DEBUG(0xbbbbc038, bp, 0, 0, 1, 0);
			}

			CLR(bp->b_flags, B_LOCKED);
			SET(bp->b_flags, B_INVAL);

			if (ISSET(bp->b_flags, B_DELWRI) && (flags & BUF_WRITE_DATA)) {
				(void) VNOP_BWRITE(bp);
			} else {
				buf_brelse(bp);
			}

			lck_mtx_lock(&buf_mtx);
			/*
			 * by dropping buf_mtx, we allow new
			 * buffers to be added to the vnode list(s)
			 * we'll have to rescan at least once more
			 * if the queues aren't empty
			 */
			must_rescan++;
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);
	}
	lck_mtx_unlock(&buf_mtx);

	return 0;
}

void
buf_flushdirtyblks(vnode_t vp, int wait, int flags, const char *msg)
{
	(void) buf_flushdirtyblks_skipinfo(vp, wait, flags, msg);
	return;
}

int
buf_flushdirtyblks_skipinfo(vnode_t vp, int wait, int flags, const char *msg)
{
	buf_t   bp;
	int     writes_issued = 0;
	errno_t error;
	int     busy = 0;
	struct  buflists local_iterblkhd;
	int     lock_flags = BAC_NOWAIT | BAC_REMOVE;
	int any_locked = 0;

	if (flags & BUF_SKIP_LOCKED) {
		lock_flags |= BAC_SKIP_LOCKED;
	}
	if (flags & BUF_SKIP_NONLOCKED) {
		lock_flags |= BAC_SKIP_NONLOCKED;
	}
loop:
	lck_mtx_lock(&buf_mtx);

	if (buf_iterprepare(vp, &local_iterblkhd, VBI_DIRTY) == 0) {
		while (!LIST_EMPTY(&local_iterblkhd)) {
			bp = LIST_FIRST(&local_iterblkhd);
			LIST_REMOVE(bp, b_vnbufs);
			LIST_INSERT_HEAD(&vp->v_dirtyblkhd, bp, b_vnbufs);

			if ((error = buf_acquire_locked(bp, lock_flags, 0, 0)) == EBUSY) {
				busy++;
			}
			if (error) {
				/*
				 * If we passed in BUF_SKIP_LOCKED or BUF_SKIP_NONLOCKED,
				 * we may want to do somethign differently if a locked or unlocked
				 * buffer was encountered (depending on the arg specified).
				 * In this case, we know that one of those two was set, and the
				 * buf acquisition failed above.
				 *
				 * If it failed with EDEADLK, then save state which can be emitted
				 * later on to the caller.  Most callers should not care.
				 */
				if (error == EDEADLK) {
					any_locked++;
				}
				continue;
			}
			lck_mtx_unlock(&buf_mtx);

			bp->b_flags &= ~B_LOCKED;

			/*
			 * Wait for I/O associated with indirect blocks to complete,
			 * since there is no way to quickly wait for them below.
			 */
			if ((bp->b_vp == vp) || (wait == 0)) {
				(void) buf_bawrite(bp);
			} else {
				(void) VNOP_BWRITE(bp);
			}
			writes_issued++;

			lck_mtx_lock(&buf_mtx);
		}
		buf_itercomplete(vp, &local_iterblkhd, VBI_DIRTY);
	}
	lck_mtx_unlock(&buf_mtx);

	if (wait) {
		(void)vnode_waitforwrites(vp, 0, 0, 0, msg);

		if (vp->v_dirtyblkhd.lh_first && busy) {
			/*
			 * we had one or more BUSY buffers on
			 * the dirtyblock list... most likely
			 * these are due to delayed writes that
			 * were moved to the bclean queue but
			 * have not yet been 'written'.
			 * if we issued some writes on the
			 * previous pass, we try again immediately
			 * if we didn't, we'll sleep for some time
			 * to allow the state to change...
			 */
			if (writes_issued == 0) {
				(void)tsleep((caddr_t)&vp->v_numoutput,
				    PRIBIO + 1, "vnode_flushdirtyblks", hz / 20);
			}
			writes_issued = 0;
			busy = 0;

			goto loop;
		}
	}

	return any_locked;
}


/*
 * called with buf_mtx held...
 * this lock protects the queue manipulation
 */
static int
buf_iterprepare(vnode_t vp, struct buflists *iterheadp, int flags)
{
	struct buflists * listheadp;

	if (flags & VBI_DIRTY) {
		listheadp = &vp->v_dirtyblkhd;
	} else {
		listheadp = &vp->v_cleanblkhd;
	}

	while (vp->v_iterblkflags & VBI_ITER) {
		vp->v_iterblkflags |= VBI_ITERWANT;
		msleep(&vp->v_iterblkflags, &buf_mtx, 0, "buf_iterprepare", NULL);
	}
	if (LIST_EMPTY(listheadp)) {
		LIST_INIT(iterheadp);
		return EINVAL;
	}
	vp->v_iterblkflags |= VBI_ITER;

	iterheadp->lh_first = listheadp->lh_first;
	listheadp->lh_first->b_vnbufs.le_prev = &iterheadp->lh_first;
	LIST_INIT(listheadp);

	return 0;
}

/*
 * called with buf_mtx held...
 * this lock protects the queue manipulation
 */
static void
buf_itercomplete(vnode_t vp, struct buflists *iterheadp, int flags)
{
	struct buflists * listheadp;
	buf_t bp;

	if (flags & VBI_DIRTY) {
		listheadp = &vp->v_dirtyblkhd;
	} else {
		listheadp = &vp->v_cleanblkhd;
	}

	while (!LIST_EMPTY(iterheadp)) {
		bp = LIST_FIRST(iterheadp);
		LIST_REMOVE(bp, b_vnbufs);
		LIST_INSERT_HEAD(listheadp, bp, b_vnbufs);
	}
	vp->v_iterblkflags &= ~VBI_ITER;

	if (vp->v_iterblkflags & VBI_ITERWANT) {
		vp->v_iterblkflags &= ~VBI_ITERWANT;
		wakeup(&vp->v_iterblkflags);
	}
}


static void
bremfree_locked(buf_t bp)
{
	struct bqueues *dp = NULL;
	int whichq;

	whichq = bp->b_whichq;

	if (whichq == -1) {
		if (bp->b_shadow_ref == 0) {
			panic("bremfree_locked: %p not on freelist", bp);
		}
		/*
		 * there are clones pointing to 'bp'...
		 * therefore, it was not put on a freelist
		 * when buf_brelse was last called on 'bp'
		 */
		return;
	}
	/*
	 * We only calculate the head of the freelist when removing
	 * the last element of the list as that is the only time that
	 * it is needed (e.g. to reset the tail pointer).
	 *
	 * NB: This makes an assumption about how tailq's are implemented.
	 */
	if (bp->b_freelist.tqe_next == NULL) {
		dp = &bufqueues[whichq];

		if (dp->tqh_last != &bp->b_freelist.tqe_next) {
			panic("bremfree: lost tail");
		}
	}
	TAILQ_REMOVE(dp, bp, b_freelist);

	if (whichq == BQ_LAUNDRY) {
		blaundrycnt--;
	}

	bp->b_whichq = -1;
	bp->b_timestamp = 0;
	bp->b_shadow = 0;
}

/*
 * Associate a buffer with a vnode.
 * buf_mtx must be locked on entry
 */
static void
bgetvp_locked(vnode_t vp, buf_t bp)
{
	if (bp->b_vp != vp) {
		panic("bgetvp_locked: not free");
	}

	if (vp->v_type == VBLK || vp->v_type == VCHR) {
		bp->b_dev = vp->v_rdev;
	} else {
		bp->b_dev = NODEV;
	}
	/*
	 * Insert onto list for new vnode.
	 */
	bufinsvn(bp, &vp->v_cleanblkhd);
}

/*
 * Disassociate a buffer from a vnode.
 * buf_mtx must be locked on entry
 */
static void
brelvp_locked(buf_t bp)
{
	/*
	 * Delete from old vnode list, if on one.
	 */
	if (bp->b_vnbufs.le_next != NOLIST) {
		bufremvn(bp);
	}

	bp->b_vp = (vnode_t)NULL;
}

/*
 * Reassign a buffer from one vnode to another.
 * Used to assign file specific control information
 * (indirect blocks) to the vnode to which they belong.
 */
static void
buf_reassign(buf_t bp, vnode_t newvp)
{
	struct buflists *listheadp;

	if (newvp == NULL) {
		printf("buf_reassign: NULL");
		return;
	}
	lck_mtx_lock_spin(&buf_mtx);

	/*
	 * Delete from old vnode list, if on one.
	 */
	if (bp->b_vnbufs.le_next != NOLIST) {
		bufremvn(bp);
	}
	/*
	 * If dirty, put on list of dirty buffers;
	 * otherwise insert onto list of clean buffers.
	 */
	if (ISSET(bp->b_flags, B_DELWRI)) {
		listheadp = &newvp->v_dirtyblkhd;
	} else {
		listheadp = &newvp->v_cleanblkhd;
	}
	bufinsvn(bp, listheadp);

	lck_mtx_unlock(&buf_mtx);
}

static __inline__ void
bufhdrinit(buf_t bp)
{
	bzero((char *)bp, sizeof *bp);
	bp->b_dev = NODEV;
	bp->b_rcred = NOCRED;
	bp->b_wcred = NOCRED;
	bp->b_vnbufs.le_next = NOLIST;
	bp->b_flags = B_INVAL;

	return;
}

/*
 * Initialize buffers and hash links for buffers.
 */
__private_extern__ void
bufinit(void)
{
	buf_t   bp;
	struct bqueues *dp;
	int     i;

	nbuf_headers = 0;
	/* Initialize the buffer queues ('freelists') and the hash table */
	for (dp = bufqueues; dp < &bufqueues[BQUEUES]; dp++) {
		TAILQ_INIT(dp);
	}
	bufhashtbl = hashinit(nbuf_hashelements, M_CACHE, &bufhash);

	buf_busycount = 0;

	/* Initialize the buffer headers */
	for (i = 0; i < max_nbuf_headers; i++) {
		nbuf_headers++;
		bp = &buf_headers[i];
		bufhdrinit(bp);

		BLISTNONE(bp);
		dp = &bufqueues[BQ_EMPTY];
		bp->b_whichq = BQ_EMPTY;
		bp->b_timestamp = buf_timestamp();
		binsheadfree(bp, dp, BQ_EMPTY);
		binshash(bp, &invalhash);
	}
	boot_nbuf_headers = nbuf_headers;

	TAILQ_INIT(&iobufqueue);
	TAILQ_INIT(&delaybufqueue);

	for (; i < nbuf_headers + niobuf_headers; i++) {
		bp = &buf_headers[i];
		bufhdrinit(bp);
		bp->b_whichq = -1;
		binsheadfree(bp, &iobufqueue, -1);
	}

	/*
	 * allocate and initialize cluster specific global locks...
	 */
	cluster_init();

	printf("using %d buffer headers and %d cluster IO buffer headers\n",
	    nbuf_headers, niobuf_headers);

	/* start the bcleanbuf() thread */
	bcleanbuf_thread_init();

	/* Register a callout for relieving vm pressure */
	if (vm_set_buffer_cleanup_callout(buffer_cache_gc) != KERN_SUCCESS) {
		panic("Couldn't register buffer cache callout for vm pressure!");
	}
}

/*
 * Zones for the meta data buffers
 */

#define MINMETA 512
#define MAXMETA 16384

KALLOC_HEAP_DEFINE(KHEAP_VFS_BIO, "vfs_bio", KHEAP_ID_DATA_BUFFERS);

static struct buf *
bio_doread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, int async, int queuetype)
{
	buf_t   bp;

	bp = buf_getblk(vp, blkno, size, 0, 0, queuetype);

	/*
	 * If buffer does not have data valid, start a read.
	 * Note that if buffer is B_INVAL, buf_getblk() won't return it.
	 * Therefore, it's valid if it's I/O has completed or been delayed.
	 */
	if (!ISSET(bp->b_flags, (B_DONE | B_DELWRI))) {
		struct proc *p;

		p = current_proc();

		/* Start I/O for the buffer (keeping credentials). */
		SET(bp->b_flags, B_READ | async);
		if (IS_VALID_CRED(cred) && !IS_VALID_CRED(bp->b_rcred)) {
			kauth_cred_ref(cred);
			bp->b_rcred = cred;
		}

		VNOP_STRATEGY(bp);

		trace(TR_BREADMISS, pack(vp, size), blkno);

		/* Pay for the read. */
		if (p && p->p_stats) {
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_inblock);            /* XXX */
		}

		if (async) {
			/*
			 * since we asked for an ASYNC I/O
			 * the biodone will do the brelse
			 * we don't want to pass back a bp
			 * that we don't 'own'
			 */
			bp = NULL;
		}
	} else if (async) {
		buf_brelse(bp);
		bp = NULL;
	}

	trace(TR_BREADHIT, pack(vp, size), blkno);

	return bp;
}

/*
 * Perform the reads for buf_breadn() and buf_meta_breadn().
 * Trivial modification to the breada algorithm presented in Bach (p.55).
 */
static errno_t
do_breadn_for_type(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes,
    int nrablks, kauth_cred_t cred, buf_t *bpp, int queuetype)
{
	buf_t   bp;
	int     i;

	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, queuetype);

	/*
	 * For each of the read-ahead blocks, start a read, if necessary.
	 */
	for (i = 0; i < nrablks; i++) {
		/* If it's in the cache, just go on to next one. */
		if (incore(vp, rablks[i])) {
			continue;
		}

		/* Get a buffer for the read-ahead block */
		(void) bio_doread(vp, rablks[i], rasizes[i], cred, B_ASYNC, queuetype);
	}

	/* Otherwise, we had to start a read for it; wait until it's valid. */
	return buf_biowait(bp);
}


/*
 * Read a disk block.
 * This algorithm described in Bach (p.54).
 */
errno_t
buf_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp)
{
	buf_t   bp;

	/* Get buffer for block. */
	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, BLK_READ);

	/* Wait for the read to complete, and return result. */
	return buf_biowait(bp);
}

/*
 * Read a disk block. [bread() for meta-data]
 * This algorithm described in Bach (p.54).
 */
errno_t
buf_meta_bread(vnode_t vp, daddr64_t blkno, int size, kauth_cred_t cred, buf_t *bpp)
{
	buf_t   bp;

	/* Get buffer for block. */
	bp = *bpp = bio_doread(vp, blkno, size, cred, 0, BLK_META);

	/* Wait for the read to complete, and return result. */
	return buf_biowait(bp);
}

/*
 * Read-ahead multiple disk blocks. The first is sync, the rest async.
 */
errno_t
buf_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp)
{
	return do_breadn_for_type(vp, blkno, size, rablks, rasizes, nrablks, cred, bpp, BLK_READ);
}

/*
 * Read-ahead multiple disk blocks. The first is sync, the rest async.
 * [buf_breadn() for meta-data]
 */
errno_t
buf_meta_breadn(vnode_t vp, daddr64_t blkno, int size, daddr64_t *rablks, int *rasizes, int nrablks, kauth_cred_t cred, buf_t *bpp)
{
	return do_breadn_for_type(vp, blkno, size, rablks, rasizes, nrablks, cred, bpp, BLK_META);
}

/*
 * Block write.  Described in Bach (p.56)
 */
errno_t
buf_bwrite(buf_t bp)
{
	int     sync, wasdelayed;
	errno_t rv;
	proc_t  p = current_proc();
	vnode_t vp = bp->b_vp;

	if (bp->b_datap == 0) {
		if (brecover_data(bp) == 0) {
			return 0;
		}
	}
	/* Remember buffer type, to switch on it later. */
	sync = !ISSET(bp->b_flags, B_ASYNC);
	wasdelayed = ISSET(bp->b_flags, B_DELWRI);
	CLR(bp->b_flags, (B_READ | B_DONE | B_ERROR | B_DELWRI));

	if (wasdelayed) {
		OSAddAtomicLong(-1, &nbdwrite);
	}

	if (!sync) {
		/*
		 * If not synchronous, pay for the I/O operation and make
		 * sure the buf is on the correct vnode queue.  We have
		 * to do this now, because if we don't, the vnode may not
		 * be properly notified that its I/O has completed.
		 */
		if (wasdelayed) {
			buf_reassign(bp, vp);
		} else if (p && p->p_stats) {
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);            /* XXX */
		}
	}
	trace(TR_BUFWRITE, pack(vp, bp->b_bcount), bp->b_lblkno);

	/* Initiate disk write.  Make sure the appropriate party is charged. */

	OSAddAtomic(1, &vp->v_numoutput);

	VNOP_STRATEGY(bp);

	if (sync) {
		/*
		 * If I/O was synchronous, wait for it to complete.
		 */
		rv = buf_biowait(bp);

		/*
		 * Pay for the I/O operation, if it's not been paid for, and
		 * make sure it's on the correct vnode queue. (async operatings
		 * were payed for above.)
		 */
		if (wasdelayed) {
			buf_reassign(bp, vp);
		} else if (p && p->p_stats) {
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);            /* XXX */
		}

		/* Release the buffer. */
		buf_brelse(bp);

		return rv;
	} else {
		return 0;
	}
}

int
vn_bwrite(struct vnop_bwrite_args *ap)
{
	return buf_bwrite(ap->a_bp);
}

/*
 * Delayed write.
 *
 * The buffer is marked dirty, but is not queued for I/O.
 * This routine should be used when the buffer is expected
 * to be modified again soon, typically a small write that
 * partially fills a buffer.
 *
 * NB: magnetic tapes cannot be delayed; they must be
 * written in the order that the writes are requested.
 *
 * Described in Leffler, et al. (pp. 208-213).
 *
 * Note: With the ability to allocate additional buffer
 * headers, we can get in to the situation where "too" many
 * buf_bdwrite()s can create situation where the kernel can create
 * buffers faster than the disks can service. Doing a buf_bawrite() in
 * cases where we have "too many" outstanding buf_bdwrite()s avoids that.
 */
int
bdwrite_internal(buf_t bp, int return_error)
{
	proc_t  p  = current_proc();
	vnode_t vp = bp->b_vp;

	/*
	 * If the block hasn't been seen before:
	 *	(1) Mark it as having been seen,
	 *	(2) Charge for the write.
	 *	(3) Make sure it's on its vnode's correct block list,
	 */
	if (!ISSET(bp->b_flags, B_DELWRI)) {
		SET(bp->b_flags, B_DELWRI);
		if (p && p->p_stats) {
			OSIncrementAtomicLong(&p->p_stats->p_ru.ru_oublock);    /* XXX */
		}
		OSAddAtomicLong(1, &nbdwrite);
		buf_reassign(bp, vp);
	}

	/*
	 * if we're not LOCKED, but the total number of delayed writes
	 * has climbed above 75% of the total buffers in the system
	 * return an error if the caller has indicated that it can
	 * handle one in this case, otherwise schedule the I/O now
	 * this is done to prevent us from allocating tons of extra
	 * buffers when dealing with virtual disks (i.e. DiskImages),
	 * because additional buffers are dynamically allocated to prevent
	 * deadlocks from occurring
	 *
	 * however, can't do a buf_bawrite() if the LOCKED bit is set because the
	 * buffer is part of a transaction and can't go to disk until
	 * the LOCKED bit is cleared.
	 */
	if (!ISSET(bp->b_flags, B_LOCKED) && nbdwrite > ((nbuf_headers / 4) * 3)) {
		if (return_error) {
			return EAGAIN;
		}
		/*
		 * If the vnode has "too many" write operations in progress
		 * wait for them to finish the IO
		 */
		(void)vnode_waitforwrites(vp, VNODE_ASYNC_THROTTLE, 0, 0, "buf_bdwrite");

		return buf_bawrite(bp);
	}

	/* Otherwise, the "write" is done, so mark and release the buffer. */
	SET(bp->b_flags, B_DONE);
	buf_brelse(bp);
	return 0;
}

errno_t
buf_bdwrite(buf_t bp)
{
	return bdwrite_internal(bp, 0);
}


/*
 * Asynchronous block write; just an asynchronous buf_bwrite().
 *
 * Note: With the abilitty to allocate additional buffer
 * headers, we can get in to the situation where "too" many
 * buf_bawrite()s can create situation where the kernel can create
 * buffers faster than the disks can service.
 * We limit the number of "in flight" writes a vnode can have to
 * avoid this.
 */
static int
bawrite_internal(buf_t bp, int throttle)
{
	vnode_t vp = bp->b_vp;

	if (vp) {
		if (throttle) {
			/*
			 * If the vnode has "too many" write operations in progress
			 * wait for them to finish the IO
			 */
			(void)vnode_waitforwrites(vp, VNODE_ASYNC_THROTTLE, 0, 0, (const char *)"buf_bawrite");
		} else if (vp->v_numoutput >= VNODE_ASYNC_THROTTLE) {
			/*
			 * return to the caller and
			 * let him decide what to do
			 */
			return EWOULDBLOCK;
		}
	}
	SET(bp->b_flags, B_ASYNC);

	return VNOP_BWRITE(bp);
}

errno_t
buf_bawrite(buf_t bp)
{
	return bawrite_internal(bp, 1);
}



static void
buf_free_meta_store(buf_t bp)
{
	if (bp->b_bufsize) {
		uintptr_t datap = bp->b_datap;
		int bufsize = bp->b_bufsize;

		bp->b_datap = (uintptr_t)NULL;
		bp->b_bufsize = 0;

		/*
		 * Ensure the assignment of b_datap has global visibility
		 * before we free the region.
		 */
		OSMemoryBarrier();

		if (ISSET(bp->b_flags, B_ZALLOC)) {
			kheap_free(KHEAP_VFS_BIO, datap, bufsize);
		} else {
			kmem_free(kernel_map, datap, bufsize);
		}
	}
}


static buf_t
buf_brelse_shadow(buf_t bp)
{
	buf_t   bp_head;
	buf_t   bp_temp;
	buf_t   bp_return = NULL;
#ifdef BUF_MAKE_PRIVATE
	buf_t   bp_data;
	int     data_ref = 0;
#endif
	int need_wakeup = 0;

	lck_mtx_lock_spin(&buf_mtx);

	__IGNORE_WCASTALIGN(bp_head = (buf_t)bp->b_orig);

	if (bp_head->b_whichq != -1) {
		panic("buf_brelse_shadow: bp_head on freelist %d", bp_head->b_whichq);
	}

#ifdef BUF_MAKE_PRIVATE
	if (bp_data = bp->b_data_store) {
		bp_data->b_data_ref--;
		/*
		 * snapshot the ref count so that we can check it
		 * outside of the lock... we only want the guy going
		 * from 1 -> 0 to try and release the storage
		 */
		data_ref = bp_data->b_data_ref;
	}
#endif
	KERNEL_DEBUG(0xbbbbc008 | DBG_FUNC_START, bp, bp_head, bp_head->b_shadow_ref, 0, 0);

	bp_head->b_shadow_ref--;

	for (bp_temp = bp_head; bp_temp && bp != bp_temp->b_shadow; bp_temp = bp_temp->b_shadow) {
		;
	}

	if (bp_temp == NULL) {
		panic("buf_brelse_shadow: bp not on list %p", bp_head);
	}

	bp_temp->b_shadow = bp_temp->b_shadow->b_shadow;

#ifdef BUF_MAKE_PRIVATE
	/*
	 * we're about to free the current 'owner' of the data buffer and
	 * there is at least one other shadow buf_t still pointing at it
	 * so transfer it to the first shadow buf left in the chain
	 */
	if (bp == bp_data && data_ref) {
		if ((bp_data = bp_head->b_shadow) == NULL) {
			panic("buf_brelse_shadow: data_ref mismatch bp(%p)", bp);
		}

		for (bp_temp = bp_data; bp_temp; bp_temp = bp_temp->b_shadow) {
			bp_temp->b_data_store = bp_data;
		}
		bp_data->b_data_ref = data_ref;
	}
#endif
	if (bp_head->b_shadow_ref == 0 && bp_head->b_shadow) {
		panic("buf_relse_shadow: b_shadow != NULL && b_shadow_ref == 0  bp(%p)", bp);
	}
	if (bp_head->b_shadow_ref && bp_head->b_shadow == 0) {
		panic("buf_relse_shadow: b_shadow == NULL && b_shadow_ref != 0  bp(%p)", bp);
	}

	if (bp_head->b_shadow_ref == 0) {
		if (!ISSET(bp_head->b_lflags, BL_BUSY)) {
			CLR(bp_head->b_flags, B_AGE);
			bp_head->b_timestamp = buf_timestamp();

			if (ISSET(bp_head->b_flags, B_LOCKED)) {
				bp_head->b_whichq = BQ_LOCKED;
				binstailfree(bp_head, &bufqueues[BQ_LOCKED], BQ_LOCKED);
			} else {
				bp_head->b_whichq = BQ_META;
				binstailfree(bp_head, &bufqueues[BQ_META], BQ_META);
			}
		} else if (ISSET(bp_head->b_lflags, BL_WAITSHADOW)) {
			CLR(bp_head->b_lflags, BL_WAITSHADOW);

			bp_return = bp_head;
		}
		if (ISSET(bp_head->b_lflags, BL_WANTED_REF)) {
			CLR(bp_head->b_lflags, BL_WANTED_REF);
			need_wakeup = 1;
		}
	}
	lck_mtx_unlock(&buf_mtx);

	if (need_wakeup) {
		wakeup(bp_head);
	}

#ifdef BUF_MAKE_PRIVATE
	if (bp == bp_data && data_ref == 0) {
		buf_free_meta_store(bp);
	}

	bp->b_data_store = NULL;
#endif
	KERNEL_DEBUG(0xbbbbc008 | DBG_FUNC_END, bp, 0, 0, 0, 0);

	return bp_return;
}


/*
 * Release a buffer on to the free lists.
 * Described in Bach (p. 46).
 */
void
buf_brelse(buf_t bp)
{
	struct bqueues *bufq;
	int    whichq;
	upl_t   upl;
	int need_wakeup = 0;
	int need_bp_wakeup = 0;


	if (bp->b_whichq != -1 || !(bp->b_lflags & BL_BUSY)) {
		panic("buf_brelse: bad buffer = %p", bp);
	}

#ifdef JOE_DEBUG
	(void) OSBacktrace(&bp->b_stackbrelse[0], 6);

	bp->b_lastbrelse = current_thread();
	bp->b_tag = 0;
#endif
	if (bp->b_lflags & BL_IOBUF) {
		buf_t   shadow_master_bp = NULL;

		if (ISSET(bp->b_lflags, BL_SHADOW)) {
			shadow_master_bp = buf_brelse_shadow(bp);
		} else if (ISSET(bp->b_lflags, BL_IOBUF_ALLOC)) {
			buf_free_meta_store(bp);
		}
		free_io_buf(bp);

		if (shadow_master_bp) {
			bp = shadow_master_bp;
			goto finish_shadow_master;
		}
		return;
	}

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 388)) | DBG_FUNC_START,
	    bp->b_lblkno * PAGE_SIZE, bp, bp->b_datap,
	    bp->b_flags, 0);

	trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

	/*
	 * if we're invalidating a buffer that has the B_FILTER bit
	 * set then call the b_iodone function so it gets cleaned
	 * up properly.
	 *
	 * the HFS journal code depends on this
	 */
	if (ISSET(bp->b_flags, B_META) && ISSET(bp->b_flags, B_INVAL)) {
		if (ISSET(bp->b_flags, B_FILTER)) {     /* if necessary, call out */
			void    (*iodone_func)(struct buf *, void *) = bp->b_iodone;
			void    *arg = bp->b_transaction;

			CLR(bp->b_flags, B_FILTER);     /* but note callout done */
			bp->b_iodone = NULL;
			bp->b_transaction = NULL;

			if (iodone_func == NULL) {
				panic("brelse: bp @ %p has NULL b_iodone!", bp);
			}
			(*iodone_func)(bp, arg);
		}
	}
	/*
	 * I/O is done. Cleanup the UPL state
	 */
	upl = bp->b_upl;

	if (!ISSET(bp->b_flags, B_META) && UBCINFOEXISTS(bp->b_vp) && bp->b_bufsize) {
		kern_return_t kret;
		int           upl_flags;

		if (upl == NULL) {
			if (!ISSET(bp->b_flags, B_INVAL)) {
				kret = ubc_create_upl_kernel(bp->b_vp,
				    ubc_blktooff(bp->b_vp, bp->b_lblkno),
				    bp->b_bufsize,
				    &upl,
				    NULL,
				    UPL_PRECIOUS,
				    VM_KERN_MEMORY_FILE);

				if (kret != KERN_SUCCESS) {
					panic("brelse: Failed to create UPL");
				}
#if  UPL_DEBUG
				upl_ubc_alias_set(upl, (uintptr_t) bp, (uintptr_t) 5);
#endif /* UPL_DEBUG */
			}
		} else {
			if (bp->b_datap) {
				kret = ubc_upl_unmap(upl);

				if (kret != KERN_SUCCESS) {
					panic("ubc_upl_unmap failed");
				}
				bp->b_datap = (uintptr_t)NULL;
			}
		}
		if (upl) {
			if (bp->b_flags & (B_ERROR | B_INVAL)) {
				if (bp->b_flags & (B_READ | B_INVAL)) {
					upl_flags = UPL_ABORT_DUMP_PAGES;
				} else {
					upl_flags = 0;
				}

				ubc_upl_abort(upl, upl_flags);
			} else {
				if (ISSET(bp->b_flags, B_DELWRI | B_WASDIRTY)) {
					upl_flags = UPL_COMMIT_SET_DIRTY;
				} else {
					upl_flags = UPL_COMMIT_CLEAR_DIRTY;
				}

				ubc_upl_commit_range(upl, 0, bp->b_bufsize, upl_flags |
				    UPL_COMMIT_INACTIVATE | UPL_COMMIT_FREE_ON_EMPTY);
			}
			bp->b_upl = NULL;
		}
	} else {
		if ((upl)) {
			panic("brelse: UPL set for non VREG; vp=%p", bp->b_vp);
		}
	}

	/*
	 * If it's locked, don't report an error; try again later.
	 */
	if (ISSET(bp->b_flags, (B_LOCKED | B_ERROR)) == (B_LOCKED | B_ERROR)) {
		CLR(bp->b_flags, B_ERROR);
	}
	/*
	 * If it's not cacheable, or an error, mark it invalid.
	 */
	if (ISSET(bp->b_flags, (B_NOCACHE | B_ERROR))) {
		SET(bp->b_flags, B_INVAL);
	}

	if ((bp->b_bufsize <= 0) ||
	    ISSET(bp->b_flags, B_INVAL) ||
	    (ISSET(bp->b_lflags, BL_WANTDEALLOC) && !ISSET(bp->b_flags, B_DELWRI))) {
		boolean_t       delayed_buf_free_meta_store = FALSE;

		/*
		 * If it's invalid or empty, dissociate it from its vnode,
		 * release its storage if B_META, and
		 * clean it up a bit and put it on the EMPTY queue
		 */
		if (ISSET(bp->b_flags, B_DELWRI)) {
			OSAddAtomicLong(-1, &nbdwrite);
		}

		if (ISSET(bp->b_flags, B_META)) {
			if (bp->b_shadow_ref) {
				delayed_buf_free_meta_store = TRUE;
			} else {
				buf_free_meta_store(bp);
			}
		}
		/*
		 * nuke any credentials we were holding
		 */
		buf_release_credentials(bp);

		lck_mtx_lock_spin(&buf_mtx);

		if (bp->b_shadow_ref) {
			SET(bp->b_lflags, BL_WAITSHADOW);

			lck_mtx_unlock(&buf_mtx);

			return;
		}
		if (delayed_buf_free_meta_store == TRUE) {
			lck_mtx_unlock(&buf_mtx);
finish_shadow_master:
			buf_free_meta_store(bp);

			lck_mtx_lock_spin(&buf_mtx);
		}
		CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED | B_AGE | B_ASYNC | B_NOCACHE | B_FUA));

		if (bp->b_vp) {
			brelvp_locked(bp);
		}

		bremhash(bp);
		BLISTNONE(bp);
		binshash(bp, &invalhash);

		bp->b_whichq = BQ_EMPTY;
		binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
	} else {
		/*
		 * It has valid data.  Put it on the end of the appropriate
		 * queue, so that it'll stick around for as long as possible.
		 */
		if (ISSET(bp->b_flags, B_LOCKED)) {
			whichq = BQ_LOCKED;             /* locked in core */
		} else if (ISSET(bp->b_flags, B_META)) {
			whichq = BQ_META;               /* meta-data */
		} else if (ISSET(bp->b_flags, B_AGE)) {
			whichq = BQ_AGE;                /* stale but valid data */
		} else {
			whichq = BQ_LRU;                /* valid data */
		}
		bufq = &bufqueues[whichq];

		bp->b_timestamp = buf_timestamp();

		lck_mtx_lock_spin(&buf_mtx);

		/*
		 * the buf_brelse_shadow routine doesn't take 'ownership'
		 * of the parent buf_t... it updates state that is protected by
		 * the buf_mtx, and checks for BL_BUSY to determine whether to
		 * put the buf_t back on a free list.  b_shadow_ref is protected
		 * by the lock, and since we have not yet cleared B_BUSY, we need
		 * to check it while holding the lock to insure that one of us
		 * puts this buf_t back on a free list when it is safe to do so
		 */
		if (bp->b_shadow_ref == 0) {
			CLR(bp->b_flags, (B_AGE | B_ASYNC | B_NOCACHE));
			bp->b_whichq = whichq;
			binstailfree(bp, bufq, whichq);
		} else {
			/*
			 * there are still cloned buf_t's pointing
			 * at this guy... need to keep it off the
			 * freelists until a buf_brelse is done on
			 * the last clone
			 */
			CLR(bp->b_flags, (B_ASYNC | B_NOCACHE));
		}
	}
	if (needbuffer) {
		/*
		 * needbuffer is a global
		 * we're currently using buf_mtx to protect it
		 * delay doing the actual wakeup until after
		 * we drop buf_mtx
		 */
		needbuffer = 0;
		need_wakeup = 1;
	}
	if (ISSET(bp->b_lflags, BL_WANTED)) {
		/*
		 * delay the actual wakeup until after we
		 * clear BL_BUSY and we've dropped buf_mtx
		 */
		need_bp_wakeup = 1;
	}
	/*
	 * Unlock the buffer.
	 */
	CLR(bp->b_lflags, (BL_BUSY | BL_WANTED));
	buf_busycount--;

	lck_mtx_unlock(&buf_mtx);

	if (need_wakeup) {
		/*
		 * Wake up any processes waiting for any buffer to become free.
		 */
		wakeup(&needbuffer);
	}
	if (need_bp_wakeup) {
		/*
		 * Wake up any proceeses waiting for _this_ buffer to become free.
		 */
		wakeup(bp);
	}
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 388)) | DBG_FUNC_END,
	    bp, bp->b_datap, bp->b_flags, 0, 0);
}

/*
 * Determine if a block is in the cache.
 * Just look on what would be its hash chain.  If it's there, return
 * a pointer to it, unless it's marked invalid.  If it's marked invalid,
 * we normally don't return the buffer, unless the caller explicitly
 * wants us to.
 */
static boolean_t
incore(vnode_t vp, daddr64_t blkno)
{
	boolean_t retval;
	struct  bufhashhdr *dp;

	dp = BUFHASH(vp, blkno);

	lck_mtx_lock_spin(&buf_mtx);

	if (incore_locked(vp, blkno, dp)) {
		retval = TRUE;
	} else {
		retval = FALSE;
	}
	lck_mtx_unlock(&buf_mtx);

	return retval;
}


static buf_t
incore_locked(vnode_t vp, daddr64_t blkno, struct bufhashhdr *dp)
{
	struct buf *bp;

	/* Search hash chain */
	for (bp = dp->lh_first; bp != NULL; bp = bp->b_hash.le_next) {
		if (bp->b_lblkno == blkno && bp->b_vp == vp &&
		    !ISSET(bp->b_flags, B_INVAL)) {
			return bp;
		}
	}
	return NULL;
}


void
buf_wait_for_shadow_io(vnode_t vp, daddr64_t blkno)
{
	buf_t bp;
	struct  bufhashhdr *dp;

	dp = BUFHASH(vp, blkno);

	lck_mtx_lock_spin(&buf_mtx);

	for (;;) {
		if ((bp = incore_locked(vp, blkno, dp)) == NULL) {
			break;
		}

		if (bp->b_shadow_ref == 0) {
			break;
		}

		SET(bp->b_lflags, BL_WANTED_REF);

		(void) msleep(bp, &buf_mtx, PSPIN | (PRIBIO + 1), "buf_wait_for_shadow", NULL);
	}
	lck_mtx_unlock(&buf_mtx);
}

/* XXX FIXME -- Update the comment to reflect the UBC changes (please) -- */
/*
 * Get a block of requested size that is associated with
 * a given vnode and block offset. If it is found in the
 * block cache, mark it as having been found, make it busy
 * and return it. Otherwise, return an empty block of the
 * correct size. It is up to the caller to insure that the
 * cached blocks be of the correct size.
 */
buf_t
buf_getblk(vnode_t vp, daddr64_t blkno, int size, int slpflag, int slptimeo, int operation)
{
	buf_t bp;
	int   err;
	upl_t upl;
	upl_page_info_t *pl;
	kern_return_t kret;
	int ret_only_valid;
	struct timespec ts;
	int upl_flags;
	struct  bufhashhdr *dp;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 386)) | DBG_FUNC_START,
	    (uintptr_t)(blkno * PAGE_SIZE), size, operation, 0, 0);

	ret_only_valid = operation & BLK_ONLYVALID;
	operation &= ~BLK_ONLYVALID;
	dp = BUFHASH(vp, blkno);
start:
	lck_mtx_lock_spin(&buf_mtx);

	if ((bp = incore_locked(vp, blkno, dp))) {
		/*
		 * Found in the Buffer Cache
		 */
		if (ISSET(bp->b_lflags, BL_BUSY)) {
			/*
			 * but is busy
			 */
			switch (operation) {
			case BLK_READ:
			case BLK_WRITE:
			case BLK_META:
				SET(bp->b_lflags, BL_WANTED);
				bufstats.bufs_busyincore++;

				/*
				 * don't retake the mutex after being awakened...
				 * the time out is in msecs
				 */
				ts.tv_sec = (slptimeo / 1000);
				ts.tv_nsec = (slptimeo % 1000) * 10  * NSEC_PER_USEC * 1000;

				KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 396)) | DBG_FUNC_NONE,
				    (uintptr_t)blkno, size, operation, 0, 0);

				err = msleep(bp, &buf_mtx, slpflag | PDROP | (PRIBIO + 1), "buf_getblk", &ts);

				/*
				 * Callers who call with PCATCH or timeout are
				 * willing to deal with the NULL pointer
				 */
				if (err && ((slpflag & PCATCH) || ((err == EWOULDBLOCK) && slptimeo))) {
					return NULL;
				}
				goto start;
			/*NOTREACHED*/

			default:
				/*
				 * unknown operation requested
				 */
				panic("getblk: paging or unknown operation for incore busy buffer - %x", operation);
				/*NOTREACHED*/
				break;
			}
		} else {
			int clear_bdone;

			/*
			 * buffer in core and not busy
			 */
			SET(bp->b_lflags, BL_BUSY);
			SET(bp->b_flags, B_CACHE);
			buf_busycount++;

			bremfree_locked(bp);
			bufstats.bufs_incore++;

			lck_mtx_unlock(&buf_mtx);
#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 1;
#endif
			if ((bp->b_upl)) {
				panic("buffer has UPL, but not marked BUSY: %p", bp);
			}

			clear_bdone = FALSE;
			if (!ret_only_valid) {
				/*
				 * If the number bytes that are valid is going
				 * to increase (even if we end up not doing a
				 * reallocation through allocbuf) we have to read
				 * the new size first.
				 *
				 * This is required in cases where we doing a read
				 * modify write of a already valid data on disk but
				 * in cases where the data on disk beyond (blkno + b_bcount)
				 * is invalid, we may end up doing extra I/O.
				 */
				if (operation == BLK_META && bp->b_bcount < (uint32_t)size) {
					/*
					 * Since we are going to read in the whole size first
					 * we first have to ensure that any pending delayed write
					 * is flushed to disk first.
					 */
					if (ISSET(bp->b_flags, B_DELWRI)) {
						CLR(bp->b_flags, B_CACHE);
						buf_bwrite(bp);
						goto start;
					}
					/*
					 * clear B_DONE before returning from
					 * this function so that the caller can
					 * can issue a read for the new size.
					 */
					clear_bdone = TRUE;
				}

				if (bp->b_bufsize != (uint32_t)size) {
					allocbuf(bp, size);
				}
			}

			upl_flags = 0;
			switch (operation) {
			case BLK_WRITE:
				/*
				 * "write" operation:  let the UPL subsystem
				 * know that we intend to modify the buffer
				 * cache pages we're gathering.
				 */
				upl_flags |= UPL_WILL_MODIFY;
				OS_FALLTHROUGH;
			case BLK_READ:
				upl_flags |= UPL_PRECIOUS;
				if (UBCINFOEXISTS(bp->b_vp) && bp->b_bufsize) {
					kret = ubc_create_upl_kernel(vp,
					    ubc_blktooff(vp, bp->b_lblkno),
					    bp->b_bufsize,
					    &upl,
					    &pl,
					    upl_flags,
					    VM_KERN_MEMORY_FILE);
					if (kret != KERN_SUCCESS) {
						panic("Failed to create UPL");
					}

					bp->b_upl = upl;

					if (upl_valid_page(pl, 0)) {
						if (upl_dirty_page(pl, 0)) {
							SET(bp->b_flags, B_WASDIRTY);
						} else {
							CLR(bp->b_flags, B_WASDIRTY);
						}
					} else {
						CLR(bp->b_flags, (B_DONE | B_CACHE | B_WASDIRTY | B_DELWRI));
					}

					kret = ubc_upl_map(upl, (vm_offset_t*)&(bp->b_datap));

					if (kret != KERN_SUCCESS) {
						panic("getblk: ubc_upl_map() failed with (%d)", kret);
					}
				}
				break;

			case BLK_META:
				/*
				 * VM is not involved in IO for the meta data
				 * buffer already has valid data
				 */
				break;

			default:
				panic("getblk: paging or unknown operation for incore buffer- %d", operation);
				/*NOTREACHED*/
				break;
			}

			if (clear_bdone) {
				CLR(bp->b_flags, B_DONE);
			}
		}
	} else { /* not incore() */
		int queue = BQ_EMPTY; /* Start with no preference */

		if (ret_only_valid) {
			lck_mtx_unlock(&buf_mtx);
			return NULL;
		}
		if ((vnode_isreg(vp) == 0) || (UBCINFOEXISTS(vp) == 0) /*|| (vnode_issystem(vp) == 1)*/) {
			operation = BLK_META;
		}

		if ((bp = getnewbuf(slpflag, slptimeo, &queue)) == NULL) {
			goto start;
		}

		/*
		 * getnewbuf may block for a number of different reasons...
		 * if it does, it's then possible for someone else to
		 * create a buffer for the same block and insert it into
		 * the hash... if we see it incore at this point we dump
		 * the buffer we were working on and start over
		 */
		if (incore_locked(vp, blkno, dp)) {
			SET(bp->b_flags, B_INVAL);
			binshash(bp, &invalhash);

			lck_mtx_unlock(&buf_mtx);

			buf_brelse(bp);
			goto start;
		}
		/*
		 * NOTE: YOU CAN NOT BLOCK UNTIL binshash() HAS BEEN
		 *       CALLED!  BE CAREFUL.
		 */

		/*
		 * mark the buffer as B_META if indicated
		 * so that when buffer is released it will goto META queue
		 */
		if (operation == BLK_META) {
			SET(bp->b_flags, B_META);
		}

		bp->b_blkno = bp->b_lblkno = blkno;
		bp->b_lblksize = 0; /* Should be set by caller */
		bp->b_vp = vp;

		/*
		 * Insert in the hash so that incore() can find it
		 */
		binshash(bp, BUFHASH(vp, blkno));

		bgetvp_locked(vp, bp);

		lck_mtx_unlock(&buf_mtx);

		allocbuf(bp, size);

		upl_flags = 0;
		switch (operation) {
		case BLK_META:
			/*
			 * buffer data is invalid...
			 *
			 * I don't want to have to retake buf_mtx,
			 * so the miss and vmhits counters are done
			 * with Atomic updates... all other counters
			 * in bufstats are protected with either
			 * buf_mtx or iobuffer_mtxp
			 */
			OSAddAtomicLong(1, &bufstats.bufs_miss);
			break;

		case BLK_WRITE:
			/*
			 * "write" operation:  let the UPL subsystem know
			 * that we intend to modify the buffer cache pages
			 * we're gathering.
			 */
			upl_flags |= UPL_WILL_MODIFY;
			OS_FALLTHROUGH;
		case BLK_READ:
		{     off_t   f_offset;
		      size_t  contig_bytes;
		      int     bmap_flags;

#if DEVELOPMENT || DEBUG
			/*
			 * Apple implemented file systems use UBC excludively; they should
			 * not call in here."
			 */
		      const char* excldfs[] = {"hfs", "afpfs", "smbfs", "acfs",
			                       "exfat", "msdos", "webdav", NULL};

		      for (int i = 0; excldfs[i] != NULL; i++) {
			      if (vp->v_mount &&
			          !strcmp(vp->v_mount->mnt_vfsstat.f_fstypename,
			          excldfs[i])) {
				      panic("%s %s calls buf_getblk",
				          excldfs[i],
				          operation == BLK_READ ? "BLK_READ" : "BLK_WRITE");
			      }
		      }
#endif

		      if ((bp->b_upl)) {
			      panic("bp already has UPL: %p", bp);
		      }

		      f_offset = ubc_blktooff(vp, blkno);

		      upl_flags |= UPL_PRECIOUS;
		      kret = ubc_create_upl_kernel(vp,
			  f_offset,
			  bp->b_bufsize,
			  &upl,
			  &pl,
			  upl_flags,
			  VM_KERN_MEMORY_FILE);

		      if (kret != KERN_SUCCESS) {
			      panic("Failed to create UPL");
		      }
#if  UPL_DEBUG
		      upl_ubc_alias_set(upl, (uintptr_t) bp, (uintptr_t) 4);
#endif /* UPL_DEBUG */
		      bp->b_upl = upl;

		      if (upl_valid_page(pl, 0)) {
			      if (operation == BLK_READ) {
				      bmap_flags = VNODE_READ;
			      } else {
				      bmap_flags = VNODE_WRITE;
			      }

			      SET(bp->b_flags, B_CACHE | B_DONE);

			      OSAddAtomicLong(1, &bufstats.bufs_vmhits);

			      bp->b_validoff = 0;
			      bp->b_dirtyoff = 0;

			      if (upl_dirty_page(pl, 0)) {
				      /* page is dirty */
				      SET(bp->b_flags, B_WASDIRTY);

				      bp->b_validend = bp->b_bcount;
				      bp->b_dirtyend = bp->b_bcount;
			      } else {
				      /* page is clean */
				      bp->b_validend = bp->b_bcount;
				      bp->b_dirtyend = 0;
			      }
			      /*
			       * try to recreate the physical block number associated with
			       * this buffer...
			       */
			      if (VNOP_BLOCKMAP(vp, f_offset, bp->b_bcount, &bp->b_blkno, &contig_bytes, NULL, bmap_flags, NULL)) {
				      panic("getblk: VNOP_BLOCKMAP failed");
			      }
			      /*
			       * if the extent represented by this buffer
			       * is not completely physically contiguous on
			       * disk, than we can't cache the physical mapping
			       * in the buffer header
			       */
			      if ((uint32_t)contig_bytes < bp->b_bcount) {
				      bp->b_blkno = bp->b_lblkno;
			      }
		      } else {
			      OSAddAtomicLong(1, &bufstats.bufs_miss);
		      }
		      kret = ubc_upl_map(upl, (vm_offset_t *)&(bp->b_datap));

		      if (kret != KERN_SUCCESS) {
			      panic("getblk: ubc_upl_map() failed with (%d)", kret);
		      }
		      break;} // end BLK_READ
		default:
			panic("getblk: paging or unknown operation - %x", operation);
			/*NOTREACHED*/
			break;
		} // end switch
	} //end buf_t !incore

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 386)) | DBG_FUNC_END,
	    bp, bp->b_datap, bp->b_flags, 3, 0);

#ifdef JOE_DEBUG
	(void) OSBacktrace(&bp->b_stackgetblk[0], 6);
#endif
	return bp;
}

/*
 * Get an empty, disassociated buffer of given size.
 */
buf_t
buf_geteblk(int size)
{
	buf_t   bp = NULL;
	int queue = BQ_EMPTY;

	do {
		lck_mtx_lock_spin(&buf_mtx);

		bp = getnewbuf(0, 0, &queue);
	} while (bp == NULL);

	SET(bp->b_flags, (B_META | B_INVAL));

#if DIAGNOSTIC
	assert(queue == BQ_EMPTY);
#endif /* DIAGNOSTIC */
	/* XXX need to implement logic to deal with other queues */

	binshash(bp, &invalhash);
	bufstats.bufs_eblk++;

	lck_mtx_unlock(&buf_mtx);

	allocbuf(bp, size);

	return bp;
}

uint32_t
buf_redundancy_flags(buf_t bp)
{
	return bp->b_redundancy_flags;
}

void
buf_set_redundancy_flags(buf_t bp, uint32_t flags)
{
	SET(bp->b_redundancy_flags, flags);
}

void
buf_clear_redundancy_flags(buf_t bp, uint32_t flags)
{
	CLR(bp->b_redundancy_flags, flags);
}



static void *
recycle_buf_from_pool(int nsize)
{
	buf_t   bp;
	void    *ptr = NULL;

	lck_mtx_lock_spin(&buf_mtx);

	TAILQ_FOREACH(bp, &bufqueues[BQ_META], b_freelist) {
		if (ISSET(bp->b_flags, B_DELWRI) || bp->b_bufsize != (uint32_t)nsize) {
			continue;
		}
		ptr = (void *)bp->b_datap;
		bp->b_bufsize = 0;

		bcleanbuf(bp, TRUE);
		break;
	}
	lck_mtx_unlock(&buf_mtx);

	return ptr;
}



int zalloc_nopagewait_failed = 0;
int recycle_buf_failed = 0;

static void *
grab_memory_for_meta_buf(int nsize)
{
	void *ptr;
	boolean_t was_vmpriv;


	/*
	 * make sure we're NOT priviliged so that
	 * if a vm_page_grab is needed, it won't
	 * block if we're out of free pages... if
	 * it blocks, then we can't honor the
	 * nopagewait request
	 */
	was_vmpriv = set_vm_privilege(FALSE);

	ptr = kheap_alloc(KHEAP_VFS_BIO, nsize, Z_NOPAGEWAIT);

	if (was_vmpriv == TRUE) {
		set_vm_privilege(TRUE);
	}

	if (ptr == NULL) {
		zalloc_nopagewait_failed++;

		ptr = recycle_buf_from_pool(nsize);

		if (ptr == NULL) {
			recycle_buf_failed++;

			if (was_vmpriv == FALSE) {
				set_vm_privilege(TRUE);
			}

			ptr = kheap_alloc(KHEAP_VFS_BIO, nsize, Z_WAITOK);

			if (was_vmpriv == FALSE) {
				set_vm_privilege(FALSE);
			}
		}
	}
	return ptr;
}

/*
 * With UBC, there is no need to expand / shrink the file data
 * buffer. The VM uses the same pages, hence no waste.
 * All the file data buffers can have one size.
 * In fact expand / shrink would be an expensive operation.
 *
 * Only exception to this is meta-data buffers. Most of the
 * meta data operations are smaller than PAGE_SIZE. Having the
 * meta-data buffers grow and shrink as needed, optimizes use
 * of the kernel wired memory.
 */

int
allocbuf(buf_t bp, int size)
{
	vm_size_t desired_size;

	desired_size = roundup(size, CLBYTES);

	if (desired_size < PAGE_SIZE) {
		desired_size = PAGE_SIZE;
	}
	if (desired_size > MAXBSIZE) {
		panic("allocbuf: buffer larger than MAXBSIZE requested");
	}

	if (ISSET(bp->b_flags, B_META)) {
		int    nsize = roundup(size, MINMETA);

		if (bp->b_datap) {
			void *elem = (void *)bp->b_datap;

			if (ISSET(bp->b_flags, B_ZALLOC)) {
				if (bp->b_bufsize < (uint32_t)nsize) {
					/* reallocate to a bigger size */

					if (nsize <= MAXMETA) {
						desired_size = nsize;

						/* b_datap not really a ptr */
						*(void **)(&bp->b_datap) = grab_memory_for_meta_buf(nsize);
					} else {
						bp->b_datap = (uintptr_t)NULL;
						kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size, VM_KERN_MEMORY_FILE);
						CLR(bp->b_flags, B_ZALLOC);
					}
					bcopy(elem, (caddr_t)bp->b_datap, bp->b_bufsize);
					kheap_free(KHEAP_VFS_BIO, elem, bp->b_bufsize);
				} else {
					desired_size = bp->b_bufsize;
				}
			} else {
				if ((vm_size_t)bp->b_bufsize < desired_size) {
					/* reallocate to a bigger size */
					bp->b_datap = (uintptr_t)NULL;
					kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size, VM_KERN_MEMORY_FILE);
					bcopy(elem, (caddr_t)bp->b_datap, bp->b_bufsize);
					kmem_free(kernel_map, (vm_offset_t)elem, bp->b_bufsize);
				} else {
					desired_size = bp->b_bufsize;
				}
			}
		} else {
			/* new allocation */
			if (nsize <= MAXMETA) {
				desired_size = nsize;

				/* b_datap not really a ptr */
				*(void **)(&bp->b_datap) = grab_memory_for_meta_buf(nsize);
				SET(bp->b_flags, B_ZALLOC);
			} else {
				kmem_alloc_kobject(kernel_map, (vm_offset_t *)&bp->b_datap, desired_size, VM_KERN_MEMORY_FILE);
			}
		}

		if (bp->b_datap == 0) {
			panic("allocbuf: NULL b_datap");
		}
	}
	bp->b_bufsize = (uint32_t)desired_size;
	bp->b_bcount = size;

	return 0;
}

/*
 *	Get a new buffer from one of the free lists.
 *
 *	Request for a queue is passes in. The queue from which the buffer was taken
 *	from is returned. Out of range queue requests get BQ_EMPTY. Request for
 *	BQUEUE means no preference. Use heuristics in that case.
 *	Heuristics is as follows:
 *	Try BQ_AGE, BQ_LRU, BQ_EMPTY, BQ_META in that order.
 *	If none available block till one is made available.
 *	If buffers available on both BQ_AGE and BQ_LRU, check the timestamps.
 *	Pick the most stale buffer.
 *	If found buffer was marked delayed write, start the async. write
 *	and restart the search.
 *	Initialize the fields and disassociate the buffer from the vnode.
 *	Remove the buffer from the hash. Return the buffer and the queue
 *	on which it was found.
 *
 *	buf_mtx is held upon entry
 *	returns with buf_mtx locked if new buf available
 *	returns with buf_mtx UNlocked if new buf NOT available
 */

static buf_t
getnewbuf(int slpflag, int slptimeo, int * queue)
{
	buf_t   bp;
	buf_t   lru_bp;
	buf_t   age_bp;
	buf_t   meta_bp;
	int     age_time, lru_time, bp_time, meta_time;
	int     req = *queue;   /* save it for restarts */
	struct timespec ts;

start:
	/*
	 * invalid request gets empty queue
	 */
	if ((*queue >= BQUEUES) || (*queue < 0)
	    || (*queue == BQ_LAUNDRY) || (*queue == BQ_LOCKED)) {
		*queue = BQ_EMPTY;
	}


	if (*queue == BQ_EMPTY && (bp = bufqueues[*queue].tqh_first)) {
		goto found;
	}

	/*
	 * need to grow number of bufs, add another one rather than recycling
	 */
	if (nbuf_headers < max_nbuf_headers) {
		/*
		 * Increment  count now as lock
		 * is dropped for allocation.
		 * That avoids over commits
		 */
		nbuf_headers++;
		goto add_newbufs;
	}
	/* Try for the requested queue first */
	bp = bufqueues[*queue].tqh_first;
	if (bp) {
		goto found;
	}

	/* Unable to use requested queue */
	age_bp = bufqueues[BQ_AGE].tqh_first;
	lru_bp = bufqueues[BQ_LRU].tqh_first;
	meta_bp = bufqueues[BQ_META].tqh_first;

	if (!age_bp && !lru_bp && !meta_bp) {
		/*
		 * Unavailble on AGE or LRU or META queues
		 * Try the empty list first
		 */
		bp = bufqueues[BQ_EMPTY].tqh_first;
		if (bp) {
			*queue = BQ_EMPTY;
			goto found;
		}
		/*
		 * We have seen is this is hard to trigger.
		 * This is an overcommit of nbufs but needed
		 * in some scenarios with diskiamges
		 */

add_newbufs:
		lck_mtx_unlock(&buf_mtx);

		/* Create a new temporary buffer header */
		bp = zalloc_flags(buf_hdr_zone, Z_WAITOK | Z_NOFAIL);
		bufhdrinit(bp);
		bp->b_whichq = BQ_EMPTY;
		bp->b_timestamp = buf_timestamp();
		BLISTNONE(bp);
		SET(bp->b_flags, B_HDRALLOC);
		*queue = BQ_EMPTY;
		lck_mtx_lock_spin(&buf_mtx);

		if (bp) {
			binshash(bp, &invalhash);
			binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
			buf_hdr_count++;
			goto found;
		}
		/* subtract already accounted bufcount */
		nbuf_headers--;

		bufstats.bufs_sleeps++;

		/* wait for a free buffer of any kind */
		needbuffer = 1;
		/* hz value is 100 */
		ts.tv_sec = (slptimeo / 1000);
		/* the hz value is 100; which leads to 10ms */
		ts.tv_nsec = (slptimeo % 1000) * NSEC_PER_USEC * 1000 * 10;

		msleep(&needbuffer, &buf_mtx, slpflag | PDROP | (PRIBIO + 1), "getnewbuf", &ts);
		return NULL;
	}

	/* Buffer available either on AGE or LRU or META */
	bp = NULL;
	*queue = -1;

	/* Buffer available either on AGE or LRU */
	if (!age_bp) {
		bp = lru_bp;
		*queue = BQ_LRU;
	} else if (!lru_bp) {
		bp = age_bp;
		*queue = BQ_AGE;
	} else { /* buffer available on both AGE and LRU */
		int             t = buf_timestamp();

		age_time = t - age_bp->b_timestamp;
		lru_time = t - lru_bp->b_timestamp;
		if ((age_time < 0) || (lru_time < 0)) { /* time set backwards */
			bp = age_bp;
			*queue = BQ_AGE;
			/*
			 * we should probably re-timestamp eveything in the
			 * queues at this point with the current time
			 */
		} else {
			if ((lru_time >= lru_is_stale) && (age_time < age_is_stale)) {
				bp = lru_bp;
				*queue = BQ_LRU;
			} else {
				bp = age_bp;
				*queue = BQ_AGE;
			}
		}
	}

	if (!bp) { /* Neither on AGE nor on LRU */
		bp = meta_bp;
		*queue = BQ_META;
	} else if (meta_bp) {
		int             t = buf_timestamp();

		bp_time = t - bp->b_timestamp;
		meta_time = t - meta_bp->b_timestamp;

		if (!(bp_time < 0) && !(meta_time < 0)) {
			/* time not set backwards */
			int bp_is_stale;
			bp_is_stale = (*queue == BQ_LRU) ?
			    lru_is_stale : age_is_stale;

			if ((meta_time >= meta_is_stale) &&
			    (bp_time < bp_is_stale)) {
				bp = meta_bp;
				*queue = BQ_META;
			}
		}
	}
found:
	if (ISSET(bp->b_flags, B_LOCKED) || ISSET(bp->b_lflags, BL_BUSY)) {
		panic("getnewbuf: bp @ %p is LOCKED or BUSY! (flags 0x%x)", bp, bp->b_flags);
	}

	/* Clean it */
	if (bcleanbuf(bp, FALSE)) {
		/*
		 * moved to the laundry thread, buffer not ready
		 */
		*queue = req;
		goto start;
	}
	return bp;
}


/*
 * Clean a buffer.
 * Returns 0 if buffer is ready to use,
 * Returns 1 if issued a buf_bawrite() to indicate
 * that the buffer is not ready.
 *
 * buf_mtx is held upon entry
 * returns with buf_mtx locked
 */
int
bcleanbuf(buf_t bp, boolean_t discard)
{
	/* Remove from the queue */
	bremfree_locked(bp);

#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 2;
#endif
	/*
	 * If buffer was a delayed write, start the IO by queuing
	 * it on the LAUNDRY queue, and return 1
	 */
	if (ISSET(bp->b_flags, B_DELWRI)) {
		if (discard) {
			SET(bp->b_lflags, BL_WANTDEALLOC);
		}

		bmovelaundry(bp);

		lck_mtx_unlock(&buf_mtx);

		wakeup(&bufqueues[BQ_LAUNDRY]);
		/*
		 * and give it a chance to run
		 */
		(void)thread_block(THREAD_CONTINUE_NULL);

		lck_mtx_lock_spin(&buf_mtx);

		return 1;
	}
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 8;
#endif
	/*
	 * Buffer is no longer on any free list... we own it
	 */
	SET(bp->b_lflags, BL_BUSY);
	buf_busycount++;

	bremhash(bp);

	/*
	 * disassociate us from our vnode, if we had one...
	 */
	if (bp->b_vp) {
		brelvp_locked(bp);
	}

	lck_mtx_unlock(&buf_mtx);

	BLISTNONE(bp);

	if (ISSET(bp->b_flags, B_META)) {
		buf_free_meta_store(bp);
	}

	trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

	buf_release_credentials(bp);

	/* If discarding, just move to the empty queue */
	if (discard) {
		lck_mtx_lock_spin(&buf_mtx);
		CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED | B_AGE | B_ASYNC | B_NOCACHE | B_FUA));
		bp->b_whichq = BQ_EMPTY;
		binshash(bp, &invalhash);
		binsheadfree(bp, &bufqueues[BQ_EMPTY], BQ_EMPTY);
		CLR(bp->b_lflags, BL_BUSY);
		buf_busycount--;
	} else {
		/* Not discarding: clean up and prepare for reuse */
		bp->b_bufsize = 0;
		bp->b_datap = (uintptr_t)NULL;
		bp->b_upl = (void *)NULL;
		/* call fs callback to release private data */
		if (bp->b_fsprivate_done != NULL){
			(void)b_fsprivate_done(bp->b_fsprivate);
		}
		bp->b_fsprivate = (void *)NULL;
		/*
		 * preserve the state of whether this buffer
		 * was allocated on the fly or not...
		 * the only other flag that should be set at
		 * this point is BL_BUSY...
		 */
#ifdef JOE_DEBUG
		bp->b_owner = current_thread();
		bp->b_tag   = 3;
#endif
		bp->b_lflags = BL_BUSY;
		bp->b_flags = (bp->b_flags & B_HDRALLOC);
		bp->b_redundancy_flags = 0;
		bp->b_dev = NODEV;
		bp->b_blkno = bp->b_lblkno = 0;
		bp->b_lblksize = 0;
		bp->b_iodone = NULL;
		bp->b_error = 0;
		bp->b_resid = 0;
		bp->b_bcount = 0;
		bp->b_dirtyoff = bp->b_dirtyend = 0;
		bp->b_validoff = bp->b_validend = 0;
		bzero(&bp->b_attr, sizeof(struct bufattr));

		lck_mtx_lock_spin(&buf_mtx);
	}
	return 0;
}



errno_t
buf_invalblkno(vnode_t vp, daddr64_t lblkno, int flags)
{
	buf_t   bp;
	errno_t error;
	struct bufhashhdr *dp;

	dp = BUFHASH(vp, lblkno);

relook:
	lck_mtx_lock_spin(&buf_mtx);

	if ((bp = incore_locked(vp, lblkno, dp)) == (struct buf *)0) {
		lck_mtx_unlock(&buf_mtx);
		return 0;
	}
	if (ISSET(bp->b_lflags, BL_BUSY)) {
		if (!ISSET(flags, BUF_WAIT)) {
			lck_mtx_unlock(&buf_mtx);
			return EBUSY;
		}
		SET(bp->b_lflags, BL_WANTED);

		error = msleep((caddr_t)bp, &buf_mtx, PDROP | (PRIBIO + 1), "buf_invalblkno", NULL);

		if (error) {
			return error;
		}
		goto relook;
	}
	bremfree_locked(bp);
	SET(bp->b_lflags, BL_BUSY);
	SET(bp->b_flags, B_INVAL);
	buf_busycount++;
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 4;
#endif
	lck_mtx_unlock(&buf_mtx);
	buf_brelse(bp);

	return 0;
}


void
buf_drop(buf_t bp)
{
	int need_wakeup = 0;

	lck_mtx_lock_spin(&buf_mtx);

	if (ISSET(bp->b_lflags, BL_WANTED)) {
		/*
		 * delay the actual wakeup until after we
		 * clear BL_BUSY and we've dropped buf_mtx
		 */
		need_wakeup = 1;
	}
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 9;
#endif
	/*
	 * Unlock the buffer.
	 */
	CLR(bp->b_lflags, (BL_BUSY | BL_WANTED));
	buf_busycount--;

	lck_mtx_unlock(&buf_mtx);

	if (need_wakeup) {
		/*
		 * Wake up any proceeses waiting for _this_ buffer to become free.
		 */
		wakeup(bp);
	}
}


errno_t
buf_acquire(buf_t bp, int flags, int slpflag, int slptimeo)
{
	errno_t error;

	lck_mtx_lock_spin(&buf_mtx);

	error = buf_acquire_locked(bp, flags, slpflag, slptimeo);

	lck_mtx_unlock(&buf_mtx);

	return error;
}


static errno_t
buf_acquire_locked(buf_t bp, int flags, int slpflag, int slptimeo)
{
	errno_t error;
	struct timespec ts;

	if (ISSET(bp->b_flags, B_LOCKED)) {
		if ((flags & BAC_SKIP_LOCKED)) {
			return EDEADLK;
		}
	} else {
		if ((flags & BAC_SKIP_NONLOCKED)) {
			return EDEADLK;
		}
	}
	if (ISSET(bp->b_lflags, BL_BUSY)) {
		/*
		 * since the lck_mtx_lock may block, the buffer
		 * may become BUSY, so we need to
		 * recheck for a NOWAIT request
		 */
		if (flags & BAC_NOWAIT) {
			return EBUSY;
		}
		SET(bp->b_lflags, BL_WANTED);

		/* the hz value is 100; which leads to 10ms */
		ts.tv_sec = (slptimeo / 100);
		ts.tv_nsec = (slptimeo % 100) * 10  * NSEC_PER_USEC * 1000;
		error = msleep((caddr_t)bp, &buf_mtx, slpflag | (PRIBIO + 1), "buf_acquire", &ts);

		if (error) {
			return error;
		}
		return EAGAIN;
	}
	if (flags & BAC_REMOVE) {
		bremfree_locked(bp);
	}
	SET(bp->b_lflags, BL_BUSY);
	buf_busycount++;

#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 5;
#endif
	return 0;
}


/*
 * Wait for operations on the buffer to complete.
 * When they do, extract and return the I/O's error value.
 */
errno_t
buf_biowait(buf_t bp)
{
	while (!ISSET(bp->b_flags, B_DONE)) {
		lck_mtx_lock_spin(&buf_mtx);

		if (!ISSET(bp->b_flags, B_DONE)) {
			DTRACE_IO1(wait__start, buf_t, bp);
			(void) msleep(bp, &buf_mtx, PDROP | (PRIBIO + 1), "buf_biowait", NULL);
			DTRACE_IO1(wait__done, buf_t, bp);
		} else {
			lck_mtx_unlock(&buf_mtx);
		}
	}
	/* check for interruption of I/O (e.g. via NFS), then errors. */
	if (ISSET(bp->b_flags, B_EINTR)) {
		CLR(bp->b_flags, B_EINTR);
		return EINTR;
	} else if (ISSET(bp->b_flags, B_ERROR)) {
		return bp->b_error ? bp->b_error : EIO;
	} else {
		return 0;
	}
}


/*
 * Mark I/O complete on a buffer.
 *
 * If a callback has been requested, e.g. the pageout
 * daemon, do so. Otherwise, awaken waiting processes.
 *
 * [ Leffler, et al., says on p.247:
 *	"This routine wakes up the blocked process, frees the buffer
 *	for an asynchronous write, or, for a request by the pagedaemon
 *	process, invokes a procedure specified in the buffer structure" ]
 *
 * In real life, the pagedaemon (or other system processes) wants
 * to do async stuff to, and doesn't want the buffer buf_brelse()'d.
 * (for swap pager, that puts swap buffers on the free lists (!!!),
 * for the vn device, that puts malloc'd buffers on the free lists!)
 */

void
buf_biodone(buf_t bp)
{
	mount_t mp;
	struct bufattr *bap;
	struct timeval real_elapsed;
	uint64_t real_elapsed_usec = 0;

	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 387)) | DBG_FUNC_START,
	    bp, bp->b_datap, bp->b_flags, 0, 0);

	if (ISSET(bp->b_flags, B_DONE)) {
		panic("biodone already");
	}

	bap = &bp->b_attr;

	if (bp->b_vp && bp->b_vp->v_mount) {
		mp = bp->b_vp->v_mount;
	} else {
		mp = NULL;
	}

	if (ISSET(bp->b_flags, B_ERROR)) {
		if (mp && (MNT_ROOTFS & mp->mnt_flag)) {
			dk_error_description_t desc;
			bzero(&desc, sizeof(desc));
			desc.description      = panic_disk_error_description;
			desc.description_size = panic_disk_error_description_size;
			VNOP_IOCTL(mp->mnt_devvp, DKIOCGETERRORDESCRIPTION, (caddr_t)&desc, 0, vfs_context_kernel());
		}
	}

	if (mp && (bp->b_flags & B_READ) == 0) {
		update_last_io_time(mp);
		INCR_PENDING_IO(-(pending_io_t)buf_count(bp), mp->mnt_pending_write_size);
	} else if (mp) {
		INCR_PENDING_IO(-(pending_io_t)buf_count(bp), mp->mnt_pending_read_size);
	}

	throttle_info_end_io(bp);

	if (kdebug_enable) {
		int code    = DKIO_DONE;
		int io_tier = GET_BUFATTR_IO_TIER(bap);

		if (bp->b_flags & B_READ) {
			code |= DKIO_READ;
		}
		if (bp->b_flags & B_ASYNC) {
			code |= DKIO_ASYNC;
		}

		if (bp->b_flags & B_META) {
			code |= DKIO_META;
		} else if (bp->b_flags & B_PAGEIO) {
			code |= DKIO_PAGING;
		}

		if (io_tier != 0) {
			code |= DKIO_THROTTLE;
		}

		code |= ((io_tier << DKIO_TIER_SHIFT) & DKIO_TIER_MASK);

		if (bp->b_flags & B_PASSIVE) {
			code |= DKIO_PASSIVE;
		}

		if (bap->ba_flags & BA_NOCACHE) {
			code |= DKIO_NOCACHE;
		}

		if (bap->ba_flags & BA_IO_TIER_UPGRADE) {
			code |= DKIO_TIER_UPGRADE;
		}

		KDBG_RELEASE_NOPROCFILT(FSDBG_CODE(DBG_DKRW, code),
		    buf_kernel_addrperm_addr(bp),
		    (uintptr_t)VM_KERNEL_ADDRPERM(bp->b_vp), bp->b_resid,
		    bp->b_error);
	}

	microuptime(&real_elapsed);
	timevalsub(&real_elapsed, &bp->b_timestamp_tv);
	real_elapsed_usec = real_elapsed.tv_sec * USEC_PER_SEC + real_elapsed.tv_usec;
	disk_conditioner_delay(bp, 1, bp->b_bcount, real_elapsed_usec);

	/*
	 * I/O was done, so don't believe
	 * the DIRTY state from VM anymore...
	 * and we need to reset the THROTTLED/PASSIVE
	 * indicators
	 */
	CLR(bp->b_flags, (B_WASDIRTY | B_PASSIVE));
	CLR(bap->ba_flags, (BA_META | BA_NOCACHE | BA_DELAYIDLESLEEP | BA_IO_TIER_UPGRADE));

	SET_BUFATTR_IO_TIER(bap, 0);

	DTRACE_IO1(done, buf_t, bp);

	if (!ISSET(bp->b_flags, B_READ) && !ISSET(bp->b_flags, B_RAW)) {
		/*
		 * wake up any writer's blocked
		 * on throttle or waiting for I/O
		 * to drain
		 */
		vnode_writedone(bp->b_vp);
	}

	if (ISSET(bp->b_flags, (B_CALL | B_FILTER))) {  /* if necessary, call out */
		void    (*iodone_func)(struct buf *, void *) = bp->b_iodone;
		void    *arg = bp->b_transaction;
		int     callout = ISSET(bp->b_flags, B_CALL);

		if (iodone_func == NULL) {
			panic("biodone: bp @ %p has NULL b_iodone!", bp);
		}

		CLR(bp->b_flags, (B_CALL | B_FILTER));  /* filters and callouts are one-shot */
		bp->b_iodone = NULL;
		bp->b_transaction = NULL;

		if (callout) {
			SET(bp->b_flags, B_DONE);       /* note that it's done */
		}
		(*iodone_func)(bp, arg);

		if (callout) {
			/*
			 * assumes that the callback function takes
			 * ownership of the bp and deals with releasing it if necessary
			 */
			goto biodone_done;
		}
		/*
		 * in this case the call back function is acting
		 * strictly as a filter... it does not take
		 * ownership of the bp and is expecting us
		 * to finish cleaning up... this is currently used
		 * by the HFS journaling code
		 */
	}
	if (ISSET(bp->b_flags, B_ASYNC)) {      /* if async, release it */
		SET(bp->b_flags, B_DONE);       /* note that it's done */

		buf_brelse(bp);
	} else {                                /* or just wakeup the buffer */
		/*
		 * by taking the mutex, we serialize
		 * the buf owner calling buf_biowait so that we'll
		 * only see him in one of 2 states...
		 * state 1: B_DONE wasn't set and he's
		 * blocked in msleep
		 * state 2: he's blocked trying to take the
		 * mutex before looking at B_DONE
		 * BL_WANTED is cleared in case anyone else
		 * is blocked waiting for the buffer... note
		 * that we haven't cleared B_BUSY yet, so if
		 * they do get to run, their going to re-set
		 * BL_WANTED and go back to sleep
		 */
		lck_mtx_lock_spin(&buf_mtx);

		CLR(bp->b_lflags, BL_WANTED);
		SET(bp->b_flags, B_DONE);               /* note that it's done */

		lck_mtx_unlock(&buf_mtx);

		wakeup(bp);
	}
biodone_done:
	KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, 387)) | DBG_FUNC_END,
	    (uintptr_t)bp, (uintptr_t)bp->b_datap, bp->b_flags, 0, 0);
}

/*
 * Obfuscate buf pointers.
 */
vm_offset_t
buf_kernel_addrperm_addr(void * addr)
{
	if ((vm_offset_t)addr == 0) {
		return 0;
	} else {
		return (vm_offset_t)addr + buf_kernel_addrperm;
	}
}

/*
 * Return a count of buffers on the "locked" queue.
 */
int
count_lock_queue(void)
{
	buf_t   bp;
	int     n = 0;

	lck_mtx_lock_spin(&buf_mtx);

	for (bp = bufqueues[BQ_LOCKED].tqh_first; bp;
	    bp = bp->b_freelist.tqe_next) {
		n++;
	}
	lck_mtx_unlock(&buf_mtx);

	return n;
}

/*
 * Return a count of 'busy' buffers. Used at the time of shutdown.
 * note: This is also called from the mach side in debug context in kdp.c
 */
uint32_t
count_busy_buffers(void)
{
	return buf_busycount + bufstats.bufs_iobufinuse;
}

#if DIAGNOSTIC
/*
 * Print out statistics on the current allocation of the buffer pool.
 * Can be enabled to print out on every ``sync'' by setting "syncprt"
 * in vfs_syscalls.c using sysctl.
 */
void
vfs_bufstats()
{
	int i, j, count;
	struct buf *bp;
	struct bqueues *dp;
	int counts[MAXBSIZE / CLBYTES + 1];
	static char *bname[BQUEUES] =
	{ "LOCKED", "LRU", "AGE", "EMPTY", "META", "LAUNDRY" };

	for (dp = bufqueues, i = 0; dp < &bufqueues[BQUEUES]; dp++, i++) {
		count = 0;
		for (j = 0; j <= MAXBSIZE / CLBYTES; j++) {
			counts[j] = 0;
		}

		lck_mtx_lock(&buf_mtx);

		for (bp = dp->tqh_first; bp; bp = bp->b_freelist.tqe_next) {
			counts[bp->b_bufsize / CLBYTES]++;
			count++;
		}
		lck_mtx_unlock(&buf_mtx);

		printf("%s: total-%d", bname[i], count);
		for (j = 0; j <= MAXBSIZE / CLBYTES; j++) {
			if (counts[j] != 0) {
				printf(", %d-%d", j * CLBYTES, counts[j]);
			}
		}
		printf("\n");
	}
}
#endif /* DIAGNOSTIC */

#define NRESERVEDIOBUFS 128

#define MNT_VIRTUALDEV_MAX_IOBUFS 128
#define VIRTUALDEV_MAX_IOBUFS ((40*niobuf_headers)/100)

buf_t
alloc_io_buf(vnode_t vp, int priv)
{
	buf_t   bp;
	mount_t mp = NULL;
	int alloc_for_virtualdev = FALSE;

	lck_mtx_lock_spin(&iobuffer_mtxp);

	/*
	 * We subject iobuf requests for diskimages to additional restrictions.
	 *
	 * a) A single diskimage mount cannot use up more than
	 * MNT_VIRTUALDEV_MAX_IOBUFS. However,vm privileged (pageout) requests
	 * are not subject to this restriction.
	 * b) iobuf headers used by all diskimage headers by all mount
	 * points cannot exceed  VIRTUALDEV_MAX_IOBUFS.
	 */
	if (vp && ((mp = vp->v_mount)) && mp != dead_mountp &&
	    mp->mnt_kern_flag & MNTK_VIRTUALDEV) {
		alloc_for_virtualdev = TRUE;
		while ((!priv && mp->mnt_iobufinuse > MNT_VIRTUALDEV_MAX_IOBUFS) ||
		    bufstats.bufs_iobufinuse_vdev > VIRTUALDEV_MAX_IOBUFS) {
			bufstats.bufs_iobufsleeps++;

			need_iobuffer = 1;
			(void)msleep(&need_iobuffer, &iobuffer_mtxp,
			    PSPIN | (PRIBIO + 1), (const char *)"alloc_io_buf (1)",
			    NULL);
		}
	}

	while ((((uint32_t)(niobuf_headers - NRESERVEDIOBUFS) < bufstats.bufs_iobufinuse) && !priv) ||
	    (bp = iobufqueue.tqh_first) == NULL) {
		bufstats.bufs_iobufsleeps++;

		need_iobuffer = 1;
		(void)msleep(&need_iobuffer, &iobuffer_mtxp, PSPIN | (PRIBIO + 1),
		    (const char *)"alloc_io_buf (2)", NULL);
	}
	TAILQ_REMOVE(&iobufqueue, bp, b_freelist);

	bufstats.bufs_iobufinuse++;
	if (bufstats.bufs_iobufinuse > bufstats.bufs_iobufmax) {
		bufstats.bufs_iobufmax = bufstats.bufs_iobufinuse;
	}

	if (alloc_for_virtualdev) {
		mp->mnt_iobufinuse++;
		bufstats.bufs_iobufinuse_vdev++;
	}

	lck_mtx_unlock(&iobuffer_mtxp);

	/*
	 * initialize various fields
	 * we don't need to hold the mutex since the buffer
	 * is now private... the vp should have a reference
	 * on it and is not protected by this mutex in any event
	 */
	bp->b_timestamp = 0;
	bp->b_proc = NULL;

	bp->b_datap = 0;
	bp->b_flags = 0;
	bp->b_lflags = BL_BUSY | BL_IOBUF;
	if (alloc_for_virtualdev) {
		bp->b_lflags |= BL_IOBUF_VDEV;
	}
	bp->b_redundancy_flags = 0;
	bp->b_blkno = bp->b_lblkno = 0;
	bp->b_lblksize = 0;
#ifdef JOE_DEBUG
	bp->b_owner = current_thread();
	bp->b_tag   = 6;
#endif
	bp->b_iodone = NULL;
	bp->b_error = 0;
	bp->b_resid = 0;
	bp->b_bcount = 0;
	bp->b_bufsize = 0;
	bp->b_upl = NULL;
	bp->b_fsprivate = (void *)NULL;
	bp->b_fsprivate_done = NULL;
	bp->b_vp = vp;
	bzero(&bp->b_attr, sizeof(struct bufattr));

	if (vp && (vp->v_type == VBLK || vp->v_type == VCHR)) {
		bp->b_dev = vp->v_rdev;
	} else {
		bp->b_dev = NODEV;
	}

	return bp;
}


void
free_io_buf(buf_t bp)
{
	int need_wakeup = 0;
	int free_for_virtualdev = FALSE;
	mount_t mp = NULL;

	/* Was this iobuf for a diskimage ? */
	if (bp->b_lflags & BL_IOBUF_VDEV) {
		free_for_virtualdev = TRUE;
		if (bp->b_vp) {
			mp = bp->b_vp->v_mount;
		}
	}

	/*
	 * put buffer back on the head of the iobufqueue
	 */
	bp->b_vp = NULL;
	bp->b_flags = B_INVAL;

	/* Zero out the bufattr and its flags before relinquishing this iobuf */
	bzero(&bp->b_attr, sizeof(struct bufattr));

	lck_mtx_lock_spin(&iobuffer_mtxp);

	binsheadfree(bp, &iobufqueue, -1);

	if (need_iobuffer) {
		/*
		 * Wake up any processes waiting because they need an io buffer
		 *
		 * do the wakeup after we drop the mutex... it's possible that the
		 * wakeup will be superfluous if need_iobuffer gets set again and
		 * another thread runs this path, but it's highly unlikely, doesn't
		 * hurt, and it means we don't hold up I/O progress if the wakeup blocks
		 * trying to grab a task related lock...
		 */
		need_iobuffer = 0;
		need_wakeup = 1;
	}
	if (bufstats.bufs_iobufinuse <= 0) {
		panic("free_io_buf: bp(%p) - bufstats.bufs_iobufinuse < 0", bp);
	}

	bufstats.bufs_iobufinuse--;

	if (free_for_virtualdev) {
		bufstats.bufs_iobufinuse_vdev--;
		if (mp && mp != dead_mountp) {
			mp->mnt_iobufinuse--;
		}
	}

	lck_mtx_unlock(&iobuffer_mtxp);

	if (need_wakeup) {
		wakeup(&need_iobuffer);
	}
}


void
buf_list_lock(void)
{
	lck_mtx_lock_spin(&buf_mtx);
}

void
buf_list_unlock(void)
{
	lck_mtx_unlock(&buf_mtx);
}

/*
 * If getnewbuf() calls bcleanbuf() on the same thread
 * there is a potential for stack overrun and deadlocks.
 * So we always handoff the work to a worker thread for completion
 */


static void
bcleanbuf_thread_init(void)
{
	thread_t        thread = THREAD_NULL;

	/* create worker thread */
	kernel_thread_start((thread_continue_t)bcleanbuf_thread, NULL, &thread);
	thread_deallocate(thread);
}

typedef int (*bcleanbufcontinuation)(int);

__attribute__((noreturn))
static void
bcleanbuf_thread(void)
{
	struct buf *bp;
	int error = 0;
	int loopcnt = 0;

	for (;;) {
		lck_mtx_lock_spin(&buf_mtx);

		while ((bp = TAILQ_FIRST(&bufqueues[BQ_LAUNDRY])) == NULL) {
			(void)msleep0(&bufqueues[BQ_LAUNDRY], &buf_mtx, PRIBIO | PDROP, "blaundry", 0, (bcleanbufcontinuation)bcleanbuf_thread);
		}

		/*
		 * Remove from the queue
		 */
		bremfree_locked(bp);

		/*
		 * Buffer is no longer on any free list
		 */
		SET(bp->b_lflags, BL_BUSY);
		buf_busycount++;

#ifdef JOE_DEBUG
		bp->b_owner = current_thread();
		bp->b_tag   = 10;
#endif

		lck_mtx_unlock(&buf_mtx);
		/*
		 * do the IO
		 */
		error = bawrite_internal(bp, 0);

		if (error) {
			bp->b_whichq = BQ_LAUNDRY;
			bp->b_timestamp = buf_timestamp();

			lck_mtx_lock_spin(&buf_mtx);

			binstailfree(bp, &bufqueues[BQ_LAUNDRY], BQ_LAUNDRY);
			blaundrycnt++;

			/* we never leave a busy page on the laundry queue */
			CLR(bp->b_lflags, BL_BUSY);
			buf_busycount--;
#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 11;
#endif

			lck_mtx_unlock(&buf_mtx);

			if (loopcnt > MAXLAUNDRY) {
				/*
				 * bawrite_internal() can return errors if we're throttled. If we've
				 * done several I/Os and failed, give the system some time to unthrottle
				 * the vnode
				 */
				(void)tsleep((void *)&bufqueues[BQ_LAUNDRY], PRIBIO, "blaundry", 1);
				loopcnt = 0;
			} else {
				/* give other threads a chance to run */
				(void)thread_block(THREAD_CONTINUE_NULL);
				loopcnt++;
			}
		}
	}
}


static int
brecover_data(buf_t bp)
{
	int     upl_offset;
	upl_t   upl;
	upl_page_info_t *pl;
	kern_return_t kret;
	vnode_t vp = bp->b_vp;
	int upl_flags;


	if (!UBCINFOEXISTS(vp) || bp->b_bufsize == 0) {
		goto dump_buffer;
	}

	upl_flags = UPL_PRECIOUS;
	if (!(buf_flags(bp) & B_READ)) {
		/*
		 * "write" operation:  let the UPL subsystem know
		 * that we intend to modify the buffer cache pages we're
		 * gathering.
		 */
		upl_flags |= UPL_WILL_MODIFY;
	}

	kret = ubc_create_upl_kernel(vp,
	    ubc_blktooff(vp, bp->b_lblkno),
	    bp->b_bufsize,
	    &upl,
	    &pl,
	    upl_flags,
	    VM_KERN_MEMORY_FILE);
	if (kret != KERN_SUCCESS) {
		panic("Failed to create UPL");
	}

	for (upl_offset = 0; (uint32_t)upl_offset < bp->b_bufsize; upl_offset += PAGE_SIZE) {
		if (!upl_valid_page(pl, upl_offset / PAGE_SIZE) || !upl_dirty_page(pl, upl_offset / PAGE_SIZE)) {
			ubc_upl_abort(upl, 0);
			goto dump_buffer;
		}
	}
	bp->b_upl = upl;

	kret = ubc_upl_map(upl, (vm_offset_t *)&(bp->b_datap));

	if (kret != KERN_SUCCESS) {
		panic("getblk: ubc_upl_map() failed with (%d)", kret);
	}
	return 1;

dump_buffer:
	bp->b_bufsize = 0;
	SET(bp->b_flags, B_INVAL);
	buf_brelse(bp);

	return 0;
}

int
fs_buffer_cache_gc_register(void (* callout)(int, void *), void *context)
{
	lck_mtx_lock(&buf_gc_callout);
	for (int i = 0; i < FS_BUFFER_CACHE_GC_CALLOUTS_MAX_SIZE; i++) {
		if (fs_callouts[i].callout == NULL) {
			fs_callouts[i].callout = callout;
			fs_callouts[i].context = context;
			lck_mtx_unlock(&buf_gc_callout);
			return 0;
		}
	}

	lck_mtx_unlock(&buf_gc_callout);
	return ENOMEM;
}

int
fs_buffer_cache_gc_unregister(void (* callout)(int, void *), void *context)
{
	lck_mtx_lock(&buf_gc_callout);
	for (int i = 0; i < FS_BUFFER_CACHE_GC_CALLOUTS_MAX_SIZE; i++) {
		if (fs_callouts[i].callout == callout &&
		    fs_callouts[i].context == context) {
			fs_callouts[i].callout = NULL;
			fs_callouts[i].context = NULL;
		}
	}
	lck_mtx_unlock(&buf_gc_callout);
	return 0;
}

static void
fs_buffer_cache_gc_dispatch_callouts(int all)
{
	lck_mtx_lock(&buf_gc_callout);
	for (int i = 0; i < FS_BUFFER_CACHE_GC_CALLOUTS_MAX_SIZE; i++) {
		if (fs_callouts[i].callout != NULL) {
			fs_callouts[i].callout(all, fs_callouts[i].context);
		}
	}
	lck_mtx_unlock(&buf_gc_callout);
}

static boolean_t
buffer_cache_gc(int all)
{
	buf_t bp;
	boolean_t did_large_zfree = FALSE;
	boolean_t need_wakeup = FALSE;
	int now = buf_timestamp();
	uint32_t found = 0;
	struct bqueues privq;
	int thresh_hold = BUF_STALE_THRESHHOLD;

	if (all) {
		thresh_hold = 0;
	}
	/*
	 * We only care about metadata (incore storage comes from zalloc()).
	 * Unless "all" is set (used to evict meta data buffers in preparation
	 * for deep sleep), we only evict up to BUF_MAX_GC_BATCH_SIZE buffers
	 * that have not been accessed in the last BUF_STALE_THRESHOLD seconds.
	 * BUF_MAX_GC_BATCH_SIZE controls both the hold time of the global lock
	 * "buf_mtx" and the length of time we spend compute bound in the GC
	 * thread which calls this function
	 */
	lck_mtx_lock(&buf_mtx);

	do {
		found = 0;
		TAILQ_INIT(&privq);
		need_wakeup = FALSE;

		while (((bp = TAILQ_FIRST(&bufqueues[BQ_META]))) &&
		    (now > bp->b_timestamp) &&
		    (now - bp->b_timestamp > thresh_hold) &&
		    (found < BUF_MAX_GC_BATCH_SIZE)) {
			/* Remove from free list */
			bremfree_locked(bp);
			found++;

#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 12;
#endif

			/* If dirty, move to laundry queue and remember to do wakeup */
			if (ISSET(bp->b_flags, B_DELWRI)) {
				SET(bp->b_lflags, BL_WANTDEALLOC);

				bmovelaundry(bp);
				need_wakeup = TRUE;

				continue;
			}

			/*
			 * Mark busy and put on private list.  We could technically get
			 * away without setting BL_BUSY here.
			 */
			SET(bp->b_lflags, BL_BUSY);
			buf_busycount++;

			/*
			 * Remove from hash and dissociate from vp.
			 */
			bremhash(bp);
			if (bp->b_vp) {
				brelvp_locked(bp);
			}

			TAILQ_INSERT_TAIL(&privq, bp, b_freelist);
		}

		if (found == 0) {
			break;
		}

		/* Drop lock for batch processing */
		lck_mtx_unlock(&buf_mtx);

		/* Wakeup and yield for laundry if need be */
		if (need_wakeup) {
			wakeup(&bufqueues[BQ_LAUNDRY]);
			(void)thread_block(THREAD_CONTINUE_NULL);
		}

		/* Clean up every buffer on private list */
		TAILQ_FOREACH(bp, &privq, b_freelist) {
			/* Take note if we've definitely freed at least a page to a zone */
			if ((ISSET(bp->b_flags, B_ZALLOC)) && (buf_size(bp) >= PAGE_SIZE)) {
				did_large_zfree = TRUE;
			}

			trace(TR_BRELSE, pack(bp->b_vp, bp->b_bufsize), bp->b_lblkno);

			/* Free Storage */
			buf_free_meta_store(bp);

			/* Release credentials */
			buf_release_credentials(bp);

			/* Prepare for moving to empty queue */
			CLR(bp->b_flags, (B_META | B_ZALLOC | B_DELWRI | B_LOCKED
			    | B_AGE | B_ASYNC | B_NOCACHE | B_FUA));
			bp->b_whichq = BQ_EMPTY;
			BLISTNONE(bp);
		}
		lck_mtx_lock(&buf_mtx);

		/* Back under lock, move them all to invalid hash and clear busy */
		TAILQ_FOREACH(bp, &privq, b_freelist) {
			binshash(bp, &invalhash);
			CLR(bp->b_lflags, BL_BUSY);
			buf_busycount--;

#ifdef JOE_DEBUG
			if (bp->b_owner != current_thread()) {
				panic("Buffer stolen from buffer_cache_gc()");
			}
			bp->b_owner = current_thread();
			bp->b_tag   = 13;
#endif
		}

		/* And do a big bulk move to the empty queue */
		TAILQ_CONCAT(&bufqueues[BQ_EMPTY], &privq, b_freelist);
	} while (all && (found == BUF_MAX_GC_BATCH_SIZE));

	lck_mtx_unlock(&buf_mtx);

	fs_buffer_cache_gc_dispatch_callouts(all);

	return did_large_zfree;
}


/*
 * disabled for now
 */

#if FLUSH_QUEUES

#define NFLUSH 32

static int
bp_cmp(void *a, void *b)
{
	buf_t *bp_a = *(buf_t **)a,
	    *bp_b = *(buf_t **)b;
	daddr64_t res;

	// don't have to worry about negative block
	// numbers so this is ok to do.
	//
	res = (bp_a->b_blkno - bp_b->b_blkno);

	return (int)res;
}


int
bflushq(int whichq, mount_t mp)
{
	buf_t   bp, next;
	int     i, buf_count;
	int     total_writes = 0;
	static buf_t flush_table[NFLUSH];

	if (whichq < 0 || whichq >= BQUEUES) {
		return 0;
	}

restart:
	lck_mtx_lock(&buf_mtx);

	bp = TAILQ_FIRST(&bufqueues[whichq]);

	for (buf_count = 0; bp; bp = next) {
		next = bp->b_freelist.tqe_next;

		if (bp->b_vp == NULL || bp->b_vp->v_mount != mp) {
			continue;
		}

		if (ISSET(bp->b_flags, B_DELWRI) && !ISSET(bp->b_lflags, BL_BUSY)) {
			bremfree_locked(bp);
#ifdef JOE_DEBUG
			bp->b_owner = current_thread();
			bp->b_tag   = 7;
#endif
			SET(bp->b_lflags, BL_BUSY);
			buf_busycount++;

			flush_table[buf_count] = bp;
			buf_count++;
			total_writes++;

			if (buf_count >= NFLUSH) {
				lck_mtx_unlock(&buf_mtx);

				qsort(flush_table, buf_count, sizeof(struct buf *), bp_cmp);

				for (i = 0; i < buf_count; i++) {
					buf_bawrite(flush_table[i]);
				}
				goto restart;
			}
		}
	}
	lck_mtx_unlock(&buf_mtx);

	if (buf_count > 0) {
		qsort(flush_table, buf_count, sizeof(struct buf *), bp_cmp);

		for (i = 0; i < buf_count; i++) {
			buf_bawrite(flush_table[i]);
		}
	}

	return total_writes;
}
#endif
