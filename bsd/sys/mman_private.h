/*
 * Copyright (c) 2000-2025 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1993
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
 *	@(#)mman.h	8.1 (Berkeley) 6/2/93
 */

/*
 * Currently unsupported:
 *
 * [TYM]	POSIX_TYPED_MEM_ALLOCATE
 * [TYM]	POSIX_TYPED_MEM_ALLOCATE_CONTIG
 * [TYM]	POSIX_TYPED_MEM_MAP_ALLOCATABLE
 * [TYM]	struct posix_typed_mem_info
 * [TYM]	posix_mem_offset()
 * [TYM]	posix_typed_mem_get_info()
 * [TYM]	posix_typed_mem_open()
 */

#ifndef _SYS_MMAN_PRIVATE_H_
#define _SYS_MMAN_PRIVATE_H_

#include <sys/cdefs.h>

#include <sys/_types.h>

#if !defined(_POSIX_C_SOURCE) || defined(_DARWIN_C_SOURCE)

#endif  /* (!_POSIX_C_SOURCE || _DARWIN_C_SOURCE) */

/*
 * Crypt ID for decryption flow
 */
#define CRYPTID_NO_ENCRYPTION     0         /* File is unencrypted */
#define CRYPTID_APP_ENCRYPTION    1         /* App binary is encrypted */
#define CRYPTID_MODEL_ENCRYPTION  2         /* ML Model is encrypted */

/*
 * Model encryption header
 */
typedef struct {
	__uint64_t version;
	__uint64_t originalSize;
	__uint64_t reserved[4];
} model_encryption_header_t;


#ifndef KERNEL

__BEGIN_DECLS

int mremap_encrypted(void *, size_t, __uint32_t, __uint32_t, __uint32_t);

__END_DECLS

#else   /* KERNEL */
#ifdef XNU_KERNEL_PRIVATE
void pshm_cache_init(void);     /* for bsd_init() */

/*
 * XXX routine exported by posix_shm.c, but never used there, only used in
 * XXX kern_mman.c in the implementation of mmap().
 */
struct mmap_args;
struct fileproc;
int pshm_mmap(
	struct proc       *p,
	vm_map_offset_t    user_addr,
	vm_map_size_t      user_size,
	int                prot,
	int                flags,
	struct fileproc   *fp,
	off_t              file_pos,
	off_t              pageoff,
	user_addr_t       *retval);


/* Really need to overhaul struct fileops to avoid this... */
struct pshmnode;
struct stat;
int pshm_stat(struct pshmnode *pnode, void *ub, int isstat64);
struct fileproc;
int pshm_truncate(struct proc *p, struct fileproc *fp, int fd, off_t length, int32_t *retval);

#endif /* XNU_KERNEL_PRIVATE */
#endif /* KERNEL */
#endif /* !_SYS_MMAN_PRIVATE_H_ */
