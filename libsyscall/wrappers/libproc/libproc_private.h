/*
 * Copyright (c) 2006, 2007, 2010 Apple Inc. All rights reserved.
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
#ifndef _LIBPROC_PRIVATE_H_
#define _LIBPROC_PRIVATE_H_

#include <libproc.h>

#if defined(PRIVATE) && \
        defined(_LIBPROC_PRIVATE_H_) /* Defeat unifdef */
#include <sys/event.h>

__BEGIN_DECLS

/*
 * Enumerate potential userspace pointers embedded in kernel data structures.
 * Currently inspects kqueues only.
 *
 * NOTE: returned "pointers" are opaque user-supplied values and thus not
 * guaranteed to address valid objects or be pointers at all.
 *
 * Returns the number of pointers found (which may exceed buffersize), or -1 on
 * failure and errno set appropriately.
 */
int proc_list_uptrs(pid_t pid, uint64_t *buffer, uint32_t buffersize);

int proc_list_dynkqueueids(int pid, kqueue_id_t *buf, uint32_t bufsz);
int proc_piddynkqueueinfo(int pid, int flavor, kqueue_id_t kq_id, void *buffer,
    int buffersize);

__END_DECLS

#endif /* PRIVATE */

#endif /* _LIBPROC_PRIVATE_H_ */
