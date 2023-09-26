/*
 * Copyright (c) 2004-2010 Apple Inc. All rights reserved.
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

#ifndef _KERN_SYS_KERNELTYPES_H_
#define _KERN_SYS_KERNELTYPES_H_

#include <sys/cdefs.h>
#include <sys/constrained_ctypes.h>
#include <sys/types.h>
#include <sys/_types/_mount_t.h>
#include <sys/_types/_vnode_t.h>
#include <stdint.h>

#ifdef BSD_BUILD
/* Macros(?) to clear/set/test flags. */
#define SET(t, f)       (t) |= (f)
#define CLR(t, f)       (t) &= ~(f)
#define ISSET(t, f)     ((t) & (f))
#endif


typedef int64_t daddr64_t;

#ifndef BSD_BUILD
struct buf;
typedef struct buf * buf_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct buf, buf);

struct file;
typedef struct file * file_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct file, file);

#ifndef __LP64__
struct ucred;
typedef struct ucred * ucred_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ucred, ucred);
#endif

__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct mount, mount);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vnode, vnode);

struct proc;
typedef struct proc * proc_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct proc, proc);

struct proc_ident;
typedef struct proc_ident * proc_ident_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct proc_ident, proc_ident);

struct uio;
typedef struct uio * uio_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct uio, uio);

struct vfs_context;
typedef struct vfs_context * vfs_context_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vfs_context, vfs_context);

struct vfstable;
typedef struct vfstable * vfstable_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vfstable, vfstable);

struct __ifnet;
struct __mbuf;
struct __pkthdr;
struct __socket;
struct __sockopt;
struct __ifaddr;
struct __ifmultiaddr;
struct __ifnet_filter;
struct __rtentry;
struct __if_clone;
struct __bufattr;

typedef struct __ifnet*                 ifnet_t;
typedef struct __mbuf*                  mbuf_t;
typedef struct __pkthdr*                pkthdr_t;
typedef struct __socket*                socket_t;
typedef struct __sockopt*               sockopt_t;
typedef struct __ifaddr*                ifaddr_t;
typedef struct __ifmultiaddr*   ifmultiaddr_t;
typedef struct __ifnet_filter*  interface_filter_t;
typedef struct __rtentry*               route_t;
typedef struct __if_clone*              if_clone_t;
typedef struct __bufattr*               bufattr_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __ifnet, ifnet);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __mbuf, mbuf);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __pkthdr, pkthdr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __socket, socket);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __sockopt, sockopt);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __ifaddr, ifaddr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __ifmultiaddr, ifmultiaddr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __ifnet_filter, ifnet_filter);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __rtentry, rtentry);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __if_clone, if_clone);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct __bufattr, bufattr);

#else /* BSD_BUILD */

typedef struct buf * buf_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct buf, buf);

typedef struct file * file_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct file, file);

#ifndef __LP64__
typedef struct ucred * ucred_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ucred, ucred);
#endif

#if defined(KERNEL) || !defined(_SYS_MOUNT_H_) /* also defined in mount.h */

typedef struct mount * mount_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct mount, mount);

typedef struct vnode * vnode_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vnode, vnode);
#endif
typedef struct proc * proc_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct proc, proc);

typedef struct proc_ident * proc_ident_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct proc_ident, proc_ident);

typedef struct uio * uio_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct uio, uio);

typedef struct user_iovec * user_iovec_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct user_iovec, user_iovec);

typedef struct vfs_context * vfs_context_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vfs_context, vfs_context);

typedef struct vfstable * vfstable_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct vfstable, vfstable);

#ifdef KERNEL_PRIVATE
typedef struct kern_iovec * kern_iovec_t;
typedef struct ifnet*           ifnet_t;
typedef struct mbuf*            mbuf_t;
typedef struct pkthdr*          pkthdr_t;
typedef struct socket*          socket_t;
typedef struct sockopt*         sockopt_t;
typedef struct ifaddr*          ifaddr_t;
typedef struct ifmultiaddr*     ifmultiaddr_t;
typedef struct ifnet_filter*    interface_filter_t;
typedef struct rtentry*         route_t;
typedef struct if_clone*        if_clone_t;
typedef struct bufattr*         bufattr_t;
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct kern_iovec, kern_iovec);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ifnet, ifnet);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct mbuf, mbuf);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct pkthdr, pkthdr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct socket, socket);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct sockopt, sockopt);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ifaddr, ifaddr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ifmultiaddr, ifmultiaddr);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct ifnet_filter, ifnet_filter);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct rtentry, rtentry);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct if_clone, if_clone);
__CCT_DECLARE_CONSTRAINED_PTR_TYPES(struct bufattr, bufattr);

#endif /* KERNEL_PRIVATE */

#endif /* !BSD_BUILD */

#include <sys/_types/_guid_t.h>

#ifndef _KAUTH_ACE
#define _KAUTH_ACE
struct kauth_ace;
typedef struct kauth_ace * kauth_ace_t;
#endif
#ifndef _KAUTH_ACL
#define _KAUTH_ACL
struct kauth_acl;
typedef struct kauth_acl * kauth_acl_t;
#endif
#ifndef _KAUTH_FILESEC
#define _KAUTH_FILESEC
struct kauth_filesec;
typedef struct kauth_filesec * kauth_filesec_t;
#endif

#ifndef _KAUTH_ACTION_T
#define _KAUTH_ACTION_T
typedef int kauth_action_t;
#endif

#endif /* !_KERN_SYS_KERNELTYPES_H_ */
