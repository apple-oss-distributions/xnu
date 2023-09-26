/*
 * Copyright (c) 2003-2021 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1999,2000,2001 Jonathan Lemon <jlemon@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/sys/sys/event.h,v 1.5.2.5 2001/12/14 19:21:22 jlemon Exp $
 */

#ifndef _SYS_EVENT_PRIVATE_H_
#define _SYS_EVENT_PRIVATE_H_

#include <machine/types.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/event.h>
#include <sys/queue.h>
#ifndef KERNEL_PRIVATE
#include <sys/types.h>
#endif
#ifdef XNU_KERNEL_PRIVATE
#include <kern/debug.h> /* panic */
#include <kern/kern_types.h>
#include <mach/vm_param.h>
#include <pthread/priority_private.h>
#include <sys/fcntl.h> /* FREAD, FWRITE */
#endif /* XNU_KERNEL_PRIVATE */

/*
 * Filter types
 */
/* Additional filter types in event.h */
#define EVFILT_UNUSED_11        (-11)   /* (-11) unused */
#define EVFILT_SOCK             (-13)   /* Socket events */
#define EVFILT_MEMORYSTATUS     (-14)   /* Memorystatus events */
#define EVFILT_NW_CHANNEL       (-16)   /* Skywalk channel events */
#define EVFILT_WORKLOOP         (-17)   /* Workloop events */
/* If additional filter types are added, make sure to update
 * EVFILT_SYSCOUNT in event.h!!!
 */

#ifdef KERNEL_PRIVATE

#pragma pack(4)

struct user64_kevent {
	uint64_t        ident;  /* identifier for this event */
	int16_t         filter; /* filter for event */
	uint16_t        flags;  /* general flags */
	uint32_t        fflags; /* filter-specific flags */
	int64_t         data;   /* filter-specific data */
	user_addr_t     udata;  /* opaque user data identifier */
};

struct user32_kevent {
	uint32_t        ident;  /* identifier for this event */
	int16_t         filter; /* filter for event */
	uint16_t        flags;  /* general flags */
	uint32_t        fflags; /* filter-specific flags */
	int32_t         data;   /* filter-specific data */
	user32_addr_t   udata;  /* opaque user data identifier */
};

#pragma pack()

#endif /* KERNEL_PRIVATE */

struct kevent_qos_s {
	uint64_t        ident;          /* identifier for this event */
	int16_t         filter;         /* filter for event */
	uint16_t        flags;          /* general flags */
	int32_t         qos;            /* quality of service */
	uint64_t        udata;          /* opaque user data identifier */
	uint32_t        fflags;         /* filter-specific flags */
	uint32_t        xflags;         /* extra filter-specific flags */
	int64_t         data;           /* filter-specific data */
	uint64_t        ext[4];         /* filter-specific extensions */
};

/*
 * Type definition for names/ids of dynamically allocated kqueues.
 */
typedef uint64_t kqueue_id_t;

/*
 * Rather than provide an EV_SET_QOS macro for kevent_qos_t structure
 * initialization, we encourage use of named field initialization support
 * instead.
 */

// was  KEVENT_FLAG_STACK_EVENTS                 0x000004
#define KEVENT_FLAG_STACK_DATA                   0x000008   /* output data allocated as stack (grows down) */
//      KEVENT_FLAG_POLL                         0x000010
#define KEVENT_FLAG_WORKQ                        0x000020   /* interact with the default workq kq */
//      KEVENT_FLAG_LEGACY32                     0x000040
//      KEVENT_FLAG_LEGACY64                     0x000080
//      KEVENT_FLAG_PROC64                       0x000100
#define KEVENT_FLAG_WORKQ_MANAGER                0x000200   /* obsolete */
#define KEVENT_FLAG_WORKLOOP                     0x000400   /* interact with the specified workloop kq */
#define KEVENT_FLAG_PARKING                      0x000800   /* workq thread is parking */
//      KEVENT_FLAG_KERNEL                       0x001000
//      KEVENT_FLAG_DYNAMIC_KQUEUE               0x002000
//      KEVENT_FLAG_NEEDS_END_PROCESSING         0x004000
#define KEVENT_FLAG_WORKLOOP_SERVICER_ATTACH     0x008000   /* obsolete */
#define KEVENT_FLAG_WORKLOOP_SERVICER_DETACH     0x010000   /* obsolete */
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST        0x020000   /* kq lookup by id must exist */
#define KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST    0x040000   /* kq lookup by id must not exist */
#define KEVENT_FLAG_WORKLOOP_NO_WQ_THREAD        0x080000   /* obsolete */

#ifdef XNU_KERNEL_PRIVATE

#define KEVENT_FLAG_POLL                         0x0010  /* Call is for poll() */
#define KEVENT_FLAG_LEGACY32                     0x0040  /* event data in legacy 32-bit format */
#define KEVENT_FLAG_LEGACY64                     0x0080  /* event data in legacy 64-bit format */
#define KEVENT_FLAG_PROC64                       0x0100  /* proc is 64bits */
#define KEVENT_FLAG_KERNEL                       0x1000  /* caller is in-kernel */
#define KEVENT_FLAG_DYNAMIC_KQUEUE               0x2000  /* kqueue is dynamically allocated */
#define KEVENT_FLAG_NEEDS_END_PROCESSING         0x4000  /* end processing required before returning */

#define KEVENT_ID_FLAG_USER (KEVENT_FLAG_WORKLOOP | \
	        KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST | KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST)

#define KEVENT_FLAG_USER (KEVENT_FLAG_IMMEDIATE | KEVENT_FLAG_ERROR_EVENTS | \
	        KEVENT_FLAG_STACK_DATA | KEVENT_FLAG_WORKQ | KEVENT_FLAG_WORKLOOP | \
	        KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST | KEVENT_FLAG_DYNAMIC_KQ_MUST_NOT_EXIST)

/*
 * Since some filter ops are not part of the standard sysfilt_ops, we use
 * kn_filtid starting from EVFILT_SYSCOUNT to identify these cases.  This is to
 * let kn_fops() get the correct fops for all cases.
 */
#define EVFILTID_KQREAD            (EVFILT_SYSCOUNT)
#define EVFILTID_PIPE_N            (EVFILT_SYSCOUNT + 1)
#define EVFILTID_PIPE_R            (EVFILT_SYSCOUNT + 2)
#define EVFILTID_PIPE_W            (EVFILT_SYSCOUNT + 3)
#define EVFILTID_PTSD              (EVFILT_SYSCOUNT + 4)
#define EVFILTID_SOREAD            (EVFILT_SYSCOUNT + 5)
#define EVFILTID_SOWRITE           (EVFILT_SYSCOUNT + 6)
#define EVFILTID_SCK               (EVFILT_SYSCOUNT + 7)
#define EVFILTID_SOEXCEPT          (EVFILT_SYSCOUNT + 8)
#define EVFILTID_SPEC              (EVFILT_SYSCOUNT + 9)
#define EVFILTID_BPFREAD           (EVFILT_SYSCOUNT + 10)
#define EVFILTID_NECP_FD           (EVFILT_SYSCOUNT + 11)
#define EVFILTID_SKYWALK_CHANNEL_W (EVFILT_SYSCOUNT + 12)
#define EVFILTID_SKYWALK_CHANNEL_R (EVFILT_SYSCOUNT + 13)
#define EVFILTID_SKYWALK_CHANNEL_E (EVFILT_SYSCOUNT + 14)
#define EVFILTID_FSEVENT           (EVFILT_SYSCOUNT + 15)
#define EVFILTID_VN                (EVFILT_SYSCOUNT + 16)
#define EVFILTID_TTY               (EVFILT_SYSCOUNT + 17)
#define EVFILTID_PTMX              (EVFILT_SYSCOUNT + 18)

#define EVFILTID_DETACHED          (EVFILT_SYSCOUNT + 19)
#define EVFILTID_MAX               (EVFILT_SYSCOUNT + 20)

#endif /* defined(XNU_KERNEL_PRIVATE) */

#define EV_SET_QOS 0

/*
 * data/hint fflags for EVFILT_WORKLOOP, shared with userspace
 *
 * The ident for thread requests should be the dynamic ID of the workloop
 * The ident for each sync waiter must be unique to that waiter [for this workloop]
 *
 *
 * Commands:
 *
 * @const NOTE_WL_THREAD_REQUEST [in/out]
 * The kevent represents asynchronous userspace work and its associated QoS.
 * There can only be a single knote with this flag set per workloop.
 *
 * @const NOTE_WL_SYNC_WAIT [in/out]
 * This bit is set when the caller is waiting to become the owner of a workloop.
 * If the NOTE_WL_SYNC_WAKE bit is already set then the caller is not blocked,
 * else it blocks until it is set.
 *
 * The QoS field of the knote is used to push on other owners or servicers.
 *
 * @const NOTE_WL_SYNC_WAKE [in/out]
 * Marks the waiter knote as being eligible to become an owner
 * This bit can only be set once, trying it again will fail with EALREADY.
 *
 * @const NOTE_WL_SYNC_IPC [in/out]
 * The knote is a sync IPC redirected turnstile push.
 *
 * Flags/Modifiers:
 *
 * @const NOTE_WL_UPDATE_QOS [in] (only NOTE_WL_THREAD_REQUEST)
 * For successful updates (EV_ADD only), learn the new userspace async QoS from
 * the kevent qos field.
 *
 * @const NOTE_WL_END_OWNERSHIP [in]
 * If the update is successful (including deletions) or returns ESTALE, and
 * the caller thread or the "suspended" thread is currently owning the workloop,
 * then ownership is forgotten.
 *
 * @const NOTE_WL_DISCOVER_OWNER [in]
 * If the update is successful (including deletions), learn the owner identity
 * from the loaded value during debounce. This requires an address to have been
 * filled in the EV_EXTIDX_WL_ADDR ext field, but doesn't require a mask to have
 * been set in the EV_EXTIDX_WL_MASK.
 *
 * @const NOTE_WL_IGNORE_ESTALE [in]
 * If the operation would fail with ESTALE, mask the error and pretend the
 * update was successful. However the operation itself didn't happen, meaning
 * that:
 * - attaching a new knote will not happen
 * - dropping an existing knote will not happen
 * - NOTE_WL_UPDATE_QOS or NOTE_WL_DISCOVER_OWNER will have no effect
 *
 * This modifier doesn't affect NOTE_WL_END_OWNERSHIP.
 */
#define NOTE_WL_THREAD_REQUEST   0x00000001
#define NOTE_WL_SYNC_WAIT        0x00000004
#define NOTE_WL_SYNC_WAKE        0x00000008
#define NOTE_WL_SYNC_IPC         0x80000000
#define NOTE_WL_COMMANDS_MASK    0x8000000f /* Mask of all the [in] commands above */

#define NOTE_WL_UPDATE_QOS       0x00000010
#define NOTE_WL_END_OWNERSHIP    0x00000020
#define NOTE_WL_DISCOVER_OWNER   0x00000080
#define NOTE_WL_IGNORE_ESTALE    0x00000100
#define NOTE_WL_UPDATES_MASK     0x000001f0 /* Mask of all the [in] updates above */

#define NOTE_WL_UPDATE_OWNER     0 /* ... compatibility define ... */

/*
 * EVFILT_WORKLOOP ext[] array indexes/meanings.
 */
#define EV_EXTIDX_WL_LANE        0         /* lane identifier  [in: sync waiter]
	                                    *                  [out: thread request]     */
#define EV_EXTIDX_WL_ADDR        1         /* debounce address [in: NULL==no debounce]   */
#define EV_EXTIDX_WL_MASK        2         /* debounce mask    [in]                      */
#define EV_EXTIDX_WL_VALUE       3         /* debounce value   [in: not current->ESTALE]
	                                    *                  [out: new/debounce value] */

/*
 * If NOTE_EXIT_MEMORY is present, these bits indicate specific jetsam condition.
 */
#define NOTE_EXIT_MEMORY_DETAIL_MASK    0xfe000000
#define NOTE_EXIT_MEMORY_VMPAGESHORTAGE 0x80000000      /* jetsam condition: lowest jetsam priority proc killed due to vm page shortage */
#define NOTE_EXIT_MEMORY_VMTHRASHING    0x40000000      /* jetsam condition: lowest jetsam priority proc killed due to vm thrashing */
#define NOTE_EXIT_MEMORY_HIWAT          0x20000000      /* jetsam condition: process reached its high water mark */
#define NOTE_EXIT_MEMORY_PID            0x10000000      /* jetsam condition: special pid kill requested */
#define NOTE_EXIT_MEMORY_IDLE           0x08000000      /* jetsam condition: idle process cleaned up */
#define NOTE_EXIT_MEMORY_VNODE          0X04000000      /* jetsam condition: virtual node kill */
#define NOTE_EXIT_MEMORY_FCTHRASHING    0x02000000      /* jetsam condition: lowest jetsam priority proc killed due to filecache thrashing */

/*
 * data/hint fflags for EVFILT_MEMORYSTATUS, shared with userspace.
 */
#define NOTE_MEMORYSTATUS_PRESSURE_NORMAL       0x00000001      /* system memory pressure has returned to normal */
#define NOTE_MEMORYSTATUS_PRESSURE_WARN         0x00000002      /* system memory pressure has changed to the warning state */
#define NOTE_MEMORYSTATUS_PRESSURE_CRITICAL     0x00000004      /* system memory pressure has changed to the critical state */
#define NOTE_MEMORYSTATUS_LOW_SWAP              0x00000008      /* system is in a low-swap state */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_WARN       0x00000010      /* process memory limit has hit a warning state */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL   0x00000020      /* process memory limit has hit a critical state - soft limit */
#define NOTE_MEMORYSTATUS_MSL_STATUS   0xf0000000      /* bits used to request change to process MSL status */

#ifdef KERNEL_PRIVATE
/*
 * data/hint fflags for EVFILT_MEMORYSTATUS, but not shared with userspace.
 */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_WARN_ACTIVE        0x00000040      /* Used to restrict sending a warn event only once, per active limit, soft limits only */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_WARN_INACTIVE      0x00000080      /* Used to restrict sending a warn event only once, per inactive limit, soft limit only */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL_ACTIVE    0x00000100      /* Used to restrict sending a critical event only once per active limit, soft limit only */
#define NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL_INACTIVE  0x00000200      /* Used to restrict sending a critical event only once per inactive limit, soft limit only */
#define NOTE_MEMORYSTATUS_JETSAM_FG_BAND                0x00000400      /* jetsam is approaching foreground band */

/*
 * Use this mask to protect the kernel private flags.
 */
#define EVFILT_MEMORYSTATUS_ALL_MASK \
	(NOTE_MEMORYSTATUS_PRESSURE_NORMAL | NOTE_MEMORYSTATUS_PRESSURE_WARN | NOTE_MEMORYSTATUS_PRESSURE_CRITICAL | NOTE_MEMORYSTATUS_LOW_SWAP | \
	 NOTE_MEMORYSTATUS_PROC_LIMIT_WARN | NOTE_MEMORYSTATUS_PROC_LIMIT_CRITICAL | NOTE_MEMORYSTATUS_MSL_STATUS)

#endif /* KERNEL_PRIVATE */

typedef enum vm_pressure_level {
	kVMPressureNormal   = 0,
	kVMPressureWarning  = 1,
	kVMPressureUrgent   = 2,
	kVMPressureCritical = 3,
	kVMPressureJetsam   = 4,  /* jetsam approaching FG bands */
} vm_pressure_level_t;

/*
 * data/hint fflags for EVFILT_SOCK, shared with userspace.
 *
 */
#define NOTE_CONNRESET          0x00000001 /* Received RST */
#define NOTE_READCLOSED         0x00000002 /* Read side is shutdown */
#define NOTE_WRITECLOSED        0x00000004 /* Write side is shutdown */
#define NOTE_TIMEOUT            0x00000008 /* timeout: rexmt, keep-alive or persist */
#define NOTE_NOSRCADDR          0x00000010 /* source address not available */
#define NOTE_IFDENIED           0x00000020 /* interface denied connection */
#define NOTE_SUSPEND            0x00000040 /* output queue suspended */
#define NOTE_RESUME             0x00000080 /* output queue resumed */
#define NOTE_KEEPALIVE          0x00000100 /* TCP Keepalive received */
#define NOTE_ADAPTIVE_WTIMO     0x00000200 /* TCP adaptive write timeout */
#define NOTE_ADAPTIVE_RTIMO     0x00000400 /* TCP adaptive read timeout */
#define NOTE_CONNECTED          0x00000800 /* socket is connected */
#define NOTE_DISCONNECTED       0x00001000 /* socket is disconnected */
#define NOTE_CONNINFO_UPDATED   0x00002000 /* connection info was updated */
#define NOTE_NOTIFY_ACK         0x00004000 /* notify acknowledgement */
#define NOTE_WAKE_PKT           0x00008000 /* received wake packet */

#define EVFILT_SOCK_LEVEL_TRIGGER_MASK \
	        (NOTE_READCLOSED | NOTE_WRITECLOSED | NOTE_SUSPEND | NOTE_RESUME | \
	         NOTE_CONNECTED | NOTE_DISCONNECTED)

#define EVFILT_SOCK_ALL_MASK \
	        (NOTE_CONNRESET | NOTE_READCLOSED | NOTE_WRITECLOSED | NOTE_TIMEOUT | \
	        NOTE_NOSRCADDR | NOTE_IFDENIED | NOTE_SUSPEND | NOTE_RESUME | \
	        NOTE_KEEPALIVE | NOTE_ADAPTIVE_WTIMO | NOTE_ADAPTIVE_RTIMO | \
	        NOTE_CONNECTED | NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED | \
	        NOTE_NOTIFY_ACK | NOTE_WAKE_PKT)

/*
 * data/hint fflags for EVFILT_NW_CHANNEL, shared with userspace.
 */
#define NOTE_FLOW_ADV_UPDATE    0x00000001 /* flow advisory update */
#define NOTE_CHANNEL_EVENT      0x00000002 /* generic channel event */
#define NOTE_IF_ADV_UPD         0x00000004 /* Interface advisory update */

#define EVFILT_NW_CHANNEL_ALL_MASK    \
    (NOTE_FLOW_ADV_UPDATE | NOTE_CHANNEL_EVENT | NOTE_IF_ADV_UPD)

#ifdef KERNEL_PRIVATE

#ifdef XNU_KERNEL_PRIVATE
LIST_HEAD(knote_list, knote);
TAILQ_HEAD(kqtailq, knote);     /* a list of "queued" events */

/* index into various kq queues */
typedef uint8_t kq_index_t;

/* lskq(1) knows about this type */
__options_decl(kn_status_t, uint16_t /* 12 bits really */, {
	KN_ACTIVE         = 0x001,  /* event has been triggered */
	KN_QUEUED         = 0x002,  /* event is on queue */
	KN_DISABLED       = 0x004,  /* event is disabled */
	KN_DROPPING       = 0x008,  /* knote is being dropped */
	KN_LOCKED         = 0x010,  /* knote is locked (kq_knlocks) */
	KN_POSTING        = 0x020,  /* f_event() in flight */
	// was KN_STAYACTIVE  = 0x040,
	KN_DEFERDELETE    = 0x080,  /* defer delete until re-enabled */
	KN_MERGE_QOS      = 0x100,  /* f_event() / f_* ran concurrently and overrides must merge */
	KN_REQVANISH      = 0x200,  /* requested EV_VANISH */
	KN_VANISHED       = 0x400,  /* has vanished */
	KN_SUPPRESSED     = 0x800,  /* event is suppressed during delivery */
});

#if __LP64__
#define KNOTE_KQ_PACKED_BITS   42
#define KNOTE_KQ_PACKED_SHIFT   0
#define KNOTE_KQ_PACKED_BASE    0
#else
#define KNOTE_KQ_PACKED_BITS   32
#define KNOTE_KQ_PACKED_SHIFT   0
#define KNOTE_KQ_PACKED_BASE    0
#endif

_Static_assert(!VM_PACKING_IS_BASE_RELATIVE(KNOTE_KQ_PACKED),
    "Make sure the knote pointer packing is based on arithmetic shifts");

struct kqueue;
struct knote {
	TAILQ_ENTRY(knote)       kn_tqe;            /* linkage for tail queue */
	SLIST_ENTRY(knote)       kn_link;           /* linkage for fd search list */
	SLIST_ENTRY(knote)       kn_selnext;        /* klist element chain */
#define KNOTE_AUTODETACHED ((struct knote *) -1)
#define KNOTE_IS_AUTODETACHED(kn) ((kn)->kn_selnext.sle_next == KNOTE_AUTODETACHED)

	kn_status_t              kn_status : 12;
	uintptr_t
	    kn_qos_index:4,                         /* in-use qos index */
	    kn_qos_override:3,                      /* qos override index */
	    kn_is_fd:1,                             /* knote is an fd */
	    kn_vnode_kqok:1,
	    kn_vnode_use_ofst:1;
#if __LP64__
	uintptr_t                   kn_kq_packed : KNOTE_KQ_PACKED_BITS;
#else
	uintptr_t                   kn_kq_packed;
#endif

	/* per filter stash of data (pointer, uint32_t or uint64_t) */
	union {
		uintptr_t           kn_hook; /* Manually PAC-ed, see knote_kn_hook_get_raw() */
		uint32_t            kn_hook32;
	};

	/* per filter pointer to the resource being watched */
	union {
		struct fileproc    *XNU_PTRAUTH_SIGNED_PTR("knote.fp") kn_fp;
		struct proc        *XNU_PTRAUTH_SIGNED_PTR("knote.proc") kn_proc;
		struct ipc_object  *XNU_PTRAUTH_SIGNED_PTR("knote.ipc_obj") kn_ipc_obj;
		struct thread_call *XNU_PTRAUTH_SIGNED_PTR("knote.thcall") kn_thcall;
		struct thread      *XNU_PTRAUTH_SIGNED_PTR("knote.thread") kn_thread;
	};

	/*
	 * Mimic kevent_qos so that knote_fill_kevent code is not horrid,
	 * but with subtleties:
	 *
	 * - kevent_qos_s::filter is 16bits where ours is 8, and we use the top
	 *   bits to store the real specialized filter.
	 *   knote_fill_kevent* will always force the top bits to 0xff.
	 *
	 * - kevent_qos_s::xflags is not kept, kn_sfflags takes its place,
	 *   knote_fill_kevent* will set xflags to 0.
	 *
	 * - kevent_qos_s::data is saved as kn_sdata and filters are encouraged
	 *   to use knote_fill_kevent, knote_fill_kevent_with_sdata will copy
	 *   kn_sdata as the output value.
	 *
	 * knote_fill_kevent_with_sdata() programatically asserts
	 * these aliasings are respected.
	 */
	struct kevent_internal_s {
		uint64_t    kei_ident;      /* identifier for this event */
#ifdef __LITTLE_ENDIAN__
		int8_t      kei_filter;     /* filter for event */
		uint8_t     kei_filtid;     /* actual filter for event */
#else
		uint8_t     kei_filtid;     /* actual filter for event */
		int8_t      kei_filter;     /* filter for event */
#endif
		uint16_t    kei_flags;      /* general flags */
		int32_t     kei_qos;        /* quality of service */
		uint64_t    kei_udata;      /* opaque user data identifier */
		uint32_t    kei_fflags;     /* filter-specific flags */
		uint32_t    kei_sfflags;    /* knote: saved fflags */
		int64_t     kei_sdata;      /* knote: filter-specific saved data */
		uint64_t    kei_ext[4];     /* filter-specific extensions */
	} kn_kevent;

#define kn_id           kn_kevent.kei_ident
#define kn_filtid       kn_kevent.kei_filtid
#define kn_filter       kn_kevent.kei_filter
#define kn_flags        kn_kevent.kei_flags
#define kn_qos          kn_kevent.kei_qos
#define kn_udata        kn_kevent.kei_udata
#define kn_fflags       kn_kevent.kei_fflags
#define kn_sfflags      kn_kevent.kei_sfflags
#define kn_sdata        kn_kevent.kei_sdata
#define kn_ext          kn_kevent.kei_ext
};

static inline struct kqueue *
knote_get_kq(struct knote *kn)
{
	vm_offset_t ptr = VM_UNPACK_POINTER(kn->kn_kq_packed, KNOTE_KQ_PACKED);
	return __unsafe_forge_single(struct kqueue *, ptr);
}

static inline int
knote_get_seltype(struct knote *kn)
{
	switch (kn->kn_filter) {
	case EVFILT_READ:
		return FREAD;
	case EVFILT_WRITE:
		return FWRITE;
	default:
		panic("%s(%p): invalid filter %d\n",
		    __func__, kn, kn->kn_filter);
		return 0;
	}
}

struct kevent_ctx_s {
	uint64_t         kec_data_avail;    /* address of remaining data size */
	union {
		user_addr_t    kec_data_out;      /* extra data pointer */
		struct pollfd *kec_poll_fds;      /* poll fds */
	};
	user_size_t      kec_data_size;     /* total extra data size */
	user_size_t      kec_data_resid;    /* residual extra data size */
	uint64_t         kec_deadline;      /* wait deadline unless KEVENT_FLAG_IMMEDIATE */
	struct fileproc *kec_fp;            /* fileproc to pass to fp_drop or NULL */
	int              kec_fd;            /* fd to pass to fp_drop or -1 */

	/* the fields below are only set during process / scan */
	int              kec_process_nevents;       /* user-level event count */
	int              kec_process_noutputs;      /* number of events output */
	unsigned int     kec_process_flags;         /* kevent flags, only set for process  */
	user_addr_t      kec_process_eventlist;     /* user-level event list address */
};
typedef struct kevent_ctx_s *kevent_ctx_t;

kevent_ctx_t
kevent_get_context(thread_t thread);

/*
 * Filter operators
 *
 * These routines, provided by each filter, are called to attach, detach, deliver events,
 * change/update filter registration and process/deliver events:
 *
 * - the f_attach, f_touch, f_process and f_detach callbacks are always
 *   serialized with respect to each other for the same knote.
 *
 * - the f_event routine is called with a use-count taken on the knote to
 *   prolongate its lifetime and protect against drop, but is not otherwise
 *   serialized with other routine calls.
 *
 * - the f_detach routine is always called last, and is serialized with all
 *   other callbacks, including f_event calls.
 *
 *
 * Here are more details:
 *
 * f_isfd -
 *        identifies if the "ident" field in the kevent structure is a file-descriptor.
 *
 *        If so, the knote is associated with the file descriptor prior to attach and
 *        auto-removed when the file descriptor is closed (this latter behavior may change
 *        for EV_DISPATCH2 kevent types to allow delivery of events identifying unintended
 *        closes).
 *
 *        Otherwise the knote is hashed by the ident and has no auto-close behavior.
 *
 * f_adjusts_qos -
 *        identifies if the filter can adjust its QoS during its lifetime.
 *
 *        Filters using this facility should request the new overrides they want
 *        using the appropriate FILTER_{RESET,ADJUST}_EVENT_QOS extended codes.
 *
 *        Currently, EVFILT_MACHPORT is the only filter using this facility.
 *
 * f_extended_codes -
 *        identifies if the filter returns extended codes from its routines
 *        (see FILTER_ACTIVE, ...) or 0 / 1 values.
 *
 * f_attach -
 *        called to attach the knote to the underlying object that will be delivering events
 *        through it when EV_ADD is supplied and no existing matching event is found
 *
 *        provided a knote that is pre-attached to the fd or hashed (see above) but is
 *        specially marked to avoid concurrent access until the attach is complete. The
 *        kevent structure embedded in this knote has been filled in with a sanitized
 *        version of the user-supplied kevent data.  However, the user-supplied filter-specific
 *        flags (fflags) and data fields have been moved into the knote's kn_sfflags and kn_sdata
 *        fields respectively.  These are usually interpretted as a set of "interest" flags and
 *        data by each filter - to be matched against delivered events.
 *
 *        The attach operator indicated errors by setting the EV_ERROR flog in the flags field
 *        embedded in the knote's kevent structure - with the specific error indicated in the
 *        corresponding data field.
 *
 *        The return value indicates if the knote should already be considered "activated" at
 *        the time of attach (one or more of the interest events has already occured).
 *
 * f_detach -
 *        called to disassociate the knote from the underlying object delivering events
 *        the filter should not attempt to deliver events through this knote after this
 *        operation returns control to the kq system.
 *
 * f_event -
 *        if the knote() function (or KNOTE() macro) is called against a list of knotes,
 *        this operator will be called on each knote in the list.
 *
 *        The "hint" parameter is completely filter-specific, but usually indicates an
 *        event or set of events that have occured against the source object associated
 *        with the list.
 *
 *        The return value indicates if the knote should already be considered "activated" at
 *        the time of attach (one or more of the interest events has already occured).
 *
 * f_process -
 *        called when attempting to deliver triggered events to user-space.
 *
 *        If the knote was previously activated, this operator will be called when a
 *        thread is trying to deliver events to user-space.  The filter gets one last
 *        chance to determine if the event/events are still interesting for this knote
 *        (are the conditions still right to deliver an event).  If so, the filter
 *        fills in the output kevent structure with the information to be delivered.
 *
 *        The input context/data parameter is used during event delivery.  Some
 *        filters allow additional data delivery as part of event delivery.  This
 *        context field indicates if space was made available for these additional
 *        items and how that space is to be allocated/carved-out.
 *
 *        The filter may set EV_CLEAR or EV_ONESHOT in the output flags field to indicate
 *        special post-delivery dispositions for the knote.
 *
 *        EV_CLEAR - indicates that all matching events have been delivered. Even
 *                   though there were events to deliver now, there will not be any
 *                   more until some additional events are delivered to the knote
 *                   via the f_event operator, or the interest set is changed via
 *                   the f_touch operator.  The knote can remain deactivated after
 *                   processing this event delivery.
 *
 *        EV_ONESHOT - indicates that this is the last event to be delivered via
 *                   this knote.  It will automatically be deleted upon delivery
 *                   (or if in dispatch-mode, upon re-enablement after this delivery).
 *
 *        The return value indicates if the knote has delivered an output event.
 *        Unless one of the special output flags was set in the output kevent, a non-
 *        zero return value ALSO indicates that the knote should be re-activated
 *        for future event processing (in case it delivers level-based or a multi-edge
 *        type events like message queues that already exist).
 *
 *        NOTE: In the future, the boolean may change to an enum that allows more
 *              explicit indication of just delivering a current event vs delivering
 *              an event with more events still pending.
 *
 * f_touch -
 *        called to update the knote with new state from the user during
 *        EVFILT_ADD/ENABLE/DISABLE on an already-attached knote.
 *
 *        f_touch should copy relevant new data from the kevent into the knote.
 *
 *        operator must lock against concurrent f_event operations.
 *
 *        A return value of 1 indicates that the knote should now be considered
 *        'activated'.
 *
 *        f_touch can set EV_ERROR with specific error in the data field to
 *        return an error to the client. You should return 1 to indicate that
 *        the kevent needs to be activated and processed.
 *
 * f_allow_drop -
 *
 *        [OPTIONAL] If this function is non-null, then it indicates that the
 *        filter wants to validate EV_DELETE events. This is necessary if
 *        a particular filter needs to synchronize knote deletion with its own
 *        filter lock.
 *
 *        When true is returned, the the EV_DELETE is allowed and can proceed.
 *
 *        If false is returned, the EV_DELETE doesn't proceed, and the passed in
 *        kevent is used for the copyout to userspace.
 *
 *        Currently, EVFILT_WORKLOOP is the only filter using this facility.
 *
 * f_post_register_wait -
 *        [OPTIONAL] called when attach or touch return the FILTER_REGISTER_WAIT
 *        extended code bit. It is possible to use this facility when the last
 *        register command wants to wait.
 *
 *        Currently, EVFILT_WORKLOOP is the only filter using this facility.
 *
 * f_sanitized_copyout -
 *        [OPTIONAL] If this function is non-null, then it should be used so
 *        that the filter can provide a sanitized copy of the current contents
 *        of a knote to userspace. This prevents leaking of any sensitive
 *        information like kernel pointers which might be stashed in filter
 *        specific data.
 *
 *        Currently, EVFILT_MACHPORT uses this facility.
 */

struct _kevent_register;
struct knote_lock_ctx;
struct proc;
struct uthread;
struct waitq;
struct thread_group;

struct filterops {
	bool    f_isfd;               /* true if ident == filedescriptor */
	bool    f_adjusts_qos;    /* true if the filter can override the knote */
	bool    f_extended_codes; /* hooks return extended codes */

	int     (*f_attach)(struct knote *kn, struct kevent_qos_s *kev);
	void    (*f_detach)(struct knote *kn);
	int     (*f_event)(struct knote *kn, long hint);
	int     (*f_touch)(struct knote *kn, struct kevent_qos_s *kev);
	int     (*f_process)(struct knote *kn, struct kevent_qos_s *kev);

	/* optional & advanced */
	bool    (*f_allow_drop)(struct knote *kn, struct kevent_qos_s *kev);
	void    (*f_post_register_wait)(struct uthread *uth, struct knote *kn,
	    struct _kevent_register *ss_kr);
	void    (*f_sanitized_copyout)(struct knote *kn, struct kevent_qos_s *kev);
};

/*
 * Extended codes returned by filter routines when f_extended_codes is set.
 *
 * FILTER_ACTIVE
 *     The filter is active and a call to f_process() may return an event.
 *
 *     For f_process() the meaning is slightly different: the knote will be
 *     activated again as long as f_process returns FILTER_ACTIVE, unless
 *     EV_CLEAR is set, which require a new f_event to reactivate the knote.
 *
 *     Valid:    f_attach, f_event, f_touch, f_process
 *     Implicit: -
 *     Ignored:  -
 *
 * FILTER_REGISTER_WAIT
 *     The filter wants its f_post_register_wait() to be called.
 *
 *     Note: It is only valid to ask for this behavior for a workloop kqueue,
 *     and is really only meant to be used by EVFILT_WORKLOOP.
 *
 *     Valid:    f_attach, f_touch
 *     Implicit: -
 *     Ignored:  f_event, f_process
 *
 * FILTER_UPDATE_REQ_QOS
 *     The filter wants the passed in QoS to be updated as the new intrinsic qos
 *     for this knote. If the kevent `qos` field is 0, no update is performed.
 *
 *     This also will reset the event QoS, so FILTER_ADJUST_EVENT_QOS() must
 *     also be used if an override should be maintained.
 *
 *     Note: when this is used in f_touch, the incoming qos validation
 *           is under the responsiblity of the filter.
 *
 *     Valid:    f_touch
 *     Implicit: f_attach
 *     Ignored:  f_event, f_process
 *
 * FILTER_RESET_EVENT_QOS
 * FILTER_ADJUST_EVENT_QOS(qos)
 *     The filter wants the QoS of the next event delivery to be overridden
 *     at the specified QoS.  This allows for the next event QoS to be elevated
 *     from the knote requested qos (See FILTER_UPDATE_REQ_QOS).
 *
 *     Event QoS Overrides are reset when a particular knote is no longer
 *     active. Hence this is ignored if FILTER_ACTIVE isn't also returned.
 *
 *     Races between an f_event() and any other f_* routine asking for
 *     a specific QoS override are handled generically and the filters do not
 *     have to worry about them.
 *
 *     To use this facility, filters MUST set their f_adjusts_qos bit to true.
 *
 *     It is expected that filters will return the new QoS they expect to be
 *     applied from any f_* callback except for f_process() where no specific
 *     information should be provided. Filters should not try to hide no-ops,
 *     kevent will already optimize these away.
 *
 *     Valid:    f_touch, f_attach, f_event, f_process
 *     Implicit: -
 *     Ignored:  -
 *
 * FILTER_THREADREQ_NODEFEER
 *     The filter has moved a turnstile priority push away from the current
 *     thread, preemption has been disabled, and thread requests need to be
 *     commited before preemption is re-enabled.
 *
 *
 *     Valid:    f_attach, f_touch
 *     Implicit: -
 *     Invalid:  f_event, f_process
 */
#define FILTER_ACTIVE                       0x00000001
#define FILTER_REGISTER_WAIT                0x00000002
#define FILTER_UPDATE_REQ_QOS               0x00000004
#define FILTER_ADJUST_EVENT_QOS_BIT         0x00000008
#define FILTER_ADJUST_EVENT_QOS_MASK        0x00000070
#define FILTER_ADJUST_EVENT_QOS_SHIFT 4
#define FILTER_ADJUST_EVENT_QOS(qos) \
	        (((qos) << FILTER_ADJUST_EVENT_QOS_SHIFT) | FILTER_ADJUST_EVENT_QOS_BIT)
#define FILTER_GET_EVENT_QOS(result) \
	        ((result >> FILTER_ADJUST_EVENT_QOS_SHIFT) & THREAD_QOS_LAST)
#define FILTER_RESET_EVENT_QOS              FILTER_ADJUST_EVENT_QOS_BIT
#define FILTER_THREADREQ_NODEFEER           0x00000080
#define FILTER_ADJUST_EVENT_IOTIER_BIT      0x00000100

#define filter_call(_ops, call)  \
	        ((_ops)->f_extended_codes ? (_ops)->call : !!((_ops)->call))

SLIST_HEAD(klist, knote);
extern void     knote_init(void);
extern void     klist_init(struct klist *list);

#define KNOTE(list, hint)       knote(list, hint, false)
#define KNOTE_ATTACH(list, kn)  knote_attach(list, kn)
#define KNOTE_DETACH(list, kn)  knote_detach(list, kn)

extern void knote(struct klist *list, long hint, bool autodetach);
extern int knote_attach(struct klist *list, struct knote *kn);
extern int knote_detach(struct klist *list, struct knote *kn);
extern void knote_vanish(struct klist *list, bool make_active);

extern void knote_set_error(struct knote *kn, int error);
extern int64_t knote_low_watermark(const struct knote *kn) __pure2;
extern void knote_fill_kevent_with_sdata(struct knote *kn, struct kevent_qos_s *kev);
extern void knote_fill_kevent(struct knote *kn, struct kevent_qos_s *kev, int64_t data);

extern void *knote_kn_hook_get_raw(struct knote *kn);
// Must be called after having specified the filtid + filter in the knote
extern void knote_kn_hook_set_raw(struct knote *kn, void *kn_hook);

extern void knote_fdclose(struct proc *p, int fd);
extern const struct filterops *knote_fops(struct knote *kn);

extern struct turnstile *kqueue_turnstile(struct kqueue *);
extern struct turnstile *kqueue_alloc_turnstile(struct kqueue *);
extern void kqueue_set_iotier_override(struct kqueue *kqu, uint8_t iotier_override);
extern uint8_t kqueue_get_iotier_override(struct kqueue *kqu);

int kevent_proc_copy_uptrs(void *proc, uint64_t *buf, uint32_t bufsize);
#if CONFIG_PREADOPT_TG
extern void kqueue_set_preadopted_thread_group(struct kqueue *kq, struct thread_group *tg, thread_qos_t qos);
extern bool kqueue_process_preadopt_thread_group(thread_t t, struct kqueue *kq, struct thread_group *tg);
#endif

int kevent_copyout_proc_dynkqids(void *proc, user_addr_t ubuf,
    uint32_t ubufsize, int32_t *nkqueues_out);
int kevent_copyout_dynkqinfo(void *proc, kqueue_id_t kq_id, user_addr_t ubuf,
    uint32_t ubufsize, int32_t *size_out);
int kevent_copyout_dynkqextinfo(void *proc, kqueue_id_t kq_id, user_addr_t ubuf,
    uint32_t ubufsize, int32_t *nknotes_out);

extern int filt_wlattach_sync_ipc(struct knote *kn);
extern void filt_wldetach_sync_ipc(struct knote *kn);

extern int kevent_workq_internal(struct proc *p,
    user_addr_t changelist, int nchanges,
    user_addr_t eventlist, int nevents,
    user_addr_t data_out, user_size_t *data_available,
    unsigned int flags, int32_t *retval);

#elif defined(KERNEL_PRIVATE) /* !XNU_KERNEL_PRIVATE: kexts still need a klist structure definition */

struct proc;
struct knote;
SLIST_HEAD(klist, knote);

#endif /* !XNU_KERNEL_PRIVATE && KERNEL_PRIVATE */

#else   /* KERNEL_PRIVATE */

__BEGIN_DECLS
int     kevent_qos(int kq,
    const struct kevent_qos_s *changelist, int nchanges,
    struct kevent_qos_s *eventlist, int nevents,
    void *data_out, size_t *data_available,
    unsigned int flags);

int     kevent_id(kqueue_id_t id,
    const struct kevent_qos_s *changelist, int nchanges,
    struct kevent_qos_s *eventlist, int nevents,
    void *data_out, size_t *data_available,
    unsigned int flags);

__END_DECLS


#endif /* KERNEL_PRIVATE */

/* Flags for pending events notified by kernel via return-to-kernel ast */
#define R2K_WORKLOOP_PENDING_EVENTS             0x1
#define R2K_WORKQ_PENDING_EVENTS                0x2

/* Flags for notifying what to do when there is a workqueue quantum expiry */
#define PTHREAD_WQ_QUANTUM_EXPIRY_NARROW 0x1
#define PTHREAD_WQ_QUANTUM_EXPIRY_SHUFFLE 0x2

#endif /* !_SYS_EVENT_PRIVATE_H_ */
