/*
 * Copyright (c) 2000-2017 Apple Computer, Inc. All rights reserved.
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

#ifndef _PTHREAD_PRIORITY_PRIVATE_H_
#define _PTHREAD_PRIORITY_PRIVATE_H_

#if KERNEL
#define PTHREAD_EXPOSE_LAYOUT 1
#else
#include <TargetConditionals.h>
#if TARGET_OS_SIMULATOR
#define PTHREAD_EXPOSE_LAYOUT 0
#else
#define PTHREAD_EXPOSE_LAYOUT 1
#endif /* TARGET_OS_SIMULATOR */
#endif

/*!
 * @typedef pthread_priority_t
 *
 * @abstract
 * pthread_priority_t is an on opaque integer that is guaranteed to be ordered
 * such that combations of QoS classes and relative priorities are ordered
 * numerically, according to their combined priority.
 *
 * <b>xnu, pthread & libdispatch flags</b>
 *
 * @const _PTHREAD_PRIORITY_OVERCOMMIT_FLAG
 * The thread this priority is applied to is overcommit (affects the workqueue
 * creation policy for this priority).
 *
 * @const _PTHREAD_PRIORITY_COOPERATIVE_FLAG
 * Used to convey that a thread is part of the cooperative pool. This is used
 * both outgoing form kernel and incoming into kernel
 *
 * @const _PTHREAD_PRIORITY_THREAD_TYPE_MASK
 * The set of bits that encode information about the thread type - whether it is
 * overcommit, non-overcommit or cooperative
 *
 * @const _PTHREAD_PRIORITY_FALLBACK_FLAG
 * Indicates that this priority is is used only when incoming events have no
 * priority at all. It is merely used as a fallback (hence the name) instead of
 * a floor.
 *
 * This is usually used with QOS_CLASS_DEFAULT and a 0 relative priority.
 *
 * @const _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG
 * The event manager flag indicates that this thread/request is for a event
 * manager thread.  There can only ever be one event manager thread at a time
 * and it is brought up at the highest of all event manager priorities pthread
 * knows about.
 *
 * @const _PTHREAD_PRIORITY_OVERRIDE_QOS_FLAG
 * This flag indicates that the bits extracted using
 * _PTHREAD_PRIORITY_QOS_CLASS_MASK represent { QoS override, req QoS } instead
 * of just req QoS. This is only currently only used as input to the kernel as
 * part of pthread_set_properties_self(). The override field here represents the
 * dispatch workqueue override.
 *
 * @const _PTHREAD_PRIORITY_SCHED_PRI_FLAG
 * @const _PTHREAD_PRIORITY_SCHED_PRI_MASK
 * This flag indicates that the bits extracted using
 * _PTHREAD_PRIORITY_SCHED_PRI_MASK represent a scheduler priority instead of
 * a {qos, relative priority} pair.
 *
 * This flag is used by the pthread kext to indicate to libdispatch that the
 * event manager queue priority is a scheduling priority and not a QoS.  When
 * the manager thread's priority is updated due to creation of pthread root
 * queues, libdispatch passed a pthread_priority_t in to kernel with this flag
 * to specify the new sched pri of manager. This flag is never used as an input
 * by anything else and is why it can perform a double duty with
 * _PTHREAD_PRIORITY_ROOTQUEUE_FLAG.
 *
 * @const _PTHREAD_PRIORITY_NEEDS_UNBIND_FLAG
 * This flag is used for the priority of event delivery threads to indicate
 * to libdispatch that this thread is bound to a kqueue.
 *
 * <b>dispatch only flags</b>
 *
 * @const _PTHREAD_PRIORITY_INHERIT_FLAG
 * This flag is meaningful to libdispatch only and has no meaning for the
 * kernel and/or pthread.
 *
 * @const _PTHREAD_PRIORITY_ROOTQUEUE_FLAG
 * This flag is meaningful to libdispatch only and has no meaning for the
 * kernel and/or pthread.
 *
 * @const _PTHREAD_PRIORITY_ENFORCE_FLAG
 * This flag is used to indicate that this priority should be prefered for work
 * submited asynchronously over the intrinsic priority of the queue/thread the
 * work is submitted to.
 *
 *
 * pthread_priority_t encoding - outgoing from kernel:
 *
 * Regular:
 *                flags                    req QoS class           Rel pri
 * |---------------------------------|--------------------|--------------------|
 *              22 - 31                      8-21                 0-7
 *
 * With _PTHREAD_PRIORITY_SCHED_PRI_FLAG:
 *
 *               flags                  unused         sched priority
 * |---------------------------------|----------|------------------------------|
 *              22 - 31                 16-21             0-15
 *
 * pthread_priority_t encoding - incoming to kernel via various syscalls:
 *
 * Regular:
 *
 *                flags                    req QoS class           Rel pri
 * |---------------------------------|--------------------|--------------------|
 *              22 - 31                      8-21                 0-7
 *
 * With _PTHREAD_PRIORITY_OVERRIDE_QOS_FLAG:
 *
 *              flags                  QoS ovr   QoS class       Rel pri
 * |---------------------------------|---------|----------|--------------------|
 *              22 - 31                 14-21      8-13            0-7
 *
 * With _PTHREAD_PRIORITY_SCHED_PRI_FLAG:
 *
 *               flags                  unused         sched priority
 * |---------------------------------|----------|------------------------------|
 *              22 - 31                 16-21             0-15
 */
typedef unsigned long pthread_priority_t;

#define _PTHREAD_PRIORITY_OVERCOMMIT_FLAG               0x80000000u
#define _PTHREAD_PRIORITY_INHERIT_FLAG                  0x40000000u /* dispatch only */
#define _PTHREAD_PRIORITY_ROOTQUEUE_FLAG                0x20000000u /* dispatch only */
#define _PTHREAD_PRIORITY_SCHED_PRI_FLAG                0x20000000u
#define _PTHREAD_PRIORITY_ENFORCE_FLAG                  0x10000000u /* dispatch only */
#define _PTHREAD_PRIORITY_FALLBACK_FLAG                 0x04000000u
#define _PTHREAD_PRIORITY_COOPERATIVE_FLAG              0x08000000u
#define _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG            0x02000000u
#define _PTHREAD_PRIORITY_NEEDS_UNBIND_FLAG             0x01000000u
#define _PTHREAD_PRIORITY_DEFAULTQUEUE_FLAG             _PTHREAD_PRIORITY_FALLBACK_FLAG // compat
#define _PTHREAD_PRIORITY_OVERRIDE_QOS_FLAG             0x00800000u

#define _PTHREAD_PRIORITY_THREAD_TYPE_MASK              (_PTHREAD_PRIORITY_COOPERATIVE_FLAG | _PTHREAD_PRIORITY_OVERCOMMIT_FLAG)

#if PTHREAD_EXPOSE_LAYOUT || defined(__PTHREAD_EXPOSE_INTERNALS__)
// Masks for encoding of pthread priority
#define _PTHREAD_PRIORITY_FLAGS_MASK                    0xff000000u

#define _PTHREAD_PRIORITY_SCHED_PRI_MASK                0x0000ffffu

#define _PTHREAD_PRIORITY_QOS_CLASS_MASK                0x003fff00u
#define _PTHREAD_PRIORITY_QOS_CLASS_SHIFT               (8ull)
#define _PTHREAD_PRIORITY_VALID_QOS_CLASS_MASK          0x00003f00u
#define _PTHREAD_PRIORITY_VALID_OVERRIDE_QOS_MASK       0x003fc000u
#define _PTHREAD_PRIORITY_QOS_OVERRIDE_SHIFT            (14ull)

#define _PTHREAD_PRIORITY_PRIORITY_MASK                 0x000000ffu
#define _PTHREAD_PRIORITY_PRIORITY_SHIFT                (0)
#endif /* PTHREAD_EXPOSE_LAYOUT */

#if PRIVATE
#if XNU_KERNEL_PRIVATE && !defined(__PTHREAD_EXPOSE_INTERNALS__)
#define __PTHREAD_EXPOSE_INTERNALS__ 1
#endif // XNU_KERNEL_PRIVATE
#ifdef __PTHREAD_EXPOSE_INTERNALS__
/*
 * This exposes the encoding used for pthread_priority_t
 * and is meant to be used by pthread and XNU only
 */
#include <mach/thread_policy.h> // THREAD_QOS_*
#include <stdbool.h>

// pthread_priority_t's type is unfortunately 64bits on LP64
// so we use this type for people who need to store it in structs
typedef unsigned int pthread_priority_compact_t;

__attribute__((always_inline, const))
static inline bool
_pthread_priority_has_qos(pthread_priority_t pp)
{
	return (pp & (_PTHREAD_PRIORITY_SCHED_PRI_FLAG |
	       _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)) == 0 &&
	       (pp & _PTHREAD_PRIORITY_VALID_QOS_CLASS_MASK) != 0;
}

__attribute__((always_inline, const))
static inline bool
_pthread_priority_has_sched_pri(pthread_priority_t pp)
{
	return pp & _PTHREAD_PRIORITY_SCHED_PRI_FLAG;
}

__attribute__((always_inline, const))
static inline bool
_pthread_priority_has_override_qos(pthread_priority_t pp)
{
	return (pp & (_PTHREAD_PRIORITY_SCHED_PRI_FLAG |
	       _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)) == 0 &&
	       (pp & _PTHREAD_PRIORITY_OVERRIDE_QOS_FLAG) != 0 &&
	       (pp & _PTHREAD_PRIORITY_VALID_OVERRIDE_QOS_MASK) != 0;
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_priority_make_from_thread_qos(thread_qos_t qos, int relpri,
    unsigned long flags)
{
	pthread_priority_compact_t pp = (flags & _PTHREAD_PRIORITY_FLAGS_MASK);
	if (qos && qos < THREAD_QOS_LAST) {
		pp |= (1 << (_PTHREAD_PRIORITY_QOS_CLASS_SHIFT + qos - 1));
		pp |= ((uint8_t)relpri - 1) & _PTHREAD_PRIORITY_PRIORITY_MASK;
	}
	return pp;
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_priority_make_from_sched_pri(int sched_pri, unsigned long flags)
{
	pthread_priority_compact_t pp = (flags & _PTHREAD_PRIORITY_FLAGS_MASK);
	pp |= _PTHREAD_PRIORITY_SCHED_PRI_FLAG;
	pp |= (pthread_priority_compact_t) sched_pri;

	return pp;
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_priority_make_from_thread_qos_and_override(thread_qos_t req_qos,
    int relpri, thread_qos_t override_qos, unsigned long flags)
{
	pthread_priority_compact_t pp;
	pp = _pthread_priority_make_from_thread_qos(req_qos, relpri, flags);

	if (override_qos && override_qos < THREAD_QOS_LAST) {
		pp |= (1 << (_PTHREAD_PRIORITY_QOS_OVERRIDE_SHIFT + (override_qos - 1)));
		pp |= _PTHREAD_PRIORITY_OVERRIDE_QOS_FLAG;
	}

	return pp;
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_event_manager_priority(void)
{
	return _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_unspecified_priority(void)
{
	return _pthread_priority_make_from_thread_qos(THREAD_QOS_UNSPECIFIED, 0, 0);
}

__attribute__((always_inline, const))
static inline pthread_priority_compact_t
_pthread_default_priority(unsigned long flags)
{
	return _pthread_priority_make_from_thread_qos(THREAD_QOS_LEGACY, 0, flags);
}

__attribute__((always_inline, const))
static inline thread_qos_t
_pthread_priority_thread_qos_fast(pthread_priority_t pp)
{
	pp &= _PTHREAD_PRIORITY_VALID_QOS_CLASS_MASK;
	pp >>= _PTHREAD_PRIORITY_QOS_CLASS_SHIFT;
	return (thread_qos_t)__builtin_ffs((int)pp);
}

__attribute__((always_inline, const))
static inline thread_qos_t
_pthread_priority_thread_override_qos_fast(pthread_priority_t pp)
{
	pp &= _PTHREAD_PRIORITY_VALID_OVERRIDE_QOS_MASK;
	pp >>= _PTHREAD_PRIORITY_QOS_OVERRIDE_SHIFT;
	return (thread_qos_t)__builtin_ffs((int)pp);
}

__attribute__((always_inline, const))
static inline int
_pthread_priority_sched_pri_fast(pthread_priority_t pp)
{
	return pp & _PTHREAD_PRIORITY_SCHED_PRI_MASK;
}

__attribute__((always_inline, const))
static inline thread_qos_t
_pthread_priority_thread_qos(pthread_priority_t pp)
{
	if (_pthread_priority_has_qos(pp)) {
		return _pthread_priority_thread_qos_fast(pp);
	}
	return THREAD_QOS_UNSPECIFIED;
}

__attribute__((always_inline, const))
static inline thread_qos_t
_pthread_priority_thread_override_qos(pthread_priority_t pp)
{
	if (_pthread_priority_has_override_qos(pp)) {
		return _pthread_priority_thread_override_qos_fast(pp);
	}
	return THREAD_QOS_UNSPECIFIED;
}

__attribute__((always_inline, const))
static inline int
_pthread_priority_sched_pri(pthread_priority_t pp)
{
	if (_pthread_priority_has_sched_pri(pp)) {
		return _pthread_priority_sched_pri_fast(pp);
	}

	return 0;
}

__attribute__((always_inline, const))
static inline int
_pthread_priority_relpri(pthread_priority_t pp)
{
	if (_pthread_priority_has_qos(pp)) {
		pp &= _PTHREAD_PRIORITY_PRIORITY_MASK;
		pp >>= _PTHREAD_PRIORITY_PRIORITY_SHIFT;
		return (int8_t)pp + 1;
	}
	return 0;
}

__attribute__((always_inline, const))
static inline bool
_pthread_priority_is_overcommit(pthread_priority_t pp)
{
	return pp & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG;
}

__attribute__((always_inline, const))
static inline bool
_pthread_priority_is_cooperative(pthread_priority_t pp)
{
	return pp & _PTHREAD_PRIORITY_COOPERATIVE_FLAG;
}

__attribute__((always_inline, const))
static inline bool
_pthread_priority_is_nonovercommit(pthread_priority_t pp)
{
	return !_pthread_priority_is_cooperative(pp) && !_pthread_priority_is_overcommit(pp);
}

#if XNU_KERNEL_PRIVATE
// Interfaces only used by the kernel and not implemented in userspace.

/*
 * Keep managerness, overcomitness and fallback, discard other flags.
 * Normalize and validate QoS/relpri
 */
__attribute__((const))
pthread_priority_compact_t
_pthread_priority_normalize(pthread_priority_t pp);

/*
 * Keep managerness, discard other flags.
 * Normalize and validate QoS/relpri
 */
__attribute__((const))
pthread_priority_compact_t
_pthread_priority_normalize_for_ipc(pthread_priority_t pp);

/*
 * Keep the flags from base_pp and return the priority with the maximum priority
 * of base_pp and _pthread_priority_make_from_thread_qos(qos, 0, 0)
 */
__attribute__((const))
pthread_priority_compact_t
_pthread_priority_combine(pthread_priority_t base_pp, thread_qos_t qos);


#endif // XNU_KERNEL_PRIVATE
#endif // __PTHREAD_EXPOSE_INTERNALS__
#endif // PRIVATE
#endif // _PTHREAD_PRIORITY_PRIVATE_H_
