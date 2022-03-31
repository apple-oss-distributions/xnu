/*
 * Copyright (c) 2012-2021 Apple Inc. All rights reserved.
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

#ifndef _KERN_BTLOG_H_
#define _KERN_BTLOG_H_

#include <sys/cdefs.h>
#include <stdbool.h>
#include <stdint.h>

#include <mach/vm_types.h>
#include <kern/kern_types.h>
#include <kern/debug.h>

__BEGIN_DECLS __ASSUME_PTR_ABI_SINGLE_BEGIN

#pragma GCC visibility push(hidden)

/*
 * The btlog subsystem allows for fast unobtrusive backtraces
 * to be recorded and maintained in chronological order.
 *
 * Each backtrace is associated with an element/object,
 * and an operation. For example, memory allocations and
 * frees can be tracked with this infrastructure. So
 * can refcounts. The "operation" namespace is maintained
 * by the caller.
 *
 * When the event buffer fills, records are reused in FIFO
 * order.
 *
 * When a btlog_t is created, callbacks can be provided
 * to ensure proper locking of the datastructures. If these
 * are not provided, the caller is responsible for
 * preventing simultaneous modification.
 */

/*
 * BTLOG_MAX_DEPTH configures how deep of a stack trace is stored.  15
 * levels is usually enough to get past all the layers of code in
 * kalloc and IOKit and see who the actual caller is up above these
 * lower levels, when used by the zone allocator logging code.
 */

#define BTLOG_MAX_DEPTH 15

#if __has_attribute(diagnose_if)
#define __btlog_check(cond, msg) \
	__attribute__((diagnose_if(cond, msg, "error")))
#else
#define __btlog_check(cond, msg)
#endif

struct btlog;
struct zone_btrecord;

typedef struct btlog *btlog_t;

/*!
 * @typedef btref_t
 *
 * @brief
 * A backtrace ref is a compact pointer referencing a unique backtrace
 * in the centralized backtrace pool.
 */
typedef uint32_t btref_t;
#define BTREF_NULL              ((btref_t)0)

__options_decl(btref_get_flags_t, uint32_t, {
	BTREF_GET_PERMANENT = 0x0001,
	BTREF_GET_NOWAIT    = 0x0002,
});

/*!
 * @function btref_get()
 *
 * @brief
 * Get the backtrace reference anchored at the given @c fp
 * for the current thread.
 *
 * @returns
 * - BTREF_NULL if allocating the backtrace failed
 * - a non 0 backtrace reference otherwise with a +1 refcount.
 */
extern btref_t btref_get(
	void                   *fp,
	btref_get_flags_t       flags);

/*!
 * @function btref_retain()
 *
 * @brief
 * Retains a given backtrace ref.
 */
extern btref_t btref_retain(
	btref_t                 ref);

/*!
 * @function btref_put()
 *
 * @brief
 * Release a given backtrace ref.
 */
extern void btref_put(
	btref_t                 btref);

/*!
 * @function btref_decode_unslide()
 *
 * @brief
 * Decodes a backtrace into a specified buffer with unslid addresses.
 *
 * @returns
 * The number of frames in the buffer.
 */
extern uint32_t btref_decode_unslide(
	btref_t                 btref,
	mach_vm_address_t       bt[__counted_by(BTLOG_MAX_DEPTH)]);


/*!
 * @typedef btlog_type_t
 *
 * @const BTLOG_LOG
 * A linear log of entries, as a circular buffer.
 *
 * @const BTLOG_HASH
 * A log of entries indexed by element address,
 * where entries can be pruned by element address,
 * but where entries might go missing.
 */
__enum_decl(btlog_type_t, uint8_t, {
	BTLOG_LOG       = 1,
	BTLOG_HASH      = 2,
});

/*!
 * @function btlog_create()
 *
 * @brief
 * Creates a backtrace log of the specified type.
 *
 * @param type          the log type to create.
 * @param num_records   how many records the log should hold.
 * @param sample        sampling rate (0 to disable).
 */
extern btlog_t btlog_create(
	btlog_type_t            type,
	uint32_t                num_records,
	uint32_t                sample);

/*!
 * @function btlog_enable()
 *
 * @brief
 * Enable the specified btlog back.
 *
 * @discussion
 * This operation is not thread safe with respect
 * to @c btlog_disable() or @c btlog_destroy(),
 * and the caller is supposed to provide serialization.
 */
extern void btlog_enable(
	btlog_t                 log);

/*!
 * @function btlog_disable()
 *
 * @brief
 * Disables the specified btlog.
 *
 * @discussion
 * This operation is not thread safe with respect
 * to @c btlog_enable() or @c btlog_destroy(),
 * and the caller is supposed to provide serialization.
 */
extern void btlog_disable(
	btlog_t                 log);

/*!
 * @function btlog_destroy()
 *
 * @brief
 * Destroys a backtrace log made with btlog_create().
 */
extern void btlog_destroy(
	btlog_t                 btlog);

/*!
 * @function btlog_get_type()
 *
 * @brief
 * Returns the type for the given btlog.
 */
extern btlog_type_t btlog_get_type(
	btlog_t                 btlog) __pure2;

/*!
 * @function btlog_get_count()
 *
 * @brief
 * Returns how many records this log can hold.
 */
extern uint32_t btlog_get_count(
	btlog_t                 btlog) __pure2;


/*!
 * @function btlog_sample()
 *
 * @brief
 * Returns whether it's the right time to record an event.
 */
extern bool btlog_sample(
	btlog_t                 btlog);

/*!
 * @function btlog_record()
 *
 * @brief
 * Records an event for a given address with
 * a user provided "operation" to tag it.
 * btlog_record will consume a reference on btref.
 */
extern void btlog_record(
	btlog_t                 btlog,
	void                   *element,
	uint8_t                 op,
	btref_t                 btref);

/*!
 * @function btlog_erase()
 *
 * @brief
 * Erase all records for a given address.
 *
 * @discussion
 * This only does something for BTLOG_HASH logs.
 */
extern void btlog_erase(
	btlog_t                 btlog,
	void                   *element);

/*!
 * @function btlog_get_records()
 *
 * @brief
 * Translates btlog records into zone bt records.
 */
extern kern_return_t btlog_get_records(
	btlog_t                 btlog,
	struct zone_btrecord *__counted_by(*numrecs) *records,
	unsigned int           *numrecs);


/*!
 * @function btlog_guess_top()
 *
 * @brief
 * Tries to guess the "top" active backtrace
 * in a @c BTLOG_HASH btlog.
 *
 * @returns
 * The number of outstanding records for this backtrace,
 * or 0 if something bad happened.
 */
extern uint32_t btlog_guess_top(
	btlog_t                 btlog,
	vm_address_t            bt[__counted_by(BTLOG_MAX_DEPTH)],
	uint32_t               *len);

#if DEBUG || DEVELOPMENT

/*!
 * @function btlog_copy_backtraces_for_elements()
 *
 * @brief
 * Copy backtraces for the specified list of elements.
 *
 * @discussion
 * This only does something for BTLOG_HASH logs with a single event per element.
 * This is really tailored for zalloc and isn't a very useful interface as is.
 */
extern void btlog_copy_backtraces_for_elements(
	btlog_t                 btlog,
	vm_address_t *__counted_by(*count) instances,
	uint32_t               *count,
	uint32_t                elem_size,
	leak_site_proc          proc);

#endif /* DEBUG || DEVELOPMENT */
#pragma GCC visibility pop

__ASSUME_PTR_ABI_SINGLE_END __END_DECLS

#endif  /* _KERN_BTLOG_H_ */
