/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

/*
 * vm_configurator.h
 *
 * Generator and checker of userspace virtual memory configurations.
 */

#ifndef VM_CONFIGURATOR_H
#define VM_CONFIGURATOR_H

/*
 * -- Dramatis personae --
 *
 * vm_entry_template_t
 *     Specification of a VM entry to create,
 *     or a hole in VM address space to skip over.
 *     Used to describe and create the VM state for the start of a test.
 *
 * vm_object_template_t
 *     Specification of a VM object to create for entries to copy or share.
 *     Used to describe and create the VM state for the start of a test.
 *
 * vm_config_t
 *     Specification of one or more contiguous VM entries,
 *     plus a test name and an address range within that VM
 *     space that is the range to be tested.
 *     Used to describe and create the VM state for the start of a test.
 *
 * vm_entry_checker_t
 *     Describes the expected state of a VM entry or a hole,
 *     and verifies that the live VM state matches the expected state.
 *     Updated by test code as test operations are performed.
 *     Used to verify the VM state during and after a test.
 *
 * vm_object_checker_t
 *     Describes the expected state of a VM object
 *     and verifies that the live VM state matches the expected state
 *     Updated by test code as test operations are performed.
 *     Used to verify the VM state during and after a test.
 *
 * -- Outline of a test --
 *
 * 1. Describe the desired initial memory state
 *    with arrays of vm_entry_template_t and vm_object_template_t.
 * 2. Call create_vm_state() to allocate the specified VM entries
 *    and lists of vm_entry_checker_t and vm_object_checker_t
 *    that match the newly-allocated state.
 * 3. Perform the VM operations to be tested. Update the checkers
 *    with the state changes that you expect. If some field's value
 *    becomes indeterminate, or difficult to specify and unimportant
 *    for your test, disable that field in the checker.
 * 4. Call verify_vm_state() to compare the live
 *    VM state to the checker's expected state.
 * 5. Optionally repeat steps 3 and 4 to test a sequence of VM operations.
 *
 * See vm_configurator_tests.h for a set of templates used by
 * many VM syscall tests, and some details on how to run them.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/vm_prot.h>
#include <mach/vm_param.h>
#include <mach/vm_region.h>
#include <mach/vm_inherit.h>
#include <mach/vm_behavior.h>
#include <mach/vm_statistics.h>

#include <darwintest.h>
#include <darwintest_utils.h>
#include <test_utils.h>

/*
 * Set Verbose = true to log the complete VM state, both expected and actual,
 * every time it is checked.
 * Initialized from environment variable VERBOSE
 */
extern bool Verbose;

static inline bool
is_new_vm(void)
{
	static dispatch_once_t is_new_once;
	static bool is_new;

	dispatch_once(&is_new_once, ^{
		int out_value = 0;
		size_t inout_size = sizeof(out_value);
		if (sysctlbyname("vm.has_range_locking", &out_value, &inout_size, NULL, 0) != 0) {
		        T_QUIET; T_ASSERT_POSIX_ERROR(errno, ENOENT, "sysctlbyname(vm.has_range_locking)");
		        /* unknown sysctl, must be old vm */
		        is_new = false;
		} else {
		        T_QUIET; T_ASSERT_EQ(inout_size, sizeof(out_value), "sysctlbyname(vm.has_range_locking)");
		        is_new = (bool)out_value;
		}
		T_LOG(is_new ? "NEW VM" : "OLD VM");
	});
	return is_new;
}


/*
 * Return values from individual test functions.
 * These are ordered from "best" to "worst".
 *
 * TODO: docs
 */
typedef enum {
	TestSucceeded = 1,
	TestFailed,
} test_result_t;

static inline test_result_t
worst_result(test_result_t *list, unsigned count)
{
	test_result_t worst = TestSucceeded;
	for (unsigned i = 0; i < count; i++) {
		if (list[i] > worst) {
			worst = list[i];
		}
	}
	return worst;
}

typedef enum {
	DontFill = 0, /* must be zero */
	Fill = 1
} fill_pattern_mode_t;

typedef struct {
	fill_pattern_mode_t mode;
	uint64_t pattern;
} fill_pattern_t;

/* Make a fill_pattern_t that fills copies of a byte. */
static inline fill_pattern_t
fill_pattern_from_char(char c)
{
	char pat[8] = {c, c, c, c, c, c, c, c};
	fill_pattern_t result;
	result.mode = Fill;
	static_assert(sizeof(pat) == sizeof(result.pattern));
	memcpy(&result.pattern, pat, sizeof(pat));
	return result;
}

/*
 * EndObjects: for END_OBJECTS array terminator
 * Deinited: an object that is no longer referenced and whose checker is now
 *   depopulated but is still allocated because some checker list may point to it
 * Anonymous: anonymous memory such as vm_allocate()
 * SubmapObject: an "object" that is really a submap
 * TODO: support named/pageable objects
 */
typedef enum {
	FreedObject = 0,  /* use after free, shouldn't happen */
	EndObjects,
	Deinited,
	Anonymous,
	SubmapObject,
} vm_object_template_kind_t;

/*
 * struct vm_object_template_t
 * Declaratively specify VM objects to be created.
 */
typedef struct vm_object_template_s {
	vm_object_template_kind_t kind;

	mach_vm_size_t size;  /* size 0 means auto-compute from entry sizes */

	fill_pattern_t fill_pattern;
	struct {
		struct vm_entry_template_s *entries;
		struct vm_object_template_s *objects;
		unsigned entry_count;
		unsigned object_count;
	} submap;
} vm_object_template_t;

/*
 * Convenience macro for initializing a vm_object_template_t.
 * The macro sets all template fields to a default value.
 * You may override any field using designated initializer syntax.
 *
 * Example usage:
 *     // all default values
 *     vm_object_template()
 *
 *     // default, with custom size and fill pattern
 *     vm_object_template(
 *             .size = 20 * PAGE_SIZE,
 *             .fill_pattern = 0x1234567890abcdef)
 */
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#define vm_object_template(...)                                         \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	_Pragma("clang diagnostic ignored \"-Wmissing-field-initializers\"") \
	(vm_object_template_t){                                         \
	        .size = 0, /* auto-computed */                          \
	            .kind = Anonymous,                                  \
	            .fill_pattern = {.mode = DontFill},                 \
	            __VA_ARGS__                                         \
	            }                                                   \
	_Pragma("clang diagnostic pop")

/* Convenience for submap objects */
#define submap_object_template(...) \
	vm_object_template(.kind = SubmapObject, __VA_ARGS__)

/*
 * EndEntries: for END_ENTRIES array terminator
 * Allocation: an ordinary VM entry
 * Hole: an unallocated range of the address space.
 * Submap: a mapping of a submap
 * Guard: a guard page added before or after the test memory
 */
typedef enum {
	EndEntries = 0,
	Allocation,
	Hole,
	Submap,
	Guard,
} vm_entry_template_kind_t;

/*
 * struct vm_entry_template_t
 * Declaratively specify VM entries to be created.
 */
typedef struct vm_entry_template_s {
	mach_vm_size_t size;
	vm_entry_template_kind_t kind;

	/*
	 * NULL object means either null vm_object_t or anonymous zerofilled
	 * memory, depending on the requirements of the other settings.
	 * (For example, non-zero wire count faults in the pages
	 * so it is no longer a null vm_object_t.)
	 * Used when .kind == Allocation.
	 */
	vm_object_template_t *object;

	mach_vm_offset_t offset;

	vm_prot_t protection;
	vm_prot_t max_protection;
	vm_inherit_t inheritance;
	vm_behavior_t behavior;
	bool permanent;

	/* New entry gets vm_wire'd this many times. */
	uint16_t user_wired_count;

	/*
	 * User tag may be a specific value, or autoincrementing.
	 *
	 * An autoincrementing tag is assigned by create_vm_state()
	 * in the VM_MEMORY_APPLICATION_SPECIFIC_1-16 range. Adjacent
	 * autoincrementing entries get distinct tags. This can be
	 * used to stop the VM from simplifying/coalescing vm entries
	 * that you want to remain separate.
	 */
	uint16_t user_tag;
#define VM_MEMORY_TAG_AUTOINCREMENTING 256

	uint8_t share_mode;

	/*
	 * Code to update when adding new fields:
	 *     vm_entry_template() macro
	 *     create_vm_state() function
	 */
} vm_entry_template_t;


/*
 * Default size for vm_entries created by this generator
 * Some tests require that this be above some minimum.
 * 64 * PAGE_SIZE is big enough that 1/4 of an entry is
 * still over the 32KB physical copy limit inside vm_map_copyin.
 */
#define DEFAULT_ENTRY_SIZE (64 * (mach_vm_address_t)PAGE_SIZE)

/*
 * Default size for address ranges that cover only part of a vm_entry.
 * Some tests require that this be above some minimum.
 */
#define DEFAULT_PARTIAL_ENTRY_SIZE (DEFAULT_ENTRY_SIZE / 2u)

/*
 * Unnesting of submap nested pmaps occurs at L[N-1] page table
 * boundaries (pmap "twig"). By default we avoid crossing those
 * boundaries in tests because it affects the unnested map entries
 * in the parent map.
 * TODO: don't hardcode this, get it from pmap somehow
 */
#define SUBMAP_ALIGNMENT_MASK (0x2000000ull - 1)

/*
 * Convenience macro for initializing a vm_entry_template_t.
 * The macro sets all template fields to a default value.
 * You may override any field using designated initializer syntax.
 *
 * Example usage:
 *     // all default values
 *     vm_entry_template()
 *
 *     // default, with custom size and protections
 *     vm_entry_template(
 *             .size = 20 * PAGE_SIZE,
 *             .protection = VM_PROT_READ,
 *             .max_protection = VM_PROT_READ | VM_PROT_WRITE)
 */
#define vm_entry_template(...)                                          \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	_Pragma("clang diagnostic ignored \"-Wmissing-field-initializers\"") \
	(vm_entry_template_t){                                          \
	        .size = DEFAULT_ENTRY_SIZE,                             \
	            .kind = Allocation,                                 \
	            .object = NULL,                                     \
	            .offset = 0,                                        \
	            .protection = VM_PROT_READ | VM_PROT_WRITE,         \
	            .max_protection = VM_PROT_READ | VM_PROT_WRITE,     \
	            .inheritance = VM_INHERIT_DEFAULT, /* inherit_copy */ \
	            .behavior = VM_BEHAVIOR_DEFAULT,                    \
	            .permanent = false,                                 \
	            .user_wired_count = 0,                              \
	            .user_tag = VM_MEMORY_TAG_AUTOINCREMENTING,         \
	            .share_mode = SM_EMPTY,                             \
	            __VA_ARGS__                                         \
	            }                                                   \
	_Pragma("clang diagnostic pop")

/* Convenience for submap entries */
#define submap_entry_template(...)              \
	vm_entry_template(.kind = Submap, __VA_ARGS__)

/*
 * Convenience templates.
 * END_ENTRIES and END_OBJECTS: terminates a template list
 *     passed to create_vm_state() instead of passing an array count.
 *     (useful for hand-written template array initializers)
 * guard_entry_template: an allocation that defaults to
 *     prot/max NONE/NONE and tag VM_MEMORY_GUARD
 * hole_template: an unallocated hole in the address space.
 */
extern vm_object_template_t END_OBJECTS;
extern vm_entry_template_t END_ENTRIES;
extern vm_entry_template_t guard_entry_template;
extern vm_entry_template_t hole_template;

/*
 * Count the number of templates in an END_TEMPLATE-terminated array.
 */
extern unsigned
count_templates(const vm_entry_template_t *templates);


/*
 * struct vm_entry_attribute_list_t
 * A list of checkable entry attributes with one bool for each.
 * Used to record which attributes should be verified by a checker,
 * or which attributes failed to match during verification.
 */
typedef struct {
	union {
		uint64_t bits;
		struct {
			uint64_t address_attr:1;
			uint64_t size_attr:1;
			uint64_t object_attr:1;
			uint64_t protection_attr:1;
			uint64_t max_protection_attr:1;
			uint64_t inheritance_attr:1;
			uint64_t behavior_attr:1;
			uint64_t permanent_attr:1;
			uint64_t user_wired_count_attr:1;
			uint64_t user_tag_attr:1;
			uint64_t is_submap_attr:1;
			uint64_t submap_depth_attr:1;
			uint64_t object_offset_attr:1;
			uint64_t pages_resident_attr:1;
			uint64_t share_mode_attr:1;
		};
	};

	/*
	 * Code to update when adding new fields:
	 * dump_checker_info()
	 * vm_entry_attributes_with_default macro
	 * verify_allocation()
	 */
} vm_entry_attribute_list_t;

/*
 * struct vm_object_attribute_list_t
 * A list of checkable entry attributes with one bool for each.
 * Used to record which attributes should be verified by a checker,
 * or which attributes failed to match during verification.
 */
typedef struct {
	union {
		uint64_t bits;
		struct {
			uint64_t object_id_attr:1;
			uint64_t size_attr:1;
			uint64_t ref_count_attr:1;
			uint64_t shadow_depth_attr:1;
			uint64_t fill_pattern_attr:1;
		};
	};

	/*
	 * Code to update when adding new fields:
	 * dump_checker_info()
	 * vm_object_attributes_with_default macro
	 * verify_allocation()
	 */
} vm_object_attribute_list_t;

/*
 * vm_entry_attributes_with_default() returns a vm_entry_attribute_list_t,
 * with all attributes set to `default_value`, and the caller can set individual
 * attributes to other values using designated initializer syntax.
 */
#define vm_entry_attributes_with_default(default_value, ...)            \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	_Pragma("clang diagnostic ignored \"-Wmissing-field-initializers\"") \
	(vm_entry_attribute_list_t){                                    \
	        .address_attr           = (default_value),              \
	        .size_attr              = (default_value),              \
	        .object_attr            = (default_value),              \
	        .protection_attr        = (default_value),              \
	        .max_protection_attr    = (default_value),              \
	        .inheritance_attr       = (default_value),              \
	        .behavior_attr          = (default_value),              \
	        .permanent_attr         = (default_value),              \
	        .user_wired_count_attr  = (default_value),              \
	        .user_tag_attr          = (default_value),              \
	        .is_submap_attr         = (default_value),              \
	        .submap_depth_attr      = (default_value),              \
	        .object_offset_attr     = (default_value),              \
	        .pages_resident_attr    = (default_value),              \
	        .share_mode_attr        = (default_value),              \
	        __VA_ARGS__                                             \
	    }                                                           \
	_Pragma("clang diagnostic pop")

/*
 * vm_object_attributes_with_default() returns a vm_object_attribute_list_t,
 * with all attributes set to `default_value`, and the caller can set individual
 * attributes to other values using designated initializer syntax.
 */
#define vm_object_attributes_with_default(default_value, ...)           \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic ignored \"-Winitializer-overrides\"") \
	_Pragma("clang diagnostic ignored \"-Wmissing-field-initializers\"") \
	(vm_object_attribute_list_t){                                   \
	        .object_id_attr    = (default_value),                   \
	        .size_attr         = (default_value),                   \
	        .ref_count_attr    = (default_value),                   \
	        .shadow_depth_attr = (default_value),                   \
	        .fill_pattern_attr = (default_value),                   \
	        __VA_ARGS__                                             \
	    }                                                           \
	_Pragma("clang diagnostic pop")

/*
 * Description of a checker's current knowledge of an object's ID.
 * object_is_unknown: object'd ID is unknown; it may be null
 * object_has_unknown_nonnull_id: object's ID is expected to be non-null,
 *     but its actual value is unknown
 * object_has_known_id: object's ID is expected to be checker->object_id
 *
 * During verification unknown object IDs are learned by reading them from the
 * actual VM state. The learned IDs are applied to subsequent verifications or
 * to subsequent uses of the same object in the same verification.
 */
typedef enum {
	object_is_unknown = 0,
	object_has_unknown_nonnull_id,
	object_has_known_id
} object_id_mode_t;

/*
 * Status of a page in an object.
 * absent: Page is not available in this object. It may be in a shadow object.
 * resident: Page is resident and owned by this object.
 */
typedef enum : uint8_t {
	page_is_absent = 0,  /* must be zero */
	page_is_resident = 1
} page_status_t;

typedef enum __attribute__((__enum_extensibility__(closed))) : uint32_t {
	copy_invalid = ~0,
	copy_none = MEMORY_OBJECT_COPY_NONE,
	copy_symmetric = MEMORY_OBJECT_COPY_SYMMETRIC,
	copy_delay = MEMORY_OBJECT_COPY_DELAY,
	copy_delay_fork = MEMORY_OBJECT_COPY_DELAY_FORK
} copy_strategy_t;

/*
 * struct vm_object_checker_t
 * Maintain and verify expected state of a VM object.
 */
typedef struct vm_object_checker_s {
	struct vm_object_checker_s *prev;
	struct vm_object_checker_s *next;

	vm_object_template_kind_t kind;
	vm_object_attribute_list_t verify;

	uint64_t object_id;
	object_id_mode_t object_id_mode;
	copy_strategy_t copy_strategy;

	/*
	 * self_ref_count is the count of references to this object specifically.
	 * vm_region's reported ref_count also includes references to
	 * the shadow chain's objects, minus the shadow chain's references
	 * to each other.
	 */
	unsigned self_ref_count;
	mach_vm_size_t size;
	fill_pattern_t fill_pattern;

	/*
	 * Page list.
	 * These pages use VM's internal page size,
	 * which may differ from userspace PAGE_SIZE.
	 * NULL array means the object cannot have pages
	 * (the null object or a submap object)
	 */
	page_status_t *pages;  /* `size / xnu_vm_page_size()` elements */

	/*
	 * Shadow chain.
	 * object->shadow is refcounted.
	 * object->vo_copy is not refcounted.
	 */
	struct vm_object_checker_s *shadow;
	struct vm_object_checker_s *vo_copy;

	/* byte offset 0 in this object is `shadow_offset` in object->shadow */
	mach_vm_address_t shadow_offset;

	/*
	 * Checkers for submap contents.
	 * These checkers are configured for a mapping of the whole
	 * submap at address 0. Verification of actual remappings will
	 * need to compensate for address offsets and bounds clipping.
	 */
	struct checker_list_s *submap_checkers;

	/*
	 * Code to update when adding new fields:
	 *     struct vm_object_attribute_list_t
	 *     make_null_object_checker()
	 *     make_anonymous_object_checker()
	 *     make_submap_object_checker()
	 *     dump_checker_info()
	 *     verify_allocation()
	 *     object_checker_clone()
	 */
} vm_object_checker_t;

/*
 * Create a new object checker duplicating an existing checker.
 * The new object is:
 * - zero self_ref_count
 * - unknown object_id
 * - not linked into any checker_list
 */
extern vm_object_checker_t *
object_checker_clone(vm_object_checker_t *obj_checker);

/*
 * Increments an object checker's refcount, mirroring the VM's refcount.
 */
extern void
object_checker_reference(vm_object_checker_t *obj_checker);

/*
 * Decrements an object checker's refcount, mirroring the VM's refcount.
 */
extern void
object_checker_dereference(vm_object_checker_t *obj_checker);

/*
 * Returns true if obj_checker refers to a NULL vm_object.
 * A non-null checker pointer can still refer to a NULL vm_object.
 */
extern bool
object_is_null(vm_object_checker_t *obj_checker);

/*
 * Convenience function for looping through an object checker's page list.
 * Returns the number of elements in the page list.
 * Returns 0 if the page list is NULL.
 */
static inline mach_vm_size_t
object_checker_page_list_count(vm_object_checker_t *obj_checker)
{
	if (obj_checker->pages == NULL) {
		return 0;
	}
	return obj_checker->size / PAGE_SIZE;
}

/*
 * struct vm_entry_checker_t
 * Maintain and verify expected state of a VM map entry.
 *
 * The `verify` bitmap specifies which properties should be checked.
 * If a property's value is indeterminate, or is difficult to specify
 * and not important to the test, that check can be disabled.
 *
 * Checkers are kept in a doubly-linked list in address order,
 * similar to vm_map_entry_t but it is not a circular list.
 * Submaps are recursive: the top-level list contains a Submap checker,
 *   and the Submap checker has its own list of contained checkers.
 */
typedef struct vm_entry_checker_s {
	struct vm_entry_checker_s *prev;
	struct vm_entry_checker_s *next;

	vm_entry_template_kind_t kind;
	vm_entry_attribute_list_t verify;

	mach_vm_address_t address;
	mach_vm_size_t size;

	vm_object_checker_t *object;

	vm_prot_t protection;
	vm_prot_t max_protection;
	vm_inherit_t inheritance;
	vm_behavior_t behavior;
	bool permanent;

	uint16_t user_wired_count;
	uint8_t user_tag;

	/* no is_submap field; use kind == Submap instead */
	uint32_t submap_depth;  /* non-zero when entry is a submap's content */

	uint64_t object_offset;
	uint64_t vm_region_object_offset_tweak;

	bool needs_copy;

	/* share_mode is computed from other entry and object attributes */

	/*
	 * Code to update when adding new fields:
	 *     struct vm_entry_attribute_list_t
	 *     make_checker_for_anonymous_private()
	 *     make_checker_for_vm_allocate()
	 *     make_checker_for_shared()
	 *     make_checker_for_submap()
	 *     dump_checker_info()
	 *     verify_allocation()
	 *     checker_simplify_left()
	 */
} vm_entry_checker_t;

/*
 * A list of consecutive entry checkers. May be a subset of the entire doubly-linked list.
 */
typedef struct {
	vm_entry_checker_t *head;
	vm_entry_checker_t *tail;
} entry_checker_range_t;

/*
 * Deallocate a checker.
 * Also un-references the checker's object.
 * Don't call this if the checker is linked into any list.
 */
extern void
checker_free(vm_entry_checker_t *checker);

/*
 * Count the number of entries between
 * checker_range->head and checker_range->tail, inclusive.
 */
extern unsigned
checker_range_count(entry_checker_range_t checker_range);

/*
 * Return the start address of the first entry in a range.
 */
extern mach_vm_address_t
checker_range_start_address(entry_checker_range_t checker_range);

/*
 * Return the end address of the last entry in a range.
 */
extern mach_vm_address_t
checker_range_end_address(entry_checker_range_t checker_range);

/*
 * Return size of all entries in a range.
 */
extern mach_vm_size_t
checker_range_size(entry_checker_range_t checker_range);

/*
 * Link a checker to the end of a checker range.
 */
extern void
checker_range_append(entry_checker_range_t *list, vm_entry_checker_t *inserted);

/*
 * Loop over all checkers between
 * entry_range->head and entry_range->tail, inclusive.
 * Does visit any submap parent entry.
 * Does not descend into submap contents.
 * Does not visit any guard pages.
 *
 * You may clip_left the current checker. The new left entry is not visited.
 * You may clip_right the current checker. The new right entry is visited next.
 * You may not delete the current checker, unless you also immediately break the loop.
 */
#define FOREACH_CHECKER(checker, entry_range)                   \
	for (vm_entry_checker_t *checker = (entry_range).head;  \
	     checker && checker != (entry_range).tail->next;    \
	     checker = checker->next)

/*
 * The list of all entry and object checkers.
 * The first and last entries may be changed by the test.
 * The first object is the common null object, so it should not change.
 *
 * Submaps get their own checker_list_t. A submap checker
 * list stores checkers for the submap's map entries.
 * It does not store any objects; a single global list of objects is
 * maintained in the top-level checker list so it can be searched by ID.
 *
 * submap_slide keeps track of a temporary address offset applied
 * to the contained checkers. This is used for submap contents.
 *
 * Guard pages may be allocated before and after the memory being tested.
 * These are checked using entry checkers, but most other checker list
 * functions ignore them.
 */
typedef struct checker_list_s {
	struct checker_list_s *parent;
	entry_checker_range_t entries;
	vm_object_checker_t *objects; /* must be NULL in submaps */
	entry_checker_range_t guard_pages;
	uint64_t submap_slide;
	bool is_slid;
} checker_list_t;

#define FOREACH_OBJECT_CHECKER(obj_checker, list) \
	for (vm_object_checker_t *obj_checker = (list)->objects; \
	     obj_checker != NULL; \
	     obj_checker = obj_checker->next)

/*
 * Return the nth checker in the list. Aborts if n is out of range.
 */
extern vm_entry_checker_t *
checker_list_nth(checker_list_t *list, unsigned n);

/*
 * Search a list of checkers for an allocation that contains the given address.
 * Returns NULL if no checker contains the address.
 * Returns NULL if a non-Allocation checker contains the address.
 * Does not descend into submaps.
 */
extern vm_entry_checker_t *
checker_list_find_allocation(checker_list_t *list, mach_vm_address_t addr);

/*
 * Search a list of checkers for a checker that contains the given address.
 * May return checkers for holes.
 * Returns NULL if no checker contains the address.
 * Does not descend into submaps.
 */
extern vm_entry_checker_t *
checker_list_find_checker(checker_list_t *list, mach_vm_address_t addr);

/*
 * Add a new vm object checker to the list.
 * Aborts if the new object is null and the list already has its null object.
 * Aborts if the object's ID is the same as some other object.
 */
extern void
checker_list_append_object(
	checker_list_t *list,
	vm_object_checker_t *obj_checker);

/*
 * Return the list of entry checkers covering an address range.
 * Aborts if the range includes any hole checkers.
 */
extern entry_checker_range_t
checker_list_find_range(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Return the list of entry checkers covering an address range.
 * Hole checkers are allowed.
 */
extern entry_checker_range_t
checker_list_find_range_including_holes(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Like checker_list_find_range(),
 * but the first and last entries are clipped to the address range.
 */
extern entry_checker_range_t
checker_list_find_and_clip(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Like checker_list_find_range_including_holes(),
 * but the first and last entries (if any) are clipped to the address range.
 */
extern entry_checker_range_t
checker_list_find_and_clip_including_holes(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Attempts to simplify all entries in an address range.
 */
extern void
checker_list_simplify(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size);

/*
 * Replace and delete checkers in old_range
 * with the checkers in new_range.
 * The two ranges must have the same start address and size.
 * Updates list->head and/or list->tail if necessary.
 */
extern void
checker_list_replace_range(
	checker_list_t *list,
	entry_checker_range_t old_range,
	entry_checker_range_t new_range);

/*
 * Convenience function to replace one checker with another.
 * The two checkers must have the same start address and size.
 */
static inline void
checker_list_replace_checker(
	checker_list_t *list,
	vm_entry_checker_t *old_checker,
	vm_entry_checker_t *new_checker)
{
	checker_list_replace_range(list,
	    (entry_checker_range_t){ old_checker, old_checker },
	    (entry_checker_range_t){ new_checker, new_checker });
}

/*
 * Convenience function to replace one checker with several checkers.
 * The old and the new must have the same start address and size.
 */
static inline void
checker_list_replace_checker_with_range(
	checker_list_t *list,
	vm_entry_checker_t *old_checker,
	entry_checker_range_t new_checkers)
{
	checker_list_replace_range(list,
	    (entry_checker_range_t){ old_checker, old_checker },
	    new_checkers);
}

/*
 * Convenience function to replace several checkers with one checker.
 * The old and the new must have the same start address and size.
 */
static inline void
checker_list_replace_range_with_checker(
	checker_list_t *list,
	entry_checker_range_t old_checkers,
	vm_entry_checker_t *new_checker)
{
	checker_list_replace_range(list,
	    old_checkers,
	    (entry_checker_range_t){ new_checker, new_checker });
}

/*
 * Insert a checker into a checker list, in address order.
 * The new checker must not overlap with any existing checker.
 */
extern void
checker_list_insert(
	checker_list_t *list,
	vm_entry_checker_t *inserted);

/*
 * Remove a contiguous range of checkers from a checker list.
 * The checkers are freed.
 * The checkers are replaced by a new hole checker.
 * VM allocations are unaffected.
 */
extern void
checker_list_free_range(
	checker_list_t *list,
	entry_checker_range_t range);

/* Convenience function for checker_list_remove_range() of a single checker. */
static inline void
checker_list_free_checker(
	checker_list_t *list,
	vm_entry_checker_t *checker)
{
	checker_list_free_range(list, (entry_checker_range_t){ checker, checker });
}

/*
 * Compute the end address of an entry.
 * `checker->address + checker->size`, with integer overflow protection.
 */
static inline mach_vm_address_t
checker_end_address(vm_entry_checker_t *checker)
{
	mach_vm_address_t end;
	bool overflowed = __builtin_add_overflow(checker->address, checker->size, &end);
	assert(!overflowed);
	return end;
}

/*
 * Return true if address is within checker's [start, end)
 */
static inline bool
checker_contains_address(vm_entry_checker_t *checker, mach_vm_address_t address)
{
	return address >= checker->address && address < checker_end_address(checker);
}

/*
 * Compute the expected share_mode value of an entry.
 * This value is computed from other values in the checker and its object.
 */
extern uint8_t
checker_share_mode(
	vm_entry_checker_t *checker);

/*
 * Compute the expected pages_resident of an entry.
 * The returned count is in userspace PAGE_SIZE units, as returned
 * by vm_region(), which may not match the VM's internal page size.
 */
extern uint32_t
checker_count_vm_region_pages_resident(
	vm_entry_checker_t *checker);

/*
 * Compute the pages resident in an entry
 * that are owned by a specific object in the shadow chain.
 * The returned count is in userspace PAGE_SIZE units, as returned
 * by vm_region(), which may not match the VM's internal page size.
 */
extern uint32_t
checker_count_vm_region_pages_resident_owned_by_object(
	vm_entry_checker_t *checker,
	vm_object_checker_t *matching_owner);

/*
 * Returns true if the page at address is resident
 * and is owned by object matching_owner.
 * If matching_owner is NULL then any owning object is allowed.
 */
extern bool
checker_page_at_address_is_resident_owned_by_object(
	vm_entry_checker_t *checker,
	mach_vm_address_t addr,
	vm_object_checker_t *matching_owner);

/*
 * Returns true if the page at address is resident
 */
static inline bool
checker_page_at_address_is_resident(
	vm_entry_checker_t *checker,
	mach_vm_address_t addr)
{
	return checker_page_at_address_is_resident_owned_by_object(
		checker, addr, NULL /* matching_owner */);
}

/*
 * Compute the is_submap value of a map entry.
 */
static inline bool
checker_is_submap(vm_entry_checker_t *checker)
{
	return checker->kind == Submap;
}

/*
 * Submap slide (checker_get_and_slide_submap_checkers)
 *
 * We want a 1:1 relationship between checkers and map entries.
 * This is complicated in submaps, where the parent map's view
 * of the submap uses different addresses.
 *
 * Our solution:
 * 1. Submap content checkers store the address as if inside the submap.
 * 2. When using a submap content checker in a parent map context,
 *    the checker is temporarily modified to use parent-relative
 *    addresses instead ("slide").
 *
 * The checker_list_t for the submap keeps track of the slide state
 * of its checkers. Some places assert that the submap is or is not slid.
 *
 * Note that this code only deals with constant submaps; therefore
 * we don't need to worry about changing checker bounds while they
 * are temporarily slid.
 */

/*
 * Return the nested checkers for a parent map's submap entry.
 * Returns NULL if the checker is not a submap entry.
 * The caller must call unslide_submap_checkers() when finished.
 */
extern checker_list_t *
checker_get_and_slide_submap_checkers(vm_entry_checker_t *checker);

/*
 * Undo the effects of get_and_slide_submap_checkers().
 */
extern void
unslide_submap_checkers(checker_list_t *submap_checkers);

/*
 * Convenience macro to call unslide_submap_checkers() at end of scope.
 * The caller may manually unslide and then set their variable to NULL
 * to cancel the automatic unslide.
 */
static inline void
cleanup_unslide_submap_checkers(checker_list_t **inout_submap_checkers)
{
	if (*inout_submap_checkers) {
		unslide_submap_checkers(*inout_submap_checkers);
		*inout_submap_checkers = NULL;
	}
}
#define DEFER_UNSLIDE \
	__attribute__((cleanup(cleanup_unslide_submap_checkers)))


/*
 * Adjust a start/end so that it does not extend beyond a limit.
 * If start/end falls outside the limit, the output's size will
 * be zero and its start will be indeterminate.
 */
extern void
clamp_start_end_to_start_end(
	mach_vm_address_t   * const inout_start,
	mach_vm_address_t   * const inout_end,
	mach_vm_address_t           limit_start,
	mach_vm_address_t           limit_end);

/*
 * Adjust a address/size so that it does not extend beyond a limit.
 * If address/size falls outside the limit, the output size will
 * be zero and the start will be indeterminate
 */
extern void
clamp_address_size_to_address_size(
	mach_vm_address_t   * const inout_address,
	mach_vm_size_t      * const inout_size,
	mach_vm_address_t           limit_address,
	mach_vm_size_t              limit_size);

/*
 * Adjust an address range so it does not extend beyond an entry's bounds.
 * When clamping to a submap entry:
 *   checker is a submap entry in the parent map.
 *   address and size are in the parent map's address space on entry and on exit.
 */
extern void
clamp_address_size_to_checker(
	mach_vm_address_t   * const inout_address,
	mach_vm_size_t      * const inout_size,
	vm_entry_checker_t         *checker);

/*
 * Adjust an address range so it does not extend beyond an entry's bounds.
 * When clamping to a submap entry:
 *   checker is a submap entry in the parent map.
 *   address and size are in the parent map's address space on entry and on exit.
 */
extern void
clamp_start_end_to_checker(
	mach_vm_address_t   * const inout_start,
	mach_vm_address_t   * const inout_end,
	vm_entry_checker_t         *checker);


/*
 * Set the VM object that an entry points to.
 * Replaces any existing object. Updates self_ref_count of any objects.
 */
extern void
checker_set_object(vm_entry_checker_t *checker, vm_object_checker_t *obj_checker);

/*
 * Set an entry's object to the null object.
 * Identical to `checker_set_object(checker, find_object_checker_for_object_id(list, 0))`
 */
extern void
checker_set_null_object(checker_list_t *list, vm_entry_checker_t *checker);

/*
 * Set checker's object to a new object that shadows its old object, if necessary.
 * In cases where the new object is not necessary, instead leave the
 * checker's object alone and change the checker to needs_copy = false.
 */
extern void
checker_make_shadow_object(checker_list_t *list, vm_entry_checker_t *checker);

/*
 * If checker has a null VM object, change it to a new anonymous object.
 */
extern void
checker_resolve_null_vm_object(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker);

/*
 * Clip and resolve COW before wiring.
 * range_address and range_size are the extent of the entire wire operation.
 * On exit:
 * - entry won't be needs_copy
 * - object won't be copy_symmetric
 */
extern void
checker_clip_and_resolve_cow_for_wire(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	mach_vm_address_t range_address,
	mach_vm_size_t range_size);

/*
 * Update an entry's checker as if a fault occurred inside it.
 * Returns KERN_PROTECTION_FAILURE with no changes if protection would disallow.
 *
 * - resolves null objects
 * - resolves COW
 * - copies pages from shadow objects, if any
 * - copies pages to copy object, if any
 * - sets the resident page count
 */
extern kern_return_t
checker_fault_address(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	mach_vm_address_t addr,
	vm_prot_t fault_prot);

/*
 * Updates an entry's checker as if it were all faulted.
 * Like checker_fault_address() for every address in it.
 */
extern void
checker_fault_all(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	vm_prot_t fault_prot);

/*
 * Write to a checker's memory with a randomly-chosen new fill pattern.
 * This changes the checker's expected state and also writes to the real memory.
 * Use this to verify that a COW copy does not see writes to its source.
 */
extern void
checker_write_new_fill_pattern(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker);

/*
 * Conditionally unnest one checker in a submap.
 *
 * submap_parent is a parent map's submap entry.
 * *inout_next_address is the current address in the parent map,
 *     within the bounds of submap_parent.
 * If the entry inside the submap that contains *inout_next_address is:
 * - unallocated:
 *     advance *inout_next_address past the unallocated space and return NULL
 * - a writeable allocation:
 *     unnest the appropriate range in the parent map,
 *     advance *inout_next_address past the unnested range,
 *     and return the unnested range's new checker
 * - a readable allocation:
 *     - (unnest_readonly == false) advance past it, same as for unallocated holes
 *     - (unnest_readonly == true) unnest it, same as for writeable allocations
 */
extern vm_entry_checker_t *
checker_list_try_unnest_one_entry_in_submap(
	checker_list_t *checker_list,
	vm_entry_checker_t *submap_parent,
	bool unnest_readonly,
	mach_vm_address_t * const inout_next_address);

/*
 * Perform a clip-left operation on a checker, similar to vm_map_clip_left.
 * Entry `right` is divided at `split`.
 * Returns the new left-hand entry.
 * Returns NULL if no split occurred.
 * Updates list->head and/or list->tail if necessary.
 */
extern vm_entry_checker_t *
checker_clip_left(
	checker_list_t *list,
	vm_entry_checker_t *right,
	mach_vm_address_t split);

/*
 * Perform a clip-right operation on a checker, similar to vm_map_clip_right.
 * Entry `left` is divided at `split`.
 * Returns the new right-hand entry.
 * Returns NULL if no split occurred.
 * Updates list->head and/or list->tail if necessary.
 */
extern vm_entry_checker_t *
checker_clip_right(
	checker_list_t *list,
	vm_entry_checker_t *left,
	mach_vm_address_t split);

/*
 * Perform a simplify operation on a checker and the entry to its left.
 * If coalescing occurs, `right` is preserved and
 * the entry to the left is destroyed.
 */
extern void
checker_simplify_left(
	checker_list_t *list,
	vm_entry_checker_t *right);

/*
 * Clone a vm entry checker.
 * The new clone increases its object's refcount.
 * The new clone is not inserted into the checker list.
 * All other fields in the new checker are the same as the old.
 */
extern vm_entry_checker_t *
checker_clone(vm_entry_checker_t *old);

/*
 * Allocate a new checker for a guard page from allocate_with_guards().
 * Add it to the checker list's guard pages.
 */
extern void
append_checker_for_guard_page(
	checker_list_t *list,
	mach_vm_address_t address,
	mach_vm_size_t size);

/*
 * Build a vm_checker for a newly-created memory region.
 * The region is assumed to be the result of vm_allocate().
 * The new checker is not linked into the list.
 */
extern vm_entry_checker_t *
make_checker_for_vm_allocate(
	checker_list_t *list,
	mach_vm_address_t address,
	mach_vm_size_t size,
	int flags_and_tag);

/*
 * Clone a checker.
 * Update both checkers as if this were a VM copy operation.
 * The new checker is not inserted into the checker list.
 */
extern vm_entry_checker_t *
checker_clone_copy(checker_list_t *list, vm_entry_checker_t *src_checker);

/*
 * Clone a checker.
 * Update both checkers as if this were a VM share operation.
 * The new checker is not inserted into the checker list.
 */
extern vm_entry_checker_t *
checker_clone_share(checker_list_t *list, vm_entry_checker_t *src_checker);

/*
 * Create VM entries and VM entry checkers
 * for the given VM entry templates.
 *
 * Entries will be created consecutively in contiguous memory, as specified.
 * "Holes" will be deallocated during construction;
 *     be warned that the holes may become filled by other allocations
 *     including Rosetta's translations, which will cause the checker to
 *     fail later.
 *
 * Alignment handling:
 *     The first entry gets `alignment_mask` alignment.
 *     After that it is the caller's responsibility to arrange their
 *     templates in a way that yields the alignments they want.
 */
extern __attribute__((overloadable))
checker_list_t *
create_vm_state(
	const vm_entry_template_t entry_templates[],
	unsigned entry_template_count,
	const vm_object_template_t object_templates[],
	unsigned object_template_count,
	mach_vm_size_t alignment_mask,
	bool allocate_guard_pages,
	const char *message);

static inline __attribute__((overloadable))
checker_list_t *
create_vm_state(
	const vm_entry_template_t templates[],
	unsigned count,
	mach_vm_size_t alignment_mask)
{
	return create_vm_state(templates, count, NULL, 0,
	           alignment_mask, true /* guard pages */, "create_vm_state");
}

/*
 * Like create_vm_state, but the alignment mask defaults to PAGE_MASK
 * and the template list is terminated by END_ENTRIES
 */
static inline __attribute__((overloadable))
checker_list_t *
create_vm_state(const vm_entry_template_t templates[])
{
	return create_vm_state(templates, count_templates(templates), PAGE_MASK);
}

/*
 * Like create_vm_state, but the alignment mask defaults to PAGE_MASK.
 */
static inline __attribute__((overloadable))
checker_list_t *
create_vm_state(const vm_entry_template_t templates[], unsigned count)
{
	return create_vm_state(templates, count, PAGE_MASK);
}


/*
 * Verify that the VM's state (as determined by vm_region)
 * matches the expected state from a list of checkers.
 *
 * Returns TestSucceeded if the state is good, TestFailed otherwise.
 *
 * Failures are also reported as darwintest failures (typically T_FAIL)
 * and failure details of expected and actual state are reported with T_LOG.
 */
extern test_result_t
verify_vm_state(checker_list_t *checker_list, const char *message);

/*
 * Perform VM read and/or write faults on every page spanned by a list of checkers,
 * and verify that exceptions are delivered (or not) as expected.
 * This is a destructive test: the faults may change VM state (for example
 * resolving COW) but the checkers are not updated.
 *
 * Returns TestSucceeded if the state is good, TestFailed otherwise.
 *
 * Failures are also reported as darwintest failures (typically T_FAIL)
 * and failure details of expected and actual state are reported with T_LOG.
 */
extern test_result_t
verify_vm_faultability(
	checker_list_t *checker_list,
	const char *message,
	bool verify_reads,
	bool verify_writes);

/*
 * Like verify_vm_faultability, but reads and/or writes
 * from a single checker's memory.
 * Returns true if the verification succeeded.
 */
extern bool
verify_checker_faultability(
	vm_entry_checker_t *checker,
	const char *message,
	bool verify_reads,
	bool verify_writes);

/*
 * Like verify_checker_faultability, but reads and/or writes
 * only part of a single checker's memory.
 * Returns true if the verification succeeded.
 */
extern bool
verify_checker_faultability_in_address_range(
	vm_entry_checker_t *checker,
	const char *message,
	bool verify_reads,
	bool verify_writes,
	mach_vm_address_t checked_address,
	mach_vm_size_t checked_size);

/*
 * Specification for a single trial:
 * - the test's name
 * - the templates for the virtual memory layout
 * - the address range within that virtual memory
 *   layout that the tested operation should use.
 */
typedef struct vm_config_s {
	char *config_name;

	/*
	 * Test's start address is the start of the first
	 * entry plus start_adjustment. Test's end address
	 * is the end of the last entry plus end_adjustment.
	 * When not zero, start_adjustment is typically positive
	 * and end_adjustment is typically negative.
	 */
	mach_vm_size_t start_adjustment;
	mach_vm_size_t end_adjustment;

	/* First map entry gets this alignment. */
	mach_vm_size_t alignment_mask;

	vm_entry_template_t *entry_templates;
	unsigned entry_template_count;
	vm_object_template_t *object_templates;
	unsigned object_template_count;

	vm_entry_template_t *submap_entry_templates;
	unsigned submap_entry_template_count;
	vm_object_template_t *submap_object_templates;
	unsigned submap_object_template_count;
} vm_config_t;

__attribute__((overloadable))
extern vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	vm_object_template_t *object_templates,
	vm_entry_template_t *submap_entry_templates,
	vm_object_template_t *submap_object_templates,
	mach_vm_size_t start_adjustment,
	mach_vm_size_t end_adjustment,
	mach_vm_size_t alignment_mask);

/*
 * make_vm_config() variants with fewer parameters
 * (convenient for hardcoded initializer syntax)
 *
 * Variants that allow submap entries force submap-compatible alignment.
 * Variants without submap entries use no alignment.
 */

__attribute__((overloadable))
static inline vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	vm_object_template_t *object_templates,
	vm_entry_template_t *submap_entry_templates,
	vm_object_template_t *submap_object_templates,
	mach_vm_size_t start_adjustment,
	mach_vm_size_t end_adjustment)
{
	return make_vm_config(name, entry_templates, object_templates,
	           submap_entry_templates, submap_object_templates,
	           start_adjustment, end_adjustment, SUBMAP_ALIGNMENT_MASK);
}

__attribute__((overloadable))
static inline vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	vm_object_template_t *object_templates,
	mach_vm_size_t start_adjustment,
	mach_vm_size_t end_adjustment)
{
	return make_vm_config(name, entry_templates, object_templates,
	           NULL, NULL,
	           start_adjustment, end_adjustment, 0);
}

__attribute__((overloadable))
static inline vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	mach_vm_size_t start_adjustment,
	mach_vm_size_t end_adjustment)
{
	return make_vm_config(name, entry_templates, NULL,
	           NULL, NULL,
	           start_adjustment, end_adjustment, 0);
}

__attribute__((overloadable))
static inline vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	vm_object_template_t *object_templates)
{
	return make_vm_config(name, entry_templates, object_templates,
	           NULL, NULL,
	           0, 0, 0);
}

__attribute__((overloadable))
static inline vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates)
{
	return make_vm_config(name, entry_templates, NULL,
	           NULL, NULL,
	           0, 0, 0);
}


/*
 * Like create_vm_state, but also computes the config's desired address range.
 */
extern void
create_vm_state_from_config(
	vm_config_t *config,
	checker_list_t ** const out_checker_list,
	mach_vm_address_t * const out_start_address,
	mach_vm_address_t * const out_end_address);


/*
 * Logs the contents of checkers.
 * Also logs the contents of submap checkers recursively.
 */
extern void
dump_checker_range(entry_checker_range_t list);

/*
 * Logs info from vm_region() for the address ranges spanned by the checkers.
 * Also logs the contents of submaps recursively.
 */
extern void
dump_region_info_for_entries(entry_checker_range_t list);


/*
 * Convenience functions for logging.
 */

extern const char *
name_for_entry_kind(vm_entry_template_kind_t kind);

extern const char *
name_for_kr(kern_return_t kr);

extern const char *
name_for_prot(vm_prot_t prot);

extern const char *
name_for_inherit(vm_inherit_t inheritance);

extern const char *
name_for_behavior(vm_behavior_t behavior);

extern const char *
name_for_share_mode(uint8_t share_mode);

extern const char *
name_for_copy_strategy(copy_strategy_t copy_strat);

extern const char *
name_for_bool(boolean_t value);

/* Convenience macro for compile-time array size */
#define countof(array)                                                  \
	_Pragma("clang diagnostic push")                                \
	_Pragma("clang diagnostic error \"-Wsizeof-pointer-div\"")      \
	(sizeof(array)/sizeof((array)[0]))                              \
	_Pragma("clang diagnostic pop")

/* Convenience macro for a heap allocated formatted string deallocated at end of scope. */
static inline void
cleanup_cstring(char **ptr)
{
	free(*ptr);
}
#define CLEANUP_CSTRING __attribute__((cleanup(cleanup_cstring)))
#define TEMP_CSTRING(str, format, ...)          \
	char *str CLEANUP_CSTRING;              \
	asprintf(&str, format, __VA_ARGS__)

/*
 * Returns true if each bit set in `values` is also set in `container`.
 */
static inline bool
prot_contains_all(vm_prot_t container, vm_prot_t values)
{
	return (container & values) == values;
}

/*
 * Convenience functions for address arithmetic
 */

static inline mach_vm_address_t
max(mach_vm_address_t a, mach_vm_address_t b)
{
	if (a > b) {
		return a;
	} else {
		return b;
	}
}

static inline mach_vm_address_t
min(mach_vm_address_t a, mach_vm_address_t b)
{
	if (a < b) {
		return a;
	} else {
		return b;
	}
}

/*
 * Allocate with VM_FLAGS_RANDOM_ADDR and workaround its spurious failures.
 * T_FAILs if the allocation fails.
 */
extern mach_vm_address_t
allocate_at_random_address(
	mach_vm_size_t size,
	mach_vm_size_t alignment_mask,
	vm_prot_t cur_prot,
	vm_prot_t max_prot);

/*
 * Allocate at a random address, with guard pages before and after.
 * `guard_page_size` may be zero.
 * T_FAILs if the allocation fails.
 */
extern mach_vm_address_t
allocate_with_guards(
	mach_vm_size_t size,
	mach_vm_size_t alignment_mask,
	mach_vm_size_t guard_page_size,
	vm_prot_t cur_prot,
	vm_prot_t max_prot);

/*
 * Call vm_region on an address.
 * If the query address is mapped at that submap depth:
 *   - Sets *inout_address and *out_size to that map entry's address and size.
 *     [*inout_address, *inout_address + *out_size) contains the query address.
 *   - Sets the info from vm_region.
 *   - Returns true.
 * If the query address is unmapped, or not mapped at that submap depth:
 *   - Sets *inout_address to the address of the next map entry, or ~0 if there is none.
 *   - Sets *out_size to zero.
 *   - Returns false.
 */
__attribute__((overloadable))
extern bool
get_info_for_address(
	mach_vm_address_t *inout_address,
	mach_vm_size_t *out_size,
	vm_region_submap_info_data_64_t *out_info,
	uint32_t submap_depth);

__attribute__((overloadable))
static inline bool
get_info_for_address(
	mach_vm_address_t * const inout_address,
	mach_vm_size_t * const out_size,
	vm_region_submap_info_data_64_t * const out_info)
{
	return get_info_for_address(inout_address, out_size, out_info, 0);
}

/*
 * Like get_info_for_address(), but
 * (1) it's faster, and
 * (2) it does not get the right ref_count or shadow_depth values from vm_region.
 */
__attribute__((overloadable))
extern bool
get_info_for_address_fast(
	mach_vm_address_t *inout_address,
	mach_vm_size_t *out_size,
	vm_region_submap_info_data_64_t *out_info,
	uint32_t submap_depth);

__attribute__((overloadable))
static inline bool
get_info_for_address_fast(
	mach_vm_address_t * const inout_address,
	mach_vm_size_t * const out_size,
	vm_region_submap_info_data_64_t * const out_info)
{
	return get_info_for_address_fast(inout_address, out_size, out_info, 0);
}

/*
 * Convenience function to get object_id_full from vm_region at an address.
 * Returns zero if the address is mapped but has a null object.
 * Aborts if the address is not mapped.
 */
extern uint64_t
get_object_id_for_address(mach_vm_address_t address);

/*
 * Convenience function to get user_tag from vm_region at an address.
 * Returns zero if the address is not mapped.
 */
extern uint16_t
get_user_tag_for_address(mach_vm_address_t address);

/*
 * Convenience function to get user_tag from vm_region at an address,
 * if that tag is within the app-specific tag range.
 * Returns zero if the address is not mapped.
 * Returns zero if the address's tag is not within the app-specific range
 * [VM_MEMORY_APPLICATION_SPECIFIC_1, VM_MEMORY_APPLICATION_SPECIFIC_16]
 *
 * This is used by tests that copy user tags from nearby memory.
 * The "nearby" memory might not be part of the tested range.
 * Copying an arbitrary user tag from outside is undesirable
 * because the VM changes some of its behavior for some tag
 * values and the tests need to see consistent behavior instead.
 */
extern uint16_t
get_app_specific_user_tag_for_address(mach_vm_address_t address);

/*
 * Convenience functions for vm_wire's host_priv port.
 * host_priv() returns the port, or halts if it can't.
 * host_priv_allowed() returns true or false.
 * The host_priv port requires root on macOS.
 */
extern host_priv_t
host_priv(void);

extern bool
host_priv_allowed(void);

/*
 * Return xnu's internal page size.
 * The userspace PAGE_SIZE may be smaller (e.g. Rosetta Intel on ARM).
 */
static inline uint32_t
xnu_vm_page_size(void)
{
	static dispatch_once_t once;
	static uint32_t vm_page_size;
	dispatch_once(&once, ^{
		size_t len = sizeof(vm_page_size);
		int err = sysctlbyname("vm.pagesize", &vm_page_size, &len, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "sysctlbyname('vm.pagesize')");
		T_QUIET; T_ASSERT_GE(len, sizeof(vm_page_size), "sysctl result size");
	});
	return vm_page_size;
}

#endif  /* VM_CONFIGURATOR_H */
