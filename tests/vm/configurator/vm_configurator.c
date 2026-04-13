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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <machine/endian.h>

#include "try_read_write.h"
#include "exc_helpers.h"
#include "exc_guard_helper.h"
#include "vm_configurator.h"
#include "vm_configurator_tests.h"

#pragma clang diagnostic ignored "-Wgnu-conditional-omitted-operand"
#pragma clang diagnostic ignored "-Wformat-pedantic"

bool Verbose = false;

/* TODO: sufficiently new SDK defines this */
#ifndef VM_BEHAVIOR_LAST_VALID
#define VM_BEHAVIOR_LAST_VALID VM_BEHAVIOR_ZERO
#endif

#define KB16 16384
#define MB (1024*1024)

/* pretty printing */

/* indentation printed in front of submap contents */
#define SUBMAP_PREFIX "    .   "

/*
 * Used when printing attributes of checkers and vm regions.
 * BadHighlight gets a highlighted color and "*" marker.
 * NormalHighlight gets normal color.
 * IgnoredHighlight gets dimmed color.
 */
typedef enum {
	BadHighlight = 0,
	NormalHighlight,
	IgnoredHighlight,
	HighlightCount
} attribute_highlight_t;

/*
 * Specify highlights for all entry and object attributes.
 * Used when printing entire checkers or VM states.
 */
typedef struct {
	attribute_highlight_t highlighting;
	vm_entry_attribute_list_t entry;
	vm_object_attribute_list_t object;
} attribute_highlights_t;

/*
 * Print all attributes as NormalHighlight.
 */
static attribute_highlights_t
normal_highlights(void)
{
	return (attribute_highlights_t) {
		       .highlighting = NormalHighlight,
		       .entry = vm_entry_attributes_with_default(true),
		       .object = vm_object_attributes_with_default(true),
	};
}

/*
 * Print bad_entry_attr and bad_object_attr as BadHighlight.
 * Print other attributes as IgnoredHighlight.
 */
static attribute_highlights_t
bad_or_ignored_highlights(
	vm_entry_attribute_list_t bad_entry_attr,
	vm_object_attribute_list_t bad_object_attr)
{
	return (attribute_highlights_t) {
		       .highlighting = BadHighlight,
		       .entry = bad_entry_attr,
		       .object = bad_object_attr,
	};
}

/*
 * Print normal_entry_attr and normal_object_attr as NormalHighlight.
 * Print other attributes as IgnoredHighlight.
 */
static attribute_highlights_t
normal_or_ignored_highlights(
	vm_entry_attribute_list_t normal_entry_attr,
	vm_object_attribute_list_t normal_object_attr)
{
	return (attribute_highlights_t) {
		       .highlighting = NormalHighlight,
		       .entry = normal_entry_attr,
		       .object = normal_object_attr,
	};
}

/* Return true if we should print terminal color codes. */
static bool
use_colors(void)
{
	static int stdout_is_tty = -1;
	if (stdout_is_tty == -1) {
		stdout_is_tty = isatty(STDOUT_FILENO);
	}
	return stdout_is_tty;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpedantic"
/* -Wpedantic doesn't like "\e" */

#define ANSI_DIM "\e[2m"
#define ANSI_UNDIM "\e[22m"

/*
 * Returns a highlighting prefix string.
 * Its printed length is one character, either ' ' or '*'
 * It may include ANSI color codes.
 */
static const char *
highlight_prefix(attribute_highlight_t highlight)
{
	assert(highlight >= 0 && highlight < HighlightCount);
	static const char * highlights[2][HighlightCount] = {
		[0] = {
			/* no tty, omit color codes */
			[BadHighlight] = "*",
			[NormalHighlight] = " ",
			[IgnoredHighlight] = " ",
		},
		[1] = {
			/* tty, add color codes */
			[BadHighlight] = "*",
			[NormalHighlight] = " ",
			[IgnoredHighlight] = ANSI_DIM " ",
		}
	};

	return highlights[use_colors()][highlight];
}

/*
 * Returns a highlighting suffix string.
 * Its printed length is zero characters.
 * It may include ANSI color codes.
 */
static const char *
highlight_suffix(attribute_highlight_t highlight __unused)
{
	if (use_colors()) {
		return ANSI_UNDIM;
	} else {
		return "";
	}
}

#pragma clang diagnostic pop  /* ignored -Wpedantic */

/*
 * Format a value with highlighting.
 * Usage:
 *     printf("%sFFFF%s", HIGHLIGHT(value, entry.some_attr));
 * where "FFFF" is the format string for `value`
 * and `highlights.entry.some_attr` is true for highlighted values.
 *
 * Uses `highlights.highlighting` if `highlights.entry.some_attr` is true.
 * Uses `IgnoredHighlight` if `highlights.entry.some_attr` is false.
 */
#define HIGHLIGHT(value, attr_path)                             \
	    highlight_prefix(highlights.attr_path ? highlights.highlighting : IgnoredHighlight), \
	    (value),                                            \
	    highlight_suffix(highlights.attr_path ? highlights.highlighting : IgnoredHighlight)


/* host_priv port wrappers */

host_priv_t
host_priv(void)
{
	host_priv_t result;
	kern_return_t kr = host_get_host_priv_port(mach_host_self(), &result);
	assert(kr == 0 && "cannot get host_priv port; try running as root");
	return result;
}

bool
host_priv_allowed(void)
{
	host_priv_t result;
	kern_return_t kr = host_get_host_priv_port(mach_host_self(), &result);
	return kr == 0;
}

/* math */

static bool
is_power_of_two(mach_vm_size_t n)
{
	return n > 0 && (n & (n - 1)) == 0;
}

static bool
is_valid_alignment_mask(mach_vm_size_t mask)
{
	if (mask == 0) {
		return true;
	}

	mach_vm_size_t pow = mask + 1; /* may wrap around to zero */
	if (pow == 0) {
		return true; /* mask is ~0, mask + 1 wrapped to zero */
	}

	return is_power_of_two(pow);
}

/*
 * Some vm_behavior_t values have a persistent effect on the vm entry.
 * Other behavior values are really one-shot memory operations.
 */
static bool
is_persistent_vm_behavior(vm_behavior_t behavior)
{
	return
	        behavior == VM_BEHAVIOR_DEFAULT ||
	        behavior == VM_BEHAVIOR_RANDOM ||
	        behavior == VM_BEHAVIOR_SEQUENTIAL ||
	        behavior == VM_BEHAVIOR_RSEQNTL;
}


const char *
name_for_entry_kind(vm_entry_template_kind_t kind)
{
	static const char *kind_name[] = {
		"END_ENTRIES", "allocation", "hole", "submap parent", "guard page"
	};
	assert(kind < countof(kind_name));
	return kind_name[kind];
}

const char *
name_for_kr(kern_return_t kr)
{
	static const char *kr_name[] = {
		"KERN_SUCCESS", "KERN_INVALID_ADDRESS",
		"KERN_PROTECTION_FAILURE", "KERN_NO_SPACE",
		"KERN_INVALID_ARGUMENT", "KERN_FAILURE",
		"KERN_RESOURCE_SHORTAGE", "KERN_NOT_RECEIVER",
		"KERN_NO_ACCESS", "KERN_MEMORY_FAILURE",
		"KERN_MEMORY_ERROR", "KERN_ALREADY_IN_SET",
		"KERN_NOT_IN_SET", "KERN_NAME_EXISTS",
		"KERN_ABORTED", "KERN_INVALID_NAME",
		"KERN_INVALID_TASK", "KERN_INVALID_RIGHT",
		"KERN_INVALID_VALUE", "KERN_UREFS_OVERFLOW",
		"KERN_INVALID_CAPABILITY", "KERN_RIGHT_EXISTS",
		"KERN_INVALID_HOST", "KERN_MEMORY_PRESENT",
		/* add other kern_return.h values here if desired */
	};

	if ((size_t)kr < countof(kr_name)) {
		return kr_name[kr];
	}

	/* TODO: recognize and/or decode mach_error format? */

	return "??";
}

const char *
name_for_prot(vm_prot_t prot)
{
	assert(prot_contains_all(VM_PROT_ALL /* rwx */, prot));
	/* TODO: uexec? */
	static const char *prot_name[] = {
		"---", "r--", "-w-", "rw-",
		"--x", "r-x", "-wx", "rwx"
	};
	return prot_name[prot];
}

const char *
name_for_inherit(vm_inherit_t inherit)
{
	static const char *inherit_name[] = {
		[VM_INHERIT_SHARE] = "VM_INHERIT_SHARE",
		[VM_INHERIT_COPY]  = "VM_INHERIT_COPY",
		[VM_INHERIT_NONE]  = "VM_INHERIT_NONE",
	};
	static_assert(countof(inherit_name) == VM_INHERIT_LAST_VALID + 1,
	    "new vm_inherit_t values need names");

	assert(inherit <= VM_INHERIT_LAST_VALID);
	return inherit_name[inherit];
}

const char *
name_for_behavior(vm_behavior_t behavior)
{
	static const char *behavior_name[] = {
		[VM_BEHAVIOR_DEFAULT]          = "VM_BEHAVIOR_DEFAULT",
		[VM_BEHAVIOR_RANDOM]           = "VM_BEHAVIOR_RANDOM",
		[VM_BEHAVIOR_SEQUENTIAL]       = "VM_BEHAVIOR_SEQUENTIAL",
		[VM_BEHAVIOR_RSEQNTL]          = "VM_BEHAVIOR_RSEQNTL",
		[VM_BEHAVIOR_WILLNEED]         = "VM_BEHAVIOR_WILLNEED",
		[VM_BEHAVIOR_DONTNEED]         = "VM_BEHAVIOR_DONTNEED",
		[VM_BEHAVIOR_FREE]             = "VM_BEHAVIOR_FREE",
		[VM_BEHAVIOR_ZERO_WIRED_PAGES] = "VM_BEHAVIOR_ZERO_WIRED_PAGES",
		[VM_BEHAVIOR_REUSABLE]         = "VM_BEHAVIOR_REUSABLE",
		[VM_BEHAVIOR_REUSE]            = "VM_BEHAVIOR_REUSE",
		[VM_BEHAVIOR_CAN_REUSE]        = "VM_BEHAVIOR_CAN_REUSE",
		[VM_BEHAVIOR_PAGEOUT]          = "VM_BEHAVIOR_PAGEOUT",
		[VM_BEHAVIOR_ZERO]             = "VM_BEHAVIOR_ZERO",
	};
	static_assert(countof(behavior_name) == VM_BEHAVIOR_LAST_VALID + 1,
	    "new vm_behavior_t values need names");

	assert(behavior >= 0 && behavior <= VM_BEHAVIOR_LAST_VALID);
	return behavior_name[behavior];
}

const char *
name_for_share_mode(uint8_t share_mode)
{
	assert(share_mode > 0);
	static const char *share_mode_name[] = {
		[0]                  = "(0)",
		[SM_COW]             = "SM_COW",
		[SM_PRIVATE]         = "SM_PRIVATE",
		[SM_EMPTY]           = "SM_EMPTY",
		[SM_SHARED]          = "SM_SHARED",
		[SM_TRUESHARED]      = "SM_TRUESHARED",
		[SM_PRIVATE_ALIASED] = "SM_PRIVATE_ALIASED",
		[SM_SHARED_ALIASED]  = "SM_SHARED_ALIASED",
		[SM_LARGE_PAGE]      = "SM_LARGE_PAGE"
	};

	assert(share_mode < countof(share_mode_name));
	return share_mode_name[share_mode];
}

const char *
name_for_copy_strategy(copy_strategy_t copy_strategy)
{
	static const char *names[] = {
		[copy_none] = "copy_none",
		[copy_delay] = "copy_delay",
		[copy_symmetric] = "copy_symmetric",
		[copy_delay_fork] = "copy_delay_fork",
	};
	if (copy_strategy < countof(names)) {
		const char *result = names[copy_strategy];
		if (result) {
			return result;
		}
	} else if (copy_strategy == copy_invalid) {
		return "(invalid copy strategy)";
	}
	return "(unknown copy strategy)";
}

const char *
name_for_bool(boolean_t value)
{
	switch (value) {
	case 0:  return "false";
	case 1:  return "true";
	default: return "true-but-not-1";
	}
}


void
clamp_start_end_to_start_end(
	mach_vm_address_t   * const inout_start,
	mach_vm_address_t   * const inout_end,
	mach_vm_address_t           limit_start,
	mach_vm_address_t           limit_end)
{
	if (*inout_start < limit_start) {
		*inout_start = limit_start;
	}

	if (*inout_end > limit_end) {
		*inout_end = limit_end;
	}

	if (*inout_start > *inout_end) {
		/* no-overlap case */
		*inout_end = *inout_start;
	}
}

void
clamp_address_size_to_address_size(
	mach_vm_address_t   * const inout_address,
	mach_vm_size_t      * const inout_size,
	mach_vm_address_t           limit_address,
	mach_vm_size_t              limit_size)
{
	mach_vm_address_t end = *inout_address + *inout_size;
	mach_vm_address_t limit_end = limit_address + limit_size;
	clamp_start_end_to_start_end(inout_address, &end, limit_address, limit_end);
	*inout_size = end - *inout_address;
}

void
clamp_address_size_to_checker(
	mach_vm_address_t   * const inout_address,
	mach_vm_size_t      * const inout_size,
	vm_entry_checker_t         *checker)
{
	clamp_address_size_to_address_size(
		inout_address, inout_size,
		checker->address, checker->size);
}

void
clamp_start_end_to_checker(
	mach_vm_address_t   * const inout_start,
	mach_vm_address_t   * const inout_end,
	vm_entry_checker_t         *checker)
{
	clamp_start_end_to_start_end(
		inout_start, inout_end,
		checker->address, checker_end_address(checker));
}


uint64_t
get_object_id_for_address(mach_vm_address_t address)
{
	mach_vm_address_t info_address = address;
	mach_vm_size_t info_size;
	vm_region_submap_info_data_64_t info;

	bool found = get_info_for_address_fast(&info_address, &info_size, &info);
	assert(found);
	assert(info_address == address);
	return info.object_id_full;
}

uint16_t
get_user_tag_for_address(mach_vm_address_t address)
{
	mach_vm_address_t info_address = address;
	mach_vm_size_t info_size;
	vm_region_submap_info_data_64_t info;

	bool found = get_info_for_address_fast(&info_address, &info_size, &info);
	if (found) {
		return info.user_tag;
	} else {
		return 0;
	}
}

uint16_t
get_app_specific_user_tag_for_address(mach_vm_address_t address)
{
	uint16_t tag = get_user_tag_for_address(address);
	if (tag < VM_MEMORY_APPLICATION_SPECIFIC_1 ||
	    tag > VM_MEMORY_APPLICATION_SPECIFIC_16) {
		/* tag is outside app-specific range, override it */
		return 0;
	}
	return tag;
}

static void
set_vm_self_region_footprint(bool value)
{
	int value_storage = value;
	int error = sysctlbyname("vm.self_region_footprint", NULL, NULL, &value_storage, sizeof(value_storage));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(error, "sysctl(vm.self_region_footprint)");
}

bool __attribute__((overloadable))
get_info_for_address_fast(
	mach_vm_address_t * const inout_address,
	mach_vm_size_t * const out_size,
	vm_region_submap_info_data_64_t * const out_info,
	uint32_t submap_depth)
{
	kern_return_t kr;

	mach_vm_address_t query_address = *inout_address;
	mach_vm_address_t actual_address = query_address;
	uint32_t actual_depth = submap_depth;
	mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
	kr = mach_vm_region_recurse(mach_task_self(),
	    &actual_address, out_size, &actual_depth,
	    (vm_region_recurse_info_t)out_info,
	    &count);

	if (kr == KERN_INVALID_ADDRESS || actual_depth < submap_depth) {
		/* query_address is unmapped, and so is everything after it */
		*inout_address = ~(mach_vm_address_t)0;
		*out_size = 0;
		return false;
	}
	assert(kr == 0);
	if (actual_address > query_address) {
		/* query_address is unmapped, but there is a subsequent mapping */
		*inout_address = actual_address;
		/* *out_size already set */
		return false;
	}

	/* query_address is mapped */
	*inout_address = actual_address;
	/* *out_size already set */
	return true;
}

bool __attribute__((overloadable))
get_info_for_address(
	mach_vm_address_t * const inout_address,
	mach_vm_size_t * const out_size,
	vm_region_submap_info_data_64_t * const out_info,
	uint32_t submap_depth)
{
	mach_vm_address_t addr1, addr2;
	mach_vm_size_t size1 = 0, size2 = 0;
	vm_region_submap_info_data_64_t info1, info2;
	bool result1, result2;

	/*
	 * VM's task_self_region_footprint() changes
	 * how vm_map_region_walk() counts things.
	 *
	 * We want the ref_count and shadow_depth from footprint==true
	 * (ignoring the specific pages in the objects)
	 * but we want pages_resident from footprint==false.
	 *
	 * Here we call vm_region once with footprint and once without,
	 * and pick out the values we want to return.
	 */

	set_vm_self_region_footprint(true);
	addr1 = *inout_address;
	result1 = get_info_for_address_fast(&addr1, &size1, &info1, submap_depth);

	set_vm_self_region_footprint(false);
	addr2 = *inout_address;
	result2 = get_info_for_address_fast(&addr2, &size2, &info2, submap_depth);
	assert(addr1 == addr2);
	assert(size1 == size2);
	assert(result1 == result2);

	info1.pages_resident = info2.pages_resident;
	*out_info = info1;
	*inout_address = addr1;
	*out_size = size1;

	return result1;
}

static bool
is_mapped(mach_vm_address_t address, uint32_t submap_depth)
{
	mach_vm_size_t size;
	vm_region_submap_info_data_64_t info;
	return get_info_for_address_fast(&address, &size, &info, submap_depth);
}


static void
dump_region_info(
	mach_vm_address_t address,
	mach_vm_size_t size,
	uint32_t submap_depth,
	vm_region_submap_info_data_64_t *info,
	attribute_highlights_t highlights)
{
	mach_vm_address_t end = address + size;

	const char *suffix = "";
	if (info->is_submap) {
		suffix = " (submap parent)";
	} else if (submap_depth > 0) {
		suffix = " (allocation in submap)";
	}

	const char *submap_prefix = submap_depth > 0 ? SUBMAP_PREFIX : "";

	/* Output order should match dump_checker_info() for the reader's convenience. */

	T_LOG("%sMAPPING   0x%llx..0x%llx (size 0x%llx)%s", submap_prefix, address, end, size, suffix);
	T_LOG("%s    %sprotection:     %s%s", submap_prefix, HIGHLIGHT(name_for_prot(info->protection), entry.protection_attr));
	T_LOG("%s    %smax protection: %s%s", submap_prefix, HIGHLIGHT(name_for_prot(info->max_protection), entry.max_protection_attr));
	T_LOG("%s    %sinheritance:    %s%s", submap_prefix, HIGHLIGHT(name_for_inherit(info->inheritance), entry.inheritance_attr));
	T_LOG("%s    %sbehavior:       %s%s", submap_prefix, HIGHLIGHT(name_for_behavior(info->behavior), entry.behavior_attr));
	T_LOG("%s    %suser wired count:  %d%s", submap_prefix, HIGHLIGHT(info->user_wired_count, entry.user_wired_count_attr));
	T_LOG("%s    %suser tag:       %d%s", submap_prefix, HIGHLIGHT(info->user_tag, entry.user_tag_attr));
	T_LOG("%s    %sobject offset:  0x%llx%s", submap_prefix, HIGHLIGHT(info->offset, entry.object_offset_attr));
	T_LOG("%s    %sobject id:      0x%llx%s", submap_prefix, HIGHLIGHT(info->object_id_full, object.object_id_attr));
	T_LOG("%s    %sref count:      %u%s", submap_prefix, HIGHLIGHT(info->ref_count, object.ref_count_attr));
	T_LOG("%s    %sshadow depth:   %hu%s", submap_prefix, HIGHLIGHT(info->shadow_depth, object.shadow_depth_attr));
	T_LOG("%s    %spages resident: %u%s", submap_prefix, HIGHLIGHT(info->pages_resident, entry.pages_resident_attr));
	T_LOG("%s    %spages shared now private: %u%s", submap_prefix, highlight_prefix(IgnoredHighlight), info->pages_shared_now_private, highlight_suffix(IgnoredHighlight));
	T_LOG("%s    %spages swapped out: %u%s", submap_prefix, highlight_prefix(IgnoredHighlight), info->pages_swapped_out, highlight_suffix(IgnoredHighlight));
	T_LOG("%s    %spages dirtied:  %u%s", submap_prefix, highlight_prefix(IgnoredHighlight), info->pages_dirtied, highlight_suffix(IgnoredHighlight));
	T_LOG("%s    %sexternal pager: %hhu%s", submap_prefix, highlight_prefix(IgnoredHighlight), info->external_pager, highlight_suffix(IgnoredHighlight));
	T_LOG("%s    %sshare mode:     %s%s", submap_prefix, HIGHLIGHT(name_for_share_mode(info->share_mode), entry.share_mode_attr));
	T_LOG("%s    %sis submap:      %s%s", submap_prefix, HIGHLIGHT(name_for_bool(info->is_submap), entry.is_submap_attr));
	T_LOG("%s    %ssubmap depth:   %u%s", submap_prefix, HIGHLIGHT(submap_depth, entry.submap_depth_attr));
}

static void
dump_hole_info(
	mach_vm_address_t address,
	mach_vm_size_t size,
	uint32_t submap_depth,
	attribute_highlights_t highlights)
{
	mach_vm_address_t end = address + size;
	const char *submap_prefix = submap_depth > 0 ? SUBMAP_PREFIX : "";
	const char *suffix = "";
	if (submap_depth > 0) {
		suffix = " (unallocated in submap)";
	}

	T_LOG("%sHOLE 0x%llx..0x%llx (size 0x%llx)%s",
	    submap_prefix, address, end, size, suffix);
	if (submap_depth > 0) {
		/* print submap depth to avoid confusion about holes inside submaps */
		T_LOG("%s    %ssubmap depth:   %u%s", submap_prefix, HIGHLIGHT(submap_depth, entry.submap_depth_attr));
	}
}

static void
dump_region_info_in_range(
	mach_vm_address_t range_start,
	mach_vm_size_t range_size,
	uint32_t submap_depth,
	bool recurse,
	attribute_highlights_t highlights)
{
	mach_vm_address_t range_end = range_start + range_size;
	mach_vm_address_t prev_end = range_start;
	do {
		mach_vm_address_t address = prev_end;
		mach_vm_size_t size = 0;
		vm_region_submap_info_data_64_t info;
		(void)get_info_for_address(&address, &size, &info, submap_depth);
		/*
		 * [address, address+size) is the next mapped region,
		 * or [~0, ~0) if there is no next mapping.
		 * There may be a hole preceding that region.
		 * That region may be beyond our range.
		 */
		if (address > prev_end) {
			/* don't report any part of the hole beyond range_end */
			mach_vm_address_t hole_end = min(address, range_end);
			dump_hole_info(prev_end, hole_end - prev_end, submap_depth, highlights);
		}
		if (address < range_end) {
			dump_region_info(address, size, submap_depth, &info, highlights);
			if (info.is_submap && recurse) {
				/* print submap contents within this window */
				mach_vm_address_t submap_start = max(prev_end, address);
				mach_vm_address_t submap_end = min(range_end, address + size);
				dump_region_info_in_range(submap_start, submap_end - submap_start,
				    submap_depth + 1, true, highlights);
			}
		}
		prev_end = address + size;
	} while (prev_end < range_end);
}


static void
dump_region_info_for_entry(
	vm_entry_checker_t *checker,
	attribute_highlights_t highlights)
{
	/* Try to print at the checker's submap depth only. Don't recurse. */
	dump_region_info_in_range(checker->address, checker->size,
	    checker->submap_depth, false /* recurse */, highlights);
}

void
dump_region_info_for_entries(entry_checker_range_t list)
{
	/*
	 * Ignore the submap depth of the checkers themselves.
	 * Print starting at submap depth 0 and recurse.
	 * Don't specially highlight any attributes.
	 *
	 * Prefer to dump large contiguous ranges in case the
	 * checkers boundaries don't match the real map entries.
	 * (The checker list may not be a single contiguous range
	 * thanks to tests like vm_remap (out) which add new
	 * checkers far away from the original address range.)
	 */

	/* Repeatedly accumulate a range of contiguous checkers and print it. */
	mach_vm_address_t print_start = 0;
	mach_vm_address_t print_size = 0;
	FOREACH_CHECKER(checker, list) {
		if (checker->address == print_start + print_size) {
			/* This checker is contiguous; just add it in. */
			print_size += checker->size;
		} else {
			/*
			 * This checker is discontiguous.
			 * Print the previous range and start a new one.
			 */
			if (print_size > 0) {
				dump_region_info_in_range(
					print_start, print_size,
					0 /* submap depth */, true /* recurse */,
					normal_highlights());
			}
			print_start = checker->address;
			print_size = checker->size;
		}
	}

	/* Print the last unprinted range, if any. */
	if (print_size > 0) {
		dump_region_info_in_range(
			print_start, print_size,
			0 /* submap depth */, true /* recurse */,
			normal_highlights());
	}
}

/*
 * Count the number of templates in a END_ENTRIES-terminated list.
 */
static unsigned
count_entry_templates(const vm_entry_template_t *templates)
{
	if (templates == NULL) {
		return 0;
	}
	for (unsigned count = 0;; count++) {
		if (templates[count].kind == EndEntries) {
			return count;
		}
	}
}

/*
 * Count the number of templates in a END_OBJECTS-terminated list.
 */
static unsigned
count_object_templates(const vm_object_template_t *templates)
{
	if (templates == NULL) {
		return 0;
	}
	for (unsigned count = 0;; count++) {
		if (templates[count].kind == EndObjects) {
			return count;
		}
	}
}

/* conveniences for some macros elsewhere */
static unsigned
count_submap_object_templates(const vm_object_template_t *templates)
{
	return count_object_templates(templates);
}
static unsigned
count_submap_entry_templates(const vm_entry_template_t *templates)
{
	return count_entry_templates(templates);
}


static vm_object_checker_t *
object_checker_new(void)
{
	return calloc(sizeof(vm_object_checker_t), 1);
}

bool
object_is_null(vm_object_checker_t *obj_checker)
{
	if (obj_checker == NULL) {
		return true;
	}
	assert(obj_checker->kind != Deinited);
	assert(obj_checker->kind != FreedObject);
	assert(obj_checker->kind != EndObjects);
	if (obj_checker->object_id_mode == object_has_known_id) {
		return obj_checker->object_id == 0;
	}
	return false;
}

static void
object_checker_set_shadow(vm_object_checker_t *obj_checker,
    vm_object_checker_t *shadow)
{
	object_checker_reference(shadow);
	if (obj_checker->shadow) {
		object_checker_dereference(obj_checker->shadow);
	}
	obj_checker->shadow = shadow;
}

static unsigned
object_checker_get_shadow_depth(vm_object_checker_t *obj_checker)
{
	if (obj_checker == NULL || obj_checker->shadow == NULL) {
		return 0;
	}
	assert(!object_is_null(obj_checker));  /* null object must have no shadow */
	return 1 + object_checker_get_shadow_depth(obj_checker->shadow);
}

static unsigned
object_checker_get_self_ref_count(vm_object_checker_t *obj_checker)
{
	if (object_is_null(obj_checker)) {
		/* null object always has zero self_ref_count */
		return 0;
	} else {
		return obj_checker->self_ref_count;
	}
}

/*
 * ref_count as reported by vm_region is:
 * this object's self_ref_count
 * plus all object self_ref_counts in its shadow chain
 * minus the number of objects in its shadow chain
 * (i.e. discounting the references internal to the shadow chain)
 * TODO: also discounting references due to paging_in_progress
 */
static unsigned
object_checker_get_vm_region_ref_count(vm_object_checker_t *obj_checker)
{
	unsigned count = object_checker_get_self_ref_count(obj_checker);
	while ((obj_checker = obj_checker->shadow)) {
		count += object_checker_get_self_ref_count(obj_checker) - 1;
	}
	return count;
}

void
object_checker_reference(vm_object_checker_t *obj_checker)
{
	if (!object_is_null(obj_checker)) {
		obj_checker->self_ref_count++;
	}
}

static void object_checker_deinit(vm_object_checker_t *obj_checker); /* forward */
static void checker_list_free(checker_list_t *checker_list); /* forward */

void
object_checker_dereference(vm_object_checker_t *obj_checker)
{
	if (!object_is_null(obj_checker)) {
		assert(obj_checker->self_ref_count > 0);
		obj_checker->self_ref_count--;
		if (obj_checker->self_ref_count == 0) {
			/*
			 * We can't free this object checker because
			 * a checker list may still point to it.
			 * But we do tear down some of its contents.
			 */
			object_checker_deinit(obj_checker);
		}
	}
}

static void
object_checker_deinit(vm_object_checker_t *obj_checker)
{
	if (obj_checker->kind != Deinited) {
		object_checker_dereference(obj_checker->shadow);
		obj_checker->shadow = NULL;
		obj_checker->vo_copy = NULL;
		free(obj_checker->pages);
		obj_checker->pages = NULL;

		if (obj_checker->submap_checkers) {
			assert(obj_checker->kind == SubmapObject);
			/* submap checker list must not store objects */
			assert(obj_checker->submap_checkers->objects == NULL);
			checker_list_free(obj_checker->submap_checkers);
		}

		/*
		 * Previously we kept the object_id intact so we could
		 * detect usage of an object that the checkers thought
		 * was dead. This caused false failures when the VM's
		 * vm_object_t allocator re-used an object pointer.
		 * Now we scrub the object_id of deinited objects
		 * so that vm_object_t pointer reuse is allowed.
		 */
		obj_checker->object_id_mode = object_has_known_id;
		obj_checker->object_id = ~0;
		obj_checker->kind = Deinited;
	}
}

static void
object_checker_free(vm_object_checker_t *obj_checker)
{
	object_checker_deinit(obj_checker);
	free(obj_checker);
}

vm_object_checker_t *
object_checker_clone(vm_object_checker_t *old_checker)
{
	assert(old_checker->kind != Deinited);
	assert(old_checker->kind != SubmapObject);  /* unimplemented */

	vm_object_checker_t *new_checker = object_checker_new();
	new_checker->next = NULL;
	new_checker->prev = NULL;

	new_checker->kind = old_checker->kind;
	new_checker->verify = old_checker->verify;

	new_checker->object_id = 0;
	new_checker->object_id_mode = object_is_unknown;
	new_checker->copy_strategy = copy_symmetric;

	new_checker->self_ref_count = 0;
	new_checker->size = old_checker->size;
	new_checker->fill_pattern = old_checker->fill_pattern;
	new_checker->pages = calloc(new_checker->size / xnu_vm_page_size(), sizeof(page_status_t));
	new_checker->shadow = NULL;
	new_checker->shadow_offset = 0;
	new_checker->vo_copy = NULL;
	new_checker->submap_checkers = NULL;

	return new_checker;
}


/*
 * Search a checker list for an object with the given object_id.
 * Returns if no object is known to have that id.
 */
static vm_object_checker_t *
find_object_checker_for_object_id(checker_list_t *list, uint64_t object_id)
{
	/* object list is only stored in the top-level checker list */
	if (list->parent) {
		return find_object_checker_for_object_id(list->parent, object_id);
	}

	/* first object must be the null object */
	assert(list->objects && object_is_null(list->objects));

	FOREACH_OBJECT_CHECKER(obj_checker, list) {
		assert(obj_checker->kind != FreedObject);
		switch (obj_checker->object_id_mode) {
		case object_is_unknown:
		case object_has_unknown_nonnull_id:
			/* nope */
			break;
		case object_has_known_id:
			if (object_id == obj_checker->object_id) {
				assert(obj_checker->kind != Deinited);
				return obj_checker;
			}
			break;
		}
	}

	return NULL;
}

/*
 * Create a new object checker for the null vm object.
 */
static vm_object_checker_t *
make_null_object_checker(checker_list_t *checker_list)
{
	vm_object_checker_t *obj_checker = object_checker_new();
	obj_checker->kind = Anonymous;
	obj_checker->verify = vm_object_attributes_with_default(true);

	obj_checker->object_id_mode = object_has_known_id;
	obj_checker->object_id = 0;
	obj_checker->copy_strategy = copy_invalid;  /* NULL object doesn't have a copy strategy */

	obj_checker->size = ~0u;
	obj_checker->self_ref_count = 0;
	obj_checker->fill_pattern.mode = DontFill;

	obj_checker->next = NULL;
	obj_checker->prev = NULL;

	/* null object must be the first in the list */
	assert(checker_list->objects == NULL);
	checker_list->objects = obj_checker;

	return obj_checker;
}

/*
 * Create a new object checker for anonymous memory.
 * The new object checker is added to the checker list.
 */
static vm_object_checker_t *
make_anonymous_object_checker(checker_list_t *checker_list, mach_vm_size_t size)
{
	vm_object_checker_t *obj_checker = object_checker_new();
	obj_checker->kind = Anonymous;
	obj_checker->verify = vm_object_attributes_with_default(true);

	/* don't know the object's id yet, we'll look it up later */
	obj_checker->object_id_mode = object_is_unknown;
	obj_checker->object_id = 0;
	obj_checker->copy_strategy = copy_symmetric;

	obj_checker->size = size;
	obj_checker->self_ref_count = 0;
	obj_checker->fill_pattern.mode = DontFill;
	obj_checker->pages = calloc(size / xnu_vm_page_size(), sizeof(page_status_t));

	obj_checker->next = NULL;
	obj_checker->prev = NULL;

	checker_list_append_object(checker_list, obj_checker);

	return obj_checker;
}

static void checker_list_move_objects_to_parent(checker_list_t *submap_list); /* forward */

/*
 * Create a new object checker for a parent map submap entry's object.
 * The submap's contents are verified using submap_checkers.
 * The new object checker takes ownership of submap_checkers.
 * The new object checker is added to the checker list.
 */
static vm_object_checker_t *
make_submap_object_checker(
	checker_list_t *checker_list,
	checker_list_t *submap_checkers)
{
	/* address range where the submap is currently mapped */
	mach_vm_address_t submap_start = checker_range_start_address(submap_checkers->entries);
	mach_vm_address_t submap_size = checker_range_size(submap_checkers->entries);
	vm_object_checker_t *obj_checker = object_checker_new();
	obj_checker->kind = SubmapObject;
	obj_checker->verify = vm_object_attributes_with_default(true);

	/* Look up the object_id stored in the parent map's submap entry. */
	obj_checker->object_id = get_object_id_for_address(submap_start); /* submap_depth==0 */
	obj_checker->object_id_mode = object_has_known_id;
	obj_checker->copy_strategy = copy_invalid;  /* NULL object doesn't have a copy strategy */

	obj_checker->size = submap_size;
	obj_checker->self_ref_count = 0;
	obj_checker->fill_pattern.mode = DontFill;

	obj_checker->next = NULL;
	obj_checker->prev = NULL;

	obj_checker->submap_checkers = submap_checkers;

	/*
	 * Slide the submap checkers as if they were
	 * checking a submap remapping at address 0.
	 * Also remove needs_copy, to match vm_map_seal().
	 */
	FOREACH_CHECKER(submap_checker, submap_checkers->entries) {
		submap_checker->address -= submap_start;
		submap_checker->needs_copy = false;
	}

	/* Change the submap's objects to copy_delay, to match vm_map_seal(). */
	for (vm_object_checker_t *submap_content_object = submap_checkers->objects;
	    submap_content_object;
	    submap_content_object = submap_content_object->next) {
		submap_content_object->copy_strategy = copy_delay;
	}

	/* Move the submap list's object checkers into the parent list. */
	submap_checkers->parent = checker_list;
	checker_list_move_objects_to_parent(submap_checkers);

	checker_list_append_object(checker_list, obj_checker);

	return obj_checker;
}

static vm_entry_checker_t *
checker_new(void)
{
	return calloc(sizeof(vm_entry_checker_t), 1);
}

void
checker_free(vm_entry_checker_t *checker)
{
	object_checker_dereference(checker->object);
	free(checker);
}


static checker_list_t *
checker_list_new(void)
{
	checker_list_t *list = calloc(sizeof(*list), 1);
	make_null_object_checker(list);
	return list;
}

void
checker_list_append_object(
	checker_list_t *list,
	vm_object_checker_t *obj_checker)
{
	/* object list is only stored in the top-level checker list */
	if (list->parent) {
		assert(list != list->parent);
		return checker_list_append_object(list->parent, obj_checker);
	}

	/* first object must be the null object */
	assert(list->objects && object_is_null(list->objects));

	/* no additional null objects are allowed */
	assert(!object_is_null(obj_checker));

	/* new object must be currently unlinked */
	assert(obj_checker->next == NULL && obj_checker->prev == NULL);

	/* no duplicate IDs allowed */
	if (obj_checker->object_id_mode == object_has_known_id) {
		assert(!find_object_checker_for_object_id(list, obj_checker->object_id));
	}

	/* insert object after the null object */
	vm_object_checker_t *left = list->objects;
	vm_object_checker_t *right = list->objects->next;
	obj_checker->prev = left;
	obj_checker->next = right;
	left->next = obj_checker;
	if (right) {
		right->prev = obj_checker;
	}
}

/*
 * Move object checkers from a submap checker list to its parent.
 * Submap checker lists do not store objects.
 */
static void
checker_list_move_objects_to_parent(checker_list_t *submap_list)
{
	vm_object_checker_t *obj_checker = submap_list->objects;

	checker_list_t *parent_list = submap_list->parent;
	assert(parent_list != NULL);

	/* skip submap's null object, the parent should already have one */
	assert(obj_checker != NULL && object_is_null(obj_checker));
	obj_checker = obj_checker->next;

	while (obj_checker != NULL) {
		vm_object_checker_t *cur = obj_checker;
		obj_checker = obj_checker->next;

		cur->prev = cur->next = NULL;
		checker_list_append_object(parent_list, cur);
	}

	/* free submap's null object */
	object_checker_free(submap_list->objects);
	submap_list->objects = NULL;
}

unsigned
checker_range_count(entry_checker_range_t entry_range)
{
	unsigned count = 0;
	FOREACH_CHECKER(checker, entry_range) {
		count++;
	}
	return count;
}

mach_vm_address_t
checker_range_start_address(entry_checker_range_t checker_range)
{
	return checker_range.head->address;
}

mach_vm_address_t
checker_range_end_address(entry_checker_range_t checker_range)
{
	return checker_end_address(checker_range.tail);
}

mach_vm_size_t
checker_range_size(entry_checker_range_t checker_range)
{
	return checker_range_end_address(checker_range) - checker_range_start_address(checker_range);
}

/*
 * Add a checker to the end of a checker range.
 */
void
checker_range_append(entry_checker_range_t *list, vm_entry_checker_t *inserted)
{
	inserted->prev = list->tail;
	if (!list->head) {
		list->head = inserted;
	}
	if (list->tail) {
		list->tail->next = inserted;
	}
	list->tail = inserted;
}

/*
 * Free a range of checkers.
 * You probably don't want to call this.
 * Use checker_list_free() or checker_list_free_range() instead.
 */
static void
checker_range_free(entry_checker_range_t range)
{
	/* not FOREACH_CHECKER due to use-after-free */
	vm_entry_checker_t *checker = range.head;
	vm_entry_checker_t *end = range.tail ? range.tail->next : NULL;
	while (checker != end) {
		vm_entry_checker_t *dead = checker;
		checker = checker->next;
		checker_free(dead);
	}
}

static void
checker_list_free(checker_list_t *list)
{
	/* Free map entry checkers */
	checker_range_free(list->entries);

	/* Free guard page checkers */
	checker_range_free(list->guard_pages);

	/* Free object checkers. */
	vm_object_checker_t *obj_checker = list->objects;
	while (obj_checker) {
		vm_object_checker_t *dead = obj_checker;
		obj_checker = obj_checker->next;
		object_checker_free(dead);
	}

	free(list);
}

vm_entry_checker_t *
checker_clone(vm_entry_checker_t *old)
{
	vm_entry_checker_t *new_checker = checker_new();
	*new_checker = *old;
	object_checker_reference(new_checker->object);
	new_checker->prev = NULL;
	new_checker->next = NULL;
	return new_checker;
}

/*
 * Return the entry's object's page index for the given address.
 * The address is allowed to be the checker's end address, even though
 * that page index may not be a valid index in the object's page array.
 */
static mach_vm_size_t
checker_get_object_page_index_for_address_including_end(
	vm_entry_checker_t *checker,
	mach_vm_address_t addr)
{
	assert(checker_contains_address(checker, addr) || addr == checker_end_address(checker));
	assert(checker->object);
	mach_vm_address_t truncated_addr = addr & ~(mach_vm_address_t)PAGE_MASK;
	mach_vm_size_t offset_in_entry = truncated_addr - checker->address;
	mach_vm_size_t offset_in_object = offset_in_entry + checker->object_offset;
	assert(offset_in_object <= checker->object->size); /* one past the end is OK */
	mach_vm_size_t page_index = offset_in_object / xnu_vm_page_size();
	return page_index;
}

/*
 * Return the entry's object's page index for the given address.
 * The checker's end address is not allowed.
 */
static mach_vm_size_t
checker_get_object_page_index_for_address(
	vm_entry_checker_t *checker,
	mach_vm_address_t addr)
{
	assert(addr != checker_end_address(checker));
	return checker_get_object_page_index_for_address_including_end(checker, addr);
}

/*
 * page_index is an index in obj_checker's page array.
 * Transform it into the equivalent index in its shadow's page array.
 */
static mach_vm_size_t
object_checker_page_index_in_shadow(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index)
{
	assert(obj_checker->shadow);
	return page_index + (obj_checker->shadow_offset / xnu_vm_page_size());
}

/*
 * Get the bounds of this entry's subset of its object's pages.
 * The entry's object must not be NULL.
 * Use this to loop through an entry's object pages.
 */
void
checker_get_object_page_bounds(
	vm_entry_checker_t *checker,
	mach_vm_size_t * const out_page_start,
	mach_vm_size_t * const out_page_end)
{
	*out_page_start = checker_get_object_page_index_for_address(checker, checker->address);
	*out_page_end = checker_get_object_page_index_for_address_including_end(checker, checker_end_address(checker));
}

/*
 * Get the bounds of this object's pages
 * (the indexes of its first page and one past the last page)
 * in its shadow object's page array.
 */
static void
object_checker_get_page_bounds_in_shadow(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t * const out_page_start,
	mach_vm_size_t * const out_page_end)
{
	*out_page_start = object_checker_page_index_in_shadow(obj_checker, 0);
	*out_page_end = object_checker_page_index_in_shadow(obj_checker, obj_checker->size / xnu_vm_page_size());
}

/*
 * Get the bounds of vo_copy's pages
 * (the indexes of its first page and one past the last page)
 * in this object's page array.
 */
static void
object_checker_get_page_bounds_of_copy(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t * const out_page_start,
	mach_vm_size_t * const out_page_end)
{
	assert(obj_checker->vo_copy);
	object_checker_get_page_bounds_in_shadow(obj_checker->vo_copy,
	    out_page_start, out_page_end);
}

/*
 * Get the page index of a page in vo_copy
 * matching page_index in this object.
 * This object must have a vo_copy copy object.
 * The copy object must span this page.
 */
static mach_vm_size_t
object_checker_page_index_in_copy(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index)
{
	assert(obj_checker->vo_copy);

	/*
	 * Verify that page_index is within the copy's bounds.
	 * The end index after the last page is allowed.
	 */
	mach_vm_size_t copy_page_start, copy_page_end;
	object_checker_get_page_bounds_of_copy(obj_checker,
	    &copy_page_start, &copy_page_end);
	assert(page_index >= copy_page_start && page_index <= copy_page_end);

	return page_index - obj_checker->vo_copy->shadow_offset / xnu_vm_page_size();
}

/*
 * Returns true if this object has a copy object
 * that spans page_index.
 *
 * Returns false if this object has no copy object.
 * Returns false if this object has a copy object,
 * but the copy object doesn't span that page.
 */
static bool
object_checker_copy_spans_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index)
{
	if (obj_checker->vo_copy == NULL) {
		return false;
	}
	mach_vm_size_t copy_page_start, copy_page_end;
	object_checker_get_page_bounds_of_copy(obj_checker,
	    &copy_page_start, &copy_page_end);
	return copy_page_start <= page_index && page_index < copy_page_end;
}

/*
 * Returns true if this object has a copy object
 * and that copy object does not have its own copy
 * of this object's page at page_index.
 *
 * Returns false if this object has no copy object.
 * Returns false if this object has a copy object,
 * but the copy object doesn't span that page.
 */
static bool
object_checker_copy_needs_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index)
{
	if (!object_checker_copy_spans_page(obj_checker, page_index)) {
		return false;
	}
	mach_vm_size_t copy_page_index =
	    object_checker_page_index_in_copy(obj_checker, page_index);
	return obj_checker->vo_copy->pages[copy_page_index] == page_is_absent;
}

/*
 * Try to unlink obj_checker from its shadow, if any.
 * (If the object already has all of its pages
 * then it no longer needs the shadow.)
 */
static void
object_checker_try_collapse_shadow(vm_object_checker_t *obj_checker)
{
	if (!obj_checker->shadow) {
		return;  /* no shadow present */
	}

	for (mach_vm_size_t page_index = 0;
	    page_index < obj_checker->size / xnu_vm_page_size();
	    page_index++) {
		if (obj_checker->pages[page_index] == page_is_absent) {
			return;  /* object is missing a page, can't unlink the shadow */
		}
	}

	/* We have all of our pages. We don't need our shadow. */
	vm_object_checker_t *shadow = obj_checker->shadow;
	if (shadow->vo_copy == obj_checker) {
		shadow->vo_copy = NULL;
	}
	/* do this last, it might deallocate shadow */
	object_checker_set_shadow(obj_checker, NULL);
}

/*
 * Copy a page to an object from somewhere in its shadow chain.
 * The page is copied from *pageref (part of page_owner)
 * to dst_page_index in this object.
 * Afterwards, try to collapse the shadow.
 */
static void
object_checker_pull_page_from_shadow(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t dst_page_index,
	page_status_t *pageref,
	vm_object_checker_t *page_owner)
{
	assert(page_owner != obj_checker);

	/* Copy the page */
	assert(obj_checker->pages[dst_page_index] == page_is_absent);
	obj_checker->pages[dst_page_index] = *pageref;

	/* Try to collapse the shadow chain. */
	object_checker_try_collapse_shadow(obj_checker);
}

/*
 * Copy a page from an object to its copy object (vo_copy).
 * The page is copied from page_index in this object
 * to the appropriate location in vo_copy.
 * Do nothing if the copy object does not span this page.
 * Do nothing if the copy object already has its own copy of this page.
 */
static void
object_checker_push_page_into_copy(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index)
{
	assert(page_index < obj_checker->size / xnu_vm_page_size());
	if (object_checker_copy_needs_page(obj_checker, page_index)) {
		mach_vm_size_t copy_page_index =
		    object_checker_page_index_in_copy(obj_checker, page_index);
		obj_checker->vo_copy->pages[copy_page_index] =
		    obj_checker->pages[page_index];
	}
}

/*
 * Look for a page in an object and its shadow chain.
 * page_index in obj_checker is the desired page.
 *
 * Returns false if no copy of the page is
 * present in obj_checker or its shadow chain.
 * Returns true if some copy of the page was found,
 * and sets *out_pageref and *out_page_owner to the copy
 * of the page closest to obj_checker in the shadow chain.
 *
 * Example: if obj_checker already has the page
 * then return true with *out_page_owner == obj_checker.
 */
static bool
object_checker_find_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index,
	page_status_t ** const out_pageref,
	vm_object_checker_t ** const out_page_owner)
{
	if (obj_checker == NULL) {
		/* recursive base case */
		return false;
	}

	if (object_is_null(obj_checker)) {
		/* null object never has pages */
		return false;
	}

	assert(obj_checker->pages);
	if (obj_checker->pages[page_index]) {
		/* we have the page */
		*out_pageref = &obj_checker->pages[page_index];
		*out_page_owner = obj_checker;
		return true;
	}

	if (obj_checker->shadow) {
		mach_vm_size_t shadow_page_index =
		    object_checker_page_index_in_shadow(obj_checker, page_index);
		if (object_checker_find_page(obj_checker->shadow, shadow_page_index,
		    out_pageref, out_page_owner)) {
			/* shadow chain has the page */
			return true;
		}
	}

	/* didn't find the page */
	return false;
}

/*
 * Mark a page as newly allocated in an object.
 * page_index in obj_checker is the page to allocate.
 * On entry that page must be absent.
 * Also sets *out_pageref and *out_page_owner for convenience
 * in code that parallels object_checker_find_page().
 */
static void
object_checker_allocate_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index,
	page_status_t ** const out_pageref,
	vm_object_checker_t ** const out_page_owner)
{
	assert(obj_checker->pages[page_index] == page_is_absent);
	obj_checker->pages[page_index] = page_is_resident;
	*out_pageref = &obj_checker->pages[page_index];
	*out_page_owner = obj_checker;
}

/*
 * Find a page in an object or its shadow chain,
 * and allocate a new page if no copy is available.
 * page_index in obj_checker is the desired page.
 * On exit the page found or allocated is
 * returned in *out_pageref and *out_page_owner.
 */
static void
object_checker_find_or_allocate_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index,
	page_status_t ** const out_pageref,
	vm_object_checker_t ** const out_page_owner)
{
	if (!object_checker_find_page(obj_checker, page_index, out_pageref, out_page_owner)) {
		object_checker_allocate_page(obj_checker, page_index, out_pageref, out_page_owner);
	}
}

/*
 * Process some pages in an object.
 * [start_page, end_page) in obj_checker are all processed as follows:
 * 1. if pull_from_shadow, pages in the shadow chain are copied into this object
 * 2. all missing pages are zerofilled in this object
 * 3. if push_into_copy, pages are copied into this object's vo_copy
 *
 * Used for fault and wire.
 */
void
object_checker_allocate_pull_push_pages(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t start_page,
	mach_vm_size_t end_page,
	bool pull_from_shadow,
	bool push_into_copy)
{
	for (mach_vm_size_t page_index = start_page;
	    page_index < end_page;
	    page_index++) {
		/* Find the page. Zerofill it locally if it is missing. */
		page_status_t *pageref;
		vm_object_checker_t *page_owner;
		object_checker_find_or_allocate_page(obj_checker, page_index, &pageref, &page_owner);
		if (pull_from_shadow && page_owner != obj_checker) {
			/* Page is in the shadow chain. Copy it here. */
			object_checker_pull_page_from_shadow(
				obj_checker, page_index, pageref, page_owner);
		}

		if (push_into_copy && obj_checker->vo_copy) {
			/* Try to push the page into the copy object. */
			object_checker_push_page_into_copy(obj_checker, page_index);
		}
	}
}

/*
 * Convenience wrapper for object_checker_allocate_pull_push_pages()
 * but for only one page.
 */
static void
object_checker_allocate_pull_push_page(
	vm_object_checker_t *obj_checker,
	mach_vm_size_t page_index,
	bool pull_from_shadow,
	bool push_into_copy)
{
	object_checker_allocate_pull_push_pages(obj_checker,
	    page_index, page_index + 1, pull_from_shadow, push_into_copy);
}

/*
 * Perform a delayed COW copy of an entry.
 * This may create a new object that shadows the old object,
 * or it may re-use an existing copy of the old object.
 */
static void
checker_copy_delayed(checker_list_t *list, vm_entry_checker_t *checker)
{
	vm_object_checker_t *old_object = checker->object;
	vm_object_checker_t *old_copy_object = old_object->vo_copy;
	vm_object_checker_t *new_object;

	/*
	 * If there is already a copy object, and no pages have been pushed
	 * to the copy object, then we can re-use it.
	 * TODO real VM can resize the existing copy object; we don't try that here
	 */
	if (old_copy_object &&
	    old_copy_object->size == old_object->size &&
	    checker_count_vm_region_pages_resident_owned_by_object(checker, old_copy_object) == 0) {
		/* Copy object owns no pages yet. Re-use it. */
		new_object = old_copy_object;
	} else {
		/* Make a new object and insert it as the new old_object->vo_copy. */

		new_object = object_checker_clone(checker->object);
		checker_list_append_object(list, new_object);

		/*
		 * was: old_object <--shadow-- old_copy_object
		 *                 --vo_copy-->
		 *
		 * now: old_object <--shadow-- new_object <--shadow-- old_copy_object
		 *                 --vo_copy-->
		 *
		 * new_object completely covers old_object, so
		 * (1) new_object's shadow_offset is 0
		 * (2) old_copy_object's shadow_offset is unchanged
		 */
		object_checker_set_shadow(new_object, old_object);
		old_object->vo_copy = new_object;
		if (old_copy_object) {
			assert(old_copy_object->shadow == old_object);

			/*
			 * do this after setting new_object->shadow
			 * or else it might deallocate old_object
			 */
			object_checker_set_shadow(old_copy_object, new_object);
		}

		new_object->copy_strategy = copy_symmetric;
	}

	checker_set_object(checker, new_object);
	checker->needs_copy = true;
}

/*
 * Unconditionally set checker's object to a new object that shadows its old object.
 * If you want to allow optimizations when the new object is not required,
 * use checker_make_shadow_object().
 */
void
checker_make_shadow_object_forced(checker_list_t *list, vm_entry_checker_t *checker)
{
	vm_object_checker_t *old_object = checker->object;
	vm_object_checker_t *new_object = object_checker_clone(checker->object);
	checker_list_append_object(list, new_object);

	/*
	 * New object only covers the part of the
	 * old object that the map entry covers.
	 */
	new_object->size = checker->size;
	new_object->shadow_offset = checker->object_offset;
	checker->object_offset = 0;

	object_checker_set_shadow(new_object, old_object);
	checker_set_object(checker, new_object);

	new_object->copy_strategy = copy_symmetric;
	checker->needs_copy = false;
}

/*
 * Set checker's object to a new object that shadows its old object if necessary.
 * In cases where the new object is not necessary, instead leave the
 * checker's object alone and change the checker to needs_copy = false.
 */
void
checker_make_shadow_object(checker_list_t *list, vm_entry_checker_t *checker)
{
	/* Optimization: try not to shadow if we don't have to. */
	vm_object_checker_t *obj_checker = checker->object;
	if (obj_checker->self_ref_count != 1) {
		/* Multiple entries may point to this object. Must shadow. */
		goto really_shadow;
	}
	if (obj_checker->shadow && obj_checker->shadow->vo_copy) {
		/* Object's shadow has a copy. Must shadow. (TODO why?) */
		goto really_shadow;
	}
	if (checker->size != obj_checker->size) {
		/* Checker doesn't cover the whole object. Must shadow. */
		goto really_shadow;
	}
	if (checker->submap_depth > 0) {
		/*
		 * We're inside a submap which may be mapped in multiple places.
		 * Must shadow.
		 */
		goto really_shadow;
	}

	/* Nothing else can be using this object. No need for a new shadow. */
	checker->needs_copy = false;
	return;

really_shadow:
	checker_make_shadow_object_forced(list, checker);
}

kern_return_t
checker_fault_address(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	mach_vm_address_t addr,
	vm_prot_t fault_prot)
{
	assert(checker_contains_address(checker, addr));

	/* write fault also requires read permission */
	vm_prot_t required_prot = fault_prot;
	if (prot_contains_all(required_prot, VM_PROT_WRITE)) {
		required_prot |= VM_PROT_READ;
	}

	/* Check permissions and resolve null object if necessary. */
	if (is_new_vm()) {
		/*
		 * Null object is resolved before checking permissions,
		 * with only a narrow optimization to avoid resolving it.
		 */
		if (checker->max_protection == VM_PROT_NONE) {
			/* access denied, optimized case */
			return KERN_PROTECTION_FAILURE;
		}
		checker_resolve_null_vm_object(checker_list, checker);
		if (!prot_contains_all(checker->protection, required_prot)) {
			/* access denied, general case */
			return KERN_PROTECTION_FAILURE;
		}
	} else {
		/* Null object is only resolved after checking permissions. */
		if (!prot_contains_all(checker->protection, required_prot)) {
			/* access denied */
			return KERN_PROTECTION_FAILURE;
		}
		checker_resolve_null_vm_object(checker_list, checker);
	}

	/* Resolve symmetric COW by making a new object. */
	if ((fault_prot & VM_PROT_WRITE) && checker->needs_copy) {
		checker_make_shadow_object(checker_list, checker);
	}

	/*
	 * Find the page in the entry's object or its shadow chain.
	 * Zero-fill a new page if it does not exist yet.
	 * If it's a write fault, copy the page up the shadow chain as needed.
	 */
	bool should_copy_page = fault_prot & VM_PROT_WRITE;
	vm_object_checker_t *obj_checker = checker->object;
	mach_vm_size_t page_index =
	    checker_get_object_page_index_for_address(checker, addr);
	object_checker_allocate_pull_push_page(obj_checker, page_index,
	    should_copy_page /* pull from shadow */,
	    should_copy_page /* push to copy */);

	return KERN_SUCCESS;
}

void
checker_clip_and_resolve_cow_for_wire(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	mach_vm_address_t range_address,
	mach_vm_size_t range_size)
{
	mach_vm_address_t range_end = range_address + range_size;
	if (checker->user_wired_count > 0) {
		/* already wired, nothing to resolve */
	} else if (object_is_null(checker->object)) {
		/* Resolve NULL object. New VM should already have done this. */
		assert(!is_new_vm());
		checker_resolve_null_vm_object(checker_list, checker);
	} else if (checker->needs_copy) {
		/* resolve COW */
		checker_make_shadow_object(checker_list, checker);
	} else if (checker->object->copy_strategy == copy_symmetric) {
		/* copy_symmetric without needs_copy: clip first then resolve COW */
		checker_clip_left(checker_list, checker, range_address);
		checker_clip_right(checker_list, checker, range_end);
		checker_make_shadow_object(checker_list, checker);
	}

	/* If it's still copy_symmetric, change it. */
	if (checker->object->copy_strategy == copy_symmetric) {
		checker->object->copy_strategy = copy_delay;
	}

	/* Clip now if we haven't already. */
	checker_clip_left(checker_list, checker, range_address);
	checker_clip_right(checker_list, checker, range_end);
}

/*
 * Resolve COW before a checker's memory is shared.
 * copy_symmetric objects cannot be shared, so
 * the object's copy strategy may be changed or
 * a new copy object may be created.
 */
static void
checker_resolve_cow_for_share(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker)
{
	vm_object_checker_t *obj_checker = checker->object;

	if (obj_checker->copy_strategy == copy_delay) {
		/* copy_delay object. We're free to share it. */
	} else if (obj_checker->copy_strategy == copy_symmetric &&
	    !checker->needs_copy &&
	    checker->object->self_ref_count == 1) {
		/*
		 * copy_symmetric object with only one owner.
		 * We're free to share this object
		 * after changing it to copy_delay.
		 */
		obj_checker->copy_strategy = copy_delay;
	} else if (obj_checker->copy_strategy == copy_symmetric) {
		/*
		 * copy_symmetric with possibly multiple map entries using it.
		 * Make a new object, or use the same object if we can
		 * prove that nothing else uses it. Then make the new object
		 * copy_delay and share that.
		 */
		checker_make_shadow_object(checker_list, checker);
		obj_checker = checker->object;  /* maybe changed */
		obj_checker->copy_strategy = copy_delay;
		checker->needs_copy = false;
	} else {
		T_FAIL("unimplemented copy_strategy %s",
		    name_for_copy_strategy(obj_checker->copy_strategy));
	}

	assert(!checker->needs_copy);
	assert(obj_checker == checker->object);
	assert(obj_checker->copy_strategy == copy_delay);
}

vm_entry_checker_t *
checker_clone_share(
	checker_list_t *list,
	vm_entry_checker_t *src_checker)
{
	switch (src_checker->kind) {
	case Allocation:
		/* Special case: inaccessible and null object */
		if (src_checker->protection == VM_PROT_NONE &&
		    src_checker->max_protection == VM_PROT_NONE &&
		    object_is_null(src_checker->object)) {
			break;
		}

		/* Need a non-null object to share. */
		checker_resolve_null_vm_object(list, src_checker);

		/* Some COW states must be resolved before sharing. */
		checker_resolve_cow_for_share(list, src_checker);
		break;
	case Hole:
	case Submap:
		break;
	case Guard:
	case EndEntries:
	default:
		assert(0);
	}

	vm_entry_checker_t *dst_checker = checker_clone(src_checker);
	return dst_checker;
}

vm_entry_checker_t *
checker_clone_copy(checker_list_t *list, vm_entry_checker_t *src_checker)
{
	vm_entry_checker_t *dst_checker = NULL;
	switch (src_checker->kind) {
	case Allocation:
		/* remap-copy resolves NULL objects at the source. */
		if (object_is_null(src_checker->object)) {
			checker_resolve_null_vm_object(list, src_checker);
		}
		/* Make a copy using the appropriate copy strategy. */
		switch (src_checker->object->copy_strategy) {
		case copy_delay:
			dst_checker = checker_clone(src_checker);
			checker_copy_delayed(list, dst_checker);
			break;
		case copy_symmetric:
			src_checker->needs_copy = true;
			dst_checker = checker_clone(src_checker);
			break;
		default:
			T_FAIL("unimplemented copy_strategy %s",
			    name_for_copy_strategy(src_checker->object->copy_strategy));
			break;
		}
		break;
	case Hole:
		dst_checker = checker_clone(src_checker);
		break;
	case Submap:
	case Guard:
	case EndEntries:
	default:
		assert(0);
	}
	return dst_checker;
}

bool
checker_page_at_address_is_resident_owned_by_object(
	vm_entry_checker_t *checker,
	mach_vm_address_t addr,
	vm_object_checker_t *matching_owner)
{
	/* null object and submap objects never have resident pages */
	if (object_is_null(checker->object) ||
	    checker->object->kind == SubmapObject) {
		return false;
	}

	mach_vm_size_t page_index = checker_get_object_page_index_for_address(checker, addr);
	page_status_t *pageref;
	vm_object_checker_t *page_owner;
	if (object_checker_find_page(checker->object, page_index, &pageref, &page_owner)) {
		if (matching_owner != NULL && page_owner != matching_owner) {
			/* page's owner is not the requested owner */
			return false;
		}
		return *pageref == page_is_resident;
	}

	/* page not allocated in any object */
	return false;
}

uint32_t
checker_count_vm_region_pages_resident_owned_by_object(
	vm_entry_checker_t *checker,
	vm_object_checker_t *matching_owner)
{
	/* null object and submap objects never have pages */
	if (object_is_null(checker->object) ||
	    checker->object->kind == SubmapObject) {
		return 0;
	}

	uint32_t pages_resident = 0;
	for (mach_vm_address_t addr = checker->address;
	    addr < checker_end_address(checker);
	    addr += xnu_vm_page_size()) {
		if (checker_page_at_address_is_resident_owned_by_object(checker, addr, matching_owner)) {
			pages_resident++;
		}
	}

	/* Convert units from xnu_vm_page_size() to PAGE_SIZE. */
	assert(xnu_vm_page_size() >= PAGE_SIZE);
	return pages_resident * xnu_vm_page_size() / PAGE_SIZE;
}

uint32_t
checker_count_vm_region_pages_resident(vm_entry_checker_t *checker)
{
	return checker_count_vm_region_pages_resident_owned_by_object(checker, NULL);
}

uint32_t
checker_get_local_pages_resident(vm_entry_checker_t *checker)
{
	/* null object and submap objects never have pages */
	if (object_is_null(checker->object) ||
	    checker->object->kind == SubmapObject) {
		return 0;
	}

	uint32_t pages_resident = 0;
	mach_vm_size_t start_page, end_page;
	checker_get_object_page_bounds(checker, &start_page, &end_page);
	for (mach_vm_size_t page_index = start_page;
	    page_index < end_page;
	    page_index++) {
		if (checker->object->pages[page_index] == page_is_resident) {
			pages_resident++;
		}
	}
	return pages_resident;
}

/*
 * Return the nth checker in a linked list of checkers.
 * Includes holes.
 */
static vm_entry_checker_t *
checker_nth(vm_entry_checker_t *checkers, unsigned n)
{
	assert(checkers != NULL);
	if (n == 0) {
		return checkers;
	} else {
		return checker_nth(checkers->next, n - 1);
	}
}

/*
 * Return the nth checker in a checker list.
 * Includes holes.
 */
vm_entry_checker_t *
checker_list_nth(checker_list_t *list, unsigned n)
{
	return checker_nth(list->entries.head, n);
}

static void
checker_list_apply_slide(checker_list_t *checker_list, mach_vm_address_t slide)
{
	FOREACH_CHECKER(checker, checker_list->entries) {
		checker->address += slide;
	}
}

checker_list_t *
checker_get_and_slide_submap_checkers(vm_entry_checker_t *submap_parent)
{
	assert(submap_parent->kind == Submap);
	assert(submap_parent->object);
	checker_list_t *submap_checkers = submap_parent->object->submap_checkers;
	assert(!submap_checkers->is_slid);
	submap_checkers->is_slid = true;
	submap_checkers->submap_slide = submap_parent->address - submap_parent->object_offset;
	checker_list_apply_slide(submap_checkers, submap_checkers->submap_slide);
	return submap_checkers;
}

void
unslide_submap_checkers(checker_list_t *submap_checkers)
{
	assert(submap_checkers->is_slid);
	submap_checkers->is_slid = false;
	checker_list_apply_slide(submap_checkers, -submap_checkers->submap_slide);
	submap_checkers->submap_slide = 0;
}


/*
 * vm_region of submap contents clamps the reported
 * address range to the parent map's submap entry,
 * and also modifies some (but not all) fields to match.
 * Our submap checkers model the submap's real contents.
 * When verifying VM state, we "tweak" the checkers
 * of submap contents to match what vm_region will
 * report, and "untweak" the checkers afterwards.
 *
 * Note that these submap "tweaks" are separate from the
 * submap "slide" (checker_get_and_slide_submap_checkers).
 * Submap slide is applied any time the submap contents are used.
 * Submap tweaks are applied only when comparing checkers to vm_region output.
 */

typedef struct {
	/* save the checker list so we can use attribute(cleanup) */
	checker_list_t *tweaked_checker_list;

	/* some entries are removed from the list; save them here */
	entry_checker_range_t original_entries;

	/* some entries are modified; save their old values here */
	vm_entry_checker_t new_head_original_contents;
	vm_entry_checker_t new_tail_original_contents;
} checker_list_tweaks_t;

static void
checker_tweak_for_vm_region(vm_entry_checker_t *checker, vm_entry_checker_t *submap_parent)
{
	/* clamp checker bounds to the submap window */
	mach_vm_address_t old_address = checker->address;
	clamp_address_size_to_checker(&checker->address, &checker->size, submap_parent);

	/* also update object_offset to match; pages_resident calculation needs it */
	uint64_t object_offset_increase = checker->address - old_address;
	checker->object_offset += object_offset_increase;

	/*
	 * vm_region does NOT adjust the reported object offset.
	 * Remember the change we just applied so we can negate it
	 * when comparing to vm_region output.
	 */
	checker->vm_region_object_offset_tweak = -object_offset_increase;
}

static checker_list_tweaks_t
submap_checkers_tweak_for_vm_region(
	checker_list_t *submap_checkers,
	vm_entry_checker_t *submap_parent)
{
	assert(submap_checkers->is_slid);

	checker_list_tweaks_t tweaks;
	tweaks.tweaked_checker_list = submap_checkers;

	/* The order below must reverse submap_checkers_untweak() */

	/*
	 * Remove entries from the list that fall outside this submap window.
	 * (we don't actually change the linked list,
	 * only the checker list's head and tail)
	 */
	tweaks.original_entries = submap_checkers->entries;
	submap_checkers->entries = checker_list_find_range_including_holes(submap_checkers,
	    submap_parent->address, submap_parent->size);

	/* "clip" the new head and tail to the submap parent's bounds */
	vm_entry_checker_t *new_head = submap_checkers->entries.head;
	vm_entry_checker_t *new_tail = submap_checkers->entries.tail;

	tweaks.new_head_original_contents = *new_head;
	tweaks.new_tail_original_contents = *new_tail;
	checker_tweak_for_vm_region(new_head, submap_parent);
	if (new_tail != new_head) {
		checker_tweak_for_vm_region(new_tail, submap_parent);
	}

	return tweaks;
}

static void
cleanup_submap_checkers_untweak(checker_list_tweaks_t *tweaks)
{
	checker_list_t *submap_checkers = tweaks->tweaked_checker_list;

	/* The order below must reverse submap_checkers_tweak_for_vm_region() */

	/* restore contents of narrowed head and tail */
	*submap_checkers->entries.tail = tweaks->new_tail_original_contents;
	*submap_checkers->entries.head = tweaks->new_head_original_contents;

	/*
	 * restore entries clipped from the list
	 *
	 * old_prefix->head..old_prefix->tail <-> head..tail <-> old_suffix->head..old_suffix->tail
	 */
	submap_checkers->entries = tweaks->original_entries;
}

#define DEFER_UNTWEAK __attribute__((cleanup(cleanup_submap_checkers_untweak)))

/*
 * Set an entry checker's object checker.
 * Adjusts the refcount of the new object checker and (if any) the old object checker.
 * Updates the entry's resident page count if the object has a fill pattern.
 */
void
checker_set_object(vm_entry_checker_t *checker, vm_object_checker_t *obj_checker)
{
	object_checker_reference(obj_checker);
	if (checker->object) {
		object_checker_dereference(checker->object);
	}
	checker->object = obj_checker;
}

/*
 * Set an entry checker's object to the null object.
 */
void
checker_set_null_object(checker_list_t *list, vm_entry_checker_t *checker)
{
	checker_set_object(checker, find_object_checker_for_object_id(list, 0));
}

/*
 * vm_region computes share_mode from several other entry and object attributes.
 * Mimic that here.
 */
uint8_t
checker_share_mode(vm_entry_checker_t *checker)
{
	vm_object_checker_t *obj_checker = checker->object;

	if (object_is_null(obj_checker)) {
		return SM_EMPTY;
	}
	if (checker_is_submap(checker)) {
		return SM_PRIVATE;
	}
	if (object_checker_get_shadow_depth(obj_checker) > 0) {
		return SM_COW;
	}
	if (checker->needs_copy) {
		return SM_COW;
	}
	if (object_checker_get_self_ref_count(obj_checker) == 1) {
		/* TODO: self_ref_count == 2 && named */
		return SM_PRIVATE;
	}

	return SM_SHARED;
}


/*
 * Translate a share mode into a "narrowed" form.
 * - SM_TRUESHARED is mapped to SM_SHARED
 * - SM_PRIVATE_ALIASED is mapped to SM_SHARED
 * - SM_SHARED_ALIASED is mapped to SM_SHARED
 * - TODO: SM_LARGE_PAGE
 */
static unsigned
narrow_share_mode(unsigned share_mode)
{
	switch (share_mode) {
	case SM_TRUESHARED:
	case SM_PRIVATE_ALIASED:
	case SM_SHARED_ALIASED:
		return SM_SHARED;
	case SM_LARGE_PAGE:
		T_FAIL("unexpected/unimplemented share mode SM_LARGE_PAGE");
	default:
		return share_mode;
	}
}

/*
 * Return true if a region and a checker have the same share_mode,
 * after accounting for share mode distinctions that the checkers do not enforce.
 */
static bool
same_share_mode(vm_region_submap_info_data_64_t *info, vm_entry_checker_t *checker)
{
	return narrow_share_mode(info->share_mode) ==
	       narrow_share_mode(checker_share_mode(checker));
}

/*
 * Allocate an entry checker using designated initializer syntax.
 */
#define vm_entry_checker(...)                                   \
	checker_clone(&(vm_entry_checker_t){ __VA_ARGS__ })

/*
 * Allocate a new checker for an unallocated hole.
 * The new checker is not linked into the list.
 */
static vm_entry_checker_t *
make_checker_for_hole(mach_vm_address_t address, mach_vm_size_t size)
{
	return vm_entry_checker(
		.address = address,
		.size = size,
		.kind = Hole,
		.verify = vm_entry_attributes_with_default(true)
		);
}

static vm_entry_checker_t *
make_checker_for_anonymous_private(
	checker_list_t *list,
	vm_entry_template_kind_t kind,
	mach_vm_address_t address,
	mach_vm_size_t size,
	vm_prot_t protection,
	vm_prot_t max_protection,
	uint16_t user_tag,
	bool permanent)
{
	// fixme hack: if you ask for protection --x you get r-x
	// fixme arm only?
	if (protection == VM_PROT_EXECUTE) {
		protection = VM_PROT_READ | VM_PROT_EXECUTE;
	}

	assert(user_tag < 256);

	vm_entry_checker_t *checker = vm_entry_checker(
		.kind = kind,

		.address = address,
		.size = size,

		.object = NULL, /* set below */

		.protection = protection,
		.max_protection = max_protection,
		.inheritance = VM_INHERIT_DEFAULT,
		.behavior = VM_BEHAVIOR_DEFAULT,
		.permanent = permanent,

		.user_wired_count = 0,
		.user_tag = (uint8_t)user_tag,

		.object_offset = 0,
		.vm_region_object_offset_tweak = 0,
		.needs_copy = false,

		.verify = vm_entry_attributes_with_default(true)
		);

	checker_set_null_object(list, checker);

	return checker;
}

void
append_checker_for_guard_page(
	checker_list_t *list,
	mach_vm_address_t address,
	mach_vm_size_t size)
{
	vm_entry_checker_t *checker;
	checker = make_checker_for_anonymous_private(list, Guard,
	    address, size, VM_PROT_NONE, VM_PROT_NONE, 0, false);

	/*
	 * Don't check object_offset. The object offset stored in the
	 * last guard page depends on the size of the arena allocation.
	 */
	checker->verify.object_offset_attr = false;

	checker_range_append(&list->guard_pages, checker);
}

vm_entry_checker_t *
make_checker_for_vm_allocate(
	checker_list_t *list,
	mach_vm_address_t address,
	mach_vm_size_t size,
	int flags_and_tag)
{
	/* Complain about flags not understood by this code. */

	/* these flags are permitted but have no effect on the checker */
	int ignored_flags =
	    VM_FLAGS_FIXED | VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR |
	    VM_FLAGS_OVERWRITE;

	/* these flags are handled by this code */
	int handled_flags = VM_FLAGS_ALIAS_MASK /* tag */ | VM_FLAGS_PERMANENT;

	int allowed_flags = ignored_flags | handled_flags;
	assert((flags_and_tag & ~allowed_flags) == 0);

	bool permanent = flags_and_tag & VM_FLAGS_PERMANENT;
	uint16_t tag;
	VM_GET_FLAGS_ALIAS(flags_and_tag, tag);

	return make_checker_for_anonymous_private(
		list, Allocation, address, size,
		VM_PROT_DEFAULT, VM_PROT_ALL, tag, permanent);
}

/*
 * Build a vm_checker for a newly-created shared memory region.
 * The region is assumed to be a remapping of anonymous memory.
 * Attributes not otherwise specified are assumed to have
 * default values as set by mach_vm_map().
 * The new checker is not linked into the list.
 */
static vm_entry_checker_t *
make_checker_for_shared(
	checker_list_t *list __unused,
	vm_entry_template_kind_t kind,
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t object_offset,
	vm_prot_t protection,
	vm_prot_t max_protection,
	uint16_t user_tag,
	bool permanent,
	vm_object_checker_t *obj_checker)
{
	// fixme hack: if you ask for protection --x you get r-x
	// fixme arm only?
	if (protection == VM_PROT_EXECUTE) {
		protection = VM_PROT_READ | VM_PROT_EXECUTE;
	}

	assert(user_tag < 256);
	vm_entry_checker_t *checker = vm_entry_checker(
		.kind = kind,

		.address = address,
		.size = size,

		.object = NULL, /* set below */

		.protection = protection,
		.max_protection = max_protection,
		.inheritance = VM_INHERIT_DEFAULT,
		.behavior = VM_BEHAVIOR_DEFAULT,
		.permanent = permanent,

		.user_wired_count = 0,
		.user_tag = (uint8_t)user_tag,

		.object_offset = object_offset,
		.vm_region_object_offset_tweak = 0,
		.needs_copy = false,

		.verify = vm_entry_attributes_with_default(true)
		);

	checker_set_object(checker, obj_checker);

	return checker;
}

/*
 * Build a checker for a parent map's submap entry.
 */
vm_entry_checker_t *
make_checker_for_submap(
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t object_offset,
	vm_object_checker_t *submap_object_checker)
{
	vm_entry_checker_t *checker = vm_entry_checker(
		.kind = Submap,
		.address = address,
		.size = size,
		.object = NULL, /* set below */
		.protection = VM_PROT_READ,
		.max_protection = 0, /* set below */
		.inheritance = VM_INHERIT_SHARE,
		.behavior = VM_BEHAVIOR_DEFAULT,
		.permanent = false, /* see comment below */
		.user_wired_count = 0,
		.user_tag = 0,
		.submap_depth = 0,
		.object_offset = object_offset,
		.vm_region_object_offset_tweak = 0,
		.needs_copy = true,  /* like a shared region submap */

		.verify = vm_entry_attributes_with_default(true),
		);

	/*
	 * Submap max_protection differs on x86_64.
	 * (see VM_MAP_POLICY_WRITABLE_SHARED_REGION
	 *  and vm_shared_region_insert_submap)
	 */
#if __x86_64__
	checker->max_protection = VM_PROT_ALL;
#else
	checker->max_protection = VM_PROT_READ;
#endif

	checker_set_object(checker, submap_object_checker);

	/*
	 * Real submap entries for the shared region are sometimes
	 * permanent (see shared_region_make_permanent()).
	 * This test does not attempt to duplicate that because
	 * permanent entries are difficult to manage in userspace.
	 */

	return checker;
}


/*
 * Print a checker's fields with optional highlighting.
 */
static void
dump_checker_info_with_highlighting(
	vm_entry_checker_t *checker,
	attribute_highlights_t highlights)
{
	const char *submap_prefix = checker->submap_depth > 0 ? SUBMAP_PREFIX : "";

	/* Output order should match dump_region_info() for the reader's convenience. */

	T_LOG("%sCHECKER   %s0x%llx%s..%s0x%llx%s %s(size 0x%llx)%s (%s%s)",
	    submap_prefix,
	    HIGHLIGHT(checker->address, entry.address_attr),
	    HIGHLIGHT(checker_end_address(checker), entry.size_attr),
	    HIGHLIGHT(checker->size, entry.size_attr),
	    name_for_entry_kind(checker->kind),
	    checker->submap_depth > 0 ? " in submap" : "");

	if (checker->kind == Hole) {
		if (checker->submap_depth != 0) {
			/* print submap depth to avoid confusion about holes inside submaps */
			T_LOG("%s    %ssubmap_depth:   %u%s", submap_prefix, HIGHLIGHT(checker->submap_depth, entry.submap_depth_attr));
		}
		return;
	}

	T_LOG("%s    %sprotection:     %s%s", submap_prefix, HIGHLIGHT(name_for_prot(checker->protection), entry.protection_attr));
	T_LOG("%s    %smax protection: %s%s", submap_prefix, HIGHLIGHT(name_for_prot(checker->max_protection), entry.max_protection_attr));
	T_LOG("%s    %sinheritance:    %s%s", submap_prefix, HIGHLIGHT(name_for_inherit(checker->inheritance), entry.inheritance_attr));
	T_LOG("%s    %sbehavior:       %s%s", submap_prefix, HIGHLIGHT(name_for_behavior(checker->behavior), entry.behavior_attr));
	T_LOG("%s    %suser wired count:  %d%s", submap_prefix, HIGHLIGHT(checker->user_wired_count, entry.user_wired_count_attr));
	T_LOG("%s    %suser tag:       %d%s", submap_prefix, HIGHLIGHT(checker->user_tag, entry.user_tag_attr));
	T_LOG("%s    %sobject offset:  0x%llx%s", submap_prefix, HIGHLIGHT(checker->object_offset, entry.object_offset_attr));
	T_LOG("%s    %svm_region object offset:  0x%llx%s", submap_prefix, HIGHLIGHT(checker->object_offset + checker->vm_region_object_offset_tweak, entry.object_offset_attr));

	vm_object_checker_t *obj_checker = checker->object;
	if (object_is_null(obj_checker)) {
		T_LOG("%s    %sobject id:      %d%s", submap_prefix, HIGHLIGHT(0, entry.object_attr));
	} else if (obj_checker->object_id_mode == object_is_unknown) {
		T_LOG("%s    %sobject id:      %s%s", submap_prefix, HIGHLIGHT("unknown", entry.object_attr));
	} else if (obj_checker->object_id_mode == object_has_unknown_nonnull_id) {
		T_LOG("%s    %sobject id:      %s%s", submap_prefix, HIGHLIGHT("unknown, not null", entry.object_attr));
	} else {
		assert(obj_checker->object_id_mode == object_has_known_id);
		if (obj_checker->shadow == NULL) {
			/* no shadow chain, simple display */
			T_LOG("%s    %sobject id:      0x%llx%s", submap_prefix, HIGHLIGHT(obj_checker->object_id, object.object_id_attr));
		} else {
			/* include shadow chain and page counts */
			const char *field_name = "object id:";
			for (vm_object_checker_t *obj = obj_checker; obj; obj = obj->shadow) {
				T_LOG("%s    %s%s%s     %s0x%llx%s %s(owns %u resident pages)%s", submap_prefix,
				    HIGHLIGHT(field_name, object.object_id_attr),
				    HIGHLIGHT(obj->object_id, object.object_id_attr),
				    HIGHLIGHT(checker_count_vm_region_pages_resident_owned_by_object(checker, obj), object.object_id_attr));
				field_name = "    shadow:   ";
			}
		}
		T_LOG("%s    %sobject size:    0x%llx%s", submap_prefix, HIGHLIGHT(obj_checker->size, object.size_attr));
		T_LOG("%s    %sref_count:      %u%s", submap_prefix, HIGHLIGHT(object_checker_get_vm_region_ref_count(obj_checker), object.ref_count_attr));
		T_LOG("%s    %sshadow_depth:   %u%s", submap_prefix, HIGHLIGHT(object_checker_get_shadow_depth(obj_checker), object.shadow_depth_attr));
		T_LOG("%s    %sself_ref_count: %u%s", submap_prefix, HIGHLIGHT(object_checker_get_self_ref_count(obj_checker), object.ref_count_attr));
	}

	T_LOG("%s    %spages resident: %u%s", submap_prefix, HIGHLIGHT(checker_count_vm_region_pages_resident(checker), entry.pages_resident_attr));
	T_LOG("%s    %sshare mode:     %s%s", submap_prefix, HIGHLIGHT(name_for_share_mode(checker_share_mode(checker)), entry.share_mode_attr));
	T_LOG("%s    %sis submap:      %s%s", submap_prefix, HIGHLIGHT(name_for_bool(checker_is_submap(checker)), entry.is_submap_attr));
	T_LOG("%s    %ssubmap_depth:   %u%s", submap_prefix, HIGHLIGHT(checker->submap_depth, entry.submap_depth_attr));
	T_LOG("%s    %spermanent:      %s%s", submap_prefix, HIGHLIGHT(name_for_bool(checker->permanent), entry.permanent_attr));

	T_LOG("%s    %sneeds copy:     %s%s", submap_prefix, highlight_prefix(IgnoredHighlight), name_for_bool(checker->needs_copy), highlight_suffix(IgnoredHighlight));
	if (!object_is_null(obj_checker)) {
		T_LOG("%s    %scopy strat:     %s%s", submap_prefix, highlight_prefix(IgnoredHighlight), name_for_copy_strategy(obj_checker->copy_strategy), highlight_suffix(IgnoredHighlight));
	}
}


static void
dump_checker_info(vm_entry_checker_t *checker)
{
	/*
	 * Verified attributes are printed normally.
	 * Unverified attributes are printed ignored.
	 */
	vm_entry_attribute_list_t verified_entry_attr = checker->verify;
	vm_object_attribute_list_t verified_object_attr;
	if (checker->verify.object_attr == false) {
		/* object verification disabled entirely */
		verified_object_attr = vm_object_attributes_with_default(false);
	} else if (checker->object == NULL) {
		verified_object_attr = vm_object_attributes_with_default(true);
	} else {
		verified_object_attr = checker->object->verify;
	}

	dump_checker_info_with_highlighting(checker,
	    normal_or_ignored_highlights(verified_entry_attr, verified_object_attr));
}

void
dump_checker_range(
	entry_checker_range_t list)
{
	FOREACH_CHECKER(checker, list) {
		dump_checker_info(checker);
		if (checker_is_submap(checker)) {
			checker_list_t *submap_checkers DEFER_UNSLIDE =
			    checker_get_and_slide_submap_checkers(checker);
			dump_checker_range(submap_checkers->entries);
		}
	}
}

/*
 * Print a checker that failed verification,
 * and the real VM regions overlapping it.
 * Attributes in bad_entry_attr and bad_object_attr are printed as BadHighlight.
 * Other attributes are printed as IgnoredHighlight.
 */
static void
warn_bad_checker(
	vm_entry_checker_t *checker,
	vm_entry_attribute_list_t bad_entry_attr,
	vm_object_attribute_list_t bad_object_attr,
	const char *message)
{
	attribute_highlights_t highlights =
	    bad_or_ignored_highlights(bad_entry_attr, bad_object_attr);
	T_LOG("*** %s: expected ***", message);
	dump_checker_info_with_highlighting(checker, highlights);
	T_LOG("*** %s: actual ***", message);
	dump_region_info_for_entry(checker, highlights);
}

static mach_vm_size_t
overestimate_size(const vm_entry_template_t templates[], unsigned count)
{
	mach_vm_size_t size = 0;
	for (unsigned i = 0; i < count; i++) {
		bool overflowed = __builtin_add_overflow(size, templates[i].size, &size);
		assert(!overflowed);
	}
	return size;
}

static void
protect_guard_page(mach_vm_address_t addr, mach_vm_size_t guard_page_size)
{
	kern_return_t kr;

	kr = mach_vm_protect(mach_task_self(), addr, guard_page_size,
	    false /* set max */, VM_PROT_NONE);
	assert(kr == KERN_SUCCESS);

	kr = mach_vm_protect(mach_task_self(), addr, guard_page_size,
	    true /* set max */, VM_PROT_NONE);
	assert(kr == KERN_SUCCESS);
}

/*
 * The arena is a contiguous address range where the VM regions for
 * a test are placed. Here we allocate the entire space to reserve it.
 * Later, it is overwritten by each desired map entry or unallocated hole.
 *
 * Problem: We want to generate unallocated holes and verify later that
 * they are still unallocated. But code like Rosetta compilation and
 * Mach exceptions can allocate VM space outside of our control. If those
 * allocations land in our unallocated holes then a test may spuriously fail.
 * Mitigations:
 * - Allocate the arena with VM_FLAGS_RANDOM_ADDR to keep it away from the
 *   VM's allocation frontier.
 * - Allocate more memory than necessary and then free the first part, leaving
 *   it available for first-fit allocations before landing inside the arena.
 * - Allocate one guard page before and after, to protect any unallocated hole
 *   at the start or end of the arena from being claimed by part of an
 *   outside allocation.
 * Together these do not prevent the problem entirely but
 * so far appear to dodge it with high probability.
 * TODO: make this more reliable or completely safe somehow.
 */
mach_vm_address_t
allocate_with_guards(
	mach_vm_size_t arena_size,
	mach_vm_size_t arena_alignment_mask,
	mach_vm_size_t guard_page_size,
	vm_prot_t cur_prot,
	vm_prot_t max_prot)
{
	/*
	 * Layout:
	 * [ space to free | first guard page | arena | last guard page ]
	 */

	/*
	 * leading_size covers space to free and first guard page as described above.
	 * It must be at least guard_page_size bytes.
	 * It must be at least arena_size bytes.
	 * It must preserve alignment of the arena following it.
	 */
	mach_vm_size_t alignment_grain = arena_alignment_mask + 1;
	if (alignment_grain < PAGE_SIZE) {
		alignment_grain = PAGE_SIZE;
	}
	mach_vm_size_t leading_size = alignment_grain;
	while (leading_size < arena_size || leading_size < guard_page_size) {
		leading_size += alignment_grain;
	}

	/* Allocate and partition. */
	mach_vm_size_t allocated_size = leading_size + arena_size + guard_page_size;
	mach_vm_address_t allocated_addr;
	kern_return_t kr;

	allocated_addr = allocate_at_random_address(allocated_size,
	    arena_alignment_mask, cur_prot, max_prot);

	mach_vm_address_t allocated_end = allocated_addr + allocated_size;
	mach_vm_address_t last_guard_page = allocated_end - guard_page_size;
	mach_vm_address_t arena_addr = last_guard_page - arena_size;
	mach_vm_address_t first_guard_page = arena_addr - guard_page_size;
	mach_vm_address_t space_to_free = arena_addr - leading_size;
	assert(space_to_free == allocated_addr);
	assert((arena_addr & arena_alignment_mask) == 0);

	/* Deallocate the leading space to free. */
	kr = mach_vm_deallocate(mach_task_self(),
	    space_to_free, leading_size - guard_page_size);
	assert(kr == 0);

	/* Protect the guard pages. */
	protect_guard_page(first_guard_page, guard_page_size);
	protect_guard_page(last_guard_page, guard_page_size);

	return arena_addr;
}

mach_vm_address_t
allocate_at_random_address(
	mach_vm_size_t size,
	mach_vm_size_t alignment_mask,
	vm_prot_t cur_prot,
	vm_prot_t max_prot)
{
	mach_vm_size_t unaligned_size;
	mach_vm_address_t allocated = 0;
	kern_return_t kr;

	/*
	 * VM_FLAGS_RANDOM_ADDR will often spuriously fail
	 * when using a large alignment mask.
	 * We instead allocate oversized and perform the alignment manually.
	 */
	if (alignment_mask > PAGE_MASK) {
		unaligned_size = size + alignment_mask + 1;
	} else {
		unaligned_size = size;
	}

	kr = mach_vm_map(mach_task_self(), &allocated, unaligned_size,
	    0 /* alignment mask */, VM_FLAGS_ANYWHERE | VM_FLAGS_RANDOM_ADDR,
	    0, 0, 0, cur_prot, max_prot, VM_INHERIT_DEFAULT);

	if (kr == KERN_NO_SPACE) {
		/*
		 * VM_FLAGS_RANDOM_ADDR can spuriously fail even without alignment.
		 * Try again without VM_FLAGS_RANDOM_ADDR.
		 */
		kr = mach_vm_map(mach_task_self(), &allocated, unaligned_size,
		    0 /* alignment mask */, VM_FLAGS_ANYWHERE,
		    0, 0, 0, cur_prot, max_prot, VM_INHERIT_DEFAULT);
		if (kr == KERN_SUCCESS) {
			T_LOG("note: forced to allocate arena without VM_FLAGS_RANDOM_ADDR");
		}
	}

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "allocation at random address "
	    "(size 0x%llx, alignment 0x%llx, unaligned addr 0x%llx)",
	    size, alignment_mask, allocated);

	if (size != unaligned_size) {
		/* Align manually within the oversized allocation. */
		mach_vm_address_t aligned = (allocated & ~alignment_mask) + alignment_mask + 1;
		mach_vm_address_t aligned_end = aligned + size;
		mach_vm_address_t allocated_end = allocated + unaligned_size;

		assert(aligned >= allocated && aligned_end <= allocated_end);
		assert((aligned & alignment_mask) == 0);
		assert((aligned & PAGE_MASK) == 0);

		/* trim the overallocation */
		(void)mach_vm_deallocate(mach_task_self(), allocated, aligned - allocated);
		(void)mach_vm_deallocate(mach_task_self(), aligned_end, allocated_end - aligned_end);

		return aligned;
	} else {
		/* No alignment needed. */
		return allocated;
	}
}

/*
 * If this object's fill pattern would write its memory then
 * mark all of this object's pages as resident in this object.
 * Use this when initializing a new object checker.
 */
static void
object_checker_allocate_initial_pages(
	vm_object_checker_t *obj_checker)
{
	assert(!obj_checker->shadow);  /* unimplemented */
	assert(!obj_checker->vo_copy); /* unimplemented */

	if (obj_checker->fill_pattern.mode == Fill) {
		for (mach_vm_size_t page_index = 0;
		    page_index < obj_checker->size / xnu_vm_page_size();
		    page_index++) {
			obj_checker->pages[page_index] = page_is_resident;
		}
	}
}

static void
write_fill_pattern(
	mach_vm_address_t start,
	mach_vm_size_t size,
	fill_pattern_t fill_pattern)
{
	assert(start % sizeof(uint64_t) == 0);
	if (fill_pattern.mode == Fill) {
		for (mach_vm_address_t c = start;
		    c < start + size;
		    c += sizeof(uint64_t)) {
			*(uint64_t *)c = fill_pattern.pattern;
		}
	}
}

/*
 * Returns true if the memory contents of [start, start + size)
 * matches the fill pattern.
 * A fill pattern of DontFill always matches and never reads the memory.
 * If the pattern did not match, *first_bad_address is set to the
 * first address (uint64_t aligned) that did not match.
 */
static bool
verify_fill_pattern(
	mach_vm_address_t start,
	mach_vm_size_t size,
	fill_pattern_t fill_pattern,
	mach_vm_address_t * const first_bad_address)
{
	mach_vm_address_t end = start + size;
	bool good = true;
	assert(start % sizeof(uint64_t) == 0);
	if (fill_pattern.mode == Fill) {
		for (mach_vm_address_t c = start;
		    c < end;
		    c += sizeof(uint64_t)) {
			if (*(uint64_t *)c != fill_pattern.pattern) {
				if (first_bad_address) {
					*first_bad_address = c;
				}
				good = false;
				break;
			}
		}
	}

	return good;
}

/* Debug syscall to manipulate submaps. */

typedef enum {
	vsto_make_submap = 1, /* make submap from entries in current_map() at start..end, offset ignored */
	vsto_remap_submap = 2, /* map in current_map() at start..end, from submap address offset */
	vsto_end
} vm_submap_test_op;

typedef struct {
	vm_submap_test_op op;
	mach_vm_address_t submap_base_address;
	mach_vm_address_t start;
	mach_vm_address_t end;
	mach_vm_address_t offset;
} vm_submap_test_args;

static void
submap_op(vm_submap_test_args *args)
{
	int err = sysctlbyname("vm.submap_test_ctl",
	    NULL, NULL, args, sizeof(*args));
	T_QUIET; T_ASSERT_POSIX_SUCCESS(err, "sysctl(vm.submap_test_ctl)");
}

/* Lower address range [start..end) into a submap at that same address. */
static void
submapify(mach_vm_address_t start, mach_vm_address_t end)
{
	vm_submap_test_args args = {
		.op = vsto_make_submap,
		.submap_base_address = 0,
		.start = start,
		.end = end,
		.offset = 0,
	};
	submap_op(&args);
}

/*
 * submap_base_address is the start of a submap created with submapify().
 * Remap that submap or a portion thereof at [start, end).
 * Use offset as the VME_OFFSET field in the parent map's submap entry.
 */
static void
remap_submap(
	mach_vm_address_t submap_base_address,
	mach_vm_address_t start,
	mach_vm_size_t size,
	mach_vm_address_t offset)
{
	vm_submap_test_args args = {
		.op = vsto_remap_submap,
		.submap_base_address = submap_base_address,
		.start = start,
		.end = start + size,
		.offset = offset,
	};
	submap_op(&args);
}

/*
 * Temporary scratch space for newly-created VM objects.
 * Used by create_vm_state() and its helpers.
 */
typedef struct {
	/* computed from entry templates */
	unsigned entry_count;
	bool is_private;
	mach_vm_size_t min_size;  /* size required by entries that use it */

	/*
	 * set when allocating the object's temporary backing storage
	 */
	mach_vm_address_t allocated_address;
	mach_vm_size_t allocated_size;
	vm_object_checker_t *checker;
} object_scratch_t;

/*
 * Force a range of memory to have a non-NULL vm_object
 * but also no resident pages.
 * If read this memory will be zero filled.
 */
static void
force_vm_object_with_no_resident_pages(mach_vm_address_t address, mach_vm_size_t size)
{
	/* Fill with zeros. Then kill the pages. */
	kern_return_t kr;
	write_fill_pattern(address, size, (fill_pattern_t){Fill, 0});
	kr = mach_vm_behavior_set(mach_task_self(),
	    address, size, VM_BEHAVIOR_FREE);
	assert(kr == 0);
	kr = mach_vm_behavior_set(mach_task_self(),
	    address, size, VM_BEHAVIOR_PAGEOUT);
	assert(kr == 0);

	/* PAGEOUT may be asynchronous. Wait until the pages are definitely gone. */
	vm_region_submap_info_data_64_t info;
	for (int retries = 0; retries < 10; retries++) {
		mach_vm_address_t actual_address = address;
		mach_vm_size_t actual_size = 0;
		get_info_for_address_fast(&actual_address, &actual_size, &info);
		if (info.pages_resident == 0) {
			return;  /* success */
		}
		T_LOG("note: pages still resident after VM_BEHAVIOR_PAGEOUT, sleeping...");
		sleep(1);
	}
	T_FAIL("%u pages still resident after VM_BEHAVIOR_PAGEOUT", info.pages_resident);
	T_END;  /* stop test now, don't risk stalling all the way to test timeout */
}

static void
allocate_submap_storage_and_checker(
	checker_list_t *checker_list,
	const vm_object_template_t *object_tmpl,
	object_scratch_t *object_scratch)
{
	assert(object_tmpl->kind == SubmapObject);
	assert(object_tmpl->size == 0);
	assert(object_scratch->min_size > 0);
	assert(object_scratch->entry_count > 0);

	/*
	 * Submap size is determined by its contents.
	 * min_size is the minimum size required for
	 * the offset/size of the parent map entries
	 * that remap this submap.
	 * We allocate the submap first, then check min_size.
	 */

	/*
	 * Check some preconditions on the submap contents.
	 * This is in addition to the checks performed by create_vm_state().
	 */
	for (unsigned i = 0; i < object_tmpl->submap.entry_count; i++) {
		const vm_entry_template_t *tmpl = &object_tmpl->submap.entries[i];

		assert(tmpl->kind != Hole);  /* no holes, vm_map_seal fills them */
		assert(tmpl->kind != Submap);  /* no nested submaps */
	}

	/*
	 * Allocate the submap's entries into temporary space,
	 * space, lower them into a submap, and build checkers for them.
	 * Later there will be entry templates in the parent map that
	 * remap this space and clone these checkers.
	 * This temporary space will be cleaned up when
	 * the object_scratch is destroyed at the end of create_vm_state().
	 */
	checker_list_t *submap_checkers = create_vm_state(
		object_tmpl->submap.entries, object_tmpl->submap.entry_count,
		object_tmpl->submap.objects, object_tmpl->submap.object_count,
		SUBMAP_ALIGNMENT_MASK,
		false /* no guard pages for submap contents */,
		"submap construction");

	/*
	 * Update the returned submap checkers for vm_map_seal and submap lowering.
	 * - set the submap depth
	 * - resolve null objects
	 * - disable share mode verification (TODO vm_region says SM_COW, we say SM_PRIVATE)
	 */
	FOREACH_CHECKER(submap_checker, submap_checkers->entries) {
		T_QUIET; T_ASSERT_EQ(submap_checker->submap_depth, 0, "nested submaps not allowed");
		submap_checker->submap_depth = 1;
		checker_resolve_null_vm_object(submap_checkers, submap_checker);
		submap_checker->needs_copy = false;
		submap_checker->object->copy_strategy = copy_delay;
		submap_checker->verify.share_mode_attr = false; /* TODO hack */
	}

	mach_vm_address_t submap_start = checker_range_start_address(submap_checkers->entries);
	mach_vm_address_t submap_end = checker_range_end_address(submap_checkers->entries);
	assert(submap_start < submap_end);

	/* verify that the submap is bigger than min_size */
	T_QUIET; T_ASSERT_GE(submap_end - submap_start, object_scratch->min_size,
	    "some submap entry extends beyond the end of the submap object");

	/* make it a real boy^W submap */
	submapify(submap_start, submap_end);

	/*
	 * Make an object checker for the entire submap.
	 * This checker stores the entry and object checkers for the submap's contents.
	 */
	vm_object_checker_t *obj_checker = make_submap_object_checker(
		checker_list, submap_checkers);

	object_scratch->allocated_address = submap_start;
	object_scratch->allocated_size = submap_end - submap_start;
	object_scratch->checker = obj_checker;
}

static void
allocate_object_storage_and_checker(
	checker_list_t *checker_list,
	const vm_object_template_t *object_tmpl,
	object_scratch_t *object_scratch)
{
	kern_return_t kr;

	assert(object_tmpl->kind != EndObjects);
	assert(object_scratch->entry_count > 0);
	assert(object_scratch->min_size > 0);

	/*
	 * min_size is the required object size as determined by
	 * the entries using this object and their sizes and offsets.
	 *
	 * tmpl->size may be zero, in which case we allocate min_size bytes
	 * OR tmpl->size may be non-zero, in which case we allocate tmpl->size bytes
	 * and verify that it is at least as large as min_size.
	 */
	mach_vm_size_t size = object_tmpl->size ?: object_scratch->min_size;
	assert(size >= object_scratch->min_size);

	if (object_scratch->is_private == 1) {
		/*
		 * Object is private memory for a single entry.
		 * It will be allocated when the entry is created.
		 */
		assert(object_scratch->entry_count == 1);
		object_scratch->allocated_address = 0;
		object_scratch->allocated_size = 0;
		object_scratch->checker = NULL;
	} else if (object_tmpl->kind == Anonymous) {
		/*
		 * Object is anonymous memory and shared or COW
		 * by multiple entries. Allocate temporary space now.
		 * Each entry will copy or share it when the entries
		 * are created. Then this temporary allocation will be freed.
		 */
		mach_vm_address_t address = 0;
		kr = mach_vm_allocate(mach_task_self(), &address, size,
		    VM_FLAGS_ANYWHERE | VM_MAKE_TAG(VM_MEMORY_SCENEKIT));
		assert(kr == 0);

		object_scratch->allocated_address = address;
		object_scratch->allocated_size = size;

		object_scratch->checker = make_anonymous_object_checker(
			checker_list, size);

		if (object_tmpl->fill_pattern.mode == DontFill) {
			/*
			 * We must have a vm_object to share, but
			 * the test may also want no resident pages.
			 */
			force_vm_object_with_no_resident_pages(address, size);
		} else {
			write_fill_pattern(address, size, object_tmpl->fill_pattern);
		}
		object_scratch->checker->fill_pattern = object_tmpl->fill_pattern;
		object_checker_allocate_initial_pages(object_scratch->checker);
	} else {
		T_FAIL("unexpected/unimplemented: object is neither private nor anonymous nor submap");
	}
}


/*
 * Choose an entry's user_tag value.
 * If the requested value is an ordinary tag, use it.
 * If the requested value is autoincrementing, pick the next
 * autoincrementing tag. *inc stores the persistent increment
 * state and should be cleared before the first call.
 */
static uint8_t
choose_user_tag(uint16_t requested_tag, uint8_t *inc)
{
	uint8_t assigned_tag;
	if (requested_tag == VM_MEMORY_TAG_AUTOINCREMENTING) {
		/* choose an incrementing tag 1..16 */
		assigned_tag = VM_MEMORY_APPLICATION_SPECIFIC_1 + *inc;
		*inc = (*inc + 1) % 16;
	} else {
		/* ordinary tag */
		assert(requested_tag < 256);
		assigned_tag = (uint8_t)requested_tag;
	}
	return assigned_tag;
}


/*
 * SM_EMPTY is the default template share mode,
 * but we allow other template values to implicitly
 * override it.
 */
static uint8_t
template_real_share_mode(const vm_entry_template_t *tmpl)
{
	if (tmpl->share_mode != SM_EMPTY) {
		return tmpl->share_mode;
	}

	/* things that can override SM_EMPTY */
	if (tmpl->user_wired_count > 0) {
		return SM_PRIVATE;
	}
	if (tmpl->object && tmpl->object->fill_pattern.mode == Fill) {
		return SM_PRIVATE;
	}

	return SM_EMPTY;
}

static void
create_vm_hole(
	const vm_entry_template_t *tmpl,
	mach_vm_address_t dest_address,
	checker_list_t *checker_list)
{
	kern_return_t kr;

	assert(dest_address % PAGE_SIZE == 0);
	assert(tmpl->size % PAGE_SIZE == 0);
	assert(tmpl->object == NULL);

	/* deallocate the hole */
	kr = mach_vm_deallocate(mach_task_self(),
	    dest_address, tmpl->size);
	assert(kr == 0);

	/* add a checker for the unallocated space */
	checker_range_append(&checker_list->entries,
	    make_checker_for_hole(dest_address, tmpl->size));
}

static void
create_vm_submap(
	const vm_entry_template_t *tmpl,
	object_scratch_t *object_scratch,
	mach_vm_address_t dest_address,
	checker_list_t *checker_list)
{
	kern_return_t kr;

	/* entry must not extend beyond submap's backing store */
	assert(tmpl->offset + tmpl->size <= object_scratch->allocated_size);

	/* deallocate space for the new submap entry */
	/* TODO vsto_remap_submap should copy-overwrite */
	kr = mach_vm_deallocate(mach_task_self(),
	    dest_address, tmpl->size);
	assert(kr == 0);

	remap_submap(object_scratch->allocated_address,
	    dest_address, tmpl->size, tmpl->offset);

	/*
	 * Create a map entry checker for the parent map's submap entry.
	 * Its object checker is the submap checker, which in turn
	 * contains the entry checkers for the submap's contents.
	 */
	checker_range_append(&checker_list->entries,
	    make_checker_for_submap(dest_address, tmpl->size, tmpl->offset,
	    object_scratch->checker));
}

__attribute__((overloadable))
checker_list_t *
create_vm_state(
	const vm_entry_template_t entry_templates[],
	unsigned entry_template_count,
	const vm_object_template_t object_templates[],
	unsigned object_template_count,
	mach_vm_size_t alignment_mask,
	bool allocate_guard_pages,
	const char *message)
{
	const vm_object_template_t *start_object_templates = &object_templates[0];
	const vm_object_template_t *end_object_templates = &object_templates[object_template_count];
	checker_list_t *checker_list = checker_list_new();
	uint8_t tag_increment = 0;
	kern_return_t kr;

	/* temporary scratch space for new objects for shared and COW entries */
	object_scratch_t *new_objects =
	    calloc(sizeof(object_scratch_t), object_template_count);

	/* Check some preconditions */

	assert(is_valid_alignment_mask(alignment_mask));
	assert(entry_template_count > 0);

	/*
	 * Check preconditions of each entry template
	 * and accumulate some info about their respective objects.
	 */
	for (unsigned i = 0; i < entry_template_count; i++) {
		const vm_entry_template_t *tmpl = &entry_templates[i];

		assert(tmpl->kind != EndEntries);
		assert(tmpl->size > 0);
		assert(tmpl->size % PAGE_SIZE == 0);
		assert(tmpl->inheritance <= VM_INHERIT_LAST_VALID);

		/* reject VM_PROT_EXEC; TODO: support it somehow */
		T_QUIET; T_ASSERT_TRUE(prot_contains_all(VM_PROT_READ | VM_PROT_WRITE, tmpl->protection),
		    "entry template #%u protection 0x%x exceeds VM_PROT_READ | VM_PROT_WRITE", i, tmpl->protection);

		T_QUIET; T_ASSERT_TRUE(prot_contains_all(VM_PROT_ALL, tmpl->max_protection),
		    "entry template #%u max_protection 0x%x exceeds VM_PROT_ALL", i, tmpl->max_protection);

		T_QUIET; T_ASSERT_TRUE(prot_contains_all(tmpl->max_protection, tmpl->protection),
		    "entry template #%u protection exceeds max_protection (%s/%s)",
		    i, name_for_prot(tmpl->protection), name_for_prot(tmpl->max_protection));

		/* entry can't be COW and wired at the same time */
		assert(!(tmpl->user_wired_count > 0 && template_real_share_mode(tmpl) == SM_COW));

		/*
		 * We only allow vm_behavior_t values that are stored
		 * persistently in the entry.
		 * Non-persistent behaviors don't make sense here because
		 * they're really more like one-shot memory operations.
		 */
		assert(is_persistent_vm_behavior(tmpl->behavior));

		/*
		 * Non-zero offset in object not implemented for
		 * SM_EMPTY and SM_PRIVATE.
		 * (TODO might be possible for SM_PRIVATE.)
		 */
		if (tmpl->kind != Submap) {
			switch (template_real_share_mode(tmpl)) {
			case SM_EMPTY:
			case SM_PRIVATE:
				assert(tmpl->offset == 0); /* unimplemented */
				break;
			default:
				break;
			}
		} else {
			/* Submap entries are SM_PRIVATE and can be offset. */
		}

		/* entry's object template must be NULL or in the object list */
		object_scratch_t *object_scratch = NULL;
		if (tmpl->object) {
			assert(tmpl->object >= start_object_templates &&
			    tmpl->object < end_object_templates);

			object_scratch =
			    &new_objects[tmpl->object - start_object_templates];

			/* object size must be large enough to span this entry */
			mach_vm_size_t min_size = tmpl->offset + tmpl->size;
			if (object_scratch->min_size < min_size) {
				object_scratch->min_size = min_size;
			}
		}

		if (tmpl->kind == Submap) {
			/* submap */
			assert(tmpl->object);
			assert(tmpl->object->kind == SubmapObject);
			object_scratch->entry_count++;
			object_scratch->is_private = false;
		} else {
			/* not submap */
			assert(tmpl->object == NULL || tmpl->object->kind != SubmapObject);

			/*
			 * object entry_count is the number of entries that use it
			 *
			 * object is_private if its only reference
			 * is an entry with share mode private
			 */
			switch (template_real_share_mode(tmpl)) {
			case SM_EMPTY:
				/*
				 * empty may not have an object
				 * (but note that some options may override SM_EMPTY,
				 * see template_real_share_mode())
				 */
				assert(tmpl->object == NULL);
				break;
			case SM_PRIVATE:
				/*
				 * private:
				 * object is optional
				 * object must not be used already
				 * object will be private
				 */
				if (tmpl->object) {
					assert(object_scratch->entry_count == 0 &&
					    "SM_PRIVATE entry template may not share "
					    "its object template with any other entry");
					object_scratch->entry_count = 1;
					object_scratch->is_private = true;
				}
				break;
			case SM_SHARED:
			/* case SM_TRUESHARED, TODO maybe */
			case SM_COW:
				/*
				 * shared or cow:
				 * object is required
				 * object must not be private already
				 */
				assert(tmpl->object);
				assert(object_scratch->is_private == false);
				object_scratch->entry_count++;
				break;
			default:
				T_FAIL("unexpected/unimplemented: unsupported share mode");
			}
		}
	}

	/*
	 * Check that every SM_SHARED entry really does share
	 * its object with at least one other entry.
	 */
	for (unsigned i = 0; i < entry_template_count; i++) {
		const vm_entry_template_t *tmpl = &entry_templates[i];
		const vm_object_template_t *object_tmpl = tmpl->object;
		object_scratch_t *object_scratch =
		    tmpl->object ? &new_objects[object_tmpl - start_object_templates] : NULL;

		if (template_real_share_mode(tmpl) == SM_SHARED) {
			assert(tmpl->object != NULL &&
			    "SM_SHARED entry template must have an object template");
			assert(object_scratch->entry_count > 1 &&
			    "SM_SHARED entry's object template must be used by at least one other entry");
		}
	}

	/*
	 * Check some preconditions of object templates,
	 * and allocate backing storage and checkers for objects that are shared.
	 * (Objects that are private are handled when the entry is created.)
	 *
	 * This also allocates backing storage and checkers for submaps in a
	 * similar way to shared non-submaps. The submap mapping(s) into this
	 * arena's address range, and the checkers thereof, are handled later.
	 */
	for (unsigned i = 0; i < object_template_count; i++) {
		const vm_object_template_t *object_tmpl = &object_templates[i];
		object_scratch_t *object_scratch = &new_objects[i];

		if (object_tmpl->kind == SubmapObject) {
			allocate_submap_storage_and_checker(
				checker_list, object_tmpl, object_scratch);
		} else {
			allocate_object_storage_and_checker(
				checker_list, object_tmpl, object_scratch);
		}
	}

	/* Allocate a range large enough to span all requested entries. */
	mach_vm_size_t guard_page_size = allocate_guard_pages ? PAGE_SIZE : 0;
	mach_vm_address_t arena_address = 0;
	mach_vm_address_t arena_end = 0;
	{
		mach_vm_size_t arena_size =
		    overestimate_size(entry_templates, entry_template_count);
		arena_address = allocate_with_guards(arena_size,
		    alignment_mask, guard_page_size, VM_PROT_NONE, VM_PROT_NONE);
		arena_end = arena_address + arena_size;
	}

	/* Add special checkers for the guard pages allocated by allocate_with_guards. */
	if (guard_page_size > 0) {
		append_checker_for_guard_page(checker_list,
		    arena_address - guard_page_size, guard_page_size);
		append_checker_for_guard_page(checker_list,
		    arena_end, guard_page_size);
	}

	/* Carve up the allocated range into the requested entries. */
	for (unsigned i = 0; i < entry_template_count; i++) {
		const vm_entry_template_t *tmpl = &entry_templates[i];
		const vm_object_template_t *object_tmpl = tmpl->object;
		object_scratch_t *object_scratch =
		    tmpl->object ? &new_objects[object_tmpl - start_object_templates] : NULL;

		/*
		 * Assign a user_tag, resolving autoincrementing if requested.
		 */
		uint8_t assigned_tag = choose_user_tag(tmpl->user_tag, &tag_increment);

		unsigned permanent_flag = tmpl->permanent ? VM_FLAGS_PERMANENT : 0;

		/* Allocate the entry. */

		if (tmpl->kind == Hole) {
			create_vm_hole(tmpl, arena_address, checker_list);
			arena_address += tmpl->size;
			continue;
		} else if (tmpl->kind == Submap) {
			create_vm_submap(tmpl, object_scratch, arena_address, checker_list);
			arena_address += tmpl->size;
			continue;
		} else {
			assert(tmpl->kind == Allocation);
		}

		/* new entry is a real allocation */
		if (template_real_share_mode(tmpl) == SM_SHARED) {
			/*
			 * New map entry is shared: it shares
			 * the same object as some other map entry.
			 *
			 * Create the map entry using mach_make_memory_entry()
			 * and mach_vm_map(). The source is the object's
			 * temporary backing store (or a portion thereof).
			 *
			 * We don't use vm_remap to share because it can't
			 * set the user_tag and (in the partial case) we
			 * don't want to clip our source.
			 */

			/* must not extend beyond object's temporary backing store */
			assert(tmpl->offset + tmpl->size <= object_scratch->allocated_size);

			/*
			 * Create a memory entry covering the *entire* source
			 * object. (Covering only the part of the source that
			 * we want to remap might clip the source.)
			 */
			mach_vm_size_t memory_entry_size = object_scratch->allocated_size;
			mach_port_t memory_entry_port;
			kr = mach_make_memory_entry_64(mach_task_self(),
			    &memory_entry_size,
			    object_scratch->allocated_address,
			    tmpl->protection,
			    &memory_entry_port, MEMORY_OBJECT_NULL /* parent */);
			assert(kr == 0);
			assert(memory_entry_size == object_scratch->allocated_size);

			/* Map from the desired part of the memory entry. */
			mach_vm_address_t allocated_address = arena_address;
			kr = mach_vm_map(mach_task_self(),
			    &allocated_address,
			    tmpl->size,
			    0,             /* alignment mask */
			    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(assigned_tag) | permanent_flag,
			    memory_entry_port,  /* source */
			    tmpl->offset, /* offset in source */
			    false, /* copy */
			    tmpl->protection,
			    tmpl->max_protection,
			    VM_INHERIT_DEFAULT);
			assert(kr == 0);
			assert(allocated_address == arena_address);

			/* Tear down the memory entry. */
			mach_port_deallocate(mach_task_self(), memory_entry_port);

			/* Set up the checkers. */
			vm_entry_checker_t *checker = make_checker_for_shared(
				checker_list, tmpl->kind,
				allocated_address, tmpl->size, tmpl->offset,
				tmpl->protection, tmpl->max_protection,
				assigned_tag, tmpl->permanent, object_scratch->checker);
			object_scratch->checker->copy_strategy = copy_delay;
			checker_range_append(&checker_list->entries, checker);

			arena_address = allocated_address + tmpl->size;
		} else if (tmpl->object == NULL || tmpl->object->kind == Anonymous) {
			/*
			 * New entry's object is null or anonymous private memory.
			 * Create the entry using mach_vm_map.
			 */

			/*
			 * We attempt to map the memory with the correct protections
			 * from the start, because this is more capable than
			 * mapping with more permissive protections and then
			 * calling vm_protect.
			 *
			 * But sometimes we need to read or write the memory
			 * during setup. In that case we are forced to map
			 * permissively and vm_protect later.
			 */
			vm_prot_t initial_protection = tmpl->protection;
			vm_prot_t initial_max_protection = tmpl->max_protection;
			bool protect_last = false;
			if (template_real_share_mode(tmpl) == SM_PRIVATE ||
			    tmpl->object != NULL) {
				protect_last = true;
				initial_protection |= VM_PROT_READ | VM_PROT_WRITE;
				initial_max_protection |= VM_PROT_READ | VM_PROT_WRITE;
			}

			mach_vm_address_t allocated_address = arena_address;
			kr = mach_vm_map(mach_task_self(),
			    &allocated_address,
			    tmpl->size,
			    0,     /* alignment mask */
			    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE | VM_MAKE_TAG(assigned_tag) | permanent_flag,
			    0,     /* memory object */
			    0,     /* object offset */
			    false, /* copy */
			    initial_protection,
			    initial_max_protection,
			    VM_INHERIT_DEFAULT);
			assert(kr == 0);
			assert(allocated_address == arena_address);

			vm_entry_checker_t *checker = make_checker_for_anonymous_private(
				checker_list,
				tmpl->kind, allocated_address, tmpl->size,
				tmpl->protection, tmpl->max_protection, assigned_tag,
				tmpl->permanent);
			checker_range_append(&checker_list->entries, checker);

			arena_address = allocated_address + tmpl->size;

			if (template_real_share_mode(tmpl) == SM_PRIVATE) {
				/*
				 * New entry needs a non-null object.
				 * tmpl->object may be NULL or have no fill pattern,
				 * in which case the caller wants a non-null
				 * object with no resident pages.
				 */
				vm_object_checker_t *obj_checker =
				    make_anonymous_object_checker(checker_list,
				    checker->object_offset + checker->size);
				if (tmpl->object) {
					obj_checker->fill_pattern = tmpl->object->fill_pattern;
					write_fill_pattern(checker->address, checker->size,
					    obj_checker->fill_pattern);
					object_checker_allocate_initial_pages(obj_checker);
				} else {
					force_vm_object_with_no_resident_pages(checker->address, checker->size);
				}
				checker_set_object(checker, obj_checker);
			} else if (tmpl->object != NULL) {
				/*
				 * New entry needs a real object for COW.
				 * (SM_SHARED was handled above)
				 */
				assert(template_real_share_mode(tmpl) == SM_COW);
				kr = mach_vm_copy(mach_task_self(),
				    object_scratch->allocated_address + tmpl->offset,
				    tmpl->size, allocated_address);
				assert(kr == 0);
				checker_set_object(checker, object_scratch->checker);
				checker->needs_copy = true;
			}

			if (protect_last) {
				/*
				 * Set protection and max_protection
				 * if we couldn't do it up front.
				 */
				kr = mach_vm_protect(mach_task_self(),
				    allocated_address, tmpl->size, false /*set_max*/, tmpl->protection);
				assert(kr == 0);
				kr = mach_vm_protect(mach_task_self(),
				    allocated_address, tmpl->size, true /*set_max*/, tmpl->max_protection);
				assert(kr == 0);
			}
		} else if (template_real_share_mode(tmpl) == SM_PRIVATE) {
			/*
			 * New entry's object is private non-anonymous memory
			 * TODO named entries
			 */
			T_FAIL("unexpected/unimplemented: non-anonymous memory unimplemented");
		} else {
			T_FAIL("unexpected/unimplemented: unrecognized share mode");
		}
	}

	/*
	 * All entries now have their objects set.
	 * Deallocate temporary storage for shared objects.
	 * Do this before verifying share_mode: any sharing from
	 * the temporary object storage itself should not count.
	 */
	for (unsigned i = 0; i < object_template_count; i++) {
		object_scratch_t *object_scratch = &new_objects[i];

		if (object_scratch->allocated_address > 0) {
			kr = mach_vm_deallocate(mach_task_self(),
			    object_scratch->allocated_address,
			    object_scratch->allocated_size);
			assert(kr == 0);
			object_scratch->allocated_address = 0;
			object_scratch->allocated_size = 0;
		}
	}

	/*
	 * All of the entries and checkers are in place.
	 * Now set each entry's properties.
	 */
	for (unsigned i = 0; i < entry_template_count; i++) {
		const vm_entry_template_t *tmpl = &entry_templates[i];
		vm_entry_checker_t *checker =
		    checker_list_nth(checker_list, i);

		if (tmpl->kind == Hole) {
			continue;  /* nothing else to do for holes */
		}
		if (tmpl->kind == Submap) {
			continue;  /* nothing else to do for submaps */
		}
		assert(tmpl->kind == Allocation);

		/* user_tag - already set */

		/* permanent - already set */

		/*
		 * protection, max_protection - already set
		 * We set these in mach_vm_map() because setting default
		 * values in mach_vm_map() and then adjusting them with
		 * mach_vm_protect() is less capable.
		 */

		/* inheritance */
		if (tmpl->inheritance != VM_INHERIT_DEFAULT) {
			kr = mach_vm_inherit(mach_task_self(),
			    checker->address, checker->size,
			    tmpl->inheritance);
			assert(kr == 0);
			checker->inheritance = tmpl->inheritance;
		}

		/* behavior */
		if (tmpl->behavior != VM_BEHAVIOR_DEFAULT) {
			checker->behavior = tmpl->behavior;
			kr = mach_vm_behavior_set(mach_task_self(),
			    checker->address, checker->size, tmpl->behavior);
			assert(kr == 0);
		}

		/* user_wired_count */
		if (tmpl->user_wired_count > 0) {
			checker_resolve_null_vm_object(checker_list, checker);
			checker->user_wired_count = tmpl->user_wired_count;
			for (uint16_t w = 0; w < tmpl->user_wired_count; w++) {
				kr = mach_vm_wire(host_priv(), mach_task_self(),
				    checker->address, checker->size, VM_PROT_READ);
				assert(kr == 0);
			}
		}

		/*
		 * Verify that the template's share mode matches
		 * the checker's share mode, after allowing for
		 * some mismatches for usability purposes.
		 * Do this last.
		 */
		assert(template_real_share_mode(tmpl) == checker_share_mode(checker));
	}

	/* Deallocate any remaining arena space */
	kr = mach_vm_deallocate(mach_task_self(),
	    arena_address, arena_end - arena_address);
	assert(kr == 0);

	/* Deallocate scratch space */
	free(new_objects);

	/* Verify that our entries and checkers match. */
	assert(verify_vm_state(checker_list, message));

	return checker_list;
}

void
create_vm_state_from_config(
	vm_config_t *config,
	checker_list_t ** const out_checker_list,
	mach_vm_address_t * const out_start_address,
	mach_vm_address_t * const out_end_address)
{
	checker_list_t *list = create_vm_state(
		config->entry_templates, config->entry_template_count,
		config->object_templates, config->object_template_count,
		config->alignment_mask, true /* guard pages */,
		"before test");

	/*
	 * Adjusted start and end address are relative to the
	 * templates' first and last entry (holes ARE included)
	 */

	*out_start_address = list->entries.head->address + config->start_adjustment;
	*out_end_address = checker_end_address(list->entries.tail) + config->end_adjustment;
	assert(*out_start_address < *out_end_address);

	*out_checker_list = list;
}


/*
 * Deallocate the real memory and update the checker for the end of a test.
 * The checker itself may be deallocated and replaced.
 */
static void
checker_deallocate_allocation(checker_list_t *list, vm_entry_checker_t *checker)
{
	assert(checker->kind == Allocation || checker->kind == Submap || checker->kind == Guard);

	kern_return_t kr = mach_vm_deallocate(mach_task_self(),
	    checker->address, checker->size);
	assert(kr == 0);

	if (checker->permanent) {
		/* permanent entry becomes inaccessible */
		checker->protection = VM_PROT_NONE;
		checker->max_protection = VM_PROT_NONE;

		/*
		 * hack: disable verification of some attributes
		 * that verify_vm_faultability perturbed
		 */
		checker->verify.object_attr = false;
		checker->verify.share_mode_attr = false;
		checker->verify.pages_resident_attr = false;

		/*
		 * Don't verify fill pattern because the verifier
		 * is noisy when the memory is inaccessible.
		 */
		if (checker->object) {
			checker->object->verify.fill_pattern_attr = false;
		}
	} else {
		/* nonpermanent entry becomes a deallocated hole */
		vm_entry_checker_t *new_hole =
		    make_checker_for_hole(checker->address, checker->size);
		checker_list_replace_checker(list, checker, new_hole);
	}
}

/*
 * Deallocate the VM allocations covered by the checkers.
 * Updates the checkers so that entry permanence can be verified later.
 * Does not deallocate any guard pages.
 *
 * Not recommended after verification errors because the
 * true VM allocations may not match the checkers' list.
 */
static void
deallocate_vm_allocations(checker_list_t *list)
{
	/* not FOREACH_CHECKER due to use-after-free */
	vm_entry_checker_t *checker = list->entries.head;
	vm_entry_checker_t *end = list->entries.tail ? list->entries.tail->next : NULL;
	while (checker != end) {
		vm_entry_checker_t *next = checker->next;

		switch (checker->kind) {
		case Allocation:
		case Submap:
			checker_deallocate_allocation(list, checker);
			break;
		case Hole:
		case Guard:
		case EndEntries:
			/* nothing allocated */
			break;
		}

		checker = next;
	}
}

/*
 * Deallocate the memory backing any guard pages in the checker list.
 * Does not update the checkers themselves.
 *
 * Not recommended after verification errors because the
 * true VM allocations may not match the checkers' list.
 */
static void
deallocate_guard_page_allocations(checker_list_t *list)
{
	FOREACH_CHECKER(checker, list->guard_pages) {
		assert(checker->kind == Guard);
		kern_return_t kr = mach_vm_deallocate(mach_task_self(),
		    checker->address, checker->size);
		assert(kr == 0);
	}
}

static void
learn_object_id(
	checker_list_t *checker_list,
	vm_object_checker_t *obj_checker,
	uint64_t object_id,
	vm_entry_attribute_list_t * const out_bad_entry_attr,
	vm_object_attribute_list_t * const out_bad_object_attr,
	const char *message)
{
	assert(obj_checker->object_id_mode != object_has_known_id);

	if (find_object_checker_for_object_id(checker_list, object_id)) {
		/*
		 * This object should have its own id,
		 * but we already have another object
		 * checker with this id. That's bad.
		 */
		T_FAIL("%s: wrong object id (expected new id, got existing id)", message);
		out_bad_entry_attr->object_attr = true;
		out_bad_object_attr->object_id_attr = true;
	} else {
		/*
		 * Remember this object id.
		 * If other entries should have the same object
		 * but don't then the mismatch will be
		 * detected when they are verified.
		 */
		obj_checker->object_id_mode = object_has_known_id;
		obj_checker->object_id = object_id;
	}
}

/*
 * Verify VM state of an address range that is expected to be an allocation.
 * Returns true if it looks correct.
 * T_FAILs and logs details and returns false if it looks wrong.
 */
static bool
verify_allocation(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	const char *message)
{
	vm_entry_attribute_list_t bad_entry_attr =
	    vm_entry_attributes_with_default(false);
	vm_object_attribute_list_t bad_object_attr =
	    vm_object_attributes_with_default(false);

	assert(checker->kind == Allocation || checker->kind == Submap || checker->kind == Guard);

	/* Call vm_region to get the actual VM state */
	mach_vm_address_t actual_address = checker->address;
	mach_vm_size_t actual_size = 0;
	vm_region_submap_info_data_64_t info;
	if (!get_info_for_address(&actual_address, &actual_size, &info, checker->submap_depth)) {
		/* address was unmapped - not a valid allocation */
		if (checker->submap_depth && is_mapped(checker->address, 0)) {
			/* address was mapped, but checker wanted a submap */
			T_FAIL("%s: allocation was expected to be in a submap", message);
		} else {
			/* address was unmapped at every submap depth */
			T_FAIL("%s: allocation was not mapped", message);
		}
		bad_entry_attr.is_submap_attr = true;
		bad_entry_attr.submap_depth_attr = true;
		warn_bad_checker(checker, bad_entry_attr, bad_object_attr, message);
		return false;
	}

	/* Report any differences between the checker and the actual state. */

	if (actual_address != checker->address ||
	    actual_size != checker->size) {
		/* address is mapped, but region doesn't match template exactly */
		T_FAIL("%s: entry bounds did not match", message);
		bad_entry_attr.address_attr = true;
		bad_entry_attr.size_attr = true;
	}

	if (checker->verify.protection_attr &&
	    info.protection != checker->protection) {
		T_FAIL("%s: wrong protection", message);
		bad_entry_attr.protection_attr = true;
	}
	if (checker->verify.max_protection_attr &&
	    info.max_protection != checker->max_protection) {
		T_FAIL("%s: wrong max protection", message);
		bad_entry_attr.max_protection_attr = true;
	}
	if (checker->verify.inheritance_attr &&
	    info.inheritance != checker->inheritance) {
		T_FAIL("%s: wrong inheritance", message);
		bad_entry_attr.inheritance_attr = true;
	}
	if (checker->verify.behavior_attr &&
	    info.behavior != checker->behavior) {
		T_FAIL("%s: wrong behavior", message);
		bad_entry_attr.behavior_attr = true;
	}
	if (checker->verify.user_wired_count_attr &&
	    info.user_wired_count != checker->user_wired_count) {
		T_FAIL("%s: wrong user wired count", message);
		bad_entry_attr.user_wired_count_attr = true;
	}
	if (checker->verify.user_tag_attr &&
	    info.user_tag != checker->user_tag) {
		T_FAIL("%s: wrong user tag", message);
		bad_entry_attr.user_tag_attr = true;
	}
	if (checker->verify.is_submap_attr &&
	    info.is_submap != checker_is_submap(checker)) {
		T_FAIL("%s: wrong is_submap", message);
		bad_entry_attr.is_submap_attr = true;
		bad_entry_attr.submap_depth_attr = true;
	}

	if (checker->verify.object_offset_attr &&
	    info.offset != checker->object_offset + checker->vm_region_object_offset_tweak) {
		T_FAIL("%s: wrong object offset", message);
		bad_entry_attr.object_offset_attr = true;
	}

	if (checker->verify.object_attr) {
		vm_object_checker_t *obj_checker = checker->object;
		assert(obj_checker != NULL);
		assert(obj_checker->kind != Deinited);

		unsigned vm_region_ref_count = object_checker_get_vm_region_ref_count(obj_checker);
		unsigned shadow_depth = object_checker_get_shadow_depth(obj_checker);

		if (obj_checker->verify.object_id_attr) {
			switch (obj_checker->object_id_mode) {
			case object_is_unknown:
				learn_object_id(checker_list, obj_checker, info.object_id_full,
				    &bad_entry_attr, &bad_object_attr, message);
				break;
			case object_has_unknown_nonnull_id:
				/*
				 * We don't know the right object id,
				 * but we know that zero is wrong.
				 */
				if (info.object_id_full == 0) {
					T_FAIL("%s: wrong object id (expected nonzero)", message);
					bad_entry_attr.object_attr = true;
					bad_object_attr.object_id_attr = true;
					break;
				}
				learn_object_id(checker_list, obj_checker, info.object_id_full,
				    &bad_entry_attr, &bad_object_attr, message);
				break;
			case object_has_known_id:
				if (info.object_id_full != obj_checker->object_id) {
					T_FAIL("%s: wrong object id", message);
					bad_entry_attr.object_attr = true;
					bad_object_attr.object_id_attr = true;
				}
				break;
			}
		}

		/*
		 * can't check object's true size, but we can
		 * check that it is big enough for this vm entry
		 */
		if (obj_checker->verify.size_attr &&
		    info.offset + actual_size > obj_checker->size) {
			T_FAIL("%s: entry extends beyond object's expected size", message);
			bad_entry_attr.object_attr = true;
			bad_object_attr.size_attr = true;
		}

		if (obj_checker->verify.ref_count_attr &&
		    info.ref_count != vm_region_ref_count) {
			T_FAIL("%s: wrong object ref count (want %u got %u)",
			    message, vm_region_ref_count, info.ref_count);
			bad_entry_attr.object_attr = true;
			bad_object_attr.ref_count_attr = true;
		}

		if (obj_checker->verify.shadow_depth_attr &&
		    info.shadow_depth != shadow_depth) {
			T_FAIL("%s: wrong object shadow depth (want %u got %u)",
			    message, shadow_depth, info.shadow_depth);
			bad_entry_attr.object_attr = true;
			bad_object_attr.shadow_depth_attr = true;
		}

		/* Verify fill pattern after checking the rest of the object */
		if (!obj_checker->verify.fill_pattern_attr) {
			/* fill pattern check disabled */
		} else if (bad_entry_attr.address_attr || bad_entry_attr.size_attr) {
			/* don't try to verify fill if the address or size were bad */
		} else if (obj_checker->fill_pattern.mode == DontFill) {
			/* no fill pattern set, don't verify it */
		} else if (!(info.protection & VM_PROT_READ)) {
			/* protection disallows read, can't verify fill pattern */
			T_LOG("note: %s: can't verify fill pattern of unreadable memory (%s/%s)",
			    message, name_for_prot(info.protection), name_for_prot(info.max_protection));
		} else {
			/* verify the fill pattern */
			mach_vm_address_t first_bad_address;
			if (!verify_fill_pattern(actual_address, actual_size,
			    obj_checker->fill_pattern, &first_bad_address)) {
				T_FAIL("%s: wrong fill at address 0x%llx "
				    "(expected 0x%016llx, got 0x%016llx)",
				    message, first_bad_address,
				    obj_checker->fill_pattern.pattern,
				    *(uint64_t *)first_bad_address);
				bad_entry_attr.object_attr = true;
				bad_object_attr.fill_pattern_attr = true;
			}
		}
	}

	/* do this after checking the object */
	if (checker->verify.share_mode_attr &&
	    !same_share_mode(&info, checker)) {
		T_FAIL("%s: wrong share mode", message);
		bad_entry_attr.share_mode_attr = true;
	}

	/* do this after checking the object */
	if (checker->verify.pages_resident_attr) {
		uint32_t checker_pages_resident = checker_count_vm_region_pages_resident(checker);
		if (info.pages_resident != checker_pages_resident) {
			T_FAIL("%s: wrong pages resident count (want %u, got %u)",
			    message, checker_pages_resident, info.pages_resident);
			bad_entry_attr.pages_resident_attr = true;
		}
	}

	/*
	 * checker->permanent can only be tested destructively.
	 * We don't verify it until the end of the test.
	 */

	if (bad_entry_attr.bits != 0 || bad_object_attr.bits != 0) {
		warn_bad_checker(checker, bad_entry_attr, bad_object_attr, message);
		return false;
	}

	return true;
}


/*
 * Verify VM state of an address range that is
 * expected to be an unallocated hole.
 * Returns true if it looks correct.
 * T_FAILs and logs details and returns false if it looks wrong.
 */
static bool
verify_hole(vm_entry_checker_t *checker, const char *message)
{
	bool good = true;

	assert(checker->kind == Hole);

	/* zero-size hole is always presumed valid */
	if (checker->size == 0) {
		return true;
	}

	mach_vm_address_t actual_address = checker->address;
	mach_vm_size_t actual_size = 0;
	vm_region_submap_info_data_64_t info;
	if (get_info_for_address_fast(&actual_address, &actual_size, &info)) {
		/* address was mapped - not a hole */
		T_FAIL("%s: expected hole is not a hole", message);
		good = false;
	} else if (actual_address < checker_end_address(checker)) {
		/* [address, address + size) was partly mapped - not a hole */
		T_FAIL("%s: expected hole is not a hole", message);
		good = false;
	} else {
		/* [address, address + size) was entirely unmapped */
	}

	if (!good) {
		warn_bad_checker(checker,
		    vm_entry_attributes_with_default(true),
		    vm_object_attributes_with_default(true),
		    message);
	}
	return good;
}

static bool
verify_vm_state_nested(checker_list_t *checker_list, bool in_submap, const char *message)
{
	bool good = true;

	if (Verbose) {
		T_LOG("*** %s: verifying vm entries %s ***",
		    message, in_submap ? "(in submap) " : "");
	}

	vm_entry_checker_t *last_checked = NULL;
	FOREACH_CHECKER(checker, checker_list->entries) {
		last_checked = checker;

		switch (checker->kind) {
		case Allocation:
			good &= verify_allocation(checker_list, checker, message);
			break;
		case Hole:
			good &= verify_hole(checker, message);
			break;
		case Submap: {
			/* Verify the submap entry in the parent map. */
			good &= verify_allocation(checker_list, checker, message);

			/* Verify the submap's contents. */

			/*
			 * Adjust the submap content checkers to match
			 * vm_region output within this submap entry.
			 * Undo those adjustments at end of scope.
			 */
			checker_list_t *submap_checkers DEFER_UNSLIDE =
			    checker_get_and_slide_submap_checkers(checker);
			checker_list_tweaks_t tweaks DEFER_UNTWEAK =
			    submap_checkers_tweak_for_vm_region(submap_checkers, checker);

			good &= verify_vm_state_nested(submap_checkers, true, message);
			break;
		}
		case Guard:
		case EndEntries:
		default:
			assert(0);
		}
	}
	assert(last_checked == checker_list->entries.tail);

	if (in_submap) {
		/* don't dump submap alone, wait until we're back at the top level */
	} else if (!good || Verbose) {
		T_LOG("*** %s: all expected ***", message);
		dump_checker_range(checker_list->entries);
		T_LOG("*** %s: all actual ***", message);
		dump_region_info_for_entries(checker_list->entries);
	}

	return good;
}

static bool
verify_guard_pages(checker_list_t *checker_list, const char *message)
{
	bool good = true;

	if (Verbose) {
		T_LOG("*** %s: verifying guard pages ***", message);
	}

	vm_entry_checker_t *last_checked;

	last_checked = NULL;
	FOREACH_CHECKER(checker, checker_list->guard_pages) {
		last_checked = checker;
		assert(checker->kind == Guard);
		good &= verify_allocation(checker_list, checker, message);
	}
	assert(last_checked == checker_list->guard_pages.tail);

	if (!good || Verbose) {
		T_LOG("*** %s: all expected guard pages ***", message);
		dump_checker_range(checker_list->guard_pages);
		T_LOG("*** %s: all actual guard pages ***", message);
		dump_region_info_for_entries(checker_list->guard_pages);
	}

	return good;
}


test_result_t
verify_vm_state(checker_list_t *checker_list, const char *message)
{
	assert(!checker_list->is_slid);
	bool good = true;
	good &= verify_guard_pages(checker_list, message);
	good &= verify_vm_state_nested(checker_list, false, message);
	return good ? TestSucceeded : TestFailed;
}


/*
 * Get the expected errors for read and write faults
 * inside the given checker's memory.
 * The signals are:
 *     0       (mapped and readable / writeable)
 *     KERN_PROTECTION_FAILURE  (mapped but not readable / writeable)
 *     KERN_INVALID_ADDRESS (unmapped)
 */
static void
get_expected_errors_for_faults(
	vm_entry_checker_t *checker,
	kern_return_t * const out_read_error,
	kern_return_t * const out_write_error)
{
	switch (checker->kind) {
	case Allocation:
	case Guard:
		/* mapped: error is either none or protection failure */
		switch (checker->protection & (VM_PROT_READ | VM_PROT_WRITE)) {
		case VM_PROT_READ | VM_PROT_WRITE:
			/* mapped, read/write */
			*out_read_error = 0;
			*out_write_error = 0;
			break;
		case VM_PROT_READ:
			/* mapped, read-only */
			*out_read_error = 0;
			*out_write_error = KERN_PROTECTION_FAILURE;
			break;
		case VM_PROT_WRITE:
			/* mapped, "write-only" but inaccessible to faults */
			*out_read_error = KERN_PROTECTION_FAILURE;
			*out_write_error = KERN_PROTECTION_FAILURE;
			break;
		case 0:
			/* mapped, inaccessible */
			*out_read_error = KERN_PROTECTION_FAILURE;
			*out_write_error = KERN_PROTECTION_FAILURE;
			break;
		default:
			T_FAIL("unexpected protection %s", name_for_prot(checker->protection));
		}
		break;
	case Hole:
		/* unmapped: error is invalid address */
		*out_read_error = KERN_INVALID_ADDRESS;
		*out_write_error = KERN_INVALID_ADDRESS;
		break;
	case EndEntries:
	default:
		assert(0);
	}
}


static fill_pattern_t
checker_fill_pattern(vm_entry_checker_t *checker)
{
	if (checker->object == NULL) {
		return (fill_pattern_t){ .mode = DontFill, .pattern = 0 };
	}
	return checker->object->fill_pattern;
}

static bool
checker_should_verify_fill_pattern(vm_entry_checker_t *checker)
{
	return checker->verify.object_attr &&
	       checker->object != NULL &&
	       checker->object->verify.fill_pattern_attr &&
	       checker->object->fill_pattern.mode == Fill;
}

/*
 * Verify read and/or write faults on every page of checker's address range.
 */
bool
verify_checker_faultability(
	vm_entry_checker_t *checker,
	const char *message,
	bool verify_reads,
	bool verify_writes)
{
	return verify_checker_faultability_in_address_range(checker, message,
	           verify_reads, verify_writes, checker->address, checker->size);
}

bool
verify_checker_faultability_in_address_range(
	vm_entry_checker_t *checker,
	const char *message,
	bool verify_reads,
	bool verify_writes,
	mach_vm_address_t checked_address,
	mach_vm_size_t checked_size)
{
	assert(verify_reads || verify_writes);

	if (Verbose) {
		const char *faults;
		if (verify_reads && verify_writes) {
			faults = "read and write";
		} else if (verify_reads) {
			faults = "read";
		} else {
			faults = "write";
		}
		T_LOG("%s: trying %s faults in [0x%llx..0x%llx)",
		    message, faults, checked_address, checked_address + checked_size);
	}

	/* range to be checked must fall within the checker */
	assert(checked_size > 0);
	assert(checker_contains_address(checker, checked_address));
	assert(checker_contains_address(checker, checked_address + checked_size - 1));

	/* read and write use the fill pattern if any */
	fill_pattern_t fill_pattern = checker_fill_pattern(checker);
	bool enforce_expected_byte = checker_should_verify_fill_pattern(checker);
#if BYTE_ORDER == LITTLE_ENDIAN
	uint8_t expected_byte = fill_pattern.pattern & 0xff;
#else
	uint8_t expected_byte = fill_pattern.pattern >> 56;
#endif

	bool good = true;
	kern_return_t expected_read_error, expected_write_error;
	get_expected_errors_for_faults(checker,
	    &expected_read_error, &expected_write_error);

	mach_vm_address_t start = checked_address;
	mach_vm_address_t end = checked_address + checked_size;
	for (mach_vm_address_t addr = start; addr < end; addr += PAGE_SIZE) {
		if (verify_reads) {
			uint8_t actual_byte;
			kern_return_t actual_read_error;
			try_read_byte(addr, &actual_byte, &actual_read_error);
			if (expected_read_error != actual_read_error) {
				T_FAIL("%s: wrong error %d %s (expected %d %s) "
				    "when reading from address 0x%llx",
				    message, actual_read_error, name_for_kr(actual_read_error),
				    expected_read_error, name_for_kr(expected_read_error), addr);
				good = false;
				break;
			}
			if (enforce_expected_byte &&
			    actual_read_error == KERN_SUCCESS &&
			    expected_byte != actual_byte) {
				T_FAIL("%s: wrong byte 0x%hhx (expected 0x%hhx) "
				    "read from address 0x%llx",
				    message, actual_byte, expected_byte, addr);
				good = false;
				break;
			}
		}

		if (verify_writes) {
			kern_return_t actual_write_error;
			try_write_byte(addr, expected_byte, &actual_write_error);
			if (expected_write_error != actual_write_error) {
				T_FAIL("%s: wrong error %d %s (expected %d %s) "
				    "when writing to address 0x%llx",
				    message, actual_write_error, name_for_kr(actual_write_error),
				    expected_write_error, name_for_kr(expected_write_error), addr);
				good = false;
				break;
			}
		}
	}

	if (!good) {
		warn_bad_checker(checker,
		    vm_entry_attributes_with_default(true),
		    vm_object_attributes_with_default(true),
		    message);
	}

	return good;
}


static test_result_t
verify_vm_faultability_nested(
	checker_list_t *checker_list,
	const char *message,
	bool verify_reads,
	bool verify_writes,
	bool in_submap)
{
	bool good = true;

	if (Verbose) {
		T_LOG("*** %s: verifying vm faultability %s ***",
		    message, in_submap ? "(in submap) " : "");
	}

	FOREACH_CHECKER(checker, checker_list->entries) {
		bool really_verify_writes = verify_writes;

		if (prot_contains_all(checker->protection, VM_PROT_READ | VM_PROT_WRITE)) {
			/*
			 * Don't try writing to "writeable" submap allocations.
			 * That provokes unnesting which confuses us, because
			 * we don't update the checkers for that unnesting here.
			 * TODO: implement write fault testing in writeable submaps
			 */
			if (checker_is_submap(checker)) {
				/* checker is parent map's submap entry with +rw */
				really_verify_writes = false;
			} else if (in_submap) {
				/* checker is submap contents with +rw */
				really_verify_writes = false;
			}
		}

		/* Read and/or write from the checker's memory. */

		if (checker_is_submap(checker)) {
			/* Verify based on submap contents. */
			T_QUIET; T_ASSERT_FALSE(in_submap, "nested submaps not allowed");

			/*
			 * Adjust the submap content checkers to match
			 * vm_region output within this submap entry.
			 * Undo those adjustments at end of scope.
			 */
			checker_list_t *submap_checkers DEFER_UNSLIDE =
			    checker_get_and_slide_submap_checkers(checker);
			checker_list_tweaks_t tweaks DEFER_UNTWEAK =
			    submap_checkers_tweak_for_vm_region(submap_checkers, checker);

			good &= verify_vm_faultability_nested(submap_checkers, message,
			    verify_reads, really_verify_writes, true /* in_submap */);
		} else {
			good &= verify_checker_faultability(checker,
			    message, verify_reads, verify_writes);
		}
	}

	if (in_submap) {
		/* don't dump submap alone, wait until we're back at the top level */
	} else if (!good || Verbose) {
		T_LOG("*** %s: all expected ***", message);
		dump_checker_range(checker_list->entries);
		T_LOG("*** %s: all actual ***", message);
		dump_region_info_for_entries(checker_list->entries);
	}

	return good ? TestSucceeded : TestFailed;
}

test_result_t
verify_vm_faultability(
	checker_list_t *checker_list,
	const char *message,
	bool verify_reads,
	bool verify_writes)
{
	return verify_vm_faultability_nested(checker_list, message,
	           verify_reads, verify_writes, false /* in_submap */);
}


/* Inserts new_left to the left of old_right. */
static void
checker_insert_left(
	vm_entry_checker_t *new_left,
	vm_entry_checker_t *old_right)
{
	assert(new_left);
	assert(old_right);

	new_left->prev = old_right->prev;
	new_left->next = old_right;

	old_right->prev = new_left;
	if (new_left->prev) {
		new_left->prev->next = new_left;
	}
}

/* Inserts new_right to the right of old_left. */
static void
checker_insert_right(
	vm_entry_checker_t *old_left,
	vm_entry_checker_t *new_right)
{
	assert(old_left);
	assert(new_right);

	new_right->prev = old_left;
	new_right->next = old_left->next;

	old_left->next = new_right;
	if (new_right->next) {
		new_right->next->prev = new_right;
	}
}

/*
 * Split a checker into two checkers at an address.
 * On entry, the checker has already been cloned into two identical checkers.
 * This function modifies the clones to make two separate checkers.
 */
static void
checker_split_clones(
	vm_entry_checker_t *left,
	vm_entry_checker_t *right,
	mach_vm_address_t split)
{
	mach_vm_address_t start = left->address;
	mach_vm_address_t end = checker_end_address(left);

	assert(split > start);
	assert(split < end);

	assert(left->next == right);
	assert(right->prev == left);

	left->address = start;
	left->size = split - start;
	right->address = split;
	right->size = end - split;

	right->object_offset = left->object_offset + left->size;
}

vm_entry_checker_t *
checker_clip_right(
	checker_list_t *list,
	vm_entry_checker_t *left,
	mach_vm_address_t split)
{
	if (split > left->address && split < checker_end_address(left)) {
		vm_entry_checker_t *right = checker_clone(left);
		checker_insert_right(left, right);
		checker_split_clones(left, right, split);
		if (list && list->entries.tail == left) {
			list->entries.tail = right;
		}
		return right;
	}
	return NULL;
}

vm_entry_checker_t *
checker_clip_left(
	checker_list_t *list,
	vm_entry_checker_t *right,
	mach_vm_address_t split)
{
	if (split > right->address && split < checker_end_address(right)) {
		vm_entry_checker_t *left = checker_clone(right);
		checker_insert_left(left, right);
		checker_split_clones(left, right, split);
		if (list && list->entries.head == right) {
			list->entries.head = left;
		}
		return left;
	}
	return NULL;
}

static entry_checker_range_t
checker_list_try_find_range_including_holes(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	mach_vm_address_t end = start + size;
	vm_entry_checker_t *first = NULL;
	vm_entry_checker_t *last = NULL;

	assert(start >= list->entries.head->address);
	assert(end <= checker_end_address(list->entries.tail));
	assert(end >= start);

	FOREACH_CHECKER(checker, list->entries) {
		/* find the first entry that ends after the start address */
		if (checker_end_address(checker) > start && !first) {
			first = checker;
		}
		/* find the last entry that begins before the end address */
		if (checker->address < end) {
			last = checker;
		}
	}

	return (entry_checker_range_t){ first, last };
}

entry_checker_range_t
checker_list_find_range_including_holes(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	entry_checker_range_t result =
	    checker_list_try_find_range_including_holes(list, start, size);
	vm_entry_checker_t *first = result.head;
	vm_entry_checker_t *last = result.tail;

	assert(first && last);
	assert(first->address <= last->address);

	return result;
}

entry_checker_range_t
checker_list_find_range(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	entry_checker_range_t result =
	    checker_list_find_range_including_holes(list, start, size);

	FOREACH_CHECKER(checker, result) {
		assert(checker->kind != Hole);
	}

	return result;
}

vm_entry_checker_t *
checker_list_find_checker(checker_list_t *list, mach_vm_address_t addr)
{
	entry_checker_range_t found =
	    checker_list_try_find_range_including_holes(list, addr, 0);
	vm_entry_checker_t *checker = found.head;

	if (!checker) {
		return NULL;
	}
	if (addr < checker->address || addr >= checker_end_address(checker)) {
		return NULL;
	}

	return checker;
}

vm_entry_checker_t *
checker_list_find_allocation(checker_list_t *list, mach_vm_address_t addr)
{
	vm_entry_checker_t *checker = checker_list_find_checker(list, addr);

	if (checker->kind != Allocation) {
		return NULL;
	}

	return checker;
}

entry_checker_range_t
checker_list_find_and_clip(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	entry_checker_range_t limit = checker_list_find_range(list, start, size);
	checker_clip_left(list, limit.head, start);
	checker_clip_right(list, limit.tail, start + size);
	return limit;
}

entry_checker_range_t
checker_list_find_and_clip_including_holes(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	mach_vm_address_t end = start + size;
	entry_checker_range_t limit =
	    checker_list_find_range_including_holes(list, start, size);

	if (checker_contains_address(limit.head, start)) {
		checker_clip_left(list, limit.head, start);
		assert(limit.head->address == start);
	}
	if (checker_contains_address(limit.tail, end)) {
		checker_clip_right(list, limit.tail, end);
		assert(checker_end_address(limit.tail) == end);
	}

	return limit;
}

static bool
can_simplify_kind(vm_entry_checker_t *left, vm_entry_checker_t *right)
{
	return (left->kind == Allocation && right->kind == Allocation) ||
	       (left->kind == Submap && right->kind == Submap);
}

void
checker_simplify_left(
	checker_list_t *list,
	vm_entry_checker_t *right)
{
	vm_entry_checker_t *left = right->prev;
	if (!left) {
		return;
	}
	if (can_simplify_kind(left, right) &&
	    left->protection == right->protection &&
	    left->max_protection == right->max_protection &&
	    left->inheritance == right->inheritance &&
	    left->behavior == right->behavior &&
	    left->user_wired_count == right->user_wired_count &&
	    left->user_tag == right->user_tag &&
	    left->submap_depth == right->submap_depth &&
	    left->object == right->object &&
	    left->object_offset + left->size == right->object_offset &&
	    left->permanent == right->permanent) {
		/* kill left and keep right so the simplify loop works unimpeded */
		right->address = left->address;
		right->size += left->size;
		right->object_offset = left->object_offset;

		/* update other properties that may differ */

		/*
		 * unlink and free left checker
		 * update the checker list if we are deleting its head
		 */
		right->prev = left->prev;
		if (left->prev) {
			left->prev->next = right;
		}
		if (list->entries.head == left) {
			list->entries.head = right;
		}
		checker_free(left);
	}
}

void
checker_list_simplify(
	checker_list_t *list,
	mach_vm_address_t start,
	mach_vm_size_t size)
{
	mach_vm_address_t end = start + size;
	entry_checker_range_t limit = checker_list_find_range_including_holes(list, start, size);

	/* vm_map_simplify_range() also includes any entry that starts at `end` */
	if (limit.tail && limit.tail->next && limit.tail->next->address == end) {
		limit.tail = limit.tail->next;
	}

	FOREACH_CHECKER(checker, limit) {
		checker_simplify_left(list, checker);
	}
}


void
checker_list_insert(
	checker_list_t *list,
	vm_entry_checker_t *inserted)
{
	if (list->entries.head == NULL) {
		/* List is empty. */
		list->entries.head = list->entries.tail = inserted;
	} else if (checker_end_address(inserted) <= list->entries.head->address) {
		/* Insertion goes before every item in the list. */
		checker_insert_left(inserted, list->entries.head);
		list->entries.head = inserted;
	} else if (checker_end_address(list->entries.tail) <= inserted->address) {
		/* Insertion goes after every item in the list. */
		checker_insert_right(list->entries.tail, inserted);
		list->entries.tail = inserted;
	} else {
		/*
		 * Insertion goes in the middle somewhere.
		 * Find every entry that precedes the inserted item
		 * in address order and insert after the last of those.
		 */
		mach_vm_size_t size = inserted->address - list->entries.head->address;
		entry_checker_range_t found;
		found = checker_list_find_range_including_holes(
			list, list->entries.head->address, size);
		checker_insert_right(found.tail, inserted);
	}

	/* Verify address order. */
	if (inserted->next) {
		assert(checker_end_address(inserted) <= inserted->next->address);
	}
	if (inserted->prev) {
		assert(checker_end_address(inserted->prev) <= inserted->address);
	}
}

void
checker_list_replace_range(
	checker_list_t *list,
	entry_checker_range_t old_range,
	entry_checker_range_t new_range)
{
	/* old_range and new_range must coincide */
	assert(checker_range_start_address(old_range) == checker_range_start_address(new_range));
	assert(checker_range_end_address(old_range) == checker_range_end_address(new_range));

	/*
	 * Unlink old_range and link in new_range.
	 * Update list->entries if necessary.
	 *
	 * before: ... prev old_range next ...
	 * after:  ... prev new_range next ...
	 * a.k.a:  ... prev new_left ... new_right next ...
	 */
	vm_entry_checker_t *prev = old_range.head->prev;
	vm_entry_checker_t *new_left = new_range.head;
	new_left->prev = prev;
	if (prev) {
		prev->next = new_left;
	} else {
		list->entries.head = new_left;
	}

	vm_entry_checker_t *next = old_range.tail->next;
	vm_entry_checker_t *new_right = new_range.tail;
	new_right->next = next;
	if (next) {
		next->prev = new_right;
	} else {
		list->entries.tail = new_right;
	}

	/* Destroy the removed entries. */
	/* TODO: update checker state to account for the removal? */
	checker_range_free(old_range);
}

void
checker_list_free_range(
	checker_list_t *list,
	entry_checker_range_t range)
{
	/* Make a new hole checker covering the removed range. */
	vm_entry_checker_t *new_hole = make_checker_for_hole(
		checker_range_start_address(range),
		checker_range_size(range));
	entry_checker_range_t new_range = { new_hole, new_hole };

	/* Remove checkers in the old range and insert the new hole. */
	checker_list_replace_range(list, range, new_range);
}


static bool
checker_has_null_vm_object(vm_entry_checker_t *checker)
{
	return object_is_null(checker->object);
}

void
checker_resolve_null_vm_object(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker)
{
	if (checker_has_null_vm_object(checker)) {
		/* entry's object offset is reset to zero */
		checker->object_offset = 0;

		/* entry gets a new object */
		vm_object_checker_t *obj_checker =
		    make_anonymous_object_checker(checker_list, checker->size);
		checker_set_object(checker, obj_checker);

		/* don't know the object's id yet, but we know it isn't zero */
		obj_checker->object_id_mode = object_has_unknown_nonnull_id;
	}
}

void
checker_fault_all(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker,
	vm_prot_t fault_prot)
{
	assert(fault_prot != VM_PROT_NONE);

	for (mach_vm_address_t address = checker->address;
	    address < checker_end_address(checker);
	    address += PAGE_SIZE) {
		kern_return_t kr = checker_fault_address(
			checker_list, checker, address, fault_prot);
		if (kr != KERN_SUCCESS) {
			return;
		}
	}
}

void
checker_write_new_fill_pattern(
	checker_list_t *checker_list,
	vm_entry_checker_t *checker)
{
	/*
	 * Choose a random fill pattern that differs from the old one.
	 * Random pattern also means we are unlikely to duplicate any
	 * pattern used previously by this checker or by any other checker.
	 */
	fill_pattern_t old_fill = checker_fill_pattern(checker);
	fill_pattern_t new_fill = {
		.mode = Fill,
		.pattern = 0
	};
	do {
		arc4random_buf(&new_fill.pattern, sizeof(new_fill.pattern));
	} while (new_fill.pattern == old_fill.pattern);

	/* Update memory. */
	write_fill_pattern(checker->address, checker->size, new_fill);

	/* Update checker state. */
	checker_fault_all(checker_list, checker, VM_PROT_WRITE);
	checker->object->fill_pattern = new_fill;
}


vm_entry_checker_t *
checker_list_try_unnest_one_entry_in_submap(
	checker_list_t *checker_list,
	vm_entry_checker_t *submap_parent,
	bool unnest_readonly,
	mach_vm_address_t * const inout_next_address)
{
	mach_vm_address_t unnest_start;
	mach_vm_address_t unnest_end;
	vm_entry_checker_t *unnested_checker;
	vm_prot_t submap_protection;
	vm_prot_t submap_max_protection;
	vm_object_checker_t *obj_checker;

	{
		/* Find the checker for the entry inside the submap at this parent map address. */
		checker_list_t *submap_checkers DEFER_UNSLIDE =
		    checker_get_and_slide_submap_checkers(submap_parent);
		vm_entry_checker_t *submap_content =
		    checker_list_find_checker(submap_checkers, *inout_next_address);

		/* Compute the range to be unnested if required, and advance past it. */
		unnest_start = submap_content->address;
		unnest_end = checker_end_address(submap_content);
		clamp_start_end_to_checker(&unnest_start, &unnest_end, submap_parent);
		*inout_next_address = unnest_end;

		/* Return now if the submap content does not need to be unnested. */
		switch (submap_content->kind) {
		case Allocation:
			if (!(submap_content->protection & VM_PROT_WRITE) && !unnest_readonly) {
				/*
				 * Allocation is read-only and unnest_readonly is not set.
				 * Don't unnest this.
				 */
				return NULL;
			}
			break;
		case Hole:
			/* Unallocated in submap. Don't unnest. */
			return NULL;
		case Submap:
			assert(0 && "nested submaps not allowed");
		case Guard:
			assert(0 && "guard pages in submaps not allowed");
		default:
			assert(0 && "unknown checker kind");
		}

		submap_protection = submap_content->protection;
		submap_max_protection = submap_content->max_protection;
		obj_checker = submap_content->object;

		/*
		 * Unslide the submap checkers now at end of scope.
		 * Changing the submap parent map entry from a submap
		 * to an allocation (below) may leave the submap checkers
		 * unreferenced and thus deallocated.
		 */
	}

	/* Clip the submap parent to the unnest bounds. */
	checker_clip_left(checker_list, submap_parent, unnest_start);
	checker_clip_right(checker_list, submap_parent, unnest_end);

	/*
	 * unnested_checker (nee submap_parent) now matches the unnesting bounds.
	 * Change its object and other attributes to become the unnested entry.
	 * (this matches the behavior of vm_map_lookup_and_lock_object(),
	 * which also edits the parent map entry in place)
	 */

	unnested_checker = submap_parent;
	unnested_checker->kind = Allocation;

	/*
	 * Set unnested_checker's protection and inheritance.
	 * Copied from vm_map_lookup_and_lock_object.
	 */
	if (unnested_checker->protection != VM_PROT_READ) {
		/*
		 * Someone has already altered the top entry's
		 * protections via vm_protect(VM_PROT_COPY).
		 * Respect these new values and ignore the
		 * submap entry's protections.
		 */
	} else {
		/*
		 * Regular copy-on-write: propagate the submap
		 * entry's protections to the top map entry.
		 */
		unnested_checker->protection |= submap_protection;
	}
	unnested_checker->max_protection |= submap_max_protection;
	if (unnested_checker->inheritance == VM_INHERIT_SHARE) {
		unnested_checker->inheritance = VM_INHERIT_COPY;
	}

	/*
	 * Set unnested_checker's vm object.
	 * unnesting is a copy-on-write copy.
	 */
	checker_set_object(unnested_checker, obj_checker);
	if (!object_is_null(obj_checker)) {
		/*
		 * Constant submap contents are never copy_symmetric.
		 * Copy strategies other than copy_delay are unimplemented here.
		 */
		assert(obj_checker->copy_strategy == copy_delay);
		checker_copy_delayed(checker_list, unnested_checker);

		if (is_new_vm() && !(submap_protection & VM_PROT_WRITE)) {
			/*
			 * TODO new VM makes another copy when writing to
			 * an unwriteable submap?
			 */
			checker_copy_delayed(checker_list, unnested_checker);
		}
	}

	/* TODO: tpro, permanent, VM_PROT_EXEC */

	assert(*inout_next_address == checker_end_address(unnested_checker));

	return unnested_checker;
}

__attribute__((overloadable))
vm_config_t *
make_vm_config(
	const char *name,
	vm_entry_template_t *entry_templates,
	vm_object_template_t *object_templates,
	vm_entry_template_t *submap_entry_templates,
	vm_object_template_t *submap_object_templates,
	mach_vm_size_t start_adjustment,
	mach_vm_size_t end_adjustment,
	mach_vm_size_t alignment_mask)
{
	/*
	 * Allocate a new vm_config_t and populate it with
	 * copies of the name string and all of the templates.
	 */
	vm_config_t *result = calloc(sizeof(vm_config_t), 1);

	result->config_name = strdup(name);
	result->start_adjustment = start_adjustment;
	result->end_adjustment = end_adjustment;
	result->alignment_mask = alignment_mask;

	/* memcpy the templates */

#define COPY_TEMPLATE_LIST(T)                                           \
	unsigned T##_template_count = count_##T##_templates(T##_templates); \
	size_t T##_template_bytes = T##_template_count * sizeof(T##_templates[0]); \
	result->T##_templates = calloc(1, T##_template_bytes);          \
	result->T##_template_count = T##_template_count;                \
	memcpy(result->T##_templates, T##_templates, T##_template_bytes)

	COPY_TEMPLATE_LIST(entry);
	COPY_TEMPLATE_LIST(object);
	COPY_TEMPLATE_LIST(submap_entry);
	COPY_TEMPLATE_LIST(submap_object);

	/* fix up the pointers inside the templates */
	/* TODO: use indexes instead of pointers so that they don't need fixup */

#define ASSERT_IS_WITHIN(ptr, array, array_count) \
	assert((ptr) >= (array) && (ptr) < (array) + (array_count))

	for (unsigned i = 0; i < result->entry_template_count; i++) {
		vm_entry_template_t *tmpl = &result->entry_templates[i];
		if (tmpl->object) {
			/* fix up entry's object to point into the copied templates */
			ASSERT_IS_WITHIN(tmpl->object, object_templates, object_template_count);
			tmpl->object = &result->object_templates[tmpl->object - object_templates];
		}
	}
	for (unsigned i = 0; i < result->submap_entry_template_count; i++) {
		vm_entry_template_t *tmpl = &result->submap_entry_templates[i];
		if (tmpl->object) {
			/* fix up submap entry's object to point into the copied submap templates */
			ASSERT_IS_WITHIN(tmpl->object, submap_object_templates, submap_object_template_count);
			tmpl->object = &result->submap_object_templates[tmpl->object - submap_object_templates];
		}
	}
	for (unsigned i = 0; i < result->object_template_count; i++) {
		vm_object_template_t *tmpl = &result->object_templates[i];
		if (tmpl->kind != SubmapObject) {
			continue;
		}
		/* fix up submap's template lists to point into the copied submap templates */
		assert(tmpl->submap.entries);  /* submap must contain at least one entry */
		ASSERT_IS_WITHIN(tmpl->submap.entries, submap_entry_templates, submap_entry_template_count);
		ptrdiff_t submap_index = tmpl->submap.entries - submap_entry_templates;
		tmpl->submap.entries = &result->submap_entry_templates[submap_index];
		if (tmpl->submap.entry_count == 0) {
			tmpl->submap.entry_count = submap_entry_template_count - submap_index;
		}
		assert(submap_index + tmpl->submap.entry_count <= submap_entry_template_count);

		if (tmpl->submap.objects) {
			ASSERT_IS_WITHIN(tmpl->submap.objects, submap_object_templates, submap_object_template_count);
			ptrdiff_t object_index = tmpl->submap.objects - submap_object_templates;
			tmpl->submap.objects = &result->submap_object_templates[object_index];
			if (tmpl->submap.object_count == 0) {
				tmpl->submap.object_count = submap_object_template_count - object_index;
			}
			assert(object_index + tmpl->submap.object_count <= submap_object_template_count);
		}
	}
	for (unsigned i = 0; i < result->submap_object_template_count; i++) {
		/* no fixups needed inside submap_object_templates, they can't be nested submap objects */
		vm_object_template_t *tmpl = &result->submap_object_templates[i];
		assert(tmpl->kind != SubmapObject);
	}

#undef ASSERT_IS_WITHIN

	return result;
}


static void
free_vm_config(vm_config_t *config)
{
	free(config->entry_templates);
	free(config->object_templates);
	free(config->config_name);
	free(config);
}


/*
 * templates are initialized by vm_configurator_init()
 * because PAGE_SIZE is not a compile-time constant
 */
vm_object_template_t END_OBJECTS;
vm_entry_template_t END_ENTRIES = {};
vm_entry_template_t guard_entry_template = {};
vm_entry_template_t hole_template = {};

__attribute__((constructor))
static void
vm_configurator_init(void)
{
	/*
	 * Set Verbose if environment variable VERBOSE is set.
	 * Also set verbose_exc_helper to match.
	 */
	char *env_verbose = getenv("VERBOSE");
	if (env_verbose) {
		if (0 == strcasecmp(env_verbose, "0") ||
		    0 == strcasecmp(env_verbose, "false") ||
		    0 == strcasecmp(env_verbose, "no")) {
			/*
			 * VERBOSE is set to something false-ish like "NO".
			 * Don't enable it.
			 */
		} else {
			Verbose = true;
		}
	}

	verbose_exc_helper = Verbose;

	/*
	 * Verify some preconditions about page sizes.
	 * These would be static_asserts but PAGE_SIZE isn't constant.
	 */
	assert(DEFAULT_PARTIAL_ENTRY_SIZE > 0);
	assert(DEFAULT_PARTIAL_ENTRY_SIZE / 2 > 0);

	/*
	 * Initialize some useful templates.
	 * These would be static initializers but PAGE_SIZE isn't constant.
	 */
	guard_entry_template = vm_entry_template(
		.protection = 0, .max_protection = 0,
		.user_tag = VM_MEMORY_GUARD /* 31 */);
	hole_template =
	    vm_entry_template(.kind = Hole);
	END_ENTRIES =
	    vm_entry_template(.kind = EndEntries);
	END_OBJECTS = (vm_object_template_t){.kind = EndObjects, .size = 0};

	/*
	 * Initialize fault exception and guard exception handlers.
	 * Do this explicitly in the hope of avoiding memory allocations
	 * inside our unallocated address ranges later.
	 */
	exc_guard_helper_init();
	{
		static const char unwriteable = 1;
		kern_return_t kr;
		bool succeeded = try_write_byte((mach_vm_address_t)&unwriteable, 0, &kr);
		assert(!succeeded);
		assert(kr == KERN_PROTECTION_FAILURE);
	}

	/*
	 * host_priv is looked up lazily so we don't
	 * unnecessarily fail tests that don't need it.
	 */
}

test_result_t
test_is_unimplemented(
	checker_list_t *checker_list __unused,
	mach_vm_address_t start __unused,
	mach_vm_size_t size __unused)
{
	T_FAIL("don't call test_is_unimplemented()");
	return TestFailed;
}

void
run_one_vm_test(
	const char *filename,
	const char *funcname,
	const char *testname,
	configure_fn_t configure_fn,
	test_fn_t test_fn)
{
	vm_config_t *config;
	checker_list_t *checker_list;
	mach_vm_address_t vm_state_start_address;
	mach_vm_address_t vm_state_end_address;
	mach_vm_address_t test_fn_start_address;
	mach_vm_address_t test_fn_end_address;
	test_result_t result;

	const char *short_filename = strstr(filename, "tests/") ?: filename;

	if (test_fn == NULL) {
		/* vm_tests_t field not set. The test file needs to be updated. */
		T_FAIL("test %s.%s not present in test file %s; please write it",
		    funcname, testname, short_filename);
		return;
	} else if (test_fn == test_is_unimplemented) {
		/* Test is deliberately not implemented. */
		T_PASS("unimplemented test: %s %s %s",
		    short_filename, funcname, testname);
		return;
	}

	/* Prepare the VM state. */
	config = configure_fn();
	if (Verbose) {
		T_LOG("");
		T_LOG("*******************");  /* extra divider between tests */
		T_LOG("");
	}
	T_LOG("note: starting test: %s %s (%s) ...", funcname, testname, config->config_name);

	create_vm_state_from_config(config, &checker_list,
	    &test_fn_start_address, &test_fn_end_address);
	vm_state_start_address = checker_range_start_address(checker_list->entries);
	vm_state_end_address = checker_range_end_address(checker_list->entries);

	if (vm_state_start_address != test_fn_start_address ||
	    vm_state_end_address != test_fn_end_address) {
		T_LOG("note: prepared vm state is 0x%llx..0x%llx; calling tested function on 0x%llx..0x%llx",
		    vm_state_start_address, vm_state_end_address,
		    test_fn_start_address, test_fn_end_address);
	} else {
		T_LOG("note: prepared vm state is 0x%llx..0x%llx; calling tested function on the entire range",
		    vm_state_start_address, vm_state_end_address);
	}

	/* Run the test. */
	result = test_fn(checker_list, test_fn_start_address,
	    test_fn_end_address - test_fn_start_address);

	/*
	 * Verify and/or deallocate depending on the initial test result.
	 * These operations may change the result to a failure.
	 */
	switch (result) {
	case TestSucceeded:
		/*
		 * Verify one more time, then perform
		 * destructive verifications and deallocate.
		 */
		result = verify_vm_state(checker_list, "after test");
		if (result == TestSucceeded) {
			result = verify_vm_faultability(checker_list, "final faultability check", true, true);
		}
		if (result == TestSucceeded) {
			deallocate_vm_allocations(checker_list);
			result = verify_vm_state(checker_list, "after final deallocation");
		}
		if (result == TestSucceeded) {
			deallocate_guard_page_allocations(checker_list);
		}
		break;
	case TestFailed:
		/*
		 * we don't attempt to deallocate after a failure
		 * because we don't know where the real allocations are
		 */
		break;
	}

	checker_list_free(checker_list);

	/* Report the final test result. */
	if (result == TestFailed) {
		/* executable name is basename(short_filename) minus ".c" suffix */
		const char *exe_name = strrchr(short_filename, '/');
		exe_name = exe_name ? exe_name + 1 : short_filename;
		int exe_name_len = strrchr(exe_name, '.') - exe_name;
		const char *arch_cmd = isRosetta() ? "arch -x86_64 " : "";
		T_FAIL("%s %s %s (%s) failed above; run it locally with `env VERBOSE=1 %s%.*s -n %s %s`",
		    short_filename, funcname, testname, config->config_name,
		    arch_cmd, exe_name_len, exe_name, funcname, testname);
	} else {
		T_PASS("%s %s %s (%s)",
		    short_filename, funcname, testname, config->config_name);
	}

	free_vm_config(config);
}
