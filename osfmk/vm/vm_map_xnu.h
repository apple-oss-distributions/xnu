/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
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

#ifndef _VM_VM_MAP_XNU_H_
#define _VM_VM_MAP_XNU_H_

#ifdef XNU_KERNEL_PRIVATE

#include <mach/vm_types.h>
#include <sys/cdefs.h>
#include <vm/vm_map.h>

__BEGIN_DECLS

extern void     vm_map_reference(vm_map_t       map);
extern vm_map_t current_map(void);

/* Setup reserved areas in a new VM map */
extern kern_return_t    vm_map_exec(
	vm_map_t                new_map,
	task_t                  task,
	boolean_t               is64bit,
	void                    *fsroot,
	cpu_type_t              cpu,
	cpu_subtype_t           cpu_subtype,
	boolean_t               reslide,
	boolean_t               is_driverkit,
	uint32_t                rsr_version);



#ifdef  MACH_KERNEL_PRIVATE

#define current_map_fast()      (current_thread()->map)
#define current_map()           (current_map_fast())

/*
 *	Types defined:
 *
 *	vm_map_t		the high-level address map data structure.
 *	vm_map_entry_t		an entry in an address map.
 *	vm_map_copy_t		represents memory copied from an address map,
 *				 used for inter-map copy operations
 */

typedef struct vm_map_entry     *vm_map_entry_t;
#define VM_MAP_ENTRY_NULL       ((vm_map_entry_t) NULL)

#define named_entry_lock_init(object)   lck_mtx_init(&(object)->Lock, &vm_object_lck_grp, &vm_object_lck_attr)
#define named_entry_lock_destroy(object)        lck_mtx_destroy(&(object)->Lock, &vm_object_lck_grp)
#define named_entry_lock(object)                lck_mtx_lock(&(object)->Lock)
#define named_entry_unlock(object)              lck_mtx_unlock(&(object)->Lock)

/*!
 * @abstract
 * Returns the number of shared owners of this shared entry lock.
 * Serves stackshots. Also helps determine if the given entry is read-locked (by returning 0).
 */
extern uint32_t kdp_vm_entry_lock_read_count(
	vm_map_entry_t          entry);
/*
 *	Type:		vm_named_entry_t [internal use only]
 *
 *	Description:
 *		Description of a mapping to a memory cache object.
 *
 *	Implementation:
 *		While the handle to this object is used as a means to map
 *              and pass around the right to map regions backed by pagers
 *		of all sorts, the named_entry itself is only manipulated
 *		by the kernel.  Named entries hold information on the
 *		right to map a region of a cached object.  Namely,
 *		the target cache object, the beginning and ending of the
 *		region to be mapped, and the permissions, (read, write)
 *		with which it can be mapped.
 *
 */

struct vm_named_entry {
	decl_lck_mtx_data(, Lock);              /* Synchronization */
	union {
		vm_map_t        map;            /* map backing submap */
		vm_map_copy_t   copy;           /* a VM map copy */
	} backing;
	vm_object_offset_t      offset;         /* offset into object */
	vm_object_size_t        size;           /* size of region */
	vm_object_offset_t      data_offset;    /* offset to first byte of data */
	unsigned int                            /* Is backing.xxx : */
	/* unsigned  */ access:8,               /* MAP_MEM_* */
	/* vm_prot_t */ protection:4,           /* access permissions */
	/* boolean_t */ is_object:1,            /* ... a VM object (wrapped in a VM map copy) */
	/* boolean_t */ internal:1,             /* ... an internal object */
	/* boolean_t */ is_sub_map:1,           /* ... a submap? */
	/* boolean_t */ is_copy:1,              /* ... a VM map copy */
	/* boolean_t */ is_fully_owned:1;       /* ... all objects are owned */
#if VM_NAMED_ENTRY_DEBUG
	uint32_t                named_entry_bt; /* btref_t */
#endif /* VM_NAMED_ENTRY_DEBUG */
};

/*
 * Bit 3 of the protection and max_protection bitfields in a vm_map_entry
 * does not correspond to bit 3 of a vm_prot_t, so these macros provide a means
 * to convert between the "packed" representation in the vm_map_entry's fields
 * and the equivalent bits defined in vm_prot_t.
 */
#if defined(__x86_64__)
#define VM_VALID_VMPROTECT_FLAGS        (VM_PROT_ALL | VM_PROT_COPY | VM_PROT_UEXEC)
#else
#define VM_VALID_VMPROTECT_FLAGS        (VM_PROT_ALL | VM_PROT_COPY)
#endif

/*
 * FOOTPRINT ACCOUNTING:
 * The "memory footprint" is better described in the pmap layer.
 *
 * At the VM level, these 2 vm_map_entry_t fields are relevant:
 * iokit_mapped:
 *	For an "iokit_mapped" entry, we add the size of the entry to the
 *	footprint when the entry is entered into the map and we subtract that
 *	size when the entry is removed.  No other accounting should take place.
 *	"use_pmap" should be FALSE but is not taken into account.
 * use_pmap: (only when is_sub_map is FALSE)
 *	This indicates if we should ask the pmap layer to account for pages
 *	in this mapping.  If FALSE, we expect that another form of accounting
 *	is being used (e.g. "iokit_mapped" or the explicit accounting of
 *	non-volatile purgable memory).
 *
 * So the logic is mostly:
 * if entry->is_sub_map == TRUE
 *	anything in a submap does not count for the footprint
 * else if entry->iokit_mapped == TRUE
 *	footprint includes the entire virtual size of this entry
 * else if entry->use_pmap == FALSE
 *	tell pmap NOT to account for pages being pmap_enter()'d from this
 *	mapping (i.e. use "alternate accounting")
 * else
 *	pmap will account for pages being pmap_enter()'d from this mapping
 *	as it sees fit (only if anonymous, etc...)
 */

#define VME_ALIAS_BITS          12
#define VME_ALIAS_MASK          ((1u << VME_ALIAS_BITS) - 1)
#define VME_OFFSET_SHIFT        VME_ALIAS_BITS
#define VME_OFFSET_BITS         (64 - VME_ALIAS_BITS)
#define VME_SUBMAP_SHIFT        2
#define VME_SUBMAP_BITS         (sizeof(vm_offset_t) * 8 - VME_SUBMAP_SHIFT)

/*
 * The reason a VM map entry's lock is invalid.
 * Certain types of entries should never be locked, and this can be for various
 * different reasons which are outlined below.
 * To aid with assertions and debugging, the reason is encoded into the bits
 * of the lock.
 */
__options_closed_decl(vmel_invalid_reason_t, uint16_t, {
	VMEL_INVALID_REASON_COPY_ENTRY = 0x1,
	VMEL_INVALID_REASON_SEALED_SUBMAP = 0x2,
	VMEL_INVALID_REASON_ENTRY_DESTROYED = 0x4,
	VMEL_INVALID_REASON_MAP_HEADER = 0x8,
	VMEL_INVALID_REASON_FAKE_ENTRY = 0x10,

	VMEL_INVALID_REASON_LAST_VALID = VMEL_INVALID_REASON_FAKE_ENTRY,
	VMEL_INVALID_REASON_ANY = (VMEL_INVALID_REASON_LAST_VALID << 1) - 1
});

/*!
 * @abstract
 * Bespoke lock used for VM map entries.
 *
 *
 * @field vmel_state8
 * These bits ([7:0]) are manipulated atomically and represent extra state of
 * the lock.
 *
 * @field vmel_needs_coalesce
 * The entry has been marked for needing to coalesce with one of its sibling
 * entries.
 *
 * @field vmel_kunwire_waiters
 * Denotes that a thread has called @c vm_entry_unlock_and_wait_for_kunwire()
 * and is waiting for the wire count of that entry to drop, until someone calls
 * @c vm_entry_wakeup_kunwire_waiters().
 *
 *
 * @field vmel_wait8
 * These bits ([15:8]) denote the state of the waiters and have to be set with
 * atomic read-modify-write operations.
 *
 * @field vmel_excl_waiters
 * There might be an exclusive waiter in the wait queues waiting for this lock.
 * This bit is cleared when waking up exclusive waiters finds no one left in the
 * wait queue.
 *
 * @field vmel_urgent_waiters
 * @c vmel_excl_waiters will be set. It denotes that one of the exclusive
 * waiters at least is at a priority higher than MINPRI_FLOOR (and non
 * realtime). It influences how the exclusive wakeups are performed (when this
 * bit is set, exclusive waiters are woken up with a broadcast in order to
 * reduce exposure to priority inversions a little).
 *
 * @field vmel_shared_waiters
 * There is at least one shared waiter in the wait queues.
 *
 *
 * @field vmel_lock16
 * These bits ([31:16]) denote the lock's proper locking state and must be
 * manipulated with atomic RMW operations.
 *
 * @field vmel_valid
 * When the lock is properly initialized and valid this bit is always 1.
 * This is used to discover memory corruption and support invalidation
 * of the lock.
 *
 * @field vmel_excl_locked
 * Denotes whether the lock is exclusively held.
 * The owner of the lock is unknown.
 *
 * @field vmel_read_count
 * If @c vmel_excl_locked is 0, this is the number of shared owners of the lock,
 * otherwise this value is garbage (it can be non zero under normal operations
 * because shared lockers optimistically increment this counter without knowing
 * precisely if the lock is exclusive held or not).
 *
 * Note that this field must be last to make sure that an overflow doesn't
 * mutate other bits.
 */
typedef union vm_entry_lock {
	/* Valid lock state. These bits are only meaningful if vmel_valid == 1. */
	struct {
		/* State bits */
		struct {
			bool     vmel_needs_coalesce  : 1;
			bool     vmel_kunwire_waiters : 1;
			uint8_t  __vmel_state_padding : 6;
		};

		/* Waiters bits */
		struct {
			uint8_t  __vmel_wait_padding  : 6;
			bool     vmel_excl_waiters    : 1;
			bool     vmel_shared_waiters  : 1;
		};

		/* Lock state bits */
		struct {
			bool     vmel_valid           : 1;
			bool     vmel_excl_locked     : 1;
			uint16_t vmel_read_count      : 14;
		};
	};
	struct {
		uint8_t  vmel_state8;
		uint8_t  vmel_wait8;
		uint16_t vmel_lock16;
	};
	uint32_t vmel_data;

	/* Invalid lock state. These bits are only meaningful if vmel_valid == 0. */
	struct {
		vmel_invalid_reason_t vmel_invalid_reason  : 16;
		/* Should match alignment of vmel_valid */
		bool                  vmel_valid2          : 1;
		uint16_t              vmel_invalid_padding : 15;
	};
} vm_entry_lock_t;

/*
 *	Type:		vm_map_entry_t [internal use only]
 *
 *	Description:
 *		A single mapping within an address map.
 *
 *	Implementation:
 *		Address map entries consist of start and end addresses,
 *		a VM object (or sub map) and offset into that object,
 *		and user-exported inheritance and protection information.
 *		Control information for virtual copy operations is also
 *		stored in the address map entry.
 *
 *	Note:
 *		vm_map_relocate_early_elem() knows about this layout,
 *		and needs to be kept in sync.
 *		(i.e. if any field is added to 'struct vm_map_links' then it also needs to be relocated, etc.).
 */
struct vm_map_links {
	struct vm_map_entry    *next;           /* next entry */
	struct vm_map_entry    *prev;           /* prev entry */
	vm_map_offset_t         start;          /* start address */
	vm_map_offset_t         end;            /* end address */
	vm_entry_lock_t         lock;
	vm_map_store_val_ptr_t  chunk;
};

struct vm_map_entry {
	struct vm_map_links     links;                      /* links to other entries */
#define vme_prev                links.prev
#define vme_next                links.next
#define vme_start               links.start
#define vme_end                 links.end
#define vme_lock                links.lock
#define vme_chunk               links.chunk

	union {
		vm_offset_t     vme_object_value;
		struct {
			vm_offset_t vme_atomic:1;           /* entry cannot be split/coalesced */
			vm_offset_t is_sub_map:1;           /* Is "object" a submap? */
			vm_offset_t vme_submap:VME_SUBMAP_BITS;
		};
		struct {
			uint32_t    vme_ctx_atomic : 1;
			uint32_t    vme_ctx_is_sub_map : 1;
			uint32_t    vme_context : 30;

			/**
			 * If vme_kernel_object==1 && KASAN,
			 * vme_object_or_delta holds the delta.
			 *
			 * If vme_kernel_object==1 && !KASAN,
			 * vme_tag_btref holds a btref when vme_alias is equal to the "vmtaglog"
			 * boot-arg.
			 *
			 * If vme_kernel_object==0,
			 * vme_object_or_delta holds the packed vm object.
			 */
			union {
				vm_page_object_t vme_object_or_delta;
				btref_t vme_tag_btref;
			};
		};
	};

	unsigned long long
	/* vm_tag_t          */ vme_alias:VME_ALIAS_BITS,   /* entry VM tag */
	/* vm_object_offset_t*/ vme_offset:VME_OFFSET_BITS, /* offset into object */

	/* boolean_t         */ is_shared:1,                /* region is shared */
#if HAS_MTE
	/* boolean_t         */ vme_is_tagged:1,            /* region is mapped with tags */
#else /* !HAS_MTE */
	/* boolean_t         */__unused1:1,
#endif /* HAS_MTE */
	/* boolean_t         */__unused2:2,
	/* behavior is not defined for submap type */
	/* vm_behavior_t     */ behavior:2,                 /* user paging behavior hint */
	/* boolean_t         */ needs_copy:1,               /* object need to be copied? */

	/* Only in task maps: */
#if defined(__arm64e__)
	/*
	 * On ARM, the fourth protection bit is unused (UEXEC is x86_64 only).
	 * We reuse it here to keep track of mappings that have hardware support
	 * for read-only/read-write trusted paths.
	 */
	/* vm_prot_t-like    */ protection:3,               /* protection code */
	/* boolean_t         */ used_for_tpro:1,
#else /* __arm64e__ */
	/* vm_prot_t-like    */protection:4,                /* protection code, bit3=UEXEC */
#endif /* __arm64e__ */

	/* vm_prot_t-like    */ max_protection:4,           /* maximum protection, bit3=UEXEC */
	/* vm_inherit_t      */ inheritance:2,              /* inheritance */

	/*
	 * use_pmap is overloaded:
	 * if "is_sub_map":
	 *      use a nested pmap?
	 * else (i.e. if object):
	 *      use pmap accounting
	 *      for footprint?
	 */
	/* boolean_t         */ use_pmap:1,
	/* boolean_t         */ no_cache:1,                 /* should new pages be cached? */
	/* boolean_t         */ vme_permanent:1,            /* mapping can not be removed */
	/* boolean_t         */ superpage_size:1,           /* use superpages of a certain size */
	/*
	 * zero out the wired pages of this entry
	 * if is being deleted without unwiring them
	 */
	/* boolean_t         */ zero_wired_pages:1,
	/* boolean_t         */ used_for_jit:1,
	/* boolean_t         */ csm_associated:1,       /* code signing monitor will validate */

	/* iokit accounting: use the virtual size rather than resident size: */
	/* boolean_t         */ iokit_acct:1,
	/* boolean_t         */ vme_resilient_codesign:1,
	/* boolean_t         */ vme_resilient_media:1,
	/* boolean_t         */ vme_xnu_user_debug:1,
	/* boolean_t         */ vme_no_copy_on_read:1,
	/* boolean_t         */ translated_allow_execute:1, /* execute in translated processes */
	/* boolean_t         */ vme_kernel_object:1,        /* vme_object is a kernel_object */
	/* boolean_t         */ __unused3 :1;

	unsigned short          wired_count;                /* can be paged if = 0 */
	unsigned short          user_wired_count;           /* for vm_wire */

#if DEBUG
#define MAP_ENTRY_CREATION_DEBUG        1
#define MAP_ENTRY_INSERTION_DEBUG       1
#define MAP_ENTRY_LOCK_DEBUG            1
#else
#define MAP_ENTRY_CREATION_DEBUG        0
#define MAP_ENTRY_INSERTION_DEBUG       0
#define MAP_ENTRY_LOCK_DEBUG            0
#endif /* DEBUG */

#if MAP_ENTRY_CREATION_DEBUG
//	struct vm_map_header   *vme_creation_maphdr;
	uint32_t                vme_creation_bt;            /* btref_t */
#endif /* MAP_ENTRY_CREATION_DEBUG */
#if MAP_ENTRY_INSERTION_DEBUG
	uint32_t                vme_insertion_bt;           /* btref_t */
	vm_map_offset_t         vme_start_original;
	vm_map_offset_t         vme_end_original;
#endif /* MAP_ENTRY_INSERTION_DEBUG */
#if MAP_ENTRY_LOCK_DEBUG
	struct thread          *vme_owner;
#endif /* MAP_ENTRY_LOCK_DEBUG */
} __attribute__((aligned(1 << VME_PACKED_PTR_SHIFT)));

/*
 *	Type:		struct vm_map_header
 *
 *	Description:
 *		Header for a vm_map and a vm_map_copy.
 *
 *	Note:
 *		vm_map_relocate_early_elem() knows about this layout,
 *		and needs to be kept in sync.
 */
struct vm_map_header {
	struct vm_map_links     links;              /* first, last, min, max */
	uint32_t                nentries;           /* Number of entries */
	uint16_t                page_shift;         /* page shift */
	uint16_t                is_vm_map_copy : 1; /* is this header for a
	                                             * vm_map_copy_t (or a
	                                             * vm_map_t)?
	                                             */
	uint16_t                __padding : 15;
};

#define VME_ALIAS(entry) \
	((entry)->vme_alias)

static inline vm_map_t
_VME_SUBMAP(
	vm_map_entry_t entry)
{
	__builtin_assume(entry->vme_submap);
	return (vm_map_t)(entry->vme_submap << VME_SUBMAP_SHIFT);
}
#define VME_SUBMAP(entry) ({ assert((entry)->is_sub_map); _VME_SUBMAP(entry); })

static inline void
VME_SUBMAP_SET(
	vm_map_entry_t entry,
	vm_map_t submap)
{
	__builtin_assume(((vm_offset_t)submap & 3) == 0);

	entry->is_sub_map = true;
	entry->vme_submap = (vm_offset_t)submap >> VME_SUBMAP_SHIFT;
}

static inline vm_object_t
_VME_OBJECT(
	vm_map_entry_t entry)
{
	vm_object_t object;

	if (!entry->vme_kernel_object) {
		object = VM_OBJECT_UNPACK(entry->vme_object_or_delta);
		__builtin_assume(!is_kernel_object(object));
	} else {
#if HAS_MTE
		object = entry->vme_is_tagged ? kernel_object_tagged : kernel_object_default;
#else /* !HAS_MTE */
		object = kernel_object_default;
#endif /* HAS_MTE */
	}
	return object;
}
#define VME_OBJECT(entry) ({ assert(!(entry)->is_sub_map); _VME_OBJECT(entry); })


static inline vm_map_size_t
VME_SIZE(
	vm_map_entry_t entry)
{
	return entry->vme_end - entry->vme_start;
}

static inline vm_object_offset_t
VME_OFFSET(
	vm_map_entry_t entry)
{
	return entry->vme_offset << VME_OFFSET_SHIFT;
}

static inline bool
VME_IS_SENTINEL(
	vm_map_entry_t entry)
{
	return !entry->is_sub_map && VME_OBJECT(entry) == sentinel_object;
}

static inline bool
VME_IN_CHUNK(vm_map_entry_t entry)
{
	return vms_is_chunk(entry->vme_chunk);
}


#if (DEBUG || DEVELOPMENT) && !KASAN
#define VM_BTLOG_TAGS 1
#else
#define VM_BTLOG_TAGS 0
#endif


/*
 * Convenience macros for dealing with superpages
 * SUPERPAGE_NBASEPAGES is architecture dependent and defined in pmap.h
 */
#define SUPERPAGE_SIZE (PAGE_SIZE*SUPERPAGE_NBASEPAGES)
#define SUPERPAGE_MASK (-SUPERPAGE_SIZE)
#define SUPERPAGE_ROUND_DOWN(a) (a & SUPERPAGE_MASK)
#define SUPERPAGE_ROUND_UP(a) ((a + SUPERPAGE_SIZE-1) & SUPERPAGE_MASK)

/*
 * wired_counts are unsigned short.  This value is used to safeguard
 * against any mishaps due to runaway user programs.
 */
#define MAX_WIRE_COUNT          65535

typedef struct vm_map_user_range {
	vm_map_address_t        vmur_min_address __kernel_data_semantics;

	vm_map_address_t        vmur_max_address : 56 __kernel_data_semantics;
	vm_map_range_id_t       vmur_range_id : 8;
} *vm_map_user_range_t;

typedef struct {
#define VM_ASYNC_TAG_FAULT_ALREADY_REPORTED  UINT64_MAX
	uint64_t        code;
	vm_map_offset_t address;
} __attribute__((aligned(16))) vm_map_async_fault_t;

/*
 *	Type:		vm_map_t [exported; contents invisible]
 *
 *	Description:
 *		An address map -- a directory relating valid
 *		regions of a task's address space to the corresponding
 *		virtual memory objects.
 *
 *	Implementation:
 *		Maps are doubly-linked lists of map entries, sorted
 *		by address.  One hint is used to start
 *		searches again from the last successful search,
 *		insertion, or removal.  Another hint is used to
 *		quickly find free space.
 *
 *	Note:
 *		vm_map_relocate_early_elem() knows about this layout,
 *		and needs to be kept in sync.
 */
struct _vm_map {
	lck_rw_new_t            ilock;
	uint64_t                unlink_timestamp; /* Counter incremented every time
	                                           * an entry is removed from the map.
	                                           * This allows us to see if a pointer
	                                           * to an entry is still valid after
	                                           * having dropped and retaken the interlock.
	                                           * Note the bounds of the entry may arbitrarily
	                                           * change.
	                                           */
	struct vm_map_header    hdr;            /* Map entry header */
	vm_map_store_root_t     root;
#define min_offset              hdr.links.start /* start of range, inclusive */
#define max_offset              hdr.links.end   /* end of range, exclusive */
	pmap_t                  XNU_PTRAUTH_SIGNED_PTR("_vm_map.pmap") pmap;           /* Physical map */
	vm_map_size_t           size;           /* virtual size */
	uint64_t                size_limit;     /* rlimit on address space size */
	uint64_t                data_limit;     /* rlimit on data size */
	vm_map_size_t           user_wire_limit;/* rlimit on user locked memory */
	vm_map_size_t           user_wire_size; /* current size of user locked memory in this map */
#if __x86_64__
	vm_map_offset_t         vmmap_high_start;
#endif /* __x86_64__ */

	os_ref_atomic_t         map_refcnt;       /* Reference count */

#if CONFIG_MAP_RANGES
#define VM_MAP_EXTRA_RANGES_MAX 1024
	uint16_t                extra_ranges_count;
	vm_map_user_range_t     extra_ranges;

	struct mach_vm_range    default_range;
	struct mach_vm_range    data_range;
	struct mach_vm_range    large_file_range;
#endif /* CONFIG_MAP_RANGES */
	vm_guard_object_slab_t  guard_object_slabs;
	vm_guard_object_chunk_t guard_object_user;

	union {
		/*
		 * If map->disable_vmentry_reuse == TRUE:
		 * the end address of the highest allocated vm_map_entry_t.
		 */
		vm_map_offset_t         highest_entry_end;
		/*
		 * For a nested VM map:
		 * the lowest address in this nested VM map that we would
		 * expect to be unnested under normal operation (i.e. for
		 * regular copy-on-write on DATA section).
		 */
		vm_map_offset_t         lowest_unnestable_start;
	};

	struct vm_map_corpse_footprint_header *vmmap_corpse_footprint;

	unsigned int
	/* boolean_t */ wait_for_space:1,         /* Should callers wait for space? */
	/* boolean_t */ no_zero_fill:1,           /* No zero fill absent pages */
	/* boolean_t */ mapped_in_other_pmaps:1,  /* has this submap been mapped in maps that use a different pmap */
	/* boolean_t */ switch_protect:1,         /* Protect map from write faults while switched */
	/* boolean_t */ disable_vmentry_reuse:1,  /* All vm entries should keep using newer and higher addresses in the map */
	/* boolean_t */ map_disallow_data_exec:1, /* Disallow execution from data pages on exec-permissive architectures */
	/* boolean_t */ is_nested_map:1,
	/* boolean_t */ map_disallow_new_exec:1,  /* Disallow new executable code */
	/* boolean_t */ jit_entry_exists:1,
	/* boolean_t */ has_corpse_footprint:1,
	/* boolean_t */ terminated:1,
	/* boolean_t */ is_alien:1,               /* for platform simulation, i.e. PLATFORM_IOS on OSX */
	/* boolean_t */ cs_enforcement:1,         /* code-signing enforcement */
	/* boolean_t */ cs_debugged:1,            /* code-signed but debugged */
	/* boolean_t */ reserved_regions:1,       /* has reserved regions. The map size that userspace sees should ignore these. */
	/* boolean_t */ single_jit:1,             /* only allow one JIT mapping */
	/* boolean_t */ never_faults:1,           /* this map should never cause faults */
	/* boolean_t */ uses_user_ranges:1,       /* has the map been configured to use user VM ranges */
	/* boolean_t */ tpro_enforcement:1,       /* enforce TPRO propagation */
	/* boolean_t */ corpse_source:1,          /* map is being used to create a corpse for diagnostics.*/
	/* boolean_t */ cs_platform_binary:1,     /* map belongs to a platform binary */

#define VM_MAP_NOT_SEALED 0                       /* map is not sealed and may be freely modified. */
#define VM_MAP_WILL_BE_SEALED 1                   /* map will be sealed and is subject to limited modification. */
#define VM_MAP_SEALED 2                           /* map is sealed and should not be modified. */
	/* unsigned int */ vmmap_sealed:2,        /* sealed state of map, see definitions above. */
#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
	/* boolean_t */ has_sec_access:1,         /* offsets into this map may contain embedded pointer tags, whether or not they're enabled */
#else
	/* reserved */ res0:1,
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */
	/* bool     */lock_contention_debug:1,    /* Enable extra checks for potential lock contention issues */
	/* reserved  */ pad:7;
	/*
	 * Weak reference to the task that owns this map. This will be NULL if the
	 * map has terminated, so you must have a task reference to be able to safely
	 * access this. Under the map lock, you can safely acquire a task reference
	 * if owning_task is not NULL, since vm_map_terminate requires the map lock.
	 */
	task_t owning_task;

	/*
	 * A generation ID for maps that increments monotonically.
	 * This is a pointer type just so we get dPAC out-of-the-box, but
	 * conceptually it's just an ID.
	 * Note that this is not a unique object ID. In particular, fork()
	 * will produce a child map with the same ID as its parent.
	 */
	vm_map_serial_t serial_id;

	/*
	 * This is used to asynchronously deliver tag check faults or guard
	 * object faults to the owner of a user vm_map when we take a tag check
	 * fault in a kernel thread with its map switched.
	 *
	 * This variable starts zero-initialized. On such a tag check fault, we
	 * atomically set the the address to the address where the fault occurred.
	 *
	 * When we vm_map_switch_back, we set AST_MACH_EXCEPTION on all of
	 * owning_task's threads.
	 *
	 * Whichever thread consumes the AST first will atomically set the
	 * fault code to VM_ASYNC_TAG_FAULT_ALREADY_REPORTED (which prevents
	 * vm_map_switch_back from spuriously setting ASTs on the map) and throw
	 * a guard exception, potentially (based on policy) killing owning_task.
	 *
	 * This field is not protected by the map lock. Readers/writers should hold
	 * a map reference and access this value atomically.
	 */
	vm_map_async_fault_t async_fault;
};

#define VME_PREV(entry)                 ((entry)->vme_prev)

#define CAST_TO_VM_MAP_ENTRY(x)         ((struct vm_map_entry *)(uintptr_t)(x))
#define vm_map_to_entry(map)            CAST_TO_VM_MAP_ENTRY(&(map)->hdr.links)
#define vm_map_first_entry(map)         ((map)->hdr.links.next)
#define vm_map_last_entry(map)          ((map)->hdr.links.prev)
#define vm_map_from_hdr(hdr)            __container_of(hdr, struct _vm_map, hdr)

static inline bool
entry_is_map_end(vm_map_t map, vm_map_entry_t entry)
{
	return entry == vm_map_to_entry(map);
}


/*
 *	Type:		vm_map_copy_t [exported; contents invisible]
 *
 *	Description:
 *		A map copy object represents a region of virtual memory
 *		that has been copied from an address map but is still
 *		in transit.
 *
 *		A map copy object may only be used by a single thread
 *		at a time.
 *
 *	Implementation:
 *              There are two formats for map copy objects.
 *		The first is very similar to the main
 *		address map in structure, and as a result, some
 *		of the internal maintenance functions/macros can
 *		be used with either address maps or map copy objects.
 *
 *		The map copy object contains a header links
 *		entry onto which the other entries that represent
 *		the region are chained.
 *
 *		The second format is a kernel buffer copy object - for data
 *              small enough that physical copies were the most efficient
 *		method. This method uses a zero-sized array unioned with
 *		other format-specific data in the 'c_u' member. This unsized
 *		array overlaps the other elements and allows us to use this
 *		extra structure space for physical memory copies. On 64-bit
 *		systems this saves ~64 bytes per vm_map_copy.
 */

struct vm_map_copy {
#define VM_MAP_COPY_ENTRY_LIST          1
#define VM_MAP_COPY_KERNEL_BUFFER       2
	uint16_t                type;
	bool                    is_kernel_range;
	bool                    is_user_range;
	vm_map_range_id_t       orig_range;
	vm_object_offset_t      offset;
	vm_map_size_t           size;
	union {
		struct vm_map_header                  hdr;    /* ENTRY_LIST */
		struct {
			void *XNU_PTRAUTH_SIGNED_PTR("vm_map_copy.kdata") kdata;  /* KERNEL_BUFFER */
			bool uses_large_buffers;
		} buffer_data;
	} c_u;
};


ZONE_DECLARE_ID(ZONE_ID_VM_MAP_ENTRY, struct vm_map_entry);
#define vm_map_entry_zone       (&zone_array[ZONE_ID_VM_MAP_ENTRY])

ZONE_DECLARE_ID(ZONE_ID_VM_MAP_NODES, struct vm_map_store_node);
#define vm_map_nodes_zone       (&zone_array[ZONE_ID_VM_MAP_NODES])

ZONE_DECLARE_ID(ZONE_ID_VM_MAP, struct _vm_map);
#define vm_map_zone             (&zone_array[ZONE_ID_VM_MAP])


#define cpy_hdr                 c_u.hdr
#define cpy_kdata               c_u.buffer_data.kdata
#define cpy_uses_large_buffers  c_u.buffer_data.uses_large_buffers

#define VM_MAP_COPY_PAGE_SHIFT(copy)    ((copy)->cpy_hdr.page_shift)
#define VM_MAP_COPY_PAGE_SIZE(copy)     (1 << VM_MAP_COPY_PAGE_SHIFT((copy)))
#define VM_MAP_COPY_PAGE_MASK(copy)     (VM_MAP_COPY_PAGE_SIZE((copy)) - 1)

/*
 *	Useful macros for entry list copy objects
 */

#define vm_map_copy_to_entry(copy)      CAST_TO_VM_MAP_ENTRY(&(copy)->cpy_hdr.links)
#define vm_map_copy_first_entry(copy)   ((copy)->cpy_hdr.links.next)
#define vm_map_copy_last_entry(copy)    ((copy)->cpy_hdr.links.prev)
#define vm_map_copy_from_hdr(hdr)       __container_of(hdr, struct vm_map_copy, c_u.hdr)

static inline bool
entry_is_copy_end(vm_map_copy_t copy, vm_map_entry_t entry)
{
	return entry == vm_map_copy_to_entry(copy);
}

#include <vm/vm_lock_perf.h>

/*
 *	Exported procedures that operate on vm_map_t.
 */

/* Lookup map entry containing or the specified address in the given map */
extern vm_map_entry_t   vm_map_lookup(
	vm_map_t                map,
	vm_map_address_t        address);

extern bool vm_map_lookup_or_next(
	vm_map_t                map,
	vm_map_address_t        address,
	vm_map_entry_t         *entry);


/*
 *	Functions implemented as macros
 */
#define         vm_map_min(map) ((map)->min_offset)
/* Lowest valid address in
 * a map */

#define         vm_map_max(map) ((map)->max_offset)
/* Highest valid address */

#define         vm_map_pmap(map)        ((map)->pmap)
/* Physical map associated
* with this address map */

/* Gain a reference to an existing map */
extern void             vm_map_reference(
	vm_map_t        map);

extern void             vm_map_inherit_limits(
	vm_map_t                new_map,
	const struct _vm_map   *old_map);

/* Create a new task map using an existing task map as a template. */
extern vm_map_t         vm_map_fork(
	ledger_t                ledger,
	vm_map_t                old_map,
	int                     options);

#if HAS_MTE
/*
 * WARNING: VM_MAP_FORK_SHARE_IF_INHERIT_NONE and VM_MAP_FORK_SHARE_IF_OWNED
 * allow fork() to create shared mappings of MTE-tagged memory, which is
 * generally forbidden.
 *
 * Currently, these flags are used only in the corpse-fork path, which is
 * safe because neither the process nor the corpse continue running, but future
 * callers should be careful.
 */
#endif /* HAS_MTE */
#define VM_MAP_FORK_SHARE_IF_INHERIT_NONE       0x00000001
#define VM_MAP_FORK_PRESERVE_PURGEABLE          0x00000002
#define VM_MAP_FORK_CORPSE_FOOTPRINT            0x00000004
#define VM_MAP_FORK_SHARE_IF_OWNED              0x00000008


extern kern_return_t vm_map_query_volatile_and_iunlock(
	vm_map_t        map,
	mach_vm_size_t  *volatile_virtual_size_p,
	mach_vm_size_t  *volatile_resident_size_p,
	mach_vm_size_t  *volatile_compressed_size_p,
	mach_vm_size_t  *volatile_pmap_size_p,
	mach_vm_size_t  *volatile_compressed_pmap_size_p);


extern kern_return_t vm_map_set_cache_attr(
	vm_map_t        map,
	vm_map_offset_t va);


extern void vm_map_copy_footprint_ledgers(
	task_t  old_task,
	task_t  new_task);


/**
 * Represents a single region of virtual address space that should be reserved
 * (pre-mapped) in a user address space.
 */
struct vm_reserved_region {
	const char             *vmrr_name;
	vm_map_offset_t         vmrr_addr;
	vm_map_size_t           vmrr_size;
};

/**
 * Return back a machine-dependent array of address space regions that should be
 * reserved by the VM. This function is defined in the machine-dependent
 * machine_routines.c files.
 */
extern size_t ml_get_vm_reserved_regions(
	bool                    vm_is64bit,
	const struct vm_reserved_region **regions);

/**
 * Explicitly preallocates a floating point save area. This function is defined
 * in the machine-dependent machine_routines.c files.
 */
extern void ml_fp_save_area_prealloc(void);

static inline bool
vm_map_is_sealed(
	vm_map_t map)
{
	return map->vmmap_sealed == VM_MAP_SEALED;
}

static inline bool
vm_map_will_be_sealed(
	vm_map_t map)
{
	return map->vmmap_sealed == VM_MAP_WILL_BE_SEALED;
}

static inline bool
vm_map_is_sealed_or_will_be_sealed(
	vm_map_t map)
{
	return vm_map_is_sealed(map) || vm_map_will_be_sealed(map);
}

#endif /* MACH_KERNEL_PRIVATE */

/*
 * Read and write from a kernel buffer to a specified map.
 */
extern  kern_return_t   vm_map_write_user(
	vm_map_t                map,
	void                   *src_p,
	vm_map_offset_ut        dst_addr_u,
	vm_size_ut              size_u);

extern  kern_return_t   vm_map_read_user(
	vm_map_t                map,
	vm_map_offset_ut        src_addr_u,
	void                   *dst_p,
	vm_size_ut              size_u);

extern vm_map_size_t    vm_map_adjusted_size(vm_map_t map);

typedef struct {
	vm_map_t map;
	task_t task;
	boolean_t sec_overridden;
} vm_map_switch_context_t;
extern vm_map_switch_context_t vm_map_switch_with_sec_override(vm_map_t, boolean_t sec_override);
static inline vm_map_switch_context_t
vm_map_switch_to(vm_map_t map)
{
	return vm_map_switch_with_sec_override(map, FALSE);
}
extern void vm_map_switch_back(vm_map_switch_context_t ctx);

extern boolean_t vm_map_cs_enforcement(
	vm_map_t                map);
extern void vm_map_cs_enforcement_set(
	vm_map_t                map,
	boolean_t               val);

extern void vm_map_cs_debugged_set(
	vm_map_t map,
	boolean_t val);

extern kern_return_t vm_map_cs_wx_enable(vm_map_t map);
extern kern_return_t vm_map_csm_allow_jit(vm_map_t map);


extern void vm_map_will_allocate_early_map(
	vm_map_t               *map_owner);

extern void vm_map_relocate_early_maps(
	vm_offset_t             delta);

extern void vm_map_relocate_early_elem(
	uint32_t                zone_id,
	vm_offset_t             new_addr,
	vm_offset_t             delta);

/* wire down a region */

/* never fails */
extern vm_map_t vm_map_create_options(
	pmap_t                  pmap,
	vm_map_offset_t         min_off,
	vm_map_offset_t         max_off,
	vm_map_create_options_t options);

extern vm_map_t vm_map_create_with_page_shift(
	pmap_t                  pmap,
	vm_map_offset_t         min_off,
	vm_map_offset_t         max_off,
	int                     pageshift,
	vm_map_create_options_t options);

extern boolean_t        vm_kernel_map_is_kernel(vm_map_t map);

#if CONFIG_LARGE_SIZE_TELEMETRY
/* Cause a simulated crash. */
extern void vm_map_enter_large_telemetry_ast(void);
#endif /* CONFIG_LARGE_SIZE_TELEMETRY */

/*!
 * @function vm_map_enter_mem_object_control()
 *
 * @brief
 * Enters a mapping of @c initial_size bytes at @c *address (subject to
 * fixed/anywhere semantics, see @c VM_FLAGS_FIXED/VM_FLAGS_ANYWHERE ).
 * The pages will come from a memory object paged in by the @c control pager,
 * and the caller may specify an @c offset into the object.
 *
 * @param target_map     The map into which to enter the mapping.
 * @param address        [in]  Pointer to the address at which to enter the
 *                             mapping (or use as a hint for anywhere
 *                             mappings).
 *                             No alignment is required, the function will
 *                             round this down to a page boundary in the
 *                             @c target_map.
 *                       [out] On success, it will be filled with the address
 *                             at which the object data is made available, and
 *                             will have the same misalignment into
 *                             @c target_map as @c offset.
 *                             On failure, it remains unmodified.
 * @param initial_size   Size of the mapping to enter.
 *                       Must be non-zero.
 *                       No alignment is required.
 * @param mask           An alignment mask the mapping must respect.
 * @param vmk_flags      The vm map kernel flags to influence this call.
 * @param control        The pager-managed memory object which is the source
 *                       of the pages.
 * @param offset         The offset into the memory object to use when
 *                       paging.
 *                       @c vm_map_enter, which is called into by
 *                       @c vm_map_enter_mem_object_control, requires that
 *                       @c offset be page-aligned for either @c target_map
 *                       pages or kernel pages.
 * @param needs_copy     Boolean which can be set to request that the mapped
 *                       pages be a copy of the memory object's pages.
 * @param cur_protection Effective protection that should be set for the
 *                       mapping.
 * @param max_protection Max protection that should be allowed for the
 *                       mapping. Should at least cover @c cur_protection.
 * @param inheritance    Inheritance policy for the mapping.
 *
 * @returns @c KERN_SUCCESS if the mapping was successfully entered, an error
 *          code otherwise.
 */
extern kern_return_t    vm_map_enter_mem_object_control(
	vm_map_t                target_map,
	vm_map_offset_ut       *address,
	vm_map_size_ut          initial_size,
	vm_map_offset_ut        mask,
	vm_map_kernel_flags_t   vmk_flags,
	memory_object_control_t control,
	vm_object_offset_ut     offset,
	boolean_t               needs_copy,
	vm_prot_ut              cur_protection,
	vm_prot_ut              max_protection,
	vm_inherit_ut           inheritance);

/* Must be executed on a new task's map before the task is enabled for IPC access */
extern void vm_map_setup(vm_map_t map, task_t task); /* always succeeds */

extern kern_return_t    vm_map_terminate(
	vm_map_t                map);

/* Overwrite existing memory with a copy */
extern kern_return_t    vm_map_copy_overwrite(
	vm_map_t                dst_map,
	vm_map_address_ut       dst_addr_u,
	vm_map_copy_t           copy,
	vm_map_size_ut          copy_size_u,
#if HAS_MTE
	boolean_t               sec_override,
#endif
	boolean_t               interruptible);

/* returns TRUE if size of vm_map_copy == *size, FALSE otherwise */
extern boolean_t        vm_map_copy_validate_size(
	vm_map_t                dst_map,
	vm_map_copy_t           copy,
	vm_map_size_t          *size);

extern kern_return_t    vm_map_copyout_size(
	vm_map_t                dst_map,
	vm_map_address_t       *dst_addr, /* OUT */
	vm_map_copy_t           copy,
	vm_map_size_ut          copy_size);

extern void             vm_map_disable_NX(
	vm_map_t                map);

extern void             vm_map_disallow_data_exec(
	vm_map_t                map);

extern void             vm_map_set_jumbo(
	vm_map_t                map);

#if XNU_PLATFORM_iPhoneOS && EXTENDED_USER_VA_SUPPORT
extern void             vm_map_set_extra_jumbo(
	vm_map_t                map);
#endif /* XNU_PLATFORM_iPhoneOS && EXTENDED_USER_VA_SUPPORT */

extern void             vm_map_set_jit_entitled(
	vm_map_t                map);

extern void             vm_map_set_max_addr(
	vm_map_t                map,
	vm_map_offset_t         new_max_offset,
	bool                    extra_jumbo);

extern boolean_t        vm_map_has_hard_pagezero(
	vm_map_t                map,
	vm_map_offset_t         pagezero_size);

extern void             vm_commit_pagezero_status(vm_map_t      tmap);

extern void             vm_map_set_platform_binary(
	vm_map_t                map,
	bool                    is_platform_binary);
extern bool             vm_map_is_platform_binary(
	vm_map_t                map);

extern boolean_t        vm_map_tpro(
	vm_map_t                map);

extern void             vm_map_set_tpro(
	vm_map_t                map);

#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
extern void             vm_map_set_sec_enabled(
	vm_map_t                map);

extern void             vm_map_set_sec_disabled(
	vm_map_t                map);
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */

#if CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS
extern vm_map_address_t vm_map_strip_addr(
	vm_map_t                map,
	vm_map_address_t        ptr);
#endif /* CONFIG_KERNEL_TAGGING || HAS_MTE_EMULATION_SHIMS */

#if HAS_MTE
extern void                     vm_map_set_restrict_receiving_aliases_to_tagged_memory(
	vm_map_t map, bool must_restrict);
#endif /* HAS_MTE */

extern void             vm_map_set_tpro_enforcement(
	vm_map_t                map);

extern boolean_t        vm_map_set_tpro_range(
	vm_map_t                map,
	vm_map_address_t        start,
	vm_map_address_t        end);

extern boolean_t        vm_map_is_64bit(
	vm_map_t                map);

extern kern_return_t    vm_map_raise_max_offset(
	vm_map_t        map,
	vm_map_offset_t new_max_offset);

extern kern_return_t    vm_map_raise_min_offset(
	vm_map_t        map,
	vm_map_offset_t new_min_offset);

#if XNU_TARGET_OS_OSX
extern void vm_map_set_high_start(
	vm_map_t        map,
	vm_map_offset_t high_start);
#endif /* XNU_TARGET_OS_OSX */


extern vm_map_offset_t  vm_compute_max_offset(
	boolean_t               is64);

extern void             vm_map_get_max_aslr_slide_section(
	vm_map_t                map,
	int64_t                 *max_sections,
	int64_t                 *section_size);

extern uint64_t         vm_map_get_max_aslr_slide_pages(
	vm_map_t map);

extern uint64_t         vm_map_get_max_loader_aslr_slide_pages(
	vm_map_t map);

extern kern_return_t    vm_map_set_size_limit(
	vm_map_t                map,
	uint64_t                limit);

extern kern_return_t    vm_map_set_data_limit(
	vm_map_t                map,
	uint64_t                limit);

extern void             vm_map_set_user_wire_limit(
	vm_map_t                map,
	vm_size_t               limit);

extern void vm_map_switch_protect(
	vm_map_t                map,
	bool                    val);

extern boolean_t        vm_map_page_aligned(
	vm_map_offset_t         offset,
	vm_map_offset_t         mask);

extern bool vm_map_range_overflows(
	vm_map_t                map,
	vm_map_offset_t         addr,
	vm_map_size_t           size);

/* Support for vm_map ranges */
extern kern_return_t    vm_map_range_configure(
	vm_map_t                map,
	bool                    needs_extra_jumbo_va);

/*!
 * @function vm_map_kernel_flags_update_range_id()
 *
 * @brief
 * Updates the @c vmkf_range_id field with the adequate value
 * according to the policy for specified map and tag set in @c vmk_flags.
 *
 * @discussion
 * This function is meant to be called by Mach VM entry points,
 * which matters for the kernel: allocations with pointers _MUST_
 * be allocated with @c kmem_*() functions.
 *
 * If the range ID is already set, it is preserved.
 */
extern void             vm_map_kernel_flags_update_range_id(
	vm_map_kernel_flags_t  *flags,
	vm_map_t                map,
	vm_map_size_t           size);

#if XNU_TARGET_OS_OSX
extern void vm_map_mark_alien(vm_map_t map);
extern void vm_map_single_jit(vm_map_t map);
#endif /* XNU_TARGET_OS_OSX */

extern kern_return_t vm_map_page_info(
	vm_map_t                map,
	vm_map_offset_ut        offset,
	vm_page_info_flavor_t   flavor,
	vm_page_info_t          info,
	mach_msg_type_number_t  *count);

extern kern_return_t vm_map_page_range_info_internal(
	vm_map_t                map,
	vm_map_offset_ut        start_offset,
	vm_map_offset_ut        end_offset,
	int                     effective_page_shift,
	vm_page_info_flavor_t   flavor,
	vm_page_info_t          info,
	mach_msg_type_number_t  *count);

#ifdef MACH_KERNEL_PRIVATE

/*
 * Internal macros for rounding and truncation of vm_map offsets and sizes
 */
#define VM_MAP_ROUND_PAGE(x, pgmask) (((vm_map_offset_t)(x) + (pgmask)) & ~((signed)(pgmask)))
#define VM_MAP_TRUNC_PAGE(x, pgmask) ((vm_map_offset_t)(x) & ~((signed)(pgmask)))

/*
 * Macros for rounding and truncation of vm_map offsets and sizes
 */
static inline int
VM_MAP_PAGE_SHIFT(
	vm_map_t map)
{
	int shift = map ? map->hdr.page_shift : PAGE_SHIFT;
	/*
	 * help ubsan and codegen in general,
	 * cannot use PAGE_{MIN,MAX}_SHIFT
	 * because of testing code which
	 * tests 16k aligned maps on 4k only systems.
	 */
	__builtin_assume(shift >= 12 && shift <= 14);
	return shift;
}

#define VM_MAP_PAGE_SIZE(map) (1 << VM_MAP_PAGE_SHIFT((map)))
#define VM_MAP_PAGE_MASK(map) (VM_MAP_PAGE_SIZE((map)) - 1)
#define VM_MAP_PAGE_ALIGNED(x, pgmask) (((x) & (pgmask)) == 0)

#endif /* MACH_KERNEL_PRIVATE */


extern bool vm_map_is_exotic(vm_map_t map);
extern bool vm_map_is_alien(vm_map_t map);
extern pmap_t vm_map_get_pmap(vm_map_t map);
#if CONFIG_MAP_RANGES
extern bool vm_map_in_user_range_voids(
	vm_map_t                map,
	vm_address_t            addr,
	vm_size_t               size);
#endif /* CONFIG_MAP_RANGES */

extern bool vm_map_is_corpse_source(vm_map_t map);
extern void vm_map_set_corpse_source(vm_map_t map);
extern void vm_map_unset_corpse_source(vm_map_t map);
#if HAS_MTE || HAS_MTE_EMULATION_SHIMS
extern bool vm_map_has_sec_access(vm_map_t map);
extern void vm_map_mark_has_sec_access_ilocked(vm_map_t map);
#if CONFIG_XNUPOST
extern void vm_map_mark_has_sec_access(vm_map_t map);
extern void vm_map_remove_sec_access(vm_map_t map);
#endif /* CONFIG_XNUPOST */
#endif /* HAS_MTE || HAS_MTE_EMULATION_SHIMS */


#if CONFIG_DYNAMIC_CODE_SIGNING

extern kern_return_t vm_map_sign(vm_map_t map,
    vm_map_offset_t start,
    vm_map_offset_t end);

#endif /* CONFIG_DYNAMIC_CODE_SIGNING */
#if CONFIG_FREEZE

__options_closed_decl(freeze_options_t, int, {
	FREEZE_NONE      = 0x00,
	FREEZE_EVAL_ONLY = 0x01, /* Only evaluate */
	FREEZE_SHARED    = 0x02, /* Freeze shared memory */
});

extern kern_return_t vm_map_freeze(
	task_t            task,
	unsigned int     *purgeable_count,
	unsigned int     *wired_count,
	unsigned int     *clean_count,
	unsigned int     *dirty_count,
	unsigned int      dirty_budget,
	unsigned int     *shared_count,
	int              *freezer_error_code,
	freeze_options_t  opts);

__enum_decl(freezer_error_code_t, int, {
	FREEZER_ERROR_GENERIC = -1,
	FREEZER_ERROR_EXCESS_SHARED_MEMORY = -2,
	FREEZER_ERROR_LOW_PRIVATE_SHARED_RATIO = -3,
	FREEZER_ERROR_NO_COMPRESSOR_SPACE = -4,
	FREEZER_ERROR_NO_SWAP_SPACE = -5,
	FREEZER_ERROR_NO_SLOTS = -6,
});

#endif /* CONFIG_FREEZE */

/*
 * In some cases, we don't have a real VM object but still want to return a
 * unique ID (to avoid a memory region looking like shared memory), so build
 * a fake pointer based on the map's ledger and the index of the ledger being
 * reported.
 */
#define VM_OBJECT_ID_FAKE(map, ledger_id) ((uint32_t)(uintptr_t)VM_KERNEL_ADDRHASH((int*)((map)->pmap->ledger)+(ledger_id)))

#if DEVELOPMENT || DEBUG

extern kern_return_t get_vm_entry_read_count(
	vm_map_t                map,
	vm_map_offset_t         address,
	uint16_t               *read_count);

extern int vm_map_disconnect_page_mappings(
	vm_map_t map,
	boolean_t);

extern kern_return_t vm_map_inject_error(vm_map_t map, vm_map_offset_t vaddr);

extern kern_return_t vm_map_entries_foreach(vm_map_t map, kern_return_t (^entry_handler)(void* entry));
extern kern_return_t vm_map_dump_entry_and_compressor_pager(void* entry, char *buf, size_t *count);

extern void vm_map_testing_make_sealed_submap(
	vm_map_t            parent_map,
	mach_vm_address_t   start,
	mach_vm_address_t   end);

extern void vm_map_testing_remap_submap(
	vm_map_t            parent_map,
	mach_vm_address_t   submap_base_address,
	mach_vm_address_t   start,
	mach_vm_address_t   end,
	mach_vm_address_t   offset);

__options_decl(dbg_vm_entry_lock_flags, uint32_t, {
	DBG_LCK_FLAG_EXCLUSIVE = 0x1,
	DBG_LCK_FLAG_SHARED = 0x2,
	DBG_LCK_FLAG_CALL_TYPE_MASK = 0x3,
	DBG_LCK_FLAG_ATOMIC = 0x4,
	DBG_LCK_FLAG_STREAM = 0x8
});

extern kern_return_t vm_map_dbg_lock_vm_entry_and_block(vm_map_t map, vm_address_t addr, uint64_t size, uint32_t flags);


#endif /* DEVELOPMENT || DEBUG */

boolean_t        kdp_vm_map_is_acquired_exclusive(vm_map_t map);

boolean_t        vm_map_entry_has_device_pager(vm_map_t, vm_map_offset_t vaddr);


#ifdef VM_SCAN_FOR_SHADOW_CHAIN
int vm_map_shadow_max(vm_map_t map);
#endif

bool vm_map_is_map_size_valid(vm_map_t target_map, vm_size_t size, bool no_soft_limit);

/* Returns the map's ID or VM_MAP_SERIAL_NONE if the input map is NULL */
vm_map_serial_t vm_map_maybe_serial_id(vm_map_t maybe_vm_map);

__END_DECLS

#endif /* XNU_KERNEL_PRIVATE */
#endif  /* _VM_VM_MAP_XNU_H_ */
