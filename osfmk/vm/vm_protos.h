/*
 * Copyright (c) 2004-2020 Apple Inc. All rights reserved.
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

#ifdef  XNU_KERNEL_PRIVATE

#ifndef _VM_VM_PROTOS_H_
#define _VM_VM_PROTOS_H_

#include <mach/mach_types.h>
#include <kern/kern_types.h>
#include <vm/vm_options.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This file contains various type definitions and routine prototypes
 * that are needed to avoid compilation warnings for VM code (in osfmk,
 * default_pager and bsd).
 * Most of these should eventually go into more appropriate header files.
 *
 * Include it after all other header files since it doesn't include any
 * type definitions and it works around some conflicts with other header
 * files.
 */


/*
 * osfmk
 */
#ifndef _IPC_IPC_PORT_H_
extern mach_port_name_t ipc_port_copyout_send(
	ipc_port_t      sright,
	ipc_space_t     space);
extern mach_port_name_t ipc_port_copyout_send_pinned(
	ipc_port_t      sright,
	ipc_space_t     space);
extern kern_return_t mach_port_deallocate_kernel(
	ipc_space_t             space,
	mach_port_name_t        name,
	natural_t               kotype);
#endif /* _IPC_IPC_PORT_H_ */

#ifndef _KERN_IPC_TT_H_

#define port_name_to_task(name) port_name_to_task_kernel(name)

extern task_t port_name_to_task_kernel(
	mach_port_name_t name);
extern task_t port_name_to_task_read(
	mach_port_name_t name);
extern task_t port_name_to_task_name(
	mach_port_name_t name);
extern void ipc_port_release_send(
	ipc_port_t      port);
#endif /* _KERN_IPC_TT_H_ */

extern ipc_space_t  get_task_ipcspace(
	task_t t);

#if CONFIG_MEMORYSTATUS
extern int max_task_footprint_mb;       /* Per-task limit on physical memory consumption in megabytes */
#endif /* CONFIG_MEMORYSTATUS */

/* Some loose-ends VM stuff */

extern const vm_size_t msg_ool_size_small;

extern kern_return_t vm_tests(void);
extern void consider_machine_adjust(void);
extern vm_map_offset_t get_map_min(vm_map_t);
extern vm_map_offset_t get_map_max(vm_map_t);
extern vm_map_size_t get_vmmap_size(vm_map_t);
extern int get_task_page_size(task_t);
#if CONFIG_COREDUMP
extern int get_vmmap_entries(vm_map_t);
#endif
extern int get_map_nentries(vm_map_t);

extern vm_map_offset_t vm_map_page_mask(vm_map_t);

#if MACH_ASSERT
extern void vm_map_pmap_set_process(
	vm_map_t        map,
	int             pid,
	char            *procname);
extern void vm_map_pmap_check_ledgers(
	pmap_t          pmap,
	ledger_t        ledger,
	int             pid,
	char            *procname);
#endif /* MACH_ASSERT */

#if CONFIG_COREDUMP
extern boolean_t coredumpok(vm_map_t map, mach_vm_offset_t va);
#endif

#if XNU_PLATFORM_MacOSX
/*
 * VM routines that used to be published to
 * user space, and are now restricted to the kernel.
 *
 * They should eventually go away entirely -
 * to be replaced with standard vm_map() and
 * vm_deallocate() calls.
 */
extern kern_return_t vm_region_object_create
(
	vm_map_t target_task,
	vm_size_t size,
	ipc_port_t *object_handle
);
#endif /* XNU_PLATFORM_MacOSX */

#if CONFIG_CODE_DECRYPTION
#define VM_MAP_DEBUG_APPLE_PROTECT      MACH_ASSERT
#if VM_MAP_DEBUG_APPLE_PROTECT
extern int vm_map_debug_apple_protect;
#endif /* VM_MAP_DEBUG_APPLE_PROTECT */
struct pager_crypt_info;
extern kern_return_t vm_map_apple_protected(
	vm_map_t                map,
	vm_map_offset_t         start,
	vm_map_offset_t         end,
	vm_object_offset_t      crypto_backing_offset,
	struct pager_crypt_info *crypt_info,
	uint32_t                cryptid);
#endif  /* CONFIG_CODE_DECRYPTION */

struct vm_shared_region_slide_info;

#if __has_feature(ptrauth_calls)
extern void shared_region_key_alloc(
	char *shared_region_id,
	bool inherit,
	uint64_t inherited_key);
extern void shared_region_key_dealloc(
	char *shared_region_id);
extern uint64_t generate_jop_key(void);
#endif /* __has_feature(ptrauth_calls) */
extern bool vm_shared_region_is_reslide(struct task *task);

struct vnode;
extern memory_object_t swapfile_pager_setup(struct vnode *vp);
extern memory_object_control_t swapfile_pager_control(memory_object_t mem_obj);

#if __arm64__ || (__ARM_ARCH_7K__ >= 2)
#define SIXTEENK_PAGE_SIZE      0x4000
#define SIXTEENK_PAGE_MASK      0x3FFF
#define SIXTEENK_PAGE_SHIFT     14
#endif /* __arm64__ || (__ARM_ARCH_7K__ >= 2) */

#define FOURK_PAGE_SIZE         0x1000
#define FOURK_PAGE_MASK         0xFFF
#define FOURK_PAGE_SHIFT        12

#if __arm64__
extern unsigned int page_shift_user32;
#endif /* __arm64__ */

/*
 * bsd
 */
struct vnode;

extern void vnode_setswapmount(struct vnode *);
extern int64_t vnode_getswappin_avail(struct vnode *);

#if CHECK_CS_VALIDATION_BITMAP
/* used by the vnode_pager_cs_validation_bitmap routine*/
#define CS_BITMAP_SET   1
#define CS_BITMAP_CLEAR 2
#define CS_BITMAP_CHECK 3

#endif /* CHECK_CS_VALIDATION_BITMAP */

extern kern_return_t vnode_pager_init(
	memory_object_t,
	memory_object_control_t,
	memory_object_cluster_size_t);

#if CONFIG_IOSCHED
extern kern_return_t vnode_pager_get_object_devvp(
	memory_object_t,
	uintptr_t *);
#endif

/*
 * Functions defined in ubc_subr.c used by the vm code
 */
extern  kern_return_t ubc_cs_check_validation_bitmap(
	struct vnode *vp,
	memory_object_offset_t offset,
	int optype);
extern int  ubc_map(
	struct vnode *vp,
	int flags);
extern void ubc_unmap(
	struct vnode *vp);


extern void   device_pager_reference(memory_object_t);
extern void   device_pager_deallocate(memory_object_t);
extern kern_return_t   device_pager_init(memory_object_t,
    memory_object_control_t,
    memory_object_cluster_size_t);
extern  kern_return_t device_pager_terminate(memory_object_t);
extern  kern_return_t   device_pager_data_request(memory_object_t,
    memory_object_offset_t,
    memory_object_cluster_size_t,
    vm_prot_t,
    memory_object_fault_info_t);
extern kern_return_t device_pager_data_return(memory_object_t,
    memory_object_offset_t,
    memory_object_cluster_size_t,
    memory_object_offset_t *,
    int *,
    boolean_t,
    boolean_t,
    int);
extern kern_return_t device_pager_data_initialize(memory_object_t,
    memory_object_offset_t,
    memory_object_cluster_size_t);
extern kern_return_t device_pager_map(memory_object_t, vm_prot_t);
extern kern_return_t device_pager_last_unmap(memory_object_t);

extern kern_return_t pager_map_to_phys_contiguous(
	memory_object_control_t object,
	memory_object_offset_t  offset,
	addr64_t                base_vaddr,
	vm_size_t               size);

struct macx_triggers_args;

extern int macx_swapinfo(
	memory_object_size_t    *total_p,
	memory_object_size_t    *avail_p,
	vm_size_t               *pagesize_p,
	boolean_t               *encrypted_p);


struct proc;
struct proc *current_proc(void);
extern int cs_allow_invalid(struct proc *p);
extern int cs_invalid_page(addr64_t vaddr, boolean_t *cs_killed);

#define CS_VALIDATE_TAINTED     0x00000001
#define CS_VALIDATE_NX          0x00000002
extern boolean_t cs_validate_range(struct vnode *vp,
    memory_object_t pager,
    memory_object_offset_t offset,
    const void *data,
    vm_size_t size,
    unsigned *result);
extern void cs_validate_page(
	struct vnode *vp,
	memory_object_t pager,
	memory_object_offset_t offset,
	const void *data,
	int *validated_p,
	int *tainted_p,
	int *nx_p);


extern kern_return_t mach_memory_entry_purgable_control(
	ipc_port_t      entry_port,
	vm_purgable_t   control,
	int             *state);

extern unsigned int vmtc_total;        /* total # of text page corruptions detected */

extern kern_return_t revalidate_text_page(task_t, vm_map_offset_t);

#define VM_TOGGLE_CLEAR         0
#define VM_TOGGLE_SET           1
#define VM_TOGGLE_GETVALUE      999
int vm_toggle_entry_reuse(int, int*);

#define SWAP_WRITE              0x00000000      /* Write buffer (pseudo flag). */
#define SWAP_READ               0x00000001      /* Read buffer. */
#define SWAP_ASYNC              0x00000002      /* Start I/O, do not wait. */

void             do_fastwake_warmup_all(void);

#if CONFIG_JETSAM
extern int proc_get_memstat_priority(struct proc*, boolean_t);
#endif /* CONFIG_JETSAM */

/* the object purger. purges the next eligible object from memory. */
/* returns TRUE if an object was purged, otherwise FALSE. */
boolean_t vm_purgeable_object_purge_one_unlocked(int force_purge_below_group);
void vm_owned_objects_disown(task_t task);
void vm_object_wired_page_update_ledgers(
	vm_object_t object,
	int64_t wired_delta);

struct trim_list {
	uint64_t        tl_offset;
	uint64_t        tl_length;
	struct trim_list *tl_next;
};

#define MAX_SWAPFILENAME_LEN    1024
#define SWAPFILENAME_INDEX_LEN  2       /* Doesn't include the terminating NULL character */

extern char     swapfilename[MAX_SWAPFILENAME_LEN + 1];

struct vm_counters {
	unsigned int    do_collapse_compressor;
	unsigned int    do_collapse_compressor_pages;
	unsigned int    do_collapse_terminate;
	unsigned int    do_collapse_terminate_failure;
	unsigned int    should_cow_but_wired;
	unsigned int    create_upl_extra_cow;
	unsigned int    create_upl_extra_cow_pages;
	unsigned int    create_upl_lookup_failure_write;
	unsigned int    create_upl_lookup_failure_copy;
};
extern struct vm_counters vm_counters;

#if CONFIG_SECLUDED_MEMORY
struct vm_page_secluded_data {
	int     eligible_for_secluded;
	int     grab_success_free;
	int     grab_success_other;
	int     grab_failure_locked;
	int     grab_failure_state;
	int     grab_failure_realtime;
	int     grab_failure_dirty;
	int     grab_for_iokit;
	int     grab_for_iokit_success;
};
extern struct vm_page_secluded_data vm_page_secluded;

extern int num_tasks_can_use_secluded_mem;

/* boot-args */

__enum_decl(secluded_filecache_mode_t, uint8_t, {
	/*
	 * SECLUDED_FILECACHE_NONE:
	 * + no file contents in secluded pool
	 */
	SECLUDED_FILECACHE_NONE = 0,
	/*
	 * SECLUDED_FILECACHE_APPS
	 * + no files from /
	 * + files from /Applications/ are OK
	 * + files from /Applications/Camera are not OK
	 * + no files that are open for write
	 */
	SECLUDED_FILECACHE_APPS = 1,
	/*
	 * SECLUDED_FILECACHE_RDONLY
	 * + all read-only files OK, except:
	 *      + dyld_shared_cache_arm64*
	 *      + Camera
	 *      + mediaserverd
	 *      + cameracaptured
	 */
	SECLUDED_FILECACHE_RDONLY = 2,
});

extern secluded_filecache_mode_t secluded_for_filecache;
extern bool secluded_for_apps;
extern bool secluded_for_iokit;

extern uint64_t vm_page_secluded_drain(void);
extern void             memory_object_mark_eligible_for_secluded(
	memory_object_control_t         control,
	boolean_t                       eligible_for_secluded);

#endif /* CONFIG_SECLUDED_MEMORY */

extern void             memory_object_mark_for_realtime(
	memory_object_control_t         control,
	bool                            for_realtime);

#define MAX_PAGE_RANGE_QUERY    (1ULL * 1024 * 1024 * 1024) /* 1 GB */

extern uint64_t vm_purge_filebacked_pagers(void);

#define roundup(x, y)   ((((x) % (y)) == 0) ? \
	                (x) : ((x) + ((y) - ((x) % (y)))))

#define rounddown(x, y) (((x)/(y))*(y))

#ifdef __cplusplus
}
#endif

/*
 * Flags for the VM swapper/reclaimer.
 * Used by vm_swap_consider_defragment()
 * to force defrag/reclaim by the swap
 * GC thread.
 */
#define VM_SWAP_FLAGS_NONE             0
#define VM_SWAP_FLAGS_FORCE_DEFRAG     1
#define VM_SWAP_FLAGS_FORCE_RECLAIM    2

#if __arm64__
/*
 * Flags to control the behavior of
 * the legacy footprint entitlement.
 */
#define LEGACY_FOOTPRINT_ENTITLEMENT_IGNORE             (1)
#define LEGACY_FOOTPRINT_ENTITLEMENT_IOS11_ACCT         (2)
#define LEGACY_FOOTPRINT_ENTITLEMENT_LIMIT_INCREASE     (3)

#endif /* __arm64__ */

#if DEVELOPMENT || DEBUG
struct proc;
extern struct proc *current_proc(void);
extern int proc_pid(struct proc *);
extern const char *proc_best_name(struct proc *);
struct thread;
extern uint64_t thread_tid(struct thread *);
extern int debug4k_filter;
extern int debug4k_proc_filter;
extern char debug4k_proc_name[];
extern const char *debug4k_category_name[];

#define __DEBUG4K(category, fmt, ...)                                   \
	MACRO_BEGIN                                                     \
	int __category = (category);                                    \
	struct thread *__t = NULL;                                      \
	struct proc *__p = NULL;                                        \
	const char *__pname = "?";                                      \
	boolean_t __do_log = FALSE;                                     \
                                                                        \
	if ((1 << __category) & debug4k_filter) {                       \
	        __do_log = TRUE;                                        \
	} else if (((1 << __category) & debug4k_proc_filter) &&         \
	           debug4k_proc_name[0] != '\0') {                      \
	        __p = current_proc();                                   \
	        if (__p != NULL) {                                      \
	                __pname = proc_best_name(__p);                  \
	        }                                                       \
	        if (!strcmp(debug4k_proc_name, __pname)) {              \
	                __do_log = TRUE;                                \
	        }                                                       \
	}                                                               \
	if (__do_log) {                                                 \
	        if (__p == NULL) {                                      \
	                __p = current_proc();                           \
	                if (__p != NULL) {                              \
	                        __pname = proc_best_name(__p);          \
	                }                                               \
	        }                                                       \
	        __t = current_thread();                                 \
	        printf("DEBUG4K(%s) %d[%s] %p(0x%llx) %s:%d: " fmt,     \
	               debug4k_category_name[__category],               \
	               __p ? proc_pid(__p) : 0,                         \
	               __pname,                                         \
	               __t,                                             \
	               thread_tid(__t),                                 \
	               __FUNCTION__,                                    \
	               __LINE__,                                        \
	               ##__VA_ARGS__);                                  \
	}                                                               \
	MACRO_END

#define __DEBUG4K_ERROR         0
#define __DEBUG4K_LIFE          1
#define __DEBUG4K_LOAD          2
#define __DEBUG4K_FAULT         3
#define __DEBUG4K_COPY          4
#define __DEBUG4K_SHARE         5
#define __DEBUG4K_ADJUST        6
#define __DEBUG4K_PMAP          7
#define __DEBUG4K_MEMENTRY      8
#define __DEBUG4K_IOKIT         9
#define __DEBUG4K_UPL           10
#define __DEBUG4K_EXC           11
#define __DEBUG4K_VFS           12

#define DEBUG4K_ERROR(...)      __DEBUG4K(__DEBUG4K_ERROR, ##__VA_ARGS__)
#define DEBUG4K_LIFE(...)       __DEBUG4K(__DEBUG4K_LIFE, ##__VA_ARGS__)
#define DEBUG4K_LOAD(...)       __DEBUG4K(__DEBUG4K_LOAD, ##__VA_ARGS__)
#define DEBUG4K_FAULT(...)      __DEBUG4K(__DEBUG4K_FAULT, ##__VA_ARGS__)
#define DEBUG4K_COPY(...)       __DEBUG4K(__DEBUG4K_COPY, ##__VA_ARGS__)
#define DEBUG4K_SHARE(...)      __DEBUG4K(__DEBUG4K_SHARE, ##__VA_ARGS__)
#define DEBUG4K_ADJUST(...)     __DEBUG4K(__DEBUG4K_ADJUST, ##__VA_ARGS__)
#define DEBUG4K_PMAP(...)       __DEBUG4K(__DEBUG4K_PMAP, ##__VA_ARGS__)
#define DEBUG4K_MEMENTRY(...)   __DEBUG4K(__DEBUG4K_MEMENTRY, ##__VA_ARGS__)
#define DEBUG4K_IOKIT(...)      __DEBUG4K(__DEBUG4K_IOKIT, ##__VA_ARGS__)
#define DEBUG4K_UPL(...)        __DEBUG4K(__DEBUG4K_UPL, ##__VA_ARGS__)
#define DEBUG4K_EXC(...)        __DEBUG4K(__DEBUG4K_EXC, ##__VA_ARGS__)
#define DEBUG4K_VFS(...)        __DEBUG4K(__DEBUG4K_VFS, ##__VA_ARGS__)

#else /* DEVELOPMENT || DEBUG */

#define DEBUG4K_ERROR(...)
#define DEBUG4K_LIFE(...)
#define DEBUG4K_LOAD(...)
#define DEBUG4K_FAULT(...)
#define DEBUG4K_COPY(...)
#define DEBUG4K_SHARE(...)
#define DEBUG4K_ADJUST(...)
#define DEBUG4K_PMAP(...)
#define DEBUG4K_MEMENTRY(...)
#define DEBUG4K_IOKIT(...)
#define DEBUG4K_UPL(...)
#define DEBUG4K_EXC(...)
#define DEBUG4K_VFS(...)

#endif /* DEVELOPMENT || DEBUG */


__enum_decl(vm_object_destroy_reason_t, uint8_t, {
	VM_OBJECT_DESTROY_UNKNOWN_REASON = 0,
	VM_OBJECT_DESTROY_RECLAIM = 1,
	VM_OBJECT_DESTROY_UNMOUNT = 2,
	VM_OBJECT_DESTROY_FORCED_UNMOUNT = 3,
	VM_OBJECT_DESTROY_UNGRAFT = 4,
	VM_OBJECT_DESTROY_PAGER = 5,
	VM_OBJECT_DESTROY_MAX = 5,
});
_Static_assert(VM_OBJECT_DESTROY_MAX < 8, "Need to fit in `no_pager_reason`'s number of bits");

/* From vm_resident.c */
void vm_update_darkwake_mode(boolean_t);

#if FBDP_DEBUG_OBJECT_NO_PAGER
extern kern_return_t memory_object_mark_as_tracked(
	memory_object_control_t         control,
	bool                            new_value,
	bool                            *old_value);
#endif /* FBDP_DEBUG_OBJECT_NO_PAGER */

#endif  /* _VM_VM_PROTOS_H_ */

#endif  /* XNU_KERNEL_PRIVATE */
