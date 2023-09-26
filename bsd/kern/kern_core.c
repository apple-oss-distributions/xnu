/*
 * Copyright (c) 2000-2021 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1991 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	bsd/kern/kern_core.c
 *
 *	This file contains machine independent code for performing core dumps.
 *
 */
#if CONFIG_COREDUMP

#include <mach/vm_param.h>
#include <mach/thread_status.h>
#include <sys/content_protection.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/file_internal.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>

#include <mach-o/loader.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#include <IOKit/IOBSD.h>

#include <vm/vm_kern.h>
#include <vm/vm_protos.h> /* last */
#include <vm/vm_map.h>          /* current_map() */
#include <vm/pmap.h>            /* pmap_user_va_bits() */
#include <mach/mach_vm.h>       /* mach_vm_region_recurse() */
#include <mach/task.h>          /* task_suspend() */
#include <kern/task.h>          /* get_task_numacts() */

#include <security/audit/audit.h>

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif /* CONFIG_MACF */

#include <kdp/core_notes.h>

#define COREDUMP_CUSTOM_LOCATION_ENTITLEMENT "com.apple.private.custom-coredump-location"

typedef struct {
	int     flavor;                 /* the number for this flavor */
	mach_msg_type_number_t  count;  /* count of ints in this flavor */
} mythread_state_flavor_t;

#if defined (__i386__) || defined (__x86_64__)
mythread_state_flavor_t thread_flavor_array[] = {
	{x86_THREAD_STATE, x86_THREAD_STATE_COUNT},
	{x86_FLOAT_STATE, x86_FLOAT_STATE_COUNT},
	{x86_EXCEPTION_STATE, x86_EXCEPTION_STATE_COUNT},
};
int mynum_flavors = 3;
#elif defined (__arm64__)
mythread_state_flavor_t thread_flavor_array[] = {
	{ARM_THREAD_STATE64, ARM_THREAD_STATE64_COUNT},
	/* ARM64_TODO: VFP */
	{ARM_EXCEPTION_STATE64, ARM_EXCEPTION_STATE64_COUNT}
};
int mynum_flavors = 2;
#else
#error architecture not supported
#endif


typedef struct {
	vm_offset_t header;
	size_t hoffset;
	mythread_state_flavor_t *flavors;
	size_t tstate_size;
	size_t flavor_count;
} tir_t;

extern int freespace_mb(vnode_t vp);
extern void task_lock(task_t);
extern void task_unlock(task_t);

/* XXX not in a Mach header anywhere */
kern_return_t thread_getstatus(thread_t act, int flavor,
    thread_state_t tstate, mach_msg_type_number_t *count);
void task_act_iterate_wth_args_locked(task_t, void (*)(thread_t, void *), void *);

#ifdef SECURE_KERNEL
__XNU_PRIVATE_EXTERN int do_coredump = 0;       /* default: don't dump cores */
#else
__XNU_PRIVATE_EXTERN int do_coredump = 1;       /* default: dump cores */
#endif /* SECURE_KERNEL */
__XNU_PRIVATE_EXTERN int sugid_coredump = 0; /* default: but not SGUID binaries */


/* cpu_type returns only the most generic indication of the current CPU. */
/* in a core we want to know the kind of process. */

cpu_type_t
process_cpu_type(proc_t core_proc)
{
	cpu_type_t what_we_think;
#if defined (__i386__) || defined (__x86_64__)
	if (IS_64BIT_PROCESS(core_proc)) {
		what_we_think = CPU_TYPE_X86_64;
	} else {
		what_we_think = CPU_TYPE_I386;
	}
#elif defined(__arm64__)
	if (IS_64BIT_PROCESS(core_proc)) {
		what_we_think = CPU_TYPE_ARM64;
	} else {
		what_we_think = CPU_TYPE_ARM;
	}
#endif

	return what_we_think;
}

cpu_type_t
process_cpu_subtype(proc_t core_proc)
{
	cpu_type_t what_we_think;
#if defined (__i386__) || defined (__x86_64__)
	if (IS_64BIT_PROCESS(core_proc)) {
		what_we_think = CPU_SUBTYPE_X86_64_ALL;
	} else {
		what_we_think = CPU_SUBTYPE_I386_ALL;
	}
#elif defined(__arm64__)
	if (IS_64BIT_PROCESS(core_proc)) {
		what_we_think = CPU_SUBTYPE_ARM64_ALL;
	} else {
		what_we_think = CPU_SUBTYPE_ARM_ALL;
	}
#endif
	return what_we_think;
}

static void
collectth_state(thread_t th_act, void *tirp)
{
	vm_offset_t     header;
	size_t  hoffset, i;
	mythread_state_flavor_t *flavors;
	struct thread_command   *tc;
	tir_t *t = (tir_t *)tirp;

	/*
	 *	Fill in thread command structure.
	 */
	header = t->header;
	hoffset = t->hoffset;
	flavors = t->flavors;

	tc = (struct thread_command *) (header + hoffset);
	tc->cmd = LC_THREAD;
	tc->cmdsize = (uint32_t)(sizeof(struct thread_command)
	    + t->tstate_size);
	hoffset += sizeof(struct thread_command);
	/*
	 * Follow with a struct thread_state_flavor and
	 * the appropriate thread state struct for each
	 * thread state flavor.
	 */
	for (i = 0; i < t->flavor_count; i++) {
		*(mythread_state_flavor_t *)(header + hoffset) =
		    flavors[i];
		hoffset += sizeof(mythread_state_flavor_t);
		thread_getstatus(th_act, flavors[i].flavor,
		    (thread_state_t)(header + hoffset),
		    &flavors[i].count);
		hoffset += flavors[i].count * sizeof(int);
	}

	t->hoffset = hoffset;
}

#if DEVELOPMENT || DEBUG
#define COREDUMPLOG(fmt, args...) printf("coredump (%s, pid %d): " fmt "\n", core_proc->p_comm, proc_getpid(core_proc), ## args)
#else
#define COREDUMPLOG(fmt, args...)
#endif

/*
 * LC_NOTE support for userspace coredumps.
 */

typedef int (write_note_cb_t)(struct vnode *vp, off_t foffset);

static int
note_addrable_bits(struct vnode *vp, off_t foffset)
{
	task_t t = current_task();
	vfs_context_t ctx = vfs_context_current();
	kauth_cred_t cred = vfs_context_ucred(ctx);

	addrable_bits_note_t note = {
		.version = ADDRABLE_BITS_VER,
		.addressing_bits = pmap_user_va_bits(get_task_pmap(t)),
		.unused = 0
	};

	return vn_rdwr_64(UIO_WRITE, vp, (vm_offset_t)&note, sizeof(note), foffset, UIO_SYSSPACE,
	           IO_NODELOCKED | IO_UNIT, cred, 0, current_proc());
}

/*
 * note handling
 */

struct core_note {
	size_t          cn_size;
	const char      *cn_owner;
	write_note_cb_t *cn_write_cb;
} const core_notes[] = {
	{
		.cn_size = sizeof(addrable_bits_note_t),
		.cn_owner = ADDRABLE_BITS_DATA_OWNER,
		.cn_write_cb = note_addrable_bits,
	}
};

const size_t notes_count = sizeof(core_notes) / sizeof(struct core_note);

/*
 * LC_NOTE commands are allocated as a part of Mach-O header and are written to
 * disk at the end of coredump. LC_NOTE's payload has to be written in callbacks here.
 */
static int
dump_notes(proc_t __unused core_proc, vm_offset_t header, size_t hoffset, struct vnode *vp, off_t foffset)
{
	for (size_t i = 0; i < notes_count; i++) {
		int error = 0;

		if (core_notes[i].cn_write_cb == NULL) {
			continue;
		}

		/* Generate LC_NOTE command. */
		struct note_command *nc = (struct note_command *)(header + hoffset);

		nc->cmd = LC_NOTE;
		nc->cmdsize = sizeof(struct note_command);
		nc->offset = foffset;
		nc->size = core_notes[i].cn_size;
		strlcpy(nc->data_owner, core_notes[i].cn_owner, sizeof(nc->data_owner));

		hoffset += sizeof(struct note_command);

		/* Add note's payload. */
		error = core_notes[i].cn_write_cb(vp, foffset);
		if (error != KERN_SUCCESS) {
			COREDUMPLOG("failed to write LC_NOTE %s: error %d", core_notes[i].cn_owner, error);
			return error;
		}

		foffset += core_notes[i].cn_size;
	}

	return 0;
}

/*
 * coredump
 *
 * Description:	Create a core image on the file "core" for the process
 *		indicated
 *
 * Parameters:	core_proc			Process to dump core [*]
 *				reserve_mb			If non-zero, leave filesystem with
 *									at least this much free space.
 *				coredump_flags	Extra options (ignore rlimit, run fsync)
 *
 * Returns:	0				Success
 *		!0				Failure errno
 *
 * IMPORTANT:	This function can only be called on the current process, due
 *		to assumptions below; see variable declaration section for
 *		details.
 */
#define MAX_TSTATE_FLAVORS      10
int
coredump(proc_t core_proc, uint32_t reserve_mb, int coredump_flags)
{
/* Begin assumptions that limit us to only the current process */
	vfs_context_t ctx = vfs_context_current();
	vm_map_t        map = current_map();
	task_t          task = current_task();
/* End assumptions */
	kauth_cred_t cred = vfs_context_ucred(ctx);
	int error = 0;
	struct vnode_attr *vap = NULL;
	size_t          thread_count, segment_count;
	size_t          command_size, header_size, tstate_size;
	size_t          hoffset;
	off_t           foffset;
	mach_vm_offset_t vmoffset;
	vm_offset_t     header;
	mach_vm_size_t  vmsize;
	vm_prot_t       prot;
	vm_prot_t       maxprot;
	int             error1 = 0;
	char            stack_name[MAXCOMLEN + 6];
	char            *alloced_name = NULL;
	char            *name = NULL;
	mythread_state_flavor_t flavors[MAX_TSTATE_FLAVORS];
	vm_size_t       mapsize;
	size_t          i;
	uint32_t nesting_depth = 0;
	kern_return_t   kret;
	struct vm_region_submap_info_64 vbr;
	mach_msg_type_number_t vbrcount = 0;
	tir_t tir1;
	struct vnode * vp;
	struct mach_header      *mh = NULL;     /* protected by is_64 */
	struct mach_header_64   *mh64 = NULL;   /* protected by is_64 */
	int             is_64 = 0;
	size_t          mach_header_sz = sizeof(struct mach_header);
	size_t          segment_command_sz = sizeof(struct segment_command);
	size_t          notes_size = 0;
	const char     *format = NULL;
	char           *custom_location_entitlement = NULL;
	size_t          custom_location_entitlement_len = 0;
	char           *alloced_format = NULL;
	size_t          alloced_format_len = 0;
	bool            include_iokit_memory = task_is_driver(task);
	bool            coredump_attempted = false;
	bool            task_locked = false;

	if (current_proc() != core_proc) {
		panic("coredump() called against proc that is not current_proc: %p", core_proc);
	}

	if (do_coredump == 0 ||         /* Not dumping at all */
	    ((sugid_coredump == 0) &&   /* Not dumping SUID/SGID binaries */
	    ((kauth_cred_getsvuid(cred) != kauth_cred_getruid(cred)) ||
	    (kauth_cred_getsvgid(cred) != kauth_cred_getrgid(cred))))) {
		error = EFAULT;
		goto out2;
	}

#if CONFIG_MACF
	error = mac_proc_check_dump_core(core_proc);
	if (error != 0) {
		goto out2;
	}
#endif

	if (IS_64BIT_PROCESS(core_proc)) {
		is_64 = 1;
		mach_header_sz = sizeof(struct mach_header_64);
		segment_command_sz = sizeof(struct segment_command_64);
	}

	mapsize = get_vmmap_size(map);

	custom_location_entitlement = IOCurrentTaskGetEntitlement(COREDUMP_CUSTOM_LOCATION_ENTITLEMENT);
	if (custom_location_entitlement != NULL) {
		custom_location_entitlement_len = strlen(custom_location_entitlement);
		const char * dirname;
		if (proc_is_driver(core_proc)) {
			dirname = defaultdrivercorefiledir;
		} else {
			dirname = defaultcorefiledir;
		}
		size_t dirname_len = strlen(dirname);
		size_t printed_len;

		/* new format is dirname + "/" + string from entitlement */
		alloced_format_len = dirname_len + 1 + custom_location_entitlement_len;
		alloced_format = kalloc_data(alloced_format_len + 1, Z_ZERO | Z_WAITOK | Z_NOFAIL);
		printed_len = snprintf(alloced_format, alloced_format_len + 1, "%s/%s", dirname, custom_location_entitlement);
		assert(printed_len == alloced_format_len);

		format = alloced_format;
		coredump_flags |= COREDUMP_IGNORE_ULIMIT;
	} else {
		if (proc_is_driver(core_proc)) {
			format = drivercorefilename;
		} else {
			format = corefilename;
		}
	}

	if (((coredump_flags & COREDUMP_IGNORE_ULIMIT) == 0) &&
	    (mapsize >= proc_limitgetcur(core_proc, RLIMIT_CORE))) {
		error = EFAULT;
		goto out2;
	}

	/* log coredump failures from here */
	coredump_attempted = true;

	task_lock(task);
	task_locked = true;
	(void) task_suspend_internal_locked(task);

	alloced_name = zalloc_flags(ZV_NAMEI, Z_NOWAIT | Z_ZERO);

	/* create name according to sysctl'able format string */
	/* if name creation fails, fall back to historical behaviour... */
	if (alloced_name == NULL ||
	    proc_core_name(format, core_proc->p_comm, kauth_cred_getuid(cred),
	    proc_getpid(core_proc), alloced_name, MAXPATHLEN)) {
		snprintf(stack_name, sizeof(stack_name),
		    "/cores/core.%d", proc_getpid(core_proc));
		name = stack_name;
	} else {
		name = alloced_name;
	}

	COREDUMPLOG("writing core to %s", name);
	if ((error = vnode_open(name, (O_CREAT | FWRITE | O_NOFOLLOW), S_IRUSR, VNODE_LOOKUP_NOFOLLOW, &vp, ctx))) {
		COREDUMPLOG("failed to open core dump file %s: error %d", name, error);
		goto out2;
	}

	vap = kalloc_type(struct vnode_attr, Z_WAITOK | Z_ZERO);
	VATTR_INIT(vap);
	VATTR_WANTED(vap, va_nlink);
	/* Don't dump to non-regular files or files with links. */
	if (vp->v_type != VREG ||
	    vnode_getattr(vp, vap, ctx) || vap->va_nlink != 1) {
		COREDUMPLOG("failed to write core to non-regular file");
		error = EFAULT;
		goto out;
	}

	VATTR_INIT(vap);        /* better to do it here than waste more stack in vnode_setsize */
	VATTR_SET(vap, va_data_size, 0);
	if (core_proc == initproc) {
		VATTR_SET(vap, va_dataprotect_class, PROTECTION_CLASS_D);
	}
	vnode_setattr(vp, vap, ctx);
	core_proc->p_acflag |= ACORE;

	COREDUMPLOG("map size: %lu", mapsize);
	if ((reserve_mb > 0) &&
	    ((freespace_mb(vp) - (mapsize >> 20)) < reserve_mb)) {
		COREDUMPLOG("insufficient free space (free=%d MB, needed=%lu MB, reserve=%d MB)", freespace_mb(vp), (mapsize >> 20), reserve_mb);
		error = ENOSPC;
		goto out;
	}

	thread_count = get_task_numacts(task);
	segment_count = get_vmmap_entries(map); /* XXX */
	tir1.flavor_count = sizeof(thread_flavor_array) / sizeof(mythread_state_flavor_t);
	bcopy(thread_flavor_array, flavors, sizeof(thread_flavor_array));
	tstate_size = 0;
	for (i = 0; i < tir1.flavor_count; i++) {
		tstate_size += sizeof(mythread_state_flavor_t) +
		    (flavors[i].count * sizeof(int));
	}

	{
		size_t lhs;
		size_t rhs;

		/* lhs = segment_count * segment_command_sz */
		if (os_mul_overflow(segment_count, segment_command_sz, &lhs)) {
			COREDUMPLOG("error: segment size overflow: segment_count=%lu, segment_command_sz=%lu", segment_count, segment_command_sz);
			error = ENOMEM;
			goto out;
		}

		/* rhs = (tstate_size + sizeof(struct thread_command)) * thread_count */
		if (os_add_and_mul_overflow(tstate_size, sizeof(struct thread_command), thread_count, &rhs)) {
			COREDUMPLOG("error: thread state size overflow: tstate_size=%lu, thread_count=%lu", tstate_size, thread_count);
			error = ENOMEM;
			goto out;
		}

		/* command_size = lhs + rhs */
		if (os_add_overflow(lhs, rhs, &command_size)) {
			COREDUMPLOG("error: command size overflow: lhs=%lu, rhs=%lu", lhs, rhs);
			error = ENOMEM;
			goto out;
		}

		/* Add notes payload. */
		if (os_mul_overflow(notes_count, sizeof(struct note_command), &notes_size)) {
			COREDUMPLOG("error: note command size overflow: note=%lu", i);
			error = ENOMEM;
			goto out;
		}

		if (os_add_overflow(command_size, notes_size, &command_size)) {
			COREDUMPLOG("error: notes overflow: notes_size=%lu", notes_size);
			error = ENOMEM;
			goto out;
		}
	}

	if (os_add_overflow(command_size, mach_header_sz, &header_size)) {
		COREDUMPLOG("error: header size overflow: command_size=%lu, mach_header_sz=%lu", command_size, mach_header_sz);
		error = ENOMEM;
		goto out;
	}

	if (kmem_alloc(kernel_map, &header, (vm_size_t)header_size,
	    KMA_DATA | KMA_ZERO, VM_KERN_MEMORY_DIAG) != KERN_SUCCESS) {
		COREDUMPLOG("error: failed to allocate memory for header (size=%lu)", header_size);
		error = ENOMEM;
		goto out;
	}

	/*
	 *	Set up Mach-O header.
	 */
	if (is_64) {
		mh64 = (struct mach_header_64 *)header;
		mh64->magic = MH_MAGIC_64;
		mh64->cputype = process_cpu_type(core_proc);
		mh64->cpusubtype = process_cpu_subtype(core_proc);
		mh64->filetype = MH_CORE;
		mh64->ncmds = (uint32_t)(segment_count + notes_count + thread_count);
		mh64->sizeofcmds = (uint32_t)command_size;
	} else {
		mh = (struct mach_header *)header;
		mh->magic = MH_MAGIC;
		mh->cputype = process_cpu_type(core_proc);
		mh->cpusubtype = process_cpu_subtype(core_proc);
		mh->filetype = MH_CORE;
		mh->ncmds = (uint32_t)(segment_count + notes_count + thread_count);
		mh->sizeofcmds = (uint32_t)command_size;
	}

	hoffset = mach_header_sz;       /* offset into header */
	foffset = round_page(header_size);      /* offset into file */
	vmoffset = MACH_VM_MIN_ADDRESS;         /* offset into VM */
	COREDUMPLOG("mach header size: %zu", header_size);

	/*
	 * We use to check for an error, here, now we try and get
	 * as much as we can
	 */
	COREDUMPLOG("dumping %zu segments", segment_count);
	while (segment_count > 0) {
		struct segment_command          *sc;
		struct segment_command_64       *sc64;

		/*
		 *	Get region information for next region.
		 */

		while (1) {
			vbrcount = VM_REGION_SUBMAP_INFO_COUNT_64;
			if ((kret = mach_vm_region_recurse(map,
			    &vmoffset, &vmsize, &nesting_depth,
			    (vm_region_recurse_info_t)&vbr,
			    &vbrcount)) != KERN_SUCCESS) {
				break;
			}
			/*
			 * If we get a valid mapping back, but we're dumping
			 * a 32 bit process,  and it's over the allowable
			 * address space of a 32 bit process, it's the same
			 * as if mach_vm_region_recurse() failed.
			 */
			if (!(is_64) &&
			    (vmoffset + vmsize > VM_MAX_ADDRESS)) {
				kret = KERN_INVALID_ADDRESS;
				COREDUMPLOG("exceeded allowable region for 32-bit process");
				break;
			}
			if (vbr.is_submap) {
				nesting_depth++;
				continue;
			} else {
				break;
			}
		}
		if (kret != KERN_SUCCESS) {
			COREDUMPLOG("ending segment dump, kret=%d", kret);
			break;
		}

		prot = vbr.protection;
		maxprot = vbr.max_protection;

		if ((prot | maxprot) == VM_PROT_NONE) {
			/*
			 * Elide unreadable (likely reserved) segments
			 */
			COREDUMPLOG("eliding unreadable segment %llx->%llx", vmoffset, vmoffset + vmsize);
			vmoffset += vmsize;
			continue;
		}

		/*
		 * Try as hard as possible to get read access to the data.
		 */
		if ((prot & VM_PROT_READ) == 0) {
			mach_vm_protect(map, vmoffset, vmsize, FALSE,
			    prot | VM_PROT_READ);
		}

		/*
		 * But only try and perform the write if we can read it.
		 */
		int64_t fsize = ((maxprot & VM_PROT_READ) == VM_PROT_READ
		    && (include_iokit_memory || vbr.user_tag != VM_MEMORY_IOKIT)
		    && coredumpok(map, vmoffset)) ? vmsize : 0;

		if (fsize) {
			int64_t resid = 0;
			const enum uio_seg sflg = IS_64BIT_PROCESS(core_proc) ?
			    UIO_USERSPACE64 : UIO_USERSPACE32;

			error = vn_rdwr_64(UIO_WRITE, vp, vmoffset, fsize,
			    foffset, sflg, IO_NODELOCKED | IO_UNIT,
			    cred, &resid, core_proc);

			if (error) {
				/*
				 * Mark segment as empty
				 */
				fsize = 0;
				COREDUMPLOG("failed to write segment %llx->%llx: error %d", vmoffset, vmoffset + vmsize, error);
			} else if (resid) {
				/*
				 * Partial write. Extend the file size so
				 * that the segment command contains a valid
				 * range of offsets, possibly creating a hole.
				 */
				VATTR_INIT(vap);
				VATTR_SET(vap, va_data_size, foffset + fsize);
				vnode_setattr(vp, vap, ctx);
				COREDUMPLOG("partially wrote segment %llx->%llx, resid %lld", vmoffset, vmoffset + vmsize, resid);
			}
		} else {
			COREDUMPLOG("skipping unreadable segment %llx->%llx", vmoffset, vmoffset + vmsize);
		}

		/*
		 *	Fill in segment command structure.
		 */

		if (is_64) {
			sc64 = (struct segment_command_64 *)(header + hoffset);
			sc64->cmd = LC_SEGMENT_64;
			sc64->cmdsize = sizeof(struct segment_command_64);
			/* segment name is zeroed by kmem_alloc */
			sc64->segname[0] = 0;
			sc64->vmaddr = vmoffset;
			sc64->vmsize = vmsize;
			sc64->fileoff = foffset;
			sc64->filesize = fsize;
			sc64->maxprot = maxprot;
			sc64->initprot = prot;
			sc64->nsects = 0;
			sc64->flags = 0;
		} else {
			sc = (struct segment_command *) (header + hoffset);
			sc->cmd = LC_SEGMENT;
			sc->cmdsize = sizeof(struct segment_command);
			/* segment name is zeroed by kmem_alloc */
			sc->segname[0] = 0;
			sc->vmaddr = CAST_DOWN_EXPLICIT(uint32_t, vmoffset);
			sc->vmsize = CAST_DOWN_EXPLICIT(uint32_t, vmsize);
			sc->fileoff = CAST_DOWN_EXPLICIT(uint32_t, foffset); /* will never truncate */
			sc->filesize = CAST_DOWN_EXPLICIT(uint32_t, fsize); /* will never truncate */
			sc->maxprot = maxprot;
			sc->initprot = prot;
			sc->nsects = 0;
			sc->flags = 0;
		}

		hoffset += segment_command_sz;
		foffset += fsize;
		vmoffset += vmsize;
		segment_count--;
	}
	COREDUMPLOG("max file offset: %lld", foffset);

	/*
	 * If there are remaining segments which have not been written
	 * out because break in the loop above, then they were not counted
	 * because they exceed the real address space of the executable
	 * type: remove them from the header's count.  This is OK, since
	 * we are allowed to have a sparse area following the segments.
	 */
	if (is_64) {
		mh64->ncmds -= segment_count;
		mh64->sizeofcmds -= segment_count * segment_command_sz;
	} else {
		mh->ncmds -= segment_count;
		mh->sizeofcmds -= segment_count * segment_command_sz;
	}

	/* Add LC_NOTES */
	COREDUMPLOG("dumping %zu notes", notes_count);
	if (dump_notes(core_proc, header, hoffset, vp, foffset) != 0) {
		error = EFAULT;
		goto out;
	}

	tir1.header = header;
	tir1.hoffset = hoffset + notes_size;
	tir1.flavors = flavors;
	tir1.tstate_size = tstate_size;
	COREDUMPLOG("dumping %zu threads", thread_count);
	task_act_iterate_wth_args_locked(task, collectth_state, &tir1);

	/*
	 *	Write out the Mach header at the beginning of the
	 *	file.  OK to use a 32 bit write for this.
	 */
	error = vn_rdwr(UIO_WRITE, vp, (caddr_t)header, (int)MIN(header_size, INT_MAX), (off_t)0,
	    UIO_SYSSPACE, IO_NODELOCKED | IO_UNIT, cred, (int *) 0, core_proc);
	if (error != KERN_SUCCESS) {
		COREDUMPLOG("failed to write mach header: error %d", error);
	}
	kmem_free(kernel_map, header, header_size);

	if ((coredump_flags & COREDUMP_FULLFSYNC) && error == 0) {
		error = VNOP_IOCTL(vp, F_FULLFSYNC, (caddr_t)NULL, 0, ctx);
		if (error != KERN_SUCCESS) {
			COREDUMPLOG("failed to FULLFSYNC core: error %d", error);
		}
	}
out:
	if (vap) {
		kfree_type(struct vnode_attr, vap);
	}
	error1 = vnode_close(vp, FWRITE, ctx);
	if (error1 != KERN_SUCCESS) {
		COREDUMPLOG("failed to close core file: error %d", error1);
	}
out2:
#if CONFIG_AUDIT
	audit_proc_coredump(core_proc, name, error);
#endif
	if (alloced_name != NULL) {
		zfree(ZV_NAMEI, alloced_name);
	}
	if (alloced_format != NULL) {
		kfree_data(alloced_format, alloced_format_len + 1);
	}
	if (custom_location_entitlement != NULL) {
		kfree_data(custom_location_entitlement, custom_location_entitlement_len + 1);
	}
	if (error == 0) {
		error = error1;
	}

	if (coredump_attempted) {
		if (error != 0) {
			COREDUMPLOG("core dump failed: error %d\n", error);
		} else {
			COREDUMPLOG("core dump succeeded");
		}
	}

	if (task_locked) {
		task_unlock(task);
	}

	return error;
}

#else /* CONFIG_COREDUMP */

/* When core dumps aren't needed, no need to compile this file at all */

#error assertion failed: this section is not compiled

#endif /* CONFIG_COREDUMP */
