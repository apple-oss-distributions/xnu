/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
#include <mach/mach_types.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>

#include <vm/pmap.h>

#include <mach/thread_status.h>
#include <mach-o/loader.h>
#include <mach/vm_region.h>
#include <mach/vm_statistics.h>

#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_protos.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_udp.h>
#include <kdp/kdp_internal.h>
#include <arm/misc_protos.h>
#include <arm/caches_internal.h>
#include <arm/cpu_data_internal.h>
#include <arm/misc_protos.h>

pmap_t          kdp_pmap = 0;
boolean_t       kdp_trans_off;
boolean_t       kdp_read_io = 0;

pmap_paddr_t    kdp_vtophys(pmap_t pmap, vm_offset_t va);

/*
 * kdp_vtophys
 */
pmap_paddr_t
kdp_vtophys(
	pmap_t pmap,
	vm_offset_t va)
{
	pmap_paddr_t    pa;

	/* Ensure that the provided va resides within the provided pmap range. */
	if (!pmap || ((pmap != kernel_pmap) && ((va < pmap->min) || (va >= pmap->max)))) {
#ifdef KDP_VTOPHYS_DEBUG
		printf("kdp_vtophys(%08x, %016lx) not in range %08x .. %08x\n", (unsigned int) pmap,
		    (unsigned long) va,
		    (unsigned int) (pmap ? pmap->min : 0),
		    (unsigned int) (pmap ? pmap->max : 0));
#endif
		return 0;   /* Just return if no translation */
	}

	pa = pmap_find_pa(pmap, va);  /* Get the physical address */
	return pa;
}

/*
 * kdp_machine_vm_read
 *
 * Verify that src is valid, and physically copy len bytes from src to
 * dst, translating if necessary. If translation is enabled
 * (kdp_trans_off is 0), a non-zero kdp_pmap specifies the pmap to use
 * when translating src.
 */

mach_vm_size_t
kdp_machine_vm_read( mach_vm_address_t src, caddr_t dst, mach_vm_size_t len)
{
	addr64_t        cur_virt_src, cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t  resid, cnt;
	pmap_t          pmap;

#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_machine_vm_read1: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *) src)[0], ((unsigned long *) src)[1]);
#endif

	cur_virt_src = (addr64_t) src;
	cur_virt_dst = (addr64_t) dst;

	if (kdp_trans_off) {
		kdp_readphysmem64_req_t rq;
		mach_vm_size_t ret;

		rq.address = src;
		rq.nbytes = (uint32_t)len;
		ret = kdp_machine_phys_read(&rq, dst, 0 /* unused */);
		return ret;
	} else {
		resid = len;

		if (kdp_pmap) {
			pmap = kdp_pmap;        /* If special pmap, use it */
		} else {
			pmap = kernel_pmap;     /* otherwise, use kernel's */
		}
		while (resid != 0) {
			/*
			 * Always translate the destination using the
			 * kernel_pmap.
			 */
			if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) {
				goto exit;
			}

			if ((cur_phys_src = kdp_vtophys(pmap, cur_virt_src)) == 0) {
				goto exit;
			}

			/* Attempt to ensure that there are valid translations for src and dst. */
			if (!kdp_read_io && ((!pmap_valid_address(cur_phys_dst)) || (!pmap_valid_address(cur_phys_src)))) {
				goto exit;
			}

			cnt = ARM_PGBYTES - (cur_virt_src & PAGE_MASK); /* Get length left on
			                                                 * page */
			if (cnt > (ARM_PGBYTES - (cur_virt_dst & PAGE_MASK))) {
				cnt = ARM_PGBYTES - (cur_virt_dst & PAGE_MASK);
			}

			if (cnt > resid) {
				cnt = resid;
			}

#ifdef KDP_VM_READ_DEBUG
			kprintf("kdp_machine_vm_read2: pmap %08X, virt %016LLX, phys %016LLX\n",
			    pmap, cur_virt_src, cur_phys_src);
#endif
			bcopy_phys(cur_phys_src, cur_phys_dst, cnt);

			cur_virt_src += cnt;
			cur_virt_dst += cnt;
			resid -= cnt;
		}
	}
exit:
#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_machine_vm_read: ret %08X\n", len - resid);
#endif
	return len - resid;
}

mach_vm_size_t
kdp_machine_phys_read(kdp_readphysmem64_req_t *rq, caddr_t dst, uint16_t lcpu __unused)
{
	mach_vm_address_t src = rq->address;
	mach_vm_size_t    len = rq->nbytes;

	addr64_t        cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t  resid = len;
	mach_vm_size_t  cnt = 0, cnt_src, cnt_dst;

#ifdef KDP_VM_READ_DEBUG
	kprintf("kdp_phys_read src %x dst %p len %x\n", src, dst, len);
#endif

	cur_virt_dst = (addr64_t) dst;
	cur_phys_src = (addr64_t) src;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) {
			goto exit;
		}

		/* Get length left on page */

		cnt_src = ARM_PGBYTES - (cur_phys_src & PAGE_MASK);
		cnt_dst = ARM_PGBYTES - (cur_phys_dst & PAGE_MASK);
		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);    /* Copy stuff over */
		cur_phys_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}

exit:
	return len - resid;
}

/*
 * kdp_vm_write
 */
mach_vm_size_t
kdp_machine_vm_write( caddr_t src, mach_vm_address_t dst, mach_vm_size_t len)
{
	addr64_t        cur_virt_src, cur_virt_dst;
	addr64_t        cur_phys_src, cur_phys_dst;
	mach_vm_size_t  resid, cnt, cnt_src, cnt_dst;

#ifdef KDP_VM_WRITE_DEBUG
	printf("kdp_vm_write: src %x dst %x len %x - %08X %08X\n", src, dst, len, ((unsigned long *) src)[0], ((unsigned long *) src)[1]);
#endif

	cur_virt_src = (addr64_t) src;
	cur_virt_dst = (addr64_t) dst;

	resid = len;

	while (resid != 0) {
		if ((cur_phys_dst = kdp_vtophys(kernel_pmap, cur_virt_dst)) == 0) {
			goto exit;
		}

		if ((cur_phys_src = kdp_vtophys(kernel_pmap, cur_virt_src)) == 0) {
			goto exit;
		}

		/* Attempt to ensure that there are valid translations for src and dst. */
		/* No support for enabling writes for an invalid translation at the moment. */
		if ((!pmap_valid_address(cur_phys_dst)) || (!pmap_valid_address(cur_phys_src))) {
			goto exit;
		}

		cnt_src = ((cur_phys_src + ARM_PGBYTES) & (-ARM_PGBYTES)) - cur_phys_src;
		cnt_dst = ((cur_phys_dst + ARM_PGBYTES) & (-ARM_PGBYTES)) - cur_phys_dst;

		if (cnt_src > cnt_dst) {
			cnt = cnt_dst;
		} else {
			cnt = cnt_src;
		}
		if (cnt > resid) {
			cnt = resid;
		}

#ifdef KDP_VM_WRITE_DEBUG
		printf("kdp_vm_write: cur_phys_src %x cur_phys_src %x len %x - %08X %08X\n", src, dst, cnt);
#endif
		bcopy_phys(cur_phys_src, cur_phys_dst, cnt);    /* Copy stuff over */
		flush_dcache64(cur_phys_dst, (unsigned int)cnt, TRUE);
		invalidate_icache64(cur_phys_dst, (unsigned int)cnt, TRUE);

		cur_virt_src += cnt;
		cur_virt_dst += cnt;
		resid -= cnt;
	}
exit:
	return len - resid;
}

mach_vm_size_t
kdp_machine_phys_write(kdp_writephysmem64_req_t *rq __unused, caddr_t src __unused,
    uint16_t lcpu __unused)
{
	return 0; /* unimplemented */
}

void
kern_collectth_state_size(uint64_t * tstate_count, uint64_t * tstate_size)
{
	uint64_t    count = ml_get_max_cpu_number() + 1;

	*tstate_count = count;
	*tstate_size  = sizeof(struct thread_command)
	    + (sizeof(arm_state_hdr_t)
#if defined(__arm64__)
	    + ARM_THREAD_STATE64_COUNT * sizeof(uint32_t));
#else
	    + ARM_THREAD_STATE32_COUNT * sizeof(uint32_t));
#endif
}

void
kern_collectth_state(thread_t thread __unused, void *buffer, uint64_t size, void ** iter)
{
	cpu_data_entry_t *cpuentryp = *iter;
	if (cpuentryp == NULL) {
		cpuentryp = &CpuDataEntries[0];
	}

	if (cpuentryp == &CpuDataEntries[ml_get_max_cpu_number()]) {
		*iter = NULL;
	} else {
		*iter = cpuentryp + 1;
	}

	struct cpu_data *cpudatap = cpuentryp->cpu_data_vaddr;

	struct thread_command *tc = (struct thread_command *)buffer;
	arm_state_hdr_t *hdr = (arm_state_hdr_t *)(void *)(tc + 1);
#if defined(__arm64__)
	hdr->flavor = ARM_THREAD_STATE64;
	hdr->count = ARM_THREAD_STATE64_COUNT;
	arm_thread_state64_t *state = (arm_thread_state64_t *)(void *)(hdr + 1);
#else
	hdr->flavor = ARM_THREAD_STATE;
	hdr->count = ARM_THREAD_STATE_COUNT;
	arm_thread_state_t *state = (arm_thread_state_t *)(void *)(hdr + 1);
#endif

	tc->cmd = LC_THREAD;
	tc->cmdsize = (uint32_t) size;

	if ((cpudatap != NULL) && (cpudatap->halt_status == CPU_HALTED_WITH_STATE)) {
		*state = cpudatap->halt_state;
		return;
	}

	processor_t processor = PERCPU_GET_RELATIVE(processor, cpu_data, cpudatap);
	if ((cpudatap == NULL) || (processor->active_thread == NULL)) {
		bzero(state, hdr->count * sizeof(uint32_t));
		return;
	}

#if defined(__arm64__)
	void *kpcb = processor->active_thread->machine.kpcb;
	if (kpcb != NULL) {
		arm_saved_state_t *saved_state = (arm_saved_state_t *)kpcb;

		state->fp   = saved_state->ss_64.fp;
		state->lr   = saved_state->ss_64.lr;
		state->sp   = saved_state->ss_64.sp;
		state->pc   = saved_state->ss_64.pc;
		state->cpsr = saved_state->ss_64.cpsr;
		bcopy(&saved_state->ss_64.x[0], &state->x[0], sizeof(state->x));
	} else {
		vm_offset_t kstackptr = (vm_offset_t) processor->active_thread->machine.kstackptr;
		arm_kernel_saved_state_t *saved_state = (arm_kernel_saved_state_t *) kstackptr;

		state->fp   = saved_state->fp;
		state->lr   = saved_state->lr;
		state->sp   = saved_state->sp;
		state->pc   = saved_state->pc_was_in_userspace ? (register_t)ptrauth_strip((void *)&_was_in_userspace, ptrauth_key_function_pointer) : 0;
		state->cpsr = PSR64_KERNEL_DEFAULT;
	}

#else /* __arm64__ */
	vm_offset_t kstackptr = (vm_offset_t) processor->active_thread->machine.kstackptr;
	arm_saved_state_t *saved_state = (arm_saved_state_t *) kstackptr;

	state->lr   = saved_state->lr;
	state->sp   = saved_state->sp;
	state->pc   = saved_state->pc;
	state->cpsr = saved_state->cpsr;
	bcopy(&saved_state->r[0], &state->r[0], sizeof(state->r));

#endif /* !__arm64__ */
}

static const arm_state_hdr_t user32_thread_flavor_array[] = {
	{ ARM_THREAD_STATE, ARM_UNIFIED_THREAD_STATE_COUNT },
};

#if defined(__arm64__)
static const arm_state_hdr_t user64_thread_flavor_array[] = {
	{ ARM_THREAD_STATE64, ARM_THREAD_STATE64_COUNT },
	{ ARM_VFP_STATE, ARM_VFP_STATE_COUNT },
	{ ARM_EXCEPTION_STATE64, ARM_EXCEPTION_STATE64_COUNT },
};
#endif

void
kern_collect_userth_state_size(task_t task, uint64_t * tstate_count, uint64_t * tstate_size)
{
	uint64_t per_thread_size = 0;
	uint64_t num_flavors = 0;
	const arm_state_hdr_t * flavors;
#if defined(__arm64__)
	bool is64bit = task_has_64Bit_addr(task);

	if (is64bit) {
		flavors = user64_thread_flavor_array;
		num_flavors = sizeof(user64_thread_flavor_array) / sizeof(user64_thread_flavor_array[0]);
	} else {
		flavors = user32_thread_flavor_array;
		num_flavors = sizeof(user32_thread_flavor_array) / sizeof(user32_thread_flavor_array[0]);
	}
#else
	flavors = user32_thread_flavor_array;
	num_flavors = sizeof(user32_thread_flavor_array) / sizeof(user32_thread_flavor_array[0]);
#endif

	for (size_t i = 0; i < num_flavors; i++) {
		per_thread_size += sizeof(arm_state_hdr_t) + (flavors[i].count * sizeof(natural_t));
	}

	*tstate_count = task->thread_count;
	*tstate_size  = sizeof(struct thread_command) + per_thread_size;
}

void
kern_collect_userth_state(task_t task, thread_t thread, void *buffer, uint64_t size)
{
	kern_return_t ret;
	uint64_t num_flavors = 0;
	const arm_state_hdr_t * flavors;
#if defined(__arm64__)
	bool is64bit = task_has_64Bit_addr(task);

	if (is64bit) {
		flavors = user64_thread_flavor_array;
		num_flavors = sizeof(user64_thread_flavor_array) / sizeof(user64_thread_flavor_array[0]);
	} else {
		flavors = user32_thread_flavor_array;
		num_flavors = sizeof(user32_thread_flavor_array) / sizeof(user32_thread_flavor_array[0]);
	}
#else
	(void)task;
	flavors = user32_thread_flavor_array;
	num_flavors = sizeof(user32_thread_flavor_array) / sizeof(user32_thread_flavor_array[0]);
#endif

	struct thread_command *tc = buffer;
	tc->cmd = LC_THREAD;
	tc->cmdsize = (uint32_t)size;

	arm_state_hdr_t *hdr = (arm_state_hdr_t *)(tc + 1);

	for (size_t i = 0; i < num_flavors; i++) {
		hdr->flavor = flavors[i].flavor;
		hdr->count = flavors[i].count;
		/* Ensure we can't write past the end of the buffer */
		assert(hdr->count + sizeof(arm_state_hdr_t) + ((uintptr_t)hdr - (uintptr_t)buffer) <= size);
		ret = machine_thread_get_state(thread, hdr->flavor, (thread_state_t)(hdr + 1), &hdr->count);
		assert(ret == KERN_SUCCESS);

		hdr = (arm_state_hdr_t *)((uintptr_t)(hdr + 1) + hdr->count * sizeof(natural_t));
	}
}

/*
 * kdp_core_start_addr
 *
 * return the address where the kernel core file starts
 *
 * The kernel start address is VM_MIN_KERNEL_AND_KEXT_ADDRESS
 * unless the physical aperture has been relocated below
 * VM_MIN_KERNEL_AND_KEXT_ADDRESS as in the case of
 * ARM_LARGE_MEMORY systems
 *
 */
vm_map_offset_t
kdp_core_start_addr()
{
#if defined(__arm64__)
	extern const vm_map_address_t physmap_base;
	return MIN(physmap_base, VM_MIN_KERNEL_AND_KEXT_ADDRESS);
#else /* !defined(__arm64__) */
	return VM_MIN_KERNEL_AND_KEXT_ADDRESS;
#endif /* !defined(__arm64__) */
}
